#![forbid(unsafe_code)]
//! Refuses the early-exit shapes by which an integration test passes without
//! having run.
//!
//! A missing binary, runtime tree, or manifest directory must fail the test
//! that needed it. The `e2e_support` resolvers panic with a proof-of-absence
//! error, so turning "absent" into a green takes an exit from the test body.
//! This scan walks every test target of the workspace
//! (each `cargo metadata` target of kind `test`, and every module file it
//! declares) and refuses:
//!
//! 1. a compile-time `env!("CARGO_BIN_EXE_…")` outside `tools/e2e-support/src`
//!    (the resolver reads the runtime value first and proves the file exists);
//! 2. an early `return` inside a `#[test]` fn;
//! 3. a string literal naming the tier variable outside `tools/e2e-support`
//!    (`e2e_support::e2e_tier` is its one reader, and refuses a malformed value);
//! 4. a print immediately followed by a `return` inside a `#[test]` fn;
//! 5. a bare `env!("CARGO_MANIFEST_DIR")` (`e2e_support::manifest_dir!` proves
//!    the directory exists; `concat!` inside `include_str!` is compile-checked).
//!
//! A file the scan cannot parse is refused, never skipped. The one sanctioned
//! early exit is the tier gate as a test body's first statement,
//! `if e2e_tier() == Tier::Unit { return; }` (optionally printing why first).
//! `return Err(..)` fails the test, so it is not a skip. A return inside a
//! closure or async block leaves only that closure, so neither is descended.
//!
//! [`ENV_SKIPS`] ratchets the tests that skip on a missing host capability
//! (a jail primitive, a target, an outbound route) rather than a missing test
//! artifact: each entry names its file and fn with the reason, and an entry
//! that no longer matches a skip fails, so the list only shrinks.
//!
//! Outside the scan, so not refused:
//! - a skip with no `return`: the body sits inside `if let Ok(..) = ..`, or a
//!   `match` whose miss arm is empty;
//! - an early return from a helper fn the `#[test]` body calls;
//! - `std::process::exit` from a test body;
//! - unit-test modules under `src/` (`cargo metadata` targets of kind `lib`);
//! - bodies under a test attribute whose last path segment is not `test`
//!   (`#[wasm_bindgen_test]`, `#[rstest]`, `#[test_case(..)]`).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use proc_macro2::{TokenStream, TokenTree};
use syn::visit::Visit;

/// The skip-scan fixtures, relative to this crate's manifest directory.
const FIXTURES: &str = "tests/fixtures/skip_scan";

/// Files under this prefix may bake a `CARGO_BIN_EXE_` path: the resolvers.
const SUPPORT_SRC: &str = "tools/e2e-support/src/";

/// Files under this prefix may name the tier variable.
const SUPPORT_ROOT: &str = "tools/e2e-support/";

/// The compile-time bin-path variable prefix cargo sets for integration tests.
const BIN_ENV_PREFIX: &str = "CARGO_BIN_EXE_";

/// The compile-time manifest-directory variable.
const MANIFEST_ENV: &str = "CARGO_MANIFEST_DIR";

/// The print macros whose message would dress up a skip.
const PRINT_MACROS: &[&str] = &["eprintln", "println", "eprint", "print"];

/// Why an OS jail test skips: the primitive is absent on this host.
const JAIL_ABSENT: &str = "the OS jail primitive is unavailable on this host";

/// Why a control-run test skips: the unjailed control run proves nothing here.
const CONTROL_INCONCLUSIVE: &str = "the unjailed control run is inconclusive on this host";

/// Why a playground test skips: its own opt-in tier or jail is absent.
const PLAYGROUND_TIER: &str = "the playground jail tier is opt-in and needs the host jail";

/// Tests that skip on a missing host capability: `(file, fn, why)`.
const ENV_SKIPS: &[(&str, &str, &str)] = &[
    (
        "src/compiler/ffi/tests/define_trait_impl_seal.rs",
        "the_marker_surfaces_the_type_and_the_emitted_crate_builds_and_runs",
        "the rustdoc-JSON inspector needs a nightly toolchain",
    ),
    (
        "src/compiler/sandbox/tests/run_jail_macos_e2e.rs",
        "undeclared_network_is_denied_under_the_run_jail_but_succeeds_under_control",
        CONTROL_INCONCLUSIVE,
    ),
    (
        "src/compiler/sandbox/tests/run_jail_macos_e2e.rs",
        "declared_network_reaches_the_network_under_the_run_jail",
        CONTROL_INCONCLUSIVE,
    ),
    (
        "src/compiler/sandbox/tests/run_jail_macos_e2e.rs",
        "an_out_of_scratch_write_is_denied_under_the_run_jail_but_succeeds_under_control",
        CONTROL_INCONCLUSIVE,
    ),
    (
        "src/compiler/sandbox/tests/run_jail_macos_e2e.rs",
        "undeclared_subprocess_spawn_is_denied_under_the_run_jail_but_succeeds_under_control",
        CONTROL_INCONCLUSIVE,
    ),
    (
        "src/compiler/sandbox/tests/run_jail_macos_e2e.rs",
        "declared_subprocess_spawn_succeeds_under_the_run_jail",
        CONTROL_INCONCLUSIVE,
    ),
    (
        "src/compiler/sandbox/tests/run_jail_e2e.rs",
        "undeclared_network_is_denied_at_the_os_boundary",
        JAIL_ABSENT,
    ),
    (
        "src/compiler/sandbox/tests/run_jail_e2e.rs",
        "declared_network_reaches_the_network",
        JAIL_ABSENT,
    ),
    (
        "src/compiler/sandbox/tests/run_jail_e2e.rs",
        "undeclared_subprocess_fork_is_denied",
        JAIL_ABSENT,
    ),
    (
        "src/compiler/sandbox/tests/run_jail_e2e.rs",
        "granted_subprocess_can_fork",
        JAIL_ABSENT,
    ),
    (
        "src/compiler/sandbox/tests/run_jail_e2e.rs",
        "a_thread_spawning_program_boots_under_the_isolated_jail",
        JAIL_ABSENT,
    ),
    (
        "src/compiler/sandbox/tests/run_jail_e2e.rs",
        "a_jailed_write_to_git_hooks_is_refused",
        JAIL_ABSENT,
    ),
    (
        "src/compiler/sandbox/tests/run_jail_e2e.rs",
        "a_jailed_git_status_still_reads_the_repo",
        JAIL_ABSENT,
    ),
    (
        "src/compiler/sandbox/tests/run_jail_e2e.rs",
        "nested_carve_ancestor_rename_refused",
        JAIL_ABSENT,
    ),
    (
        "src/compiler/sandbox/tests/run_jail_e2e.rs",
        "an_in_scratch_write_succeeds_under_the_run_jail",
        JAIL_ABSENT,
    ),
    (
        "src/compiler/sandbox/tests/run_jail_windows_e2e.rs",
        "a_child_spawn_is_denied_under_a_subprocess_withholding_job_but_succeeds_under_control",
        CONTROL_INCONCLUSIVE,
    ),
    (
        "src/compiler/sandbox/tests/run_jail_windows_e2e.rs",
        "an_out_of_scratch_write_is_denied_under_the_appcontainer_but_succeeds_under_control",
        CONTROL_INCONCLUSIVE,
    ),
    (
        "src/compiler/sandbox/tests/run_jail_windows_e2e.rs",
        "an_outbound_connect_is_denied_under_a_network_withholding_appcontainer",
        CONTROL_INCONCLUSIVE,
    ),
    (
        "src/compiler/sandbox/tests/build_jail_e2e.rs",
        "a_socket_under_a_network_withholding_jail_is_denied_naming_network",
        JAIL_ABSENT,
    ),
    (
        "src/compiler/sandbox/tests/build_jail_e2e.rs",
        "an_out_of_scratch_write_under_a_filesystem_withholding_jail_is_denied_naming_filesystem",
        JAIL_ABSENT,
    ),
    (
        "src/compiler/sandbox/tests/build_jail_e2e.rs",
        "a_benign_in_scratch_write_is_clean",
        JAIL_ABSENT,
    ),
    (
        "src/compiler/sandbox/tests/build_jail_e2e.rs",
        "a_missing_fixture_is_a_non_clean_outcome_fail_closed",
        JAIL_ABSENT,
    ),
    (
        "src/ipe-cli/tests/wasm_target_gate.rs",
        "hydrate_glue_type_name_matches_emitted_struct_and_compiles_for_wasm",
        "the wasm32 rustup target is not installed",
    ),
    (
        "src/ipe-cli/tests/static_emit.rs",
        "end_to_end_static_binary_is_static_and_runs",
        "the static-linking tier is opt-in and needs a static toolchain",
    ),
    (
        "src/ipe-cli/tests/static_emit.rs",
        "ipe_run_static_builds_and_executes_a_static_binary",
        "the static-linking tier is opt-in and needs a static toolchain",
    ),
    (
        "src/ipe-cli/tests/audit_native.rs",
        "used_but_undeclared_network_rejects_naming_the_axis_standing_canary",
        JAIL_ABSENT,
    ),
    (
        "src/ipe-cli/tests/audit_native.rs",
        "used_but_undeclared_filesystem_rejects_naming_filesystem",
        JAIL_ABSENT,
    ),
    (
        "src/ipe-cli/tests/audit_native.rs",
        "a_benign_network_package_declaring_exactly_its_axis_is_accepted",
        JAIL_ABSENT,
    ),
    (
        "src/ipe-cli/tests/audit_native.rs",
        "a_confined_clean_build_genuinely_certifies_the_first_real_certification",
        JAIL_ABSENT,
    ),
    (
        "src/ipe-cli/tests/audit_native.rs",
        "a_build_that_reaches_network_under_a_withholding_jail_rejects_at_the_os_boundary",
        JAIL_ABSENT,
    ),
    (
        "src/ipe-cli/tests/audit_native.rs",
        "a_real_native_package_with_a_probeable_binding_certifies_end_to_end",
        JAIL_ABSENT,
    ),
    (
        "src/ipe-cli/tests/audit_native.rs",
        "a_real_native_package_reaching_an_undeclared_axis_rejects_end_to_end",
        JAIL_ABSENT,
    ),
    (
        "src/ipe-cli/tests/audit_native.rs",
        "release_run_pure_native_is_jailed",
        JAIL_ABSENT,
    ),
    (
        "src/ipe-cli/tests/audit_native.rs",
        "release_run_accepts_artifact_dir",
        JAIL_ABSENT,
    ),
    (
        "src/ipe-cli/tests/audit_native.rs",
        "release_run_leaves_no_app_copy_in_tmp",
        JAIL_ABSENT,
    ),
    (
        "src/ipe-cli/tests/audit_native.rs",
        "release_run_native_bearing_is_jailed",
        JAIL_ABSENT,
    ),
    (
        "src/ipe-cli/tests/audit_native.rs",
        "release_run_withheld_subprocess_cannot_fork",
        JAIL_ABSENT,
    ),
    (
        "src/ipe-cli/tests/audit_native.rs",
        "release_run_runs_returned_artifact",
        JAIL_ABSENT,
    ),
    (
        "src/ipe-cli/tests/audit_native.rs",
        "release_run_refuses_a_development_build",
        JAIL_ABSENT,
    ),
    (
        "src/ipe-cli/tests/audit_native.rs",
        "release_run_refuses_real_dev_build",
        JAIL_ABSENT,
    ),
    (
        "src/ipe-cli/tests/audit_native.rs",
        "release_run_refuses_dev_binary_with_forged_release_literal",
        JAIL_ABSENT,
    ),
    (
        "src/ipe-cli/tests/audit_native.rs",
        "release_run_refuses_dev_run_binary_with_forged_release_literal",
        JAIL_ABSENT,
    ),
    (
        "src/ipe-cli/tests/webview_e2e.rs",
        "webview_counter_tier_b",
        "the native-window tier needs xvfb and the system webview",
    ),
    (
        "tools/panic-scan/tests/exit_codes.rs",
        "walk_fails_closed_on_an_unreadable_directory",
        "a privileged user reads a permission-locked directory",
    ),
    (
        "tools/panic-scan/tests/exit_codes.rs",
        "an_unlistable_declaring_directory_fails_closed",
        "a privileged user reads a permission-locked directory",
    ),
    (
        "examples/wasm/language-playground/jail-runner/tests/sandbox_security.rs",
        "hello_world_runs_and_returns_stdout",
        PLAYGROUND_TIER,
    ),
    (
        "examples/wasm/language-playground/jail-runner/tests/sandbox_security.rs",
        "network_access_is_denied",
        PLAYGROUND_TIER,
    ),
    (
        "examples/wasm/language-playground/jail-runner/tests/sandbox_security.rs",
        "out_of_jail_filesystem_read_is_denied",
        PLAYGROUND_TIER,
    ),
    (
        "examples/wasm/language-playground/jail-runner/tests/sandbox_security.rs",
        "a_spawned_subprocess_cannot_escape_the_jail",
        PLAYGROUND_TIER,
    ),
    (
        "examples/wasm/language-playground/jail-runner/tests/sandbox_security.rs",
        "a_fork_bomb_is_bounded_not_unbounded",
        PLAYGROUND_TIER,
    ),
    (
        "examples/wasm/language-playground/jail-runner/tests/sandbox_security.rs",
        "infinite_loop_is_killed_by_the_time_limit",
        PLAYGROUND_TIER,
    ),
];

/// A refused construct.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Rule {
    /// A compile-time `CARGO_BIN_EXE_` path outside the resolvers.
    BakedBin,
    /// An early `return` in a `#[test]` fn.
    EarlyReturn,
    /// A literal naming the tier variable outside its one reader.
    RawTierRead,
    /// A print immediately followed by a `return` in a `#[test]` fn.
    PrintedSkip,
    /// A bare compile-time `CARGO_MANIFEST_DIR`.
    BareManifestDir,
    /// A file the scan cannot parse.
    Unparsable,
}

impl Rule {
    /// Whether an [`ENV_SKIPS`] entry may exempt this rule.
    const fn is_skip(self) -> bool {
        matches!(self, Self::EarlyReturn | Self::PrintedSkip)
    }
}

/// One refused site.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Finding {
    rule: Rule,
    /// The enclosing `#[test]` fn, for the fn-scoped rules.
    func: Option<String>,
    line: usize,
}

/// Every finding in `text`, a file at workspace-relative path `rel`.
fn scan_source(rel: &str, text: &str) -> Vec<Finding> {
    let Ok(tokens) = TokenStream::from_str(text) else {
        return vec![unparsable()];
    };
    let Ok(file) = syn::parse_file(text) else {
        return vec![unparsable()];
    };
    let mut out = Vec::new();
    scan_tokens(rel, tokens, false, &mut out);
    let mut tests = TestFns { out: &mut out };
    tests.visit_file(&file);
    out.sort();
    out
}

const fn unparsable() -> Finding {
    Finding {
        rule: Rule::Unparsable,
        func: None,
        line: 0,
    }
}

/// The token-level rules: baked paths and tier-variable literals.
fn scan_tokens(rel: &str, tokens: TokenStream, in_concat: bool, out: &mut Vec<Finding>) {
    let trees: Vec<TokenTree> = tokens.into_iter().collect();
    for (i, tree) in trees.iter().enumerate() {
        match tree {
            TokenTree::Group(group) => {
                let concat = macro_name(&trees, i).is_some_and(|name| name == "concat");
                scan_tokens(rel, group.stream(), in_concat || concat, out);
            }
            TokenTree::Literal(lit) => {
                if !rel.starts_with(SUPPORT_ROOT)
                    && str_value(lit).is_some_and(|v| v == e2e_support::bin::E2E_VAR)
                {
                    out.push(Finding {
                        rule: Rule::RawTierRead,
                        func: None,
                        line: lit.span().start().line,
                    });
                }
            }
            TokenTree::Ident(ident) => {
                let is_env = ident == "env" || ident == "option_env";
                let Some(TokenTree::Group(args)) = trees.get(i + 2) else {
                    continue;
                };
                if !is_env || macro_name(&trees, i + 2).is_none() {
                    continue;
                }
                let Some((name, line)) = env_arg(args.stream()) else {
                    continue;
                };
                if name.starts_with(BIN_ENV_PREFIX) && !rel.starts_with(SUPPORT_SRC) {
                    out.push(Finding {
                        rule: Rule::BakedBin,
                        func: None,
                        line,
                    });
                } else if name == MANIFEST_ENV && !in_concat {
                    out.push(Finding {
                        rule: Rule::BareManifestDir,
                        func: None,
                        line,
                    });
                }
            }
            TokenTree::Punct(_) => {}
        }
    }
}

/// The macro name when `trees[group]` is a group invoked as `name!(…)`.
fn macro_name(trees: &[TokenTree], group: usize) -> Option<String> {
    let bang = trees.get(group.checked_sub(1)?)?;
    let name = trees.get(group.checked_sub(2)?)?;
    match (name, bang) {
        (TokenTree::Ident(name), TokenTree::Punct(p)) if p.as_char() == '!' => {
            Some(name.to_string())
        }
        _ => None,
    }
}

/// The variable an `env!` names: its first string literal, looking through a
/// leading `concat!`.
fn env_arg(args: TokenStream) -> Option<(String, usize)> {
    let trees: Vec<TokenTree> = args.into_iter().collect();
    match trees.first()? {
        TokenTree::Literal(lit) => str_value(lit).map(|v| (v, lit.span().start().line)),
        TokenTree::Ident(ident) if ident == "concat" => match trees.get(2)? {
            TokenTree::Group(inner) => env_arg(inner.stream()),
            _ => None,
        },
        _ => None,
    }
}

/// The value of a string literal token.
fn str_value(lit: &proc_macro2::Literal) -> Option<String> {
    match syn::Lit::new(lit.clone()) {
        syn::Lit::Str(s) => Some(s.value()),
        _ => None,
    }
}

/// Visits every `#[test]` fn and applies the fn-scoped rules to its body.
struct TestFns<'a> {
    out: &'a mut Vec<Finding>,
}

impl<'ast> Visit<'ast> for TestFns<'_> {
    fn visit_item_fn(&mut self, f: &'ast syn::ItemFn) {
        if f.attrs.iter().any(is_test_attr) {
            let mut body = Body {
                func: f.sig.ident.to_string(),
                out: self.out,
            };
            body.test_body(&f.block);
        }
        syn::visit::visit_item_fn(self, f);
    }
}

/// `#[test]`, `#[tokio::test]`, or any attribute path ending in `test`.
fn is_test_attr(attr: &syn::Attribute) -> bool {
    attr.path()
        .segments
        .last()
        .is_some_and(|s| s.ident == "test")
}

/// The fn-scoped rules over one `#[test]` body.
struct Body<'a> {
    func: String,
    out: &'a mut Vec<Finding>,
}

impl Body<'_> {
    fn test_body(&mut self, block: &syn::Block) {
        let stmts = block.stmts.as_slice();
        let rest = stmts
            .split_first()
            .filter(|(first, _)| is_tier_gate(first))
            .map_or(stmts, |(_, rest)| rest);
        self.printed_skips(rest);
        match rest.split_last() {
            Some((syn::Stmt::Expr(syn::Expr::Return(tail), _), init)) => {
                for stmt in init {
                    self.visit_stmt(stmt);
                }
                if let Some(expr) = &tail.expr {
                    self.visit_expr(expr);
                }
            }
            _ => {
                for stmt in rest {
                    self.visit_stmt(stmt);
                }
            }
        }
    }

    /// Rule 4 over one statement list: a print directly before a skip `return`.
    fn printed_skips(&mut self, stmts: &[syn::Stmt]) {
        for pair in stmts.windows(2) {
            let (Some(first), Some(second)) = (pair.first(), pair.get(1)) else {
                continue;
            };
            let (Some(line), Some(ret)) = (print_line(first), stmt_return(second)) else {
                continue;
            };
            if !fails_the_test(ret) {
                self.out.push(Finding {
                    rule: Rule::PrintedSkip,
                    func: Some(self.func.clone()),
                    line,
                });
            }
        }
    }
}

impl<'ast> Visit<'ast> for Body<'_> {
    fn visit_expr_return(&mut self, ret: &'ast syn::ExprReturn) {
        if !fails_the_test(ret) {
            self.out.push(Finding {
                rule: Rule::EarlyReturn,
                func: Some(self.func.clone()),
                line: ret.return_token.span.start().line,
            });
        }
        syn::visit::visit_expr_return(self, ret);
    }

    fn visit_block(&mut self, block: &'ast syn::Block) {
        self.printed_skips(&block.stmts);
        syn::visit::visit_block(self, block);
    }

    fn visit_expr_closure(&mut self, _: &'ast syn::ExprClosure) {}

    fn visit_expr_async(&mut self, _: &'ast syn::ExprAsync) {}

    fn visit_item(&mut self, _: &'ast syn::Item) {}
}

/// The `return` a statement consists of, if it is one.
const fn stmt_return(stmt: &syn::Stmt) -> Option<&syn::ExprReturn> {
    match stmt {
        syn::Stmt::Expr(syn::Expr::Return(ret), _) => Some(ret),
        _ => None,
    }
}

/// `return Err(..)`: an early exit that fails the test.
fn fails_the_test(ret: &syn::ExprReturn) -> bool {
    matches!(ret.expr.as_deref(), Some(syn::Expr::Call(call)) if path_ends(&call.func, &["Err"]))
}

/// The line of a print-macro statement, if `stmt` is one.
fn print_line(stmt: &syn::Stmt) -> Option<usize> {
    let mac = match stmt {
        syn::Stmt::Macro(m) => &m.mac,
        syn::Stmt::Expr(syn::Expr::Macro(m), _) => &m.mac,
        _ => return None,
    };
    let last = mac.path.segments.last()?;
    PRINT_MACROS
        .iter()
        .any(|p| last.ident == p)
        .then(|| last.ident.span().start().line)
}

/// The sanctioned tier gate: `if e2e_tier() == Tier::Unit { [print;] return[ Ok(())]; }`.
fn is_tier_gate(stmt: &syn::Stmt) -> bool {
    let syn::Stmt::Expr(syn::Expr::If(gate), _) = stmt else {
        return false;
    };
    let syn::Expr::Binary(cond) = gate.cond.as_ref() else {
        return false;
    };
    let reads_tier = matches!(
        cond.left.as_ref(),
        syn::Expr::Call(call) if call.args.is_empty() && path_ends(&call.func, &["e2e_tier"])
    );
    let is_unit = path_ends(&cond.right, &["Tier", "Unit"]);
    let Some((last, prints)) = gate.then_branch.stmts.split_last() else {
        return false;
    };
    gate.else_branch.is_none()
        && matches!(cond.op, syn::BinOp::Eq(_))
        && reads_tier
        && is_unit
        && prints.iter().all(|s| print_line(s).is_some())
        && stmt_return(last).is_some_and(|ret| match ret.expr.as_deref() {
            None => true,
            Some(syn::Expr::Call(call)) => {
                path_ends(&call.func, &["Ok"])
                    && call.args.len() == 1
                    && matches!(call.args.first(), Some(syn::Expr::Tuple(t)) if t.elems.is_empty())
            }
            Some(_) => false,
        })
}

/// Whether `expr` is a path whose trailing segments are `tail`.
fn path_ends(expr: &syn::Expr, tail: &[&str]) -> bool {
    let syn::Expr::Path(p) = expr else {
        return false;
    };
    let segs: Vec<String> = p
        .path
        .segments
        .iter()
        .map(|s| s.ident.to_string())
        .collect();
    segs.len() >= tail.len()
        && segs
            .iter()
            .rev()
            .zip(tail.iter().rev())
            .all(|(seg, want)| seg == want)
}

/// The workspace root and every test target's source files, relative to it.
#[allow(clippy::expect_used)] // an unreadable workspace manifest fails the scan: the designed outcome
fn test_target_files() -> (PathBuf, BTreeSet<PathBuf>) {
    let manifest = e2e_support::manifest_dir!().join("../../Cargo.toml");
    let cargo = ipe_env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let out = std::process::Command::new(cargo)
        .args([
            "metadata",
            "--no-deps",
            "--offline",
            "--format-version",
            "1",
        ])
        .arg("--manifest-path")
        .arg(&manifest)
        .output()
        .expect("`cargo metadata` must run");
    assert!(
        out.status.success(),
        "`cargo metadata` failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let meta: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("`cargo metadata` must print JSON");
    let root = PathBuf::from(
        meta.get("workspace_root")
            .and_then(serde_json::Value::as_str)
            .expect("metadata names the workspace root"),
    );
    let roots: Vec<PathBuf> = meta
        .get("packages")
        .and_then(serde_json::Value::as_array)
        .expect("metadata lists the packages")
        .iter()
        .filter_map(|p| p.get("targets").and_then(serde_json::Value::as_array))
        .flatten()
        .filter(|t| {
            t.get("kind")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|k| k.iter().any(|k| k == "test"))
        })
        .map(|t| {
            t.get("src_path")
                .and_then(serde_json::Value::as_str)
                .map(PathBuf::from)
                .expect("every metadata target names its source path")
        })
        .collect();
    assert!(!roots.is_empty(), "the workspace must declare test targets");
    let mut walk = ModWalk::default();
    for target in roots {
        walk.visit(&target, true);
    }
    assert!(
        walk.unresolved.is_empty(),
        "unresolvable `mod` declarations in test targets:\n{}",
        walk.unresolved.join("\n")
    );
    let files = walk
        .seen
        .iter()
        .map(|f| {
            f.strip_prefix(&root)
                .map_or_else(|_| f.clone(), Path::to_path_buf)
        })
        .collect();
    (root, files)
}

/// Follows every out-of-line `mod` declaration from the test-target roots.
#[derive(Default)]
struct ModWalk {
    seen: BTreeSet<PathBuf>,
    unresolved: Vec<String>,
}

impl ModWalk {
    /// Visit `file`; `mod_rs` when it is a crate root, a `mod.rs`, or a
    /// `#[path]` target, whose child modules live beside it.
    fn visit(&mut self, file: &Path, mod_rs: bool) {
        if !self.seen.insert(file.to_path_buf()) {
            return;
        }
        // An unreadable or unparsable file is refused by the per-file scan.
        let Some(parsed) = std::fs::read_to_string(file)
            .ok()
            .and_then(|text| syn::parse_file(&text).ok())
        else {
            return;
        };
        let dir = file.parent().map(Path::to_path_buf).unwrap_or_default();
        let base = if mod_rs {
            dir.clone()
        } else {
            file.file_stem()
                .map_or_else(|| dir.clone(), |stem| dir.join(stem))
        };
        self.items(file, &parsed.items, &dir, &base, false);
    }

    fn items(&mut self, file: &Path, items: &[syn::Item], dir: &Path, base: &Path, inline: bool) {
        for item in items {
            let syn::Item::Mod(m) = item else {
                continue;
            };
            let path_attr = path_attr(&m.attrs);
            if let Some((_, inner)) = &m.content {
                let nested =
                    path_attr.map_or_else(|| base.join(m.ident.to_string()), |p| base.join(p));
                self.items(file, inner, dir, &nested, true);
                continue;
            }
            let candidates = path_attr.as_deref().map_or_else(
                || {
                    let name = m.ident.to_string();
                    vec![
                        base.join(format!("{name}.rs")),
                        base.join(&name).join("mod.rs"),
                    ]
                },
                |p| vec![if inline { base.join(p) } else { dir.join(p) }],
            );
            if let Some(hit) = candidates.iter().find(|c| c.is_file()) {
                let mod_rs = path_attr.is_some() || hit.file_name().is_some_and(|n| n == "mod.rs");
                self.visit(hit, mod_rs);
                continue;
            }
            self.unresolved.push(format!(
                "{}: `mod {}` (tried {candidates:?})",
                file.display(),
                m.ident
            ));
        }
    }
}

/// The value of a `#[path = "…"]` attribute.
fn path_attr(attrs: &[syn::Attribute]) -> Option<String> {
    attrs.iter().find_map(|attr| match &attr.meta {
        syn::Meta::NameValue(nv) if nv.path.is_ident("path") => match &nv.value {
            syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Str(s),
                ..
            }) => Some(s.value()),
            _ => None,
        },
        _ => None,
    })
}

/// A fixture's findings, reading it from [`FIXTURES`].
#[allow(clippy::expect_used)] // a missing fixture fails the test: the designed outcome
fn fixture(name: &str) -> Vec<Finding> {
    let path = e2e_support::manifest_dir!().join(FIXTURES).join(name);
    let text = std::fs::read_to_string(&path).expect("read the skip-scan fixture");
    scan_source(&format!("fixture/{name}"), &text)
}

fn rules(findings: &[Finding]) -> BTreeSet<Rule> {
    findings.iter().map(|f| f.rule).collect()
}

#[test]
fn a_baked_bin_path_is_refused() {
    assert!(rules(&fixture("bare_env_bin.rs")).contains(&Rule::BakedBin));
}

#[test]
fn a_let_else_return_is_refused() {
    assert!(rules(&fixture("let_else_return.rs")).contains(&Rule::EarlyReturn));
}

#[test]
fn an_if_missing_return_is_refused() {
    assert!(rules(&fixture("if_missing_return.rs")).contains(&Rule::EarlyReturn));
}

#[test]
fn a_printed_skip_is_refused() {
    let got = rules(&fixture("eprintln_skip.rs"));
    assert!(got.contains(&Rule::PrintedSkip), "{got:?}");
    assert!(got.contains(&Rule::EarlyReturn), "{got:?}");
}

#[test]
fn a_direct_tier_read_is_refused() {
    assert!(rules(&fixture("direct_ipe_e2e.rs")).contains(&Rule::RawTierRead));
}

#[test]
fn an_unparsable_file_is_refused() {
    assert_eq!(
        rules(&fixture("unparsable.rs")),
        BTreeSet::from([Rule::Unparsable])
    );
}

#[test]
fn the_first_statement_tier_gate_is_accepted() {
    assert_eq!(fixture("tier_gate_ok.rs"), Vec::new());
}

#[test]
fn a_tier_gate_after_the_first_statement_is_an_early_return() {
    let src = "#[test] fn t() { let x = 1; \
               if e2e_tier() == Tier::Unit { return; } assert_eq!(x, 1); }";
    assert!(rules(&scan_source("inline.rs", src)).contains(&Rule::EarlyReturn));
}

#[test]
fn a_tier_gate_with_an_else_or_a_body_is_not_the_gate() {
    for src in [
        "#[test] fn t() { if e2e_tier() == Tier::Unit { return; } else { f(); } }",
        "#[test] fn t() { if e2e_tier() == Tier::Unit { f(); return; } g(); }",
        "#[test] fn t() { if e2e_tier() != Tier::Unit { return; } g(); }",
        "#[test] fn t() { if e2e_tier() == Tier::E2e { return; } g(); }",
    ] {
        assert!(
            rules(&scan_source("inline.rs", src)).contains(&Rule::EarlyReturn),
            "{src}"
        );
    }
}

#[test]
fn a_concat_built_bin_path_is_refused() {
    let src = "fn b() -> &'static str { env!(concat!(\"CARGO_BIN_EXE_\", \"ipe\")) }";
    assert!(rules(&scan_source("inline.rs", src)).contains(&Rule::BakedBin));
}

#[test]
fn a_bare_manifest_dir_is_refused_but_a_concat_include_is_not() {
    let bare = "fn d() -> &'static str { env!(\"CARGO_MANIFEST_DIR\") }";
    assert!(rules(&scan_source("inline.rs", bare)).contains(&Rule::BareManifestDir));
    let include =
        "const G: &str = include_str!(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/g.txt\"));";
    assert_eq!(scan_source("inline.rs", include), Vec::new());
}

#[test]
fn a_return_err_and_a_closure_return_are_not_skips() {
    let src = "#[test] fn t() -> Result<(), String> { \
               let f = |x: u8| { if x == 0 { return 1; } x }; \
               if f(0) != 1 { return Err(String::from(\"f\")); } Ok(()) }";
    assert_eq!(scan_source("inline.rs", src), Vec::new());
}

#[test]
fn no_test_target_skips_silently() {
    let (root, files) = test_target_files();
    for pinned in [
        "tools/e2e-support/tests/skip_scan.rs",
        "src/ipe-cli/tests/support/mod.rs",
    ] {
        assert!(
            files.contains(Path::new(pinned)),
            "the test-target walk must reach `{pinned}`; it found {} files",
            files.len()
        );
    }
    let mut matched = BTreeSet::new();
    let mut refused = Vec::new();
    for rel in &files {
        let rel_str = rel.to_string_lossy().replace('\\', "/");
        let text = std::fs::read_to_string(root.join(rel)).expect("read a test-target file");
        for finding in scan_source(&rel_str, &text) {
            if finding.rule.is_skip()
                && let Some(func) = finding.func.as_deref()
                && ENV_SKIPS
                    .iter()
                    .any(|&(file, name, _)| file == rel_str && name == func)
            {
                matched.insert((rel_str.clone(), func.to_owned()));
                continue;
            }
            refused.push(format!(
                "{rel_str}:{} {:?}{}",
                finding.line,
                finding.rule,
                finding
                    .func
                    .as_deref()
                    .map_or_else(String::new, |f| format!(" in `{f}`"))
            ));
        }
    }
    assert!(
        refused.is_empty(),
        "a test must fail, never return early, when what it needs is absent; resolve through \
         `e2e_support` and gate the tier only with a first-statement `e2e_tier()` check:\n{}",
        refused.join("\n")
    );
    let stale: Vec<String> = ENV_SKIPS
        .iter()
        .filter(|&&(file, func, _)| !matched.contains(&(file.to_owned(), func.to_owned())))
        .map(|&(file, func, why)| format!("{file} `{func}` ({why})"))
        .collect();
    assert!(
        stale.is_empty(),
        "`ENV_SKIPS` entries that no longer skip; remove them:\n{}",
        stale.join("\n")
    );
}
