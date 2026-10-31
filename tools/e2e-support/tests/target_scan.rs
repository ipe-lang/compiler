#![forbid(unsafe_code)]
//! Refuses every test-spawned cargo/`ipe` child whose target directory is not
//! decided by `tools/e2e-support/src/target.rs`.
//!
//! A shard's disk peak is bounded by terms that do not grow with the number of
//! tests only if that one decision point (`cargo_command`/`ipe_command` over a
//! typed [`BuildTarget`](e2e_support::target::BuildTarget)) is the ONE place a
//! test-spawned build picks its `CARGO_TARGET_DIR`. This scan walks every test
//! target of the workspace (via [`common::test_target_files`], which also
//! follows `mod`/`#[path]`/`cfg_attr(path)`) and refuses:
//!
//! 1. a literal (or `concat!`-joined literal) whose text contains
//!    `TARGET_DIR`, outside `target.rs`, at a place that sets, removes, or
//!    forwards it: a `.env`/`.env_remove`/`.envs` argument, an `env!`/
//!    `option_env!` argument, or a `const NAME: &str = …;` alias (caught at
//!    its declaration, independent of how it is later used) — attribute
//!    content (including a doc comment) is not executable, so it is not
//!    scanned, and a literal that is pattern DATA for an unrelated scan or
//!    message table (not an operation on the variable itself) is not this
//!    rule's concern;
//! 2. the exact string literal `"cargo"`/`"CARGO"` outside `target.rs`, at a
//!    `Type::new(…)` call or an `env!`/`option_env!` argument — the same
//!    operational scoping as rule 1, for the same reason: this blocks a
//!    hand-made cargo spawn, not a program-name comparison inside an
//!    unrelated check;
//! 3. a hand-built `Command` from an `ipe` binary reference
//!    (`cargo_bin!("ipe")`, the literal `CARGO_BIN_EXE_ipe`, `require_bin
//!    ("ipe")`) inside a fn that also holds a literal naming a build verb but
//!    never calls `target::ipe_command` — [`ALLOWLIST`] exempts a reasoned
//!    site;
//! 4. what it cannot read: an unparsable file, a bare `include!` (which splices
//!    unseen text `syn` never expands), and a `macro_rules!` body that
//!    independently trips rule 3's shape (a macro body has no fn boundary to
//!    attribute the finding to, so it cannot be told apart from a compliant
//!    call site).
//!
//! A `#[path]`/`cfg_attr(path)` module is not itself refused: the walk
//! resolves and reads it like any other file, so the same four rules apply to
//! its content once reached.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::str::FromStr;

use proc_macro2::{TokenStream, TokenTree};
use quote::ToTokens;
use syn::visit::Visit;

mod common;

/// The target-scan fixtures, relative to this crate's manifest directory.
const FIXTURES: &str = "tests/fixtures/target_scan";

/// The one file allowed to name the target-directory variable or `cargo`
/// literally: every other test-spawned build goes through it.
const TARGET_RS: &str = "tools/e2e-support/src/target.rs";

/// This file's own workspace-relative path. Rules 1-2 exempt it the same way
/// they exempt [`TARGET_RS`]: a detector's source names the patterns it looks
/// for (`TARGET_DIR_SUBSTR` below), and that is not itself an operation this
/// scan's own rules are about — exactly as `cargo_step_scan.rs`'s own
/// `"cargo"`-matching code is not a cargo spawn.
const SELF: &str = "tools/e2e-support/tests/target_scan.rs";

/// The substring rule 1 refuses outside [`TARGET_RS`]/[`SELF`].
const TARGET_DIR_SUBSTR: &str = "TARGET_DIR";

/// The literal `ipe` binary-path variable rule 3 recognises directly
/// (`cargo_bin!("ipe")` expands to `env!(concat!("CARGO_BIN_EXE_", "ipe"))`,
/// i.e. this same literal).
const IPE_BIN_ENV: &str = "CARGO_BIN_EXE_ipe";

/// The `ipe` build verbs rule 3 treats as the mark of a build/run.
const BUILD_VERBS: &[&str] = &["build", "run", "release", "test", "watch", "dev", "eject"];

/// Rule-3 exemptions: `(file, fn, reason)`. Every entry needs a reason, and a
/// test fails if the named fn no longer exists or no longer trips the rule.
const ALLOWLIST: &[(&str, &str, &str)] = &[(
    "src/ipe-cli/tests/target_dir_windows_gnu.rs",
    "build",
    "exercises ipe's own CARGO_TARGET_DIR resolution from outside (unset, a \
     non-ASCII pin, an unlinkable sysroot/pin) — routing through `ipe_command` \
     would fix the exact value this test varies, defeating it",
)];

/// A refused construct.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Rule {
    /// A literal (or `concat!`-joined literal) naming the target-directory
    /// variable outside [`TARGET_RS`].
    TargetDirLiteral,
    /// The literal program name `"cargo"`/`"CARGO"` outside [`TARGET_RS`].
    CargoLiteral,
    /// A hand-built `Command` from an `ipe` binary reference in a fn that
    /// also names a build verb but never calls `target::ipe_command`.
    UnmigratedIpeBuild,
    /// Content the scan cannot safely attribute to a fn or expand: an
    /// unparsable file, a bare `include!`, or a `macro_rules!` body that
    /// independently trips the unmigrated-build shape.
    Unreadable,
}

/// One refused site.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Finding {
    rule: Rule,
    /// The enclosing `#[test]`/fn, for the fn-scoped rule 3.
    func: Option<String>,
    line: usize,
}

const fn unreadable(line: usize) -> Finding {
    Finding {
        rule: Rule::Unreadable,
        func: None,
        line,
    }
}

/// Every finding in `text`, a file at workspace-relative path `rel`.
fn scan_source(rel: &str, text: &str) -> Vec<Finding> {
    let Ok(tokens) = TokenStream::from_str(text) else {
        return vec![unreadable(0)];
    };
    let Ok(file) = syn::parse_file(text) else {
        return vec![unreadable(0)];
    };
    let mut out = Vec::new();
    if rel != TARGET_RS && rel != SELF {
        let trees: Vec<TokenTree> = tokens.into_iter().collect();
        scan_tokens(&trees, &mut out);
        scan_const_items(&file.items, &mut out);
    }
    let consts = const_strings(&file.items);
    let mut funcs = FuncScan {
        consts: &consts,
        out: &mut out,
    };
    funcs.visit_file(&file);
    out.sort();
    out
}

/// Rules 1-2's operational trigger points and the bare-`include!` refusal: a
/// raw token walk that reaches every nested group (a `macro_rules!` body
/// among them) the same way code does, skipping only attribute content
/// (declarative, never executable — this is what keeps a doc comment naming
/// the variable from tripping rule 1).
///
/// A literal is only ever rule 1/2 material at a place that actually sets,
/// removes, forwards, or spawns: the argument list of `.env`/`.env_remove`/
/// `.envs`/`Type::new`, or of `env!`/`option_env!`. Anywhere else — a
/// `.contains("cargo")` check, a message-table literal, a match-arm pattern —
/// the same text is just data an unrelated check is comparing against, never
/// an operation on the variable or program itself; [`scan_const_items`]
/// separately catches a `const` alias at its declaration.
fn scan_tokens(trees: &[TokenTree], out: &mut Vec<Finding>) {
    for (i, tree) in trees.iter().enumerate() {
        // An outer attribute's group is preceded by `#`; an inner attribute's
        // (`#![doc = "…"]`, e.g. a module/crate-level doc comment) by `#!`.
        let is_attr = (i > 0 && is_hash(trees.get(i - 1)))
            || (i > 1 && is_hash(trees.get(i - 2)) && is_bang(trees.get(i - 1)));
        let TokenTree::Group(g) = tree else { continue };
        if is_attr {
            continue;
        }
        let inner: Vec<TokenTree> = g.stream().into_iter().collect();
        match macro_name(trees, i).as_deref() {
            Some("include") => out.push(unreadable(g.span().start().line)),
            Some("env" | "option_env") => scan_literals_blind(&inner, out),
            _ => {}
        }
        if env_call_args(trees, i) || new_call_args(trees, i) {
            scan_literals_blind(&inner, out);
        }
        scan_tokens(&inner, out);
    }
}

/// Whether `trees[i]` is the parenthesised argument list of a `.env`/
/// `.env_remove`/`.envs` method call (preceded by `. name`).
fn env_call_args(trees: &[TokenTree], i: usize) -> bool {
    let Some(TokenTree::Ident(name)) = i.checked_sub(1).and_then(|j| trees.get(j)) else {
        return false;
    };
    let Some(TokenTree::Punct(dot)) = i.checked_sub(2).and_then(|j| trees.get(j)) else {
        return false;
    };
    dot.as_char() == '.' && matches!(name.to_string().as_str(), "env" | "env_remove" | "envs")
}

/// Whether `trees[i]` is the parenthesised argument list of a `Type::new(…)`
/// call (preceded by `:: new`), whichever path the type carries.
fn new_call_args(trees: &[TokenTree], i: usize) -> bool {
    let Some(TokenTree::Ident(name)) = i.checked_sub(1).and_then(|j| trees.get(j)) else {
        return false;
    };
    let Some(TokenTree::Punct(colon2)) = i.checked_sub(2).and_then(|j| trees.get(j)) else {
        return false;
    };
    let Some(TokenTree::Punct(colon1)) = i.checked_sub(3).and_then(|j| trees.get(j)) else {
        return false;
    };
    name == "new" && colon2.as_char() == ':' && colon1.as_char() == ':'
}

/// Every literal (or `concat!`-joined literal) in `trees`, recursing into
/// every nested group — used only over the bounded argument list of an
/// operational call or macro rules 1-2 name, never over a whole file.
fn scan_literals_blind(trees: &[TokenTree], out: &mut Vec<Finding>) {
    for (i, tree) in trees.iter().enumerate() {
        match tree {
            TokenTree::Group(g) => {
                if macro_name(trees, i).as_deref() == Some("concat")
                    && let Some(joined) = concat_pieces(g.stream())
                {
                    push_literal_finding(&joined, g.span().start().line, out);
                }
                let inner: Vec<TokenTree> = g.stream().into_iter().collect();
                scan_literals_blind(&inner, out);
            }
            TokenTree::Literal(lit) => {
                if let Some(v) = str_value(lit) {
                    push_literal_finding(&v, lit.span().start().line, out);
                }
            }
            TokenTree::Ident(_) | TokenTree::Punct(_) => {}
        }
    }
}

/// Rule 1 (contains [`TARGET_DIR_SUBSTR`]) and rule 2 (exact `cargo`/`CARGO`)
/// applied to one resolved literal value.
fn push_literal_finding(v: &str, line: usize, out: &mut Vec<Finding>) {
    if v.contains(TARGET_DIR_SUBSTR) {
        out.push(Finding {
            rule: Rule::TargetDirLiteral,
            func: None,
            line,
        });
    }
    if v == "cargo" || v == "CARGO" {
        out.push(Finding {
            rule: Rule::CargoLiteral,
            func: None,
            line,
        });
    }
}

/// A file-scoped `const NAME: &str = "…";` (or `= concat!(…);`), including
/// inside a `mod { … }` block, applying rules 1-2 at its declaration —
/// independent of how (or whether) the alias is later used, so the alias
/// fixture is caught the same way a direct literal is.
fn scan_const_items(items: &[syn::Item], out: &mut Vec<Finding>) {
    for item in items {
        match item {
            syn::Item::Const(c) => {
                if let Some(v) = const_literal_value(&c.expr) {
                    push_literal_finding(&v, c.ident.span().start().line, out);
                }
            }
            syn::Item::Mod(m) => {
                if let Some((_, inner)) = &m.content {
                    scan_const_items(inner, out);
                }
            }
            _ => {}
        }
    }
}

/// The string value of a `const`'s initializer, when it is a direct string
/// literal or a `concat!` of such — the two shapes an alias can take.
fn const_literal_value(expr: &syn::Expr) -> Option<String> {
    match expr {
        syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Str(s),
            ..
        }) => Some(s.value()),
        syn::Expr::Macro(m) if m.mac.path.is_ident("concat") => concat_pieces(m.mac.tokens.clone()),
        _ => None,
    }
}

fn is_hash(tree: Option<&TokenTree>) -> bool {
    matches!(tree, Some(TokenTree::Punct(p)) if p.as_char() == '#')
}

fn is_bang(tree: Option<&TokenTree>) -> bool {
    matches!(tree, Some(TokenTree::Punct(p)) if p.as_char() == '!')
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

/// The string a `concat!`'s comma-separated pieces (literals, or a nested
/// `concat!`) join to, or `None` if a piece is not one of those two shapes.
fn concat_pieces(tokens: TokenStream) -> Option<String> {
    let trees: Vec<TokenTree> = tokens.into_iter().collect();
    let mut out = String::new();
    let mut i = 0;
    while let Some(tree) = trees.get(i) {
        match tree {
            TokenTree::Literal(l) => {
                out.push_str(&str_value(l)?);
                i += 1;
            }
            TokenTree::Ident(id)
                if id == "concat"
                    && matches!(trees.get(i + 1), Some(TokenTree::Punct(p)) if p.as_char() == '!') =>
            {
                let TokenTree::Group(g) = trees.get(i + 2)? else {
                    return None;
                };
                out.push_str(&concat_pieces(g.stream())?);
                i += 3;
            }
            TokenTree::Punct(p) if p.as_char() == ',' => i += 1,
            _ => return None,
        }
    }
    Some(out)
}

/// The value of a string literal token.
fn str_value(lit: &proc_macro2::Literal) -> Option<String> {
    match syn::Lit::new(lit.clone()) {
        syn::Lit::Str(s) => Some(s.value()),
        _ => None,
    }
}

/// Every file-scoped `const NAME: &str = "…";`, including inside a `mod { … }`
/// block, so a build verb hidden behind a named alias (`const RUN: &str =
/// "run";`) is still recognised.
fn const_strings(items: &[syn::Item]) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    collect_consts(items, &mut map);
    map
}

fn collect_consts(items: &[syn::Item], map: &mut BTreeMap<String, String>) {
    for item in items {
        match item {
            syn::Item::Const(c) => {
                if let syn::Expr::Lit(syn::ExprLit {
                    lit: syn::Lit::Str(s),
                    ..
                }) = &*c.expr
                {
                    map.insert(c.ident.to_string(), s.value());
                }
            }
            syn::Item::Mod(m) => {
                if let Some((_, inner)) = &m.content {
                    collect_consts(inner, map);
                }
            }
            _ => {}
        }
    }
}

/// The rule-3 shape found over one fn or macro body's tokens.
#[derive(Default)]
struct Verb3 {
    has_verb: bool,
    has_ipe_ref: bool,
    has_ipe_command: bool,
}

/// The rule-3 shape of `tokens`, resolving a build-verb alias through `consts`.
fn verb3(tokens: TokenStream, consts: &BTreeMap<String, String>) -> Verb3 {
    let mut out = Verb3::default();
    scan_verb3(tokens, consts, &mut out);
    out
}

fn scan_verb3(tokens: TokenStream, consts: &BTreeMap<String, String>, out: &mut Verb3) {
    let trees: Vec<TokenTree> = tokens.into_iter().collect();
    for (i, tree) in trees.iter().enumerate() {
        match tree {
            TokenTree::Group(g) => {
                if macro_name(&trees, i).as_deref() == Some("cargo_bin")
                    && let Some(TokenTree::Literal(lit)) = g.stream().into_iter().next()
                    && str_value(&lit).as_deref() == Some("ipe")
                {
                    out.has_ipe_ref = true;
                }
                scan_verb3(g.stream(), consts, out);
            }
            TokenTree::Literal(lit) => {
                if let Some(v) = str_value(lit) {
                    if BUILD_VERBS.contains(&v.as_str()) {
                        out.has_verb = true;
                    }
                    if v == IPE_BIN_ENV {
                        out.has_ipe_ref = true;
                    }
                }
            }
            TokenTree::Ident(ident) => {
                let name = ident.to_string();
                if consts
                    .get(&name)
                    .is_some_and(|v| BUILD_VERBS.contains(&v.as_str()))
                {
                    out.has_verb = true;
                }
                if name == "ipe_command" {
                    out.has_ipe_command = true;
                }
                if name == "require_bin"
                    && let Some(TokenTree::Group(args)) = trees.get(i + 1)
                    && let Some(TokenTree::Literal(lit)) = args.stream().into_iter().next()
                    && str_value(&lit).as_deref() == Some("ipe")
                {
                    out.has_ipe_ref = true;
                }
            }
            TokenTree::Punct(_) => {}
        }
    }
}

/// Visits every fn (free or `impl`-method) and `macro_rules!` body, applying
/// rule 3 to each — an `impl Case { fn build(..) }` hand-building an `ipe`
/// `Command` is the same shape as a free fn doing it, so both get the same
/// fn-boundary attribution.
struct FuncScan<'a> {
    consts: &'a BTreeMap<String, String>,
    out: &'a mut Vec<Finding>,
}

impl FuncScan<'_> {
    /// Rule 3 over one fn's `(name, body, line)`, shared by a free fn and an
    /// `impl`-method fn. Pushes the finding regardless of [`ALLOWLIST`]: the
    /// one caller that checks `rel` against it
    /// ([`no_test_target_spawns_a_build_outside_the_one_decision_point`])
    /// needs the raw finding to mark the entry matched, not a pre-filtered
    /// stream that would make every entry look stale.
    fn check_fn_body(&mut self, name: &syn::Ident, body: TokenStream) {
        let shape = verb3(body, self.consts);
        if shape.has_verb && shape.has_ipe_ref && !shape.has_ipe_command {
            self.out.push(Finding {
                rule: Rule::UnmigratedIpeBuild,
                func: Some(name.to_string()),
                line: name.span().start().line,
            });
        }
    }
}

impl<'ast> Visit<'ast> for FuncScan<'_> {
    fn visit_item_fn(&mut self, f: &'ast syn::ItemFn) {
        self.check_fn_body(&f.sig.ident, f.block.as_ref().to_token_stream());
        syn::visit::visit_item_fn(self, f);
    }

    fn visit_impl_item_fn(&mut self, f: &'ast syn::ImplItemFn) {
        self.check_fn_body(&f.sig.ident, f.block.to_token_stream());
        syn::visit::visit_impl_item_fn(self, f);
    }

    fn visit_item_macro(&mut self, m: &'ast syn::ItemMacro) {
        if m.ident.is_some() && m.mac.path.is_ident("macro_rules") {
            let shape = verb3(m.mac.tokens.clone(), self.consts);
            if shape.has_verb && shape.has_ipe_ref && !shape.has_ipe_command {
                let line = m
                    .mac
                    .path
                    .segments
                    .first()
                    .map_or(0, |s| s.ident.span().start().line);
                self.out.push(unreadable(line));
            }
        }
        syn::visit::visit_item_macro(self, m);
    }
}

fn rules(findings: &[Finding]) -> BTreeSet<Rule> {
    findings.iter().map(|f| f.rule).collect()
}

/// A fixture's findings, reading it from [`FIXTURES`].
#[allow(clippy::expect_used)] // a missing fixture fails the test: the designed outcome
fn fixture(name: &str) -> Vec<Finding> {
    let path = e2e_support::manifest_dir!().join(FIXTURES).join(name);
    let text = std::fs::read_to_string(&path).expect("read the target-scan fixture");
    scan_source(&format!("fixture/{name}"), &text)
}

#[test]
fn a_target_dir_literal_is_refused() {
    assert!(rules(&fixture("target_dir_literal.rs.txt")).contains(&Rule::TargetDirLiteral));
}

#[test]
fn a_target_dir_const_alias_is_still_the_literal() {
    assert!(rules(&fixture("target_dir_const_alias.rs.txt")).contains(&Rule::TargetDirLiteral));
}

#[test]
fn a_concat_joined_target_dir_is_refused() {
    assert!(rules(&fixture("target_dir_concat.rs.txt")).contains(&Rule::TargetDirLiteral));
}

#[test]
fn an_env_remove_of_target_dir_is_refused() {
    assert!(rules(&fixture("target_dir_env_remove.rs.txt")).contains(&Rule::TargetDirLiteral));
}

#[test]
fn a_target_dir_in_envs_is_refused() {
    assert!(rules(&fixture("target_dir_envs.rs.txt")).contains(&Rule::TargetDirLiteral));
}

#[test]
fn a_bare_cargo_spawn_is_refused() {
    assert!(rules(&fixture("cargo_new.rs.txt")).contains(&Rule::CargoLiteral));
}

#[test]
fn an_env_cargo_spawn_is_refused() {
    assert!(rules(&fixture("cargo_env_bin.rs.txt")).contains(&Rule::CargoLiteral));
}

#[test]
fn a_command_alias_still_catches_cargo() {
    assert!(rules(&fixture("cargo_aliased_command.rs.txt")).contains(&Rule::CargoLiteral));
}

#[test]
fn a_cargo_spawn_inside_a_macro_rules_body_is_still_reached() {
    assert!(rules(&fixture("macro_rules_cargo_spawn.rs.txt")).contains(&Rule::CargoLiteral));
}

#[test]
fn an_unmigrated_build_inside_a_macro_rules_body_is_unreadable() {
    assert!(rules(&fixture("macro_rules_unmigrated_build.rs.txt")).contains(&Rule::Unreadable));
}

#[test]
fn a_bare_include_is_unreadable() {
    assert!(rules(&fixture("bare_include.rs.txt")).contains(&Rule::Unreadable));
}

#[test]
fn an_args_run_verb_without_ipe_command_is_refused() {
    assert!(rules(&fixture("unmigrated_args_run.rs.txt")).contains(&Rule::UnmigratedIpeBuild));
}

#[test]
fn a_const_aliased_run_verb_without_ipe_command_is_refused() {
    assert!(rules(&fixture("unmigrated_const_verb.rs.txt")).contains(&Rule::UnmigratedIpeBuild));
}

#[test]
fn a_migrated_build_through_ipe_command_is_accepted() {
    assert_eq!(fixture("migrated_ipe_command.rs.txt"), Vec::new());
}

#[test]
fn a_doc_comment_naming_the_variable_is_not_a_literal_refusal() {
    assert_eq!(
        fixture("doc_comment_mentions_target_dir.rs.txt"),
        Vec::new()
    );
}

#[test]
fn an_unparsable_file_is_refused() {
    assert_eq!(
        rules(&fixture("unparsable.rs.txt")),
        BTreeSet::from([Rule::Unreadable])
    );
}

/// A file reached only through a `#[path]` retarget gets the same rules
/// applied to its content once the walk resolves and reads it — proven here
/// over a fixture pair the real `cargo metadata` walk never reaches, since a
/// standalone `#[path]` module target only resolves relative to a real crate
/// target (the real-repo property is pinned separately, below, via a file the
/// workspace already reaches this way).
#[test]
fn a_path_module_target_is_reached_and_scanned() {
    let dir = e2e_support::manifest_dir!().join(FIXTURES);
    let root = std::fs::read_to_string(dir.join("path_module_root.rs.txt"))
        .expect("read the path-module root fixture");
    let file = syn::parse_file(&root).expect("parse the path-module root fixture");
    let target = file
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Mod(m) => common::path_attr(&m.attrs),
            _ => None,
        })
        .expect("the root fixture declares a `#[path]` module");
    let text = std::fs::read_to_string(dir.join(&target))
        .expect("read the `#[path]` target the root fixture names");
    assert!(rules(&scan_source(&target, &text)).contains(&Rule::CargoLiteral));
}

#[test]
fn no_test_target_spawns_a_build_outside_the_one_decision_point() {
    let (root, files) = common::test_target_files();
    for pinned in [
        "tools/e2e-support/tests/target_scan.rs",
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
            if finding.rule == Rule::UnmigratedIpeBuild
                && let Some(func) = finding.func.as_deref()
                && ALLOWLIST
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
        "a test-spawned cargo/`ipe` child must get its target directory from \
         `e2e_support::target`'s one decision point:\n{}",
        refused.join("\n")
    );
    let stale: Vec<String> = ALLOWLIST
        .iter()
        .filter(|&&(file, func, _)| !matched.contains(&(file.to_owned(), func.to_owned())))
        .map(|&(file, func, why)| format!("{file} `{func}` ({why})"))
        .collect();
    assert!(
        stale.is_empty(),
        "`ALLOWLIST` entries that no longer trip rule 3; remove them:\n{}",
        stale.join("\n")
    );
}
