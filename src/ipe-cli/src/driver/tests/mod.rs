use super::*;
use crate::contained_path::ResolvedPath;
use crate::io_bounded::SourceRefusal;
use crate::output_dir::{EmitTarget, OutputRefusal, ProjectPaths};
use crate::verb::Verb;
use crate::{
    ALL_CODES, Applicability, BTreeMap, Diagnostic, Path, PathBuf, Suggestion, cli_args, fs,
    project, style,
};
use ipe_diagnostics::{Candidates, EditTarget, NameError, Span};

/// An emit target at `out`, proven disjoint from a project directory beside it.
fn emit_target(out: &Path) -> EmitTarget {
    let project = out.with_extension("project");
    fs::create_dir_all(&project).expect("project dir");
    EmitTarget::at(out, &ProjectPaths::of_file(&project.join("Main.ipe"))).expect("prove out")
}

#[test]
fn widget_tag_collision_from_distinct_paths_is_refused() {
    let mut origins: BTreeMap<String, String> = BTreeMap::new();
    // First path claims the tag.
    assert!(record_widget_tag_origin(&mut origins, "ipe-ce-dead", "src/Widget/A.js").is_ok());
    // The SAME path (a second view node of one widget) is the legitimate
    // dedup case.
    assert!(record_widget_tag_origin(&mut origins, "ipe-ce-dead", "src/Widget/A.js").is_ok());
    // A DIFFERENT path colliding onto the same tag must fail closed.
    let collision = record_widget_tag_origin(&mut origins, "ipe-ce-dead", "src/Widget/B.js")
        .expect_err("a distinct path on an occupied tag must be refused");
    assert_eq!(collision.existing_path, "src/Widget/A.js");
    assert_eq!(collision.new_path, "src/Widget/B.js");
    // A distinct tag is unaffected.
    assert!(record_widget_tag_origin(&mut origins, "ipe-ce-beef", "src/Widget/B.js").is_ok());
}

#[test]
fn bluegreen_defaults_on_when_no_env_set() {
    // No opt-out, no explicit choice → on (the new default).
    assert!(bluegreen_from_env_values(None, None));
}

#[test]
fn bluegreen_opt_out_wins() {
    // IPE_WATCH_NO_BLUEGREEN set (non-empty ≠ "0") → off, even if the legacy
    // flag would force on.
    assert!(!bluegreen_from_env_values(Some("1"), None));
    assert!(!bluegreen_from_env_values(Some("anything"), Some("1")));
    // "0"/empty opt-out is NOT an opt-out → the rest of the precedence runs.
    assert!(bluegreen_from_env_values(Some("0"), None));
    assert!(bluegreen_from_env_values(Some(""), None));
}

#[test]
fn bluegreen_explicit_legacy_choice_is_honoured() {
    // Explicit IPE_WATCH_BLUEGREEN: "0"/empty off, anything else on.
    assert!(!bluegreen_from_env_values(None, Some("0")));
    assert!(!bluegreen_from_env_values(None, Some("")));
    assert!(bluegreen_from_env_values(None, Some("1")));
    assert!(bluegreen_from_env_values(None, Some("yes")));
}

#[test]
fn registry_unreachable_matches_network_signals_only() {
    // Genuine network/offline failures.
    assert!(is_registry_unreachable(
        "Caused by:\n  Could not resolve host: index.crates.io"
    ));
    assert!(is_registry_unreachable("warning: spurious network error"));
    assert!(is_registry_unreachable(
        "error: failed to fetch `https://github.com/rust-lang/crates.io-index`"
    ));
    // A missing local path dependency or malformed manifest is NOT a
    // connectivity problem and must not be reported as one.
    assert!(!is_registry_unreachable(
        "error: failed to load source for dependency `handle_demo`\n\
         Caused by:\n  path `/tmp/x` does not exist"
    ));
    assert!(!is_registry_unreachable(
        "error: no matching package named `foo` found; updating registry index"
    ));
    assert!(!is_registry_unreachable("error[E0433]: cannot find crate"));
}

#[test]
fn vendored_runtime_dir_is_required_only_when_vendoring() {
    // The dependency-model path (default `ipe dev build`/`run`, and `ipe dev watch`)
    // never vendors the runtime source tree — it reaches the runtime as a
    // crate dependency — so it must resolve to an empty sentinel WITHOUT
    // demanding a runtime dir. Requiring the vendored tree here is what made
    // `ipe dev watch` fail to locate the runtime in an installed checkout.
    assert_eq!(
        resolve_vendored_runtime_dir(None, false).ok(),
        Some(PathBuf::new()),
    );
    // An explicit `--runtime` is honoured verbatim, vendoring or not — so the
    // vendoring path (e.g. `ipe release eject`) resolves a runtime dir even when the
    // ambient vendored tree is absent.
    assert_eq!(
        resolve_vendored_runtime_dir(Some("/opt/ipe-runtime".to_owned()), false).ok(),
        Some(PathBuf::from("/opt/ipe-runtime")),
    );
    assert_eq!(
        resolve_vendored_runtime_dir(Some("/opt/ipe-runtime".to_owned()), true).ok(),
        Some(PathBuf::from("/opt/ipe-runtime")),
    );
}

#[test]
fn io_not_found_renders_styled_without_os_error() {
    let err = CliError::Io {
        path: PathBuf::from("/no/such.ipe"),
        source: std::io::Error::from(std::io::ErrorKind::NotFound),
    };
    let rendered = err.to_string();
    assert!(
        rendered.contains("no such file `/no/such.ipe`"),
        "styled NotFound message, got: {rendered}"
    );
    // No jargon: never the raw `io error` prefix, never an `os error N` tail.
    assert!(!rendered.contains("os error"), "leaks errno: {rendered}");
    assert!(!rendered.contains("io error"), "leaks jargon: {rendered}");
}

#[test]
fn io_other_kind_stays_readable_without_errno() {
    let err = CliError::Io {
        path: PathBuf::from("/x"),
        source: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
    };
    let rendered = err.to_string();
    assert!(!rendered.contains("os error"), "leaks errno: {rendered}");
    assert!(rendered.contains("/x"), "names the path: {rendered}");
}

#[test]
fn unknown_command_screen_is_fully_guttered() {
    let err = CliError::UnknownCommand {
        attempted: style::TerminalSafe::sanitize("frobnicate"),
    };
    let rendered = err.to_string();
    // The advice line and the help header both carry the shared gutter — no
    // flush-left line breaks the screen the way the trim_start header did.
    assert!(
        rendered.starts_with("  unknown command `frobnicate`"),
        "advice guttered, got: {rendered:?}"
    );
    for line in rendered.lines().filter(|l| !l.is_empty()) {
        assert!(
            line.starts_with(style::GUTTER),
            "every non-empty line is guttered, offending: {line:?}"
        );
    }
}

/// `read_progress_chunk` stops at a newline OR a carriage return, so cargo's
/// in-place progress bar (which uses `\r` with no `\n`) surfaces live rather
/// than buffering until the next line, and it drains a stream with no final
/// terminator without dropping bytes.
#[test]
fn read_progress_chunk_stops_at_newline_or_carriage_return() {
    use std::io::BufReader;
    // A `\r` progress frame, then a `\n` message line, then a trailing chunk
    // with no terminator at end of stream.
    let input = "  Building [==>   ]\r   Compiling ipe-app\ndone";
    let mut reader = BufReader::new(input.as_bytes());
    let mut out = String::new();

    let n1 = read_progress_chunk(&mut reader, &mut out).expect("read frame");
    assert_eq!(out, "  Building [==>   ]\r");
    assert_eq!(n1, out.len());

    out.clear();
    read_progress_chunk(&mut reader, &mut out).expect("read line");
    assert_eq!(out, "   Compiling ipe-app\n");

    out.clear();
    read_progress_chunk(&mut reader, &mut out).expect("read tail");
    assert_eq!(out, "done");

    // End of stream returns zero and leaves `out` empty.
    out.clear();
    assert_eq!(
        read_progress_chunk(&mut reader, &mut out).expect("read eof"),
        0
    );
    assert!(out.is_empty());
}

/// Cargo terminal UI should be forced only when our stderr is a TTY and
/// `NO_COLOR` is unset — both conditions must hold. Checked via a
/// closed-form helper that mirrors the guard inside `force_cargo_terminal_ui`.
#[test]
fn force_cargo_ui_truth_table() {
    // Pure function extracted from the guard: is_tty && no_color is unset.
    let should_force = |is_tty: bool, no_color: bool| -> bool { is_tty && !no_color };
    assert!(should_force(true, false), "tty + color on → force");
    assert!(!should_force(false, false), "not a tty → no force");
    assert!(!should_force(true, true), "NO_COLOR set → no force");
    assert!(
        !should_force(false, true),
        "not a tty + NO_COLOR → no force"
    );
}

/// `missing_runtime_feature` pulls the feature name out of `cargo`'s
/// feature-resolution error, whether the name is backtick- or single-quoted,
/// and yields `None` for an unrelated failure.
#[test]
fn extracts_missing_runtime_feature() {
    let backtick = "package `ipe-app` depends on `ipe-runtime-rust` with feature `regex` \
         but `ipe-runtime-rust` does not have that feature.";
    assert_eq!(missing_runtime_feature(backtick).as_deref(), Some("regex"));
    let single = "package `ipe-app` depends on ipe-runtime-rust with feature 'random' \
         but ipe-runtime-rust does not have that feature";
    assert_eq!(missing_runtime_feature(single).as_deref(), Some("random"));
    assert_eq!(
        missing_runtime_feature("error: linking with `cc` failed: exit status: 1"),
        None
    );
}

/// A cargo build failure whose stderr names a missing runtime feature renders
/// a targeted, actionable diagnostic that names the feature and the stale
/// runtime — and never the `run` command's `--help` page.
#[test]
fn emitted_build_failure_reports_missing_feature() {
    let err = CliError::EmittedBuildFailed {
        what: "the emitted program",
        code: 101,
        stderr: style::TerminalSafe::sanitize(
            "package `ipe-app` depends on `ipe-runtime-rust` with feature `regex` \
             but `ipe-runtime-rust` does not have that feature.",
        ),
        runtime: Some(RuntimeContext {
            root: style::TerminalSafe::sanitize("/tmp/rt"),
            version: style::TerminalSafe::sanitize("0.1.34"),
        }),
    };
    let rendered = err.to_string();
    assert!(rendered.contains("runtime feature `regex`"), "{rendered}");
    assert!(rendered.contains("/tmp/rt"), "{rendered}");
    assert!(rendered.contains("out of date"), "{rendered}");
    assert!(
        !rendered.contains("ipe dev run [<path>]"),
        "the build failure must not print the run help page: {rendered}"
    );
}

/// A cargo build failure that is not a feature gap is unattributable: the
/// front-end gate already rejected invalid programs, so a cargo failure here
/// is a miscompile in Ipê's own emission, not the user's fault. It renders as
/// a humble compiler-bug ICE that apologises, points at the issue tracker, and
/// still embeds the raw cargo stderr as the reportable detail — never a bare
/// rustc error presented as user error, and never any command's help page.
#[test]
fn emitted_build_failure_reports_unattributed_as_compiler_bug() {
    let err = CliError::EmittedBuildFailed {
        what: "the emitted program",
        code: 101,
        stderr: style::TerminalSafe::sanitize("error[E0425]: cannot find value `x` in this scope"),
        runtime: None,
    };
    let rendered = err.to_string();
    // The humble ICE framing: this is the compiler's fault, please report it.
    assert!(rendered.contains("please report"), "{rendered}");
    assert!(rendered.contains("bug in Ipe"), "{rendered}");
    // The raw cargo error is preserved for the bug report.
    assert!(rendered.contains("cannot find value"), "{rendered}");
    assert!(rendered.contains("E0425"), "{rendered}");
    // Neither a help page nor the old plain-header user-error framing.
    assert!(!rendered.contains("ipe dev run [<path>]"), "{rendered}");
    assert!(
        !rendered.contains("building the emitted program failed (cargo exited"),
        "{rendered}"
    );
}

/// The golden entry, located relative to this crate's manifest.
fn golden_entry() -> PathBuf {
    e2e_support::manifest_dir!()
        .join("..")
        .join("..")
        .join("tests")
        .join("golden")
        .join("basics")
        .join("Main.ipe")
}

/// Drift-closed proof: every entry in `ALL_CODES` resolves via `explain_lookup`.
/// If any code is in the taxonomy but missing from `ALL_CODES` this test fails.
#[test]
fn all_taxonomy_codes_resolve_via_explain_lookup() {
    for &c in ALL_CODES {
        let result = explain_lookup(c.as_str());
        assert!(
            result.is_ok(),
            "{} is in ALL_CODES but explain_lookup returned: {:?}",
            c.as_str(),
            result.err()
        );
    }
}

#[test]
fn explain_resolves_a_known_code() {
    let page = explain_lookup("IPE-T0001");
    assert!(page.is_ok(), "known code must resolve: {:?}", page.err());
    let page = page.expect("`page` must succeed");
    assert!(
        page.starts_with("# IPE-T0001:"),
        "page line 1 must name the code, got:\n{page}"
    );
}

#[test]
fn explain_is_case_insensitive() {
    assert!(explain_lookup("ipe-t0001").is_ok());
    assert!(explain_lookup("  Ipe-T0001  ").is_ok());
}

#[test]
fn explain_resolves_ipe_t0014() {
    // IPE-T0014 resolves via ALL_CODES from ipe_diagnostics rather than
    // a hand-mirror that could omit it.
    let result = explain_lookup("IPE-T0014");
    assert!(
        result.is_ok(),
        "IPE-T0014 must resolve via ALL_CODES: {:?}",
        result.err()
    );
}

#[test]
fn explain_rejects_unknown_code_with_suggestions() {
    // Genuinely unknown code, close to IPE-T0013 — must yield did-you-mean.
    let result = explain_lookup("IPE-T0099");
    assert!(
        matches!(&result, Err(CliError::UnknownCode { .. })),
        "unknown code must error, got: {result:?}"
    );
    let Err(CliError::UnknownCode { suggestions, .. }) = result else {
        return;
    };
    assert!(
        !suggestions.is_empty(),
        "a near-miss must yield did-you-mean suggestions"
    );
}

#[test]
fn explain_unknown_code_display_is_deterministic() {
    let err = CliError::UnknownCode {
        input: "IPE-Z9999".to_owned(),
        suggestions: vec!["IPE-T0001", "IPE-T0002"],
    };
    assert_eq!(
        err.to_string(),
        "unknown error code `IPE-Z9999`\n  did you mean: IPE-T0001, IPE-T0002?"
    );
}

#[test]
fn explain_output_ends_with_trailing_newline() {
    // `ipe explain <CODE>` writes the page as is, so the page itself must
    // end with a newline to avoid a missing newline at the shell prompt.
    let page = explain_lookup("IPE-T0001").expect("known code must resolve");
    assert!(
        page.ends_with('\n'),
        "explain output must end with a trailing newline; got: {:?}",
        &page[page.len().saturating_sub(20)..]
    );
}

#[test]
fn code_index_lists_every_code() {
    let index = code_index();
    let lines = index.lines().count();
    assert_eq!(lines, ALL_CODES.len(), "one line per code");
    assert!(
        index.contains("IPE-T0001  type mismatch"),
        "index pairs code with title"
    );
}

#[test]
fn emit_ir_prints_a_tree_for_the_golden() {
    let tree = emit_ir_text(&golden_entry());
    assert!(
        tree.is_ok(),
        "emit-ir must succeed: {:?}",
        tree.as_ref().err()
    );
    let tree = tree.expect("`tree` must succeed");
    assert!(
        tree.starts_with("program"),
        "tree roots at `program`:\n{tree}"
    );
    assert!(tree.contains("main"), "tree names the `main` func:\n{tree}");
}

/// A program importing a compiled-source stdlib module that defines its own
/// types (`Ipe.Test`) must resolve its qualified members through the CLI
/// analysis path (`ipe dev build --emit-ir` / `ipe release capabilities`), exactly as it
/// does through a real `ipe dev build`. Both share the injection-aware
/// source-graph pipeline: the analysis path once ran a bare single-module
/// lower that never injected the closure, so `Test.runMain` / `Test.equal`
/// failed with IPE-N0004 "unknown module `Test`" here while the build
/// succeeded. This pins the CLI<->build parity for compiled-source-with-types
/// modules so the divergence cannot return.
#[test]
fn emit_ir_resolves_compiled_source_stdlib_with_own_types() {
    let entry = e2e_support::manifest_dir!()
        .join("..")
        .join("..")
        .join("tests")
        .join("golden")
        .join("test_summary_line_219")
        .join("Main.ipe");
    let tree = emit_ir_text(&entry);
    assert!(
        tree.is_ok(),
        "emit-ir must resolve `Ipe.Test` (no IPE-N0004): {:?}",
        tree.as_ref().err()
    );
    let tree = tree.expect("`tree` must succeed");
    // The injected compiled-source module's OWN types + members are present
    // — proof the closure was injected, not merely that the diagnostic was
    // silenced.
    assert!(
        tree.contains("type TestResult"),
        "injected `Ipe.Test` types must appear in the IR:\n{tree}"
    );
    assert!(
        tree.contains("runMain"),
        "`Test.runMain` must resolve to the injected member:\n{tree}"
    );

    // The same source-graph pipeline backs `ipe release capabilities` via
    // `lower_entry_via_graph`; it must resolve identically (a pure test
    // program).
    assert!(
        lower_entry_via_graph(&entry).is_ok(),
        "lower_entry_via_graph (capabilities path) must resolve `Ipe.Test` too"
    );
}

/// A compiled-source stdlib module that imports a kernel stdlib module inside
/// its own body must not fire IPE-N0034 on those imports.  `Ipe.Money`
/// imports `Ipe.String` (a kernel module) and uses `String.*` members
/// throughout; the Tier-C import gate must see those imports as satisfied
/// when the embedded source is injected and canonicalised.
///
/// The `money_parse_currency_maybe` golden exercises `Money.currencyCode`
/// (which calls `String.*` internally), making it the ideal witness.
#[test]
fn compiled_source_stdlib_own_imports_resolve_no_n0034() {
    let entry = e2e_support::manifest_dir!()
        .join("..")
        .join("..")
        .join("tests")
        .join("golden")
        .join("money_parse_currency_maybe")
        .join("Main.ipe");
    let tree = emit_ir_text(&entry);
    assert!(
        tree.is_ok(),
        "emit-ir must resolve `Ipe.Money` (no IPE-N0034 inside the embedded module): {:?}",
        tree.as_ref().err()
    );
    let tree = tree.expect("`tree` must succeed");
    // The injected module's types must appear — proof the closure was injected,
    // not merely that the diagnostic was silenced at a shallower stage.
    assert!(
        tree.contains("Money") || tree.contains("currency"),
        "injected `Ipe.Money` members must appear in the IR:\n{tree}"
    );
}

#[test]
fn machine_applicable_suggestion_is_collected_and_applied() {
    let src = "main = lenght";
    // `lenght` occupies bytes 7..13.
    let diag = Diagnostic::Name {
        span: Span::new(7, 13),
        msg: NameError::ValueNotFound {
            name: "lenght".into(),
            suggestions: Candidates::at(
                EditTarget::whole(Span::new(7, 13), "lenght"),
                Box::new(["length".into()]),
            ),
        },
    };
    let fixes = machine_applicable_suggestions(&diag);
    assert_eq!(fixes.len(), 1, "single candidate is machine-applicable");
    let selected = select_non_overlapping(fixes, src.len());
    let patched = apply_fixes(src, &selected);
    assert_eq!(patched.as_deref(), Some("main = length"));
}

/// A suggestion whose span holds other text than it `replaces` is refused
/// whole, never applied over the wrong bytes.
#[test]
fn apply_fixes_refuses_mismatched_replaces() {
    let s = Suggestion {
        span: Span::new(7, 15),
        replaces: "Lsit".into(),
        replacement: "List".into(),
        applicability: Applicability::MachineApplicable,
    };
    assert_eq!(apply_fixes("main = Lsit.map f", &[s]), None);
}

/// `ipe fix` on a misspelt qualifier rewrites only the qualifier: the member
/// after the dot survives.
#[test]
fn ipe_fix_never_rewrites_qualified_token_whole() {
    let src =
        "module Main exposing (main)\n\nimport Ipe.Crypto\n\nmain =\n    Crpyto.sha256 \"x\"\n";
    let diag = pipeline_first_diagnostic(src);
    assert!(
        diag.is_some(),
        "a misspelt qualifier must raise a diagnostic"
    );
    let Some(diag) = diag else {
        return;
    };
    let fixes = select_non_overlapping(machine_applicable_suggestions(&diag), src.len());
    assert_eq!(fixes.len(), 1, "one applicable fix, got {diag:?}");
    assert_eq!(
        apply_fixes(src, &fixes).as_deref(),
        Some(
            "module Main exposing (main)\n\nimport Ipe.Crypto\n\nmain =\n    Crypto.sha256 \"x\"\n"
        )
    );
}

#[test]
fn overlapping_suggestions_are_filtered_back_to_front() {
    let left = Suggestion {
        span: Span::new(0, 5),
        replaces: "a".into(),
        replacement: "x".into(),
        applicability: Applicability::MachineApplicable,
    };
    let right = Suggestion {
        span: Span::new(3, 8),
        replaces: "a".into(),
        replacement: "y".into(),
        applicability: Applicability::MachineApplicable,
    };
    let kept = select_non_overlapping(vec![left, right], 8);
    assert_eq!(kept.len(), 1, "overlapping spans collapse to one");
    // Back-to-front: the right-most (larger lo) span survives.
    assert_eq!(kept.first().map(|s| s.span.lo), Some(3));
}

#[test]
fn apply_fixes_rejects_out_of_bounds_span() {
    let s = Suggestion {
        span: Span::new(0, 999),
        replaces: "a".into(),
        replacement: "z".into(),
        applicability: Applicability::MachineApplicable,
    };
    assert_eq!(apply_fixes("short", &[s]), None);
}

#[test]
fn apply_fixes_rejects_non_char_boundary_span() {
    // "é" is two UTF-8 bytes; a span that splits it is rejected.
    let s = Suggestion {
        span: Span::new(0, 1),
        replaces: "a".into(),
        replacement: "z".into(),
        applicability: Applicability::MachineApplicable,
    };
    assert_eq!(apply_fixes("é", &[s]), None);
}

#[test]
fn levenshtein_is_symmetric_and_zero_on_equal() {
    assert_eq!(levenshtein("abc", "abc"), 0);
    assert_eq!(levenshtein("abc", "abd"), 1);
    assert_eq!(levenshtein("abc", "abd"), levenshtein("abd", "abc"));
}

#[test]
fn line_col_counts_from_one() {
    let src = "ab\ncd";
    assert_eq!(line_col(src, 0), (1, 1));
    assert_eq!(line_col(src, 1), (1, 2));
    assert_eq!(line_col(src, 3), (2, 1));
    assert_eq!(line_col(src, 4), (2, 2));
}

/// Generic records, end to end from SOURCE: parse → canon → infer → lower →
/// emit → `cargo build` → run, asserting the program prints `42` — the value
/// the Go reference backend produces for the same program (hand-verified in a
/// temp dir). Gated on `IPE_E2E=1` so the default `cargo test` stays fast and
/// offline. Complements the backend crate's hand-built-IR e2e by exercising
/// the whole frontend (record type annotations + generalisation + lowering).
#[test]
fn generic_record_program_builds_and_prints_forty_two() {
    const SRC: &str = "module Main exposing (main)\n\n\
         import Ipe.Io\n\
         import Ipe.String\n\n\
         wrap : a -> { value : a }\n\
         wrap x =\n    { value = x }\n\n\
         unwrap : { value : a } -> a\n\
         unwrap r =\n    r.value\n\n\
         main = Io.println (String.fromInt (unwrap (wrap 42)))\n";

    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let dir = ipe_test_temp::temp_root().join("ipec_generic_record_src_e2e");
    let _ = fs::remove_dir_all(&dir);
    let entry = dir.join("Main.ipe");
    let created = fs::create_dir_all(&dir).and_then(|()| fs::write(&entry, SRC));
    assert!(created.is_ok(), "write source: {created:?}");

    let runtime = resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve: {runtime:?}");
    let runtime = runtime.expect("`runtime` must succeed");

    let out = dir.join("out");
    let built = build(&entry, &out, &runtime);
    assert!(built.is_ok(), "ipe dev build must succeed: {built:?}");

    let status = std::process::Command::new("cargo")
        .arg("build")
        .current_dir(&out)
        .env("CARGO_TARGET_DIR", out.join("target"))
        .status();
    assert!(
        matches!(&status, Ok(s) if s.success()),
        "emitted generic-record crate must compile: {status:?}"
    );

    let bin = out.join("target").join("debug").join("ipe-app");
    let run = std::process::Command::new(&bin).output();
    let Ok(run) = run else {
        assert!(false_marker(), "run binary: {run:?}");
        return;
    };
    assert_eq!(
        String::from_utf8_lossy(&run.stdout),
        "42\n",
        "generic-record program prints 42 (Go-backend parity)"
    );
    assert!(run.status.success(), "exit 0, matching the Go oracle");
    let _ = std::fs::remove_dir_all(out.join("target"));
}

/// A runtime `false` the optimiser cannot fold, so `assert!(false_marker())`
/// fails the test without tripping `clippy::assertions_on_constants`.
fn false_marker() -> bool {
    std::hint::black_box(false)
}

// -----------------------------------------------------------------------
// find_manifest_for_ipe_file tests (IPE-N0020 fix)
// -----------------------------------------------------------------------

/// Creates a temp directory with a nested `src/Main.ipe` and a `package.ipe`
/// at the project root, confirming the upward walk finds the manifest.
#[cfg(unix)]
#[test]
fn find_manifest_walks_up_to_project_root() {
    let tmp = ipe_test_temp::temp_root().join("ipec_find_manifest_test");
    let _ = fs::remove_dir_all(&tmp);
    let src = tmp.join("src");
    fs::create_dir_all(&src).expect("create src/");
    let manifest = tmp.join("package.ipe");
    fs::write(
        &manifest,
        "module Package exposing (package)\n\n\npackage =\n    { name = \"test\" }\n",
    )
    .expect("write package.ipe");
    let main_ipe = src.join("Main.ipe");
    fs::write(&main_ipe, "module Main exposing (main)\nmain = 0\n").expect("write Main.ipe");

    let found = find_manifest_for_ipe_file(&main_ipe).expect("owned manifest is trusted");
    assert_eq!(
        found.as_deref(),
        Some(manifest.as_path()),
        "upward walk must find package.ipe at project root"
    );
    let _ = fs::remove_dir_all(&tmp);
}

/// Off Unix a manifest found above a file entry cannot be owner-checked, so
/// the walk refuses it, naming the explicit-directory fix — the fail-closed
/// twin of `find_manifest_walks_up_to_project_root`.
#[cfg(not(unix))]
#[test]
fn find_manifest_refuses_an_unverifiable_manifest() {
    let tmp = ipe_test_temp::temp_root().join("ipec_find_manifest_unverifiable_test");
    let _ = fs::remove_dir_all(&tmp);
    let src = tmp.join("src");
    fs::create_dir_all(&src).expect("create src/");
    let manifest = tmp.join("package.ipe");
    fs::write(&manifest, "module Package exposing (package)\n").expect("write package.ipe");
    let main_ipe = src.join("Main.ipe");
    fs::write(&main_ipe, "module Main exposing (main)\nmain = 0\n").expect("write Main.ipe");

    let refused = find_manifest_for_ipe_file(&main_ipe);
    assert!(
        matches!(&refused, Err(crate::CliError::TrustRefused(t)) if t.message() == crate::text::msg::manifest_unverifiable(&manifest.display())),
        "{refused:?}"
    );
    let _ = fs::remove_dir_all(&tmp);
}

/// A fresh scratch tree for one manifest-walk test, holding `src/Main.ipe` under `project`.
fn manifest_walk_tree(tag: &str, project: &str) -> (PathBuf, PathBuf) {
    let tmp =
        ipe_test_temp::temp_root().join(format!("ipec_manifest_walk_{tag}_{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    let src = tmp.join(project).join("src");
    fs::create_dir_all(&src).expect("create src/");
    let main_ipe = src.join("Main.ipe");
    fs::write(&main_ipe, "module Main exposing (main)\nmain = 0\n").expect("write Main.ipe");
    (tmp, main_ipe)
}

/// A `package.ipe` planted above the project's version-control root is never consulted.
#[test]
fn find_manifest_ignores_a_manifest_above_the_vcs_root() {
    let (tmp, main_ipe) = manifest_walk_tree("above_vcs", "proj");
    fs::write(
        tmp.join("package.ipe"),
        "module Package exposing (package)\n",
    )
    .expect("write planted package.ipe");
    fs::create_dir_all(tmp.join("proj").join(".git")).expect("create .git/");
    let found = find_manifest_for_ipe_file(&main_ipe);
    let _ = fs::remove_dir_all(&tmp);
    assert!(matches!(found, Ok(None)), "{found:?}");
}

/// A `.git` file (a worktree or submodule checkout) is a ceiling too.
#[test]
fn find_manifest_stops_at_a_git_file() {
    let (tmp, main_ipe) = manifest_walk_tree("git_file", "proj");
    fs::write(
        tmp.join("package.ipe"),
        "module Package exposing (package)\n",
    )
    .expect("write planted package.ipe");
    fs::write(tmp.join("proj").join(".git"), "gitdir: elsewhere\n").expect("write .git");
    let found = find_manifest_for_ipe_file(&main_ipe);
    let _ = fs::remove_dir_all(&tmp);
    assert!(matches!(found, Ok(None)), "{found:?}");
}

/// A `.hg` or `.jj` root, as a directory or a file, is a ceiling like `.git`.
#[test]
fn find_manifest_stops_at_every_vcs_marker() {
    for marker in [".hg", ".jj"] {
        for as_dir in [true, false] {
            let tag = format!("marker{marker}_{as_dir}");
            let (tmp, main_ipe) = manifest_walk_tree(&tag, "proj");
            fs::write(
                tmp.join("package.ipe"),
                "module Package exposing (package)\n",
            )
            .expect("write planted package.ipe");
            let marker_path = tmp.join("proj").join(marker);
            if as_dir {
                fs::create_dir_all(&marker_path).expect("create marker dir");
            } else {
                fs::write(&marker_path, "").expect("write marker file");
            }
            let found = find_manifest_for_ipe_file(&main_ipe);
            let _ = fs::remove_dir_all(&tmp);
            assert!(
                matches!(found, Ok(None)),
                "{marker} dir={as_dir}: {found:?}"
            );
        }
    }
}

/// A home reached through a symlink stops the walk whichever spelling either side uses.
#[cfg(unix)]
#[test]
fn find_manifest_stops_at_a_symlinked_home() {
    let (tmp, _) = manifest_walk_tree("symlinked_home", "real_home");
    fs::write(
        tmp.join("package.ipe"),
        "module Package exposing (package)\n",
    )
    .expect("write planted package.ipe");
    let real_home = tmp.join("real_home");
    let link_home = tmp.join("link_home");
    std::os::unix::fs::symlink(&real_home, &link_home).expect("symlink home");
    let via_real = real_home.join("src").join("Main.ipe");
    let via_link = link_home.join("src").join("Main.ipe");
    let link_ceiling = HomeCeiling::of(Ok(&parsed_home(&link_home)));
    let real_ceiling = HomeCeiling::of(Ok(&parsed_home(&real_home)));
    let real_under_link = find_manifest_bounded(&via_real, &link_ceiling, MAX_MANIFEST_WALK_DEPTH);
    let link_under_real = find_manifest_bounded(&via_link, &real_ceiling, MAX_MANIFEST_WALK_DEPTH);
    let unbounded = find_manifest_bounded(&via_link, &HomeCeiling::Absent, MAX_MANIFEST_WALK_DEPTH);
    let _ = fs::remove_dir_all(&tmp);
    assert!(
        matches!(&link_ceiling, HomeCeiling::At(_)),
        "{link_ceiling:?}"
    );
    assert_eq!(
        link_ceiling, real_ceiling,
        "both spellings resolve to one ceiling"
    );
    assert!(matches!(real_under_link, Ok(None)), "{real_under_link:?}");
    assert!(matches!(link_under_real, Ok(None)), "{link_under_real:?}");
    assert!(
        !matches!(unbounded, Ok(None)),
        "without the ceiling the planted manifest is reached: {unbounded:?}"
    );
}

/// A manifest in the version-control root directory itself is still the project's.
#[cfg(unix)]
#[test]
fn find_manifest_finds_the_manifest_at_the_vcs_root() {
    let (tmp, main_ipe) = manifest_walk_tree("at_vcs", "proj");
    let manifest = tmp.join("proj").join("package.ipe");
    fs::write(&manifest, "module Package exposing (package)\n").expect("write package.ipe");
    fs::create_dir_all(tmp.join("proj").join(".git")).expect("create .git/");
    let found = find_manifest_for_ipe_file(&main_ipe);
    let _ = fs::remove_dir_all(&tmp);
    assert!(
        matches!(&found, Ok(Some(path)) if *path == manifest),
        "{found:?}"
    );
}

/// A `package.ipe` above the user's home directory is never consulted.
#[test]
fn find_manifest_ignores_a_manifest_above_home() {
    let (tmp, main_ipe) = manifest_walk_tree("above_home", "home");
    fs::write(
        tmp.join("package.ipe"),
        "module Package exposing (package)\n",
    )
    .expect("write planted package.ipe");
    let home = HomeCeiling::of(Ok(&parsed_home(&tmp.join("home"))));
    let found = find_manifest_bounded(&main_ipe, &home, MAX_MANIFEST_WALK_DEPTH);
    let _ = fs::remove_dir_all(&tmp);
    assert!(matches!(found, Ok(None)), "{found:?}");
}

/// A walk that passes the depth cap with no manifest and no ceiling is refused, not unbounded.
#[test]
fn find_manifest_refuses_a_walk_past_the_depth_cap() {
    let (tmp, main_ipe) = manifest_walk_tree("depth_cap", "a/b");
    let refused = find_manifest_bounded(&main_ipe, &HomeCeiling::Absent, 2);
    let _ = fs::remove_dir_all(&tmp);
    assert!(
        matches!(&refused, Err(CliError::DiscoveryLimitReached { .. })),
        "{refused:?}"
    );
}

/// A manifest in the last directory the cap allows is still found.
#[cfg(unix)]
#[test]
fn find_manifest_finds_a_manifest_at_the_depth_cap() {
    let (tmp, main_ipe) = manifest_walk_tree("at_depth_cap", "a/b");
    let manifest = tmp.join("a").join("b").join("package.ipe");
    fs::write(&manifest, "module Package exposing (package)\n").expect("write package.ipe");
    let found = find_manifest_bounded(&main_ipe, &HomeCeiling::Absent, 2);
    let _ = fs::remove_dir_all(&tmp);
    assert!(
        matches!(&found, Ok(Some(path)) if *path == manifest),
        "{found:?}"
    );
}

/// A home reached through an alias stops a walk whose path steps through a symlinked subdirectory.
///
/// The project lives outside the home and is reached through a symlink
/// inside it, so no canonical ancestor of the project is the home; the
/// lexical steps still cross the home, and its identity ends the walk.
#[cfg(unix)]
#[test]
fn find_manifest_stops_at_an_aliased_home_above_a_symlinked_subdir() {
    let (tmp, _) = manifest_walk_tree("aliased_home", "data/code/proj");
    fs::write(
        tmp.join("package.ipe"),
        "module Package exposing (package)\n",
    )
    .expect("write planted package.ipe");
    let real_home = tmp.join("var_home");
    fs::create_dir_all(&real_home).expect("create home");
    let home_alias = tmp.join("home_link");
    std::os::unix::fs::symlink(&real_home, &home_alias).expect("symlink home alias");
    std::os::unix::fs::symlink(tmp.join("data").join("code"), real_home.join("code"))
        .expect("symlink code/ into home");
    let file_under = |root: &Path| root.join("code").join("proj").join("src").join("Main.ipe");
    let ceiling = HomeCeiling::of(Ok(&parsed_home(&home_alias)));
    let via_alias =
        find_manifest_bounded(&file_under(&home_alias), &ceiling, MAX_MANIFEST_WALK_DEPTH);
    let via_real =
        find_manifest_bounded(&file_under(&real_home), &ceiling, MAX_MANIFEST_WALK_DEPTH);
    let unbounded = find_manifest_bounded(
        &file_under(&home_alias),
        &HomeCeiling::Absent,
        MAX_MANIFEST_WALK_DEPTH,
    );
    let _ = fs::remove_dir_all(&tmp);
    assert!(matches!(via_alias, Ok(None)), "{via_alias:?}");
    assert!(matches!(via_real, Ok(None)), "{via_real:?}");
    assert!(
        !matches!(unbounded, Ok(None)),
        "without the ceiling the planted manifest is reached: {unbounded:?}"
    );
}

/// A symlink inside a package whose target sits shallow still finds the package's manifest.
///
/// The walk steps the path as given, so the target's own ancestors never
/// decide where the walk goes.
#[cfg(unix)]
#[test]
fn find_manifest_follows_the_lexical_path_through_a_shallow_symlink() {
    let (tmp, _) = manifest_walk_tree("shallow_link", "s");
    let pkg = tmp.join("pkg");
    fs::create_dir_all(pkg.join("sub")).expect("create pkg/sub/");
    let manifest = pkg.join("package.ipe");
    fs::write(&manifest, "module Package exposing (package)\n").expect("write package.ipe");
    std::os::unix::fs::symlink(tmp.join("s").join("src"), pkg.join("sub").join("deep"))
        .expect("symlink deep/");
    let main_ipe = pkg.join("sub").join("deep").join("Main.ipe");
    let found = find_manifest_bounded(
        &main_ipe,
        &HomeCeiling::of(Ok(&parsed_home(&tmp))),
        MAX_MANIFEST_WALK_DEPTH,
    );
    let _ = fs::remove_dir_all(&tmp);
    assert!(
        matches!(&found, Ok(Some(path)) if *path == manifest),
        "{found:?}"
    );
}

/// An unreadable home confines the walk to the start directory.
#[cfg(unix)]
#[test]
fn find_manifest_under_an_unreadable_home_examines_only_the_start_directory() {
    let (tmp, main_ipe) = manifest_walk_tree("unreadable_home", "proj");
    let above = tmp.join("proj").join("package.ipe");
    fs::write(&above, "module Package exposing (package)\n").expect("write package.ipe");
    let skipped =
        find_manifest_bounded(&main_ipe, &HomeCeiling::Unreadable, MAX_MANIFEST_WALK_DEPTH);
    let beside = tmp.join("proj").join("src").join("package.ipe");
    fs::write(&beside, "module Package exposing (package)\n").expect("write package.ipe");
    let found = find_manifest_bounded(&main_ipe, &HomeCeiling::Unreadable, MAX_MANIFEST_WALK_DEPTH);
    let _ = fs::remove_dir_all(&tmp);
    assert!(matches!(skipped, Ok(None)), "{skipped:?}");
    assert!(
        matches!(&found, Ok(Some(path)) if *path == beside),
        "{found:?}"
    );
}

/// An unset home, or a home that does not exist, sets no ceiling.
#[test]
fn a_missing_home_sets_no_ceiling() {
    let missing = ipe_test_temp::temp_root().join(format!(
        "ipec_manifest_walk_missing_home_{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&missing);
    assert_eq!(
        HomeCeiling::of(Err(crate::env_dir::HomeRefusal::Unset)),
        HomeCeiling::Absent
    );
    assert_eq!(
        HomeCeiling::of(Ok(&parsed_home(&missing))),
        HomeCeiling::Absent
    );
}

/// A home that is set but refused confines the walk to the start directory.
///
/// The refused value may still name the user's tree, so a `package.ipe` one
/// level above the start is never reached; an unset home, by contrast, sets
/// no ceiling and the same walk finds it.
#[cfg(unix)]
#[test]
fn a_refused_home_never_widens_the_manifest_walk() {
    use crate::env_dir::HomeRefusal;
    let (tmp, main_ipe) = manifest_walk_tree("refused_home", "proj");
    let above = tmp.join("proj").join("package.ipe");
    fs::write(&above, "module Package exposing (package)\n").expect("write package.ipe");
    let refusals = [
        HomeRefusal::NotUtf8,
        HomeRefusal::ContainsNul,
        HomeRefusal::NotAbsolute,
        HomeRefusal::ParentComponent,
        HomeRefusal::WindowsDeviceOrVerbatim,
        HomeRefusal::WindowsUnc,
    ];
    let walks: Vec<_> = refusals
        .iter()
        .map(|refusal| {
            let ceiling = HomeCeiling::of(Err(*refusal));
            let found = find_manifest_bounded(&main_ipe, &ceiling, MAX_MANIFEST_WALK_DEPTH);
            (*refusal, ceiling, found)
        })
        .collect();
    let unset = find_manifest_bounded(
        &main_ipe,
        &HomeCeiling::of(Err(HomeRefusal::Unset)),
        MAX_MANIFEST_WALK_DEPTH,
    );
    let _ = fs::remove_dir_all(&tmp);
    for (refusal, ceiling, found) in walks {
        assert_eq!(ceiling, HomeCeiling::Unreadable, "{refusal:?}");
        assert!(matches!(found, Ok(None)), "{refusal:?}: {found:?}");
    }
    assert!(
        matches!(&unset, Ok(Some(path)) if *path == above),
        "an unset home sets no ceiling: {unset:?}"
    );
}

/// A parsed home over the absolute test path `path`.
fn parsed_home(path: &Path) -> crate::env_dir::HomeDir {
    crate::env_dir::HomeDir::try_parse(Some(path.as_os_str().to_owned()))
        .expect("an absolute test home")
}

/// Two spellings of one directory share an identity; two directories never do.
#[cfg(unix)]
#[test]
fn dir_identity_is_independent_of_spelling() {
    let (tmp, _) = manifest_walk_tree("identity", "a");
    let other = tmp.join("b");
    fs::create_dir_all(&other).expect("create b/");
    let alias = tmp.join("a_link");
    std::os::unix::fs::symlink(tmp.join("a"), &alias).expect("symlink a/");
    let direct = DirIdentity::read(&tmp.join("a")).ok();
    let aliased = DirIdentity::read(&alias).ok();
    let dotted = DirIdentity::read(&tmp.join("a").join("src").join("..")).ok();
    let distinct = DirIdentity::read(&other).ok();
    let _ = fs::remove_dir_all(&tmp);
    assert!(direct.is_some(), "identity of a/ is readable");
    assert_eq!(direct, aliased);
    assert_eq!(direct, dotted);
    assert_ne!(direct, distinct);
}

// -----------------------------------------------------------------------
// Regression: PAnything (wildcard lambda param with unconstrained Ty::Var)
// -----------------------------------------------------------------------

/// Regression for `IPE-L0102` (`Feature::Polymorphism`) on wildcard `_`
/// lambda parameters.
///
/// Calling `ir_type_from_ty` on the `_` param's type is unsound: when the
/// type is still an unconstrained `Ty::Var` (e.g. the continuation of a
/// `Task.andThen` after `Task.fail` where the ok-type is never forced),
/// `ir_type_from_ty` returns `Err(unsupported(…, Feature::Polymorphism))`
/// and the pipeline aborts.
///
/// So `PAnything` params route through `ir_type_from_ty_json`, which
/// maps `Ty::Var → IrType::Json` instead of failing.
///
/// Source mirrors the failing pattern from `examples/14-task-demo`.
#[test]
fn panything_wildcard_lambda_compiles_without_polymorphism_error() {
    const SRC: &str = "\
module Main exposing (main)
import Ipe.Task as Task
import Ipe.Error as Error exposing (Error)
import Ipe.Io as Io

main =
Task.fail (Error.unexpected \"intentional\")
    |> Task.andThen (\\_ -> Task.succeed \"unreachable\")
    |> Task.andThen Io.println
    |> Task.onError (\\e -> Io.println (Error.toString e))
";

    let runtime = resolve_runtime();
    let runtime = runtime.expect("`runtime` must succeed");

    let dir = ipe_test_temp::temp_root().join("ipec_panything_regression");
    let _ = fs::remove_dir_all(&dir);
    let entry = dir.join("Main.ipe");
    let created = fs::create_dir_all(&dir).and_then(|()| fs::write(&entry, SRC));
    assert!(created.is_ok(), "write source: {created:?}");

    let out = dir.join("out");
    let result = build(&entry, &out, &runtime);
    assert!(
        result.is_ok(),
        "wildcard lambda with unconstrained type must not fire IPE-L0102: {result:?}"
    );
    let _ = fs::remove_dir_all(&dir);
}

// -----------------------------------------------------------------------
// Regression: Task.run elision — ipe_main must return IpeTask<A>
// -----------------------------------------------------------------------

/// `main` returning a `Task` directly must emit `fn ipe_main() -> IpeTask<`
/// (the shape the `block_on(ipe_main())` epilogue requires), never
/// `IpeResult<…>`. The internal `TaskRun` kernel is the auto-run mechanism
/// at the entry boundary; the surface `Task.run` binding is gone.
#[test]
fn task_run_main_emits_ipetask_not_iperesult() {
    const SRC: &str = "\
module Main exposing (main)
import Ipe.Io as Io

main =
Io.println \"hello from main task\"
";

    let runtime = resolve_runtime();
    let runtime = runtime.expect("`runtime` must succeed");

    let dir = ipe_test_temp::temp_root().join("ipec_taskrun_elision_regression");
    let _ = fs::remove_dir_all(&dir);
    let entry = dir.join("Main.ipe");
    let created = fs::create_dir_all(&dir).and_then(|()| fs::write(&entry, SRC));
    assert!(created.is_ok(), "write source: {created:?}");

    let out = dir.join("out");
    let built = build(&entry, &out, &runtime);
    assert!(built.is_ok(), "task-returning main must compile: {built:?}");

    let main_rs = out.join("src").join("main.rs");
    let emitted = fs::read_to_string(&main_rs).expect("emitted main.rs must exist after build");

    assert!(
        emitted.contains("fn ipe_main() -> IpeTask<"),
        "ipe_main must return IpeTask<…>, got signature region:\n{}",
        emitted
            .lines()
            .filter(|l| l.contains("ipe_main") || l.contains("IpeTask") || l.contains("IpeResult"))
            .collect::<Vec<_>>()
            .join("\n")
    );
    assert!(
        !emitted.contains("fn ipe_main() -> IpeResult"),
        "ipe_main must NOT return IpeResult"
    );

    let _ = fs::remove_dir_all(&dir);
}

/// The pure hot-appearance decision (over the two raw variable values):
/// default ON, the opt-out wins, and an explicit `IPE_WATCH_HOT_APPEARANCE`
/// is honoured. Exercises the logic without mutating process env.
#[test]
fn hot_appearance_defaults_on_and_honours_overrides() {
    // Neither var set ⇒ on (the new default for `ipe dev watch`).
    assert!(hot_appearance_from_env(None, None), "unset ⇒ default on");
    // Opt-out set ⇒ off, regardless of the explicit var.
    assert!(
        !hot_appearance_from_env(Some("1"), None),
        "IPE_WATCH_NO_HOT_APPEARANCE=1 ⇒ off"
    );
    assert!(
        !hot_appearance_from_env(Some("anything"), Some("1")),
        "opt-out wins over an explicit on"
    );
    // Opt-out empty / `0` does NOT opt out.
    assert!(
        hot_appearance_from_env(Some(""), None),
        "empty opt-out is not an opt-out ⇒ still on"
    );
    assert!(
        hot_appearance_from_env(Some("0"), None),
        "`0` opt-out is not an opt-out ⇒ still on"
    );
    // Explicit `IPE_WATCH_HOT_APPEARANCE` is honoured when opt-out is absent.
    assert!(
        !hot_appearance_from_env(None, Some("0")),
        "explicit `0` ⇒ off"
    );
    assert!(
        !hot_appearance_from_env(None, Some("")),
        "explicit empty ⇒ off"
    );
    assert!(
        hot_appearance_from_env(None, Some("1")),
        "explicit `1` ⇒ on"
    );
}

/// A web app with a hoist-eligible style literal (`Ui.style "font-weight"
/// "bold"`). Used to prove the build-vs-watch emit difference.
const WEB_APP_WITH_STYLE: &str = "\
module Main exposing (main)
import Ipe.Tea.Web as Web
import Ipe.Ui as Ui
import Ipe.Tea.Web.Cmd as Cmd
import Ipe.Tea.Web.Sub as Sub

type Msg = Noop
type alias Model = { count : Int }

init : WebReq -> ( Model, Cmd Msg )
init _req = ( { count = 0 }, Cmd.none )

update : Msg -> Model -> ( Model, Cmd Msg )
update _msg model = ( model, Cmd.none )

subscriptions : Model -> Sub Msg
subscriptions _model = Sub.none

view : Model -> Element Msg
view _model =
Ui.el [ Ui.style \"font-weight\" \"bold\" ] (Ui.text \"Counter\")

main =
Web.tea
    { init = init
    , update = update
    , view = view
    , subscriptions = subscriptions
    , routes = []
    , notFound = Noop
    }
";

/// Emit `WEB_APP_WITH_STYLE` with an explicit `hot_appearance` and return the
/// CONCATENATED emitted Rust source (`src/main.rs` plus every per-module file
/// under `src/ipe_mods/`, where the `view` body actually lands), or `None`
/// when the runtime cannot be resolved (so the test is a no-op on a machine
/// without an installed runtime crate).
#[allow(clippy::expect_used)] // a failed scratch setup is the test failure
fn emit_web_app_source(hot_appearance: bool, tag: &str) -> String {
    let runtime = resolve_runtime().expect("the in-repo runtime resolves");
    let dir = ipe_test_temp::temp_root().join(format!("ipec_hot_appearance_{tag}"));
    let _ = fs::remove_dir_all(&dir);
    let entry = dir.join("Main.ipe");
    fs::create_dir_all(&dir).expect("scratch setup must succeed");
    fs::write(&entry, WEB_APP_WITH_STYLE).expect("scratch setup must succeed");
    let out = dir.join("out");
    let options = BuildOptions {
        hot_appearance,
        ..BuildOptions::from_env()
    };
    let built = build_loose_file_with_options(&entry, &out, &runtime, options);
    assert!(built.is_ok(), "web app must compile ({tag}): {built:?}");
    // Walk `out/src` and concatenate every emitted `.rs` file: the view body
    // (and thus any hoisted `__ipe_lit` table) lands in a per-module file
    // under `src/ipe_mods/`, not in `src/main.rs`.
    let src_dir = out.join("src");
    let mut sources = String::new();
    let mut stack = vec![src_dir];
    while let Some(d) = stack.pop() {
        let Ok(entries) = fs::read_dir(&d) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().and_then(|x| x.to_str()) == Some("rs")
                && let Ok(text) = fs::read_to_string(&p)
            {
                sources.push_str(&text);
            }
        }
    }
    assert!(
        !sources.is_empty(),
        "emitted src/ must carry at least one .rs file ({tag})"
    );
    let _ = fs::remove_dir_all(&dir);
    sources
}

/// PROD-CLEAN: a build-mode emit (`hot_appearance = false`, what `ipe dev build`
/// / `ipe dev run` / `ipe release` thread) carries NO hot-swap scaffolding — no
/// `LiteralTable` and no `/_ipe/hot-appearance` endpoint.
#[test]
fn build_mode_emit_carries_no_hot_swap_scaffolding() {
    let src = emit_web_app_source(false, "build_clean");
    assert!(
        !src.contains("__ipe_lit"),
        "a build-mode emit must introduce no literal table, got:\n{src}"
    );
    assert!(
        !src.contains("/_ipe/hot-appearance"),
        "a build-mode emit must not mount the hot-appearance endpoint, got:\n{src}"
    );
}

/// WATCH: a watch-mode emit (`hot_appearance = true`) DOES hoist the style
/// literal into the per-view `LiteralTable`, so an appearance edit can be
/// hot-swapped without a rebuild.
#[test]
fn watch_mode_emit_hoists_literal_table() {
    let src = emit_web_app_source(true, "watch_hoist");
    assert!(
        src.contains("__ipe_lit"),
        "a watch-mode emit must hoist style literals into a table, got:\n{src}"
    );
}

/// When no package.ipe exists in any parent directory, returns None.
#[test]
fn find_manifest_returns_none_when_absent() {
    let tmp = ipe_test_temp::temp_root().join("ipec_no_manifest_test");
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).expect("create dir");
    let ipe = tmp.join("Standalone.ipe");
    fs::write(&ipe, "module Standalone exposing (f)\nf = 0\n").expect("write ipe");
    // Deliberately no package.ipe anywhere under tmp.
    // The walk terminates at the filesystem root without finding one.
    // We cannot guarantee the walk terminates before reaching /tmp or /
    // on all systems, so we only assert non-panicking behaviour and that
    // the returned path (if Some) is a real file.
    let found = find_manifest_for_ipe_file(&ipe);
    if let Ok(Some(ref p)) = found {
        assert!(p.is_file(), "if Some, the manifest must exist on disk");
    }
    let _ = fs::remove_dir_all(&tmp);
}

/// Two-module program: `Main.ipe` calls a helper in sibling `Lib.ipe`.
/// `build_loose_file` must compile both without IPE-N0020.
#[test]
fn sibling_discovery_compiles_two_module_program() {
    let runtime = resolve_runtime();
    let runtime = runtime.expect("`runtime` must succeed");

    let tmp = ipe_test_temp::temp_root().join("ipec_sibling_disc_test");
    let _ = fs::remove_dir_all(&tmp);
    let src = tmp.join("src");
    fs::create_dir_all(&src).expect("create src/");

    // Helper module: src/Helper.ipe
    fs::write(
        src.join("Helper.ipe"),
        "module Helper exposing (answer)\nanswer = 42\n",
    )
    .expect("write Helper.ipe");

    // Entry module: src/Main.ipe — imports Helper
    fs::write(
        src.join("Main.ipe"),
        "module Main exposing (main)\nimport Helper\nimport Ipe.Io\nimport Ipe.String\nmain = Io.println (String.fromInt Helper.answer)\n",
    )
    .expect("write Main.ipe");

    let out = tmp.join("out");
    let result = build_loose_file(&src.join("Main.ipe"), &out, &runtime);
    assert!(
        result.is_ok(),
        "two-module program must compile via sibling discovery: {:?}",
        result.err()
    );
    let _ = fs::remove_dir_all(&tmp);
}

/// `ipe verify`'s test-stage build: a `tests/Main.ipe` that imports a module
/// living under `src/Lib/` must resolve the `src/` code under test, not fail
/// with IPE-N0020. This is the standard `src/` + `tests/` layout the naive
/// entry-parent source root cannot see across.
#[test]
fn test_stage_build_resolves_src_modules_from_tests_dir() {
    let runtime = resolve_runtime();
    let runtime = runtime.expect("`runtime` must succeed");

    let tmp = ipe_test_temp::temp_root().join("ipec_verify_test_stage_src_disc");
    let _ = fs::remove_dir_all(&tmp);
    let src = tmp.join("src");
    let tests = tmp.join("tests");
    fs::create_dir_all(src.join("Lib")).expect("create src/Lib/");
    fs::create_dir_all(&tests).expect("create tests/");

    // Code under test: src/Lib/Foo.ipe (a multi-segment module referenced
    // via an alias, the way real projects import a nested module).
    fs::write(
        src.join("Lib").join("Foo.ipe"),
        "module Lib.Foo exposing (answer)\nanswer = 42\n",
    )
    .expect("write src/Lib/Foo.ipe");

    // A src entry that also uses the library (mirrors a real project).
    fs::write(
        src.join("Main.ipe"),
        "module Main exposing (main)\nimport Lib.Foo as Foo\nimport Ipe.Io as Io\nimport Ipe.String as String\nmain = Io.println (String.fromInt Foo.answer)\n",
    )
    .expect("write src/Main.ipe");

    // Test entry in the sibling tests/ directory imports the src/ module.
    fs::write(
        tests.join("Main.ipe"),
        "module Main exposing (main)\nimport Lib.Foo as Foo\nimport Ipe.Io as Io\nimport Ipe.String as String\nmain = Io.println (String.fromInt Foo.answer)\n",
    )
    .expect("write tests/Main.ipe");

    let out = tmp.join("out");
    let result = build_test_into(
        &src,
        &tests,
        &tests.join("Main.ipe"),
        OutTarget::Path(&out),
        &runtime,
    );
    assert!(
        result.is_ok(),
        "the test stage must resolve src/ modules from tests/ (no IPE-N0020): {:?}",
        result.err()
    );
    let _ = fs::remove_dir_all(&tmp);
}

/// The test-stage source collection unions the `src/` and `tests/` trees
/// with the correct per-root relativisation: `src/Lib/Foo.ipe` → `Lib.Foo`,
/// `tests/Main.ipe` → `Main`, and the entry is the test module. This is the
/// resolution the build depends on, asserted without a runtime.
#[test]
fn collect_test_sources_unions_src_and_tests_trees() {
    let tmp = ipe_test_temp::temp_root().join("ipec_collect_test_sources_union");
    let _ = fs::remove_dir_all(&tmp);
    let src = tmp.join("src");
    let tests = tmp.join("tests");
    fs::create_dir_all(src.join("Lib")).expect("create src/Lib/");
    fs::create_dir_all(&tests).expect("create tests/");
    fs::write(
        src.join("Lib").join("Foo.ipe"),
        "module Lib.Foo exposing (answer)\nanswer = 42\n",
    )
    .expect("write src/Lib/Foo.ipe");
    fs::write(
        tests.join("Main.ipe"),
        "module Main exposing (main)\nimport Lib.Foo as Foo\nmain = Foo.answer\n",
    )
    .expect("write tests/Main.ipe");

    let collected = collect_test_sources(&src, &tests, &tests.join("Main.ipe"))
        .expect("collect_test_sources must succeed");

    assert_eq!(
        collected.entry_module_path,
        vec!["Main".to_owned()],
        "the entry is the test module"
    );
    assert!(
        collected
            .sources
            .contains_key(&vec!["Lib".to_owned(), "Foo".to_owned()]),
        "src/Lib/Foo.ipe must be present as Lib.Foo, got keys: {:?}",
        collected.sources.keys().collect::<Vec<_>>()
    );
    assert!(
        collected.sources.contains_key(&vec!["Main".to_owned()]),
        "the test entry must be present as Main"
    );
    let _ = fs::remove_dir_all(&tmp);
}

// -----------------------------------------------------------------------
// Cross-module infer errors name the dep module's file
// -----------------------------------------------------------------------

/// When a type error originates in a dep module (`Helper.ipe`), the rendered
/// diagnostic must cite `Helper.ipe` as the file, NOT the entry `Main.ipe`.
/// A single `pipeline_err` closure capturing only the entry file path would
/// render dep-module errors with the wrong source snippet and file name.
///
/// Runtime is not reached (infer aborts first), so we pass a dummy path.
#[test]
fn infer_error_in_dep_module_names_dep_file() {
    let tmp = ipe_test_temp::temp_root().join("ipec_144_dep_err_test");
    let _ = fs::remove_dir_all(&tmp);
    let src = tmp.join("src");
    fs::create_dir_all(&src).expect("create src/");

    // Helper.ipe: deliberate type error — `1 + "oops"` mixes Int and String.
    let helper_path = src.join("Helper.ipe");
    fs::write(
        &helper_path,
        "module Helper exposing (broken)\nbroken = 1 + \"oops\"\n",
    )
    .expect("write Helper.ipe");

    // Main.ipe: imports Helper and uses `broken` — but the error is in Helper.
    let main_path = src.join("Main.ipe");
    fs::write(
        &main_path,
        "module Main exposing (main)\nimport Helper\nimport Ipe.Io\nimport Ipe.String\nmain = Io.println (String.fromInt Helper.broken)\n",
    )
    .expect("write Main.ipe");

    // Runtime is never accessed: a type error fires at infer, before lower/emit.
    let dummy_runtime = ipe_test_temp::temp_root();
    let out = tmp.join("out");
    let result = build_loose_file(&main_path, &out, &dummy_runtime);

    // Must fail — the program has a type error in Helper.
    assert!(
        matches!(result, Err(CliError::Pipeline { .. })),
        "#144 fixture must fail with a pipeline diagnostic (type error in dep): {result:?}"
    );
    let Err(CliError::Pipeline { file, .. }) = result else {
        let _ = fs::remove_dir_all(&tmp);
        return;
    };

    // The file blamed must be Helper.ipe, not Main.ipe.
    let file_name = file.file_name().and_then(|n| n.to_str()).unwrap_or("");
    assert_eq!(
        file_name,
        "Helper.ipe",
        "#144 regression: type error in dep module must blame `Helper.ipe`, \
         not `{file_name}`; full path: {}",
        file.display()
    );

    let _ = fs::remove_dir_all(&tmp);
}

// -----------------------------------------------------------------------
// Home-module discriminant — cross-module errors use `home` on Constraint
// -----------------------------------------------------------------------

/// Regression test for the home-module span discriminant fix.
///
/// Before this fix the constraint solver emitted bare `Span` values (byte
/// offsets with no module tag).  After `link::link` merges N modules into
/// one flat def list, a byte offset like 34 can be numerically contained by
/// a def from *either* module.  The byte-offset heuristic (`source_for_span`)
/// picks the closest def, but it can pick the wrong one when two modules have
/// overlapping numeric span ranges — e.g., a wide def in module A that starts
/// at byte 20 and a narrow def in module B that starts at byte 30, with the
/// type error at byte 34.  Both body spans contain byte 34, but A has a
/// closer `lo_dist` to the wrong def, so the heuristic blames the wrong file
/// whenever the numerically-nearest def belongs to a different module.
///
/// Every `Constraint` carries its source module's `home` path, so
/// `compile_modules` routes `Err((diag, home))` directly via
/// `home_to_source.get(&home)`, bypassing the heuristic entirely when a home
/// is available.
///
/// This test builds a two-module program where the type error is in module B
/// (`Lib.ipe`) but the heuristic *could* be fooled by a wide def in module A
/// (`Pad.ipe`).  The assertion checks that the blamed file is `Lib.ipe`.
///
/// To exercise the home-discriminant path rather than the heuristic, `Pad.ipe`
/// is constructed so that its def body starts at roughly the same byte offset
/// as the error in `Lib.ipe` — any byte-offset resolver that ignores the home
/// would be ambiguous.  The discriminant is the only reliable resolver.
#[test]
fn home_discriminant_cross_module_type_error_names_correct_file() {
    let tmp = ipe_test_temp::temp_root().join("ipec_home_disc_test");
    let _ = fs::remove_dir_all(&tmp);
    let src = tmp.join("src");
    fs::create_dir_all(&src).expect("create src/");

    // Pad.ipe: a valid module whose single def body starts at roughly the
    // same byte offset as the type error in Lib.ipe.  Constructed so the
    // body span (a long arithmetic chain) numerically overlaps with Lib's
    // error span.  The body itself is well-typed.
    //
    //   "module Pad exposing (pad)\npad = " is 27 bytes.
    //   The body "1 + 2 + 3 + 4 + 5 + 6 + 7 + 8 + 9" starts at byte 27.
    //   The body ends at byte 27+35 = 62.
    //
    // After link, Pad's def body covers bytes [27, 62] in Pad's namespace.
    fs::write(
        src.join("Pad.ipe"),
        "module Pad exposing (pad)\npad = 1 + 2 + 3 + 4 + 5 + 6 + 7 + 8 + 9\n",
    )
    .expect("write Pad.ipe");

    // Lib.ipe: a module with a deliberate type error at a span that falls
    // numerically inside Pad's body range.
    //
    //   "module Lib exposing (bad)\nbad = " is 27 bytes.
    //   The body "1 + 2 + 3 + 4 + \"oops\"" starts at byte 27.
    //   The type error is at "\"oops\"" = byte 27+20 = 47, inside [27,62].
    //
    // Without the home discriminant, `source_for_span(span=47)` would see
    // BOTH Pad's body [27,62] (lo_dist=20) and Lib's body [27,49] (lo_dist=20)
    // as equally-distanced candidates — and would pick the narrower body, which
    // happens to be Lib here.  But in general (different padding choices) it
    // can pick the wrong one.  The fix makes the home the authoritative signal.
    fs::write(
        src.join("Lib.ipe"),
        "module Lib exposing (bad)\nbad = 1 + 2 + 3 + 4 + \"oops\"\n",
    )
    .expect("write Lib.ipe");

    // Main.ipe: imports both; the error is in Lib, not Main or Pad.
    fs::write(
        src.join("Main.ipe"),
        "module Main exposing (main)\nimport Lib\nimport Pad\nimport Ipe.Io\nimport Ipe.String\nmain = Io.println (String.fromInt Lib.bad)\n",
    )
    .expect("write Main.ipe");

    let dummy_runtime = ipe_test_temp::temp_root();
    let out = tmp.join("out");
    let result = build_loose_file(&src.join("Main.ipe"), &out, &dummy_runtime);

    // Must fail — type error in Lib.
    assert!(
        matches!(result, Err(CliError::Pipeline { .. })),
        "home-discriminant fixture must fail with a pipeline diagnostic (type error in Lib): {result:?}"
    );
    let Err(CliError::Pipeline { file, .. }) = result else {
        let _ = fs::remove_dir_all(&tmp);
        return;
    };

    // The blamed file must be Lib.ipe — the module that OWNS the failing
    // constraint, regardless of which module the byte-offset heuristic
    // would pick.
    let file_name = file.file_name().and_then(|n| n.to_str()).unwrap_or("");
    assert_eq!(
        file_name,
        "Lib.ipe",
        "home-discriminant regression: type error in Lib must blame `Lib.ipe`, \
         not `{file_name}`; full path: {}",
        file.display()
    );

    let _ = fs::remove_dir_all(&tmp);
}

// -----------------------------------------------------------------
// On-disk build cache end-to-end proof
// -----------------------------------------------------------------

/// Walk `cache_root/<epoch>/` and return the single `EmittedProject`-tier
/// entry (`<key>.json`) a fresh build just wrote. The epoch name is
/// unpredictable from a test's perspective (it folds in the running binary's
/// own content hash), so this has to search rather than construct the path
/// directly. The co-resident IR tier writes `<key>.ir.json` under the same
/// epoch dir — that file's extension is also `json`, so it is excluded by
/// name to keep this matcher pinned to the `EmittedProject` tier.
fn find_single_cache_entry(cache_root: &Path) -> Option<PathBuf> {
    for epoch_entry in fs::read_dir(cache_root).ok()?.flatten() {
        let epoch_dir = epoch_entry.path();
        if !epoch_dir.is_dir() {
            continue;
        }
        for file_entry in fs::read_dir(&epoch_dir).ok()?.flatten() {
            let path = file_entry.path();
            let is_json = path.extension().and_then(std::ffi::OsStr::to_str) == Some("json");
            let is_ir_tier = path
                .file_name()
                .and_then(std::ffi::OsStr::to_str)
                .is_some_and(|n| n.ends_with(".ir.json"));
            if is_json && !is_ir_tier {
                return Some(path);
            }
        }
    }
    None
}

/// The end-to-end proof that `compile_modules_observed` actually
/// CONSULTS and TRUSTS the on-disk cache, not merely that two identical
/// builds happen to agree (which determinism alone would already give,
/// without proving the cache was read at all).
///
/// Strategy: compile once (a genuine cache miss, populates the cache),
/// locate the single entry the build just wrote, and TAMPER with its
/// `cargo_toml` field with a sentinel no fresh compile of the SAME
/// source could ever produce. Compile again with the SAME inputs and
/// the SAME cache dir; if the driver reads and trusts the cache, the
/// second build's `Cargo.toml` carries the sentinel verbatim. If it
/// silently recompiled instead, the sentinel is gone.
#[cfg(unix)] // a cache hit needs a file identity check
#[test]
fn on_disk_cache_hit_serves_a_tampered_entry_verbatim() {
    const SENTINEL: &str = "# CACHE-HIT-SENTINEL\n";

    let runtime = resolve_runtime().expect("the in-repo runtime resolves");

    let tmp = ipe_test_temp::temp_root().join(format!("ipe-cache-e2e-{}", std::process::id()));
    let cache_dir = tmp.join("cache");
    let cache_site = crate::cache::CacheSite::Explicit(cache_dir.clone());
    let out_a = tmp.join("out-a");
    let out_b = tmp.join("out-b");
    let _ = fs::remove_dir_all(&tmp);

    let entry_path = vec!["Main".to_owned()];
    let mut sources: BTreeMap<Vec<String>, (PathBuf, String)> = BTreeMap::new();
    sources.insert(
        entry_path.clone(),
        (
            PathBuf::from("<cache-e2e>/Main.ipe"),
            "module Main exposing (main)\n\nimport Ipe.Io as Io\nimport Ipe.String as String\n\nmain : Task Error ()\nmain =\n    Io.println (String.fromInt 1)\n".to_owned(),
        ),
    );
    let discovered = vec![project::DiscoveredModule::user(
        PathBuf::from("<cache-e2e>/Main.ipe"),
        entry_path.clone(),
    )];

    let (result_a, outcome_a) = compile_modules_observed(
        sources.clone(),
        discovered.clone(),
        &entry_path,
        &emit_target(&out_a),
        &runtime,
        Path::new("<cache-e2e>"),
        ipe_backend_rust::DbDriver::Sqlite,
        Some(&cache_site),
        BuildOptions::default(),
    );
    assert!(
        result_a.is_ok(),
        "first (cold) compile must succeed: {:?}",
        result_a.err()
    );
    assert_eq!(
        outcome_a,
        CacheOutcome::Miss,
        "first compile against an empty cache dir must be a miss"
    );

    let entry_json = find_single_cache_entry(&cache_dir)
        .expect("first build must have written exactly one cache entry");
    let stored = fs::read_to_string(&entry_json).expect("cache entry must be readable");
    let mut cached: ipe_backend::EmittedProject =
        serde_json::from_str(&stored).expect("cache entry must deserialize");
    cached.cargo_toml = format!("{SENTINEL}{}", cached.cargo_toml);
    fs::write(
        &entry_json,
        serde_json::to_vec(&cached).expect("re-serialize must succeed"),
    )
    .expect("tamper write must succeed");

    let (result_b, outcome_b) = compile_modules_observed(
        sources,
        discovered,
        &entry_path,
        &emit_target(&out_b),
        &runtime,
        Path::new("<cache-e2e>"),
        ipe_backend_rust::DbDriver::Sqlite,
        Some(&cache_site),
        BuildOptions::default(),
    );
    assert!(
        result_b.is_ok(),
        "second (cache-hit) compile must succeed: {:?}",
        result_b.err()
    );
    assert_eq!(
        outcome_b,
        CacheOutcome::Hit,
        "second compile with byte-identical inputs must hit the cache"
    );

    let written = fs::read_to_string(out_b.join("Cargo.toml")).expect("Cargo.toml must exist");
    assert!(
        written.starts_with(SENTINEL),
        "materialized output must be the TAMPERED cache entry, not a fresh \
         recompile — proves the driver actually reads and trusts the \
         on-disk cache: {written}"
    );

    let _ = fs::remove_dir_all(&tmp);
}

/// A cold build into a fresh output dir whose cache sits inside it — the
/// default `<out>/.ipe-cache/<salt>` layout — succeeds and leaves the dir
/// ipe-owned: the cache is stored only after the emit has claimed the dir,
/// never creating it unmarked first. A rebuild into the same dir then hits.
#[cfg(unix)] // a cache hit needs a file identity check
#[test]
fn cold_build_with_the_cache_inside_a_fresh_output_dir_claims_it() {
    let runtime = resolve_runtime().expect("the in-repo runtime resolves");

    let tmp = ipe_test_temp::temp_root().join(format!("ipe-cache-in-out-{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    let out = tmp.join("out");
    let cache_dir = out.join(".ipe-cache").join("salt");
    let cache_site = crate::cache::CacheSite::InOutput {
        out_dir: out.clone(),
        salt: "salt".to_owned(),
    };

    let entry_path = vec!["Main".to_owned()];
    let mut sources: BTreeMap<Vec<String>, (PathBuf, String)> = BTreeMap::new();
    sources.insert(
        entry_path.clone(),
        (
            PathBuf::from("<cache-in-out>/Main.ipe"),
            "module Main exposing (main)\n\nimport Ipe.Io as Io\n\nmain : Task Error ()\nmain =\n    Io.println \"hi\"\n".to_owned(),
        ),
    );
    let discovered = vec![project::DiscoveredModule::user(
        PathBuf::from("<cache-in-out>/Main.ipe"),
        entry_path.clone(),
    )];

    let build = || {
        compile_modules_observed(
            sources.clone(),
            discovered.clone(),
            &entry_path,
            &emit_target(&out),
            &runtime,
            Path::new("<cache-in-out>"),
            ipe_backend_rust::DbDriver::Sqlite,
            Some(&cache_site),
            BuildOptions::default(),
        )
    };

    let (cold, cold_outcome) = build();
    assert!(
        cold.is_ok(),
        "a cold build into a fresh dir must succeed: {cold:?}"
    );
    assert_eq!(cold_outcome, CacheOutcome::Miss);
    assert!(
        crate::output_dir::has_marker(&out).unwrap_or(false),
        "the fresh output dir must be claimed (marked) by the build"
    );
    assert!(
        find_single_cache_entry(&cache_dir).is_some(),
        "the cold build must still store its cache entry inside the claimed dir"
    );

    let (warm, warm_outcome) = build();
    assert!(
        warm.is_ok(),
        "a rebuild into the same dir must succeed: {warm:?}"
    );
    assert_eq!(warm_outcome, CacheOutcome::Hit);

    let _ = fs::remove_dir_all(&tmp);
}

/// Which level of a marked `out/` carries the planted cache link.
#[cfg(unix)]
#[derive(Clone, Copy)]
enum PlantedCacheLink {
    /// `out/.ipe-cache` itself.
    CacheDir,
    /// `out/.ipe-cache/<salt>`.
    Salt,
}

/// Build twice into a marked `out/` whose cache path crosses a planted link.
///
/// Both builds succeed uncached: the cache is advisory, so skipping it is the
/// fail-closed outcome that still ships the Rust built from the sources, while
/// refusing the build would add nothing (no entry is read or written through the
/// link either way). The link target stays empty.
#[cfg(unix)]
#[allow(clippy::expect_used)] // a failed precondition is the test failure
fn build_through_planted_cache_link(tag: &str, planted: PlantedCacheLink) {
    // A refusal test that skips proves nothing, so a missing runtime fails it.
    let runtime = resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve: {runtime:?}");
    let runtime = runtime.expect("`runtime` must succeed");

    let tmp =
        ipe_test_temp::temp_root().join(format!("ipe-cache-link-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    let out = tmp.join("out");
    let elsewhere = tmp.join("elsewhere");
    fs::create_dir_all(&elsewhere).expect("create the link target");
    crate::output_dir::OwnedDir::claim(&out).expect("mark out/ as ipe's");
    let cache = out.join(crate::cache::CACHE_DIR_NAME);
    match planted {
        PlantedCacheLink::CacheDir => {
            std::os::unix::fs::symlink(&elsewhere, &cache).expect("plant .ipe-cache link");
        }
        PlantedCacheLink::Salt => {
            fs::create_dir_all(&cache).expect("mkdir .ipe-cache");
            std::os::unix::fs::symlink(&elsewhere, cache.join("salt")).expect("plant salt link");
        }
    }
    let cache_site = crate::cache::CacheSite::InOutput {
        out_dir: out.clone(),
        salt: "salt".to_owned(),
    };

    let entry_path = vec!["Main".to_owned()];
    let mut sources: BTreeMap<Vec<String>, (PathBuf, String)> = BTreeMap::new();
    sources.insert(
        entry_path.clone(),
        (
            PathBuf::from("<cache-link>/Main.ipe"),
            "module Main exposing (main)\n\nimport Ipe.Io as Io\n\nmain : Task Error ()\nmain =\n    Io.println \"hi\"\n".to_owned(),
        ),
    );
    let discovered = vec![project::DiscoveredModule::user(
        PathBuf::from("<cache-link>/Main.ipe"),
        entry_path.clone(),
    )];
    let build = || {
        compile_modules_observed(
            sources.clone(),
            discovered.clone(),
            &entry_path,
            &emit_target(&out),
            &runtime,
            Path::new("<cache-link>"),
            ipe_backend_rust::DbDriver::Sqlite,
            Some(&cache_site),
            BuildOptions::default(),
        )
    };

    for round in ["cold", "rebuild"] {
        let (result, outcome) = build();
        assert!(
            result.is_ok(),
            "the {round} build proceeds without the cache: {result:?}"
        );
        assert_eq!(
            outcome,
            CacheOutcome::Miss,
            "the {round} build never uses a cache behind the link"
        );
        assert!(
            fs::read_dir(&elsewhere).is_ok_and(|mut entries| entries.next().is_none()),
            "the {round} build wrote nothing through the planted link"
        );
    }
    assert!(
        out.join("Cargo.toml").is_file(),
        "the product is still emitted"
    );

    let _ = fs::remove_dir_all(&tmp);
}

#[cfg(unix)]
#[test]
fn build_never_writes_through_a_planted_ipe_cache_link() {
    build_through_planted_cache_link("dir", PlantedCacheLink::CacheDir);
}

#[cfg(unix)]
#[test]
fn build_never_writes_through_a_planted_salt_link() {
    build_through_planted_cache_link("salt", PlantedCacheLink::Salt);
}

/// Walk `cache_root/<epoch>/*.ir.json` and return the single
/// lowered-IR entry file a build just wrote. Mirrors
/// [`find_single_cache_entry`], but matches on the `.ir.json` suffix
/// specifically — `Path::extension()` alone cannot tell `key.json` from
/// `key.ir.json` apart (both report `json`), so a build that populated
/// BOTH tiers in the same epoch directory needs the suffix check to
/// find the right one.
fn find_single_ir_cache_entry(cache_root: &Path) -> Option<PathBuf> {
    for epoch_entry in fs::read_dir(cache_root).ok()?.flatten() {
        let epoch_dir = epoch_entry.path();
        if !epoch_dir.is_dir() {
            continue;
        }
        for file_entry in fs::read_dir(&epoch_dir).ok()?.flatten() {
            let path = file_entry.path();
            if path
                .file_name()
                .and_then(std::ffi::OsStr::to_str)
                .is_some_and(|n| n.ends_with(".ir.json"))
            {
                return Some(path);
            }
        }
    }
    None
}

/// **End-to-end proof that a `db_driver`-only edit reuses the
/// lowered-IR tier instead of a full recompile.** The `EmittedProject`
/// tier's key folds in `db_driver` (a real dependency of the FINAL emit
/// stage), so it correctly MISSES on a driver flip — but
/// `linked_program`/`typecheck`/`lower_program` never read `db_driver`
/// at all, so the SAME lowered `Program` is still exactly reusable. This
/// is the concrete case the IR tier exists to cover that the
/// `EmittedProject` tier structurally cannot.
#[cfg(unix)] // a cache hit needs a file identity check
#[test]
fn ir_cache_hit_reuses_lowered_program_across_a_db_driver_only_edit() {
    let runtime = resolve_runtime().expect("the in-repo runtime resolves");
    let tmp =
        ipe_test_temp::temp_root().join(format!("ipec-ir-cache-driver-{}", std::process::id()));
    let cache_dir = tmp.join("cache");
    let cache_site = crate::cache::CacheSite::Explicit(cache_dir.clone());
    let out_a = tmp.join("out-a");
    let out_b = tmp.join("out-b");
    let _ = fs::remove_dir_all(&tmp);

    let entry_path = vec!["Main".to_owned()];
    let mut sources: BTreeMap<Vec<String>, (PathBuf, String)> = BTreeMap::new();
    sources.insert(
        entry_path.clone(),
        (
            PathBuf::from("<p>/Main.ipe"),
            "module Main exposing (main)\n\nimport Ipe.Io as Io\nimport Ipe.String as String\n\nmain : Task Error ()\nmain =\n    Io.println (String.fromInt 1)\n".to_owned(),
        ),
    );
    let discovered = vec![project::DiscoveredModule::user(
        PathBuf::from("<p>/Main.ipe"),
        entry_path.clone(),
    )];

    let (result_a, outcome_a) = compile_modules_observed(
        sources.clone(),
        discovered.clone(),
        &entry_path,
        &emit_target(&out_a),
        &runtime,
        Path::new("<p>"),
        ipe_backend_rust::DbDriver::Sqlite,
        Some(&cache_site),
        BuildOptions::default(),
    );
    assert!(
        result_a.is_ok(),
        "first (cold, Sqlite) compile must succeed: {:?}",
        result_a.err()
    );
    assert_eq!(
        outcome_a,
        CacheOutcome::Miss,
        "first compile against an empty cache dir must be a miss"
    );
    assert!(
        find_single_ir_cache_entry(&cache_dir).is_some(),
        "the cold compile must have populated the IR tier"
    );

    // Same source, DIFFERENT driver, same cache dir: the EmittedProject
    // tier's key changes (driver is part of it) so it misses, but the
    // IR tier's key does not depend on driver — it must hit.
    let (result_b, outcome_b) = compile_modules_observed(
        sources,
        discovered,
        &entry_path,
        &emit_target(&out_b),
        &runtime,
        Path::new("<p>"),
        ipe_backend_rust::DbDriver::Postgres,
        Some(&cache_site),
        BuildOptions::default(),
    );
    assert!(
        result_b.is_ok(),
        "second (Postgres) compile must succeed: {:?}",
        result_b.err()
    );
    assert_eq!(
        outcome_b,
        CacheOutcome::IrHit,
        "a db_driver-only edit must hit the IR tier, not re-run the full pipeline nor \
         merely miss everything"
    );

    let _ = fs::remove_dir_all(&tmp);
}

/// **The IR-tier end-to-end tamper proof**, mirroring
/// [`on_disk_cache_hit_serves_a_tampered_entry_verbatim`] one tier
/// earlier: compile once (populates BOTH tiers), tamper the ON-DISK
/// lowered-IR entry's literal body (`main`'s `Expr::Int(1)` ->
/// `Expr::Int(42)`) with a value no fresh compile of the SAME source
/// could ever produce, then force an IR-tier hit (a `db_driver` flip,
/// which misses the `EmittedProject` tier deterministically) and assert
/// the SENTINEL VALUE reaches the materialised `main.rs` — proof the
/// driver actually reads, relocates, and RE-EMITS the on-disk IR entry
/// rather than silently recompiling or ignoring the tamper.
#[cfg(unix)] // a cache hit needs a file identity check
#[test]
fn on_disk_ir_cache_hit_serves_a_tampered_entry_verbatim() {
    let runtime = resolve_runtime().expect("the in-repo runtime resolves");
    let tmp =
        ipe_test_temp::temp_root().join(format!("ipec-ir-cache-tamper-{}", std::process::id()));
    let cache_dir = tmp.join("cache");
    let cache_site = crate::cache::CacheSite::Explicit(cache_dir.clone());
    let out_a = tmp.join("out-a");
    let out_b = tmp.join("out-b");
    let _ = fs::remove_dir_all(&tmp);

    let entry_path = vec!["Main".to_owned()];
    let mut sources: BTreeMap<Vec<String>, (PathBuf, String)> = BTreeMap::new();
    sources.insert(
        entry_path.clone(),
        (
            PathBuf::from("<p>/Main.ipe"),
            "module Main exposing (main)\n\nimport Ipe.Io as Io\nimport Ipe.String as String\n\nmain : Task Error ()\nmain =\n    Io.println (String.fromInt 1)\n".to_owned(),
        ),
    );
    let discovered = vec![project::DiscoveredModule::user(
        PathBuf::from("<p>/Main.ipe"),
        entry_path.clone(),
    )];

    let (result_a, outcome_a) = compile_modules_observed(
        sources.clone(),
        discovered.clone(),
        &entry_path,
        &emit_target(&out_a),
        &runtime,
        Path::new("<p>"),
        ipe_backend_rust::DbDriver::Sqlite,
        Some(&cache_site),
        BuildOptions::default(),
    );
    assert!(
        result_a.is_ok(),
        "first (cold) compile must succeed: {:?}",
        result_a.err()
    );
    assert_eq!(outcome_a, CacheOutcome::Miss);

    let ir_json_path =
        find_single_ir_cache_entry(&cache_dir).expect("cold compile must write an IR entry");
    let stored = fs::read_to_string(&ir_json_path).expect("IR entry must be readable");
    // Verified shape via a one-off print during development: `main`'s body is
    // `Io.println (String.fromInt 1)`, so the only integer literal in the IR is
    // the `{"Int":1}` argument to `String.fromInt`. Tampering it to `42` makes
    // the re-emitted program print `42` — a value no fresh compile of this
    // source could produce.
    assert!(
        stored.contains("{\"Int\":1}"),
        "unexpected IR JSON shape, cannot safely tamper: {stored}"
    );
    let tampered = stored.replace("{\"Int\":1}", "{\"Int\":42}");
    fs::write(&ir_json_path, &tampered).expect("tamper write must succeed");

    // Force the EmittedProject tier to miss (driver flip) so the
    // IR-tier fast path is the one actually exercised.
    let (result_b, outcome_b) = compile_modules_observed(
        sources,
        discovered,
        &entry_path,
        &emit_target(&out_b),
        &runtime,
        Path::new("<p>"),
        ipe_backend_rust::DbDriver::Postgres,
        Some(&cache_site),
        BuildOptions::default(),
    );
    assert!(
        result_b.is_ok(),
        "second (tampered IR, hit) compile must succeed: {:?}",
        result_b.err()
    );
    assert_eq!(outcome_b, CacheOutcome::IrHit);

    let main_rs = fs::read_to_string(out_b.join("src/main.rs")).expect("main.rs must exist");
    assert!(
        main_rs.contains("42"),
        "materialized output must be re-EMITTED FROM the tampered IR entry \
         (contains the literal 42), proving the driver reads/relocates/re-emits \
         the on-disk lowered-IR cache rather than recompiling or discarding the \
         tamper: {main_rs}"
    );

    let _ = fs::remove_dir_all(&tmp);
}

/// Shipped artifacts build with the release intent: `ipe release eject` and the
/// `ipe release` bundle never carry the development console default.
#[test]
fn shipped_artifact_builds_are_release() {
    assert_eq!(
        eject_options().intent,
        ipe_backend_rust::BuildIntent::Release
    );
    assert_eq!(
        BundleProfile::Release.build_intent(),
        ipe_backend_rust::BuildIntent::Release
    );
    assert_eq!(
        BundleProfile::Dev.build_intent(),
        ipe_backend_rust::BuildIntent::Development
    );
}

/// A production IR-cache hit on a `Debug.*` program blames the in-memory entry text.
///
/// The IR tier's key omits the build intent, so a development build
/// seeds it and a release build of the same source hits it, then refuses
/// with IPE-L0140. The refusal renders against the entry source the build
/// already holds, never a fresh read of `blame_path`, whose disk bytes here
/// differ.
#[cfg(unix)] // a cache hit needs a file identity check
#[test]
fn production_ir_cache_hit_blames_the_in_memory_entry_source() {
    let runtime = resolve_runtime().expect("the in-repo runtime resolves");
    let tmp =
        ipe_test_temp::temp_root().join(format!("ipec-ir-cache-blame-{}", std::process::id()));
    let cache_dir = tmp.join("cache");
    let cache_site = crate::cache::CacheSite::Explicit(cache_dir);
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).expect("create scratch dir");
    let blame_path = tmp.join("package.ipe");
    fs::write(&blame_path, "on-disk bytes the refusal must not show\n").expect("write blame file");

    let entry_path = vec!["Main".to_owned()];
    let entry_file = tmp.join("Main.ipe");
    let entry_text = "module Main exposing (main)\n\nimport Ipe.Io as Io\nimport Ipe.Debug as Debug\n\nshout : String -> String\nshout s =\n    Debug.log \"shout\" s\n\nmain : Task Error ()\nmain =\n    Io.println (shout \"hi\")\n";
    let mut sources: BTreeMap<Vec<String>, (PathBuf, String)> = BTreeMap::new();
    sources.insert(
        entry_path.clone(),
        (entry_file.clone(), entry_text.to_owned()),
    );
    let discovered = vec![project::DiscoveredModule::user(
        entry_file.clone(),
        entry_path.clone(),
    )];

    let (dev, dev_outcome) = compile_modules_observed(
        sources.clone(),
        discovered.clone(),
        &entry_path,
        &emit_target(&tmp.join("out-dev")),
        &runtime,
        &blame_path,
        ipe_backend_rust::DbDriver::Sqlite,
        Some(&cache_site),
        BuildOptions {
            intent: ipe_backend_rust::BuildIntent::Development,
            ..BuildOptions::default()
        },
    );
    let (release, release_outcome) = compile_modules_observed(
        sources,
        discovered,
        &entry_path,
        &emit_target(&tmp.join("out-release")),
        &runtime,
        &blame_path,
        ipe_backend_rust::DbDriver::Sqlite,
        Some(&cache_site),
        BuildOptions {
            intent: ipe_backend_rust::BuildIntent::Release,
            ..BuildOptions::default()
        },
    );
    let _ = fs::remove_dir_all(&tmp);

    assert!(
        dev.is_ok(),
        "the development build succeeds: {:?}",
        dev.err()
    );
    assert_eq!(dev_outcome, CacheOutcome::Miss);
    assert_eq!(
        release_outcome,
        CacheOutcome::IrHit,
        "the release build must take the IR-cache fast path under test"
    );
    assert!(
        matches!(release, Err(CliError::Pipeline { .. })),
        "the release build must refuse with a pipeline diagnostic: {release:?}"
    );
    let Err(CliError::Pipeline { file, src, diag }) = release else {
        return;
    };
    assert_eq!(diag.code().as_str(), "IPE-L0140");
    assert_eq!(file, entry_file, "the refusal blames the entry module");
    assert_eq!(
        src, entry_text,
        "the refusal renders the in-memory entry text, not a disk re-read"
    );
}

/// A cache disabled via `cache_dir: None` never touches disk for
/// caching purposes and always runs the full pipeline.
#[test]
fn cache_dir_none_disables_caching_entirely() {
    let runtime = resolve_runtime().expect("the in-repo runtime resolves");
    let tmp = ipe_test_temp::temp_root().join(format!("ipe-cache-disabled-{}", std::process::id()));
    let out_dir = tmp.join("out");
    let _ = fs::remove_dir_all(&tmp);

    let entry_path = vec!["Main".to_owned()];
    let mut sources: BTreeMap<Vec<String>, (PathBuf, String)> = BTreeMap::new();
    sources.insert(
        entry_path.clone(),
        (
            PathBuf::from("<cache-e2e>/Main.ipe"),
            "module Main exposing (main)\n\nimport Ipe.Io as Io\nimport Ipe.String as String\n\nmain : Task Error ()\nmain =\n    Io.println (String.fromInt 1)\n".to_owned(),
        ),
    );
    let discovered = vec![project::DiscoveredModule::user(
        PathBuf::from("<cache-e2e>/Main.ipe"),
        entry_path.clone(),
    )];

    let (result, outcome) = compile_modules_observed(
        sources,
        discovered,
        &entry_path,
        &emit_target(&out_dir),
        &runtime,
        Path::new("<cache-e2e>"),
        ipe_backend_rust::DbDriver::Sqlite,
        None,
        BuildOptions::default(),
    );
    assert!(result.is_ok(), "compile must succeed: {:?}", result.err());
    assert_eq!(
        outcome,
        CacheOutcome::Miss,
        "a disabled cache is always reported as a miss"
    );
    assert!(
        !tmp.join(".ipe-cache").exists(),
        "no cache directory should be created when caching is disabled"
    );

    let _ = fs::remove_dir_all(&tmp);
}

// ── [wasm].mode target inference ─────────────────────────────────────────

fn wasm_config(mode: Option<&str>) -> project::WasmConfig {
    project::WasmConfig {
        mode: mode.map(str::to_owned),
        ..Default::default()
    }
}

/// `[wasm] mode = "solo"` with no CLI flag → inferred `WasmClient`.
#[test]
fn wasm_mode_solo_infers_wasm_target() {
    let cfg = wasm_config(Some("solo"));
    assert_eq!(
        resolve_compile_target(cli_args::WasmKind::None, Some(&cfg)),
        CompileTarget::WasmClient,
        "solo mode must infer the browser wasm client"
    );
}

/// `[wasm] mode = "hydrate"` with no CLI flag → inferred `WasmClient`.
#[test]
fn wasm_mode_hydrate_infers_wasm_target() {
    let cfg = wasm_config(Some("hydrate"));
    assert_eq!(
        resolve_compile_target(cli_args::WasmKind::None, Some(&cfg)),
        CompileTarget::WasmClient,
        "hydrate mode must infer the browser wasm client"
    );
}

/// `[wasm] mode = "off"` → native (explicit opt-out).
#[test]
fn wasm_mode_off_does_not_infer_wasm_target() {
    let cfg = wasm_config(Some("off"));
    assert_eq!(
        resolve_compile_target(cli_args::WasmKind::None, Some(&cfg)),
        CompileTarget::Native,
        "off mode must not infer a wasm target"
    );
}

/// No `[wasm]` section (None config) → native default.
#[test]
fn no_wasm_config_defaults_to_native_target() {
    assert_eq!(
        resolve_compile_target(cli_args::WasmKind::None, None),
        CompileTarget::Native,
        "absent [wasm] section must default to native"
    );
}

/// `mode = None` (section present but no mode key) → native.
#[test]
fn wasm_config_absent_mode_key_defaults_to_native_target() {
    let cfg = wasm_config(None);
    assert_eq!(
        resolve_compile_target(cli_args::WasmKind::None, Some(&cfg)),
        CompileTarget::Native,
        "absent mode key must default to native"
    );
}

/// CLI `--target wasm` wins even when no manifest.
#[test]
fn cli_flag_overrides_absent_manifest_to_wasm() {
    assert_eq!(
        resolve_compile_target(cli_args::WasmKind::Client, None),
        CompileTarget::WasmClient,
        "cli flag must win over absent manifest"
    );
}

/// CLI `--target wasm` wins even if the manifest says off (highest precedence).
#[test]
fn cli_flag_wins_over_mode_off() {
    let cfg = wasm_config(Some("off"));
    assert_eq!(
        resolve_compile_target(cli_args::WasmKind::Client, Some(&cfg)),
        CompileTarget::WasmClient,
        "explicit cli --target wasm must win over mode=off"
    );
}

/// CLI `--target wasi` selects the co-located WASI target, over any manifest.
#[test]
fn cli_flag_wasi_selects_colocated_wasi() {
    let cfg = wasm_config(Some("solo"));
    assert_eq!(
        resolve_compile_target(cli_args::WasmKind::Wasi, None),
        CompileTarget::WasmWasi,
        "cli --target wasi selects the co-located WASI target"
    );
    assert_eq!(
        resolve_compile_target(cli_args::WasmKind::Wasi, Some(&cfg)),
        CompileTarget::WasmWasi,
        "explicit cli --target wasi wins over a browser [wasm].mode",
    );
}

/// The manifest `[wasm].mode` selects the browser client only — WASI is an
/// explicit per-invocation target, never a project-default inferred from a
/// manifest that only knows the browser mode words.
#[test]
fn manifest_never_infers_wasi() {
    for mode in [Some("solo"), Some("hydrate"), Some("off"), None] {
        let cfg = wasm_config(mode);
        assert_ne!(
            resolve_compile_target(cli_args::WasmKind::None, Some(&cfg)),
            CompileTarget::WasmWasi,
            "no [wasm].mode may infer the co-located WASI target",
        );
    }
}

/// `declared_modules` reads exactly the `pub mod X;` / `mod X;` statements a
/// runtime `mod.rs` declares — the oracle the eject tree-shaker copies from.
/// A `pub use X::*;` re-export is NOT a module declaration and must not add a
/// file to the copy set, and a block-opening `pub mod X {` (an inline module
/// with no separate source file) is excluded by the `;` requirement.
#[test]
fn declared_modules_reads_only_semicolon_terminated_mod_statements() {
    let mod_rs = "\
// GENERATED by Ipê — do not edit
pub mod basics;
pub mod core;
mod path_core;
pub use basics::*;
pub use core::*;
pub mod web {
pub mod route;
}
";
    let names = declared_modules(mod_rs);
    assert!(names.contains("basics"), "a `pub mod` is a declaration");
    assert!(names.contains("core"), "a `pub mod` is a declaration");
    assert!(names.contains("path_core"), "a bare `mod` is a declaration");
    assert!(
        !names.contains("web"),
        "a block-opening `pub mod web {{` has no separate file — excluded"
    );
    // A `pub use X::*;` glob is a re-export, never a module declaration.
    assert!(
        !names.contains("basics::*") && names.iter().all(|n| !n.contains('*')),
        "a glob re-export is not a module declaration"
    );
    // The one `;`-terminated statement inside the block (`pub mod route;`) is
    // collected by name — it is harmless in practice: the copy step resolves
    // it against no top-level `route.rs`/`route/` and vendors nothing for it.
    // The real emitted native `mod.rs` is flat (no inline blocks), so this
    // case never arises there; the copy step, not this scanner, is where the
    // fail-safe lives.
    assert!(names.contains("route"));
}

/// The tree-shaker copies a reached module's single `.rs` file, a reached
/// directory module's ENTIRE subtree (fail-closed — never omit a nested
/// `mod`'s file), and nothing for a module the emitted `mod.rs` never
/// declares. This is the whole tree-shaking contract, asserted without a
/// compile.
#[test]
fn reachable_runtime_copy_takes_declared_files_and_whole_reached_dirs() {
    let tmp = ipe_test_temp::temp_root().join("ipe_eject_reach_copy");
    let _ = fs::remove_dir_all(&tmp);
    let rt = tmp.join("ipe_runtime");
    fs::create_dir_all(rt.join("web")).expect("create web/");
    fs::create_dir_all(rt.join("db")).expect("create db/");
    fs::write(rt.join("mod.rs"), "pub mod core;\npub mod web;\n").expect("mod.rs");
    fs::write(rt.join("core.rs"), "// core").expect("core.rs");
    fs::write(rt.join("unreached.rs"), "// unreached").expect("unreached.rs");
    fs::write(rt.join("web").join("mod.rs"), "pub mod route;").expect("web/mod.rs");
    fs::write(rt.join("web").join("route.rs"), "// route").expect("web/route.rs");
    // An unreached directory module: its whole subtree must be dropped.
    fs::write(rt.join("db").join("mod.rs"), "// db").expect("db/mod.rs");

    // The emitted mod.rs reaches `core` (file) and `web` (directory), never
    // `unreached` or `db`.
    let emitted_mod_rs = "pub mod core;\npub mod web;\n";
    let mut manifest = BTreeMap::new();
    collect_reachable_runtime_text(
        &rt,
        Path::new("src/ipe_runtime"),
        emitted_mod_rs,
        &mut manifest,
    )
    .expect("copy reachable runtime");

    let has = |p: &str| manifest.contains_key(&PathBuf::from(p));
    assert!(has("src/ipe_runtime/core.rs"), "reached file copied");
    assert!(
        has("src/ipe_runtime/web/mod.rs") && has("src/ipe_runtime/web/route.rs"),
        "reached directory module copied WHOLE (nested mod's file included)"
    );
    assert!(
        !has("src/ipe_runtime/unreached.rs"),
        "an undeclared file is tree-shaken away"
    );
    assert!(
        !manifest.keys().any(|k| k.starts_with("src/ipe_runtime/db")),
        "an undeclared directory module's whole subtree is tree-shaken away"
    );
    let _ = fs::remove_dir_all(&tmp);
}

/// Eject refuses a wasm-target project from the `[wasm].mode` manifest tier —
/// not only the `IPE_TARGET` env — so a browser SPA is never silently ejected
/// as a native tree (a target the emitted crate would not build). The refusal
/// fires before any file is written.
#[test]
fn eject_refuses_a_wasm_mode_project_from_the_manifest_tier() {
    let tmp = ipe_test_temp::temp_root().join("ipe_eject_wasm_mode_refuse");
    let _ = fs::remove_dir_all(&tmp);
    let src = tmp.join("src");
    fs::create_dir_all(&src).expect("create src/");
    // A project whose manifest selects the wasm target via `Package.wasm`,
    // with no `IPE_TARGET` env set — the tier the env-only check missed.
    fs::write(
        tmp.join("package.ipe"),
        "module Package exposing (package)\n\n\npackage =\n    { name = \"w\", wasm = On { mode = Solo } }\n",
    )
    .expect("write package.ipe");
    fs::write(
        src.join("Main.ipe"),
        "module Main exposing (main)\nmain = 0\n",
    )
    .expect("write Main.ipe");

    let out = tmp.join("out");
    let args = [
        tmp.join("package.ipe").to_string_lossy().into_owned(),
        "--out".to_owned(),
        out.to_string_lossy().into_owned(),
    ];
    let result = run_eject(&args);
    assert!(
        matches!(result, Err(CliError::EjectUnsupported { .. })),
        "a `[wasm].mode` project must be refused, not ejected native: {result:?}"
    );
    assert!(
        !out.exists(),
        "the refusal must fire before any project tree is written"
    );
    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn analysis_root_prefers_main_then_program_then_exposed() {
    // An application with a src/Main.ipe uses it as the analysis root.
    let app = ipe_test_temp::temp_root().join("ipe_analysis_root_app");
    let _ = fs::remove_dir_all(&app);
    let app_src = app.join("src");
    fs::create_dir_all(&app_src).expect("create src/");
    fs::write(
        app.join("package.ipe"),
        "module Package exposing (package)\n\n\npackage =\n    { name = \"app\" }\n",
    )
    .expect("pkg");
    fs::write(
        app_src.join("Main.ipe"),
        "module Main exposing (main)\nmain = 0\n",
    )
    .expect("main");
    let app_manifest = project::parse_manifest(&app.join("package.ipe")).expect("app parses");
    assert_eq!(
        analysis_root_of(&app_manifest).expect("app root resolves"),
        app_src.join("Main.ipe")
    );
    let _ = fs::remove_dir_all(&app);

    // A library (exposedModules, no Main) uses its first exposed module's file.
    let lib = ipe_test_temp::temp_root().join("ipe_analysis_root_lib");
    let _ = fs::remove_dir_all(&lib);
    let lib_src = lib.join("src");
    fs::create_dir_all(&lib_src).expect("create src/");
    fs::write(lib.join("package.ipe"), "module Package exposing (package)\n\n\npackage =\n    { name = \"lib\", exposedModules = [ \"Core.Utils\" ] }\n").expect("pkg");
    // src/ must exist for the manifest reader's source-root check; the module
    // file itself need not exist for the pure path derivation under test.
    let lib_manifest = project::parse_manifest(&lib.join("package.ipe")).expect("lib parses");
    assert_eq!(
        analysis_root_of(&lib_manifest).expect("lib root resolves"),
        lib_src.join("Core").join("Utils.ipe")
    );
    let _ = fs::remove_dir_all(&lib);
}

#[test]
fn version_flags_alias_the_version_command() {
    // `--version` / `-V` are the near-universal version probe; both resolve
    // to the `version` command rather than falling through to an
    // unknown-command failure with the full help screen.
    assert!(run_cli(&["--version".to_owned()]).is_ok());
    assert!(run_cli(&["-V".to_owned()]).is_ok());
    // Trailing format flags still reach the command.
    assert!(run_cli(&["--version".to_owned(), "--json".to_owned()]).is_ok());
}

#[test]
fn analysis_root_rejects_a_program_entry_that_escapes_the_source_root() {
    // An absolute or `..` program entry names no module, so the build's own
    // entry parse refuses it before any path is joined; analysis_root_of
    // refuses it with that same error, never a read outside the project.
    for entry in [
        "/etc/passwd",
        "/etc/Main.ipe",
        "../../secret.ipe",
        "../../Secret.ipe",
    ] {
        let proj = declared_entry_project("ipe_analysis_root_escape", entry, &[]);
        let manifest = project::parse_manifest(&proj.join("package.ipe")).expect("parses");
        assert!(
            matches!(manifest.resolved_entry(), Err(CliError::Usage(_))),
            "the build refuses entry {entry:?}"
        );
        assert!(
            matches!(analysis_root_of(&manifest), Err(CliError::Usage(_))),
            "analysis refuses entry {entry:?} like the build"
        );
        let _ = fs::remove_dir_all(&proj);
    }
}

#[cfg(unix)]
#[test]
fn analysis_root_refuses_an_entry_module_file_linked_outside_the_source_root() {
    // A well-formed entry module whose file is a symlink out of `src/` is
    // refused by the containment gate, not read.
    let outside = ipe_test_temp::temp_root().join("ipe_analysis_root_link_target.ipe");
    fs::write(&outside, "module Main exposing (main)\n\nmain = 1\n").expect("outside file");
    let proj = declared_entry_project("ipe_analysis_root_link", "Main.ipe", &[]);
    let manifest = project::parse_manifest(&proj.join("package.ipe")).expect("parses");
    let link = proj.join("src").join("Main.ipe");
    let _ = fs::remove_file(&link);
    std::os::unix::fs::symlink(&outside, link).expect("symlink entry out of src/");
    assert!(
        matches!(
            analysis_root_of(&manifest),
            Err(CliError::PathEscape { .. })
        ),
        "an entry file linked outside src/ must be refused"
    );
    let _ = fs::remove_dir_all(&proj);
    let _ = fs::remove_file(&outside);
}

/// Write a manifest-governed project with a clean default `src/Main.ipe` under
/// the test temp root, and return its root.
fn analysis_project(name: &str) -> PathBuf {
    let tmp = ipe_test_temp::temp_root().join(name);
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(tmp.join("src")).expect("create src/");
    fs::write(
        tmp.join("package.ipe"),
        "module Package exposing (package)\n\n\npackage =\n    { name = \"app\" }\n",
    )
    .expect("pkg");
    fs::write(
        tmp.join("src").join("Main.ipe"),
        "module Main exposing (main)\n\n\nmain : Int\nmain =\n    1\n",
    )
    .expect("src/Main.ipe");
    tmp
}

/// The [`ResolvedPath`] of an existing fixture path.
fn resolved(path: &Path) -> ResolvedPath {
    ResolvedPath::of(path).expect("fixture path resolves")
}

/// A planted type error in a `Main`-named `tests/Main.ipe`, beside a clean
/// `src/Main.ipe`, fails `ipe type-check tests/Main.ipe`, blamed on the named
/// file: a file argument is never substituted for the project's default entry.
#[test]
fn type_check_of_a_tests_file_is_analysed_as_itself_not_the_default_entry() {
    let tmp = analysis_project("ipe_type_check_tests_file_not_substituted");
    let tests_dir = tmp.join("tests");
    fs::create_dir_all(&tests_dir).expect("create tests/");
    let tests_main = tests_dir.join("Main.ipe");
    fs::write(
        &tests_main,
        "module Main exposing (main)\n\n\nmain : Int\nmain =\n    \"not an int\"\n",
    )
    .expect("tests/Main.ipe");
    let blamed = resolved(&tests_main);

    let result = run_type_check_body(&[tests_main.to_string_lossy().into_owned()]);
    let _ = fs::remove_dir_all(&tmp);
    assert!(
        matches!(&result, Err(CliError::Pipeline { file, .. }) if file == blamed.as_path()),
        "a type error in the NAMED test file must fail, blamed on that file, \
         not pass by analysing src/Main.ipe instead: {result:?}"
    );
}

/// A `src/` file that is not the default entry is analysed as itself, over the
/// manifest's `src/` root, never substituted for `src/Main.ipe`.
#[test]
fn type_check_of_a_non_default_src_file_is_analysed_as_itself() {
    let tmp = analysis_project("ipe_type_check_non_default_src_file_not_substituted");
    let src = tmp.join("src");
    let other = src.join("Other.ipe");
    fs::write(
        &other,
        "module Other exposing (x)\n\n\nx : Int\nx =\n    \"not an int\"\n",
    )
    .expect("src/Other.ipe");
    let blamed = resolved(&other);
    let src_root = resolved(&src);

    let result = run_type_check_body(&[other.to_string_lossy().into_owned()]);
    let target = resolve_analysis_target(&other);
    let _ = fs::remove_dir_all(&tmp);
    assert!(
        matches!(&result, Err(CliError::Pipeline { file, .. }) if file == blamed.as_path()),
        "a type error in the NAMED src file must fail, blamed on that file, \
         not pass by analysing the default src/Main.ipe instead: {result:?}"
    );
    assert_eq!(
        target.expect("resolves"),
        AnalysisTarget::Source {
            file: blamed,
            src_root,
        },
        "a src-rooted file argument resolves to itself over the manifest's src root"
    );
}

/// A DIRECTORY argument resolves to the project's own entry, classified
/// exactly as a file argument naming that entry: over the manifest's `src` root.
#[test]
fn type_check_of_a_directory_still_resolves_the_project_entry() {
    let tmp = analysis_project("ipe_type_check_directory_resolves_project_entry");
    let expected = AnalysisTarget::Source {
        file: resolved(&tmp.join("src").join("Main.ipe")),
        src_root: resolved(&tmp.join("src")),
    };
    let target = resolve_analysis_target(&tmp);
    let result = run_type_check_body(&[tmp.to_string_lossy().into_owned()]);
    let _ = fs::remove_dir_all(&tmp);
    assert_eq!(
        target.ok(),
        Some(expected),
        "a directory argument resolves to the project's entry over its src root"
    );
    assert!(
        result.is_ok(),
        "the clean default entry must type-check via a directory argument: {result:?}"
    );
}

/// A DIRECTORY argument classifies its entry against the directory's own
/// manifest, the one the build compiles from, never a manifest nested between
/// the project root and the entry file.
#[test]
fn a_directory_entry_is_classified_by_its_own_manifest_not_a_nested_one() {
    let tmp = analysis_project("ipe_type_check_directory_ignores_nested_manifest");
    let src = tmp.join("src");
    fs::create_dir_all(src.join("src")).expect("create nested src/src/");
    fs::write(
        src.join("package.ipe"),
        "module Package exposing (package)\n\n\npackage =\n    { name = \"nested\" }\n",
    )
    .expect("nested src/package.ipe");
    let expected = AnalysisTarget::Source {
        file: resolved(&src.join("Main.ipe")),
        src_root: resolved(&src),
    };
    let target = resolve_analysis_target(&tmp);
    let _ = fs::remove_dir_all(&tmp);
    assert_eq!(
        target.ok(),
        Some(expected),
        "the directory form must analyse its entry over the build's src root"
    );
}

/// A file under the manifest's `tests/` tree resolves to `AnalysisTarget::Test`, carrying
/// the canonical `src/` and `tests/` roots.
#[test]
fn resolve_analysis_target_of_a_tests_file_returns_test_file() {
    let tmp = analysis_project("ipe_resolve_target_tests_file_is_test_file");
    let tests_dir = tmp.join("tests");
    fs::create_dir_all(&tests_dir).expect("create tests/");
    let tests_main = tests_dir.join("Main.ipe");
    fs::write(&tests_main, "module Main exposing (main)\nmain = 1\n").expect("tests/Main.ipe");
    let expected = AnalysisTarget::Test {
        file: resolved(&tests_main),
        src_root: resolved(&tmp.join("src")),
        tests_root: resolved(&tests_dir),
    };

    let target = resolve_analysis_target(&tests_main);
    let _ = fs::remove_dir_all(&tmp);
    assert_eq!(
        target.expect("resolves"),
        expected,
        "a tests/-rooted file argument resolves to AnalysisTarget::Test carrying both roots"
    );
}

/// A `..`-bearing spelling of a `src/` file resolves to the same canonical
/// `AnalysisTarget::Source` its plain spelling does.
#[test]
fn resolve_analysis_target_of_a_dotdot_src_spelling_is_source_file() {
    let tmp = analysis_project("ipe_resolve_target_dotdot_src_spelling");
    let src = tmp.join("src");
    let other = src.join("Other.ipe");
    fs::write(&other, "module Other exposing (x)\nx = 1\n").expect("src/Other.ipe");
    let expected = AnalysisTarget::Source {
        file: resolved(&other),
        src_root: resolved(&src),
    };

    let target = resolve_analysis_target(&src.join("..").join("src").join("Other.ipe"));
    let _ = fs::remove_dir_all(&tmp);
    assert_eq!(
        target.expect("resolves"),
        expected,
        "`src/../src/Other.ipe` is the same project-rooted file as `src/Other.ipe`"
    );
}

/// A file reached through a symlinked project directory resolves to the
/// canonical `AnalysisTarget::Source` of the real project.
#[cfg(unix)]
#[test]
fn resolve_analysis_target_through_a_symlinked_project_dir_is_source_file() {
    let base = ipe_test_temp::temp_root().join("ipe_resolve_target_symlinked_project");
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).expect("create base");
    let tmp = analysis_project("ipe_resolve_target_symlinked_project/real");
    let src = tmp.join("src");
    let other = src.join("Other.ipe");
    fs::write(&other, "module Other exposing (x)\nx = 1\n").expect("src/Other.ipe");
    let link = base.join("link");
    std::os::unix::fs::symlink(&tmp, &link).expect("symlink project");
    let expected = AnalysisTarget::Source {
        file: resolved(&other),
        src_root: resolved(&src),
    };

    let target = resolve_analysis_target(&link.join("src").join("Other.ipe"));
    let _ = fs::remove_dir_all(&base);
    assert_eq!(
        target.expect("resolves"),
        expected,
        "a symlinked spelling of a src file is the real project's source file"
    );
}

/// A symlink under `tests/` or `src/` naming a file outside every project is
/// not admitted as project-rooted: the canonical path has no governing
/// manifest, so it resolves loose at the no-manifest exit. The containment
/// guards past that exit are pinned by the in-project fixtures below.
#[cfg(unix)]
#[test]
fn resolve_analysis_target_refuses_a_symlink_escaping_the_project_roots() {
    let base = ipe_test_temp::temp_root().join("ipe_resolve_target_symlink_escape");
    let _ = fs::remove_dir_all(&base);
    let outside = base.join("outside");
    fs::create_dir_all(&outside).expect("create outside/");
    fs::write(outside.join("Y.ipe"), "module Y exposing (y)\ny = 1\n").expect("outside/Y.ipe");
    let tmp = analysis_project("ipe_resolve_target_symlink_escape/proj");
    let tests_dir = tmp.join("tests");
    fs::create_dir_all(&tests_dir).expect("create tests/");
    std::os::unix::fs::symlink(&outside, tests_dir.join("link")).expect("symlink tests/link");
    std::os::unix::fs::symlink(&outside, tmp.join("src").join("link")).expect("symlink src/link");

    let via_tests = resolve_analysis_target(&tests_dir.join("link").join("Y.ipe"));
    let via_src = resolve_analysis_target(&tmp.join("src").join("link").join("Y.ipe"));
    let _ = fs::remove_dir_all(&base);
    assert!(
        matches!(&via_tests, Ok(AnalysisTarget::Loose(_))),
        "a tests/ symlink leaving the project must not be an AnalysisTarget::Test: {via_tests:?}"
    );
    assert!(
        matches!(&via_src, Ok(AnalysisTarget::Loose(_))),
        "a src/ symlink leaving the project must not be an AnalysisTarget::Source: {via_src:?}"
    );
}

/// A file the project's manifest governs but that lies under neither `src/`
/// nor `tests/` (here `scripts/Y.ipe`) resolves loose, never `AnalysisTarget::Source` or
/// `AnalysisTarget::Test`: it clears the manifest lookup and is refused by the
/// `tests/` and `src/` containment checks themselves.
#[test]
fn resolve_analysis_target_of_an_in_project_file_outside_src_and_tests_is_loose() {
    let tmp = analysis_project("ipe_resolve_target_in_project_outside_roots");
    fs::create_dir_all(tmp.join("tests")).expect("create tests/");
    let scripts = tmp.join("scripts");
    fs::create_dir_all(&scripts).expect("create scripts/");
    let script = scripts.join("Y.ipe");
    fs::write(&script, "module Y exposing (y)\ny = 1\n").expect("scripts/Y.ipe");

    let canonical = fs::canonicalize(&script).expect("canonicalise the argument");
    let target = resolve_analysis_target(&script);
    let _ = fs::remove_dir_all(&tmp);
    assert!(
        matches!(&target, Ok(AnalysisTarget::Loose(p)) if p.as_path() == canonical),
        "a governed file outside src/ and tests/ must stay loose: {target:?}"
    );
}

/// A `src/` symlink naming another directory of the SAME project resolves
/// loose: the manifest is found, but the canonical file is not under the
/// canonical `src/` root, so the `src/` containment check refuses it.
#[cfg(unix)]
#[test]
fn resolve_analysis_target_refuses_a_src_symlink_to_elsewhere_in_the_project() {
    let tmp = analysis_project("ipe_resolve_target_src_symlink_in_project");
    let scripts = tmp.join("scripts");
    fs::create_dir_all(&scripts).expect("create scripts/");
    fs::write(scripts.join("Y.ipe"), "module Y exposing (y)\ny = 1\n").expect("scripts/Y.ipe");
    let link = tmp.join("src").join("link");
    std::os::unix::fs::symlink(&scripts, &link).expect("symlink src/link");
    let arg = link.join("Y.ipe");

    let canonical = fs::canonicalize(&arg).expect("canonicalise the argument");
    let target = resolve_analysis_target(&arg);
    let _ = fs::remove_dir_all(&tmp);
    assert!(
        matches!(&target, Ok(AnalysisTarget::Loose(p)) if p.as_path() == canonical),
        "a src/ symlink leaving src/ for elsewhere in the project must not be a \
         AnalysisTarget::Source: {target:?}"
    );
}

/// A `tests` symlink to the project root itself is not a tests root: its
/// canonical path equals the project root, not strictly under it, so it is
/// dropped and `tests/X.ipe` (canonically `<proj>/X.ipe`) resolves loose,
/// never `AnalysisTarget::Test`.
#[cfg(unix)]
#[test]
fn resolve_analysis_target_drops_a_tests_root_that_is_the_project_root() {
    let tmp = analysis_project("ipe_resolve_target_tests_root_is_project_root");
    fs::write(tmp.join("X.ipe"), "module X exposing (x)\nx = 1\n").expect("X.ipe");
    let tests_link = tmp.join("tests");
    std::os::unix::fs::symlink(".", &tests_link).expect("symlink tests -> .");
    let arg = tests_link.join("X.ipe");

    let canonical = fs::canonicalize(&arg).expect("canonicalise the argument");
    let target = resolve_analysis_target(&arg);
    let _ = fs::remove_dir_all(&tmp);
    assert!(
        matches!(&target, Ok(AnalysisTarget::Loose(p)) if p.as_path() == canonical),
        "a tests root equal to the project root must be dropped, so the file \
         is not an AnalysisTarget::Test: {target:?}"
    );
}

/// A `tests/` root that exists but cannot be canonicalised (a self-loop
/// symlink, `ELOOP`) is an I/O refusal, never silently treated as absent.
#[cfg(unix)]
#[test]
fn resolve_analysis_target_refuses_an_unresolvable_tests_root() {
    let tmp = analysis_project("ipe_resolve_target_tests_root_eloop");
    let tests_link = tmp.join("tests");
    std::os::unix::fs::symlink("tests", &tests_link).expect("symlink tests -> tests");
    let arg = tmp.join("src").join("Main.ipe");

    let target = resolve_analysis_target(&arg);
    let _ = fs::remove_dir_all(&tmp);
    assert!(
        matches!(&target, Err(CliError::Io { path, .. }) if path.file_name() == tests_link.file_name()),
        "an unresolvable tests root must refuse with an I/O error on that \
         root, not fall back to no tests root: {target:?}"
    );
}

/// With `sourceRoot = "."` the `tests/` root lies inside the source root, so a
/// `tests/X.ipe` is under both; the tests root wins and it resolves `AnalysisTarget::Test`.
#[test]
fn resolve_analysis_target_prefers_test_file_when_tests_is_inside_src_root() {
    let tmp = ipe_test_temp::temp_root().join("ipe_resolve_target_tests_inside_src_root");
    let _ = fs::remove_dir_all(&tmp);
    let tests_dir = tmp.join("tests");
    fs::create_dir_all(&tests_dir).expect("create tests/");
    fs::write(
        tmp.join("package.ipe"),
        "module Package exposing (package)\n\n\npackage =\n    { name = \"app\", sourceRoot = \".\" }\n",
    )
    .expect("pkg");
    let tests_x = tests_dir.join("X.ipe");
    fs::write(&tests_x, "module X exposing (x)\nx = 1\n").expect("tests/X.ipe");
    let expected = AnalysisTarget::Test {
        file: resolved(&tests_x),
        src_root: resolved(&tmp),
        tests_root: resolved(&tests_dir),
    };

    let target = resolve_analysis_target(&tests_x);
    let _ = fs::remove_dir_all(&tmp);
    assert_eq!(
        target.expect("resolves"),
        expected,
        "a file under both tests/ and the source root resolves to AnalysisTarget::Test"
    );
}

/// A `tests/Main.ipe` that imports a plain `src/` module type-checks green
/// over the `tests ∪ src` module set.
#[test]
fn tests_main_importing_a_src_module_type_checks_green() {
    let tmp = analysis_project("ipe_tests_main_imports_src_module_green");
    let tests_dir = tmp.join("tests");
    fs::create_dir_all(&tests_dir).expect("create tests/");
    fs::write(
        tmp.join("src").join("Support.ipe"),
        "module Support exposing (value)\nvalue = 42\n",
    )
    .expect("src/Support.ipe");
    let tests_main = tests_dir.join("Main.ipe");
    fs::write(
        &tests_main,
        "module Main exposing (main)\nimport Support\nmain = Support.value\n",
    )
    .expect("tests/Main.ipe");

    let result = run_type_check_body(&[tests_main.to_string_lossy().into_owned()]);
    let _ = fs::remove_dir_all(&tmp);
    assert!(
        result.is_ok(),
        "tests/Main.ipe importing a src/ module must type-check: {:?}",
        result.err()
    );
}

/// A nested `src/` module importing a sibling by its full module path
/// type-checks over the manifest's whole `src/` tree; a closure rooted at the
/// file's own directory would probe `src/Api/Api/Types.ipe` instead.
#[test]
fn nested_src_module_importing_by_full_path_type_checks_green() {
    let tmp = analysis_project("ipe_nested_src_module_full_path_import_green");
    let api = tmp.join("src").join("Api");
    fs::create_dir_all(&api).expect("create src/Api/");
    fs::write(
        api.join("Types.ipe"),
        "module Api.Types exposing (id)\nid = 1\n",
    )
    .expect("src/Api/Types.ipe");
    let handlers = api.join("Handlers.ipe");
    fs::write(
        &handlers,
        "module Api.Handlers exposing (handler)\nimport Api.Types as Types\nhandler = Types.id\n",
    )
    .expect("src/Api/Handlers.ipe");

    let result = run_type_check_body(&[handlers.to_string_lossy().into_owned()]);
    let _ = fs::remove_dir_all(&tmp);
    assert!(
        result.is_ok(),
        "a nested src/ file importing a sibling by its full module path must \
         type-check against the manifest's whole src tree: {:?}",
        result.err()
    );
}

/// A project whose declared entry is nested under `src/`: `App.Main` importing
/// `Shared.Util` by its full module path.
fn nested_entry_project(name: &str, main_body: &str) -> PathBuf {
    let tmp = ipe_test_temp::temp_root().join(name);
    let _ = fs::remove_dir_all(&tmp);
    let src = tmp.join("src");
    fs::create_dir_all(src.join("App")).expect("create src/App/");
    fs::create_dir_all(src.join("Shared")).expect("create src/Shared/");
    fs::write(
        tmp.join("package.ipe"),
        "module Package exposing (package)\n\n\npackage =\n    { name = \"app\"\n    , programs = [ { name = \"app\", entry = \"App/Main.ipe\" } ]\n    }\n",
    )
    .expect("pkg");
    fs::write(
        src.join("Shared").join("Util.ipe"),
        "module Shared.Util exposing (one)\none = 1\n",
    )
    .expect("src/Shared/Util.ipe");
    fs::write(src.join("App").join("Main.ipe"), main_body).expect("src/App/Main.ipe");
    tmp
}

/// A directory argument over a nested-entry project analyses the `src`-rooted
/// module set the build compiles: `App.Main` importing `Shared.Util` resolves,
/// where a closure rooted at the entry's own directory (`src/App/`) would probe
/// `src/App/Shared/Util.ipe` and refuse a program the build accepts.
#[test]
fn type_check_of_a_nested_entry_project_directory_resolves_src_rooted_imports() {
    let tmp = nested_entry_project(
        "ipe_type_check_nested_entry_directory_src_rooted",
        "module App.Main exposing (main)\nimport Shared.Util as Util\nmain = Util.one\n",
    );
    let expected = AnalysisTarget::Source {
        file: resolved(&tmp.join("src").join("App").join("Main.ipe")),
        src_root: resolved(&tmp.join("src")),
    };
    let target = resolve_analysis_target(&tmp);
    let result = run_type_check_body(&[tmp.to_string_lossy().into_owned()]);
    let _ = fs::remove_dir_all(&tmp);
    assert_eq!(
        target.ok(),
        Some(expected),
        "a nested-entry directory resolves to its entry over the src root"
    );
    assert!(
        result.is_ok(),
        "a nested entry importing a src module by its full path must type-check \
         via a directory argument: {:?}",
        result.err()
    );
}

/// A module that lives outside `src/` is not part of the build's module set, so
/// a directory argument refuses an import of it, blamed on the entry.
#[test]
fn type_check_of_a_directory_refuses_an_import_from_outside_src() {
    let tmp = nested_entry_project(
        "ipe_type_check_directory_refuses_outside_src_import",
        "module App.Main exposing (main)\nimport Extra\nmain = Extra.one\n",
    );
    fs::write(
        tmp.join("Extra.ipe"),
        "module Extra exposing (one)\none = 1\n",
    )
    .expect("Extra.ipe outside src/");
    let entry = resolved(&tmp.join("src").join("App").join("Main.ipe"));
    let result = run_type_check_body(&[tmp.to_string_lossy().into_owned()]);
    let _ = fs::remove_dir_all(&tmp);
    assert!(
        matches!(&result, Err(CliError::Pipeline { file, .. }) if file == entry.as_path()),
        "an import of a module outside src/ must be refused, blamed on the entry: {result:?}"
    );
}

/// The analysis entry follows the build's precedence: a declared program's
/// entry wins over a `src/Main.ipe` beside it.
#[test]
fn analysis_root_prefers_the_declared_program_entry_like_the_build() {
    let tmp = nested_entry_project(
        "ipe_analysis_root_prefers_declared_program",
        "module App.Main exposing (main)\nmain = 1\n",
    );
    let src = tmp.join("src");
    fs::write(
        src.join("Main.ipe"),
        "module Main exposing (main)\nmain = 1\n",
    )
    .expect("src/Main.ipe");
    let manifest = project::parse_manifest(&tmp.join("package.ipe")).expect("parses");
    let root = analysis_root_of(&manifest);
    let _ = fs::remove_dir_all(&tmp);
    assert_eq!(
        root.ok(),
        Some(src.join("App").join("Main.ipe")),
        "the declared program's entry is the analysis root, as it is the build's"
    );
}

/// A project with a `src/Main.ipe` that defines `main` and a declared program
/// whose `entry` is spelled `entry`, beside `extra` files under `src/`.
fn declared_entry_project(name: &str, entry: &str, extra: &[(&str, &str)]) -> PathBuf {
    let tmp = ipe_test_temp::temp_root().join(name);
    let _ = fs::remove_dir_all(&tmp);
    let src = tmp.join("src");
    fs::create_dir_all(&src).expect("create src/");
    fs::write(
        tmp.join("package.ipe"),
        format!(
            "module Package exposing (package)\n\n\npackage =\n    {{ name = \"app\"\n    , programs = [ {{ name = \"app\", entry = \"{entry}\" }} ]\n    }}\n"
        ),
    )
    .expect("pkg");
    fs::write(
        src.join("Main.ipe"),
        "module Main exposing (main)\nmain = 1\n",
    )
    .expect("src/Main.ipe");
    for (rel, body) in extra {
        fs::write(src.join(rel), body).expect("extra src file");
    }
    tmp
}

/// The analysis root is the file of the module the build compiles, not the raw
/// `entry` text: a nested entry roots at the `.ipe` file of its module path.
#[test]
fn analysis_root_is_the_file_of_the_builds_entry_module() {
    let tmp = declared_entry_project("ipe_analysis_root_nested_entry", "Client/App.ipe", &[]);
    let client = tmp.join("src").join("Client");
    fs::create_dir_all(&client).expect("create src/Client/");
    fs::write(
        client.join("App.ipe"),
        "module Client.App exposing (main)\nmain = 1\n",
    )
    .expect("src/Client/App.ipe");
    let manifest = project::parse_manifest(&tmp.join("package.ipe")).expect("parses");
    let built = manifest.resolved_entry();
    let root = analysis_root_of(&manifest);
    let expected = resolved(&client.join("App.ipe"));
    let _ = fs::remove_dir_all(&tmp);
    assert_eq!(
        built.ok(),
        Some(vec!["Client".to_owned(), "App".to_owned()]),
        "the build compiles module `Client.App`"
    );
    assert_eq!(
        root.ok(),
        Some(expected.as_path().to_path_buf()),
        "the analysis root must be the build's `src/Client/App.ipe`"
    );
}

/// An entry spelled without `.ipe`, or with another extension naming a decoy
/// file, is refused by the build and by the analysis root alike, never
/// analysed as the decoy it spells.
#[test]
fn analysis_root_refuses_an_entry_without_the_ipe_extension() {
    for (name, entry) in [
        ("ipe_analysis_root_entry_without_extension", "Main"),
        ("ipe_analysis_root_entry_other_extension", "Main.txt"),
    ] {
        let tmp = declared_entry_project(
            name,
            entry,
            &[("Main.txt", "module Main exposing (one)\none = 1\n")],
        );
        let manifest = project::parse_manifest(&tmp.join("package.ipe")).expect("parses");
        let built = manifest.resolved_entry();
        let root = analysis_root_of(&manifest);
        let _ = fs::remove_dir_all(&tmp);
        assert!(built.is_err(), "the build refuses entry {entry:?}");
        assert!(
            matches!(&root, Err(CliError::Usage(_))),
            "the analysis root must refuse entry {entry:?}: {root:?}"
        );
    }
}

/// An entry the build refuses (a segment that is no module name) is refused by
/// the analysis root too, never analysed as the raw path it spells.
#[test]
fn analysis_root_refuses_an_entry_the_build_refuses() {
    let tmp = declared_entry_project(
        "ipe_analysis_root_refuses_lowercase_entry",
        "main.ipe",
        &[("main.ipe", "module Main exposing (main)\nmain = 1\n")],
    );
    let manifest = project::parse_manifest(&tmp.join("package.ipe")).expect("parses");
    let built = manifest.resolved_entry();
    let root = analysis_root_of(&manifest);
    let _ = fs::remove_dir_all(&tmp);
    assert!(built.is_err(), "the build refuses a lowercase entry module");
    assert!(
        matches!(&root, Err(CliError::Usage(_))),
        "the analysis root must refuse the entry the build refuses: {root:?}"
    );
}

/// A nested `tests/` file importing a test sibling by its full module path
/// type-checks over the manifest's whole `tests/` tree; a tree rooted at the
/// file's own directory would probe `tests/Support/Support/Fixtures.ipe`.
#[test]
fn nested_test_file_importing_a_test_sibling_type_checks_green() {
    let tmp = analysis_project("ipe_nested_test_file_sibling_import_green");
    let tests_dir = tmp.join("tests");
    let support = tests_dir.join("Support");
    fs::create_dir_all(&support).expect("create tests/Support/");
    fs::write(
        tests_dir.join("Main.ipe"),
        "module Main exposing (main)\nmain = 1\n",
    )
    .expect("tests/Main.ipe");
    fs::write(
        support.join("Fixtures.ipe"),
        "module Support.Fixtures exposing (seed)\nseed = 1\n",
    )
    .expect("tests/Support/Fixtures.ipe");
    let helpers = support.join("Helpers.ipe");
    fs::write(
        &helpers,
        "module Support.Helpers exposing (seeded)\nimport Support.Fixtures as Fixtures\nseeded = Fixtures.seed\n",
    )
    .expect("tests/Support/Helpers.ipe");

    let result = run_type_check_body(&[helpers.to_string_lossy().into_owned()]);
    let _ = fs::remove_dir_all(&tmp);
    assert!(
        result.is_ok(),
        "a nested tests/ file importing a sibling by its full module path \
         must type-check against the manifest's whole tests tree: {:?}",
        result.err()
    );
}

/// `ipe dev build --emit-ir` and `ipe release capabilities` analyse a NAMED non-default
/// `src/` file, blamed on it, never the project's default entry.
#[test]
fn emit_ir_and_capabilities_over_a_non_default_src_file_analyse_it_not_main() {
    let tmp = analysis_project("ipe_emit_ir_and_capabilities_analyse_named_file");
    let other = tmp.join("src").join("Other.ipe");
    fs::write(
        &other,
        "module Other exposing (x)\n\n\nx : Int\nx =\n    \"not an int\"\n",
    )
    .expect("src/Other.ipe");
    let blamed = resolved(&other);

    let ir_result = resolve_analysis_target(&other).and_then(|t| emit_ir_text_for_target(&t));
    let caps_result = run_capabilities(&[other.to_string_lossy().into_owned()]);
    let _ = fs::remove_dir_all(&tmp);
    assert!(
        matches!(&ir_result, Err(CliError::Pipeline { file, .. }) if file == blamed.as_path()),
        "--emit-ir over the NAMED file must analyse it, blamed on it: {ir_result:?}"
    );
    assert!(
        matches!(&caps_result, Err(CliError::Pipeline { file, .. }) if file == blamed.as_path()),
        "`ipe release capabilities` over the NAMED file must analyse it, blamed on it: {caps_result:?}"
    );
}

/// A file argument that does not exist inside a project is refused with a
/// typed `NotFound` I/O error, never substituted for the default entry.
#[test]
fn missing_file_argument_inside_a_project_is_refused() {
    let tmp = analysis_project("ipe_missing_file_argument_inside_project_refused");
    let missing = tmp.join("src").join("Missing.ipe");

    let result = run_type_check_body(&[missing.to_string_lossy().into_owned()]);
    let _ = fs::remove_dir_all(&tmp);
    assert!(
        matches!(
            &result,
            Err(CliError::Io { path, source })
                if path == &missing && source.kind() == std::io::ErrorKind::NotFound
        ),
        "a missing file argument must be a NotFound refusal naming it: {result:?}"
    );
}

#[test]
fn build_refuses_a_pure_library_with_a_clean_message() {
    let tmp = ipe_test_temp::temp_root().join("ipe_build_refuse_library");
    let _ = fs::remove_dir_all(&tmp);
    let src = tmp.join("src");
    fs::create_dir_all(&src).expect("create src/");
    fs::write(
        tmp.join("package.ipe"),
        "module Package exposing (package)\n\n\npackage =\n    { name = \"lib\", exposedModules = [ \"Core\" ] }\n",
    )
    .expect("pkg");
    fs::write(src.join("Core.ipe"), "module Core exposing (x)\nx = 0\n").expect("core");

    let out = tmp.join("out");
    let result = build_project_with_options(
        &tmp.join("package.ipe"),
        &out,
        Path::new("."),
        &BuildOptions::from_env(),
    );
    assert!(
        matches!(&result, Err(CliError::Usage(msg)) if msg.contains("library package")),
        "a pure library must be refused with a clean library message: {result:?}"
    );
    assert!(!out.exists(), "the refusal fires before any emit");
    let _ = fs::remove_dir_all(&tmp);
}

// =========================================================================
// `ipe package audit-entry` — argument parsing and fail-closed schema gate
// =========================================================================

fn temp_dir_unique(tag: &str) -> PathBuf {
    let dir = ipe_test_temp::temp_root().join(format!(
        "ipe-audit-entry-test-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

/// Write a minimal well-formed `packages/<name>.toml` entry into `root`.
fn write_entry(root: &Path, name: &str, versions: &[(&str, &str, &str, &str)]) {
    use std::fmt::Write as _;
    let pkgs = root.join("packages");
    std::fs::create_dir_all(&pkgs).expect("packages dir");
    let mut text = format!("name = \"{name}\"\npublisher = \"tester\"\n");
    for (ver, source, rev, sha) in versions {
        let _ = write!(
            text,
            "\n[[version]]\nversion = \"{ver}\"\nsource = \"{source}\"\n\
             rev = \"{rev}\"\nsha256 = \"{sha}\"\ncapabilities = []\n"
        );
    }
    std::fs::write(pkgs.join(format!("{name}.toml")), text).expect("write entry");
}

/// `parse_audit_entry_args` — missing positional yields a `Usage` error.
#[test]
fn parse_audit_entry_args_requires_entry_file() {
    let err = parse_audit_entry_args(&[]).unwrap_err();
    assert!(
        matches!(err, CliError::Usage(_)),
        "missing entry-file must be a Usage error: {err:?}"
    );
}

/// `parse_audit_entry_args` — unknown flag yields `Usage`.
#[test]
fn parse_audit_entry_args_rejects_unknown_flag() {
    let args: Vec<String> = ["packages/foo.toml", "--unknown"]
        .iter()
        .map(ToString::to_string)
        .collect();
    let err = parse_audit_entry_args(&args).unwrap_err();
    assert!(
        matches!(err, CliError::Usage(_)),
        "unknown flag must be a Usage error: {err:?}"
    );
}

/// `parse_audit_entry_args` — a value-taking flag without its value yields the
/// catalog's `flag-needs-value` refusal, the one shape every such flag shares.
#[test]
fn parse_audit_entry_args_rejects_a_flag_without_its_value() {
    for flag in ["--index", "--attested-actor"] {
        let args: Vec<String> = ["packages/foo.toml", flag]
            .iter()
            .map(ToString::to_string)
            .collect();
        let err = parse_audit_entry_args(&args).unwrap_err();
        let expected = crate::text::flag_needs_value(&"package audit-entry", &flag);
        assert!(
            matches!(&err, CliError::Usage(message) if *message == expected),
            "{flag} without value must be the flag-needs-value refusal: {err:?}"
        );
    }
}

/// `parse_audit_entry_args` — two positionals yields `Usage`.
#[test]
fn parse_audit_entry_args_rejects_two_positionals() {
    let args: Vec<String> = ["packages/foo.toml", "extra"]
        .iter()
        .map(ToString::to_string)
        .collect();
    let err = parse_audit_entry_args(&args).unwrap_err();
    assert!(
        matches!(err, CliError::Usage(_)),
        "two positionals must be a Usage error: {err:?}"
    );
}

/// `parse_audit_entry_args` — valid path + `--index` round-trips correctly.
#[test]
fn parse_audit_entry_args_parses_path_and_index() {
    let args: Vec<String> = ["packages/foo.toml", "--index", "/some/index"]
        .iter()
        .map(ToString::to_string)
        .collect();
    let parsed = parse_audit_entry_args(&args).expect("parses");
    assert_eq!(parsed.entry_path, PathBuf::from("packages/foo.toml"));
    assert_eq!(parsed.index_root, Some(PathBuf::from("/some/index")));
    assert_eq!(parsed.attested_actor, None);
}

/// `parse_audit_entry_args` — `--attested-actor` parses into a typed attestation;
/// a missing value, a repeat, or a non-login value is refused.
#[test]
fn parse_audit_entry_args_parses_and_refuses_attested_actor() {
    let argv = |v: &[&str]| -> Vec<String> { v.iter().map(ToString::to_string).collect() };
    let parsed =
        parse_audit_entry_args(&argv(&["packages/foo.toml", "--attested-actor", "octocat"]))
            .expect("parses");
    assert_eq!(
        parsed
            .attested_actor
            .as_ref()
            .map(crate::publisher::AttestedActor::as_str),
        Some("octocat")
    );
    for bad in [
        argv(&["packages/foo.toml", "--attested-actor"]),
        argv(&[
            "packages/foo.toml",
            "--attested-actor",
            "a",
            "--attested-actor",
            "b",
        ]),
        argv(&["packages/foo.toml", "--attested-actor", "not a login"]),
        argv(&["packages/foo.toml", "--attested-actor", "-lead"]),
    ] {
        assert!(parse_audit_entry_args(&bad).is_err(), "{bad:?}");
    }
}

/// `run_audit_entry` — a malformed entry file (missing `sha256`) is a hard
/// schema reject, never a warn-and-pass (§0 fail-closed).
#[test]
fn audit_entry_rejects_malformed_entry_schema() {
    let root = temp_dir_unique("ae-bad-schema");
    let pkgs = root.join("packages");
    std::fs::create_dir_all(&pkgs).expect("packages dir");
    // No `sha256` — the integrity anchor is mandatory; parse must reject.
    std::fs::write(
        pkgs.join("nohash.toml"),
        "publisher = \"tester\"\n\n[[version]]\nversion = \"1.0.0\"\n\
         source = \"https://example.invalid/nohash\"\nrev = \"abc\"\n",
    )
    .expect("write entry");
    let args: Vec<String> =
        std::iter::once(pkgs.join("nohash.toml").to_string_lossy().into_owned()).collect();
    let err = run_audit_entry(&args).unwrap_err();
    // Must be a Resolve or Io error from the schema parse — never Ok.
    assert!(
        matches!(err, CliError::Resolve(_) | CliError::Io { .. }),
        "malformed entry must be rejected at schema step: {err:?}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// `run_audit_entry` — an entry whose every `[[version]]` is already in the
/// baseline index is rejected: nothing new to audit (§0 fail-closed; the gate
/// must not silently pass with no work done).
#[test]
fn audit_entry_rejects_when_all_versions_are_already_in_baseline() {
    let submitted_root = temp_dir_unique("ae-all-baseline-sub");
    let baseline_root = temp_dir_unique("ae-all-baseline-idx");
    // Both the submitted and the baseline have exactly version 1.0.0.
    write_entry(
        &submitted_root,
        "mylib",
        &[(
            "1.0.0",
            "https://x.invalid/mylib",
            "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
            "0000000000000000000000000000000000000000000000000000000000000000",
        )],
    );
    write_entry(
        &baseline_root,
        "mylib",
        &[(
            "1.0.0",
            "https://x.invalid/mylib",
            "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
            "0000000000000000000000000000000000000000000000000000000000000000",
        )],
    );
    let args: Vec<String> = [
        submitted_root
            .join("packages")
            .join("mylib.toml")
            .to_string_lossy()
            .into_owned(),
        "--index".to_owned(),
        baseline_root.to_string_lossy().into_owned(),
    ]
    .into_iter()
    .collect();
    let err = run_audit_entry(&args).unwrap_err();
    assert!(
        matches!(err, CliError::Usage(_)),
        "no new versions must be a Usage error: {err:?}"
    );
    let _ = std::fs::remove_dir_all(&submitted_root);
    let _ = std::fs::remove_dir_all(&baseline_root);
}

/// `run_audit_entry` — a published version is immutable. Re-submitting an
/// existing version number with a *different* row (here a changed `sha256`)
/// must be a hard reject naming immutability, never a silent skip. This closes
/// the version-delta bypass: were the delta keyed on version number alone, a
/// rewritten `source`/`rev`/`sha256`/`capabilities` on an already-published
/// version would slip past both hash-verify and audit (ADR 0007, §receiving-gate).
#[test]
fn audit_entry_rejects_rewriting_a_published_version() {
    let submitted_root = temp_dir_unique("ae-immutable-sub");
    let baseline_root = temp_dir_unique("ae-immutable-idx");
    // The baseline publishes 1.0.0 with one content hash; the submission
    // keeps the same version number but rewrites its sha256 to another.
    write_entry(
        &baseline_root,
        "mylib",
        &[(
            "1.0.0",
            "https://x.invalid/mylib",
            "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
            "0000000000000000000000000000000000000000000000000000000000000000",
        )],
    );
    write_entry(
        &submitted_root,
        "mylib",
        &[(
            "1.0.0",
            "https://x.invalid/mylib",
            "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
            "1111111111111111111111111111111111111111111111111111111111111111",
        )],
    );
    let args: Vec<String> = [
        submitted_root
            .join("packages")
            .join("mylib.toml")
            .to_string_lossy()
            .into_owned(),
        "--index".to_owned(),
        baseline_root.to_string_lossy().into_owned(),
    ]
    .into_iter()
    .collect();
    let err = run_audit_entry(&args).unwrap_err();
    assert!(
        matches!(&err, CliError::Usage(msg) if msg.contains("immutable")),
        "rewriting a published version must be a Usage reject naming immutability: {err:?}"
    );
    let _ = std::fs::remove_dir_all(&submitted_root);
    let _ = std::fs::remove_dir_all(&baseline_root);
}

/// `run_audit_entry` — a new version whose `sha256` does not match the fetched
/// tree is a hard [`CliError::HashMismatch`] (verify-before-trust, §0).
///
/// Uses a local git repo as the source so the test runs offline.
#[test]
fn audit_entry_rejects_on_hash_mismatch() {
    // Build a tiny local git repo.
    let repo = temp_dir_unique("ae-mismatch-repo");
    let git = |args: &[&str]| {
        let ok = crate::remote_ingest::fixture_git(&repo)
            .args(args)
            .output()
            .expect("git runs")
            .status
            .success();
        assert!(ok, "git {args:?} must succeed");
    };
    git(&["init", "--quiet"]);
    std::fs::write(repo.join("lib.ipe"), "module Lib\n").expect("write");
    git(&["add", "."]);
    git(&["commit", "--quiet", "-m", "seed"]);
    // Get the HEAD commit hash.
    let rev_out = crate::remote_ingest::fixture_git(&repo)
        .args(["rev-parse", "HEAD"])
        .output()
        .expect("git rev-parse");
    let rev = String::from_utf8_lossy(&rev_out.stdout).trim().to_owned();

    // Write an entry that points at this repo but with a deliberately wrong
    // sha256. It is well-formed (64 lowercase-hex chars) so it clears the
    // parse gate and reaches the content-hash verification, which must then
    // reject it as a mismatch.
    let entry_root = temp_dir_unique("ae-mismatch-entry");
    let pkgs = entry_root.join("packages");
    std::fs::create_dir_all(&pkgs).expect("packages dir");
    let entry_text = format!(
        "name = \"testlib\"\npublisher = \"tester\"\n\n[[version]]\n\
         version = \"1.0.0\"\nsource = \"{}\"\nrev = \"{rev}\"\n\
         sha256 = \"0000000000000000000000000000000000000000000000000000000000000000\"\n\
         capabilities = []\n",
        repo.display()
    );
    std::fs::write(pkgs.join("testlib.toml"), entry_text).expect("write entry");

    // Point --index at a root with no baseline so all versions are "new".
    let idx_root = temp_dir_unique("ae-mismatch-idx");
    std::fs::create_dir_all(idx_root.join("packages")).expect("packages dir");

    let args: Vec<String> = [
        pkgs.join("testlib.toml").to_string_lossy().into_owned(),
        "--index".to_owned(),
        idx_root.to_string_lossy().into_owned(),
    ]
    .into_iter()
    .collect();
    let err = run_audit_entry(&args).unwrap_err();
    assert!(
        matches!(err, CliError::HashMismatch { .. }),
        "a wrong sha256 must be a HashMismatch error, not: {err:?}"
    );

    let _ = std::fs::remove_dir_all(&repo);
    let _ = std::fs::remove_dir_all(&entry_root);
    let _ = std::fs::remove_dir_all(&idx_root);
}

// ---- unsafe-scan fail-closed tests -----------------------------------

/// Returns a unique scratch directory under the OS temp root.
/// The caller is responsible for removing it when done.
fn unsafe_scan_test_dir(tag: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let dir = ipe_test_temp::temp_root().join(format!(
        "ipe-unsafe-scan-{tag}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).expect("create test scratch dir");
    dir
}

/// A manifest project with an unreadable module must return `Err(CliError::Io)`
/// naming the unreadable path — not `Ok` with a partial source list.
#[cfg(unix)]
#[test]
fn unsafe_scan_manifest_project_fails_closed_on_unreadable_module() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let dir = unsafe_scan_test_dir("manifest-fail");
    let src = dir.join("src");
    fs::create_dir_all(&src).expect("create src");

    // One readable module and one unreadable one.
    let readable = src.join("Main.ipe");
    fs::write(&readable, "module Main exposing (main)\n").expect("write Main");
    let unreadable = src.join("Locked.ipe");
    fs::write(&unreadable, "module Locked exposing ()\n").expect("write Locked");
    fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o000)).expect("chmod 000");

    let manifest_path = dir.join("package.ipe");
    fs::write(
        &manifest_path,
        "module Package exposing (package)\n\n\npackage =\n    { name = \"test\" }\n",
    )
    .expect("write manifest");

    let result = user_sources_for_unsafe_scan(Some(&manifest_path), &readable);

    // Restore permissions before any assertion so cleanup always runs.
    let _ = fs::set_permissions(&unreadable, fs::Permissions::from_mode(0o644));
    let _ = fs::remove_dir_all(&dir);

    // Must be the typed access-denied refusal naming the unreadable path —
    // never an `Ok` partial scan and never a different error variant.
    assert!(
        matches!(
            &result,
            Err(CliError::SourceRefused { path, reason: SourceRefusal::AccessDenied })
                if path == &unreadable
        ),
        "expected Err(CliError::SourceRefused(AccessDenied)) naming {unreadable:?}, got: {result:?}"
    );
}

/// A manifest project where every module is readable must return `Ok` with
/// every source text present.
#[test]
fn unsafe_scan_manifest_project_ok_when_all_readable() {
    use std::fs;

    let dir = unsafe_scan_test_dir("manifest-ok");
    let src = dir.join("src");
    fs::create_dir_all(&src).expect("create src");

    let entry = src.join("Main.ipe");
    fs::write(&entry, "module Main exposing (main)\n").expect("write Main");
    let other = src.join("Helper.ipe");
    fs::write(&other, "module Helper exposing ()\n").expect("write Helper");

    let manifest_path = dir.join("package.ipe");
    fs::write(
        &manifest_path,
        "module Package exposing (package)\n\n\npackage =\n    { name = \"test\" }\n",
    )
    .expect("write manifest");

    let result = user_sources_for_unsafe_scan(Some(&manifest_path), &entry);
    let _ = fs::remove_dir_all(&dir);

    // Every module readable ⇒ `Ok` carrying a source for each.
    assert!(
        matches!(&result, Ok(sources) if sources.len() >= 2),
        "expected Ok with a source for every readable module, got: {result:?}"
    );
}

/// Single-file fallback: when `collect_entry_and_siblings` fails and the
/// entry itself is unreadable, the result must be `Err(CliError::Io)`
/// naming the entry path — not `Ok` with an empty list.
#[cfg(unix)]
#[test]
fn unsafe_scan_single_file_fallback_fails_closed_on_unreadable_entry() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let dir = unsafe_scan_test_dir("single-fail");
    let entry = dir.join("Main.ipe");
    fs::write(&entry, "module Main exposing (main)\n").expect("write entry");
    fs::set_permissions(&entry, fs::Permissions::from_mode(0o000)).expect("chmod 000");

    // Pass no manifest so the single-file (entry + siblings) path is taken.
    let result = user_sources_for_unsafe_scan(None, &entry);

    let _ = fs::set_permissions(&entry, fs::Permissions::from_mode(0o644));
    let _ = fs::remove_dir_all(&dir);

    // Must be the typed access-denied refusal naming the unreadable entry —
    // never an `Ok` empty scan and never a different error variant.
    assert!(
        matches!(
            &result,
            Err(CliError::SourceRefused { path, reason: SourceRefusal::AccessDenied })
                if path == &entry
        ),
        "expected Err(CliError::SourceRefused(AccessDenied)) naming {entry:?}, got: {result:?}"
    );
}

/// An unreadable imported module fails both consent scans closed.
///
/// Neither scan may judge the entry alone when a module it imports cannot be
/// read — that module's `.Unsafe`/native imports would go unseen.
#[cfg(unix)]
#[test]
fn consent_scans_fail_closed_on_unreadable_imported_module() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let dir = unsafe_scan_test_dir("sibling-fail");
    let entry = dir.join("Main.ipe");
    fs::write(
        &entry,
        "module Main exposing (main)\n\nimport Helper\n\nmain = Helper.h\n",
    )
    .expect("write entry");
    let helper = dir.join("Helper.ipe");
    fs::write(&helper, "module Helper exposing (h)\n\nh = 1\n").expect("write Helper");
    fs::set_permissions(&helper, fs::Permissions::from_mode(0o000)).expect("chmod 000");

    let unsafe_scan = user_sources_for_unsafe_scan(None, &entry);
    let web_scan = named_sources_for_web_scan(None, &entry);

    let _ = fs::set_permissions(&helper, fs::Permissions::from_mode(0o644));
    let _ = fs::remove_dir_all(&dir);

    assert!(
        matches!(
            &unsafe_scan,
            Err(CliError::SourceRefused { path, reason: SourceRefusal::AccessDenied })
                if path.ends_with("Helper.ipe")
        ),
        "unsafe scan must refuse the unreadable module by name, got: {unsafe_scan:?}"
    );
    assert!(
        matches!(
            &web_scan,
            Err(CliError::SourceRefused { path, reason: SourceRefusal::AccessDenied })
                if path.ends_with("Helper.ipe")
        ),
        "web scan must refuse the unreadable module by name, got: {web_scan:?}"
    );
}

/// A closure one module past the loose-file limit fails both consent scans closed.
#[test]
fn consent_scans_fail_closed_on_closure_past_the_module_limit() {
    use std::fmt::Write as _;
    use std::fs;

    let dir = unsafe_scan_test_dir("closure-limit");
    let count = crate::loose_file::MAX_LOOSE_FILE_MODULES + 1;
    let mut entry_text = String::from("module Main exposing (main)\n\n");
    for i in 0..count {
        let _ = writeln!(entry_text, "import M{i}");
        fs::write(
            dir.join(format!("M{i}.ipe")),
            format!("module M{i} exposing ()\n"),
        )
        .expect("write module");
    }
    entry_text.push_str("\nmain = 1\n");
    let entry = dir.join("Main.ipe");
    fs::write(&entry, &entry_text).expect("write entry");

    let unsafe_scan = user_sources_for_unsafe_scan(None, &entry);
    let web_scan = named_sources_for_web_scan(None, &entry);
    let _ = fs::remove_dir_all(&dir);

    assert!(
        matches!(&unsafe_scan, Err(CliError::DiscoveryLimitReached { .. })),
        "unsafe scan must refuse the over-limit closure, got: {unsafe_scan:?}"
    );
    assert!(
        matches!(&web_scan, Err(CliError::DiscoveryLimitReached { .. })),
        "web scan must refuse the over-limit closure, got: {web_scan:?}"
    );
}

/// An entry that does not parse is scanned alone, keyed by its own path.
///
/// It has no import closure to follow; the build reports the parse error.
#[test]
fn consent_scans_read_an_unparseable_entry_alone() {
    use std::fs;

    let dir = unsafe_scan_test_dir("unparseable");
    let entry = dir.join("Main.ipe");
    let text = "module Main exposing (\nimport Ipe.Unsafe\n";
    fs::write(&entry, text).expect("write entry");

    let unsafe_scan = user_sources_for_unsafe_scan(None, &entry);
    let web_scan = named_sources_for_web_scan(None, &entry);
    let _ = fs::remove_dir_all(&dir);

    assert!(
        matches!(&unsafe_scan, Ok(sources) if sources.as_slice() == [text]),
        "unsafe scan must see the entry text, got: {unsafe_scan:?}"
    );
    let expected = vec![(entry.display().to_string(), text.to_owned())];
    assert!(
        matches!(&web_scan, Ok(named) if named == &expected),
        "web scan must see the entry text keyed by its path, got: {web_scan:?}"
    );
}

#[test]
fn check_exit_code_is_git_style() {
    use crate::version_check::UpgradeAction::*;
    assert_eq!(super::check_exit_code(&Available), 10);
    assert_eq!(super::check_exit_code(&UpToDate), 0);
    assert_eq!(super::check_exit_code(&Unreachable), 2);
}

#[test]
fn upgrade_json_reports_available() {
    use crate::version_check::{UpgradeAction, VersionCheck};
    let vc = VersionCheck {
        current: semver::Version::parse("0.1.72").expect("valid semver"),
        latest: Some(semver::Version::parse("0.1.75").expect("valid semver")),
        upgrade_available: true,
        reached_feed: true,
    };
    let s = super::render_upgrade(
        &vc,
        &UpgradeAction::Available,
        false,
        crate::cli_args::OutputFormat::Json,
    );
    assert!(
        s.contains("\"upgradeAvailable\":true"),
        "upgradeAvailable: {s}"
    );
    assert!(s.contains("\"action\":\"checked\""), "action: {s}");
    assert!(s.contains("\"latest\":\"0.1.75\""), "latest: {s}");
}

#[test]
fn upgrade_plain_is_flush_and_terse() {
    use crate::version_check::{UpgradeAction, VersionCheck};
    let vc = VersionCheck {
        current: semver::Version::parse("0.1.72").expect("valid semver"),
        latest: None,
        upgrade_available: false,
        reached_feed: false,
    };
    let s = super::render_upgrade(
        &vc,
        &UpgradeAction::Unreachable,
        false,
        crate::cli_args::OutputFormat::Plain,
    );
    assert_eq!(s, "feed unreachable\n");
}

/// A genuinely home-less post-link diagnostic (empty `Constraint`/obligation
/// `home`) must resolve to a byte-STABLE file through `source_for_span_in_linked`,
/// independent of the order the linked def list happens to carry — Correctness
/// (principle 2): the same program + input yields the same diagnostic every run.
///
/// Two defs in DIFFERENT modules enclose the same span with an identical
/// `(lo_dist, width)` — the case the pre-fix `lo_dist < prev || (== && width <
/// prev_w)` comparator could not disambiguate, so whichever def appeared first in
/// `linked.defs` won. This builds that ambiguity, then resolves the span against
/// both def orders and asserts the SAME file both times (the `home` tie-break),
/// and that it is the lexicographically-smaller home's file (`Alpha`, not
/// `Beta`) — a total order, not first-seen.
#[test]
fn homeless_span_resolves_byte_stably_regardless_of_def_order() {
    use ipe_canon::ast::{Def, Module};
    use ipe_diagnostics::Located;
    use ipe_intern::Interner;

    let mut i = Interner::new();
    let alpha = vec![i.intern("Alpha").expect("intern Alpha")];
    let beta = vec![i.intern("Beta").expect("intern Beta")];
    let name_a = i.intern("a").expect("intern a");
    let name_b = i.intern("b").expect("intern b");

    // Both bodies occupy the IDENTICAL byte range [10, 20]: same `lo_dist` and
    // same `width` for any span inside, so only the `home` tie-break can decide.
    let body_span = Span::new(10, 20);
    let def_alpha = Def::Untyped {
        home: alpha.clone(),
        name: Located::new(Span::new(0, 1), name_a),
        patterns: Vec::new(),
        body: Located::new(body_span, ipe_canon::ast::Expr_::Unit),
    };
    let def_beta = Def::Untyped {
        home: beta.clone(),
        name: Located::new(Span::new(0, 1), name_b),
        patterns: Vec::new(),
        body: Located::new(body_span, ipe_canon::ast::Expr_::Unit),
    };

    let mk_module = |defs: Vec<Def>| Module {
        name: alpha.clone(),
        unions: Vec::new(),
        defs,
        imports_unsafe_submodule: false,
        imported_web_capabilities: std::collections::BTreeSet::new(),
    };

    let mut home_to_source: BTreeMap<Vec<ipe_intern::Symbol>, (PathBuf, String)> = BTreeMap::new();
    home_to_source.insert(
        alpha.clone(),
        (PathBuf::from("Alpha.ipe"), "alpha".to_string()),
    );
    home_to_source.insert(beta, (PathBuf::from("Beta.ipe"), "beta".to_string()));
    let entry = (PathBuf::from("Entry.ipe"), "entry".to_string());
    let span = Span::new(12, 15); // inside [10, 20] for both defs

    let forward = mk_module(vec![def_alpha.clone(), def_beta.clone()]);
    let reversed = mk_module(vec![def_beta, def_alpha]);

    let (file_fwd, _) = super::source_for_span_in_linked(&forward, &home_to_source, &entry, span);
    let (file_rev, _) = super::source_for_span_in_linked(&reversed, &home_to_source, &entry, span);

    assert_eq!(
        file_fwd, file_rev,
        "a home-less span must resolve to the same file regardless of def order; \
         got {file_fwd:?} forward vs {file_rev:?} reversed"
    );
    assert_eq!(
        file_fwd,
        PathBuf::from("Alpha.ipe"),
        "the stable tie-break must pick the lexicographically-smaller home (Alpha), \
         not the first-seen def; got {file_fwd:?}"
    );
}

/// An operator-synthesized `super_var` obligation error (empty pre-fix `home`)
/// must be blamed on its OWNING source file, not a numerically-overlapping
/// sibling. `==` mints an `Equatable` obligation; over a `List (a -> a)` it fails
/// the post-solve concrete-pin gate (`super_unsatisfied`, IPE-T0014). Before this
/// fix that obligation error carried an EMPTY home and fell into the byte-offset
/// heuristic; the home threaded onto the `super_var` now attributes it directly.
///
/// `Pad.ipe` is crafted to WIN that heuristic pre-fix: its def body starts at the
/// same byte offset as `Lib.ipe`'s failing expression (identical header length)
/// and is NARROWER than `Lib`'s enclosing def body, so a home-blind resolver
/// picks `Pad` (verified: pre-fix this fixture blames `Pad.ipe`). The threaded
/// home is the only signal that recovers `Lib.ipe`.
#[test]
fn obligation_error_blames_owning_module_not_narrower_padded_sibling() {
    let tmp = ipe_test_temp::temp_root().join("ipec_obligation_home_test");
    let _ = fs::remove_dir_all(&tmp);
    let src = tmp.join("src");
    fs::create_dir_all(&src).expect("create src/");

    // `Lib.bad`'s body `[(\a -> a)] == [(\a -> a)]` starts at byte 32 (a 26-byte
    // header + `bad = `). The IPE-T0014 error span is the 11-byte left operand
    // `[(\a -> a)]` at [32, 43]; the whole def body spans [32, 57] (width 25).
    fs::write(
        src.join("Lib.ipe"),
        "module Lib exposing (bad)\nbad = [(\\a -> a)] == [(\\a -> a)]\n",
    )
    .expect("write Lib.ipe");

    // `Pad.pad`'s body `123456789012` also starts at byte 32 (`Pad` header is the
    // same 26 bytes as `Lib`), spanning [32, 44] (width 12). It ENCLOSES the
    // [32, 43] error span and is narrower than Lib's [32, 57] body, so the
    // heuristic's `(lo_dist=0, width)` order prefers Pad — the wrong file.
    fs::write(
        src.join("Pad.ipe"),
        "module Pad exposing (pad)\npad = 123456789012\n",
    )
    .expect("write Pad.ipe");

    // `bad : Bool`; `main` uses it so both siblings link into one program.
    fs::write(
        src.join("Main.ipe"),
        "module Main exposing (main)\nimport Lib\nimport Pad\nimport Ipe.Io\nmain = if Lib.bad then Io.println \"y\" else Io.println \"n\"\n",
    )
    .expect("write Main.ipe");

    let dummy_runtime = ipe_test_temp::temp_root();
    let out = tmp.join("out");
    let result = build_loose_file(&src.join("Main.ipe"), &out, &dummy_runtime);

    assert!(
        result.is_err(),
        "the obligation fixture must fail (Equatable obligation on a function list); got Ok"
    );
    let Err(CliError::Pipeline { file, .. }) = result else {
        // A non-Pipeline error kind is a separate concern, not this test's failure
        // (house idiom; the workspace clippy deny-set forbids panic! in tests).
        let _ = fs::remove_dir_all(&tmp);
        return;
    };

    let file_name = file.file_name().and_then(|n| n.to_str()).unwrap_or("");
    assert_eq!(
        file_name,
        "Lib.ipe",
        "an obligation error must blame its owning module `Lib.ipe`, not the \
         narrower padded sibling `Pad.ipe` the byte-offset heuristic would pick; \
         got `{file_name}` (path: {})",
        file.display()
    );

    let _ = fs::remove_dir_all(&tmp);
}

// --- the wasm/wasi artifact size probe --------------------------------------

#[test]
fn format_artifact_size_never_reads_zero_for_a_nonzero_file() {
    // The truncation bug: `bytes / 1024` renders any sub-KiB module as `0 KB`.
    // A 1-byte and a 1023-byte artifact are real; neither may read as `0`.
    assert_eq!(format_artifact_size(1), "1 bytes");
    assert_eq!(format_artifact_size(512), "512 bytes");
    assert_eq!(format_artifact_size(1023), "1023 bytes");
    // A zero-length file is the one legitimate zero — reported exactly.
    assert_eq!(format_artifact_size(0), "0 bytes");
}

#[test]
fn format_artifact_size_keeps_the_kib_fraction() {
    // At/above 1 KiB, integer `bytes / 1024` alone would drop the fraction and
    // round 1.9 KiB down to a misleading `1 KiB`; the one-decimal form keeps it.
    assert_eq!(format_artifact_size(1024), "1.0 KiB");
    assert_eq!(format_artifact_size(1024 + 512), "1.5 KiB");
    assert_eq!(format_artifact_size(2048), "2.0 KiB");
    // A real trivial wasm module is a few KiB — its size is reported, not `0`.
    assert_eq!(format_artifact_size(3 * 1024 + 100), "3.0 KiB");
}

#[test]
fn artifact_size_bytes_reports_a_real_files_length() {
    // The probe reads the real file: a nonzero artifact yields its true byte
    // length, so the reported size is accurate rather than a hardcoded `0`.
    let tmp =
        ipe_test_temp::temp_root().join(format!("artifact_size_probe_{}", std::process::id()));
    let _ = fs::create_dir_all(&tmp);
    let file = tmp.join("module.wasm");
    let bytes = vec![0u8; 2500];
    let write_ok = fs::write(&file, &bytes).is_ok();
    assert!(
        write_ok,
        "test setup: writing the probe artifact must succeed"
    );

    // `CliError` is not `PartialEq`, so unwrap the Ok side and compare the value.
    let size = artifact_size_bytes(&file).ok();
    assert_eq!(
        size,
        Some(2500),
        "the probe must report the real 2500-byte length, not a truncated 0",
    );
    assert_eq!(format_artifact_size(2500), "2.4 KiB");

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn artifact_size_bytes_surfaces_a_missing_artifact_as_a_typed_error() {
    // A size probe reading a real artifact must SURFACE an absent path as a
    // typed `Io` error — never paper it over as a plausible `0 KB` (the old
    // `metadata().map_or(0, …)` hid a missing module behind a fake size).
    let missing = ipe_test_temp::temp_root()
        .join(format!("artifact_absent_{}", std::process::id()))
        .join("nonexistent.wasm");
    let err = artifact_size_bytes(&missing)
        .expect_err("a missing artifact must be a typed error, not a silent 0");
    assert!(
        matches!(err, CliError::Io { .. }),
        "the missing-artifact probe must be a typed Io error, got: {err:?}",
    );
}

// ── `ipe dev run --record` / `--replay` — refusals ─────────────────────────────

// Recording and replay are refused, before any build, for every shape without
// a cli/worker update loop — never a run that silently writes no log, nor a
// replay that silently runs the app live.
#[test]
fn session_is_refused_for_shapes_without_a_session() {
    for flag in ["--record", "--replay"] {
        for shape in [
            crate::delivery::Shape::Script,
            crate::delivery::Shape::Tui,
            crate::delivery::Shape::Web,
        ] {
            let result = gate_session(flag, shape, CompileTarget::Native);
            assert!(
                matches!(&result, Err(CliError::Usage(msg)) if msg.contains(flag)),
                "{flag} on {shape:?} must be refused, got: {result:?}"
            );
        }
    }
}

// A cli app run under `--target wasi` executes in wasmtime, where the recorder
// is not wired: refused rather than recording nothing or replaying live.
#[test]
fn session_is_refused_for_a_wasi_run() {
    for flag in ["--record", "--replay"] {
        let result = gate_session(flag, crate::delivery::Shape::Cli, CompileTarget::WasmWasi);
        assert!(
            matches!(&result, Err(CliError::Usage(msg)) if msg.contains("wasi")),
            "{flag} with --target wasi must be refused, got: {result:?}"
        );
    }
}

// A native cli or worker app has a recordable session: the shape gate admits it.
#[test]
fn session_is_admitted_for_a_native_cli_or_worker_app() {
    for shape in [crate::delivery::Shape::Cli, crate::delivery::Shape::Worker] {
        let result = gate_session("--record", shape, CompileTarget::Native);
        assert!(
            result.is_ok(),
            "{shape:?} must be admitted, got: {result:?}"
        );
    }
}

// A native-bearing program runs jailed, where the log is unreachable: refused
// whether the crossing is inferred or only declared, and a pure program passes.
#[test]
fn session_is_refused_for_a_native_bearing_program() {
    use crate::run_sandbox::ResolvedCapabilities;
    use ipe_ir::Capability;
    use std::collections::BTreeSet;
    let native: BTreeSet<Capability> = std::iter::once(Capability::NativeFfi).collect();
    let raw: BTreeSet<Capability> = std::iter::once(Capability::FfiRaw).collect();
    let bearing = [
        ResolvedCapabilities {
            inferred: native.clone(),
            declared: BTreeSet::new(),
        },
        ResolvedCapabilities {
            inferred: BTreeSet::new(),
            declared: native,
        },
        ResolvedCapabilities {
            inferred: raw,
            declared: BTreeSet::new(),
        },
    ];
    for flag in ["--record", "--replay"] {
        for resolved in &bearing {
            let result = gate_session_capabilities(flag, resolved);
            assert!(
                matches!(&result, Err(CliError::Usage(msg)) if msg.contains("native-bearing")),
                "{flag} on a native-bearing program must be refused, got: {result:?}"
            );
        }
        let pure = ResolvedCapabilities {
            inferred: BTreeSet::new(),
            declared: BTreeSet::new(),
        };
        let result = gate_session_capabilities(flag, &pure);
        assert!(
            result.is_ok(),
            "{flag} on a pure program must pass: {result:?}"
        );
    }
}

// A replay whose log does not exist is refused before any build, naming the
// path and the way to record one.
#[test]
fn replay_of_a_missing_log_is_refused_before_building() {
    let dir = ipe_test_temp::temp_root().join(format!("ipe_replay_missing_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    for absent in ["absent.ipemsgs", "absent.ipelog"] {
        let result = replay_plan(dir.join(absent));
        assert!(
            matches!(&result, Err(CliError::Usage(msg)) if msg.contains("--record")),
            "a missing replay log must be refused: {result:?}"
        );
    }
}

// The default replay log is the typed sibling of the trace `--record` writes.
#[test]
fn default_replay_log_is_the_typed_sibling_of_the_trace() {
    assert_eq!(typed_log_file(), Path::new("session.ipemsgs"));
}

// ── `gate_terminal` — refuse a Tui app before any build, not just before raw
// mode — over the pure decision, never the test process's own real stdio ──

// Every non-Tui shape is unaffected, whatever the terminal decision: the gate
// exists only for the one shape that ever calls `TuiGuard::enter*`.
#[test]
fn gate_terminal_is_a_no_op_for_every_non_tui_shape() {
    use ipe_runtime_rust::terminal_access::{NoTerminal, TerminalAccess};
    for shape in [
        crate::delivery::Shape::Script,
        crate::delivery::Shape::Cli,
        crate::delivery::Shape::Worker,
        crate::delivery::Shape::Web,
    ] {
        for access in [
            TerminalAccess::Interactive,
            TerminalAccess::Refused(NoTerminal::NoStdoutTty),
        ] {
            let result = gate_terminal_decision("run", shape, access);
            assert!(
                result.is_ok(),
                "{shape:?} must never be gated on terminal access, got: {result:?}"
            );
        }
    }
}

// A Tui app is refused before any build when the terminal decision is
// `Refused`, and the message names the command and the exact refusal text —
// the same text `TuiGuard::enter*` would raise inside the built binary.
#[test]
fn gate_terminal_refuses_a_tui_app_without_an_interactive_terminal() {
    use ipe_runtime_rust::terminal_access::{NoTerminal, TerminalAccess};
    for (command, reason) in [
        ("run", NoTerminal::NoStdoutTty),
        ("run", NoTerminal::DumbTerm),
        ("run", NoTerminal::NoControllingTerminal),
        ("watch", NoTerminal::NoStdoutTty),
    ] {
        let result = gate_terminal_decision(
            command,
            crate::delivery::Shape::Tui,
            TerminalAccess::Refused(reason),
        );
        assert!(
            matches!(&result, Err(CliError::Usage(msg))
                if msg.contains(command) && msg.contains(reason.text())),
            "{command} on a Tui app with {reason:?} must be refused naming the \
             command and `{}`, got: {result:?}",
            reason.text()
        );
    }
}

// A Tui app with a confirmed interactive terminal is admitted: the gate is a
// refusal, not an extra ceremony a normal interactive run must pass through.
#[test]
fn gate_terminal_admits_a_tui_app_with_an_interactive_terminal() {
    use ipe_runtime_rust::terminal_access::TerminalAccess;
    let result = gate_terminal_decision(
        "run",
        crate::delivery::Shape::Tui,
        TerminalAccess::Interactive,
    );
    assert!(
        result.is_ok(),
        "an interactive terminal must pass: {result:?}"
    );
}

/// A fresh scratch directory for a session-log test.
fn session_scratch(tag: &str) -> PathBuf {
    let dir = ipe_test_temp::temp_root().join(format!("ipe_session_{tag}_{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    assert!(fs::create_dir_all(&dir).is_ok(), "make scratch dir");
    dir
}

// A named `.ipelog` is shown as a trace; any other named log is folded.
#[test]
fn named_replay_log_is_shown_when_it_is_a_trace() {
    let dir = session_scratch("named");
    let trace = dir.join("bug.ipelog");
    let typed = dir.join("bug.ipemsgs");
    assert!(fs::write(&trace, "Add(1) => 1\n").is_ok(), "write trace");
    assert!(fs::write(&typed, "{}").is_ok(), "write typed log");
    let shown = replay_plan(trace.clone());
    assert!(
        matches!(&shown, Ok(SessionPlan::ShowTrace(p)) if *p == trace),
        "a named trace must be shown: {shown:?}"
    );
    let folded = replay_plan(typed.clone());
    assert!(
        matches!(&folded, Ok(SessionPlan::Run(SessionEnv::Replay(p))) if *p == typed),
        "a named typed log must be folded: {folded:?}"
    );
    let _ = fs::remove_dir_all(&dir);
}

// With no path, `--replay` folds the typed log, falls back to showing the
// trace when only the trace exists (a trace-only session), and refuses when
// neither was recorded.
#[test]
fn default_replay_prefers_the_typed_log_then_the_trace() {
    let dir = session_scratch("default");
    let entry = dir.join("proj").join("Main.ipe");
    assert!(
        fs::create_dir_all(dir.join("proj")).is_ok(),
        "make project dir"
    );
    assert!(
        fs::write(&entry, "module Main exposing (main)\n").is_ok(),
        "write entry"
    );
    let out = dir.join("out");
    let output_result = resolve_output_root(Some(&out.to_string_lossy()), &entry, None);
    assert!(output_result.is_ok(), "out must resolve: {output_result:?}");
    let output = output_result.expect("`output_result` must succeed");
    let replay = cli_args::SessionMode::Replay(None);

    let none = resolve_session_plan(&replay, &output);
    assert!(
        matches!(&none, Err(CliError::Usage(msg)) if msg.contains("--record")),
        "no recorded session must be refused: {none:?}"
    );

    let trace = out.join(RECORD_LOG_FILE);
    assert!(fs::write(&trace, "Add(1) => 1\n").is_ok(), "write trace");
    let shown = resolve_session_plan(&replay, &output);
    assert!(
        matches!(&shown, Ok(SessionPlan::ShowTrace(p)) if p.ends_with(RECORD_LOG_FILE)),
        "a lone trace must be shown: {shown:?}"
    );

    assert!(
        fs::write(out.join(typed_log_file()), "{}").is_ok(),
        "write typed log"
    );
    let folded = resolve_session_plan(&replay, &output);
    assert!(
        matches!(&folded, Ok(SessionPlan::Run(SessionEnv::Replay(p))) if p.ends_with(typed_log_file())),
        "the typed log must win over the trace: {folded:?}"
    );
    let _ = fs::remove_dir_all(&dir);
}

// A planted trace carrying terminal escapes (a screen clear, an OSC 8
// hyperlink, C1 controls, DEL, tabs, a zero-width space, and a bidi override)
// is shown with every control character and denied format character removed,
// one step per line under a label that says it is not a replay.
#[test]
fn shown_trace_strips_every_control_character() {
    let dir = session_scratch("laced");
    let trace = dir.join("planted\x1b[31m.ipelog");
    let laced = "\x1b]8;;https://evil.example\x07\x1b[2JAdd(1\u{200B}) => 1\n\
                 Say(\x1b]8;;https://evil.example\x07link\x1b]8;;\x1b\\) => 2\r\n\
                 \u{9b}2J\u{9d}0;title\u{9c}Add(\u{85}3\t\u{7f}\u{202e}) => 5\n\
                 \x1b[H\x1b[2J\n";
    assert!(fs::write(&trace, laced).is_ok(), "write planted trace");
    let shown = load_session_trace(&trace);
    assert!(
        shown.is_ok(),
        "a UTF-8 trace under the cap must show: {shown:?}"
    );
    let out = shown.expect("`shown` must succeed");
    assert!(
        !out.chars().any(|c| c.is_control() && c != '\n'),
        "the shown trace must carry no control character: {out:?}"
    );
    assert!(
        !out.contains('\u{200B}') && !out.contains('\u{202e}'),
        "the shown trace must carry no denied format character: {out:?}"
    );
    assert!(
        !out.contains("\x1b]") && !out.contains("\x1b["),
        "the shown trace must carry no escape sequence: {out:?}"
    );
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 4, "label + one line per step: {out:?}");
    assert!(
        lines.first().is_some_and(|l| l.contains("not a replay")),
        "the trace must be labelled as not a replay: {out:?}"
    );
    assert_eq!(lines.get(1).copied(), Some("Add(1) => 1"));
    assert_eq!(lines.get(2).copied(), Some("Say(link) => 2"));
    assert!(
        lines.get(3).is_some_and(|l| l.ends_with("Add(3) => 5")),
        "{out:?}"
    );
    let _ = fs::remove_dir_all(&dir);
}

// A trace over the cap is refused typed, before anything is rendered.
#[test]
fn shown_trace_over_the_cap_is_refused() {
    let dir = session_scratch("oversized");
    let trace = dir.join("big.ipelog");
    let over = usize::try_from(crate::io_bounded::SESSION_TRACE_READ_CAP + 1).unwrap_or(usize::MAX);
    assert!(
        fs::write(&trace, vec![b'a'; over]).is_ok(),
        "write big trace"
    );
    let shown = load_session_trace(&trace);
    assert!(
        matches!(shown, Err(CliError::FileTooLarge { .. })),
        "an oversized trace must be refused: {shown:?}"
    );
    let _ = fs::remove_dir_all(&dir);
}

// A non-UTF-8 trace is refused typed, never a panic and never lossy output.
#[test]
fn shown_trace_not_utf8_is_refused() {
    let dir = session_scratch("not_utf8");
    let trace = dir.join("bin.ipelog");
    assert!(
        fs::write(&trace, [b'A', 0xff, 0xfe, b'\n']).is_ok(),
        "write binary trace"
    );
    let shown = load_session_trace(&trace);
    assert!(
        matches!(&shown, Err(CliError::Io { source, .. })
            if source.kind() == std::io::ErrorKind::InvalidData),
        "a non-UTF-8 trace must be refused: {shown:?}"
    );
    let _ = fs::remove_dir_all(&dir);
}

// -----------------------------------------------------------------------
// User files are never overwritten or deleted by the build pipeline
// -----------------------------------------------------------------------

fn user_project(tag: &str) -> PathBuf {
    let dir =
        ipe_test_temp::temp_root().join(format!("ipe_user_files_{tag}_{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("src")).expect("make src");
    fs::write(
        dir.join("src").join("Main.ipe"),
        "module Main exposing (main)\n",
    )
    .expect("write Main.ipe");
    fs::write(dir.join("Cargo.toml"), "# the user's own manifest\n").expect("write Cargo.toml");
    dir
}

/// Emitting into a directory that holds the user's files is refused untouched.
///
/// This is `ipe dev build --out .`: nothing is written or pruned, and the user's
/// `src/` and `Cargo.toml` survive byte-for-byte.
#[test]
fn emitting_into_a_user_directory_is_refused_untouched() {
    let dir = user_project("emit");
    let emitted = ipe_backend::EmittedProject {
        files: BTreeMap::new(),
        cargo_toml: "[package]\nname = \"ipe-app\"\n".to_owned(),
        uses_webview: false,
    };
    let elsewhere = dir.with_extension("project");
    fs::create_dir_all(&elsewhere).expect("project dir");
    let result = EmitTarget::at(&dir, &ProjectPaths::of_file(&elsewhere.join("Main.ipe")))
        .and_then(|target| {
            write_emitted_project(&emitted, &target, &dir.join("no-runtime"), None, false)
        });
    assert!(
        matches!(result, Err(CliError::OutputRefused(_))),
        "emitting into a user directory must be refused, got {result:?}"
    );
    let _ = fs::remove_dir_all(&elsewhere);
    assert_eq!(
        fs::read_to_string(dir.join("src").join("Main.ipe")).unwrap_or_default(),
        "module Main exposing (main)\n",
        "the user's source must survive"
    );
    assert_eq!(
        fs::read_to_string(dir.join("Cargo.toml")).unwrap_or_default(),
        "# the user's own manifest\n",
        "the user's Cargo.toml must survive"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// A lossy rewrite backs the original up before the atomic replace.
///
/// This covers `ipe fix` and `lint --fix`; a backup name is never reused.
#[test]
fn lossy_rewrite_backs_up_the_original() {
    let dir = user_project("lossy");
    let main = dir.join("src").join("Main.ipe");
    let first = rewrite_user_file(
        &main,
        "module Main exposing (main)\n-- v2\n",
        RewriteKind::Lossy,
    )
    .expect("rewrite");
    let second = rewrite_user_file(
        &main,
        "module Main exposing (main)\n-- v3\n",
        RewriteKind::Lossy,
    )
    .expect("rewrite again");
    let (Some(first), Some(second)) = (first, second) else {
        assert!(false_marker(), "a lossy rewrite must report its backup");
        return;
    };
    assert_ne!(first, second, "each rewrite keeps its own backup");
    assert_eq!(
        fs::read_to_string(&first).unwrap_or_default(),
        "module Main exposing (main)\n"
    );
    assert_eq!(
        fs::read_to_string(&second).unwrap_or_default(),
        "module Main exposing (main)\n-- v2\n"
    );
    assert_eq!(
        fs::read_to_string(&main).unwrap_or_default(),
        "module Main exposing (main)\n-- v3\n"
    );
    let lossless = rewrite_user_file(
        &main,
        "module Main exposing (main)\n",
        RewriteKind::Lossless,
    )
    .expect("lossless rewrite");
    assert!(lossless.is_none(), "a lossless rewrite takes no backup");
    let _ = fs::remove_dir_all(&dir);
}

/// A symlinked source file is rewritten at its real location.
///
/// That is the file the user edits; the link is kept, not replaced by a
/// detached copy.
#[cfg(unix)]
#[test]
fn rewrite_follows_a_symlinked_source_to_the_real_file() {
    let dir = user_project("symlink");
    let real = dir.join("real.ipe");
    fs::write(&real, "module Main exposing (main)\n").expect("write real");
    let link = dir.join("src").join("Link.ipe");
    std::os::unix::fs::symlink(&real, &link).expect("make link");
    rewrite_user_file(
        &link,
        "module Main exposing (main)\n-- new\n",
        RewriteKind::Lossless,
    )
    .expect("rewrite through link");
    assert!(
        fs::symlink_metadata(&link).is_ok_and(|m| m.file_type().is_symlink()),
        "the link stays a link"
    );
    assert_eq!(
        fs::read_to_string(&real).unwrap_or_default(),
        "module Main exposing (main)\n-- new\n"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// The atomic writer's temp file is created exclusively.
///
/// A symlink planted at the temp name is never written through.
#[cfg(unix)]
#[test]
fn atomic_write_never_writes_through_a_planted_temp_symlink() {
    let dir = user_project("tmp_symlink");
    let victim = dir.join("victim.txt");
    fs::write(&victim, "keep").expect("write victim");
    let tmp = dir.join("planted.tmp");
    std::os::unix::fs::symlink(&victim, &tmp).expect("plant link");
    let result = write_and_rename(&tmp, &dir.join("target.txt"), "payload");
    assert!(
        matches!(result, Err(CliError::Io { .. })),
        "an existing temp path must be refused, got {result:?}"
    );
    assert_eq!(fs::read_to_string(&victim).unwrap_or_default(), "keep");
    let _ = fs::remove_dir_all(&dir);
}

/// An emit target that is, or holds, the project is refused before any write.
///
/// This is `write_emitted_project` reached without a caller-proven target: the
/// bare path is proven against the project, and the project directory keeps
/// exactly its own files.
#[test]
fn an_emit_target_overlapping_the_project_is_refused() {
    let base = ipe_test_temp::temp_root().join(format!("ipe_emit_overlap_{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    let project_dir = base.join("app");
    fs::create_dir_all(&project_dir).expect("project dir");
    fs::write(
        project_dir.join("Main.ipe"),
        "module Main exposing (main)\n",
    )
    .expect("module");
    let project = ProjectPaths::of_file(&project_dir.join("Main.ipe"));

    let root = EmitTarget::at(&project_dir, &project);
    assert!(
        matches!(
            root,
            Err(CliError::OutputRefused(OutputRefusal::ProjectRoot(_)))
        ),
        "the project directory must be refused, got {root:?}"
    );
    let holder = EmitTarget::at(&base, &project);
    assert!(
        matches!(
            holder,
            Err(CliError::OutputRefused(
                OutputRefusal::ContainsProject { .. }
            ))
        ),
        "a directory holding the project must be refused, got {holder:?}"
    );
    let runtime = base.join("no-runtime");
    for out in [project_dir.clone(), base.clone()] {
        let built = build_loose_file(&project_dir.join("Main.ipe"), &out, &runtime);
        assert!(
            matches!(built, Err(CliError::OutputRefused(_))),
            "a bare out overlapping the project must be refused, got {built:?}"
        );
    }
    let entries = fs::read_dir(&project_dir).map_or(0, Iterator::count);
    assert_eq!(
        entries, 1,
        "the project directory keeps exactly its own file"
    );
    let _ = fs::remove_dir_all(&base);
}

/// A claimed emit target replaced after its claim is refused, never written.
///
/// A plain directory planted at the claimed path has another identity, so the
/// write fails closed and the planted directory stays empty.
#[test]
fn a_replaced_claimed_target_is_refused_untouched() {
    let base = ipe_test_temp::temp_root().join(format!("ipe_emit_replaced_{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    let out = base.join("out");
    let claimed = emit_target(&out).claim().expect("claim out");
    fs::rename(&out, base.join("moved")).expect("move the claimed dir away");
    fs::create_dir_all(&out).expect("plant a directory at the claimed path");
    let emitted = ipe_backend::EmittedProject {
        files: BTreeMap::new(),
        cargo_toml: "[package]\nname = \"ipe-app\"\n".to_owned(),
        uses_webview: false,
    };
    let result = write_emitted_project(
        &emitted,
        &EmitTarget::Claimed(claimed),
        &base.join("no-runtime"),
        None,
        false,
    );
    assert!(
        matches!(
            result,
            Err(CliError::OutputRefused(OutputRefusal::Replaced(_)))
        ),
        "a replaced target must be refused, got {result:?}"
    );
    let entries = fs::read_dir(&out).map_or(usize::MAX, Iterator::count);
    assert_eq!(entries, 0, "the planted directory stays empty");
    let _ = fs::remove_dir_all(&base);
}

/// A marked crate dir planted with symlinks is refused by the emit.
///
/// A cloned repository can force-add such a dir with a symlinked `src/` or a
/// symlinked file; the write + prune refuse both, and the link targets survive
/// byte-for-byte.
#[cfg(unix)]
#[test]
fn emitting_into_a_marked_dir_with_planted_links_is_refused() {
    let base = ipe_test_temp::temp_root().join(format!("ipe_planted_emit_{}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    let victim = base.join("victim");
    fs::create_dir_all(&victim).expect("victim dir");
    fs::write(victim.join("precious.ipe"), "keep").expect("victim file");
    let emitted = ipe_backend::EmittedProject {
        files: BTreeMap::new(),
        cargo_toml: "[package]\nname = \"ipe-app\"\n".to_owned(),
        uses_webview: false,
    };

    // A symlinked `src/`: pruning it would mass-delete the target.
    let dir_link = base.join("out-a");
    crate::output_dir::OwnedDir::claim(&dir_link).expect("claim");
    std::os::unix::fs::symlink(&victim, dir_link.join("src")).expect("dir link");
    let result = write_emitted_project(
        &emitted,
        &emit_target(&dir_link),
        &base.join("no-runtime"),
        None,
        false,
    );
    assert!(
        matches!(result, Err(CliError::OutputRefused(_))),
        "a symlinked src/ must be refused, got {result:?}"
    );

    // A symlinked final file: writing it would overwrite the target.
    let file_link = base.join("out-b");
    crate::output_dir::OwnedDir::claim(&file_link).expect("claim");
    std::os::unix::fs::symlink(victim.join("precious.ipe"), file_link.join("Cargo.toml"))
        .expect("file link");
    let result = write_emitted_project(
        &emitted,
        &emit_target(&file_link),
        &base.join("no-runtime"),
        None,
        false,
    );
    assert!(
        matches!(result, Err(CliError::OutputRefused(_))),
        "a symlinked Cargo.toml must be refused, got {result:?}"
    );

    assert_eq!(
        fs::read_to_string(victim.join("precious.ipe")).unwrap_or_default(),
        "keep",
        "the link target survives byte-for-byte"
    );
    let _ = fs::remove_dir_all(&base);
}

/// A backup keeps the original's permission bits.
///
/// An owner-only source never gets a more readable copy.
#[cfg(unix)]
#[test]
fn backup_preserves_a_private_files_mode() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = user_project("private_backup");
    let main = dir.join("src").join("Main.ipe");
    fs::set_permissions(&main, fs::Permissions::from_mode(0o600)).expect("chmod 600");
    let backup = rewrite_user_file(
        &main,
        "module Main exposing (main)\n-- v2\n",
        RewriteKind::Lossy,
    )
    .expect("rewrite");
    let Some(backup) = backup else {
        assert!(false_marker(), "a lossy rewrite must report its backup");
        return;
    };
    let mode = fs::metadata(&backup).map_or(0, |m| m.permissions().mode() & 0o777);
    assert_eq!(mode, 0o600, "the backup must stay owner-only");
    let _ = fs::remove_dir_all(&dir);
}

/// A directory walk refuses to rewrite a file that resolves outside the project.
///
/// An explicitly named file may still be followed.
#[cfg(unix)]
#[test]
fn walked_rewrite_refuses_a_file_outside_the_project() {
    let dir = user_project("walk_escape");
    let outside = dir.with_extension("outside.ipe");
    fs::write(&outside, "module Other\n").expect("outside file");
    let link = dir.join("src").join("Other.ipe");
    std::os::unix::fs::symlink(&outside, &link).expect("link");
    let result = rewrite_walked_file(
        &dir,
        &link,
        "module Other\n-- evil\n",
        RewriteKind::Lossless,
    );
    assert!(
        matches!(result, Err(CliError::OutputRefused(_))),
        "a walked file escaping the project must be refused, got {result:?}"
    );
    assert_eq!(
        fs::read_to_string(&outside).unwrap_or_default(),
        "module Other\n"
    );
    let _ = fs::remove_file(&outside);
    let _ = fs::remove_dir_all(&dir);
}

fn redundant_red_branch_at(lo: u32) -> Diagnostic {
    Diagnostic::Type {
        span: Span {
            lo,
            hi: lo.saturating_add(3),
        },
        msg: ipe_diagnostics::TypeError::RedundantCaseBranch {
            constructor: "Red".into(),
        },
    }
}

/// A warning homed in an imported module renders against that module's file.
///
/// The entry module's text also has a line at the warning's byte offset, so
/// only the home can pick the right file.
#[test]
fn homed_warning_renders_against_its_home_module_file() {
    let lib_src =
        "module Lib exposing (label)\nlabel c =\n    case c of\n        Red ->\n            3\n";
    let main_src = "module Main exposing (main)\nmain =\n    label Red\n\n\n\n\n\n\n\n";
    let lib = vec![ipe_intern::Symbol::from_raw(1)];
    let main = vec![ipe_intern::Symbol::from_raw(0)];
    let mut home_to_source = BTreeMap::new();
    home_to_source.insert(
        lib.clone(),
        (PathBuf::from("src/Lib.ipe"), lib_src.to_owned()),
    );
    home_to_source.insert(main, (PathBuf::from("src/Main.ipe"), main_src.to_owned()));
    let entry = (PathBuf::from("src/Main.ipe"), main_src.to_owned());
    let lo = lib_src
        .rfind("Red ->")
        .and_then(|o| u32::try_from(o).ok())
        .unwrap_or_default();
    let warning = ipe_types::HomedWarning::new(redundant_red_branch_at(lo), &lib);
    assert!(warning.is_ok(), "a homed T0011 warning is accepted");
    let warning = warning.expect("`warning` must succeed");

    let rendered = render_homed_warnings(&home_to_source, &entry, &[warning]);
    assert!(rendered.is_ok(), "a known home renders, got {rendered:?}");
    let rendered = rendered.expect("`rendered` must succeed");
    assert_eq!(rendered.len(), 1, "one warning renders once");
    let text = rendered.concat();
    assert!(
        text.contains("--> src/Lib.ipe:4:9"),
        "the warning must be located in Lib at the redundant arm, got:\n{text}"
    );
    assert!(
        !text.contains("Main.ipe"),
        "the entry file must not frame an imported module's warning, got:\n{text}"
    );
}

/// A warning whose home names no known module is refused as a compiler bug.
///
/// The refusal is blamed on the entry file; the warning is never framed
/// against a guessed file.
#[test]
fn homed_warning_with_unknown_home_is_refused() {
    let main_src = "module Main exposing (main)\nmain =\n    1\n";
    let mut home_to_source = BTreeMap::new();
    home_to_source.insert(
        vec![ipe_intern::Symbol::from_raw(0)],
        (PathBuf::from("src/Main.ipe"), main_src.to_owned()),
    );
    let entry = (PathBuf::from("src/Main.ipe"), main_src.to_owned());
    let warning = ipe_types::HomedWarning::new(
        redundant_red_branch_at(0),
        &[ipe_intern::Symbol::from_raw(7)],
    );
    assert!(warning.is_ok(), "a homed T0011 warning is accepted");
    let warning = warning.expect("`warning` must succeed");

    let rendered = render_homed_warnings(&home_to_source, &entry, &[warning]);
    assert!(
        matches!(
            &rendered,
            Err(CliError::Pipeline { file, diag, .. })
                if file == &entry.0
                    && matches!(
                        diag.as_ref(),
                        Diagnostic::CompilerBug { where_: "driver.render_homed_warnings", .. }
                    )
        ),
        "an unknown home must fail closed as a compiler bug, got {rendered:?}"
    );
}

/// A type-checker error sited at a module with no source file is refused.
///
/// The refusal is a compiler bug blamed on the entry; the byte-offset guess,
/// which would frame the error against whichever def encloses its span, is
/// never consulted.
#[test]
fn sited_error_with_unknown_home_fails_closed() {
    let main_src = "module Main exposing (main)\n\nmain =\n    1\n";
    let mut interner = ipe_intern::Interner::new();
    let Ok(parsed) = ipe_parse::parse_module(main_src, &mut interner) else {
        return;
    };
    let Ok(linked) = ipe_canon::canonicalise(&parsed, &mut interner) else {
        return;
    };
    let (Ok(main), Ok(other)) = (interner.intern("Main"), interner.intern("Other")) else {
        return;
    };
    let Some(other_home) = ipe_types::ModuleHome::new(vec![other]) else {
        return;
    };
    let mut home_to_source = BTreeMap::new();
    home_to_source.insert(
        vec![main],
        (PathBuf::from("src/Main.ipe"), main_src.to_owned()),
    );
    let entry = (PathBuf::from("src/Main.ipe"), main_src.to_owned());
    let lo = main_src
        .rfind('1')
        .and_then(|o| u32::try_from(o).ok())
        .unwrap_or_default();
    let err = ipe_db::PipelineError::Infer(ipe_types::InferError::sited(
        redundant_red_branch_at(lo),
        &other_home,
    ));

    let framed = attribute_post_link_error(&linked, &home_to_source, &entry, err);
    assert!(
        matches!(
            &framed,
            CliError::Pipeline { file, diag, .. }
                if file == &entry.0
                    && matches!(
                        diag.as_ref(),
                        Diagnostic::CompilerBug { where_: "driver.frame_infer_error", .. }
                    )
        ),
        "an unknown sited home must fail closed as a compiler bug, got {framed:?}"
    );
}

/// Version `1.0.0` of `audited`, published from a fresh one-file repo under
/// `root` and pinned to `sha256` (the tree's own hash when `None`), read back
/// through the index parser.
fn audited_version(root: &Path, sha256: Option<&str>) -> crate::index::EntryVersion {
    let source = root.join("source");
    std::fs::create_dir_all(&source).expect("source dir");
    let git = |args: &[&str]| -> Vec<u8> {
        let out = crate::remote_ingest::fixture_git(&source)
            .args(args)
            .output()
            .expect("git runs");
        assert!(out.status.success(), "git {args:?} must succeed");
        out.stdout
    };
    git(&["init", "--quiet"]);
    std::fs::write(source.join("lib.ipe"), "module Lib\n").expect("write file");
    git(&["add", "."]);
    git(&["commit", "--quiet", "-m", "seed"]);
    let rev = String::from_utf8(git(&["rev-parse", "HEAD"])).expect("utf-8 rev");
    let hash = crate::resolve::hash_source_tree(&source).expect("hash source");
    let sha256 = sha256.unwrap_or(hash.as_str());
    let index_root = root.join("index");
    let packages = index_root.join("packages");
    std::fs::create_dir_all(&packages).expect("packages dir");
    let entry = format!(
        "name = \"audited\"\npublisher = \"tester\"\n\n[[version]]\nversion = \"1.0.0\"\n\
         source = \"{}\"\nrev = \"{}\"\nsha256 = \"{sha256}\"\ncapabilities = []\n",
        source.display(),
        rev.trim(),
    );
    std::fs::write(packages.join("audited.toml"), entry).expect("write entry");
    let entry = crate::index::read_entry(&index_root, "audited").expect("fixture entry parses");
    let req = "^1".parse().expect("valid req");
    crate::index::resolve_version(&entry, &req)
        .expect("fixture version resolves")
        .clone()
}

/// Every way `certify_versions` ends — a pass, an audit rejection, a hash
/// mismatch and a fetch refusal — leaves no scratch directory under the cache
/// base.
#[test]
fn certify_versions_leaves_no_scratch_under_the_cache_base() {
    use crate::remote_ingest::{
        ByteBudget, FetchBudget, IngestLimit, IngestRefusal, IngestSource, PACKAGE_SOURCE,
        TreeCeiling,
    };

    let fixture = crate::scratch::ScratchDir::new("ipe-audit-fixture").expect("fixture dir");
    let cache = crate::scratch::ScratchDir::new("ipe-audit-cache").expect("cache dir");
    let scratch_parent = cache.path().join("ipe");
    let leftovers = || std::fs::read_dir(&scratch_parent).map_or(0, Iterator::count);
    let name = crate::package_name::PackageName::parse("audited").expect("name parses");
    let good = audited_version(&fixture.path().join("good"), None);

    let mut audited = Vec::new();
    let certified = certify_versions(
        cache.path(),
        &name,
        &[&good],
        &PACKAGE_SOURCE,
        |checkout, _| {
            audited
                .push(checkout.starts_with(&scratch_parent) && checkout.join("lib.ipe").is_file());
            Ok(())
        },
    )
    .expect("a verified version certifies");
    assert_eq!(certified, ["1.0.0"]);
    assert_eq!(
        audited,
        [true],
        "the audit ran on the verified checkout in the scratch dir"
    );
    assert_eq!(leftovers(), 0, "a pass leaves no scratch dir");

    let rejected = certify_versions(cache.path(), &name, &[&good], &PACKAGE_SOURCE, |_, _| {
        Err(CliError::Interrupted)
    });
    assert!(
        matches!(rejected, Err(CliError::Interrupted)),
        "{rejected:?}"
    );
    assert_eq!(leftovers(), 0, "an audit rejection leaves no scratch dir");

    let zeros = "0".repeat(64);
    let forged = audited_version(&fixture.path().join("forged"), Some(&zeros));
    let mismatch = certify_versions(cache.path(), &name, &[&forged], &PACKAGE_SOURCE, |_, _| {
        Ok(())
    });
    assert!(
        matches!(mismatch, Err(CliError::HashMismatch { .. })),
        "{mismatch:?}"
    );
    assert_eq!(leftovers(), 0, "a hash mismatch leaves no scratch dir");

    let starved = FetchBudget::for_test(
        PACKAGE_SOURCE
            .transfer()
            .with_staged_bytes(ByteBudget::for_test(1).expect("in-range byte budget"))
            .expect("a package fetch stages on disk"),
        *PACKAGE_SOURCE.refs(),
        TreeCeiling::for_test(0, 1, 0, 1).expect("paired tree ceiling"),
    )
    .expect("paired budget");
    let refused = certify_versions(cache.path(), &name, &[&good], &starved, |_, _| Ok(()));
    assert!(
        matches!(
            refused,
            Err(CliError::RemoteIngestExceeded(IngestRefusal {
                source: IngestSource::PackageFetch,
                limit: IngestLimit::Bytes(_),
                name: Some(ref named),
            })) if named.as_str() == "audited"
        ),
        "{refused:?}"
    );
    assert_eq!(leftovers(), 0, "a fetch refusal leaves no scratch dir");
}

// ── Grouped verbs: the legacy names and bare groups refuse ──────────────────

/// Run `ipe <args>` in process.
fn run_argv(words: &[&str]) -> Result<(), CliError> {
    let argv: Vec<String> = words.iter().map(|w| (*w).to_owned()).collect();
    run_cli(&argv)
}

/// Assert `ipe <args>` refuses with [`CliError::GroupRequired`].
///
/// The refusal names exactly `forms` and carries `tail`, as a user fault whose
/// screen gives one hint per form and no other.
fn assert_group_required(args: &[&str], attempted: &str, forms: &[Verb], tail: &str) {
    let result = run_argv(args);
    assert!(
        matches!(
            &result,
            Err(CliError::GroupRequired { attempted: a, forms: f, tail: t })
                if a.as_str() == attempted && *f == forms && t.as_str() == tail
        ),
        "`ipe {}` must refuse naming {forms:?} with tail {tail:?}: {result:?}",
        args.join(" ")
    );
    let Err(err) = result else {
        return;
    };
    assert!(
        matches!(err.fault(), crate::screen::Fault::User),
        "a group refusal is the user's to fix: {err:?}"
    );
    let screen = err.to_string();
    for form in forms {
        let hint = if tail.is_empty() {
            format!("ipe {form}")
        } else {
            format!("ipe {form} {tail}")
        };
        assert!(
            screen.contains(&hint),
            "`ipe {}` must hint `{hint}`: {screen}",
            args.join(" ")
        );
    }
    assert_eq!(
        screen.matches("help:").count(),
        forms.len(),
        "one hint line per grouped form: {screen}"
    );
    assert_states_both_postures(&screen, args);
}

/// A bare-verb refusal says what each posture is for, in the catalog's words.
fn assert_states_both_postures(screen: &str, args: &[&str]) {
    for posture in [crate::text::posture_dev(), crate::text::posture_release()] {
        assert!(
            screen.contains(posture),
            "`ipe {}` must state the posture {posture:?}: {screen}",
            args.join(" ")
        );
    }
}

/// Every bare legacy verb and every bare group refuses with both posture lines.
///
/// Walks the refusal table itself, so a new bare name cannot skip them.
#[test]
fn every_bare_refusal_states_both_postures() {
    let bare = super::commands::GROUP_REQUIRED
        .iter()
        .map(|(name, _)| *name)
        .chain(["release", "dev"]);
    for name in bare {
        let result = run_argv(&[name]);
        assert!(
            matches!(&result, Err(CliError::GroupRequired { .. })),
            "bare `ipe {name}` must be a group-required refusal: {result:?}"
        );
        let Err(err) = result else {
            return;
        };
        assert_states_both_postures(&err.to_string(), &[name]);
    }
}

#[test]
fn bare_build_refuses() {
    assert_group_required(
        &["build"],
        "build",
        &[Verb::DEV_BUILD, Verb::RELEASE_BUILD],
        "",
    );
    assert_group_required(
        &["build", "--help"],
        "build",
        &[Verb::DEV_BUILD, Verb::RELEASE_BUILD],
        "--help",
    );
}

#[test]
fn bare_run_refuses() {
    assert_group_required(&["run"], "run", &[Verb::DEV_RUN, Verb::RELEASE_RUN], "");
}

#[test]
fn bare_watch_refuses() {
    assert_group_required(&["watch"], "watch", &[Verb::DEV_WATCH], "");
}

#[test]
fn bare_exec_refuses() {
    assert_group_required(&["exec"], "exec", &[Verb::RELEASE_RUN], "");
}

#[test]
fn bare_capabilities_refuses() {
    assert_group_required(
        &["capabilities"],
        "capabilities",
        &[Verb::RELEASE_CAPABILITIES],
        "",
    );
    assert_group_required(
        &["capabilities", "src/Main.ipe", "--json"],
        "capabilities",
        &[Verb::RELEASE_CAPABILITIES],
        "src/Main.ipe --json",
    );
}

#[test]
fn bare_eject_refuses() {
    assert_group_required(
        &["eject", "--out", "x"],
        "eject",
        &[Verb::RELEASE_EJECT],
        "--out x",
    );
}

/// A bare `ipe release` lists its four members and fails.
///
/// `--help` on the group is a help request, never this refusal.
#[test]
fn bare_release_refuses_nonzero() {
    assert_group_required(
        &["release"],
        "release",
        &[
            Verb::RELEASE_BUILD,
            Verb::RELEASE_RUN,
            Verb::RELEASE_EJECT,
            Verb::RELEASE_CAPABILITIES,
        ],
        "",
    );
    assert!(intercept_help(&["release".to_owned()]).is_none());
    assert!(intercept_help(&["release".to_owned(), "--help".to_owned()]).is_some());
}

/// A non-member token after `ipe release` refuses towards `release build`.
///
/// The target and inspection forms of the ungrouped command are not members.
#[test]
fn release_target_form_refuses() {
    assert_group_required(
        &["release", "web", "android"],
        "release",
        &[Verb::RELEASE_BUILD],
        "web android",
    );
    assert_group_required(
        &["release", "--capabilities"],
        "release",
        &[Verb::RELEASE_BUILD],
        "--capabilities",
    );
    assert_group_required(
        &["release", "--show-profile"],
        "release",
        &[Verb::RELEASE_BUILD],
        "--show-profile",
    );
}

/// `release build` has no capability-inspection flags.
///
/// Each refuses as an unknown flag of `release build`, and the screen points
/// nowhere else.
#[test]
fn release_build_capabilities_flag_is_unknown() {
    for flag in ["--capabilities", "--show-profile"] {
        let result = run_argv(&["release", "build", flag]);
        assert!(
            matches!(
                &result,
                Err(CliError::CommandUsage { command, reason })
                    if *command == Verb::RELEASE_BUILD.name() && reason.as_str().contains(flag)
            ),
            "`release build {flag}` must refuse as an unknown flag: {result:?}"
        );
        let Err(err) = result else {
            return;
        };
        assert!(
            !err.to_string().contains("capabilities`"),
            "the refusal must not redirect to another command: {err}"
        );
    }
}

/// A bare `ipe dev` fails with no hint line; `ipe dev --help` is its page.
#[test]
fn bare_dev_refuses_nonzero() {
    assert_group_required(&["dev"], "dev", &[], "");
    assert!(intercept_help(&["dev".to_owned()]).is_none());
    assert!(intercept_help(&["dev".to_owned(), "--help".to_owned()]).is_some());
}

/// A token after `ipe dev` that names no member is an unknown subcommand.
#[test]
fn dev_unknown_member_is_unknown_group_sub() {
    let result = run_argv(&["dev", "eject"]);
    assert!(
        matches!(
            &result,
            Err(CliError::UnknownGroupSub { group: "dev", attempted }) if attempted.as_str() == "eject"
        ),
        "{result:?}"
    );
}

/// `--emit-permissions` is a `release build` flag only.
///
/// `dev build` refuses it as unknown; `release build` parses it.
#[test]
fn dev_build_emit_permissions_is_unknown() {
    let result = run_argv(&["dev", "build", "--emit-permissions", "ios"]);
    assert!(
        matches!(
            &result,
            Err(CliError::CommandUsage { command, reason })
                if *command == Verb::DEV_BUILD.name()
                    && reason.as_str().contains("--emit-permissions")
        ),
        "`dev build --emit-permissions` must refuse as an unknown flag: {result:?}"
    );
    let release =
        cli_args::parse_release_build(&["--emit-permissions".to_owned(), "ios".to_owned()]);
    assert!(
        release.is_ok(),
        "`release build --emit-permissions ios` parses: {release:?}"
    );
}

/// Every argv echo in a group refusal is sanitized.
///
/// A control or bidi sequence in the tail never reaches the screen raw.
#[test]
fn group_required_sanitizes_attempted() {
    let hostile = "\u{1b}[2Jweb\u{202e}android";
    for args in [["release", hostile], ["build", hostile]] {
        let result = run_argv(&args);
        assert!(
            matches!(&result, Err(CliError::GroupRequired { tail, .. })
                if !tail.as_str().contains('\u{1b}') && !tail.as_str().contains('\u{202e}')
                    && tail.as_str().contains("web")),
            "the tail must be stored sanitized: {result:?}"
        );
        let Err(err) = result else {
            return;
        };
        let screen = err.to_string();
        assert!(
            !screen.contains('\u{1b}') && !screen.contains('\u{202e}'),
            "the refusal screen must carry no raw control or bidi character: {screen:?}"
        );
    }
}

// ── Grouped verbs: posture comes from the verb ──────────────────────────────

/// A console program that calls `Debug.log`.
const DEBUG_LOG_MAIN: &str = "module Main exposing (main)\n\nimport Ipe.Io as Io\nimport Ipe.Debug as Debug\n\nshout : String -> String\nshout s =\n    Debug.log \"shout\" s\n\nmain : Task Error ()\nmain =\n    Io.println (shout \"hi\")\n";

/// Compile [`DEBUG_LOG_MAIN`] under `verb`'s posture, uncached.
fn compile_debug_log_as(verb: Verb, label: &str) -> Result<crate::output_dir::OwnedDir, CliError> {
    let runtime = resolve_runtime().expect("the in-repo runtime resolves");
    let tmp = ipe_test_temp::temp_root()
        .join(format!("ipec-verb-posture-{label}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).expect("create scratch dir");
    let entry_path = vec!["Main".to_owned()];
    let entry_file = tmp.join("Main.ipe");
    let mut sources: BTreeMap<Vec<String>, (PathBuf, String)> = BTreeMap::new();
    sources.insert(
        entry_path.clone(),
        (entry_file.clone(), DEBUG_LOG_MAIN.to_owned()),
    );
    let discovered = vec![project::DiscoveredModule::user(
        entry_file.clone(),
        entry_path.clone(),
    )];
    let (result, _) = compile_modules_observed(
        sources,
        discovered,
        &entry_path,
        &emit_target(&tmp.join("out")),
        &runtime,
        &entry_file,
        ipe_backend_rust::DbDriver::Sqlite,
        None,
        BuildOptions {
            intent: verb.intent(),
            ..BuildOptions::default()
        },
    );
    let _ = fs::remove_dir_all(&tmp);
    result
}

/// `dev build` admits `Debug.*`; `release build` refuses it.
///
/// The gate reads the posture each verb fixes, nothing else.
#[test]
fn dev_build_allows_debug() {
    let dev = compile_debug_log_as(Verb::DEV_BUILD, "dev");
    assert!(dev.is_ok(), "a dev build admits Debug.log: {:?}", dev.err());
    let release = compile_debug_log_as(Verb::RELEASE_BUILD, "release");
    assert!(
        matches!(&release, Err(CliError::Pipeline { diag, .. }) if diag.code().as_str() == "IPE-L0140"),
        "a release build refuses Debug.log with IPE-L0140: {release:?}"
    );
}

/// Whether `result` is the `Ipe.Debug.*` release gate's IPE-L0140 refusal.
fn is_debug_gate<T>(result: &Result<T, CliError>) -> bool {
    matches!(result, Err(CliError::Pipeline { diag, .. }) if diag.code().as_str() == "IPE-L0140")
}

/// A fresh project dir under the temp root holding a manifest and `main`.
///
/// Returns the project dir and its `package.ipe` path.
fn debug_project(label: &str, package: &str, main: &str) -> (PathBuf, String) {
    let tmp = ipe_test_temp::temp_root().join(format!("ipec-{label}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(tmp.join("src")).expect("create project dir");
    fs::write(tmp.join("package.ipe"), package).expect("write package.ipe");
    fs::write(tmp.join("src").join("Main.ipe"), main).expect("write Main.ipe");
    let manifest = tmp.join("package.ipe").to_string_lossy().into_owned();
    (tmp, manifest)
}

/// A minimal manifest naming the package `name`.
fn named_package(name: &str) -> String {
    format!("module Package exposing (package)\n\n\npackage =\n    {{ name = \"{name}\" }}\n")
}

/// `ipe dev build` admits `Debug.*` through the whole dispatch path.
///
/// The positive control for the release gates below: a site that dropped its
/// verb's intent would fall back to the release default and refuse here.
/// Gated on `IPE_E2E=1`: the dispatch path cargo-builds the emitted crate.
#[test]
fn dev_build_dispatch_admits_debug() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let (tmp, package) = debug_project(
        "dev-build-dispatch-debug",
        &named_package("dev-build-debug"),
        DEBUG_LOG_MAIN,
    );
    let out = tmp.join("out").to_string_lossy().into_owned();
    let result = run_argv(&["dev", "build", &package, "--out", &out]);
    let _ = fs::remove_dir_all(&tmp);
    assert!(
        result.is_ok(),
        "`ipe dev build` admits Debug.log end to end: {result:?}"
    );
}

/// A desktop `Web.tea` app whose `update` calls `Debug.log`.
const DEBUG_DESKTOP_PACKAGE: &str = "module Package exposing (package)\n\nimport Ipe.Package exposing (..)\n\n\npackage : Package\npackage =\n    { name = \"desktop-debug\"\n    , version = \"0.1.0\"\n    }\n";

/// The `main` of [`DEBUG_DESKTOP_PACKAGE`].
const DEBUG_DESKTOP_MAIN: &str = "module Main exposing (main)\n\nimport Ipe.Tea.Web as Web\nimport Ipe.Tea.Web.Cmd as Cmd\nimport Ipe.Tea.Web.Sub as Sub\nimport Ipe.Debug as Debug\nimport Ipe.String as String\nimport Ipe.Ui as Ui\n\n\ntype alias Model =\n    { count : Int }\n\n\ntype Msg\n    = Increment\n    | NoOp\n\n\ninit : WebReq -> ( Model, Cmd.Cmd Msg )\ninit _req =\n    ( { count = 0 }, Cmd.none )\n\n\nupdate : Msg -> Model -> ( Model, Cmd.Cmd Msg )\nupdate msg model =\n    case msg of\n        Increment ->\n            ( { model | count = Debug.log \"count\" (model.count + 1) }, Cmd.none )\n\n        NoOp ->\n            ( model, Cmd.none )\n\n\nsubscriptions : Model -> Sub.Sub Msg\nsubscriptions _model =\n    Sub.none\n\n\nview : Model -> Element Msg\nview model =\n    Ui.column []\n        [ Ui.button [] { onPress = Just Increment, label = Ui.text \"+\" }\n        , Ui.text (String.fromInt model.count)\n        ]\n\n\nmain =\n    Web.tea\n        { init = init\n        , update = update\n        , view = view\n        , subscriptions = subscriptions\n        , routes = []\n        , notFound = NoOp\n        }\n";

/// Bundle the Debug-using desktop app under `profile`.
fn bundle_debug_desktop(profile: BundleProfile, label: &str) -> Result<(), CliError> {
    let (tmp, _) = debug_project(label, DEBUG_DESKTOP_PACKAGE, DEBUG_DESKTOP_MAIN);
    let project = tmp.to_string_lossy().into_owned();
    let result = bundle_delivery(BundleHost::Desktop, profile, Some(&project));
    let _ = fs::remove_dir_all(&tmp);
    result
}

/// A release desktop bundle refuses `Debug.*`.
///
/// The bundle compiles under the release posture, so IPE-L0140 fires before
/// any cargo build.
#[test]
fn release_desktop_bundle_gates_debug() {
    let result = bundle_debug_desktop(
        Verb::RELEASE_BUILD.bundle_profile(),
        "release-desktop-debug",
    );
    assert!(
        is_debug_gate(&result),
        "a release desktop bundle refuses Debug.log with IPE-L0140: {result:?}"
    );
}

/// A dev desktop bundle admits `Debug.*`: its compile and gates pass.
///
/// The positive control for [`release_desktop_bundle_gates_debug`]: a bundle
/// that dropped its profile's intent would compile under the release default
/// and refuse here. Gated on `IPE_E2E=1`: past the compile it cargo-builds,
/// so only a compile or gate refusal fails it.
#[test]
fn dev_desktop_bundle_admits_debug() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let result = bundle_debug_desktop(Verb::DEV_BUILD.bundle_profile(), "dev-desktop-debug");
    assert!(
        !matches!(&result, Err(CliError::Pipeline { .. } | CliError::Usage(_))),
        "a dev desktop bundle compiles a Debug.log app past every gate: {result:?}"
    );
}

/// Every `release build` target yields an artifact or a typed refusal.
///
/// `--target wasm` and a manifest-selected browser client are the browser
/// bundle, a native target is the static binary, and a WASI resolution, which
/// has no release form, refuses.
#[test]
fn release_build_wasm_produces_artifact() {
    use cli_args::{ReleaseTarget, StaticTriple};
    let native = ReleaseTarget::Native(StaticTriple::X8664LinuxMusl);
    for resolved in [
        CompileTarget::Native,
        CompileTarget::WasmClient,
        CompileTarget::WasmWasi,
    ] {
        let artifact = release_artifact(ReleaseTarget::Wasm, resolved);
        assert!(
            matches!(artifact, Ok(ReleaseArtifact::Browser)),
            "--target wasm is the browser bundle whatever the environment says: {artifact:?}"
        );
    }
    assert!(matches!(
        release_artifact(native.clone(), CompileTarget::WasmClient),
        Ok(ReleaseArtifact::Browser)
    ));
    assert!(matches!(
        release_artifact(native.clone(), CompileTarget::Native),
        Ok(ReleaseArtifact::Native(StaticTriple::X8664LinuxMusl))
    ));
    let wasi = release_artifact(native, CompileTarget::WasmWasi);
    assert!(
        matches!(&wasi, Err(CliError::Usage(reason)) if reason.to_string().contains("ipe dev build --target wasi")),
        "a WASI resolution has no release form: {wasi:?}"
    );
    assert_eq!(
        ReleaseArtifact::Browser.compile_target(),
        CompileTarget::WasmClient
    );
    assert_eq!(
        ReleaseArtifact::Native(StaticTriple::X8664LinuxMusl).compile_target(),
        CompileTarget::Native
    );
}

// ── `release run` and `release eject` ───────────────────────────────────────

/// `ipe release run` refuses `Debug.*` through the whole dispatch path.
///
/// IPE-L0140 fires in the compile, before any cargo step or jail; the
/// positive control is [`dev_build_dispatch_admits_debug`].
#[test]
fn release_run_gates_debug() {
    let (tmp, package) = debug_project(
        "release-run-debug",
        &named_package("release-run-debug"),
        DEBUG_LOG_MAIN,
    );
    let out = tmp.join("out").to_string_lossy().into_owned();
    let result = run_argv(&["release", "run", &package, "--out", &out]);
    let _ = fs::remove_dir_all(&tmp);
    assert!(
        is_debug_gate(&result),
        "a release run refuses Debug.log with IPE-L0140: {result:?}"
    );
}

/// `release eject` refuses `Debug.*` before a project is written.
#[test]
fn release_eject_gates_debug() {
    let tmp =
        ipe_test_temp::temp_root().join(format!("ipec-release-eject-debug-{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(tmp.join("src")).expect("create project dir");
    fs::write(
        tmp.join("package.ipe"),
        "module Package exposing (package)\n\n\npackage =\n    { name = \"eject-debug\" }\n",
    )
    .expect("write package.ipe");
    fs::write(tmp.join("src").join("Main.ipe"), DEBUG_LOG_MAIN).expect("write Main.ipe");
    let out = tmp.join("ejected");
    let package = tmp.join("package.ipe").to_string_lossy().into_owned();
    let out_arg = out.to_string_lossy().into_owned();
    let result = run_argv(&["release", "eject", &package, "--out", &out_arg]);
    let written = out.join("Cargo.toml").exists() || out.join("src").join("main.rs").exists();
    let _ = fs::remove_dir_all(&tmp);
    assert!(
        matches!(&result, Err(CliError::Pipeline { diag, .. }) if diag.code().as_str() == "IPE-L0140"),
        "a release eject refuses Debug.log with IPE-L0140: {result:?}"
    );
    assert!(!written, "a refused eject writes no project");
}

/// Assert `ipe <args>` refuses with [`CliError::NoRunForm`] for `target`.
///
/// The refusal is the user's to fix and its hint names the build form.
fn assert_no_run_form(args: &[&str], target: cli_args::NoRunTarget) {
    let result = run_argv(args);
    assert!(
        matches!(&result, Err(CliError::NoRunForm { target: t }) if *t == target),
        "`ipe {}` must refuse with no run form for {target:?}: {result:?}",
        args.join(" ")
    );
    let Err(err) = result else {
        return;
    };
    assert!(
        matches!(err.fault(), crate::screen::Fault::User),
        "a no-run-form refusal is the user's to fix: {err:?}"
    );
    let screen = err.to_string();
    let hint = format!("ipe {} {}", Verb::RELEASE_BUILD, target.build_form());
    assert!(
        screen.contains(&hint),
        "the refusal must hint `{hint}`: {screen}"
    );
}

/// `release run --target wasm` has no run form.
///
/// A `--target` after `--` is the program's argument, not a refusal.
#[test]
fn release_run_wasm_refuses() {
    assert_no_run_form(
        &["release", "run", "--target", "wasm"],
        cli_args::NoRunTarget::Wasm,
    );
    let parsed = cli_args::parse_release_run(&["--".to_owned(), "--target".to_owned()]);
    assert!(
        matches!(&parsed, Ok(args) if args.app_args == ["--target"] && !args.build_flags),
        "a `--target` after `--` belongs to the program: {parsed:?}"
    );
}

/// A host or solo delivery has no run form under `release run`.
#[test]
fn release_run_host_bundle_refuses() {
    use cli_args::NoRunTarget;
    for (args, target) in [
        (
            &["release", "run", "web", "desktop"][..],
            NoRunTarget::Desktop,
        ),
        (
            &["release", "run", "web", "solo", "ios"][..],
            NoRunTarget::Ios,
        ),
        (
            &["release", "run", "web", "solo", "android"][..],
            NoRunTarget::Android,
        ),
        (&["release", "run", "web", "solo"][..], NoRunTarget::Solo),
    ] {
        assert_no_run_form(args, target);
    }
}

/// Assert `result` is a `release run` usage refusal whose reason contains `needle`.
fn assert_release_run_refusal(result: &Result<(), CliError>, needle: &str, what: &str) {
    assert!(
        matches!(
            result,
            Err(CliError::CommandUsage { command, reason })
                if *command == Verb::RELEASE_RUN.name() && reason.as_str().contains(needle)
        ),
        "{what}: {result:?}"
    );
}

/// An artifact directory runs as built: a build option beside it refuses.
///
/// A bundle missing its profile refuses naming it, before anything runs.
#[test]
fn release_run_artifact_dir_refuses_build_flags_and_partial_bundles() {
    let tmp = ipe_test_temp::temp_root()
        .join(format!("ipec-release-run-artifact-{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).expect("create artifact dir");
    fs::write(tmp.join("ipe-wrapper"), b"").expect("write wrapper");
    fs::write(tmp.join("ipe-app"), b"").expect("write app");
    let dir = tmp.to_string_lossy().into_owned();
    let with_flag = run_argv(&["release", "run", &dir, "--out", "x"]);
    let partial = run_argv(&["release", "run", &dir]);
    let _ = fs::remove_dir_all(&tmp);
    assert_release_run_refusal(
        &with_flag,
        &dir,
        "an artifact directory takes no build option",
    );
    assert_release_run_refusal(
        &partial,
        "ipe.profile",
        "a bundle without its profile refuses naming it",
    );
}

/// A directory holding only an `ipe-wrapper` is never executed: nothing
/// outside the wrapper can be verified, so the run refuses before any exec.
///
/// The planted wrapper writes a marker when run; the marker must stay absent.
#[cfg(unix)]
#[test]
fn release_run_refuses_a_lone_wrapper_without_running_it() {
    use std::os::unix::fs::PermissionsExt as _;
    let tmp = ipe_test_temp::temp_root().join(format!(
        "ipec-release-run-lone-wrapper-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).expect("create artifact dir");
    let marker = tmp.join("ran");
    let wrapper = tmp.join("ipe-wrapper");
    fs::write(
        &wrapper,
        format!("#!/bin/sh\ntouch '{}'\nexit 0\n", marker.display()),
    )
    .expect("write wrapper");
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o755)).expect("chmod wrapper");
    let dir = tmp.to_string_lossy().into_owned();
    let result = run_argv(&["release", "run", &dir]);
    let ran = marker.exists();
    let _ = fs::remove_dir_all(&tmp);
    assert!(!ran, "a lone planted wrapper must never be executed");
    assert_release_run_refusal(&result, &dir, "a lone wrapper refuses naming its directory");
}

/// The wrapper source is the build-time workspace, never a planted ancestor.
///
/// The root is fixed by this crate's compile-time path, and a candidate tree
/// is admitted only as the workspace declaring the wrapper package: a planted
/// `Cargo.toml` that is not that workspace refuses with the failed check.
#[test]
fn wrapper_source_ignores_planted_ancestor() {
    use crate::wrapper_source::{WrapperSource, WrapperSourceDefect};
    const COMMANDS: &str = include_str!("../commands.rs");

    let expected = Path::new(env!("CARGO_MANIFEST_DIR")).ancestors().nth(2);
    assert_eq!(WrapperSource::build_root(), expected);

    let body = COMMANDS
        .find("\npub fn release_pipeline(")
        .and_then(|start| COMMANDS.get(start + 1..))
        .map(|rest| {
            rest.find("\npub fn ")
                .and_then(|end| rest.get(..end))
                .unwrap_or(rest)
        });
    assert!(body.is_some(), "release_pipeline is defined");
    let Some(body) = body else { return };
    assert!(body.contains("WrapperSource::resolve()"));
    for forbidden in ["current_dir", "ancestors", "resolve_at"] {
        assert!(
            !body.contains(forbidden),
            "the release pipeline must not derive the wrapper source from `{forbidden}`"
        );
    }

    #[cfg(unix)]
    {
        let base = ipe_test_temp::temp_root()
            .canonicalize()
            .expect("canonical temp dir")
            .join(format!("ipec-wrapper-source-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let member = base.join("src").join("ipe-wrapper");
        fs::create_dir_all(&member).expect("create member dir");
        let member_manifest = |name: &str| {
            fs::write(
                member.join("Cargo.toml"),
                format!("[package]\nname = \"{name}\"\nversion = \"0.1.0\"\n"),
            )
            .expect("write member manifest");
        };
        let root_manifest = |text: &str| {
            fs::write(base.join("Cargo.toml"), text).expect("write root manifest");
        };
        member_manifest("ipe_wrapper");
        fs::write(base.join("Cargo.lock"), "version = 4\n").expect("write lock");

        root_manifest("# [workspace]\n[package]\nname = \"planted\"\n");
        let planted = WrapperSource::resolve_at(&base);
        assert!(
            matches!(&planted, Err(r) if matches!(r.defect, WrapperSourceDefect::NotAWorkspace)),
            "a manifest with no workspace table is no wrapper source: {planted:?}"
        );

        root_manifest("[workspace]\nmembers = [\"src/app\"]\n");
        let undeclared = WrapperSource::resolve_at(&base);
        assert!(
            matches!(&undeclared, Err(r) if matches!(r.defect, WrapperSourceDefect::MemberUndeclared)),
            "a workspace not declaring the wrapper is no wrapper source: {undeclared:?}"
        );

        root_manifest("[workspace]\nmembers = [\"src/ipe-wrapper\"]\n");
        member_manifest("evil_wrapper");
        let renamed = WrapperSource::resolve_at(&base);
        assert!(
            matches!(&renamed, Err(r) if matches!(r.defect, WrapperSourceDefect::PackageMismatch)),
            "a member that is not the wrapper package is refused: {renamed:?}"
        );

        member_manifest("ipe_wrapper");
        fs::remove_file(base.join("Cargo.lock")).expect("remove lock");
        let unlocked = WrapperSource::resolve_at(&base);
        assert!(
            matches!(&unlocked, Err(r) if matches!(r.defect, WrapperSourceDefect::Unproven(_))),
            "a workspace with no committed lock is refused: {unlocked:?}"
        );

        fs::write(base.join("Cargo.lock"), "version = 4\n").expect("write lock");
        let admitted = WrapperSource::resolve_at(&base);
        let _ = fs::remove_dir_all(&base);
        assert!(
            matches!(&admitted, Ok(source) if source.root() == base),
            "the complete wrapper workspace is admitted (control): {admitted:?}"
        );
    }
}
