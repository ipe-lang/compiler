#![forbid(unsafe_code)]
//! Format-width scan: no `ipe` production code formats with a width or
//! precision a run-time value decides.
//!
//! The formatter takes a `{:w$}` width or `{:.p$}` precision as a `u16`, so a
//! value past 65535 panics it in release builds too; a doc term from a
//! package's docs is one such value. A width an input decides is written
//! through `repeat` instead (`doc_pick::pad_right`). The scan rules live in
//! the runtime's `tests/support/format_width.rs`, which this scan shares.
#![cfg(not(target_arch = "wasm32"))]

#[path = "../../runtime/rust/tests/support/cfg_scan.rs"]
mod cfg_scan;

#[path = "../../runtime/rust/tests/support/source_tree.rs"]
mod source_tree;
use source_tree::rust_sources;

#[path = "../../runtime/rust/tests/support/format_width.rs"]
mod format_width;
use format_width::{runtime_widths, width_arguments};

#[test]
fn a_width_a_local_decides_is_caught() {
    let src = r#"
fn production(term_width: usize, term: &str) -> String {
    format!("{:<term_width$}", term)
}
"#;
    assert_eq!(runtime_widths("fixture", src), ["term_width"]);
    assert_eq!(width_arguments("{:>index_width$}"), ["index_width"]);
}

#[test]
fn a_const_width_is_admitted() {
    let src = r#"
fn production() -> String {
    format!("{:<COLUMN$}|{:>6}", "a", 1)
}
"#;
    assert_eq!(runtime_widths("fixture", src), Vec::<String>::new());
}

/// Every source file under `src/` formats with no width or precision a
/// run-time value decides, outside test-only code.
#[test]
fn no_cli_source_formats_with_a_run_time_width() {
    let root = e2e_support::manifest_dir!().join("src");
    let sources = rust_sources(&root);
    for required in ["doc_pick.rs", "help.rs", "main.rs"] {
        assert!(
            sources.iter().any(|(name, _)| name == required),
            "the source walk did not read {required}"
        );
    }
    let violations: Vec<String> = sources
        .iter()
        .flat_map(|(name, src)| {
            runtime_widths(name, src)
                .into_iter()
                .map(move |arg| format!("{name}: `{arg}$`"))
        })
        .collect();
    assert!(
        violations.is_empty(),
        "a run-time format width past 65535 panics the formatter; pad through \
         `repeat` instead:\n{}",
        violations.join("\n")
    );
}
