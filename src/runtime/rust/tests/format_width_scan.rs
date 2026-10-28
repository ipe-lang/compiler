//! Format-width scan: no runtime production code formats with a width or
//! precision a run-time value decides.
//!
//! The formatter takes a `{:w$}` width or `{:.p$}` precision as a `u16`, so a
//! value past 65535 panics it in release builds too. A width an input decides
//! is written through `repeat` instead (`db::migration_status_line`). The scan
//! rules live in `support/format_width.rs`, shared with the `ipe` crate's scan.
#![cfg(not(target_arch = "wasm32"))]

#[path = "support/cfg_scan.rs"]
mod cfg_scan;

#[path = "support/source_tree.rs"]
mod source_tree;
use source_tree::rust_sources;

#[path = "support/format_width.rs"]
mod format_width;
use format_width::{runtime_widths, width_arguments};

// ---------------------------------------------------------------------------
// Refusals: each shape the scan must catch or must not be blinded by.
// ---------------------------------------------------------------------------

#[test]
fn a_width_a_local_decides_is_caught() {
    let src = r#"
fn production(n: usize, name: &str) -> String {
    format!("  {name:<n$}  done")
}
"#;
    assert_eq!(runtime_widths("fixture", src), vec!["n"]);
}

#[test]
fn a_named_argument_bound_to_a_local_is_caught() {
    let src = r#"
fn production(f: &mut Formatter, n: usize) {
    let _ = write!(f, "{:0width$x}", 1, width = n);
}
"#;
    assert_eq!(runtime_widths("fixture", src), vec!["width"]);
}

#[test]
fn a_positional_width_and_a_precision_are_caught() {
    let src = r#"
fn production(n: usize, p: usize) -> String {
    format!("{:>1$} {:.p$}", "a", n, 1.5)
}
"#;
    assert_eq!(runtime_widths("fixture", src), vec!["1", "p"]);
}

#[test]
fn a_width_inside_a_nested_macro_group_is_caught() {
    let src = r#"
fn production(w: usize) -> Vec<String> {
    vec![format!("{:w$}", "")]
}
"#;
    assert_eq!(runtime_widths("fixture", src), vec!["w"]);
}

#[test]
fn literal_and_const_widths_are_admitted() {
    let src = r#"
const WIDTH: usize = 8;
fn production() -> String {
    let a = format!("{:<5}|{:>WIDTH$}|{:.3}", 1, 2, 3.0);
    let b = format!("{:0width$x}", 1u128, width = store::SESSION_ID_LEN);
    let c = format!("{:w$}", 1, w = 8);
    let d = format!("{{:w$}} is not a placeholder");
    a + &b + &c + &d
}
"#;
    assert_eq!(runtime_widths("fixture", src), Vec::<String>::new());
}

#[test]
fn a_cfg_test_module_is_dropped_and_production_after_it_is_scanned() {
    let src = r#"
#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    fn t(k: usize) -> String { format!("{:0k$}", 1) }
}

fn production(k: usize) -> String { format!("{:0k$}", 1) }
"#;
    assert_eq!(runtime_widths("fixture", src), vec!["k"]);
}

#[test]
fn placeholders_are_read_the_way_the_formatter_reads_them() {
    assert_eq!(width_arguments("{:$>w$}"), vec!["w"]);
    assert_eq!(width_arguments("{x:0w$.p$}"), vec!["w", "p"]);
    assert_eq!(width_arguments("{:05$}"), vec!["05"]);
    assert_eq!(width_arguments("{:wé$}"), vec!["wé"]);
    assert_eq!(width_arguments("{{:w$}} {:<8}"), Vec::<String>::new());
    assert_eq!(width_arguments("${x} {y}"), Vec::<String>::new());
}

#[test]
#[should_panic(expected = "does not parse as Rust")]
fn a_source_that_does_not_parse_fails_the_scan() {
    let _ = runtime_widths("fixture", "fn production( { format!(\"{:w$}\", 1); }");
}

// ---------------------------------------------------------------------------
// The scan over the whole runtime source tree.
// ---------------------------------------------------------------------------

/// Every source file under `src/` formats with no width or precision a
/// run-time value decides, outside test-only code.
#[test]
fn no_runtime_source_formats_with_a_run_time_width() {
    let root = e2e_support::manifest_dir!().join("src");
    let sources = rust_sources(&root);
    for required in ["db.rs", "web/mod.rs", "retained.rs", "system.rs"] {
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
