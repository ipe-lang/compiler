#![forbid(unsafe_code)]
//! Refuses a fixed-name `temp_dir()` output path anywhere in the e2e test
//! tree: two gates building from different `CARGO_TARGET_DIR` pools share the
//! process-wide `/tmp`, so a fixed name there lets one gate's build clobber
//! another's. Every e2e test must root its output under the per-binary
//! `CARGO_TARGET_TMPDIR` instead, via `crate::support::scratch_root()` (test
//! binaries that carry `mod support;`) or an inline
//! `env!("CARGO_TARGET_TMPDIR")` (those that do not).

/// Paths (relative to `tests/`) allowed to contain the literal `temp_dir()`
/// text without being a live call: `support/mod.rs`'s own doc comment
/// describes the design this scan enforces, and this scan test's own source
/// names the banned literal in its doc comment, allow-list, and message.
const ALLOWED_SUFFIXES: &[&str] = &["support/mod.rs", "e2e_scratch_dir_scan.rs"];

#[test]
fn no_fixed_temp_dir_in_e2e_tests() {
    let tests_dir = e2e_support::manifest_dir!().join("tests");
    let files = panic_scan::rust_sources(&tests_dir, panic_scan::Want::RustFiles)
        .expect("the e2e test tree is listed whole");

    let mut offenders = Vec::new();
    for path in files {
        let rel = path
            .strip_prefix(&tests_dir)
            .expect("a listed file lies under its root")
            .to_string_lossy()
            .replace('\\', "/");
        if ALLOWED_SUFFIXES.iter().any(|s| rel.ends_with(s)) {
            continue;
        }
        let text = std::fs::read_to_string(&path)
            .map_err(|error| format!("{}: {error}", path.display()))
            .expect("every listed test source is readable");
        if text.contains("temp_dir()") {
            offenders.push(rel);
        }
    }

    assert!(
        offenders.is_empty(),
        "fixed-name temp_dir() found in e2e tests (use crate::support::scratch_root() \
         or env!(\"CARGO_TARGET_TMPDIR\") instead): {offenders:?}"
    );
}
