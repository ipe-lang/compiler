#![forbid(unsafe_code)]
//! Refuses a fixed-name `temp_dir()` output path anywhere in the e2e test
//! tree: two gates building from different `CARGO_TARGET_DIR` pools share the
//! process-wide `/tmp`, so a fixed name there lets one gate's build clobber
//! another's. Every e2e test must root its output under the per-binary
//! `CARGO_TARGET_TMPDIR` instead, via `crate::support::scratch_root()` (test
//! binaries that carry `mod support;`) or an inline
//! `env!("CARGO_TARGET_TMPDIR")` (those that do not).

use std::path::{Path, PathBuf};

/// Paths (relative to `tests/`) allowed to contain the literal `temp_dir()`
/// text without being a live call: `support/mod.rs`'s own doc comment
/// describes the design this scan enforces, and this scan test's own source
/// names the banned literal in its doc comment, allow-list, and message.
const ALLOWED_SUFFIXES: &[&str] = &["support/mod.rs", "e2e_scratch_dir_scan.rs"];

/// Recursively collect every `.rs` file under `dir` into `out`.
fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn no_fixed_temp_dir_in_e2e_tests() {
    let tests_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut files = Vec::new();
    collect_rs_files(&tests_dir, &mut files);

    let mut offenders = Vec::new();
    for path in files {
        let rel = path
            .strip_prefix(&tests_dir)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        if ALLOWED_SUFFIXES.iter().any(|s| rel.ends_with(s)) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
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
