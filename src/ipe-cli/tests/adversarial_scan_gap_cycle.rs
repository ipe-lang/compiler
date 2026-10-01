//! Adversarial probe against the claim that
//! "the driver's topological sort rejects cycles (IPE-N0021) before any
//! `canonicalize` demand, so the production path never recurses into a
//! cycle". That claim rests on `extract_imports_from_source` (a pre-parse
//! STRING SCAN requiring a literal `"import "` prefix) seeing every edge the
//! parser's AST sees. The lexer, however, skips tabs and nestable block
//! comments between `import` and the module name — `import\tB` and
//! `import {- c -} B` are lexer-legal but scan-INVISIBLE.
//!
//! A scan-invisible edge that completes an import CYCLE therefore bypasses
//! the driver's IPE-N0021 gate, and the `canonicalize` query recurses into
//! the cycle on the PRODUCTION build path. The cycle must surface as a
//! diagnostic (as it did pre-salsa via the accumulated-map N0020 miss), never
//! as a compiler panic.

use std::fs;

// Deliberate: this test re-panics with a diagnostic message when it catches an
// unexpected driver panic — that IS the test's failure-reporting mechanism
// (the finding this file exists to pin), not production code.
#[allow(clippy::panic)]
#[test]
fn scan_invisible_cycle_must_not_panic_the_driver() {
    let runtime = e2e_support::require_runtime().into_path_buf();

    let tmp =
        std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ipec_review_scan_gap_cycle");
    let src = tmp.join("src");
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&src).expect("create src dir");

    // A → B via a TAB after `import`: the lexer's whitespace skip accepts it,
    // `extract_imports_from_source` (strip_prefix("import ")) does not.
    fs::write(
        src.join("A.ipe"),
        "module A exposing (a)\n\nimport\tB\n\na = 1\n",
    )
    .expect("write A");
    // B → A via a normal import: scan-visible.
    fs::write(
        src.join("B.ipe"),
        "module B exposing (b)\n\nimport A\n\nb = 2\n",
    )
    .expect("write B");

    let out = tmp.join("out");
    let entry = src.join("A.ipe");
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        ipe::build_loose_file(&entry, &out, &runtime)
    }));

    match result {
        Ok(build_result) => {
            assert!(
                build_result.is_err(),
                "an import cycle must be rejected with a diagnostic"
            );
        }
        Err(panic_payload) => {
            let msg = panic_payload
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| panic_payload.downcast_ref::<&str>().copied())
                .unwrap_or("<non-string panic payload>");
            panic!(
                "FINDING: the production driver PANICKED on a scan-invisible \
                 import cycle (IPE-N0021 gate bypassed, salsa cycle unwind \
                 reached the user): {msg}"
            );
        }
    }
}
