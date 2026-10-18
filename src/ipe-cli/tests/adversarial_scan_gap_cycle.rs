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
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).expect("create scratch dir");

    // A project whose one program starts at `A`.
    let tree = ipe::project_root::SourceTree::new()
        .field("programs = [ { name = \"a\", entry = \"A.ipe\" } ]")
        // A → B via a TAB after `import`: the lexer's whitespace skip accepts it,
        // `extract_imports_from_source` (strip_prefix("import ")) does not.
        .module("A", "module A exposing (a)\n\nimport\tB\n\na = 1\n")
        // B → A via a normal import: scan-visible.
        .module("B", "module B exposing (b)\n\nimport A\n\nb = 2\n");
    let fixture = ipe::RootFixture::from_tree(&tree).expect("write and resolve the fixture");

    let out = tmp.join("out");
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        ipe::build_fixture(&fixture, &out, &runtime)
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
