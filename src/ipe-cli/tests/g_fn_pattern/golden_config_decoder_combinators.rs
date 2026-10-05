//! The `Ipe.Config` decoder combinators are CALLABLE from user code and
//! complete the SEAL.
//!
//! A JSON document is decoded through `map2` + `oneOf` + `index` (a record),
//! `maybe` + `keyValuePairs`, and `dict`
//! (`tests/golden/config_decoder_combinators/Main.ipe`). This pins ipe-0 ∧
//! cargo-0 ∧ run-0 (THE SEAL: ipe exit 0 ⇒ emitted Rust builds and runs) and the
//! decoded values are rendered (`server: alpha:5432 tags=1 limits=1`), proving
//! each combinator routes to its runtime `decode_*` / `config_*`.
//!
//! Gated on `IPE_E2E=1`. Run:
//! `IPE_E2E=1 cargo test -p ipe --test golden_config_decoder_combinators`.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

#[test]
fn config_decoder_combinators_ipec_cargo_and_run_zero() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let dir = root
        .join("tests")
        .join("golden")
        .join("config_decoder_combinators");
    let entry = dir.join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_config_decoder_combinators_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    // ipe-0: compiling a program that calls the decoder combinators must succeed.
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe dev build must succeed for config_decoder_combinators: {:?}",
        built.err()
    );

    // cargo-0 ∧ run-0: the binary builds, decodes the document, exits 0.
    let outcome = crate::support::build_and_run_emitted("config_decoder_combinators", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "config_decoder_combinators binary must exit 0 on stdin EOF; got {:?}",
        outcome.exit_code
    );
    assert!(
        outcome
            .stdout
            .contains("server: alpha:5432 tags=1 limits=1"),
        "the decoded values must render (map2/oneOf/index/maybe/keyValuePairs/dict); got: {:?}",
        outcome.stdout
    );
}
