//! `Ipe.Json.Decode.nullable : Decoder a -> Decoder (Maybe a)` — the JSON
//! decoder surface gains the `nullable` combinator that previously lived only on
//! `Ipe.Config`. A JSON `null` decodes to `Nothing`; any other value decodes to
//! `Just` of the inner decode; an inner failure on a present (non-null) value
//! PROPAGATES rather than being swallowed, so a required-but-malformed field can
//! never silently become `Nothing`.
//!
//! The kernel reuses the shared `config_nullable` runtime builder over the
//! unified `Decoder` carrier, so there is one runtime impl behind `JsonDec`,
//! `Config`, and `Db.Decode`.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn entry_path(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("json_decode_nullable")
        .join("Main.ipe")
}

/// ipe-0: the compiler accepts `Json.Decode.nullable` and emits it as the shared
/// `config_nullable` runtime call. Checked unconditionally (no `cargo`), so the
/// acceptance-and-emit path stands even without the E2E gate.
#[test]
fn json_decode_nullable_ipec_accepts_and_emits_shared_builder() {
    let root = repo_root();
    let entry = entry_path(&root);
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("json_decode_nullable_ipec_out");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build_loose_file(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe dev build must accept Json.Decode.nullable: {:?}",
        built.err()
    );

    let emitted = std::fs::read_to_string(out.join("src").join("main.rs"))
        .expect("emitted main.rs must exist");

    // The combinator lowers to the shared `decode_nullable` runtime builder in
    // the always-available `json` module — one impl behind every decoder family,
    // never a bespoke JsonDec-only fn, and never behind the `config` feature.
    assert!(
        emitted.contains("decode_nullable("),
        "Json.Decode.nullable must emit the shared `decode_nullable` builder; got main.rs:\n{emitted}"
    );
}

/// cargo-0 ∧ run-0: the emitted project compiles and prints the three decoded
/// paths — `Just` on a present value, `Nothing` on `null`, and a PROPAGATED
/// error on a present-but-malformed value (never swallowed). Gated on `IPE_E2E`.
#[test]
fn json_decode_nullable_cargo_builds_and_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let entry = entry_path(&root);
    let out = crate::support::scratch_root().join("ipec_json_decode_nullable_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build_loose_file(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe dev build must succeed for json_decode_nullable: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("json_decode_nullable", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "json_decode_nullable binary must exit 0; got {:?} (stdout: {:?})",
        outcome.exit_code,
        outcome.stdout
    );
    assert!(
        outcome.stdout.contains("Just ada | Nothing | propagated"),
        "nullable must decode present⇒Just, null⇒Nothing, and PROPAGATE an inner \
         failure on a present value; got: {:?}",
        outcome.stdout
    );
}
