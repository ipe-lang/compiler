//! Decoder thunk coverage: tuple-destructure + record-field binders.
//!
//! Thunk-wrapping only `PVar` Decoder bindings leaves every other
//! binding-pattern shape (`PTuple`, `PRecord`, `PAlias` over either) falling
//! through to a plain `Expr::Destructure` with NO Decoder-awareness, so a
//! reused Decoder-typed component double-moves at `cargo build` (ipe exit
//! 0, cargo exit 101 — the exit-0-then-cargo-fail seal class). So (spec §2.2)
//! the WHOLE destructure value is wrapped in a zero-arg thunk and
//! every free read of every bound name rewritten to a fresh, masked
//! re-destructure of a thunk call: `{ let (d1, _) = (destr_thunk_N)(); d1 }`.
//!
//! Without the thunk, all three fixtures are ipe-0 and cargo-101 with EXACTLY
//! this rustc error:
//!
//! ```text
//! error[E0382]: use of moved value: `nameDecoder`
//!    --> src/main.rs:242:183
//!     |
//! 242 | ...t (nameDecoder, ageDecoder) = main_build_pair(()); ({ let r1 =
//!       decode_from_json_string(nameDecoder, "{\"name\":\"Alice\"}".to_string()); …
//!     |       ----------- value moved here                     ^^^^^^^^^^^ value used here after move
//!     |       move occurs because `nameDecoder` has type
//!       `json::Decoder<IpeError, std::string::String>`, which does not implement the `Copy` trait
//! ```
//!
//! (Without the thunk, the record fixture's error names the same binder moved
//! out of the record struct's `let Rec { nameDecoder, .. } = …;`; the case
//! fixture's names the single-arm `case`'s tuple binder — identical E0382 class.)
//!
//! Spec: `docs/adr/0002-codegen-soundness-and-the-seal.md` §2.
//!
//! Run: `IPE_E2E=1 cargo test -p ipe --test golden_i125_decoder_destructure_thunk`

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn golden_dir(root: &Path, name: &str) -> PathBuf {
    root.join("tests").join("golden").join(name)
}

/// Cheap tier: ipe must accept the fixture (exit 0). Always runs.
fn assert_ipec_ok(name: &str) -> PathBuf {
    let root = repo_root();
    let entry = golden_dir(&root, name).join("Main.ipe");
    let out = crate::support::scratch_root().join(format!("ipec_{name}_e2e"));
    let _ = std::fs::remove_dir_all(&out);
    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve: {:?}", runtime.err());
    let Ok(runtime) = runtime else { return out };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "#125: {name} must be ipe-0: {:?}",
        built.err()
    );
    out
}

/// `IPE_E2E` tier: the emitted project must cargo-build (no
/// E0382 like the one recorded above) AND run printing `Alice|Bob`
/// (proving the reused Decoder component decodes BOTH payloads correctly —
/// not just "compiles").
fn assert_e2e_output(name: &str) {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }
    let out = assert_ipec_ok(name);
    let outcome = crate::support::build_and_run_emitted(name, &out);
    assert_eq!(outcome.exit_code, Some(0), "{name} must run clean");
    assert_eq!(
        outcome.stdout.trim(),
        "Alice|Bob",
        "{name}: the reused decoder must decode both JSON payloads"
    );
}

/// `let (nameDecoder, ageDecoder) = buildPair ()` with `nameDecoder` reused
/// twice — `lower_let`'s destructure catch-all (§2.6, tuple binder).
#[test]
fn i125_decoder_tuple_destructure_reuse_compiles_and_runs() {
    let _ = assert_ipec_ok("decoder_tuple_destructure");
    assert_e2e_output("decoder_tuple_destructure");
}

/// `let { nameDecoder } = buildDecoders ()` with `nameDecoder` reused twice
/// — `lower_let`'s destructure catch-all (§2.6, record-field binder).
#[test]
fn i125_decoder_record_destructure_reuse_compiles_and_runs() {
    let _ = assert_ipec_ok("decoder_record_destructure");
    assert_e2e_output("decoder_record_destructure");
}

/// `case buildPair () of (nameDecoder, ageDecoder) -> …` with `nameDecoder`
/// reused twice inside the arm body — proves §2.6's `lower_case` single-arm
/// destructure wiring, not just `lower_let`'s.
#[test]
fn i125_decoder_case_destructure_reuse_compiles_and_runs() {
    let _ = assert_ipec_ok("decoder_case_destructure");
    assert_e2e_output("decoder_case_destructure");
}

/// Non-regression guard (§2.8, cheap tier): a destructure binding NO
/// Decoder-typed component must fall through UNCHANGED to the plain
/// `Expr::Destructure` path. Reuses the existing `let_destructure`
/// golden's `main.rs` byte-snapshot (`let (a, b) = (40, 2)` + a record
/// binder), asserting the emitted Rust is byte-identical to the checked-in
/// snapshot AND carries no thunk binder — proving the Decoder-free fast path
/// is untouched, not merely still-running.
#[test]
fn i125_non_decoder_destructure_fast_path_byte_identical() {
    let out = assert_ipec_ok("let_destructure");
    let root = repo_root();
    let golden_dir = golden_dir(&root, "let_destructure");
    // Seal half: the emitted source must carry no thunk binder. Read the emitted
    // `main.rs` directly for this `!contains` check — the directory-diff helper
    // below cannot express a substring assertion.
    let emitted = std::fs::read_to_string(out.join("src").join("main.rs")).unwrap_or_default();
    assert!(
        !emitted.contains("destr_thunk"),
        "#125 must not thunk a Decoder-free destructure"
    );
    // Byte-diff half: emitted `src/main.rs` must equal the checked-in
    // golden `main.rs` — routed through the shared directory-diff helper (which
    // compares `<out>/src/main.rs` against `<golden_dir>/main.rs`).
    crate::support::assert_emitted_project_matches_golden_dir(&out, &golden_dir);
}
