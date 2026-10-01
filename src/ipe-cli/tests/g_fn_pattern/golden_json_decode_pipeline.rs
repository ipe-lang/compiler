//! A Json.Decode pipeline whose accumulator value is
//! itself a function (`Decoder (a -> b)` curry chain) exercises the OWNED /
//! linear decoder-payload path.
//!
//! Without the fix, `ipe build` exits 0, but the emitted Rust fails `cargo build`. The
//! backend's `IrType::Fun` renderer stamped `Box<dyn Fn(..) -> R + Send + Sync>`
//! on the decoder payload, but the runtime represents a `Decoder (a -> b)`
//! payload as a Send-ONLY curry chain `Box<dyn FnOnce(a) -> b + Send>` (exactly
//! what the `curryN` helpers build and what `decode_succeed`'s `A` is inferred
//! to — see `src/runtime/rust/src/json.rs`). Two mismatches fired: the wrong
//! trait (`Fn` vs `FnOnce`) AND an over-constrained `+ Sync` (a `FnOnce` curry
//! chain is `Send` but NOT `Sync`) → ipe-0-then-cargo-fail (E0308 / E0277).
//!
//! Fix (`crates/ipe_backend_rust/src/emit_types.rs`): a function-typed `Decoder`
//! payload renders as the `FnOnceChain` shape the runtime uses
//! (`Box<dyn FnOnce(..) -> _ + Send>`, Send-only, never `+ Sync`) — a decoder
//! payload is owned/linear and never flows into an
//! `Arc<dyn Fn + Send + Sync>` callback slot. The `+ Sync` shared-callback
//! rendering is kept for the callback-param positions that need it (that path is
//! guarded by `golden_i190_static_bound` / `golden_i191_input_arc_capture`).
//!
//! Run:
//! ```text
//! IPE_E2E=1 cargo test -p ipe --test golden_i195_json_decode_pipeline
//! ```

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn entry_path(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("json_decode_pipeline")
        .join("Main.ipe")
}

/// ipe-0: the compiler must accept the program AND render the function-typed
/// `Decoder` payload as the runtime's Send-only `FnOnce` curry chain — checked
/// unconditionally (cheap, no `cargo`), independent of the `IPE_E2E` gate. This
/// is the exact assertion the E0308/E0277 SEAL break cannot recur: the partial
/// decoder's payload must be `Box<dyn FnOnce(..) -> _ + Send>` (never a
/// `+ Sync`-stamped `Box<dyn Fn>`).
#[test]
fn i195_ipec_accepts_and_renders_send_only_fnonce_payload() {
    let root = repo_root();
    let entry = entry_path(&root);
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("i195_json_decode_pipeline_ipec_out");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build_loose_file(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for json_decode_pipeline: {:?}",
        built.err()
    );

    let emitted = std::fs::read_to_string(out.join("src").join("main.rs"))
        .expect("emitted main.rs must exist");

    // The annotated partial decoder's function-typed payload must render as the
    // runtime's Send-only `FnOnce` curry chain — never the shared-callback
    // `Box<dyn Fn + Send + Sync>` form (the unfixed shape that E0308/E0277'd).
    //
    // Match on the innermost curry-chain fragment rather than spanning the
    // whole `Decoder<Box<...>>` return type in one substring: rustfmt wraps
    // that outer generic nesting across several indented lines once it
    // exceeds the line-width limit, so a substring spanning `Decoder<Box<dyn
    // FnOnce...` is a stale assertion the moment the wrap point shifts (same
    // stale-substring class as #269/#191). The inner `dyn FnOnce(..) -> ... +
    // Send + 'static>` leaf stays on one line and is the exact span that
    // flips between the fixed/unfixed shapes.
    assert!(
        emitted.contains("pub fn main_partial_txn_decoder() -> Decoder<")
            && emitted.contains(
                "dyn FnOnce(String) -> Box<dyn FnOnce(String) -> RecAccountAmountId + Send + 'static>"
            ),
        "the `Decoder (a -> b)` payload must render as a Send-only `Box<dyn FnOnce>` \
         curry chain (#195); got main.rs:\n{emitted}"
    );
    // Guard against the unfixed shape: the curry-chain leaf must NOT be a
    // `+ Sync`-stamped `Box<dyn Fn>` (the runtime `curryN` output is `FnOnce`,
    // Send-only, so `Fn + Send + Sync` mismatches on both trait and auto-trait).
    assert!(
        !emitted.contains(
            "dyn Fn(String) -> Box<dyn FnOnce(String) -> RecAccountAmountId + Send + Sync"
        ),
        "the `Decoder (a -> b)` payload must NOT render as a `Box<dyn Fn + Send + Sync>` \
         (the #195 over-constrained shape); got main.rs:\n{emitted}"
    );
}

/// cargo-0 ∧ run-0: the emitted project actually compiles with `rustc` (no
/// E0308 / E0277 from the decoder-payload `+ Sync` mismatch) and prints the
/// decoded summary. Gated on `IPE_E2E=1` — the only check that would have caught
/// the original SEAL violation (ipe-0, cargo-fail).
#[test]
fn i195_cargo_builds_and_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let entry = entry_path(&root);
    let out = crate::support::scratch_root().join("ipec_i195_json_decode_pipeline_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build_loose_file(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for json_decode_pipeline: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("json_decode_pipeline", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "json_decode_pipeline binary must exit 0 (no E0308/E0277); got {:?} (stdout: {:?})",
        outcome.exit_code,
        outcome.stdout
    );
    // The full pipeline result: the finished `txnDecoder` account, the `map2`
    // label (`account:amount`), and the `andThen` bucket count.
    assert!(
        outcome.stdout.contains("acme acme:12.00 3"),
        "must render the decoded summary through the `Decoder (a -> b)` accumulator, \
         `map2`, and `andThen` chain; got: {:?}",
        outcome.stdout
    );
}
