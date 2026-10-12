//! A decode-combinator mapper lambda whose PARAMETER
//! is a function-typed decoder payload (`Decoder (a -> b)`) and whose body
//! INVOKES that payload.
//!
//! A deeper surface of the same root cause as the `Decoder<T>`-type case. The
//! `Decoder (a -> b)` payload renders as the runtime's owned, Send-only curry
//! chain `Box<dyn FnOnce(a) -> b + Send>` at the `Decoder<T>` TYPE position (the
//! PRODUCER side — `emit_types::render_type`'s `Decoder(Fun)` arm). But when
//! that payload flows OUT of the decoder into a mapper's parameter —
//! `JsonDec.map (\f -> f x) d`, `JsonDec.andThen (\f -> succeed (f x)) d` — the
//! parameter's inferred type is a bare `Ty::Fun`, so `lower_lambda` stamps it
//! as `IrType::Fun`, which `render_type` emits as the SHARED callback form
//! `Box<dyn Fn(a) -> b + Send + Sync>`. The producer supplies `FnOnce + Send`;
//! the consumer's param expected `Fn + Send + Sync` → wrong trait (`Fn` vs
//! `FnOnce`) AND an unsatisfiable `+ Sync` → ipe-0-then-cargo-fail
//! (E0308 / E0277).
//!
//! Fix (`crates/ipe_lower/src/lower.rs`, `retype_decoder_payload_mapper`): at
//! the decode-combinator (`map` / `map2` / `map3` / `map4` / `andThen`, Json +
//! Db) call site — where the mapper's parameters ARE, by construction, the
//! decoded payload value(s) — retype any single-parameter function-typed mapper
//! param from `IrType::Fun` to the owned `IrType::FnOnceChain`, so it renders as
//! the same `Box<dyn FnOnce(..) -> _ + Send>` shape the producer supplies. The
//! same owned-fn-value-vs-shared-callback classification, applied at the
//! lambda-PARAM emission site rather than the `Decoder<T>` type site.
//!
//! Run:
//! ```text
//! IPE_E2E=1 cargo test -p ipe --test golden_i198_decoder_payload_mapper
//! ```

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn entry_path(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("decoder_payload_mapper")
        .join("Main.ipe")
}

/// ipe-0: the compiler must accept the program AND render the mapper lambda's
/// function-typed payload parameter as the runtime's Send-only `FnOnce` chain —
/// checked unconditionally (cheap, no `cargo`), independent of the `IPE_E2E`
/// gate. This is the exact assertion the E0308/E0277 SEAL break cannot recur:
/// the `\f -> f 10` mapper param must be `Box<dyn FnOnce(i64) -> i64 + Send>`
/// (never a `+ Sync`-stamped `Box<dyn Fn>`).
#[test]
fn i198_ipec_accepts_and_renders_send_only_fnonce_param() {
    let root = repo_root();
    let entry = entry_path(&root);
    let out =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("i198_decoder_payload_mapper_ipec_out");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build_loose_file(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe dev build must succeed for decoder_payload_mapper: {:?}",
        built.err()
    );

    let emitted = std::fs::read_to_string(out.join("src").join("main.rs"))
        .expect("emitted main.rs must exist");

    // The mapper lambda's function-typed payload parameter must render as the
    // runtime's Send-only `FnOnce` chain — the same shape the `Decoder<Fun>`
    // producer (`decode_succeed(curry1(..))`) supplies.
    assert!(
        emitted.contains("move |f: Box<dyn FnOnce(i64) -> i64 + Send + 'static>|"),
        "the decode-mapper payload param must render as a Send-only \
         `Box<dyn FnOnce(i64) -> i64 + Send>` (#198); got main.rs:\n{emitted}"
    );
    // Guard against the unfixed shape: the payload param must NOT be a
    // `+ Sync`-stamped `Box<dyn Fn>` (the shared-callback rendering that
    // mismatched the producer's `FnOnce + Send` on both trait and auto-trait).
    assert!(
        !emitted.contains("move |f: Box<dyn Fn(i64) -> i64 + Send + Sync + 'static>|"),
        "the decode-mapper payload param must NOT render as a \
         `Box<dyn Fn + Send + Sync>` (the pre-#198 over-constrained shape); \
         got main.rs:\n{emitted}"
    );
}

/// cargo-0 ∧ run-0: the emitted project actually compiles with `rustc` (no
/// E0308 / E0277 from the payload-param `Fn`/`FnOnce` + `Sync` mismatch) and
/// prints the decoded result. Gated on `IPE_E2E=1` — the only check that would
/// have caught the original SEAL violation (ipe-0, cargo-fail).
#[test]
fn i198_cargo_builds_and_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let entry = entry_path(&root);
    let out = crate::support::scratch_root().join("ipec_i198_decoder_payload_mapper_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build_loose_file(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe dev build must succeed for decoder_payload_mapper: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("decoder_payload_mapper", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "decoder_payload_mapper binary must exit 0 (no E0308/E0277); got {:?} (stdout: {:?})",
        outcome.exit_code,
        outcome.stdout
    );
    // `appliedDecoder` = `map (\f -> f 10) (succeed (addN 5))` = `5 + 10` = 15;
    // `appliedViaAndThen` = `andThen (\f -> succeed (f 100)) …` = `5 + 100` = 105.
    assert!(
        outcome.stdout.contains("15 105"),
        "must render the payload invoked through both the `map` and `andThen` \
         mappers; got: {:?}",
        outcome.stdout
    );
}
