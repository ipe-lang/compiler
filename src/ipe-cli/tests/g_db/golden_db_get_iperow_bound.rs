//! `examples/27-multi-session-chat`'s `cargo build`.
//!
//! Without the fix, `ipe dev build` exits 0, but the emitted Rust fails `cargo build`
//! with E0277 (`the trait bound T1: IpeRow is not satisfied`) at every
//! `db_get_string("field".to_string(), &(payload))` call inside a function
//! whose only generic is the wildcard `any` PARAM (example 27's
//! `decodeChatMessage : any -> ChatMessage` / `init : any -> …`).
//!
//! Root cause: the runtime's field accessors are generic
//! `db_get_*<R: IpeRow>(field, &row)`, but the emitted enclosing function
//! carried an unbounded `<T1: Clone>` param, so its body's
//! `db_get_string(_, &payload)` could not prove `payload: IpeRow`.
//!
//! Fix (`crates/ipe_ir/src/ir.rs` + `crates/ipe_lower/src/lower.rs`): a new
//! `BoundSet::IPE_ROW` flag, rendered by `render_bounds` as
//! `ipe_runtime::db::IpeRow`. The lowerer decides the bound STRUCTURALLY, at
//! IR level (`apply_db_row_bounds` / `body_calls_db_get_on_param`): it fires
//! ONLY when the fn body contains an actual `Db.get*` KERNEL application whose
//! ROW argument is a `Var`/`CloneVar` reference to the wildcard `any` param
//! (interned with the `anyp_` prefix by the lowerer's `any_param_binders`
//! pool) — never a genuine named tvar, never the record STRUCT. The emitter
//! (`render_fn_generics`) just renders whatever `BoundSet` each param carries.
//! (This replaced an earlier body-TEXT-substring scan that false-positived on a
//! `"db_get_"` string literal / a `db_get_`-named user symbol — see
//! `golden_i177_db_get_false_positive`.) The record struct stays unbounded
//! (reusable in non-row contexts), mirroring `TypeEmitter.hs:166-177`.
//!
//! Run:
//! ```text
//! IPE_E2E=1 cargo test -p ipec --test golden_i177_db_get_iperow_bound
//! ```

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn entry_path(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("db_get_iperow_bound")
        .join("Main.ipe")
}

/// ipe-0: the compiler must accept the program AND emit `+ IpeRow` on the
/// wildcard-`any` decoder function's own generic while leaving the record
/// STRUCT unbounded — checked unconditionally (cheap, no `cargo`), independent
/// of the `IPE_E2E` gate below.
#[test]
fn i177_ipec_accepts_and_bounds_fn_not_struct() {
    let root = repo_root();
    let entry = entry_path(&root);
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("i177_db_get_iperow_bound_ipec_out");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build_loose_file(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe dev build must succeed for db_get_iperow_bound: {:?}",
        built.err()
    );

    let emitted = crate::support::read_all_emitted_src(&out);

    // The decoder function's wildcard-`any` generic gains the `IpeRow` bound so
    // its `db_get_string(_, &payload)` body type-checks (E0277 half).
    assert!(
        emitted.contains("ipe_runtime::db::IpeRow"),
        "the wildcard-`any` decoder function must carry the `IpeRow` bound so \
         its `db_get_string` body type-checks (#177); got emitted user source:\n{emitted}"
    );
    assert!(
        emitted.contains("fn main_decode_row<T1: Clone + ipe_runtime::db::IpeRow>"),
        "the bound belongs on the decoder FUNCTION's generic param, not \
         elsewhere (#177); got emitted user source:\n{emitted}"
    );

    // The record struct itself MUST stay unbounded — it is reused in non-row
    // contexts (mirrors the reference's `TypeEmitter.hs` policy). A `struct`
    // line carrying `IpeRow` would be an over-bound regression.
    for line in emitted.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("pub struct ") || trimmed.starts_with("struct ") {
            assert!(
                !line.contains("IpeRow"),
                "the record struct must NOT carry a `IpeRow` bound — it stays \
                 reusable in non-row contexts (#177); offending line: {line}"
            );
        }
    }
}

/// cargo-0 ∧ run-0: the emitted project actually compiles with `rustc` and
/// prints the decoded record fields. Gated on `IPE_E2E=1` — a real
/// `cargo build`, the only check that would have caught the original SEAL
/// violation (E0277 on `examples/27-multi-session-chat`, `ipe dev build` clean).
#[test]
fn i177_cargo_builds_and_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let entry = entry_path(&root);
    let out = crate::support::scratch_root().join("ipec_i177_db_get_iperow_bound_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build_loose_file(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe dev build must succeed for db_get_iperow_bound: {:?}",
        built.err()
    );

    let outcome = crate::support::build_and_run_emitted("db_get_iperow_bound", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "db_get_iperow_bound binary must exit 0; got {:?} (stdout: {:?})",
        outcome.exit_code,
        outcome.stdout
    );
    assert_eq!(
        outcome.stdout.trim(),
        "ada,hello",
        "must print the record fields decoded out of the `Dict String String` \
         payload via the wildcard-`any` `Db.getString` decoder; got: {:?}",
        outcome.stdout
    );
}
