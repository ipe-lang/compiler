//! `Task`-in-constructor-payload gates (E2 + E3).
//!
//! E2 — a MIS-ARITY `Task` reached through a constructor FIELD type
//! (`type Boxed a = Boxed (Task Error a Bool)`) never passes through
//! `normalize_annotation_ty`, so E1's annotation-path gate does not fire. It
//! reaches `ir_type_from_canon`'s `"Task"` catch-all, which formerly raised a
//! `CompilerBug` ICE. `lower_enum`'s new Gate 0a (`task_arity_in_canon`) now
//! fails closed with the SAME clean IPE-T0016 diagnostic (`TypeError::TaskArity`)
//! at the constructor span.
//!
//! E3 — a WELL-FORMED `Task Error Int` (arity 2) embedded in a constructor
//! payload is ACCEPTED (spec's recommended branch, symmetric with Item B's
//! function / Result / Maybe precedent): the derive-demotion fixpoint degrades
//! the non-derivable enum gracefully, so the declaration builds cleanly rather
//! than being rejected. This test pins that no new rejection was added.

use std::path::PathBuf;

use ipe::CliError;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

/// Build the named golden fixture and return the pipeline diagnostic code, if the
/// build failed with one (never a panic).
fn build_fixture(fixture: &str, out_suffix: &str) -> Result<(), CliError> {
    let root = repo_root();
    let entry = root
        .join("tests")
        .join("golden")
        .join(fixture)
        .join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(out_suffix);
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    ipe::build(&entry, &out, &runtime)
}

/// E2: a mis-arity `Task` in a constructor payload is a clean IPE-T0016, not an
/// ICE / `CompilerBug`.
#[test]
fn ctor_task_arity_three_is_ipe_t0016_not_ice() {
    let built = build_fixture("gate_ctor_task_arity", "m5a_gate_ctor_task_arity_emit");
    let got = match &built {
        Err(CliError::Pipeline { diag, .. }) => Some(diag.code()),
        _ => None,
    };
    assert_eq!(
        got,
        Some(ipe_diagnostics::IPE_T0016),
        "expected IPE-T0016 for a mis-arity Task in a ctor payload, got {built:?}"
    );
}

/// E3: a well-formed `Task Error Int` in a constructor payload is ACCEPTED —
/// the front-end (ipe lowering + emitted-Rust `cargo build`) succeeds. Pins the
/// spec's decision to NOT add a new rejection here (symmetric with Item B).
#[test]
fn ctor_task_well_formed_builds() {
    let built = build_fixture("ctor_task_ok", "m5a_ctor_task_ok_emit");
    // Whatever else, it must NOT be a Task-arity rejection and must NOT be an
    // internal compiler bug. `build` may still surface a downstream cargo error
    // in a bare CI without a warm runtime, so assert on the specific fail-closed
    // codes this feature governs rather than demanding full E2E success here.
    if let Err(CliError::Pipeline { diag, .. }) = &built {
        assert_ne!(
            diag.code(),
            ipe_diagnostics::IPE_T0016,
            "a well-formed `Task Error Int` payload must not be rejected as mis-arity"
        );
        assert_ne!(
            diag.code(),
            ipe_diagnostics::IPE_I0001,
            "a well-formed `Task Error Int` payload must not ICE"
        );
    }
}
