//! Task type-annotation gate: the error channel of `Task E a` must always be
//! `Error`.  Any annotation `Task <X> a` where `X` is not `Error` (e.g. `Task String
//! Int`, `Task Int a`) is a hard type-error, surfacing IPE-T0001 from
//! `normalize_annotation_ty` with message "expected Error, found X".
//!
//! This file tests the REJECT side of the reconciliation fix.  The ACCEPT side
//! (annotations `Task Error a` that now unify with the kernel's unary `Task a`)
//! is exercised by `golden_m5a_task::task_signed_helper`.

use std::path::PathBuf;

use ipe::CliError;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

/// Build the named golden fixture and assert it surfaces exactly `expected` as a
/// pipeline diagnostic — never a panic.  A skip occurs only when the runtime
/// cannot be resolved.
fn assert_gate(fixture: &str, out_suffix: &str, expected: ipe_diagnostics::Code) {
    let root = repo_root();
    let entry = root
        .join("tests")
        .join("golden")
        .join(fixture)
        .join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(out_suffix);
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    let got = match &built {
        Err(CliError::Pipeline { diag, .. }) => Some(diag.code()),
        _ => None,
    };
    assert_eq!(
        got,
        Some(expected),
        "fixture {fixture}: expected {expected:?}, got build result {built:?}"
    );
}

/// `Task String Int` must be rejected with IPE-T0001 ("expected Error, found
/// String").  The `normalize_annotation_ty` pass validates the error channel
/// of every 2-arg `Task` annotation and rejects anything other than `Error`.
#[test]
fn task_bad_error_channel_is_ipe_t0001() {
    assert_gate(
        "gate_task_bad_error",
        "m5a_gate_task_bad_error_emit",
        ipe_diagnostics::IPE_T0001,
    );
}

/// `Task.fail "plain string"` must be rejected with IPE-T0001 ("expected
/// Error, found String"). An over-polymorphic `K::TaskFail` scheme
/// (`fun(var(1), task(var(0)))`) would let a bare `String` argument HM-check and
/// only blow up later at the emitted project's `cargo build` (E0308,
/// `IpeError` vs `String`) — a "compilation successful, then `cargo build`
/// fails" class violation. The scheme is pinned to `fun(error_ty(),
/// task(var(0)))`, matching `mapError`/`onError` and the bundled
/// `Ipe.Task.ipe:33` annotation (`fail : Error -> Task Error a`), so the
/// mismatch is caught at `ipe` type-check time. This also pins the
/// divergence from upstream Ipe's polymorphic `fail : e -> Task e a`
/// (sanctioned divergence: "`Task` error-channel scheme is
/// monomorphic") — a future "restore Elm-parity polymorphism" change cannot
/// silently reopen the ill-typed-emission hole without confronting this test.
#[test]
fn task_fail_string_literal_is_ipe_t0001() {
    assert_gate(
        "gate_task_fail_string",
        "m5a_gate_task_fail_string_emit",
        ipe_diagnostics::IPE_T0001,
    );
}

/// A mis-arity `Cmd` ANNOTATION (`Cmd Int Bool` — Cmd
/// takes exactly ONE message type) must be a clean IPE-T0016, not the
/// IPE-I0001 ICE a Task-only gate would leave the sibling carriers with.
/// `normalize_annotation_ty` validates Cmd/Sub arity too.
#[test]
fn cmd_annotation_wrong_arity_is_ipe_t0016_not_ice() {
    assert_gate(
        "gate_cmd_arity",
        "m5a_gate_cmd_arity_emit",
        ipe_diagnostics::IPE_T0016,
    );
}

/// A mis-arity `Sub` in a CTOR PAYLOAD must be a clean
/// IPE-T0016 at the ctor span, via `lower_enum`'s Gate 0a (covering all three
/// async carriers).
#[test]
fn sub_ctor_payload_wrong_arity_is_ipe_t0016_not_ice() {
    assert_gate(
        "gate_sub_ctor_arity",
        "m5a_gate_sub_ctor_arity_emit",
        ipe_diagnostics::IPE_T0016,
    );
}

/// A `Task` ANNOTATION with the wrong arity (`Task Error Int Bool`,
/// three type arguments) must surface a clean IPE-T0016 diagnostic — NOT a
/// generic `CompilerBug` ICE ("please report"). Reachable from source
/// because canonicalisation validates arity only for type *aliases*, never for a
/// non-alias constructor application like `Task`. `normalize_annotation_ty`'s
/// mis-arity arm fails closed with `TypeError::TaskArity`.
#[test]
fn task_annotation_arity_three_is_ipe_t0016_not_ice() {
    assert_gate(
        "gate_task_arity_three",
        "m5a_gate_task_arity_three_emit",
        ipe_diagnostics::IPE_T0016,
    );
}
