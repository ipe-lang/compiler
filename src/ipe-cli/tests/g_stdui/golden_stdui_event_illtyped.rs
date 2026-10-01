//! `Ipe.Html.Events.onInput` handler-payload gate: a Bool handler must be
//! REJECTED BY ipe with IPE-T0001 — never exit 0 and defer to cargo.
//!
//! ## Context
//!
//! `Ipe.Html.Events.*` resolves to the dedicated `Html*` event kernels,
//! which produce a `Ipe.Html.Attribute msg` (`html_attr`) — the same nominal
//! type Ipe.Html attribute + element builders use. The fixtures host the event
//! on a Ipe.Html element (`Html.input`) where an Html attribute belongs. The
//! payload-shape check (`(String -> msg)` argument) is the same across event
//! surfaces.
//!
//! ## What is tested
//!
//! * **Negative** (`stdui_event_illtyped`): `Event.onInput (\b -> SetChecked b)`
//!   (Bool handler on a String event) → ipe reports IPE-T0001 (type mismatch),
//!   never exits 0.
//!
//! * **Positive** (`stdui_event_oninput`): `Event.onInput (\s -> SetText s)`
//!   (String handler, well-typed) → ipe succeeds (build returns `Ok`).
//!
//! Both tests are pure ipe-pipeline checks (no cargo build / runtime binary
//! required), so they run without `IPE_E2E=1`.  They return early if
//! [`ipe::resolve_runtime`] cannot locate the embedded runtime.

use std::path::PathBuf;

use ipe::CliError;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

/// Run the ipe pipeline on the named fixture and return the build result.
/// Returns
fn run_ipec(fixture: &str, out_suffix: &str) -> Result<(), CliError> {
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

/// NEGATIVE gate: `Event.onInput` with a `Bool -> msg`
/// handler must be rejected by ipe with IPE-T0001.
///
/// Without the fix, `constrain.rs` fell to `Ty::Var(u32::MAX)` for the `"Event"`
/// qualifier → ipe exited 0 → cargo emitted E0308.
/// Post-fix: `Some("Ui" | "Event")` arm unifies `Bool -> msg` with the
/// expected `String -> msg` → IPE-T0001 at the type-checking stage.
#[test]
fn event_oninput_illtyped_bool_handler_is_ipe_t0001() {
    let result = run_ipec("stdui_event_illtyped", "m7_stdui_event_illtyped_emit");

    let got = match &result {
        Err(CliError::Pipeline { diag, .. }) => Some(diag.code()),
        _ => None,
    };
    assert_eq!(
        got,
        Some(ipe_diagnostics::IPE_T0001),
        "stdui_event_illtyped: expected IPE-T0001 (type mismatch), got: {result:?}",
    );
}

/// POSITIVE sentinel: `Event.onInput` with a correct
/// `String -> msg` handler must compile (ipe build returns `Ok`).
///
/// This confirms the widened qualifier arm in `constrain.rs` does not
/// break well-typed `Event.onInput` usage.
#[test]
fn event_oninput_correct_handler_compiles() {
    let result = run_ipec("stdui_event_oninput", "m7_stdui_event_oninput_emit");

    assert!(
        result.is_ok(),
        "stdui_event_oninput: correct Event.onInput handler must compile, got: {:?}",
        result.err()
    );
}
