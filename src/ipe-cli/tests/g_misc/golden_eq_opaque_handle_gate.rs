//! THE SEAL for `==` over an opaque foreign handle.
//!
//! A shim-free FFI binding maps an Ipê opaque type onto the real foreign Rust
//! type, which need not implement `PartialEq`; an enum holding one gets no
//! `PartialEq` derive. Comparing either would pass `ipe` and fail `cargo
//! build` with E0369, so the type checker's `Equatable` rule refuses both with
//! IPE-T0014. The control, the same union over an `Int`, builds and runs under
//! `IPE_E2E=1`, so the gate never over-refuses a comparable union.
//!
//! ```text
//! cargo test -p ipe --test g_misc golden_eq_opaque_handle_gate
//! IPE_E2E=1 cargo test -p ipe --test g_misc golden_eq_opaque_handle_gate
//! ```

use std::path::PathBuf;

use ipe::{CliError, RootFixture};

use crate::golden_ffi_nonclone_handle_reuse_seal::ffi_fixture;

/// A runtime `false` the optimiser cannot fold, for a deliberate failure.
const fn false_marker() -> bool {
    std::hint::black_box(false)
}

/// The scratch output dir for `name`, cleared.
fn out_dir(name: &str) -> PathBuf {
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("eq_opaque_handle_out")
        .join(name);
    e2e_support::scratch::fresh(&out);
    out
}

/// Assert `fixture` is refused by `ipe` with IPE-T0014, before any Rust is emitted.
#[track_caller]
fn assert_t0014(name: &str, fixture: &RootFixture) {
    let runtime = e2e_support::require_runtime().into_path_buf();
    let out = out_dir(name);
    match ipe::build_fixture(fixture, &out, &runtime) {
        Err(CliError::Pipeline { diag, .. }) => assert_eq!(
            diag.code(),
            ipe_diagnostics::IPE_T0014,
            "{name}: expected a fail-closed IPE-T0014, got a different diagnostic"
        ),
        Ok(_) => assert!(
            false_marker(),
            "{name}: ipe ACCEPTED an `==` over an opaque handle (exit 0); the \
             emitted crate fails cargo with E0369, a SEAL break"
        ),
        Err(other) => assert!(
            false_marker(),
            "{name}: non-pipeline build error: {other:?}"
        ),
    }
}

/// `==` over two bare `Rust.Handle_demo.Widget` handles.
const HANDLE_EQUALITY: &str = "module Main exposing (main)\n\
     import Ipe.Io as Io\n\
     import Rust.Handle_demo as H\n\n\
     same : H.Widget -> H.Widget -> Bool\n\
     same a b =\n\
     \x20   a == b\n\n\
     main =\n\
     \x20   Io.println \"x\"\n";

/// `==` over a union whose only payload is the handle.
const UNION_HOLDING_HANDLE_EQUALITY: &str = "module Main exposing (main)\n\
     import Ipe.Io as Io\n\
     import Rust.Handle_demo as H\n\n\
     type Holder = Hold H.Widget\n\n\
     same : Holder -> Holder -> Bool\n\
     same a b =\n\
     \x20   a == b\n\n\
     main =\n\
     \x20   Io.println \"x\"\n";

/// The control: the same union over an `Int`, compared and printed.
const UNION_HOLDING_INT_EQUALITY: &str = "module Main exposing (main)\n\
     import Ipe.Io as Io\n\n\
     type Holder = Hold Int\n\n\
     main =\n\
     \x20   if Hold 1 == Hold 1 then\n\
     \x20       Io.println \"same\"\n\n\
     \x20   else\n\
     \x20       Io.println \"different\"\n";

#[test]
fn opaque_handle_equality_refused() {
    assert_t0014("opaque_handle_equality", &ffi_fixture(HANDLE_EQUALITY));
}

#[test]
fn union_holding_opaque_handle_equality_refused() {
    assert_t0014(
        "union_holding_opaque_handle_equality",
        &ffi_fixture(UNION_HOLDING_HANDLE_EQUALITY),
    );
}

#[test]
#[allow(clippy::expect_used)] // a fixture that cannot be written fails the control loudly
fn union_holding_int_equality_builds() {
    let name = "union_holding_int_equality";
    let fixture = RootFixture::main(UNION_HOLDING_INT_EQUALITY)
        .expect("the control fixture project resolves");
    let runtime = e2e_support::require_runtime().into_path_buf();
    let out = out_dir(name);
    match ipe::build_fixture(&fixture, &out, &runtime) {
        Ok(_) => {}
        Err(err) => {
            assert!(
                false_marker(),
                "{name}: ipe REJECTED a comparable union, a false refusal: {err}"
            );
            return;
        }
    }
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let outcome = crate::support::build_and_run_emitted(name, &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "{name}: emitted crate must build and run to exit 0"
    );
    assert_eq!(
        outcome.stdout.trim_end(),
        "same",
        "{name}: emitted crate built (SEAL held) but ran to the wrong output"
    );
}
