//! Regression — the Stage-4 `Kernel.kernel "Module_function"` alias mechanism is
//! ORIGIN-GATED: minting a kernel is the exclusive privilege of the
//! driver-vouched standard library and generated FFI interface. A binding of the
//! shape `f = Kernel.kernel "K_n"` in USER source is rejected with a typed
//! diagnostic (IPE-N0042) — regardless of whether the named kernel is
//! registered, malformed, or perfectly valid.
//!
//! This closes a capability-model bypass: without the gate, user source could
//! bind a name straight to any kernel — including an unsafe-tier one (a
//! raw-`<script>` sink) — reaching the effect with no `unsafe` capability
//! disclosed and no `.Unsafe` import to acknowledge. The gate mirrors the
//! `Ffi.binding` origin gate in `canonicalise_foreign_call`: user code reaches a
//! kernel only through the published module that discloses it.
//!
//! The registry fail-closed gate for an unknown / malformed alias string
//! (IPE-N0028) still applies inside the vouched stdlib origin; it is exercised by
//! the `ipe_canon` resolver unit tests. From user source the origin gate fires
//! FIRST, so the string content never decides the outcome.
//!
//! ```text
//! cargo test -p ipe --test golden_ffi_kernel_alias_seal
//! ```

use std::fs;
use std::path::PathBuf;

fn write_project(dir: &std::path::Path, main: &str) -> bool {
    let src = dir.join("src");
    let _ = fs::remove_dir_all(dir);
    if fs::create_dir_all(&src).is_err() {
        return false;
    }
    fs::write(src.join("Main.ipe"), main).is_ok()
}

/// Build the user project and assert `ipe` rejects it with the origin-gate
/// diagnostic `NameError::KernelAliasInUserSource` (IPE-N0042).
fn assert_rejected_as_user_kernel_alias(sub_dir: &str, out_dir: &str, main: &str) {
    let runtime = e2e_support::require_runtime().into_path_buf();

    let tmp = crate::support::scratch_root().join(sub_dir);
    assert!(
        write_project(&tmp, main),
        "must write the fixture project to a temp dir"
    );

    let entry = tmp.join("src").join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(out_dir);
    let _ = fs::remove_dir_all(&out);

    let built = ipe::build_loose_file(&entry, &out, &runtime);
    let is_user_kernel_alias = matches!(
        &built,
        Err(ipe::CliError::Pipeline { diag, .. })
            if matches!(
                &**diag,
                ipe_diagnostics::Diagnostic::Name {
                    msg: ipe_diagnostics::NameError::KernelAliasInUserSource { .. },
                    ..
                }
            )
    );
    assert!(
        is_user_kernel_alias,
        "a user-source `Kernel.kernel` alias must be rejected with IPE-N0042 \
         (user code may not mint a kernel): {built:?}"
    );
}

/// A user alias to an UNREGISTERED kernel is rejected by the origin gate before
/// the registry is even consulted — IPE-N0042, not the registry's IPE-N0028.
#[test]
fn user_alias_to_unregistered_kernel_is_rejected() {
    assert_rejected_as_user_kernel_alias(
        "ipec_196_ffi_kernel_alias_unknown",
        "m196_unknown_kernel_alias_out",
        "module Main exposing (main)\n\
         import Ipe.Io as Io\n\n\
         bogus : String -> String\n\
         bogus =\n\
         \x20   Kernel.kernel \"NoSuchKernel_xyz\"\n\n\
         main = Io.println (bogus \"x\")\n",
    );
}

/// A malformed (`_`-less) alias string in user source is likewise rejected by
/// the origin gate — the string never gets a chance to be judged malformed.
#[test]
fn user_alias_with_malformed_string_is_rejected() {
    assert_rejected_as_user_kernel_alias(
        "ipec_196_ffi_kernel_alias_malformed",
        "m196_malformed_kernel_alias_out",
        "module Main exposing (main)\n\
         import Ipe.Io as Io\n\n\
         bogus : String -> String\n\
         bogus =\n\
         \x20   Kernel.kernel \"NoUnderscoreHere\"\n\n\
         main = Io.println (bogus \"x\")\n",
    );
}

/// Even an alias naming a perfectly REGISTERED kernel (`String_toUpper`) is
/// rejected in user source — the privilege is denied by ORIGIN, not by which
/// kernel is named, so there is no "safe kernel" loophole for user code to mint
/// through. The registered kernel stays reachable through its published stdlib
/// surface (e.g. `String.toUpper`), never a hand-minted alias.
#[test]
fn user_alias_to_registered_kernel_is_still_rejected() {
    assert_rejected_as_user_kernel_alias(
        "ipec_196_ffi_kernel_alias_registered",
        "m196_registered_kernel_alias_out",
        "module Main exposing (main)\n\
         import Ipe.Io as Io\n\n\
         shout : String -> String\n\
         shout =\n\
         \x20   Kernel.kernel \"String_toUpper\"\n\n\
         main = Io.println (shout \"hi\")\n",
    );
}
