//! `Ipe.Secret` negative gates: every plausible
//! accidental-stringification / accidental-leak path that is NOT redacted
//! must instead be REJECTED at `ipe` compile time — never accepted and left
//! to misbehave (or leak) at runtime, and never deferred to a `cargo`
//! failure (the SEAL). Companion to `crates/ipe/tests/golden_secret.rs`
//! (the positive goldens) and `crates/ipe/tests/model_admissibility.rs`
//! (`live_model_with_secret_field_is_rejected`, the Model-gate IPE-L0120
//! case).
//!
//! Compile-only: these fixtures never run (there is nothing to execute — the
//! program is ill-typed), so there is no oracle / `IPE_E2E` gate here.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

/// Build the named golden fixture and assert it surfaces exactly `expected` as
/// a pipeline diagnostic — never a panic, never a silent accept.
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
        Err(ipe::CliError::Pipeline { diag, .. }) => Some(diag.code()),
        _ => None,
    };
    assert_eq!(
        got,
        Some(expected),
        "fixture {fixture}: expected {expected:?}, got build result {built:?}"
    );
}

/// `"using key " ++ Secret.fromString "sk_live_abc123"` — `Secret` does not
/// satisfy the `++` append obligation (`String` / `List _` only; see
/// `BinopClass::Append`'s doc comment in `ipe_types::constrain`). Both
/// operands are `eq`'d to one shared appendable-bounded super-var; the
/// concrete `String` literal on the left pins that var to `String` FIRST, so
/// the `Secret` right operand surfaces as an ordinary `IPE-T0001` `Con`
/// mismatch (`String` vs `Secret`) rather than the "no operand pins the
/// obligation" `IPE-T0014` shape — either way, a compile-time rejection,
/// never silently accepted and never deferred to a runtime concern.
#[test]
fn secret_concat_is_rejected() {
    assert_gate(
        "secret_concat_rejected",
        "secret_concat_rejected_emit",
        ipe_diagnostics::IPE_T0001,
    );
}

/// `Secret.fromString "sk_live_abc123"` — a committed source-text string
/// LITERAL as the seal argument bakes a credential into source. The
/// committed-literal ban rejects it at ipe compile time with `IPE-L0150`,
/// fail-closed, before any Rust is emitted — never accepted, never deferred to
/// a `cargo` build. A RUNTIME `String` (e.g. `App.fromEnvRequired "VAR"`) in
/// the same position is fine; only a literal is refused.
#[test]
fn secret_from_string_literal_is_rejected() {
    assert_gate(
        "secret_literal_rejected",
        "secret_literal_rejected_emit",
        ipe_diagnostics::IPE_L0150,
    );
}

/// `List.map Secret.fromString [ "sk_live_committed" ]` — the seal is passed as
/// a VALUE, so its argument (a committed literal) is applied later, out of the
/// committed-literal gate's (IPE-L0150) sight. The un-applied-seal ban rejects
/// the point-free reference at ipe compile time with `IPE-L0151`, fail-closed,
/// keeping the literal gate structural: `Secret.fromString` is legal only as a
/// saturated one-argument call, so every argument is seen.
#[test]
fn secret_from_string_point_free_is_rejected() {
    assert_gate(
        "secret_pointfree_rejected",
        "secret_pointfree_rejected_emit",
        ipe_diagnostics::IPE_L0151,
    );
}

/// `let seal = Secret.fromString in seal "sk_live_committed"` — binding the seal
/// to a name and applying the alias later is the same escape as the point-free
/// case: the literal reaches a `Secret` on a path the argument gate never sees.
/// The un-applied-seal ban rejects the aliasing reference at ipe compile time
/// with `IPE-L0151`, fail-closed.
#[test]
fn secret_from_string_alias_is_rejected() {
    assert_gate(
        "secret_alias_rejected",
        "secret_alias_rejected_emit",
        ipe_diagnostics::IPE_L0151,
    );
}

/// `let cred = "sk_live_letbound" in Secret.fromString cred` — a `let`-bound
/// source-text literal applied to the SATURATED seal. The seal folds its
/// argument through the enclosing `let` scope to the constant string and refuses
/// it with `IPE-L0150` — the same committed-literal ban the inline
/// `Secret.fromString "…"` hits, reached through a bounded LOCAL constant-fold.
/// This is the plainest accidental hardcoding, and the syntactic `Str`-node test
/// missed it.
#[test]
fn secret_from_string_letbound_literal_is_rejected() {
    assert_gate(
        "secret_letbound_literal_rejected",
        "secret_letbound_literal_rejected_emit",
        ipe_diagnostics::IPE_L0150,
    );
}

/// `do cred = "sk_live_dobound" … Secret.fromString cred` — a `do`-notation pure
/// `=` binding desugars to the same `let` the `let cred = …` form produces, so a
/// credential bound in a `do` block reaches the seal through the identical local
/// fold and is refused with `IPE-L0150`, fail-closed.
#[test]
fn secret_from_string_dobound_literal_is_rejected() {
    assert_gate(
        "secret_dobound_literal_rejected",
        "secret_dobound_literal_rejected_emit",
        ipe_diagnostics::IPE_L0150,
    );
}

/// `Secret.fromString (String.append "sk_live_" "concat")` — a literal string
/// join whose every operand folds to a constant. `String.append` (and the
/// `String.concat [ … ]` spelling) folds to the concatenated constant, which the
/// seal refuses with `IPE-L0150` — a committed credential assembled from pieces
/// is still a committed credential.
#[test]
fn secret_from_string_append_literal_is_rejected() {
    assert_gate(
        "secret_append_literal_rejected",
        "secret_append_literal_rejected_emit",
        ipe_diagnostics::IPE_L0150,
    );
}

/// `Secret.fromString ("sk_live_" ++ "concatop")` — the `++` operator
/// canonicalises to the same `append` kernel `String.append` does, so a literal
/// `++` join folds to the constant and is refused with `IPE-L0150`, fail-closed.
#[test]
fn secret_from_string_concatop_literal_is_rejected() {
    assert_gate(
        "secret_concatop_literal_rejected",
        "secret_concatop_literal_rejected_emit",
        ipe_diagnostics::IPE_L0150,
    );
}

/// `secret <- Io.readSecret "…" ; Io.println secret` — `Io.readSecret` now yields
/// an opaque `Secret`, not a bare `String`. Printing the bound `Secret` in the
/// clear (`Io.println` wants a `String`) must be REJECTED at ipe compile time
/// with `IPE-T0001` (`String` vs `Secret`), fail-closed — never accepted and
/// left to leak the plaintext at runtime. The whole point of the typed result:
/// a freshly-read password reaches stdout/a log only through an explicit
/// `Secret.use` / `Secret.reveal`, never implicitly.
#[test]
fn io_read_secret_used_as_string_is_rejected() {
    assert_gate(
        "secret_io_read_as_string_rejected",
        "secret_io_read_as_string_rejected_emit",
        ipe_diagnostics::IPE_T0001,
    );
}
