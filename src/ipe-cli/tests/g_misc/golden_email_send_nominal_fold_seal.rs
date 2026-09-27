//! SEAL regression for "Ipe.Email family". A typed `EmailMessage`
//! built via `Email.defaultMessage` + `with*` builders is fed directly to
//! `Email.send`, and the `EmailProvider` ADT is constructed via its `Resend`
//! ctor.
//!
//! Before the fold, `Ipe.Email` fail-closed at ipe time with IPE-N0028 (no
//! registered `Email_send` kernel). Registering the kernel across every
//! anti-drift site AND folding the `EmailMessage` / `Attachment` record shapes
//! (plus the `EmailProvider` ADT) to their nominal runtime types
//! (`ipe_runtime::email::{EmailMessage, EmailAttachment, EmailProvider}`) makes
//! a builder-constructed message + a `Resend` ctor construct the exact runtime
//! types the `email_send` kernel takes. A backend-synthesised `Rec…` struct or
//! a duplicate `StdEmailEmailProvider` enum would mismatch that boundary with
//! E0308 — the classic ipe-0-then-cargo-fail SEAL violation this pins shut.
//!
//! ## Why the emit-only assertions run in the DEFAULT gate
//!
//! `IPE_E2E`-gated tests do not run in the default `cargo nextest` gate. This
//! file's first test inspects the emitted app modules (no cargo build) so it
//! runs in the DEFAULT gate and pins the regression even when `IPE_E2E` is
//! unset; the second test is the `IPE_E2E`-gated cargo-build proof that the
//! emitted crate (with the vendored `email` module + the `lettre` dep) actually
//! compiles.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn fixture_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join("email_send_nominal_fold_seal")
        .join("Main.ipe")
}

/// Recursively concatenate every emitted `.rs` file under `dir`. The
/// `Email.*` call sites land in `src/ipe_mods/*.rs` (top-level bindings emit to
/// per-module files), not `src/main.rs`, so the assertions scan the whole
/// emitted APP tree.
fn concat_emitted_rs(dir: &Path, out: &mut String) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            concat_emitted_rs(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs")
            && let Ok(text) = std::fs::read_to_string(&path)
        {
            out.push_str(&text);
            out.push('\n');
        }
    }
}

/// Build the fixture and return the concatenated emitted APP Rust source. `None`
/// when the runtime resolver is unavailable in this environment (mirrors the
/// resolve-skip convention every other golden test in this suite uses) or when
/// the build itself fails (the caller's `assert!` reports the diag).
fn built_app_rs(root: &Path, out: &Path) -> (Result<(), ipe::CliError>, Option<String>) {
    let entry = fixture_entry(root);
    let _ = std::fs::remove_dir_all(out);
    let Ok(runtime) = ipe::resolve_runtime() else {
        return (Ok(()), None);
    };
    let built = ipe::build(&entry, out, &runtime);
    let emitted = if built.is_ok() {
        // Scan the emitted APP modules only (`src/ipe_mods/` + `src/main.rs`),
        // not the vendored `src/ipe_runtime/` — the runtime's own `email.rs`
        // defines the structs/enum and would mask what the app-side codegen
        // chose.
        let mut acc = std::fs::read_to_string(out.join("src").join("main.rs")).unwrap_or_default();
        acc.push('\n');
        concat_emitted_rs(&out.join("src").join("ipe_mods"), &mut acc);
        Some(acc)
    } else {
        None
    };
    (built, emitted)
}

/// The message + attachment literals must be emitted as the runtime
/// `EmailMessage` / `EmailAttachment` structs (NOT backend-synthesised `Rec…`
/// structs), and the `Resend` ctor as the runtime `EmailProvider` variant — the
/// `email_send` kernel takes those runtime types, so a synthesised struct or a
/// duplicated enum would reject at the call boundary with E0308.
#[test]
fn email_literals_emit_runtime_structs_and_provider_variant() {
    let root = repo_root();
    let out = crate::support::scratch_root().join("ipec_email_send_nominal_fold_seal_emit");
    let (built, app_rs) = built_app_rs(&root, &out);
    assert!(
        built.is_ok(),
        "email_send_nominal_fold_seal: must be accepted (ipe-0), got: {built:?}"
    );
    let Some(app_rs) = app_rs else {
        return; // resolver unavailable — skip, matches the other goldens
    };

    assert!(
        app_rs.contains("EmailMessage {"),
        "the message literal must construct the runtime `EmailMessage {{ .. }}` \
         struct the `email_send` kernel takes.\n--- emitted ---\n{app_rs}"
    );
    assert!(
        app_rs.contains("EmailAttachment {"),
        "the attachment literal must construct the runtime `EmailAttachment \
         {{ .. }}` struct.\n--- emitted ---\n{app_rs}"
    );
    assert!(
        app_rs.contains("EmailProvider :: Resend") || app_rs.contains("EmailProvider::Resend"),
        "the `Resend` ctor must construct the runtime `EmailProvider::Resend` \
         variant, not a duplicate program-local enum.\n--- emitted ---\n{app_rs}"
    );
    assert!(
        !app_rs.contains("StdEmailEmailProvider"),
        "the `EmailProvider` ADT must NOT emit a duplicate `StdEmailEmailProvider` \
         enum — its `EnumDef` is suppressed and routed to the runtime enum.\n\
         --- emitted ---\n{app_rs}"
    );
}

/// The load-bearing SEAL proof: under `IPE_E2E=1`, actually `cargo build` the
/// emitted crate. Without kernel backing `Ipe.Email` fail-closes at ipe time
/// (IPE-N0028); with it, ipe-0 AND the emitted crate — with the vendored
/// `email` module and the injected `lettre` dep — `cargo build`s exit 0.
#[test]
fn email_send_nominal_fold_seal_builds() {
    let root = repo_root();
    let out = crate::support::scratch_root().join("ipec_email_send_nominal_fold_seal_e2e");
    let Ok(runtime) = ipe::resolve_runtime() else {
        return;
    };
    let entry = fixture_entry(&root);
    let _ = std::fs::remove_dir_all(&out);
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "email_send_nominal_fold_seal: must be accepted (ipe-0), got: {built:?}"
    );

    if std::env::var("IPE_E2E").is_err() {
        return;
    }
    // The `email.send` kernel is network-effectful (no deterministic stdout
    // without a live provider), so the SEAL proof is the cargo BUILD, not a run:
    // ipe-0 ⇒ the emitted crate compiles.
    let outcome = crate::support::build_emitted("email_send_nominal_fold_seal", &out);
    assert!(
        outcome.is_ok(),
        "email_send_nominal_fold_seal: emitted crate must `cargo build` exit 0 \
         (pre-fix: IPE-N0028 fail-closed; the fold + kernel + `lettre` dep must \
         seal it): {}",
        outcome.err().unwrap_or_default()
    );
}
