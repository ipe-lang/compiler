//! Runtime-config front door (`Web.appWith` + `Ipe.App`/`Host`/`Log`/`Db`
//! settings). Three proofs pin the security-critical surface:
//!
//!   * THE SEAL — `Web.appWith` carrying a shape-checked `List (Setting Web)`
//!     (a cross-cutting `Host.bind` / `Db.url (App.fromEnv …)` plus the
//!     web-pinned `Web.csrf` / `Web.sessionTtl`) is accepted (exit 0) AND the
//!     emitted crate `cargo build`s under `IPE_E2E=1`;
//!   * a hard-coded `Db.url "postgres://…"` (a `String`, not the `Secret` that
//!     only `App.fromEnv` mints) is REJECTED at ipe time — an in-source
//!     credential is unrepresentable at the boundary;
//!   * a non-`Setting` value in the `List (Setting Web)` slot (a bare `Int`) is
//!     REJECTED — the phantom shape on the settings list is enforced;
//!   * a bare `Int` where a config-tag ADT is expected (`Host.bind 7` /
//!     `Web.csrf 99` / `Log.level 5`) is REJECTED — the closed `HostMode` /
//!     `CsrfMode` / `LogLevel` types make an out-of-range tag a type error, not a
//!     value the runtime falls closed on. `CsrfMode` has no disabling variant.

use std::path::{Path, PathBuf};

use ipe::CliError;
use ipe_diagnostics::{
    Code, Diagnostic, IPE_N0043, IPE_T0001, NameError, Span, TyDoc, TypeError, render_ty,
};

use crate::support::repo_root;

fn fixture_entry(root: &Path, golden: &str) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join(golden)
        .join("Main.ipe")
}

/// THE SEAL: the settings-carrying web app is accepted and (under `IPE_E2E=1`)
/// the emitted crate `cargo build`s.
#[test]
fn app_settings_web_seal_builds() {
    const GOLDEN: &str = "app_settings_web_seal";
    let root = repo_root();
    let entry = fixture_entry(&root, GOLDEN);
    let out = crate::support::scratch_root().join("ipec_app_settings_web_seal_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "a `Web.appWith` carrying a shape-checked settings list must be accepted, got: {built:?}"
    );

    crate::support::assert_seal_builds(GOLDEN, &out);
}

/// A hard-coded `String` credential passed to `Db.url` (which requires a
/// `Secret`) must be an ipe-time type error — never accepted.
#[test]
fn hard_coded_db_url_secret_is_rejected() {
    const GOLDEN: &str = "app_settings_hardcoded_secret_rejected";
    let root = repo_root();
    let entry = fixture_entry(&root, GOLDEN);
    let out = crate::support::scratch_root().join("ipec_app_settings_hardcoded_secret_rejected");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert_eq!(
        judge_rejection(&built, IPE_T0001, Some("Secret")),
        Ok(()),
        "a hard-coded `Db.url \"postgres://…\"` (a `String`, not a `Secret`) MUST be \
         rejected — the only way to a config secret is `App.fromEnv`"
    );
    assert_eq!(
        emitted_rust(&out),
        None,
        "{GOLDEN}: a rejected build must emit no Rust"
    );
}

/// A bare `Int` in the `List (Setting Web)` settings slot must be an ipe-time
/// type error — the phantom-shaped settings list only admits `Setting Web`.
#[test]
fn non_setting_in_settings_list_is_rejected() {
    const GOLDEN: &str = "app_settings_non_setting_rejected";
    let root = repo_root();
    let entry = fixture_entry(&root, GOLDEN);
    let out = crate::support::scratch_root().join("ipec_app_settings_non_setting_rejected");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert_eq!(
        judge_rejection(&built, IPE_T0001, Some("Setting")),
        Ok(()),
        "a bare `Int` in the `List (Setting Web)` settings slot MUST be rejected — \
         the phantom shape on the settings list is enforced"
    );
    assert_eq!(
        emitted_rust(&out),
        None,
        "{GOLDEN}: a rejected build must emit no Rust"
    );
}

/// `Host.bind 7` — a bare `Int` where the closed `HostMode` ADT is expected —
/// must be an ipe-time type error. An out-of-range host-bind tag is now
/// unrepresentable, not a value the runtime falls closed on.
#[test]
fn bare_int_host_bind_is_rejected() {
    const GOLDEN: &str = "app_settings_bare_int_host_rejected";
    let root = repo_root();
    let entry = fixture_entry(&root, GOLDEN);
    let out = crate::support::scratch_root().join("ipec_app_settings_bare_int_host_rejected");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert_eq!(
        judge_rejection(&built, IPE_T0001, Some("HostMode")),
        Ok(()),
        "`Host.bind 7` (a bare `Int`, not a `HostMode`) MUST be rejected — the \
         closed `HostMode` ADT makes an out-of-range host-bind tag a type error"
    );
    assert_eq!(
        emitted_rust(&out),
        None,
        "{GOLDEN}: a rejected build must emit no Rust"
    );
}

/// `Web.csrf 99` — a bare `Int` where the closed `CsrfMode` ADT is expected —
/// must be an ipe-time type error. `CsrfMode` also carries no disabling variant,
/// so a setting cannot express turning CSRF off.
#[test]
fn bare_int_web_csrf_is_rejected() {
    const GOLDEN: &str = "app_settings_bare_int_csrf_rejected";
    let root = repo_root();
    let entry = fixture_entry(&root, GOLDEN);
    let out = crate::support::scratch_root().join("ipec_app_settings_bare_int_csrf_rejected");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert_eq!(
        judge_rejection(&built, IPE_T0001, Some("CsrfMode")),
        Ok(()),
        "`Web.csrf 99` (a bare `Int`, not a `CsrfMode`) MUST be rejected — the \
         closed `CsrfMode` ADT makes an out-of-range CSRF tag a type error"
    );
    assert_eq!(
        emitted_rust(&out),
        None,
        "{GOLDEN}: a rejected build must emit no Rust"
    );
}

/// THE SEAL: `Web.authMaxLifetime <seconds>` is accepted (no N0005) and (under
/// `IPE_E2E=1`) the emitted crate `cargo build`s. Proves the `WebAuthMaxLifetime`
/// kernel is wired through canon/constrain/lower.
#[test]
fn auth_max_lifetime_seal_builds() {
    const GOLDEN: &str = "app_settings_auth_max_lifetime_seal";
    let root = repo_root();
    let entry = fixture_entry(&root, GOLDEN);
    let out = crate::support::scratch_root().join("ipec_app_settings_auth_max_lifetime_seal_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "`Web.authMaxLifetime` must be accepted (no N0005) and emit a buildable crate, \
         got: {built:?}"
    );

    crate::support::assert_seal_builds(GOLDEN, &out);
}

/// THE SEAL: `Web.authSlideWindow <seconds>` is accepted (no N0005) and (under
/// `IPE_E2E=1`) the emitted crate `cargo build`s. Proves the `WebAuthSlideWindow`
/// kernel is wired through canon/constrain/lower.
#[test]
fn auth_slide_window_seal_builds() {
    const GOLDEN: &str = "app_settings_auth_slide_window_seal";
    let root = repo_root();
    let entry = fixture_entry(&root, GOLDEN);
    let out = crate::support::scratch_root().join("ipec_app_settings_auth_slide_window_seal_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "`Web.authSlideWindow` must be accepted (no N0005) and emit a buildable crate, \
         got: {built:?}"
    );

    crate::support::assert_seal_builds(GOLDEN, &out);
}

/// THE SEAL: `Web.withRevocation Web.revocationStore` is accepted (no N0005) and
/// (under `IPE_E2E=1`) the emitted crate `cargo build`s. Proves the
/// `WebAuthRevocationMode` / `WebRevocationStore` kernels are wired through
/// canon/constrain/lower and that `RevocationMode` erases to `Int` correctly.
#[test]
fn auth_revocation_seal_builds() {
    const GOLDEN: &str = "app_settings_auth_revocation_seal";
    let root = repo_root();
    let entry = fixture_entry(&root, GOLDEN);
    let out = crate::support::scratch_root().join("ipec_app_settings_auth_revocation_seal_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "`Web.withRevocation Web.revocationStore` must be accepted (no N0005) and emit \
         a buildable crate, got: {built:?}"
    );

    crate::support::assert_seal_builds(GOLDEN, &out);
}

/// A program with an authenticated route (`Server.getAuthed`) emitted under the
/// **vendored** emit model (`runtime_dep: false`) must DECLARE the `revocation`
/// module in `ipe_runtime/mod.rs`. `server.rs`'s `authed_route` middleware calls
/// `crate::revocation::is_revoked` unconditionally, so a missing declaration
/// produces E0433 (ipe exit 0, then cargo fails). This is the regression tripwire
/// for the `pub mod revocation;` append.
///
/// A full `cargo build` of a vendored `authed_route` program is a separate,
/// pre-existing SEAL gap — the vendored emitter does not add the `jwt` feature to
/// the emitted crate's default list, so `#[cfg(feature = "jwt")]` `AuthConfig` is
/// compiled out (E0425). That gap is tracked on its own; this test locks the
/// module-declaration fix that belongs to the revocation surface.
#[test]
fn authed_route_revocation_vendored_declares_module() {
    const GOLDEN: &str = "authed_route_revocation_vendored_seal";
    let root = repo_root();
    let entry = fixture_entry(&root, GOLDEN);
    let out = crate::support::scratch_root().join("ipec_authed_route_revocation_vendored_seal_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    // Force the vendored emit model regardless of the environment default —
    // the model whose trimmed `mod.rs` template must carry the revocation append.
    let opts = ipe::BuildOptions {
        runtime_dep: false,
        ..ipe::BuildOptions::default()
    };
    let built = ipe::build_with_options(&entry, &out, &runtime, opts);
    assert!(
        built.is_ok(),
        "an `authed_route` program must be accepted under the vendored emit model, \
         got: {built:?}"
    );

    let mod_rs = std::fs::read_to_string(out.join("src").join("ipe_runtime").join("mod.rs"))
        .expect("emitted vendored ipe_runtime/mod.rs");
    assert!(
        mod_rs.contains("pub mod revocation;"),
        "vendored emit must declare `pub mod revocation;` for an authed_route \
         revocation program, else the emitted crate fails cargo build with E0433 \
         on `crate::revocation`"
    );
}

/// `Log.level 5` — a bare `Int` where the closed `LogLevel` ADT is expected —
/// must be an ipe-time type error.
#[test]
fn bare_int_log_level_is_rejected() {
    const GOLDEN: &str = "app_settings_bare_int_loglevel_rejected";
    let root = repo_root();
    let entry = fixture_entry(&root, GOLDEN);
    let out = crate::support::scratch_root().join("ipec_app_settings_bare_int_loglevel_rejected");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert_eq!(
        judge_rejection(&built, IPE_T0001, Some("LogLevel")),
        Ok(()),
        "`Log.level 5` (a bare `Int`, not a `LogLevel`) MUST be rejected — the \
         closed `LogLevel` ADT makes an out-of-range severity tag a type error"
    );
    assert_eq!(
        emitted_rust(&out),
        None,
        "{GOLDEN}: a rejected build must emit no Rust"
    );
}

/// THE SEAL (item 1): a named top-level `config : List (Setting Web)` binding
/// threaded into a settings-less `Web.tea { … }` entry is accepted (exit 0) AND
/// the emitted crate `cargo build`s. Proves canon rewrites `Web.tea` to
/// `Web.appWith config` — the ergonomic one-`config`-binding surface.
#[test]
fn config_binding_threads_into_web_app_and_builds() {
    const GOLDEN: &str = "app_settings_config_binding";
    let root = repo_root();
    let entry = fixture_entry(&root, GOLDEN);
    let out = crate::support::scratch_root().join("ipec_app_settings_config_binding_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "a named `config` binding threaded into a `Web.tea` entry must be accepted \
         and emit a buildable crate, got: {built:?}"
    );

    crate::support::assert_seal_builds(GOLDEN, &out);
}

/// A top-level `config` binding that no app entry consumes (here `main` is a
/// plain Program) MUST be an ipe-time error (IPE-N0043, the discarded-config
/// lint) — the settings would otherwise be silently dropped.
#[test]
fn discarded_config_binding_is_rejected() {
    const GOLDEN: &str = "app_settings_discarded_config_rejected";
    let root = repo_root();
    let entry = fixture_entry(&root, GOLDEN);
    let out = crate::support::scratch_root().join("ipec_app_settings_discarded_config_rejected");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert_eq!(
        judge_rejection(&built, IPE_N0043, None),
        Ok(()),
        "a `config` binding that no app entry threads MUST be rejected (IPE-N0043) — \
         its settings would otherwise be silently dropped"
    );
    assert_eq!(
        emitted_rust(&out),
        None,
        "{GOLDEN}: a rejected build must emit no Rust"
    );
}

/// THE SEAL (item 2): `Db.url (App.fromEnvRequired "DATABASE_URL")` — the
/// fail-closed required-secret source — is accepted (exit 0) and (under
/// `IPE_E2E=1`) the emitted crate `cargo build`s. Proves `AppFromEnvRequired`
/// is wired through canon/constrain/lower and shares `App.fromEnv`'s signature.
#[test]
fn from_env_required_seal_builds() {
    const GOLDEN: &str = "app_settings_fromenv_required_seal";
    let root = repo_root();
    let entry = fixture_entry(&root, GOLDEN);
    let out = crate::support::scratch_root().join("ipec_app_settings_fromenv_required_seal_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "`App.fromEnvRequired` must be accepted and emit a buildable crate, got: {built:?}"
    );

    crate::support::assert_seal_builds(GOLDEN, &out);
}

/// THE SEAL (item 3): `Console.adminToken` / `ingestToken` / `metricsToken` —
/// the previously-bare env tokens given `Secret`-typed settings — are accepted
/// (exit 0) and (under `IPE_E2E=1`) the emitted crate `cargo build`s.
#[test]
fn console_token_settings_seal_builds() {
    const GOLDEN: &str = "app_settings_console_token_seal";
    let root = repo_root();
    let entry = fixture_entry(&root, GOLDEN);
    let out = crate::support::scratch_root().join("ipec_app_settings_console_token_seal_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "`Console.adminToken`/`ingestToken`/`metricsToken` must be accepted and emit \
         a buildable crate, got: {built:?}"
    );

    crate::support::assert_seal_builds(GOLDEN, &out);
}

/// A hard-coded `String` token passed to `Console.adminToken` (which requires a
/// `Secret`) MUST be an ipe-time type error — the highest-security gap closed:
/// a console token can only come from `App.fromEnv`/`App.fromEnvRequired`.
#[test]
fn hard_coded_console_token_is_rejected() {
    const GOLDEN: &str = "app_settings_hardcoded_token_rejected";
    let root = repo_root();
    let entry = fixture_entry(&root, GOLDEN);
    let out = crate::support::scratch_root().join("ipec_app_settings_hardcoded_token_rejected");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert_eq!(
        judge_rejection(&built, IPE_T0001, Some("Secret")),
        Ok(()),
        "a hard-coded `Console.adminToken \"…\"` (a `String`, not a `Secret`) MUST be \
         rejected — a console token can only come from `App.fromEnv`/`fromEnvRequired`"
    );
    assert_eq!(
        emitted_rust(&out),
        None,
        "{GOLDEN}: a rejected build must emit no Rust"
    );
}

/// A top-level `config` binding beside an inline `Web.appWith [ … ] { … }` MUST
/// be an ipe-time error (IPE-N0043). The inline settings list already supplies
/// the app's configuration; the sibling `config` has nowhere to be threaded and
/// its settings would be silently dropped.
#[test]
fn config_binding_beside_inline_appwith_is_rejected() {
    const GOLDEN: &str = "app_settings_config_beside_inline_appwith";
    let root = repo_root();
    let entry = fixture_entry(&root, GOLDEN);
    let out = crate::support::scratch_root().join("ipec_app_settings_config_beside_inline_appwith");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert_eq!(
        judge_rejection(&built, IPE_N0043, None),
        Ok(()),
        "a `config` binding beside an inline `Web.appWith` MUST be rejected (IPE-N0043) — \
         its settings would otherwise be silently dropped"
    );
    assert_eq!(
        emitted_rust(&out),
        None,
        "{GOLDEN}: a rejected build must emit no Rust"
    );
}

/// Every `tests/golden/app_settings_*` fixture this module proves accepted.
const ACCEPTED: &[&str] = &[
    "app_settings_web_seal",
    "app_settings_auth_max_lifetime_seal",
    "app_settings_auth_slide_window_seal",
    "app_settings_auth_revocation_seal",
    "app_settings_config_binding",
    "app_settings_fromenv_required_seal",
    "app_settings_console_token_seal",
];

/// Every `tests/golden/app_settings_*` fixture this module proves rejected, one
/// per rejected `#[test]` above, each pinned there to its exact code.
const REJECTED: &[&str] = &[
    "app_settings_hardcoded_secret_rejected",
    "app_settings_non_setting_rejected",
    "app_settings_bare_int_host_rejected",
    "app_settings_bare_int_csrf_rejected",
    "app_settings_bare_int_loglevel_rejected",
    "app_settings_discarded_config_rejected",
    "app_settings_hardcoded_token_rejected",
    "app_settings_config_beside_inline_appwith",
];

/// The golden-directory prefix this module owns.
const FIXTURE_PREFIX: &str = "app_settings_";

/// Why a build outcome is not the pinned refusal.
#[derive(Debug, PartialEq, Eq)]
pub enum RejectionFault {
    /// The build was accepted.
    Accepted,
    /// The build failed without a pipeline diagnostic — a missing or unreadable
    /// fixture, an absent runtime, an I/O error. Carries the error's `Debug`.
    NotADiagnostic(String),
    /// The build was refused with a different diagnostic code.
    WrongCode { expected: Code, found: Code },
    /// The refusal is not a type mismatch, so the fragment cannot be checked.
    NotATypeMismatch { code: Code },
    /// Neither side of the type mismatch renders the pinned fragment.
    MissingFragment {
        fragment: &'static str,
        expected: String,
        found: String,
    },
}

/// Judge `result` as the pinned refusal: a pipeline diagnostic carrying exactly
/// `expected`, and — when `fragment` is set — a type mismatch whose expected or
/// found type renders `fragment`. Any other outcome is a fault, so a fixture
/// that fails to load can never pass as "rejected".
pub fn judge_rejection(
    result: &Result<(), CliError>,
    expected: Code,
    fragment: Option<&'static str>,
) -> Result<(), RejectionFault> {
    let diag = match result {
        Ok(()) => return Err(RejectionFault::Accepted),
        Err(CliError::Pipeline { diag, .. }) => diag,
        Err(other) => return Err(RejectionFault::NotADiagnostic(format!("{other:?}"))),
    };
    let found = diag.code();
    if found != expected {
        return Err(RejectionFault::WrongCode { expected, found });
    }
    let Some(fragment) = fragment else {
        return Ok(());
    };
    let Diagnostic::Type {
        msg:
            TypeError::TypeMismatch {
                expected: want,
                found: got,
                ..
            },
        ..
    } = &**diag
    else {
        return Err(RejectionFault::NotATypeMismatch { code: found });
    };
    let (want, got) = (render_ty(want), render_ty(got));
    if want.contains(fragment) || got.contains(fragment) {
        Ok(())
    } else {
        Err(RejectionFault::MissingFragment {
            fragment,
            expected: want,
            found: got,
        })
    }
}

/// The emitted `src/main.rs` under `out`, if any. A rejected build must stop
/// before codegen, so every rejected test asserts this is `None`.
pub fn emitted_rust(out: &Path) -> Option<PathBuf> {
    Some(out.join("src").join("main.rs")).filter(|p| p.exists())
}

/// Why the on-disk fixture set and this module's classification disagree.
#[derive(Debug, PartialEq, Eq)]
enum InventoryFault {
    /// No fixture carries the prefix — the enumeration itself is broken.
    NoneEnumerated,
    /// A fixture on disk that no test classifies (accepted or rejected).
    Unclassified(String),
    /// A classified fixture with no directory on disk.
    Stale(&'static str),
    /// A fixture classified as both accepted and rejected.
    DoublyClassified(&'static str),
}

/// Reconcile the fixture names found on disk against the accepted and rejected
/// classifications, returning how many fixtures are exercised.
fn reconcile(
    on_disk: &[String],
    accepted: &[&'static str],
    rejected: &[&'static str],
) -> Result<usize, InventoryFault> {
    if on_disk.is_empty() {
        return Err(InventoryFault::NoneEnumerated);
    }
    if let Some(both) = accepted.iter().find(|a| rejected.contains(*a)) {
        return Err(InventoryFault::DoublyClassified(both));
    }
    if let Some(stray) = on_disk
        .iter()
        .find(|d| !accepted.contains(&d.as_str()) && !rejected.contains(&d.as_str()))
    {
        return Err(InventoryFault::Unclassified(stray.clone()));
    }
    if let Some(stale) = accepted
        .iter()
        .chain(rejected)
        .find(|c| !on_disk.iter().any(|d| d == *c))
    {
        return Err(InventoryFault::Stale(stale));
    }
    Ok(on_disk.len())
}

/// Every `app_settings_*` golden directory is classified by a test here, every
/// classified name exists on disk, and the count is non-zero — a fixture added
/// without a test, or a test whose fixture vanished, fails instead of passing
/// vacuously.
#[test]
fn every_app_settings_fixture_is_exercised() {
    let golden = repo_root().join("tests").join("golden");
    let entries = std::fs::read_dir(&golden).expect("read tests/golden");
    let mut on_disk: Vec<String> = Vec::new();
    for entry in entries {
        let entry = entry.expect("read a tests/golden entry");
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with(FIXTURE_PREFIX) {
            assert!(
                entry.path().join("Main.ipe").is_file(),
                "{name}: fixture directory has no Main.ipe"
            );
            on_disk.push(name);
        }
    }
    on_disk.sort();
    let exercised = reconcile(&on_disk, ACCEPTED, REJECTED);
    assert_eq!(
        exercised,
        Ok(ACCEPTED.len() + REJECTED.len()),
        "the `app_settings_*` fixtures on disk must match the classified set exactly"
    );
}

fn names(xs: &[&str]) -> Vec<String> {
    xs.iter().map(|s| (*s).to_owned()).collect()
}

/// A build that failed without a diagnostic (here: no runtime — the same shape
/// as a fixture that cannot be loaded) is NOT a refusal.
#[test]
fn judge_rejection_refuses_a_non_diagnostic_error() {
    let r: Result<(), CliError> = Err(CliError::RuntimeNotFound);
    assert!(matches!(
        judge_rejection(&r, IPE_T0001, None),
        Err(RejectionFault::NotADiagnostic(_))
    ));
}

/// An accepted build is not a refusal.
#[test]
fn judge_rejection_refuses_an_accepted_build() {
    assert_eq!(
        judge_rejection(&Ok(()), IPE_T0001, None),
        Err(RejectionFault::Accepted)
    );
}

fn pipeline(diag: Diagnostic) -> Result<(), CliError> {
    Err(CliError::Pipeline {
        file: PathBuf::from("Main.ipe"),
        src: String::new(),
        diag: Box::new(diag),
    })
}

/// A refusal with a different code than the pinned one fails.
#[test]
fn judge_rejection_refuses_a_wrong_code() {
    let r = pipeline(Diagnostic::Name {
        span: Span::DUMMY,
        msg: NameError::DiscardedConfig,
    });
    assert_eq!(
        judge_rejection(&r, IPE_T0001, None),
        Err(RejectionFault::WrongCode {
            expected: IPE_T0001,
            found: IPE_N0043,
        })
    );
    assert_eq!(judge_rejection(&r, IPE_N0043, None), Ok(()));
}

/// A fragment pinned on a non-mismatch refusal fails rather than passing unchecked.
#[test]
fn judge_rejection_refuses_a_fragment_on_a_non_mismatch() {
    let r = pipeline(Diagnostic::Name {
        span: Span::DUMMY,
        msg: NameError::DiscardedConfig,
    });
    assert_eq!(
        judge_rejection(&r, IPE_N0043, Some("Secret")),
        Err(RejectionFault::NotATypeMismatch { code: IPE_N0043 })
    );
}

/// A type mismatch that does not mention the pinned type fails.
#[test]
fn judge_rejection_refuses_a_missing_fragment() {
    let con = |name: &str| TyDoc::Con {
        module: "".into(),
        name: name.into(),
        args: Box::new([]),
    };
    let r = pipeline(Diagnostic::Type {
        span: Span::DUMMY,
        msg: TypeError::TypeMismatch {
            expected: Box::new(con("Int")),
            found: Box::new(con("String")),
            definition: None,
            path: Box::new([]),
        },
    });
    assert!(matches!(
        judge_rejection(&r, IPE_T0001, Some("Secret")),
        Err(RejectionFault::MissingFragment { .. })
    ));
    assert_eq!(judge_rejection(&r, IPE_T0001, Some("String")), Ok(()));
}

/// The inventory refuses an empty enumeration, an unclassified fixture, a stale
/// classification, and a doubly classified name.
#[test]
fn reconcile_refuses_vacuous_and_drifted_inventories() {
    assert_eq!(
        reconcile(&[], &["a"], &["b"]),
        Err(InventoryFault::NoneEnumerated)
    );
    assert_eq!(
        reconcile(&names(&["a", "b", "c"]), &["a"], &["b"]),
        Err(InventoryFault::Unclassified("c".to_owned()))
    );
    assert_eq!(
        reconcile(&names(&["a"]), &["a"], &["b"]),
        Err(InventoryFault::Stale("b"))
    );
    assert_eq!(
        reconcile(&names(&["a"]), &["a"], &["a"]),
        Err(InventoryFault::DoublyClassified("a"))
    );
    assert_eq!(reconcile(&names(&["a", "b"]), &["a"], &["b"]), Ok(2));
}
