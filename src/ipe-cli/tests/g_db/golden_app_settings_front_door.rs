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
    assert!(
        built.is_err(),
        "a hard-coded `Db.url \"postgres://…\"` (a `String`, not a `Secret`) MUST be \
         rejected — the only way to a config secret is `App.fromEnv`"
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
    assert!(
        built.is_err(),
        "a bare `Int` in the `List (Setting Web)` settings slot MUST be rejected — \
         the phantom shape on the settings list is enforced"
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
    assert!(
        built.is_err(),
        "`Host.bind 7` (a bare `Int`, not a `HostMode`) MUST be rejected — the \
         closed `HostMode` ADT makes an out-of-range host-bind tag a type error"
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
    assert!(
        built.is_err(),
        "`Web.csrf 99` (a bare `Int`, not a `CsrfMode`) MUST be rejected — the \
         closed `CsrfMode` ADT makes an out-of-range CSRF tag a type error"
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
    assert!(
        built.is_err(),
        "`Log.level 5` (a bare `Int`, not a `LogLevel`) MUST be rejected — the \
         closed `LogLevel` ADT makes an out-of-range severity tag a type error"
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
    assert!(
        built.is_err(),
        "a `config` binding that no app entry threads MUST be rejected (IPE-N0043) — \
         its settings would otherwise be silently dropped"
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
    assert!(
        built.is_err(),
        "a hard-coded `Console.adminToken \"…\"` (a `String`, not a `Secret`) MUST be \
         rejected — a console token can only come from `App.fromEnv`/`fromEnvRequired`"
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
    assert!(
        built.is_err(),
        "a `config` binding beside an inline `Web.appWith` MUST be rejected (IPE-N0043) — \
         its settings would otherwise be silently dropped"
    );
}
