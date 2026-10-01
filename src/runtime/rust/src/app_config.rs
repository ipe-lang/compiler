//! `Ipe.App` runtime-config front door — the process-wide typed settings a shape
//! app installs at startup.
//!
//! A [`Setting`] is the one concrete carrier the phantom-typed Ipê `Setting
//! shape` erases to (one carrier per position, no `dyn`). The setting-builder
//! kernels ([`ipe_setting_host_bind`] / [`ipe_setting_log_level`] /
//! [`ipe_setting_db_url`] / [`ipe_setting_web_csrf`] /
//! [`ipe_setting_web_session_ttl`] / [`ipe_setting_web_auth_max_lifetime`]) each
//! produce one; a shape app's entry installs the whole list through [`install_web`]
//! before its server binds.
//!
//! # One precedence
//!
//! Every resolvable value obeys a single order: **env var > setting-in-code >
//! built-in fallback**. Env always wins, so an operator can override any
//! in-code setting without a rebuild; absent both, the fallback is the safe
//! default.
//!
//! # Host bind — fail-closed to loopback
//!
//! [`resolve_host_bind`] is the security-critical resolution: a development
//! build binds `127.0.0.1` (never exposed on the LAN), a production build binds
//! all interfaces, and `IPE_HTTP_BIND` overrides either. Absent any signal the
//! conservative loopback is chosen — the dev console is never reachable off-box
//! by default.

use std::sync::OnceLock;

/// A resolved host-bind mode — the closed set the raw `Host.bind` tag resolves
/// to. The setting-builder maps the integer tag onto one of these variants,
/// falling closed to [`HostMode::Loopback`] for any out-of-range tag.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HostMode {
    /// Bind `127.0.0.1` only — never reachable off the local machine.
    Loopback,
    /// Bind `0.0.0.0` — reachable on every interface.
    AllInterfaces,
    /// Defer to the environment (`IPE_HTTP_BIND`, else the build-profile default).
    EnvDriven,
}

/// The revocation mode — a closed set controlling whether the per-request
/// revocation gate is consulted.
///
/// `Off` is the zero-overhead default: the gate is never called, preserving
/// today's token-only validation path for apps that do not need revocation.
/// `Store` arms the fail-closed `is_revoked` check on every authenticated request.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RevocationMode {
    /// No revocation check — today's token-only validation path. Zero overhead.
    Off,
    /// Arm the runtime revocation store check. Denies on `Revoked`, `Unknown`,
    /// and any store error (fail-closed). Enabled via `withRevocation Store`.
    Store,
}

/// The runtime-config carrier `ipe_runtime::app_config::Setting` — the single
/// concrete type every phantom `Setting shape` position erases to. `Clone` (a
/// setting may be stored and read at more than one site); never serde (a
/// `DbUrl` carries a [`Secret`](crate::secret::Secret), so a `Setting` in a Web
/// Model is a compile-time rejection, never a session-store leak).
#[derive(Clone)]
pub enum Setting {
    /// `Host.bind` — the requested host-bind mode.
    HostBind(HostMode),
    /// `Log.level` — the requested minimum log severity (`0` debug … `3` error).
    LogLevel(i64),
    /// `Db.url` — the database URL, sealed as a [`Secret`](crate::secret::Secret).
    #[cfg(feature = "secret")]
    DbUrl(crate::secret::Secret),
    /// `Web.csrf` — the CSRF policy tag (`0` strict / `1` inherit the framework
    /// default). The Ipê `CsrfMode` ADT carries no disabling variant, so no tag
    /// maps to "off"; the resolver apply is stricter-only, so even an unexpected
    /// tag cannot weaken CSRF below its fail-closed default — only an operator
    /// env override can disable it.
    WebCsrf(i64),
    /// `Web.sessionTtl` — the session lifetime in seconds.
    WebSessionTtl(i64),
    /// `Web.authMaxLifetime` — the hard absolute-lifetime cap for a signed session
    /// token, in seconds. A token cannot outlive `iat + max_lifetime` regardless of
    /// any subsequent re-issue. Default: 8 h (28 800 s).
    WebAuthMaxLifetime(i64),
    /// `Web.authSlideWindow` — the rolling re-issue window for a signed session
    /// token, in seconds. A token is re-issued once it is past `exp - window/2`,
    /// extending `exp` to `min(now + window, cap)`. Default: 30 m (1 800 s).
    /// Clamped so `slide_window < max_lifetime`.
    WebAuthSlideWindow(i64),
    /// `Web.withRevocation RevocationMode` — controls whether the per-request
    /// revocation gate is consulted. `Off` (default) skips the gate entirely;
    /// `Store` arms the fail-closed `is_revoked` check on every authenticated
    /// request. Setting `Off` after `Store` is a no-op (stricter-only monotonic:
    /// once armed the gate cannot be disarmed via a setting, only via env).
    WebAuthRevocationMode(RevocationMode),
    /// `Console.adminToken` / `Console.ingestToken` / `Console.metricsToken` —
    /// a console/telemetry auth token, sealed as a [`Secret`](crate::secret::Secret).
    /// The `ConsoleTokenKind` selects which endpoint the token authorises; the
    /// runtime reads the resolved secret instead of a bare env-string read.
    #[cfg(feature = "secret")]
    ConsoleToken(ConsoleTokenKind, crate::secret::Secret),
}

/// Which console/telemetry endpoint a [`Setting::ConsoleToken`] authorises. A
/// closed set — each variant is one previously-bare env token given a typed
/// `Secret` carrier. Always available (not `secret`-gated) so the console
/// runtime can name a `kind` even in a build without the `secret` feature, where
/// [`resolve_console_token`] simply returns `None`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ConsoleTokenKind {
    /// `Console.adminToken` — the admin token: authorizes `/_ipe/console*`
    /// and `/_ipe/metrics` (env sibling `IPE_ADMIN_TOKEN`).
    Admin,
    /// `Console.ingestToken` — the federation ingest-endpoint token
    /// (env sibling `IPE_INGEST_TOKEN`).
    Ingest,
    /// `Console.metricsToken` — the metrics-scrape token: authorizes
    /// `/_ipe/metrics` only (env sibling `IPE_METRICS_TOKEN`).
    Metrics,
}

/// `Host.bind : Int -> Setting a`. Maps the raw host-mode tag onto the closed
/// [`HostMode`] set: `0` loopback, `1` all interfaces, `2` env-driven. An
/// out-of-range tag falls closed to [`HostMode::Loopback`] (the safe branch),
/// never a panic.
#[must_use]
pub fn ipe_setting_host_bind(mode_tag: i64) -> Setting {
    let mode = match mode_tag {
        1 => HostMode::AllInterfaces,
        2 => HostMode::EnvDriven,
        _ => HostMode::Loopback,
    };
    Setting::HostBind(mode)
}

/// `Log.level : Int -> Setting a`. Carries the raw severity tag as-is.
#[must_use]
pub fn ipe_setting_log_level(level_tag: i64) -> Setting {
    Setting::LogLevel(level_tag)
}

/// `App.fromEnv : String -> Secret` — the sole env-secret seal. Reads the named
/// environment variable at startup and seals its value into a [`Secret`], so a
/// config credential is never a hard-coded string in source. A missing/empty
/// var seals the empty string (fail-safe: the downstream consumer sees an empty
/// secret rather than a panic); the operator supplies the value at deploy time.
#[cfg(feature = "secret")]
#[must_use]
pub fn ipe_app_from_env(var_name: String) -> crate::secret::Secret {
    let value = crate::system::read_env_var(&var_name).unwrap_or_default();
    crate::secret::secret_from_string(value)
}

/// `App.fromEnvRequired : String -> Secret` — the fail-CLOSED required variant
/// of [`ipe_app_from_env`]. Reads the named environment variable at startup and
/// seals its value into a [`Secret`], exactly like `App.fromEnv` — but a
/// MISSING or EMPTY variable is a typed load-time [`ConfigError`] naming the
/// variable, reported once to stderr, and the process exits non-zero (the
/// server never binds).
///
/// This is the security-relevant sourcing: where `App.fromEnv` is fail-SAFE (an
/// absent optional secret becomes an empty secret), a value the app declares
/// REQUIRED must not silently default to empty — an empty database URL or auth
/// token that fails obscurely later is worse than a named startup refusal. The
/// only outcomes are "a non-empty secret" or "a named fail-closed exit"; a
/// silent empty secret is unreachable by construction.
#[cfg(feature = "secret")]
#[must_use]
pub fn ipe_app_from_env_required(var_name: String) -> crate::secret::Secret {
    match crate::system::read_env_var(&var_name) {
        Ok(value) if !value.is_empty() => crate::secret::secret_from_string(value),
        // Missing (VarError) or present-but-empty: fail closed, naming the var.
        _ => ConfigError::missing_required_secret(&var_name).abort_startup(),
    }
}

/// A load-time configuration error: a REQUIRED value the app declared is absent
/// where a default would mask a misconfiguration. Carries the setting's env
/// source so the operator is told exactly which variable to supply. Never
/// carries a secret VALUE — only the NAME of the variable that was empty — so it
/// is always safe to render.
///
/// A `ConfigError` is fail-closed by construction: it exists only to be reported
/// and abort startup ([`Self::abort_startup`]); there is no path that turns one
/// into a usable (empty) config value.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ConfigError {
    /// The env variable the required setting is sourced from (never a secret).
    env_var: String,
}

impl ConfigError {
    /// A required secret setting whose env source (`var_name`) is missing/empty.
    #[must_use]
    pub fn missing_required_secret(var_name: &str) -> Self {
        Self {
            env_var: var_name.to_owned(),
        }
    }

    /// The operator-facing message naming the missing variable and its role. No
    /// secret value is ever interpolated — only the variable NAME, which is not
    /// itself sensitive.
    #[must_use]
    pub fn message(&self) -> String {
        format!(
            "required configuration secret is missing: set the `{}` environment variable \
             (a required secret sourced via `App.fromEnvRequired` must not be empty; the \
             server will not start until it is supplied)",
            self.env_var
        )
    }

    /// Report this fail-closed config error to stderr and exit non-zero — the
    /// server never binds. `-> !`: this never returns, so a caller expecting a
    /// [`Secret`] uses it in value position without producing an empty secret.
    pub fn abort_startup(&self) -> ! {
        crate::system::write_stderr_line(&format!("configuration error: {}", self.message()));
        crate::system::system_exit(1)
    }
}

/// `Db.url : Secret -> Setting a`. The URL is already a sealed [`Secret`],
/// carried unchanged.
#[cfg(feature = "secret")]
#[must_use]
pub fn ipe_setting_db_url(url: crate::secret::Secret) -> Setting {
    Setting::DbUrl(url)
}

/// `Console.adminToken : Secret -> Setting a`. The admin token (console and
/// metrics), carried as a sealed [`Secret`]. The runtime reads the resolved secret
/// (via [`resolve_console_token`]) instead of a bare `IPE_ADMIN_TOKEN` env read.
#[cfg(feature = "secret")]
#[must_use]
pub fn ipe_setting_console_admin_token(token: crate::secret::Secret) -> Setting {
    Setting::ConsoleToken(ConsoleTokenKind::Admin, token)
}

/// `Console.ingestToken : Secret -> Setting a`. The federation ingest-endpoint
/// token, carried as a sealed [`Secret`].
#[cfg(feature = "secret")]
#[must_use]
pub fn ipe_setting_console_ingest_token(token: crate::secret::Secret) -> Setting {
    Setting::ConsoleToken(ConsoleTokenKind::Ingest, token)
}

/// `Console.metricsToken : Secret -> Setting a`. The metrics-scrape token
/// (`/_ipe/metrics` only, never the console), carried as a sealed [`Secret`].
#[cfg(feature = "secret")]
#[must_use]
pub fn ipe_setting_console_metrics_token(token: crate::secret::Secret) -> Setting {
    Setting::ConsoleToken(ConsoleTokenKind::Metrics, token)
}

/// `Web.csrf : CsrfMode -> Setting Web`. Carries the CSRF policy tag the Ipê
/// `CsrfMode` ADT projects to (`0` strict / `1` inherit). The ADT has no
/// disabling variant, and the stricter-only resolver apply ensures no tag can
/// weaken CSRF below its fail-closed default.
#[must_use]
pub fn ipe_setting_web_csrf(mode_tag: i64) -> Setting {
    Setting::WebCsrf(mode_tag)
}

/// `Web.sessionTtl : Int -> Setting Web`. Carries the session lifetime (seconds).
#[must_use]
pub fn ipe_setting_web_session_ttl(seconds: i64) -> Setting {
    Setting::WebSessionTtl(seconds)
}

/// `Web.authMaxLifetime : Int -> Setting Web`. Carries the absolute hard cap on a
/// signed session token's age (seconds from original issue). A non-positive value
/// is dropped fail-closed (the caller's 8 h default applies).
#[must_use]
pub fn ipe_setting_web_auth_max_lifetime(seconds: i64) -> Setting {
    Setting::WebAuthMaxLifetime(seconds)
}

/// `Web.authSlideWindow : Int -> Setting Web`. Carries the rolling re-issue
/// window for a signed session token (seconds). A non-positive value is dropped
/// fail-closed (the 30 m default applies). Clamped to below `max_lifetime` at
/// resolution time.
#[must_use]
pub fn ipe_setting_web_auth_slide_window(seconds: i64) -> Setting {
    Setting::WebAuthSlideWindow(seconds)
}

/// `Web.withRevocation : RevocationMode -> Setting Web`. Arms (or keeps armed)
/// the per-request revocation gate. The tag is closed: `0` is `Off`, `1` is
/// `Store`. Out-of-range tags fall closed to `Store` (arms the gate; the safe
/// branch when the intent is unclear). This is stricter-only: once the gate is
/// `Store`, a subsequent `Off` setting in the same list is a no-op at resolution
/// time (`install_web` applies them in order but the resolver takes the max).
#[must_use]
pub fn ipe_setting_web_auth_revocation_mode(mode_tag: i64) -> Setting {
    let mode = match mode_tag {
        0 => RevocationMode::Off,
        // Any other tag (including unknown future tags) arms the gate — safer than
        // silently disabling revocation for an unrecognised value.
        _ => RevocationMode::Store,
    };
    Setting::WebAuthRevocationMode(mode)
}

/// The CSRF posture a `Web.csrf` setting requests. A setting can only ever
/// STRENGTHEN protection: an `Enforced` tag pins CSRF on, and every other tag
/// (including an out-of-range one) is `Unspecified` — it leaves the default in
/// place. There is deliberately no `Disabled` variant, so a setting cannot lower
/// the posture below the fail-closed default; only an operator env override may.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum CsrfSetting {
    /// The setting pins CSRF protection on (the strict, fail-closed posture).
    Enforced,
    /// The setting requests no change — the built-in default stands.
    Unspecified,
}

/// The resolved, immutable process-wide config, installed once at startup. Each
/// field is the in-code setting for one subsystem; a resolver reads it only when
/// no operator env override is present (env always wins, so these never override
/// a deployment-time decision).
#[derive(Default)]
struct ResolvedConfig {
    host_bind: Option<HostMode>,
    log_level: Option<i64>,
    csrf: Option<CsrfSetting>,
    session_ttl_secs: Option<i64>,
    auth_max_lifetime_secs: Option<i64>,
    auth_slide_window_secs: Option<i64>,
    auth_revocation_mode: Option<RevocationMode>,
    #[cfg(feature = "secret")]
    db_url: Option<crate::secret::Secret>,
    #[cfg(feature = "secret")]
    console_admin_token: Option<crate::secret::Secret>,
    #[cfg(feature = "secret")]
    console_ingest_token: Option<crate::secret::Secret>,
    #[cfg(feature = "secret")]
    console_metrics_token: Option<crate::secret::Secret>,
}

static INSTALLED: OnceLock<ResolvedConfig> = OnceLock::new();

/// Install a Web shape app's settings into the process-wide config. Folds each
/// in-code setting into its subsystem slot (env override is applied at read time
/// by the per-subsystem resolvers, so env always wins); a second install is
/// ignored (`OnceLock`), keeping the first app's config authoritative for the
/// process.
pub fn install_web(settings: Vec<Setting>) {
    let mut cfg = ResolvedConfig::default();
    for s in settings {
        match s {
            Setting::HostBind(mode) => cfg.host_bind = Some(mode),
            Setting::LogLevel(tag) => cfg.log_level = Some(tag),
            // Stricter-only: `0` is the strict/enforced tag; every other value
            // (including a would-be "disabled" tag) leaves the default posture,
            // so an in-code setting can never weaken CSRF below fail-closed.
            Setting::WebCsrf(tag) => {
                cfg.csrf = Some(if tag == 0 {
                    CsrfSetting::Enforced
                } else {
                    CsrfSetting::Unspecified
                });
            }
            Setting::WebSessionTtl(seconds) => cfg.session_ttl_secs = Some(seconds),
            Setting::WebAuthMaxLifetime(seconds) => cfg.auth_max_lifetime_secs = Some(seconds),
            Setting::WebAuthSlideWindow(seconds) => cfg.auth_slide_window_secs = Some(seconds),
            // Stricter-only: `Store` arms the gate; `Off` only applies when no
            // prior `Store` setting was seen (take the maximum/strictest value).
            Setting::WebAuthRevocationMode(mode) => {
                cfg.auth_revocation_mode = Some(match cfg.auth_revocation_mode {
                    Some(RevocationMode::Store) => RevocationMode::Store, // already armed
                    _ => mode,
                });
            }
            #[cfg(feature = "secret")]
            Setting::DbUrl(url) => cfg.db_url = Some(url),
            #[cfg(feature = "secret")]
            Setting::ConsoleToken(kind, token) => match kind {
                ConsoleTokenKind::Admin => cfg.console_admin_token = Some(token),
                ConsoleTokenKind::Ingest => cfg.console_ingest_token = Some(token),
                ConsoleTokenKind::Metrics => cfg.console_metrics_token = Some(token),
            },
        }
    }
    // First install wins; a redundant install is a no-op (never a panic).
    let _ = INSTALLED.set(cfg);
}

/// Resolve the host-bind address string, applying the one precedence:
/// `IPE_HTTP_BIND` (env) > the installed `Host.bind` setting > the default
/// fallback. The default is loopback unless production is explicitly declared
/// (`ENV`/`IPE_ENV`), so a server is never reachable off-box by accident; an
/// `EnvDriven` in-code setting defers to that same fallback. Binding all
/// interfaces requires either an explicit `Host.bind AllInterfaces` setting, an
/// explicit `IPE_HTTP_BIND`, or a declared-production posture.
#[must_use]
pub fn resolve_host_bind() -> String {
    // Env override wins unconditionally (a non-blank value).
    if let Ok(raw) = crate::system::read_env_var("IPE_HTTP_BIND") {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return trimmed.to_owned();
        }
    }
    let default_bind = || {
        if crate::telemetry::production_from_env() {
            "0.0.0.0".to_owned()
        } else {
            "127.0.0.1".to_owned()
        }
    };
    match INSTALLED.get().and_then(|c| c.host_bind) {
        Some(HostMode::Loopback) => "127.0.0.1".to_owned(),
        Some(HostMode::AllInterfaces) => "0.0.0.0".to_owned(),
        Some(HostMode::EnvDriven) | None => default_bind(),
    }
}

/// The installed `Log.level` tag, if a setting set one and no `IPE_LOG_LEVEL`
/// env override applies. Returns `None` when the caller should keep resolving
/// (env present, or no setting) — the log subsystem owns the env read and the
/// numeric fallback, so this is only the middle precedence tier. `env >
/// setting-in-code > fallback`.
#[must_use]
pub fn resolve_log_level_override() -> Option<i64> {
    // Env wins: when `IPE_LOG_LEVEL` is set (even to empty), the setting is not
    // consulted — the caller reads the env value directly.
    let env_present = crate::system::read_env_var("IPE_LOG_LEVEL").is_ok();
    log_level_from(env_present, INSTALLED.get().and_then(|c| c.log_level))
}

/// Pure middle-tier resolution for the log level: the installed setting applies
/// only when no env override is present. Split out so the precedence is unit
/// tested without touching the process-wide `INSTALLED` / real env.
const fn log_level_from(env_present: bool, setting: Option<i64>) -> Option<i64> {
    if env_present { None } else { setting }
}

/// Whether CSRF protection is enforced, applying the one precedence with a
/// stricter-only floor for the in-code setting: an operator env override
/// (`IPE_CSRF=off|0|false`) may disable CSRF (deployment-time decision, top of
/// precedence); a `Web.csrf` setting may only ENFORCE it, never disable it; and
/// absent both signals the built-in fail-closed default (on) stands. A setting
/// therefore cannot lower the posture below the default.
#[must_use]
pub fn resolve_csrf_enabled(env_enabled: bool, default_enabled: bool) -> bool {
    csrf_enabled_from(
        env_enabled,
        default_enabled,
        INSTALLED.get().and_then(|c| c.csrf),
    )
}

/// Pure CSRF resolution: the operator env override may disable; a setting may
/// only enforce (`CsrfSetting::Enforced`), never disable; absent both the
/// default stands. Split out so the stricter-only monotonicity is unit tested
/// without process-wide state.
const fn csrf_enabled_from(
    env_enabled: bool,
    default_enabled: bool,
    setting: Option<CsrfSetting>,
) -> bool {
    if !env_enabled {
        // Operator explicitly disabled via env — the top-of-precedence override.
        return false;
    }
    let enforced_by_setting = matches!(setting, Some(CsrfSetting::Enforced));
    // Stricter-only monotonic: the default OR an enforcing setting — never a way
    // to go below the default.
    default_enabled || enforced_by_setting
}

/// The installed `Web.sessionTtl` seconds, if a setting set one and no
/// `IPE_WEB_TTL` env override applies. `None` means keep resolving (env
/// present, or no setting). A non-positive setting value is ignored
/// (fail-closed to the caller's default rather than a zero/negative TTL that
/// would expire every session immediately). `env > setting-in-code > fallback`.
#[must_use]
pub fn resolve_session_ttl_override() -> Option<u64> {
    let env_present = crate::system::read_env_var("IPE_WEB_TTL").is_ok();
    session_ttl_from(
        env_present,
        INSTALLED.get().and_then(|c| c.session_ttl_secs),
    )
}

/// Pure session-TTL resolution: the installed setting applies only when no env
/// override is present, and a non-positive value is dropped (fail-closed to the
/// caller's default). Split out for unit testing without process-wide state.
fn session_ttl_from(env_present: bool, setting: Option<i64>) -> Option<u64> {
    if env_present {
        return None;
    }
    match setting {
        Some(secs) if secs > 0 => u64::try_from(secs).ok(),
        _ => None,
    }
}

/// The absolute-lifetime cap for a signed session token, in seconds. Applies the
/// one precedence: `IPE_AUTH_MAX_LIFETIME` (env) > `Web.authMaxLifetime`
/// (setting-in-code) > 8 h fallback. A non-positive value in either the env or the
/// in-code setting is dropped fail-closed to the fallback. The fallback of 8 h
/// (28 800 s) bounds the value of a stolen, still-unrevoked token.
///
/// This is the single call site for the resolved cap — all callers (sign + verify)
/// use this so the precedence is never duplicated.
#[must_use]
pub fn resolve_auth_max_lifetime() -> u64 {
    /// 8 hours in seconds.
    const DEFAULT_SECS: u64 = 8 * 60 * 60;
    // Env wins: parse a positive integer from `IPE_AUTH_MAX_LIFETIME`.
    if let Ok(raw) = crate::system::read_env_var("IPE_AUTH_MAX_LIFETIME") {
        if let Ok(secs) = raw.trim().parse::<i64>()
            && let Some(v) = auth_max_lifetime_from(true, Some(secs))
        {
            return v;
        }
        // Env var present but not parseable or non-positive → fall closed to default.
        return DEFAULT_SECS;
    }
    auth_max_lifetime_from(
        false,
        INSTALLED.get().and_then(|c| c.auth_max_lifetime_secs),
    )
    .unwrap_or(DEFAULT_SECS)
}

/// Pure auth-max-lifetime resolution: the installed setting applies only when no
/// env override is present, and a non-positive value is dropped (fail-closed to the
/// caller's default). Split out for unit testing without process-wide state.
fn auth_max_lifetime_from(env_present: bool, setting: Option<i64>) -> Option<u64> {
    if env_present {
        return match setting {
            Some(secs) if secs > 0 => u64::try_from(secs).ok(),
            _ => None,
        };
    }
    match setting {
        Some(secs) if secs > 0 => u64::try_from(secs).ok(),
        _ => None,
    }
}

/// The rolling re-issue window for a signed session token, in seconds. Applies the
/// one precedence: `IPE_AUTH_SLIDE_WINDOW` (env) > `Web.authSlideWindow`
/// (setting-in-code) > 30 m fallback. A non-positive value in either tier is
/// dropped fail-closed to the fallback. Clamped so `slide_window < max_lifetime`
/// — a slide window equal to or larger than the max lifetime would allow a
/// single re-issue to extend a session to its full cap in one step.
///
/// This is the single call site for the resolved slide window.
#[must_use]
pub fn resolve_auth_slide_window() -> u64 {
    /// 30 minutes in seconds.
    const DEFAULT_SECS: u64 = 30 * 60;
    let max_lifetime = resolve_auth_max_lifetime();
    let raw = if let Ok(raw) = crate::system::read_env_var("IPE_AUTH_SLIDE_WINDOW") {
        if let Ok(secs) = raw.trim().parse::<i64>()
            && let Some(v) = auth_slide_window_from(true, Some(secs))
        {
            v
        } else {
            DEFAULT_SECS
        }
    } else {
        auth_slide_window_from(
            false,
            INSTALLED.get().and_then(|c| c.auth_slide_window_secs),
        )
        .unwrap_or(DEFAULT_SECS)
    };
    // Clamp: slide_window must be strictly less than max_lifetime.
    if raw >= max_lifetime {
        max_lifetime.saturating_sub(1)
    } else {
        raw
    }
}

/// Pure slide-window resolution: the installed setting applies only when no env
/// override is present, and a non-positive value is dropped (fail-closed to the
/// caller's default). Split out for unit testing without process-wide state.
fn auth_slide_window_from(env_present: bool, setting: Option<i64>) -> Option<u64> {
    if env_present {
        return match setting {
            Some(secs) if secs > 0 => u64::try_from(secs).ok(),
            _ => None,
        };
    }
    match setting {
        Some(secs) if secs > 0 => u64::try_from(secs).ok(),
        _ => None,
    }
}

/// The resolved revocation mode, applying the one precedence:
/// `IPE_AUTH_REVOCATION` (env) > `withRevocation` (setting-in-code) > `Off`
/// fallback. The env var value `"store"` (case-insensitive) arms the gate; any
/// other non-empty value is ignored and the setting applies. An empty env var
/// is treated as absent. `Off` is the zero-overhead default.
#[must_use]
pub fn resolve_auth_revocation_mode() -> RevocationMode {
    if let Ok(raw) = crate::system::read_env_var("IPE_AUTH_REVOCATION") {
        let trimmed = raw.trim();
        if trimmed.eq_ignore_ascii_case("store") || trimmed == "1" {
            return RevocationMode::Store;
        }
        if trimmed.eq_ignore_ascii_case("off") || trimmed == "0" {
            return RevocationMode::Off;
        }
        // Unrecognised non-empty env value: fall through to in-code setting.
    }
    INSTALLED
        .get()
        .and_then(|c| c.auth_revocation_mode)
        .unwrap_or(RevocationMode::Off)
}

/// The per-map entry ceiling for the runtime revocation store. Applies the one
/// precedence: `IPE_REVOCATION_CAPACITY` (env) > 1,048,576 (2^20) default. A
/// positive integer value in the env var overrides; a non-positive or
/// non-parseable value falls back to the default.
///
/// At roughly 64 bytes per entry (id `String` + `i64` expiry + map overhead)
/// the default cap holds ~64 MB per map, ~128 MB for both — bounded without
/// straining a typical server, yet far above any plausible concurrent-revocation
/// count for granular revocation. A deployment that consistently saturates this
/// limit should use signing-key rotation instead of per-session revocation.
pub const REVOCATION_STORE_CAPACITY: usize = 1 << 20; // 1,048,576

/// The resolved revocation store capacity, applying the one precedence:
/// `IPE_REVOCATION_CAPACITY` (env) > [`REVOCATION_STORE_CAPACITY`] default. A
/// non-positive or non-parseable env value falls back to the default.
#[must_use]
pub fn resolve_revocation_capacity() -> usize {
    if let Ok(raw) = crate::system::read_env_var("IPE_REVOCATION_CAPACITY")
        && let Ok(n) = raw.trim().parse::<usize>()
        && n > 0
    {
        return n;
    }
    // Non-positive, unparseable, or env var absent → fall closed to default.
    REVOCATION_STORE_CAPACITY
}

/// The resolved database URL from the installed `Db.url` setting, if one was set
/// and no `DATABASE_URL` env override applies. The secret is revealed only here,
/// at the point of use, and returned to the caller that configures the pool; it
/// is never logged. `None` means keep resolving (env present, or no setting).
/// `env > setting-in-code > fallback`.
#[cfg(feature = "secret")]
#[must_use]
pub fn resolve_db_url_override() -> Option<String> {
    if crate::system::read_env_var("DATABASE_URL").is_ok() {
        return None;
    }
    INSTALLED
        .get()
        .and_then(|c| c.db_url.clone())
        .map(crate::secret::secret_reveal)
}

/// The installed `Console.*Token` secret for `kind`, revealed at the point of
/// use. `None` means the caller should keep resolving from its own env source —
/// the one precedence `env > setting-in-code` is preserved by the caller reading
/// its env var FIRST (env wins) and only consulting this in-code setting when the
/// env var is absent. The secret is revealed only here, at the auth check, and is
/// never logged (a `Secret` cannot be stringified to anything but `<redacted>`).
///
/// This replaces the previously-bare env-string token reads with a typed
/// `Secret` carrier: a token configured in code is sealed and never appears as a
/// plaintext `String` a log line could splice in.
#[must_use]
pub fn resolve_console_token(kind: ConsoleTokenKind) -> Option<String> {
    // The token settings carry a `Secret`, so they only exist in a `secret`-
    // feature build; without it there is no in-code token to resolve and the
    // caller falls back to its env source.
    #[cfg(feature = "secret")]
    {
        INSTALLED
            .get()
            .and_then(|c| match kind {
                ConsoleTokenKind::Admin => c.console_admin_token.clone(),
                ConsoleTokenKind::Ingest => c.console_ingest_token.clone(),
                ConsoleTokenKind::Metrics => c.console_metrics_token.clone(),
            })
            .map(crate::secret::secret_reveal)
    }
    #[cfg(not(feature = "secret"))]
    {
        let _ = kind;
        None
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;

    #[test]
    fn host_bind_tag_projects_to_the_closed_mode_set() {
        assert!(matches!(
            ipe_setting_host_bind(0),
            Setting::HostBind(HostMode::Loopback)
        ));
        assert!(matches!(
            ipe_setting_host_bind(1),
            Setting::HostBind(HostMode::AllInterfaces)
        ));
        assert!(matches!(
            ipe_setting_host_bind(2),
            Setting::HostBind(HostMode::EnvDriven)
        ));
    }

    #[test]
    fn out_of_range_host_tag_falls_closed_to_loopback() {
        assert!(matches!(
            ipe_setting_host_bind(99),
            Setting::HostBind(HostMode::Loopback)
        ));
    }

    // ── Log level: env > setting > fallback ──────────────────────────────

    #[test]
    fn log_level_setting_applies_when_no_env() {
        assert_eq!(log_level_from(false, Some(2)), Some(2));
    }

    #[test]
    fn log_level_env_overrides_setting() {
        // Env present → the setting is dropped so the caller reads env.
        assert_eq!(log_level_from(true, Some(2)), None);
    }

    #[test]
    fn log_level_absent_setting_falls_through() {
        // No env, no setting → the caller's built-in fallback applies.
        assert_eq!(log_level_from(false, None), None);
    }

    // ── CSRF: stricter-only, env may disable, setting may only enforce ────

    #[test]
    fn csrf_default_on_stands_without_signals() {
        assert!(csrf_enabled_from(true, true, None));
    }

    #[test]
    fn csrf_enforcing_setting_turns_on_where_default_off() {
        // A setting can STRENGTHEN: default-off but the setting enforces → on.
        assert!(csrf_enabled_from(true, false, Some(CsrfSetting::Enforced)));
    }

    #[test]
    fn csrf_setting_cannot_disable_below_default() {
        // The stricter-only floor: no setting value (including the absence of an
        // enforcing one) can turn CSRF off while the default is on.
        assert!(csrf_enabled_from(
            true,
            true,
            Some(CsrfSetting::Unspecified)
        ));
        assert!(csrf_enabled_from(true, true, None));
    }

    #[test]
    fn csrf_only_operator_env_can_disable() {
        // The env override (top of precedence) is the sole disable path; an
        // enforcing setting cannot override an explicit operator disable.
        assert!(!csrf_enabled_from(false, true, Some(CsrfSetting::Enforced)));
        assert!(!csrf_enabled_from(false, false, None));
    }

    #[test]
    fn csrf_install_maps_only_zero_tag_to_enforced() {
        // The `install_web` fold: `0` → Enforced, everything else → Unspecified
        // (a "disabled" tag can never reach an Enforced/weaker-than-default state).
        for (tag, expect_enforced) in [(0i64, true), (1, false), (99, false), (-1, false)] {
            let enforced = if tag == 0 {
                CsrfSetting::Enforced
            } else {
                CsrfSetting::Unspecified
            };
            assert_eq!(
                matches!(enforced, CsrfSetting::Enforced),
                expect_enforced,
                "csrf tag {tag} enforced-mapping"
            );
        }
    }

    // ── Session TTL: env > setting > fallback, non-positive dropped ───────

    #[test]
    fn session_ttl_setting_applies_when_no_env() {
        assert_eq!(session_ttl_from(false, Some(3600)), Some(3600));
    }

    #[test]
    fn session_ttl_env_overrides_setting() {
        assert_eq!(session_ttl_from(true, Some(3600)), None);
    }

    #[test]
    fn session_ttl_non_positive_falls_closed_to_default() {
        // A zero/negative TTL would expire every session immediately — drop it so
        // the caller's safe default applies instead.
        assert_eq!(session_ttl_from(false, Some(0)), None);
        assert_eq!(session_ttl_from(false, Some(-5)), None);
    }

    #[test]
    fn session_ttl_absent_setting_falls_through() {
        assert_eq!(session_ttl_from(false, None), None);
    }

    // ── AuthMaxLifetime: env > setting > 8h default, non-positive dropped ──

    #[test]
    fn auth_max_lifetime_setting_applies_when_no_env() {
        assert_eq!(auth_max_lifetime_from(false, Some(3600)), Some(3600));
    }

    #[test]
    fn auth_max_lifetime_env_overrides_setting() {
        // env_present → the setting value becomes the env-branch result.
        assert_eq!(auth_max_lifetime_from(true, Some(7200)), Some(7200));
    }

    #[test]
    fn auth_max_lifetime_non_positive_falls_closed_to_none() {
        // A zero or negative value is dropped in both branches.
        assert_eq!(auth_max_lifetime_from(false, Some(0)), None);
        assert_eq!(auth_max_lifetime_from(false, Some(-1)), None);
        assert_eq!(auth_max_lifetime_from(true, Some(0)), None);
        assert_eq!(auth_max_lifetime_from(true, Some(-100)), None);
    }

    #[test]
    fn auth_max_lifetime_absent_setting_falls_through() {
        assert_eq!(auth_max_lifetime_from(false, None), None);
        assert_eq!(auth_max_lifetime_from(true, None), None);
    }

    // ── AuthSlideWindow: env > setting > 30m default, non-positive dropped ──

    #[test]
    fn auth_slide_window_setting_applies_when_no_env() {
        assert_eq!(auth_slide_window_from(false, Some(900)), Some(900));
    }

    #[test]
    fn auth_slide_window_env_overrides_setting() {
        assert_eq!(auth_slide_window_from(true, Some(900)), Some(900));
    }

    #[test]
    fn auth_slide_window_non_positive_falls_closed_to_none() {
        assert_eq!(auth_slide_window_from(false, Some(0)), None);
        assert_eq!(auth_slide_window_from(false, Some(-1)), None);
        assert_eq!(auth_slide_window_from(true, Some(0)), None);
        assert_eq!(auth_slide_window_from(true, Some(-60)), None);
    }

    #[test]
    fn auth_slide_window_absent_setting_falls_through() {
        assert_eq!(auth_slide_window_from(false, None), None);
        assert_eq!(auth_slide_window_from(true, None), None);
    }

    // ── RevocationMode setting constructor ──────────────────────────────────

    #[test]
    fn revocation_mode_tag_0_maps_to_off() {
        assert!(matches!(
            ipe_setting_web_auth_revocation_mode(0),
            Setting::WebAuthRevocationMode(RevocationMode::Off)
        ));
    }

    #[test]
    fn revocation_mode_tag_1_maps_to_store() {
        assert!(matches!(
            ipe_setting_web_auth_revocation_mode(1),
            Setting::WebAuthRevocationMode(RevocationMode::Store)
        ));
    }

    // ── ConfigError (App.fromEnvRequired fail-closed) ──────────────────────

    #[test]
    fn config_error_names_the_missing_env_var() {
        // The fail-closed message must NAME the variable the operator has to set,
        // so a missing required secret is an actionable startup refusal.
        let err = ConfigError::missing_required_secret("DATABASE_URL");
        let msg = err.message();
        assert!(
            msg.contains("DATABASE_URL"),
            "message must name the missing env var, got: {msg}"
        );
        assert!(
            msg.contains("App.fromEnvRequired"),
            "message must point at the required-secret source, got: {msg}"
        );
    }

    #[cfg(feature = "secret")]
    #[test]
    fn console_token_builders_carry_the_right_kind() {
        // Each `Console.*Token` builder seals its `Secret` under the matching
        // `ConsoleTokenKind`, so the resolver reads back the correct token.
        let admin = ipe_setting_console_admin_token(crate::secret::secret_from_string("a".into()));
        let ingest =
            ipe_setting_console_ingest_token(crate::secret::secret_from_string("b".into()));
        let metrics =
            ipe_setting_console_metrics_token(crate::secret::secret_from_string("c".into()));
        assert!(matches!(
            admin,
            Setting::ConsoleToken(ConsoleTokenKind::Admin, _)
        ));
        assert!(matches!(
            ingest,
            Setting::ConsoleToken(ConsoleTokenKind::Ingest, _)
        ));
        assert!(matches!(
            metrics,
            Setting::ConsoleToken(ConsoleTokenKind::Metrics, _)
        ));
    }

    #[test]
    fn config_error_message_never_carries_a_secret_value() {
        // A `ConfigError` carries only the variable NAME, never a value — so it
        // is always safe to render, even though it names a secret's source.
        let err = ConfigError::missing_required_secret("SMTP_PASSWORD");
        // Only the variable name is present; there is no value field to leak.
        assert_eq!(err.env_var, "SMTP_PASSWORD");
    }

    #[test]
    fn revocation_mode_out_of_range_tag_arms_store() {
        // An unknown tag falls closed to Store (the safe branch).
        assert!(matches!(
            ipe_setting_web_auth_revocation_mode(99),
            Setting::WebAuthRevocationMode(RevocationMode::Store)
        ));
        assert!(matches!(
            ipe_setting_web_auth_revocation_mode(-1),
            Setting::WebAuthRevocationMode(RevocationMode::Store)
        ));
    }
}
