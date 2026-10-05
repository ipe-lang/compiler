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
//! `resolve_host_bind` is the security-critical resolution: a development
//! build binds `127.0.0.1` (never exposed on the LAN), a production build binds
//! all interfaces, and `IPE_HTTP_BIND` (an IP address, else startup refuses)
//! overrides either. Absent any signal the conservative loopback is chosen —
//! the dev console is never reachable off-box by default.

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
    /// It must be below the max lifetime, else startup refuses.
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
/// `resolve_console_token` simply returns `None`.
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
/// (via `resolve_console_token`) instead of a bare `IPE_ADMIN_TOKEN` env read.
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

/// `Web.sessionTtl : Int -> Setting Web`. Carries the session lifetime
/// (seconds); a value that is not positive or exceeds 400 days refuses startup.
#[must_use]
pub fn ipe_setting_web_session_ttl(seconds: i64) -> Setting {
    Setting::WebSessionTtl(seconds)
}

/// `Web.authMaxLifetime : Int -> Setting Web`. Carries the absolute hard cap on a
/// signed session token's age (seconds from original issue). A value that is not
/// positive or exceeds one year refuses startup.
#[must_use]
pub fn ipe_setting_web_auth_max_lifetime(seconds: i64) -> Setting {
    Setting::WebAuthMaxLifetime(seconds)
}

/// `Web.authSlideWindow : Int -> Setting Web`. Carries the rolling re-issue
/// window for a signed session token (seconds). A value that is not positive or
/// not below the max lifetime refuses startup.
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
#[cfg(all(feature = "web-core", feature = "server"))]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum CsrfSetting {
    /// The setting pins CSRF protection on (the strict, fail-closed posture).
    Enforced,
    /// The setting requests no change — the built-in default stands.
    Unspecified,
}

#[cfg(all(feature = "web-core", feature = "server"))]
impl CsrfSetting {
    /// The posture a `Web.csrf` tag requests: only `0` enforces.
    const fn from_tag(tag: i64) -> Self {
        if tag == 0 {
            Self::Enforced
        } else {
            Self::Unspecified
        }
    }
}

/// The resolved, immutable process-wide config, installed once at startup. Each
/// field is the in-code setting for one subsystem; a resolver reads it only when
/// no operator env override is present (env always wins, so these never override
/// a deployment-time decision). A field exists only in a build that compiles
/// its reader.
#[derive(Default)]
struct ResolvedConfig {
    #[cfg(feature = "server")]
    host_bind: Option<HostMode>,
    log_level: Option<i64>,
    #[cfg(all(feature = "web-core", feature = "server"))]
    csrf: Option<CsrfSetting>,
    #[cfg(all(feature = "web-core", feature = "server"))]
    session_ttl_secs: Option<i64>,
    #[cfg(feature = "jwt")]
    auth_max_lifetime_secs: Option<i64>,
    #[cfg(all(feature = "jwt", feature = "server"))]
    auth_slide_window_secs: Option<i64>,
    auth_revocation_mode: Option<RevocationMode>,
    #[cfg(feature = "db")]
    db_url: Option<crate::secret::Secret>,
    #[cfg(all(feature = "secret", feature = "web-core", feature = "server"))]
    console_admin_token: Option<crate::secret::Secret>,
    #[cfg(all(feature = "secret", feature = "web-core", feature = "server"))]
    console_ingest_token: Option<crate::secret::Secret>,
    #[cfg(all(feature = "secret", feature = "web-core", feature = "server"))]
    console_metrics_token: Option<crate::secret::Secret>,
}

static INSTALLED: OnceLock<ResolvedConfig> = OnceLock::new();

/// Install a Web shape app's settings into the process-wide config. Folds each
/// in-code setting into its subsystem slot (env override is applied at read time
/// by the per-subsystem resolvers, so env always wins); a second install is
/// ignored (`OnceLock`), keeping the first app's config authoritative for the
/// process. A setting whose reader this build does not compile is not stored.
pub fn install_web(settings: Vec<Setting>) {
    let mut cfg = ResolvedConfig::default();
    for s in settings {
        match s {
            #[cfg(feature = "server")]
            Setting::HostBind(mode) => cfg.host_bind = Some(mode),
            // No reader in this build.
            #[cfg(not(feature = "server"))]
            Setting::HostBind(_) => {}
            Setting::LogLevel(tag) => cfg.log_level = Some(tag),
            // Stricter-only: `0` is the strict/enforced tag; every other value
            // (including a would-be "disabled" tag) leaves the default posture,
            // so an in-code setting can never weaken CSRF below fail-closed.
            #[cfg(all(feature = "web-core", feature = "server"))]
            Setting::WebCsrf(tag) => cfg.csrf = Some(CsrfSetting::from_tag(tag)),
            #[cfg(all(feature = "web-core", feature = "server"))]
            Setting::WebSessionTtl(seconds) => cfg.session_ttl_secs = Some(seconds),
            // No reader in this build.
            #[cfg(not(all(feature = "web-core", feature = "server")))]
            Setting::WebCsrf(_) | Setting::WebSessionTtl(_) => {}
            #[cfg(feature = "jwt")]
            Setting::WebAuthMaxLifetime(seconds) => cfg.auth_max_lifetime_secs = Some(seconds),
            // No reader in this build.
            #[cfg(not(feature = "jwt"))]
            Setting::WebAuthMaxLifetime(_) => {}
            #[cfg(all(feature = "jwt", feature = "server"))]
            Setting::WebAuthSlideWindow(seconds) => cfg.auth_slide_window_secs = Some(seconds),
            // No reader in this build.
            #[cfg(not(all(feature = "jwt", feature = "server")))]
            Setting::WebAuthSlideWindow(_) => {}
            // Stricter-only: `Store` arms the gate; `Off` only applies when no
            // prior `Store` setting was seen (take the maximum/strictest value).
            Setting::WebAuthRevocationMode(mode) => {
                cfg.auth_revocation_mode = Some(match cfg.auth_revocation_mode {
                    Some(RevocationMode::Store) => RevocationMode::Store, // already armed
                    _ => mode,
                });
            }
            #[cfg(feature = "db")]
            Setting::DbUrl(url) => cfg.db_url = Some(url),
            // No reader in this build.
            #[cfg(all(feature = "secret", not(feature = "db")))]
            Setting::DbUrl(_) => {}
            #[cfg(all(feature = "secret", feature = "web-core", feature = "server"))]
            Setting::ConsoleToken(kind, token) => match kind {
                ConsoleTokenKind::Admin => cfg.console_admin_token = Some(token),
                ConsoleTokenKind::Ingest => cfg.console_ingest_token = Some(token),
                ConsoleTokenKind::Metrics => cfg.console_metrics_token = Some(token),
            },
            // No reader in this build.
            #[cfg(all(feature = "secret", not(all(feature = "web-core", feature = "server"))))]
            Setting::ConsoleToken(..) => {}
        }
    }
    // First install wins; a redundant install is a no-op (never a panic).
    let _ = INSTALLED.set(cfg);
}

/// The variable that overrides the bind host.
#[cfg(feature = "server")]
const HTTP_BIND_VAR: &str = "IPE_HTTP_BIND";

/// What an `IPE_HTTP_BIND` value must be.
#[cfg(feature = "server")]
const HTTP_BIND_EXPECTED: &str = "an IP address (IPv4 such as 127.0.0.1, or bare IPv6 such as ::1)";

/// Resolve the bind host, applying the one precedence: `IPE_HTTP_BIND` (env) >
/// the installed `Host.bind` setting > the default fallback. The default is
/// loopback unless production is explicitly declared (`ENV`/`IPE_ENV`), so a
/// server is never reachable off-box by accident; an `EnvDriven` in-code
/// setting defers to that same fallback. Binding all interfaces requires either
/// an explicit `Host.bind AllInterfaces` setting, an explicit `IPE_HTTP_BIND`,
/// or a declared-production posture.
///
/// # Errors
///
/// A refusal naming `IPE_HTTP_BIND` when it is present but not exactly an IP
/// address: a hostname (`localhost` included), a socket form, brackets, a scope
/// id, padding, or an empty value.
#[cfg(feature = "server")]
pub(crate) fn resolve_host_bind() -> Result<std::net::IpAddr, crate::system::EnvValueRefusal> {
    host_bind_from(
        crate::system::read_env_var(HTTP_BIND_VAR),
        INSTALLED.get().and_then(|c| c.host_bind),
        crate::telemetry::posture_is_production(),
    )
}

/// Pure host-bind resolution over the raw `IPE_HTTP_BIND` lookup, the installed
/// mode and the declared posture.
#[cfg(feature = "server")]
fn host_bind_from(
    raw: Result<String, std::env::VarError>,
    setting: Option<HostMode>,
    production: bool,
) -> Result<std::net::IpAddr, crate::system::EnvValueRefusal> {
    use std::net::{IpAddr, Ipv4Addr};
    let refuse =
        |raw: &[u8]| crate::system::EnvValueRefusal::new(HTTP_BIND_VAR, HTTP_BIND_EXPECTED, raw);
    match raw {
        Ok(value) => {
            return value
                .parse::<IpAddr>()
                .map_err(|_| refuse(value.as_bytes()));
        }
        Err(std::env::VarError::NotUnicode(os)) => return Err(refuse(os.as_encoded_bytes())),
        Err(std::env::VarError::NotPresent) => {}
    }
    let all_interfaces = match setting {
        Some(HostMode::Loopback) => false,
        Some(HostMode::AllInterfaces) => true,
        Some(HostMode::EnvDriven) | None => production,
    };
    Ok(IpAddr::V4(if all_interfaces {
        Ipv4Addr::UNSPECIFIED
    } else {
        Ipv4Addr::LOCALHOST
    }))
}

/// The installed `Log.level` tag, if a setting set one: the middle tier of
/// `env > setting-in-code > fallback`. The log subsystem owns the env tier,
/// from its one startup snapshot of `IPE_LOG_LEVEL`, so this reads no env.
// The vendored emit compiles `log.rs`, its reader, without the `log` feature.
#[cfg_attr(not(feature = "log"), allow(dead_code))]
pub(crate) fn resolve_log_level_override() -> Option<i64> {
    installed_log_level(INSTALLED.get())
}

/// The `Log.level` tag of an installed config.
#[cfg_attr(not(feature = "log"), allow(dead_code))]
fn installed_log_level(cfg: Option<&ResolvedConfig>) -> Option<i64> {
    cfg.and_then(|c| c.log_level)
}

/// Whether CSRF protection is enforced, applying the one precedence with a
/// stricter-only floor for the in-code setting: an operator env override
/// (`IPE_CSRF=off|0|false`) may disable CSRF (deployment-time decision, top of
/// precedence); a `Web.csrf` setting may only ENFORCE it, never disable it; and
/// absent both signals the built-in fail-closed default (on) stands. A setting
/// therefore cannot lower the posture below the default.
#[cfg(all(feature = "web-core", feature = "server"))]
pub(crate) fn resolve_csrf_enabled(env_enabled: bool, default_enabled: bool) -> bool {
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
#[cfg(all(feature = "web-core", feature = "server"))]
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

/// The installed `Web.sessionTtl` seconds, checked against `ttl`'s bound, if a
/// setting set one and no `ttl` env override applies. `None` means keep
/// resolving (env present, or no setting). `env > setting-in-code > fallback`.
///
/// # Errors
///
/// A refusal naming `Web.sessionTtl` when the installed value is not positive
/// or exceeds `ttl`'s bound.
#[cfg(all(feature = "web-core", feature = "server"))]
pub(crate) fn resolve_session_ttl_override(
    ttl: crate::system::EnvDuration,
) -> Result<Option<u64>, crate::system::EnvCeilingRefusal> {
    let env_present = !matches!(ttl.lookup(), Err(std::env::VarError::NotPresent));
    session_ttl_from(
        env_present,
        INSTALLED.get().and_then(|c| c.session_ttl_secs),
        ttl,
    )
}

/// Pure session-TTL resolution: the installed setting applies only when no env
/// override is present, and it must lie within `ttl`'s bound. Split out for
/// unit testing without process-wide state.
#[cfg(all(feature = "web-core", feature = "server"))]
fn session_ttl_from(
    env_present: bool,
    setting: Option<i64>,
    ttl: crate::system::EnvDuration,
) -> Result<Option<u64>, crate::system::EnvCeilingRefusal> {
    if env_present {
        return Ok(None);
    }
    setting
        .map(|secs| ttl.check_setting("Web.sessionTtl", secs))
        .transpose()
}

/// The longest an auth lifetime or window may be set to, in seconds (one year).
#[cfg(feature = "jwt")]
const AUTH_SECONDS_BOUND: u64 = 365 * 24 * 60 * 60;

/// The absolute-lifetime cap of a signed session token, from `IPE_AUTH_MAX_LIFETIME`.
#[cfg(feature = "jwt")]
const AUTH_MAX_LIFETIME_CEILING: crate::system::EnvCeiling = crate::system::EnvCeiling::new(
    "IPE_AUTH_MAX_LIFETIME",
    8 * 60 * 60,
    crate::system::ZeroCeiling::Refused,
    "decimal second count",
)
.at_most(AUTH_SECONDS_BOUND);

/// The rolling re-issue window of a signed session token, from `IPE_AUTH_SLIDE_WINDOW`.
#[cfg(all(feature = "jwt", feature = "server"))]
const AUTH_SLIDE_WINDOW_CEILING: crate::system::EnvCeiling = crate::system::EnvCeiling::new(
    "IPE_AUTH_SLIDE_WINDOW",
    30 * 60,
    crate::system::ZeroCeiling::Refused,
    "decimal second count",
)
.at_most(AUTH_SECONDS_BOUND);

/// One seconds value under the one precedence: `ceiling`'s variable, else the
/// installed `setting`, else the default, each checked against the same bound.
#[cfg(feature = "jwt")]
fn seconds_from(
    ceiling: crate::system::EnvCeiling,
    raw: Result<String, std::env::VarError>,
    setting_name: &'static str,
    setting: Option<i64>,
) -> Result<u64, crate::system::EnvCeilingRefusal> {
    if !matches!(raw, Err(std::env::VarError::NotPresent)) {
        return ceiling.parse(raw);
    }
    setting.map_or_else(
        || ceiling.check_default(),
        |secs| ceiling.check_setting(setting_name, secs),
    )
}

/// The absolute-lifetime cap for a signed session token, in seconds. Applies the
/// one precedence: `IPE_AUTH_MAX_LIFETIME` (env) > `Web.authMaxLifetime`
/// (setting-in-code) > 8 h fallback. The fallback of 8 h (28 800 s) bounds the
/// value of a stolen, still-unrevoked token.
///
/// This is the single call site for the resolved cap — all callers (sign + verify)
/// use this so the precedence is never duplicated.
///
/// # Errors
///
/// A refusal naming `IPE_AUTH_MAX_LIFETIME`, or the `Web.authMaxLifetime`
/// setting, when the value that applies is not a positive second count within
/// one year.
#[cfg(feature = "jwt")]
pub(crate) fn resolve_auth_max_lifetime() -> Result<u64, crate::system::EnvCeilingRefusal> {
    seconds_from(
        AUTH_MAX_LIFETIME_CEILING,
        AUTH_MAX_LIFETIME_CEILING.lookup(),
        "Web.authMaxLifetime",
        INSTALLED.get().and_then(|c| c.auth_max_lifetime_secs),
    )
}

/// The rolling re-issue window for a signed session token, in seconds. Applies the
/// one precedence: `IPE_AUTH_SLIDE_WINDOW` (env) > `Web.authSlideWindow`
/// (setting-in-code) > 30 m fallback. The window must be strictly below the max
/// lifetime — one equal to or larger than it would let a single re-issue extend
/// a session to its full cap in one step — so the bound it is checked against
/// is the lifetime less one second.
///
/// This is the single call site for the resolved slide window.
///
/// # Errors
///
/// A refusal naming `IPE_AUTH_SLIDE_WINDOW` or the `Web.authSlideWindow`
/// setting when the window that applies, the default included, is not a
/// positive second count below the max lifetime; or the
/// [`resolve_auth_max_lifetime`] refusal.
#[cfg(all(feature = "jwt", feature = "server"))]
pub(crate) fn resolve_auth_slide_window() -> Result<u64, crate::system::EnvCeilingRefusal> {
    slide_window_from(
        resolve_auth_max_lifetime()?,
        AUTH_SLIDE_WINDOW_CEILING.lookup(),
        INSTALLED.get().and_then(|c| c.auth_slide_window_secs),
    )
}

/// Pure slide-window resolution below `max_lifetime`.
#[cfg(all(feature = "jwt", feature = "server"))]
fn slide_window_from(
    max_lifetime: u64,
    raw: Result<String, std::env::VarError>,
    setting: Option<i64>,
) -> Result<u64, crate::system::EnvCeilingRefusal> {
    let below_lifetime =
        AUTH_SLIDE_WINDOW_CEILING.at_most(max_lifetime.saturating_sub(1).min(AUTH_SECONDS_BOUND));
    seconds_from(below_lifetime, raw, "Web.authSlideWindow", setting)
}

/// The resolved revocation mode, applying the one precedence:
/// `IPE_AUTH_REVOCATION` (env) > `withRevocation` (setting-in-code) > `Off`
/// fallback. The env var value `"store"` (case-insensitive) arms the gate; any
/// other non-empty value is ignored and the setting applies. An empty env var
/// is treated as absent. `Off` is the zero-overhead default.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "unread until the revocation setting is wired or removed"
    )
)]
pub(crate) fn resolve_auth_revocation_mode() -> RevocationMode {
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
/// precedence: `IPE_REVOCATION_CAPACITY` (env) > 1,048,576 (2^20) default.
///
/// At roughly 64 bytes per entry (id `String` + `i64` expiry + map overhead)
/// the default cap holds ~64 MB per map, ~128 MB for both — bounded without
/// straining a typical server, yet far above any plausible concurrent-revocation
/// count for granular revocation. A deployment that consistently saturates this
/// limit should use signing-key rotation instead of per-session revocation.
pub const REVOCATION_STORE_CAPACITY: usize = 1 << 20; // 1,048,576

/// The per-map entry ceiling of the revocation store, from `IPE_REVOCATION_CAPACITY`.
///
/// The bound is 2^24 entries, about 1 GiB per map at the per-entry cost above.
#[cfg(feature = "jwt")]
const REVOCATION_CAPACITY_CEILING: crate::system::EnvCeiling = crate::system::EnvCeiling::new(
    "IPE_REVOCATION_CAPACITY",
    REVOCATION_STORE_CAPACITY as u64,
    crate::system::ZeroCeiling::Refused,
    "decimal entry count",
)
.at_most(1 << 24);

/// The resolved revocation store capacity, applying the one precedence:
/// `IPE_REVOCATION_CAPACITY` (env) > [`REVOCATION_STORE_CAPACITY`] default.
///
/// # Errors
///
/// A refusal naming `IPE_REVOCATION_CAPACITY` when it is set to anything but a
/// positive decimal entry count of at most 2^24.
#[cfg(feature = "jwt")]
pub(crate) fn resolve_revocation_capacity() -> Result<usize, crate::system::EnvCeilingRefusal> {
    REVOCATION_CAPACITY_CEILING.read()
}

/// Resolves every auth ceiling once, so a malformed one refuses the app at
/// startup (`Server.listen`, `Web.tea`) rather than a later request. The
/// slide window reads the max lifetime it must stay below.
///
/// # Errors
///
/// The first refusal among `IPE_AUTH_MAX_LIFETIME`, `IPE_AUTH_SLIDE_WINDOW`
/// and `IPE_REVOCATION_CAPACITY`, or their in-code settings.
#[cfg(all(feature = "jwt", feature = "server"))]
pub(crate) fn auth_ceilings() -> Result<(), crate::system::EnvCeilingRefusal> {
    resolve_auth_slide_window()?;
    resolve_revocation_capacity()?;
    Ok(())
}

/// The resolved database URL from the installed `Db.url` setting, if one was set
/// and no `DATABASE_URL` env override applies. The secret is revealed only here,
/// at the point of use, and returned to the caller that configures the pool; it
/// is never logged. `None` means keep resolving (env present, or no setting).
/// `env > setting-in-code > fallback`.
#[cfg(feature = "db")]
pub(crate) fn resolve_db_url_override() -> Option<String> {
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
#[cfg(all(feature = "web-core", feature = "server"))]
pub(crate) fn resolve_console_token(kind: ConsoleTokenKind) -> Option<String> {
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

    // ── Log level: the setting tier reads no env ─────────────────────────

    /// The setting tier ignores an `IPE_LOG_LEVEL` written after the log
    /// subsystem's startup snapshot, so env presence has one source.
    #[test]
    fn the_log_level_setting_tier_reads_no_env() {
        let cfg = ResolvedConfig {
            log_level: Some(2),
            ..ResolvedConfig::default()
        };
        crate::system::locked_set_var("IPE_LOG_LEVEL", "error");
        let tag = installed_log_level(Some(&cfg));
        crate::system::locked_remove_var("IPE_LOG_LEVEL");
        assert_eq!(tag, Some(2));
        assert_eq!(installed_log_level(None), None);
    }

    // ── Host bind: an IP address or a startup refusal ─────────────────────

    #[cfg(feature = "server")]
    #[test]
    fn a_bind_that_is_not_exactly_an_ip_address_is_refused() {
        for refused in [
            "not-an-address",
            "localhost",
            "127.0.0.1:8080",
            "[::1]",
            "[::1]:8080",
            "fe80::1%eth0",
            " 127.0.0.1",
            "127.0.0.1 ",
            "",
            " ",
        ] {
            let outcome = host_bind_from(Ok(refused.to_owned()), None, false);
            assert!(
                outcome.as_ref().is_err_and(|r| r.name() == HTTP_BIND_VAR
                    && r.to_string().contains("must be an IP address")),
                "{refused:?} must be refused naming {HTTP_BIND_VAR}, got {outcome:?}"
            );
        }
    }

    #[cfg(feature = "server")]
    #[test]
    fn a_bind_ip_address_wins_over_the_setting_and_the_posture() {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
        let bind =
            |raw: &str| host_bind_from(Ok(raw.to_owned()), Some(HostMode::AllInterfaces), true);
        assert_eq!(bind("127.0.0.1"), Ok(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert_eq!(bind("::1"), Ok(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert_eq!(bind("::"), Ok(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
    }

    #[cfg(feature = "server")]
    #[test]
    fn an_unset_bind_follows_the_setting_then_the_posture() {
        use std::net::{IpAddr, Ipv4Addr};
        let unset = || Err(std::env::VarError::NotPresent);
        let loopback = Ok(IpAddr::V4(Ipv4Addr::LOCALHOST));
        let all = Ok(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(host_bind_from(unset(), None, false), loopback);
        assert_eq!(host_bind_from(unset(), None, true), all);
        assert_eq!(
            host_bind_from(unset(), Some(HostMode::Loopback), true),
            loopback
        );
        assert_eq!(
            host_bind_from(unset(), Some(HostMode::AllInterfaces), false),
            all
        );
        assert_eq!(
            host_bind_from(unset(), Some(HostMode::EnvDriven), false),
            loopback
        );
    }

    #[cfg(all(feature = "server", unix))]
    #[test]
    fn a_non_unicode_bind_is_refused() {
        use std::os::unix::ffi::OsStringExt as _;
        let raw = std::ffi::OsString::from_vec(b"127.0.0.\xFF".to_vec());
        let outcome = host_bind_from(Err(std::env::VarError::NotUnicode(raw)), None, false);
        assert!(outcome.is_err_and(|r| r.to_string().contains("\\xFF")));
    }

    // ── CSRF: stricter-only, env may disable, setting may only enforce ────

    #[cfg(all(feature = "web-core", feature = "server"))]
    #[test]
    fn csrf_default_on_stands_without_signals() {
        assert!(csrf_enabled_from(true, true, None));
    }

    #[cfg(all(feature = "web-core", feature = "server"))]
    #[test]
    fn csrf_enforcing_setting_turns_on_where_default_off() {
        // A setting can STRENGTHEN: default-off but the setting enforces → on.
        assert!(csrf_enabled_from(true, false, Some(CsrfSetting::Enforced)));
    }

    #[cfg(all(feature = "web-core", feature = "server"))]
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

    #[cfg(all(feature = "web-core", feature = "server"))]
    #[test]
    fn csrf_only_operator_env_can_disable() {
        // The env override (top of precedence) is the sole disable path; an
        // enforcing setting cannot override an explicit operator disable.
        assert!(!csrf_enabled_from(false, true, Some(CsrfSetting::Enforced)));
        assert!(!csrf_enabled_from(false, false, None));
    }

    #[cfg(all(feature = "web-core", feature = "server"))]
    #[test]
    fn csrf_install_maps_only_zero_tag_to_enforced() {
        // The `install_web` fold: `0` → Enforced, everything else → Unspecified
        // (a "disabled" tag can never reach an Enforced/weaker-than-default state).
        for (tag, expect_enforced) in [(0i64, true), (1, false), (99, false), (-1, false)] {
            assert_eq!(
                matches!(CsrfSetting::from_tag(tag), CsrfSetting::Enforced),
                expect_enforced,
                "csrf tag {tag} enforced-mapping"
            );
        }
    }

    // ── Session TTL: env > setting > fallback, out of range refused ───────

    /// The session TTL bound `web_ttl` applies: 400 days.
    #[cfg(all(feature = "web-core", feature = "server"))]
    const SESSION_TTL: crate::system::EnvDuration =
        crate::system::EnvDuration::new("IPE_WEB_TTL", 1800, "duration")
            .at_most(400 * 24 * 60 * 60);

    #[cfg(all(feature = "web-core", feature = "server"))]
    #[test]
    fn session_ttl_setting_applies_when_no_env() {
        assert_eq!(
            session_ttl_from(false, Some(3600), SESSION_TTL),
            Ok(Some(3600))
        );
        assert_eq!(
            session_ttl_from(false, Some(400 * 24 * 60 * 60), SESSION_TTL),
            Ok(Some(400 * 24 * 60 * 60))
        );
    }

    #[cfg(all(feature = "web-core", feature = "server"))]
    #[test]
    fn session_ttl_env_overrides_setting() {
        assert_eq!(session_ttl_from(true, Some(3600), SESSION_TTL), Ok(None));
        assert_eq!(session_ttl_from(true, Some(0), SESSION_TTL), Ok(None));
    }

    #[cfg(all(feature = "web-core", feature = "server"))]
    #[test]
    fn session_ttl_out_of_range_setting_is_refused_never_defaulted() {
        use crate::system::CeilingDefect;
        for (secs, defect) in [
            (0, CeilingDefect::Zero),
            (-5, CeilingDefect::Zero),
            (400 * 24 * 60 * 60 + 1, CeilingDefect::TooLarge),
        ] {
            let outcome = session_ttl_from(false, Some(secs), SESSION_TTL);
            assert!(
                outcome
                    .as_ref()
                    .is_err_and(|r| r.setting() == Some("Web.sessionTtl") && r.defect() == defect),
                "a sessionTtl of {secs} must be refused as {defect:?}, got {outcome:?}"
            );
        }
    }

    #[cfg(all(feature = "web-core", feature = "server"))]
    #[test]
    fn session_ttl_absent_setting_falls_through() {
        assert_eq!(session_ttl_from(false, None, SESSION_TTL), Ok(None));
    }

    // ── Auth lifetimes and revocation capacity: env > setting > default ─────

    #[cfg(feature = "jwt")]
    #[test]
    fn an_out_of_range_lifetime_setting_is_refused_never_defaulted() {
        use crate::system::CeilingDefect;
        let unset = || Err(std::env::VarError::NotPresent);
        let lifetime = |secs| {
            seconds_from(
                AUTH_MAX_LIFETIME_CEILING,
                unset(),
                "Web.authMaxLifetime",
                Some(secs),
            )
        };
        for (secs, defect) in [
            (0, CeilingDefect::Zero),
            (-5, CeilingDefect::Zero),
            (-1, CeilingDefect::Zero),
            (31_536_001, CeilingDefect::TooLarge),
        ] {
            let outcome = lifetime(secs);
            assert!(
                outcome.as_ref().is_err_and(
                    |r| r.setting() == Some("Web.authMaxLifetime") && r.defect() == defect
                ),
                "an authMaxLifetime of {secs} must be refused as {defect:?}, got {outcome:?}"
            );
        }
        assert_eq!(lifetime(31_536_000), Ok(31_536_000));
        assert_eq!(lifetime(3600), Ok(3600));
        assert_eq!(
            seconds_from(
                AUTH_MAX_LIFETIME_CEILING,
                unset(),
                "Web.authMaxLifetime",
                None
            ),
            Ok(8 * 60 * 60)
        );
    }

    #[cfg(feature = "jwt")]
    #[test]
    fn an_env_lifetime_wins_over_a_refused_setting() {
        assert_eq!(
            seconds_from(
                AUTH_MAX_LIFETIME_CEILING,
                Ok("7200".to_owned()),
                "Web.authMaxLifetime",
                Some(0)
            ),
            Ok(7200)
        );
    }

    #[cfg(all(feature = "jwt", feature = "server"))]
    #[test]
    fn the_auth_and_revocation_ceilings_honour_the_env_contract() {
        for ceiling in [
            AUTH_MAX_LIFETIME_CEILING,
            AUTH_SLIDE_WINDOW_CEILING,
            REVOCATION_CAPACITY_CEILING,
        ] {
            crate::system::assert_env_ceiling_contract(ceiling);
        }
    }

    /// `resolve` under `name` set to `raw`, the variable removed afterwards.
    #[cfg(feature = "jwt")]
    fn resolve_with<T>(
        name: &str,
        raw: &str,
        resolve: fn() -> Result<T, crate::system::EnvCeilingRefusal>,
    ) -> Result<T, crate::system::EnvCeilingRefusal> {
        crate::system::locked_set_var(name, raw);
        let resolved = resolve();
        crate::system::locked_remove_var(name);
        resolved
    }

    #[cfg(feature = "jwt")]
    #[test]
    fn a_malformed_auth_max_lifetime_is_refused_never_defaulted() {
        let name = "IPE_AUTH_MAX_LIFETIME";
        for refused in ["", "0", "-1", " 3600", "3600 ", "8h", "31536001"] {
            let outcome = resolve_with(name, refused, resolve_auth_max_lifetime);
            assert!(
                outcome.as_ref().is_err_and(|r| r.name() == name),
                "{refused:?} must be refused naming {name}, got {outcome:?}"
            );
        }
        assert_eq!(
            resolve_with(name, "31536000", resolve_auth_max_lifetime),
            Ok(31_536_000)
        );
        assert_eq!(
            resolve_with(name, "7200", resolve_auth_max_lifetime),
            Ok(7200)
        );
        assert_eq!(resolve_auth_max_lifetime(), Ok(8 * 60 * 60));
    }

    #[cfg(all(feature = "jwt", feature = "server"))]
    #[test]
    fn a_malformed_auth_slide_window_is_refused_never_defaulted() {
        let name = "IPE_AUTH_SLIDE_WINDOW";
        for refused in ["", "0", "-60", " 900", "900 ", "15m", "31536001"] {
            let outcome = resolve_with(name, refused, resolve_auth_slide_window);
            assert!(
                outcome.as_ref().is_err_and(|r| r.name() == name),
                "{refused:?} must be refused naming {name}, got {outcome:?}"
            );
        }
        assert_eq!(
            resolve_with(name, "900", resolve_auth_slide_window),
            Ok(900)
        );
        assert_eq!(resolve_auth_slide_window(), Ok(30 * 60));
    }

    #[cfg(all(feature = "jwt", feature = "server"))]
    #[test]
    fn a_slide_window_not_below_the_lifetime_is_refused_never_clamped() {
        use crate::system::CeilingDefect;
        let unset = || Err(std::env::VarError::NotPresent);
        for window in ["1800", "3600"] {
            let outcome = slide_window_from(1800, Ok(window.to_owned()), None);
            assert!(
                outcome
                    .as_ref()
                    .is_err_and(|r| r.name() == "IPE_AUTH_SLIDE_WINDOW"
                        && r.setting().is_none()
                        && r.defect() == CeilingDefect::TooLarge),
                "an env window of {window} under a 1800 s lifetime must be refused, got {outcome:?}"
            );
            assert_eq!(
                outcome.map_err(|r| r.to_string()),
                Err(format!(
                    "IPE_AUTH_SLIDE_WINDOW must be at most 1799 (got \"{window}\")"
                )),
                "the refusal names the bound the lifetime sets"
            );
        }
        for window in [1800, 3600] {
            let outcome = slide_window_from(1800, unset(), Some(window));
            assert!(
                outcome
                    .as_ref()
                    .is_err_and(|r| r.setting() == Some("Web.authSlideWindow")
                        && r.defect() == CeilingDefect::TooLarge),
                "a window setting of {window} under a 1800 s lifetime must be refused, got {outcome:?}"
            );
        }
        let default_over = slide_window_from(1800, unset(), None);
        assert!(
            default_over
                .as_ref()
                .is_err_and(|r| r.name() == "IPE_AUTH_SLIDE_WINDOW"
                    && r.to_string().contains("at most 1799")),
            "the 1800 s default under a 1800 s lifetime must be refused, got {default_over:?}"
        );
        assert_eq!(
            slide_window_from(1800, Ok("1799".to_owned()), None),
            Ok(1799)
        );
        assert_eq!(slide_window_from(1800, unset(), Some(1799)), Ok(1799));
        assert_eq!(slide_window_from(1801, unset(), None), Ok(1800));
        assert!(
            slide_window_from(1, unset(), Some(1)).is_err(),
            "a one-second lifetime leaves no window"
        );
    }

    #[cfg(all(feature = "jwt", feature = "server"))]
    #[test]
    fn the_slide_window_reaches_the_lifetime_refusal() {
        crate::system::locked_set_var("IPE_AUTH_MAX_LIFETIME", "8h");
        let refused = resolve_auth_slide_window();
        crate::system::locked_remove_var("IPE_AUTH_MAX_LIFETIME");
        assert!(
            refused.is_err_and(|r| r.name() == "IPE_AUTH_MAX_LIFETIME"),
            "the window reads the lifetime, so its refusal reaches the window"
        );
    }

    #[cfg(feature = "jwt")]
    #[test]
    fn a_malformed_revocation_capacity_is_refused_never_defaulted() {
        let name = "IPE_REVOCATION_CAPACITY";
        for refused in ["", "0", "-1", " 1024", "1024 ", "1k", "16777217"] {
            let outcome = resolve_with(name, refused, resolve_revocation_capacity);
            assert!(
                outcome.as_ref().is_err_and(|r| r.name() == name),
                "{refused:?} must be refused naming {name}, got {outcome:?}"
            );
        }
        assert_eq!(
            resolve_with(name, "16777216", resolve_revocation_capacity),
            Ok(1 << 24)
        );
        assert_eq!(resolve_revocation_capacity(), Ok(REVOCATION_STORE_CAPACITY));
    }

    #[test]
    fn the_revocation_env_value_arms_or_disarms_the_gate() {
        let name = "IPE_AUTH_REVOCATION";
        crate::system::locked_set_var(name, "store");
        let armed = resolve_auth_revocation_mode();
        crate::system::locked_set_var(name, "off");
        let disarmed = resolve_auth_revocation_mode();
        crate::system::locked_remove_var(name);
        assert_eq!(armed, RevocationMode::Store);
        assert_eq!(disarmed, RevocationMode::Off);
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
