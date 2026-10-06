//! In-process telemetry sink — the data the Ipê Console renders.
//!
//! Always compiled (so `Ipe.Log.*` can feed it regardless of features); the
//! Ipe.Web `console` module exposes it over HTTP. Bounded ring buffers (logs +
//! errors) plus monotonic request/error counters. This is the in-RAM tier of
//! the console, minus the `SQLite` spill.
//!
//! No panic vectors: a poisoned lock recovers via `into_inner()` (the data is
//! plain records — a panic mid-push can't corrupt invariants); all reads/writes
//! are bounded.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(not(all(target_arch = "wasm32", feature = "wasm-client")))]
use std::time::{SystemTime, UNIX_EPOCH};

const LOG_CAP: usize = 1000;
const ERR_CAP: usize = 200;
const SPAN_CAP: usize = 500;

/// One captured log line.
#[derive(Clone)]
pub struct LogEntry {
    pub ts_ms: u64,
    pub level: String,
    pub message: String,
}

/// One completed trace span (Ipe.Trace.span).
#[derive(Clone)]
pub struct SpanEntry {
    pub ts_ms: u64,
    pub name: String,
    pub dur_us: u64,
    pub ok: bool,
}

static LOGS: Mutex<VecDeque<LogEntry>> = Mutex::new(VecDeque::new());
static ERRORS: Mutex<VecDeque<LogEntry>> = Mutex::new(VecDeque::new());
static SPANS: Mutex<VecDeque<SpanEntry>> = Mutex::new(VecDeque::new());
static REQUESTS_TOTAL: AtomicU64 = AtomicU64::new(0);
static ERRORS_TOTAL: AtomicU64 = AtomicU64::new(0);

// `SystemTime::now()` COMPILES on `wasm32-unknown-unknown` (part of std) but
// TRAPS at runtime — no clock without `wasmbind`. That's harmless for the bare
// pure-kernel floor (nothing there calls `record_log`), but once the
// `wasm-client` browser sink makes `Ipe.Log.*` reachable it would be a
// well-typed-program-reachable trap. Route through `js_sys::Date::now()`
// (`Date.now()`) specifically when `wasm-client` is on; the floor-only wasm32
// build (no `wasm-client`, `js-sys` not even a resolvable dependency there)
// keeps the original std path unchanged.
#[cfg(not(all(target_arch = "wasm32", feature = "wasm-client")))]
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

#[cfg(all(target_arch = "wasm32", feature = "wasm-client"))]
fn now_ms() -> u64 {
    js_sys::Date::now() as u64
}

fn push_bounded<T>(ring: &Mutex<VecDeque<T>>, cap: usize, e: T) {
    let mut g = ring
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if g.len() >= cap {
        g.pop_front();
    }
    g.push_back(e);
}

/// Forward a record to the SQLite spill when enabled. A no-op
/// stub keeps this always-compiled sink tokio/sqlx-free when `db` is off.
#[cfg(feature = "db")]
#[inline]
fn spill_log(ts_ms: u64, level: &str, message: &str) {
    crate::telemetry_spill::offer_log(ts_ms, level, message);
}
#[cfg(not(feature = "db"))]
#[inline]
fn spill_log(_ts_ms: u64, _level: &str, _message: &str) {}

#[cfg(feature = "db")]
#[inline]
fn spill_span(ts_ms: u64, name: &str, dur_us: u64, ok: bool) {
    crate::telemetry_spill::offer_span(ts_ms, name, dur_us, ok);
}
#[cfg(not(feature = "db"))]
#[inline]
fn spill_span(_ts_ms: u64, _name: &str, _dur_us: u64, _ok: bool) {}

/// Forward a record to the remote exporters — federation push to the parent
/// ingest and the remote hub OTLP push. `live`-gated; a no-op
/// stub keeps the always-compiled sink reqwest/tokio-free for non-live programs.
/// Each exporter is independently env-gated and a non-blocking drop-on-full
/// offer, so this never blocks or panics the caller.
#[cfg(all(feature = "web", feature = "http_client"))]
#[inline]
fn export_log(ts_ms: u64, level: &str, message: &str) {
    crate::web::push_exporter::offer_log(ts_ms, level, message);
    crate::web::hub_exporter::offer_log(ts_ms, level, message);
}
#[cfg(not(all(feature = "web", feature = "http_client")))]
#[inline]
fn export_log(_ts_ms: u64, _level: &str, _message: &str) {}

#[cfg(all(feature = "web", feature = "http_client"))]
#[inline]
fn export_span(ts_ms: u64, name: &str, dur_us: u64, ok: bool) {
    crate::web::push_exporter::offer_span(ts_ms, name, dur_us, ok);
    crate::web::hub_exporter::offer_span(ts_ms, name, dur_us, ok);
}
#[cfg(not(all(feature = "web", feature = "http_client")))]
#[inline]
fn export_span(_ts_ms: u64, _name: &str, _dur_us: u64, _ok: bool) {}

/// Record a completed trace span (called from `Ipe.Trace.span`).
pub fn record_span(name: &str, dur_us: u64, ok: bool) {
    let ts = now_ms();
    push_bounded(
        &SPANS,
        SPAN_CAP,
        SpanEntry {
            ts_ms: ts,
            name: name.to_string(),
            dur_us,
            ok,
        },
    );
    spill_span(ts, name, dur_us, ok);
    export_span(ts, name, dur_us, ok);
}

/// Most-recent `limit` spans as a JSON array.
pub fn spans_json(limit: usize) -> String {
    let g = SPANS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let n = g.len();
    let items: Vec<String> = g
        .iter()
        .skip(n.saturating_sub(limit))
        .map(|s| {
            format!(
                r#"{{"ts":{},"name":"{}","durUs":{},"ok":{}}}"#,
                s.ts_ms,
                json_escape(&s.name),
                s.dur_us,
                s.ok
            )
        })
        .collect();
    format!("[{}]", items.join(","))
}

/// The raw read of one environment variable, before interpretation.
///
/// Keeps a present-but-non-UTF-8 value distinct from an absent one, so a
/// garbled explicit setting can never fall through to the unset default.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RawEnv<'a> {
    /// The variable is not set.
    Absent,
    /// The variable is set to valid UTF-8.
    Value(&'a str),
    /// The variable is set but is not valid UTF-8.
    NotUnicode,
}

// The read's shape only: a set value renders the redaction marker, never the
// variable's content.
impl std::fmt::Debug for RawEnv<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Absent => f.write_str("Absent"),
            Self::Value(_) => write!(f, "Value({})", crate::redact::REDACTED),
            Self::NotUnicode => f.write_str("NotUnicode"),
        }
    }
}

impl<'a> RawEnv<'a> {
    /// Classify an environment read result.
    #[must_use]
    pub fn from_read(read: &'a Result<String, std::env::VarError>) -> Self {
        match read {
            Ok(value) => Self::Value(value),
            Err(std::env::VarError::NotPresent) => Self::Absent,
            Err(std::env::VarError::NotUnicode(_)) => Self::NotUnicode,
        }
    }
}

/// The build intent compiled into this binary.
///
/// The `ipe` verb that built the program picks it: a dev-loop verb enables the
/// `dev-posture` feature, every other build leaves it off. The cargo profile is
/// never consulted, so a debug-profile release artifact is still `Release`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BuildPosture {
    /// Built by a dev-loop verb: an absent `ENV` / `IPE_ENV` reads as `Dev`.
    Development,
    /// Built for release: an absent `ENV` / `IPE_ENV` reads as `Production`.
    Release,
}

impl BuildPosture {
    /// The intent this binary was compiled with.
    pub const COMPILED: Self = if cfg!(feature = "dev-posture") {
        Self::Development
    } else {
        Self::Release
    };
}

/// Whether one HTTP listener is reachable from beyond this host.
///
/// Classified from the IP address a listener binds. Only a loopback address is
/// `Loopback`; a wildcard or any other address, an IPv4-mapped loopback
/// included, is `Exposed`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ListenScope {
    /// Bound to a loopback address: reachable from this host only.
    Loopback,
    /// Bound to anything else, or not known to be loopback.
    Exposed,
}

impl ListenScope {
    /// The scope of a listener bound to `ip`.
    #[must_use]
    pub const fn of(ip: std::net::IpAddr) -> Self {
        if ip.is_loopback() {
            Self::Loopback
        } else {
            Self::Exposed
        }
    }
}

/// The join of every app listener this process has bound.
///
/// Ordered `Unbound < Loopback < Exposed`; a bind only moves it toward
/// `Exposed`, so a later loopback bind never masks an earlier exposed one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProcessScope {
    /// No app listener has been bound yet.
    Unbound,
    /// Every app listener bound so far is loopback.
    Loopback,
    /// At least one app listener is, or may be, reachable from beyond this host.
    Exposed,
}

impl ProcessScope {
    const fn to_byte(self) -> u8 {
        match self {
            Self::Unbound => 0,
            Self::Loopback => 1,
            Self::Exposed => 2,
        }
    }

    /// Decode a stored byte; an out-of-range byte reads `Exposed`.
    const fn from_byte(byte: u8) -> Self {
        match byte {
            0 => Self::Unbound,
            1 => Self::Loopback,
            _ => Self::Exposed,
        }
    }

    /// The scope after one more listener of `bound` scope.
    #[must_use]
    pub const fn join(self, bound: ListenScope) -> Self {
        let next = match bound {
            ListenScope::Loopback => Self::Loopback,
            ListenScope::Exposed => Self::Exposed,
        };
        if next.to_byte() > self.to_byte() {
            next
        } else {
            self
        }
    }

    /// The scope recorded by every [`record_bind`] so far.
    #[must_use]
    pub fn current() -> Self {
        Self::from_byte(PROCESS_SCOPE.load(std::sync::atomic::Ordering::SeqCst))
    }
}

/// The monotone [`ProcessScope`] of this process, as its byte encoding.
static PROCESS_SCOPE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

/// Record an app listener's bind address before it binds, returning its scope.
///
/// Every app bind path (`serve_web`, `Server.listen`) calls this, so the
/// process scope is the join of all of them.
pub fn record_bind(host: std::net::IpAddr) -> ListenScope {
    let scope = ListenScope::of(host);
    let byte = ProcessScope::Unbound.join(scope).to_byte();
    PROCESS_SCOPE.fetch_max(byte, std::sync::atomic::Ordering::SeqCst);
    scope
}

/// The deployment posture of this process.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Posture {
    /// Local development: a dev-intent binary with no non-dev marker set.
    Dev,
    /// Production: every dev-only relaxation stays closed.
    Production,
}

impl Posture {
    /// Parse the posture from the raw `ENV` and `IPE_ENV` reads.
    ///
    /// A `Release` build is `Production` whatever the variables say. In a
    /// `Development` build `ENV` then `IPE_ENV` selects the posture: an
    /// explicit dev marker (`dev`/`development`/`local`, case-insensitive) is
    /// `Dev`; any other explicit value, a non-UTF-8 one included, is
    /// `Production`. An absent or empty variable defers to the next source;
    /// with neither set, the posture is `Dev`.
    #[must_use]
    pub fn parse(env: RawEnv<'_>, ipe_env: RawEnv<'_>, build: BuildPosture) -> Self {
        match build {
            BuildPosture::Release => Self::Production,
            BuildPosture::Development => match selected_marker(env, ipe_env) {
                Selected::Unset | Selected::DevMarker => Self::Dev,
                Selected::Other => Self::Production,
            },
        }
    }

    /// Resolve the posture from the process environment and compiled intent.
    ///
    /// A release binary that reads a dev marker logs, once, that it ignores it.
    #[must_use]
    pub fn from_env() -> Self {
        let env = crate::system::read_env_var("ENV");
        let ipe_env = crate::system::read_env_var("IPE_ENV");
        let (env, ipe_env) = (RawEnv::from_read(&env), RawEnv::from_read(&ipe_env));
        if release_ignores_dev_marker(env, ipe_env, BuildPosture::COMPILED) {
            static DEV_MARKER_NOTICE: std::sync::Once = std::sync::Once::new();
            DEV_MARKER_NOTICE.call_once(|| {
                crate::system::emit_runtime_log("posture", RELEASE_IGNORES_DEV_MARKER);
            });
        }
        Self::parse(env, ipe_env, BuildPosture::COMPILED)
    }

    /// The label logged at startup (`posture=<label>`).
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Dev => "dev",
            Self::Production => "production",
        }
    }
}

/// The one-line notice a release binary logs when it reads a dev marker.
const RELEASE_IGNORES_DEV_MARKER: &str =
    "ENV/IPE_ENV dev marker ignored: a release build always runs in production";

/// What the first non-empty of `ENV` / `IPE_ENV` names.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Selected {
    /// Neither variable holds a non-empty value.
    Unset,
    /// `dev` / `development` / `local`, case-insensitive.
    DevMarker,
    /// Any other value, a non-UTF-8 one included.
    Other,
}

fn selected_marker(env: RawEnv<'_>, ipe_env: RawEnv<'_>) -> Selected {
    for raw in [env, ipe_env] {
        match raw {
            RawEnv::NotUnicode => return Selected::Other,
            RawEnv::Absent | RawEnv::Value("") => {}
            RawEnv::Value(value) => {
                let dev = ["dev", "development", "local"]
                    .iter()
                    .any(|marker| value.eq_ignore_ascii_case(marker));
                return if dev {
                    Selected::DevMarker
                } else {
                    Selected::Other
                };
            }
        }
    }
    Selected::Unset
}

/// Whether a `Release` build is reading a dev marker it ignores.
fn release_ignores_dev_marker(env: RawEnv<'_>, ipe_env: RawEnv<'_>, build: BuildPosture) -> bool {
    build == BuildPosture::Release && selected_marker(env, ipe_env) == Selected::DevMarker
}

/// Proof that this binary has the dev-loop build intent and a dev posture.
///
/// Constructible only through `dev_intent`; not `Clone`/`Copy`, so a
/// consumer borrows it for one decision. Every dev-only relaxation that needs
/// no listener proof (a token-gated route, a dev-only push, non-`Secure`
/// cookies, SSRF deny-private off) takes `Option<&DevIntent>`.
#[derive(Debug)]
pub struct DevIntent(());

/// Proof of [`DevIntent`] and that every app listener of this process is loopback.
///
/// Constructible only through `dev_surface`. Every unauthenticated
/// listener-facing dev surface (console default, token-less ingest, the
/// console banner, the WebSocket origin waiver) takes `Option<&DevSurface>`.
/// Never cached: the process scope can widen after it is minted.
#[derive(Debug)]
pub struct DevSurface {
    _intent: DevIntent,
}

/// A [`DevIntent`] when `build` is `Development` and `posture` is `Dev`.
#[must_use]
pub(crate) const fn dev_intent(build: BuildPosture, posture: Posture) -> Option<DevIntent> {
    match (build, posture) {
        (BuildPosture::Development, Posture::Dev) => Some(DevIntent(())),
        (BuildPosture::Development, Posture::Production) | (BuildPosture::Release, _) => None,
    }
}

/// [`dev_intent`] over the compiled intent and the process posture.
#[must_use]
pub(crate) fn dev_intent_from_env() -> Option<DevIntent> {
    dev_intent(BuildPosture::COMPILED, Posture::from_env())
}

/// A [`DevSurface`] when every app listener of this process is loopback.
///
/// An `Unbound` process has no listener to prove loopback, so it gets none.
#[must_use]
pub(crate) fn dev_surface(intent: DevIntent, scope: ProcessScope) -> Option<DevSurface> {
    match scope {
        ProcessScope::Loopback => Some(DevSurface { _intent: intent }),
        ProcessScope::Unbound | ProcessScope::Exposed => None,
    }
}

/// [`dev_surface`] over [`dev_intent_from_env`] and the recorded process scope.
#[must_use]
pub(crate) fn dev_surface_from_env() -> Option<DevSurface> {
    dev_intent_from_env().and_then(|intent| dev_surface(intent, ProcessScope::current()))
}

/// A [`DevIntent`] for a unit test of a pure `*_with` gate.
#[cfg(all(test, not(target_arch = "wasm32")))]
pub(crate) const fn test_dev_intent() -> DevIntent {
    DevIntent(())
}

/// A [`DevSurface`] for a unit test of a pure `*_with` gate.
#[cfg(all(test, not(target_arch = "wasm32")))]
pub(crate) const fn test_dev_surface() -> DevSurface {
    DevSurface {
        _intent: DevIntent(()),
    }
}

/// Whether the process posture is production, for closing-direction reads only.
///
/// A dev-only relaxation never negates this: it takes a [`DevIntent`] or
/// [`DevSurface`]. The source inventory `tests/posture_read_inventory.rs`
/// admits every caller by name.
#[cfg(any(
    feature = "server",
    all(test, not(target_arch = "wasm32"), not(feature = "dev-posture"))
))]
#[must_use]
pub(crate) fn posture_is_production() -> bool {
    Posture::from_env() == Posture::Production
}

/// The resolved `IPE_CONSOLE_AUTH` setting for the console + metrics surface.
///
/// An explicit value is enforced whatever the posture; the posture only picks
/// the default when the variable is unset or blank. An unrecognised or
/// non-UTF-8 value resolves to `Off` — the surface is refused, never widened.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ConsoleAuthMode {
    /// Surface declared absent (`off`, an unrecognised value, or non-UTF-8).
    Off,
    /// Explicit `token`: an admin token is required in every posture.
    Token,
    /// Explicit `app`: the app-supplied `consoleAuth` callback decides.
    App,
    /// Unset where `dev_surface` fails: an admin token is required.
    UnsetProd,
    /// Unset where `dev_surface` holds: open.
    DevOpen,
}

impl ConsoleAuthMode {
    /// Parse a raw `IPE_CONSOLE_AUTH` value (trimmed, case-insensitive).
    ///
    /// `build`, `posture` and `scope` are consulted only when `raw` is absent
    /// or blank; a non-UTF-8 value resolves to `Off` in every posture.
    #[must_use]
    pub fn parse(
        raw: RawEnv<'_>,
        build: BuildPosture,
        posture: Posture,
        scope: ProcessScope,
    ) -> Self {
        ConsoleAuthResolution::resolve(raw, build, posture, scope).mode
    }

    /// Resolve the setting from the process environment.
    #[must_use]
    pub fn from_env() -> Self {
        ConsoleAuthResolution::from_env().mode
    }

    /// The label logged at console mount (`mode=<label>`).
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Token => "token",
            Self::App => "app",
            Self::UnsetProd => "unset-prod",
            Self::DevOpen => "dev-open",
        }
    }
}

/// Where the effective console-auth mode came from.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ConsoleAuthSource {
    /// `IPE_CONSOLE_AUTH` names a recognised mode, enforced in every posture.
    Explicit,
    /// `IPE_CONSOLE_AUTH` holds an unrecognised or non-UTF-8 value.
    ///
    /// The surface is refused (`Off`).
    Invalid,
    /// `IPE_CONSOLE_AUTH` is unset or blank: posture and scope pick the mode.
    PostureDefault,
}

impl ConsoleAuthSource {
    /// The label logged at startup (`source=<label>`).
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Explicit => "env",
            Self::Invalid => "env-invalid",
            Self::PostureDefault => "posture-default",
        }
    }
}

/// The effective console-auth setting: posture, mode, and the mode's source.
///
/// The single parse of `IPE_CONSOLE_AUTH`; [`ConsoleAuthMode::parse`] and
/// [`ConsoleAuthMode::from_env`] project it. It holds no credential, so
/// nothing derived from it can leak one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ConsoleAuthResolution {
    /// The deployment posture in effect.
    pub posture: Posture,
    /// The effective auth mode.
    pub mode: ConsoleAuthMode,
    /// Whether the mode was set explicitly or defaulted from the posture.
    pub source: ConsoleAuthSource,
}

impl ConsoleAuthResolution {
    /// Resolve a raw `IPE_CONSOLE_AUTH` value (trimmed, case-insensitive).
    ///
    /// `build`, `posture` and `scope` pick the mode only when `raw` is absent
    /// or blank; a recognised explicit value wins in every posture; an
    /// unrecognised or non-UTF-8 value resolves to `Off`.
    #[must_use]
    pub fn resolve(
        raw: RawEnv<'_>,
        build: BuildPosture,
        posture: Posture,
        scope: ProcessScope,
    ) -> Self {
        let default = Self::posture_default(build, posture, scope);
        let (mode, source) = match raw {
            RawEnv::NotUnicode => (ConsoleAuthMode::Off, ConsoleAuthSource::Invalid),
            RawEnv::Absent => (default, ConsoleAuthSource::PostureDefault),
            RawEnv::Value(value) => Self::from_value(value.trim(), default),
        };
        Self {
            posture,
            mode,
            source,
        }
    }

    fn from_value(value: &str, default: ConsoleAuthMode) -> (ConsoleAuthMode, ConsoleAuthSource) {
        if value.is_empty() {
            (default, ConsoleAuthSource::PostureDefault)
        } else if value.eq_ignore_ascii_case("token") {
            (ConsoleAuthMode::Token, ConsoleAuthSource::Explicit)
        } else if value.eq_ignore_ascii_case("app") {
            (ConsoleAuthMode::App, ConsoleAuthSource::Explicit)
        } else if value.eq_ignore_ascii_case("off") {
            (ConsoleAuthMode::Off, ConsoleAuthSource::Explicit)
        } else {
            (ConsoleAuthMode::Off, ConsoleAuthSource::Invalid)
        }
    }

    /// The unset default: open only where [`dev_surface`] holds.
    fn posture_default(
        build: BuildPosture,
        posture: Posture,
        scope: ProcessScope,
    ) -> ConsoleAuthMode {
        if dev_intent(build, posture)
            .and_then(|intent| dev_surface(intent, scope))
            .is_some()
        {
            ConsoleAuthMode::DevOpen
        } else {
            ConsoleAuthMode::UnsetProd
        }
    }

    /// Resolve the setting from the process environment.
    #[must_use]
    pub fn from_env() -> Self {
        let read = crate::system::read_env_var("IPE_CONSOLE_AUTH");
        Self::resolve(
            RawEnv::from_read(&read),
            BuildPosture::COMPILED,
            Posture::from_env(),
            ProcessScope::current(),
        )
    }

    /// The one startup line naming the effective posture, mode, and source.
    ///
    /// Built from labels alone: never a token, its length, or any prefix.
    #[must_use]
    pub fn startup_line(self) -> String {
        format!(
            "[ipe.console] auth posture={} mode={} source={}",
            self.posture.label(),
            self.mode.label(),
            self.source.label()
        )
    }
}

/// Floating "🔍 Console" link injected into every dev-mode `text/html` response
/// — both the Ipe.Web page path and every buffered Ipe.Http.Server response
/// . Lives here (the always-compiled
/// telemetry module) rather than under `live` so the server path (`server.rs`,
/// where the `live` module is DCE'd out of server-only builds) can reach it too.
///
/// Suppressed for a sub-app (`base` non-empty — e.g. the bundled console child
/// itself; a console link inside the console is recursive), without a
/// [`DevSurface`] (it advertises the console, so it agrees with the console
/// default), when the banner is turned off (`IPE_DEV_BANNER=off|0`,
/// ), and when the console surface is disabled (`IPE_CONSOLE_EMBED=off`
/// / `IPE_CONSOLE_AUTH` resolving to `off`). The union of  and the live path's gates —
/// suppression only ever makes bodies match MORE often across odd configs, and
/// the sweep's env (nothing set) hits the injecting path either way.
///
/// Rendered as a sibling of `#ipe-root` on the Web path (so a body patch never
/// blows it away); `position:fixed` pins it bottom-right and `pointer-events`
/// stays default so the link is clickable.
#[must_use]
pub fn dev_console_banner(base: &str) -> String {
    dev_console_banner_with(base, dev_surface_from_env().as_ref())
}

/// [`dev_console_banner`] under an explicit dev-surface proof: `None` is `""`.
#[must_use]
pub(crate) fn dev_console_banner_with(base: &str, dev: Option<&DevSurface>) -> String {
    if !base.is_empty() || dev.is_none() {
        return String::new();
    }
    if matches!(
        crate::system::read_env_var("IPE_DEV_BANNER").as_deref(),
        Ok("off" | "0")
    ) {
        return String::new();
    }
    if matches!(
        crate::system::read_env_var("IPE_CONSOLE_EMBED").as_deref(),
        Ok("off" | "0" | "false")
    ) || ConsoleAuthMode::from_env() == ConsoleAuthMode::Off
    {
        return String::new();
    }
    // The dev banner: fixed id, target/rel/title, monospace blue styling, and
    // the `&#128269;` entity (NOT a literal emoji). href honours
    // `IPE_CONSOLE_URL` (default `/_ipe/console`), attribute-escaped against a
    // hostile env value.
    let url = crate::system::read_env_var("IPE_CONSOLE_URL")
        .map(|v| v.trim().to_string())
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "/_ipe/console".to_string());
    let esc = crate::escape::html_attr(&url);
    format!(
        "<a id=\"__ipe-dev-console\" href=\"{esc}\" target=\"_blank\" rel=\"noopener\" \
         title=\"Ipe Console (dev only)\" \
         style=\"position:fixed;right:12px;bottom:12px;z-index:2147483646;\
         font:12px/1.4 ui-monospace,Menlo,monospace;\
         background:#1c2027;color:#7eb6ff;\
         border:1px solid #353b46;border-radius:6px;\
         padding:6px 10px;text-decoration:none;\
         box-shadow:0 2px 8px rgba(0,0,0,0.4);\">\
         &#128269; Console</a>"
    )
}

/// Insert `banner` just before the LAST case-insensitive `</body>` tag.
/// Falls back to appending when no `</body>` is present (body-only fragments).
/// An empty banner is a no-op.
#[must_use]
pub fn inject_dev_banner(body: &str, banner: &str) -> String {
    if banner.is_empty() {
        return body.to_string();
    }
    let low = body.to_ascii_lowercase();
    // `idx` is the byte offset of the ASCII "</body>" in the lowercased copy;
    // `to_ascii_lowercase` is byte-length-preserving on ASCII and never
    // touches multi-byte UTF-8 lead/continuation bytes, so `idx` is a valid
    // char boundary in `body` too — the `body[..idx]` / `body[idx..]` slices
    // cannot split a codepoint (no panic).
    if let Some(idx) = low.rfind("</body>") {
        let mut out = String::with_capacity(body.len() + banner.len());
        out.push_str(&body[..idx]);
        out.push_str(banner);
        out.push_str(&body[idx..]);
        out
    } else {
        let mut out = String::with_capacity(body.len() + banner.len());
        out.push_str(body);
        out.push_str(banner);
        out
    }
}

/// The environment variable holding the `frame-ancestors` source list.
pub const FRAME_ANCESTORS_ENV: &str = "IPE_WEB_FRAME_ANCESTORS";

/// The `Content-Security-Policy` value `frame-ancestors <sources>` of an
/// operator-configured embed allow-list.
///
/// Built only by [`FrameAncestors::parse`], so the value holds only visible
/// ASCII, spaces and tabs, at least one source, and no `;` or `,`: it is
/// always a header value, and it adds no directive and no second policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrameAncestors(String);

/// Why an `IPE_WEB_FRAME_ANCESTORS` value has no `frame-ancestors` representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameAncestorsRefusal {
    /// A byte outside visible ASCII, space and tab: a control (CR, LF, NUL), DEL,
    /// a non-ASCII byte, or a value that is not UTF-8.
    NotVisibleAscii,
    /// A `;`, which starts another policy directive.
    DirectiveSeparator,
    /// A `,`, which starts another policy.
    PolicySeparator,
    /// Only spaces or tabs: no source at all.
    Blank,
}

impl std::fmt::Display for FrameAncestorsRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let why = match self {
            Self::NotVisibleAscii => {
                "holds a control, DEL or non-ASCII byte (write an internationalised host in its \
                 `xn--` form)"
            }
            Self::DirectiveSeparator => "holds `;`, which would start another policy directive",
            Self::PolicySeparator => "holds `,`, which would start another policy",
            Self::Blank => "holds only whitespace",
        };
        write!(
            f,
            "{FRAME_ANCESTORS_ENV} {why}; set it to space-separated sources such as \
             `https://app.example.com`, or unset it to refuse every embedding"
        )
    }
}

impl std::error::Error for FrameAncestorsRefusal {}

impl FrameAncestors {
    /// Parse a raw `IPE_WEB_FRAME_ANCESTORS` value.
    ///
    /// The empty value is `Ok(None)`: no embedding, as when the variable is
    /// unset. Surrounding spaces and tabs are dropped.
    ///
    /// # Errors
    ///
    /// A [`FrameAncestorsRefusal`] for a value with a byte outside visible
    /// ASCII, space and tab, a `;` or `,`, or only whitespace.
    pub fn parse(raw: &str) -> Result<Option<Self>, FrameAncestorsRefusal> {
        if raw.is_empty() {
            return Ok(None);
        }
        for b in raw.bytes() {
            match b {
                b';' => return Err(FrameAncestorsRefusal::DirectiveSeparator),
                b',' => return Err(FrameAncestorsRefusal::PolicySeparator),
                b'\t' | b' '..=b'~' => {}
                _ => return Err(FrameAncestorsRefusal::NotVisibleAscii),
            }
        }
        let sources = raw.trim_matches([' ', '\t']);
        if sources.is_empty() {
            return Err(FrameAncestorsRefusal::Blank);
        }
        Ok(Some(Self(format!("frame-ancestors {sources}"))))
    }

    /// Parse a lookup of `IPE_WEB_FRAME_ANCESTORS`: absent is `Ok(None)`.
    ///
    /// # Errors
    ///
    /// As [`Self::parse`]; a value that is not UTF-8 is
    /// [`FrameAncestorsRefusal::NotVisibleAscii`].
    pub fn from_lookup(
        raw: &Result<String, std::env::VarError>,
    ) -> Result<Option<Self>, FrameAncestorsRefusal> {
        match raw {
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(std::env::VarError::NotUnicode(_)) => Err(FrameAncestorsRefusal::NotVisibleAscii),
            Ok(v) => Self::parse(v),
        }
    }

    /// The `Content-Security-Policy` header value, `frame-ancestors <sources>`.
    #[must_use]
    pub const fn csp_value(&self) -> &str {
        self.0.as_str()
    }
}

/// The process's parsed `IPE_WEB_FRAME_ANCESTORS`: `Ok(Some)` in
/// cross-origin-iframe mode, `Ok(None)` when unset or empty.
///
/// The one reader of the variable, parsed once into a `OnceLock` so the cookie
/// `SameSite` and the framing header never decide on two different values.
/// `Server.listen` and every `Ipe.Web` router refuse to start on the `Err`.
///
/// Lives in the always-compiled telemetry module so the `Ipe.Http.Server`
/// path reaches it in server-only builds.
///
/// # Errors
///
/// The [`FrameAncestorsRefusal`] of a present, unrepresentable value.
pub fn frame_ancestors_config() -> Result<Option<&'static FrameAncestors>, FrameAncestorsRefusal> {
    use std::sync::OnceLock;
    static FA: OnceLock<Result<Option<FrameAncestors>, FrameAncestorsRefusal>> = OnceLock::new();
    match FA.get_or_init(|| {
        FrameAncestors::from_lookup(&crate::system::read_env_var(FRAME_ANCESTORS_ENV))
    }) {
        Ok(fa) => Ok(fa.as_ref()),
        Err(refusal) => Err(*refusal),
    }
}

/// `Some` when responses run in cross-origin-iframe mode.
///
/// A refused value is `None`: cookies keep the same-site default, and the
/// security headers refuse the response (see [`security_headers`]).
#[must_use]
pub fn frame_ancestors() -> Option<&'static FrameAncestors> {
    frame_ancestors_config().ok().flatten()
}

/// The closed, ordered `Permissions-Policy` directive vocabulary Ipê emits an
/// allowlist for — every powerful feature denied by default. `payment` is a
/// permanent deny (no capability opens it). A granted axis flips its mapped
/// directive from the empty `()` deny to `(self)`.
///
/// SSOT note: the runtime cannot import the compiler's `ipe_kernels`
/// (a native-only DEV dependency — the emitted runtime must not link the
/// compiler), so this vocabulary is mirrored here as plain data and tied to the
/// compiler's `WebCapability::POLICY_DIRECTIVES` by an equality test
/// (`policy_directive_vocabulary_matches_kernels`, native-only where
/// `ipe_kernels` is in scope). The instant either drifts, that test breaks.
const POLICY_DIRECTIVES: &[&str] = &["geolocation", "microphone", "camera", "payment"];

/// The `Permissions-Policy` directive(s) a GRANTED web-capability wire suffix
/// (`WebCapability::as_str`, e.g. `"geolocation"`) opens to `(self)`. Empty for
/// a suffix whose Web API needs no allowance (same-origin clipboard is
/// default-allow; storage / notification / … are not `Permissions-Policy`
/// features) AND for an unrecognised suffix — fail-closed, an unknown grant can
/// only fail to open a feature, never open an unintended one.
///
/// SSOT note: mirrors the compiler's
/// `WebCapability::permissions_policy_directives`, tied by
/// `policy_directive_map_matches_kernels` (native-only). `recorder` reaches
/// both camera and microphone via `getUserMedia`.
fn directives_for_suffix(suffix: &str) -> &'static [&'static str] {
    match suffix {
        "geolocation" => &["geolocation"],
        "camera" => &["camera"],
        "microphone" => &["microphone"],
        "recorder" => &["camera", "microphone"],
        _ => &[],
    }
}

/// The web-capability wire suffixes the compiled app was GRANTED, registered
/// ONCE at startup by the emitted web-app entry
/// ([`register_granted_web_features`]). The served `Permissions-Policy` is
/// derived from this set: a granted axis opens its mapped directive to
/// `(self)`; every other directive stays the empty `()` deny. Snapshotted into
/// a `OnceLock` so the header is stable for the process and cannot be widened
/// after the server binds.
///
/// Unset (never registered) → the empty set → fully denied policy. This is the
/// fail-closed default: absent a proven grant, no powerful feature is allowed.
static GRANTED_WEB_FEATURES: std::sync::OnceLock<std::collections::BTreeSet<String>> =
    std::sync::OnceLock::new();

/// Register the app's GRANTED web-capability set from its wire-suffix names,
/// emitted from the compiler's proven grant. Idempotent: the first registration
/// wins (a `OnceLock`), so a later call can never widen the served
/// `Permissions-Policy`.
///
/// Called once at web-app startup before the server binds.
pub fn register_granted_web_features(suffixes: &[&str]) {
    let set: std::collections::BTreeSet<String> =
        suffixes.iter().map(|s| (*s).to_string()).collect();
    // First registration wins; a redundant later call is a no-op (never widens).
    let _ = GRANTED_WEB_FEATURES.set(set);
}

/// Render the `Permissions-Policy` header value from the registered granted
/// set. Every directive in [`POLICY_DIRECTIVES`] is emitted; a directive opened
/// by a granted axis (via [`directives_for_suffix`]) gets the `(self)`
/// allowlist, all others the empty `()` deny.
///
/// Defence-in-depth: this header is one of TWO independent gates — the
/// `js_port` capability layer denies an ungranted port regardless of what a
/// document's policy permits — so an ungranted feature stays denied even if
/// this derivation were bypassed.
#[must_use]
fn permissions_policy_value() -> String {
    permissions_policy_from(GRANTED_WEB_FEATURES.get())
}

/// Pure derivation of the `Permissions-Policy` value from a granted suffix set
/// (or `None` = never registered). Split out from [`permissions_policy_value`]
/// so the grant / no-grant / partial-grant derivations are unit-testable
/// without touching the process-global registry.
#[must_use]
fn permissions_policy_from(granted: Option<&std::collections::BTreeSet<String>>) -> String {
    let allowed: std::collections::BTreeSet<&'static str> = granted
        .map(|set| {
            set.iter()
                .flat_map(|s| directives_for_suffix(s).iter().copied())
                .collect()
        })
        .unwrap_or_default();
    let mut parts: Vec<String> = Vec::with_capacity(POLICY_DIRECTIVES.len());
    for &dir in POLICY_DIRECTIVES {
        if allowed.contains(dir) {
            parts.push(format!("{dir}=(self)"));
        } else {
            parts.push(format!("{dir}=()"));
        }
    }
    parts.join(", ")
}

/// Safe-by-default security response headers, applied on both the Ipe.Web
/// page path and the Ipe.Http.Server response path. Returned as owned
/// `(name, value)` pairs so each
/// caller splices them into its response builder only when the header is unset
/// (an explicit handler override wins).
///
/// # Errors
///
/// The [`FrameAncestorsRefusal`] of a refused `IPE_WEB_FRAME_ANCESTORS`: the
/// caller answers `500` rather than send a response without its framing policy.
pub fn security_headers() -> Result<Vec<(&'static str, String)>, FrameAncestorsRefusal> {
    security_headers_with(frame_ancestors_config())
}

/// [`security_headers`] under an explicit framing configuration.
fn security_headers_with(
    framing: Result<Option<&FrameAncestors>, FrameAncestorsRefusal>,
) -> Result<Vec<(&'static str, String)>, FrameAncestorsRefusal> {
    let framing = framing?;
    let mut h: Vec<(&'static str, String)> = vec![
        //
        ("x-content-type-options", "nosniff".to_string()),
        (
            "referrer-policy",
            "strict-origin-when-cross-origin".to_string(),
        ),
        // Powerful features are denied by default; a directive opens to `(self)`
        // only when the app was GRANTED the capability that maps to it. Derived
        // from the registered grant so the served policy matches the proven
        // capability set — never a blanket deny that also kills legitimate
        // granted use, never a widened allow.
        ("permissions-policy", permissions_policy_value()),
    ];
    // Framing: CSP frame-ancestors when an embed origin is configured, else
    // X-Frame-Options: SAMEORIGIN (mutually exclusive).
    match framing {
        Some(fa) => h.push(("content-security-policy", fa.csp_value().to_owned())),
        None => h.push(("x-frame-options", "SAMEORIGIN".to_string())),
    }
    Ok(h)
}

/// Record a structured log line (called from `Ipe.Log.*`). Errors also land in
/// the error ring + bump the error counter.
pub fn record_log(level: &str, message: &str) {
    let ts = now_ms();
    let e = LogEntry {
        ts_ms: ts,
        level: level.to_string(),
        message: message.to_string(),
    };
    if level.eq_ignore_ascii_case("error") {
        ERRORS_TOTAL.fetch_add(1, Ordering::Relaxed);
        push_bounded(&ERRORS, ERR_CAP, e.clone());
    }
    push_bounded(&LOGS, LOG_CAP, e);
    spill_log(ts, level, message);
    export_log(ts, level, message);
}

/// Record one served HTTP request (called from the Web counter middleware).
pub fn record_request(status: u16) {
    REQUESTS_TOTAL.fetch_add(1, Ordering::Relaxed);
    if status >= 500 {
        ERRORS_TOTAL.fetch_add(1, Ordering::Relaxed);
        metric_inc("ipe_web_errors_total", &[], 1);
    }
}

pub fn requests_total() -> u64 {
    REQUESTS_TOTAL.load(Ordering::Relaxed)
}
pub fn errors_total() -> u64 {
    ERRORS_TOTAL.load(Ordering::Relaxed)
}

// ===========================================
// Labeled metric registry + Prometheus exposition. Labeled counters + gauges
// + histograms keyed by (name, sorted-labels), rendered as canonical 0.0.4
// text — giving an
// operator pointing Prometheus/Grafana at a Rust Ipê binary the full
// route/status/SSE breakdown.
// ===========================================

use std::collections::BTreeMap;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct MetricKey {
    name: String,
    /// Label pairs, kept sorted so two call sites with the same labels in a
    /// different order map to the same series (and the exposition is stable).
    ///
    /// CARDINALITY CONSTRAINT (read before adding a labeled series): label
    /// VALUES MUST be bounded / low-cardinality — a fixed status class, a
    /// route template, etc. NEVER a session id, raw request path, user id, or
    /// any unbounded value. The registry creates one entry per distinct
    /// `(name, labels)` and NEVER evicts, so an unbounded label is a
    /// memory-DoS (the classic Prometheus cardinality explosion). All current
    /// call sites pass `&[]`.
    labels: Vec<(String, String)>,
}

enum MetricValue {
    Counter(u64),
    Gauge(i64),
    /// Cumulative histogram: `buckets[i]` counts observations `<= boundaries[i]`
    /// (Prometheus cumulative semantics); the `+Inf` bucket is `count`.
    Histogram {
        boundaries: Vec<f64>,
        buckets: Vec<u64>,
        sum: f64,
        count: u64,
    },
}

/// Hot-path latency buckets, in seconds, 1ms…5s.
const LATENCY_BUCKETS: [f64; 8] = [0.001, 0.005, 0.010, 0.050, 0.100, 0.500, 1.0, 5.0];

// `Mutex::new` + `BTreeMap::new` are const → a plain static, no OnceLock. BTree
// iteration is sorted by (name, labels), giving deterministic, grouped output.
static REGISTRY: Mutex<BTreeMap<MetricKey, MetricValue>> = Mutex::new(BTreeMap::new());

fn norm_labels(labels: &[(&str, &str)]) -> Vec<(String, String)> {
    let mut v: Vec<(String, String)> = labels
        .iter()
        .map(|(k, val)| ((*k).to_string(), (*val).to_string()))
        .collect();
    v.sort();
    v
}

/// Add `by` to a labeled counter (creating it at 0 first). A name already
/// registered as a gauge is left untouched (defensive — a given name is touched
/// by exactly ONE variant; mixing counter/gauge writes on one name silently
/// no-ops the mismatch, so don't). See `MetricKey.labels` for the cardinality
/// constraint on `labels`.
pub fn metric_inc(name: &str, labels: &[(&str, &str)], by: u64) {
    let key = MetricKey {
        name: name.to_string(),
        labels: norm_labels(labels),
    };
    let mut g = REGISTRY
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match g.entry(key).or_insert(MetricValue::Counter(0)) {
        MetricValue::Counter(c) => *c = c.saturating_add(by),
        MetricValue::Gauge(_) | MetricValue::Histogram { .. } => {}
    }
}

/// Adjust a labeled gauge by `delta` (creating it at 0 first). Saturating, and
/// floored at 0 — the gauges here (active sessions / connections) never go
/// negative in correct operation; the floor stops a double-decrement underflow.
pub fn metric_add_gauge(name: &str, labels: &[(&str, &str)], delta: i64) {
    let key = MetricKey {
        name: name.to_string(),
        labels: norm_labels(labels),
    };
    let mut g = REGISTRY
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match g.entry(key).or_insert(MetricValue::Gauge(0)) {
        MetricValue::Gauge(v) => *v = v.saturating_add(delta).max(0),
        MetricValue::Counter(_) | MetricValue::Histogram { .. } => {}
    }
}

/// Record a latency/duration `v` (seconds) into a labeled histogram (creating it
/// with the `BucketsLatency` boundaries first). Cumulative: bumps every bucket
/// whose boundary `>= v` ( `Observe`). Labels MUST be low-cardinality (see
/// `MetricKey.labels`) — callers pass `&[]` or a bounded class, NEVER a raw path.
pub fn metric_observe(name: &str, labels: &[(&str, &str)], v: f64) {
    // Contract guard: a non-finite or negative observation would poison `_sum`
    // (e.g. `_sum NaN`) and skip every finite bucket while still bumping `count`.
    // The sole current caller passes a provably-finite, non-negative duration;
    // this guards a future caller from corrupting the exposition.
    if !v.is_finite() || v < 0.0 {
        return;
    }
    let key = MetricKey {
        name: name.to_string(),
        labels: norm_labels(labels),
    };
    let mut g = REGISTRY
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let entry = g.entry(key).or_insert_with(|| MetricValue::Histogram {
        boundaries: LATENCY_BUCKETS.to_vec(),
        buckets: vec![0; LATENCY_BUCKETS.len()],
        sum: 0.0,
        count: 0,
    });
    if let MetricValue::Histogram {
        boundaries,
        buckets,
        sum,
        count,
    } = entry
    {
        for (i, b) in boundaries.iter().enumerate() {
            if v <= *b
                && let Some(c) = buckets.get_mut(i)
            {
                *c = c.saturating_add(1);
            }
        }
        *sum += v;
        *count = count.saturating_add(1);
    }
}

/// Extract the BOUNDED variant name from a `Debug` value, for use as a
/// low-cardinality metric label (e.g. `ipe_web_msg_seconds{name}`).
/// Returns ONLY the leading Rust-identifier characters of the `{:?}` rendering
/// — the enum variant name — and NEVER any payload field.
///
/// CARDINALITY GUARD (load-bearing): a derived-`Debug` enum renders as `Variant`
/// / `Variant(..)` / `Variant { .. }`, so the variant ident is always the leading
/// run of `[A-Za-z_][A-Za-z0-9_]*`; the first `(`, `{`, or space ends it. The
/// distinct label values are therefore bounded by the FINITE variant set, and an
/// attacker-controlled payload field (e.g. a `SetName(String)`'s string) can
/// never reach the label — which would otherwise be the classic Prometheus
/// cardinality memory-DoS (the registry never evicts; see `MetricKey.labels`).
///
/// A capped writer halts the `Debug` render after a small prefix, so a giant
/// payload field can't even force a full-`Debug` allocation on the hot dispatch
/// path. Result capped at 64 bytes; an empty extraction falls back to `"Msg"`.
/// Shared (not Web-specific) so Tui/WebView dispatch can record the same metric.
pub fn variant_name<M: std::fmt::Debug>(m: &M) -> String {
    use std::fmt::Write;
    // Sink accepting at most CAP bytes, then signalling "stop" via Err so
    // `write!` halts rendering — the variant ident is at the very front, so we
    // never materialise a large payload field.
    const CAP: usize = 80;
    struct Prefix {
        buf: String,
    }
    impl Write for Prefix {
        fn write_str(&mut self, s: &str) -> std::fmt::Result {
            for ch in s.chars() {
                if self.buf.len() + ch.len_utf8() > CAP {
                    return Err(std::fmt::Error); // halt the Debug render
                }
                self.buf.push(ch);
            }
            Ok(())
        }
    }
    let mut sink = Prefix { buf: String::new() };
    let _ = write!(sink, "{m:?}"); // ignore the deliberate halt error

    // Take the leading Rust identifier only.
    let mut name = String::new();
    for (idx, ch) in sink.buf.chars().enumerate() {
        let is_ident = if idx == 0 {
            ch.is_ascii_alphabetic() || ch == '_'
        } else {
            ch.is_ascii_alphanumeric() || ch == '_'
        };
        if !is_ident || name.len() >= 64 {
            break;
        }
        name.push(ch);
    }
    if name.is_empty() {
        "Msg".to_string()
    } else {
        name
    }
}

/// Format a float for Prometheus exposition (bucket `le` / `_sum`). Rust's `{}`
/// gives the canonical short form (`0.001`, `0.01`, `1`, `5`).
fn format_float(f: f64) -> String {
    format!("{f}")
}

/// Like `render_labels` but always appends an `le="<bound>"` label (histograms),
/// so the block is never empty.
fn render_labels_with_le(labels: &[(String, String)], le: &str) -> String {
    let mut pairs: Vec<String> = labels
        .iter()
        .map(|(k, v)| format!("{}=\"{}\"", k, escape_label_value(v)))
        .collect();
    pairs.push(format!("le=\"{}\"", escape_label_value(le)));
    format!("{{{}}}", pairs.join(","))
}

/// Prometheus `# TYPE` token from the stored value variant — single source of
/// truth, so the header can't contradict the emitted series body.
fn prom_type_token(v: &MetricValue) -> &'static str {
    match v {
        MetricValue::Counter(_) => "counter",
        MetricValue::Gauge(_) => "gauge",
        MetricValue::Histogram { .. } => "histogram",
    }
}

/// Per-metric HELP line for the exposition header. Unknown names get a generic
/// help line (still well-formed for scrapers). The TYPE header is derived
/// from the stored `MetricValue` variant via `prom_type_token`, so the two
/// can't contradict each other.
fn metric_help(name: &str) -> &'static str {
    match name {
        "ipe_web_requests_total" => "Total HTTP requests served, by method and status.",
        "ipe_web_sse_drops_total" => "SSE patches dropped due to a full per-session buffer.",
        "ipe_web_sse_connections_total" => "Total SSE connections opened.",
        "ipe_web_sessions_active" => "Currently-active Ipe.Web sessions.",
        "ipe_web_errors_total" => "Total responses with a 5xx status.",
        "ipe_web_request_seconds" => "HTTP request latency in seconds.",
        "ipe_web_msg_seconds" => "Msg-handling latency in seconds, by Msg variant name.",
        "ipe_web_msg_total" => "Total Msgs handled, by variant name, outcome, and noop.",
        _ => "Ipe runtime metric.",
    }
}

/// Escape a Prometheus label VALUE (`\`, `"`, newline) — spec 0.0.4.
fn escape_label_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out
}

fn render_labels(labels: &[(String, String)]) -> String {
    if labels.is_empty() {
        return String::new();
    }
    let inner: Vec<String> = labels
        .iter()
        .map(|(k, v)| format!("{}=\"{}\"", k, escape_label_value(v)))
        .collect();
    format!("{{{}}}", inner.join(","))
}

/// Render the registry as Prometheus text exposition (0.0.4). `# HELP`/`# TYPE`
/// are emitted once per metric name (`BTree` groups same-name series adjacently).
pub fn write_prom() -> String {
    use std::fmt::Write as _;
    let g = REGISTRY
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut out = String::new();
    let mut last_name: Option<&str> = None;
    for (key, val) in g.iter() {
        if last_name != Some(key.name.as_str()) {
            let _ = writeln!(out, "# HELP {} {}", key.name, metric_help(&key.name));
            let _ = writeln!(out, "# TYPE {} {}", key.name, prom_type_token(val));
            last_name = Some(key.name.as_str());
        }
        let labels = render_labels(&key.labels);
        match val {
            MetricValue::Counter(c) => {
                let _ = writeln!(out, "{}{} {}", key.name, labels, c);
            }
            MetricValue::Gauge(gv) => {
                let _ = writeln!(out, "{}{} {}", key.name, labels, gv);
            }
            MetricValue::Histogram {
                boundaries,
                buckets,
                sum,
                count,
            } => {
                // Cumulative _bucket lines, then +Inf, _sum, _count (
                // writeHistogram). buckets[i] already holds the cumulative count.
                for (i, b) in boundaries.iter().enumerate() {
                    let c = buckets.get(i).copied().unwrap_or(0);
                    let _ = writeln!(
                        out,
                        "{}_bucket{} {}",
                        key.name,
                        render_labels_with_le(&key.labels, &format_float(*b)),
                        c
                    );
                }
                let _ = writeln!(
                    out,
                    "{}_bucket{} {}",
                    key.name,
                    render_labels_with_le(&key.labels, "+Inf"),
                    count
                );
                let _ = writeln!(out, "{}_sum{} {}", key.name, labels, format_float(*sum));
                let _ = writeln!(out, "{}_count{} {}", key.name, labels, count);
            }
        }
    }
    out
}

/// Most-recent `limit` log entries, oldest→newest.
pub fn recent_logs(limit: usize) -> Vec<LogEntry> {
    let g = LOGS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let n = g.len();
    g.iter().skip(n.saturating_sub(limit)).cloned().collect()
}

/// Most-recent `limit` error entries, oldest→newest.
pub fn recent_errors(limit: usize) -> Vec<LogEntry> {
    let g = ERRORS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let n = g.len();
    g.iter().skip(n.saturating_sub(limit)).cloned().collect()
}

/// The JSON string body of `s` for every JSON log record and console payload.
///
/// The display/log escaper is `crate::escape::json_str_body`, which spells
/// every log hazard (`Cc ∪ Cf ∪ Zl ∪ Zp`, C1 and bidi controls included) as a
/// `\u` escape, so a JSON log line read in a terminal carries no live control.
/// Its callers are `log.rs` JSON mode, `core.rs`'s foreign-error and panic
/// records and the console API payloads, each written or served as JSON; no
/// inline `<script>` embeds this output.
#[must_use]
pub fn json_escape(s: &str) -> String {
    crate::escape::json_str_body(s)
}

/// Render a log-entry slice as a JSON array.
#[must_use]
pub fn entries_json(entries: &[LogEntry]) -> String {
    let items: Vec<String> = entries
        .iter()
        .map(|e| {
            format!(
                r#"{{"ts":{},"level":"{}","message":"{}"}}"#,
                e.ts_ms,
                json_escape(&e.level),
                json_escape(&e.message)
            )
        })
        .collect();
    format!("[{}]", items.join(","))
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;

    use std::collections::BTreeSet;

    // A raw environment read's `{:?}` keeps its shape and hides the value.
    #[test]
    fn raw_env_debug_hides_the_value() {
        let shown = format!(
            "{:?} {:?} {:?}",
            RawEnv::Value("S3CR3T"),
            RawEnv::Absent,
            RawEnv::NotUnicode
        );
        assert!(!shown.contains("S3CR3T"), "{shown}");
        assert_eq!(shown, "Value(<redacted>) Absent NotUnicode");
    }

    /// Every byte class with no `frame-ancestors` representation is refused,
    /// the empty value is no embedding, and a source list is kept as written.
    #[test]
    fn frame_ancestors_parse_refuses_each_unrepresentable_class() {
        let refused = [
            ("https://\u{e9}.x", FrameAncestorsRefusal::NotVisibleAscii),
            ("a\rb", FrameAncestorsRefusal::NotVisibleAscii),
            ("a\nb", FrameAncestorsRefusal::NotVisibleAscii),
            ("a\0b", FrameAncestorsRefusal::NotVisibleAscii),
            ("a\u{7f}b", FrameAncestorsRefusal::NotVisibleAscii),
            (
                "'self'; script-src *",
                FrameAncestorsRefusal::DirectiveSeparator,
            ),
            (
                "https://a.example, https://b.example",
                FrameAncestorsRefusal::PolicySeparator,
            ),
            ("  ", FrameAncestorsRefusal::Blank),
            (" \t ", FrameAncestorsRefusal::Blank),
        ];
        for (raw, want) in refused {
            assert_eq!(FrameAncestors::parse(raw), Err(want), "{raw:?}");
        }
        assert_eq!(FrameAncestors::parse(""), Ok(None));
        let kept = FrameAncestors::parse(" https://a.example https://b.example ");
        assert_eq!(
            kept.as_ref()
                .map(|fa| fa.as_ref().map(FrameAncestors::csp_value)),
            Ok(Some("frame-ancestors https://a.example https://b.example"))
        );
        assert_eq!(
            FrameAncestors::from_lookup(&Err(std::env::VarError::NotPresent)),
            Ok(None)
        );
        assert_eq!(
            FrameAncestors::from_lookup(&not_unicode()),
            Err(FrameAncestorsRefusal::NotVisibleAscii)
        );
    }

    /// The refusal names the variable and the remedy and never echoes the value.
    #[test]
    fn frame_ancestors_refusal_names_the_variable_not_the_value() {
        let Err(refusal) = FrameAncestors::parse("https://evil\rX-Injected: 1") else {
            panic!("a CR must be refused");
        };
        let text = refusal.to_string();
        assert!(text.starts_with("IPE_WEB_FRAME_ANCESTORS "), "{text}");
        assert!(text.contains("https://app.example.com"), "{text}");
        assert!(
            !text.contains("evil") && !text.contains("Injected"),
            "{text}"
        );
    }

    /// The security headers carry the parsed framing policy, and a refused
    /// value yields no header set at all, so no response ships without framing.
    #[test]
    fn security_headers_follow_the_parsed_framing_policy() {
        let embed = FrameAncestors::parse("https://a.example").ok().flatten();
        let framed = security_headers_with(Ok(embed.as_ref()));
        assert!(
            framed
                .as_ref()
                .is_ok_and(|h| h.iter().any(|(k, v)| *k == "content-security-policy"
                    && v == "frame-ancestors https://a.example")
                    && !h.iter().any(|(k, _)| *k == "x-frame-options")),
            "{framed:?}"
        );
        let same_origin = security_headers_with(Ok(None));
        assert!(
            same_origin.as_ref().is_ok_and(|h| h
                .iter()
                .any(|(k, v)| *k == "x-frame-options" && v == "SAMEORIGIN")),
            "{same_origin:?}"
        );
        assert_eq!(
            security_headers_with(Err(FrameAncestorsRefusal::Blank)),
            Err(FrameAncestorsRefusal::Blank)
        );
    }

    fn not_unicode() -> Result<String, std::env::VarError> {
        Err(std::env::VarError::NotUnicode(std::ffi::OsString::new()))
    }

    #[test]
    fn raw_env_read_classification() {
        let absent = Err(std::env::VarError::NotPresent);
        assert_eq!(RawEnv::from_read(&absent), RawEnv::Absent);
        let empty = Ok(String::new());
        assert_eq!(RawEnv::from_read(&empty), RawEnv::Value(""));
        let set = Ok("token".to_string());
        assert_eq!(RawEnv::from_read(&set), RawEnv::Value("token"));
        assert_eq!(RawEnv::from_read(&not_unicode()), RawEnv::NotUnicode);
    }

    #[test]
    fn posture_non_unicode_env_fails_closed_to_production() {
        let bad = not_unicode();
        let dev = Ok("dev".to_string());
        for build in [BuildPosture::Development, BuildPosture::Release] {
            assert_eq!(
                Posture::parse(RawEnv::from_read(&bad), RawEnv::Absent, build),
                Posture::Production
            );
            // A garbled `ENV` is explicit: it never defers to a dev `IPE_ENV`.
            assert_eq!(
                Posture::parse(RawEnv::from_read(&bad), RawEnv::from_read(&dev), build),
                Posture::Production
            );
            assert_eq!(
                Posture::parse(RawEnv::Absent, RawEnv::from_read(&bad), build),
                Posture::Production
            );
            assert_eq!(
                Posture::parse(RawEnv::Value(""), RawEnv::from_read(&bad), build),
                Posture::Production
            );
        }
    }

    #[test]
    fn posture_explicit_value_wins_over_dev_build_intent() {
        let build = BuildPosture::Development;
        for marker in ["dev", "Development", "LOCAL"] {
            assert_eq!(
                Posture::parse(RawEnv::Value(marker), RawEnv::Absent, build),
                Posture::Dev
            );
            assert_eq!(
                Posture::parse(RawEnv::Absent, RawEnv::Value(marker), build),
                Posture::Dev
            );
        }
        for other in ["prod", "production", "staging", " dev", "devel"] {
            assert_eq!(
                Posture::parse(RawEnv::Value(other), RawEnv::Absent, build),
                Posture::Production,
                "ENV={other:?} must resolve to production"
            );
        }
        // `ENV` takes precedence over `IPE_ENV`.
        assert_eq!(
            Posture::parse(RawEnv::Value("prod"), RawEnv::Value("dev"), build),
            Posture::Production
        );
    }

    // A release artifact ignores every dev marker in either variable: the
    // posture is production, and the ignored marker is reported once.
    #[test]
    fn env_dev_marker_on_release_binary_is_production() {
        let release = BuildPosture::Release;
        for marker in ["dev", "development", "local", "Dev", "DEVELOPMENT", "LoCaL"] {
            for (env, ipe_env) in [
                (RawEnv::Value(marker), RawEnv::Absent),
                (RawEnv::Absent, RawEnv::Value(marker)),
                (RawEnv::Value(""), RawEnv::Value(marker)),
                (RawEnv::Value(marker), RawEnv::Value(marker)),
            ] {
                assert_eq!(
                    Posture::parse(env, ipe_env, release),
                    Posture::Production,
                    "{env:?} {ipe_env:?} on release"
                );
                assert!(release_ignores_dev_marker(env, ipe_env, release));
                assert!(!release_ignores_dev_marker(
                    env,
                    ipe_env,
                    BuildPosture::Development
                ));
            }
        }
        for (env, ipe_env) in [
            (RawEnv::Absent, RawEnv::Absent),
            (RawEnv::Value("prod"), RawEnv::Value("dev")),
            (RawEnv::NotUnicode, RawEnv::Value("dev")),
        ] {
            assert!(
                !release_ignores_dev_marker(env, ipe_env, release),
                "no dev marker is selected by {env:?} {ipe_env:?}"
            );
        }
        assert!(!RELEASE_IGNORES_DEV_MARKER.contains('\n'));
    }

    #[test]
    fn posture_unset_defers_to_build_intent() {
        for (env, ipe_env) in [
            (RawEnv::Absent, RawEnv::Absent),
            (RawEnv::Value(""), RawEnv::Value("")),
        ] {
            assert_eq!(
                Posture::parse(env, ipe_env, BuildPosture::Release),
                Posture::Production
            );
            assert_eq!(
                Posture::parse(env, ipe_env, BuildPosture::Development),
                Posture::Dev
            );
        }
    }

    // A binary built without the dev-loop intent is a release binary,
    // whatever its cargo profile.
    #[cfg(not(feature = "dev-posture"))]
    #[test]
    fn compiled_intent_without_dev_posture_is_release() {
        assert_eq!(BuildPosture::COMPILED, BuildPosture::Release);
    }

    #[cfg(feature = "dev-posture")]
    #[test]
    fn compiled_intent_with_dev_posture_is_development() {
        assert_eq!(BuildPosture::COMPILED, BuildPosture::Development);
    }

    const SCOPES: [ProcessScope; 3] = [
        ProcessScope::Unbound,
        ProcessScope::Loopback,
        ProcessScope::Exposed,
    ];

    fn surface_holds(build: BuildPosture, posture: Posture, scope: ProcessScope) -> bool {
        dev_intent(build, posture)
            .and_then(|intent| dev_surface(intent, scope))
            .is_some()
    }

    // Only a dev-intent binary in a dev posture whose every listener is
    // loopback defaults the console open; every other triple fails closed.
    #[test]
    fn console_default_opens_only_for_dev_build_dev_posture_on_loopback() {
        use ConsoleAuthMode as M;
        for build in [BuildPosture::Development, BuildPosture::Release] {
            for posture in [Posture::Dev, Posture::Production] {
                for scope in SCOPES {
                    let open = build == BuildPosture::Development
                        && posture == Posture::Dev
                        && scope == ProcessScope::Loopback;
                    assert_eq!(surface_holds(build, posture, scope), open);
                    let mode = if open { M::DevOpen } else { M::UnsetProd };
                    for raw in [RawEnv::Absent, RawEnv::Value(""), RawEnv::Value(" ")] {
                        assert_eq!(
                            ConsoleAuthMode::parse(raw, build, posture, scope),
                            mode,
                            "{build:?} {posture:?} {scope:?} {raw:?}"
                        );
                    }
                }
            }
        }
    }

    // No posture opens a release binary: neither token exists for it, on a
    // loopback listener or any other.
    #[test]
    fn dev_intent_none_on_release_whatever_env() {
        for posture in [Posture::Dev, Posture::Production] {
            assert!(dev_intent(BuildPosture::Release, posture).is_none());
        }
        assert!(dev_intent(BuildPosture::Development, Posture::Production).is_none());
        assert!(dev_intent(BuildPosture::Development, Posture::Dev).is_some());
        for scope in [ProcessScope::Unbound, ProcessScope::Exposed] {
            let intent = dev_intent(BuildPosture::Development, Posture::Dev);
            assert!(intent.and_then(|i| dev_surface(i, scope)).is_none());
        }
        assert_eq!(
            ConsoleAuthMode::parse(
                RawEnv::Absent,
                BuildPosture::Release,
                Posture::parse(RawEnv::Value("dev"), RawEnv::Absent, BuildPosture::Release),
                ProcessScope::Loopback
            ),
            ConsoleAuthMode::UnsetProd
        );
    }

    // `ENV=dev` on the release test binary, with a loopback listener
    // recorded, mints neither token.
    #[cfg(not(feature = "dev-posture"))]
    #[test]
    fn env_dev_on_release_binary_mints_no_token() {
        crate::system::locked_set_var("ENV", "dev");
        crate::system::locked_set_var("IPE_ENV", "dev");
        record_bind(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        assert_eq!(ProcessScope::current(), ProcessScope::Loopback);
        assert_eq!(Posture::from_env(), Posture::Production);
        assert!(dev_intent_from_env().is_none());
        assert!(dev_surface_from_env().is_none());
        assert!(posture_is_production());
        crate::system::locked_remove_var("ENV");
        crate::system::locked_remove_var("IPE_ENV");
    }

    // A dev-intent binary with nothing set, on a recorded loopback listener,
    // mints both tokens; an exposed bind afterwards withdraws the surface.
    #[cfg(feature = "dev-posture")]
    #[test]
    fn dev_posture_pin_loopback_mints_surface_until_exposed() {
        crate::system::locked_remove_var("ENV");
        crate::system::locked_remove_var("IPE_ENV");
        assert!(dev_intent_from_env().is_some());
        assert!(dev_surface_from_env().is_none(), "unbound: no surface");
        record_bind(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        assert!(dev_surface_from_env().is_some());
        assert!(!dev_console_banner("").is_empty());
        record_bind(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
        assert!(dev_surface_from_env().is_none());
        assert_eq!(dev_console_banner(""), "");
        assert!(dev_intent_from_env().is_some());
    }

    // The banner advertises the console, so without a dev surface it is
    // empty: on the release test binary under `ENV=dev` on loopback, and for
    // the pure gate given no surface.
    #[test]
    fn dev_banner_empty_on_release_under_env_dev() {
        assert_eq!(dev_console_banner_with("", None), "");
        if !cfg!(feature = "dev-posture") {
            crate::system::locked_set_var("ENV", "dev");
            record_bind(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
            assert_eq!(dev_console_banner(""), "");
            crate::system::locked_remove_var("ENV");
        }
    }

    // An explicit `token` is enforced on every posture and scope.
    #[test]
    fn explicit_token_wins_on_every_posture_and_scope() {
        for build in [BuildPosture::Development, BuildPosture::Release] {
            for posture in [Posture::Dev, Posture::Production] {
                for scope in SCOPES {
                    assert_eq!(
                        ConsoleAuthMode::parse(RawEnv::Value("token"), build, posture, scope),
                        ConsoleAuthMode::Token
                    );
                }
            }
        }
    }

    // A release binary with nothing set resolves to production and the closed
    // console default.
    #[test]
    fn release_intent_with_nothing_set_is_production_closed() {
        let posture = Posture::parse(RawEnv::Absent, RawEnv::Absent, BuildPosture::Release);
        assert_eq!(posture, Posture::Production);
        for scope in SCOPES {
            assert_eq!(
                ConsoleAuthMode::parse(RawEnv::Absent, BuildPosture::Release, posture, scope),
                ConsoleAuthMode::UnsetProd
            );
        }
    }

    #[test]
    fn console_auth_resolution_names_mode_and_source() {
        use ConsoleAuthMode as M;
        use ConsoleAuthSource as S;
        let bad = not_unicode();
        for posture in [Posture::Dev, Posture::Production] {
            let default = match posture {
                Posture::Dev => M::DevOpen,
                Posture::Production => M::UnsetProd,
            };
            for (raw, mode, source) in [
                (RawEnv::Absent, default, S::PostureDefault),
                (RawEnv::Value(""), default, S::PostureDefault),
                (RawEnv::Value("  "), default, S::PostureDefault),
                (RawEnv::Value("token"), M::Token, S::Explicit),
                (RawEnv::Value(" TOKEN "), M::Token, S::Explicit),
                (RawEnv::Value("app"), M::App, S::Explicit),
                (RawEnv::Value("Off"), M::Off, S::Explicit),
                (RawEnv::Value("tokne"), M::Off, S::Invalid),
                (RawEnv::from_read(&bad), M::Off, S::Invalid),
            ] {
                let resolved = ConsoleAuthResolution::resolve(
                    raw,
                    BuildPosture::Development,
                    posture,
                    ProcessScope::Loopback,
                );
                assert_eq!(
                    resolved,
                    ConsoleAuthResolution {
                        posture,
                        mode,
                        source
                    },
                    "IPE_CONSOLE_AUTH={raw:?} under {posture:?}"
                );
                assert_eq!(
                    ConsoleAuthMode::parse(
                        raw,
                        BuildPosture::Development,
                        posture,
                        ProcessScope::Loopback
                    ),
                    mode
                );
            }
        }
    }

    #[test]
    fn console_auth_startup_line_is_labels_only() {
        // The line is fully determined by three enum labels: equality with
        // the expected text proves no credential, length, or prefix can
        // appear in it.
        for (raw, posture, expected) in [
            (
                RawEnv::Value("token"),
                Posture::Dev,
                "[ipe.console] auth posture=dev mode=token source=env",
            ),
            (
                RawEnv::Absent,
                Posture::Dev,
                "[ipe.console] auth posture=dev mode=dev-open source=posture-default",
            ),
            (
                RawEnv::Absent,
                Posture::Production,
                "[ipe.console] auth posture=production mode=unset-prod source=posture-default",
            ),
            (
                RawEnv::Value("s3cret"),
                Posture::Dev,
                "[ipe.console] auth posture=dev mode=off source=env-invalid",
            ),
        ] {
            let line = ConsoleAuthResolution::resolve(
                raw,
                BuildPosture::Development,
                posture,
                ProcessScope::Loopback,
            )
            .startup_line();
            assert_eq!(line, expected);
            assert!(!line.contains("s3cret"), "startup line leaked a value");
        }
    }

    /// Build a granted suffix set from wire suffixes for the derivation tests.
    fn granted(suffixes: &[&str]) -> BTreeSet<String> {
        suffixes.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn ungranted_geolocation_stays_denied() {
        // SECURITY-CRITICAL refusal: with NO grant (an app that discloses no
        // browser axis, and the process-global registry unset → `None`), every
        // powerful directive keeps its empty `()` deny — the fail-closed
        // default. A regression that widened this to `*` or dropped a directive
        // would silently permit a feature no capability granted.
        let denied = permissions_policy_from(None);
        assert_eq!(
            denied,
            "geolocation=(), microphone=(), camera=(), payment=()"
        );
        assert!(
            !denied.contains("(self)"),
            "no directive is opened absent a grant"
        );

        // An explicit empty grant is identical to the unset default.
        assert_eq!(permissions_policy_from(Some(&granted(&[]))), denied);
    }

    #[test]
    fn granted_geolocation_opens_only_geolocation() {
        // The grant path: a geolocation grant opens ONLY `geolocation=(self)`;
        // every other powerful directive stays denied (least privilege — the
        // grant does not leak into camera / microphone / payment).
        assert_eq!(
            permissions_policy_from(Some(&granted(&["geolocation"]))),
            "geolocation=(self), microphone=(), camera=(), payment=()"
        );
    }

    #[test]
    fn recorder_grant_opens_both_camera_and_microphone() {
        // Recorder reaches both camera and microphone via getUserMedia, so a
        // single grant opens BOTH directives — but never geolocation/payment.
        assert_eq!(
            permissions_policy_from(Some(&granted(&["recorder"]))),
            "geolocation=(), microphone=(self), camera=(self), payment=()"
        );
    }

    #[test]
    fn clipboard_grant_opens_no_directive() {
        // Same-origin clipboard is default-allow, so the clipboard axis maps to
        // NO Permissions-Policy directive — a grant of it must not open any of
        // the header's directives (fail-closed: only mapped axes open).
        assert_eq!(
            permissions_policy_from(Some(&granted(&["clipboard"]))),
            "geolocation=(), microphone=(), camera=(), payment=()"
        );
    }

    #[test]
    fn payment_is_never_opened_by_any_grant() {
        // `payment` is in the header vocabulary as a PERMANENT deny — no wire
        // suffix maps to it, so no grant can open it. Even a `"payment"` suffix
        // (which no capability produces) opens nothing, since it is not a mapped
        // axis. Proves the directive stays `()` under any registered set.
        let policy = permissions_policy_from(Some(&granted(&[
            "geolocation",
            "camera",
            "microphone",
            "recorder",
            "payment",
        ])));
        assert!(
            policy.contains("payment=()"),
            "payment must stay denied under any grant: {policy}"
        );
        assert!(!policy.contains("payment=(self)"));
    }

    #[test]
    fn unknown_suffix_opens_no_directive() {
        // Fail-closed parse: an unrecognised suffix contributes nothing (it can
        // only fail to open a feature, never open an unintended one).
        assert_eq!(directives_for_suffix("not-a-real-axis"), &[] as &[&str]);
        assert_eq!(
            permissions_policy_from(Some(&granted(&["not-a-real-axis"]))),
            "geolocation=(), microphone=(), camera=(), payment=()"
        );
    }

    // SSOT tie: the runtime cannot import `ipe_kernels` in production (it is a
    // native-only DEV dependency), so the directive vocabulary and the
    // suffix→directive map are mirrored as plain data here. These native-only
    // tests bind the runtime mirror to the compiler's `WebCapability` SSOT so
    // the two cannot drift — the instant the compiler map changes, they break.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn policy_directive_vocabulary_matches_kernels() {
        assert_eq!(
            POLICY_DIRECTIVES,
            ipe_kernels::WebCapability::POLICY_DIRECTIVES,
            "runtime Permissions-Policy vocabulary drifted from the compiler SSOT"
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn policy_directive_map_matches_kernels() {
        // For every web axis, the runtime's suffix→directives table must equal
        // the compiler's `permissions_policy_directives` for the same axis.
        for &cap in ipe_kernels::WebCapability::ALL {
            assert_eq!(
                directives_for_suffix(cap.as_str()),
                cap.permissions_policy_directives(),
                "runtime directive map for {:?} ({:?}) drifted from the compiler SSOT",
                cap,
                cap.as_str()
            );
        }
    }

    #[test]
    fn json_escape_neutralises_js_line_terminators_and_controls() {
        // U+2028 / U+2029 are valid JSON but break an inline <script> JSON
        // payload (JS line terminators) — must be \u-escaped, not passed raw.
        assert_eq!(json_escape("a\u{2028}b"), "a\\u2028b");
        assert_eq!(json_escape("a\u{2029}b"), "a\\u2029b");
        // Quotes, backslashes, and C0 controls stay escaped.
        assert_eq!(json_escape("\"\\\n\t"), "\\\"\\\\\\n\\t");
        assert_eq!(json_escape("\u{0001}"), "\\u0001");
    }

    /// Log and span records escape every hazard and stay JSON that decodes to the input.
    #[test]
    #[allow(clippy::expect_used)] // an invalid record fails the test
    fn json_records_escape_the_hazard_set() {
        let hostile = "a\u{9b}\u{202e}\u{200b}b";
        let entries = entries_json(&[LogEntry {
            ts_ms: 1,
            level: hostile.to_string(),
            message: hostile.to_string(),
        }]);
        record_span(hostile, 7, true);
        let spans = spans_json(SPAN_CAP);
        for json in [&entries, &spans] {
            for raw in ['\u{9b}', '\u{202e}', '\u{200b}'] {
                assert!(!json.contains(raw), "{raw:?} survived: {json}");
            }
        }
        let parsed: serde_json::Value = serde_json::from_str(&entries).expect("entries JSON");
        let entry = parsed.get(0).expect("one entry");
        assert_eq!(entry.get("message").and_then(|v| v.as_str()), Some(hostile));
        assert_eq!(entry.get("level").and_then(|v| v.as_str()), Some(hostile));
        let parsed: serde_json::Value = serde_json::from_str(&spans).expect("spans JSON");
        let spans_list = parsed.as_array().expect("span array");
        assert!(
            spans_list
                .iter()
                .any(|s| s.get("name").and_then(|v| v.as_str()) == Some(hostile)),
            "{spans}"
        );
        assert_eq!(json_escape(hostile), crate::escape::json_str_body(hostile));
    }

    // Synthetic Debug types for `variant_name_extracts_only_the_bounded_variant_ident`.
    struct LongIdent;
    impl std::fmt::Debug for LongIdent {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "{}", "A".repeat(200))
        }
    }
    struct NonIdent;
    impl std::fmt::Debug for NonIdent {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "(weird")
        }
    }

    #[test]
    fn variant_name_extracts_only_the_bounded_variant_ident() {
        #[derive(Debug)]
        #[allow(dead_code)]
        enum M {
            Increment,
            Tick(i64),
            SetName(String),
            Login { user: String },
        }
        assert_eq!(variant_name(&M::Increment), "Increment");
        assert_eq!(variant_name(&M::Tick(42)), "Tick");
        // SECURITY (the load-bearing invariant): an attacker-controlled payload
        // field must NEVER reach the label — only the bounded variant ident.
        let evil = "x".repeat(5000) + "\n}{ injected control chars";
        assert_eq!(variant_name(&M::SetName(evil)), "SetName");
        assert_eq!(
            variant_name(&M::Login {
                user: "a".repeat(9000)
            }),
            "Login"
        );

        // A >64-byte leading ident truncates to 64 without leaking (synthetic
        // Debug — real Ipê variant idents are short; this proves the cap).
        let n = variant_name(&LongIdent);
        assert_eq!(n.len(), 64);
        assert!(n.chars().all(|c| c == 'A'));

        // A Debug rendering that doesn't start with an ident char → "Msg".
        assert_eq!(variant_name(&NonIdent), "Msg");
    }

    #[test]
    fn record_and_read_logs() {
        record_log("info", "hello");
        record_log("error", "boom \"x\"");
        let logs = recent_logs(10);
        assert!(logs.iter().any(|e| e.message == "hello"));
        let errs = recent_errors(10);
        assert!(errs.iter().any(|e| e.level == "error"));
        // error escaping is JSON-safe.
        assert!(entries_json(&errs).contains("boom \\\"x\\\""));
    }

    #[test]
    fn request_counters_move() {
        let before = requests_total();
        record_request(200);
        record_request(500);
        assert!(requests_total() >= before + 2);
    }

    #[test]
    fn spans_recorded_as_json() {
        record_span("db.query", 1234, true);
        record_span("http.get", 50, false);
        let j = spans_json(10);
        assert!(j.contains(r#""name":"db.query""#), "{j}");
        assert!(j.contains(r#""durUs":1234"#), "{j}");
        assert!(j.contains(r#""ok":false"#), "{j}");
    }

    #[test]
    fn dev_surface_holds_only_on_a_loopback_scope() {
        assert!(dev_surface(test_dev_intent(), ProcessScope::Loopback).is_some());
        assert!(dev_surface(test_dev_intent(), ProcessScope::Unbound).is_none());
        assert!(dev_surface(test_dev_intent(), ProcessScope::Exposed).is_none());
    }

    #[test]
    fn dev_banner_markup_is_exact() {
        // Fixed id, target/rel/title, monospace blue style, `&#128269;` ENTITY
        // (not a literal emoji). The banner renders only under a dev surface.
        let b = dev_console_banner_with("", Some(&test_dev_surface()));
        let expected = "<a id=\"__ipe-dev-console\" href=\"/_ipe/console\" target=\"_blank\" \
            rel=\"noopener\" title=\"Ipe Console (dev only)\" \
            style=\"position:fixed;right:12px;bottom:12px;z-index:2147483646;\
            font:12px/1.4 ui-monospace,Menlo,monospace;\
            background:#1c2027;color:#7eb6ff;\
            border:1px solid #353b46;border-radius:6px;\
            padding:6px 10px;text-decoration:none;\
            box-shadow:0 2px 8px rgba(0,0,0,0.4);\">\
            &#128269; Console</a>";
        assert_eq!(b, expected, "dev console banner must match golden");
        assert!(
            !b.contains('🔍'),
            "must use the &#128269; entity, not a literal emoji"
        );
    }

    #[test]
    fn dev_banner_suppressed_for_subapp() {
        // A non-empty base = sub-app (e.g. the console child) → no recursive link.
        // Base-gate needs no env mutation, so this stays race-free.
        assert_eq!(dev_console_banner("/_ipe/console"), "");
    }

    #[test]
    fn inject_dev_banner_before_last_body_close() {
        let body = "<html><body><p>hi</p></body></html>";
        let out = inject_dev_banner(body, "<BANNER>");
        assert_eq!(out, "<html><body><p>hi</p><BANNER></body></html>");
    }

    #[test]
    fn inject_dev_banner_case_insensitive_body_tag() {
        // Case-insensitive `</body>` search (lower-cased before index).
        let body = "<HTML><BODY>x</BODY></HTML>";
        let out = inject_dev_banner(body, "<B>");
        assert_eq!(out, "<HTML><BODY>x<B></BODY></HTML>");
    }

    #[test]
    fn inject_dev_banner_uses_last_body_close() {
        let body = "</body>first</body>";
        let out = inject_dev_banner(body, "<B>");
        assert_eq!(out, "</body>first<B></body>");
    }

    #[test]
    fn inject_dev_banner_appends_when_no_body_tag() {
        let body = "<p>fragment only</p>";
        let out = inject_dev_banner(body, "<B>");
        assert_eq!(out, "<p>fragment only</p><B>");
    }

    #[test]
    fn inject_dev_banner_empty_is_noop() {
        // Empty banner is the observable effect of the production-suppressed path:
        // dev_console_banner returns "" in production, so injection must no-op.
        let body = "<html><body>x</body></html>";
        assert_eq!(inject_dev_banner(body, ""), body);
    }

    #[test]
    fn inject_dev_banner_utf8_body_char_boundary_safe() {
        // Multi-byte UTF-8 before the </body> must not panic on the slice.
        let body = "<body>café — 日本語</body>";
        let out = inject_dev_banner(body, "<B>");
        assert_eq!(out, "<body>café — 日本語<B></body>");
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod listen_scope_tests {
    use super::{ListenScope, ProcessScope, record_bind};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
    const UNSPECIFIED: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

    #[test]
    fn process_scope_bytes_decode_closed() {
        for scope in [
            ProcessScope::Unbound,
            ProcessScope::Loopback,
            ProcessScope::Exposed,
        ] {
            assert_eq!(ProcessScope::from_byte(scope.to_byte()), scope);
        }
        for byte in [3, 7, u8::MAX] {
            assert_eq!(ProcessScope::from_byte(byte), ProcessScope::Exposed);
        }
    }

    // The join only moves toward `Exposed`: a loopback bind after an exposed
    // one, or before it, leaves the process exposed.
    #[test]
    fn exposed_bind_after_loopback_stays_exposed() {
        let unbound = ProcessScope::Unbound;
        assert_eq!(unbound.join(ListenScope::Loopback), ProcessScope::Loopback);
        assert_eq!(
            unbound
                .join(ListenScope::Loopback)
                .join(ListenScope::Exposed),
            ProcessScope::Exposed
        );
        assert_eq!(
            unbound
                .join(ListenScope::Exposed)
                .join(ListenScope::Loopback),
            ProcessScope::Exposed
        );
        assert_eq!(ProcessScope::current(), ProcessScope::Unbound);
        assert_eq!(record_bind(LOOPBACK), ListenScope::Loopback);
        assert_eq!(ProcessScope::current(), ProcessScope::Loopback);
        assert_eq!(record_bind(UNSPECIFIED), ListenScope::Exposed);
        assert_eq!(record_bind(LOOPBACK), ListenScope::Loopback);
        assert_eq!(ProcessScope::current(), ProcessScope::Exposed);
    }

    #[test]
    fn only_a_loopback_address_is_loopback() {
        for ip in [
            UNSPECIFIED,
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped()),
        ] {
            assert_eq!(
                ListenScope::of(ip),
                ListenScope::Exposed,
                "bind address {ip} must read as exposed"
            );
        }
        for ip in [
            LOOPBACK,
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::new(127, 1, 2, 3)),
        ] {
            assert_eq!(
                ListenScope::of(ip),
                ListenScope::Loopback,
                "bind address {ip} must read as loopback"
            );
        }
    }
}

/// Runs one ignored test of this test binary as a child process holding a
/// given `IPE_WEB_FRAME_ANCESTORS`, so the process-wide parse is made under
/// that value and no other test of the parent can have made it first.
#[cfg(all(test, feature = "server", not(target_arch = "wasm32")))]
pub(crate) mod frame_ancestors_child {
    /// Printed by a child test once it has observed the startup refusal.
    pub(crate) const REFUSED: &str = "frame-ancestors startup refusal observed";

    /// Run the ignored test `name` of `module` (a `module_path!()`) with
    /// `IPE_WEB_FRAME_ANCESTORS` set to `raw`. `true` when the child exited 0
    /// having printed [`REFUSED`]; the child's stdout comes back for the report.
    #[allow(clippy::expect_used)] // test helper: a test binary that cannot re-run itself is an environment issue
    pub(crate) fn refused(module: &str, name: &str, raw: &str) -> (bool, String) {
        let module = module.split_once("::").map_or(module, |(_, rest)| rest);
        let filter = format!("{module}::{name}");
        let exe = std::env::current_exe().expect("the test binary");
        let out = std::process::Command::new(exe)
            .args([
                "--exact",
                filter.as_str(),
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(super::FRAME_ANCESTORS_ENV, raw)
            .stdin(std::process::Stdio::null())
            .output()
            .expect("run the child test");
        let ran = out.status.success();
        let stdout = String::from_utf8(out.stdout).unwrap_or_default();
        (ran && stdout.contains(REFUSED), stdout)
    }
}
