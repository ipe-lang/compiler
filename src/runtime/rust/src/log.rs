// Log helpers for `Ipe.Log.*`.
//
// Line shapes:
//   plain:  <RFC3339Nano-UTC> <LEVEL> <message>[ key=value …]   (level UPPER)
//   json:   {"level":"<level>","msg":"<message>","time":"<ts>"}  (level lower,
//           keys alphabetically sorted)
//
// Stream routing
// `IPE_LOG_LEVEL` gates output (debug < info < warn < error; default info). A
// present value outside `debug`/`info`/`warn`/`warning`/`error` (ASCII
// case-insensitive, unpadded, non-empty) refuses startup;
// `IPE_LOG_FORMAT=json` switches to the JSON shape. Each line is also mirrored
// into the telemetry ring (the Ipê Console reads it).
//
// `Log` is observability-only: bare line printing (no timestamp, no level) is
// `Ipe.Io` (`Io.println` / `Io.eprintln`, `io.rs`), not a `Log` member.
use super::*;

const LOG_LEVEL_DEBUG: i32 = 0;
const LOG_LEVEL_INFO: i32 = 1;
const LOG_LEVEL_WARN: i32 = 2;
const LOG_LEVEL_ERROR: i32 = 3;

/// A minimum severity `IPE_LOG_LEVEL` names.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum LogThreshold {
    Debug,
    Info,
    Warn,
    Error,
}

impl LogThreshold {
    /// The severity a line must reach under this threshold.
    const fn severity(self) -> i32 {
        match self {
            Self::Debug => LOG_LEVEL_DEBUG,
            Self::Info => LOG_LEVEL_INFO,
            Self::Warn => LOG_LEVEL_WARN,
            Self::Error => LOG_LEVEL_ERROR,
        }
    }
}

/// The accepted `IPE_LOG_LEVEL` values, as a refusal states them.
const LOG_LEVEL_EXPECTED: &str = "one of debug, info, warn, warning, error";

/// The parsed `IPE_LOG_LEVEL`: `None` when unset, a refusal when present but not
/// a level name.
type EnvThreshold = Result<Option<LogThreshold>, crate::system::EnvValueRefusal>;

/// Parses the raw `IPE_LOG_LEVEL` lookup into a threshold.
fn threshold_from(raw: Result<String, std::env::VarError>) -> EnvThreshold {
    let refuse =
        |raw: &[u8]| crate::system::EnvValueRefusal::new("IPE_LOG_LEVEL", LOG_LEVEL_EXPECTED, raw);
    let value = match raw {
        Ok(value) => value,
        Err(std::env::VarError::NotPresent) => return Ok(None),
        Err(std::env::VarError::NotUnicode(os)) => return Err(refuse(os.as_encoded_bytes())),
    };
    let is = |name: &str| value.eq_ignore_ascii_case(name);
    let threshold = if is("debug") {
        LogThreshold::Debug
    } else if is("info") {
        LogThreshold::Info
    } else if is("warn") || is("warning") {
        LogThreshold::Warn
    } else if is("error") {
        LogThreshold::Error
    } else {
        return Err(refuse(value.as_bytes()));
    };
    Ok(Some(threshold))
}

/// `IPE_LOG_LEVEL`, read and parsed once per process.
fn env_threshold() -> &'static EnvThreshold {
    static ENV_THRESHOLD: std::sync::OnceLock<EnvThreshold> = std::sync::OnceLock::new();
    ENV_THRESHOLD.get_or_init(|| threshold_from(crate::system::read_env_var("IPE_LOG_LEVEL")))
}

/// Refuses a present `IPE_LOG_LEVEL` that is not a level name, before any line
/// is logged.
///
/// # Errors
///
/// The refusal naming `IPE_LOG_LEVEL` and echoing its escaped value.
// The vendored emit compiles `log.rs` without the `log` feature, so no entry
// calls this check there.
#[cfg_attr(not(feature = "log"), allow(dead_code))]
pub(crate) fn startup_check() -> Result<(), crate::system::EnvValueRefusal> {
    env_threshold().as_ref().map(|_| ()).map_err(Clone::clone)
}

/// The minimum severity a line must reach to be emitted, under the one config
/// precedence `env > setting-in-code > fallback`: `IPE_LOG_LEVEL` wins; absent
/// it, an installed `Log.level` setting applies (its tag `0` debug … `3` error,
/// clamped to the known range); absent both, the built-in default is info. A
/// malformed `IPE_LOG_LEVEL` is refused by [`startup_check`]; an entry that runs
/// no such check logs at info.
fn log_threshold() -> i32 {
    threshold_under(
        env_threshold(),
        crate::app_config::resolve_log_level_override(),
    )
}

/// The precedence over the one `IPE_LOG_LEVEL` snapshot and the installed
/// `Log.level` tag. A present `IPE_LOG_LEVEL`, malformed included, shadows the
/// setting; a variable set after startup (`System.setenv`, `System.loadEnv`) is
/// not in the snapshot and changes neither tier.
fn threshold_under(env: &EnvThreshold, setting: Option<i64>) -> i32 {
    match env {
        Ok(Some(threshold)) => threshold.severity(),
        Ok(None) => setting.map_or(LOG_LEVEL_INFO, |tag| match tag {
            t if t <= i64::from(LOG_LEVEL_DEBUG) => LOG_LEVEL_DEBUG,
            1 => LOG_LEVEL_INFO,
            2 => LOG_LEVEL_WARN,
            _ => LOG_LEVEL_ERROR,
        }),
        // Refused by `startup_check`; an entry without it logs at info.
        Err(_) => LOG_LEVEL_INFO,
    }
}

fn log_json() -> bool {
    crate::system::read_env_var("IPE_LOG_FORMAT").unwrap_or_default() == "json"
}

/// Current UTC instant in  `time.RFC3339Nano` layout
/// (`2006-01-02T15:04:05.999999999Z07:00`): nanosecond precision with trailing
/// zeros trimmed, UTC rendered as `Z`. Matches
/// `now.UTC().Format(time.RFC3339Nano)`.
// The native-ish clock read covers host native AND WASI: `chrono::Utc::now()`
// resolves against the real clock on `wasm32-wasip1` (WASI has a clock), so a
// co-located WASI program logs real timestamps. Only the browser-`wasm-client`
// build substitutes `Date.now()` (`chrono` traps on `wasm32-unknown-unknown`).
#[cfg(not(all(target_arch = "wasm32", feature = "wasm-client")))]
fn rfc3339_nano_now() -> String {
    let now = chrono::Utc::now();
    let nanos = now.format("%9f").to_string();
    let trimmed = nanos.trim_end_matches('0');
    let date = now.format("%Y-%m-%dT%H:%M:%S").to_string();
    if trimmed.is_empty() {
        format!("{date}Z")
    } else {
        format!("{date}.{trimmed}Z")
    }
}

/// Browser substitute: `chrono::Utc::now()` has no denotation on
/// `wasm32-unknown-unknown` without the extra `wasmbind` feature this target
/// does not carry. `Date.now()` (via `js_sys`) gives millisecond, not
/// nanosecond, precision — millisecond granularity is acceptable here.
#[cfg(all(target_arch = "wasm32", feature = "wasm-client"))]
fn rfc3339_nano_now() -> String {
    js_sys::Date::new_0().to_iso_string().into()
}

/// Minimal JSON string escaping for the hand-built plain/JSON records, matching
///  `json.Marshal` for the characters that occur in log text. Reuses the
/// telemetry escaper so the two sinks never diverge.
fn json_str(s: &str) -> String {
    format!("\"{}\"", super::telemetry::json_escape(s))
}

/// Total line-write helpers: Rust's `println!`/`eprintln!` call `std::io::_print`,
/// which PANICS ("failed printing to stdout") when the underlying write errors.
/// Because Rust ignores SIGPIPE by default, a closed downstream pipe surfaces as
/// an `EPIPE` write error rather than process termination — so a piped consumer
/// hanging up (`ipe-app | head`) would panic from a well-typed `Log.*` call.
/// These helpers perform the write fallibly and intentionally drop the `Result`,
/// turning a broken pipe into a silently-skipped line instead of an abort.
// The native-ish stdio write covers host native AND WASI: `wasm32-wasip1` has
// real stdout/stderr, so a co-located WASI program's `Log.*` lines land on the
// host streams. Only the browser-`wasm-client` build (no tab stdio) substitutes
// `console.*`.
#[cfg(not(all(target_arch = "wasm32", feature = "wasm-client")))]
fn write_stdout_line(line: &str) {
    crate::system::write_stdout_line(line);
}

#[cfg(not(all(target_arch = "wasm32", feature = "wasm-client")))]
fn write_stderr_line(line: &str) {
    crate::system::write_stderr_line(line);
}

/// Browser substitute: there is no stdout/stderr in a tab — `Log.*` routes to
/// `console.log` / `console.error` (Q3: "`Log.*` | SUBSTITUTE |
/// `console.{debug,info,warn,error}`"). `write_stdout_line`/`write_stderr_line`
/// keep the SAME two-way (out/err) split `log_emit` already computes, so no
/// caller above this line needs to change per target.
#[cfg(all(target_arch = "wasm32", feature = "wasm-client"))]
fn write_stdout_line(line: &str) {
    web_sys::console::log_1(&wasm_bindgen::JsValue::from_str(line));
}

#[cfg(all(target_arch = "wasm32", feature = "wasm-client"))]
fn write_stderr_line(line: &str) {
    web_sys::console::error_1(&wasm_bindgen::JsValue::from_str(line));
}

/// The  core: gate on the threshold, mirror into the telemetry ring,
/// then write the plain or JSON line to the correct stream. `level` is the
/// numeric severity; `level_name` is the lowercase token (`info` / `warn` / …).
fn log_emit(level: i32, level_name: &str, msg: &str) {
    if level < log_threshold() {
        return;
    }
    super::telemetry::record_log(level_name, msg);
    let to_stderr = level >= LOG_LEVEL_WARN;
    if log_json() {
        // Keys sorted alphabetically: level, msg, time. No attrs are surfaced
        // to JSON fields today — the *With variants flatten into the message.
        let line = format!(
            "{{\"level\":{},\"msg\":{},\"time\":{}}}",
            json_str(level_name),
            json_str(msg),
            json_str(&rfc3339_nano_now()),
        );
        if to_stderr {
            write_stderr_line(&line);
        } else {
            write_stdout_line(&line);
        }
        return;
    }
    // Plain mode: sanitise before writing so control chars / embedded newlines
    // can't forge extra log lines (the JSON path is safe via json_escape already).
    let safe_msg = crate::system::scrub_log_controls(msg);
    let line = format!(
        "{} {} {}",
        rfc3339_nano_now(),
        level_name.to_ascii_uppercase(),
        safe_msg
    );
    if to_stderr {
        write_stderr_line(&line);
    } else {
        write_stdout_line(&line);
    }
}

pub fn log_info<E: Send + 'static>(msg: String) -> IpeTask<E, ()> {
    Box::pin(async move {
        log_emit(LOG_LEVEL_INFO, "info", &msg);
        ok_res(())
    })
}

// `Log.*With : String -> List a -> Task` takes a flat list of interpolable
// scalars (`[ "errId", id ]`). The attrs slot is generic over its element type
// `A`, bounded by the sealed `IpeInterpolate` — the same closed scalar set
// (`String` / `Int` / `Float` / `Bool` / `Char`) the type checker admits for
// the element, so a record, ADT, container or opaque runtime value (a
// `Secret`, a `Request`) never reaches a log line.
//
// Rendering implements `renderLogMsgWithAttrs` byte-for-byte: the flat attr
// list is space-joined onto the message (`msg a1 a2 …`, each `ai` rendered as
// its `String.from*` conversion),
// then handed to `log_emit` as a single pre-rendered line — so the plain path
// sanitises the attr values too (no newline-injection via an attr) and the JSON
// path surfaces them inside `msg` exactly for the List call shape
// ( With variants pass `ctx=nil`).

/// Flatten `(msg, attrs)` into one line, mirroring  `renderLogMsgWithAttrs`:
/// `msg` followed by a space + the rendering of each attr element, in order.
fn render_with_attrs<A: IpeInterpolate>(msg: &str, attrs: &[A]) -> String {
    if attrs.is_empty() {
        return msg.to_string();
    }
    let mut out = String::from(msg);
    for a in attrs {
        out.push(' ');
        out.push_str(&a.ipe_interpolate());
    }
    out
}

pub fn log_info_with<E: Send + 'static, A: IpeInterpolate>(
    msg: String,
    attrs: Vec<A>,
) -> IpeTask<E, ()> {
    // Render BEFORE constructing the future so the captured value is a `Send`
    // `String` (no `A: Send` bound needed); the line write still fires on `.await`.
    let line = render_with_attrs(&msg, &attrs);
    Box::pin(async move {
        log_emit(LOG_LEVEL_INFO, "info", &line);
        ok_res(())
    })
}

pub fn log_error_with<E: Send + 'static, A: IpeInterpolate>(
    msg: String,
    attrs: Vec<A>,
) -> IpeTask<E, ()> {
    let line = render_with_attrs(&msg, &attrs);
    Box::pin(async move {
        log_emit(LOG_LEVEL_ERROR, "error", &line);
        ok_res(())
    })
}

pub fn log_debug<E: Send + 'static>(msg: String) -> IpeTask<E, ()> {
    Box::pin(async move {
        log_emit(LOG_LEVEL_DEBUG, "debug", &msg);
        ok_res(())
    })
}
pub fn log_warn<E: Send + 'static>(msg: String) -> IpeTask<E, ()> {
    Box::pin(async move {
        log_emit(LOG_LEVEL_WARN, "warn", &msg);
        ok_res(())
    })
}
pub fn log_error<E: Send + 'static>(msg: String) -> IpeTask<E, ()> {
    Box::pin(async move {
        log_emit(LOG_LEVEL_ERROR, "error", &msg);
        ok_res(())
    })
}
pub fn log_debug_with<E: Send + 'static, A: IpeInterpolate>(
    msg: String,
    attrs: Vec<A>,
) -> IpeTask<E, ()> {
    let line = render_with_attrs(&msg, &attrs);
    Box::pin(async move {
        log_emit(LOG_LEVEL_DEBUG, "debug", &line);
        ok_res(())
    })
}
pub fn log_warn_with<E: Send + 'static, A: IpeInterpolate>(
    msg: String,
    attrs: Vec<A>,
) -> IpeTask<E, ()> {
    let line = render_with_attrs(&msg, &attrs);
    Box::pin(async move {
        log_emit(LOG_LEVEL_WARN, "warn", &line);
        ok_res(())
    })
}

#[cfg(test)]
mod threshold_tests {
    use super::{
        LOG_LEVEL_DEBUG, LOG_LEVEL_ERROR, LOG_LEVEL_INFO, LOG_LEVEL_WARN, LogThreshold,
        threshold_from, threshold_under,
    };

    fn parse(raw: &str) -> super::EnvThreshold {
        threshold_from(Ok(raw.to_owned()))
    }

    #[test]
    fn a_level_name_parses_case_insensitively() {
        for (raw, threshold) in [
            ("debug", LogThreshold::Debug),
            ("info", LogThreshold::Info),
            ("warn", LogThreshold::Warn),
            ("warning", LogThreshold::Warn),
            ("WARN", LogThreshold::Warn),
            ("Error", LogThreshold::Error),
        ] {
            assert_eq!(parse(raw), Ok(Some(threshold)), "{raw:?}");
        }
        assert_eq!(
            threshold_from(Err(std::env::VarError::NotPresent)),
            Ok(None)
        );
    }

    #[test]
    fn a_value_that_is_not_a_level_name_is_refused() {
        for raw in ["verbose", "", " warn", "warn ", "trace", "2"] {
            let outcome = parse(raw);
            assert!(
                outcome.as_ref().is_err_and(|r| r.name() == "IPE_LOG_LEVEL"
                    && r.to_string()
                        .contains("one of debug, info, warn, warning, error")),
                "{raw:?} must be refused naming IPE_LOG_LEVEL, got {outcome:?}"
            );
        }
    }

    /// The setting applies only when the startup snapshot holds no
    /// `IPE_LOG_LEVEL`; a present one, malformed included, shadows it.
    #[test]
    fn the_snapshot_alone_decides_whether_the_setting_applies() {
        let unset = Ok(None);
        assert_eq!(threshold_under(&unset, Some(0)), LOG_LEVEL_DEBUG);
        assert_eq!(threshold_under(&unset, Some(-7)), LOG_LEVEL_DEBUG);
        assert_eq!(threshold_under(&unset, Some(1)), LOG_LEVEL_INFO);
        assert_eq!(threshold_under(&unset, Some(2)), LOG_LEVEL_WARN);
        assert_eq!(threshold_under(&unset, Some(9)), LOG_LEVEL_ERROR);
        assert_eq!(threshold_under(&unset, None), LOG_LEVEL_INFO);
        let error = Ok(Some(LogThreshold::Error));
        assert_eq!(threshold_under(&error, Some(0)), LOG_LEVEL_ERROR);
        assert_eq!(threshold_under(&parse("verbose"), Some(0)), LOG_LEVEL_INFO);
    }
}
