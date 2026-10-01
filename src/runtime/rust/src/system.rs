// System helpers — some generic over E (when returning IpeTask).
use super::path::{OsOrigin, from_os};
use super::{IpeError, IpeMaybe, IpeResult, IpeTask, ok_res, str_err};

// `std::env::set_var`/`remove_var` are documented as NOT thread-safe: a mutator
// reallocates the C `environ` block while another thread READS it — and the
// racing reader is NOT only `std::env::var`. libc readers (`getenv`, and
// `getaddrinfo` reached through `to_socket_addrs`), and any third-party crate,
// walk `environ` WITHOUT taking any lock we control. A process-global RwLock over
// the real environ can serialise only OUR readers, never those — so a mutator
// holding a write lock still races a concurrent libc `getaddrinfo`, a real
// use-after-free reachable from safe Ipê (`Task.parallel [System.setenv, Http.get]`).
//
// The runtime therefore NEVER mutates the real `environ` after startup. Ipê env
// writes land in a process-local overlay map guarded by this `RwLock`; every Ipê
// read (`read_env_var`/`read_env_var_os`) consults the overlay first and the real
// (immutable-after-startup) environ second. Children spawned by `Process.*`
// receive the overlay applied explicitly onto their `Command` env, so an
// overlay-set var still reaches a subprocess without touching the parent's
// `environ`. No `environ` mutation ⇒ no reader↔mutator race with ANY reader,
// ours or libc's — the hazard is removed, not merely serialised on one side.
type EnvOverlay = std::collections::HashMap<String, Option<String>>;

/// Process-local env overlay. `Some(value)` shadows/introduces a variable;
/// `None` is a tombstone that hides a variable present in the real environ. An
/// absent key defers to the real environ. Guarded so concurrent Ipê readers and
/// writers are consistent; the real `environ` is never mutated, so no reader of
/// any origin can race a mutation.
static ENV_OVERLAY: std::sync::LazyLock<std::sync::RwLock<EnvOverlay>> =
    std::sync::LazyLock::new(|| std::sync::RwLock::new(std::collections::HashMap::new()));

/// A key/value pair Ipê may write to the env overlay: a key that is empty,
/// contains `=` or NUL, or a value containing NUL is rejected (would be an
/// invalid environment entry). `pub(crate)` so child-spawn paths reuse the same
/// admission rule the overlay applies.
pub(crate) fn env_entry_is_valid(key: &str, val: &str) -> bool {
    !(key.is_empty() || key.contains('=') || key.contains('\0') || val.contains('\0'))
}

/// Read an environment variable: the overlay wins over the real environ, so a
/// value Ipê set/removed via `System.setenv`/`unsetenv`/`loadEnv` is observed
/// consistently. `pub(crate)` so every non-test process-env read in the crate
/// routes through this one accessor — that is what makes the overlay authoritative
/// for Ipê by construction. The runtime's own settings follow the overlay too:
/// `NO_COLOR`, `IPE_EXPLAIN_VERBOSE`, and the debugger's `IPE_DEBUGGER_RECORD` /
/// `IPE_DEBUGGER_REPLAY` observe a value the program wrote, not only the
/// environment the process started with.
///
/// A temp-root key ([`super::scratch_core::TEMP_ROOT_NAMES`], any case) always
/// reads as unset: the temp root is a base other users can write, resolved only
/// by the scratch primitive behind its ownership checks, so no Ipê program or
/// runtime path builds a temporary name from it. `System.getenv "TMPDIR"` is
/// therefore `Err` and `getenvOr` yields its default, whatever the environ holds.
pub(crate) fn read_env_var(key: &str) -> Result<String, std::env::VarError> {
    if super::scratch_core::is_temp_root_key(key) {
        return Err(std::env::VarError::NotPresent);
    }
    let overlay = ENV_OVERLAY
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match overlay.get(key) {
        Some(Some(v)) => Ok(v.clone()),
        Some(None) => Err(std::env::VarError::NotPresent),
        #[allow(clippy::disallowed_methods)] // the accessor: overlay and temp roots answered first
        None => std::env::var(key),
    }
}

/// The invoking user's home directory: the one runtime home reader.
///
/// Reads the shared platform variable [`super::home_core::HOME_VAR`]
/// (`USERPROFILE` on Windows, `HOME` elsewhere), overlay-aware like
/// [`read_env_var`]. Gated to its readers: the console proxy's cached-binary
/// lookup, and off Unix the scratch primitive's profile-containment check.
#[cfg(any(all(feature = "web-core", feature = "http_client"), not(unix)))]
pub(crate) fn home_dir() -> Option<std::path::PathBuf> {
    home_dir_from_var(read_env_var(super::home_core::HOME_VAR))
}

/// Parse a home read: `Some` only for a valid `HomeDir`.
///
/// Bridges the overlay's `String` result to the shared
/// [`super::home_core::HomeDir::parse`], which owns every decision about what
/// counts as a home directory (UTF-8, absolute, and, on Windows, not a
/// verbatim/device-namespace prefix) — this function makes none of them
/// itself.
#[cfg(any(all(feature = "web-core", feature = "http_client"), not(unix)))]
fn home_dir_from_var(raw: Result<String, std::env::VarError>) -> Option<std::path::PathBuf> {
    super::home_core::HomeDir::parse(raw.ok().map(std::ffi::OsString::from))
        .map(super::home_core::HomeDir::into_path)
}

/// Render a runtime status line (e.g. the HTTP `listening on` banner, or an
/// `[ipe.live]`/`[ipe.console]` session-store/console line) with a 4-space
/// left gutter ONLY when stderr is an interactive terminal; a piped or
/// redirected stderr (test harness, production log capture) stays flush-left so
/// downstream `contains(...)` matchers see the bare line. The `is_terminal`
/// decision is a parameter so the indent rule is testable without a pty.
///
/// Four spaces, not the CLI's plain 2-space `GUTTER`: under `ipe watch`, these
/// lines are the spawned app's own output, printed one level deeper than the
/// `[ipe watch] ...` status lines that frame it (which themselves render at
/// two gutter-widths) — so this nests under them rather than under the
/// top-level banner.
///
/// Unconditional: every `[ipe.<tag>] ...` runtime log line, in every feature
/// combination, flows through `emit_runtime_log` below, which calls this —
/// so it can never be dead code.
pub(crate) fn gutter_line(msg: &str, is_terminal: bool) -> String {
    if is_terminal {
        format!("    {msg}")
    } else {
        msg.to_string()
    }
}

/// A character that must never reach an operator log line raw: every Unicode
/// `Cc` control (C0 incl. CR/LF/ESC, DEL, C1 incl. NEL/CSI), the Unicode
/// line/paragraph separators U+2028/U+2029 (record breaks for log viewers and
/// JS-based aggregators), and the bidirectional formatting controls
/// (U+061C, U+200E/F, U+202A-E, U+2066-9) that visually reorder a line.
fn is_log_hazard(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{2028}'
                | '\u{2029}'
                | '\u{061c}'
                | '\u{200e}'
                | '\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
        )
}

/// Neutralise every log-hazard character (see [`is_log_hazard`]) in text
/// bound for an operator log line by escaping it — `\n`, `\r`, `\t`, else
/// `\u{XX}` — so untrusted
/// input (a driver error, a request path, an env-derived path, a trace value)
/// can neither forge extra records nor inject terminal escape sequences, and
/// the escape stays visible rather than silently erased. The single log
/// scrubber: every plain-text log sink routes untrusted text through it. Not a
/// JSON escaper — JSON records keep `telemetry::json_escape`.
pub(crate) fn scrub_log_controls(s: &str) -> std::borrow::Cow<'_, str> {
    use std::fmt::Write as _;
    if !s.chars().any(is_log_hazard) {
        return std::borrow::Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len().saturating_add(16));
    for c in s.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if is_log_hazard(c) => {
                let _ = write!(out, "\\u{{{:x}}}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    std::borrow::Cow::Owned(out)
}

/// Write one line to stderr fallibly, dropping the error: `eprintln!` panics
/// when the write fails, and because Rust ignores SIGPIPE a hung-up reader
/// (`app 2>&1 | head`) surfaces as `EPIPE`. The single runtime stderr line
/// sink — `log.rs`, `debug.rs`, the tagged emitter below and every other
/// runtime diagnostic line route through it, so no stderr write can abort. Its
/// stdout sibling is [`write_stdout_line`]; callers are responsible for
/// scrubbing (via [`scrub_log_controls`]) any untrusted text before it reaches
/// either.
pub(crate) fn write_stderr_line(line: &str) {
    use std::io::Write as _;
    let _ = writeln!(std::io::stderr().lock(), "{line}");
}

/// Write one line to stdout fallibly, dropping the error — the stdout mirror
/// of [`write_stderr_line`], for the identical `println!`-panics-on-`EPIPE`
/// reason. The single runtime stdout line sink: `log.rs` and every other
/// runtime stdout write (server status lines, CLI-op summaries) route through
/// it instead of a raw `println!`/`print!`, so a closed downstream pipe
/// (`ipe-app | head`) can never abort the process;
/// `tests/no_panicking_print_macro.rs` refuses any production print macro.
/// Always compiled, like its stderr sibling, so no feature combination can
/// leave a caller without it; only `log`, `db` and the served `web` surface
/// call it.
#[cfg_attr(
    not(any(
        feature = "log",
        feature = "db",
        all(feature = "web-core", feature = "server")
    )),
    allow(dead_code) // no stdout-writing module in this feature set
)]
pub(crate) fn write_stdout_line(line: &str) {
    use std::io::Write as _;
    let _ = writeln!(std::io::stdout().lock(), "{line}");
}

/// Build a `"[<stamp> ][ipe.<tag>] <msg>"` line with `msg` scrubbed. Private:
/// the only place the literal `"[ipe."` prefix is constructed; call sites use
/// `emit_runtime_log` / `emit_runtime_log_stamped`.
fn format_runtime_log(stamp: Option<&str>, tag: &str, msg: &str) -> String {
    let msg = scrub_log_controls(msg);
    match stamp {
        Some(stamp) => format!("{stamp} [ipe.{tag}] {msg}"),
        None => format!("[ipe.{tag}] {msg}"),
    }
}

/// The fully rendered (scrubbed, terminal-guttered) form of a tagged runtime
/// log line — exactly what the emitters write.
pub(crate) fn runtime_log_line(stamp: Option<&str>, tag: &str, msg: &str) -> String {
    use std::io::IsTerminal;
    gutter_line(
        &format_runtime_log(stamp, tag, msg),
        std::io::stderr().is_terminal(),
    )
}

/// The single emitter for every `[ipe.<tag>] ...` runtime log line — session
/// stores, live sessions, the console proxy, hub/push exporters, telemetry
/// spill, list/cache/webview warnings, and any future one. Every such site
/// routes through here instead of hand-rolling `eprintln!("[ipe.<tag>] ...")`,
/// so the control-character scrub, `gutter_line`'s human-terminal indent and the
/// broken-pipe-tolerant write apply uniformly with no bypass path. Pinned by the
/// source scan in `runtime_log_emitter_tests` below.
pub(crate) fn emit_runtime_log(tag: &str, msg: &str) {
    write_stderr_line(&runtime_log_line(None, tag, msg));
}

/// `emit_runtime_log` for a line that carries a leading timestamp before its
/// tag (the memory session-store startup line).
#[cfg(all(feature = "web-core", feature = "server"))]
pub(crate) fn emit_runtime_log_stamped(stamp: &str, tag: &str, msg: &str) {
    write_stderr_line(&runtime_log_line(Some(stamp), tag, msg));
}

/// Resolve the port an HTTP listener binds: `env_value` (as injected by
/// `ipe watch` — `IPE_SERVER_PORT` for `Ipe.Http.Server`, `IPE_WEB_PORT` for
/// `Ipe.Web`) when it is a valid port number in `1..=65535`, else `fallback`.
///
/// Parsing to `u16` and rejecting `0` closes EVERY out-of-range and garbage
/// value at the boundary: empty, non-numeric, negative, greater than 65535, or
/// `0` all fall back to `fallback` — never a silently OS-chosen ephemeral port
/// the caller cannot reach. Fail-closed by construction; the single definition
/// keeps the two runtimes' port precedence from drifting. Pure over its inputs,
/// so the precedence is unit-testable without touching the process environment.
///
/// Gated to `server`: the only callers — `server::server_listen`
/// (`IPE_SERVER_PORT`) and `web::serve_web` (`IPE_WEB_PORT`, whose `web` feature
/// implies `server`) — are both `#[cfg(feature = "server")]`, so a build without
/// the server surface would otherwise carry this as dead code.
#[cfg(feature = "server")]
pub(crate) fn resolve_listen_port(env_value: Option<String>, fallback: i64) -> i64 {
    env_value
        .and_then(|s| s.parse::<u16>().ok())
        .filter(|&p| p != 0)
        .map(i64::from)
        .unwrap_or(fallback)
}

/// Read an environment variable as an `OsString` — the `var_os` companion of
/// `read_env_var` (same overlay-first semantics). `None` when unset (or masked by
/// an overlay tombstone) or — unlike `read_env_var` — when the real value is not
/// valid Unicode. Gated to the feature whose module actually reads `var_os`
/// (`tui` — the `NO_COLOR` probe); widen the gate when another feature gains a
/// `var_os` reader, so it never sits as dead code under `-D warnings`. A
/// temp-root key reads as unset, as in `read_env_var`.
#[cfg(any(feature = "tui", feature = "debugger"))]
pub(crate) fn read_env_var_os(key: &str) -> Option<std::ffi::OsString> {
    if super::scratch_core::is_temp_root_key(key) {
        return None;
    }
    let overlay = ENV_OVERLAY
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match overlay.get(key) {
        Some(Some(v)) => Some(std::ffi::OsString::from(v)),
        Some(None) => None,
        #[allow(clippy::disallowed_methods)] // the accessor: overlay and temp roots answered first
        None => std::env::var_os(key),
    }
}

/// Snapshot the overlay as explicit child-env directives: `(key, Some(val))` sets
/// the var on the child, `(key, None)` removes it (so a tombstone masks an
/// inherited value). Applied by the `Process.*` spawn paths ON TOP of the
/// inherited real environ, so a child observes exactly the env Ipê observes
/// without the parent ever mutating its own `environ`.
pub(crate) fn env_overlay_snapshot() -> Vec<(String, Option<String>)> {
    let overlay = ENV_OVERLAY
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    overlay
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// Set an environment variable in the process-local overlay (never the real
/// `environ`). A key/value the overlay would reject (`env_entry_is_valid`) is a
/// silent no-op rather than a panic.
pub(crate) fn locked_set_var(key: &str, val: &str) {
    if !env_entry_is_valid(key, val) {
        return;
    }
    let mut overlay = ENV_OVERLAY
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    overlay.insert(key.to_owned(), Some(val.to_owned()));
}

/// Set an overlay variable ONLY if it is currently absent (in BOTH the overlay
/// and the real environ), performing the presence check and the set atomically
/// under a SINGLE write-lock acquisition — no TOCTOU window a separate read + set
/// would open. Same admission rule as `locked_set_var` — never panics.
pub(crate) fn locked_set_var_if_absent(key: &str, val: &str) {
    if !env_entry_is_valid(key, val) {
        return;
    }
    let mut overlay = ENV_OVERLAY
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let absent = match overlay.get(key) {
        Some(Some(_)) => false,
        Some(None) => true,
        #[allow(clippy::disallowed_methods)] // presence in the real environ, never its value
        None => std::env::var_os(key).is_none(),
    };
    if absent {
        overlay.insert(key.to_owned(), Some(val.to_owned()));
    }
}

/// Remove an environment variable: record a tombstone in the overlay so the key
/// reads as unset even when present in the real environ. An empty/`=`-bearing/NUL
/// key is a no-op (never a valid var to remove).
pub(crate) fn locked_remove_var(key: &str) {
    if key.is_empty() || key.contains('=') || key.contains('\0') {
        return;
    }
    let mut overlay = ENV_OVERLAY
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    overlay.insert(key.to_owned(), None);
}

#[must_use]
pub fn system_args<E: Send + From<IpeError> + 'static>(_: ()) -> IpeTask<E, Vec<String>> {
    Box::pin(async move {
        match decode_args(std::env::args_os()) {
            Ok(args) => ok_res(args),
            Err(e) => IpeResult::Err(e.into()),
        }
    })
}

/// The one UTF-8 decode an OS argument passes through. The refusal names the
/// argument's position only: argv can carry a credential, so its bytes never
/// reach an error message.
fn utf8_arg(arg: std::ffi::OsString, index: usize) -> Result<String, IpeError> {
    arg.into_string().map_err(|_| {
        IpeError::invalid_input(format!("command-line argument {index} is not valid UTF-8"))
    })
}

/// Every argument after the program name, each decoded as UTF-8.
fn decode_args(argv: impl Iterator<Item = std::ffi::OsString>) -> Result<Vec<String>, IpeError> {
    argv.enumerate()
        .skip(1)
        .map(|(index, arg)| utf8_arg(arg, index))
        .collect()
}

/// The argument at `n` of the full vector (index 0 is the program name). A
/// negative `n`, or one past the target's `usize`, is out of range.
fn decode_arg_at(
    mut argv: impl Iterator<Item = std::ffi::OsString>,
    n: i64,
) -> Result<IpeMaybe<String>, IpeError> {
    let Ok(index) = usize::try_from(n) else {
        return Ok(IpeMaybe::Nothing);
    };
    match argv.nth(index) {
        Some(arg) => utf8_arg(arg, index).map(IpeMaybe::Just),
        None => Ok(IpeMaybe::Nothing),
    }
}

// ── shared blocking-pool helper ───────────────────────────────────────
//
// `process_run` calls `std::process::Command::output()`, which BLOCKS the
// calling thread until the child process exits — an arbitrarily long wait
// (the whole point of `Process.run` is running a caller-chosen subprocess).
// On a tokio worker thread that stalls every other task scheduled on it for
// the subprocess's full runtime — reactor starvation, same class as the
// bcrypt/gzip/zstd/file cases. `system` (this module) is UNCONDITIONALLY
// compiled (not gated behind any feature — see the module-level comment
// above `pub mod system;` in `mod.rs`), while `tokio` is an `optional = true`
// dependency, so `tokio` is not guaranteed present here. Same
// `#[cfg(feature = "tokio")]` / fallback split `file.rs` uses for its own
// `run_blocking` helper (real generated Ipê projects always have `tokio` —
// see `docs/adr/0003-security-render-and-data-access-invariants.md`
// §2.2 — so the fallback only matters for this crate's own narrow-feature
// standalone builds).
// tokio is native-only (declared under the `cfg(not(target_arch = "wasm32"))`
// dependency table), so the `spawn_blocking` offload compiles only there. On
// wasm32 the synchronous fallback runs even when `feature = "tokio"` is set —
// the browser has no blocking-thread pool to offload to.
#[cfg(all(feature = "tokio", not(target_arch = "wasm32")))]
async fn run_blocking<T, F>(f: F) -> Result<T, String>
where
    F: FnOnce() -> Result<T, String> + Send + 'static,
    T: Send + 'static,
{
    match tokio::task::spawn_blocking(f).await {
        Ok(r) => r,
        Err(_) => Err("background process task panicked".to_string()),
    }
}

#[cfg(any(not(feature = "tokio"), target_arch = "wasm32"))]
// `async` is required here to match the tokio variant's signature; callers
// always use `.await` to work with both feature configurations uniformly.
#[allow(clippy::unused_async)]
async fn run_blocking<T, F>(f: F) -> Result<T, String>
where
    F: FnOnce() -> Result<T, String> + Send + 'static,
    T: Send + 'static,
{
    f()
}

/// The default combined-output capture ceiling (16 MiB), overridable via
/// `IPE_PROCESS_OUTPUT_MAX` (bytes). A subprocess is a caller-chosen program
/// that may write without bound (or be attacker-influenced); an uncapped
/// `Command::output()` buffers ALL of it in memory and can OOM the host. Reading
/// past the ceiling is an `Err`, never a silent truncation of a returned success
/// value.
fn process_output_ceiling() -> u64 {
    read_env_var("IPE_PROCESS_OUTPUT_MAX")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(16 * 1024 * 1024)
}

/// The captured result of a subprocess: its combined stdout+stderr (bounded)
/// and whether it exited successfully. `status` is the display form of the exit
/// status so the sync helper needs no `std::process` types in its signature.
struct ProcessCapture {
    combined: Vec<u8>,
    success: bool,
    status: String,
}

/// RAII owner of a spawned child: guarantees the child is reaped on EVERY exit
/// path (early `?` return, panic, or normal completion). `std::process::Child`'s
/// `Drop` does NOT kill or reap, so without this a read error or a bail would
/// leak a running, unreaped child (a zombie in a long-lived server). `wait()`
/// takes ownership so the destructor becomes a no-op once the caller has reaped
/// the child itself on the success path.
struct ChildGuard(Option<std::process::Child>);

impl ChildGuard {
    fn get_mut(&mut self) -> Option<&mut std::process::Child> {
        self.0.as_mut()
    }

    /// Reap the child ourselves, taking it out of the guard so `Drop` does
    /// nothing. Returns the exit status.
    fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        match self.0.take() {
            Some(mut c) => c.wait(),
            None => Err(std::io::Error::other("child already reaped")),
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut c) = self.0.take() {
            // The child is still owned here => it was NOT reaped on a normal
            // path (an error/bail/panic left it running). Kill then reap so no
            // subprocess is left running and no zombie accumulates.
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

/// Read up to `limit` bytes from `reader` on a dedicated thread. Draining each
/// pipe on its OWN thread avoids the sequential-drain deadlock: a child that
/// fills one pipe's kernel buffer while blocking on the other cannot wedge the
/// capture, because both pipes are drained concurrently. The `take(limit)` bound
/// caps peak per-stream allocation regardless of how much the child writes.
/// `limit` is a per-call value (`cap + 1`) passed by ownership, so concurrent
/// `process_run` calls never share or clobber it.
fn spawn_capture_thread<R>(
    reader: Option<R>,
    limit: u64,
) -> std::thread::JoinHandle<std::io::Result<Vec<u8>>>
where
    R: std::io::Read + Send + 'static,
{
    std::thread::spawn(move || {
        use std::io::Read as _;
        let mut buf = Vec::new();
        if let Some(reader) = reader {
            reader.take(limit).read_to_end(&mut buf)?;
        }
        Ok::<_, std::io::Error>(buf)
    })
}

/// Spawn `cmd args` with NO shell (direct argv), capturing combined
/// stdout+stderr under `cap`. stdout and stderr are drained on SEPARATE threads
/// (no sequential-drain pipe deadlock), each bounded by `take(cap + 1)`; the
/// combined result over `cap` is an `Err`, never an unbounded allocation.
/// `stdin` is closed (`Stdio::null`) so a child reading stdin gets EOF and
/// cannot block the capture. The child is reaped on every exit path via
/// [`ChildGuard`].
/// Apply the process-local env overlay to a child `Command`: overlay sets become
/// `env`, tombstones become `env_remove`. The runtime never mutates its own
/// `environ`, so without this a child would inherit only the real environ and
/// miss every Ipê `System.setenv`/`unsetenv`/`loadEnv`. Applied BEFORE any
/// per-child override so an explicit override still wins.
fn apply_env_overlay(builder: &mut std::process::Command) {
    for (k, v) in env_overlay_snapshot() {
        match v {
            Some(val) => {
                builder.env(k, val);
            }
            None => {
                builder.env_remove(k);
            }
        }
    }
}

/// Why a hardened spawn was refused.
///
/// Every variant is a refusal: a hardened spawn never degrades to an unhardened
/// one. The variants split on whether a child can exist. `Spawn` and
/// `SpawnPanicked` from `spawn_hardened_tokio` may follow the fork: tokio drops
/// a child it forked but failed to register without killing it, and that child
/// runs until this process exits, when the parent-death floor SIGTERMs it
/// (Linux only; elsewhere nothing bounds it by this process). Every other
/// variant, and every variant from `spawn_hardened`, leaves no child running.
#[derive(Debug)]
pub enum SpawnRefusal {
    /// The process-lifetime spawner thread could not be started.
    SpawnerUnavailable(std::io::ErrorKind),
    /// The spawner thread is gone: its job queue or the reply was disconnected.
    SpawnerGone,
    /// The spawner neither accepted nor answered the request within the ceiling.
    ///
    /// A child the spawner hands back for the abandoned request afterwards is
    /// killed; one tokio forks and then fails to register is the `Spawn` case,
    /// which no requester sees.
    ReplyTimedOut,
    /// The runtime refused the child listener claimed before the fork.
    ///
    /// Nothing was forked.
    #[cfg(all(feature = "web", unix))]
    ProbeRefused(std::io::Error),
    /// Claiming the child listener before the fork panicked.
    ///
    /// Nothing was forked. Tokio panics here when the runtime was built without
    /// `enable_io`. Reachable only where panics unwind: under `panic = "abort"`
    /// (every emitted release build) the panic aborts the process instead.
    #[cfg(all(feature = "web", unix))]
    ProbePanicked,
    /// The spawn panicked on the spawner thread, which caught it and lives on.
    ///
    /// From `spawn_hardened_tokio` the panic may follow the fork (tokio panics
    /// registering a child with a runtime missing a driver), leaving a child
    /// that only the parent-death floor bounds. Reachable only where panics
    /// unwind: under `panic = "abort"` (every emitted release build) the panic
    /// aborts the process, and the floor SIGTERMs any forked child.
    SpawnPanicked,
    /// `spawn_hardened_tokio` was called outside a tokio runtime.
    #[cfg(all(feature = "web", not(target_arch = "wasm32")))]
    NoRuntime,
    /// The spawn failed.
    ///
    /// From `spawn_hardened` nothing is left running: std reaps a child whose
    /// `exec` failed. From `spawn_hardened_tokio` the error may follow the
    /// fork, when tokio fails to register the forked child (a driver shutting
    /// down, a stdio or pidfd registration refused) and drops it unkilled; that
    /// child is bounded only by the parent-death floor.
    Spawn(std::io::Error),
}

impl std::fmt::Display for SpawnRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SpawnerUnavailable(kind) => {
                write!(f, "the process spawner thread could not start ({kind})")
            }
            Self::SpawnerGone => f.write_str("the process spawner thread is gone"),
            Self::ReplyTimedOut => f.write_str("the process spawner did not answer in time"),
            #[cfg(all(feature = "web", unix))]
            Self::ProbeRefused(e) => write!(
                f,
                "the tokio runtime refused a child listener; nothing was spawned ({})",
                e.kind()
            ),
            #[cfg(all(feature = "web", unix))]
            Self::ProbePanicked => f.write_str(
                "the tokio runtime has no IO or signal driver for a child; nothing was spawned",
            ),
            Self::SpawnPanicked => f.write_str("the spawn panicked on the process spawner thread"),
            #[cfg(all(feature = "web", not(target_arch = "wasm32")))]
            Self::NoRuntime => f.write_str("no tokio runtime is active on the spawning thread"),
            Self::Spawn(e) => write!(f, "spawn failed ({})", e.kind()),
        }
    }
}

impl std::error::Error for SpawnRefusal {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Spawn(e) => Some(e),
            #[cfg(all(feature = "web", unix))]
            Self::ProbeRefused(e) => Some(e),
            #[cfg(all(feature = "web", unix))]
            Self::ProbePanicked => None,
            #[cfg(all(feature = "web", not(target_arch = "wasm32")))]
            Self::NoRuntime => None,
            Self::SpawnerUnavailable(_)
            | Self::SpawnerGone
            | Self::ReplyTimedOut
            | Self::SpawnPanicked => None,
        }
    }
}

impl From<SpawnRefusal> for std::io::Error {
    fn from(refusal: SpawnRefusal) -> Self {
        match refusal {
            SpawnRefusal::Spawn(e) => e,
            #[cfg(all(feature = "web", unix))]
            refused @ (SpawnRefusal::ProbeRefused(_) | SpawnRefusal::ProbePanicked) => {
                Self::other(refused)
            }
            #[cfg(all(feature = "web", not(target_arch = "wasm32")))]
            refused @ SpawnRefusal::NoRuntime => Self::other(refused),
            refused @ (SpawnRefusal::SpawnerUnavailable(_)
            | SpawnRefusal::SpawnerGone
            | SpawnRefusal::ReplyTimedOut
            | SpawnRefusal::SpawnPanicked) => Self::other(refused),
        }
    }
}

/// Longest a hardened spawn waits for the spawner to accept and answer it.
const SPAWN_REPLY_CEILING: std::time::Duration = std::time::Duration::from_secs(30);

/// Most spawn requests queued on the spawner at once; a full queue is retried
/// until `SPAWN_REPLY_CEILING`, never grown.
const SPAWN_QUEUE_BOUND: usize = 16;

/// Pause between attempts to enqueue on a full spawner queue.
const SPAWN_QUEUE_RETRY: std::time::Duration = std::time::Duration::from_millis(1);

/// One spawn request, run on the spawner thread.
type SpawnJob = Box<dyn FnOnce() + Send + 'static>;

/// The spawner's job queue, or why its thread could not start.
type SpawnerSlot = Result<std::sync::mpsc::SyncSender<SpawnJob>, std::io::ErrorKind>;

/// The process-lifetime spawner thread's job queue.
///
/// The sender lives in a `static`, so the queue never disconnects and the
/// thread's `recv` loop never ends: the thread lives as long as the process.
/// `PR_SET_PDEATHSIG` fires when the FORKING THREAD exits, so forking only here
/// makes the signal mean "the process died", never "some worker thread was
/// reaped".
///
/// Jobs run one at a time, so a spawn stuck in the kernel (an `exec` in
/// uninterruptible sleep) delays every later request. The delay is bounded: a
/// queued requester gives up at `SPAWN_REPLY_CEILING` with `ReplyTimedOut`, and
/// the child forked for it afterwards is reclaimed, never handed out unhardened.
fn spawner() -> Result<&'static std::sync::mpsc::SyncSender<SpawnJob>, SpawnRefusal> {
    static SPAWNER: std::sync::OnceLock<SpawnerSlot> = std::sync::OnceLock::new();
    SPAWNER
        .get_or_init(|| {
            let (jobs, queue) = std::sync::mpsc::sync_channel::<SpawnJob>(SPAWN_QUEUE_BOUND);
            std::thread::Builder::new()
                .name("ipe-spawner".to_owned())
                .spawn(move || run_spawn_jobs(&queue))
                .map(|_| jobs)
                .map_err(|e| e.kind())
        })
        .as_ref()
        .map_err(|kind| SpawnRefusal::SpawnerUnavailable(*kind))
}

/// Run every job `queue` yields, until it disconnects.
///
/// A panicking job is contained so the spawner outlives it. A job's spawn
/// panic is answered inside the job as `SpawnPanicked`; this containment is
/// the backstop for a panic anywhere else in a job.
fn run_spawn_jobs(queue: &std::sync::mpsc::Receiver<SpawnJob>) {
    while let Ok(job) = queue.recv() {
        let _unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(job));
    }
}

/// Run `spawn` on the spawner behind `jobs` and hand its child back.
///
/// A child whose requester is no longer waiting is passed to `discard` on the
/// spawner thread, so a child `spawn` hands back to an abandoned request never
/// stays running. A panic out of `spawn` is caught on the spawner thread and
/// answered as `SpawnPanicked`.
fn request_spawn<T: Send + 'static>(
    jobs: &std::sync::mpsc::SyncSender<SpawnJob>,
    ceiling: std::time::Duration,
    spawn: impl FnOnce() -> Result<T, SpawnRefusal> + Send + 'static,
    discard: fn(T),
) -> Result<T, SpawnRefusal> {
    use std::sync::mpsc::{RecvTimeoutError, SendError, TrySendError};

    let start = std::time::Instant::now();
    // Capacity 0 makes the reply a rendezvous: a child is handed over only to a
    // requester still inside `recv_timeout`. A buffered slot would accept a
    // child sent just after the requester timed out, and dropping the receiver
    // would then drop that child unkilled; with no slot the late `send` fails
    // and `discard` reclaims the child on the spawner thread.
    let (reply, answer) = std::sync::mpsc::sync_channel::<Result<T, SpawnRefusal>>(0);
    let mut job: SpawnJob = Box::new(move || {
        let spawned = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(spawn)) {
            Ok(spawned) => spawned,
            Err(_payload) => Err(SpawnRefusal::SpawnPanicked),
        };
        if let Err(SendError(Ok(child))) = reply.send(spawned) {
            discard(child);
        }
    });
    loop {
        match jobs.try_send(job) {
            Ok(()) => break,
            Err(TrySendError::Disconnected(_)) => return Err(SpawnRefusal::SpawnerGone),
            Err(TrySendError::Full(back)) => {
                if start.elapsed() >= ceiling {
                    return Err(SpawnRefusal::ReplyTimedOut);
                }
                job = back;
                std::thread::sleep(SPAWN_QUEUE_RETRY);
            }
        }
    }
    match answer.recv_timeout(ceiling.saturating_sub(start.elapsed())) {
        Ok(spawned) => spawned,
        Err(RecvTimeoutError::Timeout) => Err(SpawnRefusal::ReplyTimedOut),
        Err(RecvTimeoutError::Disconnected) => Err(SpawnRefusal::SpawnerGone),
    }
}

/// Spawn `cmd` with the parent-death floor, forked by the spawner thread.
///
/// On Linux the child is SIGTERMed when this process dies by ANY means, and
/// never earlier: the forking thread is the process-lifetime spawner, not the
/// caller's (possibly short-lived) thread.
///
/// # Thread attributes
///
/// The child inherits the per-thread kernel attributes of the spawner thread,
/// not of the requesting thread: its seccomp filter, Landlock domain,
/// `no_new_privs` bit, CPU affinity and namespaces. A restriction a caller
/// applies only to its own thread does not reach the child.
///
/// # Errors
///
/// A `SpawnRefusal` when the spawner is unavailable, gone, or silent past
/// `SPAWN_REPLY_CEILING`, or when the spawn itself fails. No refusal leaves a
/// child running, and none ever falls back to an unhardened spawn.
pub fn spawn_hardened(cmd: std::process::Command) -> Result<std::process::Child, SpawnRefusal> {
    spawn_hardened_on(spawner()?, SPAWN_REPLY_CEILING, cmd)
}

/// `spawn_hardened` against an explicit spawner queue and reply ceiling.
fn spawn_hardened_on(
    jobs: &std::sync::mpsc::SyncSender<SpawnJob>,
    ceiling: std::time::Duration,
    mut cmd: std::process::Command,
) -> Result<std::process::Child, SpawnRefusal> {
    request_spawn(
        jobs,
        ceiling,
        move || {
            harden_child_parent_death(&mut cmd);
            cmd.spawn().map_err(SpawnRefusal::Spawn)
        },
        |mut child: std::process::Child| {
            let _ = child.kill();
            let _ = child.wait();
        },
    )
}

/// Spawn a tokio `cmd` with the parent-death floor, forked by the spawner thread.
///
/// The child is registered with the caller's tokio runtime (the spawner enters
/// the caller's runtime handle to spawn it), so it is awaited like any tokio
/// child, and the caller's `kill_on_drop` still applies. A child abandoned by
/// a timed-out requester is killed; tokio's orphan queue reaps it when the
/// runtime next handles `SIGCHLD`.
///
/// Registering a child needs the runtime's IO and signal drivers, and tokio
/// panics when they are absent. On Unix the spawner claims a `SIGCHLD`
/// listener before it forks, so a runtime built without `enable_io` is refused
/// as `ProbePanicked`, and a refused listener as `ProbeRefused`, with no child
/// forked.
///
/// # Errors
///
/// `SpawnRefusal::NoRuntime` when called outside a tokio runtime, the probe
/// refusals above, otherwise the refusals of `spawn_hardened`. A `Spawn` or
/// `SpawnPanicked` refusal here may follow the fork and leave a child that only
/// the parent-death floor bounds (see [`SpawnRefusal`]). No refusal ever falls
/// back to an unhardened spawn.
#[cfg(all(feature = "web", not(target_arch = "wasm32")))]
pub fn spawn_hardened_tokio(
    mut cmd: tokio::process::Command,
) -> Result<tokio::process::Child, SpawnRefusal> {
    let handle = tokio::runtime::Handle::try_current().map_err(|_| SpawnRefusal::NoRuntime)?;
    request_spawn(
        spawner()?,
        SPAWN_REPLY_CEILING,
        move || {
            let _runtime = handle.enter();
            #[cfg(unix)]
            let _drivers = probe_child_listener()?;
            harden_child_parent_death(cmd.as_std_mut());
            cmd.spawn().map_err(SpawnRefusal::Spawn)
        },
        |mut child: tokio::process::Child| {
            let _ = child.start_kill();
        },
    )
}

/// Claim a `SIGCHLD` listener on the entered runtime before any fork.
///
/// Tokio panics claiming it on a runtime without its IO or signal driver; the
/// panic is caught here so it surfaces as `ProbePanicked`, distinct from a
/// panic after the fork.
#[cfg(all(feature = "web", unix))]
fn probe_child_listener() -> Result<tokio::signal::unix::Signal, SpawnRefusal> {
    use tokio::signal::unix::{SignalKind, signal};
    match std::panic::catch_unwind(|| signal(SignalKind::child())) {
        Ok(Ok(listener)) => Ok(listener),
        Ok(Err(e)) => Err(SpawnRefusal::ProbeRefused(e)),
        Err(_payload) => Err(SpawnRefusal::ProbePanicked),
    }
}

/// Give a child the non-graceful death floor: if the parent process dies by ANY
/// means (SIGKILL, OOM, panic-abort — the paths a signal handler or `Drop` can
/// never run on) the kernel delivers SIGTERM to the child, so it can never
/// outlive the parent as an orphan holding a port or other resource. No-op on
/// non-Linux (where graceful shutdown / kill-tracking are the only floor).
///
/// THE single sanctioned `PR_SET_PDEATHSIG` site in the whole workspace (see
/// `PRINCIPLES.md` / `AGENTS.md`). Private: it runs only inside a spawn job on
/// the process-lifetime spawner thread (`spawn_hardened` /
/// `spawn_hardened_tokio`), because the kernel fires the signal when the thread
/// that FORKED the child exits, and only that thread lives as long as the
/// process.
///
/// A parent that dies after the fork but before the child armed the signal
/// leaves the child already reparented, so the signal would never fire. The
/// child therefore compares its parent pid, AFTER arming, with the launcher
/// pid captured before the spawn, and refuses to exec (`ESRCH`) on a mismatch:
/// no orphan survives the fork-to-`prctl` window.
fn harden_child_parent_death(_builder: &mut std::process::Command) {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt as _;
        let launcher = rustix::process::getpid();
        // SAFETY: the closure runs in the forked child between fork and exec. It
        // only issues the raw `prctl(PR_SET_PDEATHSIG)` and `getppid` syscalls
        // through rustix's safe wrappers (async-signal-safe) and builds its error
        // from a raw errno — no allocation, no locks, no Rust runtime re-entry.
        // A failed `prctl` is non-fatal (best-effort hardening); a reparented
        // child is refused.
        // IPE-RUST-AUDIT:ACCEPTED — std `pre_exec` is an unsafe API with no safe
        // parent-death-signal equivalent; the workspace's sole non-FFI `unsafe`.
        #[allow(unsafe_code)]
        unsafe {
            _builder.pre_exec(move || {
                let _ = rustix::process::set_parent_process_death_signal(Some(
                    rustix::process::Signal::TERM,
                ));
                still_parented_by(launcher, rustix::process::getppid())
            });
        }
    }
}

/// Refuse (`ESRCH`) unless the child's current `parent` is still `launcher`.
///
/// Runs in the forked child, so it only compares and builds an error from a
/// raw errno: no allocation.
#[cfg(target_os = "linux")]
fn still_parented_by(
    launcher: rustix::process::Pid,
    parent: Option<rustix::process::Pid>,
) -> std::io::Result<()> {
    if parent == Some(launcher) {
        Ok(())
    } else {
        Err(rustix::io::Errno::SRCH.into())
    }
}

fn process_run_sync(cmd: &str, args: &[String], cap: u64) -> Result<ProcessCapture, String> {
    use std::process::{Command, Stdio};

    let mut builder = Command::new(cmd);
    builder
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    apply_env_overlay(&mut builder);
    let child = builder.spawn().map_err(|e| format!("{cmd}: {e}"))?;
    let mut guard = ChildGuard(Some(child));

    // Per-stream read bound; passed by value to each capture thread (no shared
    // global, so concurrent `process_run` calls cannot clobber one another).
    let limit = cap.saturating_add(1);

    // Take the pipe handles so each thread owns its reader; a `?` before the
    // joins still reaps the child via `guard`'s `Drop`.
    let (stdout, stderr) = {
        let c = guard
            .get_mut()
            .ok_or_else(|| format!("{cmd}: child unexpectedly reaped"))?;
        (c.stdout.take(), c.stderr.take())
    };
    let out_handle = spawn_capture_thread(stdout, limit);
    let err_handle = spawn_capture_thread(stderr, limit);

    // A thread panic (e.g. OOM in the reader) surfaces as an `Err`, never a
    // propagated panic; `guard` still reaps the child on the `?` return.
    let mut combined = out_handle
        .join()
        .map_err(|_| format!("{cmd}: stdout capture thread panicked"))?
        .map_err(|e| format!("{cmd}: {e}"))?;
    let stderr_bytes = err_handle
        .join()
        .map_err(|_| format!("{cmd}: stderr capture thread panicked"))?
        .map_err(|e| format!("{cmd}: {e}"))?;
    // Combined = stdout then stderr (callers usually treat it as `2>&1`).
    combined.extend_from_slice(&stderr_bytes);

    if combined.len() as u64 > cap {
        // `guard`'s `Drop` kills + reaps the still-running child on this bail.
        return Err(format!(
            "{cmd}: output exceeds the {cap}-byte capture ceiling \
             (raise IPE_PROCESS_OUTPUT_MAX)"
        ));
    }

    let status = guard.wait().map_err(|e| format!("{cmd}: {e}"))?;
    Ok(ProcessCapture {
        combined,
        success: status.success(),
        status: format!("{status}"),
    })
}

/// `Ipe.Process.run : String -> List String -> Task Error String` — run a
/// subprocess with NO shell (the arguments are a direct `argv` vector, never
/// passed to `sh -c`, so a caller-controlled argument can never be reinterpreted
/// as shell syntax — no command injection). Returns the child's combined
/// stdout+stderr on a clean exit; a non-zero exit or a spawn failure is `Err`
/// carrying the captured output + the status. Total — every failure maps to
/// `Err`, never a panic.
///
/// SECURITY: `Process.run` is a server-only capability (`subprocess`):
/// default-denied under `--target wasm`, and a program that reaches it is tagged
/// with the `subprocess` capability so a sandbox can isolate it. Captured output
/// is bounded (`process_output_ceiling`) so an unbounded-output child cannot OOM
/// the host. Sandboxing which programs may be spawned is the calling
/// application's responsibility.
///
/// The blocking spawn+wait is offloaded via `run_blocking` (see the module-level
/// doc comment above) so a long-running subprocess can't stall the tokio worker
/// thread polling this future.
#[must_use]
pub fn process_run<E: Send + From<String> + 'static>(
    cmd: String,
    args: Vec<String>,
) -> IpeTask<E, String> {
    process_run_with_cap(cmd, args, process_output_ceiling())
}

/// `process_run` with the capture ceiling supplied explicitly rather than read
/// from the environment. `process_run` reads `process_output_ceiling()` once and
/// forwards it here; tests exercise a specific ceiling by passing it directly,
/// so no test mutates the process-global environment (which would race a
/// concurrent subprocess call reading the same var).
#[must_use]
fn process_run_with_cap<E: Send + From<String> + 'static>(
    cmd: String,
    args: Vec<String>,
    cap: u64,
) -> IpeTask<E, String> {
    Box::pin(async move {
        // `process_run_sync` folds `cmd` into every `Err` string, so the outer
        // `Err` arm (a `run_blocking` `JoinError`, i.e. the blocking task
        // panicked) doesn't need `cmd` — it's moved into the closure.
        match run_blocking(move || process_run_sync(&cmd, &args, cap)).await {
            Ok(out) => {
                #[allow(clippy::disallowed_methods)] // process output reaches Ipê as `String` text
                let text = String::from_utf8_lossy(&out.combined).into_owned();
                if out.success {
                    ok_res(text)
                } else {
                    // Cap the captured output folded into the Err string: large /
                    // binary subprocess output bloats the error and may embed
                    // secrets the process printed. Truncate to a bounded prefix
                    // (on a char boundary) before prepending the status.
                    const MAX_ERR_OUTPUT: usize = 4096;
                    let snippet: String = if text.len() > MAX_ERR_OUTPUT {
                        let mut end = MAX_ERR_OUTPUT;
                        while end > 0 && !text.is_char_boundary(end) {
                            end -= 1;
                        }
                        // Total accessor — `end` is a char boundary <= len, so
                        // `get` yields Some; the fallback keeps it slice-free and
                        // clippy::indexing_slicing-clean for non-test runtime code.
                        format!("{}… (output truncated)", text.get(..end).unwrap_or(&text))
                    } else {
                        text
                    };
                    IpeResult::Err(str_err(&format!("{}: {}", snippet, out.status)))
                }
            }
            Err(e) => IpeResult::Err(str_err(&e)),
        }
    })
}
/// The structured result of a `runWith` spawn: independent exit code, stdout, and
/// stderr captures. Exposed as a `pub struct` so the emitter can access its fields
/// directly (the same pattern `email::EmailMessage` and `cache::CacheCfg` use).
///
/// Field names match the Ipê record keys verbatim (`exitCode` / `stdout` /
/// `stderr`); `#[allow(non_snake_case)]` suppresses the style lint for `exitCode`.
#[allow(non_snake_case)]
pub struct ProcessRunOutput {
    pub exitCode: i64,
    pub stdout: String,
    pub stderr: String,
}

/// Spawn `cmd args` under optional `cwd` and env overrides, capturing stdout and
/// stderr INDEPENDENTLY on SEPARATE threads (no sequential-drain pipe-deadlock),
/// each bounded by `take(cap + 1)`. Returns the exit code alongside the two
/// streams. The child is reaped on every exit path via `ChildGuard`. An env pair
/// whose key is empty, contains `=` or NUL, or whose value contains NUL is
/// silently skipped — the same guard `locked_set_var` applies.
fn process_run_with_sync(
    cmd: &str,
    args: &[String],
    cwd: Option<&std::path::Path>,
    env_overrides: &[(String, String)],
    cap: u64,
) -> Result<ProcessRunOutput, String> {
    use std::process::{Command, Stdio};

    let mut builder = Command::new(cmd);
    builder
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if let Some(dir) = cwd {
        builder.current_dir(dir);
    }

    // Overlay first (the env Ipê itself observes), then per-child overrides win.
    apply_env_overlay(&mut builder);
    for (k, v) in env_overrides {
        // Same admission rule as the overlay writers.
        if !env_entry_is_valid(k, v) {
            continue;
        }
        builder.env(k, v);
    }

    let child = builder.spawn().map_err(|e| format!("{cmd}: {e}"))?;
    let mut guard = ChildGuard(Some(child));

    let limit = cap.saturating_add(1);

    let (stdout_pipe, stderr_pipe) = {
        let c = guard
            .get_mut()
            .ok_or_else(|| format!("{cmd}: child unexpectedly reaped"))?;
        (c.stdout.take(), c.stderr.take())
    };
    let out_handle = spawn_capture_thread(stdout_pipe, limit);
    let err_handle = spawn_capture_thread(stderr_pipe, limit);

    let stdout_bytes = out_handle
        .join()
        .map_err(|_| format!("{cmd}: stdout capture thread panicked"))?
        .map_err(|e| format!("{cmd}: {e}"))?;
    let stderr_bytes = err_handle
        .join()
        .map_err(|_| format!("{cmd}: stderr capture thread panicked"))?
        .map_err(|e| format!("{cmd}: {e}"))?;

    if stdout_bytes.len() as u64 > cap {
        return Err(format!(
            "{cmd}: stdout exceeds the {cap}-byte capture ceiling \
             (raise IPE_PROCESS_OUTPUT_MAX)"
        ));
    }
    if stderr_bytes.len() as u64 > cap {
        return Err(format!(
            "{cmd}: stderr exceeds the {cap}-byte capture ceiling \
             (raise IPE_PROCESS_OUTPUT_MAX)"
        ));
    }

    let status = guard.wait().map_err(|e| format!("{cmd}: {e}"))?;
    #[allow(clippy::disallowed_methods)] // process output reaches Ipê as `String` text
    let stdout = String::from_utf8_lossy(&stdout_bytes).into_owned();
    #[allow(clippy::disallowed_methods)] // process output reaches Ipê as `String` text
    let stderr = String::from_utf8_lossy(&stderr_bytes).into_owned();

    #[allow(non_snake_case)]
    Ok(ProcessRunOutput {
        exitCode: i64::from(status.code().unwrap_or(-1)),
        stdout,
        stderr,
    })
}

/// `Ipe.Process.runWith` — spawn a child process with per-child cwd and env
/// overrides, capturing exit code, stdout, and stderr independently.
///
/// A non-zero exit is a NORMAL result carried in `exitCode`; only a spawn
/// failure fails the Task. Both streams are bounded by `IPE_PROCESS_OUTPUT_MAX`
/// (default 16 MiB) and drained concurrently (no pipe-deadlock). The blocking
/// spawn+wait is offloaded via `run_blocking` so a long-running child cannot
/// stall the tokio worker thread.
///
/// SECURITY: same `subprocess` capability gate as `Process.run`. Per-child
/// `cwd` and env overrides do NOT escape the jail/sandbox roots — the child
/// inherits its confined environment from the parent, and the overrides are
/// applied ON TOP of that already-confined environment.
#[must_use]
pub fn process_run_with<E: Send + From<String> + 'static>(
    cfg: ProcessRunWithCfg,
) -> IpeTask<E, ProcessRunOutput> {
    process_run_with_impl(cfg, process_output_ceiling())
}

/// `ProcessRunWithCfg` — the Ipê record `{ command, args, cwd, env }` lowered
/// to a plain Rust struct. Owned values let the closure move into `run_blocking`
/// without a lifetime on the borrow. The emitter constructs this directly
/// (same pattern as `EmailMessage` / `CacheCfg`).
///
/// Field names match the Ipê record keys verbatim (`exitCode` etc.); the
/// non_snake_case allow is per-field.
pub struct ProcessRunWithCfg {
    pub command: String,
    pub args: Vec<String>,
    /// `Nothing` → inherit the parent cwd; `Just(p)` → set the child's cwd.
    pub cwd: IpeMaybe<String>,
    /// Per-child env overrides as `(key, value)` pairs.
    pub env: Vec<(String, String)>,
}

#[must_use]
fn process_run_with_impl<E: Send + From<String> + 'static>(
    cfg: ProcessRunWithCfg,
    cap: u64,
) -> IpeTask<E, ProcessRunOutput> {
    Box::pin(async move {
        let result = run_blocking(move || {
            let cwd_path: Option<std::path::PathBuf> = match &cfg.cwd {
                IpeMaybe::Just(p) => Some(std::path::PathBuf::from(p)),
                IpeMaybe::Nothing => None,
            };
            process_run_with_sync(&cfg.command, &cfg.args, cwd_path.as_deref(), &cfg.env, cap)
        })
        .await;
        match result {
            Ok(out) => ok_res(out),
            Err(e) => IpeResult::Err(str_err(&e)),
        }
    })
}

/// `ProcessRunInPtyCfg` — the Ipê record `{ command, args, cwd, env, cols, rows }`
/// lowered to a plain Rust struct. Owned values let the closure move into
/// `run_blocking` without a borrow lifetime. The emitter constructs this directly
/// (same pattern as [`ProcessRunWithCfg`]).
///
/// Field names match the Ipê record keys verbatim.
pub struct ProcessRunInPtyCfg {
    pub command: String,
    pub args: Vec<String>,
    /// `Nothing` → inherit the parent cwd; `Just(p)` → set the child's cwd.
    pub cwd: IpeMaybe<String>,
    /// Per-child env overrides as `(key, value)` pairs.
    pub env: Vec<(String, String)>,
    /// Terminal width in columns; clamped into `u16` for the `winsize`.
    pub cols: i64,
    /// Terminal height in rows; clamped into `u16` for the `winsize`.
    pub rows: i64,
}

/// The structured result of a `runInPty` spawn: the child's exit code and the
/// combined stream read from the pty master until the child exits. Exposed as a
/// `pub struct` so the emitter constructs the return record directly (same pattern
/// as [`ProcessRunOutput`]).
#[allow(non_snake_case)]
pub struct ProcessPtyOutput {
    pub exitCode: i64,
    pub output: String,
}

/// `Ipe.Process.runInPty cfg` — run a child under a real pseudo-terminal, so a
/// TUI child sees `isatty(stdout) == true`, sizes to `cols`×`rows`, and emits
/// terminal control sequences. Returns the child's exit code and the combined
/// output read from the pty master until EOF, bounded by the same capture ceiling
/// as `Process.run` (`IPE_PROCESS_OUTPUT_MAX`, default 16 MiB) — a child that
/// floods the pty past the ceiling is an `Err`, never an unbounded allocation.
///
/// SECURITY: same `subprocess` capability gate as `Process.run` — the pty is an
/// implementation detail of running a child, not a new external reach. Every
/// fallible pty/spawn/read step maps to a typed `Err` (fail closed); no path
/// panics or hangs.
///
/// Unix-only: the pty surface (`openpt`/`grantpt`/`unlockpt`/`ptsname`) has no
/// meaning on non-unix targets, where this returns an honest unsupported `Err`
/// rather than a silent no-op. The blocking spawn+read+wait is offloaded via
/// `run_blocking` so a long-running child cannot stall the tokio worker thread.
#[must_use]
pub fn process_run_in_pty<E: Send + From<String> + 'static>(
    cfg: ProcessRunInPtyCfg,
) -> IpeTask<E, ProcessPtyOutput> {
    process_run_in_pty_impl(cfg, process_output_ceiling())
}

#[must_use]
fn process_run_in_pty_impl<E: Send + From<String> + 'static>(
    cfg: ProcessRunInPtyCfg,
    cap: u64,
) -> IpeTask<E, ProcessPtyOutput> {
    Box::pin(async move {
        match run_blocking(move || process_run_in_pty_sync(cfg, cap)).await {
            Ok(out) => ok_res(out),
            Err(e) => IpeResult::Err(str_err(&e)),
        }
    })
}

/// Non-unix fallback: the pty surface is unavailable, so fail closed with an
/// honest unsupported `Err` (never a silent success or no-op). Gated so the unix
/// body — which references `rustix::pty` — is the only code compiled where the
/// surface exists.
#[cfg(not(unix))]
fn process_run_in_pty_sync(
    _cfg: ProcessRunInPtyCfg,
    _cap: u64,
) -> Result<ProcessPtyOutput, String> {
    Err("Process.runInPty is only supported on Unix targets".to_owned())
}

/// Spawn `cfg.command cfg.args` under a freshly allocated pseudo-terminal, sized
/// to `cfg.cols`×`cfg.rows`, with the child's stdin/stdout/stderr all connected to
/// the pty replica. Reads the master to EOF into a buffer bounded by `cap` (a read
/// past the ceiling is an `Err`), then reaps the child via [`ChildGuard`].
///
/// Every fallible syscall maps to a typed `Err`:
/// - `openpt` (allocate the master) → `Err` on no-free-pty / EPERM.
/// - `grantpt` / `unlockpt` (grant + unlock the replica) → `Err` on failure.
/// - `ptsname` (resolve the replica path) → `Err` on failure.
/// - `open` (open the replica) → `Err` on failure.
/// - `tcsetwinsize` (set the window size) → `Err` on failure.
/// - `try_clone` (per-stdio replica handle) → `Err` on failure.
/// - `spawn` (start the child) → `Err` on failure.
/// - the master-read thread `join`/read → `Err` on panic or IO error.
/// - `wait` (reap) → `Err` on failure.
///
/// No `unsafe`: rustix's `pty`/`termios` wrappers and `std`'s `Stdio::from`
/// (fd → owned stdio) cover every step. The child's stdin also reads the pty
/// replica, so a child reading input blocks on the pty (EOF once the master is
/// closed) rather than the parent's stdin.
#[cfg(unix)]
fn process_run_in_pty_sync(cfg: ProcessRunInPtyCfg, cap: u64) -> Result<ProcessPtyOutput, String> {
    use std::io::Read as _;
    use std::process::{Command, Stdio};

    let cmd = &cfg.command;

    // Allocate the pty master with O_RDWR | O_NOCTTY (the parent must not acquire
    // the pty as its controlling terminal). `OpenptFlags::CLOEXEC` — keeping the
    // master out of the child's fd table — is only defined by rustix on
    // Linux/FreeBSD/NetBSD; where it is absent the master is simply left
    // inheritable (the child receives the replica as its stdio, never the master
    // handle by name), so its inheritance is inert.
    let openpt_flags = {
        let base = rustix::pty::OpenptFlags::RDWR | rustix::pty::OpenptFlags::NOCTTY;
        #[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "netbsd"))]
        {
            base | rustix::pty::OpenptFlags::CLOEXEC
        }
        #[cfg(not(any(target_os = "linux", target_os = "freebsd", target_os = "netbsd")))]
        {
            base
        }
    };
    let master =
        rustix::pty::openpt(openpt_flags).map_err(|e| format!("{cmd}: pty openpt failed: {e}"))?;

    // Grant + unlock the replica side, then resolve its filesystem path.
    rustix::pty::grantpt(&master).map_err(|e| format!("{cmd}: pty grantpt failed: {e}"))?;
    rustix::pty::unlockpt(&master).map_err(|e| format!("{cmd}: pty unlockpt failed: {e}"))?;
    let replica_name = rustix::pty::ptsname(&master, Vec::new())
        .map_err(|e| format!("{cmd}: pty ptsname failed: {e}"))?;

    // Open the replica the child will inherit as its stdio. O_NOCTTY: the child
    // acquires the controlling terminal via `setsid` semantics of process
    // separation, not by this open (the parent must not become the session leader).
    let replica = rustix::fs::open(
        replica_name.as_c_str(),
        rustix::fs::OFlags::RDWR | rustix::fs::OFlags::NOCTTY,
        rustix::fs::Mode::empty(),
    )
    .map_err(|e| format!("{cmd}: pty replica open failed: {e}"))?;

    // Size the pty. Clamp the caller's cols/rows into the kernel's `u16` window
    // fields (a negative or over-large value is clamped to the representable
    // range rather than wrapping). ws_xpixel/ws_ypixel are 0 (unused).
    let winsize = rustix::termios::Winsize {
        ws_row: clamp_u16(cfg.rows),
        ws_col: clamp_u16(cfg.cols),
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    rustix::termios::tcsetwinsize(&replica, winsize)
        .map_err(|e| format!("{cmd}: pty tcsetwinsize failed: {e}"))?;

    // Each of the child's three stdio slots needs its own owned handle to the
    // replica (each `Stdio::from` consumes one). Clone the replica fd twice; the
    // original covers the third.
    let replica_out = replica
        .try_clone()
        .map_err(|e| format!("{cmd}: pty replica dup failed: {e}"))?;
    let replica_err = replica
        .try_clone()
        .map_err(|e| format!("{cmd}: pty replica dup failed: {e}"))?;

    let mut builder = Command::new(cmd);
    builder
        .args(&cfg.args)
        .stdin(Stdio::from(replica))
        .stdout(Stdio::from(replica_out))
        .stderr(Stdio::from(replica_err));

    if let IpeMaybe::Just(dir) = &cfg.cwd {
        builder.current_dir(dir);
    }
    // Overlay first (the env Ipê itself observes), then per-child overrides win.
    apply_env_overlay(&mut builder);
    for (k, v) in &cfg.env {
        // Same admission rule as the overlay writers.
        if !env_entry_is_valid(k, v) {
            continue;
        }
        builder.env(k, v);
    }

    let child = builder.spawn().map_err(|e| format!("{cmd}: {e}"))?;
    let mut guard = ChildGuard(Some(child));

    // Close the parent's replica handles by dropping the `Command`: it retains
    // ownership of the three `Stdio`-wrapped replica fds after `spawn` (spawn
    // dup'd them into the child, but the parent's originals stay open until the
    // `Command` is dropped). Once ONLY the child holds replica ends open, reading
    // the master returns EOF when the child exits — otherwise the parent's own
    // open replica keeps the master readable forever, and the read below hangs.
    drop(builder);

    // Read the master to end-of-stream on a dedicated thread, bounded by `cap + 1`
    // so a flooding child cannot allocate without bound. `File::from` takes
    // ownership of the master fd; the reader thread owns it for its lifetime.
    //
    // On Linux, once the child (the last replica holder) closes the replica, a
    // read of the master returns `EIO` rather than a clean `Ok(0)` EOF — this is
    // the documented pty-master end-of-stream signal, not a real IO fault. Treat
    // `EIO` (and an interrupted `EINTR`) as end-of-stream; any OTHER error is a
    // genuine failure and propagates. The manual loop enforces the `cap + 1`
    // ceiling on peak allocation regardless.
    let mut master_file = std::fs::File::from(master);
    let limit = cap.saturating_add(1);
    let read_handle: std::thread::JoinHandle<std::io::Result<Vec<u8>>> =
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let mut chunk = [0u8; 8192];
            loop {
                let filled = u64::try_from(buf.len()).unwrap_or(u64::MAX);
                if filled >= limit {
                    break;
                }
                match master_file.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => {
                        // Never grow past `limit`: take only up to the ceiling.
                        let room = usize::try_from(limit - filled).unwrap_or(usize::MAX);
                        let take = n.min(room);
                        buf.extend_from_slice(chunk.get(..take).unwrap_or(&[]));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    // `EIO` on a pty master = the replica side closed = EOF.
                    Err(e) if e.raw_os_error() == Some(5) => break,
                    Err(e) => return Err(e),
                }
            }
            Ok(buf)
        });

    let combined = read_handle
        .join()
        .map_err(|_| format!("{cmd}: pty read thread panicked"))?
        .map_err(|e| format!("{cmd}: pty read failed: {e}"))?;

    if combined.len() as u64 > cap {
        // `guard`'s `Drop` kills + reaps the still-running child on this bail.
        return Err(format!(
            "{cmd}: pty output exceeds the {cap}-byte capture ceiling \
             (raise IPE_PROCESS_OUTPUT_MAX)"
        ));
    }

    let status = guard.wait().map_err(|e| format!("{cmd}: {e}"))?;
    #[allow(clippy::disallowed_methods)] // process output reaches Ipê as `String` text
    let output = String::from_utf8_lossy(&combined).into_owned();

    #[allow(non_snake_case)]
    Ok(ProcessPtyOutput {
        exitCode: i64::from(status.code().unwrap_or(-1)),
        output,
    })
}

/// Clamp an `i64` terminal dimension into the kernel `winsize`'s `u16` field: a
/// negative value becomes 0, an over-large value saturates at `u16::MAX`. Keeps a
/// caller-supplied `cols`/`rows` from wrapping into a nonsense window size.
#[cfg(unix)]
fn clamp_u16(n: i64) -> u16 {
    // `clamp` bounds `n` into `[0, u16::MAX]`, so the value is exactly
    // representable and `try_from` cannot fail; the fallback keeps it cast-free.
    u16::try_from(n.clamp(0, i64::from(u16::MAX))).unwrap_or(u16::MAX)
}

/// Process-exit cleanup hook. `std::process::exit` (what `System.exit` lowers to)
/// bypasses Drop, so an RAII guard's destructor never runs on that path. A backend
/// driver that puts the terminal/process into a state needing restoration (the
/// Ipe.Tui driver: raw mode + alternate screen + hidden cursor + mouse reporting)
/// registers its idempotent teardown here; `system_exit` runs it BEFORE
/// `process::exit`. The hook runs teardown before process termination, so RAII-
/// bypassed cleanup (terminal restore, cursor reset) completes before the OS reclaims
/// the process. A plain `fn()` keeps the boundary clean — `system` (always compiled) never
/// references the feature-gated `tui`/crossterm; the TUI provides the function.
static EXIT_HOOK: std::sync::OnceLock<fn()> = std::sync::OnceLock::new();

/// Register the process-exit cleanup (idempotent target; set once per process —
/// there is a single backend driver). Subsequent registrations are ignored.
pub fn register_exit_hook(f: fn()) {
    let _ = EXIT_HOOK.set(f);
}

/// Run the registered exit hook, if any. Called by `system_exit`; also safe to
/// call from a backend driver's own normal-exit path (the hook is idempotent).
pub fn run_exit_hook() {
    if let Some(f) = EXIT_HOOK.get() {
        f();
    }
}

pub fn system_exit(code: i64) -> ! {
    // Restore any driver-owned terminal/process state BEFORE exiting — Drop does
    // NOT run on std::process::exit, so without this a Ipe.Tui `System.exit` quit
    // would leave the TTY in raw mode + the alternate screen (needing `reset`).
    run_exit_hook();
    // IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — this IS the `System.exit` kernel: the Ipê program requested process termination with `code` [ledger #boundary]
    std::process::exit(code as i32)
}

/// `Ipe.System.getenv key : String -> Task Error String` — the env var as a
/// Task, or `Err` when unset. Returning a `IpeTask` (not a bare `String`) is
/// required for parity: `getenv` is Task-typed in the stdlib, so a bare `String`
/// fails to type-check in any `Task.andThen`/`Task.run` position. Returning `Err`
/// on unset (rather than `Ok("")`) fails the Task at the call site, so a
/// chained `Task.andThen` short-circuits on a missing variable. The error is
/// string-based — the generic `E` bound can only build `From<String>`, so the
/// error kind is a plain string. NOTE: `getenvOr` stays a bare
/// `String` (the default plugs the missing case at the call site).
#[must_use]
pub fn system_getenv<E: Send + From<String> + 'static>(key: String) -> IpeTask<E, String> {
    Box::pin(async move {
        if let Ok(v) = read_env_var(&key) {
            ok_res(v)
        } else {
            let msg = format!("environment variable {key:?} is not set");
            IpeResult::Err(str_err(&msg))
        }
    })
}
/// `Ipe.System.getenvOr key default` — the env var, or `default` when unset.
#[must_use]
pub fn system_getenv_or(key: String, default: String) -> String {
    read_env_var(&key).unwrap_or(default)
}

/// `System.getenvInt key : String -> Task Error Int`. Unset → `Err` (variable not
/// set); set-but-not-an-int → `Err` (parse failure). The string-based error
/// follows the generic-`E` convention (shared with `getenv`/`cwd`).
#[must_use]
pub fn system_getenv_int<E: Send + From<String> + 'static>(key: String) -> IpeTask<E, i64> {
    Box::pin(async move {
        let r: Result<i64, String> = match read_env_var(&key) {
            Err(_) => Err(format!("environment variable {key:?} is not set")),
            Ok(v) => v
                .trim()
                .parse::<i64>()
                // Do NOT echo the env var VALUE into the Ipê-propagated error
                // string: env vars are a primary secret store and this message
                // flows out via Task Error → Error.toString → operator logs /
                // user surface. Mirror system_getenv (key only).
                .map_err(|_| format!("env {key}: not a valid int")),
        };
        match r {
            Ok(n) => ok_res(n),
            Err(m) => IpeResult::Err(str_err(&m)),
        }
    })
}

/// `System.getenvBool key : String -> Task Error Bool`. Accepted truthy values:
/// `true/yes/1/on/y/t` → true; `false/no/0/off/n/f`/empty → false; unset →
/// `Err` (variable not set); anything else → `Err` (not a valid bool).
#[must_use]
pub fn system_getenv_bool<E: Send + From<String> + 'static>(key: String) -> IpeTask<E, bool> {
    Box::pin(async move {
        let r: Result<bool, String> = match read_env_var(&key) {
            Err(_) => Err(format!("environment variable {key:?} is not set")),
            Ok(v) => match v.trim().to_lowercase().as_str() {
                "true" | "yes" | "1" | "on" | "y" | "t" => Ok(true),
                "false" | "no" | "0" | "off" | "n" | "f" | "" => Ok(false),
                // Key only — never echo the env var VALUE (secret-store leak).
                _ => Err(format!("env {key}: not a valid bool")),
            },
        };
        match r {
            Ok(b) => ok_res(b),
            Err(m) => IpeResult::Err(str_err(&m)),
        }
    })
}

/// `System.getArg n : Int -> Task Error (Maybe String)`. Indexes the FULL arg
/// vector, where index 0 is the program name (unlike `System.args`, which
/// skips it); out-of-range or negative → `Ok Nothing`; an argument that is not
/// valid UTF-8 → `Err` `InvalidInput`.
#[must_use]
pub fn system_get_arg<E: Send + From<IpeError> + 'static>(n: i64) -> IpeTask<E, IpeMaybe<String>> {
    Box::pin(async move {
        match decode_arg_at(std::env::args_os(), n) {
            Ok(out) => ok_res(out),
            Err(e) => IpeResult::Err(e.into()),
        }
    })
}

#[must_use]
pub fn system_setenv<E: Send + 'static>(key: String, val: String) -> IpeTask<E, ()> {
    Box::pin(async move {
        locked_set_var(&key, &val);
        ok_res(())
    })
}

#[must_use]
pub fn system_unsetenv<E: Send + 'static>(key: String) -> IpeTask<E, ()> {
    Box::pin(async move {
        locked_remove_var(&key);
        ok_res(())
    })
}

/// `System.cwd : () -> Task Error String`.
///
/// The working directory passes the host seal; one that is not valid UTF-8
/// is refused as invalid input, never rewritten lossily.
#[must_use]
pub fn system_cwd<E: Send + From<IpeError> + 'static>(_: ()) -> IpeTask<E, String> {
    Box::pin(async move {
        let cwd = std::env::current_dir()
            .map_err(|e| IpeError::from(format!("{e}")))
            .and_then(|p| from_os(p.as_path(), OsOrigin::SystemCwd));
        match cwd {
            Ok(p) => ok_res(p.into_string()),
            Err(e) => IpeResult::Err(e.into()),
        }
    })
}

/// `System.getcwd : () -> Task Error String` — backward-compat alias for `cwd`.
/// Wraps `System_cwd` with a unit arg.
#[must_use]
pub fn system_getcwd<E: Send + From<IpeError> + 'static>(unit: ()) -> IpeTask<E, String> {
    system_cwd(unit)
}

/// Blocking half of `system_load_env`: read + parse `.env` in the CWD and set
/// each var. Never fails — a missing/unreadable `.env` is silently a no-op,
/// matching the Ipê-facing contract (`loadEnv` never returns `Err`).
fn system_load_env_sync() {
    if let Ok(contents) = std::fs::read_to_string(".env") {
        for line in contents.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                let k = k.trim();
                let v = v.trim().trim_matches('"').trim_matches('\'');
                // Atomic check-and-set under one write lock — avoids the
                // TOCTOU window a separate read + set would open against a
                // concurrent mutator.
                locked_set_var_if_absent(k, v);
            }
        }
    }
}

/// `System.loadEnv : () -> Task Error ()`. Parses a `.env` file in the CWD
/// (KEY=VALUE per line, `#` comments, optional surrounding quotes) and sets
/// each var WITHOUT overriding one already present in the process environment
/// (process env wins, matching Ipê's precedence). A missing `.env` is a no-op
/// success.
///
/// `std::fs::read_to_string(".env")` is a blocking syscall, so it routes
/// through the `run_blocking` helper this module defines (above, for
/// `process_run`) rather than running inline inside the `async move` body —
/// the same offload `file.rs`/`compression.rs`/`csv.rs`/`config_decode.rs`
/// use. Real-world impact is low (`.env` is small and read once at startup),
/// but on a slow/network filesystem an inline read would stall the tokio
/// worker thread polling this future.
#[must_use]
pub fn system_load_env<E: Send + 'static>(_: ()) -> IpeTask<E, ()> {
    Box::pin(async move {
        // `run_blocking`'s `Err` arm (the blocking task panicked) is folded
        // back into `Ok(())` here — `loadEnv` never surfaces an `Err` for a
        // missing/unreadable `.env`, and a panicked blocking task shouldn't
        // change that contract either.
        let _: Result<(), String> = run_blocking(|| {
            system_load_env_sync();
            Ok(())
        })
        .await;
        ok_res(())
    })
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod temp_root_env_tests {
    use super::{locked_remove_var, locked_set_var, read_env_var};
    use std::env::VarError;

    /// Every spelling of a temp-root key reads as unset, even when Ipê set it.
    #[test]
    fn a_temp_root_key_is_never_answered() {
        for key in ["TMPDIR", "tmpdir", "TmpDir", "TMP", "tmp", "TEMP", "Temp"] {
            locked_set_var(key, "/attacker/base");
            assert_eq!(read_env_var(key), Err(VarError::NotPresent), "{key:?}");
            locked_remove_var(key);
            assert_eq!(read_env_var(key), Err(VarError::NotPresent), "{key:?}");
        }
    }

    /// The `OsString` reader refuses every temp-root spelling alike, even when
    /// Ipê set it.
    #[cfg(any(feature = "tui", feature = "debugger"))]
    #[test]
    fn a_temp_root_key_is_never_answered_as_os_string() {
        for key in ["TMPDIR", "tmpdir", "TmpDir", "TMP", "tmp", "TEMP", "Temp"] {
            locked_set_var(key, "/attacker/base");
            assert_eq!(super::read_env_var_os(key), None, "{key:?}");
            locked_remove_var(key);
            assert_eq!(super::read_env_var_os(key), None, "{key:?}");
        }
    }

    /// A key that only contains a temp-root name is answered normally.
    #[test]
    fn a_neighbouring_key_is_answered() {
        let key = "IPE_TEMP_ROOT_ENV_TEST_NEIGHBOUR";
        locked_set_var(key, "v");
        assert_eq!(read_env_var(key), Ok("v".to_owned()));
        locked_remove_var(key);
        for key in ["TMPDIR_", "IPE_TMP", "TEMPLATE", "CARGO_TARGET_TMPDIR"] {
            assert!(
                !super::super::scratch_core::is_temp_root_key(key),
                "{key:?}"
            );
        }
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod exit_hook_tests {
    use super::{register_exit_hook, run_exit_hook};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static CALLS: AtomicUsize = AtomicUsize::new(0);
    fn bump() {
        CALLS.fetch_add(1, Ordering::SeqCst);
    }

    #[test]
    fn exit_hook_runs_and_is_safe_without_registration() {
        // No hook registered yet → run_exit_hook must be a safe no-op (the common
        // CLI / server / non-TUI case — System.exit must not require a hook).
        run_exit_hook();
        // Register one and confirm it runs (the Ipe.Tui driver registers its
        // terminal-restore here so a System.exit quit doesn't bypass cleanup).
        register_exit_hook(bump);
        run_exit_hook();
        assert!(
            CALLS.load(Ordering::SeqCst) >= 1,
            "registered exit hook must run"
        );
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod gutter_line_tests {
    use super::gutter_line;

    #[test]
    fn indents_only_under_a_terminal() {
        // Terminal stderr → 4-space gutter for the human dev loop (nests under
        // the CLI's own `[ipe watch] ...` status lines).
        assert_eq!(
            gutter_line("[ipe.http.server] listening on http://127.0.0.1:8000", true),
            "    [ipe.http.server] listening on http://127.0.0.1:8000"
        );
        // Piped/redirected stderr (the E2E harness reads through a pipe) stays
        // flush-left so `contains("[ipe.http.server] listening on")` matchers hold.
        assert_eq!(
            gutter_line(
                "[ipe.http.server] listening on http://127.0.0.1:8000",
                false
            ),
            "[ipe.http.server] listening on http://127.0.0.1:8000"
        );
    }
}

/// Drift guard for the "every `[ipe.<tag>] ...` runtime log line goes through
/// one emitter" invariant: `emit_runtime_log`/`format_runtime_log` above are
/// meant to be the ONLY place that ever constructs the `"[ipe.<tag>]"` prefix.
/// A hand-rolled `eprintln!`/`println!`/`writeln!` carrying that literal
/// bypasses `gutter_line`'s terminal-indent handling, so this scans every
/// `.rs` file under the runtime crate's `src/` (this file excepted — it IS the
/// emitter) and fails if any such macro invocation still carries one. Styled
/// after `install_style_drift.rs`'s script-scanning drift tests: a plain
/// substring/window scan, not a real parser, is enough to catch the class of
/// regression (a new call site hand-rolling the tag) without reimplementing a
/// Rust parser.
#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod runtime_log_emitter_tests {
    use std::path::{Path, PathBuf};

    /// Walk `dir` collecting every `.rs` file, skipping `system.rs` (the
    /// sanctioned construction site) so the scan only sees call sites that
    /// must route through `emit_runtime_log`.
    fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
        let entries = std::fs::read_dir(dir)
            .unwrap_or_else(|e| panic!("could not read dir {}: {e}", dir.display()));
        for entry in entries {
            let entry = entry.expect("readable dir entry");
            let path = entry.path();
            if path.is_dir() {
                collect_rs_files(&path, out);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            if path.file_name().and_then(|f| f.to_str()) == Some("system.rs") {
                continue;
            }
            out.push(path);
        }
    }

    /// True when a `"[ipe.` literal appears within a short window after an
    /// `eprintln!`/`println!`/`writeln!` invocation in `content` — wide enough
    /// to span a realistic multi-line macro call, narrow enough not to bleed
    /// into an unrelated later macro call.
    fn has_hand_rolled_tag(content: &str) -> bool {
        for macro_name in ["eprintln!", "println!", "writeln!"] {
            let mut rest = content;
            while let Some(rel) = rest.find(macro_name) {
                let tail = rest.get(rel..).unwrap_or_default();
                let window_end = tail.char_indices().nth(400).map_or(tail.len(), |(i, _)| i);
                if tail
                    .get(..window_end)
                    .unwrap_or_default()
                    .contains("\"[ipe.")
                {
                    return true;
                }
                rest = tail.get(macro_name.len()..).unwrap_or_default();
            }
        }
        false
    }

    #[test]
    fn tag_scan_window_is_char_boundary_safe() {
        let multibyte = "\u{e9}".repeat(500);
        assert!(!has_hand_rolled_tag(&format!("eprintln!({multibyte})")));
        assert!(has_hand_rolled_tag(&format!(
            "\u{e9}eprintln!(\"[ipe.x] {multibyte}\")"
        )));
    }

    #[test]
    fn no_runtime_module_hand_rolls_an_ipe_tagged_log_line() {
        let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        collect_rs_files(&src_dir, &mut files);
        assert!(
            files.len() > 10,
            "sanity: expected to scan more than 10 files under {}, found {}",
            src_dir.display(),
            files.len()
        );

        let mut violations = Vec::new();
        for path in &files {
            let content = std::fs::read_to_string(path)
                .unwrap_or_else(|e| panic!("could not read {}: {e}", path.display()));
            if has_hand_rolled_tag(&content) {
                violations.push(path.display().to_string());
            }
        }
        assert!(
            violations.is_empty(),
            "found `eprintln!`/`println!`/`writeln!` hand-rolling an `[ipe.<tag>]` \
             prefix outside system.rs — route through `crate::system::emit_runtime_log` \
             (or `crate::system::emit_runtime_log_stamped` for a timestamped line) instead:\n{}",
            violations.join("\n")
        );
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod scrub_log_controls_tests {
    use super::{runtime_log_line, scrub_log_controls};

    #[test]
    fn escapes_newline_esc_del_and_c1() {
        let out = scrub_log_controls("a\nb\r\x1b[2J\x7f\u{9b}\u{85}\0c\td");
        assert_eq!(out, "a\\nb\\r\\u{1b}[2J\\u{7f}\\u{9b}\\u{85}\\u{0}c\\td");
        assert!(
            !out.chars().any(char::is_control),
            "control survived: {out:?}"
        );
    }

    #[test]
    fn escapes_unicode_line_separators_and_bidi_controls() {
        let out = scrub_log_controls(
            "a\u{2028}b\u{2029}c\u{202e}d\u{2066}e\u{2069}f\u{200f}g\u{61c}h\u{202a}i",
        );
        assert_eq!(
            out,
            "a\\u{2028}b\\u{2029}c\\u{202e}d\\u{2066}e\\u{2069}f\\u{200f}g\\u{61c}h\\u{202a}i"
        );
        assert!(
            !out.chars().any(super::is_log_hazard),
            "hazard survived: {out:?}"
        );
        // One step past each bidi range stays verbatim.
        assert!(matches!(
            scrub_log_controls("\u{202f}\u{206a}\u{2027}"),
            std::borrow::Cow::Borrowed(_)
        ));
    }

    #[test]
    fn clean_text_is_borrowed_unchanged() {
        let out = scrub_log_controls("GET /caf\u{e9} 200 3ms");
        assert!(matches!(
            out,
            std::borrow::Cow::Borrowed("GET /caf\u{e9} 200 3ms")
        ));
    }

    #[test]
    fn emitted_line_cannot_forge_a_second_record() {
        let line = runtime_log_line(None, "http", "GET /x\r\n[ipe.http] forged\x1b[31m");
        assert!(
            !line.chars().any(super::is_log_hazard),
            "control survived: {line:?}"
        );
        assert_eq!(
            line.trim_start(),
            "[ipe.http] GET /x\\r\\n[ipe.http] forged\\u{1b}[31m"
        );
    }
}

#[cfg(all(test, feature = "web-core", feature = "http_client"))]
mod home_dir_tests {
    use super::home_dir_from_var;
    use std::env::VarError;

    // Shared with `ipe_sandbox::home`'s `tests` module: the same
    // `(raw, expected)` rows drive both crates' home readers.
    include!("../tests/data/home_cases.rs");

    #[test]
    fn every_home_parse_case_matches_the_shared_table() {
        for (raw, expected) in HOME_PARSE_CASES.iter().chain(HOME_PARSE_PLATFORM_CASES) {
            assert_eq!(
                home_dir_from_var(raw.map(str::to_owned).ok_or(VarError::NotPresent)),
                expected.map(std::path::PathBuf::from),
                "{raw:?}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_non_utf8_home_value_is_refused() {
        use std::os::unix::ffi::OsStringExt as _;
        let raw = std::ffi::OsString::from_vec(b"/home/\xff".to_vec());
        assert_eq!(home_dir_from_var(Err(VarError::NotUnicode(raw))), None);
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod parent_death_floor_tests {
    use super::{SpawnJob, SpawnRefusal, run_spawn_jobs, spawn_hardened, spawn_hardened_on};
    use std::time::Duration;

    /// The floor installs a fork-time `pre_exec` (Linux `PR_SET_PDEATHSIG`); a
    /// child spawned through the spawner must still spawn and run normally — the
    /// prctl is async-signal-safe and best-effort, so it can never break the
    /// spawn.
    #[cfg(unix)]
    #[test]
    fn hardened_child_still_spawns_and_runs() {
        let mut child = spawn_hardened(std::process::Command::new("/bin/true"))
            .expect("hardened child must spawn");
        let status = child.wait().expect("reap hardened /bin/true");
        assert!(status.success(), "hardened /bin/true must exit 0");
    }

    /// A spawn the OS refuses surfaces as `SpawnRefusal::Spawn` carrying the OS
    /// error, which converts back to that same `io::Error` kind.
    #[test]
    fn an_os_refused_spawn_is_a_spawn_refusal() {
        let refused = spawn_hardened(std::process::Command::new("/nonexistent/ipe-spawn-probe"));
        let kind = match &refused {
            Err(SpawnRefusal::Spawn(e)) => Some(e.kind()),
            _ => None,
        };
        assert_eq!(kind, Some(std::io::ErrorKind::NotFound), "{refused:?}");
        let io = std::io::Error::from(SpawnRefusal::Spawn(std::io::ErrorKind::NotFound.into()));
        assert_eq!(io.kind(), std::io::ErrorKind::NotFound);
        let gone = std::io::Error::from(SpawnRefusal::SpawnerGone);
        assert_eq!(gone.kind(), std::io::ErrorKind::Other);
    }

    /// A spawner whose queue is gone refuses the request and forks nothing: no
    /// unhardened fallback runs the command.
    #[cfg(unix)]
    #[test]
    fn a_gone_spawner_refuses_and_never_spawns() {
        let (jobs, queue) = std::sync::mpsc::sync_channel::<SpawnJob>(1);
        drop(queue);
        let marker = crate::scratch_core::test_temp_root()
            .join(format!("ipe-spawner-gone-{}", std::process::id()));
        let _ = std::fs::remove_file(&marker);
        let mut cmd = std::process::Command::new("/bin/sh");
        cmd.arg("-c").arg(": > \"$1\"").arg("sh").arg(&marker);
        let refused = spawn_hardened_on(&jobs, Duration::from_secs(5), cmd);
        assert!(
            matches!(refused, Err(SpawnRefusal::SpawnerGone)),
            "{refused:?}"
        );
        assert!(
            !marker.exists(),
            "a refused spawn must never run the command"
        );
    }

    /// A request that finds the spawner queue still full at its ceiling is
    /// refused and forks nothing.
    #[cfg(unix)]
    #[test]
    fn a_full_queue_past_the_ceiling_refuses_and_never_spawns() {
        let (jobs, _queue) = std::sync::mpsc::sync_channel::<SpawnJob>(0);
        let marker = crate::scratch_core::test_temp_root()
            .join(format!("ipe-spawner-full-{}", std::process::id()));
        let _ = std::fs::remove_file(&marker);
        let mut cmd = std::process::Command::new("/bin/sh");
        cmd.arg("-c").arg(": > \"$1\"").arg("sh").arg(&marker);
        let refused = spawn_hardened_on(&jobs, Duration::ZERO, cmd);
        assert!(
            matches!(refused, Err(SpawnRefusal::ReplyTimedOut)),
            "{refused:?}"
        );
        assert!(
            !marker.exists(),
            "a refused spawn must never run the command"
        );
    }

    /// Unwinds out of a spawn job, the way a panicking job would.
    fn unwinding_job() {
        std::panic::resume_unwind(Box::new(()));
    }

    /// A job that panics leaves the spawner running the jobs after it.
    #[test]
    fn a_panicking_job_does_not_stop_the_spawner() {
        let (jobs, queue) = std::sync::mpsc::sync_channel::<SpawnJob>(2);
        let (ran, seen) = std::sync::mpsc::channel::<()>();
        jobs.send(Box::new(unwinding_job))
            .expect("queue the unwinding job");
        jobs.send(Box::new(move || {
            let _ = ran.send(());
        }))
        .expect("queue the next job");
        drop(jobs);
        let runner = std::thread::spawn(move || run_spawn_jobs(&queue));
        let next = seen.recv_timeout(Duration::from_secs(10));
        runner.join().expect("the spawner loop must not unwind");
        assert_eq!(next, Ok(()), "the job after an unwind must still run");
    }

    /// A spawn that panics on the spawner is refused as `SpawnPanicked`, never
    /// relabelled `SpawnerGone`, and the spawner runs the next request.
    #[test]
    fn a_panicking_spawn_is_refused_as_spawn_panicked() {
        use super::request_spawn;
        let (jobs, queue) = std::sync::mpsc::sync_channel::<SpawnJob>(1);
        let runner = std::thread::spawn(move || run_spawn_jobs(&queue));
        let refused = request_spawn(
            &jobs,
            Duration::from_secs(10),
            || -> Result<(), SpawnRefusal> { std::panic::resume_unwind(Box::new(())) },
            |(): ()| {},
        );
        let next = request_spawn(&jobs, Duration::from_secs(10), || Ok(()), |(): ()| {});
        drop(jobs);
        runner.join().expect("the spawner loop must not unwind");
        assert!(
            matches!(refused, Err(SpawnRefusal::SpawnPanicked)),
            "{refused:?}"
        );
        assert!(next.is_ok(), "{next:?}");
    }

    /// A tokio runtime without its IO driver is refused before the fork.
    ///
    /// The refusal is `ProbePanicked`, which only the pre-fork probe yields
    /// (without it tokio panics after the fork, as `SpawnPanicked`). The command
    /// would hold a pipe's only other write end: the pipe reaches EOF with no
    /// byte written, so no child ever ran, and it does so once the spawner has
    /// dropped the command, with no timing race.
    #[cfg(all(feature = "web", unix))]
    #[test]
    fn a_runtime_without_io_refuses_before_forking() {
        use super::spawn_hardened_tokio;
        use std::io::Read as _;
        let (mut reader, writer) = std::io::pipe().expect("pipe");
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime");
        let mut cmd = tokio::process::Command::new("/bin/sh");
        cmd.arg("-c")
            .arg("echo forked")
            .stdout(writer)
            .kill_on_drop(true);
        let refused = rt.block_on(async { spawn_hardened_tokio(cmd) });
        assert!(
            matches!(refused, Err(SpawnRefusal::ProbePanicked)),
            "{refused:?}"
        );
        let (drained, eof) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut out = Vec::new();
            let _ = drained.send(reader.read_to_end(&mut out).map(|_| out));
        });
        let written = eof.recv_timeout(Duration::from_secs(10));
        assert!(
            matches!(&written, Ok(Ok(out)) if out.is_empty()),
            "a refused spawn must never run the command: {written:?}"
        );
    }

    /// A spawner that drops a request without answering it is reported gone.
    #[cfg(unix)]
    #[test]
    fn a_dropped_request_is_reported_gone() {
        let (jobs, queue) = std::sync::mpsc::sync_channel::<SpawnJob>(1);
        let dropper = std::thread::spawn(move || drop(queue.recv()));
        let refused = spawn_hardened_on(
            &jobs,
            Duration::from_secs(5),
            std::process::Command::new("/bin/true"),
        );
        dropper.join().expect("dropper thread");
        assert!(
            matches!(refused, Err(SpawnRefusal::SpawnerGone)),
            "{refused:?}"
        );
    }

    /// A request abandoned past its ceiling is refused, and the child the
    /// spawner forks for it afterwards is killed and reaped rather than left
    /// running: the pipe the child holds reaches EOF long before the child's
    /// own 30s sleep would end.
    #[cfg(unix)]
    #[test]
    fn a_lost_reply_kills_and_reaps_the_child() {
        use std::io::Read as _;
        let (jobs, queue) = std::sync::mpsc::sync_channel::<SpawnJob>(1);
        let (mut reader, writer) = std::io::pipe().expect("pipe");
        let mut cmd = std::process::Command::new("/bin/sleep");
        cmd.arg("30").stdout(writer);
        let refused = spawn_hardened_on(&jobs, Duration::ZERO, cmd);
        assert!(
            matches!(refused, Err(SpawnRefusal::ReplyTimedOut)),
            "{refused:?}"
        );
        let job = queue.recv().expect("the abandoned request stays queued");
        let started = std::time::Instant::now();
        job();
        let mut drained = Vec::new();
        reader.read_to_end(&mut drained).expect("read to EOF");
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the abandoned child must be killed, not left to run"
        );
    }

    /// A child reparented before it armed the signal (its launcher died in the
    /// fork-to-`prctl` window) is refused; one still parented by the launcher
    /// proceeds.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_reparented_child_is_refused() {
        use super::still_parented_by;
        let launcher = rustix::process::getpid();
        assert!(still_parented_by(launcher, Some(launcher)).is_ok());
        // Above every kernel `pid_max`, so never the launcher's own pid.
        let other = rustix::process::Pid::from_raw(i32::MAX).expect("positive pid");
        let refused = still_parented_by(launcher, Some(other)).map_err(|e| e.raw_os_error());
        assert_eq!(refused, Err(Some(rustix::io::Errno::SRCH.raw_os_error())));
        assert!(still_parented_by(launcher, None).is_err());
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod env_overlay_tests {
    use super::*;

    /// Overlay set is observed by the reader; a tombstone masks a value present
    /// in the real environ; an untouched key still defers to the real environ.
    /// Uses a process-unique key so parallel test binaries never collide.
    #[test]
    fn overlay_set_remove_and_passthrough() {
        let key = format!("IPE_OVERLAY_PROBE_{}", std::process::id());

        // Absent everywhere → the reader reports unset.
        assert!(read_env_var(&key).is_err(), "probe must start unset");

        // Overlay set is observed WITHOUT mutating the real environ.
        locked_set_var(&key, "value");
        assert_eq!(read_env_var(&key).as_deref(), Ok("value"));
        #[allow(clippy::disallowed_methods)] // the raw environ itself is under test
        let real = std::env::var_os(&key);
        assert!(
            real.is_none(),
            "the real environ must NOT be mutated by an Ipê env write"
        );

        // set-if-absent does not override an existing overlay value.
        locked_set_var_if_absent(&key, "other");
        assert_eq!(read_env_var(&key).as_deref(), Ok("value"));

        // A tombstone masks the overlay value (reads as unset).
        locked_remove_var(&key);
        assert!(read_env_var(&key).is_err(), "tombstone must mask the value");

        // Passthrough: a key never touched by the overlay reads through to the
        // real environ (PATH is present on every supported target).
        assert!(
            read_env_var("PATH").is_ok(),
            "an untouched key must defer to the real environ"
        );
    }

    /// Soundness core: an Ipê env write must NEVER mutate the real `environ`,
    /// because a concurrent libc reader (`getaddrinfo` via `to_socket_addrs`)
    /// walks `environ` under no lock we hold. This drives that exact concurrent
    /// composition — a writer thread hammering the overlay while a reader thread
    /// resolves addresses — and asserts the writes stayed OUT of the real
    /// environ. Under the pre-fix `set_var` design this same interleaving is the
    /// use-after-free the issue describes.
    #[test]
    fn concurrent_writes_never_touch_real_environ() {
        use std::net::ToSocketAddrs;

        let key = format!("IPE_OVERLAY_RACE_{}", std::process::id());
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

        let writer = {
            let key = key.clone();
            let stop = stop.clone();
            std::thread::spawn(move || {
                let mut i: u64 = 0;
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    locked_set_var(&key, &i.to_string());
                    locked_remove_var(&key);
                    i = i.wrapping_add(1);
                }
            })
        };

        let reader = std::thread::spawn(move || {
            for _ in 0..200 {
                // Exercises libc `getaddrinfo`, the unlocked `environ` reader.
                let _ = "localhost:0".to_socket_addrs().map(Iterator::count);
            }
        });

        let _ = reader.join();
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = writer.join();

        #[allow(clippy::disallowed_methods)] // the raw environ itself is under test
        let real = std::env::var_os(&key);
        assert!(
            real.is_none(),
            "an Ipê env write leaked into the real environ — the environ-reader race is back"
        );
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod process_run_tests {
    use super::*;

    fn block<T>(fut: impl std::future::Future<Output = T>) -> T {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(fut)
    }

    /// Functional correctness (independent of whether `run_blocking` takes the
    /// real `spawn_blocking` path or the no-tokio-feature fallback — both
    /// paths must return the same result).
    #[test]
    fn success_returns_combined_output() {
        let res: IpeResult<String, String> = block(process_run::<String>(
            "echo".to_string(),
            vec!["hello".to_string()],
        ));
        match res {
            IpeResult::Ok(s) => assert!(s.contains("hello"), "unexpected output: {s:?}"),
            IpeResult::Err(e) => panic!("unexpected Err: {e}"),
        }
    }

    #[test]
    fn nonexistent_binary_errs() {
        let res: IpeResult<String, String> = block(process_run::<String>(
            "ipe-does-not-exist-binary-xyz".to_string(),
            vec![],
        ));
        assert!(matches!(res, IpeResult::Err(_)));
    }

    #[test]
    fn nonzero_exit_errs() {
        let res: IpeResult<String, String> =
            block(process_run::<String>("false".to_string(), vec![]));
        assert!(matches!(res, IpeResult::Err(_)));
    }

    /// No-shell proof: an argument containing shell metacharacters is passed
    /// literally as an argv element, never evaluated by `sh -c`. `printf %s`
    /// echoes it verbatim; a shell would have run the `; touch <marker>` clause
    /// (creating the file) and would NOT echo the clause back verbatim.
    #[test]
    fn args_are_literal_no_shell_interpretation() {
        let marker = crate::scratch_core::test_temp_root()
            .join(format!("ipe_noshell_{}", std::process::id()));
        let _ = std::fs::remove_file(&marker);
        let payload = format!("; touch {} ; echo pwned", marker.display());
        let res: IpeResult<String, String> = block(process_run::<String>(
            "printf".to_string(),
            vec!["%s".to_string(), payload.clone()],
        ));
        let marker_created = marker.exists();
        let _ = std::fs::remove_file(&marker);
        match res {
            IpeResult::Ok(s) => {
                // The whole payload is echoed back verbatim (one argv element),
                // proving no `sh -c` split it on `;`.
                assert_eq!(s, payload, "argv must be passed literally (no shell)");
            }
            IpeResult::Err(e) => panic!("unexpected Err: {e}"),
        }
        assert!(
            !marker_created,
            "the `; touch` clause ran — argv was evaluated by a shell (injection)"
        );
    }

    /// Deadlock regression: a child that writes a LOT to BOTH stdout and stderr
    /// (each well past a 64 KiB pipe buffer) must complete, not wedge. The
    /// sequential stdout-then-stderr drain would deadlock here — the child
    /// blocks on a full stderr pipe while we drain stdout, and vice versa. The
    /// concurrent per-stream capture threads make this terminate.
    #[test]
    fn large_stdout_and_stderr_does_not_deadlock() {
        // `sh` is the program under test (invoked as an argv vector, not via
        // this kernel's own shell — there is none): it writes ~512 KiB to each
        // stream, far exceeding the ~64 KiB kernel pipe buffer.
        let script = "yes ABCDEFGH | head -c 524288; yes abcdefgh | head -c 524288 >&2";
        let res: IpeResult<String, String> = block(process_run::<String>(
            "sh".to_string(),
            vec!["-c".to_string(), script.to_string()],
        ));
        match res {
            IpeResult::Ok(s) => assert_eq!(
                s.len(),
                524288 * 2,
                "combined output must be both streams in full"
            ),
            IpeResult::Err(e) => panic!("large dual-stream output must not deadlock/err: {e}"),
        }
    }

    /// DoS guard: a subprocess whose combined output exceeds the capture
    /// ceiling must `Err`, never buffer it all and OOM the host, and never
    /// silently truncate a returned success value.
    #[test]
    fn output_over_ceiling_errs() {
        // The ceiling is passed explicitly (not via a process-global env var),
        // so this runs safely in parallel with any other subprocess test.
        let res: IpeResult<String, String> = block(process_run_with_cap::<String>(
            "printf".to_string(),
            vec!["%s".to_string(), "x".repeat(64)],
            8,
        ));
        assert!(
            matches!(res, IpeResult::Err(_)),
            "64 bytes of output under an 8-byte ceiling must Err, not OOM/truncate"
        );
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod process_run_with_tests {
    use super::*;

    fn block<T>(fut: impl std::future::Future<Output = T>) -> T {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(fut)
    }

    fn cfg(command: &str, args: &[&str]) -> ProcessRunWithCfg {
        ProcessRunWithCfg {
            command: command.to_owned(),
            args: args.iter().map(|s| s.to_string()).collect(),
            cwd: IpeMaybe::Nothing,
            env: Vec::new(),
        }
    }

    /// Non-zero exit is carried in `exitCode` — the Task succeeds.
    #[test]
    fn nonzero_exit_is_normal_result_not_task_failure() {
        let res: IpeResult<String, ProcessRunOutput> =
            block(process_run_with::<String>(cfg("false", &[])));
        match res {
            IpeResult::Ok(out) => {
                assert_ne!(out.exitCode, 0, "false must exit non-zero");
            }
            IpeResult::Err(e) => panic!("spawn failure not expected: {e}"),
        }
    }

    /// Successful command: exit 0, stdout captured.
    #[test]
    fn success_captures_stdout_and_exit_zero() {
        let res: IpeResult<String, ProcessRunOutput> =
            block(process_run_with::<String>(cfg("echo", &["hello"])));
        match res {
            IpeResult::Ok(out) => {
                assert_eq!(out.exitCode, 0);
                assert!(
                    out.stdout.contains("hello"),
                    "expected stdout: {:?}",
                    out.stdout
                );
                assert!(out.stderr.is_empty(), "unexpected stderr: {:?}", out.stderr);
            }
            IpeResult::Err(e) => panic!("unexpected error: {e}"),
        }
    }

    /// stderr is captured separately from stdout.
    #[test]
    fn stderr_captured_separately() {
        let res: IpeResult<String, ProcessRunOutput> = block(process_run_with::<String>(cfg(
            "sh",
            &["-c", "echo err >&2"],
        )));
        match res {
            IpeResult::Ok(out) => {
                assert!(out.stdout.is_empty(), "unexpected stdout: {:?}", out.stdout);
                assert!(
                    out.stderr.contains("err"),
                    "expected stderr: {:?}",
                    out.stderr
                );
            }
            IpeResult::Err(e) => panic!("unexpected error: {e}"),
        }
    }

    /// Spawn failure (non-existent binary) → Task.fail.
    #[test]
    fn nonexistent_binary_fails_task() {
        let res: IpeResult<String, ProcessRunOutput> = block(process_run_with::<String>(cfg(
            "ipe-does-not-exist-xyz",
            &[],
        )));
        assert!(matches!(res, IpeResult::Err(_)));
    }

    /// cwd override is honoured: `pwd` must echo the target directory.
    #[test]
    fn cwd_override_is_honoured() {
        let tmp = crate::scratch_core::test_temp_root();
        let tmp_str = tmp.to_string_lossy().into_owned();
        let mut c = cfg("sh", &["-c", "pwd"]);
        c.cwd = IpeMaybe::Just(tmp_str.clone());
        let res: IpeResult<String, ProcessRunOutput> = block(process_run_with::<String>(c));
        match res {
            IpeResult::Ok(out) => {
                let canonical_tmp = std::fs::canonicalize(&tmp)
                    .unwrap_or(tmp.clone())
                    .to_string_lossy()
                    .into_owned();
                let got = out.stdout.trim().to_owned();
                assert!(
                    got == canonical_tmp || got == tmp_str,
                    "pwd must report the overridden cwd; got {got:?}, expected {canonical_tmp:?}"
                );
            }
            IpeResult::Err(e) => panic!("unexpected error: {e}"),
        }
    }

    /// env override is passed to the child; parent env is also inherited.
    #[test]
    fn env_override_is_passed_to_child() {
        let marker = format!("ipe_run_with_probe_{}", std::process::id());
        let mut c = cfg("sh", &["-c", "echo $IPE_RUN_WITH_TEST_VAR"]);
        c.env = vec![("IPE_RUN_WITH_TEST_VAR".to_owned(), marker.clone())];
        let res: IpeResult<String, ProcessRunOutput> = block(process_run_with::<String>(c));
        match res {
            IpeResult::Ok(out) => {
                assert!(
                    out.stdout.contains(&marker),
                    "env override must be visible to child; got {:?}",
                    out.stdout
                );
            }
            IpeResult::Err(e) => panic!("unexpected error: {e}"),
        }
    }

    /// The ceiling applies per-stream; a stream that exceeds it fails the Task.
    #[test]
    fn per_stream_ceiling_is_enforced() {
        let c = ProcessRunWithCfg {
            command: "printf".to_owned(),
            args: vec!["%s".to_owned(), "x".repeat(64)],
            cwd: IpeMaybe::Nothing,
            env: Vec::new(),
        };
        // Swap command for a ceiling test via the internal cap-threaded helper.
        let _ = c; // used below via process_run_with_impl directly
        let res: IpeResult<String, ProcessRunOutput> = block(process_run_with_impl::<String>(
            ProcessRunWithCfg {
                command: "printf".to_owned(),
                args: vec!["%s".to_owned(), "x".repeat(64)],
                cwd: IpeMaybe::Nothing,
                env: Vec::new(),
            },
            8,
        ));
        assert!(
            matches!(res, IpeResult::Err(_)),
            "64-byte output under an 8-byte ceiling must fail"
        );
    }

    /// No-shell guard: a shell-metacharacter argument is passed verbatim.
    #[test]
    fn args_passed_literally_no_shell() {
        let payload = "; echo pwned".to_owned();
        let res: IpeResult<String, ProcessRunOutput> =
            block(process_run_with::<String>(cfg("printf", &["%s", &payload])));
        match res {
            IpeResult::Ok(out) => {
                assert_eq!(
                    out.stdout, payload,
                    "argv must be literal, not shell-interpreted"
                );
            }
            IpeResult::Err(e) => panic!("unexpected error: {e}"),
        }
    }
}

#[cfg(all(test, feature = "tokio", unix))]
mod process_run_in_pty_tests {
    use super::*;

    // Test-only runtime builder: a current-thread runtime cannot fail to build here.
    #[allow(clippy::unwrap_used)]
    fn block<T>(fut: impl std::future::Future<Output = T>) -> T {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(fut)
    }

    fn pty_cfg(command: &str, args: &[&str]) -> ProcessRunInPtyCfg {
        ProcessRunInPtyCfg {
            command: command.to_owned(),
            args: args.iter().map(|s| (*s).to_owned()).collect(),
            cwd: IpeMaybe::Nothing,
            env: Vec::new(),
            cols: 80,
            rows: 24,
        }
    }

    /// A child that checks `isatty(stdout)` reports "tty" under the pty. The
    /// same probe run under plain `Process.run` (piped stdio) reports "notty" —
    /// so the pty path really connects a terminal, not a pipe.
    #[test]
    fn child_sees_a_tty_under_pty_but_not_under_plain_run() {
        // `test -t 1` is true exactly when stdout is a terminal.
        let probe = "if [ -t 1 ]; then echo tty; else echo notty; fi";

        let pty_res: IpeResult<String, ProcessPtyOutput> =
            block(process_run_in_pty::<String>(pty_cfg("sh", &["-c", probe])));
        match pty_res {
            IpeResult::Ok(out) => assert!(
                out.output.contains("tty") && !out.output.contains("notty"),
                "child under a pty must see a tty; got {:?}",
                out.output
            ),
            IpeResult::Err(e) => panic!("pty run unexpectedly failed: {e}"),
        }

        let plain_res: IpeResult<String, String> = block(process_run::<String>(
            "sh".to_owned(),
            vec!["-c".to_owned(), probe.to_owned()],
        ));
        match plain_res {
            IpeResult::Ok(text) => assert!(
                text.contains("notty"),
                "child under piped stdio must NOT see a tty; got {text:?}"
            ),
            IpeResult::Err(e) => panic!("plain run unexpectedly failed: {e}"),
        }
    }

    /// Exit code propagates: a child that exits 7 surfaces `exitCode == 7`.
    #[test]
    fn exit_code_propagates() {
        let res: IpeResult<String, ProcessPtyOutput> = block(process_run_in_pty::<String>(
            pty_cfg("sh", &["-c", "exit 7"]),
        ));
        match res {
            IpeResult::Ok(out) => assert_eq!(out.exitCode, 7, "exit code must propagate"),
            IpeResult::Err(e) => panic!("pty run unexpectedly failed: {e}"),
        }
    }

    /// A flooding child hits the output ceiling and fails the Task — no
    /// unbounded allocation / OOM. Uses the internal cap-threaded helper so the
    /// test pins a small ceiling without touching the process-global env var.
    #[test]
    fn flooding_child_hits_the_output_cap() {
        let res: IpeResult<String, ProcessPtyOutput> = block(process_run_in_pty_impl::<String>(
            ProcessRunInPtyCfg {
                command: "sh".to_owned(),
                // Emit far more than the 8-byte ceiling below.
                args: vec!["-c".to_owned(), "printf 'x%.0s' $(seq 1 4096)".to_owned()],
                cwd: IpeMaybe::Nothing,
                env: Vec::new(),
                cols: 80,
                rows: 24,
            },
            8,
        ));
        assert!(
            matches!(res, IpeResult::Err(_)),
            "output far exceeding an 8-byte ceiling must fail the Task"
        );
    }

    /// A non-existent binary fails the Task (spawn failure), never a hang.
    #[test]
    fn nonexistent_binary_fails_task() {
        let res: IpeResult<String, ProcessPtyOutput> = block(process_run_in_pty::<String>(
            pty_cfg("ipe-does-not-exist-xyz", &[]),
        ));
        assert!(
            matches!(res, IpeResult::Err(_)),
            "spawn failure must fail the Task"
        );
    }
}

#[cfg(all(test, feature = "tokio"))]
#[cfg(not(target_arch = "wasm32"))]
mod process_run_spawn_blocking_tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Reactor-starvation guard: `Command::output()` blocks the calling thread until
    /// the child process exits. On a SINGLE-WORKER (current_thread) runtime,
    /// running that wait inline (no `spawn_blocking`) would starve every
    /// other task scheduled on that runtime for the subprocess's whole
    /// lifetime. This proves `process_run` offloads the wait to tokio's
    /// blocking-thread pool: a concurrently-spawned cheap ticker task must
    /// make progress (ticks > 0) WHILE the subprocess is running.
    ///
    /// Uses `sleep 1` as a cheap, portable way to force the subprocess to run
    /// long enough for at least one `yield_now` to land elsewhere. Pre-fix
    /// this is NOT a flaky race: the ticker makes EXACTLY zero progress
    /// deterministically, because the worker thread never yields back to the
    /// executor until `Command::output()` returns.
    #[test]
    fn process_run_does_not_starve_concurrent_async_work() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let ticks = rt.block_on(async move {
            let counter = Arc::new(AtomicU64::new(0));
            let counter2 = counter.clone();
            let ticker = tokio::spawn(async move {
                loop {
                    counter2.fetch_add(1, Ordering::Relaxed);
                    tokio::task::yield_now().await;
                }
            });
            let run_fut: IpeTask<String, String> =
                process_run("sleep".to_string(), vec!["1".to_string()]);
            let _res: IpeResult<String, String> = run_fut.await;
            ticker.abort();
            counter.load(Ordering::Relaxed)
        });

        assert!(
            ticks > 0,
            "concurrent ticker task made ZERO progress while process_run ran — \
             the blocking subprocess wait is starving the single-threaded executor \
             (spawn_blocking missing or not taking effect)"
        );
    }
}

#[cfg(all(test, feature = "tokio"))]
#[cfg(not(target_arch = "wasm32"))]
mod system_load_env_spawn_blocking_tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Reactor-starvation guard: `system_load_env` reads `.env` via
    /// `std::fs::read_to_string`, a blocking syscall. It must route through the
    /// shared `run_blocking` helper (defined above in this file, already used
    /// by `process_run`) rather than run inline inside the `async move` body —
    /// the same offload `file.rs` / `compression.rs` / `csv.rs` /
    /// `config_decode.rs` use. This proves `system_load_env` offloads the read
    /// to tokio's blocking-thread pool: a concurrently-
    /// spawned cheap ticker task must make progress (ticks > 0) WHILE the
    /// read is in flight.
    ///
    /// Uses a large `.env` (64 MiB of comment padding, same idiom as
    /// `file.rs`'s `spawn_blocking_tests`) so the read takes measurable wall
    /// time. Pre-fix this is NOT a flaky race — the ticker makes EXACTLY
    /// zero progress deterministically, because the worker thread never
    /// yields back to the executor until `read_to_string` returns.
    ///
    /// `set_current_dir` mutates process-global state; safe here only
    /// because this crate's tests run one-process-per-test under `cargo
    /// nextest` (the codebase's existing convention for tests that mutate
    /// global process state — e.g. this same file's `exit_hook_tests` /
    /// `console.rs`'s `ingest_token_gate` mutate env vars directly for the
    /// same reason).
    #[test]
    fn system_load_env_does_not_starve_concurrent_async_work() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = crate::scratch_core::test_temp_root().join(format!(
            "ipe_load_env_spawn_blocking_probe_{}_{}",
            std::process::id(),
            nanos
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let env_path = dir.join(".env");
        // One huge comment line (skipped by the parser) + one real var —
        // large enough that the read takes measurable (not instant) wall
        // time, same idiom as `file.rs`'s spawn_blocking probe.
        let mut contents = String::from("# ");
        contents.push_str(&"x".repeat(64 * 1024 * 1024));
        contents.push('\n');
        contents.push_str("IPE_LOAD_ENV_PROBE_VAR=probe_value\n");
        std::fs::write(&env_path, contents).unwrap();

        let orig_cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        locked_remove_var("IPE_LOAD_ENV_PROBE_VAR");

        let ticks = rt.block_on(async move {
            let counter = Arc::new(AtomicU64::new(0));
            let counter2 = counter.clone();
            let ticker = tokio::spawn(async move {
                loop {
                    counter2.fetch_add(1, Ordering::Relaxed);
                    tokio::task::yield_now().await;
                }
            });
            let load_fut: IpeTask<String, ()> = system_load_env(());
            let _res: IpeResult<String, ()> = load_fut.await;
            ticker.abort();
            counter.load(Ordering::Relaxed)
        });

        // Functional sanity: the real var was actually picked up.
        let loaded = read_env_var("IPE_LOAD_ENV_PROBE_VAR");

        std::env::set_current_dir(&orig_cwd).unwrap();
        locked_remove_var("IPE_LOAD_ENV_PROBE_VAR");
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(
            loaded.as_deref(),
            Ok("probe_value"),
            "system_load_env did not set the var from the probe .env file"
        );
        assert!(
            ticks > 0,
            "concurrent ticker task made ZERO progress while system_load_env ran — \
             the blocking .env read is starving the single-threaded executor \
             (spawn_blocking missing or not taking effect)"
        );
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod argv_tests {
    use super::super::IpeErrorKind;
    use super::{IpeError, IpeMaybe, decode_arg_at, decode_args};
    use std::ffi::OsString;

    fn argv(items: &[&str]) -> Vec<OsString> {
        items.iter().map(OsString::from).collect()
    }

    #[test]
    fn args_skip_the_program_name() {
        assert!(matches!(
            decode_args(argv(&["prog", "a", "b"]).into_iter()).as_deref(),
            Ok([a, b]) if a == "a" && b == "b"
        ));
    }

    #[test]
    fn arg_indexes_outside_the_vector_are_nothing() {
        let v = argv(&["prog", "a"]);
        assert!(matches!(
            decode_arg_at(v.clone().into_iter(), -1),
            Ok(IpeMaybe::Nothing)
        ));
        assert!(matches!(
            decode_arg_at(v.clone().into_iter(), 2),
            Ok(IpeMaybe::Nothing)
        ));
        // One past `u32::MAX`: a narrowing cast would wrap it to index 0.
        assert!(matches!(
            decode_arg_at(v.clone().into_iter(), i64::from(u32::MAX) + 1),
            Ok(IpeMaybe::Nothing)
        ));
        assert!(matches!(
            decode_arg_at(v.into_iter(), i64::MAX),
            Ok(IpeMaybe::Nothing)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_arguments_are_refused_without_echoing_their_bytes() {
        use std::os::unix::ffi::OsStringExt;
        let bad = || {
            vec![
                OsString::from("prog"),
                OsString::from_vec(b"secret\xff".to_vec()),
            ]
        };
        let all = decode_args(bad().into_iter()).map(|_| ());
        let one = decode_arg_at(bad().into_iter(), 1).map(|_| ());
        for refused in [all, one] {
            match refused {
                Err(IpeError::Error(IpeErrorKind::InvalidInput, info)) => {
                    assert!(
                        !info.message.contains("secret"),
                        "refusal echoed argv bytes: {}",
                        info.message
                    );
                }
                other => panic!("non-UTF-8 argument must be refused, got {other:?}"),
            }
        }
        assert!(matches!(
            decode_arg_at(bad().into_iter(), 0),
            Ok(IpeMaybe::Just(p)) if p == "prog"
        ));
    }
}
