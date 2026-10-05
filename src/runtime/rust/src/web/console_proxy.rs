//! Pre-built console child + reverse-proxy.
//!
//! Replaces the in-process `console.rs` plain-HTML shell with the **real bundled
//! Ipe.Web console**, spawned as a child process and reverse-proxied at
//! `/_ipe/console/*`. This module only `exec`s a console binary already on
//! disk (`IPE_CONSOLE_BIN`, else the version-keyed cache path); it never builds
//! one, and no build step writes the cache path. Without a binary the
//! in-process console serves.
//!
//! This module: gate + spawn + lifecycle + the reverse-proxy handler.
//!
//! No panic vectors: a missing binary / spawn failure / disabled gate returns
//! `None` so the caller falls back to the in-process console; no `unwrap`.

use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::process::{Child, Command};

/// Override for the pre-built console binary path. When unset, the cache path
/// `~/.cache/ipe/rust-console/<ipe-version>/ipe-console` is used if a binary is
/// present there. No build step writes that path.
const CONSOLE_BIN_ENV: &str = "IPE_CONSOLE_BIN";

/// The child's ingest-token variable (the one its ingest gate reads).
const INGEST_TOKEN_ENV: &str = super::push_exporter::ExporterEnv::IngestToken.name();

/// The mount prefix. The parent proxies everything under this path to the child
/// and STRIPS the prefix before forwarding (the strip convention — see the
/// module doc): the child's router stays root-relative, identical to a
/// standalone Web app. The child only learns the prefix via `IPE_WEB_BASE_PATH`
/// (so its rendered `/_ipe/event` / `/_ipe/sse` URLs come back prefixed and we
/// strip them again on the way in).
const CONSOLE_BASE: &str = "/_ipe/console";

/// Request-body buffer cap for the proxy (16 MiB). Event POST bodies are far
/// smaller (`IPE_WEB_MAX_BODY_BYTES` defaults to 5 MiB); this is the hard
/// ceiling above which we 502 rather than buffer unboundedly. Responses are
/// STREAMED, never buffered, so SSE is unaffected by this cap.
const MAX_PROXY_BODY: usize = 16 * 1024 * 1024;

/// Readiness-wait ceiling after spawn before we declare the child live (else we
/// fall back to the in-process console). Bounded so a wedged child can't hang
/// boot.
const READY_TIMEOUT: Duration = Duration::from_secs(8);

/// The spawned console child, tracked so the parent can kill it on shutdown
/// to avoid an orphan child process.
static CHILD: Mutex<Option<Child>> = Mutex::new(None);

/// The zero-config console store's private directory, held for the life of the
/// process (the child writes into it) and removed by [`shutdown_console`].
static CONSOLE_SCRATCH: Mutex<Option<crate::scratch_core::ScratchDir>> = Mutex::new(None);

/// Resolve the pre-built console binary path: `IPE_CONSOLE_BIN`, else the
/// version-keyed cache path. `None` when neither names a file (→ the caller
/// falls back to the in-process console).
pub fn console_bin_path() -> Option<std::path::PathBuf> {
    if let Ok(p) = crate::system::read_env_var(CONSOLE_BIN_ENV)
        && !p.is_empty()
    {
        let pb = std::path::PathBuf::from(p);
        return if pb.is_file() { Some(pb) } else { None };
    }
    // Key on the IPE compiler version (same source as `/_ipe/buildinfo`), NOT
    // the generated crate's CARGO_PKG_VERSION (always "0.1.0"). The ipe dev build
    // sets IPE_VERSION when compiling this app, so a console binary placed for
    // one ipe version is never exec'd by an app built with another.
    let ver = option_env!("IPE_VERSION").unwrap_or("dev");
    let pb = crate::system::home_dir()?
        .join(".cache/ipe/rust-console")
        .join(ver)
        .join("ipe-console");
    if pb.is_file() { Some(pb) } else { None }
}

/// The console child's command: its port, base path, data store, bind and
/// ingest token.
///
/// The child always binds loopback (`IPE_HTTP_BIND=127.0.0.1`): it serves the
/// console unauthenticated behind the gated parent proxy, so it is never
/// reachable off the machine under any posture. Its ingest requires `token`
/// (`IPE_INGEST_TOKEN`), which only this parent and the child hold, so the
/// parent's pushes are admitted under every build and posture and a process
/// running as another user cannot write the store. A process running as the
/// same user can read the token from `/proc/<pid>/environ`; it is in the
/// parent's trust domain already.
///
/// The child exports nowhere: every [`ExporterEnv::egress`] name is removed,
/// so neither an inherited `IPE_PARENT_URL` nor a hub target makes the child
/// push, and the token minted for this child's ingest never leaves for a party
/// it was not minted for.
///
/// [`ExporterEnv::egress`]: super::push_exporter::ExporterEnv::egress
fn console_command(
    bin: &std::path::Path,
    child_port: u16,
    store: &str,
    child_collects: bool,
    token: &super::push_exporter::IngestToken,
) -> Command {
    let mut cmd = Command::new(bin);
    cmd.env(crate::LISTEN_PORT_RELOCATION_ENV, child_port.to_string())
        .env("IPE_WEB_BASE_PATH", "/_ipe/console")
        .env("IPE_HTTP_BIND", "127.0.0.1")
        .env(INGEST_TOKEN_ENV, token.expose())
        // Belt-and-braces: suppress the child's own console auto-mount + banner.
        .env("IPE_CONSOLE_EMBED", "off")
        .kill_on_drop(true);
    for name in super::push_exporter::ExporterEnv::egress() {
        cmd.env_remove(name);
    }
    // hubStore read source.
    if store.is_empty() {
        cmd.env_remove("IPE_CONSOLE_HUB_DB");
    } else {
        cmd.env("IPE_CONSOLE_HUB_DB", store);
    }
    // Collector write source: only when the child collects (parent pushes).
    // env_remove otherwise so an inherited IPE_CONSOLE_DB_PATH (the parent's own
    // spill path) doesn't make the child double-write it.
    if child_collects && !store.is_empty() {
        cmd.env("IPE_CONSOLE_DB_PATH", store);
    } else {
        cmd.env_remove("IPE_CONSOLE_DB_PATH");
    }
    cmd
}

/// Spawn the pre-built console child on `child_port`, pointing it at the data
/// `store`. Returns the ingest token minted for this child on a successful
/// spawn (the `Child` is tracked in `CHILD`); `None` when the binary is absent,
/// no entropy is available for the token, or the spawn fails — the caller falls
/// back to the in-process console.
///
/// `store` is the SQLite file the console renders from (`IPE_CONSOLE_HUB_DB` →
/// hubStore). `child_collects` selects who WRITES it:
///   - `true`  — push-to-local-collector: a lean parent has no spill,
///     so the child is the collector — it also writes `store`
///     (`IPE_CONSOLE_DB_PATH`) from the parent's pushed telemetry.
///   - `false` — the parent writes `store` directly (db parent's own spill); the
///     child reads only, and MUST NOT also write it (double-write).
///
/// No-orphan defence in depth: `kill_on_drop` + `shutdown_console` (signal
/// handler) cover the graceful paths, and on Linux `PR_SET_PDEATHSIG` makes the
/// kernel SIGTERM the child if the parent dies by ANY means — including SIGKILL
/// / OOM / a crash the signal handler can't catch. A refused hardened spawn
/// falls back to the in-process console, never to an unhardened child. A
/// refusal tokio raises after the fork (`SpawnRefusal::Spawn` /
/// `SpawnPanicked`) can leave that child running unproxied on `child_port`
/// until this process exits, when the parent-death floor SIGTERMs it.
pub(crate) fn spawn_console(
    child_port: u16,
    store: &str,
    child_collects: bool,
) -> Option<super::push_exporter::IngestToken> {
    let bin = console_bin_path()?;
    let Some(token) = super::push_exporter::IngestToken::mint() else {
        crate::system::emit_runtime_log(
            "console",
            "OS entropy source unavailable for the ingest token; falling back to in-process console",
        );
        return None;
    };
    let cmd = console_command(&bin, child_port, store, child_collects, &token);
    // Parent-death signal: if the parent dies for ANY reason (SIGKILL, OOM,
    // panic-abort) the kernel SIGTERMs this child, so it can never outlive the
    // parent as an orphan. `spawn_hardened_tokio` forks it from the runtime's
    // process-lifetime spawner thread (the signal is bound to the forking
    // thread), registered with this caller's tokio runtime. `kill_on_drop` in
    // `console_command` remains the graceful-path floor tokio adds on top, for
    // a registered child only. The signal is Linux-only; on every Unix the
    // child also inherits stdio and no other descriptor of this process.
    match crate::system::spawn_hardened_tokio(cmd) {
        Ok(child) => {
            if let Ok(mut g) = CHILD.lock() {
                *g = Some(child);
            }
            crate::system::emit_runtime_log(
                "console",
                &format!(
                    "spawned console child on :{child_port} (bin {})",
                    bin.display()
                ),
            );
            Some(token)
        }
        Err(e) => {
            crate::system::emit_runtime_log(
                "console",
                &format!("spawn failed ({e}); falling back to in-process console"),
            );
            None
        }
    }
}

/// Kill the tracked console child (parent shutdown), then remove the
/// zero-config store directory. Idempotent; never panics.
pub fn shutdown_console() {
    if let Ok(mut g) = CHILD.lock() {
        if let Some(child) = g.as_mut() {
            let _ = child.start_kill();
        }
        *g = None;
    }
    if let Ok(mut dir) = CONSOLE_SCRATCH.lock() {
        drop(dir.take());
    }
}

// NOTE (shutdown ownership): the console child's teardown on parent shutdown is
// owned by the ONE coherent graceful-shutdown path in `web::web_shutdown_signal`
// — it calls `shutdown_console()` then returns so axum drains and the process
// exits 0. A previous `install_shutdown_hook` here installed a SECOND tokio
// signal handler that `std::process::exit(130)`'d; two handlers raced and the
// 130 exit defeated the exit-0-on-clean-shutdown contract. It was removed. The
// `PR_SET_PDEATHSIG` (Linux, via `system::spawn_hardened_tokio`) + `kill_on_drop`
// set in `spawn_console` remain the defense-in-depth floor for NON-graceful parent death (SIGKILL / OOM / crash).

// ─── Reverse proxy ──────────────────────────────────────────────────────────

/// Shared proxy state, initialised once when the proxy mounts: the upstream
/// origin (`http://127.0.0.1:<child_port>`) and a connection-pooling client.
struct ProxyState {
    client: reqwest::Client,
    upstream: String,
}

static PROXY: OnceLock<ProxyState> = OnceLock::new();

/// RFC 7230 §6.1 hop-by-hop headers (plus `host`, which reqwest derives from the
/// upstream URL, and `content-length`, which we drop because every proxied
/// response is re-encoded as a stream). Never forwarded in either direction.
fn is_hop_by_hop(name: &axum::http::HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "host"
            | "content-length"
    )
}

/// Build a small status-only error response without panicking.
fn error_response(status: axum::http::StatusCode, msg: &str) -> axum::response::Response {
    use axum::response::IntoResponse;
    (status, msg.to_string()).into_response()
}

/// Forward one request to `upstream`, STRIPPING the `/_ipe/console` prefix from
/// the path (strip convention). Response body is streamed, so SSE
/// (`/_ipe/console/_ipe/sse`) passes through without buffering. No panic
/// vectors: every fallible step degrades to a 502/503, never `unwrap`.
///
/// Factored to take `client` + `upstream` explicitly (rather than reading the
/// `PROXY` static) so it is unit-testable against a throwaway upstream without
/// touching global state.
async fn forward(
    client: &reqwest::Client,
    upstream: &str,
    req: axum::extract::Request,
) -> axum::response::Response {
    // Strip the mount prefix: `/_ipe/console` → `/`, `/_ipe/console/x` → `/x`.
    let path = req.uri().path();
    let rest = path.strip_prefix(CONSOLE_BASE).unwrap_or(path);
    let rest = if rest.is_empty() { "/" } else { rest };
    let query = req
        .uri()
        .query()
        .map(|q| format!("?{q}"))
        .unwrap_or_default();
    let url = format!("{upstream}{rest}{query}");

    let method = req.method().clone();
    let headers = req.headers().clone();
    let body_bytes = match axum::body::to_bytes(req.into_body(), MAX_PROXY_BODY).await {
        Ok(b) => b,
        Err(_) => {
            return error_response(
                axum::http::StatusCode::BAD_GATEWAY,
                "console proxy: request body read failed",
            );
        }
    };

    let mut rb = client.request(method, &url);
    for (name, value) in headers.iter() {
        if is_hop_by_hop(name) {
            continue;
        }
        // The child performs NO auth (spawned with IPE_CONSOLE_EMBED=off). The
        // parent admin credential — validated by `console::gate_blocked` in the
        // `Authorization` header BEFORE this handler runs — is pure liability
        // downstream: the child can't act on it and would record it verbatim in
        // its telemetry store (request-header capture). Strip it so the gate
        // secret never crosses into the child. (`proxy-authorization` is already
        // dropped as hop-by-hop above.)
        if name.as_str() == "authorization" {
            continue;
        }
        rb = rb.header(name, value);
    }
    // Pass the buffered `Bytes` straight to reqwest (which impls `From<Bytes>`)
    // rather than cloning into a `Vec<u8>` — avoids a second full-body copy and
    // halves peak per-request memory for large proxied POSTs.
    let upstream_resp = match rb.body(body_bytes).send().await {
        Ok(r) => r,
        Err(_) => {
            return error_response(
                axum::http::StatusCode::BAD_GATEWAY,
                "console proxy: upstream unreachable",
            );
        }
    };

    let status = upstream_resp.status();
    let resp_headers = upstream_resp.headers().clone();
    let stream = upstream_resp.bytes_stream();
    let body = axum::body::Body::from_stream(stream);

    let mut builder = axum::response::Response::builder().status(status);
    for (name, value) in resp_headers.iter() {
        if is_hop_by_hop(name) {
            continue;
        }
        builder = builder.header(name, value);
    }
    match builder.body(body) {
        Ok(r) => r,
        Err(_) => error_response(
            axum::http::StatusCode::BAD_GATEWAY,
            "console proxy: malformed upstream response",
        ),
    }
}

/// axum route handler: forward via the mounted `PROXY` state. 503 if the proxy
/// somehow isn't initialised (can't happen once mounted, but degrade rather
/// than panic).
async fn proxy_entry(req: axum::extract::Request) -> axum::response::Response {
    // Per-request auth, defense-in-depth. The PRIMARY enforcement is the
    // outermost `observability::track` middleware, which routes every
    // `/_ipe/console*` request through `console::gate_blocked` (production →
    // admin credential required; dev open) BEFORE it reaches this handler — so
    // the proxied path is already gated. This second call to the SAME gate keeps
    // the sensitive console surface protected even if a future router change ever
    // mounts the proxy outside that middleware. `gate_allows()` (mount-time) is
    // orthogonal: it decides whether to mount at all, not who may reach it.
    if let Some(blocked) =
        super::console::gate_blocked(super::console::Surface::Console, req.headers())
    {
        return blocked;
    }
    match PROXY.get() {
        Some(state) => forward(&state.client, &state.upstream, req).await,
        None => error_response(
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "console proxy not initialised",
        ),
    }
}

/// Poll the child's TCP port until it accepts a connection or `timeout` elapses.
/// `true` = ready. Bounded so a child that never binds can't wedge boot.
async fn wait_ready(port: u16, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Grab a free ephemeral loopback port by binding `:0` and reading the assigned
/// port. `None` if the OS won't hand one out. (Small TOCTOU window between drop
/// and the child's bind.)
fn pick_free_port() -> Option<u16> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").ok()?;
    let port = listener.local_addr().ok()?.port();
    drop(listener);
    Some(port)
}

/// Gate → pick port → spawn the pre-built console child → wait for readiness →
/// init the proxy state + shutdown hook. Returns `true` when the reverse proxy
/// is live (the caller mounts `proxy_routes` instead of the in-process console);
/// `false` on gate-closed / binary-absent / spawn-fail / readiness-timeout
/// (caller mounts the in-process console fallback — no side effects left behind).
///
/// Reads the parent's `IPE_CONSOLE_DB_PATH` (the telemetry spill D writes) and
/// wires it to the child's `IPE_CONSOLE_HUB_DB` so the dashboard renders what
/// the parent recorded. Decided BEFORE the router is built so both the proxy and
/// the in-process fallback sit under the same observability middleware.
/// The console child's data store path. The user's `IPE_CONSOLE_DB_PATH` when
/// set (durable history at their chosen location), else `console.db` inside a
/// private per-process scratch directory so the console works zero-config (a
/// lean app gets a live console without configuring durability).
///
/// `None` when no private scratch directory can be created; the caller then
/// serves the in-process console rather than a store another local user could
/// predict, pre-create, or redirect.
fn console_store_path() -> Option<String> {
    match crate::system::read_env_var("IPE_CONSOLE_DB_PATH") {
        Ok(p) if !p.is_empty() => Some(p),
        _ => {
            let leaf = crate::scratch_core::LeafName::new("console.db").ok()?;
            let mut slot = CONSOLE_SCRATCH.lock().ok()?;
            if slot.is_none() {
                *slot = Some(crate::scratch_core::ScratchDir::new("ipe-console").ok()?);
            }
            slot.as_ref()
                .map(|dir| dir.child(&leaf).to_string_lossy().into_owned())
        }
    }
}

/// Whether THIS (parent) process writes the telemetry store directly via its own
/// spill (db app with `IPE_CONSOLE_DB_PATH`). When true the child reads only;
/// when false the parent pushes to the child collector. Always false without the
/// `db` feature (a lean live app can't spill).
fn parent_spill_active() -> bool {
    #[cfg(feature = "db")]
    {
        crate::telemetry_spill::is_enabled()
    }
    #[cfg(not(feature = "db"))]
    {
        false
    }
}

pub async fn ensure_console_proxy() -> bool {
    if !super::console::gate_allows() {
        return false;
    }
    // Fast path for the common case (binary not pre-built yet): skip the
    // port-pick + spawn entirely and let the in-process console serve.
    if console_bin_path().is_none() {
        return false;
    }
    // Console data store + who writes it (push-to-local-collector):
    //   - db parent (its own spill is active) → parent writes the store
    //     directly; the child only reads it. No push.
    //   - lean/memory parent → the child collects: the parent PUSHES its in-RAM
    //     telemetry to the child, which writes + reads the store.
    let Some(store) = console_store_path() else {
        return false;
    };
    let parent_writes = parent_spill_active();
    let port = match pick_free_port() {
        Some(p) => p,
        None => return false,
    };
    let Some(token) = spawn_console(port, &store, /* child_collects = */ !parent_writes) else {
        // Binary absent (not pre-built / different ipe version) or spawn error.
        return false;
    };
    if !wait_ready(port, READY_TIMEOUT).await {
        crate::system::emit_runtime_log(
            "console",
            &format!(
                "child not ready within {READY_TIMEOUT:?}; falling back to in-process console"
            ),
        );
        shutdown_console();
        return false;
    }
    // Bound the upstream hop so a wedged child can't accumulate in-flight
    // requests without limit. `connect_timeout` caps the TCP handshake; a
    // `read_timeout` (per-read inactivity, NOT a total `.timeout`) caps a child
    // that accepts the connection then stalls — set well above the Ipe.Web SSE
    // heartbeat (~15 s) + TTL (~35 s) so long-lived `/_ipe/sse` streams are not
    // severed.
    // `redirect::Policy::none()`: a reverse proxy RELAYS an upstream 3xx to the
    // browser verbatim — it must never follow it itself. Following would both
    // break proxy semantics (the client never learns the redirect) and re-issue
    // the forwarded request headers to the redirect target; `forward` strips the
    // parent admin `Authorization` before forwarding, but other forwarded headers
    // (cookies) must not be replayed to an upstream-chosen location.
    // `no_proxy()`: the upstream is always loopback, so an inherited
    // `HTTP_PROXY` never receives the forwarded cookies.
    // No client (TLS backend init failed) → no proxy: the in-process console
    // serves; there is no unpinned fallback client.
    let Some(client) = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .read_timeout(Duration::from_secs(60))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .ok()
    else {
        crate::system::emit_runtime_log(
            "console",
            "no HTTP client for the console proxy; falling back to in-process console",
        );
        shutdown_console();
        return false;
    };
    // Lean parent: start pushing our telemetry to the child collector now that
    // its ingest is up. (db parent already wrote the store directly.)
    if !parent_writes {
        super::push_exporter::enable_to_console(port, token).await;
    }
    if PROXY
        .set(ProxyState {
            client,
            upstream: format!("http://127.0.0.1:{port}"),
        })
        .is_err()
    {
        // Already initialised once (shouldn't happen — one Web server per process).
        crate::system::emit_runtime_log(
            "console",
            "proxy already initialised; keeping the first mount",
        );
    }
    // NOTE: child teardown on shutdown is now owned by the ONE coherent
    // graceful-shutdown path in `web::web_shutdown_signal` (it calls
    // `shutdown_console()` then lets axum drain → exit 0). We deliberately do
    // NOT install the old `install_shutdown_hook` here — two signal handlers
    // would race, and that hook's `std::process::exit(130)` would defeat the
    // exit-0-on-clean-shutdown contract. The PR_SET_PDEATHSIG + kill_on_drop on
    // the child remain the defense-in-depth floor for non-graceful parent death.
    crate::system::emit_runtime_log(
        "console",
        &format!("reverse-proxy ready at {CONSOLE_BASE}/* → 127.0.0.1:{port}"),
    );
    true
}

/// Add the reverse-proxy routes (`/_ipe/console` + `/_ipe/console/*rest`) to a
/// router. Generic over the app state `S` because `proxy_entry` is state-free —
/// so this composes into the main `Router<WebState<…>>` before `with_state`,
/// keeping the proxy under the same `track` middleware as every other route.
/// Call only when `ensure_console_proxy().await` returned `true`.
pub fn proxy_routes<S>(router: axum::Router<S>) -> axum::Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    use axum::routing::any;
    router
        .route(CONSOLE_BASE, any(proxy_entry))
        .route(&format!("{CONSOLE_BASE}/*rest"), any(proxy_entry))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bin_path_none_when_absent() {
        crate::system::locked_set_var(CONSOLE_BIN_ENV, "/nonexistent/ipe-console-xyz");
        assert!(console_bin_path().is_none());
        crate::system::locked_remove_var(CONSOLE_BIN_ENV);
    }

    #[test]
    fn spawn_returns_none_without_binary() {
        // No binary at the override path → None (caller falls back), no panic.
        crate::system::locked_set_var(CONSOLE_BIN_ENV, "/nonexistent/ipe-console-xyz");
        assert!(spawn_console(9931, "", false).is_none());
        crate::system::locked_remove_var(CONSOLE_BIN_ENV);
    }

    // The unauthenticated console child binds loopback on every spawn shape,
    // so it never listens beside the gated proxy on an exposed interface.
    #[test]
    fn console_child_binds_loopback() {
        let bin = std::path::Path::new("/nonexistent/ipe-console");
        for (store, collects) in [("", false), ("/tmp/hub.db", false), ("/tmp/hub.db", true)] {
            let token = super::super::push_exporter::IngestToken::mint().expect("entropy");
            let cmd = console_command(bin, 9931, store, collects, &token);
            let bind = cmd
                .as_std()
                .get_envs()
                .find(|(key, _)| *key == "IPE_HTTP_BIND")
                .and_then(|(_, value)| value);
            assert_eq!(
                bind,
                Some(std::ffi::OsStr::new("127.0.0.1")),
                "store {store:?} collects {collects}"
            );
        }
    }

    // The child is placed on its port through the supervisor relocation var,
    // which outranks an inherited operator `IPE_WEB_PORT` (or a relocation the
    // parent itself received); the operator var is never written.
    #[test]
    fn console_child_is_relocated_through_the_internal_port_var() {
        let bin = std::path::Path::new("/nonexistent/ipe-console");
        let token = super::super::push_exporter::IngestToken::mint().expect("entropy");
        let cmd = console_command(bin, 9931, "", false, &token);
        let env_of = |name: &str| {
            cmd.as_std()
                .get_envs()
                .find(|(key, _)| *key == std::ffi::OsStr::new(name))
        };
        assert_eq!(
            env_of(crate::LISTEN_PORT_RELOCATION_ENV).and_then(|(_, value)| value),
            Some(std::ffi::OsStr::new("9931"))
        );
        assert!(
            env_of("IPE_WEB_PORT").is_none(),
            "the operator var is never written"
        );
    }

    // The child's ingest demands the token the parent minted for it, on every
    // spawn shape (the explicit `env` overrides any inherited value), so a
    // Release child under any posture admits the parent's pushes and nothing
    // else.
    #[test]
    fn console_child_carries_its_minted_ingest_token() {
        use super::super::push_exporter::IngestToken;
        let bin = std::path::Path::new("/nonexistent/ipe-console");
        for (store, collects) in [("", false), ("/tmp/hub.db", false), ("/tmp/hub.db", true)] {
            let token = IngestToken::mint().expect("entropy");
            let cmd = console_command(bin, 9931, store, collects, &token);
            let carried = cmd
                .as_std()
                .get_envs()
                .find(|(key, _)| *key == INGEST_TOKEN_ENV)
                .and_then(|(_, value)| value);
            assert_eq!(
                carried,
                Some(std::ffi::OsStr::new(token.expose())),
                "store {store:?} collects {collects}"
            );
        }
        let first = IngestToken::mint().expect("entropy");
        let second = IngestToken::mint().expect("entropy");
        assert_eq!(first.expose().len(), 64);
        assert!(first.expose().bytes().all(|b| b.is_ascii_hexdigit()));
        assert_ne!(first.expose(), second.expose(), "every spawn mints afresh");
    }

    // The child exports nowhere: every egress name is removed on every spawn
    // shape, so the token minted for the child's ingest never reaches an
    // inherited parent or hub target.
    #[test]
    fn console_child_inherits_no_egress_target() {
        use super::super::push_exporter::{ExporterEnv, IngestToken};
        let bin = std::path::Path::new("/nonexistent/ipe-console");
        let egress: Vec<&str> = ExporterEnv::egress().collect();
        assert!(egress.contains(&"IPE_PARENT_URL"));
        assert!(egress.contains(&"IPE_CONSOLE_HUB"));
        assert!(egress.contains(&"IPE_CONSOLE_HUB_TOKEN"));
        for (store, collects) in [("", false), ("/tmp/hub.db", false), ("/tmp/hub.db", true)] {
            let token = IngestToken::mint().expect("entropy");
            let cmd = console_command(bin, 9931, store, collects, &token);
            for name in &egress {
                let entry = cmd
                    .as_std()
                    .get_envs()
                    .find(|(key, _)| *key == std::ffi::OsStr::new(name));
                assert_eq!(
                    entry,
                    Some((std::ffi::OsStr::new(name), None)),
                    "{name} not removed; store {store:?} collects {collects}"
                );
            }
        }
    }

    #[test]
    fn shutdown_is_idempotent_noop_when_empty() {
        shutdown_console();
        shutdown_console();
    }

    #[test]
    fn pick_free_port_returns_a_port() {
        let p = pick_free_port();
        assert!(p.is_some());
        assert!(p.unwrap_or(0) > 0);
    }

    #[test]
    fn hop_by_hop_filters_connection_not_content_type() {
        use axum::http::header::{CONNECTION, CONTENT_TYPE};
        assert!(is_hop_by_hop(&CONNECTION));
        assert!(!is_hop_by_hop(&CONTENT_TYPE));
    }

    // Spin a throwaway upstream that echoes "METHOD PATH BODY", forward a
    // parent-shaped request through `forward`, and assert the /_ipe/console
    // prefix is stripped while method + body + query round-trip.
    #[tokio::test]
    async fn forward_strips_prefix_and_round_trips() {
        use axum::{Router, routing::any};

        async fn echo(req: axum::extract::Request) -> String {
            let method = req.method().clone();
            let uri = req.uri().clone();
            let body = axum::body::to_bytes(req.into_body(), 1 << 20)
                .await
                .unwrap_or_default();
            format!(
                "{method} {}{} {}",
                uri.path(),
                uri.query().map(|q| format!("?{q}")).unwrap_or_default(),
                String::from_utf8(body.to_vec()).expect("a UTF-8 request body")
            )
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind upstream");
        let port = listener.local_addr().expect("addr").port();
        let app = Router::new().fallback(any(echo));
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        // The parent receives POST /_ipe/console/_ipe/event?x=1 with body "hi".
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/_ipe/console/_ipe/event?x=1")
            .body(axum::body::Body::from("hi"))
            .expect("build req");

        let client = reqwest::Client::new();
        let upstream = format!("http://127.0.0.1:{port}");
        let resp = forward(&client, &upstream, req).await;
        assert_eq!(resp.status(), axum::http::StatusCode::OK);

        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .expect("read resp body");
        let text = String::from_utf8(bytes.to_vec()).expect("a UTF-8 response body");
        // Prefix stripped → child sees /_ipe/event; method, query, body preserved.
        assert_eq!(text, "POST /_ipe/event?x=1 hi", "got: {text}");
    }

    // Prove the refusal: the proxy RELAYS an upstream 3xx to the caller and does
    // NOT follow it. A redirect-disabled client is what `ensure_console_proxy`
    // builds; forwarding a request whose upstream answers 307→leak must return
    // the 307 to the caller (browser) and leave the leak target untouched, so no
    // forwarded header is replayed to an upstream-chosen location.
    #[tokio::test]
    async fn forward_relays_redirect_without_following() {
        use axum::extract::State;
        use axum::response::IntoResponse;
        use axum::{Router, routing::any};
        use std::sync::{Arc, Mutex};

        let leak_hits: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
        async fn leak(State(hits): State<Arc<Mutex<u32>>>) -> &'static str {
            if let Ok(mut g) = hits.lock() {
                *g += 1;
            }
            "LEAKED"
        }
        let leak_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind leak");
        let leak_port = leak_listener.local_addr().expect("addr").port();
        let leak_app = Router::new()
            .fallback(any(leak))
            .with_state(leak_hits.clone());
        tokio::spawn(async move {
            let _ = axum::serve(leak_listener, leak_app).await;
        });

        let leak_base = format!("http://127.0.0.1:{leak_port}");
        async fn redirect(State(loc): State<String>) -> axum::response::Response {
            (
                axum::http::StatusCode::TEMPORARY_REDIRECT,
                [(axum::http::header::LOCATION, format!("{loc}/leak"))],
                "moved",
            )
                .into_response()
        }
        let up_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind upstream");
        let up_port = up_listener.local_addr().expect("addr").port();
        let up_app = Router::new()
            .fallback(any(redirect))
            .with_state(leak_base.clone());
        tokio::spawn(async move {
            let _ = axum::serve(up_listener, up_app).await;
        });

        // The same redirect-disabled client `ensure_console_proxy` constructs.
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("client");
        let upstream = format!("http://127.0.0.1:{up_port}");
        let req = axum::http::Request::builder()
            .method("GET")
            .uri("/_ipe/console")
            .body(axum::body::Body::empty())
            .expect("build req");

        let resp = forward(&client, &upstream, req).await;
        // The 307 is relayed to the caller, NOT followed.
        assert_eq!(resp.status(), axum::http::StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(
            *leak_hits.lock().expect("lock"),
            0,
            "proxy followed the redirect instead of relaying it"
        );
    }

    // The bare mount path `/_ipe/console` (no trailing slash) maps to the
    // child's root `/`.
    #[tokio::test]
    async fn forward_bare_base_maps_to_root() {
        use axum::{Router, routing::any};

        async fn echo_path(req: axum::extract::Request) -> String {
            req.uri().path().to_string()
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind upstream");
        let port = listener.local_addr().expect("addr").port();
        let app = Router::new().fallback(any(echo_path));
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let req = axum::http::Request::builder()
            .method("GET")
            .uri("/_ipe/console")
            .body(axum::body::Body::empty())
            .expect("build req");

        let client = reqwest::Client::new();
        let upstream = format!("http://127.0.0.1:{port}");
        let resp = forward(&client, &upstream, req).await;
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .expect("read resp body");
        assert_eq!(bytes.as_ref(), b"/".as_slice());
    }
}
