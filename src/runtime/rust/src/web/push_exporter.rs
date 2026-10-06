//! Observability federation — child→parent telemetry push.
//!
//! When a Rust Web app runs as a sub-app under a parent (`IPE_PARENT_URL` set),
//! this background exporter batches its logs + spans and POSTs them every
//! `IPE_OBSERVABILITY_PUSH_INTERVAL_MS` (default 2000) to the parent's
//! `/_ipe/observability/ingest` — the symmetric counterpart to the receiver in
//! `web/console.rs`.
//!
//! `live`-gated (uses reqwest). Best-effort end to end: a bounded queue drops on
//! overflow, POST failures warn + drop. The observability path must never block
//! or panic the request path. No `unwrap`/`expect`/indexing in any reachable
//! path.
//!
//! Deliberate divergence from `hub_exporter` (which keeps a bounded retry spool):
//! child→parent federation is a same-host loopback hop on a short cadence — a
//! transient parent blip is recovered by the very next tick's fresh batch, so the
//! added complexity + memory of a retry spool buys little here. The remote-hub
//! exporter spools because its push crosses the network to a possibly-distant hub.

use std::sync::OnceLock;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// Every env name the observability exporters (this module and `hub_exporter`)
/// read. [`ExporterEnv::read`] is the only env read in either exporter, so no
/// exporter input exists without an [`ExporterEnvRole`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExporterEnv {
    /// Parent base URL — presence means "I'm a sub-app, push upward".
    ParentUrl,
    /// Federation flush cadence (ms).
    PushInterval,
    /// Federation bounded queue depth override.
    PushBuffer,
    /// Shared secret the parent's ingest gate checks (`X-Ipê-Ingest-Token`).
    IngestToken,
    /// Hub OTLP collector base URL — presence enables the hub exporter.
    HubUrl,
    /// Hub bearer token (must be ≥32 bytes; shorter tokens are refused).
    HubToken,
    /// Hub flush cadence (ms).
    HubInterval,
    /// Service name attached as the OTLP `service.name` resource attribute.
    ServiceName,
}

/// What an exporter env name carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExporterEnvRole {
    /// An outbound telemetry destination or its credential. A spawned child
    /// that must not export upstream has every one of these removed.
    Egress,
    /// The ingest secret: the credential a push carries and the one the
    /// process's own ingest gate checks.
    IngestSecret,
    /// A cadence, buffer or label knob; reaches no other party.
    Tuning,
}

impl ExporterEnv {
    /// Every exporter env name.
    pub(crate) const ALL: [Self; 8] = [
        Self::ParentUrl,
        Self::PushInterval,
        Self::PushBuffer,
        Self::IngestToken,
        Self::HubUrl,
        Self::HubToken,
        Self::HubInterval,
        Self::ServiceName,
    ];

    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::ParentUrl => "IPE_PARENT_URL",
            Self::PushInterval => "IPE_OBSERVABILITY_PUSH_INTERVAL_MS",
            Self::PushBuffer => "IPE_OBSERVABILITY_BUFFER",
            Self::IngestToken => "IPE_INGEST_TOKEN",
            Self::HubUrl => "IPE_CONSOLE_HUB",
            Self::HubToken => "IPE_CONSOLE_HUB_TOKEN",
            Self::HubInterval => "IPE_CONSOLE_BATCH_INTERVAL_MS",
            Self::ServiceName => "IPE_SERVICE_NAME",
        }
    }

    pub(crate) const fn role(self) -> ExporterEnvRole {
        match self {
            Self::ParentUrl | Self::HubUrl | Self::HubToken => ExporterEnvRole::Egress,
            Self::IngestToken => ExporterEnvRole::IngestSecret,
            Self::PushInterval | Self::PushBuffer | Self::HubInterval | Self::ServiceName => {
                ExporterEnvRole::Tuning
            }
        }
    }

    /// The names a child must not inherit when it must not export upstream.
    pub(crate) fn egress() -> impl Iterator<Item = &'static str> {
        Self::ALL
            .into_iter()
            .filter(|e| e.role() == ExporterEnvRole::Egress)
            .map(Self::name)
    }

    /// This process's value for the name; `None` when unset or not UTF-8.
    pub(crate) fn read(self) -> Option<String> {
        self.raw().ok()
    }

    /// The numeric ceiling this tuning name carries; `0` is refused, and a
    /// queue depth is bounded by what a `tokio` channel can hold.
    pub(crate) const fn ceiling(
        self,
        default: u64,
        unit: &'static str,
    ) -> crate::system::EnvCeiling {
        let ceiling = crate::system::EnvCeiling::new(
            self.name(),
            default,
            crate::system::ZeroCeiling::Refused,
            unit,
        );
        match self {
            Self::PushBuffer => ceiling.at_most(tokio::sync::Semaphore::MAX_PERMITS as u64),
            Self::ParentUrl
            | Self::IngestToken
            | Self::PushInterval
            | Self::HubUrl
            | Self::HubToken
            | Self::HubInterval
            | Self::ServiceName => ceiling,
        }
    }

    /// This process's value for the name, parsed as [`Self::ceiling`].
    ///
    /// # Errors
    ///
    /// Returns the refusal for a present, malformed value.
    pub(crate) fn read_ceiling<T: TryFrom<u64>>(
        self,
        default: u64,
        unit: &'static str,
    ) -> Result<T, crate::system::EnvCeilingRefusal> {
        self.ceiling(default, unit).parse_as(self.raw())
    }

    fn raw(self) -> Result<String, std::env::VarError> {
        crate::system::read_env_var(self.name())
    }
}

/// Logs a refused exporter ceiling; the exporter stays disabled.
pub(crate) fn log_refused_ceiling(label: &str, refusal: &crate::system::EnvCeilingRefusal) {
    crate::system::emit_runtime_log(label, &format!("{refusal}; exporter disabled"));
}

const DEFAULT_QUEUE_CAP: usize = 1024;
const DEFAULT_INTERVAL_MS: u64 = 2000;
/// Floor on the flush interval so a typo can't spin a hot loop.
const MIN_INTERVAL_MS: u64 = 100;
/// Hard cap on the in-batcher accumulator so a high log/span rate over a long
/// flush interval can't grow `buf` without bound (the mpsc channel is bounded,
/// but the batcher drains it continuously into `buf`). Reaching the cap forces
/// an early flush instead of waiting for the tick.
const MAX_BATCH: usize = 8192;

/// One telemetry record queued for the exporter.
enum Entry {
    Log {
        ts_ms: u64,
        level: String,
        message: String,
    },
    Span {
        ts_ms: u64,
        name: String,
        dur_us: u64,
        ok: bool,
    },
    /// Synchronous flush request: batcher drains its buffer then acks via the
    /// oneshot. Used by `flush_now` for a bounded pre-exit drain.
    Flush(tokio::sync::oneshot::Sender<()>),
}

static SENDER: OnceLock<mpsc::Sender<Entry>> = OnceLock::new();

/// The shared secret a push carries in `x-ipe-ingest-token`. Opaque: no
/// `Debug`, `Display` or `Clone`, so formatting cannot carry it into a log line
/// and only [`IngestToken::expose`] yields its text, at the header write.
pub(crate) struct IngestToken(String);

/// Entropy bytes in a minted token: 256 bits, rendered as 64 lowercase hex.
const MINTED_TOKEN_BYTES: usize = 32;

impl IngestToken {
    /// A fresh token from the OS CSPRNG (`getrandom`). `None` when the entropy
    /// source is unavailable; the caller refuses rather than run token-less.
    pub(crate) fn mint() -> Option<Self> {
        let mut buf = [0u8; MINTED_TOKEN_BYTES];
        getrandom::getrandom(&mut buf).ok()?;
        let mut hex = String::with_capacity(MINTED_TOKEN_BYTES * 2);
        for byte in buf {
            hex.push(hex_digit(byte >> 4));
            hex.push(hex_digit(byte & 0x0f));
        }
        Some(Self(hex))
    }

    /// The operator-configured `IPE_INGEST_TOKEN`; `None` when unset or empty.
    fn from_env() -> Option<Self> {
        ExporterEnv::IngestToken
            .read()
            .filter(|t| !t.is_empty())
            .map(Self)
    }

    /// The token text, for the one header (or child env) write that carries it.
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

/// The lowercase hex digit of a nibble (`0..=15`); total over `u8`.
fn hex_digit(nibble: u8) -> char {
    char::from_digit(u32::from(nibble & 0x0f), 16).unwrap_or('0')
}

/// What one batch POST came to. A refusal is the ingest answering with a
/// non-2xx status (a 401 for a missing or wrong token); a transport failure is
/// no answer at all.
pub(crate) enum PushOutcome {
    Accepted,
    Refused(reqwest::StatusCode),
    Transport(reqwest::Error),
}

/// Enable the push exporter from env. No-op unless `IPE_PARENT_URL` is set
/// (i.e. this process runs as a sub-app pushing UP to its parent's ingest —
/// federation). Idempotent. Call once at Web boot.
///
/// Secrets-in-transit: `enable` (below) sends `IPE_INGEST_TOKEN` as a header
/// on every push. A misconfigured `http://` parent URL would leak that token
/// on the wire, so this gate mirrors `hub_exporter::enable_from_env`: refuse
/// to push to anything but `https://`, or `http://` when the host is exactly
/// a loopback name/address. PARSE the URL rather than string-prefix-matching
/// it — a prefix check on `"http://localhost"` also matches
/// `"http://localhost.evil.com"`.
pub async fn enable_from_env() {
    // Trim ONCE so the URL we validate is the exact one we push to (same fix
    // as hub_exporter: a leading-whitespace value otherwise passes the scheme
    // check yet leaves the space in the built URL).
    let parent = match ExporterEnv::ParentUrl.read() {
        Some(p) if !p.trim().is_empty() => p.trim().to_string(),
        _ => return,
    };
    if !url_allows_cleartext_token(&parent) {
        crate::system::emit_runtime_log(
            "push",
            &format!(
                "refusing to push ingest token over non-https {}={}; \
                 use https:// (or a localhost loopback); exporter disabled",
                ExporterEnv::ParentUrl.name(),
                redacted_origin(&parent)
            ),
        );
        return;
    }
    let interval_ms: u64 = match ExporterEnv::PushInterval
        .read_ceiling(DEFAULT_INTERVAL_MS, "decimal millisecond count")
    {
        Ok(ms) => ms,
        Err(refusal) => return log_refused_ceiling("push", &refusal),
    };
    let ingest_url = format!("{}/_ipe/observability/ingest", parent.trim_end_matches('/'));
    enable(
        "federation",
        Pipeline {
            ingest_url,
            token: IngestToken::from_env(),
            interval_ms,
        },
    );
}

/// Whether `url`'s host is EXACTLY a loopback name/address. `false` for an
/// unparseable or host-less value.
fn host_is_loopback(url: &reqwest::Url) -> bool {
    matches!(
        url.host_str(),
        Some("localhost") | Some("127.0.0.1") | Some("[::1]")
    )
}

/// Whether `url` is safe to carry `IPE_INGEST_TOKEN` on the wire: `https://`
/// unconditionally, or `http://` only when the host is EXACTLY a loopback
/// name/address. PARSE the URL rather than string-prefix-matching it — a
/// prefix check on `"http://localhost"` also matches
/// `"http://localhost.evil.com"`. The one gate both exporters (this and
/// `hub_exporter`) apply before carrying a token.
pub(crate) fn url_allows_cleartext_token(url: &str) -> bool {
    match reqwest::Url::parse(url) {
        Ok(u) => u.scheme() == "https" || (u.scheme() == "http" && host_is_loopback(&u)),
        Err(_) => false,
    }
}

/// How a client reaches its target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProxyRoute {
    /// Straight to the target; the environment's proxy settings are ignored.
    Direct,
    /// Through the proxy `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` name, if any.
    System,
}

/// The route for a client bound to `url`. A loopback target is always
/// [`ProxyRoute::Direct`]: an inherited `HTTP_PROXY` would otherwise receive a
/// loopback hop in cleartext, its ingest token, bearer and forwarded cookies
/// included, though the hop never needed to leave the machine. An unparseable
/// target is `Direct` too (the request then fails without involving a third
/// party). Anything else is `https://` by the enable gates, so a proxy only
/// tunnels it.
pub(crate) fn proxy_route(url: &str) -> ProxyRoute {
    match reqwest::Url::parse(url) {
        Ok(u) if !host_is_loopback(&u) => ProxyRoute::System,
        Ok(_) | Err(_) => ProxyRoute::Direct,
    }
}

/// `builder` with [`proxy_route`] applied for `url`.
pub(crate) fn routed(builder: reqwest::ClientBuilder, url: &str) -> reqwest::ClientBuilder {
    match proxy_route(url) {
        ProxyRoute::Direct => builder.no_proxy(),
        ProxyRoute::System => builder,
    }
}

/// The log-safe form of an exporter URL: `scheme://host[:port]` only. Userinfo
/// (`https://user:pass@host`), path, query and fragment may carry credentials
/// or tokens, so none of them ever reaches a log line; an unparseable or
/// host-less value renders as a fixed placeholder, never the raw text.
pub(crate) fn redacted_origin(url: &str) -> String {
    let Ok(parsed) = reqwest::Url::parse(url.trim()) else {
        return "<unparseable url>".to_string();
    };
    let Some(host) = parsed.host_str() else {
        return "<url without host>".to_string();
    };
    match parsed.port() {
        Some(port) => format!("{}://{host}:{port}", parsed.scheme()),
        None => format!("{}://{host}", parsed.scheme()),
    }
}

/// Where one exporter pushes and with which credential.
struct Pipeline {
    ingest_url: String,
    token: Option<IngestToken>,
    interval_ms: u64,
}

impl Pipeline {
    /// The pipeline to a local console child on `child_port`, carrying the
    /// `token` minted for that child.
    fn to_console(child_port: u16, token: IngestToken) -> Self {
        Self {
            ingest_url: format!("http://127.0.0.1:{child_port}/_ipe/observability/ingest"),
            token: Some(token),
            interval_ms: DEFAULT_INTERVAL_MS,
        }
    }
}

/// Enable pushing THIS app's telemetry to a LOCAL console-child collector
/// ("push-to-local-collector"): a lean parent (no SQLite) batches its
/// in-RAM telemetry and POSTs it to the console child's
/// `/_ipe/observability/ingest`, where the child (which owns sqlx + the store)
/// records → spills → serves it. Called by the console mount after the child is
/// ready, when the parent has no spill of its own.
///
/// `token` is the one `spawn_console` minted and handed the child as its
/// `IPE_INGEST_TOKEN`, so the child's ingest gate admits these pushes under
/// every build and posture.
pub(crate) async fn enable_to_console(child_port: u16, token: IngestToken) {
    enable("console-collector", Pipeline::to_console(child_port, token));
}

/// Shared activation: bound the interval, claim the SENDER, spawn the batcher.
/// Idempotent (first caller wins the OnceLock — a sub-app pushes to its parent
/// OR a top-level app pushes to its console child, never both). No HTTP client
/// (TLS backend init failed) leaves the exporter disabled, logged.
fn enable(label: &str, pipeline: Pipeline) {
    if SENDER.get().is_some() {
        return;
    }
    let Some(client) = exporter_client(&pipeline.ingest_url) else {
        crate::system::emit_runtime_log(
            "push",
            &format!("{label} push: no HTTP client available; exporter disabled"),
        );
        return;
    };
    let cap: usize = match ExporterEnv::PushBuffer
        .read_ceiling(DEFAULT_QUEUE_CAP as u64, "decimal entry count")
    {
        Ok(cap) => cap,
        Err(refusal) => return log_refused_ceiling("push", &refusal),
    };
    let (tx, rx) = mpsc::channel::<Entry>(cap);
    if SENDER.set(tx).is_err() {
        return; // lost an enable race
    }
    crate::system::emit_runtime_log(
        "push",
        &format!(
            "{label} push → {} every {}ms",
            redacted_origin(&pipeline.ingest_url),
            pipeline.interval_ms.max(MIN_INTERVAL_MS)
        ),
    );
    tokio::spawn(batcher(rx, client, pipeline));
}

/// The exporter's reqwest client for `ingest_url`: explicit timeouts so a
/// parent that accepts the TCP connection but never responds
/// (slow/hung/half-dead) can't wedge the batcher task (and, through it,
/// `flush_now`'s pre-exit drain) forever; `redirect::Policy::none()`; and the
/// [`proxy_route`] for the target. This exporter sends `IPE_INGEST_TOKEN` as a
/// header on every push — following a redirect is a secret-leak vector:
/// reqwest's default follows up to 10 hops and re-sends the credential to the
/// redirect target, defeating the https-only enable gate
/// (`url_allows_cleartext_token`) by pushing the token to an attacker-chosen
/// `http://` location. Push to the configured ingest only; never chase a 3xx.
/// `None` when the TLS backend cannot initialise; there is no unpinned
/// fallback client.
fn exporter_client(ingest_url: &str) -> Option<reqwest::Client> {
    let builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .connect_timeout(Duration::from_millis(CONNECT_TIMEOUT_MS))
        .redirect(reqwest::redirect::Policy::none());
    routed(builder, ingest_url).build().ok()
}

/// Connect ceiling of the push client, in milliseconds.
///
/// The client builder and `FLUSH_DEADLINE` both read it, so the shutdown
/// flush always outlasts a connect in flight.
const CONNECT_TIMEOUT_MS: u64 = 2_000;

/// How long the shutdown flush waits for the push batcher's final batch.
const FLUSH_DEADLINE: FlushDeadline = FlushDeadline::after_connect::<CONNECT_TIMEOUT_MS>();

/// Accumulate entries and flush a batch on each tick. Channel close drains a
/// final batch then exits. A `Flush` sentinel drains immediately and acks.
async fn batcher(mut rx: mpsc::Receiver<Entry>, client: reqwest::Client, pipeline: Pipeline) {
    let Pipeline {
        ingest_url,
        token,
        interval_ms,
    } = pipeline;
    let token = token.as_ref().map(IngestToken::expose);
    let mut log = OutcomeLog::new(Instant::now());
    let mut buf: Vec<Entry> = Vec::new();
    let mut tick = tokio::time::interval(Duration::from_millis(interval_ms.max(MIN_INTERVAL_MS)));
    // The first tick fires immediately; skip it so we don't flush an empty batch.
    tick.tick().await;
    loop {
        tokio::select! {
            maybe = rx.recv() => match maybe {
                Some(Entry::Flush(ack)) => {
                    if !buf.is_empty() {
                        flush(&client, &ingest_url, token, &buf, &mut log).await;
                        buf.clear();
                    }
                    // Best-effort ack — ignore send errors (caller may have timed out).
                    let _ = ack.send(());
                }
                Some(e) => {
                    buf.push(e);
                    // Bound the accumulator: flush early at the cap rather than
                    // letting it grow until the next tick.
                    if buf.len() >= MAX_BATCH {
                        flush(&client, &ingest_url, token, &buf, &mut log).await;
                        buf.clear();
                    }
                }
                None => {
                    if !buf.is_empty() {
                        flush(&client, &ingest_url, token, &buf, &mut log).await;
                    }
                    break;
                }
            },
            _ = tick.tick() => {
                if !buf.is_empty() {
                    flush(&client, &ingest_url, token, &buf, &mut log).await;
                    buf.clear();
                }
            }
        }
    }
}

/// Best-effort pre-exit flush of the push exporter, bounded by `FLUSH_DEADLINE`.
///
/// No-op when the exporter is disabled. Never panics.
pub async fn flush_now() {
    drain_before_exit(SENDER.get(), Entry::Flush, FLUSH_DEADLINE).await;
}

/// Extra wait past an exporter's connect timeout for its batch to be sent and answered.
const FLUSH_SEND_BUDGET_MS: u64 = 500;

/// Upper bound on any exporter's shutdown flush wait, in milliseconds.
const FLUSH_DEADLINE_CEILING_MS: u64 = 6_000;

/// How long a shutdown flush waits for one exporter's final batch.
///
/// The only constructor derives it from the exporter's connect timeout plus
/// `FLUSH_SEND_BUDGET_MS` and refuses at build time a deadline above
/// `FLUSH_DEADLINE_CEILING_MS`; `drain_before_exit` is the only consumer.
#[derive(Clone, Copy)]
pub(crate) struct FlushDeadline(Duration);

impl FlushDeadline {
    /// The deadline for an exporter whose client connects within `CONNECT_MS` milliseconds.
    pub(crate) const fn after_connect<const CONNECT_MS: u64>() -> Self {
        // IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if an exporter's flush deadline exceeds the shutdown ceiling [ledger #boundary]
        const { assert!(CONNECT_MS.saturating_add(FLUSH_SEND_BUDGET_MS) <= FLUSH_DEADLINE_CEILING_MS) };
        Self(Duration::from_millis(
            CONNECT_MS.saturating_add(FLUSH_SEND_BUDGET_MS),
        ))
    }
}

/// Asks an exporter's batcher to push its buffer and waits for its ack until `deadline`.
///
/// The one pre-exit flush path: each exporter's `flush_now` routes here with
/// the deadline derived from its own connect timeout. No-op when the exporter
/// is disabled (`tx` is `None`) or its queue is full (telemetry is
/// best-effort, never user data).
pub(crate) async fn drain_before_exit<E>(
    tx: Option<&mpsc::Sender<E>>,
    sentinel: fn(tokio::sync::oneshot::Sender<()>) -> E,
    deadline: FlushDeadline,
) {
    let Some(tx) = tx else { return };
    let (ack_tx, ack_rx) = tokio::sync::oneshot::channel::<()>();
    if tx.try_send(sentinel(ack_tx)).is_err() {
        return;
    }
    let _ = tokio::time::timeout(deadline.0, ack_rx).await;
}

/// Build the `{ "logs": [...], "spans": [...] }` payload the receiver accepts.
/// serde_json (a `live` dep) keeps the escaping correct.
fn build_payload(buf: &[Entry]) -> String {
    let mut logs = Vec::new();
    let mut spans = Vec::new();
    for e in buf {
        match e {
            Entry::Log {
                ts_ms,
                level,
                message,
            } => logs.push(serde_json::json!({
                "ts": ts_ms, "level": level, "message": message,
            })),
            Entry::Span {
                ts_ms,
                name,
                dur_us,
                ok,
            } => spans.push(serde_json::json!({
                "ts": ts_ms, "name": name, "durUs": dur_us, "ok": ok,
            })),
            // The batcher clears the buf before any Flush sentinel reaches here;
            // this arm is unreachable in practice but required for exhaustiveness.
            Entry::Flush(_) => {}
        }
    }
    serde_json::json!({ "logs": logs, "spans": spans }).to_string()
}

/// POST one batch to the ingest and report its outcome through `log`. The
/// batch is dropped either way (best-effort).
async fn flush(
    client: &reqwest::Client,
    ingest_url: &str,
    token: Option<&str>,
    buf: &[Entry],
    log: &mut OutcomeLog,
) {
    let outcome = send_batch(client, ingest_url, token, buf).await;
    if let Some(line) = log.observe(Instant::now(), ingest_url, &outcome, "batch dropped") {
        crate::system::emit_runtime_log("push", &line);
    }
}

/// POST one batch, carrying `token` in `x-ipe-ingest-token`, and classify the
/// answer: only a 2xx status is an acceptance.
async fn send_batch(
    client: &reqwest::Client,
    ingest_url: &str,
    token: Option<&str>,
    buf: &[Entry],
) -> PushOutcome {
    let body = build_payload(buf);
    let mut req = client
        .post(ingest_url)
        .header("content-type", "application/json")
        .body(body);
    if let Some(t) = token {
        req = req.header("x-ipe-ingest-token", t);
    }
    send_classified(req).await
}

/// Send one exporter request and classify the answer: only a 2xx status is an
/// acceptance. The one classifier both exporters (this and `hub_exporter`)
/// apply, so neither drops a refusal silently.
pub(crate) async fn send_classified(req: reqwest::RequestBuilder) -> PushOutcome {
    match req.send().await {
        Ok(resp) if resp.status().is_success() => PushOutcome::Accepted,
        Ok(resp) => PushOutcome::Refused(resp.status()),
        Err(e) => PushOutcome::Transport(e.without_url()),
    }
}

/// The log line for a push outcome: `None` for an acceptance. Names the
/// endpoint by its redacted origin only and never carries a token.
pub(crate) fn outcome_log_line(ingest_url: &str, outcome: &PushOutcome) -> Option<String> {
    let origin = redacted_origin(ingest_url);
    match outcome {
        PushOutcome::Accepted => None,
        PushOutcome::Refused(status) => Some(format!(
            "push to {origin} refused with HTTP {}",
            status.as_u16()
        )),
        PushOutcome::Transport(e) => Some(format!("push to {origin}: {e}")),
    }
}

/// A push outcome with its detail dropped: a refusal by its status, every
/// transport failure as one class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OutcomeClass {
    Accepted,
    Refused(u16),
    Transport,
}

impl OutcomeClass {
    fn of(outcome: &PushOutcome) -> Self {
        match outcome {
            PushOutcome::Accepted => Self::Accepted,
            PushOutcome::Refused(status) => Self::Refused(status.as_u16()),
            PushOutcome::Transport(_) => Self::Transport,
        }
    }
}

/// How long a persisting failure goes between its count lines.
pub(crate) const REPEAT_REPORT_EVERY: Duration = Duration::from_secs(300);

/// Bounded push-outcome logging. A change of [`OutcomeClass`] logs one line;
/// while one failure class persists, its repeats are counted and reported in
/// one line per [`REPEAT_REPORT_EVERY`]. A refusal on every tick therefore
/// costs a dozen lines an hour, not one per push.
pub(crate) struct OutcomeLog {
    last: OutcomeClass,
    /// Pushes of the `last` failure class since its last line.
    unreported: u64,
    reported_at: Instant,
}

impl OutcomeLog {
    pub(crate) fn new(now: Instant) -> Self {
        Self {
            last: OutcomeClass::Accepted,
            unreported: 0,
            reported_at: now,
        }
    }

    /// The line `outcome` warrants at `now`, if any. `failure_note` closes a
    /// failure line (what became of the batch).
    pub(crate) fn observe(
        &mut self,
        now: Instant,
        ingest_url: &str,
        outcome: &PushOutcome,
        failure_note: &str,
    ) -> Option<String> {
        let class = OutcomeClass::of(outcome);
        if class == self.last {
            if class == OutcomeClass::Accepted {
                return None;
            }
            self.unreported = self.unreported.saturating_add(1);
            if now.saturating_duration_since(self.reported_at) < REPEAT_REPORT_EVERY {
                return None;
            }
            let line = outcome_log_line(ingest_url, outcome).map(|line| {
                format!(
                    "{line}; {failure_note}; {} such pushes since the last report",
                    self.unreported
                )
            });
            self.unreported = 0;
            self.reported_at = now;
            return line;
        }
        let earlier = match self.unreported {
            0 => String::new(),
            n => format!(" (unlogged earlier failures: {n})"),
        };
        let line = match outcome_log_line(ingest_url, outcome) {
            Some(line) => format!("{line}; {failure_note}{earlier}"),
            None => format!(
                "push to {} accepted again{earlier}",
                redacted_origin(ingest_url)
            ),
        };
        self.last = class;
        self.unreported = 0;
        self.reported_at = now;
        Some(line)
    }
}

/// Non-blocking offer of a log. No-op when disabled or the queue is full.
pub fn offer_log(ts_ms: u64, level: &str, message: &str) {
    if let Some(tx) = SENDER.get() {
        let _ = tx.try_send(Entry::Log {
            ts_ms,
            level: level.to_string(),
            message: message.to_string(),
        });
    }
}

/// Non-blocking offer of a span.
pub fn offer_span(ts_ms: u64, name: &str, dur_us: u64, ok: bool) {
    if let Some(tx) = SENDER.get() {
        let _ = tx.try_send(Entry::Span {
            ts_ms,
            name: name.to_string(),
            dur_us,
            ok,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "server")]
    use std::sync::Arc;
    #[cfg(feature = "server")]
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn offer_without_enable_is_noop() {
        offer_log(0, "info", "ignored");
        offer_span(0, "noop", 0, true);
    }

    // ── redacted_origin — no credential reaches a log line ──────────────────

    #[test]
    fn redacted_origin_drops_userinfo_path_and_query() {
        assert_eq!(
            redacted_origin("https://admin:s3cr3t@hub.example.com:8443/v1/logs?token=t0k#f"),
            "https://hub.example.com:8443"
        );
        assert_eq!(
            redacted_origin(" https://user@hub.example.com/x "),
            "https://hub.example.com"
        );
        assert_eq!(
            redacted_origin("http://u:p@[::1]:9000/"),
            "http://[::1]:9000"
        );
    }

    #[test]
    fn redacted_origin_never_echoes_unparseable_input() {
        for raw in [
            "not a url s3cr3t",
            "",
            "https://u:s3cr3t@",
            "mailto:s3cr3t@x.example",
        ] {
            let out = redacted_origin(raw);
            assert!(!out.contains("s3cr3t"), "leaked {raw:?} as {out:?}");
        }
    }

    // ── url_allows_cleartext_token — the secrets-in-transit gate ────────────

    #[test]
    fn https_is_always_allowed() {
        assert!(url_allows_cleartext_token("https://parent.example.com"));
        assert!(url_allows_cleartext_token("https://127.0.0.1:9000"));
    }

    #[test]
    fn http_loopback_is_allowed() {
        assert!(url_allows_cleartext_token("http://localhost:9000"));
        assert!(url_allows_cleartext_token("http://127.0.0.1:9000"));
        assert!(url_allows_cleartext_token("http://[::1]:9000"));
    }

    #[test]
    fn http_non_loopback_is_refused() {
        assert!(!url_allows_cleartext_token("http://parent.example.com"));
        // A hostname that merely STARTS WITH "localhost" is a distinct host —
        // a naive prefix check would wrongly allow this.
        assert!(!url_allows_cleartext_token("http://localhost.evil.com"));
    }

    #[test]
    fn malformed_url_is_refused() {
        assert!(!url_allows_cleartext_token("not-a-url"));
        assert!(!url_allows_cleartext_token(""));
    }

    #[test]
    fn payload_shape_logs_and_spans() {
        let buf = vec![
            Entry::Log {
                ts_ms: 1700,
                level: "error".into(),
                message: "boom \"x\"".into(),
            },
            Entry::Span {
                ts_ms: 1700,
                name: "db.query".into(),
                dur_us: 5000,
                ok: true,
            },
        ];
        let body = build_payload(&buf);
        let v: serde_json::Value = serde_json::from_str(&body).expect("valid json");
        assert_eq!(v["logs"][0]["level"], "error");
        assert_eq!(v["logs"][0]["message"], "boom \"x\"");
        assert_eq!(v["spans"][0]["name"], "db.query");
        assert_eq!(v["spans"][0]["ok"], true);
        assert_eq!(v["spans"][0]["durUs"], 5000);
    }

    /// Verify that the `Flush` sentinel causes the batcher to drain its
    /// buffer and send the ack. This is the load-bearing seam for
    /// `flush_now`: the ack proves the buffered batch was processed before
    /// the pre-exit window expires.
    ///
    /// A flush failure must never withhold the ack.
    ///
    /// The ingest endpoint is a bare listener that accepts the flush POST's
    /// connection and closes it unread: the connect succeeds immediately on
    /// every host, so the POST still fails (a reset, never a response),
    /// exercising the "flush POST fails with a log warning" best-effort
    /// path. We send a Log first so the buf is non-empty, then confirm the
    /// ack still arrives. An unreachable port would instead measure the
    /// OS's own connection-refused timing, which is platform-dependent (on
    /// Windows a refused connect can take seconds of SYN retries) and would
    /// make this 500 ms bound flaky by host rather than by the code under
    /// test.
    #[allow(clippy::expect_used)] // test setup: a bind/local_addr failure is a test environment issue
    #[tokio::test]
    async fn flush_sentinel_acks_even_when_ingest_unreachable() {
        let (tx, rx) = mpsc::channel::<Entry>(16);
        // Pre-load a log entry into the channel (will land in the batcher's buf).
        tx.try_send(Entry::Log {
            ts_ms: 42,
            level: "info".into(),
            message: "pre-exit".into(),
        })
        .ok();
        // Send the Flush sentinel.
        let (ack_tx, ack_rx) = tokio::sync::oneshot::channel::<()>();
        tx.try_send(Entry::Flush(ack_tx)).ok();
        // Drop the sender so the batcher exits after the ack.
        drop(tx);

        // Accept-then-close: the flush POST connects at once, then the
        // connection resets before any response, on every host.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind an accept-then-close listener");
        let addr = listener.local_addr().expect("listener local addr");
        tokio::spawn(async move {
            if let Ok((socket, _)) = listener.accept().await {
                drop(socket);
            }
        });

        let url = format!("http://{addr}");
        tokio::spawn(batcher(
            rx,
            client(&url),
            Pipeline {
                ingest_url: url,
                token: None,
                interval_ms: 5000,
            },
        ));

        // The POST fails at once, so the ack arrives well inside 500 ms.
        let result = tokio::time::timeout(Duration::from_millis(500), ack_rx).await;
        assert!(result.is_ok(), "flush ack must arrive within 500 ms");
        assert!(result.unwrap().is_ok(), "ack oneshot must not be dropped");
    }

    // Prove the refusal: the exporter client does NOT follow a redirect, so the
    // ingest token is never re-sent to a redirect target. A parent that answers
    // the push with a 307 to a *different* (leak) endpoint must not cause the
    // `x-ipe-ingest-token` header to cross to that endpoint — reqwest's DEFAULT
    // would follow up to 10 hops and re-send it. This asserts `Policy::none()`
    // prevents that: the leak endpoint records zero requests.
    #[tokio::test]
    async fn exporter_does_not_follow_redirect_and_never_leaks_ingest_token() {
        use axum::extract::State;
        use axum::response::IntoResponse;
        use axum::{Router, routing::any};
        use std::sync::{Arc, Mutex};

        // The leak target: any request here is a token-leak failure.
        let leak_hits: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        async fn leak(State(hits): State<Arc<Mutex<Vec<String>>>>, req: axum::extract::Request) {
            let tok = req
                .headers()
                .get("x-ipe-ingest-token")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("")
                .to_string();
            if let Ok(mut g) = hits.lock() {
                g.push(tok);
            }
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

        // The parent: answers every push with a 307 redirect to the leak target.
        let leak_base = format!("http://127.0.0.1:{leak_port}");
        async fn redirect(State(loc): State<String>) -> axum::response::Response {
            (
                axum::http::StatusCode::TEMPORARY_REDIRECT,
                [(axum::http::header::LOCATION, format!("{loc}/leak"))],
                "moved",
            )
                .into_response()
        }
        let parent_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind parent");
        let parent_port = parent_listener.local_addr().expect("addr").port();
        let parent_app = Router::new()
            .fallback(any(redirect))
            .with_state(leak_base.clone());
        tokio::spawn(async move {
            let _ = axum::serve(parent_listener, parent_app).await;
        });

        let ingest_url = format!("http://127.0.0.1:{parent_port}/_ipe/observability/ingest");
        let client = client(&ingest_url);
        let buf = vec![Entry::Log {
            ts_ms: 1,
            level: "info".into(),
            message: "hi".into(),
        }];

        flush(
            &client,
            &ingest_url,
            Some("super-secret-ingest-token"),
            &buf,
            &mut OutcomeLog::new(Instant::now()),
        )
        .await;

        let hits = leak_hits.lock().map(|g| g.clone()).unwrap_or_default();
        assert!(
            hits.is_empty(),
            "exporter followed the redirect and leaked the ingest token: {hits:?}"
        );
    }

    /// `flush_now` is a no-op when the exporter is disabled (SENDER not set).
    #[tokio::test]
    async fn flush_now_noop_when_disabled() {
        // flush_now on a fresh (not-enabled) state must return quickly.
        let deadline = tokio::time::timeout(Duration::from_millis(200), flush_now()).await;
        assert!(
            deadline.is_ok(),
            "flush_now must not block when exporter is off"
        );
    }

    /// The shutdown flush waits out a POST whose ingest has not yet accepted.
    ///
    /// The ingest accepts only after 1.5 s, inside the deadline the connect
    /// timeout derives (2.5 s) and far past a fixed 250 ms cap. The listener
    /// records the batch before it answers and the batcher acks only after the
    /// answer, so the record is set when the drain returns exactly when the
    /// drain waited for the ack.
    #[allow(clippy::expect_used)] // test setup: a bind/local_addr failure is a test environment issue
    #[tokio::test]
    async fn flush_waits_out_a_connect_in_flight() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        const MARKER: &[u8] = b"final-batch";
        const READ_CAP: usize = 64 * 1024;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind a late-accepting ingest");
        let addr = listener.local_addr().expect("listener local addr");
        let received = Arc::new(AtomicBool::new(false));
        let seen = Arc::clone(&received);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(1_500)).await;
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let mut request = Vec::new();
            let mut chunk = [0u8; 4096];
            let holds_marker = |r: &[u8]| r.windows(MARKER.len()).any(|w| w == MARKER);
            while request.len() < READ_CAP && !holds_marker(&request) {
                match socket.read(&mut chunk).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => request.extend_from_slice(chunk.get(..n).unwrap_or_default()),
                }
            }
            seen.store(holds_marker(&request), Ordering::SeqCst);
            let _ = socket
                .write_all(b"HTTP/1.1 204 No Content\r\nconnection: close\r\n\r\n")
                .await;
        });

        let url = format!("http://{addr}");
        let (tx, rx) = mpsc::channel::<Entry>(4);
        tx.try_send(Entry::Log {
            ts_ms: 1,
            level: "info".into(),
            message: "final-batch".into(),
        })
        .expect("queue the final batch");
        tokio::spawn(batcher(
            rx,
            client(&url),
            Pipeline {
                ingest_url: url,
                token: None,
                interval_ms: 60_000,
            },
        ));

        tokio::time::timeout(
            Duration::from_secs(10),
            drain_before_exit(Some(&tx), Entry::Flush, FLUSH_DEADLINE),
        )
        .await
        .expect("the drain is bounded by its deadline");
        assert!(
            received.load(Ordering::SeqCst),
            "the shutdown flush returned before the final batch reached the ingest"
        );
    }

    /// A batcher that never acks holds the drain for exactly its deadline.
    #[tokio::test(start_paused = true)]
    async fn drain_gives_up_at_its_deadline() {
        let (tx, _rx) = mpsc::channel::<Entry>(4);
        let start = tokio::time::Instant::now();
        drain_before_exit(Some(&tx), Entry::Flush, FLUSH_DEADLINE).await;
        let waited = start.elapsed();
        assert!(waited >= FLUSH_DEADLINE.0, "gave up early: {waited:?}");
        assert!(
            waited < FLUSH_DEADLINE.0 + Duration::from_millis(10),
            "waited past the deadline: {waited:?}"
        );
        assert!(FLUSH_DEADLINE.0 > Duration::from_millis(CONNECT_TIMEOUT_MS));
        assert!(FLUSH_DEADLINE.0 <= Duration::from_millis(FLUSH_DEADLINE_CEILING_MS));
    }

    fn client(url: &str) -> reqwest::Client {
        exporter_client(url).expect("TLS backend")
    }

    fn one_log() -> Vec<Entry> {
        vec![Entry::Log {
            ts_ms: 1,
            level: "info".into(),
            message: "hi".into(),
        }]
    }

    /// A loopback ingest gated by the console's own receiver decision with
    /// `want` configured and no dev surface (a Release child under any
    /// posture). Returns its port, its ingest URL and its count of admitted
    /// pushes.
    #[cfg(feature = "server")]
    async fn release_ingest(want: String) -> (u16, String, Arc<AtomicUsize>) {
        use axum::extract::State;
        use axum::response::IntoResponse;
        use axum::{Router, routing::any};
        async fn gate(
            State((want, accepted)): State<(String, Arc<AtomicUsize>)>,
            headers: axum::http::HeaderMap,
        ) -> axum::response::Response {
            match super::super::console::ingest_decision(&headers, Some(&want), None) {
                Some(refusal) => refusal,
                None => {
                    accepted.fetch_add(1, Ordering::SeqCst);
                    axum::http::StatusCode::NO_CONTENT.into_response()
                }
            }
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ingest");
        let port = listener.local_addr().expect("addr").port();
        let accepted = Arc::new(AtomicUsize::new(0));
        let app = Router::new()
            .fallback(any(gate))
            .with_state((want, accepted.clone()));
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (
            port,
            format!("http://127.0.0.1:{port}/_ipe/observability/ingest"),
            accepted,
        )
    }

    // The console pipeline carries the token `spawn_console` minted, so the
    // child's Release ingest admits its batches.
    #[cfg(feature = "server")]
    #[tokio::test]
    async fn console_pipeline_pushes_with_the_minted_token() {
        let token = IngestToken::mint().expect("entropy");
        let (port, url, accepted) = release_ingest(token.expose().to_string()).await;
        let pipeline = Pipeline::to_console(port, token);
        assert_eq!(pipeline.ingest_url, url);
        let (tx, rx) = mpsc::channel::<Entry>(4);
        tx.try_send(Entry::Log {
            ts_ms: 1,
            level: "info".into(),
            message: "hi".into(),
        })
        .expect("queue");
        let (ack_tx, ack_rx) = tokio::sync::oneshot::channel::<()>();
        tx.try_send(Entry::Flush(ack_tx)).expect("queue");
        tokio::spawn(batcher(rx, client(&url), pipeline));
        tokio::time::timeout(Duration::from_secs(5), ack_rx)
            .await
            .expect("flush ack in time")
            .expect("ack sent");
        assert_eq!(accepted.load(Ordering::SeqCst), 1);
    }

    // The push carries the token in `x-ipe-ingest-token`, and the Release
    // receiver admits it.
    #[cfg(feature = "server")]
    #[tokio::test]
    async fn push_with_the_minted_token_is_accepted_by_a_release_ingest() {
        let token = IngestToken::mint().expect("entropy");
        let (_, url, _) = release_ingest(token.expose().to_string()).await;
        let outcome = send_batch(&client(&url), &url, Some(token.expose()), &one_log()).await;
        assert!(
            matches!(outcome, PushOutcome::Accepted),
            "{:?}",
            outcome_log_line(&url, &outcome)
        );
        assert!(outcome_log_line(&url, &outcome).is_none());
    }

    // A missing or wrong token is a 401 the exporter surfaces as a log line,
    // never a silent drop; the line carries neither token.
    #[cfg(feature = "server")]
    #[tokio::test]
    async fn refused_push_is_logged_without_any_token() {
        let token = IngestToken::mint().expect("entropy");
        let wrong = IngestToken::mint().expect("entropy");
        let (_, url, _) = release_ingest(token.expose().to_string()).await;
        for sent in [None, Some(wrong.expose())] {
            let outcome = send_batch(&client(&url), &url, sent, &one_log()).await;
            assert!(
                matches!(outcome, PushOutcome::Refused(s) if s == reqwest::StatusCode::UNAUTHORIZED),
                "sent token: {}",
                sent.is_some()
            );
            let line = outcome_log_line(&url, &outcome).expect("a refusal is logged");
            assert!(line.contains("HTTP 401"), "{line}");
            assert!(!line.contains(token.expose()), "{line}");
            assert!(!line.contains(wrong.expose()), "{line}");
        }
    }

    // A transport failure is logged too, and neither the header token nor a
    // token placed in the URL reaches the line.
    #[tokio::test]
    async fn transport_failure_is_logged_without_the_token() {
        let token = IngestToken::mint().expect("entropy");
        let closed = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = closed.local_addr().expect("addr").port();
        drop(closed);
        let url = format!(
            "http://127.0.0.1:{port}/_ipe/observability/ingest?t={}",
            token.expose()
        );
        let outcome = send_batch(&client(&url), &url, Some(token.expose()), &one_log()).await;
        assert!(matches!(outcome, PushOutcome::Transport(_)));
        let line = outcome_log_line(&url, &outcome).expect("a transport failure is logged");
        assert!(!line.contains(token.expose()), "{line}");
    }
    // ── ExporterEnv — the one list of exporter env names ────────────────────

    /// The non-test part of an exporter source file.
    fn production(src: &'static str) -> &'static str {
        src.split("#[cfg(test)]").next().unwrap_or(src)
    }

    /// Every `"IPE_…"` string literal in `src`.
    fn ipe_literals(src: &str) -> Vec<String> {
        src.split("\"IPE_")
            .skip(1)
            .map(|rest| {
                let name: String = rest
                    .chars()
                    .take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == '_')
                    .collect();
                format!("IPE_{name}")
            })
            .collect()
    }

    // Each exporter reads env only through `ExporterEnv`, and names no env
    // var outside it, so `ExporterEnv::egress()` covers every egress reader.
    #[test]
    fn exporters_read_env_only_through_exporter_env() {
        let push = production(include_str!("push_exporter.rs"));
        let hub = production(include_str!("hub_exporter.rs"));
        assert_eq!(push.matches("read_env_var(").count(), 1);
        assert_eq!(hub.matches("read_env_var(").count(), 0);
        assert_eq!(hub.matches("std::env::var").count(), 0);
        assert_eq!(push.matches("std::env::var").count(), 0);
        let known: Vec<&str> = ExporterEnv::ALL.iter().map(|e| e.name()).collect();
        for src in [push, hub] {
            for lit in ipe_literals(src) {
                assert!(
                    known.contains(&lit.as_str()),
                    "{lit} is not an ExporterEnv name"
                );
            }
        }
    }

    #[test]
    fn exporter_ceilings_honour_the_shared_contract() {
        for env in [
            ExporterEnv::PushInterval,
            ExporterEnv::PushBuffer,
            ExporterEnv::HubInterval,
        ] {
            assert_eq!(env.role(), ExporterEnvRole::Tuning);
            crate::system::assert_env_ceiling_contract(env.ceiling(2000, "decimal count"));
        }
    }

    #[test]
    fn a_push_buffer_past_the_tokio_permit_limit_is_refused() {
        let ceiling = ExporterEnv::PushBuffer.ceiling(DEFAULT_QUEUE_CAP as u64, "decimal count");
        let limit = tokio::sync::Semaphore::MAX_PERMITS as u64;
        assert_eq!(ceiling.parse(Ok(limit.to_string())), Ok(limit));
        assert!(
            ceiling
                .parse(Ok((limit + 1).to_string()))
                .is_err_and(|r| r.defect() == crate::system::CeilingDefect::TooLarge),
            "a queue depth tokio cannot hold must be refused, not reach mpsc::channel"
        );
    }

    #[test]
    fn egress_names_are_every_upstream_destination_and_its_credential() {
        let egress: Vec<&str> = ExporterEnv::egress().collect();
        assert_eq!(
            egress,
            ["IPE_PARENT_URL", "IPE_CONSOLE_HUB", "IPE_CONSOLE_HUB_TOKEN"]
        );
        assert!(!egress.contains(&ExporterEnv::IngestToken.name()));
    }

    // ── proxy_route — a loopback hop never goes through a proxy ─────────────

    #[test]
    fn loopback_targets_bypass_any_proxy() {
        for url in [
            "http://127.0.0.1:9000/_ipe/observability/ingest",
            "http://localhost:9000",
            "http://[::1]:9000",
            "https://127.0.0.1:9000",
            "not a url",
        ] {
            assert_eq!(proxy_route(url), ProxyRoute::Direct, "{url}");
        }
        for url in ["https://hub.example.com", "https://localhost.evil.com"] {
            assert_eq!(proxy_route(url), ProxyRoute::System, "{url}");
        }
    }

    // ── OutcomeLog — bounded logging of a persisting failure ────────────────

    const URL: &str = "http://127.0.0.1:9/_ipe/observability/ingest";

    fn refused(code: u16) -> PushOutcome {
        PushOutcome::Refused(reqwest::StatusCode::from_u16(code).expect("status"))
    }

    async fn transport() -> PushOutcome {
        let closed = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = closed.local_addr().expect("addr").port();
        drop(closed);
        let url = format!("http://127.0.0.1:{port}/");
        send_classified(client(&url).post(&url)).await
    }

    #[test]
    fn a_persisting_refusal_logs_once_then_a_bounded_count() {
        let t0 = Instant::now();
        let mut log = OutcomeLog::new(t0);
        assert_eq!(
            log.observe(t0, URL, &PushOutcome::Accepted, "dropped"),
            None
        );
        let first = log
            .observe(t0, URL, &refused(401), "dropped")
            .expect("first refusal");
        assert!(first.contains("HTTP 401"), "{first}");
        let tick = Duration::from_secs(2);
        let mut lines = 0;
        let mut now = t0;
        // One push every 2 s for an hour.
        for _ in 0..1800 {
            now += tick;
            if let Some(line) = log.observe(now, URL, &refused(401), "dropped") {
                assert!(line.contains("such pushes since the last report"), "{line}");
                lines += 1;
            }
        }
        let per_hour = Duration::from_secs(3600).as_secs() / REPEAT_REPORT_EVERY.as_secs();
        assert!(lines <= per_hour, "{lines} lines in an hour");
        assert!(lines >= 1);
    }

    #[test]
    fn recovery_and_a_new_status_each_log_once() {
        let t0 = Instant::now();
        let mut log = OutcomeLog::new(t0);
        assert!(log.observe(t0, URL, &refused(401), "dropped").is_some());
        assert!(log.observe(t0, URL, &refused(401), "dropped").is_none());
        let other = log
            .observe(t0, URL, &refused(503), "dropped")
            .expect("new status");
        assert!(other.contains("HTTP 503"), "{other}");
        let back = log
            .observe(t0, URL, &PushOutcome::Accepted, "dropped")
            .expect("recovery");
        assert!(back.contains("accepted again"), "{back}");
        assert!(
            log.observe(t0, URL, &PushOutcome::Accepted, "dropped")
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_transport_failure_after_a_refusal_logs() {
        let t0 = Instant::now();
        let mut log = OutcomeLog::new(t0);
        assert!(log.observe(t0, URL, &refused(401), "dropped").is_some());
        assert!(log.observe(t0, URL, &refused(401), "dropped").is_none());
        let line = log
            .observe(t0, URL, &transport().await, "dropped")
            .expect("new class");
        assert!(line.contains("(unlogged earlier failures: 1)"), "{line}");
        assert!(
            log.observe(t0, URL, &transport().await, "dropped")
                .is_none()
        );
    }
}
