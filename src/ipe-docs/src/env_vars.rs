/// A documented `IPE_*` environment variable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvVar {
    /// The environment variable name, e.g. `IPE_LOG_LEVEL`.
    pub name: &'static str,
    /// Default value as a human-readable string, e.g. `"info"` or `"unset"`.
    pub default: &'static str,
    /// One-line description of what the variable controls.
    pub purpose: &'static str,
    /// The runtime subsystem that reads this variable.
    pub subsystem: Subsystem,
    /// Operational classification.
    pub class: Class,
}

/// Operational classification of an environment variable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Class {
    /// A runtime knob that changes behaviour or performance. Safe to expose in
    /// documentation; the default is always the conservative choice.
    Tunable,
    /// A secret credential — token, key, or password. Provide via a secret
    /// manager; never commit or log the value.
    Secret,
    /// A security-boundary switch. Loosening widens the trust boundary;
    /// document the trade-off before changing from the default.
    SecurityTunable,
}

impl Class {
    /// Short label used in the generated reference table.
    #[must_use]
    pub const fn badge(self) -> &'static str {
        match self {
            Self::Tunable => "Tunable",
            Self::Secret => "Secret",
            Self::SecurityTunable => "SecurityTunable",
        }
    }
}

/// The subsystem that reads the variable — used for grouping in the reference.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Subsystem {
    /// `ipe dev build` / static-build pipeline.
    Build,
    /// Type solver and compiler internals.
    Compiler,
    /// Console / developer-console proxy and auth.
    Console,
    /// CSV serialisation.
    Csv,
    /// Database connection pools.
    Db,
    /// Email sending.
    Email,
    /// File I/O limits.
    File,
    /// FFI / Rust-crate binding sandbox.
    Ffi,
    /// Outbound HTTP client.
    Http,
    /// Observability: logging, tracing, telemetry export.
    Observability,
    /// Regex matching input ceiling.
    Regex,
    /// Compression (gzip / zstd decompression).
    Compression,
    /// Config-file loading.
    Config,
    /// Runtime embedding and home directory.
    Runtime,
    /// Web server — session, CSRF, routing, static assets.
    Web,
    /// WebSocket (client and server).
    Ws,
    /// `ipe doc` / documentation server.
    Doc,
    /// UI layout render — developer overlays and diagnostics.
    Ui,
}

impl Subsystem {
    /// Human-readable display name for the generated reference.
    #[must_use]
    pub const fn display(self) -> &'static str {
        match self {
            Self::Build => "Build",
            Self::Compiler => "Compiler",
            Self::Console => "Console",
            Self::Csv => "CSV",
            Self::Db => "Database",
            Self::Doc => "Doc",
            Self::Email => "Email",
            Self::Ffi => "FFI",
            Self::File => "File",
            Self::Http => "HTTP client",
            Self::Observability => "Observability",
            Self::Regex => "Regex",
            Self::Compression => "Compression",
            Self::Config => "Config",
            Self::Runtime => "Runtime",
            Self::Ui => "UI render",
            Self::Web => "Web server",
            Self::Ws => "WebSocket",
        }
    }
}

/// The complete annotated table of `IPE_*` environment variables.
///
/// Variables are listed in alphabetical order within each subsystem. The drift
/// gate test asserts that every `IPE_*` literal read in the codebase appears
/// here; the generator renders this table into `docs/reference/env.md`.
///
/// Excluded from this table:
/// - Test-only variables (`IPE_TEST_*`, `IPE_BLESS`, `IPE_RUN_WITH_TEST_VAR`,
///   `IPE_LOAD_ENV_PROBE_VAR`, `IPE_HTTP_TEST_URL`, `IPE_ORACLE_SHARED_TARGET`,
///   `IPE_DEBUG_TODO_SUBPROCESS`).
/// - Build-time baked vars set by `option_env!` only
///   (`IPE_BUILD_COMMIT`, `IPE_BUILD_AT`, `IPE_VERSION`) — documented here for
///   operator awareness but never read via `std::env::var` at runtime.
pub static ENV_VARS: &[EnvVar] = &[
    // ── Build ─────────────────────────────────────────────────────────────────
    EnvVar {
        name: "IPE_ALLOC",
        default: "unset (system allocator)",
        purpose: "Select the memory allocator: `mimalloc`, `jemalloc`, or `system`. \
                  Mirrors `--allocator`; env wins over `package.ipe [rust] allocator`.",
        subsystem: Subsystem::Build,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_BIN",
        default: "unset",
        purpose: "Path to the `ipe` binary used by the build driver when invoking itself \
                  recursively. Set automatically by the wrapper; operator override is rarely needed.",
        subsystem: Subsystem::Build,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_BUILD_AT",
        default: "unknown",
        purpose: "Build timestamp baked in by CI (`option_env!`). Surfaced at \
                  `GET /_ipe/buildinfo`. Not read at runtime via `env::var`.",
        subsystem: Subsystem::Build,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_BUILD_CACHE",
        default: "on",
        purpose: "Set to `0`, `off`, or `false` to disable the incremental build cache. \
                  Default is on; the cache directory is `<out>/.ipe-cache/<per-user salt>` unless \
                  `IPE_BUILD_CACHE_DIR` is set.",
        subsystem: Subsystem::Build,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_BUILD_CACHE_DIR",
        default: "unset (<out>/.ipe-cache/<per-user salt>)",
        purpose: "Explicit path for the incremental build cache directory. Takes effect \
                  only when the cache is enabled (`IPE_BUILD_CACHE` not `off`).",
        subsystem: Subsystem::Build,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_BUILD_COMMIT",
        default: "dev",
        purpose: "Git commit SHA baked in by CI (`option_env!`). Surfaced at \
                  `GET /_ipe/buildinfo`. Not read at runtime via `env::var`.",
        subsystem: Subsystem::Build,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_CFREE",
        default: "unset (false)",
        purpose: "Set to `1` or `true` to build without linking any C code. Mirrors \
                  `--cfree`; incompatible with allocators that require C (e.g. mimalloc).",
        subsystem: Subsystem::Build,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_EMBED_APP",
        default: "unset",
        purpose: "Path to the compiled app binary embedded into a wrapper binary. Set \
                  by the build driver; not intended for operator use.",
        subsystem: Subsystem::Build,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_EMBED_PROFILE",
        default: "unset",
        purpose: "Build profile string embedded into a wrapper binary alongside \
                  `IPE_EMBED_APP`. Set by the build driver.",
        subsystem: Subsystem::Build,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_EMIT_PACKAGE_NAME",
        default: "unset (`ipe-app`)",
        purpose: "Overrides the emitted crate's package name for a single-file build \
                  (validated through the package-name sanitizer). Set by the coverage \
                  probe to give each emitted build a unique crate identity; not intended \
                  for operator use.",
        subsystem: Subsystem::Build,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_INDEX_DIR",
        default: "unset ($XDG_CACHE_HOME/ipe/index, then $HOME/.cache/ipe/index)",
        purpose: "Override the root directory of the package-index checkout used by \
                  `ipe add` / `ipe install`. Points to a local mirror of the \
                  ipe-registry index. Useful for air-gapped environments. Must be an \
                  absolute path.",
        subsystem: Subsystem::Build,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_INSTALL_DIR",
        default: "$HOME/.local/bin",
        purpose: "Directory `install.sh` installs the `ipe` binary into.",
        subsystem: Subsystem::Build,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_PUBLISH_SIGNING_KEY",
        default: "unset",
        purpose: "Path to the SSH private-key file `ipe package publish` signs the index \
                  commit with (its public half must be registered as a signing key on your \
                  GitHub account). Overrides the key `ipe login --signing-key` stored; when \
                  set but not a readable file, publish refuses rather than fall back. \
                  Unset with no stored key, publish refuses.",
        subsystem: Subsystem::Build,
        class: Class::Secret,
    },
    EnvVar {
        name: "IPE_REGISTRY_URL",
        default: "https://arthurmaciel.github.io/ipe-registry",
        purpose: "Base URL of the registry's static Pages read API (per-package JSON \
                  mirror + advisory index). `ipe add` and `ipe package audit` read it as \
                  a fast-path, falling back to the `IPE_INDEX_DIR` git checkout on any \
                  network failure or malformed response. Set to empty to disable the HTTP \
                  fast-path (air-gapped): resolution then reads the checkout directly. \
                  The pinned rev + sha256 stay the trust root either way.",
        subsystem: Subsystem::Build,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_STATIC",
        default: "unset (dynamic build)",
        purpose: "Set to `1` or `true` to request a fully-static (musl) binary. Mirrors \
                  `--static`; env wins over `package.ipe [rust] static`.",
        subsystem: Subsystem::Build,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_TARGET",
        default: "unset (native)",
        purpose: "Cross-compilation target triple, e.g. `wasm32-unknown-unknown` or \
                  `aarch64-unknown-linux-musl`. Set to `wasm` as a shorthand for \
                  `wasm32-unknown-unknown`.",
        subsystem: Subsystem::Build,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_VERSION",
        default: "dev",
        purpose: "Compiler version baked in by CI (`option_env!`). Surfaced at \
                  `GET /_ipe/buildinfo` and used to locate the cached console binary. \
                  Not read at runtime via `env::var`.",
        subsystem: Subsystem::Build,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_WATCH_BLUEGREEN",
        default: "unset (on)",
        purpose: "Dev-loop blue-green swaps are ON by default: `ipe dev watch` holds the \
                  port behind a proxy and cuts over to the rebuilt binary without \
                  dropping the browser connection. Set to `0`/empty to force it off, \
                  or any other value to force it on; `IPE_WATCH_NO_BLUEGREEN` overrides \
                  either way. Dev-only; no effect on a release build.",
        subsystem: Subsystem::Build,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_WATCH_HOT_APPEARANCE",
        default: "unset (on for `ipe dev watch`)",
        purpose: "Explicit control over dev-loop appearance hot-swap, which is ON \
                  by default for `ipe dev watch`: an edit to a style literal is pushed \
                  to the browser without a rebuild. Set to `0` or empty to force it \
                  off; any other value forces it on. `IPE_WATCH_NO_HOT_APPEARANCE` \
                  takes precedence. Dev-only; no effect on a release build.",
        subsystem: Subsystem::Build,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_WATCH_HOT_TOKEN",
        default: "unset",
        purpose: "Per-process control token for the dev-only appearance-hot-swap \
                  endpoint. `ipe dev watch` sets it and sends it as `X-Ipe-Hot-Token`; a \
                  request whose token does not constant-time-match is refused. \
                  Dev-only; the endpoint is never mounted in a release build.",
        subsystem: Subsystem::Build,
        class: Class::Secret,
    },
    EnvVar {
        name: "IPE_WATCH_NO_BLUEGREEN",
        default: "unset (blue-green on)",
        purpose: "Set to any non-empty value other than `0` to opt OUT of dev-loop \
                  blue-green swaps and restore the direct-bind, \
                  kill-old-then-spawn-new `ipe dev watch` path (a rebuild briefly drops \
                  the browser connection). Overrides `IPE_WATCH_BLUEGREEN`. Dev-only; \
                  no effect on a release build.",
        subsystem: Subsystem::Build,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_WATCH_NO_HOT_APPEARANCE",
        default: "unset (hot-swap on)",
        purpose: "Set to any non-empty value other than `0` to opt OUT of dev-loop \
                  appearance hot-swap: `ipe dev watch` normally hot-swaps a style-literal \
                  edit into the running app without a rebuild. This restores the plain \
                  direct-literal emit, so an appearance edit triggers a full recompile. \
                  Dev-only; no effect on `ipe dev build` or a release build.",
        subsystem: Subsystem::Build,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_WATCH_NO_INCREMENTAL",
        default: "unset (incremental on)",
        purpose: "Set to any non-empty value other than `0` to opt OUT of the \
                  dev-loop incremental rebuild path: `ipe dev watch` normally builds the \
                  emitted app with `CARGO_INCREMENTAL=1` and no rustc wrapper (so a \
                  machine-level sccache config cannot force non-incremental), which \
                  speeds the warm view/update-body edit loop and is \
                  behaviour-identical. This restores the machine's normal build \
                  configuration for the watch rebuild. Dev-only; no effect on \
                  `ipe dev build` or `ipe release build`.",
        subsystem: Subsystem::Build,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_WATCH_TIMING",
        default: "unset (off)",
        purpose: "Set to `1` or `true` to print a per-phase `ipe dev watch` rebuild \
                  breakdown (emit, cargo, restart, reconnect) to stderr. Dev-loop \
                  instrumentation; has no effect outside `ipe dev watch`.",
        subsystem: Subsystem::Build,
        class: Class::Tunable,
    },
    // ── Console ───────────────────────────────────────────────────────────────
    EnvVar {
        name: "IPE_ADMIN_TOKEN",
        default: "unset",
        purpose: "Admin token (`Bearer`, or the `Basic` password) granting access to the \
                  embedded developer console and `/_ipe/metrics` in production or under \
                  `IPE_CONSOLE_AUTH=token`. Provide via your secret manager; never commit. \
                  Falls back to the in-code `Console.adminToken`, then `IPE_CONSOLE_TOKEN`. \
                  A non-UTF-8 value refuses every admin request and keeps the console \
                  unmounted in production.",
        subsystem: Subsystem::Console,
        class: Class::Secret,
    },
    EnvVar {
        name: "IPE_CONSOLE_AUTH",
        default: "unset (token; open only in a dev build on loopback)",
        purpose: "Console authentication mode: `token` (admin-token gate, enforced in \
                  every posture, dev included), `off` (console disabled), `app` (app \
                  callback; mounted but answers 501 on the Rust runtime). The posture \
                  picks the default only when the variable is unset or blank: a binary \
                  from `ipe dev build`, `ipe dev run`, `ipe test` or `ipe dev watch` in development \
                  posture bound to loopback defaults open; every other binary, including \
                  every `ipe release` artifact, and every exposed bind default to \
                  `token`, so the console stays closed until a credential is set. Any other \
                  value (including a non-UTF-8 one) disables the console. The effective \
                  posture, mode, and source are logged once at startup \
                  (`[ipe.console] auth posture=… mode=… source=env|env-invalid|posture-default`); \
                  no token is ever logged.",
        subsystem: Subsystem::Console,
        class: Class::SecurityTunable,
    },
    EnvVar {
        name: "IPE_CONSOLE_BATCH_INTERVAL_MS",
        default: "2000",
        purpose: "Flush cadence (ms) for telemetry batches shipped to the Hub. Reduce \
                  for lower latency at the cost of more HTTP round-trips.",
        subsystem: Subsystem::Console,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_CONSOLE_BIN",
        default: "unset (~/.cache/ipe/rust-console/<version>/ipe-console)",
        purpose: "Explicit path to the `ipe-console` binary. Overrides the default \
                  cache location resolved from `IPE_VERSION`.",
        subsystem: Subsystem::Console,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_CONSOLE_DB_PATH",
        default: "unset (per-process temp file)",
        purpose: "Path to the SQLite database the console uses to store telemetry \
                  (logs, spans). Set automatically when embedding the console; \
                  operator override selects a persistent path.",
        subsystem: Subsystem::Console,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_CONSOLE_EMBED",
        default: "unset (on in development)",
        purpose: "Set to `off`, `0`, or `false` to disable the automatic embedded \
                  developer console. The console is never embedded in a sub-app \
                  (sub-app detection is automatic).",
        subsystem: Subsystem::Console,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_CONSOLE_HUB",
        default: "unset",
        purpose: "Base URL of a remote Ipê Hub OTLP collector. When set, the console \
                  ships telemetry there. Leave unset unless you operate a Hub.",
        subsystem: Subsystem::Console,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_CONSOLE_HUB_DB",
        default: "unset",
        purpose: "SQLite path the console child reads as its Hub data source. Set \
                  automatically by the console proxy when wiring the child; not for \
                  operator use.",
        subsystem: Subsystem::Console,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_CONSOLE_HUB_TOKEN",
        default: "unset",
        purpose: "Bearer token sent to the Hub OTLP collector. Must be at least 32 \
                  bytes; shorter tokens are refused. Provide via your secret manager.",
        subsystem: Subsystem::Console,
        class: Class::Secret,
    },
    EnvVar {
        name: "IPE_CONSOLE_TOKEN",
        default: "unset",
        purpose: "Deprecated alias for `IPE_ADMIN_TOKEN`. Prefer `IPE_ADMIN_TOKEN`. \
                  Provide via your secret manager; never commit.",
        subsystem: Subsystem::Console,
        class: Class::Secret,
    },
    EnvVar {
        name: "IPE_CONSOLE_URL",
        default: "unset (auto-detected sub-path)",
        purpose: "Explicit URL at which the developer console is reachable. Overrides \
                  the auto-detected `/_ipe/console` path for proxied deployments.",
        subsystem: Subsystem::Console,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_DEV_BANNER",
        default: "unset (on in development)",
        purpose: "Set to `off` or `0` to suppress the development-mode banner injected \
                  into HTML responses. The banner is never shown in production.",
        subsystem: Subsystem::Console,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_INGEST_TOKEN",
        default: "unset",
        purpose: "Bearer token the parent ingest gate checks on `X-Ipê-Ingest-Token`. \
                  Required when a sub-app pushes telemetry to a parent app's \
                  `/_ipe/ingest` endpoint. Provide via your secret manager.",
        subsystem: Subsystem::Console,
        class: Class::Secret,
    },
    EnvVar {
        name: "IPE_METRICS_TOKEN",
        default: "unset",
        purpose: "Metrics-scrape token (`Bearer`, or the `Basic` password) authorizing \
                  `/_ipe/metrics` only, never the console; the admin token is accepted \
                  there too. Falls back to the in-code `Console.metricsToken`. A non-UTF-8 \
                  value refuses every metrics-token request. Provide via your secret \
                  manager; never commit.",
        subsystem: Subsystem::Console,
        class: Class::Secret,
    },
    // ── Compiler ──────────────────────────────────────────────────────────────
    EnvVar {
        name: "IPE_EXHAUST_BUDGET",
        default: "2000000",
        purpose: "Maximum work units the pattern-match exhaustiveness pass spends on a single \
                  `case` before giving up and emitting a budget-exceeded error. Set to `0` for \
                  no limit (escape hatch for a `case` with very many independent or-patterns). \
                  Raise when the compiler reports an exhaustiveness budget-exceeded diagnostic.",
        subsystem: Subsystem::Compiler,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_SOLVER_BUDGET",
        default: "5000000",
        purpose: "Maximum unification steps the type solver takes before giving up and \
                  emitting a budget-exceeded error. Set to `0` for no limit (escape hatch \
                  for programs with very large type graphs). Raise when the compiler \
                  reports a budget-exceeded diagnostic.",
        subsystem: Subsystem::Compiler,
        class: Class::Tunable,
    },
    // ── Compression ───────────────────────────────────────────────────────────
    EnvVar {
        name: "IPE_DECOMPRESS_MAX_BYTES",
        default: "268435456 (256 MiB)",
        purpose: "Maximum number of bytes that may be produced by a single decompression \
                  operation. Prevents zip-bomb / decompression-bomb exhaustion of memory.",
        subsystem: Subsystem::Compression,
        class: Class::Tunable,
    },
    // ── Config ────────────────────────────────────────────────────────────────
    EnvVar {
        name: "IPE_CONFIG_MAX_BYTES",
        default: "16777216 (16 MiB)",
        purpose: "Maximum size (bytes) of a config file loaded via `Config.load*`. \
                  Prevents memory exhaustion from unexpectedly large config files.",
        subsystem: Subsystem::Config,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_YAML_MAX_BYTES",
        default: "16777216 (16 MiB)",
        purpose: "Maximum YAML source size (bytes) that `Config.loadYaml` will parse. \
                  A separate ceiling from `IPE_CONFIG_MAX_BYTES`.",
        subsystem: Subsystem::Config,
        class: Class::Tunable,
    },
    // ── CSV ───────────────────────────────────────────────────────────────────
    EnvVar {
        name: "IPE_CSV_MAX_BYTES",
        default: "536870912 (512 MiB)",
        purpose: "Maximum total decoded field bytes parsed from a single CSV input. \
                  Bounds heap use when rows fit the row cap but carry oversized fields.",
        subsystem: Subsystem::Csv,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_CSV_MAX_ROWS",
        default: "10000000 (10 M)",
        purpose: "Maximum rows parsed from a single CSV input. Prevents OOM from \
                  unbounded CSV streams.",
        subsystem: Subsystem::Csv,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_CSV_SANITIZE_FORMULAS",
        default: "unset (false)",
        purpose: "Set to `1`, `on`, `true`, or `yes` to prefix formula-injection \
                  characters (`=`, `+`, `-`, `@`) with a single quote in CSV output, \
                  preventing spreadsheet formula injection.",
        subsystem: Subsystem::Csv,
        class: Class::SecurityTunable,
    },
    // ── Regex ─────────────────────────────────────────────────────────────────
    EnvVar {
        name: "IPE_REGEX_MAX_INPUT_BYTES",
        default: "16777216 (16 MiB)",
        purpose: "Maximum subject (input) size in bytes that any `Ipe.Regex` \
                  match/find/findAll/replace/split will scan. Past the ceiling the \
                  operation returns its safe empty result, bounding untrusted-input \
                  work and allocation.",
        subsystem: Subsystem::Regex,
        class: Class::Tunable,
    },
    // ── Database ──────────────────────────────────────────────────────────────
    EnvVar {
        name: "IPE_DB_MAX_CONNECTIONS",
        default: "10",
        purpose: "Maximum connections per database pool. Raise for high-concurrency \
                  workloads; lower to reduce database load.",
        subsystem: Subsystem::Db,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_DB_MAX_POOLS",
        default: "4",
        purpose: "Maximum number of distinct database pools (one per unique connection \
                  string). Raise if your app connects to many distinct databases.",
        subsystem: Subsystem::Db,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_DB_OP",
        default: "unset",
        purpose: "Database CLI op mode. Set to `migrate` to run pending migrations and \
                  exit. Intended for container entrypoints and deployment pipelines.",
        subsystem: Subsystem::Db,
        class: Class::Tunable,
    },
    // ── Doc ───────────────────────────────────────────────────────────────────
    EnvVar {
        name: "IPE_DOC_NO_OPEN",
        default: "unset",
        purpose: "Set to any non-empty value to prevent `ipe doc` from opening a \
                  browser tab. The URL is always printed to stdout. Useful in CI or \
                  headless environments.",
        subsystem: Subsystem::Doc,
        class: Class::Tunable,
    },
    // ── Email ─────────────────────────────────────────────────────────────────
    EnvVar {
        name: "IPE_EMAIL_DRY_RUN",
        default: "unset (false)",
        purpose: "Set to `1` to skip actual SMTP delivery and return a synthetic \
                  message ID. Useful in integration tests and staging environments.",
        subsystem: Subsystem::Email,
        class: Class::Tunable,
    },
    // ── FFI ───────────────────────────────────────────────────────────────────
    EnvVar {
        name: "IPE_FFI_ALLOW_UNSANDBOXED",
        default: "unset (false)",
        purpose: "Set to `1` to allow `ipe add` / `ipe install` to run the FFI \
                  inspector without a bubblewrap (`bwrap`) sandbox. Widens the trust \
                  boundary — untrusted build scripts execute without confinement. \
                  Never set in CI or production.",
        subsystem: Subsystem::Ffi,
        class: Class::SecurityTunable,
    },
    EnvVar {
        name: "IPE_FFI_CPU_SECS",
        default: "unset (sandbox default)",
        purpose: "CPU-time limit (seconds) for each sandboxed FFI inspector phase. \
                  Raise only when inspecting crates with very long compile phases.",
        subsystem: Subsystem::Ffi,
        class: Class::SecurityTunable,
    },
    EnvVar {
        name: "IPE_FFI_DBG",
        default: "unset",
        purpose: "Set to any non-empty value to enable verbose debug output from the \
                  FFI inspector. For developer diagnostics only.",
        subsystem: Subsystem::Ffi,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_FFI_FD_CAP",
        default: "unset (sandbox default)",
        purpose: "File-descriptor limit for each sandboxed FFI inspector phase.",
        subsystem: Subsystem::Ffi,
        class: Class::SecurityTunable,
    },
    EnvVar {
        name: "IPE_FFI_INSPECTOR",
        default: "unset (auto-located beside test binary)",
        purpose: "Explicit path to the `ipe-ffi-inspector` binary used in integration \
                  tests. Not needed in normal use.",
        subsystem: Subsystem::Ffi,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_FFI_OUT_CAP_MB",
        default: "unset (sandbox default)",
        purpose: "Output-size cap (MB) for each sandboxed FFI inspector phase. \
                  Prevents inspector stdout from exhausting memory.",
        subsystem: Subsystem::Ffi,
        class: Class::SecurityTunable,
    },
    EnvVar {
        name: "IPE_FFI_PROBE_DIR",
        default: "unset (per-run temp dir)",
        purpose: "Root directory for the FFI inspector's probe workspace. Setting a \
                  stable path allows Cargo to reuse dependency build artefacts across \
                  repeated `ipe add` invocations.",
        subsystem: Subsystem::Ffi,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_FFI_PROC_CAP",
        default: "unset (sandbox default)",
        purpose: "Process-count limit for each sandboxed FFI inspector phase.",
        subsystem: Subsystem::Ffi,
        class: Class::SecurityTunable,
    },
    EnvVar {
        name: "IPE_FFI_RSS_MB",
        default: "unset (sandbox default)",
        purpose: "RSS memory limit (MB) for each sandboxed FFI inspector phase.",
        subsystem: Subsystem::Ffi,
        class: Class::SecurityTunable,
    },
    EnvVar {
        name: "IPE_FFI_WALL_SECS",
        default: "unset (sandbox default)",
        purpose: "Wall-clock time limit (seconds) for each sandboxed FFI inspector phase.",
        subsystem: Subsystem::Ffi,
        class: Class::SecurityTunable,
    },
    EnvVar {
        name: "IPE_FFI_XC_LOAD",
        default: "unset",
        purpose: "Path to a pre-generated cross-compilation manifest to load instead \
                  of running the inspector. Developer / CI optimisation.",
        subsystem: Subsystem::Ffi,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_FFI_XC_SAVE",
        default: "unset",
        purpose: "Path at which to save the generated cross-compilation manifest after \
                  an inspector run. Developer / CI optimisation.",
        subsystem: Subsystem::Ffi,
        class: Class::Tunable,
    },
    // ── File ──────────────────────────────────────────────────────────────────
    EnvVar {
        name: "IPE_FILE_READ_MAX",
        default: "536870912 (512 MiB)",
        purpose: "Maximum bytes `File.readFile` reads in a single call; 0 refuses every \
                  non-empty file; a non-numeric value makes the read fail. Prevents OOM \
                  from unexpectedly large files.",
        subsystem: Subsystem::File,
        class: Class::Tunable,
    },
    // ── HTTP client ───────────────────────────────────────────────────────────
    EnvVar {
        name: "IPE_HTTP_BIND",
        default: "unset (loopback in dev, all-interfaces in release)",
        purpose: "Override the IP address the HTTP server binds: IPv4 such as \
                  `127.0.0.1`, or bare IPv6 such as `::1`. A hostname, a socket \
                  form (`host:port`), brackets, a scope id, padding, or an empty \
                  value refuses startup. Takes precedence over the `Host.bind` \
                  setting and the build-profile default. The conservative loopback \
                  default keeps a dev server off the LAN.",
        subsystem: Subsystem::Http,
        class: Class::SecurityTunable,
    },
    EnvVar {
        name: "IPE_HTTP_DENY_PRIVATE",
        default: "unset (on, except a development binary with no exposed listener)",
        purpose: "Set to `1`, `on`, or `true` to block all outbound HTTP / SMTP / \
                  database connections to RFC-1918 private, loopback, and link-local \
                  addresses, closing the SSRF attack surface; `0`, `off`, or `false` \
                  disables it. Unset, the guard is on in every `ipe release` artifact \
                  and production posture, and off only in a development binary in a \
                  dev posture that has bound no listener beyond loopback. Any other \
                  value turns the guard on and logs one warning.",
        subsystem: Subsystem::Http,
        class: Class::SecurityTunable,
    },
    EnvVar {
        name: "IPE_HTTP_DNS_TIMEOUT_MS",
        default: "5000 (5 s)",
        purpose: "Deadline (ms) for each SSRF-gate DNS resolve (HTTP, WebSocket, database, \
                  SMTP), through the non-blocking resolver. A host still unresolved at the \
                  deadline is refused, so a slow or stalling resolver cannot hold an \
                  outbound dial.",
        subsystem: Subsystem::Http,
        class: Class::SecurityTunable,
    },
    EnvVar {
        name: "IPE_HTTP_MAX_BODY_BYTES",
        default: "33554432 (32 MiB)",
        purpose: "Maximum request-body size (bytes) for outbound `Http.*` calls. \
                  Prevents OOM from unexpectedly large responses.",
        subsystem: Subsystem::Http,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_HTTP_MAX_INFLIGHT",
        default: "1024",
        purpose: "Global cap on simultaneously in-flight HTTP requests at the \
                  `Server.listen` front door. Bounds task/worker fan-out; requests \
                  beyond the cap are backpressured and, with the request timeout \
                  outermost, shed as a timeout rather than queued unboundedly.",
        subsystem: Subsystem::Http,
        class: Class::SecurityTunable,
    },
    EnvVar {
        name: "IPE_HTTP_REQUEST_TIMEOUT",
        default: "30 (seconds)",
        purpose: "Per-request deadline (seconds) at the `Server.listen` front door. \
                  A request — headers or body — that does not complete within the \
                  window is dropped with 408, closing the slowloris hold-open vector.",
        subsystem: Subsystem::Http,
        class: Class::SecurityTunable,
    },
    EnvVar {
        name: "IPE_SERVER_PORT",
        default: "the port passed to `Server.listen`",
        purpose: "TCP port an `Ipe.Http.Server` app listens on. A value outside \
                  `1..=65535` (empty, non-numeric, signed, `0`, or too large) is \
                  ignored and the port passed to `Server.listen` is used. Under \
                  `ipe dev watch` the supervisor chooses the port, so this value has \
                  no effect there.",
        subsystem: Subsystem::Http,
        class: Class::Tunable,
    },
    // ── Observability ─────────────────────────────────────────────────────────
    EnvVar {
        name: "IPE_ENV",
        default: "unset (development in a dev build, production in a release build)",
        purpose: "Deployment environment marker. Any non-empty value other than `dev`, \
                  `development`, or `local` activates production mode: SSRF guard on, \
                  console requires a token, Secure cookies, no dev banner. Unset, the \
                  build decides: `ipe dev build`, `ipe dev run`, `ipe test` and `ipe dev watch` \
                  binaries read as development, `ipe release` artifacts as production. \
                  An `ipe release` artifact is production whatever this says: a dev \
                  marker there opens no dev-only surface and logs one notice. Also \
                  accepted as bare `ENV`.",
        subsystem: Subsystem::Observability,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_LOG_FORMAT",
        default: "unset (human-readable)",
        purpose: "Set to `json` to emit structured JSON log lines instead of the \
                  default human-readable format. Recommended for log aggregation \
                  pipelines (Datadog, Loki, etc.).",
        subsystem: Subsystem::Observability,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_LOG_LEVEL",
        default: "unset (info)",
        purpose: "Minimum log level: `debug`, `info`, `warn` (or `warning`), or \
                  `error`, ASCII case-insensitive. Any other value, an empty or \
                  padded one included, refuses startup. Read once at process start, \
                  so a later `System.setenv` or `System.loadEnv` does not change it. \
                  Takes precedence over an installed `Log.level` setting.",
        subsystem: Subsystem::Observability,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_OBSERVABILITY_BUFFER",
        default: "1024",
        purpose: "Bounded queue depth for the parent-push telemetry exporter. Overflow \
                  drops and warns rather than blocking the application.",
        subsystem: Subsystem::Observability,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_OBSERVABILITY_PUSH_INTERVAL_MS",
        default: "2000",
        purpose: "Flush cadence (ms) for telemetry shipped from a sub-app to its \
                  parent's `/_ipe/ingest` endpoint.",
        subsystem: Subsystem::Observability,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_PARENT_URL",
        default: "unset",
        purpose: "Base URL of the parent app to which this sub-app pushes telemetry. \
                  Presence of this variable activates the push exporter.",
        subsystem: Subsystem::Observability,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_RECURSION_LIMIT",
        default: "10000",
        purpose: "Maximum Ipê call-stack depth before a recursion-limit error is \
                  raised. Prevents stack-overflow crashes from unbounded recursion.",
        subsystem: Subsystem::Observability,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_SERVICE_NAME",
        default: "unset (binary name)",
        purpose: "Service name attached as the `service.name` resource attribute on \
                  telemetry records shipped to the Hub or the telemetry SQLite spill.",
        subsystem: Subsystem::Observability,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_TRACE",
        default: "unset (false)",
        purpose: "Set to any non-empty truthy value (`1`, `true`, etc.) to emit \
                  `Trace.span` timings to stderr. Off by default — no noise in \
                  production.",
        subsystem: Subsystem::Observability,
        class: Class::Tunable,
    },
    // ── Process ───────────────────────────────────────────────────────────────
    EnvVar {
        name: "IPE_PROCESS_OUTPUT_MAX",
        default: "16777216 (16 MiB)",
        purpose: "Maximum bytes buffered from a subprocess's stdout or stderr by \
                  `Process.run`. Prevents OOM when a child writes without bound.",
        subsystem: Subsystem::File,
        class: Class::Tunable,
    },
    // ── Runtime ───────────────────────────────────────────────────────────────
    EnvVar {
        name: "IPE_HOME",
        default: "unset ($XDG_DATA_HOME/ipe, then $HOME/.ipe)",
        purpose: "Root directory for materialised runtime source, config, and cached \
                  binaries. Overrides the XDG / home-directory fallback. Must be an \
                  absolute path.",
        subsystem: Subsystem::Runtime,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_RUNTIME_DIR",
        default: "unset (embedded / in-repo)",
        purpose: "Explicit path to the runtime crate source directory. Overrides the \
                  embedded fallback. Used in tests and in-repo development.",
        subsystem: Subsystem::Runtime,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_RUNTIME_VENDORED",
        default: "unset (false)",
        purpose: "Set to `1` to declare that the runtime is vendored (already present \
                  on disk) and skip materialization. Used during packaging.",
        subsystem: Subsystem::Runtime,
        class: Class::Tunable,
    },
    // ── Web server ────────────────────────────────────────────────────────────
    EnvVar {
        name: "IPE_AUTH_MAX_LIFETIME",
        default: "28800 (8 h)",
        purpose: "Absolute lifetime cap (seconds) for a signed session token. A stolen \
                  but unrevoked token is worthless after this deadline. Takes \
                  precedence over `Web.authMaxLifetime`.",
        subsystem: Subsystem::Web,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_AUTH_REVOCATION",
        default: "unset (Off)",
        purpose: "Session-token revocation mode. Set to `store` or `1` to enable the \
                  in-process revocation store, which checks each request against a list \
                  of revoked token IDs. `off` or `0` disables; default is Off \
                  (zero overhead).",
        subsystem: Subsystem::Web,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_AUTH_SLIDE_WINDOW",
        default: "1800 (30 min)",
        purpose: "Rolling re-issue window (seconds) for a signed session token. A \
                  request within this window of expiry re-issues a fresh token, \
                  keeping an active session alive without a full login. It must be \
                  below the max lifetime, else startup refuses. Takes precedence \
                  over `Web.authSlideWindow`.",
        subsystem: Subsystem::Web,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_AUTH_TOKEN_SECRET",
        default: "unset",
        purpose: "HMAC signing secret for session tokens. Must be at least 32 bytes. \
                  Rotate with care — outstanding tokens signed with the old secret \
                  become invalid. Provide via your secret manager; never commit.",
        subsystem: Subsystem::Web,
        class: Class::Secret,
    },
    EnvVar {
        name: "IPE_CSRF",
        default: "unset (on)",
        purpose: "Set to `off`, `0`, or `false` to disable CSRF protection. \
                  Disabling widens the trust boundary — only safe on loopback in \
                  automated tests.",
        subsystem: Subsystem::Web,
        class: Class::SecurityTunable,
    },
    EnvVar {
        name: "IPE_REVOCATION_CAPACITY",
        default: "1048576 (2^20)",
        purpose: "Maximum number of entries in the per-process token revocation store. \
                  Each entry is roughly 64 bytes; the default cap holds ~64 MB. Raise \
                  for very high user volumes with token revocation enabled.",
        subsystem: Subsystem::Web,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_TRUSTED_PROXY",
        default: "unset (false)",
        purpose: "Set to any truthy value to trust `X-Forwarded-For` / \
                  `X-Forwarded-Proto` headers for remote-address and TLS detection. \
                  Enable only when a trusted reverse proxy sits in front of this \
                  process; leaving unset prevents clients from forging these headers.",
        subsystem: Subsystem::Web,
        class: Class::SecurityTunable,
    },
    EnvVar {
        name: "IPE_WEB_BANNER",
        default: "unset (on in dev)",
        purpose: "Set to `off`, `0`, or `false` to disable the reconnection-status \
                  banner in the browser client.",
        subsystem: Subsystem::Web,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_WEB_BASE_PATH",
        default: "unset (root-mounted)",
        purpose: "Sub-app mount prefix, e.g. `/billing`. All session-cookie, \
                  CSRF-cookie, and asset paths are scoped to this prefix. Set \
                  automatically when mounting a sub-app. After trimming, \
                  dropping a trailing `/` and adding a missing leading `/`, a \
                  value that is not one or more `/segment` parts made only of \
                  `A-Z a-z 0-9 - . _ ~` (no empty, `.`, or `..` segment, no `%` \
                  escape, at most 1024 bytes) refuses the app: a standalone \
                  server does not start and a mounted app answers every \
                  request with 503.",
        subsystem: Subsystem::Web,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_WEB_CSRF_ORIGIN_CHECK",
        default: "unset (off)",
        purpose: "Set to `on` to enforce strict `Origin`-header cross-origin checking \
                  on top of the double-submit CSRF token.",
        subsystem: Subsystem::Web,
        class: Class::SecurityTunable,
    },
    EnvVar {
        name: "IPE_WEB_FRAME_ANCESTORS",
        default: "unset (no embedding allowed)",
        purpose: "Space-separated `Content-Security-Policy: frame-ancestors` allow-list, \
                  e.g. `https://app.example.com`. Enables embedding this app in a \
                  third-party iframe; also sets `SameSite=None; Secure` on session \
                  cookies. A value holding a control or non-ASCII byte, a `;` or `,`, \
                  or only whitespace refuses to start the server.",
        subsystem: Subsystem::Web,
        class: Class::SecurityTunable,
    },
    EnvVar {
        name: "IPE_WEB_HEARTBEAT_TTL_MS",
        default: "35000",
        purpose: "SSE heartbeat interval (ms) the browser uses to detect a stale \
                  connection.",
        subsystem: Subsystem::Web,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_WEB_HELLO_TIMEOUT_MS",
        default: "8000",
        purpose: "Timeout (ms) for the initial SSE hello handshake. The browser \
                  closes and retries if this deadline passes.",
        subsystem: Subsystem::Web,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_WEB_MAX_BODY_BYTES",
        default: "33554432 (32 MiB)",
        purpose: "Maximum inbound request-body size (bytes) for `/_ipe/event`. Raise \
                  for large file uploads; lower to tighten the DoS floor.",
        subsystem: Subsystem::Web,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_WEB_MAX_SESSIONS",
        default: "50000",
        purpose: "Maximum concurrent web sessions before new connections are rejected. \
                  Prevents unbounded memory growth under a session-creation flood.",
        subsystem: Subsystem::Web,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_WEB_PORT",
        default: "8000",
        purpose: "TCP port an `Ipe.Web` app listens on. A value outside `1..=65535` \
                  (empty, non-numeric, signed, `0`, or too large) is ignored and \
                  8000 is used. Under `ipe dev watch` the supervisor chooses the port, \
                  so this value has no effect there.",
        subsystem: Subsystem::Web,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_WEB_QUEUE_MAX",
        default: "50",
        purpose: "Maximum queued events per session before back-pressure is applied.",
        subsystem: Subsystem::Web,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_WEB_RESET_STATE",
        default: "unset (off)",
        purpose: "Set to `1`, `true`, `yes`, or `on` to force every returning session \
                  to a fresh `init`, bypassing the additive-superset checkpoint splice. \
                  Injected by `ipe dev watch --reset-state`; never set in production. \
                  Fail-closed: an absent or unrecognised value leaves the normal \
                  additive-preserve algorithm in place.",
        subsystem: Subsystem::Web,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_WEB_RETRY_BASE_MS",
        default: "500",
        purpose: "Initial retry interval (ms) for client reconnection after a \
                  disconnect.",
        subsystem: Subsystem::Web,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_WEB_RETRY_FAST_MS",
        default: "200",
        purpose: "Fast-retry interval (ms) used during the fast-retry window after a \
                  hot-reload disconnect.",
        subsystem: Subsystem::Web,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_WEB_RETRY_FAST_WINDOW_MS",
        default: "3000",
        purpose: "Duration (ms) of the fast-retry window after a disconnect. Set to \
                  `8000` automatically by `ipe dev watch` to accommodate server restart \
                  time.",
        subsystem: Subsystem::Web,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_WEB_RETRY_MAX_ATTEMPTS",
        default: "10",
        purpose: "Maximum reconnection attempts before the client stops retrying.",
        subsystem: Subsystem::Web,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_WEB_RETRY_MAX_MS",
        default: "16000",
        purpose: "Maximum retry interval (ms) — the exponential back-off ceiling.",
        subsystem: Subsystem::Web,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_WEB_SHUTDOWN_GRACE_MS",
        default: "1500",
        purpose: "Grace period (ms) between receiving SIGTERM and closing active \
                  connections. Allows in-flight requests to complete. Set to `0` for \
                  immediate shutdown.",
        subsystem: Subsystem::Web,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_WEB_SSE_BUFFER",
        default: "16",
        purpose: "SSE channel buffer capacity per session (clamped 1–1024). A full \
                  buffer applies TCP backpressure rather than dropping events.",
        subsystem: Subsystem::Web,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_WEB_STATIC_DIR",
        default: "unset",
        purpose: "Directory served at `/static/*`. Populated from `package.ipe [web] \
                  static`. Path traversal is blocked by construction.",
        subsystem: Subsystem::Web,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_WEB_STORE",
        default: "memory",
        purpose: "Session-store backend for the web server: `memory` (per-process, \
                  lost on restart), `file` (persisted to `IPE_WEB_STORE_PATH`, no \
                  database dependency), or `sqlite`/`postgres`/`redis` (persisted, \
                  require the `db` or `redis_store` feature). `ipe dev watch` selects \
                  `file` so a rebuild preserves live sessions even for a plain web \
                  app. A persisted session survives a restart or a rolling restart \
                  even across a purely-additive `Model` change (a new field added, \
                  none removed or retyped): old state is kept and each new field \
                  takes its `init` value; any non-additive change resets the session \
                  to a fresh `init`. Requesting a backend the build lacks the \
                  feature for is a fail-closed startup error, not a silent \
                  downgrade — build with the feature or set \
                  `IPE_WEB_STORE=file|memory`.",
        subsystem: Subsystem::Web,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_WEB_STORE_PATH",
        default: "unset (temp file)",
        purpose: "Filesystem path for the `file` or `sqlite` session store. Ignored \
                  when `IPE_WEB_STORE` is `memory`. Unset uses a per-process temporary file.",
        subsystem: Subsystem::Web,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_WEB_SWAP_TOAST",
        default: "unset (off)",
        purpose: "Set by the `ipe dev watch` blue-green proxy on the app it supervises. \
                  Tells the web client a reconnect is an expected rebuild cutover, so it \
                  greets it with a brief positive \"updated ✓\" toast instead of the \
                  \"Reconnecting…\" banner. Dev-only; a release build never sets it.",
        subsystem: Subsystem::Web,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_WEB_TTL",
        default: "1800 (30 min)",
        purpose: "Session idle TTL. Accepts seconds (`1800`) or duration strings \
                  (`30m`, `1h`). Takes precedence over `Web.sessionTtl`.",
        subsystem: Subsystem::Web,
        class: Class::Tunable,
    },
    // ── WebSocket ─────────────────────────────────────────────────────────────
    EnvVar {
        name: "IPE_WS_HEARTBEAT",
        default: "30",
        purpose: "WebSocket ping interval (seconds). A peer that does not respond \
                  within two intervals is considered dead and disconnected.",
        subsystem: Subsystem::Ws,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_WS_MAX_CONNECTIONS",
        default: "1024",
        purpose: "Ceiling on simultaneously live server WebSocket peers. Each peer \
                  pins a registry slot, an mpsc channel, and a heartbeat task; an \
                  upgrade beyond the ceiling is refused with 503 before any slot is \
                  allocated, bounding FD/memory exhaustion by construction.",
        subsystem: Subsystem::Ws,
        class: Class::SecurityTunable,
    },
    EnvVar {
        name: "IPE_WS_MAX_MESSAGE_BYTES",
        default: "1048576 (1 MiB)",
        purpose: "Maximum WebSocket message size (bytes) for both client and server \
                  connections. Messages larger than this limit are rejected.",
        subsystem: Subsystem::Ws,
        class: Class::Tunable,
    },
    EnvVar {
        name: "IPE_WS_SEND_BUFFER",
        default: "256",
        purpose: "Per-connection outbound frame buffer depth. A full buffer applies \
                  backpressure (the send kernel returns `Err`) rather than dropping \
                  frames.",
        subsystem: Subsystem::Ws,
        class: Class::Tunable,
    },
    // ── UI render ─────────────────────────────────────────────────────────────
    EnvVar {
        name: "IPE_EXPLAIN_VERBOSE",
        default: "unset",
        purpose: "Enable the verbose `Debug.explain` dev overlay: each explained \
                  layout box gets a `title` tooltip annotating its type, width, and \
                  padding. Accepts `1`, `true`, or `on` (case-insensitive). \
                  Developer diagnostic, off by default.",
        subsystem: Subsystem::Ui,
        class: Class::Tunable,
    },
];

/// Set of variable names that are intentionally excluded from the drift gate
/// because they are test-only, internal, or build-time baked.
///
/// The drift gate checks that every `IPE_*` string literal read at runtime
/// appears in `ENV_VARS` OR in this exclusion set. The reverse holds too: a name
/// here that no source file reads is refused, as is an `IPE_*` name in a registry
/// entry's text that is neither registered nor excluded.
pub static EXCLUDED_NAMES: &[&str] = &[
    // Test harness variables — not operator-facing.
    "IPE_ALLOWED_E2E", // Windows jail e2e test sentinel
    "IPE_ANYTHING",    // used only in a denylist assertion string
    "IPE_BLESS",
    "IPE_CAPABILITY_FLOOR", // a linker-retained static symbol, not an env var
    "IPE_COVERAGE_BUILD_JOBS", // coverage test harness: parallel build+run job count
    "IPE_DEBUG_TODO_SUBPROCESS",
    "IPE_E2E",                              // CI gate for enabling e2e test suites
    "IPE_E2E_BUILD_IDLE_SECS", // golden E2E harness: emitted-crate build idle-inactivity cap
    "IPE_E2E_BUILD_TIMEOUT_SECS", // golden E2E harness: emitted-crate build fail-fast cap
    "IPE_E2E_SECRET",          // macOS jail e2e test sentinel
    "IPE_E2E_STATIC",          // CI gate for static-binary e2e tests
    "IPE_FUZZ_ITERS",          // fuzz template harness: random-run iteration count
    "IPE_FUZZ_SEED",           // fuzz template harness: random-run seed
    "IPE_HOST_ENV_TEST_UNSET_7F3A9C21D84E", // sandbox host_env test: a name no host sets
    "IPE_HTTP_TEST_URL",
    "IPE_INDEX_EXTRACTOR", // ipe-index build script: extractor digest handed to the crate at compile time
    "IPE_JUNCTION_OUT",    // Windows junction test helper: compiled helper output path
    "IPE_LOAD_ENV_PROBE_VAR",
    "IPE_ORACLE_SHARED_TARGET",
    "IPE_PDEATH_PROBE", // parent-death spawner test: selects the re-executed probe mode
    "IPE_RUN_WITH_TEST_VAR",
    "IPE_SECRET_E2E",                   // Windows jail e2e test sentinel
    "IPE_SMOKE_ASKPASS_USER", // registry smoke: git askpass helper's internal user-name channel
    "IPE_SMOKE_TOKEN", // registry smoke script input (its publish token), not a runtime variable
    "IPE_TEMP_ROOT_ENV_TEST_NEIGHBOUR", // temp-root refusal test: a key that only contains a temp-root name
    "IPE_TEST_BOOL_BAD",
    "IPE_TEST_BOOL_F",
    "IPE_TEST_BOOL_T",
    "IPE_TEST_BOOL_UNSET",
    "IPE_TEST_CEILING", // runtime env-ceiling contract tests: a fixed name, never read in production
    "IPE_TEST_DURATION", // runtime env-duration contract tests: a fixed name, never read in production
    "IPE_TEST_DURATION_LIVE", // runtime env-duration live-read test: a fixed name, never read in production
    "IPE_TEST_GETENV_PRESENT",
    "IPE_TEST_GETENV_UNSET_XYZ_42", // variant with numeric suffix in proptest
    "IPE_TEST_INT_BAD",
    "IPE_TEST_INT_OK",
    "IPE_TEST_INT_UNSET",
    "IPE_TEST_PG_URL",
    "IPE_TEST_REDIS_URL",
    "IPE_TIME_STRING_TZ_CHILD", // runtime time test: marks the non-UTC `TZ` re-exec
    "IPE_TMP", // temp-root refusal tests: a neighbouring key that must not be refused
    "IPE_WASI_SEAL_CHILD", // WASI seal e2e: marks the cargo-env re-exec
    "IPE_WINDOWS_E2E_ENV_CHILD", // Windows jail e2e: marks the env-seeded re-exec
    // Dev-loop-internal listener relocation port — set by `ipe dev watch` and the
    // dev console proxy on the child they spawn (never operator-set); it
    // outranks the operator port vars and is never inherited by `Process.*` children.
    "IPE_INTERNAL_LISTEN_PORT",
    // Dev-loop-internal control-channel port — allocated and injected by
    // `ipe dev watch` into the spawned child (never operator-set), like the relocation
    // port above. Present only in a dev-loop (web/debugger) build.
    "IPE_CONTROL_PORT",
    // Dev-loop-internal record-log destination — set by `ipe dev run --record` on
    // the executed child (the log always lands in the ipe-owned output root; the
    // operator never sets this var directly). Read by the recorder dump; present
    // only in a `debugger` build.
    "IPE_DEBUGGER_RECORD",
    // Dev-loop-internal replay-log path — set by `ipe dev run --replay` on the
    // executed child (never operator-set). Read by the cli/worker loop, which
    // replays the named typed log instead of running; present only in a
    // `debugger` build.
    "IPE_DEBUGGER_REPLAY",
    // `ipe upgrade` <-> `install.sh` handshake — set by the upgrade wrapper on
    // the installer child it spawns (never operator-set): the wrapped marker
    // suppresses the installer's own failure banner, and the tag file carries
    // the resolved release tag back to the wrapper.
    "IPE_UPGRADE_TAG_FILE",
    "IPE_UPGRADE_WRAPPED",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_vars_sorted_within_subsystem() {
        // Collect subsystem-buckets in the order they appear.
        let mut last: Option<(&str, Subsystem)> = None;
        for v in ENV_VARS {
            if let Some((prev_name, prev_sub)) = last
                && v.subsystem == prev_sub
            {
                assert!(
                    v.name >= prev_name,
                    "ENV_VARS: within subsystem {:?}, '{}' must come after '{}' (alphabetical)",
                    v.subsystem,
                    v.name,
                    prev_name,
                );
            }
            last = Some((v.name, v.subsystem));
        }
    }

    /// The documented `IPE_FILE_READ_MAX` default is the enforced runtime const.
    #[test]
    fn file_read_max_default_matches_runtime() {
        let entry = ENV_VARS.iter().find(|v| v.name == "IPE_FILE_READ_MAX");
        let expected = format!("{} ", ipe_runtime_rust::file::READ_FILE_DEFAULT_CEILING);
        assert!(
            entry.is_some_and(|v| v.default.starts_with(&expected)),
            "IPE_FILE_READ_MAX default must start with {expected:?}: {entry:?}"
        );
    }

    #[test]
    fn env_var_names_unique() {
        let mut seen = std::collections::HashSet::new();
        for v in ENV_VARS {
            assert!(seen.insert(v.name), "ENV_VARS: duplicate name '{}'", v.name);
        }
    }

    /// The operator listen-port vars are documented; the supervisor's
    /// relocation var is internal and never documented.
    #[test]
    fn operator_port_vars_registered_relocation_var_excluded() {
        for name in ["IPE_SERVER_PORT", "IPE_WEB_PORT"] {
            assert!(
                ENV_VARS.iter().any(|v| v.name == name),
                "{name} is an operator var and must be registered"
            );
            assert!(
                !EXCLUDED_NAMES.contains(&name),
                "{name} must not be excluded"
            );
        }
        assert!(EXCLUDED_NAMES.contains(&"IPE_INTERNAL_LISTEN_PORT"));
        assert!(
            ENV_VARS
                .iter()
                .all(|v| v.name != "IPE_INTERNAL_LISTEN_PORT"),
            "the relocation var is internal and must never be documented"
        );
    }

    #[test]
    fn excluded_names_no_overlap_with_registry() {
        let registered: std::collections::HashSet<&str> = ENV_VARS.iter().map(|v| v.name).collect();
        for name in EXCLUDED_NAMES {
            assert!(
                !registered.contains(name),
                "EXCLUDED_NAMES: '{name}' also appears in ENV_VARS — remove it from one",
            );
        }
    }
}
