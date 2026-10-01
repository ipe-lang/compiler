//! Single source of truth for the `ipe-runtime-rust` cargo features a program
//! needs.
//!
//! The emitter trims the vendored runtime to the modules + crates a program
//! actually reaches. Today that trimming is expressed by the per-surface
//! manifest augmenters (`db_cargo_toml`, `url_cargo_toml`, …) and the
//! `RUNTIME_MOD_RS_*_APPEND` module appends in [`crate::project`]. This module
//! restates the SAME reachability, once, as a mapping from an [`EmitCtx`]'s
//! `uses_*` / `reaches_*` predicates to the exact set of runtime-crate cargo
//! features that program selects.
//!
//! The feature set is a typed value, not a bag of strings: [`RuntimeFeature`]'s
//! variants ARE the runtime crate's declared feature universe, so a feature
//! that does not exist in `src/runtime/rust/Cargo.toml` cannot be named here,
//! and the closure SEAL (`tests/runtime_featureset_closure.rs`) proves the
//! image over the whole flag space stays inside that universe.
//!
//! This is the authority the dependency-model emit will read to write the
//! `features = [...]` list. It is introduced here and unit-/SEAL-tested; the
//! emit path is not yet switched to it, so the emitted output is unchanged.

use std::collections::BTreeSet;

use crate::EmitCtx;

/// One runtime-crate cargo feature. Every variant maps to a feature declared in
/// `src/runtime/rust/Cargo.toml`'s `[features]` table; [`Self::as_str`] is that
/// exact feature name. Keeping the set closed as an enum makes a
/// "select a feature the crate does not declare" state unrepresentable at the
/// SSOT boundary — the drift can only be a stale variant, which the closure
/// SEAL catches against the crate manifest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RuntimeFeature {
    /// `json` — the JSON codec (`serde_json`, and via `json = […, "serde"]` the
    /// serde stack). Selected by `reaches_json()`: a program that NAMES the
    /// `Value`/`Decoder` type (a `Json`-building kernel, a `Json`/`Decoder`
    /// type-mention, or a db/config/jwt/web surface whose crate feature lists
    /// `json`). A program that names none of these drops the crate.
    Json,
    /// `async` — the tokio reactor spine, selected for any reactor-requiring
    /// program (mirrors [`EmitCtx::uses_async_runtime`]).
    Async,
    /// `db-sqlite` — the sqlite driver alias set (`uses_db` under the Sqlite
    /// driver). Implies `db`.
    DbSqlite,
    /// `db-postgres` — the postgres driver alias set (`uses_db` under the
    /// Postgres driver). Implies `db` (and, per the crate graph, `sqlx/sqlite`
    /// for the session store).
    DbPostgres,
    /// `server` — axum + tower-http (`uses_server`, and forced by `web` /
    /// `webview`, whose runtime modules import the server surface).
    Server,
    /// `web` — the Live web app runtime (`uses_web`, forced by `webview`).
    Web,
    /// `tui` — the terminal-UI backend (`uses_tui`).
    Tui,
    /// `webview` — the native-window backend (`uses_webview`).
    Webview,
    /// `websocket_client` — the outbound WebSocket client (`uses_websocket`).
    WebsocketClient,
    /// `email` — the SMTP transport (`uses_email`).
    Email,
    /// `locale` — the ICU4X BCP-47 parse + locale-aware case mapping
    /// (`icu_casemap` + `icu_locale_core`). Selected by `uses_locale`: any
    /// `Locale.fromTag` / `Locale.toTag` / `String.toUpperIn` /
    /// `String.toLowerIn` kernel call, or any type position that names
    /// `IrType::Locale`. Without this feature `locale_from_tag` always returns
    /// `Nothing` — the locale module compiles but the ICU4X parse body is gated
    /// behind `#[cfg(feature = "locale")]`.
    Locale,
    /// `http_client` — the reqwest outbound HTTP stack (`reaches_http_client()`:
    /// an HTTP kernel or the email surface, whose `email.rs` calls
    /// `http_client::ssrf_apply`). `http_stream.rs` (which calls
    /// `ssrf_apply` + `method_to_reqwest`) is declared alongside `http_client`
    /// so server/web apps that make no outbound HTTP calls omit reqwest.
    HttpClient,
    /// `url` — the `Ipe.Url` typed-URL module + `ssrf` validators, i.e. the
    /// `url` crate and its idna → ICU4X subtree (`reaches_url()`: a URL kernel
    /// or a surface that parses with `url` — the HTTP or WebSocket client).
    Url,
    /// `config` — the TOML/YAML `Config` decoders (`uses_config`).
    Config,
    /// `compression` — flate2 + zstd (`uses_compression`).
    Compression,
    /// `csv_kernel` — the csv crate (`uses_csv`).
    CsvKernel,
    /// `cache_kernel` — the `cache.rs` handle-based LRU cache module (`uses_cache`:
    /// an `Ipe.Cache` kernel, or a `CacheCfg` / `CacheStats` type-mention). A
    /// standalone leaf — no surface implies it. Selecting it compiles `cache.rs`
    /// (the `cache_new_raw` / `cache_get` / `cache_put` / … functions, the
    /// `CacheCfg` / `CacheStats` structs, and the `IpeCacheHandle` enum the emitted
    /// code references). The runtime feature pulls `tokio` + `random` (the module's
    /// `IpeTask` return + its LCG-free eviction clock), so a program that reaches no
    /// `Ipe.Cache` surface drops the module.
    CacheKernel,
    /// `time` — the IANA-zone calendar surface, `chrono-tz` (`uses_time`).
    Time,
    /// `encoding` — the `base64` + `hex` + `percent-encoding` codec crates and
    /// the `encoding.rs` / `bytes.rs` runtime modules (`reaches_encoding()`: an
    /// `Ipe.Encoding` / `Ipe.Bytes` kernel, OR a crypto/db/server/email/jwt/web
    /// surface whose runtime module uses the raw codec crates). A program that
    /// reaches none of these drops `base64` + `hex` (`percent-encoding` also
    /// enters via the `serde_urlencoded` floor dep, untouched here).
    Encoding,
    /// `regex` — the `regex` crate (+ its `aho-corasick` / `regex-automata` /
    /// `regex-syntax` subtree) and the `regex_kernel.rs` module (`reaches_regex()`:
    /// an `Ipe.Regex` kernel or `String.isUrl`, whose validator relocated into
    /// that module). A standalone leaf — no surface implies it. A program that
    /// reaches neither drops all four crates.
    Regex,
    /// `uuid` — the `uuid` crate and the `uuid_kernel.rs` module
    /// (`reaches_uuid()`: an `Ipe.Uuid` kernel, OR the `server` / `web` surfaces
    /// whose runtime modules mint ids via `uuid::new_v4`, OR the `jwt` / `auth`
    /// surface whose `auth.rs` calls `uuid::Uuid::new_v4()` to mint per-session
    /// `jti` ids in `auth_sign_token`). A bare Program that reaches none drops the
    /// crate.
    Uuid,
    /// `random` — the `random.rs` module (`reaches_random()`: an `Ipe.Random`
    /// kernel). A standalone leaf — no surface implies it. The feature gates the
    /// MODULE only, not `getrandom`, which every runtime carries.
    Random,
    /// `log` — the `log.rs` module (`reaches_log()`: an `Ipe.Log` kernel). A
    /// standalone leaf — no surface implies it. Enables base `chrono` (`log =
    /// ["dep:chrono"]`), so it is one of the two selectors that keep `chrono` in
    /// the graph (the other is `time-core`).
    Log,
    /// `time-core` — base `chrono` and the `time.rs` module
    /// (`reaches_time_core()`: `log` OR any Time/Db/Web/WebView surface). The IANA
    /// zone DB (`chrono-tz`) is the separate `Time` feature, which implies this.
    /// The single selector for whether the emitted crate keeps `chrono`.
    TimeCore,
    /// `decimal` — the `decimal.rs`/`money.rs` modules + `rust_decimal`
    /// (`reaches_decimal()`: a `Decimal.*`/`Money.*` kernel OR the `Db` surface,
    /// which decodes numeric columns through `rust_decimal`). `money.rs` builds on
    /// `decimal.rs`'s `Decimal`, so one feature gates both.
    Decimal,
    /// `char-category` — the `char_category.rs` module + `unicode-general-category`
    /// (`reaches_char_category()`: an `Ipe.Char` `General_Category` predicate). A
    /// standalone leaf. The std-only `Ipe.Char` kernels stay in `char_kernel.rs`.
    CharCategory,
    /// `crypto-core` — the cryptographic floor: `crypto_core.rs` and its `sha2`
    /// hash / `hmac` / `subtle` constant-time deps
    /// (`reaches_crypto_core()`: a crypto-floor kernel, OR the crypto / jwt / db /
    /// web / webview / email / server surfaces, all of which reach the floor). A
    /// bare synchronous Program reaches none of these and drops the module and
    /// the `sha2`/`hmac`/`subtle` subtree.
    CryptoCore,
    /// `secret` — the `secret.rs` opaque secret-string module and its `zeroize`
    /// dep (`reaches_secret()`: a `Secret.*` kernel / `Secret`-typed value, or the
    /// JWT / Auth surface whose `Algorithm` is a `secret::Secret`). Implies
    /// `crypto-core` for the shared `subtle` compare.
    Secret,
    /// `crypto` — the heavy crypto surface: rsa + bcrypt + AEAD + pbkdf2
    /// (`uses_crypto`). Implies `crypto-core`.
    Crypto,
    /// `jwt` — the JWT encode/decode surface, `jsonwebtoken` (`reaches_jwt()`:
    /// a JWT kernel or the `Ipe.Auth` surface). Implies `json` + `crypto`.
    Jwt,
    /// `wasm-client` — the browser-WASM TEA sink (`src/wasm/`): the closed wasm
    /// module floor. Selected ONLY on [`ipe_ir::Target::WasmClient`]. It is the
    /// wasm target's fail-closed floor: the feature transitively pulls the whole
    /// proven wasm module set (`json` → `serde`, `crypto-core`, `secret`, `url`,
    /// `encoding`, `regex`, `uuid`, `random`, `log`, `time`, `decimal`,
    /// `char-category`), so a wasm program selects it plus whatever additional
    /// browser-admissible surface it reaches (`websocket_client`, `time`). Never
    /// selected on a native target — the `wasm` runtime module is target-cfg'd to
    /// `wasm32`, so a native crate that enabled it would fail to link.
    WasmClient,
    /// `debugger` — the development-only time-travelling debugger recorder
    /// (`ipe build/run --debugger`). Selected by [`EmitCtx::debugger`], not by
    /// any kernel/surface reachability: it is a build-mode opt-in, orthogonal to
    /// what the program uses. Adds the `debugger/mod.rs` recorder module and the
    /// wasm TEA record hook. `ipe release` never sets the flag, so no production
    /// artifact carries recorder code.
    Debugger,
    /// `control-wire` — the loopback dev-loop control channel WITHOUT the
    /// debugger recorder: the `ControlFrame` codec, the loopback `transport`
    /// primitives, and (with `tokio`, which the `tui` feature already pulls) the
    /// `control::server` accept-loop and the crate-root `literal_table` overlay.
    /// It is the terminal-shape analogue of the web app's HTTP hot-swap endpoint:
    /// a `Tui.tea` app has no HTTP port, so its appearance hot-swap rides this
    /// socket instead. Selected ONLY for an `ipe watch` build of a tui view
    /// (`hot_appearance && uses_tui`); a plain `ipe build`/`ipe release` sets no
    /// dev-loop flag, so a production terminal artifact selects it not and carries
    /// no control server (dev == prod by absence). A cli (`uses_console`) is
    /// excluded — no repaintable appearance surface, and its debugger records to
    /// the `IPE_DEBUGGER_RECORD` dump, not this socket. Redundant under `web`
    /// (which pulls the control module via its `server` feature) and under
    /// `debugger` (whose Cargo feature implies `control-wire` directly), so those
    /// shapes never need this row to fire.
    ControlWire,
    /// `dev-posture` — the build was emitted by a dev-loop verb
    /// ([`crate::BuildIntent::Development`]). Selected by [`EmitCtx::build_intent`],
    /// not by reachability. It is the one input that lets the runtime's operator
    /// console default open, and only on a loopback bind; without it every
    /// absent posture resolves to production and the console stays closed.
    DevPosture,
}

impl RuntimeFeature {
    /// Every variant, once. The exhaustive universe the capability-table drift
    /// assert ([`crate::capabilities`]) folds over to prove every feature has a
    /// row. A companion `ALL`-coverage seal in that module proves this list
    /// covers every [`Self::index`] below [`Self::index_domain_size`]: because
    /// the `index` match is exhaustive and wildcard-free, a new variant is forced
    /// into it (and so into the domain size), and the coverage seal then fails
    /// the build until the variant is listed here too — so a variant present in
    /// `index` but missing from `ALL` cannot slip through, and the universe
    /// cannot silently grow.
    pub(crate) const ALL: &'static [Self] = &[
        Self::Json,
        Self::Async,
        Self::DbSqlite,
        Self::DbPostgres,
        Self::Server,
        Self::Web,
        Self::Tui,
        Self::Webview,
        Self::WebsocketClient,
        Self::Email,
        Self::Locale,
        Self::HttpClient,
        Self::Url,
        Self::Config,
        Self::Compression,
        Self::CsvKernel,
        Self::CacheKernel,
        Self::Time,
        Self::Encoding,
        Self::Regex,
        Self::Uuid,
        Self::Random,
        Self::Log,
        Self::TimeCore,
        Self::Decimal,
        Self::CharCategory,
        Self::CryptoCore,
        Self::Secret,
        Self::Crypto,
        Self::Jwt,
        Self::WasmClient,
        Self::Debugger,
        Self::ControlWire,
        Self::DevPosture,
    ];

    /// A stable per-variant index for `const`-context identity. The exhaustive,
    /// wildcard-free match makes a new variant a compile error here until it is
    /// given an index — so [`Self::const_eq`] and the drift assert cannot be
    /// fooled by an unhandled variant.
    pub(crate) const fn index(self) -> usize {
        match self {
            Self::Json => 0,
            Self::Async => 1,
            Self::DbSqlite => 2,
            Self::DbPostgres => 3,
            Self::Server => 4,
            Self::Web => 5,
            Self::Tui => 6,
            Self::Webview => 7,
            Self::WebsocketClient => 8,
            Self::Email => 9,
            Self::Locale => 10,
            Self::HttpClient => 11,
            Self::Url => 12,
            Self::Config => 13,
            Self::Compression => 14,
            Self::CsvKernel => 15,
            Self::CacheKernel => 16,
            Self::Time => 17,
            Self::Encoding => 18,
            Self::Regex => 19,
            Self::Uuid => 20,
            Self::Random => 21,
            Self::Log => 22,
            Self::TimeCore => 23,
            Self::Decimal => 24,
            Self::CharCategory => 25,
            Self::CryptoCore => 26,
            Self::Secret => 27,
            Self::Crypto => 28,
            Self::Jwt => 29,
            Self::WasmClient => 30,
            Self::Debugger => 31,
            Self::ControlWire => 32,
            Self::DevPosture => 33,
        }
    }

    /// Variant equality usable in a `const` context (the derived [`PartialEq`]
    /// is not `const`).
    pub(crate) const fn const_eq(self, other: Self) -> bool {
        self.index() == other.index()
    }

    /// One past the greatest [`Self::index`] — the size of the index domain,
    /// derived from the exhaustive `index` match rather than from
    /// [`Self::ALL`]'s length. The `ALL`-coverage seal ([`crate::capabilities`])
    /// checks `ALL` against this domain; deriving the size from `ALL.len()`
    /// instead would be circular, since a variant missing from `ALL` shrinks both
    /// the size and the coverage domain together, hiding the very gap the seal
    /// exists to catch.
    ///
    /// The anchor is the last-declared variant, whose `index` is the greatest.
    /// A new variant declared after it becomes the new anchor here (and the
    /// `index` match refuses to compile until the variant is indexed), so the
    /// domain size grows in lockstep with the variant set and the seal then
    /// forces the variant into `ALL` too.
    pub(crate) const fn index_domain_size() -> usize {
        Self::DevPosture.index() + 1
    }

    /// The exact cargo feature name in `src/runtime/rust/Cargo.toml`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Async => "async",
            Self::DbSqlite => "db-sqlite",
            Self::DbPostgres => "db-postgres",
            Self::Server => "server",
            Self::Web => "web",
            Self::Tui => "tui",
            Self::Webview => "webview",
            Self::WebsocketClient => "websocket_client",
            Self::Email => "email",
            Self::Locale => "locale",
            Self::HttpClient => "http_client",
            Self::Url => "url",
            Self::Config => "config",
            Self::Compression => "compression",
            Self::CsvKernel => "csv_kernel",
            Self::CacheKernel => "cache_kernel",
            Self::Time => "time",
            Self::Encoding => "encoding",
            Self::Regex => "regex",
            Self::Uuid => "uuid",
            Self::Random => "random",
            Self::Log => "log",
            Self::TimeCore => "time-core",
            Self::Decimal => "decimal",
            Self::CharCategory => "char-category",
            Self::CryptoCore => "crypto-core",
            Self::Secret => "secret",
            Self::Crypto => "crypto",
            Self::Jwt => "jwt",
            Self::WasmClient => "wasm-client",
            Self::Debugger => "debugger",
            Self::ControlWire => "control-wire",
            Self::DevPosture => "dev-posture",
        }
    }
}

/// The set of runtime-crate features a program selects. A thin newtype over a
/// sorted, deduplicated [`BTreeSet`] so callers get a canonical, stable
/// `features = [...]` order and cannot construct a set from arbitrary strings.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RuntimeFeatureSet(BTreeSet<RuntimeFeature>);

impl RuntimeFeatureSet {
    /// The selected feature names, canonical order — the `features = [...]`
    /// list a dependency-model manifest would write.
    pub fn as_feature_names(&self) -> Vec<&'static str> {
        self.0.iter().map(|f| f.as_str()).collect()
    }
}

/// The runtime-crate features a program's kernel/surface usage selects.
///
/// This is the SSOT restating the trimming in [`crate::project`] once. Each
/// insertion below pairs one-to-one with an augmenter/append in
/// `assemble_project_files`, keyed to the SAME predicate — so the SSOT and the
/// emitter can never disagree once the emit path reads this (the closure SEAL
/// enforces that the referenced modules are covered).
pub fn runtime_features(ctx: &EmitCtx) -> RuntimeFeatureSet {
    // Browser-WASM: the feature set is EXACTLY the `wasm-client` floor — nothing
    // unioned. This is the genuine wasm-specific divergence from the native
    // reachability map, and it is sound BY CONSTRUCTION:
    //
    //   • `wasm-client` is the closed, SSOT-declared browser floor. It
    //     transitively pulls the whole wasm module set (`json` → `serde`, `url`,
    //     `encoding`, `crypto-core`, `secret`, `regex`, `uuid`, `random`, `log`,
    //     `time`, `decimal`, `char-category`) and its browser-glue crates, so it
    //     already covers every kernel a wasm program can reach.
    //   • The native surface features (`web`/`server`/`http_client`/`async`/
    //     `websocket_client`/…) map to the tokio/axum/reqwest/tokio-tungstenite
    //     stacks, NONE of which compile to `wasm32-unknown-unknown`. Their browser
    //     denotations are the `cfg(target_arch = "wasm32")` arms INSIDE the
    //     `wasm-client` module set (the `web_sys::WebSocket` WS substitute, the
    //     `fetch` HTTP arm, the in-tab pubsub broker), reached WITHOUT their
    //     native feature. Selecting a native surface feature here would link a
    //     tokio backend and break the wasm build (mio has no wasm32 backend).
    //
    // `assert_wasm_admissible` already rejected every non-browser surface
    // upstream, so a wasm program can only reach the browser sink — which the
    // floor covers. This is fail-closed: the floor is always the full wasm set,
    // never a narrowed subset that could drop a reached module.
    if ctx.target == ipe_ir::Target::WasmClient {
        let mut set = BTreeSet::new();
        set.insert(RuntimeFeature::WasmClient);
        // `ipe build/run --debugger --target wasm`: the recorder rides on top of
        // the closed wasm floor. `debugger` implies `json`/`serde`, already in
        // the `wasm-client` floor, and its `async` implication is inert on wasm
        // (tokio is native-only) — the wasm `tea` types come from `wasm-client`.
        if ctx.debugger {
            set.insert(RuntimeFeature::Debugger);
        }
        if ctx.build_intent == crate::BuildIntent::Development {
            set.insert(RuntimeFeature::DevPosture);
        }
        return RuntimeFeatureSet(set);
    }

    // Co-located WASI (`wasm32-wasip1`): the SEALED FLOOR closure. A WASI build
    // reaches ONLY the `Direct`/`Script` sealed floor — the delivery matrix
    // (`admit_triple`) refuses every non-viable shape, and the `available_on`
    // gate refuses every non-viable kernel, upstream of here. So the reachable
    // feature universe is exactly the pure families + the always-on effect floor
    // (`Io`/`File`/`System`/`Task`/`Time`).
    //
    // This arm restates that floor as a POSITIVE, closed selection rather than
    // reusing the native map: the excluded families
    // (`Server`/`Web`/`Tui`/`Webview`/`HttpClient`/`WebsocketClient`/`Db`/
    // `Email`/`Locale`/`Config`/`Compression`/`CsvKernel`/`CacheKernel`/`Crypto`/
    // `Jwt`) map to tokio/axum/reqwest/tokio-tungstenite/`spawn_blocking` stacks
    // that DO NOT build on wasip1. Their `uses_*` flags are already false here
    // (the upstream gates guarantee it), so this is defense in depth: even a
    // mis-set flag cannot select an unbuildable feature and break THE SEAL. The
    // `Async` feature is deliberately omitted — the reactor spine on wasip1 is
    // the std-only `block_on` (no tokio), and `tokio` is `not(wasm32)`-gated in
    // the runtime manifest, so selecting it would be inert at best.
    if ctx.target == ipe_ir::Target::WasmWasi {
        // The wasip1 sealed-floor legal subset: iterate the ONE capability table
        // and keep only the rows a program reaches whose feature is legal on
        // wasip1. Every excluded family (`Server`/`Web`/`Db`/`Async`/…) maps to a
        // stack that does not build on wasip1 and is marked `wasip1_legal: false`,
        // so this filter is the positive, closed legal subset — defense in depth
        // even if an upstream gate mis-set a flag. The `Async` feature is
        // deliberately excluded (`wasip1_legal: false`): the reactor spine on
        // wasip1 is the std-only `block_on`, and `tokio` is `not(wasm32)`-gated.
        let set = crate::capabilities::CAPABILITIES
            .iter()
            .filter(|c| c.wasip1_legal && (c.gate)(ctx))
            .map(|c| (c.select)(ctx))
            .collect();
        return RuntimeFeatureSet(set);
    }

    // Native target: iterate the ONE capability table and select every feature a
    // program reaches. Each row's gate is the SAME `reaches_*` / `uses_*` union
    // the per-surface manifest augmenter and `mod.rs` append in [`crate::project`]
    // key on, so this SSOT and the emitter can never disagree (the closure SEAL
    // enforces the referenced modules are covered). The `Db` row resolves its
    // driver alias (sqlite/postgres) in its `select` closure; the `WasmClient` row
    // never fires here (its gate is the wasm target, handled above). The set is a
    // sorted `BTreeSet`, so the emitted `features = [...]` order is canonical
    // regardless of row order.
    let set = crate::capabilities::CAPABILITIES
        .iter()
        .filter(|c| (c.gate)(ctx))
        .map(|c| (c.select)(ctx))
        .collect();
    RuntimeFeatureSet(set)
}

#[cfg(test)]
mod tests {
    use super::{RuntimeFeature, runtime_features};
    use crate::{DbDriver, RustBackend};
    use ipe_intern::Interner;
    use ipe_ir::{ModPath, Module, Program};

    /// A body-free module with the named `uses_*` flags set. `configure` sets the
    /// surface flags under test; the async spine + tui⇒ui invariants the lowerer
    /// enforces are restored afterwards so the ctx matches a real program.
    fn ctx_module(name: ipe_intern::Symbol, configure: impl FnOnce(&mut Module)) -> Module {
        let mut m = Module {
            name: ModPath(vec![name]),
            types: vec![],
            funcs: vec![],
            entry: None,
            records: vec![],
            uses_tea: false,
            uses_server: false,
            uses_ui: false,
            uses_web: false,
            uses_tui: false,
            uses_console: false,
            uses_webview: false,
            uses_css: false,
            uses_auth: false,
            uses_principal: false,
            uses_websocket: false,
            uses_email: false,
            uses_locale: false,
            uses_time: false,
            uses_env_public: false,
            uses_http: false,
            uses_config: false,
            uses_compression: false,
            uses_csv: false,
            uses_cache: false,
            uses_encoding: false,
            uses_regex: false,
            uses_uuid: false,
            uses_random: false,
            uses_log: false,
            uses_decimal: false,
            uses_char_category: false,
            uses_crypto_core: false,
            uses_secret: false,
            uses_json: false,
            uses_crypto: false,
            uses_jwt: false,
            uses_url: false,
            uses_debug: false,
            uses_ffi: false,
            uses_async_runtime: false,
        };
        configure(&mut m);
        m
    }

    /// Compute the selected feature names for a single-module program via the
    /// real backend's `EmitCtx`, so the SSOT is exercised through the exact ctx
    /// the emitter builds.
    fn features_for(configure: impl FnOnce(&mut Module)) -> Vec<&'static str> {
        let mut interner = Interner::new();
        let main = interner.intern("Main").expect("intern Main");
        let prog = Program {
            imports_unsafe_submodule: false,
            imported_web_capabilities: std::collections::BTreeSet::new(),
            modules: vec![ctx_module(main, configure)],
        };
        let backend = RustBackend::new(&interner);
        let ctx = backend.emit_ctx_for_tests(&prog).expect("build EmitCtx");
        runtime_features(&ctx).as_feature_names()
    }

    /// Compute the selected feature names for a single-module program under the
    /// given target and `--debugger` flag, so the debugger wiring is exercised
    /// through the exact ctx `ipe build/run --debugger` builds.
    fn features_for_target_debugger(
        target: ipe_ir::Target,
        debugger: bool,
        configure: impl FnOnce(&mut Module),
    ) -> Vec<&'static str> {
        let mut interner = Interner::new();
        let main = interner.intern("Main").expect("intern Main");
        let prog = Program {
            imports_unsafe_submodule: false,
            imported_web_capabilities: std::collections::BTreeSet::new(),
            modules: vec![ctx_module(main, configure)],
        };
        let backend = RustBackend::new(&interner)
            .with_target(target)
            .with_debugger(debugger);
        let ctx = backend.emit_ctx_for_tests(&prog).expect("build EmitCtx");
        runtime_features(&ctx).as_feature_names()
    }

    // `ipe build/run --debugger` must make the emitted runtime request the
    // `debugger` feature so the recorder is present; a build WITHOUT the flag
    // must not select it (the recorder stays absent), on both the native and the
    // wasm target.
    #[test]
    fn debugger_flag_selects_debugger_feature_native() {
        let with = features_for_target_debugger(ipe_ir::Target::Native, true, |_| {});
        assert!(
            with.contains(&"debugger"),
            "`--debugger` (native) must select the `debugger` feature: {with:?}"
        );
        let without = features_for_target_debugger(ipe_ir::Target::Native, false, |_| {});
        assert!(
            !without.contains(&"debugger"),
            "a native build without `--debugger` must NOT select it: {without:?}"
        );
    }

    #[test]
    fn debugger_flag_selects_debugger_feature_wasm() {
        let with = features_for_target_debugger(ipe_ir::Target::WasmClient, true, |_| {});
        assert!(
            with.contains(&"debugger"),
            "`--debugger --target wasm` must select the `debugger` feature: {with:?}"
        );
        assert!(
            with.contains(&"wasm-client"),
            "the wasm floor stays present alongside `debugger`: {with:?}"
        );
        let without = features_for_target_debugger(ipe_ir::Target::WasmClient, false, |_| {});
        assert!(
            !without.contains(&"debugger"),
            "a wasm build without `--debugger` must NOT select it: {without:?}"
        );
    }

    /// Compute the selected feature names for an empty program emitted under
    /// `target` with the given build intent.
    fn features_for_intent(
        target: ipe_ir::Target,
        intent: crate::BuildIntent,
    ) -> Vec<&'static str> {
        let mut interner = Interner::new();
        let main = interner.intern("Main").expect("intern Main");
        let prog = Program {
            imports_unsafe_submodule: false,
            imported_web_capabilities: std::collections::BTreeSet::new(),
            modules: vec![ctx_module(main, |_| {})],
        };
        let backend = RustBackend::new(&interner)
            .with_target(target)
            .with_build_intent(intent);
        let ctx = backend.emit_ctx_for_tests(&prog).expect("build EmitCtx");
        runtime_features(&ctx).as_feature_names()
    }

    // A release emit never carries `dev-posture` (the console default stays
    // closed); a dev-verb emit carries it, on every target.
    #[test]
    fn build_intent_selects_dev_posture_on_every_target() {
        for target in [
            ipe_ir::Target::Native,
            ipe_ir::Target::WasmClient,
            ipe_ir::Target::WasmWasi,
        ] {
            let release = features_for_intent(target, crate::BuildIntent::Release);
            assert!(
                !release.contains(&"dev-posture"),
                "a release emit ({target:?}) must NOT select `dev-posture`: {release:?}"
            );
            let dev = features_for_intent(target, crate::BuildIntent::Development);
            assert!(
                dev.contains(&"dev-posture"),
                "a development emit ({target:?}) must select `dev-posture`: {dev:?}"
            );
        }
    }

    // An emit whose caller states no intent is a release emit.
    #[test]
    fn unstated_intent_omits_dev_posture() {
        let features = features_for(|_| {});
        assert!(
            !features.contains(&"dev-posture"),
            "the default backend intent must be Release: {features:?}"
        );
    }

    /// Compute the selected feature names with the `hot_appearance` dev flag armed
    /// (as `ipe watch` sets it) so the `control-wire` selection row is exercised
    /// through the exact ctx a watch build produces.
    fn features_for_hot(configure: impl FnOnce(&mut Module)) -> Vec<&'static str> {
        let mut interner = Interner::new();
        let main = interner.intern("Main").expect("intern Main");
        let prog = Program {
            imports_unsafe_submodule: false,
            imported_web_capabilities: std::collections::BTreeSet::new(),
            modules: vec![ctx_module(main, configure)],
        };
        let backend = RustBackend::new(&interner).with_hot_appearance(true);
        let ctx = backend.emit_ctx_for_tests(&prog).expect("build EmitCtx");
        runtime_features(&ctx).as_feature_names()
    }

    // A tui view under `ipe watch` (`hot_appearance` armed) selects `control-wire`
    // so the loopback control server is present to push appearance patches to; a
    // plain build (no dev flag) selects it not — the release-absence proof.
    #[test]
    fn watch_tui_selects_control_wire() {
        let watch = features_for_hot(|m| {
            m.uses_tui = true;
            m.uses_ui = true;
            m.uses_async_runtime = true;
        });
        assert!(
            watch.contains(&"control-wire"),
            "an `ipe watch` tui build must select `control-wire`: {watch:?}"
        );
    }

    /// The release-absence proof: a plain `ipe build` / `ipe release` of the same
    /// tui view arms no dev flag, so `control-wire` is absent — the control server
    /// never ships in a production terminal artifact (dev == prod by absence).
    #[test]
    fn plain_build_tui_selects_no_control_wire() {
        let plain = features_for(|m| {
            m.uses_tui = true;
            m.uses_ui = true;
            m.uses_async_runtime = true;
        });
        assert!(
            !plain.contains(&"control-wire"),
            "a plain (non-watch) tui build must NOT select `control-wire`: {plain:?}"
        );
    }

    /// A cli (`Cli.tea`, `uses_console`) under `ipe watch` selects `control-wire`
    /// NOT: a line-oriented transcript has no repaintable appearance surface, and
    /// its dev-loop debugger records to the `IPE_DEBUGGER_RECORD` dump rather than
    /// driving the control socket. The row is the pure-`hot_appearance` tui
    /// selector; console is excluded from it.
    #[test]
    fn watch_cli_selects_no_control_wire() {
        let watch = features_for_hot(|m| {
            m.uses_console = true;
            m.uses_ui = true;
            m.uses_async_runtime = true;
        });
        assert!(
            !watch.contains(&"control-wire"),
            "an `ipe watch` cli build must NOT select `control-wire` (no repaintable \
             surface): {watch:?}"
        );
    }

    #[test]
    fn hello_world_selects_no_features() {
        // A pure program (no surface, no reactor, no Json type) selects NOTHING;
        // the emitted crate carries no `serde_json` and no serde stack, leaving
        // `app + ipe_runtime + rustix`.
        assert!(
            features_for(|_| {}).is_empty(),
            "a bare program selects no runtime feature: {:?}",
            features_for(|_| {})
        );
    }

    #[test]
    fn json_type_mention_selects_json() {
        // A program that NAMES the `Value`/`Decoder` type (here via the
        // `uses_json` flag the lowerer sets from a type-mention or Json kernel)
        // keeps `json` — the fail-closed case the two prelude aliases need.
        let f = features_for(|m| {
            m.uses_json = true;
        });
        assert_eq!(
            f,
            vec!["json"],
            "a Json-naming program selects `json`: {f:?}"
        );
    }

    #[test]
    fn tui_selects_tui_and_async() {
        let f = features_for(|m| {
            m.uses_tui = true;
            m.uses_ui = true;
            m.uses_async_runtime = true;
        });
        assert!(f.contains(&"tui"), "tui program selects `tui`: {f:?}");
        assert!(f.contains(&"async"), "tui program selects `async`: {f:?}");
        // `tui` does NOT list `json` in the crate graph, and this program names no
        // `Value`/`Decoder` type — so `json` (demoted from the floor) is dropped.
        assert!(
            !f.contains(&"json"),
            "a bare tui program drops `json`: {f:?}"
        );
    }

    #[test]
    fn cli_selects_tui() {
        // A `Cli.tea` (line-oriented) program renders its `Lines msg` view
        // through the terminal runtime module, so it selects the same `tui`
        // Cargo feature as a full-screen `Tui.tea` — the two drive axes share
        // one runtime module.
        let f = features_for(|m| {
            m.uses_console = true;
            m.uses_ui = true;
            m.uses_async_runtime = true;
        });
        assert!(f.contains(&"tui"), "a Cli program selects `tui`: {f:?}");
    }

    #[test]
    fn web_selects_server_without_outbound_http() {
        // A web program reaches server (axum) but makes no outbound request: with
        // no `Ipe.Http` kernel and no email it does not link the reqwest client,
        // so `http_client` — and the `url` parser that only rides along with it —
        // are both dropped. `server`, `async`, and `json` remain.
        let f = features_for(|m| {
            m.uses_web = true;
            m.uses_async_runtime = true;
        });
        for want in ["web", "server", "async", "json"] {
            assert!(f.contains(&want), "web program must select `{want}`: {f:?}");
        }
        for reject in ["http_client", "url", "tui"] {
            assert!(
                !f.contains(&reject),
                "a web program with no outbound HTTP must not select `{reject}`: {f:?}"
            );
        }
    }

    #[test]
    fn http_client_only_selects_encoding() {
        // A bare `Ipe.Http` client (no server/web/db surface) still reaches
        // `http_client.rs`, which decodes query pairs through `encoding.rs`.
        // Dropping `encoding` here ships a program whose `cargo build` fails on
        // an unresolved `decode_form_query` — the forbidden under-inclusion.
        // `encoding` must ride along with `http_client`.
        let f = features_for(|m| {
            m.uses_http = true;
            m.uses_async_runtime = true;
        });
        assert!(
            f.contains(&"http_client"),
            "http program selects `http_client`: {f:?}"
        );
        assert!(
            f.contains(&"encoding"),
            "http_client decodes queries → must select `encoding`: {f:?}"
        );
        assert!(
            !f.contains(&"server"),
            "a bare client must not select `server`: {f:?}"
        );
    }

    #[test]
    fn websocket_pulls_url_but_not_http_client() {
        // The WS client parses URLs (via `url`) but does not link the reqwest
        // HTTP stack — the option-B split the crate features encode.
        let f = features_for(|m| {
            m.uses_websocket = true;
            m.uses_async_runtime = true;
        });
        assert!(f.contains(&"websocket_client"), "{f:?}");
        assert!(f.contains(&"url"), "ws client selects `url`: {f:?}");
        assert!(
            !f.contains(&"http_client"),
            "ws client must NOT select `http_client`: {f:?}"
        );
    }

    #[test]
    fn auth_reaches_jwt_and_crypto_core() {
        // `Ipe.Auth` reaches `jwt`; `jwt` implies `crypto` in the crate graph,
        // so the RSA (crypto_core heavy) arm the RS256 path needs is enabled.
        let f = features_for(|m| {
            m.uses_auth = true;
            m.uses_async_runtime = true;
        });
        assert!(f.contains(&"jwt"), "auth reaches `jwt`: {f:?}");
        assert!(
            !f.contains(&"crypto"),
            "auth need not select heavy `crypto` directly — `jwt` implies it: {f:?}"
        );
    }

    #[test]
    fn db_sqlite_vs_postgres_selects_the_driver_alias() {
        let mut interner = Interner::new();
        let main = interner.intern("Main").expect("intern Main");
        // The db flag is derived from an injected SqlValue enum, not a bare
        // `uses_*` — drive it through the driver-aware backend instead.
        for (driver, want) in [
            (DbDriver::Sqlite, "db-sqlite"),
            (DbDriver::Postgres, "db-postgres"),
        ] {
            let prog = Program {
                imports_unsafe_submodule: false,
                imported_web_capabilities: std::collections::BTreeSet::new(),
                modules: vec![db_module(&mut interner, main)],
            };
            let backend = RustBackend::new(&interner).with_db_driver(driver);
            let ctx = backend.emit_ctx_for_tests(&prog).expect("build EmitCtx");
            let f = super::runtime_features(&ctx).as_feature_names();
            assert!(f.contains(&want), "{driver:?} selects `{want}`: {f:?}");
            let other = if want == "db-sqlite" {
                "db-postgres"
            } else {
                "db-sqlite"
            };
            assert!(
                !f.contains(&other),
                "{driver:?} selects exactly one driver alias, not `{other}`: {f:?}"
            );
        }
    }

    /// A module carrying the injected `SqlValue` enum the backend reads to set
    /// `uses_db` — the same signal a real Db program lowers to.
    fn db_module(interner: &mut Interner, name: ipe_intern::Symbol) -> Module {
        use ipe_ir::{EnumDef, TypeDef};
        let sqlvalue = interner.intern("SqlValue").expect("intern SqlValue");
        let mut m = ctx_module(name, |m| {
            m.uses_async_runtime = true;
        });
        m.types.push(TypeDef::Enum(EnumDef {
            name: sqlvalue,
            home: ModPath(vec![name]),
            variants: vec![],
            type_params: vec![],
        }));
        m
    }

    #[test]
    fn every_variant_maps_to_a_distinct_nonempty_name() {
        // The variant→name map is total and injective (no two features share a
        // cargo name, none empty).
        let all = [
            RuntimeFeature::Json,
            RuntimeFeature::Async,
            RuntimeFeature::DbSqlite,
            RuntimeFeature::DbPostgres,
            RuntimeFeature::Server,
            RuntimeFeature::Web,
            RuntimeFeature::Tui,
            RuntimeFeature::Webview,
            RuntimeFeature::WebsocketClient,
            RuntimeFeature::Email,
            RuntimeFeature::HttpClient,
            RuntimeFeature::Url,
            RuntimeFeature::Config,
            RuntimeFeature::Compression,
            RuntimeFeature::CsvKernel,
            RuntimeFeature::CacheKernel,
            RuntimeFeature::Time,
            RuntimeFeature::Decimal,
            RuntimeFeature::CharCategory,
            RuntimeFeature::Crypto,
            RuntimeFeature::Jwt,
            RuntimeFeature::WasmClient,
        ];
        let mut seen = std::collections::BTreeSet::new();
        for f in all {
            assert!(!f.as_str().is_empty(), "empty name for {f:?}");
            assert!(seen.insert(f.as_str()), "duplicate name {}", f.as_str());
        }
    }
}
