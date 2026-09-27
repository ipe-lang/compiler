//! The typed IR node definitions. The surface is deliberately narrow so that
//! every constructible value is a well-formed program fragment.

use std::collections::{BTreeMap, BTreeSet};

use ipe_diagnostics::{DResult, Diagnostic};
use ipe_intern::Symbol;

/// A dotted module path, e.g. `Main` or `Ipe.Io`, as interned segments in
/// source order.
#[derive(
    Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, serde::Serialize, serde::Deserialize,
)]
pub struct ModPath(pub Vec<Symbol>);

/// A function identifier, unique within a [`Program`].
#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, serde::Serialize, serde::Deserialize,
)]
pub struct FuncId(pub u32);

impl FuncId {
    #[must_use]
    pub const fn from_raw(n: u32) -> Self {
        Self(n)
    }

    #[must_use]
    pub const fn as_raw(self) -> u32 {
        self.0
    }
}

/// A whole compiled program: an ordered list of modules.
//
// `Eq` is not derived: a module's functions hold [`Expr`] bodies that may carry
// a float literal (only `PartialEq`).
#[derive(Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
pub struct Program {
    pub modules: Vec<Module>,
    /// `true` when the program's source imported at least one `Ipe.<M>.Unsafe`
    /// submodule — the import-derived signal that discloses the `unsafe`
    /// capability. Carried whole-program (not per module) because the import is
    /// the reviewable act regardless of which module reached for the hatch; set
    /// by the lowerer from the canonical module's `imports_unsafe_submodule`
    /// fact and read by `program_capabilities_scan`.
    pub imports_unsafe_submodule: bool,
    /// The web capabilities the program disclosed by importing reserved
    /// `Ipe.Browser.<Api>` submodules — an import-derived, whole-program fact
    /// (not per module, not a kernel visit), union-folded across every linked
    /// module by `ipe_canon::link` and threaded here by the lowerer. Read by
    /// `program_capabilities_scan`, which inserts one `Capability::JsPort(w)` per
    /// member so a browser import discloses its specific `js-port:<axis>` axis on
    /// top of the raw kernel floor. Importing the module is the signal, regardless
    /// of dead code.
    pub imported_web_capabilities: BTreeSet<ipe_kernels::WebCapability>,
}

/// A single module: its declared types and functions, plus an optional entry
/// point (the `main` function, when this module carries it).
//
// `Eq` is not derived: `funcs` hold [`Expr`] bodies that may carry a float
// literal (only `PartialEq`).
#[derive(Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct Module {
    pub name: ModPath,
    pub types: Vec<TypeDef>,
    pub funcs: Vec<Func>,
    pub entry: Option<FuncId>,
    /// Every CLOSED record shape the module's expressions construct or read,
    /// each an [`IrType::Record`]. The lowerer surfaces these (it alone has the
    /// solved types) so the backend can synthesise one Rust struct per shape —
    /// record literals live inside function bodies, where the type does not
    /// otherwise appear in a signature. Non-record entries are ignored by the
    /// backend, so the field stays robust to a stray shape.
    pub records: Vec<IrType>,
    /// `true` when the lowerer detected at least one TEA kernel call
    /// (`Cmd.none / batch / perform`, `Sub.none / batch / every`, `Time.every`)
    /// in the module's function bodies.
    ///
    /// Set by `ipe_lower::lower::Lowerer::run` when any call site resolves to a
    /// `KernelFn::is_tea()` variant.  The backend reads this flag to decide
    /// whether to append `pub mod tea; pub use tea::*;` to the emitted
    /// `ipe_runtime/mod.rs` and to add `IpeCmd` / `IpeSub` type aliases.
    pub uses_tea: bool,
    /// `true` when the lowerer detected at least one Ipe.Http.Server kernel call
    /// (`Server.get/post/put/delete/any/api/static/listen`, response builders,
    /// extractors, cookie helpers, middleware, `RateLimit.allow`) in the module's
    /// function bodies.
    ///
    /// Set by `ipe_lower::lower::Lowerer::run` when any call site resolves to a
    /// `KernelFn::is_server()` variant.  The backend reads this flag to decide
    /// whether to inject the `server` feature in the emitted `Cargo.toml` and to
    /// append `pub mod server; pub use server::*; pub mod server_stream; pub use
    /// server_stream::*;` to the emitted `ipe_runtime/mod.rs`.
    pub uses_server: bool,
    /// `true` when the lowerer detected at least one outbound `Ipe.Http` client
    /// kernel call (`Http.get` / `post` / `request`, the pure request/method
    /// builders, `Http.parseQuery`) — or a function signature mentioning
    /// `HttpRequest` / `HttpMethod` — in the module.
    ///
    /// Set by `ipe_lower` when any call site resolves to a
    /// `KernelFn::is_http_client()` variant (or a signature mentions an
    /// `http_client`-owned opaque type). The backend reads this flag to decide
    /// whether to declare `pub mod http_client; pub use http_client::*;` in the
    /// emitted `ipe_runtime/mod.rs`, add the `reqwest` dependency, and keep the
    /// `http_client` kernel-wrapper prelude bindings. The `url` crate stays
    /// unconditional (it backs the always-present `Ipe.Url` and `ssrf`
    /// surfaces), so only the reqwest HTTP stack is gated here.
    pub uses_http: bool,
    /// `true` when the lowerer detected at least one `Ipe.Config` decoder that
    /// emits into the `config_decode` runtime module — `Config.decodeToml` /
    /// `decodeYaml` / `decodeJson` / `loadFromFile`, or the `config_decode`-own
    /// `nullable` / `maybe` / `dict` combinators.
    ///
    /// Set by `ipe_lower` when any call site resolves to a
    /// `KernelFn::is_config()` variant. The backend reads this flag to decide
    /// whether to declare `pub mod config_decode; pub use config_decode::*;` in
    /// the emitted `ipe_runtime/mod.rs` and add the `toml` + `serde_yaml`
    /// dependencies. The JSON-backed `Config.*` combinators (`string` / `field`
    /// / `map` / …) emit into the `json` module and do NOT set this
    /// flag, so a JSON-only program pulls neither crate.
    pub uses_config: bool,
    /// `true` when the lowerer detected at least one `Ipe.Compression` kernel
    /// call (`Compression.gzip` / `gunzip` / `zstdCompress` / `zstdDecompress`).
    ///
    /// Set by `ipe_lower` when any call site resolves to a
    /// `KernelFn::is_compression()` variant. The backend reads this flag to
    /// decide whether to declare `pub mod compression; pub use compression::*;`
    /// in the emitted `ipe_runtime/mod.rs` and add the `flate2` + `zstd`
    /// dependencies. `compression` is a leaf module — no other runtime surface
    /// reaches it — so no other `uses_*` flag forces it on.
    pub uses_compression: bool,
    /// `true` when the lowerer detected at least one `Ipe.Csv` kernel call
    /// (`Csv.parse` / `parseWithDelimiter` / `encode` / `encodeWithDelimiter` /
    /// `parseStreamFromFile`), OR a function signature mentioning the `CsvDoc`
    /// opaque type.
    ///
    /// Set by `ipe_lower` when any call site resolves to a `KernelFn::is_csv()`
    /// variant, or a signature mentions `CsvDoc` (a bare `{ header, rows }`
    /// record shape folds to it). The backend reads this flag to decide whether
    /// to declare `pub mod csv; pub use csv::*;` in the emitted
    /// `ipe_runtime/mod.rs` and add the `csv` dependency. `csv` is a leaf module
    /// — no other runtime surface reaches it — so no other `uses_*` flag forces
    /// it on.
    pub uses_csv: bool,
    /// `true` when the lowerer detected an `Ipe.Cache` kernel
    /// (`KernelFn::is_cache()`), or a signature/record/enum mentions the folded
    /// `CacheCfg` / `CacheStats` config-and-stats record types. The backend reads
    /// this flag to declare `pub mod cache; pub use cache::*;` in the emitted
    /// `ipe_runtime/mod.rs` and enable the `cache_kernel` runtime-crate feature
    /// (which provides `cache_new_raw` / `cache_get` / `cache_put` / …, the
    /// `CacheCfg` / `CacheStats` structs, and the `IpeCacheHandle` enum the
    /// emitted code references). `cache` is a leaf module — no other runtime
    /// surface reaches it — so no other `uses_*` flag forces it on. The
    /// type-mention guard mirrors `uses_csv`'s `CsvDoc` guard: `Cache.defaultCfg`
    /// and the `with*` builders are pure Ipê source producing `CacheCfg` record
    /// literals with no kernel call, so a config-only program still names the type
    /// and needs the module.
    pub uses_cache: bool,
    /// `true` when the lowerer detected at least one `Ipe.Encoding` codec kernel
    /// (`base64Encode` / `base64Decode` / `urlEncode` / `urlDecode` / `hexEncode`
    /// / `hexDecode`) or any `Ipe.Bytes` kernel.
    ///
    /// Set by `ipe_lower` when any call site resolves to a
    /// `KernelFn::is_encoding()` variant. The backend reads this flag to declare
    /// `pub mod encoding;` + `pub mod bytes;` in the emitted `ipe_runtime/mod.rs`
    /// and add the `base64` + `hex` + `percent-encoding` dependencies. Those three
    /// crates are also reached by the `crypto` / `db` / `server` / `email` / `jwt`
    /// / `web` surfaces (whose runtime modules use the raw crates directly), so
    /// the backend force-declares `encoding` under `reaches_encoding()` — the
    /// union of this flag with those surfaces.
    pub uses_encoding: bool,
    /// `true` when the lowerer detected an `Ipe.Regex` kernel or `String.isUrl`
    /// (`KernelFn::is_regex()`). The backend reads this to declare
    /// `pub mod regex_kernel;` in the emitted `ipe_runtime/mod.rs` and add the
    /// `regex` dependency (with its `aho-corasick` / `regex-automata` /
    /// `regex-syntax` subtree). `regex` is a standalone leaf — no other surface
    /// reaches it — so this flag alone gates it. A program that reaches neither an
    /// `Ipe.Regex` kernel nor `String.isUrl` drops all four crates.
    pub uses_regex: bool,
    /// `true` when the lowerer detected an `Ipe.Uuid` kernel
    /// (`KernelFn::is_uuid()`). The backend reads this to declare
    /// `pub mod uuid_kernel;` and add the `uuid` dependency. The `server` and
    /// `web` surfaces also draw session/CSRF ids from `uuid::new_v4` directly, so
    /// the backend force-declares `uuid` under `reaches_uuid()` — the union of
    /// this flag with those two surfaces. A bare Program that reaches none drops
    /// the crate.
    pub uses_uuid: bool,
    /// `true` when the lowerer detected an `Ipe.Random` kernel
    /// (`KernelFn::is_random()`). The backend reads this to declare
    /// `pub mod random;` in the emitted `ipe_runtime/mod.rs`. `random` is a
    /// standalone leaf — no other surface reaches it — so this flag alone gates
    /// the module. The `random` feature gates only the module declaration, NOT the
    /// `getrandom` crate (which the `crypto_core` floor keeps present);
    /// a program that reaches no `Ipe.Random` kernel drops the `random.rs` module.
    pub uses_random: bool,
    /// `true` when the lowerer detected an `Ipe.Log` kernel
    /// (`KernelFn::is_log()`). The backend reads this to declare `pub mod log;`
    /// behind the `log` feature and add `chrono` (via `log = ["dep:chrono"]`).
    /// `log.rs` is the sole always-emittable consumer of `chrono` (its
    /// RFC3339-nano timestamp). A program that reaches no `Log.*` kernel — and no
    /// Time/Db/Web/WebView surface, which reach `chrono` via `time-core` — drops
    /// `chrono`. `Debug.log` does NOT set this flag (`debug.rs` is a pure,
    /// always-compiled `IpeStringify` passthrough with no `chrono`).
    pub uses_log: bool,
    /// `true` when the lowerer detected an `Ipe.Decimal` or `Ipe.Money` kernel
    /// (`KernelFn::is_decimal()`). The backend reads this to declare the
    /// `decimal.rs` / `money.rs` modules behind the `decimal` feature and add the
    /// `rust_decimal` crate (with its `arrayvec` subtree). `money.rs` builds on
    /// `decimal.rs`'s `Decimal` newtype, so both modules gate together. The `Db`
    /// surface decodes numeric SQL columns through `rust_decimal`, so the backend
    /// keeps `decimal` under `uses_decimal || uses_db`; a program that reaches
    /// neither a `Decimal.*`/`Money.*` kernel nor a `Db` surface drops the crate.
    pub uses_decimal: bool,
    /// `true` when the lowerer detected an `Ipe.Char` `General_Category` predicate
    /// (`isAlpha`/`isDigit`/`isLower`/`isUpper`/`isAlphaNum`,
    /// `KernelFn::is_char_category()`). The backend reads this to declare the
    /// `char_category.rs` module behind the `char-category` feature and add the
    /// `unicode-general-category` crate. A standalone leaf — no surface implies it.
    /// A program that reaches only the std-only `Ipe.Char` kernels (or none) drops
    /// the crate; those std kernels stay in the always-compiled `char_kernel.rs`.
    pub uses_char_category: bool,
    /// `true` when the lowerer detected at least one crypto-FLOOR kernel call
    /// (SHA-2 hash, the HMAC family, RSA sign/verify, constant-time compare, the
    /// entropy pair, or a `Key`/`Mac` newtype kernel).
    ///
    /// Set by `ipe_lower` when any call site resolves to a
    /// `KernelFn::is_crypto_core()` variant. The backend folds this flag with the
    /// crypto/jwt/db/web/webview/email/server surfaces (`reaches_crypto_core`) to
    /// select the `crypto-core` runtime feature — `crypto_core.rs` plus its
    /// `sha2`, `hmac`, `subtle`, and `getrandom` dependencies. A program that
    /// reaches none of these drops the module and that whole dependency subtree.
    pub uses_crypto_core: bool,
    /// `true` when the lowerer detected at least one `Ipe.Secret` kernel call
    /// (`Secret.fromString`/`reveal`/`redacted`) OR a `Secret`-typed value in a
    /// function signature.
    ///
    /// Set by `ipe_lower` (call site via `KernelFn::is_secret()`, or the
    /// `Secret` type-mention guard). The backend reads this flag to select the
    /// `secret` runtime feature — `secret.rs` plus its `zeroize` dependency (and,
    /// via the shared `subtle`, `crypto-core`). A program that reaches no `Secret`
    /// kernel and holds no `Secret` value drops the module and `zeroize`.
    pub uses_secret: bool,
    /// `true` when the emitted crate names the `Value` (`JsonVal`) or `Decoder<T>`
    /// type — the two the fixed prelude aliases as `type Value = JsonVal;` and
    /// `pub type Decoder<T> = ipe_runtime::json::Decoder<IpeError, T>`, both
    /// hard-referencing the `json` runtime module (`serde_json`).
    ///
    /// Set by `ipe_lower` as the union of a call-site signal (any
    /// `KernelFn::is_json()` variant — a `JsonEnc`/`JsonDec`/`Config`-decoder/
    /// `Db.Decode`/`Server.json` kernel that builds a `Value`/`Decoder` value in a
    /// body) and a TYPE-MENTION scan: any `Json` or `Decoder` type in a function
    /// signature, a record field, or an enum-variant payload. The type-mention
    /// guard is REQUIRED — a signature can name `Value`/`Decoder` (e.g. a decoder
    /// forwarded as a parameter) with no `Json.*` call site, so dropping the
    /// aliases on the call-site flag alone would emit a signature referencing an
    /// absent `JsonVal` / `ipe_runtime::json::Decoder` (E0412 / E0433). The
    /// backend reads this flag (`reaches_json`) to keep both prelude aliases and
    /// select the `json` feature; a program that reaches neither drops the
    /// aliases, `serde_json`, and the whole serde stack. FAIL-CLOSED: any
    /// uncertain `json` consumer keeps the feature on.
    pub uses_json: bool,
    /// `true` when the lowerer detected at least one HEAVY `Ipe.Crypto` kernel
    /// call (legacy SHA-1/MD5, AES-GCM / ChaCha20-Poly1305 AEAD, or PBKDF2
    /// key derivation).
    ///
    /// Set by `ipe_lower` when any call site resolves to a
    /// `KernelFn::is_crypto()` variant. The backend reads this flag to decide
    /// whether to declare `pub mod crypto; pub use crypto::*;` in the emitted
    /// `ipe_runtime/mod.rs` and add the `sha1` + `md-5` + `aes-gcm` +
    /// `chacha20poly1305` + `pbkdf2` dependencies. The `crypto` feature implies
    /// `crypto-core`, so the floor (SHA-2, HMAC, RSA, constant-time compare, the
    /// entropy pair, the `Key`/`Mac` newtypes) rides along transitively.
    pub uses_crypto: bool,
    /// `true` when the lowerer detected at least one `Ipe.Jwt` kernel call
    /// (`Jwt.encodeHs256` / `decodeHs256` / … or a builder-API kernel).
    ///
    /// Set by `ipe_lower` when any call site resolves to a
    /// `KernelFn::is_jwt()` variant. The backend reads this flag to decide
    /// whether to declare `pub mod jwt; pub use jwt::*;` in the emitted
    /// `ipe_runtime/mod.rs` and add the `jsonwebtoken` dependency. `auth.rs`
    /// also reaches `crate::jwt`, so the backend force-declares `jwt` under
    /// `uses_jwt || uses_auth`.
    pub uses_jwt: bool,
    /// `true` when the lowerer detected at least one `Ipe.Url` kernel call
    /// (`Url.fromString` / `toString` / `scheme` / `host` / `port` / `path` /
    /// `query` / `fragment` / `buildQuery`) in the module's function bodies.
    ///
    /// Set by `ipe_lower` when any call site resolves to a
    /// `KernelFn::is_url()` variant. The backend reads this flag to decide
    /// whether to declare `pub mod url; pub use url::*;` in the emitted
    /// `ipe_runtime/mod.rs` and add the `url` crate (with its `idna` → ICU4X
    /// subtree). The `http_client` / `ws_client` modules (and the shared `ssrf`
    /// validators) also reach the `url` crate, so the backend force-declares
    /// `url` under `uses_url || reaches_http_client || uses_websocket`.
    pub uses_url: bool,
    /// `true` when the lowerer detected at least one `Ipe.Ui` / `Ipe.Html`
    /// kernel call (`Ui.layout`, `Ui.layoutWith`, `Html.render`, etc.) in the
    /// module's function bodies.
    ///
    /// Set by `ipe_lower` when any call site resolves to a
    /// `KernelFn::is_ui()` variant.  The backend reads this flag to decide
    /// whether to add `pub mod ui;` to the emitted `ipe_runtime/mod.rs`.
    pub uses_ui: bool,
    /// `true` when the lowerer detected at least one `Ipe.Web` / `Ipe.Web`
    /// kernel call (`Web.tea`, `Web.appRouted`, `Web.route`, etc.) in the
    /// module's function bodies.
    ///
    /// Set by `ipe_lower` when any call site resolves to a
    /// `KernelFn::is_web()` variant.
    pub uses_web: bool,
    /// `true` when the lowerer detected the `Ipe.Terminal` full-screen
    /// app-entry (`Tui.tea`) in the module's function bodies.
    ///
    /// Set by `ipe_lower` when any call site resolves to a
    /// `KernelFn::is_tui()` variant.
    pub uses_tui: bool,
    /// `true` when the lowerer detected the `Ipe.Terminal` line-oriented
    /// app-entry (`Cli.tea`) in the module's function bodies.
    ///
    /// Set by `ipe_lower` when any call site resolves to a
    /// `KernelFn::is_console()` variant.
    pub uses_console: bool,
    /// `true` when the emit targets the webview-native host. No source kernel
    /// sets this: the webview delivery is a HOST decision (`web desktop`)
    /// threaded from the CLI into the backend, not a distinct source entry, so
    /// `ipe_lower` always leaves this `false`. The backend ORs it with its
    /// resolved `webview_host` signal to select the webview executor and the
    /// `webview` runtime feature; kept here for the backend consumers that key
    /// on it. Implies `uses_web` for the runtime dependency chain.
    pub uses_webview: bool,
    /// `true` when the lowerer detected at least one `Ipe.CssSafety`
    /// leaf security kernel (`CssSafety.safeValue` / `safePropName` /
    /// `safeSelector` / `stripStyleClose` — the `Ipe.Css` backing) in the
    /// module's function bodies.
    ///
    /// Set by `ipe_lower` when any call site resolves to a
    /// `KernelFn::is_css()` variant.  The backend reads this flag to decide
    /// whether to declare `css_safety` / `css` (`pub use css::*`) in the emitted
    /// `ipe_runtime/mod.rs` even when `uses_ui` is `false` — a pure `Ipe.Css`
    /// program uses the css kernels without any `Ipe.Ui` / `Ipe.Html` render
    /// kernel, so the UI append would never fire and the bare kernel names would
    /// be out of scope (E0425).
    pub uses_css: bool,
    /// `true` when the lowerer detected at least one `Ipe.Auth` kernel call
    /// (`Auth.hashPassword`, `Auth.verifyPassword`, `Auth.signToken`,
    /// `Auth.verifyToken`, `Auth.register`, `Auth.login`, `Auth.setRole`, etc.)
    /// in the module's function bodies.
    ///
    /// Set by `ipe_lower` when any call site resolves to a
    /// `KernelFn::is_auth()` variant.  The backend reads this flag to decide
    /// whether to append `pub mod auth; pub use auth::*;` to the emitted
    /// `ipe_runtime/mod.rs`.
    pub uses_auth: bool,
    /// `true` when the lowerer detected an `Ipe.Auth.subject` call (any kernel
    /// that touches the opaque `Principal` runtime type).
    ///
    /// The backend reads this flag to append `pub mod principal;` to the emitted
    /// `ipe_runtime/mod.rs` so the `Principal` type + `principal_subject`
    /// accessor resolve.
    pub uses_principal: bool,
    /// `true` when the lowerer detected at least one outbound
    /// `Ipe.WebSocket` client kernel call (`WebSocket.connect` /
    /// `connectWith` / `send` / `sendBinary` / `close` / `closeWithCode`, or an
    /// `onOpen` / `onMessage` / `onClose` / `onError` subscription).
    ///
    /// Set by `ipe_lower` when any call site resolves to a
    /// `KernelFn::is_websocket_client()` variant.  The backend reads this flag
    /// to add the `websocket_client` feature to the emitted `Cargo.toml` (plus
    /// the `tokio-tungstenite` dep) and to append `pub mod ws_client; pub use
    /// ws_client::*;` to the emitted `ipe_runtime/mod.rs` — the `ws_client`
    /// runtime module is feature-gated and NOT part of the base module set.
    pub uses_websocket: bool,
    /// `true` when the lowerer detected at least one `Ipe.Email` kernel call
    /// (`Email.send`, `EmailAddress.parse`, `EmailAddress.toString`) in the
    /// module's function bodies, OR any emittable type position that mentions
    /// an `Ipe.Email` runtime type (`EmailAddress`, `EmailMessage`, `EmailProvider`,
    /// etc.).
    ///
    /// The backend reads this flag to decide whether to append `pub mod email;
    /// pub use email::*;` to the emitted `ipe_runtime/mod.rs` and to add the
    /// `lettre` dependency to the emitted `Cargo.toml`. The type-mention guard
    /// is required: a program that only names `EmailAddress` in a signature
    /// (without calling `Email.send`) still emits a reference to
    /// `ipe_runtime::email::EmailAddress`, which resolves only when the module
    /// is declared.
    pub uses_email: bool,
    /// `true` when the lowerer detected at least one `Ipe.Locale` kernel call
    /// (`Locale.fromTag`, `Locale.toTag`, `String.toUpperIn`, `String.toLowerIn`)
    /// in the module's function bodies, OR any emittable type position that
    /// mentions `IrType::Locale`.
    ///
    /// The backend reads this flag to append `pub mod locale; pub use locale::*;`
    /// to the emitted `ipe_runtime/mod.rs` and to enable the `locale` Cargo
    /// feature (`icu_casemap` + `icu_locale_core`). Without the feature,
    /// `locale_from_tag` compiles but always returns `Nothing`; the type-mention
    /// guard ensures the module is declared whenever the type appears.
    pub uses_locale: bool,
    /// `true` when the lowerer detected at least one non-TEA `Ipe.Time` kernel
    /// call (`Time.now` / `unixMillis` / `sleep` / `timeString` / `isLeapYear` /
    /// `daysInMonth`) in the module's function bodies.
    ///
    /// Set by `ipe_lower` when any call site resolves to a `KernelFn::is_time()`
    /// variant. The backend reads this flag to enable the `time` Cargo feature
    /// and add the `chrono-tz` dependency — the IANA-zone calendar surface of the
    /// always-declared `time` runtime module, gated behind that feature. A
    /// program that reaches no `Ipe.Time` kernel drops the crate. The `chrono`
    /// core crate (reached by the `log`/`db`/`web`/`telemetry` timestamp
    /// surfaces) is gated separately by `time-core`/`log`, not by this flag.
    /// `Time.every` is TEA,
    /// tracked by `uses_tea`.
    pub uses_time: bool,
    /// `true` when the lowerer detected the `Ipe.Env` `Env.public` kernel
    /// call in the module's function bodies.
    ///
    /// Set by `ipe_lower` when a call site resolves to `KernelFn::EnvPublic`.
    /// The backend reads this flag to decide whether to emit the per-project
    /// `env_public.rs` (built from `package.ipe`'s `[wasm] publicEnv` allowlist)
    /// and append `pub mod env_public; pub use env_public::*;` to the
    /// emitted `ipe_runtime/mod.rs`.
    pub uses_env_public: bool,
    /// `true` when the lowerer detected at least one development-only
    /// `Debug.*` escape-hatch call (`Debug.log`) in the module's function
    /// bodies. Set unconditionally (regardless of build profile) at the same
    /// choke point as the other `uses_*` flags; a PRODUCTION build
    /// (`ipe release`) reads it at emit demand to reject the program
    /// (IPE-L0140), while a development build ignores it.
    pub uses_debug: bool,
    /// `true` when the lowerer lowered at least one [`Callee::Ffi`] call —
    /// a foreign-crate wrapper forwarder from a driver-generated FFI
    /// interface module. The backend reads this flag to declare `mod ffi;`
    /// in the emitted crate root and to append the bound crates'
    /// `[dependencies]` lines to the emitted `Cargo.toml`.
    pub uses_ffi: bool,
    /// `true` when the program reaches at least one reactor-requiring kernel —
    /// async IO, a timer, a spawn, network, database, or any foreign FFI call
    /// ([`KernelFn::requires_async_runtime`]). The backend reads this flag to
    /// select the entry point: `false` emits a synchronous `fn main` driven by
    /// a std-only executor and drops `tokio` + `futures-util` from the emitted
    /// `Cargo.toml`; `true` keeps the tokio `block_on` entry unchanged.
    /// FAIL-CLOSED — the lowerer defaults every unknown kernel (and every FFI
    /// call) to reactor-requiring, so the synchronous entry is emitted only for
    /// a program proven to need no reactor.
    pub uses_async_runtime: bool,
}

/// A user-declared type. The IR models user types as enums (Ipê's `type`
/// declarations): a variant may be nullary, or carry payload fields, and the
/// enum may be generic.
#[derive(Clone, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
pub enum TypeDef {
    Enum(EnumDef),
}

/// An enum (algebraic data type) declaration.
///
/// A variant may carry payload fields and the type may be generic over a
/// list of type parameters (`type Maybe a = Just a | Nothing`). A nullary-only,
/// non-generic enum (`type Msg = Increment | Decrement`) has every variant's
/// `fields` empty and an empty `type_params`.
#[derive(Clone, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
pub struct EnumDef {
    pub name: Symbol,
    /// The module that DEFINES this type (its *home*), not the entry module the
    /// linker merged it into. Two modules may each declare a `type Color`; they
    /// intern the same bare `name` [`Symbol`], so `(home, name)` — not `name`
    /// alone — is the type's nominal identity. The backend derives the emitted
    /// Rust enum name from `home` (`["Std","Palette"] + Shade` → `StdPaletteShade`,
    /// `["Lib"] + Color` → `LibColor`, `["Main"] + Msg` → `MainMsg`), so a
    /// single-module program (home == entry) mangles to the bare short name
    /// while two same-short-named types from different modules mangle to
    /// distinct Rust enums. Empty for backend-unit-test IR built by hand.
    pub home: ModPath,
    /// The type variables this enum quantifies, in declaration order. Each is a
    /// Ipê type-variable [`Symbol`] that appears as an [`IrType::Generic`] in a
    /// variant's field types. A non-generic enum has an empty list.
    ///
    /// The order is load-bearing: the backend derives each parameter's Rust
    /// generic name (`T1`, `T2`, …) from its *position* here — exactly as for
    /// [`Func::type_params`] — so the emitted `enum Name<T1, T2>` agrees with
    /// every field type and use-site instantiation regardless of source naming.
    pub type_params: Vec<Symbol>,
    pub variants: Vec<Variant>,
}

/// One constructor of an [`EnumDef`]: its name and its ordered payload field
/// types.
///
/// A nullary constructor (`Increment`, `Nothing`) has an empty `fields`. A
/// payload constructor (`Just a`, `Rect Float Float`, `Node Tree Int Tree`)
/// lists one [`IrType`] per positional field, in source order. A field whose
/// type is the enum being declared (direct self-recursion) is rendered boxed by
/// the backend so the Rust enum stays finite-sized; the IR carries the bare
/// recursive type and leaves the boxing to emission.
#[derive(Clone, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
pub struct Variant {
    pub name: Symbol,
    pub fields: Vec<IrType>,
}

/// The set of Rust trait bounds a generic type parameter carries, held as a
/// compact bit set.
///
/// An unconstrained type variable — one the body only passes through (`id x =
/// x`) — has the empty set [`BoundSet::UNBOUNDED`], which the backend emits as a
/// bare generic (`T1`), the same as any structurally-parametric function. A
/// variable the body *constrains* by applying an operation to it
/// carries the matching bounds, so the emitted generic is `T1: <bounds>`.
///
/// Each flag maps a Ipê super-type capability to the Rust standard-library
/// trait that realises it, with no new runtime trait:
///
/// * `add` / `sub` / `mul` realise Ipê's **Number** super-type (`Int` or
///   `Float`). They are split per arithmetic operator because Ipê's
///   `Basics.add` / `sub` / `mul` already lower to Rust's `+` / `-` / `*`, and
///   each operator demands exactly its own `::core::ops` trait — a body that
///   only adds needs only `Add`, so the bound stays minimal rather than
///   over-constraining a caller.
/// * `ord` realises Ipê's **Comparable** super-type (`Int` / `Float` / `Char` /
///   `String` / `Bool`) for the ordering comparisons `<` `>` `<=` `>=`, mapping
///   to Rust's `PartialOrd`.
/// * `eq` realises Ipê's **Equatable** super-type (every non-function type) for
///   the equality comparisons `==` `/=`, mapping to Rust's `PartialEq`. Unlike
///   `ord` / the arithmetic traits it adds no `copy`: `PartialEq::eq` takes
///   `&self`, so an equated value is borrowed, never moved.
/// * `copy` is added when a bound value is used more than once and is a
///   bit-copyable primitive (every `Number` / `Comparable` primitive except
///   `String`), so the generated body can reuse it without a move error.
/// * `clone` is the non-`Copy` counterpart — added when a reused value's type
///   may be `String`, where `Clone` is the available duplication trait.
/// * `ord_total` realises a `Set` element's Rust requirement: `BTreeSet<A>`
///   needs `A : Ord` (the TOTAL order), which is strictly stronger than the
///   `ord` flag's `PartialOrd`. A generic `a -> Set a` carries `ord_total`.
/// * `hash` realises a `Dict` key's Rust requirement: `HashMap<K, V>` needs
///   `K : Hash + Eq`. Paired with `ord_total` on a Dict key (so the
///   determinism-sorted `Dict.keys` / `Dict.toList` also compile, and `Eq`
///   arrives as `Ord`'s supertrait) a generic `a -> Dict a v` carries
///   `hash | ord_total | clone`.
///
/// The flags are independent and compose: a Comparable-and-reused variable
/// carries `ord | copy`; a numeric-add-and-reused variable carries `add | copy`.
/// The `with_*` builders set a flag and return the updated set, so a bound set
/// is assembled fluently (`BoundSet::UNBOUNDED.with_add().with_copy()`); the
/// `has_*` predicates read one flag back.
#[derive(
    Clone, Copy, PartialEq, Eq, Debug, Default, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct BoundSet(u16);

impl BoundSet {
    const ADD: u16 = 1 << 0;
    const SUB: u16 = 1 << 1;
    const MUL: u16 = 1 << 2;
    const ORD: u16 = 1 << 3;
    const COPY: u16 = 1 << 4;
    const CLONE: u16 = 1 << 5;
    const EQ: u16 = 1 << 6;
    const ORD_TOTAL: u16 = 1 << 7;
    const HASH: u16 = 1 << 8;
    const SHOW: u16 = 1 << 9;
    /// The SQL-bind-parameter bound: realises the type checker's
    /// `TyBounds::sql_param` obligation as Rust `Into<ipe_runtime::db::SqlParam>`
    /// — a generic wrapper around `Db.exec` / `Db.query` / `Db.queryDecode`
    /// (`Database.exec label sql args` in `examples/17-ipemon`'s `Ipe.Db`
    /// access layer) needs this bound on its own emitted type parameter so its
    /// body's `SqlParam::from`-style projection type-checks for the CALLER's
    /// concrete element type, not just the one instantiation the function
    /// happened to be lowered against.
    const SQL_PARAM: u16 = 1 << 10;
    /// The `IpeRow` bound: a wildcard `any` generic that flows into a
    /// `Db.get*` field accessor (`Db.getString`/`getInt`/`getBool`/`getField`)
    /// gains `ipe_runtime::db::IpeRow` so the generic body type-checks and
    /// monomorphises per call site against the row's real shape (a query result
    /// `Dict String String`, a pub/sub `Dict` payload, or the typed `WebReq` an
    /// `init` handler receives). The runtime's `db_get_*` helpers are generic
    /// over `R: IpeRow`; without this bound the emitted body's `db_get_string(_,
    /// &payload)` call cannot prove `payload: IpeRow` (E0277). Added ONLY to the
    /// wildcard `any` variable and ONLY when the body actually calls a `db_get_*`
    /// — no blast radius on genuine named type variables (`a`, `msg`).
    const IPE_ROW: u16 = 1 << 11;
    /// The target-relative `Send` bound of a `Cmd` / `Sub` / `Task` payload generic.
    ///
    /// Renders `Send` exactly where the target's effect carriers are `Send`,
    /// plus `'static` on every target.
    /// A generic riding a `Cmd` / `Sub` / `Task` payload (`cmd_map` /
    /// `sub_map`'s `A`, the task combinators' element, `sub_subscribe_ws_open`'s
    /// `M`) needs `Send` only on a target whose
    /// runtime carriers are `Send` ([`ipe_kernels::Target::effect_carriers_are_send`]);
    /// on wasm32 the carriers themselves are not `Send`, so demanding it would
    /// refuse an instantiation at a `Cmd` / `Sub` / `Task` type and break the
    /// SEAL. The target is an emit-time fact, so the lowerer records this
    /// target-relative flag and [`Self::requires_send_on`] resolves it. Distinct
    /// from [`Self::SEND`], which is unconditional (`Decoder` elements, boxed `Send`
    /// callbacks). Always paired with `STATIC`.
    const EFFECT_SEND: u16 = 1 << 12;
    /// The `'static` lifetime bound: a generic type-param that flows,
    /// INSIDE the function body, into a value boxed as a boxed `dyn Fn` trait
    /// object (`Box<dyn Fn(..) -> .. + Send + 'static>`, or the `Arc` +Sync
    /// variant) — a callback (`FuncValue` / lambda) passed to a higher-order
    /// kernel like `List.map` — whose own type still mentions that type-param.
    /// Coercing a concrete-but-`tv`-generic function item to a `+ 'static` trait
    /// object requires `tv: 'static`, so the emitted generic must carry it.
    /// Without it the enclosing generic is only `<T{n}: Clone>` and the box
    /// coercion fails E0310 ("the parameter type may not live long enough") —
    /// well-typed to `ipe`, a `cargo build` break (a SEAL violation).
    ///
    /// This is a LIFETIME bound, not a trait: it renders as the leading
    /// `'static` in the bound list (`T{n}: 'static + Clone`), where Rust
    /// requires lifetime bounds to precede trait bounds. Unlike the trait
    /// obligations above it is not sourced from a kernel→bound map keyed on a
    /// PARAM value binder — the type-param appears in the boxed callback's TYPE,
    /// not as the accessed value — so it has its own structural walk
    /// (`body_boxes_generic_callback` in `ipe_lower`). It lands on wildcard `any`
    /// AND named tvars alike: every concrete Ipê type the caller substitutes is
    /// `'static` (emitted values never borrow), so `T: 'static` is satisfied by
    /// every real instantiation — no caller-side failure, matching the reference
    /// (no lifetime concern). NOT a new SEAL violation: it only
    /// relocates the pre-existing E0310 from the callee body to a bound that
    /// makes acceptance-by-`ipe` prove the box coercion type-checks.
    const STATIC: u16 = 1 << 13;
    /// The unconditional `Send` auto-trait bound: a generic type-param whose
    /// VALUE is moved into a runtime consumer that requires `Send` on EVERY
    /// target — a `Decoder` element (`decode_list<T: 'static + Send>`), or a
    /// value captured by a boxed `+ Send` callback. A consumer that requires
    /// `Send` only where the target's effect carriers are `Send` uses
    /// [`Self::EFFECT_SEND`] instead. Always paired with `STATIC` (a moved value
    /// that must be `Send` for a spawned/boxed consumer is also `'static`).
    /// Satisfied by every concrete Ipê type the target's runtime can carry.
    const SEND: u16 = 1 << 14;
    /// The `Sync` auto-trait bound: a generic type-param whose VALUE is captured
    /// behind a `Send + Sync` shared carrier that itself requires the element
    /// `Sync` — the optional-decoder runtime slots (`decode_pipeline_optional`,
    /// `db_decode_optional`), whose first type parameter is bounded `Clone +
    /// 'static + Send + Sync` because the decoded element's default rides a
    /// thread-shareable closure. A generic optional-field combinator over a free
    /// type var threads that var into the slot's element position, so the emitted
    /// generic must carry `Sync` or the crate is `ipe`-accepted then `cargo`-fails
    /// E0277 (`cannot be shared between threads safely`) — a SEAL violation.
    /// Strictly narrower than [`Self::SEND`]: a var that reaches a `Send`-only
    /// slot (`decode_list`) gains `Send` but NOT `Sync`. Satisfied by every
    /// concrete Ipê type (emitted values own their data and are trivially `Sync`),
    /// so no caller-side failure.
    const SYNC: u16 = 1 << 15;

    /// The empty bound set: an unconstrained, structurally-parametric variable.
    pub const UNBOUNDED: Self = Self(0);

    /// This set with the `Ord` (total order, `BTreeSet` element) bound. Strictly
    /// stronger than [`Self::with_ord`]'s `PartialOrd`.
    #[must_use]
    pub const fn with_ord_total(self) -> Self {
        Self(self.0 | Self::ORD_TOTAL)
    }

    /// This set with the `::core::hash::Hash` (`HashMap` key) bound.
    #[must_use]
    pub const fn with_hash(self) -> Self {
        Self(self.0 | Self::HASH)
    }

    /// Whether the `Ord` (total-order) bound is set.
    #[must_use]
    pub const fn has_ord_total(self) -> bool {
        self.0 & Self::ORD_TOTAL != 0
    }

    /// Whether the `Hash` bound is set.
    #[must_use]
    pub const fn has_hash(self) -> bool {
        self.0 & Self::HASH != 0
    }

    /// Whether this set carries no bound at all — the variable is a true
    /// parametric pass-through and emits as a bare generic.
    #[must_use]
    pub const fn is_unbounded(self) -> bool {
        self.0 == 0
    }

    /// This set with the `::core::ops::Add<Output = Self>` (Number `+`) bound.
    #[must_use]
    pub const fn with_add(self) -> Self {
        Self(self.0 | Self::ADD)
    }

    /// This set with the `::core::ops::Sub<Output = Self>` (Number `-`) bound.
    #[must_use]
    pub const fn with_sub(self) -> Self {
        Self(self.0 | Self::SUB)
    }

    /// This set with the `::core::ops::Mul<Output = Self>` (Number `*`) bound.
    #[must_use]
    pub const fn with_mul(self) -> Self {
        Self(self.0 | Self::MUL)
    }

    /// This set with the `PartialOrd` (Comparable ordering) bound.
    #[must_use]
    pub const fn with_ord(self) -> Self {
        Self(self.0 | Self::ORD)
    }

    /// This set with the `PartialEq` (Equatable equality) bound.
    #[must_use]
    pub const fn with_eq(self) -> Self {
        Self(self.0 | Self::EQ)
    }

    /// This set with the `IpeStringify` (Ipê `toString` / `Log.*With`) bound.
    #[must_use]
    pub const fn with_show(self) -> Self {
        Self(self.0 | Self::SHOW)
    }

    /// This set with the `Copy` (bit-copyable reuse) bound.
    #[must_use]
    pub const fn with_copy(self) -> Self {
        Self(self.0 | Self::COPY)
    }

    /// This set with the `Clone` (non-`Copy` reuse) bound.
    #[must_use]
    pub const fn with_clone(self) -> Self {
        Self(self.0 | Self::CLONE)
    }

    /// This set with the SQL-bind-parameter (`Into<SqlParam>`) bound — see
    /// [`Self::SQL_PARAM`].
    #[must_use]
    pub const fn with_sql_param(self) -> Self {
        Self(self.0 | Self::SQL_PARAM)
    }

    /// This set with the `IpeRow` (Db field-accessor row) bound — see
    /// [`Self::IPE_ROW`].
    #[must_use]
    pub const fn with_ipe_row(self) -> Self {
        Self(self.0 | Self::IPE_ROW)
    }

    /// This set with the `'static` (boxed-callback trait-object) lifetime bound —
    /// see [`Self::STATIC`].
    #[must_use]
    pub const fn with_static(self) -> Self {
        Self(self.0 | Self::STATIC)
    }

    /// This set with the `Send` auto-trait bound (and `'static`, its always-paired
    /// companion) — see [`Self::SEND`].
    #[must_use]
    pub const fn with_send(self) -> Self {
        Self(self.0 | Self::SEND | Self::STATIC)
    }

    /// Whether the `Send` bound is set — see [`Self::SEND`].
    #[must_use]
    pub const fn has_send(self) -> bool {
        self.0 & Self::SEND != 0
    }

    /// This set with the target-relative effect-carrier `Send` bound (and `'static`).
    ///
    /// See [`Self::EFFECT_SEND`].
    #[must_use]
    pub const fn with_effect_send(self) -> Self {
        Self(self.0 | Self::EFFECT_SEND | Self::STATIC)
    }

    /// Whether the target-relative effect-carrier `Send` bound is set.
    ///
    /// See [`Self::EFFECT_SEND`].
    #[must_use]
    pub const fn has_effect_send(self) -> bool {
        self.0 & Self::EFFECT_SEND != 0
    }

    /// Whether this set demands `Send` when emitted for `target`.
    ///
    /// The unconditional [`Self::SEND`] always does; the effect-carrier
    /// [`Self::EFFECT_SEND`] does only where
    /// [`ipe_kernels::Target::effect_carriers_are_send`] holds.
    #[must_use]
    pub const fn requires_send_on(self, target: ipe_kernels::Target) -> bool {
        self.has_send() || (self.has_effect_send() && target.effect_carriers_are_send())
    }

    /// This set with the `Sync` auto-trait bound (and its always-implied
    /// companions `Send` + `'static`, since a value shared across threads is also
    /// sendable and owned) — see [`Self::SYNC`].
    #[must_use]
    pub const fn with_sync(self) -> Self {
        Self(self.0 | Self::SYNC | Self::SEND | Self::STATIC)
    }

    /// Whether the `Sync` bound is set — see [`Self::SYNC`].
    #[must_use]
    pub const fn has_sync(self) -> bool {
        self.0 & Self::SYNC != 0
    }

    /// Whether the `Add` bound is set.
    #[must_use]
    pub const fn has_add(self) -> bool {
        self.0 & Self::ADD != 0
    }

    /// Whether the `Sub` bound is set.
    #[must_use]
    pub const fn has_sub(self) -> bool {
        self.0 & Self::SUB != 0
    }

    /// Whether the `Mul` bound is set.
    #[must_use]
    pub const fn has_mul(self) -> bool {
        self.0 & Self::MUL != 0
    }

    /// Whether the `PartialOrd` bound is set.
    #[must_use]
    pub const fn has_ord(self) -> bool {
        self.0 & Self::ORD != 0
    }

    /// Whether the `PartialEq` bound is set.
    #[must_use]
    pub const fn has_eq(self) -> bool {
        self.0 & Self::EQ != 0
    }

    /// Whether the `IpeStringify` bound is set.
    #[must_use]
    pub const fn has_show(self) -> bool {
        self.0 & Self::SHOW != 0
    }

    /// Whether the `Copy` bound is set.
    #[must_use]
    pub const fn has_copy(self) -> bool {
        self.0 & Self::COPY != 0
    }

    /// Whether the `Clone` bound is set.
    #[must_use]
    pub const fn has_clone(self) -> bool {
        self.0 & Self::CLONE != 0
    }

    /// Whether the SQL-bind-parameter (`Into<SqlParam>`) bound is set — see
    /// [`Self::SQL_PARAM`].
    #[must_use]
    pub const fn has_sql_param(self) -> bool {
        self.0 & Self::SQL_PARAM != 0
    }

    /// Whether the `IpeRow` (Db field-accessor row) bound is set — see
    /// [`Self::IPE_ROW`].
    #[must_use]
    pub const fn has_ipe_row(self) -> bool {
        self.0 & Self::IPE_ROW != 0
    }

    /// Whether the `'static` (boxed-callback trait-object) lifetime bound is set
    /// — see [`Self::STATIC`].
    #[must_use]
    pub const fn has_static(self) -> bool {
        self.0 & Self::STATIC != 0
    }
}

/// A function: the type variables it quantifies, typed parameters, a return
/// type, and a body expression.
//
// `Eq` is not derived: `body` is an [`Expr`] that may carry a float literal
// (only `PartialEq`).
#[derive(Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
pub struct Func {
    pub id: FuncId,
    pub name: Symbol,
    /// The defining module's path. After `link::link` merges several modules
    /// into one this field retains the original source module path, so the
    /// backend can prefix the emitted Rust function name with the correct
    /// module segment (e.g. `lib_helper` for `home = ModPath(["Lib"])`,
    /// `main_helper` for `home = ModPath(["Main"])`) instead of always using
    /// the merged entry module's name — preventing same-named functions from
    /// different source modules from colliding with Rust E0428.
    pub home: ModPath,
    /// The type variables this function quantifies, in quantification order,
    /// each paired with its [`BoundSet`]. A type variable is a Ipê
    /// type-variable [`Symbol`] that appears as an [`IrType::Generic`] in the
    /// parameters / return / body; its `BoundSet` records the Rust trait bounds
    /// the body's use of the variable demands. A monomorphic function has an
    /// empty list. A structurally-parametric variable carries
    /// [`BoundSet::UNBOUNDED`], so its emitted generic stays a bare `T1`.
    ///
    /// The order is load-bearing: the backend derives each variable's Rust
    /// generic name (`T1`, `T2`, …) from its *position* here, so a function
    /// quantifying `[a, b]` emits `fn name<T1, T2>(..)` with `a` → `T1` and
    /// `b` → `T2` regardless of the source variable spellings. Only the
    /// [`Symbol`] participates in naming; the [`BoundSet`] adds the `: <bounds>`
    /// clause at that position.
    pub type_params: Vec<(Symbol, BoundSet)>,
    /// The row variables this function quantifies, in quantification order,
    /// after [`Self::type_params`]. A row variable names the open tail of a
    /// row-polymorphic record annotation `{ r | f : T }` and appears as an
    /// [`IrType::RowGeneric`] in the parameters / return / body; its
    /// [`RowParam`] carries the fields the annotation guarantees. A function
    /// with no row-polymorphic annotation has an empty list.
    ///
    /// The order is load-bearing exactly as for [`Self::type_params`]: the
    /// backend derives each row variable's Rust generic name (`R1`, `R2`, …)
    /// from its *position* here, so the synthesised generic clause, the
    /// witness bounds, and every use-site agree. `R`-prefixed names cannot
    /// collide with the `T`-prefixed ordinary type generics.
    pub row_params: Vec<RowParam>,
    pub params: Vec<(Symbol, IrType)>,
    pub ret: IrType,
    pub body: Expr,
}

/// A row variable's required-field contract — the single source of truth for
/// what a row-polymorphic function's row parameter guarantees.
///
/// `var` is the source row variable [`Symbol`] (matching the
/// [`IrType::RowGeneric`] carried in the signature); `fields` maps each
/// annotated field name to its lowered type, in field-name order (the
/// [`BTreeMap`] iteration order is fixed). The backend emits one witness-trait
/// bound per field on this variable's Rust generic, so a body field read
/// resolves through the field's getter and rustc monomorphises the call to the
/// concrete record struct.
///
/// `updated_fields` records the subset of `fields` that the function body
/// updates via functional-update syntax (`{ rec | f = … }`). For each such
/// field the backend emits an `IpeWithF` setter witness trait and bound, so
/// a body update emits `rec.ipe_with_f(v)` on the generic receiver rather
/// than a bare struct rebuild (which requires the concrete type name).
#[derive(Clone, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
pub struct RowParam {
    pub var: Symbol,
    pub fields: BTreeMap<Symbol, IrType>,
    /// Field names from `fields` that are updated in the function body.
    /// Drives `IpeWithF` setter witness synthesis in the backend.
    pub updated_fields: BTreeSet<Symbol>,
}

/// The type lattice.
///
/// `Hash` is derived so record-shape collection (`ipe_lower`'s
/// `collect_record_types`) can dedup via a `HashSet` gate instead of an
/// O(n²) `Vec::contains` scan (efficiency-audit §3 medium). The derive is
/// inert — it emits no IR and changes no equality semantics.
#[derive(Clone, PartialEq, Eq, Hash, Debug, serde::Serialize, serde::Deserialize)]
pub enum IrType {
    Int,
    Float,
    Bool,
    Str,
    /// A Unicode scalar value `Char`. Renders as Rust's `char`.
    Char,
    Unit,
    /// A task producing a value of type `A` (`Task Error A` in Ipê). Renders as
    /// the project-level alias `IpeTask<A>` (which expands to
    /// `ipe_runtime::IpeTask<IpeError, A>`). Replaces the former `TaskUnit`
    /// leaf — `Task Error ()` is now `Task(Box::new(Unit))`.
    Task(Box<Self>),
    /// A user-declared enum type, applied to its type arguments.
    ///
    /// `home` is the type's DEFINING module and `name` its bare type [`Symbol`];
    /// together they are the type's nominal identity (see [`EnumDef::home`]). Two
    /// modules each declaring `type Color` share the bare `name` but differ in
    /// `home`, so the backend resolves each use site to the correct distinct Rust
    /// enum. `args` are the concrete type arguments at a use site (`Maybe Int` →
    /// `args = [Int]`, rendered `MainMaybe<i64>`). A non-generic enum (`Msg`)
    /// carries an empty `args` list, so it renders as the bare Rust type name.
    /// An `arg` may itself be an [`IrType::Generic`] when a generic enum is passed
    /// through a generic function (`Maybe a` inside a parametric signature →
    /// `MainMaybe<T1>`).
    Enum {
        home: ModPath,
        name: Symbol,
        args: Vec<Self>,
    },
    /// The built-in `Maybe a` type, carrying its element type. Renders as the
    /// runtime's `IpeMaybe<T>`. Distinct from a user [`IrType::Enum`] so the
    /// backend maps it to the shared runtime representation (and the type
    /// checker / lowerer never need a synthetic `type Maybe a = …` declaration).
    Maybe(Box<Self>),
    /// The built-in `Result e a` type, carrying its error type then its success
    /// type (Ipê's `Result e a` argument order). Renders as the runtime's
    /// `IpeResult<E, A>`.
    Result(Box<Self>, Box<Self>),
    /// The built-in `List a` type, carrying its element type. Renders as the
    /// runtime's `Vec<T>` (the representation the Rust runtime's list kernels
    /// operate over).
    List(Box<Self>),
    /// An anonymous product type `(T1, T2, ...)`.
    ///
    /// Invariant: the element list has arity ≥ 2. A 0-tuple is [`IrType::Unit`]
    /// and a 1-tuple is just its element type — neither is a `Tuple`. The
    /// lowerer is the sole producer and upholds this; the backend stays total
    /// over any vector it receives (it never panics on a degenerate arity).
    Tuple(Vec<Self>),
    /// A CLOSED record type `{ x : Int, y : Bool, ... }` — an exact, known field
    /// set keyed by field name.
    ///
    /// The field map is a [`BTreeMap`], so its iteration order is fixed (by
    /// [`Symbol`]). The backend re-canonicalises by *field name* before it
    /// derives a struct name or emits the struct body, so the synthesised Rust
    /// struct is deterministic regardless of interning order.
    ///
    /// Open / row-polymorphic records (`{ r | x : Int }`) are intentionally NOT
    /// representable here — they are unsupported and rejected at lowering, so
    /// every `Record` the backend sees is closed.
    Record(BTreeMap<Symbol, Self>),
    /// A function type `T0 -> T1 -> ... -> R`, carried as its parameter list and
    /// return type (`params -> ret`).
    ///
    /// This is the type of a first-class function value — a lambda, a
    /// function-typed parameter or binding, or a top-level function used as a
    /// value. The backend renders it as a boxed trait object
    /// `Box<dyn Fn(T0, ...) -> R>`.
    ///
    /// Invariant: a zero-parameter function type (`params` empty) is a genuine
    /// nullary `Fn() -> R`, distinct from `ret` alone. The lowerer is the sole
    /// producer; the backend stays total over any parameter vector it receives.
    Fun(Vec<Self>, Box<Self>),
    /// [`Self::Fun`]'s reference-counted sibling: same `params -> ret`, but its
    /// carrier is `Arc<dyn Fn(..) -> R + Send + Sync + 'static>` instead of
    /// `Box<dyn Fn(..)>`. `Arc` is `Clone` (a refcount bump), so a binding whose
    /// type embeds a `SharedFun` slot can be duplicated for reuse — the whole
    /// point of the carrier.
    ///
    /// Produced ONLY by the fn-value-reuse promotion (`ipe_lower`): a contained,
    /// whole-clonable composite fn value (a `Maybe`/`Result`/record/user-union
    /// payload holding a function, reused more than once) has its `Fun` slots
    /// flipped to `SharedFun` so the composite becomes `Clone`. Every non-promoted
    /// function value keeps the lean `Box` carrier of [`Self::Fun`]. The two are
    /// distinct Rust types (`Arc<..>` vs `Box<..>`) with no coercion, so the
    /// promotion is admissible only when the value provably never reaches a
    /// position where a `Box`/`impl Fn` carrier would be required — the
    /// containment precondition the promotion pass enforces.
    ///
    /// Same param/ret invariant as [`Self::Fun`].
    SharedFun(Vec<Self>, Box<Self>),
    /// A CURRIED chain of one-shot closures `T0 -> (T1 -> ( ... -> R))`,
    /// carried as its parameter list (one per curry level, in application
    /// order) and the FINAL, non-function return type.
    ///
    /// Distinct from [`Self::Fun`] (a flattened, re-callable
    /// `Box<dyn Fn(T0, T1, ...) -> R>`): this variant renders as NESTED
    /// `Box<dyn FnOnce(Ti) -> { next level or R } + Send>` boxes, one level
    /// of currying per parameter. Types the `next_decoder` slot of the
    /// `JsonDec.Pipeline`/`Db.Decode`
    /// curried-combinator kernels (`decode_pipeline_required` /
    /// `decode_pipeline_optional` / `decode_pipeline_required_at` /
    /// `db_decode_required` / `db_decode_optional`), whose hand-written Rust
    /// signatures deliberately require a `Box<dyn FnOnce>` chain — each
    /// level is consumed exactly once per pipeline `run` (matching the
    /// `curryN` runtime helpers' factory-produced chains) — never the
    /// re-callable `Fn` boxing the generic [`Self::Fun`] path emits. Only
    /// ever produced by `eta_expand_partial`'s special-cased handling of
    /// those five kernels; every other position keeps the ordinary,
    /// flattened [`Self::Fun`] shape.
    ///
    /// Invariant: `params` is non-empty (a chain of zero levels is just
    /// `ret` itself, never constructed as `FnOnceChain`).
    FnOnceChain(Vec<Self>, Box<Self>),
    /// A generic type parameter — a Ipê type variable used STRUCTURALLY
    /// (pass-through, no operation applied to it) in a fully-parametric
    /// top-level function. The carried [`Symbol`] is the source type
    /// variable's name (e.g. interned `"a"`).
    ///
    /// The backend renders this as the function's corresponding Rust generic
    /// (`T1`, `T2`, …), resolved by the variable's position in the enclosing
    /// [`Func::type_params`] — not by the symbol's spelling — so emission is
    /// deterministic regardless of source naming.
    ///
    /// A `Generic` is only ever in scope inside a function that quantifies it;
    /// it never appears in a program-level position (enum / record-struct
    /// declaration). Constrained type variables (those needing a Rust trait
    /// bound — `Number` / `Comparable` / `Appendable`) are NOT representable
    /// here: they are rejected at lowering.
    ///
    /// The wildcard `any` is a SEPARATE case, not genuine polymorphism: the
    /// checker gives every `any` occurrence in an annotation its own fresh flex
    /// UV ("fresh flex UV per occurrence" — `ipe_types::constrain`), so two
    /// `any` params in one signature can be pinned to two DIFFERENT concrete
    /// types by the body. `split_typed_sig` (AUD-01 seal fix) resolves each
    /// param-position `any` from the def's solved env type, per occurrence, to
    /// its concrete `IrType` whenever that solved type is available — a shared
    /// `Generic(any_sym)` here would collapse distinct occurrences onto ONE
    /// Rust generic (exit-0-then-cargo-fail). A `Generic` carrying the interned
    /// `"any"` symbol therefore still appears ONLY as the fallback when the
    /// solved type genuinely could not be resolved (should not occur for a
    /// well-formed `Def::Typed` post-solve) — it is not the steady-state
    /// representation the way it is for a genuine type parameter.
    Generic(Symbol),
    /// A row variable in type position — the open tail of a row-polymorphic
    /// record annotation `{ r | f : T }`. The carried [`Symbol`] is the source
    /// row variable's name (e.g. interned `"r"`).
    ///
    /// A row-polymorphic function erases its open row into an ordinary rustc
    /// generic bounded by synthesised per-field witness traits (one trait per
    /// required field name). The backend renders this as the function's
    /// corresponding row generic (`R1`, `R2`, …), resolved by the variable's
    /// position in the enclosing [`Func::row_params`] — never by the symbol's
    /// spelling — so emission is deterministic regardless of source naming. The
    /// required fields and their types live in the matching [`RowParam`]; a
    /// field read on a value of this type routes through the field's witness
    /// getter rather than a struct field.
    ///
    /// This variant is DISTINCT from [`IrType::Generic`] on purpose: a plain
    /// generic is unbounded structural pass-through, whereas a row generic
    /// carries field obligations discharged through witness bounds. Keeping them
    /// separate forces every consumer to decide the row case explicitly and
    /// keeps `Generic`'s existing meaning intact. It is representable here, but
    /// — unlike an open row — never as an [`IrType::Record`]: every `Record` the
    /// backend sees stays closed.
    RowGeneric(Symbol),
    /// The built-in `Dict k v` associative map type, carrying its key type then
    /// its value type. Renders as the runtime's `HashMap<K, V>` (backed by
    /// `std::collections::HashMap`). Distinct from a user [`IrType::Enum`] so
    /// the backend maps it to the shared runtime representation. Key iteration
    /// is sorted for determinism (map iteration order is unstable).
    Dict(Box<Self>, Box<Self>),
    /// The built-in `Set a` unordered-set type, carrying its element type.
    /// Renders as the runtime's `BTreeSet<A>` (backed by
    /// `std::collections::BTreeSet`). Iteration is sorted on the Rust backend
    /// (map order is unstable) — a conforming strengthening.
    Set(Box<Self>),
    /// The built-in `Bytes` type — an arbitrary byte buffer.
    ///
    /// Divergence from Ipê: Ipê defines `type alias Bytes = String` (
    /// `string` is a byte sequence, making the alias cost-free). Rust's
    /// `String` is UTF-8 constrained; mapping `Bytes` to `String` would be
    /// unsound for non-UTF-8 binary payloads. Ipê-Rust makes `Bytes` a
    /// distinct primitive lowering to `Vec<u8>` — lossless for arbitrary
    /// binary, with explicit UTF-8 conversion via `Bytes.fromString` /
    /// `Bytes.toString`. Rationale: Rust type-system correctness.
    Bytes,
    /// The JSON value type — an opaque, dynamically-typed JSON node.
    ///
    /// The Ipê `Value` type alias (`Value = any`) creates an unresolved
    /// `Ty::Var` at use sites.  In a JSON-kernel context the concrete Rust
    /// type is always `serde_json::Value`, re-exported from the runtime as
    /// `JsonVal`.  The lowerer produces this variant when a `Ty::Var`
    /// appears in the argument or return position of a `JsonEnc.*` kernel
    /// call — the only place where `any` is meaningful.
    /// The backend emits `JsonVal`.
    Json,
    /// The `Decoder a` type — an opaque decoder that reads a JSON value and
    /// produces a value of type `a`.
    ///
    /// Backs `Ipe.Json.Decode`.  Renders as
    /// `Decoder<T>` using the emitted project's preamble type alias:
    /// `pub type Decoder<T> = ipe_runtime::json::Decoder<IpeError, T>`.
    Decoder(Box<Self>),
    /// The `Db` connection pool type — an opaque handle to an open database
    /// connection pool (`Ipe.Db`).
    ///
    /// Renders as `Db` via the runtime re-export
    /// `pub use ipe_runtime::Db;` in the emitted crate preamble.  The type is
    /// zero-argument (no type parameters) and value-cloneable (the pool is
    /// reference-counted internally).
    Db,
    /// A `Cmd msg` value — an opaque command produced by the `update` function
    /// and passed back to the TEA runtime.
    ///
    /// Renders as `IpeCmd<T>` via the project-level alias
    /// `pub type IpeCmd<M> = ipe_runtime::tea::IpeCmd<M>`.
    /// The inner type is the message type `M`.
    Cmd(Box<Self>),
    /// A `Sub msg` value — an opaque subscription descriptor returned by
    /// the `subscriptions` function.
    ///
    /// Renders as `IpeSub<T>` via the project-level alias
    /// `pub type IpeSub<M> = ipe_runtime::tea::IpeSub<M>`.
    /// The inner type is the message type `M`.
    Sub(Box<Self>),
    // ── Ipe.Http.Server opaque types ────────────────────────────────────
    /// `Request` — opaque HTTP server request.  Renders as `ServerRequest`.
    ///
    /// Corresponds to `ipe_runtime::server::ServerRequest`.  Never synthesised
    /// as a record struct; always treated as an opaque handle.
    ServerRequest,
    /// `Response` — opaque HTTP server response.  Renders as `ServerResponse`.
    ///
    /// Corresponds to `ipe_runtime::server::ServerResponse`.
    ServerResponse,
    /// `Route` — opaque server route descriptor.  Renders as `ServerRoute`.
    ///
    /// Corresponds to `ipe_runtime::server::ServerRoute`.
    ServerRoute,
    /// `Cookie` — opaque server cookie descriptor.  Renders as `ServerCookie`.
    ///
    /// Corresponds to `ipe_runtime::server::ServerCookie`.
    ServerCookie,
    /// `StreamWriter` — opaque server-side stream writer handle.  Renders as
    /// `StreamWriter`.
    ///
    /// Corresponds to `ipe_runtime::server_stream::StreamWriter`.  Used as the
    /// argument type of the `Stream.stream` callback and the target type of
    /// `Stream.emit` / `Stream.finish` / `Stream.withContentType`.  Never
    /// synthesised as a record struct; always treated as an opaque handle.
    StreamWriter,
    /// `HttpRequest` — opaque HTTP request descriptor used by `Ipe.Http`
    /// and `Ipe.Http.Stream`.  Renders as `HttpRequest`.
    ///
    /// Corresponds to `ipe_runtime::http::HttpRequest`.  In Ipê source, users
    /// write `HttpRequest` literals as structural records; the lowerer detects
    /// the canonical 6-field set (`body`, `headers`, `method`, `redirects`,
    /// `timeout`, `url`) and folds it to this opaque
    /// variant instead of synthesising a backend record struct, so call sites
    /// that pass the value to `http_stream_open` / `http_request` kernels see
    /// the correct runtime type.  Never stored in a Ipe.Web Model.
    HttpRequest,
    // ── Ipe.Http.Server.WebSocket opaque type handles ──────────────────
    /// `WebSocketServer` — opaque per-peer WebSocket handle.  Renders as
    /// `WsHandle`.
    ///
    /// Passed to every `WsServerCfg` callback as the first argument; also
    /// accepted by `Ws.sendToClient` / `Ws.sendBinaryToClient` /
    /// `Ws.broadcast` / `Ws.closeClient`.  Never stored in a Ipe.Web Model.
    WebSocketServer,
    /// `WebSocketServerCfg` — opaque WebSocket server configuration.  Renders
    /// as `WsServerCfg<IpeError>`.
    ///
    /// Constructed by `Ws.defaultCfg` and threaded through the `Ws.with*`
    /// builder chain; consumed by `Ws.upgrade`.  Phantom `msg` type parameter
    /// dropped (D2 — see docs/adr/0003-security-render-and-data-access-invariants.md).
    WebSocketServerCfg,
    // ── Ipe.Ui / Ipe.Html parametric types ──────────────────────────────
    /// A parametric `Ipe.Ui` or `Ipe.Html` type — one that carries a message type
    /// parameter `msg`.  The `ctor` field identifies which of the five
    /// message-parametric types this is; `msg` is the message type.
    ///
    /// | ctor                     | Rust type                                    |
    /// |--------------------------|----------------------------------------------|
    /// | `UiCtor::Html`           | `ipe_runtime::html::Html<M>`                 |
    /// | `UiCtor::Element`        | `ipe_runtime::ui::element::Element<M>`       |
    /// | `UiCtor::Cells`          | `ipe_runtime::tui::CellsView<M>`             |
    /// | `UiCtor::UiAttribute`    | `ipe_runtime::ui::element::Attribute<M>`     |
    /// | `UiCtor::HtmlAttribute`  | `ipe_runtime::html::Attribute<M>`            |
    /// | `UiCtor::HtmlEvent`      | `ipe_runtime::html::Event<M>`                |
    /// | `UiCtor::Label`          | `ipe_runtime::ui::input::Label<M>`           |
    /// | `UiCtor::Placeholder`    | `ipe_runtime::ui::input::Placeholder<M>`     |
    /// | `UiCtor::RadioOption`    | `ipe_runtime::ui::input::RadioOption<M>`     |
    Ui {
        ctor: UiCtor,
        msg: Box<Self>,
    },
    /// A nullary (non-parametric) `Ipe.Ui` type.  These are closed value types
    /// that carry no message type parameter.
    ///
    /// | plain             | Rust type                                         |
    /// |-------------------|---------------------------------------------------|
    /// | `Length`          | `ipe_runtime::ui::element::Length`                |
    /// | `Color`           | `ipe_runtime::color::Color`                       |
    /// | `HAlign`          | `ipe_runtime::ui::element::HAlign`                |
    /// | `VAlign`          | `ipe_runtime::ui::element::VAlign`                |
    /// | `Location`        | `ipe_runtime::ui::element::Location`              |
    /// | `PseudoClass`     | `ipe_runtime::ui::element::PseudoClass`           |
    /// | `Description`     | `ipe_runtime::ui::element::Description`           |
    /// | `LayoutContext`   | `ipe_runtime::ui::element::LayoutContext`          |
    UiPlain(UiPlain),
    /// `WebReq` — opaque request type threaded through `Web.tea`'s `init`
    /// callback.  Rendered as `ipe_runtime::dom::req::WebReq` (the canonical,
    /// target-neutral definition; compiles on every target including `wasm32`).
    WebReq,
    /// `SessionHandle` — the opaque handle addressing one bounded `Ipe.Ffi.Js`
    /// session stream, obtained ONLY from `Js.openSession`. It carries the
    /// runtime-minted session id and is rendered as the plain `i64` the session
    /// registry keys on. It has no Ipê constructor, so a program cannot forge a
    /// handle for a session it did not open — cross-handle addressing is
    /// unrepresentable. Non-derivable/non-serde (never crosses the seam as a
    /// value; it is a live-registry key, not a session datum).
    SessionHandle,
    /// `WebRoute page` — route descriptor returned by `Web.route`, carrying
    /// the page type it builds. Rendered as
    /// `ipe_runtime::web::route::Route<Page>`. The runtime `Route<Page>`
    /// struct has NO default type parameter, so the page argument is
    /// load-bearing: rendering a bare `Route` is an E0107 `cargo` failure
    /// whenever the type reaches a rendered position
    /// (an empty `routes = []` literal's `Vec::<…>::new()` turbofish, or a
    /// let-bound route table's fn signature).
    WebRoute(Box<Self>),
    /// `CustomElement down up` — the opaque handle placed by `CustomElement.node` for a
    /// typed JS custom-element widget. Rendered as
    /// `ipe_runtime::ui::widget::IpeCustomElement`, a plain data handle carrying
    /// the generated content-addressed element tag. `down` / `up` are the
    /// declared seal types; they are load-bearing for codegen (the down-state
    /// encode and the up-event decode are generated against the concrete Rust
    /// types they render to) but the HANDLE itself never crosses the seam and
    /// never serialises — like [`Self::WebRoute`], it is non-derivable and
    /// non-serde. The value is produced only by the reserved `CustomElement.fromFile`
    /// constructor and consumed only as `CustomElement.node`'s first argument.
    CustomElement {
        down: Box<Self>,
        up: Box<Self>,
    },
    /// The built-in `Order` type — the result of `Basics.compare`.
    ///
    /// Renders as `ipe_runtime::IpeOrder` (the `#[repr(u8)]` enum exposed from
    /// the runtime's `basics` module and re-exported via `pub use basics::*`).
    /// Constructors `LT / EQ / GT` emit as `ipe_runtime::IpeOrder::LT` etc.
    /// via the `builtin_runtime_enum` path in the backend (no synthetic
    /// `EnumDef` is injected — the enum lives entirely in the runtime crate).
    ///
    /// Sanctioned divergence: `Basics_compareT` returns an
    /// `int` (-1/0/1).  The Rust backend uses a typed enum for sound exhaustive
    /// pattern matching without a range-check.
    Order,

    /// `Ipe.Task.BackoffStrategy` — the four-constructor retry-backoff ADT.
    ///
    /// Renders as `ipe_runtime::task::BackoffStrategy` (a `#[derive(Clone,
    /// Copy, Debug, PartialEq, Eq)]` enum with four variants: `Linear /
    /// LinearWithJitter / Exponential / ExponentialWithJitter`). Constructors
    /// emit via the `builtin_runtime_enum` path — no synthetic `EnumDef`.
    BackoffStrategy,

    /// `Ipe.Http.HttpMethod` — the closed ADT for HTTP verbs.
    ///
    /// Renders as `ipe_runtime::HttpMethod` (a `#[derive(Clone, Copy, Debug,
    /// PartialEq, Eq)]` enum with seven variants: `Get / Post / Put / Delete /
    /// Patch / Head / Options`).  Constructors emit as
    /// `ipe_runtime::HttpMethod::Get` etc. via the `builtin_runtime_enum` path
    /// — no synthetic `EnumDef` is injected.  The lowerer registers `HttpMethod`
    /// as a pre-interned nominal (like `Order` / `Decimal`) so any `Ty::Con`
    /// with name `"HttpMethod"` and empty module path folds to this variant.
    HttpMethod,

    /// `Ipe.Decimal` — arbitrary-precision decimal arithmetic.
    ///
    /// Renders as `ipe_runtime::decimal::Decimal` (newtype around
    /// `rust_decimal::Decimal`).  Carries Copy + serde semantics; used as
    /// a field type in record structs and as a direct call-argument / return
    /// value for all `Decimal.*` kernels.
    Decimal,

    /// `Ipe.Auth.Principal` — the authenticated subject of a request.
    ///
    /// Renders as `ipe_runtime::principal::Principal` (a private-field newtype
    /// over the verified subject `String`). Opaque with no Ipê constructor, so a
    /// value only ever originates from the server auth middleware's mint;
    /// consumed by `Ipe.Auth.subject` and the DB secured (`…As`) operations. A
    /// dedicated leaf rather than [`IrType::Json`] so the type keeps a
    /// `Principal` distinct from a `String` or a claims object — a caller
    /// identifier cannot stand in where a `Principal` is required.
    Principal,

    /// `Ipe.Server.AuthConfig` — the opaque authed-route configuration.
    ///
    /// Renders as `ipe_runtime::server::AuthConfig` (a private-field struct
    /// holding the verification `Secret`, the [`IrType::TokenSource`], and the
    /// subject-claim key). Built only through `Server.authConfig`; the sole
    /// value the authed-route kernels accept. A dedicated leaf, never serde: it
    /// carries a `Secret` and must never round-trip through a session store.
    AuthConfig,

    /// `Ipe.Server.TokenSource` — the opaque descriptor of where the authed
    /// middleware reads the session token from.
    ///
    /// Renders as `ipe_runtime::server::TokenSource` (a closed runtime enum:
    /// bearer header or a named cookie). Built only through the `Server` token
    /// source kernels; a dedicated leaf so a bare `String` cannot stand in for a
    /// token source. Not serde.
    TokenSource,

    /// The built-in `ErrorKind` type — `Error`'s 11-variant classification
    ///
    /// Renders as `ipe_runtime::error::IpeErrorKind` (a `#[repr(u8)]` enum,
    /// same convention as [`IrType::Order`]). Constructors (`Io` / `Network` /
    /// …) emit via the `builtin_runtime_enum` path — no synthetic `EnumDef`.
    ErrorKind,

    /// The built-in `Error` type — `Error ErrorKind ErrorInfo`.
    ///
    /// Renders as `ipe_runtime::error::IpeError`. Sole constructor shares its
    /// name with the type (`enum_variants[(Prelude, error)] = [error]`, set in
    /// `ipe_lower`), so it emits as the tuple variant `IpeError::Error(kind,
    /// info)` via the SAME `builtin_runtime_enum` path `Maybe`/`Result` use —
    /// no synthetic `EnumDef`, no new emitter mechanism.
    ///
    /// `ErrorInfo` carries `{ message : String, details : Maybe ErrorDetails
    /// }` — a plain closed record, not a leaf `IrType` (Ipê records are
    /// structural).
    Error,

    /// The built-in `ErrorDetails` type — the 5-variant enrichment union
    /// carried optionally on `ErrorInfo.details`.
    ///
    /// Renders as `ipe_runtime::error::IpeErrorDetails`. Constructor names
    /// match Ipê source verbatim (`FfiPanic` / `TypeMismatch` / `HttpStatus`
    /// / `JsonDecode` / `Custom`) and emit via the SAME `builtin_runtime_enum`
    /// path [`IrType::Error`]/[`IrType::ErrorKind`] use — no synthetic
    /// `EnumDef`.
    ErrorDetails,

    /// The built-in NOMINAL `ErrorInfo` type — `Error`'s second constructor
    /// argument, `{ message : String, details : Maybe ErrorDetails }` at the
    /// field level (SEAL fix — see `docs/architecture/
    /// docs/adr/0001-language-semantics-and-types.md`).
    ///
    /// Renders as `ipe_runtime::error::IpeErrorInfo`. NOT a structural
    /// record: a bare record literal cannot construct it (the type checker
    /// rejects the unification), so the backend never has to reconcile a
    /// synthesized record struct with the runtime's concrete type — the
    /// exit-0-then-cargo-fail this leaf exists to prevent. Field access is
    /// resolved by `ipe_types`' `ErrorRecordFields` table and emits plain
    /// `.message` / `.details` reads of the runtime struct's pub fields.
    ErrorInfo,

    /// The built-in NOMINAL `PanicInfo` type — `FfiPanic`'s payload,
    /// `{ message : String, stack : List String }` at the field level (SEAL
    /// fix; same design as [`IrType::ErrorInfo`]).
    ///
    /// Renders as `ipe_runtime::error::IpePanicInfo`.
    PanicInfo,

    /// The built-in NOMINAL `TypeInfo` type — `TypeMismatch`'s payload,
    /// `{ expected : String, actual : String }` at the field level (SEAL fix
    /// same design as [`IrType::ErrorInfo`]).
    ///
    /// Renders as `ipe_runtime::error::IpeTypeInfo`.
    TypeInfo,

    /// `Ipe.Db.Sql`'s opaque WHERE-fragment type — SQL injection closed by
    /// construction: a `SqlFragment` can only be built through the `Sql.*`
    /// combinator kernels, never from an arbitrary `String`.
    ///
    /// Renders as `ipe_runtime::db::SqlFragment`. Fully `Clone + PartialEq`
    /// (derivable), but NOT serde — it is a query-building value, never
    /// persisted to a Web session store. `Debug` is hand-written on the
    /// runtime type to show SQL text + bind COUNT only, never bind values (a
    /// bind may carry a revealed secret).
    SqlFragment,

    /// `Ipe.Secret`'s opaque, sealed secret-string type — "secrets are
    /// typed, never `fmt`-stringified": a `Secret` can only be built through
    /// `Secret.fromString`, never implicitly from a `String`.
    ///
    /// Renders as `ipe_runtime::secret::Secret`. Fully `Clone + PartialEq`
    /// (derivable — `PartialEq` is hand-written and CONSTANT-TIME, the only
    /// equality impl the runtime type has), but NOT serde — a `Secret` must
    /// never round-trip through a session store or any other serialisation
    /// path (this is ALSO the WASM hydration-island containment predicate a
    /// future `HydrationState` field-type gate consults, per
    /// `docs/adr/0005-delivery-shapes-runtimes-hosts-targets.md` §Q6 — nothing to build yet, the
    /// target does not exist). `Debug` and the Ipê-facing `IpeStringify` (the
    /// trait backing `toString` / interpolation / `Log.*With`) are BOTH
    /// hand-written on the runtime type to ALWAYS render a fixed
    /// `"<redacted>"` placeholder, never the wrapped value — see
    /// `ipe_runtime::secret`'s module doc for the full design.
    Secret,

    /// `Ipe.Path`'s opaque, validated filesystem-path type — "paths are
    /// typed, never a raw `String`": a `Path` can only be built through
    /// `Path.fromString`, which normalises the path and REJECTS a NUL byte or a
    /// `..` traversal escape, so an unvalidated string can never reach a
    /// filesystem syscall. This closes the raw-`String`-path injection surface
    /// (the reference compiler `FilePath = String` anti-pattern).
    ///
    /// Renders as `ipe_runtime::path::Path` (a `#[derive(Clone)]` newtype around
    /// a cleaned `String`; `Debug`/`PartialEq`/`Eq` are safe — a path is not a
    /// secret). The `Ipe.File` kernels take a `Path`, not a `String`, so
    /// construction is the single validated boundary.
    Path,
    /// `Ipe.Regex`'s opaque compiled-pattern handle. A `Regex` is built ONLY
    /// through `Regex.compile : String -> Result Error Regex`, which turns an
    /// invalid pattern into a typed `Err` rather than a silent no-match.
    ///
    /// Renders as `ipe_runtime::regex_kernel::Regex` (a newtype over an
    /// `Arc`-shared `regex::Regex`). `Clone` only: `regex::Regex` is neither
    /// `PartialEq`/`Eq`/`Hash`/`Ord` nor serde, so — like [`IrType::HttpRequest`]
    /// and the other opaque handles — a `Regex` is non-derivable-for-equality
    /// and not serde (a `Ipe.Web` Model field of type `Regex` is a compile-time
    /// rejection, never a silent wrong behaviour). `Debug` prints the source
    /// pattern, backing `toString` via the runtime's `Debug`-based fallback.
    Regex,

    /// `Ipe.Process.runWith`'s input record `{ args : List String, command :
    /// String, cwd : Maybe Path, env : List (String, String) }`. Renders as
    /// `ipe_runtime::system::ProcessRunWithCfg`.
    ///
    /// The lowerer folds any solved / annotated record matching that exact
    /// 4-field shape to this opaque variant (same mechanism as
    /// [`IrType::CacheCfg`]) so a `Process.runWith`-call record literal
    /// constructs the runtime struct the `process_run_with` kernel takes, rather
    /// than a backend-synthesised `RecArgsCommand…` struct that would mismatch
    /// it (E0308). Fully `Clone` (derivable on the runtime struct); never stored
    /// in a Ipe.Web Model.
    ProcessRunWithCfg,

    /// `Ipe.Process.runInPty`'s input record `{ command : String, args : List
    /// String, cwd : Maybe Path, env : List (String, String), cols : Int, rows :
    /// Int }`. Renders as `ipe_runtime::system::ProcessRunInPtyCfg`.
    ///
    /// The lowerer folds any solved / annotated record matching that exact
    /// 6-field shape to this opaque variant (same mechanism as
    /// [`IrType::ProcessRunWithCfg`]) so a `Process.runInPty`-call record literal
    /// constructs the runtime struct the `process_run_in_pty` kernel takes.
    ProcessRunInPtyCfg,

    /// `Ipe.Cache`'s configuration record `{ maxEntries : Int, ttlMs : Int,
    /// maxBytes : Int }`. Renders as `ipe_runtime::cache::CacheCfg`.
    ///
    /// The lowerer folds any solved / annotated record matching that exact
    /// 3-field shape to this opaque variant (same mechanism as
    /// [`IrType::HttpRequest`]) so a `Cache.defaultCfg`-built record literal
    /// constructs the runtime struct the `cache_new_raw` kernel takes, rather
    /// than a backend-synthesised `RecMaxBytes…` struct that would mismatch it
    /// (E0308). Fully `Clone` (derivable on the runtime struct); never stored in
    /// a Ipe.Web Model.
    CacheCfg,

    /// `Ipe.Cache.stats`'s return record `{ hits : Int, misses : Int,
    /// evictions : Int }`. Renders as `ipe_runtime::cache::CacheStats`.
    ///
    /// Folded the same way as [`IrType::CacheCfg`]: the `statsRaw` kernel
    /// alias's annotated return type is this record shape, and the runtime
    /// `cache_stats` returns `CacheStats`, so folding the annotation to this
    /// nominal type keeps the wrapper's declared return type in step with the
    /// kernel (otherwise E0308). Fields are read via `.hits`/`.misses`/
    /// `.evictions` on the runtime struct's pub fields.
    CacheStats,

    /// `Ipe.WebSocket`'s connect-configuration record `{ url : String,
    /// headers : List (String, String), timeout : Int, pingInterval : Int }`.
    /// Renders as `ipe_runtime::ws_client::WsClientCfg`.
    ///
    /// The lowerer folds any solved / annotated record matching that exact
    /// 4-field shape to this opaque variant (same mechanism as
    /// [`IrType::CacheCfg`]) so a `WebSocket.defaultCfg`-built record literal
    /// constructs the runtime struct the `web_socket_connect_with` kernel takes,
    /// rather than a backend-synthesised `RecHeaders…` struct that would mismatch
    /// it (E0308). Fully `Clone` (derivable on the runtime struct); never stored
    /// in a Ipe.Web Model.
    WebSocketClientCfg,

    /// `Ipe.Csv`'s document record `{ header : List String, rows : List (List
    /// String) }`. Renders as `ipe_runtime::csv::CsvDoc`.
    ///
    /// The lowerer folds any solved / annotated record matching that exact
    /// 2-field shape to this opaque variant (same mechanism as
    /// [`IrType::CacheCfg`]) so a record literal fed to `Csv.encode` constructs
    /// the runtime `CsvDoc` struct the `csv_encode` kernel takes — and the
    /// `csv_parse` kernel's `CsvDoc` return is field-accessed via `.header` /
    /// `.rows` — rather than a backend-synthesised `RecHeaderRows` struct that
    /// would mismatch it (E0308). Fully `Clone` (derivable on the runtime
    /// struct); never stored in a Ipe.Web Model.
    CsvDoc,

    /// `Ipe.Email`'s message record — 9 fields `{ from, to, cc, bcc, subject,
    /// textBody, htmlBody, attachments, replyTo }`. Renders as
    /// `ipe_runtime::email::EmailMessage`.
    ///
    /// Folded the same way as [`IrType::CsvDoc`]: the lowerer folds any solved /
    /// annotated record matching that exact 9-field shape (field NAMES and
    /// TYPES) so a `defaultMessage`-built record literal constructs the runtime
    /// struct the `email_send` kernel takes, rather than a backend-synthesised
    /// record struct that would mismatch it (E0308). Fully `Clone`.
    EmailMessage,

    /// `Ipe.Email`'s attachment record `{ filename : String, mimeType : String,
    /// content : Bytes }`. Renders as `ipe_runtime::email::EmailAttachment`
    /// (the runtime type name differs from the Ipê alias `Attachment`; the
    /// `content` field is `Bytes` = `Vec<u8>`, correct for arbitrary binary
    /// attachment payloads). Folded like [`IrType::EmailMessage`].
    EmailAttachment,

    /// `Ipe.Email`'s SES config record `{ region : String, key : String,
    /// secret : String }`. Renders as `ipe_runtime::email::SesConfig`. Folded
    /// like [`IrType::EmailMessage`].
    EmailSesConfig,

    /// `Ipe.Email`'s SMTP config record `{ host : String, port : Int,
    /// user : String, pass : String }`. Renders as
    /// `ipe_runtime::email::SmtpConfig`. Folded like [`IrType::EmailMessage`].
    EmailSmtpConfig,

    /// `Ipe.Email`'s `EmailProvider` ADT (`Resend String | Ses SesConfig |
    /// SendGrid String | Smtp SmtpConfig`). Renders as
    /// `ipe_runtime::email::EmailProvider`.
    ///
    /// The Ipê union's own [`EnumDef`] is SUPPRESSED in `ipe_lower` (same
    /// mechanism as `IpeCacheHandle`): the runtime enum IS the canonical
    /// representation, and the Ipê ctor names (`Resend`/`Ses`/`SendGrid`/`Smtp`)
    /// match the runtime variant names verbatim, so construction and pattern
    /// matching route directly onto the runtime enum. Mirrors the reference's
    /// `runtimeOpaqueTypes` `RPubUseAlias` for `EmailProvider`.
    EmailProvider,

    // ── Ipe.Crypto typed-key newtypes ─────────────────────────────────────
    /// Opaque role-typed crypto key (`ipe_runtime::crypto::Key`).
    ///
    /// The ONLY construction boundary is `Key.fromString`/`Key.fromBytes`;
    /// no implicit `String` coercion.  `PartialEq` is constant-time
    /// (`subtle::ConstantTimeEq`); `Debug` renders `"<key>"` — the wrapped
    /// material is never observable outside the construction boundary.
    /// Non-serde (a `Key` must never round-trip through a session store).
    CryptoKey,

    /// Opaque role-typed HMAC output (`ipe_runtime::crypto::Mac`).
    ///
    /// Produced exclusively by `hmacSha256WithKey` / `hmacSha512WithKey`.
    /// Extracted via `Mac.toHex` — the single greppable extraction boundary.
    /// `PartialEq` is safe (a MAC hex string is not secret); `Clone` + `Debug`.
    /// Non-serde.
    CryptoMac,

    // ── Ipe.Email.EmailAddress ─────────────────────────────────────────────
    /// Opaque validated email address (`ipe_runtime::email::EmailAddress`).
    ///
    /// The ONLY constructor is `EmailAddress.parse : String -> Maybe
    /// EmailAddress`, which rejects invalid addresses at the boundary —
    /// downstream code never sees the unvalidated `String`.  Extracted via
    /// `EmailAddress.toString`.  `Clone` + `PartialEq` + `Debug`; non-serde.
    EmailAddress,

    // ── Ipe.Url ────────────────────────────────────────────────────────────
    /// `Ipe.Url`'s opaque, validated URL type — "URLs are typed, never a raw
    /// `String`". A `Url` can only be built through `Url.fromString : String ->
    /// Result Error Url`, which parses with the `url` crate (the SAME parser the
    /// SSRF guard uses) and REJECTS a scheme-less / relative / unparseable
    /// string, so an unvalidated URL can never reach an outbound request. This
    /// closes the raw-`String`-URL scheme-confusion surface at the type
    /// boundary.
    ///
    /// Renders as `ipe_runtime::url::Url` (a newtype over `url::Url`). `Clone` +
    /// `Debug` + `PartialEq` + `Eq` are safe (a URL is not a secret); non-serde
    /// (a `Url` in a `Ipe.Web` Model field is a compile-time rejection, never a
    /// silent wrong behaviour — same posture as `Path`/`Regex`).
    Url,
    /// `Ipe.Url`'s opaque, validated same-origin RELATIVE reference — the path
    /// plus optional query plus optional fragment projection (RFC 3986 §4.2),
    /// NOT a `Url` (a
    /// `Url` is always absolute). Built only through `Url.relative : String ->
    /// Result Error Relative`, the `Url_relative` kernel that resolves the raw
    /// string against a fixed same-origin base with the `url` crate and REJECTS
    /// any scheme/authority (the browser-href SSRF boundary), so a
    /// `javascript:` / `//evil` / cross-origin string can never reach an `href`
    /// / `src` sink. Renders as `ipe_runtime::url::UrlRelative`. `Clone` +
    /// `Debug` + `PartialEq` + `Eq` are safe; non-serde (same posture as `Url`).
    UrlRelative,
    // ── Ipe.Db.Dsn ─────────────────────────────────────────────────────────
    /// Opaque validated database-connection descriptor
    /// (`ipe_runtime::dsn::Dsn`).
    ///
    /// The ONLY constructors are `Db.Dsn.parse : String -> Result Error Dsn` and
    /// `Db.Dsn.build`, both fail-closed parses; the descriptor's password is a
    /// `Secret`, so a `Dsn` cannot leak a credential. Renders as
    /// `ipe_runtime::dsn::Dsn`. `Clone` is safe; `Debug` is redacted; non-serde
    /// (a `Dsn` in a Model field is a compile-time rejection, same posture as
    /// `Secret`/`Url`).
    Dsn,
    // ── Ipe.Db external Connection ──────────────────────────────────────────
    /// The external-database connection handle `Connection mode`
    /// (`ipe_runtime::external_conn::ExternalConnection`), distinct from the app's
    /// `Db`. The phantom access-mode argument (`ReadOnly` / `ReadWrite`) is erased
    /// here: both modes render to the one concrete runtime type, so there is no
    /// `dyn` and one concrete pool per position. Minted only by `Db.Dsn.open`;
    /// `Clone`; `Debug` redacted; non-serde.
    Connection,
    /// The phantom read-only access-mode marker. Never a standalone runtime value
    /// — it appears only as [`Self::Connection`]'s erased argument. Present in the
    /// IR only so the read-only-vs-read-write distinction survives to the point the
    /// argument is dropped; it never renders to a Rust type on its own.
    ConnReadOnly,
    /// The phantom mutable access-mode marker. Same erasure as
    /// [`Self::ConnReadOnly`]; never renders standalone.
    ConnReadWrite,
    // ── Ipe.App runtime-config Setting ──────────────────────────────────────
    /// The runtime-config carrier `Setting shape`
    /// (`ipe_runtime::app_config::Setting`). The phantom shape marker
    /// (`Web` / `WebView` / `Terminal`) is erased here: every position renders
    /// to the one concrete runtime type, so there is no `dyn` and one concrete
    /// carrier per position. Built only by the setting kernels; `Clone`;
    /// non-serde (a `Setting` may carry a `Secret`).
    Setting,
    /// The phantom web-shape marker. Never a standalone runtime value — it
    /// appears only as [`Self::Setting`]'s erased argument; it never renders to
    /// a Rust type on its own.
    ShapeWeb,
    /// The phantom webview-shape marker. Same erasure as [`Self::ShapeWeb`].
    ShapeWebView,
    /// The phantom terminal-shape marker. Same erasure as [`Self::ShapeWeb`].
    ShapeTerminal,
    // ── Ipe.Locale ─────────────────────────────────────────────────────────
    /// Opaque validated BCP-47 locale handle (`ipe_runtime::locale::Locale`).
    ///
    /// The ONLY constructor is `Locale.fromTag : String -> Maybe Locale`, which
    /// rejects invalid BCP-47 tags at the boundary — an invalid tag is a typed
    /// absence (`Nothing`), never a silent fallback.  Extracted via
    /// `Locale.toTag : Locale -> String`.  `Clone` + `PartialEq` + `Debug`;
    /// non-serde (a `Locale` is a transient runtime value, not a session-store
    /// datum).  Model-schema tag: 62.
    Locale,
    // ── Shape opaque app leaves ─────────────────────────────────────────────
    /// The msg-erased result of `Ipe.Tea.Web.tea` — an opaque handle carrying
    /// a fully-initialised web app whose `msg` type was erased at the
    /// `app`-call boundary.
    ///
    /// Rendered as `ipe_runtime::tea::WebApp`. The handle is opaque (no public
    /// constructor in Ipê; produced only by `Web.tea`/`Web.appRouted`/`Web.appWith`)
    /// so `mountApp : WebApp -> Route` can reject a `TuiApp` at compile time.
    /// Non-derivable, non-serde: the handle wraps live runtime state.
    WebApp,
    /// The msg-erased result of `Ipe.Tea.Tui.tea` — a live TUI
    /// (terminal full-screen) app handle.
    ///
    /// Rendered as `ipe_runtime::tea::TuiApp`.
    TuiApp,
    /// The msg-erased result of `Ipe.Tea.Cli.tea` — a live
    /// line-oriented CLI app handle.
    ///
    /// Rendered as `ipe_runtime::tea::CliApp`.
    CliApp,
    /// The msg-erased result of `Ipe.Tea.Worker.tea` — a live view-less,
    /// co-located worker app handle.
    ///
    /// Rendered as `ipe_runtime::tea::WorkerApp`. Opaque, non-derivable,
    /// non-serde: the handle wraps a live runtime event loop.
    WorkerApp,
}

/// Tag enum for the message-parametric `Ipe.Ui` / `Ipe.Html` types.
///
/// Used inside [`IrType::Ui`] to select the correct Rust path at emission time.
/// The set is intentionally small to keep the pattern match exhaustive without a
/// catch-all.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, serde::Serialize, serde::Deserialize)]
pub enum UiCtor {
    /// `Html msg` — a rendered HTML tree (`ipe_runtime::html::Html<M>`).
    Html,
    /// `Element msg` — a Ipe.Ui layout element (`ipe_runtime::ui::element::Element<M>`).
    Element,
    /// `Cells msg` — a Tui-only structured view (`ipe_runtime::tui::CellsView<M>`).
    /// Produced exclusively by `Ipe.Ui.Cells.*` builders; the type is distinct from
    /// `Element msg` so Web-only constructs cannot appear inside a Tui view.
    Cells,
    /// `Attribute msg` from `Ipe.Ui` — a layout attribute (`ipe_runtime::ui::element::Attribute<M>`).
    UiAttribute,
    /// `Attribute msg` from `Ipe.Ui.Tui` — a cell-native attribute
    /// (`ipe_runtime::tui::TuiAttr<M>`). Distinct from `UiAttribute`: only
    /// terminal-honorable attributes inhabit it, so a DOM attribute is a
    /// type error in a `Screen` view rather than a silent render-time drop.
    TuiAttribute,
    /// `Lines msg` from `Ipe.Ui.Cli` — a line-oriented view
    /// (`ipe_runtime::tui::LinesView<M>`). Distinct from both `Element msg` and
    /// `Cells msg`: line-scoped, so 2D cell and DOM builders cannot appear in it.
    CliLines,
    /// `Attribute msg` from `Ipe.Ui.Cli` — a line-native attribute
    /// (`ipe_runtime::tui::CliAttr<M>`). Only line-scoped styles inhabit it, so a
    /// 2D cell attribute or a DOM attribute is a type error in a `Lines` view.
    CliAttribute,
    /// `Attribute msg` from `Ipe.Html` / `Ipe.Html.Attributes` —
    /// an HTML attribute (`ipe_runtime::html::Attribute<M>`).
    HtmlAttribute,
    /// `Event msg` from `Ipe.Html.Events` —
    /// an HTML event handler (`ipe_runtime::html::Event<M>`).
    HtmlEvent,
    /// `Label msg` — a `Ipe.Ui.Input` label descriptor (`ipe_runtime::ui::input::Label<M>`).
    Label,
    /// `Placeholder msg` — a `Ipe.Ui.Input` placeholder descriptor
    /// (`ipe_runtime::ui::input::Placeholder<M>`).
    Placeholder,
    /// `RadioOption msg` — a `Ipe.Ui.Input` radio option descriptor
    /// (`ipe_runtime::ui::input::RadioOption<M>`).
    RadioOption,
}

/// Tag enum for the nullary (non-message-parametric) `Ipe.Ui` types.
///
/// Used inside [`IrType::UiPlain`] to select the correct Rust path at emission
/// time.  The set is closed.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, serde::Serialize, serde::Deserialize)]
pub enum UiPlain {
    /// `Length` — `ipe_runtime::ui::element::Length`.
    Length,
    /// `Color` — `ipe_runtime::color::Color`.
    Color,
    /// `HAlign` — `ipe_runtime::ui::element::HAlign`.
    HAlign,
    /// `VAlign` — `ipe_runtime::ui::element::VAlign`.
    VAlign,
    /// `Location` — `ipe_runtime::ui::element::Location`.
    Location,
    /// `PseudoClass` — `ipe_runtime::ui::element::PseudoClass`.
    PseudoClass,
    /// `Description` — `ipe_runtime::ui::element::Description`.
    Description,
    /// `LayoutContext` — `ipe_runtime::ui::element::LayoutContext`.
    LayoutContext,
    /// `ColorError` — `ipe_runtime::color::ColorError`, the typed parse-error
    /// channel of the `Ipe.Color` string constructors (`fromHex` / `fromName`).
    ColorError,
    /// `TermProfile` — `ipe_runtime::color::TermProfile`, the terminal capability
    /// profile `Color.toAnsi` targets.
    TermProfile,
    /// `AnsiColor` — `ipe_runtime::color::AnsiColor`, the terminal colour: the
    /// `Ipe.Color` palette constructors (`black`…`brightWhite`, `default`, `rgb`)
    /// build it, `Color.toAnsi` down-samples an sRGB `Color` to it, and the Tui
    /// and Cli `color` / `bg` builders accept it.
    AnsiColor,
    /// `WcagLevel` — `ipe_runtime::color::WcagLevel`, the WCAG conformance level
    /// (`aa` / `aaa`) `Color.meetsWcag` checks against.
    WcagLevel,
    /// `TextSize` — `ipe_runtime::color::TextSize`, the text-size band
    /// (`normalText` / `largeText`) a WCAG threshold applies to.
    TextSize,
    /// `Deficiency` — `ipe_runtime::color::Deficiency`, the colour-vision
    /// deficiency `Color.simulate` previews.
    Deficiency,
}

/// Total predicate: does the Rust type that [`IrType`] renders to support the
/// full `#[derive(Clone, Debug, PartialEq)]` set the backend stamps on every
/// generated enum / record struct?
///
/// This is the authoritative soundness gate that keeps the *unconditional*
/// derive off any type whose rendered Rust form lacks one of those traits, so a
/// well-typed program that stores such a value in a record field or enum payload
/// can never `ipe`-succeed and then `cargo`-fail on a missing `Clone` / `Debug`
/// / `PartialEq` impl. The non-derivable leaves are:
///
/// * [`IrType::Fun`] — a first-class function, rendered `Box<dyn Fn(..) -> R>`
///   (no `Clone`/`Debug`/`PartialEq`).
/// * the opaque effect / handle wrappers [`IrType::Task`], [`IrType::Cmd`],
///   [`IrType::Sub`], [`IrType::Decoder`], [`IrType::Db`] — each wraps a boxed
///   closure or future (no `Clone`/`Debug`/`PartialEq`).
/// * the opaque server / live handles [`IrType::ServerRequest`] /
///   [`IrType::ServerResponse`] / [`IrType::ServerRoute`] /
///   [`IrType::ServerCookie`] / [`IrType::StreamWriter`] /
///   [`IrType::HttpRequest`] / [`IrType::WebSocketServer`] /
///   [`IrType::WebSocketServerCfg`] / [`IrType::WebReq`] / [`IrType::WebRoute`]
///   (each lacks at least `PartialEq`).
/// * the two `Clone`-only `Ipe.Html` carriers [`UiCtor::HtmlAttribute`] /
///   [`UiCtor::HtmlEvent`] (they hold `Arc<dyn Fn>` event handlers).
///
/// A non-derivable leaf poisons every *transparent carrier* that reaches it
/// (list / set / tuple / dict / result / maybe / closed record) and every user
/// enum whose payload reaches it. `enum_derivable` answers the same question for
/// a referenced user [`IrType::Enum`]; the caller resolves the enum-to-enum
/// fixpoint before consulting it (see the backend `EmitCtx`).
///
/// Leaves that DO render to a fully-derivable Rust type return `true`:
/// primitives, `Bytes` (`Vec<u8>`), `Json` (`serde_json::Value`), every
/// [`UiPlain`] value type, the three fully-derivable [`IrType::Ui`] carriers
/// (`Html` / `Element` / ui-`Attribute`), and a [`IrType::Generic`] parameter
/// (the `derive` macro adds the per-parameter trait bound, so the generic frame
/// stays derivable).
///
/// The match is deliberately exhaustive with no wildcard arm: a new [`IrType`]
/// variant must make an explicit derivability decision here rather than default
/// silently into the derivable branch (walker-arm rule).
#[must_use]
#[allow(clippy::too_many_lines)] // one arm per IrType variant, deliberately exhaustive
pub fn ir_type_is_derivable(
    ty: &IrType,
    enum_derivable: &impl Fn(&ModPath, Symbol) -> bool,
) -> bool {
    match ty {
        IrType::Int
        | IrType::Float
        | IrType::Bool
        | IrType::Str
        | IrType::Char
        | IrType::Unit
        | IrType::Bytes
        | IrType::Json
        // `IpeOrder` derives Clone + Copy + PartialEq + Eq + Debug — fully derivable.
        // `Decimal` derives Clone + Copy + PartialEq + Eq + Debug — fully derivable.
        // `IpeErrorKind` derives Clone + Copy + PartialEq + Eq + Debug.
        // `IpeError` derives Clone + PartialEq + Debug (not Copy — carries a
        // heap-allocated `String` message; not `Eq` — its `IpeErrorInfo`
        // field carries a `IpeMaybe`, which is `PartialEq`-only).
        // `IpeErrorDetails` derives Clone + PartialEq + Eq + Debug (backlog
        // follow-up).
        // `IpeErrorInfo` derives Clone + PartialEq + Debug (not Eq — carries
        // a `IpeMaybe`); `IpePanicInfo`/`IpeTypeInfo` derive Clone +
        // PartialEq + Eq + Debug (SEAL fix).
        // `SqlFragment` derives Clone + PartialEq (hand-written Debug; see
        // its own doc) — fully derivable, not serde (see `ir_type_is_serde`).
        // `Secret` derives Clone; `PartialEq`/`Debug` are hand-written
        // (constant-time equality, always-redacting Debug — see its own doc)
        // — fully derivable, not serde (see `ir_type_is_serde`).
        // `BackoffStrategy` derives Clone+Copy+Debug+PartialEq+Eq — fully derivable, not serde.
        | IrType::BackoffStrategy
        | IrType::Order
        | IrType::HttpMethod
        | IrType::Decimal
        | IrType::ErrorKind
        | IrType::Error
        | IrType::ErrorDetails
        | IrType::ErrorInfo
        | IrType::PanicInfo
        | IrType::TypeInfo
        | IrType::SqlFragment
        | IrType::Secret
        // `Path` derives Clone+Debug+PartialEq+Eq (a validated string newtype).
        | IrType::Path
        // `Url` derives Clone+Debug+PartialEq+Eq (a newtype over `url::Url`).
        | IrType::Url
        // `Relative` derives Clone+Debug+PartialEq+Eq (validated String fields).
        | IrType::UrlRelative
        // `Dsn` derives Clone; `Debug` is hand-written (redacting) — fully
        // derivable, not serde (carries a `Secret`).
        | IrType::Dsn
        // Cache config / stats + Csv document + process-run config runtime
        // structs derive Clone+Debug+PartialEq.
        | IrType::ProcessRunWithCfg
        | IrType::ProcessRunInPtyCfg
        | IrType::CacheCfg
        | IrType::WebSocketClientCfg
        | IrType::CacheStats
        | IrType::CsvDoc
        // `CryptoKey` derives Clone; PartialEq is constant-time (hand-written);
        // Debug renders "<key>" (hand-written) — same posture as Secret.
        | IrType::CryptoKey
        // `CryptoMac`: `Clone`+`Debug` derived, `PartialEq` hand-written
        // constant-time (same posture as `CryptoKey`/`Secret`).
        | IrType::CryptoMac
        // `EmailAddress` derives Clone+PartialEq+Debug — fully derivable.
        | IrType::EmailAddress
        // `Locale` derives Clone+PartialEq+Debug — fully derivable.
        | IrType::Locale
        // `Principal` derives Clone+Debug+PartialEq+Eq — fully derivable.
        | IrType::Principal
        | IrType::Generic(_)
        // A row generic monomorphises to a concrete record struct, which is
        // derivable by construction; its `Clone` (and any whole-record bound)
        // is guaranteed by the witness bound set the backend emits.
        | IrType::RowGeneric(_)
        // `SessionHandle` renders to a bare `i64` — fully derivable + serde.
        | IrType::SessionHandle
        | IrType::UiPlain(_) => true,
        // The fully-derivable Ipe.Ui / Ipe.Html carriers vs the two Clone-only
        // ones (`html::Attribute` / `html::Event`, which hold `Arc<dyn Fn>`).
        IrType::Ui { ctor, msg } => {
            matches!(
                ctor,
                UiCtor::Html
                    | UiCtor::Element
                    | UiCtor::Cells
                    | UiCtor::UiAttribute
                    | UiCtor::Label
                    | UiCtor::Placeholder
                    | UiCtor::RadioOption
            ) && ir_type_is_derivable(msg, enum_derivable)
        }
        // Non-derivable opaque leaves (each lacks ≥1 of Clone / Debug / PartialEq).
        IrType::Task(_)
        | IrType::Cmd(_)
        | IrType::Sub(_)
        | IrType::Decoder(_)
        | IrType::Db
        // External connection handle + its phantom access-mode markers — opaque
        // runtime types, same posture as `Db` (not derivable, not serde).
        | IrType::Connection
        | IrType::ConnReadOnly
        | IrType::ConnReadWrite
        // Runtime-config carrier + its phantom shape markers — opaque, same
        // posture as the connection handle (not derivable, not serde).
        | IrType::Setting
        | IrType::ShapeWeb
        | IrType::ShapeWebView
        | IrType::ShapeTerminal
        | IrType::Fun(_, _)
        // The promoted `Arc<dyn Fn>` carrier is `Clone` but still lacks `Debug`
        // and `PartialEq`, so it is exactly as non-derivable as `Fun`.
        | IrType::SharedFun(_, _)
        // A curried `Box<dyn FnOnce>` chain is exactly as non-derivable as
        // `Fun` (it renders to the same family of boxed trait objects).
        | IrType::FnOnceChain(_, _)
        | IrType::ServerRequest
        | IrType::ServerResponse
        | IrType::ServerRoute
        | IrType::ServerCookie
        // `AuthConfig` derives only Clone (holds a `Secret`); `TokenSource`
        // derives Clone+Debug — both lack PartialEq, so not fully derivable.
        | IrType::AuthConfig
        | IrType::TokenSource
        // `StreamWriter` derives Clone+Copy+Debug but not PartialEq — not fully derivable.
        | IrType::StreamWriter
        // `HttpRequest` is an opaque handle — not fully derivable.
        | IrType::HttpRequest
        // `Regex` is an opaque compiled-pattern handle — Clone + Debug but the
        // inner `regex::Regex` has no PartialEq, so not fully derivable.
        | IrType::Regex
        // `WsHandle` / `WsServerCfg` are opaque handles — not fully derivable.
        | IrType::WebSocketServer
        | IrType::WebSocketServerCfg
        // Ipe.Email runtime structs + the EmailProvider enum derive only
        // Clone+Debug (no PartialEq) — not fully derivable.
        | IrType::EmailMessage
        | IrType::EmailAttachment
        | IrType::EmailSesConfig
        | IrType::EmailSmtpConfig
        | IrType::EmailProvider
        | IrType::WebReq
        // `Route<Page>` holds an `Arc<dyn Fn>` builder — never derivable/serde
        // regardless of its page argument.
        | IrType::WebRoute(_)
        // The widget handle carries a generated tag string only; it never
        // crosses the seam, so it is non-derivable regardless of its seal args.
        | IrType::CustomElement { .. }
        // Opaque shape app leaves — each wraps live runtime state (event loops,
        // handles) that cannot be cloned, compared, or serialised.
        | IrType::WebApp
        | IrType::TuiApp
        | IrType::CliApp
        | IrType::WorkerApp => false,
        // Transparent carriers: derivable iff every carried element is.
        IrType::Maybe(e) | IrType::List(e) | IrType::Set(e) => {
            ir_type_is_derivable(e, enum_derivable)
        }
        IrType::Result(a, b) | IrType::Dict(a, b) => {
            ir_type_is_derivable(a, enum_derivable) && ir_type_is_derivable(b, enum_derivable)
        }
        IrType::Tuple(es) => es.iter().all(|e| ir_type_is_derivable(e, enum_derivable)),
        IrType::Record(fields) => fields
            .values()
            .all(|f| ir_type_is_derivable(f, enum_derivable)),
        IrType::Enum { home, name, args } => {
            enum_derivable(home, *name)
                && args.iter().all(|a| ir_type_is_derivable(a, enum_derivable))
        }
    }
}

/// Total predicate: does the Rust type that [`IrType`] renders to derive
/// `serde::Serialize` **and** `serde::de::DeserializeOwned`?
///
/// This is the authoritative admissibility gate for a `Ipe.Web` / `Ipe.Web`
/// **Model**: the live runtime persists the Model to the session store, so
/// `web_app` bounds it "Serialize + `DeserializeOwned` + Clone + `PartialEq`".
/// Without this gate a well-typed program that stores a non-serialisable value
/// in its Model `ipe`-succeeds and then `cargo`-fails on the missing `serde`
/// bound (the seal hole this gate closes).
///
/// The serde-OK leaf set is a **strict subset** of the derivable leaf set
/// ([`ir_type_is_derivable`]): every serde-OK leaf is also derivable, so
/// `ir_type_is_serde(t) ⇒ ir_type_is_derivable(t)` structurally (the two arms
/// that differ both demote to `false` here). Consequently a serde-admissible
/// Model automatically satisfies the `Clone + PartialEq` half of the bound too —
/// the Web gate needs only this one predicate.
///
/// serde-OK leaves (render to a `serde`-deriving Rust type):
/// * primitives `Int` / `Float` / `Bool` / `Str` / `Char` / `Unit`,
/// * `Bytes` (`Vec<u8>`), `Json` (`serde_json::Value` — itself `serde`),
/// * `Generic(_)` — the derive macro adds a per-parameter `T: Serialize` /
///   `T: DeserializeOwned` bound, so the frame stays admissible (a concrete
///   Model never carries a free generic anyway).
///
/// NON-serde leaves — the full non-derivable set (functions, the opaque
/// effect/handle wrappers, the two `Clone`-only `Ipe.Html` carriers) PLUS the
/// derivable-but-not-`serde` UI value types:
/// * every [`IrType::Ui`] carrier (`Html` / `Element` / ui-`Attribute` and the
///   two `html` carriers) — verified: `src/runtime/rust/src/{html,ui}` derive
///   only `Clone, Debug, PartialEq`, never `Serialize` / `Deserialize`,
/// * every [`IrType::UiPlain`] value type (`Length` / `Color` / `HAlign` / … →
///   `ipe_runtime::ui::element::*`) — verified: no `serde` derive in
///   `src/runtime/rust/src/ui`.
///
/// A non-serde leaf poisons every transparent carrier that reaches it and every
/// user enum whose payload reaches it. `enum_serde` answers the same question
/// for a referenced user [`IrType::Enum`]; the caller resolves the enum-to-enum
/// fixpoint before consulting it (see the backend `EmitCtx`, which computes an
/// `enum_serde` fixpoint parallel to `enum_derivable`).
///
/// The match is deliberately exhaustive with no wildcard arm: a new [`IrType`]
/// variant must make an explicit serde decision here (walker-arm rule).
#[must_use]
pub fn ir_type_is_serde(ty: &IrType, enum_serde: &impl Fn(&ModPath, Symbol) -> bool) -> bool {
    match ty {
        IrType::Int
        | IrType::Float
        | IrType::Bool
        | IrType::Str
        | IrType::Char
        | IrType::Unit
        | IrType::Bytes
        | IrType::Json
        | IrType::Generic(_)
        // A row generic resolves to a concrete struct at each call site; serde
        // over the whole record, if the body needs it, is carried by the
        // witness bound set exactly as for a plain generic.
        | IrType::RowGeneric(_)
        // `Order` (LT/EQ/GT) is a plain no-payload enum; IpeOrder derives serde.
        // `Decimal` is a Copy newtype; rust_decimal supports serde via feature.
        // `IpeErrorKind`/`IpeError`/`IpeErrorDetails` derive serde — `Error`
        // must serialize to round-trip through a Web session store (e.g. a
        // Model's `historyError : Maybe Error` field). The nominal payload
        // types `IpeErrorInfo`/`IpePanicInfo`/`IpeTypeInfo` derive serde for
        // the same reason (they ride inside `Error`; SEAL fix).
        // `HttpMethod` derives serde (unit-variant enum, maps to/from string).
        | IrType::Order
        | IrType::HttpMethod
        | IrType::Decimal
        | IrType::ErrorKind
        | IrType::Error
        | IrType::ErrorDetails
        | IrType::ErrorInfo
        | IrType::PanicInfo
        | IrType::TypeInfo
        // `SessionHandle` renders to a bare `i64` (the session-registry key), which
        // is natively serde. Round-tripping it through a Web/SPA Model store is
        // harmless: every session op validates the id fail-closed (an unknown or
        // stale id yields an inert frame stream / a typed `Err`), so a rehydrated id
        // that names no live session is safe by construction. Opacity — no Ipê
        // constructor — still makes a MEANINGFUL handle unforgeable in source.
        | IrType::SessionHandle => true,
        // All non-serde leaves collapse to `false`:
        //   * `UiPlain` value types (`Length`/`Color`/… → `ui::element::*`) and
        //     every `Ui` carrier (`Html`/`Element`/`Attribute`) derive only
        //     Clone/Debug/PartialEq, never serde — the two arms where serde is
        //     STRICTER than `ir_type_is_derivable` (there they are `true`);
        //   * the opaque effect/handle wrappers + first-class functions (also
        //     non-derivable) — a `Box<dyn Fn>` / future / handle is not serde.
        IrType::UiPlain(_)
        | IrType::Ui { .. }
        | IrType::Task(_)
        | IrType::Cmd(_)
        | IrType::Sub(_)
        | IrType::Decoder(_)
        | IrType::Db
        // External connection handle + its phantom access-mode markers — opaque
        // runtime types, same posture as `Db` (not derivable, not serde).
        | IrType::Connection
        | IrType::ConnReadOnly
        | IrType::ConnReadWrite
        // Runtime-config carrier + shape markers — non-serde (may carry a
        // `Secret`), so a `Setting` in a Web Model field is a compile-time
        // rejection (`IPE-L0120`), never a session-store leak.
        | IrType::Setting
        | IrType::ShapeWeb
        | IrType::ShapeWebView
        | IrType::ShapeTerminal
        | IrType::Fun(_, _)
        // Same family as `Fun` — the `Arc<dyn Fn>` promoted carrier is never serde.
        | IrType::SharedFun(_, _)
        // Same family as `Fun` — a boxed `FnOnce` chain is never serde.
        | IrType::FnOnceChain(_, _)
        | IrType::ServerRequest
        | IrType::ServerResponse
        | IrType::ServerRoute
        | IrType::ServerCookie
        // `StreamWriter` is an opaque handle; not serde.
        | IrType::StreamWriter
        // `HttpRequest` is an opaque handle; not serde.
        | IrType::HttpRequest
        // `Regex` is an opaque compiled-pattern handle; `regex::Regex` is not
        // serde, so a `Regex` never round-trips through a session store.
        | IrType::Regex
        // `SqlFragment` is a query-building value, never persisted to a Web
        // session store — derivable (see `ir_type_is_derivable`) but not serde.
        | IrType::SqlFragment
        // `Secret` must NEVER round-trip through serde (session store, JSON
        // encode, anything) — derivable (see `ir_type_is_derivable`) but not
        // serde. This is the load-bearing gate that makes a `Ipe.Web` Model
        // field of type `Secret` a compile-time IPE-L0120, not a session-store
        // leak.
        | IrType::Secret
        // `Path` is a filesystem-boundary value, not a serialisable Model
        // field — derivable (see `ir_type_is_derivable`) but NOT serde. The
        // runtime `ipe_runtime::path::Path` deliberately has no serde impl, so
        // a `Ipe.Web` Model field of type `Path` is a compile-time IPE-L0120
        // rather than a mismatch at emit — a filesystem path has no place in a
        // client-hydrated session Model.
        | IrType::Path
        // `Url` is a request-boundary value, not a serialisable Model field —
        // derivable but NOT serde (the runtime `ipe_runtime::url::Url` has no
        // serde impl), so a `Ipe.Web` Model field of type `Url` is a
        // compile-time IPE-L0120 rather than a mismatch at emit, same posture
        // as `Path`.
        | IrType::Url
        // `Relative` is a same-origin href projection, never a serialisable
        // Model field — derivable but NOT serde, same posture as `Url`.
        | IrType::UrlRelative
        // `Dsn` is a connection-descriptor value carrying a `Secret`, never a
        // serialisable Model field — derivable but NOT serde (the runtime
        // `ipe_runtime::dsn::Dsn` has no serde impl), so a Model field of type
        // `Dsn` is a compile-time IPE-L0120, same posture as `Url` / `Secret`.
        | IrType::Dsn
        // Cache config / stats + Csv document + process-run config are
        // kernel-boundary data records — derivable (see `ir_type_is_derivable`)
        // but never persisted to a session store, so not serde.
        | IrType::ProcessRunWithCfg
        | IrType::ProcessRunInPtyCfg
        | IrType::CacheCfg
        | IrType::WebSocketClientCfg
        | IrType::CacheStats
        | IrType::CsvDoc
        // Ipe.Email runtime structs + EmailProvider enum are kernel-boundary
        // values (`email_send`), never persisted to a session store — the
        // runtime types carry no serde derive.
        | IrType::EmailMessage
        | IrType::EmailAttachment
        | IrType::EmailSesConfig
        | IrType::EmailSmtpConfig
        | IrType::EmailProvider
        // `WsHandle` / `WsServerCfg` are opaque handles; not serde.
        | IrType::WebSocketServer
        | IrType::WebSocketServerCfg
        | IrType::WebReq
        // `BackoffStrategy` is not a session datum — kernel-boundary value, no serde derive.
        | IrType::BackoffStrategy
        // Typed-key newtypes must NEVER round-trip through serde — a `Key`
        // in a Web Model session store would be a secret-material leak; a
        // `Mac` in a session store is unnecessary exposure; an `EmailAddress`
        // in a session store is fine in principle but the runtime type carries
        // no serde derive (additive expansion is straightforward when needed).
        | IrType::CryptoKey
        | IrType::CryptoMac
        | IrType::EmailAddress
        // `Locale` is a transient runtime value, not a session datum; the
        // runtime type carries no serde derive.
        | IrType::Locale
        // `Principal` must NEVER round-trip through serde — a client-hydrated
        // Web Model field of type `Principal` would let a client forge an
        // authenticated identity by supplying the session datum. Non-serde makes
        // that a compile-time IPE-L0120 rather than a mint bypass, the same
        // posture as `Secret`.
        | IrType::Principal
        // `AuthConfig` carries a `Secret`; `TokenSource` is a transient
        // routing descriptor. Neither is a session datum — never serde.
        | IrType::AuthConfig
        | IrType::TokenSource
        // `Route<Page>` holds an `Arc<dyn Fn>` builder — never derivable/serde
        // regardless of its page argument.
        | IrType::WebRoute(_)
        // The widget handle is never a session datum and never crosses the
        // seam; the runtime type carries no serde derive.
        | IrType::CustomElement { .. }
        // Opaque shape app leaves — live runtime handles wrapping event loops;
        // they cannot be serialised. A shape app handle in a Web Model field is
        // a compile-time IPE-L0120 rejection.
        | IrType::WebApp
        | IrType::TuiApp
        | IrType::CliApp
        | IrType::WorkerApp => false,
        // Transparent carriers: serde-OK iff every carried element is.
        IrType::Maybe(e) | IrType::List(e) | IrType::Set(e) => ir_type_is_serde(e, enum_serde),
        IrType::Result(a, b) | IrType::Dict(a, b) => {
            ir_type_is_serde(a, enum_serde) && ir_type_is_serde(b, enum_serde)
        }
        IrType::Tuple(es) => es.iter().all(|e| ir_type_is_serde(e, enum_serde)),
        IrType::Record(fields) => fields.values().all(|f| ir_type_is_serde(f, enum_serde)),
        IrType::Enum { home, name, args } => {
            enum_serde(home, *name) && args.iter().all(|a| ir_type_is_serde(a, enum_serde))
        }
    }
}

/// A neutral runtime-feature identifier that an [`IrType`] leaf's emitted Rust
/// form REQUIRES to compile.
///
/// This enum is the IR-crate half of the feature single-source-of-truth. It is
/// deliberately provider-agnostic: it names only the runtime cargo features a
/// *type mention* can force (the leaf renders to an `ipe_runtime::<module>` path
/// the runtime crate `#[cfg(feature = …)]`-gates), NOT the kernel-call or
/// build-mode features (`async`, `debugger`) that no type carries. The backend
/// maps each variant to its concrete `RuntimeFeature` at the SSOT boundary
/// ([`RuntimeFeatureId::feature_name`] is that exact cargo name), so the IR crate
/// stays free of a backend dependency while the mapping remains a total function
/// checked by rustc — a feature the runtime crate does not declare cannot be
/// named, and a new gated leaf that forgets its requirement fails to compile in
/// [`ir_type_feature_requirement`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RuntimeFeatureId {
    /// `json` — the `Value` (`JsonVal`) / `Decoder<T>` types.
    Json,
    /// `url` — the `ipe_runtime::url::Url` typed-URL newtype.
    Url,
    /// `secret` — the `ipe_runtime::secret::Secret` opaque secret.
    Secret,
    /// `decimal` — the `ipe_runtime::decimal::Decimal` newtype.
    Decimal,
    /// `regex` — the `ipe_runtime::regex_kernel::Regex` compiled-pattern handle.
    Regex,
    /// `csv_kernel` — the `ipe_runtime::csv::CsvDoc` document record.
    Csv,
    /// `cache_kernel` — the `ipe_runtime::cache::{CacheCfg, CacheStats}` records.
    CacheKernel,
    /// `websocket_client` — the `ipe_runtime::ws_client::WsClientCfg` record.
    WebsocketClient,
    /// `email` — the `ipe_runtime::email::*` message / attachment / config /
    /// provider / address types.
    Email,
    /// `crypto-core` — the `ipe_runtime::crypto_core::{Key, Mac}` typed newtypes.
    CryptoCore,
    /// `db` — the `ipe_runtime::db`/`dsn`/`external_conn` types (`SqlFragment`,
    /// `Dsn`, the external `Connection` handle).
    Db,
    /// `server` — the `ipe_runtime::server`/`server_stream` opaque handles
    /// (`ServerRequest` / `ServerResponse` / `ServerRoute` / `ServerCookie` /
    /// `AuthConfig` / `TokenSource` / `StreamWriter` / the WebSocket-server
    /// handles).
    Server,
    /// `http_client` — the `ipe_runtime::http_client::{HttpRequest, HttpMethod}`
    /// outbound-client types.
    HttpClient,
    /// `web` — the `ipe_runtime::web::{WebReq, route::Route}` app types.
    Web,
}

impl RuntimeFeatureId {
    /// The exact cargo feature name in `src/runtime/rust/Cargo.toml` this
    /// identifier maps to. The backend's `RuntimeFeature::as_str` produces the
    /// same string for the corresponding variant; the two are kept in step by the
    /// featureset-closure SEAL, which resolves every selected name against the
    /// runtime crate's declared `[features]` universe.
    #[must_use]
    pub const fn feature_name(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Url => "url",
            Self::Secret => "secret",
            Self::Decimal => "decimal",
            Self::Regex => "regex",
            Self::Csv => "csv_kernel",
            Self::CacheKernel => "cache_kernel",
            Self::WebsocketClient => "websocket_client",
            Self::Email => "email",
            Self::CryptoCore => "crypto-core",
            Self::Db => "db",
            Self::Server => "server",
            Self::HttpClient => "http_client",
            Self::Web => "web",
        }
    }
}

/// The runtime cargo feature a single [`IrType`] leaf's emitted Rust form
/// requires.
///
/// The total, wildcard-free single source of truth that makes "a feature-gated
/// type emitted without its feature" unrepresentable.
///
/// This is the exact shape of [`ir_type_is_derivable`]: an exhaustive `match`
/// over every [`IrType`] variant with NO wildcard arm. A leaf whose emitted Rust
/// names an `ipe_runtime::<module>` path the runtime crate `#[cfg(feature = …)]`-
/// gates returns `Some(<that feature>)`; every ungated leaf returns `None`; every
/// transparent carrier (`List` / `Maybe` / `Tuple` / record / enum / …) returns
/// `None` at its own node — the CARRIER itself renders to an ungated `Vec` /
/// `IpeMaybe` / tuple / user struct, and its element leaves are visited by the
/// transitive walk the callers drive (`ir_type_mentions` in the lowerer, the
/// backend's program-wide type fold). Folding those two — one requirement per
/// leaf, unioned over every emitted type — yields the whole program's
/// type-required feature set.
///
/// The `Url` breach this closes was precisely a gated leaf (`IrType::Url`,
/// rendering `ipe_runtime::url::Url` behind `#[cfg(feature = "url")]`) with no
/// feature predicate: the feature stayed off and the emit dangled (E0433) though
/// `ipe` exited 0. Because this function is total and wildcard-free, a future
/// gated leaf CANNOT be added without stating its feature here — the compile
/// fails otherwise — so the class is closed by construction rather than by an
/// authored per-feature predicate that may be forgotten.
///
/// A note on the phantom / erased markers (`ConnReadOnly` / `ShapeWeb` / …): they
/// never render standalone, but their enclosing carrier (`Connection` / `Setting`)
/// does; where the carrier is feature-gated the marker shares that gate, so the
/// markers carry the same requirement as their carrier for a fail-closed union.
#[must_use]
#[allow(clippy::too_many_lines)] // one arm per IrType variant, deliberately exhaustive
pub const fn ir_type_feature_requirement(ty: &IrType) -> Option<RuntimeFeatureId> {
    match ty {
        // ── `json` — the JSON value + decoder types ──────────────────────────
        // A `Decoder<T>` node is itself a `json` mention (the `Decoder<T>` alias
        // is gated); its inner type is visited by the transitive walk, not here.
        IrType::Json | IrType::Decoder(_) => Some(RuntimeFeatureId::Json),
        // ── `url` — the opaque validated URL newtype (the breach this closes) ──
        IrType::Url | IrType::UrlRelative => Some(RuntimeFeatureId::Url),
        // ── `secret` — the opaque secret-string module ───────────────────────
        IrType::Secret => Some(RuntimeFeatureId::Secret),
        // ── `decimal` — `rust_decimal` newtype (Money carries it) ────────────
        IrType::Decimal => Some(RuntimeFeatureId::Decimal),
        // ── `regex` — the compiled-pattern handle ────────────────────────────
        IrType::Regex => Some(RuntimeFeatureId::Regex),
        // ── `csv` — the CSV document record ──────────────────────────────────
        IrType::CsvDoc => Some(RuntimeFeatureId::Csv),
        // ── `cache_kernel` — the cache config / stats records ────────────────
        IrType::CacheCfg | IrType::CacheStats => Some(RuntimeFeatureId::CacheKernel),
        // ── `websocket_client` — the WS-client connect-config record ─────────
        IrType::WebSocketClientCfg => Some(RuntimeFeatureId::WebsocketClient),
        // ── `email` — the Email message / attachment / config / provider set ─
        IrType::EmailMessage
        | IrType::EmailAttachment
        | IrType::EmailSesConfig
        | IrType::EmailSmtpConfig
        | IrType::EmailProvider
        | IrType::EmailAddress => Some(RuntimeFeatureId::Email),
        // ── `crypto-core` — the typed Key / Mac newtypes ─────────────────────
        IrType::CryptoKey | IrType::CryptoMac => Some(RuntimeFeatureId::CryptoCore),
        // ── `db` — the Db query fragment + connection descriptors ────────────
        // `SqlFragment` renders `ipe_runtime::db::SqlFragment`; `Dsn` /
        // `Connection` render the `dsn` / `external_conn` modules; all three are
        // `#[cfg(feature = "db")]`. The phantom access-mode markers never render
        // standalone but share `Connection`'s gate (fail-closed).
        IrType::SqlFragment
        | IrType::Dsn
        | IrType::Connection
        | IrType::ConnReadOnly
        | IrType::ConnReadWrite => Some(RuntimeFeatureId::Db),
        // ── `server` — the opaque server-side handles ────────────────────────
        IrType::ServerRequest
        | IrType::ServerResponse
        | IrType::ServerRoute
        | IrType::ServerCookie
        | IrType::AuthConfig
        | IrType::TokenSource
        | IrType::StreamWriter
        | IrType::WebSocketServer
        | IrType::WebSocketServerCfg => Some(RuntimeFeatureId::Server),
        // ── `http_client` — the outbound-client request / method types ───────
        // Both render behind `pub use http_client::*` (gated `http_client`).
        IrType::HttpRequest | IrType::HttpMethod => Some(RuntimeFeatureId::HttpClient),
        // ── `web` — the Live web app request + route types ───────────────────
        IrType::WebReq | IrType::WebRoute(_) => Some(RuntimeFeatureId::Web),
        // ── ungated leaves: primitives, always-compiled runtime types, and the
        // transparent CARRIERS (their own node renders to an ungated container;
        // element leaves are visited by the transitive walk, not here). ────────
        IrType::Int
        | IrType::Float
        | IrType::Bool
        | IrType::Str
        | IrType::Char
        | IrType::Unit
        | IrType::Bytes
        // `Db` (the app connection pool) is re-exported ungated; the `db`-gated
        // reach is the `SqlFragment` / `Dsn` / `Connection` set above.
        | IrType::Db
        | IrType::BackoffStrategy
        // `SessionHandle` renders to a plain `i64` (the session-registry key) — no
        // gated runtime type, so it is ungated like the primitives.
        | IrType::SessionHandle
        | IrType::Order
        | IrType::ErrorKind
        | IrType::Error
        | IrType::ErrorDetails
        | IrType::ErrorInfo
        | IrType::PanicInfo
        | IrType::TypeInfo
        | IrType::Path
        | IrType::Principal
        // The runtime-config carrier + its phantom shape markers render to the
        // always-compiled `app_config` module.
        | IrType::Setting
        | IrType::ShapeWeb
        | IrType::ShapeWebView
        | IrType::ShapeTerminal
        // `Locale` renders to the always-compiled `locale` module.
        | IrType::Locale
        // `ProcessRunWithCfg` / `ProcessRunInPtyCfg` render to the
        // always-compiled `system` module.
        | IrType::ProcessRunWithCfg
        | IrType::ProcessRunInPtyCfg
        // The shape app leaves render to the always-compiled `tea` module.
        | IrType::WebApp
        | IrType::TuiApp
        | IrType::CliApp
        | IrType::WorkerApp
        // The `Ipe.Ui` / `Ipe.Html` carriers render to the always-compiled
        // `ui` / `html` modules; their message parameter is visited by the walk.
        | IrType::Ui { .. }
        | IrType::UiPlain(_)
        // The widget handle renders to the always-compiled `ui::widget` module.
        | IrType::CustomElement { .. }
        // A generic / row generic is a pass-through type variable — its concrete
        // instantiation's leaves are visited where it is applied, not here.
        | IrType::Generic(_)
        | IrType::RowGeneric(_)
        // Transparent carriers + effect wrappers: the node renders to an ungated
        // container / alias; the transitive walk visits the carried leaves.
        | IrType::Task(_)
        | IrType::Cmd(_)
        | IrType::Sub(_)
        | IrType::Maybe(_)
        | IrType::List(_)
        | IrType::Set(_)
        | IrType::Result(_, _)
        | IrType::Dict(_, _)
        | IrType::Tuple(_)
        | IrType::Record(_)
        | IrType::Enum { .. }
        | IrType::Fun(_, _)
        | IrType::SharedFun(_, _)
        | IrType::FnOnceChain(_, _) => None,
    }
}

/// Does this type's DEFAULT emitted Rust carrier implement `Clone`?
///
/// The SINGLE authority both the lowerer's capture classifier and the backend's
/// carrier choice consult, so a shape that renders a `Clone` carrier can never be
/// classified `NonClone` (or vice-versa) — the two tables cannot drift.
///
/// The carrier model is POSITION-TYPED (mirroring the reference backend): a
/// first-class function value's default carrier is `Box<dyn Fn(..) -> R + Send +
/// Sync + 'static>` — NOT `Clone` — so [`IrType::Fun`] is `false` here.
/// `Arc<dyn Fn>`
/// does not satisfy an `impl Fn` bound (std has no `impl Fn for Arc<F>`), so a
/// universal Arc carrier is unsound across the HOF-kernel surface; instead the
/// lowerer promotes exactly the fn-value BINDINGS that are captured at closure
/// depth ≥ 1 or reused as values (`Expr::SharedLambda`, an `Arc<dyn Fn + Send +
/// Sync>` carrier that IS `Clone`) and re-dispatches Arc-carried values through
/// fresh closures where a `Box`/`impl Fn` slot needs them. Which shapes are
/// eligible for that promotion is [`fun_value_arc_promotable`] — the companion
/// authority.
///
/// The `false` set is the default carriers that do NOT implement `Clone`:
/// * [`IrType::Fun`] — the default `Box<dyn Fn>` first-class carrier (see above).
/// * [`IrType::FnOnceChain`] — a curried `Box<dyn FnOnce>` tower, consume-once by
///   type (the decode/db-decode pipeline `next_decoder` slots require it); a
///   `FnOnce` cannot be re-called, so it is never `Clone`.
/// * [`IrType::Task`] / [`IrType::Cmd`] / [`IrType::Sub`] — pinned futures /
///   effect descriptors whose runtime carriers are not `Clone`.
/// * [`IrType::Generic`] — a parametric type variable: its `Clone`-ness is
///   decided by the caller's instantiation and its emitted `T: Clone` bound, not
///   by the carrier here (`clone_class`'s bare-`Generic` admission handles the
///   sound multi-use clone under that bound).
///
/// A transparent carrier (list / set / tuple / dict / result / maybe / record /
/// enum) is `Clone` iff every element it carries is — one non-`Clone` member
/// poisons the whole composite, matching the emitted Rust (`IpeMaybe<T>: Clone`
/// requires `T: Clone`, etc.).
///
/// The match is exhaustive with no wildcard: a new [`IrType`] variant must make
/// an explicit carrier-`Clone` decision here (walker-arm rule / SEAL
/// make-invalid-states-unrepresentable).
#[must_use]
pub fn carrier_is_clone(ty: &IrType) -> bool {
    match ty {
        // Copy / Clone scalar and opaque leaves — every one implements `Clone`.
        IrType::Int
        | IrType::Float
        | IrType::Bool
        | IrType::Str
        | IrType::Char
        | IrType::Unit
        | IrType::Bytes
        | IrType::Json
        | IrType::BackoffStrategy
        | IrType::Order
        | IrType::HttpMethod
        | IrType::Decimal
        | IrType::ErrorKind
        | IrType::Error
        | IrType::ErrorDetails
        | IrType::ErrorInfo
        | IrType::PanicInfo
        | IrType::TypeInfo
        | IrType::SqlFragment
        | IrType::Secret
        | IrType::Path
        // `Url` is a newtype over `url::Url` — clone is a String clone.
        | IrType::Url
        // `Relative` clones its validated String projection fields.
        | IrType::UrlRelative
        // `Dsn` clones its String fields + `Secret` (a String clone).
        | IrType::Dsn
        | IrType::Db
        // The external connection wraps `Clone` sqlx pools; the phantom markers
        // never carry a runtime value but must stay exhaustive.
        | IrType::Connection
        | IrType::ConnReadOnly
        | IrType::ConnReadWrite
        // The runtime-config carrier is `Clone`; its shape markers are phantom
        // (never a runtime value) but must stay exhaustive.
        | IrType::Setting
        | IrType::ShapeWeb
        | IrType::ShapeWebView
        | IrType::ShapeTerminal
        | IrType::ServerRequest
        | IrType::ServerResponse
        | IrType::ServerRoute
        | IrType::ServerCookie
        | IrType::StreamWriter
        | IrType::HttpRequest
        // `Regex` wraps an `Arc<regex::Regex>` — clone is a refcount bump.
        | IrType::Regex
        | IrType::WebSocketServer
        | IrType::WebSocketServerCfg
        | IrType::UiPlain(_)
        | IrType::WebReq
        | IrType::SessionHandle
        | IrType::ProcessRunWithCfg
        | IrType::ProcessRunInPtyCfg
        | IrType::CacheCfg
        | IrType::WebSocketClientCfg
        | IrType::CacheStats
        | IrType::CsvDoc
        | IrType::EmailMessage
        | IrType::EmailAttachment
        | IrType::EmailSesConfig
        | IrType::EmailSmtpConfig
        | IrType::EmailProvider
        // Typed-key newtype carriers: all derive / hand-write `Clone`.
        | IrType::CryptoKey
        | IrType::CryptoMac
        | IrType::EmailAddress
        // `Locale` wraps a `String` — derives `Clone`.
        | IrType::Locale
        // `Principal` wraps a `String` — derives `Clone`.
        | IrType::Principal
        // `AuthConfig` and `TokenSource` both derive `Clone`.
        | IrType::AuthConfig
        | IrType::TokenSource
        // The widget handle carries only a generated tag `String` — derives
        // `Clone`. Its seal args are phantom (not stored), so its `Clone`-ness
        // is unconditional.
        | IrType::CustomElement { .. }
        // The promoted `Arc<dyn Fn>` fn carrier: `Arc` is `Clone` (a refcount
        // bump), so a `SharedFun` slot never poisons its enclosing composite.
        | IrType::SharedFun(_, _)
        // The runtime `Decoder<E, T>` carries `run : Arc<dyn Fn + Send + Sync>`
        // and a hand-written `Clone` that bounds neither `E` nor `T`, so a
        // `Decoder` slot clones by refcount bump and never poisons its enclosing
        // composite.
        | IrType::Decoder(_) => true,
        // Non-`Clone` default carriers. `Fun`'s default carrier is `Box<dyn Fn>`
        // (position-typed model — the `Clone` `Arc` carrier exists only at
        // promoted binding sites, see [`fun_value_arc_promotable`]).
        IrType::Fun(_, _)
        | IrType::FnOnceChain(_, _)
        | IrType::Task(_)
        | IrType::Cmd(_)
        | IrType::Sub(_)
        | IrType::Generic(_)
        // A row generic's `Clone`-ness rides its emitted `R: Clone` witness
        // bound, exactly as a plain generic's rides `T: Clone` — the carrier
        // itself makes no promise here.
        | IrType::RowGeneric(_)
        // Opaque shape app leaves — live runtime handles wrapping event loops;
        // not `Clone`.
        | IrType::WebApp
        | IrType::TuiApp
        | IrType::CliApp
        | IrType::WorkerApp => false,
        // Transparent carriers: `Clone` iff every carried element is.
        IrType::Maybe(e) | IrType::List(e) | IrType::Set(e) => carrier_is_clone(e),
        IrType::Result(a, b) | IrType::Dict(a, b) => carrier_is_clone(a) && carrier_is_clone(b),
        IrType::Tuple(es) => es.iter().all(carrier_is_clone),
        IrType::Record(fields) => fields.values().all(carrier_is_clone),
        IrType::Enum { args, .. } => args.iter().all(carrier_is_clone),
        // `Element<M>` / `Html<M>` and `Route<Page>` recurse on their type
        // parameter — the runtime carriers derive `Clone` over a `Clone` param.
        IrType::Ui { msg, .. } => carrier_is_clone(msg),
        IrType::WebRoute(page) => carrier_is_clone(page),
    }
}

/// Is a BINDING of this type eligible for the `Arc<dyn Fn>` carrier promotion
/// ([`Expr::SharedLambda`]) when it is captured at closure depth ≥ 1 or reused
/// as a function value?
///
/// The single authority the lowerer's capture classifier, reuse gate, and
/// promotion pass all consult — no per-site shape enumeration. The eligible set
/// is exactly the pure [`IrType::Fun`] shapes: the whole binding is one
/// first-class function, so flipping its own carrier from `Box<dyn Fn>` to
/// `Arc<dyn Fn + Send + Sync>` is a local, sound change (every capture clones
/// the pointer; `impl Fn` / `Box` consumer slots receive a fresh re-dispatch
/// closure).
///
/// Deliberately EXCLUDED, each for a structural reason:
/// * [`IrType::FnOnceChain`] — consume-once by type; an `Arc<dyn Fn>` cannot
///   satisfy the runtime's `Box<dyn FnOnce>` pipeline slots.
/// * [`IrType::Decoder`] — a nominal runtime struct, not a first-class function
///   value; it carries its own `Clone` (an `Arc`-backed `run` field), so a
///   captured/reused `Decoder` clones as an ordinary `CloneOk` value rather than
///   taking this `Fun`-value promotion.
///
/// A composite carrying a `Fun` (`Maybe (Int -> Int)`, a record-of-functions, …)
/// is NOT a bare fn value and so is not this predicate's concern — its own
/// carrier is the composite (`IpeMaybe<Box<dyn Fn>>`). The composite reuse path
/// has its own whole-value promotability decision
/// ([`shared_fun_promotable_shapes`] in `ipe_lower`), which flips the composite's
/// inner `Fun` slots to [`IrType::SharedFun`] rather than the whole value's own
/// carrier.
///
/// An already-promoted [`IrType::SharedFun`] is trivially eligible — it is
/// already the `Clone` `Arc` carrier — so re-running the bare-`Fun` promotion
/// over it is a sound no-op.
#[must_use]
pub const fn fun_value_arc_promotable(ty: &IrType) -> bool {
    matches!(ty, IrType::Fun(_, _) | IrType::SharedFun(_, _))
}

/// An expression in the typed IR.
///
/// Note: the [`Match`] variant wraps the opaque [`Match`] type rather than
/// inlining `scrutinee` / `arms` fields. That is deliberate — it keeps the
/// exhaustiveness invariant unbreakable, because the only constructor for a
/// [`Match`] is [`Match::new`], which validates the arm set. An inline
/// struct-variant with public fields could be built directly, bypassing the
/// check, and would make illegal IR representable.
// `Eq` is not derived: [`Expr::Float`] carries an `f64`, which is only
// `PartialEq` (IEEE-754). No consumer keys a map / set on an [`Expr`].
#[derive(Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
pub enum Expr {
    Int(i64),
    /// A boolean literal `True` / `False` used as a VALUE. Ipê's `Bool` is the
    /// closed two-constructor type whose constructors are Prelude-exposed; the
    /// backend renders this as the Rust `true` / `false` keyword constant. (A
    /// `Bool` PATTERN is the separate [`Pat::Bool`] leaf.)
    Bool(bool),
    /// A floating-point literal — the carried [`f64`] is the parsed value. The
    /// backend renders it as an f64-typed Rust literal (a whole-number value
    /// keeps its decimal point, `3.0`, so it never types as an integer).
    Float(f64),
    /// A string literal — the carried [`String`] is the already-unescaped value.
    /// The backend renders it as an owned `String` (`"…".to_string()`).
    Str(String),
    /// A `path "…"` compile-time-validated path literal. The carried [`String`]
    /// is the CLEANED, NUL-free, non-escaping form validated by the canonicaliser.
    /// The backend renders it as `ipe_runtime::path::path_literal(…)`, bypassing
    /// the runtime's `Result`-returning seal (the compiler already proved the
    /// string is valid).
    PathLit(String),
    /// The reserved `CustomElement.fromFile "<js-path>"` constructor, lowered. `tag` is
    /// the generated content-addressed custom-element tag (`ipe-ce-<hex>`),
    /// derived at lowering from a hash of the cleaned JS path (which the canon
    /// path seal + the build-stage containment gate already proved is in-project
    /// and traversal-free); it NEVER contains raw user input, so
    /// `customElements.define`-style registration injection is impossible by
    /// construction. `js_path` is the cleaned relative path, retained for the
    /// serving stage (WP5). The backend renders this as
    /// `ipe_runtime::ui::widget::custom_element_(tag)`. The value's type is
    /// [`IrType::CustomElement`]; it is produced only as the whole body of a
    /// `CustomElement`-annotated binding and consumed only as `CustomElement.node`'s
    /// first argument.
    CustomElementRef {
        tag: String,
        js_path: String,
    },
    /// A character literal — the carried [`String`] is the single unescaped
    /// character's text. The backend renders it as a Rust `char` literal.
    Char(String),
    /// The unit value `()` — the sole inhabitant of [`IrType::Unit`].
    ///
    /// Ipê's `()` literal lowers here; the backend emits the Rust unit
    /// expression `()`. Distinct from a zero-element [`Expr::Tuple`], which the
    /// tuple invariant forbids (arity ≥ 2): the empty product is this `Unit`.
    Unit,
    Var(Symbol),
    /// A read of a CAPTURED binder inside a closure body that must not consume
    /// the capture: renders as `{ident}.clone()`. Produced only by the lowerer's
    /// capture-clone rewrite (`lower_lambda` / `eta_expand_partial` / Fix-C thunk);
    /// never for `Copy`-classed or function-typed captures.
    CloneVar(Symbol),
    /// A constructor application `Variant arg0 arg1 …` (a nullary constructor
    /// `Variant` has an empty `args`).
    ///
    /// `home` + `ty` are the constructor's enum-type nominal identity (its
    /// defining module and bare type [`Symbol`]; see [`EnumDef::home`]); `variant`
    /// is the constructor name. `args` are the payload expressions, one per
    /// declared field, in source order. The backend resolves the variant's
    /// declared field types from the enum declaration (keyed by `(home, ty)`) to
    /// wrap any direct-self-recursive field in `Box::new` at construction
    /// (matching the boxed enum field).
    Ctor {
        home: ModPath,
        ty: Symbol,
        variant: Symbol,
        args: Vec<Self>,
    },
    BinOp {
        op: BinOp,
        lhs: Box<Self>,
        rhs: Box<Self>,
    },
    /// A non-recursive single-binding `let name = value in body`. Multi-binding
    /// `let` lowers to nested `Let`s; `name` is bound only within `body`, not in
    /// `value`.
    Let {
        name: Symbol,
        value: Box<Self>,
        body: Box<Self>,
    },
    /// An irrefutable destructuring binding `let <binder> = value in body`.
    ///
    /// The sibling of [`Self::Let`] for the pattern-binder case: where `Let`
    /// binds a single [`Symbol`] (the audited common fast path), `Destructure`
    /// binds an IRREFUTABLE [`Pat`] — a [`Pat::Tuple`] of variables / wildcards
    /// (recursively), or a bare [`Pat::Var`] / [`Pat::Wildcard`]. It is the IR
    /// The lowerer emits this for a tuple-destructuring `case` arm and a tuple
    /// function parameter (`fst (a, b) = a` → a synthetic param plus
    /// `Destructure { (a, b) = arg } a`). The binder must be irrefutable — the
    /// lowerer is the sole producer and rejects a refutable element
    /// (a constructor / literal) fail-closed (IPE-L0115) — so the backend's
    /// `let <binder> = <value>;` is a sound, exhaustive Rust binding. `binder`
    /// is bound only within `body`, not in `value`.
    Destructure {
        binder: Pat,
        value: Box<Self>,
        body: Box<Self>,
    },
    /// A conditional `if cond then then_ else else_`. The `else` arm is
    /// mandatory — every Ipê `if` is an expression with both branches.
    If {
        cond: Box<Self>,
        then_: Box<Self>,
        else_: Box<Self>,
    },
    Match(Match),
    Call {
        callee: Callee,
        args: Vec<Self>,
        /// A turbofish pin for a polymorphic kernel whose free result type
        /// parameter the HM solver left GENUINELY UNCONSTRAINED at this call
        /// site (a discarded / empty / phantom position). Without it the
        /// emitted Rust hits `E0282`/`E0283` "type annotations needed" — the
        /// SEAL-violating exit-0-then-cargo-fail class.
        ///
        /// The lowerer sets a non-[`CallPin::None`] value ONLY when the
        /// relevant parameter's solved type is a free type variable that is
        /// NOT bound by an enclosing generic function's signature (which would
        /// already pin it, making an added turbofish a conflict). When the
        /// type is concrete, rustc infers it from the argument / context, so
        /// the pin stays [`CallPin::None`]. Every IR→IR rewrite that
        /// reconstructs a `Call` MUST preserve this field.
        pin: CallPin,
        /// Type-directed form-submit handler classification for the
        /// `onSubmit` kernel family (`Ui.onSubmit` / `Ipe.Html.Events.onSubmit`).
        /// The runtime's `Event::OnForm` slot accepts either a DECODER
        /// (`FormData -> Option<Msg>`, from a `T -> Msg` handler) or a FIXED
        /// value (`Msg`, from a bare non-function handler). Which one is a
        /// property of the handler's SOLVED type — an arrow vs a non-arrow —
        /// known only to the HM solver at lower time, never re-derivable from
        /// the payload's SYNTAX at emit time (a `Var` bound to a bare `Msg`
        /// reads identically to a `Var` bound to a decoder function). The
        /// lowerer records the verdict here so the backend dispatches
        /// mechanically. For every non-`onSubmit` call this stays
        /// [`OnFormKind::NotForm`] and emission is byte-identical.
        on_form: OnFormKind,
    },
    /// A tuple constructor `(e1, e2, ...)`.
    ///
    /// Invariant: the element list has arity ≥ 2 — a 0-tuple is the unit value
    /// and a 1-tuple is just its element, so neither is a `Tuple`. The lowerer
    /// upholds this; the backend remains total over any vector (it never panics
    /// on a degenerate arity).
    Tuple(Vec<Self>),
    /// A list literal `[]` / `[e1, e2, …]`. `elem` is the element [`IrType`]
    /// (recorded so the empty list renders with a concrete `Vec::<T>::new()`);
    /// `items` are the element expressions in source order. Renders as a Rust
    /// `vec![…]` (or a typed `Vec::new()` when empty).
    List {
        elem: IrType,
        items: Vec<Self>,
    },
    /// A cons `head :: tail` — prepend one element to a list. Renders through the
    /// runtime's `ipe_list_cons(head, tail)`, the move-only list prepend.
    Cons {
        head: Box<Self>,
        tail: Box<Self>,
    },
    /// Clone the element at a CONSTANT index of a list value: `<list>[<index>].clone()`.
    ///
    /// Introduced for Class 4 item C2. A cons / list sub-pattern nested in
    /// a constructor payload lowers to a fresh `Vec` binder plus an arm-level
    /// length GUARD ([`Arm::guard`]); the named head elements are then recovered
    /// in the arm-body prelude via this node, one per prefix position. It is ONLY
    /// ever emitted where the arm's guard has already proven `list.len() > index`,
    /// so the Rust index is in bounds by construction (never a panic on
    /// well-typed source — the guard falls through to the next arm otherwise).
    /// The `.clone()` keeps the original list intact for the sibling tail binder
    /// (`List.drop`), mirroring the `rebind_clone` the top-level slice path uses.
    ListIndexClone {
        list: Box<Self>,
        index: usize,
    },
    /// A borrowing list-length CHECK for a Class 4 item C2 arm guard:
    /// `<list>.len() >= <len>` (`exact == false`, an OPEN cons chain
    /// `a :: b :: rest`) or `<list>.len() == <len>` (`exact == true`, a CLOSED
    /// list literal `[a, b]`). `.len()` borrows the bound `Vec` — a match guard
    /// may not MOVE out of a binding, so this is deliberately NOT the consuming
    /// `List.length` kernel. Only ever emitted in [`Arm::guard`] position.
    ListLenCheck {
        list: Box<Self>,
        len: usize,
        exact: bool,
    },
    /// A record literal `{ x = e1, y = e2, ... }`.
    ///
    /// The fields are carried as `(field name, value)` pairs sorted by field
    /// name, so the construction is deterministic. The backend resolves the
    /// literal's synthesised Rust struct from its full structural shape (field
    /// names AND field types), so two records that share a field-name set but
    /// differ in a field's type resolve to their two distinct structs; Rust
    /// names its struct-literal fields, so the emitted construction is
    /// order-independent.
    ///
    /// `ty` is the literal's solved [`IrType::Record`] shape, threaded from the
    /// lowerer (the sole site with the solved region type). It disambiguates a
    /// field-name collision at the resolution site; when the lowerer cannot
    /// resolve a concrete shape (a still-generic record inside a polymorphic
    /// body) it is `None`, and the backend falls back to field-name resolution
    /// (sound because a name-set that is genuinely ambiguous only arises from
    /// two DISTINCT concrete shapes, and a generic body's literal shares its
    /// one struct with every instantiation).
    Record {
        fields: Vec<(Symbol, Self)>,
        ty: Option<IrType>,
    },
    /// A record field access `record.field`. `field_ty` is the field's own
    /// solved type — carried so the Rust backend can decide, WITHOUT any
    /// textual heuristic, whether the read needs a `.clone()` (a heap-backed
    /// field) or can skip it (a Rust-`Copy` scalar) — see AUD-09's
    /// type-directed Copy-elision,
    /// `docs/adr/0002-codegen-soundness-and-the-seal.md` §3.
    /// When the lowerer cannot resolve a concrete field type (a still-generic
    /// field inside a polymorphic body), it falls back to
    /// [`IrType::Generic`], which the backend classifies as non-`Copy` and
    /// therefore conservatively KEEPS the `.clone()`.
    Access {
        record: Box<Self>,
        field: Symbol,
        field_ty: IrType,
    },
    /// A record update `{ record | x = e1, ... }`: a copy of `record` with the
    /// listed fields replaced. `fields` lists only the changed fields, as
    /// `(field name, new value)` pairs.
    Update {
        record: Box<Self>,
        fields: Vec<(Symbol, Self)>,
    },
    /// An anonymous function `\p0 p1 ... -> body`: typed parameters, a return
    /// type, and a body expression.
    ///
    /// Distinct from [`Func`] (a named top-level declaration): a `Lambda` is an
    /// expression value. The backend emits it as a boxed closure
    /// `Box::new(move |p0: T0, ...| -> R { body })`, move-capturing any free
    /// locals. A zero-parameter lambda is a genuine nullary closure.
    Lambda {
        params: Vec<(Symbol, IrType)>,
        ret: IrType,
        body: Box<Self>,
    },
    /// A LET-BOUND closure literal that must be reference-counted (`Arc`)
    /// rather than uniquely owned (`Box`), because the lowerer's capture
    /// analysis proved the bound symbol is captured-by-move into more than
    /// one closure environment along some nesting chain (see
    /// `ipe_lower::needs_shared_capture`).
    ///
    /// SEAL fix (E0507 pair): `examples/18-job-queue`'s
    /// `withErrorReporting` (and its `saveSnapshot`/`loadHistory` siblings)
    /// let-bind a local closure (`logAndFail`, `insertRow`, `selectRecent`)
    /// that is referenced from INSIDE another, more-deeply-nested closure --
    /// e.g. `report e = Crypto.randomToken 4 |> Task.andThen (\errId ->
    /// logAndFail e errId)`. Each `move` closure independently move-captures
    /// its free locals: the outer `report` closure must own `logAndFail` to
    /// hand it to the inner `\errId -> ...` closure, which ALSO move-captures
    /// it to call it. A `Box<dyn Fn>` is not `Clone`, so the inner capture's
    /// move is illegal against the outer closure's `&self`-borrowed field --
    /// `cannot move out of ... a captured variable in an Fn closure` (E0507).
    /// The lowerer's PER-LAMBDA capture classification (`lower_lambda`) has
    /// no visibility into ANCESTOR closures' captures, so each closure's own
    /// depth-0 bare-callee exemption fires independently and unsoundly.
    ///
    /// Rendering: the backend emits `Arc::new(move |p0: T0, ...| -> R { body
    /// })` pinned to `Arc<dyn Fn(T0, ...) -> R + Send + Sync + 'static>`
    /// (`emit_shared_lambda`, mirroring [`Self::Lambda`]'s `emit_lambda` but
    /// with the `+ Sync` bound Arc needs to itself be `Send + Sync`). Every
    /// read of the bound symbol at lambda-nesting depth >= 1 relative to its
    /// binding is rewritten to [`Self::CloneVar`] (`Arc::clone`, cheap
    /// pointer bump) by `ipe_lower::force_shared_capture_clones`; a depth-0
    /// (non-nested) read stays a bare [`Self::Var`] -- calling through an
    /// `Arc<dyn Fn>` auto-derefs exactly like `Box<dyn Fn>`, no clone needed.
    ///
    /// Produced ONLY by `ipe_lower::lower_let`'s `PVar` arm, for a
    /// function-typed (`IrType::Fun`) let-binding whose capture pre-pass
    /// fires. Never appears anywhere else (never a `Match` scrutinee, never
    /// a def-head body, never a bare call-arg lambda) -- the type system
    /// still models it as an ordinary [`IrType::Fun`]; only its OWN Rust
    /// pointer representation differs.
    SharedLambda {
        params: Vec<(Symbol, IrType)>,
        ret: IrType,
        body: Box<Self>,
    },
    /// Application of an arbitrary expression value to arguments, `func(args)`.
    ///
    /// Distinct from [`Expr::Call`], which targets a known [`Callee`] (a direct
    /// top-level function or a kernel) and keeps the efficient direct-call path.
    /// `Apply` calls a first-class function *value* — a lambda, a
    /// function-typed parameter/binding, or a top-level function passed as a
    /// value — and renders as `(func)(args)` (a boxed `dyn Fn` auto-derefs).
    Apply {
        func: Box<Self>,
        args: Vec<Self>,
    },
    /// A top-level function or kernel named as a first-class *value* — passed as
    /// an argument, returned, or let-bound — rather than directly called.
    ///
    /// Distinct from [`Expr::Call`] (which applies a known [`Callee`] to
    /// arguments on the spot): `FuncValue` reifies the callee into a boxed
    /// closure value so it fills a `Box<dyn Fn(..) -> R>` slot uniformly. The
    /// backend emits `{ let f: <ty> = Box::new(<callee>); f }`, the explicit
    /// binding type pinning the unsized coercion of the top-level `fn` item (a
    /// zero-sized `Fn` implementor) to the boxed trait object. `ty` is the
    /// value's flattened [`IrType::Fun`], recorded by the lowerer from the
    /// reference's solved region type. A direct call keeps the efficient
    /// [`Expr::Call`] path; only a bare value reference becomes a `FuncValue`.
    FuncValue {
        callee: Callee,
        ty: IrType,
    },
    /// Force-and-sequence a Task effect, discarding its result, then continue
    /// with `rest`. Produced by `lower_let` when a `let _ = <task>` binding
    /// discards a Task-typed value; the backend emits
    /// `task_and_then(Box::new(move |_: ()| -> IpeTask<()> { <rest> }), <effect>)`.
    /// This is the auto-force fix (F1): without `TaskSeq`, the future would be
    /// silently dropped unawaited.
    TaskSeq {
        effect: Box<Self>,
        rest: Box<Self>,
    },
    /// A tail-recursive function body wrapped for loop emission. Produced ONLY by
    /// the lowerer's TCO rewrite (`ipe_lower::rewrite_tail_calls`); `params` are
    /// the enclosing [`Func`]'s parameters (name + type) so emission can shadow
    /// them `let mut`. Invariant: `body` contains ≥ 1 [`Self::TailRecur`] in tail
    /// position and no self-[`Self::Call`] to the enclosing [`FuncId`] remains.
    /// Consumed by the Rust backend's `emit_func` / `emit_expr_tail`; reaching one
    /// on the ordinary value-emit path is a compiler bug, surfaced fail-closed
    /// (never a panic).
    TailLoop {
        params: Vec<(Symbol, IrType)>,
        body: Box<Self>,
    },
    /// A tail self-call rewritten to a loop jump. `args` are the next-iteration
    /// argument expressions, one per enclosing [`Self::TailLoop`] parameter, in the
    /// same order. Invariant: appears ONLY in tail position inside a `TailLoop`,
    /// and `args.len() == TailLoop.params.len()`.
    TailRecur {
        args: Vec<Self>,
    },
}

/// The target of a [`Expr::Call`].
#[derive(Clone, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
pub enum Callee {
    Func(FuncId),
    Kernel(KernelFn),
    /// A foreign-crate FFI wrapper (`crate::ffi::<ident>`), reachable only
    /// through a driver-generated FFI interface module's forwarder body.
    /// `ident` is the emitted `_bindings.rs` wrapper `pub fn` identifier,
    /// validated as a Rust identifier at canonicalisation.
    ///
    /// `asserted` marks a shim whose signature was author-asserted
    /// (`Rust.Ffi.call`) rather than derived from crate inspection; it flips
    /// the `ffi-raw` capability in the whole-program scan.
    Ffi {
        ident: Symbol,
        #[serde(default)]
        asserted: bool,
    },
}

impl Callee {
    /// Whether a call to this callee evaluates its arguments in the REVERSE of
    /// their IR order — a kernel whose runtime function takes them reversed
    /// ([`ipe_kernels::StdlibKernel::swaps_first_two`]). Analyses that depend on
    /// evaluation order visit a call's arguments reversed exactly when this holds.
    #[must_use]
    pub const fn evaluates_args_reversed(&self) -> bool {
        matches!(self, Self::Kernel(k) if k.swaps_first_two())
    }
}

/// A per-call-site turbofish pin for a polymorphic kernel.
///
/// Set when the HM solver left the kernel's free result type parameter
/// genuinely unconstrained. Each variant names the SEMANTIC default the emitter
/// renders; the mapping to a concrete `::<…>` suffix lives in the backend
/// (`emit_expr`), so this enum stays a small, typed decision — never a raw
/// string in the IR.
///
/// The lowerer only ever emits a non-[`Self::None`] variant when the free
/// parameter is a bare type variable NOT bound by an enclosing generic
/// signature; a concrete parameter needs no pin (rustc infers it) and stays
/// [`Self::None`].
#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize, Default)]
pub enum CallPin {
    /// No turbofish — the common case (rustc infers every type parameter).
    #[default]
    None,
    /// A single free element/value type defaulted to `i64` — `::<i64>`.
    /// Used by `list_head` / `list_tail` / `set_empty` and the `task_fail`
    /// main-crate wrapper (`fn task_fail<A>(…) -> IpeTask<A>`, error already
    /// pinned to `IpeError`).
    DefaultI64,
    /// A free key AND value defaulted to a String-keyed i64-valued map —
    /// `::<String, i64>`. Used by `dict_empty` (`fn dict_empty<K, V>()`).
    DefaultDict,
    /// Two inferred leading parameters and a trailing free type defaulted to
    /// `i64` — `::<_, _, i64>`. Used by `ipe_result_map_error<E, F, A>` where
    /// the `Ok` type `A` is discarded (the value comes only from an `Err`).
    DefaultResultMapErr,
    /// A single free error/phantom parameter pinned to the project's canonical
    /// error type — `::<IpeError>`. Used by `decimal_from_string<E: From<String>>`
    /// when the `Err` channel is discarded.
    ErrIpeError,
}

impl CallPin {
    /// The turbofish suffix this pin renders immediately after a kernel's name
    /// (before its `(` argument list): `dict_empty::<String, i64>(…)`, etc.
    /// [`Self::None`] renders the empty string, so an unpinned call emits no
    /// turbofish.
    ///
    /// The concrete default types (`i64` / `String` / `IpeError`) mirror the
    /// polymorphic-kernel defaults: a genuinely
    /// unconstrained parameter has no observable effect on behaviour (the value
    /// is discarded / the collection is empty / the task never yields), so any
    /// inhabited default is sound — `i64` and `String` are the reference's
    /// canonical choices, `IpeError` the project's canonical error type.
    #[must_use]
    pub const fn turbofish(self) -> &'static str {
        match self {
            Self::None => "",
            Self::DefaultI64 => "::<i64>",
            Self::DefaultDict => "::<String, i64>",
            Self::DefaultResultMapErr => "::<_, _, i64>",
            Self::ErrIpeError => "::<IpeError>",
        }
    }
}

/// How an `onSubmit`-family call ([`Expr::Call`] whose callee is
/// `Ui.onSubmit` / `Ipe.Html.Events.onSubmit`) dispatches its handler.
///
/// The runtime `Event::OnForm` slot is `Arc<dyn Fn(FormData) -> Option<Msg>>`.
/// A well-typed `onSubmit` handler is one of two SHAPES, distinguished ONLY by
/// its solved type:
///
/// * an ARROW handler `T -> Msg` (a decoder function, a `Creds -> Msg`
///   constructor, a `\fd -> …` lambda) — the wire `FormData` is decoded into
///   `T` and mapped through the handler ([`Self::Decoder`]);
/// * a NON-ARROW handler — a bare `Msg` value (`DoSignUp`, a `let`-bound
///   `m : Msg`, a record/tuple/list literal that IS the `Msg`) — the form
///   payload is ignored and the fixed value is dispatched verbatim
///   ([`Self::FixedValue`]).
///
/// This is a property of the HANDLER'S TYPE, not its syntax: `Ui.onSubmit m`
/// and `Ui.onSubmit decoder` are syntactically identical when `m`/`decoder`
/// are both `Var`s — only the solver knows which is callable. Deciding it at
/// emit time from the payload's `Expr` shape is unsound (`let m = DoSignUp in
/// onSubmit m` would emit `(m)(_x)`, a cargo `E0618` after `ipe` exit 0).
/// The lowerer resolves it from the handler's solved
/// region type and records the verdict here so the backend never guesses.
///
/// [`Self::NotForm`] is the default carried by every non-`onSubmit` call; the
/// backend ignores this field except in the two `onSubmit` emit arms.
#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize, Default)]
pub enum OnFormKind {
    /// Not an `onSubmit` call — the field is inert. Byte-identical emission.
    #[default]
    NotForm,
    /// Arrow handler `T -> Msg`: decode `FormData` into `T`, map to `Msg`.
    Decoder,
    /// Non-arrow handler: dispatch the fixed `Msg` value, ignore the form.
    FixedValue,
}

/// Every stdlib kernel function known to the Ipê compiler.
///
/// Re-export alias so `ipe_ir` call-sites (`Callee::Kernel(KernelFn)`,
/// `k.is_db()`, `KernelFn::*` variant patterns) reach the enum through this
/// crate.  `ipe_kernels::StdlibKernel` is the single source of truth;
/// `ipe_ir` re-exports it under the `KernelFn` alias.
///
/// See [`ipe_kernels::StdlibKernel`] for the full variant list and
/// [`ipe_kernels::StdlibKernel::decl`] for per-variant metadata.
pub type KernelFn = ipe_kernels::StdlibKernel;

/// Re-export of the `Ipe.Html.Events` payload-shape ADT, so backend
/// crates that already depend on `ipe_ir` (for `KernelFn`) can match on it
/// without taking a direct `ipe_kernels` dependency.
pub use ipe_kernels::HtmlEventShape;

/// Re-export of the runtime-module requirement ADT returned by
/// [`KernelFn::required_runtime_module`], so `ipe_lower` (and any `ipe_ir`
/// consumer) can drive the `uses_*` module-set flags from it without a direct
/// `ipe_kernels` dependency.
pub use ipe_kernels::RuntimeModule;

/// Re-export of the emit-ownership ADT carried by [`ipe_kernels::KernelDef`],
/// so the backend can route kernel-call emission on `KernelFn::def().class` — a
/// wildcard-free `match` whose exhaustiveness breaks the build the instant a new
/// class lands without an emit arm — without a direct `ipe_kernels` dependency.
pub use ipe_kernels::KernelClass;

/// Binary operators.
///
/// Covers the arithmetic, comparison, and boolean operators. `Append` (`++`)
/// carries string concatenation.
///
/// For concrete `Int` or `Float` operands the lowering emits a type-split
/// variant (`Int{Add,Sub,Mul}` / `Float{Add,Sub,Mul}`) so the backend routes
/// each to the correct implementation without re-inspecting types:
///
/// - `Int{Add,Sub,Mul}` → total wrapping helpers in `ipe_runtime::math`
///   (two's-complement wrap, no panic regardless of Cargo `overflow-checks`).
/// - `Float{Add,Sub,Mul}` → raw Rust infix (IEEE 754, total: overflow → ±∞).
/// - `Add`/`Sub`/`Mul` (generic) → raw Rust infix via the `Add`/`Sub`/`Mul`
///   trait bounds; used only for still-polymorphic `Number a` functions whose
///   result type is not yet resolved to `Int` or `Float` at lowering time.
///
/// The type-split at the lowering site makes an unsound `i64` infix-emit path
/// unrepresentable for all concrete integer call sites, mirroring the existing
/// `IntDiv`/`Div` split.
#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
pub enum BinOp {
    /// Integer addition — emitted via `ipe_runtime::math::ipe_int_add` (wrapping).
    IntAdd,
    /// Integer subtraction — emitted via `ipe_runtime::math::ipe_int_sub` (wrapping).
    IntSub,
    /// Integer multiplication — emitted via `ipe_runtime::math::ipe_int_mul` (wrapping).
    IntMul,
    /// Float addition — safe Rust infix `+` (IEEE 754, total).
    FloatAdd,
    /// Float subtraction — safe Rust infix `-` (IEEE 754, total).
    FloatSub,
    /// Float multiplication — safe Rust infix `*` (IEEE 754, total).
    FloatMul,
    /// Generic (polymorphic `Number a`) addition — Rust infix `+` via trait bound.
    /// Only emitted when the result type is a still-unresolved type variable.
    Add,
    /// Generic subtraction — Rust infix `-` via trait bound.
    Sub,
    /// Generic multiplication — Rust infix `*` via trait bound.
    Mul,
    /// Float division `/`. Raw Rust `/` on `f64` is total (`x/0.0 = ±∞`,
    /// never panics), so the infix form is sound.
    Div,
    Eq,
    Neq,
    Lt,
    Gt,
    Le,
    Ge,
    And,
    Or,
    /// Integer division `//`. Has no sound Rust infix form: raw `/` on `i64`
    /// panics on `b == 0` (divide by zero) **and** on `i64::MIN / -1`
    /// (signed overflow); `//` is a Rust line comment, so it cannot be
    /// emitted literally. The backend routes this variant through the total
    /// helper `ipe_runtime::math::ipe_int_div(l, r)`, never via `op_str`.
    IntDiv,
    /// String append `++`. Unlike the infix arithmetic/comparison operators,
    /// this has no single Rust infix form for two `String`s, so the backend
    /// emits it as a `format!` concatenation rather than via `op_str`.
    Append,
}

/// One arm of a [`Match`]: a constructor pattern and the body it guards.
//
// `Eq` is not derived: `body` is an [`Expr`], only `PartialEq` (float literals).
#[derive(Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
pub struct Arm {
    pub pat: Pat,
    pub body: Expr,
    /// An optional boolean guard evaluated after `pat` matches; `false` falls
    /// through to the next arm (native Rust `match` guard semantics). `None`
    /// for an arm with no guard — the backend renders `{pat} => …`, adding
    /// `if {guard}` only when `Some`.
    ///
    /// A cons / list sub-pattern nested
    /// in a constructor payload lowers to a plain [`Pat::Var`] binder for that
    /// position PLUS a guard checking the bound `Vec`'s length, with the named
    /// sub-bindings (`h`, `t`) recovered via indexing / slicing in the arm
    /// body's prelude rather than embedded in the pattern itself (Rust cannot
    /// slice-pattern a `Vec<T>` ENUM FIELD inline — only an actual slice/array,
    /// which needs a scrutinee-level `.as_slice()` coercion this nested position
    /// does not have).
    pub guard: Option<Expr>,
}

impl Arm {
    /// A guard-free arm — the default shape for every pattern that discriminates
    /// entirely in its `Pat`. Keeps the ~40 existing `Arm { pat, body }` call
    /// sites concise while the `guard` field defaults to `None`.
    #[must_use]
    pub const fn new(pat: Pat, body: Expr) -> Self {
        Self {
            pat,
            body,
            guard: None,
        }
    }
}

/// A pattern.
///
/// A constructor pattern ([`Pat::Ctor`]) carries payload sub-patterns; a
/// nullary constructor has an empty `args`. The tuple ([`Pat::Tuple`]) and
/// record ([`Pat::Record`]) patterns nest fully recursively: ANY [`Pat`] may
/// appear as a constructor payload, a tuple element, or a record-field
/// sub-pattern (`Just (a, b)`, `Node (Node …) x r`, `{ point = (a, b) }`).
///
/// [`Pat::Var`] / [`Pat::Wildcard`] and the refutable literal leaves
/// [`Pat::Int`] / [`Pat::Bool`] / [`Pat::Char`] / [`Pat::Str`] are leaves;
/// [`Pat::Ctor`] / [`Pat::Tuple`] / [`Pat::Record`] / [`Pat::Alias`] (the
/// alias / `as` binder) are nesting nodes whose sub-patterns reuse the same
/// enum, recursively. The var / wildcard / alias-of-irrefutable shapes also
/// serve as an irrefutable destructuring binder (a single irrefutable case
/// arm, a function parameter, or a `let`-destructure) when every leaf is a
/// var / wildcard.
///
/// Cons / list patterns have no `Pat` variant: they lower to a [`Pat::Var`]
/// binder plus an arm-level length guard (see [`Arm::guard`]).
#[derive(Clone, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
pub enum Pat {
    /// A variable binder — binds the matched value (a constructor payload field)
    /// to a name.
    Var(Symbol),
    /// A wildcard `_` — matches any value and binds nothing.
    Wildcard,
    /// An integer literal pattern `0`, `42`, `-1`. Refutable. Renders as the Rust
    /// integer literal of the same value.
    Int(i64),
    /// A boolean literal pattern `True` / `False`. Refutable in isolation but a
    /// `True` + `False` pair is an exhaustive cover of `Bool`. Renders as the Rust
    /// `true` / `false` literal.
    Bool(bool),
    /// A character literal pattern `'a'`. The carried [`String`] is the source
    /// character text (a single grapheme in well-formed IR); the backend renders
    /// it as a Rust `char` literal. Refutable.
    Char(String),
    /// A string literal pattern `"hello"`. The carried [`String`] is the literal's
    /// value; the backend renders it as a Rust string literal with deterministic
    /// escaping. Refutable.
    Str(String),
    /// An alias / `as` pattern `inner as name` — matches `inner` and additionally
    /// binds the whole matched value to `name`. Renders as the Rust binding-with-
    /// subpattern form `name @ <inner>`. The inner sub-pattern is an arbitrary
    /// [`Pat`] and recurses.
    Alias(Box<Self>, Symbol),
    /// A constructor pattern `Variant sub0 sub1 …` (a nullary pattern `Variant`
    /// has an empty `args`). Each `args` element is an arbitrary [`Pat`]
    /// (nested ctor / tuple / record sub-patterns are all permitted). `home` + `ty`
    /// are the scrutinee enum's nominal identity (see [`EnumDef::home`]).
    Ctor {
        home: ModPath,
        ty: Symbol,
        variant: Symbol,
        args: Vec<Self>,
    },
    /// A tuple pattern `(p0, p1, …)`, destructuring an [`IrType::Tuple`] value
    /// element-by-element.
    ///
    /// The element sub-patterns are arbitrary [`Pat`]s. The tuple-value invariant
    /// (arity ≥ 2) applies to well-formed IR — the lowerer is the sole producer
    /// and upholds it — but the backend stays total over any element vector it
    /// receives and never panics on a degenerate arity.
    Tuple(Vec<Self>),
    /// A record pattern `{ field0 = p0, field1 = p1, … }`, destructuring an
    /// [`IrType::Record`] value field-by-field.
    ///
    /// Each entry pairs a field name ([`Symbol`]) with its sub-pattern (an
    /// arbitrary [`Pat`]). The lowerer is contracted to surface the COMPLETE
    /// field set of the record type — every field the type declares appears here,
    /// a field the source omits binding to a [`Pat::Wildcard`] — so the field-name
    /// set resolves the synthesised struct unambiguously, exactly as a record
    /// literal does. The backend stays total over any entry vector it receives.
    Record(Vec<(Symbol, Self)>),
    /// A list / cons pattern, flattened to a Rust slice-pattern shape: a
    /// `prefix` of fixed leading element sub-patterns plus an optional `rest`
    /// tail binder.
    ///
    /// * `rest = None` is a CLOSED, exact-length list pattern — `[]`
    ///   (`prefix` empty) or `[a, b]` (`prefix` = `[a, b]`). It matches only a
    ///   list of exactly `prefix.len()` elements.
    /// * `rest = Some(p)` is an OPEN cons tail — `x :: xs` (`prefix` = `[x]`,
    ///   `rest` = `xs`) or `a :: b :: rest` (`prefix` = `[a, b]`, `rest` =
    ///   `rest`). It matches any list with AT LEAST `prefix.len()` elements; `p`
    ///   binds the remaining list (a variable / wildcard / alias).
    ///
    /// The element sub-patterns (`prefix`) and the tail binder (`rest`) are
    /// arbitrary [`Pat`]s and recurse. The List type is the closed two-constructor
    /// type `Nil | Cons`, so a `[]` arm plus an `_ :: _`-shaped arm is an
    /// exhaustive cover; coverage over the flattened shape is the type phase's
    /// usefulness check (IPE-T0010), proven before lowering. The backend renders
    /// this directly as a Rust slice pattern (`[p0, p1]` / `[p0, p1, rest @ ..]`).
    Slice {
        prefix: Vec<Self>,
        rest: Option<Box<Self>>,
    },
    /// An or-pattern `p0 | p1 | …` — matches if ANY alternative matches. Each
    /// alternative is an arbitrary [`Pat`] and recurses. Every alternative binds
    /// the identical set of names at identical types (proved upstream in
    /// canon/types), so a single copy of the arm body reads those binders
    /// regardless of which alternative matched. The backend renders this as the
    /// native Rust or-pattern `p0 | p1 | …`, joining the rendered sub-patterns
    /// with ` | `, with the arm body emitted exactly once. Refutable (it
    /// discriminates). Invariant: length ≥ 2 — the lowerer never wraps a lone
    /// alternative.
    Or(Vec<Self>),
}

/// Whether a pattern matches EVERY value of its scrutinee type.
///
/// True for a wildcard, a variable binder, or an alias whose inner pattern is
/// itself irrefutable. Used to prove a flat `match`'s trailing arm is a genuine
/// catch-all.
#[must_use]
pub fn is_irrefutable(pat: &Pat) -> bool {
    match pat {
        Pat::Wildcard | Pat::Var(_) => true,
        Pat::Alias(inner, _) => is_irrefutable(inner),
        // An or-pattern is irrefutable only if every alternative is — in practice
        // never for a well-formed `≥ 2` or-pattern (two distinct irrefutable
        // alternatives are redundant), so it routes through the refutable
        // `Match` path.
        Pat::Or(alts) => alts.iter().all(is_irrefutable),
        Pat::Int(_)
        | Pat::Bool(_)
        | Pat::Char(_)
        | Pat::Str(_)
        | Pat::Ctor { .. }
        | Pat::Tuple(_)
        | Pat::Record(_)
        // A slice / cons pattern is refutable: `[]` matches only the empty list,
        // and `[x, rest @ ..]` matches only a non-empty one. (The lowerer never
        // produces an empty-`prefix` open `[rest @ ..]`, which would be the lone
        // irrefutable slice shape — a whole-list binder stays a [`Pat::Var`].)
        | Pat::Slice { .. } => false,
    }
}

/// Whether this pattern needs NO Rust-level runtime dispatch (discriminant
/// check) anywhere in its shape — no [`Pat::Ctor`], literal leaf, or
/// [`Pat::Slice`] at any depth.
///
/// A `Var` / `Wildcard` leaf, or any nesting of `Tuple` / `Record` /
/// `Alias` over such leaves, is dispatch-free: Rust's tuple/struct/binding
/// patterns always succeed structurally, so matching them costs no
/// discriminant check and (unlike [`is_irrefutable`], which answers a
/// different question about catch-all arms and treats `Tuple`/`Record` as
/// unconditionally refutable) is safe to evaluate at ANY nesting depth,
/// including inside another constructor's payload.
///
/// Used by the Rust backend (`render_arm_pat_alias_safe`) to decide whether
/// an `Alias` node's inner shape can be safely rebuilt from a CLONE of the
/// alias binder (the by-value alias-split) — safe exactly when
/// reconstructing every leaf `inner` binds is possible without having
/// discarded any data, which holds only when `inner` never needed a runtime
/// check to get there. The `ipe_lower` lowerer calls this too, to reject an
/// alias over a dispatch-needing inner pattern in a REFUTABLE match-arm
/// position (IPE-L0128) rather than let it reach the backend, where
/// honoring it soundly would require matching the scrutinee by reference
/// throughout — a materially larger redesign. See
/// `docs/adr/0002-codegen-soundness-and-the-seal.md` §1.
#[must_use]
pub fn is_dispatch_free(pat: &Pat) -> bool {
    match pat {
        Pat::Wildcard | Pat::Var(_) => true,
        Pat::Alias(inner, _) => is_dispatch_free(inner),
        Pat::Tuple(elems) => elems.iter().all(is_dispatch_free),
        Pat::Record(fields) => fields.iter().all(|(_, p)| is_dispatch_free(p)),
        // An or-pattern always discriminates (a well-formed `≥ 2` alternative
        // set selects between shapes), so it is never dispatch-free — grouped
        // with the other refutable, dispatch-needing leaves.
        Pat::Or(_)
        | Pat::Int(_)
        | Pat::Bool(_)
        | Pat::Char(_)
        | Pat::Str(_)
        | Pat::Ctor { .. }
        | Pat::Slice { .. } => false,
    }
}

/// Whether a pattern is LIST-SHAPED — a slice / cons pattern ([`Pat::Slice`]), an
/// irrefutable whole-list binder (a variable / wildcard catch-all over a list
/// scrutinee), or an alias whose inner pattern is itself list-shaped. Used by
/// [`Match::new_flat`] to recognise a list `case` (whose `Nil | Cons` coverage
/// the upstream Maranget check already proved) as a structurally-exhaustive arm
/// set, distinct from a constructor / literal cover.
#[must_use]
pub fn is_list_shaped(pat: &Pat) -> bool {
    match pat {
        Pat::Slice { .. } | Pat::Wildcard | Pat::Var(_) => true,
        Pat::Alias(inner, _) => is_list_shaped(inner),
        // An or-pattern is list-shaped iff every alternative is (`[] | [_]`),
        // so a list `case` written with alternatives still reads as list-shaped.
        Pat::Or(alts) => alts.iter().all(is_list_shaped),
        Pat::Int(_)
        | Pat::Bool(_)
        | Pat::Char(_)
        | Pat::Str(_)
        | Pat::Ctor { .. }
        | Pat::Tuple(_)
        | Pat::Record(_) => false,
    }
}

/// Whether a pattern's HEAD is a constructor — a [`Pat::Ctor`] directly, or an
/// alias (`name @ <inner>`) whose inner pattern is itself constructor-headed.
/// Used by [`Match::new_flat`] to recognise a constructor-discrimination arm set
/// (where coverage is proven by the upstream enum exhaustiveness check) as a
/// distinct case from an open-literal cover (which needs a trailing catch-all).
#[must_use]
pub fn is_ctor_headed(pat: &Pat) -> bool {
    match pat {
        Pat::Ctor { .. } => true,
        Pat::Alias(inner, _) => is_ctor_headed(inner),
        // An or-pattern is constructor-headed iff every alternative is
        // (`Red | Green`), so an alternative-written enum cover reads as a
        // constructor-discrimination arm set.
        Pat::Or(alts) => alts.iter().all(is_ctor_headed),
        Pat::Wildcard
        | Pat::Var(_)
        | Pat::Int(_)
        | Pat::Bool(_)
        | Pat::Char(_)
        | Pat::Str(_)
        | Pat::Tuple(_)
        | Pat::Record(_)
        | Pat::Slice { .. } => false,
    }
}

/// Whether a pattern is PRODUCT-SHAPED — a tuple pattern ([`Pat::Tuple`]), an
/// irrefutable whole-tuple binder (a variable / wildcard catch-all over a tuple
/// scrutinee), or an alias whose inner pattern is itself product-shaped. Used by
/// [`Match::new_flat`] to recognise a multi-arm tuple `case` (whose product
/// coverage the upstream Maranget check already proved) as a structurally-
/// exhaustive arm set, distinct from a constructor / literal / list cover.
#[must_use]
pub fn is_product_shaped(pat: &Pat) -> bool {
    match pat {
        Pat::Tuple(_) | Pat::Wildcard | Pat::Var(_) => true,
        Pat::Alias(inner, _) => is_product_shaped(inner),
        // An or-pattern is product-shaped iff every alternative is.
        Pat::Or(alts) => alts.iter().all(is_product_shaped),
        Pat::Int(_)
        | Pat::Bool(_)
        | Pat::Char(_)
        | Pat::Str(_)
        | Pat::Ctor { .. }
        | Pat::Record(_)
        | Pat::Slice { .. } => false,
    }
}

/// An exhaustive case analysis over an enum scrutinee.
///
/// Fields are private: the sole way to obtain a `Match` is [`Match::new`],
/// which proves exhaustiveness at construction time. This makes a
/// non-exhaustive `Match` unrepresentable.
//
// `Eq` is not derived: the scrutinee / arm bodies are [`Expr`]s that may carry
// a float literal (only `PartialEq`).
#[derive(Clone, PartialEq, Debug)]
pub struct Match {
    scrutinee: Box<Expr>,
    arms: Vec<Arm>,
}

/// Serialises as the plain `{ scrutinee, arms }` shape via the public
/// accessors — no invariant to preserve on the way OUT (any value that
/// exists has already been validated by [`Match::new`]/[`Match::new_flat`]
/// at construction time).
impl serde::Serialize for Match {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(serde::Serialize)]
        struct MatchRef<'a> {
            scrutinee: &'a Expr,
            arms: &'a [Arm],
        }
        MatchRef {
            scrutinee: self.scrutinee(),
            arms: self.arms(),
        }
        .serialize(serializer)
    }
}

/// **Deliberately hand-written, never `#[derive(Deserialize)]`** — `Match`'s
/// fields are private specifically because the sole way to obtain one is
/// [`Match::new`]/[`Match::new_flat`], which prove the arm set is
/// structurally exhaustive at construction time (see the type's own doc). A
/// derived impl would reconstruct `Match { scrutinee, arms }` directly from
/// untrusted bytes, bypassing that proof entirely — the exact same "parse,
/// don't validate" gap `ipe_backend::RelPath`'s hand-written `Deserialize`
/// closes for path-traversal.
///
/// This impl re-validates through [`Match::new_flat`] rather than
/// re-deriving [`Match::new`]'s stricter ctor-exhaustive-cover check,
/// because `new_flat`'s NECESSARY-condition backstop (trailing catch-all /
/// complete `Bool` cover / all-constructor-headed / all-list-shaped /
/// all-product-shaped) is a **provable superset** of what `new` guarantees:
/// every arm `Match::new` accepts has `Pat::Ctor` as its literal arm head
/// (`new`'s own hard requirement — a non-`Ctor` head is rejected before the
/// exhaustiveness check even runs), so `is_ctor_headed` holds for every arm
/// and `new_flat`'s `all_ctor_headed` branch always accepts it. A `Match`
/// built via `new_flat` trivially re-validates through the same function
/// (pure, deterministic over the same arms). So EVERY legitimately
/// constructed `Match` in the whole compiler round-trips through this
/// impl unchanged, while an EMPTY arm list or an open-literal cover with no
/// trailing catch-all is rejected exactly as it would be at original
/// construction time.
///
/// **Honestly scoped gap.** `new_flat`'s `all_ctor_headed` branch (unlike
/// `Match::new` itself) does not re-verify that the ctor-headed arms cover
/// EVERY variant of the scrutinee's enum — `Match` carries no external
/// "complete variant set" of its own to check against (that list lives on
/// the `EnumDef` elsewhere in the `Program`, not on `Match`), and `new_flat`
/// deliberately trusts the upstream Maranget check for that shape (see its
/// own doc). So a tampered entry that DROPS one arm from an otherwise-
/// exhaustive ctor cover (while keeping every remaining arm ctor-headed)
/// is NOT caught here. This is not a silent-corruption or RCE risk: the
/// missing-variant gap surfaces the moment the relocated `Program` reaches
/// `RustBackend::emit` as a plain Rust `match` with a missing arm, which
/// `cargo build` rejects with E0004 — a loud, safe failure, never wrong
/// output. Closing it fully would require deserializing the WHOLE
/// `Program` first and cross-checking every `Match` against its scrutinee
/// enum's `EnumDef` in a second pass — recorded here as a possible future
/// hardening, not attempted because the current gap already fails safe.
impl<'de> serde::Deserialize<'de> for Match {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(serde::Deserialize)]
        struct RawMatch {
            scrutinee: Expr,
            arms: Vec<Arm>,
        }
        let raw = RawMatch::deserialize(deserializer)?;
        Self::new_flat(raw.scrutinee, raw.arms)
            .map_err(|diag| serde::de::Error::custom(format!("{diag:?}")))
    }
}

impl Match {
    /// Build a constructor-headed `Match` from an ORDERED arm list.
    ///
    /// `variants` is the complete set of constructors of the scrutinee's enum.
    /// Every arm head is a constructor pattern, and the same top-level
    /// constructor MAY appear in more than one arm — those arms discriminate on
    /// their nested sub-patterns (`Som (Som x)`, `Som Non`, `Non`) and Rust's
    /// `match` resolves the overlap and ordering natively. Arms are kept in
    /// source order; the renderer emits them one-to-one.
    ///
    /// Exhaustiveness over the nested shape is proven UPSTREAM by the type
    /// phase's usefulness/Maranget analysis (IPE-T0010), which runs before
    /// lowering, so a non-exhaustive `case` never reaches this constructor. The
    /// check here is a cheap NECESSARY-condition backstop only: every variant of
    /// the enum must appear as some arm's top constructor, and no arm may name a
    /// constructor outside the enum. A variant wholly absent from the top
    /// constructors guarantees non-exhaustiveness, so it is a genuine internal
    /// invariant violation; duplicate top constructors are the normal nested-
    /// discrimination shape and are accepted.
    ///
    /// # Errors
    ///
    /// Returns [`Diagnostic::CompilerBug`] when an arm head is not a constructor,
    /// an arm names a constructor not in `variants`, or some variant is missing
    /// from the top constructors — each an internal invariant violation the
    /// lowerer must never produce.
    pub fn new(scrutinee: Expr, arms: Vec<Arm>, variants: &[Symbol]) -> DResult<Self> {
        let expected: BTreeSet<Symbol> = variants.iter().copied().collect();

        let mut covered: BTreeSet<Symbol> = BTreeSet::new();
        for arm in &arms {
            // The case-arm head is always a constructor pattern (payload binders
            // are sub-patterns). A bare variable / wildcard whole-scrutinee arm
            // routes through `new_flat`, so a non-ctor arm head here is an
            // internal invariant violation, surfaced as a `CompilerBug` rather
            // than silently skewing the coverage set.
            let Pat::Ctor { variant, .. } = &arm.pat else {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_ir::Match::new",
                    detail: "match arm head is not a constructor pattern".to_owned(),
                });
            };
            let variant = *variant;
            if !expected.contains(&variant) {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_ir::Match::new",
                    detail: format!(
                        "match arm covers variant {} not in the scrutinee's enum",
                        variant.as_raw()
                    ),
                });
            }
            // A repeated top constructor is the nested-discrimination shape
            // (`Som (Som x)` then `Som Non`); the set insert ignores the repeat.
            covered.insert(variant);
        }

        if covered != expected {
            return Err(Diagnostic::CompilerBug {
                where_: "ipe_ir::Match::new",
                detail: format!(
                    "non-exhaustive match: top constructors cover {} of {} variants",
                    covered.len(),
                    expected.len()
                ),
            });
        }

        Ok(Self {
            scrutinee: Box::new(scrutinee),
            arms,
        })
    }

    /// Build a FLAT refutable `match` from an ORDERED arm list whose heads are
    /// literals (`0` / `'a'` / `"hi"` / `True` / `False`), wildcards / variables,
    /// alias binders, or constructors, in any mix. Arms are kept in source order;
    /// the renderer emits them one-to-one, so several arms may discriminate on the
    /// same top-level constructor via their nested sub-patterns.
    ///
    /// Unlike [`Match::new`] (the all-constructor path), this path admits open
    /// literal types (`Int` / `Char` / `String`) whose coverage cannot be proven
    /// from a finite variant set. Exhaustiveness is therefore proven UPSTREAM by
    /// the type phase's usefulness/Maranget analysis (IPE-T0010), which runs
    /// before lowering, so a non-exhaustive `case` never reaches this constructor.
    ///
    /// The backstop here is a cheap NECESSARY-condition check — the arm set is
    /// accepted when it is structurally guaranteed to cover its scrutinee:
    ///
    /// * a trailing IRREFUTABLE arm (`_`, a variable, or an alias whose inner
    ///   pattern is irrefutable) matches every remaining value, OR
    /// * the arms are a complete `Bool` cover (`True` and `False` both present), OR
    /// * every arm head is constructor-shaped (a constructor, or an alias over
    ///   one): the scrutinee is then a finite enum whose coverage the upstream
    ///   Maranget check already proved, so no open-literal gap can hide here.
    ///
    /// An arm set matching none of these (an open-literal cover with no trailing
    /// catch-all) would be genuinely non-exhaustive, so it is a `CompilerBug`
    /// rather than a Rust `match` rustc would reject with E0004.
    ///
    /// # Errors
    /// [`Diagnostic::CompilerBug`] when `arms` is empty or none of the backstop
    /// conditions hold.
    pub fn new_flat(scrutinee: Expr, arms: Vec<Arm>) -> DResult<Self> {
        let Some(last) = arms.last() else {
            return Err(Diagnostic::CompilerBug {
                where_: "ipe_ir::Match::new_flat",
                detail: "flat match has no arms".to_owned(),
            });
        };
        let trailing_catch_all = is_irrefutable(&last.pat);
        let bool_complete = arms.iter().all(|a| matches!(a.pat, Pat::Bool(_)))
            && arms.iter().any(|a| matches!(a.pat, Pat::Bool(true)))
            && arms.iter().any(|a| matches!(a.pat, Pat::Bool(false)));
        // Constructor-shaped heads (a constructor, or an alias whose inner is one)
        // mean the scrutinee is a finite enum; the upstream Maranget check proved
        // its coverage, so an alias-over-constructor discrimination set with no
        // trailing catch-all (`Som (Som x) as w` then `Som Non` then `Non`) is
        // still sound here.
        let all_ctor_headed = arms.iter().all(|a| is_ctor_headed(&a.pat));
        // A list `case`: every arm is list-shaped (a slice / cons pattern, an
        // irrefutable whole-list binder, or an alias over those) and at least one
        // is a genuine slice pattern. The List type is the closed `Nil | Cons`
        // type, so a `[]` arm plus an `_ :: _`-shaped arm covers it; that coverage
        // was proven UPSTREAM by the Maranget usefulness check (IPE-T0010), so an
        // arm set in this shape with no trailing catch-all (`x :: rest` then `[]`)
        // is still sound here.
        let all_list_shaped = arms.iter().all(|a| is_list_shaped(&a.pat))
            && arms.iter().any(|a| matches!(a.pat, Pat::Slice { .. }));
        // A multi-arm tuple `case`: every arm is product-shaped (a tuple pattern,
        // an irrefutable whole-tuple binder, or an alias over those) and at least
        // one is a genuine tuple pattern. A product type is inhabited only by its
        // element tuples, so the upstream Maranget usefulness check (IPE-T0010)
        // already proved coverage before lowering — an arm set in this shape with
        // no trailing catch-all (`(True, _)` then `(False, _)`) is still sound.
        let all_product_shaped = arms.iter().all(|a| is_product_shaped(&a.pat))
            && arms.iter().any(|a| matches!(a.pat, Pat::Tuple(_)));
        if !trailing_catch_all
            && !bool_complete
            && !all_ctor_headed
            && !all_list_shaped
            && !all_product_shaped
        {
            return Err(Diagnostic::CompilerBug {
                where_: "ipe_ir::Match::new_flat",
                detail: "flat match is not structurally exhaustive (no trailing \
                         catch-all, not a complete Bool cover, not a \
                         constructor-headed cover, not a list cover, and not a \
                         tuple cover)"
                    .to_owned(),
            });
        }
        Ok(Self {
            scrutinee: Box::new(scrutinee),
            arms,
        })
    }

    #[must_use]
    pub fn scrutinee(&self) -> &Expr {
        &self.scrutinee
    }

    #[must_use]
    pub fn arms(&self) -> &[Arm] {
        &self.arms
    }

    /// Rebuild this `Match` by transforming its scrutinee and every arm's
    /// body/guard, leaving every arm's PATTERN — and the arm count and order —
    /// completely untouched.
    ///
    /// [`Self::new`]/[`Self::new_flat`]'s exhaustiveness invariant is a
    /// property of the pattern SHAPES alone (see their doc comments), so a
    /// transformation that only ever touches `scrutinee`, [`Arm::body`], and
    /// [`Arm::guard`] (an expression evaluated in the arm's scope, not a
    /// pattern shape) can never invalidate it. This is the sound, sealed
    /// replacement for the former `pub fn from_parts_unchecked` escape hatch
    /// (AUD-09), which took a raw `Vec<Arm>` and could rebuild a `Match` with
    /// an empty arm list (`match x {}` — rustc E0004, no Ipê diagnostic) or a
    /// reordered/dropped-arm list. `pub(crate)`-sealing was not viable
    /// instead, because every caller of the old function lived in a different
    /// crate (`ipe_lower`, `ipe_backend_rust`).
    ///
    /// `arm_map` receives `(pattern, body, guard)` per arm and returns the
    /// new `(body, guard)`; the pattern is read-only by construction.
    ///
    /// When a pass threads one `&mut` accumulator through BOTH the scrutinee
    /// and the arm bodies (two closures cannot share a unique borrow —
    /// E0524), rewrite the scrutinee first via [`Self::map_scrutinee`] and
    /// then map the bodies with an identity `scrutinee_map`.
    #[must_use]
    pub fn map_bodies(
        self,
        scrutinee_map: impl FnOnce(Expr) -> Expr,
        mut arm_map: impl FnMut(&Pat, Expr, Option<Expr>) -> (Expr, Option<Expr>),
    ) -> Self {
        let new_scrutinee = Box::new(scrutinee_map(*self.scrutinee));
        let new_arms = self
            .arms
            .into_iter()
            .map(|arm| {
                let (body, guard) = arm_map(&arm.pat, arm.body, arm.guard);
                Arm {
                    pat: arm.pat,
                    body,
                    guard,
                }
            })
            .collect();
        Self {
            scrutinee: new_scrutinee,
            arms: new_arms,
        }
    }

    /// Rebuild this `Match` with a transformed scrutinee, leaving every arm
    /// completely untouched. Shape-preserving by construction — the arm
    /// vector is never even iterated. Companion to [`Self::map_bodies`] for
    /// passes that thread a single `&mut` accumulator through scrutinee and
    /// bodies sequentially (see `map_bodies`'s doc).
    #[must_use]
    pub fn map_scrutinee(self, scrutinee_map: impl FnOnce(Expr) -> Expr) -> Self {
        Self {
            scrutinee: Box::new(scrutinee_map(*self.scrutinee)),
            arms: self.arms,
        }
    }

    /// Fallible sibling of [`Self::map_bodies`] for passes that can fail
    /// (e.g. depth-limited clone-capture rewriting). Same shape invariant:
    /// only `scrutinee`, [`Arm::body`], and [`Arm::guard`] are transformed;
    /// each arm's `pat` is carried through untouched, and a failure
    /// short-circuits before any arm is lost or reordered.
    ///
    /// # Errors
    ///
    /// Propagates the first error `scrutinee_map` or `arm_map` returns.
    pub fn try_map_bodies<E>(
        self,
        scrutinee_map: impl FnOnce(Expr) -> Result<Expr, E>,
        mut arm_map: impl FnMut(&Pat, Expr, Option<Expr>) -> Result<(Expr, Option<Expr>), E>,
    ) -> Result<Self, E> {
        let new_scrutinee = Box::new(scrutinee_map(*self.scrutinee)?);
        let new_arms = self
            .arms
            .into_iter()
            .map(|arm| {
                let (body, guard) = arm_map(&arm.pat, arm.body, arm.guard)?;
                Ok(Arm {
                    pat: arm.pat,
                    body,
                    guard,
                })
            })
            .collect::<Result<Vec<_>, E>>()?;
        Ok(Self {
            scrutinee: new_scrutinee,
            arms: new_arms,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipe_diagnostics::DResult;
    use ipe_intern::Interner;
    use ipe_kernels::Target;

    /// An effect-carrier `Send` renders `Send` natively and only `'static` on wasm32.
    #[test]
    fn effect_send_is_target_relative() {
        let effect = BoundSet::UNBOUNDED.with_effect_send();
        assert!(effect.has_static(), "effect-carrier Send implies 'static");
        assert!(
            !effect.has_send(),
            "effect-carrier Send is not unconditional"
        );
        assert!(effect.requires_send_on(Target::Native));
        assert!(!effect.requires_send_on(Target::WasmClient));
        assert!(!effect.requires_send_on(Target::WasmWasi));
    }

    /// An unconditional `Send` (a `Decoder` element) holds on every target.
    #[test]
    fn unconditional_send_holds_on_every_target() {
        let decoder = BoundSet::UNBOUNDED.with_send();
        for target in [Target::Native, Target::WasmClient, Target::WasmWasi] {
            assert!(decoder.requires_send_on(target), "{target:?}");
            assert!(
                decoder.with_effect_send().requires_send_on(target),
                "{target:?}"
            );
        }
        assert!(
            !BoundSet::UNBOUNDED
                .with_static()
                .requires_send_on(Target::Native)
        );
    }

    fn msg_enum(i: &mut Interner) -> DResult<(Symbol, Symbol, Symbol)> {
        let ty = i.intern("Msg")?;
        let inc = i.intern("Increment")?;
        let dec = i.intern("Decrement")?;
        Ok((ty, inc, dec))
    }

    // ── ir_type_feature_requirement (Phase 1 SSOT) ─────────────────────────

    /// Every gated leaf declares the exact runtime feature its emitted Rust
    /// needs, and the `Url` breach leaf (`IrType::Url`) is covered — the whole
    /// point of the total function. A regression that drops a leaf's arm fails
    /// to compile (no wildcard), so this test pins the *mapping*, not the
    /// totality (rustc enforces totality).
    #[test]
    fn gated_leaves_declare_their_feature() {
        let cases: &[(IrType, RuntimeFeatureId)] = &[
            (IrType::Url, RuntimeFeatureId::Url),
            (IrType::UrlRelative, RuntimeFeatureId::Url),
            (IrType::Secret, RuntimeFeatureId::Secret),
            (IrType::Decimal, RuntimeFeatureId::Decimal),
            (IrType::Regex, RuntimeFeatureId::Regex),
            (IrType::Json, RuntimeFeatureId::Json),
            (
                IrType::Decoder(Box::new(IrType::Int)),
                RuntimeFeatureId::Json,
            ),
            (IrType::CsvDoc, RuntimeFeatureId::Csv),
            (IrType::CacheCfg, RuntimeFeatureId::CacheKernel),
            (IrType::CacheStats, RuntimeFeatureId::CacheKernel),
            (
                IrType::WebSocketClientCfg,
                RuntimeFeatureId::WebsocketClient,
            ),
            (IrType::EmailMessage, RuntimeFeatureId::Email),
            (IrType::EmailAddress, RuntimeFeatureId::Email),
            (IrType::EmailProvider, RuntimeFeatureId::Email),
            (IrType::CryptoKey, RuntimeFeatureId::CryptoCore),
            (IrType::CryptoMac, RuntimeFeatureId::CryptoCore),
            (IrType::SqlFragment, RuntimeFeatureId::Db),
            (IrType::Dsn, RuntimeFeatureId::Db),
            (IrType::Connection, RuntimeFeatureId::Db),
            (IrType::ServerRequest, RuntimeFeatureId::Server),
            (IrType::StreamWriter, RuntimeFeatureId::Server),
            (IrType::AuthConfig, RuntimeFeatureId::Server),
            (IrType::HttpRequest, RuntimeFeatureId::HttpClient),
            (IrType::HttpMethod, RuntimeFeatureId::HttpClient),
            (IrType::WebReq, RuntimeFeatureId::Web),
            (
                IrType::WebRoute(Box::new(IrType::Unit)),
                RuntimeFeatureId::Web,
            ),
        ];
        for (ty, want) in cases {
            assert_eq!(
                ir_type_feature_requirement(ty),
                Some(*want),
                "leaf {ty:?} must require feature {want:?}"
            );
        }
    }

    /// Ungated leaves and the transparent CARRIERS return `None` at their own
    /// node (their element leaves are visited by the transitive walk, not here).
    #[test]
    fn ungated_leaves_and_carriers_require_nothing() {
        let none: &[IrType] = &[
            IrType::Int,
            IrType::Str,
            IrType::Bytes,
            IrType::Db,
            IrType::Order,
            IrType::Error,
            IrType::Path,
            IrType::Principal,
            IrType::Setting,
            IrType::Locale,
            IrType::TuiApp,
            IrType::UiPlain(UiPlain::Color),
            IrType::Generic(Symbol::from_raw(0)),
            // Carriers: `Some` requirement only ever comes from carried leaves,
            // reached by the walk, never from the carrier node itself.
            IrType::List(Box::new(IrType::Url)),
            IrType::Maybe(Box::new(IrType::Secret)),
            IrType::Task(Box::new(IrType::Json)),
            IrType::Tuple(vec![IrType::Url, IrType::Int]),
        ];
        for ty in none {
            assert_eq!(
                ir_type_feature_requirement(ty),
                None,
                "leaf/carrier {ty:?} must require no feature at its own node"
            );
        }
    }

    /// The neutral IR feature ids map to non-empty cargo feature names; the
    /// featureset-closure SEAL proves each is in the runtime crate's declared
    /// `[features]` universe.
    #[test]
    fn feature_ids_map_to_nonempty_names() {
        for id in [
            RuntimeFeatureId::Json,
            RuntimeFeatureId::Url,
            RuntimeFeatureId::Secret,
            RuntimeFeatureId::Decimal,
            RuntimeFeatureId::Regex,
            RuntimeFeatureId::Csv,
            RuntimeFeatureId::CacheKernel,
            RuntimeFeatureId::WebsocketClient,
            RuntimeFeatureId::Email,
            RuntimeFeatureId::CryptoCore,
            RuntimeFeatureId::Db,
            RuntimeFeatureId::Server,
            RuntimeFeatureId::HttpClient,
            RuntimeFeatureId::Web,
        ] {
            assert!(!id.feature_name().is_empty(), "empty name for {id:?}");
        }
    }

    #[test]
    fn match_new_accepts_exhaustive_and_round_trips_debug() -> DResult<()> {
        let mut i = Interner::new();
        let (ty, inc, dec) = msg_enum(&mut i)?;
        let count = i.intern("count")?;

        // case msg of Increment -> count + 1 ; Decrement -> count - 1
        let arms = vec![
            Arm {
                pat: Pat::Ctor {
                    home: ModPath(vec![]),
                    ty,
                    variant: inc,
                    args: vec![],
                },
                body: Expr::BinOp {
                    op: BinOp::IntAdd,
                    lhs: Box::new(Expr::Var(count)),
                    rhs: Box::new(Expr::Int(1)),
                },
                guard: None,
            },
            Arm {
                pat: Pat::Ctor {
                    home: ModPath(vec![]),
                    ty,
                    variant: dec,
                    args: vec![],
                },
                body: Expr::BinOp {
                    op: BinOp::IntSub,
                    lhs: Box::new(Expr::Var(count)),
                    rhs: Box::new(Expr::Int(1)),
                },
                guard: None,
            },
        ];
        let res = Match::new(Expr::Var(i.intern("msg")?), arms, &[inc, dec]);

        assert_eq!(res.as_ref().map(|m| m.arms().len()), Ok(2));
        assert!(matches!(
            res.as_ref().map(Match::scrutinee),
            Ok(Expr::Var(_))
        ));
        // Debug round-trips (no panic, stable shape).
        let rendered = format!("{res:?}");
        assert!(rendered.contains("Match"));
        Ok(())
    }

    /// Build the canonical 2-arm exhaustive `Match` the AUD-09 combinator
    /// tests transform (`case msg of Increment -> count ; Decrement -> count`).
    fn two_arm_match(i: &mut Interner) -> DResult<Match> {
        let (ty, inc, dec) = msg_enum(i)?;
        let count = i.intern("count")?;
        let arms = vec![
            Arm {
                pat: Pat::Ctor {
                    home: ModPath(vec![]),
                    ty,
                    variant: inc,
                    args: vec![],
                },
                body: Expr::Var(count),
                guard: None,
            },
            Arm {
                pat: Pat::Ctor {
                    home: ModPath(vec![]),
                    ty,
                    variant: dec,
                    args: vec![],
                },
                body: Expr::Var(count),
                guard: None,
            },
        ];
        Match::new(Expr::Var(i.intern("msg")?), arms, &[inc, dec])
    }

    /// AUD-09: `map_bodies` must carry every arm's pattern (and the arm
    /// count/order) through untouched — an identity transform round-trips, and
    /// a body-rewriting transform changes ONLY the bodies.
    #[test]
    fn map_bodies_preserves_arm_patterns_and_count() -> DResult<()> {
        let mut i = Interner::new();
        let m = two_arm_match(&mut i)?;
        let before_pats: Vec<Pat> = m.arms().iter().map(|a| a.pat.clone()).collect();

        // Identity transform: everything structurally equal.
        let id = m.clone().map_bodies(|s| s, |_, b, g| (b, g));
        assert_eq!(id.arms().len(), 2);
        let id_pats: Vec<Pat> = id.arms().iter().map(|a| a.pat.clone()).collect();
        assert_eq!(id_pats, before_pats);
        assert_eq!(id, m);

        // Real body rewrite: bodies change, patterns/count/order do not.
        let rewritten = m.map_bodies(|s| s, |_, _, g| (Expr::Int(9), g));
        assert_eq!(rewritten.arms().len(), 2);
        let new_pats: Vec<Pat> = rewritten.arms().iter().map(|a| a.pat.clone()).collect();
        assert_eq!(new_pats, before_pats);
        assert!(rewritten.arms().iter().all(|a| a.body == Expr::Int(9)));
        Ok(())
    }

    /// AUD-09: `try_map_bodies` short-circuits on the first arm error — the
    /// whole call is `Err`, no partial/corrupted `Match` is observable.
    #[test]
    fn try_map_bodies_short_circuits_on_err() -> DResult<()> {
        let mut i = Interner::new();
        let m = two_arm_match(&mut i)?;
        let mut seen = 0_u32;
        let res: Result<Match, &str> = m.try_map_bodies(Ok, |_, b, g| {
            seen += 1;
            if seen == 2 {
                Err("second arm fails")
            } else {
                Ok((b, g))
            }
        });
        assert_eq!(res, Err("second arm fails"));
        Ok(())
    }

    /// AUD-09: a scrutinee error short-circuits BEFORE any arm transform runs.
    #[test]
    fn try_map_bodies_scrutinee_error_short_circuits_before_any_arm_runs() -> DResult<()> {
        let mut i = Interner::new();
        let m = two_arm_match(&mut i)?;
        let mut arm_ran = false;
        let res: Result<Match, &str> = m.try_map_bodies(
            |_| Err("scrutinee fails"),
            |_, b, g| {
                arm_ran = true;
                Ok((b, g))
            },
        );
        assert_eq!(res, Err("scrutinee fails"));
        assert!(!arm_ran, "arm_map must never run after a scrutinee error");
        Ok(())
    }

    /// AUD-09 seal: `from_parts_unchecked` must never be reintroduced. Any
    /// caller that needs to rebuild a `Match` after a body-only rewrite must
    /// use `map_bodies`/`try_map_bodies`, which cannot change arm patterns or
    /// arm count/order. (The test's own name spells the sealed identifier
    /// differently so the scan below does not trip on itself.)
    #[test]
    fn no_raw_parts_match_escape_hatch_reintroduced() {
        let src = include_str!("ir.rs");
        for (idx, line) in src.lines().enumerate() {
            let code = line.split("//").next().unwrap_or(line);
            assert!(
                !code.contains(concat!("from_parts_", "unchecked")),
                "AUD-09 seal reintroduced at ir.rs:{} — rebuild via \
                 Match::map_bodies/try_map_bodies instead: {line:?}",
                idx + 1,
            );
        }
    }

    #[test]
    fn match_new_rejects_non_exhaustive() -> DResult<()> {
        let mut i = Interner::new();
        let (ty, inc, dec) = msg_enum(&mut i)?;
        let count = i.intern("count")?;

        // Only the Increment arm — Decrement uncovered.
        let arms = vec![Arm {
            pat: Pat::Ctor {
                home: ModPath(vec![]),
                ty,
                variant: inc,
                args: vec![],
            },
            body: Expr::Var(count),
            guard: None,
        }];
        let r = Match::new(Expr::Var(i.intern("msg")?), arms, &[inc, dec]);
        assert!(matches!(r, Err(Diagnostic::CompilerBug { .. })));
        Ok(())
    }

    #[test]
    fn match_new_accepts_duplicate_top_ctor_with_full_cover() -> DResult<()> {
        let mut i = Interner::new();
        let (ty, inc, dec) = msg_enum(&mut i)?;

        // Two arms head-matching the same top constructor (`Increment`) is the
        // nested-discrimination shape; combined with the `Decrement` arm the top
        // constructors cover the whole enum, so the ordered arm list is accepted.
        let arms = vec![
            Arm {
                pat: Pat::Ctor {
                    home: ModPath(vec![]),
                    ty,
                    variant: inc,
                    args: vec![],
                },
                body: Expr::Int(0),
                guard: None,
            },
            Arm {
                pat: Pat::Ctor {
                    home: ModPath(vec![]),
                    ty,
                    variant: inc,
                    args: vec![],
                },
                body: Expr::Int(1),
                guard: None,
            },
            Arm {
                pat: Pat::Ctor {
                    home: ModPath(vec![]),
                    ty,
                    variant: dec,
                    args: vec![],
                },
                body: Expr::Int(2),
                guard: None,
            },
        ];
        let r = Match::new(Expr::Var(i.intern("msg")?), arms, &[inc, dec])?;
        assert_eq!(r.arms().len(), 3);
        Ok(())
    }

    #[test]
    fn match_new_rejects_missing_top_ctor_despite_duplicate() -> DResult<()> {
        let mut i = Interner::new();
        let (ty, inc, dec) = msg_enum(&mut i)?;

        // `Increment` twice but `Decrement` never: a variant wholly absent from
        // the top constructors guarantees non-exhaustiveness, so the cheap
        // necessary-condition backstop still fails closed.
        let arms = vec![
            Arm {
                pat: Pat::Ctor {
                    home: ModPath(vec![]),
                    ty,
                    variant: inc,
                    args: vec![],
                },
                body: Expr::Int(0),
                guard: None,
            },
            Arm {
                pat: Pat::Ctor {
                    home: ModPath(vec![]),
                    ty,
                    variant: inc,
                    args: vec![],
                },
                body: Expr::Int(1),
                guard: None,
            },
        ];
        let r = Match::new(Expr::Var(i.intern("msg")?), arms, &[inc, dec]);
        assert!(matches!(r, Err(Diagnostic::CompilerBug { .. })));
        Ok(())
    }

    #[test]
    fn match_new_rejects_unknown_variant() -> DResult<()> {
        let mut i = Interner::new();
        let (ty, inc, dec) = msg_enum(&mut i)?;
        let bogus = i.intern("Reset")?;

        let arms = vec![
            Arm {
                pat: Pat::Ctor {
                    home: ModPath(vec![]),
                    ty,
                    variant: inc,
                    args: vec![],
                },
                body: Expr::Int(0),
                guard: None,
            },
            Arm {
                pat: Pat::Ctor {
                    home: ModPath(vec![]),
                    ty,
                    variant: bogus,
                    args: vec![],
                },
                body: Expr::Int(1),
                guard: None,
            },
        ];
        let r = Match::new(Expr::Var(i.intern("msg")?), arms, &[inc, dec]);
        assert!(matches!(r, Err(Diagnostic::CompilerBug { .. })));
        Ok(())
    }

    // ── flat refutable match (`Match::new_flat`) ──────────────────────────

    #[test]
    fn new_flat_accepts_literal_arms_with_trailing_wildcard() -> DResult<()> {
        let mut i = Interner::new();
        let n = i.intern("n")?;
        // case n of 0 -> 0 ; 1 -> 1 ; _ -> 9
        let arms = vec![
            Arm {
                pat: Pat::Int(0),
                body: Expr::Int(0),
                guard: None,
            },
            Arm {
                pat: Pat::Int(1),
                body: Expr::Int(1),
                guard: None,
            },
            Arm {
                pat: Pat::Wildcard,
                body: Expr::Int(9),
                guard: None,
            },
        ];
        let r = Match::new_flat(Expr::Var(n), arms);
        assert_eq!(r.as_ref().map(|m| m.arms().len()), Ok(3));
        Ok(())
    }

    #[test]
    fn new_flat_accepts_trailing_variable_and_alias_catch_all() -> DResult<()> {
        let mut i = Interner::new();
        let n = i.intern("n")?;
        let m = i.intern("m")?;
        let k = i.intern("k")?;
        // case n of 0 -> 0 ; (m as k) -> k  — alias-of-var is irrefutable.
        let arms = vec![
            Arm {
                pat: Pat::Int(0),
                body: Expr::Int(0),
                guard: None,
            },
            Arm {
                pat: Pat::Alias(Box::new(Pat::Var(m)), k),
                body: Expr::Var(k),
                guard: None,
            },
        ];
        assert!(Match::new_flat(Expr::Var(n), arms).is_ok());
        Ok(())
    }

    #[test]
    fn new_flat_accepts_complete_bool_cover_without_wildcard() -> DResult<()> {
        let mut i = Interner::new();
        let b = i.intern("b")?;
        // case b of True -> 1 ; False -> 0 — closed cover, no catch-all needed.
        let arms = vec![
            Arm {
                pat: Pat::Bool(true),
                body: Expr::Int(1),
                guard: None,
            },
            Arm {
                pat: Pat::Bool(false),
                body: Expr::Int(0),
                guard: None,
            },
        ];
        assert!(Match::new_flat(Expr::Var(b), arms).is_ok());
        Ok(())
    }

    #[test]
    fn new_flat_accepts_alias_over_ctor_discrimination_without_catch_all() -> DResult<()> {
        let mut i = Interner::new();
        let opt = i.intern("Opt")?;
        let som = i.intern("Som")?;
        let non = i.intern("Non")?;
        let o = i.intern("o")?;
        let w = i.intern("w")?;
        let x = i.intern("x")?;
        // case o of (Som (Som x)) as w -> … ; Som Non -> … ; Non -> …
        // Every head is constructor-shaped (the first under an alias), so the
        // scrutinee is a finite enum whose coverage the upstream Maranget check
        // proved — no trailing catch-all needed.
        let arms = vec![
            Arm {
                pat: Pat::Alias(
                    Box::new(Pat::Ctor {
                        home: ModPath(vec![]),
                        ty: opt,
                        variant: som,
                        args: vec![Pat::Ctor {
                            home: ModPath(vec![]),
                            ty: opt,
                            variant: som,
                            args: vec![Pat::Var(x)],
                        }],
                    }),
                    w,
                ),
                body: Expr::Var(x),
                guard: None,
            },
            Arm {
                pat: Pat::Ctor {
                    home: ModPath(vec![]),
                    ty: opt,
                    variant: som,
                    args: vec![Pat::Ctor {
                        home: ModPath(vec![]),
                        ty: opt,
                        variant: non,
                        args: vec![],
                    }],
                },
                body: Expr::Int(0),
                guard: None,
            },
            Arm {
                pat: Pat::Ctor {
                    home: ModPath(vec![]),
                    ty: opt,
                    variant: non,
                    args: vec![],
                },
                body: Expr::Int(1),
                guard: None,
            },
        ];
        assert!(Match::new_flat(Expr::Var(o), arms).is_ok());
        Ok(())
    }

    #[test]
    fn new_flat_rejects_open_literals_without_catch_all() -> DResult<()> {
        let mut i = Interner::new();
        let n = i.intern("n")?;
        // case n of 0 -> 0 ; 1 -> 1 — Int is OPEN; no catch-all → not structurally
        // exhaustive. The soundness floor: a CompilerBug here, never an emitted
        // `match` that rustc would reject with E0004.
        let arms = vec![
            Arm {
                pat: Pat::Int(0),
                body: Expr::Int(0),
                guard: None,
            },
            Arm {
                pat: Pat::Int(1),
                body: Expr::Int(1),
                guard: None,
            },
        ];
        assert!(matches!(
            Match::new_flat(Expr::Var(n), arms),
            Err(Diagnostic::CompilerBug { .. })
        ));
        Ok(())
    }

    #[test]
    fn new_flat_rejects_incomplete_bool_cover() -> DResult<()> {
        let mut i = Interner::new();
        let b = i.intern("b")?;
        // Only `True` — `False` uncovered and no wildcard.
        let arms = vec![Arm {
            pat: Pat::Bool(true),
            body: Expr::Int(1),
            guard: None,
        }];
        assert!(matches!(
            Match::new_flat(Expr::Var(b), arms),
            Err(Diagnostic::CompilerBug { .. })
        ));
        Ok(())
    }

    #[test]
    fn is_irrefutable_classifies_binders_only() -> DResult<()> {
        let mut i = Interner::new();
        let x = i.intern("x")?;
        assert!(is_irrefutable(&Pat::Wildcard));
        assert!(is_irrefutable(&Pat::Var(x)));
        assert!(is_irrefutable(&Pat::Alias(Box::new(Pat::Var(x)), x)));
        assert!(!is_irrefutable(&Pat::Int(0)));
        assert!(!is_irrefutable(&Pat::Bool(true)));
        assert!(!is_irrefutable(&Pat::Str("hi".to_owned())));
        assert!(!is_irrefutable(&Pat::Alias(Box::new(Pat::Int(0)), x)));
        Ok(())
    }

    #[test]
    fn dispatch_free_over_tuple_of_vars_and_wildcards() -> DResult<()> {
        let mut i = Interner::new();
        let x = i.intern("x")?;
        assert!(is_dispatch_free(&Pat::Tuple(vec![
            Pat::Var(x),
            Pat::Wildcard
        ])));
        // An alias over a dispatch-free tuple stays dispatch-free.
        assert!(is_dispatch_free(&Pat::Alias(
            Box::new(Pat::Tuple(vec![Pat::Var(x), Pat::Var(x)])),
            x,
        )));
        // A record of binder leaves is dispatch-free too.
        assert!(is_dispatch_free(&Pat::Record(vec![
            (x, Pat::Var(x)),
            (x, Pat::Wildcard)
        ])));
        Ok(())
    }

    #[test]
    fn dispatch_free_false_over_nested_ctor_or_literal() -> DResult<()> {
        let mut i = Interner::new();
        let x = i.intern("x")?;
        assert!(!is_dispatch_free(&Pat::Tuple(vec![
            Pat::Int(0),
            Pat::Var(x)
        ])));
        // A Ctor nested inside a Tuple inside an Alias must still fail.
        assert!(!is_dispatch_free(&Pat::Alias(
            Box::new(Pat::Tuple(vec![Pat::Ctor {
                home: ModPath(vec![]),
                ty: x,
                variant: x,
                args: vec![],
            }])),
            x,
        )));
        // Slice / literal leaves need dispatch wherever they sit.
        assert!(!is_dispatch_free(&Pat::Slice {
            prefix: vec![Pat::Var(x)],
            rest: None,
        }));
        assert!(!is_dispatch_free(&Pat::Str("s".to_owned())));
        Ok(())
    }

    #[test]
    fn tuple_expr_and_type_construct_and_round_trip() -> DResult<()> {
        let mut i = Interner::new();
        let x = i.intern("x")?;

        // ( x + 1, 2, "three"-as-Var ) — a 3-tuple expression.
        let expr = Expr::Tuple(vec![
            Expr::BinOp {
                op: BinOp::IntAdd,
                lhs: Box::new(Expr::Var(x)),
                rhs: Box::new(Expr::Int(1)),
            },
            Expr::Int(2),
            Expr::Var(x),
        ]);
        assert_eq!(expr, expr.clone());
        let rendered = format!("{expr:?}");
        assert!(rendered.contains("Tuple"));

        // (Int, Bool) — a 2-tuple type.
        let ty = IrType::Tuple(vec![IrType::Int, IrType::Bool]);
        assert_eq!(ty, ty.clone());
        assert!(format!("{ty:?}").contains("Tuple"));

        // Nested tuple type: (Int, (Bool, String)).
        let nested = IrType::Tuple(vec![
            IrType::Int,
            IrType::Tuple(vec![IrType::Bool, IrType::Str]),
        ]);
        assert_eq!(nested, nested.clone());
        Ok(())
    }

    #[test]
    fn record_expr_access_update_and_type_construct_and_round_trip() -> DResult<()> {
        let mut i = Interner::new();
        let x = i.intern("x")?;
        let y = i.intern("y")?;
        let p = i.intern("p")?;

        // { x = 1, y = 2 } — fields sorted by name (x before y).
        let lit = Expr::Record {
            fields: vec![(x, Expr::Int(1)), (y, Expr::Int(2))],
            ty: None,
        };
        assert_eq!(lit, lit.clone());
        assert!(format!("{lit:?}").contains("Record"));

        // p.x — a field access.
        let access = Expr::Access {
            record: Box::new(Expr::Var(p)),
            field: x,
            field_ty: IrType::Int,
        };
        assert_eq!(access, access.clone());
        assert!(format!("{access:?}").contains("Access"));

        // { p | x = 5 } — a single-field update.
        let update = Expr::Update {
            record: Box::new(Expr::Var(p)),
            fields: vec![(x, Expr::Int(5))],
        };
        assert_eq!(update, update.clone());
        assert!(format!("{update:?}").contains("Update"));

        // { x : Int, y : Bool } — a closed record TYPE.
        let mut fields = BTreeMap::new();
        fields.insert(x, IrType::Int);
        fields.insert(y, IrType::Bool);
        let ty = IrType::Record(fields);
        assert_eq!(ty, ty.clone());
        assert!(format!("{ty:?}").contains("Record"));

        // Nested record type: { x : Int, y : { x : Int, y : Bool } }.
        let mut outer = BTreeMap::new();
        outer.insert(x, IrType::Int);
        outer.insert(y, ty);
        let nested = IrType::Record(outer);
        assert_eq!(nested, nested.clone());
        Ok(())
    }

    #[test]
    fn lambda_apply_expr_and_fun_type_construct_and_round_trip() -> DResult<()> {
        let mut i = Interner::new();
        let x = i.intern("x")?;
        let f = i.intern("f")?;

        // \x -> x + 1 — a single-param lambda returning Int.
        let lambda = Expr::Lambda {
            params: vec![(x, IrType::Int)],
            ret: IrType::Int,
            body: Box::new(Expr::BinOp {
                op: BinOp::IntAdd,
                lhs: Box::new(Expr::Var(x)),
                rhs: Box::new(Expr::Int(1)),
            }),
        };
        assert_eq!(lambda, lambda.clone());
        assert!(format!("{lambda:?}").contains("Lambda"));

        // f 2 — apply the function-typed local `f` to one argument.
        let apply = Expr::Apply {
            func: Box::new(Expr::Var(f)),
            args: vec![Expr::Int(2)],
        };
        assert_eq!(apply, apply.clone());
        assert!(format!("{apply:?}").contains("Apply"));

        // Int -> Int — a one-param function type.
        let fun_ty = IrType::Fun(vec![IrType::Int], Box::new(IrType::Int));
        assert_eq!(fun_ty, fun_ty.clone());
        assert!(format!("{fun_ty:?}").contains("Fun"));

        // () -> Bool — a nullary function type (distinct from Bool alone).
        let nullary = IrType::Fun(vec![], Box::new(IrType::Bool));
        assert_eq!(nullary, nullary.clone());
        assert_ne!(nullary, IrType::Bool);

        // (Int, Bool) -> Int — a multi-param function type, nested under Fun.
        let multi = IrType::Fun(
            vec![IrType::Int, IrType::Bool],
            Box::new(IrType::Fun(vec![IrType::Str], Box::new(IrType::Unit))),
        );
        assert_eq!(multi, multi.clone());

        // A top-level function named as a first-class value: callee `fn#0`,
        // reified at its boxed `Int -> Int` value type.
        let func_value = Expr::FuncValue {
            callee: Callee::Func(FuncId::from_raw(0)),
            ty: IrType::Fun(vec![IrType::Int], Box::new(IrType::Int)),
        };
        assert_eq!(func_value, func_value.clone());
        assert!(format!("{func_value:?}").contains("FuncValue"));
        Ok(())
    }

    #[test]
    fn generic_type_and_quantified_func_construct_and_round_trip() -> DResult<()> {
        let mut i = Interner::new();
        let a = i.intern("a")?;
        let b = i.intern("b")?;
        let x = i.intern("x")?;
        let id = i.intern("id")?;

        // A fully-parametric `id : a -> a` quantifying [a].
        let generic_a = IrType::Generic(a);
        assert_eq!(generic_a, generic_a.clone());
        assert!(format!("{generic_a:?}").contains("Generic"));

        let func = Func {
            id: FuncId::from_raw(0),
            name: id,
            home: ModPath(vec![]),
            type_params: vec![(a, BoundSet::UNBOUNDED)],
            row_params: vec![],
            params: vec![(x, IrType::Generic(a))],
            ret: IrType::Generic(a),
            body: Expr::Var(x),
        };
        assert_eq!(func, func.clone());
        assert_eq!(func.type_params, vec![(a, BoundSet::UNBOUNDED)]);

        // Distinct generic vars compare unequal; quantification order is carried
        // verbatim (no dedup / sort), so [a, b] stays [a, b].
        assert_ne!(IrType::Generic(a), IrType::Generic(b));
        let two = Func {
            id: FuncId::from_raw(1),
            name: id,
            home: ModPath(vec![]),
            type_params: vec![(a, BoundSet::UNBOUNDED), (b, BoundSet::UNBOUNDED)],
            row_params: vec![],
            params: vec![(x, IrType::Generic(a))],
            ret: IrType::Generic(b),
            body: Expr::Var(x),
        };
        assert_eq!(
            two.type_params,
            vec![(a, BoundSet::UNBOUNDED), (b, BoundSet::UNBOUNDED)]
        );

        // A constrained variable carries its bounds; an unbounded one does not.
        assert!(BoundSet::default().is_unbounded());
        let bounds = BoundSet::UNBOUNDED.with_add().with_copy();
        assert!(!bounds.is_unbounded());
        assert!(bounds.has_add() && bounds.has_copy());
        assert!(!bounds.has_sub() && !bounds.has_ord());
        let double = Func {
            id: FuncId::from_raw(2),
            name: id,
            home: ModPath(vec![]),
            type_params: vec![(a, bounds)],
            row_params: vec![],
            params: vec![(x, IrType::Generic(a))],
            ret: IrType::Generic(a),
            body: Expr::Var(x),
        };
        assert_eq!(double.type_params, vec![(a, bounds)]);
        Ok(())
    }

    #[test]
    fn program_round_trips_debug() -> DResult<()> {
        let mut i = Interner::new();
        let (ty, inc, dec) = msg_enum(&mut i)?;
        let main_sym = i.intern("main")?;
        let main_mod = i.intern("Main")?;

        let func = Func {
            id: FuncId::from_raw(0),
            name: main_sym,
            home: ModPath(vec![]),
            type_params: vec![],
            row_params: vec![],
            params: vec![],
            ret: IrType::Task(Box::new(IrType::Unit)),
            body: Expr::Call {
                callee: Callee::Kernel(KernelFn::IoPrintln),
                args: vec![Expr::Call {
                    callee: Callee::Kernel(KernelFn::StringFromInt),
                    args: vec![Expr::Int(1)],
                    pin: CallPin::None,
                    on_form: OnFormKind::NotForm,
                }],
                pin: CallPin::None,
                on_form: OnFormKind::NotForm,
            },
        };
        let program = Program {
            imports_unsafe_submodule: false,
            imported_web_capabilities: std::collections::BTreeSet::new(),
            modules: vec![Module {
                name: ModPath(vec![main_mod]),
                types: vec![TypeDef::Enum(EnumDef {
                    home: ModPath(vec![]),
                    name: ty,
                    type_params: vec![],
                    variants: vec![
                        Variant {
                            name: inc,
                            fields: vec![],
                        },
                        Variant {
                            name: dec,
                            fields: vec![],
                        },
                    ],
                })],
                funcs: vec![func],
                entry: Some(FuncId::from_raw(0)),
                records: vec![],
                uses_tea: false,
                uses_server: false,
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
                uses_debug: false,
                uses_ffi: false,
                uses_async_runtime: false,
            }],
        };
        let clone = program.clone();
        assert_eq!(program, clone);
        assert!(format!("{program:?}").contains("Program"));
        Ok(())
    }

    #[test]
    fn let_if_and_extended_binops_construct_and_round_trip() -> DResult<()> {
        let mut i = Interner::new();
        let x = i.intern("x")?;

        // let x = 6 / 2 in if (x == 3) && (x > 0) then x * 10 else x - 1
        let expr = Expr::Let {
            name: x,
            value: Box::new(Expr::BinOp {
                op: BinOp::Div,
                lhs: Box::new(Expr::Int(6)),
                rhs: Box::new(Expr::Int(2)),
            }),
            body: Box::new(Expr::If {
                cond: Box::new(Expr::BinOp {
                    op: BinOp::And,
                    lhs: Box::new(Expr::BinOp {
                        op: BinOp::Eq,
                        lhs: Box::new(Expr::Var(x)),
                        rhs: Box::new(Expr::Int(3)),
                    }),
                    rhs: Box::new(Expr::BinOp {
                        op: BinOp::Gt,
                        lhs: Box::new(Expr::Var(x)),
                        rhs: Box::new(Expr::Int(0)),
                    }),
                }),
                then_: Box::new(Expr::BinOp {
                    op: BinOp::IntMul,
                    lhs: Box::new(Expr::Var(x)),
                    rhs: Box::new(Expr::Int(10)),
                }),
                else_: Box::new(Expr::BinOp {
                    op: BinOp::IntSub,
                    lhs: Box::new(Expr::Var(x)),
                    rhs: Box::new(Expr::Int(1)),
                }),
            }),
        };

        // Clone + structural equality + Debug all hold for the new variants.
        assert_eq!(expr, expr.clone());
        let rendered = format!("{expr:?}");
        assert!(rendered.contains("Let"));
        assert!(rendered.contains("If"));

        // Every BinOp variant is a distinct, Copy, comparable value: the full
        // set has no duplicates and the Copy bound holds (the array is consumed
        // by value below without moving out of `all`).
        let all = [
            BinOp::IntAdd,
            BinOp::IntSub,
            BinOp::IntMul,
            BinOp::FloatAdd,
            BinOp::FloatSub,
            BinOp::FloatMul,
            BinOp::Div,
            BinOp::IntDiv,
            BinOp::Eq,
            BinOp::Neq,
            BinOp::Lt,
            BinOp::Gt,
            BinOp::Le,
            BinOp::Ge,
            BinOp::And,
            BinOp::Or,
            BinOp::Append,
        ];
        let distinct: BTreeSet<_> = all.iter().map(|op| format!("{op:?}")).collect();
        assert_eq!(distinct.len(), all.len());
        let copied = all;
        assert_eq!(copied.len(), all.len());
        Ok(())
    }

    #[test]
    fn payload_and_generic_enum_construct_and_round_trip() -> DResult<()> {
        let mut i = Interner::new();
        let a = i.intern("a")?;
        let maybe = i.intern("Maybe")?;
        let just = i.intern("Just")?;
        let nothing = i.intern("Nothing")?;

        // type Maybe a = Just a | Nothing — one generic param, one payload
        // variant (carrying the type variable), one nullary variant.
        let def = EnumDef {
            home: ModPath(vec![]),
            name: maybe,
            type_params: vec![a],
            variants: vec![
                Variant {
                    name: just,
                    fields: vec![IrType::Generic(a)],
                },
                Variant {
                    name: nothing,
                    fields: vec![],
                },
            ],
        };
        assert_eq!(def, def.clone());
        assert_eq!(def.type_params, vec![a]);
        assert_eq!(def.variants.len(), 2);
        assert!(def.variants.first().is_some_and(|v| !v.fields.is_empty()));
        assert!(def.variants.get(1).is_some_and(|v| v.fields.is_empty()));

        // A use-site type `Maybe Int` carries its concrete type argument.
        let use_ty = IrType::Enum {
            home: ModPath(vec![]),
            name: maybe,
            args: vec![IrType::Int],
        };
        assert_eq!(use_ty, use_ty.clone());
        // A non-generic enum use carries no args and is distinct from the applied
        // form.
        let bare = IrType::Enum {
            home: ModPath(vec![]),
            name: maybe,
            args: vec![],
        };
        assert_ne!(use_ty, bare);

        // Construction `Just 5` carries its payload argument.
        let ctor = Expr::Ctor {
            home: ModPath(vec![]),
            ty: maybe,
            variant: just,
            args: vec![Expr::Int(5)],
        };
        assert_eq!(ctor, ctor.clone());
        assert!(format!("{ctor:?}").contains("Ctor"));
        Ok(())
    }

    #[test]
    fn ctor_pattern_with_var_and_wildcard_payloads_round_trip() -> DResult<()> {
        let mut i = Interner::new();
        let maybe = i.intern("Maybe")?;
        let just = i.intern("Just")?;
        let nothing = i.intern("Nothing")?;
        let x = i.intern("x")?;
        let m = i.intern("m")?;

        // case m of Just x -> x ; Nothing -> 0  — a var-binding payload pattern
        // and a nullary pattern. Match::new accepts it (coverage over the variant
        // NAME set; payload binding does not affect coverage).
        let arms = vec![
            Arm {
                pat: Pat::Ctor {
                    home: ModPath(vec![]),
                    ty: maybe,
                    variant: just,
                    args: vec![Pat::Var(x)],
                },
                body: Expr::Var(x),
                guard: None,
            },
            Arm {
                pat: Pat::Ctor {
                    home: ModPath(vec![]),
                    ty: maybe,
                    variant: nothing,
                    args: vec![],
                },
                body: Expr::Int(0),
                guard: None,
            },
        ];
        let m1 = Match::new(Expr::Var(m), arms, &[just, nothing])?;
        assert_eq!(m1.arms().len(), 2);

        // The wildcard payload sub-pattern is also representable.
        let wild = Pat::Ctor {
            home: ModPath(vec![]),
            ty: maybe,
            variant: just,
            args: vec![Pat::Wildcard],
        };
        assert_eq!(wild, wild.clone());
        assert!(format!("{wild:?}").contains("Wildcard"));
        Ok(())
    }

    #[test]
    fn match_new_rejects_non_ctor_arm_head() -> DResult<()> {
        let mut i = Interner::new();
        let (_ty, inc, dec) = msg_enum(&mut i)?;

        // A bare variable whole-scrutinee arm is not a valid arm head — it
        // must be a constructor pattern, so Match::new fails closed.
        let arms = vec![Arm {
            pat: Pat::Var(i.intern("anything")?),
            body: Expr::Int(0),
            guard: None,
        }];
        let r = Match::new(Expr::Var(i.intern("msg")?), arms, &[inc, dec]);
        assert!(matches!(r, Err(Diagnostic::CompilerBug { .. })));
        Ok(())
    }

    #[test]
    fn recursive_enum_def_round_trips() -> DResult<()> {
        let mut i = Interner::new();
        let tree = i.intern("Tree")?;
        let leaf = i.intern("Leaf")?;
        let node = i.intern("Node")?;

        // type Tree = Leaf | Node Tree Int Tree — the Node payload carries two
        // direct self-edges (the enum's own type) around an Int.
        let self_ty = IrType::Enum {
            home: ModPath(vec![]),
            name: tree,
            args: vec![],
        };
        let def = EnumDef {
            home: ModPath(vec![]),
            name: tree,
            type_params: vec![],
            variants: vec![
                Variant {
                    name: leaf,
                    fields: vec![],
                },
                Variant {
                    name: node,
                    fields: vec![self_ty.clone(), IrType::Int, self_ty],
                },
            ],
        };
        assert_eq!(def, def.clone());
        assert!(def.variants.get(1).is_some_and(|v| v.fields.len() == 3));
        Ok(())
    }

    // ── seal: ir_type_is_serde ─────────────────────────────────────────

    /// `true` for every referenced enum — the leaf-level predicate under test.
    fn all_serde(_: &ModPath, _: Symbol) -> bool {
        true
    }

    #[test]
    fn serde_primitives_and_plain_carriers_are_ok() {
        let ok = [
            IrType::Int,
            IrType::Float,
            IrType::Bool,
            IrType::Str,
            IrType::Char,
            IrType::Unit,
            IrType::Bytes,
            IrType::Json,
            IrType::Generic(Symbol::from_raw(0)),
            IrType::List(Box::new(IrType::Int)),
            IrType::Maybe(Box::new(IrType::Str)),
            IrType::Result(Box::new(IrType::Str), Box::new(IrType::Int)),
            IrType::Tuple(vec![IrType::Int, IrType::Bool]),
        ];
        for t in ok {
            assert!(ir_type_is_serde(&t, &all_serde), "{t:?} should be serde");
        }
    }

    #[test]
    fn serde_rejects_effects_handles_and_functions() {
        let bad = [
            IrType::Cmd(Box::new(IrType::Unit)),
            IrType::Sub(Box::new(IrType::Unit)),
            IrType::Task(Box::new(IrType::Unit)),
            IrType::Decoder(Box::new(IrType::Int)),
            IrType::Db,
            IrType::Fun(vec![IrType::Int], Box::new(IrType::Int)),
            IrType::ServerRequest,
            IrType::WebReq,
        ];
        for t in bad {
            assert!(!ir_type_is_serde(&t, &all_serde), "{t:?} must NOT be serde");
        }
    }

    /// The two arms where serde is STRICTER than derivable: UI carriers and UI
    /// plain values are `Clone`/`Debug`/`PartialEq` but not `serde`.
    #[test]
    fn serde_rejects_ui_but_derivable_accepts_it() {
        let html = IrType::Ui {
            ctor: UiCtor::Html,
            msg: Box::new(IrType::Unit),
        };
        let color = IrType::UiPlain(UiPlain::Color);
        for t in [&html, &color] {
            assert!(
                ir_type_is_derivable(t, &all_serde),
                "{t:?} IS derivable (CDPeq)"
            );
            assert!(
                !ir_type_is_serde(t, &all_serde),
                "{t:?} must NOT be serde (the #91 CDPeq-but-not-serde gap)"
            );
        }
    }

    /// `SqlFragment`: fully derivable (Clone + `PartialEq`) but
    /// deliberately NOT serde — it is a query-building value, never persisted
    /// to a Web session store.
    #[test]
    fn sqlfragment_derivable_but_not_serde() {
        let t = IrType::SqlFragment;
        assert!(
            ir_type_is_derivable(&t, &all_serde),
            "SqlFragment IS derivable (Clone + PartialEq)"
        );
        assert!(
            !ir_type_is_serde(&t, &all_serde),
            "SqlFragment must NOT be serde"
        );
    }

    /// `Secret`: fully derivable (Clone + `PartialEq`) but
    /// deliberately NOT serde — a `Secret` must never round-trip through a
    /// Web session store or any other serialisation path. Guards the
    /// derive-blast-radius property: a record containing a `Secret`
    /// field must still get `Clone`/`Debug`/`==` (proved by
    /// `serde_poisons_carriers_transitively`-style coverage below).
    #[test]
    fn secret_derivable_but_not_serde() {
        let t = IrType::Secret;
        assert!(
            ir_type_is_derivable(&t, &all_serde),
            "Secret IS derivable (Clone + PartialEq)"
        );
        assert!(
            !ir_type_is_serde(&t, &all_serde),
            "Secret must NOT be serde"
        );
    }

    /// derive-blast-radius: a record `{ apiKey : Secret, label :
    /// String }` must still be derivable (Clone/Debug/PartialEq) even though
    /// its `Secret` field is not serde — marking a leaf non-derivable (rather
    /// than merely non-serde) would make the WHOLE record lose ALL
    /// derives, an exit-0-then-cargo-fail class.
    #[test]
    fn record_containing_secret_stays_derivable() {
        let mut fields = std::collections::BTreeMap::new();
        fields.insert(Symbol::from_raw(0), IrType::Secret);
        fields.insert(Symbol::from_raw(1), IrType::Str);
        let t = IrType::Record(fields);
        assert!(
            ir_type_is_derivable(&t, &all_serde),
            "a record containing a Secret field must stay derivable"
        );
        assert!(
            !ir_type_is_serde(&t, &all_serde),
            "a record containing a Secret field must NOT be serde"
        );
    }

    /// A carrier is serde iff every child is; one bad field poisons it.
    #[test]
    fn serde_poisons_carriers_transitively() {
        let bad_list = IrType::List(Box::new(IrType::Cmd(Box::new(IrType::Unit))));
        assert!(!ir_type_is_serde(&bad_list, &all_serde));
        let good_list = IrType::List(Box::new(IrType::Int));
        assert!(ir_type_is_serde(&good_list, &all_serde));
        // A record with one Cmd field is not serde; all-Int is.
        let mut bad = std::collections::BTreeMap::new();
        bad.insert(Symbol::from_raw(0), IrType::Int);
        bad.insert(Symbol::from_raw(1), IrType::Cmd(Box::new(IrType::Unit)));
        assert!(!ir_type_is_serde(&IrType::Record(bad), &all_serde));
    }

    /// A referenced enum's serde verdict flows through the `enum_serde` lookup.
    #[test]
    fn serde_consults_enum_lookup() {
        let e = IrType::Enum {
            home: ModPath(vec![]),
            name: Symbol::from_raw(7),
            args: vec![],
        };
        assert!(ir_type_is_serde(&e, &|_, _| true), "serde enum passes");
        assert!(
            !ir_type_is_serde(&e, &|_, _| false),
            "non-serde enum poisons"
        );
    }
}

/// Symbol-relocation persistence — `ipe_ir`-level round-trip and
/// cross-process id-drift proof for whole-`Program` `serde` persistence.
///
/// Complements `ipe_intern`'s `Symbol`-level proof
/// (`serialize_then_deserialize_survives_cross_process_id_drift`) with the
/// SAME property one layer up, over a realistic `Program` value that
/// exercises every `Symbol`-carrying shape: `ModPath`, `EnumDef`/`Variant`
/// names, `Func` `name`/`params`/`type_params`, a `Match` (the one hand-written
/// `serde` impl in this crate), `Pat::Ctor`/`Pat::Var`, and a record literal
/// (`Vec<(Symbol, Expr)>`).
#[cfg(test)]
mod serde_persistence_tests {
    use std::sync::{Arc, Mutex};

    use ipe_diagnostics::DResult;
    use ipe_intern::{Interner, SerdeInternerGuard};

    use super::{
        Arm, CallPin, Callee, EnumDef, Expr, Func, FuncId, IrType, KernelFn, Match, ModPath,
        Module, OnFormKind, Pat, Program, TypeDef, Variant,
    };
    use crate::pretty::pretty;

    /// Build a small but representative `Program`: one enum (`Msg`), one
    /// entry function whose body pattern-matches the enum via a genuine
    /// [`Match`] node and constructs a record literal — every
    /// `Symbol`-carrying IR shape this module's doc names, in one value.
    // A single exhaustive `Module` struct literal (every `uses_*` gate spelled
    // out) dominates the length; splitting it would only scatter the fixture.
    #[allow(clippy::too_many_lines)]
    fn sample_program(i: &mut Interner) -> DResult<Program> {
        let msg_ty = i.intern("Msg")?;
        let inc = i.intern("Increment")?;
        let dec = i.intern("Decrement")?;
        let main_sym = i.intern("main")?;
        let main_mod = i.intern("Main")?;
        let msg_param = i.intern("msg")?;
        let count_field = i.intern("count")?;

        let scrutinee = Expr::Var(msg_param);
        let arms = vec![
            Arm::new(
                Pat::Ctor {
                    home: ModPath(vec![]),
                    ty: msg_ty,
                    variant: inc,
                    args: vec![],
                },
                // A record literal `{ count = 1 }` — exercises
                // `Vec<(Symbol, Expr)>`.
                Expr::Record {
                    fields: vec![(count_field, Expr::Int(1))],
                    ty: None,
                },
            ),
            Arm::new(
                Pat::Ctor {
                    home: ModPath(vec![]),
                    ty: msg_ty,
                    variant: dec,
                    args: vec![],
                },
                Expr::Record {
                    fields: vec![(count_field, Expr::Int(0))],
                    ty: None,
                },
            ),
        ];
        let body = Expr::Match(Match::new(scrutinee, arms, &[inc, dec])?);

        let func = Func {
            id: FuncId::from_raw(0),
            name: main_sym,
            home: ModPath(vec![]),
            type_params: vec![],
            row_params: vec![],
            params: vec![(msg_param, IrType::Generic(msg_param))],
            ret: IrType::Unit,
            body,
        };
        Ok(Program {
            imports_unsafe_submodule: false,
            imported_web_capabilities: std::collections::BTreeSet::new(),
            modules: vec![Module {
                name: ModPath(vec![main_mod]),
                types: vec![TypeDef::Enum(EnumDef {
                    home: ModPath(vec![]),
                    name: msg_ty,
                    type_params: vec![],
                    variants: vec![
                        Variant {
                            name: inc,
                            fields: vec![],
                        },
                        Variant {
                            name: dec,
                            fields: vec![],
                        },
                    ],
                })],
                funcs: vec![func],
                entry: Some(FuncId::from_raw(0)),
                records: vec![],
                uses_tea: false,
                uses_server: false,
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
                uses_debug: false,
                uses_ffi: false,
                uses_async_runtime: false,
            }],
        })
    }

    #[test]
    fn round_trips_within_one_interner() -> DResult<()> {
        let mut plain = Interner::new();
        let program = sample_program(&mut plain)?;
        let interner = Arc::new(Mutex::new(plain));

        let json = {
            let _guard = SerdeInternerGuard::install(Arc::clone(&interner));
            serde_json::to_string(&program).expect("serialize must succeed")
        };
        let round_tripped: Program = {
            let _guard = SerdeInternerGuard::install(Arc::clone(&interner));
            serde_json::from_str(&json).expect("deserialize must succeed")
        };
        assert_eq!(
            program, round_tripped,
            "same interner: ids AND strings agree"
        );
        Ok(())
    }

    /// A tampered [`Callee::Kernel`] entry must not silently coerce — the
    /// derived `Deserialize` on the closed `StdlibKernel` enum rejects any
    /// tag it does not recognise (proof that the whole-`Program` `serde`
    /// surface fails closed on structurally-invalid input, not just on a
    /// poisoned `Symbol`).
    #[test]
    fn deserialize_rejects_unknown_kernel_tag() -> DResult<()> {
        let mut plain = Interner::new();
        let f = plain.intern("f")?;
        let interner = Arc::new(Mutex::new(plain));
        let program = Program {
            imports_unsafe_submodule: false,
            imported_web_capabilities: std::collections::BTreeSet::new(),
            modules: vec![Module {
                name: ModPath(vec![f]),
                types: vec![],
                funcs: vec![Func {
                    id: FuncId::from_raw(0),
                    name: f,
                    home: ModPath(vec![]),
                    type_params: vec![],
                    row_params: vec![],
                    params: vec![],
                    ret: IrType::Unit,
                    body: Expr::Call {
                        callee: Callee::Kernel(KernelFn::IoPrintln),
                        args: vec![],
                        pin: CallPin::None,
                        on_form: OnFormKind::NotForm,
                    },
                }],
                entry: None,
                records: vec![],
                uses_tea: false,
                uses_server: false,
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
                uses_debug: false,
                uses_ffi: false,
                uses_async_runtime: false,
            }],
        };
        let json = {
            let _guard = SerdeInternerGuard::install(Arc::clone(&interner));
            serde_json::to_string(&program).expect("serialize must succeed")
        };
        let tampered = json.replace("\"IoPrintln\"", "\"NotARealKernelVariant\"");
        let _guard = SerdeInternerGuard::install(Arc::clone(&interner));
        let result: Result<Program, _> = serde_json::from_str(&tampered);
        assert!(
            result.is_err(),
            "an unknown kernel tag must be rejected, never silently coerced"
        );
        Ok(())
    }

    /// A tampered `Match` with an EMPTIED arm list must be rejected at
    /// deserialize time via [`Match::new_flat`]'s structural backstop —
    /// proof that `Match`'s hand-written `Deserialize` actually revalidates
    /// rather than trusting the disk bytes verbatim.
    #[test]
    fn deserialize_rejects_emptied_tampered_match() -> DResult<()> {
        let mut plain = Interner::new();
        let program = sample_program(&mut plain)?;
        let interner = Arc::new(Mutex::new(plain));
        let json = {
            let _guard = SerdeInternerGuard::install(Arc::clone(&interner));
            serde_json::to_string(&program).expect("serialize must succeed")
        };

        // Parse back into a generic JSON value and empty the arm list
        // entirely — `Match::new_flat` rejects an arm-less match outright
        // ("flat match has no arms").
        let mut value: serde_json::Value =
            serde_json::from_str(&json).expect("must parse as generic JSON");
        let arms = value
            .pointer_mut("/modules/0/funcs/0/body/Match/arms")
            .and_then(serde_json::Value::as_array_mut)
            .expect("Match.arms must be a JSON array at the expected path");
        assert_eq!(
            arms.len(),
            2,
            "sample_program must have built a 2-arm Match"
        );
        arms.clear();
        let tampered = serde_json::to_string(&value).expect("re-serialize must succeed");

        let _guard = SerdeInternerGuard::install(Arc::clone(&interner));
        let result: Result<Program, _> = serde_json::from_str(&tampered);
        assert!(
            result.is_err(),
            "an emptied tampered Match arm list must be rejected, \
             never silently accepted as a valid Program"
        );
        Ok(())
    }

    /// **Honestly scoped gap, verified rather than merely documented.**
    /// Dropping ONE arm from an otherwise-exhaustive ctor-headed cover is
    /// NOT caught by [`Match`]'s `Deserialize` (see that impl's own doc for
    /// why: `new_flat`'s `all_ctor_headed` branch trusts the upstream
    /// Maranget check and does not re-verify full variant coverage, and
    /// `Match` carries no external "complete variant set" to check
    /// against). This test pins that boundary explicitly so a future
    /// change to `new_flat`'s semantics is forced to reconsider it, rather
    /// than silently regressing this deserializer's actual coverage
    /// without anyone noticing. The gap is safe: the resulting `Program`
    /// still cannot reach a `cargo build` success — `RustBackend::emit`
    /// renders the missing arm as a genuine Rust exhaustiveness gap, which
    /// `cargo build` rejects with E0004 (a loud failure, never silently
    /// wrong output).
    #[test]
    fn deserialize_accepts_single_arm_ctor_headed_match_new_flat_does_not_reverify_full_coverage()
    -> DResult<()> {
        let mut plain = Interner::new();
        let program = sample_program(&mut plain)?;
        let interner = Arc::new(Mutex::new(plain));
        let json = {
            let _guard = SerdeInternerGuard::install(Arc::clone(&interner));
            serde_json::to_string(&program).expect("serialize must succeed")
        };

        let mut value: serde_json::Value =
            serde_json::from_str(&json).expect("must parse as generic JSON");
        let arms = value
            .pointer_mut("/modules/0/funcs/0/body/Match/arms")
            .and_then(serde_json::Value::as_array_mut)
            .expect("Match.arms must be a JSON array at the expected path");
        arms.truncate(1);
        let tampered = serde_json::to_string(&value).expect("re-serialize must succeed");

        let _guard = SerdeInternerGuard::install(Arc::clone(&interner));
        let result: Result<Program, _> = serde_json::from_str(&tampered);
        assert!(
            result.is_ok(),
            "documents the known `new_flat` scope boundary: a single \
             ctor-headed arm still passes `all_ctor_headed`, since \
             `new_flat` does not itself re-check variant coverage"
        );
        Ok(())
    }

    /// **The mission proof.** Proves a `Program` deserialized through the
    /// relocation pass, into a reader interner whose id-assignment history
    /// has NOTHING in common with the writer's, is structurally/
    /// name-identical to a Program built by a totally independent, never-
    /// serialized construction — i.e. behaves exactly as if it had been
    /// freshly lowered in THAT reader process, which is the property this
    /// whole persistence design exists to guarantee.
    ///
    /// A same-process round trip (the test above) cannot distinguish "the
    /// relocation pass correctly re-interns by string" from "the id
    /// happened to survive by coincidence" — a fresh interner given the
    /// exact same sequence of `intern` calls in the exact same order would
    /// trivially reproduce the same ids either way. This test deliberately
    /// diverges every interner's history (different noise, different
    /// counts, different orders) so a raw-id relocation bug WOULD manifest
    /// as a wrong resolved name somewhere in the structural dump — then
    /// asserts the dumps are identical anyway, comparing by RESOLVED NAME
    /// (via `ipe_ir::pretty::pretty`, not raw `Symbol` equality, since two
    /// independently-built-then-relocated `Program`s are not expected to
    /// share numeric ids — only meaning).
    #[test]
    fn program_survives_cross_process_symbol_id_drift() -> DResult<()> {
        // "Process A" (the writer): pollute with noise unrelated to the
        // program, then build + serialize.
        let mut interner_a = Interner::new();
        for noise in ["alpha", "beta", "gamma"] {
            interner_a.intern(noise)?;
        }
        let program_a = sample_program(&mut interner_a)?;
        let interner_a = Arc::new(Mutex::new(interner_a));
        let json = {
            let _guard = SerdeInternerGuard::install(Arc::clone(&interner_a));
            serde_json::to_string(&program_a).expect("serialize must succeed")
        };

        // "Process B" (the reader): pollute with a DIFFERENT set of noise,
        // in a different order and count, before deserializing — forces
        // genuine id drift relative to process A for every relocated
        // symbol.
        let mut interner_b = Interner::new();
        for noise in ["zzz_one", "zzz_two", "zzz_three", "zzz_four", "zzz_five"] {
            interner_b.intern(noise)?;
        }
        let interner_b = Arc::new(Mutex::new(interner_b));
        let program_b: Program = {
            let _guard = SerdeInternerGuard::install(Arc::clone(&interner_b));
            serde_json::from_str(&json).expect("deserialize must succeed")
        };

        // "Process C" (ground truth): a COMPLETELY independent construction
        // that never touches serialization at all — the value a genuine
        // fresh `lower_program()` call would produce in yet another
        // process. Its interner has its OWN unrelated history too.
        let mut interner_c = Interner::new();
        for noise in ["unrelated_1", "unrelated_2"] {
            interner_c.intern(noise)?;
        }
        let program_c = sample_program(&mut interner_c)?;

        // The raw entry-function-name ids MUST differ across all three —
        // proves the drift is real, not an accident of matching histories.
        let entry_name_raw = |p: &Program| -> u32 {
            p.modules
                .first()
                .and_then(|m| m.funcs.first())
                .expect("sample_program always builds one module with one func")
                .name
                .as_raw()
        };
        let raw_a = entry_name_raw(&program_a);
        let raw_b = entry_name_raw(&program_b);
        let raw_c = entry_name_raw(&program_c);
        assert!(
            raw_a != raw_b && raw_b != raw_c && raw_a != raw_c,
            "the three interners' differing histories must produce three \
             different raw ids for this test to actually probe drift \
             (got a={raw_a}, b={raw_b}, c={raw_c})"
        );

        // Yet the STRUCTURAL, NAME-RESOLVED content is identical: the
        // relocated `program_b` (interner_b) reads exactly like the
        // never-serialized `program_c` (interner_c).
        let dump_b = {
            let guard = interner_b
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            pretty(&program_b, &guard)
        };
        let dump_c = pretty(&program_c, &interner_c);
        assert_eq!(
            dump_b, dump_c,
            "a Program relocated across a simulated process boundary must be \
             structurally/name-identical to a fresh, never-serialized \
             construction in an unrelated interner"
        );
        // Sanity: the dump actually contains the meaningful names (not an
        // accidental empty-string comparison).
        assert!(dump_b.contains("Increment") && dump_b.contains("Decrement"));
        assert!(dump_b.contains("main"));
        Ok(())
    }
}
