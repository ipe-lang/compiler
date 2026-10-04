//! Kernel-function registry — the single closed enum covering every Ipê
//! stdlib kernel.
//!
//! # DAG constraint
//!
//! `ipe_kernels` is a **leaf crate**.  Its only permitted dependencies are
//! `ipe_intern` and `ipe_diagnostics`.  No edge to `ipe_ir`, `ipe_types`, or
//! `ipe_backend_rust` is ever allowed; those crates import `ipe_kernels` and a
//! reverse edge would create a DAG cycle.
//!
//! `ipe_ir` re-exports `type KernelFn = ipe_kernels::StdlibKernel` so
//! call-sites reach the enum through either crate.

#![allow(clippy::module_name_repetitions)] // KernelId / KernelClass / FfiKernelId all contain "Kernel"
#![forbid(unsafe_code)]

mod capability;
pub use capability::{Capability, ElementCapability, UnknownCapability, WebCapability};

pub mod css_value_safety;
pub use css_value_safety::css_value_is_safe;

pub mod reserved_namespace;
pub use reserved_namespace::{
    BLESSED_PUBLISHER, RESERVED_MODULE_PREFIXES, RESERVED_PACKAGE_PREFIXES,
    is_reserved_module_path, reserved_package_prefix_of, reserved_prefix_of,
};

/// Classification of a kernel variant by which compiler / runtime subsystem
/// owns its emission.
#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
pub enum KernelClass {
    /// String, Char, Math, List, Maybe, Result, Dict, Set, Bytes, Encoding,
    /// Json*, Crypto, Uuid, Jwt, Task combinators, Io, Time (non-TEA),
    /// System, Random, File, Http — everything that does not belong to a
    /// specialised subsystem.
    Pure,
    /// `Ipe.Db` / `Db.Decode` kernels.
    Db,
    /// `Ipe.Http.Server` / Middleware / `RateLimit` kernels.
    Server,
    /// `Cmd` / `Sub` / `Time.every` TEA wiring kernels, including reserved
    /// pub/sub variants.
    Tea,
    /// `Ipe.Ui` / `Ipe.Html` element and attribute builders.
    Ui,
    /// `Ipe.Web` app-entry kernels.
    Web,
    /// Terminal rendering family — the `Tui.tea` / `Cli.tea` app-entry kernels
    /// and their `onKey` / `onLine` companions.
    Terminal,
    /// Reserved for the FFI kernel tier.
    Ffi,
}

/// A conditionally-vendored runtime feature-module that a kernel's emitted
/// symbol lives in but whose emit-`class` does NOT already pull in.
///
/// The backend trims the emitted `ipe_runtime/mod.rs` to a base set and appends
/// feature-modules per `uses_*` flag. A kernel's emit [`KernelClass`] drives its
/// codegen dispatch, but is NOT the same fact as "which vendored module defines
/// the symbol I emit": `Cmd.publish` is `class = Tea` yet its `cmd_publish`
/// symbol lives in `web::pubsub`; `HttpStream.chunks` is `class = Pure` yet its
/// `sub_subscribe_stream` symbol lives in `http_stream`. When those two facts
/// diverge, the module the symbol needs must be declared independently of the
/// class — otherwise `ipe` accepts the program (exit 0) but the emitted crate
/// fails `cargo build` (E0425/E0412), the module-set SEAL breach class.
///
/// This is the SINGLE source of truth for that divergence: [`KernelFn::required_runtime_module`]
/// returns it, and the lowerer's per-program kernel scan sets the matching
/// `uses_*` flag from it. A kernel whose symbol lives in the module its class
/// already pulls in returns `None` — no second table to keep in sync.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RuntimeModule {
    /// The `web` feature-module (`ipe_runtime::web::*`, incl. `pubsub`).
    /// Declared by the `uses_web` `mod.rs` append.
    Web,
    /// The `server` feature-module set (`ipe_runtime::server` +
    /// `server_stream` + `http_stream`). Declared by the `uses_server` append.
    Server,
    /// The `cache` feature-module (`ipe_runtime::cache`, whose `cache_*`
    /// functions, `CacheCfg` / `CacheStats` structs, and `IpeCacheHandle` enum
    /// the emitted code references). Declared by the `uses_cache` append.
    Cache,
    /// The `random` feature-module (`ipe_runtime::random`, whose `random_*`
    /// draw functions the emitted code references). Declared by the `uses_random`
    /// append.
    Random,
}

/// The event-payload shape of a `Ipe.Html.Events` builder.
///
/// Drives both the constrain scheme (the argument type) and the backend emit
/// arm (which `html::Event` variant to construct). Making the shape an ADT —
/// rather than re-deriving it from the kernel name at each site — keeps the
/// scheme and the emit in lockstep and makes an unhandled shape a
/// non-exhaustive-match error.
#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
pub enum HtmlEventShape {
    /// Zero wire args — the `Msg` dispatches as-is. `msg -> Attribute msg`.
    /// Constructs `Event::OnMsg(name, msg)`.
    Msg,
    /// Value-carrying — the handler receives the input string.
    /// `(String -> msg) -> Attribute msg`. Constructs `Event::OnString`.
    String,
    /// Checkbox state — the handler receives the checked bool.
    /// `(Bool -> msg) -> Attribute msg`. Constructs `Event::OnBool`.
    Bool,
    /// Heterogeneous payload whose handler type is DECOUPLED from `msg`
    /// (`onSubmit`: `a -> Attribute msg`). `msg`/the payload type stay free at
    /// the Ipê/HM level only; the codegen-side runtime constructor
    /// (`html_on_raw_`) now builds `Event::OnForm` with the concrete payload
    /// type recovered via Rust generic inference — never `Arc<dyn Any>` at
    /// runtime.
    Raw,
}

/// Per-variant metadata returned by [`StdlibKernel::decl`].
///
/// All fields are `'static` — the struct is `Copy` and can be embedded in
/// `const` contexts.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct StdlibDecl {
    /// The canonical qualifier used in the canon `QUALIFIERS` table
    /// (e.g. `"String"`, `"Math"`).
    ///
    /// Qualifiers starting with `'_'` are internal or not-yet-registered and
    /// are excluded from the canon-equality tripwire test.
    pub qualifier: &'static str,
    /// The canonical function name (e.g. `"fromInt"`, `"pi"`).
    pub name: &'static str,
    /// Ipê-level arity: number of arguments before the result.
    pub arity: u8,
    /// Which subsystem owns emission of this kernel.
    pub class: KernelClass,
    /// Name of the Rust runtime symbol that implements this kernel.
    ///
    /// This field is the single source of truth for the emitted symbol.
    /// It is copied verbatim into [`KernelDef::runtime_fn`] at construction.
    /// `ipe_backend_rust::naming::kernel_name` is then a zero-cost projection
    /// that reads `k.def().runtime_fn` — pinned equal to this field for every
    /// kernel by the `kernel_name_delegates_to_def_runtime_fn` test in that
    /// crate. (`ipe_kernels` is a leaf crate and may not depend on the backend,
    /// so the delegation flows from kernel → backend, never the reverse.)
    pub emit: &'static str,
    /// Whether [`Self::emit`] takes the first two arguments in Ipê order or swapped.
    pub arg_order: ArgOrder,
}

/// The order in which a kernel's runtime function takes its Ipê arguments.
///
/// Declared on every registry row beside the runtime symbol, with no default, so
/// a kernel whose runtime signature diverges from its Ipê signature cannot be
/// added without saying so. The build asserts every [`Self::ContainerFirst`] row
/// is an arity-2 kernel whose Ipê scheme takes a function first
/// ([`container_first_kernels_take_a_function_first`]); the runtime crate's
/// symbol-resolution test checks each declaration against the runtime
/// function's parameter list.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ArgOrder {
    /// The runtime function takes the arguments in the Ipê call order.
    IpeOrder,
    /// The runtime function takes the container first and the function second.
    ///
    /// Ipê's `Maybe.map f m` is `ipe_maybe_map(m, f)` in the runtime: the backend
    /// reverses the rendered arguments, and every lowering analysis that orders
    /// uses (the last-use clone rewrite, the fn-value move walk) visits the
    /// arguments in that same reversed order, so the container's reads come
    /// before the function's captures in both.
    ContainerFirst,
}

/// The app surface a program's entry `main` pins.
///
/// Each TEA surface runs its own loop and owns its own `Cmd` / `Sub` import path
/// (`Ipe.Tea.<Surface>.{Cmd,Sub}`). The shared `Ipe.Tea.Terminal.{Cmd,Sub}`
/// re-export names no surface; it serves both terminal surfaces. `Script` is a
/// `main` that heads on no app entry.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum AppSurface {
    /// `Web.tea` / `Web.appRouted` / `Web.appWith` / `Web.embed`.
    Web,
    /// A `Web` app delivered to a desktop webview host.
    WebView,
    /// `Tui.tea` — the full-screen terminal loop.
    Tui,
    /// `Cli.tea` — the line-oriented terminal loop.
    Cli,
    /// `Worker.tea` — the view-less loop.
    Worker,
    /// A plain `main : Task Error ()`.
    Script,
}

impl AppSurface {
    /// The surface's segment in its `Ipe.Tea.<Surface>` import path.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Web => "Web",
            Self::WebView => "WebView",
            Self::Tui => "Tui",
            Self::Cli => "Cli",
            Self::Worker => "Worker",
            Self::Script => "Script",
        }
    }

    /// The app surface an `Ipe.Tea.<segment>` path segment names.
    ///
    /// `Terminal` is the shared terminal re-export, not a surface, so it (and any
    /// unrecognised segment) yields `None`.
    #[must_use]
    pub fn from_segment(segment: &str) -> Option<Self> {
        match segment {
            "Web" => Some(Self::Web),
            "WebView" => Some(Self::WebView),
            "Tui" => Some(Self::Tui),
            "Cli" => Some(Self::Cli),
            "Worker" => Some(Self::Worker),
            _ => None,
        }
    }

    /// Whether an app on this surface may import `Ipe.Tea.<segment>.{Cmd,Sub}`.
    ///
    /// Only its own surface's modules qualify, plus the shared
    /// `Ipe.Tea.Terminal.{Cmd,Sub}` for either terminal surface.
    #[must_use]
    pub fn admits_cmd_sub_of(self, segment: &str) -> bool {
        Self::from_segment(segment).map_or_else(
            || segment == "Terminal" && matches!(self, Self::Tui | Self::Cli),
            |imported| imported == self,
        )
    }
}

/// A reference to the HM type scheme of a kernel, without carrying the scheme
/// itself.
///
/// The scheme cannot be a `'static` value: it is built from interned `Symbol`s
/// that exist only after the `Interner` runs, and some schemes are
/// row-polymorphic (fresh unification vars). So a [`KernelDef`] identifies its
/// scheme by KEY — the kernel variant itself — and the scheme builder
/// (`ipe_types::constrain`, where the `Interner`/`Builtins`/`UnionFind` live)
/// resolves the key to a concrete `Ty`. Keeping the key as the variant means the
/// row binds the scheme without `ipe_kernels` gaining a `types` dependency.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SchemeKey(pub StdlibKernel);

/// A built-in type constructor named structurally, by tag rather than by an
/// interned `Symbol`.
///
/// A [`TyShape`] cannot reference `ipe_types::Ty`'s interned `Symbol`s — those
/// exist only after the `Interner` runs, and `ipe_kernels` is a leaf crate that
/// must not depend on `ipe_types`. So a shape names each built-in constructor by
/// this `'static` tag, and the single interpreter in `ipe_types` resolves the
/// tag against its `Builtins` symbol cache.
///
/// Only the tags a structural kernel scheme references are listed; a scheme that
/// needs another built-in adds its tag here and an arm in the `ipe_types`
/// interpreter that resolves it.
///
/// Both nullary primitives (`Int`, `Bool`, …, an empty argument slice) and the
/// parametric built-in constructors a polymorphic scheme applies to type
/// arguments (`List a`, `Maybe a`) are named here; the arity is carried by the
/// argument slice of the [`TyShape::Con`] that references the tag, not by the
/// tag itself.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BuiltinTag {
    /// `Int` — the signed-integer primitive.
    Int,
    /// `Float` — the double-precision primitive.
    Float,
    /// `Bool` — the boolean primitive.
    Bool,
    /// `String` — the UTF-8 string primitive.
    String,
    /// `Char` — the Unicode-scalar primitive.
    Char,
    /// `Bytes` — the opaque byte-buffer primitive.
    Bytes,
    /// `List` — the built-in sequence constructor, applied to one element type.
    List,
    /// `Maybe` — the built-in optional constructor, applied to one payload type.
    Maybe,
    /// `Result` — the built-in fallible constructor, applied to its error and
    /// success payload types (`Result e a`).
    Result,
    /// `Set` — the built-in ordered-set constructor, applied to one element type.
    Set,
    /// `Dict` — the built-in ordered-map constructor, applied to its key and
    /// value types (`Dict k v`).
    Dict,
    /// `Order` — the nullary three-way-comparison result constructor
    /// (`LT` / `EQ` / `GT`).
    Order,
    /// `Error` — the nullary runtime `IpeError` value type (the implicit error
    /// channel of every `Task` and the payload of the `Result Error _` schemes).
    Error,
    /// `ErrorKind` — the nullary classified-error-kind union.
    ErrorKind,
    /// `ErrorDetails` — the nullary structured-error-detail union.
    ErrorDetails,
    /// `BackoffStrategy` — the four-constructor retry-strategy ADT
    /// (`Linear | LinearWithJitter | Exponential | ExponentialWithJitter`).
    BackoffStrategy,
    /// `Step` — `Ipe.Task`'s two-constructor loop step `Continue s | Done a`,
    /// applied to its state and result types.
    TaskStep,
    /// `Decimal` — the nullary fixed-point decimal value type.
    Decimal,
    /// `Task` — the effect constructor `Task a` (its error channel is the
    /// implicit `Error`), applied to its result payload type.
    Task,
    /// `Cmd` — the TEA outbound-command constructor `Cmd msg`, applied to the
    /// message type.
    Cmd,
    /// `Sub` — the TEA subscription constructor `Sub msg`, applied to the
    /// message type.
    Sub,
    /// `Topic` — the phantom publish/subscribe topic-handle constructor
    /// `Topic a`, applied to the shared payload type.
    Topic,
    /// `Decoder` — the opaque row/JSON/config decoder constructor `Decoder a`,
    /// applied to the decoded result type.
    Decoder,
    /// `Db` — the nullary opaque database-connection handle.
    Db,
    /// `SqlValue` — the nullary opaque typed SQL bind-value.
    SqlValue,
    /// `SqlField` — the nullary opaque typed SQL column-assignment value.
    SqlField,
    /// `SqlFragment` — the nullary opaque validated SQL WHERE-fragment.
    SqlFragment,
    /// `ProjectionTerm` — the typed projection-descriptor ADT for `selectNamed`.
    /// Defined in `ipe_runtime::db`; aliased into the Spine by the backend.
    ProjectionTerm,
    /// `ProjectionOperand` — companion to `ProjectionTerm` for `CoalesceTerm` operands.
    /// Defined in `ipe_runtime::db`; aliased into the Spine by the backend.
    ProjectionOperand,
    /// `Secret` — the nullary opaque sealed secret-string.
    Secret,
    /// `Path` — the nullary opaque validated filesystem path.
    Path,
    /// `Regex` — the nullary opaque compiled regular-expression handle.
    Regex,
    /// `Url` — the nullary opaque validated URL.
    Url,
    /// `Relative` — the nullary opaque validated same-origin relative reference
    /// (`Ipe.Url`'s path + optional query + optional fragment projection),
    /// distinct from the always-absolute `Url`.
    UrlRelative,
    /// `Dsn` — the nullary opaque validated database-connection descriptor.
    Dsn,
    /// `Connection` — the external-database connection handle constructor
    /// `Connection mode`, applied to its phantom access-mode tag
    /// ([`Self::ConnReadOnly`] / [`Self::ConnReadWrite`]). Distinct from the app's
    /// `Db`; the access mode is erased at emit (one concrete pool per position).
    Connection,
    /// `ReadOnly` — the nullary phantom access-mode marker for a read-only
    /// external connection. Appears only as `Connection`'s parameter; never a
    /// standalone runtime value (phantom, erased at emit).
    ConnReadOnly,
    /// `ReadWrite` — the nullary phantom access-mode marker for a mutable external
    /// connection. Appears only as `Connection`'s parameter; never a standalone
    /// runtime value (phantom, erased at emit).
    ConnReadWrite,
    /// `Setting` — the runtime-config carrier constructor `Setting shape`, applied
    /// to its phantom shape marker ([`Self::ShapeWeb`] / [`Self::ShapeWebView`] /
    /// [`Self::ShapeTerminal`], or a free type variable for a cross-cutting
    /// `Setting any`). The `shape` distinguishes a `Web`-only setting from a
    /// `Terminal`-only one at inference and is erased at emit (one concrete
    /// `ipe_runtime::app_config::Setting` per position).
    Setting,
    /// `Web` — the nullary phantom shape marker for the web shape. Appears only as
    /// [`Self::Setting`]'s argument; never a standalone runtime value (phantom,
    /// erased at emit).
    ShapeWeb,
    /// `WebView` — the nullary phantom shape marker for the webview shape. Appears
    /// only as [`Self::Setting`]'s argument; never a standalone runtime value.
    ShapeWebView,
    /// `Terminal` — the nullary phantom shape marker for the terminal shape.
    /// Appears only as [`Self::Setting`]'s argument; never a standalone value.
    ShapeTerminal,
    /// `Program` — the shape-carrier constructor `Program shape msg`, the uniform
    /// result type of every TEA entry (`Web.tea` → `Program Web msg`, `Tui.tea` →
    /// `Program Tui msg`, `Cli.tea` → `Program Cli msg`). Arity 2: the phantom
    /// `shape` tag ([`Self::ProgramShapeWeb`] / [`Self::ProgramShapeTui`] /
    /// [`Self::ProgramShapeCli`]) is compile-time only and erased at lower to the
    /// existing per-shape app leaf ([`Self::WebApp`] / [`Self::TuiApp`] /
    /// [`Self::CliApp`]); the `msg` argument is likewise erased (like `Setting
    /// shape`), so a `Program` carries no emitted runtime state of its own.
    Program,
    /// `Web` — the nullary phantom program-shape tag for the web shape. Appears
    /// only as [`Self::Program`]'s first argument; never a standalone value
    /// (phantom, erased at lower). Distinct from [`Self::ShapeWeb`], the `Setting`
    /// shape marker, though both interpret to the interned name `Web`.
    ProgramShapeWeb,
    /// `Tui` — the nullary phantom program-shape tag for the terminal-cells shape.
    /// Appears only as [`Self::Program`]'s first argument; never a standalone
    /// value (phantom, erased at lower).
    ProgramShapeTui,
    /// `Cli` — the nullary phantom program-shape tag for the terminal-lines shape.
    /// Appears only as [`Self::Program`]'s first argument; never a standalone
    /// value (phantom, erased at lower).
    ProgramShapeCli,
    /// `Worker` — the nullary phantom program-shape tag for the view-less
    /// co-located worker shape (`Ipe.Tea.Worker.tea` → `Program Worker msg`). Appears
    /// only as [`Self::Program`]'s first argument; never a standalone value
    /// (phantom, erased at lower to the opaque worker leaf). A worker renders no
    /// view and can never reach the sandboxed Spa/wasm bundle.
    ProgramShapeWorker,
    /// `HostMode` — the nullary closed host-bind ADT (`loopback` /
    /// `allInterfaces` / `envDriven`). The sole argument type of `Host.bind`; a
    /// value only ever comes from its three constructor kernels, each of which
    /// projects to the raw `Int` tag `resolve_host_bind` consumes. Making it a
    /// closed type means an out-of-range host-bind tag is a type error rather
    /// than a value the runtime must fall closed on.
    HostMode,
    /// `LogLevel` — the nullary closed log-severity ADT (`debug` / `info` /
    /// `warn` / `error`). The sole argument type of `Log.level`; each
    /// constructor projects to its raw `Int` severity tag.
    LogLevel,
    /// `CsrfMode` — the nullary closed CSRF-policy ADT (`strict` / an inherit
    /// default). The sole argument type of `Web.csrf`. It carries no disabling
    /// variant, so a setting cannot express turning CSRF off — the runtime's
    /// stricter-only monotonicity becomes an unrepresentable-at-the-type-level
    /// property.
    CsrfMode,
    /// `RevocationMode` — the nullary closed revocation-gate ADT (`Off` / `Store`).
    /// The sole argument type of `Web.withRevocation` and `Server.withRevocation`.
    /// Stricter-only monotonic: once `Store`, `Off` is a no-op; erases to `Int`.
    RevocationMode,
    /// `Locale` — the nullary opaque BCP-47 locale handle.
    Locale,
    /// `HttpMethod` — the nullary closed HTTP-method ADT.
    HttpMethod,
    /// `RedirectPolicy` — the redirect-behaviour ADT (`NoRedirects | FollowRedirects Int`).
    RedirectPolicy,
    /// `Duration` — the `Ipe.Duration.Duration` opaque non-negative time span
    /// (`Duration Int`, compiled-source), consumed by the `Http.withTimeout`
    /// kernel's typed timeout argument. Homed at `["Ipe", "Duration"]` (see
    /// `builtin_con_module`), mirroring `EmailProvider`.
    Duration,
    /// `CryptoKey` — the nullary opaque role-typed crypto key.
    CryptoKey,
    /// `CryptoMac` — the nullary opaque role-typed MAC output.
    CryptoMac,
    /// `EmailAddress` — the nullary opaque validated email address.
    EmailAddress,
    /// `Principal` — the nullary opaque authenticated subject. No Ipê
    /// constructor: a value only ever comes from the server auth middleware's
    /// mint, so it is never buildable by an Ipê term.
    Principal,
    /// `Claims` — the nullary opaque JWT claims accumulator.
    Claims,
    /// `Algorithm` — the nullary opaque JWT signing-algorithm descriptor.
    Algorithm,
    /// `Value` — the nullary opaque JSON node (`Value = any`) the
    /// `JsonEnc.*` encoders produce and consume.
    JsonValue,
    /// `StreamId` — the nullary opaque HTTP-stream registry handle.
    StreamId,
    /// `StreamWriter` — the nullary opaque server-side streaming-response
    /// writer handle.
    StreamWriter,
    /// `WsServer` — the nullary opaque per-peer WebSocket-server handle.
    WsServer,
    /// `WsServerCfg` — the nullary opaque WebSocket-server configuration.
    WsServerCfg,
    /// `ServerRequest` — the nullary opaque inbound HTTP-server request.
    ServerRequest,
    /// `ServerCookie` — the nullary opaque HTTP-server cookie.
    ServerCookie,
    /// `ServerRoute` — the nullary opaque HTTP-server route.
    ServerRoute,
    /// `AuthConfig` — the nullary opaque authed-route configuration. Built only
    /// through `Server.authConfig`; never buildable by an Ipê term directly.
    AuthConfig,
    /// `TokenSource` — the nullary opaque authed-route token-source descriptor.
    /// Built only through the `Server` token-source kernels.
    TokenSource,
    /// `Attribute` — the `Ipe.Ui` attribute constructor `Attribute msg`, applied
    /// to the message type. Empty-module (unqualified), distinct from
    /// [`Self::HtmlAttribute`], which shares the same interned `Attribute` name
    /// but carries a module path so the lowerer selects the `Html` variant.
    UiAttribute,
    /// `Attribute` — the `Ipe.Html` attribute constructor `Attribute msg`. Shares
    /// the interned `Attribute` name with [`Self::UiAttribute`] but is
    /// MODULE-QUALIFIED with the `Html` constructor symbol, so `ir_type_from_ty`
    /// disambiguation resolves it to the `Html` attribute variant that every
    /// `Ipe.Html` node kernel takes. Its interpreted `Con` carries a non-empty
    /// module path (see `builtin_con_module`).
    HtmlAttribute,
    /// `View` — the engine-tagged view carrier `View engine msg`. Arity 2: the
    /// first argument is an engine tag drawn from the CLOSED `{Web, Tui, Cli}`
    /// set (the same phantom shape tags [`Self::ProgramShapeWeb`] /
    /// [`Self::ProgramShapeTui`] / [`Self::ProgramShapeCli`] `Program` carries),
    /// the second is the message type. It is the SSOT surface for every
    /// engine's view: `View Web msg` IS the DOM view (`Element msg`), `View Tui
    /// msg` the terminal-cells view (`Screen msg`), `View Cli msg` the
    /// line-oriented view (`Lines msg`). The engine tag is phantom and erases at
    /// lower — a `View <tag> msg` lowers to the tag's existing `IrType::Ui`
    /// ctor ([`ipe_ir::UiCtor::Element`] / `Cells` / `CliLines`) — so its IR is
    /// byte-identical to the per-engine name. A cross-engine view (`View Tui
    /// msg` where `View Web msg` is expected) fails unification on the distinct
    /// engine tag; an unconstrained engine leaves the tag variable unsolved and
    /// is rejected, never defaulted.
    View,
    /// `Element` — the `Ipe.Ui` element constructor `Element msg`, applied to the
    /// message type. Retained as the canon alias `View Web msg`.
    UiElement,
    /// `Cells` — the Tui-only view type constructor `Screen msg` (exposed name).
    /// Distinct from `Element msg`; produced exclusively by `Ipe.Ui.Tui.*`
    /// builders and consumed only by `Tui.tea`'s view field. The internal tag
    /// keeps the `Cells` spelling (the rendering model); the user-facing type is
    /// `Screen`.
    Cells,
    /// `TuiAttr` — the cell-native attribute type constructor
    /// `Ipe.Ui.Tui.Attribute msg`. Distinct from the DOM `UiAttribute`:
    /// only terminal-honorable attributes inhabit it, so a DOM attribute is
    /// unnameable in a `Screen` view (a type error, never a silent drop).
    TuiAttr,
    /// `Lines` — the Cli-only line-oriented view type constructor `Lines msg`
    /// (exposed name `Lines`). Distinct from both `Element msg` and `Screen msg`;
    /// produced exclusively by `Ipe.Ui.Cli.*` builders. Line-scoped: it has
    /// no 2D geometry, so a cell-grid or DOM builder is unnameable in it.
    CliLines,
    /// `CliAttr` — the line-native attribute type constructor
    /// `Ipe.Ui.Cli.Attribute msg`. Only line-scoped styles inhabit it
    /// (bold/underline/dim/reverse/colour), so a 2D cell attribute or a DOM
    /// attribute is unnameable in a `Lines` view (a type error, never a drop).
    CliAttr,
    /// `Color` — the unified opaque colour value type, `ipe_runtime::color::Color`.
    /// The single carrier shared by every surface (`Ui`/`Html`/`Css`/`Tui`/`Cli`);
    /// produced by the `Ipe.Color` constructor/manipulation kernels.
    Color,
    /// `ColorError` — the typed parse-error channel of the string-input colour
    /// constructors (`fromHex` / `fromName`), `ipe_runtime::color::ColorError`.
    ColorError,
    /// `TermProfile` — the terminal capability profile `Color.toAnsi` targets,
    /// `ipe_runtime::color::TermProfile`. Nullary.
    TermProfile,
    /// `AnsiColor` — the terminal colour type, `ipe_runtime::color::AnsiColor`.
    /// Built by the `Ipe.Color` palette constructors (`black`…`brightWhite`,
    /// `default`, `rgb`) and yielded by `Color.toAnsi`; the argument type of the
    /// Tui and Cli `color` / `bg` builders. Nullary.
    AnsiColor,
    /// `WcagLevel` — the WCAG conformance level `Color.meetsWcag` checks against
    /// (`aa` / `aaa`), `ipe_runtime::color::WcagLevel`. Nullary.
    WcagLevel,
    /// `TextSize` — the text-size band a WCAG threshold applies to
    /// (`normalText` / `largeText`), `ipe_runtime::color::TextSize`. Nullary.
    TextSize,
    /// `Deficiency` — the colour-vision deficiency `Color.simulate` previews,
    /// `ipe_runtime::color::Deficiency`. Nullary.
    Deficiency,
    /// `CustomElement` — the JS-widget boundary constructor `CustomElement down up`,
    /// applied to its sealed down-state and up-event types. Empty-module
    /// (unqualified); an opaque handle produced only by the reserved `CustomElement.fromFile`
    /// constructor and consumed only by `CustomElement.node`. Never serialisable, never
    /// storable in a `Model` (it fails the plain-value gate like a function).
    CustomElement,
    /// `Html` — the `Html msg` constructor shared by `Ipe.Html` and the `Ipe.Ui`
    /// render entry points, applied to the message type.
    Html,
    /// `Length` — the nullary `Ipe.Ui` length value type.
    UiLength,
    /// `Color` — the nullary `Ipe.Ui` colour value type.
    UiColor,
    /// `Description` — the nullary `Ipe.Ui` semantic-description value type.
    UiDescription,
    /// `PseudoClass` — the nullary `Ipe.Ui` pseudo-class-selector value type.
    UiPseudoClass,
    /// `Label` — the `Ipe.Ui.Input` label constructor `Label msg`, applied to the
    /// message type.
    InputLabel,
    /// `Placeholder` — the `Ipe.Ui.Input` placeholder constructor `Placeholder
    /// msg`, applied to the message type.
    InputPlaceholder,
    /// `RadioOption` — the `Ipe.Ui.Input` radio-option constructor `RadioOption
    /// msg`, applied to the message type.
    InputRadioOption,
    /// `WebReq` — the opaque request handle threaded through `Web.tea`'s `init`
    /// field. Nullary.
    WebReq,
    /// `SessionHandle` — the opaque handle addressing one bounded `Ipe.Ffi.Js`
    /// session stream. Nullary. Obtained ONLY from `Js.openSession`; no Ipê
    /// constructor, so cross-handle addressing is unrepresentable. Backed by the
    /// runtime session id (`i64`).
    SessionHandle,
    /// `WebRoute` — the route descriptor `WebRoute page`, applied to the page
    /// type. Carried by the `routes` field of the `Web.tea` cfg record.
    WebRoute,
    /// `EmailProvider` — the provider handle `Email.send` takes before the
    /// `EmailMessage`. Nullary, and module-qualified with its `Ipe.Email` home
    /// (see `builtin_con_module`) so a point-free `send` reference lowers to the
    /// runtime-backed enum instead of an unhomed unknown-builtin `Con`.
    EmailProvider,
    // ── Shape opaque app-leaf type constructors ──────────────────────────────
    /// `WebApp` — opaque app handle returned by `Web.tea` / `Web.appRouted` /
    /// `Web.appWith`. Nullary; backed by `ipe_runtime::tea::WebApp` (served) or
    /// `ipe_runtime::tea::WebViewApp` (webview-native `web desktop` host).
    WebApp,
    /// `TuiApp` — opaque app handle returned by `Tui.tea`. Nullary;
    /// backed by `ipe_runtime::tea::TuiApp`.
    TuiApp,
    /// `CliApp` — opaque app handle returned by `Cli.tea`. Nullary;
    /// backed by `ipe_runtime::tea::CliApp`.
    CliApp,
    // ── Ipe.Db.Store query-algebra ADTs ──────────────────────────────────────
    // Each is homed at `["Ipe", "Db", "Store"]` (see `builtin_con_module`) so a
    // point-free reference lowers to the emitted enum, exactly as the accessor
    // query / schema / policy leaves require.
    /// `Store` — the classified queryable table `Store row`, applied to its row
    /// type. Homed at `Ipe.Db.Store`.
    DbStore,
    /// `Draft` — the unclassified table `Draft row`, applied to its row type.
    /// Homed at `Ipe.Db.Store`.
    DbDraft,
    /// `Joined` — the two-store inner-join `Joined a b`, applied to both sides'
    /// row types. Homed at `Ipe.Db.Store`.
    DbJoined,
    /// `Select` — the column-projection `Select row`, applied to the projected
    /// shape. Homed at `Ipe.Db.Store`.
    DbSelect,
    /// `Policy` — the row-security policy algebra `Policy row`, applied to its
    /// phantom row type. Homed at `Ipe.Db.Store`.
    DbPolicy,
    /// `Cond` — the typed `WHERE`-predicate `Cond row`, applied to the store's
    /// row type. Homed at `Ipe.Db.Store`.
    DbCond,
    /// `Pred` — the row-security predicate algebra `Pred row`, applied to its
    /// phantom row type. The result of the `StoreCorrelate` scheme and the
    /// lambda result the `StoreExistsIn` scheme expects. Homed at `Ipe.Db.Store`.
    DbPred,
    /// `Secured` — the classified, policy-attached table `Secured row`, applied
    /// to its row type. The first argument of the `StoreExistsIn` scheme (the
    /// referenced share store whose own read policy composes into the subquery).
    /// Homed at `Ipe.Db.Store`.
    DbSecured,
    /// `Order` — the `Ipe.Db.Store.Order` nullary sort-direction ADT
    /// (`Asc | Desc`), the second argument of `orderByLeft` / `orderByRight`.
    /// Empty-module, distinct from [`Self::Order`] (the three-way comparison
    /// result) though both interpret to the interned name `Order`.
    DbOrder,
    /// `Codec` — the `Ipe.Codec.Codec inner` codec ADT, the first parameter of
    /// the `*By` accessor query leaves. Homed at `Ipe.Codec`.
    Codec,
}

impl BuiltinTag {
    /// Whether the constructor is an opaque boxed wrapper that defers its callbacks.
    ///
    /// A `Task`, `Cmd`, `Sub`, or `Decoder` value boxes the callback it is
    /// built from rather than applying it at a fixed arity on the spot, and the
    /// decoder runtime curries its applicative pipeline (`curry1..curry10`), so
    /// an arrow-valued callback result is that pipeline's normal shape. A
    /// kernel yielding one of these carriers therefore takes no
    /// callback-result obligation ([`StdlibKernel::hof_result_vars`]).
    #[must_use]
    pub const fn is_opaque_boxed_wrapper(self) -> bool {
        matches!(self, Self::Task | Self::Cmd | Self::Sub | Self::Decoder)
    }
}

/// A `'static`, `const`-embeddable representation of a kernel's HM type scheme.
///
/// A [`KernelDef`] carries this beside the row so a kernel's scheme lives with
/// its other facts rather than in a distant `match` in `ipe_types`. `ipe_types`
/// owns the single interpreter that turns a `TyShape` back into a concrete `Ty`,
/// resolving each [`BuiltinTag`] against its interned-symbol cache.
///
/// The vocabulary encodes an arrow spine over built-in constructor applications,
/// anonymous tuples, and records (closed or open-row), with **rank-1
/// scheme-local type variables** ([`Self::Var`]).
/// A scheme var is a `'static` positional index, NOT a solver union-find var:
/// the `ipe_types` interpreter maps each index to a placeholder `Ty::Var`, and
/// generalization / instantiation with fresh solver vars happens LATER at the
/// use site (`instantiate_in`). So the interpreter touches no union-find state.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TyShape {
    /// A function arrow `arg -> result`. Nested on the right to build a spine.
    Fun(&'static Self, &'static Self),
    /// A built-in type-constructor application, named by [`BuiltinTag`] with its
    /// (possibly empty) type arguments. A nullary constructor (`Int`, `Bool`, …)
    /// carries an empty argument slice; a parametric one (`List`, `Maybe`)
    /// carries its argument shapes.
    Con(BuiltinTag, &'static [Self]),
    /// An anonymous tuple over an ordered element list, `(e0, e1, …)`. Element
    /// order is significant and preserved: the interpreter materialises the
    /// same-ordered `Ty::Tuple` a hand-built scheme's `Ty::Tuple(vec![…])`
    /// produces. A two-element slice encodes the common pair `(a, b)`.
    Tuple(&'static [Self]),
    /// A record over named fields, closed or open-row. Each field pairs a
    /// [`FieldTag`] (naming the interned field [`ipe_intern::Symbol`] the
    /// interpreter resolves against its `Builtins` cache) with the field's shape.
    /// The interpreter materialises a `Ty::Record` whose `BTreeMap` keys are the
    /// resolved field symbols — insertion into the `BTreeMap` re-sorts by symbol,
    /// so the map's key order is byte-identical to a hand-built one regardless of
    /// the declared slice order. Declared fields are kept in ascending
    /// resolved-symbol order so the byte-identity oracle can also assert order.
    Record {
        /// The named fields, each a `(FieldTag, field-shape)` pair.
        fields: &'static [(FieldTag, &'static Self)],
        /// Closed (exact field set) or open (a row variable absorbs extras).
        tail: RowTailShape,
    },
    /// The empty-tuple unit type `()`. Materialises the interpreter's `Ty::Unit`
    /// — the argument of every `() -> …` kernel and the result payload of a
    /// `Task ()` (`Task Error ()`). A leaf with no children, distinct from a
    /// zero-argument `Con` (it names no interned constructor symbol).
    Unit,
    /// A rank-1 scheme-local type variable, named by a positional index
    /// (`0` → the scheme's first variable `a`, `1` → `b`, …). Repeating the
    /// same index within one scheme denotes the SAME variable — the interpreter
    /// resolves each index to the identical placeholder `Ty::Var`, so both `a`s
    /// in `List a -> List b`'s shape share one variable. The index is the raw the
    /// interpreter puts on the placeholder `Ty::Var`.
    Var(u8),
}

/// The tail of a record [`TyShape`] — closed (exact fields) or open (a row
/// variable absorbs additional fields).
///
/// Mirrors `ipe_types::RowTail`, kept in the leaf `ipe_kernels` crate so a
/// record shape is `const`-embeddable without an `ipe_types` dependency. The
/// interpreter maps [`Self::Closed`] to `RowTail::Closed` and [`Self::Open`] to
/// `RowTail::Open(raw)` over the same scheme-local variable index space as
/// [`TyShape::Var`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RowTailShape {
    /// Exact field set — no extension variable.
    Closed,
    /// Extra fields flow into the scheme-local row variable named by this
    /// positional index (the same index space as [`TyShape::Var`]).
    Open(u8),
}

/// Whether scheme variable `var` occurs in `shape` at a position that aligns positionally with a solved type.
///
/// An arrow side, a constructor argument, and a tuple element align by
/// position; a record field is keyed by an interned symbol this leaf crate
/// cannot name, so an occurrence only under a record does not count.
#[must_use]
pub const fn shape_aligns_var(shape: &TyShape, var: u8) -> bool {
    match shape {
        TyShape::Var(v) => *v == var,
        TyShape::Fun(arg, res) => shape_aligns_var(arg, var) || shape_aligns_var(res, var),
        TyShape::Con(_, items) | TyShape::Tuple(items) => {
            let mut rest: &[TyShape] = items;
            while let Some((item, tail)) = rest.split_first() {
                if shape_aligns_var(item, var) {
                    return true;
                }
                rest = tail;
            }
            false
        }
        TyShape::Record { .. } | TyShape::Unit => false,
    }
}

/// Whether `shape` is exactly the scheme variable `var`.
const fn is_var(shape: &TyShape, var: u8) -> bool {
    matches!(shape, TyShape::Var(v) if *v == var)
}

/// Whether some shape of `items` is exactly the scheme variable `var`.
const fn items_hold_var(items: &[TyShape], var: u8) -> bool {
    let mut rest = items;
    while let Some((item, tail)) = rest.split_first() {
        if is_var(item, var) {
            return true;
        }
        rest = tail;
    }
    false
}

/// Whether some shape of `items` stores `var` ([`shape_stores_var`]).
const fn items_store_var(items: &[TyShape], var: u8) -> bool {
    let mut rest = items;
    while let Some((item, tail)) = rest.split_first() {
        if shape_stores_var(item, var) {
            return true;
        }
        rest = tail;
    }
    false
}

/// Whether argument `slot` of the builtin constructor `tag` is a STORAGE slot.
///
/// A storage slot carries a function on the `Arc` storage carrier: a `List` or
/// `Set` element and a `Dict` value. The lowerer's collection flips
/// (`normalize_record_fun_carriers`) consult this predicate, so the scheme-side
/// binding derivation and the emitted carrier read one fact. A `Dict` key, a
/// `Maybe`/`Result` payload, and every other constructor argument keep the
/// direct carrier.
#[must_use]
pub const fn storage_slot(tag: BuiltinTag, slot: usize) -> bool {
    matches!(
        (tag, slot),
        (BuiltinTag::List | BuiltinTag::Set, 0) | (BuiltinTag::Dict, 1)
    )
}

/// Whether storage slot `slot` of `tag` can hold a function at all.
///
/// A `Set` element is `Ord`-bound, which the `Arc<dyn Fn>` carrier is not, so
/// no function ever reaches a mapper through it; every other storage slot
/// ([`storage_slot`]) admits one.
#[must_use]
pub const fn slot_admits_function(tag: BuiltinTag, slot: usize) -> bool {
    storage_slot(tag, slot) && !matches!(tag, BuiltinTag::Set)
}

/// Whether scheme variable `var` sits directly in a function-admitting storage slot of `shape`, at any depth outside an arrow.
///
/// A function-admitting storage slot is a constructor slot
/// [`slot_admits_function`] names, a tuple component, or a record field: the
/// positions the lowerer carries a function on the `Arc` storage carrier and
/// that a function can actually occupy. Any other constructor argument keeps
/// the direct carrier (a `Set` element never holds a function), and an arrow's
/// sides are direct positions, so neither counts — though a storage slot
/// nested under them does.
#[must_use]
pub const fn shape_stores_var(shape: &TyShape, var: u8) -> bool {
    match shape {
        TyShape::Con(tag, items) => {
            let mut rest: &[TyShape] = items;
            let mut slot = 0;
            while let Some((item, tail)) = rest.split_first() {
                if (is_var(item, var) && slot_admits_function(*tag, slot))
                    || shape_stores_var(item, var)
                {
                    return true;
                }
                rest = tail;
                slot += 1;
            }
            false
        }
        TyShape::Tuple(items) => items_hold_var(items, var) || items_store_var(items, var),
        TyShape::Record { fields, .. } => {
            let mut rest = *fields;
            while let Some(((_, field), tail)) = rest.split_first() {
                if is_var(field, var) || shape_stores_var(field, var) {
                    return true;
                }
                rest = tail;
            }
            false
        }
        TyShape::Fun(..) | TyShape::Var(_) | TyShape::Unit => false,
    }
}

/// The `index`-th argument of the curried arrow `shape`, or `None` past its spine.
#[must_use]
pub const fn spine_arg(shape: &TyShape, index: usize) -> Option<&TyShape> {
    let mut cur = shape;
    let mut left = index;
    while let TyShape::Fun(arg, rest) = cur {
        if left == 0 {
            return Some(arg);
        }
        left -= 1;
        cur = rest;
    }
    None
}

/// Whether an argument of a kernel with scheme `shape` other than `arg`, among its first `arity`, stores `var` ([`shape_stores_var`]).
const fn var_stored_elsewhere(shape: &TyShape, arity: usize, arg: usize, var: u8) -> bool {
    let mut other = 0;
    while other < arity {
        if other != arg
            && let Some(collection) = spine_arg(shape, other)
            && shape_stores_var(collection, var)
        {
            return true;
        }
        other += 1;
    }
    false
}

/// Whether parameter `param` of the function argument `arg` of a kernel with scheme `shape` and `arity` binds a stored element.
///
/// Holds when that parameter is a bare scheme variable which another of the
/// kernel's `arity` arguments stores in a function-admitting slot
/// ([`shape_stores_var`]): the kernel
/// feeds the parameter an element read out of that argument, so the
/// parameter's carrier is the element's storage carrier. `List.map`'s `a`,
/// each list of `List.map2`, and the value of `Dict.map` qualify; the
/// `Maybe v` parameter of `Dict.update` is not bare, and a `Dict` key or `Set`
/// element never holds a function, so none of them does. The derivation reads
/// only the scheme, so every schemed higher-order kernel is covered without a
/// list to keep in sync.
#[must_use]
pub const fn mapper_param_binds_stored_element(
    shape: &TyShape,
    arity: u8,
    arg: usize,
    param: usize,
) -> bool {
    let arity = arity as usize;
    if arg >= arity {
        return false;
    }
    let Some(mapper) = spine_arg(shape, arg) else {
        return false;
    };
    if !matches!(mapper, TyShape::Fun(..)) {
        return false;
    }
    let Some(TyShape::Var(var)) = spine_arg(mapper, param) else {
        return false;
    };
    var_stored_elsewhere(shape, arity, arg, *var)
}

/// Whether some scheme variable of the mapper parameter `param` is stored, in a function-admitting slot, by an argument of the kernel other than `arg`.
///
/// Walks every variable of `param` — under an arrow, a constructor, a tuple,
/// or a record (row variable included) — against every storage slot that can
/// hold a function ([`shape_stores_var`]). A variable stored only
/// in a slot that admits no function (a `Set` element) never carries a
/// function into the mapper, so it opens no frontier.
const fn param_reads_stored(param: &TyShape, shape: &TyShape, arity: usize, arg: usize) -> bool {
    match param {
        TyShape::Var(var) => var_stored_elsewhere(shape, arity, arg, *var),
        TyShape::Fun(from, to) => {
            param_reads_stored(from, shape, arity, arg) || param_reads_stored(to, shape, arity, arg)
        }
        TyShape::Con(_, items) | TyShape::Tuple(items) => {
            let mut rest: &[TyShape] = items;
            while let Some((item, tail)) = rest.split_first() {
                if param_reads_stored(item, shape, arity, arg) {
                    return true;
                }
                rest = tail;
            }
            false
        }
        TyShape::Record { fields, tail } => {
            if let RowTailShape::Open(var) = tail
                && var_stored_elsewhere(shape, arity, arg, *var)
            {
                return true;
            }
            let mut rest = *fields;
            while let Some(((_, field), more)) = rest.split_first() {
                if param_reads_stored(field, shape, arity, arg) {
                    return true;
                }
                rest = more;
            }
            false
        }
        TyShape::Unit => false,
    }
}

/// Whether a kernel with scheme `shape` and `arity` feeds a stored element into a mapper parameter the lowerer cannot re-carrier.
///
/// The lowerer's `retype_collection_element_param` aligns exactly the
/// parameters [`mapper_param_binds_stored_element`] names. Any other mapper
/// parameter reading a function-admitting stored variable — a wrapped one
/// (`Dict.update`'s `Maybe v`) — leaves the frontier open, so the kernel must
/// refuse a function element ([`ElementCapability::MapperFrontierOpen`]). Derived from the scheme
/// and the same binding predicate the lowerer consults, so graduation to
/// `CloneOk` needs no hand-maintained list.
#[must_use]
pub const fn mapper_frontier_open(shape: &TyShape, arity: u8) -> bool {
    let wide = arity as usize;
    let mut arg = 0;
    while arg < wide {
        if let Some(mapper @ TyShape::Fun(..)) = spine_arg(shape, arg) {
            let mut param = 0;
            while let Some(read) = spine_arg(mapper, param) {
                if param_reads_stored(read, shape, wide, arg)
                    && !mapper_param_binds_stored_element(shape, arity, arg, param)
                {
                    return true;
                }
                param += 1;
            }
        }
        arg += 1;
    }
    false
}

/// A set of scheme variables that callbacks of a kernel return.
///
/// Holds variable indices below [`Self::CAPACITY`]; adding a larger one marks
/// the set overflowed, which the build rejects for every kernel
/// ([`hof_result_vars_fit`]), so no callback result is silently dropped.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CallbackResults {
    mask: u64,
    overflowed: bool,
}

impl CallbackResults {
    /// The exclusive upper bound on a representable variable index.
    pub const CAPACITY: u8 = 64;

    /// The empty set.
    pub const EMPTY: Self = Self {
        mask: 0,
        overflowed: false,
    };

    /// The set with scheme variable `var` added.
    #[must_use]
    pub const fn with(self, var: u8) -> Self {
        match 1_u64.checked_shl(var as u32) {
            Some(bit) if var < Self::CAPACITY => Self {
                mask: self.mask | bit,
                overflowed: self.overflowed,
            },
            _ => Self {
                mask: self.mask,
                overflowed: true,
            },
        }
    }

    /// Whether scheme variable `var` is in the set.
    #[must_use]
    pub const fn contains(self, var: u8) -> bool {
        match 1_u64.checked_shl(var as u32) {
            Some(bit) if var < Self::CAPACITY => self.mask & bit != 0,
            _ => false,
        }
    }

    /// Whether the set holds no variable.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.mask == 0
    }

    /// Whether a variable at or past [`Self::CAPACITY`] was added and lost.
    #[must_use]
    pub const fn overflowed(self) -> bool {
        self.overflowed
    }

    /// The variables of the set, in ascending order.
    pub fn vars(self) -> impl Iterator<Item = u8> {
        (0..Self::CAPACITY).filter(move |var| self.contains(*var))
    }
}

/// The final result of `shape` past every arrow.
const fn final_result(shape: &TyShape) -> &TyShape {
    let mut cur = shape;
    while let TyShape::Fun(_, rest) = cur {
        cur = rest;
    }
    cur
}

/// `found` extended with the variable final result of every callback in `shape`.
///
/// A function is a callback: its final result, when a bare variable, is
/// recorded, and neither its parameters nor a structured result are entered.
/// A constructor argument, a tuple element, and a record field are searched
/// for callbacks they carry (`andMap`'s `Maybe (a -> b)`).
const fn collect_callback_results(shape: &TyShape, found: CallbackResults) -> CallbackResults {
    match shape {
        TyShape::Fun(..) => match final_result(shape) {
            TyShape::Var(var) => found.with(*var),
            TyShape::Fun(..)
            | TyShape::Con(..)
            | TyShape::Tuple(_)
            | TyShape::Record { .. }
            | TyShape::Unit => found,
        },
        TyShape::Con(_, items) | TyShape::Tuple(items) => {
            let mut acc = found;
            let mut rest: &[TyShape] = items;
            while let Some((item, tail)) = rest.split_first() {
                acc = collect_callback_results(item, acc);
                rest = tail;
            }
            acc
        }
        TyShape::Record { fields, .. } => {
            let mut acc = found;
            let mut rest = *fields;
            while let Some(((_, field), tail)) = rest.split_first() {
                acc = collect_callback_results(field, acc);
                rest = tail;
            }
            acc
        }
        TyShape::Var(_) | TyShape::Unit => found,
    }
}

/// The scheme variables returned by the callbacks among the first `arity` arguments of scheme `shape`.
///
/// Each variable is the final result of a callback the kernel receives, at
/// any depth inside an argument's constructors, tuples, and records. A
/// callback whose final result is structured (`a -> Maybe b`) contributes
/// nothing: a curried callback there is already a plain type mismatch.
#[must_use]
pub const fn callback_result_vars(shape: &TyShape, arity: u8) -> CallbackResults {
    let wide = arity as usize;
    let mut found = CallbackResults::EMPTY;
    let mut arg = 0;
    while arg < wide {
        if let Some(param) = spine_arg(shape, arg) {
            found = collect_callback_results(param, found);
        }
        arg += 1;
    }
    found
}

/// The result of scheme `shape` once `arity` arguments are applied, or `None` past its spine.
#[must_use]
pub const fn applied_result(shape: &TyShape, arity: u8) -> Option<&TyShape> {
    let mut cur = shape;
    let mut left = arity;
    while left > 0 {
        let TyShape::Fun(_, rest) = cur else {
            return None;
        };
        cur = rest;
        left -= 1;
    }
    Some(cur)
}

/// Whether every kernel of `kernels` keeps each callback result representable and aligned.
///
/// No callback result may lie past [`CallbackResults::CAPACITY`], and every
/// [`StdlibKernel::hof_result_vars`] entry must occur where
/// [`shape_aligns_var`] finds it, so the lowering backstop can always read the
/// variable's instantiation from a reference's solved type.
#[must_use]
pub const fn hof_result_vars_fit(kernels: &[StdlibKernel]) -> bool {
    let mut rest = kernels;
    while let Some((kernel, tail)) = rest.split_first() {
        if let Some(shape) = kernel.scheme_shape() {
            if callback_result_vars(shape, kernel.identity().arity).overflowed() {
                return false;
            }
            let results = kernel.hof_result_vars();
            let mut var = 0;
            while var < CallbackResults::CAPACITY {
                if results.contains(var) && !shape_aligns_var(shape, var) {
                    return false;
                }
                var += 1;
            }
        }
        rest = tail;
    }
    true
}

// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if a kernel callback returns a scheme variable the callback-result set cannot hold or the lowering backstop cannot align, which would drop that callback's HOF_KERNEL_RESULT obligation [ledger #boundary]
#[allow(clippy::assertions_on_constants)] // the constant IS the tripwire
const _: () = assert!(
    hof_result_vars_fit(StdlibKernel::ALL),
    "a kernel callback returns a scheme variable past CallbackResults::CAPACITY or at no aligned position",
);

/// Whether every [`StdlibKernel::sync_obliged_scheme_vars`] entry of `kernels` aligns in its scheme.
///
/// A kernel listing a variable must carry a [`StdlibKernel::scheme_shape`] in
/// which [`shape_aligns_var`] finds that variable; otherwise the lowerer cannot
/// read the variable's instantiation at a call site.
#[must_use]
pub const fn sync_obliged_scheme_vars_are_aligned(kernels: &[StdlibKernel]) -> bool {
    let mut rest = kernels;
    while let Some((kernel, tail)) = rest.split_first() {
        let mut vars = kernel.sync_obliged_scheme_vars();
        if !vars.is_empty() {
            let Some(shape) = kernel.scheme_shape() else {
                return false;
            };
            while let Some((var, more)) = vars.split_first() {
                if !shape_aligns_var(shape, *var) {
                    return false;
                }
                vars = more;
            }
        }
        rest = tail;
    }
    true
}

// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if a `sync_obliged_scheme_vars` entry has no aligned occurrence in its kernel's scheme, the capture-`Sync` SEAL invariant [ledger #boundary]
#[allow(clippy::assertions_on_constants)] // the constant IS the tripwire
const _: () = assert!(
    sync_obliged_scheme_vars_are_aligned(StdlibKernel::ALL),
    "a kernel's sync_obliged_scheme_vars names a variable its scheme_shape does not carry at an aligned position",
);

/// How a function-typed kernel argument slot receives a function value.
///
/// A stored function (a record field, a constructor payload, a tuple component,
/// a collection element) is carried as `Arc<dyn Fn>`, which implements no `Fn`
/// trait. Every function-typed slot of a kernel scheme is [`Self::Direct`]
/// unless the backend re-wraps that argument on the `Arc` carrier itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FnSlotCarrier {
    /// The runtime parameter takes a direct `Fn` value, so a stored read is eta-converted first.
    ///
    /// The parameter is an `impl Fn`, a generic `F: Fn`, or a `Box<dyn Fn>`.
    Direct,
    /// The backend rebuilds the argument as an `Arc` callback, so a stored read passes unchanged.
    AcceptsShared,
}

/// Whether every capture-cloned handler of `kernels` sits at an [`FnSlotCarrier::AcceptsShared`] slot.
#[must_use]
pub const fn capture_cloned_handlers_accept_shared(kernels: &[StdlibKernel]) -> bool {
    let mut rest = kernels;
    while let Some((kernel, tail)) = rest.split_first() {
        if let Some(index) = kernel.capture_cloned_handler_arg()
            && !matches!(
                kernel.fn_slot_carrier(index),
                Some(FnSlotCarrier::AcceptsShared)
            )
        {
            return false;
        }
        rest = tail;
    }
    true
}

// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if a handler the backend re-wraps as an `Arc` callback is not derived as an `AcceptsShared` function slot, which would eta-convert a value the backend expects to re-wrap [ledger #boundary]
#[allow(clippy::assertions_on_constants)] // the constant IS the tripwire
const _: () = assert!(
    capture_cloned_handlers_accept_shared(StdlibKernel::ALL),
    "a kernel's capture_cloned_handler_arg is not an AcceptsShared function slot",
);

/// Whether `shape`'s final result, past every arrow, is an app carrier (a `Program` or the opaque `WebApp` leaf).
#[must_use]
pub const fn shape_yields_app(shape: &TyShape) -> bool {
    match shape {
        TyShape::Fun(_, res) => shape_yields_app(res),
        TyShape::Con(tag, _) => matches!(tag, BuiltinTag::Program | BuiltinTag::WebApp),
        TyShape::Var(_) | TyShape::Tuple(_) | TyShape::Record { .. } | TyShape::Unit => false,
    }
}

/// Whether [`StdlibKernel::is_app_entry`] holds for exactly the schemed kernels of `kernels` that yield an app carrier.
///
/// A new kernel whose scheme builds a program is thereby an app entry, so it
/// reaches the lowerer's concrete-`Model` / `Msg` gate; a kernel listed as an
/// app entry whose scheme builds no program is stale. An unschemed kernel has
/// no result to compare and is not constrained.
#[must_use]
pub const fn app_entries_match_their_schemes(kernels: &[StdlibKernel]) -> bool {
    let mut rest = kernels;
    while let Some((kernel, tail)) = rest.split_first() {
        if let Some(shape) = kernel.scheme_shape()
            && shape_yields_app(shape) != kernel.is_app_entry()
        {
            return false;
        }
        rest = tail;
    }
    true
}

// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if a kernel building a program is not registered as an app entry (so it would skip the concrete Model/Msg gate), the app-entry SEAL invariant [ledger #boundary]
#[allow(clippy::assertions_on_constants)] // the constant IS the tripwire
const _: () = assert!(
    app_entries_match_their_schemes(StdlibKernel::ALL),
    "a kernel whose scheme yields a Program / WebApp carrier must be StdlibKernel::is_app_entry, and only those",
);

/// Whether every [`ArgOrder::ContainerFirst`] kernel of `kernels` has arity 2 and a scheme taking a function then a non-function.
///
/// The backend swaps exactly the first two rendered arguments of such a kernel
/// and the lowering analyses visit them in that swapped order; the swap is only
/// the function/container exchange it claims to be when the Ipê scheme puts a
/// function first and a non-function container second.
#[must_use]
pub const fn container_first_kernels_take_a_function_first(kernels: &[StdlibKernel]) -> bool {
    let mut rest = kernels;
    while let Some((kernel, tail)) = rest.split_first() {
        if matches!(kernel.arg_order(), ArgOrder::ContainerFirst) {
            let takes_fn_then_container = matches!(
                kernel.scheme_shape(),
                Some(TyShape::Fun(TyShape::Fun(..), TyShape::Fun(container, _)))
                    if !matches!(container, TyShape::Fun(..))
            );
            if kernel.identity().arity != 2 || !takes_fn_then_container {
                return false;
            }
        }
        rest = tail;
    }
    true
}

// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if a ContainerFirst kernel is not an arity-2 function-then-container scheme, so the emitted argument swap stays the exchange the lowering analyses mirror [ledger #boundary]
#[allow(clippy::assertions_on_constants)] // the constant IS the tripwire
const _: () = assert!(
    container_first_kernels_take_a_function_first(StdlibKernel::ALL),
    "an ArgOrder::ContainerFirst kernel must have arity 2 and an Ipê scheme `(a -> b) -> container -> r`",
);

/// Whether every `CloneOk` / `MapperFrontierOpen` tag in `kernels` agrees with [`mapper_frontier_open`].
///
/// A `CloneOk` kernel must carry a scheme whose every stored-element-reading
/// mapper parameter the lowerer re-carriers, and a `MapperFrontierOpen` kernel
/// must have no scheme or an open frontier — so neither tag can be
/// hand-assigned against the derivation.
#[must_use]
pub const fn mapper_capabilities_match_their_schemes(kernels: &[StdlibKernel]) -> bool {
    let mut rest = kernels;
    while let Some((kernel, tail)) = rest.split_first() {
        let open = match kernel.scheme_shape() {
            Some(shape) => mapper_frontier_open(shape, kernel.def().arity),
            None => true,
        };
        match kernel.element_capability() {
            Some(ElementCapability::CloneOk) if open => return false,
            Some(ElementCapability::MapperFrontierOpen) if !open => return false,
            Some(_) | None => {}
        }
        rest = tail;
    }
    true
}

// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if a collection kernel is tagged CloneOk while its scheme feeds a stored element to a mapper parameter the lowerer cannot re-carrier (or MapperFrontierOpen while it can), the stored-function SEAL invariant [ledger #boundary]
#[allow(clippy::assertions_on_constants)] // the constant IS the tripwire
const _: () = assert!(
    mapper_capabilities_match_their_schemes(StdlibKernel::ALL),
    "a collection kernel's CloneOk/MapperFrontierOpen tag disagrees with mapper_frontier_open over its scheme",
);

/// A record field name, named structurally by tag rather than by an interned
/// [`ipe_intern::Symbol`].
///
/// A [`TyShape::Record`] cannot reference the interned field symbols the
/// interpreted `Ty::Record` keys use — those exist only after the
/// `Interner` runs, and `ipe_kernels` is a leaf crate. So a record shape names
/// each field by this `'static` tag, and the single interpreter in `ipe_types`
/// resolves the tag against its `Builtins` field-symbol cache, reproducing the
/// exact `BTreeMap` key the hand-built record used.
///
/// One variant per distinct field name a migrated record family uses; a field
/// symbol shared across families (e.g. `label` between the `Input` config
/// records) resolves to one tag.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FieldTag {
    // ── Ipe.Db.Migration ──
    /// `"name"`.
    MigrationName,
    /// `"sql"`.
    MigrationSql,
    // ── Http request / response / server response ──
    /// `"body"`.
    HttpBody,
    /// `"headers"`.
    HttpHeaders,
    /// `"status"`.
    HttpStatus,
    /// `"method"`.
    HttpMethod,
    /// `"url"`.
    HttpUrl,
    /// `"timeout"`.
    HttpTimeout,
    /// `"redirects"`.
    HttpRedirects,
    /// `"contentType"` — `Ipe.Http.Server.Response`.
    ServerContentType,
    // ── Csv ──
    /// `"header"`.
    CsvHeader,
    /// `"rows"`.
    CsvRows,
    // ── CacheCfg / CacheStats ──
    /// `"maxEntries"`.
    CacheMaxEntries,
    /// `"ttlMs"`.
    CacheTtlMs,
    /// `"maxBytes"`.
    CacheMaxBytes,
    /// `"hits"`.
    CacheHits,
    /// `"misses"`.
    CacheMisses,
    /// `"evictions"`.
    CacheEvictions,
    // ── WebSocketCfg (client) ──
    /// `"url"` — `WebSocketCfg`.
    WsUrl,
    /// `"headers"` — `WebSocketCfg`.
    WsHeaders,
    /// `"timeout"` — `WebSocketCfg`.
    WsTimeout,
    /// `"pingInterval"` — `WebSocketCfg`.
    WsPingInterval,
    // ── EmailMessage + nested Attachment ──
    /// `"from"`.
    EmailFrom,
    /// `"to"`.
    EmailTo,
    /// `"cc"`.
    EmailCc,
    /// `"bcc"`.
    EmailBcc,
    /// `"subject"`.
    EmailSubject,
    /// `"textBody"`.
    EmailTextBody,
    /// `"htmlBody"`.
    EmailHtmlBody,
    /// `"attachments"`.
    EmailAttachments,
    /// `"replyTo"`.
    EmailReplyTo,
    /// `"filename"` — `EmailAttachment`.
    EmailFilename,
    /// `"mimeType"` — `EmailAttachment`.
    EmailMimeType,
    /// `"content"` — `EmailAttachment`.
    EmailContent,
    // ── RetryPolicy ──
    /// `"baseMs"`.
    RetryBaseMs,
    /// `"maxAttempts"`.
    RetryMaxAttempts,
    /// `"shouldRetry"`.
    RetryShouldRetry,
    /// `"strategy"` — the `BackoffStrategy` ADT field.
    RetryStrategy,
    // ── Ui.layoutWith ──
    /// `"wrapperAttrs"`.
    LayoutWrapperAttrs,
    /// `"rootAttrs"`.
    LayoutRootAttrs,
    // ── Ui.button / shared `label` field ──
    /// `"onPress"`.
    ButtonOnPress,
    /// `"label"` — shared by `Ui.button`, `Ui.link`, and every `Input` config
    /// record.
    Label,
    // ── App-entry cfg (Web / Terminal) shared TEA fields ──
    /// `"init"`.
    AppInit,
    /// `"update"`.
    AppUpdate,
    /// `"view"`.
    AppView,
    /// `"subscriptions"`.
    AppSubscriptions,
    /// `"routes"` — `Web.tea` only.
    AppRoutes,
    /// `"notFound"` — `Web.tea` only.
    AppNotFound,
    /// `"kind"` — the `KeyEvent` record field (`Tui.Sub.onKey`).
    TerminalKeyKind,
    /// `"value"` — the `KeyEvent` record field (`Tui.Sub.onKey`).
    TerminalKeyValue,
    // ── Edge record (Ui.paddingEach / Border.widthEach) ──
    /// `"top"`.
    EdgeTop,
    /// `"right"`.
    EdgeRight,
    /// `"bottom"`.
    EdgeBottom,
    /// `"left"`.
    EdgeLeft,
    // ── Input config records ──
    /// `"onChange"`.
    InputOnChange,
    /// `"text"`.
    InputText,
    /// `"placeholder"`.
    InputPlaceholder,
    /// `"icon"`.
    InputIcon,
    /// `"checked"`.
    InputChecked,
    /// `"spellcheck"`.
    InputSpellcheck,
    /// `"value"`.
    InputValue,
    /// `"min"`.
    InputMin,
    /// `"max"`.
    InputMax,
    /// `"step"`.
    InputStep,
    /// `"options"`.
    InputOptions,
    /// `"selected"`.
    InputSelected,
    // ── Border.shadow / innerShadow ──
    /// `"offsetX"`.
    ShadowOffsetX,
    /// `"offsetY"`.
    ShadowOffsetY,
    /// `"blur"`.
    ShadowBlur,
    /// `"spread"`.
    ShadowSpread,
    /// `"color"`.
    ShadowColor,
    // ── Ui.image ──
    /// `"src"`.
    ImageSrc,
    /// `"description"`.
    ImageDescription,
    // ── Process.runWith input / output records ──
    /// `"command"` — `Process.runWith` input: the executable name/path.
    ProcessCommand,
    /// `"args"` — `Process.runWith` input: the argument vector.
    ProcessArgs,
    /// `"cwd"` — `Process.runWith` input: optional per-child working directory.
    ProcessCwd,
    /// `"env"` — `Process.runWith` input: per-child env overrides.
    ProcessEnv,
    /// `"exitCode"` — `Process.runWith` output: the child's exit status code.
    ProcessExitCode,
    /// `"stdout"` — `Process.runWith` output: the child's captured standard output.
    ProcessStdout,
    /// `"stderr"` — `Process.runWith` output: the child's captured standard error.
    ProcessStderr,
    /// `"cols"` — `Process.runInPty` input: the pty window width in columns.
    ProcessCols,
    /// `"rows"` — `Process.runInPty` input: the pty window height in rows.
    ProcessRows,
    /// `"output"` — `Process.runInPty` output: the combined stream read from the
    /// pty master until the child exits.
    ProcessOutput,
}

/// The whole kernel "row" as one descriptor.
///
/// It co-locates the facts about a single kernel that were otherwise smeared
/// across [`StdlibKernel::decl`], [`StdlibKernel::capability`], and
/// [`StdlibKernel::required_runtime_module`].
///
/// Binding the fragments to one row makes an incoherent row (a capability with
/// no scheme, an emit symbol whose runtime module is never appended) a testable
/// unit rather than a silent hole. [`StdlibKernel::def`] is the authoritative
/// source: the identity + emit fields come from the single
/// [`StdlibKernel::identity`] match, while the security and runtime-residency
/// axes are aggregated from [`StdlibKernel::capability`] and
/// [`StdlibKernel::required_runtime_module`] — each the grouped
/// single-source-of-truth for its axis. [`StdlibKernel::decl`] is a projection
/// of this row, not an independent table, so no fact has two homes and the row
/// changes no emitted output.
///
/// All non-scheme fields are `'static`/`Copy`; the scheme is carried as a
/// [`SchemeKey`] reference (see its doc).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct KernelDef {
    /// The canonical qualifier (e.g. `"Random"`), from [`StdlibDecl::qualifier`].
    pub qualifier: &'static str,
    /// The canonical source name (e.g. `"shuffle"`), from [`StdlibDecl::name`].
    pub name: &'static str,
    /// Ipê-level arity — argument count before the result, from
    /// [`StdlibDecl::arity`].
    pub arity: u8,
    /// Which subsystem owns emission, from [`StdlibDecl::class`].
    pub class: KernelClass,
    /// The Rust runtime symbol this kernel emits, from [`StdlibDecl::emit`].
    pub runtime_fn: &'static str,
    /// The order `runtime_fn` takes the arguments in, from [`StdlibDecl::arg_order`].
    pub arg_order: ArgOrder,
    /// The security capability this kernel exercises, from
    /// [`StdlibKernel::capability`]. `None` when pure.
    pub capability: Option<Capability>,
    /// The conditionally-vendored runtime module `runtime_fn` lives in when it
    /// diverges from the module `class` already pulls in, from
    /// [`StdlibKernel::required_runtime_module`]. `None` when the symbol is in
    /// the class's own module.
    pub runtime_module: Option<RuntimeModule>,
    /// A reference to this kernel's HM type scheme (see [`SchemeKey`]).
    pub scheme: SchemeKey,
    /// The structural encoding of this kernel's HM type scheme — the single
    /// source `ipe_types` interprets into the concrete `Ty` (via [`Self::scheme`]
    /// / `resolve_scheme`). `Some` for every schemed kernel; `None` ONLY for a
    /// genuinely unschemed kernel (a routed / unlowered bucket), whose caller
    /// fails closed rather than type-checks. See [`StdlibKernel::scheme_shape`].
    pub shape: Option<&'static TyShape>,
}

/// Every stdlib kernel function known to the Ipê compiler.
///
/// Variant order matches `lower.rs` `lower_callee` declaration order so that
/// the discriminant values are stable across a rename cycle.
///
/// # Registry invariant
///
/// [`StdlibKernel::ALL`] is the canonical wired-variant slice.  Every variant
/// in `ALL` has a matching entry in the canon `QUALIFIERS` table (verified by
/// the `canon_equals_registry` tripwire test in `ipe_canon`).  Variants
/// intentionally absent from `ALL` have their qualifier noted in the `decl()`
/// doc section below.
#[derive(
    Clone, Copy, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize, strum::EnumCount,
)]
pub enum StdlibKernel {
    // ── Log ─────────────────────────────────────────────────────────────────
    LogInfo,
    LogDebug,
    LogWarn,
    LogError,
    LogInfoWith,
    LogDebugWith,
    LogWarnWith,
    LogErrorWith,
    // ── String ──────────────────────────────────────────────────────────────
    StringFromInt,
    StringFromFloat,
    StringLength,
    StringIsEmpty,
    StringReverse,
    StringToUpper,
    StringToLower,
    StringCasefold,
    StringTrim,
    StringTrimStart,
    StringTrimEnd,
    StringToInt,
    StringToFloat,
    StringFromChar,
    StringFromBool,
    StringFromList,
    StringConcat,
    StringWords,
    StringLines,
    StringToList,
    StringIsEmail,
    StringIsUrl,
    StringAppend,
    StringContains,
    StringStartsWith,
    StringEndsWith,
    StringEqualFold,
    StringJoin,
    StringSplit,
    StringRepeat,
    StringDropLeft,
    StringDropRight,
    StringReplace,
    StringSlice,
    StringPadLeft,
    StringPadRight,
    // Haystack-first companions (`containsIn`/`startsWithIn`/`endsWithIn`).
    StringContainsIn,
    StringStartsWithIn,
    StringEndsWithIn,
    // Char-level navigation + fold family.
    StringLeft,
    StringRight,
    StringCons,
    StringUncons,
    StringPad,
    StringIndexes,
    StringMap,
    StringFilter,
    StringFoldl,
    StringFoldr,
    StringAny,
    StringAll,
    // ── Char ────────────────────────────────────────────────────────────────
    CharIsAlpha,
    CharIsDigit,
    CharIsLower,
    CharIsUpper,
    CharToLower,
    CharToUpper,
    CharToCode,
    CharFromCode,
    CharIsAlphaNum,
    CharIsHexDigit,
    CharIsOctDigit,
    // ── List ────────────────────────────────────────────────────────────────
    ListMap,
    ListFilter,
    ListFoldl,
    ListFoldr,
    ListLength,
    ListHead,
    ListTail,
    ListMember,
    ListRange,
    ListReverse,
    ListAppend,
    ListConcat,
    ListTake,
    ListDrop,
    ListZip,
    ListCons,
    ListIsEmpty,
    ListConcatMap,
    ListIndexedMap,
    ListAny,
    ListAll,
    ListFind,
    // ── List batch ───────────────────────────────────────────────────
    ListFilterMap,
    ListSortBy,
    ListSort,
    ListSortWith,
    ListSingleton,
    ListRepeat,
    ListSum,
    ListProduct,
    ListMaximum,
    ListMinimum,
    ListUnique,
    ListIntersperse,
    ListPartition,
    ListUnzip,
    ListMap2,
    ListMap3,
    ListMap4,
    ListMap5,
    // ── Basics (core Prelude) ────────────────────────────────────────────────
    BasicsNot,
    BasicsIdentity,
    BasicsAlways,
    BasicsFst,
    BasicsSnd,
    BasicsModBy,
    /// `clamp : comparable -> comparable -> comparable -> comparable`. Carries
    /// the `Comparable a` (Ord) obligation via `constrain_var_kernel`, exactly
    /// like `Math.min` / `Math.max`.
    BasicsClamp,
    // ── Basics numerics ──────────────────────────────────────────────
    /// `negate : number -> number` — unary negation on Int or Float.
    /// Also the runtime target for the `-x` desugar (`negate x`).
    BasicsNegate,
    /// `abs : number -> number` — absolute value on Int or Float.
    BasicsAbs,
    /// `sqrt : Float -> Float` — square root (Float-only, matches Elm).
    BasicsSqrt,
    /// `min : comparable -> comparable -> comparable` — Basics.min.
    BasicsMin,
    /// `max : comparable -> comparable -> comparable` — Basics.max.
    BasicsMax,
    /// `compare : comparable -> comparable -> Order` — three-way comparison.
    ///
    /// Returns `LT` / `EQ` / `GT` (a typed Rust enum on the Rust backend;
    /// `-1 / 0 / 1` int — sanctioned divergence).
    /// The `comparable` (`Ord`) constraint is enforced via `constrain_var_kernel`.
    BasicsCompare,
    // ── end Basics numerics ──────────────────────────────────────────
    // ── Error (Ipe.Error — minimal `Error = String` slice) ─────────
    // Message-carrying constructors: `String -> Error`. With `IpeError = String`
    // the message IS the error value, so all eight collapse to one identity
    // runtime symbol (`ipe_error_from_message`); the distinct Ipê-level names are
    // preserved for the rich-ADT upgrade.
    ErrorUnexpected,
    ErrorInvalidInput,
    ErrorIo,
    ErrorNetwork,
    ErrorFfi,
    ErrorDecode,
    ErrorConflict,
    ErrorUnavailable,
    // Nullary constructors: `Error` (a canonical message string).
    ErrorTimeout,
    ErrorNotFound,
    ErrorPermissionDenied,
    // Render: `Error -> String` (reuses the `errorToString` runtime).
    ErrorToString,
    // Modifier: `String -> Error -> Error` (replace the message).
    ErrorWithMessage,
    // Classification: `Error -> Bool` (kind ∈ {Timeout, Network, Unavailable}).
    ErrorIsRetryable,
    // Modifier: `ErrorDetails -> Error -> Error`
    // (attaches the `ErrorDetails` union to `ErrorInfo.details`).
    ErrorWithDetails,
    // Inspectors: extract the kind (`Error -> ErrorKind`), the bare message
    // (`Error -> String`), and a kind's stable label (`ErrorKind -> String`).
    ErrorKind,
    ErrorMessage,
    ErrorKindName,
    // ── CssSafety (Ipe.CssSafety — Ipe.Css leaf security kernels) ───
    // The FOUR primitive leaf shims over the audited `css_safety` policy that the
    // compiled-source `Ipe.Css` funnels every free-string entry through (PARSE,
    // DON'T VALIDATE). `safeValue`/`safePropName`/`safeSelector` are the
    // `String -> Maybe String` parsers (`None` => the Ipê side drops the
    // declaration/rule); `stripStyleClose` is the `String -> String` breakout
    // floor for a raw `<style>` body.
    CssSafetySafeValue,
    CssSafetySafePropName,
    CssSafetySafeSelector,
    CssSafetyStripStyleClose,
    // `sanitizeRawBody : String -> Maybe String` — the authoritative gate for a
    // raw `<style>`-body fragment (`Css.raw` / `Css.keyframes`). Runs the audited
    // `css_safety` raw-body policy (`css_unescape` normalization + whitespace
    // strip), so a CSS-escaped `@import`/script-sink payload a substring check
    // misses is dropped. `Nothing` => the Ipê side drops the rule.
    CssSafetySanitizeRawBody,
    // ── Maybe ───────────────────────────────────────────────────────────────
    MaybeWithDefault,
    MaybeMap,
    MaybeAndThen,
    /// `Maybe.map2` .. `Maybe.map5` — apply an N-ary function across N `Maybe`s;
    /// the first `Nothing` short-circuits.
    MaybeMap2,
    MaybeMap3,
    MaybeMap4,
    MaybeMap5,
    /// `Maybe.andMap : Maybe a -> Maybe (a -> b) -> Maybe b`.
    MaybeAndMap,
    /// `Maybe.combine : List (Maybe a) -> Maybe (List a)`.
    MaybeCombine,
    /// `Maybe.isJust : Maybe a -> Bool`.
    MaybeIsJust,
    /// `Maybe.isNothing : Maybe a -> Bool`.
    MaybeIsNothing,
    // ── Result ──────────────────────────────────────────────────────────────
    ResultWithDefault,
    ResultMap,
    ResultAndThen,
    ResultMapError,
    /// `Result.map2` .. `Result.map5` — apply an N-ary function across N
    /// `Result`s over a shared error channel; the first `Err` short-circuits.
    ResultMap2,
    ResultMap3,
    ResultMap4,
    ResultMap5,
    /// `Result.andMap : Result e a -> Result e (a -> b) -> Result e b`.
    ResultAndMap,
    /// `Result.combine : List (Result e a) -> Result e (List a)`.
    ResultCombine,
    /// `Result.traverse : (a -> Result e b) -> List a -> Result e (List b)`
    /// — one-pass map+collect; first `Err` short-circuits.
    ResultTraverse,
    /// `Result.toMaybe : Result e a -> Maybe a` — `Ok`→`Just`, `Err`→`Nothing`.
    ResultToMaybe,
    /// `Result.fromMaybe : e -> Maybe a -> Result e a` — `Just`→`Ok`,
    /// `Nothing`→`Err err`.
    ResultFromMaybe,
    /// Internal: `Result.withDefault`-style defaulting used during lowering.
    /// Qualifier `"_internal_"` — not registered in the canon `QUALIFIERS`
    /// table and excluded from the tripwire test.
    ResultOkDefault,
    /// Internal: the `{{expr}}` string-interpolation renderer.
    ///
    /// Qualifier `"_internal_"` — no surface binding; canon inserts it around
    /// every interpolated chunk, and its argument carries the interpolable
    /// obligation (exactly `String` / `Int` / `Float` / `Bool` / `Char`).
    Interpolate,
    // ── Math ────────────────────────────────────────────────────────────────
    MathMin,
    MathMax,
    MathPi,
    MathE,
    MathPhi,
    MathSqrt2,
    MathInf,
    MathNan,
    MathIsNaN,
    MathAbs,
    MathSqrt,
    MathCbrt,
    MathExp,
    MathExp2,
    MathLog,
    MathLog2,
    MathLog10,
    MathSin,
    MathCos,
    MathTan,
    MathAsin,
    MathAcos,
    MathAtan,
    MathSinh,
    MathCosh,
    MathTanh,
    MathAsinh,
    MathAcosh,
    MathAtanh,
    MathFloor,
    MathCeil,
    MathRound,
    MathTrunc,
    MathPow,
    MathHypot,
    MathAtan2,
    MathMod,
    MathRemainder,
    // ── Bitwise ───────────────────────────────────────────────────────────────
    BitwiseAnd,
    BitwiseOr,
    BitwiseXor,
    BitwiseComplement,
    BitwiseShiftLeftBy,
    BitwiseShiftRightBy,
    BitwiseShiftRightZfBy,
    // ── Random seeded (deterministic Generator primitives) ────────────────────
    /// `Random.seededIntRaw : Int -> Int -> Int -> (Int, Int)` — pure seeded
    /// draw, `(value, nextSeed)`. Backs the `Ipe.Random.Generator` `int` primitive.
    RandomSeededInt,
    /// `Random.seededFloatRaw : Int -> (Float, Int)` — pure seeded unit draw in
    /// `[0, 1)`, `(value, nextSeed)`. Backs the Generator `float` primitive.
    RandomSeededFloat,
    /// `Random.seededChoiceRaw : Int -> List a -> (Maybe a, Int)` — pure seeded
    /// element pick, `(choice, nextSeed)`; `Nothing` only for an empty list.
    /// Backs the `Ipe.Random` `seededChoice` wrapper.
    RandomSeededChoice,
    // ── Dict ────────────────────────────────────────────────────────────────
    DictEmpty,
    DictIsEmpty,
    DictSize,
    DictKeys,
    DictValues,
    DictToList,
    DictFromList,
    DictGet,
    DictMember,
    DictRemove,
    DictUnion,
    DictMap,
    DictInsert,
    DictFoldl,
    DictSingleton,
    DictFoldr,
    DictFilter,
    DictPartition,
    DictIntersect,
    DictDiff,
    DictUpdate,
    // ── Set ─────────────────────────────────────────────────────────────────
    SetEmpty,
    SetSize,
    SetToList,
    SetFromList,
    SetMember,
    SetInsert,
    SetRemove,
    SetUnion,
    SetIntersect,
    SetDiff,
    SetIsEmpty,
    SetSingleton,
    SetFoldl,
    SetFoldr,
    SetMap,
    SetFilter,
    SetPartition,
    // ── Bytes ───────────────────────────────────────────────────────────────
    BytesEmpty,
    BytesLength,
    BytesIsEmpty,
    BytesFromString,
    BytesToString,
    BytesFromHex,
    BytesToHex,
    BytesFromBase64,
    BytesToBase64,
    BytesAppend,
    BytesSlice,
    // ── Encoding ────────────────────────────────────────────────────────────
    EncodingBase64Encode,
    EncodingBase64Decode,
    EncodingUrlEncode,
    EncodingUrlDecode,
    EncodingPercentDecode,
    EncodingHexEncode,
    EncodingHexDecode,
    // ── Json.Encode ─────────────────────────────────────────────────────────
    JsonEncString,
    JsonEncInt,
    JsonEncFloat,
    JsonEncBool,
    JsonEncNull,
    JsonEncList,
    JsonEncObject,
    JsonEncEncode,
    // ── Json.Decode ─────────────────────────────────────────────────────────
    JsonDecString,
    JsonDecInt,
    JsonDecFloat,
    JsonDecBool,
    JsonDecValue,
    JsonDecDecodeString,
    JsonDecDecodeValue,
    JsonDecField,
    JsonDecAt,
    JsonDecIndex,
    JsonDecList,
    JsonDecNullable,
    JsonDecMap,
    JsonDecAndThen,
    JsonDecSucceed,
    JsonDecFail,
    JsonDecOneOf,
    JsonDecMap2,
    JsonDecMap3,
    JsonDecMap4,
    // ── Json.Decode.Pipeline ────────────────────────────────────────────────
    JsonDecPRequired,
    JsonDecPOptional,
    JsonDecPCustom,
    JsonDecPRequiredAt,
    // ── Crypto ──────────────────────────────────────────────────────────────
    CryptoSha256,
    CryptoSha512,
    CryptoSha1,
    CryptoMd5,
    CryptoRsaSha256Sign,
    CryptoRsaSha256Verify,
    CryptoConstantTimeEqual,
    CryptoAesGcmEncrypt,
    CryptoAesGcmDecrypt,
    CryptoChacha20Encrypt,
    CryptoChacha20Decrypt,
    CryptoAesKeyFromPassword,
    CryptoChachaKeyFromPassword,
    CryptoRandomBytes,
    CryptoRandomToken,
    // ── Uuid ────────────────────────────────────────────────────────────────
    UuidV4,
    UuidV7,
    UuidParse,
    // ── Jwt ─────────────────────────────────────────────────────────────────
    JwtEncodeHs256,
    JwtDecodeHs256,
    JwtEncodeRs256,
    JwtDecodeRs256,
    // ── Jwt builder API ─────────────────────────────────────────
    /// `Jwt.claims` — arity 0; returns an empty `Claims` accumulator.
    JwtClaims,
    /// `Jwt.hs256 : String -> Algorithm` — builds an HS256 algorithm descriptor.
    JwtHs256,
    /// `Jwt.rs256 : String -> Algorithm` — builds an RS256 algorithm descriptor.
    JwtRs256,
    /// `Jwt.subject : String -> Claims -> Claims` — sets the `sub` claim.
    JwtSubject,
    /// `Jwt.issuer : String -> Claims -> Claims` — sets the `iss` claim.
    JwtIssuer,
    /// `Jwt.audience : String -> Claims -> Claims` — sets the `aud` claim.
    JwtAudience,
    /// `Jwt.expiresAt : Int -> Claims -> Claims` — sets the `exp` claim (Unix ms).
    JwtExpiresAt,
    /// `Jwt.notBefore : Int -> Claims -> Claims` — sets the `nbf` claim (Unix ms).
    JwtNotBefore,
    /// `Jwt.issuedAt : Int -> Claims -> Claims` — sets the `iat` claim (Unix ms).
    JwtIssuedAt,
    /// `Jwt.jwtId : String -> Claims -> Claims` — sets the `jti` claim.
    JwtJwtId,
    /// `Jwt.withClaim : String -> JsonEnc.Value -> Claims -> Claims` — adds an arbitrary claim.
    JwtWithClaim,
    /// `Jwt.encode : Algorithm -> Claims -> Result Error String` — signs the claims.
    JwtEncode,
    /// `Jwt.decode : Algorithm -> String -> Result Error Claims` — verifies and decodes.
    JwtDecode,
    // ── Task combinators ────────────────────────────────────────────────────
    TaskSucceed,
    TaskFail,
    TaskMap,
    /// `Task.map2`..`Task.map5` — combine 2..5 independent tasks with an N-ary
    /// function; effects run in argument order, first `Err` short-circuits.
    TaskMap2,
    TaskMap3,
    TaskMap4,
    TaskMap5,
    /// `Task.attempt : (Result Error a -> msg) -> Task Error a -> Cmd msg` —
    /// bridge a `Task` into a `Cmd`, mapping the settled `Result` to a message.
    /// Emits the runtime `cmd_perform` (arg order swapped from `Cmd.perform`).
    TaskAttempt,
    TaskAndThen,
    TaskMapError,
    TaskOnError,
    TaskFromResult,
    TaskAndThenResult,
    TaskSequence,
    TaskParallel,
    TaskRun,
    /// `Task.perform` — 1-arg legacy alias of `Task.run`; both map to
    /// `task_run` at the runtime boundary.
    TaskPerform,
    /// `Task.lazy : (() -> Task e a) -> Task e a` — deferred task creation.
    TaskLazy,
    /// `Task.loop : Int -> s -> (s -> Task Error (Step s a)) -> Task Error a`.
    ///
    /// Runs a step from an initial state until it returns `Done`, at most the
    /// ceiling's number of times, at constant stack depth (runtime `task_loop`).
    TaskLoop,
    // ── Task retry surface (retryWith) ──────────────────────────────────────
    /// `Task.retryWith : RetryPolicy Error -> Task Error a -> Task Error a`
    /// Runs the task retrying per policy on failure.
    TaskRetryWith,
    /// `Task.linearBackoff : Int -> Int -> RetryPolicy e`
    /// Constant-delay policy; strategy=Linear.
    TaskLinearBackoff,
    /// `Task.exponentialBackoff : Int -> Int -> RetryPolicy e`
    /// Exponential back-off policy; strategy=Exponential.
    TaskExponentialBackoff,
    /// `Task.withJitter : RetryPolicy e -> RetryPolicy e`
    /// Upgrades the policy's strategy to its `*WithJitter` variant.
    TaskWithJitter,
    /// `Task.retryOn : (e -> Bool) -> RetryPolicy e -> RetryPolicy e`
    /// Sets the shouldRetry predicate.
    TaskRetryOn,
    /// `Task.withRetryOn : (e -> Bool) -> RetryPolicy e -> RetryPolicy e`
    /// Alias for retryOn.
    TaskWithRetryOn,
    /// `Task.defaultRetryPolicy : RetryPolicy e`
    /// 3 attempts, 500 ms exponential with jitter, retry-all.
    TaskDefaultRetryPolicy,
    /// `Task.withMaxAttempts : Int -> RetryPolicy e -> RetryPolicy e`
    TaskWithMaxAttempts,
    /// `Task.withBaseMs : Int -> RetryPolicy e -> RetryPolicy e`
    TaskWithBaseMs,
    // ── Io ──────────────────────────────────────────────────────────────────
    IoReadLine,
    /// `Io.readSecret : String -> Task Error Secret` — write a prompt, then read
    /// one line from stdin with terminal echo suppressed (a password read). The
    /// prior terminal mode is always restored, even on error. On a non-tty stdin
    /// this degrades to a plain line read (no echo state to toggle). The line is
    /// returned as an opaque sealed `Secret`, not a bare `String`: the plaintext
    /// is reachable only through the scoped `Secret.use` / `Secret.reveal` API, so
    /// a freshly-read secret cannot flow into a log/error/serialization by default.
    IoReadSecret,
    IoWriteStdout,
    IoWriteStderr,
    /// `Io.println : String -> Task Error ()` — write message + newline to stdout.
    IoPrintln,
    /// `Io.eprintln : String -> Task Error ()` — write message + newline to stderr.
    IoEprintln,
    // ── Debug (development-only) ──────────────────────────────────────────────
    /// `Debug.log : String -> a -> a` — print `"label: value"` to stderr, return
    /// the value unchanged. The one deliberate impure escape hatch; a production
    /// build (`ipe release`) rejects any use (IPE-L0140).
    DebugLog,
    /// `Debug.todo : String -> a` — typed unfinished-code marker. Compiles in
    /// development so the finished branches can run; reaching it at runtime aborts
    /// via the Error path (`TODO at <location>: <note>`) with a non-zero exit.
    /// Never returns a value of `a` — the `!` return makes it diverging. A
    /// production build (`ipe release`) rejects any use (IPE-L0140).
    DebugTodo,
    /// `Debug.explain : Attribute msg` — draw visible outlines on an element and
    /// all its descendants (box bounds vs padding, distinct colours). Never
    /// changes layout. Applies to the `Web` shape only; a production build
    /// (`ipe release`) rejects any use (IPE-L0140).
    DebugExplain,
    // ── Time (non-TEA) ──────────────────────────────────────────────────────
    TimeNow,
    TimeSleep,
    TimeUnixMillis,
    TimeTimeString,
    // `Ipe.Time` pure calendar helpers (no I/O). Reference:
    // `Ffi.callPure "Time_isLeapYear"` / `"Time_daysInMonth"`.
    TimeIsLeapYear,
    TimeDaysInMonth,
    // ── Time formatting + arithmetic (backed by time.rs) ──────────────────
    TimeFormat,
    TimeFormatHTTP,
    TimeFormatISO8601,
    TimeFormatRFC3339,
    TimeAddMillis,
    TimeDiffMillis,
    // ── System ──────────────────────────────────────────────────────────────
    SystemArgs,
    SystemGetenv,
    SystemGetenvOr,
    SystemGetArg,
    SystemGetenvInt,
    SystemGetenvBool,
    SystemSetenv,
    SystemUnsetenv,
    SystemCwd,
    /// `System.getcwd : () -> Task Error String` — backward-compatible alias of
    /// `System.cwd`; both resolve to the same `system_getcwd` runtime effect.
    SystemGetcwd,
    SystemLoadEnv,
    SystemExit,
    // ── Random ──────────────────────────────────────────────────────────────
    RandomInt,
    RandomFloat,
    RandomChoice,
    /// `Random.choice : List a -> Task Error (Maybe a)` — entropy-backed uniform
    /// pick over any element type; total (`Nothing` only for an empty list).
    RandomChoiceMaybe,
    /// `Random.shuffle : List a -> Task Error (List a)` — entropy-backed
    /// Fisher-Yates; returns a new list, input unchanged.
    RandomShuffle,
    /// `Random.weighted : List (Float, a) -> Task Error (Maybe a)` —
    /// entropy-backed pick proportional to non-negative weights; total.
    RandomWeighted,
    // ── File ────────────────────────────────────────────────────────────────
    FileReadFile,
    FileWriteFile,
    FileExists,
    FileRemove,
    FileMkdirAll,
    FileReadFileLimit,
    FileReadFileBytes,
    FileAppend,
    FileReadDir,
    FileIsDir,
    FileTempFile,
    FileTempDir,
    FileCopy,
    FileRename,
    FileDelete,
    /// `File.walk : Path -> Task Error (List Path)` — recursive walk,
    /// files only, lexicographic order, symlink-cycle-safe.
    FileWalk,
    /// `File.walkMatching : Path -> (Path -> Bool) -> Task Error (List Path)`
    /// — like `walk` but filtered by a synchronous predicate.
    FileWalkMatching,
    // ── Process ───────────────────────────────────────────────────────────────
    ProcessRun,
    ProcessRunWith,
    ProcessRunInPty,
    // ── Http ────────────────────────────────────────────────────────────────
    HttpGet,
    HttpPost,
    HttpRequest,
    HttpParseQuery,
    /// `Http.defaultRequest : Url -> Result Error HttpRequest` — primary
    /// request constructor over a typed `Url`; narrows the scheme to
    /// http/https at the API layer (fail-closed).
    HttpDefaultRequest,
    /// `Http.defaultRequestFromString : String -> Result Error HttpRequest` —
    /// the MARKED parse-at-the-boundary helper: one `Url.fromString` parse of a
    /// raw string, then the same fail-closed scheme narrowing.
    HttpDefaultRequestFromString,
    HttpWithMethod,
    HttpWithTimeout,
    HttpWithBody,
    HttpWithHeader,
    /// `Http.withUrl : Url -> HttpRequest -> Result Error HttpRequest` —
    /// retarget to a typed `Url`, re-narrowing the scheme (fail-closed).
    HttpWithUrl,
    /// `Http.withRedirects : RedirectPolicy -> HttpRequest -> HttpRequest` —
    /// pure builder that sets the redirect policy.
    HttpWithRedirects,
    /// `Http.methodFromString : String -> Maybe HttpMethod` — typed parse
    /// boundary; `Nothing` for unrecognised verbs.
    HttpMethodFromString,
    /// `Http.methodToString : HttpMethod -> String` — canonical uppercase string.
    HttpMethodToString,
    // ── Db ──────────────────────────────────────────────────────────────────
    DbConnect,
    DbOpen,
    DbClose,
    // ── Ipe.Db.Dsn — the typed, opaque connection descriptor (parse surface) ──
    // Each returns/consumes primitives (`Int`/`String`/`Secret`) plus the opaque
    // `Dsn`; the `Driver`/`TlsMode` ADTs are marshalled to/from small-integer tags
    // by the compiled-source `Ipe.Db.Dsn` wrapper, so no ADT crosses the kernel
    // boundary directly.
    /// `Ipe.Db.Dsn.parse : String -> Result Error Dsn` — parse a full DSN URL
    /// string into the opaque descriptor, fail-closed on every invalid shape.
    DsnParse,
    /// The typed-parts constructor `Ipe.Db.Dsn.build`, lowered to primitive args:
    /// `Int(driverTag) -> String(host) -> Int(port) -> String(db) -> String(user)
    /// -> Secret(password) -> Int(tlsTag) -> Result Error Dsn`.
    DsnBuild,
    /// `dsn_driver : Dsn -> Int` — the driver discriminant, re-tagged to the
    /// `Driver` ADT in the wrapper.
    DsnDriverTag,
    /// `dsn_host : Dsn -> String`.
    DsnHost,
    /// `dsn_port : Dsn -> Int`.
    DsnPort,
    /// `dsn_database : Dsn -> String`.
    DsnDatabase,
    /// `dsn_user : Dsn -> String`.
    DsnUser,
    /// `dsn_tls : Dsn -> Int` — the TLS-mode discriminant, re-tagged to the
    /// `TlsMode` ADT in the wrapper.
    DsnTlsTag,
    /// `Ipe.Db.Dsn.redacted : Dsn -> String` — the credential-free render.
    DsnRedacted,
    // ── Ipe.Db external Connection — connecting a parsed `Dsn` to a live,
    // read-only-by-type foreign database (distinct from the app's `Db`). ──
    /// `Ipe.Db.Dsn.open : Dsn -> Task Error (Connection ReadOnly)` — the SAFE
    /// connector. Opens an independent pool of the driver the `Dsn` names;
    /// discloses `network`. Read-only by phantom type — a write against the
    /// returned connection is a compile-time type error.
    DbConnOpen,
    /// `Ipe.Db.Dsn.close : Connection mode -> Task Error ()` — return the pool.
    /// Total and idempotent over either access mode.
    DbConnClose,
    /// `Ipe.Db.Unsafe.unsafeExecRawOn : Connection ReadWrite -> String -> Task
    /// Error Int` — verbatim SQL against an external connection. Requires
    /// `Connection ReadWrite`, so a `Connection ReadOnly` cannot type-check into
    /// it (the read-only guarantee is a compile error, not a runtime check).
    DbConnUnsafeExecRawOn,
    /// `Db.findWhereOn : Connection a -> String -> SqlFragment -> Task Error
    /// (List (Dict String String))` — read the rows matching a `Sql.*`-built
    /// fragment from an EXTERNAL connection. Mode-polymorphic in `a`: a read is
    /// available on `Connection ReadOnly` and `ReadWrite` alike. Same validated
    /// identifiers + bound params as the app-`Db` `findWhere`.
    DbConnFindWhere,
    /// `Db.queryDecodeOn : Connection a -> String -> List b -> Decoder c -> Task
    /// Error (List c)` — typed query with a per-row decoder against an EXTERNAL
    /// connection, so a foreign source of a different dialect reads through one
    /// codec. Bound-parameter-only (the safe path); mode-polymorphic in `a`.
    DbConnQueryDecode,
    /// `Db.getByIdOn : Connection a -> String -> String -> Task Error (Maybe
    /// (Dict String String))` — read a single row by id from an EXTERNAL
    /// connection; the id binds as a parameter. Mode-polymorphic in `a`.
    DbConnGetById,
    DbExecRaw,
    DbExec,
    DbQuery,
    DbQueryDecode,
    DbGetString,
    DbGetInt,
    DbGetBool,
    DbGetField,
    DbInsertRow,
    DbGetById,
    DbUpdateById,
    DbDeleteById,
    DbFindOneByField,
    DbFindManyByField,
    DbFindByConditions,
    DbInsertFields,
    DbUpdateFields,
    DbInsertFieldsReturning,
    DbWithTransaction,
    DbMigrate,
    /// `Db.defaultMigration : String -> Migration` — a Migration named with an
    /// empty SQL body.
    DbDefaultMigration,
    // ── Db.Store (accessor-typed query column) ────────────────────────────────
    /// `Store.eq : (row -> t) -> t -> Cond` — the accessor-typed equality leaf.
    /// The scheme presents its first parameter as the getter arrow `row -> t`, so
    /// an accessor literal `.field` unifies against it by ordinary inference and
    /// the comparison value's type `t` is pinned to the field's type. At lowering
    /// the accessor argument is recognised and replaced by the validated column
    /// identifier; the call becomes the `Compare OpEq name (sqlValue)` `Cond`
    /// constructor, so the audited `Cond`→`SqlFragment` path is reused unchanged.
    StoreEqCol,
    /// `Store.join : Store a -> (a -> k) -> Store b -> (b -> k) -> Joined a b` —
    /// an inner join of two stores on key equality. The two accessor arguments
    /// (`.authorId`, `.id`) name the join columns the same way `Store.eq` names a
    /// column; their result type `k` must match, so a mistyped join key is a type
    /// error. At lowering each accessor is recognised and replaced by its
    /// validated column identifier, and the call becomes the `joinNamed` stdlib
    /// helper carrying both stores and both key columns.
    StoreJoin,
    /// `Store.select : (( Cols a, Cols b ) -> row) -> Joined a b -> Select row`
    /// — project specific columns of a join. The lambda receives the two sides'
    /// column records; a field accessor on a `Cols` record is a validated column
    /// reference (a `Proj`), so the projection cannot name a column absent from
    /// the codec or carry a raw value into SQL text. At lowering the lambda is
    /// read into the ordered `(alias, column)` projection list and a per-column
    /// decoder, and the call becomes the `selectNamed` stdlib helper.
    StoreSelect,
    /// `Store.literal : t -> t` — a projection element that binds its argument
    /// as a SQL parameter (`? AS pN`) rather than naming a column. Valid only
    /// inside a `Store.select` projection lambda; recognized structurally at
    /// lowering (the argument is bound as a `SqlValue` in the SELECT, never
    /// interpolated into SQL text). An accessor-intercept placeholder: a
    /// point-free or partially-applied `literal` is a fail-closed IPE-L0146.
    StoreLiteral,
    /// `Store.upper : String -> String` — a projection-body operator that wraps
    /// a column reference in SQL `UPPER(…)`. Valid only as a direct element of a
    /// `Store.select` projection body applied to a `side.field` column reference.
    /// Recognized structurally at lowering; the column is re-validated by the
    /// runtime (defence in depth). Point-free or partial use is a fail-closed
    /// IPE-L0146.
    StoreUpper,
    /// `Store.lower : String -> String` — a projection-body operator that wraps
    /// a column reference in SQL `LOWER(…)`. Symmetric counterpart to
    /// `StoreUpper`; the same structural restrictions apply.
    StoreLower,
    /// `Store.coalesce : Projection a -> Projection a -> Projection a` — emits
    /// `COALESCE(a, b) AS pN` in the SELECT list. Both operands must be either a
    /// bare column reference (`side.field`) or a `Store.literal` value; the two
    /// arguments must share the same `Projection` type variable. Lowered inline
    /// to a `COALESCE` sentinel triple in the projection descriptor; the
    /// runtime-fn name is a never-called placeholder.
    StoreCoalesce,
    /// `Store.add : number a => a -> a -> a` — emits `(a + b) AS pN` in a
    /// projection SELECT list.  Both operands are a bare column reference
    /// (`side.field`) or a `Store.literal` value, sharing one numeric type.
    /// Lowered inline to an arithmetic term in the projection descriptor; the
    /// runtime-fn name is a never-called placeholder.
    StoreAdd,
    /// `Store.sub : number a => a -> a -> a` — emits `(a - b) AS pN`.  Same
    /// operand and numeric-type restrictions as `StoreAdd`.
    StoreSub,
    /// `Store.mul : number a => a -> a -> a` — emits `(a * b) AS pN`.  Same
    /// operand and numeric-type restrictions as `StoreAdd`.
    StoreMul,
    /// `Store.eqBy : Codec t -> (row -> t) -> t -> Cond` — the accessor-typed
    /// equality leaf for an ENUM or newtype column whose wire form is not
    /// type-derivable. The `Codec t` argument projects the comparison value to a
    /// bound `SqlValue`; the getter-arrow scheme (as `StoreEqCol`) pins the
    /// column and value types. At lowering the accessor becomes the validated
    /// column identifier and the value is bound through the codec, so the same
    /// audited `Cond`→`SqlFragment` path applies.
    StoreEqBy,
    /// `Store.neq : (row -> t) -> t -> Cond` — accessor-typed not-equal leaf.
    /// Mirrors `StoreEqCol` but emits `OpNeq` in the `Compare` constructor.
    StoreNeqCol,
    /// `Store.neqBy : Codec t -> (row -> t) -> t -> Cond` — codec twin of
    /// `StoreNeqCol`. Mirrors `StoreEqBy` with `OpNeq`.
    StoreNeqBy,
    /// `Store.gt : (row -> t) -> t -> Cond` — accessor-typed greater-than leaf.
    StoreGtCol,
    /// `Store.gtBy : Codec t -> (row -> t) -> t -> Cond` — codec twin.
    StoreGtBy,
    /// `Store.gte : (row -> t) -> t -> Cond` — accessor-typed ≥ leaf.
    StoreGteCol,
    /// `Store.gteBy : Codec t -> (row -> t) -> t -> Cond` — codec twin.
    StoreGteBy,
    /// `Store.lt : (row -> t) -> t -> Cond` — accessor-typed < leaf.
    StoreLtCol,
    /// `Store.ltBy : Codec t -> (row -> t) -> t -> Cond` — codec twin.
    StoreLtBy,
    /// `Store.lte : (row -> t) -> t -> Cond` — accessor-typed ≤ leaf.
    StoreLteCol,
    /// `Store.lteBy : Codec t -> (row -> t) -> t -> Cond` — codec twin.
    StoreLteBy,
    /// `Store.like : (row -> String) -> String -> Cond` — accessor-typed LIKE
    /// leaf. The accessor must name a `String` field; the pattern is a bound
    /// parameter (wildcards are data, never SQL text).
    StoreLike,
    /// `Store.isNull : (row -> t) -> Cond` — accessor-typed IS NULL leaf.
    /// Arity 1: only the accessor (column name), no value.
    StoreIsNull,
    /// `Store.notNull : (row -> t) -> Cond` — accessor-typed IS NOT NULL leaf.
    StoreNotNull,
    /// `Store.inList : (row -> t) -> List t -> Cond` — accessor-typed IN-list
    /// leaf for scalar fields. Each element binds as a parameter; an empty
    /// list lowers to the always-false `Cond` (`OrList []`).
    StoreInListCol,
    /// `Store.inListBy : Codec t -> (row -> t) -> List t -> Cond` — codec
    /// twin. Each element is projected through the codec; dropped on failure.
    StoreInListBy,
    // ── Db.Store column-spec builders (accessor-typed) ───────────────────────
    /// `Store.primaryKey : (row -> t) -> Store row -> Store row` — marks the
    /// accessor-named column the primary key. The intercept extracts the column
    /// name and delegates to the `primaryKeyNamed` stdlib helper.
    StorePrimaryKey,
    /// `Store.compositePrimaryKey2 : (row -> a) -> (row -> b) -> Draft row ->
    /// Draft row` — makes the two accessor-named columns one table-level
    /// primary key. The intercept extracts both column names and delegates to
    /// the `compositePrimaryKeyNamed` stdlib helper with them as a list.
    StoreCompositePrimaryKey2,
    /// `Store.compositePrimaryKey3 : (row -> a) -> (row -> b) -> (row -> c) ->
    /// Draft row -> Draft row` — the three-column form of
    /// `compositePrimaryKey2`.
    StoreCompositePrimaryKey3,
    /// `Store.serial : (row -> t) -> Store row -> Store row` — marks the
    /// accessor-named column DB-assigned (serial).
    StoreSerial,
    /// `Store.unique : (row -> t) -> Store row -> Store row` — marks the
    /// accessor-named column unique.
    StoreUnique,
    /// `Store.defaultNow : (row -> t) -> Store row -> Store row` — marks the
    /// accessor-named column DB-stamped with the current time on insert.
    StoreDefaultNow,
    /// `Store.touchOnUpdate : (row -> t) -> Store row -> Store row` — marks
    /// the accessor-named column a DB-stamped updated-at column.
    StoreTouchOnUpdate,
    /// `Store.defaultText : (row -> String) -> String -> Store row -> Store row`
    /// — gives the accessor-named column a DB-level `DEFAULT` of the text value.
    StoreDefaultText,
    /// `Store.defaultInt : (row -> Int) -> Int -> Store row -> Store row` —
    /// gives the accessor-named column a DB-level `DEFAULT` of the integer value.
    StoreDefaultInt,
    /// `Store.ownerColumn : (row -> t) -> Policy row` — a row-security policy of
    /// one owner-column rule over the accessor-named column. The intercept
    /// extracts the column name and delegates to the `ownerColumnNamed` stdlib
    /// helper.
    StoreOwnerColumn,
    /// `Store.immutable : (row -> t) -> Policy row` — a row-security policy of
    /// one immutable-column rule over the accessor-named column. The intercept
    /// extracts the column name and delegates to the `immutableNamed` helper.
    StoreImmutable,
    /// `Store.mask : (row -> t) -> Pred row -> Policy row -> Policy row` — a
    /// column-masking policy refinement: the accessor-named column is projected
    /// as `CASE WHEN (<pred>) THEN col ELSE NULL END` in every secured read, so an
    /// unauthorized row yields `Nothing` for that column. The intercept extracts
    /// the validated, snake-cased column name and delegates to the `maskNamed`
    /// stdlib helper (`maskNamed col pred policy`). An accessor-intercept
    /// placeholder; a non-nullable masked column fails closed at `secured`.
    StoreMask,
    /// `Store.correlate : (share -> t) -> (row -> t) -> Pred share` — the
    /// column=column correlation leaf of a `Store.existsIn` predicate: it equates
    /// a `share`-side column with an OUTER-`row`-side column (`shares.doc =
    /// docs.id`), the one comparison `Cond`/`matchWhere` cannot express (their RHS
    /// is always a bound value). Both accessors name validated columns pinned to
    /// their own record types by the shared `t`. Valid ONLY as the body (or an
    /// `allOf` element) of an `existsIn` lambda; the intercept reads both
    /// accessors structurally. A point-free or standalone use is a fail-closed
    /// IPE-L0149. An accessor-intercept placeholder.
    StoreCorrelate,
    /// `Store.existsIn : Secured share -> (share -> row -> Pred share) -> Pred row`
    /// — a correlated-subquery row-security predicate: the outer row is admitted
    /// when a row of the referenced `share` store satisfies both the lambda's
    /// correlation (via `Store.correlate`) AND the share store's OWN read policy
    /// (composed in, defence in depth). Lowered by a two-binder walker that reads
    /// the `\share row -> …` lambda into a `PExists` data leaf carrying the share
    /// table, the two correlation columns, and the share read policy. The share's
    /// columns and the outer row's columns are both re-validated by `secured`. An
    /// accessor-intercept placeholder.
    StoreExistsIn,
    /// `Store.orderByLeft : (a -> k) -> Order -> Joined a b -> Joined a b` —
    /// sort a join result by a column on the LEFT side (`a0`), ascending or
    /// descending. The accessor names the column (validated at lowering, the same
    /// snake-case derivation every other accessor-typed leaf uses); `Order` is
    /// `Asc | Desc`. At lowering the accessor becomes the validated column
    /// identifier and the call becomes `orderByLeftNamed`, which adds the
    /// `ORDER BY a0.col ASC|DESC` clause to the join/projection statement.
    StoreOrderByLeft,
    /// `Store.orderByRight : (b -> k) -> Order -> Joined a b -> Joined a b` —
    /// the right-side (`a1`) counterpart to `StoreOrderByLeft`. The accessor
    /// names a column on the right store; `Order` is `Asc | Desc`.
    StoreOrderByRight,
    // ── Db.Decode ───────────────────────────────────────────────────────────
    DbDecString,
    DbDecInt,
    DbDecFloat,
    DbDecBool,
    DbDecNullable,
    DbDecMap,
    DbDecAndThen,
    DbDecSucceed,
    DbDecFail,
    DbDecMap2,
    DbDecMap3,
    DbDecMap4,
    DbDecRequired,
    DbDecOptional,
    DbDecMoney,
    /// `Db.Decode.decimal : String -> Decoder Decimal` — reads a TEXT column
    /// as an exact-decimal value. Symmetric counterpart to `DbDecMoney`
    /// (which returns `Decoder (Decimal, String)`).
    DbDecDecimal,
    /// `Db.Decode.bytes : String -> Decoder (List Int)` — hex-decodes a
    /// BYTEA/BLOB column written by `SqlBytes` back to raw bytes.
    DbDecBytes,
    // ── TEA: Cmd / Sub / Time.every ─────────────────────────────────────────
    CmdNone,
    CmdBatch,
    CmdPerform,
    /// `Cmd.map` — `(a -> msg) -> Cmd a -> Cmd msg`; retags a sub-component's
    /// commands into the parent's message type.
    CmdMap,
    SubNone,
    SubBatch,
    SubEvery,
    TimeEvery,
    /// `Sub.map` — `(a -> msg) -> Sub a -> Sub msg`; the `Sub` twin of
    /// [`Self::CmdMap`].
    SubMap,
    /// `Tui.Sub.onKey` — `(KeyEvent -> msg) -> Sub msg`, key input as a subscription.
    ///
    /// Reachable only through `Ipe.Tea.Tui.Sub`, so only a `Tui.tea` app can
    /// name it.
    TuiSubOnKey,
    /// `Cli.Sub.onLine` — `(String -> msg) -> Sub msg`, line input as a subscription.
    ///
    /// Reachable only through `Ipe.Tea.Cli.Sub`, so only a `Cli.tea` app can
    /// name it.
    CliSubOnLine,
    // ── TEA: pub/sub ────────────────────────────────────────────────────────
    /// `Cmd.publish` — `"publish"` registered in canon `QUALIFIERS`.
    CmdPublish,
    /// `Cmd.publishNoEcho` — alongside `CmdPublish`.
    CmdPublishNoEcho,
    /// `Sub.subscribeTopic`.
    SubSubscribeTopic,
    /// `PubSub.publish` — reserved; absent from [`Self::ALL`] until the
    /// `"PubSub"` qualifier is added to the canon `QUALIFIERS` table.
    PubSubPublish,
    /// `PubSub.publishNoEcho` — reserved; absent from [`Self::ALL`].
    PubSubPublishNoEcho,
    /// `PubSub.topic : String -> Topic a` — constructs a typed topic handle.
    /// Emits as the identity function: `Topic a` erases to `String` at runtime.
    /// Resolved exclusively through `Kernel.kernel "PubSub_topic"` in `Ipe.PubSub`.
    PubSubTopic,
    // ── Ipe.Http.Server / Middleware / RateLimit ─────────────────────────────
    ServerGet,
    ServerPost,
    ServerPut,
    ServerDelete,
    ServerAny,
    ServerApi,
    ServerStatic,
    /// `Server.mountApp : String -> WebApp -> Route` — mount a `Web.embed`
    /// handle at a path prefix into the shared server Router. The nominal
    /// `WebApp` argument is the §9 type gate (a non-`WebApp` shape leaf is a
    /// compile error). Contributes one served route-group; the app runs on the
    /// same port as the sibling `Server.get`/`post` handlers (one listener).
    ServerMountApp,
    ServerListen,
    ServerText,
    ServerJson,
    ServerHtml,
    ServerWithStatus,
    ServerWithHeader,
    ServerRedirect,
    ServerParam,
    ServerQueryParam,
    ServerHeader,
    ServerGetCookie,
    ServerBody,
    ServerPath,
    ServerMethod,
    ServerCookieNew,
    ServerWithCookie,
    // Authed-route surface — the sole compiler path to the fail-closed
    // Principal-minting runtime middleware.
    ServerAuthConfig,
    ServerTokenBearer,
    ServerCookieToken,
    /// `Server.withRevocation : RevocationMode -> AuthConfig -> AuthConfig` — arms
    /// the per-request revocation gate on an `AuthConfig`.
    ServerWithRevocation,
    ServerGetAuthed,
    ServerPostAuthed,
    ServerPutAuthed,
    ServerDeleteAuthed,
    MiddlewareWithCors,
    MiddlewareWithLogging,
    MiddlewareWithBasicAuth,
    MiddlewareWithRateLimit,
    MiddlewareWithCsrf,
    RateLimitAllow,
    // ── Ipe.Ui / Ipe.Html render kernels ─────────────────────────────────
    UiLayout,
    UiLayoutWith,
    HtmlRender,
    HtmlEscapeText,
    HtmlEscapeAttr,
    HtmlAttrToString,
    // ── Ipe.Ui element builders ──────────────────────────────────────────
    UiNone,
    UiText,
    UiHtml,
    /// `Ui.cells : List (List Char) -> Element msg` — a raw terminal cell grid
    /// embedded as an island inside an `Ipe.Ui` view under `Tui.tea`.
    UiCells,
    /// `UiCells.none : Cells msg` — empty cell, matching `Ui.none` but returns
    /// `Cells msg`.
    UiCellsNone,
    /// `UiCells.text : String -> Cells msg` — a text leaf returning `Cells msg`.
    UiCellsText,
    /// `UiCells.el : List (Attribute msg) -> Cells msg -> Cells msg` — a single
    /// child wrapper returning `Cells msg`.
    UiCellsEl,
    /// `UiCells.row : List (Attribute msg) -> List (Cells msg) -> Cells msg` — a
    /// horizontal layout row returning `Cells msg`.
    UiCellsRow,
    /// `UiCells.column : List (Attribute msg) -> List (Cells msg) -> Cells msg` —
    /// a vertical layout column returning `Cells msg`.
    UiCellsColumn,
    /// `UiCells.cells : List (List Char) -> Cells msg` — a raw character-grid
    /// island inside a `Cells`-typed Tui view.
    UiCellsCells,
    // ── Ipe.Ui.Tui cell-native attribute builders ─────────────────────────
    /// `TuiUi.spacing : Int -> Attribute msg` — gap between children, in cells.
    TuiUiSpacing,
    /// `TuiUi.padding : Int -> Attribute msg` — inner padding, in cells.
    TuiUiPadding,
    /// `TuiUi.alignLeft : Attribute msg`
    TuiUiAlignLeft,
    /// `TuiUi.alignRight : Attribute msg`
    TuiUiAlignRight,
    /// `TuiUi.center : Attribute msg` — centre content horizontally.
    TuiUiCenter,
    /// `TuiUi.bold : Attribute msg`
    TuiUiBold,
    /// `TuiUi.underline : Attribute msg`
    TuiUiUnderline,
    /// `TuiUi.dim : Attribute msg` — faint text.
    TuiUiDim,
    /// `TuiUi.reverse : Attribute msg` — reverse video.
    TuiUiReverse,
    /// `TuiUi.color : Color -> Attribute msg` — foreground text colour.
    TuiUiColor,
    /// `TuiUi.bg : Color -> Attribute msg` — background colour.
    TuiUiBg,
    // ── Ipe.Ui.Cli line-oriented view + attribute builders ─────────────────
    /// `CliUi.none : Lines msg` — the empty line view.
    CliUiNone,
    /// `CliUi.text : String -> Lines msg` — one unstyled line.
    CliUiText,
    /// `CliUi.line : List (Attribute msg) -> String -> Lines msg` — one styled line.
    CliUiLine,
    /// `CliUi.lines : List (Lines msg) -> Lines msg` — stack lines vertically.
    CliUiLines,
    /// `CliUi.bold : Attribute msg`
    CliUiBold,
    /// `CliUi.underline : Attribute msg`
    CliUiUnderline,
    /// `CliUi.dim : Attribute msg` — faint text.
    CliUiDim,
    /// `CliUi.reverse : Attribute msg` — reverse video.
    CliUiReverse,
    /// `CliUi.color : Color -> Attribute msg` — foreground text colour.
    CliUiColor,
    /// `CliUi.bg : Color -> Attribute msg` — background colour.
    CliUiBg,
    // ── Ipe.Color terminal palette constructors (the `AnsiColor` type) ─────────
    // Internal kernel home stays `TermColor` (the reachability key
    // `TermColor_*`); the user surface is `Ipe.Color`, the return type
    // `AnsiColor`.
    /// `TermColor.black : AnsiColor`
    TermColorBlack,
    /// `TermColor.red : AnsiColor`
    TermColorRed,
    /// `TermColor.green : AnsiColor`
    TermColorGreen,
    /// `TermColor.yellow : AnsiColor`
    TermColorYellow,
    /// `TermColor.blue : AnsiColor`
    TermColorBlue,
    /// `TermColor.magenta : AnsiColor`
    TermColorMagenta,
    /// `TermColor.cyan : AnsiColor`
    TermColorCyan,
    /// `TermColor.white : AnsiColor`
    TermColorWhite,
    /// `TermColor.brightBlack : AnsiColor`
    TermColorBrightBlack,
    /// `TermColor.brightRed : AnsiColor`
    TermColorBrightRed,
    /// `TermColor.brightGreen : AnsiColor`
    TermColorBrightGreen,
    /// `TermColor.brightYellow : AnsiColor`
    TermColorBrightYellow,
    /// `TermColor.brightBlue : AnsiColor`
    TermColorBrightBlue,
    /// `TermColor.brightMagenta : AnsiColor`
    TermColorBrightMagenta,
    /// `TermColor.brightCyan : AnsiColor`
    TermColorBrightCyan,
    /// `TermColor.brightWhite : AnsiColor`
    TermColorBrightWhite,
    /// `TermColor.default : AnsiColor` — the terminal's own default colour.
    TermColorDefault,
    /// `TermColor.rgb : Int -> Int -> Int -> AnsiColor` — a 24-bit truecolour.
    TermColorRgb,
    /// `TermColor.rgba : Int -> Int -> Int -> Float -> AnsiColor` — truecolour + alpha.
    TermColorRgba,
    /// `CustomElement.node : CustomElement down up -> down -> (up -> msg) -> Element msg` —
    /// the one view node that places a typed JS custom-element widget. The
    /// `CustomElement` handle is opaque; it lowers to the shipped widget handle
    /// type and is placed in the view tree by the widget transport.
    UiWidget,
    /// `Ui.node : Description -> List (Attribute msg) -> List (Element msg) -> Element msg`
    /// — the irreducible container-element constructor. The layout builders
    /// (`el`/`row`/`column`/`wrappedRow`/`grid`) are pure Ipê over this in
    /// `Ipe/Ui.ipe`.
    UiNode,
    /// `Ui.taggedNode : String -> Description -> List (Attribute msg) -> List (Element msg) -> Element msg`
    /// — the irreducible tagged-element constructor. The flow builders
    /// (`paragraph`/`textColumn`/`form`/`input`) are pure Ipê over this.
    UiTaggedNode,
    UiButton, // (List Attr, { onPress : Maybe msg, label : Element msg }) → Element msg
    UiLink,   // (List Attr, { url : String, label : Element msg }) → Element msg
    /// `Ui.image : List Attr -> { src : String, description : String } -> Element msg`
    /// — renders `<img src=… alt=…>` (a void `TaggedNode`, no children).
    UiImage,
    // ── Ipe.Ui nearby attribute builders (absolute-positioned overlays) ──
    /// `Ui.above : Element msg -> Attribute msg`
    UiAbove,
    /// `Ui.below : Element msg -> Attribute msg`
    UiBelow,
    /// `Ui.onLeft : Element msg -> Attribute msg`
    UiOnLeft,
    /// `Ui.onRight : Element msg -> Attribute msg`
    UiOnRight,
    /// `Ui.inFront : Element msg -> Attribute msg`
    UiInFront,
    /// `Ui.behind : Element msg -> Attribute msg`
    UiBehind,
    // ── Ipe.Ui attribute builders ────────────────────────────────────────
    UiSpacing,
    UiPadding,
    UiPaddingXY,
    /// `Ui.paddingEach : { top : Int, right : Int, bottom : Int, left : Int } -> Attribute msg`
    UiPaddingEach,
    UiWidth,
    UiHeight,
    UiCenterX,
    UiCenterY,
    UiAlignLeft,
    UiAlignRight,
    UiAlignTop,
    UiAlignBottom,
    UiPointer,
    UiClip,
    /// `Ui.clipX : Attribute msg` — `AttrOverflow "clip" "visible"` (single-axis
    /// clip; Y stays truly visible, no `auto`-scrollbar promotion).
    UiClipX,
    /// `Ui.clipY : Attribute msg` — `AttrOverflow "visible" "clip"`.
    UiClipY,
    UiScrollbars,
    /// `Ui.scrollbarX : Attribute msg` — `AttrOverflow "auto" "hidden"`.
    UiScrollbarX,
    /// `Ui.scrollbarY : Attribute msg` — `AttrOverflow "hidden" "auto"`.
    UiScrollbarY,
    UiGridColumns,
    // ── Ipe.Ui Length builders ───────────────────────────────────────────
    UiPx,
    UiFill,
    UiContent,
    UiShrink,
    UiFillPortion,
    UiVh,
    UiVw,
    UiMinimum,
    UiMaximum,
    // ── Ipe.Ui Color builders ────────────────────────────────────────────
    UiRgb,
    UiRgba,
    UiWhite,
    UiBlack,
    UiTransparent,
    /// `Ui.colorCss color` — convert a `Color` to its CSS string representation.
    UiColorCss,
    // ── Background / Border / Font sub-modules ───────────────────────────
    BackgroundColor,
    BackgroundImage,
    /// `Background.linearGradient : Float -> List (Float, Color) -> Attribute msg`
    /// — renders `background-image: linear-gradient(<angle>deg, <c1> <p1>%, …);`
    /// via the existing `AttrBgGradient` runtime variant.
    BackgroundLinearGradient,
    BorderWidth,
    BorderRounded,
    BorderColor,
    BorderWidthEach, // { top : Int, right : Int, bottom : Int, left : Int } → Attribute msg
    BorderShadow, // { offsetX : Int, offsetY : Int, blur : Int, spread : Int, color : Color } → Attribute msg
    BorderGlow,   // Int → Color → Attribute msg (box-shadow, 0,0 offset + 0 spread; blur + colour)
    BorderInnerShadow, // same record as BorderShadow but INSET → Attribute msg
    FontSize,
    FontColor,
    FontFamily,
    FontBold,
    FontItalic,
    // ── Html element builders ────────────────────────────────────────────
    HtmlTextNode,
    HtmlRawNode,
    HtmlNode,
    /// `Html.voidNode : String -> List Attr -> Html msg` — a void element of an
    /// arbitrary (runtime) tag; the generic counterpart of the fixed-tag void
    /// builders below. Routes through the same `html_node_(tag, attrs, [])`
    /// sink as `Html.node`, just with an empty children vec baked at emit.
    HtmlVoidNode,
    /// `Html.doctype : List Html -> Html msg` — wraps children in the
    /// `!doctype-wrapper` pseudo-tag; `html::render_into_ctx` already
    /// special-cases that tag to emit a literal `<!DOCTYPE html>` prefix then
    /// the children directly (renderer support pre-existed this kernel wiring).
    HtmlDoctype,
    /// `Html.titleNode : String -> Html msg` — wraps a raw string directly in
    /// `<title>` (`HElement "title" [] [HText s]`).
    HtmlTitleNode,
    /// `Html.toString : Html msg -> String` — alias of `Html.render` (same
    /// runtime kernel `html_render_`), kept for API familiarity.
    HtmlToString,
    /// `Html.styleNode : List Attr -> String -> Html msg` — arity-2, distinct
    /// from the arity-3 `HtmlNode`. Its dedicated runtime kernel
    /// `html_style_node_` close-tag-neutralises the CSS body at construction
    /// (F7).
    HtmlStyleNode,
    /// `Html.Unsafe.unsafeScript : String -> Html msg` — an inline `<script>`
    /// with a verbatim JavaScript body. An escape hatch homed in
    /// `Ipe.Html.Unsafe` (its import discloses the `unsafe` capability), named
    /// `unsafe*`, never on the safe `Ipe.Html` surface: a script body is
    /// trusted-code injection. Its kernel `html_script_node_` neutralises a
    /// `</script` breakout at construction, mirroring `styleNode`.
    HtmlScriptNode,
    // ── Ipe.Html.Attributes retained primitives ─────────────────────────
    // The three irreducible `Attribute`-value constructors. The fixed-key
    // builders (`class`/`checked`/…) are pure Ipê in `Ipe/Html/Attributes.ipe`
    // over these, reached via `Kernel.kernel "Attr_attribute"` etc.
    HtmlAttribute,     // `attribute : String -> String -> Attribute msg`
    HtmlBoolAttribute, // `boolAttribute : String -> Bool -> Attribute msg`
    HtmlNoAttr,        // `noAttr : Attribute msg`
    // ── Ipe.Web app-entry kernels ───────────────────────────────────────
    WebApp,
    WebAppRouted,
    /// `Web.embed : { … } -> WebApp` — produce a mountable web-app handle from
    /// the same six-field cfg as `Web.tea`. The result is the opaque `WebApp`
    /// leaf; unlike `Web.tea` (a top-level entry that binds its own listener),
    /// an `embed`'d `WebApp` is meant to be `Server.mountApp`'d into a shared
    /// server router on one port. Shares `Web.tea`'s emit path.
    WebEmbed,
    WebRoute,
    WebRenderStatic,
    // ── Ipe.Terminal app-entry kernels ───────────────────────────────────
    /// `Tui.tea` — full-screen TEA entry, `view : Model -> Element
    /// Msg`, driven by `onKey`.
    TerminalAppScreen,
    // ── Ipe.Web app-entry with runtime settings ──────────────────────────
    /// `Web.appWith : List (Setting Web) -> { … } -> app` — the additive
    /// settings-carrying web entry. Same cfg record as `Web.tea`, preceded by a
    /// shape-checked `List (Setting Web)` (a `Terminal`-only or cross-shape
    /// setting is a type error in this slot).
    WebAppWith,
    // ── Ipe.App runtime-config front door ────────────────────────────────
    /// `App.fromEnv : String -> Secret` — the ONLY way to obtain a config
    /// `Secret` from an environment variable. A hard-coded credential is a
    /// plain `String`, so it does not type-check where a `Secret` is required.
    AppFromEnv,
    /// `App.fromEnvRequired : String -> Secret` — the fail-CLOSED required
    /// variant of [`Self::AppFromEnv`]. Same seal, but a missing/empty env var
    /// is a typed load-time `ConfigError` naming the var (the server never
    /// binds) rather than the fail-safe empty secret `App.fromEnv` yields.
    AppFromEnvRequired,
    /// `Host.bind : Int -> Setting a` — cross-cutting host-bind setting (raw
    /// host-mode tag; out-of-range resolves fail-closed to loopback).
    HostBind,
    /// `Log.level : Int -> Setting a` — cross-cutting log-level setting (raw
    /// severity tag).
    LogLevelSetting,
    /// `Db.url : Secret -> Setting a` — cross-cutting database-URL setting; the
    /// URL is a `Secret`, so it can only come from `App.fromEnv`.
    DbUrlSetting,
    /// `Console.adminToken : Secret -> Setting a` — the admin/metrics-console
    /// auth token as a `Secret`-typed setting (was a bare `IPE_ADMIN_TOKEN` env
    /// read with no typed carrier). Sourced via `App.fromEnvRequired`.
    ConsoleAdminToken,
    /// `Console.ingestToken : Secret -> Setting a` — the federation ingest token
    /// as a `Secret`-typed setting (was a bare `IPE_INGEST_TOKEN` env read).
    ConsoleIngestToken,
    /// `Console.metricsToken : Secret -> Setting a` — the metrics-scrape token as
    /// a `Secret`-typed setting (was a bare `IPE_METRICS_TOKEN` env read).
    ConsoleMetricsToken,
    /// `Web.csrf : Int -> Setting Web` — web-only CSRF-policy setting (raw
    /// policy tag; a stricter-only apply means it can never weaken CSRF).
    WebCsrf,
    /// `Web.sessionTtl : Int -> Setting Web` — web-only session-TTL setting (seconds).
    WebSessionTtl,
    /// `Web.authMaxLifetime : Int -> Setting Web` — absolute session-lifetime cap (seconds).
    WebAuthMaxLifetime,
    /// `Web.authSlideWindow : Int -> Setting Web` — rolling re-issue window (seconds).
    WebAuthSlideWindow,
    /// `Web.withRevocation : RevocationMode -> Setting Web` — arms the revocation gate;
    /// web-pinned. The `RevocationMode` argument (built by `Web.revocationOff` /
    /// `Web.revocationStore`) erases to a raw `Int` tag that `ipe_setting_web_auth_revocation_mode`
    /// consumes. Stricter-only monotonic: `Store` wins over `Off` at fold time.
    WebAuthRevocationMode,
    // ── Config-tag ADT constructors (nullary; project to a raw Int tag) ──────
    /// `Host.loopback : HostMode` — bind `127.0.0.1` only. Projects to tag `0`.
    HostLoopback,
    /// `Host.allInterfaces : HostMode` — bind every interface. Projects to tag `1`.
    HostAllInterfaces,
    /// `Host.envDriven : HostMode` — defer to the environment / build profile.
    /// Projects to tag `2`.
    HostEnvDriven,
    /// `Level.debug : LogLevel` — the debug severity. Projects to tag `0`.
    LevelDebug,
    /// `Level.info : LogLevel` — the info severity. Projects to tag `1`.
    LevelInfo,
    /// `Level.warn : LogLevel` — the warn severity. Projects to tag `2`.
    LevelWarn,
    /// `Level.error : LogLevel` — the error severity. Projects to tag `3`.
    LevelError,
    /// `Web.strict : CsrfMode` — enforce CSRF. Projects to tag `0`.
    WebCsrfStrict,
    /// `Web.inheritCsrf : CsrfMode` — inherit the framework CSRF default. Projects
    /// to tag `1`. There is deliberately no disabling variant.
    WebCsrfInherit,
    // ── RevocationMode ADT constructors ──────────────────────────────────
    /// `Web.revocationOff : RevocationMode` — no revocation check. Projects to
    /// tag `0`. The zero-overhead default path.
    WebRevocationOff,
    /// `Web.revocationStore : RevocationMode` — arm the runtime store check.
    /// Projects to tag `1`. The fail-closed, every-request path.
    WebRevocationStore,
    // ── event-attribute builders ─────────────────────────────────────────
    UiOnClick,
    UiOnFocus,
    UiOnBlur,
    UiOnMouseOver,
    UiOnMouseOut,
    UiOnInput,
    UiOnChange,
    UiOnKeyDown,
    UiOnKeyUp,
    UiOnBool,
    UiOnSubmit, // (a -> msg) -> Attribute msg  — form submit
    /// `Ui.onFile : (String -> msg) -> Attribute msg` — wire event name
    /// `"ipe-file"`; the browser-side driver reads the chosen file, base64
    /// data-URL-encodes it, and dispatches the URL string to the handler.
    UiOnFile,
    // ── Ipe.Html.Events builders — produce `Ipe.Html.Attribute msg`
    // (`html_attr`), so they unify with `Ipe.Html.Attributes` builders and the
    // element builders' `List (Ipe.Html.Attribute msg)` slot. Distinct from the
    // `UiOn*` kernels above, which produce the `Ipe.Ui.Attribute` variant for
    // the Ipe.Ui element family. Emit constructs `html::Attribute::EventAttr`.
    HtmlOnClick,
    HtmlOnFocus,
    HtmlOnBlur,
    HtmlOnMouseOver,
    HtmlOnMouseOut,
    HtmlOnSubmit,
    HtmlOnInput,
    HtmlOnChange,
    HtmlOnKeyDown,
    HtmlOnKeyUp,
    HtmlOnBool,
    // ── Ipe.Ui extended attribute builders ───────────────────────
    // Ui namespace — aspect-ratio + htmlAttribute + name/style/cinemascope
    UiSquare,        // nullary Attr: "1 / 1"
    UiWidescreen,    // nullary Attr: "16 / 9"
    UiCinemascope,   // nullary Attr: "2.35 / 1"
    UiAspectRatio,   // Float → Attr
    UiAspectRatioWH, // Int → Int → Attr
    UiHtmlAttribute, // String → String → Attr (AttrAttribute escape-hatch)
    UiName,          // String → Attr (HTML name= attribute)
    UiStyle,         // String → String → Attr (raw CSS property + value)
    UiTransitionRaw, // String → Bool → Attr (CSS transition shorthand + respect-reduced-motion flag)
    UiGridTracksRaw, // String → String → Attr (grid-template-columns + grid-template-rows)
    UiAnimateRaw, // String → String → String → Bool → Attr (name + shorthand-tail + @keyframes body + respect flag)
    // ── Breakpoint opaque constants + Ui.breakpoint wrapper ────────────
    /// `Ui.breakpoint : Breakpoint -> List (Attribute msg) -> Element msg -> Element msg`
    ///
    /// Delegates to `Ui.mediaQuery` at runtime (`ui_breakpoint_` →
    /// `ui_media_query_`), mirroring upstream's `breakpoint bp attrs child =
    /// mediaQuery (breakpointToQuery bp) attrs child` — `breakpointToQuery`
    /// is the identity here because `Breakpoint` is typed as `String` in the
    /// Rust port.
    UiBreakpoint,
    /// `Ui.mediaQuery : String -> List (Attribute msg) -> Element msg -> Element msg`
    ///
    /// Raw-CSS-media-query escape hatch (the typed `Breakpoint` constants
    /// cover the common cases via `Ui.breakpoint`). Wraps `child` in a
    /// marker-carrying `<div>` (`data-ipe-mq-q` = the query, gated through
    /// `SafeCssMediaQuery`; `data-ipe-mq-rules` = the attrs folded through
    /// the shared `build_style_string` collector). The Web / Webview render
    /// pipelines consume the markers via
    /// `web::style_inject::apply_style_injections` (`build_mq`) into a
    /// ipe-id-scoped `<style data-ipe-mq="<sid>">@media <q> {
    /// [ipe-id="<sid>"] { <rules> } }</style>` block. See
    /// `docs/adr/0003-security-render-and-data-access-invariants.md`.
    UiMediaQuery,
    UiMobile,        // Breakpoint constant: "(max-width: 767px)"
    UiTablet,        // Breakpoint constant: "(min-width: 768px) and (max-width: 1023px)"
    UiDesktop,       // Breakpoint constant: "(min-width: 1024px)"
    UiDarkMode,      // Breakpoint constant: "(prefers-color-scheme: dark)"
    UiLightMode,     // Breakpoint constant: "(prefers-color-scheme: light)"
    UiReducedMotion, // Breakpoint constant: "(prefers-reduced-motion: reduce)"
    // ── PseudoClass opaque constants + Ui.onPseudo generic escape hatch ──
    // `PseudoClass` is a genuine 5-constructor opaque runtime type (mirrors
    // `ipe_runtime::ui::element::PseudoClass` byte-for-byte — the SAME enum
    // `Background.hoverColor` / `Border.hoverColor` / `Font.hoverColor` already
    // construct internally via `AttrPseudoRule`). Unlike `Breakpoint` (typed as
    // a bare CSS-query `String`), `PseudoClass` carries no CSS text itself — it
    // is a closed 5-value tag consumed by `onPseudo`/the pseudo-class-colour
    // helpers — so it is registered as a real opaque nullary-constant type
    // rather than a String divergence.
    /// `Ui.onPseudo : PseudoClass -> List (Attribute msg) -> Attribute msg`
    /// — generic escape hatch: folds `attrs` into one CSS rules-string (the
    /// same style-collection logic as `Ui.layout`'s `style=""` attr) and
    /// attaches it as `AttrPseudoRule(pc, css)`. Sub-module helpers
    /// (`Background.hoverColor` etc.) already build on this exact primitive on
    /// the `../ipe` reference; the Rust port backs them the same way.
    UiOnPseudo,
    /// `Ui.hover : PseudoClass` — `PseudoClass::Hover`.
    UiHover,
    /// `Ui.focus : PseudoClass` — `PseudoClass::Focus`.
    UiFocus,
    /// `Ui.focusVisible : PseudoClass` — `PseudoClass::FocusVisible`.
    UiFocusVisible,
    /// `Ui.active : PseudoClass` — `PseudoClass::Active`.
    UiActive,
    /// `Ui.disabled : PseudoClass` — `PseudoClass::Disabled`. Distinct from the
    /// unrelated `Attr.disabled : Bool -> Attribute msg` (HTML boolean attr).
    UiDisabled,
    // Background namespace — pseudo-class colour tints
    BackgroundHoverColor,
    BackgroundFocusColor,
    BackgroundActiveColor,
    BackgroundDisabledColor,
    // Border namespace — style keywords (nullary)
    BorderSolid,
    BorderDashed,
    BorderDotted,
    // Border namespace — pseudo-class
    BorderHoverColor,
    BorderFocusColor,
    BorderActiveColor,
    BorderHoverWidth,   // Int → Attr
    BorderHoverRounded, // Int → Attr
    // Font namespace — weight variants (nullary)
    FontWeight,    // Int → Attr
    FontSemiBold,  // nullary (600)
    FontRegular,   // nullary (400)
    FontLight,     // nullary (300)
    FontExtraBold, // nullary (800)
    FontBlack,     // nullary (900)
    // Font namespace — decoration
    FontUnderline,    // nullary (AttrFontUnderline)
    FontNoDecoration, // nullary (AttrFontDecoration("none"))
    FontLineThrough,  // nullary (AttrFontDecoration("line-through"))
    // Font namespace — spacing (Float → Attr)
    FontLetterSpacing, // Float → Attr (AttrFontLetterSpacing)
    FontWordSpacing,   // Float → Attr (AttrFontWordSpacing)
    // Font namespace — text alignment (nullary)
    FontAlignLeft,   // nullary (AttrFontAlign("left"))
    FontAlignRight,  // nullary (AttrFontAlign("right"))
    FontAlignCenter, // nullary (AttrFontAlign("center")) — distinct from FontCenter
    FontCenter,      // nullary (AttrFontAlign("center"))
    FontJustify,     // nullary (AttrFontAlign("justify"))
    // Font namespace — string constants (nullary → String, NOT Attribute)
    FontSansSerif, // String constant "sans-serif"
    FontSerif,     // String constant "serif"
    FontMonospace, // String constant "monospace"
    // Font namespace — pseudo-class
    FontHoverColor,
    FontFocusColor,
    FontActiveColor,
    FontDisabledColor,
    FontHoverSize, // Int → Attr pseudo
    // ── Effect stdlib modules ────────────────────────────────────────
    // `Cli.tea` — line-oriented TEA app-entry, `view : Model ->
    // String`, driven by `onLine`.
    TerminalAppLines,
    // `Ipe.Tea.Worker.tea` — view-less co-located TEA app-entry:
    // `{ init, update, subscriptions } -> Program Worker msg`. No `view`; output
    // is `Cmd msg` (effects) and input is `Sub msg`. Co-located and
    // capability-gated; never reaches the sandbox.
    TeaWorker,
    // Ipe.Auth / Ipe.Auth — authentication helpers (fail-closed: no lower arm
    // yet → IPE-L0108 at lower time; qualified registration removes N0004).
    AuthHashPassword,
    AuthHashPasswordCost,
    AuthVerifyPassword,
    AuthPasswordStrength,
    AuthSignToken,
    AuthVerifyToken,
    AuthRegister,
    AuthLogin,
    AuthSetRole,
    /// `Ipe.Auth.subject : Principal -> String` — the verified subject claim.
    AuthSubject,
    /// `Ipe.Auth.claim : String -> Principal -> Maybe String` — the verified
    /// value of one claim, `Nothing` when the token carried no such claim
    /// (fail-closed: an absent claim never fabricates a value).
    AuthClaim,
    /// `Ipe.Auth.hasRole : String -> Principal -> Bool` — whether the principal
    /// holds a role, read from the conventional space-separated `roles` claim.
    /// Fail-closed: an absent `roles` claim reads as `False`.
    AuthHasRole,
    /// `Ipe.Auth.memberOf : String -> Principal -> Bool` — whether the principal
    /// belongs to a group, read from the conventional space-separated `groups`
    /// claim. Fail-closed: an absent `groups` claim reads as `False`.
    AuthMemberOf,
    // ── Ipe.Auth.Revocation — runtime revocation store (fail-closed) ──────
    /// `Auth.Revocation.revokeUser : Principal -> String -> Task Error ()` — mark
    /// every session of `subject` revoked. Requires an authenticated `Principal`.
    AuthRevocationRevokeUser,
    /// `Auth.Revocation.revokeSession : Principal -> String -> Task Error ()` — mark
    /// one session (`jti`) revoked. Requires an authenticated `Principal`.
    AuthRevocationRevokeSession,
    /// `Auth.Revocation.restoreUser : Principal -> String -> Task Error ()` — clear
    /// the subject-level revocation. Requires an authenticated `Principal`.
    AuthRevocationRestoreUser,
    /// `Auth.Revocation.isRevoked : String -> Task Error Bool` — query whether
    /// the subject is in the subject-revocation set.
    AuthRevocationIsRevoked,
    // Ipe.Http.Server.Stream — server-side streaming HTTP (fail-closed).
    StreamStream,
    StreamEmit,
    StreamFinish,
    StreamWithContentType,
    // Ipe.Http.Stream — client-side HTTP streaming (fail-closed).
    HttpStreamOpen,
    HttpStreamForEachChunk,
    HttpStreamClose,
    /// `Http.Stream.chunks sid toMsg` — subscribes to stream chunks; returns `Sub msg`.
    /// Classified as TEA (not server) because it returns `IpeSub<M>`.
    HttpStreamChunks,
    // ── Ipe.Http.Server.WebSocket (12 kernels) ─────────────────────
    WsDefaultCfg,          // WebSocketServerCfg (arity 0)
    WsWithOnConnect, // (WebSocketServer -> Task Error ()) -> WebSocketServerCfg -> WebSocketServerCfg (arity 2)
    WsWithOnMessage, // (WebSocketServer -> String -> Task Error ()) -> WebSocketServerCfg -> WebSocketServerCfg (arity 2)
    WsWithOnClose, // (WebSocketServer -> Task Error ()) -> WebSocketServerCfg -> WebSocketServerCfg (arity 2)
    WsWithOnError, // (WebSocketServer -> Error -> Task Error ()) -> WebSocketServerCfg -> WebSocketServerCfg (arity 2)
    WsWithMaxMessageBytes, // Int -> WebSocketServerCfg -> WebSocketServerCfg (arity 2)
    WsWithOriginPatterns, // List String -> WebSocketServerCfg -> WebSocketServerCfg (arity 2)
    WsUpgrade,     // Request -> WebSocketServerCfg -> Task Error Response (arity 2)
    WsSendToClient, // WebSocketServer -> String -> Task Error () (arity 2)
    WsSendBinaryToClient, // WebSocketServer -> Bytes -> Task Error () (arity 2)
    WsBroadcast,   // List WebSocketServer -> String -> Task Error () (arity 2)
    WsCloseClient, // WebSocketServer -> Task Error () (arity 1)
    // ── Ipe.WebSocket — outbound WebSocket client (7 kernels) ──
    // The 6 Task-tier kernels take/return a raw `Int` socket id (the stdlib
    // wraps it in the `WebSocket` ADT). `Sub_subscribeWebSocket` is the single
    // `any`-typed Sub-tier kernel the stdlib routes onOpen/onMessage/onClose/
    // onError through; the backend peephole splits it on the compile-time literal
    // `kind` string into the four typed runtime fns (sub_subscribe_ws_*).
    WebSocketConnect,       // String -> Task Error Int (arity 1)
    WebSocketConnectWith,   // WebSocketCfg -> Task Error Int (arity 1)
    WebSocketSend,          // Int -> String -> Task Error () (arity 2)
    WebSocketSendBinary,    // Int -> Bytes -> Task Error () (arity 2)
    WebSocketClose,         // Int -> Task Error () (arity 1)
    WebSocketCloseWithCode, // Int -> String -> Int -> Task Error () (arity 3)
    SubSubscribeWebSocket,  // Int -> String -> (any -> msg) -> Sub msg (arity 3)
    // ── Ipe.Ffi.Js — the raw typed transport across the Ipê↔JS seam (ports) ──
    // `Js.send : a -> Cmd msg` (outbound) and
    // `Js.subscribe : Decoder a -> (a -> msg) -> Sub msg` (inbound). The crossing
    // value `a` must be a plain, closed, concrete SEAL type: the CONCRETE inferred
    // argument type is checked fail-closed at lowering (`reject_illegal_js_port_seal`,
    // the same seal `CustomElement down up` enforces, extended transitively through
    // ADT payloads), so a `Secret`/reserved-sink payload and a `Decoder Value`
    // subscription are both rejected (IPE-L0148) — a secret can never cross to JS and
    // the untyped channel cannot be spelled. On passing the seal the port lowers to
    // the live per-target transport: a server-driven crossing rides the event-class
    // wire behind the fail-closed seal decoder, a client-wasm crossing delivers
    // in-process through the seal codec. Both disclose the `js-port` capability.
    JsSend,      // a -> Cmd msg (arity 1)
    JsSubscribe, // Decoder a -> (a -> msg) -> Sub msg (arity 2)
    JsRequest,   // a -> Decoder b -> Task b (arity 2) — correlated one-shot request/reply
    // ── Ipe.Ffi.Js session-stream primitive ──────────────────────────────────
    // The correlated, bounded, session-scoped stream: open → N frames → close →
    // terminal. Generalises `JsRequest`'s one-shot correlation to a bounded
    // multi-frame lifecycle over the SAME private-id routing + seal gate. All run
    // on the wasm client, like the other ports; the frame/cmd/terminal types are
    // seal-legal (IPE-N0039). `SessionHandle` is the opaque address (no user ctor).
    JsOpenSession,   // openCmd -> Decoder frame -> Task SessionHandle (arity 2)
    JsSessionFrames, // SessionHandle -> (frame -> msg) -> Sub msg (arity 2)
    JsSendToSession, // SessionHandle -> sessionCmd -> Cmd msg (arity 2)
    JsCloseSession,  // SessionHandle -> closeCmd -> Decoder terminal -> Task terminal (arity 3)
    // ── Ipe.Env — build-time-embedded public config (wasm M5 residual) ──
    // `Env.public "KEY"` resolves ONLY for names in the project's `[wasm]
    // publicEnv` allowlist (`package.ipe`, validated against the secret-name
    // denylist at PARSE time — `ipe_cli::project::is_denylisted_public_env_name`).
    // Any other key returns `Nothing`, by construction (the generated match
    // has no arm for it) — never a live lookup against the raw process/host
    // environment, on EITHER target.
    EnvPublic, // String -> Maybe String (arity 1)
    // ── Ipe.Ui.Region ──────────────────────────────────────────────
    RegionMainContent,      // Attribute msg (arity 0)
    RegionNavigation,       // Attribute msg (arity 0)
    RegionFooter,           // Attribute msg (arity 0)
    RegionAside,            // Attribute msg (arity 0)
    RegionHeading,          // Int → Attribute msg (arity 1)
    RegionLabel,            // String → Attribute msg (arity 1)
    RegionAnnounce,         // Attribute msg (arity 0)
    RegionAnnounceUrgently, // Attribute msg (arity 0)
    // ── Ui.describe + desc* constructors ──────────────────────────────────
    UiDescribe,          // Description -> Attribute msg (arity 1)
    UiDescNone,          // Description (arity 0) — the `NoDescription` role
    UiDescParagraph,     // Description (arity 0) — the `DescParagraph` role
    UiDescMain,          // Description (arity 0)
    UiDescNavigation,    // Description (arity 0)
    UiDescContentInfo,   // Description (arity 0)
    UiDescComplementary, // Description (arity 0)
    UiDescLivePolite,    // Description (arity 0)
    UiDescLiveAssertive, // Description (arity 0)
    UiDescHeading,       // Int -> Description (arity 1)
    UiDescLabel,         // String -> Description (arity 1)
    // ── Ipe.Ui.Input ──────────────────────────────────────────────────
    /// `Input.labelAbove : List (Attribute msg) -> Element msg -> Label msg`
    InputLabelAbove,
    /// `Input.labelBelow : List (Attribute msg) -> Element msg -> Label msg`
    InputLabelBelow,
    /// `Input.labelLeft : List (Attribute msg) -> Element msg -> Label msg`
    InputLabelLeft,
    /// `Input.labelRight : List (Attribute msg) -> Element msg -> Label msg`
    InputLabelRight,
    /// `Input.labelHidden : String -> Label msg`
    InputLabelHidden,
    /// `Input.placeholder : List (Attribute msg) -> Element msg -> Placeholder msg`
    InputPlaceholder,
    /// `Input.text : List (Attribute msg) -> { onChange, text, placeholder, label } -> Element msg`
    InputText,
    /// `Input.multiline : List (Attribute msg) -> { onChange, text, placeholder, label, spellcheck } -> Element msg`
    InputMultiline,
    /// `Input.email : List (Attribute msg) -> { onChange, text, placeholder, label } -> Element msg`
    InputEmail,
    /// `Input.username : List (Attribute msg) -> { onChange, text, placeholder, label } -> Element msg`
    InputUsername,
    /// `Input.search : List (Attribute msg) -> { onChange, text, placeholder, label } -> Element msg`
    InputSearch,
    /// `Input.currentPassword : List (Attribute msg) -> { onChange, text, placeholder, label } -> Element msg`
    InputCurrentPassword,
    /// `Input.newPassword : List (Attribute msg) -> { onChange, text, placeholder, label } -> Element msg`
    InputNewPassword,
    /// `Input.checkbox : List (Attribute msg) -> { onChange, icon, checked, label } -> Element msg`
    InputCheckbox,
    /// `Input.slider : List (Attribute msg) -> { onChange, value, min, max, step, label } -> Element msg`
    InputSlider,
    /// `Input.option : String -> Element msg -> RadioOption msg`
    InputOption,
    /// `Input.radio : List (Attribute msg) -> { onChange, options, selected, label } -> Element msg`
    InputRadio,
    /// `Input.radioRow : List (Attribute msg) -> { onChange, options, selected, label } -> Element msg`
    InputRadioRow,
    // ── Ipe.Ui.Lazy ────────────────────────────────────────────────────
    /// `Lazy.lazy : (a -> Element msg) -> a -> Element msg`
    ///
    /// **Eager in v1.** Ipê's the runtime memoises the subtree; Ipê evaluates
    /// immediately (no keyed LRU available before the TEA diff layer).  The
    /// Sanctioned divergence §B-Lazy.
    LazyLazy,
    /// `Lazy.lazy2 : (a -> b -> Element msg) -> a -> b -> Element msg` (eager)
    LazyLazy2,
    /// `Lazy.lazy3 : (a -> b -> c -> Element msg) -> a -> b -> c -> Element msg` (eager)
    LazyLazy3,
    /// `Lazy.lazy4 : (a -> b -> c -> d -> Element msg) -> a -> b -> c -> d -> Element msg` (eager)
    LazyLazy4,
    /// `Lazy.lazy5 : (a -> b -> c -> d -> e -> Element msg) -> a -> b -> c -> d -> e -> Element msg` (eager)
    LazyLazy5,
    // ── Ipe.Ui.Keyed — ipe-key for diff identity ─────────────────────────
    /// `Keyed.column : List (Attribute msg) -> List (String, Element msg) -> Element msg`
    KeyedColumn,
    /// `Keyed.row : List (Attribute msg) -> List (String, Element msg) -> Element msg`
    KeyedRow,

    // ── Ipe.Decimal — arbitrary-precision decimal arithmetic ──────────────
    /// `Decimal.zero : Decimal`
    DecZero,
    /// `Decimal.one : Decimal`
    DecOne,
    /// `Decimal.oneHundred : Decimal`
    DecOneHundred,
    /// `Decimal.fromString : String -> Result Error Decimal`
    DecFromString,
    /// `Decimal.fromInt : Int -> Decimal`
    DecFromInt,
    /// `Decimal.fromFloat : Float -> Decimal`
    DecFromFloat,
    /// `Decimal.fromMinor : Int -> Int -> Decimal`
    DecFromMinor,
    /// `Decimal.toString : Decimal -> String`
    DecToString,
    /// `Decimal.toStringFixed : Int -> Decimal -> String`
    DecToStringFixed,
    /// `Decimal.toFloat : Decimal -> Float`
    DecToFloat,
    /// `Decimal.toInt : Decimal -> Int`
    DecToInt,
    /// `Decimal.toMinor : Int -> Decimal -> Int`
    DecToMinor,
    /// `Decimal.add : Decimal -> Decimal -> Decimal`
    DecAdd,
    /// `Decimal.sub : Decimal -> Decimal -> Decimal`
    DecSub,
    /// `Decimal.mul : Decimal -> Decimal -> Decimal`
    DecMul,
    /// `Decimal.div : Decimal -> Decimal -> Result Error Decimal`
    DecDiv,
    /// `Decimal.mod : Decimal -> Decimal -> Result Error Decimal`
    DecMod,
    /// `Decimal.neg : Decimal -> Decimal`
    DecNeg,
    /// `Decimal.abs : Decimal -> Decimal`
    DecAbs,
    /// `Decimal.floor : Decimal -> Decimal`
    DecFloor,
    /// `Decimal.ceil : Decimal -> Decimal`
    DecCeil,
    /// `Decimal.round : Int -> Decimal -> Decimal`
    DecRound,
    /// `Decimal.roundHalfUp : Int -> Decimal -> Decimal`
    DecRoundHalfUp,
    /// `Decimal.truncate : Int -> Decimal -> Decimal`
    DecTruncate,
    /// `Decimal.compare : Decimal -> Decimal -> Int`
    DecCompare,
    /// `Decimal.eq : Decimal -> Decimal -> Bool`
    DecEq,
    /// `Decimal.neq : Decimal -> Decimal -> Bool`
    DecNeq,
    /// `Decimal.lt : Decimal -> Decimal -> Bool`
    DecLt,
    /// `Decimal.lte : Decimal -> Decimal -> Bool`
    DecLte,
    /// `Decimal.gt : Decimal -> Decimal -> Bool`
    DecGt,
    /// `Decimal.gte : Decimal -> Decimal -> Bool`
    DecGte,
    /// `Decimal.min : Decimal -> Decimal -> Decimal`
    DecMin,
    /// `Decimal.max : Decimal -> Decimal -> Decimal`
    DecMax,
    /// `Decimal.isZero : Decimal -> Bool`
    DecIsZero,
    /// `Decimal.isPositive : Decimal -> Bool`
    DecIsPositive,
    /// `Decimal.isNegative : Decimal -> Bool`
    DecIsNegative,
    /// `Decimal.percentOf : Decimal -> Decimal -> Decimal`
    DecPercentOf,
    /// `Decimal.addPercent : Decimal -> Decimal -> Decimal`
    DecAddPercent,
    /// `Decimal.subPercent : Decimal -> Decimal -> Decimal`
    DecSubPercent,
    /// `Decimal.formatWith : String -> String -> Int -> Decimal -> String`
    DecFormatWith,
    // ── Ipe.Money — currency table + FX registry + fair-split allocate ────
    // The Ipê-side `Money` ADT carries a typed `Currency` enum; the
    // compiled-source `Ipe.Money` wrappers convert `Currency` to its ISO 4217
    // code (a `String`) before invoking these kernels, so every property /
    // format / rate kernel takes the code as a plain `String`. Runtime bodies:
    // `ipe_runtime::money::*`.
    /// `Money.minorUnits : String -> Int` — decimal places for a currency's
    /// minor unit (JPY=0, USD=2, BHD=3, BTC=8; unknown → 2).
    MoneyMinorUnits,
    /// `Money.symbol : String -> String` — currency symbol ("$", "€", "₿").
    MoneySymbol,
    /// `Money.currencyName : String -> String` — human-readable name.
    MoneyCurrencyName,
    /// `Money.isKnownCurrency : String -> Bool` — is the code a recognised
    /// ISO 4217 / crypto ticker?
    MoneyIsKnownCurrency,
    /// `Money.format : String -> Decimal -> String` — symbol-prefixed, rounded
    /// half-away-from-zero to the currency's minor units ("$2.55").
    MoneyFormat,
    /// `Money.formatWithCode : String -> Decimal -> String` — ISO-code suffix
    /// form ("2.55 USD").
    MoneyFormatWithCode,
    /// `Money.allocate : Int -> Int -> Decimal -> List Decimal` — fair split of
    /// an amount across N parts (minor-unit places, parts, amount); residue
    /// distributed toward zero. Caps `parts` at 100k (memory-amplification
    /// guard) and returns `[]` on overflow / non-positive parts.
    MoneyAllocate,
    /// `Money.setRate : String -> String -> Decimal -> Result Error ()` —
    /// register an FX rate (positive-only; auto-inverse; bounded registry).
    MoneySetRate,
    /// `Money.getRate : String -> String -> Result Error Decimal` — look up a
    /// registered rate (identity for from==to; missing → Err).
    MoneyGetRate,
    /// `Money.hasRate : String -> String -> Bool`.
    MoneyHasRate,
    /// `Money.clearRates : () -> Result Error ()` — drop every registered rate.
    MoneyClearRates,
    // ── Ipe.Db.Sql — SqlFragment builder ───────────────────────
    // Typed, parameterized WHERE-fragment combinators. Replace the removed
    // `Db.unsafeFindWhere` raw-string escape hatch: a `SqlFragment` can only be
    // constructed through these kernels, so SQL injection via a hand-built
    // WHERE clause becomes a type error (String where SqlFragment is expected)
    // rather than a runtime risk.
    /// `Sql.column : String -> SqlFragment` — validated column/table reference
    /// (dot-accepting, so `users.id` is legal).
    SqlColumn,
    /// `Ipe.Db.Unsafe.unsafeFragment : String -> SqlFragment` — the un-validated
    /// anti-`Sql.column`: mints a `SqlFragment` from a verbatim string WITHOUT
    /// the `valid_sql_ident` gate. Reachable only through the disclosed
    /// `Ipe.Db.Unsafe` submodule; the caller asserts the identifier is safe.
    SqlUnsafeFragment,
    /// `Sql.param : SqlValue -> SqlFragment` — binds a single `?` placeholder.
    SqlParam,
    /// `Sql.int : Int -> SqlFragment` — sugar over `Sql.param`; shares the
    /// `sql_param` runtime symbol (`i64: Into<SqlParam>` already exists).
    SqlInt,
    /// `Sql.string : String -> SqlFragment` — sugar over `Sql.param`.
    SqlString,
    /// `Sql.float : Float -> SqlFragment` — sugar over `Sql.param`.
    SqlFloat,
    /// `Sql.bool : Bool -> SqlFragment` — sugar over `Sql.param`.
    SqlBool,
    /// `Sql.eq : SqlFragment -> SqlFragment -> SqlFragment`
    SqlEq,
    /// `Sql.ne : SqlFragment -> SqlFragment -> SqlFragment`
    SqlNe,
    /// `Sql.gt : SqlFragment -> SqlFragment -> SqlFragment`
    SqlGt,
    /// `Sql.lt : SqlFragment -> SqlFragment -> SqlFragment`
    SqlLt,
    /// `Sql.gte : SqlFragment -> SqlFragment -> SqlFragment`
    SqlGte,
    /// `Sql.lte : SqlFragment -> SqlFragment -> SqlFragment`
    SqlLte,
    /// `Sql.and : SqlFragment -> SqlFragment -> SqlFragment`
    SqlAnd,
    /// `Sql.or : SqlFragment -> SqlFragment -> SqlFragment`
    SqlOr,
    /// `Sql.not : SqlFragment -> SqlFragment`
    SqlNot,
    /// `Sql.isNull : SqlFragment -> SqlFragment`
    SqlIsNull,
    /// `Sql.isNotNull : SqlFragment -> SqlFragment`
    SqlIsNotNull,
    /// `Sql.inList : SqlFragment -> List SqlValue -> SqlFragment` — `[]` emits
    /// `(1 = 0)` rather than the SQL syntax error `IN ()`.
    SqlInList,
    /// `Sql.like : SqlFragment -> String -> SqlFragment` — the pattern is
    /// always a bound param, never interpolated.
    SqlLike,
    /// `Sql.exists : String -> SqlFragment -> SqlFragment` — a correlated-
    /// subquery existence test `EXISTS (SELECT 1 FROM <table> WHERE <inner>)`.
    /// The table is validated through the same bare-identifier gate as
    /// `Db.findWhere`'s table (never `unsafeFragment`); `inner` was built only
    /// through the audited `Sql.*` combinators, so the subquery adds no injection
    /// surface. The single site that embeds a table name and a nested `SELECT`.
    SqlExists,
    /// `Sql.maskedColumn : SqlFragment -> String -> SqlFragment` — a column-masking
    /// projection term `CASE WHEN (<pred>) THEN col ELSE NULL END AS col`. `pred`
    /// was built only through the audited `Sql.*` combinators; `col` is validated
    /// through the same dotted-identifier gate as `Sql.column` (never
    /// `unsafeFragment`), so the term adds no injection surface. The unauthorized
    /// (predicate-false) row projects SQL `NULL`, decoded to `Nothing` by the
    /// NULL-preserving masked read.
    SqlMaskedColumn,
    /// `Db.findWhere : Db -> String -> SqlFragment -> Task Error (List Row)` —
    /// the `SqlFragment`-typed replacement for the removed `unsafeFindWhere`.
    DbFindWhere,
    /// `Db.findWhereMasked : Db -> String -> List SqlFragment -> SqlFragment
    ///                        -> Decoder a -> Task Error (List a)` — the
    /// NULL-preserving projected read the secured column-masking path routes
    /// through. Unlike `Db.findWhere` (which emits `SELECT *` and collapses SQL
    /// NULL → `""` via `row_to_map`), it emits an EXPLICIT projection from the
    /// caller's validated `SqlFragment` terms (each an `Sql.column col AS col` or a
    /// masked `Sql.maskedColumn`) and decodes each row through the threaded
    /// `Decoder` over the NULL-preserving row→JSON bridge, so a masked cell arrives
    /// as `Nothing`, never `Just ""`. Every identifier is combinator-validated and
    /// every value is a bound parameter; a poisoned fragment fails the read closed.
    DbFindWhereMasked,
    /// `Db.findJoin : Db -> String -> String -> List String -> String -> String
    ///                -> List String -> SqlFragment
    ///                -> Task Error (List (Row, Row))` — read an inner join of
    /// two tables as one parameterized statement. The two `(table, alias,
    /// columns)` triples name the join sides; every identifier reaches SQL only
    /// after the runtime re-validates it, and `frag` (the join-key equality plus
    /// any filter) is a combinator-built `SqlFragment`, so no value or identifier
    /// is interpolated. Each result row is the pair of the two sides' plain-keyed
    /// cell maps, so a caller decodes each side through its own store codec.
    DbFindJoin,
    /// `Db.findProjection : Db -> String -> String -> String -> String
    ///                      -> SqlFragment -> List (String, String)
    ///                      -> Task Error (List Row)` — read a typed projection
    /// over a two-table join as one parameterized statement. The two
    /// `(table, alias)` pairs name the join sides, `frag` is the join-key
    /// equality plus any filter, and the `List (String, String)` is the ordered
    /// `(alias, column)` references to project. Every identifier reaches SQL only
    /// after the runtime re-validates it, and no value is interpolated. Each
    /// result row is one cell map keyed by the projection output names
    /// (`p0`, `p1`, …), so a caller decodes each projected column by position.
    DbFindProjection,
    /// `Db.findJoinOrdered : Db -> String -> String -> List String -> String
    ///                       -> String -> List String -> SqlFragment
    ///                       -> String -> String -> Bool
    ///                       -> Task Error (List (Row, Row))` — ordered variant of
    /// `Db.findJoin` that appends `ORDER BY <orderAlias>.<orderCol> ASC|DESC` to
    /// the join statement. The three trailing args are the order-column alias,
    /// column name, and ascending flag. Every identifier is re-validated at the
    /// runtime boundary; no value is interpolated.
    DbFindJoinOrdered,
    /// `Db.findProjectionOrdered : Db -> String -> String -> String -> String
    ///                             -> SqlFragment -> List (String, String)
    ///                             -> String -> String -> Bool
    ///                             -> Task Error (List Row)` — ordered variant of
    /// `Db.findProjection` that appends `ORDER BY <orderAlias>.<orderCol> ASC|DESC`.
    /// The three trailing args are the order-column alias, column name, and
    /// ascending flag. Every identifier is re-validated at the runtime boundary.
    DbFindProjectionOrdered,
    /// `Db.deleteWhere : Db -> String -> SqlFragment -> Task Error Int`
    DbDeleteWhere,
    /// `Db.updateWhere : Db -> String -> List (String, SqlField) -> SqlFragment -> Task Error Int`
    DbUpdateWhere,
    /// `Db.upsertFields : Db -> String -> List String -> List (String, SqlField) -> Task Error Int`
    /// — `INSERT … ON CONFLICT (<target>) DO UPDATE SET c = excluded.c, …`
    /// (update-in-place on both backends); the `List String` is the conflict
    /// target.
    DbUpsertFields,
    /// `Db_insertFieldsChecked : Db -> String -> List (String, SqlField)
    /// -> SqlFragment -> Task Error Int` — `Store.insertAs`'s insert: kept only
    /// when the policy check holds over the row as stored (`0` otherwise).
    /// Store-private: bound by a non-exported `Kernel.kernel` alias.
    DbInsertFieldsChecked,
    /// `Db_updateWhereChecked : Db -> String -> List (String, SqlField)
    /// -> SqlFragment -> SqlFragment -> Task Error Int` — `Store.updateAs`'s
    /// update (fields, scoping `WHERE`, check): kept only when every updated row
    /// satisfies the check as stored. Store-private like `DbInsertFieldsChecked`.
    DbUpdateWhereChecked,
    // ── Ipe.Secret — opaque secret-string wrapper ─────────
    // The ONLY public constructor: every `Secret` value traces back to one of
    // these calls. Never derivable from a bare `String` implicitly.
    /// `Secret.fromString : String -> Secret` — the seal; construction boundary.
    SecretFromString,
    /// `Secret.reveal : Secret -> String` — the single greppable un-parse.
    SecretReveal,
    /// `Secret.use : Secret -> (String -> a) -> a` — the scoped consume. Applies
    /// the caller's function to the revealed plaintext and returns its result;
    /// a thin wrapper over `reveal` that keeps the common case off the `unsafe`
    /// axis. Capability-neutral (like every `Secret.*` kernel): disclosure is
    /// import-derived, and `use` is reached off a plain `import Ipe.Secret`.
    SecretUse,
    /// `Secret.redacted : Secret -> String` — explicit `"<redacted>"` (also
    /// what `{{…}}` interpolation gives automatically — see
    /// `ipe_runtime::secret`'s hand-written `IpeStringify` impl).
    SecretRedacted,

    // ── Ipe.Regex — RE2 helpers ──────────────────────────────────
    // Pure, total kernels routed via the compiled-source `Ipe.Regex`
    // Layer-3 surface + `Kernel.kernel "Regex_*"` aliases. Runtime fns
    // (`ipe_runtime::regex_kernel::*`) are re-exported ungated — no feature gate
    // and no `project.rs` thread needed (the emitted `mod.rs` declares
    // `regex_kernel` unconditionally, deps always present).
    /// `Regex.compile : String -> Result Error Regex` — parse a pattern ONCE
    /// into the opaque `Regex` handle; an invalid pattern is a typed `Err`,
    /// never a silent no-match.
    RegexCompile,
    /// `Regex.match : Regex -> String -> Bool` — does the pattern match anywhere?
    RegexMatch,
    /// `Regex.find : Regex -> String -> Maybe String` — first match, if any.
    RegexFind,
    /// `Regex.findAll : Regex -> String -> List String` — every match, in order.
    RegexFindAll,
    /// `Regex.replace : Regex -> String -> String -> String` — replace every match.
    RegexReplace,
    /// `Regex.split : Regex -> String -> List String` — split on every match.
    RegexSplit,

    // ── Ipe.Path — typed, validated filesystem paths ───────────────────
    // Pure, total kernels routed via the compiled-source `Ipe.Path`
    // Layer-3 surface + `Kernel.kernel "Path_*"` aliases. Runtime fns
    // (`ipe_runtime::path::*`) are re-exported ungated (same posture as Regex).
    // `Path` is an opaque, validated type: the ONLY constructor is
    // `PathFromString` (the parse-don't-validate seal that rejects NUL bytes
    // and `..` traversal escapes); the helpers take a `Path`, never a raw
    // `String`.
    /// `Path.fromString : String -> Result Error Path` — THE seal; the only
    /// constructor. Normalises the path and rejects NUL / traversal escapes.
    PathFromString,
    /// `Path.toString : Path -> String` — THE un-parse; recover the cleaned
    /// path string.
    PathToString,
    /// `Path.base : Path -> String` — final path component.
    PathBase,
    /// `Path.dir : Path -> String` — everything but the final component.
    PathDir,
    /// `Path.ext : Path -> String` — file extension (with the dot), or empty.
    PathExt,
    /// `Path.isAbsolute : Path -> Bool` — does the path start from the root?
    PathIsAbsolute,
    /// `Path.under : Path -> Path -> Result Error Path` — join a relative child
    /// beneath a root; refuses an empty, absolute, `..`-bearing, or NUL child.
    PathUnder,
    /// `Path.absolute : Path -> Task Error Path` — resolve a relative path
    /// against the working directory (reads the cwd: `Filesystem`).
    PathAbsolute,

    // ── Ipe.Trace — opt-in tracing spans ──────────────────────────────
    // Task-effectful; runtime fns `ipe_runtime::trace::*` are re-exported
    // (emitted `mod.rs` declares `trace` unconditionally). Class `Pure` (the
    // effect lives in the `Task` scheme, same as File/Io/Http).
    /// `Trace.span : String -> Task e a -> Task e a` — wrap a Task in a named span.
    TraceSpan,
    /// `Trace.event : String -> Task Error ()` — record an instantaneous event.
    TraceEvent,
    /// `Trace.attr : String -> String -> Task Error ()` — annotate the span.
    TraceAttr,

    // ── Ipe.Compression — gzip + zstd ─────────────────────────────────
    // Task-effectful; runtime `ipe_runtime::compression::*`. Operates on `Bytes`
    // (`Vec<u8>`) to match the runtime `compression_*(Vec<u8>) -> Vec<u8>` shape.
    /// `Compression.gzip : Bytes -> Task Error Bytes`.
    CompressionGzip,
    /// `Compression.gunzip : Bytes -> Task Error Bytes`.
    CompressionGunzip,
    /// `Compression.zstdCompress : Bytes -> Task Error Bytes`.
    CompressionZstdCompress,
    /// `Compression.zstdDecompress : Bytes -> Task Error Bytes`.
    CompressionZstdDecompress,

    // ── Ipe.Csv — RFC 4180 encode/decode ──────────────────────────────
    // Runtime `ipe_runtime::csv::*`. `Csv` is the record
    // `{ header : List String, rows : List (List String) }`.
    /// `Csv.parse : String -> Result Error Csv`.
    CsvParse,
    /// `Csv.parseWithDelimiter : String -> String -> Result Error Csv`.
    CsvParseWithDelimiter,
    /// `Csv.encode : Csv -> String`.
    CsvEncode,
    /// `Csv.encodeWithDelimiter : String -> Csv -> String`.
    CsvEncodeWithDelimiter,
    /// `Csv.parseStreamFromFile : String -> Task Error (List (List String))`.
    CsvParseStreamFromFile,

    // ── Ipe.Cache — in-memory LRU + TTL cache ─────────────────────────
    // Task-effectful; runtime `ipe_runtime::cache::*` (the emitted `mod.rs`
    // declares `cache` unconditionally — same ungated-vendoring posture as
    // Csv/Compression). Routed via the compiled-source `Ipe.Cache` Layer-3
    // surface + `Kernel.kernel "Cache_*"` aliases. Class `Pure` (the effect lives
    // in the `Task` scheme, same as File/Io/Http). All kernels take the raw
    // `Int` handle; the surface `Cache k v` ADT is unwrapped in Ipê source.
    /// `Cache.newRaw : CacheCfg -> Task Error Int` — allocate, return the handle.
    CacheNewRaw,
    /// `Cache.getRaw : Int -> k -> Task Error (Maybe v)` — look up a key.
    CacheGet,
    /// `Cache.putRaw : Int -> k -> v -> Task Error ()` — insert / update.
    CachePut,
    /// `Cache.removeRaw : Int -> k -> Task Error ()` — delete a key (idempotent).
    CacheRemove,
    /// `Cache.clearRaw : Int -> Task Error ()` — purge every entry.
    CacheClear,
    /// `Cache.sizeRaw : Int -> Task Error Int` — current entry count.
    CacheSize,
    /// `Cache.statsRaw : Int -> Task Error { hits, misses, evictions }`.
    CacheStats,
    /// `Cache.destroyRaw : Int -> Task Error ()` — reclaim a cache handle.
    CacheDestroyRaw,

    // ── Ipe.Config — typed TOML/YAML/JSON decoders ────────────────────
    // Config shares the JSON `Decoder<E, T>` carrier and its `decode_*`
    // combinator runtime fns: `string`/`int`/`float`/`bool`/`field`/`at`/
    // `list`/`map`/`andThen`/`succeed`/`fail` route to the SAME runtime fns
    // as the corresponding `JsonDec*` kernels (see `naming.rs`). Only the
    // format front-ends (`decodeToml`/`decodeYaml`/`decodeJson`), `nullable`,
    // and `loadFromFile` have Config-specific runtime fns
    // (`ipe_runtime::config_decode::*`). Distinct variants keep
    // `Config.<member>` resolution clean while reusing the shared decoder
    // runtime. Class `Pure` (Task effect lives in the scheme, same as
    // File/Io/Http).
    /// `Config.string : Decoder String` — shares `json_decode_string`.
    ConfigString,
    /// `Config.int : Decoder Int` — shares `json_decode_int`.
    ConfigInt,
    /// `Config.float : Decoder Float` — shares `json_decode_float`.
    ConfigFloat,
    /// `Config.bool : Decoder Bool` — shares `json_decode_bool`.
    ConfigBool,
    /// `Config.nullable : Decoder a -> Decoder (Maybe a)`.
    ConfigNullable,
    /// `Config.field : String -> Decoder a -> Decoder a` — shares `decode_field`.
    ConfigField,
    /// `Config.at : List String -> Decoder a -> Decoder a` — shares `decode_at`.
    ConfigAt,
    /// `Config.list : Decoder a -> Decoder (List a)` — shares `decode_list`.
    ConfigList,
    /// `Config.succeed : a -> Decoder a` — shares `decode_succeed`.
    ConfigSucceed,
    /// `Config.fail : String -> Decoder a` — shares `decode_fail`.
    ConfigFail,
    /// `Config.map : (a -> b) -> Decoder a -> Decoder b` — shares `decode_map`.
    ConfigMap,
    /// `Config.andThen : (a -> Decoder b) -> Decoder a -> Decoder b` — shares `decode_and_then`.
    ConfigAndThen,
    /// `Config.map2`..`Config.map8` — combine 2..8 decoders with an N-ary
    /// function; share the runtime `decode_map2`..`decode_map8`.
    ConfigMap2,
    ConfigMap3,
    ConfigMap4,
    ConfigMap5,
    ConfigMap6,
    ConfigMap7,
    ConfigMap8,
    /// `Config.oneOf : List (Decoder a) -> Decoder a` — first succeeding branch;
    /// shares `decode_one_of`.
    ConfigOneOf,
    /// `Config.index : Int -> Decoder a -> Decoder a` — decode the n-th array
    /// element; shares `decode_index`.
    ConfigIndex,
    /// `Config.keyValuePairs : Decoder a -> Decoder (List (String, a))` — decode
    /// every object entry; shares `decode_key_value_pairs`.
    ConfigKeyValuePairs,
    /// `Config.maybe : Decoder a -> Decoder (Maybe a)` — `Just` on success,
    /// `Nothing` on ANY failure (`config_maybe`).
    ConfigMaybe,
    /// `Config.dict : Decoder a -> Decoder (Dict String a)` — decode an object
    /// into a `Dict String a` (`config_dict`).
    ConfigDict,
    /// `Config.decodeToml : String -> Decoder a -> Result Error a`.
    ConfigDecodeToml,
    /// `Config.decodeYaml : String -> Decoder a -> Result Error a`.
    ConfigDecodeYaml,
    /// `Config.decodeJson : String -> Decoder a -> Result Error a`.
    ConfigDecodeJson,
    /// `Config.loadFromFile : String -> Decoder a -> Task Error a`.
    ConfigLoadFromFile,
    // ── Ipe.Email — provider-abstract email send ──────────────────────
    // Task-effectful; runtime `ipe_runtime::email::email_send`. Routed via the
    // compiled-source `Ipe.Email` Layer-3 surface + `Kernel.kernel "Email_send"`.
    // Class `Pure` (the effect lives in the `Task` scheme, same as File/Http).
    // Takes the runtime `EmailProvider` enum + `EmailMessage` struct (the Ipê
    // ADT / record aliases fold to those nominal runtime types).
    /// `Email.send : EmailProvider -> EmailMessage -> Task Error String`.
    EmailSend,

    // ── Ipe.Crypto typed-key newtypes ─────────────────────────────────
    // Opaque role-typed newtypes carrying `Key`/`Mac` runtime types from
    // `ipe_runtime::crypto`.  All are Pure (no side-effect).  The AEAD and
    // key-derivation kernels themselves require/return `Key` (see the raw
    // `CryptoAesGcmEncrypt` etc. entries above) — there is no bare-`String`-key
    // spelling for encrypt/decrypt/derive.
    /// `Key.fromString : String -> Key` — the ONLY constructor; parse boundary.
    CryptoKeyFromString,
    /// `Key.fromBytes : String -> Key` — construction boundary for byte-string callers.
    CryptoKeyFromBytes,
    /// `Mac.toHex : Mac -> String` — the single extraction boundary for MAC output.
    CryptoMacToHex,
    /// `Crypto.hmacSha256WithKey : Key -> String -> Mac` — typed HMAC-SHA256.
    CryptoHmacSha256WithKey,
    /// `Crypto.hmacSha512WithKey : Key -> String -> Mac` — typed HMAC-SHA512.
    CryptoHmacSha512WithKey,

    // ── Ipe.Email.EmailAddress — typed parse-don't-validate boundary ───
    // Additive API: `EmailAddress.parse` is the only constructor; downstream
    // code never sees the raw `String`.  `EmailAddress.toString` is the single
    // extraction boundary.  Both are Pure.
    /// `EmailAddress.parse : String -> Maybe EmailAddress` — parse boundary.
    EmailAddressParse,
    /// `EmailAddress.toString : EmailAddress -> String` — single extraction boundary.
    EmailAddressToString,

    // ── Ipe.Url — typed, validated URLs (parse-don't-validate) ─────────────
    // Pure, total kernels routed via the compiled-source `Ipe.Url` Layer-3
    // surface + `Kernel.kernel "Url_*"` aliases. `Url` is an opaque, validated
    // type: the ONLY constructor is `UrlFromString` (the parse seal that rejects
    // a scheme-less / unparseable string); the accessors take a `Url`, never a
    // raw `String`. Runtime fns live in `ipe_runtime::url::*`.
    /// `Url.fromString : String -> Result Error Url` — THE seal; the only
    /// constructor. An unparseable / relative URL is a typed `Err`.
    UrlFromString,
    /// `Url.toString : Url -> String` — THE un-parse; recover the URL string.
    UrlToString,
    /// `Url.scheme : Url -> String` — the URL's scheme (always present).
    UrlScheme,
    /// `Url.host : Url -> Maybe String` — the host, or `Nothing` (hostless scheme).
    UrlHost,
    /// `Url.port : Url -> Maybe Int` — port (scheme default applied), or `Nothing`.
    UrlPort,
    /// `Url.path : Url -> String` — the path component.
    UrlPath,
    /// `Url.query : Url -> Maybe String` — the raw query (no `?`), or `Nothing`.
    UrlQuery,
    /// `Url.fragment : Url -> Maybe String` — the fragment (no `#`), or `Nothing`.
    UrlFragment,
    /// `Url.schemeShown : Url -> String` — the scheme as an error message may
    /// show it: a well-known scheme quoted, any other withheld (a user name
    /// can parse as the scheme). Private to `Ipe.Url`; backs `checkScheme`.
    UrlSchemeShown,
    /// `Url.buildQuery : List (String, String) -> String` — the injection-safe
    /// query-string builder; every key/value is percent-encoded.
    UrlBuildQuery,
    /// `Url.relative : String -> Result Error Relative` — THE seal for a
    /// same-origin relative reference. Resolves `raw` against a fixed same-origin
    /// base with the `url` crate and REJECTS any scheme/authority (the
    /// browser-href SSRF boundary). The ONLY `Relative` constructor.
    UrlRelativeParse,
    /// `Url.Relative.path : Relative -> String` — the path projection (always
    /// present: `/`, `/a/b`, `./x`).
    UrlRelativePath,
    /// `Url.Relative.query : Relative -> Maybe String` — the query (no `?`).
    UrlRelativeQuery,
    /// `Url.Relative.fragment : Relative -> Maybe String` — the fragment (no `#`).
    UrlRelativeFragment,
    /// `Url.Relative.toString : Relative -> String` — recover the reference.
    UrlRelativeToString,
    // ── Ipe.Locale — opaque BCP-47 locale handle ─────────────────────────
    // Parse-don't-validate: `Locale.fromTag` is the only constructor; an invalid
    // BCP-47 tag is `Nothing`, never a silent default.  `Locale.toTag` is the
    // single extraction boundary.  `String.toUpperIn`/`toLowerIn` are the
    // locale-aware case-mapping kernels.  All four are Pure.
    /// `Locale.fromTag : String -> Maybe Locale` — BCP-47 parse boundary.
    LocaleFromTag,
    /// `Locale.toTag : Locale -> String` — recover the BCP-47 tag.
    LocaleToTag,
    /// `String.toUpperIn : Locale -> String -> String` — locale-correct upper-case.
    StringToUpperIn,
    /// `String.toLowerIn : Locale -> String -> String` — locale-correct lower-case.
    StringToLowerIn,
    // ── Ipe.Color constructor kernels (produce the unified `color::Color`) ──
    /// `Color.rgb : Int -> Int -> Int -> Color` — opaque sRGB colour, alpha = 1.
    ColorRgb,
    /// `Color.rgba : Int -> Int -> Int -> Float -> Color` — sRGB colour with alpha.
    ColorRgba,
    /// `Color.hsl : Float -> Float -> Float -> Color` — HSL colour, alpha = 1.
    ColorHsl,
    /// `Color.hsla : Float -> Float -> Float -> Float -> Color` — HSL colour with alpha.
    ColorHsla,
    /// `Color.white : Color`
    ColorWhite,
    /// `Color.black : Color`
    ColorBlack,
    /// `Color.red : Color`
    ColorRed,
    /// `Color.green : Color`
    ColorGreen,
    /// `Color.blue : Color`
    ColorBlue,
    /// `Color.transparent : Color` — fully transparent.
    ColorTransparent,
    // ── Ipe.Color accessor + manipulation kernels ──
    /// `Color.toCss : Color -> String` — CSS `rgb()/rgba()` spelling.
    ColorToCss,
    /// `Color.toCssRgba : Color -> String` — always the four-channel `rgba()` form.
    ColorToCssRgba,
    /// `Color.toHex : Color -> String` — `#rrggbb`/`#rrggbbaa` hex spelling.
    ColorToHex,
    /// `Color.luminance : Color -> Float` — WCAG relative luminance.
    ColorLuminance,
    /// `Color.withAlpha : Float -> Color -> Color` — replace the alpha channel.
    ColorWithAlpha,
    /// `Color.mix : Float -> Color -> Color -> Color` — perceptual blend at `t`.
    ColorMix,
    /// `Color.blend : Color -> Color -> Color` — source-over alpha compositing.
    ColorBlend,
    /// `Color.lighten : Float -> Color -> Color` — raise HSL lightness.
    ColorLighten,
    /// `Color.darken : Float -> Color -> Color` — lower HSL lightness.
    ColorDarken,
    /// `Color.saturate : Float -> Color -> Color` — raise HSL saturation.
    ColorSaturate,
    /// `Color.desaturate : Float -> Color -> Color` — lower HSL saturation.
    ColorDesaturate,
    /// `Color.rotateHue : Float -> Color -> Color` — rotate the hue by degrees.
    ColorRotateHue,
    /// `Color.complementary : Color -> Color` — the 180°-rotated hue.
    ColorComplementary,
    /// `Color.grayscale : Color -> Color` — desaturate fully to grey.
    ColorGrayscale,
    // ── Ipe.Color parse boundary (typed `Result ColorError Color`) ──
    /// `Color.fromHex : String -> Result ColorError Color` — parse a hex string.
    ColorFromHex,
    /// `Color.fromName : String -> Result ColorError Color` — parse a named colour.
    ColorFromName,
    // ── Ipe.Color terminal-profile constructors (nullary `TermProfile`) ──
    /// `Color.trueColorProfile : TermProfile` — 24-bit truecolour target.
    ColorTrueColorProfile,
    /// `Color.ansi256Profile : TermProfile` — 256-colour xterm target.
    ColorAnsi256Profile,
    /// `Color.ansi16Profile : TermProfile` — 16 SGR-palette target.
    ColorAnsi16Profile,
    /// `Color.noColorProfile : TermProfile` — degrade everything to default.
    ColorNoColorProfile,
    /// `Color.toAnsi : TermProfile -> Color -> AnsiColor` — down-sample a colour.
    ColorToAnsi,
    // ── Ipe.Color WCAG / contrast (a11y) ──
    /// `Color.wcagAa : WcagLevel` — the WCAG AA conformance level.
    ColorWcagAa,
    /// `Color.wcagAaa : WcagLevel` — the WCAG AAA conformance level.
    ColorWcagAaa,
    /// `Color.normalText : TextSize` — the normal-size text band.
    ColorNormalText,
    /// `Color.largeText : TextSize` — the large-text band.
    ColorLargeText,
    /// `Color.contrastRatio : Color -> Color -> Float` — WCAG contrast ratio.
    ColorContrastRatio,
    /// `Color.readableTextOn : Color -> Color` — black or white for legibility.
    ColorReadableTextOn,
    /// `Color.meetsWcag : WcagLevel -> TextSize -> Color -> Color -> Bool`.
    ColorMeetsWcag,
    /// `Color.maximumContrast : Color -> List Color -> Color` — best candidate.
    ColorMaximumContrast,
    // ── Ipe.Color colour-vision-deficiency simulation ──
    /// `Color.protanopia : Deficiency` — red-blind.
    ColorProtanopia,
    /// `Color.deuteranopia : Deficiency` — green-blind.
    ColorDeuteranopia,
    /// `Color.tritanopia : Deficiency` — blue-blind.
    ColorTritanopia,
    /// `Color.simulate : Deficiency -> Color -> Color` — CVD preview.
    ColorSimulate,
}

impl StdlibKernel {
    /// The co-locatable identity + emit facts of this kernel — its qualifier,
    /// source name, arity, emit class, and runtime symbol.
    ///
    /// This is the ONE authoritative `match self` over the whole registry for
    /// those five facts. [`Self::def`] aggregates it with the two axis-specific
    /// sources ([`Self::capability`], [`Self::required_runtime_module`]) into the
    /// full kernel row; [`Self::decl`] projects the row back down to this subset.
    /// The subset is expressed as a [`StdlibDecl`] because that struct already
    /// holds exactly these fields and is `'static`/`Copy` (`const`-embeddable).
    #[must_use]
    #[allow(clippy::too_many_lines)]
    const fn identity(self) -> StdlibDecl {
        // Shorthand constructor to keep each arm concise.
        const fn d(
            qualifier: &'static str,
            name: &'static str,
            arity: u8,
            class: KernelClass,
            emit: &'static str,
            arg_order: ArgOrder,
        ) -> StdlibDecl {
            StdlibDecl {
                qualifier,
                name,
                arity,
                class,
                emit,
                arg_order,
            }
        }
        use ArgOrder::{ContainerFirst, IpeOrder};
        use KernelClass::{Db, Pure, Server, Tea, Terminal, Ui, Web};
        match self {
            // ── Log ─────────────────────────────────────────────────────────
            // Qualifier "Log" is installed via `install_builtin_vars` as an
            // unqualified name; it is NOT in the canon `QUALIFIERS` table.
            // The tripwire test skips it because "Log" is absent from
            // `env.qual_vars`.
            Self::LogInfo => d("Log", "info", 1, Pure, "log_info", IpeOrder),
            Self::LogDebug => d("Log", "debug", 1, Pure, "log_debug", IpeOrder),
            Self::LogWarn => d("Log", "warn", 1, Pure, "log_warn", IpeOrder),
            Self::LogError => d("Log", "error", 1, Pure, "log_error", IpeOrder),
            Self::LogInfoWith => d("Log", "infoWith", 2, Pure, "log_info_with", IpeOrder),
            Self::LogDebugWith => d("Log", "debugWith", 2, Pure, "log_debug_with", IpeOrder),
            Self::LogWarnWith => d("Log", "warnWith", 2, Pure, "log_warn_with", IpeOrder),
            Self::LogErrorWith => d("Log", "errorWith", 2, Pure, "log_error_with", IpeOrder),
            // ── String ──────────────────────────────────────────────────────
            Self::StringFromInt => d("String", "fromInt", 1, Pure, "string_from_int", IpeOrder),
            Self::StringFromFloat => d(
                "String",
                "fromFloat",
                1,
                Pure,
                "string_from_float",
                IpeOrder,
            ),
            Self::StringLength => d("String", "length", 1, Pure, "string_length", IpeOrder),
            Self::StringIsEmpty => d("String", "isEmpty", 1, Pure, "string_is_empty", IpeOrder),
            Self::StringReverse => d("String", "reverse", 1, Pure, "string_reverse", IpeOrder),
            Self::StringToUpper => d("String", "toUpper", 1, Pure, "string_to_upper", IpeOrder),
            Self::StringToLower => d("String", "toLower", 1, Pure, "string_to_lower", IpeOrder),
            Self::StringCasefold => d("String", "casefold", 1, Pure, "string_casefold", IpeOrder),
            Self::StringTrim => d("String", "trim", 1, Pure, "string_trim", IpeOrder),
            Self::StringTrimStart => d(
                "String",
                "trimStart",
                1,
                Pure,
                "string_trim_start",
                IpeOrder,
            ),
            Self::StringTrimEnd => d("String", "trimEnd", 1, Pure, "string_trim_end", IpeOrder),
            Self::StringToInt => d("String", "toInt", 1, Pure, "string_to_int", IpeOrder),
            Self::StringToFloat => d("String", "toFloat", 1, Pure, "string_to_float", IpeOrder),
            Self::StringFromChar => d("String", "fromChar", 1, Pure, "string_from_char", IpeOrder),
            Self::StringFromBool => d("String", "fromBool", 1, Pure, "string_from_bool", IpeOrder),
            Self::StringFromList => d("String", "fromList", 1, Pure, "string_from_list", IpeOrder),
            Self::StringConcat => d("String", "concat", 1, Pure, "string_concat", IpeOrder),
            Self::StringWords => d("String", "words", 1, Pure, "string_words", IpeOrder),
            Self::StringLines => d("String", "lines", 1, Pure, "string_lines", IpeOrder),
            Self::StringToList => d("String", "toList", 1, Pure, "string_to_list", IpeOrder),
            Self::StringIsEmail => d("String", "isEmail", 1, Pure, "string_is_email", IpeOrder),
            Self::StringIsUrl => d("String", "isUrl", 1, Pure, "string_is_url", IpeOrder),
            Self::StringAppend => d("String", "append", 2, Pure, "string_append", IpeOrder),
            Self::StringContains => d("String", "contains", 2, Pure, "string_contains", IpeOrder),
            Self::StringStartsWith => d(
                "String",
                "startsWith",
                2,
                Pure,
                "string_starts_with",
                IpeOrder,
            ),
            Self::StringEndsWith => d("String", "endsWith", 2, Pure, "string_ends_with", IpeOrder),
            Self::StringEqualFold => d(
                "String",
                "equalFold",
                2,
                Pure,
                "string_equal_fold",
                IpeOrder,
            ),
            Self::StringJoin => d("String", "join", 2, Pure, "string_join", IpeOrder),
            Self::StringSplit => d("String", "split", 2, Pure, "string_split", IpeOrder),
            Self::StringRepeat => d("String", "repeat", 2, Pure, "string_repeat", IpeOrder),
            Self::StringDropLeft => d("String", "dropLeft", 2, Pure, "string_drop_left", IpeOrder),
            Self::StringDropRight => d(
                "String",
                "dropRight",
                2,
                Pure,
                "string_drop_right",
                IpeOrder,
            ),
            Self::StringReplace => d("String", "replace", 3, Pure, "string_replace", IpeOrder),
            Self::StringSlice => d("String", "slice", 3, Pure, "string_slice", IpeOrder),
            Self::StringPadLeft => d("String", "padLeft", 3, Pure, "string_pad_left", IpeOrder),
            Self::StringPadRight => d("String", "padRight", 3, Pure, "string_pad_right", IpeOrder),
            Self::StringContainsIn => d(
                "String",
                "containsIn",
                2,
                Pure,
                "string_contains_in",
                IpeOrder,
            ),
            Self::StringStartsWithIn => d(
                "String",
                "startsWithIn",
                2,
                Pure,
                "string_starts_with_in",
                IpeOrder,
            ),
            Self::StringEndsWithIn => d(
                "String",
                "endsWithIn",
                2,
                Pure,
                "string_ends_with_in",
                IpeOrder,
            ),
            Self::StringLeft => d("String", "left", 2, Pure, "string_left", IpeOrder),
            Self::StringRight => d("String", "right", 2, Pure, "string_right", IpeOrder),
            Self::StringCons => d("String", "cons", 2, Pure, "string_cons", IpeOrder),
            Self::StringUncons => d("String", "uncons", 1, Pure, "string_uncons", IpeOrder),
            Self::StringPad => d("String", "pad", 3, Pure, "string_pad", IpeOrder),
            Self::StringIndexes => d("String", "indexes", 2, Pure, "string_indexes", IpeOrder),
            Self::StringMap => d("String", "map", 2, Pure, "string_map", IpeOrder),
            Self::StringFilter => d("String", "filter", 2, Pure, "string_filter", IpeOrder),
            Self::StringFoldl => d("String", "foldl", 3, Pure, "string_foldl", IpeOrder),
            Self::StringFoldr => d("String", "foldr", 3, Pure, "string_foldr", IpeOrder),
            Self::StringAny => d("String", "any", 2, Pure, "string_any", IpeOrder),
            Self::StringAll => d("String", "all", 2, Pure, "string_all", IpeOrder),
            // ── Char ────────────────────────────────────────────────────────
            Self::CharIsAlpha => d("Char", "isAlpha", 1, Pure, "char_is_alpha", IpeOrder),
            Self::CharIsDigit => d("Char", "isDigit", 1, Pure, "char_is_digit", IpeOrder),
            Self::CharIsLower => d("Char", "isLower", 1, Pure, "char_is_lower", IpeOrder),
            Self::CharIsUpper => d("Char", "isUpper", 1, Pure, "char_is_upper", IpeOrder),
            Self::CharToLower => d("Char", "toLower", 1, Pure, "char_to_lower", IpeOrder),
            Self::CharToUpper => d("Char", "toUpper", 1, Pure, "char_to_upper", IpeOrder),
            Self::CharToCode => d("Char", "toCode", 1, Pure, "char_to_code", IpeOrder),
            Self::CharFromCode => d("Char", "fromCode", 1, Pure, "char_from_code", IpeOrder),
            Self::CharIsAlphaNum => d("Char", "isAlphaNum", 1, Pure, "char_is_alpha_num", IpeOrder),
            Self::CharIsHexDigit => d("Char", "isHexDigit", 1, Pure, "char_is_hex_digit", IpeOrder),
            Self::CharIsOctDigit => d("Char", "isOctDigit", 1, Pure, "char_is_oct_digit", IpeOrder),
            // ── List ────────────────────────────────────────────────────────
            Self::ListMap => d("List", "map", 2, Pure, "list_map_consume", IpeOrder),
            Self::ListFilter => d("List", "filter", 2, Pure, "list_filter", IpeOrder),
            Self::ListFoldl => d("List", "foldl", 3, Pure, "list_foldl", IpeOrder),
            Self::ListFoldr => d("List", "foldr", 3, Pure, "list_foldr", IpeOrder),
            Self::ListLength => d("List", "length", 1, Pure, "list_length", IpeOrder),
            Self::ListHead => d("List", "head", 1, Pure, "list_head", IpeOrder),
            Self::ListTail => d("List", "tail", 1, Pure, "list_tail", IpeOrder),
            Self::ListMember => d("List", "member", 2, Pure, "list_member", IpeOrder),
            Self::ListRange => d("List", "range", 2, Pure, "list_range", IpeOrder),
            Self::ListReverse => d("List", "reverse", 1, Pure, "list_reverse", IpeOrder),
            Self::ListAppend => d("List", "append", 2, Pure, "list_append", IpeOrder),
            Self::ListConcat => d("List", "concat", 1, Pure, "list_concat", IpeOrder),
            Self::ListTake => d("List", "take", 2, Pure, "list_take", IpeOrder),
            Self::ListDrop => d("List", "drop", 2, Pure, "list_drop", IpeOrder),
            Self::ListZip => d("List", "zip", 2, Pure, "list_zip", IpeOrder),
            Self::ListCons => d("List", "cons", 2, Pure, "ipe_list_cons", IpeOrder),
            Self::ListIsEmpty => d("List", "isEmpty", 1, Pure, "list_is_empty", IpeOrder),
            Self::ListConcatMap => d("List", "concatMap", 2, Pure, "list_concat_map", IpeOrder),
            Self::ListIndexedMap => d("List", "indexedMap", 2, Pure, "list_indexed_map", IpeOrder),
            Self::ListAny => d("List", "any", 2, Pure, "list_any", IpeOrder),
            Self::ListAll => d("List", "all", 2, Pure, "list_all", IpeOrder),
            Self::ListFind => d("List", "find", 2, Pure, "list_find", IpeOrder),
            // ── List batch ────────────────────────────────────────────
            Self::ListFilterMap => d("List", "filterMap", 2, Pure, "list_filter_map", IpeOrder),
            Self::ListSortBy => d("List", "sortBy", 2, Pure, "list_sort_by", IpeOrder),
            Self::ListSort => d("List", "sort", 1, Pure, "list_sort", IpeOrder),
            Self::ListSortWith => d(
                "List",
                "sortWith",
                2,
                Pure,
                "list_sort_with_order",
                IpeOrder,
            ),
            Self::ListSingleton => d("List", "singleton", 1, Pure, "list_singleton", IpeOrder),
            Self::ListRepeat => d("List", "repeat", 2, Pure, "list_repeat", IpeOrder),
            Self::ListSum => d("List", "sum", 1, Pure, "list_sum", IpeOrder),
            Self::ListProduct => d("List", "product", 1, Pure, "list_product", IpeOrder),
            Self::ListMaximum => d("List", "maximum", 1, Pure, "list_maximum", IpeOrder),
            Self::ListMinimum => d("List", "minimum", 1, Pure, "list_minimum", IpeOrder),
            Self::ListUnique => d("List", "unique", 1, Pure, "list_unique", IpeOrder),
            Self::ListIntersperse => {
                d("List", "intersperse", 2, Pure, "list_intersperse", IpeOrder)
            }
            Self::ListPartition => d("List", "partition", 2, Pure, "list_partition", IpeOrder),
            Self::ListUnzip => d("List", "unzip", 1, Pure, "list_unzip", IpeOrder),
            Self::ListMap2 => d("List", "map2", 3, Pure, "list_map2", IpeOrder),
            Self::ListMap3 => d("List", "map3", 4, Pure, "list_map3", IpeOrder),
            Self::ListMap4 => d("List", "map4", 5, Pure, "list_map4", IpeOrder),
            Self::ListMap5 => d("List", "map5", 6, Pure, "list_map5", IpeOrder),
            Self::BasicsNot => d("Basics", "not", 1, Pure, "basics_not", IpeOrder),
            Self::BasicsIdentity => d("Basics", "identity", 1, Pure, "basics_identity", IpeOrder),
            Self::BasicsAlways => d("Basics", "always", 2, Pure, "basics_always", IpeOrder),
            Self::BasicsFst => d("Basics", "fst", 1, Pure, "basics_fst", IpeOrder),
            Self::BasicsSnd => d("Basics", "snd", 1, Pure, "basics_snd", IpeOrder),
            Self::BasicsModBy => d("Basics", "modBy", 2, Pure, "basics_mod_by", IpeOrder),
            Self::BasicsClamp => d("Basics", "clamp", 3, Pure, "basics_clamp", IpeOrder),
            // ── Basics numerics ──────────────────────────────────────────
            Self::BasicsNegate => d("Basics", "negate", 1, Pure, "basics_negate", IpeOrder),
            Self::BasicsAbs => d("Basics", "abs", 1, Pure, "basics_abs", IpeOrder),
            Self::BasicsSqrt => d("Basics", "sqrt", 1, Pure, "math_sqrt", IpeOrder),
            Self::BasicsMin => d("Basics", "min", 2, Pure, "math_min", IpeOrder),
            Self::BasicsMax => d("Basics", "max", 2, Pure, "math_max", IpeOrder),
            Self::BasicsCompare => d("Basics", "compare", 2, Pure, "basics_compare", IpeOrder),
            // ── end Basics numerics ──────────────────────────────────────
            // ── Error (Ipe.Error — real Error/ErrorKind ADT) ──
            // Each message constructor classifies its own `ErrorKind` at
            // construction (`ipe_runtime::error::IpeError`, no longer a
            // shared string-identity). `toString` reuses the existing
            // `errorToString` runtime (`basics_error_to_string`).
            Self::ErrorUnexpected => d(
                "Error",
                "unexpected",
                1,
                Pure,
                "ipe_error_unexpected",
                IpeOrder,
            ),
            Self::ErrorInvalidInput => d(
                "Error",
                "invalidInput",
                1,
                Pure,
                "ipe_error_invalid_input",
                IpeOrder,
            ),
            Self::ErrorIo => d("Error", "io", 1, Pure, "ipe_error_io", IpeOrder),
            Self::ErrorNetwork => d("Error", "network", 1, Pure, "ipe_error_network", IpeOrder),
            Self::ErrorFfi => d("Error", "ffi", 1, Pure, "ipe_error_ffi", IpeOrder),
            Self::ErrorDecode => d("Error", "decode", 1, Pure, "ipe_error_decode", IpeOrder),
            Self::ErrorConflict => d("Error", "conflict", 1, Pure, "ipe_error_conflict", IpeOrder),
            Self::ErrorUnavailable => d(
                "Error",
                "unavailable",
                1,
                Pure,
                "ipe_error_unavailable",
                IpeOrder,
            ),
            Self::ErrorTimeout => d("Error", "timeout", 0, Pure, "ipe_error_timeout", IpeOrder),
            Self::ErrorNotFound => d(
                "Error",
                "notFound",
                0,
                Pure,
                "ipe_error_not_found",
                IpeOrder,
            ),
            Self::ErrorPermissionDenied => d(
                "Error",
                "permissionDenied",
                0,
                Pure,
                "ipe_error_permission_denied",
                IpeOrder,
            ),
            Self::ErrorToString => d(
                "Error",
                "toString",
                1,
                Pure,
                "basics_error_to_string",
                IpeOrder,
            ),
            Self::ErrorWithMessage => d(
                "Error",
                "withMessage",
                2,
                Pure,
                "ipe_error_with_message",
                IpeOrder,
            ),
            Self::ErrorIsRetryable => d(
                "Error",
                "isRetryable",
                1,
                Pure,
                "ipe_error_is_retryable",
                IpeOrder,
            ),
            Self::ErrorWithDetails => d(
                "Error",
                "withDetails",
                2,
                Pure,
                "ipe_error_with_details",
                IpeOrder,
            ),
            Self::ErrorKind => d("Error", "kind", 1, Pure, "ipe_error_kind", IpeOrder),
            Self::ErrorMessage => d("Error", "message", 1, Pure, "ipe_error_message", IpeOrder),
            Self::ErrorKindName => d(
                "Error",
                "kindName",
                1,
                Pure,
                "ipe_error_kind_name",
                IpeOrder,
            ),
            // ── CssSafety (Ipe.CssSafety — Ipe.Css leaf kernels) ────
            // The `emit` symbols are the bare runtime fn names re-exported at the
            // `ipe_runtime` root (`pub use css::*`): `safe_value` /
            // `safe_prop_name` / `safe_selector` / `strip_style_close_kernel`.
            Self::CssSafetySafeValue => {
                d("CssSafety", "safeValue", 1, Pure, "safe_value", IpeOrder)
            }
            Self::CssSafetySafePropName => d(
                "CssSafety",
                "safePropName",
                1,
                Pure,
                "safe_prop_name",
                IpeOrder,
            ),
            Self::CssSafetySafeSelector => d(
                "CssSafety",
                "safeSelector",
                1,
                Pure,
                "safe_selector",
                IpeOrder,
            ),
            Self::CssSafetyStripStyleClose => d(
                "CssSafety",
                "stripStyleClose",
                1,
                Pure,
                "strip_style_close_kernel",
                IpeOrder,
            ),
            Self::CssSafetySanitizeRawBody => d(
                "CssSafety",
                "sanitizeRawBody",
                1,
                Pure,
                "safe_raw_body",
                IpeOrder,
            ),
            // ── Maybe ───────────────────────────────────────────────────────
            Self::MaybeWithDefault => d(
                "Maybe",
                "withDefault",
                2,
                Pure,
                "maybe_with_default",
                IpeOrder,
            ),
            Self::MaybeMap => d("Maybe", "map", 2, Pure, "ipe_maybe_map", ContainerFirst),
            Self::MaybeAndThen => d(
                "Maybe",
                "andThen",
                2,
                Pure,
                "ipe_maybe_and_then",
                ContainerFirst,
            ),
            // `mapN` arity = 1 (fn) + N containers; `andMap` = 2; `combine` = 1.
            Self::MaybeMap2 => d("Maybe", "map2", 3, Pure, "maybe_map2", IpeOrder),
            Self::MaybeMap3 => d("Maybe", "map3", 4, Pure, "maybe_map3", IpeOrder),
            Self::MaybeMap4 => d("Maybe", "map4", 5, Pure, "maybe_map4", IpeOrder),
            Self::MaybeMap5 => d("Maybe", "map5", 6, Pure, "maybe_map5", IpeOrder),
            Self::MaybeAndMap => d("Maybe", "andMap", 2, Pure, "maybe_and_map", IpeOrder),
            Self::MaybeCombine => d("Maybe", "combine", 1, Pure, "maybe_combine", IpeOrder),
            Self::MaybeIsJust => d("Maybe", "isJust", 1, Pure, "maybe_is_just", IpeOrder),
            Self::MaybeIsNothing => d("Maybe", "isNothing", 1, Pure, "maybe_is_nothing", IpeOrder),
            // ── Result ──────────────────────────────────────────────────────
            Self::ResultWithDefault => d(
                "Result",
                "withDefault",
                2,
                Pure,
                "result_with_default",
                IpeOrder,
            ),
            Self::ResultMap => d("Result", "map", 2, Pure, "ipe_result_map", ContainerFirst),
            Self::ResultAndThen => d(
                "Result",
                "andThen",
                2,
                Pure,
                "ipe_result_and_then",
                ContainerFirst,
            ),
            Self::ResultMapError => d(
                "Result",
                "mapError",
                2,
                Pure,
                "ipe_result_map_error",
                ContainerFirst,
            ),
            Self::ResultMap2 => d("Result", "map2", 3, Pure, "result_map2", IpeOrder),
            Self::ResultMap3 => d("Result", "map3", 4, Pure, "result_map3", IpeOrder),
            Self::ResultMap4 => d("Result", "map4", 5, Pure, "result_map4", IpeOrder),
            Self::ResultMap5 => d("Result", "map5", 6, Pure, "result_map5", IpeOrder),
            Self::ResultAndMap => d("Result", "andMap", 2, Pure, "result_and_map", IpeOrder),
            Self::ResultCombine => d("Result", "combine", 1, Pure, "result_combine", IpeOrder),
            Self::ResultTraverse => d("Result", "traverse", 2, Pure, "result_traverse", IpeOrder),
            Self::ResultToMaybe => d(
                "Result",
                "toMaybe",
                1,
                Pure,
                "ipe_result_to_maybe",
                IpeOrder,
            ),
            Self::ResultFromMaybe => d(
                "Result",
                "fromMaybe",
                2,
                Pure,
                "ipe_result_from_maybe",
                IpeOrder,
            ),
            // Internal: qualifier starts with '_' → skipped by tripwire test.
            Self::ResultOkDefault => d("_internal_", "okDefault", 1, Pure, "ok_res", IpeOrder),
            Self::Interpolate => d(
                "_internal_",
                "interpolate",
                1,
                Pure,
                "interpolate_to_string",
                IpeOrder,
            ),
            // ── Math ────────────────────────────────────────────────────────
            Self::MathMin => d("Math", "min", 2, Pure, "math_min", IpeOrder),
            Self::MathMax => d("Math", "max", 2, Pure, "math_max", IpeOrder),
            Self::MathPi => d("Math", "pi", 0, Pure, "math_pi", IpeOrder),
            Self::MathE => d("Math", "e", 0, Pure, "math_e", IpeOrder),
            Self::MathPhi => d("Math", "phi", 0, Pure, "math_phi", IpeOrder),
            Self::MathSqrt2 => d("Math", "sqrt2", 0, Pure, "math_sqrt2", IpeOrder),
            Self::MathInf => d("Math", "inf", 0, Pure, "math_inf", IpeOrder),
            Self::MathNan => d("Math", "nan", 0, Pure, "math_nan", IpeOrder),
            Self::MathIsNaN => d("Math", "isNaN", 1, Pure, "math_is_nan", IpeOrder),
            Self::MathAbs => d("Math", "abs", 1, Pure, "math_abs", IpeOrder),
            Self::MathSqrt => d("Math", "sqrt", 1, Pure, "math_sqrt", IpeOrder),
            Self::MathCbrt => d("Math", "cbrt", 1, Pure, "math_cbrt", IpeOrder),
            Self::MathExp => d("Math", "exp", 1, Pure, "math_exp", IpeOrder),
            Self::MathExp2 => d("Math", "exp2", 1, Pure, "math_exp2", IpeOrder),
            Self::MathLog => d("Math", "log", 1, Pure, "math_log", IpeOrder),
            Self::MathLog2 => d("Math", "log2", 1, Pure, "math_log2", IpeOrder),
            Self::MathLog10 => d("Math", "log10", 1, Pure, "math_log10", IpeOrder),
            Self::MathSin => d("Math", "sin", 1, Pure, "math_sin", IpeOrder),
            Self::MathCos => d("Math", "cos", 1, Pure, "math_cos", IpeOrder),
            Self::MathTan => d("Math", "tan", 1, Pure, "math_tan", IpeOrder),
            Self::MathAsin => d("Math", "asin", 1, Pure, "math_asin", IpeOrder),
            Self::MathAcos => d("Math", "acos", 1, Pure, "math_acos", IpeOrder),
            Self::MathAtan => d("Math", "atan", 1, Pure, "math_atan", IpeOrder),
            Self::MathSinh => d("Math", "sinh", 1, Pure, "math_sinh", IpeOrder),
            Self::MathCosh => d("Math", "cosh", 1, Pure, "math_cosh", IpeOrder),
            Self::MathTanh => d("Math", "tanh", 1, Pure, "math_tanh", IpeOrder),
            Self::MathAsinh => d("Math", "asinh", 1, Pure, "math_asinh", IpeOrder),
            Self::MathAcosh => d("Math", "acosh", 1, Pure, "math_acosh", IpeOrder),
            Self::MathAtanh => d("Math", "atanh", 1, Pure, "math_atanh", IpeOrder),
            Self::MathFloor => d("Math", "floor", 1, Pure, "math_floor", IpeOrder),
            Self::MathCeil => d("Math", "ceil", 1, Pure, "math_ceil", IpeOrder),
            Self::MathRound => d("Math", "round", 1, Pure, "math_round", IpeOrder),
            Self::MathTrunc => d("Math", "trunc", 1, Pure, "math_trunc", IpeOrder),
            Self::MathPow => d("Math", "pow", 2, Pure, "math_pow", IpeOrder),
            Self::MathHypot => d("Math", "hypot", 2, Pure, "math_hypot", IpeOrder),
            Self::MathAtan2 => d("Math", "atan2", 2, Pure, "math_atan2", IpeOrder),
            Self::MathMod => d("Math", "mod", 2, Pure, "math_mod", IpeOrder),
            Self::MathRemainder => d("Math", "remainder", 2, Pure, "math_remainder", IpeOrder),
            // ── Bitwise ──────────────────────────────────────────────────────
            Self::BitwiseAnd => d("Bitwise", "and", 2, Pure, "bitwise_and", IpeOrder),
            Self::BitwiseOr => d("Bitwise", "or", 2, Pure, "bitwise_or", IpeOrder),
            Self::BitwiseXor => d("Bitwise", "xor", 2, Pure, "bitwise_xor", IpeOrder),
            Self::BitwiseComplement => d(
                "Bitwise",
                "complement",
                1,
                Pure,
                "bitwise_complement",
                IpeOrder,
            ),
            Self::BitwiseShiftLeftBy => d(
                "Bitwise",
                "shiftLeftBy",
                2,
                Pure,
                "bitwise_shift_left_by",
                IpeOrder,
            ),
            Self::BitwiseShiftRightBy => d(
                "Bitwise",
                "shiftRightBy",
                2,
                Pure,
                "bitwise_shift_right_by",
                IpeOrder,
            ),
            Self::BitwiseShiftRightZfBy => d(
                "Bitwise",
                "shiftRightZfBy",
                2,
                Pure,
                "bitwise_shift_right_zf_by",
                IpeOrder,
            ),
            // ── Random seeded (Generator primitives) ─────────────────────────
            Self::RandomSeededInt => d(
                "Random",
                "seededIntRaw",
                3,
                Pure,
                "random_seeded_int",
                IpeOrder,
            ),
            Self::RandomSeededFloat => d(
                "Random",
                "seededFloatRaw",
                1,
                Pure,
                "random_seeded_float",
                IpeOrder,
            ),
            Self::RandomSeededChoice => d(
                "Random",
                "seededChoiceRaw",
                2,
                Pure,
                "random_seeded_choice",
                IpeOrder,
            ),
            // ── Dict ────────────────────────────────────────────────────────
            Self::DictEmpty => d("Dict", "empty", 0, Pure, "dict_empty", IpeOrder),
            Self::DictIsEmpty => d("Dict", "isEmpty", 1, Pure, "dict_is_empty", IpeOrder),
            Self::DictSize => d("Dict", "size", 1, Pure, "dict_size", IpeOrder),
            Self::DictKeys => d("Dict", "keys", 1, Pure, "dict_keys", IpeOrder),
            Self::DictValues => d("Dict", "values", 1, Pure, "dict_values", IpeOrder),
            Self::DictToList => d("Dict", "toList", 1, Pure, "dict_to_list", IpeOrder),
            Self::DictFromList => d("Dict", "fromList", 1, Pure, "dict_from_list", IpeOrder),
            Self::DictGet => d("Dict", "get", 2, Pure, "dict_get", IpeOrder),
            Self::DictMember => d("Dict", "member", 2, Pure, "dict_member", IpeOrder),
            Self::DictRemove => d("Dict", "remove", 2, Pure, "dict_remove", IpeOrder),
            Self::DictUnion => d("Dict", "union", 2, Pure, "dict_union", IpeOrder),
            Self::DictMap => d("Dict", "map", 2, Pure, "dict_map", IpeOrder),
            Self::DictInsert => d("Dict", "insert", 3, Pure, "dict_insert", IpeOrder),
            Self::DictFoldl => d("Dict", "foldl", 3, Pure, "dict_foldl", IpeOrder),
            Self::DictSingleton => d("Dict", "singleton", 2, Pure, "dict_singleton", IpeOrder),
            Self::DictFoldr => d("Dict", "foldr", 3, Pure, "dict_foldr", IpeOrder),
            Self::DictFilter => d("Dict", "filter", 2, Pure, "dict_filter", IpeOrder),
            Self::DictPartition => d("Dict", "partition", 2, Pure, "dict_partition", IpeOrder),
            Self::DictIntersect => d("Dict", "intersect", 2, Pure, "dict_intersect", IpeOrder),
            Self::DictDiff => d("Dict", "diff", 2, Pure, "dict_diff", IpeOrder),
            Self::DictUpdate => d("Dict", "update", 3, Pure, "dict_update", IpeOrder),
            // ── Set ─────────────────────────────────────────────────────────
            Self::SetEmpty => d("Set", "empty", 0, Pure, "set_empty", IpeOrder),
            Self::SetSize => d("Set", "size", 1, Pure, "set_size", IpeOrder),
            Self::SetToList => d("Set", "toList", 1, Pure, "set_to_list", IpeOrder),
            Self::SetFromList => d("Set", "fromList", 1, Pure, "set_from_list", IpeOrder),
            Self::SetMember => d("Set", "member", 2, Pure, "set_member", IpeOrder),
            Self::SetInsert => d("Set", "insert", 2, Pure, "set_insert", IpeOrder),
            Self::SetRemove => d("Set", "remove", 2, Pure, "set_remove", IpeOrder),
            Self::SetUnion => d("Set", "union", 2, Pure, "set_union", IpeOrder),
            Self::SetIntersect => d("Set", "intersect", 2, Pure, "set_intersect", IpeOrder),
            Self::SetDiff => d("Set", "diff", 2, Pure, "set_diff", IpeOrder),
            Self::SetIsEmpty => d("Set", "isEmpty", 1, Pure, "set_is_empty", IpeOrder),
            Self::SetSingleton => d("Set", "singleton", 1, Pure, "set_singleton", IpeOrder),
            Self::SetFoldl => d("Set", "foldl", 3, Pure, "set_foldl", IpeOrder),
            Self::SetFoldr => d("Set", "foldr", 3, Pure, "set_foldr", IpeOrder),
            Self::SetMap => d("Set", "map", 2, Pure, "set_map", IpeOrder),
            Self::SetFilter => d("Set", "filter", 2, Pure, "set_filter", IpeOrder),
            Self::SetPartition => d("Set", "partition", 2, Pure, "set_partition", IpeOrder),
            // ── Bytes ───────────────────────────────────────────────────────
            Self::BytesEmpty => d("Bytes", "empty", 0, Pure, "bytes_empty", IpeOrder),
            Self::BytesLength => d("Bytes", "length", 1, Pure, "bytes_length", IpeOrder),
            Self::BytesIsEmpty => d("Bytes", "isEmpty", 1, Pure, "bytes_is_empty", IpeOrder),
            Self::BytesFromString => d(
                "Bytes",
                "fromString",
                1,
                Pure,
                "bytes_from_string",
                IpeOrder,
            ),
            Self::BytesToString => d("Bytes", "toString", 1, Pure, "bytes_to_string", IpeOrder),
            Self::BytesFromHex => d("Bytes", "fromHex", 1, Pure, "bytes_from_hex", IpeOrder),
            Self::BytesToHex => d("Bytes", "toHex", 1, Pure, "bytes_to_hex", IpeOrder),
            Self::BytesFromBase64 => d(
                "Bytes",
                "fromBase64",
                1,
                Pure,
                "bytes_from_base64",
                IpeOrder,
            ),
            Self::BytesToBase64 => d("Bytes", "toBase64", 1, Pure, "bytes_to_base64", IpeOrder),
            Self::BytesAppend => d("Bytes", "append", 2, Pure, "bytes_append", IpeOrder),
            Self::BytesSlice => d("Bytes", "slice", 3, Pure, "bytes_slice", IpeOrder),
            // ── Encoding ────────────────────────────────────────────────────
            Self::EncodingBase64Encode => d(
                "Encoding",
                "base64Encode",
                1,
                Pure,
                "base64_encode",
                IpeOrder,
            ),
            Self::EncodingBase64Decode => d(
                "Encoding",
                "base64Decode",
                1,
                Pure,
                "ipe_base64_decode",
                IpeOrder,
            ),
            Self::EncodingUrlEncode => d("Encoding", "urlEncode", 1, Pure, "url_encode", IpeOrder),
            Self::EncodingUrlDecode => {
                d("Encoding", "urlDecode", 1, Pure, "ipe_url_decode", IpeOrder)
            }
            Self::EncodingPercentDecode => d(
                "Encoding",
                "percentDecode",
                1,
                Pure,
                "ipe_percent_decode",
                IpeOrder,
            ),
            Self::EncodingHexEncode => d(
                "Encoding",
                "hexEncode",
                1,
                Pure,
                "encoding_hex_encode",
                IpeOrder,
            ),
            Self::EncodingHexDecode => d(
                "Encoding",
                "hexDecode",
                1,
                Pure,
                "ipe_encoding_hex_decode",
                IpeOrder,
            ),
            // ── Json.Encode ─────────────────────────────────────────────────
            Self::JsonEncString => d("JsonEnc", "string", 1, Pure, "json_enc_string", IpeOrder),
            Self::JsonEncInt => d("JsonEnc", "int", 1, Pure, "json_enc_int", IpeOrder),
            Self::JsonEncFloat => d("JsonEnc", "float", 1, Pure, "json_enc_float", IpeOrder),
            Self::JsonEncBool => d("JsonEnc", "bool", 1, Pure, "json_enc_bool", IpeOrder),
            Self::JsonEncNull => d("JsonEnc", "null", 0, Pure, "json_enc_null", IpeOrder),
            Self::JsonEncList => d("JsonEnc", "list", 2, Pure, "json_enc_list", IpeOrder),
            Self::JsonEncObject => d("JsonEnc", "object", 1, Pure, "json_enc_object", IpeOrder),
            Self::JsonEncEncode => d("JsonEnc", "encode", 2, Pure, "json_enc_encode", IpeOrder),
            // ── Json.Decode ─────────────────────────────────────────────────
            Self::JsonDecString => d("JsonDec", "string", 0, Pure, "json_decode_string", IpeOrder),
            Self::JsonDecInt => d("JsonDec", "int", 0, Pure, "json_decode_int", IpeOrder),
            Self::JsonDecFloat => d("JsonDec", "float", 0, Pure, "json_decode_float", IpeOrder),
            Self::JsonDecBool => d("JsonDec", "bool", 0, Pure, "json_decode_bool", IpeOrder),
            Self::JsonDecValue => d(
                "JsonDec",
                "value",
                0,
                Pure,
                "decode_value_identity",
                IpeOrder,
            ),
            Self::JsonDecDecodeString => d(
                "JsonDec",
                "decodeString",
                2,
                Pure,
                "decode_from_json_string",
                IpeOrder,
            ),
            Self::JsonDecDecodeValue => d(
                "JsonDec",
                "decodeValue",
                2,
                Pure,
                "decode_from_json_value",
                IpeOrder,
            ),
            Self::JsonDecField => d("JsonDec", "field", 2, Pure, "decode_field", IpeOrder),
            Self::JsonDecAt => d("JsonDec", "at", 2, Pure, "decode_at", IpeOrder),
            Self::JsonDecIndex => d("JsonDec", "index", 2, Pure, "decode_index", IpeOrder),
            Self::JsonDecList => d("JsonDec", "list", 1, Pure, "decode_list", IpeOrder),
            // `nullable` maps to the shared `decode_nullable` runtime builder in
            // the always-available `json` module — null ⇒ `Nothing`, any other
            // value ⇒ `Just` of the inner decode, with the inner error propagated
            // (never swallowed). One runtime impl serves JsonDec, Config, and
            // Db.Decode; it is NOT behind the `config` feature, so a pure-JSON
            // program pulls in neither `toml` nor `serde_yaml`.
            Self::JsonDecNullable => d("JsonDec", "nullable", 1, Pure, "decode_nullable", IpeOrder),
            Self::JsonDecMap => d("JsonDec", "map", 2, Pure, "decode_map", IpeOrder),
            Self::JsonDecAndThen => d(
                "JsonDec",
                "andThen",
                2,
                Pure,
                "decode_and_then",
                ContainerFirst,
            ),
            Self::JsonDecSucceed => d("JsonDec", "succeed", 1, Pure, "decode_succeed", IpeOrder),
            Self::JsonDecFail => d("JsonDec", "fail", 1, Pure, "decode_fail", IpeOrder),
            Self::JsonDecOneOf => d("JsonDec", "oneOf", 1, Pure, "decode_one_of", IpeOrder),
            Self::JsonDecMap2 => d("JsonDec", "map2", 3, Pure, "decode_map2", IpeOrder),
            Self::JsonDecMap3 => d("JsonDec", "map3", 4, Pure, "decode_map3", IpeOrder),
            Self::JsonDecMap4 => d("JsonDec", "map4", 5, Pure, "decode_map4", IpeOrder),
            // ── Json.Decode.Pipeline ────────────────────────────────────────
            Self::JsonDecPRequired => d(
                "JsonDecP",
                "required",
                3,
                Pure,
                "decode_pipeline_required",
                IpeOrder,
            ),
            Self::JsonDecPOptional => d(
                "JsonDecP",
                "optional",
                4,
                Pure,
                "decode_pipeline_optional",
                IpeOrder,
            ),
            Self::JsonDecPCustom => d(
                "JsonDecP",
                "custom",
                2,
                Pure,
                "decode_pipeline_custom",
                IpeOrder,
            ),
            Self::JsonDecPRequiredAt => d(
                "JsonDecP",
                "requiredAt",
                3,
                Pure,
                "decode_pipeline_required_at",
                IpeOrder,
            ),
            // ── Crypto ──────────────────────────────────────────────────────
            Self::CryptoSha256 => d("Crypto", "sha256", 1, Pure, "crypto_sha256", IpeOrder),
            Self::CryptoSha512 => d("Crypto", "sha512", 1, Pure, "crypto_sha512", IpeOrder),
            Self::CryptoSha1 => d("Crypto", "sha1", 1, Pure, "crypto_sha1", IpeOrder),
            Self::CryptoMd5 => d("Crypto", "md5", 1, Pure, "crypto_md5", IpeOrder),
            Self::CryptoRsaSha256Sign => d(
                "Crypto",
                "rsaSha256Sign",
                2,
                Pure,
                "ipe_crypto_rsa_sha256_sign",
                IpeOrder,
            ),
            Self::CryptoRsaSha256Verify => d(
                "Crypto",
                "rsaSha256Verify",
                3,
                Pure,
                "crypto_rsa_sha256_verify",
                IpeOrder,
            ),
            Self::CryptoConstantTimeEqual => d(
                "Crypto",
                "constantTimeEqual",
                2,
                Pure,
                "crypto_constant_time_equal",
                IpeOrder,
            ),
            // AEAD arity is 2 (key, plaintext/ciphertext): the Rust runtime
            // (`ipe_aes_gcm_encrypt(key, plaintext)` etc.) prepends/strips a
            // fresh random nonce internally, so — unlike the backend which
            // took an explicit nonce/AAD arg — there is no third argument.
            Self::CryptoAesGcmEncrypt => d(
                "Crypto",
                "aesGcmEncrypt",
                2,
                Pure,
                "ipe_aes_gcm_encrypt_key",
                IpeOrder,
            ),
            Self::CryptoAesGcmDecrypt => d(
                "Crypto",
                "aesGcmDecrypt",
                2,
                Pure,
                "ipe_aes_gcm_decrypt_key",
                IpeOrder,
            ),
            Self::CryptoChacha20Encrypt => d(
                "Crypto",
                "chacha20Encrypt",
                2,
                Pure,
                "ipe_chacha20_encrypt_key",
                IpeOrder,
            ),
            Self::CryptoChacha20Decrypt => d(
                "Crypto",
                "chacha20Decrypt",
                2,
                Pure,
                "ipe_chacha20_decrypt_key",
                IpeOrder,
            ),
            Self::CryptoAesKeyFromPassword => d(
                "Crypto",
                "aesKeyFromPassword",
                2,
                Pure,
                "crypto_aes_key_from_password_key",
                IpeOrder,
            ),
            Self::CryptoChachaKeyFromPassword => d(
                "Crypto",
                "chachaKeyFromPassword",
                2,
                Pure,
                "crypto_chacha_key_from_password_key",
                IpeOrder,
            ),
            Self::CryptoRandomBytes => d(
                "Crypto",
                "randomBytes",
                1,
                Pure,
                "crypto_random_bytes",
                IpeOrder,
            ),
            Self::CryptoRandomToken => d(
                "Crypto",
                "randomToken",
                1,
                Pure,
                "crypto_random_token",
                IpeOrder,
            ),
            // ── Uuid ────────────────────────────────────────────────────────
            // `v4`/`v7` are EFFECT-tier (`() -> Task Error String`):
            // entropy is not a memoizable pure `String`. Arity is 1 (the unit
            // argument) so the FIRST_SCHEMED `arrow-count == decl().arity`
            // invariant holds against the `fun(Unit, task(string))` scheme.
            // Runtime `uuid_v4::<E>(_: ())` / `uuid_v7::<E>(_: ())` take that unit.
            Self::UuidV4 => d("Uuid", "v4", 1, Pure, "uuid_v4", IpeOrder),
            Self::UuidV7 => d("Uuid", "v7", 1, Pure, "uuid_v7", IpeOrder),
            Self::UuidParse => d("Uuid", "parse", 1, Pure, "uuid_parse", IpeOrder),
            // ── Jwt ─────────────────────────────────────────────────────────
            // Encode arity is 2 (secret/key, claims_json): the Rust runtime
            // `ipe_jwt_encode_hs256(secret, claims_json)` / `_rs256(key_pem,
            // claims_json)` take exactly two args.
            Self::JwtEncodeHs256 => d(
                "Jwt",
                "encodeHs256",
                2,
                Pure,
                "ipe_jwt_encode_hs256",
                IpeOrder,
            ),
            Self::JwtDecodeHs256 => d(
                "Jwt",
                "decodeHs256",
                2,
                Pure,
                "ipe_jwt_decode_hs256",
                IpeOrder,
            ),
            Self::JwtEncodeRs256 => d(
                "Jwt",
                "encodeRs256",
                2,
                Pure,
                "ipe_jwt_encode_rs256",
                IpeOrder,
            ),
            Self::JwtDecodeRs256 => d(
                "Jwt",
                "decodeRs256",
                2,
                Pure,
                "ipe_jwt_decode_rs256",
                IpeOrder,
            ),
            // ── Jwt builder API ──────────────────────────────────
            Self::JwtClaims => d("Jwt", "claims", 0, Pure, "ipe_jwt_claims", IpeOrder),
            Self::JwtHs256 => d("Jwt", "hs256", 1, Pure, "ipe_jwt_hs256", IpeOrder),
            Self::JwtRs256 => d("Jwt", "rs256", 1, Pure, "ipe_jwt_rs256", IpeOrder),
            Self::JwtSubject => d("Jwt", "subject", 2, Pure, "ipe_jwt_subject", IpeOrder),
            Self::JwtIssuer => d("Jwt", "issuer", 2, Pure, "ipe_jwt_issuer", IpeOrder),
            Self::JwtAudience => d("Jwt", "audience", 2, Pure, "ipe_jwt_audience", IpeOrder),
            Self::JwtExpiresAt => d("Jwt", "expiresAt", 2, Pure, "ipe_jwt_expires_at", IpeOrder),
            Self::JwtNotBefore => d("Jwt", "notBefore", 2, Pure, "ipe_jwt_not_before", IpeOrder),
            Self::JwtIssuedAt => d("Jwt", "issuedAt", 2, Pure, "ipe_jwt_issued_at", IpeOrder),
            Self::JwtJwtId => d("Jwt", "jwtId", 2, Pure, "ipe_jwt_jwt_id", IpeOrder),
            Self::JwtWithClaim => d("Jwt", "withClaim", 3, Pure, "ipe_jwt_with_claim", IpeOrder),
            Self::JwtEncode => d("Jwt", "encode", 2, Pure, "ipe_jwt_encode", IpeOrder),
            Self::JwtDecode => d("Jwt", "decode", 3, Pure, "ipe_jwt_decode", IpeOrder),
            // ── Task combinators ────────────────────────────────────────────
            Self::TaskSucceed => d("Task", "succeed", 1, Pure, "task_succeed", IpeOrder),
            Self::TaskFail => d("Task", "fail", 1, Pure, "task_fail", IpeOrder),
            Self::TaskMap => d("Task", "map", 2, Pure, "task_map", IpeOrder),
            Self::TaskMap2 => d("Task", "map2", 3, Pure, "task_map2", IpeOrder),
            Self::TaskMap3 => d("Task", "map3", 4, Pure, "task_map3", IpeOrder),
            Self::TaskMap4 => d("Task", "map4", 5, Pure, "task_map4", IpeOrder),
            Self::TaskMap5 => d("Task", "map5", 6, Pure, "task_map5", IpeOrder),
            Self::TaskAttempt => d("Task", "attempt", 2, Tea, "cmd_perform", ContainerFirst),
            Self::TaskAndThen => d("Task", "andThen", 2, Pure, "task_and_then", ContainerFirst),
            Self::TaskMapError => d("Task", "mapError", 2, Pure, "task_map_error", IpeOrder),
            Self::TaskOnError => d("Task", "onError", 2, Pure, "task_on_error", IpeOrder),
            Self::TaskFromResult => d("Task", "fromResult", 1, Pure, "task_from_result", IpeOrder),
            Self::TaskAndThenResult => d(
                "Task",
                "andThenResult",
                2,
                Pure,
                "task_and_then_result",
                IpeOrder,
            ),
            Self::TaskSequence => d("Task", "sequence", 1, Pure, "task_sequence", IpeOrder),
            Self::TaskParallel => d("Task", "parallel", 1, Pure, "task_parallel", IpeOrder),
            Self::TaskRun => d("Task", "run", 1, Pure, "task_run", IpeOrder),
            Self::TaskPerform => d("Task", "perform", 1, Pure, "task_run", IpeOrder),
            Self::TaskLazy => d("Task", "lazy", 1, Pure, "task_lazy", IpeOrder),
            Self::TaskLoop => d("Task", "loop", 3, Pure, "task_loop", IpeOrder),
            // ── Task retry surface (special-case emitter in emit_expr.rs) ───
            Self::TaskRetryWith => d("Task", "retryWith", 2, Pure, "task_retry_with", IpeOrder),
            Self::TaskLinearBackoff => d(
                "Task",
                "linearBackoff",
                2,
                Pure,
                "task_linear_backoff",
                IpeOrder,
            ),
            Self::TaskExponentialBackoff => d(
                "Task",
                "exponentialBackoff",
                2,
                Pure,
                "task_exponential_backoff",
                IpeOrder,
            ),
            Self::TaskWithJitter => d("Task", "withJitter", 1, Pure, "task_with_jitter", IpeOrder),
            Self::TaskRetryOn => d("Task", "retryOn", 2, Pure, "task_retry_on", IpeOrder),
            Self::TaskWithRetryOn => d(
                "Task",
                "withRetryOn",
                2,
                Pure,
                "task_with_retry_on",
                IpeOrder,
            ),
            Self::TaskDefaultRetryPolicy => d(
                "Task",
                "defaultRetryPolicy",
                0,
                Pure,
                "task_default_retry_policy",
                IpeOrder,
            ),
            Self::TaskWithMaxAttempts => d(
                "Task",
                "withMaxAttempts",
                2,
                Pure,
                "task_with_max_attempts",
                IpeOrder,
            ),
            Self::TaskWithBaseMs => d("Task", "withBaseMs", 2, Pure, "task_with_base_ms", IpeOrder),
            // ── Io ──────────────────────────────────────────────────────────
            Self::IoReadLine => d("Io", "readLine", 1, Pure, "io_read_line", IpeOrder),
            Self::IoReadSecret => d("Io", "readSecret", 1, Pure, "io_read_secret", IpeOrder),
            Self::IoWriteStdout => d("Io", "writeStdout", 1, Pure, "io_write_stdout", IpeOrder),
            Self::IoWriteStderr => d("Io", "writeStderr", 1, Pure, "io_write_stderr", IpeOrder),
            Self::IoPrintln => d("Io", "println", 1, Pure, "io_println", IpeOrder),
            Self::IoEprintln => d("Io", "eprintln", 1, Pure, "io_eprintln", IpeOrder),
            Self::DebugLog => d("Debug", "log", 2, Pure, "debug_log", IpeOrder),
            // `Debug.todo : String -> a` — prints the note to stderr and
            // exits non-zero; the result type coerces to any `A` via `!`.
            Self::DebugTodo => d("Debug", "todo", 1, Pure, "debug_todo", IpeOrder),
            // `Debug.explain : Attribute msg` — nullary UI helper (trailing
            // underscore matches the UI-helpers naming convention).
            Self::DebugExplain => d("Debug", "explain", 0, Ui, "debug_explain_", IpeOrder),
            // ── Time (non-TEA) ──────────────────────────────────────────────
            Self::TimeNow => d("Time", "now", 1, Pure, "time_now", IpeOrder),
            Self::TimeSleep => d("Time", "sleep", 1, Pure, "time_sleep", IpeOrder),
            Self::TimeUnixMillis => d("Time", "unixMillis", 1, Pure, "time_unix_millis", IpeOrder),
            Self::TimeTimeString => d("Time", "timeString", 1, Pure, "time_time_string", IpeOrder),
            Self::TimeIsLeapYear => d("Time", "isLeapYear", 1, Pure, "time_is_leap_year", IpeOrder),
            Self::TimeDaysInMonth => d(
                "Time",
                "daysInMonth",
                2,
                Pure,
                "time_days_in_month",
                IpeOrder,
            ),
            Self::TimeFormat => d("Time", "format", 2, Pure, "time_format", IpeOrder),
            Self::TimeFormatHTTP => d("Time", "formatHTTP", 1, Pure, "time_format_http", IpeOrder),
            Self::TimeFormatISO8601 => d(
                "Time",
                "formatISO8601",
                1,
                Pure,
                "time_format_iso8601",
                IpeOrder,
            ),
            Self::TimeFormatRFC3339 => d(
                "Time",
                "formatRFC3339",
                1,
                Pure,
                "time_format_rfc3339",
                IpeOrder,
            ),
            Self::TimeAddMillis => d("Time", "addMillis", 2, Pure, "time_add_millis", IpeOrder),
            Self::TimeDiffMillis => d("Time", "diffMillis", 2, Pure, "time_diff_millis", IpeOrder),
            // ── System ──────────────────────────────────────────────────────
            Self::SystemArgs => d("System", "args", 1, Pure, "system_args", IpeOrder),
            Self::SystemGetenv => d("System", "getenv", 1, Pure, "system_getenv", IpeOrder),
            Self::SystemGetenvOr => d("System", "getenvOr", 2, Pure, "system_getenv_or", IpeOrder),
            Self::SystemGetArg => d("System", "getArg", 1, Pure, "system_get_arg", IpeOrder),
            Self::SystemGetenvInt => d(
                "System",
                "getenvInt",
                1,
                Pure,
                "system_getenv_int",
                IpeOrder,
            ),
            Self::SystemGetenvBool => d(
                "System",
                "getenvBool",
                1,
                Pure,
                "system_getenv_bool",
                IpeOrder,
            ),
            Self::SystemSetenv => d("System", "setenv", 2, Pure, "system_setenv", IpeOrder),
            Self::SystemUnsetenv => d("System", "unsetenv", 1, Pure, "system_unsetenv", IpeOrder),
            Self::SystemCwd => d("System", "cwd", 1, Pure, "system_cwd", IpeOrder),
            Self::SystemGetcwd => d("System", "getcwd", 1, Pure, "system_getcwd", IpeOrder),
            Self::SystemLoadEnv => d("System", "loadEnv", 1, Pure, "system_load_env", IpeOrder),
            Self::SystemExit => d("System", "exit", 1, Pure, "system_exit", IpeOrder),
            // ── Random ──────────────────────────────────────────────────────
            Self::RandomInt => d("Random", "int", 2, Pure, "random_int", IpeOrder),
            Self::RandomFloat => d("Random", "float", 2, Pure, "random_float", IpeOrder),
            Self::RandomChoice => d("Random", "choice", 1, Pure, "random_choice", IpeOrder),
            Self::RandomChoiceMaybe => d(
                "Random",
                "choiceMaybe",
                1,
                Pure,
                "random_choice_maybe",
                IpeOrder,
            ),
            Self::RandomShuffle => d("Random", "shuffle", 1, Pure, "random_shuffle", IpeOrder),
            Self::RandomWeighted => d("Random", "weighted", 1, Pure, "random_weighted", IpeOrder),
            // ── File ────────────────────────────────────────────────────────
            Self::FileReadFile => d("File", "readFile", 1, Pure, "file_read_file", IpeOrder),
            Self::FileWriteFile => d("File", "writeFile", 2, Pure, "file_write_file", IpeOrder),
            Self::FileExists => d("File", "exists", 1, Pure, "file_exists", IpeOrder),
            Self::FileRemove => d("File", "remove", 1, Pure, "file_remove", IpeOrder),
            Self::FileMkdirAll => d("File", "mkdirAll", 1, Pure, "file_mkdir_all", IpeOrder),
            Self::FileReadFileLimit => d(
                "File",
                "readFileLimit",
                2,
                Pure,
                "file_read_file_limit",
                IpeOrder,
            ),
            Self::FileReadFileBytes => d(
                "File",
                "readFileBytes",
                1,
                Pure,
                "file_read_file_bytes",
                IpeOrder,
            ),
            Self::FileAppend => d("File", "append", 2, Pure, "file_append", IpeOrder),
            Self::FileReadDir => d("File", "readDir", 1, Pure, "file_read_dir", IpeOrder),
            Self::FileIsDir => d("File", "isDir", 1, Pure, "file_is_dir", IpeOrder),
            Self::FileTempFile => d("File", "tempFile", 1, Pure, "file_temp_file", IpeOrder),
            Self::FileTempDir => d("File", "tempDir", 1, Pure, "file_temp_dir", IpeOrder),
            Self::FileCopy => d("File", "copy", 2, Pure, "file_copy", IpeOrder),
            Self::FileRename => d("File", "rename", 2, Pure, "file_rename", IpeOrder),
            Self::FileDelete => d("File", "delete", 1, Pure, "file_delete", IpeOrder),
            Self::FileWalk => d("File", "walk", 1, Pure, "file_walk", IpeOrder),
            Self::FileWalkMatching => d(
                "File",
                "walkMatching",
                2,
                Pure,
                "file_walk_matching",
                IpeOrder,
            ),
            // ── Process ───────────────────────────────────────────────────────
            Self::ProcessRun => d("Process", "run", 2, Pure, "process_run", IpeOrder),
            Self::ProcessRunWith => d("Process", "runWith", 1, Pure, "process_run_with", IpeOrder),
            Self::ProcessRunInPty => d(
                "Process",
                "runInPty",
                1,
                Pure,
                "process_run_in_pty",
                IpeOrder,
            ),
            // ── Http ────────────────────────────────────────────────────────
            Self::HttpGet => d("Http", "get", 1, Pure, "http_get", IpeOrder),
            Self::HttpPost => d("Http", "post", 2, Pure, "http_post", IpeOrder),
            Self::HttpRequest => d("Http", "request", 1, Pure, "http_request", IpeOrder),
            Self::HttpParseQuery => d("Http", "parseQuery", 1, Pure, "http_parse_query", IpeOrder),
            Self::HttpDefaultRequest => d(
                "Http",
                "defaultRequest",
                1,
                Pure,
                "http_default_request",
                IpeOrder,
            ),
            Self::HttpDefaultRequestFromString => d(
                "Http",
                "defaultRequestFromString",
                1,
                Pure,
                "http_default_request_from_string",
                IpeOrder,
            ),
            Self::HttpWithMethod => d("Http", "withMethod", 2, Pure, "http_with_method", IpeOrder),
            Self::HttpWithTimeout => d(
                "Http",
                "withTimeout",
                2,
                Pure,
                "http_with_timeout",
                IpeOrder,
            ),
            Self::HttpWithBody => d("Http", "withBody", 2, Pure, "http_with_body", IpeOrder),
            Self::HttpWithHeader => d("Http", "withHeader", 3, Pure, "http_with_header", IpeOrder),
            Self::HttpWithUrl => d("Http", "withUrl", 2, Pure, "http_with_url", IpeOrder),
            Self::HttpWithRedirects => d(
                "Http",
                "withRedirects",
                2,
                Pure,
                "http_with_redirects",
                IpeOrder,
            ),
            Self::HttpMethodFromString => d(
                "Http",
                "methodFromString",
                1,
                Pure,
                "http_method_from_string",
                IpeOrder,
            ),
            Self::HttpMethodToString => d(
                "Http",
                "methodToString",
                1,
                Pure,
                "http_method_to_string",
                IpeOrder,
            ),
            // ── Db ──────────────────────────────────────────────────────────
            Self::DbConnect => d("Db", "connect", 1, Db, "db_connect", IpeOrder),
            Self::DbOpen => d("Db", "open", 2, Db, "db_open", IpeOrder),
            Self::DbClose => d("Db", "close", 1, Db, "db_close", IpeOrder),
            // ── Ipe.Db.Dsn — parse-don't-validate descriptor kernels ──
            Self::DsnParse => d("Db.Dsn", "parse", 1, Db, "dsn_parse", IpeOrder),
            Self::DsnBuild => d("Db.Dsn", "build", 7, Db, "dsn_build", IpeOrder),
            Self::DsnDriverTag => d("Db.Dsn", "driverTag", 1, Db, "dsn_driver", IpeOrder),
            Self::DsnHost => d("Db.Dsn", "host", 1, Db, "dsn_host", IpeOrder),
            Self::DsnPort => d("Db.Dsn", "port", 1, Db, "dsn_port", IpeOrder),
            Self::DsnDatabase => d("Db.Dsn", "database", 1, Db, "dsn_database", IpeOrder),
            Self::DsnUser => d("Db.Dsn", "user", 1, Db, "dsn_user", IpeOrder),
            Self::DsnTlsTag => d("Db.Dsn", "tlsTag", 1, Db, "dsn_tls", IpeOrder),
            Self::DsnRedacted => d("Db.Dsn", "redacted", 1, Db, "dsn_redacted", IpeOrder),
            // ── External Connection: connect a `Dsn`, close it, and the raw hatches. ──
            Self::DbConnOpen => d("Db.Dsn", "open", 1, Db, "db_conn_open", IpeOrder),
            Self::DbConnClose => d("Db.Dsn", "close", 1, Db, "db_conn_close", IpeOrder),
            // Surface-homed in the `Ipe.Db.Unsafe` compiled-source wrapper (which
            // discloses `unsafe` by import); the registry qualifier stays `Db`, so
            // the `Kernel.kernel` alias key is `Db_unsafeExecRawOn`, matching the
            // existing raw-SQL hatch convention.
            Self::DbConnUnsafeExecRawOn => d(
                "Db",
                "unsafeExecRawOn",
                2,
                Db,
                "db_conn_unsafe_exec_raw_on",
                IpeOrder,
            ),
            // External read path: the app-`Db` read kernels' `…On` counterparts,
            // taking a `Connection a` (mode-polymorphic read) instead of `Db`.
            Self::DbConnFindWhere => d("Db", "findWhereOn", 3, Db, "db_conn_find_where", IpeOrder),
            Self::DbConnQueryDecode => d(
                "Db",
                "queryDecodeOn",
                4,
                Db,
                "db_conn_query_decode_params",
                IpeOrder,
            ),
            Self::DbConnGetById => d("Db", "getByIdOn", 3, Db, "db_conn_get_by_id", IpeOrder),
            Self::DbExecRaw => d("Db", "unsafeExecRaw", 2, Db, "db_exec_raw", IpeOrder),
            Self::DbExec => d("Db", "exec", 3, Db, "db_exec_params", IpeOrder),
            Self::DbQuery => d("Db", "unsafeQuery", 3, Db, "db_query_params", IpeOrder),
            Self::DbQueryDecode => d(
                "Db",
                "queryDecode",
                4,
                Db,
                "db_query_decode_params",
                IpeOrder,
            ),
            Self::DbGetString => d("Db", "unsafeGetString", 2, Db, "db_get_string", IpeOrder),
            Self::DbGetInt => d("Db", "unsafeGetInt", 2, Db, "db_get_int", IpeOrder),
            Self::DbGetBool => d("Db", "unsafeGetBool", 2, Db, "db_get_bool", IpeOrder),
            Self::DbGetField => d("Db", "unsafeGetField", 2, Db, "db_get_field", IpeOrder),
            Self::DbInsertRow => d("Db", "insertRow", 3, Db, "db_insert_row", IpeOrder),
            Self::DbGetById => d("Db", "getById", 3, Db, "db_get_by_id", IpeOrder),
            Self::DbUpdateById => d("Db", "updateById", 4, Db, "db_update_by_id", IpeOrder),
            Self::DbDeleteById => d("Db", "deleteById", 3, Db, "db_delete_by_id", IpeOrder),
            Self::DbFindOneByField => d(
                "Db",
                "findOneByField",
                4,
                Db,
                "db_find_one_by_field",
                IpeOrder,
            ),
            Self::DbFindManyByField => d(
                "Db",
                "findManyByField",
                4,
                Db,
                "db_find_many_by_field",
                IpeOrder,
            ),
            Self::DbFindByConditions => d(
                "Db",
                "findByConditions",
                3,
                Db,
                "db_find_by_conditions",
                IpeOrder,
            ),
            Self::DbInsertFields => d("Db", "insertFields", 3, Db, "db_insert_fields", IpeOrder),
            Self::DbUpdateFields => d("Db", "updateFields", 4, Db, "db_update_fields", IpeOrder),
            Self::DbInsertFieldsReturning => d(
                "Db",
                "insertFieldsReturning",
                5,
                Db,
                "db_insert_fields_returning",
                IpeOrder,
            ),
            Self::DbWithTransaction => d(
                "Db",
                "withTransaction",
                2,
                Db,
                "db_with_transaction",
                IpeOrder,
            ),
            Self::DbMigrate => d("Db", "migrate", 2, Db, "db_migrate_apply", IpeOrder),
            // Pure record builder — emitted inline as a `Migration` struct
            // literal (see the `DbDefaultMigration` arm in `emit_expr`), so the
            // runtime-fn name is a never-called placeholder.
            Self::DbDefaultMigration => d(
                "Db",
                "defaultMigration",
                1,
                Pure,
                "db_default_migration",
                IpeOrder,
            ),
            // Accessor-typed equality leaf — lowered inline to the `Compare`
            // `Cond` constructor (the accessor argument becomes the validated
            // column identifier), so the runtime-fn name is a never-called
            // placeholder like `DbDefaultMigration`.
            Self::StoreEqCol => d("Store", "eq", 2, Pure, "store_eq_col", IpeOrder),
            // Accessor-intercepted at lowering (rewritten to `joinNamed`); the
            // runtime name is a never-called placeholder like `store_eq_col`.
            Self::StoreJoin => d("Store", "join", 4, Pure, "store_join", IpeOrder),
            // Accessor-intercepted at lowering (rewritten to `selectNamed`); the
            // runtime name is a never-called placeholder like `store_join`.
            Self::StoreSelect => d("Store", "select", 2, Pure, "store_select", IpeOrder),
            Self::StoreLiteral => d("Store", "literal", 1, Pure, "store_literal", IpeOrder),
            // Intercepted at lowering (rewritten to a `UPPER`/`LOWER` sentinel
            // in the projection pair); the runtime-fn name is a never-called
            // placeholder, the same class as `store_literal`.
            Self::StoreUpper => d("Store", "upper", 1, Pure, "store_upper", IpeOrder),
            Self::StoreLower => d("Store", "lower", 1, Pure, "store_lower", IpeOrder),
            // Intercepted at lowering (rewritten to a `COALESCE` sentinel triple in
            // the projection descriptor); the runtime-fn name is a never-called
            // placeholder.
            Self::StoreCoalesce => d("Store", "coalesce", 2, Pure, "store_coalesce", IpeOrder),
            // Intercepted at lowering (rewritten to an arithmetic term in the
            // projection descriptor); the runtime-fn name is a never-called
            // placeholder, the same class as `store_coalesce`.
            Self::StoreAdd => d("Store", "add", 2, Pure, "store_add", IpeOrder),
            Self::StoreSub => d("Store", "sub", 2, Pure, "store_sub", IpeOrder),
            Self::StoreMul => d("Store", "mul", 2, Pure, "store_mul", IpeOrder),
            // Accessor-typed equality leaf for enum/newtype columns — lowered
            // inline to the `Compare` `Cond` constructor (the value bound through
            // the passed codec), so the runtime-fn name is a never-called
            // placeholder like `StoreEqCol`.
            Self::StoreEqBy => d("Store", "eqBy", 3, Pure, "store_eq_by", IpeOrder),
            // All remaining accessor-typed leaves are lowered inline (the accessor
            // becomes the validated column), so their runtime-fn names are
            // never-called placeholders — the same class as `StoreEqCol`.
            Self::StoreNeqCol => d("Store", "neq", 2, Pure, "store_neq_col", IpeOrder),
            Self::StoreNeqBy => d("Store", "neqBy", 3, Pure, "store_neq_by", IpeOrder),
            Self::StoreGtCol => d("Store", "gt", 2, Pure, "store_gt_col", IpeOrder),
            Self::StoreGtBy => d("Store", "gtBy", 3, Pure, "store_gt_by", IpeOrder),
            Self::StoreGteCol => d("Store", "gte", 2, Pure, "store_gte_col", IpeOrder),
            Self::StoreGteBy => d("Store", "gteBy", 3, Pure, "store_gte_by", IpeOrder),
            Self::StoreLtCol => d("Store", "lt", 2, Pure, "store_lt_col", IpeOrder),
            Self::StoreLtBy => d("Store", "ltBy", 3, Pure, "store_lt_by", IpeOrder),
            Self::StoreLteCol => d("Store", "lte", 2, Pure, "store_lte_col", IpeOrder),
            Self::StoreLteBy => d("Store", "lteBy", 3, Pure, "store_lte_by", IpeOrder),
            // `Store.like` — arity 2 (accessor + pattern string).
            Self::StoreLike => d("Store", "like", 2, Pure, "store_like", IpeOrder),
            // `Store.isNull` / `Store.notNull` — arity 1 (accessor only).
            Self::StoreIsNull => d("Store", "isNull", 1, Pure, "store_is_null", IpeOrder),
            Self::StoreNotNull => d("Store", "notNull", 1, Pure, "store_not_null", IpeOrder),
            // `Store.inList` / `Store.inListBy` — arity 2 / 3.
            Self::StoreInListCol => d("Store", "inList", 2, Pure, "store_in_list_col", IpeOrder),
            Self::StoreInListBy => d("Store", "inListBy", 3, Pure, "store_in_list_by", IpeOrder),
            // Accessor-typed column-spec builders — intercepted inline (accessor
            // becomes the validated column name, then the stringly `*Named`
            // helper is called). Runtime-fn names are never-called placeholders.
            Self::StorePrimaryKey => d(
                "Store",
                "primaryKey",
                2,
                Pure,
                "store_primary_key",
                IpeOrder,
            ),
            Self::StoreSerial => d("Store", "serial", 2, Pure, "store_serial", IpeOrder),
            Self::StoreUnique => d("Store", "unique", 2, Pure, "store_unique", IpeOrder),
            Self::StoreDefaultNow => d(
                "Store",
                "defaultNow",
                2,
                Pure,
                "store_default_now",
                IpeOrder,
            ),
            Self::StoreTouchOnUpdate => d(
                "Store",
                "touchOnUpdate",
                2,
                Pure,
                "store_touch_on_update",
                IpeOrder,
            ),
            // `defaultText` / `defaultInt` — arity 3 (accessor + value + store).
            Self::StoreDefaultText => d(
                "Store",
                "defaultText",
                3,
                Pure,
                "store_default_text",
                IpeOrder,
            ),
            Self::StoreDefaultInt => d(
                "Store",
                "defaultInt",
                3,
                Pure,
                "store_default_int",
                IpeOrder,
            ),
            // Composite primary keys — one accessor per key column + store.
            Self::StoreCompositePrimaryKey2 => d(
                "Store",
                "compositePrimaryKey2",
                3,
                Pure,
                "store_composite_primary_key2",
                IpeOrder,
            ),
            Self::StoreCompositePrimaryKey3 => d(
                "Store",
                "compositePrimaryKey3",
                4,
                Pure,
                "store_composite_primary_key3",
                IpeOrder,
            ),
            // Row-security policy builders — arity 1 (accessor only), intercepted
            // inline (accessor becomes the validated column, then the stringly
            // `*Named` helper is called). Runtime-fn names are placeholders.
            Self::StoreMask => d("Store", "mask", 3, Pure, "store_mask", IpeOrder),
            Self::StoreOwnerColumn => d(
                "Store",
                "ownerColumn",
                1,
                Pure,
                "store_owner_column",
                IpeOrder,
            ),
            // Accessor-intercepted at lowering (rewritten to `orderByLeftNamed`/
            // `orderByRightNamed`); the runtime-fn names are never-called
            // placeholders like `store_join`.
            Self::StoreOrderByLeft => d(
                "Store",
                "orderByLeft",
                3,
                Pure,
                "store_order_by_left",
                IpeOrder,
            ),
            Self::StoreOrderByRight => d(
                "Store",
                "orderByRight",
                3,
                Pure,
                "store_order_by_right",
                IpeOrder,
            ),
            Self::StoreImmutable => d("Store", "immutable", 1, Pure, "store_immutable", IpeOrder),
            // Correlated-subquery row-security — accessor-intercepted at lowering
            // (walked into a `PExists` data leaf / a correlation); the runtime-fn
            // names are never-called placeholders like `store_owner_column`.
            Self::StoreCorrelate => d("Store", "correlate", 2, Pure, "store_correlate", IpeOrder),
            Self::StoreExistsIn => d("Store", "existsIn", 2, Pure, "store_exists_in", IpeOrder),
            // ── Db.Decode ───────────────────────────────────────────────────
            Self::DbDecString => d("Db.Decode", "string", 1, Db, "db_decode_string", IpeOrder),
            Self::DbDecInt => d("Db.Decode", "int", 1, Db, "db_decode_int", IpeOrder),
            Self::DbDecFloat => d("Db.Decode", "float", 1, Db, "db_decode_float", IpeOrder),
            Self::DbDecBool => d("Db.Decode", "bool", 1, Db, "db_decode_bool", IpeOrder),
            Self::DbDecNullable => d(
                "Db.Decode",
                "nullable",
                1,
                Db,
                "db_decode_nullable",
                IpeOrder,
            ),
            Self::DbDecMap => d("Db.Decode", "map", 2, Db, "decode_map", IpeOrder),
            Self::DbDecAndThen => d(
                "Db.Decode",
                "andThen",
                2,
                Db,
                "decode_and_then",
                ContainerFirst,
            ),
            Self::DbDecSucceed => d("Db.Decode", "succeed", 1, Db, "decode_succeed", IpeOrder),
            Self::DbDecFail => d("Db.Decode", "fail", 1, Db, "decode_fail", IpeOrder),
            Self::DbDecMap2 => d("Db.Decode", "map2", 3, Db, "decode_map2", IpeOrder),
            Self::DbDecMap3 => d("Db.Decode", "map3", 4, Db, "decode_map3", IpeOrder),
            Self::DbDecMap4 => d("Db.Decode", "map4", 5, Db, "decode_map4", IpeOrder),
            Self::DbDecRequired => d(
                "Db.Decode",
                "required",
                3,
                Db,
                "db_decode_required",
                IpeOrder,
            ),
            Self::DbDecOptional => d(
                "Db.Decode",
                "optional",
                4,
                Db,
                "db_decode_optional",
                IpeOrder,
            ),
            Self::DbDecMoney => d("Db.Decode", "money", 1, Db, "db_decode_money", IpeOrder),
            Self::DbDecDecimal => d("Db.Decode", "decimal", 1, Db, "db_decode_decimal", IpeOrder),
            Self::DbDecBytes => d("Db.Decode", "bytes", 1, Db, "db_decode_bytes", IpeOrder),
            // ── TEA: Cmd / Sub / Time.every ─────────────────────────────────
            Self::CmdNone => d("Cmd", "none", 0, Tea, "cmd_none", IpeOrder),
            Self::CmdBatch => d("Cmd", "batch", 1, Tea, "cmd_batch", IpeOrder),
            Self::CmdPerform => d("Cmd", "perform", 2, Tea, "cmd_perform", IpeOrder),
            Self::CmdMap => d("Cmd", "map", 2, Tea, "cmd_map", ContainerFirst),
            Self::SubNone => d("Sub", "none", 0, Tea, "sub_none", IpeOrder),
            Self::SubBatch => d("Sub", "batch", 1, Tea, "sub_batch", IpeOrder),
            Self::SubEvery => d("Sub", "every", 2, Tea, "sub_every", IpeOrder),
            Self::TimeEvery => d("Time", "every", 2, Tea, "time_every", IpeOrder),
            Self::SubMap => d("Sub", "map", 2, Tea, "sub_map", ContainerFirst),
            // Shape-scoped input subscriptions: declared under the shape-scoped
            // qualifier (not the canonical `Sub`), so the per-shape `Sub`
            // re-export clone never carries them into another shape.
            Self::TuiSubOnKey => d("TeaTuiSub", "onKey", 1, Tea, "tui_sub_on_key", IpeOrder),
            Self::CliSubOnLine => d("TeaCliSub", "onLine", 1, Tea, "cli_sub_on_line", IpeOrder),
            // ── TEA: reserved pub/sub ────────────────────────────────────────
            // Qualifier "Cmd" IS in qual_vars but "publish"/"publishNoEcho" are
            // NOT yet. Absent from ALL until wired; decl() is still exhaustive.
            Self::CmdPublish => d("Cmd", "publish", 2, Tea, "cmd_publish", IpeOrder),
            Self::CmdPublishNoEcho => d(
                "Cmd",
                "publishNoEcho",
                2,
                Tea,
                "cmd_publish_no_echo",
                IpeOrder,
            ),
            // Qualifier "Sub" IS in qual_vars but "subscribeTopic" is NOT yet.
            Self::SubSubscribeTopic => d(
                "Sub",
                "subscribeTopic",
                2,
                Tea,
                "sub_subscribe_topic",
                IpeOrder,
            ),
            // `Ipe.PubSub` is the Task-shaped top-level publish surface — NOT
            // TEA-loop machinery. `class = Web` because its runtime symbols live
            // in `ipe_runtime::web::pubsub` (the web module), the same home
            // as `Html.renderStatic`; it is excluded from `is_tea()` so it never
            // pulls in the `Cmd`/`Sub` (`tea` module) aliases. `Ipe.PubSub` is a
            // compiled-source module, so `Ipe.PubSub.publish` resolves through its
            // `Kernel.kernel "PubSub_publish"` alias to this `("PubSub", "publish")`
            // canonical kernel — the `"PubSub"` qualifier is intentionally NOT in
            // canon `QUALIFIERS` (compiled-source, not a kernel qualifier).
            Self::PubSubPublish => d("PubSub", "publish", 2, Web, "pubsub_publish", IpeOrder),
            Self::PubSubPublishNoEcho => d(
                "PubSub",
                "publishNoEcho",
                2,
                Web,
                "pubsub_publish_no_echo",
                IpeOrder,
            ),
            // `PubSub.topic : String -> Topic a` — identity at runtime; `Topic a`
            // erases to `String`. Arity 1. Resolved via `Kernel.kernel "PubSub_topic"`.
            Self::PubSubTopic => d("PubSub", "topic", 1, Pure, "pubsub_topic", IpeOrder),
            // ── Ipe.Http.Server / Middleware / RateLimit ─────────────────────
            Self::ServerGet => d("Server", "get", 2, Server, "server_get", IpeOrder),
            Self::ServerPost => d("Server", "post", 2, Server, "server_post", IpeOrder),
            Self::ServerPut => d("Server", "put", 2, Server, "server_put", IpeOrder),
            Self::ServerDelete => d("Server", "delete", 2, Server, "server_delete", IpeOrder),
            Self::ServerAny => d("Server", "any", 2, Server, "server_any", IpeOrder),
            Self::ServerApi => d("Server", "api", 2, Server, "server_api", IpeOrder),
            Self::ServerStatic => d("Server", "static", 2, Server, "server_static", IpeOrder),
            Self::ServerMountApp => d(
                "Server",
                "mountApp",
                2,
                Server,
                "server_mount_app",
                IpeOrder,
            ),
            Self::ServerListen => d("Server", "listen", 2, Server, "server_listen", IpeOrder),
            Self::ServerText => d("Server", "text", 1, Server, "server_text", IpeOrder),
            Self::ServerJson => d("Server", "json", 1, Server, "server_json", IpeOrder),
            Self::ServerHtml => d("Server", "html", 1, Server, "server_html", IpeOrder),
            Self::ServerWithStatus => d(
                "Server",
                "withStatus",
                2,
                Server,
                "server_with_status",
                IpeOrder,
            ),
            Self::ServerWithHeader => d(
                "Server",
                "withHeader",
                3,
                Server,
                "server_with_header",
                IpeOrder,
            ),
            Self::ServerRedirect => d("Server", "redirect", 1, Server, "server_redirect", IpeOrder),
            Self::ServerParam => d("Server", "param", 2, Server, "server_param", IpeOrder),
            Self::ServerQueryParam => d(
                "Server",
                "queryParam",
                2,
                Server,
                "server_query_param",
                IpeOrder,
            ),
            Self::ServerHeader => d("Server", "header", 2, Server, "server_header", IpeOrder),
            Self::ServerGetCookie => d(
                "Server",
                "getCookie",
                2,
                Server,
                "server_get_cookie",
                IpeOrder,
            ),
            Self::ServerBody => d("Server", "body", 1, Server, "server_body", IpeOrder),
            Self::ServerPath => d("Server", "path", 1, Server, "server_path", IpeOrder),
            Self::ServerMethod => d("Server", "method", 1, Server, "server_method", IpeOrder),
            Self::ServerCookieNew => d("Server", "cookie", 2, Server, "server_cookie", IpeOrder),
            Self::ServerWithCookie => d(
                "Server",
                "withCookie",
                2,
                Server,
                "server_with_cookie",
                IpeOrder,
            ),
            Self::ServerAuthConfig => d(
                "Server",
                "authConfig",
                2,
                Server,
                "server_auth_config",
                IpeOrder,
            ),
            Self::ServerTokenBearer => d(
                "Server",
                "bearerToken",
                0,
                Server,
                "server_token_bearer",
                IpeOrder,
            ),
            Self::ServerCookieToken => d(
                "Server",
                "cookieToken",
                1,
                Server,
                "server_cookie_token",
                IpeOrder,
            ),
            Self::ServerGetAuthed => d(
                "Server",
                "getAuthed",
                3,
                Server,
                "server_get_authed",
                IpeOrder,
            ),
            Self::ServerPostAuthed => d(
                "Server",
                "postAuthed",
                3,
                Server,
                "server_post_authed",
                IpeOrder,
            ),
            Self::ServerPutAuthed => d(
                "Server",
                "putAuthed",
                3,
                Server,
                "server_put_authed",
                IpeOrder,
            ),
            Self::ServerDeleteAuthed => d(
                "Server",
                "deleteAuthed",
                3,
                Server,
                "server_delete_authed",
                IpeOrder,
            ),
            Self::MiddlewareWithCors => d(
                "Middleware",
                "withCors",
                2,
                Server,
                "middleware_with_cors",
                IpeOrder,
            ),
            Self::MiddlewareWithLogging => d(
                "Middleware",
                "withLogging",
                1,
                Server,
                "middleware_with_logging",
                IpeOrder,
            ),
            Self::MiddlewareWithBasicAuth => d(
                "Middleware",
                "withBasicAuth",
                3,
                Server,
                "middleware_with_basic_auth",
                IpeOrder,
            ),
            Self::MiddlewareWithRateLimit => d(
                "Middleware",
                "withRateLimit",
                4,
                Server,
                "middleware_with_rate_limit",
                IpeOrder,
            ),
            Self::MiddlewareWithCsrf => d(
                "Middleware",
                "withCsrf",
                1,
                Server,
                "middleware_with_csrf",
                IpeOrder,
            ),
            Self::RateLimitAllow => d(
                "RateLimit",
                "allow",
                4,
                Server,
                "rate_limit_allow",
                IpeOrder,
            ),
            // ── Ipe.Ui / Ipe.Html render kernels ─────────────────────────
            Self::UiLayout => d("Ui", "layout", 2, Ui, "ui_layout", IpeOrder),
            Self::UiLayoutWith => d("Ui", "layoutWith", 2, Ui, "ui_layout_with", IpeOrder),
            Self::HtmlRender => d("Html", "render", 1, Ui, "html_render_", IpeOrder),
            Self::HtmlEscapeText => d("Html", "escapeHtml", 1, Ui, "html_escape_text_", IpeOrder),
            Self::HtmlEscapeAttr => d("Html", "escapeAttr", 1, Ui, "html_escape_attr_", IpeOrder),
            Self::HtmlAttrToString => d(
                "Html",
                "attrToString",
                1,
                Ui,
                "html_attr_to_string_",
                IpeOrder,
            ),
            // ── Ipe.Ui element builders ──────────────────────────────────
            Self::UiNone => d("Ui", "none", 0, Ui, "ui_none_", IpeOrder),
            Self::UiText => d("Ui", "text", 1, Ui, "ui_text_", IpeOrder),
            Self::UiHtml => d("Ui", "html", 1, Ui, "ui_html_", IpeOrder),
            Self::UiCells => d("Ui", "cells", 1, Ui, "ui_cells_", IpeOrder),
            // ── Ipe.Ui.Cells Cells-typed builders ────────────────────────
            Self::UiCellsNone => d("UiCells", "none", 0, Ui, "cells_none_", IpeOrder),
            Self::UiCellsText => d("UiCells", "text", 1, Ui, "cells_text_", IpeOrder),
            Self::UiCellsEl => d("UiCells", "el", 2, Ui, "cells_el_", IpeOrder),
            Self::UiCellsRow => d("UiCells", "row", 2, Ui, "cells_row_", IpeOrder),
            Self::UiCellsColumn => d("UiCells", "column", 2, Ui, "cells_column_", IpeOrder),
            Self::UiCellsCells => d("UiCells", "cells", 1, Ui, "cells_cells_", IpeOrder),
            // ── Ipe.Ui.Tui cell-native attribute builders ────────────
            Self::TuiUiSpacing => d("TuiUi", "spacing", 1, Ui, "tui_spacing_", IpeOrder),
            Self::TuiUiPadding => d("TuiUi", "padding", 1, Ui, "tui_padding_", IpeOrder),
            Self::TuiUiAlignLeft => d("TuiUi", "alignLeft", 0, Ui, "tui_align_left_", IpeOrder),
            Self::TuiUiAlignRight => d("TuiUi", "alignRight", 0, Ui, "tui_align_right_", IpeOrder),
            Self::TuiUiCenter => d("TuiUi", "center", 0, Ui, "tui_center_", IpeOrder),
            Self::TuiUiBold => d("TuiUi", "bold", 0, Ui, "tui_bold_", IpeOrder),
            Self::TuiUiUnderline => d("TuiUi", "underline", 0, Ui, "tui_underline_", IpeOrder),
            Self::TuiUiDim => d("TuiUi", "dim", 0, Ui, "tui_dim_", IpeOrder),
            Self::TuiUiReverse => d("TuiUi", "reverse", 0, Ui, "tui_reverse_", IpeOrder),
            Self::TuiUiColor => d("TuiUi", "color", 1, Ui, "tui_color_", IpeOrder),
            Self::TuiUiBg => d("TuiUi", "bg", 1, Ui, "tui_bg_", IpeOrder),
            // ── Ipe.Ui.Cli line-oriented view + attribute builders ────
            Self::CliUiNone => d("CliUi", "none", 0, Ui, "cli_none_", IpeOrder),
            Self::CliUiText => d("CliUi", "text", 1, Ui, "cli_text_", IpeOrder),
            Self::CliUiLine => d("CliUi", "line", 2, Ui, "cli_line_", IpeOrder),
            Self::CliUiLines => d("CliUi", "lines", 1, Ui, "cli_lines_", IpeOrder),
            Self::CliUiBold => d("CliUi", "bold", 0, Ui, "cli_bold_", IpeOrder),
            Self::CliUiUnderline => d("CliUi", "underline", 0, Ui, "cli_underline_", IpeOrder),
            Self::CliUiDim => d("CliUi", "dim", 0, Ui, "cli_dim_", IpeOrder),
            Self::CliUiReverse => d("CliUi", "reverse", 0, Ui, "cli_reverse_", IpeOrder),
            Self::CliUiColor => d("CliUi", "color", 1, Ui, "cli_color_", IpeOrder),
            Self::CliUiBg => d("CliUi", "bg", 1, Ui, "cli_bg_", IpeOrder),
            // ── Ipe.Color terminal palette constructors (the `AnsiColor` type).
            // Internal home stays `TermColor` (the `TermColor_*` reachability
            // key); the user surface is `Ipe.Color`. ──────────────────────────
            Self::TermColorBlack => d("TermColor", "black", 0, Pure, "term_color_black_", IpeOrder),
            Self::TermColorRed => d("TermColor", "red", 0, Pure, "term_color_red_", IpeOrder),
            Self::TermColorGreen => d("TermColor", "green", 0, Pure, "term_color_green_", IpeOrder),
            Self::TermColorYellow => d(
                "TermColor",
                "yellow",
                0,
                Pure,
                "term_color_yellow_",
                IpeOrder,
            ),
            Self::TermColorBlue => d("TermColor", "blue", 0, Pure, "term_color_blue_", IpeOrder),
            Self::TermColorMagenta => d(
                "TermColor",
                "magenta",
                0,
                Pure,
                "term_color_magenta_",
                IpeOrder,
            ),
            Self::TermColorCyan => d("TermColor", "cyan", 0, Pure, "term_color_cyan_", IpeOrder),
            Self::TermColorWhite => d("TermColor", "white", 0, Pure, "term_color_white_", IpeOrder),
            Self::TermColorBrightBlack => d(
                "TermColor",
                "brightBlack",
                0,
                Pure,
                "term_color_bright_black_",
                IpeOrder,
            ),
            Self::TermColorBrightRed => d(
                "TermColor",
                "brightRed",
                0,
                Pure,
                "term_color_bright_red_",
                IpeOrder,
            ),
            Self::TermColorBrightGreen => d(
                "TermColor",
                "brightGreen",
                0,
                Pure,
                "term_color_bright_green_",
                IpeOrder,
            ),
            Self::TermColorBrightYellow => d(
                "TermColor",
                "brightYellow",
                0,
                Pure,
                "term_color_bright_yellow_",
                IpeOrder,
            ),
            Self::TermColorBrightBlue => d(
                "TermColor",
                "brightBlue",
                0,
                Pure,
                "term_color_bright_blue_",
                IpeOrder,
            ),
            Self::TermColorBrightMagenta => d(
                "TermColor",
                "brightMagenta",
                0,
                Pure,
                "term_color_bright_magenta_",
                IpeOrder,
            ),
            Self::TermColorBrightCyan => d(
                "TermColor",
                "brightCyan",
                0,
                Pure,
                "term_color_bright_cyan_",
                IpeOrder,
            ),
            Self::TermColorBrightWhite => d(
                "TermColor",
                "brightWhite",
                0,
                Pure,
                "term_color_bright_white_",
                IpeOrder,
            ),
            Self::TermColorDefault => d(
                "TermColor",
                "default",
                0,
                Pure,
                "term_color_default_",
                IpeOrder,
            ),
            Self::TermColorRgb => d("TermColor", "rgb", 3, Pure, "term_color_rgb_", IpeOrder),
            Self::TermColorRgba => d("TermColor", "rgba", 4, Pure, "term_color_rgba_", IpeOrder),
            // ── Ipe.Color constructors ──
            Self::ColorRgb => d("Color", "rgb", 3, Pure, "color_rgb", IpeOrder),
            Self::ColorRgba => d("Color", "rgba", 4, Pure, "color_rgba", IpeOrder),
            Self::ColorHsl => d("Color", "hsl", 3, Pure, "color_hsl", IpeOrder),
            Self::ColorHsla => d("Color", "hsla", 4, Pure, "color_hsla", IpeOrder),
            Self::ColorWhite => d("Color", "white", 0, Pure, "color_white", IpeOrder),
            Self::ColorBlack => d("Color", "black", 0, Pure, "color_black", IpeOrder),
            Self::ColorRed => d("Color", "red", 0, Pure, "color_red", IpeOrder),
            Self::ColorGreen => d("Color", "green", 0, Pure, "color_green", IpeOrder),
            Self::ColorBlue => d("Color", "blue", 0, Pure, "color_blue", IpeOrder),
            Self::ColorTransparent => d(
                "Color",
                "transparent",
                0,
                Pure,
                "color_transparent",
                IpeOrder,
            ),
            // ── Ipe.Color accessors + manipulation ──
            Self::ColorToCss => d("Color", "toCss", 1, Pure, "color_to_css", IpeOrder),
            Self::ColorToCssRgba => d("Color", "toCssRgba", 1, Pure, "color_to_css_rgba", IpeOrder),
            Self::ColorToHex => d("Color", "toHex", 1, Pure, "color_to_hex", IpeOrder),
            Self::ColorLuminance => d("Color", "luminance", 1, Pure, "color_luminance", IpeOrder),
            Self::ColorWithAlpha => d("Color", "withAlpha", 2, Pure, "color_with_alpha", IpeOrder),
            Self::ColorMix => d("Color", "mix", 3, Pure, "color_mix", IpeOrder),
            Self::ColorBlend => d("Color", "blend", 2, Pure, "color_blend", IpeOrder),
            Self::ColorLighten => d("Color", "lighten", 2, Pure, "color_lighten", IpeOrder),
            Self::ColorDarken => d("Color", "darken", 2, Pure, "color_darken", IpeOrder),
            Self::ColorSaturate => d("Color", "saturate", 2, Pure, "color_saturate", IpeOrder),
            Self::ColorDesaturate => {
                d("Color", "desaturate", 2, Pure, "color_desaturate", IpeOrder)
            }
            Self::ColorRotateHue => d("Color", "rotateHue", 2, Pure, "color_rotate_hue", IpeOrder),
            Self::ColorComplementary => d(
                "Color",
                "complementary",
                1,
                Pure,
                "color_complementary",
                IpeOrder,
            ),
            Self::ColorGrayscale => d("Color", "grayscale", 1, Pure, "color_grayscale", IpeOrder),
            // ── Ipe.Color parse boundary (typed `Result ColorError Color`) ──
            Self::ColorFromHex => d("Color", "fromHex", 1, Pure, "color_from_hex", IpeOrder),
            Self::ColorFromName => d("Color", "fromName", 1, Pure, "color_from_name", IpeOrder),
            // ── Ipe.Color terminal-profile constructors + toAnsi ──
            Self::ColorTrueColorProfile => d(
                "Color",
                "trueColorProfile",
                0,
                Pure,
                "color_true_color_profile",
                IpeOrder,
            ),
            Self::ColorAnsi256Profile => d(
                "Color",
                "ansi256Profile",
                0,
                Pure,
                "color_ansi256_profile",
                IpeOrder,
            ),
            Self::ColorAnsi16Profile => d(
                "Color",
                "ansi16Profile",
                0,
                Pure,
                "color_ansi16_profile",
                IpeOrder,
            ),
            Self::ColorNoColorProfile => d(
                "Color",
                "noColorProfile",
                0,
                Pure,
                "color_no_color_profile",
                IpeOrder,
            ),
            Self::ColorToAnsi => d("Color", "toAnsi", 2, Pure, "color_to_ansi", IpeOrder),
            // ── Ipe.Color WCAG / contrast (a11y) ──
            Self::ColorWcagAa => d("Color", "wcagAa", 0, Pure, "color_wcag_aa", IpeOrder),
            Self::ColorWcagAaa => d("Color", "wcagAaa", 0, Pure, "color_wcag_aaa", IpeOrder),
            Self::ColorNormalText => d(
                "Color",
                "normalText",
                0,
                Pure,
                "color_normal_text",
                IpeOrder,
            ),
            Self::ColorLargeText => d("Color", "largeText", 0, Pure, "color_large_text", IpeOrder),
            Self::ColorContrastRatio => d(
                "Color",
                "contrastRatio",
                2,
                Pure,
                "color_contrast_ratio",
                IpeOrder,
            ),
            Self::ColorReadableTextOn => d(
                "Color",
                "readableTextOn",
                1,
                Pure,
                "color_readable_text_on",
                IpeOrder,
            ),
            Self::ColorMeetsWcag => d("Color", "meetsWcag", 4, Pure, "color_meets_wcag", IpeOrder),
            Self::ColorMaximumContrast => d(
                "Color",
                "maximumContrast",
                2,
                Pure,
                "color_maximum_contrast",
                IpeOrder,
            ),
            // ── Ipe.Color colour-vision-deficiency simulation ──
            Self::ColorProtanopia => {
                d("Color", "protanopia", 0, Pure, "color_protanopia", IpeOrder)
            }
            Self::ColorDeuteranopia => d(
                "Color",
                "deuteranopia",
                0,
                Pure,
                "color_deuteranopia",
                IpeOrder,
            ),
            Self::ColorTritanopia => {
                d("Color", "tritanopia", 0, Pure, "color_tritanopia", IpeOrder)
            }
            Self::ColorSimulate => d("Color", "simulate", 2, Pure, "color_simulate", IpeOrder),
            Self::UiWidget => d("CustomElement", "node", 3, Ui, "ui_widget_", IpeOrder),
            Self::UiNode => d("Ui", "node", 3, Ui, "ui_node_", IpeOrder),
            Self::UiTaggedNode => d("Ui", "taggedNode", 4, Ui, "ui_tagged_node_", IpeOrder),
            Self::UiButton => d("Ui", "button", 2, Ui, "ui_button_", IpeOrder),
            Self::UiLink => d("Ui", "link", 2, Ui, "ui_link_", IpeOrder),
            Self::UiImage => d("Ui", "image", 2, Ui, "ui_image_", IpeOrder),
            // ── Ipe.Ui nearby attribute builders ───────────────────────
            Self::UiAbove => d("Ui", "above", 1, Ui, "ui_above_", IpeOrder),
            Self::UiBelow => d("Ui", "below", 1, Ui, "ui_below_", IpeOrder),
            Self::UiOnLeft => d("Ui", "onLeft", 1, Ui, "ui_on_left_", IpeOrder),
            Self::UiOnRight => d("Ui", "onRight", 1, Ui, "ui_on_right_", IpeOrder),
            Self::UiInFront => d("Ui", "inFront", 1, Ui, "ui_in_front_", IpeOrder),
            Self::UiBehind => d("Ui", "behind", 1, Ui, "ui_behind_", IpeOrder),
            // ── Ipe.Ui attribute builders ────────────────────────────────
            Self::UiSpacing => d("Ui", "spacing", 1, Ui, "ui_spacing_", IpeOrder),
            Self::UiPadding => d("Ui", "padding", 1, Ui, "ui_padding_", IpeOrder),
            Self::UiPaddingXY => d("Ui", "paddingXY", 2, Ui, "ui_padding_xy_", IpeOrder),
            Self::UiPaddingEach => d("Ui", "paddingEach", 1, Ui, "ui_padding_each_", IpeOrder),
            Self::UiWidth => d("Ui", "width", 1, Ui, "ui_width_", IpeOrder),
            Self::UiHeight => d("Ui", "height", 1, Ui, "ui_height_", IpeOrder),
            Self::UiCenterX => d("Ui", "centerX", 0, Ui, "ui_center_x_", IpeOrder),
            Self::UiCenterY => d("Ui", "centerY", 0, Ui, "ui_center_y_", IpeOrder),
            Self::UiAlignLeft => d("Ui", "alignLeft", 0, Ui, "ui_align_left_", IpeOrder),
            Self::UiAlignRight => d("Ui", "alignRight", 0, Ui, "ui_align_right_", IpeOrder),
            Self::UiAlignTop => d("Ui", "alignTop", 0, Ui, "ui_align_top_", IpeOrder),
            Self::UiAlignBottom => d("Ui", "alignBottom", 0, Ui, "ui_align_bottom_", IpeOrder),
            Self::UiPointer => d("Ui", "pointer", 0, Ui, "ui_pointer_", IpeOrder),
            Self::UiClip => d("Ui", "clip", 0, Ui, "ui_clip_", IpeOrder),
            Self::UiClipX => d("Ui", "clipX", 0, Ui, "ui_clip_x_", IpeOrder),
            Self::UiClipY => d("Ui", "clipY", 0, Ui, "ui_clip_y_", IpeOrder),
            Self::UiScrollbars => d("Ui", "scrollbars", 0, Ui, "ui_scrollbars_", IpeOrder),
            Self::UiScrollbarX => d("Ui", "scrollbarX", 0, Ui, "ui_scrollbar_x_", IpeOrder),
            Self::UiScrollbarY => d("Ui", "scrollbarY", 0, Ui, "ui_scrollbar_y_", IpeOrder),
            Self::UiGridColumns => d("Ui", "gridColumns", 1, Ui, "ui_grid_columns_", IpeOrder),
            // ── Ipe.Ui Length builders ───────────────────────────────────
            Self::UiPx => d("Ui", "px", 1, Ui, "ui_px_", IpeOrder),
            Self::UiFill => d("Ui", "fill", 0, Ui, "ui_fill_", IpeOrder),
            Self::UiContent => d("Ui", "content", 0, Ui, "ui_content_", IpeOrder),
            Self::UiShrink => d("Ui", "shrink", 0, Ui, "ui_shrink_", IpeOrder),
            Self::UiFillPortion => d("Ui", "fillPortion", 1, Ui, "ui_fill_portion_", IpeOrder),
            Self::UiVh => d("Ui", "vh", 1, Ui, "ui_vh_", IpeOrder),
            Self::UiVw => d("Ui", "vw", 1, Ui, "ui_vw_", IpeOrder),
            Self::UiMinimum => d("Ui", "minimum", 2, Ui, "ui_minimum_", IpeOrder),
            Self::UiMaximum => d("Ui", "maximum", 2, Ui, "ui_maximum_", IpeOrder),
            // ── Ipe.Ui Color builders ────────────────────────────────────
            Self::UiRgb => d("Ui", "rgb", 3, Ui, "ui_rgb_", IpeOrder),
            Self::UiRgba => d("Ui", "rgba", 4, Ui, "ui_rgba_", IpeOrder),
            Self::UiWhite => d("Ui", "white", 0, Ui, "ui_white_", IpeOrder),
            Self::UiBlack => d("Ui", "black", 0, Ui, "ui_black_", IpeOrder),
            Self::UiTransparent => d("Ui", "transparent", 0, Ui, "ui_transparent_", IpeOrder),
            Self::UiColorCss => d("Ui", "colorCss", 1, Ui, "ui_color_css_", IpeOrder),
            // ── Background / Border / Font sub-modules ───────────────────
            Self::BackgroundColor => d(
                "Background",
                "color",
                1,
                Ui,
                "ui_background_color_",
                IpeOrder,
            ),
            Self::BackgroundImage => d(
                "Background",
                "image",
                1,
                Ui,
                "ui_background_image_",
                IpeOrder,
            ),
            Self::BackgroundLinearGradient => d(
                "Background",
                "linearGradient",
                2,
                Ui,
                "ui_background_linear_gradient_",
                IpeOrder,
            ),
            Self::BorderWidth => d("Border", "width", 1, Ui, "ui_border_width_", IpeOrder),
            Self::BorderRounded => d("Border", "rounded", 1, Ui, "ui_border_rounded_", IpeOrder),
            Self::BorderColor => d("Border", "color", 1, Ui, "ui_border_color_", IpeOrder),
            Self::BorderWidthEach => d(
                "Border",
                "widthEach",
                1,
                Ui,
                "ui_border_width_each_",
                IpeOrder,
            ),
            Self::BorderShadow => d("Border", "shadow", 1, Ui, "ui_border_shadow_", IpeOrder),
            Self::BorderGlow => d("Border", "glow", 2, Ui, "ui_border_glow_", IpeOrder),
            Self::BorderInnerShadow => d(
                "Border",
                "innerShadow",
                1,
                Ui,
                "ui_border_inner_shadow_",
                IpeOrder,
            ),
            Self::FontSize => d("Font", "size", 1, Ui, "ui_font_size_", IpeOrder),
            Self::FontColor => d("Font", "color", 1, Ui, "ui_font_color_", IpeOrder),
            Self::FontFamily => d("Font", "family", 1, Ui, "ui_font_family_", IpeOrder),
            Self::FontBold => d("Font", "bold", 0, Ui, "ui_font_bold_", IpeOrder),
            Self::FontItalic => d("Font", "italic", 0, Ui, "ui_font_italic_", IpeOrder),
            // ── Html element builders ────────────────────────────────────
            Self::HtmlTextNode => d("Html", "text", 1, Ui, "html_text_node_", IpeOrder),
            Self::HtmlRawNode => d("Html", "unsafeRaw", 1, Ui, "html_raw_node_", IpeOrder),
            Self::HtmlNode => d("Html", "node", 3, Ui, "html_node_", IpeOrder),
            Self::HtmlVoidNode => d("Html", "voidNode", 2, Ui, "html_node_", IpeOrder),
            Self::HtmlDoctype => d("Html", "doctype", 1, Ui, "html_doctype_", IpeOrder),
            Self::HtmlTitleNode => d("Html", "titleNode", 1, Ui, "html_title_node_", IpeOrder),
            Self::HtmlToString => d("Html", "toString", 1, Ui, "html_render_", IpeOrder),
            Self::HtmlStyleNode => d("Html", "styleNode", 2, Ui, "html_style_node_", IpeOrder),
            Self::HtmlScriptNode => d("Html", "unsafeScript", 1, Ui, "html_script_node_", IpeOrder),
            // ── Ipe.Html.Attributes builders ────────────────────────────
            // Qualifier "Attr" matches the `Kernel.kernel "Attr_*"` alias namespace
            // (the compiled-source `Ipe.Html.Attributes` reaches these three
            // retained primitives through it). Emit routes through the generic
            // runtime helpers; a fixed key is a plain runtime argument.
            Self::HtmlAttribute => d("Attr", "attribute", 2, Ui, "html_named_attr_", IpeOrder),
            Self::HtmlBoolAttribute => d(
                "Attr",
                "boolAttribute",
                2,
                Ui,
                "html_bool_named_attr_",
                IpeOrder,
            ),
            Self::HtmlNoAttr => d("Attr", "noAttr", 0, Ui, "html_no_attr_", IpeOrder),
            // ── Ipe.Web app-entry kernels ───────────────────────────────
            Self::WebApp => d("Web", "tea", 1, Web, "web_app", IpeOrder),
            Self::WebAppRouted => d("Web", "appRouted", 1, Web, "web_app_routed", IpeOrder),
            // `Web.embed` shares `Web.tea`'s emit path (both build the `WebApp`
            // leaf from the same cfg); the runtime symbol is the same builder.
            Self::WebEmbed => d("Web", "embed", 1, Web, "web_app", IpeOrder),
            Self::WebRoute => d("Web", "route", 2, Web, "web_route", IpeOrder),
            // `Ipe.Html.renderStatic` is a shape-neutral static-render bridge, NOT
            // a TEA entry: it renders a `view` once to HTML and returns a `Task`, so
            // it lives under `Ipe.Html` next to `render`. `class = Web` because its
            // runtime symbols live in the web module (`web_render_static`); it
            // stays out of `is_tea()`, so a Program using it never pulls in the
            // `Cmd`/`Sub` loop aliases.
            Self::WebRenderStatic => d(
                "Html",
                "renderStatic",
                2,
                Web,
                "web_render_static",
                IpeOrder,
            ),
            // ── Ipe.Tui app-entry kernel ─────────────────────────────────
            // Surface `Tui.tea`; the internal rendering family is `Terminal`.
            Self::TerminalAppScreen => d("Tui", "tea", 1, Terminal, "tui_app_ui", IpeOrder),
            // ── Ipe.Web settings-carrying app entry + runtime-config kernels ──
            Self::WebAppWith => d("Web", "appWith", 2, Web, "web_app_with", IpeOrder),
            Self::AppFromEnv => d("App", "fromEnv", 1, Pure, "ipe_app_from_env", IpeOrder),
            Self::AppFromEnvRequired => d(
                "App",
                "fromEnvRequired",
                1,
                Pure,
                "ipe_app_from_env_required",
                IpeOrder,
            ),
            Self::HostBind => d("Host", "bind", 1, Pure, "ipe_setting_host_bind", IpeOrder),
            Self::LogLevelSetting => d("Log", "level", 1, Pure, "ipe_setting_log_level", IpeOrder),
            Self::DbUrlSetting => d("Db", "url", 1, Pure, "ipe_setting_db_url", IpeOrder),
            Self::ConsoleAdminToken => d(
                "Console",
                "adminToken",
                1,
                Pure,
                "ipe_setting_console_admin_token",
                IpeOrder,
            ),
            Self::ConsoleIngestToken => d(
                "Console",
                "ingestToken",
                1,
                Pure,
                "ipe_setting_console_ingest_token",
                IpeOrder,
            ),
            Self::ConsoleMetricsToken => d(
                "Console",
                "metricsToken",
                1,
                Pure,
                "ipe_setting_console_metrics_token",
                IpeOrder,
            ),
            Self::WebCsrf => d("Web", "csrf", 1, Pure, "ipe_setting_web_csrf", IpeOrder),
            Self::WebSessionTtl => d(
                "Web",
                "sessionTtl",
                1,
                Pure,
                "ipe_setting_web_session_ttl",
                IpeOrder,
            ),
            Self::WebAuthMaxLifetime => d(
                "Web",
                "authMaxLifetime",
                1,
                Pure,
                "ipe_setting_web_auth_max_lifetime",
                IpeOrder,
            ),
            Self::WebAuthSlideWindow => d(
                "Web",
                "authSlideWindow",
                1,
                Pure,
                "ipe_setting_web_auth_slide_window",
                IpeOrder,
            ),
            Self::WebAuthRevocationMode => d(
                "Web",
                "withRevocation",
                1,
                Pure,
                "ipe_setting_web_auth_revocation_mode",
                IpeOrder,
            ),
            // ── Ipe.Auth.Revocation kernels ──────────────────────────────
            Self::AuthRevocationRevokeUser => d(
                "Revocation",
                "revokeUser",
                2,
                Pure,
                "auth_revocation_revoke_user",
                IpeOrder,
            ),
            Self::AuthRevocationRevokeSession => d(
                "Revocation",
                "revokeSession",
                3,
                Pure,
                "auth_revocation_revoke_session",
                IpeOrder,
            ),
            Self::AuthRevocationRestoreUser => d(
                "Revocation",
                "restoreUser",
                2,
                Pure,
                "auth_revocation_restore_user",
                IpeOrder,
            ),
            Self::AuthRevocationIsRevoked => d(
                "Revocation",
                "isRevoked",
                1,
                Pure,
                "auth_revocation_is_revoked",
                IpeOrder,
            ),
            // ── Server.withRevocation ──────────────────────────────────────────
            Self::ServerWithRevocation => d(
                "Server",
                "withRevocation",
                2,
                Server,
                "server_with_revocation",
                IpeOrder,
            ),
            // Config-tag ADT constructors — nullary, emitted inline as a raw `Int`
            // tag (the `runtime_fn` name is never called; it is allowlisted in the
            // runtime symbol-resolution test as inline-emitted).
            Self::HostLoopback => d(
                "Host",
                "loopback",
                0,
                Pure,
                "config_host_mode_loopback",
                IpeOrder,
            ),
            Self::HostAllInterfaces => d(
                "Host",
                "allInterfaces",
                0,
                Pure,
                "config_host_mode_all_interfaces",
                IpeOrder,
            ),
            Self::HostEnvDriven => d(
                "Host",
                "envDriven",
                0,
                Pure,
                "config_host_mode_env_driven",
                IpeOrder,
            ),
            Self::LevelDebug => d(
                "Level",
                "debug",
                0,
                Pure,
                "config_log_level_debug",
                IpeOrder,
            ),
            Self::LevelInfo => d("Level", "info", 0, Pure, "config_log_level_info", IpeOrder),
            Self::LevelWarn => d("Level", "warn", 0, Pure, "config_log_level_warn", IpeOrder),
            Self::LevelError => d(
                "Level",
                "error",
                0,
                Pure,
                "config_log_level_error",
                IpeOrder,
            ),
            Self::WebCsrfStrict => d(
                "Web",
                "strict",
                0,
                Pure,
                "config_csrf_mode_strict",
                IpeOrder,
            ),
            Self::WebCsrfInherit => d(
                "Web",
                "inheritCsrf",
                0,
                Pure,
                "config_csrf_mode_inherit",
                IpeOrder,
            ),
            Self::WebRevocationOff => d(
                "Web",
                "revocationOff",
                0,
                Pure,
                "config_revocation_mode_off",
                IpeOrder,
            ),
            Self::WebRevocationStore => d(
                "Web",
                "revocationStore",
                0,
                Pure,
                "config_revocation_mode_store",
                IpeOrder,
            ),
            // ── event-attribute builders ─────────────────────────────────
            Self::UiOnClick => d("Ui", "onClick", 1, Ui, "ui_on_click_", IpeOrder),
            Self::UiOnFocus => d("Ui", "onFocus", 1, Ui, "ui_on_focus_", IpeOrder),
            Self::UiOnBlur => d("Ui", "onBlur", 1, Ui, "ui_on_blur_", IpeOrder),
            Self::UiOnMouseOver => d("Ui", "onMouseOver", 1, Ui, "ui_on_mouse_over_", IpeOrder),
            Self::UiOnMouseOut => d("Ui", "onMouseOut", 1, Ui, "ui_on_mouse_out_", IpeOrder),
            Self::UiOnInput => d("Ui", "onInput", 1, Ui, "ui_on_input_", IpeOrder),
            Self::UiOnChange => d("Ui", "onChange", 1, Ui, "ui_on_change_", IpeOrder),
            Self::UiOnKeyDown => d("Ui", "onKeyDown", 1, Ui, "ui_on_key_down_", IpeOrder),
            Self::UiOnKeyUp => d("Ui", "onKeyUp", 1, Ui, "ui_on_key_up_", IpeOrder),
            Self::UiOnBool => d("Ui", "onBool", 1, Ui, "ui_on_bool_", IpeOrder),
            Self::UiOnSubmit => d("Ui", "onSubmit", 1, Ui, "ui_on_submit_", IpeOrder),
            Self::UiOnFile => d("Ui", "onFile", 1, Ui, "ui_on_file_", IpeOrder),
            // ── Ipe.Html.Events builders (qualifier "Event" — matches the
            // `QUALIFIERS` table in env.rs). Each produces `html::Attribute<M>`
            // via a dedicated runtime constructor (family `Ui` so emit routes
            // through `emit_ui_call`). The emit arm supplies the fixed wire
            // event name; see `html_event_wire_name`.
            Self::HtmlOnClick => d("Event", "onClick", 1, Ui, "html_on_msg_", IpeOrder),
            Self::HtmlOnFocus => d("Event", "onFocus", 1, Ui, "html_on_msg_", IpeOrder),
            Self::HtmlOnBlur => d("Event", "onBlur", 1, Ui, "html_on_msg_", IpeOrder),
            Self::HtmlOnMouseOver => d("Event", "onMouseOver", 1, Ui, "html_on_msg_", IpeOrder),
            Self::HtmlOnMouseOut => d("Event", "onMouseOut", 1, Ui, "html_on_msg_", IpeOrder),
            Self::HtmlOnSubmit => d("Event", "onSubmit", 1, Ui, "html_on_raw_", IpeOrder),
            Self::HtmlOnInput => d("Event", "onInput", 1, Ui, "html_on_string_", IpeOrder),
            Self::HtmlOnChange => d("Event", "onChange", 1, Ui, "html_on_string_", IpeOrder),
            Self::HtmlOnKeyDown => d("Event", "onKeyDown", 1, Ui, "html_on_string_", IpeOrder),
            Self::HtmlOnKeyUp => d("Event", "onKeyUp", 1, Ui, "html_on_string_", IpeOrder),
            Self::HtmlOnBool => d("Event", "onBool", 1, Ui, "html_on_bool_", IpeOrder),
            // Ui namespace
            Self::UiSquare => d("Ui", "square", 0, Ui, "ui_square_", IpeOrder),
            Self::UiWidescreen => d("Ui", "widescreen", 0, Ui, "ui_widescreen_", IpeOrder),
            Self::UiCinemascope => d("Ui", "cinemascope", 0, Ui, "ui_cinemascope_", IpeOrder),
            Self::UiAspectRatio => d("Ui", "aspectRatio", 1, Ui, "ui_aspect_ratio_", IpeOrder),
            Self::UiAspectRatioWH => d(
                "Ui",
                "aspectRatioWH",
                2,
                Ui,
                "ui_aspect_ratio_wh_",
                IpeOrder,
            ),
            Self::UiHtmlAttribute => {
                d("Ui", "htmlAttribute", 2, Ui, "ui_html_attribute_", IpeOrder)
            }
            Self::UiName => d("Ui", "name", 1, Ui, "ui_name_", IpeOrder),
            Self::UiStyle => d("Ui", "style", 2, Ui, "ui_style_", IpeOrder),
            Self::UiTransitionRaw => d("Ui", "transition", 2, Ui, "ui_transition_raw_", IpeOrder),
            Self::UiGridTracksRaw => d("Ui", "gridTracks", 2, Ui, "ui_grid_tracks_raw_", IpeOrder),
            Self::UiAnimateRaw => d("Ui", "animate", 4, Ui, "ui_animate_raw_", IpeOrder),
            // Breakpoint
            Self::UiBreakpoint => d("Ui", "breakpoint", 3, Ui, "ui_breakpoint_", IpeOrder),
            Self::UiMediaQuery => d("Ui", "mediaQuery", 3, Ui, "ui_media_query_", IpeOrder),
            Self::UiMobile => d("Ui", "mobile", 0, Ui, "ui_mobile_", IpeOrder),
            Self::UiTablet => d("Ui", "tablet", 0, Ui, "ui_tablet_", IpeOrder),
            Self::UiDesktop => d("Ui", "desktop", 0, Ui, "ui_desktop_", IpeOrder),
            Self::UiDarkMode => d("Ui", "darkMode", 0, Ui, "ui_dark_mode_", IpeOrder),
            Self::UiLightMode => d("Ui", "lightMode", 0, Ui, "ui_light_mode_", IpeOrder),
            Self::UiReducedMotion => {
                d("Ui", "reducedMotion", 0, Ui, "ui_reduced_motion_", IpeOrder)
            }
            // PseudoClass opaque constants + Ui.onPseudo
            Self::UiOnPseudo => d("Ui", "onPseudo", 2, Ui, "ui_on_pseudo_", IpeOrder),
            Self::UiHover => d("Ui", "hover", 0, Ui, "ui_hover_", IpeOrder),
            Self::UiFocus => d("Ui", "focus", 0, Ui, "ui_focus_", IpeOrder),
            Self::UiFocusVisible => d("Ui", "focusVisible", 0, Ui, "ui_focus_visible_", IpeOrder),
            Self::UiActive => d("Ui", "active", 0, Ui, "ui_active_", IpeOrder),
            Self::UiDisabled => d("Ui", "disabled", 0, Ui, "ui_disabled_", IpeOrder),
            // Background namespace
            Self::BackgroundHoverColor => d(
                "Background",
                "hoverColor",
                1,
                Ui,
                "ui_bg_hover_color_",
                IpeOrder,
            ),
            Self::BackgroundFocusColor => d(
                "Background",
                "focusColor",
                1,
                Ui,
                "ui_bg_focus_color_",
                IpeOrder,
            ),
            Self::BackgroundActiveColor => d(
                "Background",
                "activeColor",
                1,
                Ui,
                "ui_bg_active_color_",
                IpeOrder,
            ),
            Self::BackgroundDisabledColor => d(
                "Background",
                "disabledColor",
                1,
                Ui,
                "ui_bg_disabled_color_",
                IpeOrder,
            ),
            // Border namespace
            Self::BorderSolid => d("Border", "solid", 0, Ui, "ui_border_solid_", IpeOrder),
            Self::BorderDashed => d("Border", "dashed", 0, Ui, "ui_border_dashed_", IpeOrder),
            Self::BorderDotted => d("Border", "dotted", 0, Ui, "ui_border_dotted_", IpeOrder),
            Self::BorderHoverColor => d(
                "Border",
                "hoverColor",
                1,
                Ui,
                "ui_border_hover_color_",
                IpeOrder,
            ),
            Self::BorderFocusColor => d(
                "Border",
                "focusColor",
                1,
                Ui,
                "ui_border_focus_color_",
                IpeOrder,
            ),
            Self::BorderActiveColor => d(
                "Border",
                "activeColor",
                1,
                Ui,
                "ui_border_active_color_",
                IpeOrder,
            ),
            Self::BorderHoverWidth => d(
                "Border",
                "hoverWidth",
                1,
                Ui,
                "ui_border_hover_width_",
                IpeOrder,
            ),
            Self::BorderHoverRounded => d(
                "Border",
                "hoverRounded",
                1,
                Ui,
                "ui_border_hover_rounded_",
                IpeOrder,
            ),
            // Font namespace
            Self::FontWeight => d("Font", "weight", 1, Ui, "ui_font_weight_", IpeOrder),
            Self::FontSemiBold => d("Font", "semiBold", 0, Ui, "ui_font_semi_bold_", IpeOrder),
            Self::FontRegular => d("Font", "regular", 0, Ui, "ui_font_regular_", IpeOrder),
            Self::FontLight => d("Font", "light", 0, Ui, "ui_font_light_", IpeOrder),
            Self::FontExtraBold => d("Font", "extraBold", 0, Ui, "ui_font_extra_bold_", IpeOrder),
            Self::FontBlack => d("Font", "black", 0, Ui, "ui_font_black_", IpeOrder),
            Self::FontUnderline => d("Font", "underline", 0, Ui, "ui_font_underline_", IpeOrder),
            Self::FontNoDecoration => d(
                "Font",
                "noDecoration",
                0,
                Ui,
                "ui_font_no_decoration_",
                IpeOrder,
            ),
            Self::FontLineThrough => d(
                "Font",
                "lineThrough",
                0,
                Ui,
                "ui_font_line_through_",
                IpeOrder,
            ),
            Self::FontLetterSpacing => d(
                "Font",
                "letterSpacing",
                1,
                Ui,
                "ui_font_letter_spacing_",
                IpeOrder,
            ),
            Self::FontWordSpacing => d(
                "Font",
                "wordSpacing",
                1,
                Ui,
                "ui_font_word_spacing_",
                IpeOrder,
            ),
            Self::FontAlignLeft => d("Font", "alignLeft", 0, Ui, "ui_font_align_left_", IpeOrder),
            Self::FontAlignRight => d(
                "Font",
                "alignRight",
                0,
                Ui,
                "ui_font_align_right_",
                IpeOrder,
            ),
            Self::FontAlignCenter => d(
                "Font",
                "alignCenter",
                0,
                Ui,
                "ui_font_align_center_",
                IpeOrder,
            ),
            Self::FontCenter => d("Font", "center", 0, Ui, "ui_font_center_", IpeOrder),
            Self::FontJustify => d("Font", "justify", 0, Ui, "ui_font_justify_", IpeOrder),
            Self::FontSansSerif => d("Font", "sansSerif", 0, Ui, "ui_font_sans_serif_", IpeOrder),
            Self::FontSerif => d("Font", "serif", 0, Ui, "ui_font_serif_", IpeOrder),
            Self::FontMonospace => d("Font", "monospace", 0, Ui, "ui_font_monospace_", IpeOrder),
            Self::FontHoverColor => d(
                "Font",
                "hoverColor",
                1,
                Ui,
                "ui_font_hover_color_",
                IpeOrder,
            ),
            Self::FontFocusColor => d(
                "Font",
                "focusColor",
                1,
                Ui,
                "ui_font_focus_color_",
                IpeOrder,
            ),
            Self::FontActiveColor => d(
                "Font",
                "activeColor",
                1,
                Ui,
                "ui_font_active_color_",
                IpeOrder,
            ),
            Self::FontDisabledColor => d(
                "Font",
                "disabledColor",
                1,
                Ui,
                "ui_font_disabled_color_",
                IpeOrder,
            ),
            Self::FontHoverSize => d("Font", "hoverSize", 1, Ui, "ui_font_hover_size_", IpeOrder),
            // ── Effect stdlib modules ────────────────────────────────────
            // Ipe.Cli line-oriented app-entry. Surface `Cli.tea`; the internal
            // rendering family is `Terminal`.
            Self::TerminalAppLines => d("Cli", "tea", 1, Terminal, "ipe_console_app_", IpeOrder),
            // Ipe.Tea.Worker view-less worker app-entry. Surface `Worker.tea`; the
            // internal family is `Tea` (TEA-loop wiring, no render).
            Self::TeaWorker => d("Worker", "tea", 1, Tea, "ipe_worker_app_", IpeOrder),
            // Ipe.Auth / Ipe.Auth (fail-closed: qual-registered only, no lower arm).
            Self::AuthHashPassword => d(
                "Auth",
                "hashPassword",
                1,
                Pure,
                "auth_hash_password",
                IpeOrder,
            ),
            Self::AuthHashPasswordCost => d(
                "Auth",
                "hashPasswordCost",
                2,
                Pure,
                "auth_hash_password_cost",
                IpeOrder,
            ),
            Self::AuthVerifyPassword => d(
                "Auth",
                "verifyPassword",
                2,
                Pure,
                "auth_verify_password",
                IpeOrder,
            ),
            Self::AuthPasswordStrength => d(
                "Auth",
                "passwordStrength",
                1,
                Pure,
                "auth_password_strength",
                IpeOrder,
            ),
            Self::AuthSignToken => d("Auth", "signToken", 3, Pure, "auth_sign_token", IpeOrder),
            Self::AuthVerifyToken => d(
                "Auth",
                "verifyToken",
                2,
                Pure,
                "auth_verify_token",
                IpeOrder,
            ),
            Self::AuthRegister => d("Auth", "register", 3, Pure, "auth_register", IpeOrder),
            Self::AuthLogin => d("Auth", "login", 3, Pure, "auth_login", IpeOrder),
            Self::AuthSetRole => d("Auth", "setRole", 3, Pure, "auth_set_role", IpeOrder),
            Self::AuthSubject => d("Auth", "subject", 1, Pure, "principal_subject", IpeOrder),
            Self::AuthClaim => d("Auth", "claim", 2, Pure, "principal_claim", IpeOrder),
            Self::AuthHasRole => d("Auth", "hasRole", 2, Pure, "principal_has_role", IpeOrder),
            Self::AuthMemberOf => d("Auth", "memberOf", 2, Pure, "principal_member_of", IpeOrder),
            // Ipe.Http.Server.Stream (fail-closed: qual-registered only, no lower arm).
            Self::StreamStream => d(
                "Stream",
                "stream",
                2,
                Server,
                "server_stream_stream",
                IpeOrder,
            ),
            Self::StreamEmit => d("Stream", "emit", 2, Server, "server_stream_emit", IpeOrder),
            Self::StreamFinish => d(
                "Stream",
                "finish",
                1,
                Server,
                "server_stream_finish",
                IpeOrder,
            ),
            Self::StreamWithContentType => d(
                "Stream",
                "withContentType",
                2,
                Server,
                "server_stream_with_content_type",
                IpeOrder,
            ),
            // Ipe.Http.Stream (fail-closed: qual-registered only, no lower arm).
            Self::HttpStreamOpen => d("HttpStream", "open", 1, Pure, "http_stream_open", IpeOrder),
            Self::HttpStreamForEachChunk => d(
                "HttpStream",
                "forEachChunk",
                2,
                Pure,
                "http_stream_for_each_chunk",
                IpeOrder,
            ),
            Self::HttpStreamClose => d(
                "HttpStream",
                "close",
                1,
                Pure,
                "http_stream_close",
                IpeOrder,
            ),
            Self::HttpStreamChunks => d(
                "HttpStream",
                "chunks",
                2,
                Pure,
                "sub_subscribe_stream",
                IpeOrder,
            ),
            // ── Ipe.Http.Server.WebSocket (12 kernels) ─────────────────────
            Self::WsDefaultCfg => d(
                "Ws",
                "defaultCfg",
                0,
                Server,
                "ws_server_default_cfg",
                IpeOrder,
            ),
            Self::WsWithOnConnect => d(
                "Ws",
                "withOnConnect",
                2,
                Server,
                "ws_server_with_on_connect",
                IpeOrder,
            ),
            Self::WsWithOnMessage => d(
                "Ws",
                "withOnMessage",
                2,
                Server,
                "ws_server_with_on_message",
                IpeOrder,
            ),
            Self::WsWithOnClose => d(
                "Ws",
                "withOnClose",
                2,
                Server,
                "ws_server_with_on_close",
                IpeOrder,
            ),
            Self::WsWithOnError => d(
                "Ws",
                "withOnError",
                2,
                Server,
                "ws_server_with_on_error",
                IpeOrder,
            ),
            Self::WsWithMaxMessageBytes => d(
                "Ws",
                "withMaxMessageBytes",
                2,
                Server,
                "ws_server_with_max_message_bytes",
                IpeOrder,
            ),
            Self::WsWithOriginPatterns => d(
                "Ws",
                "withOriginPatterns",
                2,
                Server,
                "ws_server_with_origin_patterns",
                IpeOrder,
            ),
            Self::WsUpgrade => d(
                "Ws",
                "upgrade",
                2,
                Server,
                "server_web_socket_upgrade",
                IpeOrder,
            ),
            Self::WsSendToClient => d(
                "Ws",
                "sendToClient",
                2,
                Server,
                "ws_server_send_to_client",
                IpeOrder,
            ),
            Self::WsSendBinaryToClient => d(
                "Ws",
                "sendBinaryToClient",
                2,
                Server,
                "ws_server_send_binary_to_client",
                IpeOrder,
            ),
            Self::WsBroadcast => d(
                "Ws",
                "broadcast",
                2,
                Server,
                "ws_server_broadcast",
                IpeOrder,
            ),
            Self::WsCloseClient => d(
                "Ws",
                "closeClient",
                1,
                Server,
                "ws_server_close_client",
                IpeOrder,
            ),
            // ── Ipe.WebSocket — outbound WebSocket client (7 kernels) ──
            // The Task-tier six are `Pure`-classed (plain effects, default N-arg
            // emit like `Http.get`); the runtime fns live in `ws_client.rs`
            // (gated by the `websocket_client` feature the backend adds via the
            // `uses_websocket` flag). `Sub_subscribeWebSocket` is `Tea`-classed —
            // the backend's `emit_tea_call` peephole splits it on the literal
            // `kind` into the four typed `sub_subscribe_ws_*` runtime fns.
            Self::WebSocketConnect => d(
                "WebSocket",
                "connect",
                1,
                Pure,
                "web_socket_connect",
                IpeOrder,
            ),
            Self::WebSocketConnectWith => d(
                "WebSocket",
                "connectWith",
                1,
                Pure,
                "web_socket_connect_with",
                IpeOrder,
            ),
            Self::WebSocketSend => d("WebSocket", "send", 2, Pure, "web_socket_send", IpeOrder),
            Self::WebSocketSendBinary => d(
                "WebSocket",
                "sendBinary",
                2,
                Pure,
                "web_socket_send_binary",
                IpeOrder,
            ),
            Self::WebSocketClose => d("WebSocket", "close", 1, Pure, "web_socket_close", IpeOrder),
            Self::WebSocketCloseWithCode => d(
                "WebSocket",
                "closeWithCode",
                3,
                Pure,
                "web_socket_close_with_code",
                IpeOrder,
            ),
            // The runtime fn here is a placeholder: the peephole always rewrites
            // the call to one of `sub_subscribe_ws_{message,open,close,error}`,
            // so this name is never emitted directly.
            Self::SubSubscribeWebSocket => d(
                "Sub",
                "subscribeWebSocket",
                3,
                Tea,
                "sub_subscribe_ws_message",
                IpeOrder,
            ),
            // The runtime fn names here name the live per-target port transport:
            // `js_send` posts the seal-encoded payload, `js_subscribe` decodes an
            // inbound payload through the fail-closed seal decoder.
            Self::JsSend => d("Js", "send", 1, Tea, "js_send", IpeOrder),
            Self::JsSubscribe => d("Js", "subscribe", 2, Tea, "js_subscribe", IpeOrder),
            Self::JsRequest => d("Js", "request", 2, Tea, "js_request", IpeOrder),
            Self::JsOpenSession => d("Js", "openSession", 2, Tea, "js_open_session", IpeOrder),
            Self::JsSessionFrames => {
                d("Js", "sessionFrames", 3, Tea, "js_session_frames", IpeOrder)
            }
            Self::JsSendToSession => d(
                "Js",
                "sendToSession",
                2,
                Tea,
                "js_send_to_session",
                IpeOrder,
            ),
            Self::JsCloseSession => d("Js", "closeSession", 3, Tea, "js_close_session", IpeOrder),
            Self::EnvPublic => d("Env", "public", 1, Pure, "env_public", IpeOrder),
            // ── Ipe.Ui.Region ──────────────────────────────────────────────
            Self::RegionMainContent => d(
                "Region",
                "mainContent",
                0,
                Ui,
                "ui_region_main_content_",
                IpeOrder,
            ),
            Self::RegionNavigation => d(
                "Region",
                "navigation",
                0,
                Ui,
                "ui_region_navigation_",
                IpeOrder,
            ),
            Self::RegionFooter => d("Region", "footer", 0, Ui, "ui_region_footer_", IpeOrder),
            Self::RegionAside => d("Region", "aside", 0, Ui, "ui_region_aside_", IpeOrder),
            Self::RegionHeading => d("Region", "heading", 1, Ui, "ui_region_heading_", IpeOrder),
            Self::RegionLabel => d("Region", "label", 1, Ui, "ui_region_label_", IpeOrder),
            Self::RegionAnnounce => d("Region", "announce", 0, Ui, "ui_region_announce_", IpeOrder),
            Self::RegionAnnounceUrgently => d(
                "Region",
                "announceUrgently",
                0,
                Ui,
                "ui_region_announce_urgently_",
                IpeOrder,
            ),
            // ── Ui.input + Ui.describe + desc* constructors ───────────────
            Self::UiDescribe => d("Ui", "describe", 1, Ui, "ui_describe_", IpeOrder),
            Self::UiDescNone => d("Ui", "descNone", 0, Ui, "ui_desc_none_", IpeOrder),
            Self::UiDescParagraph => {
                d("Ui", "descParagraph", 0, Ui, "ui_desc_paragraph_", IpeOrder)
            }
            Self::UiDescMain => d("Ui", "descMain", 0, Ui, "ui_desc_main_", IpeOrder),
            Self::UiDescNavigation => d(
                "Ui",
                "descNavigation",
                0,
                Ui,
                "ui_desc_navigation_",
                IpeOrder,
            ),
            Self::UiDescContentInfo => d(
                "Ui",
                "descContentInfo",
                0,
                Ui,
                "ui_desc_content_info_",
                IpeOrder,
            ),
            Self::UiDescComplementary => d(
                "Ui",
                "descComplementary",
                0,
                Ui,
                "ui_desc_complementary_",
                IpeOrder,
            ),
            Self::UiDescLivePolite => d(
                "Ui",
                "descLivePolite",
                0,
                Ui,
                "ui_desc_live_polite_",
                IpeOrder,
            ),
            Self::UiDescLiveAssertive => d(
                "Ui",
                "descLiveAssertive",
                0,
                Ui,
                "ui_desc_live_assertive_",
                IpeOrder,
            ),
            Self::UiDescHeading => d("Ui", "descHeading", 1, Ui, "ui_desc_heading_", IpeOrder),
            Self::UiDescLabel => d("Ui", "descLabel", 1, Ui, "ui_desc_label_", IpeOrder),
            // ── Ipe.Ui.Input ───────────────────────────────────────────
            Self::InputLabelAbove => {
                d("Input", "labelAbove", 2, Ui, "input_label_above_", IpeOrder)
            }
            Self::InputLabelBelow => {
                d("Input", "labelBelow", 2, Ui, "input_label_below_", IpeOrder)
            }
            Self::InputLabelLeft => d("Input", "labelLeft", 2, Ui, "input_label_left_", IpeOrder),
            Self::InputLabelRight => {
                d("Input", "labelRight", 2, Ui, "input_label_right_", IpeOrder)
            }
            Self::InputLabelHidden => d(
                "Input",
                "labelHidden",
                1,
                Ui,
                "input_label_hidden_",
                IpeOrder,
            ),
            Self::InputPlaceholder => d(
                "Input",
                "placeholder",
                2,
                Ui,
                "input_placeholder_",
                IpeOrder,
            ),
            // Record-arg kernels: arity 2 (attrs + cfg record).
            Self::InputText => d("Input", "text", 2, Ui, "input_text_", IpeOrder),
            Self::InputMultiline => d("Input", "multiline", 2, Ui, "input_multiline_", IpeOrder),
            Self::InputEmail => d("Input", "email", 2, Ui, "input_email_", IpeOrder),
            Self::InputUsername => d("Input", "username", 2, Ui, "input_username_", IpeOrder),
            Self::InputSearch => d("Input", "search", 2, Ui, "input_search_", IpeOrder),
            Self::InputCurrentPassword => d(
                "Input",
                "currentPassword",
                2,
                Ui,
                "input_current_password_",
                IpeOrder,
            ),
            Self::InputNewPassword => d(
                "Input",
                "newPassword",
                2,
                Ui,
                "input_new_password_",
                IpeOrder,
            ),
            Self::InputCheckbox => d("Input", "checkbox", 2, Ui, "input_checkbox_", IpeOrder),
            Self::InputSlider => d("Input", "slider", 2, Ui, "input_slider_", IpeOrder),
            Self::InputOption => d("Input", "option", 2, Ui, "input_option_", IpeOrder),
            Self::InputRadio => d("Input", "radio", 2, Ui, "input_radio_", IpeOrder),
            Self::InputRadioRow => d("Input", "radioRow", 2, Ui, "input_radio_row_", IpeOrder),
            // ── Ipe.Ui.Lazy ─────────────────────────────────────��──────
            Self::LazyLazy => d("Lazy", "lazy", 2, Ui, "lazy_lazy_", IpeOrder),
            Self::LazyLazy2 => d("Lazy", "lazy2", 3, Ui, "lazy_lazy2_", IpeOrder),
            Self::LazyLazy3 => d("Lazy", "lazy3", 4, Ui, "lazy_lazy3_", IpeOrder),
            Self::LazyLazy4 => d("Lazy", "lazy4", 5, Ui, "lazy_lazy4_", IpeOrder),
            Self::LazyLazy5 => d("Lazy", "lazy5", 6, Ui, "lazy_lazy5_", IpeOrder),
            // ── Ipe.Ui.Keyed ────────────────────────────────────────────────
            Self::KeyedColumn => d("Keyed", "column", 2, Ui, "keyed_column_", IpeOrder),
            Self::KeyedRow => d("Keyed", "row", 2, Ui, "keyed_row_", IpeOrder),
            // ── Ipe.Decimal — arbitrary-precision decimal arithmetic ──────────
            Self::DecZero => d("Decimal", "zero", 0, Pure, "decimal_zero", IpeOrder),
            Self::DecOne => d("Decimal", "one", 0, Pure, "decimal_one", IpeOrder),
            Self::DecOneHundred => d(
                "Decimal",
                "oneHundred",
                0,
                Pure,
                "decimal_one_hundred",
                IpeOrder,
            ),
            Self::DecFromString => d(
                "Decimal",
                "fromString",
                1,
                Pure,
                "decimal_from_string",
                IpeOrder,
            ),
            Self::DecFromInt => d("Decimal", "fromInt", 1, Pure, "decimal_from_int", IpeOrder),
            Self::DecFromFloat => d(
                "Decimal",
                "fromFloat",
                1,
                Pure,
                "decimal_from_float",
                IpeOrder,
            ),
            Self::DecFromMinor => d(
                "Decimal",
                "fromMinor",
                2,
                Pure,
                "decimal_from_minor",
                IpeOrder,
            ),
            Self::DecToString => d(
                "Decimal",
                "toString",
                1,
                Pure,
                "decimal_to_string",
                IpeOrder,
            ),
            Self::DecToStringFixed => d(
                "Decimal",
                "toStringFixed",
                2,
                Pure,
                "decimal_to_string_fixed",
                IpeOrder,
            ),
            Self::DecToFloat => d("Decimal", "toFloat", 1, Pure, "decimal_to_float", IpeOrder),
            Self::DecToInt => d("Decimal", "toInt", 1, Pure, "decimal_to_int", IpeOrder),
            Self::DecToMinor => d("Decimal", "toMinor", 2, Pure, "decimal_to_minor", IpeOrder),
            Self::DecAdd => d("Decimal", "add", 2, Pure, "decimal_add", IpeOrder),
            Self::DecSub => d("Decimal", "sub", 2, Pure, "decimal_sub", IpeOrder),
            Self::DecMul => d("Decimal", "mul", 2, Pure, "decimal_mul", IpeOrder),
            Self::DecDiv => d("Decimal", "div", 2, Pure, "decimal_div", IpeOrder),
            Self::DecMod => d("Decimal", "mod", 2, Pure, "decimal_mod", IpeOrder),
            Self::DecNeg => d("Decimal", "neg", 1, Pure, "decimal_neg", IpeOrder),
            Self::DecAbs => d("Decimal", "abs", 1, Pure, "decimal_abs", IpeOrder),
            Self::DecFloor => d("Decimal", "floor", 1, Pure, "decimal_floor", IpeOrder),
            Self::DecCeil => d("Decimal", "ceil", 1, Pure, "decimal_ceil", IpeOrder),
            Self::DecRound => d("Decimal", "round", 2, Pure, "decimal_round", IpeOrder),
            Self::DecRoundHalfUp => d(
                "Decimal",
                "roundHalfUp",
                2,
                Pure,
                "decimal_round_half_up",
                IpeOrder,
            ),
            Self::DecTruncate => d("Decimal", "truncate", 2, Pure, "decimal_truncate", IpeOrder),
            Self::DecCompare => d("Decimal", "compare", 2, Pure, "decimal_compare", IpeOrder),
            Self::DecEq => d("Decimal", "eq", 2, Pure, "decimal_eq", IpeOrder),
            Self::DecNeq => d("Decimal", "neq", 2, Pure, "decimal_neq", IpeOrder),
            Self::DecLt => d("Decimal", "lt", 2, Pure, "decimal_lt", IpeOrder),
            Self::DecLte => d("Decimal", "lte", 2, Pure, "decimal_lte", IpeOrder),
            Self::DecGt => d("Decimal", "gt", 2, Pure, "decimal_gt", IpeOrder),
            Self::DecGte => d("Decimal", "gte", 2, Pure, "decimal_gte", IpeOrder),
            Self::DecMin => d("Decimal", "min", 2, Pure, "decimal_min", IpeOrder),
            Self::DecMax => d("Decimal", "max", 2, Pure, "decimal_max", IpeOrder),
            Self::DecIsZero => d("Decimal", "isZero", 1, Pure, "decimal_is_zero", IpeOrder),
            Self::DecIsPositive => d(
                "Decimal",
                "isPositive",
                1,
                Pure,
                "decimal_is_positive",
                IpeOrder,
            ),
            Self::DecIsNegative => d(
                "Decimal",
                "isNegative",
                1,
                Pure,
                "decimal_is_negative",
                IpeOrder,
            ),
            Self::DecPercentOf => d(
                "Decimal",
                "percentOf",
                2,
                Pure,
                "decimal_percent_of",
                IpeOrder,
            ),
            Self::DecAddPercent => d(
                "Decimal",
                "addPercent",
                2,
                Pure,
                "decimal_add_percent",
                IpeOrder,
            ),
            Self::DecSubPercent => d(
                "Decimal",
                "subPercent",
                2,
                Pure,
                "decimal_sub_percent",
                IpeOrder,
            ),
            Self::DecFormatWith => d(
                "Decimal",
                "formatWith",
                4,
                Pure,
                "decimal_format_with",
                IpeOrder,
            ),
            // ── Ipe.Money — currency table + FX registry + allocate ───────────
            Self::MoneyMinorUnits => d(
                "Money",
                "minorUnits",
                1,
                Pure,
                "money_minor_units",
                IpeOrder,
            ),
            Self::MoneySymbol => d("Money", "symbol", 1, Pure, "money_symbol", IpeOrder),
            Self::MoneyCurrencyName => d(
                "Money",
                "currencyName",
                1,
                Pure,
                "money_currency_name",
                IpeOrder,
            ),
            Self::MoneyIsKnownCurrency => d(
                "Money",
                "isKnownCurrency",
                1,
                Pure,
                "money_is_known_currency",
                IpeOrder,
            ),
            Self::MoneyFormat => d("Money", "format", 2, Pure, "money_format", IpeOrder),
            Self::MoneyFormatWithCode => d(
                "Money",
                "formatWithCode",
                2,
                Pure,
                "money_format_with_code",
                IpeOrder,
            ),
            Self::MoneyAllocate => d("Money", "allocate", 3, Pure, "money_allocate", IpeOrder),
            Self::MoneySetRate => d("Money", "setRate", 3, Pure, "money_set_rate", IpeOrder),
            Self::MoneyGetRate => d("Money", "getRate", 2, Pure, "money_get_rate", IpeOrder),
            Self::MoneyHasRate => d("Money", "hasRate", 2, Pure, "money_has_rate", IpeOrder),
            Self::MoneyClearRates => d(
                "Money",
                "clearRates",
                1,
                Pure,
                "money_clear_rates",
                IpeOrder,
            ),
            // ── Ipe.Db.Sql — SqlFragment builder ───────────────
            Self::SqlColumn => d("Sql", "column", 1, Db, "sql_column", IpeOrder),
            Self::SqlUnsafeFragment => d(
                "Sql",
                "unsafeFragment",
                1,
                Db,
                "sql_unsafe_fragment",
                IpeOrder,
            ),
            // `int` / `string` / `float` / `bool` are Ipê-level type
            // narrowings of `param`; all five share the `sql_param` runtime
            // symbol (see the emit-side note in `ipe_backend_rust::naming`).
            Self::SqlParam => d("Sql", "param", 1, Db, "sql_param", IpeOrder),
            Self::SqlInt => d("Sql", "int", 1, Db, "sql_param", IpeOrder),
            Self::SqlString => d("Sql", "string", 1, Db, "sql_param", IpeOrder),
            Self::SqlFloat => d("Sql", "float", 1, Db, "sql_param", IpeOrder),
            Self::SqlBool => d("Sql", "bool", 1, Db, "sql_param", IpeOrder),
            Self::SqlEq => d("Sql", "eq", 2, Db, "sql_eq", IpeOrder),
            Self::SqlNe => d("Sql", "ne", 2, Db, "sql_ne", IpeOrder),
            Self::SqlGt => d("Sql", "gt", 2, Db, "sql_gt", IpeOrder),
            Self::SqlLt => d("Sql", "lt", 2, Db, "sql_lt", IpeOrder),
            Self::SqlGte => d("Sql", "gte", 2, Db, "sql_gte", IpeOrder),
            Self::SqlLte => d("Sql", "lte", 2, Db, "sql_lte", IpeOrder),
            Self::SqlAnd => d("Sql", "and", 2, Db, "sql_and", IpeOrder),
            Self::SqlOr => d("Sql", "or", 2, Db, "sql_or", IpeOrder),
            Self::SqlNot => d("Sql", "not", 1, Db, "sql_not", IpeOrder),
            Self::SqlIsNull => d("Sql", "isNull", 1, Db, "sql_is_null", IpeOrder),
            Self::SqlIsNotNull => d("Sql", "isNotNull", 1, Db, "sql_is_not_null", IpeOrder),
            Self::SqlInList => d("Sql", "inList", 2, Db, "sql_in_list", IpeOrder),
            Self::SqlLike => d("Sql", "like", 2, Db, "sql_like", IpeOrder),
            Self::SqlExists => d("Sql", "exists", 2, Db, "sql_exists", IpeOrder),
            Self::SqlMaskedColumn => d("Sql", "maskedColumn", 2, Db, "sql_masked_column", IpeOrder),
            Self::DbFindWhere => d("Db", "findWhere", 3, Db, "db_find_where", IpeOrder),
            Self::DbFindWhereMasked => d(
                "Db",
                "findWhereMasked",
                5,
                Db,
                "db_find_where_masked",
                IpeOrder,
            ),
            Self::DbFindJoin => d("Db", "findJoin", 8, Db, "db_find_join", IpeOrder),
            Self::DbFindProjection => d(
                "Db",
                "findProjection",
                8,
                Db,
                "db_find_projection",
                IpeOrder,
            ),
            Self::DbFindJoinOrdered => d(
                "Db",
                "findJoinOrdered",
                11,
                Db,
                "db_find_join_ordered",
                IpeOrder,
            ),
            Self::DbFindProjectionOrdered => d(
                "Db",
                "findProjectionOrdered",
                11,
                Db,
                "db_find_projection_ordered",
                IpeOrder,
            ),
            Self::DbDeleteWhere => d("Db", "deleteWhere", 3, Db, "db_delete_where", IpeOrder),
            Self::DbUpdateWhere => d("Db", "updateWhere", 4, Db, "db_update_where", IpeOrder),
            Self::DbUpsertFields => d("Db", "upsertFields", 4, Db, "db_upsert_fields", IpeOrder),
            Self::DbInsertFieldsChecked => d(
                "Db",
                "insertFieldsChecked",
                4,
                Db,
                "db_insert_fields_checked",
                IpeOrder,
            ),
            Self::DbUpdateWhereChecked => d(
                "Db",
                "updateWhereChecked",
                5,
                Db,
                "db_update_where_checked",
                IpeOrder,
            ),
            // ── Ipe.Secret — opaque secret-string wrapper ─
            Self::SecretFromString => d(
                "Secret",
                "fromString",
                1,
                Pure,
                "secret_from_string",
                IpeOrder,
            ),
            Self::SecretReveal => d("Secret", "reveal", 1, Pure, "secret_reveal", IpeOrder),
            Self::SecretUse => d("Secret", "use", 2, Pure, "secret_use", IpeOrder),
            Self::SecretRedacted => d("Secret", "redacted", 1, Pure, "secret_redacted", IpeOrder),
            // ── Ipe.Regex ────────────────────────────────────────
            // Runtime names MUST match `ipe_runtime::regex_kernel::*` exactly
            // (note `regex_find_all`). Class `Pure` — the kernels are total/pure
            // (no effect); the HM scheme carries no `Task`. `compile` parses the
            // pattern once; every operation then takes the compiled `Regex`.
            Self::RegexCompile => d("Regex", "compile", 1, Pure, "regex_compile", IpeOrder),
            Self::RegexMatch => d("Regex", "match", 2, Pure, "regex_match", IpeOrder),
            Self::RegexFind => d("Regex", "find", 2, Pure, "regex_find", IpeOrder),
            Self::RegexFindAll => d("Regex", "findAll", 2, Pure, "regex_find_all", IpeOrder),
            Self::RegexReplace => d("Regex", "replace", 3, Pure, "regex_replace", IpeOrder),
            Self::RegexSplit => d("Regex", "split", 2, Pure, "regex_split", IpeOrder),
            // ── Ipe.Path ─────────────────────────────────────────
            // Runtime names MUST match `ipe_runtime::path::*` exactly
            // (`path_is_absolute`). Total and effect-free, except `absolute`,
            // which reads the working directory (`Filesystem`) inside an
            // already-`Ready` task.
            Self::PathFromString => d("Path", "fromString", 1, Pure, "path_from_string", IpeOrder),
            Self::PathToString => d("Path", "toString", 1, Pure, "path_to_string", IpeOrder),
            Self::PathBase => d("Path", "base", 1, Pure, "path_base", IpeOrder),
            Self::PathDir => d("Path", "dir", 1, Pure, "path_dir", IpeOrder),
            Self::PathExt => d("Path", "ext", 1, Pure, "path_ext", IpeOrder),
            Self::PathIsAbsolute => d("Path", "isAbsolute", 1, Pure, "path_is_absolute", IpeOrder),
            Self::PathUnder => d("Path", "under", 2, Pure, "path_under", IpeOrder),
            Self::PathAbsolute => d("Path", "absolute", 1, Pure, "path_absolute", IpeOrder),
            // ── Ipe.Trace ─────────────────────────────────────────────
            // Runtime names MUST match `ipe_runtime::trace::*` exactly.
            Self::TraceSpan => d("Trace", "span", 2, Pure, "trace_span", IpeOrder),
            Self::TraceEvent => d("Trace", "event", 1, Pure, "trace_event", IpeOrder),
            Self::TraceAttr => d("Trace", "attr", 2, Pure, "trace_attr", IpeOrder),
            // ── Ipe.Compression ───────────────────────────────────────
            // Runtime names MUST match `ipe_runtime::compression::*` exactly.
            Self::CompressionGzip => {
                d("Compression", "gzip", 1, Pure, "compression_gzip", IpeOrder)
            }
            Self::CompressionGunzip => d(
                "Compression",
                "gunzip",
                1,
                Pure,
                "compression_gunzip",
                IpeOrder,
            ),
            Self::CompressionZstdCompress => d(
                "Compression",
                "zstdCompress",
                1,
                Pure,
                "compression_zstd_compress",
                IpeOrder,
            ),
            Self::CompressionZstdDecompress => d(
                "Compression",
                "zstdDecompress",
                1,
                Pure,
                "compression_zstd_decompress",
                IpeOrder,
            ),
            // ── Ipe.Csv ───────────────────────────────────────────────
            Self::CsvParse => d("Csv", "parse", 1, Pure, "csv_parse", IpeOrder),
            Self::CsvParseWithDelimiter => d(
                "Csv",
                "parseWithDelimiter",
                2,
                Pure,
                "csv_parse_with_delimiter",
                IpeOrder,
            ),
            Self::CsvEncode => d("Csv", "encode", 1, Pure, "csv_encode", IpeOrder),
            Self::CsvEncodeWithDelimiter => d(
                "Csv",
                "encodeWithDelimiter",
                2,
                Pure,
                "csv_encode_with_delimiter",
                IpeOrder,
            ),
            Self::CsvParseStreamFromFile => d(
                "Csv",
                "parseStreamFromFile",
                1,
                Pure,
                "csv_parse_stream_from_file",
                IpeOrder,
            ),
            // ── Ipe.Cache ─────────────────────────────────────────────
            // Runtime names MUST match `ipe_runtime::cache::*` exactly. Alias
            // strings `Cache_newRaw`/`Cache_get`/… split to qualifier `Cache` +
            // the `*Raw`-stripped `name` written here; the emit column is the
            // runtime fn (`cache_new_raw` for `newRaw`).
            Self::CacheNewRaw => d("Cache", "newRaw", 1, Pure, "cache_new_raw", IpeOrder),
            Self::CacheGet => d("Cache", "get", 2, Pure, "cache_get", IpeOrder),
            Self::CachePut => d("Cache", "put", 3, Pure, "cache_put", IpeOrder),
            Self::CacheRemove => d("Cache", "remove", 2, Pure, "cache_remove", IpeOrder),
            Self::CacheClear => d("Cache", "clear", 1, Pure, "cache_clear", IpeOrder),
            Self::CacheSize => d("Cache", "size", 1, Pure, "cache_size", IpeOrder),
            Self::CacheStats => d("Cache", "stats", 1, Pure, "cache_stats", IpeOrder),
            Self::CacheDestroyRaw => d("Cache", "destroy", 1, Pure, "cache_destroy", IpeOrder),

            // ── Ipe.Config ────────────────────────────────────────────
            // The 11 combinator/primitive kernels share the JSON `decode_*`
            // runtime fns; the 5 format/nullable/load kernels are Config-own
            // (`ipe_runtime::config_decode::*`).
            Self::ConfigString => d("Config", "string", 0, Pure, "json_decode_string", IpeOrder),
            Self::ConfigInt => d("Config", "int", 0, Pure, "json_decode_int", IpeOrder),
            Self::ConfigFloat => d("Config", "float", 0, Pure, "json_decode_float", IpeOrder),
            Self::ConfigBool => d("Config", "bool", 0, Pure, "json_decode_bool", IpeOrder),
            Self::ConfigNullable => d("Config", "nullable", 1, Pure, "config_nullable", IpeOrder),
            Self::ConfigField => d("Config", "field", 2, Pure, "decode_field", IpeOrder),
            Self::ConfigAt => d("Config", "at", 2, Pure, "decode_at", IpeOrder),
            Self::ConfigList => d("Config", "list", 1, Pure, "decode_list", IpeOrder),
            Self::ConfigSucceed => d("Config", "succeed", 1, Pure, "decode_succeed", IpeOrder),
            Self::ConfigFail => d("Config", "fail", 1, Pure, "decode_fail", IpeOrder),
            Self::ConfigMap => d("Config", "map", 2, Pure, "decode_map", IpeOrder),
            Self::ConfigAndThen => d(
                "Config",
                "andThen",
                2,
                Pure,
                "decode_and_then",
                ContainerFirst,
            ),
            Self::ConfigMap2 => d("Config", "map2", 3, Pure, "decode_map2", IpeOrder),
            Self::ConfigMap3 => d("Config", "map3", 4, Pure, "decode_map3", IpeOrder),
            Self::ConfigMap4 => d("Config", "map4", 5, Pure, "decode_map4", IpeOrder),
            Self::ConfigMap5 => d("Config", "map5", 6, Pure, "decode_map5", IpeOrder),
            Self::ConfigMap6 => d("Config", "map6", 7, Pure, "decode_map6", IpeOrder),
            Self::ConfigMap7 => d("Config", "map7", 8, Pure, "decode_map7", IpeOrder),
            Self::ConfigMap8 => d("Config", "map8", 9, Pure, "decode_map8", IpeOrder),
            Self::ConfigOneOf => d("Config", "oneOf", 1, Pure, "decode_one_of", IpeOrder),
            Self::ConfigIndex => d("Config", "index", 2, Pure, "decode_index", IpeOrder),
            Self::ConfigKeyValuePairs => d(
                "Config",
                "keyValuePairs",
                1,
                Pure,
                "decode_key_value_pairs",
                IpeOrder,
            ),
            Self::ConfigMaybe => d("Config", "maybe", 1, Pure, "config_maybe", IpeOrder),
            Self::ConfigDict => d("Config", "dict", 1, Pure, "config_dict", IpeOrder),
            Self::ConfigDecodeToml => d(
                "Config",
                "decodeToml",
                2,
                Pure,
                "config_decode_toml",
                IpeOrder,
            ),
            Self::ConfigDecodeYaml => d(
                "Config",
                "decodeYaml",
                2,
                Pure,
                "config_decode_yaml",
                IpeOrder,
            ),
            Self::ConfigDecodeJson => d(
                "Config",
                "decodeJson",
                2,
                Pure,
                "config_decode_json",
                IpeOrder,
            ),
            Self::ConfigLoadFromFile => d(
                "Config",
                "loadFromFile",
                2,
                Pure,
                "config_load_from_file",
                IpeOrder,
            ),
            // ── Ipe.Email ─────────────────────────────────────────────
            // Alias `Email_send` splits to qualifier `Email` + name `send`; the
            // emit column is the runtime fn `ipe_runtime::email::email_send`.
            Self::EmailSend => d("Email", "send", 2, Pure, "email_send", IpeOrder),
            // ── Ipe.Crypto typed-key newtypes ─────────────────────────
            Self::CryptoKeyFromString => d(
                "Key",
                "fromString",
                1,
                Pure,
                "crypto_key_from_string",
                IpeOrder,
            ),
            Self::CryptoKeyFromBytes => d(
                "Key",
                "fromBytes",
                1,
                Pure,
                "crypto_key_from_bytes",
                IpeOrder,
            ),
            Self::CryptoMacToHex => d("Mac", "toHex", 1, Pure, "crypto_mac_to_hex", IpeOrder),
            Self::CryptoHmacSha256WithKey => d(
                "Crypto",
                "hmacSha256WithKey",
                2,
                Pure,
                "crypto_hmac_sha256_key",
                IpeOrder,
            ),
            Self::CryptoHmacSha512WithKey => d(
                "Crypto",
                "hmacSha512WithKey",
                2,
                Pure,
                "crypto_hmac_sha512_key",
                IpeOrder,
            ),
            // ── Ipe.Email.EmailAddress ─────────────────────────────────
            Self::EmailAddressParse => d(
                "EmailAddress",
                "parse",
                1,
                Pure,
                "email_address_parse",
                IpeOrder,
            ),
            Self::EmailAddressToString => d(
                "EmailAddress",
                "toString",
                1,
                Pure,
                "email_address_to_string",
                IpeOrder,
            ),
            // ── Ipe.Url ────────────────────────────────────────────────
            Self::UrlFromString => d("Url", "fromString", 1, Pure, "url_from_string", IpeOrder),
            Self::UrlToString => d("Url", "toString", 1, Pure, "url_to_string", IpeOrder),
            Self::UrlScheme => d("Url", "scheme", 1, Pure, "url_scheme", IpeOrder),
            Self::UrlHost => d("Url", "host", 1, Pure, "url_host", IpeOrder),
            Self::UrlPort => d("Url", "port", 1, Pure, "url_port", IpeOrder),
            Self::UrlPath => d("Url", "path", 1, Pure, "url_path", IpeOrder),
            Self::UrlQuery => d("Url", "query", 1, Pure, "url_query", IpeOrder),
            Self::UrlFragment => d("Url", "fragment", 1, Pure, "url_fragment", IpeOrder),
            Self::UrlSchemeShown => d("Url", "schemeShown", 1, Pure, "url_scheme_shown", IpeOrder),
            Self::UrlBuildQuery => d("Url", "buildQuery", 1, Pure, "url_build_query", IpeOrder),
            Self::UrlRelativeParse => d("Url", "relative", 1, Pure, "url_relative", IpeOrder),
            Self::UrlRelativePath => d(
                "Url",
                "relativePath",
                1,
                Pure,
                "url_relative_path",
                IpeOrder,
            ),
            Self::UrlRelativeQuery => d(
                "Url",
                "relativeQuery",
                1,
                Pure,
                "url_relative_query",
                IpeOrder,
            ),
            Self::UrlRelativeFragment => d(
                "Url",
                "relativeFragment",
                1,
                Pure,
                "url_relative_fragment",
                IpeOrder,
            ),
            Self::UrlRelativeToString => d(
                "Url",
                "relativeToString",
                1,
                Pure,
                "url_relative_to_string",
                IpeOrder,
            ),
            // ── Ipe.Locale ──────────────────────────────────────────────
            Self::LocaleFromTag => d("Locale", "fromTag", 1, Pure, "locale_from_tag", IpeOrder),
            Self::LocaleToTag => d("Locale", "toTag", 1, Pure, "locale_to_tag", IpeOrder),
            // `toUpperIn`/`toLowerIn` live in the `String` qualifier (arity 2:
            // `Locale -> String -> String`) and route to the `locale` module.
            Self::StringToUpperIn => d(
                "String",
                "toUpperIn",
                2,
                Pure,
                "string_to_upper_in",
                IpeOrder,
            ),
            Self::StringToLowerIn => d(
                "String",
                "toLowerIn",
                2,
                Pure,
                "string_to_lower_in",
                IpeOrder,
            ),
        }
    }

    /// All **wired** stdlib kernel variants.
    ///
    /// This slice is the single source of truth used by the canon-equality
    /// tripwire test (`canon_equals_registry` in `ipe_canon`) to verify that
    /// every registry entry has a matching entry in the canon `QUALIFIERS`
    /// table.
    ///
    /// # Exclusions
    ///
    /// `PubSubPublish` / `PubSubPublishNoEcho` / `PubSubTopic` are in `ALL` but
    /// their `"PubSub"` qualifier is not a kernel-`QUALIFIERS` entry — `Ipe.PubSub`
    /// is a compiled-source module, so they are resolved through `Kernel.kernel
    /// "PubSub_*"` aliases, not a canon qualifier. The tripwire skips a qualifier
    /// absent from `qual_vars`, so this is an automatic skip, not a hand-maintained
    /// exclusion. `CmdPublish` / `CmdPublishNoEcho` carry their own `"Cmd"`
    /// `QUALIFIERS` entries.
    pub const ALL: &'static [Self] = &[
        // Log
        Self::LogInfo,
        Self::LogDebug,
        Self::LogWarn,
        Self::LogError,
        Self::LogInfoWith,
        Self::LogDebugWith,
        Self::LogWarnWith,
        Self::LogErrorWith,
        // String
        Self::StringFromInt,
        Self::StringFromFloat,
        Self::StringLength,
        Self::StringIsEmpty,
        Self::StringReverse,
        Self::StringToUpper,
        Self::StringToLower,
        Self::StringCasefold,
        Self::StringTrim,
        Self::StringTrimStart,
        Self::StringTrimEnd,
        Self::StringToInt,
        Self::StringToFloat,
        Self::StringFromChar,
        Self::StringFromBool,
        Self::StringFromList,
        Self::StringConcat,
        Self::StringWords,
        Self::StringLines,
        Self::StringToList,
        Self::StringIsEmail,
        Self::StringIsUrl,
        Self::StringAppend,
        Self::StringContains,
        Self::StringStartsWith,
        Self::StringEndsWith,
        Self::StringEqualFold,
        Self::StringJoin,
        Self::StringSplit,
        Self::StringRepeat,
        Self::StringDropLeft,
        Self::StringDropRight,
        Self::StringReplace,
        Self::StringSlice,
        Self::StringPadLeft,
        Self::StringPadRight,
        Self::StringContainsIn,
        Self::StringStartsWithIn,
        Self::StringEndsWithIn,
        Self::StringLeft,
        Self::StringRight,
        Self::StringCons,
        Self::StringUncons,
        Self::StringPad,
        Self::StringIndexes,
        Self::StringMap,
        Self::StringFilter,
        Self::StringFoldl,
        Self::StringFoldr,
        Self::StringAny,
        Self::StringAll,
        // Char
        Self::CharIsAlpha,
        Self::CharIsDigit,
        Self::CharIsLower,
        Self::CharIsUpper,
        Self::CharToLower,
        Self::CharToUpper,
        Self::CharToCode,
        Self::CharFromCode,
        Self::CharIsAlphaNum,
        Self::CharIsHexDigit,
        Self::CharIsOctDigit,
        // List
        Self::ListMap,
        Self::ListFilter,
        Self::ListFoldl,
        Self::ListFoldr,
        Self::ListLength,
        Self::ListHead,
        Self::ListTail,
        Self::ListMember,
        Self::ListRange,
        Self::ListReverse,
        Self::ListAppend,
        Self::ListConcat,
        Self::ListTake,
        Self::ListDrop,
        Self::ListZip,
        Self::ListCons,
        Self::ListIsEmpty,
        Self::ListConcatMap,
        Self::ListIndexedMap,
        Self::ListAny,
        Self::ListAll,
        Self::ListFind,
        // ── List batch ────────────────────────────────────────────────
        Self::ListFilterMap,
        Self::ListSortBy,
        Self::ListSort,
        Self::ListSortWith,
        Self::ListSingleton,
        Self::ListRepeat,
        Self::ListSum,
        Self::ListProduct,
        Self::ListMaximum,
        Self::ListMinimum,
        Self::ListUnique,
        Self::ListIntersperse,
        Self::ListPartition,
        Self::ListUnzip,
        Self::ListMap2,
        Self::ListMap3,
        Self::ListMap4,
        Self::ListMap5,
        // Basics
        Self::BasicsNot,
        Self::BasicsIdentity,
        Self::BasicsAlways,
        Self::BasicsFst,
        Self::BasicsSnd,
        Self::BasicsModBy,
        Self::BasicsClamp,
        // ── Basics numerics ──────────────────────────────────────────
        Self::BasicsNegate,
        Self::BasicsAbs,
        Self::BasicsSqrt,
        Self::BasicsMin,
        Self::BasicsMax,
        Self::BasicsCompare,
        // ── end Basics numerics ──────────────────────────────────────
        // Error (Ipe.Error — minimal `Error = String` slice)
        Self::ErrorUnexpected,
        Self::ErrorInvalidInput,
        Self::ErrorIo,
        Self::ErrorNetwork,
        Self::ErrorFfi,
        Self::ErrorDecode,
        Self::ErrorConflict,
        Self::ErrorUnavailable,
        Self::ErrorTimeout,
        Self::ErrorNotFound,
        Self::ErrorPermissionDenied,
        Self::ErrorToString,
        Self::ErrorWithMessage,
        Self::ErrorIsRetryable,
        Self::ErrorWithDetails,
        Self::ErrorKind,
        Self::ErrorMessage,
        Self::ErrorKindName,
        // CssSafety (Ipe.CssSafety — Ipe.Css leaf security kernels)
        Self::CssSafetySafeValue,
        Self::CssSafetySafePropName,
        Self::CssSafetySafeSelector,
        Self::CssSafetyStripStyleClose,
        Self::CssSafetySanitizeRawBody,
        // Maybe
        Self::MaybeWithDefault,
        Self::MaybeMap,
        Self::MaybeAndThen,
        Self::MaybeMap2,
        Self::MaybeMap3,
        Self::MaybeMap4,
        Self::MaybeMap5,
        Self::MaybeAndMap,
        Self::MaybeCombine,
        Self::MaybeIsJust,
        Self::MaybeIsNothing,
        // Result
        Self::ResultWithDefault,
        Self::ResultMap,
        Self::ResultAndThen,
        Self::ResultMapError,
        Self::ResultMap2,
        Self::ResultMap3,
        Self::ResultMap4,
        Self::ResultMap5,
        Self::ResultAndMap,
        Self::ResultCombine,
        Self::ResultTraverse,
        Self::ResultToMaybe,
        Self::ResultFromMaybe,
        Self::ResultOkDefault, // qualifier "_internal_" → tripwire skips
        Self::Interpolate,     // qualifier "_internal_" → tripwire skips
        // Math
        Self::MathMin,
        Self::MathMax,
        Self::MathPi,
        Self::MathE,
        Self::MathPhi,
        Self::MathSqrt2,
        Self::MathInf,
        Self::MathNan,
        Self::MathIsNaN,
        Self::MathAbs,
        Self::MathSqrt,
        Self::MathCbrt,
        Self::MathExp,
        Self::MathExp2,
        Self::MathLog,
        Self::MathLog2,
        Self::MathLog10,
        Self::MathSin,
        Self::MathCos,
        Self::MathTan,
        Self::MathAsin,
        Self::MathAcos,
        Self::MathAtan,
        Self::MathSinh,
        Self::MathCosh,
        Self::MathTanh,
        Self::MathAsinh,
        Self::MathAcosh,
        Self::MathAtanh,
        Self::MathFloor,
        Self::MathCeil,
        Self::MathRound,
        Self::MathTrunc,
        Self::MathPow,
        Self::MathHypot,
        Self::MathAtan2,
        Self::MathMod,
        Self::MathRemainder,
        // Bitwise
        Self::BitwiseAnd,
        Self::BitwiseOr,
        Self::BitwiseXor,
        Self::BitwiseComplement,
        Self::BitwiseShiftLeftBy,
        Self::BitwiseShiftRightBy,
        Self::BitwiseShiftRightZfBy,
        // Dict
        Self::DictEmpty,
        Self::DictIsEmpty,
        Self::DictSize,
        Self::DictKeys,
        Self::DictValues,
        Self::DictToList,
        Self::DictFromList,
        Self::DictGet,
        Self::DictMember,
        Self::DictRemove,
        Self::DictUnion,
        Self::DictMap,
        Self::DictInsert,
        Self::DictFoldl,
        Self::DictSingleton,
        Self::DictFoldr,
        Self::DictFilter,
        Self::DictPartition,
        Self::DictIntersect,
        Self::DictDiff,
        Self::DictUpdate,
        // Set
        Self::SetEmpty,
        Self::SetSize,
        Self::SetToList,
        Self::SetFromList,
        Self::SetMember,
        Self::SetInsert,
        Self::SetRemove,
        Self::SetUnion,
        Self::SetIntersect,
        Self::SetDiff,
        Self::SetIsEmpty,
        Self::SetSingleton,
        Self::SetFoldl,
        Self::SetFoldr,
        Self::SetMap,
        Self::SetFilter,
        Self::SetPartition,
        // Bytes
        Self::BytesEmpty,
        Self::BytesLength,
        Self::BytesIsEmpty,
        Self::BytesFromString,
        Self::BytesToString,
        Self::BytesFromHex,
        Self::BytesToHex,
        Self::BytesFromBase64,
        Self::BytesToBase64,
        Self::BytesAppend,
        Self::BytesSlice,
        // Encoding
        Self::EncodingBase64Encode,
        Self::EncodingBase64Decode,
        Self::EncodingUrlEncode,
        Self::EncodingUrlDecode,
        Self::EncodingPercentDecode,
        Self::EncodingHexEncode,
        Self::EncodingHexDecode,
        // Json.Encode
        Self::JsonEncString,
        Self::JsonEncInt,
        Self::JsonEncFloat,
        Self::JsonEncBool,
        Self::JsonEncNull,
        Self::JsonEncList,
        Self::JsonEncObject,
        Self::JsonEncEncode,
        // Json.Decode
        Self::JsonDecString,
        Self::JsonDecInt,
        Self::JsonDecFloat,
        Self::JsonDecBool,
        Self::JsonDecValue,
        Self::JsonDecDecodeString,
        Self::JsonDecDecodeValue,
        Self::JsonDecField,
        Self::JsonDecAt,
        Self::JsonDecIndex,
        Self::JsonDecList,
        Self::JsonDecNullable,
        Self::JsonDecMap,
        Self::JsonDecAndThen,
        Self::JsonDecSucceed,
        Self::JsonDecFail,
        Self::JsonDecOneOf,
        Self::JsonDecMap2,
        Self::JsonDecMap3,
        Self::JsonDecMap4,
        // Json.Decode.Pipeline
        Self::JsonDecPRequired,
        Self::JsonDecPOptional,
        Self::JsonDecPCustom,
        Self::JsonDecPRequiredAt,
        // Crypto
        Self::CryptoSha256,
        Self::CryptoSha512,
        Self::CryptoSha1,
        Self::CryptoMd5,
        Self::CryptoRsaSha256Sign,
        Self::CryptoRsaSha256Verify,
        Self::CryptoConstantTimeEqual,
        Self::CryptoAesGcmEncrypt,
        Self::CryptoAesGcmDecrypt,
        Self::CryptoChacha20Encrypt,
        Self::CryptoChacha20Decrypt,
        Self::CryptoAesKeyFromPassword,
        Self::CryptoChachaKeyFromPassword,
        Self::CryptoRandomBytes,
        Self::CryptoRandomToken,
        // Uuid
        Self::UuidV4,
        Self::UuidV7,
        Self::UuidParse,
        // Jwt
        Self::JwtEncodeHs256,
        Self::JwtDecodeHs256,
        Self::JwtEncodeRs256,
        Self::JwtDecodeRs256,
        // Jwt builder API (D-00)
        Self::JwtClaims,
        Self::JwtHs256,
        Self::JwtRs256,
        Self::JwtSubject,
        Self::JwtIssuer,
        Self::JwtAudience,
        Self::JwtExpiresAt,
        Self::JwtNotBefore,
        Self::JwtIssuedAt,
        Self::JwtJwtId,
        Self::JwtWithClaim,
        Self::JwtEncode,
        Self::JwtDecode,
        // Task
        Self::TaskSucceed,
        Self::TaskFail,
        Self::TaskMap,
        Self::TaskMap2,
        Self::TaskMap3,
        Self::TaskMap4,
        Self::TaskMap5,
        Self::TaskAttempt,
        Self::TaskAndThen,
        Self::TaskMapError,
        Self::TaskOnError,
        Self::TaskFromResult,
        Self::TaskAndThenResult,
        Self::TaskSequence,
        Self::TaskParallel,
        Self::TaskLazy,
        Self::TaskLoop,
        Self::TaskRetryWith,
        Self::TaskLinearBackoff,
        Self::TaskExponentialBackoff,
        Self::TaskWithJitter,
        Self::TaskRetryOn,
        Self::TaskWithRetryOn,
        Self::TaskDefaultRetryPolicy,
        Self::TaskWithMaxAttempts,
        Self::TaskWithBaseMs,
        // Io
        Self::IoReadLine,
        Self::IoReadSecret,
        Self::IoWriteStdout,
        Self::IoWriteStderr,
        Self::IoPrintln,
        Self::IoEprintln,
        // Debug (development-only)
        Self::DebugLog,
        Self::DebugTodo,
        Self::DebugExplain,
        // Time (non-TEA)
        Self::TimeNow,
        Self::TimeSleep,
        Self::TimeUnixMillis,
        Self::TimeTimeString,
        Self::TimeIsLeapYear,
        Self::TimeDaysInMonth,
        Self::TimeFormat,
        Self::TimeFormatHTTP,
        Self::TimeFormatISO8601,
        Self::TimeFormatRFC3339,
        Self::TimeAddMillis,
        Self::TimeDiffMillis,
        // System
        Self::SystemArgs,
        Self::SystemGetenv,
        Self::SystemGetenvOr,
        Self::SystemGetArg,
        Self::SystemGetenvInt,
        Self::SystemGetenvBool,
        Self::SystemSetenv,
        Self::SystemUnsetenv,
        Self::SystemCwd,
        Self::SystemGetcwd,
        Self::SystemLoadEnv,
        Self::SystemExit,
        // Random
        Self::RandomInt,
        Self::RandomFloat,
        Self::RandomChoice,
        Self::RandomChoiceMaybe,
        Self::RandomShuffle,
        Self::RandomWeighted,
        Self::RandomSeededInt,
        Self::RandomSeededFloat,
        Self::RandomSeededChoice,
        // File
        Self::FileReadFile,
        Self::FileWriteFile,
        Self::FileExists,
        Self::FileRemove,
        Self::FileMkdirAll,
        Self::FileReadFileLimit,
        Self::FileReadFileBytes,
        Self::FileAppend,
        Self::FileReadDir,
        Self::FileIsDir,
        Self::FileTempFile,
        Self::FileTempDir,
        Self::FileCopy,
        Self::FileRename,
        Self::FileDelete,
        Self::FileWalk,
        Self::FileWalkMatching,
        // Process
        Self::ProcessRun,
        Self::ProcessRunWith,
        Self::ProcessRunInPty,
        // Http
        Self::HttpGet,
        Self::HttpPost,
        Self::HttpRequest,
        Self::HttpParseQuery,
        Self::HttpDefaultRequest,
        Self::HttpDefaultRequestFromString,
        Self::HttpWithMethod,
        Self::HttpWithTimeout,
        Self::HttpWithBody,
        Self::HttpWithHeader,
        Self::HttpWithUrl,
        Self::HttpWithRedirects,
        Self::HttpMethodFromString,
        Self::HttpMethodToString,
        // Db
        Self::DbConnect,
        Self::DbOpen,
        Self::DbClose,
        Self::DsnParse,
        Self::DsnBuild,
        Self::DsnDriverTag,
        Self::DsnHost,
        Self::DsnPort,
        Self::DsnDatabase,
        Self::DsnUser,
        Self::DsnTlsTag,
        Self::DsnRedacted,
        Self::DbConnOpen,
        Self::DbConnClose,
        Self::DbConnUnsafeExecRawOn,
        Self::DbConnFindWhere,
        Self::DbConnQueryDecode,
        Self::DbConnGetById,
        Self::DbExecRaw,
        Self::DbExec,
        Self::DbQuery,
        Self::DbQueryDecode,
        Self::DbGetString,
        Self::DbGetInt,
        Self::DbGetBool,
        Self::DbGetField,
        Self::DbInsertRow,
        Self::DbGetById,
        Self::DbUpdateById,
        Self::DbDeleteById,
        Self::DbFindOneByField,
        Self::DbFindManyByField,
        Self::DbFindByConditions,
        Self::DbInsertFields,
        Self::DbUpdateFields,
        Self::DbInsertFieldsReturning,
        Self::DbWithTransaction,
        Self::DbMigrate,
        Self::DbDefaultMigration,
        Self::StoreJoin,
        Self::StoreSelect,
        Self::StoreLiteral,
        Self::StoreUpper,
        Self::StoreLower,
        Self::StoreCoalesce,
        Self::StoreAdd,
        Self::StoreSub,
        Self::StoreMul,
        Self::StoreEqCol,
        Self::StoreEqBy,
        Self::StoreNeqCol,
        Self::StoreNeqBy,
        Self::StoreGtCol,
        Self::StoreGtBy,
        Self::StoreGteCol,
        Self::StoreGteBy,
        Self::StoreLtCol,
        Self::StoreLtBy,
        Self::StoreLteCol,
        Self::StoreLteBy,
        Self::StoreLike,
        Self::StoreIsNull,
        Self::StoreNotNull,
        Self::StoreInListCol,
        Self::StoreInListBy,
        // Accessor-typed column-spec builders.
        Self::StorePrimaryKey,
        Self::StoreSerial,
        Self::StoreUnique,
        Self::StoreDefaultNow,
        Self::StoreTouchOnUpdate,
        Self::StoreDefaultText,
        Self::StoreDefaultInt,
        Self::StoreCompositePrimaryKey2,
        Self::StoreCompositePrimaryKey3,
        // Row-security policy builders (accessor-typed).
        Self::StoreOwnerColumn,
        Self::StoreImmutable,
        Self::StoreMask,
        Self::StoreCorrelate,
        Self::StoreExistsIn,
        // orderBy modifiers (accessor-typed).
        Self::StoreOrderByLeft,
        Self::StoreOrderByRight,
        // Db.Decode
        Self::DbDecString,
        Self::DbDecInt,
        Self::DbDecFloat,
        Self::DbDecBool,
        Self::DbDecNullable,
        Self::DbDecMap,
        Self::DbDecAndThen,
        Self::DbDecSucceed,
        Self::DbDecFail,
        Self::DbDecMap2,
        Self::DbDecMap3,
        Self::DbDecMap4,
        Self::DbDecRequired,
        Self::DbDecOptional,
        Self::DbDecMoney,
        Self::DbDecDecimal,
        Self::DbDecBytes,
        // TEA: Cmd / Sub / Time.every
        Self::CmdNone,
        Self::CmdBatch,
        Self::CmdPerform,
        Self::CmdMap,
        Self::CmdPublish,
        Self::CmdPublishNoEcho,
        Self::SubNone,
        Self::SubBatch,
        Self::SubEvery,
        Self::SubMap,
        Self::SubSubscribeTopic,
        Self::TuiSubOnKey,
        Self::CliSubOnLine,
        Self::TimeEvery,
        // Ipe.PubSub — Task-shaped top-level publish (qualifier "PubSub" in
        // canon QUALIFIERS; class = Web, not TEA-loop machinery)
        Self::PubSubPublish,
        Self::PubSubPublishNoEcho,
        // `PubSub.topic` — phantom topic handle constructor (Pure, arity 1).
        Self::PubSubTopic,
        // Ipe.Http.Server / Middleware / RateLimit
        Self::ServerGet,
        Self::ServerPost,
        Self::ServerPut,
        Self::ServerDelete,
        Self::ServerAny,
        Self::ServerApi,
        Self::ServerStatic,
        Self::ServerMountApp,
        Self::ServerListen,
        Self::ServerText,
        Self::ServerJson,
        Self::ServerHtml,
        Self::ServerWithStatus,
        Self::ServerWithHeader,
        Self::ServerRedirect,
        Self::ServerParam,
        Self::ServerQueryParam,
        Self::ServerHeader,
        Self::ServerGetCookie,
        Self::ServerBody,
        Self::ServerPath,
        Self::ServerMethod,
        Self::ServerCookieNew,
        Self::ServerWithCookie,
        Self::ServerAuthConfig,
        Self::ServerTokenBearer,
        Self::ServerCookieToken,
        Self::ServerWithRevocation,
        Self::ServerGetAuthed,
        Self::ServerPostAuthed,
        Self::ServerPutAuthed,
        Self::ServerDeleteAuthed,
        Self::MiddlewareWithCors,
        Self::MiddlewareWithLogging,
        Self::MiddlewareWithBasicAuth,
        Self::MiddlewareWithRateLimit,
        Self::MiddlewareWithCsrf,
        Self::RateLimitAllow,
        // Ui / Html render kernels
        Self::UiLayout,
        Self::UiLayoutWith,
        Self::HtmlRender,
        Self::HtmlEscapeText,
        Self::HtmlEscapeAttr,
        Self::HtmlAttrToString,
        // Ui element builders
        Self::UiNone,
        Self::UiText,
        Self::UiHtml,
        Self::UiCells,
        // Ipe.Ui.Cells Cells-typed builders
        Self::UiCellsNone,
        Self::UiCellsText,
        Self::UiCellsEl,
        Self::UiCellsRow,
        Self::UiCellsColumn,
        Self::UiCellsCells,
        // Ipe.Ui.Tui cell-native attribute builders
        Self::TuiUiSpacing,
        Self::TuiUiPadding,
        Self::TuiUiAlignLeft,
        Self::TuiUiAlignRight,
        Self::TuiUiCenter,
        Self::TuiUiBold,
        Self::TuiUiUnderline,
        Self::TuiUiDim,
        Self::TuiUiReverse,
        Self::TuiUiColor,
        Self::TuiUiBg,
        // Ipe.Ui.Cli line-oriented view + attribute builders
        Self::CliUiNone,
        Self::CliUiText,
        Self::CliUiLine,
        Self::CliUiLines,
        Self::CliUiBold,
        Self::CliUiUnderline,
        Self::CliUiDim,
        Self::CliUiReverse,
        Self::CliUiColor,
        Self::CliUiBg,
        // Ipe.Color terminal palette constructors (the `AnsiColor` type)
        Self::TermColorBlack,
        Self::TermColorRed,
        Self::TermColorGreen,
        Self::TermColorYellow,
        Self::TermColorBlue,
        Self::TermColorMagenta,
        Self::TermColorCyan,
        Self::TermColorWhite,
        Self::TermColorBrightBlack,
        Self::TermColorBrightRed,
        Self::TermColorBrightGreen,
        Self::TermColorBrightYellow,
        Self::TermColorBrightBlue,
        Self::TermColorBrightMagenta,
        Self::TermColorBrightCyan,
        Self::TermColorBrightWhite,
        Self::TermColorDefault,
        Self::TermColorRgb,
        Self::TermColorRgba,
        // ── Ipe.Color constructors ──
        Self::ColorRgb,
        Self::ColorRgba,
        Self::ColorHsl,
        Self::ColorHsla,
        Self::ColorWhite,
        Self::ColorBlack,
        Self::ColorRed,
        Self::ColorGreen,
        Self::ColorBlue,
        Self::ColorTransparent,
        // ── Ipe.Color accessors + manipulation ──
        Self::ColorToCss,
        Self::ColorToCssRgba,
        Self::ColorToHex,
        Self::ColorLuminance,
        Self::ColorWithAlpha,
        Self::ColorMix,
        Self::ColorBlend,
        Self::ColorLighten,
        Self::ColorDarken,
        Self::ColorSaturate,
        Self::ColorDesaturate,
        Self::ColorRotateHue,
        Self::ColorComplementary,
        Self::ColorGrayscale,
        // ── Ipe.Color parse boundary ──
        Self::ColorFromHex,
        Self::ColorFromName,
        // ── Ipe.Color profile / toAnsi ──
        Self::ColorTrueColorProfile,
        Self::ColorAnsi256Profile,
        Self::ColorAnsi16Profile,
        Self::ColorNoColorProfile,
        Self::ColorToAnsi,
        // ── Ipe.Color WCAG / contrast (a11y) ──
        Self::ColorWcagAa,
        Self::ColorWcagAaa,
        Self::ColorNormalText,
        Self::ColorLargeText,
        Self::ColorContrastRatio,
        Self::ColorReadableTextOn,
        Self::ColorMeetsWcag,
        Self::ColorMaximumContrast,
        // ── Ipe.Color colour-vision-deficiency simulation ──
        Self::ColorProtanopia,
        Self::ColorDeuteranopia,
        Self::ColorTritanopia,
        Self::ColorSimulate,
        Self::UiWidget,
        Self::UiNode,
        Self::UiTaggedNode,
        Self::UiButton,
        Self::UiLink,
        Self::UiImage,
        // Ui nearby attribute builders
        Self::UiAbove,
        Self::UiBelow,
        Self::UiOnLeft,
        Self::UiOnRight,
        Self::UiInFront,
        Self::UiBehind,
        // Ui attribute builders
        Self::UiSpacing,
        Self::UiPadding,
        Self::UiPaddingXY,
        Self::UiPaddingEach,
        Self::UiWidth,
        Self::UiHeight,
        Self::UiCenterX,
        Self::UiCenterY,
        Self::UiAlignLeft,
        Self::UiAlignRight,
        Self::UiAlignTop,
        Self::UiAlignBottom,
        Self::UiPointer,
        Self::UiClip,
        Self::UiClipX,
        Self::UiClipY,
        Self::UiScrollbars,
        Self::UiScrollbarX,
        Self::UiScrollbarY,
        Self::UiGridColumns,
        // Ui Length builders
        Self::UiPx,
        Self::UiFill,
        Self::UiContent,
        Self::UiShrink,
        Self::UiFillPortion,
        Self::UiVh,
        Self::UiVw,
        Self::UiMinimum,
        Self::UiMaximum,
        // Ui Color builders
        Self::UiRgb,
        Self::UiRgba,
        Self::UiWhite,
        Self::UiBlack,
        Self::UiTransparent,
        Self::UiColorCss,
        // Background / Border / Font
        Self::BackgroundColor,
        Self::BackgroundImage,
        Self::BackgroundLinearGradient,
        Self::BorderWidth,
        Self::BorderRounded,
        Self::BorderColor,
        Self::BorderWidthEach,
        Self::BorderShadow,
        Self::BorderGlow,
        Self::BorderInnerShadow,
        Self::FontSize,
        Self::FontColor,
        Self::FontFamily,
        Self::FontBold,
        Self::FontItalic,
        // Html element builders
        Self::HtmlTextNode,
        Self::HtmlRawNode,
        Self::HtmlNode,
        Self::HtmlVoidNode,
        Self::HtmlDoctype,
        Self::HtmlTitleNode,
        Self::HtmlToString,
        // Ipe.Html.Attributes retained primitives (reached from the
        // compiled-source module via `Kernel.kernel "Attr_*"`).
        Self::HtmlAttribute,
        Self::HtmlBoolAttribute,
        Self::HtmlNoAttr,
        // `Html.styleNode` (F7) — a canon `Html` qualifier member (env.rs).
        // Registering it here gives it id=Some so its scheme resolves; without
        // this it would fail closed. A canon qualifier member absent from ALL is
        // minted with id=None and fails closed at the caller.
        Self::HtmlStyleNode,
        // `Html.Unsafe.unsafeScript` — same registration rationale as
        // `HtmlStyleNode` above (id=Some so its scheme resolves).
        Self::HtmlScriptNode,
        // Web
        Self::WebApp,
        Self::WebAppRouted,
        Self::WebEmbed,
        Self::WebRoute,
        Self::WebRenderStatic,
        // Terminal
        Self::TerminalAppScreen,
        // Ipe.Web settings-carrying app entry + runtime-config front door
        Self::WebAppWith,
        Self::AppFromEnv,
        Self::AppFromEnvRequired,
        Self::HostBind,
        Self::LogLevelSetting,
        Self::DbUrlSetting,
        Self::ConsoleAdminToken,
        Self::ConsoleIngestToken,
        Self::ConsoleMetricsToken,
        Self::WebCsrf,
        Self::WebSessionTtl,
        Self::WebAuthMaxLifetime,
        Self::WebAuthSlideWindow,
        Self::WebAuthRevocationMode,
        // Config-tag ADT constructors
        Self::HostLoopback,
        Self::HostAllInterfaces,
        Self::HostEnvDriven,
        Self::LevelDebug,
        Self::LevelInfo,
        Self::LevelWarn,
        Self::LevelError,
        Self::WebCsrfStrict,
        Self::WebCsrfInherit,
        // RevocationMode ADT constructors
        Self::WebRevocationOff,
        Self::WebRevocationStore,
        // event-attribute builders
        Self::UiOnClick,
        Self::UiOnFocus,
        Self::UiOnBlur,
        Self::UiOnMouseOver,
        Self::UiOnMouseOut,
        Self::UiOnInput,
        Self::UiOnChange,
        Self::UiOnKeyDown,
        Self::UiOnKeyUp,
        Self::UiOnBool,
        Self::UiOnSubmit,
        Self::UiOnFile,
        // Ipe.Html.Events builders (produce html_attr)
        Self::HtmlOnClick,
        Self::HtmlOnFocus,
        Self::HtmlOnBlur,
        Self::HtmlOnMouseOver,
        Self::HtmlOnMouseOut,
        Self::HtmlOnSubmit,
        Self::HtmlOnInput,
        Self::HtmlOnChange,
        Self::HtmlOnKeyDown,
        Self::HtmlOnKeyUp,
        Self::HtmlOnBool,
        Self::UiSquare,
        Self::UiWidescreen,
        Self::UiCinemascope,
        Self::UiAspectRatio,
        Self::UiAspectRatioWH,
        Self::UiHtmlAttribute,
        Self::UiName,
        Self::UiStyle,
        Self::UiTransitionRaw,
        Self::UiGridTracksRaw,
        Self::UiAnimateRaw,
        Self::UiBreakpoint,
        Self::UiMediaQuery,
        Self::UiMobile,
        Self::UiTablet,
        Self::UiDesktop,
        Self::UiDarkMode,
        Self::UiLightMode,
        Self::UiReducedMotion,
        Self::UiOnPseudo,
        Self::UiHover,
        Self::UiFocus,
        Self::UiFocusVisible,
        Self::UiActive,
        Self::UiDisabled,
        Self::BackgroundHoverColor,
        Self::BackgroundFocusColor,
        Self::BackgroundActiveColor,
        Self::BackgroundDisabledColor,
        Self::BorderSolid,
        Self::BorderDashed,
        Self::BorderDotted,
        Self::BorderHoverColor,
        Self::BorderFocusColor,
        Self::BorderActiveColor,
        Self::BorderHoverWidth,
        Self::BorderHoverRounded,
        Self::FontWeight,
        Self::FontSemiBold,
        Self::FontRegular,
        Self::FontLight,
        Self::FontExtraBold,
        Self::FontBlack,
        Self::FontUnderline,
        Self::FontNoDecoration,
        Self::FontLineThrough,
        Self::FontLetterSpacing,
        Self::FontWordSpacing,
        Self::FontAlignLeft,
        Self::FontAlignRight,
        Self::FontAlignCenter,
        Self::FontCenter,
        Self::FontJustify,
        Self::FontSansSerif,
        Self::FontSerif,
        Self::FontMonospace,
        Self::FontHoverColor,
        Self::FontFocusColor,
        Self::FontActiveColor,
        Self::FontDisabledColor,
        Self::FontHoverSize,
        // ── Effect stdlib modules ────────────────────────────────────────
        Self::TerminalAppLines,
        Self::TeaWorker,
        Self::AuthHashPassword,
        Self::AuthHashPasswordCost,
        Self::AuthVerifyPassword,
        Self::AuthPasswordStrength,
        Self::AuthSignToken,
        Self::AuthVerifyToken,
        Self::AuthRegister,
        Self::AuthLogin,
        Self::AuthSetRole,
        Self::AuthSubject,
        Self::AuthClaim,
        Self::AuthHasRole,
        Self::AuthMemberOf,
        // Ipe.Auth.Revocation — runtime revocation store
        Self::AuthRevocationRevokeUser,
        Self::AuthRevocationRevokeSession,
        Self::AuthRevocationRestoreUser,
        Self::AuthRevocationIsRevoked,
        Self::StreamStream,
        Self::StreamEmit,
        Self::StreamFinish,
        Self::StreamWithContentType,
        Self::HttpStreamOpen,
        Self::HttpStreamForEachChunk,
        Self::HttpStreamClose,
        Self::HttpStreamChunks,
        // ── Ipe.Http.Server.WebSocket (12 kernels) ─────────────────────
        Self::WsDefaultCfg,
        Self::WsWithOnConnect,
        Self::WsWithOnMessage,
        Self::WsWithOnClose,
        Self::WsWithOnError,
        Self::WsWithMaxMessageBytes,
        Self::WsWithOriginPatterns,
        Self::WsUpgrade,
        Self::WsSendToClient,
        Self::WsSendBinaryToClient,
        Self::WsBroadcast,
        Self::WsCloseClient,
        // ── Ipe.WebSocket — outbound WebSocket client (7 kernels) ──
        Self::WebSocketConnect,
        Self::WebSocketConnectWith,
        Self::WebSocketSend,
        Self::WebSocketSendBinary,
        Self::WebSocketClose,
        Self::WebSocketCloseWithCode,
        Self::SubSubscribeWebSocket,
        // ── Ipe.Ffi.Js — the raw typed transport across the Ipê↔JS seam ──────
        Self::JsSend,
        Self::JsSubscribe,
        Self::JsRequest,
        Self::JsOpenSession,
        Self::JsSessionFrames,
        Self::JsSendToSession,
        Self::JsCloseSession,
        // ── Ipe.Env — build-time-embedded public config ──────────────
        Self::EnvPublic,
        // ── Ipe.Ui.Region ──────────────────────────────────────────────
        Self::RegionMainContent,
        Self::RegionNavigation,
        Self::RegionFooter,
        Self::RegionAside,
        Self::RegionHeading,
        Self::RegionLabel,
        Self::RegionAnnounce,
        Self::RegionAnnounceUrgently,
        // ── Ui.input + Ui.describe + desc* constructors ───────────────────
        Self::UiDescribe,
        Self::UiDescNone,
        Self::UiDescParagraph,
        Self::UiDescMain,
        Self::UiDescNavigation,
        Self::UiDescContentInfo,
        Self::UiDescComplementary,
        Self::UiDescLivePolite,
        Self::UiDescLiveAssertive,
        Self::UiDescHeading,
        Self::UiDescLabel,
        // ── Ipe.Ui.Input ───────────────────────────────────────────────
        Self::InputLabelAbove,
        Self::InputLabelBelow,
        Self::InputLabelLeft,
        Self::InputLabelRight,
        Self::InputLabelHidden,
        Self::InputPlaceholder,
        Self::InputText,
        Self::InputMultiline,
        Self::InputEmail,
        Self::InputUsername,
        Self::InputSearch,
        Self::InputCurrentPassword,
        Self::InputNewPassword,
        Self::InputCheckbox,
        Self::InputSlider,
        Self::InputOption,
        Self::InputRadio,
        Self::InputRadioRow,
        // ── Ipe.Ui.Lazy ────────────────────────────────────────────────
        Self::LazyLazy,
        Self::LazyLazy2,
        Self::LazyLazy3,
        Self::LazyLazy4,
        Self::LazyLazy5,
        // ── Ipe.Ui.Keyed ──────────────────────────────────────────────────────
        Self::KeyedColumn,
        Self::KeyedRow,
        // ── Ipe.Decimal ───────────────────────────────────────────────────────
        Self::DecZero,
        Self::DecOne,
        Self::DecOneHundred,
        Self::DecFromString,
        Self::DecFromInt,
        Self::DecFromFloat,
        Self::DecFromMinor,
        Self::DecToString,
        Self::DecToStringFixed,
        Self::DecToFloat,
        Self::DecToInt,
        Self::DecToMinor,
        Self::DecAdd,
        Self::DecSub,
        Self::DecMul,
        Self::DecDiv,
        Self::DecMod,
        Self::DecNeg,
        Self::DecAbs,
        Self::DecFloor,
        Self::DecCeil,
        Self::DecRound,
        Self::DecRoundHalfUp,
        Self::DecTruncate,
        Self::DecCompare,
        Self::DecEq,
        Self::DecNeq,
        Self::DecLt,
        Self::DecLte,
        Self::DecGt,
        Self::DecGte,
        Self::DecMin,
        Self::DecMax,
        Self::DecIsZero,
        Self::DecIsPositive,
        Self::DecIsNegative,
        Self::DecPercentOf,
        Self::DecAddPercent,
        Self::DecSubPercent,
        Self::DecFormatWith,
        Self::MoneyMinorUnits,
        Self::MoneySymbol,
        Self::MoneyCurrencyName,
        Self::MoneyIsKnownCurrency,
        Self::MoneyFormat,
        Self::MoneyFormatWithCode,
        Self::MoneyAllocate,
        Self::MoneySetRate,
        Self::MoneyGetRate,
        Self::MoneyHasRate,
        Self::MoneyClearRates,
        Self::SqlColumn,
        Self::SqlUnsafeFragment,
        Self::SqlParam,
        Self::SqlInt,
        Self::SqlString,
        Self::SqlFloat,
        Self::SqlBool,
        Self::SqlEq,
        Self::SqlNe,
        Self::SqlGt,
        Self::SqlLt,
        Self::SqlGte,
        Self::SqlLte,
        Self::SqlAnd,
        Self::SqlOr,
        Self::SqlNot,
        Self::SqlIsNull,
        Self::SqlIsNotNull,
        Self::SqlInList,
        Self::SqlLike,
        Self::SqlExists,
        Self::SqlMaskedColumn,
        Self::DbFindWhere,
        Self::DbFindWhereMasked,
        Self::DbFindJoin,
        Self::DbFindProjection,
        Self::DbFindJoinOrdered,
        Self::DbFindProjectionOrdered,
        Self::DbDeleteWhere,
        Self::DbUpdateWhere,
        Self::DbUpsertFields,
        Self::DbInsertFieldsChecked,
        Self::DbUpdateWhereChecked,
        Self::SecretFromString,
        Self::SecretReveal,
        Self::SecretUse,
        Self::SecretRedacted,
        // ── Ipe.Regex ────────────────────────────────────────────
        Self::RegexCompile,
        Self::RegexMatch,
        Self::RegexFind,
        Self::RegexFindAll,
        Self::RegexReplace,
        Self::RegexSplit,
        // ── Ipe.Path ─────────────────────────────────────────────
        Self::PathFromString,
        Self::PathToString,
        Self::PathBase,
        Self::PathDir,
        Self::PathExt,
        Self::PathIsAbsolute,
        Self::PathUnder,
        Self::PathAbsolute,
        // ── Ipe.Trace ─────────────────────────────────────────────────
        Self::TraceSpan,
        Self::TraceEvent,
        Self::TraceAttr,
        // ── Ipe.Compression ───────────────────────────────────────────
        Self::CompressionGzip,
        Self::CompressionGunzip,
        Self::CompressionZstdCompress,
        Self::CompressionZstdDecompress,
        // ── Ipe.Csv ───────────────────────────────────────────────────
        Self::CsvParse,
        Self::CsvParseWithDelimiter,
        Self::CsvEncode,
        Self::CsvEncodeWithDelimiter,
        Self::CsvParseStreamFromFile,
        // ── Ipe.Cache ─────────────────────────────────────────────────
        Self::CacheNewRaw,
        Self::CacheGet,
        Self::CachePut,
        Self::CacheRemove,
        Self::CacheClear,
        Self::CacheSize,
        Self::CacheStats,
        Self::CacheDestroyRaw,
        Self::ConfigString,
        Self::ConfigInt,
        Self::ConfigFloat,
        Self::ConfigBool,
        Self::ConfigNullable,
        Self::ConfigField,
        Self::ConfigAt,
        Self::ConfigList,
        Self::ConfigSucceed,
        Self::ConfigFail,
        Self::ConfigMap,
        Self::ConfigAndThen,
        Self::ConfigMap2,
        Self::ConfigMap3,
        Self::ConfigMap4,
        Self::ConfigMap5,
        Self::ConfigMap6,
        Self::ConfigMap7,
        Self::ConfigMap8,
        Self::ConfigOneOf,
        Self::ConfigIndex,
        Self::ConfigKeyValuePairs,
        Self::ConfigMaybe,
        Self::ConfigDict,
        Self::ConfigDecodeToml,
        Self::ConfigDecodeYaml,
        Self::ConfigDecodeJson,
        Self::ConfigLoadFromFile,
        // ── Ipe.Email ─────────────────────────────────────────────────
        Self::EmailSend,
        // ── Ipe.Crypto typed-key newtypes ─────────────────────────────
        Self::CryptoKeyFromString,
        Self::CryptoKeyFromBytes,
        Self::CryptoMacToHex,
        Self::CryptoHmacSha256WithKey,
        Self::CryptoHmacSha512WithKey,
        // ── Ipe.Email.EmailAddress ─────────────────────────────────────
        Self::EmailAddressParse,
        Self::EmailAddressToString,
        // ── Ipe.Url ────────────────────────────────────────────────────
        Self::UrlFromString,
        Self::UrlToString,
        Self::UrlScheme,
        Self::UrlHost,
        Self::UrlPort,
        Self::UrlPath,
        Self::UrlQuery,
        Self::UrlFragment,
        Self::UrlSchemeShown,
        Self::UrlBuildQuery,
        Self::UrlRelativeParse,
        Self::UrlRelativePath,
        Self::UrlRelativeQuery,
        Self::UrlRelativeFragment,
        Self::UrlRelativeToString,
        // ── Ipe.Locale ─────────────────────────────────────────────────
        Self::LocaleFromTag,
        Self::LocaleToTag,
        Self::StringToUpperIn,
        Self::StringToLowerIn,
    ];

    // ── Classification predicates (moved from ipe_ir::KernelFn) ─────────────
    // These are the single authoritative classification lists.  `ipe_ir`
    // re-exports them through the `type KernelFn = StdlibKernel` alias.

    /// `true` when this variant's kernel `class` is [`KernelClass::Db`] — the
    /// `Db` / `Db.Decode` / `Db.Sql` subsystem.
    ///
    /// Derived from the [`Self::decl`] class column (const, so this predicate
    /// stays const) rather than hand-mirroring the variant set. This predicate
    /// is the SOLE selector for the `db` runtime module/feature (`ipe_lower`
    /// sets `uses_db` from it), so a Db-class kernel a hand list forgot would
    /// emit an `ipe`-accepted crate that fails at `cargo` time (E0425/E0433).
    /// Reading the class makes that drift unrepresentable, not merely
    /// test-detectable.
    #[must_use]
    pub const fn is_db(self) -> bool {
        matches!(self.decl().class, KernelClass::Db)
    }

    /// The whole kernel row as one [`KernelDef`] descriptor — the authoritative
    /// source for the co-located per-kernel facts.
    ///
    /// The identity + emit facts (qualifier / name / arity / class / `runtime_fn`)
    /// come from the single [`Self::identity`] match; the security and
    /// runtime-residency axes are aggregated from their own grouped sources
    /// ([`Self::capability`], [`Self::required_runtime_module`]), each the
    /// readable single-source-of-truth for its axis; the scheme is carried as a
    /// [`SchemeKey`] pointing back at this variant. [`Self::decl`] projects this
    /// row back down to the identity subset, so the row and its projection can
    /// never disagree — that binding is what the coherence and
    /// emit-symbol-defined invariant tests gate.
    #[must_use]
    pub const fn def(self) -> KernelDef {
        let identity = self.identity();
        KernelDef {
            qualifier: identity.qualifier,
            name: identity.name,
            arity: identity.arity,
            class: identity.class,
            runtime_fn: identity.emit,
            arg_order: identity.arg_order,
            capability: self.capability_classification(),
            runtime_module: self.required_runtime_module(),
            scheme: SchemeKey(self),
            shape: self.scheme_shape(),
        }
    }

    /// The user-facing qualified source name for this kernel, suitable for
    /// diagnostics and IR pretty-printing.
    ///
    /// For almost every kernel this is `"{qualifier}.{name}"` derived from
    /// [`Self::def`]. The handful of exceptions are kernels whose display path
    /// differs from the canon-resolution qualifier — principally internal
    /// kernels and those relocated into an `Unsafe` sub-module after their
    /// canon entry was registered.
    #[must_use]
    pub fn source_display_name(self) -> String {
        let d = self.def();
        match self {
            // Internal helper — surfaces as `Result.Ok` in diagnostics.
            Self::ResultOkDefault => "Result.Ok".to_owned(),
            // Internal helper — surfaces as the interpolation syntax itself.
            Self::Interpolate => "{{…}} interpolation".to_owned(),
            // Kernels relocated into `Ipe.Db.Unsafe` after the canon qualifier
            // `"Db"` was registered; the display path includes the sub-module.
            Self::DbExecRaw => "Db.Unsafe.unsafeExecRaw".to_owned(),
            Self::DbQuery => "Db.Unsafe.unsafeQuery".to_owned(),
            Self::DbGetString => "Db.Unsafe.unsafeGetString".to_owned(),
            Self::DbGetInt => "Db.Unsafe.unsafeGetInt".to_owned(),
            Self::DbGetBool => "Db.Unsafe.unsafeGetBool".to_owned(),
            Self::DbGetField => "Db.Unsafe.unsafeGetField".to_owned(),
            // `Sql.unsafeFragment` surfaces under `Ipe.Db.Unsafe`.
            Self::SqlUnsafeFragment => "Db.Unsafe.unsafeFragment".to_owned(),
            // Relocated into `Ipe.Html.Unsafe` after canon registration.
            Self::HtmlScriptNode => "Html.Unsafe.unsafeScript".to_owned(),
            // The `Cache.*` kernels are bound to the `*Raw` source functions
            // (`Kernel.kernel "cache_get"` in `Cache.getRaw`); `def().name` is the
            // pure Ipê wrapper (`get`), so the display name is spelled out to
            // name the kernel node, not its wrapper.
            Self::CacheGet => "Cache.getRaw".to_owned(),
            Self::CachePut => "Cache.putRaw".to_owned(),
            Self::CacheRemove => "Cache.removeRaw".to_owned(),
            Self::CacheClear => "Cache.clearRaw".to_owned(),
            Self::CacheSize => "Cache.sizeRaw".to_owned(),
            Self::CacheStats => "Cache.statsRaw".to_owned(),
            Self::CacheDestroyRaw => "Cache.destroyRaw".to_owned(),
            // Default: derive from the canonical qualifier + name.
            _ => format!("{}.{}", d.qualifier, d.name),
        }
    }

    /// The structural [`TyShape`] encoding of this kernel's HM type scheme — the
    /// single source `ipe_types` interprets into the concrete `Ty`.
    ///
    /// `Some` for every schemed kernel; `None` ONLY for a genuinely unschemed
    /// kernel (a routed / unlowered bucket), whose caller fails closed rather than
    /// type-checks. A shape may be **monomorphic** (an arrow spine over the
    /// primitive built-ins) or **rank-1 polymorphic** (over [`TyShape::Var`]
    /// applied to the `List` / `Maybe` / `Dict` / `Set` and every opaque
    /// [`BuiltinTag`] constructor, tuples, records, and open rows). [`TyShape`]'s
    /// vocabulary carries a [`TyShape::Tuple`] node, a [`TyShape::Record`] node,
    /// and a [`RowTailShape::Open`] open-tail marker, so tuple-, record-, and
    /// open-row-shaped schemes are all expressible.
    ///
    /// A `comparable` / `number`-obligated member (`sort`/`sortBy`, `sum`,
    /// `product`, `maximum`, `minimum`, `min`/`max`, `clamp`, the `Store`
    /// arithmetic operators) carries its BASE (unbounded) shape here; the bound
    /// is minted in `constrain_var_kernel`, which takes the base scheme by
    /// direct-build or by tying the base's var to a bounded super-var.
    #[must_use]
    #[allow(clippy::too_many_lines)] // one flat declarative spine table per family
    #[allow(clippy::match_same_arms)] // family-grouped spine table; merging cross-family arms with coincidentally-equal spines would obscure the per-family structure
    pub const fn scheme_shape(self) -> Option<&'static TyShape> {
        // ── Primitive leaves (nullary constructor applications). ──
        const INT: TyShape = TyShape::Con(BuiltinTag::Int, &[]);
        const FLOAT: TyShape = TyShape::Con(BuiltinTag::Float, &[]);
        const BOOL: TyShape = TyShape::Con(BuiltinTag::Bool, &[]);
        const STRING: TyShape = TyShape::Con(BuiltinTag::String, &[]);
        const CHAR: TyShape = TyShape::Con(BuiltinTag::Char, &[]);
        const BYTES: TyShape = TyShape::Con(BuiltinTag::Bytes, &[]);
        // ── Arrow spines, each named by its curried signature. ──
        const INT_TO_INT: TyShape = TyShape::Fun(&INT, &INT);
        const INT_TO_INT_TO_INT: TyShape = TyShape::Fun(&INT, &INT_TO_INT);
        const INT_TO_BOOL: TyShape = TyShape::Fun(&INT, &BOOL);
        const INT_TO_STRING: TyShape = TyShape::Fun(&INT, &STRING);
        const INT_TO_CHAR: TyShape = TyShape::Fun(&INT, &CHAR);
        const FLOAT_TO_FLOAT: TyShape = TyShape::Fun(&FLOAT, &FLOAT);
        const FLOAT_TO_INT: TyShape = TyShape::Fun(&FLOAT, &INT);
        const FLOAT_TO_BOOL: TyShape = TyShape::Fun(&FLOAT, &BOOL);
        const FLOAT_TO_STRING: TyShape = TyShape::Fun(&FLOAT, &STRING);
        const FLOAT_TO_FLOAT_TO_FLOAT: TyShape = TyShape::Fun(&FLOAT, &FLOAT_TO_FLOAT);
        const BOOL_TO_BOOL: TyShape = TyShape::Fun(&BOOL, &BOOL);
        const CHAR_TO_BOOL: TyShape = TyShape::Fun(&CHAR, &BOOL);
        const CHAR_TO_INT: TyShape = TyShape::Fun(&CHAR, &INT);
        const CHAR_TO_STRING: TyShape = TyShape::Fun(&CHAR, &STRING);
        const BOOL_TO_STRING: TyShape = TyShape::Fun(&BOOL, &STRING);
        const CHAR_TO_CHAR: TyShape = TyShape::Fun(&CHAR, &CHAR);
        const STRING_TO_INT: TyShape = TyShape::Fun(&STRING, &INT);
        const STRING_TO_BOOL: TyShape = TyShape::Fun(&STRING, &BOOL);
        const STRING_TO_STRING: TyShape = TyShape::Fun(&STRING, &STRING);
        const STRING_TO_BYTES: TyShape = TyShape::Fun(&STRING, &BYTES);
        const STRING_TO_INT_TO_STRING: TyShape = TyShape::Fun(&STRING, &INT_TO_STRING);
        const STRING_TO_STRING_TO_STRING: TyShape = TyShape::Fun(&STRING, &STRING_TO_STRING);
        const STRING_TO_STRING_TO_BOOL: TyShape = TyShape::Fun(&STRING, &STRING_TO_BOOL);
        const STRING_TO_STRING_TO_STRING_TO_STRING: TyShape =
            TyShape::Fun(&STRING, &STRING_TO_STRING_TO_STRING);
        const STRING_TO_STRING_TO_STRING_TO_BOOL: TyShape =
            TyShape::Fun(&STRING, &STRING_TO_STRING_TO_BOOL);
        const BYTES_TO_INT: TyShape = TyShape::Fun(&BYTES, &INT);
        const BYTES_TO_BOOL: TyShape = TyShape::Fun(&BYTES, &BOOL);
        const BYTES_TO_STRING: TyShape = TyShape::Fun(&BYTES, &STRING);
        const BYTES_TO_BYTES: TyShape = TyShape::Fun(&BYTES, &BYTES);
        const BYTES_TO_BYTES_TO_BYTES: TyShape = TyShape::Fun(&BYTES, &BYTES_TO_BYTES);
        const INT_TO_BYTES_TO_BYTES: TyShape = TyShape::Fun(&INT, &BYTES_TO_BYTES);
        const INT_TO_INT_TO_BYTES_TO_BYTES: TyShape = TyShape::Fun(&INT, &INT_TO_BYTES_TO_BYTES);
        const INT_TO_STRING_TO_STRING: TyShape = TyShape::Fun(&INT, &STRING_TO_STRING);
        const INT_TO_INT_TO_STRING_TO_STRING: TyShape =
            TyShape::Fun(&INT, &INT_TO_STRING_TO_STRING);
        const CHAR_TO_STRING_TO_STRING: TyShape = TyShape::Fun(&CHAR, &STRING_TO_STRING);
        const INT_TO_CHAR_TO_STRING_TO_STRING: TyShape =
            TyShape::Fun(&INT, &CHAR_TO_STRING_TO_STRING);
        // Higher-order-over-`Char` spines (the callback is itself an all-primitive
        // arrow — no type variable, so still fully monomorphic).
        const CHAR_TO_CHAR_ARROW: TyShape = TyShape::Fun(&CHAR_TO_CHAR, &STRING_TO_STRING);
        const CHAR_TO_BOOL_TO_STRING_STRING: TyShape =
            TyShape::Fun(&CHAR_TO_BOOL, &STRING_TO_STRING);
        const STRING_TO_BOOL_SPINE: TyShape = TyShape::Fun(&STRING, &BOOL);
        const CHAR_TO_BOOL_TO_STRING_BOOL: TyShape =
            TyShape::Fun(&CHAR_TO_BOOL, &STRING_TO_BOOL_SPINE);
        // `String -> String -> Int -> Int -> Bool` (RateLimit.allow).
        const INT_TO_INT_TO_BOOL: TyShape = TyShape::Fun(&INT, &INT_TO_BOOL);
        const STRING_TO_INT_TO_INT_TO_BOOL: TyShape = TyShape::Fun(&STRING, &INT_TO_INT_TO_BOOL);
        const STRING_TO_STRING_TO_INT_TO_INT_TO_BOOL: TyShape =
            TyShape::Fun(&STRING, &STRING_TO_INT_TO_INT_TO_BOOL);

        // ── Polymorphic leaves for the core `List` combinator family. ──
        // Scheme-local type variables `a` (index 0) and `b` (index 1); `Int` /
        // `Bool` reuse the primitive leaves above.
        const A: TyShape = TyShape::Var(0);
        const B: TyShape = TyShape::Var(1);
        // `List a` / `List b` / `List Int` / `List (List a)` and `Maybe a` /
        // `Maybe (List a)` / `Maybe b` constructor applications, spelled once and
        // reused by reference.
        const LIST_A: TyShape = TyShape::Con(BuiltinTag::List, &[A]);
        const LIST_B: TyShape = TyShape::Con(BuiltinTag::List, &[B]);
        const LIST_INT: TyShape = TyShape::Con(BuiltinTag::List, &[INT]);
        const LIST_LIST_A: TyShape = TyShape::Con(BuiltinTag::List, &[LIST_A]);
        const MAYBE_A: TyShape = TyShape::Con(BuiltinTag::Maybe, &[A]);
        const MAYBE_B: TyShape = TyShape::Con(BuiltinTag::Maybe, &[B]);
        const MAYBE_LIST_A: TyShape = TyShape::Con(BuiltinTag::Maybe, &[LIST_A]);
        // Shared arrow spines over the `List` variables.
        const LIST_A_TO_LIST_A: TyShape = TyShape::Fun(&LIST_A, &LIST_A);
        const LIST_A_TO_LIST_B: TyShape = TyShape::Fun(&LIST_A, &LIST_B);
        const LIST_A_TO_BOOL: TyShape = TyShape::Fun(&LIST_A, &BOOL);
        const LIST_A_TO_MAYBE_A: TyShape = TyShape::Fun(&LIST_A, &MAYBE_A);
        // map : (a -> b) -> List a -> List b
        const A_TO_B: TyShape = TyShape::Fun(&A, &B);
        const LIST_MAP: TyShape = TyShape::Fun(&A_TO_B, &LIST_A_TO_LIST_B);
        // filter / any / find : (a -> Bool) -> List a -> (List a | Bool | Maybe a)
        const A_TO_BOOL: TyShape = TyShape::Fun(&A, &BOOL);
        const LIST_FILTER: TyShape = TyShape::Fun(&A_TO_BOOL, &LIST_A_TO_LIST_A);
        const LIST_ANY: TyShape = TyShape::Fun(&A_TO_BOOL, &LIST_A_TO_BOOL);
        const LIST_FIND: TyShape = TyShape::Fun(&A_TO_BOOL, &LIST_A_TO_MAYBE_A);
        // length : List a -> Int
        const LIST_LENGTH: TyShape = TyShape::Fun(&LIST_A, &INT);
        // tail : List a -> Maybe (List a)
        const LIST_TAIL: TyShape = TyShape::Fun(&LIST_A, &MAYBE_LIST_A);
        // member / cons / intersperse : a -> List a -> (Bool | List a)
        const LIST_MEMBER: TyShape = TyShape::Fun(&A, &LIST_A_TO_BOOL);
        const LIST_CONS: TyShape = TyShape::Fun(&A, &LIST_A_TO_LIST_A);
        // range : Int -> Int -> List Int
        const INT_TO_LIST_INT: TyShape = TyShape::Fun(&INT, &LIST_INT);
        const LIST_RANGE: TyShape = TyShape::Fun(&INT, &INT_TO_LIST_INT);
        // append : List a -> List a -> List a
        const LIST_APPEND: TyShape = TyShape::Fun(&LIST_A, &LIST_A_TO_LIST_A);
        // concat : List (List a) -> List a
        const LIST_CONCAT: TyShape = TyShape::Fun(&LIST_LIST_A, &LIST_A);
        // take / drop : Int -> List a -> List a
        const INT_TO_LIST_A_TO_LIST_A: TyShape = TyShape::Fun(&INT, &LIST_A_TO_LIST_A);
        // singleton : a -> List a; repeat : Int -> a -> List a
        const A_TO_LIST_A: TyShape = TyShape::Fun(&A, &LIST_A);
        const LIST_REPEAT: TyShape = TyShape::Fun(&INT, &A_TO_LIST_A);
        // concatMap : (a -> List b) -> List a -> List b
        const A_TO_LIST_B: TyShape = TyShape::Fun(&A, &LIST_B);
        const LIST_CONCAT_MAP: TyShape = TyShape::Fun(&A_TO_LIST_B, &LIST_A_TO_LIST_B);
        // filterMap : (a -> Maybe b) -> List a -> List b
        const A_TO_MAYBE_B: TyShape = TyShape::Fun(&A, &MAYBE_B);
        const LIST_FILTER_MAP: TyShape = TyShape::Fun(&A_TO_MAYBE_B, &LIST_A_TO_LIST_B);

        // ── Further scheme-local variables and constructor leaves. ──
        // Vars `c` (2), `d` (3), `e` (4), `f` (5), `g` (6) for the N-ary
        // combinators; `Order` / `Set a` / `Set b` / `Result e a` and the `Dict`
        // key/value applications, spelled once and reused by reference.
        const C: TyShape = TyShape::Var(2);
        const D: TyShape = TyShape::Var(3);
        const E: TyShape = TyShape::Var(4);
        const F: TyShape = TyShape::Var(5);
        const G: TyShape = TyShape::Var(6);
        const ORDER: TyShape = TyShape::Con(BuiltinTag::Order, &[]);

        // ── List fold / sort / reduce (rank-1 polymorphic, arrow-only). ──
        // foldl / foldr : (a -> b -> b) -> b -> List a -> b
        const A_TO_B_TO_B: TyShape = TyShape::Fun(&A, &TyShape::Fun(&B, &B));
        const LIST_A_TO_B: TyShape = TyShape::Fun(&LIST_A, &B);
        const B_TO_LIST_A_TO_B: TyShape = TyShape::Fun(&B, &LIST_A_TO_B);
        const LIST_FOLD: TyShape = TyShape::Fun(&A_TO_B_TO_B, &B_TO_LIST_A_TO_B);
        // sort : List a -> List a  (base scheme; the Ord obligation is layered
        // separately, so the shape is exercised only by the totality / oracle
        // tripwires, never in production).
        const LIST_SORT: TyShape = LIST_A_TO_LIST_A;
        // sortBy : (a -> b) -> List a -> List a  (base scheme).
        const LIST_SORT_BY: TyShape = TyShape::Fun(&A_TO_B, &LIST_A_TO_LIST_A);
        // sortWith : (a -> a -> Order) -> List a -> List a
        const A_TO_A_TO_ORDER: TyShape = TyShape::Fun(&A, &TyShape::Fun(&A, &ORDER));
        const LIST_SORT_WITH: TyShape = TyShape::Fun(&A_TO_A_TO_ORDER, &LIST_A_TO_LIST_A);
        // sum / product : List a -> a  (base scheme; number obligation layered).
        const LIST_SUM: TyShape = TyShape::Fun(&LIST_A, &A);
        // maximum / minimum : List a -> Maybe a  (base scheme; Ord obligation
        // layered).
        const LIST_MAX_MIN: TyShape = LIST_A_TO_MAYBE_A;

        // ── Basics (rank-1 polymorphic, arrow-only). ──
        // identity : a -> a; negate / abs : a -> a (base scheme).
        const A_TO_A: TyShape = TyShape::Fun(&A, &A);
        // always : a -> b -> a
        const B_TO_A: TyShape = TyShape::Fun(&B, &A);
        const BASICS_ALWAYS: TyShape = TyShape::Fun(&A, &B_TO_A);
        // modBy : Int -> Int -> Int
        const INT_TO_INT_TO_INT_LEAF: TyShape = INT_TO_INT_TO_INT;
        // clamp / min / max : a -> a -> a (base scheme; Ord obligation layered).
        const A_TO_A_TO_A: TyShape = TyShape::Fun(&A, &A_TO_A);
        const BASICS_CLAMP: TyShape = TyShape::Fun(&A, &A_TO_A_TO_A);
        // interpolate : a -> String (base scheme; interpolable obligation layered).
        const A_TO_STRING: TyShape = TyShape::Fun(&A, &STRING);
        // compare : a -> a -> Order (base scheme; Ord obligation layered).
        const A_TO_ORDER: TyShape = TyShape::Fun(&A, &ORDER);
        const BASICS_COMPARE: TyShape = TyShape::Fun(&A, &A_TO_ORDER);

        // ── Maybe combinators (rank-1 polymorphic, arrow-only). ──
        // withDefault : a -> Maybe a -> a
        const MAYBE_A_TO_A: TyShape = TyShape::Fun(&MAYBE_A, &A);
        const MAYBE_WITH_DEFAULT: TyShape = TyShape::Fun(&A, &MAYBE_A_TO_A);
        // map : (a -> b) -> Maybe a -> Maybe b
        const MAYBE_A_TO_MAYBE_B: TyShape = TyShape::Fun(&MAYBE_A, &MAYBE_B);
        const MAYBE_MAP: TyShape = TyShape::Fun(&A_TO_B, &MAYBE_A_TO_MAYBE_B);
        // andThen : (a -> Maybe b) -> Maybe a -> Maybe b
        const MAYBE_AND_THEN: TyShape = TyShape::Fun(&A_TO_MAYBE_B, &MAYBE_A_TO_MAYBE_B);
        // map2 : (a -> b -> c) -> Maybe a -> Maybe b -> Maybe c
        const MAYBE_C: TyShape = TyShape::Con(BuiltinTag::Maybe, &[C]);
        const A_TO_B_TO_C: TyShape = TyShape::Fun(&A, &TyShape::Fun(&B, &C));
        const MAYBE_MAP2: TyShape = TyShape::Fun(
            &A_TO_B_TO_C,
            &TyShape::Fun(&MAYBE_A, &TyShape::Fun(&MAYBE_B, &MAYBE_C)),
        );
        // map3 : (a -> b -> c -> d) -> Maybe a -> Maybe b -> Maybe c -> Maybe d
        const MAYBE_D: TyShape = TyShape::Con(BuiltinTag::Maybe, &[D]);
        const A_TO_B_TO_C_TO_D: TyShape =
            TyShape::Fun(&A, &TyShape::Fun(&B, &TyShape::Fun(&C, &D)));
        const MAYBE_MAP3: TyShape = TyShape::Fun(
            &A_TO_B_TO_C_TO_D,
            &TyShape::Fun(
                &MAYBE_A,
                &TyShape::Fun(&MAYBE_B, &TyShape::Fun(&MAYBE_C, &MAYBE_D)),
            ),
        );
        // map4 : (a -> b -> c -> d -> e) -> Maybe a..d -> Maybe e
        const MAYBE_E: TyShape = TyShape::Con(BuiltinTag::Maybe, &[E]);
        const A_TO_B_TO_C_TO_D_TO_E: TyShape = TyShape::Fun(
            &A,
            &TyShape::Fun(&B, &TyShape::Fun(&C, &TyShape::Fun(&D, &E))),
        );
        const MAYBE_MAP4: TyShape = TyShape::Fun(
            &A_TO_B_TO_C_TO_D_TO_E,
            &TyShape::Fun(
                &MAYBE_A,
                &TyShape::Fun(
                    &MAYBE_B,
                    &TyShape::Fun(&MAYBE_C, &TyShape::Fun(&MAYBE_D, &MAYBE_E)),
                ),
            ),
        );
        // map5 : (a -> b -> c -> d -> e -> f) -> Maybe a..e -> Maybe f
        const MAYBE_F: TyShape = TyShape::Con(BuiltinTag::Maybe, &[F]);
        const A_TO_B_TO_C_TO_D_TO_E_TO_F: TyShape = TyShape::Fun(
            &A,
            &TyShape::Fun(
                &B,
                &TyShape::Fun(&C, &TyShape::Fun(&D, &TyShape::Fun(&E, &F))),
            ),
        );
        const MAYBE_MAP5: TyShape = TyShape::Fun(
            &A_TO_B_TO_C_TO_D_TO_E_TO_F,
            &TyShape::Fun(
                &MAYBE_A,
                &TyShape::Fun(
                    &MAYBE_B,
                    &TyShape::Fun(
                        &MAYBE_C,
                        &TyShape::Fun(&MAYBE_D, &TyShape::Fun(&MAYBE_E, &MAYBE_F)),
                    ),
                ),
            ),
        );
        // andMap : Maybe a -> Maybe (a -> b) -> Maybe b
        const MAYBE_A_TO_B: TyShape = TyShape::Con(BuiltinTag::Maybe, &[A_TO_B]);
        const MAYBE_AND_MAP: TyShape =
            TyShape::Fun(&MAYBE_A, &TyShape::Fun(&MAYBE_A_TO_B, &MAYBE_B));
        // combine : List (Maybe a) -> Maybe (List a)
        const LIST_MAYBE_A: TyShape = TyShape::Con(BuiltinTag::List, &[MAYBE_A]);
        const MAYBE_LIST_A_LEAF: TyShape = MAYBE_LIST_A;
        const MAYBE_COMBINE: TyShape = TyShape::Fun(&LIST_MAYBE_A, &MAYBE_LIST_A_LEAF);
        // isJust : Maybe a -> Bool
        const MAYBE_IS_JUST: TyShape = TyShape::Fun(&MAYBE_A, &BOOL);
        // isNothing : Maybe a -> Bool
        const MAYBE_IS_NOTHING: TyShape = TyShape::Fun(&MAYBE_A, &BOOL);

        // ── Result combinators (rank-1 polymorphic, arrow-only). Var indices
        //    follow each kernel's published signature exactly. ──
        // withDefault : a -> Result b a -> a   (var(0)=a, var(1)=b)
        const RESULT_B_A: TyShape = TyShape::Con(BuiltinTag::Result, &[B, A]);
        const RESULT_B_A_TO_A: TyShape = TyShape::Fun(&RESULT_B_A, &A);
        const RESULT_WITH_DEFAULT: TyShape = TyShape::Fun(&A, &RESULT_B_A_TO_A);
        // map : (a -> b) -> Result c a -> Result c b  (var(0)=a, var(1)=b, var(2)=c)
        const RESULT_C_A: TyShape = TyShape::Con(BuiltinTag::Result, &[C, A]);
        const RESULT_C_B: TyShape = TyShape::Con(BuiltinTag::Result, &[C, B]);
        const RESULT_MAP: TyShape = TyShape::Fun(&A_TO_B, &TyShape::Fun(&RESULT_C_A, &RESULT_C_B));
        // andThen : (a -> Result b c) -> Result b a -> Result b c
        const RESULT_B_C: TyShape = TyShape::Con(BuiltinTag::Result, &[B, C]);
        const A_TO_RESULT_B_C: TyShape = TyShape::Fun(&A, &RESULT_B_C);
        const RESULT_AND_THEN: TyShape =
            TyShape::Fun(&A_TO_RESULT_B_C, &TyShape::Fun(&RESULT_B_A, &RESULT_B_C));
        // mapError : (a -> b) -> Result a c -> Result b c
        const RESULT_A_C: TyShape = TyShape::Con(BuiltinTag::Result, &[A, C]);
        const RESULT_B_C2: TyShape = TyShape::Con(BuiltinTag::Result, &[B, C]);
        const RESULT_MAP_ERROR: TyShape =
            TyShape::Fun(&A_TO_B, &TyShape::Fun(&RESULT_A_C, &RESULT_B_C2));
        // map2 : (a -> b -> c) -> Result d a -> Result d b -> Result d c
        const RESULT_D_A: TyShape = TyShape::Con(BuiltinTag::Result, &[D, A]);
        const RESULT_D_B: TyShape = TyShape::Con(BuiltinTag::Result, &[D, B]);
        const RESULT_D_C: TyShape = TyShape::Con(BuiltinTag::Result, &[D, C]);
        const RESULT_MAP2: TyShape = TyShape::Fun(
            &A_TO_B_TO_C,
            &TyShape::Fun(&RESULT_D_A, &TyShape::Fun(&RESULT_D_B, &RESULT_D_C)),
        );
        // map3 : (a -> b -> c -> d) -> Result e a -> Result e b -> Result e c -> Result e d
        const RESULT_E_A: TyShape = TyShape::Con(BuiltinTag::Result, &[E, A]);
        const RESULT_E_B: TyShape = TyShape::Con(BuiltinTag::Result, &[E, B]);
        const RESULT_E_C: TyShape = TyShape::Con(BuiltinTag::Result, &[E, C]);
        const RESULT_E_D: TyShape = TyShape::Con(BuiltinTag::Result, &[E, D]);
        const RESULT_MAP3: TyShape = TyShape::Fun(
            &A_TO_B_TO_C_TO_D,
            &TyShape::Fun(
                &RESULT_E_A,
                &TyShape::Fun(&RESULT_E_B, &TyShape::Fun(&RESULT_E_C, &RESULT_E_D)),
            ),
        );
        // map4 : (a -> b -> c -> d -> e) -> Result f a..d -> Result f e
        const RESULT_F_A: TyShape = TyShape::Con(BuiltinTag::Result, &[F, A]);
        const RESULT_F_B: TyShape = TyShape::Con(BuiltinTag::Result, &[F, B]);
        const RESULT_F_C: TyShape = TyShape::Con(BuiltinTag::Result, &[F, C]);
        const RESULT_F_D: TyShape = TyShape::Con(BuiltinTag::Result, &[F, D]);
        const RESULT_F_E: TyShape = TyShape::Con(BuiltinTag::Result, &[F, E]);
        const RESULT_MAP4: TyShape = TyShape::Fun(
            &A_TO_B_TO_C_TO_D_TO_E,
            &TyShape::Fun(
                &RESULT_F_A,
                &TyShape::Fun(
                    &RESULT_F_B,
                    &TyShape::Fun(&RESULT_F_C, &TyShape::Fun(&RESULT_F_D, &RESULT_F_E)),
                ),
            ),
        );
        // map5 : (a -> b -> c -> d -> e -> f) -> Result g a..e -> Result g f
        const RESULT_G_A: TyShape = TyShape::Con(BuiltinTag::Result, &[G, A]);
        const RESULT_G_B: TyShape = TyShape::Con(BuiltinTag::Result, &[G, B]);
        const RESULT_G_C: TyShape = TyShape::Con(BuiltinTag::Result, &[G, C]);
        const RESULT_G_D: TyShape = TyShape::Con(BuiltinTag::Result, &[G, D]);
        const RESULT_G_E: TyShape = TyShape::Con(BuiltinTag::Result, &[G, E]);
        const RESULT_G_F: TyShape = TyShape::Con(BuiltinTag::Result, &[G, F]);
        const RESULT_MAP5: TyShape = TyShape::Fun(
            &A_TO_B_TO_C_TO_D_TO_E_TO_F,
            &TyShape::Fun(
                &RESULT_G_A,
                &TyShape::Fun(
                    &RESULT_G_B,
                    &TyShape::Fun(
                        &RESULT_G_C,
                        &TyShape::Fun(&RESULT_G_D, &TyShape::Fun(&RESULT_G_E, &RESULT_G_F)),
                    ),
                ),
            ),
        );
        // andMap : Result c a -> Result c (a -> b) -> Result c b
        const RESULT_C_A_TO_B: TyShape = TyShape::Con(BuiltinTag::Result, &[C, A_TO_B]);
        const RESULT_AND_MAP: TyShape =
            TyShape::Fun(&RESULT_C_A, &TyShape::Fun(&RESULT_C_A_TO_B, &RESULT_C_B));
        // combine : List (Result b a) -> Result b (List a)   (var(0)=a, var(1)=b)
        const LIST_RESULT_B_A: TyShape = TyShape::Con(BuiltinTag::List, &[RESULT_B_A]);
        const RESULT_B_LIST_A: TyShape = TyShape::Con(BuiltinTag::Result, &[B, LIST_A]);
        const RESULT_COMBINE: TyShape = TyShape::Fun(&LIST_RESULT_B_A, &RESULT_B_LIST_A);
        // traverse : (a -> Result c b) -> List a -> Result c (List b)
        const A_TO_RESULT_C_B: TyShape = TyShape::Fun(&A, &RESULT_C_B);
        const RESULT_C_LIST_B: TyShape = TyShape::Con(BuiltinTag::Result, &[C, LIST_B]);
        const RESULT_TRAVERSE: TyShape =
            TyShape::Fun(&A_TO_RESULT_C_B, &TyShape::Fun(&LIST_A, &RESULT_C_LIST_B));
        // toMaybe : Result a b -> Maybe b   (var(0)=a, var(1)=b)
        const RESULT_A_B: TyShape = TyShape::Con(BuiltinTag::Result, &[A, B]);
        const RESULT_TO_MAYBE: TyShape = TyShape::Fun(&RESULT_A_B, &MAYBE_B);
        // fromMaybe : a -> Maybe b -> Result a b   (var(0)=a, var(1)=b)
        const MAYBE_B_TO_RESULT_A_B: TyShape = TyShape::Fun(&MAYBE_B, &RESULT_A_B);
        const RESULT_FROM_MAYBE: TyShape = TyShape::Fun(&A, &MAYBE_B_TO_RESULT_A_B);
        // okDefault : a -> Result b a   (var(0)=a, var(1)=b)
        const RESULT_OK_DEFAULT: TyShape = TyShape::Fun(&A, &RESULT_B_A);

        // ── Set combinators (base schemes; the `set_elem` Ord obligation is
        //    layered in `constrain_var_kernel`, so these shapes are exercised
        //    only by the totality / oracle tripwires, never in production). ──
        const SET_A: TyShape = TyShape::Con(BuiltinTag::Set, &[A]);
        const SET_B: TyShape = TyShape::Con(BuiltinTag::Set, &[B]);
        const SET_A_TO_SET_A: TyShape = TyShape::Fun(&SET_A, &SET_A);
        // size : Set a -> Int
        const SET_SIZE: TyShape = TyShape::Fun(&SET_A, &INT);
        // insert / remove : a -> Set a -> Set a
        const SET_INSERT: TyShape = TyShape::Fun(&A, &SET_A_TO_SET_A);
        // member : a -> Set a -> Bool
        const SET_A_TO_BOOL: TyShape = TyShape::Fun(&SET_A, &BOOL);
        const SET_MEMBER: TyShape = TyShape::Fun(&A, &SET_A_TO_BOOL);
        // toList : Set a -> List a; fromList : List a -> Set a
        const SET_TO_LIST: TyShape = TyShape::Fun(&SET_A, &LIST_A);
        const SET_FROM_LIST: TyShape = TyShape::Fun(&LIST_A, &SET_A);
        // union / intersect / diff : Set a -> Set a -> Set a
        const SET_UNION: TyShape = TyShape::Fun(&SET_A, &SET_A_TO_SET_A);
        // isEmpty : Set a -> Bool
        const SET_IS_EMPTY: TyShape = TyShape::Fun(&SET_A, &BOOL);
        // singleton : a -> Set a
        const SET_SINGLETON: TyShape = TyShape::Fun(&A, &SET_A);
        // foldl / foldr : (a -> b -> b) -> b -> Set a -> b
        const SET_A_TO_B: TyShape = TyShape::Fun(&SET_A, &B);
        const B_TO_SET_A_TO_B: TyShape = TyShape::Fun(&B, &SET_A_TO_B);
        const SET_FOLD: TyShape = TyShape::Fun(&A_TO_B_TO_B, &B_TO_SET_A_TO_B);
        // map : (a -> b) -> Set a -> Set b
        const SET_A_TO_SET_B: TyShape = TyShape::Fun(&SET_A, &SET_B);
        const SET_MAP: TyShape = TyShape::Fun(&A_TO_B, &SET_A_TO_SET_B);
        // filter : (a -> Bool) -> Set a -> Set a
        const SET_FILTER: TyShape = TyShape::Fun(&A_TO_BOOL, &SET_A_TO_SET_A);

        // ── Dict combinators (base schemes; the `dict_key` obligation is layered
        //    in `constrain_var_kernel`, so these shapes are exercised only by the
        //    totality / oracle tripwires, never in production). Var(0)=k, Var(1)=v,
        //    higher indices as each scheme requires. ──
        const DICT_A_B: TyShape = TyShape::Con(BuiltinTag::Dict, &[A, B]);
        const DICT_A_B_TO_DICT_A_B: TyShape = TyShape::Fun(&DICT_A_B, &DICT_A_B);
        // empty : Dict k v
        const DICT_EMPTY: TyShape = DICT_A_B;
        // isEmpty : Dict k v -> Bool
        const DICT_IS_EMPTY: TyShape = TyShape::Fun(&DICT_A_B, &BOOL);
        // size : Dict k v -> Int
        const DICT_SIZE: TyShape = TyShape::Fun(&DICT_A_B, &INT);
        // insert : k -> v -> Dict k v -> Dict k v
        const B_TO_DICT_A_B_TO_DICT_A_B: TyShape = TyShape::Fun(&B, &DICT_A_B_TO_DICT_A_B);
        const DICT_INSERT: TyShape = TyShape::Fun(&A, &B_TO_DICT_A_B_TO_DICT_A_B);
        // get : k -> Dict k v -> Maybe v
        const DICT_A_B_TO_MAYBE_B: TyShape = TyShape::Fun(&DICT_A_B, &MAYBE_B);
        const DICT_GET: TyShape = TyShape::Fun(&A, &DICT_A_B_TO_MAYBE_B);
        // remove : k -> Dict k v -> Dict k v
        const DICT_REMOVE: TyShape = TyShape::Fun(&A, &DICT_A_B_TO_DICT_A_B);
        // member : k -> Dict k v -> Bool
        const DICT_A_B_TO_BOOL: TyShape = TyShape::Fun(&DICT_A_B, &BOOL);
        const DICT_MEMBER: TyShape = TyShape::Fun(&A, &DICT_A_B_TO_BOOL);
        // keys : Dict k v -> List k
        const DICT_KEYS: TyShape = TyShape::Fun(&DICT_A_B, &LIST_A);
        // values : Dict k v -> List v
        const DICT_VALUES: TyShape = TyShape::Fun(&DICT_A_B, &LIST_B);
        // map : (k -> v -> c) -> Dict k v -> Dict k c
        const DICT_A_C: TyShape = TyShape::Con(BuiltinTag::Dict, &[A, C]);
        const A_TO_B_TO_C_LEAF: TyShape = A_TO_B_TO_C;
        const DICT_MAP: TyShape =
            TyShape::Fun(&A_TO_B_TO_C_LEAF, &TyShape::Fun(&DICT_A_B, &DICT_A_C));
        // foldl / foldr : (k -> v -> c -> c) -> c -> Dict k v -> c
        const A_TO_B_TO_C_TO_C: TyShape =
            TyShape::Fun(&A, &TyShape::Fun(&B, &TyShape::Fun(&C, &C)));
        const DICT_A_B_TO_C: TyShape = TyShape::Fun(&DICT_A_B, &C);
        const C_TO_DICT_A_B_TO_C: TyShape = TyShape::Fun(&C, &DICT_A_B_TO_C);
        const DICT_FOLD: TyShape = TyShape::Fun(&A_TO_B_TO_C_TO_C, &C_TO_DICT_A_B_TO_C);
        // union / intersect / diff : Dict k v -> Dict k v -> Dict k v
        const DICT_UNION: TyShape = TyShape::Fun(&DICT_A_B, &DICT_A_B_TO_DICT_A_B);
        // singleton : k -> v -> Dict k v
        const B_TO_DICT_A_B: TyShape = TyShape::Fun(&B, &DICT_A_B);
        const DICT_SINGLETON: TyShape = TyShape::Fun(&A, &B_TO_DICT_A_B);
        // filter : (k -> v -> Bool) -> Dict k v -> Dict k v
        const A_TO_B_TO_BOOL: TyShape = TyShape::Fun(&A, &TyShape::Fun(&B, &BOOL));
        const DICT_FILTER: TyShape = TyShape::Fun(&A_TO_B_TO_BOOL, &DICT_A_B_TO_DICT_A_B);
        // update : k -> (Maybe v -> Maybe v) -> Dict k v -> Dict k v
        const MAYBE_B_TO_MAYBE_B: TyShape = TyShape::Fun(&MAYBE_B, &MAYBE_B);
        const DICT_UPDATE: TyShape = TyShape::Fun(
            &A,
            &TyShape::Fun(&MAYBE_B_TO_MAYBE_B, &DICT_A_B_TO_DICT_A_B),
        );

        // ── Bytes decode / codec (arrow-only over `Maybe`). ──
        // toString : Bytes -> Maybe String
        const MAYBE_STRING: TyShape = TyShape::Con(BuiltinTag::Maybe, &[STRING]);
        const BYTES_TO_MAYBE_STRING: TyShape = TyShape::Fun(&BYTES, &MAYBE_STRING);
        // fromHex / fromBase64 : String -> Maybe Bytes
        const MAYBE_BYTES: TyShape = TyShape::Con(BuiltinTag::Maybe, &[BYTES]);
        const STRING_TO_MAYBE_BYTES: TyShape = TyShape::Fun(&STRING, &MAYBE_BYTES);

        // ── Tuple-shaped schemes (pairs / paired projections). ──
        // fst / snd : (a, b) -> a  /  (a, b) -> b
        const TUPLE_A_B: TyShape = TyShape::Tuple(&[A, B]);
        const BASICS_FST: TyShape = TyShape::Fun(&TUPLE_A_B, &A);
        const BASICS_SND: TyShape = TyShape::Fun(&TUPLE_A_B, &B);

        // List.zip : List a -> List b -> List (a, b)
        const LIST_TUPLE_A_B: TyShape = TyShape::Con(BuiltinTag::List, &[TUPLE_A_B]);
        const LIST_B_TO_LIST_TUPLE: TyShape = TyShape::Fun(&LIST_B, &LIST_TUPLE_A_B);
        const LIST_ZIP: TyShape = TyShape::Fun(&LIST_A, &LIST_B_TO_LIST_TUPLE);
        // List.unzip : List (a, b) -> (List a, List b)
        const TUPLE_LIST_A_LIST_B: TyShape = TyShape::Tuple(&[LIST_A, LIST_B]);
        const LIST_UNZIP: TyShape = TyShape::Fun(&LIST_TUPLE_A_B, &TUPLE_LIST_A_LIST_B);
        // List.partition : (a -> Bool) -> List a -> (List a, List a)
        const TUPLE_LIST_A_LIST_A: TyShape = TyShape::Tuple(&[LIST_A, LIST_A]);
        const LIST_A_TO_TUPLE_LISTS: TyShape = TyShape::Fun(&LIST_A, &TUPLE_LIST_A_LIST_A);
        const LIST_PARTITION: TyShape = TyShape::Fun(&A_TO_BOOL, &LIST_A_TO_TUPLE_LISTS);

        // Set.partition : (a -> Bool) -> Set a -> (Set a, Set a)
        const TUPLE_SET_A_SET_A: TyShape = TyShape::Tuple(&[SET_A, SET_A]);
        const SET_A_TO_TUPLE_SETS: TyShape = TyShape::Fun(&SET_A, &TUPLE_SET_A_SET_A);
        const SET_PARTITION: TyShape = TyShape::Fun(&A_TO_BOOL, &SET_A_TO_TUPLE_SETS);

        // Dict.toList : Dict a b -> List (a, b)
        const LIST_TUPLE_DICT: TyShape = TyShape::Con(BuiltinTag::List, &[TUPLE_A_B]);
        const DICT_TO_LIST: TyShape = TyShape::Fun(&DICT_A_B, &LIST_TUPLE_DICT);
        // Dict.fromList : List (a, b) -> Dict a b
        const DICT_FROM_LIST: TyShape = TyShape::Fun(&LIST_TUPLE_DICT, &DICT_A_B);
        // Dict.partition : (a -> b -> Bool) -> Dict a b -> (Dict a b, Dict a b)
        const TUPLE_DICT_DICT: TyShape = TyShape::Tuple(&[DICT_A_B, DICT_A_B]);
        const DICT_A_B_TO_TUPLE_DICTS: TyShape = TyShape::Fun(&DICT_A_B, &TUPLE_DICT_DICT);
        const DICT_PARTITION: TyShape = TyShape::Fun(&A_TO_B_TO_BOOL, &DICT_A_B_TO_TUPLE_DICTS);

        // Random.seededInt : Int -> Int -> Int -> (Int, Int)
        const TUPLE_INT_INT: TyShape = TyShape::Tuple(&[INT, INT]);
        const INT_TO_TUPLE_INT_INT: TyShape = TyShape::Fun(&INT, &TUPLE_INT_INT);
        const INT_TO_INT_TO_TUPLE: TyShape = TyShape::Fun(&INT, &INT_TO_TUPLE_INT_INT);
        const RANDOM_SEEDED_INT: TyShape = TyShape::Fun(&INT, &INT_TO_INT_TO_TUPLE);
        // Random.seededFloat : Int -> (Float, Int)
        const TUPLE_FLOAT_INT: TyShape = TyShape::Tuple(&[FLOAT, INT]);
        const RANDOM_SEEDED_FLOAT: TyShape = TyShape::Fun(&INT, &TUPLE_FLOAT_INT);
        // Random.seededChoiceRaw : Int -> List a -> (Maybe a, Int)
        const TUPLE_MAYBE_A_INT: TyShape = TyShape::Tuple(&[MAYBE_A, INT]);
        const LIST_A_TO_TUPLE_MAYBE_A_INT: TyShape = TyShape::Fun(&LIST_A, &TUPLE_MAYBE_A_INT);
        const RANDOM_SEEDED_CHOICE: TyShape = TyShape::Fun(&INT, &LIST_A_TO_TUPLE_MAYBE_A_INT);
        // Random.choice : List a -> Task Error (Maybe a)
        const TASK_MAYBE_A: TyShape = TyShape::Con(BuiltinTag::Task, &[MAYBE_A]);
        const RANDOM_CHOICE_MAYBE: TyShape = TyShape::Fun(&LIST_A, &TASK_MAYBE_A);
        // Random.weighted : List (Float, a) -> Task Error (Maybe a)
        const TUPLE_FLOAT_A: TyShape = TyShape::Tuple(&[FLOAT, A]);
        const LIST_TUPLE_FLOAT_A: TyShape = TyShape::Con(BuiltinTag::List, &[TUPLE_FLOAT_A]);
        const RANDOM_WEIGHTED: TyShape = TyShape::Fun(&LIST_TUPLE_FLOAT_A, &TASK_MAYBE_A);
        // Random.shuffle : List a -> Task Error (List a)
        const RANDOM_SHUFFLE: TyShape = TyShape::Fun(&LIST_A, &TASK_LIST_A);

        // ── List higher-arity mappers (arrow-only, rank-1 polymorphic). ──
        // indexedMap : (Int -> a -> b) -> List a -> List b
        const INT_TO_A_TO_B: TyShape = TyShape::Fun(&INT, &A_TO_B);
        const LIST_INDEXED_MAP: TyShape = TyShape::Fun(&INT_TO_A_TO_B, &LIST_A_TO_LIST_B);
        // map2 : (a -> b -> c) -> List a -> List b -> List c   (vars 0=a,1=b,2=c)
        const LIST_C: TyShape = TyShape::Con(BuiltinTag::List, &[C]);
        const LIST_MAP2: TyShape = TyShape::Fun(
            &A_TO_B_TO_C,
            &TyShape::Fun(&LIST_A, &TyShape::Fun(&LIST_B, &LIST_C)),
        );
        // map3 : (a -> b -> c -> d) -> List a -> List b -> List c -> List d
        const LIST_D: TyShape = TyShape::Con(BuiltinTag::List, &[D]);
        const LIST_MAP3: TyShape = TyShape::Fun(
            &A_TO_B_TO_C_TO_D,
            &TyShape::Fun(
                &LIST_A,
                &TyShape::Fun(&LIST_B, &TyShape::Fun(&LIST_C, &LIST_D)),
            ),
        );
        // map4 : (a -> b -> c -> d -> e) -> List a..d -> List e
        const LIST_E: TyShape = TyShape::Con(BuiltinTag::List, &[E]);
        const LIST_MAP4: TyShape = TyShape::Fun(
            &A_TO_B_TO_C_TO_D_TO_E,
            &TyShape::Fun(
                &LIST_A,
                &TyShape::Fun(
                    &LIST_B,
                    &TyShape::Fun(&LIST_C, &TyShape::Fun(&LIST_D, &LIST_E)),
                ),
            ),
        );
        // map5 : (a -> b -> c -> d -> e -> f) -> List a..e -> List f
        const LIST_F: TyShape = TyShape::Con(BuiltinTag::List, &[F]);
        const LIST_MAP5: TyShape = TyShape::Fun(
            &A_TO_B_TO_C_TO_D_TO_E_TO_F,
            &TyShape::Fun(
                &LIST_A,
                &TyShape::Fun(
                    &LIST_B,
                    &TyShape::Fun(
                        &LIST_C,
                        &TyShape::Fun(&LIST_D, &TyShape::Fun(&LIST_E, &LIST_F)),
                    ),
                ),
            ),
        );

        // ── String combinators (arrow spines over the primitives and `Char`). ──
        const LIST_CHAR: TyShape = TyShape::Con(BuiltinTag::List, &[CHAR]);
        const STRING_LIST: TyShape = TyShape::Con(BuiltinTag::List, &[STRING]);
        const MAYBE_INT: TyShape = TyShape::Con(BuiltinTag::Maybe, &[INT]);
        const MAYBE_FLOAT: TyShape = TyShape::Con(BuiltinTag::Maybe, &[FLOAT]);
        // toInt : String -> Maybe Int; toFloat : String -> Maybe Float
        const STRING_TO_MAYBE_INT: TyShape = TyShape::Fun(&STRING, &MAYBE_INT);
        const STRING_TO_MAYBE_FLOAT: TyShape = TyShape::Fun(&STRING, &MAYBE_FLOAT);
        // fromList : List Char -> String
        const STRING_FROM_LIST: TyShape = TyShape::Fun(&LIST_CHAR, &STRING);
        // concat : List String -> String
        const STRING_CONCAT: TyShape = TyShape::Fun(&STRING_LIST, &STRING);
        // words / lines : String -> List String
        const STRING_TO_LIST_STRING: TyShape = TyShape::Fun(&STRING, &STRING_LIST);
        // toList : String -> List Char
        const STRING_TO_LIST_CHAR: TyShape = TyShape::Fun(&STRING, &LIST_CHAR);
        // join : String -> List String -> String  (`STRING_CONCAT` is the shared
        // `List String -> String` tail).
        const STRING_JOIN: TyShape = TyShape::Fun(&STRING, &STRING_CONCAT);
        // split : String -> String -> List String
        const STRING_SPLIT: TyShape = TyShape::Fun(&STRING, &STRING_TO_LIST_STRING);
        // uncons : String -> Maybe (Char, String)
        const TUPLE_CHAR_STRING: TyShape = TyShape::Tuple(&[CHAR, STRING]);
        const MAYBE_TUPLE_CHAR_STRING: TyShape =
            TyShape::Con(BuiltinTag::Maybe, &[TUPLE_CHAR_STRING]);
        const STRING_UNCONS: TyShape = TyShape::Fun(&STRING, &MAYBE_TUPLE_CHAR_STRING);
        // indexes : String -> String -> List Int
        const STRING_TO_LIST_INT: TyShape = TyShape::Fun(&STRING, &LIST_INT);
        const STRING_INDEXES: TyShape = TyShape::Fun(&STRING, &STRING_TO_LIST_INT);
        // foldl / foldr : (Char -> b -> b) -> b -> String -> b   (b = var(0))
        const CHAR_TO_A_TO_A: TyShape = TyShape::Fun(&CHAR, &A_TO_A);
        const STRING_TO_A: TyShape = TyShape::Fun(&STRING, &A);
        const A_TO_STRING_TO_A: TyShape = TyShape::Fun(&A, &STRING_TO_A);
        const STRING_FOLD: TyShape = TyShape::Fun(&CHAR_TO_A_TO_A, &A_TO_STRING_TO_A);

        // ── `String -> Maybe String` parsers (CSS-safety guards, Uuid.parse). ──
        const STRING_TO_MAYBE_STRING: TyShape = TyShape::Fun(&STRING, &MAYBE_STRING);

        // ── Miscellaneous arrow-only polymorphic / primitive schemes. ──
        // Debug.log : String -> a -> a   (base scheme; STRINGIFY obligation layered)
        const STRING_TO_A_TO_A: TyShape = TyShape::Fun(&STRING, &A_TO_A);
        // System.exit : Int -> a
        const INT_TO_A: TyShape = TyShape::Fun(&INT, &A);
        const DICT_STRING_STRING: TyShape = TyShape::Con(BuiltinTag::Dict, &[STRING, STRING]);
        // Db.getString / getField : String -> Dict String String -> String
        const DICT_TO_STRING: TyShape = TyShape::Fun(&DICT_STRING_STRING, &STRING);
        const DB_GET_STRING: TyShape = TyShape::Fun(&STRING, &DICT_TO_STRING);
        // Db.getInt : String -> Dict String String -> Int
        const DICT_TO_INT: TyShape = TyShape::Fun(&DICT_STRING_STRING, &INT);
        const DB_GET_INT: TyShape = TyShape::Fun(&STRING, &DICT_TO_INT);
        // Db.getBool : String -> Dict String String -> Bool
        const DICT_TO_BOOL: TyShape = TyShape::Fun(&DICT_STRING_STRING, &BOOL);
        const DB_GET_BOOL: TyShape = TyShape::Fun(&STRING, &DICT_TO_BOOL);

        // ── Opaque-constructor leaves for the effect / scalar-opaque families. ──
        // The unit type `()` and the nullary opaque constructors, each spelled
        // once and shared by reference.
        const UNIT: TyShape = TyShape::Unit;
        const ERROR: TyShape = TyShape::Con(BuiltinTag::Error, &[]);
        const ERRORKIND: TyShape = TyShape::Con(BuiltinTag::ErrorKind, &[]);
        const ERRORDETAILS: TyShape = TyShape::Con(BuiltinTag::ErrorDetails, &[]);
        const DECIMAL: TyShape = TyShape::Con(BuiltinTag::Decimal, &[]);
        const DB: TyShape = TyShape::Con(BuiltinTag::Db, &[]);
        const SQLVALUE: TyShape = TyShape::Con(BuiltinTag::SqlValue, &[]);
        const SQLFIELD: TyShape = TyShape::Con(BuiltinTag::SqlField, &[]);
        const SQLFRAGMENT: TyShape = TyShape::Con(BuiltinTag::SqlFragment, &[]);
        const SECRET: TyShape = TyShape::Con(BuiltinTag::Secret, &[]);
        const PATH: TyShape = TyShape::Con(BuiltinTag::Path, &[]);
        const REGEX: TyShape = TyShape::Con(BuiltinTag::Regex, &[]);
        const URL: TyShape = TyShape::Con(BuiltinTag::Url, &[]);
        const DSN: TyShape = TyShape::Con(BuiltinTag::Dsn, &[]);
        const LOCALE: TyShape = TyShape::Con(BuiltinTag::Locale, &[]);
        const HTTP_METHOD: TyShape = TyShape::Con(BuiltinTag::HttpMethod, &[]);
        const CRYPTO_KEY: TyShape = TyShape::Con(BuiltinTag::CryptoKey, &[]);
        const CRYPTO_MAC: TyShape = TyShape::Con(BuiltinTag::CryptoMac, &[]);
        const EMAIL_ADDRESS: TyShape = TyShape::Con(BuiltinTag::EmailAddress, &[]);
        const CLAIMS: TyShape = TyShape::Con(BuiltinTag::Claims, &[]);
        // The nullary config-tag ADTs, returned by their constructor kernels.
        const HOST_MODE: TyShape = TyShape::Con(BuiltinTag::HostMode, &[]);
        const LOG_LEVEL: TyShape = TyShape::Con(BuiltinTag::LogLevel, &[]);
        const CSRF_MODE: TyShape = TyShape::Con(BuiltinTag::CsrfMode, &[]);
        const REVOCATION_MODE: TyShape = TyShape::Con(BuiltinTag::RevocationMode, &[]);
        const PRINCIPAL: TyShape = TyShape::Con(BuiltinTag::Principal, &[]);
        const PRINCIPAL_TO_STRING: TyShape = TyShape::Fun(&PRINCIPAL, &STRING);
        const STRING_TO_PRINCIPAL_TO_MAYBE_STRING: TyShape =
            TyShape::Fun(&STRING, &TyShape::Fun(&PRINCIPAL, &MAYBE_STRING));
        const STRING_TO_PRINCIPAL_TO_BOOL: TyShape =
            TyShape::Fun(&STRING, &TyShape::Fun(&PRINCIPAL, &BOOL));
        const ALGORITHM: TyShape = TyShape::Con(BuiltinTag::Algorithm, &[]);
        const JSON_VALUE: TyShape = TyShape::Con(BuiltinTag::JsonValue, &[]);
        const STREAM_ID: TyShape = TyShape::Con(BuiltinTag::StreamId, &[]);
        const STREAM_WRITER: TyShape = TyShape::Con(BuiltinTag::StreamWriter, &[]);
        const WS_SERVER: TyShape = TyShape::Con(BuiltinTag::WsServer, &[]);
        const WS_SERVER_CFG: TyShape = TyShape::Con(BuiltinTag::WsServerCfg, &[]);
        const SERVER_REQUEST: TyShape = TyShape::Con(BuiltinTag::ServerRequest, &[]);
        const SERVER_COOKIE: TyShape = TyShape::Con(BuiltinTag::ServerCookie, &[]);
        const SERVER_ROUTE: TyShape = TyShape::Con(BuiltinTag::ServerRoute, &[]);
        const AUTH_CONFIG: TyShape = TyShape::Con(BuiltinTag::AuthConfig, &[]);
        const TOKEN_SOURCE: TyShape = TyShape::Con(BuiltinTag::TokenSource, &[]);
        // Scheme-local vars beyond `g` (index 6) for the widest `Config.map*`.
        const H: TyShape = TyShape::Var(7);
        const I_VAR: TyShape = TyShape::Var(8);
        // `Task a` / `Task ()` / `Cmd msg` / `Sub msg` / `Topic a` / `Decoder a`
        // applications reused across the effect families.
        const TASK_A: TyShape = TyShape::Con(BuiltinTag::Task, &[A]);
        const TASK_B: TyShape = TyShape::Con(BuiltinTag::Task, &[B]);
        const TASK_UNIT: TyShape = TyShape::Con(BuiltinTag::Task, &[UNIT]);
        const TASK_INT: TyShape = TyShape::Con(BuiltinTag::Task, &[INT]);
        const TASK_STRING: TyShape = TyShape::Con(BuiltinTag::Task, &[STRING]);
        const TASK_BOOL: TyShape = TyShape::Con(BuiltinTag::Task, &[BOOL]);
        const TASK_FLOAT: TyShape = TyShape::Con(BuiltinTag::Task, &[FLOAT]);
        const TASK_BYTES: TyShape = TyShape::Con(BuiltinTag::Task, &[BYTES]);
        const TASK_SECRET: TyShape = TyShape::Con(BuiltinTag::Task, &[SECRET]);
        const CMD_A: TyShape = TyShape::Con(BuiltinTag::Cmd, &[A]);
        const CMD_B: TyShape = TyShape::Con(BuiltinTag::Cmd, &[B]);
        const SUB_A: TyShape = TyShape::Con(BuiltinTag::Sub, &[A]);
        const SUB_B: TyShape = TyShape::Con(BuiltinTag::Sub, &[B]);
        const TOPIC_A: TyShape = TyShape::Con(BuiltinTag::Topic, &[A]);
        const TOPIC_B: TyShape = TyShape::Con(BuiltinTag::Topic, &[B]);
        const DEC_A: TyShape = TyShape::Con(BuiltinTag::Decoder, &[A]);
        const DEC_B: TyShape = TyShape::Con(BuiltinTag::Decoder, &[B]);
        const DEC_STRING: TyShape = TyShape::Con(BuiltinTag::Decoder, &[STRING]);
        const DEC_INT: TyShape = TyShape::Con(BuiltinTag::Decoder, &[INT]);
        const DEC_FLOAT: TyShape = TyShape::Con(BuiltinTag::Decoder, &[FLOAT]);
        const DEC_BOOL: TyShape = TyShape::Con(BuiltinTag::Decoder, &[BOOL]);
        // `Result Error _` — the fixed-error-channel result the opaque families
        // return (`e = Error`).
        const RESULT_ERR_STRING: TyShape = TyShape::Con(BuiltinTag::Result, &[ERROR, STRING]);
        const RESULT_ERR_BOOL: TyShape = TyShape::Con(BuiltinTag::Result, &[ERROR, BOOL]);
        const RESULT_ERR_A: TyShape = TyShape::Con(BuiltinTag::Result, &[ERROR, A]);
        const RESULT_ERR_REGEX: TyShape = TyShape::Con(BuiltinTag::Result, &[ERROR, REGEX]);
        const RESULT_ERR_PATH: TyShape = TyShape::Con(BuiltinTag::Result, &[ERROR, PATH]);
        const RESULT_ERR_URL: TyShape = TyShape::Con(BuiltinTag::Result, &[ERROR, URL]);
        const RESULT_ERR_DSN: TyShape = TyShape::Con(BuiltinTag::Result, &[ERROR, DSN]);
        const RESULT_ERR_DICT_SS: TyShape =
            TyShape::Con(BuiltinTag::Result, &[ERROR, DICT_STRING_STRING]);

        // ── Effect / scalar-opaque per-kernel shapes. ──
        // `Log.*`, `Time.sleep`, `System.loadEnv`, `Io.*` → `String -> Task ()`.
        const STRING_TO_TASK_UNIT: TyShape = TyShape::Fun(&STRING, &TASK_UNIT);
        // `Log.*With : String -> List a -> Task ()`.
        const LIST_A_TO_TASK_UNIT: TyShape = TyShape::Fun(&LIST_A, &TASK_UNIT);
        const LOG_WITH: TyShape = TyShape::Fun(&STRING, &LIST_A_TO_TASK_UNIT);
        // `File.remove/mkdirAll/delete : Path -> Task ()`.
        const PATH_TO_TASK_UNIT: TyShape = TyShape::Fun(&PATH, &TASK_UNIT);
        // `() -> Task ()` (system.loadEnv).
        const UNIT_TO_TASK_UNIT: TyShape = TyShape::Fun(&UNIT, &TASK_UNIT);
        // `() -> Task String`.
        const UNIT_TO_TASK_STRING: TyShape = TyShape::Fun(&UNIT, &TASK_STRING);
        // `String -> Task String` (getenv / tempFile / tempDir).
        const STRING_TO_TASK_STRING: TyShape = TyShape::Fun(&STRING, &TASK_STRING);
        // `String -> Task Secret` (readSecret): the prompt goes in, an opaque
        // sealed `Secret` comes out — the plaintext is reachable only through the
        // scoped `Secret.use` / `Secret.reveal` API, never as a bare `String`.
        const STRING_TO_TASK_SECRET: TyShape = TyShape::Fun(&STRING, &TASK_SECRET);
        // `Path -> Task String` (readFile).
        const PATH_TO_TASK_STRING: TyShape = TyShape::Fun(&PATH, &TASK_STRING);
        // `() -> Task Int` (time.now / unixMillis).
        const UNIT_TO_TASK_INT: TyShape = TyShape::Fun(&UNIT, &TASK_INT);
        // `Int -> Task ()` (time.sleep).
        const INT_TO_TASK_UNIT: TyShape = TyShape::Fun(&INT, &TASK_UNIT);
        // `Int -> a -> Sub a` (time.every / sub.every).
        const A_TO_SUB_A: TyShape = TyShape::Fun(&A, &SUB_A);
        const INT_TO_A_TO_SUB_A: TyShape = TyShape::Fun(&INT, &A_TO_SUB_A);
        // `() -> Task (List String)` (system.args).
        const LIST_STRING: TyShape = TyShape::Con(BuiltinTag::List, &[STRING]);
        const TASK_LIST_STRING: TyShape = TyShape::Con(BuiltinTag::Task, &[LIST_STRING]);
        const UNIT_TO_TASK_LIST_STRING: TyShape = TyShape::Fun(&UNIT, &TASK_LIST_STRING);
        // `String -> String -> Task ()` (system.setenv).
        const STRING_TO_STRING_TO_TASK_UNIT: TyShape = TyShape::Fun(&STRING, &STRING_TO_TASK_UNIT);
        // `Path -> String -> Task ()` (file.writeFile / append).
        const PATH_TO_STRING_TO_TASK_UNIT: TyShape = TyShape::Fun(&PATH, &STRING_TO_TASK_UNIT);
        // `Path -> Path -> Task ()` (file.copy / rename).
        const PATH_TO_PATH_TO_TASK_UNIT: TyShape = TyShape::Fun(&PATH, &PATH_TO_TASK_UNIT);
        // `Int -> Task (Maybe String)` (system.getArg).
        const TASK_MAYBE_STRING: TyShape = TyShape::Con(BuiltinTag::Task, &[MAYBE_STRING]);
        const INT_TO_TASK_MAYBE_STRING: TyShape = TyShape::Fun(&INT, &TASK_MAYBE_STRING);
        // `String -> Task Int` / `String -> Task Bool` (getenvInt/getenvBool).
        const STRING_TO_TASK_INT: TyShape = TyShape::Fun(&STRING, &TASK_INT);
        const STRING_TO_TASK_BOOL: TyShape = TyShape::Fun(&STRING, &TASK_BOOL);
        // `Path -> Task Bool` (file.exists / isDir).
        const PATH_TO_TASK_BOOL: TyShape = TyShape::Fun(&PATH, &TASK_BOOL);
        // `Int -> Int -> Task Int` (random.int).
        const INT_TO_TASK_INT: TyShape = TyShape::Fun(&INT, &TASK_INT);
        const INT_TO_INT_TO_TASK_INT: TyShape = TyShape::Fun(&INT, &INT_TO_TASK_INT);
        // `Float -> Float -> Task Float` (random.float).
        const FLOAT_TO_TASK_FLOAT: TyShape = TyShape::Fun(&FLOAT, &TASK_FLOAT);
        const FLOAT_TO_FLOAT_TO_TASK_FLOAT: TyShape = TyShape::Fun(&FLOAT, &FLOAT_TO_TASK_FLOAT);
        // `List a -> Task a` (random.choice).
        const LIST_A_TO_TASK_A: TyShape = TyShape::Fun(&LIST_A, &TASK_A);
        // `String -> List String -> Task String` (process.run).
        const LIST_STRING_TO_TASK_STRING: TyShape = TyShape::Fun(&LIST_STRING, &TASK_STRING);
        const PROCESS_RUN: TyShape = TyShape::Fun(&STRING, &LIST_STRING_TO_TASK_STRING);
        // `{ command, args, cwd, env } -> Task { exitCode, stdout, stderr }` (process.runWith).
        const MAYBE_PATH: TyShape = TyShape::Con(BuiltinTag::Maybe, &[PATH]);
        // `List (String, String)` for env overrides.
        const TUPLE_STRING_STRING_PLAIN: TyShape = TyShape::Tuple(&[STRING, STRING]);
        const LIST_TUPLE_SS: TyShape = TyShape::Con(BuiltinTag::List, &[TUPLE_STRING_STRING_PLAIN]);
        // Input record: fields in ascending resolved-symbol (intern) order.
        // Intern sequence: command, args, cwd, env → symbol IDs: command < args < cwd < env.
        const PROCESS_RUN_WITH_INPUT: TyShape = TyShape::Record {
            fields: &[
                (FieldTag::ProcessCommand, &STRING),
                (FieldTag::ProcessArgs, &LIST_STRING),
                (FieldTag::ProcessCwd, &MAYBE_PATH),
                (FieldTag::ProcessEnv, &LIST_TUPLE_SS),
            ],
            tail: RowTailShape::Closed,
        };
        // Output record: fields in ascending resolved-symbol (intern) order.
        // Intern sequence: exitCode, stdout, stderr → symbol IDs: exitCode < stdout < stderr.
        const PROCESS_RUN_WITH_OUTPUT: TyShape = TyShape::Record {
            fields: &[
                (FieldTag::ProcessExitCode, &INT),
                (FieldTag::ProcessStdout, &STRING),
                (FieldTag::ProcessStderr, &STRING),
            ],
            tail: RowTailShape::Closed,
        };
        const TASK_PROCESS_OUTPUT: TyShape =
            TyShape::Con(BuiltinTag::Task, &[PROCESS_RUN_WITH_OUTPUT]);
        const PROCESS_RUN_WITH: TyShape =
            TyShape::Fun(&PROCESS_RUN_WITH_INPUT, &TASK_PROCESS_OUTPUT);
        // `{ command, args, cwd, env, cols, rows } -> Task { exitCode, output }`
        // (process.runInPty). Input fields in ascending resolved-symbol (intern)
        // order: `rows` shares the earlier-interned `csv` `"rows"` symbol so it
        // sorts first; the rest are first-interned in the Process block in the
        // order command < args < cwd < env < cols.
        const PROCESS_RUN_IN_PTY_INPUT: TyShape = TyShape::Record {
            fields: &[
                (FieldTag::ProcessRows, &INT),
                (FieldTag::ProcessCommand, &STRING),
                (FieldTag::ProcessArgs, &LIST_STRING),
                (FieldTag::ProcessCwd, &MAYBE_PATH),
                (FieldTag::ProcessEnv, &LIST_TUPLE_SS),
                (FieldTag::ProcessCols, &INT),
            ],
            tail: RowTailShape::Closed,
        };
        const PROCESS_RUN_IN_PTY_OUTPUT: TyShape = TyShape::Record {
            fields: &[
                (FieldTag::ProcessExitCode, &INT),
                (FieldTag::ProcessOutput, &STRING),
            ],
            tail: RowTailShape::Closed,
        };
        const TASK_PROCESS_PTY_OUTPUT: TyShape =
            TyShape::Con(BuiltinTag::Task, &[PROCESS_RUN_IN_PTY_OUTPUT]);
        const PROCESS_RUN_IN_PTY: TyShape =
            TyShape::Fun(&PROCESS_RUN_IN_PTY_INPUT, &TASK_PROCESS_PTY_OUTPUT);
        // `Path -> Task (List String)` (file.readDir).
        const PATH_TO_TASK_LIST_STRING: TyShape = TyShape::Fun(&PATH, &TASK_LIST_STRING);
        // `Path -> Int -> Task String` (file.readFileLimit).
        const INT_TO_TASK_STRING: TyShape = TyShape::Fun(&INT, &TASK_STRING);
        const PATH_TO_INT_TO_TASK_STRING: TyShape = TyShape::Fun(&PATH, &INT_TO_TASK_STRING);
        // `Path -> Task (List Int)` (file.readFileBytes).
        const TASK_LIST_INT: TyShape = TyShape::Con(BuiltinTag::Task, &[LIST_INT]);
        const PATH_TO_TASK_LIST_INT: TyShape = TyShape::Fun(&PATH, &TASK_LIST_INT);
        // `Path -> Task (List Path)` (file.walk).
        const LIST_PATH: TyShape = TyShape::Con(BuiltinTag::List, &[PATH]);
        const TASK_LIST_PATH: TyShape = TyShape::Con(BuiltinTag::Task, &[LIST_PATH]);
        const PATH_TO_TASK_LIST_PATH: TyShape = TyShape::Fun(&PATH, &TASK_LIST_PATH);
        // `Path -> (Path -> Bool) -> Task (List Path)` (file.walkMatching).
        // PATH_TO_BOOL is already defined (used by Path.isAbsolute).
        const PATH_TO_BOOL_TO_TASK_LIST_PATH: TyShape =
            TyShape::Fun(&PATH, &TyShape::Fun(&PATH_TO_BOOL, &TASK_LIST_PATH));
        // `Int -> a` (system.exit).
        // (INT_TO_A already defined above.)

        // ── Task combinator shapes. ──
        // `a -> Task a` (succeed).
        const A_TO_TASK_A: TyShape = TyShape::Fun(&A, &TASK_A);
        // `Error -> Task a` (fail).
        const ERROR_TO_TASK_A: TyShape = TyShape::Fun(&ERROR, &TASK_A);
        // `(a -> b) -> Task a -> Task b` (map).
        const TASK_A_TO_TASK_B: TyShape = TyShape::Fun(&TASK_A, &TASK_B);
        const TASK_MAP: TyShape = TyShape::Fun(&A_TO_B, &TASK_A_TO_TASK_B);
        // map2..5 spines share the callback shapes with the List/Maybe families
        // (A_TO_B_TO_C etc are defined in the polymorphic block below or here).
        const TASK_C: TyShape = TyShape::Con(BuiltinTag::Task, &[C]);
        const TASK_D: TyShape = TyShape::Con(BuiltinTag::Task, &[D]);
        const TASK_E: TyShape = TyShape::Con(BuiltinTag::Task, &[E]);
        const TASK_F: TyShape = TyShape::Con(BuiltinTag::Task, &[F]);
        // Curried callback spines `A_TO_B_TO_C` … `A_TO_B_TO_C_TO_D_TO_E_TO_F`
        // are already defined by the polymorphic `List`/`Maybe` map families
        // above; reused here by reference.
        const TASK_MAP2: TyShape = TyShape::Fun(
            &A_TO_B_TO_C,
            &TyShape::Fun(&TASK_A, &TyShape::Fun(&TASK_B, &TASK_C)),
        );
        const TASK_MAP3: TyShape = TyShape::Fun(
            &A_TO_B_TO_C_TO_D,
            &TyShape::Fun(
                &TASK_A,
                &TyShape::Fun(&TASK_B, &TyShape::Fun(&TASK_C, &TASK_D)),
            ),
        );
        const TASK_MAP4: TyShape = TyShape::Fun(
            &A_TO_B_TO_C_TO_D_TO_E,
            &TyShape::Fun(
                &TASK_A,
                &TyShape::Fun(
                    &TASK_B,
                    &TyShape::Fun(&TASK_C, &TyShape::Fun(&TASK_D, &TASK_E)),
                ),
            ),
        );
        const TASK_MAP5: TyShape = TyShape::Fun(
            &A_TO_B_TO_C_TO_D_TO_E_TO_F,
            &TyShape::Fun(
                &TASK_A,
                &TyShape::Fun(
                    &TASK_B,
                    &TyShape::Fun(
                        &TASK_C,
                        &TyShape::Fun(&TASK_D, &TyShape::Fun(&TASK_E, &TASK_F)),
                    ),
                ),
            ),
        );
        // `Task.attempt : (Result Error a -> msg) -> Task a -> Cmd msg`.
        const RESULT_ERR_A_TO_B: TyShape = TyShape::Fun(&RESULT_ERR_A, &B);
        const TASK_A_TO_CMD_B: TyShape = TyShape::Fun(&TASK_A, &CMD_B);
        const TASK_ATTEMPT: TyShape = TyShape::Fun(&RESULT_ERR_A_TO_B, &TASK_A_TO_CMD_B);
        // `andThen : (a -> Task b) -> Task a -> Task b`.
        const A_TO_TASK_B: TyShape = TyShape::Fun(&A, &TASK_B);
        const TASK_AND_THEN: TyShape = TyShape::Fun(&A_TO_TASK_B, &TASK_A_TO_TASK_B);
        // `mapError : (Error -> Error) -> Task a -> Task a`.
        const ERROR_TO_ERROR: TyShape = TyShape::Fun(&ERROR, &ERROR);
        const TASK_A_TO_TASK_A: TyShape = TyShape::Fun(&TASK_A, &TASK_A);
        const TASK_MAP_ERROR: TyShape = TyShape::Fun(&ERROR_TO_ERROR, &TASK_A_TO_TASK_A);
        // `onError : (Error -> Task a) -> Task a -> Task a`.
        const TASK_ON_ERROR: TyShape = TyShape::Fun(&ERROR_TO_TASK_A, &TASK_A_TO_TASK_A);
        // `fromResult : Result Error a -> Task a`. The `Result`'s error slot is
        // the `Task`'s fixed `Error` channel.
        const TASK_FROM_RESULT: TyShape = TyShape::Fun(&RESULT_ERR_A, &TASK_A);
        // `andThenResult : (a -> Result Error b) -> Task a -> Task b`.
        const RESULT_ERR_B: TyShape = TyShape::Con(BuiltinTag::Result, &[ERROR, B]);
        const A_TO_RESULT_ERR_B: TyShape = TyShape::Fun(&A, &RESULT_ERR_B);
        const TASK_AND_THEN_RESULT: TyShape = TyShape::Fun(&A_TO_RESULT_ERR_B, &TASK_A_TO_TASK_B);
        // `sequence / parallel : List (Task a) -> Task (List a)`.
        const LIST_TASK_A: TyShape = TyShape::Con(BuiltinTag::List, &[TASK_A]);
        const TASK_LIST_A: TyShape = TyShape::Con(BuiltinTag::Task, &[LIST_A]);
        const TASK_SEQUENCE: TyShape = TyShape::Fun(&LIST_TASK_A, &TASK_LIST_A);
        // `run / perform : Task a -> Result Error a`.
        const TASK_A_TO_RESULT_ERR_A: TyShape = TyShape::Fun(&TASK_A, &RESULT_ERR_A);
        // `lazy : (() -> Task a) -> Task a`.
        const UNIT_TO_TASK_A: TyShape = TyShape::Fun(&UNIT, &TASK_A);
        const TASK_LAZY: TyShape = TyShape::Fun(&UNIT_TO_TASK_A, &TASK_A);
        // `loop : Int -> s -> (s -> Task (Step s a)) -> Task a`, with `s` = `A`
        // and `a` = `B`.
        const STEP_A_B: TyShape = TyShape::Con(BuiltinTag::TaskStep, &[A, B]);
        const TASK_STEP_A_B: TyShape = TyShape::Con(BuiltinTag::Task, &[STEP_A_B]);
        const A_TO_TASK_STEP: TyShape = TyShape::Fun(&A, &TASK_STEP_A_B);
        const STEP_FN_TO_TASK_B: TyShape = TyShape::Fun(&A_TO_TASK_STEP, &TASK_B);
        const A_TO_STEP_FN_TO_TASK_B: TyShape = TyShape::Fun(&A, &STEP_FN_TO_TASK_B);
        const TASK_LOOP: TyShape = TyShape::Fun(&INT, &A_TO_STEP_FN_TO_TASK_B);

        // ── Cmd / Sub shapes. ──
        // `Cmd.batch : List (Cmd a) -> Cmd a`.
        const LIST_CMD_A: TyShape = TyShape::Con(BuiltinTag::List, &[CMD_A]);
        const CMD_BATCH: TyShape = TyShape::Fun(&LIST_CMD_A, &CMD_A);
        // `Cmd.perform : Task a -> (Result Error a -> b) -> Cmd b`.
        const RESULT_ERR_A_TO_B_TO_CMD_B: TyShape = TyShape::Fun(&RESULT_ERR_A_TO_B, &CMD_B);
        const CMD_PERFORM: TyShape = TyShape::Fun(&TASK_A, &RESULT_ERR_A_TO_B_TO_CMD_B);
        // `Cmd.map / Sub.map : (a -> b) -> Cmd a -> Cmd b`.
        const CMD_A_TO_CMD_B: TyShape = TyShape::Fun(&CMD_A, &CMD_B);
        const CMD_MAP: TyShape = TyShape::Fun(&A_TO_B, &CMD_A_TO_CMD_B);
        const SUB_A_TO_SUB_B: TyShape = TyShape::Fun(&SUB_A, &SUB_B);
        const SUB_MAP: TyShape = TyShape::Fun(&A_TO_B, &SUB_A_TO_SUB_B);
        // `Cmd.publish : Topic b -> b -> Cmd a`. var(0)=msg, var(1)=payload.
        const B_TO_CMD_A: TyShape = TyShape::Fun(&B, &CMD_A);
        const CMD_PUBLISH: TyShape = TyShape::Fun(&TOPIC_B, &B_TO_CMD_A);
        // `Sub.batch : List (Sub a) -> Sub a`.
        const LIST_SUB_A: TyShape = TyShape::Con(BuiltinTag::List, &[SUB_A]);
        const SUB_BATCH: TyShape = TyShape::Fun(&LIST_SUB_A, &SUB_A);
        // `Sub.subscribeTopic : Topic b -> (b -> a) -> Sub a`.
        // (`B_TO_A` defined above.)
        const B_TO_A_TO_SUB_A: TyShape = TyShape::Fun(&B_TO_A, &SUB_A);
        const SUB_SUBSCRIBE_TOPIC: TyShape = TyShape::Fun(&TOPIC_B, &B_TO_A_TO_SUB_A);
        // `PubSub.publish : Topic a -> a -> Task Int`.
        const A_TO_TASK_INT: TyShape = TyShape::Fun(&A, &TASK_INT);
        const PUBSUB_PUBLISH: TyShape = TyShape::Fun(&TOPIC_A, &A_TO_TASK_INT);
        // `PubSub.topic : String -> Topic a`.
        const STRING_TO_TOPIC_A: TyShape = TyShape::Fun(&STRING, &TOPIC_A);

        // ── Decoder families (Json.Decode / Db.Decode / Config), sharing the
        //    `Decoder a` carrier. ──
        // Bare primitive decoders (`Decoder String` … arity 0).
        // (DEC_STRING/DEC_INT/DEC_FLOAT/DEC_BOOL defined above.)
        // `field/at/index : … -> Decoder a -> Decoder a`.
        const DEC_A_TO_DEC_A: TyShape = TyShape::Fun(&DEC_A, &DEC_A);
        const STRING_TO_DEC_A_TO_DEC_A: TyShape = TyShape::Fun(&STRING, &DEC_A_TO_DEC_A);
        const LIST_STRING_TO_DEC_A_TO_DEC_A: TyShape = TyShape::Fun(&LIST_STRING, &DEC_A_TO_DEC_A);
        const INT_TO_DEC_A_TO_DEC_A: TyShape = TyShape::Fun(&INT, &DEC_A_TO_DEC_A);
        // `map : (a -> b) -> Decoder a -> Decoder b`.
        const DEC_A_TO_DEC_B: TyShape = TyShape::Fun(&DEC_A, &DEC_B);
        const DEC_MAP: TyShape = TyShape::Fun(&A_TO_B, &DEC_A_TO_DEC_B);
        // `andThen : (a -> Decoder b) -> Decoder a -> Decoder b`.
        const A_TO_DEC_B: TyShape = TyShape::Fun(&A, &DEC_B);
        const DEC_AND_THEN: TyShape = TyShape::Fun(&A_TO_DEC_B, &DEC_A_TO_DEC_B);
        // `succeed : a -> Decoder a`.
        const A_TO_DEC_A: TyShape = TyShape::Fun(&A, &DEC_A);
        // `fail : String -> Decoder a`.
        const STRING_TO_DEC_A: TyShape = TyShape::Fun(&STRING, &DEC_A);
        // `list : Decoder a -> Decoder (List a)`.
        const DEC_LIST_A: TyShape = TyShape::Con(BuiltinTag::Decoder, &[LIST_A]);
        const DEC_LIST: TyShape = TyShape::Fun(&DEC_A, &DEC_LIST_A);
        // `nullable / maybe : Decoder a -> Decoder (Maybe a)`.
        const DEC_MAYBE_A: TyShape = TyShape::Con(BuiltinTag::Decoder, &[MAYBE_A]);
        const DEC_NULLABLE: TyShape = TyShape::Fun(&DEC_A, &DEC_MAYBE_A);
        // `oneOf : List (Decoder a) -> Decoder a`.
        const LIST_DEC_A: TyShape = TyShape::Con(BuiltinTag::List, &[DEC_A]);
        const DEC_ONE_OF: TyShape = TyShape::Fun(&LIST_DEC_A, &DEC_A);
        // `map2..8 : (a -> … -> r) -> Decoder a -> … -> Decoder r`.
        const DEC_MAP2: TyShape = TyShape::Fun(
            &A_TO_B_TO_C,
            &TyShape::Fun(&DEC_A, &TyShape::Fun(&DEC_B, &DEC_C)),
        );
        const DEC_C: TyShape = TyShape::Con(BuiltinTag::Decoder, &[C]);
        const DEC_D: TyShape = TyShape::Con(BuiltinTag::Decoder, &[D]);
        const DEC_E: TyShape = TyShape::Con(BuiltinTag::Decoder, &[E]);
        const DEC_F: TyShape = TyShape::Con(BuiltinTag::Decoder, &[F]);
        const DEC_G: TyShape = TyShape::Con(BuiltinTag::Decoder, &[G]);
        const DEC_H: TyShape = TyShape::Con(BuiltinTag::Decoder, &[H]);
        const DEC_I: TyShape = TyShape::Con(BuiltinTag::Decoder, &[I_VAR]);
        const DEC_MAP3: TyShape = TyShape::Fun(
            &A_TO_B_TO_C_TO_D,
            &TyShape::Fun(&DEC_A, &TyShape::Fun(&DEC_B, &TyShape::Fun(&DEC_C, &DEC_D))),
        );
        const DEC_MAP4: TyShape = TyShape::Fun(
            &A_TO_B_TO_C_TO_D_TO_E,
            &TyShape::Fun(
                &DEC_A,
                &TyShape::Fun(&DEC_B, &TyShape::Fun(&DEC_C, &TyShape::Fun(&DEC_D, &DEC_E))),
            ),
        );
        const DEC_MAP5: TyShape = TyShape::Fun(
            &A_TO_B_TO_C_TO_D_TO_E_TO_F,
            &TyShape::Fun(
                &DEC_A,
                &TyShape::Fun(
                    &DEC_B,
                    &TyShape::Fun(&DEC_C, &TyShape::Fun(&DEC_D, &TyShape::Fun(&DEC_E, &DEC_F))),
                ),
            ),
        );
        // 7-ary callback spine `a -> b -> c -> d -> e -> f -> g` and map6.
        const A_TO_G_SPINE7: TyShape = TyShape::Fun(
            &A,
            &TyShape::Fun(
                &B,
                &TyShape::Fun(
                    &C,
                    &TyShape::Fun(&D, &TyShape::Fun(&E, &TyShape::Fun(&F, &G))),
                ),
            ),
        );
        const DEC_MAP6: TyShape = TyShape::Fun(
            &A_TO_G_SPINE7,
            &TyShape::Fun(
                &DEC_A,
                &TyShape::Fun(
                    &DEC_B,
                    &TyShape::Fun(
                        &DEC_C,
                        &TyShape::Fun(&DEC_D, &TyShape::Fun(&DEC_E, &TyShape::Fun(&DEC_F, &DEC_G))),
                    ),
                ),
            ),
        );
        // 8-ary callback spine and map7.
        const A_TO_H_SPINE8: TyShape = TyShape::Fun(
            &A,
            &TyShape::Fun(
                &B,
                &TyShape::Fun(
                    &C,
                    &TyShape::Fun(
                        &D,
                        &TyShape::Fun(&E, &TyShape::Fun(&F, &TyShape::Fun(&G, &H))),
                    ),
                ),
            ),
        );
        const DEC_MAP7: TyShape = TyShape::Fun(
            &A_TO_H_SPINE8,
            &TyShape::Fun(
                &DEC_A,
                &TyShape::Fun(
                    &DEC_B,
                    &TyShape::Fun(
                        &DEC_C,
                        &TyShape::Fun(
                            &DEC_D,
                            &TyShape::Fun(
                                &DEC_E,
                                &TyShape::Fun(&DEC_F, &TyShape::Fun(&DEC_G, &DEC_H)),
                            ),
                        ),
                    ),
                ),
            ),
        );
        // 9-ary callback spine and map8.
        const A_TO_I_SPINE9: TyShape = TyShape::Fun(
            &A,
            &TyShape::Fun(
                &B,
                &TyShape::Fun(
                    &C,
                    &TyShape::Fun(
                        &D,
                        &TyShape::Fun(
                            &E,
                            &TyShape::Fun(&F, &TyShape::Fun(&G, &TyShape::Fun(&H, &I_VAR))),
                        ),
                    ),
                ),
            ),
        );
        const DEC_MAP8: TyShape = TyShape::Fun(
            &A_TO_I_SPINE9,
            &TyShape::Fun(
                &DEC_A,
                &TyShape::Fun(
                    &DEC_B,
                    &TyShape::Fun(
                        &DEC_C,
                        &TyShape::Fun(
                            &DEC_D,
                            &TyShape::Fun(
                                &DEC_E,
                                &TyShape::Fun(
                                    &DEC_F,
                                    &TyShape::Fun(&DEC_G, &TyShape::Fun(&DEC_H, &DEC_I)),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        );
        // `required/optional/custom` pipeline: `next : Decoder (a -> b)`.
        const A_TO_B_FN: TyShape = A_TO_B;
        const DEC_A_TO_B: TyShape = TyShape::Con(BuiltinTag::Decoder, &[A_TO_B_FN]);
        const DEC_AB_TO_DEC_B: TyShape = TyShape::Fun(&DEC_A_TO_B, &DEC_B);
        const DEC_A_TO_DEC_AB_TO_DEC_B: TyShape = TyShape::Fun(&DEC_A, &DEC_AB_TO_DEC_B);
        // `required : String -> Decoder a -> Decoder (a -> b) -> Decoder b`.
        const DEC_REQUIRED: TyShape = TyShape::Fun(&STRING, &DEC_A_TO_DEC_AB_TO_DEC_B);
        // `requiredAt : List String -> Decoder a -> Decoder (a -> b) -> Decoder b`.
        const DEC_REQUIRED_AT: TyShape = TyShape::Fun(&LIST_STRING, &DEC_A_TO_DEC_AB_TO_DEC_B);
        // `custom : Decoder a -> Decoder (a -> b) -> Decoder b`.
        const DEC_CUSTOM: TyShape = DEC_A_TO_DEC_AB_TO_DEC_B;
        // `optional : String -> Decoder a -> a -> Decoder (a -> b) -> Decoder b`.
        const A_TO_DEC_AB_TO_DEC_B: TyShape = TyShape::Fun(&A, &DEC_AB_TO_DEC_B);
        const DEC_A_TO_A_TO_DEC_AB_TO_DEC_B: TyShape = TyShape::Fun(&DEC_A, &A_TO_DEC_AB_TO_DEC_B);
        const DEC_OPTIONAL: TyShape = TyShape::Fun(&STRING, &DEC_A_TO_A_TO_DEC_AB_TO_DEC_B);
        // `decodeString : Decoder a -> String -> Result Error a`.
        const STRING_TO_RESULT_ERR_A: TyShape = TyShape::Fun(&STRING, &RESULT_ERR_A);
        const DEC_DECODE_STRING: TyShape = TyShape::Fun(&DEC_A, &STRING_TO_RESULT_ERR_A);
        // `value : Decoder Value` — the identity decoder, yielding the raw JSON
        // node so a caller can re-serialise it or introspect it in Ipê.
        const DEC_JSON_VALUE: TyShape = TyShape::Con(BuiltinTag::Decoder, &[JSON_VALUE]);
        // `decodeValue : Decoder a -> Value -> Result Error a` — run a decoder
        // against an in-memory `Value`, sharing the exact decode path
        // `decodeString` uses after its parse step (no second decoder).
        const VALUE_TO_RESULT_ERR_A: TyShape = TyShape::Fun(&JSON_VALUE, &RESULT_ERR_A);
        const DEC_DECODE_VALUE: TyShape = TyShape::Fun(&DEC_A, &VALUE_TO_RESULT_ERR_A);
        // Config `decodeToml/Yaml/Json : String -> Decoder a -> Result Error a`.
        const DEC_A_TO_RESULT_ERR_A: TyShape = TyShape::Fun(&DEC_A, &RESULT_ERR_A);
        const CONFIG_DECODE: TyShape = TyShape::Fun(&STRING, &DEC_A_TO_RESULT_ERR_A);
        // Config `loadFromFile : String -> Decoder a -> Task a`.
        const DEC_A_TO_TASK_A: TyShape = TyShape::Fun(&DEC_A, &TASK_A);
        const CONFIG_LOAD: TyShape = TyShape::Fun(&PATH, &DEC_A_TO_TASK_A);
        // Config `keyValuePairs : Decoder a -> Decoder (List (String, a))`.
        const TUPLE_STRING_A: TyShape = TyShape::Tuple(&[STRING, A]);
        const LIST_TUPLE_STRING_A: TyShape = TyShape::Con(BuiltinTag::List, &[TUPLE_STRING_A]);
        const DEC_LIST_TUPLE_STRING_A: TyShape =
            TyShape::Con(BuiltinTag::Decoder, &[LIST_TUPLE_STRING_A]);
        const CONFIG_KVP: TyShape = TyShape::Fun(&DEC_A, &DEC_LIST_TUPLE_STRING_A);
        // Config `dict : Decoder a -> Decoder (Dict String a)`.
        const DICT_STRING_A: TyShape = TyShape::Con(BuiltinTag::Dict, &[STRING, A]);
        const DEC_DICT_STRING_A: TyShape = TyShape::Con(BuiltinTag::Decoder, &[DICT_STRING_A]);
        const CONFIG_DICT: TyShape = TyShape::Fun(&DEC_A, &DEC_DICT_STRING_A);
        // Db.Decode extras.
        // `Db.Decode.money : String -> Decoder (Decimal, String)`.
        const TUPLE_DECIMAL_STRING: TyShape = TyShape::Tuple(&[DECIMAL, STRING]);
        const DEC_TUPLE_DECIMAL_STRING: TyShape =
            TyShape::Con(BuiltinTag::Decoder, &[TUPLE_DECIMAL_STRING]);
        const DB_DEC_MONEY: TyShape = TyShape::Fun(&STRING, &DEC_TUPLE_DECIMAL_STRING);
        // `Db.Decode.decimal : String -> Decoder Decimal`.
        const DEC_DECIMAL: TyShape = TyShape::Con(BuiltinTag::Decoder, &[DECIMAL]);
        const DB_DEC_DECIMAL: TyShape = TyShape::Fun(&STRING, &DEC_DECIMAL);
        // `Db.Decode.bytes : String -> Decoder (List Int)`.
        const DEC_LIST_INT: TyShape = TyShape::Con(BuiltinTag::Decoder, &[LIST_INT]);
        const DB_DEC_BYTES: TyShape = TyShape::Fun(&STRING, &DEC_LIST_INT);
        // Db.Decode column primitives: `String -> Decoder <prim>`.
        const STRING_TO_DEC_STRING: TyShape = TyShape::Fun(&STRING, &DEC_STRING);
        const STRING_TO_DEC_INT: TyShape = TyShape::Fun(&STRING, &DEC_INT);
        const STRING_TO_DEC_FLOAT: TyShape = TyShape::Fun(&STRING, &DEC_FLOAT);
        const STRING_TO_DEC_BOOL: TyShape = TyShape::Fun(&STRING, &DEC_BOOL);

        // ── JsonEnc encoders (`Value = any`). ──
        const STRING_TO_VALUE: TyShape = TyShape::Fun(&STRING, &JSON_VALUE);
        const INT_TO_VALUE: TyShape = TyShape::Fun(&INT, &JSON_VALUE);
        const FLOAT_TO_VALUE: TyShape = TyShape::Fun(&FLOAT, &JSON_VALUE);
        const BOOL_TO_VALUE: TyShape = TyShape::Fun(&BOOL, &JSON_VALUE);
        const A_TO_VALUE: TyShape = TyShape::Fun(&A, &JSON_VALUE);
        const LIST_A_TO_VALUE: TyShape = TyShape::Fun(&LIST_A, &JSON_VALUE);
        const JSON_ENC_LIST: TyShape = TyShape::Fun(&A_TO_VALUE, &LIST_A_TO_VALUE);
        const TUPLE_STRING_VALUE: TyShape = TyShape::Tuple(&[STRING, JSON_VALUE]);
        const LIST_TUPLE_STRING_VALUE: TyShape =
            TyShape::Con(BuiltinTag::List, &[TUPLE_STRING_VALUE]);
        const JSON_ENC_OBJECT: TyShape = TyShape::Fun(&LIST_TUPLE_STRING_VALUE, &JSON_VALUE);
        const VALUE_TO_STRING: TyShape = TyShape::Fun(&JSON_VALUE, &STRING);
        const JSON_ENC_ENCODE: TyShape = TyShape::Fun(&INT, &VALUE_TO_STRING);

        // ── Error ADT family. ──
        const STRING_TO_ERROR: TyShape = TyShape::Fun(&STRING, &ERROR);
        const ERROR_TO_ERROR_SPINE: TyShape = TyShape::Fun(&ERROR, &ERROR);
        const STRING_TO_ERROR_TO_ERROR: TyShape = TyShape::Fun(&STRING, &ERROR_TO_ERROR_SPINE);
        const ERROR_TO_BOOL: TyShape = TyShape::Fun(&ERROR, &BOOL);
        const ERRORDETAILS_TO_ERROR_TO_ERROR: TyShape =
            TyShape::Fun(&ERRORDETAILS, &ERROR_TO_ERROR_SPINE);
        const ERROR_TO_ERRORKIND: TyShape = TyShape::Fun(&ERROR, &ERRORKIND);
        const ERROR_TO_STRING: TyShape = TyShape::Fun(&ERROR, &STRING);
        const ERRORKIND_TO_STRING: TyShape = TyShape::Fun(&ERRORKIND, &STRING);

        // ── Scalar-opaque families (Secret / Regex / Path / Url / Locale /
        //    Crypto typed-key / EmailAddress / Sql / Auth / Compression /
        //    Trace / HttpStream / WebSocket / Ws-server / Encoding / Uuid). ──
        // Secret.
        const STRING_TO_SECRET: TyShape = TyShape::Fun(&STRING, &SECRET);
        const SECRET_TO_STRING: TyShape = TyShape::Fun(&SECRET, &STRING);
        // Regex.
        const STRING_TO_RESULT_ERR_REGEX: TyShape = TyShape::Fun(&STRING, &RESULT_ERR_REGEX);
        const STRING_TO_BOOL_LEAF: TyShape = TyShape::Fun(&STRING, &BOOL);
        const REGEX_TO_STRING_TO_BOOL: TyShape = TyShape::Fun(&REGEX, &STRING_TO_BOOL_LEAF);
        const STRING_TO_MAYBE_STRING_LEAF: TyShape = TyShape::Fun(&STRING, &MAYBE_STRING);
        const REGEX_TO_STRING_TO_MAYBE_STRING: TyShape =
            TyShape::Fun(&REGEX, &STRING_TO_MAYBE_STRING_LEAF);
        const REGEX_TO_STRING_TO_LIST_STRING: TyShape =
            TyShape::Fun(&REGEX, &TyShape::Fun(&STRING, &LIST_STRING));
        const REGEX_TO_STRING_TO_STRING_TO_STRING: TyShape = TyShape::Fun(
            &REGEX,
            &TyShape::Fun(&STRING, &TyShape::Fun(&STRING, &STRING)),
        );
        // Path.
        const STRING_TO_RESULT_ERR_PATH: TyShape = TyShape::Fun(&STRING, &RESULT_ERR_PATH);
        const PATH_TO_STRING: TyShape = TyShape::Fun(&PATH, &STRING);
        const PATH_TO_BOOL: TyShape = TyShape::Fun(&PATH, &BOOL);
        const PATH_TO_RESULT_ERR_PATH: TyShape = TyShape::Fun(&PATH, &RESULT_ERR_PATH);
        const PATH_TO_PATH_TO_RESULT_ERR_PATH: TyShape =
            TyShape::Fun(&PATH, &PATH_TO_RESULT_ERR_PATH);
        const TASK_PATH: TyShape = TyShape::Con(BuiltinTag::Task, &[PATH]);
        const PATH_TO_TASK_PATH: TyShape = TyShape::Fun(&PATH, &TASK_PATH);
        // Url.
        const STRING_TO_RESULT_ERR_URL: TyShape = TyShape::Fun(&STRING, &RESULT_ERR_URL);
        const URL_TO_STRING: TyShape = TyShape::Fun(&URL, &STRING);
        const URL_TO_MAYBE_STRING: TyShape = TyShape::Fun(&URL, &MAYBE_STRING);
        // (`MAYBE_INT` defined above.)
        const URL_TO_MAYBE_INT: TyShape = TyShape::Fun(&URL, &MAYBE_INT);
        const TUPLE_STRING_STRING: TyShape = TyShape::Tuple(&[STRING, STRING]);
        const LIST_TUPLE_STRING_STRING: TyShape =
            TyShape::Con(BuiltinTag::List, &[TUPLE_STRING_STRING]);
        const URL_BUILD_QUERY: TyShape = TyShape::Fun(&LIST_TUPLE_STRING_STRING, &STRING);
        // Url.Relative — the opaque same-origin relative reference.
        const RELATIVE: TyShape = TyShape::Con(BuiltinTag::UrlRelative, &[]);
        const RESULT_ERR_RELATIVE: TyShape = TyShape::Con(BuiltinTag::Result, &[ERROR, RELATIVE]);
        const STRING_TO_RESULT_ERR_RELATIVE: TyShape = TyShape::Fun(&STRING, &RESULT_ERR_RELATIVE);
        const RELATIVE_TO_STRING: TyShape = TyShape::Fun(&RELATIVE, &STRING);
        const RELATIVE_TO_MAYBE_STRING: TyShape = TyShape::Fun(&RELATIVE, &MAYBE_STRING);
        // Dsn — the parse-don't-validate descriptor. Accessors return primitive
        // tags (`Int`) the compiled-source wrapper re-tags into the `Driver` /
        // `TlsMode` ADTs; the descriptor itself is the opaque `DSN` leaf.
        const STRING_TO_RESULT_ERR_DSN: TyShape = TyShape::Fun(&STRING, &RESULT_ERR_DSN);
        const DSN_TO_STRING: TyShape = TyShape::Fun(&DSN, &STRING);
        const DSN_TO_INT: TyShape = TyShape::Fun(&DSN, &INT);
        // `build : Int -> String -> Int -> String -> String -> Secret -> Int
        //   -> Result Error Dsn` (driverTag, host, port, database, user,
        //   password, tlsTag).
        const SECRET_TO_INT_TO_RESULT_ERR_DSN: TyShape =
            TyShape::Fun(&SECRET, &TyShape::Fun(&INT, &RESULT_ERR_DSN));
        const STRING_TO_SECRET_TO_INT_TO_RESULT_ERR_DSN: TyShape =
            TyShape::Fun(&STRING, &SECRET_TO_INT_TO_RESULT_ERR_DSN);
        const STRING_TO_STRING_TO_SECRET_TO_INT_TO_RESULT_ERR_DSN: TyShape =
            TyShape::Fun(&STRING, &STRING_TO_SECRET_TO_INT_TO_RESULT_ERR_DSN);
        const INT_TO_STRING_TO_STRING_TO_SECRET_TO_INT_TO_RESULT_ERR_DSN: TyShape =
            TyShape::Fun(&INT, &STRING_TO_STRING_TO_SECRET_TO_INT_TO_RESULT_ERR_DSN);
        const STRING_TO_INT_TO_STRING_TO_STRING_TO_SECRET_TO_INT_TO_RESULT_ERR_DSN: TyShape =
            TyShape::Fun(
                &STRING,
                &INT_TO_STRING_TO_STRING_TO_SECRET_TO_INT_TO_RESULT_ERR_DSN,
            );
        const DSN_BUILD: TyShape = TyShape::Fun(
            &INT,
            &STRING_TO_INT_TO_STRING_TO_STRING_TO_SECRET_TO_INT_TO_RESULT_ERR_DSN,
        );
        // ── External Connection — read-only-by-type foreign-DB handle. ──
        // The phantom access mode is a real type at inference (so `ReadOnly` ≠
        // `ReadWrite` and a read-only value cannot unify into a write kernel),
        // erased at emit. `open` yields `Connection ReadOnly`; the raw
        // `unsafeExecRawOn` REQUIRES `Connection ReadWrite`.
        const CONN_READONLY: TyShape = TyShape::Con(BuiltinTag::ConnReadOnly, &[]);
        const CONN_READWRITE: TyShape = TyShape::Con(BuiltinTag::ConnReadWrite, &[]);
        const CONNECTION_READONLY: TyShape = TyShape::Con(BuiltinTag::Connection, &[CONN_READONLY]);
        const CONNECTION_READWRITE: TyShape =
            TyShape::Con(BuiltinTag::Connection, &[CONN_READWRITE]);
        // `close` is polymorphic over the access mode — it accepts `Connection a`.
        const CONNECTION_MODE: TyShape = TyShape::Con(BuiltinTag::Connection, &[A]);
        const TASK_CONNECTION_READONLY: TyShape =
            TyShape::Con(BuiltinTag::Task, &[CONNECTION_READONLY]);
        // `open : Dsn -> Task Error (Connection ReadOnly)`.
        const DSN_TO_TASK_CONN_RO: TyShape = TyShape::Fun(&DSN, &TASK_CONNECTION_READONLY);
        // `close : Connection a -> Task Error ()`.
        const CONN_MODE_TO_TASK_UNIT: TyShape = TyShape::Fun(&CONNECTION_MODE, &TASK_UNIT);
        // `unsafeExecRawOn : Connection ReadWrite -> String -> Task Error Int`.
        const STRING_TO_TASK_INT_CONN: TyShape = TyShape::Fun(&STRING, &TASK_INT);
        const CONN_RW_TO_STRING_TO_TASK_INT: TyShape =
            TyShape::Fun(&CONNECTION_READWRITE, &STRING_TO_TASK_INT_CONN);
        // ── External read path — mode-polymorphic `Connection a` first arg. ──
        // A read is available on any access mode, so the mode is a free var (`a`
        // for the single-var reads; `c` for `queryDecodeOn`, whose `a`/`b` are the
        // decoder element and params element). The `Connection` handle is one
        // concrete pool at emit — the phantom mode is erased.
        //
        // `findWhereOn : Connection a -> String -> SqlFragment
        //                -> Task Error (List (Dict String String))`.
        const CONN_FIND_WHERE: TyShape = TyShape::Fun(&CONNECTION_MODE, &STRING_TO_FIND_WHERE);
        // `getByIdOn : Connection a -> String -> String
        //              -> Task Error (Maybe (Dict String String))`.
        const CONN_GET_BY_ID: TyShape =
            TyShape::Fun(&CONNECTION_MODE, &STRING_TO_STRING_TO_TASK_MAYBE_DICT_SS);
        // `queryDecodeOn : Connection c -> String -> List b -> Decoder a
        //                  -> Task Error (List a)`. Mode var is `c` (Var 2) so it
        // never unifies with the decoder's `a` or the params list's `b`.
        const CONNECTION_MODE_C: TyShape = TyShape::Con(BuiltinTag::Connection, &[C]);
        const CONN_QUERY_DECODE: TyShape =
            TyShape::Fun(&CONNECTION_MODE_C, &STRING_TO_QUERY_DECODE);
        // Locale.
        const MAYBE_LOCALE: TyShape = TyShape::Con(BuiltinTag::Maybe, &[LOCALE]);
        const STRING_TO_MAYBE_LOCALE: TyShape = TyShape::Fun(&STRING, &MAYBE_LOCALE);
        const LOCALE_TO_STRING: TyShape = TyShape::Fun(&LOCALE, &STRING);
        const LOCALE_TO_STRING_TO_STRING: TyShape =
            TyShape::Fun(&LOCALE, &TyShape::Fun(&STRING, &STRING));
        // Crypto typed-key.
        const MAYBE_CRYPTO_KEY: TyShape = TyShape::Con(BuiltinTag::Maybe, &[CRYPTO_KEY]);
        const STRING_TO_MAYBE_CRYPTO_KEY: TyShape = TyShape::Fun(&STRING, &MAYBE_CRYPTO_KEY);
        const STRING_TO_CRYPTO_KEY: TyShape = TyShape::Fun(&STRING, &CRYPTO_KEY);
        const CRYPTO_MAC_TO_STRING: TyShape = TyShape::Fun(&CRYPTO_MAC, &STRING);
        const STRING_TO_CRYPTO_MAC: TyShape = TyShape::Fun(&STRING, &CRYPTO_MAC);
        const CRYPTO_KEY_TO_STRING_TO_CRYPTO_MAC: TyShape =
            TyShape::Fun(&CRYPTO_KEY, &STRING_TO_CRYPTO_MAC);
        const STRING_TO_STRING_TO_CRYPTO_KEY: TyShape =
            TyShape::Fun(&STRING, &STRING_TO_CRYPTO_KEY);
        const STRING_TO_RESULT_ERR_STRING: TyShape = TyShape::Fun(&STRING, &RESULT_ERR_STRING);
        const CRYPTO_KEY_TO_STRING_TO_RESULT_ERR_STRING: TyShape =
            TyShape::Fun(&CRYPTO_KEY, &STRING_TO_RESULT_ERR_STRING);
        // Crypto/Jwt `String -> String -> Result Error String`.
        const STRING_TO_STRING_TO_RESULT_ERR_STRING: TyShape =
            TyShape::Fun(&STRING, &STRING_TO_RESULT_ERR_STRING);
        // Crypto.randomBytes / randomToken : Int -> Task String.
        const INT_TO_TASK_STRING_LEAF: TyShape = TyShape::Fun(&INT, &TASK_STRING);
        // EmailAddress.
        const MAYBE_EMAIL_ADDRESS: TyShape = TyShape::Con(BuiltinTag::Maybe, &[EMAIL_ADDRESS]);
        const STRING_TO_MAYBE_EMAIL_ADDRESS: TyShape = TyShape::Fun(&STRING, &MAYBE_EMAIL_ADDRESS);
        const EMAIL_ADDRESS_TO_STRING: TyShape = TyShape::Fun(&EMAIL_ADDRESS, &STRING);
        // Email.send : EmailProvider -> EmailMessage -> Task String  (record → S4).
        // Auth.
        const DICT_SS_TO_INT_TO_RESULT_ERR_STRING: TyShape =
            TyShape::Fun(&DICT_STRING_STRING, &TyShape::Fun(&INT, &RESULT_ERR_STRING));
        const AUTH_SIGN_TOKEN: TyShape =
            TyShape::Fun(&SECRET, &DICT_SS_TO_INT_TO_RESULT_ERR_STRING);
        const STRING_TO_RESULT_ERR_DICT_SS: TyShape = TyShape::Fun(&STRING, &RESULT_ERR_DICT_SS);
        const AUTH_VERIFY_TOKEN: TyShape = TyShape::Fun(&SECRET, &STRING_TO_RESULT_ERR_DICT_SS);
        const STRING_TO_RESULT_ERR_BOOL: TyShape = TyShape::Fun(&STRING, &RESULT_ERR_BOOL);
        const STRING_TO_STRING_TO_RESULT_ERR_BOOL: TyShape =
            TyShape::Fun(&STRING, &STRING_TO_RESULT_ERR_BOOL);
        const INT_TO_RESULT_ERR_STRING: TyShape = TyShape::Fun(&INT, &RESULT_ERR_STRING);
        const STRING_TO_INT_TO_RESULT_ERR_STRING: TyShape =
            TyShape::Fun(&STRING, &INT_TO_RESULT_ERR_STRING);
        const DB_TO_STRING_TO_STRING_TO_TASK_INT: TyShape = TyShape::Fun(
            &DB,
            &TyShape::Fun(&STRING, &TyShape::Fun(&STRING, &TASK_INT)),
        );
        const DB_TO_INT_TO_STRING_TO_TASK_UNIT: TyShape =
            TyShape::Fun(&DB, &TyShape::Fun(&INT, &TyShape::Fun(&STRING, &TASK_UNIT)));
        // Auth.Revocation: `Principal -> String -> Task ()` (revokeUser / restoreUser).
        const PRINCIPAL_TO_STRING_TO_TASK_UNIT: TyShape =
            TyShape::Fun(&PRINCIPAL, &TyShape::Fun(&STRING, &TASK_UNIT));
        // Auth.Revocation: `Principal -> String -> Int -> Task ()` (revokeSession).
        const PRINCIPAL_TO_STRING_TO_INT_TO_TASK_UNIT: TyShape = TyShape::Fun(
            &PRINCIPAL,
            &TyShape::Fun(&STRING, &TyShape::Fun(&INT, &TASK_UNIT)),
        );
        // Auth.Revocation: `String -> Task Bool` (isRevoked).
        const STRING_TO_TASK_BOOL_REVOKE: TyShape = TyShape::Fun(&STRING, &TASK_BOOL);
        // Compression : Bytes -> Task Bytes.
        const BYTES_TO_TASK_BYTES: TyShape = TyShape::Fun(&BYTES, &TASK_BYTES);
        // Trace.
        const TASK_A_TO_TASK_A_TRACE: TyShape = TyShape::Fun(&TASK_A, &TASK_A);
        const STRING_TO_TASK_A_TO_TASK_A: TyShape = TyShape::Fun(&STRING, &TASK_A_TO_TASK_A_TRACE);
        const STRING_TO_STRING_TO_TASK_UNIT_TRACE: TyShape =
            TyShape::Fun(&STRING, &STRING_TO_TASK_UNIT);
        // HttpStream.
        const STREAM_ID_TO_TASK_UNIT: TyShape = TyShape::Fun(&STREAM_ID, &TASK_UNIT);
        const STRING_TO_TASK_UNIT_LEAF: TyShape = TyShape::Fun(&STRING, &TASK_UNIT);
        const STREAM_ID_FOR_EACH: TyShape = TyShape::Fun(
            &STREAM_ID,
            &TyShape::Fun(&STRING_TO_TASK_UNIT_LEAF, &TASK_UNIT),
        );
        const A_TO_B_TO_SUB_B: TyShape = TyShape::Fun(&A_TO_B, &SUB_B);
        const STREAM_ID_CHUNKS: TyShape = TyShape::Fun(&STREAM_ID, &A_TO_B_TO_SUB_B);
        // WebSocket client (raw Int handle).
        const INT_TO_TASK_UNIT_LEAF: TyShape = TyShape::Fun(&INT, &TASK_UNIT);
        const STRING_TO_TASK_INT_LEAF: TyShape = TyShape::Fun(&STRING, &TASK_INT);
        const INT_TO_STRING_TO_TASK_UNIT: TyShape = TyShape::Fun(&INT, &STRING_TO_TASK_UNIT);
        const INT_TO_BYTES_TO_TASK_UNIT: TyShape =
            TyShape::Fun(&INT, &TyShape::Fun(&BYTES, &TASK_UNIT));
        const WS_CLOSE_WITH_CODE: TyShape = TyShape::Fun(
            &INT,
            &TyShape::Fun(&STRING, &TyShape::Fun(&INT, &TASK_UNIT)),
        );
        const SUB_SUBSCRIBE_WS: TyShape =
            TyShape::Fun(&INT, &TyShape::Fun(&STRING, &TyShape::Fun(&A, &SUB_B)));
        // Ipe.Ffi.Js ports. `send : a -> Cmd msg` — payload `a` is the scheme's `A`
        // (the sealed crossing value), `msg` is `B` (so `Cmd msg` reuses `CMD_B`).
        // `subscribe : Decoder a -> (a -> msg) -> Sub msg` — decoded `a` is `A`,
        // `msg` is `B`, reusing `DEC_A` / `A_TO_B` / `SUB_B`. The seal-legality of the concrete
        // `a` is not expressible as a `TyShape` bound (it is a structural predicate,
        // not a class), so it is enforced separately at lowering
        // (`reject_illegal_js_port_seal`), exactly as `CustomElement`'s seal is a
        // canon gate rather than a scheme constraint.
        const JS_SEND: TyShape = TyShape::Fun(&A, &CMD_B);
        const JS_SUBSCRIBE: TyShape = TyShape::Fun(&DEC_A, &TyShape::Fun(&A_TO_B, &SUB_B));
        // `request : a -> Decoder b -> Task b` — correlated one-shot port request.
        // Outbound payload `a` = var 0, decoded reply `b` = var 1.
        const JS_REQUEST: TyShape = TyShape::Fun(&A, &TyShape::Fun(&DEC_B, &TASK_B));
        // Ipe.Ffi.Js session-stream primitive. `SessionHandle` is the opaque leaf
        // address (nullary). Same seal-legality discipline as the other ports (the
        // concrete `openCmd`/`frame`/`sessionCmd`/`closeCmd`/`terminal` are checked
        // at lowering, not as a scheme bound).
        //   `openSession   : openCmd -> Decoder frame -> Task SessionHandle`
        //       openCmd = var 0 (`A`), frame = var 1 (`B`).
        //   `sessionFrames : SessionHandle -> (frame -> msg) -> Sub msg`
        //       frame = var 0 (`A`), msg = var 1 (`B`).
        //   `sendToSession : SessionHandle -> sessionCmd -> Cmd msg`
        //       sessionCmd = var 0 (`A`), msg = var 1 (`B`).
        //   `closeSession  : SessionHandle -> closeCmd -> Decoder terminal -> Task terminal`
        //       closeCmd = var 0 (`A`), terminal = var 1 (`B`).
        const SESSION_HANDLE: TyShape = TyShape::Con(BuiltinTag::SessionHandle, &[]);
        const TASK_SESSION_HANDLE: TyShape = TyShape::Con(BuiltinTag::Task, &[SESSION_HANDLE]);
        const JS_OPEN_SESSION: TyShape =
            TyShape::Fun(&A, &TyShape::Fun(&DEC_B, &TASK_SESSION_HANDLE));
        const JS_SESSION_FRAMES: TyShape = TyShape::Fun(
            &SESSION_HANDLE,
            &TyShape::Fun(&DEC_A, &TyShape::Fun(&A_TO_B, &SUB_B)),
        );
        const JS_SEND_TO_SESSION: TyShape =
            TyShape::Fun(&SESSION_HANDLE, &TyShape::Fun(&A, &CMD_B));
        const JS_CLOSE_SESSION: TyShape = TyShape::Fun(
            &SESSION_HANDLE,
            &TyShape::Fun(&A, &TyShape::Fun(&DEC_B, &TASK_B)),
        );
        // Ws server.
        const WS_ON_CB_TO_CFG: TyShape = TyShape::Fun(
            &TyShape::Fun(&WS_SERVER, &TASK_UNIT),
            &TyShape::Fun(&WS_SERVER_CFG, &WS_SERVER_CFG),
        );
        const WS_ON_MESSAGE: TyShape = TyShape::Fun(
            &TyShape::Fun(&WS_SERVER, &STRING_TO_TASK_UNIT),
            &TyShape::Fun(&WS_SERVER_CFG, &WS_SERVER_CFG),
        );
        const WS_ON_ERROR: TyShape = TyShape::Fun(
            &TyShape::Fun(&WS_SERVER, &TyShape::Fun(&ERROR, &TASK_UNIT)),
            &TyShape::Fun(&WS_SERVER_CFG, &WS_SERVER_CFG),
        );
        const INT_TO_CFG_TO_CFG: TyShape =
            TyShape::Fun(&INT, &TyShape::Fun(&WS_SERVER_CFG, &WS_SERVER_CFG));
        const LIST_STRING_TO_CFG_TO_CFG: TyShape =
            TyShape::Fun(&LIST_STRING, &TyShape::Fun(&WS_SERVER_CFG, &WS_SERVER_CFG));
        const WS_SEND_TO_CLIENT: TyShape = TyShape::Fun(&WS_SERVER, &STRING_TO_TASK_UNIT);
        const WS_SEND_BINARY: TyShape = TyShape::Fun(&WS_SERVER, &TyShape::Fun(&BYTES, &TASK_UNIT));
        const LIST_WS_SERVER: TyShape = TyShape::Con(BuiltinTag::List, &[WS_SERVER]);
        const WS_BROADCAST: TyShape = TyShape::Fun(&LIST_WS_SERVER, &STRING_TO_TASK_UNIT);
        const WS_CLOSE_CLIENT: TyShape = TyShape::Fun(&WS_SERVER, &TASK_UNIT);
        // Server (route/cookie only — non-record arms).
        const STRING_TO_STRING_TO_ROUTE: TyShape =
            TyShape::Fun(&STRING, &TyShape::Fun(&STRING, &SERVER_ROUTE));
        const STRING_TO_STRING_TO_COOKIE: TyShape =
            TyShape::Fun(&STRING, &TyShape::Fun(&STRING, &SERVER_COOKIE));
        const REQ_TO_STRING: TyShape = TyShape::Fun(&SERVER_REQUEST, &STRING);
        const STRING_TO_REQ_TO_MAYBE_STRING: TyShape =
            TyShape::Fun(&STRING, &TyShape::Fun(&SERVER_REQUEST, &MAYBE_STRING));
        // Jwt builder.
        const STRING_TO_ALGORITHM: TyShape = TyShape::Fun(&STRING, &ALGORITHM);
        const STRING_TO_CLAIMS_TO_CLAIMS: TyShape =
            TyShape::Fun(&STRING, &TyShape::Fun(&CLAIMS, &CLAIMS));
        const INT_TO_CLAIMS_TO_CLAIMS: TyShape =
            TyShape::Fun(&INT, &TyShape::Fun(&CLAIMS, &CLAIMS));
        const JWT_WITH_CLAIM: TyShape = TyShape::Fun(
            &STRING,
            &TyShape::Fun(&JSON_VALUE, &TyShape::Fun(&CLAIMS, &CLAIMS)),
        );
        const JWT_ENCODE: TyShape =
            TyShape::Fun(&ALGORITHM, &TyShape::Fun(&CLAIMS, &RESULT_ERR_STRING));
        const JWT_DECODE: TyShape = TyShape::Fun(
            &ALGORITHM,
            &TyShape::Fun(&INT, &TyShape::Fun(&STRING, &RESULT_ERR_STRING)),
        );
        // Sql fragment builders.
        const STRING_TO_SQLFRAGMENT: TyShape = TyShape::Fun(&STRING, &SQLFRAGMENT);
        const SQLVALUE_TO_SQLFRAGMENT: TyShape = TyShape::Fun(&SQLVALUE, &SQLFRAGMENT);
        const INT_TO_SQLFRAGMENT: TyShape = TyShape::Fun(&INT, &SQLFRAGMENT);
        const FLOAT_TO_SQLFRAGMENT: TyShape = TyShape::Fun(&FLOAT, &SQLFRAGMENT);
        const BOOL_TO_SQLFRAGMENT: TyShape = TyShape::Fun(&BOOL, &SQLFRAGMENT);
        const SQLFRAGMENT_TO_SQLFRAGMENT: TyShape = TyShape::Fun(&SQLFRAGMENT, &SQLFRAGMENT);
        const SQLFRAGMENT_BINOP: TyShape = TyShape::Fun(&SQLFRAGMENT, &SQLFRAGMENT_TO_SQLFRAGMENT);
        const LIST_SQLVALUE: TyShape = TyShape::Con(BuiltinTag::List, &[SQLVALUE]);
        const SQL_IN_LIST: TyShape =
            TyShape::Fun(&SQLFRAGMENT, &TyShape::Fun(&LIST_SQLVALUE, &SQLFRAGMENT));
        const SQL_LIKE: TyShape = TyShape::Fun(&SQLFRAGMENT, &TyShape::Fun(&STRING, &SQLFRAGMENT));
        // `exists : String -> SqlFragment -> SqlFragment` — table name + inner
        // fragment to a correlated-subquery existence test.
        const SQL_EXISTS: TyShape =
            TyShape::Fun(&STRING, &TyShape::Fun(&SQLFRAGMENT, &SQLFRAGMENT));
        // `maskedColumn : SqlFragment -> String -> SqlFragment` — a predicate
        // fragment + a column name to a `CASE WHEN … THEN col ELSE NULL END AS col`
        // masking projection term.
        const SQL_MASKED_COLUMN: TyShape =
            TyShape::Fun(&SQLFRAGMENT, &TyShape::Fun(&STRING, &SQLFRAGMENT));
        // Server-side stream (opaque `StreamWriter` handle).
        // `emit : String -> StreamWriter -> Task ()`.
        const SW_TO_TASK_UNIT: TyShape = TyShape::Fun(&STREAM_WRITER, &TASK_UNIT);
        const STRING_TO_SW_TO_TASK_UNIT: TyShape = TyShape::Fun(&STRING, &SW_TO_TASK_UNIT);
        // Db.insertFields / updateFields (opaque `SqlField` / `SqlValue`, no record).
        // `insertFields : Db -> String -> List (String, SqlField) -> Task Int`.
        const TUPLE_STRING_SQLFIELD: TyShape = TyShape::Tuple(&[STRING, SQLFIELD]);
        const LIST_TUPLE_STRING_SQLFIELD: TyShape =
            TyShape::Con(BuiltinTag::List, &[TUPLE_STRING_SQLFIELD]);
        const LIST_SQLFIELD_TO_TASK_INT: TyShape =
            TyShape::Fun(&LIST_TUPLE_STRING_SQLFIELD, &TASK_INT);
        const STRING_TO_LIST_SQLFIELD_TO_TASK_INT: TyShape =
            TyShape::Fun(&STRING, &LIST_SQLFIELD_TO_TASK_INT);
        const DB_INSERT_FIELDS: TyShape = TyShape::Fun(&DB, &STRING_TO_LIST_SQLFIELD_TO_TASK_INT);
        // `updateFields : Db -> String -> List (String, SqlValue)
        //                 -> List (String, SqlField) -> Task Int`.
        const TUPLE_STRING_SQLVALUE: TyShape = TyShape::Tuple(&[STRING, SQLVALUE]);
        const LIST_TUPLE_STRING_SQLVALUE: TyShape =
            TyShape::Con(BuiltinTag::List, &[TUPLE_STRING_SQLVALUE]);
        const LIST_SQLVALUE_TO_LIST_SQLFIELD_TO_TASK_INT: TyShape =
            TyShape::Fun(&LIST_TUPLE_STRING_SQLVALUE, &LIST_SQLFIELD_TO_TASK_INT);
        const STRING_TO_UPDATE_FIELDS: TyShape =
            TyShape::Fun(&STRING, &LIST_SQLVALUE_TO_LIST_SQLFIELD_TO_TASK_INT);
        const DB_UPDATE_FIELDS: TyShape = TyShape::Fun(&DB, &STRING_TO_UPDATE_FIELDS);
        // `upsertFields : Db -> String -> List String
        //                 -> List (String, SqlField) -> Task Int`.
        const LIST_STRING_TO_LIST_SQLFIELD_TO_TASK_INT: TyShape =
            TyShape::Fun(&LIST_STRING, &LIST_SQLFIELD_TO_TASK_INT);
        const STRING_TO_UPSERT_FIELDS: TyShape =
            TyShape::Fun(&STRING, &LIST_STRING_TO_LIST_SQLFIELD_TO_TASK_INT);
        const DB_UPSERT_FIELDS: TyShape = TyShape::Fun(&DB, &STRING_TO_UPSERT_FIELDS);
        // Db.exec / query / findWhere / deleteWhere / etc. (opaque Db + Dict rows,
        // no record).
        // `Db.connect : () -> Task Db`.
        const TASK_DB: TyShape = TyShape::Con(BuiltinTag::Task, &[DB]);
        const UNIT_TO_TASK_DB: TyShape = TyShape::Fun(&UNIT, &TASK_DB);
        // `Db.open : String -> String -> Task Db`.
        const STRING_TO_TASK_DB: TyShape = TyShape::Fun(&STRING, &TASK_DB);
        const STRING_TO_STRING_TO_TASK_DB: TyShape = TyShape::Fun(&STRING, &STRING_TO_TASK_DB);
        // `Db.close : Db -> Task ()`.
        const DB_TO_TASK_UNIT: TyShape = TyShape::Fun(&DB, &TASK_UNIT);
        // `Db.execRaw : Db -> String -> Task Int`.
        const STRING_TO_TASK_INT_LEAF2: TyShape = TyShape::Fun(&STRING, &TASK_INT);
        const DB_EXEC_RAW: TyShape = TyShape::Fun(&DB, &STRING_TO_TASK_INT_LEAF2);
        // `Db.exec : Db -> String -> List a -> Task Int`.
        const LIST_A_TO_TASK_INT: TyShape = TyShape::Fun(&LIST_A, &TASK_INT);
        const STRING_TO_LIST_A_TO_TASK_INT: TyShape = TyShape::Fun(&STRING, &LIST_A_TO_TASK_INT);
        const DB_EXEC: TyShape = TyShape::Fun(&DB, &STRING_TO_LIST_A_TO_TASK_INT);
        // `Db.query : Db -> String -> List a -> Task (List (Dict String String))`.
        const LIST_DICT_SS: TyShape = TyShape::Con(BuiltinTag::List, &[DICT_STRING_STRING]);
        const TASK_LIST_DICT_SS: TyShape = TyShape::Con(BuiltinTag::Task, &[LIST_DICT_SS]);
        const LIST_A_TO_TASK_LIST_DICT_SS: TyShape = TyShape::Fun(&LIST_A, &TASK_LIST_DICT_SS);
        const STRING_TO_LIST_A_TO_TASK_LIST_DICT_SS: TyShape =
            TyShape::Fun(&STRING, &LIST_A_TO_TASK_LIST_DICT_SS);
        const DB_QUERY: TyShape = TyShape::Fun(&DB, &STRING_TO_LIST_A_TO_TASK_LIST_DICT_SS);
        // `Db.queryDecode : Db -> String -> List b -> Decoder a -> Task (List a)`.
        const DEC_A_TO_TASK_LIST_A: TyShape = TyShape::Fun(&DEC_A, &TASK_LIST_A);
        const LIST_B_TO_DEC_A_TO_TASK_LIST_A: TyShape =
            TyShape::Fun(&LIST_B, &DEC_A_TO_TASK_LIST_A);
        const STRING_TO_QUERY_DECODE: TyShape =
            TyShape::Fun(&STRING, &LIST_B_TO_DEC_A_TO_TASK_LIST_A);
        const DB_QUERY_DECODE: TyShape = TyShape::Fun(&DB, &STRING_TO_QUERY_DECODE);
        // `Db.findWhereMasked : Db -> String -> List SqlFragment -> SqlFragment
        //                        -> Decoder a -> Task (List a)`. The projection
        // fragment list is the masked/unmasked SELECT terms; the trailing
        // `SqlFragment` is the WHERE; the `Decoder a` reads each NULL-preserving
        // row back to the store's row type.
        const LIST_SQLFRAGMENT: TyShape = TyShape::Con(BuiltinTag::List, &[SQLFRAGMENT]);
        const DEC_A_TO_TASK_LIST_A_MASKED: TyShape = TyShape::Fun(&DEC_A, &TASK_LIST_A);
        const SQLFRAGMENT_TO_DEC_A_TO_FIND_MASKED: TyShape =
            TyShape::Fun(&SQLFRAGMENT, &DEC_A_TO_TASK_LIST_A_MASKED);
        const LIST_SQLFRAGMENT_TO_FIND_MASKED: TyShape =
            TyShape::Fun(&LIST_SQLFRAGMENT, &SQLFRAGMENT_TO_DEC_A_TO_FIND_MASKED);
        const STRING_TO_FIND_MASKED: TyShape =
            TyShape::Fun(&STRING, &LIST_SQLFRAGMENT_TO_FIND_MASKED);
        const DB_FIND_WHERE_MASKED: TyShape = TyShape::Fun(&DB, &STRING_TO_FIND_MASKED);
        // `Db.insertRow : Db -> String -> Dict String String -> Task Int`.
        const DICT_SS_TO_TASK_INT: TyShape = TyShape::Fun(&DICT_STRING_STRING, &TASK_INT);
        const STRING_TO_DICT_SS_TO_TASK_INT: TyShape = TyShape::Fun(&STRING, &DICT_SS_TO_TASK_INT);
        const DB_INSERT_ROW: TyShape = TyShape::Fun(&DB, &STRING_TO_DICT_SS_TO_TASK_INT);
        // `Db.getById : Db -> String -> String -> Task (Maybe (Dict String String))`.
        const MAYBE_DICT_SS: TyShape = TyShape::Con(BuiltinTag::Maybe, &[DICT_STRING_STRING]);
        const TASK_MAYBE_DICT_SS: TyShape = TyShape::Con(BuiltinTag::Task, &[MAYBE_DICT_SS]);
        const STRING_TO_TASK_MAYBE_DICT_SS: TyShape = TyShape::Fun(&STRING, &TASK_MAYBE_DICT_SS);
        const STRING_TO_STRING_TO_TASK_MAYBE_DICT_SS: TyShape =
            TyShape::Fun(&STRING, &STRING_TO_TASK_MAYBE_DICT_SS);
        const DB_GET_BY_ID: TyShape = TyShape::Fun(&DB, &STRING_TO_STRING_TO_TASK_MAYBE_DICT_SS);
        // `Db.updateById : Db -> String -> String -> Dict String String -> Task Int`.
        const STRING_TO_DICT_SS_TO_TASK_INT_2: TyShape =
            TyShape::Fun(&STRING, &DICT_SS_TO_TASK_INT);
        const STRING_TO_UPDATE_BY_ID: TyShape =
            TyShape::Fun(&STRING, &STRING_TO_DICT_SS_TO_TASK_INT_2);
        const DB_UPDATE_BY_ID: TyShape = TyShape::Fun(&DB, &STRING_TO_UPDATE_BY_ID);
        // `Db.deleteById : Db -> String -> String -> Task Int`.
        const STRING_TO_TASK_INT_2: TyShape = TyShape::Fun(&STRING, &TASK_INT);
        const STRING_TO_STRING_TO_TASK_INT: TyShape = TyShape::Fun(&STRING, &STRING_TO_TASK_INT_2);
        const DB_DELETE_BY_ID: TyShape = TyShape::Fun(&DB, &STRING_TO_STRING_TO_TASK_INT);
        // `Db.findOneByField : Db -> String -> String -> String
        //                      -> Task (Maybe (Dict String String))`.
        const STRING_TO_STRING_TO_TASK_MAYBE_DICT_SS_2: TyShape =
            TyShape::Fun(&STRING, &STRING_TO_TASK_MAYBE_DICT_SS);
        const STRING_TO_FIND_ONE: TyShape =
            TyShape::Fun(&STRING, &STRING_TO_STRING_TO_TASK_MAYBE_DICT_SS_2);
        const DB_FIND_ONE_BY_FIELD: TyShape = TyShape::Fun(&DB, &STRING_TO_FIND_ONE);
        // `Db.findManyByField : Db -> String -> String -> String
        //                       -> Task (List (Dict String String))`.
        const STRING_TO_TASK_LIST_DICT_SS: TyShape = TyShape::Fun(&STRING, &TASK_LIST_DICT_SS);
        const STRING_TO_STRING_TO_TASK_LIST_DICT_SS: TyShape =
            TyShape::Fun(&STRING, &STRING_TO_TASK_LIST_DICT_SS);
        const STRING_TO_FIND_MANY: TyShape =
            TyShape::Fun(&STRING, &STRING_TO_STRING_TO_TASK_LIST_DICT_SS);
        const DB_FIND_MANY_BY_FIELD: TyShape = TyShape::Fun(&DB, &STRING_TO_FIND_MANY);
        // `Db.findByConditions : Db -> String -> Dict String String
        //                        -> Task (List (Dict String String))`.
        const DICT_SS_TO_TASK_LIST_DICT_SS: TyShape =
            TyShape::Fun(&DICT_STRING_STRING, &TASK_LIST_DICT_SS);
        const STRING_TO_FIND_BY_COND: TyShape =
            TyShape::Fun(&STRING, &DICT_SS_TO_TASK_LIST_DICT_SS);
        const DB_FIND_BY_CONDITIONS: TyShape = TyShape::Fun(&DB, &STRING_TO_FIND_BY_COND);
        // `Db.findWhere : Db -> String -> SqlFragment
        //                 -> Task (List (Dict String String))`.
        const SQLFRAGMENT_TO_TASK_LIST_DICT_SS: TyShape =
            TyShape::Fun(&SQLFRAGMENT, &TASK_LIST_DICT_SS);
        const STRING_TO_FIND_WHERE: TyShape =
            TyShape::Fun(&STRING, &SQLFRAGMENT_TO_TASK_LIST_DICT_SS);
        const DB_FIND_WHERE: TyShape = TyShape::Fun(&DB, &STRING_TO_FIND_WHERE);
        // `Db.findJoin : Db -> String -> String -> List String -> String
        //                -> String -> List String -> SqlFragment
        //                -> Task (List (Dict String String, Dict String String))`.
        const TUPLE_DICT_SS_DICT_SS: TyShape =
            TyShape::Tuple(&[DICT_STRING_STRING, DICT_STRING_STRING]);
        const LIST_TUPLE_DICT_SS_DICT_SS: TyShape =
            TyShape::Con(BuiltinTag::List, &[TUPLE_DICT_SS_DICT_SS]);
        const TASK_LIST_TUPLE_DICT_SS_DICT_SS: TyShape =
            TyShape::Con(BuiltinTag::Task, &[LIST_TUPLE_DICT_SS_DICT_SS]);
        const SQLFRAGMENT_TO_FIND_JOIN: TyShape =
            TyShape::Fun(&SQLFRAGMENT, &TASK_LIST_TUPLE_DICT_SS_DICT_SS);
        const LIST_STRING_TO_FIND_JOIN: TyShape =
            TyShape::Fun(&LIST_STRING, &SQLFRAGMENT_TO_FIND_JOIN);
        const STRING_TO_LIST_STRING_TO_FIND_JOIN: TyShape =
            TyShape::Fun(&STRING, &LIST_STRING_TO_FIND_JOIN);
        const STRING_2_TO_FIND_JOIN: TyShape =
            TyShape::Fun(&STRING, &STRING_TO_LIST_STRING_TO_FIND_JOIN);
        const LIST_STRING_2_TO_FIND_JOIN: TyShape =
            TyShape::Fun(&LIST_STRING, &STRING_2_TO_FIND_JOIN);
        const STRING_3_TO_FIND_JOIN: TyShape = TyShape::Fun(&STRING, &LIST_STRING_2_TO_FIND_JOIN);
        const STRING_4_TO_FIND_JOIN: TyShape = TyShape::Fun(&STRING, &STRING_3_TO_FIND_JOIN);
        const DB_FIND_JOIN: TyShape = TyShape::Fun(&DB, &STRING_4_TO_FIND_JOIN);
        // `Db.findProjection : Db -> String -> String -> String -> String
        //                      -> SqlFragment -> List ProjectionTerm -> List a
        //                      -> Task (List (Dict String String))`.
        // `List a` (= `LIST_A`) is the `extraBinds` parameter — `Store.literal`
        // bind values, schemed polymorphically so a concrete `SqlValue` element unifies.
        const PROJECTION_TERM: TyShape = TyShape::Con(BuiltinTag::ProjectionTerm, &[]);
        const LIST_PROJECTION_TERM: TyShape = TyShape::Con(BuiltinTag::List, &[PROJECTION_TERM]);
        const LIST_A_TO_FIND_PROJECTION: TyShape = TyShape::Fun(&LIST_A, &TASK_LIST_DICT_SS);
        const LIST_PT_TO_FIND_PROJECTION: TyShape =
            TyShape::Fun(&LIST_PROJECTION_TERM, &LIST_A_TO_FIND_PROJECTION);
        const SQLFRAGMENT_TO_FIND_PROJECTION: TyShape =
            TyShape::Fun(&SQLFRAGMENT, &LIST_PT_TO_FIND_PROJECTION);
        const STRING_TO_FIND_PROJECTION: TyShape =
            TyShape::Fun(&STRING, &SQLFRAGMENT_TO_FIND_PROJECTION);
        const STRING_2_TO_FIND_PROJECTION: TyShape =
            TyShape::Fun(&STRING, &STRING_TO_FIND_PROJECTION);
        const STRING_3_TO_FIND_PROJECTION: TyShape =
            TyShape::Fun(&STRING, &STRING_2_TO_FIND_PROJECTION);
        const STRING_4_TO_FIND_PROJECTION: TyShape =
            TyShape::Fun(&STRING, &STRING_3_TO_FIND_PROJECTION);
        const DB_FIND_PROJECTION: TyShape = TyShape::Fun(&DB, &STRING_4_TO_FIND_PROJECTION);
        // `Db.findJoinOrdered : Db -> String -> String -> List String -> String
        //                       -> String -> List String -> SqlFragment
        //                       -> String -> String -> Bool
        //                       -> Task (List (Dict String String, Dict String String))`.
        // Identical to `DB_FIND_JOIN` plus 3 trailing args: orderAlias, orderCol, Bool.
        const BOOL_TO_FIND_JOIN_ORDERED: TyShape =
            TyShape::Fun(&BOOL, &TASK_LIST_TUPLE_DICT_SS_DICT_SS);
        const STRING_TO_BOOL_TO_FIND_JOIN_ORDERED: TyShape =
            TyShape::Fun(&STRING, &BOOL_TO_FIND_JOIN_ORDERED);
        const STRING_2_ORDER_TO_FIND_JOIN: TyShape =
            TyShape::Fun(&STRING, &STRING_TO_BOOL_TO_FIND_JOIN_ORDERED);
        const SQLFRAGMENT_TO_FIND_JOIN_ORD: TyShape =
            TyShape::Fun(&SQLFRAGMENT, &STRING_2_ORDER_TO_FIND_JOIN);
        const LIST_STRING_TO_FIND_JOIN_ORD: TyShape =
            TyShape::Fun(&LIST_STRING, &SQLFRAGMENT_TO_FIND_JOIN_ORD);
        const STR_TO_LS_TO_FIND_JOIN_ORD: TyShape =
            TyShape::Fun(&STRING, &LIST_STRING_TO_FIND_JOIN_ORD);
        const STR2_TO_FIND_JOIN_ORD: TyShape = TyShape::Fun(&STRING, &STR_TO_LS_TO_FIND_JOIN_ORD);
        const LS_STR2_TO_FIND_JOIN_ORD: TyShape =
            TyShape::Fun(&LIST_STRING, &STR2_TO_FIND_JOIN_ORD);
        const STR3_TO_FIND_JOIN_ORD: TyShape = TyShape::Fun(&STRING, &LS_STR2_TO_FIND_JOIN_ORD);
        const STR4_TO_FIND_JOIN_ORD: TyShape = TyShape::Fun(&STRING, &STR3_TO_FIND_JOIN_ORD);
        const DB_FIND_JOIN_ORDERED: TyShape = TyShape::Fun(&DB, &STR4_TO_FIND_JOIN_ORD);
        // `Db.findProjectionOrdered : Db -> String -> String -> String -> String
        //                             -> SqlFragment -> List ProjectionTerm -> List a
        //                             -> String -> String -> Bool
        //                             -> Task (List (Dict String String))`.
        // `List a` is `extraBinds` (same as in `DB_FIND_PROJECTION`).
        // Three trailing args after `extraBinds`: orderAlias, orderCol, Bool.
        const BOOL_TO_FIND_PROJ_ORD: TyShape = TyShape::Fun(&BOOL, &TASK_LIST_DICT_SS);
        const STRING_TO_BOOL_TO_FIND_PROJ_ORD: TyShape =
            TyShape::Fun(&STRING, &BOOL_TO_FIND_PROJ_ORD);
        const STRING_2_ORDER_TO_FIND_PROJ: TyShape =
            TyShape::Fun(&STRING, &STRING_TO_BOOL_TO_FIND_PROJ_ORD);
        const LIST_A_TO_FIND_PROJ_ORD: TyShape =
            TyShape::Fun(&LIST_A, &STRING_2_ORDER_TO_FIND_PROJ);
        const LIST_PT_TO_FIND_PROJ_ORD: TyShape =
            TyShape::Fun(&LIST_PROJECTION_TERM, &LIST_A_TO_FIND_PROJ_ORD);
        const SQLFRAGMENT_TO_FIND_PROJ_ORD: TyShape =
            TyShape::Fun(&SQLFRAGMENT, &LIST_PT_TO_FIND_PROJ_ORD);
        const STR_TO_FIND_PROJ_ORD: TyShape = TyShape::Fun(&STRING, &SQLFRAGMENT_TO_FIND_PROJ_ORD);
        const STR2_TO_FIND_PROJ_ORD: TyShape = TyShape::Fun(&STRING, &STR_TO_FIND_PROJ_ORD);
        const STR3_TO_FIND_PROJ_ORD: TyShape = TyShape::Fun(&STRING, &STR2_TO_FIND_PROJ_ORD);
        const STR4_TO_FIND_PROJ_ORD: TyShape = TyShape::Fun(&STRING, &STR3_TO_FIND_PROJ_ORD);
        const DB_FIND_PROJECTION_ORDERED: TyShape = TyShape::Fun(&DB, &STR4_TO_FIND_PROJ_ORD);
        // `Db.deleteWhere : Db -> String -> SqlFragment -> Task Int`.
        const SQLFRAGMENT_TO_TASK_INT: TyShape = TyShape::Fun(&SQLFRAGMENT, &TASK_INT);
        const STRING_TO_DELETE_WHERE: TyShape = TyShape::Fun(&STRING, &SQLFRAGMENT_TO_TASK_INT);
        const DB_DELETE_WHERE: TyShape = TyShape::Fun(&DB, &STRING_TO_DELETE_WHERE);
        // `Db.updateWhere : Db -> String -> List (String, SqlField) -> SqlFragment
        //                   -> Task Int`.
        const LIST_SQLFIELD_TO_UPDATE_WHERE: TyShape =
            TyShape::Fun(&LIST_TUPLE_STRING_SQLFIELD, &SQLFRAGMENT_TO_TASK_INT);
        const STRING_TO_UPDATE_WHERE: TyShape =
            TyShape::Fun(&STRING, &LIST_SQLFIELD_TO_UPDATE_WHERE);
        const DB_UPDATE_WHERE: TyShape = TyShape::Fun(&DB, &STRING_TO_UPDATE_WHERE);
        // `Db_updateWhereChecked : Db -> String -> List (String, SqlField)
        //                          -> SqlFragment -> SqlFragment -> Task Int`.
        const SQLFRAGMENT_TO_SQLFRAGMENT_TO_TASK_INT: TyShape =
            TyShape::Fun(&SQLFRAGMENT, &SQLFRAGMENT_TO_TASK_INT);
        const LIST_SQLFIELD_TO_UPDATE_WHERE_CHECKED: TyShape = TyShape::Fun(
            &LIST_TUPLE_STRING_SQLFIELD,
            &SQLFRAGMENT_TO_SQLFRAGMENT_TO_TASK_INT,
        );
        const STRING_TO_UPDATE_WHERE_CHECKED: TyShape =
            TyShape::Fun(&STRING, &LIST_SQLFIELD_TO_UPDATE_WHERE_CHECKED);
        const DB_UPDATE_WHERE_CHECKED: TyShape = TyShape::Fun(&DB, &STRING_TO_UPDATE_WHERE_CHECKED);
        // `Db.insertFieldsReturning : Db -> String -> List (String, SqlField)
        //                             -> String -> Decoder a -> Task (List a)`.
        const DEC_A_TO_TASK_LIST_A_2: TyShape = TyShape::Fun(&DEC_A, &TASK_LIST_A);
        const STRING_TO_DEC_A_TO_TASK_LIST_A: TyShape =
            TyShape::Fun(&STRING, &DEC_A_TO_TASK_LIST_A_2);
        const LIST_SQLFIELD_TO_RETURNING: TyShape =
            TyShape::Fun(&LIST_TUPLE_STRING_SQLFIELD, &STRING_TO_DEC_A_TO_TASK_LIST_A);
        const STRING_TO_INSERT_RETURNING: TyShape =
            TyShape::Fun(&STRING, &LIST_SQLFIELD_TO_RETURNING);
        const DB_INSERT_FIELDS_RETURNING: TyShape = TyShape::Fun(&DB, &STRING_TO_INSERT_RETURNING);
        // `Db.withTransaction : Db -> (Db -> Task a) -> Task a`.
        const DB_TO_TASK_A: TyShape = TyShape::Fun(&DB, &TASK_A);
        const DB_TO_TASK_A_TO_TASK_A: TyShape = TyShape::Fun(&DB_TO_TASK_A, &TASK_A);
        const DB_WITH_TRANSACTION: TyShape = TyShape::Fun(&DB, &DB_TO_TASK_A_TO_TASK_A);

        // Encoding decoders / Env / HttpMethod.
        const HTTP_METHOD_TO_STRING: TyShape = TyShape::Fun(&HTTP_METHOD, &STRING);
        const MAYBE_HTTP_METHOD: TyShape = TyShape::Con(BuiltinTag::Maybe, &[HTTP_METHOD]);
        const STRING_TO_MAYBE_HTTP_METHOD: TyShape = TyShape::Fun(&STRING, &MAYBE_HTTP_METHOD);
        const STRING_TO_MAYBE_STRING_ENV: TyShape = TyShape::Fun(&STRING, &MAYBE_STRING);

        // ── Ipe.Ui / Ipe.Html / style constructor leaves. ──
        // The message-parametric constructors carry the scheme's first variable
        // `msg` (`A` = `Var(0)`). `HTML_ATTR_A` is the module-qualified
        // `Ipe.Html.Attribute msg` (its interpreted `Con` carries the `Html`
        // module path — see `builtin_con_module`); `UI_ATTR_A` is the bare
        // `Ipe.Ui.Attribute msg`. `LENGTH` / `COLOR` / `DESCRIPTION` /
        // `PSEUDO_CLASS` are nullary value types.
        const UI_ATTR_A: TyShape = TyShape::Con(BuiltinTag::UiAttribute, &[A]);
        const HTML_ATTR_A: TyShape = TyShape::Con(BuiltinTag::HtmlAttribute, &[A]);
        // Every DOM combinator yields `View Web msg` (SSOT): the engine tag
        // reuses `Program`'s Web shape tag, so `Element msg` and `View Web msg`
        // are one type. `A` = `Var(0)` = msg.
        const UI_ELEM_A: TyShape = TyShape::Con(BuiltinTag::View, &[PROGRAM_SHAPE_WEB, A]);
        const HTML_A: TyShape = TyShape::Con(BuiltinTag::Html, &[A]);
        const LENGTH: TyShape = TyShape::Con(BuiltinTag::UiLength, &[]);
        const COLOR: TyShape = TyShape::Con(BuiltinTag::UiColor, &[]);
        const DESCRIPTION: TyShape = TyShape::Con(BuiltinTag::UiDescription, &[]);
        const PSEUDO_CLASS: TyShape = TyShape::Con(BuiltinTag::UiPseudoClass, &[]);
        const LABEL_A: TyShape = TyShape::Con(BuiltinTag::InputLabel, &[A]);
        const PLACEHOLDER_A: TyShape = TyShape::Con(BuiltinTag::InputPlaceholder, &[A]);
        const RADIO_OPTION_A: TyShape = TyShape::Con(BuiltinTag::InputRadioOption, &[A]);
        // `List (Attribute msg)` / `List (Element msg)` / `List (Html msg)` /
        // `List (Html.Attribute msg)` slots.
        const LIST_UI_ATTR_A: TyShape = TyShape::Con(BuiltinTag::List, &[UI_ATTR_A]);
        const LIST_UI_ELEM_A: TyShape = TyShape::Con(BuiltinTag::List, &[UI_ELEM_A]);
        const LIST_HTML_A: TyShape = TyShape::Con(BuiltinTag::List, &[HTML_A]);
        const LIST_HTML_ATTR_A: TyShape = TyShape::Con(BuiltinTag::List, &[HTML_ATTR_A]);
        // `Screen msg` (var(0) = msg), and derived forms for `Ipe.Ui.Tui`
        // builders. The internal `Cells` tag is the exposed `Screen` type.
        const CELLS_A: TyShape = TyShape::Con(BuiltinTag::View, &[PROGRAM_SHAPE_TUI, A]);
        const LIST_CELLS_A: TyShape = TyShape::Con(BuiltinTag::List, &[CELLS_A]);
        // The cell-native attribute type `Ipe.Ui.Tui.Attribute msg` and its
        // list slot — DISTINCT from the DOM `UI_ATTR_A`, so a `Screen` builder
        // rejects a DOM attribute at type-check (make-invalid-states-unrepresentable).
        const TUI_ATTR_A: TyShape = TyShape::Con(BuiltinTag::TuiAttr, &[A]);
        const LIST_TUI_ATTR_A: TyShape = TyShape::Con(BuiltinTag::List, &[TUI_ATTR_A]);
        // `String -> Screen msg`
        const STRING_TO_CELLS_A: TyShape = TyShape::Fun(&STRING, &CELLS_A);
        // `List (Attribute msg) -> Screen msg -> Screen msg` (el)
        const CELLS_A_TO_CELLS_A: TyShape = TyShape::Fun(&CELLS_A, &CELLS_A);
        const CELLS_EL: TyShape = TyShape::Fun(&LIST_TUI_ATTR_A, &CELLS_A_TO_CELLS_A);
        // `List (Attribute msg) -> List (Screen msg) -> Screen msg` (row / column)
        const LIST_CELLS_A_TO_CELLS_A: TyShape = TyShape::Fun(&LIST_CELLS_A, &CELLS_A);
        const CELLS_CONTAINER: TyShape = TyShape::Fun(&LIST_TUI_ATTR_A, &LIST_CELLS_A_TO_CELLS_A);
        // `List (List Char) -> Screen msg` (cells)
        const LIST_LIST_CHAR_TO_CELLS_A: TyShape = TyShape::Fun(&LIST_LIST_CHAR, &CELLS_A);
        // Cell-native attribute builders.
        const INT_TO_TUI_ATTR_A: TyShape = TyShape::Fun(&INT, &TUI_ATTR_A);
        // ── Ipe.Color kernel scheme shapes (the unified `Color` value type). ──
        // Reuses the existing `COLOR` const (`BuiltinTag::UiColor` and
        // `BuiltinTag::Color` share the one runtime `color::Color` carrier).
        const INT_TO_INT_TO_INT_TO_COLOR: TyShape =
            TyShape::Fun(&INT, &TyShape::Fun(&INT, &TyShape::Fun(&INT, &COLOR)));
        const INT_TO_INT_TO_INT_TO_FLOAT_TO_COLOR: TyShape = TyShape::Fun(
            &INT,
            &TyShape::Fun(&INT, &TyShape::Fun(&INT, &TyShape::Fun(&FLOAT, &COLOR))),
        );
        const FLOAT_TO_FLOAT_TO_FLOAT_TO_COLOR: TyShape =
            TyShape::Fun(&FLOAT, &TyShape::Fun(&FLOAT, &TyShape::Fun(&FLOAT, &COLOR)));
        const FLOAT_TO_FLOAT_TO_FLOAT_TO_FLOAT_TO_COLOR: TyShape = TyShape::Fun(
            &FLOAT,
            &TyShape::Fun(&FLOAT, &TyShape::Fun(&FLOAT, &TyShape::Fun(&FLOAT, &COLOR))),
        );
        const COLOR_TO_FLOAT: TyShape = TyShape::Fun(&COLOR, &FLOAT);
        const COLOR_TO_COLOR: TyShape = TyShape::Fun(&COLOR, &COLOR);
        const COLOR_TO_COLOR_TO_COLOR: TyShape = TyShape::Fun(&COLOR, &COLOR_TO_COLOR);
        const FLOAT_TO_COLOR_TO_COLOR: TyShape = TyShape::Fun(&FLOAT, &COLOR_TO_COLOR);
        const FLOAT_TO_COLOR_TO_COLOR_TO_COLOR: TyShape =
            TyShape::Fun(&FLOAT, &COLOR_TO_COLOR_TO_COLOR);
        // ── Ipe.Color a11y / profile / parse companion-type scheme shapes. ──
        // The opaque companion carriers (`ColorError` / `TermProfile` /
        // `AnsiColor` / `WcagLevel` / `TextSize` / `Deficiency`), each a nullary
        // `Con` over its dedicated `BuiltinTag`, and the kernel arrows over them.
        const COLOR_ERROR: TyShape = TyShape::Con(BuiltinTag::ColorError, &[]);
        const TERM_PROFILE: TyShape = TyShape::Con(BuiltinTag::TermProfile, &[]);
        const ANSI_COLOR: TyShape = TyShape::Con(BuiltinTag::AnsiColor, &[]);
        const WCAG_LEVEL: TyShape = TyShape::Con(BuiltinTag::WcagLevel, &[]);
        const TEXT_SIZE: TyShape = TyShape::Con(BuiltinTag::TextSize, &[]);
        const DEFICIENCY: TyShape = TyShape::Con(BuiltinTag::Deficiency, &[]);
        // `String -> Result ColorError Color` (fromHex / fromName).
        const RESULT_COLOR_ERROR_COLOR: TyShape =
            TyShape::Con(BuiltinTag::Result, &[COLOR_ERROR, COLOR]);
        const STRING_TO_RESULT_COLOR_ERROR_COLOR: TyShape =
            TyShape::Fun(&STRING, &RESULT_COLOR_ERROR_COLOR);
        // `TermProfile -> Color -> AnsiColor` (toAnsi).
        const TERM_PROFILE_TO_COLOR_TO_ANSI: TyShape =
            TyShape::Fun(&TERM_PROFILE, &TyShape::Fun(&COLOR, &ANSI_COLOR));
        // `Color -> Color -> Float` (contrastRatio).
        const COLOR_TO_COLOR_TO_FLOAT: TyShape = TyShape::Fun(&COLOR, &COLOR_TO_FLOAT);
        // `WcagLevel -> TextSize -> Color -> Color -> Bool` (meetsWcag).
        const WCAG_LEVEL_TO_TEXT_SIZE_TO_COLOR_TO_COLOR_TO_BOOL: TyShape = TyShape::Fun(
            &WCAG_LEVEL,
            &TyShape::Fun(
                &TEXT_SIZE,
                &TyShape::Fun(&COLOR, &TyShape::Fun(&COLOR, &BOOL)),
            ),
        );
        // `Color -> List Color -> Color` (maximumContrast).
        const LIST_COLOR: TyShape = TyShape::Con(BuiltinTag::List, &[COLOR]);
        const COLOR_TO_LIST_COLOR_TO_COLOR: TyShape =
            TyShape::Fun(&COLOR, &TyShape::Fun(&LIST_COLOR, &COLOR));
        // `Deficiency -> Color -> Color` (simulate).
        const DEFICIENCY_TO_COLOR_TO_COLOR: TyShape = TyShape::Fun(&DEFICIENCY, &COLOR_TO_COLOR);
        const COLOR_TO_TUI_ATTR_A: TyShape = TyShape::Fun(&ANSI_COLOR, &TUI_ATTR_A);
        // `Lines msg` (var(0) = msg) and the Cli line-native attribute type and
        // list slots — DISTINCT from both DOM `UI_ATTR_A` and cell `TUI_ATTR_A`.
        const LINES_A: TyShape = TyShape::Con(BuiltinTag::View, &[PROGRAM_SHAPE_CLI, A]);
        const LIST_LINES_A: TyShape = TyShape::Con(BuiltinTag::List, &[LINES_A]);
        const CLI_ATTR_A: TyShape = TyShape::Con(BuiltinTag::CliAttr, &[A]);
        const LIST_CLI_ATTR_A: TyShape = TyShape::Con(BuiltinTag::List, &[CLI_ATTR_A]);
        // `String -> Lines msg` (text)
        const STRING_TO_LINES_A: TyShape = TyShape::Fun(&STRING, &LINES_A);
        // `List (Attribute msg) -> String -> Lines msg` (line)
        const STRING_TO_LINES_A_INNER: TyShape = TyShape::Fun(&STRING, &LINES_A);
        const CLI_LINE: TyShape = TyShape::Fun(&LIST_CLI_ATTR_A, &STRING_TO_LINES_A_INNER);
        // `List (Lines msg) -> Lines msg` (lines)
        const LIST_LINES_A_TO_LINES_A: TyShape = TyShape::Fun(&LIST_LINES_A, &LINES_A);
        // Line-native colour attribute builders.
        const COLOR_TO_CLI_ATTR_A: TyShape = TyShape::Fun(&ANSI_COLOR, &CLI_ATTR_A);
        // Terminal palette constructors — build the shared `AnsiColor` carrier.
        const INT_TO_INT_TO_INT_TO_ANSI_COLOR: TyShape =
            TyShape::Fun(&INT, &TyShape::Fun(&INT, &TyShape::Fun(&INT, &ANSI_COLOR)));
        const INT_TO_INT_TO_INT_TO_FLOAT_TO_ANSI_COLOR: TyShape = TyShape::Fun(
            &INT,
            &TyShape::Fun(
                &INT,
                &TyShape::Fun(&INT, &TyShape::Fun(&FLOAT, &ANSI_COLOR)),
            ),
        );

        // ── Ipe.Ui element / layout arrows. ──
        // `layout : List (Attribute msg) -> Element msg -> Html msg`.
        const UI_ELEM_A_TO_HTML_A: TyShape = TyShape::Fun(&UI_ELEM_A, &HTML_A);
        const UI_LAYOUT: TyShape = TyShape::Fun(&LIST_UI_ATTR_A, &UI_ELEM_A_TO_HTML_A);
        const UI_ELEM_A_TO_UI_ELEM_A: TyShape = TyShape::Fun(&UI_ELEM_A, &UI_ELEM_A);
        // `column / row / … : List (Attribute msg) -> List (Element msg) -> Element msg`.
        const LIST_UI_ELEM_A_TO_UI_ELEM_A: TyShape = TyShape::Fun(&LIST_UI_ELEM_A, &UI_ELEM_A);
        const UI_CONTAINER: TyShape = TyShape::Fun(&LIST_UI_ATTR_A, &LIST_UI_ELEM_A_TO_UI_ELEM_A);
        // `node : Description -> List (Attribute msg) -> List (Element msg) -> Element msg`.
        const UI_NODE: TyShape = TyShape::Fun(&DESCRIPTION, &UI_CONTAINER);
        // `taggedNode : String -> Description -> List (Attribute msg) -> List (Element msg) -> Element msg`.
        const UI_TAGGED_NODE: TyShape = TyShape::Fun(&STRING, &UI_NODE);
        // `widget : CustomElement down up -> down -> (up -> msg) -> Element msg`.
        // `msg` is the scheme's first variable `A` (so `Element msg` reuses the
        // shared `UI_ELEM_A`); `down` = `B`, `up` = `C`. The `CustomElement down up`
        // handle is the opaque JS-widget boundary; the up-callback maps a decoded
        // typed event into the app's `msg`.
        const CUSTOM_ELEMENT_B_C: TyShape = TyShape::Con(BuiltinTag::CustomElement, &[B, C]);
        const C_TO_A: TyShape = TyShape::Fun(&C, &A);
        const C_TO_A_TO_UI_ELEM_A: TyShape = TyShape::Fun(&C_TO_A, &UI_ELEM_A);
        const B_TO_C_TO_A_TO_UI_ELEM_A: TyShape = TyShape::Fun(&B, &C_TO_A_TO_UI_ELEM_A);
        const UI_WIDGET: TyShape = TyShape::Fun(&CUSTOM_ELEMENT_B_C, &B_TO_C_TO_A_TO_UI_ELEM_A);
        // `above / below / … : Element msg -> Attribute msg`.
        const UI_ELEM_A_TO_UI_ATTR_A: TyShape = TyShape::Fun(&UI_ELEM_A, &UI_ATTR_A);
        // `onClick / … : msg -> Attribute msg`.
        const A_TO_UI_ATTR_A: TyShape = TyShape::Fun(&A, &UI_ATTR_A);
        // `onInput / … : (String -> msg) -> Attribute msg` (reuses `STRING_TO_A`).
        const STRING_TO_A_TO_UI_ATTR_A: TyShape = TyShape::Fun(&STRING_TO_A, &UI_ATTR_A);
        // `onBool : (Bool -> msg) -> Attribute msg`.
        const BOOL_TO_A: TyShape = TyShape::Fun(&BOOL, &A);
        const BOOL_TO_A_TO_UI_ATTR_A: TyShape = TyShape::Fun(&BOOL_TO_A, &UI_ATTR_A);
        // `onSubmit : (formData -> msg) -> Attribute msg`, form-data var `B`
        // (reuses `B_TO_A`).
        const B_TO_A_TO_UI_ATTR_A: TyShape = TyShape::Fun(&B_TO_A, &UI_ATTR_A);
        // `text : String -> Element msg`; `html : Html msg -> Element msg`.
        const STRING_TO_UI_ELEM_A: TyShape = TyShape::Fun(&STRING, &UI_ELEM_A);
        const HTML_A_TO_UI_ELEM_A: TyShape = TyShape::Fun(&HTML_A, &UI_ELEM_A);
        // `cells : List (List Char) -> Element msg` (reuses `LIST_CHAR`).
        const LIST_LIST_CHAR: TyShape = TyShape::Con(BuiltinTag::List, &[LIST_CHAR]);
        const LIST_LIST_CHAR_TO_UI_ELEM_A: TyShape = TyShape::Fun(&LIST_LIST_CHAR, &UI_ELEM_A);

        // ── Attribute builders by argument shape. ──
        const INT_TO_UI_ATTR_A: TyShape = TyShape::Fun(&INT, &UI_ATTR_A);
        const FLOAT_TO_UI_ATTR_A: TyShape = TyShape::Fun(&FLOAT, &UI_ATTR_A);
        const LENGTH_TO_UI_ATTR_A: TyShape = TyShape::Fun(&LENGTH, &UI_ATTR_A);
        const COLOR_TO_UI_ATTR_A: TyShape = TyShape::Fun(&COLOR, &UI_ATTR_A);
        const STRING_TO_UI_ATTR_A: TyShape = TyShape::Fun(&STRING, &UI_ATTR_A);
        // `paddingXY / aspectRatioWH : Int -> Int -> Attribute msg`.
        const INT_TO_INT_TO_UI_ATTR_A: TyShape = TyShape::Fun(&INT, &INT_TO_UI_ATTR_A);
        // `htmlAttribute / style / gridTracks : String -> String -> Attribute msg`.
        const STRING_TO_UI_ATTR_A_INNER: TyShape = TyShape::Fun(&STRING, &UI_ATTR_A);
        const STRING_TO_STRING_TO_UI_ATTR_A: TyShape =
            TyShape::Fun(&STRING, &STRING_TO_UI_ATTR_A_INNER);
        // `transition : String -> Bool -> Attribute msg`.
        const BOOL_TO_UI_ATTR_A: TyShape = TyShape::Fun(&BOOL, &UI_ATTR_A);
        const STRING_TO_BOOL_TO_UI_ATTR_A: TyShape = TyShape::Fun(&STRING, &BOOL_TO_UI_ATTR_A);
        // `animate : String -> String -> String -> Bool -> Attribute msg`.
        const STRING_TO_STRING_TO_BOOL_TO_UI_ATTR_A: TyShape =
            TyShape::Fun(&STRING, &STRING_TO_BOOL_TO_UI_ATTR_A);
        const UI_ANIMATE_RAW: TyShape =
            TyShape::Fun(&STRING, &STRING_TO_STRING_TO_BOOL_TO_UI_ATTR_A);
        // `Background.linearGradient : Float -> List (Float, Color) -> Attribute msg`.
        const FLOAT_COLOR: TyShape = TyShape::Tuple(&[FLOAT, COLOR]);
        const LIST_FLOAT_COLOR: TyShape = TyShape::Con(BuiltinTag::List, &[FLOAT_COLOR]);
        const LIST_FLOAT_COLOR_TO_UI_ATTR_A: TyShape = TyShape::Fun(&LIST_FLOAT_COLOR, &UI_ATTR_A);
        const BG_LINEAR_GRADIENT: TyShape = TyShape::Fun(&FLOAT, &LIST_FLOAT_COLOR_TO_UI_ATTR_A);

        // ── breakpoint / mediaQuery : String -> List (Attribute msg)
        //    -> Element msg -> Element msg. ──
        const LIST_UI_ATTR_A_TO_UI_ELEM_A_TO_UI_ELEM_A: TyShape =
            TyShape::Fun(&LIST_UI_ATTR_A, &UI_ELEM_A_TO_UI_ELEM_A);
        const UI_BREAKPOINT: TyShape =
            TyShape::Fun(&STRING, &LIST_UI_ATTR_A_TO_UI_ELEM_A_TO_UI_ELEM_A);

        // ── PseudoClass + onPseudo. ──
        // `onPseudo : PseudoClass -> List (Attribute msg) -> Attribute msg`.
        const LIST_UI_ATTR_A_TO_UI_ATTR_A: TyShape = TyShape::Fun(&LIST_UI_ATTR_A, &UI_ATTR_A);
        const UI_ON_PSEUDO: TyShape = TyShape::Fun(&PSEUDO_CLASS, &LIST_UI_ATTR_A_TO_UI_ATTR_A);

        // ── Ipe.Html node / attribute / render arrows. ──
        // `render / toString : Html msg -> String`; `attrToString : Html.Attribute msg -> String`.
        const HTML_A_TO_STRING: TyShape = TyShape::Fun(&HTML_A, &STRING);
        const HTML_ATTR_A_TO_STRING: TyShape = TyShape::Fun(&HTML_ATTR_A, &STRING);
        // `textNode / titleNode : String -> Html msg`.
        const STRING_TO_HTML_A: TyShape = TyShape::Fun(&STRING, &HTML_A);
        // container node: `List (Html.Attribute msg) -> List (Html msg) -> Html msg`.
        const LIST_HTML_A_TO_HTML_A: TyShape = TyShape::Fun(&LIST_HTML_A, &HTML_A);
        const HTML_CONTAINER: TyShape = TyShape::Fun(&LIST_HTML_ATTR_A, &LIST_HTML_A_TO_HTML_A);
        // generic `node : String -> List (Html.Attribute msg) -> List (Html msg) -> Html msg`.
        const HTML_NODE: TyShape = TyShape::Fun(&STRING, &HTML_CONTAINER);
        // void node: `List (Html.Attribute msg) -> Html msg`.
        const LIST_HTML_ATTR_A_TO_HTML_A: TyShape = TyShape::Fun(&LIST_HTML_ATTR_A, &HTML_A);
        // `voidNode : String -> List (Html.Attribute msg) -> Html msg`.
        const STRING_TO_LIST_HTML_ATTR_A_TO_HTML_A: TyShape =
            TyShape::Fun(&STRING, &LIST_HTML_ATTR_A_TO_HTML_A);
        // `doctype : List (Html msg) -> Html msg`.
        const LIST_HTML_A_TO_HTML_A_TOP: TyShape = TyShape::Fun(&LIST_HTML_A, &HTML_A);
        // `styleNode : List (Html.Attribute msg) -> String -> Html msg`.
        const STRING_TO_HTML_A_INNER: TyShape = TyShape::Fun(&STRING, &HTML_A);
        const HTML_STYLE_NODE: TyShape = TyShape::Fun(&LIST_HTML_ATTR_A, &STRING_TO_HTML_A_INNER);
        // Html.Attributes retained primitives.
        const BOOL_TO_HTML_ATTR_A: TyShape = TyShape::Fun(&BOOL, &HTML_ATTR_A);
        // `attribute : String -> String -> Html.Attribute msg`.
        const STRING_TO_HTML_ATTR_A_INNER: TyShape = TyShape::Fun(&STRING, &HTML_ATTR_A);
        const STRING_TO_STRING_TO_HTML_ATTR_A: TyShape =
            TyShape::Fun(&STRING, &STRING_TO_HTML_ATTR_A_INNER);
        // `boolAttribute : String -> Bool -> Html.Attribute msg`.
        const STRING_TO_BOOL_TO_HTML_ATTR_A: TyShape = TyShape::Fun(&STRING, &BOOL_TO_HTML_ATTR_A);

        // ── Html.Events builders (`html_event_shape`). ──
        // Msg form: `msg -> Html.Attribute msg`.
        const A_TO_HTML_ATTR_A: TyShape = TyShape::Fun(&A, &HTML_ATTR_A);
        // String form: `(String -> msg) -> Html.Attribute msg`.
        const STRING_TO_A_TO_HTML_ATTR_A: TyShape = TyShape::Fun(&STRING_TO_A, &HTML_ATTR_A);
        // Bool form: `(Bool -> msg) -> Html.Attribute msg`.
        const BOOL_TO_A_TO_HTML_ATTR_A: TyShape = TyShape::Fun(&BOOL_TO_A, &HTML_ATTR_A);
        // Raw (onSubmit) form: `handler -> Html.Attribute msg`, handler var `B`.
        const B_TO_HTML_ATTR_A: TyShape = TyShape::Fun(&B, &HTML_ATTR_A);

        // ── Ipe.Ui.Keyed : List (Attribute msg)
        //    -> List (String, Element msg) -> Element msg. ──
        const STRING_UI_ELEM_A: TyShape = TyShape::Tuple(&[STRING, UI_ELEM_A]);
        const LIST_STRING_UI_ELEM_A: TyShape = TyShape::Con(BuiltinTag::List, &[STRING_UI_ELEM_A]);
        const LIST_STRING_UI_ELEM_A_TO_UI_ELEM_A: TyShape =
            TyShape::Fun(&LIST_STRING_UI_ELEM_A, &UI_ELEM_A);
        const KEYED_CONTAINER: TyShape =
            TyShape::Fun(&LIST_UI_ATTR_A, &LIST_STRING_UI_ELEM_A_TO_UI_ELEM_A);

        // ── Region attribute builders. ──
        const INT_TO_UI_ATTR_A_REGION: TyShape = TyShape::Fun(&INT, &UI_ATTR_A);
        const STRING_TO_UI_ATTR_A_REGION: TyShape = TyShape::Fun(&STRING, &UI_ATTR_A);

        // ── Ui.describe / Description constructors. ──
        // `describe : Description -> Attribute msg`.
        const DESCRIPTION_TO_UI_ATTR_A: TyShape = TyShape::Fun(&DESCRIPTION, &UI_ATTR_A);
        // `descHeading : Int -> Description`; `descLabel : String -> Description`.
        const INT_TO_DESCRIPTION: TyShape = TyShape::Fun(&INT, &DESCRIPTION);
        const STRING_TO_DESCRIPTION: TyShape = TyShape::Fun(&STRING, &DESCRIPTION);

        // ── Ipe.Ui.Input non-record constructors. ──
        // label*: `List (Attribute msg) -> Element msg -> Label msg`.
        const UI_ELEM_A_TO_LABEL_A: TyShape = TyShape::Fun(&UI_ELEM_A, &LABEL_A);
        const INPUT_LABEL: TyShape = TyShape::Fun(&LIST_UI_ATTR_A, &UI_ELEM_A_TO_LABEL_A);
        // `labelHidden : String -> Label msg`.
        const STRING_TO_LABEL_A: TyShape = TyShape::Fun(&STRING, &LABEL_A);
        // `placeholder : List (Attribute msg) -> Element msg -> Placeholder msg`.
        const UI_ELEM_A_TO_PLACEHOLDER_A: TyShape = TyShape::Fun(&UI_ELEM_A, &PLACEHOLDER_A);
        const INPUT_PLACEHOLDER: TyShape =
            TyShape::Fun(&LIST_UI_ATTR_A, &UI_ELEM_A_TO_PLACEHOLDER_A);
        // `option : String -> Element msg -> RadioOption msg`.
        const UI_ELEM_A_TO_RADIO_OPTION_A: TyShape = TyShape::Fun(&UI_ELEM_A, &RADIO_OPTION_A);
        const INPUT_OPTION: TyShape = TyShape::Fun(&STRING, &UI_ELEM_A_TO_RADIO_OPTION_A);

        // ── Ipe.Ui.Lazy (function reuse, arity 1..5). ──
        // `lazy : (a -> Element msg) -> a -> Element msg`, msg var `B`.
        const A_TO_UI_ELEM_B: TyShape =
            TyShape::Fun(&A, &TyShape::Con(BuiltinTag::View, &[PROGRAM_SHAPE_WEB, B]));
        const LAZY_LAZY: TyShape = TyShape::Fun(&A_TO_UI_ELEM_B, &A_TO_UI_ELEM_B);
        // `lazy2 : (a -> b -> Element msg) -> a -> b -> Element msg`, msg var `C`.
        const UI_ELEM_C: TyShape = TyShape::Con(BuiltinTag::View, &[PROGRAM_SHAPE_WEB, C]);
        const B_TO_UI_ELEM_C: TyShape = TyShape::Fun(&B, &UI_ELEM_C);
        const A_TO_B_TO_UI_ELEM_C: TyShape = TyShape::Fun(&A, &B_TO_UI_ELEM_C);
        const LAZY_LAZY2: TyShape = TyShape::Fun(&A_TO_B_TO_UI_ELEM_C, &A_TO_B_TO_UI_ELEM_C);
        // `lazy3`, msg var `D`.
        const UI_ELEM_D: TyShape = TyShape::Con(BuiltinTag::View, &[PROGRAM_SHAPE_WEB, D]);
        const C_TO_UI_ELEM_D: TyShape = TyShape::Fun(&C, &UI_ELEM_D);
        const B_TO_C_TO_UI_ELEM_D: TyShape = TyShape::Fun(&B, &C_TO_UI_ELEM_D);
        const A_TO_B_TO_C_TO_UI_ELEM_D: TyShape = TyShape::Fun(&A, &B_TO_C_TO_UI_ELEM_D);
        const LAZY_LAZY3: TyShape =
            TyShape::Fun(&A_TO_B_TO_C_TO_UI_ELEM_D, &A_TO_B_TO_C_TO_UI_ELEM_D);
        // `lazy4`, msg var `E`.
        const UI_ELEM_E: TyShape = TyShape::Con(BuiltinTag::View, &[PROGRAM_SHAPE_WEB, E]);
        const D_TO_UI_ELEM_E: TyShape = TyShape::Fun(&D, &UI_ELEM_E);
        const C_TO_D_TO_UI_ELEM_E: TyShape = TyShape::Fun(&C, &D_TO_UI_ELEM_E);
        const B_TO_C_TO_D_TO_UI_ELEM_E: TyShape = TyShape::Fun(&B, &C_TO_D_TO_UI_ELEM_E);
        const A_TO_B_TO_C_TO_D_TO_UI_ELEM_E: TyShape = TyShape::Fun(&A, &B_TO_C_TO_D_TO_UI_ELEM_E);
        const LAZY_LAZY4: TyShape = TyShape::Fun(
            &A_TO_B_TO_C_TO_D_TO_UI_ELEM_E,
            &A_TO_B_TO_C_TO_D_TO_UI_ELEM_E,
        );
        // `lazy5`, msg var `F`.
        const UI_ELEM_F: TyShape = TyShape::Con(BuiltinTag::View, &[PROGRAM_SHAPE_WEB, F]);
        const E_TO_UI_ELEM_F: TyShape = TyShape::Fun(&E, &UI_ELEM_F);
        const D_TO_E_TO_UI_ELEM_F: TyShape = TyShape::Fun(&D, &E_TO_UI_ELEM_F);
        const C_TO_D_TO_E_TO_UI_ELEM_F: TyShape = TyShape::Fun(&C, &D_TO_E_TO_UI_ELEM_F);
        const B_TO_C_TO_D_TO_E_TO_UI_ELEM_F: TyShape = TyShape::Fun(&B, &C_TO_D_TO_E_TO_UI_ELEM_F);
        const A_TO_B_TO_C_TO_D_TO_E_TO_UI_ELEM_F: TyShape =
            TyShape::Fun(&A, &B_TO_C_TO_D_TO_E_TO_UI_ELEM_F);
        const LAZY_LAZY5: TyShape = TyShape::Fun(
            &A_TO_B_TO_C_TO_D_TO_E_TO_UI_ELEM_F,
            &A_TO_B_TO_C_TO_D_TO_E_TO_UI_ELEM_F,
        );

        // ── Ui length / color builders. ──
        const INT_TO_LENGTH: TyShape = TyShape::Fun(&INT, &LENGTH);
        const LENGTH_TO_LENGTH: TyShape = TyShape::Fun(&LENGTH, &LENGTH);
        const INT_TO_LENGTH_TO_LENGTH: TyShape = TyShape::Fun(&INT, &LENGTH_TO_LENGTH);
        const INT_TO_COLOR: TyShape = TyShape::Fun(&INT, &COLOR);
        const INT_TO_INT_TO_COLOR: TyShape = TyShape::Fun(&INT, &INT_TO_COLOR);
        const UI_RGB: TyShape = TyShape::Fun(&INT, &INT_TO_INT_TO_COLOR);
        const FLOAT_TO_COLOR: TyShape = TyShape::Fun(&FLOAT, &COLOR);
        const INT_TO_FLOAT_TO_COLOR: TyShape = TyShape::Fun(&INT, &FLOAT_TO_COLOR);
        const INT_TO_INT_TO_FLOAT_TO_COLOR: TyShape = TyShape::Fun(&INT, &INT_TO_FLOAT_TO_COLOR);
        const UI_RGBA: TyShape = TyShape::Fun(&INT, &INT_TO_INT_TO_FLOAT_TO_COLOR);
        const COLOR_TO_STRING: TyShape = TyShape::Fun(&COLOR, &STRING);

        // ── ServerListen : Int -> List ServerRoute -> Task (). ──
        const LIST_SERVER_ROUTE: TyShape = TyShape::Con(BuiltinTag::List, &[SERVER_ROUTE]);
        const LIST_SERVER_ROUTE_TO_TASK_UNIT: TyShape =
            TyShape::Fun(&LIST_SERVER_ROUTE, &TASK_UNIT);
        const SERVER_LISTEN: TyShape = TyShape::Fun(&INT, &LIST_SERVER_ROUTE_TO_TASK_UNIT);

        // ── Record field-value shapes + the record nodes themselves. ──
        // The interpreter re-sorts a record's fields by resolved field symbol, so
        // fields are declared here in ascending resolved-symbol order. The `label`
        // field symbol is shared across the `Ui.button` / `Ui.link` / `Input`
        // records via `FieldTag::Label`.
        const WEB_REQ: TyShape = TyShape::Con(BuiltinTag::WebReq, &[]);
        const WEB_ROUTE_C: TyShape = TyShape::Con(BuiltinTag::WebRoute, &[C]);
        const UI_ELEM_B: TyShape = TyShape::Con(BuiltinTag::View, &[PROGRAM_SHAPE_WEB, B]);
        const LIST_LIST_STRING: TyShape = TyShape::Con(BuiltinTag::List, &[LIST_STRING]);
        const MAYBE_PLACEHOLDER_A: TyShape = TyShape::Con(BuiltinTag::Maybe, &[PLACEHOLDER_A]);
        const LIST_RADIO_OPTION_A: TyShape = TyShape::Con(BuiltinTag::List, &[RADIO_OPTION_A]);

        // Migration `{ name : String, sql : String }`.
        const MIGRATION: TyShape = TyShape::Record {
            fields: &[
                (FieldTag::MigrationName, &STRING),
                (FieldTag::MigrationSql, &STRING),
            ],
            tail: RowTailShape::Closed,
        };
        // Server `Response { body, contentType, headers, status }`.
        const SERVER_RESPONSE: TyShape = TyShape::Record {
            fields: &[
                (FieldTag::HttpBody, &STRING),
                (FieldTag::HttpHeaders, &DICT_STRING_STRING),
                (FieldTag::HttpStatus, &INT),
                (FieldTag::ServerContentType, &STRING),
            ],
            tail: RowTailShape::Closed,
        };
        // `HttpResponse { body, headers, status }`.
        const HTTP_RESPONSE: TyShape = TyShape::Record {
            fields: &[
                (FieldTag::HttpBody, &STRING),
                (FieldTag::HttpHeaders, &DICT_STRING_STRING),
                (FieldTag::HttpStatus, &INT),
            ],
            tail: RowTailShape::Closed,
        };
        const REDIRECT_POLICY: TyShape = TyShape::Con(BuiltinTag::RedirectPolicy, &[]);
        const DURATION: TyShape = TyShape::Con(BuiltinTag::Duration, &[]);
        // `HttpRequest { body, headers, method, url, timeout, redirects }`.
        // Field order matches the BTreeMap iteration order (ascending intern-symbol
        // order from the Builtins constructor): body, headers, method, url, timeout,
        // redirects — NOT alphabetical order.
        const HTTP_REQUEST: TyShape = TyShape::Record {
            fields: &[
                (FieldTag::HttpBody, &STRING),
                (FieldTag::HttpHeaders, &LIST_TUPLE_STRING_STRING),
                (FieldTag::HttpMethod, &HTTP_METHOD),
                (FieldTag::HttpUrl, &STRING),
                (FieldTag::HttpTimeout, &INT),
                (FieldTag::HttpRedirects, &REDIRECT_POLICY),
            ],
            tail: RowTailShape::Closed,
        };
        // `Csv { header : List String, rows : List (List String) }`.
        const CSV: TyShape = TyShape::Record {
            fields: &[
                (FieldTag::CsvHeader, &LIST_STRING),
                (FieldTag::CsvRows, &LIST_LIST_STRING),
            ],
            tail: RowTailShape::Closed,
        };
        // `CacheCfg { maxEntries, ttlMs, maxBytes }`.
        const CACHE_CFG: TyShape = TyShape::Record {
            fields: &[
                (FieldTag::CacheMaxEntries, &INT),
                (FieldTag::CacheTtlMs, &INT),
                (FieldTag::CacheMaxBytes, &INT),
            ],
            tail: RowTailShape::Closed,
        };
        // `CacheStats { hits, misses, evictions }`.
        const CACHE_STATS: TyShape = TyShape::Record {
            fields: &[
                (FieldTag::CacheHits, &INT),
                (FieldTag::CacheMisses, &INT),
                (FieldTag::CacheEvictions, &INT),
            ],
            tail: RowTailShape::Closed,
        };
        // `WebSocketCfg { url, headers : List (String, String), timeout,
        // pingInterval }`.
        const WS_CLIENT_CFG: TyShape = TyShape::Record {
            fields: &[
                (FieldTag::WsHeaders, &LIST_TUPLE_STRING_STRING),
                (FieldTag::WsUrl, &STRING),
                (FieldTag::WsTimeout, &INT),
                (FieldTag::WsPingInterval, &INT),
            ],
            tail: RowTailShape::Closed,
        };
        // `EmailAttachment { filename, mimeType, content : Bytes }`.
        const EMAIL_ATTACHMENT: TyShape = TyShape::Record {
            fields: &[
                (FieldTag::EmailFilename, &STRING),
                (FieldTag::EmailMimeType, &STRING),
                (FieldTag::EmailContent, &BYTES),
            ],
            tail: RowTailShape::Closed,
        };
        const LIST_EMAIL_ATTACHMENT: TyShape = TyShape::Con(BuiltinTag::List, &[EMAIL_ATTACHMENT]);
        // `EmailMessage { from, to, cc, bcc, subject, textBody, htmlBody,
        // attachments : List Attachment, replyTo }`.
        const LIST_EMAIL_ADDRESS: TyShape = TyShape::Con(BuiltinTag::List, &[EMAIL_ADDRESS]);
        const EMAIL_MESSAGE: TyShape = TyShape::Record {
            fields: &[
                (FieldTag::EmailFrom, &EMAIL_ADDRESS),
                (FieldTag::EmailTo, &LIST_EMAIL_ADDRESS),
                (FieldTag::EmailCc, &LIST_EMAIL_ADDRESS),
                (FieldTag::EmailBcc, &LIST_EMAIL_ADDRESS),
                (FieldTag::EmailSubject, &STRING),
                (FieldTag::EmailTextBody, &STRING),
                (FieldTag::EmailHtmlBody, &STRING),
                (FieldTag::EmailAttachments, &LIST_EMAIL_ATTACHMENT),
                (FieldTag::EmailReplyTo, &EMAIL_ADDRESS),
            ],
            tail: RowTailShape::Closed,
        };
        // `BackoffStrategy` — the four-constructor retry-strategy ADT.
        const BACKOFF_STRATEGY: TyShape = TyShape::Con(BuiltinTag::BackoffStrategy, &[]);
        // `RetryPolicy e { baseMs, maxAttempts, shouldRetry : e -> Bool, strategy }`.
        // `e` = var(0). `A_TO_BOOL` (`shouldRetry : a -> Bool`) is defined above.
        // Fields in alphabetical BTreeMap order: baseMs, maxAttempts, shouldRetry, strategy.
        const RETRY_POLICY: TyShape = TyShape::Record {
            fields: &[
                (FieldTag::RetryBaseMs, &INT),
                (FieldTag::RetryMaxAttempts, &INT),
                (FieldTag::RetryShouldRetry, &A_TO_BOOL),
                (FieldTag::RetryStrategy, &BACKOFF_STRATEGY),
            ],
            tail: RowTailShape::Closed,
        };
        // `RetryPolicy Error` — `Task.retryWith`'s policy fixes the error channel
        // to `Error`, so `shouldRetry : Error -> Bool`.
        const RETRY_POLICY_ERROR: TyShape = TyShape::Record {
            fields: &[
                (FieldTag::RetryBaseMs, &INT),
                (FieldTag::RetryMaxAttempts, &INT),
                (FieldTag::RetryShouldRetry, &ERROR_TO_BOOL),
                (FieldTag::RetryStrategy, &BACKOFF_STRATEGY),
            ],
            tail: RowTailShape::Closed,
        };
        // `Ui.layoutWith { wrapperAttrs, rootAttrs } : List (Attribute msg)` each.
        const LAYOUT_WITH_CFG: TyShape = TyShape::Record {
            fields: &[
                (FieldTag::LayoutWrapperAttrs, &LIST_UI_ATTR_A),
                (FieldTag::LayoutRootAttrs, &LIST_UI_ATTR_A),
            ],
            tail: RowTailShape::Closed,
        };
        // `Ui.button { onPress : Maybe msg, label : Element msg }`.
        const BUTTON_CFG: TyShape = TyShape::Record {
            fields: &[
                (FieldTag::ButtonOnPress, &MAYBE_A),
                (FieldTag::Label, &UI_ELEM_A),
            ],
            tail: RowTailShape::Closed,
        };
        // ── App-entry cfg records. var(0)=model, var(1)=msg, var(2)=page,
        // var(3)=appExt (open-row tail on Web.tea). ──
        const TUPLE_A_CMD_B: TyShape = TyShape::Tuple(&[A, CMD_B]);
        const WEB_REQ_TO_TUPLE: TyShape = TyShape::Fun(&WEB_REQ, &TUPLE_A_CMD_B);
        const UNIT_TO_TUPLE: TyShape = TyShape::Fun(&UNIT, &TUPLE_A_CMD_B);
        const A_TO_TUPLE: TyShape = TyShape::Fun(&A, &TUPLE_A_CMD_B);
        const UPDATE_FN: TyShape = TyShape::Fun(&B, &A_TO_TUPLE);
        const VIEW_ELEM_FN: TyShape = TyShape::Fun(&A, &UI_ELEM_B);
        const CELLS_B: TyShape = TyShape::Con(BuiltinTag::View, &[PROGRAM_SHAPE_TUI, B]);
        const VIEW_CELLS_FN: TyShape = TyShape::Fun(&A, &CELLS_B);
        const SUBS_FN: TyShape = TyShape::Fun(&A, &SUB_B);
        const LIST_WEB_ROUTE_C: TyShape = TyShape::Con(BuiltinTag::List, &[WEB_ROUTE_C]);
        // `Web.tea` cfg — OPEN row (var(3) absorbs optional extra fields).
        const WEB_APP_CFG: TyShape = TyShape::Record {
            fields: &[
                (FieldTag::AppInit, &WEB_REQ_TO_TUPLE),
                (FieldTag::AppUpdate, &UPDATE_FN),
                (FieldTag::AppView, &VIEW_ELEM_FN),
                (FieldTag::AppSubscriptions, &SUBS_FN),
                (FieldTag::AppRoutes, &LIST_WEB_ROUTE_C),
                (FieldTag::AppNotFound, &C),
            ],
            tail: RowTailShape::Open(3),
        };
        // `Tui.Sub.onKey : (KeyEvent -> msg) -> Sub msg` — the pinned, CLOSED
        // `KeyEvent` record the runtime's flat `(kind, value)` key event fills.
        const KEY_EVENT: TyShape = TyShape::Record {
            fields: &[
                (FieldTag::TerminalKeyKind, &STRING),
                (FieldTag::TerminalKeyValue, &STRING),
            ],
            tail: RowTailShape::Closed,
        };
        const KEY_EVENT_TO_A: TyShape = TyShape::Fun(&KEY_EVENT, &A);
        const TUI_SUB_ON_KEY: TyShape = TyShape::Fun(&KEY_EVENT_TO_A, &SUB_A);
        // `Cli.Sub.onLine : (String -> msg) -> Sub msg`.
        const CLI_SUB_ON_LINE: TyShape = TyShape::Fun(&STRING_TO_A, &SUB_A);
        // `Tui.tea` — the canonical four TEA fields, CLOSED: input arrives
        // through `subscriptions` (`Tui.Sub.onKey`), so no extra field has a
        // denotation and a stray one is refused rather than silently dropped.
        const TERMINAL_SCREEN_CFG: TyShape = TyShape::Record {
            fields: &[
                (FieldTag::AppInit, &UNIT_TO_TUPLE),
                (FieldTag::AppUpdate, &UPDATE_FN),
                (FieldTag::AppView, &VIEW_CELLS_FN),
                (FieldTag::AppSubscriptions, &SUBS_FN),
            ],
            tail: RowTailShape::Closed,
        };
        // `Cli.tea` — `view : model -> Lines msg`, the canonical four TEA
        // fields, CLOSED: line input arrives through `Cli.Sub.onLine`.
        const LINES_B: TyShape = TyShape::Con(BuiltinTag::View, &[PROGRAM_SHAPE_CLI, B]);
        const VIEW_LINES_FN: TyShape = TyShape::Fun(&A, &LINES_B);
        const TERMINAL_LINES_CFG: TyShape = TyShape::Record {
            fields: &[
                (FieldTag::AppInit, &UNIT_TO_TUPLE),
                (FieldTag::AppUpdate, &UPDATE_FN),
                (FieldTag::AppView, &VIEW_LINES_FN),
                (FieldTag::AppSubscriptions, &SUBS_FN),
            ],
            tail: RowTailShape::Closed,
        };
        // Edge record `{ top, right, bottom, left }` (Ui.paddingEach /
        // Border.widthEach).
        const EDGE: TyShape = TyShape::Record {
            fields: &[
                (FieldTag::EdgeTop, &INT),
                (FieldTag::EdgeRight, &INT),
                (FieldTag::EdgeBottom, &INT),
                (FieldTag::EdgeLeft, &INT),
            ],
            tail: RowTailShape::Closed,
        };
        // Shadow record `{ offsetX, offsetY, blur, spread, color }`
        // (Border.shadow / innerShadow).
        const SHADOW: TyShape = TyShape::Record {
            fields: &[
                (FieldTag::ShadowOffsetX, &INT),
                (FieldTag::ShadowOffsetY, &INT),
                (FieldTag::ShadowBlur, &INT),
                (FieldTag::ShadowSpread, &INT),
                (FieldTag::ShadowColor, &COLOR),
            ],
            tail: RowTailShape::Closed,
        };
        // ── Input config records. var(0) = msg. Shared `label` via
        // `FieldTag::Label`. ──
        const BOOL_TO_UI_ELEM_A: TyShape = TyShape::Fun(&BOOL, &UI_ELEM_A);
        // `Input.text` / email / … `{ onChange, text, placeholder, label }`.
        const INPUT_TEXT_CFG: TyShape = TyShape::Record {
            fields: &[
                (FieldTag::Label, &LABEL_A),
                (FieldTag::InputOnChange, &STRING_TO_A),
                (FieldTag::InputText, &STRING),
                (FieldTag::InputPlaceholder, &MAYBE_PLACEHOLDER_A),
            ],
            tail: RowTailShape::Closed,
        };
        // `Input.multiline` — adds `spellcheck : Bool`.
        const INPUT_MULTILINE_CFG: TyShape = TyShape::Record {
            fields: &[
                (FieldTag::Label, &LABEL_A),
                (FieldTag::InputOnChange, &STRING_TO_A),
                (FieldTag::InputText, &STRING),
                (FieldTag::InputPlaceholder, &MAYBE_PLACEHOLDER_A),
                (FieldTag::InputSpellcheck, &BOOL),
            ],
            tail: RowTailShape::Closed,
        };
        // `Input.checkbox` — `{ onChange : Bool -> msg, icon : Bool -> Element
        // msg, checked, label }`.
        const INPUT_CHECKBOX_CFG: TyShape = TyShape::Record {
            fields: &[
                (FieldTag::Label, &LABEL_A),
                (FieldTag::InputOnChange, &BOOL_TO_A),
                (FieldTag::InputChecked, &BOOL),
                (FieldTag::InputIcon, &BOOL_TO_UI_ELEM_A),
            ],
            tail: RowTailShape::Closed,
        };
        // `Input.slider` — `{ onChange, value, min, max, step, label }`.
        const INPUT_SLIDER_CFG: TyShape = TyShape::Record {
            fields: &[
                (FieldTag::InputValue, &STRING),
                (FieldTag::Label, &LABEL_A),
                (FieldTag::InputOnChange, &STRING_TO_A),
                (FieldTag::InputMin, &STRING),
                (FieldTag::InputMax, &STRING),
                (FieldTag::InputStep, &STRING),
            ],
            tail: RowTailShape::Closed,
        };
        // `Input.radio` / `radioRow` — `{ onChange, options, selected, label }`.
        const INPUT_RADIO_CFG: TyShape = TyShape::Record {
            fields: &[
                (FieldTag::Label, &LABEL_A),
                (FieldTag::InputOnChange, &STRING_TO_A),
                (FieldTag::InputOptions, &LIST_RADIO_OPTION_A),
                (FieldTag::InputSelected, &STRING),
            ],
            tail: RowTailShape::Closed,
        };
        // `Ui.link { url : String, label : Element msg }`.
        const LINK_CFG: TyShape = TyShape::Record {
            fields: &[(FieldTag::HttpUrl, &STRING), (FieldTag::Label, &UI_ELEM_A)],
            tail: RowTailShape::Closed,
        };
        // `Ui.image { src : String, description : String }`.
        const IMAGE_CFG: TyShape = TyShape::Record {
            fields: &[
                (FieldTag::ImageSrc, &STRING),
                (FieldTag::ImageDescription, &STRING),
            ],
            tail: RowTailShape::Closed,
        };

        // ── Whole-signature spines over the record nodes. ──
        // Migration.
        const DB_DEFAULT_MIGRATION: TyShape = TyShape::Fun(&STRING, &MIGRATION);
        const LIST_MIGRATION: TyShape = TyShape::Con(BuiltinTag::List, &[MIGRATION]);
        // `Db.migrate : Db -> List Migration -> Task (List String)`.
        const LIST_MIGRATION_TO_TASK: TyShape = TyShape::Fun(&LIST_MIGRATION, &TASK_LIST_STRING);
        const DB_MIGRATE: TyShape = TyShape::Fun(&DB, &LIST_MIGRATION_TO_TASK);
        // Http.
        const TASK_HTTP_RESPONSE: TyShape = TyShape::Con(BuiltinTag::Task, &[HTTP_RESPONSE]);
        const HTTP_GET: TyShape = TyShape::Fun(&URL, &TASK_HTTP_RESPONSE);
        const STRING_TO_TASK_HTTP_RESPONSE: TyShape = TyShape::Fun(&STRING, &TASK_HTTP_RESPONSE);
        const HTTP_POST: TyShape = TyShape::Fun(&URL, &STRING_TO_TASK_HTTP_RESPONSE);
        const HTTP_DO_REQUEST: TyShape = TyShape::Fun(&HTTP_REQUEST, &TASK_HTTP_RESPONSE);
        const RESULT_ERROR_HTTP_REQUEST: TyShape =
            TyShape::Con(BuiltinTag::Result, &[ERROR, HTTP_REQUEST]);
        const HTTP_DEFAULT_REQUEST: TyShape = TyShape::Fun(&URL, &RESULT_ERROR_HTTP_REQUEST);
        const HTTP_DEFAULT_REQUEST_FROM_STRING: TyShape =
            TyShape::Fun(&STRING, &RESULT_ERROR_HTTP_REQUEST);
        const HTTP_REQUEST_TO_HTTP_REQUEST: TyShape = TyShape::Fun(&HTTP_REQUEST, &HTTP_REQUEST);
        const HTTP_WITH_METHOD: TyShape = TyShape::Fun(&HTTP_METHOD, &HTTP_REQUEST_TO_HTTP_REQUEST);
        const HTTP_WITH_TIMEOUT: TyShape = TyShape::Fun(&DURATION, &HTTP_REQUEST_TO_HTTP_REQUEST);
        const HTTP_WITH_REDIRECTS: TyShape =
            TyShape::Fun(&REDIRECT_POLICY, &HTTP_REQUEST_TO_HTTP_REQUEST);
        const HTTP_WITH_BODY: TyShape = TyShape::Fun(&STRING, &HTTP_REQUEST_TO_HTTP_REQUEST);
        const STRING_TO_HTTP_REQUEST_TO_HTTP_REQUEST: TyShape =
            TyShape::Fun(&STRING, &HTTP_REQUEST_TO_HTTP_REQUEST);
        const HTTP_WITH_HEADER: TyShape =
            TyShape::Fun(&STRING, &STRING_TO_HTTP_REQUEST_TO_HTTP_REQUEST);
        const HTTP_REQUEST_TO_RESULT: TyShape =
            TyShape::Fun(&HTTP_REQUEST, &RESULT_ERROR_HTTP_REQUEST);
        const HTTP_WITH_URL: TyShape = TyShape::Fun(&URL, &HTTP_REQUEST_TO_RESULT);
        // Server.
        const RESP_HANDLER: TyShape = TyShape::Fun(&SERVER_REQUEST, &TASK_SERVER_RESPONSE);
        const TASK_SERVER_RESPONSE: TyShape = TyShape::Con(BuiltinTag::Task, &[SERVER_RESPONSE]);
        const HANDLER_TO_ROUTE: TyShape = TyShape::Fun(&RESP_HANDLER, &SERVER_ROUTE);
        const SERVER_ROUTE_KERNEL: TyShape = TyShape::Fun(&STRING, &HANDLER_TO_ROUTE);
        // Authed routes. `authConfig : Secret -> TokenSource -> AuthConfig`;
        // `cookieToken : String -> TokenSource`; the route kernels take a
        // two-argument handler `Request -> Principal -> Task Error Response`.
        const SECRET_TO_TOKEN_SOURCE_TO_AUTH_CONFIG: TyShape =
            TyShape::Fun(&SECRET, &TyShape::Fun(&TOKEN_SOURCE, &AUTH_CONFIG));
        const STRING_TO_TOKEN_SOURCE: TyShape = TyShape::Fun(&STRING, &TOKEN_SOURCE);
        // `withRevocation : RevocationMode -> AuthConfig -> AuthConfig` — arms the gate.
        const REVOCATION_MODE_TO_AUTH_CONFIG_TO_AUTH_CONFIG: TyShape =
            TyShape::Fun(&REVOCATION_MODE, &TyShape::Fun(&AUTH_CONFIG, &AUTH_CONFIG));
        const AUTHED_HANDLER: TyShape = TyShape::Fun(
            &SERVER_REQUEST,
            &TyShape::Fun(&PRINCIPAL, &TASK_SERVER_RESPONSE),
        );
        const AUTHED_HANDLER_TO_ROUTE: TyShape = TyShape::Fun(&AUTHED_HANDLER, &SERVER_ROUTE);
        const CONFIG_TO_HANDLER_TO_ROUTE: TyShape =
            TyShape::Fun(&AUTH_CONFIG, &AUTHED_HANDLER_TO_ROUTE);
        const SERVER_AUTHED_ROUTE_KERNEL: TyShape =
            TyShape::Fun(&STRING, &CONFIG_TO_HANDLER_TO_ROUTE);
        const STRING_TO_RESPONSE: TyShape = TyShape::Fun(&STRING, &SERVER_RESPONSE);
        const RESPONSE_TO_RESPONSE: TyShape = TyShape::Fun(&SERVER_RESPONSE, &SERVER_RESPONSE);
        const SERVER_WITH_STATUS: TyShape = TyShape::Fun(&INT, &RESPONSE_TO_RESPONSE);
        const STRING_TO_RESPONSE_TO_RESPONSE: TyShape =
            TyShape::Fun(&STRING, &RESPONSE_TO_RESPONSE);
        const SERVER_WITH_HEADER: TyShape = TyShape::Fun(&STRING, &STRING_TO_RESPONSE_TO_RESPONSE);
        // Server withCookie : Cookie -> Response -> Response.
        const SERVER_WITH_COOKIE: TyShape = TyShape::Fun(&SERVER_COOKIE, &RESPONSE_TO_RESPONSE);
        // Middleware — every wrapper is a `Handler -> Handler` transform over the
        // response handler `Request -> Task Response`, some behind leading config
        // arguments. `Handler` reuses the `RESP_HANDLER` spine.
        const MIDDLEWARE_TRANSFORM: TyShape = TyShape::Fun(&RESP_HANDLER, &RESP_HANDLER);
        // withCors : List String -> Handler -> Handler.
        const MIDDLEWARE_WITH_CORS: TyShape = TyShape::Fun(&LIST_STRING, &MIDDLEWARE_TRANSFORM);
        // withBasicAuth : String -> String -> Handler -> Handler.
        const STRING_TO_MIDDLEWARE_TRANSFORM: TyShape =
            TyShape::Fun(&STRING, &MIDDLEWARE_TRANSFORM);
        const MIDDLEWARE_WITH_BASIC_AUTH: TyShape =
            TyShape::Fun(&STRING, &STRING_TO_MIDDLEWARE_TRANSFORM);
        // withRateLimit : String -> Int -> Int -> Handler -> Handler.
        const INT_TO_MIDDLEWARE_TRANSFORM: TyShape = TyShape::Fun(&INT, &MIDDLEWARE_TRANSFORM);
        const INT_TO_INT_TO_MIDDLEWARE_TRANSFORM: TyShape =
            TyShape::Fun(&INT, &INT_TO_MIDDLEWARE_TRANSFORM);
        const MIDDLEWARE_WITH_RATE_LIMIT: TyShape =
            TyShape::Fun(&STRING, &INT_TO_INT_TO_MIDDLEWARE_TRANSFORM);
        // Stream.stream : String -> (StreamWriter -> Task ()) -> Task Response.
        const STREAM_STREAM: TyShape = TyShape::Fun(
            &STRING,
            &TyShape::Fun(&SW_TO_TASK_UNIT, &TASK_SERVER_RESPONSE),
        );
        // HttpStream.open : HttpRequest -> Task StreamId.
        const TASK_STREAM_ID: TyShape = TyShape::Con(BuiltinTag::Task, &[STREAM_ID]);
        const HTTP_STREAM_OPEN: TyShape = TyShape::Fun(&HTTP_REQUEST, &TASK_STREAM_ID);
        // Ws.upgrade : Request -> WsServerCfg -> Task Response.
        const WS_UPGRADE: TyShape = TyShape::Fun(
            &SERVER_REQUEST,
            &TyShape::Fun(&WS_SERVER_CFG, &TASK_SERVER_RESPONSE),
        );
        // Csv.
        const RESULT_ERROR_CSV: TyShape = TyShape::Con(BuiltinTag::Result, &[ERROR, CSV]);
        const CSV_PARSE: TyShape = TyShape::Fun(&STRING, &RESULT_ERROR_CSV);
        const STRING_TO_RESULT_ERROR_CSV: TyShape = TyShape::Fun(&STRING, &RESULT_ERROR_CSV);
        const CSV_PARSE_WITH_DELIMITER: TyShape =
            TyShape::Fun(&STRING, &STRING_TO_RESULT_ERROR_CSV);
        const CSV_ENCODE: TyShape = TyShape::Fun(&CSV, &STRING);
        const CSV_TO_STRING: TyShape = TyShape::Fun(&CSV, &STRING);
        const CSV_ENCODE_WITH_DELIMITER: TyShape = TyShape::Fun(&STRING, &CSV_TO_STRING);
        // Cache.
        const CACHE_NEW_RAW: TyShape = TyShape::Fun(&CACHE_CFG, &TASK_INT);
        const TASK_CACHE_STATS: TyShape = TyShape::Con(BuiltinTag::Task, &[CACHE_STATS]);
        const CACHE_STATS_KERNEL: TyShape = TyShape::Fun(&INT, &TASK_CACHE_STATS);
        // WebSocket client.
        const WS_CONNECT_WITH: TyShape = TyShape::Fun(&WS_CLIENT_CFG, &TASK_INT);
        // Email — `send : EmailProvider -> EmailMessage -> Task String`.
        const EMAIL_PROVIDER: TyShape = TyShape::Con(BuiltinTag::EmailProvider, &[]);
        const EMAIL_MESSAGE_TO_TASK: TyShape = TyShape::Fun(&EMAIL_MESSAGE, &TASK_STRING);
        const EMAIL_SEND: TyShape = TyShape::Fun(&EMAIL_PROVIDER, &EMAIL_MESSAGE_TO_TASK);
        // RetryPolicy builders.
        const RETRY_POLICY_TO_RETRY_POLICY: TyShape = TyShape::Fun(&RETRY_POLICY, &RETRY_POLICY);
        const INT_TO_RETRY_POLICY: TyShape = TyShape::Fun(&INT, &RETRY_POLICY);
        const TASK_BACKOFF: TyShape = TyShape::Fun(&INT, &INT_TO_RETRY_POLICY);
        const INT_TO_RETRY_TO_RETRY: TyShape = TyShape::Fun(&INT, &RETRY_POLICY_TO_RETRY_POLICY);
        const RETRY_ON: TyShape = TyShape::Fun(&A_TO_BOOL, &RETRY_POLICY_TO_RETRY_POLICY);
        // `retryWith : RetryPolicy Error -> Task e a -> Task e a`. var(0) = a.
        const RETRY_WITH: TyShape = TyShape::Fun(&RETRY_POLICY_ERROR, &TASK_A_TO_TASK_A);
        // App-entry whole signatures — `cfg -> Program <shape> msg`.
        // Each entry builder returns the uniform shape carrier `Program shape msg`
        // (not `Task ()`): the phantom `shape` tag distinguishes the surface at
        // inference and erases at lower to the shape's opaque app leaf; `msg`
        // (scheme var `B`, the cfg's message type) erases the same way.
        const PROGRAM_SHAPE_WEB: TyShape = TyShape::Con(BuiltinTag::ProgramShapeWeb, &[]);
        const PROGRAM_SHAPE_TUI: TyShape = TyShape::Con(BuiltinTag::ProgramShapeTui, &[]);
        const PROGRAM_SHAPE_CLI: TyShape = TyShape::Con(BuiltinTag::ProgramShapeCli, &[]);
        const PROGRAM_SHAPE_WORKER: TyShape = TyShape::Con(BuiltinTag::ProgramShapeWorker, &[]);
        const PROGRAM_WEB: TyShape = TyShape::Con(BuiltinTag::Program, &[PROGRAM_SHAPE_WEB, B]);
        const PROGRAM_TUI: TyShape = TyShape::Con(BuiltinTag::Program, &[PROGRAM_SHAPE_TUI, B]);
        const PROGRAM_CLI: TyShape = TyShape::Con(BuiltinTag::Program, &[PROGRAM_SHAPE_CLI, B]);
        const PROGRAM_WORKER: TyShape =
            TyShape::Con(BuiltinTag::Program, &[PROGRAM_SHAPE_WORKER, B]);
        // The opaque per-shape app leaf still names `Server.mountApp`'s §9 gate.
        const WEB_APP_LEAF: TyShape = TyShape::Con(BuiltinTag::WebApp, &[]);
        const WEB_APP: TyShape = TyShape::Fun(&WEB_APP_CFG, &PROGRAM_WEB);
        // `Web.embed` keeps the opaque `WebApp` leaf as its result: an embedded
        // handle is `Server.mountApp`'d, whose §9 nominal gate is `WebApp` (a
        // `Program` carrier is not a mountable handle).
        const WEB_EMBED: TyShape = TyShape::Fun(&WEB_APP_CFG, &WEB_APP_LEAF);
        // `Server.mountApp : String -> WebApp -> ServerRoute` — nominal `WebApp`
        // in the second slot is the §9 type gate: only a `Web.embed`/`Web.tea`
        // handle mounts; a `TuiApp`/`CliApp` is rejected at unify.
        const WEB_APP_LEAF_TO_SERVER_ROUTE: TyShape = TyShape::Fun(&WEB_APP_LEAF, &SERVER_ROUTE);
        const MOUNT_APP: TyShape = TyShape::Fun(&STRING, &WEB_APP_LEAF_TO_SERVER_ROUTE);
        const TERMINAL_APP_SCREEN: TyShape = TyShape::Fun(&TERMINAL_SCREEN_CFG, &PROGRAM_TUI);
        const TERMINAL_APP_LINES: TyShape = TyShape::Fun(&TERMINAL_LINES_CFG, &PROGRAM_CLI);
        // `Ipe.Tea.Worker.tea` — view-less cfg, CLOSED. `init : () -> (model, Cmd msg)`,
        // `update : msg -> model -> (model, Cmd msg)`, `subscriptions : model ->
        // Sub msg`. No `view`, no input handler; reuses the app-entry field shapes
        // (`UNIT_TO_TUPLE`/`UPDATE_FN`/`SUBS_FN`), var(0)=model, var(1)=msg.
        const WORKER_CFG: TyShape = TyShape::Record {
            fields: &[
                (FieldTag::AppInit, &UNIT_TO_TUPLE),
                (FieldTag::AppUpdate, &UPDATE_FN),
                (FieldTag::AppSubscriptions, &SUBS_FN),
            ],
            tail: RowTailShape::Closed,
        };
        const WORKER_APP: TyShape = TyShape::Fun(&WORKER_CFG, &PROGRAM_WORKER);
        // Ui builders taking a record.
        const LAYOUT_WITH: TyShape = {
            const HTML_A_INNER: TyShape = TyShape::Con(BuiltinTag::Html, &[A]);
            const ELEM_TO_HTML: TyShape = TyShape::Fun(&UI_ELEM_A, &HTML_A_INNER);
            TyShape::Fun(&LAYOUT_WITH_CFG, &ELEM_TO_HTML)
        };
        const BUTTON: TyShape = {
            const CFG_TO_ELEM: TyShape = TyShape::Fun(&BUTTON_CFG, &UI_ELEM_A);
            TyShape::Fun(&LIST_UI_ATTR_A, &CFG_TO_ELEM)
        };
        const PADDING_EACH: TyShape = TyShape::Fun(&EDGE, &UI_ATTR_A);
        const WIDTH_EACH: TyShape = TyShape::Fun(&EDGE, &UI_ATTR_A);
        const SHADOW_ATTR: TyShape = TyShape::Fun(&SHADOW, &UI_ATTR_A);
        const LINK: TyShape = {
            const CFG_TO_ELEM: TyShape = TyShape::Fun(&LINK_CFG, &UI_ELEM_A);
            TyShape::Fun(&LIST_UI_ATTR_A, &CFG_TO_ELEM)
        };
        const IMAGE: TyShape = {
            const CFG_TO_ELEM: TyShape = TyShape::Fun(&IMAGE_CFG, &UI_ELEM_A);
            TyShape::Fun(&LIST_UI_ATTR_A, &CFG_TO_ELEM)
        };
        // Input builders — `List (Attribute msg) -> cfg -> Element msg`.
        const INPUT_TEXT: TyShape = {
            const CFG_TO_ELEM: TyShape = TyShape::Fun(&INPUT_TEXT_CFG, &UI_ELEM_A);
            TyShape::Fun(&LIST_UI_ATTR_A, &CFG_TO_ELEM)
        };
        const INPUT_MULTILINE: TyShape = {
            const CFG_TO_ELEM: TyShape = TyShape::Fun(&INPUT_MULTILINE_CFG, &UI_ELEM_A);
            TyShape::Fun(&LIST_UI_ATTR_A, &CFG_TO_ELEM)
        };
        const INPUT_CHECKBOX: TyShape = {
            const CFG_TO_ELEM: TyShape = TyShape::Fun(&INPUT_CHECKBOX_CFG, &UI_ELEM_A);
            TyShape::Fun(&LIST_UI_ATTR_A, &CFG_TO_ELEM)
        };
        const INPUT_SLIDER: TyShape = {
            const CFG_TO_ELEM: TyShape = TyShape::Fun(&INPUT_SLIDER_CFG, &UI_ELEM_A);
            TyShape::Fun(&LIST_UI_ATTR_A, &CFG_TO_ELEM)
        };
        const INPUT_RADIO: TyShape = {
            const CFG_TO_ELEM: TyShape = TyShape::Fun(&INPUT_RADIO_CFG, &UI_ELEM_A);
            TyShape::Fun(&LIST_UI_ATTR_A, &CFG_TO_ELEM)
        };

        // ── Ipe.Decimal / Ipe.Money value shapes. ──
        const RESULT_ERR_DECIMAL: TyShape = TyShape::Con(BuiltinTag::Result, &[ERROR, DECIMAL]);
        const RESULT_ERR_UNIT: TyShape = TyShape::Con(BuiltinTag::Result, &[ERROR, UNIT]);
        const LIST_DECIMAL: TyShape = TyShape::Con(BuiltinTag::List, &[DECIMAL]);
        const INT_TO_DECIMAL: TyShape = TyShape::Fun(&INT, &DECIMAL);
        const FLOAT_TO_DECIMAL: TyShape = TyShape::Fun(&FLOAT, &DECIMAL);
        const STRING_TO_RESULT_ERR_DECIMAL: TyShape = TyShape::Fun(&STRING, &RESULT_ERR_DECIMAL);
        const INT_TO_INT_TO_DECIMAL: TyShape = TyShape::Fun(&INT, &INT_TO_DECIMAL);
        const DECIMAL_TO_STRING: TyShape = TyShape::Fun(&DECIMAL, &STRING);
        const DECIMAL_TO_FLOAT: TyShape = TyShape::Fun(&DECIMAL, &FLOAT);
        const DECIMAL_TO_INT: TyShape = TyShape::Fun(&DECIMAL, &INT);
        const DECIMAL_TO_BOOL: TyShape = TyShape::Fun(&DECIMAL, &BOOL);
        const DECIMAL_TO_DECIMAL: TyShape = TyShape::Fun(&DECIMAL, &DECIMAL);
        const INT_TO_DECIMAL_TO_STRING: TyShape = TyShape::Fun(&INT, &DECIMAL_TO_STRING);
        const INT_TO_DECIMAL_TO_INT: TyShape = TyShape::Fun(&INT, &DECIMAL_TO_INT);
        const DECIMAL_TO_DECIMAL_TO_DECIMAL: TyShape = TyShape::Fun(&DECIMAL, &DECIMAL_TO_DECIMAL);
        const DECIMAL_TO_DECIMAL_TO_INT: TyShape = TyShape::Fun(&DECIMAL, &DECIMAL_TO_INT);
        const DECIMAL_TO_DECIMAL_TO_BOOL: TyShape = TyShape::Fun(&DECIMAL, &DECIMAL_TO_BOOL);
        const DECIMAL_TO_RESULT_ERR_DECIMAL: TyShape = TyShape::Fun(&DECIMAL, &RESULT_ERR_DECIMAL);
        const DECIMAL_TO_DECIMAL_TO_RESULT_ERR_DECIMAL: TyShape =
            TyShape::Fun(&DECIMAL, &DECIMAL_TO_RESULT_ERR_DECIMAL);
        const INT_TO_DECIMAL_TO_DECIMAL: TyShape = TyShape::Fun(&INT, &DECIMAL_TO_DECIMAL);
        // `Decimal.formatWith : String -> String -> Int -> Decimal -> String`.
        const STRING_TO_STRING_TO_INT_TO_DECIMAL_TO_STRING: TyShape = {
            const TAIL: TyShape = TyShape::Fun(&STRING, &INT_TO_DECIMAL_TO_STRING);
            TyShape::Fun(&STRING, &TAIL)
        };
        // `Money.format / formatWithCode : String -> Decimal -> String`.
        const STRING_TO_DECIMAL_TO_STRING: TyShape = TyShape::Fun(&STRING, &DECIMAL_TO_STRING);
        // `Money.allocate : Int -> Int -> Decimal -> List Decimal`.
        const DECIMAL_TO_LIST_DECIMAL: TyShape = TyShape::Fun(&DECIMAL, &LIST_DECIMAL);
        const INT_TO_DECIMAL_TO_LIST_DECIMAL: TyShape =
            TyShape::Fun(&INT, &DECIMAL_TO_LIST_DECIMAL);
        const MONEY_ALLOCATE: TyShape = TyShape::Fun(&INT, &INT_TO_DECIMAL_TO_LIST_DECIMAL);
        // `Money.setRate : String -> String -> Decimal -> Result Error ()`.
        const DECIMAL_TO_RESULT_ERR_UNIT: TyShape = TyShape::Fun(&DECIMAL, &RESULT_ERR_UNIT);
        const STRING_TO_DECIMAL_TO_RESULT_ERR_UNIT: TyShape =
            TyShape::Fun(&STRING, &DECIMAL_TO_RESULT_ERR_UNIT);
        const MONEY_SET_RATE: TyShape =
            TyShape::Fun(&STRING, &STRING_TO_DECIMAL_TO_RESULT_ERR_UNIT);
        // `Money.getRate : String -> String -> Result Error Decimal`.
        const STRING_TO_RESULT_ERR_DECIMAL_MONEY: TyShape =
            TyShape::Fun(&STRING, &RESULT_ERR_DECIMAL);
        const MONEY_GET_RATE: TyShape = TyShape::Fun(&STRING, &STRING_TO_RESULT_ERR_DECIMAL_MONEY);
        // `Money.clearRates : () -> Result Error ()`.
        const UNIT_TO_RESULT_ERR_UNIT: TyShape = TyShape::Fun(&UNIT, &RESULT_ERR_UNIT);

        // ── Ipe.App runtime-config front door / Ipe.Web settings. ──
        const SETTING_A: TyShape = TyShape::Con(BuiltinTag::Setting, &[A]);
        const SHAPE_WEB_TAG: TyShape = TyShape::Con(BuiltinTag::ShapeWeb, &[]);
        const SETTING_WEB: TyShape = TyShape::Con(BuiltinTag::Setting, &[SHAPE_WEB_TAG]);
        const HOST_MODE_TO_SETTING_A: TyShape = TyShape::Fun(&HOST_MODE, &SETTING_A);
        const LOG_LEVEL_TO_SETTING_A: TyShape = TyShape::Fun(&LOG_LEVEL, &SETTING_A);
        const SECRET_TO_SETTING_A: TyShape = TyShape::Fun(&SECRET, &SETTING_A);
        const CSRF_MODE_TO_SETTING_WEB: TyShape = TyShape::Fun(&CSRF_MODE, &SETTING_WEB);
        const INT_TO_SETTING_WEB: TyShape = TyShape::Fun(&INT, &SETTING_WEB);
        const REVOCATION_MODE_TO_SETTING_WEB: TyShape =
            TyShape::Fun(&REVOCATION_MODE, &SETTING_WEB);
        // `Web.appWith : List (Setting Web) -> WEB_APP_CFG -> Program Web msg`.
        const LIST_SETTING_WEB: TyShape = TyShape::Con(BuiltinTag::List, &[SETTING_WEB]);
        const WEB_APP_WITH: TyShape = {
            const CFG_TO_PROGRAM: TyShape = TyShape::Fun(&WEB_APP_CFG, &PROGRAM_WEB);
            TyShape::Fun(&LIST_SETTING_WEB, &CFG_TO_PROGRAM)
        };
        // `Web.route : String -> builder -> WebRoute page` (builder = B, page = A).
        const WEB_ROUTE_A: TyShape = TyShape::Con(BuiltinTag::WebRoute, &[A]);
        const B_TO_WEB_ROUTE_A: TyShape = TyShape::Fun(&B, &WEB_ROUTE_A);
        const WEB_ROUTE_KERNEL: TyShape = TyShape::Fun(&STRING, &B_TO_WEB_ROUTE_A);
        // `Web.renderStatic : (a -> Html b) -> a -> Task ()`.
        const HTML_B: TyShape = TyShape::Con(BuiltinTag::Html, &[B]);
        const A_TO_HTML_B: TyShape = TyShape::Fun(&A, &HTML_B);
        const A_TO_TASK_UNIT: TyShape = TyShape::Fun(&A, &TASK_UNIT);
        const WEB_RENDER_STATIC: TyShape = TyShape::Fun(&A_TO_HTML_B, &A_TO_TASK_UNIT);

        // ── Ipe.Cache (the raw-Int-handle read/write kernels). ──
        const TASK_MAYBE_B: TyShape = TyShape::Con(BuiltinTag::Task, &[MAYBE_B]);
        const A_TO_TASK_MAYBE_B: TyShape = TyShape::Fun(&A, &TASK_MAYBE_B);
        const CACHE_GET: TyShape = TyShape::Fun(&INT, &A_TO_TASK_MAYBE_B);
        const B_TO_TASK_UNIT: TyShape = TyShape::Fun(&B, &TASK_UNIT);
        const A_TO_B_TO_TASK_UNIT: TyShape = TyShape::Fun(&A, &B_TO_TASK_UNIT);
        const CACHE_PUT: TyShape = TyShape::Fun(&INT, &A_TO_B_TO_TASK_UNIT);
        const INT_TO_A_TO_TASK_UNIT: TyShape = TyShape::Fun(&INT, &A_TO_TASK_UNIT);
        const CACHE_REMOVE: TyShape = INT_TO_A_TO_TASK_UNIT;
        const CACHE_CLEAR: TyShape = TyShape::Fun(&INT, &TASK_UNIT);
        const CACHE_SIZE: TyShape = TyShape::Fun(&INT, &TASK_INT);

        // ── Ipe.Secret.use : Secret -> (String -> a) -> a. ──
        // The callback `(String -> a)` sits in ARGUMENT position, distinct from
        // the existing `STRING_TO_A_TO_A` (`String -> a -> a`).
        const STRING_TO_A_ARROW_TO_A: TyShape = TyShape::Fun(&STRING_TO_A, &A);
        const SECRET_USE: TyShape = TyShape::Fun(&SECRET, &STRING_TO_A_ARROW_TO_A);

        // ── Ipe.Csv.parseStreamFromFile : Path -> Task (List (List String)). ──
        const LIST_LIST_STRING_CSV: TyShape = TyShape::Con(BuiltinTag::List, &[LIST_STRING]);
        const TASK_LIST_LIST_STRING: TyShape =
            TyShape::Con(BuiltinTag::Task, &[LIST_LIST_STRING_CSV]);
        const CSV_PARSE_STREAM_FROM_FILE: TyShape = TyShape::Fun(&PATH, &TASK_LIST_LIST_STRING);

        // ── Border.glow : Int -> Color -> Attribute msg. ──
        const BORDER_GLOW: TyShape = TyShape::Fun(&INT, &COLOR_TO_UI_ATTR_A);

        // ── Ipe.Db.Store query-algebra shapes. ──
        // ADT applications over the store home (interpreted via `builtin_con_module`).
        const STORE_A: TyShape = TyShape::Con(BuiltinTag::DbStore, &[A]);
        const STORE_B: TyShape = TyShape::Con(BuiltinTag::DbStore, &[B]);
        const DRAFT_A: TyShape = TyShape::Con(BuiltinTag::DbDraft, &[A]);
        const JOINED_A_B: TyShape = TyShape::Con(BuiltinTag::DbJoined, &[A, B]);
        const SELECT_C: TyShape = TyShape::Con(BuiltinTag::DbSelect, &[C]);
        const POLICY_A: TyShape = TyShape::Con(BuiltinTag::DbPolicy, &[A]);
        const COND_A: TyShape = TyShape::Con(BuiltinTag::DbCond, &[A]);
        const CODEC_B: TyShape = TyShape::Con(BuiltinTag::Codec, &[B]);
        const DB_ORDER: TyShape = TyShape::Con(BuiltinTag::DbOrder, &[]);
        // `join : Store a -> (a -> k) -> Store b -> (b -> k) -> Joined a b`
        // (k = var(2) = C).
        const STORE_JOIN: TyShape = {
            const A_TO_C: TyShape = TyShape::Fun(&A, &C);
            const B_TO_C: TyShape = TyShape::Fun(&B, &C);
            const B_TO_C_TO_JOINED: TyShape = TyShape::Fun(&B_TO_C, &JOINED_A_B);
            const STORE_B_TO_REST: TyShape = TyShape::Fun(&STORE_B, &B_TO_C_TO_JOINED);
            const A_TO_C_TO_REST: TyShape = TyShape::Fun(&A_TO_C, &STORE_B_TO_REST);
            TyShape::Fun(&STORE_A, &A_TO_C_TO_REST)
        };
        // `select : ((a, b) -> row) -> Joined a b -> Select row` (row = var(2) = C).
        const STORE_SELECT: TyShape = {
            const TUPLE_A_B: TyShape = TyShape::Tuple(&[A, B]);
            const TUPLE_TO_C: TyShape = TyShape::Fun(&TUPLE_A_B, &C);
            const JOINED_TO_SELECT: TyShape = TyShape::Fun(&JOINED_A_B, &SELECT_C);
            TyShape::Fun(&TUPLE_TO_C, &JOINED_TO_SELECT)
        };
        // `literal : t -> t` (t = var(0)).
        const A_TO_A_IDENT: TyShape = TyShape::Fun(&A, &A);
        // `upper / lower : String -> String` — reuse STRING_TO_STRING.
        // `coalesce / add / sub / mul : a -> a -> a` (a = var(0)).
        const A_TO_A_TO_A_STORE: TyShape = {
            const TAIL: TyShape = TyShape::Fun(&A, &A);
            TyShape::Fun(&A, &TAIL)
        };
        // Accessor query leaf: `(row -> t) -> t -> Cond row`
        // (row = var(0), t = var(1)).
        const A_TO_B_GETTER: TyShape = TyShape::Fun(&A, &B);
        const B_TO_COND_A: TyShape = TyShape::Fun(&B, &COND_A);
        const STORE_EQ_COL: TyShape = TyShape::Fun(&A_TO_B_GETTER, &B_TO_COND_A);
        // `*By : Codec t -> (row -> t) -> t -> Cond row`.
        const STORE_EQ_BY: TyShape = TyShape::Fun(&CODEC_B, &STORE_EQ_COL);
        // `like : (row -> String) -> String -> Cond row`.
        const A_TO_STRING_GETTER: TyShape = TyShape::Fun(&A, &STRING);
        const STRING_TO_COND_A: TyShape = TyShape::Fun(&STRING, &COND_A);
        const STORE_LIKE: TyShape = TyShape::Fun(&A_TO_STRING_GETTER, &STRING_TO_COND_A);
        // `isNull / notNull : (row -> t) -> Cond row`.
        const STORE_IS_NULL: TyShape = TyShape::Fun(&A_TO_B_GETTER, &COND_A);
        // `inList : (row -> t) -> List t -> Cond row`.
        const LIST_B_TO_COND_A: TyShape = {
            const LIST_B_INNER: TyShape = TyShape::Con(BuiltinTag::List, &[B]);
            TyShape::Fun(&LIST_B_INNER, &COND_A)
        };
        const STORE_IN_LIST_COL: TyShape = TyShape::Fun(&A_TO_B_GETTER, &LIST_B_TO_COND_A);
        // `inListBy : Codec t -> (row -> t) -> List t -> Cond row`.
        const STORE_IN_LIST_BY: TyShape = TyShape::Fun(&CODEC_B, &STORE_IN_LIST_COL);
        // Schema builders: `(row -> t) -> Draft row -> Draft row`.
        const DRAFT_A_TO_DRAFT_A: TyShape = TyShape::Fun(&DRAFT_A, &DRAFT_A);
        const STORE_SCHEMA_BUILDER: TyShape = TyShape::Fun(&A_TO_B_GETTER, &DRAFT_A_TO_DRAFT_A);
        // `defaultText : (row -> String) -> String -> Draft row -> Draft row`.
        const STRING_TO_DRAFT_A_TO_DRAFT_A: TyShape = TyShape::Fun(&STRING, &DRAFT_A_TO_DRAFT_A);
        const STORE_DEFAULT_TEXT: TyShape =
            TyShape::Fun(&A_TO_STRING_GETTER, &STRING_TO_DRAFT_A_TO_DRAFT_A);
        // `defaultInt : (row -> Int) -> Int -> Draft row -> Draft row`.
        const A_TO_INT_GETTER: TyShape = TyShape::Fun(&A, &INT);
        const INT_TO_DRAFT_A_TO_DRAFT_A: TyShape = TyShape::Fun(&INT, &DRAFT_A_TO_DRAFT_A);
        const STORE_DEFAULT_INT: TyShape =
            TyShape::Fun(&A_TO_INT_GETTER, &INT_TO_DRAFT_A_TO_DRAFT_A);
        // `compositePrimaryKey2 : (row -> a) -> (row -> b) -> Draft row -> Draft row`
        // (row = var(0); each key column keeps its own field type).
        const A_TO_C_GETTER: TyShape = TyShape::Fun(&A, &C);
        const A_TO_D_GETTER: TyShape = TyShape::Fun(&A, &D);
        const STORE_COMPOSITE_PK2_TAIL: TyShape = TyShape::Fun(&A_TO_C_GETTER, &DRAFT_A_TO_DRAFT_A);
        const STORE_COMPOSITE_PK2: TyShape =
            TyShape::Fun(&A_TO_B_GETTER, &STORE_COMPOSITE_PK2_TAIL);
        // `compositePrimaryKey3 : (row -> a) -> (row -> b) -> (row -> c) -> Draft row -> Draft row`.
        const STORE_COMPOSITE_PK3_TAIL: TyShape = {
            const D_TAIL: TyShape = TyShape::Fun(&A_TO_D_GETTER, &DRAFT_A_TO_DRAFT_A);
            TyShape::Fun(&A_TO_C_GETTER, &D_TAIL)
        };
        const STORE_COMPOSITE_PK3: TyShape =
            TyShape::Fun(&A_TO_B_GETTER, &STORE_COMPOSITE_PK3_TAIL);
        // Policy builders: `(row -> t) -> Policy row`.
        const STORE_POLICY_BUILDER: TyShape = TyShape::Fun(&A_TO_B_GETTER, &POLICY_A);
        // Correlated-subquery row-security ADTs (phantom in the row type).
        const PRED_A: TyShape = TyShape::Con(BuiltinTag::DbPred, &[A]);
        // `mask : (row -> t) -> Pred row -> Policy row -> Policy row` (row = A,
        // t = B). The accessor names the masked column; the `Pred row` is the
        // authorization predicate; the policy is refined with the masked column.
        const STORE_MASK: TyShape = {
            const POLICY_A_TO_POLICY_A: TyShape = TyShape::Fun(&POLICY_A, &POLICY_A);
            const PRED_A_TO_POLICY_A_TO_POLICY_A: TyShape =
                TyShape::Fun(&PRED_A, &POLICY_A_TO_POLICY_A);
            TyShape::Fun(&A_TO_B_GETTER, &PRED_A_TO_POLICY_A_TO_POLICY_A)
        };
        const PRED_B: TyShape = TyShape::Con(BuiltinTag::DbPred, &[B]);
        const SECURED_A: TyShape = TyShape::Con(BuiltinTag::DbSecured, &[A]);
        // `correlate : t -> t -> Pred share` (t = var(0) = A, share = var(1) = B).
        // Both arguments are column VALUES read directly at the call site
        // (`correlate share.docRef doc.author`), sharing one column type `t` so a
        // share-side column and an outer-side column of unequal type cannot be
        // equated. The lowering intercept reads each argument structurally as a
        // `.field` access on its binder; `existsIn` ties this `Pred share` result
        // to its lambda's share binder.
        const STORE_CORRELATE: TyShape = {
            const T_TO_PRED_SHARE: TyShape = TyShape::Fun(&A, &PRED_B);
            TyShape::Fun(&A, &T_TO_PRED_SHARE)
        };
        // `existsIn : Secured share -> (share -> row -> Pred share) -> Pred row`
        // (share = var(0) = A, row = var(1) = B).
        const STORE_EXISTS_IN: TyShape = {
            const ROW_TO_PRED_SHARE: TyShape = TyShape::Fun(&B, &PRED_A);
            const SHARE_TO_ROW_TO_PRED_SHARE: TyShape = TyShape::Fun(&A, &ROW_TO_PRED_SHARE);
            const LAMBDA_TO_PRED_ROW: TyShape = TyShape::Fun(&SHARE_TO_ROW_TO_PRED_SHARE, &PRED_B);
            TyShape::Fun(&SECURED_A, &LAMBDA_TO_PRED_ROW)
        };
        // `orderByLeft : (a -> k) -> Order -> Joined a b -> Joined a b` (k = var(2)).
        const JOINED_TO_JOINED: TyShape = TyShape::Fun(&JOINED_A_B, &JOINED_A_B);
        const ORDER_TO_JOINED_TO_JOINED: TyShape = TyShape::Fun(&DB_ORDER, &JOINED_TO_JOINED);
        const STORE_ORDER_BY_LEFT: TyShape = {
            const A_TO_C: TyShape = TyShape::Fun(&A, &C);
            TyShape::Fun(&A_TO_C, &ORDER_TO_JOINED_TO_JOINED)
        };
        const STORE_ORDER_BY_RIGHT: TyShape = {
            const B_TO_C: TyShape = TyShape::Fun(&B, &C);
            TyShape::Fun(&B_TO_C, &ORDER_TO_JOINED_TO_JOINED)
        };

        match self {
            // ── Bitwise — Int -> Int -> Int / Int -> Int. ──
            Self::BitwiseAnd
            | Self::BitwiseOr
            | Self::BitwiseXor
            | Self::BitwiseShiftLeftBy
            | Self::BitwiseShiftRightBy
            | Self::BitwiseShiftRightZfBy => Some(&INT_TO_INT_TO_INT),
            Self::BitwiseComplement | Self::MathAbs => Some(&INT_TO_INT),

            // ── Math (the fully-monomorphic arms; min/max stay on the
            //    obligation path and carry no shape). ──
            Self::MathPi
            | Self::MathE
            | Self::MathPhi
            | Self::MathSqrt2
            | Self::MathInf
            | Self::MathNan => Some(&FLOAT),
            Self::MathIsNaN => Some(&FLOAT_TO_BOOL),
            Self::MathSqrt
            | Self::MathCbrt
            | Self::MathExp
            | Self::MathExp2
            | Self::MathLog
            | Self::MathLog2
            | Self::MathLog10
            | Self::MathSin
            | Self::MathCos
            | Self::MathTan
            | Self::MathAsin
            | Self::MathAcos
            | Self::MathAtan
            | Self::MathSinh
            | Self::MathCosh
            | Self::MathTanh
            | Self::MathAsinh
            | Self::MathAcosh
            | Self::MathAtanh
            | Self::BasicsSqrt => Some(&FLOAT_TO_FLOAT),
            Self::MathFloor | Self::MathCeil | Self::MathRound | Self::MathTrunc => {
                Some(&FLOAT_TO_INT)
            }
            Self::MathPow
            | Self::MathHypot
            | Self::MathAtan2
            | Self::MathMod
            | Self::MathRemainder => Some(&FLOAT_TO_FLOAT_TO_FLOAT),

            // ── Basics (monomorphic arms). ──
            Self::BasicsNot => Some(&BOOL_TO_BOOL),

            // ── String → String / String → Int / String → Bool primitive kernels. ──
            Self::StringFromInt | Self::TimeTimeString => Some(&INT_TO_STRING),
            Self::StringFromFloat => Some(&FLOAT_TO_STRING),
            // `Money.minorUnits : String -> Int` (the code-taking kernel).
            Self::StringLength | Self::MoneyMinorUnits => Some(&STRING_TO_INT),
            Self::StringIsEmpty
            | Self::StringIsEmail
            | Self::StringIsUrl
            | Self::MoneyIsKnownCurrency => Some(&STRING_TO_BOOL),
            Self::StringReverse
            | Self::StringToUpper
            | Self::StringToLower
            | Self::StringCasefold
            | Self::StringTrim
            | Self::StringTrimStart
            | Self::StringTrimEnd
            | Self::CryptoSha256
            | Self::CryptoSha512
            | Self::CryptoSha1
            | Self::CryptoMd5
            | Self::EncodingBase64Encode
            | Self::EncodingUrlEncode
            | Self::EncodingHexEncode
            | Self::HtmlEscapeText
            | Self::HtmlEscapeAttr
            | Self::CssSafetyStripStyleClose
            | Self::MoneySymbol
            | Self::MoneyCurrencyName => Some(&STRING_TO_STRING),
            Self::StringFromChar | Self::CharToLower | Self::CharToUpper => Some(&CHAR_TO_STRING),
            Self::StringFromBool => Some(&BOOL_TO_STRING),
            Self::StringAppend | Self::SystemGetenvOr => Some(&STRING_TO_STRING_TO_STRING),
            Self::StringContains
            | Self::StringStartsWith
            | Self::StringEndsWith
            | Self::StringEqualFold
            | Self::StringContainsIn
            | Self::StringStartsWithIn
            | Self::StringEndsWithIn
            | Self::CryptoConstantTimeEqual
            | Self::MoneyHasRate => Some(&STRING_TO_STRING_TO_BOOL),
            Self::StringReplace => Some(&STRING_TO_STRING_TO_STRING_TO_STRING),
            Self::CryptoRsaSha256Verify => Some(&STRING_TO_STRING_TO_STRING_TO_BOOL),
            Self::StringRepeat
            | Self::StringDropLeft
            | Self::StringDropRight
            | Self::StringLeft
            | Self::StringRight => Some(&INT_TO_STRING_TO_STRING),
            Self::StringSlice => Some(&INT_TO_INT_TO_STRING_TO_STRING),
            Self::StringPadLeft | Self::StringPadRight | Self::StringPad => {
                Some(&INT_TO_CHAR_TO_STRING_TO_STRING)
            }
            Self::StringCons => Some(&CHAR_TO_STRING_TO_STRING),
            Self::StringMap => Some(&CHAR_TO_CHAR_ARROW),
            Self::StringFilter => Some(&CHAR_TO_BOOL_TO_STRING_STRING),
            Self::StringAny | Self::StringAll => Some(&CHAR_TO_BOOL_TO_STRING_BOOL),

            // ── Char primitive kernels. ──
            Self::CharIsAlpha
            | Self::CharIsDigit
            | Self::CharIsLower
            | Self::CharIsUpper
            | Self::CharIsAlphaNum
            | Self::CharIsHexDigit
            | Self::CharIsOctDigit => Some(&CHAR_TO_BOOL),
            Self::CharToCode => Some(&CHAR_TO_INT),
            Self::CharFromCode => Some(&INT_TO_CHAR),

            // ── Bytes primitive kernels. ──
            Self::BytesEmpty => Some(&BYTES),
            Self::BytesLength => Some(&BYTES_TO_INT),
            Self::BytesIsEmpty => Some(&BYTES_TO_BOOL),
            Self::BytesFromString => Some(&STRING_TO_BYTES),
            Self::BytesToHex | Self::BytesToBase64 => Some(&BYTES_TO_STRING),
            Self::BytesAppend => Some(&BYTES_TO_BYTES_TO_BYTES),
            Self::BytesSlice => Some(&INT_TO_INT_TO_BYTES_TO_BYTES),

            // ── Time (pure calendar kernels — no Task wrap). ──
            Self::TimeIsLeapYear => Some(&INT_TO_BOOL),
            Self::TimeDaysInMonth | Self::TimeAddMillis | Self::TimeDiffMillis => {
                Some(&INT_TO_INT_TO_INT)
            }
            Self::TimeFormatHTTP | Self::TimeFormatISO8601 | Self::TimeFormatRFC3339 => {
                Some(&INT_TO_STRING)
            }
            Self::TimeFormat => Some(&STRING_TO_INT_TO_STRING),

            // ── RateLimit / string-constant kernels. ──
            Self::RateLimitAllow => Some(&STRING_TO_STRING_TO_INT_TO_INT_TO_BOOL),
            Self::FontSansSerif
            | Self::FontSerif
            | Self::FontMonospace
            | Self::UiMobile
            | Self::UiTablet
            | Self::UiDesktop
            | Self::UiDarkMode
            | Self::UiLightMode
            | Self::UiReducedMotion => Some(&STRING),

            // ── Core `List` combinators (rank-1 polymorphic). The pair-shaped
            //    members (`zip`/`unzip`/`partition`) carry a tuple shape; the
            //    arrow-only `map2`..`map5`/`indexedMap` still carry no shape.
            //    The obligation-bearing base schemes
            //    (`sort*`/`sum`/`product`/`maximum`/`minimum`) DO carry a shape —
            //    the obligation is layered separately in `constrain_var_kernel`,
            //    so the shape is exercised only by the totality / oracle
            //    tripwires, never in production. ──
            Self::ListZip => Some(&LIST_ZIP),
            Self::ListUnzip => Some(&LIST_UNZIP),
            Self::ListPartition => Some(&LIST_PARTITION),
            Self::ListMap => Some(&LIST_MAP),
            Self::ListFilter => Some(&LIST_FILTER),
            Self::ListAny | Self::ListAll => Some(&LIST_ANY),
            Self::ListFind => Some(&LIST_FIND),
            Self::ListLength => Some(&LIST_LENGTH),
            Self::ListIsEmpty => Some(&LIST_A_TO_BOOL),
            Self::ListHead => Some(&LIST_A_TO_MAYBE_A),
            Self::ListTail => Some(&LIST_TAIL),
            Self::ListMember => Some(&LIST_MEMBER),
            Self::ListCons | Self::ListIntersperse => Some(&LIST_CONS),
            Self::ListRange => Some(&LIST_RANGE),
            Self::ListReverse | Self::ListUnique => Some(&LIST_A_TO_LIST_A),
            Self::ListAppend => Some(&LIST_APPEND),
            Self::ListConcat => Some(&LIST_CONCAT),
            Self::ListTake | Self::ListDrop => Some(&INT_TO_LIST_A_TO_LIST_A),
            Self::ListRepeat => Some(&LIST_REPEAT),
            Self::ListSingleton => Some(&A_TO_LIST_A),
            Self::ListConcatMap => Some(&LIST_CONCAT_MAP),
            Self::ListFilterMap => Some(&LIST_FILTER_MAP),
            Self::ListFoldl | Self::ListFoldr => Some(&LIST_FOLD),
            Self::ListSort => Some(&LIST_SORT),
            Self::ListSortBy => Some(&LIST_SORT_BY),
            Self::ListSortWith => Some(&LIST_SORT_WITH),
            Self::ListSum | Self::ListProduct => Some(&LIST_SUM),
            Self::ListMaximum | Self::ListMinimum => Some(&LIST_MAX_MIN),

            // ── Basics (rank-1 polymorphic; the obligation-bearing arms carry
            //    their base scheme, the obligation layered in
            //    `constrain_var_kernel`). ──
            Self::BasicsIdentity | Self::BasicsNegate | Self::BasicsAbs => Some(&A_TO_A),
            Self::BasicsFst => Some(&BASICS_FST),
            Self::BasicsSnd => Some(&BASICS_SND),
            Self::BasicsAlways => Some(&BASICS_ALWAYS),
            Self::BasicsModBy => Some(&INT_TO_INT_TO_INT_LEAF),
            Self::BasicsClamp => Some(&BASICS_CLAMP),
            Self::Interpolate => Some(&A_TO_STRING),
            Self::BasicsMin | Self::BasicsMax | Self::MathMin | Self::MathMax => Some(&A_TO_A_TO_A),
            Self::BasicsCompare => Some(&BASICS_COMPARE),

            // ── Maybe combinators. ──
            Self::MaybeWithDefault => Some(&MAYBE_WITH_DEFAULT),
            Self::MaybeMap => Some(&MAYBE_MAP),
            Self::MaybeAndThen => Some(&MAYBE_AND_THEN),
            Self::MaybeMap2 => Some(&MAYBE_MAP2),
            Self::MaybeMap3 => Some(&MAYBE_MAP3),
            Self::MaybeMap4 => Some(&MAYBE_MAP4),
            Self::MaybeMap5 => Some(&MAYBE_MAP5),
            Self::MaybeAndMap => Some(&MAYBE_AND_MAP),
            Self::MaybeCombine => Some(&MAYBE_COMBINE),
            Self::MaybeIsJust => Some(&MAYBE_IS_JUST),
            Self::MaybeIsNothing => Some(&MAYBE_IS_NOTHING),

            // ── Result combinators. ──
            Self::ResultWithDefault => Some(&RESULT_WITH_DEFAULT),
            Self::ResultMap => Some(&RESULT_MAP),
            Self::ResultAndThen => Some(&RESULT_AND_THEN),
            Self::ResultMapError => Some(&RESULT_MAP_ERROR),
            Self::ResultMap2 => Some(&RESULT_MAP2),
            Self::ResultMap3 => Some(&RESULT_MAP3),
            Self::ResultMap4 => Some(&RESULT_MAP4),
            Self::ResultMap5 => Some(&RESULT_MAP5),
            Self::ResultAndMap => Some(&RESULT_AND_MAP),
            Self::ResultCombine => Some(&RESULT_COMBINE),
            Self::ResultTraverse => Some(&RESULT_TRAVERSE),
            Self::ResultToMaybe => Some(&RESULT_TO_MAYBE),
            Self::ResultFromMaybe => Some(&RESULT_FROM_MAYBE),
            Self::ResultOkDefault => Some(&RESULT_OK_DEFAULT),

            // ── Set combinators (base schemes; `set_elem` obligation layered). ──
            Self::SetEmpty => Some(&SET_A),
            Self::SetSize => Some(&SET_SIZE),
            Self::SetInsert | Self::SetRemove => Some(&SET_INSERT),
            Self::SetMember => Some(&SET_MEMBER),
            Self::SetToList => Some(&SET_TO_LIST),
            Self::SetFromList => Some(&SET_FROM_LIST),
            Self::SetUnion | Self::SetIntersect | Self::SetDiff => Some(&SET_UNION),
            Self::SetIsEmpty => Some(&SET_IS_EMPTY),
            Self::SetSingleton => Some(&SET_SINGLETON),
            Self::SetFoldl | Self::SetFoldr => Some(&SET_FOLD),
            Self::SetMap => Some(&SET_MAP),
            Self::SetFilter => Some(&SET_FILTER),
            Self::SetPartition => Some(&SET_PARTITION),

            // ── Dict combinators (base schemes; `dict_key` obligation layered). ──
            Self::DictEmpty => Some(&DICT_EMPTY),
            Self::DictIsEmpty => Some(&DICT_IS_EMPTY),
            Self::DictSize => Some(&DICT_SIZE),
            Self::DictInsert => Some(&DICT_INSERT),
            Self::DictGet => Some(&DICT_GET),
            Self::DictRemove => Some(&DICT_REMOVE),
            Self::DictMember => Some(&DICT_MEMBER),
            Self::DictKeys => Some(&DICT_KEYS),
            Self::DictValues => Some(&DICT_VALUES),
            Self::DictToList => Some(&DICT_TO_LIST),
            Self::DictFromList => Some(&DICT_FROM_LIST),
            Self::DictPartition => Some(&DICT_PARTITION),
            Self::DictMap => Some(&DICT_MAP),
            Self::DictFoldl | Self::DictFoldr => Some(&DICT_FOLD),
            Self::DictUnion | Self::DictIntersect | Self::DictDiff => Some(&DICT_UNION),
            Self::DictSingleton => Some(&DICT_SINGLETON),
            Self::DictFilter => Some(&DICT_FILTER),
            Self::DictUpdate => Some(&DICT_UPDATE),

            // ── Random seeded generators (pure, reproducible). ──
            Self::RandomSeededInt => Some(&RANDOM_SEEDED_INT),
            Self::RandomSeededFloat => Some(&RANDOM_SEEDED_FLOAT),
            Self::RandomSeededChoice => Some(&RANDOM_SEEDED_CHOICE),

            // ── Bytes decode / codec. ──
            Self::BytesToString => Some(&BYTES_TO_MAYBE_STRING),
            Self::BytesFromHex | Self::BytesFromBase64 => Some(&STRING_TO_MAYBE_BYTES),

            // ── List higher-arity mappers (rank-1 polymorphic, arrow-only). ──
            Self::ListIndexedMap => Some(&LIST_INDEXED_MAP),
            Self::ListMap2 => Some(&LIST_MAP2),
            Self::ListMap3 => Some(&LIST_MAP3),
            Self::ListMap4 => Some(&LIST_MAP4),
            Self::ListMap5 => Some(&LIST_MAP5),

            // ── String combinators over the primitives / `Char`. The
            //    obligation-free members carry their shape directly; `foldl`/`foldr`
            //    are fully generic (the callback supplies the fold), so no
            //    obligation is layered. ──
            Self::StringToInt => Some(&STRING_TO_MAYBE_INT),
            Self::StringToFloat => Some(&STRING_TO_MAYBE_FLOAT),
            Self::StringFromList => Some(&STRING_FROM_LIST),
            Self::StringConcat => Some(&STRING_CONCAT),
            Self::StringWords | Self::StringLines => Some(&STRING_TO_LIST_STRING),
            Self::StringToList => Some(&STRING_TO_LIST_CHAR),
            Self::StringJoin => Some(&STRING_JOIN),
            Self::StringSplit => Some(&STRING_SPLIT),
            Self::StringUncons => Some(&STRING_UNCONS),
            Self::StringIndexes => Some(&STRING_INDEXES),
            Self::StringFoldl | Self::StringFoldr => Some(&STRING_FOLD),

            // ── `String -> Maybe String` parsers. ──
            Self::CssSafetySafeValue
            | Self::CssSafetySafePropName
            | Self::CssSafetySafeSelector
            | Self::CssSafetySanitizeRawBody
            | Self::UuidParse => Some(&STRING_TO_MAYBE_STRING),

            // ── Miscellaneous arrow-only schemes. `Debug.log` / `Error.toString`
            //    carry their base scheme; the STRINGIFY obligation is layered in
            //    `constrain_var_kernel`, so the shape is exercised only by the
            //    totality / oracle tripwires, never in production. ──
            Self::DebugLog => Some(&STRING_TO_A_TO_A),
            // `Debug.todo : String -> a` — diverging; unconstrained result var.
            // Same shape class as `System.exit : Int -> a` (never returns `a`).
            Self::DebugTodo => Some(&STRING_TO_A),
            // `Debug.explain : Attribute msg` — nullary, same class as the
            // other nullary Ui attribute builders (`UiPointer`, `UiCenterX`, …).
            Self::DebugExplain => Some(&UI_ATTR_A),
            Self::ErrorToString => Some(&A_TO_STRING),
            Self::SystemExit => Some(&INT_TO_A),
            Self::HttpParseQuery => Some(&STRING_TO_RESULT_ERR_DICT_SS),
            Self::DbGetString | Self::DbGetField => Some(&DB_GET_STRING),
            Self::DbGetInt => Some(&DB_GET_INT),
            Self::DbGetBool => Some(&DB_GET_BOOL),

            // ── Log (base schemes; the `*With` INTERPOLABLE obligation is
            //    layered in `constrain_var_kernel`). ──
            Self::LogInfo | Self::LogDebug | Self::LogWarn | Self::LogError => {
                Some(&STRING_TO_TASK_UNIT)
            }
            Self::LogInfoWith | Self::LogDebugWith | Self::LogWarnWith | Self::LogErrorWith => {
                Some(&LOG_WITH)
            }

            // ── Task combinators. ──
            Self::TaskSucceed => Some(&A_TO_TASK_A),
            Self::TaskFail => Some(&ERROR_TO_TASK_A),
            Self::TaskMap => Some(&TASK_MAP),
            Self::TaskMap2 => Some(&TASK_MAP2),
            Self::TaskMap3 => Some(&TASK_MAP3),
            Self::TaskMap4 => Some(&TASK_MAP4),
            Self::TaskMap5 => Some(&TASK_MAP5),
            Self::TaskAttempt => Some(&TASK_ATTEMPT),
            Self::TaskAndThen => Some(&TASK_AND_THEN),
            Self::TaskMapError => Some(&TASK_MAP_ERROR),
            Self::TaskOnError => Some(&TASK_ON_ERROR),
            Self::TaskFromResult => Some(&TASK_FROM_RESULT),
            Self::TaskAndThenResult => Some(&TASK_AND_THEN_RESULT),
            Self::TaskSequence | Self::TaskParallel => Some(&TASK_SEQUENCE),
            Self::TaskRun | Self::TaskPerform => Some(&TASK_A_TO_RESULT_ERR_A),
            Self::TaskLazy => Some(&TASK_LAZY),
            Self::TaskLoop => Some(&TASK_LOOP),

            // ── Cmd / Sub / PubSub. ──
            Self::CmdNone => Some(&CMD_A),
            Self::CmdBatch => Some(&CMD_BATCH),
            Self::CmdPerform => Some(&CMD_PERFORM),
            Self::CmdMap => Some(&CMD_MAP),
            Self::CmdPublish | Self::CmdPublishNoEcho => Some(&CMD_PUBLISH),
            Self::SubNone => Some(&SUB_A),
            Self::SubBatch => Some(&SUB_BATCH),
            Self::SubEvery | Self::TimeEvery => Some(&INT_TO_A_TO_SUB_A),
            Self::SubMap => Some(&SUB_MAP),
            Self::SubSubscribeTopic => Some(&SUB_SUBSCRIBE_TOPIC),
            Self::TuiSubOnKey => Some(&TUI_SUB_ON_KEY),
            Self::CliSubOnLine => Some(&CLI_SUB_ON_LINE),
            Self::PubSubPublish | Self::PubSubPublishNoEcho => Some(&PUBSUB_PUBLISH),
            Self::PubSubTopic => Some(&STRING_TO_TOPIC_A),

            // ── Io / File / System / Time — `()`/`Task ()` effect kernels. ──
            Self::IoWriteStdout
            | Self::IoWriteStderr
            | Self::IoPrintln
            | Self::IoEprintln
            | Self::SystemUnsetenv => Some(&STRING_TO_TASK_UNIT),
            Self::FileRemove | Self::FileMkdirAll | Self::FileDelete => Some(&PATH_TO_TASK_UNIT),
            Self::IoReadLine | Self::SystemCwd | Self::SystemGetcwd => Some(&UNIT_TO_TASK_STRING),
            Self::IoReadSecret => Some(&STRING_TO_TASK_SECRET),
            Self::TimeNow | Self::TimeUnixMillis => Some(&UNIT_TO_TASK_INT),
            Self::TimeSleep => Some(&INT_TO_TASK_UNIT),
            Self::SystemGetenv | Self::FileTempFile | Self::FileTempDir => {
                Some(&STRING_TO_TASK_STRING)
            }
            Self::FileReadFile => Some(&PATH_TO_TASK_STRING),
            Self::SystemArgs => Some(&UNIT_TO_TASK_LIST_STRING),
            Self::SystemLoadEnv => Some(&UNIT_TO_TASK_UNIT),
            Self::SystemSetenv => Some(&STRING_TO_STRING_TO_TASK_UNIT),
            Self::FileWriteFile | Self::FileAppend => Some(&PATH_TO_STRING_TO_TASK_UNIT),
            Self::FileCopy | Self::FileRename => Some(&PATH_TO_PATH_TO_TASK_UNIT),
            Self::SystemGetArg => Some(&INT_TO_TASK_MAYBE_STRING),
            Self::SystemGetenvInt => Some(&STRING_TO_TASK_INT),
            Self::SystemGetenvBool => Some(&STRING_TO_TASK_BOOL),
            Self::FileExists | Self::FileIsDir => Some(&PATH_TO_TASK_BOOL),
            Self::FileReadDir => Some(&PATH_TO_TASK_LIST_STRING),
            Self::FileReadFileLimit => Some(&PATH_TO_INT_TO_TASK_STRING),
            Self::FileReadFileBytes => Some(&PATH_TO_TASK_LIST_INT),
            Self::FileWalk => Some(&PATH_TO_TASK_LIST_PATH),
            Self::FileWalkMatching => Some(&PATH_TO_BOOL_TO_TASK_LIST_PATH),

            // ── Random / Process. ──
            Self::RandomInt => Some(&INT_TO_INT_TO_TASK_INT),
            Self::RandomFloat => Some(&FLOAT_TO_FLOAT_TO_TASK_FLOAT),
            Self::RandomChoice => Some(&LIST_A_TO_TASK_A),
            Self::RandomChoiceMaybe => Some(&RANDOM_CHOICE_MAYBE),
            Self::RandomShuffle => Some(&RANDOM_SHUFFLE),
            Self::RandomWeighted => Some(&RANDOM_WEIGHTED),
            Self::ProcessRun => Some(&PROCESS_RUN),
            Self::ProcessRunWith => Some(&PROCESS_RUN_WITH),
            Self::ProcessRunInPty => Some(&PROCESS_RUN_IN_PTY),

            // ── Json.Decode / Db.Decode / Config — the shared `Decoder a`
            //    carrier families. ──
            Self::JsonDecString | Self::ConfigString => Some(&DEC_STRING),
            Self::JsonDecInt | Self::ConfigInt => Some(&DEC_INT),
            Self::JsonDecFloat | Self::ConfigFloat => Some(&DEC_FLOAT),
            Self::JsonDecBool | Self::ConfigBool => Some(&DEC_BOOL),
            Self::JsonDecValue => Some(&DEC_JSON_VALUE),
            Self::JsonDecDecodeValue => Some(&DEC_DECODE_VALUE),
            Self::JsonDecField | Self::ConfigField => Some(&STRING_TO_DEC_A_TO_DEC_A),
            Self::DbDecString => Some(&STRING_TO_DEC_STRING),
            Self::JsonDecAt | Self::ConfigAt => Some(&LIST_STRING_TO_DEC_A_TO_DEC_A),
            Self::JsonDecPRequiredAt => Some(&DEC_REQUIRED_AT),
            Self::JsonDecIndex | Self::ConfigIndex => Some(&INT_TO_DEC_A_TO_DEC_A),
            Self::JsonDecList | Self::ConfigList => Some(&DEC_LIST),
            Self::JsonDecMap | Self::ConfigMap | Self::DbDecMap => Some(&DEC_MAP),
            Self::JsonDecAndThen | Self::ConfigAndThen | Self::DbDecAndThen => Some(&DEC_AND_THEN),
            Self::JsonDecSucceed | Self::ConfigSucceed | Self::DbDecSucceed => Some(&A_TO_DEC_A),
            Self::JsonDecFail | Self::ConfigFail | Self::DbDecFail => Some(&STRING_TO_DEC_A),
            Self::JsonDecOneOf | Self::ConfigOneOf => Some(&DEC_ONE_OF),
            Self::JsonDecMap2 | Self::ConfigMap2 | Self::DbDecMap2 => Some(&DEC_MAP2),
            Self::JsonDecMap3 | Self::ConfigMap3 | Self::DbDecMap3 => Some(&DEC_MAP3),
            Self::JsonDecMap4 | Self::ConfigMap4 | Self::DbDecMap4 => Some(&DEC_MAP4),
            Self::ConfigMap5 => Some(&DEC_MAP5),
            Self::ConfigMap6 => Some(&DEC_MAP6),
            Self::ConfigMap7 => Some(&DEC_MAP7),
            Self::ConfigMap8 => Some(&DEC_MAP8),
            Self::JsonDecPRequired | Self::DbDecRequired => Some(&DEC_REQUIRED),
            Self::JsonDecPOptional | Self::DbDecOptional => Some(&DEC_OPTIONAL),
            Self::JsonDecPCustom => Some(&DEC_CUSTOM),
            Self::JsonDecDecodeString => Some(&DEC_DECODE_STRING),
            Self::JsonDecNullable
            | Self::ConfigNullable
            | Self::ConfigMaybe
            | Self::DbDecNullable => Some(&DEC_NULLABLE),
            Self::ConfigKeyValuePairs => Some(&CONFIG_KVP),
            Self::ConfigDict => Some(&CONFIG_DICT),
            Self::ConfigDecodeToml | Self::ConfigDecodeYaml | Self::ConfigDecodeJson => {
                Some(&CONFIG_DECODE)
            }
            Self::ConfigLoadFromFile => Some(&CONFIG_LOAD),
            // Db.Decode primitives with a `String` key argument.
            Self::DbDecInt => Some(&STRING_TO_DEC_INT),
            Self::DbDecFloat => Some(&STRING_TO_DEC_FLOAT),
            Self::DbDecBool => Some(&STRING_TO_DEC_BOOL),
            Self::DbDecMoney => Some(&DB_DEC_MONEY),
            Self::DbDecDecimal => Some(&DB_DEC_DECIMAL),
            Self::DbDecBytes => Some(&DB_DEC_BYTES),

            // ── Json.Encode encoders (`Value = any`). ──
            Self::JsonEncString => Some(&STRING_TO_VALUE),
            Self::JsonEncInt => Some(&INT_TO_VALUE),
            Self::JsonEncFloat => Some(&FLOAT_TO_VALUE),
            Self::JsonEncBool => Some(&BOOL_TO_VALUE),
            Self::JsonEncNull => Some(&JSON_VALUE),
            Self::JsonEncList => Some(&JSON_ENC_LIST),
            Self::JsonEncObject => Some(&JSON_ENC_OBJECT),
            Self::JsonEncEncode => Some(&JSON_ENC_ENCODE),

            // ── Error ADT family. ──
            Self::ErrorUnexpected
            | Self::ErrorInvalidInput
            | Self::ErrorIo
            | Self::ErrorNetwork
            | Self::ErrorFfi
            | Self::ErrorDecode
            | Self::ErrorConflict
            | Self::ErrorUnavailable => Some(&STRING_TO_ERROR),
            Self::ErrorTimeout | Self::ErrorNotFound | Self::ErrorPermissionDenied => Some(&ERROR),
            Self::ErrorWithMessage => Some(&STRING_TO_ERROR_TO_ERROR),
            Self::ErrorIsRetryable => Some(&ERROR_TO_BOOL),
            Self::ErrorWithDetails => Some(&ERRORDETAILS_TO_ERROR_TO_ERROR),
            Self::ErrorKind => Some(&ERROR_TO_ERRORKIND),
            Self::ErrorMessage => Some(&ERROR_TO_STRING),
            Self::ErrorKindName => Some(&ERRORKIND_TO_STRING),

            // ── Encoding decoders / HttpMethod / Env. ──
            Self::EncodingBase64Decode
            | Self::EncodingUrlDecode
            | Self::EncodingPercentDecode
            | Self::EncodingHexDecode => Some(&STRING_TO_RESULT_ERR_STRING),
            Self::HttpMethodToString => Some(&HTTP_METHOD_TO_STRING),
            Self::HttpMethodFromString => Some(&STRING_TO_MAYBE_HTTP_METHOD),
            Self::EnvPublic => Some(&STRING_TO_MAYBE_STRING_ENV),

            // ── Uuid entropy effect + parse. ──
            Self::UuidV4 | Self::UuidV7 => Some(&UNIT_TO_TASK_STRING),

            // ── Secret. ──
            Self::SecretFromString => Some(&STRING_TO_SECRET),
            Self::SecretReveal | Self::SecretRedacted => Some(&SECRET_TO_STRING),

            // ── Regex. ──
            Self::RegexCompile => Some(&STRING_TO_RESULT_ERR_REGEX),
            Self::RegexMatch => Some(&REGEX_TO_STRING_TO_BOOL),
            Self::RegexFind => Some(&REGEX_TO_STRING_TO_MAYBE_STRING),
            Self::RegexFindAll | Self::RegexSplit => Some(&REGEX_TO_STRING_TO_LIST_STRING),
            Self::RegexReplace => Some(&REGEX_TO_STRING_TO_STRING_TO_STRING),

            // ── Path. ──
            Self::PathFromString => Some(&STRING_TO_RESULT_ERR_PATH),
            Self::PathToString | Self::PathBase | Self::PathDir | Self::PathExt => {
                Some(&PATH_TO_STRING)
            }
            Self::PathIsAbsolute => Some(&PATH_TO_BOOL),
            Self::PathUnder => Some(&PATH_TO_PATH_TO_RESULT_ERR_PATH),
            Self::PathAbsolute => Some(&PATH_TO_TASK_PATH),

            // ── Url. ──
            Self::UrlFromString => Some(&STRING_TO_RESULT_ERR_URL),
            Self::UrlToString | Self::UrlScheme | Self::UrlSchemeShown | Self::UrlPath => {
                Some(&URL_TO_STRING)
            }
            Self::UrlHost | Self::UrlQuery | Self::UrlFragment => Some(&URL_TO_MAYBE_STRING),
            Self::UrlPort => Some(&URL_TO_MAYBE_INT),
            Self::UrlBuildQuery => Some(&URL_BUILD_QUERY),
            Self::UrlRelativeParse => Some(&STRING_TO_RESULT_ERR_RELATIVE),
            Self::UrlRelativePath | Self::UrlRelativeToString => Some(&RELATIVE_TO_STRING),
            Self::UrlRelativeQuery | Self::UrlRelativeFragment => Some(&RELATIVE_TO_MAYBE_STRING),

            // ── Ipe.Db.Dsn — parse-don't-validate descriptor. ──
            Self::DsnParse => Some(&STRING_TO_RESULT_ERR_DSN),
            Self::DsnBuild => Some(&DSN_BUILD),
            Self::DsnDriverTag | Self::DsnPort | Self::DsnTlsTag => Some(&DSN_TO_INT),
            Self::DsnHost | Self::DsnDatabase | Self::DsnUser | Self::DsnRedacted => {
                Some(&DSN_TO_STRING)
            }

            // ── External Connection — read-only-by-type foreign-DB connect. ──
            Self::DbConnOpen => Some(&DSN_TO_TASK_CONN_RO),
            Self::DbConnClose => Some(&CONN_MODE_TO_TASK_UNIT),
            Self::DbConnUnsafeExecRawOn => Some(&CONN_RW_TO_STRING_TO_TASK_INT),
            Self::DbConnFindWhere => Some(&CONN_FIND_WHERE),
            Self::DbConnQueryDecode => Some(&CONN_QUERY_DECODE),
            Self::DbConnGetById => Some(&CONN_GET_BY_ID),

            // ── Locale. ──
            Self::LocaleFromTag => Some(&STRING_TO_MAYBE_LOCALE),
            Self::LocaleToTag => Some(&LOCALE_TO_STRING),
            Self::StringToUpperIn | Self::StringToLowerIn => Some(&LOCALE_TO_STRING_TO_STRING),

            // ── Crypto typed-key newtypes + AEAD/HMAC/sign. ──
            Self::CryptoKeyFromString | Self::CryptoKeyFromBytes => {
                Some(&STRING_TO_MAYBE_CRYPTO_KEY)
            }
            Self::CryptoMacToHex => Some(&CRYPTO_MAC_TO_STRING),
            Self::CryptoHmacSha256WithKey | Self::CryptoHmacSha512WithKey => {
                Some(&CRYPTO_KEY_TO_STRING_TO_CRYPTO_MAC)
            }
            // Key-derivation returns a typed `Key`.
            Self::CryptoAesKeyFromPassword | Self::CryptoChachaKeyFromPassword => {
                Some(&STRING_TO_STRING_TO_CRYPTO_KEY)
            }
            // AEAD requires a typed `Key` in the key role.
            Self::CryptoAesGcmEncrypt
            | Self::CryptoAesGcmDecrypt
            | Self::CryptoChacha20Encrypt
            | Self::CryptoChacha20Decrypt => Some(&CRYPTO_KEY_TO_STRING_TO_RESULT_ERR_STRING),
            Self::CryptoRsaSha256Sign => Some(&STRING_TO_STRING_TO_RESULT_ERR_STRING),
            Self::CryptoRandomBytes | Self::CryptoRandomToken => Some(&INT_TO_TASK_STRING_LEAF),

            // ── Jwt (raw + builder). ──
            Self::JwtDecodeHs256
            | Self::JwtDecodeRs256
            | Self::JwtEncodeHs256
            | Self::JwtEncodeRs256 => Some(&STRING_TO_STRING_TO_RESULT_ERR_STRING),
            Self::JwtClaims => Some(&CLAIMS),
            // Config-tag ADT constructors — nullary, each returns its closed type.
            Self::HostLoopback | Self::HostAllInterfaces | Self::HostEnvDriven => Some(&HOST_MODE),
            Self::LevelDebug | Self::LevelInfo | Self::LevelWarn | Self::LevelError => {
                Some(&LOG_LEVEL)
            }
            Self::WebCsrfStrict | Self::WebCsrfInherit => Some(&CSRF_MODE),
            // `revocationOff / revocationStore : RevocationMode` — nullary ADT constructors.
            Self::WebRevocationOff | Self::WebRevocationStore => Some(&REVOCATION_MODE),
            Self::JwtHs256 | Self::JwtRs256 => Some(&STRING_TO_ALGORITHM),
            Self::JwtSubject | Self::JwtIssuer | Self::JwtAudience | Self::JwtJwtId => {
                Some(&STRING_TO_CLAIMS_TO_CLAIMS)
            }
            Self::JwtExpiresAt | Self::JwtNotBefore | Self::JwtIssuedAt => {
                Some(&INT_TO_CLAIMS_TO_CLAIMS)
            }
            Self::JwtWithClaim => Some(&JWT_WITH_CLAIM),
            Self::JwtEncode => Some(&JWT_ENCODE),
            Self::JwtDecode => Some(&JWT_DECODE),

            // ── EmailAddress. ──
            Self::EmailAddressParse => Some(&STRING_TO_MAYBE_EMAIL_ADDRESS),
            Self::EmailAddressToString => Some(&EMAIL_ADDRESS_TO_STRING),

            // ── Auth. ──
            Self::AuthHashPassword | Self::AuthPasswordStrength => {
                Some(&STRING_TO_RESULT_ERR_STRING)
            }
            Self::AuthHashPasswordCost => Some(&STRING_TO_INT_TO_RESULT_ERR_STRING),
            Self::AuthVerifyPassword => Some(&STRING_TO_STRING_TO_RESULT_ERR_BOOL),
            Self::AuthSignToken => Some(&AUTH_SIGN_TOKEN),
            Self::AuthVerifyToken => Some(&AUTH_VERIFY_TOKEN),
            Self::AuthRegister | Self::AuthLogin => Some(&DB_TO_STRING_TO_STRING_TO_TASK_INT),
            Self::AuthSetRole => Some(&DB_TO_INT_TO_STRING_TO_TASK_UNIT),
            Self::AuthSubject => Some(&PRINCIPAL_TO_STRING),
            Self::AuthClaim => Some(&STRING_TO_PRINCIPAL_TO_MAYBE_STRING),
            Self::AuthHasRole | Self::AuthMemberOf => Some(&STRING_TO_PRINCIPAL_TO_BOOL),
            // `revokeUser / restoreUser : Principal -> String -> Task ()`
            Self::AuthRevocationRevokeUser | Self::AuthRevocationRestoreUser => {
                Some(&PRINCIPAL_TO_STRING_TO_TASK_UNIT)
            }
            // `revokeSession : Principal -> String -> Int -> Task ()` (cap is the third arg)
            Self::AuthRevocationRevokeSession => Some(&PRINCIPAL_TO_STRING_TO_INT_TO_TASK_UNIT),
            // `isRevoked : String -> Task Bool`
            Self::AuthRevocationIsRevoked => Some(&STRING_TO_TASK_BOOL_REVOKE),

            // ── Compression. ──
            Self::CompressionGzip
            | Self::CompressionGunzip
            | Self::CompressionZstdCompress
            | Self::CompressionZstdDecompress => Some(&BYTES_TO_TASK_BYTES),

            // ── Trace. ──
            Self::TraceSpan => Some(&STRING_TO_TASK_A_TO_TASK_A),
            Self::TraceEvent => Some(&STRING_TO_TASK_UNIT),
            Self::TraceAttr => Some(&STRING_TO_STRING_TO_TASK_UNIT_TRACE),

            // ── HttpStream. ──
            Self::HttpStreamForEachChunk => Some(&STREAM_ID_FOR_EACH),
            Self::HttpStreamClose => Some(&STREAM_ID_TO_TASK_UNIT),
            Self::HttpStreamChunks => Some(&STREAM_ID_CHUNKS),

            // ── Server-side Stream (opaque StreamWriter; `stream` itself keeps a
            //    table arm — its result is a `Response` record). ──
            Self::StreamFinish => Some(&SW_TO_TASK_UNIT),
            Self::StreamEmit | Self::StreamWithContentType => Some(&STRING_TO_SW_TO_TASK_UNIT),

            // ── Db (opaque Db handle + Dict rows; the record-shaped Migration
            //    arms keep their table entry — S4). ──
            Self::DbConnect => Some(&UNIT_TO_TASK_DB),
            Self::DbOpen => Some(&STRING_TO_STRING_TO_TASK_DB),
            Self::DbClose => Some(&DB_TO_TASK_UNIT),
            Self::DbExecRaw => Some(&DB_EXEC_RAW),
            Self::DbExec => Some(&DB_EXEC),
            Self::DbQuery => Some(&DB_QUERY),
            Self::DbQueryDecode => Some(&DB_QUERY_DECODE),
            Self::DbInsertRow => Some(&DB_INSERT_ROW),
            Self::DbGetById => Some(&DB_GET_BY_ID),
            Self::DbUpdateById => Some(&DB_UPDATE_BY_ID),
            Self::DbDeleteById => Some(&DB_DELETE_BY_ID),
            Self::DbFindOneByField => Some(&DB_FIND_ONE_BY_FIELD),
            Self::DbFindManyByField => Some(&DB_FIND_MANY_BY_FIELD),
            Self::DbFindByConditions => Some(&DB_FIND_BY_CONDITIONS),
            Self::DbFindWhere => Some(&DB_FIND_WHERE),
            Self::DbFindWhereMasked => Some(&DB_FIND_WHERE_MASKED),
            Self::DbFindJoin => Some(&DB_FIND_JOIN),
            Self::DbFindProjection => Some(&DB_FIND_PROJECTION),
            Self::DbFindJoinOrdered => Some(&DB_FIND_JOIN_ORDERED),
            Self::DbFindProjectionOrdered => Some(&DB_FIND_PROJECTION_ORDERED),
            Self::DbDeleteWhere => Some(&DB_DELETE_WHERE),
            // `Db_insertFieldsChecked` has `Db.updateWhere`'s exact shape
            // (`Db -> String -> List (String, SqlField) -> SqlFragment -> Task Int`).
            Self::DbUpdateWhere | Self::DbInsertFieldsChecked => Some(&DB_UPDATE_WHERE),
            Self::DbUpdateWhereChecked => Some(&DB_UPDATE_WHERE_CHECKED),
            Self::DbUpsertFields => Some(&DB_UPSERT_FIELDS),
            Self::DbInsertFields => Some(&DB_INSERT_FIELDS),
            Self::DbUpdateFields => Some(&DB_UPDATE_FIELDS),
            Self::DbInsertFieldsReturning => Some(&DB_INSERT_FIELDS_RETURNING),
            Self::DbWithTransaction => Some(&DB_WITH_TRANSACTION),

            // ── WebSocket client. ──
            Self::WebSocketConnect => Some(&STRING_TO_TASK_INT_LEAF),
            Self::WebSocketSend => Some(&INT_TO_STRING_TO_TASK_UNIT),
            Self::WebSocketSendBinary => Some(&INT_TO_BYTES_TO_TASK_UNIT),
            Self::WebSocketClose => Some(&INT_TO_TASK_UNIT_LEAF),
            Self::WebSocketCloseWithCode => Some(&WS_CLOSE_WITH_CODE),
            Self::SubSubscribeWebSocket => Some(&SUB_SUBSCRIBE_WS),

            // ── Ipe.Ffi.Js ports. ──
            Self::JsSend => Some(&JS_SEND),
            Self::JsSubscribe => Some(&JS_SUBSCRIBE),
            Self::JsRequest => Some(&JS_REQUEST),
            Self::JsOpenSession => Some(&JS_OPEN_SESSION),
            Self::JsSessionFrames => Some(&JS_SESSION_FRAMES),
            Self::JsSendToSession => Some(&JS_SEND_TO_SESSION),
            Self::JsCloseSession => Some(&JS_CLOSE_SESSION),

            // ── Ws server (opaque handle / cfg). ──
            Self::WsDefaultCfg => Some(&WS_SERVER_CFG),
            Self::WsWithOnConnect | Self::WsWithOnClose => Some(&WS_ON_CB_TO_CFG),
            Self::WsWithOnMessage => Some(&WS_ON_MESSAGE),
            Self::WsWithOnError => Some(&WS_ON_ERROR),
            Self::WsWithMaxMessageBytes => Some(&INT_TO_CFG_TO_CFG),
            Self::WsWithOriginPatterns => Some(&LIST_STRING_TO_CFG_TO_CFG),
            Self::WsSendToClient => Some(&WS_SEND_TO_CLIENT),
            Self::WsSendBinaryToClient => Some(&WS_SEND_BINARY),
            Self::WsBroadcast => Some(&WS_BROADCAST),
            Self::WsCloseClient => Some(&WS_CLOSE_CLIENT),

            // ── Server (non-record route/cookie arms). ──
            Self::ServerStatic => Some(&STRING_TO_STRING_TO_ROUTE),
            Self::ServerCookieNew => Some(&STRING_TO_STRING_TO_COOKIE),
            Self::ServerBody | Self::ServerPath | Self::ServerMethod => Some(&REQ_TO_STRING),
            Self::ServerParam
            | Self::ServerQueryParam
            | Self::ServerHeader
            | Self::ServerGetCookie => Some(&STRING_TO_REQ_TO_MAYBE_STRING),

            // ── Sql fragment builders. ──
            Self::SqlColumn | Self::SqlUnsafeFragment => Some(&STRING_TO_SQLFRAGMENT),
            Self::SqlParam => Some(&SQLVALUE_TO_SQLFRAGMENT),
            Self::SqlInt => Some(&INT_TO_SQLFRAGMENT),
            Self::SqlString => Some(&STRING_TO_SQLFRAGMENT),
            Self::SqlFloat => Some(&FLOAT_TO_SQLFRAGMENT),
            Self::SqlBool => Some(&BOOL_TO_SQLFRAGMENT),
            Self::SqlEq
            | Self::SqlNe
            | Self::SqlGt
            | Self::SqlLt
            | Self::SqlGte
            | Self::SqlLte
            | Self::SqlAnd
            | Self::SqlOr => Some(&SQLFRAGMENT_BINOP),
            Self::SqlNot | Self::SqlIsNull | Self::SqlIsNotNull => {
                Some(&SQLFRAGMENT_TO_SQLFRAGMENT)
            }
            Self::SqlInList => Some(&SQL_IN_LIST),
            Self::SqlLike => Some(&SQL_LIKE),
            Self::SqlExists => Some(&SQL_EXISTS),
            Self::SqlMaskedColumn => Some(&SQL_MASKED_COLUMN),

            // ── Ipe.Ui layout / element / container. ──
            Self::UiLayout => Some(&UI_LAYOUT),
            Self::UiAbove
            | Self::UiBelow
            | Self::UiOnLeft
            | Self::UiOnRight
            | Self::UiInFront
            | Self::UiBehind => Some(&UI_ELEM_A_TO_UI_ATTR_A),

            // ── Ipe.Ui events. ──
            Self::UiOnClick
            | Self::UiOnFocus
            | Self::UiOnBlur
            | Self::UiOnMouseOver
            | Self::UiOnMouseOut => Some(&A_TO_UI_ATTR_A),
            Self::UiOnInput
            | Self::UiOnChange
            | Self::UiOnKeyDown
            | Self::UiOnKeyUp
            | Self::UiOnFile => Some(&STRING_TO_A_TO_UI_ATTR_A),
            Self::UiOnBool => Some(&BOOL_TO_A_TO_UI_ATTR_A),
            Self::UiOnSubmit => Some(&B_TO_A_TO_UI_ATTR_A),

            // ── Ipe.Html.Events (arg shape from `html_event_shape`). ──
            Self::HtmlOnClick
            | Self::HtmlOnFocus
            | Self::HtmlOnBlur
            | Self::HtmlOnMouseOver
            | Self::HtmlOnMouseOut
            | Self::HtmlOnSubmit
            | Self::HtmlOnInput
            | Self::HtmlOnChange
            | Self::HtmlOnKeyDown
            | Self::HtmlOnKeyUp
            | Self::HtmlOnBool => match self.html_event_shape() {
                Some(HtmlEventShape::Msg) => Some(&A_TO_HTML_ATTR_A),
                Some(HtmlEventShape::String) => Some(&STRING_TO_A_TO_HTML_ATTR_A),
                Some(HtmlEventShape::Bool) => Some(&BOOL_TO_A_TO_HTML_ATTR_A),
                Some(HtmlEventShape::Raw) => Some(&B_TO_HTML_ATTR_A),
                None => None,
            },

            // ── Ipe.Html serialise / element / attribute builders. ──
            Self::HtmlRender | Self::HtmlToString => Some(&HTML_A_TO_STRING),
            Self::HtmlAttrToString => Some(&HTML_ATTR_A_TO_STRING),
            Self::HtmlTextNode | Self::HtmlRawNode | Self::HtmlTitleNode | Self::HtmlScriptNode => {
                Some(&STRING_TO_HTML_A)
            }
            Self::HtmlNode => Some(&HTML_NODE),
            Self::HtmlVoidNode => Some(&STRING_TO_LIST_HTML_ATTR_A_TO_HTML_A),
            Self::HtmlDoctype => Some(&LIST_HTML_A_TO_HTML_A_TOP),
            Self::HtmlStyleNode => Some(&HTML_STYLE_NODE),
            Self::HtmlAttribute => Some(&STRING_TO_STRING_TO_HTML_ATTR_A),
            Self::HtmlBoolAttribute => Some(&STRING_TO_BOOL_TO_HTML_ATTR_A),
            Self::HtmlNoAttr => Some(&HTML_ATTR_A),

            // ── Ipe.Ui element builders. ──
            Self::UiNone => Some(&UI_ELEM_A),
            Self::UiText => Some(&STRING_TO_UI_ELEM_A),
            Self::UiHtml => Some(&HTML_A_TO_UI_ELEM_A),
            Self::UiCells => Some(&LIST_LIST_CHAR_TO_UI_ELEM_A),
            // ── Ipe.Ui.Cells Cells-typed builders. ──
            Self::UiCellsNone => Some(&CELLS_A),
            Self::UiCellsText => Some(&STRING_TO_CELLS_A),
            Self::UiCellsEl => Some(&CELLS_EL),
            Self::UiCellsRow | Self::UiCellsColumn => Some(&CELLS_CONTAINER),
            Self::UiCellsCells => Some(&LIST_LIST_CHAR_TO_CELLS_A),
            // Cell-native attribute builders.
            Self::TuiUiSpacing | Self::TuiUiPadding => Some(&INT_TO_TUI_ATTR_A),
            Self::TuiUiAlignLeft
            | Self::TuiUiAlignRight
            | Self::TuiUiCenter
            | Self::TuiUiBold
            | Self::TuiUiUnderline
            | Self::TuiUiDim
            | Self::TuiUiReverse => Some(&TUI_ATTR_A),
            Self::TuiUiColor | Self::TuiUiBg => Some(&COLOR_TO_TUI_ATTR_A),
            // ── Ipe.Ui.Cli line-oriented builders. ──
            Self::CliUiNone => Some(&LINES_A),
            Self::CliUiText => Some(&STRING_TO_LINES_A),
            Self::CliUiLine => Some(&CLI_LINE),
            Self::CliUiLines => Some(&LIST_LINES_A_TO_LINES_A),
            Self::CliUiBold | Self::CliUiUnderline | Self::CliUiDim | Self::CliUiReverse => {
                Some(&CLI_ATTR_A)
            }
            Self::CliUiColor | Self::CliUiBg => Some(&COLOR_TO_CLI_ATTR_A),
            // ── Ipe.Color terminal palette constructors (the `AnsiColor` type). ──
            Self::TermColorBlack
            | Self::TermColorRed
            | Self::TermColorGreen
            | Self::TermColorYellow
            | Self::TermColorBlue
            | Self::TermColorMagenta
            | Self::TermColorCyan
            | Self::TermColorWhite
            | Self::TermColorBrightBlack
            | Self::TermColorBrightRed
            | Self::TermColorBrightGreen
            | Self::TermColorBrightYellow
            | Self::TermColorBrightBlue
            | Self::TermColorBrightMagenta
            | Self::TermColorBrightCyan
            | Self::TermColorBrightWhite
            | Self::TermColorDefault => Some(&ANSI_COLOR),
            Self::TermColorRgb => Some(&INT_TO_INT_TO_INT_TO_ANSI_COLOR),
            Self::TermColorRgba => Some(&INT_TO_INT_TO_INT_TO_FLOAT_TO_ANSI_COLOR),
            // ── Ipe.Color constructors ──
            Self::ColorRgb => Some(&INT_TO_INT_TO_INT_TO_COLOR),
            Self::ColorRgba => Some(&INT_TO_INT_TO_INT_TO_FLOAT_TO_COLOR),
            Self::ColorHsl => Some(&FLOAT_TO_FLOAT_TO_FLOAT_TO_COLOR),
            Self::ColorHsla => Some(&FLOAT_TO_FLOAT_TO_FLOAT_TO_FLOAT_TO_COLOR),
            Self::ColorWhite => Some(&COLOR),
            Self::ColorBlack => Some(&COLOR),
            Self::ColorRed => Some(&COLOR),
            Self::ColorGreen => Some(&COLOR),
            Self::ColorBlue => Some(&COLOR),
            Self::ColorTransparent => Some(&COLOR),
            // ── Ipe.Color accessors + manipulation ──
            Self::ColorToCss => Some(&COLOR_TO_STRING),
            Self::ColorToCssRgba => Some(&COLOR_TO_STRING),
            Self::ColorToHex => Some(&COLOR_TO_STRING),
            Self::ColorLuminance => Some(&COLOR_TO_FLOAT),
            Self::ColorWithAlpha => Some(&FLOAT_TO_COLOR_TO_COLOR),
            Self::ColorMix => Some(&FLOAT_TO_COLOR_TO_COLOR_TO_COLOR),
            Self::ColorBlend => Some(&COLOR_TO_COLOR_TO_COLOR),
            Self::ColorLighten => Some(&FLOAT_TO_COLOR_TO_COLOR),
            Self::ColorDarken => Some(&FLOAT_TO_COLOR_TO_COLOR),
            Self::ColorSaturate => Some(&FLOAT_TO_COLOR_TO_COLOR),
            Self::ColorDesaturate => Some(&FLOAT_TO_COLOR_TO_COLOR),
            Self::ColorRotateHue => Some(&FLOAT_TO_COLOR_TO_COLOR),
            Self::ColorComplementary => Some(&COLOR_TO_COLOR),
            Self::ColorGrayscale => Some(&COLOR_TO_COLOR),
            // ── Ipe.Color parse boundary (typed `Result ColorError Color`) ──
            Self::ColorFromHex | Self::ColorFromName => Some(&STRING_TO_RESULT_COLOR_ERROR_COLOR),
            // ── Ipe.Color profile / toAnsi ──
            Self::ColorTrueColorProfile
            | Self::ColorAnsi256Profile
            | Self::ColorAnsi16Profile
            | Self::ColorNoColorProfile => Some(&TERM_PROFILE),
            Self::ColorToAnsi => Some(&TERM_PROFILE_TO_COLOR_TO_ANSI),
            // ── Ipe.Color WCAG / contrast (a11y) ──
            Self::ColorWcagAa | Self::ColorWcagAaa => Some(&WCAG_LEVEL),
            Self::ColorNormalText | Self::ColorLargeText => Some(&TEXT_SIZE),
            Self::ColorContrastRatio => Some(&COLOR_TO_COLOR_TO_FLOAT),
            Self::ColorReadableTextOn => Some(&COLOR_TO_COLOR),
            Self::ColorMeetsWcag => Some(&WCAG_LEVEL_TO_TEXT_SIZE_TO_COLOR_TO_COLOR_TO_BOOL),
            Self::ColorMaximumContrast => Some(&COLOR_TO_LIST_COLOR_TO_COLOR),
            // ── Ipe.Color colour-vision-deficiency simulation ──
            Self::ColorProtanopia | Self::ColorDeuteranopia | Self::ColorTritanopia => {
                Some(&DEFICIENCY)
            }
            Self::ColorSimulate => Some(&DEFICIENCY_TO_COLOR_TO_COLOR),
            Self::UiWidget => Some(&UI_WIDGET),
            Self::UiNode => Some(&UI_NODE),
            Self::UiTaggedNode => Some(&UI_TAGGED_NODE),

            // ── Ipe.Ui / Font / Border nullary attribute builders. ──
            Self::UiCenterX
            | Self::UiCenterY
            | Self::UiAlignLeft
            | Self::UiAlignRight
            | Self::UiAlignTop
            | Self::UiAlignBottom
            | Self::UiPointer
            | Self::UiClip
            | Self::UiClipX
            | Self::UiClipY
            | Self::UiScrollbars
            | Self::UiScrollbarX
            | Self::UiScrollbarY
            | Self::FontBold
            | Self::FontItalic
            | Self::UiSquare
            | Self::UiWidescreen
            | Self::UiCinemascope
            | Self::BorderSolid
            | Self::BorderDashed
            | Self::BorderDotted
            | Self::FontSemiBold
            | Self::FontRegular
            | Self::FontLight
            | Self::FontExtraBold
            | Self::FontBlack
            | Self::FontUnderline
            | Self::FontNoDecoration
            | Self::FontLineThrough
            | Self::FontAlignLeft
            | Self::FontAlignRight
            | Self::FontAlignCenter
            | Self::FontCenter
            | Self::FontJustify => Some(&UI_ATTR_A),

            // ── Attribute builders by argument shape. ──
            Self::UiSpacing
            | Self::UiPadding
            | Self::UiGridColumns
            | Self::BorderWidth
            | Self::BorderRounded
            | Self::FontSize
            | Self::FontWeight
            | Self::FontHoverSize
            | Self::BorderHoverWidth
            | Self::BorderHoverRounded => Some(&INT_TO_UI_ATTR_A),
            Self::FontLetterSpacing | Self::FontWordSpacing | Self::UiAspectRatio => {
                Some(&FLOAT_TO_UI_ATTR_A)
            }
            Self::UiWidth | Self::UiHeight => Some(&LENGTH_TO_UI_ATTR_A),
            Self::BackgroundColor
            | Self::BorderColor
            | Self::FontColor
            | Self::BackgroundHoverColor
            | Self::BackgroundFocusColor
            | Self::BackgroundActiveColor
            | Self::BackgroundDisabledColor
            | Self::BorderHoverColor
            | Self::BorderFocusColor
            | Self::BorderActiveColor
            | Self::FontHoverColor
            | Self::FontFocusColor
            | Self::FontActiveColor
            | Self::FontDisabledColor => Some(&COLOR_TO_UI_ATTR_A),
            Self::BackgroundImage | Self::FontFamily => Some(&STRING_TO_UI_ATTR_A),
            Self::BackgroundLinearGradient => Some(&BG_LINEAR_GRADIENT),
            Self::UiPaddingXY | Self::UiAspectRatioWH => Some(&INT_TO_INT_TO_UI_ATTR_A),
            Self::UiHtmlAttribute | Self::UiStyle | Self::UiGridTracksRaw => {
                Some(&STRING_TO_STRING_TO_UI_ATTR_A)
            }
            Self::UiName => Some(&STRING_TO_UI_ATTR_A),
            Self::UiTransitionRaw => Some(&STRING_TO_BOOL_TO_UI_ATTR_A),
            Self::UiAnimateRaw => Some(&UI_ANIMATE_RAW),
            Self::UiBreakpoint | Self::UiMediaQuery => Some(&UI_BREAKPOINT),

            // ── PseudoClass constants + onPseudo. ──
            Self::UiHover
            | Self::UiFocus
            | Self::UiFocusVisible
            | Self::UiActive
            | Self::UiDisabled => Some(&PSEUDO_CLASS),
            Self::UiOnPseudo => Some(&UI_ON_PSEUDO),

            // ── Ipe.Ui.Keyed. ──
            Self::KeyedColumn | Self::KeyedRow => Some(&KEYED_CONTAINER),

            // ── Ipe.Ui.Region. ──
            Self::RegionMainContent
            | Self::RegionNavigation
            | Self::RegionFooter
            | Self::RegionAside
            | Self::RegionAnnounce
            | Self::RegionAnnounceUrgently => Some(&UI_ATTR_A),
            Self::RegionHeading => Some(&INT_TO_UI_ATTR_A_REGION),
            Self::RegionLabel => Some(&STRING_TO_UI_ATTR_A_REGION),

            // ── Ui.describe / Description. ──
            Self::UiDescribe => Some(&DESCRIPTION_TO_UI_ATTR_A),
            Self::UiDescNone
            | Self::UiDescParagraph
            | Self::UiDescMain
            | Self::UiDescNavigation
            | Self::UiDescContentInfo
            | Self::UiDescComplementary
            | Self::UiDescLivePolite
            | Self::UiDescLiveAssertive => Some(&DESCRIPTION),
            Self::UiDescHeading => Some(&INT_TO_DESCRIPTION),
            Self::UiDescLabel => Some(&STRING_TO_DESCRIPTION),

            // ── Ipe.Ui.Input non-record constructors. ──
            Self::InputLabelAbove
            | Self::InputLabelBelow
            | Self::InputLabelLeft
            | Self::InputLabelRight => Some(&INPUT_LABEL),
            Self::InputLabelHidden => Some(&STRING_TO_LABEL_A),
            Self::InputPlaceholder => Some(&INPUT_PLACEHOLDER),
            Self::InputOption => Some(&INPUT_OPTION),

            // ── Ipe.Ui.Lazy. ──
            Self::LazyLazy => Some(&LAZY_LAZY),
            Self::LazyLazy2 => Some(&LAZY_LAZY2),
            Self::LazyLazy3 => Some(&LAZY_LAZY3),
            Self::LazyLazy4 => Some(&LAZY_LAZY4),
            Self::LazyLazy5 => Some(&LAZY_LAZY5),

            // ── Ui length / color builders. ──
            Self::UiPx | Self::UiFillPortion | Self::UiVh | Self::UiVw => Some(&INT_TO_LENGTH),
            Self::UiFill | Self::UiContent | Self::UiShrink => Some(&LENGTH),
            Self::UiMinimum | Self::UiMaximum => Some(&INT_TO_LENGTH_TO_LENGTH),
            Self::UiRgb => Some(&UI_RGB),
            Self::UiRgba => Some(&UI_RGBA),
            Self::UiWhite | Self::UiBlack | Self::UiTransparent => Some(&COLOR),
            Self::UiColorCss => Some(&COLOR_TO_STRING),

            // ── Server route-listen (non-record). ──
            Self::ServerListen => Some(&SERVER_LISTEN),
            Self::ServerMountApp => Some(&MOUNT_APP),

            // ── Record / open-row families. ──
            // Migration (Db).
            Self::DbMigrate => Some(&DB_MIGRATE),
            Self::DbDefaultMigration => Some(&DB_DEFAULT_MIGRATION),
            // Http request / response.
            Self::HttpGet => Some(&HTTP_GET),
            Self::HttpPost => Some(&HTTP_POST),
            Self::HttpRequest => Some(&HTTP_DO_REQUEST),
            Self::HttpDefaultRequest => Some(&HTTP_DEFAULT_REQUEST),
            Self::HttpDefaultRequestFromString => Some(&HTTP_DEFAULT_REQUEST_FROM_STRING),
            Self::HttpWithMethod => Some(&HTTP_WITH_METHOD),
            Self::HttpWithTimeout => Some(&HTTP_WITH_TIMEOUT),
            Self::HttpWithRedirects => Some(&HTTP_WITH_REDIRECTS),
            Self::HttpWithBody => Some(&HTTP_WITH_BODY),
            Self::HttpWithHeader => Some(&HTTP_WITH_HEADER),
            Self::HttpWithUrl => Some(&HTTP_WITH_URL),
            // Server response (record) kernels.
            Self::ServerGet
            | Self::ServerPost
            | Self::ServerPut
            | Self::ServerDelete
            | Self::ServerAny
            | Self::ServerApi => Some(&SERVER_ROUTE_KERNEL),
            Self::ServerGetAuthed
            | Self::ServerPostAuthed
            | Self::ServerPutAuthed
            | Self::ServerDeleteAuthed => Some(&SERVER_AUTHED_ROUTE_KERNEL),
            Self::ServerAuthConfig => Some(&SECRET_TO_TOKEN_SOURCE_TO_AUTH_CONFIG),
            Self::ServerTokenBearer => Some(&TOKEN_SOURCE),
            Self::ServerCookieToken => Some(&STRING_TO_TOKEN_SOURCE),
            // `withRevocation : RevocationMode -> AuthConfig -> AuthConfig`
            Self::ServerWithRevocation => Some(&REVOCATION_MODE_TO_AUTH_CONFIG_TO_AUTH_CONFIG),
            Self::ServerText | Self::ServerJson | Self::ServerHtml | Self::ServerRedirect => {
                Some(&STRING_TO_RESPONSE)
            }
            Self::ServerWithStatus => Some(&SERVER_WITH_STATUS),
            Self::ServerWithHeader => Some(&SERVER_WITH_HEADER),
            Self::ServerWithCookie => Some(&SERVER_WITH_COOKIE),
            // Middleware wrappers (arrow spines over the response record).
            Self::MiddlewareWithLogging | Self::MiddlewareWithCsrf => Some(&MIDDLEWARE_TRANSFORM),
            Self::MiddlewareWithCors => Some(&MIDDLEWARE_WITH_CORS),
            Self::MiddlewareWithBasicAuth => Some(&MIDDLEWARE_WITH_BASIC_AUTH),
            Self::MiddlewareWithRateLimit => Some(&MIDDLEWARE_WITH_RATE_LIMIT),
            // Server-side / client-side streaming and WebSocket upgrade.
            Self::StreamStream => Some(&STREAM_STREAM),
            Self::HttpStreamOpen => Some(&HTTP_STREAM_OPEN),
            Self::WsUpgrade => Some(&WS_UPGRADE),
            // Csv.
            Self::CsvParse => Some(&CSV_PARSE),
            Self::CsvParseWithDelimiter => Some(&CSV_PARSE_WITH_DELIMITER),
            Self::CsvEncode => Some(&CSV_ENCODE),
            Self::CsvEncodeWithDelimiter => Some(&CSV_ENCODE_WITH_DELIMITER),
            // Cache.
            Self::CacheNewRaw => Some(&CACHE_NEW_RAW),
            Self::CacheStats => Some(&CACHE_STATS_KERNEL),
            // WebSocket client.
            Self::WebSocketConnectWith => Some(&WS_CONNECT_WITH),
            // Email.
            Self::EmailSend => Some(&EMAIL_SEND),
            // RetryPolicy.
            Self::TaskLinearBackoff | Self::TaskExponentialBackoff => Some(&TASK_BACKOFF),
            Self::TaskWithJitter => Some(&RETRY_POLICY_TO_RETRY_POLICY),
            Self::TaskRetryOn | Self::TaskWithRetryOn => Some(&RETRY_ON),
            Self::TaskDefaultRetryPolicy => Some(&RETRY_POLICY),
            Self::TaskWithMaxAttempts | Self::TaskWithBaseMs => Some(&INT_TO_RETRY_TO_RETRY),
            Self::TaskRetryWith => Some(&RETRY_WITH),
            // App-entry cfg records.
            Self::WebApp => Some(&WEB_APP),
            Self::WebEmbed => Some(&WEB_EMBED),
            Self::TerminalAppScreen => Some(&TERMINAL_APP_SCREEN),
            Self::TerminalAppLines => Some(&TERMINAL_APP_LINES),
            Self::TeaWorker => Some(&WORKER_APP),
            // Ui / Input / Border record builders.
            Self::UiLayoutWith => Some(&LAYOUT_WITH),
            Self::UiButton => Some(&BUTTON),
            Self::UiPaddingEach => Some(&PADDING_EACH),
            Self::UiLink => Some(&LINK),
            Self::UiImage => Some(&IMAGE),
            Self::BorderWidthEach => Some(&WIDTH_EACH),
            Self::BorderShadow | Self::BorderInnerShadow => Some(&SHADOW_ATTR),
            Self::InputText
            | Self::InputEmail
            | Self::InputUsername
            | Self::InputSearch
            | Self::InputCurrentPassword
            | Self::InputNewPassword => Some(&INPUT_TEXT),
            Self::InputMultiline => Some(&INPUT_MULTILINE),
            Self::InputCheckbox => Some(&INPUT_CHECKBOX),
            Self::InputSlider => Some(&INPUT_SLIDER),
            Self::InputRadio | Self::InputRadioRow => Some(&INPUT_RADIO),

            // ── Ipe.Decimal. ──
            Self::DecZero | Self::DecOne | Self::DecOneHundred => Some(&DECIMAL),
            Self::DecFromString => Some(&STRING_TO_RESULT_ERR_DECIMAL),
            Self::DecFromInt => Some(&INT_TO_DECIMAL),
            Self::DecFromFloat => Some(&FLOAT_TO_DECIMAL),
            Self::DecFromMinor => Some(&INT_TO_INT_TO_DECIMAL),
            Self::DecToString => Some(&DECIMAL_TO_STRING),
            Self::DecToStringFixed => Some(&INT_TO_DECIMAL_TO_STRING),
            Self::DecToFloat => Some(&DECIMAL_TO_FLOAT),
            Self::DecToInt => Some(&DECIMAL_TO_INT),
            Self::DecToMinor => Some(&INT_TO_DECIMAL_TO_INT),
            Self::DecAdd
            | Self::DecSub
            | Self::DecMul
            | Self::DecMin
            | Self::DecMax
            | Self::DecPercentOf
            | Self::DecAddPercent
            | Self::DecSubPercent => Some(&DECIMAL_TO_DECIMAL_TO_DECIMAL),
            Self::DecDiv | Self::DecMod => Some(&DECIMAL_TO_DECIMAL_TO_RESULT_ERR_DECIMAL),
            Self::DecNeg | Self::DecAbs | Self::DecFloor | Self::DecCeil => {
                Some(&DECIMAL_TO_DECIMAL)
            }
            Self::DecRound | Self::DecRoundHalfUp | Self::DecTruncate => {
                Some(&INT_TO_DECIMAL_TO_DECIMAL)
            }
            Self::DecCompare => Some(&DECIMAL_TO_DECIMAL_TO_INT),
            Self::DecEq
            | Self::DecNeq
            | Self::DecLt
            | Self::DecLte
            | Self::DecGt
            | Self::DecGte => Some(&DECIMAL_TO_DECIMAL_TO_BOOL),
            Self::DecIsZero | Self::DecIsPositive | Self::DecIsNegative => Some(&DECIMAL_TO_BOOL),
            Self::DecFormatWith => Some(&STRING_TO_STRING_TO_INT_TO_DECIMAL_TO_STRING),

            // ── Ipe.Money (ISO-code-taking kernels over Decimal). ──
            Self::MoneyFormat | Self::MoneyFormatWithCode => Some(&STRING_TO_DECIMAL_TO_STRING),
            Self::MoneyAllocate => Some(&MONEY_ALLOCATE),
            Self::MoneySetRate => Some(&MONEY_SET_RATE),
            Self::MoneyGetRate => Some(&MONEY_GET_RATE),
            Self::MoneyClearRates => Some(&UNIT_TO_RESULT_ERR_UNIT),

            // ── Ipe.App runtime-config front door / Ipe.Web settings. ──
            Self::AppFromEnv | Self::AppFromEnvRequired => Some(&STRING_TO_SECRET),
            Self::HostBind => Some(&HOST_MODE_TO_SETTING_A),
            Self::LogLevelSetting => Some(&LOG_LEVEL_TO_SETTING_A),
            Self::DbUrlSetting
            | Self::ConsoleAdminToken
            | Self::ConsoleIngestToken
            | Self::ConsoleMetricsToken => Some(&SECRET_TO_SETTING_A),
            Self::WebCsrf => Some(&CSRF_MODE_TO_SETTING_WEB),
            Self::WebSessionTtl | Self::WebAuthMaxLifetime | Self::WebAuthSlideWindow => {
                Some(&INT_TO_SETTING_WEB)
            }
            Self::WebAuthRevocationMode => Some(&REVOCATION_MODE_TO_SETTING_WEB),
            Self::WebAppWith => Some(&WEB_APP_WITH),
            Self::WebRoute => Some(&WEB_ROUTE_KERNEL),
            Self::WebRenderStatic => Some(&WEB_RENDER_STATIC),

            // ── Ipe.Cache raw-Int-handle read/write. ──
            Self::CacheGet => Some(&CACHE_GET),
            Self::CachePut => Some(&CACHE_PUT),
            Self::CacheRemove => Some(&CACHE_REMOVE),
            Self::CacheClear => Some(&CACHE_CLEAR),
            Self::CacheSize => Some(&CACHE_SIZE),
            // `Cache.destroyRaw : Int -> Task ()` — same shape as `clearRaw`.
            Self::CacheDestroyRaw => Some(&CACHE_CLEAR),

            // ── Ipe.Secret.use. ──
            Self::SecretUse => Some(&SECRET_USE),

            // ── Ipe.Csv streaming parse. ──
            Self::CsvParseStreamFromFile => Some(&CSV_PARSE_STREAM_FROM_FILE),

            // ── Border.glow. ──
            Self::BorderGlow => Some(&BORDER_GLOW),

            // ── Ipe.Db.Store query algebra. ──
            Self::StoreJoin => Some(&STORE_JOIN),
            Self::StoreSelect => Some(&STORE_SELECT),
            Self::StoreLiteral => Some(&A_TO_A_IDENT),
            Self::StoreUpper | Self::StoreLower => Some(&STRING_TO_STRING),
            Self::StoreCoalesce | Self::StoreAdd | Self::StoreSub | Self::StoreMul => {
                Some(&A_TO_A_TO_A_STORE)
            }
            Self::StoreEqCol
            | Self::StoreNeqCol
            | Self::StoreGtCol
            | Self::StoreGteCol
            | Self::StoreLtCol
            | Self::StoreLteCol => Some(&STORE_EQ_COL),
            Self::StoreEqBy
            | Self::StoreNeqBy
            | Self::StoreGtBy
            | Self::StoreGteBy
            | Self::StoreLtBy
            | Self::StoreLteBy => Some(&STORE_EQ_BY),
            Self::StoreLike => Some(&STORE_LIKE),
            Self::StoreIsNull | Self::StoreNotNull => Some(&STORE_IS_NULL),
            Self::StoreInListCol => Some(&STORE_IN_LIST_COL),
            Self::StoreInListBy => Some(&STORE_IN_LIST_BY),
            Self::StorePrimaryKey
            | Self::StoreSerial
            | Self::StoreUnique
            | Self::StoreDefaultNow
            | Self::StoreTouchOnUpdate => Some(&STORE_SCHEMA_BUILDER),
            Self::StoreDefaultText => Some(&STORE_DEFAULT_TEXT),
            Self::StoreDefaultInt => Some(&STORE_DEFAULT_INT),
            Self::StoreCompositePrimaryKey2 => Some(&STORE_COMPOSITE_PK2),
            Self::StoreCompositePrimaryKey3 => Some(&STORE_COMPOSITE_PK3),
            Self::StoreOwnerColumn | Self::StoreImmutable => Some(&STORE_POLICY_BUILDER),
            Self::StoreMask => Some(&STORE_MASK),
            Self::StoreCorrelate => Some(&STORE_CORRELATE),
            Self::StoreExistsIn => Some(&STORE_EXISTS_IN),
            Self::StoreOrderByLeft => Some(&STORE_ORDER_BY_LEFT),
            Self::StoreOrderByRight => Some(&STORE_ORDER_BY_RIGHT),

            // The ONLY unschemed kernel: `Web.appRouted`'s lowering
            // (`Feature::RoutedWebApp`) is unimplemented, so it deliberately
            // carries no scheme and its caller fails closed. An exhaustive arm (no
            // wildcard) means any NEW kernel must declare its shape here or fail to
            // compile — an unschemed-but-resolved kernel is unrepresentable.
            Self::WebAppRouted => None,
        }
    }

    /// Canonical identity + emit metadata for this kernel variant — a projection
    /// of [`Self::def`] onto the qualifier / name / arity / class / emit subset.
    ///
    /// The returned [`StdlibDecl`] is `'static` and `Copy` — safe to embed in
    /// `const` contexts. `def()` is authoritative; this reads it, so the two can
    /// never disagree.
    #[must_use]
    pub const fn decl(self) -> StdlibDecl {
        let def = self.def();
        StdlibDecl {
            qualifier: def.qualifier,
            name: def.name,
            arity: def.arity,
            class: def.class,
            emit: def.runtime_fn,
            arg_order: def.arg_order,
        }
    }

    /// The complete set of accessor-typed `Store.*` query leaves and column-spec
    /// builders whose emit symbols (`store_eq_col`, `store_serial`, …) are
    /// never-defined PLACEHOLDERS — the real work is done by the lowering
    /// accessor-intercept, which rewrites the SATURATED call inline (the `.field`
    /// accessor becomes the validated column) before the backend ever names the
    /// symbol.
    ///
    /// This is the single authoritative source (SSOT) for this set. Every site
    /// that needs to enumerate or test membership derives from this constant:
    ///
    /// * [`Self::is_accessor_intercept_placeholder`] — the membership predicate
    ///   (used by the point-free SEAL gate, IPE-L0146).
    /// * `ipe_lower`'s dispatch arms — enumerate by kernel family; each arm must
    ///   cover exactly the variants listed here (enforced by the
    ///   `accessor_intercept_dispatch_covers_ssot` test in `ipe_lower`).
    /// * `ipe-runtime-rust`'s `every_kernel_name_resolves` test — derives the
    ///   `store_*` dead-symbol allowlist from this constant at test time instead
    ///   of maintaining a parallel string list.
    pub const ACCESSOR_INTERCEPT_PLACEHOLDERS: &[Self] = &[
        // ── Join constructor — arity-4 (storeA, accA, storeB, accB) ──────────
        Self::StoreJoin,
        // ── Projection constructor — arity-2 (select lambda + joined) ────────
        Self::StoreSelect,
        // ── Literal projection element — arity-1 (value) ─────────────────────
        Self::StoreLiteral,
        // ── Unary text projection operators — arity-1 (inner column expr) ─────
        Self::StoreUpper,
        Self::StoreLower,
        // ── Binary coalesce projection operator — arity-2 (left + right) ─────
        Self::StoreCoalesce,
        // ── Binary arithmetic projection operators — arity-2 (left + right) ──
        Self::StoreAdd,
        Self::StoreSub,
        Self::StoreMul,
        // ── Query leaves — arity-2 (accessor + store) ────────────────────────
        Self::StoreEqCol,
        Self::StoreEqBy,
        Self::StoreNeqCol,
        Self::StoreNeqBy,
        Self::StoreGtCol,
        Self::StoreGtBy,
        Self::StoreGteCol,
        Self::StoreGteBy,
        Self::StoreLtCol,
        Self::StoreLtBy,
        Self::StoreLteCol,
        Self::StoreLteBy,
        Self::StoreLike,
        Self::StoreIsNull,
        Self::StoreNotNull,
        Self::StoreInListCol,
        Self::StoreInListBy,
        // ── Column-spec builders — arity-2 (accessor + store) ────────────────
        Self::StorePrimaryKey,
        Self::StoreSerial,
        Self::StoreUnique,
        Self::StoreDefaultNow,
        Self::StoreTouchOnUpdate,
        // ── Column-spec builders — arity-3 (accessor + value + store) ────────
        Self::StoreDefaultText,
        Self::StoreDefaultInt,
        // ── Composite primary keys — one accessor per key column + store ─────
        Self::StoreCompositePrimaryKey2,
        Self::StoreCompositePrimaryKey3,
        // ── Row-security policy builders — arity-1 (accessor only) ───────────
        Self::StoreOwnerColumn,
        Self::StoreImmutable,
        // ── Column-masking policy refinement — arity-3 (accessor + Pred + Policy) ─
        Self::StoreMask,
        // ── Correlated-subquery row-security — arity-2 ───────────────────────
        // `correlate` (two accessors) and `existsIn` (Secured + a two-binder
        // lambda) are both walked structurally at lowering, never emitted as a
        // runtime call.
        Self::StoreCorrelate,
        Self::StoreExistsIn,
        // ── orderBy modifiers — arity-3 (accessor + Order + Joined) ──────────
        Self::StoreOrderByLeft,
        Self::StoreOrderByRight,
    ];

    /// Returns `true` when this kernel is an accessor-intercept placeholder —
    /// one of the `Store.*` query leaves or column-spec builders listed in
    /// [`Self::ACCESSOR_INTERCEPT_PLACEHOLDERS`].
    ///
    /// These kernels have no runtime function. They are sound ONLY under direct
    /// full application, where the intercept fires. A point-free / partial
    /// application routes through eta-expansion, which would emit the raw
    /// placeholder call — accepted by the frontend but a `cargo` E0425. The
    /// lowerer uses this predicate to fail such a program closed with a typed
    /// diagnostic instead of emitting broken Rust.
    #[must_use]
    pub fn is_accessor_intercept_placeholder(self) -> bool {
        Self::ACCESSOR_INTERCEPT_PLACEHOLDERS.contains(&self)
    }

    /// The argument positions whose value this kernel moves into a `Send + Sync` box.
    ///
    /// The single source of truth for the capture-`Sync` obligation: the
    /// kernel's emitted Rust moves each listed argument into a thread-shared
    /// carrier (`Box<dyn Fn() -> A + Send + Sync>` / an `Arc<dyn Fn + Send +
    /// Sync>` handler), so every type variable that reaches the argument's
    /// instantiated type bare must itself be `Send + Sync`. The lowerer reads the
    /// argument type off the call site's solved kernel instantiation, so the
    /// obligation holds wherever the kernel is referenced — tail or not, bound to
    /// a parameter or to any local.
    ///
    /// * `succeed` (`Json.Decode` / `Config` / `Db.Decode`) — arg 0, the value
    ///   `decode_succeed`'s factory captures.
    /// * the optional-field decoders (`JsonDecP.optional` /
    ///   `Db.Decode.optional`) — arg 2, the captured default.
    /// * `onSubmit` (`Ui` / `Event`) — arg 0, a fixed message value dispatched
    ///   from a thread-shared handler (a function-typed handler never reaches a
    ///   type variable bare, so the decoder form obliges nothing).
    #[must_use]
    pub const fn sync_captured_args(self) -> &'static [usize] {
        match self {
            Self::JsonDecSucceed
            | Self::ConfigSucceed
            | Self::DbDecSucceed
            | Self::UiOnSubmit
            | Self::HtmlOnSubmit => &[0],
            Self::JsonDecPOptional | Self::DbDecOptional => &[2],
            _ => &[],
        }
    }

    /// The scheme variables ([`TyShape::Var`] indices) this kernel's runtime call bounds `Sync`.
    ///
    /// The sibling of [`Self::sync_captured_args`] for a `Sync` bound no argument
    /// exposes bare: the runtime function puts `Sync` on a type parameter the Ipê
    /// scheme spells only as a constructor argument (the `msg` of `Element msg`),
    /// so the obligation is keyed on the scheme variable. The lowerer reads the
    /// variable's instantiation off the call site's solved kernel type, and every
    /// generic reaching that instantiation bare becomes `Send + Sync`.
    ///
    /// * `Input.checkbox` / `Input.radio` / `Input.radioRow` — var 0, the `msg`
    ///   bound `M: Clone + Send + Sync` by `input_checkbox_` / `input_radio_` /
    ///   `input_radio_row_`.
    ///
    /// Every listed variable occurs in the kernel's [`Self::scheme_shape`] at a
    /// position the lowerer aligns (an arrow, constructor-argument, or tuple
    /// slot — not only under a record field); the build asserts it
    /// ([`sync_obliged_scheme_vars_are_aligned`]).
    #[must_use]
    pub const fn sync_obliged_scheme_vars(self) -> &'static [u8] {
        match self {
            Self::InputCheckbox | Self::InputRadio | Self::InputRadioRow => &[0],
            _ => &[],
        }
    }

    /// The scheme variables returned by callbacks this kernel applies at a fixed arity.
    ///
    /// Each carries the higher-order-kernel callback-result obligation: the
    /// runtime kernel takes an exact-arity closure while the IR flattens a
    /// curried Ipê function into one multi-parameter function, so a callback
    /// whose final result is itself an arrow has no sound lowering. Derived
    /// from the scheme by [`callback_result_vars`], so every schemed
    /// higher-order kernel is covered without a list to keep in sync.
    ///
    /// Empty, by scope, for:
    /// * an unschemed kernel — no shape to classify;
    /// * a kernel outside [`KernelClass::Pure`] — its callbacks are message
    ///   handlers and column getters whose result is a caller-generic `msg` or
    ///   row variable, which the fail-closed obligation would refuse in every
    ///   generic view or schema helper;
    /// * a kernel yielding an opaque boxed wrapper
    ///   ([`BuiltinTag::is_opaque_boxed_wrapper`]) — it defers its callback, and
    ///   the decoder pipeline curries by design.
    #[must_use]
    pub const fn hof_result_vars(self) -> CallbackResults {
        let def = self.identity();
        let Some(shape) = self.scheme_shape() else {
            return CallbackResults::EMPTY;
        };
        let defers = matches!(
            applied_result(shape, def.arity),
            Some(TyShape::Con(tag, _)) if tag.is_opaque_boxed_wrapper()
        );
        if defers || !matches!(def.class, KernelClass::Pure) {
            return CallbackResults::EMPTY;
        }
        callback_result_vars(shape, def.arity)
    }

    /// The conditionally-vendored runtime module this kernel's emitted symbol
    /// needs, when that module is NOT already pulled in by the kernel's emit
    /// [`KernelClass`]. `None` for the common case (symbol lives in the module
    /// the class declares, or in the always-present base set).
    ///
    /// This closes the module-set SEAL breach class: a kernel whose `rust_name`
    /// resolves to a feature-module the class does not declare MUST report that
    /// module here so the lowerer sets the matching `uses_*` flag. Keep this in
    /// lockstep with the emit table (`decl().emit`) — the `runtime_module_closure`
    /// backend test asserts every emitted crate is module-closed for every
    /// reachable flag combination, so a missing entry fails at `ipe` build time,
    /// never as a downstream `cargo` E0425/E0412.
    #[must_use]
    pub const fn required_runtime_module(self) -> Option<RuntimeModule> {
        match self {
            // `cmd_publish` / `cmd_publish_no_echo` / `sub_subscribe_topic` are
            // `class = Tea` (they dispatch through the standard TEA emit path) but
            // their runtime symbols are defined ONLY in `ipe_runtime::web::pubsub`
            // — the `live` module. Without this the `live` append never fires and
            // the emitted `main.rs` references undefined `cmd_publish` (E0425).
            Self::CmdPublish | Self::CmdPublishNoEcho | Self::SubSubscribeTopic => {
                Some(RuntimeModule::Web)
            }
            // `pubsub_publish` / `pubsub_publish_no_echo` are `class = Web` and
            // also `is_web`, so the `live` append fires via the `is_web` path in
            // the lowerer. Recording them here too keeps this function the complete
            // SSOT: every kernel whose emitted symbol diverges from its class's
            // module home is listed, whether or not a parallel predicate already
            // covers it. (`class = Web`'s home is the `web` module; the symbols
            // live in its `web::pubsub` submodule, gated by the `web` feature.)
            Self::PubSubPublish | Self::PubSubPublishNoEcho => Some(RuntimeModule::Web),
            // `HttpStream.chunks` is `class = Pure` but emits `sub_subscribe_stream`
            // and the `IpeStreamId` type, both defined in `ipe_runtime::http_stream`
            // — declared only by the `server` append. Its siblings
            // (`open`/`forEachChunk`/`close`) are `is_server` and ride along, but
            // `chunks` can be reached with a param-supplied `StreamId` and no `open`
            // in the same module set (E0412 `IpeStreamId` + E0425 otherwise).
            Self::HttpStreamChunks => Some(RuntimeModule::Server),
            // The `Ipe.Cache` family is `class = Pure` (task-returning handle
            // ops), but every `cache_*` symbol, `CacheCfg` / `CacheStats`, and the
            // `IpeCacheHandle` enum live in `ipe_runtime::cache` — a standalone
            // feature-module no emit-class pulls in. Declaring the module here is
            // the SSOT that gates the `cache` append (the lowerer additionally
            // forces the module on a bare `CacheCfg` / `CacheStats` / handle
            // type-mention with no kernel call — see `ir_type_mentions_cache`
            // and `ir_type_mentions_cache_handle`).
            Self::CacheNewRaw
            | Self::CacheGet
            | Self::CachePut
            | Self::CacheRemove
            | Self::CacheClear
            | Self::CacheSize
            | Self::CacheStats
            | Self::CacheDestroyRaw => Some(RuntimeModule::Cache),
            // The `Ipe.Random` family is `class = Pure` but its `random_*` draw
            // symbols live only in `ipe_runtime::random` — a standalone
            // feature-module no emit-class pulls in. Declaring the module here is
            // the SSOT that gates the `random` append. (The seeded generators are
            // pure/deterministic but still emit `random_seeded_*` from `random.rs`,
            // so they share the module.)
            Self::RandomInt
            | Self::RandomFloat
            | Self::RandomChoice
            | Self::RandomChoiceMaybe
            | Self::RandomShuffle
            | Self::RandomWeighted
            | Self::RandomSeededInt
            | Self::RandomSeededFloat
            | Self::RandomSeededChoice => Some(RuntimeModule::Random),
            _ => None,
        }
    }

    /// The security-relevant capability this kernel exercises, or `None` when it
    /// is pure. Classified by effect family: HTTP / server / WebSocket / email →
    /// [`Capability::Network`]; file / database / config-and-`.env`-file reads →
    /// [`Capability::Filesystem`]; environment-variable and argv reads →
    /// [`Capability::Env`]; wall-clock / sleep / timer → [`Capability::Clock`];
    /// RNG / random tokens / UUIDs → [`Capability::Random`]. `Env.public` reads
    /// the live process environment on native (a per-call `std::env::var`), so it
    /// discloses [`Capability::Env`] like `System.getenv`; only its wasm32
    /// emission is a build-time constant, and over-reporting there is the
    /// fail-closed direction. `Trace.*` write only to an observability sink, and
    /// `Io.*` only to the console, so neither is a sandboxed capability.
    ///
    /// The match is exhaustive with no `_` arm: a newly-added kernel cannot
    /// compile until it is classified here, so a program's inferred capability
    /// set cannot silently drift as the stdlib grows.
    ///
    /// This is the single classifying match that populates [`KernelDef::capability`].
    /// It is private: every consumer reads the capability off the [`KernelDef`]
    /// row that [`Self::def`] returns, so the fact has exactly one public home.
    #[allow(clippy::too_many_lines)]
    const fn capability_classification(self) -> Option<Capability> {
        match self {
            Self::HttpGet
            | Self::HttpPost
            | Self::HttpRequest
            | Self::ServerGet
            | Self::ServerPost
            | Self::ServerPut
            | Self::ServerDelete
            | Self::ServerAny
            | Self::ServerApi
            | Self::ServerStatic
            | Self::ServerMountApp
            | Self::ServerListen
            | Self::ServerText
            | Self::ServerJson
            | Self::ServerHtml
            | Self::ServerWithStatus
            | Self::ServerWithHeader
            | Self::ServerRedirect
            | Self::ServerParam
            | Self::ServerQueryParam
            | Self::ServerHeader
            | Self::ServerGetCookie
            | Self::ServerBody
            | Self::ServerPath
            | Self::ServerMethod
            | Self::ServerCookieNew
            | Self::ServerWithCookie
            | Self::ServerAuthConfig
            | Self::ServerTokenBearer
            | Self::ServerCookieToken
            | Self::ServerWithRevocation
            | Self::ServerGetAuthed
            | Self::ServerPostAuthed
            | Self::ServerPutAuthed
            | Self::ServerDeleteAuthed
            | Self::MiddlewareWithCors
            | Self::MiddlewareWithLogging
            | Self::MiddlewareWithBasicAuth
            | Self::MiddlewareWithRateLimit
            | Self::MiddlewareWithCsrf
            | Self::RateLimitAllow
            | Self::StreamStream
            | Self::StreamEmit
            | Self::StreamFinish
            | Self::StreamWithContentType
            | Self::HttpStreamOpen
            | Self::HttpStreamForEachChunk
            | Self::HttpStreamClose
            | Self::HttpStreamChunks
            | Self::WsDefaultCfg
            | Self::WsWithOnConnect
            | Self::WsWithOnMessage
            | Self::WsWithOnClose
            | Self::WsWithOnError
            | Self::WsWithMaxMessageBytes
            | Self::WsWithOriginPatterns
            | Self::WsUpgrade
            | Self::WsSendToClient
            | Self::WsSendBinaryToClient
            | Self::WsBroadcast
            | Self::WsCloseClient
            | Self::WebSocketConnect
            | Self::WebSocketConnectWith
            | Self::WebSocketSend
            | Self::WebSocketSendBinary
            | Self::WebSocketClose
            | Self::WebSocketCloseWithCode
            | Self::SubSubscribeWebSocket
            | Self::EmailSend
            // Connecting a `Dsn` to a live EXTERNAL host reaches an arbitrary
            // network endpoint of the program's choosing — the enforceable egress
            // axis an OS jail isolates, the same `network` `Http` discloses.
            // (`database` semantics come from the `Db` module residency; the
            // capability model tags one enforceable axis per kernel, and the
            // external act's isolatable resource is the network host.)
            | Self::DbConnOpen => Some(Capability::Network),
            Self::SystemCwd
            | Self::SystemGetcwd
            | Self::PathAbsolute
            | Self::SystemLoadEnv
            | Self::FileReadFile
            | Self::FileWriteFile
            | Self::FileExists
            | Self::FileRemove
            | Self::FileMkdirAll
            | Self::FileReadFileLimit
            | Self::FileReadFileBytes
            | Self::FileAppend
            | Self::FileReadDir
            | Self::FileIsDir
            | Self::FileTempFile
            | Self::FileTempDir
            | Self::FileCopy
            | Self::FileRename
            | Self::FileDelete
            | Self::FileWalk
            | Self::FileWalkMatching
            | Self::CsvParseStreamFromFile
            | Self::ConfigLoadFromFile => Some(Capability::Filesystem),
            Self::DbConnect
            | Self::DbOpen
            | Self::DbClose
            | Self::DbExecRaw
            | Self::DbExec
            | Self::DbQuery
            | Self::DbQueryDecode
            | Self::DbGetString
            | Self::DbGetInt
            | Self::DbGetBool
            | Self::DbGetField
            | Self::DbInsertRow
            | Self::DbGetById
            | Self::DbUpdateById
            | Self::DbDeleteById
            | Self::DbFindOneByField
            | Self::DbFindManyByField
            | Self::DbFindByConditions
            | Self::DbInsertFields
            | Self::DbUpdateFields
            | Self::DbInsertFieldsReturning
            | Self::DbWithTransaction
            | Self::DbMigrate
            | Self::DbFindWhere
            | Self::DbFindWhereMasked
            | Self::DbFindJoin
            | Self::DbFindProjection
            | Self::DbFindJoinOrdered
            | Self::DbFindProjectionOrdered
            | Self::DbDeleteWhere
            | Self::DbUpdateWhere
            | Self::DbUpsertFields
            | Self::DbInsertFieldsChecked
            | Self::DbUpdateWhereChecked
            | Self::DbDefaultMigration
            | Self::DbDecString
            | Self::DbDecInt
            | Self::DbDecFloat
            | Self::DbDecBool
            | Self::DbDecNullable
            | Self::DbDecMap
            | Self::DbDecAndThen
            | Self::DbDecSucceed
            | Self::DbDecFail
            | Self::DbDecMap2
            | Self::DbDecMap3
            | Self::DbDecMap4
            | Self::DbDecRequired
            | Self::DbDecOptional
            | Self::DbDecMoney
            | Self::DbDecDecimal
            | Self::DbDecBytes
            // Closing an external pool and executing against an already-open one
            // touch a database but reach no NEW network host — `database`, the
            // same axis the app-connection query kernels disclose.
            | Self::DbConnClose
            | Self::DbConnUnsafeExecRawOn
            // External reads: the connection already disclosed `network` at
            // `open`; a read against it is a database op (like every other read).
            | Self::DbConnFindWhere
            | Self::DbConnQueryDecode
            | Self::DbConnGetById
            // Auth kernels that take a live `Db` handle and run CREATE TABLE /
            // INSERT / SELECT / UPDATE through it — a database op like every other
            // handle-consuming kernel, disclosed as `database` for capability honesty.
            | Self::AuthRegister
            | Self::AuthLogin
            | Self::AuthSetRole => Some(Capability::Database),
            Self::SystemArgs
            | Self::SystemGetenv
            | Self::SystemGetenvOr
            | Self::SystemGetArg
            | Self::SystemGetenvInt
            | Self::SystemGetenvBool
            | Self::SystemSetenv
            | Self::SystemUnsetenv
            // The native emission of `Env.public` is a per-call `std::env::var`
            // read of the live process environment, so it discloses the same env
            // axis as `System.getenv`. (Only the wasm32 emission is a
            // build-time-embedded constant.) Reporting `Env` on both targets is
            // the fail-closed direction: it over-reports on wasm32 at no cost,
            // and it re-injects the allowlisted keys into the scrubbed jail
            // environment so `Env.public` does not silently return `Nothing`.
            | Self::EnvPublic
            // `App.fromEnv` / `App.fromEnvRequired` read a CALLER-NAMED
            // environment variable at startup (`read_env_var` →
            // `std::env::var`) and seal it into a `Secret`. That live process-env
            // read is the same enforceable env axis `System.getenv` discloses —
            // the resource an OS jail isolates by scrubbing the environment.
            // Unlike the sibling `Setting`-builders (`Db.url`, `Console.*Token`),
            // which only wrap an already-obtained value, THESE kernels perform
            // the read, so under-reporting them would hide a real env dependency
            // (and silently break under a scrubbed jail) — the fail-closed
            // direction discloses `Env`.
            | Self::AppFromEnv
            | Self::AppFromEnvRequired => Some(Capability::Env),
            Self::ProcessRun | Self::ProcessRunWith | Self::ProcessRunInPty => {
                Some(Capability::Subprocess)
            }
            // `CustomElement.node` places a browser custom-element widget: its reachable
            // presence means the program serves author-written JS that runs in
            // the page with full DOM authority. That shipped-JS surface is a
            // security-relevant disclosure (declared trust, SRI-pinned but not
            // sandboxed) — the `custom-element` axis. The `CustomElement.fromFile "<path>"`
            // handle is a reserved constructor, not a kernel, and only `CustomElement.node`
            // consumes it, so tagging this one kernel is the whole inference point:
            // any module whose reachable code binds a widget discloses the axis.
            Self::UiWidget => Some(Capability::CustomElement),
            // `Js.send` / `Js.subscribe` exchange typed values with page JS over
            // the raw port transport: their reachable presence means the program
            // talks to attacker-controlled browser JavaScript, gated only by the
            // seal type (outbound) and the fail-closed seal decoder (inbound). That
            // is a security-relevant declared-trust disclosure — the `js-port`
            // axis. Tagging these two kernels is the whole inference point: any
            // module whose reachable code binds a port discloses the axis, through
            // the same SSOT the other axes use. The kernel cannot see which Web API
            // the hand-written JS behind the port reaches, so it discloses the
            // uncharacterised `:raw` floor — the reachability floor no port slips
            // below. A characterised `Ipe.Browser.<Api>` import adds its specific
            // web axis on top, import-derived (see the whole-program scan).
            Self::JsSend
            | Self::JsSubscribe
            | Self::JsRequest
            | Self::JsOpenSession
            | Self::JsSessionFrames
            | Self::JsSendToSession
            | Self::JsCloseSession => Some(Capability::JsPort(WebCapability::Raw)),
            Self::TimeNow
            | Self::TimeSleep
            | Self::TimeUnixMillis
            | Self::TimeTimeString
            | Self::SubEvery
            | Self::TimeEvery
            // Validates a token's `exp` / `nbf` against the wall clock (`SystemTime::now`).
            | Self::AuthVerifyToken => Some(Capability::Clock),
            Self::CryptoRandomBytes
            | Self::CryptoRandomToken
            | Self::UuidV4
            | Self::UuidV7
            | Self::RandomInt
            | Self::RandomFloat
            | Self::RandomChoice
            | Self::RandomChoiceMaybe
            | Self::RandomShuffle
            | Self::RandomWeighted
            // Mints a random `jti` from OS entropy (also reads the clock for `iat`;
            // the entropy draw is the security-relevant disclosure).
            | Self::AuthSignToken => Some(Capability::Random),
            Self::LogInfo
            | Self::LogDebug
            | Self::LogWarn
            | Self::LogError
            | Self::LogInfoWith
            | Self::LogDebugWith
            | Self::LogWarnWith
            | Self::LogErrorWith
            | Self::DebugLog
            | Self::StringFromInt
            | Self::StringFromFloat
            | Self::StringLength
            | Self::StringIsEmpty
            | Self::StringReverse
            | Self::StringToUpper
            | Self::StringToLower
            | Self::StringCasefold
            | Self::StringTrim
            | Self::StringTrimStart
            | Self::StringTrimEnd
            | Self::StringToInt
            | Self::StringToFloat
            | Self::StringFromChar
            | Self::StringFromBool
            | Self::StringFromList
            | Self::StringConcat
            | Self::StringWords
            | Self::StringLines
            | Self::StringToList
            | Self::StringIsEmail
            | Self::StringIsUrl
            | Self::StringAppend
            | Self::StringContains
            | Self::StringStartsWith
            | Self::StringEndsWith
            | Self::StringEqualFold
            | Self::StringJoin
            | Self::StringSplit
            | Self::StringRepeat
            | Self::StringDropLeft
            | Self::StringDropRight
            | Self::StringReplace
            | Self::StringSlice
            | Self::StringPadLeft
            | Self::StringPadRight
            | Self::StringContainsIn
            | Self::StringStartsWithIn
            | Self::StringEndsWithIn
            | Self::StringLeft
            | Self::StringRight
            | Self::StringCons
            | Self::StringUncons
            | Self::StringPad
            | Self::StringIndexes
            | Self::StringMap
            | Self::StringFilter
            | Self::StringFoldl
            | Self::StringFoldr
            | Self::StringAny
            | Self::StringAll
            | Self::CharIsAlpha
            | Self::CharIsDigit
            | Self::CharIsLower
            | Self::CharIsUpper
            | Self::CharToLower
            | Self::CharToUpper
            | Self::CharToCode
            | Self::CharFromCode
            | Self::CharIsAlphaNum
            | Self::CharIsHexDigit
            | Self::CharIsOctDigit
            | Self::StoreJoin
            | Self::StoreSelect
            | Self::StoreLiteral
            | Self::StoreUpper
            | Self::StoreLower
            | Self::StoreCoalesce
            | Self::StoreAdd
            | Self::StoreSub
            | Self::StoreMul
            | Self::StoreEqCol
            | Self::StoreEqBy
            | Self::StoreNeqCol
            | Self::StoreNeqBy
            | Self::StoreGtCol
            | Self::StoreGtBy
            | Self::StoreGteCol
            | Self::StoreGteBy
            | Self::StoreLtCol
            | Self::StoreLtBy
            | Self::StoreLteCol
            | Self::StoreLteBy
            | Self::StoreLike
            | Self::StoreIsNull
            | Self::StoreNotNull
            | Self::StoreInListCol
            | Self::StoreInListBy
            | Self::StorePrimaryKey
            | Self::StoreSerial
            | Self::StoreUnique
            | Self::StoreDefaultNow
            | Self::StoreTouchOnUpdate
            | Self::StoreDefaultText
            | Self::StoreDefaultInt
            | Self::StoreCompositePrimaryKey2
            | Self::StoreCompositePrimaryKey3
            | Self::StoreOwnerColumn
            | Self::StoreImmutable
            | Self::StoreMask
            | Self::StoreCorrelate
            | Self::StoreExistsIn
            | Self::StoreOrderByLeft
            | Self::StoreOrderByRight
            | Self::ListMap
            | Self::ListFilter
            | Self::ListFoldl
            | Self::ListFoldr
            | Self::ListLength
            | Self::ListHead
            | Self::ListTail
            | Self::ListMember
            | Self::ListRange
            | Self::ListReverse
            | Self::ListAppend
            | Self::ListConcat
            | Self::ListTake
            | Self::ListDrop
            | Self::ListZip
            | Self::ListCons
            | Self::ListIsEmpty
            | Self::ListConcatMap
            | Self::ListIndexedMap
            | Self::ListAny
            | Self::ListAll
            | Self::ListFind
            | Self::ListFilterMap
            | Self::ListSortBy
            | Self::ListSort
            | Self::ListSortWith
            | Self::ListSingleton
            | Self::ListRepeat
            | Self::ListSum
            | Self::ListProduct
            | Self::ListMaximum
            | Self::ListMinimum
            | Self::ListUnique
            | Self::ListIntersperse
            | Self::ListPartition
            | Self::ListUnzip
            | Self::ListMap2
            | Self::ListMap3
            | Self::ListMap4
            | Self::ListMap5
            | Self::BasicsNot
            | Self::BasicsIdentity
            | Self::BasicsAlways
            | Self::BasicsFst
            | Self::BasicsSnd
            | Self::BasicsModBy
            | Self::BasicsClamp
            | Self::Interpolate
            | Self::BasicsNegate
            | Self::BasicsAbs
            | Self::BasicsSqrt
            | Self::BasicsMin
            | Self::BasicsMax
            | Self::BasicsCompare
            | Self::ErrorUnexpected
            | Self::ErrorInvalidInput
            | Self::ErrorIo
            | Self::ErrorNetwork
            | Self::ErrorFfi
            | Self::ErrorDecode
            | Self::ErrorConflict
            | Self::ErrorUnavailable
            | Self::ErrorTimeout
            | Self::ErrorNotFound
            | Self::ErrorPermissionDenied
            | Self::ErrorToString
            | Self::ErrorWithMessage
            | Self::ErrorIsRetryable
            | Self::ErrorWithDetails
            | Self::ErrorKind
            | Self::ErrorMessage
            | Self::ErrorKindName
            | Self::CssSafetySafeValue
            | Self::CssSafetySafePropName
            | Self::CssSafetySafeSelector
            | Self::CssSafetySanitizeRawBody
            | Self::CssSafetyStripStyleClose
            | Self::MaybeWithDefault
            | Self::MaybeMap
            | Self::MaybeAndThen
            | Self::MaybeMap2
            | Self::MaybeMap3
            | Self::MaybeMap4
            | Self::MaybeMap5
            | Self::MaybeAndMap
            | Self::MaybeCombine
            | Self::MaybeIsJust
            | Self::MaybeIsNothing
            | Self::ResultWithDefault
            | Self::ResultMap
            | Self::ResultAndThen
            | Self::ResultMapError
            | Self::ResultMap2
            | Self::ResultMap3
            | Self::ResultMap4
            | Self::ResultMap5
            | Self::ResultAndMap
            | Self::ResultCombine
            | Self::ResultTraverse
            | Self::ResultToMaybe
            | Self::ResultFromMaybe
            | Self::ResultOkDefault
            | Self::MathMin
            | Self::MathMax
            | Self::MathPi
            | Self::MathE
            | Self::MathPhi
            | Self::MathSqrt2
            | Self::MathInf
            | Self::MathNan
            | Self::MathIsNaN
            | Self::MathAbs
            | Self::MathSqrt
            | Self::MathCbrt
            | Self::MathExp
            | Self::MathExp2
            | Self::MathLog
            | Self::MathLog2
            | Self::MathLog10
            | Self::MathSin
            | Self::MathCos
            | Self::MathTan
            | Self::MathAsin
            | Self::MathAcos
            | Self::MathAtan
            | Self::MathSinh
            | Self::MathCosh
            | Self::MathTanh
            | Self::MathAsinh
            | Self::MathAcosh
            | Self::MathAtanh
            | Self::MathFloor
            | Self::MathCeil
            | Self::MathRound
            | Self::MathTrunc
            | Self::MathPow
            | Self::MathHypot
            | Self::MathAtan2
            | Self::MathMod
            | Self::MathRemainder
            | Self::BitwiseAnd
            | Self::BitwiseOr
            | Self::BitwiseXor
            | Self::BitwiseComplement
            | Self::BitwiseShiftLeftBy
            | Self::BitwiseShiftRightBy
            | Self::BitwiseShiftRightZfBy
            // Seeded Random draws are PURE/deterministic (no entropy), so they
            // carry no `Random` capability — unlike the entropy-backed
            // `RandomInt`/`RandomFloat`/`RandomChoice` above.
            | Self::RandomSeededInt
            | Self::RandomSeededFloat
            | Self::RandomSeededChoice
            | Self::DictEmpty
            | Self::DictIsEmpty
            | Self::DictSize
            | Self::DictKeys
            | Self::DictValues
            | Self::DictToList
            | Self::DictFromList
            | Self::DictGet
            | Self::DictMember
            | Self::DictRemove
            | Self::DictUnion
            | Self::DictMap
            | Self::DictInsert
            | Self::DictFoldl
            | Self::DictSingleton
            | Self::DictFoldr
            | Self::DictFilter
            | Self::DictPartition
            | Self::DictIntersect
            | Self::DictDiff
            | Self::DictUpdate
            | Self::SetEmpty
            | Self::SetSize
            | Self::SetToList
            | Self::SetFromList
            | Self::SetMember
            | Self::SetInsert
            | Self::SetRemove
            | Self::SetUnion
            | Self::SetIntersect
            | Self::SetDiff
            | Self::SetIsEmpty
            | Self::SetSingleton
            | Self::SetFoldl
            | Self::SetFoldr
            | Self::SetMap
            | Self::SetFilter
            | Self::SetPartition
            | Self::BytesEmpty
            | Self::BytesLength
            | Self::BytesIsEmpty
            | Self::BytesFromString
            | Self::BytesToString
            | Self::BytesFromHex
            | Self::BytesToHex
            | Self::BytesFromBase64
            | Self::BytesToBase64
            | Self::BytesAppend
            | Self::BytesSlice
            | Self::EncodingBase64Encode
            | Self::EncodingBase64Decode
            | Self::EncodingUrlEncode
            | Self::EncodingUrlDecode
            | Self::EncodingPercentDecode
            | Self::EncodingHexEncode
            | Self::EncodingHexDecode
            | Self::JsonEncString
            | Self::JsonEncInt
            | Self::JsonEncFloat
            | Self::JsonEncBool
            | Self::JsonEncNull
            | Self::JsonEncList
            | Self::JsonEncObject
            | Self::JsonEncEncode
            | Self::JsonDecString
            | Self::JsonDecInt
            | Self::JsonDecFloat
            | Self::JsonDecBool
            | Self::JsonDecValue
            | Self::JsonDecDecodeString
            | Self::JsonDecDecodeValue
            | Self::JsonDecField
            | Self::JsonDecAt
            | Self::JsonDecIndex
            | Self::JsonDecList
            | Self::JsonDecNullable
            | Self::JsonDecMap
            | Self::JsonDecAndThen
            | Self::JsonDecSucceed
            | Self::JsonDecFail
            | Self::JsonDecOneOf
            | Self::JsonDecMap2
            | Self::JsonDecMap3
            | Self::JsonDecMap4
            | Self::JsonDecPRequired
            | Self::JsonDecPOptional
            | Self::JsonDecPCustom
            | Self::JsonDecPRequiredAt
            | Self::CryptoSha256
            | Self::CryptoSha512
            | Self::CryptoSha1
            | Self::CryptoMd5
            | Self::CryptoRsaSha256Sign
            | Self::CryptoRsaSha256Verify
            | Self::CryptoConstantTimeEqual
            | Self::CryptoAesGcmEncrypt
            | Self::CryptoAesGcmDecrypt
            | Self::CryptoChacha20Encrypt
            | Self::CryptoChacha20Decrypt
            | Self::CryptoAesKeyFromPassword
            | Self::CryptoChachaKeyFromPassword
            | Self::UuidParse
            // The Jwt decode kernels validate `exp` / `nbf` against the wall clock,
            // an incidental read left undisclosed on purpose: Clock is pinned
            // low-value and never jail-enforced, and a decode is a pure verification
            // over its two inputs rather than a clock effect the caller selects.
            | Self::JwtEncodeHs256
            | Self::JwtDecodeHs256
            | Self::JwtEncodeRs256
            | Self::JwtDecodeRs256
            | Self::JwtClaims
            | Self::JwtHs256
            | Self::JwtRs256
            | Self::JwtSubject
            | Self::JwtIssuer
            | Self::JwtAudience
            | Self::JwtExpiresAt
            | Self::JwtNotBefore
            | Self::JwtIssuedAt
            | Self::JwtJwtId
            | Self::JwtWithClaim
            | Self::JwtEncode
            | Self::JwtDecode
            | Self::TaskSucceed
            | Self::TaskFail
            | Self::TaskMap
            | Self::TaskMap2
            | Self::TaskMap3
            | Self::TaskMap4
            | Self::TaskMap5
            | Self::TaskAttempt
            | Self::TaskAndThen
            | Self::TaskMapError
            | Self::TaskOnError
            | Self::TaskFromResult
            | Self::TaskAndThenResult
            | Self::TaskSequence
            | Self::TaskParallel
            | Self::TaskRun
            | Self::TaskPerform
            | Self::TaskLazy
            | Self::TaskLoop
            | Self::TaskRetryWith
            | Self::TaskLinearBackoff
            | Self::TaskExponentialBackoff
            | Self::TaskWithJitter
            | Self::TaskRetryOn
            | Self::TaskWithRetryOn
            | Self::TaskDefaultRetryPolicy
            | Self::TaskWithMaxAttempts
            | Self::TaskWithBaseMs
            | Self::IoReadLine
            | Self::IoReadSecret
            | Self::IoWriteStdout
            | Self::IoWriteStderr
            | Self::IoPrintln
            | Self::IoEprintln
            | Self::TimeIsLeapYear
            | Self::TimeDaysInMonth
            | Self::SystemExit
            | Self::HttpParseQuery
            | Self::HttpDefaultRequest
            | Self::HttpDefaultRequestFromString
            | Self::HttpWithMethod
            | Self::HttpWithTimeout
            | Self::HttpWithBody
            | Self::HttpWithHeader
            | Self::HttpWithUrl
            | Self::HttpWithRedirects
            | Self::CmdNone
            | Self::CmdBatch
            | Self::CmdPerform
            | Self::CmdMap
            | Self::SubNone
            | Self::SubBatch
            | Self::SubMap
            // Terminal input is the app's own stdin, read by the shape's loop;
            // no sandboxed capability beyond the terminal shape itself.
            | Self::TuiSubOnKey
            | Self::CliSubOnLine
            | Self::CmdPublish
            | Self::CmdPublishNoEcho
            | Self::SubSubscribeTopic
            | Self::PubSubPublish
            | Self::PubSubPublishNoEcho
            | Self::PubSubTopic
            | Self::UiLayout
            | Self::UiLayoutWith
            | Self::HtmlRender
            | Self::HtmlEscapeText
            | Self::HtmlEscapeAttr
            | Self::HtmlAttrToString
            | Self::UiNone
            | Self::UiText
            | Self::UiHtml
            | Self::UiCells
            | Self::UiCellsNone
            | Self::UiCellsText
            | Self::UiCellsEl
            | Self::UiCellsRow
            | Self::UiCellsColumn
            | Self::UiCellsCells
            | Self::TuiUiSpacing
            | Self::TuiUiPadding
            | Self::TuiUiAlignLeft
            | Self::TuiUiAlignRight
            | Self::TuiUiCenter
            | Self::TuiUiBold
            | Self::TuiUiUnderline
            | Self::TuiUiDim
            | Self::TuiUiReverse
            | Self::TuiUiColor
            | Self::TuiUiBg
            | Self::CliUiNone
            | Self::CliUiText
            | Self::CliUiLine
            | Self::CliUiLines
            | Self::CliUiBold
            | Self::CliUiUnderline
            | Self::CliUiDim
            | Self::CliUiReverse
            | Self::CliUiColor
            | Self::CliUiBg
            | Self::TermColorBlack
            | Self::TermColorRed
            | Self::TermColorGreen
            | Self::TermColorYellow
            | Self::TermColorBlue
            | Self::TermColorMagenta
            | Self::TermColorCyan
            | Self::TermColorWhite
            | Self::TermColorBrightBlack
            | Self::TermColorBrightRed
            | Self::TermColorBrightGreen
            | Self::TermColorBrightYellow
            | Self::TermColorBrightBlue
            | Self::TermColorBrightMagenta
            | Self::TermColorBrightCyan
            | Self::TermColorBrightWhite
            | Self::TermColorDefault
            | Self::TermColorRgb
            | Self::TermColorRgba
            | Self::ColorRgb
            | Self::ColorRgba
            | Self::ColorHsl
            | Self::ColorHsla
            | Self::ColorWhite
            | Self::ColorBlack
            | Self::ColorRed
            | Self::ColorGreen
            | Self::ColorBlue
            | Self::ColorTransparent
            | Self::ColorToCss
            | Self::ColorToCssRgba
            | Self::ColorToHex
            | Self::ColorLuminance
            | Self::ColorWithAlpha
            | Self::ColorMix
            | Self::ColorBlend
            | Self::ColorLighten
            | Self::ColorDarken
            | Self::ColorSaturate
            | Self::ColorDesaturate
            | Self::ColorRotateHue
            | Self::ColorComplementary
            | Self::ColorGrayscale
            | Self::ColorFromHex
            | Self::ColorFromName
            | Self::ColorTrueColorProfile
            | Self::ColorAnsi256Profile
            | Self::ColorAnsi16Profile
            | Self::ColorNoColorProfile
            | Self::ColorToAnsi
            | Self::ColorWcagAa
            | Self::ColorWcagAaa
            | Self::ColorNormalText
            | Self::ColorLargeText
            | Self::ColorContrastRatio
            | Self::ColorReadableTextOn
            | Self::ColorMeetsWcag
            | Self::ColorMaximumContrast
            | Self::ColorProtanopia
            | Self::ColorDeuteranopia
            | Self::ColorTritanopia
            | Self::ColorSimulate
            | Self::UiNode
            | Self::UiTaggedNode
            | Self::UiButton
            | Self::UiLink
            | Self::UiImage
            | Self::UiAbove
            | Self::UiBelow
            | Self::UiOnLeft
            | Self::UiOnRight
            | Self::UiInFront
            | Self::UiBehind
            | Self::UiSpacing
            | Self::UiPadding
            | Self::UiPaddingXY
            | Self::UiPaddingEach
            | Self::UiWidth
            | Self::UiHeight
            | Self::UiCenterX
            | Self::UiCenterY
            | Self::UiAlignLeft
            | Self::UiAlignRight
            | Self::UiAlignTop
            | Self::UiAlignBottom
            | Self::UiPointer
            | Self::UiClip
            | Self::UiClipX
            | Self::UiClipY
            | Self::UiScrollbars
            | Self::UiScrollbarX
            | Self::UiScrollbarY
            | Self::UiGridColumns
            | Self::UiPx
            | Self::UiFill
            | Self::UiContent
            | Self::UiShrink
            | Self::UiFillPortion
            | Self::UiVh
            | Self::UiVw
            | Self::UiMinimum
            | Self::UiMaximum
            | Self::UiRgb
            | Self::UiRgba
            | Self::UiWhite
            | Self::UiBlack
            | Self::UiTransparent
            | Self::UiColorCss
            | Self::BackgroundColor
            | Self::BackgroundImage
            | Self::BackgroundLinearGradient
            | Self::BorderWidth
            | Self::BorderRounded
            | Self::BorderColor
            | Self::BorderWidthEach
            | Self::BorderShadow
            | Self::BorderGlow
            | Self::BorderInnerShadow
            | Self::FontSize
            | Self::FontColor
            | Self::FontFamily
            | Self::FontBold
            | Self::FontItalic
            | Self::HtmlTextNode
            | Self::HtmlRawNode
            | Self::HtmlNode
            | Self::HtmlVoidNode
            | Self::HtmlDoctype
            | Self::HtmlTitleNode
            | Self::HtmlToString
            | Self::HtmlStyleNode
            | Self::HtmlScriptNode
            | Self::HtmlAttribute
            | Self::HtmlBoolAttribute
            | Self::HtmlNoAttr
            | Self::WebApp
            | Self::WebEmbed
            | Self::WebAppRouted
            | Self::WebRoute
            | Self::WebRenderStatic
            | Self::TerminalAppScreen
            | Self::UiOnClick
            | Self::UiOnFocus
            | Self::UiOnBlur
            | Self::UiOnMouseOver
            | Self::UiOnMouseOut
            | Self::UiOnInput
            | Self::UiOnChange
            | Self::UiOnKeyDown
            | Self::UiOnKeyUp
            | Self::UiOnBool
            | Self::UiOnSubmit
            | Self::UiOnFile
            | Self::HtmlOnClick
            | Self::HtmlOnFocus
            | Self::HtmlOnBlur
            | Self::HtmlOnMouseOver
            | Self::HtmlOnMouseOut
            | Self::HtmlOnSubmit
            | Self::HtmlOnInput
            | Self::HtmlOnChange
            | Self::HtmlOnKeyDown
            | Self::HtmlOnKeyUp
            | Self::HtmlOnBool
            | Self::UiSquare
            | Self::UiWidescreen
            | Self::UiCinemascope
            | Self::UiAspectRatio
            | Self::UiAspectRatioWH
            | Self::UiHtmlAttribute
            | Self::UiName
            | Self::UiStyle
            | Self::UiTransitionRaw
            | Self::UiGridTracksRaw
            | Self::UiAnimateRaw
            | Self::UiBreakpoint
            | Self::UiMediaQuery
            | Self::UiMobile
            | Self::UiTablet
            | Self::UiDesktop
            | Self::UiDarkMode
            | Self::UiLightMode
            | Self::UiReducedMotion
            | Self::UiOnPseudo
            | Self::UiHover
            | Self::UiFocus
            | Self::UiFocusVisible
            | Self::UiActive
            | Self::UiDisabled
            | Self::BackgroundHoverColor
            | Self::BackgroundFocusColor
            | Self::BackgroundActiveColor
            | Self::BackgroundDisabledColor
            | Self::BorderSolid
            | Self::BorderDashed
            | Self::BorderDotted
            | Self::BorderHoverColor
            | Self::BorderFocusColor
            | Self::BorderActiveColor
            | Self::BorderHoverWidth
            | Self::BorderHoverRounded
            | Self::FontWeight
            | Self::FontSemiBold
            | Self::FontRegular
            | Self::FontLight
            | Self::FontExtraBold
            | Self::FontBlack
            | Self::FontUnderline
            | Self::FontNoDecoration
            | Self::FontLineThrough
            | Self::FontLetterSpacing
            | Self::FontWordSpacing
            | Self::FontAlignLeft
            | Self::FontAlignRight
            | Self::FontAlignCenter
            | Self::FontCenter
            | Self::FontJustify
            | Self::FontSansSerif
            | Self::FontSerif
            | Self::FontMonospace
            | Self::FontHoverColor
            | Self::FontFocusColor
            | Self::FontActiveColor
            | Self::FontDisabledColor
            | Self::FontHoverSize
            | Self::TerminalAppLines
            // The worker app-entry itself has no capability: its effects come
            // from the `Cmd` closure, gated by the linked-module capability scan.
            | Self::TeaWorker
            | Self::AuthHashPassword
            | Self::AuthHashPasswordCost
            | Self::AuthVerifyPassword
            | Self::AuthPasswordStrength
            | Self::AuthSubject
            // Principal read accessors — pure reads of the verified claims the
            // principal already carries; no isolatable capability.
            | Self::AuthClaim
            | Self::AuthHasRole
            | Self::AuthMemberOf
            // Revocation store — writes/reads to a process-global in-memory set;
            // no network, DB, filesystem, or other isolatable capability.
            | Self::AuthRevocationRevokeUser
            | Self::AuthRevocationRevokeSession
            | Self::AuthRevocationRestoreUser
            | Self::AuthRevocationIsRevoked
            | Self::RegionMainContent
            | Self::RegionNavigation
            | Self::RegionFooter
            | Self::RegionAside
            | Self::RegionHeading
            | Self::RegionLabel
            | Self::RegionAnnounce
            | Self::RegionAnnounceUrgently
            | Self::UiDescribe
            | Self::UiDescNone
            | Self::UiDescParagraph
            | Self::UiDescMain
            | Self::UiDescNavigation
            | Self::UiDescContentInfo
            | Self::UiDescComplementary
            | Self::UiDescLivePolite
            | Self::UiDescLiveAssertive
            | Self::UiDescHeading
            | Self::UiDescLabel
            | Self::InputLabelAbove
            | Self::InputLabelBelow
            | Self::InputLabelLeft
            | Self::InputLabelRight
            | Self::InputLabelHidden
            | Self::InputPlaceholder
            | Self::InputText
            | Self::InputMultiline
            | Self::InputEmail
            | Self::InputUsername
            | Self::InputSearch
            | Self::InputCurrentPassword
            | Self::InputNewPassword
            | Self::InputCheckbox
            | Self::InputSlider
            | Self::InputOption
            | Self::InputRadio
            | Self::InputRadioRow
            | Self::LazyLazy
            | Self::LazyLazy2
            | Self::LazyLazy3
            | Self::LazyLazy4
            | Self::LazyLazy5
            | Self::KeyedColumn
            | Self::KeyedRow
            | Self::DecZero
            | Self::DecOne
            | Self::DecOneHundred
            | Self::DecFromString
            | Self::DecFromInt
            | Self::DecFromFloat
            | Self::DecFromMinor
            | Self::DecToString
            | Self::DecToStringFixed
            | Self::DecToFloat
            | Self::DecToInt
            | Self::DecToMinor
            | Self::DecAdd
            | Self::DecSub
            | Self::DecMul
            | Self::DecDiv
            | Self::DecMod
            | Self::DecNeg
            | Self::DecAbs
            | Self::DecFloor
            | Self::DecCeil
            | Self::DecRound
            | Self::DecRoundHalfUp
            | Self::DecTruncate
            | Self::DecCompare
            | Self::DecEq
            | Self::DecNeq
            | Self::DecLt
            | Self::DecLte
            | Self::DecGt
            | Self::DecGte
            | Self::DecMin
            | Self::DecMax
            | Self::DecIsZero
            | Self::DecIsPositive
            | Self::DecIsNegative
            | Self::DecPercentOf
            | Self::DecAddPercent
            | Self::DecSubPercent
            | Self::DecFormatWith
            | Self::MoneyMinorUnits
            | Self::MoneySymbol
            | Self::MoneyCurrencyName
            | Self::MoneyIsKnownCurrency
            | Self::MoneyFormat
            | Self::MoneyFormatWithCode
            | Self::MoneyAllocate
            | Self::MoneySetRate
            | Self::MoneyGetRate
            | Self::MoneyHasRate
            | Self::MoneyClearRates
            | Self::SqlColumn
            | Self::SqlUnsafeFragment
            | Self::SqlParam
            | Self::SqlInt
            | Self::SqlString
            | Self::SqlFloat
            | Self::SqlBool
            | Self::SqlEq
            | Self::SqlNe
            | Self::SqlGt
            | Self::SqlLt
            | Self::SqlGte
            | Self::SqlLte
            | Self::SqlAnd
            | Self::SqlOr
            | Self::SqlNot
            | Self::SqlIsNull
            | Self::SqlIsNotNull
            | Self::SqlInList
            | Self::SqlLike
            | Self::SqlExists
            | Self::SqlMaskedColumn
            | Self::SecretFromString
            | Self::SecretReveal
            | Self::SecretUse
            | Self::SecretRedacted
            // Runtime-config front door — building a `Setting` value discloses no
            // capability; the capability is the app run itself. (`App.fromEnv` /
            // `App.fromEnvRequired` are NOT here: they READ the process env and
            // are classified `Env` above.)
            | Self::WebAppWith
            | Self::HostBind
            | Self::LogLevelSetting
            | Self::DbUrlSetting
            | Self::ConsoleAdminToken
            | Self::ConsoleIngestToken
            | Self::ConsoleMetricsToken
            | Self::WebCsrf
            | Self::WebSessionTtl
            | Self::WebAuthMaxLifetime
            | Self::WebAuthSlideWindow
            | Self::WebAuthRevocationMode
            // Config-tag ADT constructors — a bare closed-tag value discloses no
            // capability (it is just an `Int` at emit).
            | Self::HostLoopback
            | Self::HostAllInterfaces
            | Self::HostEnvDriven
            | Self::LevelDebug
            | Self::LevelInfo
            | Self::LevelWarn
            | Self::LevelError
            | Self::WebCsrfStrict
            | Self::WebCsrfInherit
            | Self::WebRevocationOff
            | Self::WebRevocationStore
            // `Ipe.Db.Dsn.*` — the parse surface is PURE: parsing/rendering a
            // descriptor performs no I/O and discloses no capability. The
            // network/database disclosure belongs to a future `open` that
            // CONNECTS a `Dsn`, not to constructing one.
            | Self::DsnParse
            | Self::DsnBuild
            | Self::DsnDriverTag
            | Self::DsnHost
            | Self::DsnPort
            | Self::DsnDatabase
            | Self::DsnUser
            | Self::DsnTlsTag
            | Self::DsnRedacted
            | Self::RegexCompile
            | Self::RegexMatch
            | Self::RegexFind
            | Self::RegexFindAll
            | Self::RegexReplace
            | Self::RegexSplit
            | Self::PathFromString
            | Self::PathToString
            | Self::PathBase
            | Self::PathDir
            | Self::PathExt
            | Self::PathIsAbsolute
            | Self::PathUnder
            | Self::TraceSpan
            | Self::TraceEvent
            | Self::TraceAttr
            | Self::CompressionGzip
            | Self::CompressionGunzip
            | Self::CompressionZstdCompress
            | Self::CompressionZstdDecompress
            | Self::CsvParse
            | Self::CsvParseWithDelimiter
            | Self::CsvEncode
            | Self::CsvEncodeWithDelimiter
            | Self::CacheNewRaw
            | Self::CacheGet
            | Self::CachePut
            | Self::CacheRemove
            | Self::CacheClear
            | Self::CacheSize
            | Self::CacheStats
            | Self::CacheDestroyRaw
            | Self::ConfigString
            | Self::ConfigInt
            | Self::ConfigFloat
            | Self::ConfigBool
            | Self::ConfigNullable
            | Self::ConfigField
            | Self::ConfigAt
            | Self::ConfigList
            | Self::ConfigSucceed
            | Self::ConfigFail
            | Self::ConfigMap
            | Self::ConfigAndThen
            | Self::ConfigMap2
            | Self::ConfigMap3
            | Self::ConfigMap4
            | Self::ConfigMap5
            | Self::ConfigMap6
            | Self::ConfigMap7
            | Self::ConfigMap8
            | Self::ConfigOneOf
            | Self::ConfigIndex
            | Self::ConfigKeyValuePairs
            | Self::ConfigMaybe
            | Self::ConfigDict
            | Self::ConfigDecodeToml
            | Self::ConfigDecodeYaml
            | Self::ConfigDecodeJson
            // `HttpMethodFromString` / `HttpMethodToString` are pure converters —
            // no network or I/O side-effect, capability = None.
            | Self::HttpMethodFromString
            | Self::HttpMethodToString
            // ── Ipe.Crypto typed-key newtypes ─────────────────────────
            | Self::CryptoKeyFromString
            | Self::CryptoKeyFromBytes
            | Self::CryptoMacToHex
            | Self::CryptoHmacSha256WithKey
            | Self::CryptoHmacSha512WithKey
            // ── Ipe.Email.EmailAddress ─────────────────────────────────
            | Self::EmailAddressParse
            | Self::EmailAddressToString
            // ── Ipe.Url — pure parse/accessor/builder kernels, no I/O side-effect.
            | Self::UrlFromString
            | Self::UrlToString
            | Self::UrlScheme
            | Self::UrlHost
            | Self::UrlPort
            | Self::UrlPath
            | Self::UrlQuery
            | Self::UrlFragment
            | Self::UrlSchemeShown
            | Self::UrlBuildQuery
            | Self::UrlRelativeParse
            | Self::UrlRelativePath
            | Self::UrlRelativeQuery
            | Self::UrlRelativeFragment
            | Self::UrlRelativeToString
            // ── Ipe.Locale — pure BCP-47 parse + locale-aware case mapping ──
            | Self::LocaleFromTag
            | Self::LocaleToTag
            | Self::StringToUpperIn
            | Self::StringToLowerIn
            // `Time.format*` / `Time.addMillis` / `Time.diffMillis` are pure
            // converters that take a supplied timestamp as input — they read no
            // system clock and disclose no `Clock` capability.
            | Self::TimeFormat
            | Self::TimeFormatHTTP
            | Self::TimeFormatISO8601
            | Self::TimeFormatRFC3339
            | Self::TimeAddMillis
            | Self::TimeDiffMillis
            // `Debug.todo` / `Debug.explain` are dev-only escape hatches;
            // no runtime capability beyond `Debug.*` dev membership.
            | Self::DebugTodo
            | Self::DebugExplain => None,
        }
    }

    /// The ELEMENT trait bound this kernel imposes, when it is a
    /// `List`/`Dict`/`Set` kernel; `None` for every non-collection kernel.
    ///
    /// This is the soundness axis for storing a value in a collection: the
    /// carrier for a stored function is `Arc<dyn Fn>` (`Clone` but not
    /// `PartialEq`/`Ord`), so a kernel that only moves/clones its element
    /// ([`ElementCapability::CloneOk`]) is sound over a function element, while a
    /// kernel that compares ([`ElementCapability::RequiresPartialEq`]) or orders
    /// ([`ElementCapability::RequiresOrd`]) it is not, and the lowerer rejects a
    /// function-embedding element for the latter with the equality/ordering
    /// diagnostic (fail-closed at `ipe` time).
    ///
    /// The equality and ordering families are enumerated explicitly. Every
    /// other `List`/`Dict`/`Set` kernel is derived from its scheme: it is
    /// [`ElementCapability::MapperFrontierOpen`] exactly when
    /// [`mapper_frontier_open`] holds (or it has no scheme to derive from —
    /// fail-closed), and `CloneOk` otherwise, so the gate and the lowerer's
    /// mapper re-carrier read one binding predicate. A `Dict` KEY /`Set`
    /// element function is separately rejected by the region gate
    /// (`embeds_nonderivable_function`) before a kernel is even resolved, since
    /// those positions are non-storable; this tag governs the storable-element
    /// kernels (the `List` element and `Dict` value the carrier flip admits). A
    /// collection kernel matching none of the explicit arms falls to the tail
    /// wildcard and returns `None`; the
    /// `every_collection_kernel_carries_an_element_capability_tag` test — not the
    /// match — is what forces every `List`/`Dict`/`Set` kernel to return `Some`.
    #[must_use]
    pub const fn element_capability(self) -> Option<ElementCapability> {
        match self {
            // `PartialEq` on the element (`list.contains`, dedup): the emitted
            // Rust compares the element, unsound over an `Arc<dyn Fn>` carrier.
            Self::ListMember | Self::ListUnique => {
                return Some(ElementCapability::RequiresPartialEq);
            }
            // `PartialOrd`/`Ord` on the element (sort / extremum).
            Self::ListSort | Self::ListMaximum | Self::ListMinimum => {
                return Some(ElementCapability::RequiresOrd);
            }
            // Collection kernels that move/clone the element, or feed it to a
            // mapper: `CloneOk` unless the scheme leaves a mapper parameter the
            // lowerer's `retype_collection_element_param` cannot align to the
            // stored `Arc<dyn Fn>` carrier. A newly added List/Dict/Set kernel
            // listed in none of the arms falls to the `_ => {}` tail and returns
            // `None`; the `collection_kernel_capability_is_never_implicitly_permissive`
            // test catches that omission.
            Self::ListMap
            | Self::ListFilter
            | Self::ListFoldl
            | Self::ListFoldr
            | Self::ListLength
            | Self::ListHead
            | Self::ListTail
            | Self::ListRange
            | Self::ListReverse
            | Self::ListAppend
            | Self::ListConcat
            | Self::ListTake
            | Self::ListDrop
            | Self::ListZip
            | Self::ListCons
            | Self::ListIsEmpty
            | Self::ListConcatMap
            | Self::ListIndexedMap
            | Self::ListAny
            | Self::ListAll
            | Self::ListFind
            | Self::ListFilterMap
            | Self::ListSingleton
            | Self::ListRepeat
            | Self::ListSum
            | Self::ListProduct
            | Self::ListIntersperse
            | Self::ListUnzip
            | Self::DictEmpty
            | Self::DictIsEmpty
            | Self::DictSize
            | Self::DictKeys
            | Self::DictValues
            | Self::DictToList
            | Self::DictFromList
            | Self::DictGet
            | Self::DictMember
            | Self::DictRemove
            | Self::DictUnion
            | Self::DictInsert
            | Self::DictSingleton
            | Self::DictIntersect
            | Self::DictDiff
            | Self::SetEmpty
            | Self::SetSize
            | Self::SetToList
            | Self::SetFromList
            | Self::SetMember
            | Self::SetInsert
            | Self::SetRemove
            | Self::SetUnion
            | Self::SetIntersect
            | Self::SetDiff
            | Self::SetIsEmpty
            | Self::SetSingleton
            | Self::ListPartition
            | Self::ListMap2
            | Self::ListMap3
            | Self::ListMap4
            | Self::ListMap5
            | Self::ListSortBy
            | Self::ListSortWith
            | Self::DictMap
            | Self::DictFoldl
            | Self::DictFoldr
            | Self::DictFilter
            | Self::DictPartition
            | Self::DictUpdate
            | Self::SetMap
            | Self::SetFilter
            | Self::SetFoldl
            | Self::SetFoldr
            | Self::SetPartition => {
                return Some(match self.scheme_shape() {
                    Some(shape) if !mapper_frontier_open(shape, self.def().arity) => {
                        ElementCapability::CloneOk
                    }
                    _ => ElementCapability::MapperFrontierOpen,
                });
            }
            _ => {}
        }
        // Non-collection kernels carry no element capability.
        None
    }

    /// A development-only escape hatch (the `Ipe.Debug` family). Rejected in a
    /// PRODUCTION build (`ipe release`, IPE-L0140) rather than
    /// silently stripped or shipped. The single SSOT for "which kernels are
    /// dev-only" — the lowerer's usage scan and every gate consult this.
    #[must_use]
    pub const fn is_dev_only(self) -> bool {
        matches!(self, Self::DebugLog | Self::DebugTodo | Self::DebugExplain)
    }

    /// `true` when this variant is emitted through the TEA (`Cmd` / `Sub` /
    /// `Time.every`) dispatch arm — every `class = Tea` wiring kernel EXCEPT the
    /// view-less `Ipe.Tea.Worker.tea` app-entry (which routes through the UI
    /// delegate chain, see [`Self::is_worker`]), PLUS the `class = Pure`
    /// `HttpStream.chunks` `Sub` builder (a stream subscription emitted as a
    /// `Sub`, whose `sub_subscribe_stream` symbol lives in `http_stream`).
    ///
    /// Derived from the [`Self::decl`] class column with those two named
    /// carve-outs rather than a hand-mirrored variant set — like [`Self::is_db`]
    /// / [`Self::is_web`]. The `TeaWorker` exclusion is exactly the boundary the
    /// UI emitter domain owns; `tea_predicate_tracks_tea_class` pins both
    /// carve-outs so any class/predicate drift fails the build.
    #[must_use]
    pub const fn is_tea(self) -> bool {
        // `HttpStream.chunks` is a `Sub`-shaped client stream — `class = Pure`
        // (it must not force a TEA-only feature) but emitted through the TEA arm.
        if matches!(self, Self::HttpStreamChunks) {
            return true;
        }
        // Every other TEA kernel is `class = Tea`, save the view-less worker
        // app-entry, which the UI delegate chain owns (`is_worker`).
        matches!(self.decl().class, KernelClass::Tea) && !self.is_worker()
    }

    /// `true` when this variant is emitted through the `Ipe.Http.Server` /
    /// Middleware / `RateLimit` dispatch arm — every `class = Server` kernel,
    /// PLUS the three `class = Pure` `Ipe.Http.Stream` client-relay builders
    /// (`open` / `forEachChunk` / `close`) whose `http_stream` symbols the server
    /// module append declares.
    ///
    /// Derived from the [`Self::decl`] class column with that one named
    /// `HttpStream*` carve-out rather than a hand-mirrored variant set — like
    /// [`Self::is_db`] / [`Self::is_web`]. `server_predicate_tracks_server_module_residency`
    /// pins the carve-out, so a `class = Server` kernel a hand list forgot — or a
    /// drift in the carve-out — fails the build rather than emitting `server::*`
    /// with no module declaration (E0425/E0412).
    #[must_use]
    pub const fn is_server(self) -> bool {
        if matches!(self.decl().class, KernelClass::Server) {
            return true;
        }
        // The `Ipe.Http.Stream` client-relay builders are `class = Pure` (they
        // must not force the server feature) but their `http_stream` symbols live
        // in the module set the server append declares, so they route through the
        // server emit arm. `HttpStream.chunks` is deliberately NOT here — it is a
        // `Sub`-shaped stream handled via the TEA arm (see [`Self::is_tea`]).
        matches!(
            self,
            Self::HttpStreamOpen | Self::HttpStreamForEachChunk | Self::HttpStreamClose
        )
    }

    /// `true` when this variant is an outbound `Ipe.WebSocket` CLIENT
    /// kernel (the 6 Task-tier connect/send/close kernels plus the Sub-tier
    /// `Sub.subscribeWebSocket`).
    ///
    /// Used by `ipe_lower` to detect `uses_websocket` and by the backend to add
    /// the `websocket_client` Cargo feature + `ws_client` runtime module (whose
    /// fns are gated behind that feature — unlike `Http.get`, they are NOT part
    /// of the always-present base module set).
    #[must_use]
    pub const fn is_websocket_client(self) -> bool {
        matches!(
            self,
            Self::WebSocketConnect
                | Self::WebSocketConnectWith
                | Self::WebSocketSend
                | Self::WebSocketSendBinary
                | Self::WebSocketClose
                | Self::WebSocketCloseWithCode
                | Self::SubSubscribeWebSocket
        )
    }

    /// `true` when this variant belongs to the outbound `Ipe.Http` client
    /// family — the `Http.get` / `Http.post` / `Http.request` senders plus the
    /// pure request/method builders (`Http.defaultRequest`, `Http.with*`,
    /// `Http.methodFromString` / `methodToString`), the `Http.parseQuery`
    /// query splitter, and the `Ipe.Http.Stream` relay kernels.
    ///
    /// Every variant here emits a symbol that lives in the `http_client` or
    /// `http_stream` runtime module, both of which require reqwest. Used by
    /// `ipe_lower` to detect `uses_http` and by the backend to declare
    /// `http_client` + `http_stream` in the emitted `ipe_runtime/mod.rs` and
    /// add `reqwest` to the emitted manifest — unlike `Ipe.Url` (whose
    /// `url`-crate surface stays unconditional), the reqwest HTTP stack is
    /// pulled in only on demand.
    ///
    /// The `Ipe.Http.Stream` relay kernels (`HttpStream*`) are included here
    /// because `http_stream.rs` calls `http_client::ssrf_apply` and
    /// `http_client::method_to_reqwest` — both modules require reqwest. A
    /// program using `HttpStream.*` makes outbound HTTP connections and must
    /// pull reqwest; `uses_http = true` causes the backend to declare both
    /// `http_client` and `http_stream` together.
    #[must_use]
    pub const fn is_http_client(self) -> bool {
        matches!(
            self,
            Self::HttpGet
                | Self::HttpPost
                | Self::HttpRequest
                | Self::HttpParseQuery
                | Self::HttpDefaultRequest
                | Self::HttpDefaultRequestFromString
                | Self::HttpWithMethod
                | Self::HttpWithTimeout
                | Self::HttpWithBody
                | Self::HttpWithHeader
                | Self::HttpWithUrl
                | Self::HttpWithRedirects
                | Self::HttpMethodFromString
                | Self::HttpMethodToString
                // Outbound HTTP streaming: open/stream/close a reqwest response
                // body incrementally. These call http_client::ssrf_apply +
                // method_to_reqwest, so they require reqwest just like Http.get.
                | Self::HttpStreamOpen
                | Self::HttpStreamForEachChunk
                | Self::HttpStreamClose
                | Self::HttpStreamChunks
        )
    }

    /// `true` when this variant emits a symbol that lives in the `config_decode`
    /// runtime module — the format front-ends (`Config.decodeToml` /
    /// `decodeYaml` / `decodeJson` / `loadFromFile`) and the three
    /// `config_decode`-own combinators (`Config.nullable` / `maybe` / `dict`).
    ///
    /// `config_decode` is the sole consumer of the `toml` and `serde_yaml`
    /// crates (`decodeToml` / `decodeYaml`, and `loadFromFile` which dispatches
    /// to both by file extension). Used by `ipe_lower` to detect `uses_config`
    /// and by the backend to declare `config_decode` in the emitted
    /// `ipe_runtime/mod.rs` and add `toml` + `serde_yaml` to the emitted
    /// manifest.
    ///
    /// The rest of the `Ipe.Config` surface (`string` / `int` / `field` / `map`
    /// / `oneOf` / …) is NOT here: those combinators emit the shared
    /// `json_decode_*` / `decode_*` symbols that live in the `json`
    /// module, so a program using only them pulls neither `config_decode` nor
    /// the `toml` / `serde_yaml` crates.
    #[must_use]
    pub const fn is_config(self) -> bool {
        matches!(
            self,
            Self::ConfigNullable
                | Self::ConfigMaybe
                | Self::ConfigDict
                | Self::ConfigDecodeToml
                | Self::ConfigDecodeYaml
                | Self::ConfigDecodeJson
                | Self::ConfigLoadFromFile
        )
    }

    /// `true` when this variant produces or consumes a `Value` (`JsonVal`) or a
    /// `Decoder<T>` in the emitted body — the two types the fixed prelude aliases
    /// as `type Value = JsonVal;` and `pub type Decoder<T> =
    /// ipe_runtime::json::Decoder<IpeError, T>`.
    ///
    /// Both aliases hard-reference the `json` runtime module (`serde_json`), so a
    /// program that emits either type must select the `json` feature. Used by
    /// `ipe_lower` (unioned with a `Json`/`Decoder` type-mention scan over the
    /// program's signatures, records, and enum payloads) to set `uses_json` — the
    /// selector the backend reads (`reaches_json`) to keep the two prelude aliases
    /// and the `json` feature. A program that calls no such kernel AND names
    /// neither type drops the aliases, `serde_json`, and the whole serde stack.
    ///
    /// The family: every `JsonEnc.*` encoder (builds a `Value`), every `JsonDec.*`
    /// / `JsonDecP.*` decoder combinator (builds a `Decoder<T>`), the whole
    /// `Ipe.Config` decoder surface (its combinators share the `json` module's
    /// `Decoder<E, T>` carrier and `decode_*` runtime fns), the `Db.Decode.*`
    /// column decoders and `Db.queryDecode` (same `Decoder<E, T>` carrier), and
    /// `Server.json` (takes a `Value`). FAIL-CLOSED: a kernel whose result flows
    /// into a `let`-bound `Value`/`Decoder` local — spelling the alias with no
    /// signature to catch it — is kept by this call-site predicate.
    #[must_use]
    pub const fn is_json(self) -> bool {
        matches!(
            self,
            Self::JsonEncString
                | Self::JsonEncInt
                | Self::JsonEncFloat
                | Self::JsonEncBool
                | Self::JsonEncNull
                | Self::JsonEncList
                | Self::JsonEncObject
                | Self::JsonEncEncode
                | Self::JsonDecString
                | Self::JsonDecInt
                | Self::JsonDecFloat
                | Self::JsonDecBool
                | Self::JsonDecValue
                | Self::JsonDecDecodeString
                | Self::JsonDecDecodeValue
                | Self::JsonDecField
                | Self::JsonDecAt
                | Self::JsonDecIndex
                | Self::JsonDecList
                | Self::JsonDecNullable
                | Self::JsonDecMap
                | Self::JsonDecAndThen
                | Self::JsonDecSucceed
                | Self::JsonDecFail
                | Self::JsonDecOneOf
                | Self::JsonDecMap2
                | Self::JsonDecMap3
                | Self::JsonDecMap4
                | Self::JsonDecPRequired
                | Self::JsonDecPOptional
                | Self::JsonDecPCustom
                | Self::JsonDecPRequiredAt
                | Self::ConfigString
                | Self::ConfigInt
                | Self::ConfigFloat
                | Self::ConfigBool
                | Self::ConfigNullable
                | Self::ConfigField
                | Self::ConfigAt
                | Self::ConfigList
                | Self::ConfigSucceed
                | Self::ConfigFail
                | Self::ConfigMap
                | Self::ConfigAndThen
                | Self::ConfigMap2
                | Self::ConfigMap3
                | Self::ConfigMap4
                | Self::ConfigMap5
                | Self::ConfigMap6
                | Self::ConfigMap7
                | Self::ConfigMap8
                | Self::ConfigOneOf
                | Self::ConfigIndex
                | Self::ConfigKeyValuePairs
                | Self::ConfigMaybe
                | Self::ConfigDict
                | Self::ConfigDecodeToml
                | Self::ConfigDecodeYaml
                | Self::ConfigDecodeJson
                | Self::ConfigLoadFromFile
                | Self::DbQueryDecode
                | Self::DbDecString
                | Self::DbDecInt
                | Self::DbDecFloat
                | Self::DbDecBool
                | Self::DbDecNullable
                | Self::DbDecMap
                | Self::DbDecAndThen
                | Self::DbDecSucceed
                | Self::DbDecFail
                | Self::DbDecMap2
                | Self::DbDecMap3
                | Self::DbDecMap4
                | Self::DbDecRequired
                | Self::DbDecOptional
                | Self::DbDecMoney
                | Self::DbDecDecimal
                | Self::DbDecBytes
                | Self::ServerJson
                | Self::JwtWithClaim
        )
    }

    /// `true` when this variant belongs to the `Ipe.Compression` kernel family
    /// (`Compression.gzip` / `gunzip` / `zstdCompress` / `zstdDecompress`).
    ///
    /// The `compression` runtime module is the sole consumer of the `flate2` and
    /// `zstd` crates (`gzip` / `gunzip` go through `flate2`, `zstdCompress` /
    /// `zstdDecompress` through `zstd`). Used by `ipe_lower` to detect
    /// `uses_compression` and by the backend to declare `compression` in the
    /// emitted `ipe_runtime/mod.rs` and add `flate2` + `zstd` to the emitted
    /// manifest. It is a leaf module — no other runtime surface calls into it —
    /// so the flag alone gates it, never forced on transitively.
    #[must_use]
    pub const fn is_compression(self) -> bool {
        matches!(
            self,
            Self::CompressionGzip
                | Self::CompressionGunzip
                | Self::CompressionZstdCompress
                | Self::CompressionZstdDecompress
        )
    }

    /// `true` when this variant belongs to the `Ipe.Csv` kernel family
    /// (`Csv.parse` / `parseWithDelimiter` / `encode` / `encodeWithDelimiter` /
    /// `parseStreamFromFile`).
    ///
    /// The `csv` runtime module is the sole consumer of the `csv` crate. Used by
    /// `ipe_lower` to detect `uses_csv` and by the backend to declare `csv` in
    /// the emitted `ipe_runtime/mod.rs` and add the `csv` dependency to the
    /// emitted manifest. It is a leaf module — no other runtime surface calls
    /// into it — so the flag (unioned with a `CsvDoc` type-mention guard: a bare
    /// `{ header, rows }` record shape folds to `IrType::CsvDoc`, which emits a
    /// bare `CsvDoc` reference resolved through the module's `pub use csv::*`
    /// glob) gates it, never forced on transitively.
    #[must_use]
    pub const fn is_csv(self) -> bool {
        matches!(
            self,
            Self::CsvParse
                | Self::CsvParseWithDelimiter
                | Self::CsvEncode
                | Self::CsvEncodeWithDelimiter
                | Self::CsvParseStreamFromFile
        )
    }

    /// `true` when this variant reaches the `encoding.rs` / `bytes.rs` runtime
    /// modules — the `Ipe.Encoding` codecs (base64 / url-percent / hex) and the
    /// `Ipe.Bytes` buffer kernels.
    ///
    /// The whole `bytes.rs` module (including its std-only `empty`/`length`/… half)
    /// moves behind the `encoding` feature, so ANY `Bytes.*` kernel selects it —
    /// module-granular over-inclusion, accepted so the SEAL's module-level
    /// cfg-satisfaction proof covers it. Used by `ipe_lower` to detect
    /// `uses_encoding` and by the backend to declare `encoding` and add the
    /// `base64` + `hex` + `percent-encoding` deps to the emitted manifest; a
    /// program that reaches none of these — and no crypto/db/server/email/jwt/web
    /// surface implying `encoding` — drops all three crates. `Crypto.randomToken`
    /// is NOT here: its `crypto_random_token` floor body uses an inline base64url
    /// encoder (no `base64` crate), so it stays available at
    /// `--no-default-features` for the always-emitted prelude wrapper.
    #[must_use]
    pub const fn is_encoding(self) -> bool {
        matches!(
            self,
            Self::BytesEmpty
                | Self::BytesLength
                | Self::BytesIsEmpty
                | Self::BytesFromString
                | Self::BytesToString
                | Self::BytesFromHex
                | Self::BytesToHex
                | Self::BytesFromBase64
                | Self::BytesToBase64
                | Self::BytesAppend
                | Self::BytesSlice
                | Self::EncodingBase64Encode
                | Self::EncodingBase64Decode
                | Self::EncodingUrlEncode
                | Self::EncodingUrlDecode
                | Self::EncodingPercentDecode
                | Self::EncodingHexEncode
                | Self::EncodingHexDecode
        )
    }

    /// `true` when this variant reaches the `regex_kernel.rs` runtime module —
    /// the `Ipe.Regex` compile/match/find/replace/split kernels PLUS
    /// `String.isUrl`, whose validator body lives in `regex_kernel.rs` (the one
    /// non-`Ipe.Regex` consumer of the `regex` crate). The whole
    /// module — hence the `regex` crate and its `aho-corasick` / `regex-automata`
    /// / `regex-syntax` subtree — is behind the `regex` feature: a program that
    /// reaches neither an `Ipe.Regex` kernel nor `String.isUrl` drops all four
    /// crates. Used by `ipe_lower` to detect `uses_regex` and by the backend to
    /// declare `regex_kernel` and add the `regex` dependency. `String.isUrl` is
    /// deliberately here (not a `Regex`-qualifier kernel) — the exhaustiveness
    /// test below asserts exactly `qualifier == "Regex" || StringIsUrl`.
    #[must_use]
    pub const fn is_regex(self) -> bool {
        matches!(
            self,
            Self::RegexCompile
                | Self::RegexMatch
                | Self::RegexFind
                | Self::RegexFindAll
                | Self::RegexReplace
                | Self::RegexSplit
                | Self::StringIsUrl
        )
    }

    /// `true` when this variant reaches the `uuid_kernel.rs` runtime module — the
    /// `Ipe.Uuid` v4 / v7 / parse kernels, the sole consumers of the `uuid` crate
    /// as a runtime module. Behind the `uuid` feature: a program that reaches no
    /// `Ipe.Uuid` kernel — and no `server` / `web` surface, whose runtime modules
    /// draw session/CSRF ids from `uuid::new_v4` directly — drops the crate. Used
    /// by `ipe_lower` to detect `uses_uuid` and by the backend to declare
    /// `uuid_kernel` and add the `uuid` dependency; the `server` / `web`
    /// implications are folded in by the backend's `reaches_uuid`.
    #[must_use]
    pub const fn is_uuid(self) -> bool {
        matches!(self, Self::UuidV4 | Self::UuidV7 | Self::UuidParse)
    }

    /// `true` when this variant reaches the `random.rs` runtime module — the
    /// `Ipe.Random` non-cryptographic PRNG surface (`int` / `float` / `choice`
    /// and the seeded `Random.Generator` primitives `seededIntRaw` /
    /// `seededFloatRaw`). Behind the `random` feature, which gates the `random.rs`
    /// module declaration. A program that reaches no `Ipe.Random` kernel drops the
    /// module. Used by `ipe_lower` to detect `uses_random` and by the backend to
    /// declare `random`.
    ///
    /// NOTE the `random` feature gates the `random.rs` module only. `getrandom`
    /// (the entropy source) is always present: the runtime's scratch primitive
    /// and the `crypto_core` module draw from it too.
    #[must_use]
    pub const fn is_random(self) -> bool {
        matches!(
            self,
            Self::RandomInt
                | Self::RandomFloat
                | Self::RandomChoice
                | Self::RandomChoiceMaybe
                | Self::RandomShuffle
                | Self::RandomWeighted
                | Self::RandomSeededInt
                | Self::RandomSeededFloat
                | Self::RandomSeededChoice
        )
    }

    /// `true` when this variant belongs to the `Ipe.Cache` kernel family — the
    /// handle-based LRU cache operations backed by `cache.rs`. Selecting the flag
    /// declares the `cache` runtime module (whose `cache_new_raw` / `cache_get` /
    /// `cache_put` / … functions, the `CacheCfg` / `CacheStats` structs, and the
    /// `IpeCacheHandle` enum the emitted code references) and enables the
    /// `cache_kernel` runtime-crate feature. A standalone leaf — no other surface
    /// reaches it — so the flag alone gates the module. The `CacheCfg` /
    /// `CacheStats` config/stats types are folded from record shapes and can be
    /// named without a call site, so the lowerer unions this flag with a
    /// type-mention guard (mirrors `CsvDoc`).
    #[must_use]
    pub const fn is_cache(self) -> bool {
        matches!(
            self,
            Self::CacheNewRaw
                | Self::CacheGet
                | Self::CachePut
                | Self::CacheRemove
                | Self::CacheClear
                | Self::CacheSize
                | Self::CacheStats
                | Self::CacheDestroyRaw
        )
    }

    /// `true` when this variant belongs to the non-TEA `Ipe.Time` kernel family
    /// (`Time.now` / `unixMillis` / `sleep` / `timeString` / `isLeapYear` /
    /// `daysInMonth`). Excludes `Time.every`, which is TEA (`is_tea()`).
    ///
    /// The whole `time.rs` runtime module is behind the `time-core` Cargo feature
    /// (base `chrono`); its IANA-zone calendar surface additionally needs the
    /// `time` feature (`chrono-tz`), which implies `time-core`. Used by
    /// `ipe_lower` to detect `uses_time` and by the backend to enable both
    /// features and add the `chrono-tz` dependency; a program that reaches no
    /// `Ipe.Time` kernel drops `chrono-tz` and — unless a Log/Db/Web surface (or
    /// a webview-native `web desktop` host) also reaches `time-core` — `chrono`
    /// itself.
    #[must_use]
    pub const fn is_time(self) -> bool {
        matches!(
            self,
            Self::TimeNow
                | Self::TimeSleep
                | Self::TimeUnixMillis
                | Self::TimeTimeString
                | Self::TimeIsLeapYear
                | Self::TimeDaysInMonth
                | Self::TimeFormat
                | Self::TimeFormatHTTP
                | Self::TimeFormatISO8601
                | Self::TimeFormatRFC3339
                | Self::TimeAddMillis
                | Self::TimeDiffMillis
        )
    }

    /// `true` when this variant reaches the `log.rs` runtime module — the
    /// `Ipe.Log.*` observability kernels (`info` / `debug` / `warn` / `error` and
    /// their `*With` structured-attribute companions). `log.rs` is the sole
    /// always-emittable consumer of `chrono` for its RFC3339-nano timestamp, so
    /// the module — and, via `time-core`, the base `chrono` crate — is behind the
    /// `log` feature. Used by `ipe_lower` to detect `uses_log` and by the backend
    /// to declare `log` and add `chrono`. A program that reaches no `Log.*` kernel
    /// (and no Time/Db/Web surface or webview-native `web desktop` host) drops
    /// `chrono`.
    ///
    /// `Debug.log` is deliberately NOT here: `debug.rs` is a pure `IpeStringify`
    /// passthrough (no `chrono`, no `log.rs`), always compiled, so it never
    /// selects the `log` feature.
    #[must_use]
    pub const fn is_log(self) -> bool {
        matches!(
            self,
            Self::LogInfo
                | Self::LogDebug
                | Self::LogWarn
                | Self::LogError
                | Self::LogInfoWith
                | Self::LogDebugWith
                | Self::LogWarnWith
                | Self::LogErrorWith
        )
    }

    /// `true` when this variant reaches the `decimal.rs` / `money.rs` runtime
    /// modules — the `Ipe.Decimal` arbitrary-precision surface and the `Ipe.Money`
    /// surface built on it. They are the sole consumers of the `rust_decimal`
    /// crate (and its `arrayvec` subtree), so both modules — and the crate — are
    /// behind the `decimal` feature. `money.rs` builds on `decimal.rs`'s `Decimal`
    /// newtype, so the two gate together. Used by `ipe_lower` to detect
    /// `uses_decimal` and by the backend to declare the modules and add
    /// `rust_decimal`. The `Db` surface decodes numeric SQL columns (and
    /// `Db.Decode.money`) through `rust_decimal` too, so the backend keeps
    /// `decimal` under `uses_decimal || uses_db`; a program that reaches neither a
    /// `Decimal.*`/`Money.*` kernel nor a `Db` surface drops the crate.
    #[must_use]
    pub const fn is_decimal(self) -> bool {
        matches!(
            self,
            Self::DecZero
                | Self::DecOne
                | Self::DecOneHundred
                | Self::DecFromString
                | Self::DecFromInt
                | Self::DecFromFloat
                | Self::DecFromMinor
                | Self::DecToString
                | Self::DecToStringFixed
                | Self::DecToFloat
                | Self::DecToInt
                | Self::DecToMinor
                | Self::DecAdd
                | Self::DecSub
                | Self::DecMul
                | Self::DecDiv
                | Self::DecMod
                | Self::DecNeg
                | Self::DecAbs
                | Self::DecFloor
                | Self::DecCeil
                | Self::DecRound
                | Self::DecRoundHalfUp
                | Self::DecTruncate
                | Self::DecCompare
                | Self::DecEq
                | Self::DecNeq
                | Self::DecLt
                | Self::DecLte
                | Self::DecGt
                | Self::DecGte
                | Self::DecMin
                | Self::DecMax
                | Self::DecIsZero
                | Self::DecIsPositive
                | Self::DecIsNegative
                | Self::DecPercentOf
                | Self::DecAddPercent
                | Self::DecSubPercent
                | Self::DecFormatWith
                | Self::MoneyMinorUnits
                | Self::MoneySymbol
                | Self::MoneyCurrencyName
                | Self::MoneyIsKnownCurrency
                | Self::MoneyFormat
                | Self::MoneyFormatWithCode
                | Self::MoneyAllocate
                | Self::MoneySetRate
                | Self::MoneyGetRate
                | Self::MoneyHasRate
                | Self::MoneyClearRates
        )
    }

    /// `true` when this variant reaches the `char_category.rs` runtime module —
    /// the `Ipe.Char` predicates keyed off the Unicode `General_Category`
    /// (`isAlpha` / `isDigit` / `isLower` / `isUpper` / `isAlphaNum`). That module
    /// is the sole consumer of the `unicode-general-category` table, so it — and
    /// the crate — is behind the `char-category` feature. Used by `ipe_lower` to
    /// detect `uses_char_category` and by the backend to declare the module and
    /// add the crate. A standalone leaf: no surface implies it.
    ///
    /// The std-only `Ipe.Char` kernels (`isHexDigit` / `isOctDigit` / `toLower` /
    /// `toUpper` / `toCode` / `fromCode`) are deliberately NOT here: their
    /// `char_kernel.rs` bodies resolve through Rust std alone (ASCII ranges +
    /// `char::to_lowercase`/`to_uppercase`/`from_u32`), so that module is always
    /// compiled and a program using only them drops `unicode-general-category`.
    #[must_use]
    pub const fn is_char_category(self) -> bool {
        matches!(
            self,
            Self::CharIsAlpha
                | Self::CharIsDigit
                | Self::CharIsLower
                | Self::CharIsUpper
                | Self::CharIsAlphaNum
        )
    }

    /// `true` when this variant belongs to the `Ipe.Auth` kernel family
    /// (`Ipe.Auth.hashPassword` / `verifyPassword` / `signToken` / `verifyToken` /
    /// `register` / `login` / `setRole` and companions).
    ///
    /// Used by `ipe_lower` to detect `uses_auth` and emit the `auth` module into
    /// the generated `ipe_runtime/mod.rs`.
    #[must_use]
    pub const fn is_auth(self) -> bool {
        matches!(
            self,
            Self::AuthHashPassword
                | Self::AuthHashPasswordCost
                | Self::AuthVerifyPassword
                | Self::AuthPasswordStrength
                | Self::AuthSignToken
                | Self::AuthVerifyToken
                | Self::AuthRegister
                | Self::AuthLogin
                | Self::AuthSetRole
        )
    }

    /// `true` when this variant belongs to the HEAVY `Ipe.Crypto` kernel family
    /// — the ones whose emitted symbol lives in the gated `crypto` runtime module
    /// (legacy SHA-1/MD5 checksums, AES-256-GCM + ChaCha20-Poly1305 AEAD, PBKDF2
    /// password-key derivation, and the typed-key AEAD variants).
    ///
    /// The `crypto` module is the sole consumer of `sha1`, `md-5`, `aes-gcm`,
    /// `chacha20poly1305`, and `pbkdf2`. Used by `ipe_lower` to detect
    /// `uses_crypto` and by the backend to declare `crypto` in the emitted
    /// `ipe_runtime/mod.rs` and add those five crates to the emitted manifest.
    ///
    /// The `crypto_core` floor (SHA-2 hash/HMAC, RSA sign/verify,
    /// constant-time compare, the entropy pair, the `Key`/`Mac` newtypes) is
    /// EXCLUDED here — those kernels emit into `crypto_core`, which stays in the
    /// base module set, so their presence never forces the heavy `crypto` module
    /// or its crates.
    #[must_use]
    pub const fn is_crypto(self) -> bool {
        matches!(
            self,
            Self::CryptoSha1
                | Self::CryptoMd5
                // RSA sign/verify: emit into `crypto_core.rs` but their bodies are
                // `#[cfg(feature = "crypto")]` (the `rsa` subtree), so they need the
                // heavy feature. `crypto` implies `crypto-core`, so the floor is
                // still present for their `crypto_core`-resident symbol.
                | Self::CryptoRsaSha256Sign
                | Self::CryptoRsaSha256Verify
                | Self::CryptoAesGcmEncrypt
                | Self::CryptoAesGcmDecrypt
                | Self::CryptoChacha20Encrypt
                | Self::CryptoChacha20Decrypt
                | Self::CryptoAesKeyFromPassword
                | Self::CryptoChachaKeyFromPassword
        )
    }

    /// `true` when this variant's emitted symbol lives in `crypto_core.rs` AND is
    /// available with only the `crypto-core` feature — the cryptographic floor:
    /// SHA-2 hash (`sha256`/`sha512`), the HMAC family (`hmacSha256`/`hmacSha512`
    /// and their `Key`-typed `WithKey` forms), the constant-time compare, the
    /// entropy pair (`randomBytes`/`randomToken`), and the typed `Key`/`Mac`
    /// newtype kernels (`Key.fromString` / `Key.fromBytes` / `Mac.toHex`).
    ///
    /// EXCLUDES RSA sign/verify: although their emit symbols reside in
    /// `crypto_core.rs`, their bodies are `#[cfg(feature = "crypto")]` (they pull
    /// the ~34-crate `rsa` subtree), so they need the heavy `crypto` feature — they
    /// are classified by [`Self::is_crypto`], which implies `crypto-core`. Gating
    /// an RSA-only program on `crypto-core` alone would drop the `#[cfg]`-off RSA
    /// arm and ship an E0433.
    ///
    /// Used by `ipe_lower` to detect `uses_crypto_core` and by the backend to
    /// select the `crypto-core` Cargo feature (which pulls `sha2` / `hmac` /
    /// `subtle`). A program that reaches no crypto-floor kernel —
    /// and no `crypto` / `jwt` / `db` / `web` / `webview` / `email` / `server`
    /// surface that reaches the floor transitively (folded in by the backend's
    /// `reaches_crypto_core`) — drops the module and its crates. Disjoint from
    /// [`Self::is_crypto`]: the heavy legacy-checksum / AEAD / PBKDF2 kernels live
    /// in `crypto.rs` (the `crypto` feature), which itself implies `crypto-core`.
    #[must_use]
    pub const fn is_crypto_core(self) -> bool {
        matches!(
            self,
            Self::CryptoSha256
                | Self::CryptoSha512
                | Self::CryptoHmacSha256WithKey
                | Self::CryptoHmacSha512WithKey
                | Self::CryptoConstantTimeEqual
                | Self::CryptoRandomBytes
                | Self::CryptoRandomToken
                | Self::CryptoKeyFromString
                | Self::CryptoKeyFromBytes
                | Self::CryptoMacToHex
        )
    }

    /// `true` when this variant belongs to the `Ipe.Secret` opaque
    /// secret-string family (`Secret.fromString` / `reveal` / `use` / `redacted`).
    ///
    /// The `secret.rs` runtime module (a `zeroize`-on-`Drop` newtype with a
    /// `subtle` constant-time compare) is its sole consumer. Used by `ipe_lower`
    /// to detect `uses_secret` and by the backend to select the `secret` Cargo
    /// feature (which pulls `zeroize` + `subtle`, and implies `crypto-core` for
    /// the shared `subtle`). A program that reaches no `Secret.*` kernel and holds
    /// no `Secret`-typed value drops the module and `zeroize`.
    #[must_use]
    pub const fn is_secret(self) -> bool {
        matches!(
            self,
            Self::SecretFromString | Self::SecretReveal | Self::SecretUse | Self::SecretRedacted
        )
    }

    /// `true` when this kernel's use requires the `secret` Cargo feature even
    /// though it is NOT a `Ipe.Secret`-module kernel: `App.fromEnv` mints a
    /// `Secret`, and `Db.url` carries one into a `Setting` (the
    /// `app_config::Setting::DbUrl` variant is `secret`-gated). Distinct from
    /// [`Self::is_secret`], which tracks `secret.rs`-module residency.
    #[must_use]
    pub const fn needs_secret_feature(self) -> bool {
        self.is_secret()
            || matches!(
                self,
                Self::AppFromEnv
                    | Self::AppFromEnvRequired
                    | Self::DbUrlSetting
                    | Self::ConsoleAdminToken
                    | Self::ConsoleIngestToken
                    | Self::ConsoleMetricsToken
            )
    }

    /// `true` when this variant belongs to the `Ipe.Jwt` kernel family
    /// (`Jwt.encodeHs256` / `decodeHs256` / `encodeRs256` / `decodeRs256` and the
    /// builder API — `claims` / `hs256` / `rs256` / `subject` / `issuer` /
    /// `audience` / `expiresAt` / `notBefore` / `issuedAt` / `jwtId` /
    /// `withClaim` / `encode` / `decode`).
    ///
    /// The `jwt` runtime module is the sole direct consumer of the
    /// `jsonwebtoken` crate. Used by `ipe_lower` to detect `uses_jwt` and by the
    /// backend to declare `jwt` in the emitted `ipe_runtime/mod.rs` and add
    /// `jsonwebtoken` to the emitted manifest. `auth.rs` also reaches `jwt`, so
    /// the backend force-declares `jwt` under `uses_jwt || uses_auth`.
    #[must_use]
    pub const fn is_jwt(self) -> bool {
        matches!(
            self,
            Self::JwtEncodeHs256
                | Self::JwtDecodeHs256
                | Self::JwtEncodeRs256
                | Self::JwtDecodeRs256
                | Self::JwtClaims
                | Self::JwtHs256
                | Self::JwtRs256
                | Self::JwtSubject
                | Self::JwtIssuer
                | Self::JwtAudience
                | Self::JwtExpiresAt
                | Self::JwtNotBefore
                | Self::JwtIssuedAt
                | Self::JwtJwtId
                | Self::JwtWithClaim
                | Self::JwtEncode
                | Self::JwtDecode
        )
    }

    /// `true` when this kernel is part of the authed-route surface — the
    /// `Server` kernels whose runtime denotations token-verify through the `jwt`
    /// module (`server_get_authed` and companions, `server_auth_config`, the
    /// token-source constructors). Their runtime functions are `cfg(feature =
    /// "jwt")`, and the `server` feature does NOT imply `jwt`, so the backend
    /// selects `jwt` for a program that reaches any of them
    /// ([`crate::EmitCtx::reaches_jwt`]). Distinct from [`Self::is_jwt`], which is
    /// the `Jwt`-qualifier module-residency predicate a byte-parity tripwire pins.
    #[must_use]
    pub const fn is_authed_route(self) -> bool {
        matches!(
            self,
            Self::ServerGetAuthed
                | Self::ServerPostAuthed
                | Self::ServerPutAuthed
                | Self::ServerDeleteAuthed
                | Self::ServerAuthConfig
                | Self::ServerTokenBearer
                | Self::ServerCookieToken
                | Self::ServerWithRevocation
        )
    }

    /// `true` when this variant belongs to the `Ipe.Url` kernel family
    /// (`Url.fromString` / `toString` / `scheme` / `host` / `port` / `path` /
    /// `query` / `fragment` / `buildQuery`).
    ///
    /// The `url` runtime module (backing the opaque, validated `Url` type) is a
    /// direct consumer of the `url` crate, whose transitive `idna` → ICU4X
    /// subtree is the single largest gateable dependency root. Used by
    /// `ipe_lower` to detect `uses_url` and by the backend to declare `url` in
    /// the emitted `ipe_runtime/mod.rs` and add the `url` crate to the emitted
    /// manifest. The `http_client` and `ws_client` modules (and the shared
    /// `ssrf` validators) also parse with the `url` crate, so the backend
    /// force-declares `url` under `uses_url || reaches_http_client || websocket`.
    #[must_use]
    pub const fn is_url(self) -> bool {
        matches!(
            self,
            Self::UrlFromString
                | Self::UrlToString
                | Self::UrlScheme
                | Self::UrlHost
                | Self::UrlPort
                | Self::UrlPath
                | Self::UrlQuery
                | Self::UrlFragment
                | Self::UrlSchemeShown
                | Self::UrlBuildQuery
                | Self::UrlRelativeParse
                | Self::UrlRelativePath
                | Self::UrlRelativeQuery
                | Self::UrlRelativeFragment
                | Self::UrlRelativeToString
        )
    }

    /// `true` when this kernel's runtime implementation drives the future to
    /// completion only through the tokio reactor — a spawned task, a timer, a
    /// socket, an async filesystem offload, or a `.await` on any such primitive.
    /// A program that reaches such a kernel MUST link tokio and enter through
    /// its runtime; a program that reaches none of them runs on the std-only
    /// executor with a plain synchronous `fn main`, shedding the whole tokio
    /// subtree.
    ///
    /// FAIL-CLOSED. The default arm is `true`: a kernel counts as
    /// reactor-requiring UNLESS it is on the proven-pure whitelist below. A
    /// kernel added later, or one whose implementation is uncertain, is
    /// reactor-requiring by construction — so the worst a misjudgement can do is
    /// keep tokio for a program that did not need it (a lost optimisation),
    /// never emit a synchronous entry for a program whose future parks on a
    /// reactor op that will never fire (a hang). Every whitelisted family below
    /// is one whose runtime module drives its futures to `Ready` on the first
    /// poll — no `.await` on a reactor primitive, no `tokio::spawn`, no timer —
    /// verified against the runtime source.
    ///
    /// The whitelist is keyed on the kernel's canonical qualifier for the
    /// families that are pure in WHOLE. The mixed families (`Time`, `System`)
    /// carry both pure and reactor-driven members, so admitting them by
    /// qualifier would let any future reactor-driven member added under that
    /// qualifier default to pure — a silent hang. Those two families are held
    /// OFF the qualifier whitelist; their proven-pure members are admitted one
    /// by one by NAME ([`Self::is_reactor_free_time_or_system`]), so a new
    /// member of either defaults to reactor-requiring until it is audited and
    /// listed. `Task` is likewise mixed and never gets a qualifier entry.
    ///
    /// Not `const`: the whole-family arms compare the kernel's canonical
    /// qualifier (`&str`), which stable Rust cannot match in a `const fn`.
    #[must_use]
    pub fn requires_async_runtime(self) -> bool {
        // Every `Task` member — `Task.run` / `Task.perform` block on an inner
        // task of unknown purity, `Task.parallel` spawns, `Task.retryWith`
        // sleeps, `Task.attempt` bridges into the TEA loop — has no qualifier
        // entry and falls to the reactor-requiring default below.
        // The proven-pure members of the mixed `Time` / `System` families are
        // admitted one by one by NAME, so a new member of either family
        // defaults to reactor-requiring below.
        if self.is_reactor_free_time_or_system() {
            return false;
        }
        // Whole-family pure qualifiers: every kernel under these qualifiers
        // resolves without the reactor (synchronous computation, or a
        // synchronous `std` effect wrapped in an already-`Ready` future).
        // Verified reactor-free in the runtime module for each. The mixed
        // `Time` / `System` / `Task` families are deliberately absent — their
        // pure members were admitted by name above. A qualifier not listed here
        // is reactor-requiring.
        !matches!(
            self.decl().qualifier,
            "Log"
                | "String"
                | "Char"
                | "List"
                | "Basics"
                | "Maybe"
                | "Result"
                | "Math"
                | "Bitwise"
                | "Dict"
                | "Set"
                | "Bytes"
                | "Encoding"
                | "JsonEnc"
                | "JsonDec"
                | "JsonDecP"
                | "Uuid"
                | "Decimal"
                | "Money"
                | "Secret"
                | "Regex"
                | "Path"
                | "Locale"
                | "Error"
                | "CssSafety"
                | "Random"
                | "Io"
                | "Sql"
        )
    }

    /// `true` for the individually-audited, reactor-free members of the mixed
    /// `Time` and `System` families. These families each carry a reactor-driven
    /// member (`Time.sleep` / `Time.every` drive a tokio timer; `System.loadEnv`
    /// is a `spawn_blocking` offload), so neither can be admitted whole by
    /// qualifier without letting a future reactor-driven member default to pure.
    /// Membership here is an allow-list of the proven-pure members by name: a
    /// kernel added later under `Time` or `System` is absent, so
    /// [`Self::requires_async_runtime`] classifies it reactor-requiring until it
    /// is audited and added here.
    #[must_use]
    const fn is_reactor_free_time_or_system(self) -> bool {
        matches!(
            self,
            Self::TimeNow
                | Self::TimeUnixMillis
                | Self::TimeTimeString
                | Self::TimeIsLeapYear
                | Self::TimeDaysInMonth
                | Self::TimeFormat
                | Self::TimeFormatHTTP
                | Self::TimeFormatISO8601
                | Self::TimeFormatRFC3339
                | Self::TimeAddMillis
                | Self::TimeDiffMillis
                | Self::SystemArgs
                | Self::SystemGetenv
                | Self::SystemGetenvOr
                | Self::SystemGetArg
                | Self::SystemGetenvInt
                | Self::SystemGetenvBool
                | Self::SystemSetenv
                | Self::SystemUnsetenv
                | Self::SystemCwd
                | Self::SystemExit
        )
    }

    /// `true` when this variant belongs to the `Ipe.Ui` / `Ipe.Html` subsystem
    /// — every `class = Ui` element/attribute builder, plus the `Ipe.Color.Ansi`
    /// palette constructors (`qualifier = "TermColor"`), which are `class = Pure`
    /// (they must not force a UI runtime feature) yet the UI emitter hoists their
    /// appearance literals.
    ///
    /// Derived from the [`Self::decl`] class column plus that one named
    /// `qualifier` carve-out rather than a hand-mirrored variant set — like
    /// [`Self::is_db`] / [`Self::is_web`]. The `TermColor` carve-out is the sole
    /// off-class member of the UI *emitter domain*; `ui_predicate_tracks_ui_class_plus_termcolor`
    /// pins this predicate to its class/qualifier oracle, and the backend's
    /// `ui_call_shape_domain_is_reached_by_the_dispatcher` pins the whole domain
    /// (Ui/Web/Terminal + `TeaWorker` + `TermColor*`) to the class-routed
    /// dispatcher so no emitter can be gated on a set that silently spans classes
    /// the dispatcher separates.
    #[must_use]
    pub const fn is_ui(self) -> bool {
        if matches!(self.decl().class, KernelClass::Ui) {
            return true;
        }
        // The `Ipe.Color.Ansi` palette constructors are `class = Pure` but belong
        // to the UI emitter domain (their appearance literals hoist). Keyed on the
        // `TermColor` qualifier so a new palette constructor joins by construction.
        Self::str_eq(self.decl().qualifier, "TermColor")
    }

    /// Const-context `&str` equality — `==`/`matches!` on `str` is not `const`.
    /// Lockstep slice-pattern walk, no indexing.
    const fn str_eq(a: &str, b: &str) -> bool {
        let (mut a, mut b) = (a.as_bytes(), b.as_bytes());
        if a.len() != b.len() {
            return false;
        }
        while let ([x, xa @ ..], [y, yb @ ..]) = (a, b) {
            if *x != *y {
                return false;
            }
            a = xa;
            b = yb;
        }
        true
    }

    /// The fixed wire event name for a `Ipe.Html.Events` builder (`onClick` →
    /// `"click"`). `None` for any non-Html-event variant. The name is a
    /// compile-time constant (never attacker data) that the emit arm passes to
    /// the `html_on_*_` runtime constructor.
    #[must_use]
    pub const fn html_event_wire_name(self) -> Option<&'static str> {
        Some(match self {
            Self::HtmlOnClick => "click",
            Self::HtmlOnFocus => "focus",
            Self::HtmlOnBlur => "blur",
            Self::HtmlOnMouseOver => "mouseover",
            Self::HtmlOnMouseOut => "mouseout",
            Self::HtmlOnSubmit => "submit",
            Self::HtmlOnInput => "input",
            Self::HtmlOnKeyDown => "keydown",
            Self::HtmlOnKeyUp => "keyup",
            // `onBool` mirrors `Ipe.Html.Events.onCheck` — the checkbox check
            // state arrives on the `change` DOM event, same wire name as
            // `onChange`.
            Self::HtmlOnChange | Self::HtmlOnBool => "change",
            _ => return None,
        })
    }

    /// The event payload shape of a `Ipe.Html.Events` builder, driving both the
    /// constrain scheme and the emit arm. `None` for any non-Html-event variant.
    #[must_use]
    pub const fn html_event_shape(self) -> Option<HtmlEventShape> {
        Some(match self {
            Self::HtmlOnClick
            | Self::HtmlOnFocus
            | Self::HtmlOnBlur
            | Self::HtmlOnMouseOver
            | Self::HtmlOnMouseOut => HtmlEventShape::Msg,
            Self::HtmlOnInput | Self::HtmlOnChange | Self::HtmlOnKeyDown | Self::HtmlOnKeyUp => {
                HtmlEventShape::String
            }
            Self::HtmlOnBool => HtmlEventShape::Bool,
            Self::HtmlOnSubmit => HtmlEventShape::Raw,
            _ => return None,
        })
    }

    /// `true` for a kernel whose Rust runtime consumer requires its
    /// function-valued argument to be `Send + Sync` — either an
    /// `Arc<dyn Fn(..) -> .. + Send + Sync + 'static>` runtime slot
    /// (`ui_on_input_`/`ui_on_change_`/…, `html_on_string_`/`html_on_bool_`/
    /// `html_on_raw_`) or a generic `F: .. + Send + Sync + 'static` bound
    /// (`ui_on_submit_`, `server_stream_stream`) — NOT merely `Send`
    /// (`Box<dyn Fn(..) -> .. + Send + 'static>`, which is how a generic
    /// `IrType::Fun` renders in `emit_types.rs`).
    ///
    /// The emit-site "re-wrap the payload in a freshly-declared closure"
    /// technique (`ipe_backend_rust::emit_expr`'s `KernelFn::UiOnSubmit` /
    /// `HtmlEventShape::Raw` / `StreamStream` arms) only launders a
    /// MISSING `+Sync` bound when the payload is constructed INLINE at the call
    /// site (a literal `Lambda`/`FuncValue` — the box is rebuilt fresh, as
    /// source, inside the wrapper's body on every call, so it never enters the
    /// wrapper's own captured environment). A `Var`/`CloneVar` referencing an
    /// ALREADY-BUILT `let`-bound closure is a different shape: the wrapper
    /// closure captures that already-existing value BY MOVE, and Rust's
    /// auto-trait inference is structural over every captured field — a
    /// captured `Box<dyn Fn + Send>` (never `+Sync`) makes the wrapper itself
    /// non-`Sync`, no matter how the wrapper's body is written. Re-wrapping
    /// cannot launder a missing trait bound on a value that already exists.
    ///
    /// This predicate is consulted by
    /// `ipe_lower::flows_into_sync_kernel_call` (from `lower_let_pvar`,
    /// alongside the `needs_shared_capture` nested/sibling check) to decide
    /// whether a `let`-bound function-typed local must be
    /// promoted to `Expr::SharedLambda` — emitted as
    /// `Arc<dyn Fn(..) -> .. + Send + Sync + 'static>` — even for a single,
    /// non-nested use. Unlike `needs_shared_capture`'s trigger (2+ competing
    /// closure captures), a SINGLE occurrence here is already sufficient: the
    /// runtime callback slot's `+Sync` bound applies however many times the
    /// value is referenced.
    ///
    /// Deliberately excludes the WebSocket server-config callbacks and the
    /// `Ipe.Http.Server` request-handler shape: both are ALREADY immune by a
    /// different, structural mechanism —
    /// `ipe_backend_rust::emit_expr::wants_arc_ctor` recognises their FIXED
    /// closure shape at the closure's OWN construction site and boxes with
    /// `Arc::new` there, regardless of inline-vs-`let`-bound. `Ui.on*` /
    /// `Ipe.Html.Events.on*` / `Stream.stream` have no such fixed structural
    /// shape (their callback's argument/return type is the app's own
    /// polymorphic `msg`), so they need this USAGE-SITE detection instead.
    #[must_use]
    pub const fn requires_sync_capture(self) -> bool {
        matches!(
            self,
            Self::UiOnInput
                | Self::UiOnChange
                | Self::UiOnKeyDown
                | Self::UiOnKeyUp
                | Self::UiOnFile
                | Self::UiOnBool
                | Self::UiOnSubmit
                | Self::HtmlOnInput
                | Self::HtmlOnChange
                | Self::HtmlOnKeyDown
                | Self::HtmlOnKeyUp
                | Self::HtmlOnBool
                | Self::HtmlOnSubmit
                | Self::StreamStream
        )
    }

    /// The argument index of the handler the backend re-wraps with a capture-clone prologue.
    ///
    /// The backend rebuilds this handler inside a fresh `move` closure per call
    /// and shadows every free local the handler captures with `.clone()`, so
    /// each such capture must be `Clone`. The lowerer reads this index to refuse
    /// a non-`Clone` capture (IPE-L0126) and a point-free or partial use
    /// (IPE-L0152) at `ipe` time; the backend asserts the index at build time
    /// against the argument it re-wraps.
    #[must_use]
    pub const fn capture_cloned_handler_arg(self) -> Option<usize> {
        match self {
            Self::StreamStream => Some(1),
            _ => None,
        }
    }

    /// The carrier of this kernel's argument `arg`, or `None` when `arg` is not a function slot.
    ///
    /// Derived from the kernel scheme alone: an argument below the arity whose
    /// scheme position is an arrow is a function slot. It is
    /// [`FnSlotCarrier::AcceptsShared`] when the backend re-wraps the kernel's
    /// callback as an `Arc` ([`Self::requires_sync_capture`]), and
    /// [`FnSlotCarrier::Direct`] otherwise. A scheme-variable position (`a`
    /// instantiated at a function) is not a function slot.
    #[must_use]
    pub const fn fn_slot_carrier(self, arg: usize) -> Option<FnSlotCarrier> {
        if arg >= self.decl().arity as usize {
            return None;
        }
        let Some(shape) = self.scheme_shape() else {
            return None;
        };
        match spine_arg(shape, arg) {
            Some(TyShape::Fun(..)) if self.requires_sync_capture() => {
                Some(FnSlotCarrier::AcceptsShared)
            }
            Some(TyShape::Fun(..)) => Some(FnSlotCarrier::Direct),
            _ => None,
        }
    }

    /// The scheme variable whose solved instance must hold no function type.
    ///
    /// `task_loop` carries its state between steps as plain data, so the
    /// lowerer refuses a call whose state variable is solved to a type
    /// containing a function, and refuses fail-closed when no solved type is
    /// recorded for the reference.
    #[must_use]
    pub const fn plain_data_scheme_var(self) -> Option<u8> {
        match self {
            Self::TaskLoop => Some(0),
            _ => None,
        }
    }

    /// `true` when this variant belongs to the `Ipe.Web` subsystem — the
    /// `Ipe.Web` app-entry kernels plus the Task-shaped `PubSub.publish` /
    /// `publishNoEcho`, all of which are `class = Web` and whose symbols live in
    /// `ipe_runtime::web` (gated by the `web` Cargo feature).
    ///
    /// Derived from the [`Self::decl`] class column (const, so this predicate
    /// stays const) rather than hand-mirroring the variant set — exactly like
    /// [`Self::is_db`]. `is_web` is the SOLE selector that fires the `live`
    /// feature-module append; a `class = Web` kernel a hand list forgot would
    /// leave `web::*` out of scope in the emitted crate (E0425). Reading the
    /// class makes that drift unrepresentable, not merely test-detectable.
    #[must_use]
    pub const fn is_web(self) -> bool {
        matches!(self.decl().class, KernelClass::Web)
    }

    /// `true` when this variant is the `Ipe.Terminal` full-screen app-entry.
    #[must_use]
    pub const fn is_tui(self) -> bool {
        matches!(self, Self::TerminalAppScreen)
    }

    /// `true` when this variant is the `Ipe.Terminal` line-oriented app-entry.
    #[must_use]
    pub const fn is_console(self) -> bool {
        matches!(self, Self::TerminalAppLines)
    }

    /// `true` when this variant is the view-less `Ipe.Tea.Worker.tea` app-entry.
    #[must_use]
    pub const fn is_worker(self) -> bool {
        matches!(self, Self::TeaWorker)
    }

    /// The order this kernel's runtime function takes its arguments in.
    #[must_use]
    pub const fn arg_order(self) -> ArgOrder {
        self.identity().arg_order
    }

    /// `true` when this variant is an app entry: it takes an app cfg record and builds a program.
    ///
    /// Every app entry's runtime function bounds the cfg's `Model` / `Msg` with
    /// traits a generic type parameter does not carry (`IpeStringify`,
    /// `Serialize`, `Sync`, …), so the lowerer refuses an entry reference whose
    /// solved type still mentions a generic of the enclosing definition. The
    /// build asserts this set equals the schemed kernels yielding an app carrier
    /// ([`app_entries_match_their_schemes`]).
    #[must_use]
    pub const fn is_app_entry(self) -> bool {
        matches!(
            self,
            Self::WebApp
                | Self::WebEmbed
                | Self::WebAppRouted
                | Self::WebAppWith
                | Self::TerminalAppScreen
                | Self::TerminalAppLines
                | Self::TeaWorker
        )
    }

    /// The app surface this app-entry kernel pins, when it is one.
    #[must_use]
    pub const fn app_entry_surface(self) -> Option<AppSurface> {
        match self {
            Self::WebApp | Self::WebAppRouted | Self::WebAppWith | Self::WebEmbed => {
                Some(AppSurface::Web)
            }
            Self::TerminalAppScreen => Some(AppSurface::Tui),
            Self::TerminalAppLines => Some(AppSurface::Cli),
            Self::TeaWorker => Some(AppSurface::Worker),
            _ => None,
        }
    }

    /// The one app surface whose loop reads this shape-owned input subscription.
    ///
    /// `Tui.Sub.onKey` is driven only by the `Tui` loop and `Cli.Sub.onLine` only
    /// by the `Cli` loop; anywhere else the subscription would be silently dead.
    #[must_use]
    pub const fn input_surface(self) -> Option<AppSurface> {
        match self {
            Self::TuiSubOnKey => Some(AppSurface::Tui),
            Self::CliSubOnLine => Some(AppSurface::Cli),
            _ => None,
        }
    }

    /// Whether this kernel is emittable only as a saturated call.
    ///
    /// Such a kernel's emit arm carries a bridge or a guard (the input
    /// subscriptions' `KeyEvent` bridge and surface check, `Task.loop`'s bridge
    /// from the emitted `Step` enum to the runtime `LoopStep`) that a point-free
    /// first-class reference would bypass, so the lowerer eta-expands every
    /// point-free reference to it into `\x -> kernel x` and the backend refuses
    /// to box it as a bare function value.
    #[must_use]
    pub const fn requires_saturated_emit(self) -> bool {
        self.input_surface().is_some() || matches!(self, Self::TaskLoop)
    }

    /// `true` when this variant belongs to the `Ipe.CssSafety` leaf
    /// security-kernel family (the `Ipe.Css` backing): `safe_value` /
    /// `safe_prop_name` / `safe_selector` / `strip_style_close_kernel`.
    ///
    /// These kernels live in `ipe_runtime::css` (which glob-re-exports their
    /// bare names) and depend only on `ipe_runtime::css_safety`. A program that
    /// uses `Ipe.Css` WITHOUT any `Ipe.Ui` / `Ipe.Html` kernel does NOT set
    /// `uses_ui`, so the backend consults this predicate to decide whether the
    /// emitted `ipe_runtime/mod.rs` must declare `css_safety` / `css` (and
    /// `pub use css::*`) on its own — otherwise the bare `safe_value` … names
    /// `naming::kernel_name` emits are out of scope (E0425).
    #[must_use]
    pub const fn is_css(self) -> bool {
        matches!(
            self,
            Self::CssSafetySafeValue
                | Self::CssSafetySafePropName
                | Self::CssSafetySafeSelector
                | Self::CssSafetySanitizeRawBody
                | Self::CssSafetyStripStyleClose
        )
    }
}

// ── Two-tier kernel identity ─────────────────────────────────────────────────

/// Opaque identifier for a user-provided FFI binding.
///
/// Reserved. The landed FFI consumer wiring realises the open registry
/// WITHOUT a kernel-tier id: each bound crate becomes a driver-generated,
/// fully-annotated `Rust.<Crate>` interface module
/// (`ipe_canon::resolve::ModuleOrigin::FfiInterface`) whose forwarder bodies
/// lower to `ipe_ir::Callee::Ffi { ident }` — FFI signatures ride the ONE
/// existing annotation → `Ty` path, so there is no second scheme table for
/// this id to index. The variant stays reserved for a future need to
/// register an FFI binding at the KERNEL tier (e.g. a stdlib-visible alias
/// onto a bound crate); constructors are deliberately unexposed until that
/// consumer exists.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FfiKernelId(u32);

/// A fully-resolved kernel function.
///
/// Either a known stdlib kernel (resolved at canonicalisation time) or a
/// user-provided FFI binding (reserved — see [`FfiKernelId`] for why the
/// landed FFI wiring does not mint these).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KernelId {
    /// A known stdlib kernel.
    Stdlib(StdlibKernel),
    /// A user-provided FFI binding (reserved).
    Ffi(FfiKernelId),
}

// ── Compilation target — kernel availability ──────────────────────────────────

/// The compilation target a build resolves kernels against.
///
/// `WasmClient` is a public browser bundle: every kernel is DENIED there
/// unless [`StdlibKernel::available_on`] explicitly allows it (default-deny —
/// a newly added kernel is unrepresentable client-side until audited and
/// allowed, so the forgotten state is the safe state; see
/// `docs/adr/0005-delivery-shapes-runtimes-hosts-targets.md` Q5 Layer 1).
///
/// `WasmWasi` is the co-located portable WASI target (`wasm32-wasip1`): a
/// native-ish target whose effects run through WASI (stdio, the WASI clock, the
/// preopened-dir filesystem, `random_get` entropy) rather than the browser
/// sandbox's Web-API substitutes. It is DISTINCT from `WasmClient`: the browser
/// client denies native effects and reaches the world only through Web APIs,
/// whereas WASI runs a `Direct`/`Script` program's native effect floor. Its
/// availability set is ALSO default-deny — a kernel appears only if its runtime
/// module actually compiles on `wasm32-wasip1` — because the non-viable
/// families (`Http`/`WebSocket` → reqwest/tokio-tungstenite → `tokio/net`→`mio`;
/// `compression`/`csv`/`config` → `tokio::spawn_blocking`; the whole
/// tokio/axum/db/TEA/browser surface) do not build on wasip1, and admitting one
/// would break THE SEAL (`ipe`-accept then `cargo build --target wasm32-wasip1`
/// fail).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, serde::Serialize, serde::Deserialize)]
pub enum Target {
    /// The native host binary (server / CLI / TUI / desktop).
    #[default]
    Native,
    /// A browser WASM bundle (`ipe dev build --target wasm`) — fully public,
    /// `wasm2wat`-inspectable; no server effect or secret may compile in.
    WasmClient,
    /// A co-located portable WASI bundle (`wasm32-wasip1`) — a `Direct`/`Script`
    /// program running its native effect floor over WASI. Default-deny to the
    /// WASI-viable sealed floor; every non-viable family is refused at `ipe`
    /// time so it never reaches the wasip1 `cargo build`.
    WasmWasi,
}

impl StdlibKernel {
    /// Whether this kernel has a denotation on `target`.
    ///
    /// Everything is available natively. The `WasmClient` arm is the
    /// default-deny allowlist over the capability matrix
    /// (`docs/adr/0005-delivery-shapes-runtimes-hosts-targets.md` Q3): the pure/fallible-pure
    /// families plus the whole `Ipe.Ui`/`Ipe.Html`/`Ipe.Css` render surface
    /// compile wholesale; effect kernels appear here ONLY once their browser
    /// substitute exists in the runtime `wasm` module (tagging earlier would
    /// break THE SEAL — the name would resolve with no symbol to link).
    #[must_use]
    pub fn available_on(self, target: Target) -> bool {
        match target {
            Target::Native => true,
            Target::WasmClient => self.wasm_client_available(),
            Target::WasmWasi => self.wasi_available(),
        }
    }

    /// The `WasmClient` allowlist. The catch-all `false` arm IS the
    /// default-deny invariant — never widen it to a family without a probe
    /// build proving the family's runtime module compiles to wasm32.
    #[allow(clippy::too_many_lines)]
    fn wasm_client_available(self) -> bool {
        let decl = self.decl();
        match decl.class {
            // The whole render surface (Ui/Html/Attr/Event/Font/Border/
            // Background/Input/Region/Lazy/Keyed) — probe-verified to
            // compile to wasm32 as part of the runtime floor.
            KernelClass::Ui => true,
            // `Web.tea` gains a browser denotation via the runtime `wasm`
            // sink (`wasm_app` / `wasm_app_routed`). `Web.route` constructs a
            // `Route<Page>` via `ipe_runtime::web::route::Route::new` — the
            // `web::route` module is pure (no tokio/axum) and is vendored into
            // the wasm project's `pub mod web { pub mod route; }` submodule.
            // `PubSub.publish` / `publishNoEcho` are `class = Web` (Task-shaped,
            // not TEA-loop) and route through the in-tab broker (`wasm::pubsub`),
            // the same M4 Cmd/Sub browser-effects bridge the TEA-side pub/sub uses.
            KernelClass::Web => matches!(
                self,
                Self::WebApp | Self::WebRoute | Self::PubSubPublish | Self::PubSubPublishNoEcho
            ),
            // TEA wiring the wasm scheduler drives today. `Cmd.perform` runs
            // on the browser microtask queue; `Sub.every`/`Time.every` run on
            // `gloo-timers` (`wasm::subs::SubManager`); `Cmd.publish` /
            // `Cmd.publishNoEcho` / `Sub.subscribeTopic` route through the in-tab
            // broker (`wasm::pubsub`) — the M4 Cmd/Sub browser-effects bridge.
            // (The Task-shaped `PubSub.publish` / `publishNoEcho` are `class = Web`
            // and handled in the `KernelClass::Web` arm above.)
            // `SubSubscribeWebSocket` (the WebSocket client's onOpen/
            // onMessage/onClose/onError receive surface) routes through
            // `ws_client.rs`'s wasm32 arm — `web_sys::WebSocket`'s
            // `onopen`/`onmessage`/`onclose`/`onerror` handler slots.
            // `JsSend`/`JsSubscribe` (the typed `Ipe.Ffi.Js` port) route through
            // `js_port.rs`'s wasm32 arm: outbound `Js.send` posts the sealed
            // frame to `window.ipeOnReceive`, inbound `Js.subscribe` drains the
            // in-tab queue the page's `window.ipe.send` feeds — the SAME bounded,
            // fail-closed seal decoder the native port uses. The concrete-ADT
            // seal (IPE-N0039) that governs every value crossing the port is
            // unchanged; this only gives the existing typed port a client sink.
            KernelClass::Tea => matches!(
                self,
                Self::CmdNone
                    | Self::CmdBatch
                    | Self::CmdPerform
                    | Self::CmdMap
                    | Self::TaskAttempt
                    | Self::SubNone
                    | Self::SubBatch
                    | Self::SubEvery
                    | Self::SubMap
                    | Self::TimeEvery
                    | Self::CmdPublish
                    | Self::CmdPublishNoEcho
                    | Self::SubSubscribeTopic
                    | Self::SubSubscribeWebSocket
                    | Self::JsSend
                    | Self::JsSubscribe
                    | Self::JsRequest
                    | Self::JsOpenSession
                    | Self::JsSessionFrames
                    | Self::JsSendToSession
                    | Self::JsCloseSession
            ),
            KernelClass::Pure => {
                // `StringToUpperIn` / `StringToLowerIn` require ICU4X
                // `icu_casemap` which has no wasm32 build in the current feature
                // graph.  Their qualifier is `"String"` which appears in the
                // wasm-allowed qualifier set below, so they must be explicitly
                // excluded first before the qualifier-wide allow fires.
                // `LocaleFromTag` / `LocaleToTag` carry qualifier `"Locale"` which
                // is NOT in the set — they are already denied by the catch-all.
                if matches!(self, Self::StringToUpperIn | Self::StringToLowerIn) {
                    return false;
                }
                // `Path.absolute` reads the process working directory — a
                // `Filesystem` read a browser tab has no denotation for — so it
                // is denied before the `Path` qualifier-wide allow fires.
                if matches!(self, Self::PathAbsolute) {
                    return false;
                }
                // Pure families whose runtime modules are in the proven wasm
                // floor (no host I/O, no tokio, no un-shimmed entropy) OR
                // whose M4 browser substitute has landed:
                //   - `Log` → `console.{debug,info,warn,error}` (log.rs).
                //   - `Random` → `crypto.getRandomValues` via getrandom(js)
                //     (random.rs's `lcg_init` wasm arm) — all 3 registered
                //     kernels (int/float/choice) share the one entropy fix.
                //   - `Http` → `fetch` (http_client.rs); this qualifier ALSO
                //     covers the header/UninitialisedRequest builder kernels
                //     (`defaultRequest`/`withMethod`/…), which have no
                //     runtime symbol at all (inline `HttpRequest{..}` struct
                //     literals in `emit_expr.rs`) and so carry no wasm risk.
                //   - `Url` → the `url` crate's pure parser (url.rs), which has
                //     a genuine wasm32 build (no host I/O, no tokio). Required
                //     because `Http.get`/`post` take a typed `Url`, whose only
                //     constructor (`Url.fromString`) must be callable on the
                //     client for a browser fetch to build a request at all.
                matches!(
                    decl.qualifier,
                    "String"
                        | "Char"
                        | "List"
                        | "Basics"
                        | "Math"
                        | "Dict"
                        | "Set"
                        | "Maybe"
                        | "Result"
                        | "Error"
                        | "Bytes"
                        | "Encoding"
                        | "JsonEnc"
                        | "JsonDec"
                        | "JsonDecP"
                        | "Decimal"
                        | "Regex"
                        | "Path"
                        | "Secret"
                        | "CssSafety"
                        | "Uuid"
                        | "Log"
                        | "Random"
                        | "Http"
                        | "Url"
                ) ||
                // Pure calendar helpers (chrono, no clock read) PLUS the M4
                // `Date.now()`/`setTimeout` clock+sleep substitutes.
                matches!(
                    self,
                    Self::TimeTimeString
                        | Self::TimeIsLeapYear
                        | Self::TimeDaysInMonth
                        | Self::TimeFormat
                        | Self::TimeFormatHTTP
                        | Self::TimeFormatISO8601
                        | Self::TimeFormatRFC3339
                        | Self::TimeAddMillis
                        | Self::TimeDiffMillis
                        | Self::TimeNow
                        | Self::TimeSleep
                        | Self::TimeUnixMillis
                ) ||
                // `Crypto.randomBytes`/`randomToken` — `crypto.getRandomValues`
                // via getrandom(js) (crypto.rs's wasm32 arm). Every OTHER
                // `Crypto` kernel (hashing, AEAD, RSA, PBKDF2) stays denied —
                // deliberately NOT a qualifier-wide allow.
                matches!(self, Self::CryptoRandomBytes | Self::CryptoRandomToken) ||
                // `Ipe.WebSocket` client Task-tier — `web_sys::WebSocket`
                // (ws_client.rs's wasm32 arm). The Sub-tier receive kernel
                // (`SubSubscribeWebSocket`) is `Tea`-classed, not `Pure` —
                // see the `KernelClass::Tea` arm above.
                matches!(
                    self,
                    Self::WebSocketConnect
                        | Self::WebSocketConnectWith
                        | Self::WebSocketSend
                        | Self::WebSocketSendBinary
                        | Self::WebSocketClose
                        | Self::WebSocketCloseWithCode
                ) ||
                // `Task.*` pure future combinators (`task.rs`'s ungated half —
                // no tokio dependency, just `Box::pin(async move { .. })` over
                // an already-`IpeTask`). Required for the M4 bridge to be
                // usable at all: `Ipe.WebSocket.connect`/`Http.get`'s own
                // stdlib wrappers (`Task.map`, …) call these, so every
                // Cmd.perform pipeline routes through at least `Task.map`.
                // `Task.run`/`Task.parallel`/`Task.retryWith`/`Task.perform`
                // stay denied — their runtime bodies are tokio-bound
                // (`block_on`/`tokio::spawn`/`tokio::time::sleep`) and have no
                // wasm arm.
                matches!(
                    self,
                    Self::TaskSucceed
                        | Self::TaskFail
                        | Self::TaskMap
                        | Self::TaskMap2
                        | Self::TaskMap3
                        | Self::TaskMap4
                        | Self::TaskMap5
                        | Self::TaskAndThen
                        | Self::TaskMapError
                        | Self::TaskOnError
                        | Self::TaskFromResult
                        | Self::TaskAndThenResult
                        | Self::TaskSequence
                        | Self::TaskLoop
                ) ||
                // `Env.public` — build-time-embedded `[wasm] publicEnv`
                // allowlist (`option_env!` on wasm32; the SAME allowlist via
                // `std::env::var` natively — `env_public.rs`, backend-
                // generated per project, never vendored from the source tree).
                matches!(self, Self::EnvPublic) ||
                // `PubSub.topic` — identity over a String; no runtime I/O.
                // Emits as pass-through in the wasm backend (same as native).
                matches!(self, Self::PubSubTopic)
            }
            // Server-only surfaces: no browser denotation, ever (Db/Server)
            // or until a dedicated backend exists (Terminal/Ffi).
            KernelClass::Db | KernelClass::Server | KernelClass::Terminal | KernelClass::Ffi => {
                false
            }
        }
    }

    /// The co-located WASI (`wasm32-wasip1`) allowlist — the SEALED FLOOR.
    ///
    /// Default-deny like [`Self::wasm_client_available`], but keyed to a
    /// DIFFERENT viable set: WASI runs a `Direct`/`Script` program's NATIVE
    /// effect floor through WASI (stdio, the WASI clock, the preopened-dir
    /// filesystem, `random_get` entropy), so it admits the always-on effect
    /// floor (`Io`/`File`/`System` + the `Task` reactor spine) and the pure
    /// computational families — the exact surface the runtime
    /// `_WASI_EFFECT_FLOOR_SEAL` binds and a wasip1 runtime build proves resolves.
    ///
    /// It is NOT the browser allowlist: the browser-only effect kernels denote
    /// through Web-API substitutes (`Http` → `fetch`, `WebSocket` →
    /// `web_sys::WebSocket`, the `Ipe.Ffi.Js` ports, the TEA loop, the render
    /// surface) that have NO wasip1 arm, and their native crates
    /// (reqwest/tokio-tungstenite → `tokio/net`→`mio`) do not build on wasip1.
    /// Every such family is DENIED here — admitting one would break THE SEAL.
    /// The catch-all `false` is the default-deny invariant: a newly added kernel
    /// is unrepresentable on WASI until its runtime module is proven to compile
    /// on `wasm32-wasip1`.
    #[allow(clippy::too_many_lines)]
    fn wasi_available(self) -> bool {
        let decl = self.decl();
        match decl.class {
            // No co-located WASI denotation: the render surface / TEA wiring /
            // `Web`-app entries are browser/native-loop surfaces (a WASI program
            // is `Direct`/`Script`, never a TEA loop), and Db/Server/Terminal/Ffi
            // ride tokio/axum/sqlx reactor spines that do not build on wasip1.
            KernelClass::Ui
            | KernelClass::Web
            | KernelClass::Tea
            | KernelClass::Db
            | KernelClass::Server
            | KernelClass::Terminal
            | KernelClass::Ffi => false,
            // Everything the runtime calls "pure" — which INCLUDES the effect
            // floor (`Io`/`File`/`System`/`Task`/`Time`) as well as the genuine
            // pure families — distinguished by qualifier + kernel.
            KernelClass::Pure => {
                // ICU4X case-mapping has no wasip1 build (same as the browser
                // arm) — deny before the qualifier-wide allow fires.
                if matches!(self, Self::StringToUpperIn | Self::StringToLowerIn) {
                    return false;
                }
                // The always-on native effect floor a `Direct`/`Script` program
                // reaches over WASI: stdio (`Io`), the preopened-dir filesystem
                // (`File`), the process environment/args + exit (`System`). Each
                // compiles on wasip1 (the always-compiled runtime modules the
                // baseline wasip1 build resolves); an operation with no WASI
                // mapping (subprocess spawn) returns a typed `Err`, never a panic
                // — fail-closed through the `Result` channel. This is the exact
                // surface the runtime `_WASI_EFFECT_FLOOR_SEAL` binds.
                matches!(decl.qualifier, "Io" | "File" | "System")
                // The full `Ipe.Time` calendar + clock surface. WASI HAS a real
                // clock, so `Time.now`/`unixMillis`/`sleep` resolve against the
                // native `SystemTime`/`chrono` arm (the `_WASI_TIME_FLOOR_SEAL`),
                // NOT the browser `Date.now()` substitute — so the WHOLE family
                // is viable, unlike on the browser (which admits only a subset).
                || matches!(decl.qualifier, "Time")
                // The pure computational families whose runtime modules build on
                // wasip1 — the SAME proven-wasm modules the browser floor uses
                // (no host I/O, no tokio, no un-shimmed entropy). `Http`/`Url`
                // are DELIBERATELY absent: `Http` has no wasip1 arm (fetch is
                // browser-only, reqwest does not build there), and `Url` is only
                // pulled in by the HTTP client, so it carries no WASI denotation
                // on the sealed floor.
                || matches!(
                    decl.qualifier,
                    "String"
                        | "Char"
                        | "List"
                        | "Basics"
                        | "Math"
                        | "Dict"
                        | "Set"
                        | "Maybe"
                        | "Result"
                        | "Error"
                        | "Bytes"
                        | "Encoding"
                        | "JsonEnc"
                        | "JsonDec"
                        | "JsonDecP"
                        | "Decimal"
                        | "Regex"
                        | "Path"
                        | "Secret"
                        | "CssSafety"
                        | "Uuid"
                        | "Log"
                        | "Random"
                )
                // `Crypto.randomBytes`/`randomToken` — `random_get` entropy via
                // getrandom. Every OTHER `Crypto` kernel (hashing, AEAD, RSA,
                // PBKDF2) stays denied: the heavy crypto surface is out of the
                // sealed floor.
                || matches!(self, Self::CryptoRandomBytes | Self::CryptoRandomToken)
                // `Task.*` pure future combinators — the std-only reactor spine
                // (`block_on`/`task_run`/`task_parallel`, the LIVE wasip1 arm; no
                // tokio) drives a `Direct` program's `main`. The tokio-bound
                // `Task.run`/`parallel`/`retryWith`/`perform` stay denied (their
                // runtime bodies are `block_on`/`tokio::spawn`/`tokio::time`).
                || matches!(
                    self,
                    Self::TaskSucceed
                        | Self::TaskFail
                        | Self::TaskMap
                        | Self::TaskMap2
                        | Self::TaskMap3
                        | Self::TaskMap4
                        | Self::TaskMap5
                        | Self::TaskAndThen
                        | Self::TaskMapError
                        | Self::TaskOnError
                        | Self::TaskFromResult
                        | Self::TaskAndThenResult
                        | Self::TaskSequence
                        | Self::TaskLoop
                )
                // `Env.public` — build-time-embedded allowlist (`option_env!` on
                // wasm32, the same as the browser arm).
                || matches!(self, Self::EnvPublic)
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use strum::EnumCount as _;

    use super::StdlibKernel;

    /// The kernel variants deliberately absent from [`StdlibKernel::ALL`], each
    /// with the reason it is not a wired row.
    ///
    /// `ALL` is the canonical *wired* slice — the variants that carry a kernel
    /// id and whose scheme arm is consulted. Two `Task` aliases are intentionally
    /// not wired:
    ///
    /// - [`StdlibKernel::TaskRun`] and [`StdlibKernel::TaskPerform`] are the
    ///   auto-run entry aliases (both emit `task_run`, arity 1, class `Pure`, no
    ///   capability, no runtime module). They are lowered and emitted through a
    ///   dedicated whole-function-body path, not through `ALL`-driven kernel-id
    ///   dispatch, so wiring them into `ALL` would assign them ids and pull them
    ///   into every `ALL`-iterating consumer for no benefit. They are excluded
    ///   here explicitly rather than silently missing.
    ///
    /// The [`all_covers_every_variant_except_documented_exclusions`] guard fails
    /// closed if the count of wired + excluded variants ever disagrees with the
    /// compiler-maintained [`StdlibKernel::COUNT`] — so a newly added variant
    /// forgotten in both `ALL` and this list cannot slip through.
    const UNWIRED_VARIANTS: &[StdlibKernel] = &[StdlibKernel::TaskRun, StdlibKernel::TaskPerform];

    /// Whether `kernel`'s mapper argument `arg` binds a stored element at parameter `param`.
    fn binds(kernel: StdlibKernel, arg: usize, param: usize) -> bool {
        kernel.scheme_shape().is_some_and(|shape| {
            super::mapper_param_binds_stored_element(shape, kernel.def().arity, arg, param)
        })
    }

    /// Every element-feeding higher-order kernel binds its element parameters,
    /// derived from the scheme alone: the `List` family (each list of
    /// `map2`..`map5` binding its own parameter) and the value of the `Dict`
    /// family.
    #[test]
    fn mapper_params_bind_stored_elements() {
        use StdlibKernel as K;
        let bound: &[(K, usize, usize)] = &[
            (K::ListMap, 0, 0),
            (K::ListFilter, 0, 0),
            (K::ListFilterMap, 0, 0),
            (K::ListConcatMap, 0, 0),
            (K::ListAny, 0, 0),
            (K::ListAll, 0, 0),
            (K::ListFind, 0, 0),
            (K::ListFoldl, 0, 0),
            (K::ListFoldr, 0, 0),
            (K::ListIndexedMap, 0, 1),
            (K::ListPartition, 0, 0),
            (K::ListSortBy, 0, 0),
            (K::ListSortWith, 0, 0),
            (K::ListSortWith, 0, 1),
            (K::ListMap2, 0, 0),
            (K::ListMap2, 0, 1),
            (K::ListMap3, 0, 2),
            (K::ListMap4, 0, 3),
            (K::ListMap5, 0, 0),
            (K::ListMap5, 0, 4),
            (K::DictMap, 0, 1),
            (K::DictFilter, 0, 1),
            (K::DictPartition, 0, 1),
            (K::DictFoldl, 0, 1),
            (K::DictFoldr, 0, 1),
        ];
        for &(kernel, arg, param) in bound {
            assert!(
                binds(kernel, arg, param),
                "{kernel:?} arg {arg} param {param}"
            );
        }
    }

    /// A parameter that is not a bare function-admitting stored element binds
    /// nothing: an index, an accumulator, a `Maybe`-wrapped value, a `Dict` key
    /// and a `Set` element (neither ever holds a function), a non-function
    /// argument, and a position past the mapper's own parameters.
    #[test]
    fn non_element_mapper_params_do_not_bind() {
        use StdlibKernel as K;
        let unbound: &[(K, usize, usize)] = &[
            (K::ListIndexedMap, 0, 0),
            (K::ListFoldl, 0, 1),
            (K::DictFoldl, 0, 2),
            (K::DictUpdate, 1, 0),
            (K::DictMap, 0, 0),
            (K::DictFilter, 0, 0),
            (K::DictFoldl, 0, 0),
            (K::DictFoldr, 0, 0),
            (K::SetMap, 0, 0),
            (K::SetFilter, 0, 0),
            (K::SetFoldl, 0, 0),
            (K::ListMap, 1, 0),
            (K::ListMap, 0, 1),
            (K::ListMap, 2, 0),
            (K::ListMap2, 0, 2),
        ];
        for &(kernel, arg, param) in unbound {
            assert!(
                !binds(kernel, arg, param),
                "{kernel:?} arg {arg} param {param}"
            );
        }
    }

    /// `ALL` must cover every `StdlibKernel` variant except the documented
    /// [`UNWIRED_VARIANTS`]. Both Kernel Row invariant suites iterate `ALL`, so
    /// their whole safety rests on `ALL` being exhaustive; this guard is that
    /// safety net.
    ///
    /// The count comes from `strum::EnumCount`, which the compiler regenerates
    /// on every enum edit — a variant added but forgotten in `ALL` (and not
    /// listed as an explicit exclusion) makes `ALL.len() + UNWIRED == COUNT`
    /// false and fails here, before any downstream `ALL`-driven test can pass on
    /// an incomplete registry. It also asserts `ALL` has no duplicate entries and
    /// no exclusion is wrongly also present in `ALL`.
    /// `App.fromEnv` / `App.fromEnvRequired` READ a caller-named process
    /// environment variable at startup (`read_env_var` → `std::env::var`), the
    /// same enforceable env axis `System.getenv` / `Env.public` disclose. They
    /// MUST classify as [`Capability::Env`], not `None`: under-reporting an env
    /// read is the dangerous direction (it hides the dependency from the audit
    /// surface and breaks silently under a scrubbed OS jail). Pins the refusal so
    /// a regression to `None` fails here.
    #[test]
    fn app_from_env_kernels_disclose_env_capability() {
        use super::Capability;
        assert_eq!(
            StdlibKernel::AppFromEnv.capability_classification(),
            Some(Capability::Env),
            "App.fromEnv reads the process environment and must disclose Env"
        );
        assert_eq!(
            StdlibKernel::AppFromEnvRequired.capability_classification(),
            Some(Capability::Env),
            "App.fromEnvRequired reads the process environment and must disclose Env"
        );
    }

    #[test]
    fn all_covers_every_variant_except_documented_exclusions() {
        for (i, &a) in StdlibKernel::ALL.iter().enumerate() {
            let rest = StdlibKernel::ALL.get(i + 1..).unwrap_or(&[]);
            assert!(
                !rest.contains(&a),
                "{a:?} appears more than once in StdlibKernel::ALL"
            );
        }
        for &excluded in UNWIRED_VARIANTS {
            assert!(
                !StdlibKernel::ALL.contains(&excluded),
                "{excluded:?} is listed as UNWIRED but is also present in ALL"
            );
        }
        assert_eq!(
            StdlibKernel::ALL.len() + UNWIRED_VARIANTS.len(),
            StdlibKernel::COUNT,
            "ALL ({}) + UNWIRED ({}) != StdlibKernel::COUNT ({}) — a variant was \
             added to the enum but forgotten in ALL and not listed as an explicit \
             exclusion; every kernel must be either wired in ALL or documented in \
             UNWIRED_VARIANTS",
            StdlibKernel::ALL.len(),
            UNWIRED_VARIANTS.len(),
            StdlibKernel::COUNT,
        );
    }

    /// Every excluded variant carries no runtime-module requirement, closing the
    /// blind spot where a real wired kernel relocated from `ALL` to
    /// `UNWIRED_VARIANTS` keeps the count equal and passes the count guard while
    /// silently escaping the scheme/coherence suites.
    #[test]
    fn unwired_variants_carry_no_runtime_module() {
        for &k in UNWIRED_VARIANTS {
            assert!(
                k.required_runtime_module().is_none(),
                "{k:?} is listed as unwired but declares a runtime module — \
                 it looks like a wired kernel; either add it to ALL or document \
                 the exception explicitly in UNWIRED_VARIANTS",
            );
        }
    }

    /// Every wired kernel has a capability decision on its row (the exhaustive
    /// classifying match is total over the whole registry — no panic, no gap).
    /// The compile error on a missing arm is the real drift guarantee; this
    /// asserts the fact is live over `ALL`.
    #[test]
    fn every_wired_kernel_has_a_capability_decision() {
        for k in StdlibKernel::ALL {
            let _ = k.def().capability;
        }
    }

    /// Coherence tripwire: EVERY wired `List`/`Dict`/`Set` kernel carries an
    /// element-capability tag, and no non-collection kernel does. A collection
    /// kernel added without a tag (or a non-collection kernel that accidentally
    /// returns one) is a CI error, mirroring the scheme/arity coherence oracles —
    /// so the storable-element soundness fact can never silently drift as the
    /// stdlib grows.
    #[test]
    fn every_collection_kernel_carries_an_element_capability_tag() {
        for k in StdlibKernel::ALL {
            let is_collection = matches!(k.def().qualifier, "List" | "Dict" | "Set");
            let tag = k.element_capability();
            assert_eq!(
                tag.is_some(),
                is_collection,
                "{k:?} (qualifier {:?}): a List/Dict/Set kernel MUST carry an \
                 element-capability tag and no other kernel may — got tag {tag:?}",
                k.def().qualifier,
            );
        }
    }

    /// The element-equality / element-ordering `List` kernels forbid a function
    /// element; the FRONTIER-CLOSED map/fold/filter family admits it. Pins the
    /// soundness classification so a future retag that would silently let
    /// `Arc<dyn Fn>` reach a `==`/`sort` element bound (a cargo-fail) fails this
    /// test instead.
    #[test]
    fn equality_and_ordering_kernels_forbid_a_function_element() {
        use super::ElementCapability;
        assert_eq!(
            StdlibKernel::ListMember.element_capability(),
            Some(ElementCapability::RequiresPartialEq)
        );
        assert_eq!(
            StdlibKernel::ListUnique.element_capability(),
            Some(ElementCapability::RequiresPartialEq)
        );
        assert_eq!(
            StdlibKernel::ListSort.element_capability(),
            Some(ElementCapability::RequiresOrd)
        );
        assert_eq!(
            StdlibKernel::ListMaximum.element_capability(),
            Some(ElementCapability::RequiresOrd)
        );
        // The frontier-closed map/fold/filter family is sound over a function
        // element (`retype_collection_element_param` aligns the mapper carrier).
        assert_eq!(
            StdlibKernel::ListMap.element_capability(),
            Some(ElementCapability::CloneOk)
        );
        assert_eq!(
            StdlibKernel::ListFoldl.element_capability(),
            Some(ElementCapability::CloneOk)
        );
        assert!(
            ElementCapability::RequiresPartialEq.forbids_function_element()
                && ElementCapability::RequiresOrd.forbids_function_element()
                && !ElementCapability::CloneOk.forbids_function_element()
        );
    }

    /// The mapper frontier is derived from each scheme: over every wired kernel,
    /// exactly the kernels feeding a stored element into a parameter the
    /// lowerer cannot re-carrier stay `MapperFrontierOpen` (fail-closed
    /// IPE-L0134) — only `Dict.update`'s `Maybe v` — and every graduated
    /// mapper kernel is `CloneOk`, the `Set` higher-order family included: its
    /// `Ord`-bound element admits no function, so it feeds none to a mapper.
    #[test]
    fn open_frontier_mapper_kernels_forbid_a_function_element() {
        use super::ElementCapability;
        use StdlibKernel as K;
        let mut got_open: Vec<K> = K::ALL
            .iter()
            .copied()
            .filter(|k| k.element_capability() == Some(ElementCapability::MapperFrontierOpen))
            .collect();
        let mut expected_open = [K::DictUpdate];
        expected_open.sort_by_key(|k| format!("{k:?}"));
        got_open.sort_by_key(|k| format!("{k:?}"));
        assert_eq!(
            got_open,
            expected_open.to_vec(),
            "open-frontier set drifted"
        );
        for k in [
            K::ListPartition,
            K::ListMap2,
            K::ListMap3,
            K::ListMap4,
            K::ListMap5,
            K::ListSortBy,
            K::ListSortWith,
            K::DictMap,
            K::DictFoldl,
            K::DictFoldr,
            K::DictFilter,
            K::DictPartition,
            K::SetMap,
            K::SetFilter,
            K::SetFoldl,
            K::SetFoldr,
            K::SetPartition,
        ] {
            assert_eq!(
                k.element_capability(),
                Some(ElementCapability::CloneOk),
                "{k:?} feeds only re-carriered mapper parameters and must be CloneOk"
            );
        }
        assert!(ElementCapability::MapperFrontierOpen.forbids_function_element());
        assert!(super::mapper_capabilities_match_their_schemes(K::ALL));
    }

    /// The storage slots are exactly the positions the lowerer flips to the
    /// `Arc` carrier: a `List`/`Set` element and a `Dict` value, never a `Dict`
    /// key or a `Maybe`/`Result` payload; a `Set` element admits no function.
    #[test]
    fn storage_slots_match_the_lowerer_flips() {
        use super::{BuiltinTag as T, slot_admits_function, storage_slot};
        assert!(storage_slot(T::List, 0) && storage_slot(T::Set, 0) && storage_slot(T::Dict, 1));
        assert!(
            !storage_slot(T::Dict, 0) && !storage_slot(T::Maybe, 0) && !storage_slot(T::List, 1)
        );
        assert!(!storage_slot(T::Result, 0) && !storage_slot(T::Result, 1));
        assert!(slot_admits_function(T::List, 0) && slot_admits_function(T::Dict, 1));
        assert!(!slot_admits_function(T::Set, 0) && !slot_admits_function(T::Dict, 0));
    }

    /// One representative kernel per effect family maps to the right capability,
    /// and a pure kernel maps to `None`.
    #[test]
    fn effect_kernels_map_to_their_capability() {
        use super::{Capability, WebCapability};
        let js_raw = Some(Capability::JsPort(WebCapability::Raw));
        // A representative kernel per family paired with the capability its `def()`
        // row must project. Notes on the non-obvious rows:
        //   - `Env.public` reads the live process environment on native, so it
        //     discloses the env axis like `System.getenv` (wasm32 over-reports).
        //   - `CustomElement.node` ships browser JS → the `custom-element` axis.
        //   - the `Js.*` / session-stream ops exchange typed data with page JS →
        //     the `js-port:raw` uncharacterised-floor axis (the kernel cannot see
        //     the hand-written JS's target Web API).
        //   - Auth kernels over a live `Db` handle disclose `database`;
        //     `Auth.signToken` mints a random `jti`, `Auth.verifyToken` reads the
        //     clock for `exp`/`nbf`.
        let cases: &[(StdlibKernel, Option<Capability>)] = &[
            (StdlibKernel::HttpGet, Some(Capability::Network)),
            (StdlibKernel::ServerListen, Some(Capability::Network)),
            (StdlibKernel::EmailSend, Some(Capability::Network)),
            (StdlibKernel::FileReadFile, Some(Capability::Filesystem)),
            (StdlibKernel::PathAbsolute, Some(Capability::Filesystem)),
            (StdlibKernel::PathUnder, None),
            (StdlibKernel::DbQuery, Some(Capability::Database)),
            (StdlibKernel::DbDecString, Some(Capability::Database)),
            (StdlibKernel::SystemGetenv, Some(Capability::Env)),
            (StdlibKernel::TimeNow, Some(Capability::Clock)),
            (StdlibKernel::RandomInt, Some(Capability::Random)),
            (StdlibKernel::UuidV4, Some(Capability::Random)),
            (StdlibKernel::StringToUpper, None),
            (StdlibKernel::LogInfo, None),
            (StdlibKernel::IoPrintln, None),
            (StdlibKernel::DebugLog, None),
            (StdlibKernel::EnvPublic, Some(Capability::Env)),
            (StdlibKernel::UiWidget, Some(Capability::CustomElement)),
            (StdlibKernel::JsSend, js_raw),
            (StdlibKernel::JsSubscribe, js_raw),
            (StdlibKernel::JsRequest, js_raw),
            (StdlibKernel::JsOpenSession, js_raw),
            (StdlibKernel::JsSessionFrames, js_raw),
            (StdlibKernel::JsSendToSession, js_raw),
            (StdlibKernel::JsCloseSession, js_raw),
            (StdlibKernel::AuthRegister, Some(Capability::Database)),
            (StdlibKernel::AuthLogin, Some(Capability::Database)),
            (StdlibKernel::AuthSetRole, Some(Capability::Database)),
            (StdlibKernel::AuthSignToken, Some(Capability::Random)),
            (StdlibKernel::AuthVerifyToken, Some(Capability::Clock)),
        ];

        for (kernel, expected) in cases {
            assert_eq!(kernel.def().capability, *expected, "{kernel:?}");
        }
    }

    /// Every `Ipe.Http` kernel (qualifier `"Http"`) emits a symbol that lives in
    /// the `http_client` runtime module, so it MUST be reported by
    /// `is_http_client()` — that predicate is what gates declaring `http_client`
    /// and linking `reqwest` in the emitted crate. A new `Http.*` kernel that
    /// forgets the predicate would emit `ipe_runtime::http_client::…` into a
    /// crate that declares neither the module nor the dependency (E0433 at
    /// `cargo build`); this test fails the instant that happens. The
    /// `Ipe.Http.Stream` relay kernels use the distinct `"HttpStream"` qualifier
    /// and are intentionally NOT covered (they ride the server surface).
    #[test]
    fn every_http_kernel_is_reported_as_http_client() {
        for k in StdlibKernel::ALL {
            if k.decl().qualifier == "Http" {
                assert!(
                    k.is_http_client(),
                    "{k:?} is an `Ipe.Http` kernel (emits `{}` in http_client) but \
                     is_http_client() is false — the emitted crate would fail to link reqwest",
                    k.decl().emit
                );
            }
        }
    }

    /// Every `Ipe.Url` kernel emits a symbol into the `url` runtime module (a
    /// consumer of the `url` crate and its large `idna` → ICU4X subtree), so
    /// `qualifier == "Url"` MUST imply `is_url()`, and no other qualifier may
    /// report `is_url()`. The lookalike `String.isUrl` (qualifier `"String"`,
    /// structural parse, no `url` crate) and `Encoding.urlEncode` / `urlDecode` /
    /// `percentDecode` (qualifier `"Encoding"`) are deliberately excluded.
    /// Both directions are asserted, so a new `Url.*` kernel the predicate
    /// forgets — or an unrelated kernel wrongly claimed — fails the instant the
    /// two disagree.
    #[test]
    fn url_predicate_tracks_url_qualifier() {
        for k in StdlibKernel::ALL {
            let is_url_qualifier = k.decl().qualifier == "Url";
            assert_eq!(
                k.is_url(),
                is_url_qualifier,
                "{k:?}: is_url()={} but qualifier==\"Url\" is {} — the emitted crate \
                 would either fail to declare the url module (E0433) or pull the url \
                 crate into a program that never parses a URL",
                k.is_url(),
                is_url_qualifier,
            );
        }
    }

    /// The async-runtime classification is FAIL-CLOSED: a kernel counts as
    /// reactor-requiring unless its whole qualifier is on the proven-pure
    /// whitelist (or it is a pure member of a mixed family). This test pins the
    /// classification against a hand-audited ground truth for every wired
    /// kernel, so a new kernel — or a rename that moves one across the boundary
    /// — cannot silently flip a program onto the wrong executor. The invariant
    /// the whole increment rests on: a kernel that `requires_async_runtime()`
    /// reports `false` for MUST resolve its future without the tokio reactor
    /// (else a synchronous `fn main` would park forever on an op that never
    /// fires).
    #[test]
    fn async_runtime_classification_is_fail_closed() {
        // Ground truth is an INDEPENDENT hand-audited enumeration of the
        // reactor-FREE kernels — not a copy of the production qualifier formula.
        // A kernel is reactor-free iff its runtime denotation drives its future
        // to `Ready` without a tokio timer, socket, spawn, or `spawn_blocking`
        // offload. Every kernel NOT listed here must classify reactor-requiring;
        // in particular the mixed-family reactor members (`Time.sleep`,
        // `Time.every`, `System.loadEnv`, the reactor `Task` combinators) are
        // absent, so this table catches the exact drift — a new reactor member
        // under a mixed qualifier wrongly admitted as pure — that the invariant
        // guards. The listed pure members of `Time` / `System` were each audited
        // against their runtime source.
        let reactor_free = |k: StdlibKernel| -> bool {
            let pure_time_system = matches!(
                k,
                StdlibKernel::TimeNow
                    | StdlibKernel::TimeUnixMillis
                    | StdlibKernel::TimeTimeString
                    | StdlibKernel::TimeIsLeapYear
                    | StdlibKernel::TimeDaysInMonth
                    | StdlibKernel::TimeFormat
                    | StdlibKernel::TimeFormatHTTP
                    | StdlibKernel::TimeFormatISO8601
                    | StdlibKernel::TimeFormatRFC3339
                    | StdlibKernel::TimeAddMillis
                    | StdlibKernel::TimeDiffMillis
                    | StdlibKernel::SystemArgs
                    | StdlibKernel::SystemGetenv
                    | StdlibKernel::SystemGetenvOr
                    | StdlibKernel::SystemGetArg
                    | StdlibKernel::SystemGetenvInt
                    | StdlibKernel::SystemGetenvBool
                    | StdlibKernel::SystemSetenv
                    | StdlibKernel::SystemUnsetenv
                    | StdlibKernel::SystemCwd
                    | StdlibKernel::SystemExit
            );
            // The families that are pure in whole: every member resolves without
            // the reactor. Distinct from the qualifier list in production only
            // in that this test re-derives it from the audited-purity judgement
            // rather than reading the production constant.
            let pure_whole_family = matches!(
                k.decl().qualifier,
                "Log"
                    | "String"
                    | "Char"
                    | "List"
                    | "Basics"
                    | "Maybe"
                    | "Result"
                    | "Math"
                    | "Bitwise"
                    | "Dict"
                    | "Set"
                    | "Bytes"
                    | "Encoding"
                    | "JsonEnc"
                    | "JsonDec"
                    | "JsonDecP"
                    | "Uuid"
                    | "Decimal"
                    | "Money"
                    | "Secret"
                    | "Regex"
                    | "Path"
                    | "Locale"
                    | "Error"
                    | "CssSafety"
                    | "Random"
                    | "Io"
                    | "Sql"
            );
            pure_time_system || pure_whole_family
        };
        for k in StdlibKernel::ALL {
            let q = k.decl().qualifier;
            let expected_async = !reactor_free(*k);
            assert_eq!(
                k.requires_async_runtime(),
                expected_async,
                "{k:?} (qualifier {q:?}): requires_async_runtime()={} but the audited \
                 ground truth is {expected_async}. A pure kernel wrongly marked async only \
                 keeps tokio (safe); a reactor kernel wrongly marked pure would emit a \
                 synchronous `fn main` that HANGS on a reactor op — re-audit the runtime impl \
                 before changing the whitelist.",
                k.requires_async_runtime(),
            );
        }
    }

    /// The mixed-family drift the fail-closed invariant exists to catch: the
    /// reactor-driven members of `Time` / `System` must classify
    /// reactor-requiring, and admitting their family by qualifier would silently
    /// demote them. This pins each reactor member directly (independent of the
    /// whitelist formula) and asserts a representative pure member of the same
    /// family stays admitted, so a regression that re-adds `Time` / `System` to
    /// the whole-family qualifier list fails here.
    #[test]
    fn mixed_family_reactor_members_are_not_admitted_by_qualifier() {
        for reactor in [
            StdlibKernel::TimeSleep,
            StdlibKernel::TimeEvery,
            StdlibKernel::SystemLoadEnv,
        ] {
            assert!(
                reactor.requires_async_runtime(),
                "{reactor:?} drives the tokio reactor but was classified pure — a mixed \
                 family admitted by qualifier would emit a synchronous `fn main` that HANGS"
            );
        }
        for pure in [StdlibKernel::TimeNow, StdlibKernel::SystemGetenv] {
            assert!(
                !pure.requires_async_runtime(),
                "{pure:?} is a proven-pure member of a mixed family and must stay admitted"
            );
        }
    }

    /// The fail-closed default itself: a synthetic qualifier that is not on the
    /// whitelist must classify as reactor-requiring. Guards against a future
    /// refactor that inverts the default arm.
    #[test]
    fn unknown_qualifier_defaults_to_async() {
        for k in StdlibKernel::ALL {
            let q = k.decl().qualifier;
            // Every Db/Http/Server/Web kernel is a known reactor surface; assert
            // the default arm keeps them async (they are never on the pure list).
            if matches!(q, "Db" | "Http" | "Server" | "Web" | "File" | "Cmd" | "Sub") {
                assert!(
                    k.requires_async_runtime(),
                    "{k:?} (qualifier {q:?}) is a reactor surface but was classified pure — \
                     the fail-closed default arm has regressed"
                );
            }
        }
    }

    /// Every `Ipe.Config` kernel whose emitted symbol lives in the
    /// `config_decode` runtime module MUST be reported by `is_config()` — that
    /// predicate gates declaring `config_decode` and linking `toml` +
    /// `serde_yaml`. The residency test is content-addressed: a `config_decode`
    /// symbol is exactly one whose emit name starts with `config_`
    /// (`config_nullable` / `config_maybe` / `config_dict` / `config_decode_*` /
    /// `config_load_from_file`). The remaining `Config.*` combinators emit the
    /// shared `json_decode_*` / `decode_*` symbols in the `json`
    /// module and must NOT be `is_config()` — gating on them would pull `toml` /
    /// `serde_yaml` into a program that only decodes JSON. Both directions are
    /// asserted, so a new `Config.*` kernel added on either side of the split
    /// fails this test the instant its emit symbol and predicate disagree.
    #[test]
    fn config_predicate_tracks_config_decode_residency() {
        for k in StdlibKernel::ALL {
            let decl = k.decl();
            if decl.qualifier != "Config" {
                continue;
            }
            let lives_in_config_decode = decl.emit.starts_with("config_");
            assert_eq!(
                k.is_config(),
                lives_in_config_decode,
                "{k:?} emits `{}`: is_config()={} but config_decode residency={} — \
                 the emitted crate would either fail to declare config_decode (E0433) \
                 or pull toml/serde_yaml into a JSON-only program",
                decl.emit,
                k.is_config(),
                lives_in_config_decode,
            );
        }
    }

    /// Every `Ipe.Compression` kernel emits a symbol into the `compression`
    /// runtime module (the sole consumer of `flate2` + `zstd`), so `qualifier ==
    /// "Compression"` MUST imply `is_compression()`, and no other qualifier may
    /// report `is_compression()`. Both directions are asserted, so a new
    /// `Compression.*` kernel that the predicate forgets — or an unrelated kernel
    /// wrongly claimed — fails this test the instant the two disagree.
    #[test]
    fn compression_predicate_tracks_compression_qualifier() {
        for k in StdlibKernel::ALL {
            let is_compression_qualifier = k.decl().qualifier == "Compression";
            assert_eq!(
                k.is_compression(),
                is_compression_qualifier,
                "{k:?}: is_compression()={} but qualifier==\"Compression\" is {} — \
                 the emitted crate would either fail to declare the compression module \
                 (E0433) or pull flate2/zstd into a program that never compresses",
                k.is_compression(),
                is_compression_qualifier,
            );
        }
    }

    /// Every `Ipe.Csv` kernel emits a symbol into the `csv` runtime module (the
    /// sole consumer of the `csv` crate), so `qualifier == "Csv"` MUST imply
    /// `is_csv()`, and no other qualifier may report `is_csv()`. Both directions
    /// are asserted, so a new `Csv.*` kernel that the predicate forgets — or an
    /// unrelated kernel wrongly claimed — fails this test the instant the two
    /// disagree.
    #[test]
    fn csv_predicate_tracks_csv_qualifier() {
        for k in StdlibKernel::ALL {
            let is_csv_qualifier = k.decl().qualifier == "Csv";
            assert_eq!(
                k.is_csv(),
                is_csv_qualifier,
                "{k:?}: is_csv()={} but qualifier==\"Csv\" is {} — \
                 the emitted crate would either fail to declare the csv module \
                 (E0433) or pull the csv crate into a program that never parses CSV",
                k.is_csv(),
                is_csv_qualifier,
            );
        }
    }

    /// Every non-TEA `Ipe.Time` kernel keys the `uses_time` gate that enables
    /// the `time` Cargo feature (and the `chrono-tz` dependency). So `qualifier
    /// == "Time" && !is_tea()` MUST imply `is_time()`, and no other kernel may
    /// report `is_time()`. `Time.every` is TEA, excluded on both sides. Both
    /// directions are asserted, so a new `Time.*` kernel the predicate forgets —
    /// or an unrelated kernel wrongly claimed — fails the instant the two
    /// disagree.
    #[test]
    fn time_predicate_tracks_non_tea_time_qualifier() {
        for k in StdlibKernel::ALL {
            let is_time_qualifier = k.decl().qualifier == "Time" && !k.is_tea();
            assert_eq!(
                k.is_time(),
                is_time_qualifier,
                "{k:?}: is_time()={} but (qualifier==\"Time\" && !is_tea()) is {} — \
                 a Time-using program would either drop chrono-tz it needs or a \
                 non-Time program would pull it",
                k.is_time(),
                is_time_qualifier,
            );
        }
    }

    /// Every `Ipe.Log` kernel reaches the `log.rs` runtime module — the sole
    /// always-emittable consumer of `chrono` (its RFC3339-nano timestamp), gated
    /// behind the `log` feature. So `is_log()` MUST report exactly
    /// `qualifier == "Log"`, and no other qualifier may — in particular NOT
    /// `Debug.log` (qualifier "Debug"), whose `debug.rs` body is a pure
    /// `IpeStringify` passthrough with no `chrono`. Both directions asserted, so a
    /// new `Log.*` kernel the predicate forgets — or an unrelated kernel wrongly
    /// claimed — drops `chrono`/`log.rs` a program needs (E0433) or pulls it into
    /// a program that does not.
    #[test]
    fn log_predicate_tracks_log_qualifier() {
        for k in StdlibKernel::ALL {
            // `Log.level` shares the `Log` qualifier but emits its symbol into
            // `app_config` (a runtime-config setting builder), NOT `log.rs`, so
            // it does not pull `chrono`/`log.rs` — the sole carve-out, mirroring
            // the `web_predicate` PubSub carve-out.
            let is_log_module_kernel =
                k.decl().qualifier == "Log" && !matches!(k, StdlibKernel::LogLevelSetting);
            assert_eq!(
                k.is_log(),
                is_log_module_kernel,
                "{k:?}: is_log()={} but log-module residency is {} — \
                 a Log-using program would drop the `log`/`chrono` surface it needs \
                 or a non-Log program (e.g. one calling Debug.log) would pull it",
                k.is_log(),
                is_log_module_kernel,
            );
        }
    }

    /// Every `Ipe.Decimal` and `Ipe.Money` kernel reaches the `decimal.rs` /
    /// `money.rs` runtime modules — the sole consumers of the `rust_decimal` crate,
    /// gated behind the `decimal` feature. So `is_decimal()` MUST report exactly
    /// `qualifier ∈ {"Decimal", "Money"}`, and no other qualifier may. Both
    /// directions asserted, so a new `Decimal.*`/`Money.*` kernel the predicate
    /// forgets drops `rust_decimal` a program needs (E0433), or an unrelated kernel
    /// wrongly claimed pulls it into a program that does not.
    #[test]
    fn decimal_predicate_tracks_decimal_money_qualifiers() {
        for k in StdlibKernel::ALL {
            let is_decimal_qualifier =
                k.decl().qualifier == "Decimal" || k.decl().qualifier == "Money";
            assert_eq!(
                k.is_decimal(),
                is_decimal_qualifier,
                "{k:?}: is_decimal()={} but qualifier∈{{Decimal,Money}} is {} — \
                 a Decimal/Money-using program would drop the `rust_decimal` surface \
                 it needs or a non-Decimal program would pull it",
                k.is_decimal(),
                is_decimal_qualifier,
            );
        }
    }

    /// Exactly the five `Ipe.Char` `General_Category` predicates
    /// (`isAlpha`/`isDigit`/`isLower`/`isUpper`/`isAlphaNum`) reach the
    /// `char_category.rs` runtime module — the sole consumer of the
    /// `unicode-general-category` table, gated behind the `char-category` feature.
    /// So `is_char_category()` MUST report exactly those five and NO other kernel —
    /// in particular NOT the std-only `Char` kernels (`isHexDigit`/`isOctDigit`/
    /// `toLower`/`toUpper`/`toCode`/`fromCode`), whose `char_kernel.rs` bodies use
    /// Rust std alone. Both directions asserted, so a category predicate the
    /// method forgets drops `unicode-general-category` a program needs (E0433), or
    /// a std-only `Char` kernel wrongly claimed pulls the crate into a program that
    /// (correctly) reaches only `char_kernel.rs`.
    #[test]
    fn char_category_predicate_tracks_category_kernels() {
        for k in StdlibKernel::ALL {
            let is_category = matches!(
                k,
                StdlibKernel::CharIsAlpha
                    | StdlibKernel::CharIsDigit
                    | StdlibKernel::CharIsLower
                    | StdlibKernel::CharIsUpper
                    | StdlibKernel::CharIsAlphaNum
            );
            assert_eq!(
                k.is_char_category(),
                is_category,
                "{k:?}: is_char_category()={} but the category-kernel set membership \
                 is {} — a General_Category-using program would drop the \
                 `unicode-general-category` surface it needs or a std-only Char \
                 program would pull it",
                k.is_char_category(),
                is_category,
            );
        }
    }

    /// Every `Ipe.Regex` kernel — plus `String.isUrl`, whose validator body lives
    /// in `regex_kernel.rs` — reaches the gated `regex_kernel` runtime module (the
    /// sole consumer of the `regex` crate). So `is_regex()` MUST report exactly
    /// `qualifier == "Regex" || StringIsUrl`, and nothing else. Both directions
    /// are asserted: a new `Regex.*` kernel the predicate forgets — or an
    /// unrelated kernel wrongly claimed — drops `regex` a program needs or pulls
    /// it into a program that does not.
    #[test]
    fn regex_predicate_tracks_regex_module_residency() {
        for k in StdlibKernel::ALL {
            let lives_in_regex_module =
                k.decl().qualifier == "Regex" || matches!(k, StdlibKernel::StringIsUrl);
            assert_eq!(
                k.is_regex(),
                lives_in_regex_module,
                "{k:?}: is_regex()={} but (qualifier==\"Regex\" || StringIsUrl) is {} — \
                 the emitted crate would either drop the `regex` crate it needs \
                 (E0433) or pull it into a program that reaches neither Regex nor \
                 String.isUrl",
                k.is_regex(),
                lives_in_regex_module,
            );
        }
    }

    /// Every `Ipe.Uuid` kernel reaches the gated `uuid_kernel` runtime module (the
    /// sole consumer of the `uuid` crate as a runtime module). So `is_uuid()` MUST
    /// report exactly `qualifier == "Uuid"`, and no other qualifier may. Both
    /// directions asserted.
    #[test]
    fn uuid_predicate_tracks_uuid_qualifier() {
        for k in StdlibKernel::ALL {
            let is_uuid_qualifier = k.decl().qualifier == "Uuid";
            assert_eq!(
                k.is_uuid(),
                is_uuid_qualifier,
                "{k:?}: is_uuid()={} but qualifier==\"Uuid\" is {} — \
                 a Uuid-using program would drop the `uuid` crate it needs or a \
                 non-Uuid program would pull it",
                k.is_uuid(),
                is_uuid_qualifier,
            );
        }
    }

    /// Every `Ipe.Random` kernel reaches the gated `random.rs` runtime module. So
    /// `is_random()` MUST report exactly `qualifier == "Random"`, and no other
    /// qualifier may. Both directions asserted, so a new `Random.*` kernel the
    /// predicate forgets — or an unrelated kernel wrongly claimed — fails the
    /// instant the two disagree (the module would be dropped for a program that
    /// needs it, E0433).
    #[test]
    fn random_predicate_tracks_random_qualifier() {
        for k in StdlibKernel::ALL {
            let is_random_qualifier = k.decl().qualifier == "Random";
            assert_eq!(
                k.is_random(),
                is_random_qualifier,
                "{k:?}: is_random()={} but qualifier==\"Random\" is {} — \
                 a Random-using program would drop the `random` module it needs or \
                 a non-Random program would pull it",
                k.is_random(),
                is_random_qualifier,
            );
        }
    }

    /// Every HEAVY `Ipe.Crypto` kernel emits a symbol into the gated `crypto`
    /// runtime module (the sole consumer of `sha1` / `md-5` / `aes-gcm` /
    /// `chacha20poly1305` / `pbkdf2`), so `is_crypto()` MUST report exactly those
    /// kernels — and NONE of the `crypto_core` floor kernels (SHA-2
    /// hash/HMAC, RSA sign/verify, constant-time compare, the entropy pair, the
    /// `Key`/`Mac` newtypes). The residency is content-addressed off the emit
    /// symbol: a `crypto` (heavy) symbol is exactly one that names a legacy
    /// checksum (`crypto_sha1` / `crypto_md5`), an AEAD op (`aes_gcm` /
    /// `chacha20` in the name), or a PBKDF2 key derivation
    /// (`_key_from_password`). Both directions are asserted, so a new `Crypto.*`
    /// kernel added on either side of the split fails the instant its emit symbol
    /// and predicate disagree — mis-gating a floor kernel (E0433 for a program
    /// using only `Crypto.sha256`) or pulling the heavy AEAD crates into a
    /// hash-only program.
    #[test]
    fn crypto_predicate_tracks_heavy_module_residency() {
        for k in StdlibKernel::ALL {
            let emit = k.decl().emit;
            let lives_in_heavy_crypto = emit == "crypto_sha1"
                || emit == "crypto_md5"
                || emit.contains("rsa_sha256")
                || emit.contains("aes_gcm")
                || emit.contains("chacha20")
                || emit.contains("_key_from_password");
            assert_eq!(
                k.is_crypto(),
                lives_in_heavy_crypto,
                "{k:?} emits `{emit}`: is_crypto()={} but heavy-crypto residency={} — \
                 the emitted crate would either fail to declare the crypto module (E0433) \
                 or pull sha1/md-5/aes-gcm/chacha20poly1305/pbkdf2 into a program that \
                 uses only the always-on crypto_core floor",
                k.is_crypto(),
                lives_in_heavy_crypto,
            );
        }
    }

    /// Every crypto-floor kernel emits a symbol into `crypto_core.rs` (the sole
    /// consumer of `sha2` / `hmac` / the `subtle` compare once `crypto-core`
    /// gates them), so `is_crypto_core()` MUST
    /// report exactly the kernels whose emit symbol resides there — and NONE of
    /// the heavy `crypto.rs` kernels. Residency is content-addressed off the emit
    /// symbol, the SAME discipline `crypto_predicate_tracks_heavy_module_residency`
    /// uses for the heavy side: a floor symbol is one under the
    /// `Crypto` / `Key` / `Mac` qualifiers that is NOT a heavy residency
    /// (`crypto_sha1` / `crypto_md5`, an AEAD op — `aes_gcm` / `chacha20` in the
    /// name — or a PBKDF2 derivation, `_key_from_password`). Both directions are
    /// asserted, so mis-gating a floor kernel (E0433 for a program using only
    /// `Crypto.sha256`) or wrongly claiming a heavy kernel fails the instant the
    /// emit symbol and the predicate disagree.
    #[test]
    fn crypto_core_predicate_tracks_floor_module_residency() {
        for k in StdlibKernel::ALL {
            let decl = k.decl();
            let emit = decl.emit;
            let qual = decl.qualifier;
            let heavy = emit == "crypto_sha1"
                || emit == "crypto_md5"
                || emit.contains("rsa_sha256")
                || emit.contains("aes_gcm")
                || emit.contains("chacha20")
                || emit.contains("_key_from_password");
            let lives_in_floor = (qual == "Crypto" || qual == "Key" || qual == "Mac") && !heavy;
            assert_eq!(
                k.is_crypto_core(),
                lives_in_floor,
                "{k:?} emits `{emit}` (qualifier `{qual}`): is_crypto_core()={} but \
                 crypto_core residency={} — the emitted crate would either fail to \
                 select the `crypto-core` feature (E0433 for a floor kernel) or pull \
                 sha2/hmac/subtle into a program that reaches no crypto floor",
                k.is_crypto_core(),
                lives_in_floor,
            );
        }
    }

    /// Every `Ipe.Secret` kernel emits a symbol into the `secret.rs` runtime
    /// module (the sole consumer of `zeroize`), so `is_secret()` MUST report
    /// exactly `qualifier == "Secret"`, and no other qualifier may. Both
    /// directions asserted, so a new `Secret.*` kernel the predicate forgets — or
    /// an unrelated kernel wrongly claimed — fails the instant the two disagree
    /// (the module would be dropped for a program that needs it, E0433).
    #[test]
    fn secret_predicate_tracks_secret_qualifier() {
        for k in StdlibKernel::ALL {
            let is_secret_qualifier = k.decl().qualifier == "Secret";
            assert_eq!(
                k.is_secret(),
                is_secret_qualifier,
                "{k:?}: is_secret()={} but qualifier==\"Secret\" is {} — \
                 a Secret-using program would drop the `secret` module it needs or \
                 a non-Secret program would pull `zeroize`",
                k.is_secret(),
                is_secret_qualifier,
            );
        }
    }

    /// Every `Ipe.Jwt` kernel emits a symbol into the `jwt` runtime module (the
    /// sole direct consumer of `jsonwebtoken`), so `qualifier == "Jwt"` MUST
    /// imply `is_jwt()`, and no other qualifier may report `is_jwt()`. Both
    /// directions are asserted, so a new `Jwt.*` kernel the predicate forgets — or
    /// an unrelated kernel wrongly claimed — fails the instant the two disagree.
    #[test]
    fn jwt_predicate_tracks_jwt_qualifier() {
        for k in StdlibKernel::ALL {
            let is_jwt_qualifier = k.decl().qualifier == "Jwt";
            assert_eq!(
                k.is_jwt(),
                is_jwt_qualifier,
                "{k:?}: is_jwt()={} but qualifier==\"Jwt\" is {} — \
                 the emitted crate would either fail to declare the jwt module \
                 (E0433) or pull jsonwebtoken into a program that never uses JWT",
                k.is_jwt(),
                is_jwt_qualifier,
            );
        }
    }

    /// `is_json()` covers every kernel whose runtime denotation carries or
    /// decodes a JSON `Value` / `Decoder<E, T>` — spanning five qualifier
    /// families (`JsonEnc`, `JsonDec`, `JsonDecP`, `Config`, `Db.Decode`) and
    /// three cross-family outliers (`Db.queryDecode`, `Server.json`,
    /// `Jwt.withClaim`). Both directions are asserted: a new Json/Config/Db
    /// decoder the predicate forgets drops the `json`/`config` runtime surface
    /// the emitted crate needs (E0433), and a wrongly claimed kernel pulls it
    /// into a program that never touches JSON.
    #[test]
    fn json_predicate_tracks_json_family_kernels() {
        for k in StdlibKernel::ALL {
            let qual = k.decl().qualifier;
            // Five qualifier families whose every member belongs to the JSON
            // value / decoder surface, plus the three cross-family outliers
            // that carry a `Value` or `Decoder` argument.
            let is_json_family = matches!(
                qual,
                "JsonEnc" | "JsonDec" | "JsonDecP" | "Config" | "Db.Decode"
            ) || matches!(
                k,
                StdlibKernel::DbQueryDecode | StdlibKernel::ServerJson | StdlibKernel::JwtWithClaim
            );
            assert_eq!(
                k.is_json(),
                is_json_family,
                "{k:?} (qualifier {qual:?}): is_json()={} but json-family membership={} — \
                 a JSON-using program would drop the decoder surface it needs or a \
                 non-JSON program would pull it",
                k.is_json(),
                is_json_family,
            );
        }
    }

    /// The `WasmClient` allowlist is default-deny: every server-effect family
    /// is denied and the pure floor + render surface is allowed.
    #[test]
    fn wasm_client_allowlist_is_default_deny() {
        use super::Target;
        // Crown-jewel denials (secret consumers / server surfaces / effects
        // whose browser substitute has not landed).
        for denied in [
            StdlibKernel::AuthSignToken,
            StdlibKernel::AuthVerifyToken,
            StdlibKernel::DbQuery,
            StdlibKernel::DbConnect,
            StdlibKernel::FileReadFile,
            StdlibKernel::ProcessRun,
            StdlibKernel::ProcessRunWith,
            StdlibKernel::ProcessRunInPty,
            StdlibKernel::SystemGetenv,
            StdlibKernel::SystemExit,
            StdlibKernel::ServerListen,
            StdlibKernel::EmailSend,
            StdlibKernel::IoReadLine,
            StdlibKernel::TaskPerform,
            StdlibKernel::WebRenderStatic,
            // The view-less worker app-entry is co-located, never sandbox-capable
            // (guard 5): it is absent from the `KernelClass::Tea` wasm allowlist,
            // so a worker can never link into a Spa/wasm bundle even by mistake.
            StdlibKernel::TeaWorker,
            // The other co-located app-entries stay denied for the same reason —
            // only `Web.tea` gains a browser denotation.
            StdlibKernel::TerminalAppLines,
            StdlibKernel::TerminalAppScreen,
            // Terminal input subscriptions are driven only by the terminal
            // loops, which never run in a browser.
            StdlibKernel::TuiSubOnKey,
            StdlibKernel::CliSubOnLine,
            // Crypto: only the entropy pair (`randomBytes`/`randomToken`) has
            // a wasm substitute; hashing/AEAD/RSA stay denied (M4 scope cut,
            // NOT a qualifier-wide allow — see `wasm_client_available`).
            StdlibKernel::CryptoSha256,
            StdlibKernel::CryptoAesGcmEncrypt,
            StdlibKernel::CryptoAesKeyFromPassword,
            // `Path.absolute` reads the process working directory, which a
            // browser tab has no denotation for, despite the `Path` family allow.
            StdlibKernel::PathAbsolute,
        ] {
            assert!(
                !denied.available_on(Target::WasmClient),
                "{denied:?} must have no wasm-client denotation"
            );
        }
        // The floor + the headline render surface + the M4 Cmd/Sub browser
        // effects bridge (Log/Random/Http/WebSocket substitutes, timers,
        // in-tab pub/sub) + client-side router.
        for allowed in [
            StdlibKernel::StringFromInt,
            StdlibKernel::ListMap,
            StdlibKernel::DictInsert,
            StdlibKernel::JsonDecDecodeString,
            StdlibKernel::DecAdd,
            StdlibKernel::UiLayout,
            StdlibKernel::UiButton,
            StdlibKernel::HtmlNode,
            StdlibKernel::CssSafetySafeValue,
            StdlibKernel::WebApp,
            StdlibKernel::WebRoute,
            StdlibKernel::CmdNone,
            StdlibKernel::CmdPerform,
            StdlibKernel::SubNone,
            StdlibKernel::LogInfo,
            StdlibKernel::LogErrorWith,
            StdlibKernel::RandomInt,
            StdlibKernel::RandomFloat,
            StdlibKernel::RandomChoice,
            StdlibKernel::CryptoRandomBytes,
            StdlibKernel::CryptoRandomToken,
            StdlibKernel::HttpGet,
            StdlibKernel::HttpPost,
            StdlibKernel::HttpRequest,
            StdlibKernel::HttpParseQuery,
            // `Http.get`/`post` take a typed `Url`; the `url` crate parser has a
            // wasm build, so the constructor + accessors are client-available.
            StdlibKernel::UrlFromString,
            StdlibKernel::UrlToString,
            StdlibKernel::UrlScheme,
            // `Url.checkScheme` names a refused scheme through this, client-side too.
            StdlibKernel::UrlSchemeShown,
            // `Attributes.linkTarget` / `href` parse a relative reference client-side
            // (the same `url` crate wasm build) to render a Web-shape `href`.
            StdlibKernel::UrlRelativeParse,
            StdlibKernel::UrlRelativePath,
            StdlibKernel::UrlRelativeQuery,
            StdlibKernel::UrlRelativeFragment,
            StdlibKernel::UrlRelativeToString,
            StdlibKernel::TimeNow,
            StdlibKernel::TimeSleep,
            StdlibKernel::TimeUnixMillis,
            StdlibKernel::SubEvery,
            StdlibKernel::TimeEvery,
            StdlibKernel::CmdPublish,
            StdlibKernel::CmdPublishNoEcho,
            StdlibKernel::SubSubscribeTopic,
            StdlibKernel::PubSubPublish,
            StdlibKernel::PubSubPublishNoEcho,
            StdlibKernel::PubSubTopic,
            StdlibKernel::WebSocketConnect,
            StdlibKernel::WebSocketSend,
            StdlibKernel::WebSocketClose,
            // The WebSocket client's Sub-tier receive surface —
            // `ws_client.rs`'s wasm32 arm now wires `onOpen`/`onMessage`/
            // `onClose`/`onError` via `web_sys::WebSocket`'s `onopen`/
            // `onmessage`/`onclose`/`onerror` handler slots.
            StdlibKernel::SubSubscribeWebSocket,
            // `Env.public` — build-time-embedded `[wasm] publicEnv` allowlist.
            StdlibKernel::EnvPublic,
            // The lexical `Path` surface is pure; only `absolute` is denied.
            StdlibKernel::PathFromString,
            StdlibKernel::PathUnder,
        ] {
            assert!(
                allowed.available_on(Target::WasmClient),
                "{allowed:?} must be wasm-client-representable"
            );
        }
        // Everything is available natively.
        for &sk in StdlibKernel::ALL {
            assert!(sk.available_on(Target::Native));
        }
    }

    /// The `WasmWasi` (co-located `wasm32-wasip1`) allowlist is default-deny to
    /// the SEALED FLOOR: the always-on native effect floor
    /// (`Io`/`File`/`System`) + the WASI clock (`Time`) + the pure computational
    /// families + the pure `Task` combinator spine, and NOTHING that pulls a
    /// stack not building on wasip1. A kernel wrongly admitted here breaks THE
    /// SEAL (`ipe`-accept then `cargo build --target wasm32-wasip1` fail); a
    /// kernel wrongly denied turns away a buildable program.
    #[test]
    fn wasi_allowlist_is_default_deny() {
        use super::Target;
        // Admitted: the sealed floor a `Direct`/`Script` program reaches.
        for allowed in [
            // The always-on native effect floor over WASI.
            StdlibKernel::IoPrintln,
            StdlibKernel::IoWriteStdout,
            StdlibKernel::IoReadLine,
            StdlibKernel::FileReadFile,
            StdlibKernel::FileWriteFile,
            StdlibKernel::SystemArgs,
            StdlibKernel::SystemGetenv,
            StdlibKernel::SystemExit,
            // The WASI clock — the WHOLE Time family (unlike the browser subset).
            StdlibKernel::TimeNow,
            StdlibKernel::TimeSleep,
            StdlibKernel::TimeUnixMillis,
            // Pure computational families.
            StdlibKernel::StringFromInt,
            StdlibKernel::ListMap,
            StdlibKernel::DictInsert,
            StdlibKernel::JsonDecDecodeString,
            StdlibKernel::DecAdd,
            StdlibKernel::LogInfo,
            StdlibKernel::RandomInt,
            // The pure `Task` combinator spine (std-only reactor; no tokio).
            StdlibKernel::TaskSucceed,
            StdlibKernel::TaskMap,
            StdlibKernel::TaskAndThen,
            StdlibKernel::TaskSequence,
            StdlibKernel::TaskLoop,
            // Entropy pair (`random_get`) + `Env.public`.
            StdlibKernel::CryptoRandomBytes,
            StdlibKernel::CryptoRandomToken,
            StdlibKernel::EnvPublic,
        ] {
            assert!(
                allowed.available_on(Target::WasmWasi),
                "{allowed:?} must be WASI-representable (sealed floor)"
            );
        }
        // DENIED: every family whose wasip1 build does not exist — the SEAL rests
        // on these staying refused so they never reach the wasip1 cargo build.
        for denied in [
            // Http / WebSocket: reqwest / tokio-tungstenite → tokio/net → mio.
            StdlibKernel::HttpGet,
            StdlibKernel::HttpPost,
            StdlibKernel::WebSocketConnect,
            StdlibKernel::WebSocketSend,
            StdlibKernel::SubSubscribeWebSocket,
            // `Url` carries no WASI denotation of its own (only the HTTP client
            // pulled it in, and that is denied).
            StdlibKernel::UrlFromString,
            // Db / Server / Email: tokio/axum/sqlx spines.
            StdlibKernel::DbQuery,
            StdlibKernel::DbConnect,
            StdlibKernel::ServerListen,
            StdlibKernel::EmailSend,
            // TEA loop + render surface + Web app entries + terminal apps: a WASI
            // program is `Direct`, never a TEA loop.
            StdlibKernel::CmdPerform,
            StdlibKernel::SubEvery,
            StdlibKernel::UiButton,
            StdlibKernel::HtmlNode,
            StdlibKernel::WebApp,
            StdlibKernel::TeaWorker,
            StdlibKernel::TerminalAppLines,
            StdlibKernel::TerminalAppScreen,
            // Tokio-bound Task entries (block_on/spawn/time), and the auto-run
            // aliases — their runtime bodies do not build on the std-only spine.
            StdlibKernel::TaskRun,
            StdlibKernel::TaskParallel,
            StdlibKernel::TaskPerform,
            // Heavy crypto (only the entropy pair is on the floor).
            StdlibKernel::CryptoSha256,
            StdlibKernel::CryptoAesGcmEncrypt,
            // Auth (jsonwebtoken + secret consumers) + subprocess spawn (no WASI
            // spawn mapping — but these are `Ffi`/`Server`-shaped, denied).
            StdlibKernel::AuthSignToken,
        ] {
            assert!(
                !denied.available_on(Target::WasmWasi),
                "{denied:?} must have NO WASI denotation (breaks THE SEAL otherwise)"
            );
        }
    }

    /// `Task.loop`'s runtime driver is a pure `async` loop beside
    /// `task_sequence`, so it builds on both wasm targets; it keeps the
    /// fail-closed reactor-requiring default like every non-`Backoff*` `Task`
    /// member.
    #[test]
    fn task_loop_is_wasm_representable_and_keeps_the_reactor_default() {
        use super::Target;
        assert!(StdlibKernel::TaskLoop.available_on(Target::WasmWasi));
        assert!(StdlibKernel::TaskLoop.available_on(Target::WasmClient));
        assert!(StdlibKernel::TaskLoop.requires_async_runtime());
        // Its emit arm carries the `Step` bridge, so a point-free reference is
        // eta-expanded rather than boxed as a bare runtime function.
        assert!(StdlibKernel::TaskLoop.requires_saturated_emit());
        // Its step is a direct function slot a stored `Arc<dyn Fn>` read is
        // converted at.
        assert_eq!(
            StdlibKernel::TaskLoop.fn_slot_carrier(2),
            Some(super::FnSlotCarrier::Direct)
        );
    }

    /// Function slots and their carriers come from the kernel scheme, not a per-kernel list.
    #[test]
    fn fn_slot_carrier_is_derived_from_the_scheme() {
        use super::FnSlotCarrier::{AcceptsShared, Direct};
        assert_eq!(StdlibKernel::ListFilter.fn_slot_carrier(0), Some(Direct));
        assert_eq!(StdlibKernel::JsonEncList.fn_slot_carrier(0), Some(Direct));
        // The list argument is data, and an index past the arity is no slot.
        assert_eq!(StdlibKernel::ListFilter.fn_slot_carrier(1), None);
        assert_eq!(StdlibKernel::ListFilter.fn_slot_carrier(2), None);
        // A scheme-variable payload is not a function slot.
        assert_eq!(StdlibKernel::MaybeWithDefault.fn_slot_carrier(0), None);
        // The backend re-wraps these callbacks as `Arc` itself.
        assert_eq!(
            StdlibKernel::UiOnInput.fn_slot_carrier(0),
            Some(AcceptsShared)
        );
        assert_eq!(
            StdlibKernel::StreamStream.fn_slot_carrier(1),
            Some(AcceptsShared)
        );
        assert_eq!(StdlibKernel::StreamStream.fn_slot_carrier(0), None);
    }

    /// Verifies that no two non-internal variants in [`StdlibKernel::ALL`] share
    /// the same `(qualifier, name)` pair.
    ///
    /// A collision in `decl()` would let `stdlib_index`'s silent last-wins insert
    /// silently alias one variant onto another, making `id = Some(k)` ambiguous:
    /// the variant stored in the index would not necessarily be the one `decl()`
    /// names, and the `stdlib_index` fast path would fire with the wrong
    /// variant.
    ///
    /// MECHANICAL: built from `ALL` + `decl()` only — no read of `stdlib_index`
    /// or any runtime state.  Fails deterministically on any transposition in
    /// `decl()` that creates a duplicate `(qualifier, name)` pair, regardless of
    /// whether the compiler is ever invoked.
    #[test]
    fn no_colliding_qualifier_name_pairs() {
        let mut seen: HashMap<(&'static str, &'static str), StdlibKernel> = HashMap::new();
        let mut non_internal_count: usize = 0;

        for &sk in StdlibKernel::ALL {
            let decl = sk.decl();
            // Skip internal-only entries (qualifier starts with '_', e.g.
            // ResultOkDefault whose qualifier is "_internal_").  These are never
            // inserted into stdlib_index and need not be injective with respect
            // to the public namespace.
            if decl.qualifier.starts_with('_') {
                continue;
            }
            non_internal_count += 1;
            let prior = seen.insert((decl.qualifier, decl.name), sk);
            assert!(
                prior.is_none(),
                "COLLISION in StdlibKernel::decl(): \
                 StdlibKernel::{sk:?} and StdlibKernel::{prior:?} \
                 both declare (qualifier={:?}, name={:?}). \
                 decl() must be injective over non-internal ALL variants; \
                 stdlib_index's last-wins insert would silently drop one.",
                decl.qualifier,
                decl.name,
            );
        }

        // Sanity: the HashMap length must equal the non-internal variant count.
        assert_eq!(
            seen.len(),
            non_internal_count,
            "HashMap len ({}) != non-internal variant count ({}); loop accounting broken",
            seen.len(),
            non_internal_count,
        );
    }

    /// `PubSub.publish` / `publishNoEcho` have `class = Tea` and their emitted
    /// symbols (`pubsub_publish`, `pubsub_publish_no_echo`) live in
    /// `ipe_runtime::web::pubsub` — the `web` feature-module.  This test is
    /// the SSOT invariant: `required_runtime_module` MUST return
    /// `Some(RuntimeModule::Web)` for both so that any future code path relying
    /// solely on this function (rather than `is_web`) cannot silently omit the
    /// `live` append and produce an E0425 at `cargo build` time.
    #[test]
    fn pubsub_kernels_require_web_module() {
        use super::RuntimeModule;

        assert_eq!(
            StdlibKernel::PubSubPublish.required_runtime_module(),
            Some(RuntimeModule::Web),
            "PubSubPublish must map to RuntimeModule::Web — \
             pubsub_publish is defined in ipe_runtime::web::pubsub"
        );
        assert_eq!(
            StdlibKernel::PubSubPublishNoEcho.required_runtime_module(),
            Some(RuntimeModule::Web),
            "PubSubPublishNoEcho must map to RuntimeModule::Web — \
             pubsub_publish_no_echo is defined in ipe_runtime::web::pubsub"
        );
    }

    /// Fail-closed classification invariant (kernels-1): the `CloneOk` arm in
    /// `element_capability` is now an EXPLICIT exhaustive list, not a
    /// qualifier-wildcard default.  This test pins the soundness classification
    /// of every wired `List`/`Dict`/`Set` kernel so a newly added collection
    /// kernel that is NOT added to any explicit arm causes a compile error in
    /// `element_capability` rather than silently defaulting to `CloneOk`
    /// (which could let an unsound fn-element kernel emit `Arc<dyn Fn>`-
    /// incompatible Rust).
    ///
    /// The test asserts that:
    /// * Every `List`/`Dict`/`Set` kernel returns `Some(_)` (the existing
    ///   coherence test already asserts this for all kernels; this pins it
    ///   for the `CloneOk` family specifically).
    /// * No non-collection kernel returns `Some(_)`.
    /// * The kernels known to require ordering/equality/open-frontier do NOT
    ///   return `CloneOk` (they are in the other explicit arms; `CloneOk` is
    ///   for pure structural move/clone access only).
    #[test]
    fn collection_kernel_capability_is_never_implicitly_permissive() {
        use super::ElementCapability;

        // Kernels that must NOT be CloneOk — they require eq/ord or have an
        // open mapper frontier.  Any other capability is fine for them.
        let non_clone_ok = [
            StdlibKernel::ListMember,
            StdlibKernel::ListUnique,
            StdlibKernel::ListSort,
            StdlibKernel::ListMaximum,
            StdlibKernel::ListMinimum,
            StdlibKernel::DictUpdate,
        ];

        for k in StdlibKernel::ALL {
            let is_collection = matches!(k.def().qualifier, "List" | "Dict" | "Set");
            let cap = k.element_capability();

            // Every collection kernel must return Some. This test is the guarantee:
            // `element_capability`'s match ends in a swallowing `_ => {}`, so an
            // unlisted collection kernel returns `None` at compile time and only
            // this check catches the omission.
            assert_eq!(
                cap.is_some(),
                is_collection,
                "{k:?}: collection kernel must have Some capability, \
                 non-collection must have None"
            );

            // A kernel in the non-CloneOk set must NOT be CloneOk.
            if non_clone_ok.contains(k) {
                assert_ne!(
                    cap,
                    Some(ElementCapability::CloneOk),
                    "{k:?} is in the non-CloneOk set but returned CloneOk — \
                     it requires ordering/equality or has an open mapper frontier"
                );
            }
        }
    }

    /// `is_server()` MUST be true for exactly the kernels whose emitted symbols
    /// live in the `server` runtime module set. The oracle is:
    /// `class == Server` (which already implies server-module residency) OR
    /// `required_runtime_module() == Some(RuntimeModule::Server)` (the cross-class
    /// carve-outs — `HttpStreamOpen`/`ForEachChunk`/`Close` are `class = Pure`
    /// but their symbols live in `http_stream`, which the server append declares).
    /// `HttpStreamChunks` has `required_runtime_module() == Some(Server)` and is
    /// intentionally NOT `is_server` — it is covered via the `required_runtime_module`
    /// path in the lowerer directly. Both directions are asserted, so a new
    /// `class = Server` kernel the predicate forgets → emitted crate references
    /// `server::*` with no module (E0425/E0412).
    #[test]
    fn server_predicate_tracks_server_module_residency() {
        use super::{KernelClass, RuntimeModule};
        for k in StdlibKernel::ALL {
            let decl = k.decl();
            // Primary oracle: class=Server (all server-dispatch kernels) or
            // required_runtime_module=Some(Server) (cross-class kernels whose
            // symbols live in the server module set).
            let server_resident = decl.class == KernelClass::Server
                || k.required_runtime_module() == Some(RuntimeModule::Server);
            // Carve-outs that require an explicit `matches!` in the predicate:
            //
            // `HttpStreamOpen`/`ForEachChunk`/`Close` are `class=Pure` and
            // `required_runtime_module()=None` yet `is_server=true` — their
            // symbols live in `http_stream`, which the server append declares,
            // but they predate `required_runtime_module` and the divergence is
            // not yet reflected there. They are the legitimate cross-class
            // entries that keep the predicate a hand list.
            let extra_server = matches!(
                k,
                StdlibKernel::HttpStreamOpen
                    | StdlibKernel::HttpStreamForEachChunk
                    | StdlibKernel::HttpStreamClose
            );
            // `HttpStreamChunks` returns `Some(Server)` from
            // `required_runtime_module` but is explicitly NOT `is_server` —
            // it is handled by the lowerer's `required_runtime_module` scan
            // directly, not via the `is_server` predicate path.
            let expected =
                (server_resident || extra_server) && !matches!(k, StdlibKernel::HttpStreamChunks);
            assert_eq!(
                k.is_server(),
                expected,
                "{k:?} (class={:?}, required_runtime_module={:?}): is_server()={} \
                 but server-module residency oracle={} — a forgotten class=Server \
                 kernel causes the emitted crate to reference server::* with no \
                 module declaration (E0425/E0412)",
                decl.class,
                k.required_runtime_module(),
                k.is_server(),
                expected,
            );
        }
    }

    /// `is_web()` is derived from `class == Web` (like `is_db`). This pins that
    /// derivation to an INDEPENDENT residency oracle: the `web` runtime module
    /// hosts exactly the `Ipe.Web` app-entry family and the Task-shaped
    /// `PubSub.publish` / `publishNoEcho` — all `class = Web`, all carrying
    /// `required_runtime_module() == Some(Web)`. `CmdPublish` / `CmdPublishNoEcho`
    /// / `SubSubscribeTopic` also carry `required_runtime_module=Some(Web)` but
    /// are `class = Tea` and NOT `is_web` — the lowerer sets `uses_web` for them
    /// through the `required_runtime_module` scan, not via `is_web`. Both
    /// directions are asserted: a forgotten `class = Web` kernel → the `live`
    /// feature-module append never fires → `web::*` out of scope (E0425).
    #[test]
    fn web_predicate_tracks_web_module_residency() {
        use super::KernelClass;
        for k in StdlibKernel::ALL {
            let decl = k.decl();
            // Independent residency oracle: the kernels whose symbols the `web`
            // append declares are exactly the `Ipe.Web` app-entry family and the
            // two `PubSub.publish*` builders. Named by variant, not by reading the
            // class column, so it is a genuine second statement of the fact.
            let web_resident = matches!(
                k,
                StdlibKernel::WebApp
                    | StdlibKernel::WebEmbed
                    | StdlibKernel::WebAppRouted
                    | StdlibKernel::WebAppWith
                    | StdlibKernel::WebRoute
                    | StdlibKernel::WebRenderStatic
                    | StdlibKernel::PubSubPublish
                    | StdlibKernel::PubSubPublishNoEcho
            );
            assert_eq!(
                k.is_web(),
                web_resident,
                "{k:?} (class={:?}): is_web()={} but web-module residency oracle={} \
                 — a forgotten class=Web kernel causes the emitted crate to reference \
                 web::* with no module declaration (E0425)",
                decl.class,
                k.is_web(),
                web_resident,
            );
            assert_eq!(
                k.is_web(),
                decl.class == KernelClass::Web,
                "{k:?}: is_web()={} disagrees with class==Web ({}) — is_web is \
                 derived from the class column and must equal it exactly",
                k.is_web(),
                decl.class == KernelClass::Web,
            );
        }
    }

    /// `is_css()` MUST be true for exactly the kernels under the `"CssSafety"`
    /// qualifier. Those kernels emit bare names (`safe_value` / `safe_prop_name` /
    /// …) into `ipe_runtime::css` — declared only when `uses_css` is set. A
    /// program that uses `Ipe.Css` without any `Ipe.Ui`/`Ipe.Html` kernel does
    /// not trigger `uses_ui`, so only `is_css()` gates the `css`/`css_safety`
    /// append. A forgotten `CssSafety` kernel → bare name out of scope (E0425).
    /// Both directions are asserted.
    #[test]
    fn css_predicate_tracks_css_safety_qualifier() {
        for k in StdlibKernel::ALL {
            let expected = k.decl().qualifier == "CssSafety";
            assert_eq!(
                k.is_css(),
                expected,
                "{k:?} (qualifier={:?}): is_css()={} but qualifier==\"CssSafety\" \
                 is {} — a forgotten CssSafety kernel causes the emitted crate to \
                 reference safe_value/safe_prop_name/… with no css module (E0425)",
                k.decl().qualifier,
                k.is_css(),
                expected,
            );
        }
    }

    /// `is_db()` MUST be true for exactly the `class = Db` kernels — it is the
    /// SOLE selector for the `db` runtime module/feature (`ipe_lower` sets
    /// `uses_db` from it), so a forgotten Db-class kernel would emit an
    /// `ipe`-accepted crate that references `ipe_runtime::db::*` with no `db`
    /// feature enabled (E0425/E0433).
    ///
    /// The oracle is an INDEPENDENT restatement, not a copy of the predicate:
    /// the Db-class kernels live under the qualifiers `Db` / `Db.Decode` /
    /// `Db.Dsn` / `Sql`, with the `class = Pure` exceptions `Db.url`
    /// (`DbUrlSetting`, a setting reader emitting `ipe_setting_db_url`) and
    /// `Db.defaultMigration` (`DbDefaultMigration`, a record builder emitted
    /// inline as a `Migration` struct literal) — neither emits a db-runtime
    /// symbol, so neither must set `uses_db`. Those exceptions are exactly why
    /// `is_db` reads the `class` column and not the qualifier. Both directions
    /// are asserted, so a Db-class kernel outside these qualifiers, a non-Db
    /// kernel inside them, or a drift in either Pure exception all fail.
    #[test]
    fn db_predicate_tracks_db_class() {
        use super::KernelClass;
        for k in StdlibKernel::ALL {
            let qualifier = k.decl().qualifier;
            let expected = matches!(qualifier, "Db" | "Db.Decode" | "Db.Dsn" | "Sql")
                && !matches!(
                    k,
                    StdlibKernel::DbUrlSetting | StdlibKernel::DbDefaultMigration
                );
            assert_eq!(
                k.is_db(),
                expected,
                "{k:?} (qualifier={qualifier:?}, class={:?}): is_db()={} but the \
                 Db-residency oracle={expected} — a forgotten Db-class kernel omits \
                 the db feature/module, leaving ipe_runtime::db::* out of scope \
                 (E0425/E0433)",
                k.decl().class,
                k.is_db(),
            );
            assert_eq!(
                k.is_db(),
                k.decl().class == KernelClass::Db,
                "{k:?}: is_db()={} disagrees with class==Db ({}) — is_db is derived \
                 from the class column and must equal it exactly",
                k.is_db(),
                k.decl().class == KernelClass::Db,
            );
        }
    }

    /// `is_websocket_client()` MUST be true for exactly the kernels that gate the
    /// `websocket_client` Cargo feature and `ws_client` runtime module. The oracle
    /// is: `qualifier == "WebSocket"` (the six Task-tier connect/send/close
    /// kernels) OR the variant is `SubSubscribeWebSocket` (the Sub-tier entry,
    /// qualifier `"Sub"`). A forgotten member → the `ws_client` module is not
    /// declared and/or the `websocket_client` feature not enabled → runtime
    /// symbols out of scope (E0425). Both directions are asserted.
    #[test]
    fn websocket_client_predicate_tracks_ws_client_residency() {
        for k in StdlibKernel::ALL {
            let expected = k.decl().qualifier == "WebSocket"
                || matches!(k, StdlibKernel::SubSubscribeWebSocket);
            assert_eq!(
                k.is_websocket_client(),
                expected,
                "{k:?} (qualifier={:?}): is_websocket_client()={} but ws-client \
                 residency oracle={} — a forgotten WebSocket kernel causes the \
                 emitted crate to omit the websocket_client feature/module, leaving \
                 ws_client::* out of scope (E0425)",
                k.decl().qualifier,
                k.is_websocket_client(),
                expected,
            );
        }
    }

    /// Every `class = Terminal` kernel must be reported by EXACTLY ONE of
    /// `is_tui()` or `is_console()` — never both, never neither.
    /// Every non-Terminal kernel must report false for both.
    ///
    /// `TerminalAppScreen` → `is_tui`; `TerminalAppLines` → `is_console`.
    /// The XOR condition ensures: (a) a new Terminal app-entry forgotten in BOTH
    /// predicates → RED (neither true); (b) a kernel wrongly added to BOTH →
    /// RED (XOR fails); (c) a non-Terminal kernel accidentally claimed → RED.
    /// Failure message cites the SEAL consequence (missing tui/console runtime
    /// symbols).
    #[test]
    fn terminal_predicates_partition_terminal_class() {
        use super::KernelClass;
        for k in StdlibKernel::ALL {
            let is_terminal = k.decl().class == KernelClass::Terminal;
            let tui = k.is_tui();
            let console = k.is_console();

            if is_terminal {
                assert!(
                    tui ^ console,
                    "{k:?} has class=Terminal but is_tui()={tui} and is_console()={console} \
                     — every Terminal kernel must be assigned to exactly one of tui or console \
                     (XOR); a kernel in neither means tui/console runtime symbols are never \
                     declared for it (E0425); a kernel in both would double-declare"
                );
            } else {
                assert!(
                    !tui,
                    "{k:?} (class={:?}): is_tui()=true but class != Terminal — \
                     would incorrectly set uses_tui for a non-Terminal kernel",
                    k.decl().class
                );
                assert!(
                    !console,
                    "{k:?} (class={:?}): is_console()=true but class != Terminal — \
                     would incorrectly set uses_console for a non-Terminal kernel",
                    k.decl().class
                );
            }
        }
    }

    /// `is_worker()` MUST be true for exactly the view-less `Ipe.Tea.Worker.tea`
    /// app-entry — a `class = Tea` kernel that the UI delegate chain owns rather
    /// than the TEA dispatch arm. It is load-bearing in [`super::StdlibKernel::is_tea`]
    /// (which excludes it) and gates the `worker` runtime module. The oracle names
    /// the qualifier/name pair independently of the predicate; both directions are
    /// asserted, so a second worker entry, or a drift in the single one, fails.
    #[test]
    fn worker_predicate_tracks_tea_worker() {
        for k in StdlibKernel::ALL {
            let decl = k.decl();
            let expected = decl.qualifier == "Worker" && decl.name == "tea";
            assert_eq!(
                k.is_worker(),
                expected,
                "{k:?} (qualifier={:?}, name={:?}): is_worker()={} but the \
                 `Worker.tea` oracle={} — is_worker selects the view-less TEA \
                 app-entry the UI delegate chain owns; a drift here silently moves \
                 the is_tea/UI-domain boundary (IPE-I0001 ICE class)",
                decl.qualifier,
                decl.name,
                k.is_worker(),
                expected,
            );
        }
    }

    /// `is_tea()` is derived from `class == Tea`, minus the worker app-entry the
    /// UI delegate chain owns, plus the `class = Pure` `HttpStream.chunks` `Sub`.
    /// This pins that derivation to an INDEPENDENT oracle stated over the class
    /// column and named carve-outs. Both directions are asserted, so any drift —
    /// a new `class = Tea` kernel, a reclassified worker, or a moved `chunks` —
    /// fails the build rather than dispatching a TEA kernel through the wrong arm.
    #[test]
    fn tea_predicate_tracks_tea_class() {
        use super::KernelClass;
        for k in StdlibKernel::ALL {
            let decl = k.decl();
            // Independent oracle: every Tea-class kernel except the worker
            // app-entry, plus the one Pure `HttpStream.chunks` Sub builder.
            let tea_dispatched = (decl.class == KernelClass::Tea && !k.is_worker())
                || matches!(k, StdlibKernel::HttpStreamChunks);
            assert_eq!(
                k.is_tea(),
                tea_dispatched,
                "{k:?} (class={:?}): is_tea()={} but the TEA-dispatch oracle={} — \
                 a drift routes a TEA kernel through the wrong emit arm (or misses \
                 its arm), the IPE-I0001 ICE class the class↔predicate split caused",
                decl.class,
                k.is_tea(),
                tea_dispatched,
            );
        }
    }

    /// `is_ui()` is derived from `class == Ui`, plus the `Ipe.Color.Ansi` palette
    /// constructors (`qualifier == "TermColor"`, which are `class = Pure`). This
    /// pins that derivation to an INDEPENDENT oracle over the class column and the
    /// named `TermColor` qualifier carve-out. Both directions are asserted, so a
    /// new `class = Ui` kernel, or a palette constructor whose qualifier drifts,
    /// fails the build rather than missing the UI emitter (lost appearance-literal
    /// hoisting — the divergence class #2733 patched).
    #[test]
    fn ui_predicate_tracks_ui_class_plus_termcolor() {
        use super::KernelClass;
        for k in StdlibKernel::ALL {
            let decl = k.decl();
            let ui_domain = decl.class == KernelClass::Ui || decl.qualifier == "TermColor";
            assert_eq!(
                k.is_ui(),
                ui_domain,
                "{k:?} (class={:?}, qualifier={:?}): is_ui()={} but the UI-domain \
                 oracle={} — a drift drops a UI kernel from its emitter (lost \
                 appearance-literal hoisting / IPE-I0001 ICE class)",
                decl.class,
                decl.qualifier,
                k.is_ui(),
                ui_domain,
            );
        }
    }

    /// `requires_sync_capture()` MUST be true for exactly the kernels whose
    /// runtime callback slot demands `+ Send + Sync` — where an already-built
    /// `let`-bound closure must be promoted to `Arc<dyn Fn + Send + Sync>`.
    ///
    /// The oracle is derived from production data, not a copy of the predicate:
    /// - `Ipe.Ui` on-event builders whose emit name is one of the sync-slot set
    ///   (input / change / key-down / key-up / file / bool / submit — NOT the
    ///   zero-arg Msg-slot ones: click / focus / blur / mouse-over / mouse-out /
    ///   left / right / pseudo).
    /// - `Ipe.Html.Events` builders whose `html_event_shape()` returns `Some`
    ///   with a payload that is NOT `Msg` (i.e. `String` / `Bool` / `Raw`) —
    ///   these runtime constructors (`html_on_string_`, `html_on_bool_`,
    ///   `html_on_raw_`) take a callback stored in an `Arc<dyn Fn + Sync>` slot.
    ///   The Msg-shape constructors (`html_on_msg_`) take the message VALUE
    ///   directly, no callback slot, so they are excluded.
    /// - `StreamStream` (emit `server_stream_stream`) whose runtime generic bound
    ///   is `F: Fn + Send + Sync + 'static`.
    ///
    /// A forgotten sync-callback kernel → a `let`-bound closure is lowered as
    /// `Box<dyn Fn + Send>`, which the runtime's `+ Sync` slot rejects (E0277).
    /// Both directions are asserted.
    #[test]
    fn sync_capture_predicate_tracks_sync_bound_slots() {
        use super::HtmlEventShape;
        // Emit names of Ipe.Ui on-event builders whose runtime slot is +Sync.
        const UI_SYNC_EMITS: &[&str] = &[
            "ui_on_input_",
            "ui_on_change_",
            "ui_on_key_down_",
            "ui_on_key_up_",
            "ui_on_file_",
            "ui_on_bool_",
            "ui_on_submit_",
        ];
        for k in StdlibKernel::ALL {
            let emit = k.decl().emit;
            let ui_sync = UI_SYNC_EMITS.contains(&emit);
            // Html.Events: non-Msg shapes use a +Sync callback slot.
            let html_sync = matches!(
                k.html_event_shape(),
                Some(HtmlEventShape::String | HtmlEventShape::Bool | HtmlEventShape::Raw)
            );
            // Stream.stream generic bound is F: Fn + Send + Sync + 'static.
            let stream_sync = emit == "server_stream_stream";
            let expected = ui_sync || html_sync || stream_sync;
            assert_eq!(
                k.requires_sync_capture(),
                expected,
                "{k:?} (emit={emit:?}): requires_sync_capture()={} but sync-slot \
                 oracle={} — a forgotten +Sync callback kernel causes an already-built \
                 let-bound closure to be lowered as Box<dyn Fn+Send>, which the \
                 runtime's +Sync slot rejects (E0277)",
                k.requires_sync_capture(),
                expected,
            );
        }
    }

    /// The HOF classifier obliges exactly the variable final result of each callback.
    ///
    /// Map, fold, a two-argument mapper, and a callback carried inside a
    /// constructor are obliged; a boxed wrapper, a non-pure class, and a
    /// structured callback result are not.
    #[test]
    fn hof_result_vars_classify_callback_final_results() {
        let only = |var: u8| super::CallbackResults::EMPTY.with(var);
        assert_eq!(StdlibKernel::ListMap.hof_result_vars(), only(1));
        assert_eq!(StdlibKernel::ListFoldl.hof_result_vars(), only(1));
        assert_eq!(StdlibKernel::MaybeMap2.hof_result_vars(), only(2));
        assert_eq!(StdlibKernel::MaybeAndMap.hof_result_vars(), only(1));
        assert!(StdlibKernel::TaskMap.hof_result_vars().is_empty());
        assert!(StdlibKernel::JsonDecMap.hof_result_vars().is_empty());
        assert!(StdlibKernel::UiOnInput.hof_result_vars().is_empty());
        assert!(StdlibKernel::MaybeAndThen.hof_result_vars().is_empty());
        for k in StdlibKernel::ALL {
            assert!(!k.hof_result_vars().overflowed(), "{k:?}");
        }
    }

    /// A callback's own function-typed parameter is not searched for results.
    #[test]
    fn callback_result_vars_skip_callback_parameters() {
        use super::{TyShape, callback_result_vars};
        const A: TyShape = TyShape::Var(0);
        const B: TyShape = TyShape::Var(1);
        const C: TyShape = TyShape::Var(2);
        const A_TO_B: TyShape = TyShape::Fun(&A, &B);
        const HIGHER: TyShape = TyShape::Fun(&A_TO_B, &C);
        const SHAPE: TyShape = TyShape::Fun(&HIGHER, &A);
        let found = callback_result_vars(&SHAPE, 1);
        assert!(found.contains(2));
        assert!(!found.contains(1));
        assert!(callback_result_vars(&SHAPE, 0).is_empty());
    }

    /// A variable past the capacity is flagged, never silently dropped.
    #[test]
    fn callback_results_flag_overflow() {
        use super::CallbackResults;
        let last = CallbackResults::CAPACITY - 1;
        let set = CallbackResults::EMPTY.with(0).with(last);
        assert!(set.contains(0));
        assert!(set.contains(last));
        assert!(!set.overflowed());
        assert_eq!(set.vars().collect::<Vec<_>>(), vec![0, last]);
        let over = set.with(CallbackResults::CAPACITY);
        assert!(over.overflowed());
        assert!(!over.contains(CallbackResults::CAPACITY));
        assert_eq!(over.vars().count(), 2);
    }
}
