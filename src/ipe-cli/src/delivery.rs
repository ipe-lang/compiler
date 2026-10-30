//! The delivery grammar — one typed model of `ipe (build|release|watch) [shape]
//! [runtime] [host] [target] [--static]` and the single source of truth for
//! which combinations are valid.
//!
//! Two orthogonal axes place every program (spec § 0):
//!
//! * **shape** — what `view` renders (DOM / cells / lines / http / none). Pinned
//!   by the head of `main`, never redeclared. The optional leading `[shape]`
//!   positional is a *validated cross-check* against `main`, not a second source
//!   of truth.
//! * **runtime × host** — for the `web` shape only, whether the loop is
//!   co-located (`served`, the unnamed default) or sandboxed (`client`), and
//!   which host carries it.
//!
//! Every invalid combination is a [`DeliveryError`] — a kind-teacher diagnostic
//! that names the problem, explains the two-axis picture in a sentence, and
//! gives the fix. The message set lives here so it is itself a single source of
//! truth (spec § 6).
//!
//! Invalid states are unrepresentable: a resolved [`Delivery`] can only be built
//! by [`Delivery::resolve`], which admits nothing the validity table rejects.

use core::fmt;

use crate::text;
use ipe_backend_rust::static_build::StaticTriple;

/// A rendering class, pinned by the head of `main` (spec § 1). The leading CLI
/// positional, when present, must name the same shape `main` selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    /// `main : Task Error ()` — renders nothing; a native binary.
    Script,
    /// `main = Tui.tea …` — full-screen terminal cells.
    Tui,
    /// `main = Cli.tea …` — line-oriented terminal output.
    Cli,
    /// `main = Worker.tea …` — the view-less TEA loop; renders nothing, a native
    /// co-located binary with no runtime or host axis.
    Worker,
    /// `main = Web.tea …` — a DOM app, the only shape with a runtime choice.
    Web,
}

impl Shape {
    /// The canonical CLI word for this shape — the one vocabulary shared by CLI,
    /// errors, config, and docs.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Script => "script",
            Self::Tui => "tui",
            Self::Cli => "cli",
            Self::Worker => "worker",
            Self::Web => "web",
        }
    }

    /// Parse a shape word. `None` for any token outside the closed set (so a
    /// leading positional that is not a shape word is read as an entry path, not
    /// a mistyped shape). `server` is NOT a shape word: a server is a `script`
    /// (a `Direct` `Task Error ()` running `Server.listen`), so a leading
    /// `server` token reads as an entry path, never a shape.
    #[must_use]
    pub fn from_word(word: &str) -> Option<Self> {
        Some(match word {
            "script" => Self::Script,
            "tui" => Self::Tui,
            "cli" => Self::Cli,
            "worker" => Self::Worker,
            "web" => Self::Web,
            _ => return None,
        })
    }

    /// The rendering family a shape's TEA `Cmd`/`Sub` imports fold onto — `Tui`
    /// and `Cli` share the `Terminal` family. Mirrors the compiler classifier so
    /// the CLI cross-check and the compiler agree on one vocabulary.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Tui | Self::Cli)
    }

    /// The control model this shape's `main` runs under — the compiler-derived
    /// answer to "how does this program drive itself". It is a projection of the
    /// same shape the compiler already pinned, never a second derivation: a
    /// view-ful shape (`Web`/`Tui`/`Cli`) runs the Elm-style
    /// model/update/view loop ([`ControlModel::Tea`]); a `Script` (a plain
    /// `Task Error ()` — a batch tool or a listening `Server.listen` server
    /// alike) runs directly to completion ([`ControlModel::Direct`]).
    #[must_use]
    pub const fn control_model(self) -> ControlModel {
        ControlModel::from_shape(self.to_main())
    }

    /// The compiler [`MainShape`] this delivery [`Shape`] mirrors — the inverse of
    /// [`Self::from_main`]. Lets the control-model projection stay defined once,
    /// in the compiler, keyed on the shape the compiler pins.
    #[must_use]
    const fn to_main(self) -> ipe_canon::shape_source::MainShape {
        use ipe_canon::shape_source::MainShape;
        match self {
            Self::Script => MainShape::Script,
            Self::Tui => MainShape::Tui,
            Self::Cli => MainShape::Cli,
            Self::Worker => MainShape::Worker,
            Self::Web => MainShape::Web,
        }
    }

    /// The delivery shape a compiler-classified `main` pins. The compiler is the
    /// single source of truth for the shape (spec § 0); this maps its
    /// [`ipe_canon::shape_source::MainShape`] onto the delivery vocabulary so the
    /// grammar cross-check and the packager routing speak the same words.
    #[must_use]
    pub const fn from_main(shape: ipe_canon::shape_source::MainShape) -> Self {
        use ipe_canon::shape_source::MainShape;
        match shape {
            MainShape::Script => Self::Script,
            MainShape::Tui => Self::Tui,
            MainShape::Cli => Self::Cli,
            MainShape::Worker => Self::Worker,
            MainShape::Web => Self::Web,
        }
    }
}

/// How a program drives itself, projected from its compiler-pinned [`Shape`].
///
/// The definition lives in the compiler ([`ipe_canon::shape_source::ControlModel`])
/// so `ipe audit`, `ipe doc`, and LSP hover all read one control-model vocabulary
/// and one shape→model projection — never a second derivation that could disagree
/// with the shape the compiler already pinned. Re-exported here as the delivery
/// grammar's own name for it.
pub use ipe_canon::shape_source::ControlModel;

/// The Web-shape runtime (spec § 2).
///
/// Only `web` has a runtime choice; every other shape has exactly one, so this
/// axis is absent for them. The compiler's placement enum is the one source:
/// its [`Runtime::word`] is the only spelling the delivery grammar reads and
/// writes, and `served`, the unnamed default, has none.
pub use ipe_canon::shape_runtime::Runtime;

/// Declares [`RetiredRuntimeWord`], its [`RetiredRuntimeWord::ALL`], its text
/// and its replacement from one row list.
macro_rules! closed_retired_runtime_words {
    ($($doc:literal, $variant:ident, $text:literal, $now:ident;)+) => {
        /// A delivery word that existed once and is refused now, with its
        /// replacement.
        ///
        /// The set is closed: [`RetiredRuntimeWord::ALL`] lists each word once,
        /// in declaration order.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum RetiredRuntimeWord {
            $(
                #[doc = $doc]
                $variant,
            )+
        }

        impl RetiredRuntimeWord {
            /// Every retired word, the one list the refusals and the scan derive
            /// from.
            pub const ALL: [Self; Self::COUNT] = [$(RetiredRuntimeWord::$variant),+];

            const COUNT: usize = [$(RetiredRuntimeWord::$variant),+].len();

            /// The retired spelling.
            #[must_use]
            pub const fn text(self) -> &'static str {
                match self {
                    $(RetiredRuntimeWord::$variant => $text,)+
                }
            }

            /// The runtime that replaces the retired word.
            #[must_use]
            pub const fn replacement(self) -> Runtime {
                match self {
                    $(RetiredRuntimeWord::$variant => Runtime::$now,)+
                }
            }
        }
    };
}

closed_retired_runtime_words! {
    "`solo`: the self-contained browser client, now `client`.", Solo, "solo", Client;
    "`spa`: the self-contained browser client, now `client`.", Spa, "spa", Client;
    "`live`: the served default, never written.", Live, "live", Served;
}

impl RetiredRuntimeWord {
    /// The retired word `text` spells, or `None` for any other text.
    #[must_use]
    pub fn from_text(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|word| word.text() == text)
    }
}

/// Where a build was handed a compile target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetSource {
    /// The `--target` flag.
    Flag,
    /// The `IPE_TARGET` environment variable.
    Env,
}

impl TargetSource {
    /// The source's name as a refusal prints it.
    #[must_use]
    pub const fn spelling(self) -> &'static str {
        match self {
            Self::Flag => text::target_source_flag(),
            Self::Env => text::target_source_env(),
        }
    }
}

/// A delivery host — where a resolved shape × runtime actually runs (spec § 2,
/// § 4). Not every host is valid for every runtime; the validity table decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Host {
    /// The implicit host: `web` (served, over SSE) or `web client` (the browser).
    /// Never written — it is what an absent host token means.
    #[default]
    Default,
    /// `desktop`. Under `served` it is **webview-native** (the diff/patch
    /// pipeline over a local IPC bridge); under `client` it is **webview-wasm**
    /// (the self-contained client wrapped in a `wry` shell).
    Desktop,
    /// `ios` — a wasm client in `WKWebView` plus a native shell. `client` only.
    Ios,
    /// `android` — a wasm client in an Android `WebView` plus a native shell.
    /// `client` only.
    Android,
}

impl Host {
    /// The canonical CLI word, or `None` for the implicit default host (which is
    /// never written).
    #[must_use]
    pub const fn word(self) -> Option<&'static str> {
        match self {
            Self::Default => None,
            Self::Desktop => Some("desktop"),
            Self::Ios => Some("ios"),
            Self::Android => Some("android"),
        }
    }

    /// Parse a host word. `None` for any token outside the closed host set.
    #[must_use]
    pub fn from_word(word: &str) -> Option<Self> {
        Some(match word {
            "desktop" => Self::Desktop,
            "ios" => Self::Ios,
            "android" => Self::Android,
            _ => return None,
        })
    }

    /// The host's word in a camel-case builder name (`Desktop` in
    /// `clientDesktop`), or `None` for the implicit default host.
    #[must_use]
    pub const fn camel(self) -> Option<&'static str> {
        match self {
            Self::Default => None,
            Self::Desktop => Some("Desktop"),
            Self::Ios => Some("Ios"),
            Self::Android => Some("Android"),
        }
    }
}

/// The compile engine a program runs under.
///
/// The delivery-layer name for the backend [`ipe_ir::Target`], carried here so
/// the validity matrix can reason over `(engine, delivery, triple)` in one place
/// without importing the whole kernel crate. A projection of the same enum,
/// never a second derivation.
///
/// A closed set kept in lock-step with [`ipe_ir::Target`] by [`Self::of`]: the
/// instant a variant is added there, this `match` stops compiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Engine {
    /// The native host binary — full-kernel effects, `available_on == true`.
    Native,
    /// The sandboxed browser WASM client (`web client`) — the default-deny
    /// allowlist. Effects only via Web-API substitutes; native effects denied.
    WasmClient,
    /// The co-located portable WASI engine (`wasm32-wasip1`) — a
    /// `Direct`/`Script` program's native effect floor over WASI. Distinct from
    /// `WasmClient`: it runs native-ish effects (stdio, the WASI clock, the
    /// preopened-dir filesystem, `random_get`), not the browser sandbox. Its
    /// `available_on` is default-deny to the WASI-viable sealed floor.
    WasmWasi,
}

impl Engine {
    /// Project a backend [`ipe_ir::Target`] onto the delivery-layer engine. The
    /// backend enum is the single source of truth; this maps it, so a new
    /// backend target forces a new arm here at compile time.
    #[must_use]
    pub const fn of(target: ipe_ir::Target) -> Self {
        match target {
            ipe_ir::Target::Native => Self::Native,
            ipe_ir::Target::WasmClient => Self::WasmClient,
            ipe_ir::Target::WasmWasi => Self::WasmWasi,
        }
    }
}

/// An explicit compile target — the one closed set `--target`, the delivery
/// matrix, and `release` all name.
///
/// The host's own triple is the ABSENCE of a target (`Option<TargetTriple>` is
/// `None`), never a member, so "no `--target`" has exactly one representation.
/// Parsed from a raw `--target` word or rustc triple ONCE at the boundary (parse,
/// don't validate), so no unverifiable triple reaches the validity matrix or,
/// past it, cargo. A member being representable is not a licence to build it:
/// the matrix ([`Delivery::admit_triple`]) and each command's own refusals are
/// the gates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetTriple {
    /// `wasm32-unknown-unknown` — the browser sandbox triple (`web client`),
    /// `--target wasm`.
    BrowserWasm,
    /// `wasm32-wasip1` — the co-located portable WASI triple, `--target wasi`.
    Wasm32Wasip1,
    /// A supported musl-static native triple.
    Native(StaticTriple),
}

impl TargetTriple {
    /// The rustc triple spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BrowserWasm => "wasm32-unknown-unknown",
            Self::Wasm32Wasip1 => "wasm32-wasip1",
            Self::Native(triple) => triple.as_str(),
        }
    }

    /// The spelling of an optional target: its rustc triple, or `host` for none
    /// (the ambient host has no fixed spelling).
    #[must_use]
    pub const fn name_of(target: Option<Self>) -> &'static str {
        match target {
            Some(triple) => triple.as_str(),
            None => "host",
        }
    }

    /// Parse a rustc triple string into the representable set. `None` for any
    /// token outside the closed set — the caller turns that into a typed
    /// refusal. The empty string and an unsupported triple are both `None`.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "wasm32-unknown-unknown" => Some(Self::BrowserWasm),
            "wasm32-wasip1" => Some(Self::Wasm32Wasip1),
            triple => StaticTriple::parse(triple).map(Self::Native),
        }
    }

    /// Parse a `--target` word: `wasm`, `wasi`, or a supported musl triple.
    ///
    /// `None` for any word outside that vocabulary.
    #[must_use]
    pub fn from_flag(word: &str) -> Option<Self> {
        match word {
            "wasm" => Some(Self::BrowserWasm),
            "wasi" => Some(Self::Wasm32Wasip1),
            triple => StaticTriple::parse(triple).map(Self::Native),
        }
    }

    /// Whether this triple names a WebAssembly target (either wasm flavour).
    #[must_use]
    pub const fn is_wasm(self) -> bool {
        matches!(self, Self::BrowserWasm | Self::Wasm32Wasip1)
    }
}

/// The host a build asks the emit for.
///
/// The webview arm carries a [`WebViewProof`], which only
/// [`Delivery::host_intent`] mints, so a webview emit always traces back to a
/// resolved `web desktop` delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostIntent {
    /// The served host: every delivery except `web desktop`.
    Served,
    /// The webview-native `web desktop` host.
    WebView(WebViewProof),
}

/// Proof that a resolved delivery is webview-native.
///
/// Its field is private and [`Delivery::host_intent`] is its one constructor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WebViewProof(());

/// A fully-resolved delivery target — a shape, its (web-only) runtime, and a
/// valid host.
///
/// Constructible only through [`Delivery::resolve`], so no invalid combination
/// can be built. The runtime is `None` for every non-web shape (the axis does
/// not exist for them).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Delivery {
    shape: Shape,
    runtime: Option<Runtime>,
    host: Host,
}

impl Delivery {
    /// The resolved shape.
    #[must_use]
    pub const fn shape(self) -> Shape {
        self.shape
    }

    /// The resolved web runtime, or `None` for a non-web shape.
    #[must_use]
    pub const fn runtime(self) -> Option<Runtime> {
        self.runtime
    }

    /// The resolved host.
    #[must_use]
    pub const fn host(self) -> Host {
        self.host
    }

    /// `true` when this delivery links the system webview at runtime — the
    /// `web desktop` (webview-native) target. This is the single source of the
    /// backend `uses_webview` signal: the webview executor and the
    /// `default = ["webview"]` feature are emitted for exactly this delivery, and
    /// a served `web` (or any other shape) emits neither.
    #[must_use]
    pub const fn is_webview_native(self) -> bool {
        matches!(
            self,
            Self {
                shape: Shape::Web,
                runtime: Some(Runtime::Served),
                host: Host::Desktop,
            }
        )
    }

    /// The host this delivery asks the emit for: the webview host exactly when
    /// [`Self::is_webview_native`].
    #[must_use]
    pub const fn host_intent(self) -> HostIntent {
        if self.is_webview_native() {
            HostIntent::WebView(WebViewProof(()))
        } else {
            HostIntent::Served
        }
    }

    /// The `web desktop` delivery, the one the desktop packager ships.
    #[must_use]
    pub const fn web_desktop() -> Self {
        Self {
            shape: Shape::Web,
            runtime: Some(Runtime::Served),
            host: Host::Desktop,
        }
    }

    /// The `web client` delivery on the default host, the browser bundle the
    /// mobile packager builds for its shell.
    #[must_use]
    pub const fn web_client() -> Self {
        Self {
            shape: Shape::Web,
            runtime: Some(Runtime::Client),
            host: Host::Default,
        }
    }

    /// The CLI words that spell this delivery, in order: the shape, then the
    /// written runtime, then the written host. The served runtime and the
    /// default host are never written.
    pub fn words(self) -> impl Iterator<Item = &'static str> {
        core::iter::once(self.shape.word())
            .chain(self.runtime.and_then(Runtime::word))
            .chain(self.host.word())
    }

    /// `true` when a static (musl) artifact is admissible for this delivery.
    /// Only the co-located, no-webview shapes qualify: a webview host links the
    /// system webview at runtime, and a `client`/mobile host is a wasm/bundle
    /// target where a musl triple is moot.
    #[must_use]
    pub const fn allows_static(self) -> bool {
        match self.shape {
            Shape::Script | Shape::Tui | Shape::Cli | Shape::Worker => true,
            Shape::Web => matches!(
                self,
                Self {
                    runtime: Some(Runtime::Served),
                    host: Host::Default,
                    ..
                }
            ),
        }
    }

    /// Resolve a `main`-pinned shape and the parsed runtime/host tokens into a
    /// valid [`Delivery`], applying the defaults (`web` → served, every host →
    /// its implicit default) and rejecting every invalid combination with a
    /// pedagogical [`DeliveryError`].
    ///
    /// `runtime`/`host` apply to `web` only; a runtime or non-default host on a
    /// non-web shape is refused. For `web`, an absent runtime means served.
    ///
    /// # Errors
    /// [`DeliveryError`] naming the exact invalid combination and its fix.
    pub fn resolve(
        shape: Shape,
        runtime: Option<Runtime>,
        host: Host,
    ) -> Result<Self, DeliveryError> {
        if !matches!(shape, Shape::Web) {
            if runtime.is_some() {
                return Err(DeliveryError::RuntimeOnNonWeb { shape });
            }
            if host != Host::Default {
                return Err(DeliveryError::HostOnNonWeb { shape, host });
            }
            return Ok(Self {
                shape,
                runtime: None,
                host: Host::Default,
            });
        }

        // Web: absent runtime is the unnamed served default.
        let runtime = runtime.unwrap_or(Runtime::Served);
        match runtime {
            Runtime::Served => match host {
                // Served (implicit) or webview-native desktop.
                Host::Default | Host::Desktop => {}
                Host::Ios | Host::Android => {
                    return Err(DeliveryError::ServedHostNotMobile { host });
                }
            },
            Runtime::Client => {} // every host is valid for client.
        }
        Ok(Self {
            shape,
            runtime: Some(runtime),
            host,
        })
    }

    /// Resolve a delivery from the compiler-pinned shape and the parsed CLI
    /// tail, applying the `[shape]` cross-check and the `--static` gate.
    ///
    /// `pinned` is the shape the compiler derived from `main` (the single source
    /// of truth). `stated` is the optional leading `[shape]` positional: when
    /// present it must name the same shape as `pinned`, else the
    /// [`DeliveryError::ShapeMismatch`] lesson. `tokens` carries the parsed
    /// `[runtime] [host]`; `wants_static` is the `--static` request, refused for
    /// a delivery that has no static musl form.
    ///
    /// # Errors
    /// [`DeliveryError`] for a shape mismatch, an invalid runtime/host
    /// combination, or a `--static` request the delivery cannot honour.
    pub fn resolve_checked(
        pinned: Shape,
        stated: Option<Shape>,
        tokens: &DeliveryTokens,
        wants_static: bool,
    ) -> Result<Self, DeliveryError> {
        if let Some(stated) = stated
            && stated != pinned
        {
            return Err(DeliveryError::ShapeMismatch { stated, pinned });
        }
        let delivery = Self::resolve(pinned, tokens.runtime, tokens.host)?;
        if wants_static && !delivery.allows_static() {
            return Err(DeliveryError::StaticNotAllowed { delivery });
        }
        Ok(delivery)
    }

    /// The `(engine, delivery, triple)` validity matrix — a typed total function
    /// that admits exactly the legal combinations and refuses every other with a
    /// pedagogical [`DeliveryError`]. It is the single live gate coupling the
    /// delivery runtime to the compile target: it enforces the `client` IFF wasm
    /// biconditional (the runtime and the target are derived from independent
    /// sources — the delivery grammar vs the `--target`/`IPE_TARGET`/`[wasm].mode`
    /// chain — so this is the one point that refuses their disagreement) and adds
    /// the third axis (the triple), so the two wasm flavours — the sandboxed
    /// browser client (`wasm32-unknown-unknown`) and the co-located portable WASI
    /// target (`wasm32-wasip1`) — are kept cleanly separate at one place. It is
    /// load-bearing for security: the native-deny backstops that keep native
    /// effects out of a sandboxed client are keyed to the wasm engine, so a `client`
    /// delivery that slipped through as a native build would ship those effects
    /// into the sandbox. Absent proof the axes agree, the build is refused.
    ///
    /// Fail-closed by construction: the `match` is exhaustive and has NO
    /// permissive catch-all — a tuple not enumerated legal hits a refusal arm.
    /// `triple` is the explicit target, or `None` for the host's own triple.
    /// A new [`Engine`], [`Host`], or [`TargetTriple`] member forces a new arm at
    /// compile time, so a forgotten combination cannot ship as an open default.
    /// Co-located WASI (`wasm32-wasip1`) accepts only the sealed Direct/Script
    /// floor (`available_on(WasmWasi)`: the pure + always-on effect-floor kernels
    /// that build on wasip1); every non-viable TEA shape (`Tui`/`Cli`/`Web`) is
    /// refused here at ipe time, and every non-viable kernel — including a
    /// server's `Server.listen` (a `Direct` shape, so it passes this control-model
    /// gate) and Http/WebSocket/Db/… — is refused by the per-kernel sealed floor
    /// (`check_wasm_wasi`, IPE-N0029), so THE SEAL holds either way: an admitted
    /// wasip1 program `cargo build`s for that target.
    ///
    /// # Errors
    /// [`DeliveryError`] naming the exact illegal `(engine, delivery, triple)`
    /// cell and its fix.
    pub const fn admit_triple(
        self,
        engine: Engine,
        triple: Option<TargetTriple>,
    ) -> Result<(), DeliveryError> {
        let is_client = matches!(self.runtime, Some(Runtime::Client));
        match engine {
            // The native host binary: a WASM triple has no native form, and a
            // `client` delivery must not resolve to a native engine (the wasm-keyed
            // sandbox backstops would be skipped). Otherwise the static-triple
            // gate decides which co-located triples are admissible.
            Engine::Native => {
                match triple {
                    Some(wasm @ (TargetTriple::BrowserWasm | TargetTriple::Wasm32Wasip1)) => {
                        Err(DeliveryError::NativeEngineRefusesWasmTriple { triple: wasm })
                    }
                    None | Some(TargetTriple::Native(_)) if is_client => {
                        Err(DeliveryError::ClientRequiresBrowserTriple { triple })
                    }
                    None => Ok(()),
                    Some(TargetTriple::Native(_)) => {
                        // A musl static triple mirrors the `--static` gate: a
                        // webview-native (`web desktop`) delivery links the
                        // system webview and has no static form.
                        if self.allows_static() {
                            Ok(())
                        } else {
                            Err(DeliveryError::WebviewHasNoStaticTriple { delivery: self })
                        }
                    }
                }
            }
            // The sandboxed browser client: exactly `web client` on the browser
            // triple, and nothing else. It NEVER widens to the WASI triple —
            // that would be a sandbox escape hatch.
            Engine::WasmClient => {
                if !is_client {
                    return Err(DeliveryError::WasmTargetRequiresClient);
                }
                match triple {
                    Some(TargetTriple::BrowserWasm) => Ok(()),
                    Some(TargetTriple::Wasm32Wasip1) => Err(DeliveryError::ClientRefusesWasiTriple),
                    None | Some(TargetTriple::Native(_)) => {
                        Err(DeliveryError::ClientRequiresBrowserTriple { triple })
                    }
                }
            }
            // The co-located portable WASI engine: exactly the sealed
            // `Direct`/`Script` floor on the `wasm32-wasip1` triple, and nothing
            // else. It is NEVER `client` (that is the browser sandbox), and it
            // carries ONLY a `Direct` control model — a TEA loop (`Tui`/`Cli`/
            // `Web`) has no co-located WASI floor (its runtime spine pulls
            // tokio/axum, which do not build on wasip1), so admitting one would
            // break THE SEAL. A `Server.listen` program is a `Direct` shape, so
            // it passes THIS gate; its own tokio/axum-bound `ServerListen` kernel
            // is turned back by the per-kernel sealed floor (`check_wasm_wasi`),
            // the defense-in-depth backstop that upholds THE SEAL for it. The
            // other triples have no WASI form: the browser triple is the sandbox,
            // and a musl/host triple is a native binary, not a wasip1 module.
            Engine::WasmWasi => {
                if is_client {
                    return Err(DeliveryError::WasiRefusesClientDelivery);
                }
                match self.shape.control_model() {
                    ControlModel::Direct => {}
                    ControlModel::Tea => {
                        return Err(DeliveryError::WasiRequiresDirectShape { shape: self.shape });
                    }
                }
                match triple {
                    Some(TargetTriple::Wasm32Wasip1) => Ok(()),
                    None | Some(TargetTriple::BrowserWasm | TargetTriple::Native(_)) => {
                        Err(DeliveryError::WasiRequiresWasiTriple { triple })
                    }
                }
            }
        }
    }
}

impl fmt::Display for Delivery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (at, word) in self.words().enumerate() {
            if at > 0 {
                f.write_str(" ")?;
            }
            f.write_str(word)?;
        }
        Ok(())
    }
}

/// A pedagogical delivery refusal (spec § 6).
///
/// Each variant names the problem, explains the two-axis big picture in a
/// sentence, and suggests the fix. This enum is the message-set single source of
/// truth — every delivery diagnostic is one of these, phrased once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryError {
    /// The leading `[shape]` positional names a different shape than `main`.
    /// The shape is pinned by `main`; the positional is only a cross-check.
    ShapeMismatch {
        /// The shape the positional named.
        stated: Shape,
        /// The shape `main`'s entry actually selects.
        pinned: Shape,
    },
    /// The literal token `served` was written. `served` is the unnamed default —
    /// it is never spelled out.
    ServedNotAWord,
    /// A runtime word (`client`) was given for a non-web shape, which has no
    /// runtime axis.
    RuntimeOnNonWeb {
        /// The non-web shape that was given a runtime word.
        shape: Shape,
    },
    /// A host word was given for a non-web shape, which has no host axis.
    HostOnNonWeb {
        /// The non-web shape that was given a host word.
        shape: Shape,
        /// The host word given.
        host: Host,
    },
    /// A mobile host (`ios`/`android`) was given for the served runtime. Mobile
    /// is a self-contained `client` target only.
    ServedHostNotMobile {
        /// The mobile host that served does not carry.
        host: Host,
    },
    /// `--static` was requested for a delivery that cannot be a static musl
    /// binary (a webview host, or a `client`/mobile wasm/bundle target).
    StaticNotAllowed {
        /// The delivery that has no static form.
        delivery: Delivery,
    },
    /// An unknown token appeared where a runtime or host was expected.
    UnknownToken {
        /// The offending token.
        got: String,
    },
    /// A retired runtime word was written; its replacement is named.
    ///
    /// Raised before the host and unknown-token checks, so a retired word is
    /// never read as anything else.
    RetiredRuntimeWord {
        /// The retired word written.
        got: RetiredRuntimeWord,
    },
    /// A release was handed a wasm compile target.
    ///
    /// A release derives its browser bundle from the `web client` delivery, so
    /// a wasm target from the flag or the environment is refused, never ignored.
    ReleaseWasmTarget {
        /// Where the wasm target came from.
        source: TargetSource,
    },
    /// An app-bundle delivery was handed a compile target.
    ///
    /// A `desktop`/`ios`/`android` bundle picks its own target, so a target
    /// from the flag or the environment is refused, never ignored.
    BundleHostHasNoTarget {
        /// The app-bundle delivery.
        delivery: Delivery,
        /// Where the target came from.
        source: TargetSource,
    },
    /// `ipe dev run` was handed a `client` app-bundle delivery.
    ///
    /// A `desktop`/`ios`/`android` client bundle is laid out by `ipe dev
    /// build`; a dev run has no route that runs it, so the delivery is refused
    /// rather than run as the bare browser client.
    ClientHostHasNoDevRun {
        /// The app-bundle delivery.
        delivery: Delivery,
    },
    /// A runtime (`client`) or host (`desktop`/`ios`/`android`) token was given
    /// more than once. Each axis accepts exactly one value; a second token on
    /// the same axis is a conflict, not a last-wins override.
    DuplicateToken {
        /// `"runtime"` or `"host"`.
        kind: &'static str,
        /// The conflicting token that was seen a second time.
        got: String,
    },
    /// A wasm compile target resolved without a `client` delivery. The wasm
    /// client target exists only to carry a sandboxed `client` app; a
    /// non-`client` delivery has no wasm form, so the two were derived from
    /// disagreeing sources.
    WasmTargetRequiresClient,
    /// A WASM triple was requested for the native engine. The native binary has
    /// no WebAssembly form; the browser client compiles to
    /// `wasm32-unknown-unknown`, and the co-located WASI target to
    /// `wasm32-wasip1` — neither is a native build.
    NativeEngineRefusesWasmTriple {
        /// The WASM triple asked for on the native engine.
        triple: TargetTriple,
    },
    /// A `web client` app asked for a triple other than the browser sandbox
    /// triple. The sandboxed client compiles only to `wasm32-unknown-unknown`.
    ClientRequiresBrowserTriple {
        /// The non-browser triple asked for on a `client` delivery (`None` = the
        /// host's own).
        triple: Option<TargetTriple>,
    },
    /// A `web client` app asked for the `wasm32-wasip1` (WASI) triple. The
    /// browser sandbox never widens to WASI: WASI is the co-located portable
    /// target with native-ish effects, the exact opposite of the browser
    /// sandbox's default-deny surface. Allowing it would be a sandbox escape.
    ClientRefusesWasiTriple,
    /// A musl static triple was requested for a delivery that links the system
    /// webview at runtime (`web desktop`), which has no static binary. Mirrors
    /// the `--static` × webview refusal on the triple axis.
    WebviewHasNoStaticTriple {
        /// The webview-native delivery that has no static triple.
        delivery: Delivery,
    },
    /// A co-located WASI build was asked to carry a `client` delivery. `client`
    /// is the browser sandbox (`wasm32-unknown-unknown`); WASI is the co-located
    /// native-ish target — the two are opposite ends of the wasm axis.
    WasiRefusesClientDelivery,
    /// A co-located WASI build was asked for a non-`Direct` shape (a `Tui`/`Cli`/
    /// `Web` TEA loop). Only a `Direct` (`Task Error ()` script) program has a
    /// co-located WASI floor: a TEA loop's spine pulls tokio/axum, which do not
    /// build on `wasm32-wasip1`. (A server is a `Direct` shape and passes this
    /// gate; its `Server.listen` kernel is refused by the per-kernel WASI floor.)
    WasiRequiresDirectShape {
        /// The non-`Direct` shape asked for on the WASI engine.
        shape: Shape,
    },
    /// A co-located WASI engine was asked for a triple other than
    /// `wasm32-wasip1`. The WASI engine compiles only to its own portable
    /// triple.
    WasiRequiresWasiTriple {
        /// The non-WASI triple asked for on the WASI engine (`None` = the host's
        /// own).
        triple: Option<TargetTriple>,
    },
}

/// The runtime/host tokens parsed out of a delivery positional tail, before
/// validity resolution. Both axes are optional; resolution supplies the defaults.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct DeliveryTokens {
    /// The parsed web runtime (`Some(Client)` if `client` was written; `None` =
    /// served default). Only meaningful for the web shape.
    pub runtime: Option<Runtime>,
    /// The parsed host, defaulting to the implicit host.
    pub host: Host,
}

impl DeliveryTokens {
    /// Parse the delivery tail — the positional tokens that follow an optional
    /// `[shape]` — into typed axes. The runtime words are [`Runtime::word`]'s
    /// (`served` is refused); `desktop`/`ios`/`android` are hosts. A repeated
    /// host or runtime token is [`DeliveryError::DuplicateToken`].
    ///
    /// # Errors
    /// [`DeliveryError::ServedNotAWord`] if `served` is written;
    /// [`DeliveryError::RetiredRuntimeWord`] for a retired runtime word;
    /// [`DeliveryError::DuplicateToken`] for a repeated host or runtime token;
    /// [`DeliveryError::UnknownToken`] for any other unrecognised token.
    pub fn parse(tokens: &[String]) -> Result<Self, DeliveryError> {
        let mut out = Self::default();
        let mut saw_runtime = false;
        let mut saw_host = false;
        for tok in tokens {
            let runtime = parse_runtime_word(tok)?;
            if let Some(runtime) = runtime {
                if saw_runtime {
                    return Err(DeliveryError::DuplicateToken {
                        kind: "runtime",
                        got: tok.clone(),
                    });
                }
                saw_runtime = true;
                out.runtime = Some(runtime);
                continue;
            }
            if let Some(host) = Host::from_word(tok) {
                if saw_host {
                    return Err(DeliveryError::DuplicateToken {
                        kind: "host",
                        got: tok.clone(),
                    });
                }
                saw_host = true;
                out.host = host;
                continue;
            }
            return Err(DeliveryError::UnknownToken { got: tok.clone() });
        }
        Ok(out)
    }
}

/// Read one token as a runtime word: the written runtime it names, `None` for a
/// token that names no runtime, or the refusal of `served` and a retired word.
///
/// The one runtime-word reader the delivery tail and `ipe init` share.
///
/// # Errors
/// [`DeliveryError::ServedNotAWord`] for `served`;
/// [`DeliveryError::RetiredRuntimeWord`] for a retired word.
pub fn parse_runtime_word(token: &str) -> Result<Option<Runtime>, DeliveryError> {
    if token == "served" {
        return Err(DeliveryError::ServedNotAWord);
    }
    if let Some(got) = RetiredRuntimeWord::from_text(token) {
        return Err(DeliveryError::RetiredRuntimeWord { got });
    }
    Ok(Runtime::from_word(token))
}

impl fmt::Display for DeliveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShapeMismatch { stated, pinned } => f.write_str(&text::delivery_shape_mismatch(
                &stated.word(),
                &pinned.word(),
            )),
            Self::ServedNotAWord => f.write_str(text::delivery_served_not_a_word()),
            Self::RuntimeOnNonWeb { shape } => {
                f.write_str(&text::delivery_runtime_on_non_web(&shape.word()))
            }
            Self::HostOnNonWeb { shape, host } => f.write_str(&text::delivery_host_on_non_web(
                &shape.word(),
                &host.word().unwrap_or("default"),
            )),
            Self::ServedHostNotMobile { host } => f.write_str(
                &text::delivery_served_host_not_mobile(&host.word().unwrap_or("default")),
            ),
            Self::StaticNotAllowed { delivery } => match delivery.host() {
                Host::Desktop if delivery.runtime() == Some(Runtime::Served) => {
                    f.write_str(text::delivery_static_not_allowed_webview())
                }
                _ => f.write_str(&text::delivery_static_not_allowed(delivery)),
            },
            Self::UnknownToken { got } => f.write_str(&text::delivery_unknown_token(
                got,
                &Runtime::Client.word().unwrap_or_default(),
            )),
            Self::RetiredRuntimeWord { got } => match got.replacement() {
                Runtime::Client => f.write_str(&text::delivery_retired_client_word(&got.text())),
                Runtime::Served => f.write_str(&text::delivery_retired_served_word(&got.text())),
            },
            Self::ReleaseWasmTarget { source } => {
                f.write_str(&text::delivery_release_wasm_target(&source.spelling()))
            }
            Self::BundleHostHasNoTarget { delivery, source } => {
                f.write_str(&text::delivery_bundle_host_has_no_target(
                    delivery,
                    &delivery.host().word().unwrap_or_default(),
                    &source.spelling(),
                ))
            }
            Self::ClientHostHasNoDevRun { delivery } => {
                f.write_str(&text::delivery_client_host_has_no_dev_run(
                    delivery,
                    &delivery.host().word().unwrap_or_default(),
                ))
            }
            Self::DuplicateToken { kind, got } => {
                f.write_str(&text::delivery_duplicate_token(kind, got))
            }
            Self::WasmTargetRequiresClient => {
                f.write_str(text::delivery_wasm_target_requires_client())
            }
            Self::NativeEngineRefusesWasmTriple { triple } => f.write_str(
                &text::delivery_native_engine_refuses_wasm_triple(&triple.as_str()),
            ),
            Self::ClientRequiresBrowserTriple { triple } => {
                let name = TargetTriple::name_of(*triple);
                f.write_str(&text::delivery_client_requires_browser_triple(&name))
            }
            Self::ClientRefusesWasiTriple => {
                f.write_str(text::delivery_client_refuses_wasi_triple())
            }
            Self::WebviewHasNoStaticTriple { delivery } => {
                f.write_str(&text::delivery_webview_has_no_static_triple(delivery))
            }
            Self::WasiRefusesClientDelivery => {
                f.write_str(text::delivery_wasi_refuses_client_delivery())
            }
            Self::WasiRequiresDirectShape { shape } => {
                f.write_str(&text::delivery_wasi_requires_direct_shape(&shape.word()))
            }
            Self::WasiRequiresWasiTriple { triple } => {
                let name = TargetTriple::name_of(*triple);
                f.write_str(&text::delivery_wasi_requires_wasi_triple(&name))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tokens(words: &[&str]) -> Vec<String> {
        words.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn web_no_tokens_is_served_default() {
        let t = DeliveryTokens::parse(&tokens(&[])).unwrap();
        let d = Delivery::resolve(Shape::Web, t.runtime, t.host).unwrap();
        assert_eq!(d.runtime(), Some(Runtime::Served));
        assert_eq!(d.host(), Host::Default);
        assert!(!d.is_webview_native());
        assert!(d.allows_static(), "served is a co-located static target");
        assert_eq!(d.to_string(), "web");
    }

    #[test]
    fn host_intent_matches_webview_native() {
        let shapes = [
            Shape::Script,
            Shape::Tui,
            Shape::Cli,
            Shape::Worker,
            Shape::Web,
        ];
        let runtimes = [None, Some(Runtime::Served), Some(Runtime::Client)];
        let hosts = [Host::Default, Host::Desktop, Host::Ios, Host::Android];
        let mut webview = Vec::new();
        for shape in shapes {
            for runtime in runtimes {
                for host in hosts {
                    let Ok(delivery) = Delivery::resolve(shape, runtime, host) else {
                        continue;
                    };
                    let intent = delivery.host_intent();
                    assert_eq!(
                        matches!(intent, HostIntent::WebView(_)),
                        delivery.is_webview_native(),
                        "{delivery}: {intent:?}"
                    );
                    if matches!(intent, HostIntent::WebView(_)) {
                        webview.push(delivery.to_string());
                    }
                }
            }
        }
        webview.dedup();
        assert_eq!(webview, ["web desktop"]);
        assert_eq!(
            Delivery::resolve(Shape::Web, None, Host::Desktop).ok(),
            Some(Delivery::web_desktop())
        );
    }

    #[test]
    fn web_desktop_is_webview_native_and_not_static() {
        let t = DeliveryTokens::parse(&tokens(&["desktop"])).unwrap();
        let d = Delivery::resolve(Shape::Web, t.runtime, t.host).unwrap();
        assert!(d.is_webview_native());
        assert!(!d.allows_static());
        assert_eq!(d.to_string(), "web desktop");
    }

    #[test]
    fn web_client_hosts_all_resolve() {
        for host in ["desktop", "ios", "android"] {
            let t = DeliveryTokens::parse(&tokens(&["client", host])).unwrap();
            let d = Delivery::resolve(Shape::Web, t.runtime, t.host).unwrap();
            assert_eq!(d.runtime(), Some(Runtime::Client));
            assert!(!d.is_webview_native(), "client is never webview-native");
            assert!(!d.allows_static());
        }
        let t = DeliveryTokens::parse(&tokens(&["client"])).unwrap();
        let d = Delivery::resolve(Shape::Web, t.runtime, t.host).unwrap();
        assert_eq!(d.host(), Host::Default);
        assert!(!d.allows_static());
    }

    #[test]
    fn served_is_never_a_word() {
        assert_eq!(
            DeliveryTokens::parse(&tokens(&["served"])).unwrap_err(),
            DeliveryError::ServedNotAWord
        );
        assert_eq!(
            DeliveryTokens::parse(&tokens(&["client", "served"])).unwrap_err(),
            DeliveryError::ServedNotAWord
        );
    }

    #[test]
    fn served_refuses_mobile_hosts() {
        for host in [Host::Ios, Host::Android] {
            assert_eq!(
                Delivery::resolve(Shape::Web, None, host).unwrap_err(),
                DeliveryError::ServedHostNotMobile { host }
            );
        }
    }

    #[test]
    fn runtime_or_host_on_non_web_is_refused() {
        for shape in [Shape::Script, Shape::Tui, Shape::Cli, Shape::Worker] {
            assert_eq!(
                Delivery::resolve(shape, Some(Runtime::Client), Host::Default).unwrap_err(),
                DeliveryError::RuntimeOnNonWeb { shape }
            );
            assert_eq!(
                Delivery::resolve(shape, None, Host::Desktop).unwrap_err(),
                DeliveryError::HostOnNonWeb {
                    shape,
                    host: Host::Desktop
                }
            );
        }
    }

    #[test]
    fn non_web_shapes_are_static_capable() {
        for shape in [Shape::Script, Shape::Tui, Shape::Cli, Shape::Worker] {
            let d = Delivery::resolve(shape, None, Host::Default).unwrap();
            assert_eq!(d.runtime(), None);
            assert!(d.allows_static());
        }
    }

    #[test]
    fn unknown_token_is_pedagogical() {
        assert_eq!(
            DeliveryTokens::parse(&tokens(&["wut"])).unwrap_err(),
            DeliveryError::UnknownToken {
                got: "wut".to_owned()
            }
        );
        // A hyphenated token that looks like a target triple is no longer
        // silently absorbed — the grammar has no target positional. It must
        // be an unknown-token refusal, not silent last-wins acceptance.
        assert!(matches!(
            DeliveryTokens::parse(&tokens(&["wasm32-unknown-unknown"])).unwrap_err(),
            DeliveryError::UnknownToken { .. }
        ));
    }

    #[test]
    fn retired_solo_is_refused_naming_client() {
        for words in [&["solo"][..], &["solo", "ios"][..]] {
            let err = DeliveryTokens::parse(&tokens(words)).unwrap_err();
            assert_eq!(
                err,
                DeliveryError::RetiredRuntimeWord {
                    got: RetiredRuntimeWord::Solo,
                }
            );
            let text = err.to_string();
            assert!(text.contains("`client`"), "names the replacement: {text}");
            assert!(text.contains("web client"), "names the delivery: {text}");
        }
    }

    #[test]
    fn retired_spa_and_live_are_refused() {
        let spa = DeliveryTokens::parse(&tokens(&["spa"])).unwrap_err();
        assert_eq!(
            spa,
            DeliveryError::RetiredRuntimeWord {
                got: RetiredRuntimeWord::Spa,
            }
        );
        assert!(spa.to_string().contains("`client`"), "{spa}");
        let live = DeliveryTokens::parse(&tokens(&["live"])).unwrap_err();
        assert_eq!(
            live,
            DeliveryError::RetiredRuntimeWord {
                got: RetiredRuntimeWord::Live,
            }
        );
        assert!(live.to_string().contains("Write `web` alone"), "{live}");
        for word in RetiredRuntimeWord::ALL {
            assert_eq!(RetiredRuntimeWord::from_text(word.text()), Some(word));
            assert_eq!(Runtime::from_word(word.text()), None);
            assert_eq!(Host::from_word(word.text()), None);
        }
    }

    #[test]
    fn web_ios_is_refused_hinting_web_client_ios() {
        for host in [Host::Ios, Host::Android] {
            let Some(word) = host.word() else { return };
            let t = DeliveryTokens::parse(&tokens(&[word])).unwrap();
            let err = Delivery::resolve(Shape::Web, t.runtime, t.host).unwrap_err();
            assert_eq!(err, DeliveryError::ServedHostNotMobile { host });
            let hint = format!("web client {word}");
            assert!(err.to_string().contains(&hint), "hints `{hint}`: {err}");
        }
    }

    #[test]
    fn duplicate_runtime_token_is_refused() {
        // `client client` — second runtime token must be a typed refusal, not last-wins.
        assert!(matches!(
            DeliveryTokens::parse(&tokens(&["client", "client"])).unwrap_err(),
            DeliveryError::DuplicateToken {
                kind: "runtime",
                ..
            }
        ));
    }

    #[test]
    fn duplicate_host_token_is_refused() {
        // Two host words — second host must be a typed refusal, not last-wins.
        assert!(matches!(
            DeliveryTokens::parse(&tokens(&["desktop", "ios"])).unwrap_err(),
            DeliveryError::DuplicateToken { kind: "host", .. }
        ));
        assert!(matches!(
            DeliveryTokens::parse(&tokens(&["android", "android"])).unwrap_err(),
            DeliveryError::DuplicateToken { kind: "host", .. }
        ));
    }

    #[test]
    fn duplicate_token_message_is_pedagogical() {
        let e = DeliveryError::DuplicateToken {
            kind: "runtime",
            got: "client".to_owned(),
        };
        assert!(e.to_string().len() > 40, "a refusal is a lesson: {e}");
        let e2 = DeliveryError::DuplicateToken {
            kind: "host",
            got: "ios".to_owned(),
        };
        assert!(e2.to_string().len() > 40, "a refusal is a lesson: {e2}");
    }

    #[test]
    fn control_model_is_the_projection_of_the_pinned_shape() {
        // The view-ful shapes run the TEA loop; a script runs direct. Pins the
        // SSOT projection against drift.
        assert_eq!(Shape::Web.control_model(), ControlModel::Tea);
        assert_eq!(Shape::Tui.control_model(), ControlModel::Tea);
        assert_eq!(Shape::Cli.control_model(), ControlModel::Tea);
        // A worker is the view-less corner of the same managed loop — Tea, never
        // a run-to-completion Direct program.
        assert_eq!(Shape::Worker.control_model(), ControlModel::Tea);
        // A server is a `script` — a `Direct` `Task Error ()` run to completion.
        assert_eq!(Shape::Script.control_model(), ControlModel::Direct);
        // Every model has a stable, distinct word.
        assert_eq!(ControlModel::Tea.word(), "tea");
        assert_eq!(ControlModel::Direct.word(), "direct");
    }

    #[test]
    fn control_model_word_round_trips_and_rejects_unknown() {
        for model in [ControlModel::Tea, ControlModel::Direct] {
            assert_eq!(ControlModel::from_word(model.word()), Some(model));
        }
        // A token outside the closed set is None — never a permissive default.
        // The retired `server` model no longer parses.
        assert_eq!(ControlModel::from_word("server"), None);
        assert_eq!(ControlModel::from_word("Direct"), None); // case-sensitive
        assert_eq!(ControlModel::from_word("telepathy"), None);
        assert_eq!(ControlModel::from_word(""), None);
    }

    #[test]
    fn only_direct_is_the_elevated_unmanaged_model() {
        // The managed model runs under the runtime's loop; Direct drives itself.
        assert!(ControlModel::Tea.is_managed());
        assert!(!ControlModel::Direct.is_managed());
    }

    #[test]
    fn shape_words_round_trip() {
        for shape in [
            Shape::Script,
            Shape::Tui,
            Shape::Cli,
            Shape::Worker,
            Shape::Web,
        ] {
            assert_eq!(Shape::from_word(shape.word()), Some(shape));
        }
        assert_eq!(Shape::from_word("nope"), None);
        // `server` is not a shape word — it reads as an entry path.
        assert_eq!(Shape::from_word("server"), None);
    }

    #[test]
    fn messages_teach_not_slap() {
        let cases = [
            DeliveryError::ServedNotAWord,
            DeliveryError::ShapeMismatch {
                stated: Shape::Tui,
                pinned: Shape::Web,
            },
            DeliveryError::RuntimeOnNonWeb { shape: Shape::Cli },
            DeliveryError::ServedHostNotMobile { host: Host::Ios },
            DeliveryError::StaticNotAllowed {
                delivery: Delivery::resolve(Shape::Web, None, Host::Desktop).unwrap(),
            },
            DeliveryError::ClientRequiresBrowserTriple { triple: None },
            DeliveryError::WasmTargetRequiresClient,
            DeliveryError::RetiredRuntimeWord {
                got: RetiredRuntimeWord::Live,
            },
            DeliveryError::ReleaseWasmTarget {
                source: TargetSource::Env,
            },
            DeliveryError::BundleHostHasNoTarget {
                delivery: Delivery::resolve(Shape::Web, Some(Runtime::Client), Host::Ios).unwrap(),
                source: TargetSource::Flag,
            },
            DeliveryError::ClientHostHasNoDevRun {
                delivery: Delivery::resolve(Shape::Web, Some(Runtime::Client), Host::Android)
                    .unwrap(),
            },
        ];
        for c in &cases {
            assert!(c.to_string().len() > 40, "a refusal is a lesson: {c}");
        }
    }

    // === The engine × host × triple validity matrix (#2461) ===

    fn client() -> Delivery {
        Delivery::resolve(Shape::Web, Some(Runtime::Client), Host::Default).unwrap()
    }
    fn served() -> Delivery {
        Delivery::resolve(Shape::Web, Some(Runtime::Served), Host::Default).unwrap()
    }
    fn web_desktop() -> Delivery {
        Delivery::resolve(Shape::Web, Some(Runtime::Served), Host::Desktop).unwrap()
    }

    #[test]
    fn target_triple_parse_is_closed() {
        // Every representable triple round-trips; everything else is `None` —
        // parse, don't validate. The empty string and one-past-the-last-legal
        // (`wasm64`, gnu, a bogus wasm flavour) are all refused at the boundary.
        assert_eq!(
            TargetTriple::parse("x86_64-unknown-linux-musl"),
            Some(TargetTriple::Native(StaticTriple::X8664LinuxMusl))
        );
        assert_eq!(
            TargetTriple::parse("aarch64-unknown-linux-musl"),
            Some(TargetTriple::Native(StaticTriple::Aarch64LinuxMusl))
        );
        assert_eq!(
            TargetTriple::parse("wasm32-unknown-unknown"),
            Some(TargetTriple::BrowserWasm)
        );
        assert_eq!(
            TargetTriple::parse("wasm32-wasip1"),
            Some(TargetTriple::Wasm32Wasip1)
        );
        assert_eq!(TargetTriple::parse(""), None);
        assert_eq!(TargetTriple::parse("x86_64-unknown-linux-gnu"), None);
        assert_eq!(TargetTriple::parse("wasm32-wasi"), None);
        assert_eq!(TargetTriple::parse("wasm64-unknown-unknown"), None);
        // The spellings are stable and match rustc's.
        assert_eq!(TargetTriple::Wasm32Wasip1.as_str(), "wasm32-wasip1",);
        assert!(TargetTriple::BrowserWasm.is_wasm());
        assert!(TargetTriple::Wasm32Wasip1.is_wasm());
        assert!(!TargetTriple::Native(StaticTriple::X8664LinuxMusl).is_wasm());
        assert_eq!(TargetTriple::name_of(None), "host");
    }

    #[test]
    fn target_flag_vocabulary_is_closed() {
        // The `--target` words map onto the same set the rustc spellings do.
        assert_eq!(
            TargetTriple::from_flag("wasm"),
            Some(TargetTriple::BrowserWasm)
        );
        assert_eq!(
            TargetTriple::from_flag("wasi"),
            Some(TargetTriple::Wasm32Wasip1)
        );
        assert_eq!(
            TargetTriple::from_flag("aarch64-unknown-linux-musl"),
            Some(TargetTriple::Native(StaticTriple::Aarch64LinuxMusl))
        );
        // The rustc spelling of a wasm triple, the host word, and the empty
        // word are not `--target` words.
        assert_eq!(TargetTriple::from_flag("wasm32-unknown-unknown"), None);
        assert_eq!(TargetTriple::from_flag("host"), None);
        assert_eq!(TargetTriple::from_flag(""), None);
    }

    #[test]
    fn engine_projects_the_backend_target() {
        // The delivery-layer engine is a projection of the backend target, never
        // a second derivation — pins the SSOT map against drift.
        assert_eq!(Engine::of(ipe_ir::Target::Native), Engine::Native);
        assert_eq!(Engine::of(ipe_ir::Target::WasmClient), Engine::WasmClient);
        assert_eq!(Engine::of(ipe_ir::Target::WasmWasi), Engine::WasmWasi);
    }

    // --- Refusals first: every illegal cell turned away with a typed diagnostic.

    #[test]
    fn client_refuses_wasi_triple() {
        // THE headline separation: the browser sandbox never widens to WASI.
        assert_eq!(
            client().admit_triple(Engine::WasmClient, Some(TargetTriple::Wasm32Wasip1)),
            Err(DeliveryError::ClientRefusesWasiTriple),
        );
    }

    #[test]
    fn wasi_engine_admits_only_direct_script() {
        // The co-located WASI accept-path: a `Direct` script (`Task Error ()`)
        // on `wasm32-wasip1` is the ONE admitted cell. THE SEAL rests on this —
        // only the sealed floor a `Direct` program reaches builds on wasip1.
        let script = Delivery::resolve(Shape::Script, None, Host::Default).unwrap();
        assert_eq!(
            script.admit_triple(Engine::WasmWasi, Some(TargetTriple::Wasm32Wasip1)),
            Ok(()),
        );
    }

    #[test]
    fn wasi_engine_refuses_non_direct_shapes() {
        // A TEA loop (`Tui`/`Cli`/`Web`/`Worker`) has no co-located WASI floor —
        // its spine pulls tokio/axum, which do not build on wasip1. Fail-closed
        // with a typed diagnostic so the unbuildable shape never reaches the
        // wasip1 `cargo build`.
        for shape in [Shape::Tui, Shape::Cli, Shape::Worker] {
            let d = Delivery::resolve(shape, None, Host::Default).unwrap();
            assert_eq!(
                d.admit_triple(Engine::WasmWasi, Some(TargetTriple::Wasm32Wasip1)),
                Err(DeliveryError::WasiRequiresDirectShape { shape }),
                "the WASI engine must refuse the non-Direct {shape:?} shape",
            );
        }
        // A `web` (served) app is a TEA loop too — refused on the WASI engine.
        assert_eq!(
            served().admit_triple(Engine::WasmWasi, Some(TargetTriple::Wasm32Wasip1)),
            Err(DeliveryError::WasiRequiresDirectShape { shape: Shape::Web }),
        );
        // A `script` (the `Direct` bucket a server folds into) PASSES this
        // control-model gate — a server's own tokio/axum-bound `Server.listen`
        // kernel is instead turned back by the per-kernel WASI floor
        // (`ipe_canon::target_gate::check_wasm_wasi`), the defense-in-depth
        // backstop that upholds THE SEAL for it.
        assert_eq!(
            Delivery::resolve(Shape::Script, None, Host::Default)
                .unwrap()
                .admit_triple(Engine::WasmWasi, Some(TargetTriple::Wasm32Wasip1)),
            Ok(()),
        );
    }

    #[test]
    fn wasi_engine_refuses_client_delivery() {
        // `client` is the browser sandbox — the exact opposite of co-located WASI.
        assert_eq!(
            client().admit_triple(Engine::WasmWasi, Some(TargetTriple::Wasm32Wasip1)),
            Err(DeliveryError::WasiRefusesClientDelivery),
        );
    }

    #[test]
    fn wasi_engine_refuses_non_wasi_triples() {
        // The WASI engine compiles only to its own portable triple; every other
        // triple (browser sandbox, host, musl) has no wasip1 form.
        let script = Delivery::resolve(Shape::Script, None, Host::Default).unwrap();
        for t in [
            Some(TargetTriple::BrowserWasm),
            None,
            Some(TargetTriple::Native(StaticTriple::X8664LinuxMusl)),
            Some(TargetTriple::Native(StaticTriple::Aarch64LinuxMusl)),
        ] {
            assert_eq!(
                script.admit_triple(Engine::WasmWasi, t),
                Err(DeliveryError::WasiRequiresWasiTriple { triple: t }),
            );
        }
    }

    #[test]
    fn native_engine_still_refuses_wasi_triple() {
        // The WASI triple is admissible ONLY on the WASI engine — the native
        // engine has no wasip1 form (defense in depth against a mis-routed
        // triple slipping past the engine gate).
        for d in [
            Delivery::resolve(Shape::Script, None, Host::Default).unwrap(),
            served(),
        ] {
            assert_eq!(
                d.admit_triple(Engine::Native, Some(TargetTriple::Wasm32Wasip1)),
                Err(DeliveryError::NativeEngineRefusesWasmTriple {
                    triple: TargetTriple::Wasm32Wasip1
                }),
            );
        }
    }

    #[test]
    fn client_requires_browser_triple() {
        // A `client` client on any non-browser triple is refused.
        for t in [
            None,
            Some(TargetTriple::Native(StaticTriple::X8664LinuxMusl)),
            Some(TargetTriple::Native(StaticTriple::Aarch64LinuxMusl)),
        ] {
            assert_eq!(
                client().admit_triple(Engine::WasmClient, t),
                Err(DeliveryError::ClientRequiresBrowserTriple { triple: t }),
            );
        }
    }

    #[test]
    fn native_engine_refuses_wasm_triples() {
        // Both wasm flavours have no native form.
        for t in [TargetTriple::BrowserWasm, TargetTriple::Wasm32Wasip1] {
            assert_eq!(
                served().admit_triple(Engine::Native, Some(t)),
                Err(DeliveryError::NativeEngineRefusesWasmTriple { triple: t }),
            );
        }
    }

    #[test]
    fn native_engine_refuses_client_delivery() {
        // A `client` delivery must not resolve to the native engine — the
        // wasm-keyed sandbox backstops would be skipped. Subsumes the
        // biconditional's client-to-wasm half on the triple axis: the host's
        // own triple and an explicit native triple are refused alike, naming
        // the triple asked for.
        for triple in [
            None,
            Some(TargetTriple::Native(StaticTriple::Aarch64LinuxMusl)),
        ] {
            assert_eq!(
                client().admit_triple(Engine::Native, triple),
                Err(DeliveryError::ClientRequiresBrowserTriple { triple }),
            );
        }
    }

    #[test]
    fn wasm_client_engine_refuses_non_client_delivery() {
        // The symmetric half: the browser client engine only carries `client`.
        for d in [
            served(),
            web_desktop(),
            Delivery::resolve(Shape::Cli, None, Host::Default).unwrap(),
        ] {
            assert_eq!(
                d.admit_triple(Engine::WasmClient, Some(TargetTriple::BrowserWasm)),
                Err(DeliveryError::WasmTargetRequiresClient),
                "the browser client engine must refuse the non-client delivery {d}",
            );
        }
    }

    #[test]
    fn webview_native_has_no_static_triple() {
        // Mirrors the `--static` × webview refusal on the triple axis: a
        // webview-native delivery has no musl binary.
        for t in [StaticTriple::X8664LinuxMusl, StaticTriple::Aarch64LinuxMusl] {
            assert_eq!(
                web_desktop().admit_triple(Engine::Native, Some(TargetTriple::Native(t))),
                Err(DeliveryError::WebviewHasNoStaticTriple {
                    delivery: web_desktop()
                }),
            );
        }
    }

    // --- Legal cells: the enumerated admissions.

    #[test]
    fn browser_client_admits_browser_wasm() {
        assert_eq!(
            client().admit_triple(Engine::WasmClient, Some(TargetTriple::BrowserWasm)),
            Ok(()),
        );
    }

    #[test]
    fn native_colocated_admits_host_and_musl() {
        for d in [
            Delivery::resolve(Shape::Script, None, Host::Default).unwrap(),
            Delivery::resolve(Shape::Tui, None, Host::Default).unwrap(),
            Delivery::resolve(Shape::Cli, None, Host::Default).unwrap(),
            Delivery::resolve(Shape::Worker, None, Host::Default).unwrap(),
            served(),
        ] {
            assert_eq!(d.admit_triple(Engine::Native, None), Ok(()));
            assert_eq!(
                d.admit_triple(
                    Engine::Native,
                    Some(TargetTriple::Native(StaticTriple::X8664LinuxMusl))
                ),
                Ok(()),
                "{d} is static-capable on x86-64 musl",
            );
            assert_eq!(
                d.admit_triple(
                    Engine::Native,
                    Some(TargetTriple::Native(StaticTriple::Aarch64LinuxMusl))
                ),
                Ok(()),
            );
        }
    }

    #[test]
    fn matrix_enforces_the_client_iff_wasm_biconditional() {
        // The matrix IS the `client` IFF wasm biconditional: on the browser-client
        // axis, `client` compiles to wasm and wasm carries only `client` — both
        // agreeing corners admitted, both disagreeing corners refused, with no
        // permissive middle. (engine, triple) is the target side of the
        // biconditional: WasmClient+BrowserWasm is the wasm corner, Native+Host
        // the native corner.
        let client = client();
        let served = served();
        // client + wasm: admitted (the sandboxed client's one legal target).
        assert_eq!(
            client.admit_triple(Engine::WasmClient, Some(TargetTriple::BrowserWasm)),
            Ok(()),
        );
        // client + native: refused — the wasm-keyed sandbox backstops would be
        // skipped for a client shipped as a native binary.
        assert_eq!(
            client.admit_triple(Engine::Native, None),
            Err(DeliveryError::ClientRequiresBrowserTriple { triple: None }),
        );
        // served + wasm: refused — a non-`client` shape has no browser-wasm form.
        assert_eq!(
            served.admit_triple(Engine::WasmClient, Some(TargetTriple::BrowserWasm)),
            Err(DeliveryError::WasmTargetRequiresClient),
        );
        // served + native: admitted — the co-located native binary.
        assert_eq!(served.admit_triple(Engine::Native, None), Ok(()),);
    }

    #[test]
    fn matrix_refusals_teach_not_slap() {
        let cases = [
            DeliveryError::NativeEngineRefusesWasmTriple {
                triple: TargetTriple::Wasm32Wasip1,
            },
            DeliveryError::ClientRequiresBrowserTriple {
                triple: Some(TargetTriple::Native(StaticTriple::X8664LinuxMusl)),
            },
            DeliveryError::ClientRefusesWasiTriple,
            DeliveryError::WebviewHasNoStaticTriple {
                delivery: web_desktop(),
            },
            DeliveryError::WasiRefusesClientDelivery,
            DeliveryError::WasiRequiresDirectShape { shape: Shape::Tui },
            DeliveryError::WasiRequiresWasiTriple { triple: None },
        ];
        for c in &cases {
            assert!(c.to_string().len() > 40, "a refusal is a lesson: {c}");
        }
    }
}
