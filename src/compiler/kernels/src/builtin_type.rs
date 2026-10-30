//! The one table of builtin type heads.
//!
//! Every fact the compiler keeps about a builtin type constructor — its
//! canonical `(home, name)` head, whether a user may declare its name, how the
//! boundary seal judges it, the type arguments it takes, the qualifiers that
//! also spell it, and the [`BuiltinTag`] a kernel scheme names it by — is one
//! row of [`BUILTIN_TYPES`]. Every other site reads the table; the `const`
//! assertions below fail the build the moment a row breaks an invariant.
//!
//! Identity is the `(home, name)` pair: [`BuiltinType::of_head`]. A row at
//! [`KernelHome::Builtin`] is the empty-home builtin an unqualified annotation
//! resolves to; [`BuiltinType::of_bare_name`] is that resolver's lookup and
//! never sees a row with a module home.

use strum::EnumCount as _;

use crate::{BuiltinTag, FieldTag, StdlibKernel, TyShape};
use BuiltinRole::{KernelImplicit, LoweredBelowGuard, Reserved};
use SealClass::{EffectCarrier, Opaque, Plain, SealedHandle, SecretOrSink, ValueContainer, View};
use TypeParams::{Exact, InferredCarrier, OptionalMessage};

/// Where a builtin type head lives.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KernelHome {
    /// The empty home: the name resolves unqualified in every module.
    Builtin,
    /// A module home, as its dotted path (`"Ipe.Db.Store"`).
    Module(&'static str),
}

impl KernelHome {
    /// Whether this home is the canonical home spelled by `segments`.
    ///
    /// The empty home matches only an empty segment list; a module home
    /// matches exactly its dotted path, segment by segment.
    #[must_use]
    pub fn matches(self, segments: &[&str]) -> bool {
        match self {
            Self::Builtin => segments.is_empty(),
            Self::Module(path) => path.split('.').eq(segments.iter().copied()),
        }
    }
}

impl BuiltinTag {
    /// The home of the head a kernel scheme mints for this tag.
    ///
    /// The one owner of the scheme-side home: `ipe_types` interprets a
    /// [`crate::TyShape::Con`] under it and canon mints a kernel module's type
    /// exports under it, so the two paths name one head. A row whose
    /// [`BuiltinRow::home`] differs is listed by the divergence test below.
    #[must_use]
    #[allow(clippy::too_many_lines)] // one exhaustive arm per tag; the match IS the table
    pub const fn scheme_home(self) -> KernelHome {
        match self {
            Self::TaskStep => KernelHome::Module("Ipe.Task"),
            Self::Duration => KernelHome::Module("Ipe.Duration"),
            Self::HtmlAttribute => KernelHome::Module("Html"),
            Self::EmailProvider => KernelHome::Module("Ipe.Email"),
            Self::DbStore
            | Self::DbDraft
            | Self::DbJoined
            | Self::DbSelect
            | Self::DbPolicy
            | Self::DbCond
            | Self::DbPred
            | Self::DbSecured
            | Self::DbOrder => KernelHome::Module("Ipe.Db.Store"),
            Self::Codec => KernelHome::Module("Ipe.Codec"),
            Self::Remote | Self::RemoteAuth => KernelHome::Module("Ipe.Remote"),
            Self::Int
            | Self::Float
            | Self::Bool
            | Self::String
            | Self::Char
            | Self::Bytes
            | Self::List
            | Self::Maybe
            | Self::Result
            | Self::Set
            | Self::Dict
            | Self::Order
            | Self::Error
            | Self::ErrorKind
            | Self::ErrorDetails
            | Self::BackoffStrategy
            | Self::Decimal
            | Self::Task
            | Self::Cmd
            | Self::Sub
            | Self::Topic
            | Self::Decoder
            | Self::Db
            | Self::SqlValue
            | Self::SqlField
            | Self::SqlFragment
            | Self::ProjectionTerm
            | Self::ProjectionOperand
            | Self::Secret
            | Self::Path
            | Self::Regex
            | Self::Url
            | Self::UrlRelative
            | Self::Dsn
            | Self::DbLocation
            | Self::Connection
            | Self::ConnReadOnly
            | Self::ConnReadWrite
            | Self::Setting
            | Self::ShapeWeb
            | Self::ShapeWebView
            | Self::ShapeTerminal
            | Self::Program
            | Self::ProgramShapeWeb
            | Self::ProgramShapeTui
            | Self::ProgramShapeCli
            | Self::ProgramShapeWorker
            | Self::HostMode
            | Self::LogLevel
            | Self::CsrfMode
            | Self::RevocationMode
            | Self::Locale
            | Self::HttpMethod
            | Self::RedirectPolicy
            | Self::DbFailure
            | Self::AuthError
            | Self::CryptoKey
            | Self::CryptoMac
            | Self::EmailAddress
            | Self::Principal
            | Self::Claims
            | Self::Algorithm
            | Self::JsonValue
            | Self::StreamId
            | Self::StreamWriter
            | Self::WsServer
            | Self::WsServerCfg
            | Self::ServerRequest
            | Self::ServerCookie
            | Self::ServerRoute
            | Self::AuthConfig
            | Self::TokenSource
            | Self::UiAttribute
            | Self::View
            | Self::UiElement
            | Self::Cells
            | Self::TuiAttr
            | Self::CliLines
            | Self::CliAttr
            | Self::Color
            | Self::ColorError
            | Self::TermProfile
            | Self::AnsiColor
            | Self::WcagLevel
            | Self::TextSize
            | Self::Deficiency
            | Self::CustomElement
            | Self::Html
            | Self::UiLength
            | Self::UiColor
            | Self::UiDescription
            | Self::UiPseudoClass
            | Self::InputLabel
            | Self::InputPlaceholder
            | Self::InputRadioOption
            | Self::WebReq
            | Self::SessionHandle
            | Self::WebRoute
            | Self::WebApp
            | Self::TuiApp
            | Self::CliApp => KernelHome::Builtin,
        }
    }
}

/// Where the lowerer maps a builtin name, which decides whether a user may
/// declare it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BuiltinRole {
    /// Lowered by name ABOVE the lowerer's `enum_variants` guard to a fixed IR
    /// type. A user `type` of the name would be silently overridden, so the
    /// declaration is refused (IPE-N0026).
    Reserved,
    /// Lowered BELOW the `enum_variants` guard: a program union of the name
    /// wins by its own `(home, name)`, so a user declaration is sound.
    LoweredBelowGuard,
    /// A kernel-implicit opaque handle no source module declares; a user
    /// declaration wins by its own home, as for [`Self::LoweredBelowGuard`].
    KernelImplicit,
}

impl BuiltinRole {
    /// Whether a user module may NOT declare a type of this name.
    #[must_use]
    pub const fn forbids_user_declaration(self) -> bool {
        matches!(self, Self::Reserved)
    }

    /// Whether a builtin union of this row may carry constructors.
    #[must_use]
    pub const fn admits_ctors(self) -> bool {
        matches!(self, Self::Reserved | Self::LoweredBelowGuard)
    }
}

/// How the Ipê↔JS boundary seal judges a builtin head.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SealClass {
    /// A closed primitive with a total JSON denotation; crosses the seam.
    Plain,
    /// A value container the seal recurses into, argument by argument.
    ValueContainer,
    /// An effect carrier; never boundary data.
    EffectCarrier,
    /// A view or `Ipe.Ui` value; clonable but not serialisable data.
    View,
    /// A secret, a sink-privileged value, or a validated security handle;
    /// never serialised.
    SecretOrSink,
    /// A security-tier opaque handle with a fixed lowering; not proven plain.
    SealedHandle,
    /// Any other opaque builtin; not proven plain.
    Opaque,
}

impl SealClass {
    /// Whether the class pins a fixed lowering, so its row must be
    /// [`BuiltinRole::Reserved`].
    const fn needs_reservation(self) -> bool {
        !matches!(self, Self::View | Self::Opaque)
    }
}

/// The type arguments a builtin head takes, and the gate that counts them.
///
/// Every row declares one, so no head escapes the count: a use applied to a
/// count its row does not admit is refused before lowering.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TypeParams {
    /// Exactly this many; canon refuses any other count (IPE-N0031).
    Exact(u8),
    /// One message parameter a bare use may omit: canon fills the omitted one
    /// with the `any` wildcard and refuses a second (IPE-N0031).
    OptionalMessage,
    /// One argument, counted by inference (IPE-T0016): the effect carriers.
    InferredCarrier,
}

impl TypeParams {
    /// The count a kernel scheme applies the head to.
    #[must_use]
    pub const fn in_schemes(self) -> usize {
        match self {
            Self::Exact(n) => n as usize,
            Self::OptionalMessage | Self::InferredCarrier => 1,
        }
    }
}

/// One builtin type head and every fact the compiler keeps about it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BuiltinRow {
    name: &'static str,
    home: KernelHome,
    role: BuiltinRole,
    seal: SealClass,
    params: TypeParams,
    qualified_via: &'static [&'static str],
    tag: Option<BuiltinTag>,
}

impl BuiltinRow {
    /// The head's type name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// The head's canonical home.
    #[must_use]
    pub const fn home(&self) -> KernelHome {
        self.home
    }

    /// Where the lowerer maps the name.
    #[must_use]
    pub const fn role(&self) -> BuiltinRole {
        self.role
    }

    /// How the boundary seal judges the head.
    #[must_use]
    pub const fn seal(&self) -> SealClass {
        self.seal
    }

    /// The type arguments the head takes.
    #[must_use]
    pub const fn params(&self) -> TypeParams {
        self.params
    }

    /// The exact type-argument count canon enforces, or `None` when the head
    /// takes an optional message or an inference-counted argument.
    #[must_use]
    pub const fn fixed_arity(&self) -> Option<u8> {
        match self.params {
            Exact(n) => Some(n),
            OptionalMessage | InferredCarrier => None,
        }
    }

    /// The kernel qualifiers that also spell this head (`Http.HttpMethod`).
    #[must_use]
    pub const fn qualified_via(&self) -> &'static [&'static str] {
        self.qualified_via
    }

    /// The tag a kernel type scheme names this head by, if any.
    #[must_use]
    pub const fn tag(&self) -> Option<BuiltinTag> {
        self.tag
    }

    const fn via(self, qualifiers: &'static [&'static str]) -> Self {
        Self {
            qualified_via: qualifiers,
            ..self
        }
    }

    const fn tagged(self, tag: BuiltinTag) -> Self {
        Self {
            tag: Some(tag),
            ..self
        }
    }
}

/// A builtin type head: a row of [`BUILTIN_TYPES`], obtainable only by lookup.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BuiltinType(&'static BuiltinRow);

impl BuiltinType {
    /// The builtin whose canonical head is exactly `(home, name)`.
    ///
    /// `home` is the resolved module path as segments; the empty slice is the
    /// empty home. A head that is not a row is a user type, never a builtin.
    #[must_use]
    pub fn of_head(home: &[&str], name: &str) -> Option<Self> {
        if home.is_empty() {
            return bare_row(name).map(Self);
        }
        BUILTIN_TYPES
            .get(BARE_ROWS..)?
            .iter()
            .find(|row| row.name == name && row.home.matches(home))
            .map(Self)
    }

    /// The empty-home builtin named `name`, for the unqualified type-name
    /// resolver.
    ///
    /// Only that resolver may read a head by its bare name: every other
    /// identity question goes through [`Self::of_head`].
    #[must_use]
    pub fn of_bare_name(name: &str) -> Option<Self> {
        bare_row(name).map(Self)
    }

    /// The row holding this builtin's facts.
    #[must_use]
    pub const fn row(self) -> &'static BuiltinRow {
        self.0
    }
}

/// Binary search over the empty-home prefix, which the sortedness assertion
/// keeps ordered by name.
fn bare_row(name: &str) -> Option<&'static BuiltinRow> {
    let bare = BUILTIN_TYPES.get(..BARE_ROWS)?;
    let at = bare.binary_search_by(|row| row.name.cmp(name)).ok()?;
    bare.get(at)
}

const fn bare(
    name: &'static str,
    role: BuiltinRole,
    seal: SealClass,
    params: TypeParams,
) -> BuiltinRow {
    BuiltinRow {
        name,
        home: KernelHome::Builtin,
        role,
        seal,
        params,
        qualified_via: &[],
        tag: None,
    }
}

const fn homed(
    path: &'static str,
    name: &'static str,
    role: BuiltinRole,
    seal: SealClass,
    params: TypeParams,
) -> BuiltinRow {
    BuiltinRow {
        name,
        home: KernelHome::Module(path),
        role,
        seal,
        params,
        qualified_via: &[],
        tag: None,
    }
}

/// Every builtin type head, sorted by `(home, name)`: the empty home first,
/// then module homes by dotted path, each by name in byte order.
///
/// A row's home is its canonical `(home, name)` identity. A
/// [`BuiltinRole::Reserved`] row sits at the empty home: its reservation keys
/// on the name a user would declare.
pub const BUILTIN_TYPES: &[BuiltinRow] = &[
    // `Ipe.Jwt`'s signing-algorithm descriptor; sealed, no rendering of key material.
    bare("Algorithm", Reserved, SealedHandle, Exact(0)).tagged(BuiltinTag::Algorithm),
    bare("AnsiColor", Reserved, Opaque, Exact(0)).tagged(BuiltinTag::AnsiColor),
    bare("ArithOp", Reserved, Opaque, Exact(0)),
    bare("Attribute", Reserved, View, OptionalMessage).tagged(BuiltinTag::UiAttribute),
    // `Ipe.Server`'s authed-route descriptors: `AuthConfig` carries the token-verification `Secret`.
    bare("AuthConfig", Reserved, Opaque, Exact(0))
        .via(&["Server"])
        .tagged(BuiltinTag::AuthConfig),
    // `Ipe.Auth`'s closed token-refusal ADT, the error of `Auth.verifyToken`; its constructors are `Auth.`-qualified.
    bare("AuthError", LoweredBelowGuard, Opaque, Exact(0))
        .via(&["Auth"])
        .tagged(BuiltinTag::AuthError),
    bare("Bool", Reserved, Plain, Exact(0)).tagged(BuiltinTag::Bool),
    bare("Bytes", Reserved, Plain, Exact(0)).tagged(BuiltinTag::Bytes),
    bare("Cells", Reserved, Opaque, Exact(1)),
    bare("Char", Reserved, Plain, Exact(0)).tagged(BuiltinTag::Char),
    bare("ChunkEvent", Reserved, SealedHandle, Exact(0)).via(&["HttpStream"]),
    bare("CliAttr", Reserved, Opaque, Exact(1)).tagged(BuiltinTag::CliAttr),
    bare("Cmd", Reserved, EffectCarrier, InferredCarrier)
        .via(&[
            "TeaCliCmd",
            "TeaTerminalCmd",
            "TeaTuiCmd",
            "TeaWebCmd",
            "TeaWorkerCmd",
        ])
        .tagged(BuiltinTag::Cmd),
    // The unified colour value; a program `type Color` wins by its own home.
    bare("Color", LoweredBelowGuard, View, Exact(0)).tagged(BuiltinTag::Color),
    // `Ipe.Color`'s companions, each a fixed `ipe_runtime::color` carrier built only through `Ipe.Color` kernels.
    bare("ColorError", Reserved, Opaque, Exact(0)).tagged(BuiltinTag::ColorError),
    // `Ipe.Db`'s external connection and its phantom access modes: the read-only-by-type write barrier.
    bare("Connection", Reserved, SealedHandle, Exact(1)).tagged(BuiltinTag::Connection),
    bare("Cookie", Reserved, Opaque, Exact(0)).tagged(BuiltinTag::ServerCookie),
    bare("CsrfMode", Reserved, Opaque, Exact(0)).tagged(BuiltinTag::CsrfMode),
    // The JS-widget boundary `CustomElement down up`: a use resolves only through the arity gate (IPE-N0031) and the plain-value seal (IPE-N0039).
    bare("CustomElement", Reserved, Opaque, Exact(2)).tagged(BuiltinTag::CustomElement),
    bare("Db", Reserved, Opaque, Exact(0))
        .via(&["Db"])
        .tagged(BuiltinTag::Db),
    // `Ipe.Db`'s closed failure-cause ADT, carried by `ErrorDetails.Database`; its constructors are `Db.`-qualified.
    bare("DbFailure", LoweredBelowGuard, Opaque, Exact(0))
        .via(&["Db"])
        .tagged(BuiltinTag::DbFailure),
    // `Ipe.Db.Location`'s typed database location: may carry a `Dsn` and its `Secret` password.
    bare("DbLocation", Reserved, SecretOrSink, Exact(0)).tagged(BuiltinTag::DbLocation),
    bare("Decimal", LoweredBelowGuard, Opaque, Exact(0)).tagged(BuiltinTag::Decimal),
    bare("Decoder", Reserved, Opaque, Exact(1))
        .via(&["Db.Decode", "JsonDec"])
        .tagged(BuiltinTag::Decoder),
    bare("Deficiency", Reserved, Opaque, Exact(0)).tagged(BuiltinTag::Deficiency),
    bare("Description", Reserved, View, Exact(0)).tagged(BuiltinTag::UiDescription),
    bare("Dict", Reserved, ValueContainer, Exact(2)).tagged(BuiltinTag::Dict),
    // `Ipe.Db.Dsn`'s connection descriptor: carries a `Secret` password and a fail-closed TLS posture.
    bare("Dsn", Reserved, SecretOrSink, Exact(0)).tagged(BuiltinTag::Dsn),
    bare("Element", Reserved, View, OptionalMessage).tagged(BuiltinTag::UiElement),
    // `Ipe.Email`'s validated address.
    bare("EmailAddress", Reserved, SecretOrSink, Exact(0)).tagged(BuiltinTag::EmailAddress),
    bare("Error", Reserved, Opaque, Exact(0)).tagged(BuiltinTag::Error),
    bare("ErrorDetails", LoweredBelowGuard, Opaque, Exact(0)).tagged(BuiltinTag::ErrorDetails),
    bare("ErrorInfo", LoweredBelowGuard, Opaque, Exact(0)),
    bare("ErrorKind", LoweredBelowGuard, Opaque, Exact(0)).tagged(BuiltinTag::ErrorKind),
    bare("Event", Reserved, View, Exact(1)),
    bare("Float", Reserved, Plain, Exact(0)).tagged(BuiltinTag::Float),
    bare("HAlign", Reserved, View, Exact(0)),
    bare("Handler", KernelImplicit, Opaque, Exact(0)).via(&["Server"]),
    // Closed config-tag ADTs, built only through their constructor kernels; `CsrfMode` has no disabling variant.
    bare("HostMode", Reserved, Opaque, Exact(0)).tagged(BuiltinTag::HostMode),
    bare("Html", Reserved, View, OptionalMessage).tagged(BuiltinTag::Html),
    // `Ipe.Http`'s closed verb ADT, lowered to a fixed enum.
    bare("HttpMethod", Reserved, SealedHandle, Exact(0))
        .via(&["Http"])
        .tagged(BuiltinTag::HttpMethod),
    bare("HttpRequest", LoweredBelowGuard, Opaque, Exact(0)).via(&["Http"]),
    bare("Int", Reserved, Plain, Exact(0)).tagged(BuiltinTag::Int),
    // `Ipe.Crypto`'s role-typed key and HMAC output.
    bare("Key", Reserved, SecretOrSink, Exact(0))
        .via(&["Crypto"])
        .tagged(BuiltinTag::CryptoKey),
    bare("Label", LoweredBelowGuard, Opaque, Exact(1)).tagged(BuiltinTag::InputLabel),
    bare("LayoutContext", Reserved, View, Exact(0)),
    // The nullary `Ipe.Ui` names; trusted stdlib may define them (`STDLIB_DEFINABLE_UI_TYPES`).
    bare("Length", Reserved, View, Exact(0)).tagged(BuiltinTag::UiLength),
    // `Ipe.Ui.Cli`'s line view `Lines msg` and its line-native attribute.
    bare("Lines", Reserved, Opaque, OptionalMessage).tagged(BuiltinTag::CliLines),
    bare("List", Reserved, ValueContainer, Exact(1)).tagged(BuiltinTag::List),
    // `Ipe.Locale`'s BCP-47 handle.
    bare("Locale", Reserved, SecretOrSink, Exact(0)).tagged(BuiltinTag::Locale),
    bare("Location", Reserved, View, Exact(0)),
    bare("LogLevel", Reserved, Opaque, Exact(0)).tagged(BuiltinTag::LogLevel),
    bare("Mac", Reserved, SecretOrSink, Exact(0))
        .via(&["Crypto"])
        .tagged(BuiltinTag::CryptoMac),
    bare("Maybe", Reserved, ValueContainer, Exact(1)).tagged(BuiltinTag::Maybe),
    bare("Middleware", KernelImplicit, Opaque, Exact(0)),
    bare("Migration", LoweredBelowGuard, Opaque, Exact(0)).via(&["Db"]),
    // `Basics.Order` names this row through the compiled-source `Ipe.Basics`
    // home, not a kernel qualifier, so the row carries no `via`.
    bare("Order", LoweredBelowGuard, Opaque, Exact(0)).tagged(BuiltinTag::Order),
    bare("PanicInfo", LoweredBelowGuard, Opaque, Exact(0)),
    // `Ipe.Path`'s validated path: the traversal and NUL refusal boundary.
    bare("Path", Reserved, SecretOrSink, Exact(0)).tagged(BuiltinTag::Path),
    bare("Placeholder", LoweredBelowGuard, Opaque, Exact(1)).tagged(BuiltinTag::InputPlaceholder),
    // `Ipe.Auth`'s authenticated subject: the auth mint is its only origin.
    bare("Principal", Reserved, Opaque, Exact(0))
        .via(&["Auth"])
        .tagged(BuiltinTag::Principal),
    // `Program shape msg`, the TEA shape carrier every `<Shape>.app` entry returns.
    bare("Program", Reserved, Opaque, Exact(2)).tagged(BuiltinTag::Program),
    bare("ProjectionOperand", Reserved, Opaque, Exact(0)).tagged(BuiltinTag::ProjectionOperand),
    // `Ipe.Db.Store`'s projection-descriptor ADTs: a user union of the name would override the synthetic `EnumDef` the lowerer injects.
    bare("ProjectionTerm", Reserved, Opaque, Exact(0)).tagged(BuiltinTag::ProjectionTerm),
    bare("PseudoClass", Reserved, View, Exact(0)).tagged(BuiltinTag::UiPseudoClass),
    bare("ReadOnly", Reserved, SealedHandle, Exact(0)).tagged(BuiltinTag::ConnReadOnly),
    bare("ReadWrite", Reserved, SealedHandle, Exact(0)).tagged(BuiltinTag::ConnReadWrite),
    // `Ipe.Regex`'s compiled pattern: `Regex.compile`'s typed refusal is its only origin.
    bare("Regex", Reserved, SecretOrSink, Exact(0)).tagged(BuiltinTag::Regex),
    // `Ipe.Url`'s same-origin relative reference: the browser-href SSRF boundary.
    bare("Relative", Reserved, SecretOrSink, Exact(0)).tagged(BuiltinTag::UrlRelative),
    bare("Request", Reserved, Opaque, Exact(0))
        .via(&["Server"])
        .tagged(BuiltinTag::ServerRequest),
    bare("Response", Reserved, Opaque, Exact(0)).via(&["Server"]),
    bare("Result", Reserved, ValueContainer, Exact(2)).tagged(BuiltinTag::Result),
    bare("RevocationMode", Reserved, Opaque, Exact(0)).tagged(BuiltinTag::RevocationMode),
    bare("Route", Reserved, Opaque, Exact(0))
        .via(&["Server"])
        .tagged(BuiltinTag::ServerRoute),
    // `Ipe.Ui.Tui`'s view `Screen msg`; `Cells` is its rendering-model spelling.
    bare("Screen", Reserved, Opaque, OptionalMessage).tagged(BuiltinTag::Cells),
    // `Ipe.Secret`'s sealed secret string, a security-tier type.
    bare("Secret", Reserved, SecretOrSink, Exact(0))
        .via(&["Secret"])
        .tagged(BuiltinTag::Secret),
    bare("Session", KernelImplicit, Opaque, Exact(0)),
    // `Ipe.Ffi.Js`'s session-stream address: `Js.openSession` is its only origin.
    bare("SessionHandle", Reserved, Opaque, Exact(0)).tagged(BuiltinTag::SessionHandle),
    bare("Set", Reserved, ValueContainer, Exact(1)).tagged(BuiltinTag::Set),
    // `Ipe.App`'s config carrier `Setting shape`: the phantom shape keeps a `Web`-only setting out of another shape.
    bare("Setting", Reserved, Opaque, Exact(1)).tagged(BuiltinTag::Setting),
    bare("SqlField", Reserved, SecretOrSink, Exact(0)).tagged(BuiltinTag::SqlField),
    // `Ipe.Db.Sql`'s opaque WHERE fragment, a security-tier sink.
    bare("SqlFragment", Reserved, SecretOrSink, Exact(0)).tagged(BuiltinTag::SqlFragment),
    bare("SqlValue", Reserved, SecretOrSink, Exact(0)).tagged(BuiltinTag::SqlValue),
    bare("Store", KernelImplicit, Opaque, Exact(0)),
    bare("StreamId", Reserved, SealedHandle, Exact(0))
        .via(&["HttpStream"])
        .tagged(BuiltinTag::StreamId),
    bare("StreamWriter", LoweredBelowGuard, Opaque, Exact(0))
        .via(&["Stream"])
        .tagged(BuiltinTag::StreamWriter),
    bare("String", Reserved, Plain, Exact(0)).tagged(BuiltinTag::String),
    bare("Sub", Reserved, EffectCarrier, InferredCarrier)
        .via(&[
            "TeaCliSub",
            "TeaTerminalSub",
            "TeaTuiSub",
            "TeaWebSub",
            "TeaWorkerSub",
        ])
        .tagged(BuiltinTag::Sub),
    bare("Task", Reserved, EffectCarrier, InferredCarrier).tagged(BuiltinTag::Task),
    bare("TermProfile", Reserved, Opaque, Exact(0)).tagged(BuiltinTag::TermProfile),
    bare("TextSize", Reserved, Opaque, Exact(0)).tagged(BuiltinTag::TextSize),
    bare("TokenSource", Reserved, Opaque, Exact(0)).tagged(BuiltinTag::TokenSource),
    // `Ipe.PubSub`'s phantom topic handle.
    bare("Topic", Reserved, SealedHandle, Exact(1)).tagged(BuiltinTag::Topic),
    bare("TuiAttr", Reserved, Opaque, Exact(1)).tagged(BuiltinTag::TuiAttr),
    bare("TypeInfo", LoweredBelowGuard, Opaque, Exact(0)),
    // `Ipe.Url`'s validated URL: the scheme and SSRF parse boundary.
    bare("Url", Reserved, SecretOrSink, Exact(0)).tagged(BuiltinTag::Url),
    bare("VAlign", Reserved, View, Exact(0)),
    bare("VNode", KernelImplicit, Opaque, Exact(0)),
    bare("Value", KernelImplicit, Opaque, Exact(0))
        .via(&["JsonEnc"])
        .tagged(BuiltinTag::JsonValue),
    // `View engine msg`, the engine-tagged view carrier over the closed `{Web, Tui, Cli}` tag set.
    bare("View", Reserved, View, Exact(2)).tagged(BuiltinTag::View),
    bare("WcagLevel", Reserved, Opaque, Exact(0)).tagged(BuiltinTag::WcagLevel),
    bare("WebReq", Reserved, Opaque, Exact(0))
        .via(&["Web"])
        .tagged(BuiltinTag::WebReq),
    bare("WebRoute", LoweredBelowGuard, Opaque, Exact(1)).tagged(BuiltinTag::WebRoute),
    bare("WebSocketServer", LoweredBelowGuard, Opaque, Exact(0))
        .via(&["Ws"])
        .tagged(BuiltinTag::WsServer),
    bare("WebSocketServerCfg", LoweredBelowGuard, Opaque, Exact(0)).tagged(BuiltinTag::WsServerCfg),
    homed("Html", "Attribute", KernelImplicit, Opaque, Exact(1)).tagged(BuiltinTag::HtmlAttribute),
    homed("Ipe.App", "Terminal", KernelImplicit, Opaque, Exact(0))
        .tagged(BuiltinTag::ShapeTerminal),
    homed("Ipe.App", "Web", KernelImplicit, Opaque, Exact(0)).tagged(BuiltinTag::ShapeWeb),
    homed("Ipe.App", "WebView", KernelImplicit, Opaque, Exact(0)).tagged(BuiltinTag::ShapeWebView),
    homed("Ipe.Codec", "Codec", LoweredBelowGuard, Opaque, Exact(1)).tagged(BuiltinTag::Codec),
    homed("Ipe.Db.Store", "Cond", LoweredBelowGuard, Opaque, Exact(1)).tagged(BuiltinTag::DbCond),
    homed("Ipe.Db.Store", "Draft", LoweredBelowGuard, Opaque, Exact(1)).tagged(BuiltinTag::DbDraft),
    homed(
        "Ipe.Db.Store",
        "Joined",
        LoweredBelowGuard,
        Opaque,
        Exact(2),
    )
    .tagged(BuiltinTag::DbJoined),
    homed("Ipe.Db.Store", "Order", LoweredBelowGuard, Opaque, Exact(0)).tagged(BuiltinTag::DbOrder),
    homed(
        "Ipe.Db.Store",
        "Policy",
        LoweredBelowGuard,
        Opaque,
        Exact(1),
    )
    .tagged(BuiltinTag::DbPolicy),
    homed("Ipe.Db.Store", "Pred", LoweredBelowGuard, Opaque, Exact(1)).tagged(BuiltinTag::DbPred),
    homed(
        "Ipe.Db.Store",
        "Secured",
        LoweredBelowGuard,
        Opaque,
        Exact(1),
    )
    .tagged(BuiltinTag::DbSecured),
    homed(
        "Ipe.Db.Store",
        "Select",
        LoweredBelowGuard,
        Opaque,
        Exact(1),
    )
    .tagged(BuiltinTag::DbSelect),
    homed("Ipe.Db.Store", "Store", LoweredBelowGuard, Opaque, Exact(1)).tagged(BuiltinTag::DbStore),
    homed(
        "Ipe.Duration",
        "Duration",
        LoweredBelowGuard,
        Opaque,
        Exact(0),
    )
    .tagged(BuiltinTag::Duration),
    homed(
        "Ipe.Email",
        "EmailProvider",
        LoweredBelowGuard,
        Opaque,
        Exact(0),
    )
    .tagged(BuiltinTag::EmailProvider),
    homed(
        "Ipe.Http",
        "RedirectPolicy",
        LoweredBelowGuard,
        Opaque,
        Exact(0),
    )
    .tagged(BuiltinTag::RedirectPolicy),
    homed("Ipe.Jwt", "Claims", KernelImplicit, Opaque, Exact(0)).tagged(BuiltinTag::Claims),
    homed("Ipe.Remote", "Remote", LoweredBelowGuard, Opaque, Exact(2)).tagged(BuiltinTag::Remote),
    homed(
        "Ipe.Remote",
        "RemoteAuth",
        LoweredBelowGuard,
        Opaque,
        Exact(0),
    )
    .tagged(BuiltinTag::RemoteAuth),
    homed(
        "Ipe.Task",
        "BackoffStrategy",
        LoweredBelowGuard,
        Opaque,
        Exact(0),
    )
    .tagged(BuiltinTag::BackoffStrategy),
    homed("Ipe.Task", "Step", LoweredBelowGuard, Opaque, Exact(2)).tagged(BuiltinTag::TaskStep),
    homed("Ipe.Tea", "Cli", KernelImplicit, Opaque, Exact(0)).tagged(BuiltinTag::ProgramShapeCli),
    homed("Ipe.Tea", "CliApp", KernelImplicit, Opaque, Exact(0)).tagged(BuiltinTag::CliApp),
    homed("Ipe.Tea", "Tui", KernelImplicit, Opaque, Exact(0)).tagged(BuiltinTag::ProgramShapeTui),
    homed("Ipe.Tea", "TuiApp", KernelImplicit, Opaque, Exact(0)).tagged(BuiltinTag::TuiApp),
    homed("Ipe.Tea", "Web", KernelImplicit, Opaque, Exact(0)).tagged(BuiltinTag::ProgramShapeWeb),
    homed("Ipe.Tea", "WebApp", KernelImplicit, Opaque, Exact(0))
        .via(&["Web"])
        .tagged(BuiltinTag::WebApp),
    homed("Ipe.Tea", "Worker", KernelImplicit, Opaque, Exact(0))
        .tagged(BuiltinTag::ProgramShapeWorker),
    homed("Ipe.Ui", "Color", LoweredBelowGuard, Opaque, Exact(0)).tagged(BuiltinTag::UiColor),
    homed(
        "Ipe.Ui.Input",
        "RadioOption",
        KernelImplicit,
        Opaque,
        Exact(1),
    )
    .tagged(BuiltinTag::InputRadioOption),
];

/// The number of empty-home rows: the prefix [`BuiltinType::of_bare_name`]
/// searches.
const BARE_ROWS: usize = {
    let mut rest = BUILTIN_TYPES;
    let mut count = 0;
    while let Some((row, tail)) = rest.split_first() {
        if matches!(row.home, KernelHome::Builtin) {
            count += 1;
        }
        rest = tail;
    }
    count
};

/// Byte-wise three-way comparison; byte order matches `str`'s `Ord`.
/// `split_first` keeps the walk free of slice indexing in a `const fn`.
const fn bytes_cmp(mut a: &[u8], mut b: &[u8]) -> core::cmp::Ordering {
    use core::cmp::Ordering;
    loop {
        match (a.split_first(), b.split_first()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some((&ha, ta)), Some((&hb, tb))) => {
                if ha < hb {
                    return Ordering::Less;
                }
                if ha > hb {
                    return Ordering::Greater;
                }
                (a, b) = (ta, tb);
            }
        }
    }
}

/// Whether `a` sorts strictly before `b` by `(home, name)`, the empty home
/// first.
const fn head_lt(a: &BuiltinRow, b: &BuiltinRow) -> bool {
    use core::cmp::Ordering;
    let home = match (a.home, b.home) {
        (KernelHome::Builtin, KernelHome::Builtin) => Ordering::Equal,
        (KernelHome::Builtin, KernelHome::Module(_)) => Ordering::Less,
        (KernelHome::Module(_), KernelHome::Builtin) => Ordering::Greater,
        (KernelHome::Module(x), KernelHome::Module(y)) => bytes_cmp(x.as_bytes(), y.as_bytes()),
    };
    match home {
        Ordering::Less => true,
        Ordering::Greater => false,
        Ordering::Equal => {
            matches!(
                bytes_cmp(a.name.as_bytes(), b.name.as_bytes()),
                Ordering::Less
            )
        }
    }
}

/// Whether `rows` is strictly ascending by `(home, name)`: one pass, which
/// makes every name unique within its home and keeps the empty-home rows a
/// sorted prefix.
const fn heads_strictly_ascending(mut rows: &[BuiltinRow]) -> bool {
    while let Some((row, tail)) = rows.split_first() {
        if let Some((next, _)) = tail.split_first()
            && !head_lt(row, next)
        {
            return false;
        }
        rows = tail;
    }
    true
}

/// Whether every [`BuiltinTag`] names exactly one row: one pass over the rows
/// marking each tag, refusing a second mark, then one check that every tag
/// was marked.
#[allow(clippy::indexing_slicing)] // `tag as usize < BuiltinTag::COUNT`: the enum's discriminants are dense from 0
const fn every_tag_names_one_row(mut rows: &[BuiltinRow]) -> bool {
    let mut seen = [false; BuiltinTag::COUNT];
    while let Some((row, tail)) = rows.split_first() {
        if let Some(tag) = row.tag {
            let slot = tag as usize;
            if seen[slot] {
                return false;
            }
            seen[slot] = true;
        }
        rows = tail;
    }
    let mut marks: &[bool] = &seen;
    while let Some((&marked, tail)) = marks.split_first() {
        if !marked {
            return false;
        }
        marks = tail;
    }
    true
}

/// Whether every row's role agrees with the columns that depend on it, in
/// one pass:
/// * a seal class that pins a fixed lowering is reserved — the security-tier
///   handles cannot be shadowed;
/// * a reserved row sits at the empty home, where the name it reserves lives;
/// * a value container has the exact, non-zero arity the seal recurses over.
///
/// A row's [`TypeParams`] needs no reservation: canon counts the arguments of
/// the row a use resolved to, so a user type of the same name is counted by
/// its own declaration.
///
/// A module-home row may carry qualifier spellings: `WebApp` lives at
/// `Ipe.Tea` and is spelled `Web.WebApp`.
const fn roles_partition(mut rows: &[BuiltinRow]) -> bool {
    while let Some((row, tail)) = rows.split_first() {
        let reserved = row.role.forbids_user_declaration();
        let builtin_home = matches!(row.home, KernelHome::Builtin);
        if row.seal.needs_reservation() && !reserved {
            return false;
        }
        if reserved && !builtin_home {
            return false;
        }
        if matches!(row.seal, SealClass::ValueContainer) && !matches!(row.params, Exact(n) if n > 0)
        {
            return false;
        }
        rows = tail;
    }
    true
}

// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if two rows share a head or the table leaves `(home, name)` order, on which `of_bare_name`'s binary search depends [ledger #boundary]
#[allow(clippy::assertions_on_constants)] // the constant IS the tripwire
const _: () = assert!(
    heads_strictly_ascending(BUILTIN_TYPES),
    "BUILTIN_TYPES must be strictly ascending by (home, name)",
);

// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if a `BuiltinTag` names no row or two rows [ledger #boundary]
#[allow(clippy::assertions_on_constants)] // the constant IS the tripwire
const _: () = assert!(
    every_tag_names_one_row(BUILTIN_TYPES),
    "every BuiltinTag must name exactly one BUILTIN_TYPES row",
);

// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if a row lowered by name above the `enum_variants` guard is left user-declarable, the silent-override SEAL break [ledger #boundary]
#[allow(clippy::assertions_on_constants)] // the constant IS the tripwire
const _: () = assert!(
    roles_partition(BUILTIN_TYPES),
    "a BUILTIN_TYPES row's role disagrees with its seal, arity or home",
);

/// The row a kernel scheme names by `tag`; [`every_tag_names_one_row`] makes
/// it unique.
const fn row_of_tag(tag: BuiltinTag) -> Option<&'static BuiltinRow> {
    let mut rows = BUILTIN_TYPES;
    while let Some((row, tail)) = rows.split_first() {
        if let Some(named) = row.tag
            && named as usize == tag as usize
        {
            return Some(row);
        }
        rows = tail;
    }
    None
}

/// Whether every builtin head `shape` applies is applied to the count its
/// row's [`TypeParams`] declares.
const fn shape_fits_params(shape: &TyShape) -> bool {
    match shape {
        TyShape::Fun(arg, res) => shape_fits_params(arg) && shape_fits_params(res),
        TyShape::Con(tag, args) => match row_of_tag(*tag) {
            Some(row) => args.len() == row.params.in_schemes() && shapes_fit_params(args),
            None => false,
        },
        TyShape::Tuple(elems) => shapes_fit_params(elems),
        TyShape::Record { fields, .. } => {
            let mut rest: &[(FieldTag, &TyShape)] = fields;
            while let Some(((_, field), tail)) = rest.split_first() {
                if !shape_fits_params(field) {
                    return false;
                }
                rest = tail;
            }
            true
        }
        TyShape::Var(_) | TyShape::Unit => true,
    }
}

const fn shapes_fit_params(mut shapes: &[TyShape]) -> bool {
    while let Some((shape, tail)) = shapes.split_first() {
        if !shape_fits_params(shape) {
            return false;
        }
        shapes = tail;
    }
    true
}

/// Whether every kernel scheme applies each builtin head to the count its row
/// declares: the table's [`TypeParams`] and the schemes are one fact.
const fn kernel_schemes_fit_params(mut kernels: &[StdlibKernel]) -> bool {
    while let Some((kernel, tail)) = kernels.split_first() {
        if let Some(shape) = kernel.scheme_shape()
            && !shape_fits_params(shape)
        {
            return false;
        }
        kernels = tail;
    }
    true
}

// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if a kernel scheme applies a builtin head to a count its row's `TypeParams` does not declare, so canon's arity gate and the schemes cannot drift [ledger #boundary]
#[allow(clippy::assertions_on_constants)] // the constant IS the tripwire
const _: () = assert!(
    kernel_schemes_fit_params(StdlibKernel::ALL),
    "a kernel scheme applies a builtin head to a count its BUILTIN_TYPES row does not declare",
);

#[cfg(test)]
mod tests {
    use super::TypeParams::{Exact, OptionalMessage};
    use super::{
        BUILTIN_TYPES, BuiltinRole, BuiltinRow, BuiltinTag, BuiltinType, KernelHome, SealClass,
        TyShape, bare, every_tag_names_one_row, heads_strictly_ascending, homed,
        kernel_schemes_fit_params, roles_partition, shape_fits_params,
    };
    use crate::StdlibKernel;

    #[test]
    fn scheme_home_divergence_is_the_listed_set() {
        let diverging: Vec<(KernelHome, &str)> = BUILTIN_TYPES
            .iter()
            .filter(|row| row.tag().is_some_and(|tag| tag.scheme_home() != row.home()))
            .map(|row| (row.home(), row.name()))
            .collect();
        let listed: &[(&str, &str)] = &[
            ("Ipe.App", "Terminal"),
            ("Ipe.App", "Web"),
            ("Ipe.App", "WebView"),
            ("Ipe.Http", "RedirectPolicy"),
            ("Ipe.Jwt", "Claims"),
            ("Ipe.Task", "BackoffStrategy"),
            ("Ipe.Tea", "Cli"),
            ("Ipe.Tea", "CliApp"),
            ("Ipe.Tea", "Tui"),
            ("Ipe.Tea", "TuiApp"),
            ("Ipe.Tea", "Web"),
            ("Ipe.Tea", "WebApp"),
            ("Ipe.Tea", "Worker"),
            ("Ipe.Ui", "Color"),
            ("Ipe.Ui.Input", "RadioOption"),
        ];
        let listed: Vec<(KernelHome, &str)> = listed
            .iter()
            .map(|&(home, name)| (KernelHome::Module(home), name))
            .collect();
        assert_eq!(
            diverging, listed,
            "a row whose home differs from its tag's scheme home must be listed here"
        );
    }

    #[test]
    fn heads_out_of_order_or_doubled_are_refused() {
        assert!(heads_strictly_ascending(BUILTIN_TYPES));
        let int = bare("Int", BuiltinRole::Reserved, SealClass::Plain, Exact(0));
        let bool_row = bare("Bool", BuiltinRole::Reserved, SealClass::Plain, Exact(0));
        let ui_color = homed(
            "Ipe.Ui",
            "Color",
            BuiltinRole::LoweredBelowGuard,
            SealClass::Opaque,
            Exact(0),
        );
        let color = bare(
            "Color",
            BuiltinRole::LoweredBelowGuard,
            SealClass::View,
            Exact(0),
        );
        let ws = bare(
            "WebSocketServer",
            BuiltinRole::LoweredBelowGuard,
            SealClass::Opaque,
            Exact(0),
        );
        let ws_cfg = bare(
            "WebSocketServerCfg",
            BuiltinRole::LoweredBelowGuard,
            SealClass::Opaque,
            Exact(0),
        );
        assert!(
            heads_strictly_ascending(&[color, ui_color]),
            "one name at two homes is two heads"
        );
        assert!(heads_strictly_ascending(&[ws, ws_cfg]));
        for (rows, why) in [
            ([int, int], "a head on two rows"),
            ([int, bool_row], "two names out of byte order"),
            ([ui_color, color], "a module home before the empty home"),
            ([ws_cfg, ws], "a name before its own prefix"),
        ] {
            assert!(!heads_strictly_ascending(&rows), "{why} must be refused");
        }
    }

    #[test]
    fn a_role_disagreeing_with_its_columns_is_refused() {
        assert!(roles_partition(BUILTIN_TYPES));
        assert!(
            roles_partition(&[bare(
                "Color",
                BuiltinRole::LoweredBelowGuard,
                SealClass::View,
                Exact(0),
            )]),
            "a view below the guard stays user-declarable"
        );
        assert!(
            roles_partition(&[homed(
                "Ipe.Tea",
                "WebApp",
                BuiltinRole::KernelImplicit,
                SealClass::Opaque,
                Exact(0),
            )
            .via(&["Web"])]),
            "a module-home row may carry a qualifier spelling"
        );
        for (row, why) in [
            (
                bare(
                    "Secret",
                    BuiltinRole::LoweredBelowGuard,
                    SealClass::SecretOrSink,
                    Exact(0),
                ),
                "a secret seal left user-declarable",
            ),
            (
                bare(
                    "Topic",
                    BuiltinRole::KernelImplicit,
                    SealClass::SealedHandle,
                    Exact(1),
                ),
                "a sealed handle left user-declarable",
            ),
            (
                homed(
                    "Ipe.Secret",
                    "Secret",
                    BuiltinRole::Reserved,
                    SealClass::SecretOrSink,
                    Exact(0),
                ),
                "a reservation away from the empty home",
            ),
            (
                bare(
                    "List",
                    BuiltinRole::Reserved,
                    SealClass::ValueContainer,
                    OptionalMessage,
                ),
                "a value container with no exact arity",
            ),
            (
                bare(
                    "List",
                    BuiltinRole::Reserved,
                    SealClass::ValueContainer,
                    Exact(0),
                ),
                "a value container with nothing to recurse into",
            ),
        ] {
            assert!(!roles_partition(&[row]), "{why} must be refused");
        }
    }

    /// The opaque heads whose lowerer arm sits above the `enum_variants`
    /// guard: a user declaration of one would be silently mis-lowered.
    #[test]
    fn above_guard_handles_are_reserved() {
        for name in [
            "SqlFragment",
            "Secret",
            "Algorithm",
            "Path",
            "Regex",
            "Url",
            "Dsn",
            "DbLocation",
            "Key",
            "Mac",
            "EmailAddress",
            "Locale",
            "Connection",
            "ReadOnly",
            "ReadWrite",
            "Topic",
            "StreamId",
            "ChunkEvent",
            "HttpMethod",
        ] {
            let role = BuiltinType::of_bare_name(name).map(|t| t.row().role());
            assert_eq!(role, Some(BuiltinRole::Reserved), "`{name}`");
        }
    }

    #[test]
    fn every_builtin_tag_has_one_row() {
        assert!(every_tag_names_one_row(BUILTIN_TYPES));
        let first = BUILTIN_TYPES.first().copied();
        assert!(first.is_some_and(|row| row.tag().is_some()));
        let doubled: Vec<BuiltinRow> = BUILTIN_TYPES.iter().copied().chain(first).collect();
        assert!(
            !every_tag_names_one_row(&doubled),
            "a tag on two rows must be refused"
        );
        let missing: Vec<BuiltinRow> = BUILTIN_TYPES
            .iter()
            .copied()
            .filter(|row| row.tag() != Some(BuiltinTag::Int))
            .collect();
        assert!(
            !every_tag_names_one_row(&missing),
            "a tag on no row must be refused"
        );
    }

    #[test]
    fn bare_name_lookup_never_sees_a_module_home() {
        assert!(BuiltinType::of_bare_name("Claims").is_none());
        assert!(BuiltinType::of_bare_name("Draft").is_none());
        let store = BuiltinType::of_bare_name("Store").map(|t| t.row().role());
        assert_eq!(store, Some(BuiltinRole::KernelImplicit));
    }

    #[test]
    fn of_head_matches_the_exact_pair() {
        let db_order = BuiltinType::of_head(&["Ipe", "Db", "Store"], "Order");
        let order = BuiltinType::of_head(&[], "Order");
        assert_eq!(
            db_order.and_then(|t| t.row().tag()),
            Some(BuiltinTag::DbOrder)
        );
        assert_eq!(order.and_then(|t| t.row().tag()), Some(BuiltinTag::Order));
        assert!(BuiltinType::of_head(&["Ipe", "String"], "Order").is_none());
        assert!(BuiltinType::of_head(&["Ipe", "Db"], "Store").is_none());
    }

    #[test]
    fn every_row_is_found_by_its_head() {
        for row in BUILTIN_TYPES {
            let segments: Vec<&str> = match row.home() {
                KernelHome::Builtin => Vec::new(),
                KernelHome::Module(path) => path.split('.').collect(),
            };
            let found = BuiltinType::of_head(&segments, row.name()).map(BuiltinType::row);
            assert_eq!(found, Some(row), "{row:?}");
        }
    }

    #[test]
    fn the_schemes_fit_the_table() {
        assert!(kernel_schemes_fit_params(StdlibKernel::ALL));
    }

    #[test]
    fn a_scheme_head_applied_off_its_params_is_refused() {
        static INT: TyShape = TyShape::Con(BuiltinTag::Int, &[]);
        static VAR: TyShape = TyShape::Var(0);
        static BARE_MAYBE: TyShape = TyShape::Con(BuiltinTag::Maybe, &[]);
        let refused: &[(TyShape, &str)] = &[
            (TyShape::Con(BuiltinTag::List, &[]), "List under its arity"),
            (
                TyShape::Con(BuiltinTag::List, &[TyShape::Var(0), TyShape::Var(1)]),
                "List over its arity",
            ),
            (
                TyShape::Con(BuiltinTag::Int, &[TyShape::Var(0)]),
                "a nullary head applied",
            ),
            (
                TyShape::Con(BuiltinTag::Html, &[]),
                "an optional message the scheme omits",
            ),
            (
                TyShape::Con(BuiltinTag::Cmd, &[TyShape::Var(0), TyShape::Var(1)]),
                "a carrier over one argument",
            ),
            (
                TyShape::Fun(&VAR, &BARE_MAYBE),
                "a mis-arity head under an arrow",
            ),
            (
                TyShape::Con(BuiltinTag::List, &[TyShape::Con(BuiltinTag::Dict, &[])]),
                "a mis-arity head under an argument",
            ),
        ];
        for (shape, why) in refused {
            assert!(!shape_fits_params(shape), "{why}");
        }
        assert!(shape_fits_params(&TyShape::Fun(&INT, &INT)));
        assert!(shape_fits_params(&TyShape::Con(
            BuiltinTag::List,
            &[TyShape::Var(0)]
        )));
    }
}
