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

/// How a builtin head's runtime carrier answers `PartialEq`.
///
/// Every row states it; a row that states nothing is [`HeadEq::Never`], so a
/// head added without a decision refuses `==` rather than emitting a
/// comparison its carrier cannot build. The lowerer's `ir_type_is_derivable`
/// over the head's lowering is the consumer each row is tested against.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HeadEq {
    /// The carrier derives `PartialEq` exactly when every type argument does.
    Structural,
    /// The carrier erases its type arguments and always derives `PartialEq`.
    Erased,
    /// The carrier never implements `PartialEq`, whatever its arguments.
    Never,
    /// The head lowers to an enum whose own definition decides `PartialEq`.
    ByDefinition,
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
    declared_in: Option<&'static str>,
    tag: Option<BuiltinTag>,
    eq: HeadEq,
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

    /// The source module that declares this reserved head as its own type
    /// (`Ipe.Set` for `Set`), as its dotted path.
    ///
    /// That module exports the head whether or not its `exposing` clause lists
    /// it, so `import <module> as Q` spells it `Q.<name>`.
    #[must_use]
    pub const fn declared_in(&self) -> Option<&'static str> {
        self.declared_in
    }

    /// The tag a kernel type scheme names this head by, if any.
    #[must_use]
    pub const fn tag(&self) -> Option<BuiltinTag> {
        self.tag
    }

    /// How the head's runtime carrier answers `PartialEq` ([`HeadEq`]).
    #[must_use]
    pub const fn equality(&self) -> HeadEq {
        self.eq
    }

    const fn via(self, qualifiers: &'static [&'static str]) -> Self {
        Self {
            qualified_via: qualifiers,
            ..self
        }
    }

    const fn declared_in_module(self, module: &'static str) -> Self {
        Self {
            declared_in: Some(module),
            ..self
        }
    }

    const fn tagged(self, tag: BuiltinTag) -> Self {
        Self {
            tag: Some(tag),
            ..self
        }
    }

    const fn compares(self, eq: HeadEq) -> Self {
        Self { eq, ..self }
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

    /// The empty-home builtin named `name`.
    ///
    /// Only name resolution reads a head by its bare name: the unqualified
    /// type-name resolver, the terminal-attribute binding and the re-export
    /// home. Every other identity question goes through [`Self::of_head`].
    #[must_use]
    pub fn of_bare_name(name: &str) -> Option<Self> {
        bare_row(name).map(Self)
    }

    /// The reserved heads the source module at `module` declares as its own.
    ///
    /// `module` is the module's resolved path as segments; a head's
    /// [`BuiltinRow::declared_in`] path must match it exactly.
    pub fn declared_by_module<'a>(module: &'a [&'a str]) -> impl Iterator<Item = Self> + 'a {
        BUILTIN_TYPES
            .iter()
            .filter(move |row| {
                row.declared_in
                    .is_some_and(|path| KernelHome::Module(path).matches(module))
            })
            .map(Self)
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
        declared_in: None,
        tag: None,
        eq: HeadEq::Never,
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
        declared_in: None,
        tag: None,
        eq: HeadEq::Never,
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
    bare("Algorithm", Reserved, SealedHandle, Exact(0))
        .tagged(BuiltinTag::Algorithm)
        .compares(HeadEq::Structural),
    bare("AnsiColor", Reserved, Opaque, Exact(0))
        .tagged(BuiltinTag::AnsiColor)
        .compares(HeadEq::Structural),
    bare("ArithOp", Reserved, Opaque, Exact(0)).compares(HeadEq::ByDefinition),
    bare("Attribute", Reserved, View, OptionalMessage)
        .tagged(BuiltinTag::UiAttribute)
        .compares(HeadEq::Structural),
    // `Ipe.Server`'s authed-route descriptors: `AuthConfig` carries the token-verification `Secret`.
    bare("AuthConfig", Reserved, Opaque, Exact(0))
        .via(&["Server"])
        .tagged(BuiltinTag::AuthConfig)
        .compares(HeadEq::Never),
    // `Ipe.Auth`'s closed token-refusal ADT, the error of `Auth.verifyToken`; its constructors are `Auth.`-qualified.
    bare("AuthError", LoweredBelowGuard, Opaque, Exact(0))
        .via(&["Auth"])
        .tagged(BuiltinTag::AuthError)
        .compares(HeadEq::ByDefinition),
    bare("Bool", Reserved, Plain, Exact(0))
        .tagged(BuiltinTag::Bool)
        .compares(HeadEq::Structural),
    bare("Bytes", Reserved, Plain, Exact(0))
        .declared_in_module("Ipe.Bytes")
        .tagged(BuiltinTag::Bytes)
        .compares(HeadEq::Structural),
    bare("Char", Reserved, Plain, Exact(0))
        .declared_in_module("Ipe.Char")
        .tagged(BuiltinTag::Char)
        .compares(HeadEq::Structural),
    bare("ChunkEvent", Reserved, SealedHandle, Exact(0))
        .via(&["HttpStream"])
        .compares(HeadEq::ByDefinition),
    bare("CliAttr", Reserved, Opaque, Exact(1))
        .tagged(BuiltinTag::CliAttr)
        .compares(HeadEq::Never),
    bare("Cmd", Reserved, EffectCarrier, InferredCarrier)
        .via(&[
            "TeaCliCmd",
            "TeaTerminalCmd",
            "TeaTuiCmd",
            "TeaWebCmd",
            "TeaWorkerCmd",
        ])
        .tagged(BuiltinTag::Cmd)
        .compares(HeadEq::Never),
    // The unified colour value; a program `type Color` wins by its own home.
    bare("Color", LoweredBelowGuard, View, Exact(0))
        .tagged(BuiltinTag::Color)
        .compares(HeadEq::Structural),
    // `Ipe.Color`'s companions, each a fixed `ipe_runtime::color` carrier built only through `Ipe.Color` kernels.
    bare("ColorError", Reserved, Opaque, Exact(0))
        .tagged(BuiltinTag::ColorError)
        .compares(HeadEq::Structural),
    // `Ipe.Db`'s external connection and its phantom access modes: the read-only-by-type write barrier.
    bare("Connection", Reserved, SealedHandle, Exact(1))
        .tagged(BuiltinTag::Connection)
        .compares(HeadEq::Never),
    bare("Cookie", Reserved, Opaque, Exact(0))
        .tagged(BuiltinTag::ServerCookie)
        .compares(HeadEq::Never),
    bare("CsrfMode", Reserved, Opaque, Exact(0))
        .tagged(BuiltinTag::CsrfMode)
        .compares(HeadEq::Structural),
    // The JS-widget boundary `CustomElement down up`: a use resolves only through the arity gate (IPE-N0031) and the plain-value seal (IPE-N0039).
    bare("CustomElement", Reserved, Opaque, Exact(2))
        .declared_in_module("Ipe.Ffi.Js.CustomElement")
        .tagged(BuiltinTag::CustomElement)
        .compares(HeadEq::Never),
    bare("Db", Reserved, Opaque, Exact(0))
        .via(&["Db"])
        .tagged(BuiltinTag::Db)
        .compares(HeadEq::Never),
    // `Ipe.Db`'s closed failure-cause ADT, carried by `ErrorDetails.Database`; its constructors are `Db.`-qualified.
    bare("DbFailure", LoweredBelowGuard, Opaque, Exact(0))
        .via(&["Db"])
        .tagged(BuiltinTag::DbFailure)
        .compares(HeadEq::ByDefinition),
    // `Ipe.Db.Location`'s typed database location: may carry a `Dsn` and its `Secret` password.
    bare("DbLocation", Reserved, SecretOrSink, Exact(0))
        .tagged(BuiltinTag::DbLocation)
        .compares(HeadEq::Structural),
    bare("Decimal", LoweredBelowGuard, Opaque, Exact(0))
        .tagged(BuiltinTag::Decimal)
        .compares(HeadEq::Structural),
    bare("Decoder", Reserved, Opaque, Exact(1))
        .via(&["Db.Decode", "JsonDec"])
        .tagged(BuiltinTag::Decoder)
        .compares(HeadEq::Never),
    bare("Deficiency", Reserved, Opaque, Exact(0))
        .tagged(BuiltinTag::Deficiency)
        .compares(HeadEq::Structural),
    bare("Description", Reserved, View, Exact(0))
        .tagged(BuiltinTag::UiDescription)
        .compares(HeadEq::Structural),
    bare("Dict", Reserved, ValueContainer, Exact(2))
        .declared_in_module("Ipe.Dict")
        .tagged(BuiltinTag::Dict)
        .compares(HeadEq::Structural),
    // `Ipe.Db.Dsn`'s connection descriptor: carries a `Secret` password and a fail-closed TLS posture.
    bare("Dsn", Reserved, SecretOrSink, Exact(0))
        .declared_in_module("Ipe.Db.Dsn")
        .tagged(BuiltinTag::Dsn)
        .compares(HeadEq::Structural),
    bare("Element", Reserved, View, OptionalMessage)
        .tagged(BuiltinTag::UiElement)
        .compares(HeadEq::Structural),
    // `Ipe.Email`'s validated address.
    bare("EmailAddress", Reserved, SecretOrSink, Exact(0))
        .declared_in_module("Ipe.Email")
        .tagged(BuiltinTag::EmailAddress)
        .compares(HeadEq::Structural),
    bare("Error", Reserved, Opaque, Exact(0))
        .declared_in_module("Ipe.Error")
        .tagged(BuiltinTag::Error)
        .compares(HeadEq::Structural),
    bare("ErrorDetails", LoweredBelowGuard, Opaque, Exact(0))
        .tagged(BuiltinTag::ErrorDetails)
        .compares(HeadEq::Structural),
    bare("ErrorInfo", LoweredBelowGuard, Opaque, Exact(0)).compares(HeadEq::Structural),
    bare("ErrorKind", LoweredBelowGuard, Opaque, Exact(0))
        .tagged(BuiltinTag::ErrorKind)
        .compares(HeadEq::Structural),
    bare("Event", Reserved, View, Exact(1)).compares(HeadEq::Never),
    bare("Float", Reserved, Plain, Exact(0))
        .tagged(BuiltinTag::Float)
        .compares(HeadEq::Structural),
    bare("HAlign", Reserved, View, Exact(0)).compares(HeadEq::Structural),
    bare("Handler", KernelImplicit, Opaque, Exact(0))
        .via(&["Server"])
        .compares(HeadEq::Structural),
    // Closed config-tag ADTs, built only through their constructor kernels; `CsrfMode` has no disabling variant.
    bare("HostMode", Reserved, Opaque, Exact(0))
        .tagged(BuiltinTag::HostMode)
        .compares(HeadEq::Structural),
    bare("Html", Reserved, View, OptionalMessage)
        .tagged(BuiltinTag::Html)
        .compares(HeadEq::Structural),
    // `Ipe.Http`'s closed verb ADT, lowered to a fixed enum.
    bare("HttpMethod", Reserved, SealedHandle, Exact(0))
        .via(&["Http"])
        .tagged(BuiltinTag::HttpMethod)
        .compares(HeadEq::Structural),
    bare("HttpRequest", LoweredBelowGuard, Opaque, Exact(0))
        .via(&["Http"])
        .compares(HeadEq::Never),
    bare("Int", Reserved, Plain, Exact(0))
        .tagged(BuiltinTag::Int)
        .compares(HeadEq::Structural),
    // `Ipe.Crypto`'s role-typed key and HMAC output.
    bare("Key", Reserved, SecretOrSink, Exact(0))
        .via(&["Crypto"])
        .tagged(BuiltinTag::CryptoKey)
        .compares(HeadEq::Structural),
    bare("Label", LoweredBelowGuard, Opaque, Exact(1))
        .tagged(BuiltinTag::InputLabel)
        .compares(HeadEq::Structural),
    bare("LayoutContext", Reserved, View, Exact(0)).compares(HeadEq::Structural),
    // The nullary `Ipe.Ui` names; trusted stdlib may define them (`STDLIB_DEFINABLE_UI_TYPES`).
    bare("Length", Reserved, View, Exact(0))
        .tagged(BuiltinTag::UiLength)
        .compares(HeadEq::Structural),
    // `Ipe.Ui.Cli`'s line view `Lines msg` and its line-native attribute.
    bare("Lines", Reserved, Opaque, OptionalMessage)
        .tagged(BuiltinTag::CliLines)
        .compares(HeadEq::Never),
    bare("List", Reserved, ValueContainer, Exact(1))
        .declared_in_module("Ipe.List")
        .tagged(BuiltinTag::List)
        .compares(HeadEq::Structural),
    // `Ipe.Locale`'s BCP-47 handle.
    bare("Locale", Reserved, SecretOrSink, Exact(0))
        .declared_in_module("Ipe.Locale")
        .tagged(BuiltinTag::Locale)
        .compares(HeadEq::Structural),
    bare("Location", Reserved, View, Exact(0)).compares(HeadEq::Structural),
    bare("LogLevel", Reserved, Opaque, Exact(0))
        .tagged(BuiltinTag::LogLevel)
        .compares(HeadEq::Structural),
    bare("Mac", Reserved, SecretOrSink, Exact(0))
        .via(&["Crypto"])
        .tagged(BuiltinTag::CryptoMac)
        .compares(HeadEq::Structural),
    bare("Maybe", Reserved, ValueContainer, Exact(1))
        .declared_in_module("Ipe.Maybe")
        .tagged(BuiltinTag::Maybe)
        .compares(HeadEq::Structural),
    bare("Middleware", KernelImplicit, Opaque, Exact(0)).compares(HeadEq::Structural),
    bare("Migration", LoweredBelowGuard, Opaque, Exact(0))
        .via(&["Db"])
        .compares(HeadEq::Structural),
    // `Basics.Order` names this row through the compiled-source `Ipe.Basics`
    // home, not a kernel qualifier, so the row carries no `via`.
    bare("Order", LoweredBelowGuard, Opaque, Exact(0))
        .tagged(BuiltinTag::Order)
        .compares(HeadEq::Structural),
    bare("PanicInfo", LoweredBelowGuard, Opaque, Exact(0)).compares(HeadEq::Structural),
    // `Ipe.Path`'s validated path: the traversal and NUL refusal boundary.
    bare("Path", Reserved, SecretOrSink, Exact(0))
        .declared_in_module("Ipe.Path")
        .tagged(BuiltinTag::Path)
        .compares(HeadEq::Structural),
    bare("Placeholder", LoweredBelowGuard, Opaque, Exact(1))
        .tagged(BuiltinTag::InputPlaceholder)
        .compares(HeadEq::Structural),
    // `Ipe.Auth`'s authenticated subject: the auth mint is its only origin.
    bare("Principal", Reserved, Opaque, Exact(0))
        .via(&["Auth"])
        .tagged(BuiltinTag::Principal)
        .compares(HeadEq::Structural),
    // `Program shape msg`, the TEA shape carrier every `<Shape>.app` entry returns.
    bare("Program", Reserved, Opaque, Exact(2))
        .tagged(BuiltinTag::Program)
        .compares(HeadEq::Never),
    bare("ProjectionOperand", Reserved, Opaque, Exact(0))
        .tagged(BuiltinTag::ProjectionOperand)
        .compares(HeadEq::ByDefinition),
    // `Ipe.Db.Store`'s projection-descriptor ADTs: a user union of the name would override the synthetic `EnumDef` the lowerer injects.
    bare("ProjectionTerm", Reserved, Opaque, Exact(0))
        .tagged(BuiltinTag::ProjectionTerm)
        .compares(HeadEq::ByDefinition),
    bare("PseudoClass", Reserved, View, Exact(0))
        .tagged(BuiltinTag::UiPseudoClass)
        .compares(HeadEq::Structural),
    bare("ReadOnly", Reserved, SealedHandle, Exact(0))
        .tagged(BuiltinTag::ConnReadOnly)
        .compares(HeadEq::Never),
    bare("ReadWrite", Reserved, SealedHandle, Exact(0))
        .tagged(BuiltinTag::ConnReadWrite)
        .compares(HeadEq::Never),
    // `Ipe.Regex`'s compiled pattern: `Regex.compile`'s typed refusal is its only origin.
    bare("Regex", Reserved, SecretOrSink, Exact(0))
        .declared_in_module("Ipe.Regex")
        .tagged(BuiltinTag::Regex)
        .compares(HeadEq::Never),
    // `Ipe.Url`'s same-origin relative reference: the browser-href SSRF boundary.
    bare("Relative", Reserved, SecretOrSink, Exact(0))
        .declared_in_module("Ipe.Url")
        .tagged(BuiltinTag::UrlRelative)
        .compares(HeadEq::Structural),
    bare("Request", Reserved, Opaque, Exact(0))
        .via(&["Server"])
        .tagged(BuiltinTag::ServerRequest)
        .compares(HeadEq::Never),
    bare("Response", Reserved, Opaque, Exact(0))
        .via(&["Server"])
        .compares(HeadEq::Never),
    bare("Result", Reserved, ValueContainer, Exact(2))
        .declared_in_module("Ipe.Result")
        .tagged(BuiltinTag::Result)
        .compares(HeadEq::Structural),
    bare("RevocationMode", Reserved, Opaque, Exact(0))
        .tagged(BuiltinTag::RevocationMode)
        .compares(HeadEq::Structural),
    bare("Route", Reserved, Opaque, Exact(0))
        .via(&["Server"])
        .tagged(BuiltinTag::ServerRoute)
        .compares(HeadEq::Never),
    // `Ipe.Ui.Tui`'s view `Screen msg`, the cell-grid rendering model.
    bare("Screen", Reserved, Opaque, OptionalMessage)
        .tagged(BuiltinTag::Cells)
        .compares(HeadEq::Structural),
    // `Ipe.Secret`'s sealed secret string, a security-tier type.
    bare("Secret", Reserved, SecretOrSink, Exact(0))
        .via(&["Secret"])
        .tagged(BuiltinTag::Secret)
        .compares(HeadEq::Structural),
    bare("Session", KernelImplicit, Opaque, Exact(0)).compares(HeadEq::Structural),
    // `Ipe.Ffi.Js`'s session-stream address: `Js.openSession` is its only origin.
    bare("SessionHandle", Reserved, Opaque, Exact(0))
        .declared_in_module("Ipe.Ffi.Js")
        .tagged(BuiltinTag::SessionHandle)
        .compares(HeadEq::Structural),
    bare("Set", Reserved, ValueContainer, Exact(1))
        .declared_in_module("Ipe.Set")
        .tagged(BuiltinTag::Set)
        .compares(HeadEq::Structural),
    // `Ipe.App`'s config carrier `Setting shape`: the phantom shape keeps a `Web`-only setting out of another shape.
    bare("Setting", Reserved, Opaque, Exact(1))
        .tagged(BuiltinTag::Setting)
        .compares(HeadEq::Never),
    bare("SqlField", Reserved, SecretOrSink, Exact(0))
        .tagged(BuiltinTag::SqlField)
        .compares(HeadEq::ByDefinition),
    // `Ipe.Db.Sql`'s opaque WHERE fragment, a security-tier sink.
    bare("SqlFragment", Reserved, SecretOrSink, Exact(0))
        .tagged(BuiltinTag::SqlFragment)
        .compares(HeadEq::Structural),
    bare("SqlValue", Reserved, SecretOrSink, Exact(0))
        .tagged(BuiltinTag::SqlValue)
        .compares(HeadEq::ByDefinition),
    bare("Store", KernelImplicit, Opaque, Exact(0)).compares(HeadEq::Structural),
    bare("StreamId", Reserved, SealedHandle, Exact(0))
        .via(&["HttpStream"])
        .tagged(BuiltinTag::StreamId)
        .compares(HeadEq::ByDefinition),
    bare("StreamWriter", LoweredBelowGuard, Opaque, Exact(0))
        .via(&["Stream"])
        .tagged(BuiltinTag::StreamWriter)
        .compares(HeadEq::Never),
    bare("String", Reserved, Plain, Exact(0))
        .declared_in_module("Ipe.String")
        .tagged(BuiltinTag::String)
        .compares(HeadEq::Structural),
    bare("Sub", Reserved, EffectCarrier, InferredCarrier)
        .via(&[
            "TeaCliSub",
            "TeaTerminalSub",
            "TeaTuiSub",
            "TeaWebSub",
            "TeaWorkerSub",
        ])
        .tagged(BuiltinTag::Sub)
        .compares(HeadEq::Never),
    bare("Task", Reserved, EffectCarrier, InferredCarrier)
        .declared_in_module("Ipe.Task")
        .tagged(BuiltinTag::Task)
        .compares(HeadEq::Never),
    bare("TermProfile", Reserved, Opaque, Exact(0))
        .tagged(BuiltinTag::TermProfile)
        .compares(HeadEq::Structural),
    bare("TextSize", Reserved, Opaque, Exact(0))
        .tagged(BuiltinTag::TextSize)
        .compares(HeadEq::Structural),
    bare("TokenSource", Reserved, Opaque, Exact(0))
        .tagged(BuiltinTag::TokenSource)
        .compares(HeadEq::Never),
    // `Ipe.PubSub`'s phantom topic handle.
    bare("Topic", Reserved, SealedHandle, Exact(1))
        .declared_in_module("Ipe.PubSub")
        .tagged(BuiltinTag::Topic)
        .compares(HeadEq::Erased),
    bare("TuiAttr", Reserved, Opaque, Exact(1))
        .tagged(BuiltinTag::TuiAttr)
        .compares(HeadEq::Never),
    bare("TypeInfo", LoweredBelowGuard, Opaque, Exact(0)).compares(HeadEq::Structural),
    // `Ipe.Url`'s validated URL: the scheme and SSRF parse boundary.
    bare("Url", Reserved, SecretOrSink, Exact(0))
        .declared_in_module("Ipe.Url")
        .tagged(BuiltinTag::Url)
        .compares(HeadEq::Structural),
    bare("VAlign", Reserved, View, Exact(0)).compares(HeadEq::Structural),
    bare("VNode", KernelImplicit, Opaque, Exact(0)).compares(HeadEq::Structural),
    bare("Value", KernelImplicit, Opaque, Exact(0))
        .via(&["JsonEnc"])
        .tagged(BuiltinTag::JsonValue)
        .compares(HeadEq::Structural),
    // `View engine msg`, the engine-tagged view carrier over the closed `{Web, Tui, Cli}` tag set.
    bare("View", Reserved, View, Exact(2))
        .tagged(BuiltinTag::View)
        .compares(HeadEq::Structural),
    bare("WcagLevel", Reserved, Opaque, Exact(0))
        .tagged(BuiltinTag::WcagLevel)
        .compares(HeadEq::Structural),
    bare("WebReq", Reserved, Opaque, Exact(0))
        .via(&["Web"])
        .tagged(BuiltinTag::WebReq)
        .compares(HeadEq::Never),
    bare("WebRoute", LoweredBelowGuard, Opaque, Exact(1))
        .tagged(BuiltinTag::WebRoute)
        .compares(HeadEq::Never),
    bare("WebSocketServer", LoweredBelowGuard, Opaque, Exact(0))
        .via(&["Ws"])
        .tagged(BuiltinTag::WsServer)
        .compares(HeadEq::Never),
    bare("WebSocketServerCfg", LoweredBelowGuard, Opaque, Exact(0))
        .tagged(BuiltinTag::WsServerCfg)
        .compares(HeadEq::Never),
    homed("Html", "Attribute", KernelImplicit, Opaque, Exact(1))
        .tagged(BuiltinTag::HtmlAttribute)
        .compares(HeadEq::Never),
    homed("Ipe.App", "Terminal", KernelImplicit, Opaque, Exact(0))
        .tagged(BuiltinTag::ShapeTerminal)
        .compares(HeadEq::Never),
    homed("Ipe.App", "Web", KernelImplicit, Opaque, Exact(0))
        .tagged(BuiltinTag::ShapeWeb)
        .compares(HeadEq::Never),
    homed("Ipe.App", "WebView", KernelImplicit, Opaque, Exact(0))
        .tagged(BuiltinTag::ShapeWebView)
        .compares(HeadEq::Never),
    homed("Ipe.Codec", "Codec", LoweredBelowGuard, Opaque, Exact(1))
        .tagged(BuiltinTag::Codec)
        .compares(HeadEq::ByDefinition),
    homed("Ipe.Db.Store", "Cond", LoweredBelowGuard, Opaque, Exact(1))
        .tagged(BuiltinTag::DbCond)
        .compares(HeadEq::ByDefinition),
    homed("Ipe.Db.Store", "Draft", LoweredBelowGuard, Opaque, Exact(1))
        .tagged(BuiltinTag::DbDraft)
        .compares(HeadEq::ByDefinition),
    homed(
        "Ipe.Db.Store",
        "Joined",
        LoweredBelowGuard,
        Opaque,
        Exact(2),
    )
    .tagged(BuiltinTag::DbJoined)
    .compares(HeadEq::ByDefinition),
    homed("Ipe.Db.Store", "Order", LoweredBelowGuard, Opaque, Exact(0))
        .tagged(BuiltinTag::DbOrder)
        .compares(HeadEq::ByDefinition),
    homed(
        "Ipe.Db.Store",
        "Policy",
        LoweredBelowGuard,
        Opaque,
        Exact(1),
    )
    .tagged(BuiltinTag::DbPolicy)
    .compares(HeadEq::ByDefinition),
    homed("Ipe.Db.Store", "Pred", LoweredBelowGuard, Opaque, Exact(1))
        .tagged(BuiltinTag::DbPred)
        .compares(HeadEq::ByDefinition),
    homed(
        "Ipe.Db.Store",
        "Secured",
        LoweredBelowGuard,
        Opaque,
        Exact(1),
    )
    .tagged(BuiltinTag::DbSecured)
    .compares(HeadEq::ByDefinition),
    homed(
        "Ipe.Db.Store",
        "Select",
        LoweredBelowGuard,
        Opaque,
        Exact(1),
    )
    .tagged(BuiltinTag::DbSelect)
    .compares(HeadEq::ByDefinition),
    homed("Ipe.Db.Store", "Store", LoweredBelowGuard, Opaque, Exact(1))
        .tagged(BuiltinTag::DbStore)
        .compares(HeadEq::ByDefinition),
    homed(
        "Ipe.Duration",
        "Duration",
        LoweredBelowGuard,
        Opaque,
        Exact(0),
    )
    .tagged(BuiltinTag::Duration)
    .compares(HeadEq::ByDefinition),
    homed(
        "Ipe.Email",
        "EmailProvider",
        LoweredBelowGuard,
        Opaque,
        Exact(0),
    )
    .tagged(BuiltinTag::EmailProvider)
    .compares(HeadEq::Never),
    homed(
        "Ipe.Http",
        "RedirectPolicy",
        LoweredBelowGuard,
        Opaque,
        Exact(0),
    )
    .tagged(BuiltinTag::RedirectPolicy)
    .compares(HeadEq::Never),
    homed("Ipe.Jwt", "Claims", KernelImplicit, Opaque, Exact(0))
        .tagged(BuiltinTag::Claims)
        .compares(HeadEq::Structural),
    homed("Ipe.Remote", "Remote", LoweredBelowGuard, Opaque, Exact(2))
        .tagged(BuiltinTag::Remote)
        .compares(HeadEq::Never),
    homed(
        "Ipe.Remote",
        "RemoteAuth",
        LoweredBelowGuard,
        Opaque,
        Exact(0),
    )
    .tagged(BuiltinTag::RemoteAuth)
    .compares(HeadEq::Never),
    homed(
        "Ipe.Task",
        "BackoffStrategy",
        LoweredBelowGuard,
        Opaque,
        Exact(0),
    )
    .tagged(BuiltinTag::BackoffStrategy)
    .compares(HeadEq::Structural),
    homed("Ipe.Task", "Step", LoweredBelowGuard, Opaque, Exact(2))
        .tagged(BuiltinTag::TaskStep)
        .compares(HeadEq::ByDefinition),
    homed("Ipe.Tea", "Cli", KernelImplicit, Opaque, Exact(0))
        .tagged(BuiltinTag::ProgramShapeCli)
        .compares(HeadEq::Never),
    homed("Ipe.Tea", "CliApp", KernelImplicit, Opaque, Exact(0))
        .tagged(BuiltinTag::CliApp)
        .compares(HeadEq::Never),
    homed("Ipe.Tea", "Tui", KernelImplicit, Opaque, Exact(0))
        .tagged(BuiltinTag::ProgramShapeTui)
        .compares(HeadEq::Never),
    homed("Ipe.Tea", "TuiApp", KernelImplicit, Opaque, Exact(0))
        .tagged(BuiltinTag::TuiApp)
        .compares(HeadEq::Never),
    homed("Ipe.Tea", "Web", KernelImplicit, Opaque, Exact(0))
        .tagged(BuiltinTag::ProgramShapeWeb)
        .compares(HeadEq::Never),
    homed("Ipe.Tea", "WebApp", KernelImplicit, Opaque, Exact(0))
        .via(&["Web"])
        .tagged(BuiltinTag::WebApp)
        .compares(HeadEq::Never),
    homed("Ipe.Tea", "Worker", KernelImplicit, Opaque, Exact(0))
        .tagged(BuiltinTag::ProgramShapeWorker)
        .compares(HeadEq::Never),
    homed("Ipe.Ui", "Color", LoweredBelowGuard, Opaque, Exact(0))
        .tagged(BuiltinTag::UiColor)
        .compares(HeadEq::Structural),
    homed(
        "Ipe.Ui.Input",
        "RadioOption",
        KernelImplicit,
        Opaque,
        Exact(1),
    )
    .tagged(BuiltinTag::InputRadioOption)
    .compares(HeadEq::Structural),
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
/// * a value container has the exact, non-zero arity the seal recurses over;
/// * only a reserved row names a declaring module: the module export it
///   creates is a row binding, which a non-reserved name never needs.
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
        if row.declared_in.is_some() && !reserved {
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

/// Whether every effect carrier and application handle refuses `PartialEq`.
///
/// A boxed future, a boxed callback and an application's callbacks have no
/// equality, whatever a row's [`HeadEq`] claims.
const fn effects_and_apps_never_equal(mut rows: &[BuiltinRow]) -> bool {
    while let Some((row, tail)) = rows.split_first() {
        let carrier = matches!(row.seal, SealClass::EffectCarrier)
            || matches!(
                row.tag,
                Some(BuiltinTag::CliApp | BuiltinTag::TuiApp | BuiltinTag::WebApp)
            );
        if carrier && !matches!(row.eq, HeadEq::Never) {
            return false;
        }
        rows = tail;
    }
    true
}

// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if an effect carrier or application handle row claims `PartialEq` [ledger #boundary]
#[allow(clippy::assertions_on_constants)] // the constant IS the tripwire
const _: () = assert!(
    effects_and_apps_never_equal(BUILTIN_TYPES),
    "an effect carrier or application handle BUILTIN_TYPES row must be HeadEq::Never",
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
    use super::TypeParams::{Exact, InferredCarrier, OptionalMessage};
    use super::{
        BUILTIN_TYPES, BuiltinRole, BuiltinRow, BuiltinTag, BuiltinType, HeadEq, KernelHome,
        SealClass, TyShape, bare, effects_and_apps_never_equal, every_tag_names_one_row,
        heads_strictly_ascending, homed, kernel_schemes_fit_params, roles_partition,
        shape_fits_params,
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
    fn an_effect_or_app_row_claiming_equality_is_refused() {
        assert!(effects_and_apps_never_equal(BUILTIN_TYPES));
        let task = bare(
            "Task",
            BuiltinRole::Reserved,
            SealClass::EffectCarrier,
            InferredCarrier,
        );
        let web_app = homed(
            "Ipe.Tea",
            "WebApp",
            BuiltinRole::KernelImplicit,
            SealClass::Opaque,
            Exact(0),
        )
        .tagged(BuiltinTag::WebApp);
        assert!(
            effects_and_apps_never_equal(&[task, web_app]),
            "a carrier row stating nothing is `HeadEq::Never`"
        );
        let int = bare("Int", BuiltinRole::Reserved, SealClass::Plain, Exact(0))
            .compares(HeadEq::Structural);
        assert!(effects_and_apps_never_equal(&[int]));
        for eq in [HeadEq::Structural, HeadEq::Erased, HeadEq::ByDefinition] {
            assert!(
                !effects_and_apps_never_equal(&[task.compares(eq)]),
                "an effect carrier claiming {eq:?} must be refused"
            );
            assert!(
                !effects_and_apps_never_equal(&[web_app.compares(eq)]),
                "an application handle claiming {eq:?} must be refused"
            );
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
            (
                bare(
                    "Order",
                    BuiltinRole::LoweredBelowGuard,
                    SealClass::Opaque,
                    Exact(0),
                )
                .declared_in_module("Ipe.Basics"),
                "a declaring module on a user-declarable row",
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
