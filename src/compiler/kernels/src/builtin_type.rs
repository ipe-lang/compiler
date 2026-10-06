//! The one table of builtin type heads.
//!
//! Every fact the compiler keeps about a builtin type constructor — its
//! canonical `(home, name)` head, whether a user may declare its name, how the
//! boundary seal judges it, its fixed type-argument arity, the qualifiers that
//! also spell it, and the [`BuiltinTag`] a kernel scheme names it by — is one
//! row of [`BUILTIN_TYPES`]. Every other site reads the table; the `const`
//! assertions below fail the build the moment a row breaks an invariant.
//!
//! Identity is the `(home, name)` pair: [`BuiltinType::of_head`]. A row at
//! [`KernelHome::Builtin`] is the empty-home builtin an unqualified annotation
//! resolves to; [`BuiltinType::of_bare_name`] is that resolver's lookup and
//! never sees a row with a module home.

use strum::EnumCount as _;

use crate::BuiltinTag;
use BuiltinRole::{KernelImplicit, LoweredBelowGuard, Reserved};
use SealClass::{EffectCarrier, Opaque, Plain, SealedHandle, SecretOrSink, ValueContainer, View};

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

/// One builtin type head and every fact the compiler keeps about it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BuiltinRow {
    name: &'static str,
    home: KernelHome,
    role: BuiltinRole,
    seal: SealClass,
    fixed_arity: Option<u8>,
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

    /// The fixed type-argument count the IPE-N0031 arity gate enforces, or
    /// `None` when the head has no fixed-arity gate in canon.
    #[must_use]
    pub const fn fixed_arity(&self) -> Option<u8> {
        self.fixed_arity
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

    const fn arity(self, n: u8) -> Self {
        Self {
            fixed_arity: Some(n),
            ..self
        }
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

const fn bare(name: &'static str, role: BuiltinRole, seal: SealClass) -> BuiltinRow {
    BuiltinRow {
        name,
        home: KernelHome::Builtin,
        role,
        seal,
        fixed_arity: None,
        qualified_via: &[],
        tag: None,
    }
}

const fn homed(
    path: &'static str,
    name: &'static str,
    role: BuiltinRole,
    seal: SealClass,
) -> BuiltinRow {
    BuiltinRow {
        name,
        home: KernelHome::Module(path),
        role,
        seal,
        fixed_arity: None,
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
    bare("Algorithm", Reserved, SealedHandle).tagged(BuiltinTag::Algorithm),
    bare("AnsiColor", Reserved, Opaque)
        .arity(0)
        .tagged(BuiltinTag::AnsiColor),
    bare("ArithOp", Reserved, Opaque).arity(0),
    bare("Attribute", Reserved, View).tagged(BuiltinTag::UiAttribute),
    // `Ipe.Server`'s authed-route descriptors: `AuthConfig` carries the token-verification `Secret`.
    bare("AuthConfig", Reserved, Opaque).tagged(BuiltinTag::AuthConfig),
    bare("Bool", Reserved, Plain).tagged(BuiltinTag::Bool),
    bare("Bytes", Reserved, Plain).tagged(BuiltinTag::Bytes),
    bare("Cells", Reserved, Opaque),
    bare("Char", Reserved, Plain).tagged(BuiltinTag::Char),
    bare("ChunkEvent", Reserved, SealedHandle),
    bare("CliAttr", Reserved, Opaque).tagged(BuiltinTag::CliAttr),
    bare("Cmd", Reserved, EffectCarrier).tagged(BuiltinTag::Cmd),
    // The unified colour value; a program `type Color` wins by its own home.
    bare("Color", LoweredBelowGuard, View).tagged(BuiltinTag::Color),
    // `Ipe.Color`'s companions, each a fixed `ipe_runtime::color` carrier built only through `Ipe.Color` kernels.
    bare("ColorError", Reserved, Opaque)
        .arity(0)
        .tagged(BuiltinTag::ColorError),
    // `Ipe.Db`'s external connection and its phantom access modes: the read-only-by-type write barrier.
    bare("Connection", Reserved, SealedHandle)
        .arity(1)
        .tagged(BuiltinTag::Connection),
    bare("Cookie", Reserved, Opaque).tagged(BuiltinTag::ServerCookie),
    bare("CsrfMode", Reserved, Opaque)
        .arity(0)
        .tagged(BuiltinTag::CsrfMode),
    // The JS-widget boundary `CustomElement down up`: a use resolves only through the arity gate (IPE-N0031) and the plain-value seal (IPE-N0039).
    bare("CustomElement", Reserved, Opaque).tagged(BuiltinTag::CustomElement),
    bare("Db", Reserved, Opaque).tagged(BuiltinTag::Db),
    bare("Decimal", LoweredBelowGuard, Opaque).tagged(BuiltinTag::Decimal),
    bare("Decoder", Reserved, Opaque).tagged(BuiltinTag::Decoder),
    bare("Deficiency", Reserved, Opaque)
        .arity(0)
        .tagged(BuiltinTag::Deficiency),
    bare("Description", Reserved, View).tagged(BuiltinTag::UiDescription),
    bare("Dict", Reserved, ValueContainer)
        .arity(2)
        .tagged(BuiltinTag::Dict),
    // `Ipe.Db.Dsn`'s connection descriptor: carries a `Secret` password and a fail-closed TLS posture.
    bare("Dsn", Reserved, SecretOrSink).tagged(BuiltinTag::Dsn),
    bare("Element", Reserved, View).tagged(BuiltinTag::UiElement),
    // `Ipe.Email`'s validated address.
    bare("EmailAddress", Reserved, SecretOrSink).tagged(BuiltinTag::EmailAddress),
    bare("Error", Reserved, Opaque).tagged(BuiltinTag::Error),
    bare("ErrorDetails", LoweredBelowGuard, Opaque).tagged(BuiltinTag::ErrorDetails),
    bare("ErrorInfo", LoweredBelowGuard, Opaque),
    bare("ErrorKind", LoweredBelowGuard, Opaque).tagged(BuiltinTag::ErrorKind),
    bare("Event", Reserved, View),
    bare("Float", Reserved, Plain).tagged(BuiltinTag::Float),
    bare("HAlign", Reserved, View),
    bare("Handler", KernelImplicit, Opaque),
    // Closed config-tag ADTs, built only through their constructor kernels; `CsrfMode` has no disabling variant.
    bare("HostMode", Reserved, Opaque)
        .arity(0)
        .tagged(BuiltinTag::HostMode),
    bare("Html", Reserved, View).tagged(BuiltinTag::Html),
    // `Ipe.Http`'s closed verb ADT, lowered to a fixed enum.
    bare("HttpMethod", Reserved, SealedHandle)
        .via(&["Http"])
        .tagged(BuiltinTag::HttpMethod),
    bare("HttpRequest", LoweredBelowGuard, Opaque),
    bare("Int", Reserved, Plain).tagged(BuiltinTag::Int),
    // `Ipe.Crypto`'s role-typed key and HMAC output.
    bare("Key", Reserved, SecretOrSink).tagged(BuiltinTag::CryptoKey),
    bare("Label", LoweredBelowGuard, Opaque).tagged(BuiltinTag::InputLabel),
    bare("LayoutContext", Reserved, View),
    // The nullary `Ipe.Ui` names; trusted stdlib may define them (`STDLIB_DEFINABLE_UI_TYPES`).
    bare("Length", Reserved, View).tagged(BuiltinTag::UiLength),
    // `Ipe.Ui.Cli`'s line view `Lines msg` and its line-native attribute.
    bare("Lines", Reserved, Opaque).tagged(BuiltinTag::CliLines),
    bare("List", Reserved, ValueContainer)
        .arity(1)
        .tagged(BuiltinTag::List),
    // `Ipe.Locale`'s BCP-47 handle.
    bare("Locale", Reserved, SecretOrSink).tagged(BuiltinTag::Locale),
    bare("Location", Reserved, View),
    bare("LogLevel", Reserved, Opaque)
        .arity(0)
        .tagged(BuiltinTag::LogLevel),
    bare("Mac", Reserved, SecretOrSink).tagged(BuiltinTag::CryptoMac),
    bare("Maybe", Reserved, ValueContainer)
        .arity(1)
        .tagged(BuiltinTag::Maybe),
    bare("Middleware", KernelImplicit, Opaque),
    bare("Migration", LoweredBelowGuard, Opaque),
    // `compare : a -> a -> Order` makes `Basics.Order` a spelling of this row.
    bare("Order", LoweredBelowGuard, Opaque)
        .via(&["Basics"])
        .tagged(BuiltinTag::Order),
    bare("PanicInfo", LoweredBelowGuard, Opaque),
    // `Ipe.Path`'s validated path: the traversal and NUL refusal boundary.
    bare("Path", Reserved, SecretOrSink).tagged(BuiltinTag::Path),
    bare("Placeholder", LoweredBelowGuard, Opaque).tagged(BuiltinTag::InputPlaceholder),
    // `Ipe.Auth`'s authenticated subject: the auth mint is its only origin.
    bare("Principal", Reserved, Opaque).tagged(BuiltinTag::Principal),
    // `Program shape msg`, the TEA shape carrier every `<Shape>.app` entry returns.
    bare("Program", Reserved, Opaque)
        .arity(2)
        .tagged(BuiltinTag::Program),
    bare("ProjectionOperand", Reserved, Opaque)
        .arity(0)
        .tagged(BuiltinTag::ProjectionOperand),
    // `Ipe.Db.Store`'s projection-descriptor ADTs: a user union of the name would override the synthetic `EnumDef` the lowerer injects.
    bare("ProjectionTerm", Reserved, Opaque)
        .arity(0)
        .tagged(BuiltinTag::ProjectionTerm),
    bare("PseudoClass", Reserved, View).tagged(BuiltinTag::UiPseudoClass),
    bare("ReadOnly", Reserved, SealedHandle)
        .arity(0)
        .tagged(BuiltinTag::ConnReadOnly),
    bare("ReadWrite", Reserved, SealedHandle)
        .arity(0)
        .tagged(BuiltinTag::ConnReadWrite),
    // `Ipe.Regex`'s compiled pattern: `Regex.compile`'s typed refusal is its only origin.
    bare("Regex", Reserved, SecretOrSink).tagged(BuiltinTag::Regex),
    // `Ipe.Url`'s same-origin relative reference: the browser-href SSRF boundary.
    bare("Relative", Reserved, SecretOrSink).tagged(BuiltinTag::UrlRelative),
    bare("Request", Reserved, Opaque).tagged(BuiltinTag::ServerRequest),
    bare("Response", Reserved, Opaque),
    bare("Result", Reserved, ValueContainer)
        .arity(2)
        .tagged(BuiltinTag::Result),
    bare("RevocationMode", Reserved, Opaque)
        .arity(0)
        .tagged(BuiltinTag::RevocationMode),
    bare("Route", Reserved, Opaque).tagged(BuiltinTag::ServerRoute),
    // `Ipe.Ui.Tui`'s view `Screen msg`; `Cells` is its rendering-model spelling.
    bare("Screen", Reserved, Opaque).tagged(BuiltinTag::Cells),
    // `Ipe.Secret`'s sealed secret string, a security-tier type.
    bare("Secret", Reserved, SecretOrSink).tagged(BuiltinTag::Secret),
    bare("Session", KernelImplicit, Opaque),
    // `Ipe.Ffi.Js`'s session-stream address: `Js.openSession` is its only origin.
    bare("SessionHandle", Reserved, Opaque).tagged(BuiltinTag::SessionHandle),
    bare("Set", Reserved, ValueContainer)
        .arity(1)
        .tagged(BuiltinTag::Set),
    // `Ipe.App`'s config carrier `Setting shape`: the phantom shape keeps a `Web`-only setting out of another shape.
    bare("Setting", Reserved, Opaque)
        .arity(1)
        .tagged(BuiltinTag::Setting),
    bare("SqlField", Reserved, SecretOrSink).tagged(BuiltinTag::SqlField),
    // `Ipe.Db.Sql`'s opaque WHERE fragment, a security-tier sink.
    bare("SqlFragment", Reserved, SecretOrSink).tagged(BuiltinTag::SqlFragment),
    bare("SqlValue", Reserved, SecretOrSink).tagged(BuiltinTag::SqlValue),
    bare("Store", KernelImplicit, Opaque),
    bare("StreamId", Reserved, SealedHandle).tagged(BuiltinTag::StreamId),
    bare("StreamWriter", LoweredBelowGuard, Opaque).tagged(BuiltinTag::StreamWriter),
    bare("String", Reserved, Plain).tagged(BuiltinTag::String),
    bare("Sub", Reserved, EffectCarrier).tagged(BuiltinTag::Sub),
    bare("Task", Reserved, EffectCarrier).tagged(BuiltinTag::Task),
    bare("TermProfile", Reserved, Opaque)
        .arity(0)
        .tagged(BuiltinTag::TermProfile),
    bare("TextSize", Reserved, Opaque)
        .arity(0)
        .tagged(BuiltinTag::TextSize),
    bare("TokenSource", Reserved, Opaque).tagged(BuiltinTag::TokenSource),
    // `Ipe.PubSub`'s phantom topic handle.
    bare("Topic", Reserved, SealedHandle).tagged(BuiltinTag::Topic),
    bare("TuiAttr", Reserved, Opaque).tagged(BuiltinTag::TuiAttr),
    bare("TypeInfo", LoweredBelowGuard, Opaque),
    // `Ipe.Url`'s validated URL: the scheme and SSRF parse boundary.
    bare("Url", Reserved, SecretOrSink).tagged(BuiltinTag::Url),
    bare("VAlign", Reserved, View),
    bare("VNode", KernelImplicit, Opaque),
    bare("Value", KernelImplicit, Opaque).tagged(BuiltinTag::JsonValue),
    // `View engine msg`, the engine-tagged view carrier over the closed `{Web, Tui, Cli}` tag set.
    bare("View", Reserved, View)
        .arity(2)
        .tagged(BuiltinTag::View),
    bare("WcagLevel", Reserved, Opaque)
        .arity(0)
        .tagged(BuiltinTag::WcagLevel),
    bare("WebReq", Reserved, Opaque).tagged(BuiltinTag::WebReq),
    bare("WebRoute", LoweredBelowGuard, Opaque).tagged(BuiltinTag::WebRoute),
    bare("WebSocketServer", LoweredBelowGuard, Opaque).tagged(BuiltinTag::WsServer),
    bare("WebSocketServerCfg", LoweredBelowGuard, Opaque).tagged(BuiltinTag::WsServerCfg),
    homed("Html", "Attribute", KernelImplicit, Opaque).tagged(BuiltinTag::HtmlAttribute),
    homed("Ipe.App", "Terminal", KernelImplicit, Opaque).tagged(BuiltinTag::ShapeTerminal),
    homed("Ipe.App", "Web", KernelImplicit, Opaque).tagged(BuiltinTag::ShapeWeb),
    homed("Ipe.App", "WebView", KernelImplicit, Opaque).tagged(BuiltinTag::ShapeWebView),
    homed("Ipe.Codec", "Codec", LoweredBelowGuard, Opaque).tagged(BuiltinTag::Codec),
    homed("Ipe.Db.Store", "Cond", LoweredBelowGuard, Opaque).tagged(BuiltinTag::DbCond),
    homed("Ipe.Db.Store", "Draft", LoweredBelowGuard, Opaque).tagged(BuiltinTag::DbDraft),
    homed("Ipe.Db.Store", "Joined", LoweredBelowGuard, Opaque).tagged(BuiltinTag::DbJoined),
    homed("Ipe.Db.Store", "Order", LoweredBelowGuard, Opaque).tagged(BuiltinTag::DbOrder),
    homed("Ipe.Db.Store", "Policy", LoweredBelowGuard, Opaque).tagged(BuiltinTag::DbPolicy),
    homed("Ipe.Db.Store", "Pred", LoweredBelowGuard, Opaque).tagged(BuiltinTag::DbPred),
    homed("Ipe.Db.Store", "Secured", LoweredBelowGuard, Opaque).tagged(BuiltinTag::DbSecured),
    homed("Ipe.Db.Store", "Select", LoweredBelowGuard, Opaque).tagged(BuiltinTag::DbSelect),
    homed("Ipe.Db.Store", "Store", LoweredBelowGuard, Opaque).tagged(BuiltinTag::DbStore),
    homed("Ipe.Duration", "Duration", LoweredBelowGuard, Opaque).tagged(BuiltinTag::Duration),
    homed("Ipe.Email", "EmailProvider", LoweredBelowGuard, Opaque)
        .tagged(BuiltinTag::EmailProvider),
    homed("Ipe.Http", "RedirectPolicy", LoweredBelowGuard, Opaque)
        .tagged(BuiltinTag::RedirectPolicy),
    homed("Ipe.Jwt", "Claims", KernelImplicit, Opaque).tagged(BuiltinTag::Claims),
    homed("Ipe.Task", "BackoffStrategy", LoweredBelowGuard, Opaque)
        .tagged(BuiltinTag::BackoffStrategy),
    homed("Ipe.Task", "Step", LoweredBelowGuard, Opaque).tagged(BuiltinTag::TaskStep),
    homed("Ipe.Tea", "Cli", KernelImplicit, Opaque).tagged(BuiltinTag::ProgramShapeCli),
    homed("Ipe.Tea", "CliApp", KernelImplicit, Opaque).tagged(BuiltinTag::CliApp),
    homed("Ipe.Tea", "Tui", KernelImplicit, Opaque).tagged(BuiltinTag::ProgramShapeTui),
    homed("Ipe.Tea", "TuiApp", KernelImplicit, Opaque).tagged(BuiltinTag::TuiApp),
    homed("Ipe.Tea", "Web", KernelImplicit, Opaque).tagged(BuiltinTag::ProgramShapeWeb),
    homed("Ipe.Tea", "WebApp", KernelImplicit, Opaque).tagged(BuiltinTag::WebApp),
    homed("Ipe.Tea", "Worker", KernelImplicit, Opaque).tagged(BuiltinTag::ProgramShapeWorker),
    homed("Ipe.Ui", "Color", LoweredBelowGuard, Opaque).tagged(BuiltinTag::UiColor),
    homed("Ipe.Ui.Input", "RadioOption", KernelImplicit, Opaque)
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
/// * a seal class that pins a fixed lowering, or a fixed arity, is reserved —
///   the security-tier handles and the arity-gated heads cannot be shadowed;
/// * a reserved row sits at the empty home, where the name it reserves lives;
/// * a value container has the arity the seal recurses over;
/// * only an empty-home row carries qualifier spellings.
const fn roles_partition(mut rows: &[BuiltinRow]) -> bool {
    while let Some((row, tail)) = rows.split_first() {
        let reserved = row.role.forbids_user_declaration();
        let builtin_home = matches!(row.home, KernelHome::Builtin);
        if (row.seal.needs_reservation() || row.fixed_arity.is_some()) && !reserved {
            return false;
        }
        if reserved && !builtin_home {
            return false;
        }
        if matches!(row.seal, SealClass::ValueContainer) && row.fixed_arity.is_none() {
            return false;
        }
        if !row.qualified_via.is_empty() && !builtin_home {
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
    "a BUILTIN_TYPES row's role disagrees with its seal, arity, home or qualifiers",
);

#[cfg(test)]
mod tests {
    use super::{
        BUILTIN_TYPES, BuiltinRole, BuiltinRow, BuiltinTag, BuiltinType, KernelHome,
        every_tag_names_one_row,
    };

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
}
