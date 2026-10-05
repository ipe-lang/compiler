//! How a lowered type becomes text: every [`IrType`] leaf has exactly one
//! [`ShowPolicy`], declared once in [`SHOWN_LEAVES`].
//!
//! [`SHOWN_LEAVES`] lists the leaves in the runtime's `SHOWN_RUNTIME_TYPES`
//! order, and `ipe-cli` asserts the two tables equal at build time, so a leaf
//! the compiler can show is a leaf the runtime renders. [`IrType::show_shape`]
//! is an exhaustive match over every variant: a new variant fails to compile
//! until it names its leaf or its children.

use ipe_intern::{Interner, Symbol};

use crate::enum_facts::RuntimeBridgedEnum;
use crate::held::{EnumPayloadTable, ir_type_holds};
use crate::ir::{IrType, ModPath, UiCtor, UiPlain};

/// How a lowered type leaf becomes text. The tags equal the runtime's.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ShowPolicy {
    /// The value itself.
    Value,
    /// A fixed marker that never carries the value's content.
    Redacted,
    /// A `<Module.Type>` marker for opaque runtime machinery.
    Internals,
    /// No rendering: the compiler refuses to show the leaf.
    Refused,
}

impl ShowPolicy {
    /// The policy as a number, comparable in a `const` context.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Value => 0,
            Self::Redacted => 1,
            Self::Internals => 2,
            Self::Refused => 3,
        }
    }
}

/// One row of [`SHOWN_LEAVES`]: a leaf's name and its policy.
///
/// Its fields are private, so the only values are the generated
/// [`show_leaf`] constants.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ShowLeaf {
    name: &'static str,
    policy: ShowPolicy,
}

impl ShowLeaf {
    /// The leaf's name, as the runtime table spells it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        self.name
    }

    /// The leaf's show policy.
    #[must_use]
    pub const fn policy(self) -> ShowPolicy {
        self.policy
    }
}

macro_rules! show_leaves {
    ($($id:ident = $name:literal => $policy:ident;)*) => {
        /// Every show leaf, one constant each.
        pub mod show_leaf {
            use super::{ShowLeaf, ShowPolicy};
            $(
                #[doc = concat!("The `", $name, "` leaf.")]
                pub const $id: ShowLeaf = ShowLeaf {
                    name: $name,
                    policy: ShowPolicy::$policy,
                };
            )*
        }

        /// Every show leaf and its policy, in the runtime table's order.
        pub const SHOWN_LEAVES: [(&str, ShowPolicy); [$($name),*].len()] =
            [$(($name, ShowPolicy::$policy)),*];
    };
}

show_leaves! {
    INT = "Int" => Value;
    FLOAT = "Float" => Value;
    BOOL = "Bool" => Value;
    STRING = "String" => Value;
    CHAR = "Char" => Value;
    UNIT = "Unit" => Value;
    ORDER = "Order" => Value;
    BACKOFF_STRATEGY = "BackoffStrategy" => Value;
    HTTP_METHOD = "HttpMethod" => Value;
    REDIRECT_POLICY = "RedirectPolicy" => Value;
    DECIMAL = "Decimal" => Value;
    ERROR_KIND = "ErrorKind" => Value;
    ERROR = "Error" => Value;
    ERROR_DETAILS = "ErrorDetails" => Value;
    ERROR_INFO = "ErrorInfo" => Value;
    PANIC_INFO = "PanicInfo" => Value;
    TYPE_INFO = "TypeInfo" => Value;
    PATH = "Path" => Value;
    URL_RELATIVE = "UrlRelative" => Value;
    LOCALE = "Locale" => Value;
    EMAIL_ADDRESS = "EmailAddress" => Value;
    CRYPTO_MAC = "CryptoMac" => Value;
    COLOR = "Color" => Value;
    COLOR_ERROR = "ColorError" => Value;
    WCAG_LEVEL = "WcagLevel" => Value;
    TEXT_SIZE = "TextSize" => Value;
    DEFICIENCY = "Deficiency" => Value;
    CSV_DOC = "CsvDoc" => Value;
    CACHE_STATS = "CacheStats" => Value;
    STREAM_ID = "StreamId" => Value;
    JSON = "Json" => Value;
    BYTES = "Bytes" => Redacted;
    URL = "Url" => Redacted;
    SECRET = "Secret" => Redacted;
    CRYPTO_KEY = "CryptoKey" => Redacted;
    PRINCIPAL = "Principal" => Redacted;
    DSN = "Dsn" => Redacted;
    SQL_FRAGMENT = "SqlFragment" => Redacted;
    SERVER_REQUEST = "ServerRequest" => Redacted;
    SERVER_RESPONSE = "ServerResponse" => Redacted;
    SERVER_COOKIE = "ServerCookie" => Redacted;
    WEB_REQ = "WebReq" => Redacted;
    HTTP_REQUEST = "HttpRequest" => Redacted;
    AUTH_CONFIG = "AuthConfig" => Redacted;
    TOKEN_SOURCE = "TokenSource" => Redacted;
    WEB_SOCKET_CLIENT_CFG = "WebSocketClientCfg" => Redacted;
    PROCESS_RUN_WITH_CFG = "ProcessRunWithCfg" => Redacted;
    PROCESS_RUN_IN_PTY_CFG = "ProcessRunInPtyCfg" => Redacted;
    CACHE_CFG = "CacheCfg" => Redacted;
    REGEX = "Regex" => Redacted;
    EMAIL_MESSAGE = "EmailMessage" => Redacted;
    EMAIL_ATTACHMENT = "EmailAttachment" => Redacted;
    EMAIL_SES_CONFIG = "EmailSesConfig" => Redacted;
    EMAIL_SMTP_CONFIG = "EmailSmtpConfig" => Redacted;
    TASK = "Task" => Internals;
    CMD = "Cmd" => Internals;
    SUB = "Sub" => Internals;
    DECODER = "Decoder" => Internals;
    DB = "Db" => Internals;
    CONNECTION = "Connection" => Internals;
    SETTING = "Setting" => Internals;
    STREAM_WRITER = "StreamWriter" => Internals;
    SERVER_ROUTE = "ServerRoute" => Internals;
    WEB_SOCKET_SERVER = "WebSocketServer" => Internals;
    WEB_SOCKET_SERVER_CFG = "WebSocketServerCfg" => Internals;
    WEB_APP = "WebApp" => Internals;
    TUI_APP = "TuiApp" => Internals;
    CLI_APP = "CliApp" => Internals;
    WORKER_APP = "WorkerApp" => Internals;
    WEB_ROUTE = "WebRoute" => Internals;
    CUSTOM_ELEMENT = "CustomElement" => Internals;
    CACHE_HANDLE = "CacheHandle" => Internals;
    CHUNK_EVENT = "ChunkEvent" => Internals;
    EMAIL_PROVIDER = "EmailProvider" => Internals;
    TERM_PROFILE = "TermProfile" => Internals;
    ANSI_COLOR = "AnsiColor" => Internals;
    HTML = "Html" => Internals;
    ELEMENT = "Element" => Internals;
    CELLS = "Cells" => Internals;
    UI_ATTRIBUTE = "UiAttribute" => Internals;
    TUI_ATTRIBUTE = "TuiAttribute" => Internals;
    CLI_LINES = "CliLines" => Internals;
    CLI_ATTRIBUTE = "CliAttribute" => Internals;
    HTML_ATTRIBUTE = "HtmlAttribute" => Internals;
    HTML_EVENT = "HtmlEvent" => Internals;
    LABEL = "Label" => Internals;
    PLACEHOLDER = "Placeholder" => Internals;
    RADIO_OPTION = "RadioOption" => Internals;
    LENGTH = "Length" => Internals;
    H_ALIGN = "HAlign" => Internals;
    V_ALIGN = "VAlign" => Internals;
    LOCATION = "Location" => Internals;
    PSEUDO_CLASS = "PseudoClass" => Internals;
    DESCRIPTION = "Description" => Internals;
    LAYOUT_CONTEXT = "LayoutContext" => Internals;
    FUN = "Fun" => Refused;
    SHARED_FUN = "SharedFun" => Refused;
    FN_ONCE_CHAIN = "FnOnceChain" => Refused;
    FOREIGN = "Foreign" => Refused;
}

/// The widest tuple the runtime renders.
pub const MAX_SHOWN_TUPLE_ARITY: usize = 12;

/// How [`IrType::show_shape`] classifies one type.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ShowShape<'a> {
    /// A leaf with its own runtime row.
    Leaf(ShowLeaf),
    /// A structural carrier: shown exactly when every child is.
    Carrier(Vec<&'a IrType>),
    /// A type parameter: the emitted impl bounds it `IpeStringify`.
    Param,
    /// A named enum, classified by [`named_enum_shape`].
    Named {
        /// The enum's home module.
        home: &'a ModPath,
        /// The enum's name.
        name: Symbol,
        /// The enum's type arguments.
        args: &'a [IrType],
    },
    /// A tuple wider than [`MAX_SHOWN_TUPLE_ARITY`]: no runtime impl.
    TooWide,
}

impl IrType {
    /// The show leaf or the children of `self`.
    #[must_use]
    pub fn show_shape(&self) -> ShowShape<'_> {
        use show_leaf as l;
        let leaf = ShowShape::Leaf;
        match self {
            Self::Int | Self::SessionHandle => leaf(l::INT),
            Self::Float => leaf(l::FLOAT),
            Self::Bool => leaf(l::BOOL),
            Self::Str => leaf(l::STRING),
            Self::Char => leaf(l::CHAR),
            Self::Unit => leaf(l::UNIT),
            Self::Task(_) => leaf(l::TASK),
            Self::Enum { home, name, args } => ShowShape::Named {
                home,
                name: *name,
                args,
            },
            Self::Maybe(e) | Self::List(e) | Self::Set(e) => ShowShape::Carrier(vec![e]),
            Self::Result(a, b) | Self::Dict(a, b) => ShowShape::Carrier(vec![a, b]),
            Self::Tuple(es) if es.len() > MAX_SHOWN_TUPLE_ARITY => ShowShape::TooWide,
            Self::Tuple(es) => ShowShape::Carrier(es.iter().collect()),
            Self::Record(fields) => ShowShape::Carrier(fields.values().collect()),
            Self::Fun(_, _) => leaf(l::FUN),
            Self::SharedFun(_, _) => leaf(l::SHARED_FUN),
            Self::FnOnceChain(_, _) => leaf(l::FN_ONCE_CHAIN),
            Self::Generic(_) | Self::RowGeneric(_) => ShowShape::Param,
            Self::Bytes => leaf(l::BYTES),
            Self::Json => leaf(l::JSON),
            Self::Decoder(_) => leaf(l::DECODER),
            Self::Db => leaf(l::DB),
            Self::Cmd(_) => leaf(l::CMD),
            Self::Sub(_) => leaf(l::SUB),
            Self::ServerRequest => leaf(l::SERVER_REQUEST),
            Self::ServerResponse => leaf(l::SERVER_RESPONSE),
            Self::ServerRoute => leaf(l::SERVER_ROUTE),
            Self::ServerCookie => leaf(l::SERVER_COOKIE),
            Self::StreamWriter => leaf(l::STREAM_WRITER),
            Self::HttpRequest => leaf(l::HTTP_REQUEST),
            Self::WebSocketServer => leaf(l::WEB_SOCKET_SERVER),
            Self::WebSocketServerCfg => leaf(l::WEB_SOCKET_SERVER_CFG),
            Self::Ui { ctor, .. } => leaf(ui_ctor_leaf(*ctor)),
            Self::UiPlain(plain) => leaf(ui_plain_leaf(*plain)),
            Self::WebReq => leaf(l::WEB_REQ),
            Self::WebRoute(_) => leaf(l::WEB_ROUTE),
            Self::CustomElement { .. } => leaf(l::CUSTOM_ELEMENT),
            Self::Order => leaf(l::ORDER),
            Self::BackoffStrategy => leaf(l::BACKOFF_STRATEGY),
            Self::HttpMethod => leaf(l::HTTP_METHOD),
            Self::Decimal => leaf(l::DECIMAL),
            Self::Principal => leaf(l::PRINCIPAL),
            Self::AuthConfig => leaf(l::AUTH_CONFIG),
            Self::TokenSource => leaf(l::TOKEN_SOURCE),
            Self::ErrorKind => leaf(l::ERROR_KIND),
            Self::Error => leaf(l::ERROR),
            Self::ErrorDetails => leaf(l::ERROR_DETAILS),
            Self::ErrorInfo => leaf(l::ERROR_INFO),
            Self::PanicInfo => leaf(l::PANIC_INFO),
            Self::TypeInfo => leaf(l::TYPE_INFO),
            Self::SqlFragment => leaf(l::SQL_FRAGMENT),
            Self::Secret => leaf(l::SECRET),
            Self::Path => leaf(l::PATH),
            Self::Regex => leaf(l::REGEX),
            Self::ProcessRunWithCfg => leaf(l::PROCESS_RUN_WITH_CFG),
            Self::ProcessRunInPtyCfg => leaf(l::PROCESS_RUN_IN_PTY_CFG),
            Self::CacheCfg => leaf(l::CACHE_CFG),
            Self::CacheStats => leaf(l::CACHE_STATS),
            Self::WebSocketClientCfg => leaf(l::WEB_SOCKET_CLIENT_CFG),
            Self::CsvDoc => leaf(l::CSV_DOC),
            Self::EmailMessage => leaf(l::EMAIL_MESSAGE),
            Self::EmailAttachment => leaf(l::EMAIL_ATTACHMENT),
            Self::EmailSesConfig => leaf(l::EMAIL_SES_CONFIG),
            Self::EmailSmtpConfig => leaf(l::EMAIL_SMTP_CONFIG),
            Self::EmailProvider => leaf(l::EMAIL_PROVIDER),
            Self::CryptoKey => leaf(l::CRYPTO_KEY),
            Self::CryptoMac => leaf(l::CRYPTO_MAC),
            Self::EmailAddress => leaf(l::EMAIL_ADDRESS),
            Self::Url => leaf(l::URL),
            Self::UrlRelative => leaf(l::URL_RELATIVE),
            Self::Dsn => leaf(l::DSN),
            Self::Connection | Self::ConnReadOnly | Self::ConnReadWrite => leaf(l::CONNECTION),
            Self::Setting | Self::ShapeWeb | Self::ShapeWebView | Self::ShapeTerminal => {
                leaf(l::SETTING)
            }
            Self::Locale => leaf(l::LOCALE),
            Self::WebApp => leaf(l::WEB_APP),
            Self::TuiApp => leaf(l::TUI_APP),
            Self::CliApp => leaf(l::CLI_APP),
            Self::WorkerApp => leaf(l::WORKER_APP),
        }
    }
}

/// The leaf of a `Ui` constructor.
const fn ui_ctor_leaf(ctor: UiCtor) -> ShowLeaf {
    use show_leaf as l;
    match ctor {
        UiCtor::Html => l::HTML,
        UiCtor::Element => l::ELEMENT,
        UiCtor::Cells => l::CELLS,
        UiCtor::UiAttribute => l::UI_ATTRIBUTE,
        UiCtor::TuiAttribute => l::TUI_ATTRIBUTE,
        UiCtor::CliLines => l::CLI_LINES,
        UiCtor::CliAttribute => l::CLI_ATTRIBUTE,
        UiCtor::HtmlAttribute => l::HTML_ATTRIBUTE,
        UiCtor::HtmlEvent => l::HTML_EVENT,
        UiCtor::Label => l::LABEL,
        UiCtor::Placeholder => l::PLACEHOLDER,
        UiCtor::RadioOption => l::RADIO_OPTION,
    }
}

/// The leaf of a plain `Ipe.Ui` / `Ipe.Color` type.
const fn ui_plain_leaf(plain: UiPlain) -> ShowLeaf {
    use show_leaf as l;
    match plain {
        UiPlain::Length => l::LENGTH,
        UiPlain::Color => l::COLOR,
        UiPlain::HAlign => l::H_ALIGN,
        UiPlain::VAlign => l::V_ALIGN,
        UiPlain::Location => l::LOCATION,
        UiPlain::PseudoClass => l::PSEUDO_CLASS,
        UiPlain::Description => l::DESCRIPTION,
        UiPlain::LayoutContext => l::LAYOUT_CONTEXT,
        UiPlain::ColorError => l::COLOR_ERROR,
        UiPlain::TermProfile => l::TERM_PROFILE,
        UiPlain::AnsiColor => l::ANSI_COLOR,
        UiPlain::WcagLevel => l::WCAG_LEVEL,
        UiPlain::TextSize => l::TEXT_SIZE,
        UiPlain::Deficiency => l::DEFICIENCY,
    }
}

/// How a named enum is shown.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NamedShow {
    /// A registered enum: its emitted impl renders its arguments and payloads.
    Registered,
    /// A runtime-bridged enum or an opaque handle: one leaf.
    Leaf(ShowLeaf),
}

/// Classify the named enum `(home, name)`.
///
/// A registered enum (one in `payloads`) is shown through its emitted impl. An
/// unregistered one is a runtime-bridged enum's leaf, else an opaque `Rust.*`
/// handle, else unclassified; the last two have no rendering, so both are
/// [`show_leaf::FOREIGN`] (fail closed).
#[must_use]
pub fn named_enum_shape(
    interner: &Interner,
    payloads: &EnumPayloadTable,
    home: &ModPath,
    name: Symbol,
) -> NamedShow {
    if payloads.contains_key(&(home.clone(), name)) {
        return NamedShow::Registered;
    }
    let segs: Option<Vec<&str>> = home.0.iter().map(|s| interner.resolve(*s)).collect();
    let bridged = segs
        .zip(interner.resolve(name))
        .and_then(|(segs, name)| RuntimeBridgedEnum::classify(&segs, name));
    NamedShow::Leaf(bridged.map_or(show_leaf::FOREIGN, RuntimeBridgedEnum::show_leaf))
}

/// Does a value of type `ty` hold a component with no rendering?
///
/// The [`ir_type_holds`] walk with a flat leaf test: a `Refused` leaf, a tuple
/// too wide to render, or an unregistered enum that is not runtime-bridged.
/// The walk's fail-closed depth ceiling answers `true`.
#[must_use]
pub fn ir_type_holds_refused(
    ty: &IrType,
    payloads: &EnumPayloadTable,
    interner: &Interner,
) -> bool {
    ir_type_holds(ty, payloads, &|t: &IrType| match t.show_shape() {
        ShowShape::Leaf(leaf) => leaf.policy() == ShowPolicy::Refused,
        ShowShape::TooWide => true,
        ShowShape::Named { home, name, .. } => {
            match named_enum_shape(interner, payloads, home, name) {
                NamedShow::Registered => false,
                NamedShow::Leaf(leaf) => leaf.policy() == ShowPolicy::Refused,
            }
        }
        ShowShape::Carrier(_) | ShowShape::Param => false,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn every_leaf_is_listed_once() {
        for (i, (a, _)) in SHOWN_LEAVES.iter().enumerate() {
            for (b, _) in SHOWN_LEAVES.iter().skip(i + 1) {
                assert_ne!(a, b, "leaf listed twice");
            }
        }
    }

    #[test]
    fn every_bridged_enum_has_a_listed_leaf() {
        for e in RuntimeBridgedEnum::ALL {
            let leaf = e.show_leaf();
            assert!(
                SHOWN_LEAVES.contains(&(leaf.name(), leaf.policy())),
                "{e:?}"
            );
        }
    }

    #[test]
    fn a_function_or_foreign_handle_field_is_refused() {
        let mut interner = Interner::new();
        let payloads = BTreeMap::new();
        let fun = IrType::Fun(vec![IrType::Int], Box::new(IrType::Int));
        let record = IrType::Record(BTreeMap::from([(
            interner.intern("f").expect("intern"),
            IrType::List(Box::new(fun)),
        )]));
        assert!(ir_type_holds_refused(&record, &payloads, &interner));
        let foreign = IrType::Enum {
            home: ModPath(vec![
                interner.intern("Rust").expect("intern"),
                interner.intern("Demo").expect("intern"),
            ]),
            name: interner.intern("Widget").expect("intern"),
            args: vec![],
        };
        assert!(ir_type_holds_refused(
            &IrType::Maybe(Box::new(foreign)),
            &payloads,
            &interner
        ));
        let wide = IrType::Tuple(vec![IrType::Int; MAX_SHOWN_TUPLE_ARITY + 1]);
        assert!(ir_type_holds_refused(&wide, &payloads, &interner));
    }

    #[test]
    fn a_shown_leaf_or_bridged_enum_is_not_refused() {
        let mut interner = Interner::new();
        let payloads = BTreeMap::new();
        let topic = IrType::Enum {
            home: ModPath(vec![
                interner.intern("Ipe").expect("intern"),
                interner.intern("PubSub").expect("intern"),
            ]),
            name: interner.intern("Topic").expect("intern"),
            args: vec![],
        };
        let tuple = IrType::Tuple(vec![IrType::Bytes; MAX_SHOWN_TUPLE_ARITY]);
        for ty in [
            topic,
            tuple,
            IrType::Task(Box::new(IrType::Unit)),
            IrType::Url,
        ] {
            assert!(!ir_type_holds_refused(&ty, &payloads, &interner), "{ty:?}");
        }
    }
}
