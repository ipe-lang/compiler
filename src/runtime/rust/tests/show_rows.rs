//! Pins every leaf of `SHOWN_RUNTIME_TYPES` to the runtime type that renders
//! it, under that type's own feature gate.
//!
//! Each pin is a compile-time check that the type's `show_row!` declares the
//! listed leaf and policy, so a row moved to another leaf or policy fails to
//! compile here. The coverage check is cfg-independent: every non-`Refused`
//! leaf must carry at least one pin, whichever features are enabled.

use ipe_runtime_rust::stringify::{SHOWN_RUNTIME_TYPES, ShowPolicy, ShownRow, str_eq};

macro_rules! pins {
    ($($(#[$cfg:meta])* $leaf:literal => $policy:ident: $ty:ty;)*) => {
        $(
            $(#[$cfg])*
            const _: () = assert!(
                str_eq(<$ty as ShownRow>::LEAF, $leaf)
                    && <$ty as ShownRow>::POLICY.tag() == ShowPolicy::$policy.tag(),
                concat!("show row drifted from its pin: ", $leaf),
            );
        )*
        /// Every pinned leaf, whatever the enabled features.
        const PINNED: [&str; [$($leaf),*].len()] = [$($leaf),*];
    };
}

pins! {
    "Int" => Value: i64;
    "Float" => Value: f64;
    "Bool" => Value: bool;
    "String" => Value: String;
    "Char" => Value: char;
    "Unit" => Value: ();
    "Order" => Value: ipe_runtime_rust::basics::IpeOrder;
    "BackoffStrategy" => Value: ipe_runtime_rust::task::BackoffStrategy;
    #[cfg(any(feature = "http_client", all(target_arch = "wasm32", feature = "wasm-client")))]
    "HttpMethod" => Value: ipe_runtime_rust::http_client::HttpMethod;
    #[cfg(any(feature = "http_client", all(target_arch = "wasm32", feature = "wasm-client")))]
    "RedirectPolicy" => Value: ipe_runtime_rust::http_client::RedirectPolicy;
    #[cfg(feature = "decimal")]
    "Decimal" => Value: ipe_runtime_rust::decimal::Decimal;
    "ErrorKind" => Value: ipe_runtime_rust::error::IpeErrorKind;
    "Error" => Value: ipe_runtime_rust::error::IpeError;
    "ErrorDetails" => Value: ipe_runtime_rust::error::IpeErrorDetails;
    "ErrorInfo" => Value: ipe_runtime_rust::error::IpeErrorInfo;
    "PanicInfo" => Value: ipe_runtime_rust::error::IpePanicInfo;
    "TypeInfo" => Value: ipe_runtime_rust::error::IpeTypeInfo;
    "Path" => Value: ipe_runtime_rust::path::Path;
    #[cfg(feature = "url")]
    "UrlRelative" => Value: ipe_runtime_rust::url::UrlRelative;
    "Locale" => Value: ipe_runtime_rust::locale::Locale;
    #[cfg(feature = "email")]
    "EmailAddress" => Value: ipe_runtime_rust::email::EmailAddress;
    #[cfg(feature = "crypto-core")]
    "CryptoMac" => Value: ipe_runtime_rust::crypto_core::Mac;
    "Color" => Value: ipe_runtime_rust::color::Color;
    "ColorError" => Value: ipe_runtime_rust::color::ColorError;
    "WcagLevel" => Value: ipe_runtime_rust::color::WcagLevel;
    "TextSize" => Value: ipe_runtime_rust::color::TextSize;
    "Deficiency" => Value: ipe_runtime_rust::color::Deficiency;
    #[cfg(feature = "csv")]
    "CsvDoc" => Value: ipe_runtime_rust::csv::CsvDoc;
    #[cfg(feature = "cache_kernel")]
    "CacheStats" => Value: ipe_runtime_rust::cache::CacheStats;
    #[cfg(feature = "http_client")]
    "StreamId" => Value: ipe_runtime_rust::http_stream::IpeStreamId;
    #[cfg(feature = "json")]
    "Json" => Value: ipe_runtime_rust::json::JsonVal;
    "Bytes" => Redacted: Vec<u8>;
    #[cfg(feature = "url")]
    "Url" => Redacted: ipe_runtime_rust::url::Url;
    #[cfg(feature = "secret")]
    "Secret" => Redacted: ipe_runtime_rust::secret::Secret;
    #[cfg(feature = "crypto-core")]
    "CryptoKey" => Redacted: ipe_runtime_rust::crypto_core::Key;
    #[cfg(any(feature = "server", feature = "db", feature = "jwt"))]
    "Principal" => Redacted: ipe_runtime_rust::principal::Principal;
    #[cfg(feature = "db")]
    "Dsn" => Redacted: ipe_runtime_rust::dsn::Dsn;
    #[cfg(feature = "db")]
    "SqlFragment" => Redacted: ipe_runtime_rust::db::SqlFragment;
    #[cfg(feature = "server")]
    "ServerRequest" => Redacted: ipe_runtime_rust::server::ServerRequest;
    #[cfg(feature = "server")]
    "ServerResponse" => Redacted: ipe_runtime_rust::server::ServerResponse;
    #[cfg(feature = "server")]
    "ServerCookie" => Redacted: ipe_runtime_rust::server::ServerCookie;
    "WebReq" => Redacted: ipe_runtime_rust::dom::req::WebReq;
    #[cfg(any(feature = "http_client", all(target_arch = "wasm32", feature = "wasm-client")))]
    "HttpRequest" => Redacted: ipe_runtime_rust::http_client::HttpRequest;
    #[cfg(all(feature = "server", feature = "jwt"))]
    "AuthConfig" => Redacted: ipe_runtime_rust::server::AuthConfig;
    #[cfg(all(feature = "server", feature = "jwt"))]
    "TokenSource" => Redacted: ipe_runtime_rust::server::TokenSource;
    #[cfg(any(feature = "websocket_client", all(target_arch = "wasm32", feature = "wasm-client")))]
    "WebSocketClientCfg" => Redacted: ipe_runtime_rust::ws_client::WsClientCfg;
    "ProcessRunWithCfg" => Redacted: ipe_runtime_rust::system::ProcessRunWithCfg;
    "ProcessRunInPtyCfg" => Redacted: ipe_runtime_rust::system::ProcessRunInPtyCfg;
    #[cfg(feature = "cache_kernel")]
    "CacheCfg" => Redacted: ipe_runtime_rust::cache::CacheCfg;
    #[cfg(feature = "regex")]
    "Regex" => Redacted: ipe_runtime_rust::regex_kernel::Regex;
    #[cfg(feature = "email")]
    "EmailMessage" => Redacted: ipe_runtime_rust::email::EmailMessage;
    #[cfg(feature = "email")]
    "EmailAttachment" => Redacted: ipe_runtime_rust::email::EmailAttachment;
    #[cfg(feature = "email")]
    "EmailSesConfig" => Redacted: ipe_runtime_rust::email::SesConfig;
    #[cfg(feature = "email")]
    "EmailSmtpConfig" => Redacted: ipe_runtime_rust::email::SmtpConfig;
    "Task" => Internals: ipe_runtime_rust::core::IpeTask<ipe_runtime_rust::error::IpeError, ()>;
    #[cfg(any(feature = "tokio", all(target_arch = "wasm32", feature = "wasm-client")))]
    "Cmd" => Internals: ipe_runtime_rust::tea::IpeCmd<()>;
    #[cfg(any(feature = "tokio", all(target_arch = "wasm32", feature = "wasm-client")))]
    "Sub" => Internals: ipe_runtime_rust::tea::IpeSub<()>;
    #[cfg(feature = "json")]
    "Decoder" => Internals: ipe_runtime_rust::json::Decoder<ipe_runtime_rust::error::IpeError, ()>;
    #[cfg(feature = "db")]
    "Db" => Internals: ipe_runtime_rust::db::Db;
    #[cfg(feature = "db")]
    "Connection" => Internals: ipe_runtime_rust::external_conn::ExternalConnection;
    "Setting" => Internals: ipe_runtime_rust::app_config::Setting;
    #[cfg(feature = "server")]
    "StreamWriter" => Internals: ipe_runtime_rust::server_stream::StreamWriter;
    #[cfg(feature = "server")]
    "ServerRoute" => Internals: ipe_runtime_rust::server::ServerRoute;
    #[cfg(feature = "server")]
    "WebSocketServer" => Internals: ipe_runtime_rust::server::WsHandle;
    #[cfg(feature = "server")]
    "WebSocketServerCfg" => Internals: ipe_runtime_rust::server::WsServerCfg<ipe_runtime_rust::error::IpeError>;
    #[cfg(all(feature = "tokio", not(target_arch = "wasm32")))]
    "WebApp" => Internals: ipe_runtime_rust::tea::WebApp;
    #[cfg(all(feature = "tokio", not(target_arch = "wasm32")))]
    "WebApp" => Internals: ipe_runtime_rust::tea::WebViewApp;
    #[cfg(all(feature = "tokio", not(target_arch = "wasm32")))]
    "TuiApp" => Internals: ipe_runtime_rust::tea::TuiApp;
    #[cfg(all(feature = "tokio", not(target_arch = "wasm32")))]
    "CliApp" => Internals: ipe_runtime_rust::tea::CliApp;
    #[cfg(all(feature = "tokio", not(target_arch = "wasm32")))]
    "WorkerApp" => Internals: ipe_runtime_rust::tea::WorkerApp;
    #[cfg(feature = "web-core")]
    "WebRoute" => Internals: ipe_runtime_rust::web::route::Route<()>;
    "CustomElement" => Internals: ipe_runtime_rust::ui::widget::IpeCustomElement;
    #[cfg(feature = "cache_kernel")]
    "CacheHandle" => Internals: ipe_runtime_rust::cache::IpeCacheHandle;
    #[cfg(feature = "http_client")]
    "ChunkEvent" => Internals: ipe_runtime_rust::http_stream::ChunkEvent<ipe_runtime_rust::error::IpeError>;
    #[cfg(feature = "email")]
    "EmailProvider" => Internals: ipe_runtime_rust::email::EmailProvider;
    "TermProfile" => Internals: ipe_runtime_rust::color::TermProfile;
    "AnsiColor" => Internals: ipe_runtime_rust::color::AnsiColor;
    "Html" => Internals: ipe_runtime_rust::html::Html<()>;
    "Element" => Internals: ipe_runtime_rust::ui::element::Element<()>;
    #[cfg(feature = "tui")]
    "Cells" => Internals: ipe_runtime_rust::tui::CellsView<()>;
    "UiAttribute" => Internals: ipe_runtime_rust::ui::element::Attribute<()>;
    #[cfg(feature = "tui")]
    "TuiAttribute" => Internals: ipe_runtime_rust::tui::TuiAttr<()>;
    #[cfg(feature = "tui")]
    "CliLines" => Internals: ipe_runtime_rust::tui::LinesView<()>;
    #[cfg(feature = "tui")]
    "CliAttribute" => Internals: ipe_runtime_rust::tui::CliAttr<()>;
    "HtmlAttribute" => Internals: ipe_runtime_rust::html::Attribute<()>;
    "HtmlEvent" => Internals: ipe_runtime_rust::html::Event<()>;
    "Label" => Internals: ipe_runtime_rust::ui::input::Label<()>;
    "Placeholder" => Internals: ipe_runtime_rust::ui::input::Placeholder<()>;
    "RadioOption" => Internals: ipe_runtime_rust::ui::input::RadioOption<()>;
    "Length" => Internals: ipe_runtime_rust::ui::element::Length;
    "HAlign" => Internals: ipe_runtime_rust::ui::element::HAlign;
    "VAlign" => Internals: ipe_runtime_rust::ui::element::VAlign;
    "Location" => Internals: ipe_runtime_rust::ui::element::Location;
    "PseudoClass" => Internals: ipe_runtime_rust::ui::element::PseudoClass;
    "Description" => Internals: ipe_runtime_rust::ui::element::Description;
    "LayoutContext" => Internals: ipe_runtime_rust::ui::element::LayoutContext;
    #[cfg(feature = "db")]
    "ProjectionTerm" => Internals: ipe_runtime_rust::db::ProjectionTerm;
    #[cfg(feature = "db")]
    "ProjectionOperand" => Internals: ipe_runtime_rust::db::ProjectionOperand;
    #[cfg(feature = "db")]
    "ArithOp" => Internals: ipe_runtime_rust::db::ArithOp;
}

const fn pinned(leaf: &str) -> bool {
    let mut rest: &[&str] = &PINNED;
    while let [first, tail @ ..] = rest {
        if str_eq(first, leaf) {
            return true;
        }
        rest = tail;
    }
    false
}

const fn every_shown_leaf_is_pinned() -> bool {
    let mut rest: &[(&str, ShowPolicy)] = &SHOWN_RUNTIME_TYPES;
    while let [(leaf, policy), tail @ ..] = rest {
        if policy.tag() != ShowPolicy::Refused.tag() && !pinned(leaf) {
            return false;
        }
        rest = tail;
    }
    true
}

const _: () = assert!(
    every_shown_leaf_is_pinned(),
    "a shown leaf has no runtime type pin"
);

// A pin names only listed leaves.
#[test]
fn every_pin_names_a_listed_leaf() {
    for pin in PINNED {
        assert!(
            SHOWN_RUNTIME_TYPES.iter().any(|(leaf, _)| *leaf == pin),
            "{pin} is pinned but not listed"
        );
    }
}
