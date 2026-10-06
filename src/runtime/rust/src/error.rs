//! Ipe.Error: the rich, typed `Error` ADT.
//!
//! `Error = Error ErrorKind ErrorInfo`, an 11-variant `ErrorKind`
//! classification, message-carrying `ErrorInfo`, and the 5-variant
//! `ErrorDetails` union (`FfiPanic`/`TypeMismatch`/`HttpStatus`/`JsonDecode`/
//! `Custom`) carried optionally on `ErrorInfo.details : Maybe ErrorDetails`.
//!
//! Kind-based classification (`isRetryable`, pattern matching, `toString`)
//! and the `details` enrichment are both fully real and load-bearing today.
//! `Error.withDetails` is the sanctioned way to attach `ErrorDetails` to a
//! live `Error` value — raw Ipê-source construction of `ErrorInfo`/
//! `PanicInfo`/`TypeInfo` record literals is NOT supported (those are
//! anonymous structural records at the type level, so a literal lowers to a
//! project-local synthesized struct, not this module's concrete
//! `IpeErrorInfo`/`IpePanicInfo`/`IpeTypeInfo` — the same limitation
//! `ErrorInfo` itself already had before this pass; see
//! the `B-ErrorADT` sanctioned divergence).
//!
//! Backed by `builtin_runtime_enum` (mirrors `Order`/`IpeOrder`):
//! `Error`'s sole constructor shares its name with the type
//! (`ipe_lower`'s `enum_variants` table), so it emits as the tuple variant
//! `IpeError::Error(kind, info)` via the SAME generic constructor/pattern
//! path `IpeMaybe::Just`/`IpeResult::Ok` already use — no new emitter
//! mechanism needed, just table rows. `ErrorDetails` is registered the same
//! way (`builtin_runtime_enum("ErrorDetails") -> "IpeErrorDetails"`).

use std::fmt;

use crate::core::IpeMaybe;

/// Ipê's `ErrorKind` — 11 nullary variants. Repr(u8) for a compact, sound,
/// exhaustively-matched runtime type (mirrors `IpeOrder`'s convention).
/// Variant order matches canon's registration (`crates/ipe_canon/src/env.rs`,
/// "E-12") — do not reorder without updating that table.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum IpeErrorKind {
    Io = 0,
    Network = 1,
    Ffi = 2,
    Decode = 3,
    Timeout = 4,
    NotFound = 5,
    PermissionDenied = 6,
    InvalidInput = 7,
    Conflict = 8,
    Unavailable = 9,
    Unexpected = 10,
}

crate::stringify::show_row!("ErrorKind", Value, [] IpeErrorKind, |k| k.label().to_owned());

impl IpeErrorKind {
    /// Renders the reference design's `"<Kind>: "` prefix (`Error.toString`,
    /// `"<Kind>: <message>"`).
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Io => "Io",
            Self::Network => "Network",
            Self::Ffi => "Ffi",
            Self::Decode => "Decode",
            Self::Timeout => "Timeout",
            Self::NotFound => "NotFound",
            Self::PermissionDenied => "PermissionDenied",
            Self::InvalidInput => "InvalidInput",
            Self::Conflict => "Conflict",
            Self::Unavailable => "Unavailable",
            Self::Unexpected => "Unexpected",
        }
    }
}

/// Ipê's `PanicInfo` — `FfiPanic`'s payload: `{ message : String, stack :
/// List String }`.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IpePanicInfo {
    pub message: String,
    pub stack: Vec<String>,
}

crate::stringify::show_row!("PanicInfo", Value, [] IpePanicInfo, |p| format!(
    "{{{} {}}}",
    p.message,
    crate::stringify::IpeStringify::ipe_show(&p.stack)
));

/// Ipê's `TypeInfo` — `TypeMismatch`'s payload: `{ expected : String, actual
/// : String }`.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IpeTypeInfo {
    pub expected: String,
    pub actual: String,
}

crate::stringify::show_row!("TypeInfo", Value, [] IpeTypeInfo, |t| format!(
    "{{{} {}}}",
    t.expected, t.actual
));

/// Ipê's `ErrorDetails` — the 5-variant enrichment union. Constructor names
/// match Ipê source verbatim
/// (`ipe_backend_rust`'s `builtin_runtime_enum("ErrorDetails")` routes
/// `FfiPanic` / `TypeMismatch` / `HttpStatus` / `JsonDecode` / `Custom`
/// straight to these variants — no synthetic `EnumDef`).
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum IpeErrorDetails {
    FfiPanic(IpePanicInfo),
    TypeMismatch(IpeTypeInfo),
    HttpStatus(i64),
    JsonDecode(String),
    Custom(String),
}

crate::stringify::show_row!("ErrorDetails", Value, [] IpeErrorDetails, |d| match d {
    IpeErrorDetails::FfiPanic(p) => format!("FfiPanic {}", crate::stringify::IpeStringify::ipe_show(p)),
    IpeErrorDetails::TypeMismatch(t) => {
        format!("TypeMismatch {}", crate::stringify::IpeStringify::ipe_show(t))
    }
    IpeErrorDetails::HttpStatus(n) => format!("HttpStatus {n}"),
    IpeErrorDetails::JsonDecode(s) => format!("JsonDecode {s}"),
    IpeErrorDetails::Custom(s) => format!("Custom {s}"),
});

/// Ipê's `ErrorInfo` — `{ message : String, details : Maybe ErrorDetails }`.
///
/// No `#[derive(Eq)]`: `IpeMaybe<T>` (the `details` field's carrier) derives
/// only `PartialEq`, not `Eq` (see `core.rs`'s `IpeMaybe` doc), so `Eq` here
/// would fail to compile. `PartialEq` is unaffected and is what
/// `ir_type_is_derivable`'s Rust-side gate actually requires.
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IpeErrorInfo {
    pub message: String,
    pub details: IpeMaybe<IpeErrorDetails>,
}

crate::stringify::show_row!("ErrorInfo", Value, [] IpeErrorInfo, |i| format!(
    "{{{} {}}}",
    i.message,
    crate::stringify::IpeStringify::ipe_show(&i.details)
));

/// Ipê's `Error` — `Error ErrorKind ErrorInfo`, a single tuple-variant enum
/// (constructor name == type name, matching `ipe_lower`'s registration) so
/// the generic `builtin_runtime_enum` constructor/pattern path handles it
/// exactly like `IpeMaybe::Just`/`IpeResult::Ok`.
///
/// No `#[derive(Eq)]` (see `IpeErrorInfo`'s doc — it carries a `IpeMaybe`
/// field, and `IpeMaybe` is `PartialEq`-only).
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum IpeError {
    Error(IpeErrorKind, IpeErrorInfo),
}

impl IpeError {
    /// Every message constructor defaults `details = Nothing`, mirroring the
    /// reference design's `mkInfo` smart constructor.
    fn with(kind: IpeErrorKind, message: String) -> Self {
        Self::Error(
            kind,
            IpeErrorInfo {
                message,
                details: IpeMaybe::Nothing,
            },
        )
    }

    #[must_use]
    pub fn io(message: String) -> Self {
        Self::with(IpeErrorKind::Io, message)
    }
    #[must_use]
    pub fn network(message: String) -> Self {
        Self::with(IpeErrorKind::Network, message)
    }
    #[must_use]
    pub fn ffi(message: String) -> Self {
        Self::with(IpeErrorKind::Ffi, message)
    }
    #[must_use]
    pub fn decode(message: String) -> Self {
        Self::with(IpeErrorKind::Decode, message)
    }
    #[must_use]
    pub fn invalid_input(message: String) -> Self {
        Self::with(IpeErrorKind::InvalidInput, message)
    }
    #[must_use]
    pub fn conflict(message: String) -> Self {
        Self::with(IpeErrorKind::Conflict, message)
    }
    #[must_use]
    pub fn unavailable(message: String) -> Self {
        Self::with(IpeErrorKind::Unavailable, message)
    }
    #[must_use]
    pub fn unexpected(message: String) -> Self {
        Self::with(IpeErrorKind::Unexpected, message)
    }
    /// Nullary in the Ipê surface — pre-built, fixed message.
    #[must_use]
    pub fn timeout() -> Self {
        Self::with(IpeErrorKind::Timeout, "operation timed out".to_owned())
    }
    #[must_use]
    pub fn not_found() -> Self {
        Self::with(IpeErrorKind::NotFound, "not found".to_owned())
    }
    #[must_use]
    pub fn permission_denied() -> Self {
        Self::with(
            IpeErrorKind::PermissionDenied,
            "permission denied".to_owned(),
        )
    }

    /// Ipê `Error.withMessage : String -> Error -> Error` — replaces the
    /// message, keeps the kind.
    #[must_use]
    pub fn with_message(self, message: String) -> Self {
        let Self::Error(kind, _) = self;
        Self::with(kind, message)
    }

    /// Ipê `Error.toString : Error -> String` — `"<Kind>: <message>"`.
    #[must_use]
    pub fn to_ipe_string(&self) -> String {
        let Self::Error(kind, info) = self;
        format!("{}: {}", kind.label(), info.message)
    }

    /// Ipê `Error.isRetryable : Error -> Bool` — `True` only for the three
    /// kinds a caller can reasonably back off and retry.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        let Self::Error(kind, _) = self;
        matches!(
            kind,
            IpeErrorKind::Timeout | IpeErrorKind::Network | IpeErrorKind::Unavailable
        )
    }

    /// Ipê `Error.withDetails : ErrorDetails -> Error -> Error` — keeps kind
    /// and message, sets `details = Just <details>`.
    /// This is the sanctioned way to attach `ErrorDetails` to a live `Error`
    /// value from Ipê source (see module doc for why raw record-literal
    /// construction of `ErrorInfo`/`PanicInfo`/`TypeInfo` is not supported).
    #[must_use]
    pub fn with_details(self, details: IpeErrorDetails) -> Self {
        let Self::Error(kind, info) = self;
        Self::Error(
            kind,
            IpeErrorInfo {
                message: info.message,
                details: IpeMaybe::Just(details),
            },
        )
    }
}

impl fmt::Display for IpeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_ipe_string())
    }
}

// ── Ipe.Error kernels ────────────────────────────────
// Each message constructor classifies its own `ErrorKind` at construction,
// rather than sharing one string-identity runtime symbol across all eight.

#[must_use]
pub fn ipe_error_unexpected(msg: String) -> IpeError {
    IpeError::unexpected(msg)
}
#[must_use]
pub fn ipe_error_invalid_input(msg: String) -> IpeError {
    IpeError::invalid_input(msg)
}
#[must_use]
pub fn ipe_error_io(msg: String) -> IpeError {
    IpeError::io(msg)
}
#[must_use]
pub fn ipe_error_network(msg: String) -> IpeError {
    IpeError::network(msg)
}
#[must_use]
pub fn ipe_error_ffi(msg: String) -> IpeError {
    IpeError::ffi(msg)
}
#[must_use]
pub fn ipe_error_decode(msg: String) -> IpeError {
    IpeError::decode(msg)
}
#[must_use]
pub fn ipe_error_conflict(msg: String) -> IpeError {
    IpeError::conflict(msg)
}
#[must_use]
pub fn ipe_error_unavailable(msg: String) -> IpeError {
    IpeError::unavailable(msg)
}
/// `Error.timeout : Error` — canonical timeout error.
#[must_use]
pub fn ipe_error_timeout() -> IpeError {
    IpeError::timeout()
}
/// `Error.notFound : Error` — canonical not-found error.
#[must_use]
pub fn ipe_error_not_found() -> IpeError {
    IpeError::not_found()
}
/// `Error.permissionDenied : Error` — canonical permission-denied error.
#[must_use]
pub fn ipe_error_permission_denied() -> IpeError {
    IpeError::permission_denied()
}
/// `Error.withMessage : String -> Error -> Error`.
#[must_use]
pub fn ipe_error_with_message(msg: String, old: IpeError) -> IpeError {
    old.with_message(msg)
}
/// `Error.isRetryable : Error -> Bool`.
#[must_use]
pub fn ipe_error_is_retryable(e: IpeError) -> bool {
    e.is_retryable()
}
/// `Error.withDetails : ErrorDetails -> Error -> Error`.
#[must_use]
pub fn ipe_error_with_details(details: IpeErrorDetails, old: IpeError) -> IpeError {
    old.with_details(details)
}
/// `Error.kind : Error -> ErrorKind` — the classification carried by an error.
#[must_use]
pub fn ipe_error_kind(e: IpeError) -> IpeErrorKind {
    let IpeError::Error(kind, _) = e;
    kind
}
/// `Error.message : Error -> String` — the human-readable message, without the
/// `"<Kind>: "` prefix `Error.toString` adds.
#[must_use]
pub fn ipe_error_message(e: IpeError) -> String {
    let IpeError::Error(_, info) = e;
    info.message
}
/// `Error.kindName : ErrorKind -> String` — the stable variant name (`"Io"`,
/// `"Network"`, …), the same label `Error.toString` prefixes with.
#[must_use]
pub fn ipe_error_kind_name(kind: IpeErrorKind) -> String {
    kind.label().to_owned()
}

// `Error.toString` routes through the shared Stringify-bounded mechanism (any
// `Show`-obligated type, not an Error-specific kernel): `"<Kind>: <message>"`.
crate::stringify::show_row!("Error", Value, [] IpeError, |e| e.to_ipe_string());

/// Compatibility bridge: kernel call sites across the runtime that produce a
/// bare `String` error keep compiling — `?`/`.into()` on a `String` yields an
/// `Unexpected`-classified `Error` instead of losing type information. Such
/// call sites should migrate to a properly-classified constructor
/// (`IpeError::io`, `::network`, …).
impl From<String> for IpeError {
    fn from(message: String) -> Self {
        Self::unexpected(message)
    }
}

impl From<&str> for IpeError {
    fn from(message: &str) -> Self {
        Self::unexpected(message.to_owned())
    }
}

/// A generic error sink that can classify a refusal as `Unavailable`.
///
/// A kernel generic over `E: From<String>` (`tui_app`, the blocking-pool file
/// and process kernels) reports a missing terminal or a refused thread through
/// this bound instead of folding the text into `Unexpected` through the blanket
/// `From<String>` bridge above. `IpeError` carries the retryable kind; a bare
/// `String` sink, which has no kind, keeps the message.
pub trait FromUnavailable {
    fn from_unavailable(message: String) -> Self;
}

impl FromUnavailable for IpeError {
    fn from_unavailable(message: String) -> Self {
        Self::unavailable(message)
    }
}

impl FromUnavailable for String {
    fn from_unavailable(message: String) -> Self {
        message
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;

    #[test]
    fn constructors_carry_kind_and_message() {
        let e = IpeError::io("disk full".to_owned());
        assert_eq!(e.to_ipe_string(), "Io: disk full");
        assert!(!e.is_retryable());
    }

    #[test]
    fn nullary_constructors_have_fixed_messages() {
        assert_eq!(
            IpeError::timeout().to_ipe_string(),
            "Timeout: operation timed out"
        );
        assert_eq!(IpeError::not_found().to_ipe_string(), "NotFound: not found");
        assert_eq!(
            IpeError::permission_denied().to_ipe_string(),
            "PermissionDenied: permission denied"
        );
    }

    #[test]
    fn retryable_kinds_are_exactly_timeout_network_unavailable() {
        assert!(IpeError::timeout().is_retryable());
        assert!(IpeError::network(String::new()).is_retryable());
        assert!(IpeError::unavailable(String::new()).is_retryable());
        assert!(!IpeError::io(String::new()).is_retryable());
        assert!(!IpeError::unexpected(String::new()).is_retryable());
        assert!(!IpeError::conflict(String::new()).is_retryable());
    }

    #[test]
    fn with_message_replaces_message_keeps_kind() {
        let e = IpeError::network("timeout".to_owned()).with_message("retry later".to_owned());
        assert_eq!(e.to_ipe_string(), "Network: retry later");
    }

    #[test]
    fn from_string_classifies_as_unexpected() {
        let e: IpeError = "legacy bare string error".to_owned().into();
        assert_eq!(e.to_ipe_string(), "Unexpected: legacy bare string error");
    }

    #[test]
    fn pattern_match_destructures_kind_and_message() {
        let e = IpeError::conflict("duplicate key".to_owned());
        let IpeError::Error(kind, info) = &e;
        assert_eq!(*kind, IpeErrorKind::Conflict);
        assert_eq!(info.message, "duplicate key");
    }

    #[test]
    fn message_constructors_default_details_to_nothing() {
        let e = IpeError::io("disk full".to_owned());
        let IpeError::Error(_, info) = &e;
        assert_eq!(info.details, IpeMaybe::Nothing);
    }

    #[test]
    fn with_details_sets_just_keeps_kind_and_message() {
        let e = IpeError::io("disk full".to_owned()).with_details(IpeErrorDetails::HttpStatus(404));
        let IpeError::Error(kind, info) = &e;
        assert_eq!(*kind, IpeErrorKind::Io);
        assert_eq!(info.message, "disk full");
        assert_eq!(
            info.details,
            IpeMaybe::Just(IpeErrorDetails::HttpStatus(404))
        );
    }

    #[test]
    fn kind_extracts_the_classification() {
        assert_eq!(
            ipe_error_kind(IpeError::io("x".to_owned())),
            IpeErrorKind::Io
        );
        assert_eq!(ipe_error_kind(IpeError::timeout()), IpeErrorKind::Timeout);
    }

    #[test]
    fn message_extracts_the_bare_message() {
        assert_eq!(
            ipe_error_message(IpeError::io("disk full".to_owned())),
            "disk full"
        );
        assert_eq!(ipe_error_message(IpeError::not_found()), "not found");
    }

    #[test]
    fn kind_name_renders_the_stable_label() {
        assert_eq!(ipe_error_kind_name(IpeErrorKind::Io), "Io");
        assert_eq!(
            ipe_error_kind_name(IpeErrorKind::PermissionDenied),
            "PermissionDenied"
        );
        assert_eq!(ipe_error_kind_name(IpeErrorKind::Unexpected), "Unexpected");
    }

    #[test]
    fn error_details_round_trips_all_five_variants() {
        let cases = [
            IpeErrorDetails::FfiPanic(IpePanicInfo {
                message: "panic!".to_owned(),
                stack: vec!["frame1".to_owned(), "frame2".to_owned()],
            }),
            IpeErrorDetails::TypeMismatch(IpeTypeInfo {
                expected: "Int".to_owned(),
                actual: "String".to_owned(),
            }),
            IpeErrorDetails::HttpStatus(500),
            IpeErrorDetails::JsonDecode("unexpected token".to_owned()),
            IpeErrorDetails::Custom("custom detail".to_owned()),
        ];
        for details in cases {
            let e = IpeError::unexpected("boom".to_owned()).with_details(details.clone());
            let IpeError::Error(_, info) = &e;
            assert_eq!(info.details, IpeMaybe::Just(details));
        }
    }
}
