//! Ipe.Error: the rich, typed `Error` ADT.
//!
//! `Error = Error ErrorKind ErrorInfo`, a 13-variant `ErrorKind`
//! classification, message-carrying `ErrorInfo`, and the 6-variant
//! `ErrorDetails` union (`FfiPanic`/`TypeMismatch`/`HttpStatus`/`JsonDecode`/
//! `Custom`/`Database`) carried optionally on `ErrorInfo.details : Maybe ErrorDetails`.
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

/// Ipê's `ErrorKind` — 13 nullary variants.
///
/// Repr(u8) for a compact, sound, exhaustively-matched runtime type (mirrors
/// `IpeOrder`'s convention). The order is append-only: each discriminant is
/// stable across serde and the JS port. Canon's `BuiltinUnion` ctor table
/// (`src/compiler/canon/src/builtins.rs`) mirrors it, and
/// `src/ipe-cli/tests/error_kind_agreement.rs` pins the two equal.
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
    /// A declared ceiling (a size, count or depth bound on one input) turned
    /// the input back; a larger bound would accept the same input.
    LimitExceeded = 11,
    /// The client is older than the server it calls; the user updates the app.
    UpdateRequired = 12,
}

crate::stringify::show_row!("ErrorKind", Value, [] IpeErrorKind, |k| k.label().to_owned());

impl IpeErrorKind {
    /// Every kind, in discriminant order.
    pub const ALL: [Self; 13] = [
        Self::Io,
        Self::Network,
        Self::Ffi,
        Self::Decode,
        Self::Timeout,
        Self::NotFound,
        Self::PermissionDenied,
        Self::InvalidInput,
        Self::Conflict,
        Self::Unavailable,
        Self::Unexpected,
        Self::LimitExceeded,
        Self::UpdateRequired,
    ];

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
            Self::LimitExceeded => "LimitExceeded",
            Self::UpdateRequired => "UpdateRequired",
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

/// Ipê's `DbFailure` — the closed classification of a database failure.
///
/// Spelled `Db.<Ctor>` in Ipê source and carried as `ErrorDetails.Database`.
/// The one producer is the runtime's database classifier; a cause it does not
/// recognise is `OtherFailure`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum IpeDbFailure {
    UniqueViolation = 0,
    ForeignKeyViolation = 1,
    NotNullViolation = 2,
    CheckViolation = 3,
    TriggerRaised = 4,
    OtherConstraint = 5,
    Busy = 6,
    ReadOnlyDatabase = 7,
    AccessDenied = 8,
    CannotOpen = 9,
    NotADatabase = 10,
    InvalidStatement = 11,
    Unreachable = 12,
    OtherFailure = 13,
}

// `ALL` spans the whole discriminant range, `OtherFailure` last.
const _: [(); IpeDbFailure::ALL.len()] = [(); IpeDbFailure::OtherFailure as usize + 1];

crate::stringify::show_row!("DbFailure", Value, [] IpeDbFailure, |f| f
    .ctor_name()
    .to_owned());

impl IpeDbFailure {
    /// Every variant, in declaration order.
    pub const ALL: [Self; 14] = [
        Self::UniqueViolation,
        Self::ForeignKeyViolation,
        Self::NotNullViolation,
        Self::CheckViolation,
        Self::TriggerRaised,
        Self::OtherConstraint,
        Self::Busy,
        Self::ReadOnlyDatabase,
        Self::AccessDenied,
        Self::CannotOpen,
        Self::NotADatabase,
        Self::InvalidStatement,
        Self::Unreachable,
        Self::OtherFailure,
    ];

    /// Every variant as its `(constructor name, discriminant)` row, in
    /// declaration order.
    pub const ROWS: [(&'static str, usize); 14] = {
        let mut rows = [("", 0_usize); 14];
        let mut out: &mut [(&str, usize)] = &mut rows;
        let mut all: &[Self] = &Self::ALL;
        while let ([failure, all_rest @ ..], [slot, out_rest @ ..]) = (all, out) {
            *slot = (failure.ctor_name(), *failure as usize);
            all = all_rest;
            out = out_rest;
        }
        rows
    };

    /// The Ipê constructor name, without the `Db.` qualifier.
    #[must_use]
    pub const fn ctor_name(self) -> &'static str {
        match self {
            Self::UniqueViolation => "UniqueViolation",
            Self::ForeignKeyViolation => "ForeignKeyViolation",
            Self::NotNullViolation => "NotNullViolation",
            Self::CheckViolation => "CheckViolation",
            Self::TriggerRaised => "TriggerRaised",
            Self::OtherConstraint => "OtherConstraint",
            Self::Busy => "Busy",
            Self::ReadOnlyDatabase => "ReadOnlyDatabase",
            Self::AccessDenied => "AccessDenied",
            Self::CannotOpen => "CannotOpen",
            Self::NotADatabase => "NotADatabase",
            Self::InvalidStatement => "InvalidStatement",
            Self::Unreachable => "Unreachable",
            Self::OtherFailure => "OtherFailure",
        }
    }

    /// The fixed human phrase an error message carries for this failure.
    #[must_use]
    pub const fn phrase(self) -> &'static str {
        match self {
            Self::UniqueViolation => "unique constraint violated",
            Self::ForeignKeyViolation => "foreign key constraint violated",
            Self::NotNullViolation => "not-null constraint violated",
            Self::CheckViolation => "check constraint violated",
            Self::TriggerRaised => "trigger refused the statement",
            Self::OtherConstraint => "constraint violated",
            Self::Busy => "database busy",
            Self::ReadOnlyDatabase => "database is read-only",
            Self::AccessDenied => "access denied",
            Self::CannotOpen => "cannot open database",
            Self::NotADatabase => "file is not a database",
            Self::InvalidStatement => "invalid statement",
            Self::Unreachable => "database unreachable",
            Self::OtherFailure => "database error",
        }
    }

    /// The `ErrorKind` an error carrying this failure is classified under.
    #[must_use]
    pub const fn kind(self) -> IpeErrorKind {
        match self {
            Self::UniqueViolation
            | Self::ForeignKeyViolation
            | Self::NotNullViolation
            | Self::CheckViolation
            | Self::TriggerRaised
            | Self::OtherConstraint => IpeErrorKind::Conflict,
            Self::Busy | Self::Unreachable => IpeErrorKind::Unavailable,
            Self::ReadOnlyDatabase | Self::AccessDenied => IpeErrorKind::PermissionDenied,
            Self::CannotOpen => IpeErrorKind::NotFound,
            Self::NotADatabase | Self::InvalidStatement | Self::OtherFailure => {
                IpeErrorKind::Unexpected
            }
        }
    }
}

/// Ipê's `AuthError` — the closed, payload-free reason `Auth.verifyToken`
/// refused a token.
///
/// Spelled `Auth.<Ctor>` in Ipê source. No variant carries the token, the key
/// or a parser's text, so a refusal has nothing to leak. `Expired` and
/// `NotYetValid` are judged before the signature check: they do not prove the
/// token was authentic, so a client must never see them as different from
/// `BadSignature`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum IpeAuthError {
    Malformed = 0,
    BadSignature = 1,
    Expired = 2,
    NotYetValid = 3,
    MissingClaim = 4,
    Revoked = 5,
    RevocationUnavailable = 6,
    TooManyCredentials = 7,
    SecretTooShort = 8,
}

// `ALL` spans the whole discriminant range, `SecretTooShort` last.
const _: [(); IpeAuthError::ALL.len()] = [(); IpeAuthError::SecretTooShort as usize + 1];

crate::stringify::show_row!("AuthError", Value, [] IpeAuthError, |e| e
    .ctor_name()
    .to_owned());

impl IpeAuthError {
    /// Every variant, in declaration order.
    pub const ALL: [Self; 9] = [
        Self::Malformed,
        Self::BadSignature,
        Self::Expired,
        Self::NotYetValid,
        Self::MissingClaim,
        Self::Revoked,
        Self::RevocationUnavailable,
        Self::TooManyCredentials,
        Self::SecretTooShort,
    ];

    /// Every variant as its `(constructor name, discriminant)` row, in
    /// declaration order.
    pub const ROWS: [(&'static str, usize); 9] = {
        let mut rows = [("", 0_usize); 9];
        let mut out: &mut [(&str, usize)] = &mut rows;
        let mut all: &[Self] = &Self::ALL;
        while let ([refusal, all_rest @ ..], [slot, out_rest @ ..]) = (all, out) {
            *slot = (refusal.ctor_name(), *refusal as usize);
            all = all_rest;
            out = out_rest;
        }
        rows
    };

    /// The Ipê constructor name, without the `Auth.` qualifier.
    #[must_use]
    pub const fn ctor_name(self) -> &'static str {
        match self {
            Self::Malformed => "Malformed",
            Self::BadSignature => "BadSignature",
            Self::Expired => "Expired",
            Self::NotYetValid => "NotYetValid",
            Self::MissingClaim => "MissingClaim",
            Self::Revoked => "Revoked",
            Self::RevocationUnavailable => "RevocationUnavailable",
            Self::TooManyCredentials => "TooManyCredentials",
            Self::SecretTooShort => "SecretTooShort",
        }
    }

    /// The fixed human phrase for this refusal; it names no token content.
    #[must_use]
    pub const fn phrase(self) -> &'static str {
        match self {
            Self::Malformed => "token is malformed",
            Self::BadSignature => "token signature does not verify",
            Self::Expired => "token has expired",
            Self::NotYetValid => "token is not yet valid",
            Self::MissingClaim => "token lacks a required claim",
            Self::Revoked => "credential revoked",
            Self::RevocationUnavailable => "revocation store unavailable",
            Self::TooManyCredentials => "too many credentials bound to this channel",
            Self::SecretTooShort => "token key is shorter than the minimum",
        }
    }
}

/// Ipê's `ErrorDetails` — the 6-variant enrichment union. Constructor names
/// match Ipê source verbatim
/// (`ipe_backend_rust`'s `builtin_runtime_enum("ErrorDetails")` routes
/// `FfiPanic` / `TypeMismatch` / `HttpStatus` / `JsonDecode` / `Custom` /
/// `Database` straight to these variants — no synthetic `EnumDef`).
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum IpeErrorDetails {
    FfiPanic(IpePanicInfo),
    TypeMismatch(IpeTypeInfo),
    HttpStatus(i64),
    JsonDecode(String),
    Custom(String),
    Database(IpeDbFailure),
}

crate::stringify::show_row!("ErrorDetails", Value, [] IpeErrorDetails, |d| match d {
    IpeErrorDetails::FfiPanic(p) => format!("FfiPanic {}", crate::stringify::IpeStringify::ipe_show(p)),
    IpeErrorDetails::TypeMismatch(t) => {
        format!("TypeMismatch {}", crate::stringify::IpeStringify::ipe_show(t))
    }
    IpeErrorDetails::HttpStatus(n) => format!("HttpStatus {n}"),
    IpeErrorDetails::JsonDecode(s) => format!("JsonDecode {s}"),
    IpeErrorDetails::Custom(s) => format!("Custom {s}"),
    IpeErrorDetails::Database(f) => format!("Database {}", f.ctor_name()),
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
    /// An error for a host I/O failure category, kinded by [`io_error_kind`].
    ///
    /// The caller owns `message`, which must already be fixed or scrubbed
    /// text; [`IoFailure`] builds one that names a path.
    #[must_use]
    pub fn from_io_kind(kind: std::io::ErrorKind, message: String) -> Self {
        Self::with(io_error_kind(kind), message)
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
    /// A declared ceiling turned the input back (`ErrorKind.LimitExceeded`).
    #[must_use]
    pub fn limit_exceeded(message: impl Into<String>) -> Self {
        Self::with(IpeErrorKind::LimitExceeded, message.into())
    }
    /// The client is older than the server it calls (`ErrorKind.UpdateRequired`).
    #[must_use]
    pub fn update_required(message: impl Into<String>) -> Self {
        Self::with(IpeErrorKind::UpdateRequired, message.into())
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

    /// A database failure, classified under the failure's own kind.
    ///
    /// Sets `details = Just (Database failure)`.
    #[must_use]
    pub fn database(failure: IpeDbFailure, message: String) -> Self {
        Self::Error(
            failure.kind(),
            IpeErrorInfo {
                message,
                details: IpeMaybe::Just(IpeErrorDetails::Database(failure)),
            },
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

    /// Ipê `Error.isRetryable : Error -> Bool` — `True` only for `Timeout`,
    /// `Network` and `Unavailable`.
    ///
    /// Those three are the kinds a caller can reasonably back off and retry.
    /// The other ten fail again on the same input: `LimitExceeded` in
    /// particular is a deterministic refusal of that input by its bound, and
    /// `UpdateRequired` holds until the client is updated.
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
// rather than sharing one string-identity runtime symbol across all nine.

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
/// `Error.limitExceeded : String -> Error` — a declared-ceiling refusal.
#[must_use]
pub fn ipe_error_limit_exceeded(msg: String) -> IpeError {
    IpeError::limit_exceeded(msg)
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

/// A generic error sink that keeps a classified [`IpeError`]'s kind.
///
/// A kernel generic over `E: From<String>` (`server_listen`) reports a typed
/// refusal (a port in use, a bind the OS refused) through this bound instead of
/// folding its text into `Unexpected` through the blanket `From<String>`
/// bridge. `IpeError` keeps the error as built; a bare `String` sink, which has
/// no kind, keeps its `Error.toString` text.
pub trait FromIpeError {
    fn from_ipe_error(error: IpeError) -> Self;
}

impl FromIpeError for IpeError {
    fn from_ipe_error(error: IpeError) -> Self {
        error
    }
}

impl FromIpeError for String {
    fn from_ipe_error(error: IpeError) -> Self {
        error.to_ipe_string()
    }
}

/// A generic error sink that can classify a failed decode as `Decode`.
///
/// Every JSON, YAML and row decoder reports malformed or mistyped input
/// through this bound, never through the blanket `From<String>` bridge, so a
/// client's bad payload reaches the program as `Decode` and never as
/// `Unexpected`. A bare `String` sink, which has no kind, keeps the message.
pub trait FromDecodeFailure {
    fn from_decode_failure(message: String) -> Self;
}

impl FromDecodeFailure for IpeError {
    fn from_decode_failure(message: String) -> Self {
        Self::decode(message)
    }
}

impl FromDecodeFailure for String {
    fn from_decode_failure(message: String) -> Self {
        message
    }
}

/// An error sink every decoder can land a failure in.
///
/// The one bound every generic decoder names: `From<String>` for the
/// composed decoders that only forward an inner error, and
/// [`FromDecodeFailure`] for the failure a decoder builds itself.
pub trait DecodeErrorSink: From<String> + FromDecodeFailure {}

impl<E> DecodeErrorSink for E where E: From<String> + FromDecodeFailure {}

/// A generic `E: From<String>` error sink that can classify a refusal as
/// `LimitExceeded`.
///
/// The blanket `From<String>` bridge yields `Unexpected`; a declared-ceiling
/// refusal reaching such a sink goes through this trait instead, so it keeps
/// its kind. Implemented for `IpeError`, as `FromUnavailable` is (unit tests
/// add the bare `String` sink below).
pub trait FromLimitExceeded {
    fn from_limit_exceeded(message: String) -> Self;
}

impl FromLimitExceeded for IpeError {
    fn from_limit_exceeded(message: String) -> Self {
        Self::limit_exceeded(message)
    }
}

/// A unit test's bare-`String` error sink keeps only the message.
///
/// Kind assertions in tests use an `IpeError` sink, so a `String` sink can
/// never be mistaken for one that proves the `LimitExceeded` kind.
#[cfg(all(test, not(target_arch = "wasm32")))]
impl FromLimitExceeded for String {
    fn from_limit_exceeded(message: String) -> Self {
        message
    }
}

/// A declared ceiling turned the input back.
///
/// The message names the ceiling and, when one exists, the setting that
/// raises it. The value reaches an error sink only as `LimitExceeded`: it has
/// no conversion into `String`, so it cannot fall into the `From<String>`
/// bridge that yields `Unexpected`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LimitRefusal(String);

impl LimitRefusal {
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.0
    }

    /// Prefixes the message with the refusing operation, keeping the kind.
    #[must_use]
    pub fn context(self, operation: &str) -> Self {
        Self(format!("{operation}: {}", self.0))
    }

    /// The refusal in a generic error sink, kinded `LimitExceeded`.
    #[must_use]
    pub fn into_error<E: FromLimitExceeded>(self) -> E {
        E::from_limit_exceeded(self.0)
    }
}

impl From<LimitRefusal> for IpeError {
    fn from(refusal: LimitRefusal) -> Self {
        Self::limit_exceeded(refusal.0)
    }
}

/// A declared wall-clock ceiling ended the operation.
///
/// The message names the operation, the ceiling and, when one exists, the
/// setting that raises it. The value reaches an error sink only as `Timeout`:
/// it has no conversion into `String`, so it cannot fall into the
/// `From<String>` bridge that yields `Unexpected`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimeoutRefusal(String);

impl TimeoutRefusal {
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.0
    }

    /// Prefixes the message with the refusing operation, keeping the kind.
    #[must_use]
    pub fn context(self, operation: &str) -> Self {
        Self(format!("{operation}: {}", self.0))
    }

    /// The refusal in a generic error sink, kinded `Timeout`.
    #[must_use]
    pub fn into_error<E: FromIpeError>(self) -> E {
        E::from_ipe_error(IpeError::from(self))
    }
}

impl From<TimeoutRefusal> for IpeError {
    fn from(refusal: TimeoutRefusal) -> Self {
        Self::with(IpeErrorKind::Timeout, refusal.0)
    }
}

/// The Ipê kind of a host I/O failure category.
///
/// The one classification of `std::io::ErrorKind`: every runtime boundary
/// that turns an `std::io::Error` into an Ipê `Error` reads its kind here. A
/// category with no Ipê counterpart, `Other`, and any category a later
/// toolchain adds stay `Unexpected`.
#[must_use]
pub const fn io_error_kind(kind: std::io::ErrorKind) -> IpeErrorKind {
    use std::io::ErrorKind as K;
    match kind {
        K::NotFound => IpeErrorKind::NotFound,
        K::PermissionDenied | K::ReadOnlyFilesystem => IpeErrorKind::PermissionDenied,
        K::ConnectionRefused
        | K::ConnectionReset
        | K::ConnectionAborted
        | K::NotConnected
        | K::HostUnreachable
        | K::NetworkUnreachable
        | K::NetworkDown => IpeErrorKind::Network,
        K::AlreadyExists | K::DirectoryNotEmpty | K::AddrInUse => IpeErrorKind::Conflict,
        K::WouldBlock | K::ResourceBusy | K::ExecutableFileBusy => IpeErrorKind::Unavailable,
        K::TimedOut => IpeErrorKind::Timeout,
        K::InvalidInput
        | K::InvalidFilename
        | K::NotADirectory
        | K::IsADirectory
        | K::AddrNotAvailable => IpeErrorKind::InvalidInput,
        K::InvalidData => IpeErrorKind::Decode,
        K::FileTooLarge | K::QuotaExceeded | K::ArgumentListTooLong => IpeErrorKind::LimitExceeded,
        K::BrokenPipe
        | K::StaleNetworkFileHandle
        | K::Interrupted
        | K::WriteZero
        | K::UnexpectedEof
        | K::StorageFull
        | K::NotSeekable
        | K::Deadlock
        | K::CrossesDevices
        | K::TooManyLinks
        | K::Unsupported
        | K::OutOfMemory => IpeErrorKind::Io,
        _ => IpeErrorKind::Unexpected,
    }
}

/// The byte ceiling on a path shown in an [`IoFailure`] message.
const IO_FAILURE_PATH_MAX_BYTES: usize = 4096;

/// The byte ceiling on the host's reason shown in an [`IoFailure`] message.
const IO_FAILURE_REASON_MAX_BYTES: usize = 1024;

/// A host I/O failure, kinded by [`io_error_kind`] where it is built.
///
/// The message names the operation, the path it touched and the host's
/// reason, each passed through the runtime's log-hazard scrub so a control or
/// bidi character in a path shows as a visible escape. The value has no
/// conversion into `String`, so it cannot fall into the `From<String>` bridge
/// that yields `Unexpected`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IoFailure {
    kind: IpeErrorKind,
    message: String,
}

impl IoFailure {
    /// The failure of `operation` on `path`.
    #[must_use]
    pub fn on_path(operation: &str, path: &str, error: &std::io::Error) -> Self {
        Self {
            kind: io_error_kind(error.kind()),
            message: format!("{operation} {}: {}", shown_path(path), shown_reason(error)),
        }
    }

    /// The failure of `operation` from `from` to `to` (a copy or a rename).
    #[must_use]
    pub fn on_paths(operation: &str, from: &str, to: &str, error: &std::io::Error) -> Self {
        Self {
            kind: io_error_kind(error.kind()),
            message: format!(
                "{operation} {} to {}: {}",
                shown_path(from),
                shown_path(to),
                shown_reason(error)
            ),
        }
    }

    /// The failure of `operation`, which names no path (a standard stream).
    #[must_use]
    pub fn without_path(operation: &str, error: &std::io::Error) -> Self {
        Self {
            kind: io_error_kind(error.kind()),
            message: format!("{operation}: {}", shown_reason(error)),
        }
    }

    #[must_use]
    pub const fn kind(&self) -> IpeErrorKind {
        self.kind
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Prefixes the message with the failing operation, keeping the kind.
    #[must_use]
    pub fn context(self, operation: &str) -> Self {
        Self {
            kind: self.kind,
            message: format!("{operation}: {}", self.message),
        }
    }

    /// The failure in a generic error sink, under its classified kind.
    #[must_use]
    pub fn into_error<E: FromIpeError>(self) -> E {
        E::from_ipe_error(IpeError::from(self))
    }
}

impl From<IoFailure> for IpeError {
    fn from(failure: IoFailure) -> Self {
        Self::with(failure.kind, failure.message)
    }
}

/// A path as an [`IoFailure`] message shows it: scrubbed, capped and quoted.
///
/// The scrub never writes `\"`, so escaping the quote keeps the quoted span
/// unambiguous: a path cannot close its own quotes and spell a forged reason.
fn shown_path(path: &str) -> String {
    let scrubbed = crate::system::scrub_log_controls_capped(path, IO_FAILURE_PATH_MAX_BYTES);
    format!("\"{}\"", scrubbed.replace('"', "\\\""))
}

/// The host's reason as an [`IoFailure`] message shows it: scrubbed and capped.
fn shown_reason(error: &std::io::Error) -> String {
    crate::system::scrub_log_controls_capped(&error.to_string(), IO_FAILURE_REASON_MAX_BYTES)
}

/// An error sink that can carry every [`KernelFailure`] kind.
///
/// The one bound every generic kernel that lands a `KernelFailure` names, so a
/// new kind widens this trait, never each kernel's own bound list.
pub trait KernelErrorSink:
    From<String> + FromLimitExceeded + FromUnavailable + FromIpeError
{
}

impl<E> KernelErrorSink for E where
    E: From<String> + FromLimitExceeded + FromUnavailable + FromIpeError
{
}

/// A kernel failure whose kind is decided where it is built.
///
/// A bare `String` converts into `Unexpected`; a host I/O failure is built as
/// [`IoFailure`] under its classified kind; a ceiling refusal is built as
/// `LimitExceeded`, a wall-clock expiry as `Timeout`, and each keeps its kind
/// through `into_error`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KernelFailure {
    /// An unclassified failure (a library error with no host category).
    Unexpected(String),
    /// A declared ceiling turned the input back.
    LimitExceeded(LimitRefusal),
    /// A declared wall-clock ceiling ended the operation.
    TimedOut(TimeoutRefusal),
    /// The blocking pool could not start a thread for the operation.
    Unavailable(String),
    /// A host I/O failure, kinded by its category.
    Io(IoFailure),
    /// Malformed input a parser refused.
    Decode(String),
}

impl KernelFailure {
    #[must_use]
    pub fn message(&self) -> &str {
        match self {
            Self::Unexpected(message) | Self::Unavailable(message) | Self::Decode(message) => {
                message
            }
            Self::LimitExceeded(refusal) => refusal.message(),
            Self::TimedOut(refusal) => refusal.message(),
            Self::Io(failure) => failure.message(),
        }
    }

    /// Prefixes the message with the failing operation, keeping the kind.
    #[must_use]
    pub fn context(self, operation: &str) -> Self {
        match self {
            Self::Unexpected(message) => Self::Unexpected(format!("{operation}: {message}")),
            Self::LimitExceeded(refusal) => Self::LimitExceeded(refusal.context(operation)),
            Self::TimedOut(refusal) => Self::TimedOut(refusal.context(operation)),
            Self::Unavailable(message) => Self::Unavailable(format!("{operation}: {message}")),
            Self::Io(failure) => Self::Io(failure.context(operation)),
            Self::Decode(message) => Self::Decode(format!("{operation}: {message}")),
        }
    }

    /// The failure in a generic error sink, each variant under its own kind.
    #[must_use]
    pub fn into_error<E: KernelErrorSink>(self) -> E {
        match self {
            Self::Unexpected(message) => E::from(message),
            Self::LimitExceeded(refusal) => refusal.into_error(),
            Self::TimedOut(refusal) => refusal.into_error(),
            Self::Unavailable(message) => E::from_unavailable(message),
            Self::Io(failure) => failure.into_error(),
            Self::Decode(message) => E::from_ipe_error(IpeError::decode(message)),
        }
    }
}

impl From<TimeoutRefusal> for KernelFailure {
    fn from(refusal: TimeoutRefusal) -> Self {
        Self::TimedOut(refusal)
    }
}

impl From<String> for KernelFailure {
    fn from(message: String) -> Self {
        Self::Unexpected(message)
    }
}

impl From<IoFailure> for KernelFailure {
    fn from(failure: IoFailure) -> Self {
        Self::Io(failure)
    }
}

impl From<LimitRefusal> for KernelFailure {
    fn from(refusal: LimitRefusal) -> Self {
        Self::LimitExceeded(refusal)
    }
}

impl FromUnavailable for KernelFailure {
    fn from_unavailable(message: String) -> Self {
        Self::Unavailable(message)
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;

    /// Every classified host I/O category lands on its `ErrorKind`.
    #[test]
    fn io_categories_map_to_their_kind() {
        use IpeErrorKind as I;
        use std::io::ErrorKind as K;
        let table = [
            (K::NotFound, I::NotFound),
            (K::PermissionDenied, I::PermissionDenied),
            (K::ReadOnlyFilesystem, I::PermissionDenied),
            (K::ConnectionRefused, I::Network),
            (K::ConnectionReset, I::Network),
            (K::ConnectionAborted, I::Network),
            (K::NotConnected, I::Network),
            (K::HostUnreachable, I::Network),
            (K::NetworkUnreachable, I::Network),
            (K::NetworkDown, I::Network),
            (K::AlreadyExists, I::Conflict),
            (K::DirectoryNotEmpty, I::Conflict),
            (K::AddrInUse, I::Conflict),
            (K::WouldBlock, I::Unavailable),
            (K::ResourceBusy, I::Unavailable),
            (K::ExecutableFileBusy, I::Unavailable),
            (K::TimedOut, I::Timeout),
            (K::InvalidInput, I::InvalidInput),
            (K::InvalidFilename, I::InvalidInput),
            (K::NotADirectory, I::InvalidInput),
            (K::IsADirectory, I::InvalidInput),
            (K::AddrNotAvailable, I::InvalidInput),
            (K::InvalidData, I::Decode),
            (K::FileTooLarge, I::LimitExceeded),
            (K::QuotaExceeded, I::LimitExceeded),
            (K::ArgumentListTooLong, I::LimitExceeded),
            (K::BrokenPipe, I::Io),
            (K::StaleNetworkFileHandle, I::Io),
            (K::Interrupted, I::Io),
            (K::WriteZero, I::Io),
            (K::UnexpectedEof, I::Io),
            (K::StorageFull, I::Io),
            (K::NotSeekable, I::Io),
            (K::Deadlock, I::Io),
            (K::CrossesDevices, I::Io),
            (K::TooManyLinks, I::Io),
            (K::Unsupported, I::Io),
            (K::OutOfMemory, I::Io),
        ];
        for (host, kind) in table {
            assert_eq!(io_error_kind(host), kind, "{host:?}");
            let failure = IoFailure::without_path("op", &std::io::Error::from(host));
            assert_eq!(failure.kind(), kind, "{host:?}");
        }
    }

    /// A host category with no Ipê meaning stays `Unexpected`.
    #[test]
    fn unclassified_io_category_stays_unexpected() {
        assert_eq!(
            io_error_kind(std::io::ErrorKind::Other),
            IpeErrorKind::Unexpected
        );
        let failure = IoFailure::without_path("op", &std::io::Error::other("custom"));
        assert_eq!(failure.kind(), IpeErrorKind::Unexpected);
    }

    /// A missing file is `NotFound` and its message names the path.
    #[test]
    fn missing_path_is_not_found_and_named() {
        let missing = std::io::Error::from(std::io::ErrorKind::NotFound);
        let err = IpeError::from(IoFailure::on_path("read file", "/no/such.txt", &missing));
        let IpeError::Error(kind, info) = &err;
        assert_eq!(*kind, IpeErrorKind::NotFound);
        assert!(
            info.message.starts_with("read file \"/no/such.txt\": "),
            "{}",
            info.message
        );
    }

    /// A path's control characters and quotes show escaped, never raw.
    #[test]
    fn path_hazards_are_escaped() {
        let missing = std::io::Error::from(std::io::ErrorKind::NotFound);
        let failure = IoFailure::on_path("read file", "a\u{1b}[2J\n\"b", &missing);
        let message = failure.message();
        assert!(!message.contains('\u{1b}'), "{message}");
        assert!(!message.contains('\n'), "{message}");
        assert!(message.contains("\"a\\u{1b}[2J\\n\\\"b\""), "{message}");
        let two = IoFailure::on_paths("copy", "x\ry", "z", &missing);
        assert!(!two.message().contains('\r'), "{}", two.message());
    }

    /// A path past the display cap is cut and marked, never echoed whole.
    #[test]
    fn long_path_is_capped() {
        let missing = std::io::Error::from(std::io::ErrorKind::NotFound);
        let long = "p".repeat(IO_FAILURE_PATH_MAX_BYTES + 1);
        let failure = IoFailure::on_path("read file", &long, &missing);
        assert!(!failure.message().contains(&long));
        assert!(failure.message().contains(crate::system::SCRUB_TRUNCATED));
    }

    /// A decode failure lands as `Decode` in `IpeError` and verbatim in `String`.
    #[test]
    fn decode_failure_is_decode_kind() {
        let err = IpeError::from_decode_failure("bad".to_owned());
        assert_eq!(err.to_ipe_string(), "Decode: bad");
        assert_eq!(String::from_decode_failure("bad".to_owned()), "bad");
    }

    /// The `Io` and `Decode` kernel failures keep their kinds in the sink.
    #[test]
    fn kernel_failure_io_and_decode_keep_kind() {
        let missing = std::io::Error::from(std::io::ErrorKind::NotFound);
        let io: IpeError =
            KernelFailure::from(IoFailure::on_path("read", "f", &missing)).into_error();
        let IpeError::Error(kind, _) = &io;
        assert_eq!(*kind, IpeErrorKind::NotFound);
        let decode: IpeError = KernelFailure::Decode("bad row".to_owned()).into_error();
        assert_eq!(decode.to_ipe_string(), "Decode: bad row");
    }

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
        for kind in IpeErrorKind::ALL {
            let e = IpeError::with(kind, String::new());
            let expected = matches!(
                kind,
                IpeErrorKind::Timeout | IpeErrorKind::Network | IpeErrorKind::Unavailable
            );
            assert_eq!(e.is_retryable(), expected, "{kind:?}");
        }
        assert!(!IpeError::limit_exceeded("x").is_retryable());
        assert!(!IpeError::update_required("x").is_retryable());
    }

    #[test]
    fn kinds_are_append_only_with_stable_discriminants() {
        let pinned: [(IpeErrorKind, u8, &str); 13] = [
            (IpeErrorKind::Io, 0, "Io"),
            (IpeErrorKind::Network, 1, "Network"),
            (IpeErrorKind::Ffi, 2, "Ffi"),
            (IpeErrorKind::Decode, 3, "Decode"),
            (IpeErrorKind::Timeout, 4, "Timeout"),
            (IpeErrorKind::NotFound, 5, "NotFound"),
            (IpeErrorKind::PermissionDenied, 6, "PermissionDenied"),
            (IpeErrorKind::InvalidInput, 7, "InvalidInput"),
            (IpeErrorKind::Conflict, 8, "Conflict"),
            (IpeErrorKind::Unavailable, 9, "Unavailable"),
            (IpeErrorKind::Unexpected, 10, "Unexpected"),
            (IpeErrorKind::LimitExceeded, 11, "LimitExceeded"),
            (IpeErrorKind::UpdateRequired, 12, "UpdateRequired"),
        ];
        assert_eq!(IpeErrorKind::ALL.len(), pinned.len());
        for (index, (kind, discriminant, label)) in pinned.into_iter().enumerate() {
            assert_eq!(IpeErrorKind::ALL.get(index), Some(&kind));
            assert_eq!(kind as u8, discriminant);
            assert_eq!(kind.label(), label);
        }
        let mut labels: Vec<&str> = IpeErrorKind::ALL.iter().map(|k| k.label()).collect();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), IpeErrorKind::ALL.len(), "label is injective");
    }

    #[test]
    fn limit_exceeded_carries_its_kind_and_prefix() {
        let e = ipe_error_limit_exceeded("x".to_owned());
        assert_eq!(ipe_error_kind(e.clone()), IpeErrorKind::LimitExceeded);
        assert_eq!(e.to_ipe_string(), "LimitExceeded: x");
        assert!(!ipe_error_is_retryable(e.clone()));
        assert_eq!(
            <IpeError as FromLimitExceeded>::from_limit_exceeded("x".to_owned()),
            e
        );
        assert_eq!(
            ipe_error_kind_name(IpeErrorKind::LimitExceeded),
            "LimitExceeded"
        );
        let bridged = IpeError::from("file exceeds read ceiling of 4 bytes".to_owned());
        assert_eq!(
            ipe_error_kind(bridged),
            IpeErrorKind::Unexpected,
            "the bare-String bridge never classifies a ceiling"
        );
    }

    #[test]
    fn update_required_carries_its_kind_and_prefix() {
        let e = IpeError::update_required("x");
        assert_eq!(ipe_error_kind(e.clone()), IpeErrorKind::UpdateRequired);
        assert_eq!(e.to_ipe_string(), "UpdateRequired: x");
        assert!(!ipe_error_is_retryable(e));
        assert_eq!(
            ipe_error_kind_name(IpeErrorKind::UpdateRequired),
            "UpdateRequired"
        );
    }

    #[test]
    fn kernel_failure_keeps_each_kind_through_a_generic_sink() {
        let limit = KernelFailure::from(LimitRefusal::new("over 4 bytes")).context("Op");
        let other = KernelFailure::from("disk gone".to_owned()).context("Op");
        let refused = KernelFailure::from_unavailable("no thread".to_owned()).context("Op");
        assert_eq!(
            refused.into_error::<IpeError>().to_ipe_string(),
            "Unavailable: Op: no thread"
        );
        assert_eq!(limit.message(), "Op: over 4 bytes");
        assert_eq!(
            limit.into_error::<IpeError>().to_ipe_string(),
            "LimitExceeded: Op: over 4 bytes"
        );
        assert_eq!(
            other.into_error::<IpeError>().to_ipe_string(),
            "Unexpected: Op: disk gone"
        );
        assert_eq!(
            IpeError::from(LimitRefusal::new("x")),
            IpeError::limit_exceeded("x")
        );
        let expired =
            KernelFailure::from(TimeoutRefusal::new("still running after 1s")).context("Op");
        assert_eq!(expired.message(), "Op: still running after 1s");
        assert_eq!(
            expired.clone().into_error::<IpeError>().to_ipe_string(),
            "Timeout: Op: still running after 1s"
        );
        assert_eq!(
            expired.into_error::<String>(),
            "Timeout: Op: still running after 1s",
            "a bare String sink keeps the kinded text"
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn kinds_round_trip_through_serde_by_variant_name() {
        for kind in IpeErrorKind::ALL {
            let wire = serde_json::to_string(&kind).expect("serialize");
            assert_eq!(wire, format!("\"{}\"", kind.label()));
            let back: IpeErrorKind = serde_json::from_str(&wire).expect("deserialize");
            assert_eq!(back, kind);
        }
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
    fn error_details_round_trips_every_variant() {
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
            IpeErrorDetails::Database(IpeDbFailure::UniqueViolation),
        ];
        for details in cases {
            let e = IpeError::unexpected("boom".to_owned()).with_details(details.clone());
            let IpeError::Error(_, info) = &e;
            assert_eq!(info.details, IpeMaybe::Just(details));
        }
    }

    #[test]
    fn db_failure_kind_table_is_exact() {
        use IpeDbFailure as F;
        let expected = [
            (F::UniqueViolation, IpeErrorKind::Conflict),
            (F::ForeignKeyViolation, IpeErrorKind::Conflict),
            (F::NotNullViolation, IpeErrorKind::Conflict),
            (F::CheckViolation, IpeErrorKind::Conflict),
            (F::TriggerRaised, IpeErrorKind::Conflict),
            (F::OtherConstraint, IpeErrorKind::Conflict),
            (F::Busy, IpeErrorKind::Unavailable),
            (F::ReadOnlyDatabase, IpeErrorKind::PermissionDenied),
            (F::AccessDenied, IpeErrorKind::PermissionDenied),
            (F::CannotOpen, IpeErrorKind::NotFound),
            (F::NotADatabase, IpeErrorKind::Unexpected),
            (F::InvalidStatement, IpeErrorKind::Unexpected),
            (F::Unreachable, IpeErrorKind::Unavailable),
            (F::OtherFailure, IpeErrorKind::Unexpected),
        ];
        assert_eq!(expected.len(), IpeDbFailure::ALL.len());
        for (failure, kind) in expected {
            assert_eq!(failure.kind(), kind, "{failure:?}");
        }
    }

    #[test]
    fn db_failure_all_and_ctor_names_are_distinct() {
        let mut seen = std::collections::HashSet::new();
        let mut names = std::collections::HashSet::new();
        for (index, failure) in IpeDbFailure::ALL.into_iter().enumerate() {
            assert_eq!(failure as usize, index, "{failure:?} out of order in ALL");
            assert!(seen.insert(failure), "{failure:?} listed twice");
            assert!(names.insert(failure.ctor_name()), "{failure:?} name reused");
            assert!(!failure.phrase().is_empty(), "{failure:?} has no phrase");
        }
        assert_eq!(names.len(), IpeDbFailure::ALL.len());
    }

    #[test]
    fn db_failure_ctor_names_round_trip() {
        for failure in IpeDbFailure::ALL {
            let back = IpeDbFailure::ALL
                .into_iter()
                .find(|f| f.ctor_name() == failure.ctor_name());
            assert_eq!(back, Some(failure));
        }
    }

    #[test]
    fn auth_error_all_and_ctor_names_are_in_declaration_order() {
        use IpeAuthError as A;
        let expected = [
            (A::Malformed, "Malformed"),
            (A::BadSignature, "BadSignature"),
            (A::Expired, "Expired"),
            (A::NotYetValid, "NotYetValid"),
            (A::MissingClaim, "MissingClaim"),
            (A::Revoked, "Revoked"),
            (A::RevocationUnavailable, "RevocationUnavailable"),
            (A::TooManyCredentials, "TooManyCredentials"),
            (A::SecretTooShort, "SecretTooShort"),
        ];
        assert_eq!(expected.len(), IpeAuthError::ALL.len());
        let mut names = std::collections::HashSet::new();
        for (index, ((variant, name), listed)) in
            expected.into_iter().zip(IpeAuthError::ALL).enumerate()
        {
            assert_eq!(variant, listed, "{variant:?} out of order in ALL");
            assert_eq!(variant as usize, index, "{variant:?} discriminant");
            assert_eq!(variant.ctor_name(), name);
            assert!(names.insert(name), "{variant:?} name reused");
            assert!(!variant.phrase().is_empty(), "{variant:?} has no phrase");
        }
    }

    #[test]
    fn nullary_rows_mirror_all() {
        assert_eq!(IpeAuthError::ROWS.len(), IpeAuthError::ALL.len());
        for ((name, index), variant) in IpeAuthError::ROWS.into_iter().zip(IpeAuthError::ALL) {
            assert_eq!(name, variant.ctor_name());
            assert_eq!(index, variant as usize);
        }
        assert_eq!(IpeDbFailure::ROWS.len(), IpeDbFailure::ALL.len());
        for ((name, index), failure) in IpeDbFailure::ROWS.into_iter().zip(IpeDbFailure::ALL) {
            assert_eq!(name, failure.ctor_name());
            assert_eq!(index, failure as usize);
        }
    }

    #[test]
    fn database_constructor_derives_kind_and_details() {
        let e = IpeError::database(
            IpeDbFailure::ReadOnlyDatabase,
            "db: database is read-only".to_owned(),
        );
        let IpeError::Error(kind, info) = &e;
        assert_eq!(*kind, IpeErrorKind::PermissionDenied);
        assert_eq!(
            info.details,
            IpeMaybe::Just(IpeErrorDetails::Database(IpeDbFailure::ReadOnlyDatabase))
        );
        assert_eq!(info.message, "db: database is read-only");
    }
}
