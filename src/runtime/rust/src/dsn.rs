//! `Ipe.Db.Dsn` — a typed, opaque database connection descriptor
//! (parse-don't-validate).
//!
//! The ONLY way to obtain a `Dsn` is through [`dsn_parse`] (from a URL string) or
//! [`dsn_build`] (from typed parts). Both enforce the same invariants on what
//! they admit — known driver, bounded control-free parts, in-range port, no
//! cleartext transport, no password without a user name — so a `Dsn` value is
//! a proof that the connection descriptor passed every fail-closed check.
//! There is no un-parsed way to construct one.
//!
//! A `Dsn` deliberately stores its password as a [`Secret`], never a plain
//! `String`: the descriptor's most sensitive field cannot be `Debug`-printed,
//! `Display`-rendered, logged, or echoed into an error. The `Debug` impl below is
//! hand-written to redact the whole struct, and no accessor returns the password
//! as a plain `String` — only the reserved `Secret` surface (`Secret.use` /
//! `Secret.redacted`) may touch it.
//!
//! # Trust model — what `Dsn` does and does NOT guarantee
//!
//! A `Dsn` guarantees the descriptor is structurally valid and TLS-secure: a
//! known driver, a present host for a network driver, an in-range port, no
//! control characters in any component, and a transport that is not explicitly
//! downgraded to cleartext (`sslmode=disable` is a hard parse error). It
//! deliberately does NOT decide whether the host is safe to REACH — that is the
//! separate authority of the connect step (a future slice), which owns the
//! `network` capability and any SSRF-style host policy. `Dsn` is the syntactic
//! parse boundary; connecting is a distinct, separately-reviewed act.

use super::IpeResult;
use crate::encoding::{UrlGrammar, decode_component};
use crate::secret::{Secret, secret_from_string};
use crate::ssrf::{ConfiguredHost, DriverParityQuery, UnambiguousUrl};

/// The closed set of drivers the runtime can describe. Exactly the two sqlx
/// drivers the `db` feature links (`sqlite`, `postgres`); a driver the runtime
/// cannot dial is unrepresentable here rather than a free string the parser would
/// have to string-compare.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DsnDriver {
    Postgres,
    Sqlite,
}

/// The transport-security posture. `Require`/`Prefer` are the two accepted modes;
/// `Disable` exists for exhaustiveness and a future explicitly-disclosed
/// opt-in, but the parse path REJECTS it — a `Dsn` is never a proof of a
/// cleartext transport.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsMode {
    Require,
    Prefer,
    Disable,
}

/// A DSN's network host, proven not to be part of its credentials.
///
/// Built only inside this module: by [`dsn_parse`] from the host of a URL it
/// first proves unambiguous (`UnambiguousUrl`), by [`dsn_build`] from a host
/// part holding no URL delimiter, or empty for file-backed SQLite. It carries a
/// [`ConfiguredHost`], the only host an SSRF refusal names, so a refusal for a
/// DSN's host can never echo part of its user name or password.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DsnHost(ConfiguredHost);

impl DsnHost {
    /// No network host: a file-backed SQLite descriptor.
    const fn none() -> Self {
        Self(ConfiguredHost::from_config(String::new()))
    }

    /// The host of `url`, whose userinfo is proven unambiguous.
    fn of_url(url: &UnambiguousUrl) -> Option<Self> {
        url.host().map(Self)
    }

    /// A host given as its own part, parsed as a host name or IP literal.
    ///
    /// Refused when it holds a character that would end or split a URL
    /// authority it is written into, or a port. Kept in the form the URL
    /// parser writes it, so the SSRF gate vets the host the driver dials.
    fn of_part(host: &str) -> Option<Self> {
        if host.contains(['@', '/', '?', '#', '\\', '%']) {
            return None;
        }
        ::url::Host::parse(host)
            .ok()
            .map(|parsed| Self(ConfiguredHost::from_config(parsed.to_string())))
    }

    /// The host as an SSRF refusal may name it.
    pub(crate) const fn configured(&self) -> &ConfiguredHost {
        &self.0
    }

    /// The host text (`""` for file-backed SQLite).
    #[must_use]
    pub const fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// A PostgreSQL user name or database name.
///
/// Holds its decoded text and reaches a connection URL only percent-encoded
/// ([`DsnPart::encoded`]), so no character in it can end the component it sits
/// in and add URL syntax such as a `sslmode` parameter. A user name is
/// credential-adjacent, so it has no derived (early-exit) equality.
#[derive(Clone, Debug)]
struct DsnPart(String);

impl DsnPart {
    /// A part written percent-encoded in a URL, held decoded.
    fn of_encoded(encoded: &str) -> Option<Self> {
        Self::of_text(decode_component(encoded, UrlGrammar::Path).ok()?)
    }

    /// A part given as its own literal text.
    fn of_text(text: String) -> Option<Self> {
        text_ok(&text).then_some(Self(text))
    }

    /// The text as held.
    const fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// The text percent-encoded for a URL component.
    fn encoded(&self) -> String {
        percent_encode(&self.0)
    }
}

/// `text` with every byte but an ASCII letter or digit percent-encoded.
fn percent_encode(text: &str) -> String {
    percent_encoding::utf8_percent_encode(text, percent_encoding::NON_ALPHANUMERIC).to_string()
}

/// The bytes a SQLite file name is percent-encoded for in its connection URL.
///
/// The driver's URL reader cuts the path at the first `?`, strips repeated
/// `sqlite:` prefixes, and percent-decodes the rest, so every byte but an
/// ASCII letter, digit, `/`, `.`, `-`, `_` or `~` is encoded: `?`, `:` and `%`
/// cannot act, and a URL parser finds no userinfo, port, or query in the path.
const SQLITE_PATH_ENCODE: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
    .remove(b'/')
    .remove(b'.')
    .remove(b'-')
    .remove(b'_')
    .remove(b'~');

/// The SQLite file name of the in-memory database.
const SQLITE_MEMORY: &str = ":memory:";

/// The SQLite database a DSN opens.
///
/// Built only by [`SqliteDb::of_name`], so a file name never starts with
/// `file:` (which SQLite would read as a URI whose parameters choose the open
/// mode) and is never `:memory:`.
#[derive(Clone, Debug, PartialEq, Eq)]
enum SqliteDb {
    /// SQLite's private in-memory database, named `:memory:`.
    Memory,
    /// A database file, held as its literal file name.
    File(String),
}

impl SqliteDb {
    /// The database a literal file name opens.
    ///
    /// `:memory:` names the in-memory database; a name starting `file:` is
    /// refused.
    fn of_name(name: String) -> Option<Self> {
        if !text_ok(&name) || name.starts_with("file:") {
            None
        } else if name == SQLITE_MEMORY {
            Some(Self::Memory)
        } else {
            Some(Self::File(name))
        }
    }

    /// The database named by the text of a SQLite DSN after its scheme.
    ///
    /// Read as a single scheme, one optional `//`, and the path up to the
    /// first `?`, percent-decoded under the path grammar. The only query
    /// admitted is `mode=rwc`, the mode the connection pins; every query pair
    /// is decoded under the form grammar, so a malformed escape is refused.
    fn of_dsn_rest(rest: &str) -> Result<Self, DsnReject> {
        let rest = rest.strip_prefix("//").unwrap_or(rest);
        let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
        let pinned_only = query
            .split('&')
            .filter(|pair| !pair.is_empty())
            .all(|pair| {
                let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
                decode_component(key, UrlGrammar::Form).is_ok_and(|key| key == "mode")
                    && decode_component(value, UrlGrammar::Form).is_ok_and(|value| value == "rwc")
            });
        if !pinned_only {
            return Err(DsnReject::ConflictingParameter);
        }
        if path.len() > MAX_COMPONENT_LEN {
            return Err(DsnReject::InvalidComponent);
        }
        decode_component(path, UrlGrammar::Path)
            .ok()
            .and_then(Self::of_name)
            .ok_or(DsnReject::InvalidComponent)
    }

    /// The literal file name (`:memory:` for the in-memory database).
    const fn name(&self) -> &str {
        match self {
            Self::Memory => SQLITE_MEMORY,
            Self::File(name) => name.as_str(),
        }
    }

    /// The connection URL the driver opens.
    ///
    /// A file is opened `mode=rwc` (created when missing), its name
    /// percent-encoded so the driver decodes it back exactly and no character
    /// in it adds or overrides a parameter.
    fn connection_url(&self) -> String {
        match self {
            Self::Memory => format!("sqlite:{SQLITE_MEMORY}"),
            Self::File(name) => format!(
                "sqlite://{}?mode=rwc",
                percent_encoding::utf8_percent_encode(name, SQLITE_PATH_ENCODE)
            ),
        }
    }
}

/// A connection's credentials: a user name and, optionally, its password.
///
/// A password is held only beside the user name it belongs to, so a password
/// with no user name has no representation.
#[derive(Clone, Debug)]
struct Credentials {
    user: DsnPart,
    /// `None` when the password is empty.
    password: Option<Secret>,
}

impl Credentials {
    /// The credentials of an optional user name and a literal password.
    ///
    /// `None` when both are empty. A password longer than
    /// [`MAX_COMPONENT_LEN`] bytes, or one with no user name, is refused.
    fn of_parts(user: Option<DsnPart>, password: Secret) -> Result<Option<Self>, DsnReject> {
        if password.byte_len() > MAX_COMPONENT_LEN {
            return Err(DsnReject::InvalidComponent);
        }
        let password = (password.byte_len() > 0).then_some(password);
        match (user, password) {
            (Some(user), password) => Ok(Some(Self { user, password })),
            (None, None) => Ok(None),
            (None, Some(_)) => Err(DsnReject::PasswordWithoutUser),
        }
    }
}

/// What a DSN connects to, per driver.
#[derive(Clone, Debug)]
enum DsnTarget {
    /// A PostgreSQL database name.
    Postgres(DsnPart),
    /// A SQLite database.
    Sqlite(SqliteDb),
}

/// `Ipe.Db.Dsn`'s opaque, validated descriptor. Every field is the result of a
/// fail-closed parse; the password is a [`Secret`] so the struct cannot leak it.
///
/// `Debug` is hand-written (below) to redact the whole value; `Clone` is safe
/// (cloning observes no plaintext — `Secret`'s own `Clone` does not reveal the
/// payload). No `Display`/`IpeStringify` is derived: a `Dsn` is only ever
/// rendered through its explicit redacted form.
#[derive(Clone)]
pub struct Dsn {
    target: DsnTarget,
    host: DsnHost,
    port: u16,
    credentials: Option<Credentials>,
    tls: TlsMode,
}

impl std::fmt::Debug for Dsn {
    /// Redact the whole descriptor. The password is already a `Secret` (its own
    /// `Debug` is the fixed placeholder), but the struct-level impl stays
    /// conservative: a `dbg!(dsn)` left in shipped code prints only the
    /// non-secret shape, never the credential.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dsn")
            .field("target", &self.target)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("credentials", &self.credentials)
            .field("tls", &self.tls)
            .finish()
    }
}

/// A structural, credential-free rejection reason. Its `Display` NEVER embeds the
/// offending DSN string or any credential — only the category of failure — so a
/// parse `Err` surfaced or logged by the caller cannot echo a pasted password.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DsnReject {
    Unparseable,
    UnknownDriver,
    MissingHost,
    InvalidPort,
    TlsDisabled,
    UnknownSslMode,
    ConflictingParameter,
    InvalidComponent,
    AmbiguousUserinfo,
    PasswordWithoutUser,
    TooLong,
}

impl DsnReject {
    /// The value-free message. Every arm is a fixed, credential-free string; the
    /// input is never interpolated, so the rejection cannot leak a pasted secret.
    fn message(self) -> &'static str {
        match self {
            Self::Unparseable => "Ipe.Db.Dsn: cannot parse DSN",
            Self::UnknownDriver => "Ipe.Db.Dsn: unknown driver",
            Self::MissingHost => "Ipe.Db.Dsn: missing host",
            Self::InvalidPort => "Ipe.Db.Dsn: invalid port",
            Self::TlsDisabled => "Ipe.Db.Dsn: TLS disabled is not permitted",
            Self::UnknownSslMode => "Ipe.Db.Dsn: unknown sslmode",
            Self::ConflictingParameter => "Ipe.Db.Dsn: conflicting or misplaced parameter",
            Self::InvalidComponent => "Ipe.Db.Dsn: invalid DSN component",
            Self::PasswordWithoutUser => "Ipe.Db.Dsn: a password needs a user name",
            Self::TooLong => "Ipe.Db.Dsn: DSN exceeds the length limit",
            Self::AmbiguousUserinfo => {
                "Ipe.Db.Dsn: the user name or password may run past the URL's authority: \
                 percent-encode `/`, `?`, `#`, `@` and `\\` in them, and write `@` \
                 elsewhere as `%40`"
            }
        }
    }
}

fn reject<E: From<String>>(r: DsnReject) -> IpeResult<E, Dsn> {
    IpeResult::Err(r.message().to_owned().into())
}

/// A generous-but-bounded length cap for any single DSN component (host, user,
/// password, database). Guards the oversize-allocation vector without
/// rejecting any real identifier.
const MAX_COMPONENT_LEN: usize = 512;

/// The length cap, in bytes, of a whole DSN string given to [`dsn_parse`].
const MAX_DSN_LEN: usize = 4096;

/// True when `s` is safe to carry as a DSN component: no control characters, no
/// embedded null, no leading/trailing/interior whitespace, and within the length
/// bound — checked on the PERCENT-DECODED form, so a `%0a`/`%00` that decodes to a
/// control byte is rejected too. Rejecting whitespace and control bytes closes the
/// injection/smuggling vector before any component is trusted. A malformed escape
/// or decoded bytes that are not UTF-8 are rejected as well.
fn component_ok(s: &str) -> bool {
    s.len() <= MAX_COMPONENT_LEN
        && decode_component(s, UrlGrammar::Path).is_ok_and(|decoded| text_ok(&decoded))
}

/// True when `s`, taken literally, is non-empty, within the length bound, and
/// free of control characters and whitespace.
fn text_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_COMPONENT_LEN
        && !s.chars().any(|c| c.is_control() || c.is_whitespace())
}

/// True when `s` names the Postgres driver.
fn driver_is_postgres(scheme: &str) -> bool {
    matches!(scheme, "postgres" | "postgresql")
}

/// True when `s` names the Sqlite driver.
fn driver_is_sqlite(scheme: &str) -> bool {
    matches!(scheme, "sqlite" | "file")
}

/// Parse an `sslmode` token into a `TlsMode`, or a rejection. `disable` is a
/// hard reject (a downgraded transport is not a value the parser mints); an
/// unrecognised token is fail-closed, never coerced to a permissive default.
fn parse_sslmode(token: &str) -> Result<TlsMode, DsnReject> {
    match token {
        "require" => Ok(TlsMode::Require),
        "prefer" => Ok(TlsMode::Prefer),
        "disable" => Err(DsnReject::TlsDisabled),
        _ => Err(DsnReject::UnknownSslMode),
    }
}

/// Read the TLS posture from a URL's query pairs, applying the SECURE DEFAULT
/// (`Require`) when no `sslmode` is present. A `password=` in the query string, a
/// duplicated `sslmode` with differing values, or any of the credential-smuggling
/// shapes is a `ConflictingParameter` rejection: the password must arrive through
/// the structured userinfo, never a re-parseable query segment.
fn tls_from_query(url: &UnambiguousUrl) -> Result<TlsMode, DsnReject> {
    let mut chosen: Option<TlsMode> = None;
    for (key, value) in DriverParityQuery::of(url).pairs() {
        match key.as_ref() {
            "password" | "user" | "username" => {
                // Credential smuggled into the query string — reject; credentials
                // belong in the structured userinfo only.
                return Err(DsnReject::ConflictingParameter);
            }
            "sslmode" => {
                let mode = parse_sslmode(value.as_ref())?;
                match chosen {
                    Some(prev) if prev != mode => {
                        // Two different answers to "is TLS on" — ambiguity is
                        // fail-closed.
                        return Err(DsnReject::ConflictingParameter);
                    }
                    _ => chosen = Some(mode),
                }
            }
            _ => {}
        }
    }
    Ok(chosen.unwrap_or(TlsMode::Require))
}

/// `Ipe.Db.Dsn.parse : String -> Result Error Dsn` — THE seal from a full URL
/// string. Every `Dsn` built this way traces back to one call, so a reviewer can
/// grep this one symbol to audit every place a raw string becomes a descriptor.
///
/// Fails closed on all of: an unparseable string; an unknown driver scheme; a
/// missing host for a network driver; an out-of-range/non-numeric port; an
/// explicit `sslmode=disable`; an unknown `sslmode`; a credential or duplicated
/// security key smuggled into the query; a PostgreSQL URL whose user name or
/// password may run past its authority (`crate::ssrf::userinfo_is_ambiguous`);
/// and a control-character/oversized component. The password is captured as a
/// `Secret`, never a plain `String`.
///
/// A SQLite DSN names its file as [`SqliteDb::of_dsn_rest`] reads it;
/// credentials, any query but `mode=rwc`, and a file name starting `file:` are
/// refused. A password with no user name, a password over
/// [`MAX_COMPONENT_LEN`] bytes, and a DSN over [`MAX_DSN_LEN`] bytes are
/// refused.
#[must_use]
pub fn dsn_parse<E: From<String>>(s: String) -> IpeResult<E, Dsn> {
    if s.len() > MAX_DSN_LEN {
        return reject(DsnReject::TooLong);
    }
    let parsed = match ::url::Url::parse(&s) {
        Ok(u) => u,
        Err(_) => return reject(DsnReject::Unparseable),
    };

    let scheme = parsed.scheme();
    let driver = if driver_is_postgres(scheme) {
        DsnDriver::Postgres
    } else if driver_is_sqlite(scheme) {
        DsnDriver::Sqlite
    } else {
        return reject(DsnReject::UnknownDriver);
    };

    // Sqlite is a local file driver: the "host" is empty and the database is the
    // file path. Postgres is a network driver: a host is mandatory.
    let (host, port, target, tls) = match driver {
        DsnDriver::Postgres => {
            // A credential holding an unencoded `/`, `?`, `#` or `\` ends the
            // authority early, so the parser would read part of it as the host.
            let Some(url) = UnambiguousUrl::of_parsed(&s, parsed.clone()) else {
                return reject(DsnReject::AmbiguousUserinfo);
            };
            let tls = match tls_from_query(&url) {
                Ok(t) => t,
                Err(r) => return reject(r),
            };
            let Some(host) = DsnHost::of_url(&url) else {
                return reject(DsnReject::MissingHost);
            };
            if !component_ok(host.as_str()) {
                return reject(DsnReject::InvalidComponent);
            }
            // Postgres' well-known default; an omitted port is not an error.
            let port = parsed.port().unwrap_or(5432);
            let Some(database) = DsnPart::of_encoded(parsed.path().trim_start_matches('/')) else {
                return reject(DsnReject::InvalidComponent);
            };
            (host, port, DsnTarget::Postgres(database), tls)
        }
        DsnDriver::Sqlite => {
            // A file-backed sqlite DSN has no network host, port, or
            // credentials; everything after the scheme names the database.
            if !parsed.username().is_empty() || parsed.password().is_some() {
                return reject(DsnReject::ConflictingParameter);
            }
            // The query admits only `mode=rwc` (`SqliteDb::of_dsn_rest`), so
            // no `sslmode` can be present and the posture is the secure default.
            let rest = s.split_once(':').map_or("", |(_, rest)| rest);
            match SqliteDb::of_dsn_rest(rest) {
                Ok(db) => (DsnHost::none(), 0, DsnTarget::Sqlite(db), TlsMode::Require),
                Err(r) => return reject(r),
            }
        }
    };

    // The username may legitimately be empty (sqlite, or a Postgres DSN relying on
    // a default role); when present it must be a clean component.
    let user = match parsed.username() {
        "" => None,
        encoded => {
            let Some(user) = DsnPart::of_encoded(encoded) else {
                return reject(DsnReject::InvalidComponent);
            };
            Some(user)
        }
    };

    // Held decoded, as the user name is, so the connection URL encodes it once.
    let Ok(password) = decode_component(parsed.password().unwrap_or(""), UrlGrammar::Path) else {
        return reject(DsnReject::InvalidComponent);
    };
    let password = secret_from_string(password);
    let credentials = match Credentials::of_parts(user, password) {
        Ok(credentials) => credentials,
        Err(r) => return reject(r),
    };

    IpeResult::Ok(Dsn {
        target,
        host,
        port,
        credentials,
        tls,
    })
}

/// `Ipe.Db.Dsn.build` — THE seal from typed parts.
///
/// Enforces the invariants [`dsn_parse`] does, on literal parts rather than
/// URL text: the host is parsed as a host name or IP literal, the other parts
/// must be bounded and control-free, a password needs a user name, and a
/// SQLite descriptor takes no host or credentials. `driver`/`tls` arrive
/// already as closed tags; `port` is validated
/// into `1..=65535` (no narrowing cast); `password` is a `Secret` on the way in.
/// The database name, user name, and password are taken literally: the
/// connection URL percent-encodes them, so none of them can add URL syntax. A
/// SQLite database is a file name, `:memory:` for the in-memory database; one
/// starting `file:` is refused.
///
/// The driver/TLS tags are passed as their small-integer discriminants
/// (`0 = Postgres`, `1 = Sqlite`; `0 = Require`, `1 = Prefer`, `2 = Disable`),
/// which is how the emitted ADT constructors marshal. An out-of-set discriminant
/// is a rejection rather than a panic.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn dsn_build<E: From<String>>(
    driver_tag: i64,
    host: String,
    port: i64,
    database: String,
    user: String,
    password: Secret,
    tls_tag: i64,
) -> IpeResult<E, Dsn> {
    let driver = match driver_tag {
        0 => DsnDriver::Postgres,
        1 => DsnDriver::Sqlite,
        _ => return reject(DsnReject::UnknownDriver),
    };
    let tls = match tls_tag {
        0 => TlsMode::Require,
        1 => TlsMode::Prefer,
        2 => TlsMode::Disable,
        _ => return reject(DsnReject::UnknownSslMode),
    };
    if tls == TlsMode::Disable {
        // A downgraded transport is never a value the seal mints.
        return reject(DsnReject::TlsDisabled);
    }

    // Port must be proven in range; no `as u16` narrowing (that truncation is
    // itself the bug being banned). Sqlite carries no port (0 is the sentinel).
    let port_u16: u16 = match driver {
        DsnDriver::Sqlite => 0,
        DsnDriver::Postgres => match u16::try_from(port) {
            Ok(p) if p >= 1 => p,
            _ => return reject(DsnReject::InvalidPort),
        },
    };

    let host = match driver {
        DsnDriver::Postgres => {
            if !component_ok(&host) {
                return reject(DsnReject::InvalidComponent);
            }
            let Some(host) = DsnHost::of_part(&host) else {
                return reject(DsnReject::InvalidComponent);
            };
            host
        }
        DsnDriver::Sqlite => {
            // Sqlite has no network host; a non-empty host is a misuse.
            if !host.is_empty() {
                return reject(DsnReject::InvalidComponent);
            }
            DsnHost::none()
        }
    };
    let target = match driver {
        DsnDriver::Postgres => DsnPart::of_text(database).map(DsnTarget::Postgres),
        DsnDriver::Sqlite => SqliteDb::of_name(database).map(DsnTarget::Sqlite),
    };
    let Some(target) = target else {
        return reject(DsnReject::InvalidComponent);
    };
    let user = if user.is_empty() {
        None
    } else {
        let Some(user) = DsnPart::of_text(user) else {
            return reject(DsnReject::InvalidComponent);
        };
        Some(user)
    };
    let credentials = match Credentials::of_parts(user, password) {
        Ok(credentials) => credentials,
        Err(r) => return reject(r),
    };
    if driver == DsnDriver::Sqlite && credentials.is_some() {
        // A SQLite file is opened with no credentials; a user name or password
        // for one is a misuse.
        return reject(DsnReject::InvalidComponent);
    }

    IpeResult::Ok(Dsn {
        target,
        host,
        port: port_u16,
        credentials,
        tls,
    })
}

impl Dsn {
    /// The driver this descriptor names, for the connect step's dialect
    /// selection. Crate-internal: only the external-connection module reads it.
    pub(crate) const fn driver(&self) -> DsnDriver {
        match &self.target {
            DsnTarget::Postgres(_) => DsnDriver::Postgres,
            DsnTarget::Sqlite(_) => DsnDriver::Sqlite,
        }
    }

    /// The database name or SQLite file name.
    fn database(&self) -> &str {
        match &self.target {
            DsnTarget::Postgres(database) => database.as_str(),
            DsnTarget::Sqlite(db) => db.name(),
        }
    }

    /// The network host this descriptor names. Empty for file-backed SQLite
    /// (no network host). Crate-internal: used by the connect step to apply
    /// the SSRF host gate before dialing.
    pub(crate) const fn host(&self) -> &DsnHost {
        &self.host
    }

    /// The port this descriptor names. Zero for file-backed SQLite (no port).
    /// Crate-internal: used alongside [`Dsn::host`] for the SSRF host gate.
    pub(crate) fn port(&self) -> u16 {
        self.port
    }

    /// Reconstruct the connection URL the sqlx driver dials, consuming the
    /// password `Secret` at the point of use (never stored back as plaintext).
    /// The result is a live credential-bearing string; it is handed straight to
    /// the sqlx connector and dropped, never logged or returned to Ipê.
    ///
    /// For Postgres the user name, password, and database are percent-encoded,
    /// so the only query is the `sslmode` written here: the TLS posture is
    /// folded into it so the parsed secure default (`Require`/`Prefer`) survives
    /// the round-trip; `Disable` is unrepresentable (the parse/build path
    /// rejected it). For Sqlite see [`SqliteDb::connection_url`].
    pub(crate) fn connection_url(&self) -> String {
        match &self.target {
            DsnTarget::Sqlite(db) => db.connection_url(),
            DsnTarget::Postgres(database) => {
                let sslmode = match self.tls {
                    TlsMode::Require => "require",
                    TlsMode::Prefer => "prefer",
                    // Unreachable: a `Dsn` never carries `Disable`. Fall back to
                    // the strongest posture rather than emitting a downgrade.
                    TlsMode::Disable => "require",
                };
                let mut url = String::from("postgres://");
                if let Some(credentials) = &self.credentials {
                    url.push_str(&credentials.user.encoded());
                    if let Some(password) = &credentials.password {
                        url.push(':');
                        url.push_str(&percent_encode(&crate::secret::secret_reveal(
                            password.clone(),
                        )));
                    }
                    url.push('@');
                }
                url.push_str(self.host.as_str());
                url.push(':');
                url.push_str(&self.port.to_string());
                url.push('/');
                url.push_str(&database.encoded());
                url.push_str("?sslmode=");
                url.push_str(sslmode);
                url
            }
        }
    }
}

/// `Ipe.Db.Dsn.driver : Dsn -> Driver` — the driver tag as its discriminant
/// (`0 = Postgres`, `1 = Sqlite`), which the emitted `Driver` ADT constructor
/// re-tags. Non-secret; safe to read.
#[must_use]
pub fn dsn_driver(d: Dsn) -> i64 {
    match d.driver() {
        DsnDriver::Postgres => 0,
        DsnDriver::Sqlite => 1,
    }
}

/// `Ipe.Db.Dsn.host : Dsn -> String` — the host component (`""` for a
/// file-backed sqlite descriptor). Non-secret.
#[must_use]
pub fn dsn_host(d: Dsn) -> String {
    d.host.as_str().to_owned()
}

/// `Ipe.Db.Dsn.port : Dsn -> Int` — the port (`0` for sqlite). Non-secret.
#[must_use]
pub fn dsn_port(d: Dsn) -> i64 {
    i64::from(d.port)
}

/// `Ipe.Db.Dsn.database : Dsn -> String` — the database name or file path.
/// Non-secret.
#[must_use]
pub fn dsn_database(d: Dsn) -> String {
    match d.target {
        DsnTarget::Postgres(database) => database.0,
        DsnTarget::Sqlite(SqliteDb::File(name)) => name,
        DsnTarget::Sqlite(SqliteDb::Memory) => SQLITE_MEMORY.to_owned(),
    }
}

/// `Ipe.Db.Dsn.user : Dsn -> String` — the connection user (`""` when none).
/// Non-secret.
#[must_use]
pub fn dsn_user(d: Dsn) -> String {
    d.credentials
        .map_or_else(String::new, |credentials| credentials.user.0)
}

/// `Ipe.Db.Dsn.tls : Dsn -> TlsMode` — the transport posture as its discriminant
/// (`0 = Require`, `1 = Prefer`, `2 = Disable`), which the emitted `TlsMode` ADT
/// constructor re-tags. Non-secret.
#[must_use]
pub fn dsn_tls(d: Dsn) -> i64 {
    match d.tls {
        TlsMode::Require => 0,
        TlsMode::Prefer => 1,
        TlsMode::Disable => 2,
    }
}

/// `Ipe.Db.Dsn.redacted : Dsn -> String` — a credential-free, human-readable
/// rendering of the descriptor. The password is NEVER included — it is a
/// `Secret`, and this render substitutes the fixed placeholder. This is the ONLY
/// display path a `Dsn` has.
#[must_use]
pub fn dsn_redacted(d: Dsn) -> String {
    let driver = match d.driver() {
        DsnDriver::Postgres => "postgres",
        DsnDriver::Sqlite => "sqlite",
    };
    let tls = match d.tls {
        TlsMode::Require => "require",
        TlsMode::Prefer => "prefer",
        TlsMode::Disable => "disable",
    };
    // The `Secret`'s own `IpeStringify` yields the redacted placeholder; use it so
    // there is exactly one redaction convention.
    let user_part = d
        .credentials
        .as_ref()
        .map_or_else(String::new, |credentials| {
            format!("{}@", credentials.user.as_str())
        });
    match d.driver() {
        DsnDriver::Sqlite => format!("{driver}://{}", d.database()),
        DsnDriver::Postgres => format!(
            "{driver}://{user_part}{}:{}/{} (tls={tls}, password=[redacted])",
            d.host.as_str(),
            d.port,
            d.database()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A distinctive sentinel: any test that finds this substring in a render or
    // error has leaked the password.
    const SENTINEL: &str = "hunter2-SENTINEL";

    fn parse_ok(s: &str) -> Dsn {
        match dsn_parse::<String>(s.to_string()) {
            IpeResult::Ok(d) => d,
            IpeResult::Err(e) => panic!("expected {s:?} to parse, got Err: {e}"),
        }
    }

    fn parse_err(s: &str) -> String {
        match dsn_parse::<String>(s.to_string()) {
            IpeResult::Ok(_) => panic!("expected {s:?} to be rejected, but it parsed"),
            IpeResult::Err(e) => e,
        }
    }

    // ── The eight fail-closed parse cases ────────────────────────────────────

    #[test]
    fn rejects_unparseable() {
        assert!(parse_err("").contains("cannot parse"));
        assert!(parse_err("not a url at all").contains("cannot parse"));
    }

    #[test]
    fn rejects_unknown_driver() {
        assert!(parse_err("mysql://h:3306/d").contains("unknown driver"));
        assert!(parse_err("http://h/d").contains("unknown driver"));
    }

    #[test]
    fn rejects_missing_host_for_network_driver() {
        assert!(parse_err("postgres:///justadb").contains("missing host"));
    }

    #[test]
    fn rejects_invalid_port() {
        // 99999 is out of the u16 range — the `url` crate rejects it as
        // unparseable, which is still a fail-closed reject (no accepted value).
        let e = parse_err("postgres://h:99999/d");
        assert!(e.contains("cannot parse") || e.contains("invalid port"));
    }

    #[test]
    fn rejects_explicit_tls_disable() {
        assert!(parse_err("postgres://h:5432/d?sslmode=disable").contains("TLS disabled"));
    }

    #[test]
    fn rejects_unknown_sslmode() {
        assert!(parse_err("postgres://h:5432/d?sslmode=bananas").contains("unknown sslmode"));
    }

    #[test]
    fn rejects_smuggled_credential_and_conflicting_keys() {
        assert!(parse_err("postgres://h:5432/d?password=x").contains("conflicting or misplaced"));
        assert!(
            parse_err("postgres://h:5432/d?sslmode=require&sslmode=prefer")
                .contains("conflicting or misplaced")
        );
    }

    #[test]
    fn rejects_control_char_component() {
        // A percent-encoded newline in the database component.
        assert!(parse_err("postgres://h:5432/d%0aevil").contains("invalid DSN component"));
    }

    /// A credential holding an unencoded `?`, `#`, or `/` ends the authority
    /// early, so the parser reads part of it as the host (`admin` here, port
    /// `8`). Such a DSN is refused at the parse, so no `Dsn` exists to resolve
    /// or dial, and the refusal names neither that host nor the user name.
    #[test]
    fn rejects_userinfo_running_past_the_authority() {
        for dsn in [
            "postgres://admin:8/s3cr3t?pw@db.example/app",
            "postgres://admin:8/s3cr3t#pw@db.example/app",
            "postgres://admin:8/s3cr3t-pw@db.example/app",
            "postgres://admin@s3cr3t/pw@db.example/app",
            "postgres://db.example/app?application_name=admin@s3cr3t",
        ] {
            let parsed = dsn_parse::<String>(dsn.to_owned());
            assert!(
                matches!(parsed, IpeResult::Err(_)),
                "{dsn:?} must be refused"
            );
            let IpeResult::Err(e) = parsed else {
                continue;
            };
            assert_eq!(e, DsnReject::AmbiguousUserinfo.message(), "{dsn:?}");
            for shown in [e.clone(), format!("{e:?}")] {
                for secret in ["admin", "s3cr3t", "db.example"] {
                    assert!(
                        !shown.contains(secret),
                        "{dsn:?} leaked {secret:?}: {shown}"
                    );
                }
            }
        }
    }

    /// A clean DSN is admitted with the host after its last `@`: a
    /// percent-encoded `@`, or a raw `@` inside the authority, stays in the
    /// password.
    #[test]
    fn admits_a_clean_dsn_with_its_host() {
        for (dsn, host) in [
            (
                "postgres://admin:s3cr3t-pw@db.example:6432/app",
                "db.example",
            ),
            ("postgres://admin:s3cr%40t@db.example/app", "db.example"),
            ("postgres://admin:s3cr@3t@db.example/app", "db.example"),
            ("postgres://[::1]:5432/app", "[::1]"),
        ] {
            let parsed = dsn_parse::<String>(dsn.to_owned());
            assert!(matches!(parsed, IpeResult::Ok(_)), "{dsn:?} must parse");
            let IpeResult::Ok(d) = parsed else {
                continue;
            };
            assert_eq!(d.host().as_str(), host, "{dsn:?}");
        }
    }

    /// A built host holding a URL delimiter or a port would split the authority
    /// the connection URL writes it into, so it is refused.
    #[test]
    fn build_rejects_a_host_holding_a_url_delimiter() {
        for host in [
            "admin@db.example",
            "db.example/x",
            "db?x",
            "db#x",
            "db\\x",
            "db%2Fx",
            "db.example:6543",
            "::1",
            "db x",
            "",
        ] {
            let built = dsn_build::<String>(
                0,
                host.into(),
                5432,
                "d".into(),
                "u".into(),
                secret_from_string("p".into()),
                0,
            );
            assert!(
                matches!(built, IpeResult::Err(ref e) if e.contains("invalid DSN component")),
                "{host:?} must be refused"
            );
        }
    }

    /// The password `d` holds, revealed.
    fn revealed_password(d: Dsn) -> Option<String> {
        d.credentials
            .and_then(|credentials| credentials.password)
            .map(crate::secret::secret_reveal)
    }

    /// A password with no user name is refused, built or parsed; an empty
    /// password beside a user name is none.
    #[test]
    fn password_without_user_is_refused() {
        let built = dsn_build::<String>(
            0,
            "db.example".into(),
            5432,
            "app".into(),
            String::new(),
            secret_from_string("pw".into()),
            0,
        );
        assert!(
            matches!(built, IpeResult::Err(ref e) if e.contains("a password needs a user name"))
        );
        assert!(
            parse_err("postgres://:pw@db.example/app").contains("a password needs a user name")
        );
        let d = parse_ok("postgres://reader:@db.example/app");
        assert_eq!(dsn_user(d.clone()), "reader");
        assert_eq!(revealed_password(d.clone()), None);
        assert!(
            d.connection_url()
                .starts_with("postgres://reader@db.example:5432/")
        );
        let sqlite = dsn_build::<String>(
            1,
            String::new(),
            0,
            "app.db".into(),
            "reader".into(),
            secret_from_string(String::new()),
            0,
        );
        assert!(matches!(sqlite, IpeResult::Err(ref e) if e.contains("invalid DSN component")));
    }

    /// A built password and a parsed DSN are bounded; one byte past each cap
    /// is refused.
    #[test]
    fn password_and_dsn_lengths_are_capped() {
        let build_with = |password: String| {
            dsn_build::<String>(
                0,
                "db.example".into(),
                5432,
                "app".into(),
                "reader".into(),
                secret_from_string(password),
                0,
            )
        };
        assert!(matches!(
            build_with("p".repeat(MAX_COMPONENT_LEN)),
            IpeResult::Ok(_)
        ));
        assert!(matches!(
            build_with("p".repeat(MAX_COMPONENT_LEN + 1)),
            IpeResult::Err(ref e) if e.contains("invalid DSN component")
        ));
        let prefix = "postgres://reader@db.example/app?application_name=";
        let at_cap = format!("{prefix}{}", "a".repeat(MAX_DSN_LEN - prefix.len()));
        assert!(matches!(
            dsn_parse::<String>(at_cap.clone()),
            IpeResult::Ok(_)
        ));
        assert!(parse_err(&format!("{at_cap}a")).contains("exceeds the length limit"));
        let long_password = format!(
            "postgres://reader:{}@db.example/app",
            "p".repeat(MAX_COMPONENT_LEN + 1)
        );
        assert!(parse_err(&long_password).contains("invalid DSN component"));
    }

    /// The connection URL `d` dials, read back by the `Dsn` parser and by the
    /// driver.
    fn reread(d: &Dsn) -> (Option<Dsn>, Option<sqlx::postgres::PgConnectOptions>) {
        let url = d.connection_url();
        let reparsed = match dsn_parse::<String>(url.clone()) {
            IpeResult::Ok(d) => Some(d),
            IpeResult::Err(_) => None,
        };
        (reparsed, url.parse().ok())
    }

    /// Parts that would carry URL syntax if written into the connection URL
    /// as they are.
    const URL_SYNTAX_PARTS: [&str; 8] = [
        "app?sslmode=disable&x",
        "app#?sslmode=disable",
        "app/x?sslmode=disable",
        "a@b?sslmode=disable",
        "a:b@evil.example/x?sslmode=disable",
        "%3Fsslmode%3Ddisable",
        "50%off",
        "app&sslmode=disable",
    ];

    /// A built database name, user name, or password holding URL syntax stays
    /// inside its component: the connection URL keeps `sslmode=require` for
    /// both the `Dsn` parser and the driver, and each part reads back exactly.
    #[test]
    fn build_parts_cannot_inject_url_syntax() {
        for part in URL_SYNTAX_PARTS {
            for slot in 0..3 {
                let pick = |i: usize, other: &'static str| if slot == i { part } else { other };
                let built = dsn_build::<String>(
                    0,
                    "db.example".into(),
                    5432,
                    pick(0, "app").into(),
                    pick(1, "reader").into(),
                    secret_from_string(pick(2, "pw").into()),
                    0,
                );
                assert!(matches!(built, IpeResult::Ok(_)), "{part:?} in slot {slot}");
                let IpeResult::Ok(d) = built else {
                    continue;
                };
                let (reparsed, options) = reread(&d);
                assert!(options.is_some(), "{part:?} in slot {slot}: driver parse");
                let Some(options) = options else {
                    continue;
                };
                assert!(
                    matches!(options.get_ssl_mode(), sqlx::postgres::PgSslMode::Require),
                    "{part:?} in slot {slot} downgraded the driver's TLS"
                );
                assert_eq!(options.get_host(), "db.example", "{part:?} in slot {slot}");
                assert_eq!(options.get_database(), Some(pick(0, "app")));
                assert_eq!(options.get_username(), pick(1, "reader"));
                assert!(reparsed.is_some(), "{part:?} in slot {slot}: Dsn reparse");
                let Some(reparsed) = reparsed else {
                    continue;
                };
                assert_eq!(dsn_tls(reparsed.clone()), 0, "{part:?} in slot {slot}");
                assert_eq!(reparsed.host().as_str(), "db.example");
                assert_eq!(dsn_database(reparsed.clone()), pick(0, "app"));
                assert_eq!(dsn_user(reparsed.clone()), pick(1, "reader"));
                assert_eq!(revealed_password(reparsed).as_deref(), Some(pick(2, "pw")));
            }
        }
    }

    /// Weird-but-legal names survive `build` then `parse` with their TLS mode.
    #[test]
    fn build_then_parse_keeps_the_tls_mode() {
        for (tls_tag, name) in [
            (0, "app-v2.prod_db"),
            (1, "caf\u{e9}"),
            (0, "100%"),
            (1, "a+b=c;d,e"),
            (0, "[x]{y}"),
        ] {
            let built = dsn_build::<String>(
                0,
                "db.example".into(),
                6432,
                name.into(),
                name.into(),
                secret_from_string(name.into()),
                tls_tag,
            );
            assert!(matches!(built, IpeResult::Ok(_)), "{name:?}");
            let IpeResult::Ok(d) = built else {
                continue;
            };
            let (reparsed, _) = reread(&d);
            assert!(reparsed.is_some(), "{name:?}");
            let Some(reparsed) = reparsed else {
                continue;
            };
            assert_eq!(dsn_tls(reparsed.clone()), tls_tag, "{name:?}");
            assert_eq!(dsn_port(reparsed.clone()), 6432);
            assert_eq!(dsn_database(reparsed.clone()), name);
            assert_eq!(dsn_user(reparsed), name);
        }
    }

    /// A parsed user name, password, and database are held decoded, so the
    /// connection URL encodes them exactly once.
    #[test]
    fn parse_then_connect_keeps_encoded_parts() {
        let d = parse_ok("postgres://re%40der:s3cr%40t@db.example/my%3Fdb");
        assert_eq!(dsn_user(d.clone()), "re@der");
        assert_eq!(dsn_database(d.clone()), "my?db");
        let (_, options) = reread(&d);
        assert!(options.is_some());
        let Some(options) = options else {
            return;
        };
        assert_eq!(options.get_username(), "re@der");
        assert_eq!(options.get_database(), Some("my?db"));
        assert!(matches!(
            options.get_ssl_mode(),
            sqlx::postgres::PgSslMode::Require
        ));
        assert_eq!(revealed_password(d).as_deref(), Some("s3cr@t"));
    }

    /// A parsed part that decodes to invalid UTF-8 or a control character is
    /// refused.
    #[test]
    fn parse_rejects_undecodable_parts() {
        for dsn in [
            "postgres://u%ff@db.example/app",
            "postgres://u:p%ff@db.example/app",
            "postgres://db.example/a%ff",
            "postgres://u%0a@db.example/app",
            "postgres://u%zz@db.example/app",
            "postgres://u:p%zz@db.example/app",
            "postgres://u:p%@db.example/app",
            "postgres://db.example/a%zz",
            "postgres://db.example/a%C0%AF",
        ] {
            assert!(
                matches!(dsn_parse::<String>(dsn.to_owned()), IpeResult::Err(ref e) if e.contains("invalid DSN component")),
                "{dsn:?} must be refused"
            );
        }
    }

    // ── SQLite ───────────────────────────────────────────────────────────────

    /// A SQLite `Dsn` built from the file name `name`.
    fn sqlite_build(name: &str) -> IpeResult<String, Dsn> {
        dsn_build::<String>(
            1,
            String::new(),
            0,
            name.into(),
            String::new(),
            secret_from_string(String::new()),
            0,
        )
    }

    /// The options the driver reads from `d`'s connection URL.
    fn sqlite_options(d: &Dsn) -> Option<sqlx::sqlite::SqliteConnectOptions> {
        d.connection_url().parse().ok()
    }

    /// Whether the driver opens `options` as its private in-memory database,
    /// which it names `file:sqlx-in-memory-<n>`.
    fn sqlite_in_memory(options: &sqlx::sqlite::SqliteConnectOptions) -> bool {
        options
            .get_filename()
            .to_str()
            .is_some_and(|name| name.starts_with("file:sqlx-in-memory-"))
    }

    /// Whether `url` opens a file `mode=rwc` with no other parameter.
    fn pins_rwc_only(url: &str) -> bool {
        url.matches('?').count() == 1 && url.ends_with("?mode=rwc")
    }

    /// File names that would carry URL syntax or a SQLite special name if
    /// written into the connection URL as they are.
    const SQLITE_SYNTAX_NAMES: [&str; 11] = [
        "x?mode=memory",
        "app.db?mode=ro&cache=shared",
        "a#x",
        "a#x?vfs=memdb",
        "%41",
        "%3Amemory%3A",
        "a:b",
        "sqlite:x.db",
        "u:p@x.db",
        "/abs/p?q#r.db",
        "//x/caf\u{e9}[1].db",
    ];

    /// A built SQLite file name opens that very file `mode=rwc`, for the
    /// driver and the pooled opener, and reads back through the `Dsn` parser.
    #[test]
    fn built_sqlite_names_open_the_named_file() {
        for name in SQLITE_SYNTAX_NAMES
            .into_iter()
            .chain(["data/app.db", "/abs/app.db"])
        {
            let built = sqlite_build(name);
            assert!(matches!(built, IpeResult::Ok(_)), "{name:?}");
            let IpeResult::Ok(d) = built else {
                continue;
            };
            let url = d.connection_url();
            assert!(pins_rwc_only(&url), "{name:?}: {url}");
            let options = sqlite_options(&d);
            assert!(options.is_some(), "{name:?}: driver parse of {url}");
            let Some(options) = options else {
                continue;
            };
            assert_eq!(options.get_filename(), std::path::Path::new(name));
            assert!(!sqlite_in_memory(&options), "{name:?}");
            assert!(
                crate::db::DbUrl::parse(&url).is_ok_and(|db| db.is_shared_sqlite_file()),
                "{name:?}: pooled opener of {url}"
            );
            let reparsed = dsn_parse::<String>(url.clone());
            assert!(
                matches!(reparsed, IpeResult::Ok(ref r) if dsn_database(r.clone()) == name),
                "{name:?}: Dsn reparse of {url}"
            );
        }
    }

    /// `:memory:` names SQLite's private in-memory database, built or parsed.
    #[test]
    fn sqlite_memory_opens_in_memory() {
        let built = sqlite_build(":memory:");
        let parsed = dsn_parse::<String>("sqlite::memory:".to_owned());
        for d in [built, parsed] {
            assert!(matches!(d, IpeResult::Ok(_)));
            let IpeResult::Ok(d) = d else {
                continue;
            };
            assert_eq!(dsn_database(d.clone()), ":memory:");
            assert_eq!(d.connection_url(), "sqlite::memory:");
            let options = sqlite_options(&d);
            assert!(options.as_ref().is_some_and(sqlite_in_memory));
            assert!(
                crate::db::DbUrl::parse(&d.connection_url())
                    .is_ok_and(|db| !db.is_shared_sqlite_file())
            );
        }
    }

    /// A SQLite DSN names the file the driver opens: the text after the
    /// scheme and an optional `//`, percent-decoded.
    #[test]
    fn parse_reads_sqlite_names_as_the_driver_opens_them() {
        for (dsn, name) in [
            ("sqlite://data/app.db", "data/app.db"),
            ("sqlite:///abs/app.db", "/abs/app.db"),
            ("sqlite://app.db?mode=rwc", "app.db"),
            ("sqlite:app.db", "app.db"),
            ("file:data/app.db", "data/app.db"),
            ("sqlite:a%3Fb%23c%25.db", "a?b#c%.db"),
        ] {
            let parsed = parse_ok(dsn);
            assert_eq!(dsn_database(parsed.clone()), name, "{dsn:?}");
            assert_eq!(dsn_driver(parsed.clone()), 1, "{dsn:?}");
            let options = sqlite_options(&parsed);
            assert_eq!(
                options.as_ref().map(|o| o.get_filename().to_path_buf()),
                Some(std::path::PathBuf::from(name)),
                "{dsn:?}"
            );
            assert!(pins_rwc_only(&parsed.connection_url()), "{dsn:?}");
        }
    }

    /// A SQLite DSN or file name that would choose the open mode or another
    /// option is refused.
    #[test]
    fn sqlite_option_overrides_are_refused() {
        for dsn in [
            "sqlite:x.db?mode=memory",
            "sqlite://x.db?mode=ro",
            "sqlite://x.db?mode=rwc&cache=shared",
            "sqlite://x.db#y?vfs=memdb",
            "sqlite://x.db?sslmode=require",
            "sqlite://u:p@x.db",
            "sqlite::memory:?cache=shared",
            "sqlite:x.db?mode=%zz",
            "sqlite:x.db?mode=rwc&%zz",
        ] {
            assert!(
                matches!(dsn_parse::<String>(dsn.to_owned()), IpeResult::Err(ref e) if e.contains("conflicting or misplaced parameter")),
                "{dsn:?} must be refused"
            );
        }
        for dsn in [
            "sqlite:file:x.db",
            "sqlite:file%3Ax.db?mode=rwc",
            "sqlite:%ff",
            "sqlite:a%zz.db",
            "sqlite:a%.db",
        ] {
            assert!(
                matches!(dsn_parse::<String>(dsn.to_owned()), IpeResult::Err(ref e) if e.contains("invalid DSN component")),
                "{dsn:?} must be refused"
            );
        }
        for name in ["file:x.db", "file::memory:?cache=shared", "", "a\nb"] {
            assert!(
                matches!(sqlite_build(name), IpeResult::Err(ref e) if e.contains("invalid DSN component")),
                "{name:?} must be refused"
            );
        }
    }

    // ── Secure defaults ──────────────────────────────────────────────────────

    #[test]
    fn omitted_sslmode_defaults_to_require() {
        let d = parse_ok("postgres://user@h:5432/mydb");
        assert_eq!(dsn_tls(d), 0); // 0 = Require
    }

    #[test]
    fn accepts_explicit_prefer() {
        let d = parse_ok("postgres://h:5432/d?sslmode=prefer");
        assert_eq!(dsn_tls(d), 1); // 1 = Prefer
    }

    #[test]
    fn build_rejects_tls_disable_and_out_of_range_port() {
        // tls_tag 2 = Disable → reject.
        assert!(matches!(
            dsn_build::<String>(
                0,
                "h".into(),
                5432,
                "d".into(),
                "u".into(),
                secret_from_string("p".into()),
                2
            ),
            IpeResult::Err(_)
        ));
        // port 0 for a Postgres driver → reject (no narrowing accept).
        assert!(matches!(
            dsn_build::<String>(
                0,
                "h".into(),
                0,
                "d".into(),
                "u".into(),
                secret_from_string("p".into()),
                0
            ),
            IpeResult::Err(_)
        ));
        // port 70000 (> u16::MAX) → reject, not truncated.
        assert!(matches!(
            dsn_build::<String>(
                0,
                "h".into(),
                70000,
                "d".into(),
                "u".into(),
                secret_from_string("p".into()),
                0
            ),
            IpeResult::Err(_)
        ));
    }

    /// A built host is held as the URL parser writes it, the form the SSRF gate
    /// vets and the driver dials.
    #[test]
    fn build_holds_the_parsed_host() {
        for (host, held) in [
            ("DB.Example", "db.example"),
            ("[::1]", "[::1]"),
            ("127.0.0.1", "127.0.0.1"),
        ] {
            let built = dsn_build::<String>(
                0,
                host.into(),
                5432,
                "d".into(),
                "u".into(),
                secret_from_string("p".into()),
                0,
            );
            assert!(
                matches!(built, IpeResult::Ok(ref d) if d.host().as_str() == held),
                "{host:?}"
            );
        }
    }

    #[test]
    fn build_accepts_valid_typed_parts() {
        let d = dsn_build::<String>(
            0,
            "db.example.com".into(),
            5432,
            "app".into(),
            "reader".into(),
            secret_from_string("p".into()),
            0,
        );
        assert!(matches!(d, IpeResult::Ok(_)));
    }

    // ── The four Secret-non-leak invariants ──────────────────────────────────

    #[test]
    fn redacted_render_omits_password() {
        let d = parse_ok(&format!("postgres://reader:{SENTINEL}@h:5432/app"));
        let rendered = dsn_redacted(d);
        assert!(
            !rendered.contains(SENTINEL),
            "redacted render leaked the password"
        );
        assert!(rendered.contains("h")); // non-secret host still present
        assert!(rendered.contains("[redacted]"));
    }

    #[test]
    fn debug_inspect_omits_password() {
        let d = parse_ok(&format!("postgres://reader:{SENTINEL}@h:5432/app"));
        let shown = format!("{d:?}");
        assert!(!shown.contains(SENTINEL), "Debug leaked the password");
    }

    #[test]
    fn error_payload_omits_password() {
        // A DSN that carries a password AND trips a reject (sslmode=disable). The
        // error must not echo the credential-bearing input.
        let e = parse_err(&format!(
            "postgres://reader:{SENTINEL}@h:5432/app?sslmode=disable"
        ));
        assert!(!e.contains(SENTINEL), "parse error leaked the password");
    }

    // The fourth invariant — "no plain-String password accessor" — is enforced at
    // the type surface: this module exposes NO `dsn_password -> String`. A grep
    // for a password accessor over this file finds only the `Secret`-typed field
    // and the redaction path. (A compile-fail Ipê fixture guards the source
    // surface; see tests/golden.)
    #[test]
    fn no_plain_password_accessor_exists() {
        // Proof by absence over this module's own source: no public accessor
        // returns the password as a plain `String`. The needle is assembled at
        // runtime so this assertion's own text does not self-match.
        let src = include_str!("dsn.rs");
        let needle = format!("pub fn dsn_{}", "password");
        assert!(
            !src.contains(&needle),
            "a plain-String password accessor must never exist"
        );
    }
}
