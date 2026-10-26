//! `Redacted<T>` — a field carrier whose `Debug` never prints the value.
//!
//! A runtime type that holds secret-role data (a cookie value, a principal's
//! identity) wraps each such field in [`Redacted`]. Its `Debug` writes [`REDACTED`] and nothing else, so the
//! owning type can keep `#[derive(Debug)]` and every `{:?}` of it — a runtime
//! log line, a `dbg!`, the stringify `Debug` fallback — prints the type's
//! structure with the secret fields masked. The value stays reachable to the
//! runtime code that owns it through `Deref` and [`Redacted::into_inner`]. There
//! is no inherent `get`: a method of that name would shadow the wrapped
//! value's own (`BTreeMap::get`) through auto-deref.
//!
//! `Redacted` implements no `Display` and no `IpeStringify`, so there is no
//! second formatting path that could reach the value. Std-only and declared in
//! every runtime module set; reached by qualified path (`crate::redact::…`),
//! never glob-re-exported.
//!
//! The module also holds the one credential-position rule for HTTP header
//! names, [`classify_header`]: every renderer that withholds a header's value
//! by its name asks this rule, so no second list of header names exists
//! (`tests/secret_debug_scan.rs` refuses one).

/// The one spelling of a masked value, shared by every redacting `Debug` and
/// the `Secret` renderers.
pub const REDACTED: &str = "<redacted>";

/// An HTTP header name, lowercased: RFC 7230 `token` bytes only.
///
/// The grammar admits only ASCII, so the fold is exact; a byte outside it is a
/// parse refusal, never a fold, so no non-ASCII spelling can pass as a listed
/// name.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct HeaderName(String);

impl HeaderName {
    /// Parse `raw`: `None` for an empty name or a byte outside the `token`
    /// grammar.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        if raw.is_empty() || !raw.bytes().all(is_tchar) {
            return None;
        }
        Some(Self(raw.to_ascii_lowercase()))
    }

    /// The lowercased name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// RFC 7230 `tchar`: a byte a header-name token may hold.
const fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// What a header's value is, decided by its name.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HeaderClass {
    /// The value carries a credential: a token, a key, a cookie, a signature.
    Credential,
    /// The value is metadata: a content type, a host, a request id.
    Plain,
}

/// The whole names whose values carry a credential.
const CREDENTIAL_HEADERS: [&str; 8] = [
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-amz-security-token",
    "x-csrf-token",
];

/// The name suffixes that mark a credential header (`X-Custom-Token`).
const CREDENTIAL_SUFFIXES: [&str; 4] = ["-authorization", "-token", "-api-key", "-secret"];

/// The name prefixes that mark a credential header (`X-Amz-Date` signs a request).
const CREDENTIAL_PREFIXES: [&str; 1] = ["x-amz-"];

/// The one credential-position rule for header names.
///
/// `Credential` for a name in [`CREDENTIAL_HEADERS`], a name ending in one of
/// [`CREDENTIAL_SUFFIXES`] or starting with one of [`CREDENTIAL_PREFIXES`];
/// `Plain` otherwise. The dev view and every redacting renderer call this rule
/// and keep no list of their own.
#[must_use]
pub fn classify_header(name: &HeaderName) -> HeaderClass {
    let name = name.as_str();
    let listed = CREDENTIAL_HEADERS.contains(&name)
        || CREDENTIAL_SUFFIXES
            .iter()
            .any(|suffix| name.ends_with(suffix))
        || CREDENTIAL_PREFIXES
            .iter()
            .any(|prefix| name.starts_with(prefix));
    if listed {
        HeaderClass::Credential
    } else {
        HeaderClass::Plain
    }
}

/// [`classify_header`] over header-name text, fail closed.
///
/// A name the header grammar refuses cannot be matched against the rule, so it
/// is `Credential`: its value is withheld.
#[must_use]
pub fn classify_header_text(raw: &str) -> HeaderClass {
    HeaderName::parse(raw).map_or(HeaderClass::Credential, |name| classify_header(&name))
}

/// A value whose `Debug` is [`REDACTED`], whatever it holds.
///
/// Equality, hashing and cloning delegate to the value; only formatting is
/// masked.
#[derive(Clone, Default, PartialEq, Eq, Hash)]
pub struct Redacted<T>(T);

impl<T> Redacted<T> {
    /// Wrap `value`.
    pub const fn new(value: T) -> Self {
        Self(value)
    }

    /// The wrapped value, by move.
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> From<T> for Redacted<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

impl<T> std::ops::Deref for Redacted<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T> std::ops::DerefMut for Redacted<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T> std::fmt::Debug for Redacted<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(REDACTED)
    }
}

/// Write a redacting `Debug` for a struct whose layout is fixed by emitted code.
///
/// Some runtime structs mirror an Ipê record (the emitter builds and reads their
/// fields by name), so their secret-role fields cannot change type to
/// [`Redacted`]. Their `Debug` is generated here instead: the listed `shown`
/// fields print their own `Debug`, every `masked` field prints [`REDACTED`],
/// and the `struct` destructure names every field, so a field added to the
/// struct and absent from both lists is a compile error (E0027), never a field
/// printed by default.
macro_rules! redacting_debug {
    ($ty:ident { shown: [$($shown:ident),* $(,)?], masked: [$($masked:ident),* $(,)?] $(,)? }) => {
        impl ::std::fmt::Debug for $ty {
            // The bindings carry the field names, which mirror camelCase Ipê fields.
            #[allow(non_snake_case)]
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                let Self { $($shown,)* $($masked: _,)* } = self;
                f.debug_struct(stringify!($ty))
                    $(.field(stringify!($shown), $shown))*
                    $(.field(stringify!($masked), &$crate::redact::Redacted::new(())))*
                    .finish()
            }
        }
    };
}
pub(crate) use redacting_debug;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    #[test]
    fn debug_never_prints_the_value() {
        let r = Redacted::new("Bearer S3CR3T".to_owned());
        assert_eq!(format!("{r:?}"), REDACTED);
        assert_eq!(format!("{r:#?}"), REDACTED);
        assert_eq!(r.as_str(), "Bearer S3CR3T");
    }

    #[allow(non_snake_case)]
    struct Mirror {
        method: String,
        authHeader: String,
    }
    redacting_debug!(Mirror {
        shown: [method],
        masked: [authHeader]
    });

    #[test]
    fn the_macro_masks_every_listed_field() {
        let m = Mirror {
            method: "GET".to_owned(),
            authHeader: "Bearer S3CR3T".to_owned(),
        };
        let shown = format!("{m:?}");
        assert_eq!(shown, "Mirror { method: \"GET\", authHeader: <redacted> }");
        assert!(!shown.contains("S3CR3T"));
        assert_eq!(m.authHeader.len(), 13);
    }

    // Every listed name, in any ASCII case, and every name a suffix or prefix
    // rule covers is a credential position.
    #[test]
    fn credential_header_names_classify_as_credential() {
        let credential = [
            "authorization",
            "AUTHORIZATION",
            "Proxy-Authorization",
            "Cookie",
            "Set-Cookie",
            "X-Api-Key",
            "X-Auth-Token",
            "X-Amz-Security-Token",
            "X-CSRF-Token",
            "X-Custom-Token",
            "X-Vendor-Authorization",
            "X-Service-Api-Key",
            "X-Client-Secret",
            "X-Amz-Date",
        ];
        for raw in credential {
            assert_eq!(classify_header_text(raw), HeaderClass::Credential, "{raw}");
        }
        for name in CREDENTIAL_HEADERS {
            assert_eq!(
                classify_header_text(name),
                HeaderClass::Credential,
                "{name}"
            );
            assert_eq!(
                classify_header_text(&name.to_ascii_uppercase()),
                HeaderClass::Credential,
                "{name}"
            );
        }
    }

    // A metadata header is plain, and only a whole-suffix match counts.
    #[test]
    fn plain_header_names_classify_as_plain() {
        for raw in [
            "Content-Type",
            "Accept",
            "Host",
            "User-Agent",
            "Location",
            "X-Request-Id",
            "Tokenizer",
            "Secretary",
        ] {
            assert_eq!(classify_header_text(raw), HeaderClass::Plain, "{raw}");
        }
    }

    // A name outside the header grammar never reaches the rule: it is refused
    // by the parser and withheld by the text classifier, so a non-ASCII
    // spelling of a listed name is not folded into a plain one.
    #[test]
    fn a_name_outside_the_grammar_is_refused_and_withheld() {
        for raw in [
            "",
            "Authorizatıon",
            "X-Api Key",
            "Content\u{200c}-Type",
            "Set:Cookie",
        ] {
            assert!(HeaderName::parse(raw).is_none(), "{raw:?}");
            assert_eq!(
                classify_header_text(raw),
                HeaderClass::Credential,
                "{raw:?}"
            );
        }
    }

    // The parsed name is the lowercased token, so the rule compares one form.
    #[test]
    fn a_parsed_name_is_lowercased() {
        #[allow(clippy::expect_used)] // fixture: a token-only name always parses
        let name = HeaderName::parse("X-Api-Key").expect("a token name");
        assert_eq!(name.as_str(), "x-api-key");
        assert_eq!(classify_header(&name), HeaderClass::Credential);
    }
}
