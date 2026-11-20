//! The one HTTP method type every runtime surface shares.
//!
//! `HttpMethod` is the Rust mirror of the `HttpMethod` ADT in `Ipe.Http`; the
//! outbound client, the server's route table and the wire parse all read it.
//! The module is std-only and ungated in every emitted module set, so a
//! program that merely names a method links no client or server dependency.
//! `HttpMethod::ALL` with `HttpMethod::as_str` is the one spelling table every
//! reader derives from.

/// Closed set of HTTP methods, one variant per `Ipe.Http` constructor.
///
/// The variant order is the Ipê constructor order the resolver indexes; emitted
/// match arms (`HttpMethod::Get`, …) resolve through the `pub use http_method::*`
/// glob in every emitted `mod.rs`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Head,
    Options,
}

crate::retained::inline_measure!(HttpMethod);

crate::stringify::show_row!("HttpMethod", Value, [] HttpMethod, |m| match m {
    HttpMethod::Get => "Get".to_owned(),
    HttpMethod::Post => "Post".to_owned(),
    HttpMethod::Put => "Put".to_owned(),
    HttpMethod::Delete => "Delete".to_owned(),
    HttpMethod::Patch => "Patch".to_owned(),
    HttpMethod::Head => "Head".to_owned(),
    HttpMethod::Options => "Options".to_owned(),
});

impl HttpMethod {
    /// Every method, in the order an `Allow` header lists them.
    pub const ALL: [Self; 7] = [
        Self::Delete,
        Self::Get,
        Self::Head,
        Self::Options,
        Self::Patch,
        Self::Post,
        Self::Put,
    ];

    /// The method's canonical uppercase wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
            Self::Patch => "PATCH",
            Self::Head => "HEAD",
            Self::Options => "OPTIONS",
        }
    }

    /// The method a token names, ignoring ASCII case; `None` for any other token.
    // Named `from_str` for call-site readability; it returns `Option<Self>`, not
    // `FromStr`'s `Result`, so it deliberately does not implement that trait.
    #[allow(clippy::should_implement_trait)]
    #[must_use]
    pub fn from_str(s: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|m| m.as_str().eq_ignore_ascii_case(s))
    }
}

/// `Http.methodFromString : String -> Maybe HttpMethod`, the typed parse of a method string.
///
/// `Just` for the seven standard verbs (case-insensitive), `Nothing` otherwise.
#[must_use]
pub fn http_method_from_string(s: String) -> crate::core::IpeMaybe<HttpMethod> {
    HttpMethod::from_str(&s).map_or(crate::core::IpeMaybe::Nothing, crate::core::IpeMaybe::Just)
}

/// `Http.methodToString : HttpMethod -> String`, the canonical uppercase token.
#[must_use]
pub fn http_method_to_string(m: HttpMethod) -> String {
    m.as_str().to_owned()
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::HttpMethod;

    #[test]
    fn all_and_as_str_are_one_table() {
        for m in HttpMethod::ALL {
            assert_eq!(HttpMethod::from_str(m.as_str()), Some(m));
            assert_eq!(
                HttpMethod::from_str(&m.as_str().to_ascii_lowercase()),
                Some(m)
            );
        }
        let mut seen = HttpMethod::ALL.to_vec();
        seen.sort_by_key(|m| m.as_str());
        seen.dedup();
        assert_eq!(seen.len(), 7);
        assert_eq!(HttpMethod::from_str("TRACE"), None);
        assert_eq!(HttpMethod::from_str(""), None);
    }

    #[cfg(feature = "serde")]
    #[test]
    #[allow(clippy::expect_used)] // a unit variant always serializes and its own wire always parses
    fn serde_round_trips_every_method() {
        for m in HttpMethod::ALL {
            let wire = serde_json::to_string(&m).expect("a unit variant serializes");
            let back: HttpMethod = serde_json::from_str(&wire).expect("its own wire parses");
            assert_eq!(back, m);
        }
    }
}
