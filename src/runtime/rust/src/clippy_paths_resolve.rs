//! Names every path the runtime `clippy.toml` denies, so rustc resolves each.
//!
//! An entry marked `allow-invalid` is skipped by clippy without a word once its
//! path stops resolving, so each one is spelled here under the feature that
//! brings its crate in: a renamed or removed path is an unresolved-path error in
//! the `--all-targets` build instead of a silently dropped entry. The
//! `lenient_decode_scan` test asserts this file names exactly the `clippy.toml`
//! set.
//!
//! Each naming carries its own `#[expect]` of the clippy lint the entry
//! configures, so the file also proves each ban fires: an entry clippy stops
//! matching leaves its expectation unfulfilled, and `unfulfilled_lint_expectations`
//! under `-D warnings` fails the clippy run. rustc leaves tool-lint expectations
//! unchecked, so a plain build is unaffected.

const _STD: () = {
    #[allow(deprecated)] // named to prove the ban, never called
    #[expect(clippy::disallowed_methods)]
    let _ = ::std::env::home_dir;
    #[expect(clippy::disallowed_methods)]
    let _ = ::std::string::String::from_utf8_lossy;
};

#[cfg(feature = "encoding")]
const _PERCENT_ENCODING: () = {
    #[expect(clippy::disallowed_methods)]
    let _ = ::percent_encoding::percent_decode_str;
    #[expect(clippy::disallowed_methods)]
    let _ = ::percent_encoding::percent_decode;
    #[expect(clippy::disallowed_methods)]
    let _ = ::percent_encoding::PercentDecode::decode_utf8_lossy;
};

#[cfg(feature = "url")]
const _URL: () = {
    #[expect(clippy::disallowed_methods)]
    let _ = ::url::form_urlencoded::parse;
    #[expect(clippy::disallowed_methods)]
    let _ = ::url::Url::query_pairs;
};

#[cfg(feature = "web-core")]
const _SERDE_URLENCODED: () = {
    #[expect(clippy::disallowed_methods)]
    let _ = ::serde_urlencoded::from_str::<()>;
    #[expect(clippy::disallowed_methods)]
    let _ = ::serde_urlencoded::from_bytes::<()>;
    #[expect(clippy::disallowed_methods)]
    let _ = ::serde_urlencoded::from_reader::<(), &[u8]>;
};

#[cfg(feature = "server")]
const _AXUM: () = {
    #[expect(clippy::disallowed_types)]
    let _: Option<::axum::extract::Query<()>> = None;
    #[expect(clippy::disallowed_types)]
    let _: Option<::axum::extract::Form<()>> = None;
};
