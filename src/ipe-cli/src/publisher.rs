//! Publisher identity, typed by how much of it is proven.
//!
//! The registry grants two privileges to the blessed first-party publisher
//! ([`ipe_kernels::BLESSED_PUBLISHER`]): the reserved-namespace exemption (a
//! reserved package name or `Ipe.*` / `Rust.*` module) and the drop-only reset of
//! the disposable reserved smoke probe. A privilege must rest on a proven
//! identity, never on the `publisher` string an entry file declares about itself,
//! so the three levels of trust are three types:
//!
//! - [`SelfDeclaredPublisher`] — the `publisher` an index entry claims (parsed
//!   from committed TOML / the JSON mirror, or inferred from a source URL).
//!   Attacker-controllable; informational only. It exposes no blessed predicate.
//! - [`AuthenticatedPublisher`] — the account a live, token-authenticated GitHub
//!   `GET /user` reports. Constructed only from that response.
//! - [`AttestedActor`] — the authenticated pull-request author the registry
//!   admission workflow hands to `ipe package audit-entry --attested-actor`, read
//!   from the GitHub-provided event context (never from the PR's own files).
//!
//! [`BlessedPublisher`] is the only value a privilege accepts, and it exists only
//! when a proven identity (authenticated or attested) equals BOTH the claimed
//! publisher AND the blessed identity. A forged `publisher = "<blessed>"` alone
//! can never produce one: absent proof, every constructor returns a
//! [`BlessingRefusal`] and the privileged branch is unreachable.

use std::fmt;

use crate::CliError;
use crate::text;

/// The GitHub login-length ceiling (GitHub caps usernames at 39 characters).
const MAX_LOGIN_LEN: usize = 39;

/// The suffix GitHub appends to an App (bot) account's login.
const BOT_SUFFIX: &str = "[bot]";

/// Why a string is not a GitHub login.
///
/// The one definition of a login's shape, shared by every identity parse, so a
/// value that reaches a log line or a refusal message can never carry control
/// bytes, ANSI escapes, whitespace, or any other non-login text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoginRefusal {
    /// Nothing precedes the optional `[bot]` suffix.
    Empty,
    /// The handle exceeds GitHub's 39-character ceiling.
    TooLong,
    /// A byte other than an ASCII letter, digit, or hyphen.
    ForbiddenByte,
    /// The handle starts or ends with a hyphen.
    EdgeHyphen,
    /// The handle holds two consecutive hyphens.
    DoubleHyphen,
}

impl fmt::Display for LoginRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str(text::login_empty()),
            Self::TooLong => f.write_str(&text::login_too_long(&MAX_LOGIN_LEN)),
            Self::ForbiddenByte => f.write_str(text::login_forbidden_byte()),
            Self::EdgeHyphen => f.write_str(text::login_edge_hyphen()),
            Self::DoubleHyphen => f.write_str(text::login_double_hyphen()),
        }
    }
}

impl std::error::Error for LoginRefusal {}

/// Check `raw` against GitHub's login shape.
///
/// A login is 1–39 ASCII alphanumerics or single interior hyphens, optionally
/// followed by the `[bot]` App suffix.
fn check_login_shape(raw: &str) -> Result<(), LoginRefusal> {
    let handle = raw.strip_suffix(BOT_SUFFIX).unwrap_or(raw);
    if handle.is_empty() {
        Err(LoginRefusal::Empty)
    } else if handle.len() > MAX_LOGIN_LEN {
        Err(LoginRefusal::TooLong)
    } else if !handle
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        Err(LoginRefusal::ForbiddenByte)
    } else if handle.starts_with('-') || handle.ends_with('-') {
        Err(LoginRefusal::EdgeHyphen)
    } else if handle.contains("--") {
        Err(LoginRefusal::DoubleHyphen)
    } else {
        Ok(())
    }
}

/// The `publisher` an index entry declares about itself — untrusted.
///
/// Parsed once at the entry boundary so the rest of the CLI never handles the
/// raw field as if it were an identity. The parse admits only a login-shaped
/// value, so the claim is safe to render in logs and refusals; it still grants
/// nothing — it renders and compares for display and provenance only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelfDeclaredPublisher(String);

impl SelfDeclaredPublisher {
    /// Parse a claimed publisher (from an entry file, a flag, or a source URL).
    ///
    /// # Errors
    /// The [`LoginRefusal`] naming why `claimed` is not a GitHub login.
    pub fn parse(claimed: &str) -> Result<Self, LoginRefusal> {
        check_login_shape(claimed)?;
        Ok(Self(claimed.to_owned()))
    }

    /// The claimed publisher, verbatim.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SelfDeclaredPublisher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl PartialEq<str> for SelfDeclaredPublisher {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for SelfDeclaredPublisher {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

/// The GitHub account a live, token-authenticated `GET /user` reports.
///
/// Its only constructor parses that response, so a value exists only where the
/// CLI has just proven the identity with the bearer token. The login and the
/// immutable numeric account id both come from GitHub, never from free-text
/// configuration or an entry file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedPublisher {
    login: String,
    id: u64,
}

impl AuthenticatedPublisher {
    /// Parse the authenticated `GET /user` response body.
    ///
    /// Call this ONLY on the body of a `GET https://api.github.com/user` that
    /// returned HTTP 200 for the publishing token — that request is the proof.
    /// Fail-closed: a missing or non-string `login`, an empty login, or a missing
    /// or non-integer `id` yields `None`, never a partial identity.
    #[must_use]
    pub(crate) fn from_authenticated_user_response(json: &serde_json::Value) -> Option<Self> {
        let login = json.get("login").and_then(serde_json::Value::as_str)?;
        if login.is_empty() {
            return None;
        }
        let id = json.get("id").and_then(serde_json::Value::as_u64)?;
        Some(Self {
            login: login.to_owned(),
            id,
        })
    }

    /// The account's GitHub login (its `@handle`).
    #[must_use]
    pub fn login(&self) -> &str {
        &self.login
    }

    /// The account's immutable numeric id.
    #[must_use]
    pub const fn id(&self) -> u64 {
        self.id
    }
}

/// The authenticated pull-request author, attested by the registry admission
/// workflow.
///
/// The admission workflow passes `--attested-actor` from GitHub's own event
/// context (`github.event.pull_request.user.login`), which GitHub authenticates
/// and the PR's contents cannot set. The trust therefore rests on the calling
/// workflow, not on this parse: the parse only guarantees the value is
/// login-shaped, so a malformed attestation is refused rather than compared.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttestedActor(String);

impl AttestedActor {
    /// Parse an attested GitHub login.
    ///
    /// # Errors
    /// [`CliError::UsageOwned`] when the value is not a GitHub login; the value is
    /// echoed Debug-escaped, so no control byte reaches the terminal.
    pub fn parse(raw: &str) -> Result<Self, CliError> {
        check_login_shape(raw).map_err(|refusal| {
            CliError::UsageOwned(text::attested_actor_not_login(
                &format!("{raw:?}"),
                &refusal,
            ))
        })?;
        Ok(Self(raw.to_owned()))
    }

    /// The attested login, verbatim.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Why no [`BlessedPublisher`] could be established.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlessingRefusal {
    /// No authenticated or attested identity was presented.
    NoProvenIdentity,
    /// The proven identity is not the publisher the entry claims.
    IdentityMismatch { proven: String, claimed: String },
    /// The proven identity matches the claim but is not the blessed identity.
    NotBlessed { proven: String },
}

impl fmt::Display for BlessingRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoProvenIdentity => f.write_str(text::blessing_no_proven_identity()),
            Self::IdentityMismatch { proven, claimed } => {
                f.write_str(&text::blessing_identity_mismatch(proven, claimed))
            }
            Self::NotBlessed { proven } => f.write_str(&text::blessing_not_blessed(
                proven,
                &ipe_kernels::BLESSED_PUBLISHER,
            )),
        }
    }
}

/// Proof that the blessed first-party publisher, identified by an authenticated
/// or attested identity, is the publisher an entry claims.
///
/// The field is private and every constructor checks the proven identity against
/// both the claim and [`ipe_kernels::BLESSED_PUBLISHER`], so holding one is the
/// proof. The reserved-namespace exemption and the reserved smoke reset accept
/// only this type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlessedPublisher {
    login: &'static str,
}

impl BlessedPublisher {
    /// Bless `claimed` from a live authenticated identity.
    ///
    /// # Errors
    /// The [`BlessingRefusal`] naming why the claim is not proven blessed.
    pub fn from_authenticated(
        authenticated: Option<&AuthenticatedPublisher>,
        claimed: &SelfDeclaredPublisher,
    ) -> Result<Self, BlessingRefusal> {
        Self::from_proven(authenticated.map(AuthenticatedPublisher::login), claimed)
    }

    /// Bless `claimed` from the admission workflow's attested PR author.
    ///
    /// # Errors
    /// The [`BlessingRefusal`] naming why the claim is not proven blessed.
    pub fn from_attested(
        attested: Option<&AttestedActor>,
        claimed: &SelfDeclaredPublisher,
    ) -> Result<Self, BlessingRefusal> {
        Self::from_proven(attested.map(AttestedActor::as_str), claimed)
    }

    /// The single comparison both constructors share: proven == claimed ==
    /// blessed, exact and case-sensitive (a differently-cased login fails
    /// closed).
    fn from_proven(
        proven: Option<&str>,
        claimed: &SelfDeclaredPublisher,
    ) -> Result<Self, BlessingRefusal> {
        let proven = proven.ok_or(BlessingRefusal::NoProvenIdentity)?;
        if proven != claimed.as_str() {
            return Err(BlessingRefusal::IdentityMismatch {
                proven: proven.to_owned(),
                claimed: claimed.as_str().to_owned(),
            });
        }
        if proven != ipe_kernels::BLESSED_PUBLISHER {
            return Err(BlessingRefusal::NotBlessed {
                proven: proven.to_owned(),
            });
        }
        Ok(Self {
            login: ipe_kernels::BLESSED_PUBLISHER,
        })
    }

    /// Whether this proof covers `claimed` — the claim a privilege is about to be
    /// granted for must itself be the blessed identity the proof was built over.
    #[must_use]
    pub fn vouches_for(&self, claimed: &SelfDeclaredPublisher) -> bool {
        claimed.as_str() == self.login
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BLESSED: &str = ipe_kernels::BLESSED_PUBLISHER;

    fn claim(s: &str) -> SelfDeclaredPublisher {
        SelfDeclaredPublisher::parse(s).expect("login-shaped claim")
    }

    fn authenticated(login: &str) -> AuthenticatedPublisher {
        AuthenticatedPublisher::from_authenticated_user_response(
            &serde_json::json!({"login": login, "id": 7}),
        )
        .expect("well-formed /user response")
    }

    #[test]
    fn a_forged_blessed_claim_alone_is_never_blessed() {
        let forged = claim(BLESSED);
        assert_eq!(
            BlessedPublisher::from_attested(None, &forged),
            Err(BlessingRefusal::NoProvenIdentity)
        );
        assert_eq!(
            BlessedPublisher::from_authenticated(None, &forged),
            Err(BlessingRefusal::NoProvenIdentity)
        );
    }

    #[test]
    fn an_identity_not_matching_the_claim_is_refused() {
        let attacker = AttestedActor::parse("attacker").expect("login-shaped");
        assert!(matches!(
            BlessedPublisher::from_attested(Some(&attacker), &claim(BLESSED)),
            Err(BlessingRefusal::IdentityMismatch { .. })
        ));
        let blessed = AttestedActor::parse(BLESSED).expect("login-shaped");
        assert!(matches!(
            BlessedPublisher::from_attested(Some(&blessed), &claim("attacker")),
            Err(BlessingRefusal::IdentityMismatch { .. })
        ));
        assert!(matches!(
            BlessedPublisher::from_authenticated(Some(&authenticated("attacker")), &claim(BLESSED)),
            Err(BlessingRefusal::IdentityMismatch { .. })
        ));
    }

    #[test]
    fn a_matching_non_blessed_identity_is_refused() {
        let someone = AttestedActor::parse("someone").expect("login-shaped");
        assert_eq!(
            BlessedPublisher::from_attested(Some(&someone), &claim("someone")),
            Err(BlessingRefusal::NotBlessed {
                proven: "someone".to_owned()
            })
        );
        assert!(matches!(
            BlessedPublisher::from_authenticated(
                Some(&authenticated("someone")),
                &claim("someone")
            ),
            Err(BlessingRefusal::NotBlessed { .. })
        ));
    }

    #[test]
    fn a_differently_cased_blessed_login_is_refused() {
        let upper = BLESSED.to_ascii_uppercase();
        let actor = AttestedActor::parse(&upper).expect("login-shaped");
        assert!(BlessedPublisher::from_attested(Some(&actor), &claim(&upper)).is_err());
    }

    #[test]
    fn a_proven_blessed_identity_matching_the_claim_is_blessed() {
        let actor = AttestedActor::parse(BLESSED).expect("login-shaped");
        let blessed =
            BlessedPublisher::from_attested(Some(&actor), &claim(BLESSED)).expect("blessed");
        assert!(blessed.vouches_for(&claim(BLESSED)));
        assert!(!blessed.vouches_for(&claim("attacker")));
        assert!(
            BlessedPublisher::from_authenticated(Some(&authenticated(BLESSED)), &claim(BLESSED))
                .is_ok()
        );
    }

    #[test]
    fn attested_actor_accepts_only_github_logins() {
        let longest = "x".repeat(39);
        let too_long = "x".repeat(40);
        for ok in ["a", "octo-cat", "A1", "dependabot[bot]", longest.as_str()] {
            assert!(AttestedActor::parse(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "-lead",
            "trail-",
            "dou--ble",
            "sp ace",
            "semi;colon",
            "[bot]",
            too_long.as_str(),
        ] {
            assert!(AttestedActor::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn self_declared_publisher_refuses_every_non_login_shape() {
        let too_long = "x".repeat(40);
        let too_long_bot = format!("{too_long}[bot]");
        let cases: [(&str, LoginRefusal); 16] = [
            ("", LoginRefusal::Empty),
            ("[bot]", LoginRefusal::Empty),
            (too_long.as_str(), LoginRefusal::TooLong),
            (too_long_bot.as_str(), LoginRefusal::TooLong),
            ("sp ace", LoginRefusal::ForbiddenByte),
            ("semi;colon", LoginRefusal::ForbiddenByte),
            ("under_score", LoginRefusal::ForbiddenByte),
            ("new\nline", LoginRefusal::ForbiddenByte),
            ("nul\0byte", LoginRefusal::ForbiddenByte),
            ("\x1b[31mred\x1b[0m", LoginRefusal::ForbiddenByte),
            ("bell\x07", LoginRefusal::ForbiddenByte),
            ("caf\u{e9}", LoginRefusal::ForbiddenByte),
            ("x[bot][bot]", LoginRefusal::ForbiddenByte),
            ("-lead", LoginRefusal::EdgeHyphen),
            ("trail-", LoginRefusal::EdgeHyphen),
            ("dou--ble", LoginRefusal::DoubleHyphen),
        ];
        for (raw, refusal) in cases {
            assert_eq!(SelfDeclaredPublisher::parse(raw), Err(refusal), "{raw:?}");
        }
        let longest = "x".repeat(39);
        for ok in ["a", "octo-cat", "A1", "dependabot[bot]", longest.as_str()] {
            assert_eq!(
                SelfDeclaredPublisher::parse(ok).map(|p| p.as_str().to_owned()),
                Ok(ok.to_owned())
            );
        }
    }

    #[test]
    fn attested_actor_refusal_debug_escapes_the_raw_value() {
        let hostile = "\x1b[2Jevil\nforged line";
        let refused = AttestedActor::parse(hostile);
        assert!(
            matches!(refused, Err(CliError::UsageOwned(_))),
            "a control-byte login must be refused"
        );
        let Err(CliError::UsageOwned(msg)) = refused else {
            return;
        };
        assert!(!msg.contains('\x1b') && !msg.contains('\n'), "{msg:?}");
        assert!(msg.contains(r"\u{1b}[2Jevil\nforged line"), "{msg:?}");
    }

    #[test]
    fn authenticated_user_response_fails_closed_on_malformed_shapes() {
        for bad in [
            serde_json::json!({"id": 42}),
            serde_json::json!({"login": "octocat"}),
            serde_json::json!({"login": "", "id": 42}),
            serde_json::json!({"login": "octocat", "id": "42"}),
            serde_json::json!({}),
        ] {
            assert!(
                AuthenticatedPublisher::from_authenticated_user_response(&bad).is_none(),
                "{bad}"
            );
        }
        let ok = authenticated("octocat");
        assert_eq!(ok.login(), "octocat");
        assert_eq!(ok.id(), 7);
    }
}
