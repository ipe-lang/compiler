//! The authenticated `Principal` — the verified subject of a request.
//!
//! A `Principal` names the caller a row-security policy filters on. Its subject
//! string is only ever a value that a cryptographically verified, unexpired
//! session token carried: the sole producer is [`principal_mint_with_claims`],
//! which the HTTP-server auth middleware calls exclusively on the success
//! branch of token verification. No other runtime path and no Ipê term can build one — the
//! fields are private and there is no public constructor — so holding a
//! `Principal` is proof the subject was authenticated.
//!
//! The verified claims travel WITH the principal so the read accessors
//! ([`principal_claim`], [`principal_has_role`], [`principal_member_of`]) can
//! answer principal-side questions without a second trip to the token. The
//! claims are the JWT's own verified payload — the same bearer-readable strings
//! the caller already presented — so surfacing them back to Ipê exposes nothing
//! the token-holder did not already hold. Every accessor is FAIL-CLOSED: an
//! absent claim reads as `None` / `false`, never a fabricated authority.

use std::collections::BTreeMap;

use crate::redact::Redacted;

/// The verified subject of an authenticated request, together with the verified
/// claims the session token carried. The fields are private: a value of this
/// type can only originate from [`principal_mint_with_claims`] (or, in unit
/// tests, `principal_mint`).
///
/// The claims map is a `BTreeMap` so its iteration order is deterministic — a
/// principal built from the same claims always reads back identically
/// (correctness).
///
/// Deliberately NOT serde: a `Principal` must never round-trip through a session
/// store or JSON boundary, or a client could forge an authenticated identity by
/// supplying the serialized datum. Minting is the only way in.
///
/// Both fields are `Redacted`: the subject and claims identify the caller, so
/// the derived `Debug` (a log line, the stringify fallback) prints the
/// principal's shape and never its identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Principal {
    subject: Redacted<String>,
    claims: Redacted<BTreeMap<String, String>>,
}

crate::stringify::show_row!("Principal", Redacted, [] Principal, |_| crate::stringify::REDACTED_SHOW.to_owned());

/// Mint a `Principal` with a subject and no claims — a unit-test fixture for
/// the principal and revocation tests. Production minting goes through
/// [`principal_mint_with_claims`] alone, so this exists only under `test`.
#[cfg(test)]
#[must_use]
pub(crate) fn principal_mint(subject: String) -> Principal {
    Principal {
        subject: subject.into(),
        claims: Redacted::default(),
    }
}

/// Mint a `Principal` from a verified subject claim and the full verified claims
/// map. Crate-internal: the auth middleware is the only non-test caller and
/// calls this only on the success branch of token verification, so every
/// `Principal` in existence carries a subject a valid session proved and
/// exactly the token's verified payload. Not a registered kernel and not
/// reachable from Ipê. Gated on `jwt` to match that caller.
#[cfg(any(feature = "jwt", test))]
#[must_use]
pub(crate) fn principal_mint_with_claims(
    subject: String,
    claims: BTreeMap<String, String>,
) -> Principal {
    Principal {
        subject: subject.into(),
        claims: claims.into(),
    }
}

/// Ipê `Ipe.Auth.subject : Principal -> String` — the verified subject claim.
#[must_use]
pub fn principal_subject(p: Principal) -> String {
    p.subject.into_inner()
}

/// Ipê `Ipe.Auth.claim : String -> Principal -> Maybe String` — the verified
/// value of one claim, or `Nothing` when the token carried no such claim.
/// Fail-closed: an absent key is `None`, never a fabricated value.
#[must_use]
pub fn principal_claim(key: String, p: Principal) -> crate::core::IpeMaybe<String> {
    match p.claims.get(&key) {
        Some(value) => crate::core::IpeMaybe::Just(value.clone()),
        None => crate::core::IpeMaybe::Nothing,
    }
}

/// Ipê `Ipe.Auth.hasRole : String -> Principal -> Bool` — whether the principal
/// holds `role`. Roles are read from the conventional space-separated `roles`
/// claim (the OAuth `scope`-style convention). Fail-closed: no `roles` claim,
/// or the role absent from it, reads as `false` — a missing claim never grants
/// authority.
#[must_use]
pub fn principal_has_role(role: String, p: Principal) -> bool {
    claim_list_contains(&p, "roles", &role)
}

/// Ipê `Ipe.Auth.memberOf : String -> Principal -> Bool` — whether the principal
/// belongs to `group`. Groups are read from the conventional space-separated
/// `groups` claim. Fail-closed: no `groups` claim, or the group absent from it,
/// reads as `false`.
#[must_use]
pub fn principal_member_of(group: String, p: Principal) -> bool {
    claim_list_contains(&p, "groups", &group)
}

/// Membership test over a conventional space-separated multi-valued claim. The
/// claim value is split on ASCII whitespace (empty segments dropped), matching
/// the OAuth `scope` convention. Returns `false` when the claim is absent —
/// fail-closed by construction.
fn claim_list_contains(p: &Principal, claim_key: &str, needle: &str) -> bool {
    match p.claims.get(claim_key) {
        Some(value) => value.split_whitespace().any(|item| item == needle),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_claims(subject: &str, pairs: &[(&str, &str)]) -> Principal {
        let claims = pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        principal_mint_with_claims(subject.to_string(), claims)
    }

    #[test]
    fn subject_round_trips_the_minted_value() {
        let p = principal_mint("user-42".to_string());
        assert_eq!(principal_subject(p), "user-42");
    }

    #[test]
    fn debug_prints_neither_subject_nor_claims() {
        let p = with_claims("user-S3CR3T", &[("email", "T0K3N@example.com")]);
        let shown = format!("{p:?}");
        assert!(!shown.contains("S3CR3T"), "{shown}");
        assert!(!shown.contains("T0K3N"), "{shown}");
        assert!(shown.contains(crate::redact::REDACTED));
    }

    #[test]
    fn distinct_subjects_are_unequal() {
        assert_ne!(
            principal_mint("a".to_string()),
            principal_mint("b".to_string())
        );
    }

    #[test]
    fn claim_reads_a_present_value() {
        let p = with_claims("u1", &[("email", "u1@example.com")]);
        assert_eq!(
            principal_claim("email".to_string(), p),
            crate::core::IpeMaybe::Just("u1@example.com".to_string())
        );
    }

    #[test]
    fn claim_is_none_for_an_absent_key() {
        let p = with_claims("u1", &[("email", "u1@example.com")]);
        assert_eq!(
            principal_claim("phone".to_string(), p),
            crate::core::IpeMaybe::Nothing
        );
    }

    #[test]
    fn claim_on_a_claimless_principal_is_none() {
        let p = principal_mint("u1".to_string());
        assert_eq!(
            principal_claim("email".to_string(), p),
            crate::core::IpeMaybe::Nothing
        );
    }

    #[test]
    fn has_role_true_when_role_present_in_space_separated_claim() {
        let p = with_claims("u1", &[("roles", "reader editor admin")]);
        assert!(principal_has_role("editor".to_string(), p));
    }

    #[test]
    fn has_role_false_when_role_absent() {
        let p = with_claims("u1", &[("roles", "reader editor")]);
        assert!(!principal_has_role("admin".to_string(), p.clone()));
        // A prefix of a present role must not match — whole-token equality only.
        assert!(!principal_has_role("read".to_string(), p));
    }

    #[test]
    fn has_role_false_when_roles_claim_missing() {
        let p = with_claims("u1", &[("email", "u1@example.com")]);
        assert!(!principal_has_role("admin".to_string(), p));
    }

    #[test]
    fn member_of_true_when_group_present() {
        let p = with_claims("u1", &[("groups", "eng platform")]);
        assert!(principal_member_of("platform".to_string(), p));
    }

    #[test]
    fn member_of_false_when_group_absent_or_claim_missing() {
        let present = with_claims("u1", &[("groups", "eng")]);
        assert!(!principal_member_of("sales".to_string(), present));
        let missing = principal_mint("u1".to_string());
        assert!(!principal_member_of("eng".to_string(), missing));
    }
}
