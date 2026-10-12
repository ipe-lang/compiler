//! Publisher-identity provenance over the index-pinned `sha256`.
//!
//! The registry's trust root is verify-before-trust: at resolve time the client
//! git-fetches a version's pinned `rev` and refuses unless the fetched tree's
//! content hash equals the entry's `sha256` (`crate::resolve`). Signing layers
//! PUBLISHER IDENTITY over that anchor. A publisher signs an in-toto/DSSE
//! statement whose subject digest is exactly the entry's `sha256`, keyless:
//! the signature is made under a Fulcio-issued ephemeral certificate bound to a
//! GitHub Actions OIDC identity, with a Rekor transparency-log inclusion proof.
//! The client verifies that a *trusted* identity produced a signature over the
//! *pinned* digest before trusting the version.
//!
//! # The asymmetry: present-but-untrusted is worse than absent
//!
//! A missing signature is a known-unknown — the publisher never asserted
//! identity. A signature that does not verify against a trusted identity is a
//! present, active claim that failed: it may be an attacker's. So the policy is
//! deliberately asymmetric and fail-closed:
//!
//! | signature | `require_signature` | outcome                         |
//! |-----------|---------------------|---------------------------------|
//! | absent    | `false`             | resolve, with a warning         |
//! | absent    | `true`              | REJECT                          |
//! | present   | either              | verify or REJECT — never ignore |
//!
//! The load-bearing rule is the last row: **a version carrying a signature MUST
//! verify against a trusted identity, or the version is rejected**, regardless
//! of `require_signature`. A signature the client cannot validate never
//! resolves — you can neither silently drop it (it might be genuine and pin a
//! real trust decision) nor silently accept it (it might be forged).
//!
//! # Deny by default
//!
//! [`TrustPolicy::trusted_identities`] is EMPTY until a project or global config
//! adds `[registry.trust]` identities. With no trusted identity configured, any
//! present signature fails to match and the version is rejected — the safe
//! default. `require_signature` is `false` pre-1.0 so unsigned versions still
//! resolve (with a warning) until the registry's publishers have signed.
//!
//! # Verification seam
//!
//! [`SignatureVerifier`] is the trait the decision core calls. The concrete
//! Sigstore-backed implementation lives behind the `signing` feature (it pulls a
//! heavy async/TLS graph); the always-compiled decision core
//! ([`evaluate_signature`]) is exercised in tests against a mock verifier, so the
//! deny-by-default and present-but-untrusted rules are covered by the default
//! gate without linking the crypto crate.

use crate::CliError;

/// The maximum size, in bytes, of a Sigstore bundle carried in an index entry.
///
/// A DSSE bundle is a small JSON document (a cert chain, a signature, a Rekor
/// inclusion proof). A value far larger than any real bundle is a malformed or
/// hostile field, refused before it is parsed rather than allocated in full.
const MAX_BUNDLE_BYTES: usize = 512 * 1024;

/// A trusted signing identity: an OIDC issuer paired with the exact certificate
/// identity (subject-alternative-name) the issuer must have bound.
///
/// Both fields are matched EXACTLY against the verified certificate — there is
/// no wildcard or prefix match. A GitHub Actions publisher is, for example,
/// issuer `https://token.actions.githubusercontent.com` and identity
/// `https://github.com/owner/repo/.github/workflows/publish.yml@refs/heads/main`.
/// Exact match is the conservative choice: a looser pattern would admit any
/// workflow in the org, widening the trusted set beyond the one the user named.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    issuer: String,
    san: String,
}

impl Identity {
    /// Parse a configured `(issuer, identity)` pair into a typed [`Identity`].
    ///
    /// Both values must be non-empty and free of control/whitespace characters —
    /// a certificate SAN or OIDC issuer is a URL-shaped token, and a value with
    /// embedded control characters is malformed config, never a real identity.
    ///
    /// # Errors
    /// [`CliError::Resolve`] when either field is empty or carries a control or
    /// whitespace character.
    pub fn parse(issuer: &str, san: &str) -> Result<Self, CliError> {
        let clean = |label: &str, raw: &str| -> Result<String, CliError> {
            let trimmed = raw.trim();
            if trimmed.is_empty() || trimmed.chars().any(|c| c.is_control() || c.is_whitespace()) {
                return Err(CliError::Resolve(crate::text::msg::trust_token_invalid(
                    &label,
                    &crate::style::TerminalSafe::sanitize(&format!("{raw:?}")),
                )));
            }
            Ok(trimmed.to_owned())
        };
        Ok(Self {
            issuer: clean("issuer", issuer)?,
            san: clean("identity", san)?,
        })
    }

    /// The OIDC issuer this identity requires (e.g. the GitHub Actions issuer).
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// The exact certificate SAN this identity requires.
    #[must_use]
    pub fn san(&self) -> &str {
        &self.san
    }
}

/// The client's signature trust policy, deny-by-default.
///
/// [`Self::trusted_identities`] starts EMPTY: absent an explicit
/// `[registry.trust]` identity, no present signature can match, so any signed
/// version is rejected — fail closed. [`Self::require_signature`] defaults to
/// `false` (pre-1.0), so an unsigned version still resolves with a warning; set
/// it `true` to refuse any version that carries no signature.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TrustPolicy {
    trusted_identities: Vec<Identity>,
    require_signature: bool,
}

impl TrustPolicy {
    /// Build a policy from a set of trusted identities and the require flag.
    ///
    /// An empty `trusted_identities` is the deny-by-default policy.
    #[must_use]
    pub const fn new(trusted_identities: Vec<Identity>, require_signature: bool) -> Self {
        Self {
            trusted_identities,
            require_signature,
        }
    }

    /// The trusted identities. Empty means no signed version can be trusted.
    #[must_use]
    pub fn trusted_identities(&self) -> &[Identity] {
        &self.trusted_identities
    }

    /// Whether an unsigned version is refused.
    #[must_use]
    pub const fn require_signature(&self) -> bool {
        self.require_signature
    }
}

/// A parsed reference to a version's Sigstore bundle.
///
/// Parse, don't validate: a present bundle field is turned into this typed value
/// at read time. The bundle bytes must be non-empty, within
/// [`MAX_BUNDLE_BYTES`], and a JSON object (the DSSE-bundle envelope shape) — a
/// truncated, oversized, or non-object value is a HARD error, never a
/// silently-dropped field. The full cryptographic validation (cert chain, Rekor
/// proof, subject digest) happens in [`SignatureVerifier::verify`]; this
/// boundary only guarantees the field is a well-formed bundle envelope so a
/// malformed value cannot masquerade as "no signature".
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignatureBundle {
    /// The raw bundle JSON, retained verbatim for the verifier. Kept as the
    /// original bytes (not a re-serialized value) so verification sees exactly
    /// what the registry served.
    raw: String,
}

impl SignatureBundle {
    /// Parse a raw bundle string from an index entry into a typed
    /// [`SignatureBundle`], refusing an empty, oversized, or non-object value.
    ///
    /// # Errors
    /// [`CliError::Resolve`] when the bundle is empty, exceeds
    /// [`MAX_BUNDLE_BYTES`], is not valid JSON, or is not a JSON object.
    pub fn parse(pkg: &str, raw: &str) -> Result<Self, CliError> {
        let refuse = |detail: &str| {
            CliError::Resolve(crate::text::msg::signature_bundle_malformed(
                &pkg,
                &crate::style::TerminalSafe::sanitize(detail),
            ))
        };
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(refuse("empty bundle"));
        }
        if trimmed.len() > MAX_BUNDLE_BYTES {
            return Err(refuse("bundle exceeds the size ceiling"));
        }
        // A DSSE Sigstore bundle is a JSON object. Parsing here rejects a
        // truncated or injection-shaped value at the boundary so it can never
        // reach the verifier — or, worse, be silently treated as absent.
        let value: serde_json::Value =
            serde_json::from_str(trimmed).map_err(|e| refuse(&format!("not valid JSON: {e}")))?;
        if !value.is_object() {
            return Err(refuse("bundle top level is not a JSON object"));
        }
        Ok(Self {
            raw: trimmed.to_owned(),
        })
    }

    /// The raw bundle JSON, as served, for the verifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.raw
    }
}

/// The identity a verifier confirmed produced a valid signature.
///
/// The `(issuer, san)` extracted from the verified certificate, returned by a
/// successful [`SignatureVerifier::verify`] so the caller can report *who*
/// signed, not merely that verification passed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedIdentity {
    /// The OIDC issuer bound in the verified certificate.
    pub issuer: String,
    /// The certificate SAN bound in the verified certificate.
    pub san: String,
}

/// A typed signature-verification failure, distinct from the ordinary
/// resolve/parse errors so a caller can tell "the crypto did not check out" from
/// "the field was malformed".
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignatureError {
    /// The bundle's cryptographic material did not verify against the trust root
    /// (bad cert chain, bad Rekor proof, or a bad signature).
    BundleInvalid { detail: String },
    /// The bundle verified, but its signed subject digest did not equal the
    /// entry's pinned `sha256` — the signature is over other bytes.
    DigestMismatch { expected: String, signed: String },
    /// The bundle verified, but the certificate's `(issuer, san)` is not among
    /// the policy's trusted identities.
    UntrustedIdentity { issuer: String, san: String },
    /// The concrete verifier is not compiled in (the `signing` feature is off),
    /// so a present signature cannot be validated — fail closed.
    VerifierUnavailable,
}

impl std::fmt::Display for SignatureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BundleInvalid { detail } => {
                write!(f, "signature bundle did not verify: {detail}")
            }
            Self::DigestMismatch { expected, signed } => write!(
                f,
                "signature is over digest {signed} but the entry pins {expected} — the signature \
                 does not cover the published source"
            ),
            Self::UntrustedIdentity { issuer, san } => write!(
                f,
                "signature verified but its identity (issuer {issuer:?}, identity {san:?}) is not \
                 in the configured `[registry.trust]` allowlist"
            ),
            Self::VerifierUnavailable => f.write_str(
                "a signature is present but this build cannot verify Sigstore bundles \
                 (built without the `signing` feature) — refusing rather than trusting \
                 an unverifiable signature",
            ),
        }
    }
}

/// The seam the decision core calls to verify a bundle.
///
/// The concrete implementation is Sigstore-backed and feature-gated; tests
/// inject a mock so the deny-by-default policy is exercised without the crypto
/// crate or network.
pub trait SignatureVerifier {
    /// Verify `bundle` offline against the vendored trust root, requiring that
    /// (a) the cert chain and Rekor inclusion proof are valid, (b) the signed
    /// subject digest equals `tree` (the digest of the fetched source, which
    /// the resolver independently compares with the pinned `subject_digest`),
    /// and (c) the certificate's `(issuer, san)` is one of
    /// `policy.trusted_identities()`.
    ///
    /// `tree` is the caller's one budgeted walk of the fetched source: the
    /// verifier receives no path, so it cannot walk the tree again, however
    /// many identities it tries. The concrete verifier hands a copy of its
    /// hasher to sigstore's `verify_digest`, so the DSSE subject-digest
    /// comparison is over the same tree the resolver pins — no digest is
    /// re-derived from the hex string. `subject_digest` is the pinned hex,
    /// retained for the typed [`SignatureError::DigestMismatch`] and as a
    /// defensive cross-check.
    ///
    /// # Errors
    /// A [`SignatureError`] for any of the three failures above. On success,
    /// returns the [`VerifiedIdentity`] that signed.
    fn verify(
        &self,
        bundle: &SignatureBundle,
        subject_digest: &str,
        tree: &crate::cache::TreeDigest,
        policy: &TrustPolicy,
    ) -> Result<VerifiedIdentity, SignatureError>;
}

/// What signature verification decided for one version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignatureOutcome {
    /// No signature was present and the policy does not require one — resolve,
    /// but carry the reason so the caller can warn.
    UnsignedAllowed,
    /// A signature was present and verified against a trusted identity — resolve.
    Verified(VerifiedIdentity),
}

/// The deny-by-default, fail-closed decision core over one version's signature.
///
/// This is the whole trust-model asymmetry in one place, and it is always
/// compiled (the concrete verifier is injected, so this logic is tested against
/// a mock):
///
/// - no signature + `require_signature == false` ⟹ [`SignatureOutcome::UnsignedAllowed`];
/// - no signature + `require_signature == true`  ⟹ [`CliError::Resolve`] (reject);
/// - a signature present ⟹ it MUST verify against a trusted identity, else
///   [`CliError::Resolve`] (reject) — regardless of `require_signature`.
///
/// # Errors
/// [`CliError::Resolve`] when a required signature is absent, or when a present
/// signature fails any verification check (invalid bundle, digest mismatch, or
/// untrusted identity).
pub fn evaluate_signature(
    pkg: &str,
    policy: &TrustPolicy,
    signature: Option<&SignatureBundle>,
    subject_digest: &str,
    tree: &crate::cache::TreeDigest,
    verifier: &dyn SignatureVerifier,
) -> Result<SignatureOutcome, CliError> {
    signature.map_or_else(
        // Absent signature: fail closed only when the policy requires one.
        || {
            if policy.require_signature() {
                Err(CliError::Resolve(
                    crate::text::msg::signature_required_absent(&pkg),
                ))
            } else {
                Ok(SignatureOutcome::UnsignedAllowed)
            }
        },
        // Present signature: it MUST verify against a trusted identity, else the
        // version is rejected — regardless of `require_signature`.
        |bundle| {
            verifier
                .verify(bundle, subject_digest, tree, policy)
                .map(SignatureOutcome::Verified)
                .map_err(|e| {
                    CliError::Resolve(crate::text::msg::signature_untrusted(
                        &pkg,
                        &crate::style::TerminalSafe::sanitize(&e.to_string()),
                    ))
                })
        },
    )
}

/// Parse a `[registry.trust]` table from config TOML into a [`TrustPolicy`].
///
/// Absent table, absent keys, or an empty identity list all yield the
/// deny-by-default policy (empty trusted set, `require_signature = false`) — a
/// config that says nothing trusts nothing.
///
/// The expected shape:
///
/// ```toml
/// [registry.trust]
/// require_signature = false
/// trusted_identities = [
///   { issuer = "https://token.actions.githubusercontent.com", identity = "https://github.com/owner/repo/.github/workflows/publish.yml@refs/heads/main" },
/// ]
/// ```
///
/// # Errors
/// [`CliError::Resolve`] when the TOML does not parse, when `[registry.trust]`
/// is present but malformed (a non-array `trusted_identities`, an entry missing
/// `issuer`/`identity`), or when an identity fails [`Identity::parse`]. A
/// malformed trust config is a hard error, never silently downgraded to "trust
/// nothing" — a typo in an allowlist must not quietly widen (or here, void) the
/// trusted set.
pub fn parse_trust_policy_toml(text: &str) -> Result<TrustPolicy, CliError> {
    let refuse = |detail: &str| {
        CliError::Resolve(crate::text::msg::trust_config_malformed(
            &crate::style::TerminalSafe::sanitize(detail),
        ))
    };
    let table: toml::Table = text
        .parse()
        .map_err(|e| refuse(&format!("not valid TOML: {e}")))?;

    let Some(trust) = table
        .get("registry")
        .and_then(toml::Value::as_table)
        .and_then(|reg| reg.get("trust"))
    else {
        // No `[registry.trust]` at all — the deny-by-default policy.
        return Ok(TrustPolicy::default());
    };
    let trust = trust
        .as_table()
        .ok_or_else(|| refuse("`registry.trust` is not a table"))?;

    let require_signature = match trust.get("require_signature") {
        None => false,
        Some(v) => v
            .as_bool()
            .ok_or_else(|| refuse("`require_signature` must be a boolean"))?,
    };

    let mut identities = Vec::new();
    if let Some(raw) = trust.get("trusted_identities") {
        let array = raw
            .as_array()
            .ok_or_else(|| refuse("`trusted_identities` must be an array"))?;
        for entry in array {
            let item = entry
                .as_table()
                .ok_or_else(|| refuse("each trusted identity must be a table"))?;
            let issuer = item
                .get("issuer")
                .and_then(toml::Value::as_str)
                .ok_or_else(|| refuse("a trusted identity is missing string `issuer`"))?;
            let san = item
                .get("identity")
                .and_then(toml::Value::as_str)
                .ok_or_else(|| refuse("a trusted identity is missing string `identity`"))?;
            identities.push(Identity::parse(issuer, san)?);
        }
    }

    Ok(TrustPolicy::new(identities, require_signature))
}

/// Load the client's [`TrustPolicy`] from config, merging the global
/// `$IPE_HOME/config.toml` with the project's `ipe.toml`.
///
/// Both files may carry a `[registry.trust]` table. The merge is UNION-safe: the
/// trusted-identity sets are unioned (a project may add trusted identities but
/// never has to re-declare the global ones), and `require_signature` is the OR
/// of both (either file may tighten the policy; neither can loosen the other).
/// A file that is absent contributes the empty deny-by-default policy; a file
/// that is present but malformed is a hard error (never silently ignored).
/// Each file is opened beneath its directory, never through a symlink.
///
/// # Errors
/// [`CliError::Resolve`] when a present config file's `[registry.trust]` is
/// malformed; [`CliError::SourceRefused`] when it is a symlink or not a
/// regular file; [`CliError::Io`] when it cannot otherwise be read.
pub fn load_trust_policy(project_root: &std::path::Path) -> Result<TrustPolicy, CliError> {
    let mut identities: Vec<Identity> = Vec::new();
    let mut require_signature = false;

    let mut absorb = |dir: &std::path::Path, name: &str| -> Result<(), CliError> {
        let text =
            match crate::io_bounded::read_named_in(dir, &[name], crate::io_bounded::SMALL_FILE_CAP)
            {
                Ok(t) => t,
                Err(CliError::Io { ref source, .. })
                    if source.kind() == std::io::ErrorKind::NotFound =>
                {
                    return Ok(());
                }
                Err(e) => return Err(e),
            };
        let policy = parse_trust_policy_toml(&text)?;
        require_signature = require_signature || policy.require_signature();
        for id in policy.trusted_identities() {
            if !identities.contains(id) {
                identities.push(id.clone());
            }
        }
        Ok(())
    };

    // Global config first, then the project — order is immaterial to the union.
    if let Ok(home) = crate::runtime_embed::ipe_home() {
        absorb(&home, "config.toml")?;
    }
    absorb(project_root, "ipe.toml")?;

    Ok(TrustPolicy::new(identities, require_signature))
}

/// The GitHub Actions OIDC issuer — the only keyless issuer the registry uses.
///
/// Surfaced so config parsing and the publish-side statement generator name one
/// constant rather than repeating the URL.
pub const GITHUB_ACTIONS_ISSUER: &str = "https://token.actions.githubusercontent.com";

/// Build the in-toto/DSSE **statement** a publisher signs for one version.
///
/// The statement is an in-toto Statement whose single subject is named
/// `<name>@<version>` with a `sha256` digest equal to the entry's pinned
/// `sha256`.
///
/// Binding the subject digest to the already-pinned `sha256` is what ties the
/// signature to the exact source the resolver hash-verifies: a signature over
/// this statement is a signature over those bytes. The publisher feeds this
/// statement to keyless `cosign`/`gh attest` in CI, which mints the Fulcio cert,
/// signs, and records the Rekor entry, producing the bundle that goes into the
/// index entry's `signature` field.
///
/// The returned JSON is deterministic (sorted keys) so the same version always
/// yields the same statement.
#[must_use]
pub fn dsse_statement(name: &str, version: &str, sha256: &str) -> String {
    // A minimal in-toto Statement (predicateType left generic): the load-bearing
    // content is the subject name + sha256 digest that the signature covers.
    let statement = serde_json::json!({
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [ {
            "name": format!("{name}@{version}"),
            "digest": { "sha256": sha256 },
        } ],
        "predicateType": "https://ipe-lang.org/registry/publish/v1",
        "predicate": {},
    });
    // `serde_json::to_string` over a `json!` value emits object keys in
    // insertion order; the fixed insertion order above makes this deterministic.
    serde_json::to_string(&statement).unwrap_or_default()
}

/// A verifier that refuses every present signature.
///
/// Used when no crypto backend is compiled in (the `signing` feature is off).
/// Fail-closed: a present signature that cannot be verified is rejected, never
/// trusted.
///
/// The decision core still runs — an unsigned version resolves under this
/// verifier exactly as it would under the real one (the verifier is only
/// consulted for a PRESENT signature), so a default build behaves identically
/// for the unsigned pre-1.0 registry while refusing to trust any signature it
/// cannot check.
pub struct UnavailableVerifier;

impl SignatureVerifier for UnavailableVerifier {
    fn verify(
        &self,
        _bundle: &SignatureBundle,
        _subject_digest: &str,
        _tree: &crate::cache::TreeDigest,
        _policy: &TrustPolicy,
    ) -> Result<VerifiedIdentity, SignatureError> {
        Err(SignatureError::VerifierUnavailable)
    }
}

#[cfg(feature = "signing")]
pub use sigstore_impl::{SigstoreVerifier, vendored_sigstore_verifier};

/// The Sigstore-backed [`SignatureVerifier`]. Compiled only under the `signing`
/// feature — it pulls the heavy async/TLS Sigstore graph.
///
/// # The digest bridge
///
/// `sigstore` 0.14's `verify_digest(input_digest: sha2::Sha256, …)` takes a
/// `Sha256` HASHER and finalizes it internally; for a DSSE bundle it verifies
/// the envelope signature over the statement's PAE (those bytes are IN the
/// bundle) and uses `input_digest` ONLY to check the statement's subject digest:
/// it compares `hex(input_digest.finalize())` against the bundle's
/// `subject_sha256_digest`. So verification needs a `Sha256` that finalizes to
/// our pinned tree hash — nothing more.
///
/// The registry pins `cache::hash_tree` over the fetched source, which is a
/// plain `Sha256` over a deterministic byte stream. `cache::TreeDigest` holds
/// that same hasher UN-finalized; feeding a copy to `verify_digest` makes the
/// subject-digest comparison exactly `pinned tree hash == bundle subject digest`
/// — no digest is re-derived from the hex string, no double-hash. The resolver
/// walks the fetched tree once into that `TreeDigest` and compares the same
/// value with the pinned `sha256`.
#[cfg(feature = "signing")]
mod sigstore_impl {
    use super::{
        Identity, SignatureBundle, SignatureError, SignatureVerifier, TrustPolicy, VerifiedIdentity,
    };

    use sigstore::bundle::verify::blocking::Verifier;
    use sigstore::bundle::verify::policy::Identity as SigstoreIdentity;
    use sigstore::rekor::apis::configuration::Configuration as RekorConfiguration;
    use sigstore::trust::ManualTrustRoot;
    use sigstore_protobuf_specs::dev::sigstore::{
        common::v1::TimeRange,
        trustroot::v1::{CertificateAuthority, TransparencyLogInstance, TrustedRoot},
    };

    /// A [`SignatureVerifier`] verifying a bundle OFFLINE against a manual root.
    ///
    /// Offline: the bundle carries its own Rekor inclusion proof, so no network
    /// call is made at verify time.
    ///
    /// The verifier enforces exactly the policy asymmetry the decision core
    /// relies on: the bundle must cryptographically verify, its subject digest
    /// must equal the pinned `sha256`, and its certificate `(issuer, san)` must
    /// be one of the policy's trusted identities. Any failure is a typed
    /// [`SignatureError`].
    ///
    /// The trust root is a [`ManualTrustRoot`] rather than the TUF-fetched
    /// public-good root, so no `sigstore-trust-root`/`tough` TUF client is linked
    /// and verification never touches the network. The registry supplies the
    /// vendored Fulcio root certificates and the Rekor / CT-log public keys.
    pub struct SigstoreVerifier {
        trust_root: ManualTrustRoot<'static>,
    }

    impl SigstoreVerifier {
        /// The exact-match certificate-identity policy for one trusted identity.
        fn identity_policy(identity: &Identity) -> SigstoreIdentity {
            SigstoreIdentity::new(identity.san(), identity.issuer())
        }

        /// A fresh [`ManualTrustRoot`] cloned from this verifier's fields.
        ///
        /// `verify_digest` consumes the built [`Verifier`], and `ManualTrustRoot`
        /// is not `Clone`, so each verification attempt rebuilds the root from
        /// the (clonable) field values.
        fn clone_root(&self) -> ManualTrustRoot<'static> {
            ManualTrustRoot {
                fulcio_certs: self.trust_root.fulcio_certs.clone(),
                rekor_keys: self.trust_root.rekor_keys.clone(),
                ctfe_keys: self.trust_root.ctfe_keys.clone(),
            }
        }
    }

    impl SignatureVerifier for SigstoreVerifier {
        fn verify(
            &self,
            bundle: &SignatureBundle,
            subject_digest: &str,
            tree: &crate::cache::TreeDigest,
            policy: &TrustPolicy,
        ) -> Result<VerifiedIdentity, SignatureError> {
            // Deny by default: with no trusted identity configured, nothing can
            // match, so any present signature is refused before any crypto runs.
            let identities = policy.trusted_identities();
            if identities.is_empty() {
                return Err(SignatureError::UntrustedIdentity {
                    issuer: "<none configured>".to_owned(),
                    san: "<none configured>".to_owned(),
                });
            }

            // Prove the bundle parses into the crate's typed `Bundle` up front so
            // a malformed bundle is a distinct, clear error rather than surfacing
            // as an opaque per-identity verification failure below.
            let parse_bundle = || -> Result<sigstore::bundle::Bundle, SignatureError> {
                serde_json::from_str(bundle.as_str()).map_err(|e| SignatureError::BundleInvalid {
                    detail: format!("bundle is not a Sigstore bundle: {e}"),
                })
            };
            parse_bundle()?;

            // Try each trusted identity in turn; accept the FIRST that verifies.
            // Each attempt rebuilds the consumed inputs: a fresh `Bundle`, a fresh
            // `Verifier`, and a copy of the one tree hasher (the crate finalizes
            // it). The DSSE path checks the envelope signature over the in-bundle
            // PAE and compares the statement's subject digest against
            // `tree.to_hex()` — the pinned tree hash.
            let mut last_detail: Option<String> = None;
            for identity in identities {
                let parsed = parse_bundle()?;
                let verifier = Verifier::new(RekorConfiguration::default(), self.clone_root())
                    .map_err(|e| SignatureError::BundleInvalid {
                        detail: format!("could not build the verifier: {e}"),
                    })?;
                let hasher = tree.hasher();
                let sig_policy = Self::identity_policy(identity);
                match verifier.verify_digest(hasher, parsed, &sig_policy, true) {
                    Ok(()) => {
                        return Ok(VerifiedIdentity {
                            issuer: identity.issuer().to_owned(),
                            san: identity.san().to_owned(),
                        });
                    }
                    Err(e) => last_detail = Some(e.to_string()),
                }
            }

            // No trusted identity verified. The failure is reported as an
            // untrusted-identity rejection: the material may be a genuine bundle
            // signed under an identity the user has not allowlisted, or an invalid
            // one — either way it is not trusted. `subject_digest` is named in the
            // detail so a digest mismatch (subject != pinned tree hash) is legible.
            Err(SignatureError::BundleInvalid {
                detail: format!(
                    "no configured trusted identity verified the signature over the pinned \
                     digest {subject_digest}{}",
                    last_detail
                        .map(|d| format!(" (last failure: {d})"))
                        .unwrap_or_default()
                ),
            })
        }
    }

    /// The vendored Sigstore trusted-root JSON (the `TrustedRoot` protobuf-JSON:
    /// Fulcio CA cert chains + Rekor / CT-log public keys).
    ///
    /// Embedded at build time so offline verification never fetches it over TUF.
    /// EMPTY placeholder until the registry's operator supplies a real root —
    /// that root of trust is the operator's decision, not the compiler's. While
    /// empty (or unparseable), [`vendored_sigstore_verifier`] returns `None`, no
    /// verifier is available, and a present signature falls to the fail-closed
    /// `UnavailableVerifier` — a signature is refused rather than trusted against
    /// no root.
    const VENDORED_TRUSTED_ROOT: &[u8] = include_bytes!("signing/trusted_root.json");

    /// Whether `range` includes the current time. Mirrors sigstore's own
    /// `is_timerange_valid`: an absent start is always-valid-from; with
    /// `allow_expired` an absent-or-past end still passes (a cert may have been
    /// valid when it signed). Epoch seconds via [`std::time::SystemTime`] — no
    /// `chrono` dependency is pulled in for this one comparison.
    fn timerange_valid(range: Option<&TimeRange>, allow_expired: bool) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0_i64, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
        let start = range.and_then(|r| r.start.as_ref()).map(|t| t.seconds);
        let end = range.and_then(|r| r.end.as_ref()).map(|t| t.seconds);
        match (start, end) {
            (None, _) => true,
            (Some(start), _) if now < start => false,
            _ if allow_expired => true,
            (_, None) => true,
            (_, Some(end)) => now <= end,
        }
    }

    /// The DER-encoded Fulcio CA certificates from a parsed [`TrustedRoot`].
    /// Expired chains are allowed (a cert may have signed while valid); mirrors
    /// sigstore's `SigstoreTrustRoot::fulcio_certs`.
    fn fulcio_certs(root: &TrustedRoot) -> Vec<pki_types::CertificateDer<'static>> {
        root.certificate_authorities
            .iter()
            .filter(|ca: &&CertificateAuthority| timerange_valid(ca.valid_for.as_ref(), true))
            .filter_map(|ca| ca.cert_chain.as_ref())
            .flat_map(|chain| chain.certificates.iter())
            .map(|cert| pki_types::CertificateDer::from(cert.raw_bytes.clone()))
            .collect()
    }

    /// The `(log-id-hex -> DER public key)` map for a set of transparency logs
    /// whose keys are currently valid; mirrors sigstore's `tlog_keys`.
    fn tlog_keys(tlogs: &[TransparencyLogInstance]) -> std::collections::BTreeMap<String, Vec<u8>> {
        tlogs
            .iter()
            .filter(|tlog| {
                tlog.public_key
                    .as_ref()
                    .is_some_and(|pk| timerange_valid(pk.valid_for.as_ref(), false))
            })
            .filter_map(|tlog| {
                let key_id = tlog
                    .log_id
                    .as_ref()
                    .map(|log_id| hex::encode(log_id.key_id.as_slice()))?;
                let key = tlog
                    .public_key
                    .as_ref()
                    .and_then(|pk| pk.raw_bytes.as_ref())?;
                Some((key_id, key.clone()))
            })
            .collect()
    }

    /// Parse the vendored `trusted_root.json` bytes into an owned
    /// [`ManualTrustRoot`], or `None` when the bytes are empty or do not parse
    /// into a `TrustedRoot`, or carry no Fulcio certs — fail closed.
    fn manual_root_from_vendored(data: &[u8]) -> Option<ManualTrustRoot<'static>> {
        if data.is_empty() {
            return None;
        }
        let root: TrustedRoot = serde_json::from_slice(data).ok()?;
        let fulcio = fulcio_certs(&root);
        if fulcio.is_empty() {
            return None;
        }
        Some(ManualTrustRoot {
            fulcio_certs: fulcio,
            rekor_keys: tlog_keys(&root.tlogs),
            ctfe_keys: tlog_keys(&root.ctlogs),
        })
    }

    /// Build the offline [`SigstoreVerifier`] from the vendored trust root, or
    /// `None` when no trust material is vendored (or it does not parse).
    ///
    /// Fail-closed by construction: `None` here routes the resolver to the
    /// fail-closed `UnavailableVerifier`, so a present signature is refused
    /// rather than trusted against an absent root. A real vendored root activates
    /// verification with no other change.
    #[must_use]
    pub fn vendored_sigstore_verifier() -> Option<SigstoreVerifier> {
        let trust_root = manual_root_from_vendored(VENDORED_TRUSTED_ROOT)?;
        Some(SigstoreVerifier { trust_root })
    }

    #[cfg(test)]
    mod feature_tests {
        use std::collections::BTreeMap;

        use sigstore::trust::ManualTrustRoot;

        use super::super::{Identity, SignatureError};
        use super::{
            SignatureBundle, SignatureVerifier as _, SigstoreVerifier, TrustPolicy,
            manual_root_from_vendored, vendored_sigstore_verifier,
        };

        /// A verifier over an arbitrary trust root, for wiring tests that must
        /// reach `verify_digest` without a real vendored root.
        fn verifier_over(root: ManualTrustRoot<'static>) -> SigstoreVerifier {
            SigstoreVerifier { trust_root: root }
        }

        /// The digest of an empty source tree.
        fn empty_tree() -> crate::cache::TreeDigest {
            let dir = crate::scratch::ScratchDir::new("ipe-sig-tree").expect("scratch dir");
            crate::cache::TreeDigest::of_tree_within(
                dir.path(),
                crate::remote_ingest::PACKAGE_SOURCE.tree(),
            )
            .expect("an empty tree hashes")
        }

        fn empty_root() -> ManualTrustRoot<'static> {
            ManualTrustRoot {
                fulcio_certs: Vec::new(),
                rekor_keys: BTreeMap::new(),
                ctfe_keys: BTreeMap::new(),
            }
        }

        fn a_trusted_identity() -> Identity {
            Identity::parse(
                "https://token.actions.githubusercontent.com",
                "https://github.com/o/r/.github/workflows/publish.yml@refs/heads/main",
            )
            .expect("valid identity")
        }

        /// The EMPTY placeholder `trusted_root.json` fails closed: no
        /// `ManualTrustRoot` is built, so no verifier is available and a present
        /// signature falls to the fail-closed path.
        #[test]
        fn empty_vendored_root_fails_closed() {
            assert!(
                manual_root_from_vendored(b"").is_none(),
                "empty bytes must not yield a trust root"
            );
            assert!(
                manual_root_from_vendored(b"not json").is_none(),
                "unparseable bytes must not yield a trust root"
            );
            assert!(
                vendored_sigstore_verifier().is_none(),
                "the vendored placeholder is empty, so no verifier is available"
            );
        }

        /// With NO trusted identity configured, the concrete verifier refuses
        /// before any crypto runs — deny by default, proven on the real
        /// `SigstoreVerifier`, not the mock.
        #[test]
        fn empty_policy_denies_before_crypto() {
            let verifier = verifier_over(empty_root());
            let bundle = SignatureBundle::parse("p", r#"{"dsseEnvelope":{}}"#).expect("bundle");
            let err = verifier
                .verify(&bundle, "00", &empty_tree(), &TrustPolicy::default())
                .expect_err("empty allowlist must reject");
            assert!(
                matches!(err, SignatureError::UntrustedIdentity { .. }),
                "{err}"
            );
        }

        /// A present signature with a configured identity but an EMPTY trust root
        /// reaches the crypto path (`verify_digest`) and is rejected there — the
        /// fork is closed (no blanket "cannot bridge" stub), and with no CA the
        /// bundle cannot verify, so it fails closed. This proves the wiring
        /// reaches real verification; a valid keyless bundle cannot be minted
        /// in-test (it needs OIDC/Fulcio + a Rekor entry), so the ACCEPT case is
        /// proven by the always-compiled decision-core tests against the mock.
        #[test]
        fn configured_identity_reaches_verify_digest_and_fails_closed() {
            let verifier = verifier_over(empty_root());
            // A syntactically-valid but crypto-empty DSSE bundle: enough to parse,
            // never enough to verify against an empty CA set.
            let bundle = SignatureBundle::parse(
                "p",
                r#"{ "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.3",
                     "verificationMaterial": {}, "dsseEnvelope": {} }"#,
            )
            .expect("bundle");
            let policy = TrustPolicy::new(vec![a_trusted_identity()], false);
            let err = verifier
                .verify(&bundle, "00", &empty_tree(), &policy)
                .expect_err("no CA + empty root must reject at the crypto path");
            // Not the old blanket "cannot bridge" refusal: the message reflects a
            // real verification attempt over the pinned digest.
            let msg = format!("{err}");
            assert!(
                !msg.contains("cannot bridge"),
                "the fork must be closed: {msg}"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 64-char lowercase-hex digest fixture (a real sha256 shape).
    const DIGEST: &str = "abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabcab";

    /// A minimal well-formed JSON-object bundle. The typed [`SignatureBundle`]
    /// only requires a JSON object at the parse boundary; cryptographic content
    /// is the verifier's concern (mocked in these tests).
    fn valid_bundle_json() -> &'static str {
        r#"{ "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.3",
             "verificationMaterial": {}, "dsseEnvelope": {} }"#
    }

    /// A mock verifier scripted to accept or reject, so the decision core's
    /// asymmetry is exercised without the crypto crate.
    struct MockVerifier {
        result: Result<VerifiedIdentity, SignatureError>,
    }

    impl MockVerifier {
        fn accepting() -> Self {
            Self {
                result: Ok(VerifiedIdentity {
                    issuer: GITHUB_ACTIONS_ISSUER.to_owned(),
                    san: "https://github.com/o/r/.github/workflows/publish.yml@refs/heads/main"
                        .to_owned(),
                }),
            }
        }
        fn rejecting(err: SignatureError) -> Self {
            Self { result: Err(err) }
        }
    }

    impl SignatureVerifier for MockVerifier {
        fn verify(
            &self,
            _bundle: &SignatureBundle,
            _subject_digest: &str,
            _tree: &crate::cache::TreeDigest,
            _policy: &TrustPolicy,
        ) -> Result<VerifiedIdentity, SignatureError> {
            self.result.clone()
        }
    }

    /// The digest of an empty source tree.
    fn empty_tree() -> crate::cache::TreeDigest {
        let dir = crate::scratch::ScratchDir::new("ipe-sig-tree").expect("scratch dir");
        crate::cache::TreeDigest::of_tree_within(
            dir.path(),
            crate::remote_ingest::PACKAGE_SOURCE.tree(),
        )
        .expect("an empty tree hashes")
    }

    fn trusted_identity() -> Identity {
        Identity::parse(
            GITHUB_ACTIONS_ISSUER,
            "https://github.com/o/r/.github/workflows/publish.yml@refs/heads/main",
        )
        .expect("valid identity")
    }

    // ── Identity parse boundary ─────────────────────────────────────────────

    #[test]
    fn identity_parse_accepts_url_shaped_pair() {
        let id = trusted_identity();
        assert_eq!(id.issuer(), GITHUB_ACTIONS_ISSUER);
        assert!(id.san().contains("publish.yml"));
    }

    #[test]
    fn identity_parse_rejects_empty_and_whitespace() {
        assert!(
            Identity::parse("", "san").is_err(),
            "empty issuer must fail"
        );
        assert!(Identity::parse("iss", "").is_err(), "empty san must fail");
        assert!(
            Identity::parse("iss with space", "san").is_err(),
            "whitespace in issuer must fail"
        );
        assert!(
            Identity::parse("iss", "san\twith\ttab").is_err(),
            "control char in san must fail"
        );
    }

    // ── SignatureBundle parse boundary ──────────────────────────────────────

    #[test]
    fn bundle_parse_accepts_a_json_object() {
        let b = SignatureBundle::parse("p", valid_bundle_json()).expect("object parses");
        assert!(b.as_str().contains("dsseEnvelope"));
    }

    #[test]
    fn bundle_parse_rejects_empty() {
        let err = SignatureBundle::parse("p", "   ").unwrap_err();
        assert!(format!("{err}").contains("empty"), "{err}");
    }

    #[test]
    fn bundle_parse_rejects_non_json() {
        let err = SignatureBundle::parse("p", "this is not json ===").unwrap_err();
        assert!(format!("{err}").contains("malformed"), "{err}");
    }

    #[test]
    fn bundle_parse_rejects_a_non_object_json() {
        // A JSON array/string/number is valid JSON but not a bundle envelope.
        let err = SignatureBundle::parse("p", "[1, 2, 3]").unwrap_err();
        assert!(format!("{err}").contains("not a JSON object"), "{err}");
    }

    #[test]
    fn bundle_parse_rejects_a_partial_truncated_object() {
        // A truncated object is a malformed field, never silently "no signature".
        let err = SignatureBundle::parse("p", r#"{ "verificationMaterial": {"#).unwrap_err();
        assert!(format!("{err}").contains("malformed"), "{err}");
    }

    #[test]
    fn bundle_parse_rejects_oversized() {
        let huge = format!("{{\"x\":\"{}\"}}", "a".repeat(MAX_BUNDLE_BYTES + 1));
        let err = SignatureBundle::parse("p", &huge).unwrap_err();
        assert!(format!("{err}").contains("size ceiling"), "{err}");
    }

    // ── evaluate_signature: the deny-by-default asymmetry ───────────────────

    #[test]
    fn unsigned_with_require_false_resolves_with_warning() {
        let policy = TrustPolicy::new(vec![trusted_identity()], false);
        let verifier = MockVerifier::accepting();
        let outcome = evaluate_signature("p", &policy, None, DIGEST, &empty_tree(), &verifier)
            .expect("unsigned + !require resolves");
        assert_eq!(outcome, SignatureOutcome::UnsignedAllowed);
    }

    #[test]
    fn unsigned_with_require_true_is_rejected() {
        let policy = TrustPolicy::new(vec![trusted_identity()], true);
        let verifier = MockVerifier::accepting();
        let err = evaluate_signature("p", &policy, None, DIGEST, &empty_tree(), &verifier)
            .expect_err("unsigned + require must reject");
        assert!(format!("{err}").contains("requires one"), "{err}");
    }

    #[test]
    fn present_and_verified_against_trusted_identity_resolves() {
        let policy = TrustPolicy::new(vec![trusted_identity()], false);
        let verifier = MockVerifier::accepting();
        let bundle = SignatureBundle::parse("p", valid_bundle_json()).expect("bundle");
        let outcome = evaluate_signature(
            "p",
            &policy,
            Some(&bundle),
            DIGEST,
            &empty_tree(),
            &verifier,
        )
        .expect("verified signature resolves");
        assert!(matches!(outcome, SignatureOutcome::Verified(_)));
    }

    #[test]
    fn present_but_untrusted_identity_is_rejected_even_when_require_is_false() {
        // The load-bearing asymmetry: a present signature that fails to match a
        // trusted identity is rejected REGARDLESS of require_signature.
        let policy = TrustPolicy::new(vec![trusted_identity()], false);
        let verifier = MockVerifier::rejecting(SignatureError::UntrustedIdentity {
            issuer: "https://evil.example".to_owned(),
            san: "https://github.com/attacker/repo/...".to_owned(),
        });
        let bundle = SignatureBundle::parse("p", valid_bundle_json()).expect("bundle");
        let err = evaluate_signature(
            "p",
            &policy,
            Some(&bundle),
            DIGEST,
            &empty_tree(),
            &verifier,
        )
        .expect_err("present-but-untrusted must reject");
        let msg = format!("{err}");
        assert!(msg.contains("not trusted"), "{msg}");
        assert!(msg.contains("allowlist"), "{msg}");
    }

    #[test]
    fn present_with_digest_mismatch_is_rejected() {
        // A signature over other bytes than the pinned sha256 is rejected: the
        // provenance must cover exactly the source the resolver hash-verifies.
        let policy = TrustPolicy::new(vec![trusted_identity()], false);
        let verifier = MockVerifier::rejecting(SignatureError::DigestMismatch {
            expected: DIGEST.to_owned(),
            signed: "0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
        });
        let bundle = SignatureBundle::parse("p", valid_bundle_json()).expect("bundle");
        let err = evaluate_signature(
            "p",
            &policy,
            Some(&bundle),
            DIGEST,
            &empty_tree(),
            &verifier,
        )
        .expect_err("digest mismatch must reject");
        assert!(format!("{err}").contains("does not cover"), "{err}");
    }

    #[test]
    fn present_with_empty_trusted_set_is_rejected_deny_by_default() {
        // Deny by default: with no trusted identity configured, a real verifier
        // matches nothing. Model that here with a rejecting verifier and an empty
        // policy — the version is refused.
        let policy = TrustPolicy::default();
        assert!(policy.trusted_identities().is_empty());
        assert!(!policy.require_signature());
        let verifier = MockVerifier::rejecting(SignatureError::UntrustedIdentity {
            issuer: "<none configured>".to_owned(),
            san: "<none configured>".to_owned(),
        });
        let bundle = SignatureBundle::parse("p", valid_bundle_json()).expect("bundle");
        let err = evaluate_signature(
            "p",
            &policy,
            Some(&bundle),
            DIGEST,
            &empty_tree(),
            &verifier,
        )
        .expect_err("signed version with empty allowlist must reject");
        assert!(format!("{err}").contains("not trusted"), "{err}");
    }

    #[test]
    fn invalid_bundle_crypto_is_rejected() {
        let policy = TrustPolicy::new(vec![trusted_identity()], false);
        let verifier = MockVerifier::rejecting(SignatureError::BundleInvalid {
            detail: "bad Rekor inclusion proof".to_owned(),
        });
        let bundle = SignatureBundle::parse("p", valid_bundle_json()).expect("bundle");
        let err = evaluate_signature(
            "p",
            &policy,
            Some(&bundle),
            DIGEST,
            &empty_tree(),
            &verifier,
        )
        .expect_err("invalid bundle must reject");
        assert!(format!("{err}").contains("did not verify"), "{err}");
    }

    #[test]
    fn verifier_unavailable_is_rejected_fail_closed() {
        // A present signature in a build without the crypto verifier fails closed:
        // an unverifiable signature is worse than none.
        let policy = TrustPolicy::new(vec![trusted_identity()], false);
        let verifier = MockVerifier::rejecting(SignatureError::VerifierUnavailable);
        let bundle = SignatureBundle::parse("p", valid_bundle_json()).expect("bundle");
        let err = evaluate_signature(
            "p",
            &policy,
            Some(&bundle),
            DIGEST,
            &empty_tree(),
            &verifier,
        )
        .expect_err("no verifier + present signature must reject");
        assert!(format!("{err}").contains("cannot verify"), "{err}");
    }

    // ── DSSE statement generation ───────────────────────────────────────────

    #[test]
    fn dsse_statement_binds_name_version_and_sha256() {
        let stmt = dsse_statement("http-extras", "1.2.0", DIGEST);
        assert!(stmt.contains("http-extras@1.2.0"), "{stmt}");
        assert!(stmt.contains(DIGEST), "{stmt}");
        assert!(stmt.contains("in-toto.io/Statement"), "{stmt}");
        // Parse it back to prove it is well-formed JSON with the subject digest.
        let value: serde_json::Value = serde_json::from_str(&stmt).expect("valid JSON");
        let signed_digest = value
            .pointer("/subject/0/digest/sha256")
            .and_then(serde_json::Value::as_str);
        assert_eq!(signed_digest, Some(DIGEST));
    }

    // ── Trust-policy config parsing ─────────────────────────────────────────

    #[test]
    fn trust_config_absent_table_is_deny_by_default() {
        let policy = parse_trust_policy_toml("name = \"app\"\n").expect("parses");
        assert!(policy.trusted_identities().is_empty());
        assert!(!policy.require_signature());
    }

    #[test]
    fn trust_config_reads_identities_and_require_flag() {
        let text = r#"
[registry.trust]
require_signature = true
trusted_identities = [
  { issuer = "https://token.actions.githubusercontent.com", identity = "https://github.com/o/r/.github/workflows/publish.yml@refs/heads/main" },
]
"#;
        let policy = parse_trust_policy_toml(text).expect("parses");
        assert!(policy.require_signature());
        assert_eq!(policy.trusted_identities().len(), 1);
        let id = policy.trusted_identities().first().expect("one identity");
        assert_eq!(id.issuer(), GITHUB_ACTIONS_ISSUER);
        assert!(id.san().contains("publish.yml"));
    }

    #[test]
    fn trust_config_rejects_malformed_toml() {
        let err = parse_trust_policy_toml("this is not toml ===").unwrap_err();
        assert!(format!("{err}").contains("malformed"), "{err}");
    }

    #[test]
    fn trust_config_rejects_identity_missing_issuer() {
        let text = r#"
[registry.trust]
trusted_identities = [ { identity = "https://github.com/o/r/wf@refs/heads/main" } ]
"#;
        let err = parse_trust_policy_toml(text).unwrap_err();
        assert!(format!("{err}").contains("issuer"), "{err}");
    }

    #[test]
    fn trust_config_rejects_non_array_identities() {
        let text = "[registry.trust]\ntrusted_identities = \"nope\"\n";
        let err = parse_trust_policy_toml(text).unwrap_err();
        assert!(format!("{err}").contains("array"), "{err}");
    }

    #[test]
    fn trust_config_rejects_non_bool_require() {
        let text = "[registry.trust]\nrequire_signature = \"yes\"\n";
        let err = parse_trust_policy_toml(text).unwrap_err();
        assert!(format!("{err}").contains("boolean"), "{err}");
    }

    #[test]
    fn dsse_statement_is_deterministic() {
        let a = dsse_statement("p", "1.0.0", DIGEST);
        let b = dsse_statement("p", "1.0.0", DIGEST);
        assert_eq!(a, b, "the statement for a version must be stable");
    }
}
