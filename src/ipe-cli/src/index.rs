//! The package index entry schema and reader.
//!
//! The index is a git repository holding one entry file per package at
//! `packages/<name>.toml`. An entry lists every published version, and for each
//! the source repository, its pinned revision, the sha256 of the source tree at
//! that revision, and the capability set the publisher declared. Resolution
//! ([`resolve_version`]) picks the highest published version satisfying a
//! [`semver::VersionReq`].
//!
//! Parse, don't validate: an entry file is read into a typed [`IndexEntry`] whose
//! versions are [`semver::Version`] and whose capabilities are [`Capability`], so
//! a malformed version or an unknown capability name is a hard error at read
//! time, never a resolution-time surprise.
//!
//! [`SourceUrl`] and [`CommitId`] are typed newtypes that gate the two
//! publisher-controlled fields. An unvalidated string can never reach the `git`
//! subprocess — it must first pass through one of these constructors.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::str::FromStr as _;

use ipe_ir::Capability;

use crate::CliError;
use crate::package_name::PackageName;
use crate::publisher::{AttestedActor, BlessedPublisher, SelfDeclaredPublisher};
use crate::signing::SignatureBundle;

/// A validated source-repository URL accepted by the package index.
///
/// The accept set covers the network transports (`https://`, `git://`, `ssh://`,
/// `file://`) and bare absolute paths (a leading `/`). Any value that begins
/// with `-` (option injection) or contains `::` (git transport helpers such as
/// `ext::` or `fd::`, the real RCE vector) is rejected at parse time so a
/// malicious index entry can never reach the `git` subprocess.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceUrl(String);

impl SourceUrl {
    /// Parse a raw string from the index into a [`SourceUrl`], rejecting
    /// injection-shaped values.
    ///
    /// Accepted: `https://`, `git://`, `ssh://`, `file://`, and bare absolute
    /// paths (starting with `/`). Rejected: a leading `-` (git flag injection)
    /// or `::` anywhere (transport-helper execution, the RCE vector).
    ///
    /// # Errors
    /// [`CliError::Resolve`] when the value is not an accepted source form.
    pub fn parse(pkg: &str, raw: &str) -> Result<Self, CliError> {
        let allowed = raw.starts_with("https://")
            || raw.starts_with("git://")
            || raw.starts_with("ssh://")
            || raw.starts_with("file://")
            || raw.starts_with('/');
        // Fail closed: absent proof the transport is safe, reject.
        // `-`-leading values would be parsed as git flags; `::` introduces
        // transport helpers (e.g. `ext::`) that execute arbitrary commands.
        if !allowed || raw.starts_with('-') || raw.contains("::") {
            return Err(CliError::Resolve(format!(
                "package `{pkg}`: `source` must be an https://, git://, ssh://, or file:// URL \
                 (or a bare absolute path), got: {raw:?}"
            )));
        }
        Ok(Self(raw.to_owned()))
    }

    /// The validated URL string, safe to pass to `git clone -- <url> <dest>`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for SourceUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// An injection-safe requested ref: what the author typed in their manifest.
///
/// Accepts full commit hashes, abbreviated hashes, ref names, and `HEAD` —
/// anything git itself accepts — as long as the value is not injection-shaped.
/// Rejected: a leading `-` (git flag injection), `::` anywhere (transport
/// helper), whitespace or control characters, git refspec metacharacters
/// (`..`, `~`, `^`, `:`, `?`, `*`, `[`, `\`, `@{`), and a trailing `/` or
/// `.lock` (path-confusion vectors).
///
/// A `CommitId` is the REQUEST spelling — what to check out. It is deliberately
/// distinct from [`PinnedRev`], which holds only the resolved immutable SHA
/// recorded in the lockfile or index entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitId(String);

impl CommitId {
    /// Parse a raw string into a [`CommitId`], rejecting injection-shaped values.
    ///
    /// Accepts any non-injection ref name, including full/abbreviated hashes,
    /// branch names, and `HEAD`. Rejected: a leading `-`, `::`, whitespace,
    /// control chars, git refspec metacharacters (`..`, `~`, `^`, `:`, `?`,
    /// `*`, `[`, `\`, `@{`), trailing `/`, and `.lock` suffix.
    ///
    /// # Errors
    /// [`CliError::Resolve`] when the value is injection-shaped.
    pub fn parse(pkg: &str, raw: &str) -> Result<Self, CliError> {
        let injection = raw.is_empty()
            || raw.starts_with('-')
            || raw.contains("::")
            || raw
                .chars()
                .any(|c| c.is_ascii_whitespace() || c.is_ascii_control())
            || raw.contains("..")
            || raw.contains('~')
            || raw.contains('^')
            || raw.contains(':')
            || raw.contains('?')
            || raw.contains('*')
            || raw.contains('[')
            || raw.contains('\\')
            || raw.contains("@{")
            || raw.ends_with('/')
            || std::path::Path::new(raw)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("lock"));
        if injection {
            return Err(CliError::Resolve(format!(
                "package `{pkg}`: `rev` contains an injection-shaped value, got: {raw:?}"
            )));
        }
        Ok(Self(raw.to_owned()))
    }

    /// The validated commit-id string, safe to pass to `git checkout <rev>`.
    ///
    /// The `CommitId` parse boundary guarantees this value cannot start with
    /// `-`, so passing it without `--` is safe — `--` in `git checkout` means
    /// "treat as a path, not a ref", which is wrong for a commit id.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for CommitId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// An immutable, resolved commit SHA pinned in a lockfile or index entry.
///
/// The only inhabitants are 40-char lowercase-hex strings produced by resolving
/// a ref against a real git object. A moving ref (`HEAD`, `main`, a tag) cannot
/// inhabit this type — it must first be resolved to a concrete SHA via
/// [`PinnedRev::resolve_in_checkout`] (write path) or re-parsed from a stored
/// value via [`PinnedRev::from_full_sha`] (read path).
///
/// This is the recorded-pin type. [`CommitId`] is the distinct request type
/// (what the author typed; may be a branch).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinnedRev(String);

impl PinnedRev {
    /// Parse a stored rev from a lockfile or index entry, accepting only a
    /// 40-char lowercase-hex SHA.
    ///
    /// A stored non-SHA value (e.g. a legacy `"HEAD"` or `"main"`) is a hard
    /// error — fail closed rather than re-fetching a moving tip. Re-run
    /// `ipe add` to record an immutable SHA for the dependency.
    ///
    /// # Errors
    /// [`CliError::Resolve`] when `raw` is not a 40-char lowercase-hex string.
    pub fn from_full_sha(pkg: &str, raw: &str) -> Result<Self, CliError> {
        // Require exactly 40 lowercase hex chars — no uppercase, no short hashes.
        let is_sha = raw.len() == 40 && raw.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'));
        if !is_sha {
            return Err(CliError::Resolve(format!(
                "package `{pkg}`: recorded `rev` is not an immutable commit SHA \
                 (expected 40 lowercase hex chars), got: {raw:?} — re-run `ipe add` \
                 to record an immutable pin"
            )));
        }
        Ok(Self(raw.to_owned()))
    }

    /// Resolve a requested ref to a concrete commit SHA by running
    /// `git rev-parse --verify --quiet <ref>^{{commit}}` inside `checkout`.
    ///
    /// This is the single WRITE-path site that collapses any ref — including the
    /// default `HEAD` — to a concrete, immutable SHA before it is recorded.
    ///
    /// # Errors
    /// [`CliError::Resolve`] when git cannot be run, when the ref does not
    /// resolve to a commit, or when the output is not a 40-hex SHA.
    pub fn resolve_in_checkout(
        pkg: &str,
        checkout: &std::path::Path,
        requested: &CommitId,
    ) -> Result<Self, CliError> {
        let refspec = format!("{}^{{commit}}", requested.as_str());
        let output = std::process::Command::new("git")
            .args(["rev-parse", "--verify", "--quiet", &refspec])
            .current_dir(checkout)
            .output()
            .map_err(|e| {
                CliError::Resolve(format!(
                    "package `{pkg}`: could not run `git rev-parse`: {e}"
                ))
            })?;
        if !output.status.success() {
            return Err(CliError::Resolve(format!(
                "package `{pkg}`: `git rev-parse --verify {refspec}` failed — \
                 ref {:?} does not resolve to a commit in the fetched checkout",
                requested.as_str()
            )));
        }
        let raw = String::from_utf8_lossy(&output.stdout);
        let sha = raw.trim();
        Self::from_full_sha(pkg, sha)
    }

    /// The pinned SHA string, suitable for use as a cache-dir key or for
    /// writing to the lockfile or index entry.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for PinnedRev {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A validated source-tree content hash: exactly 64 lowercase hex characters.
///
/// The only inhabitants are the digests `hex::encode(Sha256)` produces
/// ([`crate::cache::hash_tree`], the hash the resolver verifies a fetched tree
/// against). A short, uppercase, non-hex, or otherwise malformed value cannot
/// inhabit this type, so a garbage integrity anchor is refused at the entry-parse
/// boundary — the cheap structural gate (`ipe package validate-entry`) the index
/// CI runs first — rather than only surfacing as a fetch-time mismatch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sha256Hex(String);

impl Sha256Hex {
    /// Parse a stored `sha256` field, accepting only a 64-char lowercase-hex
    /// digest.
    ///
    /// # Errors
    /// [`CliError::Resolve`] when `raw` is not exactly 64 lowercase hex chars.
    pub fn parse(pkg: &str, raw: &str) -> Result<Self, CliError> {
        let is_digest = raw.len() == 64 && raw.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'));
        if !is_digest {
            return Err(CliError::Resolve(format!(
                "package `{pkg}`: `sha256` is not a 64-char lowercase-hex content hash, \
                 got: {raw:?}"
            )));
        }
        Ok(Self(raw.to_owned()))
    }

    /// The validated 64-hex digest string, compared against a freshly-computed
    /// tree hash at verify-before-trust time.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Sha256Hex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A parsed index entry: one package and every version published for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexEntry {
    /// The package name, matching the entry file stem (`packages/<name>.toml`).
    pub name: String,
    /// The publisher the entry claims — self-declared and untrusted; provenance
    /// only. A privilege rests on a [`crate::publisher::BlessedPublisher`], never
    /// on this field.
    pub publisher: SelfDeclaredPublisher,
    /// Every published version, in file order. [`resolve_version`] scans these
    /// for the highest match rather than relying on file order.
    pub versions: Vec<EntryVersion>,
}

/// One published version of a package: where its source lives, exactly which
/// revision, the content hash to verify the fetched tree against, and the
/// capabilities the publisher declared.
///
/// `source` is a [`SourceUrl`] and `rev` is a [`PinnedRev`] — typed newtypes
/// that prevent an unvalidated or moving ref from reaching the `git` subprocess
/// or being written to the lockfile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryVersion {
    /// The exact published version.
    pub version: semver::Version,
    /// The source repository URL, validated at parse time.
    pub source: SourceUrl,
    /// The immutable commit SHA pinned at publish time.
    pub rev: PinnedRev,
    /// The sha256 of the source tree at `rev`. A fetched tree is trusted only
    /// when its hash equals this (verify-before-trust, in `crate::resolve`).
    pub sha256: String,
    /// The capability set the publisher declared for this version, surfaced for
    /// consent at `ipe add`.
    pub capabilities: BTreeSet<Capability>,
    /// The publisher's Sigstore signature bundle over this version's `sha256`,
    /// when one was published. Optional and backward-compatible: an absent
    /// `signature` is an unsigned version (resolved with a warning unless the
    /// trust policy requires a signature). A PRESENT-but-malformed bundle is a
    /// hard parse error, never a silently-dropped field — a malformed signature
    /// must not masquerade as "unsigned".
    pub signature: Option<crate::signing::SignatureBundle>,
}

/// The path of a package's entry file inside an index checkout.
///
/// Takes a validated [`PackageName`] so the name is a single, non-traversing
/// path component by construction — an unvalidated string cannot reach this
/// join and reroot it outside the index root.
fn entry_path(index_root: &Path, name: &PackageName) -> PathBuf {
    index_root
        .join("packages")
        .join(format!("{}.toml", name.as_str()))
}

/// Whether the package named `name` has an entry file in the index checkout at
/// `index_root`.
///
/// Publish uses this to distinguish a first publish (no file — create it) from a
/// present-but-unreadable entry (a real error to surface), rather than treating
/// every read failure as "absent".
///
/// # Errors
/// [`CliError::Resolve`] when `name` is not a valid package name (it would
/// otherwise be joined into a filesystem path).
pub fn entry_file_exists(index_root: &Path, name: &str) -> Result<bool, CliError> {
    let name = PackageName::parse(name)?;
    Ok(entry_path(index_root, &name).is_file())
}

/// The three-way outcome of looking up a package entry in the index.
///
/// This split prevents callers from collapsing "genuinely absent" and
/// "present-but-unreadable" into the same value — the fused form that lets
/// security gates fail open. Use [`EntryLookup::require_present`] for
/// integrity gates (Unreadable → propagate error → refuse) and
/// [`EntryLookup::absent_or_err`] where the first-version skip must survive a
/// true absence but still refuse on corruption.
#[must_use]
pub enum EntryLookup {
    /// The entry file does not exist — the package has never been published.
    Absent,
    /// The entry file exists and parsed successfully.
    Present(IndexEntry),
    /// The entry file exists but could not be read or parsed.
    Unreadable(CliError),
}

impl EntryLookup {
    /// Fail-closed accessor for integrity gates.
    ///
    /// `Absent` → `Ok(None)` (no published baseline; a new submission is
    /// allowed through). `Present` → `Ok(Some(entry))`. `Unreadable` → `Err`
    /// (propagate the error; the gate refuses rather than treating corruption
    /// as "no baseline").
    ///
    /// # Errors
    /// The [`CliError`] carried by the `Unreadable` variant.
    pub fn require_present(self) -> Result<Option<IndexEntry>, CliError> {
        match self {
            Self::Absent => Ok(None),
            Self::Present(e) => Ok(Some(e)),
            Self::Unreadable(err) => Err(err),
        }
    }

    /// Fail-closed accessor for the semver-bump gate.
    ///
    /// Semantically identical to [`require_present`](Self::require_present):
    /// `Absent` → `Ok(None)` (first version; skip preserved), `Present` →
    /// `Ok(Some(entry))`, `Unreadable` → `Err` (refuse; a corrupt predecessor
    /// cannot be treated as "no predecessor").
    ///
    /// # Errors
    /// The [`CliError`] carried by the `Unreadable` variant.
    pub fn absent_or_err(self) -> Result<Option<IndexEntry>, CliError> {
        self.require_present()
    }
}

/// Read and parse the index entry for `name` as a [`EntryLookup`].
///
/// Returns the three-way outcome (Absent / Present / Unreadable) that
/// distinguishes genuinely absent from present-but-unreadable. Use this in
/// every integrity gate so an unreadable baseline propagates as an error (fail
/// closed) rather than collapsing to "absent → skip".
pub fn read_entry_lookup(index_root: &Path, name: &str) -> EntryLookup {
    let name = match PackageName::parse(name) {
        Ok(name) => name,
        Err(err) => return EntryLookup::Unreadable(err),
    };
    let path = entry_path(index_root, &name);
    let text = match crate::io_bounded::read_to_string_capped(
        &path,
        crate::io_bounded::SMALL_FILE_READ_CAP,
    ) {
        Ok(t) => t,
        Err(crate::CliError::Io { ref source, .. })
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            return EntryLookup::Absent;
        }
        Err(e) => {
            return EntryLookup::Unreadable(crate::CliError::Resolve(format!(
                "index entry for `{name}` exists but could not be read — {e}"
            )));
        }
    };
    match parse_entry(name.as_str(), &text) {
        Ok(entry) => EntryLookup::Present(entry),
        Err(err) => EntryLookup::Unreadable(err),
    }
}

/// Read and parse the index entry for `name` from an index checkout rooted at
/// `index_root` (which holds `packages/<name>.toml`).
///
/// For non-security callers that treat both absence and corruption as errors
/// (e.g. the resolver, publish). Security/integrity gates must use
/// [`read_entry_lookup`] instead so they cannot accidentally collapse
/// "unreadable" to "absent → skip".
///
/// # Errors
/// [`CliError::Resolve`] when the entry file is absent or malformed.
pub fn read_entry(index_root: &Path, name: &str) -> Result<IndexEntry, CliError> {
    let package_name = PackageName::parse(name)?;
    let path = entry_path(index_root, &package_name);
    let text =
        crate::io_bounded::read_to_string_capped(&path, crate::io_bounded::SMALL_FILE_READ_CAP)
            .map_err(|e| match e {
                crate::CliError::Io { ref source, .. } => read_entry_error(name, source),
                other => other,
            })?;
    parse_entry(name, &text)
}

/// The typed diagnostic when an index entry cannot be read. A missing entry is
/// the ordinary "unknown package" case: the message names the package and points
/// the user at the index, WITHOUT leaking the internal cache path or the errno
/// tail. Any other read failure (a permission or corruption problem the user can
/// act on) keeps a readable kind description, still errno-free.
fn read_entry_error(name: &str, e: &std::io::Error) -> CliError {
    if e.kind() == std::io::ErrorKind::NotFound {
        CliError::Resolve(format!(
            "add: package `{name}` is not in the index — check the name, or run \
             `ipe rust add` for a Rust crate"
        ))
    } else {
        CliError::Resolve(format!(
            "add: could not read the index entry for `{name}` — {}",
            e.kind()
        ))
    }
}

/// Validate a single `packages/<name>.toml` entry file by its own path, the way
/// the index repository's admission CI checks a submitted entry.
///
/// The package name is the file stem (the schema's authoritative name), so the
/// file `packages/http-extras.toml` is validated as package `http-extras`. This
/// is the same parse [`read_entry`] runs, reused so the validator and the reader
/// can never disagree about what a well-formed entry is: a version that parses
/// here is a version the resolver will later accept.
///
/// Fail-closed: any parse failure (a bad version, a missing per-version field,
/// an unknown capability, an absent `publisher`, or zero `[[version]]` blocks)
/// is a hard error, never a warning. Structure only — the source pin and the
/// package gate are the admission CI's fetch and `ipe package audit` steps, not
/// this offline check.
///
/// # Errors
/// [`CliError::UsageOwned`] when `path` has no `.toml` file-stem to name the
/// package; [`CliError::Io`] when the file cannot be read; [`CliError::Resolve`]
/// when the entry is malformed.
pub fn validate_entry_file(path: &Path) -> Result<IndexEntry, CliError> {
    let name = path
        .file_stem()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            CliError::UsageOwned(format!(
                "{} is not a `packages/<name>.toml` entry file — the file stem names the package",
                path.display()
            ))
        })?;
    let text =
        crate::io_bounded::read_to_string_capped(path, crate::io_bounded::SMALL_FILE_READ_CAP)?;
    parse_entry(name, &text)
}

/// The per-entry version ceiling enforced at admission.
///
/// A real package accrues versions across many reviewed PRs; one submission
/// listing more than this is a resource / review-flooding vector, refused
/// fail-closed.
pub const MAX_ENTRY_VERSIONS: usize = 1024;

/// The structural admission checks that need no fetch.
///
/// Covers the version-count ceiling, per-version immutability against the
/// baseline, and source continuity (anti-squat). A pure function of the
/// submitted entry and the previously published `baseline` (if any), so the
/// whole deny/accept surface is testable without a network, a git fetch, or a
/// build.
///
/// Fail-closed and deny-by-default:
/// - **Version ceiling** — more than [`MAX_ENTRY_VERSIONS`] versions is refused.
/// - **Immutability** — a submitted version whose NUMBER already exists in the
///   baseline must be byte-for-byte identical; rewriting its
///   source/rev/sha256/capabilities is a supply-chain mutation and is refused.
/// - **Append-only** — a version NUMBER published in the baseline must not be
///   dropped from the submission; the index never removes a published version.
///   The one carve-out (drop-only) is the disposable reserved smoke namespace
///   owned by the blessed first-party publisher, which may reset to a single
///   version — granted only when `attested` (the admission workflow's
///   authenticated PR author) proves the claimed publisher is blessed, never on
///   the entry's self-declared `publisher` alone.
/// - **Source continuity** — a package name is bound to one source repository.
///   The established source is the baseline's first published version's source
///   (on first publish, the submitted entry's own first version fixes it); a
///   version pointing elsewhere is a name-squat and is refused.
///
/// # Errors
/// [`CliError::UsageOwned`] naming the exact rule that refused the entry.
pub fn admission_precheck(
    submitted: &IndexEntry,
    baseline: Option<&IndexEntry>,
    attested: Option<&AttestedActor>,
) -> Result<(), CliError> {
    if submitted.versions.len() > MAX_ENTRY_VERSIONS {
        return Err(CliError::UsageOwned(format!(
            "ipe package audit-entry: `{}` lists {} versions, exceeding the {MAX_ENTRY_VERSIONS} \
             per-entry ceiling — a single submission cannot carry this many versions.",
            submitted.name,
            submitted.versions.len()
        )));
    }

    let baseline_by_version: std::collections::BTreeMap<&semver::Version, &EntryVersion> = baseline
        .map(|e| e.versions.iter().map(|v| (&v.version, v)).collect())
        .unwrap_or_default();

    // Immutability: an existing version NUMBER must match the published row exactly.
    for version in &submitted.versions {
        if let Some(&prior) = baseline_by_version.get(&version.version)
            && prior != version
        {
            return Err(CliError::UsageOwned(format!(
                "ipe package audit-entry: `{}` version {} is already published and immutable, \
                 but the submitted entry rewrites it (source, rev, sha256, or capabilities \
                 differ). A published version must never be rewritten — publish a new version.",
                submitted.name, version.version
            )));
        }
    }

    // Append-only: a version NUMBER published in the baseline must not be
    // dropped from the submission. A published version is immutable AND
    // permanent — silently removing one is a supply-chain regression (a
    // consumer's pinned resolution would vanish), so it is refused fail-closed.
    //
    // Carve-out (drop-only, both conditions required): the disposable reserved
    // smoke namespace may reset to a single version when the attested PR author
    // proves the claimed publisher is the blessed first-party identity. A reserved
    // name without that proof (no attestation, an attestation not matching the
    // claim, a non-blessed attestation), or a non-reserved name, still hits the
    // rejection — absent proof the drop is the sanctioned reset, the permissive
    // branch is unreachable. Rewriting a version stays forbidden everywhere
    // (enforced above); only dropping is carved out.
    let reserved_name = ipe_kernels::reserved_package_prefix_of(&submitted.name).is_some();
    let blessing = BlessedPublisher::from_attested(attested, &submitted.publisher);
    let reset_allowed = reserved_name
        && blessing
            .as_ref()
            .is_ok_and(|blessed| blessed.vouches_for(&submitted.publisher));
    if !reset_allowed {
        let reset_refusal = if reserved_name {
            blessing.as_ref().err().map_or_else(String::new, |refusal| {
                format!(" The reserved smoke-namespace reset is refused: {refusal}.")
            })
        } else {
            String::new()
        };
        let submitted_versions: std::collections::BTreeSet<&semver::Version> =
            submitted.versions.iter().map(|v| &v.version).collect();
        for baseline_version in baseline_by_version.keys() {
            if !submitted_versions.contains(*baseline_version) {
                return Err(CliError::UsageOwned(format!(
                    "ipe package audit-entry: `{}` drops the published version {baseline_version}, \
                     but the index is append-only: a published version must never be removed. \
                     Publish a new version instead.{reset_refusal}",
                    submitted.name
                )));
            }
        }
    }

    // Source continuity (anti-squat): every version's source must equal the
    // package's established source.
    let established_source: Option<&str> = baseline
        .and_then(|e| e.versions.first())
        .map(|v| v.source.as_str())
        .or_else(|| submitted.versions.first().map(|v| v.source.as_str()));
    if let Some(expected_source) = established_source {
        for version in &submitted.versions {
            if version.source.as_str() != expected_source {
                return Err(CliError::UsageOwned(format!(
                    "ipe package audit-entry: `{}` version {} declares source `{}`, but this \
                     package's established source is `{}`. A package name is bound to one source \
                     repository; a version pointing elsewhere is a name-squat and is refused.",
                    submitted.name,
                    version.version,
                    version.source.as_str(),
                    expected_source
                )));
            }
        }
    }

    Ok(())
}

/// Resolve the highest published version satisfying `req`.
///
/// # Errors
/// [`CliError::Resolve`] when no published version matches — the requirement is
/// unsatisfiable against this entry, named so the user sees what was available.
pub fn resolve_version<'a>(
    entry: &'a IndexEntry,
    req: &semver::VersionReq,
) -> Result<&'a EntryVersion, CliError> {
    entry
        .versions
        .iter()
        .filter(|v| req.matches(&v.version))
        .max_by(|a, b| a.version.cmp(&b.version))
        .ok_or_else(|| {
            let available: Vec<String> = entry
                .versions
                .iter()
                .map(|v| v.version.to_string())
                .collect();
            CliError::Resolve(format!(
                "package `{}`: no published version satisfies `{req}` (available: {})",
                entry.name,
                if available.is_empty() {
                    "none".to_owned()
                } else {
                    available.join(", ")
                }
            ))
        })
}

/// Parse an entry file's text into a typed [`IndexEntry`]. The format is a
/// top-level `name`/`publisher` followed by one `[[version]]` table per
/// published version. Comments (`#`) and blank lines are ignored; unrecognised
/// keys are ignored (forward-compatible), but a malformed known value is a hard
/// error.
fn parse_entry(name: &str, text: &str) -> Result<IndexEntry, CliError> {
    let mut publisher: Option<String> = None;
    let mut versions: Vec<RawVersion> = Vec::new();
    // `None` while reading the top-level table, `Some(idx)` while inside a
    // `[[version]]` table.
    let mut current: Option<usize> = None;

    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line == "[[version]]" {
            versions.push(RawVersion::default());
            current = Some(versions.len() - 1);
            continue;
        }
        if line.starts_with('[') {
            // Any other section closes the current `[[version]]` and is ignored.
            current = None;
            continue;
        }
        let Some((key, raw_val)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let raw_val = raw_val.trim();
        match current {
            None => {
                if key == "publisher" {
                    publisher = Some(unquote(raw_val).to_owned());
                }
                // A top-level `name` is informational; the authoritative name is
                // the file stem the caller asked for.
            }
            Some(idx) => {
                let Some(record) = versions.get_mut(idx) else {
                    continue;
                };
                match key {
                    "version" => record.version = Some(unquote(raw_val).to_owned()),
                    "source" => record.source = Some(unquote(raw_val).to_owned()),
                    "rev" => record.rev = Some(unquote(raw_val).to_owned()),
                    "sha256" => record.sha256 = Some(unquote(raw_val).to_owned()),
                    "capabilities" => record.capabilities = Some(raw_val.to_owned()),
                    "signature" => record.signature = Some(unquote(raw_val).to_owned()),
                    _ => {}
                }
            }
        }
    }

    let publisher = publisher.map(SelfDeclaredPublisher::new).ok_or_else(|| {
        CliError::Resolve(format!(
            "package `{name}`: index entry is missing `publisher`"
        ))
    })?;
    if versions.is_empty() {
        return Err(CliError::Resolve(format!(
            "package `{name}`: index entry lists no `[[version]]`"
        )));
    }
    let versions = versions
        .into_iter()
        .map(|raw| raw.into_version(name))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(IndexEntry {
        name: name.to_owned(),
        publisher,
        versions,
    })
}

/// Parse the registry's per-package JSON mirror (`/packages/<name>.json`) into
/// the SAME typed [`IndexEntry`] the TOML reader produces.
///
/// The Pages read API serves a JSON mirror of the authoritative `packages/<name>.toml`
/// so the resolver can discover an entry without cloning the index repo. This is
/// an optimisation ONLY: the trust root stays the per-version pinned `rev` +
/// `sha256`, still git-fetched and hash-verified downstream. Every publisher-
/// controlled field passes the same [`SourceUrl`] / [`PinnedRev`] / [`Capability`]
/// constructors as the TOML path, so a malformed or partial JSON response is a
/// hard error — never a partial entry trusted as complete. The caller treats any
/// error here as a signal to fall back to the git-checkout reader.
///
/// The expected shape:
///
/// ```json
/// { "name": "http-extras", "publisher": "tester",
///   "versions": [ { "version": "1.2.0", "source": "https://…",
///                   "rev": "<40-hex>", "sha256": "…",
///                   "capabilities": ["network"] } ] }
/// ```
///
/// # Errors
/// [`CliError::Resolve`] when the JSON is malformed, is missing `publisher` or
/// `versions`, lists zero versions, or any per-version field fails its typed
/// constructor (an unknown capability, a non-immutable `rev`, an injection-shaped
/// `source`).
pub fn parse_entry_json(name: &str, text: &str) -> Result<IndexEntry, CliError> {
    let malformed = |detail: &str| {
        CliError::Resolve(format!(
            "package `{name}`: registry JSON is malformed ({detail})"
        ))
    };

    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|e| malformed(&format!("not valid JSON: {e}")))?;
    let object = value
        .as_object()
        .ok_or_else(|| malformed("top level is not a JSON object"))?;

    let publisher = object
        .get("publisher")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| malformed("missing string field `publisher`"))
        .map(|claimed| SelfDeclaredPublisher::new(claimed.to_owned()))?;

    let raw_versions = object
        .get("versions")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| malformed("missing array field `versions`"))?;
    if raw_versions.is_empty() {
        return Err(malformed("`versions` is empty"));
    }

    let mut versions = Vec::with_capacity(raw_versions.len());
    for raw in raw_versions {
        versions.push(parse_entry_version_json(name, raw)?);
    }

    Ok(IndexEntry {
        name: name.to_owned(),
        publisher,
        versions,
    })
}

/// Parse one element of the JSON mirror's `versions` array into a typed
/// [`EntryVersion`], routing every publisher-controlled field through the same
/// constructors the TOML reader uses (parse, don't validate).
fn parse_entry_version_json(name: &str, raw: &serde_json::Value) -> Result<EntryVersion, CliError> {
    let malformed = |detail: String| {
        CliError::Resolve(format!(
            "package `{name}`: registry JSON is malformed ({detail})"
        ))
    };
    let object = raw
        .as_object()
        .ok_or_else(|| malformed("a `versions` element is not an object".to_owned()))?;
    let field = |key: &str| -> Result<&str, CliError> {
        object
            .get(key)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| malformed(format!("a `versions` element is missing string `{key}`")))
    };

    let version_str = field("version")?;
    let version = semver::Version::parse(version_str)
        .map_err(|e| malformed(format!("`{version_str}` is not a valid version: {e}")))?;
    // Parse-don't-validate: the same typed boundaries the TOML path uses. A
    // moving or injection-shaped value can never reach `git` from the JSON path
    // either.
    let source = SourceUrl::parse(name, field("source")?)?;
    let rev = PinnedRev::from_full_sha(name, field("rev")?)?;
    let sha256 = Sha256Hex::parse(name, field("sha256")?)?
        .as_str()
        .to_owned();

    // `capabilities` is an optional array of strings; absent means none. An
    // unknown capability name is a hard error, never a silently-dropped effect.
    let mut capabilities = BTreeSet::new();
    if let Some(caps) = object.get("capabilities") {
        let array = caps
            .as_array()
            .ok_or_else(|| malformed("`capabilities` is not an array".to_owned()))?;
        for cap in array {
            let token = cap
                .as_str()
                .ok_or_else(|| malformed("a `capabilities` element is not a string".to_owned()))?;
            let parsed = Capability::from_str(token)
                .map_err(|e| CliError::Resolve(format!("package `{name}`: {e}")))?;
            capabilities.insert(parsed);
        }
    }

    // `signature` is an optional Sigstore bundle. In the JSON mirror it is a
    // nested object (the bundle envelope), re-serialized verbatim and routed
    // through the same typed constructor as the TOML path. A present-but-
    // malformed bundle is a hard error, never a silently-dropped field.
    let signature = match object.get("signature") {
        None | Some(serde_json::Value::Null) => None,
        Some(value) => {
            let raw = serde_json::to_string(value)
                .map_err(|e| malformed(format!("`signature` could not be serialized: {e}")))?;
            Some(SignatureBundle::parse(name, &raw)?)
        }
    };

    Ok(EntryVersion {
        version,
        source,
        rev,
        sha256,
        capabilities,
        signature,
    })
}

/// The raw per-`[[version]]` fields collected during the line scan, before they
/// are parsed into the typed [`EntryVersion`].
#[derive(Default)]
struct RawVersion {
    version: Option<String>,
    source: Option<String>,
    rev: Option<String>,
    sha256: Option<String>,
    capabilities: Option<String>,
    signature: Option<String>,
}

impl RawVersion {
    /// Turn the collected raw fields into a typed [`EntryVersion`], erroring on a
    /// missing required field, a malformed version, or an unknown capability.
    fn into_version(self, name: &str) -> Result<EntryVersion, CliError> {
        let missing = |field: &str| {
            CliError::Resolve(format!(
                "package `{name}`: a `[[version]]` entry is missing `{field}`"
            ))
        };
        let version_str = self.version.ok_or_else(|| missing("version"))?;
        let version = semver::Version::parse(&version_str).map_err(|e| {
            CliError::Resolve(format!(
                "package `{name}`: `{version_str}` is not a valid version: {e}"
            ))
        })?;
        let raw_source = self.source.ok_or_else(|| missing("source"))?;
        let raw_rev = self.rev.ok_or_else(|| missing("rev"))?;
        let raw_sha256 = self.sha256.ok_or_else(|| missing("sha256"))?;
        // Parse-don't-validate: typed constructors reject invalid values at
        // the read boundary before any value can reach `git`.
        let source = SourceUrl::parse(name, &raw_source)?;
        let rev = PinnedRev::from_full_sha(name, &raw_rev)?;
        // A malformed content hash is refused here, at the cheap structural gate,
        // not deferred to a fetch-time mismatch.
        let sha256 = Sha256Hex::parse(name, &raw_sha256)?.as_str().to_owned();
        let capabilities = parse_capabilities(name, self.capabilities.as_deref())?;
        // A present `signature` is parsed into a typed bundle; a malformed one is
        // a hard error, never a silently-dropped field. Absent = unsigned.
        let signature = self
            .signature
            .as_deref()
            .map(|raw| crate::signing::SignatureBundle::parse(name, raw))
            .transpose()?;
        Ok(EntryVersion {
            version,
            source,
            rev,
            sha256,
            capabilities,
            signature,
        })
    }
}

/// Parse a `capabilities = ["network", …]` array value into a typed set via
/// [`Capability::from_str`]. Absent (or empty) means no capabilities; an unknown
/// name is a hard error — a typo can never become a silently-dropped capability
/// the user is then not warned about.
fn parse_capabilities(name: &str, raw: Option<&str>) -> Result<BTreeSet<Capability>, CliError> {
    let Some(raw) = raw else {
        return Ok(BTreeSet::new());
    };
    let inner = raw
        .trim()
        .strip_prefix('[')
        .and_then(|r| r.strip_suffix(']'))
        .ok_or_else(|| {
            CliError::Resolve(format!(
                "package `{name}`: `capabilities` must be a `[\"…\", …]` array, got: {raw}"
            ))
        })?;
    let mut set = BTreeSet::new();
    for token in inner.split(',') {
        let token = token.trim().trim_matches('"');
        if token.is_empty() {
            continue;
        }
        let cap = Capability::from_str(token)
            .map_err(|e| CliError::Resolve(format!("package `{name}`: {e}")))?;
        set.insert(cap);
    }
    Ok(set)
}

/// Strip one layer of surrounding double quotes from a scalar value.
fn unquote(value: &str) -> &str {
    value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or(value)
}

#[cfg(test)]
mod tests {
    use super::{CommitId, IndexEntry, PinnedRev, SourceUrl, read_entry, resolve_version};
    use ipe_ir::Capability;
    use std::path::{Path, PathBuf};

    /// A 40-char lowercase hex placeholder rev used across fixtures.
    const FIXTURE_REV: &str = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";

    /// Write a minimal fixture index with one package publishing the given
    /// versions, and return the index root. Every version shares one placeholder
    /// source/rev/sha256; capabilities are `["network"]`.
    fn write_fixture_index(root: &Path, name: &str, versions: &[&str]) {
        use std::fmt::Write as _;
        let packages = root.join("packages");
        std::fs::create_dir_all(&packages).expect("create packages dir");
        let mut text = format!("name = \"{name}\"\npublisher = \"tester\"\n");
        for v in versions {
            let _ = write!(
                text,
                "\n[[version]]\nversion = \"{v}\"\nsource = \"https://example.invalid/{name}\"\n\
                 rev = \"{FIXTURE_REV}\"\nsha256 = \"0000000000000000000000000000000000000000000000000000000000000000\"\ncapabilities = [\"network\"]\n"
            );
        }
        std::fs::write(packages.join(format!("{name}.toml")), text).expect("write entry");
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ipe-index-test-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn reads_and_resolves_the_highest_matching_version() {
        let root = temp_dir("highest");
        write_fixture_index(&root, "http-extras", &["1.0.0", "1.2.0", "2.0.0"]);
        let entry = read_entry(&root, "http-extras").expect("entry parses");
        assert_eq!(entry.publisher, "tester");
        assert_eq!(entry.versions.len(), 3);

        let req = "^1.0".parse().expect("valid req");
        let chosen = resolve_version(&entry, &req).expect("a match exists");
        assert_eq!(chosen.version.to_string(), "1.2.0");
        assert!(chosen.capabilities.contains(&Capability::Network));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_unknown_package_is_an_error() {
        let root = temp_dir("unknown-pkg");
        std::fs::create_dir_all(root.join("packages")).expect("packages dir");
        let err = read_entry(&root, "absent").unwrap_err();
        assert!(format!("{err}").contains("absent"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_unsatisfiable_requirement_is_an_error() {
        let root = temp_dir("unsat");
        write_fixture_index(&root, "http-extras", &["1.0.0", "1.2.0"]);
        let entry = read_entry(&root, "http-extras").expect("entry parses");
        let req = "^3".parse().expect("valid req");
        let err = resolve_version(&entry, &req).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("no published version"), "{msg}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_unknown_capability_is_rejected() {
        let root = temp_dir("bad-cap");
        std::fs::create_dir_all(root.join("packages")).expect("packages dir");
        std::fs::write(
            root.join("packages").join("weird.toml"),
            format!(
                "publisher = \"tester\"\n\n[[version]]\nversion = \"1.0.0\"\n\
                 source = \"https://example.invalid/weird\"\nrev = \"{FIXTURE_REV}\"\n\
                 sha256 = \"0000000000000000000000000000000000000000000000000000000000000000\"\ncapabilities = [\"telepathy\"]\n"
            ),
        )
        .expect("write entry");
        let err = read_entry(&root, "weird").unwrap_err();
        assert!(format!("{err}").contains("telepathy"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_missing_per_version_field_is_rejected() {
        let root = temp_dir("missing-field");
        std::fs::create_dir_all(root.join("packages")).expect("packages dir");
        // No `sha256` — the integrity anchor is mandatory, so validation rejects
        // on the missing field before even reaching transport/commit validation.
        std::fs::write(
            root.join("packages").join("nohash.toml"),
            format!(
                "publisher = \"tester\"\n\n[[version]]\nversion = \"1.0.0\"\n\
                 source = \"https://example.invalid/nohash\"\nrev = \"{FIXTURE_REV}\"\n"
            ),
        )
        .expect("write entry");
        let err = read_entry(&root, "nohash").unwrap_err();
        assert!(format!("{err}").contains("sha256"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn validate_entry_file_accepts_a_well_formed_entry() {
        // The admission-CI validator names the package by the file stem and
        // parses it exactly as the resolver would.
        use super::validate_entry_file;
        let root = temp_dir("validate-ok");
        write_fixture_index(&root, "http-extras", &["1.0.0", "1.2.0"]);
        let entry = validate_entry_file(&root.join("packages").join("http-extras.toml"))
            .expect("well-formed entry validates");
        assert_eq!(entry.name, "http-extras");
        assert_eq!(entry.versions.len(), 2);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn validate_entry_file_rejects_an_unknown_capability() {
        use super::validate_entry_file;
        let root = temp_dir("validate-bad-cap");
        let packages = root.join("packages");
        std::fs::create_dir_all(&packages).expect("packages dir");
        let path = packages.join("weird.toml");
        std::fs::write(
            &path,
            format!(
                "publisher = \"tester\"\n\n[[version]]\nversion = \"1.0.0\"\n\
                 source = \"https://example.invalid/weird\"\nrev = \"{FIXTURE_REV}\"\n\
                 sha256 = \"0000000000000000000000000000000000000000000000000000000000000000\"\ncapabilities = [\"telepathy\"]\n"
            ),
        )
        .expect("write entry");
        let err = validate_entry_file(&path).unwrap_err();
        assert!(format!("{err}").contains("telepathy"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn validate_entry_file_rejects_a_missing_field() {
        use super::validate_entry_file;
        let root = temp_dir("validate-missing");
        let packages = root.join("packages");
        std::fs::create_dir_all(&packages).expect("packages dir");
        let path = packages.join("nohash.toml");
        // No `sha256` — the integrity anchor is mandatory, so validation rejects
        // on the missing field before reaching transport/commit validation.
        std::fs::write(
            &path,
            format!(
                "publisher = \"tester\"\n\n[[version]]\nversion = \"1.0.0\"\n\
                 source = \"https://example.invalid/nohash\"\nrev = \"{FIXTURE_REV}\"\n"
            ),
        )
        .expect("write entry");
        let err = validate_entry_file(&path).unwrap_err();
        assert!(format!("{err}").contains("sha256"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn multiple_versions_are_all_parsed() {
        // Guards the array-of-tables scan: each `[[version]]` starts a fresh
        // record rather than overwriting the previous.
        let root = temp_dir("multi");
        write_fixture_index(&root, "p", &["0.1.0", "0.2.0", "0.3.0"]);
        let entry: IndexEntry = read_entry(&root, "p").expect("parses");
        let versions: Vec<String> = entry
            .versions
            .iter()
            .map(|v| v.version.to_string())
            .collect();
        assert_eq!(versions, vec!["0.1.0", "0.2.0", "0.3.0"]);
        let _ = std::fs::remove_dir_all(&root);
    }

    // --- SourceUrl parse-boundary tests ---

    #[test]
    fn source_url_accepts_https() {
        assert!(SourceUrl::parse("p", "https://github.com/user/repo").is_ok());
    }

    #[test]
    fn source_url_accepts_git_and_ssh() {
        assert!(SourceUrl::parse("p", "git://github.com/user/repo").is_ok());
        assert!(SourceUrl::parse("p", "ssh://git@github.com/user/repo").is_ok());
    }

    #[test]
    fn source_url_rejects_ext_transport_helper() {
        // `ext::` spawns an arbitrary shell command at clone time — RCE vector.
        let err = SourceUrl::parse("p", "ext::sh -c 'id > /tmp/pwned'").unwrap_err();
        assert!(format!("{err}").contains("https://"), "{err}");
    }

    #[test]
    fn source_url_rejects_dash_leading_value() {
        // A value starting with `-` would be parsed by git as a flag.
        let err = SourceUrl::parse("p", "--upload-pack=evil").unwrap_err();
        assert!(format!("{err}").contains("https://"), "{err}");
    }

    #[test]
    fn source_url_accepts_file_scheme() {
        // `file://` is on the allow-list so local and test-fixture repos work.
        assert!(SourceUrl::parse("p", "file:///home/user/repo").is_ok());
    }

    #[test]
    fn source_url_accepts_bare_absolute_path() {
        assert!(SourceUrl::parse("p", "/home/user/repo").is_ok());
    }

    #[test]
    fn source_url_rejects_fd_transport() {
        let err = SourceUrl::parse("p", "fd::4").unwrap_err();
        assert!(format!("{err}").contains("https://"), "{err}");
    }

    // --- CommitId parse-boundary tests ---

    #[test]
    fn commit_id_accepts_40_char_lowercase_hex() {
        assert!(CommitId::parse("p", FIXTURE_REV).is_ok());
    }

    #[test]
    fn commit_id_accepts_64_char_sha256() {
        let sha256_rev = "a".repeat(64);
        assert!(CommitId::parse("p", &sha256_rev).is_ok());
    }

    #[test]
    fn commit_id_accepts_short_hex() {
        // Abbreviated hashes are valid ref names with no injection shape.
        assert!(CommitId::parse("p", "deadbeef").is_ok());
        assert!(CommitId::parse("p", "abc").is_ok());
        assert!(CommitId::parse("p", "00").is_ok());
    }

    #[test]
    fn commit_id_accepts_branch_name() {
        // Branch names are valid ref names with no injection shape.
        assert!(CommitId::parse("p", "main").is_ok());
        assert!(CommitId::parse("p", "HEAD").is_ok());
    }

    #[test]
    fn commit_id_accepts_uppercase_hex() {
        // Mixed-case is not injection-shaped.
        assert!(CommitId::parse("p", "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2").is_ok());
    }

    #[test]
    fn commit_id_rejects_dash_leading_value() {
        // A `-`-leading rev would be parsed by git as a flag — injection shape.
        let err = CommitId::parse("p", "-S injected").unwrap_err();
        assert!(format!("{err}").contains("rev"), "{err}");
    }

    #[test]
    fn commit_id_rejects_double_dot() {
        // `..` is a refspec metacharacter — injection shape.
        let err = CommitId::parse("p", "HEAD..main").unwrap_err();
        assert!(format!("{err}").contains("rev"), "{err}");
    }

    #[test]
    fn commit_id_rejects_transport_helper_colons() {
        // `::` is the transport-helper separator — RCE vector.
        let err = CommitId::parse("p", "ext::evil").unwrap_err();
        assert!(format!("{err}").contains("rev"), "{err}");
    }

    #[test]
    fn commit_id_rejects_at_brace() {
        // `@{` is a git reflog selector — injection shape.
        let err = CommitId::parse("p", "HEAD@{0}").unwrap_err();
        assert!(format!("{err}").contains("rev"), "{err}");
    }

    #[test]
    fn malicious_index_entry_is_rejected_at_parse_time() {
        // An entry with `source = "ext::sh -c …"` must be rejected by
        // `read_entry` before any git invocation is possible.
        let root = temp_dir("malicious");
        let packages = root.join("packages");
        std::fs::create_dir_all(&packages).expect("packages dir");
        std::fs::write(
            packages.join("evil.toml"),
            format!(
                "publisher = \"attacker\"\n\n[[version]]\nversion = \"1.0.0\"\n\
                 source = \"ext::sh -c 'id > /tmp/pwned'\"\nrev = \"{FIXTURE_REV}\"\n\
                 sha256 = \"0000000000000000000000000000000000000000000000000000000000000000\"\ncapabilities = []\n"
            ),
        )
        .expect("write entry");
        let err = read_entry(&root, "evil").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("source"), "{msg}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn injection_shaped_rev_in_index_entry_is_rejected_at_parse_time() {
        // A `-`-leading `rev` must be rejected by `read_entry` before any git
        // invocation — flag injection is the real threat, not plain ref names.
        let root = temp_dir("bad-rev");
        let packages = root.join("packages");
        std::fs::create_dir_all(&packages).expect("packages dir");
        std::fs::write(
            packages.join("badrev.toml"),
            "publisher = \"tester\"\n\n[[version]]\nversion = \"1.0.0\"\n\
             source = \"https://example.invalid/badrev\"\nrev = \"-S injected\"\n\
             sha256 = \"0000000000000000000000000000000000000000000000000000000000000000\"\ncapabilities = []\n",
        )
        .expect("write entry");
        let err = read_entry(&root, "badrev").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("rev"), "{msg}");
        let _ = std::fs::remove_dir_all(&root);
    }

    // -----------------------------------------------------------------------
    // EntryLookup / read_entry_lookup — fail-closed integrity gate regression
    // -----------------------------------------------------------------------

    fn write_corrupt_entry(packages: &std::path::Path, name: &str) {
        // A file that exists but is not valid TOML / missing required fields.
        std::fs::write(
            packages.join(format!("{name}.toml")),
            "publisher = \"tester\"\n\n[[version]]\nversion = \"NOT_SEMVER\"\n\
             source = \"https://example.invalid/x\"\nrev = \"aabbcc\"\nsha256 = \"0000000000000000000000000000000000000000000000000000000000000000\"\n",
        )
        .expect("write corrupt entry");
    }

    #[test]
    fn lookup_absent_is_absent_variant() {
        let root = temp_dir("lookup-absent");
        std::fs::create_dir_all(root.join("packages")).expect("packages dir");
        let result = super::read_entry_lookup(&root, "nosuchpkg");
        assert!(
            matches!(result, super::EntryLookup::Absent),
            "a missing file must produce Absent, not Unreadable"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn lookup_present_is_present_variant() {
        let root = temp_dir("lookup-present");
        write_fixture_index(&root, "mypkg", &["1.0.0"]);
        let result = super::read_entry_lookup(&root, "mypkg");
        assert!(
            matches!(result, super::EntryLookup::Present(_)),
            "a well-formed entry must produce Present"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn lookup_corrupt_is_unreadable_variant() {
        let root = temp_dir("lookup-corrupt");
        let packages = root.join("packages");
        std::fs::create_dir_all(&packages).expect("packages dir");
        write_corrupt_entry(&packages, "broken");
        let result = super::read_entry_lookup(&root, "broken");
        assert!(
            matches!(result, super::EntryLookup::Unreadable(_)),
            "a present-but-malformed entry must produce Unreadable, not Absent"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A traversing name must be refused by the name gate BEFORE `entry_path`
    /// joins it — never read an entry from outside the index root. The gate
    /// surfaces as `Unreadable` (fail-closed), never `Absent` (which a gate would
    /// treat as "first version → skip").
    #[test]
    fn lookup_rejects_traversal_name_as_unreadable() {
        let root = temp_dir("lookup-traversal");
        std::fs::create_dir_all(root.join("packages")).expect("packages dir");
        for hostile in ["..", "../../etc/passwd", "/etc/passwd", "a/b"] {
            let result = super::read_entry_lookup(&root, hostile);
            assert!(
                matches!(result, super::EntryLookup::Unreadable(_)),
                "hostile name {hostile:?} must be Unreadable (refused), got a non-Unreadable variant"
            );
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    /// `read_entry` must refuse a traversing name with an error rather than
    /// joining it into a path and reading an arbitrary `.toml`.
    #[test]
    fn read_entry_rejects_traversal_name() {
        let root = temp_dir("read-entry-traversal");
        std::fs::create_dir_all(root.join("packages")).expect("packages dir");
        for hostile in ["..", "../secret", "/etc/hosts", "a/b"] {
            super::read_entry(&root, hostile)
                .expect_err(&format!("hostile name {hostile:?} must be rejected"));
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    /// `entry_file_exists` must refuse a traversing name rather than probing a
    /// path outside the index root.
    #[test]
    fn entry_file_exists_rejects_traversal_name() {
        let root = temp_dir("exists-traversal");
        std::fs::create_dir_all(root.join("packages")).expect("packages dir");
        super::entry_file_exists(&root, "../../etc/passwd")
            .expect_err("a traversing name must be rejected, not probed");
    }

    #[test]
    fn require_present_absent_yields_ok_none() {
        let root = temp_dir("rp-absent");
        std::fs::create_dir_all(root.join("packages")).expect("packages dir");
        let got = super::read_entry_lookup(&root, "nosuchpkg")
            .require_present()
            .expect("Absent must be Ok(None)");
        assert!(got.is_none(), "Absent must map to Ok(None), got Some");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn require_present_present_yields_ok_some() {
        let root = temp_dir("rp-present");
        write_fixture_index(&root, "mypkg", &["2.0.0"]);
        let got = super::read_entry_lookup(&root, "mypkg")
            .require_present()
            .expect("Present must be Ok(Some(_))")
            .expect("inner Option must be Some");
        assert_eq!(got.name, "mypkg");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn require_present_unreadable_yields_err() {
        // Regression for #1: a present-but-corrupt baseline must NOT produce
        // Ok(None) — that would let the immutability wall treat every submitted
        // version as "new" and skip the mutation check.
        let root = temp_dir("rp-corrupt");
        let packages = root.join("packages");
        std::fs::create_dir_all(&packages).expect("packages dir");
        write_corrupt_entry(&packages, "broken");
        let result = super::read_entry_lookup(&root, "broken").require_present();
        assert!(
            result.is_err(),
            "Unreadable must map to Err (fail closed), got Ok"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn absent_or_err_unreadable_yields_err() {
        // Regression for #2: a corrupt predecessor must NOT produce Ok(None)
        // (which the semver gate treats as "first version → skip").
        let root = temp_dir("aoe-corrupt");
        let packages = root.join("packages");
        std::fs::create_dir_all(&packages).expect("packages dir");
        write_corrupt_entry(&packages, "broken");
        let result = super::read_entry_lookup(&root, "broken").absent_or_err();
        assert!(
            result.is_err(),
            "Unreadable must map to Err (fail closed) in absent_or_err, got Ok"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    // --- PinnedRev type tests (test plan E) ---

    #[test]
    fn pinned_rev_rejects_moving_refs() {
        // Moving refs cannot inhabit PinnedRev; CommitId still accepts them
        // (the request role is deliberately distinct from the pin role).
        assert!(
            CommitId::parse("p", "HEAD").is_ok(),
            "CommitId must accept HEAD as a request ref"
        );
        assert!(
            CommitId::parse("p", "main").is_ok(),
            "CommitId must accept branch names as request refs"
        );
        assert!(
            PinnedRev::from_full_sha("p", "HEAD").is_err(),
            "PinnedRev must reject HEAD"
        );
        assert!(
            PinnedRev::from_full_sha("p", "main").is_err(),
            "PinnedRev must reject branch names"
        );
        assert!(
            PinnedRev::from_full_sha("p", "v1.0").is_err(),
            "PinnedRev must reject tag names"
        );
        // Length boundary: 39 and 41 chars must be rejected.
        let short = "a".repeat(39);
        let long = "a".repeat(41);
        assert!(
            PinnedRev::from_full_sha("p", &short).is_err(),
            "39-char hex must be rejected"
        );
        assert!(
            PinnedRev::from_full_sha("p", &long).is_err(),
            "41-char hex must be rejected"
        );
        // Non-hex characters must be rejected even at length 40.
        let nonhex = format!("{}g", "a".repeat(39));
        assert!(
            PinnedRev::from_full_sha("p", &nonhex).is_err(),
            "non-hex char must be rejected"
        );
        // Uppercase is rejected — the stored form must be lowercase hex.
        let upper = "A".repeat(40);
        assert!(
            PinnedRev::from_full_sha("p", &upper).is_err(),
            "uppercase hex must be rejected"
        );
        // A valid 40-char lowercase hex string must be accepted.
        assert!(
            PinnedRev::from_full_sha("p", FIXTURE_REV).is_ok(),
            "40-char lowercase hex must be accepted"
        );
    }

    // --- Entry reader refuses non-SHA rev (test plan F) ---

    #[test]
    fn entry_reader_refuses_nonsha_rev() {
        // An index entry with a non-SHA rev is rejected at parse time.
        let root = temp_dir("nonsha-rev");
        let packages = root.join("packages");
        std::fs::create_dir_all(&packages).expect("packages dir");
        std::fs::write(
            packages.join("badpin.toml"),
            "publisher = \"tester\"\n\n[[version]]\nversion = \"1.0.0\"\n\
             source = \"https://example.invalid/badpin\"\nrev = \"main\"\n\
             sha256 = \"0000000000000000000000000000000000000000000000000000000000000000\"\ncapabilities = []\n",
        )
        .expect("write entry");
        let err = read_entry(&root, "badpin").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("rev"), "{msg}");
        assert!(msg.contains("immutable"), "{msg}");
        let _ = std::fs::remove_dir_all(&root);

        // Also verify a legacy "HEAD" stored rev is refused.
        let root2 = temp_dir("head-rev");
        let packages2 = root2.join("packages");
        std::fs::create_dir_all(&packages2).expect("packages dir");
        std::fs::write(
            packages2.join("headpin.toml"),
            "publisher = \"tester\"\n\n[[version]]\nversion = \"1.0.0\"\n\
             source = \"https://example.invalid/headpin\"\nrev = \"HEAD\"\n\
             sha256 = \"0000000000000000000000000000000000000000000000000000000000000000\"\ncapabilities = []\n",
        )
        .expect("write entry");
        let err2 = read_entry(&root2, "headpin").unwrap_err();
        let msg2 = format!("{err2}");
        assert!(msg2.contains("rev"), "{msg2}");
        let _ = std::fs::remove_dir_all(&root2);
    }

    // --- signature field: parse, backward-compat, malformed refusal ---

    /// A minimal well-formed single-line JSON-object bundle for fixtures.
    const BUNDLE_JSON: &str =
        r#"{"mediaType":"application/vnd.dev.sigstore.bundle+json;version=0.3","dsseEnvelope":{}}"#;

    #[test]
    fn an_entry_without_a_signature_parses_as_unsigned() {
        // Backward compatibility: an entry with no `signature` field parses
        // exactly as before, with `signature == None`.
        let root = temp_dir("no-sig");
        write_fixture_index(&root, "http-extras", &["1.0.0"]);
        let entry = read_entry(&root, "http-extras").expect("entry parses");
        let v = entry.versions.first().expect("one version");
        assert!(v.signature.is_none(), "absent signature must be None");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_signed_entry_parses_the_bundle_from_toml() {
        // The reader's line scan strips one outer layer of quotes from a scalar,
        // so the bundle is stored as a bare (unquoted) JSON object value.
        let root = temp_dir("signed-toml");
        let packages = root.join("packages");
        std::fs::create_dir_all(&packages).expect("packages dir");
        std::fs::write(
            packages.join("signed.toml"),
            format!(
                "publisher = \"tester\"\n\n[[version]]\nversion = \"1.0.0\"\n\
                 source = \"https://example.invalid/signed\"\nrev = \"{FIXTURE_REV}\"\n\
                 sha256 = \"0000000000000000000000000000000000000000000000000000000000000000\"\ncapabilities = []\nsignature = {BUNDLE_JSON}\n"
            ),
        )
        .expect("write entry");
        let entry = read_entry(&root, "signed").expect("entry parses");
        let v = entry.versions.first().expect("one version");
        assert!(
            v.signature.is_some(),
            "present signature must parse to Some"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_malformed_signature_is_a_hard_error_not_silently_unsigned() {
        // A present-but-malformed bundle must be a hard error, never dropped to
        // "unsigned" — a malformed signature must not masquerade as absent.
        let root = temp_dir("bad-sig");
        let packages = root.join("packages");
        std::fs::create_dir_all(&packages).expect("packages dir");
        std::fs::write(
            packages.join("badsig.toml"),
            format!(
                "publisher = \"tester\"\n\n[[version]]\nversion = \"1.0.0\"\n\
                 source = \"https://example.invalid/badsig\"\nrev = \"{FIXTURE_REV}\"\n\
                 sha256 = \"{}\"\ncapabilities = []\nsignature = not-json-at-all\n",
                "0".repeat(64)
            ),
        )
        .expect("write entry");
        let err = read_entry(&root, "badsig").unwrap_err();
        assert!(format!("{err}").contains("signature"), "{err}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn json_mirror_parses_a_nested_signature_object() {
        // The JSON mirror carries `signature` as a nested object, re-serialized
        // and routed through the same typed constructor.
        let json = r#"{ "name": "http-extras", "publisher": "p",
            "versions": [ { "version": "1.0.0",
                            "source": "https://example.invalid/x",
                            "rev": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
                            "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
                            "signature": { "dsseEnvelope": {} } } ] }"#;
        let entry = super::parse_entry_json("http-extras", json).expect("parses");
        let v = entry.versions.first().expect("one version");
        assert!(v.signature.is_some(), "nested signature object must parse");
        let _ = v;
    }

    #[test]
    fn json_mirror_null_signature_is_unsigned() {
        // An explicit null `signature` is unsigned, backward-compatible.
        let json = r#"{ "name": "x", "publisher": "p",
            "versions": [ { "version": "1.0.0",
                            "source": "https://example.invalid/x",
                            "rev": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
                            "sha256": "0000000000000000000000000000000000000000000000000000000000000000", "signature": null } ] }"#;
        let entry = super::parse_entry_json("x", json).expect("parses");
        assert!(entry.versions.first().expect("v").signature.is_none());
    }

    #[test]
    fn ssot_guardrail_no_read_entry_ok_in_ipe_cli_src() {
        // Assert that no future edit re-introduces a fail-open collapse of
        // `read_entry` at an integrity gate. The pattern `read_entry(…).ok()`
        // fuses "absent" and "unreadable" into None; every integrity gate must
        // use `read_entry_lookup` + `require_present` / `absent_or_err` instead.
        let src_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut violations = Vec::new();
        collect_ssot_violations(&src_dir, &mut violations);
        assert!(
            violations.is_empty(),
            "fail-open read_entry collapse detected — use read_entry_lookup instead:\n{}",
            violations.join("\n")
        );
    }

    #[test]
    fn ssot_guardrail_no_read_to_string_ok_in_unsafe_scan_scope() {
        // Assert that no future edit re-introduces a fail-open read in the
        // unsafe-acknowledgment scan. `read_to_string(…).ok()` silently drops
        // unreadable modules so they never reach the acknowledgment gate; every
        // read in a security scan must propagate errors, not swallow them.
        // The scan covers index.rs's own production code: it reads only each
        // file's pre-`#[cfg(test)]` region, so the guardrail bodies below
        // (which mention the banned substrings as string literals) never
        // self-trigger.
        let src_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut violations = Vec::new();
        collect_read_to_string_ok_violations(&src_dir, &mut violations);
        assert!(
            violations.is_empty(),
            "fail-open read_to_string collapse detected — propagate the error instead:\n{}",
            violations.join("\n")
        );
    }

    /// The number of production lines to scan in a source file: everything up
    /// to (but not including) the first `#[cfg(test)]` attribute. Both guardrails
    /// enforce a *production* invariant — a fail-open collapse in shipped code —
    /// so scanning only the production region (a) covers this file's own
    /// production `read_entry` without the test-module guardrail bodies
    /// self-triggering on their `.contains("read_entry(")` string literals, and
    /// (b) never false-flags a `read_entry(x).ok()` written legitimately inside
    /// another file's test code.
    ///
    /// Relies on the crate convention that `#[cfg(test)]` items sit at the end of
    /// each file (a trailing `mod tests`, or a test-only helper below the
    /// production body); code above the first such attribute is production. The
    /// guardrail is defense-in-depth — the load-bearing guarantee is the fallible
    /// `Result` signature the call sites `?`-propagate.
    fn production_line_count(text: &str) -> usize {
        text.lines()
            .position(|l| l.trim_start().starts_with("#[cfg(test)]"))
            .unwrap_or_else(|| text.lines().count())
    }

    fn collect_ssot_violations(dir: &std::path::Path, out: &mut Vec<String>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect_ssot_violations(&path, out);
            } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                let Ok(text) = std::fs::read_to_string(&path) else {
                    continue;
                };
                let prod = production_line_count(&text);
                for (i, line) in text.lines().take(prod).enumerate() {
                    let trimmed = line.trim();
                    // Skip pure comment lines.
                    if trimmed.starts_with("//") {
                        continue;
                    }
                    if trimmed.contains("read_entry(") && trimmed.contains(".ok()") {
                        out.push(format!("{}:{}: {}", path.display(), i + 1, trimmed));
                    }
                    if trimmed.contains("let Ok(") && trimmed.contains("read_entry(") {
                        out.push(format!("{}:{}: {}", path.display(), i + 1, trimmed));
                    }
                }
            }
        }
    }

    fn collect_read_to_string_ok_violations(dir: &std::path::Path, out: &mut Vec<String>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect_read_to_string_ok_violations(&path, out);
            } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                let Ok(text) = std::fs::read_to_string(&path) else {
                    continue;
                };
                let prod = production_line_count(&text);
                for (i, line) in text.lines().take(prod).enumerate() {
                    let trimmed = line.trim();
                    // Skip pure comment lines.
                    if trimmed.starts_with("//") {
                        continue;
                    }
                    // The two banned forms that produce a fail-open unsafe scan:
                    // 1. filter_map(|…| fs::read_to_string(…).ok()) — silently
                    //    drops unreadable modules from the security scan.
                    // 2. read_to_string(entry).ok().into_iter() — same defect on
                    //    the single-file fallback path.
                    if trimmed.contains("read_to_string") && trimmed.contains("filter_map") {
                        out.push(format!("{}:{}: {}", path.display(), i + 1, trimmed));
                    }
                    if trimmed.contains("read_to_string(") && trimmed.contains(".ok().into_iter()")
                    {
                        out.push(format!("{}:{}: {}", path.display(), i + 1, trimmed));
                    }
                }
            }
        }
    }
}
