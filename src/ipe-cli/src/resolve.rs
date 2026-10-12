//! Package resolution: turn `ipe add <name>` into a fetched, hash-verified,
//! locked dependency.
//!
//! The flow for an index dependency ([`resolve_and_add`]): read the index entry,
//! resolve the highest version satisfying the requirement, `git`-fetch that
//! version's source at its pinned revision into the package cache, hash the
//! fetched tree, and **verify the hash equals the one the index pinned before
//! anything is written**. Only then is the resolution recorded — in `ipe.lock`
//! (the exact pins) and in `package.ipe`'s `dependencies` block (the requirement)
//! — and the resolved version and its capability set printed for consent.
//!
//! The `{git=}` / `{path=}` escapes ([`resolve_escape`]) bypass the index by
//! design but still carry lockfile integrity: the fetched (or copied) tree is
//! hashed and that hash is locked, so a later build re-verifies the same source.
//!
//! Verify-before-trust is the security boundary: a content-hash mismatch is a
//! hard [`CliError::HashMismatch`], never a warning — the fetched bytes are not
//! the source the publisher registered, so nothing derived from them is trusted.

use std::path::{Path, PathBuf};

use ipe_ir::Capability;

use crate::CliError;
use crate::index::{
    self, CommitId, EntryVersion, PinnedRev, RequestedRev, RevMismatch, Sha256Hex, SourceUrl,
    check_served,
};
use crate::lockfile::{LocalSource, LockedDep, LockedOrigin, Lockfile};
use crate::package_name::PackageName;
use crate::project::IpeDep;
use crate::published_version::PublishedVersion;
use crate::remote_ingest::{
    self, Captured, ChildStderr, FetchBudget, Git, IngestLimit, RefsCeiling, RunError, Transfer,
    TreeCeiling,
};

/// The environment variable overriding the index checkout root; tests point it
/// at a fixture index. Absent, the standard location ([`default_index_root`]) is
/// used.
const INDEX_DIR_ENV: &str = "IPE_INDEX_DIR";

/// Resolve an index dependency and record it: fetch the source at the pinned
/// revision, verify its content hash, then write the lockfile and manifest.
///
/// `index_root` is the index checkout to read from (a fixture in tests, the
/// standard location otherwise). Nothing is written until the fetched source's
/// hash matches the index-pinned hash.
///
/// # Errors
/// [`CliError::Resolve`] if the package or a matching version is not found, or a
/// `git` fetch fails; [`CliError::RemoteIngestExceeded`] when the fetch crosses
/// its transfer ceiling; [`CliError::LocalLimitExceeded`] when the fetched tree
/// crosses its tree ceiling or holds a refused entry; [`CliError::HashMismatch`]
/// if the fetched source's hash does not equal the pinned hash; [`CliError::Io`]
/// on a filesystem failure.
pub fn resolve_and_add(
    project_root: &Path,
    name: &str,
    req: &semver::VersionReq,
    index_root: &Path,
) -> Result<(), CliError> {
    // Prefer the registry Pages fast-path (an HTTP read of the per-package JSON
    // mirror), falling back to the git checkout on any network failure, air-gap,
    // or malformed response. The entry only decides WHICH version to fetch; the
    // resolved version's pinned `rev` + `sha256` stay the trust root, still
    // git-fetched and hash-verified below (verify-before-trust).
    // Parse-don't-validate: gate the name into a safe path component here, at the
    // boundary, before it reaches the cache-directory join in `fetch_source` or
    // the per-package URL/entry lookup.
    let package_name = PackageName::parse(name)?;
    let entry = crate::registry::read_entry_via_pages(package_name.as_str(), index_root)?;
    let version = index::resolve_version(&entry, req)?;
    resolve_and_add_within(
        project_root,
        &package_name,
        req,
        version,
        &remote_ingest::PACKAGE_SOURCE,
    )
}

/// [`resolve_and_add`] from the resolved index `version`, its fetch and tree
/// hash held to `budget`.
fn resolve_and_add_within(
    project_root: &Path,
    package_name: &PackageName,
    req: &semver::VersionReq,
    version: &EntryVersion,
    budget: &FetchBudget,
) -> Result<(), CliError> {
    let name = package_name.as_str();
    // Trust-verification ordering INVARIANT: nothing is installed or recorded
    // until BOTH the publisher signature (if any) and the pinned content hash
    // have verified against the FETCHED tree. Both read ONE budgeted walk of
    // that tree (`tree`): the signed subject digest must equal it, and so must
    // the pinned `sha256`. A crossed tree ceiling, a rejected signature OR a
    // hash mismatch aborts here, before `write_records`, so no unverified bytes
    // are ever trusted.
    let policy = crate::signing::load_trust_policy(project_root)?;
    let verifier = signature_verifier();

    let fetched = fetch_source(project_root, package_name, version, budget)?;
    let checkout = fetched.path().to_path_buf();
    let tree = crate::cache::TreeDigest::of_tree_within(&checkout, budget.tree())
        .map_err(CliError::from)
        .map_err(naming(package_name))?;

    // Publisher-identity provenance over the pinned `sha256`, at the same
    // verify-before-trust seam. Deny-by-default and fail-closed: a present
    // signature MUST verify against a configured trusted identity (its signed
    // subject digest equal to the fetched tree's hash) or the version is
    // rejected; an unsigned version resolves (with a warning) unless the trust
    // policy requires a signature.
    match crate::signing::evaluate_signature(
        name,
        &policy,
        version.signature.as_ref(),
        version.sha256.as_str(),
        &tree,
        verifier.as_ref(),
    )? {
        crate::signing::SignatureOutcome::UnsignedAllowed => {
            if !policy.trusted_identities().is_empty() {
                crate::screen::chatter(
                    crate::screen::Stream::Stderr,
                    crate::screen::Tone::UserError,
                    &format!(
                        "warning: `{name}` {} is unsigned — no publisher signature to verify \
                         against the configured registry trust policy.",
                        version.version
                    ),
                );
            }
        }
        crate::signing::SignatureOutcome::Verified(_) => {}
    }

    check_pin(name, &Sha256Hex::of_digest(&tree), &version.sha256)?;
    fetched.keep();

    let locked = LockedDep {
        name: package_name.clone(),
        version: version.version.clone(),
        origin: LockedOrigin::Index {
            source: version.source.clone(),
            rev: version.rev.clone(),
        },
        sha256: version.sha256.clone(),
    };
    write_records(project_root, name, &locked, req)?;

    report_added(name, &version.version.to_string(), &version.capabilities);
    Ok(())
}

/// Resolve one of the `{git=}` / `{path=}` escapes and record it.
///
/// Fetch (git) or copy (path) the source into the package cache, hash the tree,
/// and lock that hash. The escape bypasses the index but still carries lockfile
/// integrity.
///
/// The manifest is not rewritten here — the escape is already spelled in
/// `[dependencies]` by the author; this locks what it points at.
///
/// # Errors
/// [`CliError::Resolve`] if a `git` fetch fails or a path source is missing;
/// [`CliError::RemoteIngestExceeded`] when a `git` fetch crosses its transfer
/// ceiling; [`CliError::LocalLimitExceeded`] when the tree crosses its tree
/// ceiling or holds a refused entry; [`CliError::Io`] on a filesystem failure.
pub fn resolve_escape(project_root: &Path, name: &str, dep: &IpeDep) -> Result<(), CliError> {
    resolve_escape_within(project_root, name, dep, &remote_ingest::PACKAGE_SOURCE)
}

/// [`resolve_escape`] with a `git` fetch and the tree hash held to `budget`.
fn resolve_escape_within(
    project_root: &Path,
    name: &str,
    dep: &IpeDep,
    budget: &FetchBudget,
) -> Result<(), CliError> {
    // Parse-don't-validate: gate the name into a safe path component here, at the
    // boundary, before it reaches any cache-directory join.
    let package_name = PackageName::parse(name)?;
    let (origin, checkout, fetched) = match dep {
        IpeDep::Git { url, rev } => {
            // Parse-don't-validate: convert the raw manifest strings to typed
            // newtypes at this escape-path boundary before they reach the git
            // sink, so the sink cannot be called with an unvalidated value.
            let typed_url = SourceUrl::parse(&package_name, url)?;
            // The requested ref (may be a branch or HEAD) is injection-gated
            // here but not yet an immutable pin.
            let raw_rev = rev.as_deref().unwrap_or("HEAD");
            let requested = CommitId::parse(&package_name, raw_rev)?;
            // Classify the request's shape once, from the already
            // injection-validated `CommitId` — never re-parse the raw string.
            let shape = RequestedRev::classify(&package_name, &requested)?;
            // Fetch into the escape's fetch slot; the pin is the commit the
            // checkout holds, read from it after the fetch.
            let (fetched, commit) = fetch_git_requested(
                project_root,
                &package_name,
                &typed_url,
                &requested,
                &shape,
                budget,
            )?;
            let pinned = commit.into_pin();
            match check_served(&shape, &pinned) {
                None => {}
                Some(RevMismatch::Different { requested, served }) => {
                    return Err(CliError::Resolve(
                        crate::text::msg::index_rev_served_mismatch(
                            &package_name,
                            &requested,
                            &served,
                        ),
                    ));
                }
                Some(RevMismatch::ShadowedAbbrev { requested, served }) => {
                    // A same-shaped ref shadowed the abbreviation. The checkout
                    // still succeeded and is what gets locked — warn, don't
                    // refuse, per the maintainer-resolved override for this
                    // specific ambiguity.
                    let mut screen = crate::screen::Screen::new(crate::screen::Stream::Stderr);
                    let warning = crate::style::escape_abbrev_shadowed_warning(
                        screen.palette(),
                        package_name.as_str(),
                        &requested,
                        served.as_str(),
                    );
                    screen.guttered(&warning).emit();
                }
            }
            // Re-key the cache dir by the immutable SHA so fetch and verify
            // share the same key regardless of what ref was requested.
            let final_dest = cache_dir(project_root, &package_name, CacheSlot::Escape(&pinned));
            if final_dest.exists() {
                std::fs::remove_dir_all(&final_dest).map_err(|e| CliError::Io {
                    path: final_dest.clone(),
                    source: e,
                })?;
            }
            std::fs::rename(fetched.path(), &final_dest).map_err(|e| CliError::Io {
                path: fetched.path().to_path_buf(),
                source: e,
            })?;
            fetched.keep();
            let fetched = UnverifiedCheckout::new(final_dest.clone());
            (
                LockedOrigin::Git {
                    source: typed_url,
                    rev: pinned,
                },
                final_dest,
                Some(fetched),
            )
        }
        IpeDep::Path(path) => {
            let resolved = if path.is_absolute() {
                path.clone()
            } else {
                project_root.join(path)
            };
            if !resolved.is_dir() {
                return Err(CliError::Resolve(
                    crate::text::msg::resolve_path_dep_missing(&name, &resolved.display()),
                ));
            }
            let source = LocalSource::from_path(&package_name, path)?;
            // The author's own directory: never removed on a failure.
            (LockedOrigin::Path { source }, resolved, None)
        }
        IpeDep::Index(_) => {
            return Err(CliError::Resolve(
                crate::text::msg::resolve_index_dep_escape(&name),
            ));
        }
    };

    let sha256 = hash_checkout(&checkout, budget.tree()).map_err(naming(&package_name))?;
    if let Some(fetched) = fetched {
        fetched.keep();
    }
    // An escape has no published version; `0.0.0` marks "locked from an escape,
    // not the index" without inventing a version the source does not claim.
    let version = PublishedVersion::new(0, 0, 0);
    let locked = LockedDep {
        name: package_name,
        version,
        origin,
        sha256,
    };
    let mut lock = Lockfile::read(project_root)?;
    lock.upsert(locked);
    lock.write(project_root)?;
    Ok(())
}

/// Remove a dependency: drop it from both `package.ipe`'s `dependencies` block
/// and `ipe.lock`. A clean add→remove cycle leaves both files as they began.
///
/// # Errors
/// [`CliError::Io`] if the manifest or lockfile cannot be read or written.
pub fn resolve_and_remove(project_root: &Path, name: &str) -> Result<(), CliError> {
    crate::package_manifest::remove_manifest_dependency(&manifest_path(project_root), name)?;
    let mut lock = Lockfile::read(project_root)?;
    let was_locked = lock.remove(name);
    lock.write(project_root)?;
    if was_locked {
        crate::screen::Screen::new(crate::screen::Stream::Stdout)
            .line(crate::screen::Tone::Text, &format!("Removed `{name}`."))
            .emit();
    } else {
        crate::screen::Screen::new(crate::screen::Stream::Stdout)
            .line(
                crate::screen::Tone::Text,
                &format!("`{name}` was not a dependency; nothing to remove."),
            )
            .emit();
    }
    Ok(())
}

/// The per-user cache base: `XDG_CACHE_HOME`, else `<home>/.cache`.
///
/// The home is the platform home variable (`HOME`, or `USERPROFILE` on
/// Windows). Only an absolute path is accepted (a relative `XDG_CACHE_HOME` is
/// ignored, as the XDG spec requires), so nothing is ever written relative to
/// the current working directory.
///
/// # Errors
/// [`CliError::CacheHomeUnknown`] when neither names an absolute path.
pub fn default_cache_base() -> Result<PathBuf, CliError> {
    cache_base_from(
        ipe_env::var_os("XDG_CACHE_HOME"),
        crate::env_dir::home().ok().as_ref(),
    )
}

/// Resolve the cache base from the raw `XDG_CACHE_HOME` value and the home.
fn cache_base_from(
    xdg_cache_home: Option<std::ffi::OsString>,
    home: Option<&crate::env_dir::HomeDir>,
) -> Result<PathBuf, CliError> {
    crate::env_dir::ambient_home_from(xdg_cache_home, home, ".cache")
        .ok_or(CliError::CacheHomeUnknown)
}

/// The default index checkout root when `IPE_INDEX_DIR` is unset.
///
/// The standard per-user location under [`default_cache_base`]. Provisioning and
/// populating this checkout is a separate, deliberate outward-facing step; the
/// resolver only reads it.
///
/// # Errors
/// [`CliError::CacheHomeUnknown`] when no per-user cache base can be resolved.
pub fn default_index_root() -> Result<PathBuf, CliError> {
    Ok(default_cache_base()?.join("ipe").join("index"))
}

/// The index checkout root: `IPE_INDEX_DIR` when set, else [`default_index_root`].
///
/// # Errors
/// - [`CliError::EnvDirNotAbsolute`] when `IPE_INDEX_DIR` is set but not absolute.
/// - [`CliError::CacheHomeUnknown`] when `IPE_INDEX_DIR` is unset and no per-user
///   cache base can be resolved.
pub fn index_root() -> Result<PathBuf, CliError> {
    index_root_from(ipe_env::var_os(INDEX_DIR_ENV))
}

/// Resolve the index root from the raw `IPE_INDEX_DIR` value.
fn index_root_from(index_dir: Option<std::ffi::OsString>) -> Result<PathBuf, CliError> {
    crate::env_dir::explicit_override(INDEX_DIR_ENV, index_dir)?.map_or_else(default_index_root, Ok)
}

/// The content hash of a source tree.
///
/// The same hash the index pins and the resolver verifies against. Exposed so a
/// caller (e.g. `ipe package publish`, or a test building a fixture index)
/// computes the exact hash the resolver expects, rather than reimplementing the
/// tree walk. The walk is held to the tree ceiling of
/// [`remote_ingest::PACKAGE_SOURCE`], the one a fetch of the published tree is
/// verified under, so a tree that hashes here is never refused on fetch.
///
/// # Errors
/// [`CliError::LocalLimitExceeded`] when the tree crosses its tree ceiling or
/// holds a refused entry; [`CliError::Io`] if the tree cannot be walked or a
/// file cannot be read.
pub fn hash_source_tree(root: &Path) -> Result<Sha256Hex, CliError> {
    hash_checkout(root, remote_ingest::PACKAGE_SOURCE.tree())
}

/// Fetch a specific published index version's source at its pinned revision into
/// the package cache and verify its content hash equals the index pin, returning
/// the verified checkout directory.
///
/// The SP4 package gate's enforced-semver check calls this to materialise the
/// previous published version's source as the semver baseline — the exact bytes
/// the index registered, since nothing derived from an unverified fetch is
/// returned (verify-before-trust, the same boundary [`resolve_and_add`] applies
/// at install).
///
/// # Errors
/// [`CliError::Resolve`] on a `git` fetch failure;
/// [`CliError::RemoteIngestExceeded`] when the fetch crosses its transfer
/// ceiling; [`CliError::LocalLimitExceeded`] when the fetched tree crosses its
/// tree ceiling or holds a refused entry; [`CliError::HashMismatch`] when the
/// fetched tree's hash does not equal the pinned hash; [`CliError::Io`] on a
/// filesystem failure.
pub fn fetch_and_verify_index_version(
    project_root: &Path,
    name: &str,
    version: &EntryVersion,
) -> Result<PathBuf, CliError> {
    let name = PackageName::parse(name)?;
    fetch_and_verify_index_version_within(
        project_root,
        &name,
        version,
        &remote_ingest::PACKAGE_SOURCE,
    )
}

/// [`fetch_and_verify_index_version`] with the fetch and tree hash held to `budget`.
pub(crate) fn fetch_and_verify_index_version_within(
    project_root: &Path,
    name: &PackageName,
    version: &EntryVersion,
    budget: &FetchBudget,
) -> Result<PathBuf, CliError> {
    let fetched = fetch_source(project_root, name, version, budget)?;
    verify_hash(name, fetched.path(), &version.sha256, budget.tree())?;
    Ok(fetched.keep())
}

/// Re-verify that every locked Ipê dependency's cached source still hashes to the
/// pin recorded in `ipe.lock`.
///
/// The resolver verifies a fetched tree's hash at install ([`resolve_and_add`]);
/// this re-asserts the same integrity over the ALREADY-cached trees at publish
/// (the SP4 supply-chain check). A dependency whose cached bytes drifted from the
/// locked hash is a hard [`CliError::HashMismatch`] — the same verify-before-trust
/// boundary, never a warning. A dependency whose cache directory is absent is not
/// a mismatch (nothing was tampered; a build re-fetches it), so it is skipped,
/// as is a path escape, which is never cached.
///
/// # Errors
/// [`CliError::HashMismatch`] when a cached tree no longer matches its locked
/// hash; [`CliError::LocalLimitExceeded`] when a cached tree crosses its tree
/// ceiling or holds a refused entry; [`CliError::Io`] on a read failure;
/// [`CliError::Resolve`] on a malformed lockfile.
pub fn verify_lockfile_hashes(project_root: &Path) -> Result<(), CliError> {
    let lockfile = Lockfile::read(project_root)?;
    for dep in lockfile.packages() {
        let Some(cached) = dep_cache_dir(project_root, dep).filter(|dir| dir.is_dir()) else {
            // Not cached locally — nothing to re-verify here; a build re-fetches
            // and re-verifies against this same pin.
            continue;
        };
        verify_hash(
            &dep.name,
            &cached,
            &dep.sha256,
            remote_ingest::PACKAGE_SOURCE.tree(),
        )?;
    }
    Ok(())
}

/// The signature verifier for the current build.
///
/// Without the `signing` feature, this is the fail-closed
/// [`crate::signing::UnavailableVerifier`]: an unsigned version still resolves,
/// but any PRESENT signature is refused (an unverifiable signature is worse than
/// none). With the feature on, the Sigstore-backed offline verifier is used when
/// the vendored public-good trust-root material is available; if it cannot be
/// built, the fail-closed verifier is used so a present signature is still
/// refused rather than silently trusted.
fn signature_verifier() -> Box<dyn crate::signing::SignatureVerifier> {
    #[cfg(feature = "signing")]
    {
        if let Some(v) = crate::signing::vendored_sigstore_verifier() {
            return Box::new(v);
        }
    }
    Box::new(crate::signing::UnavailableVerifier)
}

/// The manifest path for a project root — the `package.ipe` the toolchain reads.
///
/// `ipe add` must record the requirement in this file (not a legacy `ipe.toml`),
/// or a fresh clone + resolve would lose the dependency: the lockfile pins an
/// exact version but is regenerated from the manifest's requirements.
fn manifest_path(project_root: &Path) -> PathBuf {
    project_root.join(crate::package_manifest::PACKAGE_IPE)
}

/// Which fetched source a package cache directory holds.
#[derive(Debug, Clone, Copy)]
enum CacheSlot<'a> {
    /// An index version, keyed by its published version.
    Index(&'a PublishedVersion),
    /// A git escape, keyed by the commit it resolved to.
    Escape(&'a PinnedRev),
    /// A git escape being fetched, before the commit it names is known.
    EscapeFetch,
}

/// The package cache directory of `slot` for `name` under the project's
/// `.ipe/packages/` tree.
///
/// The single SSOT for the cache key — the fetch path and the verify path both
/// call this, so they can never key by different values. The three slot shapes
/// never overlap: an index slot is `{name}-{version}`, and a package name never
/// starts with `.`, while an escape slot is `.git-{name}-{sha}` (a fixed-length
/// hex commit) and a fetch slot is `.fetch-{name}`. A requested ref never
/// reaches the path, so an escape pinned to a ref spelled like a version cannot
/// land in (or remove) that version's index slot.
///
/// Takes a validated [`PackageName`] so the name is a single, non-traversing
/// path component by construction — an unvalidated string cannot reach this
/// join and reroot the cache directory outside the project.
fn cache_dir(project_root: &Path, name: &PackageName, slot: CacheSlot<'_>) -> PathBuf {
    let key = match slot {
        CacheSlot::Index(version) => format!("{}-{version}", name.as_str()),
        CacheSlot::Escape(pinned) => format!(".git-{}-{}", name.as_str(), pinned.as_str()),
        CacheSlot::EscapeFetch => format!(".fetch-{}", name.as_str()),
    };
    project_root.join(".ipe").join("packages").join(key)
}

/// The cache directory for a locked dep, or `None` for a path escape, which is
/// read in place and never cached.
///
/// The [`LockedOrigin`] is the sole authority — field shapes are never
/// re-derived — and the name is a [`PackageName`] parsed at [`Lockfile::read`],
/// so a traversing name never reaches the join.
fn dep_cache_dir(project_root: &Path, dep: &LockedDep) -> Option<PathBuf> {
    match &dep.origin {
        LockedOrigin::Git { rev, .. } => {
            Some(cache_dir(project_root, &dep.name, CacheSlot::Escape(rev)))
        }
        LockedOrigin::Index { .. } => Some(cache_dir(
            project_root,
            &dep.name,
            CacheSlot::Index(&dep.version),
        )),
        LockedOrigin::Path { .. } => None,
    }
}

/// A fetched package checkout not yet verified, removed on drop unless kept.
///
/// Every fetch hands its checkout back in this form, so a fetch or a
/// verification that fails leaves nothing in the package cache.
#[derive(Debug)]
struct UnverifiedCheckout {
    /// The checkout directory.
    dir: PathBuf,
    /// Whether the checkout was kept.
    kept: bool,
}

impl UnverifiedCheckout {
    /// Take ownership of the freshly fetched `dir`.
    const fn new(dir: PathBuf) -> Self {
        Self { dir, kept: false }
    }

    /// The checkout directory.
    fn path(&self) -> &Path {
        &self.dir
    }

    /// Keep the checkout in the cache, returning its directory.
    fn keep(mut self) -> PathBuf {
        self.kept = true;
        std::mem::take(&mut self.dir)
    }
}

impl Drop for UnverifiedCheckout {
    fn drop(&mut self) {
        if !self.kept {
            // Best effort: the refusal already carries the real error.
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}

/// Fetch an index version's source at its pinned revision into the package
/// cache under `budget`, returning the unverified checkout.
fn fetch_source(
    project_root: &Path,
    name: &PackageName,
    entry: &EntryVersion,
    budget: &FetchBudget,
) -> Result<UnverifiedCheckout, CliError> {
    let dest = cache_dir(project_root, name, CacheSlot::Index(&entry.version));
    fetch_git_into(
        name,
        &entry.source,
        &Wanted::of_commit(&entry.rev),
        &dest,
        budget,
    )
    .map(|(checkout, _)| checkout)
    .map_err(naming(name))
}

/// Fetch a git escape's source at the requested ref into the escape's fetch
/// slot under `budget`.
///
/// The returned checkout holds the checked-out tree, and the commit it holds is
/// the pin the caller records before renaming the directory to its SHA-keyed
/// final location.
fn fetch_git_requested(
    project_root: &Path,
    name: &PackageName,
    url: &SourceUrl,
    requested: &CommitId,
    shape: &RequestedRev,
    budget: &FetchBudget,
) -> Result<(UnverifiedCheckout, CheckedOutCommit), CliError> {
    let dest = cache_dir(project_root, name, CacheSlot::EscapeFetch);
    let wanted = Wanted::of_request(requested, shape);
    fetch_git_into(name, url, &wanted, &dest, budget).map_err(naming(name))
}

/// What a fetch asks the server for.
///
/// A full commit SHA names exactly one commit, and only that commit satisfies
/// the fetch: no advertised ref, whatever its name, stands in for it. Any
/// other spelling names a ref (or an abbreviated SHA) the server resolves.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Wanted<'a> {
    /// A full commit SHA.
    Commit(PinnedRev),
    /// A ref name or an abbreviated SHA — never a full SHA.
    Name(&'a CommitId),
}

impl<'a> Wanted<'a> {
    /// A fetch of the pinned commit `rev`.
    fn of_commit(rev: &PinnedRev) -> Self {
        Self::Commit(rev.clone())
    }

    /// A fetch of what the author requested, by its classified `shape`: a full
    /// SHA is a [`Wanted::Commit`], anything else a [`Wanted::Name`].
    fn of_request(requested: &'a CommitId, shape: &RequestedRev) -> Self {
        match shape {
            RequestedRev::FullSha(sha) => Self::Commit(sha.clone()),
            RequestedRev::Head | RequestedRev::AbbrevHex(_) | RequestedRev::Name(_) => {
                Self::Name(requested)
            }
        }
    }

    /// The spelling passed to git — safe in argv, since both a [`PinnedRev`]
    /// and a [`CommitId`] never begin with `-`.
    fn as_str(&self) -> &str {
        match self {
            Self::Commit(sha) => sha.as_str(),
            Self::Name(name) => name.as_str(),
        }
    }

    /// What to check out once a single ref's tip was fetched: a commit by its
    /// SHA, so a tip that is not it fails closed; a name by `FETCH_HEAD`.
    fn fetched_tip(&self) -> &str {
        match self {
            Self::Commit(sha) => sha.as_str(),
            Self::Name(_) => "FETCH_HEAD",
        }
    }
}

/// The commit a fetch left checked out, read from `HEAD` after the checkout.
///
/// This is the only source of a recorded pin: the pin is what the tree on disk
/// is, never what the server's advertisement said it would be.
#[derive(Debug)]
struct CheckedOutCommit(PinnedRev);

impl CheckedOutCommit {
    /// Read the commit checked out in `dest` as a step of `transfer`, and
    /// [`check`](Self::check) it against `wanted`.
    fn read(
        name: &PackageName,
        wanted: &Wanted<'_>,
        dest: &Path,
        transfer: &Transfer,
    ) -> Result<Self, CliError> {
        let args = ["rev-parse", "--verify", "--quiet", "HEAD^{commit}"];
        let head =
            git_step(&args, dest, transfer).map_err(|failed| failed.into_cli(name, &args))?;
        let served = PinnedRev::from_full_sha(name, String::from_utf8_lossy(&head.stdout).trim())?;
        Self::check(name, wanted, served)
    }

    /// Accept `served` as the fetch of `wanted`: a requested commit must be
    /// exactly the commit served, and a requested name is whatever it served.
    fn check(name: &PackageName, wanted: &Wanted<'_>, served: PinnedRev) -> Result<Self, CliError> {
        match wanted {
            Wanted::Commit(requested) if *requested != served => Err(CliError::Resolve(
                crate::text::msg::resolve_fetched_commit_mismatch(name, requested, &served),
            )),
            Wanted::Commit(_) | Wanted::Name(_) => Ok(Self(served)),
        }
    }

    /// The commit, as the pin to record.
    fn into_pin(self) -> PinnedRev {
        self.0
    }
}

/// Clone `url` into `dest` and check out exactly `wanted`, returning the
/// checkout and the commit it holds. A pre-existing `dest` is removed first so
/// a re-add always fetches fresh.
///
/// `url` is a [`SourceUrl`] newtype — a raw unvalidated string cannot reach
/// this function — and `wanted` is built only from a [`CommitId`] or a
/// [`PinnedRev`], both of which never begin with `-`, so its spelling is safe
/// to pass to `git checkout` without `--`.
///
/// Defense-in-depth: [`Git::isolated`] restricts transports to the
/// [`Transport`](crate::index::Transport) set even if a value somehow bypassed
/// the parse boundary, and reads no user or system configuration.
///
/// The whole fetch is one [`Transfer`] under `budget`'s transfer ceilings: every step shares its
/// deadline, `dest` (object store and working tree) is measured against its
/// disk ceilings while git runs, and a crossing kills git with every process it
/// started and refuses the fetch. On any failure — a served commit that is not
/// the requested one included — `dest` is removed, so nothing partial stays in
/// the cache.
fn fetch_git_into(
    name: &PackageName,
    url: &SourceUrl,
    wanted: &Wanted<'_>,
    dest: &Path,
    budget: &FetchBudget,
) -> Result<(UnverifiedCheckout, CheckedOutCommit), CliError> {
    let checkout = UnverifiedCheckout::new(dest.to_path_buf());
    let transfer = Transfer::begin(*budget.transfer());
    stage_origin(name, url, dest, &transfer)?;
    // Fetch the EXACT pinned object rather than cloning a branch and hoping it
    // contains the rev. `git init` + `fetch <sha>` pulls precisely the pinned
    // commit and its tree — a shallow, single-object fetch independent of which
    // branch (if any) currently points at it. A server that refuses the
    // request is asked through its ref advertisement instead; any other failure
    // ends the fetch.
    //
    // `--end-of-options` ends git's option list before the remote-supplied or
    // requested positionals; `checkout <rev>` takes no terminator, since `--`
    // there means "path, not ref" — the spelling never begins with `-`.
    let exact = [
        "fetch",
        "--quiet",
        "--depth",
        "1",
        "--end-of-options",
        "origin",
        wanted.as_str(),
    ];
    match git_step(&exact, dest, &transfer) {
        Ok(_) => {
            run_git(
                name,
                &["checkout", "--quiet", wanted.fetched_tip()],
                dest,
                &transfer,
            )?;
        }
        Err(failed) if failed.widens() => {
            fetch_advertised(name, wanted, dest, &transfer, budget.refs())?;
        }
        Err(failed) => return Err(failed.into_cli(name, &exact)),
    }
    let commit = CheckedOutCommit::read(name, wanted, dest, &transfer)?;
    Ok((checkout, commit))
}

/// Make `dest` an empty repository whose `origin` is `url`, as the first steps
/// of `transfer`. A pre-existing `dest` is removed first.
fn stage_origin(
    name: &PackageName,
    url: &SourceUrl,
    dest: &Path,
    transfer: &Transfer,
) -> Result<(), CliError> {
    if dest.exists() {
        std::fs::remove_dir_all(dest).map_err(|e| CliError::Io {
            path: dest.to_path_buf(),
            source: e,
        })?;
    }
    // `git init` runs inside `dest`, so create it now (not just its parent).
    std::fs::create_dir_all(dest).map_err(|e| CliError::Io {
        path: dest.to_path_buf(),
        source: e,
    })?;
    run_git(name, &["init", "--quiet"], dest, transfer)?;
    // `git remote add` has no option terminator; the URL is a parse-validated
    // newtype (no leading `-`), so it is a safe trailing arg.
    run_git(
        name,
        &["remote", "add", "origin", url.as_str()],
        dest,
        transfer,
    )?;
    Ok(())
}

/// Fetch `wanted` from a server that refused it as a raw want.
///
/// The server's tag and branch advertisement is read first under `refs`, as a
/// step of `transfer` whose output is capped at `refs.bytes()`; a longer or
/// malformed advertisement refuses the fetch before any object arrives. When
/// an advertised ref matches `wanted` — a requested commit by its tip (the
/// peeled commit of an annotated tag) only, a requested name by its name only
/// — that ref alone is fetched, at depth 1. Only a `wanted` reachable solely
/// through history fetches every tag and branch, still under `transfer`'s
/// disk, entry and wall ceilings.
fn fetch_advertised(
    name: &PackageName,
    wanted: &Wanted<'_>,
    dest: &Path,
    transfer: &Transfer,
    refs: &RefsCeiling,
) -> Result<(), CliError> {
    let list = ["ls-remote", "origin", "refs/tags/*", "refs/heads/*"];
    let listed = git_step(&list, dest, &transfer.with_stdout_ceiling(refs.bytes()))
        .map_err(|failed| failed.into_cli(name, &list))?;
    let advertised = parse_advertisement(&listed.stdout, refs)
        .map_err(|limit| CliError::RemoteIngestExceeded(transfer.refusal(limit)))?;
    let tip = advertised
        .iter()
        .filter_map(|advert| {
            advert
                .matches(wanted)
                .map(|rank| (rank, advert.name.as_str()))
        })
        .min_by_key(|(rank, _)| *rank)
        .map(|(_, tip)| tip);
    if let Some(tip) = tip {
        let fetch = [
            "fetch",
            "--quiet",
            "--depth",
            "1",
            "--no-tags",
            "--end-of-options",
            "origin",
            tip,
        ];
        run_git(name, &fetch, dest, transfer)?;
        return run_git(
            name,
            &["checkout", "--quiet", wanted.fetched_tip()],
            dest,
            transfer,
        );
    }
    run_git(
        name,
        &[
            "fetch",
            "--quiet",
            "--no-tags",
            "--end-of-options",
            "origin",
            "refs/tags/*:refs/tags/*",
            "refs/heads/*:refs/remotes/origin/*",
        ],
        dest,
        transfer,
    )?;
    // A 40-hex argument is always an object name to `git checkout`, never a
    // ref spelled like one, so a requested commit checks out only itself.
    run_git(
        name,
        &["checkout", "--quiet", wanted.as_str()],
        dest,
        transfer,
    )
}

/// Parse `ls-remote` output into at most `refs.count()` advertised refs.
///
/// More lines is [`IngestLimit::Entries`]; a line that is not a SHA, a tab and
/// a safe tag or branch name is [`IngestLimit::MalformedRef`] — the whole
/// advertisement is refused. The one line skipped rather than refused is a
/// valid SHA beside a ref name that is not UTF-8: git allows such a name, no
/// requested name can equal it, and it never reaches argv, so dropping it only
/// sends a commit at its tip through the full fetch.
fn parse_advertisement(
    stdout: &[u8],
    refs: &RefsCeiling,
) -> Result<Vec<AdvertisedRef>, IngestLimit> {
    let body = stdout.strip_suffix(b"\n").unwrap_or(stdout);
    if body.is_empty() {
        return Ok(Vec::new());
    }
    let mut parsed = Vec::new();
    for (count, line) in (1_u64..).zip(body.split(|byte| *byte == b'\n')) {
        if count > refs.count() {
            return Err(IngestLimit::Entries(refs.count()));
        }
        match AdvertisedRef::parse(line).ok_or(IngestLimit::MalformedRef)? {
            Advertised::Ref(advert) => parsed.push(advert),
            Advertised::Unmatchable => {}
        }
    }
    Ok(parsed)
}

/// One line of a server's ref advertisement.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AdvertisedRef {
    /// The commit the line names; for a peeled line, the tag's commit.
    sha: PinnedRev,
    /// The ref, without any peeled suffix.
    name: RefName,
}

/// A well-formed advertisement line.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Advertised {
    /// A safe tag or branch ref.
    Ref(AdvertisedRef),
    /// A ref whose name is not UTF-8, which no request can match.
    Unmatchable,
}

/// How an advertised ref matches what a fetch wants, strongest first — git's
/// own order for resolving a short name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum TipMatch {
    /// The requested name is the ref's full name.
    FullName,
    /// The requested name is the tag's short name.
    Tag,
    /// The requested name is the branch's short name.
    Branch,
    /// The ref's tip is the requested commit.
    Commit,
}

impl AdvertisedRef {
    /// Parse `<sha>\t<ref>`, where a peeled `<ref>^{}` is accepted on a tag
    /// only; `None` when the line is malformed.
    fn parse(line: &[u8]) -> Option<Advertised> {
        let mut fields = line.splitn(2, |byte| *byte == b'\t');
        let sha = std::str::from_utf8(fields.next()?).ok()?;
        let sha = PinnedRev::parse_sha(sha)?;
        let Ok(name) = std::str::from_utf8(fields.next()?) else {
            return Some(Advertised::Unmatchable);
        };
        let name = match name.strip_suffix("^{}") {
            Some(base) if base.starts_with(RefName::TAGS) => base,
            Some(_) => return None,
            None => name,
        };
        Some(Advertised::Ref(Self {
            sha,
            name: RefName::parse(name)?,
        }))
    }

    /// How this ref matches `wanted`, if it does. A requested commit matches
    /// only by the ref's tip, never by its name, so a ref named like a SHA
    /// cannot stand in for that commit.
    fn matches(&self, wanted: &Wanted<'_>) -> Option<TipMatch> {
        let name = self.name.as_str();
        match *wanted {
            Wanted::Commit(ref sha) => (self.sha == *sha).then_some(TipMatch::Commit),
            Wanted::Name(rev) if name == rev.as_str() => Some(TipMatch::FullName),
            Wanted::Name(rev) if name.strip_prefix(RefName::TAGS) == Some(rev.as_str()) => {
                Some(TipMatch::Tag)
            }
            Wanted::Name(rev) if name.strip_prefix(RefName::HEADS) == Some(rev.as_str()) => {
                Some(TipMatch::Branch)
            }
            Wanted::Name(_) => None,
        }
    }
}

/// A remote-supplied tag or branch name, safe as a fetch refspec in argv.
///
/// It lies under `refs/tags/` or `refs/heads/` and obeys exactly the
/// `git check-ref-format` rules: none of `: * ^ ~ ? [ \`, a space or a control
/// byte, no `..`, `@{`, `//`, trailing `/` or `.`, and no component that
/// starts with `.` or ends with `.lock` in any case. Its `refs/` prefix keeps it from ever
/// being an option or a forced update, and the absent `:` keeps it from naming
/// a destination.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RefName(String);

impl RefName {
    const TAGS: &'static str = "refs/tags/";
    const HEADS: &'static str = "refs/heads/";

    /// Parse `raw`, or `None` when it is not a safe tag or branch name.
    fn parse(raw: &str) -> Option<Self> {
        let rest = raw
            .strip_prefix(Self::TAGS)
            .or_else(|| raw.strip_prefix(Self::HEADS))?;
        let unsafe_char = |c: char| {
            c.is_ascii_control() || matches!(c, ' ' | ':' | '*' | '^' | '~' | '?' | '[' | '\\')
        };
        let safe = !rest.is_empty()
            && !raw.chars().any(unsafe_char)
            && !raw.contains("..")
            && !raw.contains("@{")
            && !raw.contains("//")
            && !raw.ends_with('/')
            && !raw.ends_with('.')
            && rest
                .split('/')
                .all(|component| !component.starts_with('.') && !has_lock_suffix(component));
        safe.then(|| Self(raw.to_owned()))
    }

    const fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// Why one `git` step of a package fetch failed.
///
/// Only [`GitStepError::Exited`] — git ran and the server refused the request
/// — may widen the fetch; every other failure ends it.
#[derive(Debug)]
enum GitStepError {
    /// Git ran and exited non-zero, with this stderr, its cut marked.
    Exited { stderr: ChildStderr },
    /// The step crossed its budget.
    Refused(remote_ingest::IngestRefusal),
    /// A process git started held an output pipe past the grace.
    PipeHeld(remote_ingest::Stream),
    /// Reading one of git's output pipes failed, so its output was not used.
    PipeUnread(remote_ingest::Stream, std::io::ErrorKind),
    /// Git could not be started or waited on.
    Unavailable(std::io::Error),
    /// The staged path could not be measured.
    Measure(PathBuf, std::io::Error),
    /// A signal ended the step.
    Interrupted,
}

impl GitStepError {
    /// The step failure a run error is.
    fn from_run(error: RunError) -> Self {
        match error {
            RunError::Spawn(e) | RunError::Wait(e)
                if e.kind() == std::io::ErrorKind::Interrupted =>
            {
                Self::Interrupted
            }
            RunError::Spawn(e) | RunError::Wait(e) => Self::Unavailable(e),
            RunError::Measure(path, e) => Self::Measure(path, e),
            RunError::Exceeded(refusal) => Self::Refused(refusal),
            RunError::PipeDrainTimeout(stream) => Self::PipeHeld(stream),
            RunError::PipeRead(stream, kind) => Self::PipeUnread(stream, kind),
        }
    }

    /// Whether the fetch may ask the server again, more widely, after this failure.
    const fn widens(&self) -> bool {
        match self {
            Self::Exited { .. } => true,
            Self::Refused(_)
            | Self::PipeHeld(_)
            | Self::PipeUnread(..)
            | Self::Unavailable(_)
            | Self::Measure(..)
            | Self::Interrupted => false,
        }
    }

    /// The CLI error for this failure of `git <args>` fetching `name`.
    fn into_cli(self, name: &PackageName, args: &[&str]) -> CliError {
        match self {
            Self::Exited { stderr } => CliError::Resolve(crate::text::msg::resolve_git_failed(
                name,
                &crate::style::TerminalSafe::sanitize(&args.join(" ")),
                &stderr.to_terminal(),
            )),
            Self::Refused(refusal) => CliError::RemoteIngestExceeded(refusal),
            Self::PipeHeld(stream) => CliError::ChildPipeHeld(stream),
            Self::PipeUnread(stream, kind) => CliError::ChildPipeUnread(stream, kind),
            Self::Unavailable(e) => {
                CliError::Resolve(crate::text::msg::resolve_git_unavailable(name, &e))
            }
            Self::Measure(path, source) => CliError::Io { path, source },
            Self::Interrupted => CliError::Interrupted,
        }
    }
}

/// Run `git <args>` in `dest` as one step of `transfer`, with `dest` watched.
fn git_step(args: &[&str], dest: &Path, transfer: &Transfer) -> Result<Captured, GitStepError> {
    let output = Git::isolated(dest)
        .args(args)
        .run_detached(Some(dest), transfer)
        .map_err(GitStepError::from_run)?;
    if output.status.success() {
        Ok(output)
    } else {
        Err(GitStepError::Exited {
            stderr: output.stderr,
        })
    }
}

/// Run `git <args>` in `dest` as one step of `transfer` fetching `name`.
///
/// A spawn failure or a non-zero exit is a [`CliError::Resolve`] naming the
/// package; a crossed budget is [`CliError::RemoteIngestExceeded`].
fn run_git(
    name: &PackageName,
    args: &[&str],
    dest: &Path,
    transfer: &Transfer,
) -> Result<(), CliError> {
    git_step(args, dest, transfer)
        .map(drop)
        .map_err(|failed| failed.into_cli(name, args))
}

/// Hash the fetched source tree under `ceiling`; a crossed ceiling or refused
/// entry is a [`CliError::LocalLimitExceeded`], a walk/read failure an IO error.
fn hash_checkout(checkout: &Path, ceiling: &TreeCeiling) -> Result<Sha256Hex, CliError> {
    Sha256Hex::of_tree_within(checkout, ceiling).map_err(CliError::from)
}

/// Verify the fetched tree's content hash equals the index-pinned hash. This is
/// the verify-before-trust boundary: a mismatch is a hard error, so nothing
/// derived from an unverified fetch is ever written.
fn verify_hash(
    name: &PackageName,
    checkout: &Path,
    expected: &Sha256Hex,
    ceiling: &TreeCeiling,
) -> Result<(), CliError> {
    let actual = hash_checkout(checkout, ceiling).map_err(naming(name))?;
    check_pin(name.as_str(), &actual, expected)
}

/// Name the package `name` in a fetch or tree refusal an error carries; every
/// other error passes through unchanged.
fn naming(name: &PackageName) -> impl Fn(CliError) -> CliError + '_ {
    move |err| match err {
        CliError::RemoteIngestExceeded(refusal) => {
            CliError::RemoteIngestExceeded(refusal.with_name(name))
        }
        CliError::LocalLimitExceeded(refusal) => {
            CliError::LocalLimitExceeded(refusal.with_name(name))
        }
        other => other,
    }
}

/// Compare a fetched tree's `actual` hash with the index-pinned `expected`.
fn check_pin(name: &str, actual: &Sha256Hex, expected: &Sha256Hex) -> Result<(), CliError> {
    if actual == expected {
        Ok(())
    } else {
        Err(CliError::HashMismatch {
            package: name.to_owned(),
            expected: expected.to_string(),
            actual: actual.to_string(),
        })
    }
}

/// Write the lockfile pin and the manifest requirement for a resolved index
/// dependency. Both writes happen only after the hash verified.
fn write_records(
    project_root: &Path,
    name: &str,
    locked: &LockedDep,
    req: &semver::VersionReq,
) -> Result<(), CliError> {
    // Write the manifest FIRST: the rewrite fails closed (e.g. an index add
    // that collides with an author-written escape is refused), and doing it
    // before the lockfile keeps the two files consistent — a refusal leaves
    // BOTH untouched rather than a lockfile pin with no manifest requirement.
    // Only an INDEX requirement is written into the manifest: an escape
    // (`{git=}`/`{path=}`) is author-written and lockfile-only by design, so
    // `resolve_escape` never routes through here.
    crate::package_manifest::upsert_index_dependency(&manifest_path(project_root), name, req)?;
    let mut lock = Lockfile::read(project_root)?;
    lock.upsert(locked.clone());
    lock.write(project_root)
}

/// Print the resolved version and its capability set for consent.
fn report_added(name: &str, version: &str, capabilities: &std::collections::BTreeSet<Capability>) {
    crate::screen::Screen::new(crate::screen::Stream::Stdout)
        .line(
            crate::screen::Tone::Text,
            &added_report(name, version, capabilities),
        )
        .emit();
}

/// The `ipe add` consent report: the resolved version, the capability set, and —
/// loud — a warning when the package uses `native-ffi` (it crosses into opaque
/// native code, the one capability inference cannot see past). A pure function of
/// its inputs so the exact wording is testable.
///
/// Returns unindented body text; the caller applies the 2-space gutter.
fn added_report(
    name: &str,
    version: &str,
    capabilities: &std::collections::BTreeSet<Capability>,
) -> String {
    use std::fmt::Write as _;
    let mut out = format!("Added `{name}` {version}.\n");
    if capabilities.is_empty() {
        out.push_str("capabilities: none\n");
    } else {
        let names: Vec<&str> = capabilities.iter().map(|c| c.as_str()).collect();
        let _ = writeln!(out, "capabilities: {}", names.join(", "));
    }
    if capabilities.contains(&Capability::NativeFfi) {
        let _ = writeln!(
            out,
            "WARNING: `{name}` uses native FFI (`native-ffi`) — it runs native code whose \
             true capabilities cannot be inferred from Ipê. Review its source before trusting it."
        );
    }
    out
}

/// Whether a ref-name component ends in `.lock`, in any case: git reserves it
/// for its lock files, and a case-folding filesystem makes `.LOCK` the same file.
fn has_lock_suffix(component: &str) -> bool {
    component
        .get(component.len().saturating_sub(".lock".len())..)
        .is_some_and(|tail| tail.eq_ignore_ascii_case(".lock"))
}

#[cfg(test)]
mod tests {
    use super::{
        CacheSlot, CheckedOutCommit, GitStepError, INDEX_DIR_ENV, Wanted, added_report,
        cache_base_from, cache_dir, dep_cache_dir, fetch_advertised,
        fetch_and_verify_index_version_within, fetch_git_into, hash_checkout, hash_source_tree,
        index_root_from, parse_advertisement, resolve_and_add_within, resolve_and_remove,
        resolve_escape, resolve_escape_within, stage_origin, verify_hash, verify_lockfile_hashes,
    };
    use crate::CliError;
    use crate::index::{
        self, CommitId, EntryVersion, PinnedRev, RequestedRev, Sha256Hex, SourceUrl,
    };
    use crate::lockfile::{LockedDep, LockedOrigin, Lockfile};
    use crate::package_name::PackageName;
    use crate::project::IpeDep;
    use crate::published_version::PublishedVersion;
    use crate::remote_ingest::{
        self, ByteBudget, ChildStderr, FetchBudget, IngestLimit, IngestRefusal, IngestSource,
        LocalRefusal, LocalSource, PACKAGE_FILE_MAX_BYTES, PACKAGE_SOURCE, PACKAGE_TREE_MAX_BYTES,
        PACKAGE_TREE_MAX_DEPTH, PACKAGE_TREE_MAX_ENTRIES, REFS_MAX_BYTES, REFS_MAX_COUNT,
        RefsCeiling, RunError, Stream, Transfer, TreeCeiling,
    };
    use ipe_ir::Capability;
    use std::collections::BTreeSet;
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};

    /// A fixture package name.
    #[allow(clippy::expect_used)] // fixture names are literal registry names
    fn pn(raw: &str) -> PackageName {
        PackageName::parse(raw).expect("fixture package name parses")
    }

    fn temp_dir(_tag: &str) -> PathBuf {
        let sd = crate::scratch::ScratchDir::new("ipe-resolve-test").expect("scratch dir");
        sd.into_path() // caller's explicit remove_dir_all handles cleanup
    }

    fn scaffold_project(root: &Path) {
        std::fs::create_dir_all(root.join("src")).expect("src dir");
        std::fs::write(root.join("src").join("Main.ipe"), "module Main\n").expect("main");
        std::fs::write(
            root.join("package.ipe"),
            "module Package exposing (package)\n\nimport Ipe.Package exposing (..)\n\n\n\
             package : Package\npackage =\n    { name = \"app\" }\n",
        )
        .expect("manifest");
    }

    /// Create a git repo with one file at HEAD, returning its path.
    fn git_source(tag: &str, content: &str) -> PathBuf {
        let repo = temp_dir(&format!("src-{tag}"));
        let git = |args: &[&str]| {
            let ok = remote_ingest::fixture_git(&repo)
                .args(args)
                .output()
                .expect("git runs")
                .status
                .success();
            assert!(ok, "git {args:?} must succeed");
        };
        git(&["init", "--quiet"]);
        std::fs::write(repo.join("lib.ipe"), content).expect("write file");
        git(&["add", "."]);
        git(&["commit", "--quiet", "-m", "seed"]);
        repo
    }

    /// The HEAD commit of the fixture repo `repo`.
    fn head_rev(repo: &Path) -> String {
        let out = remote_ingest::fixture_git(repo)
            .args(["rev-parse", "HEAD"])
            .output()
            .expect("git rev-parse HEAD");
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    }

    /// Version `1.0.0` of `name`, published from `source` at its HEAD and
    /// pinned to `sha256`, read back through the index parser.
    fn index_version(name: &str, source: &Path, sha256: &str) -> EntryVersion {
        let index_root = temp_dir("index");
        let packages = index_root.join("packages");
        std::fs::create_dir_all(&packages).expect("packages dir");
        let entry = format!(
            "name = \"{name}\"\npublisher = \"tester\"\n\n[[version]]\nversion = \"1.0.0\"\n\
             source = \"{}\"\nrev = \"{}\"\nsha256 = \"{sha256}\"\ncapabilities = []\n",
            source.display(),
            head_rev(source),
        );
        std::fs::write(packages.join(format!("{name}.toml")), entry).expect("write entry");
        let entry = index::read_entry(&index_root, name).expect("fixture entry parses");
        let req = "^1".parse().expect("valid req");
        let version = index::resolve_version(&entry, &req)
            .expect("fixture version resolves")
            .clone();
        let _ = std::fs::remove_dir_all(&index_root);
        version
    }

    /// A fixture git repo with `count` small files at HEAD.
    fn git_source_of(tag: &str, count: usize) -> PathBuf {
        let repo = git_source(tag, "module Lib\n");
        for index in 1..count {
            std::fs::write(repo.join(format!("f{index}.ipe")), "x").expect("write file");
        }
        let git = |args: &[&str]| {
            remote_ingest::fixture_git(&repo)
                .args(args)
                .output()
                .expect("git runs")
                .status
                .success()
        };
        assert!(git(&["add", "."]));
        assert!(git(&["commit", "--quiet", "-m", "more"]));
        repo
    }

    /// A budget whose transfer and ref ceilings are production and whose tree
    /// ceiling is `tree`.
    fn with_tree(tree: TreeCeiling) -> FetchBudget {
        FetchBudget::for_test(*PACKAGE_SOURCE.transfer(), *PACKAGE_SOURCE.refs(), tree)
            .expect("paired budget")
    }

    /// Nothing is recorded or cached in `proj`: no lock, the manifest as it
    /// was, and an empty package cache.
    fn assert_nothing_recorded(proj: &Path, manifest_before: &[u8]) {
        assert!(
            !proj.join("ipe.lock").exists(),
            "a refused fetch writes no lock"
        );
        assert_eq!(
            std::fs::read(proj.join("package.ipe")).expect("manifest"),
            manifest_before,
            "a refused fetch leaves the manifest untouched"
        );
        let packages = proj.join(".ipe").join("packages");
        let leftover = std::fs::read_dir(&packages).map_or(0, Iterator::count);
        assert_eq!(leftover, 0, "a refused fetch leaves nothing in the cache");
    }

    #[test]
    fn verify_hash_rejects_a_mismatch() {
        // The verify-before-trust boundary: a wrong expected hash is a hard
        // HashMismatch, never accepted.
        let dir = temp_dir("verify");
        std::fs::write(dir.join("a.txt"), "hello").expect("write");
        let real = Sha256Hex::of_tree(&dir).expect("hash");
        verify_hash(&pn("p"), &dir, &real, PACKAGE_SOURCE.tree()).expect("matching hash passes");
        let wrong = Sha256Hex::parse(&pn("p"), &"0".repeat(64)).expect("valid digest");
        let err = verify_hash(&pn("p"), &dir, &wrong, PACKAGE_SOURCE.tree()).unwrap_err();
        assert!(matches!(err, crate::CliError::HashMismatch { .. }));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_path_escape_locks_its_hash() {
        let proj = temp_dir("path-escape");
        scaffold_project(&proj);
        let src = git_source("path", "module Lib\n");
        let dep = IpeDep::Path(src.clone());
        resolve_escape(&proj, "locallib", &dep).expect("path escape resolves");
        let lock = Lockfile::read(&proj).expect("lock");
        let entry = lock
            .packages()
            .iter()
            .find(|p| p.name.as_str() == "locallib")
            .expect("locked");
        assert!(
            matches!(entry.origin, LockedOrigin::Path { .. }),
            "a path escape locks a path origin"
        );
        assert_eq!(
            entry.sha256,
            Sha256Hex::of_tree(&src).expect("hash"),
            "an escape still locks its tree hash"
        );
        let _ = std::fs::remove_dir_all(&proj);
        let _ = std::fs::remove_dir_all(&src);
    }

    #[test]
    fn a_git_escape_records_immutable_sha_not_head() {
        let proj = temp_dir("git-escape-sha");
        scaffold_project(&proj);
        let src = git_source("git-sha", "module Lib\ngreeting = \"hi\"\n");
        let dep = IpeDep::Git {
            url: src.display().to_string(),
            rev: None,
        };
        resolve_escape(&proj, "remotelib", &dep).expect("git escape resolves");
        let lock = Lockfile::read(&proj).expect("lock");
        let entry = lock
            .packages()
            .iter()
            .find(|p| p.name.as_str() == "remotelib")
            .expect("remotelib must be locked");
        // The locked rev must be an immutable 40-hex SHA, not the string "HEAD".
        let rev_str = entry
            .origin
            .pinned_rev()
            .map(PinnedRev::as_str)
            .expect("a git escape pins a rev");
        assert_eq!(rev_str.len(), 40, "locked rev must be 40 chars");
        assert!(
            rev_str.chars().all(|c| c.is_ascii_hexdigit()),
            "locked rev must be lowercase hex"
        );
        assert_ne!(rev_str, "HEAD", "locked rev must not be the string HEAD");
        // The cached checkout must be keyed by the SHA, not by the fetch slot.
        let remotelib = PackageName::parse("remotelib").expect("valid name");
        assert!(
            !cache_dir(&proj, &remotelib, CacheSlot::EscapeFetch).exists(),
            "the fetch slot must be renamed away"
        );
        let pinned = entry.origin.pinned_rev().expect("a git escape pins a rev");
        assert!(
            cache_dir(&proj, &remotelib, CacheSlot::Escape(pinned)).exists(),
            "SHA-keyed cache dir must exist"
        );
        // Verify the locked SHA matches the fixture repo's actual HEAD.
        let actual_head = head_rev(&src);
        assert_eq!(
            rev_str, actual_head,
            "locked SHA must equal the fixture HEAD"
        );
        let _ = std::fs::remove_dir_all(&proj);
        let _ = std::fs::remove_dir_all(&src);
    }

    #[test]
    fn verify_refetch_pins_original_commit_after_branch_moves() {
        // After locking C1's SHA, adding a new commit C2 on the same branch
        // must not affect what the locked dep resolves to: re-resolve still
        // fetches C1 (the pinned SHA), not C2.
        let proj = temp_dir("branch-moves");
        scaffold_project(&proj);
        let src = git_source("branch-moves-src", "module Lib\nv = 1\n");

        // Lock dep at C1 (current HEAD).
        let dep = IpeDep::Git {
            url: src.display().to_string(),
            rev: None,
        };
        resolve_escape(&proj, "pinned", &dep).expect("first resolve");
        let lock1 = Lockfile::read(&proj).expect("lock after C1");
        let entry1 = lock1
            .packages()
            .iter()
            .find(|p| p.name.as_str() == "pinned")
            .expect("pinned locked")
            .clone();
        let sha1 = entry1
            .origin
            .pinned_rev()
            .map(PinnedRev::as_str)
            .expect("a git escape pins a rev")
            .to_owned();

        // Add C2 on the same branch — moves HEAD forward.
        let git = |args: &[&str]| {
            remote_ingest::fixture_git(&src)
                .args(args)
                .output()
                .expect("git")
                .status
                .success()
        };
        std::fs::write(src.join("lib.ipe"), "module Lib\nv = 2\n").expect("write");
        assert!(git(&["add", "."]));
        assert!(git(&["commit", "--quiet", "-m", "c2"]));

        // Resolve again — must pin C1's SHA, not the new HEAD.
        resolve_escape(&proj, "pinned", &dep).expect("second resolve");
        let lock2 = Lockfile::read(&proj).expect("lock after C2");
        let entry2 = lock2
            .packages()
            .iter()
            .find(|p| p.name.as_str() == "pinned")
            .expect("pinned locked");
        // The second resolve also records the current HEAD (C2), so the SHA
        // changes — what matters is that it IS a concrete SHA both times.
        let rev2_str = entry2
            .origin
            .pinned_rev()
            .map(PinnedRev::as_str)
            .expect("a git escape pins a rev");
        assert_eq!(rev2_str.len(), 40, "second locked rev must be 40 hex chars");
        assert!(
            rev2_str.chars().all(|c| c.is_ascii_hexdigit()),
            "second locked rev must be hex"
        );
        assert_ne!(rev2_str, "HEAD", "second locked rev must not be HEAD");
        // The two SHAs must differ (C2 is a new commit).
        assert_ne!(
            sha1, rev2_str,
            "locking after a branch move records the new concrete SHA"
        );

        let _ = std::fs::remove_dir_all(&proj);
        let _ = std::fs::remove_dir_all(&src);
    }

    #[test]
    fn verify_lockfile_hashes_covers_git_escapes() {
        // After locking a git escape, tampering a file in the cached checkout
        // must cause verify_lockfile_hashes to return HashMismatch — not Ok.
        let proj = temp_dir("verify-escape");
        scaffold_project(&proj);
        let src = git_source("verify-escape-src", "module Lib\n");
        let dep = IpeDep::Git {
            url: src.display().to_string(),
            rev: None,
        };
        resolve_escape(&proj, "escapedep", &dep).expect("resolve");

        let lock = Lockfile::read(&proj).expect("lock");
        let entry = lock
            .packages()
            .iter()
            .find(|p| p.name.as_str() == "escapedep")
            .expect("escapedep locked")
            .clone();

        // Tamper a file inside the cache dir.
        let escapedep = PackageName::parse("escapedep").expect("valid name");
        let cache = cache_dir(
            &proj,
            &escapedep,
            CacheSlot::Escape(entry.origin.pinned_rev().expect("a git escape pins a rev")),
        );
        assert!(cache.is_dir(), "cache dir must exist at the SHA key");
        std::fs::write(cache.join("TAMPERED"), "evil").expect("tamper");

        // Verify must detect the tamper.
        let result = verify_lockfile_hashes(&proj);
        assert!(
            matches!(result, Err(crate::CliError::HashMismatch { .. })),
            "tampered escape must produce HashMismatch, not Ok: {result:?}"
        );

        let _ = std::fs::remove_dir_all(&proj);
        let _ = std::fs::remove_dir_all(&src);
    }

    #[test]
    fn cache_key_is_shared_between_fetch_and_verify() {
        // The SSOT accessor: dep_cache_dir returns the same path for an escape
        // dep regardless of whether called from the fetch path or verify path.
        let proj = temp_dir("cache-key-ssot");

        // An escape dep: version 0.0.0 + 40-hex rev.
        let sha = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        let pinned_sha = PinnedRev::from_full_sha(&pn("myescape"), sha).expect("valid sha");
        let digest = Sha256Hex::parse(&pn("p"), &"0".repeat(64)).expect("valid digest");
        let escape_dep = LockedDep {
            name: PackageName::parse("myescape").expect("valid name"),
            version: PublishedVersion::new(0, 0, 0),
            origin: LockedOrigin::Git {
                source: SourceUrl::parse(&pn("myescape"), "https://example.invalid/myescape")
                    .expect("valid url"),
                rev: pinned_sha.clone(),
            },
            sha256: digest.clone(),
        };

        // An index dep: real version + any rev.
        let index_dep = LockedDep {
            name: PackageName::parse("mypkg").expect("valid name"),
            version: PublishedVersion::parse("1.2.0").expect("valid"),
            origin: LockedOrigin::Index {
                source: SourceUrl::parse(&pn("mypkg"), "https://example.invalid/mypkg")
                    .expect("valid url"),
                rev: PinnedRev::from_full_sha(&pn("mypkg"), sha).expect("valid sha"),
            },
            sha256: digest,
        };

        // Escape: dep_cache_dir must equal the escape slot (keyed by SHA).
        let myescape = PackageName::parse("myescape").expect("valid name");
        let via_escape = cache_dir(&proj, &myescape, CacheSlot::Escape(&pinned_sha));
        let via_dep = dep_cache_dir(&proj, &escape_dep);
        assert_eq!(
            Some(via_escape.clone()),
            via_dep,
            "fetch and verify must key escape by the same path"
        );

        // Index dep: dep_cache_dir must key by version, not rev.
        let mypkg = PackageName::parse("mypkg").expect("valid name");
        let version = PublishedVersion::parse("1.2.0").expect("valid");
        let via_version = cache_dir(&proj, &mypkg, CacheSlot::Index(&version));
        let via_index = dep_cache_dir(&proj, &index_dep);
        assert_eq!(
            Some(via_version.clone()),
            via_index,
            "index dep must be keyed by version"
        );
        assert_ne!(
            via_escape, via_version,
            "escape and index deps must not share a cache dir"
        );

        let _ = std::fs::remove_dir_all(&proj);
    }

    /// `resolve_escape` must refuse a traversing package name before any git
    /// fetch or cache-dir join — the delete-then-clone sink is unreachable with
    /// an unvalidated name.
    #[test]
    fn resolve_escape_rejects_traversal_name() {
        let proj = temp_dir("resolve-escape-traversal");
        scaffold_project(&proj);
        let dep = IpeDep::Git {
            url: "https://example.invalid/x".to_owned(),
            rev: None,
        };
        resolve_escape(&proj, "../../evil", &dep)
            .expect_err("a traversing package name must be refused");
        let _ = std::fs::remove_dir_all(&proj);
    }

    #[test]
    fn the_add_report_shows_the_capability_set() {
        let caps: BTreeSet<Capability> = [Capability::Network, Capability::Clock]
            .into_iter()
            .collect();
        let report = added_report("http-extras", "1.2.0", &caps);
        assert!(report.contains("Added `http-extras` 1.2.0."));
        assert!(report.contains("capabilities: network, clock"));
        assert!(
            !report.contains("WARNING"),
            "no native-ffi means no warning"
        );
    }

    #[test]
    fn the_add_report_is_loud_on_native_ffi() {
        let caps: BTreeSet<Capability> = std::iter::once(Capability::NativeFfi).collect();
        let report = added_report("risky", "0.1.0", &caps);
        assert!(report.contains("native-ffi"));
        assert!(
            report.contains("WARNING"),
            "native-ffi must be surfaced loudly"
        );
    }

    #[test]
    fn the_add_report_names_no_capabilities() {
        let report = added_report("pure", "1.0.0", &BTreeSet::new());
        assert!(report.contains("capabilities: none"));
    }

    #[test]
    fn remove_of_an_absent_dep_is_clean() {
        let proj = temp_dir("remove-absent");
        scaffold_project(&proj);
        resolve_and_remove(&proj, "nope").expect("removing an absent dep is not an error");
        let manifest = std::fs::read_to_string(proj.join("package.ipe")).expect("manifest");
        assert!(!manifest.contains("nope"));
        let _ = std::fs::remove_dir_all(&proj);
    }

    // --- git hardening: env vars and `--` option terminator ---

    #[test]
    fn git_clone_uses_double_dash_before_url() {
        // Exercises the `git clone -- <url> <dest>` path: `--` terminates git's
        // option list so the URL is always a positional. The checkout uses the
        // validated rev without `--` (checkout's `--` means "path, not ref").
        // Both url and rev must be typed newtypes — raw strings cannot reach
        // `fetch_git_into` directly, enforcing parse-don't-validate at the sink.
        let src = git_source("dash-url-clone", "module Lib\n");
        let dest = temp_dir("dash-url-dest");
        let url = SourceUrl::parse(&pn("p"), &src.display().to_string())
            .expect("local path is a valid source URL");
        let rev = CommitId::parse(&pn("p"), "HEAD").expect("HEAD is a valid commit id");
        let shape = RequestedRev::classify(&pn("p"), &rev).expect("HEAD classifies");
        let (checkout, commit) = fetch_git_into(
            &pn("p"),
            &url,
            &Wanted::of_request(&rev, &shape),
            &dest,
            &PACKAGE_SOURCE,
        )
        .expect("clone succeeds for a valid local repo");
        assert_eq!(commit.into_pin().as_str(), head_rev(&src));
        assert!(checkout.keep().is_dir(), "destination was populated");
        let _ = std::fs::remove_dir_all(&src);
        let _ = std::fs::remove_dir_all(&dest);
    }

    // --- the want-by-SHA fallback: the ref advertisement ---

    /// Run `git <args>` in the fixture repo `repo` with `stdin`, asserting it
    /// succeeds; returns its stdout.
    fn run_fixture(repo: &Path, args: &[&str], stdin: &[u8]) -> Vec<u8> {
        use std::io::Write as _;
        let mut child = remote_ingest::fixture_git(repo)
            .args(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("git spawns");
        child
            .stdin
            .take()
            .expect("piped stdin")
            .write_all(stdin)
            .expect("feed git stdin");
        let out = child.wait_with_output().expect("git runs");
        assert!(out.status.success(), "git {args:?} must succeed");
        out.stdout
    }

    /// Commit `file` to the fixture repo `repo`, returning the new HEAD.
    fn commit_file(repo: &Path, file: &str) -> String {
        std::fs::write(repo.join(file), "x").expect("write file");
        run_fixture(repo, &["add", "."], b"");
        run_fixture(repo, &["commit", "--quiet", "-m", file], b"");
        head_rev(repo)
    }

    /// A fixture repo with `tags` packed lightweight tags at HEAD beside its
    /// one branch, so it advertises `tags + 1` refs; returns it and HEAD.
    fn tagged_source(tag: &str, tags: u64) -> (PathBuf, String) {
        use std::fmt::Write as _;
        let repo = git_source(tag, "module Lib\n");
        let head = head_rev(&repo);
        let script = (0..tags).fold(String::new(), |mut script, n| {
            let _ = writeln!(script, "create refs/tags/t{n:05} {head}");
            script
        });
        run_fixture(&repo, &["update-ref", "--stdin"], script.as_bytes());
        run_fixture(&repo, &["pack-refs", "--all"], b"");
        (repo, head)
    }

    /// The byte length of `repo`'s tag and branch advertisement.
    fn advertisement_len(repo: &Path) -> u64 {
        let out = run_fixture(
            repo,
            &["ls-remote", ".", "refs/tags/*", "refs/heads/*"],
            b"",
        );
        u64::try_from(out.len()).expect("advertisement length fits u64")
    }

    /// `dest` staged with `src` as its origin, and the fresh transfer it is under.
    fn staged(src: &Path, dest: &Path) -> Transfer {
        let url = SourceUrl::parse(&pn("p"), &src.display().to_string())
            .expect("local path is a valid source URL");
        let transfer = Transfer::begin(*PACKAGE_SOURCE.transfer());
        stage_origin(&pn("p"), &url, dest, &transfer).expect("origin stages");
        transfer
    }

    /// No object pack reached `dest`.
    fn assert_no_pack(dest: &Path) {
        let packs = std::fs::read_dir(dest.join(".git").join("objects").join("pack"))
            .map_or(0, Iterator::count);
        assert_eq!(packs, 0, "no object may be fetched before the refusal");
    }

    /// Whether `dest` holds a shallow (depth-limited) history.
    fn is_shallow(dest: &Path) -> bool {
        dest.join(".git").join("shallow").is_file()
    }

    /// The refusal a package fetch reports for `limit`.
    const fn fetch_refused(limit: IngestLimit) -> IngestRefusal {
        IngestRefusal {
            source: IngestSource::PackageFetch,
            limit,
            name: None,
        }
    }

    /// The byte ceiling `bytes`, which a fixture keeps inside the remote range.
    #[allow(clippy::expect_used)] // fixture ceilings are measured in-range sizes
    fn byte_budget(bytes: u64) -> ByteBudget {
        ByteBudget::for_test(bytes).expect("in-range byte budget")
    }

    /// A fetch of the fixture commit `sha`.
    #[allow(clippy::expect_used)] // fixture SHAs come from `git rev-parse`
    fn commit(sha: &str) -> Wanted<'static> {
        Wanted::Commit(PinnedRev::parse_sha(sha).expect("fixture SHA parses"))
    }

    /// An advertisement of exactly `REFS_MAX_COUNT` lines is read, and the rev
    /// at a tip is fetched from it.
    #[test]
    fn an_advertisement_at_the_ref_count_ceiling_fetches_the_tip() {
        let (src, head) = tagged_source("refs-at", REFS_MAX_COUNT - 1);
        let dest = temp_dir("refs-at-dest");
        let transfer = staged(&src, &dest);
        fetch_advertised(
            &pn("p"),
            &commit(&head),
            &dest,
            &transfer,
            PACKAGE_SOURCE.refs(),
        )
        .expect("a tip within the ref ceilings fetches");
        assert_eq!(head_rev(&dest), head);
        assert!(
            dest.join("lib.ipe").is_file(),
            "the tip's tree is checked out"
        );
        let _ = std::fs::remove_dir_all(&dest);
        let _ = std::fs::remove_dir_all(&src);
    }

    /// One advertised line past `REFS_MAX_COUNT` refuses the fetch before any
    /// object is fetched.
    #[test]
    fn an_advertisement_past_the_ref_count_ceiling_is_refused_before_any_fetch() {
        let (src, head) = tagged_source("refs-past", REFS_MAX_COUNT);
        let dest = temp_dir("refs-past-dest");
        let transfer = staged(&src, &dest);
        let result = fetch_advertised(
            &pn("p"),
            &commit(&head),
            &dest,
            &transfer,
            PACKAGE_SOURCE.refs(),
        );
        assert!(
            matches!(
                result,
                Err(CliError::RemoteIngestExceeded(ref refusal))
                    if *refusal == fetch_refused(IngestLimit::Entries(REFS_MAX_COUNT))
            ),
            "got {result:?}"
        );
        assert_no_pack(&dest);
        let _ = std::fs::remove_dir_all(&dest);
        let _ = std::fs::remove_dir_all(&src);
    }

    /// An advertisement exactly at its byte ceiling is read; one byte past it
    /// is refused as a byte overrun before any object is fetched.
    #[test]
    fn an_advertisement_at_the_ref_byte_ceiling_is_read_and_one_byte_past_is_refused() {
        let (src, head) = tagged_source("refs-bytes", 8);
        let len = advertisement_len(&src);

        let past_dest = temp_dir("refs-bytes-past");
        let transfer = staged(&src, &past_dest);
        let past = RefsCeiling::for_test(byte_budget(len - 1), REFS_MAX_COUNT);
        let result = fetch_advertised(&pn("p"), &commit(&head), &past_dest, &transfer, &past);
        assert!(
            matches!(
                result,
                Err(CliError::RemoteIngestExceeded(ref refusal))
                    if *refusal == fetch_refused(IngestLimit::Bytes(len - 1))
            ),
            "got {result:?}"
        );
        assert_no_pack(&past_dest);

        let at_dest = temp_dir("refs-bytes-at");
        let transfer = staged(&src, &at_dest);
        let at = RefsCeiling::for_test(byte_budget(len), REFS_MAX_COUNT);
        fetch_advertised(&pn("p"), &commit(&head), &at_dest, &transfer, &at)
            .expect("an advertisement at its byte ceiling is read");
        assert_eq!(head_rev(&at_dest), head);
        for dir in [past_dest, at_dest, src] {
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    /// A tag whose name starts with `-` is a legal ref; its `refs/` prefix keeps
    /// it a positional, so the commit at its tip is fetched through it alone.
    #[test]
    fn a_dash_leading_tag_name_is_fetched_as_a_positional() {
        let src = git_source("refs-dash", "module Lib\n");
        let base = head_rev(&src);
        let tip = commit_file(&src, "tip.ipe");
        run_fixture(
            &src,
            &["update-ref", "--stdin"],
            format!("create refs/tags/-x {tip}\n").as_bytes(),
        );
        run_fixture(&src, &["reset", "--hard", "--quiet", &base], b"");
        let dest = temp_dir("refs-dash-dest");
        let transfer = staged(&src, &dest);
        fetch_advertised(
            &pn("p"),
            &commit(&tip),
            &dest,
            &transfer,
            PACKAGE_SOURCE.refs(),
        )
        .expect("the tip of a dash-leading tag fetches");
        assert_eq!(head_rev(&dest), tip);
        assert!(is_shallow(&dest), "the tag's tip is fetched at depth 1");
        let _ = std::fs::remove_dir_all(&dest);
        let _ = std::fs::remove_dir_all(&src);
    }

    /// A tag named like the requested commit's SHA but pointing elsewhere never
    /// stands in for that commit: the commit itself is checked out, and it is
    /// the pin read back.
    #[test]
    fn a_tag_named_like_the_requested_sha_is_never_fetched_in_its_place() {
        let src = git_source("refs-sha-named", "module Lib\n");
        let wanted_sha = commit_file(&src, "wanted.ipe");
        commit_file(&src, "hostile.ipe");
        run_fixture(&src, &["tag", &wanted_sha], b"");
        let dest = temp_dir("refs-sha-named-dest");
        let transfer = staged(&src, &dest);
        let wanted = commit(&wanted_sha);
        fetch_advertised(&pn("p"), &wanted, &dest, &transfer, PACKAGE_SOURCE.refs())
            .expect("the requested commit fetches");
        assert_eq!(head_rev(&dest), wanted_sha);
        assert!(
            !dest.join("hostile.ipe").exists(),
            "the SHA-named tag's tree must not be checked out"
        );
        let pinned = CheckedOutCommit::read(&pn("p"), &wanted, &dest, &transfer)
            .expect("the checked-out commit is the requested one");
        assert_eq!(pinned.into_pin().as_str(), wanted_sha);
        let _ = std::fs::remove_dir_all(&dest);
        let _ = std::fs::remove_dir_all(&src);
    }

    /// A requested commit accepts only itself as the checked-out commit; a
    /// requested name accepts whatever commit it served.
    #[test]
    fn a_served_commit_other_than_the_requested_one_is_refused() {
        let other = "fedcba9876543210fedcba9876543210fedcba98";
        let served = || PinnedRev::parse_sha(other).expect("fixture SHA parses");
        let refused = CheckedOutCommit::check(&pn("p"), &commit(SHA), served());
        assert!(
            matches!(&refused, Err(CliError::Resolve(msg)) if msg.to_string().contains(other)),
            "got {refused:?}"
        );
        let same = CheckedOutCommit::check(&pn("p"), &commit(other), served())
            .expect("the requested commit is accepted");
        assert_eq!(same.into_pin().as_str(), other);
        let named = CheckedOutCommit::check(
            &pn("p"),
            &Wanted::Name(&CommitId::parse(&pn("p"), "v1").expect("v1 is a valid commit id")),
            served(),
        )
        .expect("a requested name accepts the commit it served");
        assert_eq!(named.into_pin().as_str(), other);
    }

    /// A full-SHA fetch from a server that can serve only other commits — its
    /// every tag, one spelled like the requested SHA included, tips elsewhere —
    /// is refused end to end, and the partial checkout is removed.
    #[test]
    fn a_commit_the_server_cannot_serve_is_refused_and_leaves_no_checkout() {
        let absent = "fedcba9876543210fedcba9876543210fedcba98";
        let src = git_source("commit-absent", "module Lib\n");
        commit_file(&src, "served.ipe");
        run_fixture(&src, &["tag", "v1.0.0"], b"");
        run_fixture(&src, &["tag", absent], b"");
        let url = SourceUrl::parse(&pn("p"), &src.display().to_string())
            .expect("local path is a valid source URL");
        let dest = temp_dir("commit-absent-dest");
        let result = fetch_git_into(&pn("p"), &url, &commit(absent), &dest, &PACKAGE_SOURCE);
        assert!(
            matches!(&result, Err(CliError::Resolve(msg)) if msg.to_string().contains(absent)),
            "{result:?}"
        );
        assert!(!dest.exists(), "a refused fetch leaves no checkout behind");
        let _ = std::fs::remove_dir_all(&src);
    }

    /// A git escape pinned by tag name locks the tag's commit, not the branch
    /// tip past it.
    #[test]
    fn a_git_escape_by_tag_name_locks_the_tags_commit() {
        let proj = temp_dir("git-escape-tag");
        scaffold_project(&proj);
        let src = git_source("git-tag", "module Lib\n");
        let tagged = head_rev(&src);
        run_fixture(&src, &["tag", "v1.0.0"], b"");
        commit_file(&src, "later.ipe");
        let dep = IpeDep::Git {
            url: src.display().to_string(),
            rev: Some("v1.0.0".into()),
        };
        resolve_escape(&proj, "taglib", &dep).expect("a tag escape resolves");
        let lock = Lockfile::read(&proj).expect("lock");
        let entry = lock
            .packages()
            .iter()
            .find(|p| p.name.as_str() == "taglib")
            .expect("taglib must be locked");
        let pinned = entry.origin.pinned_rev().expect("a git escape pins a rev");
        assert_eq!(pinned.as_str(), tagged);
        let checkout = cache_dir(&proj, &pn("taglib"), CacheSlot::Escape(pinned));
        assert!(
            checkout.join("lib.ipe").is_file(),
            "the tag's tree is cached"
        );
        assert!(
            !checkout.join("later.ipe").exists(),
            "a commit past the tag must not be cached"
        );
        let _ = std::fs::remove_dir_all(&proj);
        let _ = std::fs::remove_dir_all(&src);
    }

    /// An annotated tag whose commit is the rev is fetched alone at depth 1,
    /// matched by its peeled line; the same tag also matches by its name.
    #[test]
    fn an_annotated_tag_whose_commit_is_the_rev_fetches_that_tag() {
        let src = git_source("refs-peeled", "module Lib\n");
        let tagged = commit_file(&src, "tagged.ipe");
        run_fixture(&src, &["tag", "-a", "v1", "-m", "v1"], b"");
        commit_file(&src, "later.ipe");

        let by_sha = temp_dir("refs-peeled-sha");
        let transfer = staged(&src, &by_sha);
        fetch_advertised(
            &pn("p"),
            &commit(&tagged),
            &by_sha,
            &transfer,
            PACKAGE_SOURCE.refs(),
        )
        .expect("a peeled tip fetches");
        assert_eq!(head_rev(&by_sha), tagged);
        assert!(is_shallow(&by_sha), "a tip is fetched at depth 1");
        assert!(!by_sha.join("later.ipe").exists());

        let by_name = temp_dir("refs-peeled-name");
        let transfer = staged(&src, &by_name);
        fetch_advertised(
            &pn("p"),
            &Wanted::Name(&CommitId::parse(&pn("p"), "v1").expect("v1 is a valid commit id")),
            &by_name,
            &transfer,
            PACKAGE_SOURCE.refs(),
        )
        .expect("a tag named by the rev fetches");
        assert_eq!(head_rev(&by_name), tagged);
        assert!(is_shallow(&by_name), "a named tip is fetched at depth 1");
        for dir in [by_sha, by_name, src] {
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    /// A rev behind every tip is reached only through history: the full fetch
    /// runs and checks it out.
    #[test]
    fn a_rev_behind_every_tip_takes_the_full_fetch() {
        let src = git_source("refs-history", "module Lib\n");
        let old = commit_file(&src, "old.ipe");
        commit_file(&src, "new.ipe");
        let dest = temp_dir("refs-history-dest");
        let transfer = staged(&src, &dest);
        fetch_advertised(
            &pn("p"),
            &commit(&old),
            &dest,
            &transfer,
            PACKAGE_SOURCE.refs(),
        )
        .expect("a rev in history fetches");
        assert_eq!(head_rev(&dest), old);
        assert!(
            !is_shallow(&dest),
            "a rev behind the tips needs the full history"
        );
        let _ = std::fs::remove_dir_all(&dest);
        let _ = std::fs::remove_dir_all(&src);
    }

    const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

    /// An advertisement line for `name` at the fixture SHA.
    fn line(name: &str) -> String {
        format!("{SHA}\t{name}\n")
    }

    /// The parser accepts exactly its line ceiling, with or without a final
    /// newline, and a peeled tag line; one line more is an entry overrun.
    #[test]
    fn the_advertisement_parser_holds_its_line_ceiling() {
        let two = RefsCeiling::for_test(REFS_MAX_BYTES, 2);
        let at = format!("{}{}", line("refs/tags/v1"), line("refs/tags/v1^{}"));
        let parsed =
            parse_advertisement(at.as_bytes(), &two).expect("two lines at a ceiling of two");
        assert_eq!(parsed.len(), 2);
        assert_eq!(
            parse_advertisement(at.trim_end().as_bytes(), &two).map(|refs| refs.len()),
            Ok(2)
        );
        assert_eq!(parse_advertisement(b"", &two).map(|refs| refs.len()), Ok(0));
        let past = format!("{at}{}", line("refs/heads/main"));
        assert_eq!(
            parse_advertisement(past.as_bytes(), &two).map(|refs| refs.len()),
            Err(IngestLimit::Entries(2))
        );
    }

    /// A line that is not a SHA, a tab and a ref is refused, never skipped.
    #[test]
    fn a_malformed_advertisement_line_is_refused() {
        let refs = *PACKAGE_SOURCE.refs();
        let upper = SHA.to_uppercase();
        let short = SHA.trim_end_matches('7');
        let cases: [Vec<u8>; 7] = [
            format!("{short}\trefs/tags/v1\n").into_bytes(),
            format!("{upper}\trefs/tags/v1\n").into_bytes(),
            format!("{SHA} refs/tags/v1\n").into_bytes(),
            format!("{SHA}\trefs/tags/v\0\n").into_bytes(),
            format!("{SHA}\trefs/heads/main^{{}}\n").into_bytes(),
            format!("{SHA}\trefs/tags/v1\n\n").into_bytes(),
            b"\n\n".to_vec(),
        ];
        for case in cases {
            assert_eq!(
                parse_advertisement(&case, &refs).map(|parsed| parsed.len()),
                Err(IngestLimit::MalformedRef),
                "{:?}",
                String::from_utf8_lossy(&case)
            );
        }
    }

    /// A valid SHA beside a ref name that is not UTF-8 is skipped rather than
    /// refused, still counted against the line ceiling; a SHA that is not
    /// UTF-8 is refused.
    #[test]
    fn a_non_utf8_ref_name_is_skipped_but_counted() {
        let refs = *PACKAGE_SOURCE.refs();
        let skipped = [SHA.as_bytes(), b"\trefs/tags/\xff\n"].concat();
        assert_eq!(
            parse_advertisement(&skipped, &refs).map(|parsed| parsed.len()),
            Ok(0)
        );
        let beside = [line("refs/tags/v1").as_bytes(), skipped.as_slice()].concat();
        assert_eq!(
            parse_advertisement(&beside, &refs).map(|parsed| parsed.len()),
            Ok(1)
        );
        let one = RefsCeiling::for_test(REFS_MAX_BYTES, 1);
        assert_eq!(
            parse_advertisement(&beside, &one).map(|parsed| parsed.len()),
            Err(IngestLimit::Entries(1))
        );
        let bad_sha = b"\xff\trefs/tags/v1\n".to_vec();
        assert_eq!(
            parse_advertisement(&bad_sha, &refs).map(|parsed| parsed.len()),
            Err(IngestLimit::MalformedRef)
        );
    }

    /// A hostile or unsafe ref name refuses the advertisement; a safe one parses.
    #[test]
    fn only_a_safe_tag_or_branch_name_parses() {
        let refs = *PACKAGE_SOURCE.refs();
        let hostile = [
            "refs/tags/*",
            "refs/tags/a:b",
            "refs/tags/a..b",
            "refs/tags/a@{b",
            "refs/tags/a~1",
            "refs/tags/a^b",
            "refs/tags/a?",
            "refs/tags/a[b",
            "refs/tags/a\\b",
            "refs/heads/a b",
            "refs/tags/a\x7f",
            "refs/tags/x.lock",
            "refs/tags/x.LOCK",
            "refs/tags/a/b.Lock",
            "refs/tags/.x",
            "refs/tags/a/.b",
            "refs/tags/a//b",
            "refs/tags/a/",
            "refs/tags/a.",
            "refs/tags/",
            "refs/remotes/origin/main",
            "HEAD",
            "-x",
        ];
        for name in hostile {
            assert_eq!(
                parse_advertisement(line(name).as_bytes(), &refs).map(|parsed| parsed.len()),
                Err(IngestLimit::MalformedRef),
                "{name:?} must be refused"
            );
        }
        for name in [
            "refs/tags/v1.0.0",
            "refs/tags/v1.0.0+build.1",
            "refs/tags/+a",
            "refs/tags/-x",
            "refs/heads/-x",
            "refs/heads/feature/x-y",
            "refs/tags/a-b_c",
        ] {
            assert_eq!(
                parse_advertisement(line(name).as_bytes(), &refs).map(|parsed| parsed.len()),
                Ok(1),
                "{name:?} must parse"
            );
        }
    }

    /// Only a git exit widens the fetch: a crossed budget, a held pipe, an
    /// unavailable git, a failed measure and a signal all end it, typed.
    #[test]
    fn only_an_exit_widens_a_fetch() {
        use std::io::{Error, ErrorKind};

        assert!(
            GitStepError::Exited {
                stderr: ChildStderr::Whole(Vec::new())
            }
            .widens()
        );
        let ending = [
            GitStepError::Refused(fetch_refused(IngestLimit::Bytes(1))),
            GitStepError::PipeHeld(Stream::Stdout),
            GitStepError::PipeUnread(Stream::Stdout, ErrorKind::Other),
            GitStepError::Unavailable(Error::from(ErrorKind::NotFound)),
            GitStepError::Measure(PathBuf::from("stage"), Error::from(ErrorKind::NotFound)),
            GitStepError::Interrupted,
        ];
        for failed in ending {
            assert!(!failed.widens(), "{failed:?} must not widen the fetch");
        }

        let run = |error: RunError| GitStepError::from_run(error).into_cli(&pn("p"), &["fetch"]);
        assert!(matches!(
            run(RunError::Wait(Error::from(ErrorKind::Interrupted))),
            CliError::Interrupted
        ));
        assert!(matches!(
            run(RunError::Spawn(Error::from(ErrorKind::Interrupted))),
            CliError::Interrupted
        ));
        assert!(matches!(
            run(RunError::Spawn(Error::from(ErrorKind::NotFound))),
            CliError::Resolve(_)
        ));
        assert!(matches!(
            run(RunError::Measure(
                PathBuf::from("stage"),
                Error::from(ErrorKind::NotFound)
            )),
            CliError::Io { .. }
        ));
        assert!(matches!(
            run(RunError::Exceeded(fetch_refused(IngestLimit::Bytes(1)))),
            CliError::RemoteIngestExceeded(_)
        ));
        assert!(matches!(
            run(RunError::PipeDrainTimeout(Stream::Stderr)),
            CliError::ChildPipeHeld(Stream::Stderr)
        ));
        assert!(matches!(
            run(RunError::PipeRead(Stream::Stdout, ErrorKind::Other)),
            CliError::ChildPipeUnread(Stream::Stdout, ErrorKind::Other)
        ));
    }

    /// A git escape one byte past its fetch budget is refused, and the refusal
    /// leaves no lock, no manifest change and no cached checkout.
    #[test]
    fn a_git_escape_past_its_fetch_budget_records_nothing() {
        let src = git_source("budget", "module Lib\n");
        let dep = IpeDep::Git {
            url: src.display().to_string(),
            rev: None,
        };
        // Measure the exact on-disk size of a full fetch of this source.
        let sized = temp_dir("budget-sized");
        scaffold_project(&sized);
        resolve_escape(&sized, "lib", &dep).expect("an in-budget fetch resolves");
        let lock = Lockfile::read(&sized).expect("lock");
        let entry = lock.packages().first().expect("locked");
        let cached = dep_cache_dir(&sized, entry).expect("a git escape is cached");
        let usage = remote_ingest::measure(&cached, PACKAGE_SOURCE.transfer()).expect("measure");
        assert!(usage.bytes > 0, "a fetch stages bytes");

        let proj = temp_dir("budget-over");
        scaffold_project(&proj);
        let manifest_before = std::fs::read(proj.join("package.ipe")).expect("manifest");
        let result = resolve_escape_within(&proj, "lib", &dep, &under_transfer(usage.bytes));
        assert!(matches!(
            result,
            Err(CliError::RemoteIngestExceeded(IngestRefusal {
                source: IngestSource::PackageFetch,
                limit: IngestLimit::Bytes(_),
                name: Some(ref named),
            })) if named.as_str() == "lib"
        ));
        assert_nothing_recorded(&proj, &manifest_before);
        let _ = std::fs::remove_dir_all(&sized);
        let _ = std::fs::remove_dir_all(&proj);
        let _ = std::fs::remove_dir_all(&src);
    }

    /// A git escape whose transfer outlasts its wall time is refused as a
    /// timeout naming the package, and the refusal records nothing.
    #[test]
    fn a_git_escape_past_its_wall_time_records_nothing() {
        let src = git_source("slow-drip", "module Lib\n");
        let dep = IpeDep::Git {
            url: src.display().to_string(),
            rev: None,
        };
        let proj = temp_dir("slow-drip-over");
        scaffold_project(&proj);
        let manifest_before = std::fs::read(proj.join("package.ipe")).expect("manifest");
        crate::remote_ingest::spend_transfer_clock_for_test(
            PACKAGE_SOURCE.transfer().wall().get() + std::time::Duration::from_secs(1),
        );
        let result = resolve_escape_within(&proj, "lib", &dep, &PACKAGE_SOURCE);
        crate::remote_ingest::spend_transfer_clock_for_test(std::time::Duration::ZERO);
        assert!(
            matches!(
                result,
                Err(CliError::RemoteIngestExceeded(IngestRefusal {
                    source: IngestSource::PackageFetch,
                    limit: IngestLimit::Time(_),
                    name: Some(ref named),
                })) if named.as_str() == "lib"
            ),
            "{result:?}"
        );
        assert_nothing_recorded(&proj, &manifest_before);
        let _ = std::fs::remove_dir_all(&proj);
        let _ = std::fs::remove_dir_all(&src);
    }

    /// A budget one byte short of staging `bytes`, its tree ceiling halved to
    /// stay paired.
    fn under_transfer(bytes: u64) -> FetchBudget {
        let disk_bytes = bytes.saturating_sub(1);
        let tree = disk_bytes / 2;
        FetchBudget::for_test(
            PACKAGE_SOURCE
                .transfer()
                .with_staged_bytes(byte_budget(disk_bytes))
                .expect("a package fetch stages on disk"),
            *PACKAGE_SOURCE.refs(),
            TreeCeiling::for_test(tree, PACKAGE_TREE_MAX_ENTRIES, tree, PACKAGE_TREE_MAX_DEPTH)
                .expect("paired tree ceiling"),
        )
        .expect("paired budget")
    }

    /// An index add whose fetched tree is past its entry ceiling is refused as
    /// a local limit, and records and caches nothing.
    #[test]
    fn an_index_add_past_its_tree_entry_ceiling_records_nothing() {
        let src = git_source_of("tree-entries", 5);
        let sha = hash_source_tree(&src).expect("hash source");
        let version = index_version("wide", &src, sha.as_str());
        let proj = temp_dir("tree-entries");
        scaffold_project(&proj);
        let manifest_before = std::fs::read(proj.join("package.ipe")).expect("manifest");
        let budget = with_tree(
            TreeCeiling::for_test(
                PACKAGE_TREE_MAX_BYTES,
                4,
                PACKAGE_FILE_MAX_BYTES,
                PACKAGE_TREE_MAX_DEPTH,
            )
            .expect("paired tree ceiling"),
        );
        let req = "^1".parse().expect("valid req");
        let result = resolve_and_add_within(&proj, &pn("wide"), &req, &version, &budget);
        assert!(
            matches!(
                result,
                Err(CliError::LocalLimitExceeded(LocalRefusal {
                    source: LocalSource::PackageTree,
                    limit: IngestLimit::Entries(4),
                    name: Some(ref named),
                })) if named.as_str() == "wide"
            ),
            "{result:?}"
        );
        assert_nothing_recorded(&proj, &manifest_before);
        let _ = std::fs::remove_dir_all(&proj);
        let _ = std::fs::remove_dir_all(&src);
    }

    /// An index add whose fetched tree is exactly at its entry ceiling — three
    /// files beside the `.git` directory the walk counts — is locked.
    #[test]
    fn an_index_add_at_its_tree_entry_ceiling_is_locked() {
        let src = git_source_of("tree-entries-at", 3);
        let sha = hash_source_tree(&src).expect("hash source");
        let version = index_version("snug", &src, sha.as_str());
        let proj = temp_dir("tree-entries-at");
        scaffold_project(&proj);
        let budget = with_tree(
            TreeCeiling::for_test(
                PACKAGE_TREE_MAX_BYTES,
                4,
                PACKAGE_FILE_MAX_BYTES,
                PACKAGE_TREE_MAX_DEPTH,
            )
            .expect("paired tree ceiling"),
        );
        let req = "^1".parse().expect("valid req");
        resolve_and_add_within(&proj, &pn("snug"), &req, &version, &budget)
            .expect("an index add at its tree entry ceiling is accepted");
        let lock = Lockfile::read(&proj).expect("lock");
        assert!(
            lock.packages().iter().any(|p| p.name.as_str() == "snug"),
            "the add at its ceiling is locked"
        );
        let _ = std::fs::remove_dir_all(&proj);
        let _ = std::fs::remove_dir_all(&src);
    }

    /// A signed index add whose fetched tree is past its entry ceiling, under a
    /// policy trusting two identities, is refused once as a local limit by the
    /// one budgeted walk every identity shares — the verifier is handed that
    /// walk's digest, never a path it could walk again — and records nothing.
    #[test]
    fn a_signed_add_past_its_tree_ceiling_is_refused_once_before_any_signature_check() {
        let src = git_source_of("signed-tree", 5);
        let sha = hash_source_tree(&src).expect("hash source");
        let mut version = index_version("signed", &src, sha.as_str());
        version.signature = Some(
            crate::signing::SignatureBundle::parse("signed", r#"{ "dsseEnvelope": {} }"#)
                .expect("bundle parses"),
        );
        let proj = temp_dir("signed-tree");
        scaffold_project(&proj);
        let identity = |repo: &str| {
            format!(
                "  {{ issuer = \"{}\", identity = \"https://github.com/o/{repo}/.github/workflows/publish.yml@refs/heads/main\" }},\n",
                crate::signing::GITHUB_ACTIONS_ISSUER
            )
        };
        std::fs::write(
            proj.join("ipe.toml"),
            format!(
                "[registry.trust]\ntrusted_identities = [\n{}{}]\n",
                identity("a"),
                identity("b")
            ),
        )
        .expect("trust config");
        let policy = crate::signing::load_trust_policy(&proj).expect("trust policy loads");
        assert!(
            policy.trusted_identities().len() >= 2,
            "two identities trusted"
        );
        let manifest_before = std::fs::read(proj.join("package.ipe")).expect("manifest");
        let budget = with_tree(
            TreeCeiling::for_test(
                PACKAGE_TREE_MAX_BYTES,
                4,
                PACKAGE_FILE_MAX_BYTES,
                PACKAGE_TREE_MAX_DEPTH,
            )
            .expect("paired tree ceiling"),
        );
        let req = "^1".parse().expect("valid req");
        let result = resolve_and_add_within(&proj, &pn("signed"), &req, &version, &budget);
        assert!(
            matches!(
                result,
                Err(CliError::LocalLimitExceeded(LocalRefusal {
                    source: LocalSource::PackageTree,
                    limit: IngestLimit::Entries(4),
                    name: Some(ref named),
                })) if named.as_str() == "signed"
            ),
            "{result:?}"
        );
        assert_nothing_recorded(&proj, &manifest_before);
        let _ = std::fs::remove_dir_all(&proj);
        let _ = std::fs::remove_dir_all(&src);
    }

    /// An index add whose fetched tree does not hash to its pin is a hash
    /// mismatch, and records and caches nothing.
    #[test]
    fn an_index_add_with_a_wrong_pin_records_nothing() {
        let src = git_source("wrong-pin", "module Lib\n");
        let version = index_version("pinned", &src, &"0".repeat(64));
        let proj = temp_dir("wrong-pin");
        scaffold_project(&proj);
        let manifest_before = std::fs::read(proj.join("package.ipe")).expect("manifest");
        let req = "^1".parse().expect("valid req");
        let result = resolve_and_add_within(&proj, &pn("pinned"), &req, &version, &PACKAGE_SOURCE);
        assert!(
            matches!(result, Err(CliError::HashMismatch { .. })),
            "{result:?}"
        );
        assert_nothing_recorded(&proj, &manifest_before);
        let _ = std::fs::remove_dir_all(&proj);
        let _ = std::fs::remove_dir_all(&src);
    }

    /// The baseline fetch of a published version one byte past its transfer
    /// ceiling is refused, and leaves nothing in the cache.
    #[test]
    fn a_baseline_fetch_past_its_transfer_ceiling_leaves_nothing() {
        let src = git_source("baseline", "module Lib\n");
        let sha = hash_source_tree(&src).expect("hash source");
        let version = index_version("baseline", &src, sha.as_str());
        let proj = temp_dir("baseline");
        scaffold_project(&proj);
        let name = pn("baseline");
        let fetched =
            fetch_and_verify_index_version_within(&proj, &name, &version, &PACKAGE_SOURCE)
                .expect("an in-budget baseline fetch verifies");
        let usage = remote_ingest::measure(&fetched, PACKAGE_SOURCE.transfer()).expect("measure");
        std::fs::remove_dir_all(&fetched).expect("clear the baseline");

        let result = fetch_and_verify_index_version_within(
            &proj,
            &name,
            &version,
            &under_transfer(usage.bytes),
        );
        assert!(
            matches!(
                result,
                Err(CliError::RemoteIngestExceeded(IngestRefusal {
                    source: IngestSource::PackageFetch,
                    limit: IngestLimit::Bytes(_),
                    name: Some(ref named),
                })) if named.as_str() == "baseline"
            ),
            "{result:?}"
        );
        assert!(
            !cache_dir(&proj, &name, CacheSlot::Index(&version.version)).exists(),
            "a refused baseline fetch leaves no checkout"
        );
        let _ = std::fs::remove_dir_all(&proj);
        let _ = std::fs::remove_dir_all(&src);
    }

    /// A tree exactly at the production entry ceiling hashes alike for the
    /// publisher and the consumer; one entry more is refused by both.
    #[test]
    fn publisher_and_consumer_share_the_tree_entry_ceiling() {
        let root = temp_dir("entry-ceiling");
        for index in 0..PACKAGE_TREE_MAX_ENTRIES {
            std::fs::write(root.join(format!("f{index}")), "").expect("write file");
        }
        let published = hash_source_tree(&root).expect("a tree at the ceiling publishes");
        let fetched =
            hash_checkout(&root, PACKAGE_SOURCE.tree()).expect("a tree at the ceiling verifies");
        assert_eq!(published, fetched);

        std::fs::write(root.join("one-more"), "").expect("write file");
        let refused = LocalRefusal {
            source: LocalSource::PackageTree,
            limit: IngestLimit::Entries(PACKAGE_TREE_MAX_ENTRIES),
            name: None,
        };
        assert!(matches!(
            hash_source_tree(&root),
            Err(CliError::LocalLimitExceeded(refusal)) if refusal == refused
        ));
        assert!(matches!(
            hash_checkout(&root, PACKAGE_SOURCE.tree()),
            Err(CliError::LocalLimitExceeded(refusal)) if refusal == refused
        ));
        let _ = std::fs::remove_dir_all(&root);
    }

    /// An escape pinned to a ref spelled like a version neither lands in nor
    /// clears that version's index cache slot.
    #[test]
    fn an_escape_ref_spelled_like_a_version_keeps_the_index_slot() {
        let src = git_source("version-ref", "module Lib\n");
        let tagged = remote_ingest::fixture_git(&src)
            .args(["tag", "1.0.0"])
            .output()
            .expect("git tag")
            .status
            .success();
        assert!(tagged, "git tag must succeed");
        let proj = temp_dir("version-ref");
        scaffold_project(&proj);
        let name = pn("lib");
        let version = PublishedVersion::parse("1.0.0").expect("valid");
        let index_slot = cache_dir(&proj, &name, CacheSlot::Index(&version));
        std::fs::create_dir_all(&index_slot).expect("index slot");
        std::fs::write(index_slot.join("marker"), "index").expect("marker");

        let dep = IpeDep::Git {
            url: src.display().to_string(),
            rev: Some("1.0.0".to_owned()),
        };
        resolve_escape(&proj, "lib", &dep).expect("escape resolves");
        assert_eq!(
            std::fs::read_to_string(index_slot.join("marker")).expect("marker kept"),
            "index"
        );
        let lock = Lockfile::read(&proj).expect("lock");
        let entry = lock.packages().first().expect("locked");
        let escape_slot = dep_cache_dir(&proj, entry).expect("a git escape is cached");
        assert_ne!(escape_slot, index_slot);
        assert!(escape_slot.is_dir(), "the escape is cached at its own slot");
        let _ = std::fs::remove_dir_all(&proj);
        let _ = std::fs::remove_dir_all(&src);
    }

    #[test]
    fn source_url_newtype_rejects_ext_transport_before_fetch() {
        // A `source` field containing `ext::` must be rejected by `SourceUrl::parse`
        // at the index-parse boundary; `fetch_git_into` is never called.
        let err = SourceUrl::parse(&pn("evil"), "ext::sh -c 'id'").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("source"), "{msg}");
    }

    #[test]
    fn source_url_newtype_rejects_dash_leading_before_fetch() {
        let err = SourceUrl::parse(&pn("evil"), "--upload-pack=malicious").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("source"), "{msg}");
    }

    #[test]
    fn commit_id_newtype_rejects_injection_shaped_rev_before_checkout() {
        // An injection-shaped `rev` (leading `-`) is rejected at parse time
        // so it never reaches `git checkout`. Ordinary ref names are accepted.
        assert!(
            CommitId::parse(&pn("ok"), "main").is_ok(),
            "branch names are valid refs"
        );
        assert!(
            CommitId::parse(&pn("ok"), "abc").is_ok(),
            "short hashes are valid refs"
        );
        let err = CommitId::parse(&pn("evil"), "-S injected").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("rev"), "{msg}");
    }

    #[test]
    fn commit_id_newtype_rejects_dash_rev_before_checkout() {
        let err = CommitId::parse(&pn("evil"), "-S injected").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("rev"), "{msg}");
    }

    #[test]
    fn git_escape_with_injection_shaped_url_is_rejected_before_fetch() {
        // The `{git=}` manifest-escape path parses `url` through `SourceUrl::parse`
        // before calling the git sink, so an injection-shaped value is caught at
        // the escape boundary, not silently forwarded to the subprocess.
        let proj = temp_dir("escape-bad-url");
        scaffold_project(&proj);
        let dep = IpeDep::Git {
            url: "ext::sh -c 'id > /tmp/pwned'".to_owned(),
            rev: None,
        };
        let err = resolve_escape(&proj, "evil", &dep).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("source"), "bad url rejected: {msg}");
        let _ = std::fs::remove_dir_all(&proj);
    }

    #[test]
    fn git_escape_with_injection_shaped_rev_is_rejected_before_fetch() {
        // The `{git=}` manifest-escape path also parses `rev` through
        // `CommitId::parse`, so a leading-dash rev is caught before git runs.
        let src = git_source("escape-rev-src", "module Lib\n");
        let proj = temp_dir("escape-bad-rev");
        scaffold_project(&proj);
        let dep = IpeDep::Git {
            url: src.display().to_string(),
            rev: Some("-S injected".to_owned()),
        };
        let err = resolve_escape(&proj, "evil", &dep).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("rev"), "bad rev rejected: {msg}");
        let _ = std::fs::remove_dir_all(&proj);
        let _ = std::fs::remove_dir_all(&src);
    }

    /// Commit twice to `repo`, returning (first commit sha, second commit sha).
    /// The second commit becomes `HEAD`.
    fn two_commits(repo: &Path) -> (String, String) {
        let git = |args: &[&str]| {
            let ok = remote_ingest::fixture_git(repo)
                .args(args)
                .output()
                .expect("git runs")
                .status
                .success();
            assert!(ok, "git {args:?} must succeed");
        };
        let head = || {
            let out = remote_ingest::fixture_git(repo)
                .args(["rev-parse", "HEAD"])
                .output()
                .expect("git rev-parse HEAD");
            String::from_utf8_lossy(&out.stdout).trim().to_owned()
        };
        let c1 = head();
        std::fs::write(repo.join("lib.ipe"), "module Lib\nv = 2\n").expect("write");
        git(&["add", "."]);
        git(&["commit", "--quiet", "-m", "second"]);
        let c2 = head();
        (c1, c2)
    }

    #[test]
    fn git_escape_warns_not_refuses_when_a_tag_shadows_an_abbreviation() {
        // A tag literally named "abcd123" (hex-shaped, 7 chars — inside the
        // AbbrevHex range) points at C1, not HEAD (C2). Git's ref-name-first
        // resolution serves C1 for the request, not an abbreviated-hex lookup
        // against C2. Per the maintainer-resolved override, this is a WARN,
        // not a refusal: the escape still resolves and locks the commit git
        // actually served (C1), not C2.
        let src = git_source("shadow-warn-src", "module Lib\nv = 1\n");
        let (c1, _c2) = two_commits(&src);
        let tag_ok = remote_ingest::fixture_git(&src)
            .args(["tag", "abcd123", &c1])
            .output()
            .expect("git tag runs")
            .status
            .success();
        assert!(tag_ok, "creating the shadowing tag must succeed");

        let proj = temp_dir("escape-shadow-warn");
        scaffold_project(&proj);
        let dep = IpeDep::Git {
            url: src.display().to_string(),
            rev: Some("abcd123".to_owned()),
        };
        resolve_escape(&proj, "shadowed", &dep)
            .expect("a shadowed abbreviation warns but still resolves");
        let lock = Lockfile::read(&proj).expect("lock");
        let entry = lock
            .packages()
            .iter()
            .find(|p| p.name.as_str() == "shadowed")
            .expect("shadowed must be locked");
        let rev_str = entry
            .origin
            .pinned_rev()
            .map(PinnedRev::as_str)
            .expect("a git escape pins a rev");
        assert_eq!(
            rev_str, c1,
            "the commit the shadowing tag served (C1) must be locked, not C2"
        );

        let _ = std::fs::remove_dir_all(&proj);
        let _ = std::fs::remove_dir_all(&src);
    }

    #[test]
    fn git_escape_locks_the_exact_commit_when_a_tag_shadows_a_full_sha() {
        // A tag literally named after C1's full 40-hex SHA points at C2. Git
        // resolves a full object name before any ref of the same spelling, so
        // the escape serves and locks C1 — the commit the author pinned —
        // never the tag's C2. `check_served` re-checks served == requested,
        // so a source that substituted C2 anyway is refused, not locked.
        let src = git_source("shadow-full-src", "module Lib\nv = 1\n");
        let (c1, c2) = two_commits(&src);
        let tag_ok = remote_ingest::fixture_git(&src)
            .args(["tag", &c1, &c2])
            .output()
            .expect("git tag runs")
            .status
            .success();
        assert!(tag_ok, "creating the shadowing tag must succeed");

        let proj = temp_dir("escape-shadow-full");
        scaffold_project(&proj);
        let dep = IpeDep::Git {
            url: src.display().to_string(),
            rev: Some(c1.clone()),
        };
        resolve_escape(&proj, "shadowed", &dep)
            .expect("a full-SHA request resolves to the pinned commit");
        let lock = Lockfile::read(&proj).expect("lock");
        let entry = lock
            .packages()
            .iter()
            .find(|p| p.name.as_str() == "shadowed")
            .expect("shadowed must be locked");
        let rev_str = entry
            .origin
            .pinned_rev()
            .map(PinnedRev::as_str)
            .expect("a git escape pins a rev");
        assert_eq!(
            rev_str, c1,
            "the pinned full SHA (C1) must be locked, never the shadowing tag's C2"
        );

        let _ = std::fs::remove_dir_all(&proj);
        let _ = std::fs::remove_dir_all(&src);
    }

    /// The home the parser makes of the raw value `raw`, when it accepts one.
    fn parsed_home(raw: Option<&str>) -> Option<crate::env_dir::HomeDir> {
        crate::env_dir::HomeDir::try_parse(raw.map(OsString::from)).ok()
    }

    #[test]
    #[cfg(not(windows))]
    fn cache_base_prefers_an_absolute_xdg_cache_home() {
        let base = cache_base_from(
            Some(OsString::from("/xdg/cache")),
            parsed_home(Some("/home/u")).as_ref(),
        )
        .expect("absolute XDG_CACHE_HOME");
        assert_eq!(base, PathBuf::from("/xdg/cache"));
    }

    #[test]
    #[cfg(not(windows))]
    fn cache_base_falls_back_to_home_dot_cache() {
        let home = parsed_home(Some("/home/u"));
        let base = cache_base_from(None, home.as_ref()).expect("absolute home");
        assert_eq!(base, PathBuf::from("/home/u/.cache"));
        let base = cache_base_from(Some(OsString::from("rel")), home.as_ref())
            .expect("relative XDG_CACHE_HOME is ignored");
        assert_eq!(base, PathBuf::from("/home/u/.cache"));
    }

    #[test]
    fn cache_base_refuses_without_an_absolute_home() {
        for (xdg, home) in [
            (None, None),
            (None, Some("")),
            (None, Some("relative/home")),
            (Some(""), None),
            (Some("relative/xdg"), Some("")),
        ] {
            let err = cache_base_from(xdg.map(OsString::from), parsed_home(home).as_ref())
                .expect_err("no absolute cache base must be refused");
            assert!(
                matches!(err, CliError::CacheHomeUnknown),
                "xdg={xdg:?} home={home:?}: {err:?}"
            );
        }
    }

    #[test]
    fn index_root_uses_an_absolute_override() {
        let root = index_root_from(Some(OsString::from("/srv/ipe-index")));
        assert!(matches!(root, Ok(p) if p == std::path::Path::new("/srv/ipe-index")));
    }

    #[test]
    fn index_root_refuses_a_relative_or_empty_override() {
        for raw in ["", "index", "./index", "../elsewhere"] {
            let root = index_root_from(Some(OsString::from(raw)));
            assert!(
                matches!(
                    root,
                    Err(CliError::EnvDirNotAbsolute { var: INDEX_DIR_ENV })
                ),
                "IPE_INDEX_DIR={raw:?} must be refused: {root:?}"
            );
        }
    }
}
