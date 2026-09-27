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
use std::process::Command;

use ipe_ir::Capability;

use crate::index::{self, CommitId, EntryVersion, PinnedRev, SourceUrl};
use crate::lockfile::{DepKind, LockedDep, LockedRev, Lockfile};
use crate::package_name::PackageName;
use crate::project::IpeDep;
use crate::{CliError, cache};

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
/// `git` fetch fails; [`CliError::HashMismatch`] if the fetched source's hash
/// does not equal the pinned hash; [`CliError::Io`] on a filesystem failure.
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

    // Trust-verification ordering INVARIANT: nothing is installed or recorded
    // until BOTH the publisher signature (if any) and the pinned content hash
    // have verified against the FETCHED tree. The signature's digest-binding
    // check hashes that tree (the signed subject digest must equal the tree
    // hash), so it necessarily runs after the fetch; the pinned-`sha256` check
    // does too. A rejected signature OR a hash mismatch aborts here, before
    // `write_records`, so no unverified bytes are ever trusted.
    let policy = crate::signing::load_trust_policy(project_root)?;
    let verifier = signature_verifier();

    let checkout = fetch_source(
        project_root,
        &package_name,
        &version.version.to_string(),
        version,
    )?;

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
        &version.sha256,
        &checkout,
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

    verify_hash(name, &checkout, &version.sha256)?;

    let locked = LockedDep {
        name: name.to_owned(),
        version: version.version.clone(),
        source: version.source.to_string(),
        rev: LockedRev::Pinned(version.rev.clone()),
        sha256: version.sha256.clone(),
        kind: DepKind::Index,
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
/// [`CliError::Io`] on a filesystem failure.
pub fn resolve_escape(project_root: &Path, name: &str, dep: &IpeDep) -> Result<(), CliError> {
    // Parse-don't-validate: gate the name into a safe path component here, at the
    // boundary, before it reaches any cache-directory join.
    let package_name = PackageName::parse(name)?;
    let (source, locked_rev, checkout) = match dep {
        IpeDep::Git { url, rev } => {
            // Parse-don't-validate: convert the raw manifest strings to typed
            // newtypes at this escape-path boundary before they reach the git
            // sink, so the sink cannot be called with an unvalidated value.
            let typed_url = SourceUrl::parse(name, url)?;
            // The requested ref (may be a branch or HEAD) is injection-gated
            // here but not yet an immutable pin.
            let raw_rev = rev.as_deref().unwrap_or("HEAD");
            let requested = CommitId::parse(name, raw_rev)?;
            // Fetch first into a temporary location keyed by the requested ref,
            // then resolve to the concrete SHA that names the exact commit.
            let checkout =
                fetch_git_requested(project_root, &package_name, &typed_url, &requested)?;
            let pinned = PinnedRev::resolve_in_checkout(name, &checkout, &requested)?;
            // Re-key the cache dir by the immutable SHA so fetch and verify
            // share the same key regardless of what ref was requested.
            let final_dest = escape_cache_dir(project_root, &package_name, &pinned);
            if checkout != final_dest {
                if final_dest.exists() {
                    std::fs::remove_dir_all(&final_dest).map_err(|e| CliError::Io {
                        path: final_dest.clone(),
                        source: e,
                    })?;
                }
                std::fs::rename(&checkout, &final_dest).map_err(|e| CliError::Io {
                    path: checkout.clone(),
                    source: e,
                })?;
            }
            (url.clone(), LockedRev::Pinned(pinned), final_dest)
        }
        IpeDep::Path(path) => {
            let resolved = if path.is_absolute() {
                path.clone()
            } else {
                project_root.join(path)
            };
            if !resolved.is_dir() {
                return Err(CliError::Resolve(format!(
                    "package `{name}`: path dependency `{}` does not exist",
                    resolved.display()
                )));
            }
            (path.display().to_string(), LockedRev::Local, resolved)
        }
        IpeDep::Index(_) => {
            return Err(CliError::Resolve(format!(
                "package `{name}`: an index dependency is resolved through `resolve_and_add`, \
                 not `resolve_escape`"
            )));
        }
    };

    let sha256 = hash_checkout(&checkout)?;
    // An escape has no published version; `0.0.0` marks "locked from an escape,
    // not the index" without inventing a version the source does not claim.
    let version = semver::Version::new(0, 0, 0);
    let locked = LockedDep {
        name: name.to_owned(),
        version,
        source,
        rev: locked_rev,
        sha256,
        kind: DepKind::Escape,
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

/// The default index checkout root when `IPE_INDEX_DIR` is unset.
///
/// The standard per-user location. Provisioning and populating this checkout is
/// a separate, deliberate outward-facing step; the resolver only reads it.
#[must_use]
pub fn default_index_root() -> PathBuf {
    // Mirror the build cache's home discovery so the index lives beside it.
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
        .unwrap_or_else(|| PathBuf::from(".ipe"));
    base.join("ipe").join("index")
}

/// The index checkout root: `IPE_INDEX_DIR` when set, else [`default_index_root`].
#[must_use]
pub fn index_root() -> PathBuf {
    std::env::var_os(INDEX_DIR_ENV).map_or_else(default_index_root, PathBuf::from)
}

/// The content hash of a source tree.
///
/// The same hash the index pins and the resolver verifies against. Exposed so a
/// caller (e.g. `ipe package publish`, or a test building a fixture index)
/// computes the exact hash the resolver expects, rather than reimplementing the
/// tree walk.
///
/// # Errors
/// [`CliError::Io`] if the tree cannot be walked or a file cannot be read.
pub fn hash_source_tree(root: &Path) -> Result<String, CliError> {
    hash_checkout(root)
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
/// [`CliError::Resolve`] on a `git` fetch failure; [`CliError::HashMismatch`]
/// when the fetched tree's hash does not equal the pinned hash; [`CliError::Io`]
/// on a filesystem failure.
pub fn fetch_and_verify_index_version(
    project_root: &Path,
    name: &str,
    version: &EntryVersion,
) -> Result<PathBuf, CliError> {
    let name = PackageName::parse(name)?;
    let checkout = fetch_source(project_root, &name, &version.version.to_string(), version)?;
    verify_hash(name.as_str(), &checkout, &version.sha256)?;
    Ok(checkout)
}

/// Re-verify that every locked Ipê dependency's cached source still hashes to the
/// pin recorded in `ipe.lock`.
///
/// The resolver verifies a fetched tree's hash at install ([`resolve_and_add`]);
/// this re-asserts the same integrity over the ALREADY-cached trees at publish
/// (the SP4 supply-chain check). A dependency whose cached bytes drifted from the
/// locked hash is a hard [`CliError::HashMismatch`] — the same verify-before-trust
/// boundary, never a warning. A dependency whose cache directory is absent is not
/// a mismatch (nothing was tampered; a build re-fetches it), so it is skipped.
///
/// # Errors
/// [`CliError::HashMismatch`] when a cached tree no longer matches its locked
/// hash; [`CliError::Io`] on a read failure; [`CliError::Resolve`] on a malformed
/// lockfile.
pub fn verify_lockfile_hashes(project_root: &Path) -> Result<(), CliError> {
    let lockfile = Lockfile::read(project_root)?;
    for dep in lockfile.packages() {
        let cache_dir = dep_cache_dir(project_root, dep)?;
        if !cache_dir.is_dir() {
            // Not cached locally — nothing to re-verify here; a build re-fetches
            // and re-verifies against this same pin.
            continue;
        }
        verify_hash(&dep.name, &cache_dir, &dep.sha256)?;
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

/// The package cache directory for one resolved `(name, version)` under the
/// project's `.ipe/packages/` tree.
///
/// Takes a validated [`PackageName`] so the name is a single, non-traversing
/// path component by construction — an unvalidated string cannot reach this
/// join and reroot the cache directory outside the project.
fn package_cache_dir(project_root: &Path, name: &PackageName, version: &str) -> PathBuf {
    project_root
        .join(crate::output_dir::CACHE_NAMESPACE_DIR)
        .join("packages")
        .join(format!("{}-{version}", name.as_str()))
}

/// The cache directory for a git escape dep, keyed by its pinned SHA.
///
/// This is the single SSOT for the escape cache key — both the fetch path and
/// the verify path call this so they can never key by different values.
fn escape_cache_dir(project_root: &Path, name: &PackageName, pinned: &PinnedRev) -> PathBuf {
    package_cache_dir(project_root, name, pinned.as_str())
}

/// The cache directory for a locked dep: git-escape deps key by their pinned
/// SHA, path-escape deps key by their sha256 (no git rev), and index deps key
/// by their version.
///
/// Both [`resolve_escape`]'s fetch path and [`verify_lockfile_hashes`]'s
/// verify path route through this function so the two dirs are provably equal.
/// The [`DepKind`] tag is the sole authority — field shapes are never re-derived.
///
/// # Errors
/// [`CliError::Resolve`] when the locked dep's name is not a valid package name
/// (a lockfile carrying a traversing name is refused rather than joined).
fn dep_cache_dir(project_root: &Path, dep: &LockedDep) -> Result<PathBuf, CliError> {
    let name = PackageName::parse(&dep.name)?;
    Ok(match dep.kind {
        DepKind::Escape => match &dep.rev {
            LockedRev::Pinned(sha) => package_cache_dir(project_root, &name, sha.as_str()),
            LockedRev::Local => package_cache_dir(project_root, &name, &dep.version.to_string()),
        },
        DepKind::Index => package_cache_dir(project_root, &name, &dep.version.to_string()),
    })
}

/// Fetch an index version's source at its pinned revision into the package
/// cache, returning the checkout directory.
fn fetch_source(
    project_root: &Path,
    name: &PackageName,
    version: &str,
    entry: &EntryVersion,
) -> Result<PathBuf, CliError> {
    let dest = package_cache_dir(project_root, name, version);
    fetch_git_into(name.as_str(), &entry.source, entry.rev.as_str(), &dest)?;
    Ok(dest)
}

/// Fetch a git escape's source at the requested ref into a temporary cache
/// location keyed by the requested ref string.
///
/// The returned path holds the checked-out tree; the caller resolves the
/// concrete SHA via [`PinnedRev::resolve_in_checkout`] and then renames the
/// directory to the SHA-keyed final location.
fn fetch_git_requested(
    project_root: &Path,
    name: &PackageName,
    url: &SourceUrl,
    requested: &CommitId,
) -> Result<PathBuf, CliError> {
    let dest = package_cache_dir(project_root, name, requested.as_str());
    fetch_git_into(name.as_str(), url, requested.as_str(), &dest)?;
    Ok(dest)
}

/// Clone `url` into `dest` and check out exactly `rev_str`. A pre-existing
/// `dest` is removed first so a re-add always fetches fresh.
///
/// `url` is a [`SourceUrl`] newtype — a raw unvalidated string cannot reach
/// this function. `rev_str` must come from either a [`CommitId`] or a
/// [`PinnedRev`] `.as_str()` — both newtypes guarantee no leading `-` so the
/// value is safe to pass to `git checkout` without `--`.
///
/// Defense-in-depth: `GIT_ALLOW_PROTOCOL` restricts transports (network +
/// `file`) even if a value somehow bypassed the parse boundary. `--` terminates
/// git's option list for clone so the URL is always a positional; checkout
/// omits `--` because in checkout it means "treat as a path, not a ref".
fn fetch_git_into(name: &str, url: &SourceUrl, rev_str: &str, dest: &Path) -> Result<(), CliError> {
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
    // Fetch the EXACT pinned object rather than cloning a branch and hoping it
    // contains the rev. `git init` + `fetch <sha>` pulls precisely the pinned
    // commit and its tree — cheaper than a full clone (a shallow, single-object
    // fetch) and independent of which branch (if any) currently points at it, so
    // a rev that has scrolled off its branch tip but is still ref-reachable is
    // still fetched. A server that refuses a raw-SHA want falls back to fetching
    // all refs, then checking the rev out from among them.
    //
    // `--` terminates git's option list where a URL is positional; for
    // `checkout` / `fetch <rev>` it is omitted so git treats the rev as a ref,
    // not a path — `rev_str` / `url` come from parse-validated newtypes with no
    // leading `-`.
    run_git(name, &["init", "--quiet"], dest, Some(dest))?;
    // `git remote add` has no `--` option terminator; the URL is a
    // parse-validated newtype (no leading `-`), so it is a safe trailing arg.
    run_git(
        name,
        &["remote", "add", "origin", url.as_str()],
        dest,
        Some(dest),
    )?;
    if run_git(
        name,
        &["fetch", "--quiet", "--depth", "1", "origin", rev_str],
        dest,
        Some(dest),
    )
    .is_err()
    {
        // Fallback for a server that disallows fetching an arbitrary SHA (e.g. a
        // local `file://` remote with `allowReachableSHA1InWant` off): pull every
        // branch AND tag, from which any ref-reachable rev — including one held
        // alive only by a tag — resolves.
        run_git(
            name,
            &["fetch", "--quiet", "--tags", "origin"],
            dest,
            Some(dest),
        )?;
        run_git(name, &["checkout", "--quiet", rev_str], dest, Some(dest))?;
        return Ok(());
    }
    // The exact-SHA fetch lands the commit at FETCH_HEAD.
    run_git(
        name,
        &["checkout", "--quiet", "FETCH_HEAD"],
        dest,
        Some(dest),
    )?;
    Ok(())
}

/// Run `git <args>`, treating a spawn failure or a non-zero exit as a
/// [`CliError::Resolve`] naming the package. When `cwd` is `Some`, git runs
/// there; otherwise the final arg of a `clone` is the destination path (git's
/// own convention), so `dest` is appended.
///
/// `GIT_ALLOW_PROTOCOL` is always set, restricting git to the same transports
/// the index parse boundary allows (network transports plus `file`).
/// `GIT_TERMINAL_PROMPT=0` ensures git never blocks waiting for interactive
/// credentials.
fn run_git(name: &str, args: &[&str], dest: &Path, cwd: Option<&Path>) -> Result<(), CliError> {
    let mut command = Command::new("git");
    command.args(args);
    if cwd.is_none() {
        // A `clone` takes the destination as its final positional argument.
        command.arg(dest);
    }
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    // Defense-in-depth: restrict git transports at the subprocess level so a
    // value that bypassed the parse boundary still cannot open an arbitrary
    // transport (`file` is included for local-path and file:// sources).
    // `GIT_TERMINAL_PROMPT=0` prevents credential prompts that would block a
    // non-interactive `ipe add`.
    command
        .env("GIT_ALLOW_PROTOCOL", "https:git:ssh:file")
        .env("GIT_TERMINAL_PROMPT", "0");
    let output = command
        .output()
        .map_err(|e| CliError::Resolve(format!("package `{name}`: could not run `git`: {e}")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(CliError::Resolve(format!(
            "package `{name}`: `git {}` failed: {}",
            args.join(" "),
            stderr.trim()
        )));
    }
    Ok(())
}

/// Hash the fetched source tree, mapping a walk/read failure to an IO error.
fn hash_checkout(checkout: &Path) -> Result<String, CliError> {
    cache::hash_tree(checkout).map_err(|(path, source)| CliError::Io { path, source })
}

/// Verify the fetched tree's content hash equals the index-pinned hash. This is
/// the verify-before-trust boundary: a mismatch is a hard error, so nothing
/// derived from an unverified fetch is ever written.
fn verify_hash(name: &str, checkout: &Path, expected: &str) -> Result<(), CliError> {
    let actual = hash_checkout(checkout)?;
    if actual == expected {
        Ok(())
    } else {
        Err(CliError::HashMismatch {
            package: name.to_owned(),
            expected: expected.to_owned(),
            actual,
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

#[cfg(test)]
mod tests {
    use super::{
        added_report, dep_cache_dir, escape_cache_dir, fetch_git_into, package_cache_dir,
        resolve_and_remove, resolve_escape, verify_hash, verify_lockfile_hashes,
    };
    use crate::cache;
    use crate::index::{CommitId, PinnedRev, SourceUrl};
    use crate::lockfile::{DepKind, LockedDep, LockedRev, Lockfile};
    use crate::package_name::PackageName;
    use crate::project::IpeDep;
    use ipe_ir::Capability;
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    fn temp_dir(_tag: &str) -> PathBuf {
        let sd = crate::scratch::ScratchDir::new("ipe-resolve-test").expect("scratch dir");
        let p = sd.path().to_path_buf();
        std::mem::forget(sd); // caller's explicit remove_dir_all handles cleanup
        p
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
            let ok = Command::new("git")
                .args(args)
                .current_dir(&repo)
                .env("GIT_AUTHOR_NAME", "t")
                .env("GIT_AUTHOR_EMAIL", "t@t")
                .env("GIT_COMMITTER_NAME", "t")
                .env("GIT_COMMITTER_EMAIL", "t@t")
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

    #[test]
    fn verify_hash_rejects_a_mismatch() {
        // The verify-before-trust boundary: a wrong expected hash is a hard
        // HashMismatch, never accepted.
        let dir = temp_dir("verify");
        std::fs::write(dir.join("a.txt"), "hello").expect("write");
        let real = cache::hash_tree(&dir).expect("hash");
        verify_hash("p", &dir, &real).expect("matching hash passes");
        let err = verify_hash("p", &dir, "not-the-hash").unwrap_err();
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
            .find(|p| p.name == "locallib")
            .expect("locked");
        assert!(!entry.sha256.is_empty(), "an escape still locks a hash");
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
            .find(|p| p.name == "remotelib")
            .expect("remotelib must be locked");
        // The locked rev must be an immutable 40-hex SHA, not the string "HEAD".
        let rev_str = entry.rev.as_str();
        assert_eq!(rev_str.len(), 40, "locked rev must be 40 chars");
        assert!(
            rev_str.chars().all(|c| c.is_ascii_hexdigit()),
            "locked rev must be lowercase hex"
        );
        assert_ne!(rev_str, "HEAD", "locked rev must not be the string HEAD");
        // The cached checkout must be keyed by the SHA, not by "HEAD".
        let remotelib = PackageName::parse("remotelib").expect("valid name");
        assert!(
            !package_cache_dir(&proj, &remotelib, "HEAD").exists(),
            "HEAD-keyed cache dir must not exist"
        );
        assert!(
            package_cache_dir(&proj, &remotelib, rev_str).exists(),
            "SHA-keyed cache dir must exist"
        );
        // Verify the locked SHA matches the fixture repo's actual HEAD.
        let actual_head = {
            let out = Command::new("git")
                .args(["rev-parse", "HEAD"])
                .current_dir(&src)
                .output()
                .expect("git rev-parse HEAD");
            String::from_utf8_lossy(&out.stdout).trim().to_owned()
        };
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
            .find(|p| p.name == "pinned")
            .expect("pinned locked")
            .clone();
        let sha1 = entry1.rev.as_str().to_owned();

        // Add C2 on the same branch — moves HEAD forward.
        let git = |args: &[&str]| {
            Command::new("git")
                .args(args)
                .current_dir(&src)
                .env("GIT_AUTHOR_NAME", "t")
                .env("GIT_AUTHOR_EMAIL", "t@t")
                .env("GIT_COMMITTER_NAME", "t")
                .env("GIT_COMMITTER_EMAIL", "t@t")
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
            .find(|p| p.name == "pinned")
            .expect("pinned locked");
        // The second resolve also records the current HEAD (C2), so the SHA
        // changes — what matters is that it IS a concrete SHA both times.
        let rev2_str = entry2.rev.as_str();
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
            .find(|p| p.name == "escapedep")
            .expect("escapedep locked")
            .clone();

        // Tamper a file inside the cache dir.
        let escapedep = PackageName::parse("escapedep").expect("valid name");
        let cache = package_cache_dir(&proj, &escapedep, entry.rev.as_str());
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
        let pinned_sha = PinnedRev::from_full_sha("myescape", sha).expect("valid sha");
        let escape_dep = LockedDep {
            name: "myescape".to_owned(),
            version: semver::Version::new(0, 0, 0),
            source: "https://example.invalid/myescape".to_owned(),
            rev: LockedRev::Pinned(pinned_sha.clone()),
            sha256: "00".to_owned(),
            kind: DepKind::Escape,
        };

        // An index dep: real version + any rev.
        let index_dep = LockedDep {
            name: "mypkg".to_owned(),
            version: semver::Version::parse("1.2.0").expect("valid"),
            source: "https://example.invalid/mypkg".to_owned(),
            rev: LockedRev::Pinned(PinnedRev::from_full_sha("mypkg", sha).expect("valid sha")),
            sha256: "00".to_owned(),
            kind: DepKind::Index,
        };

        // Escape: dep_cache_dir must equal escape_cache_dir (keyed by SHA).
        let myescape = PackageName::parse("myescape").expect("valid name");
        let via_escape = escape_cache_dir(&proj, &myescape, &pinned_sha);
        let via_dep = dep_cache_dir(&proj, &escape_dep).expect("valid dep name");
        assert_eq!(
            via_escape, via_dep,
            "fetch and verify must key escape by the same path"
        );

        // Index dep: dep_cache_dir must key by version, not rev.
        let mypkg = PackageName::parse("mypkg").expect("valid name");
        let via_version = package_cache_dir(&proj, &mypkg, "1.2.0");
        let via_index = dep_cache_dir(&proj, &index_dep).expect("valid dep name");
        assert_eq!(via_version, via_index, "index dep must be keyed by version");
        assert_ne!(
            via_escape, via_index,
            "escape and index deps must not share a cache dir"
        );

        let _ = std::fs::remove_dir_all(&proj);
    }

    /// A lockfile carrying a traversing dep name must be refused by
    /// `dep_cache_dir` — the name is never joined into a cache path that could
    /// reroot outside the project. The refusal is a typed error, not a path.
    #[test]
    fn dep_cache_dir_rejects_traversal_name() {
        let proj = temp_dir("dep-cache-traversal");
        let sha = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";
        for hostile in ["..", "../../evil", "/abs", "a/b"] {
            let dep = LockedDep {
                name: hostile.to_owned(),
                version: semver::Version::new(0, 0, 0),
                source: "https://example.invalid/x".to_owned(),
                rev: LockedRev::Pinned(PinnedRev::from_full_sha("x", sha).expect("valid sha")),
                sha256: "00".to_owned(),
                kind: DepKind::Escape,
            };
            dep_cache_dir(&proj, &dep)
                .expect_err(&format!("hostile dep name {hostile:?} must be refused"));
        }
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
        let url = SourceUrl::parse("p", &src.display().to_string())
            .expect("local path is a valid source URL");
        let rev = CommitId::parse("p", "HEAD").expect("HEAD is a valid commit id");
        fetch_git_into("p", &url, rev.as_str(), &dest)
            .expect("clone succeeds for a valid local repo");
        assert!(dest.is_dir(), "destination was populated");
        let _ = std::fs::remove_dir_all(&src);
        let _ = std::fs::remove_dir_all(&dest);
    }

    #[test]
    fn source_url_newtype_rejects_ext_transport_before_fetch() {
        // A `source` field containing `ext::` must be rejected by `SourceUrl::parse`
        // at the index-parse boundary; `fetch_git_into` is never called.
        let err = SourceUrl::parse("evil", "ext::sh -c 'id'").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("source"), "{msg}");
    }

    #[test]
    fn source_url_newtype_rejects_dash_leading_before_fetch() {
        let err = SourceUrl::parse("evil", "--upload-pack=malicious").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("source"), "{msg}");
    }

    #[test]
    fn commit_id_newtype_rejects_injection_shaped_rev_before_checkout() {
        // An injection-shaped `rev` (leading `-`) is rejected at parse time
        // so it never reaches `git checkout`. Ordinary ref names are accepted.
        assert!(
            CommitId::parse("ok", "main").is_ok(),
            "branch names are valid refs"
        );
        assert!(
            CommitId::parse("ok", "abc").is_ok(),
            "short hashes are valid refs"
        );
        let err = CommitId::parse("evil", "-S injected").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("rev"), "{msg}");
    }

    #[test]
    fn commit_id_newtype_rejects_dash_rev_before_checkout() {
        let err = CommitId::parse("evil", "-S injected").unwrap_err();
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
}
