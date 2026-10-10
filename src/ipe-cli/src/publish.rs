//! `ipe package publish` — prepare a package's index entry and open the index PR.
//!
//! Publish is a thin, non-privileged helper. It runs the same
//! [`crate::audit::run_audit`] gate the author and the index CI run, computes the
//! [`crate::index::EntryVersion`] for the working package, merges it into the
//! package's `packages/<name>.toml` entry file, and opens a pull request against
//! the index repository. It holds no index credentials: the index CI is the
//! authority, publish only opens the PR.
//!
//! Verify-before-trust at authoring time: the pinned `rev` and `sha256` are
//! COMPUTED from the working tree, never authored, so the pin the resolver later
//! re-verifies cannot be mistyped. Publish refuses anything that would pin a
//! non-reproducible source — a dirty working tree or an unpushed HEAD — so a
//! merged entry always names an immutable, fetchable revision.
//!
//! The curated index enforces `required_signatures`, so the publish commit must
//! be signed AND marked "Verified" or it can never merge. Two preconditions,
//! each fail-closed:
//!  - An SSH signing key whose `.pub` is registered as a *signing* key on the
//!    GitHub account that owns the fork — publish signs the commit with it. The
//!    key `ipe login` generates and registers is used by default;
//!    `IPE_PUBLISH_SIGNING_KEY` (a private-key file path) overrides it
//!    (see [`crate::ssh_signing_key`]).
//!  - Run `ipe login` (or set `GITHUB_TOKEN`): publish derives the committer
//!    identity from the authenticated publishing account (`GET /user`) and
//!    authors the commit under that account's verified GitHub noreply identity
//!    (`<id>+<login>@users.noreply.github.com`), which GitHub marks "Verified"
//!    by construction while leaking no real email.
//!
//! Absent either — no usable key, or an unresolvable identity — publish fails
//! closed with a typed refusal rather than push a commit that would be rejected
//! at merge (unsigned, or committed under a non-verifiable placeholder).

use std::ffi::OsString;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use crate::remote_ingest::{
    self, ByteBudget, CappedReadError, Captured, Curl, Git, IngestRefusal, LocalSource, RunError,
    Transfer,
};
use crate::scratch::{LeafName, ScratchDir, ScratchFile};

use crate::CliError;
use crate::index::{self, CommitId, EntryVersion, IndexEntry, PinnedRev, SourceUrl};
use crate::project::{self, ProjectManifest};
use crate::published_version::{PublishedVersion, require_successor};
use crate::publisher::{
    AuthenticatedPublisher, BlessedPublisher, BlessingRefusal, SelfDeclaredPublisher,
};
use crate::text;

/// A publish refusal: a typed reason publish declined to proceed.
///
/// Each variant carries its own already-rendered message. Distinct from an
/// [`crate::audit::Rejection`] (a gate reject) — these are the preconditions
/// publish itself enforces before a PR is ever prepared. A closed value so the
/// CLI boundary need only print it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The working tree has uncommitted changes — the pinned revision would not
    /// name the bytes actually published.
    DirtyTree { source_root: PathBuf },
    /// The current HEAD is not reachable from any remote branch — a consumer
    /// could not fetch the pinned revision.
    UnpushedHead { rev: String },
    /// The package's version is already published in the index — a published
    /// version is immutable and must never be rewritten.
    DuplicateVersion { name: String, version: String },
    /// The source URL could not be determined (no `--source` and no git remote).
    NoSource,
    /// No usable commit-signing key is configured, so the publish commit could
    /// only be pushed unsigned. The curated index enforces `required_signatures`
    /// and would refuse to merge an unsigned commit, so publish fails closed
    /// rather than push a commit that can never land.
    UnsignedCommit,
    /// The publishing account's GitHub identity could not be resolved (no login
    /// token, or `GET /user` failed / returned malformed JSON). The index
    /// enforces `required_signatures`, so a commit whose committer is not the
    /// authenticated account's verified GitHub identity could never be marked
    /// "Verified" and would be rejected at merge — publish fails closed rather
    /// than author the commit under a placeholder identity.
    UnresolvableIdentity,
    /// A level of the entry's path in the index-fork checkout, or the entry
    /// itself, is a link, a reparse point, or of the wrong kind. Git checks a
    /// committed link out as a link, so publish refuses rather than write
    /// through one to wherever the fork points it.
    ForkEntryNotPlain { path: PathBuf },
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DirtyTree { source_root } => {
                f.write_str(&crate::text::publish_dirty_tree(&source_root.display()))
            }
            Self::UnpushedHead { rev } => f.write_str(&crate::text::publish_unpushed_head(rev)),
            Self::DuplicateVersion { name, version } => {
                f.write_str(&crate::text::publish_duplicate_version(name, version))
            }
            Self::NoSource => f.write_str(crate::text::publish_no_source()),
            Self::UnsignedCommit => f.write_str(crate::text::publish_unsigned_commit()),
            Self::UnresolvableIdentity => f.write_str(crate::text::publish_unresolvable_identity()),
            Self::ForkEntryNotPlain { path } => {
                f.write_str(&crate::text::publish_fork_entry_not_plain(&path.display()))
            }
        }
    }
}

/// Build a [`CliError::Publish`] from a [`Refusal`].
const fn refuse(refusal: Refusal) -> CliError {
    CliError::Publish(refusal)
}

/// The parsed `ipe package publish` invocation.
#[derive(Debug)]
struct Args {
    /// The package directory or `package.ipe` (defaults to the current directory).
    path: PathBuf,
    /// `--dry-run`: compute and print, touch no network.
    dry_run: bool,
    /// `--index <repo>`: the index GitHub repo (`owner/name`) the PR targets.
    index_repo: String,
    /// `--source <url>`: the source URL to pin, overriding the git remote.
    source: Option<String>,
    /// `--rev <sha>`: the revision to pin, overriding the git HEAD.
    rev: Option<String>,
    /// `--fork <owner>`: the GitHub owner of the author's index fork to push to
    /// (defaults to the source repo's owner).
    fork: Option<String>,
    /// `--fresh`: write a single-version entry (the new version only) instead of
    /// appending to the existing entry. Permitted ONLY for the blessed publisher
    /// on a reserved-namespace package (the disposable smoke probe); it would
    /// otherwise erase a package's published history.
    fresh: bool,
}

/// The real curated index repository. A `--index` override retargets the PR (a
/// fork, a fixture) without changing any computed bytes.
const DEFAULT_INDEX_REPO: &str = "arthurmaciel/ipe-registry";

/// `ipe package publish [--dry-run] [--index <repo>] [--source <url>] [--rev <sha>]`
/// — run the gate, compute the index entry, and open (or, under `--dry-run`,
/// print) the index PR.
///
/// # Errors
/// [`CliError::Usage`] on argument misuse; [`CliError::PackageAudit`] when
/// the local gate rejects the package; [`CliError::Publish`] on a publish
/// precondition (dirty tree, unpushed HEAD, duplicate version, no signing key,
/// or an unresolvable committer identity); resolution / IO errors otherwise.
pub fn run_publish(rest: &[String]) -> Result<(), CliError> {
    let args = parse_args(rest)?;

    // 1. Compute the entry version + the publisher this publish claims (the
    //    source URL's owner — self-declared, written into the submitted entry).
    let manifest_path = locate_manifest(&args.path)?;
    let manifest = project::parse_manifest(&manifest_path)?;
    let entry_version =
        compute_entry_version(&manifest, args.source.as_deref(), args.rev.as_deref())?;

    let claimed = SelfDeclaredPublisher::parse(&infer_publisher(entry_version.source.as_str()))
        .map_err(|refusal| CliError::Usage(text::msg::publish_source_owner_not_login(&refusal)))?;

    // 2. Prove the publishing identity. A real publish resolves the signing key
    //    and then the authenticated account (`GET /user`) before the gate, so the
    //    blessed privileges — the reserved-namespace exemption in the local audit
    //    and the `--fresh` reset — rest on that proof, bound to the claim, never on
    //    the claim alone. `--dry-run` makes no network call and so carries no
    //    authenticated identity: a reserved-namespace preview is refused
    //    fail-closed. The registry admission gate re-checks the same privileges
    //    against the attested PR author (defense in depth).
    let credentials = if args.dry_run {
        None
    } else {
        Some(resolve_publish_credentials()?)
    };
    let blessing =
        BlessedPublisher::from_authenticated(credentials.as_ref().map(|c| &c.identity), &claimed);

    // 3. Gate locally — refuse to publish a package that fails its own audit.
    //    `run_audit_as` prints its own passing line and returns the typed reject.
    //    It reads the previous published version from the resolver's index root
    //    (the same checkout `merge_into_entry` reads below), so the semver check
    //    and the duplicate-version check see one consistent index view.
    crate::audit::run_audit_as(
        &audit_args_for_publish(&args.path, &claimed),
        blessing.as_ref(),
    )?;

    // 4. Compute the entry file. The default appends the new version to the
    //    existing entry (refusing a duplicate); `--fresh` writes a single-version
    //    entry (the new version only), used to reset the disposable reserved smoke
    //    probe so its index entry never accumulates.
    let index_root = crate::resolve::index_root()?;
    let entry_toml = if args.fresh {
        build_fresh_entry(&manifest.name, &claimed, blessing.as_ref(), &entry_version)?
    } else {
        merge_into_entry(
            &index_root,
            &manifest.name,
            claimed.as_str(),
            &entry_version,
        )?
    };

    // 5/6. Open the PR, or under --dry-run print the entry + intended PR.
    let plan = PrPlan {
        index_repo: args.index_repo.clone(),
        entry_file: format!("packages/{}.toml", manifest.name),
        branch: format!("publish/{}-{}", manifest.name, entry_version.version),
        title: format!("Publish {} {}", manifest.name, entry_version.version),
    };

    if args.dry_run {
        // No network under --dry-run: the committer identity (an authenticated
        // `GET /user`) is not resolved here; the plan states it is resolved at
        // publish time.
        print_dry_run(&entry_toml, &plan, None);
        return Ok(());
    }
    let Some(credentials) = credentials else {
        return Err(refuse(Refusal::UnresolvableIdentity));
    };

    // The fork owner defaults to the source repo's owner — the account that
    // publishes its own package would fork the index under the same name.
    let fork_owner = args
        .fork
        .unwrap_or_else(|| infer_publisher(entry_version.source.as_str()));
    if fork_owner == "unknown" {
        return Err(CliError::Usage(text::msg::publish_fork_owner_unknown()));
    }

    open_pr(&entry_toml, &plan, &fork_owner, &credentials)
}

/// Parse `publish`'s tail into typed [`Args`].
///
/// # Errors
/// [`CliError::Usage`] on an unknown flag, a missing flag value, or a second
/// positional.
fn parse_args(rest: &[String]) -> Result<Args, CliError> {
    let mut path: Option<PathBuf> = None;
    let mut dry_run = false;
    let mut index_repo: Option<String> = None;
    let mut source: Option<String> = None;
    let mut rev: Option<String> = None;
    let mut fork: Option<String> = None;
    let mut fresh = false;

    let mut it = rest.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--dry-run" => dry_run = true,
            "--index" => index_repo = Some(take_value(&mut it, "--index")?),
            "--source" => source = Some(take_value(&mut it, "--source")?),
            "--rev" => rev = Some(take_value(&mut it, "--rev")?),
            "--fork" => fork = Some(take_value(&mut it, "--fork")?),
            "--fresh" => fresh = true,
            flag if flag.starts_with('-') => {
                return Err(CliError::Usage(text::msg::unknown_flag(
                    &"package publish",
                    &flag,
                )));
            }
            positional => {
                if path.is_some() {
                    return Err(CliError::Usage(text::msg::publish_single_path()));
                }
                path = Some(PathBuf::from(positional));
            }
        }
    }

    Ok(Args {
        path: path.unwrap_or_else(|| PathBuf::from(".")),
        dry_run,
        index_repo: index_repo.unwrap_or_else(|| DEFAULT_INDEX_REPO.to_owned()),
        source,
        rev,
        fork,
        fresh,
    })
}

/// Take the value following a flag, erroring when it is absent.
fn take_value<'a>(
    it: &mut impl Iterator<Item = &'a String>,
    flag: &str,
) -> Result<String, CliError> {
    it.next()
        .cloned()
        .ok_or_else(|| CliError::Usage(text::msg::flag_needs_value(&"package publish", &flag)))
}

/// Resolve `path` (a directory or a `package.ipe`) to its manifest file.
fn locate_manifest(path: &Path) -> Result<PathBuf, CliError> {
    if path.is_dir() {
        if let Some(manifest) = crate::project::manifest_in_dir(path) {
            return Ok(manifest);
        }
        if crate::project::has_only_legacy_toml(path) {
            return Err(CliError::Usage(text::msg::legacy_toml_hint()));
        }
        return Err(CliError::Usage(text::msg::publish_no_manifest(
            &path.display(),
        )));
    }
    if path.file_name().and_then(|n| n.to_str()) == Some(crate::package_manifest::PACKAGE_IPE)
        && path.is_file()
    {
        return Ok(path.to_path_buf());
    }
    Err(CliError::Usage(text::msg::publish_not_a_package(
        &path.display(),
    )))
}

/// Compute the [`EntryVersion`] for the working package: version from the
/// manifest, source from `--source` or the git remote, rev from `--rev` or the
/// committed HEAD, sha256 over the source tree, and the inferred capability set.
///
/// Refuses a dirty tree or an unpushed HEAD (unless an explicit `--rev` was
/// given, which the caller is asserting is immutable) so the pin names a
/// reproducible revision.
///
/// # Errors
/// [`CliError::Publish`] on a publish precondition; [`CliError::Usage`] when
/// the manifest declares no version; [`CliError::VersionRefused`] when it carries
/// build metadata; resolution / IO errors otherwise.
fn compute_entry_version(
    manifest: &ProjectManifest,
    source_override: Option<&str>,
    rev_override: Option<&str>,
) -> Result<EntryVersion, CliError> {
    let version = manifest_published_version(manifest)?;

    let source_root = &manifest.root;
    let raw_source = match source_override {
        Some(s) => s.to_owned(),
        None => git_remote_url(source_root)?.ok_or_else(|| refuse(Refusal::NoSource))?,
    };
    // Parse-don't-validate: the typed constructor rejects any value outside the
    // transport allow-list. Publish uses the same gate as the resolver so an
    // entry written by `publish` round-trips through `read_entry` without error.
    let package_name = crate::package_name::PackageName::parse(&manifest.name)?;
    let source = SourceUrl::parse(&package_name, &raw_source)
        .map_err(|e| CliError::Usage(text::msg::publish_source_refused(&e)))?;

    // The revision is pinned as an immutable commit SHA. The default path runs
    // `committed_pushed_head` which already calls `git rev-parse HEAD` and
    // returns a full SHA; the override path resolves the given ref to a SHA
    // so branch names or tags are pinned to their current commit, never stored
    // as moving refs.
    let rev = if let Some(r) = rev_override {
        // Injection-gate the requested ref before passing it to git.
        let requested = CommitId::parse(&package_name, r)
            .map_err(|e| CliError::Usage(text::msg::publish_rev_refused(&e)))?;
        let raw_sha = resolve_rev_to_sha(source_root, requested.as_str())?;
        PinnedRev::from_full_sha(&package_name, &raw_sha)
            .map_err(|e| CliError::Usage(text::msg::publish_rev_not_sha(&e)))?
    } else {
        let raw_sha = committed_pushed_head(source_root)?;
        PinnedRev::from_full_sha(&package_name, &raw_sha)
            .map_err(|e| CliError::Usage(text::msg::publish_head_not_sha(&e)))?
    };

    let sha256 = crate::resolve::hash_source_tree(source_root)?;
    let capabilities = crate::infer_package_capabilities(&manifest_path_of(source_root))?;

    Ok(EntryVersion {
        version,
        source,
        rev,
        sha256,
        capabilities,
        // Publish computes the entry; the keyless signature is minted by the
        // registry's CI workflow (Fulcio/Rekor) over the statement this module
        // emits, then attached to the entry there. The locally-authored entry is
        // therefore always unsigned.
        signature: None,
    })
}

/// The committed HEAD revision of the git repo at `source_root`, after insisting
/// the working tree is clean and the commit is pushed — the two preconditions for
/// pinning a reproducible, fetchable revision.
///
/// # Errors
/// [`CliError::Publish`] on a dirty tree or an unpushed HEAD; [`CliError::Resolve`]
/// when the path is not a git repository.
fn committed_pushed_head(source_root: &Path) -> Result<String, CliError> {
    if git_tree_is_dirty(source_root)? {
        return Err(refuse(Refusal::DirtyTree {
            source_root: source_root.to_path_buf(),
        }));
    }
    let head = git_head_rev(source_root)?;
    if git_rev_is_pushed(source_root, &head)? {
        Ok(head)
    } else {
        Err(refuse(Refusal::UnpushedHead { rev: head }))
    }
}

/// Resolve an arbitrary git ref to the full 40-hex SHA of its commit object.
///
/// Runs `git rev-parse --verify <ref>^{commit}` in `root`. A branch name,
/// tag, or short hash resolves to its underlying commit SHA; a full SHA
/// passes through. Returns a resolve error when the ref does not exist.
///
/// # Errors
/// [`CliError::Resolve`] when `git` cannot be run or the ref does not resolve.
fn resolve_rev_to_sha(root: &Path, rev: &str) -> Result<String, CliError> {
    let refspec = format!("{rev}^{{commit}}");
    let out = run_git_capture(root, &["rev-parse", "--verify", "--quiet", &refspec])?.ok_or_else(
        || {
            CliError::Resolve(crate::text::msg::publish_rev_unresolved(
                &crate::style::TerminalSafe::sanitize(&refspec),
                &crate::style::TerminalSafe::sanitize(&format!("{rev:?}")),
            ))
        },
    )?;
    Ok(out.trim().to_owned())
}

/// The `package.ipe` path for a project root.
fn manifest_path_of(root: &Path) -> PathBuf {
    root.join(crate::package_manifest::PACKAGE_IPE)
}

/// Render one [`EntryVersion`] as the `[[version]]` TOML block the index reader
/// parses, exactly round-tripping through [`crate::index::read_entry`].
///
/// Pure: a function of the version alone, so the rendered bytes are testable
/// against the reader without any filesystem or network.
#[must_use]
pub fn render_entry_version(version: &EntryVersion) -> String {
    let mut out = String::from("[[version]]\n");
    let _ = writeln!(out, "version = \"{}\"", version.version);
    let _ = writeln!(out, "source = \"{}\"", version.source.as_str());
    let _ = writeln!(out, "rev = \"{}\"", version.rev.as_str());
    let _ = writeln!(out, "sha256 = \"{}\"", version.sha256);
    let caps: Vec<String> = version
        .capabilities
        .iter()
        .map(|c| format!("\"{}\"", c.as_str()))
        .collect();
    let _ = writeln!(out, "capabilities = [{}]", caps.join(", "));
    // A signed version carries its Sigstore bundle verbatim (single-line JSON,
    // so it round-trips through the reader's quote-stripping line scan).
    if let Some(sig) = &version.signature {
        let _ = writeln!(out, "signature = \"{}\"", sig.as_str());
    }
    out
}

/// Render a whole entry file: the `name`/`publisher` header followed by every
/// version block, in ascending version order.
#[must_use]
pub fn render_entry(name: &str, publisher: &str, versions: &[EntryVersion]) -> String {
    let mut out = format!("name = \"{name}\"\npublisher = \"{publisher}\"\n");
    let mut ordered: Vec<&EntryVersion> = versions.iter().collect();
    ordered.sort_by(|a, b| a.version.cmp(&b.version));
    for v in ordered {
        out.push('\n');
        out.push_str(&render_entry_version(v));
    }
    out
}

/// The manifest's version as the index will record it.
///
/// # Errors
/// [`CliError::Usage`] when the manifest declares no version;
/// [`CliError::VersionRefused`] when it carries build metadata.
fn manifest_published_version(manifest: &ProjectManifest) -> Result<PublishedVersion, CliError> {
    let version = manifest
        .version
        .clone()
        .ok_or_else(|| CliError::Usage(text::msg::publish_no_version(&manifest.name)))?;
    PublishedVersion::from_semver(version).map_err(|refusal| refusal.for_package(&manifest.name))
}

/// Merge `new_version` into the package's existing index entry (or create a first
/// entry), returning the rendered entry-file TOML.
///
/// Reads the current `packages/<name>.toml` from `index_root` if present, appends
/// the new version, and re-renders. Refuses a version already published — a
/// published version is immutable — and a version that does not exceed every
/// published one, mirroring the admission gate's monotonicity rule.
///
/// # Errors
/// [`CliError::Publish`] on a duplicate version; [`CliError::VersionRefused`]
/// when the new version is not above the greatest published one; the reader's
/// errors when an existing entry file is present but malformed.
fn merge_into_entry(
    index_root: &Path,
    name: &str,
    publisher: &str,
    new_version: &EntryVersion,
) -> Result<String, CliError> {
    // An absent entry file ⇒ a first publish. A present-but-malformed entry is a
    // read error we surface rather than silently overwrite.
    let existing: Option<IndexEntry> = if index::entry_file_exists(index_root, name)? {
        Some(index::read_entry(index_root, name)?)
    } else {
        None
    };

    let mut versions: Vec<EntryVersion> = existing.map(|e| e.versions).unwrap_or_default();
    if versions.iter().any(|v| v.version == new_version.version) {
        return Err(refuse(Refusal::DuplicateVersion {
            name: name.to_owned(),
            version: new_version.version.to_string(),
        }));
    }
    require_successor(versions.iter().map(|v| &v.version), &new_version.version)
        .map_err(|refusal| refusal.for_package(name))?;
    versions.push(new_version.clone());

    Ok(render_entry(name, publisher, &versions))
}

/// Build a single-version entry file — the new version ONLY, discarding any
/// existing published history — for the `--fresh` reset path.
///
/// Fail-closed guard: `--fresh` is permitted ONLY when the package name is
/// reserved (`ipe_kernels::reserved_package_prefix_of`) AND `blessing` proves the
/// claimed publisher is the blessed first-party identity — the authenticated
/// `GET /user` account equals both the claim and the blessed identity. This
/// mirrors the admission gate's carve-out — defence in depth, so neither the CLI
/// nor `admission_precheck` alone is the sole guard against erasing a package's
/// published versions. Absent proof of both, the reset is unreachable and the
/// caller must use the appending path.
///
/// # Errors
/// [`CliError::Usage`] when the name is not reserved or the claim is not a
/// proven blessed publisher (including every `--dry-run`, which carries no
/// authenticated identity).
fn build_fresh_entry(
    name: &str,
    claimed: &SelfDeclaredPublisher,
    blessing: Result<&BlessedPublisher, &BlessingRefusal>,
    new_version: &EntryVersion,
) -> Result<String, CliError> {
    if ipe_kernels::reserved_package_prefix_of(name).is_none() {
        return Err(CliError::Usage(text::msg::publish_fresh_refused(&name)));
    }
    match blessing {
        Ok(blessed) if blessed.vouches_for(claimed) => Ok(render_entry(
            name,
            claimed.as_str(),
            std::slice::from_ref(new_version),
        )),
        Ok(_) => Err(fresh_needs_blessing(
            name,
            &text::publish_fresh_claim_not_covered(claimed),
        )),
        Err(refusal) => Err(fresh_needs_blessing(name, refusal)),
    }
}

/// The `--fresh` refusal for a reserved package whose claimed publisher is not a
/// proven blessed identity; `reason` says why.
fn fresh_needs_blessing(name: &str, reason: &dyn std::fmt::Display) -> CliError {
    CliError::Usage(text::msg::publish_fresh_needs_blessing(&name, reason))
}

/// The intended pull request — everything publish would push, so `--dry-run` can
/// print it and the network path can act on it.
struct PrPlan {
    index_repo: String,
    entry_file: String,
    branch: String,
    title: String,
}

/// Print the computed entry and the intended PR, touching no network.
///
/// `identity` is the committer the index-PR commit would be authored under, when
/// it can be shown. It is `None` under the no-network dry-run (resolving it is an
/// authenticated `GET /user`), in which case the plan states it is resolved from
/// the logged-in account at publish time; when present (e.g. a caller that
/// already holds one), the concrete `name <email>` is shown.
fn print_dry_run(entry_toml: &str, plan: &PrPlan, identity: Option<&CommitIdentity>) {
    let toml_block = if entry_toml.ends_with('\n') {
        entry_toml.to_owned()
    } else {
        format!("{entry_toml}\n")
    };
    let committer = identity.map_or_else(
        || {
            "resolved from your logged-in GitHub account at publish time \
             (run `ipe login`)"
                .to_owned()
        },
        |id| format!("{} <{}>", id.name, id.email),
    );
    let body = format!(
        "ipe package publish --dry-run: computed index entry\n\
         \n\
         --- {} ---\n\
         {toml_block}\
         \n\
         --- intended pull request ---\n\
           target repo: {}\n\
           branch:      {}\n\
           file:        {}\n\
           title:       {}\n\
           committer:   {}\n\
         \n\
         No network was touched (--dry-run).",
        plan.entry_file, plan.index_repo, plan.branch, plan.entry_file, plan.title, committer,
    );
    crate::screen::Screen::new(crate::screen::Stream::Stdout)
        .line(crate::screen::Tone::Text, &body)
        .emit();
}

/// The SSH key used to sign the publish commit, parsed once at the boundary
/// into a value that only holds a path to a readable, regular key file.
///
/// `parse, don't validate` at the signing boundary: the configuration
/// (`IPE_PUBLISH_SIGNING_KEY`, else the key `ipe login` stored) is resolved
/// into a `SigningKey` exactly once by [`crate::ssh_signing_key::lookup`], and
/// only a value that names an existing regular file reaches the commit step —
/// an unset, empty, or unreadable configuration can never be mistaken for a
/// usable key downstream, so the only reachable outcome without a real key is a
/// typed refusal, never an unsigned push. The key material itself stays in the
/// file: only its path is handed to `git -c user.signingkey=<path>`, so no
/// private-key bytes ever reach an argv or a log line.
struct SigningKey(crate::ssh_signing_key::PrivateKeyPath);

impl SigningKey {
    /// Resolve the configured signing key, if one is usable.
    ///
    /// A set `IPE_PUBLISH_SIGNING_KEY` is authoritative: it must name an
    /// existing regular file, and when it does not publish refuses rather than
    /// fall back to the stored key. Unset, the key `ipe login` stored is used.
    /// `None` becomes a fail-closed [`Refusal::UnsignedCommit`].
    fn configured() -> Option<Self> {
        crate::ssh_signing_key::configured().map(Self)
    }

    /// Parse a raw `IPE_PUBLISH_SIGNING_KEY` value alone: an absent value
    /// (`None`), an empty/whitespace value, or a path that is not a readable
    /// regular file all fail closed.
    #[cfg(test)]
    fn from_raw(raw: Option<&str>) -> Option<Self> {
        raw.and_then(|r| {
            crate::ssh_signing_key::PrivateKeyPath::from_env_value(std::ffi::OsStr::new(r))
        })
        .map(Self)
    }

    /// The `-c` overrides that make `git commit` produce an SSH-signed commit
    /// with this key, followed by the `-S` flag on the commit itself.
    ///
    /// `commit.gpgsign=true` plus an explicit `-S` is belt-and-braces: the
    /// commit is signed even if the throwaway clone inherited no `gpgsign`
    /// config, and the key/format overrides pin SSH signing regardless of the
    /// ambient git configuration.
    fn commit_prefix(&self) -> Vec<String> {
        vec![
            "-c".to_owned(),
            "gpg.format=ssh".to_owned(),
            "-c".to_owned(),
            format!("user.signingkey={}", self.0.as_path().display()),
            "-c".to_owned(),
            "commit.gpgsign=true".to_owned(),
        ]
    }
}

/// The committer identity the index-PR commit is authored under, built once from
/// an [`AuthenticatedPublisher`]. The email is the account's GitHub noreply address,
/// which is verified-by-construction for that account — so the signed commit is
/// marked "Verified" for the index CI and every third party, while leaking no
/// real email address.
///
/// A typed value so [`commit_and_push_steps`] cannot construct the commit without
/// a resolved identity: there is no path from raw strings to the commit steps.
#[derive(Clone, Debug, PartialEq, Eq)]
struct CommitIdentity {
    name: String,
    email: String,
}

impl CommitIdentity {
    /// The committer identity `git commit` is invoked with: the account's login
    /// as the name and its GitHub noreply email (fronted by the immutable numeric
    /// account id) as the address.
    fn of(account: &AuthenticatedPublisher) -> Self {
        Self {
            name: account.login().to_owned(),
            email: format!(
                "{}+{}@users.noreply.github.com",
                account.id(),
                account.login()
            ),
        }
    }

    /// The `-c user.name=… -c user.email=…` overrides that pin this committer
    /// identity on the `git commit` invocation.
    fn commit_config(&self) -> Vec<String> {
        vec![
            "-c".to_owned(),
            format!("user.name={}", self.name),
            "-c".to_owned(),
            format!("user.email={}", self.email),
        ]
    }
}

/// Resolve the publishing account's GitHub identity from its authenticated
/// `GET /user`, or fail closed with [`Refusal::UnresolvableIdentity`].
///
/// The token is the same one the PR-open path uses ([`publish_token`]); the HTTP
/// call reuses the same secret-safe curl path as [`github_api_post`] (token on
/// stdin, response to an `O_EXCL` scratch file read back through the retained
/// handle). Any missing token, transport failure, non-200 status, or malformed
/// JSON collapses to the one typed refusal — never a placeholder identity. A
/// response over its budget, or a curl whose output pipe stays held, is that
/// typed error instead.
fn resolve_publisher_identity() -> Result<AuthenticatedPublisher, CliError> {
    let unresolvable = || refuse(Refusal::UnresolvableIdentity);
    let token = publish_token().ok_or_else(unresolvable)?;
    let json = github_api_get_json("https://api.github.com/user", &token)
        .map_err(|e| e.into_cli(unresolvable))?
        .ok_or_else(unresolvable)?;
    AuthenticatedPublisher::from_authenticated_user_response(&json).ok_or_else(unresolvable)
}

/// What a real (non-`--dry-run`) publish proves before the gate: the
/// commit-signing key and the authenticated publishing account.
struct PublishCredentials {
    signing_key: SigningKey,
    identity: AuthenticatedPublisher,
}

/// Resolve the [`PublishCredentials`], the signing key FIRST: the curated index
/// requires signed commits, so publish refuses an unsigned publish before any
/// network work, then resolves the committer identity from the authenticated
/// account. A `required_signatures` index only marks a commit "Verified" when its
/// committer is the account's verified GitHub identity, so an unresolvable
/// identity is refused up front rather than authored under a placeholder.
///
/// # Errors
/// [`Refusal::UnsignedCommit`] with no usable signing key;
/// [`Refusal::UnresolvableIdentity`] when `GET /user` cannot prove the account.
fn resolve_publish_credentials() -> Result<PublishCredentials, CliError> {
    let signing_key = SigningKey::configured().ok_or_else(|| refuse(Refusal::UnsignedCommit))?;
    let identity = resolve_publisher_identity()?;
    Ok(PublishCredentials {
        signing_key,
        identity,
    })
}

/// A validated 3-digit HTTP status in `100..=599`.
///
/// The private field means the only way to hold one is [`HttpStatus::parse`]
/// succeeding — there is no path from an unvalidated `u16`, and so no path for
/// curl's raw, possibly-garbage status text to reach a branch that treats it as
/// a real reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct HttpStatus(u16);

impl HttpStatus {
    /// Parse curl's `-w '%{http_code}'` text: exactly 3 ASCII digits, no
    /// surrounding whitespace (curl writes none, so any present is refused as
    /// malformed rather than trimmed away), value in `100..=599`.
    ///
    /// `000` — curl's own "no response" sentinel — is refused as
    /// [`StatusError::NoResponse`], distinct from an in-range-length-but-out-of-
    /// range value like `099`: both are 3 digits, but only `000` means curl
    /// never got a reply at all.
    fn parse(raw: &str) -> Result<Self, StatusError> {
        if raw.is_empty() {
            return Err(StatusError::Empty);
        }
        if raw.len() != 3 || !raw.bytes().all(|b| b.is_ascii_digit()) {
            return Err(StatusError::NotDigits);
        }
        let value = raw
            .bytes()
            .fold(0u16, |acc, b| acc * 10 + u16::from(b - b'0'));
        if value == 0 {
            return Err(StatusError::NoResponse);
        }
        if !(100..=599).contains(&value) {
            return Err(StatusError::OutOfRange(value));
        }
        Ok(Self(value))
    }

    /// The validated status value.
    const fn get(self) -> u16 {
        self.0
    }
}

/// Why [`HttpStatus::parse`] refused curl's status text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StatusError {
    /// Curl wrote no status text at all.
    Empty,
    /// The text was not exactly 3 ASCII digits.
    NotDigits,
    /// Curl's own "no response" sentinel (`000`), usually a connection failure.
    NoResponse,
    /// 3 digits, but outside `100..=599`.
    OutOfRange(u16),
}

/// Curl's own exit status for one GitHub API call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CurlExit(Option<i32>);

/// A GitHub API call that ran to completion within [`remote_ingest::GITHUB_API`].
#[derive(Debug)]
enum CurlOutcome {
    /// Curl exited 0 and wrote a parseable status; the body is read back but
    /// not yet interpreted — the caller classifies it.
    Reply { status: HttpStatus, body: Vec<u8> },
    /// Curl itself did not complete the request (DNS, TLS, connection refused,
    /// …). Carries curl's exit code only — no body, no argv, no token.
    TransportFailed(CurlExit),
}

/// Everything else that can keep [`run_github_curl`] from returning a
/// [`CurlOutcome`].
#[derive(Debug)]
enum CurlRunError {
    /// The response scratch file could not be created.
    Scratch(std::io::Error),
    /// The `curl` child could not be run or waited on.
    CouldNotRun(RunError),
    /// The call crossed [`remote_ingest::GITHUB_API`]: its deadline, or its
    /// response ceiling at curl's own `--max-filesize`, the scratch watcher, or
    /// the bounded read-back.
    Exceeded(IngestRefusal),
    /// Curl exited 0 but its `-w '%{http_code}'` text did not parse.
    Status(StatusError),
    /// Curl exited 0 but the response body could not be read back.
    Body,
}

impl CurlRunError {
    /// The [`CliError`] for this failure; a failure with no typed error of its own is `other`.
    fn into_cli(self, other: impl FnOnce() -> CliError) -> CliError {
        match self {
            Self::Exceeded(refusal) | Self::CouldNotRun(RunError::Exceeded(refusal)) => {
                CliError::RemoteIngestExceeded(refusal)
            }
            Self::CouldNotRun(RunError::PipeDrainTimeout(stream)) => {
                CliError::ChildPipeHeld(stream)
            }
            Self::CouldNotRun(RunError::PipeRead(stream, kind)) => {
                CliError::ChildPipeUnread(stream, kind)
            }
            Self::Scratch(_)
            | Self::CouldNotRun(RunError::Spawn(_) | RunError::Wait(_) | RunError::Measure(..))
            | Self::Status(_)
            | Self::Body => other(),
        }
    }
}

/// One GitHub API call shape: `GET`, or `POST` with a JSON body.
enum CurlMethod<'a> {
    Get,
    Post(&'a str),
}

/// Build the curl arguments for one GitHub API call — the single place either
/// call shape is constructed, so [`github_api_get_json`], [`github_api_post`],
/// and their test cannot drift apart.
///
/// Takes no token: the auth header travels on curl's stdin config, written by
/// [`run_github_curl`], so a token cannot reach this function and so cannot
/// appear in the argv it builds — not by convention, but because there is no
/// parameter to carry it through.
///
/// [`remote_ingest::curl_limit_args`] holds the call to
/// [`remote_ingest::GITHUB_API`]: `--max-time` bounds a stalled remote party,
/// `--max-filesize` the same response ceiling [`read_body`] enforces again on
/// the bytes read back. `--fail-with-body` is deliberately never added: the
/// status is read through `-w`, not curl's own pass/fail exit mapping, so curl
/// always writes the body for classification.
fn github_curl_argv(method: &CurlMethod<'_>, url: &str, out_path: &Path) -> Vec<OsString> {
    let budget = &remote_ingest::GITHUB_API;
    let mut args: Vec<OsString> = vec!["--silent".into(), "--show-error".into()];
    if let CurlMethod::Post(_) = method {
        args.extend(["-X".into(), "POST".into()]);
    }
    args.extend([
        "-H".into(),
        "Accept: application/vnd.github+json".into(),
        "-H".into(),
        "User-Agent: ipe-cli".into(),
        // Token delivered via stdin config, never via argv.
        "--config".into(),
        "-".into(),
    ]);
    if let CurlMethod::Post(body) = method {
        args.extend(["-d".into(), (*body).into()]);
    }
    args.extend(["-o".into(), out_path.as_os_str().to_owned()]);
    args.extend(["-w".into(), "%{http_code}".into()]);
    args.extend(
        remote_ingest::curl_limit_args(remote_ingest::JSON_RESPONSE_MAX_BYTES, budget)
            .map(OsString::from),
    );
    args.push(url.into());
    args
}

/// Read a GitHub response body back through the retained scratch handle,
/// refusing past `cap` bytes.
///
/// The read is bounded by construction ([`remote_ingest::read_capped`] buffers
/// at most `cap + 1` bytes), so an oversized body is refused, never silently
/// truncated. Defense in depth alongside curl's own `--max-filesize` and the
/// scratch watcher — any one of them alone already refuses an oversized body.
///
/// # Errors
/// [`CurlRunError::Exceeded`] past `cap`; [`CurlRunError::Body`] on a rewind
/// or read failure.
fn read_body(scratch: &mut ScratchFile, cap: ByteBudget) -> Result<Vec<u8>, CurlRunError> {
    scratch.rewind().map_err(|_| CurlRunError::Body)?;
    remote_ingest::read_capped(&mut scratch.file, cap, remote_ingest::GITHUB_API.source()).map_err(
        |e| match e {
            CappedReadError::Io(_) => CurlRunError::Body,
            CappedReadError::Exceeded(refusal) => CurlRunError::Exceeded(refusal),
        },
    )
}

/// Run one GitHub API curl call end to end under
/// [`remote_ingest::GITHUB_API`] — spawn, hand the token to stdin, wait, and
/// read the reply back — the one place any of it happens for either call
/// shape.
fn run_github_curl(
    method: &CurlMethod<'_>,
    url: &str,
    token: &crate::login::PublishToken,
    scratch_label: &str,
) -> Result<CurlOutcome, CurlRunError> {
    run_curl_on(Curl::https(), method, url, token, scratch_label)
}

/// [`run_github_curl`]'s implementation over a given [`Curl`], so a test can
/// run a fake `curl` executable without touching the process environment.
///
/// Checks curl's own exit status BEFORE the status text: an exit at a
/// [`remote_ingest::curl_limit_args`] limit is [`CurlRunError::Exceeded`], any
/// other nonzero exit is a transport failure (DNS, TLS, …) refused as
/// [`CurlOutcome::TransportFailed`] before the status text or body are ever
/// looked at.
///
/// The token travels on curl's stdin config (`--config -`), never argv, so it
/// cannot be read from `/proc/<pid>/cmdline`; the arriving
/// [`crate::login::PublishToken`] alphabet excludes the quote/newline that
/// could inject a further curl directive; and the response is read back
/// through the retained scratch handle, not by re-opening the path, so the
/// bytes parsed are the bytes curl wrote to that inode. The scratch file is
/// watched while curl writes it, so a body whose length curl could not know in
/// advance is still stopped at the ceiling.
fn run_curl_on(
    curl: Curl,
    method: &CurlMethod<'_>,
    url: &str,
    token: &crate::login::PublishToken,
    scratch_label: &str,
) -> Result<CurlOutcome, CurlRunError> {
    let budget = &remote_ingest::GITHUB_API;
    let mut scratch = ScratchFile::create(scratch_label).map_err(CurlRunError::Scratch)?;
    let command = curl.args(github_curl_argv(method, url, scratch.path()));
    let header = zeroize::Zeroizing::new(format!(
        "header = \"Authorization: Bearer {}\"\n",
        token.as_str()
    ));
    let output = command
        .run(
            Some(header.as_bytes()),
            Some(scratch.path()),
            &Transfer::begin(*budget),
        )
        .map_err(|e| match e {
            RunError::Exceeded(refusal) => CurlRunError::Exceeded(refusal),
            other => CurlRunError::CouldNotRun(other),
        })?;
    if let Some(refusal) = remote_ingest::curl_refusal(
        output.status,
        remote_ingest::JSON_RESPONSE_MAX_BYTES,
        budget,
    ) {
        return Err(CurlRunError::Exceeded(refusal));
    }
    if !output.status.success() {
        return Ok(CurlOutcome::TransportFailed(CurlExit(output.status.code())));
    }
    let status_text = String::from_utf8_lossy(&output.stdout);
    let status = HttpStatus::parse(&status_text).map_err(CurlRunError::Status)?;
    let body = read_body(&mut scratch, remote_ingest::JSON_RESPONSE_MAX_BYTES)?;
    Ok(CurlOutcome::Reply { status, body })
}

/// Describe curl's exit status for a transport-failure message: its exit code,
/// or that it was killed by a signal before it could finish.
fn describe_curl_exit(exit: CurlExit) -> String {
    exit.0.map_or_else(
        || "curl was killed by a signal before it could finish".to_owned(),
        |code| format!("curl exited with code {code}"),
    )
}

/// Render a [`StatusError`] into the user-facing message for `op` (e.g. `"GET
/// repo"`, `"POST pulls"`) — the one place curl's status refusals become text.
fn status_error_message(op: &str, err: StatusError) -> String {
    String::from(match err {
        StatusError::Empty => text::msg::publish_http_status_empty(&op),
        StatusError::NotDigits => text::msg::publish_http_status_not_digits(&op),
        StatusError::NoResponse => text::msg::publish_http_status_no_response(&op),
        StatusError::OutOfRange(value) => text::msg::publish_http_status_out_of_range(&op, &value),
    })
}

/// Render a curl transport failure into the user-facing message for `op`. The
/// message carries curl's exit status only — never the argv or the token,
/// neither of which this function has access to.
fn transport_failed_message(op: &str, exit: CurlExit) -> String {
    let detail = describe_curl_exit(exit);
    String::from(text::msg::publish_http_transport_failed(
        &op,
        &crate::style::TerminalSafe::sanitize(&detail),
    ))
}

/// Render a [`CurlRunError`] into the user-facing message for `op`.
fn curl_run_error_message(op: &str, err: CurlRunError) -> String {
    match err {
        CurlRunError::Scratch(e) | CurlRunError::CouldNotRun(RunError::Spawn(e)) => {
            format!("could not run `curl` for {op}: {e}")
        }
        CurlRunError::CouldNotRun(other) => other.to_string(),
        CurlRunError::Exceeded(refusal) => refusal.to_string(),
        CurlRunError::Status(err) => status_error_message(op, err),
        CurlRunError::Body => String::from(text::msg::publish_http_body_io(&op)),
    }
}

/// The most `errors[]` entries [`pr_already_exists_marker`] walks looking for
/// the "already exists" marker — GitHub's own reply carries a handful of
/// entries; a bound keeps a pathological reply from costing an unbounded scan.
const MAX_PR_REPLY_ERRORS: usize = 16;

/// Whether `json` carries GitHub's "a pull request already exists" marker
/// (case-insensitive), checking the top-level `message` field AND, bounded to
/// [`MAX_PR_REPLY_ERRORS`] entries, every `errors[].message`.
///
/// GitHub's real duplicate-PR 422 puts the marker only inside
/// `errors[0].message`; the top-level `message` is the generic "Validation
/// Failed" shared by every 422, so a check of the top-level field alone never
/// matches the real reply; this function looks where GitHub puts the marker.
fn pr_already_exists_marker(json: &serde_json::Value) -> bool {
    let mentions_marker = |text: &str| text.to_lowercase().contains("already exists");
    if json
        .get("message")
        .and_then(serde_json::Value::as_str)
        .is_some_and(mentions_marker)
    {
        return true;
    }
    json.get("errors")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .take(MAX_PR_REPLY_ERRORS)
        .filter_map(|entry| entry.get("message").and_then(serde_json::Value::as_str))
        .any(mentions_marker)
}

/// Classify a GitHub PR-open reply into a typed [`PrResult`] — the one place an
/// [`HttpStatus`] and a parsed JSON body become that outcome, shared by
/// production and its test.
///
/// A 422 is [`PrResult::AlreadyExists`] only when [`pr_already_exists_marker`]
/// finds the marker (in the top-level `message` or an `errors[].message`); any
/// other 422 — or any status outside 201/422 — is [`PrResult::Failed`]. GitHub
/// also returns 422 for unrelated validation failures (e.g. a malformed
/// `head`), so a 422 alone never means success.
fn classify_pr_reply(status: HttpStatus, json: &serde_json::Value) -> PrResult {
    let message = json.get("message").and_then(serde_json::Value::as_str);
    match status.get() {
        201 => json
            .get("html_url")
            .and_then(serde_json::Value::as_str)
            .map_or_else(
                || PrResult::Failed("201 response missing html_url".to_owned()),
                |url| PrResult::Created(url.to_owned()),
            ),
        422 if pr_already_exists_marker(json) => PrResult::AlreadyExists,
        _ => PrResult::Failed(
            message
                .unwrap_or("unexpected GitHub API response")
                .to_owned(),
        ),
    }
}

/// `GET` a JSON resource from the GitHub API with the bearer token, returning the
/// parsed body only on an HTTP 200.
///
/// `None` on a transport failure, a non-200
/// status, or an unparseable body — the caller turns that into a fail-closed
/// refusal.
///
/// # Errors
/// A [`CurlRunError`] when the call produced no [`CurlOutcome`].
fn github_api_get_json(
    url: &str,
    token: &crate::login::PublishToken,
) -> Result<Option<serde_json::Value>, CurlRunError> {
    Ok(
        match run_github_curl(&CurlMethod::Get, url, token, "ipe-publish-user")? {
            CurlOutcome::Reply { status, body } if status.get() == 200 => {
                serde_json::from_slice(&body).ok()
            }
            CurlOutcome::Reply { .. } | CurlOutcome::TransportFailed(_) => None,
        },
    )
}

/// Open the index PR the spec's default way: push the entry to the author's fork
/// of the index over `git`, then open a browser at GitHub's pre-filled "create
/// pull request" page.
///
/// No credential is stored and `gh` is not required — the push uses the git
/// credentials already on the machine, and the fork is a one-time setup the
/// author does on GitHub. Everything happens in a throwaway clone, so a failure
/// never touches the working project, and the PR URL is printed regardless so
/// the publish can always be finished by hand.
///
/// # Errors
/// [`CliError::Resolve`] when a git step fails (clone / commit / push); the
/// message carries the fork URL and the pre-filled PR URL as the manual
/// fallback.
fn open_pr(
    entry_toml: &str,
    plan: &PrPlan,
    fork_owner: &str,
    credentials: &PublishCredentials,
) -> Result<(), CliError> {
    // The signing key and the authenticated account were resolved up front
    // (`resolve_publish_credentials`); the commit is authored under that account.
    let identity = CommitIdentity::of(&credentials.identity);

    let index_name = index_repo_name(&plan.index_repo);
    let fork_url = format!("https://github.com/{fork_owner}/{index_name}.git");

    let scratch = ScratchDir::new("ipe-publish").map_err(|e| scratch_io(&e))?;
    let clone = scratch
        .child(&LeafName::new(index_name).map_err(|e| scratch_io(&std::io::Error::from(e)))?);

    // Shallow-clone the fork — it carries the index's `main` history, which the
    // branch must descend from for the compare page to work.
    // The clone is watched against the index-clone ceilings while git writes it.
    git_step(
        Git::user(scratch.path())
            .args(["clone", "--quiet", "--depth", "1", "--"])
            .args([fork_url.as_str(), index_name])
            .run_detached(Some(&clone), &Transfer::begin(remote_ingest::INDEX_CLONE)),
    )
    .map_err(|failure| failure.into_cli(|git| clone_failed(&fork_url, git)))?;

    // Write the entry on a fresh branch and commit it. `-c user.*` supplies an
    // identity so the commit succeeds even where git has none configured, and
    // the signing-key overrides make the commit SSH-signed so a
    // `required_signatures` index will merge it.
    write_fork_entry(&clone, &plan.entry_file, entry_toml)?;

    // Every step shares one deadline, so the sequence as a whole is held to it.
    let transfer = Transfer::begin(remote_ingest::INDEX_PUSH);
    for step in commit_and_push_steps(plan, &credentials.signing_key, &identity) {
        let git = Git::user(&clone).args(&step.args);
        let result = match step.reach {
            StepReach::Local => git.run_attached(&transfer),
            StepReach::Remote => git.run_detached(None, &transfer),
        };
        git_step(result).map_err(|failure| {
            failure.into_cli(|git| push_failed(&fork_url, plan, fork_owner, git))
        })?;
    }

    // The branch is pushed. Open the PR headlessly when a token is available
    // (CI's `GITHUB_TOKEN` or `ipe login`); otherwise fall back to the browser
    // compare page.
    publish_token().map_or_else(
        || {
            let url = compare_url(
                &plan.index_repo,
                "main",
                fork_owner,
                &plan.branch,
                &plan.title,
            );
            let opened = open_in_browser(&url);
            print_pr_opened(plan, &url, opened);
        },
        |token| submit_pr_via_api(plan, fork_owner, &token),
    );
    Ok(())
}

/// Write `contents` as the entry at `rel` inside `clone`, a checkout of the index fork.
///
/// The fork is another party's tree and git checks a committed link out as a
/// link, so every level is entered through the held level above it, never
/// following a link, and the entry is staged and renamed within its held
/// parent: no byte is written through a link the fork planted.
///
/// # Errors
/// [`Refusal::ForkEntryNotPlain`] when a level of `rel`, or the entry itself, is
/// a link, a reparse point, or of the wrong kind, or `rel` holds a component
/// other than a plain name; [`CliError::Io`] on a filesystem failure.
fn write_fork_entry(clone: &Path, rel: &str, contents: &str) -> Result<(), CliError> {
    use crate::output_dir::OutputRefusal;
    use crate::output_dir::held::{EntryKind, HeldDir};
    use std::io::Write as _;
    use std::path::Component;

    /// A held-walk refusal of a level as the publish refusal naming it.
    fn plain(error: CliError) -> CliError {
        match error {
            CliError::OutputRefused(
                OutputRefusal::Symlink(path)
                | OutputRefusal::NotADirectory(path)
                | OutputRefusal::ReparsePoint(path),
            ) => refuse(Refusal::ForkEntryNotPlain { path }),
            other => other,
        }
    }
    let not_plain = |path: PathBuf| refuse(Refusal::ForkEntryNotPlain { path });

    let names = Path::new(rel)
        .components()
        .map(|component| match component {
            Component::Normal(name) => Ok(name),
            Component::Prefix(_)
            | Component::RootDir
            | Component::CurDir
            | Component::ParentDir => Err(not_plain(clone.join(rel))),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let Some((leaf, levels)) = names.split_last() else {
        return Err(not_plain(clone.join(rel)));
    };
    let mut dir = HeldDir::open(clone)
        .map_err(plain)?
        .ok_or_else(|| CliError::Io {
            path: clone.to_path_buf(),
            source: std::io::ErrorKind::NotFound.into(),
        })?;
    for level in levels {
        dir = dir.create_child(level).map_err(plain)?.0;
    }
    match dir.kind_of(leaf).map_err(plain)? {
        EntryKind::Symlink | EntryKind::Directory => Err(not_plain(dir.path().join(leaf))),
        EntryKind::Absent | EntryKind::Other => dir
            .write_file(leaf, None, |file| file.write_all(contents.as_bytes()))
            .map_err(plain),
    }
}

/// The ordered `git` invocations that put the entry on a fresh branch, commit
/// it SSH-signed, and push it to the fork.
///
/// The commit step carries the signing-key `-c` overrides and `-S`, so a merged
/// entry always descends from a signed commit — the shape a `required_signatures`
/// index admits. The committer identity is the resolved [`CommitIdentity`] (the
/// authenticated account's verified GitHub noreply identity), taken as a
/// parameter so a caller cannot construct the commit steps without one — there is
/// no placeholder path. Extracted from [`open_pr`] so the signed-commit invariant
/// is checkable without a network: a caller can assert `-S`, the key overrides,
/// and the account identity appear on the commit step.
fn commit_and_push_steps(
    plan: &PrPlan,
    signing_key: &SigningKey,
    identity: &CommitIdentity,
) -> Vec<GitStep> {
    let owned = |args: &[&str]| {
        args.iter()
            .map(|s| (*s).to_owned())
            .collect::<Vec<String>>()
    };

    let mut commit = signing_key.commit_prefix();
    commit.extend(identity.commit_config());
    commit.push("commit".to_owned());
    commit.push("-S".to_owned());
    commit.extend(owned(&["--quiet", "-m", &plan.title]));

    vec![
        GitStep::local(owned(&["checkout", "--quiet", "-b", &plan.branch])),
        GitStep::local(owned(&["add", "--", &plan.entry_file])),
        GitStep::local(commit),
        GitStep {
            reach: StepReach::Remote,
            args: owned(&["push", "--quiet", "-u", "origin", &plan.branch]),
        },
    ]
}

/// Whether a publish `git` step works only on the local clone or reaches the remote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StepReach {
    /// Local work; it keeps the terminal, so the signing key can ask for its passphrase.
    Local,
    /// Network work; it runs in its own process group, so a stop reaches every process it started.
    Remote,
}

/// One publish `git` invocation and how far it reaches.
#[derive(Debug)]
struct GitStep {
    reach: StepReach,
    args: Vec<String>,
}

impl GitStep {
    /// A step that works only on the local clone.
    const fn local(args: Vec<String>) -> Self {
        Self {
            reach: StepReach::Local,
            args,
        }
    }
}

/// The token for the headless PR-open path: `GITHUB_TOKEN` (CI) wins, else the
/// token stored by `ipe login`. `None` selects the browser path.
///
/// Both sources are parsed through [`crate::login::PublishToken`], so a token
/// carrying a quote, newline, or other non-alphabet byte selects the browser
/// path rather than reaching curl's `--config` mini-language.
fn publish_token() -> Option<crate::login::PublishToken> {
    ipe_env::var("GITHUB_TOKEN")
        .ok()
        .and_then(|t| crate::login::PublishToken::parse(&t))
        .or_else(crate::login::stored_token)
}

/// The `POST /repos/{index}/pulls` request body: a PR from `fork_owner:branch`
/// against the index's `main`.
fn pr_request_body(plan: &PrPlan, fork_owner: &str) -> serde_json::Value {
    serde_json::json!({
        "title": plan.title,
        "head": format!("{fork_owner}:{}", plan.branch),
        "base": "main",
    })
}

/// Typed outcome of a GitHub PR-open API call.
#[derive(Debug, PartialEq)]
enum PrResult {
    /// HTTP 201 Created — PR was successfully opened.
    Created(String),
    /// HTTP 422 — GitHub reports the PR already exists for this branch.
    AlreadyExists,
    /// Any other outcome — carries the GitHub `message` or a description.
    Failed(String),
}

/// Open the index PR through the GitHub REST API — no browser. Reuses the branch
/// already pushed to the fork. On any API failure the pre-filled compare URL is
/// printed as the manual fallback, so a headless publish never dead-ends.
fn submit_pr_via_api(plan: &PrPlan, fork_owner: &str, token: &crate::login::PublishToken) {
    let api = format!("https://api.github.com/repos/{}/pulls", plan.index_repo);
    let body = pr_request_body(plan, fork_owner);
    let fallback_url = compare_url(
        &plan.index_repo,
        "main",
        fork_owner,
        &plan.branch,
        &plan.title,
    );
    match github_api_post(&api, token, &body) {
        PrResult::Created(url) => print_pr_submitted(plan, &url),
        PrResult::AlreadyExists => print_pr_submitted(plan, &fallback_url),
        PrResult::Failed(err) => print_pr_api_fallback(plan, &fallback_url, &err),
    }
}

/// `POST` a JSON body to the GitHub API with the bearer token.
///
/// The token is passed to curl via stdin (`--config -`) so it never appears in
/// the process argument list and cannot be read from `/proc/<pid>/cmdline` by
/// other local users.
///
/// The token arrives as a [`crate::login::PublishToken`], whose alphabet
/// excludes the quote and newline that could otherwise inject a new curl
/// directive on the `--config` header line — the injection is unrepresentable,
/// not merely escaped.
///
/// The HTTP status drives the result — not body-field presence — so the outcome
/// is a typed [`PrResult`] parsed once, by [`classify_pr_reply`], at the
/// network boundary. The call runs under [`remote_ingest::GITHUB_API`]; an
/// over-budget response is a [`PrResult::Failed`] naming the ceiling.
fn github_api_post(
    url: &str,
    token: &crate::login::PublishToken,
    body: &serde_json::Value,
) -> PrResult {
    let body_str = body.to_string();
    match run_github_curl(&CurlMethod::Post(&body_str), url, token, "ipe-publish-resp") {
        Ok(CurlOutcome::Reply { status, body }) => match serde_json::from_slice(&body) {
            Ok(json) => classify_pr_reply(status, &json),
            Err(e) => PrResult::Failed(format!("could not parse GitHub's response: {e}")),
        },
        Ok(CurlOutcome::TransportFailed(exit)) => {
            PrResult::Failed(transport_failed_message("POST pulls", exit))
        }
        Err(err) => PrResult::Failed(curl_run_error_message("POST pulls", err)),
    }
}

/// The `<name>` of an `<owner>/<name>` repo (the whole string when it has no
/// slash).
fn index_repo_name(index_repo: &str) -> &str {
    index_repo.rsplit('/').next().unwrap_or(index_repo)
}

/// Why one publish `git` step failed.
#[derive(Debug)]
enum GitStepFailure {
    /// git could not run or exited non-zero; its stderr or the run error.
    Git(String),
    /// git crossed its ingest budget and was killed.
    Exceeded(IngestRefusal),
    /// git finished, but a process it started held an output pipe open and was stopped.
    PipeHeld(remote_ingest::Stream),
    /// Reading one of git's output pipes failed, so its output was not used.
    PipeUnread(remote_ingest::Stream, std::io::ErrorKind),
}

impl GitStepFailure {
    /// The [`CliError`] for this failure; a git failure is shaped by `on_git`.
    fn into_cli(self, on_git: impl FnOnce(&str) -> CliError) -> CliError {
        match self {
            Self::Git(git) => on_git(&git),
            Self::Exceeded(refusal) => CliError::RemoteIngestExceeded(refusal),
            Self::PipeHeld(stream) => CliError::ChildPipeHeld(stream),
            Self::PipeUnread(stream, kind) => CliError::ChildPipeUnread(stream, kind),
        }
    }
}

/// The outcome of one publish `git` step; on a non-zero exit, git's stderr so
/// the caller can surface the real cause.
fn git_step(result: Result<Captured, RunError>) -> Result<(), GitStepFailure> {
    match result {
        Ok(out) if out.status.success() => Ok(()),
        Ok(out) => Err(GitStepFailure::Git(
            out.stderr.to_terminal().as_str().to_owned(),
        )),
        Err(RunError::Exceeded(refusal)) => Err(GitStepFailure::Exceeded(refusal)),
        Err(RunError::PipeDrainTimeout(stream)) => Err(GitStepFailure::PipeHeld(stream)),
        Err(RunError::PipeRead(stream, kind)) => Err(GitStepFailure::PipeUnread(stream, kind)),
        Err(RunError::Spawn(e)) => Err(GitStepFailure::Git(format!("could not run `git`: {e}"))),
        Err(other @ (RunError::Wait(_) | RunError::Measure(..))) => {
            Err(GitStepFailure::Git(other.to_string()))
        }
    }
}

/// GitHub's pre-filled "create pull request" URL: the compare page for
/// `fork_owner:branch` against the index's `base`, with the title filled in.
/// `quick_pull=1` opens the PR form directly.
fn compare_url(
    index_repo: &str,
    base: &str,
    fork_owner: &str,
    branch: &str,
    title: &str,
) -> String {
    format!(
        "https://github.com/{index_repo}/compare/{base}...{fork_owner}:{branch}\
         ?quick_pull=1&title={}",
        percent_encode(title)
    )
}

/// Percent-encode a URL query value, keeping the RFC 3986 unreserved set.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(b));
        } else {
            out.push('%');
            let _ = write!(out, "{b:02X}");
        }
    }
    out
}

/// Best-effort launch of the platform browser on `url`. Returns whether the
/// opener started; the URL is printed regardless, so `false` is never fatal. A
/// URL that is not an admitted GitHub [`crate::browser::BrowserUrl`] is not
/// opened.
fn open_in_browser(url: &str) -> bool {
    crate::browser::BrowserUrl::parse(url, crate::browser::BrowserOrigin::GitHub).is_ok_and(|url| {
        matches!(
            crate::browser::open_url(&url),
            crate::browser::OpenOutcome::Opened
        )
    })
}

/// Print the "pushed, now finish the PR" summary, framed and guttered like every
/// other human-facing publish message.
fn print_pr_opened(plan: &PrPlan, url: &str, opened: bool) {
    let mut body = String::new();
    let _ = writeln!(body, "pushed `{}` to your index fork", plan.branch);
    let _ = writeln!(body);
    let _ = writeln!(
        body,
        "{}finish the pull request here:",
        if opened {
            "opened your browser — "
        } else {
            ""
        }
    );
    let _ = write!(body, "  {url}");
    crate::screen::Screen::new(crate::screen::Stream::Stdout)
        .line(crate::screen::Tone::Text, &body)
        .emit();
}

/// Print the "PR opened via the API" summary (headless path — no browser).
fn print_pr_submitted(plan: &PrPlan, url: &str) {
    let mut body = String::new();
    let _ = writeln!(body, "published `{}` — pull request opened:", plan.branch);
    let _ = write!(body, "  {url}");
    crate::screen::Screen::new(crate::screen::Stream::Stdout)
        .line(crate::screen::Tone::Text, &body)
        .emit();
}

/// Print the manual fallback when the headless API PR-open failed. The branch is
/// already pushed, so the author finishes at the compare URL by hand.
fn print_pr_api_fallback(plan: &PrPlan, url: &str, err: &str) {
    let mut body = String::new();
    let _ = writeln!(body, "pushed `{}` to your index fork", plan.branch);
    let _ = writeln!(
        body,
        "the GitHub API PR-open failed ({err}); finish it here:"
    );
    let _ = write!(body, "  {url}");
    crate::screen::Screen::new(crate::screen::Stream::Stdout)
        .line(crate::screen::Tone::Text, &body)
        .emit();
}

/// A scratch-filesystem failure during publish.
fn scratch_io(e: &std::io::Error) -> CliError {
    CliError::Resolve(crate::text::msg::publish_scratch_io(e))
}

/// Clone of the author's fork failed — most often the fork does not exist yet.
fn clone_failed(fork_url: &str, git: &str) -> CliError {
    CliError::Resolve(crate::text::msg::publish_clone_failed(
        &fork_url,
        &crate::style::TerminalSafe::sanitize(git),
    ))
}

/// Push to the author's fork failed — nothing was published; the pre-filled PR
/// URL is included so the author can retry the push and finish by hand.
fn push_failed(fork_url: &str, plan: &PrPlan, fork_owner: &str, git: &str) -> CliError {
    let url = compare_url(
        &plan.index_repo,
        "main",
        fork_owner,
        &plan.branch,
        &plan.title,
    );
    CliError::Resolve(crate::text::msg::publish_push_failed(
        &plan.branch,
        &fork_url,
        &url,
        &crate::style::TerminalSafe::sanitize(git),
    ))
}

/// Derive a plausible `publisher` from a GitHub source URL (the `owner` segment
/// of `github.com/<owner>/<repo>`), falling back to `unknown` when the URL is not
/// a recognised GitHub URL. Informational only — the index CI binds the
/// authoritative publisher to the authenticated PR account.
fn infer_publisher(source: &str) -> String {
    github_owner(source).unwrap_or_else(|| "unknown".to_owned())
}

/// The `ipe package audit` argv the local publish gate runs: the package path
/// plus the publisher this publish claims. The blessed exemption on a
/// reserved-namespace package needs both this claim and the authenticated
/// blessing passed alongside it (`run_audit_as`), which covers only the claimed
/// publisher — so a regression to a path-only argv would silently re-close the
/// reserved namespace to its own owner, and the flag is pinned by a test.
fn audit_args_for_publish(path: &Path, claimed: &SelfDeclaredPublisher) -> Vec<String> {
    vec![
        path.display().to_string(),
        "--publisher".to_owned(),
        claimed.as_str().to_owned(),
    ]
}

/// The `<owner>` of a `github.com/<owner>/<repo>` URL, for either the `https://`
/// or `git@` form. `None` when the URL is not a GitHub URL.
fn github_owner(source: &str) -> Option<String> {
    let after_host = source
        .split_once("github.com/")
        .or_else(|| source.split_once("github.com:"))
        .map(|(_, rest)| rest)?;
    let owner = after_host.split('/').next()?;
    if owner.is_empty() {
        None
    } else {
        Some(owner.to_owned())
    }
}

// ===========================================================================
// git introspection — the package's source repository
// ===========================================================================

/// The `origin` remote's fetch URL for the git repo at `root`, or `None` when
/// there is no such remote (or no git repo).
fn git_remote_url(root: &Path) -> Result<Option<String>, CliError> {
    let out = run_git_capture(root, &["remote", "get-url", "origin"])?;
    Ok(out.map(|s| s.trim().to_owned()).filter(|s| !s.is_empty()))
}

/// Whether the working tree at `root` has any uncommitted change (a non-empty
/// `git status --porcelain`).
fn git_tree_is_dirty(root: &Path) -> Result<bool, CliError> {
    let out = run_git_capture(root, &["status", "--porcelain"])?.ok_or_else(|| not_a_repo(root))?;
    Ok(!out.trim().is_empty())
}

/// The full commit id of HEAD at `root`.
fn git_head_rev(root: &Path) -> Result<String, CliError> {
    let out = run_git_capture(root, &["rev-parse", "HEAD"])?.ok_or_else(|| not_a_repo(root))?;
    Ok(out.trim().to_owned())
}

/// Whether `rev` is reachable from at least one remote-tracking branch — i.e.
/// the commit has been pushed and a consumer could fetch it.
fn git_rev_is_pushed(root: &Path, rev: &str) -> Result<bool, CliError> {
    let out = run_git_capture(root, &["branch", "-r", "--contains", rev])?
        .ok_or_else(|| not_a_repo(root))?;
    Ok(!out.trim().is_empty())
}

/// A "not a git repository" resolve error, the shared fallback when a git
/// introspection command cannot run at `root`.
fn not_a_repo(root: &Path) -> CliError {
    CliError::Resolve(crate::text::msg::publish_not_git_repo(&root.display()))
}

/// Run `git <args>` in `root`, returning its stdout on success, `None` when git
/// exits non-zero (the "no such remote / not a repo" signal the caller
/// interprets), and an error when git cannot run or crosses a query's ceilings.
fn run_git_capture(root: &Path, args: &[&str]) -> Result<Option<String>, CliError> {
    let output = Git::user(root)
        .args(args)
        .query(LocalSource::GitQuery)
        .map_err(|e| match e {
            RunError::Spawn(e) | RunError::Wait(e) => {
                CliError::Resolve(crate::text::msg::publish_git_unavailable(&e))
            }
            RunError::Measure(path, source) => CliError::Io { path, source },
            RunError::Exceeded(refusal) => CliError::LocalLimitExceeded(refusal),
            RunError::PipeDrainTimeout(stream) => CliError::ChildPipeHeld(stream),
            RunError::PipeRead(stream, kind) => CliError::ChildPipeUnread(stream, kind),
        })?;
    if output.status.success() {
        Ok(Some(String::from_utf8_lossy(&output.stdout).into_owned()))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::published_version::VersionRefusal;

    /// A hostile source root or revision cannot carry an escape sequence or open a line.
    #[test]
    fn a_hostile_refusal_value_renders_inert() {
        let hostile = "src\u{1b}]0;title\u{7}\n\u{1b}[2Kerror: forged";
        let refusals = [
            Refusal::DirtyTree {
                source_root: PathBuf::from(hostile),
            },
            Refusal::UnpushedHead {
                rev: hostile.to_owned(),
            },
        ];
        for refusal in refusals {
            let shown = refusal.to_string();
            assert!(!shown.contains('\u{1b}'), "{shown:?}");
            assert!(!shown.contains('\u{7}'), "{shown:?}");
            assert!(!shown.lines().any(|l| l.starts_with("error:")), "{shown:?}");
        }
    }
    use ipe_ir::Capability;
    use std::collections::BTreeSet;

    /// A fixture package name.
    #[allow(clippy::expect_used)] // fixture names are literal registry names
    fn pn(raw: &str) -> crate::package_name::PackageName {
        crate::package_name::PackageName::parse(raw).expect("fixture package name parses")
    }

    fn caps(names: &[Capability]) -> BTreeSet<Capability> {
        names.iter().copied().collect()
    }

    fn sample_version(v: &str, caps_set: BTreeSet<Capability>) -> EntryVersion {
        EntryVersion {
            version: PublishedVersion::parse(v).expect("valid version"),
            source: SourceUrl::parse(
                &pn("http-extras"),
                "https://github.com/arthurmaciel/http-extras",
            )
            .expect("valid source url"),
            rev: PinnedRev::from_full_sha(
                &pn("http-extras"),
                "9f2c7b1e0a4d5c6f8b2a1e3d4c5b6a7f8e9d0c1b",
            )
            .expect("valid pinned rev"),
            sha256: crate::index::Sha256Hex::parse(
                &pn("http-extras"),
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            )
            .expect("valid digest"),
            capabilities: caps_set,
            signature: None,
        }
    }

    fn temp_dir(_tag: &str) -> PathBuf {
        // Use the scratch module so test-only paths are also exclusively created
        // and free of the predictable pid-name idiom.  The returned PathBuf
        // outlives the ScratchDir (caller removes it explicitly at the end of
        // each test), which is intentional: the RAII guard's drop is a
        // best-effort no-op when the directory is already gone.
        let sd = crate::scratch::ScratchDir::new("ipe-publish-test").expect("scratch dir");
        sd.into_path()
    }

    /// The rendered single entry parses back through the index reader into an
    /// identical `EntryVersion` — the authoring contract the reader defines.
    #[test]
    fn a_rendered_entry_round_trips_through_the_reader() {
        let root = temp_dir("round-trip");
        let packages = root.join("packages");
        std::fs::create_dir_all(&packages).expect("packages dir");

        let version = sample_version("1.2.0", caps(&[Capability::Network]));
        let toml = render_entry(
            "http-extras",
            "arthurmaciel",
            std::slice::from_ref(&version),
        );
        std::fs::write(packages.join("http-extras.toml"), &toml).expect("write entry");

        let parsed = index::read_entry(&root, "http-extras").expect("entry parses");
        assert_eq!(parsed.name, "http-extras");
        assert_eq!(parsed.publisher, "arthurmaciel");
        assert_eq!(parsed.versions, vec![version]);

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A signed version's `signature` bundle survives the render → read round
    /// trip: the emitted `[[version]]` block re-parses with the same bundle.
    #[test]
    fn a_signed_entry_round_trips_through_the_reader() {
        let root = temp_dir("signed-round-trip");
        let packages = root.join("packages");
        std::fs::create_dir_all(&packages).expect("packages dir");

        let mut version = sample_version("1.2.0", caps(&[Capability::Network]));
        let bundle = crate::signing::SignatureBundle::parse(
            "http-extras",
            r#"{"mediaType":"application/vnd.dev.sigstore.bundle+json;version=0.3","dsseEnvelope":{}}"#,
        )
        .expect("valid bundle");
        version.signature = Some(bundle);

        let toml = render_entry(
            "http-extras",
            "arthurmaciel",
            std::slice::from_ref(&version),
        );
        std::fs::write(packages.join("http-extras.toml"), &toml).expect("write entry");

        let parsed = index::read_entry(&root, "http-extras").expect("entry parses");
        let v = parsed.versions.first().expect("one version");
        assert!(
            v.signature.is_some(),
            "the signature must survive round-trip"
        );
        assert_eq!(&parsed.versions, std::slice::from_ref(&version));

        let _ = std::fs::remove_dir_all(&root);
    }

    /// The publish-side DSSE statement binds the subject digest to the version's
    /// pinned `sha256`, so a signature over it covers exactly the published bytes.
    #[test]
    fn publish_dsse_statement_binds_the_pinned_sha256() {
        let version = sample_version("1.2.0", caps(&[Capability::Network]));
        let stmt = crate::signing::dsse_statement("http-extras", "1.2.0", version.sha256.as_str());
        assert!(stmt.contains("http-extras@1.2.0"), "{stmt}");
        assert!(stmt.contains(version.sha256.as_str()), "{stmt}");
    }

    /// Every capability wire name survives the render → read round-trip.
    #[test]
    fn capabilities_round_trip_including_native_ffi() {
        let root = temp_dir("caps-round-trip");
        let packages = root.join("packages");
        std::fs::create_dir_all(&packages).expect("packages dir");

        let version = sample_version(
            "0.1.0",
            caps(&[
                Capability::Network,
                Capability::NativeFfi,
                Capability::Clock,
            ]),
        );
        let toml = render_entry("risky", "arthurmaciel", std::slice::from_ref(&version));
        std::fs::write(packages.join("risky.toml"), &toml).expect("write entry");

        let parsed = index::read_entry(&root, "risky").expect("entry parses");
        let only = parsed.versions.first().expect("one version");
        assert_eq!(only.capabilities, version.capabilities);

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A version with no capabilities renders an empty array and round-trips to
    /// the empty set (the reader's "absent/empty ⇒ no capabilities" contract).
    #[test]
    fn no_capabilities_round_trips_to_the_empty_set() {
        let root = temp_dir("no-caps");
        std::fs::create_dir_all(root.join("packages")).expect("packages dir");
        let version = sample_version("1.0.0", caps(&[]));
        let toml = render_entry("pure", "arthurmaciel", std::slice::from_ref(&version));
        std::fs::write(root.join("packages").join("pure.toml"), &toml).expect("write");
        let parsed = index::read_entry(&root, "pure").expect("entry parses");
        let only = parsed.versions.first().expect("one version");
        assert!(only.capabilities.is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Appending a version preserves the prior one and both round-trip; the file
    /// is re-rendered in ascending version order.
    #[test]
    fn appending_a_version_preserves_the_prior_one() {
        let root = temp_dir("append");
        let packages = root.join("packages");
        std::fs::create_dir_all(&packages).expect("packages dir");

        let v1 = sample_version("1.2.0", caps(&[Capability::Network]));
        std::fs::write(
            packages.join("http-extras.toml"),
            render_entry("http-extras", "arthurmaciel", std::slice::from_ref(&v1)),
        )
        .expect("write first entry");

        let v2 = sample_version("1.3.0", caps(&[Capability::Network, Capability::Clock]));
        let merged =
            merge_into_entry(&root, "http-extras", "arthurmaciel", &v2).expect("merge appends");
        std::fs::write(packages.join("http-extras.toml"), &merged).expect("rewrite entry");

        let parsed = index::read_entry(&root, "http-extras").expect("entry parses");
        let versions: Vec<String> = parsed
            .versions
            .iter()
            .map(|v| v.version.to_string())
            .collect();
        assert_eq!(versions, vec!["1.2.0", "1.3.0"]);
        assert!(parsed.versions.contains(&v1), "prior version preserved");
        assert!(parsed.versions.contains(&v2), "new version appended");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A first publish (no existing entry file) produces a valid, parseable
    /// entry.
    #[test]
    fn a_first_publish_creates_the_entry() {
        let root = temp_dir("first");
        std::fs::create_dir_all(root.join("packages")).expect("packages dir");

        let v = sample_version("0.1.0", caps(&[]));
        let toml = merge_into_entry(&root, "brand-new", "arthurmaciel", &v).expect("first publish");
        std::fs::write(root.join("packages").join("brand-new.toml"), &toml).expect("write");

        let parsed = index::read_entry(&root, "brand-new").expect("entry parses");
        assert_eq!(parsed.versions.len(), 1);
        let only = parsed.versions.first().expect("one version");
        assert_eq!(only.version.to_string(), "0.1.0");
        assert!(only.capabilities.is_empty());

        let _ = std::fs::remove_dir_all(&root);
    }

    /// Re-publishing an already-published version is a typed refusal, never a
    /// silent overwrite.
    #[test]
    fn a_duplicate_version_is_a_typed_refusal() {
        let root = temp_dir("dup");
        let packages = root.join("packages");
        std::fs::create_dir_all(&packages).expect("packages dir");

        let v1 = sample_version("1.2.0", caps(&[Capability::Network]));
        std::fs::write(
            packages.join("http-extras.toml"),
            render_entry("http-extras", "arthurmaciel", std::slice::from_ref(&v1)),
        )
        .expect("write entry");

        let dup = sample_version("1.2.0", caps(&[Capability::Network]));
        let err = merge_into_entry(&root, "http-extras", "arthurmaciel", &dup).unwrap_err();
        assert!(matches!(
            err,
            CliError::Publish(Refusal::DuplicateVersion { .. })
        ));
        assert!(format!("{err}").contains("already published"));

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A version below the greatest published one is refused at publish, before
    /// any PR is opened, so the index never gains a release that goes backwards.
    #[test]
    fn a_non_greatest_version_is_a_typed_refusal() {
        let root = temp_dir("non-greatest");
        let packages = root.join("packages");
        std::fs::create_dir_all(&packages).expect("packages dir");
        let published = [
            sample_version("1.0.0", caps(&[])),
            sample_version("2.0.0", caps(&[])),
        ];
        std::fs::write(
            packages.join("http-extras.toml"),
            render_entry("http-extras", "arthurmaciel", &published),
        )
        .expect("write entry");

        for below in ["1.5.0", "2.0.0-rc.1"] {
            let candidate = sample_version(below, caps(&[]));
            let err =
                merge_into_entry(&root, "http-extras", "arthurmaciel", &candidate).unwrap_err();
            assert!(
                matches!(
                    &err,
                    CliError::VersionRefused { refusal, .. }
                        if matches!(**refusal, VersionRefusal::NotAboveGreatest { .. })
                ),
                "{below} is below 2.0.0: {err:?}"
            );
        }

        let above = sample_version("2.0.1-rc.1", caps(&[]));
        merge_into_entry(&root, "http-extras", "arthurmaciel", &above)
            .expect("a prerelease above the greatest version is a successor");

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A manifest version carrying build metadata is refused when publish parses
    /// it, before the audit or any index read.
    #[test]
    fn a_build_metadata_version_is_refused_at_publish() {
        let root = temp_dir("build-metadata");
        let mut manifest = crate::project::ProjectManifest {
            name: "http-extras".to_owned(),
            version: Some("1.2.0+build.5".parse().expect("valid semver with build")),
            root: root.clone(),
            src_root: root.join("src"),
            icon: None,
            driver: ipe_backend_rust::DbDriver::default(),
            static_request: crate::build_plan::StaticRequestLayer::default(),
            wasm: crate::project::WasmConfig::default(),
            dependencies: std::collections::BTreeMap::new(),
            rust_dependencies: std::collections::BTreeMap::new(),
            capabilities: BTreeSet::new(),
            capabilities_accept: BTreeSet::new(),
            control_models_accept: BTreeSet::new(),
            has_rust_wrapper: false,
            programs: Vec::new(),
            exposed_modules: Vec::new(),
            delivery: crate::project::DeliveryConfig::default(),
        };
        let err = manifest_published_version(&manifest).unwrap_err();
        assert!(
            matches!(
                &err,
                CliError::VersionRefused { refusal, .. }
                    if matches!(**refusal, VersionRefusal::BuildMetadata { .. })
            ),
            "{err:?}"
        );

        manifest.version = Some("1.2.0".parse().expect("valid release"));
        assert_eq!(
            manifest_published_version(&manifest)
                .expect("a release without build metadata is publishable")
                .to_string(),
            "1.2.0"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// `--fresh` on a reserved-namespace package published by the blessed
    /// identity yields a single-version entry (the reset): only the new version,
    /// no accumulated history.
    #[test]
    fn fresh_on_reserved_blessed_yields_a_single_version_entry() {
        let root = temp_dir("fresh-reset");
        let packages = root.join("packages");
        std::fs::create_dir_all(&packages).expect("packages dir");

        let v = sample_version("0.0.0-smoke.1", caps(&[]));
        let claimed = claim(ipe_kernels::BLESSED_PUBLISHER);
        let blessing = authenticated_blessing(ipe_kernels::BLESSED_PUBLISHER, &claimed);
        let toml = build_fresh_entry("ipe-registry-smoke-probe", &claimed, blessing.as_ref(), &v)
            .expect("reserved + authenticated blessed --fresh is permitted");
        std::fs::write(packages.join("ipe-registry-smoke-probe.toml"), &toml).expect("write");

        let parsed =
            index::read_entry(&root, "ipe-registry-smoke-probe").expect("fresh entry parses");
        assert_eq!(parsed.versions.len(), 1, "the fresh entry has one version");
        assert_eq!(
            parsed
                .versions
                .first()
                .expect("one version")
                .version
                .to_string(),
            "0.0.0-smoke.1"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A claimed publisher, as `infer_publisher` would produce it.
    fn claim(publisher: &str) -> SelfDeclaredPublisher {
        SelfDeclaredPublisher::parse(publisher).expect("login-shaped publisher")
    }

    /// The account a `GET /user` for `login` would authenticate.
    fn authenticated(login: &str) -> AuthenticatedPublisher {
        AuthenticatedPublisher::from_authenticated_user_response(
            &serde_json::json!({"login": login, "id": 42}),
        )
        .expect("well-formed /user response")
    }

    /// The blessing an authenticated `login` establishes for `claimed`.
    fn authenticated_blessing(
        login: &str,
        claimed: &SelfDeclaredPublisher,
    ) -> Result<BlessedPublisher, BlessingRefusal> {
        BlessedPublisher::from_authenticated(Some(&authenticated(login)), claimed)
    }

    /// Assert `--fresh` on the reserved probe is refused under `blessing`.
    fn assert_fresh_refused(
        claimed: &SelfDeclaredPublisher,
        blessing: &Result<BlessedPublisher, BlessingRefusal>,
    ) {
        let v = sample_version("0.0.0-smoke.1", caps(&[]));
        let err = build_fresh_entry("ipe-registry-smoke-probe", claimed, blessing.as_ref(), &v)
            .expect_err("an unproven blessed claim must reject --fresh");
        assert!(matches!(err, CliError::Usage(_)));
        assert!(format!("{err}").contains("--fresh"), "{err}");
    }

    /// `--fresh` on a NON-reserved package is refused, even for the
    /// authenticated blessed publisher — it would erase a real package's
    /// published history.
    #[test]
    fn fresh_on_a_non_reserved_package_is_refused() {
        let v = sample_version("1.0.0", caps(&[]));
        let claimed = claim(ipe_kernels::BLESSED_PUBLISHER);
        let blessing = authenticated_blessing(ipe_kernels::BLESSED_PUBLISHER, &claimed);
        let err = build_fresh_entry("http-extras", &claimed, blessing.as_ref(), &v)
            .expect_err("a non-reserved name must reject --fresh");
        assert!(matches!(err, CliError::Usage(_)));
        assert!(format!("{err}").contains("--fresh"), "{err}");
    }

    /// `--fresh` on a reserved package by a NON-blessed (authenticated)
    /// publisher is refused — fail-closed: reserved alone does not license the
    /// reset.
    #[test]
    fn fresh_on_reserved_non_blessed_is_refused() {
        let claimed = claim("attacker");
        assert_fresh_refused(&claimed, &authenticated_blessing("attacker", &claimed));
    }

    /// A blessed CLAIM with no authenticated identity (every `--dry-run`, or a
    /// forged source owner) is refused — the claim alone never licenses the reset.
    #[test]
    fn fresh_with_an_absent_authenticated_identity_is_refused() {
        let claimed = claim(ipe_kernels::BLESSED_PUBLISHER);
        let blessing = BlessedPublisher::from_authenticated(None, &claimed);
        assert_eq!(blessing, Err(BlessingRefusal::NoProvenIdentity));
        assert_fresh_refused(&claimed, &blessing);
    }

    /// A blessed CLAIM whose authenticated account is someone else is refused —
    /// `claimed == authenticated login == blessed` must all hold.
    #[test]
    fn fresh_with_a_mismatched_authenticated_login_is_refused() {
        let claimed = claim(ipe_kernels::BLESSED_PUBLISHER);
        let blessing = authenticated_blessing("attacker", &claimed);
        assert!(matches!(
            blessing,
            Err(BlessingRefusal::IdentityMismatch { .. })
        ));
        assert_fresh_refused(&claimed, &blessing);
    }

    /// The local publish gate must audit with the claimed publisher, not a
    /// path-only argv. The authenticated blessing covers only the claimed
    /// publisher, so threading `--publisher` is what lets the blessed first-party
    /// publisher clear its own gate on a reserved-namespace package; a regression
    /// to a path-only argv silently re-closes the reserved namespace to its owner
    /// (the smoke probe stops publishing). Pin the flag + value + order.
    #[test]
    fn publish_audit_argv_carries_the_claimed_publisher() {
        let argv = audit_args_for_publish(Path::new("/pkg"), &claim("arthurmaciel"));
        assert_eq!(
            argv,
            vec![
                "/pkg".to_owned(),
                "--publisher".to_owned(),
                "arthurmaciel".to_owned(),
            ],
            "the publish gate must pass --publisher <claimed> to the audit"
        );
    }

    /// The `--dry-run` path prints the entry and the intended PR from pure
    /// artifacts (no network). Asserts the rendered TOML + plan it consumes, then
    /// exercises the printer itself.
    #[test]
    fn dry_run_prints_the_entry_and_pr_plan() {
        let version = sample_version("1.2.0", caps(&[Capability::Network]));
        let toml = render_entry(
            "http-extras",
            "arthurmaciel",
            std::slice::from_ref(&version),
        );
        let plan = PrPlan {
            index_repo: DEFAULT_INDEX_REPO.to_owned(),
            entry_file: "packages/http-extras.toml".to_owned(),
            branch: "publish/http-extras-1.2.0".to_owned(),
            title: "Publish http-extras 1.2.0".to_owned(),
        };
        assert!(toml.contains("[[version]]"));
        assert!(toml.contains("version = \"1.2.0\""));
        assert_eq!(plan.index_repo, DEFAULT_INDEX_REPO);
        assert_eq!(plan.entry_file, "packages/http-extras.toml");
        // A resolved identity is shown as `name <noreply-email>` in the plan:
        // build the rendered body the printer produces and assert the identity
        // (and no placeholder) appears.
        let identity = sample_identity();
        let rendered = crate::style::frame(&crate::style::gutter(&format!(
            "committer:   {} <{}>",
            identity.name, identity.email
        )));
        assert!(rendered.contains("octocat"), "{rendered}");
        assert!(
            rendered.contains("42+octocat@users.noreply.github.com"),
            "the plan shows the resolved account noreply identity: {rendered}"
        );
        assert!(
            !rendered.contains("ipe@localhost"),
            "the plan never shows a placeholder identity: {rendered}"
        );
        // Exercise the printer on both the resolved and the no-network arms.
        print_dry_run(&toml, &plan, Some(&identity));
        print_dry_run(&toml, &plan, None);
    }

    /// The networked path refuses with a clear instruction when no token is set —
    /// a typed refusal, not a panic. Skipped when a runner sets `GITHUB_TOKEN`.
    #[test]
    fn compare_url_is_the_prefilled_pr_page() {
        let url = compare_url(
            "arthurmaciel/ipe-registry",
            "main",
            "octocat",
            "publish/foo-1.2.3",
            "Publish foo 1.2.3",
        );
        assert_eq!(
            url,
            "https://github.com/arthurmaciel/ipe-registry/compare/\
             main...octocat:publish/foo-1.2.3?quick_pull=1&title=Publish%20foo%201.2.3"
        );
    }

    #[test]
    fn pr_request_body_targets_fork_head_against_main() {
        let plan = PrPlan {
            index_repo: "arthurmaciel/ipe-registry".to_owned(),
            entry_file: "packages/foo.toml".to_owned(),
            branch: "publish/foo-1.2.3".to_owned(),
            title: "Publish foo 1.2.3".to_owned(),
        };
        let body = pr_request_body(&plan, "octocat");
        assert_eq!(
            body.get("head").and_then(serde_json::Value::as_str),
            Some("octocat:publish/foo-1.2.3")
        );
        assert_eq!(
            body.get("base").and_then(serde_json::Value::as_str),
            Some("main")
        );
        assert_eq!(
            body.get("title").and_then(serde_json::Value::as_str),
            Some("Publish foo 1.2.3")
        );
    }

    #[test]
    fn percent_encode_keeps_unreserved_and_escapes_the_rest() {
        assert_eq!(percent_encode("Publish foo 1.2.3"), "Publish%20foo%201.2.3");
        assert_eq!(percent_encode("a-b_c.d~e"), "a-b_c.d~e");
        assert_eq!(percent_encode("x/y&z=w"), "x%2Fy%26z%3Dw");
    }

    #[test]
    fn index_repo_name_takes_the_last_segment() {
        assert_eq!(index_repo_name("arthurmaciel/ipe-registry"), "ipe-registry");
        assert_eq!(index_repo_name("ipe-registry"), "ipe-registry");
    }

    #[test]
    fn github_owner_is_extracted_for_both_url_forms() {
        assert_eq!(
            github_owner("https://github.com/arthurmaciel/http-extras").as_deref(),
            Some("arthurmaciel")
        );
        assert_eq!(
            github_owner("git@github.com:arthurmaciel/http-extras.git").as_deref(),
            Some("arthurmaciel")
        );
        assert_eq!(github_owner("https://example.invalid/x"), None);
    }

    #[test]
    fn unknown_flag_is_a_usage_error() {
        let err = parse_args(&["--nope".to_owned()]).unwrap_err();
        assert!(matches!(err, CliError::Usage(_)));
    }

    #[test]
    fn a_missing_flag_value_is_a_usage_error() {
        let err = parse_args(&["--index".to_owned()]).unwrap_err();
        assert!(matches!(err, CliError::Usage(_)));
    }

    /// `github_curl_argv` must never put the token in curl's argv — it has no
    /// token parameter at all, so the property holds by construction; this
    /// drives the production builder and pins the absence as a refusal, not
    /// just a convention. It must also always carry the transport-safety
    /// flags: `--max-time` (a stalled remote party) and `--max-filesize` (an
    /// oversized reply), matching [`crate::remote_ingest::GITHUB_API`].
    #[test]
    fn token_not_in_curl_argv() {
        let token = "super-secret-token";
        let url = "https://api.github.com/repos/foo/bar/pulls";
        let body_str = r#"{"title":"t"}"#;
        let tmp_path = Path::new("/tmp/fake-resp");

        let as_text = |args: Vec<OsString>| -> Vec<String> {
            args.iter()
                .map(|a| a.to_string_lossy().into_owned())
                .collect()
        };
        let get_args = as_text(github_curl_argv(&CurlMethod::Get, url, tmp_path));
        let post_args = as_text(github_curl_argv(&CurlMethod::Post(body_str), url, tmp_path));
        // The response is held to the GitHub API budget by curl's own limits.
        let limits = crate::remote_ingest::curl_limit_args(
            crate::remote_ingest::JSON_RESPONSE_MAX_BYTES,
            &crate::remote_ingest::GITHUB_API,
        );

        for args in [&get_args, &post_args] {
            for arg in args {
                assert!(
                    !arg.contains(token),
                    "token must not appear in curl argv; found it in: {arg:?}"
                );
                assert!(
                    !arg.contains("Bearer"),
                    "Authorization header must not appear in curl argv; found in: {arg:?}"
                );
            }
            assert!(
                args.iter().any(|a| a == "--max-time"),
                "curl argv must bound a stalled remote party with --max-time: {args:?}"
            );
            assert!(
                args.iter().any(|a| a == "--max-filesize"),
                "curl argv must bound an oversized reply with --max-filesize: {args:?}"
            );
            assert!(
                args.windows(limits.len()).any(|w| w == limits),
                "curl argv must carry the ingest limits: {args:?}"
            );
            assert!(
                args.iter().any(|a| a == "--config"),
                "the token is read from stdin config"
            );
        }
        // The stdin config line that WOULD carry the token — verify format.
        let config_line = format!("header = \"Authorization: Bearer {token}\"");
        assert!(config_line.contains(token));
        assert!(config_line.contains("Bearer"));
    }

    /// `HttpStatus::parse` refuses everything but exactly 3 ASCII digits in
    /// `100..=599`, and never trims — curl's `-w` writes no surrounding
    /// whitespace, so any is a malformed status, not one to clean up.
    #[test]
    fn http_status_parse_refuses_malformed_or_out_of_range() {
        assert_eq!(HttpStatus::parse(""), Err(StatusError::Empty));
        assert_eq!(HttpStatus::parse("abc"), Err(StatusError::NotDigits));
        assert_eq!(HttpStatus::parse("000"), Err(StatusError::NoResponse));
        assert_eq!(HttpStatus::parse("099"), Err(StatusError::OutOfRange(99)));
        assert_eq!(HttpStatus::parse("600"), Err(StatusError::OutOfRange(600)));
        assert_eq!(HttpStatus::parse("2000"), Err(StatusError::NotDigits));
        assert_eq!(HttpStatus::parse(" 200"), Err(StatusError::NotDigits));
        assert_eq!(HttpStatus::parse("200\n"), Err(StatusError::NotDigits));
        assert_eq!(HttpStatus::parse("-20"), Err(StatusError::NotDigits));

        assert_eq!(HttpStatus::parse("100"), Ok(HttpStatus(100)));
        assert_eq!(HttpStatus::parse("200"), Ok(HttpStatus(200)));
        assert_eq!(HttpStatus::parse("599"), Ok(HttpStatus(599)));
    }

    /// A curl child that exits nonzero before writing a usable status is a
    /// typed [`CurlOutcome::TransportFailed`], never a fabricated status —
    /// and the resulting message carries curl's exit code but no argv and no
    /// token.
    ///
    /// Unix-only: the fake binary is a `#!/bin/sh` script made executable via
    /// `std::os::unix::fs::PermissionsExt`, neither of which exists on Windows.
    #[cfg(unix)]
    #[test]
    fn curl_nonzero_exit_is_a_typed_transport_failure() {
        // A fake `curl` binary, invoked by absolute path (bypassing `PATH`
        // search entirely, so the test never touches the process's real
        // `PATH`), that always exits 7 (curl's own "could not connect" code)
        // without writing a status or a body — a nonzero exit is checked
        // BEFORE the (absent) status text is parsed.
        let fake_bin = ScratchDir::new("fake-curl-bin").expect("scratch dir");
        let fake_curl = fake_bin.path().join("curl");
        std::fs::write(&fake_curl, "#!/bin/sh\nexit 7\n").expect("write fake curl");
        let mut perms = std::fs::metadata(&fake_curl)
            .expect("stat fake curl")
            .permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
        std::fs::set_permissions(&fake_curl, perms).expect("chmod fake curl");

        let token = crate::login::PublishToken::parse("testtoken123").expect("token");
        let result = run_curl_on(
            Curl::https_at(&fake_curl),
            &CurlMethod::Get,
            "https://api.github.com/user",
            &token,
            "ipe-test-transport-failed",
        );

        assert!(
            matches!(result, Ok(CurlOutcome::TransportFailed(_))),
            "expected TransportFailed for a nonzero curl exit, got {result:?}"
        );
        let Ok(CurlOutcome::TransportFailed(exit)) = result else {
            return;
        };
        assert_eq!(exit, CurlExit(Some(7)));
        let message = transport_failed_message("GET user", exit);
        assert!(
            !message.contains("testtoken123"),
            "message leaked the token"
        );
        assert!(
            !message.contains("Bearer"),
            "message leaked the auth header"
        );
    }

    /// A curl child that exits 0 but writes status text `HttpStatus::parse`
    /// refuses — `"000"`, non-digits, or nothing at all — is a typed
    /// [`CurlRunError::Status`], never a fabricated 0 or an empty reply
    /// silently treated as success.
    ///
    /// Unix-only: the fake binary is a `#!/bin/sh` script made executable via
    /// `std::os::unix::fs::PermissionsExt`, neither of which exists on Windows.
    #[cfg(unix)]
    #[test]
    fn curl_zero_exit_with_malformed_status_is_a_typed_status_refusal() {
        let cases: [(&str, StatusError); 3] = [
            ("000", StatusError::NoResponse),
            ("abc", StatusError::NotDigits),
            ("", StatusError::Empty),
        ];
        for (stdout_text, expected) in cases {
            let fake_bin = ScratchDir::new("fake-curl-bad-status").expect("scratch dir");
            let fake_curl = fake_bin.path().join("curl");
            std::fs::write(
                &fake_curl,
                format!("#!/bin/sh\nprintf '%s' '{stdout_text}'\nexit 0\n"),
            )
            .expect("write fake curl");
            let mut perms = std::fs::metadata(&fake_curl)
                .expect("stat fake curl")
                .permissions();
            std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
            std::fs::set_permissions(&fake_curl, perms).expect("chmod fake curl");

            let token = crate::login::PublishToken::parse("testtoken123").expect("token");
            let result = run_curl_on(
                Curl::https_at(&fake_curl),
                &CurlMethod::Get,
                "https://api.github.com/user",
                &token,
                "ipe-test-bad-status",
            );

            assert!(
                matches!(&result, Err(CurlRunError::Status(actual)) if *actual == expected),
                "status text {stdout_text:?} should refuse as Status({expected:?}), got {result:?}"
            );
        }
    }

    /// A curl whose output pipe could not be read is that typed error, never
    /// the caller's catch-all refusal.
    #[test]
    fn an_unread_curl_pipe_is_its_own_error() {
        let unread = CurlRunError::CouldNotRun(RunError::PipeRead(
            remote_ingest::Stream::Stdout,
            std::io::ErrorKind::Other,
        ))
        .into_cli(|| CliError::Interrupted);
        assert!(
            matches!(
                unread,
                CliError::ChildPipeUnread(remote_ingest::Stream::Stdout, std::io::ErrorKind::Other)
            ),
            "{unread:?}"
        );
    }

    /// A response body past the cap is a typed ingest refusal, never a
    /// silently truncated read.
    #[test]
    fn oversized_body_is_refused_not_truncated() {
        use std::io::Write as _;
        let cap = ByteBudget::for_test(8).expect("a nonzero cap");
        let mut scratch = ScratchFile::create("ipe-test-oversized-body").expect("scratch file");
        scratch
            .file
            .write_all(&[b'x'; 16])
            .expect("write oversized body");
        let oversized = read_body(&mut scratch, cap);
        assert!(
            matches!(&oversized, Err(CurlRunError::Exceeded(refusal))
                if refusal.limit == crate::remote_ingest::IngestLimit::Bytes(8)),
            "a body past the cap must be refused, got {oversized:?}"
        );

        let mut small = ScratchFile::create("ipe-test-small-body").expect("scratch file");
        small.file.write_all(b"12345").expect("write small body");
        let within = read_body(&mut small, cap);
        assert!(
            matches!(&within, Ok(body) if body == b"12345"),
            "a body within the cap is read whole, got {within:?}"
        );
    }

    /// HTTP 201 with `html_url` → `PrResult::Created`.
    /// HTTP 200 with `html_url` → `PrResult::Failed` (not a Create response).
    /// HTTP 422 shaped like GitHub's real duplicate-PR reply (the marker sits
    /// only in `errors[].message`, not the generic top-level `message`) →
    /// `PrResult::AlreadyExists`.
    /// HTTP 422 whose `errors` never mention "already exists", 422 with no
    /// `errors` at all, 5xx, and 401/403 are all refusals — `PrResult::Failed`,
    /// never `AlreadyExists` or `Created`.
    #[test]
    fn pr_result_classification() {
        let with_url = serde_json::json!({"html_url": "https://github.com/foo/bar/pull/1"});
        // GitHub's actual shape for a duplicate-PR 422: a generic top-level
        // `message` plus the real marker nested in `errors[0].message`.
        let already_exists = serde_json::json!({
            "message": "Validation Failed",
            "errors": [
                {
                    "resource": "PullRequest",
                    "code": "custom",
                    "message": "A pull request already exists for foo:branch."
                }
            ]
        });
        let validation_failed = serde_json::json!({"message": "Validation Failed"});
        // A 422 that DOES carry `errors`, none of which mention "already
        // exists" — e.g. a malformed `head` — must still be a refusal.
        let unrelated_validation_failure = serde_json::json!({
            "message": "Validation Failed",
            "errors": [
                {
                    "resource": "PullRequest",
                    "code": "invalid",
                    "message": "head sha can't be blank"
                }
            ]
        });
        let forbidden = serde_json::json!({"message": "Forbidden"});
        let empty = serde_json::json!({});

        let s = |raw: &str| HttpStatus::parse(raw).expect("valid test status");

        assert_eq!(
            classify_pr_reply(s("201"), &with_url),
            PrResult::Created("https://github.com/foo/bar/pull/1".to_owned())
        );
        assert_eq!(
            classify_pr_reply(s("200"), &with_url),
            PrResult::Failed("unexpected GitHub API response".to_owned()),
            "200 with html_url is NOT a success"
        );
        assert_eq!(
            classify_pr_reply(s("422"), &already_exists),
            PrResult::AlreadyExists,
            "the marker in errors[].message must be found even though the \
             top-level message is only the generic \"Validation Failed\""
        );
        assert_eq!(
            classify_pr_reply(s("422"), &validation_failed),
            PrResult::Failed("Validation Failed".to_owned()),
            "a 422 without an \"already exists\" marker must never be reported as success"
        );
        assert_eq!(
            classify_pr_reply(s("422"), &unrelated_validation_failure),
            PrResult::Failed("Validation Failed".to_owned()),
            "a 422 whose errors never mention \"already exists\" must never be reported as success"
        );
        assert_eq!(
            classify_pr_reply(s("500"), &validation_failed),
            PrResult::Failed("Validation Failed".to_owned())
        );
        assert_eq!(
            classify_pr_reply(s("401"), &forbidden),
            PrResult::Failed("Forbidden".to_owned())
        );
        assert_eq!(
            classify_pr_reply(s("403"), &forbidden),
            PrResult::Failed("Forbidden".to_owned())
        );
        assert_eq!(
            classify_pr_reply(s("201"), &empty),
            PrResult::Failed("201 response missing html_url".to_owned())
        );
    }

    // --- Helpers shared by tests G and H ---

    fn make_git_repo(tag: &str, content: &str) -> PathBuf {
        let sd = crate::scratch::ScratchDir::new(&format!("ipe-publish-test-{tag}"))
            .expect("scratch dir");
        let repo = sd.into_path();
        let git = |args: &[&str]| {
            crate::remote_ingest::fixture_git(&repo)
                .args(args)
                .output()
                .expect("git")
                .status
                .success()
        };
        assert!(git(&["init", "--quiet"]));
        std::fs::write(repo.join("lib.ipe"), content).expect("write");
        assert!(git(&["add", "."]));
        assert!(git(&["commit", "--quiet", "-m", "seed"]));
        // Add a fake remote so git_rev_is_pushed can succeed.
        let remote = {
            let sd2 = crate::scratch::ScratchDir::new(&format!("ipe-publish-remote-{tag}"))
                .expect("scratch dir");
            sd2.into_path()
        };
        assert!(
            crate::remote_ingest::fixture_git(&repo)
                .args(["init", "--bare", "--quiet"])
                .arg(&remote)
                .output()
                .expect("git init bare")
                .status
                .success()
        );
        assert!(git(&[
            "remote",
            "add",
            "origin",
            &remote.display().to_string()
        ]));
        assert!(git(&["push", "--quiet", "origin", "HEAD:main"]));
        repo
    }

    fn head_sha(repo: &Path) -> String {
        let out = crate::remote_ingest::fixture_git(repo)
            .args(["rev-parse", "HEAD"])
            .output()
            .expect("git rev-parse HEAD");
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    }

    // --- Test G: publish pins SHAs ---

    #[test]
    fn publish_default_head_is_sha() {
        let repo = make_git_repo("pub-head", "module Lib\n");
        let expected_sha = head_sha(&repo);
        // resolve_rev_to_sha on HEAD must return the same 40-hex SHA.
        let sha = resolve_rev_to_sha(&repo, "HEAD").expect("rev-parse HEAD");
        assert_eq!(
            sha, expected_sha,
            "resolve_rev_to_sha must return the HEAD SHA"
        );
        assert_eq!(sha.len(), 40, "SHA must be 40 chars");
        assert!(
            sha.chars().all(|c| c.is_ascii_hexdigit()),
            "SHA must be hex"
        );
        // PinnedRev::from_full_sha must accept it.
        assert!(
            PinnedRev::from_full_sha(&pn("lib"), &sha).is_ok(),
            "HEAD SHA must be accepted by PinnedRev"
        );
        let _ = std::fs::remove_dir_all(&repo);
    }

    #[test]
    fn publish_rev_override_resolves_to_sha() {
        let repo = make_git_repo("pub-rev-override", "module Lib\n");
        // Create a branch "feat" pointing at the same commit.
        assert!(
            crate::remote_ingest::fixture_git(&repo)
                .args(["checkout", "-b", "feat"])
                .output()
                .expect("git checkout")
                .status
                .success()
        );
        let expected_sha = head_sha(&repo);
        // resolve_rev_to_sha with "feat" must return the commit SHA, not "feat".
        let sha = resolve_rev_to_sha(&repo, "feat").expect("rev-parse feat");
        assert_eq!(
            sha, expected_sha,
            "feat branch must resolve to its commit SHA"
        );
        assert_ne!(sha, "feat", "must not record the branch name as the pin");
        assert_eq!(sha.len(), 40);
        assert!(sha.chars().all(|c| c.is_ascii_hexdigit()));
        let _ = std::fs::remove_dir_all(&repo);
    }

    // --- Test H: render_entry_version round-trips a PinnedRev entry ---

    #[test]
    fn render_entry_version_round_trips_sha_rev() {
        let root = temp_dir("render-roundtrip");
        let packages = root.join("packages");
        std::fs::create_dir_all(&packages).expect("packages dir");

        let version = sample_version("2.0.0", caps(&[Capability::Network]));
        let toml = render_entry("mylib", "arthurmaciel", std::slice::from_ref(&version));
        std::fs::write(packages.join("mylib.toml"), &toml).expect("write entry");

        let parsed = index::read_entry(&root, "mylib").expect("entry parses");
        let only = parsed.versions.first().expect("one version");
        // The rev must round-trip byte-for-byte.
        assert_eq!(
            only.rev.as_str(),
            version.rev.as_str(),
            "rev must round-trip through render/read unchanged"
        );
        assert_eq!(only.rev.as_str().len(), 40, "round-tripped rev is 40 chars");
        assert!(
            only.rev.as_str().chars().all(|c| c.is_ascii_hexdigit()),
            "round-tripped rev is lowercase hex"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    fn sample_plan() -> PrPlan {
        PrPlan {
            index_repo: "arthurmaciel/ipe-registry".to_owned(),
            entry_file: "packages/http-extras.toml".to_owned(),
            branch: "publish/http-extras-1.2.0".to_owned(),
            title: "Publish http-extras 1.2.0".to_owned(),
        }
    }

    /// Fail-closed: with signing required but no usable key configured, the
    /// signing-key boundary yields nothing — the value `open_pr` turns into a
    /// typed [`Refusal::UnsignedCommit`] BEFORE any clone/commit/push. This is
    /// the security-critical rejection: absent proof the commit can be signed,
    /// publish must never push an unsigned commit the require-signed index would
    /// reject at merge. Every non-usable configuration is pinned here.
    #[test]
    fn no_signing_key_is_a_fail_closed_refusal() {
        // An unset variable, an empty/whitespace value, and a path to no real
        // file are each unusable — the boundary rejects all of them.
        assert!(
            SigningKey::from_raw(None).is_none(),
            "unset key is unusable"
        );
        assert!(
            SigningKey::from_raw(Some("")).is_none(),
            "empty key is unusable"
        );
        assert!(
            SigningKey::from_raw(Some("   ")).is_none(),
            "whitespace-only key is unusable"
        );
        assert!(
            SigningKey::from_raw(Some("/nonexistent/ipe-publish/no-such-key")).is_none(),
            "a path to no real file is unusable"
        );

        // The refusal `open_pr` builds from that `None` is the typed, closed
        // variant, and its message tells the author how to configure a key.
        let refusal = refuse(Refusal::UnsignedCommit);
        assert!(matches!(
            refusal,
            CliError::Publish(Refusal::UnsignedCommit)
        ));
        let rendered = Refusal::UnsignedCommit.to_string();
        assert!(
            rendered.contains("IPE_PUBLISH_SIGNING_KEY"),
            "the refusal names the signing-key variable so the fix is discoverable"
        );
        assert!(
            rendered.contains("nothing was published"),
            "the refusal states no unsigned commit was pushed"
        );
    }

    /// A directory is not a signing key: the boundary accepts only a regular
    /// file, so a path that resolves to a directory fails closed like an absent
    /// key.
    #[test]
    fn a_directory_is_not_a_usable_signing_key() {
        let dir = temp_dir("signing-key-dir");
        assert!(
            SigningKey::from_raw(Some(&dir.display().to_string())).is_none(),
            "a directory path is not a usable signing key"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The signed-commit path: given a usable key, the commit `git` step carries
    /// the SSH signing overrides AND `-S`, so the pushed commit is signed — the
    /// shape a `required_signatures` index admits. Pins that the signing
    /// invocation is actually taken (not merely that a key parsed).
    #[test]
    fn a_configured_key_signs_the_publish_commit() {
        let dir = temp_dir("signing-key-file");
        let key_path = dir.join("id_ed25519");
        std::fs::write(&key_path, b"fake-ssh-private-key").expect("write key file");

        let key = SigningKey::from_raw(Some(&key_path.display().to_string()))
            .expect("an existing regular file is a usable key");

        let identity = sample_identity();
        let steps = commit_and_push_steps(&sample_plan(), &key, &identity);
        let commit_step = steps
            .iter()
            .find(|s| s.args.iter().any(|a| a == "commit"))
            .expect("a commit step exists");
        // The commit keeps the terminal so the key can prompt; only the push reaches the remote.
        assert_eq!(commit_step.reach, StepReach::Local);
        assert!(
            steps.iter().all(|s| (s.reach == StepReach::Remote)
                == (s.args.first().map(String::as_str) == Some("push"))),
            "{steps:?}"
        );
        let commit = &commit_step.args;

        assert!(
            commit.iter().any(|a| a == "-S"),
            "the commit step signs the commit (-S): {commit:?}"
        );
        assert!(
            commit.iter().any(|a| a == "gpg.format=ssh"),
            "the commit step selects SSH signing: {commit:?}"
        );
        assert!(
            commit
                .iter()
                .any(|a| a == &format!("user.signingkey={}", key_path.display())),
            "the commit step pins the configured signing key by path: {commit:?}"
        );
        assert!(
            commit.iter().any(|a| a == "commit.gpgsign=true"),
            "the commit step forces signing regardless of ambient config: {commit:?}"
        );
        // The committer identity is the authenticated account's verified GitHub
        // noreply identity — the shape a `required_signatures` index marks
        // "Verified" — never the old `ipe@localhost` placeholder.
        assert!(
            commit.iter().any(|a| a == "user.name=octocat"),
            "the commit step sets the account login as the committer name: {commit:?}"
        );
        assert!(
            commit
                .iter()
                .any(|a| a == "user.email=42+octocat@users.noreply.github.com"),
            "the commit step uses the account's GitHub noreply email: {commit:?}"
        );
        assert!(
            !commit.iter().any(|a| a.contains("ipe@localhost")),
            "the placeholder email must never appear: {commit:?}"
        );
        assert!(
            !commit.iter().any(|a| a == "user.name=ipe"),
            "the placeholder name must never appear: {commit:?}"
        );
        // The key's private bytes never travel on argv — only its path does.
        assert!(
            !commit.iter().any(|a| a.contains("fake-ssh-private-key")),
            "no private-key bytes appear on the git argv: {commit:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A stable sample identity for the commit-step and dry-run tests: the
    /// account `octocat` with numeric id `42`, whose noreply email is
    /// `42+octocat@users.noreply.github.com`.
    fn sample_identity() -> CommitIdentity {
        CommitIdentity::of(&authenticated("octocat"))
    }

    /// The identity is built from the account's login and numeric id, and its
    /// email is the GitHub noreply address for exactly that account — never a
    /// real email, never a placeholder.
    #[test]
    fn identity_renders_the_account_noreply_email() {
        let id = sample_identity();
        assert_eq!(id.name, "octocat");
        assert_eq!(id.email, "42+octocat@users.noreply.github.com");
        assert!(!id.email.contains("localhost"));
    }

    /// The authenticated `GET /user` response is parsed once into a typed
    /// identity; a response missing `login`/`id`, carrying an empty login, or a
    /// non-integer id fails closed to `None` — never a partial or placeholder
    /// identity.
    #[test]
    fn user_json_parses_login_and_id_and_fails_closed() {
        let ok = serde_json::json!({"login": "octocat", "id": 42});
        let parsed = AuthenticatedPublisher::from_authenticated_user_response(&ok)
            .expect("well-formed /user parses");
        assert_eq!(parsed.login(), "octocat");
        assert_eq!(parsed.id(), 42);
        assert_eq!(
            CommitIdentity::of(&parsed).email,
            "42+octocat@users.noreply.github.com"
        );

        // Each malformed shape fails closed.
        assert!(
            AuthenticatedPublisher::from_authenticated_user_response(
                &serde_json::json!({"id": 42})
            )
            .is_none(),
            "a response with no login is unusable"
        );
        assert!(
            AuthenticatedPublisher::from_authenticated_user_response(
                &serde_json::json!({"login": "octocat"})
            )
            .is_none(),
            "a response with no id is unusable"
        );
        assert!(
            AuthenticatedPublisher::from_authenticated_user_response(
                &serde_json::json!({"login": "", "id": 42})
            )
            .is_none(),
            "an empty login is unusable"
        );
        assert!(
            AuthenticatedPublisher::from_authenticated_user_response(
                &serde_json::json!({"login": "octocat", "id": "42"})
            )
            .is_none(),
            "a non-integer id is unusable"
        );
        assert!(
            AuthenticatedPublisher::from_authenticated_user_response(&serde_json::json!({}))
                .is_none(),
            "an empty response is unusable"
        );
    }

    /// Fail-closed: an unresolvable identity is the typed
    /// [`Refusal::UnresolvableIdentity`], whose message names the fix
    /// (`ipe login`), and it can never yield a placeholder committer — the
    /// identity path only ever produces a real account identity or the refusal.
    #[test]
    fn unresolvable_identity_is_a_typed_refusal_naming_the_fix() {
        // The refusal a malformed/absent `/user` response collapses to is the
        // typed, closed variant.
        let mapped: Option<CliError> =
            AuthenticatedPublisher::from_authenticated_user_response(&serde_json::json!({}))
                .map(|id| CommitIdentity::of(&id))
                .map_or_else(|| Some(refuse(Refusal::UnresolvableIdentity)), |_| None);
        let err = mapped.expect("an empty /user response must not yield an identity");
        assert!(matches!(
            err,
            CliError::Publish(Refusal::UnresolvableIdentity)
        ));
        let rendered = Refusal::UnresolvableIdentity.to_string();
        assert!(
            rendered.contains("ipe login"),
            "the refusal names the fix so it is discoverable: {rendered}"
        );
        assert!(
            rendered.to_lowercase().contains("nothing was published"),
            "the refusal states no commit was authored: {rendered}"
        );
        assert!(
            !rendered.contains("localhost"),
            "the refusal must not name a placeholder identity: {rendered}"
        );
    }

    /// The entry path every fork-write test writes.
    const FORK_ENTRY: &str = "packages/foo.toml";

    /// A scratch fork checkout and a sibling directory outside it.
    fn fork_and_outside(tag: &str) -> (ScratchDir, PathBuf, PathBuf) {
        let sd = ScratchDir::new(&format!("ipe-publish-fork-{tag}")).expect("scratch dir");
        let clone = sd.path().join("index");
        let outside = sd.path().join("outside");
        std::fs::create_dir(&clone).expect("clone dir");
        std::fs::create_dir(&outside).expect("outside dir");
        (sd, clone, outside)
    }

    /// `result` is the fork-entry refusal naming `at`.
    fn assert_fork_entry_refused(result: &Result<(), CliError>, at: &Path) {
        assert!(
            matches!(result, Err(CliError::Publish(Refusal::ForkEntryNotPlain { path })) if path == at),
            "expected the fork-entry refusal at {}: {result:?}",
            at.display()
        );
    }

    /// The entry is written, creating `packages`, when the fork has none yet.
    #[test]
    fn fork_entry_is_written_creating_its_directory() {
        let (_sd, clone, _outside) = fork_and_outside("fresh");
        write_fork_entry(&clone, FORK_ENTRY, "name = \"foo\"\n").expect("written");
        let written = std::fs::read_to_string(clone.join(FORK_ENTRY)).expect("read back");
        assert_eq!(written, "name = \"foo\"\n");
    }

    /// An existing regular entry is replaced with the new bytes.
    #[test]
    fn fork_entry_replaces_an_existing_entry() {
        let (_sd, clone, _outside) = fork_and_outside("replace");
        std::fs::create_dir(clone.join("packages")).expect("packages");
        std::fs::write(clone.join(FORK_ENTRY), "old").expect("old entry");
        write_fork_entry(&clone, FORK_ENTRY, "new").expect("written");
        let written = std::fs::read_to_string(clone.join(FORK_ENTRY)).expect("read back");
        assert_eq!(written, "new");
    }

    /// A `packages` that is a regular file is refused, and the file is untouched.
    #[test]
    fn fork_entry_refuses_a_packages_file() {
        let (_sd, clone, _outside) = fork_and_outside("packages-file");
        let packages = clone.join("packages");
        std::fs::write(&packages, "keep").expect("packages file");
        let result = write_fork_entry(&clone, FORK_ENTRY, "new");
        assert_fork_entry_refused(&result, &packages);
        assert_eq!(std::fs::read_to_string(&packages).expect("read"), "keep");
    }

    /// An entry that is a directory is refused, never renamed over.
    #[test]
    fn fork_entry_refuses_an_entry_directory() {
        let (_sd, clone, _outside) = fork_and_outside("entry-dir");
        let entry = clone.join(FORK_ENTRY);
        std::fs::create_dir_all(&entry).expect("entry dir");
        let result = write_fork_entry(&clone, FORK_ENTRY, "new");
        assert_fork_entry_refused(&result, &entry);
        assert!(entry.is_dir());
    }

    /// A relative entry path that climbs out of the fork is refused before any write.
    #[test]
    fn fork_entry_refuses_a_non_plain_component() {
        let (_sd, clone, outside) = fork_and_outside("climb");
        let rel = "../outside/foo.toml";
        let result = write_fork_entry(&clone, rel, "new");
        assert_fork_entry_refused(&result, &clone.join(rel));
        assert!(!outside.join("foo.toml").exists());
    }

    /// A committed `packages` link to a directory outside the fork is refused, never followed.
    #[cfg(unix)]
    #[test]
    fn fork_entry_refuses_a_packages_symlink() {
        let (_sd, clone, outside) = fork_and_outside("packages-link");
        let packages = clone.join("packages");
        std::os::unix::fs::symlink(&outside, &packages).expect("packages link");
        let result = write_fork_entry(&clone, FORK_ENTRY, "new");
        assert_fork_entry_refused(&result, &packages);
        assert!(
            !outside.join("foo.toml").exists(),
            "the write followed the link"
        );
    }

    /// A committed entry link to a file outside the fork is refused; the file keeps its bytes.
    #[cfg(unix)]
    #[test]
    fn fork_entry_refuses_an_entry_symlink_to_an_outside_file() {
        let (_sd, clone, outside) = fork_and_outside("entry-link");
        let victim = outside.join("victim");
        std::fs::write(&victim, "keep").expect("victim");
        std::fs::create_dir(clone.join("packages")).expect("packages");
        let entry = clone.join(FORK_ENTRY);
        std::os::unix::fs::symlink(&victim, &entry).expect("entry link");
        let result = write_fork_entry(&clone, FORK_ENTRY, "new");
        assert_fork_entry_refused(&result, &entry);
        assert_eq!(std::fs::read_to_string(&victim).expect("read"), "keep");
        assert!(
            entry.is_symlink(),
            "the planted link was replaced, not refused"
        );
    }

    /// A committed dangling entry link is refused; its target is never created.
    #[cfg(unix)]
    #[test]
    fn fork_entry_refuses_a_dangling_entry_symlink() {
        let (_sd, clone, outside) = fork_and_outside("entry-dangling");
        let target = outside.join("created");
        std::fs::create_dir(clone.join("packages")).expect("packages");
        let entry = clone.join(FORK_ENTRY);
        std::os::unix::fs::symlink(&target, &entry).expect("entry link");
        let result = write_fork_entry(&clone, FORK_ENTRY, "new");
        assert_fork_entry_refused(&result, &entry);
        assert!(!target.exists(), "the write created the link's target");
    }

    /// The refusal names the fork path inertly, so a hostile name cannot drive the terminal.
    #[test]
    fn fork_entry_refusal_renders_inert() {
        let shown = Refusal::ForkEntryNotPlain {
            path: PathBuf::from("pkg\u{1b}]0;t\u{7}\nerror: forged"),
        }
        .to_string();
        assert!(!shown.contains('\u{1b}'), "{shown:?}");
        assert!(!shown.lines().any(|l| l.starts_with("error:")), "{shown:?}");
    }
}
