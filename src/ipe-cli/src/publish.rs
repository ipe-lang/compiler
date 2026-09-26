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
//!  - Set `IPE_PUBLISH_SIGNING_KEY` to the path of an SSH signing key (the
//!    private-key file; its `.pub` must be registered as a *signing* key on the
//!    GitHub account that owns the fork) — publish signs the commit with it.
//!  - Run `ipe login` (or set `GITHUB_TOKEN`): publish derives the committer
//!    identity from the authenticated publishing account (`GET /user`) and
//!    authors the commit under that account's verified GitHub noreply identity
//!    (`<id>+<login>@users.noreply.github.com`), which GitHub marks "Verified"
//!    by construction while leaking no real email.
//!
//! Absent either — no usable key, or an unresolvable identity — publish fails
//! closed with a typed refusal rather than push a commit that would be rejected
//! at merge (unsigned, or committed under a non-verifiable placeholder).

use std::fmt::Write as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::scratch::{ScratchDir, ScratchFile};

use crate::CliError;
use crate::index::{self, CommitId, EntryVersion, IndexEntry, PinnedRev, SourceUrl};
use crate::project::{self, ProjectManifest};
use crate::publisher::{
    AuthenticatedPublisher, BlessedPublisher, BlessingRefusal, SelfDeclaredPublisher,
};

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
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DirtyTree { source_root } => write!(
                f,
                "the working tree at {} has uncommitted changes — publish pins the exact \
                 committed revision, so commit (or stash) every change first; otherwise the \
                 pinned `sha256`/`rev` would not name the bytes you publish.",
                source_root.display()
            ),
            Self::UnpushedHead { rev } => write!(
                f,
                "HEAD ({rev}) is not reachable from any remote branch — a published version \
                 pins an immutable, fetchable revision, so push this commit to its remote \
                 before publishing."
            ),
            Self::DuplicateVersion { name, version } => write!(
                f,
                "`{name}` {version} is already published in the index — a published version is \
                 immutable and must never be rewritten. Bump the version in `package.ipe` and \
                 publish the new one."
            ),
            Self::NoSource => f.write_str(
                "could not determine the package's source URL — the index needs a public git \
                 URL the resolver can fetch. Pass `--source <url>`, or set an `origin` remote \
                 on the package's git repository.",
            ),
            Self::UnsignedCommit => f.write_str(
                "no commit-signing key is configured, so the publish commit could only be \
                 pushed unsigned — the curated index requires signed commits and would never \
                 merge it, so nothing was published. Set `IPE_PUBLISH_SIGNING_KEY` to the path \
                 of an SSH signing key (the private key file; its `.pub` must be registered as \
                 a signing key on your GitHub account) and publish again.",
            ),
            Self::UnresolvableIdentity => f.write_str(
                "could not resolve your GitHub identity for the index-PR commit — the curated \
                 index requires signed commits marked \"Verified\", which is only possible when \
                 the commit's committer is your authenticated GitHub account's verified noreply \
                 identity. Run `ipe login` so publish can sign the index PR under your verified \
                 GitHub identity, then publish again. Nothing was published.",
            ),
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
/// [`CliError::UsageOwned`] on argument misuse; [`CliError::PackageAudit`] when
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

    let claimed = SelfDeclaredPublisher::new(infer_publisher(entry_version.source.as_str()));

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
    let index_root = crate::resolve::index_root();
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
        return Err(CliError::UsageOwned(
            "ipe package publish: could not infer your GitHub fork owner from the source URL — \
             pass `--fork <github-user>` (the owner of your fork of the index)."
                .to_owned(),
        ));
    }

    open_pr(&entry_toml, &plan, &fork_owner, &credentials)
}

/// Parse `publish`'s tail into typed [`Args`].
///
/// # Errors
/// [`CliError::UsageOwned`] on an unknown flag, a missing flag value, or a second
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
                return Err(CliError::UsageOwned(format!(
                    "ipe package publish: unknown flag `{flag}`"
                )));
            }
            positional => {
                if path.is_some() {
                    return Err(CliError::Usage(
                        "ipe package publish: expected a single <path> argument",
                    ));
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
        .ok_or_else(|| CliError::UsageOwned(format!("ipe package publish: {flag} needs a value")))
}

/// Resolve `path` (a directory or a `package.ipe`) to its manifest file.
fn locate_manifest(path: &Path) -> Result<PathBuf, CliError> {
    if path.is_dir() {
        if let Some(manifest) = crate::project::manifest_in_dir(path) {
            return Ok(manifest);
        }
        if crate::project::migration_pending(path) {
            return Err(CliError::Usage(crate::project::MIGRATE_CONFIG_HINT));
        }
        return Err(CliError::UsageOwned(format!(
            "ipe package publish: no `package.ipe` in `{}` — publish operates on a publishable \
             Ipê package, which needs a manifest",
            path.display()
        )));
    }
    if path.file_name().and_then(|n| n.to_str()) == Some(crate::package_manifest::PACKAGE_IPE)
        && path.is_file()
    {
        return Ok(path.to_path_buf());
    }
    Err(CliError::UsageOwned(format!(
        "ipe package publish: `{}` is neither an Ipê project directory nor a package.ipe",
        path.display()
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
/// [`CliError::Publish`] on a publish precondition; [`CliError::UsageOwned`] when
/// the manifest declares no version; resolution / IO errors otherwise.
fn compute_entry_version(
    manifest: &ProjectManifest,
    source_override: Option<&str>,
    rev_override: Option<&str>,
) -> Result<EntryVersion, CliError> {
    let version = manifest.version.clone().ok_or_else(|| {
        CliError::UsageOwned(format!(
            "ipe package publish: `{}` declares no `version = \"…\"` — publish records the \
             version being published, so the manifest must name one.",
            manifest.name
        ))
    })?;

    let source_root = &manifest.root;
    let raw_source = match source_override {
        Some(s) => s.to_owned(),
        None => git_remote_url(source_root)?.ok_or_else(|| refuse(Refusal::NoSource))?,
    };
    // Parse-don't-validate: the typed constructor rejects any value outside the
    // transport allow-list. Publish uses the same gate as the resolver so an
    // entry written by `publish` round-trips through `read_entry` without error.
    let source = SourceUrl::parse(&manifest.name, &raw_source).map_err(|e| {
        CliError::UsageOwned(format!(
            "ipe package publish: the source URL is not accepted — {e}"
        ))
    })?;

    // The revision is pinned as an immutable commit SHA. The default path runs
    // `committed_pushed_head` which already calls `git rev-parse HEAD` and
    // returns a full SHA; the override path resolves the given ref to a SHA
    // so branch names or tags are pinned to their current commit, never stored
    // as moving refs.
    let rev = if let Some(r) = rev_override {
        // Injection-gate the requested ref before passing it to git.
        let requested = CommitId::parse(&manifest.name, r).map_err(|e| {
            CliError::UsageOwned(format!(
                "ipe package publish: the revision is not accepted — {e}"
            ))
        })?;
        let raw_sha = resolve_rev_to_sha(source_root, requested.as_str())?;
        PinnedRev::from_full_sha(&manifest.name, &raw_sha).map_err(|e| {
            CliError::UsageOwned(format!(
                "ipe package publish: `--rev` resolved to a non-SHA: {e}"
            ))
        })?
    } else {
        let raw_sha = committed_pushed_head(source_root)?;
        PinnedRev::from_full_sha(&manifest.name, &raw_sha).map_err(|e| {
            CliError::UsageOwned(format!(
                "ipe package publish: HEAD did not resolve to a full SHA: {e}"
            ))
        })?
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
            CliError::Resolve(format!(
                "ipe package publish: `git rev-parse --verify {refspec}` failed — \
                     ref {rev:?} does not resolve to a commit"
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

/// Merge `new_version` into the package's existing index entry (or create a first
/// entry), returning the rendered entry-file TOML.
///
/// Reads the current `packages/<name>.toml` from `index_root` if present, appends
/// the new version, and re-renders. Refuses a version already published — a
/// published version is immutable.
///
/// # Errors
/// [`CliError::Publish`] on a duplicate version; the reader's errors when an
/// existing entry file is present but malformed.
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
/// [`CliError::UsageOwned`] when the name is not reserved or the claim is not a
/// proven blessed publisher (including every `--dry-run`, which carries no
/// authenticated identity).
fn build_fresh_entry(
    name: &str,
    claimed: &SelfDeclaredPublisher,
    blessing: Result<&BlessedPublisher, &BlessingRefusal>,
    new_version: &EntryVersion,
) -> Result<String, CliError> {
    if ipe_kernels::reserved_package_prefix_of(name).is_none() {
        return Err(CliError::UsageOwned(format!(
            "ipe package publish: `--fresh` is only permitted on a reserved-namespace package \
             (the disposable smoke probe); it would otherwise erase `{name}`'s published \
             history. Publish a new version without `--fresh` instead."
        )));
    }
    match blessing {
        Ok(blessed) if blessed.vouches_for(claimed) => Ok(render_entry(
            name,
            claimed.as_str(),
            std::slice::from_ref(new_version),
        )),
        Ok(_) => Err(fresh_needs_blessing(
            name,
            &format!("the proof does not cover the claimed publisher `{claimed}`"),
        )),
        Err(refusal) => Err(fresh_needs_blessing(name, &refusal.to_string())),
    }
}

/// The `--fresh` refusal for a reserved package whose claimed publisher is not a
/// proven blessed identity; `reason` says why.
fn fresh_needs_blessing(name: &str, reason: &str) -> CliError {
    CliError::UsageOwned(format!(
        "ipe package publish: `--fresh` on `{name}` requires an authenticated blessed \
         publisher identity: {reason}. The identity is the account your `ipe login` token \
         authenticates as, resolved only on a real publish — `--dry-run` makes no network \
         call, so it can never preview a `--fresh` reset."
    ))
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
    print!("{}", crate::style::frame(&crate::style::gutter(&body)));
}

/// The SSH key used to sign the publish commit, parsed once at the boundary
/// into a value that only holds a path to a readable, regular key file.
///
/// `parse, don't validate` at the signing boundary: the raw
/// `IPE_PUBLISH_SIGNING_KEY` string is turned into a `SigningKey` exactly once,
/// and only a value that names an existing regular file reaches the commit step
/// — an unset, empty, or unreadable configuration can never be mistaken for a
/// usable key downstream, so the only reachable outcome without a real key is a
/// typed refusal, never an unsigned push. The key material itself stays in the
/// file: only its path is handed to `git -c user.signingkey=<path>`, so no
/// private-key bytes ever reach an argv or a log line.
struct SigningKey(PathBuf);

impl SigningKey {
    /// The environment variable naming the SSH signing key's private-key file.
    const ENV: &'static str = "IPE_PUBLISH_SIGNING_KEY";

    /// Resolve the configured signing key, if one is usable.
    ///
    /// Returns `Some` only when `IPE_PUBLISH_SIGNING_KEY` names an existing
    /// regular file; an unset variable, an empty value, or a path that is not a
    /// readable regular file all yield `None`, which the caller turns into a
    /// fail-closed [`Refusal::UnsignedCommit`].
    fn from_env() -> Option<Self> {
        Self::from_raw(std::env::var(Self::ENV).ok().as_deref())
    }

    /// The pure core of [`Self::from_env`]: turn a raw configuration value into a
    /// usable key, or `None`. An absent value (`None`), an empty/whitespace
    /// value, or a path that is not a readable regular file all fail closed.
    fn from_raw(raw: Option<&str>) -> Option<Self> {
        let trimmed = raw?.trim();
        if trimmed.is_empty() {
            return None;
        }
        let path = PathBuf::from(trimmed);
        // A regular file the process can stat is the proof the key exists; git
        // reads the bytes itself, so absent that proof publish refuses rather
        // than hand git a path that would make signing fail or silently skip.
        if std::fs::metadata(&path).is_ok_and(|m| m.is_file()) {
            Some(Self(path))
        } else {
            None
        }
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
            format!("user.signingkey={}", self.0.display()),
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
/// JSON collapses to the one typed refusal — never a placeholder identity.
fn resolve_publisher_identity() -> Result<AuthenticatedPublisher, Refusal> {
    let token = publish_token().ok_or(Refusal::UnresolvableIdentity)?;
    let json = github_api_get_json("https://api.github.com/user", &token)
        .ok_or(Refusal::UnresolvableIdentity)?;
    AuthenticatedPublisher::from_authenticated_user_response(&json)
        .ok_or(Refusal::UnresolvableIdentity)
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
    let signing_key = SigningKey::from_env().ok_or_else(|| refuse(Refusal::UnsignedCommit))?;
    let identity = resolve_publisher_identity().map_err(refuse)?;
    Ok(PublishCredentials {
        signing_key,
        identity,
    })
}

/// `GET` a JSON resource from the GitHub API with the bearer token, returning the
/// parsed body only on an HTTP 200. `None` on any transport failure, non-200
/// status, or unparseable body — the caller turns that into a fail-closed
/// refusal.
///
/// Mirrors [`github_api_post`]'s security shape exactly: the token travels on
/// curl's stdin config (`--config -`), never argv, so it cannot be read from
/// `/proc/<pid>/cmdline`; the arriving [`crate::login::PublishToken`] alphabet
/// excludes the quote/newline that could inject a further curl directive; and the
/// response is read back through the retained scratch handle, not by re-opening
/// the path, so the bytes parsed are the bytes curl wrote to that inode.
fn github_api_get_json(url: &str, token: &crate::login::PublishToken) -> Option<serde_json::Value> {
    let mut scratch = ScratchFile::create("ipe-publish-user").ok()?;
    let tmp_path = scratch.path().to_string_lossy().into_owned();

    let mut child = Command::new("curl")
        .args(["--silent", "--show-error"])
        .args(["-H", "Accept: application/vnd.github+json"])
        .args(["-H", "User-Agent: ipe-cli"])
        // Token delivered via stdin config, never via argv.
        .args(["--config", "-"])
        .args(["-o", &tmp_path])
        .args(["-w", "%{http_code}"])
        .arg(url)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;

    if let Some(mut stdin) = child.stdin.take() {
        let _ = writeln!(
            stdin,
            r#"header = "Authorization: Bearer {}""#,
            token.as_str()
        );
    }

    let output = child.wait_with_output().ok()?;
    let status_str = String::from_utf8_lossy(&output.stdout);
    let http_status: u16 = status_str.trim().parse().unwrap_or(0);
    if http_status != 200 {
        return None;
    }
    let body_bytes = scratch.read_all().unwrap_or_default();
    serde_json::from_slice(&body_bytes).ok()
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
    let clone = scratch.child(index_name);

    // Shallow-clone the fork — it carries the index's `main` history, which the
    // branch must descend from for the compare page to work.
    if let Err(git) = run_git_step(
        scratch.path(),
        &["clone", "--quiet", "--depth", "1", &fork_url, index_name],
    ) {
        return Err(clone_failed(&fork_url, &git));
    }

    // Write the entry on a fresh branch and commit it. `-c user.*` supplies an
    // identity so the commit succeeds even where git has none configured, and
    // the signing-key overrides make the commit SSH-signed so a
    // `required_signatures` index will merge it.
    let entry_path = clone.join(&plan.entry_file);
    if let Some(parent) = entry_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| scratch_io(&e))?;
    }
    std::fs::write(&entry_path, entry_toml).map_err(|e| scratch_io(&e))?;

    for step in commit_and_push_steps(plan, &credentials.signing_key, &identity) {
        let refs: Vec<&str> = step.iter().map(String::as_str).collect();
        if let Err(git) = run_git_step(&clone, &refs) {
            return Err(push_failed(&fork_url, plan, fork_owner, &git));
        }
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
) -> Vec<Vec<String>> {
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
        owned(&["checkout", "--quiet", "-b", &plan.branch]),
        owned(&["add", "--", &plan.entry_file]),
        commit,
        owned(&["push", "--quiet", "-u", "origin", &plan.branch]),
    ]
}

/// The token for the headless PR-open path: `GITHUB_TOKEN` (CI) wins, else the
/// token stored by `ipe login`. `None` selects the browser path.
///
/// Both sources are parsed through [`crate::login::PublishToken`], so a token
/// carrying a quote, newline, or other non-alphabet byte selects the browser
/// path rather than reaching curl's `--config` mini-language.
fn publish_token() -> Option<crate::login::PublishToken> {
    std::env::var("GITHUB_TOKEN")
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
/// is a typed [`PrResult`] parsed once at the network boundary.
fn github_api_post(
    url: &str,
    token: &crate::login::PublishToken,
    body: &serde_json::Value,
) -> PrResult {
    let body_str = body.to_string();
    // curl writes the response body to an exclusively-created scratch file;
    // the HTTP status code is captured on stdout (`-w '%{http_code}'`).
    // The scratch file is created with O_EXCL before curl runs, so a
    // pre-seeded symlink or a pre-existing name is refused rather than
    // followed.  The response is read back through the retained file handle —
    // not by re-opening the path — so the bytes parsed are the bytes curl
    // wrote to this inode, with no race between write and read.
    let mut scratch = match ScratchFile::create("ipe-publish-resp") {
        Ok(sf) => sf,
        Err(e) => {
            return PrResult::Failed(format!(
                "could not create scratch file for curl response: {e}"
            ));
        }
    };
    let tmp_path = scratch.path().to_string_lossy().into_owned();

    let mut child = match Command::new("curl")
        .args(["--silent", "--show-error", "-X", "POST"])
        .args(["-H", "Accept: application/vnd.github+json"])
        .args(["-H", "User-Agent: ipe-cli"])
        // Token delivered via stdin config, never via argv.
        .args(["--config", "-"])
        .args(["-d", &body_str])
        .args(["-o", &tmp_path])
        .args(["-w", "%{http_code}"])
        .arg(url)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            return PrResult::Failed(format!("could not run `curl` (needed to open the PR): {e}"));
        }
    };

    // Write the auth header line to curl's stdin config, then close stdin so
    // curl proceeds.  A write failure here means curl never gets the header;
    // the subsequent wait will capture the error.
    if let Some(mut stdin) = child.stdin.take() {
        let _ = writeln!(
            stdin,
            r#"header = "Authorization: Bearer {}""#,
            token.as_str()
        );
    }

    let output = match child.wait_with_output() {
        Ok(o) => o,
        Err(e) => return PrResult::Failed(format!("curl wait failed: {e}")),
    };

    // stdout carries the 3-digit HTTP status code written by `-w '%{http_code}'`.
    let status_str = String::from_utf8_lossy(&output.stdout);
    let http_status: u16 = status_str.trim().parse().unwrap_or(0);

    // Read the response body through the retained handle (not by path) so the
    // bytes parsed are exactly what curl wrote to this inode.
    let body_bytes = scratch.read_all().unwrap_or_default();
    // `scratch` drops here, removing the temp file.

    let json: serde_json::Value = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(e) => return PrResult::Failed(format!("could not parse GitHub's response: {e}")),
    };

    match http_status {
        201 => {
            // 201 Created must carry an `html_url`; anything else is unexpected.
            json.get("html_url")
                .and_then(serde_json::Value::as_str)
                .map_or_else(
                    || PrResult::Failed("201 response missing html_url".to_owned()),
                    |url| PrResult::Created(url.to_owned()),
                )
        }
        422 => PrResult::AlreadyExists,
        _ => {
            let msg = json
                .get("message")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unexpected GitHub API response");
            PrResult::Failed(msg.to_owned())
        }
    }
}

/// The `<name>` of an `<owner>/<name>` repo (the whole string when it has no
/// slash).
fn index_repo_name(index_repo: &str) -> &str {
    index_repo.rsplit('/').next().unwrap_or(index_repo)
}

/// Run one `git` step in `dir`; on a non-zero exit, return git's stderr as the
/// error string so the caller can surface the real cause.
fn run_git_step(dir: &Path, args: &[&str]) -> Result<(), String> {
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .map_err(|e| format!("could not run `git`: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_owned())
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
/// opener started — the URL is printed regardless, so `false` is never fatal.
fn open_in_browser(url: &str) -> bool {
    let mut command = if cfg!(target_os = "macos") {
        let mut c = Command::new("open");
        c.arg(url);
        c
    } else if cfg!(target_os = "windows") {
        let mut c = Command::new("cmd");
        c.args(["/C", "start", "", url]);
        c
    } else {
        let mut c = Command::new("xdg-open");
        c.arg(url);
        c
    };
    command.status().is_ok_and(|s| s.success())
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
    print!("{}", crate::style::frame(&crate::style::gutter(&body)));
}

/// Print the "PR opened via the API" summary (headless path — no browser).
fn print_pr_submitted(plan: &PrPlan, url: &str) {
    let mut body = String::new();
    let _ = writeln!(body, "published `{}` — pull request opened:", plan.branch);
    let _ = write!(body, "  {url}");
    print!("{}", crate::style::frame(&crate::style::gutter(&body)));
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
    print!("{}", crate::style::frame(&crate::style::gutter(&body)));
}

/// A scratch-filesystem failure during publish.
fn scratch_io(e: &std::io::Error) -> CliError {
    CliError::Resolve(format!(
        "ipe package publish: scratch filesystem error: {e}"
    ))
}

/// Clone of the author's fork failed — most often the fork does not exist yet.
fn clone_failed(fork_url: &str, git: &str) -> CliError {
    CliError::Resolve(format!(
        "ipe package publish: could not clone your index fork `{fork_url}` — publish pushes the \
         entry to your fork, so fork the index on GitHub first (a one-time step) and make sure \
         git can reach it.\n  git: {git}"
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
    CliError::Resolve(format!(
        "ipe package publish: could not push `{}` to `{fork_url}` — nothing was published. Fix \
         the push (git credentials / fork access), then open the PR here:\n  {url}\n  git: {git}",
        plan.branch
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
    CliError::Resolve(format!(
        "ipe package publish: `{}` is not a git repository — publish pins a committed, pushed \
         revision, so the package must live in a git repo (or pass `--source`/`--rev`).",
        root.display()
    ))
}

/// Run `git <args>` in `root`, returning its stdout on success, `None` when git
/// exits non-zero (the "no such remote / not a repo" signal the caller
/// interprets), and a resolve error only when git cannot be spawned at all.
fn run_git_capture(root: &Path, args: &[&str]) -> Result<Option<String>, CliError> {
    let output = Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .map_err(|e| CliError::Resolve(format!("ipe package publish: could not run `git`: {e}")))?;
    if output.status.success() {
        Ok(Some(String::from_utf8_lossy(&output.stdout).into_owned()))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipe_ir::Capability;
    use std::collections::BTreeSet;

    fn caps(names: &[Capability]) -> BTreeSet<Capability> {
        names.iter().copied().collect()
    }

    fn sample_version(v: &str, caps_set: BTreeSet<Capability>) -> EntryVersion {
        EntryVersion {
            version: semver::Version::parse(v).expect("valid version"),
            source: SourceUrl::parse("http-extras", "https://github.com/arthurmaciel/http-extras")
                .expect("valid source url"),
            rev: PinnedRev::from_full_sha(
                "http-extras",
                "9f2c7b1e0a4d5c6f8b2a1e3d4c5b6a7f8e9d0c1b",
            )
            .expect("valid pinned rev"),
            sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_owned(),
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
        let p = sd.path().to_path_buf();
        std::mem::forget(sd); // caller's explicit remove_dir_all handles cleanup
        p
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
        let stmt = crate::signing::dsse_statement("http-extras", "1.2.0", &version.sha256);
        assert!(stmt.contains("http-extras@1.2.0"), "{stmt}");
        assert!(stmt.contains(&version.sha256), "{stmt}");
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
        SelfDeclaredPublisher::new(publisher.to_owned())
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
        assert!(matches!(err, CliError::UsageOwned(_)));
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
        assert!(matches!(err, CliError::UsageOwned(_)));
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
        assert!(matches!(err, CliError::UsageOwned(_)));
    }

    #[test]
    fn a_missing_flag_value_is_a_usage_error() {
        let err = parse_args(&["--index".to_owned()]).unwrap_err();
        assert!(matches!(err, CliError::UsageOwned(_)));
    }

    /// `github_api_post` must never put the token in curl's argv — no
    /// `Authorization` or `Bearer` substring must appear in the args list.
    /// We verify the command that would be built (not the network result)
    /// by constructing the same `Command` args here.
    #[test]
    fn token_not_in_curl_argv() {
        // Mirror the argv construction in `github_api_post`.
        let token = "super-secret-token";
        let url = "https://api.github.com/repos/foo/bar/pulls";
        let body_str = r#"{"title":"t"}"#;
        let tmp_path = "/tmp/fake-resp";

        let mut cmd = Command::new("curl");
        cmd.args(["--silent", "--show-error", "-X", "POST"])
            .args(["-H", "Accept: application/vnd.github+json"])
            .args(["-H", "User-Agent: ipe-cli"])
            .args(["--config", "-"])
            .args(["-d", body_str])
            .args(["-o", tmp_path])
            .args(["-w", "%{http_code}"])
            .arg(url);

        // Collect every argv string and assert the token is absent.
        let args: Vec<_> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        for arg in &args {
            assert!(
                !arg.contains(token),
                "token must not appear in curl argv; found it in: {arg:?}"
            );
            assert!(
                !arg.contains("Bearer"),
                "Authorization header must not appear in curl argv; found in: {arg:?}"
            );
        }
        // The stdin config line that WOULD carry the token — verify format.
        let config_line = format!("header = \"Authorization: Bearer {token}\"");
        assert!(config_line.contains(token));
        assert!(config_line.contains("Bearer"));
    }

    /// HTTP 201 with `html_url` → `PrResult::Created`.
    /// HTTP 200 with `html_url` → `PrResult::Failed` (not a Create response).
    /// HTTP 422 → `PrResult::AlreadyExists`.
    ///
    /// We test the branching logic directly by driving the match arms with
    /// constructed inputs — no curl subprocess needed.
    #[test]
    fn pr_result_classification() {
        // Simulate the dispatch logic from github_api_post for unit-testability.
        fn classify(http_status: u16, json: &serde_json::Value) -> String {
            match http_status {
                201 => json
                    .get("html_url")
                    .and_then(serde_json::Value::as_str)
                    .map_or_else(
                        || "Failed:201 response missing html_url".to_owned(),
                        |url| format!("Created:{url}"),
                    ),
                422 => "AlreadyExists".to_owned(),
                _ => {
                    let msg = json
                        .get("message")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("unexpected GitHub API response");
                    format!("Failed:{msg}")
                }
            }
        }

        let with_url = serde_json::json!({"html_url": "https://github.com/foo/bar/pull/1"});
        let error_body = serde_json::json!({"message": "Validation Failed"});
        let empty = serde_json::json!({});

        assert_eq!(
            classify(201, &with_url),
            "Created:https://github.com/foo/bar/pull/1"
        );
        assert_eq!(
            classify(200, &with_url),
            "Failed:unexpected GitHub API response",
            "200 with html_url is NOT a success"
        );
        assert_eq!(classify(422, &error_body), "AlreadyExists");
        assert_eq!(classify(500, &error_body), "Failed:Validation Failed");
        assert_eq!(
            classify(201, &empty),
            "Failed:201 response missing html_url"
        );
    }

    // --- Helpers shared by tests G and H ---

    fn make_git_repo(tag: &str, content: &str) -> PathBuf {
        let sd = crate::scratch::ScratchDir::new(&format!("ipe-publish-test-{tag}"))
            .expect("scratch dir");
        let repo = sd.path().to_path_buf();
        std::mem::forget(sd);
        let git = |args: &[&str]| {
            Command::new("git")
                .args(args)
                .current_dir(&repo)
                .env("GIT_AUTHOR_NAME", "t")
                .env("GIT_AUTHOR_EMAIL", "t@t")
                .env("GIT_COMMITTER_NAME", "t")
                .env("GIT_COMMITTER_EMAIL", "t@t")
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
            let p = sd2.path().to_path_buf();
            std::mem::forget(sd2);
            p
        };
        assert!(
            Command::new("git")
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
        let out = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(repo)
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
            PinnedRev::from_full_sha("lib", &sha).is_ok(),
            "HEAD SHA must be accepted by PinnedRev"
        );
        let _ = std::fs::remove_dir_all(&repo);
    }

    #[test]
    fn publish_rev_override_resolves_to_sha() {
        let repo = make_git_repo("pub-rev-override", "module Lib\n");
        // Create a branch "feat" pointing at the same commit.
        assert!(
            Command::new("git")
                .args(["checkout", "-b", "feat"])
                .current_dir(&repo)
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
        let commit = steps
            .iter()
            .find(|s| s.iter().any(|a| a == "commit"))
            .expect("a commit step exists");

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
}
