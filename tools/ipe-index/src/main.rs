mod coverage;
mod diff;
#[cfg(test)]
mod display_hazard_vectors;
mod extract;
#[cfg(test)]
mod extractor_digest;
mod model;
mod pipeline;
mod query;
mod repo_set;
mod static_re;
mod store;
mod walk;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::collections::HashMap;

#[derive(Parser)]
#[command(name = "ipe-index", version)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Rebuild every index table from the configured repos' tracked sources.
    /// The review queue is reconciled against the previous index, never reset.
    Index {
        /// Repo to index, as `tag:path` (repeatable). Default: this repo
        /// (`ipe:.`). Symbols/files are stored path-prefixed with the tag.
        #[arg(long, default_values_t = default_repos())]
        repo: Vec<String>,
        #[arg(long, default_value = ".ipe-index/index.db")]
        db: String,
    },
    /// Incrementally refresh the index: walk the same files `index` walks and
    /// re-extract each one whose content stamp changed. Falls back to a full
    /// `index` when the DB is absent, of another schema or root set, or holds
    /// a path with no stamp.
    Update {
        #[arg(long, default_values_t = default_repos())]
        repo: Vec<String>,
        #[arg(long, default_value = ".ipe-index/index.db")]
        db: String,
    },
    /// Import dependencies of a module (substring match).
    Deps {
        module: String,
        #[arg(long, default_value = ".ipe-index/index.db")]
        db: String,
    },
    /// File counts per role.
    Roles {
        #[arg(long, default_value = ".ipe-index/index.db")]
        db: String,
    },
    /// Compiler-stage module counts.
    Pipeline {
        #[arg(long, default_value = ".ipe-index/index.db")]
        db: String,
    },
    /// Fixtures/examples covering a module (substring match).
    Covers {
        kernel: String,
        #[arg(long, default_value = ".ipe-index/index.db")]
        db: String,
    },
    /// One-screen digest of the index.
    Wakeup {
        #[arg(long, default_value = ".ipe-index/index.db")]
        db: String,
    },
    /// Find all occurrences of a symbol name across the index. Each site is
    /// annotated with the unit's qualified name + uid so it feeds `callers` /
    /// `callees` / `context` directly.
    Locate {
        name: String,
        #[arg(long, default_value = ".ipe-index/index.db")]
        db: String,
    },
    /// Inbound blast radius: every unit that calls the target (a symbol name,
    /// qualified name, or uid). "Who breaks if this changes?"
    Callers {
        target: String,
        #[arg(long, default_value = ".ipe-index/index.db")]
        db: String,
    },
    /// Outbound dependencies: every unit the target calls (name/qualified/uid).
    /// "What does this change rely on?"
    Callees {
        target: String,
        #[arg(long, default_value = ".ipe-index/index.db")]
        db: String,
    },
    /// Review card for a unit (name/qualified/uid): location, kind, facing,
    /// purpose, and caller/callee counts — judge a change without opening it.
    Context {
        target: String,
        #[arg(long, default_value = ".ipe-index/index.db")]
        db: String,
    },
    /// Diff-scoped review entry point: the units a git range touches, as
    /// clickable `file:line-line kind qualified uid` coordinates. `<range>` is
    /// any git range, e.g. `main..HEAD`. Read-only.
    Changed {
        range: String,
        /// Repo to run `git diff` in (default: current directory).
        #[arg(long, default_value = ".")]
        repo: String,
        #[arg(long, default_value = ".ipe-index/index.db")]
        db: String,
    },
    /// Reverse dependencies: files/modules that import a given module or path.
    Rdeps {
        module: String,
        #[arg(long, default_value = ".ipe-index/index.db")]
        db: String,
        #[arg(long)]
        count: bool,
        /// Also match submodules (e.g. `Ipe.Core.List` also matches `Ipe.Core.List.Foo`).
        #[arg(long)]
        subtree: bool,
    },
    /// Outgoing links + calls of a unit (by uid).
    Links {
        uid: String,
        #[arg(long, default_value = ".ipe-index/index.db")]
        db: String,
    },
    /// Links + callgraph neighbors of a unit in both directions (by uid).
    Neighbors {
        uid: String,
        #[arg(long, default_value = ".ipe-index/index.db")]
        db: String,
    },
    /// Change-queue rows as JSON lines. `--since <sha>` excludes rows enqueued
    /// by that update run; `--limit N` caps the output.
    Pending {
        #[arg(long)]
        since: Option<String>,
        #[arg(long)]
        limit: Option<i64>,
        #[arg(long, default_value = ".ipe-index/index.db")]
        db: String,
    },
    /// Find all edit sites for a path rename (whole-segment match). `--to <new>`
    /// emits replacement paths. Read-only.
    RenamePath {
        old: String,
        #[arg(long)]
        to: Option<String>,
        #[arg(long, default_value = ".ipe-index/index.db")]
        db: String,
    },
    /// Find all resolved occurrences of a symbol name (units/links). `--to <new>`
    /// emits replacements; `--preserve <regex>...` skips matches; `--map k=v,...`
    /// correlates longest-key-first. Read-only.
    RenameSymbol {
        old: String,
        #[arg(long)]
        to: Option<String>,
        #[arg(long)]
        preserve: Vec<String>,
        #[arg(long)]
        map: Option<String>,
        #[arg(long, default_value = ".ipe-index/index.db")]
        db: String,
    },
}

/// The text of an admitted file, or `None` (reported when worth a line) when
/// [`walk::read_owned`] refuses it.
fn read_capped(
    repo: &repo_set::DeclaredRoot,
    rel: &str,
    claimed: &[&repo_set::DeclaredRoot],
) -> Option<String> {
    walk::read_owned(repo.root(), rel, claimed)
        .inspect_err(|refusal| {
            if refusal.is_reported() {
                eprintln!("ipe-index: not reading {}: {refusal}", walk::shown(rel));
            }
        })
        .ok()
}

/// Default repo set: this repo (`ipe:.`).
pub fn default_repos() -> Vec<String> {
    vec!["ipe:.".to_string()]
}

/// Parse a `tag:path` repo spec. The tag is load-bearing (path-prefix
/// disambiguation + role classification), so it must be a `RepoTag`: a tag
/// `split_tag` cannot read back would store every path as untagged.
fn parse_repo(spec: &str) -> Result<model::RepoSpec> {
    let bad = |why: &dyn std::fmt::Display| {
        anyhow::anyhow!("bad --repo spec {spec:?}: {why}; expected tag:path (e.g. ipe:.)")
    };
    let (tag, root) = spec.split_once(':').ok_or_else(|| bad(&"no `:`"))?;
    let tag = model::RepoTag::parse(tag).map_err(|e| bad(&e))?;
    if root.is_empty() {
        return Err(bad(&"the path is empty"));
    }
    Ok(model::RepoSpec {
        tag,
        root: root.to_string(),
    })
}

/// Parse the whole repo set: each spec, then one directory identity per tag
/// (see [`repo_set::RepoSet::parse`]).
fn parse_repos(specs: &[String]) -> Result<repo_set::RepoSet> {
    let specs = specs
        .iter()
        .map(|spec| parse_repo(spec))
        .collect::<Result<Vec<_>>>()?;
    Ok(repo_set::RepoSet::parse(&specs)?)
}

/// Store one file's rows (file, symbols, units, stage and coverage edges)
/// under its tagged path. The caller has already dropped any old rows.
///
/// The file's [`store::FileStamp`] is taken over `src`, the very text the
/// units are extracted from, so a stamp never names other bytes than its rows.
fn ingest_file(
    store: &store::Store,
    tagged: &str,
    lang: model::Lang,
    src: &str,
    sha: &str,
) -> Result<()> {
    // `walk` classified the role on the UNTAGGED path (before the tag is
    // known). Recompute the role on the tagged path so the tag-aware
    // classifier fires.
    let role = model::role_of(tagged);
    let stamp = store::FileStamp::of_bytes(src.as_bytes());
    store.put_file(
        tagged,
        lang.as_str(),
        role.as_str(),
        src.len() as i64,
        &stamp,
    )?;
    extract::extract_file(store, tagged, lang, src, sha)?;
    pipeline::record_stage(store, tagged)?;
    // Coverage is an Ipê-import relation, so it only applies to `.ipe`
    // example/fixture sources — a `.edits`/`.md`/`.json` under `examples/`
    // must not be Ipê-scanned for `import` lines.
    if lang == model::Lang::Ipe && (role == model::Role::Fixture || role == model::Role::Example) {
        coverage::record_coverage(store, tagged, src)?;
    }
    Ok(())
}

/// Apply the queue operations between two snapshots, each attributed to the
/// HEAD sha of the repo its unit belongs to (`""` for a repo no longer indexed).
fn reconcile_queue(
    store: &store::Store,
    before: &diff::Snapshot,
    after: &diff::Snapshot,
    shas: &HashMap<String, String>,
    now: i64,
) -> Result<()> {
    for op in diff::reconcile(before, after) {
        let sha = shas
            .get(model::split_tag(&op.path).0)
            .map_or("", String::as_str);
        store.apply(&op, sha, now)?;
    }
    Ok(())
}

/// A full rebuild over an open store, in one transaction: snapshot the units
/// the queue was last reconciled against, empty every index table, let
/// `ingest` refill them (recording each repo's `last_sha` meta and returning
/// each repo tag's HEAD sha), and reconcile
/// the queue from the old snapshot to the new one.
///
/// The queue is never reseeded from empty: a unit whose body is unchanged
/// keeps whatever row it had, or none if the review app drained it. Only a
/// store with no previous units (a first index) queues every unit as `new`.
/// A failure anywhere rolls back to the previous index and queue.
fn rebuild(
    store: &store::Store,
    ingest: impl FnOnce(&store::Store) -> Result<HashMap<String, String>>,
) -> Result<()> {
    store.begin()?;
    let built = (|| {
        let before = store.snapshot_all()?;
        store.reset_index()?;
        let shas = ingest(store)?;
        let after = store.snapshot_all()?;
        reconcile_queue(store, &before, &after, &shas, diff::now_millis())?;
        // Resolution passes over the merged store (tagged paths). Best-effort across tags.
        store.resolve_calls()?;
        query::resolve_edges(store, ".")
    })();
    match built {
        Ok(()) => store.commit(),
        Err(e) => {
            // The build error is the one worth reporting; a failed rollback
            // still leaves the transaction uncommitted.
            if let Err(rb) = store.rollback() {
                eprintln!("ipe-index: rollback after a failed rebuild: {rb}");
            }
            Err(e)
        }
    }
}

fn cmd_index(repo_specs: &[String], db: &str) -> Result<()> {
    index_set(&parse_repos(repo_specs)?, db)
}

/// A full index of the parsed root set, which the index records beside its rows.
fn index_set(repos: &repo_set::RepoSet, db: &str) -> Result<()> {
    if let Some(parent) = std::path::Path::new(db).parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).ok();
    }
    let store = store::Store::open(db)?;
    let mut total_files = 0usize;
    rebuild(&store, |store| {
        store.record_repos(&repos.recorded())?;
        let mut shas = HashMap::new();
        for repo in repos.iter() {
            let claimed = repos.claimed_in(repo);
            let files = walk::tracked(repo, &claimed)?;
            let sha = head_sha_or_empty(repo.root_str());
            for f in &files {
                let Some(src) = read_capped(repo, &f.path, &claimed) else {
                    continue;
                };
                // Store every path prefixed with the repo tag so multiple repos
                // never collide (each has Cargo.toml, README.md, scripts/*, tools/*).
                ingest_file(store, &repo.tag().tagged(&f.path), f.lang, &src, &sha)?;
            }
            // Per-repo HEAD sha the index was last built at.
            if !sha.is_empty() {
                store.set_meta(&repo.tag().last_sha_key(), &sha)?;
            }
            shas.insert(repo.tag().as_str().to_string(), sha);
            total_files += files.len();
        }
        Ok(shas)
    })?;
    eprintln!(
        "ipe-index: indexed {total_files} files across {} repo(s)",
        repos.iter().len()
    );
    Ok(())
}

fn head_sha_or_empty(root: &str) -> String {
    walk::head_sha(root).unwrap_or_else(|e| {
        eprintln!("ipe-index: no HEAD sha for {root}: {e}");
        String::new()
    })
}

/// Why `update` rebuilds the whole index instead of judging file by file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FullReason {
    /// The rows are of another schema version, so their hashes are of another format.
    SchemaVersion,
    /// The index was written by another ipe-index build, whose units may differ.
    Extractor,
    /// The index was built under another root set, so some path has another owner.
    RepoSet,
    /// Some indexed path carries no [`store::FileStamp`] to judge it by.
    NoStamps,
}

/// One declared root as an incremental `update` walks it.
struct RepoWalk<'a> {
    root: &'a repo_set::DeclaredRoot,
    claimed: Vec<&'a repo_set::DeclaredRoot>,
    /// The root's HEAD sha (`""` without one): the attribution of its rows and events.
    sha: String,
}

/// One path an incremental `update` must judge.
enum FileWork<'a> {
    /// A file the walk lists: read, and re-extracted when its stamp is not `stored`.
    Listed {
        repo: &'a RepoWalk<'a>,
        file: walk::Tracked,
        stored: Option<store::FileStamp>,
    },
    /// An indexed path no walk lists (deleted, ignored, no longer a regular
    /// file): its rows leave the index.
    Gone {
        tagged: String,
        repo: Option<&'a RepoWalk<'a>>,
    },
}

/// What an `update` does: judge each path, or rebuild the whole index.
enum UpdatePlan<'a> {
    Incremental(Vec<FileWork<'a>>),
    Full(FullReason),
}

/// The reason an index cannot be judged file by file before its stamps are
/// read, or `None` when its format, extractor and root set are this run's.
fn full_reason(store: &store::Store, repos: &repo_set::RepoSet) -> Result<Option<FullReason>> {
    if !store.schema_is_current()? {
        return Ok(Some(FullReason::SchemaVersion));
    }
    if !store.extractor_is_current()? {
        return Ok(Some(FullReason::Extractor));
    }
    if store.recorded_repos()? != repos.recorded() {
        return Ok(Some(FullReason::RepoSet));
    }
    Ok(None)
}

/// Plans an incremental `update` over the files [`walk::tracked`] lists, the
/// listing `index` reads, so the paths `update` judges are the paths a fresh
/// `index` of the same working tree would store.
fn plan_update<'a>(
    store: &store::Store,
    repos: &repo_set::RepoSet,
    walks: &'a [RepoWalk<'a>],
) -> Result<UpdatePlan<'a>> {
    if let Some(reason) = full_reason(store, repos)? {
        return Ok(UpdatePlan::Full(reason));
    }
    let Some(mut stamps) = store.stamps()? else {
        return Ok(UpdatePlan::Full(FullReason::NoStamps));
    };
    let mut work = Vec::new();
    for repo in walks {
        for file in walk::tracked(repo.root, &repo.claimed)? {
            let stored = stamps.remove(&repo.root.tag().tagged(&file.path));
            work.push(FileWork::Listed { repo, file, stored });
        }
    }
    let mut gone: Vec<String> = stamps.into_keys().collect();
    gone.sort();
    work.extend(gone.into_iter().map(|tagged| {
        let tag = model::split_tag(&tagged).0;
        let repo = walks.iter().find(|w| w.root.tag().as_str() == tag);
        FileWork::Gone { tagged, repo }
    }));
    Ok(UpdatePlan::Incremental(work))
}

/// Applies one path's work; returns whether its rows changed.
///
/// A listed file is read under the same ceiling as `index`. Equal stamps skip
/// it. A file that cannot be read (absent by now, over the ceiling, not UTF-8,
/// refused on disk) takes the delete branch, never the skip: its old units
/// must not stay open, or hidden, under bytes the tree no longer holds.
fn apply_work(store: &store::Store, work: &FileWork<'_>, now: i64) -> Result<bool> {
    let (tagged, sha, fresh) = match work {
        FileWork::Gone { tagged, repo } => {
            (tagged.clone(), repo.map_or("", |r| r.sha.as_str()), None)
        }
        FileWork::Listed { repo, file, stored } => {
            let src = read_capped(repo.root, &file.path, &repo.claimed);
            let unchanged = match (&src, stored) {
                (Some(src), Some(stored)) => store::FileStamp::of_bytes(src.as_bytes()) == *stored,
                (None, None) => true,
                (Some(_), None) | (None, Some(_)) => false,
            };
            if unchanged {
                return Ok(false);
            }
            (
                repo.root.tag().tagged(&file.path),
                repo.sha.as_str(),
                src.map(|src| (file.lang, src)),
            )
        }
    };
    let shas = HashMap::from([(model::split_tag(&tagged).0.to_string(), sha.to_string())]);
    let before = store.snapshot_path(&tagged)?;
    store.drop_file(&tagged)?;
    if let Some((lang, src)) = &fresh {
        ingest_file(store, &tagged, *lang, src, sha)?;
    }
    let after = store.snapshot_path(&tagged)?;
    reconcile_queue(store, &before, &after, &shas, now)?;
    Ok(true)
}

/// Incremental refresh: judge every file `index` would read by its stamp and
/// re-extract only the changed ones. Falls back to a full `index` when the DB
/// is absent or [`plan_update`] finds it cannot be judged file by file.
fn cmd_update(repo_specs: &[String], db: &str) -> Result<()> {
    let repos = parse_repos(repo_specs)?;
    if !std::path::Path::new(db).exists() {
        return index_set(&repos, db);
    }
    let walks: Vec<RepoWalk<'_>> = repos
        .iter()
        .map(|root| RepoWalk {
            root,
            claimed: repos.claimed_in(root),
            sha: head_sha_or_empty(root.root_str()),
        })
        .collect();
    let store = store::Store::open(db)?;
    store.begin()?;
    let applied = (|| -> Result<Result<usize, FullReason>> {
        let work = match plan_update(&store, &repos, &walks)? {
            UpdatePlan::Full(reason) => return Ok(Err(reason)),
            UpdatePlan::Incremental(work) => work,
        };
        // One timestamp per run so its events order stably (`enqueued_at` is
        // a tiebreaker in `pending`'s ORDER BY).
        let now = diff::now_millis();
        let mut changed = 0usize;
        for item in &work {
            if apply_work(&store, item, now)? {
                changed += 1;
            }
        }
        for repo in &walks {
            if !repo.sha.is_empty() {
                store.set_meta(&repo.root.tag().last_sha_key(), &repo.sha)?;
            }
        }
        store.resolve_calls()?;
        query::resolve_edges(&store, ".")?;
        Ok(Ok(changed))
    })();
    let outcome = match applied {
        Ok(outcome) => outcome,
        Err(e) => {
            if let Err(rb) = store.rollback() {
                eprintln!("ipe-index: rollback after a failed update: {rb}");
            }
            return Err(e);
        }
    };
    match outcome {
        Ok(changed) => {
            store.commit()?;
            eprintln!(
                "ipe-index: updated {changed} changed path(s) across {} repo(s)",
                repos.iter().len()
            );
            Ok(())
        }
        Err(reason) => {
            store.rollback()?;
            drop(store);
            eprintln!("ipe-index: {}; rebuilding the whole index", reason.why());
            index_set(&repos, db)
        }
    }
}

impl FullReason {
    /// Why the run rebuilds, as a clause for its stderr line.
    const fn why(self) -> &'static str {
        match self {
            Self::SchemaVersion => "the index is of another schema version",
            Self::Extractor => "the index was written by another ipe-index build",
            Self::RepoSet => "the index was built under another root set",
            Self::NoStamps => "an indexed path has no content stamp",
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Index { repo, db } => cmd_index(&repo, &db),
        Cmd::Update { repo, db } => cmd_update(&repo, &db),
        Cmd::Deps { module, db } => query::cmd_deps(&db, &module),
        Cmd::Roles { db } => query::cmd_roles(&db),
        Cmd::Pipeline { db } => query::cmd_pipeline(&db),
        Cmd::Covers { kernel, db } => query::cmd_covers(&db, &kernel),
        Cmd::Wakeup { db } => query::cmd_wakeup(&db),
        Cmd::Locate { name, db } => query::cmd_locate(&db, &name),
        Cmd::Callers { target, db } => query::cmd_callers(&db, &target),
        Cmd::Callees { target, db } => query::cmd_callees(&db, &target),
        Cmd::Context { target, db } => query::cmd_context(&db, &target),
        Cmd::Changed { range, repo, db } => query::cmd_changed(&db, &repo, &range),
        Cmd::Rdeps {
            module,
            db,
            count,
            subtree,
        } => query::cmd_rdeps(&db, &module, count, subtree),
        Cmd::Links { uid, db } => query::cmd_links(&db, &uid),
        Cmd::Neighbors { uid, db } => query::cmd_neighbors(&db, &uid),
        Cmd::Pending { since, limit, db } => query::cmd_pending(&db, since.as_deref(), limit),
        Cmd::RenamePath { old, to, db } => query::cmd_rename_path(&db, &old, to.as_deref()),
        Cmd::RenameSymbol {
            old,
            to,
            preserve,
            map,
            db,
        } => query::cmd_rename_symbol(&db, &old, to.as_deref(), &preserve, map.as_deref()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repos() -> repo_set::RepoSet {
        parse_repos(&default_repos()).unwrap()
    }

    #[test]
    fn a_current_db_of_this_root_set_is_judged_file_by_file() {
        let s = store::Store::open(":memory:").unwrap();
        let set = repos();
        s.record_repos(&set.recorded()).unwrap();
        assert_eq!(full_reason(&s, &set).unwrap(), None);
    }

    #[test]
    fn a_db_with_no_recorded_root_set_rebuilds() {
        let s = store::Store::open(":memory:").unwrap();
        assert_eq!(
            full_reason(&s, &repos()).unwrap(),
            Some(FullReason::RepoSet)
        );
    }

    // Rows of an older schema carry hashes in the old format; an incremental
    // update would keep them for every unchanged file, so it rebuilds instead.
    #[test]
    fn older_schema_rebuilds() {
        let s = store::Store::open(":memory:").unwrap();
        let set = repos();
        s.record_repos(&set.recorded()).unwrap();
        s.set_meta("schema_version", "2").unwrap();
        assert_eq!(
            full_reason(&s, &set).unwrap(),
            Some(FullReason::SchemaVersion)
        );
    }

    // Rows another extractor wrote are kept for every unchanged file by an
    // incremental update, so a recorded extractor other than this build's
    // rebuilds.
    #[test]
    fn update_after_an_extractor_change_takes_full_index() {
        let s = store::Store::open(":memory:").unwrap();
        let set = repos();
        s.record_repos(&set.recorded()).unwrap();
        s.set_meta("extractor", "blake3:another-build").unwrap();
        assert_eq!(full_reason(&s, &set).unwrap(), Some(FullReason::Extractor));
    }

    // An index that records no extractor names no build that wrote it, so it
    // rebuilds too.
    #[test]
    fn an_index_without_an_extractor_stamp_takes_full_index() {
        let s = store::Store::open(":memory:").unwrap();
        let set = repos();
        s.record_repos(&set.recorded()).unwrap();
        s.conn
            .execute("DELETE FROM meta WHERE k='extractor'", [])
            .unwrap();
        assert_eq!(full_reason(&s, &set).unwrap(), Some(FullReason::Extractor));
    }

    fn refusal(spec: &str) -> String {
        parse_repo(spec)
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default()
    }

    // Each tag `split_tag` would misread is refused at the flag, so no path is
    // ever stored under it.
    #[test]
    fn parse_repo_refuses_unreadable_tags() {
        assert!(refusal("a/b:root").contains("holds a `/`"));
        assert!(refusal(":root").contains("is empty"));
        assert!(refusal("ipe").contains("no `:`"));
        assert!(refusal("ipe:").contains("path is empty"));
        let ok = parse_repo("a:b:root").unwrap();
        assert_eq!((ok.tag.as_str(), ok.root.as_str()), ("a", "b:root"));
    }

    #[test]
    fn parse_repos_refuses_a_twice_bound_tag_and_an_empty_set() {
        let twice = vec!["ipe:.".to_string(), "ipe:../other".to_string()];
        let err = parse_repos(&twice).err().map(|e| e.to_string());
        assert!(err.is_some_and(|e| e.contains("given twice")));
        let none = parse_repos(&[]).err().map(|e| e.to_string());
        assert!(none.is_some_and(|e| e.contains("no --repo")));
    }

    const PATH: &str = "ipe:tools/x/src/lib.rs";
    const BASE: &str =
        "use std::fmt;\n\nfn alpha() -> u8 {\n    1\n}\n\nfn beta() -> u8 {\n    2\n}\n";
    const CHILD_EDIT: &str =
        "use std::fmt;\n\nfn alpha() -> u8 {\n    3\n}\n\nfn beta() -> u8 {\n    2\n}\n";
    const TOP_EDIT: &str = "use std::fmt;\nuse std::io;\n\nfn alpha() -> u8 {\n    1\n}\n\nfn beta() -> u8 {\n    2\n}\n";

    /// Rebuild `store` from `files` (tagged path → Rust source) at `sha`.
    fn rebuild_from(store: &store::Store, files: &[(&str, &str)], sha: &str) {
        rebuild(store, |s| {
            for (path, src) in files {
                ingest_file(s, path, model::Lang::Rust, src, sha)?;
            }
            Ok(HashMap::from([("ipe".to_string(), sha.to_string())]))
        })
        .unwrap();
    }

    /// `(uid, change, new_hash, enqueued_sha)` for every queue row, by uid.
    fn queue(store: &store::Store) -> Vec<(String, String, Option<String>, String)> {
        let mut st = store
            .conn
            .prepare("SELECT uid, change, new_hash, enqueued_sha FROM change_queue ORDER BY uid")
            .unwrap();
        st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .unwrap()
            .collect::<std::result::Result<_, _>>()
            .unwrap()
    }

    fn uid_of(store: &store::Store, kind: &str, name: &str) -> String {
        store
            .conn
            .query_row(
                "SELECT uid FROM units WHERE kind=? AND name=?",
                [kind, name],
                |r| r.get(0),
            )
            .unwrap()
    }

    fn body_of(store: &store::Store, uid: &str) -> String {
        store
            .conn
            .query_row("SELECT body_hash FROM units WHERE uid=?", [uid], |r| {
                r.get(0)
            })
            .unwrap()
    }

    fn drain_all(store: &store::Store) {
        store.conn.execute("DELETE FROM change_queue", []).unwrap();
    }

    #[test]
    fn a_first_index_queues_every_unit_new() {
        let s = store::Store::open(":memory:").unwrap();
        rebuild_from(&s, &[(PATH, BASE)], "s1");
        let rows = queue(&s);
        assert_eq!(rows.len() as i64, s.count("units").unwrap());
        assert!(
            rows.iter()
                .all(|(_, change, _, sha)| change == "new" && sha == "s1")
        );
    }

    // The defect this pins: a rebuild that reseeds the queue from an empty
    // baseline re-queues every drained unit as `new`.
    #[test]
    fn a_rebuild_never_requeues_drained_units() {
        let s = store::Store::open(":memory:").unwrap();
        rebuild_from(&s, &[(PATH, BASE)], "s1");
        assert!(!queue(&s).is_empty());
        drain_all(&s);
        rebuild_from(&s, &[(PATH, BASE)], "s2");
        assert_eq!(queue(&s), Vec::new());
    }

    #[test]
    fn a_rebuild_keeps_an_undrained_row_as_it_was() {
        let s = store::Store::open(":memory:").unwrap();
        rebuild_from(&s, &[(PATH, BASE)], "s1");
        let beta = uid_of(&s, "fn", "beta");
        s.conn
            .execute("DELETE FROM change_queue WHERE uid != ?", [beta.as_str()])
            .unwrap();
        let kept = queue(&s);
        rebuild_from(&s, &[(PATH, BASE)], "s2");
        assert_eq!(queue(&s), kept);
    }

    // A change inside a child queues the child alone, not the whole file too.
    #[test]
    fn a_child_edit_queues_the_child_alone() {
        let s = store::Store::open(":memory:").unwrap();
        rebuild_from(&s, &[(PATH, BASE)], "s1");
        drain_all(&s);
        rebuild_from(&s, &[(PATH, CHILD_EDIT)], "s2");
        let alpha = uid_of(&s, "fn", "alpha");
        let want = vec![(
            alpha.clone(),
            "modified".to_string(),
            Some(body_of(&s, &alpha)),
            "s2".to_string(),
        )];
        assert_eq!(queue(&s), want);
    }

    // A top-level line no child covers is reviewed through the file unit.
    #[test]
    fn a_top_level_edit_queues_the_file() {
        let s = store::Store::open(":memory:").unwrap();
        rebuild_from(&s, &[(PATH, BASE)], "s1");
        drain_all(&s);
        rebuild_from(&s, &[(PATH, TOP_EDIT)], "s2");
        let file = uid_of(&s, "file", "lib.rs");
        let changed: Vec<(String, String)> = queue(&s)
            .into_iter()
            .map(|(uid, change, _, _)| (uid, change))
            .collect();
        assert_eq!(changed, vec![(file, "modified".to_string())]);
    }

    // A pending file row tracks the file's current body, so the review app can
    // still drain it once a child edit moves the file's attested hash.
    #[test]
    fn a_pending_file_row_follows_its_body() {
        let s = store::Store::open(":memory:").unwrap();
        rebuild_from(&s, &[(PATH, BASE)], "s1");
        let file = uid_of(&s, "file", "lib.rs");
        s.conn
            .execute("DELETE FROM change_queue WHERE uid != ?", [file.as_str()])
            .unwrap();
        rebuild_from(&s, &[(PATH, CHILD_EDIT)], "s2");
        let rows = queue(&s);
        let file_row = rows.iter().find(|(uid, ..)| *uid == file);
        assert_eq!(
            file_row.map(|(_, change, hash, sha)| (change.as_str(), hash.clone(), sha.as_str())),
            Some(("new", Some(body_of(&s, &file)), "s1"))
        );
    }

    #[test]
    fn a_removed_file_queues_its_units_deleted() {
        let s = store::Store::open(":memory:").unwrap();
        rebuild_from(&s, &[(PATH, BASE)], "s1");
        let units = s.count("units").unwrap();
        drain_all(&s);
        rebuild_from(&s, &[], "s2");
        let rows = queue(&s);
        assert_eq!(rows.len() as i64, units);
        assert!(
            rows.iter()
                .all(|(_, change, hash, _)| change == "deleted" && hash.is_none())
        );
    }

    /// The attestation of the whole of `src`, which a pre-residual index
    /// stored as a file unit's `body_hash`.
    fn whole_file_hash(src: &str) -> String {
        let whole = extract::view::view_text(src, 1, extract::view::view_line_count(src)).unwrap();
        extract::view::attest(&whole)
    }

    // A rebuild over an older-schema index (no `residual_hash`, file units
    // attesting the whole file) keeps its queue: unchanged children stay
    // drained, and each file unit is queued once because its change key
    // cannot be compared across the schemas.
    #[test]
    fn a_rebuild_over_an_older_schema_keeps_the_queue() {
        let s = store::Store::open(":memory:").unwrap();
        rebuild_from(&s, &[(PATH, BASE)], "s1");
        drain_all(&s);
        s.conn
            .execute(
                "UPDATE units SET body_hash=? WHERE kind='file'",
                [whole_file_hash(BASE)],
            )
            .unwrap();
        s.conn
            .execute_batch(
                "ALTER TABLE units DROP COLUMN residual_hash; \
                 UPDATE meta SET v='3' WHERE k='schema_version';",
            )
            .unwrap();
        rebuild_from(&s, &[(PATH, BASE)], "s2");
        let file = uid_of(&s, "file", "lib.rs");
        let changed: Vec<(String, String)> = queue(&s)
            .into_iter()
            .map(|(uid, change, _, _)| (uid, change))
            .collect();
        assert_eq!(changed, vec![(file, "modified".to_string())]);
        assert!(s.schema_is_current().unwrap());
    }

    // A rebuild over a v4 index, whose file unit attested the whole file and
    // kept its residual beside it, re-points the pending file row at the
    // residual attestation, so the review app's drain of the shown residual
    // matches. Nothing else is queued.
    #[test]
    fn a_rebuild_over_a_v4_index_repoints_a_pending_file_row() {
        let s = store::Store::open(":memory:").unwrap();
        rebuild_from(&s, &[(PATH, BASE)], "s1");
        let file = uid_of(&s, "file", "lib.rs");
        let residual = body_of(&s, &file);
        let whole = whole_file_hash(BASE);
        assert_ne!(residual, whole);
        s.conn
            .execute("DELETE FROM change_queue WHERE uid != ?", [file.as_str()])
            .unwrap();
        s.conn
            .execute(
                "UPDATE units SET residual_hash=body_hash, body_hash=? WHERE kind='file'",
                [whole.as_str()],
            )
            .unwrap();
        s.conn
            .execute(
                "UPDATE change_queue SET new_hash=? WHERE uid=?",
                [whole.as_str(), file.as_str()],
            )
            .unwrap();
        s.conn
            .execute_batch("UPDATE meta SET v='4' WHERE k='schema_version';")
            .unwrap();
        assert!(!s.schema_is_current().unwrap());
        rebuild_from(&s, &[(PATH, BASE)], "s2");
        assert_eq!(
            queue(&s),
            vec![(
                file.clone(),
                "new".to_string(),
                Some(residual.clone()),
                "s1".to_string()
            )]
        );
        assert_eq!(body_of(&s, &file), residual);
        assert!(s.schema_is_current().unwrap());
    }

    /// The stored file paths of the index at `db`, sorted.
    #[cfg(unix)]
    fn stored_files(db: &str) -> Vec<String> {
        let s = store::Store::open(db).unwrap();
        let mut st = s
            .conn
            .prepare("SELECT path FROM files ORDER BY path")
            .unwrap();
        st.query_map([], |r| r.get(0))
            .unwrap()
            .collect::<std::result::Result<_, _>>()
            .unwrap()
    }

    // A root declared inside another owns its files: they are stored under its
    // tag alone, never under the outer tag too.
    #[cfg(unix)]
    #[test]
    fn nested_root_files_owned_by_inner_only() {
        let fx = walk::fixture::Fixture::new("index-nested");
        fx.write("top.rs", "fn t() {}\n");
        fx.write("inner/x.rs", "fn x() {}\n");
        fx.commit("one");
        let db = fx.path(".git/ipe-index.db");
        let specs = [
            format!("out:{}", fx.root()),
            format!("in:{}", fx.path("inner")),
        ];
        cmd_index(&specs, &db).unwrap();
        assert_eq!(stored_files(&db), ["in:x.rs", "out:top.rs"]);
    }

    // Any change to the root set rebuilds the index, so the rows of a path's
    // previous owner never survive beside its new owner's (or its absence).
    #[cfg(unix)]
    #[test]
    fn root_set_change_forces_full_index() {
        let fx = walk::fixture::Fixture::new("index-root-set");
        fx.write("top.rs", "fn t() {}\n");
        fx.write("inner/x.rs", "fn x() {}\n");
        fx.commit("one");
        let db = fx.path(".git/ipe-index.db");
        let out = format!("out:{}", fx.root());
        let both = [out.clone(), format!("in:{}", fx.path("inner"))];
        cmd_index(std::slice::from_ref(&out), &db).unwrap();
        assert_eq!(stored_files(&db), ["out:inner/x.rs", "out:top.rs"]);
        {
            let s = store::Store::open(&db).unwrap();
            assert_eq!(
                full_reason(&s, &parse_repos(&both).unwrap()).unwrap(),
                Some(FullReason::RepoSet)
            );
        }
        cmd_update(&both, &db).unwrap();
        assert_eq!(stored_files(&db), ["in:x.rs", "out:top.rs"]);
        cmd_update(std::slice::from_ref(&out), &db).unwrap();
        assert_eq!(stored_files(&db), ["out:inner/x.rs", "out:top.rs"]);
    }

    // A rebuild that fails part-way leaves the previous index and queue.
    #[test]
    fn a_failed_rebuild_keeps_the_previous_index() {
        let s = store::Store::open(":memory:").unwrap();
        rebuild_from(&s, &[(PATH, BASE)], "s1");
        let units = s.count("units").unwrap();
        let rows = queue(&s);
        let failed = rebuild(&s, |_| Err(anyhow::anyhow!("extract failed")));
        assert!(
            failed
                .err()
                .is_some_and(|e| e.to_string() == "extract failed")
        );
        assert_eq!(s.count("units").unwrap(), units);
        assert_eq!(queue(&s), rows);
    }

    /// The review-visible rows of the index at `db`: every open unit (queue
    /// columns aside, which differ between a first index and an update by
    /// design), every file with its stamp, every edge with its resolution,
    /// every call site, and every callgraph edge.
    #[cfg(unix)]
    fn index_dump(db: &str) -> Vec<String> {
        let s = store::Store::open(db).unwrap();
        let mut rows = Vec::new();
        for sql in [
            "SELECT 'unit|' || uid || '|' || path || '|' || COALESCE(kind, '') || '|' \
             || COALESCE(name, '') || '|' || COALESCE(qualified, '') || '|' \
             || COALESCE(line_start, '') || '|' || COALESCE(line_end, '') || '|' \
             || COALESCE(body_hash, '') || '|' || COALESCE(lang, '') \
             FROM open_units ORDER BY uid",
            "SELECT 'file|' || path || '|' || COALESCE(sha, '') FROM files ORDER BY path",
            "SELECT 'edge|' || src || '|' || dst || '|' || kind || '|' \
             || COALESCE(resolved, '') FROM edges ORDER BY 1",
            "SELECT 'site|' || caller_uid || '|' || path || '|' || exact || '|' \
             || COALESCE(local, '') FROM call_sites ORDER BY 1",
            "SELECT 'call|' || caller_uid || '|' || callee_uid FROM callgraph ORDER BY 1",
        ] {
            let mut st = s.conn.prepare(sql).unwrap();
            let got: Vec<String> = st
                .query_map([], |r| r.get(0))
                .unwrap()
                .collect::<std::result::Result<_, _>>()
                .unwrap();
            rows.extend(got);
        }
        rows
    }

    /// Runs `update` on `db`, then a fresh `index` of the same working tree
    /// into a second DB, and asserts both hold the same rows. Returns the dump.
    #[cfg(unix)]
    fn update_then_compare(fx: &walk::fixture::Fixture, specs: &[String], db: &str) -> Vec<String> {
        cmd_update(specs, db).unwrap();
        let fresh = fx.path(".git/fresh-index.db");
        let _ = std::fs::remove_file(&fresh);
        cmd_index(specs, &fresh).unwrap();
        let updated = index_dump(db);
        assert_eq!(updated, index_dump(&fresh));
        updated
    }

    /// `(updated_sha)` of every unit of `path` in the index at `db`.
    #[cfg(unix)]
    fn updated_shas(db: &str, path: &str) -> Vec<String> {
        let s = store::Store::open(db).unwrap();
        let mut st = s
            .conn
            .prepare("SELECT updated_sha FROM units WHERE path=? ORDER BY uid")
            .unwrap();
        st.query_map([path], |r| r.get(0))
            .unwrap()
            .collect::<std::result::Result<_, _>>()
            .unwrap()
    }

    // `update` judges the files `index` lists, by content: whatever the working
    // tree did since the last run (committed or not, tracked or not), the open
    // units after `update` are the open units of a fresh `index`. A file whose
    // bytes are back to the stamped ones is not re-extracted.
    #[cfg(unix)]
    #[test]
    fn update_membership_equals_index() {
        const A: &str = "fn a() -> u8 {\n    1\n}\n";
        const A_EDIT: &str = "fn a() -> u8 {\n    2\n}\n\nfn a2() {}\n";
        type Change = fn(&walk::fixture::Fixture);
        let rows: [(&str, Change, bool, bool); 7] = [
            (
                "untracked file added",
                |fx| fx.write("new.rs", "fn n() {}\n"),
                true,
                true,
            ),
            (
                "untracked file removed",
                |fx| std::fs::remove_file(fx.0.join("u.rs")).unwrap(),
                true,
                true,
            ),
            (
                "tracked file deleted without commit",
                |fx| std::fs::remove_file(fx.0.join("b.rs")).unwrap(),
                true,
                true,
            ),
            (
                "tracked file edited without commit",
                |fx| fx.write("a.rs", A_EDIT),
                true,
                false,
            ),
            (
                "untracked file newly ignored",
                |fx| fx.write(".gitignore", "u.rs\n"),
                true,
                true,
            ),
            (
                "tracked file replaced by a symlink on disk",
                |fx| {
                    std::fs::remove_file(fx.0.join("b.rs")).unwrap();
                    std::os::unix::fs::symlink("a.rs", fx.0.join("b.rs")).unwrap();
                },
                true,
                true,
            ),
            (
                "edit then revert",
                |fx| {
                    fx.write("a.rs", A_EDIT);
                    fx.write("a.rs", A);
                },
                false,
                true,
            ),
        ];
        for (i, (row, change, moves, a_kept)) in rows.into_iter().enumerate() {
            let fx = walk::fixture::Fixture::new(&format!("update-membership-{i}"));
            fx.write("a.rs", A);
            fx.write("b.rs", "fn b() {}\n");
            fx.commit("one");
            fx.write("u.rs", "fn u() {}\n");
            let specs = [format!("ipe:{}", fx.root())];
            let db = fx.path(".git/ipe-index.db");
            cmd_index(&specs, &db).unwrap();
            let before = index_dump(&db);
            {
                let s = store::Store::open(&db).unwrap();
                s.conn
                    .execute(
                        "UPDATE units SET updated_sha='kept' WHERE path='ipe:a.rs'",
                        [],
                    )
                    .unwrap();
            }
            change(&fx);
            let after = update_then_compare(&fx, &specs, &db);
            assert_eq!(after != before, moves, "{row}: rows moved");
            let kept = updated_shas(&db, "ipe:a.rs")
                .iter()
                .all(|sha| sha == "kept");
            assert_eq!(kept, a_kept, "{row}: `ipe:a.rs` re-extracted");
        }
    }

    // An import resolution belongs to the current file set, not to the run
    // that extracted the importing file: deleting the target of an unchanged
    // file's import leaves that import unresolved, as a fresh `index` stores
    // it, and restoring the target resolves it again.
    #[cfg(unix)]
    #[test]
    fn update_reresolves_imports_of_unchanged_files() {
        let fx = walk::fixture::Fixture::new("update-reresolve");
        fx.write("src/a.rs", "use crate::b;\n\nfn a() {}\n");
        fx.write("src/b.rs", "pub fn b() {}\n");
        fx.commit("one");
        let specs = [format!("ipe:{}", fx.root())];
        let db = fx.path(".git/ipe-index.db");
        cmd_index(&specs, &db).unwrap();
        let resolved = |db: &str| -> Vec<Option<String>> {
            let s = store::Store::open(db).unwrap();
            let mut st = s
                .conn
                .prepare("SELECT resolved FROM edges WHERE src='ipe:src/a.rs' AND kind='import'")
                .unwrap();
            st.query_map([], |r| r.get(0))
                .unwrap()
                .collect::<std::result::Result<_, _>>()
                .unwrap()
        };
        let target = Some("ipe:src/b.rs".to_string());
        assert_eq!(resolved(&db), std::slice::from_ref(&target));
        std::fs::remove_file(fx.0.join("src/b.rs")).unwrap();
        update_then_compare(&fx, &specs, &db);
        assert_eq!(resolved(&db), [None]);
        fx.write("src/b.rs", "pub fn b() {}\n");
        update_then_compare(&fx, &specs, &db);
        assert_eq!(resolved(&db), std::slice::from_ref(&target));
    }

    // An indexed file that is now over the read ceiling, or no longer UTF-8,
    // takes the delete branch: its old units leave the index, as a fresh
    // `index` would never have stored them.
    #[cfg(unix)]
    #[test]
    fn update_drops_unreadable_and_oversized() {
        let fx = walk::fixture::Fixture::new("update-unreadable");
        fx.write("a.rs", "fn a() {}\n");
        fx.write("big.rs", "fn big() {}\n");
        fx.write("bin.rs", "fn bin() {}\n");
        fx.commit("one");
        let specs = [format!("ipe:{}", fx.root())];
        let db = fx.path(".git/ipe-index.db");
        cmd_index(&specs, &db).unwrap();
        assert_eq!(stored_files(&db), ["ipe:a.rs", "ipe:big.rs", "ipe:bin.rs"]);
        let over = usize::try_from(walk::MAX_FILE_BYTES).unwrap() + 1;
        fx.write("big.rs", &format!("fn big() {{}}\n{}", "/".repeat(over)));
        std::fs::write(fx.0.join("bin.rs"), b"fn bin() {}\n\xff\n").unwrap();
        update_then_compare(&fx, &specs, &db);
        assert_eq!(stored_files(&db), ["ipe:a.rs"]);
        let s = store::Store::open(&db).unwrap();
        let left: i64 = s
            .conn
            .query_row(
                "SELECT COUNT(*) FROM units WHERE path IN ('ipe:big.rs', 'ipe:bin.rs')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(left, 0);
    }

    // A v8 index stores `""` where a stamp belongs: `update` cannot judge its
    // files, so it rebuilds, and the store reads version 10 only once the full
    // run has stamped every file. The same rows under the current version
    // still rebuild, for want of stamps.
    #[cfg(unix)]
    #[test]
    fn update_on_v8_store_takes_full_index() {
        let fx = walk::fixture::Fixture::new("update-v8");
        fx.write("a.rs", "fn a() {}\n");
        fx.commit("one");
        let specs = [format!("ipe:{}", fx.root())];
        let db = fx.path(".git/ipe-index.db");
        cmd_index(&specs, &db).unwrap();
        let repos = parse_repos(&specs).unwrap();
        let walks: Vec<RepoWalk<'_>> = repos
            .iter()
            .map(|root| RepoWalk {
                root,
                claimed: repos.claimed_in(root),
                sha: String::new(),
            })
            .collect();
        let plan_of = |s: &store::Store| match plan_update(s, &repos, &walks).unwrap() {
            UpdatePlan::Full(reason) => Some(reason),
            UpdatePlan::Incremental(_) => None,
        };
        {
            let s = store::Store::open(&db).unwrap();
            assert_eq!(plan_of(&s), None);
            s.conn
                .execute_batch(
                    "PRAGMA ignore_check_constraints = ON; \
                     UPDATE files SET sha = ''; \
                     PRAGMA ignore_check_constraints = OFF;",
                )
                .unwrap();
            assert_eq!(plan_of(&s), Some(FullReason::NoStamps));
            s.set_meta("schema_version", "8").unwrap();
            assert_eq!(plan_of(&s), Some(FullReason::SchemaVersion));
        }
        fx.write("a.rs", "fn a() {}\n\nfn b() {}\n");
        update_then_compare(&fx, &specs, &db);
        let s = store::Store::open(&db).unwrap();
        assert_eq!(s.get_meta("schema_version").unwrap().as_deref(), Some("10"));
        assert!(s.stamps().unwrap().is_some_and(|st| st.len() == 1));
        assert_eq!(plan_of(&s), None);
    }

    /// Every `callgraph` edge of the index at `db` as `(caller, callee)`
    /// qualified names, sorted, and the count of edges naming a uid no unit has.
    #[cfg(unix)]
    fn call_edges(db: &str) -> (Vec<(String, String)>, i64) {
        let s = store::Store::open(db).unwrap();
        let mut st = s
            .conn
            .prepare(
                "SELECT cu.qualified, ce.qualified FROM callgraph cg \
                 JOIN units cu ON cu.uid = cg.caller_uid \
                 JOIN units ce ON ce.uid = cg.callee_uid ORDER BY 1, 2",
            )
            .unwrap();
        let edges = st
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<std::result::Result<_, _>>()
            .unwrap();
        let dangling = s
            .conn
            .query_row(
                "SELECT COUNT(*) FROM callgraph \
                 WHERE caller_uid NOT IN (SELECT uid FROM units) \
                 OR callee_uid NOT IN (SELECT uid FROM units)",
                [],
                |r| r.get(0),
            )
            .unwrap();
        (edges, dangling)
    }

    /// The one call `z` makes into `b`, as [`call_edges`] lists it.
    #[cfg(unix)]
    fn z_calls_b() -> (Vec<(String, String)>, i64) {
        (vec![("crate::z".to_string(), "crate::b".to_string())], 0)
    }

    // The caller sorts after its callee, so a fresh `index` holds the call.
    // Re-extracting only the callee's file keeps the unchanged caller's call.
    #[cfg(unix)]
    #[test]
    fn update_keeps_calls_into_a_reextracted_file() {
        let fx = walk::fixture::Fixture::new("update-calls-reextract");
        fx.write("src/b.rs", "pub fn b() {}\n");
        fx.write("src/z.rs", "pub fn z() { b(); }\n");
        fx.commit("one");
        let specs = [format!("ipe:{}", fx.root())];
        let db = fx.path(".git/ipe-index.db");
        cmd_index(&specs, &db).unwrap();
        assert_eq!(call_edges(&db), z_calls_b());
        fx.write("src/b.rs", "pub fn b() {}\n\npub fn c() {}\n");
        update_then_compare(&fx, &specs, &db);
        assert_eq!(call_edges(&db), z_calls_b());
    }

    // A callee file added under an unchanged caller gains the caller's call.
    #[cfg(unix)]
    #[test]
    fn update_adds_calls_into_an_added_file() {
        let fx = walk::fixture::Fixture::new("update-calls-add");
        fx.write("src/z.rs", "pub fn z() { b(); }\n");
        fx.commit("one");
        let specs = [format!("ipe:{}", fx.root())];
        let db = fx.path(".git/ipe-index.db");
        cmd_index(&specs, &db).unwrap();
        assert_eq!(call_edges(&db), (Vec::new(), 0));
        fx.write("src/b.rs", "pub fn b() {}\n");
        update_then_compare(&fx, &specs, &db);
        assert_eq!(call_edges(&db), z_calls_b());
    }

    // A deleted callee file takes the calls into it along, and leaves no
    // edge naming a unit the index no longer holds.
    #[cfg(unix)]
    #[test]
    fn update_drops_calls_into_a_deleted_file() {
        let fx = walk::fixture::Fixture::new("update-calls-delete");
        fx.write("src/b.rs", "pub fn b() {}\n");
        fx.write("src/z.rs", "pub fn z() { b(); }\n");
        fx.commit("one");
        let specs = [format!("ipe:{}", fx.root())];
        let db = fx.path(".git/ipe-index.db");
        cmd_index(&specs, &db).unwrap();
        assert_eq!(call_edges(&db), z_calls_b());
        std::fs::remove_file(fx.0.join("src/b.rs")).unwrap();
        update_then_compare(&fx, &specs, &db);
        assert_eq!(call_edges(&db), (Vec::new(), 0));
    }

    // A root below the top of its work tree walks relative to itself: a file
    // outside it never enters, and a file inside it is named from the root.
    #[cfg(unix)]
    #[test]
    fn update_in_subdir_root_is_root_relative() {
        let fx = walk::fixture::Fixture::new("subdir-update");
        fx.write("sub/x.rs", "fn a() {}\n");
        fx.write("top.rs", "fn t() {}\n");
        fx.commit("one");
        let specs = [format!("sub:{}", fx.path("sub"))];
        let db = fx.path(".git/ipe-index.db");
        cmd_index(&specs, &db).unwrap();
        fx.write("sub/x.rs", "fn b() {}\n");
        fx.write("top.rs", "fn u() {}\n");
        update_then_compare(&fx, &specs, &db);
        assert_eq!(stored_files(&db), ["sub:x.rs"]);
    }

    // A file under a declared inner root is judged by that root alone: the
    // outer root's update neither stores nor deletes it.
    #[cfg(unix)]
    #[test]
    fn update_skips_claimed_paths() {
        let fx = walk::fixture::Fixture::new("claimed-update");
        fx.write("top.rs", "fn t() {}\n");
        fx.write("inner/x.rs", "fn x() {}\n");
        fx.write("inner/y.rs", "fn y() {}\n");
        fx.commit("one");
        let specs = [
            format!("out:{}", fx.root()),
            format!("in:{}", fx.path("inner")),
        ];
        let db = fx.path(".git/ipe-index.db");
        cmd_index(&specs, &db).unwrap();
        assert_eq!(stored_files(&db), ["in:x.rs", "in:y.rs", "out:top.rs"]);
        fx.write("top.rs", "fn u() {}\n");
        fx.write("inner/x.rs", "fn z() {}\n");
        std::fs::remove_file(fx.0.join("inner/y.rs")).unwrap();
        update_then_compare(&fx, &specs, &db);
        assert_eq!(stored_files(&db), ["in:x.rs", "out:top.rs"]);
    }
}
