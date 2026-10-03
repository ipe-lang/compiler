mod coverage;
mod diff;
#[cfg(test)]
mod display_hazard_vectors;
mod extract;
mod model;
mod pipeline;
mod query;
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
    /// Incrementally refresh the index: per-repo `last_sha..HEAD` git diff,
    /// re-extract only changed files. Falls back to a full `index` when the DB
    /// is absent or a repo has no recorded sha.
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
/// [`walk::read_indexed`] refuses it.
fn read_capped(repo: &str, rel: &str) -> Option<String> {
    walk::read_indexed(std::path::Path::new(repo), rel)
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

/// One `--repo tag:path` entry: the tag every stored path of the repo carries
/// and the directory its sources are read from.
struct RepoSpec {
    tag: model::RepoTag,
    root: String,
}

/// Parse a `tag:path` repo spec. The tag is load-bearing (path-prefix
/// disambiguation + role classification), so it must be a `RepoTag`: a tag
/// `split_tag` cannot read back would store every path as untagged.
fn parse_repo(spec: &str) -> Result<RepoSpec> {
    let bad = |why: &dyn std::fmt::Display| {
        anyhow::anyhow!("bad --repo spec {spec:?}: {why}; expected tag:path (e.g. ipe:.)")
    };
    let (tag, root) = spec.split_once(':').ok_or_else(|| bad(&"no `:`"))?;
    let tag = model::RepoTag::parse(tag).map_err(|e| bad(&e))?;
    if root.is_empty() {
        return Err(bad(&"the path is empty"));
    }
    Ok(RepoSpec {
        tag,
        root: root.to_string(),
    })
}

/// Parse the whole repo set: at least one spec, each tag bound once.
fn parse_repos(specs: &[String]) -> Result<Vec<RepoSpec>> {
    let mut repos: Vec<RepoSpec> = Vec::with_capacity(specs.len());
    for spec in specs {
        let repo = parse_repo(spec)?;
        if repos.iter().any(|r| r.tag == repo.tag) {
            anyhow::bail!("--repo tag {:?} is given twice", repo.tag.as_str());
        }
        repos.push(repo);
    }
    if repos.is_empty() {
        anyhow::bail!("no --repo to index");
    }
    Ok(repos)
}

/// Store one file's rows (file, symbols, units, stage and coverage edges)
/// under its tagged path. The caller has already dropped any old rows.
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
    store.put_file(tagged, lang.as_str(), role.as_str(), src.len() as i64, "")?;
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
        // Resolution pass over the merged store (tagged paths). Best-effort across tags.
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
    let repos = parse_repos(repo_specs)?;
    if let Some(parent) = std::path::Path::new(db).parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).ok();
    }
    let store = store::Store::open(db)?;
    let mut total_files = 0usize;
    rebuild(&store, |store| {
        let mut shas = HashMap::new();
        for repo in &repos {
            let files = walk::tracked(&repo.root)?;
            let sha = head_sha_or_empty(&repo.root);
            for f in &files {
                let Some(src) = read_capped(&repo.root, &f.path) else {
                    continue;
                };
                // Store every path prefixed with the repo tag so multiple repos
                // never collide (each has Cargo.toml, README.md, scripts/*, tools/*).
                ingest_file(store, &repo.tag.tagged(&f.path), f.lang, &src, &sha)?;
            }
            // Per-repo HEAD sha so an incremental `update` can diff each.
            if !sha.is_empty() {
                store.set_meta(&repo.tag.last_sha_key(), &sha)?;
            }
            shas.insert(repo.tag.as_str().to_string(), sha);
            total_files += files.len();
        }
        Ok(shas)
    })?;
    eprintln!(
        "ipe-index: indexed {total_files} files across {} repo(s)",
        repos.len()
    );
    Ok(())
}

fn head_sha_or_empty(root: &str) -> String {
    walk::head_sha(root).unwrap_or_else(|e| {
        eprintln!("ipe-index: no HEAD sha for {root}: {e}");
        String::new()
    })
}

/// Incremental refresh: for each repo, diff `last_sha:<tag>..HEAD`, re-extract
/// only the changed files. Falls back to a full `index` when the DB is absent,
/// its rows are of another schema version, or a repo has no recorded sha.
fn cmd_update(repo_specs: &[String], db: &str) -> Result<()> {
    if !std::path::Path::new(db).exists() {
        return cmd_index(repo_specs, db);
    }
    let repos = parse_repos(repo_specs)?;
    let store = store::Store::open(db)?;
    if needs_full_index(&store, &repos)? {
        drop(store);
        return cmd_index(repo_specs, db);
    }
    store.begin()?;
    let mut changed_count = 0usize;
    for repo in &repos {
        let since = store
            .get_meta(&repo.tag.last_sha_key())?
            .unwrap_or_default();
        let sha = head_sha_or_empty(&repo.root);
        let shas = HashMap::from([(repo.tag.as_str().to_string(), sha.clone())]);
        let (ups, dels) = walk::changed(&repo.root, &since)?;
        // One timestamp per repo so the run's events order stably
        // (enqueued_at is a tiebreaker in `pending`'s ORDER BY).
        let now = diff::now_millis();
        for d in &dels {
            let tagged = repo.tag.tagged(d);
            let before = store.snapshot_path(&tagged)?;
            store.drop_file(&tagged)?;
            reconcile_queue(&store, &before, &diff::Snapshot::new(), &shas, now)?;
        }
        for f in &ups {
            let tagged = repo.tag.tagged(&f.path);
            let before = store.snapshot_path(&tagged)?;
            // An oversized/unreadable file keeps no units, so its old units
            // reconcile as deleted.
            let src = read_capped(&repo.root, &f.path);
            store.drop_file(&tagged)?;
            if let Some(src) = src {
                ingest_file(&store, &tagged, f.lang, &src, &sha)?;
            }
            let after = store.snapshot_path(&tagged)?;
            reconcile_queue(&store, &before, &after, &shas, now)?;
        }
        if !sha.is_empty() {
            store.set_meta(&repo.tag.last_sha_key(), &sha)?;
        }
        changed_count += ups.len() + dels.len();
    }
    query::resolve_edges(&store, ".")?;
    store.commit()?;
    eprintln!(
        "ipe-index: updated {changed_count} changed path(s) across {} repo(s)",
        repos.len()
    );
    Ok(())
}

/// An incremental `update` can only diff a DB whose rows are in the current
/// format and that records a sha for every repo; anything else is rebuilt.
fn needs_full_index(store: &store::Store, repos: &[RepoSpec]) -> Result<bool> {
    if !store.schema_is_current()? {
        return Ok(true);
    }
    for repo in repos {
        if store.get_meta(&repo.tag.last_sha_key())?.is_none() {
            return Ok(true);
        }
    }
    Ok(false)
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

    fn repos() -> Vec<RepoSpec> {
        parse_repos(&default_repos()).unwrap()
    }

    #[test]
    fn current_db_with_shas_updates_incrementally() {
        let s = store::Store::open(":memory:").unwrap();
        s.set_meta("last_sha:ipe", "abc").unwrap();
        assert!(!needs_full_index(&s, &repos()).unwrap());
    }

    #[test]
    fn missing_repo_sha_rebuilds() {
        let s = store::Store::open(":memory:").unwrap();
        assert!(needs_full_index(&s, &repos()).unwrap());
    }

    // Rows of an older schema carry hashes in the old format; an incremental
    // update would keep them for every unchanged file, so it rebuilds instead.
    #[test]
    fn older_schema_rebuilds() {
        let s = store::Store::open(":memory:").unwrap();
        s.set_meta("last_sha:ipe", "abc").unwrap();
        s.set_meta("schema_version", "2").unwrap();
        assert!(needs_full_index(&s, &repos()).unwrap());
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
}
