//! The change diff: what changed between two unit snapshots, expressed as
//! review-queue operations.

use crate::repo_set::DeclaredRoot;
use std::collections::{BTreeMap, BTreeSet};
use std::time::{SystemTime, UNIX_EPOCH};

/// The queue-relevant state of one unit.
///
/// `body_hash` is the attested hash a queue row carries and the review app
/// drains by; `change_key` is what a change is judged on. A `file` unit
/// attests the lines no other unit of the file covers, so a change inside a
/// child unit queues the child alone. The two differ only for a `file` row
/// written by an index that attested the whole file and kept the residual
/// beside it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitState {
    pub path: String,
    pub body_hash: String,
    pub change_key: String,
}

/// Every unit of a scope (one path, or the whole index), keyed by uid.
pub type Snapshot = BTreeMap<String, UnitState>;

/// What one unit's change does to the review queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// The unit appeared: queue it as `new`.
    New { new_hash: String },
    /// The unit's change key moved: queue it as `modified`.
    Modified { old_hash: String, new_hash: String },
    /// The unit vanished: queue it as `deleted`.
    Deleted { old_hash: String },
    /// Only lines another unit owns moved: a pending row, if any, is re-pointed
    /// at the current body hash, and no new review is queued.
    Refresh { new_hash: String },
}

/// One queue operation on one unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueueOp {
    pub uid: String,
    pub path: String,
    pub change: Change,
}

/// The queue operations that carry the review queue from `before` to `after`.
///
/// This is the only definition of a queue transition: a full rebuild and an
/// incremental update both diff the state the queue was last reconciled
/// against, so neither can reset review state a drain removed. Units with an
/// unchanged body yield nothing; the output is ordered by uid.
pub fn reconcile(before: &Snapshot, after: &Snapshot) -> Vec<QueueOp> {
    let uids: BTreeSet<&String> = before.keys().chain(after.keys()).collect();
    uids.into_iter()
        .filter_map(|uid| {
            let (path, change) = match (before.get(uid), after.get(uid)) {
                (Some(old), None) => (
                    old.path.clone(),
                    Change::Deleted {
                        old_hash: old.body_hash.clone(),
                    },
                ),
                (None, Some(new)) => (
                    new.path.clone(),
                    Change::New {
                        new_hash: new.body_hash.clone(),
                    },
                ),
                (Some(old), Some(new)) if old.change_key != new.change_key => (
                    new.path.clone(),
                    Change::Modified {
                        old_hash: old.body_hash.clone(),
                        new_hash: new.body_hash.clone(),
                    },
                ),
                (Some(old), Some(new)) if old.body_hash != new.body_hash => (
                    new.path.clone(),
                    Change::Refresh {
                        new_hash: new.body_hash.clone(),
                    },
                ),
                _ => return None,
            };
            Some(QueueOp {
                uid: uid.clone(),
                path,
                change,
            })
        })
        .collect()
}

/// A changed file and the new-side line ranges its diff hunks touch.
pub type FileHunks = (String, Vec<(i64, i64)>);

/// Why a git diff of a root is not trusted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffRefusal {
    /// A header line, or the hunk it opens, is not the documented shape: a
    /// quoted file name, a name the `--raw -z` listing does not hold, a
    /// non-positive or overflowing line number, or a hunk that ends early.
    UnparsedHeader { header: String },
    /// The patch does not hold one `diff --git` section per entry of the
    /// `--raw -z` listing, so some changed file may have no hunks in it.
    SectionsDisagree { listed: usize, patched: usize },
    /// A file the `--raw -z` listing names has no section in the patch.
    MissingSection { path: String },
}

impl std::fmt::Display for DiffRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnparsedHeader { header } => write!(
                f,
                "the diff holds a header that is not understood, so its hunks are not trusted: {}",
                crate::walk::shown(header)
            ),
            Self::SectionsDisagree { listed, patched } => write!(
                f,
                "the diff lists {listed} changed entries but its patch holds {patched} file sections, so its hunks are not trusted"
            ),
            Self::MissingSection { path } => write!(
                f,
                "the diff lists {} as changed but its patch holds no section for it, so its hunks are not trusted",
                crate::walk::shown(path)
            ),
        }
    }
}

impl std::error::Error for DiffRefusal {}

fn unparsed(header: &str) -> DiffRefusal {
    DiffRefusal::UnparsedHeader {
        header: header.to_string(),
    }
}

/// What the `--raw -z` listing of a diff predicts its patch holds.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Listed {
    /// Every indexable path the listing names.
    paths: BTreeSet<String>,
    /// The `diff --git` sections the patch must hold.
    sections: usize,
}

/// Options that pin the patch to the shape [`parse_patch`] reads, whatever the
/// user's git configuration: no external diff driver or text conversion
/// rewrites it, every name carries the `a/`/`b/` prefix, a submodule is one
/// `diff --git` section, and no context line joins two hunks.
const PATCH_SHAPE: [&str; 7] = [
    "--no-ext-diff",
    "--no-textconv",
    "--src-prefix=a/",
    "--dst-prefix=b/",
    "--submodule=short",
    "--inter-hunk-context=0",
    "--no-color",
];

/// The changed line ranges of each file in a git range, from
/// `git diff --unified=0`. Returns `(relpath, [(start, end)])` covering the
/// NEW-side lines a hunk touches, with `relpath` relative to `root` — the
/// review scope a `changed` query maps onto units. Deletions (no new-side
/// lines) attribute to the line the removal sits at, so a deleted body still
/// surfaces its enclosing unit.
///
/// `range` is validated the same way `walk::changed`'s since-ref is: no leading
/// `-` (option smuggling) and only ref-safe bytes, so a crafted range can't
/// inject git options. The files come from the `--raw -z` listing, which never
/// quotes a name, and the patch must agree with it both ways: one section per
/// listed entry, one for every listed file, and no hunk of a file it does not
/// list. A patch that disagrees, or holds a quoted header, refuses the whole
/// diff rather than dropping its hunks.
pub fn changed_line_ranges(root: &DeclaredRoot, range: &str) -> anyhow::Result<Vec<FileHunks>> {
    ranges_through(root, range, |args| {
        crate::walk::git_stdout(root.root_str(), args)
    })
}

/// [`changed_line_ranges`], running each git command through `git`.
fn ranges_through(
    root: &DeclaredRoot,
    range: &str,
    git: impl Fn(&[&str]) -> anyhow::Result<Vec<u8>>,
) -> anyhow::Result<Vec<FileHunks>> {
    use anyhow::bail;
    if range.is_empty()
        || range.starts_with('-')
        || !range.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'/' | b'-' | b'~' | b'^')
        })
    {
        bail!("refusing unsafe git range: {range:?}");
    }
    crate::walk::verify_root(root)?;
    // `--` ends the revisions: an unresolvable range is an error, never a pathspec.
    let raw = git(&[
        "diff",
        "--raw",
        "-z",
        "--no-renames",
        "--relative",
        "--no-ext-diff",
        "--no-textconv",
        range,
        "--",
    ])?;
    let listed = listed_paths(&raw)?;
    let mut args = vec!["diff", "--unified=0", "--no-renames", "--relative"];
    args.extend(PATCH_SHAPE);
    args.extend([range, "--"]);
    let patch = git(args.as_slice())?;
    Ok(parse_patch(&patch, &listed)?.into_iter().collect())
}

/// Every indexable path the `--raw -z` listing of a diff names, and the
/// sections its patch must hold.
fn listed_paths(raw: &[u8]) -> anyhow::Result<Listed> {
    use crate::walk::Change;
    let listing = crate::walk::parse_diff_listing(raw)?;
    let paths = listing
        .changes
        .into_iter()
        .filter_map(|change| match change {
            Change::Upsert(path) | Change::Delete(path) => Some(path),
            Change::Refused(_) => None,
        })
        .collect();
    Ok(Listed {
        paths,
        sections: listing.patch_sections,
    })
}

/// The hunks of a `--unified=0 --relative` patch, by file.
///
/// A hunk is consumed by its own line counts, so a changed line whose text
/// reads like a header (`+++ x`) is never taken for one. The patch must hold
/// exactly the sections `listed` predicts and one for each of its paths.
fn parse_patch(
    patch: &[u8],
    listed: &Listed,
) -> Result<BTreeMap<String, Vec<(i64, i64)>>, DiffRefusal> {
    let mut per_file: BTreeMap<String, Vec<(i64, i64)>> = BTreeMap::new();
    let mut sectioned: BTreeSet<&str> = BTreeSet::new();
    let mut sections: usize = 0;
    let mut current: Option<String> = None;
    let mut owed: u64 = 0;
    for line in patch.split(|&b| b == b'\n') {
        if owed > 0 {
            match line.first() {
                Some(b'+' | b'-') => owed = owed.saturating_sub(1),
                Some(b'\\') => {}
                _ => return Err(unparsed(&String::from_utf8_lossy(line))),
            }
            continue;
        }
        if let Some(names) = line.strip_prefix(b"diff --git ") {
            sections = sections.saturating_add(1);
            current = None;
            if let Some(path) = section_path(names)
                && let Some(known) = listed.paths.get(path)
            {
                sectioned.insert(known.as_str());
            }
        } else if let Some(rest) = line.strip_prefix(b"+++ ") {
            current = new_side_path(rest, &listed.paths)?;
        } else if let Some(range_text) = line.strip_prefix(b"@@ ") {
            let text = String::from_utf8_lossy(range_text);
            let hunk = parse_hunk(&text)?;
            owed = u64::from(hunk.old_count) + u64::from(hunk.new_count);
            let Some(file) = &current else { continue };
            // `count == 0` is a pure deletion after `start`; treat it as a
            // single line so the enclosing unit is still reported.
            let first = if hunk.new_count == 0 {
                hunk.new_start.max(1)
            } else {
                hunk.new_start
            };
            let end = first
                .checked_add(hunk.new_count.max(1).saturating_sub(1))
                .ok_or_else(|| unparsed(&text))?;
            per_file
                .entry(file.clone())
                .or_default()
                .push((i64::from(first), i64::from(end)));
        }
    }
    if owed > 0 {
        return Err(unparsed("a hunk that ends before its lines do"));
    }
    if sections != listed.sections {
        return Err(DiffRefusal::SectionsDisagree {
            listed: listed.sections,
            patched: sections,
        });
    }
    if let Some(path) = listed
        .paths
        .iter()
        .find(|path| !sectioned.contains(path.as_str()))
    {
        return Err(DiffRefusal::MissingSection { path: path.clone() });
    }
    Ok(per_file)
}

/// The one path of a `diff --git a/<path> b/<path>` header, which names the
/// same path twice under `--no-renames`; `None` for any other shape, such as
/// a quoted name.
fn section_path(names: &[u8]) -> Option<&str> {
    let text = std::str::from_utf8(names).ok()?;
    let rest = text.strip_prefix("a/")?;
    // `rest` is `<path> b/<path>`: the path is the first half before ` b/`.
    let half = rest.len().checked_sub(3)?.checked_div(2)?;
    let (path, tail) = (rest.get(..half)?, rest.get(half..)?);
    (tail.strip_prefix(" b/")? == path).then_some(path)
}

/// The path a `+++ ` header names, or `None` for `+++ /dev/null` and a path
/// the index never reads.
fn new_side_path(header: &[u8], listed: &BTreeSet<String>) -> Result<Option<String>, DiffRefusal> {
    let text =
        std::str::from_utf8(header).map_err(|_| unparsed(&String::from_utf8_lossy(header)))?;
    if text == "/dev/null" {
        return Ok(None);
    }
    // Git ends a header whose name holds a space with a TAB; a name holding a
    // TAB is quoted instead, so one trailing TAB is never part of the name.
    let name = text.strip_suffix('\t').unwrap_or(text);
    let Some(path) = name.strip_prefix("b/") else {
        return Err(unparsed(text));
    };
    if !crate::walk::is_indexable(path) {
        return Ok(None);
    }
    if listed.contains(path) {
        Ok(Some(path.to_string()))
    } else {
        Err(unparsed(text))
    }
}

/// The line counts of one `@@ -a[,b] +c[,d] @@` header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Hunk {
    old_count: u32,
    new_start: u32,
    new_count: u32,
}

/// Parses a hunk header (the text after `@@ `): every number is a `u32` line
/// number, and a hunk that adds lines starts at line 1 or later.
fn parse_hunk(header: &str) -> Result<Hunk, DiffRefusal> {
    let refused = || unparsed(header);
    let mut tokens = header.split_whitespace();
    let old = tokens
        .next()
        .and_then(|t| t.strip_prefix('-'))
        .ok_or_else(refused)?;
    let new = tokens
        .next()
        .and_then(|t| t.strip_prefix('+'))
        .ok_or_else(refused)?;
    let counted = |body: &str| -> Option<(u32, u32)> {
        match body.split_once(',') {
            Some((start, count)) => Some((start.parse().ok()?, count.parse().ok()?)),
            None => Some((body.parse().ok()?, 1)),
        }
    };
    let (_, old_count) = counted(old).ok_or_else(refused)?;
    let (new_start, new_count) = counted(new).ok_or_else(refused)?;
    if new_count > 0 && new_start == 0 {
        return Err(refused());
    }
    Ok(Hunk {
        old_count,
        new_start,
        new_count,
    })
}

/// Unix-epoch milliseconds, as the change queue's enqueued_at column wants.
///
/// A clock before the epoch reads as 0 and one past `i64::MAX` milliseconds
/// saturates; the column only orders rows.
pub fn now_millis() -> i64 {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    i64::try_from(millis).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(path: &str, body: &str, key: &str) -> UnitState {
        UnitState {
            path: path.to_string(),
            body_hash: body.to_string(),
            change_key: key.to_string(),
        }
    }

    fn snap(rows: Vec<(&str, UnitState)>) -> Snapshot {
        rows.into_iter().map(|(u, s)| (u.to_string(), s)).collect()
    }

    fn changes(ops: Vec<QueueOp>) -> Vec<(String, Change)> {
        ops.into_iter().map(|op| (op.uid, op.change)).collect()
    }

    #[test]
    fn identical_snapshots_produce_no_ops() {
        let s = snap(vec![
            ("u-a", state("p", "h1", "h1")),
            ("u-b", state("p", "h2", "h2")),
        ]);
        assert!(reconcile(&s, &s.clone()).is_empty());
    }

    #[test]
    fn brand_new_units_are_new() {
        let ops = reconcile(
            &Snapshot::new(),
            &snap(vec![("u-c", state("p", "h3", "h3"))]),
        );
        assert_eq!(ops.first().map(|op| op.path.as_str()), Some("p"));
        let want = Change::New {
            new_hash: "h3".to_string(),
        };
        assert_eq!(changes(ops), vec![("u-c".to_string(), want)]);
    }

    #[test]
    fn vanished_units_are_deleted() {
        let ops = reconcile(
            &snap(vec![("u-a", state("p", "h1", "h1"))]),
            &Snapshot::new(),
        );
        let want = Change::Deleted {
            old_hash: "h1".to_string(),
        };
        assert_eq!(changes(ops), vec![("u-a".to_string(), want)]);
    }

    #[test]
    fn moved_key_is_modified() {
        let ops = reconcile(
            &snap(vec![("u-a", state("p", "h1", "k1"))]),
            &snap(vec![("u-a", state("p", "h2", "k2"))]),
        );
        let want = Change::Modified {
            old_hash: "h1".to_string(),
            new_hash: "h2".to_string(),
        };
        assert_eq!(changes(ops), vec![("u-a".to_string(), want)]);
    }

    // A file unit whose own lines are unchanged is not queued for review when
    // only a child's body moved; its pending row is re-pointed instead.
    #[test]
    fn body_move_under_a_steady_key_only_refreshes() {
        let ops = reconcile(
            &snap(vec![("u-f", state("p", "h1", "k"))]),
            &snap(vec![("u-f", state("p", "h2", "k"))]),
        );
        let want = Change::Refresh {
            new_hash: "h2".to_string(),
        };
        assert_eq!(changes(ops), vec![("u-f".to_string(), want)]);
    }

    // A file row whose attestation moves from the whole file to its residual,
    // with the residual unchanged, is re-pointed and never queued for review.
    #[test]
    fn a_rekeyed_file_unit_is_a_refresh_not_a_review() {
        let ops = reconcile(
            &snap(vec![("u-f", state("p", "whole", "residual"))]),
            &snap(vec![("u-f", state("p", "residual", "residual"))]),
        );
        let want = Change::Refresh {
            new_hash: "residual".to_string(),
        };
        assert_eq!(changes(ops), vec![("u-f".to_string(), want)]);
    }

    #[test]
    fn ops_are_ordered_by_uid() {
        let before = snap(vec![("u-b", state("p", "h1", "h1"))]);
        let after = snap(vec![
            ("u-a", state("p", "h2", "h2")),
            ("u-b", state("p", "h2", "h2")),
        ]);
        let uids: Vec<String> = reconcile(&before, &after)
            .into_iter()
            .map(|op| op.uid)
            .collect();
        assert_eq!(uids, vec!["u-a", "u-b"]);
    }

    fn hunk(old_count: u32, new_start: u32, new_count: u32) -> Hunk {
        Hunk {
            old_count,
            new_start,
            new_count,
        }
    }

    #[test]
    fn parses_hunk_headers() {
        assert_eq!(parse_hunk("-1,3 +4,5 @@ fn x"), Ok(hunk(3, 4, 5)));
        assert_eq!(parse_hunk("-1 +2 @@"), Ok(hunk(1, 2, 1))); // single line, no count
        assert_eq!(parse_hunk("-1,2 +0,0 @@"), Ok(hunk(2, 0, 0))); // pure deletion
        assert!(parse_hunk("no plus token").is_err());
    }

    // A header is refused, never skipped, so its hunk cannot silently vanish.
    #[test]
    fn hunk_headers_that_are_not_line_numbers_are_refused() {
        for bad in [
            "-1 +0,2 @@",
            "-1 +-3,2 @@",
            "-1 +x @@",
            "-1,y +2 @@",
            "-1 @@",
            "+1 -1 @@",
        ] {
            assert!(parse_hunk(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn hunk_end_overflow_is_refused() {
        assert!(parse_hunk("-1 +9223372036854775807,2 @@").is_err());
        assert!(parse_hunk("-1 +4294967296 @@").is_err());
        let patch = b"diff --git a/a.rs b/a.rs\n+++ b/a.rs\n@@ -1 +4294967295,2 @@\n-x\n+y\n+z\n";
        assert_eq!(
            one_file(patch, &["a.rs"]),
            Err(unparsed("-1 +4294967295,2 @@"))
        );
    }

    fn one_file(
        patch: &[u8],
        names: &[&str],
    ) -> Result<Vec<(String, Vec<(i64, i64)>)>, DiffRefusal> {
        let listed = Listed {
            paths: names.iter().map(|n| (*n).to_string()).collect(),
            sections: names.len(),
        };
        parse_patch(patch, &listed).map(|m| m.into_iter().collect())
    }

    #[test]
    fn hunks_map_to_new_side_ranges() {
        let patch = b"diff --git a/a.rs b/a.rs\n--- a/a.rs\n+++ b/a.rs\n\
@@ -1,0 +2,3 @@\n+x\n+y\n+z\n@@ -9,2 +0,0 @@\n-p\n-q\n\
diff --git a/gone.rs b/gone.rs\n--- a/gone.rs\n+++ /dev/null\n@@ -1 +0,0 @@\n-old\n";
        assert_eq!(
            one_file(patch, &["a.rs", "gone.rs"]),
            Ok(vec![("a.rs".to_string(), vec![(2, 4), (1, 1)])])
        );
    }

    // A changed line whose text reads like a file header belongs to its hunk.
    #[test]
    fn a_changed_line_that_looks_like_a_header_is_not_one() {
        let patch = b"diff --git a/a.rs b/a.rs\n+++ b/a.rs\n@@ -1 +1 @@\n-old\n+++ b/evil.rs\n";
        assert_eq!(
            one_file(patch, &["a.rs"]),
            Ok(vec![("a.rs".to_string(), vec![(1, 1)])])
        );
    }

    #[test]
    fn a_header_the_raw_listing_does_not_hold_is_refused() {
        let patch = b"diff --git a/other.rs b/other.rs\n+++ b/other.rs\n@@ -1 +1 @@\n-a\n+b\n";
        assert_eq!(one_file(patch, &["a.rs"]), Err(unparsed("b/other.rs")));
        let short = b"diff --git a/a.rs b/a.rs\n+++ b/a.rs\n@@ -1 +1 @@\n-a\n";
        assert_eq!(
            one_file(short, &["a.rs"]),
            Err(unparsed("a hunk that ends before its lines do"))
        );
    }

    // Git ends a header whose name holds a space with a TAB.
    #[test]
    fn a_name_with_a_space_keeps_its_hunks() {
        let patch = b"diff --git a/a b.rs b/a b.rs\n+++ b/a b.rs\t\n@@ -1 +1 @@\n-a\n+b\n";
        assert_eq!(
            one_file(patch, &["a b.rs"]),
            Ok(vec![("a b.rs".to_string(), vec![(1, 1)])])
        );
    }

    #[test]
    fn a_quoted_header_is_refused() {
        let patch =
            b"diff --git \"a/a\\tb.rs\" \"b/a\\tb.rs\"\n+++ \"b/a\\tb.rs\"\n@@ -1 +1 @@\n-a\n+b\n";
        assert!(one_file(patch, &["a\tb.rs"]).is_err());
    }

    // An external diff tool prints no `diff --git` section: the change the
    // listing names is refused, never read as having no hunks.
    #[test]
    fn a_patch_with_fewer_sections_than_listed_is_refused() {
        for patch in [&b"external tool text\n"[..], b""] {
            assert_eq!(
                one_file(patch, &["a.rs"]),
                Err(DiffRefusal::SectionsDisagree {
                    listed: 1,
                    patched: 0
                })
            );
        }
        let twice = b"diff --git a/a.rs b/a.rs\ndiff --git a/a.rs b/a.rs\n";
        assert_eq!(
            one_file(twice, &["a.rs"]),
            Err(DiffRefusal::SectionsDisagree {
                listed: 1,
                patched: 2
            })
        );
    }

    // The counts agree, but the section is another file's.
    #[test]
    fn a_listed_file_without_its_own_section_is_refused() {
        assert_eq!(
            one_file(b"diff --git a/b.rs b/b.rs\n", &["a.rs"]),
            Err(DiffRefusal::MissingSection {
                path: "a.rs".to_string()
            })
        );
    }

    #[test]
    fn a_section_header_names_one_path_twice() {
        assert_eq!(section_path(b"a/x.rs b/x.rs"), Some("x.rs"));
        assert_eq!(section_path(b"a/a b.rs b/a b.rs"), Some("a b.rs"));
        for other in [
            &b"x.rs x.rs"[..],
            b"a/x.rs b/y.rs",
            b"c/x.rs i/x.rs",
            b"\"a/x\\tb\" \"b/x\\tb\"",
            b"a/",
            b"a/\xff b/\xff",
        ] {
            assert_eq!(section_path(other), None, "{other:?}");
        }
    }

    /// A repository whose `a.rs` changes on lines 2 and 9 in `HEAD`.
    #[cfg(unix)]
    fn two_line_change(name: &str) -> crate::walk::fixture::Fixture {
        let fx = crate::walk::fixture::Fixture::new(name);
        let lines =
            |two: &str, nine: &str| format!("l1\n{two}\nl3\nl4\nl5\nl6\nl7\nl8\n{nine}\nl10\n");
        fx.write("a.rs", &lines("l2", "l9"));
        fx.commit("one");
        fx.write("a.rs", &lines("x2", "x9"));
        fx.commit("two");
        fx
    }

    // Each setting reshapes git's default patch: an external tool or a text
    // conversion that prints nothing, no `a/`/`b/` prefixes, context lines
    // joining the two hunks. The pinned options read the same ranges anyway.
    #[cfg(unix)]
    #[test]
    fn a_users_diff_configuration_does_not_reshape_the_patch() {
        use crate::walk::fixture::{root_of, set};
        let fx = two_line_change("diff-config");
        fx.write(".gitattributes", "*.rs diff=blank\n");
        for (key, value) in [
            ("diff.external", "true"),
            ("diff.blank.textconv", "true"),
            ("diff.noprefix", "true"),
            ("diff.mnemonicPrefix", "true"),
            ("diff.interHunkContext", "10"),
            ("diff.submodule", "log"),
        ] {
            fx.git(&["config", key, value]);
        }
        let roots = set(&[("ipe", fx.root())]);
        let hunks = changed_line_ranges(root_of(&roots, "ipe"), "HEAD~1..HEAD").unwrap();
        assert_eq!(hunks, vec![("a.rs".to_string(), vec![(2, 2), (9, 9)])]);
    }

    // `GIT_EXTERNAL_DIFF` set where git runs is not trusted to be cleared.
    #[cfg(unix)]
    #[test]
    fn an_external_diff_in_the_environment_does_not_empty_the_patch() {
        use crate::walk::fixture::{root_of, set};
        use crate::walk::{MAX_GIT_STDOUT_BYTES, git_command, run_git};
        let fx = two_line_change("diff-ext-env");
        let roots = set(&[("ipe", fx.root())]);
        let root = root_of(&roots, "ipe");
        let hunks = ranges_through(root, "HEAD~1..HEAD", |args| {
            let mut cmd = git_command(root.root_str());
            cmd.args(args).env("GIT_EXTERNAL_DIFF", "true");
            run_git(&mut cmd, root.root_str(), args, MAX_GIT_STDOUT_BYTES)
        })
        .unwrap();
        assert_eq!(hunks, vec![("a.rs".to_string(), vec![(2, 2), (9, 9)])]);
    }

    // A file that becomes a link is one listing entry but two patch sections,
    // a deletion and a creation.
    #[cfg(unix)]
    #[test]
    fn a_type_change_is_two_sections() {
        use crate::walk::fixture::{root_of, set};
        let fx = two_line_change("diff-type-change");
        std::fs::remove_file(fx.path("a.rs")).unwrap();
        std::os::unix::fs::symlink("other.rs", fx.path("a.rs")).unwrap();
        fx.commit("three");
        let roots = set(&[("ipe", fx.root())]);
        let hunks = changed_line_ranges(root_of(&roots, "ipe"), "HEAD~1..HEAD").unwrap();
        assert_eq!(hunks, vec![("a.rs".to_string(), vec![(1, 1)])]);
    }

    // A file whose name git quotes in a patch header is still a changed file:
    // the diff is refused, not read as having no hunks.
    #[cfg(unix)]
    #[test]
    fn quoted_hunk_header_is_refused() {
        use crate::walk::fixture::{Fixture, root_of, set};
        let fx = Fixture::new("diff-quoted");
        fx.write("a\tb.rs", "fn a() {}\n");
        fx.commit("one");
        fx.write("a\tb.rs", "fn a() {}\nfn b() {}\n");
        fx.commit("two");
        let roots = set(&[("ipe", fx.root())]);
        let err = changed_line_ranges(root_of(&roots, "ipe"), "HEAD~1..HEAD").unwrap_err();
        assert!(
            err.downcast_ref::<DiffRefusal>().is_some(),
            "not a diff refusal: {err}"
        );
    }

    // `--relative`: a root that is a subdirectory of its work tree is diffed
    // by paths relative to it.
    #[cfg(unix)]
    #[test]
    fn a_subdirectory_root_is_diffed_relative() {
        use crate::walk::fixture::{Fixture, root_of, set};
        let fx = Fixture::new("diff-relative");
        fx.write("sub/a.rs", "fn a() {}\n");
        fx.write("top.rs", "fn t() {}\n");
        fx.commit("one");
        fx.write("sub/a.rs", "fn a() {}\nfn b() {}\n");
        fx.write("top.rs", "fn t() {}\nfn u() {}\n");
        fx.commit("two");
        let roots = set(&[("in", &fx.path("sub"))]);
        let hunks = changed_line_ranges(root_of(&roots, "in"), "HEAD~1..HEAD").unwrap();
        assert_eq!(hunks, vec![("a.rs".to_string(), vec![(2, 2)])]);
    }

    #[cfg(unix)]
    #[test]
    fn an_unsafe_range_is_refused_before_git_runs() {
        use crate::walk::fixture::set;
        let roots = set(&[("ipe", ".")]);
        let root = roots.iter().next().unwrap();
        assert!(changed_line_ranges(root, "--output=x").is_err());
        assert!(changed_line_ranges(root, "").is_err());
    }
}
