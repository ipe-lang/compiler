//! The A6 change diff: what changed between two unit snapshots, expressed as
//! review-queue operations.

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

/// The changed line ranges of each file in a git range, from
/// `git diff --unified=0`. Returns `(relpath, [(start, end)])` covering the
/// NEW-side lines a hunk touches — the review scope a `changed` query maps onto
/// units. Deletions (no new-side lines) attribute to the line the removal sits
/// at, so a deleted body still surfaces its enclosing unit.
///
/// `range` is validated before it reaches git: no leading `-` (option
/// smuggling) and only ref-safe bytes, so a crafted range can't inject git
/// options.
pub fn changed_line_ranges(repo: &str, range: &str) -> anyhow::Result<Vec<FileHunks>> {
    use anyhow::bail;
    if range.is_empty()
        || range.starts_with('-')
        || !range.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'/' | b'-' | b'~' | b'^')
        })
    {
        bail!("refusing unsafe git range: {range:?}");
    }
    // `--` ends the revisions: an unresolvable range is an error, never a pathspec.
    let out = crate::walk::git_command(repo)
        .args([
            "diff",
            "--unified=0",
            "--no-color",
            "--no-renames",
            range,
            "--",
        ])
        .output()?;
    if !out.status.success() {
        bail!(
            "git diff failed in {repo}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut per_file: BTreeMap<String, Vec<(i64, i64)>> = BTreeMap::new();
    let mut current: Option<String> = None;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("+++ ") {
            // `+++ b/path` (or `+++ /dev/null` for a deletion).
            current = rest
                .strip_prefix("b/")
                .filter(|p| *p != "/dev/null")
                .map(|p| p.to_string());
        } else if let Some(range_text) = line.strip_prefix("@@ ") {
            let Some(file) = &current else { continue };
            if let Some((start, count)) = parse_new_hunk(range_text) {
                // `count == 0` is a pure deletion at `start`; treat it as a
                // single line so the enclosing unit is still reported.
                let end = start + count.max(1) - 1;
                per_file.entry(file.clone()).or_default().push((start, end));
            }
        }
    }
    Ok(per_file.into_iter().collect())
}

/// Parse the NEW-side `+start[,count]` of a `@@ -a,b +start,count @@` header.
fn parse_new_hunk(header: &str) -> Option<(i64, i64)> {
    let plus = header.split_whitespace().find(|t| t.starts_with('+'))?;
    let body = plus.strip_prefix('+')?;
    match body.split_once(',') {
        Some((s, c)) => Some((s.parse().ok()?, c.parse().ok()?)),
        None => Some((body.parse().ok()?, 1)),
    }
}

/// Unix-epoch milliseconds, as the change queue's enqueued_at column wants.
pub fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
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

    #[test]
    fn parses_new_hunk_headers() {
        assert_eq!(parse_new_hunk("-1,3 +4,5 @@ fn x"), Some((4, 5)));
        assert_eq!(parse_new_hunk("-1 +2 @@"), Some((2, 1))); // single line, no count
        assert_eq!(parse_new_hunk("-1,2 +0,0 @@"), Some((0, 0))); // pure deletion
        assert_eq!(parse_new_hunk("no plus token"), None);
    }
}
