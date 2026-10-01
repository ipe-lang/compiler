//! Machine-checked proof that every golden test that byte-diffs a checked-in
//! golden `main.rs` uses the shared directory-diff harness
//! (`crate::support::assert_emitted_project_matches_golden_dir`) — see design doc §2.4
//! step 5 / Task 9. A POSITIVE check: we assert the shared helper is present on
//! every byte-diffing golden, not merely that some retired hand-roll is absent
//! (a syntactically different but still-stale hand-roll would pass a negative
//! grep while staying unmigrated).
//!
//! # The exemption is STRUCTURAL, not a hand-maintained name list
//!
//! Earlier revisions carried a `NEVER_BYTE_DIFFED` allowlist: every golden that
//! runs / inspects the emitted source (SEAL `emitted.contains(...)`, exit-0,
//! `outcome.stdout`, Pipeline-diagnostic) but never compares it to a checked-in
//! golden `main.rs` had to be named there by hand, and every sweep that added
//! such a golden re-tripped the gate until someone extended the list. That list
//! grew without bound and needed a self-validating second invariant to stop a
//! genuinely-byte-diffing file being parked on it to dodge the first.
//!
//! Both are replaced by ONE structural fact the gate derives per file:
//!
//! > A golden test byte-diffs a checked-in golden `main.rs` **iff** it references
//! > a fixture directory `tests/golden/<name>/` that actually contains a
//! > committed `main.rs`.
//!
//! The shared helper compares `<out>/src/main.rs` against `<golden_dir>/main.rs`
//! (see [`crate::support::assert_emitted_project_matches_golden_dir`]); every golden
//! that byte-diffs does so against a `tests/golden/<name>/main.rs` that must
//! exist on disk. A SEAL / run / exit-0 test references only fixture dirs that
//! carry a `Main.ipe` but NO `main.rs` — there is, by construction, nothing to
//! byte-diff, so the dir-diff helper is inapplicable and the file is
//! AUTO-EXEMPT. A future SEAL golden that ships no golden `main.rs` never
//! re-trips this gate; a future byte-diffing golden that ships a golden
//! `main.rs` but forgets the helper is still caught.
//!
//! # The single invariant (one file walk)
//!
//! Every `golden_*.rs` that references a `tests/golden/<name>/main.rs` present
//! on disk MUST call the shared helper. Nothing else is required to; nothing on
//! any list is trusted — membership in the "must call the helper" set is proven
//! per run from the filesystem, so the gate cannot silently rot as goldens are
//! added.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// The `crates/ipe/tests` directory holding every `golden_*.rs`.
fn tests_dir() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("tests");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

/// The `tests/golden` fixture tree at the workspace root (two levels up from
/// this crate's manifest). Every golden test resolves its fixtures under here
/// via `root.join("tests").join("golden").join(<name>)`.
fn golden_fixtures_dir() -> PathBuf {
    let joined = e2e_support::manifest_dir!()
        .join("..")
        .join("..")
        .join("tests")
        .join("golden");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

/// Every bare double-quoted string literal `"<token>"` in `src` whose body is a
/// plausible fixture-directory name (identifier-shaped: `[A-Za-z0-9_]+`). Used
/// to discover which `tests/golden/<name>/` dirs a golden test references. A
/// name that is not identifier-shaped cannot be a fixture directory, so it is
/// skipped; over-collecting an unrelated identifier literal is harmless because
/// the caller only acts on it when `tests/golden/<name>/main.rs` actually
/// exists on disk.
fn quoted_identifier_literals(src: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for line in src.lines() {
        // Skip comment lines. A `"name"` inside a doc/line comment is prose
        // (e.g. the JSON-path example `at ["nested","score"]`), never a
        // functional fixture reference — counting it produces a false positive
        // against an unrelated same-named golden dir that happens to exist.
        if line.trim_start().starts_with("//") {
            continue;
        }
        let bytes = line.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes.get(i) == Some(&b'"') {
                let start = i + 1;
                let mut j = start;
                while j < bytes.len() && bytes.get(j) != Some(&b'"') {
                    // A raw/escaped-string body would break the identifier shape
                    // check below anyway; a backslash means "not a plain name".
                    if bytes.get(j) == Some(&b'\\') {
                        j += 2;
                        continue;
                    }
                    j += 1;
                }
                if j < bytes.len() {
                    let body = &line[start..j];
                    if !body.is_empty()
                        && body.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                    {
                        names.insert(body.to_owned());
                    }
                    i = j + 1;
                    continue;
                }
            }
            i += 1;
        }
    }
    names
}

/// True if `src` references at least one fixture directory that carries a
/// committed golden `main.rs` under `golden_root` — i.e. the file byte-diffs a
/// checked-in golden `main.rs` and therefore MUST route through the shared
/// directory-diff helper. A file that references only fixture dirs without a
/// `main.rs` (SEAL / run / exit-0 tests) has nothing to byte-diff and is exempt
/// by construction.
fn byte_diffs_a_golden_main_rs(src: &str, golden_root: &Path) -> bool {
    quoted_identifier_literals(src)
        .iter()
        .any(|name| golden_root.join(name).join("main.rs").is_file())
}

// The lone `panic!` is this gate's deliberate failure-reporting mechanism: an
// unreadable `tests/` dir must hard-fail rather than pass vacuously (guardian
// ruling — a gate that "couldn't look" is not a gate). See the inline comment.
#[allow(clippy::panic)]
#[test]
fn every_byte_diffing_golden_test_calls_the_shared_helper() {
    let dir = tests_dir();
    let golden_root = golden_fixtures_dir();

    // A coverage gate that can pass because it "couldn't look" is not a gate:
    // hard-fail if the tests directory is unreadable rather than silently
    // returning green (guardian ruling — no vacuous pass).
    let entries = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("tests dir {} must be readable: {e}", dir.display()));

    // A gate that finds no fixtures cannot catch anything — if the golden tree
    // vanished, the structural exemption would silently exempt EVERYTHING. Fail
    // loudly rather than pass vacuously.
    assert!(
        golden_root.join("records").join("main.rs").is_file(),
        "golden fixture tree not found at {} (expected at least \
         records/main.rs) — the structural exemption cannot be trusted \
         without it",
        golden_root.display()
    );

    let mut offenders = Vec::new(); // byte-diffing golden missing the shared helper

    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let is_rs = Path::new(name)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("rs"));
        if !name.starts_with("golden_") || !is_rs {
            continue;
        }
        // This gate's own file never calls the helper — it checks for it.
        if name == "golden_harness_coverage.rs" {
            continue;
        }
        // A file that will not read is neither provably a byte-diff nor provably
        // exempt — treat as an offender rather than skipping it (no vacuous pass
        // at the per-file level either).
        let Ok(src) = std::fs::read_to_string(&path) else {
            offenders.push(format!("{name} (unreadable)"));
            continue;
        };

        let byte_diffs = byte_diffs_a_golden_main_rs(&src, &golden_root);
        let calls_helper = src.contains("assert_emitted_project_matches_golden_dir");

        // The single invariant: a golden that byte-diffs a checked-in golden
        // `main.rs` MUST route through the shared directory-diff helper. A
        // golden that references no committed golden `main.rs` (SEAL / run /
        // exit-0) has nothing to byte-diff and is auto-exempt.
        if byte_diffs && !calls_helper {
            offenders.push(name.to_owned());
        }
    }

    assert!(
        offenders.is_empty(),
        "golden tests that byte-diff a checked-in golden `main.rs` but do NOT \
         route through the shared directory-diff helper \
         (`crate::support::assert_emitted_project_matches_golden_dir`): {offenders:?}"
    );
}
