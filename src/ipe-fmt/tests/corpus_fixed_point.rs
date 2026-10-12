//! Corpus-wide fixed-point proof for `ipe_fmt::format_source`.
//!
//! Every tracked `.ipe` file under the workspace is either rejected by the
//! parser — a skip set pinned exactly, so a new unparseable file or a parser
//! regression turns this test red — or is a fixed point of a second format
//! pass: `format_source(format_source(x)) == format_source(x)`. This is the
//! corpus half of BUG-CLASSES 8e (a source-keyed rewrite must be its own
//! fixed point) and closes the anti-vacuity gap in BUG-CLASSES 12a.

use std::fs;
use std::path::{Path, PathBuf};

use ipe_intern::Interner;

/// Directories deeper than this are refused rather than walked.
///
/// The walk is bounded by construction, not by what the tree happens to
/// contain.
const MAX_WALK_DEPTH: u32 = 32;

/// A file larger than this fails the test outright.
///
/// The corpus is a fixed, known set of small source files, so a file over
/// the cap is itself a defect to surface, never a thing to skip quietly.
const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;

/// The exact files the parser is known to reject today.
///
/// Malformed character literals/patterns, an unterminated block comment, and
/// lambda arguments the grammar refuses. Pinned as an explicit list so a new
/// unparseable file, or a parser regression that starts rejecting more, goes
/// red here instead of silently widening the skip set.
const KNOWN_PARSE_REFUSALS: &[&str] = &[
    "tests/golden/blockcomment_unterminated/Main.ipe",
    "tests/golden/gate_malformed_char_pattern/Main.ipe",
    "tests/golden/gate_malformed_char_scrutinee/Main.ipe",
    "tests/golden/neg_int_lambda/Main.ipe",
    "tests/golden/neg_list_lambda/Main.ipe",
];

/// The floor a healthy walk must clear.
///
/// Below it, the walk ran over far too little of the tree to mean anything —
/// the anti-vacuity half of this test.
const MIN_FORMATTED_FILES: usize = 1200;

fn workspace_root() -> PathBuf {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../..")).to_path_buf()
}

/// Collects every `.ipe` file under `root`.
///
/// Never follows a symlink, never descends past [`MAX_WALK_DEPTH`], and
/// skips `target` and dot directories.
fn collect_ipe_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack: Vec<(PathBuf, u32)> = vec![(root.to_path_buf(), 0)];
    while let Some((dir, depth)) = stack.pop() {
        assert!(
            depth <= MAX_WALK_DEPTH,
            "corpus walk exceeded MAX_WALK_DEPTH at {}",
            dir.display()
        );
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries {
            let Ok(entry) = entry else { continue };
            let path = entry.path();
            let Ok(meta) = fs::symlink_metadata(&path) else {
                continue;
            };
            if meta.file_type().is_symlink() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if meta.is_dir() {
                if name == "target" || name.starts_with('.') {
                    continue;
                }
                stack.push((path, depth + 1));
            } else if meta.is_file() && path.extension().is_some_and(|ext| ext == "ipe") {
                out.push(path);
            }
        }
    }
    out
}

/// Every `.ipe` file under the corpus roots.
fn corpus_files(root: &Path) -> Vec<PathBuf> {
    ["src", "examples", "tools", "tests", "packages"]
        .iter()
        .flat_map(|top| collect_ipe_files(&root.join(top)))
        .collect()
}

/// Every corpus file the formatter accepts formats under its output cap, so
/// the cap never refuses real code. Red if the cap tightens past the corpus.
#[test]
fn fmt_cap_admits_the_corpus() {
    let root = workspace_root();
    let mut formatted_count = 0usize;
    for path in &corpus_files(&root) {
        let rel = path
            .strip_prefix(&root)
            .unwrap_or(path)
            .display()
            .to_string();
        let src = fs::read_to_string(path).expect("corpus .ipe file is UTF-8");
        let cap = ipe_fmt::OutputCap::for_input(src.len());
        match ipe_fmt::format_source(&src) {
            Ok(out) => {
                assert!(cap.admits(&out), "{rel}: output passed its cap {cap}");
                formatted_count += 1;
            }
            Err(e) => assert!(
                !matches!(e, ipe_fmt::FmtError::Limit(_)),
                "{rel}: the output cap refused real code: {e}"
            ),
        }
    }
    assert!(
        formatted_count >= MIN_FORMATTED_FILES,
        "formatted_count {formatted_count} is below the anti-vacuity floor of \
         {MIN_FORMATTED_FILES}"
    );
}

#[test]
fn every_repo_ipe_file_is_a_meaning_preserving_fixed_point() {
    let root = workspace_root();

    let files = corpus_files(&root);

    let mut skipped: Vec<String> = Vec::new();
    let mut formatted_count = 0usize;

    for path in &files {
        let rel = path
            .strip_prefix(&root)
            .expect("walked file is under the workspace root")
            .to_string_lossy()
            .replace('\\', "/");

        let meta = fs::symlink_metadata(path).expect("file existed during the walk");
        assert!(
            meta.len() <= MAX_FILE_BYTES,
            "{rel}: {} bytes exceeds the {MAX_FILE_BYTES}-byte corpus cap",
            meta.len()
        );

        let src = fs::read_to_string(path).expect("corpus .ipe file is UTF-8");

        let mut interner = Interner::new();
        if ipe_parse::parse_module(&src, &mut interner).is_err() {
            skipped.push(rel);
            continue;
        }

        let once = {
            let msg = format!("{rel}: format_source rejected a file the parser accepted");
            ipe_fmt::format_source(&src).expect(&msg)
        };
        let twice = {
            let msg = format!("{rel}: the second format pass rejected the first pass's output");
            ipe_fmt::format_source(&once).expect(&msg)
        };
        assert_eq!(
            twice, once,
            "{rel}: not a meaning-preserving fixed point of a second format pass"
        );
        formatted_count += 1;
    }

    skipped.sort();
    let mut expected_skips: Vec<String> = KNOWN_PARSE_REFUSALS
        .iter()
        .map(ToString::to_string)
        .collect();
    expected_skips.sort();
    assert_eq!(
        skipped, expected_skips,
        "the parse-refusal skip set drifted from the pinned list — a new \
         unparseable file or a parser regression must be investigated, never \
         silently widened"
    );

    assert!(
        formatted_count >= MIN_FORMATTED_FILES,
        "formatted_count {formatted_count} is below the anti-vacuity floor of \
         {MIN_FORMATTED_FILES} — the walk likely ran over far too little of the tree"
    );
}
