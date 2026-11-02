#![forbid(unsafe_code)]
//! Pins which workspace Rust files reach the degraded analysis.
//!
//! The degraded queries in `ipe_db` answer for a module that failed: they
//! leave each failing declaration out and keep analysing the rest. That is
//! the right answer for an editor request and a wrong one for anything that
//! builds, checks, or reports, which must refuse with the module's first
//! error. The facade's module is therefore named only by the interactive
//! language-server features (`src/lsp/features/src/`) and by the database
//! crate that defines it (`src/compiler/db/`). A Rust file anywhere else that
//! names it goes red.
//!
//! The scan covers every `.rs` file git would commit under `src/`, `tools/`,
//! `examples/` and `editors/`. This file spells the module name through
//! `concat!`, so it holds none.

use std::path::PathBuf;

/// The degraded facade's module name.
const FACADE: &str = concat!("lsp", "_degraded");

/// The workspace-relative prefixes allowed to name [`FACADE`].
const ALLOWED: [&str; 2] = ["src/lsp/features/src/", "src/compiler/db/"];

/// The workspace root.
fn workspace() -> PathBuf {
    e2e_support::manifest_dir!().join("../..")
}

/// Every scanned `.rs` file, as `(workspace-relative path, text)`.
///
/// The set is what git would commit: tracked files plus untracked ones not
/// ignored, so build output is never scanned while a new, unadded source is.
fn scanned_files() -> Vec<(String, String)> {
    let root = workspace();
    let listed = std::process::Command::new("git")
        .arg("-C")
        .arg(&root)
        .args([
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ])
        .args(["--", "src", "tools", "examples", "editors"])
        .output();
    assert!(
        matches!(&listed, Ok(out) if out.status.success()),
        "git ls-files must list the workspace checkout: {listed:?}"
    );
    let stdout = listed.map(|out| out.stdout).unwrap_or_default();
    let listed = String::from_utf8(stdout);
    assert!(
        listed.is_ok(),
        "git ls-files listed a non-UTF-8 path: {listed:?}"
    );
    let listed = listed.unwrap_or_default();
    let mut files = Vec::new();
    let mut unreadable = Vec::new();
    for rel in listed.split('\0') {
        let is_rust = std::path::Path::new(rel)
            .extension()
            .is_some_and(|ext| ext == "rs");
        if rel.is_empty() || !is_rust {
            continue;
        }
        let path = root.join(rel);
        match std::fs::read_to_string(&path) {
            Ok(text) => files.push((rel.to_owned(), text)),
            // `--cached` still lists a tracked file deleted from the worktree.
            Err(e)
                if e.kind() == std::io::ErrorKind::NotFound && path.symlink_metadata().is_err() => {
            }
            Err(e) => unreadable.push(format!("{rel}: {e}")),
        }
    }
    assert!(
        unreadable.is_empty(),
        "unreadable scanned files: {unreadable:?}"
    );
    files
}

/// Every file outside [`ALLOWED`] that names [`FACADE`].
fn outside_reach(files: &[(String, String)]) -> Vec<String> {
    files
        .iter()
        .filter(|(rel, text)| {
            text.contains(FACADE) && !ALLOWED.iter().any(|prefix| rel.starts_with(prefix))
        })
        .map(|(rel, _)| rel.clone())
        .collect()
}

#[test]
fn only_the_language_server_features_reach_the_degraded_analysis() {
    let files = scanned_files();
    let this_file = format!("src/ipe-cli/tests/{FACADE}_scan.rs");
    assert!(
        files.iter().any(|(rel, _)| *rel == this_file),
        "the scan must list this file (the listing is not vacuous)"
    );
    assert!(
        files
            .iter()
            .any(|(rel, text)| rel.starts_with("src/lsp/features/src/") && text.contains(FACADE)),
        "the language-server features must reach the facade (the scan is not vacuous)"
    );
    let outside = outside_reach(&files);
    assert!(
        outside.is_empty(),
        "the degraded analysis is for interactive requests only; build, check \
         and diagnostics read the strict queries:\n{}",
        outside.join("\n")
    );
}

#[test]
fn a_planted_reach_from_the_cli_is_refused() {
    let planted = vec![
        (
            "src/lsp/features/src/db_access.rs".to_owned(),
            format!("use ipe_db::{FACADE};\n"),
        ),
        (
            "src/compiler/db/src/lib.rs".to_owned(),
            format!("pub mod {FACADE};\n"),
        ),
        (
            "src/ipe-cli/src/check.rs".to_owned(),
            format!("let types = ipe_db::{FACADE}::typecheck_module(db, root, entry, file);\n"),
        ),
        (
            "src/lsp/features/tests/hover.rs".to_owned(),
            format!("use ipe_db::{FACADE};\n"),
        ),
    ];
    assert_eq!(
        outside_reach(&planted),
        vec![
            "src/ipe-cli/src/check.rs".to_owned(),
            "src/lsp/features/tests/hover.rs".to_owned(),
        ]
    );
}
