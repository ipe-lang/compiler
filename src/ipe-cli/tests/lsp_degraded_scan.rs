#![forbid(unsafe_code)]
//! Pins which workspace Rust files reach the degraded analysis.
//!
//! The degraded queries in `ipe_db` answer for a module that failed: they
//! leave each failing declaration out and keep analysing the rest. That is
//! the right answer for an editor request and a wrong one for anything that
//! builds, checks, or reports, which must refuse with the module's first
//! error. The facade's module is therefore named only by the interactive
//! language-server features (`src/lsp/features/src/`), by its own file and
//! tests in the database crate, and by the one `pub mod` line declaring it,
//! so no other module of the database crate (where the strict pipeline
//! lives) reads it or re-exports it under another name. The features crate
//! re-exposes the degraded results through its own accessors, so only the
//! language server depends on it, and the server re-exports none of it.
//!
//! The scan covers every `.rs` and `Cargo.toml` file git would commit under
//! `src/`, `tools/`, `examples/` and `editors/`. This file spells each
//! guarded name through `concat!`, so it holds none.

use std::path::PathBuf;

/// The degraded facade's module name.
const FACADE: &str = concat!("lsp", "_degraded");

/// The workspace-relative prefixes allowed to name [`FACADE`] anywhere.
const ALLOWED: [&str; 2] = ["src/lsp/features/src/", "src/compiler/db/tests/"];

/// The database crate's root, which may name [`FACADE`] only to declare it.
const DB_ROOT: &str = "src/compiler/db/src/lib.rs";

/// The features crate, which re-exposes the degraded results.
const FEATURES: &str = concat!("ipe_lsp", "_features");

/// The manifests allowed to name [`FEATURES`]: its own and the language server's.
const FEATURES_MANIFESTS: [&str; 2] = ["src/lsp/features/Cargo.toml", "src/lsp/server/Cargo.toml"];

/// The language server's sources, which must not re-export [`FEATURES`].
const SERVER: &str = "src/lsp/server/";

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
        let path = std::path::Path::new(rel);
        let is_rust = path.extension().is_some_and(|ext| ext == "rs");
        let is_manifest = path.file_name().is_some_and(|name| name == "Cargo.toml");
        if rel.is_empty() || !(is_rust || is_manifest) {
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

/// Whether `rel` may name [`FACADE`] as `text` does.
fn may_name_facade(rel: &str, text: &str) -> bool {
    let own_file = format!("src/compiler/db/src/{FACADE}.rs");
    let declaration = format!("pub mod {FACADE};");
    ALLOWED.iter().any(|prefix| rel.starts_with(prefix))
        || rel == own_file
        || (rel == DB_ROOT
            && text
                .lines()
                .filter(|line| line.contains(FACADE))
                .all(|line| line.trim() == declaration))
}

/// Whether `rel`, holding `text`, reaches the degraded analysis outside the language server.
fn reaches(rel: &str, text: &str) -> bool {
    if std::path::Path::new(rel)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("rs"))
    {
        (text.contains(FACADE) && !may_name_facade(rel, text))
            || (rel.starts_with(SERVER) && text.contains(&format!("pub use {FEATURES}")))
    } else {
        text.contains(FEATURES) && !FEATURES_MANIFESTS.contains(&rel)
    }
}

/// Every file that reaches the degraded analysis outside the language server.
fn outside_reach(files: &[(String, String)]) -> Vec<String> {
    files
        .iter()
        .filter(|(rel, text)| reaches(rel, text))
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
        (
            format!("src/compiler/db/src/{FACADE}.rs"),
            format!("//! {FACADE}\n"),
        ),
        (
            "src/compiler/db/tests/differential.rs".to_owned(),
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

#[test]
fn a_planted_reach_inside_the_database_crate_is_refused() {
    let planted = vec![
        (
            DB_ROOT.to_owned(),
            format!("pub mod {FACADE};\npub use {FACADE}::typecheck_module as lenient;\n"),
        ),
        (
            "src/compiler/db/src/build.rs".to_owned(),
            format!("let types = crate::{FACADE}::typecheck_module(db, root, entry, file);\n"),
        ),
    ];
    assert_eq!(
        outside_reach(&planted),
        vec![
            DB_ROOT.to_owned(),
            "src/compiler/db/src/build.rs".to_owned()
        ]
    );
}

#[test]
fn a_planted_dependency_on_the_features_crate_is_refused() {
    let planted = vec![
        (
            "src/lsp/server/Cargo.toml".to_owned(),
            format!("{FEATURES} = {{ path = \"../features\" }}\n"),
        ),
        (
            "src/lsp/features/Cargo.toml".to_owned(),
            format!("name = \"{FEATURES}\"\n"),
        ),
        (
            "src/ipe-cli/Cargo.toml".to_owned(),
            format!("{FEATURES} = {{ path = \"../lsp/features\" }}\n"),
        ),
        (
            "src/lsp/server/src/lib.rs".to_owned(),
            format!("pub use {FEATURES}::db_access;\n"),
        ),
        (
            "src/lsp/server/src/hover.rs".to_owned(),
            format!("use {FEATURES}::hover::hover;\n"),
        ),
    ];
    assert_eq!(
        outside_reach(&planted),
        vec![
            "src/ipe-cli/Cargo.toml".to_owned(),
            "src/lsp/server/src/lib.rs".to_owned(),
        ]
    );
}
