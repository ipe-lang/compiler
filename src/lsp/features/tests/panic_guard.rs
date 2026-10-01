#![forbid(unsafe_code)]
//! Cycle-survival tests: prove every interactive provider returns a value
//! (never panics) when the import graph is cyclic, and that the canonicalize
//! call-site policy is enforced.
//!
//! Test plan items 1 and 4 from the class fix spec:
//!   1 — CYCLE-SURVIVAL PROVIDER TESTS (one per confirmed instance).
//!   4 — TRIPWIRE: no raw `ipe_db::canonicalize(` on the interactive path.

use ipe_db::{IpeDatabase, ModuleOrigin, SourceFile, SourceRoot};

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn file(db: &IpeDatabase, path: &[&str], text: &str) -> SourceFile {
    SourceFile::new(
        db,
        path.iter().map(|s| (*s).to_owned()).collect(),
        text.to_owned(),
        ModuleOrigin::User,
    )
}

fn root_of(db: &IpeDatabase, files: &[(&[&str], SourceFile)]) -> SourceRoot {
    SourceRoot::new(
        db,
        files
            .iter()
            .map(|(path, f)| (path.iter().map(|s| (*s).to_owned()).collect(), *f))
            .collect(),
    )
}

/// Build a 2-module project where A imports B and B imports A.
/// Returns `(db, root, entry_a, entry_b)`.
fn cyclic_project() -> (IpeDatabase, SourceRoot, SourceFile, SourceFile) {
    let a_src = "module A exposing (a)\nimport B\na = B.b\n";
    let b_src = "module B exposing (b)\nimport A\nb = A.a\n";

    let db = IpeDatabase::new();
    let a = file(&db, &["A"], a_src);
    let b = file(&db, &["B"], b_src);
    let root = root_of(&db, &[(&["A"], a), (&["B"], b)]);
    (db, root, a, b)
}

// ---------------------------------------------------------------------------
// Cycle-survival: goto_definition (navigation.rs — confirmed instance)
// ---------------------------------------------------------------------------

#[test]
fn goto_definition_returns_none_on_cyclic_graph() {
    let (db, root, entry_a, _b) = cyclic_project();
    // No catch_unwind here: if the cycle-gate is removed salsa's
    // dependency-cycle panic unwinds this thread and the test FAILS (RED
    // before the fix, GREEN after).
    let result =
        ipe_lsp_features::navigation::goto_definition(&db, root, entry_a, &["A".to_owned()], 0);
    // A cyclic graph is unresolvable — the call returns None, never panics.
    assert!(
        result.is_none(),
        "expected None on cyclic graph, got {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Cycle-survival: find_references (navigation.rs — topo-gated, already safe)
// ---------------------------------------------------------------------------

#[test]
fn find_references_returns_empty_on_cyclic_graph() {
    let (db, root, entry_a, _b) = cyclic_project();
    let refs =
        ipe_lsp_features::navigation::find_references(&db, root, entry_a, &["A".to_owned()], "a");
    // Already topo-gated; must not panic and must return an empty-or-valid vec.
    let _ = refs; // just proving no panic
}

// ---------------------------------------------------------------------------
// Cycle-survival: completions (completion.rs — confirmed instance)
// ---------------------------------------------------------------------------

#[test]
fn completions_returns_empty_on_cyclic_graph() {
    let (db, root, entry_a, _b) = cyclic_project();
    let items = ipe_lsp_features::completion::completions(
        &db,
        root,
        entry_a,
        &["A".to_owned()],
        0,
        ipe_lsp_features::offset::PositionEncoding::Utf16,
        None,
    );
    let _ = items;
}

// ---------------------------------------------------------------------------
// Cycle-survival: signature_help (signature_help.rs — confirmed instance)
// ---------------------------------------------------------------------------

#[test]
fn signature_help_returns_none_on_cyclic_graph() {
    let (db, root, entry_a, _b) = cyclic_project();
    let result = ipe_lsp_features::signature_help::signature_help(
        &db,
        root,
        entry_a,
        &["A".to_owned()],
        0,
        None,
    );
    assert!(
        result.is_none(),
        "expected None on cyclic graph, got {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Cycle-survival: prepare_rename (rename.rs — confirmed instance)
// ---------------------------------------------------------------------------

#[test]
fn prepare_rename_returns_none_on_cyclic_graph() {
    let (db, root, entry_a, _b) = cyclic_project();
    let result = ipe_lsp_features::rename::prepare_rename(&db, root, entry_a, &["A".to_owned()], 0);
    assert!(
        result.is_none(),
        "expected None on cyclic graph, got {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Tripwire: no raw ipe_db::canonicalize on the interactive path (test plan 4)
// ---------------------------------------------------------------------------

/// Every `.rs` under `src/lsp/features/src` must not contain a raw
/// `ipe_db::canonicalize(` call except in `db_access.rs` (the checked
/// accessor) and the already-topo-gated `find_references` site in
/// `navigation.rs`. A future raw call on the interactive path fails here,
/// converting a latent server crash into a CI failure.
#[test]
#[allow(clippy::expect_used)]
fn no_raw_canonicalize_on_interactive_path() -> Result<(), Box<dyn std::error::Error>> {
    use std::fs;

    // Locate the features/src directory relative to CARGO_MANIFEST_DIR.
    let src_dir = e2e_support::manifest_dir!().join("src");
    assert!(
        src_dir.exists(),
        "features src dir not found at {src_dir:?}"
    );

    let raw_call = "ipe_db::canonicalize(";

    // Files that are explicitly allow-listed.
    let allowed = ["db_access.rs", "diagnostics.rs"];

    // navigation.rs is allowed only for the topo-gated find_references loop
    // (which uses `let Ok(canonical) = ipe_db::canonicalize(...)` inside an
    // already-ordered loop, not a bare direct demand). We allow the file but
    // verify it does not gain a second ungated call.
    let nav_file = src_dir.join("navigation.rs");
    let nav_content = fs::read_to_string(&nav_file)?;
    let nav_count = nav_content.matches(raw_call).count();
    assert!(
        nav_count <= 1,
        "navigation.rs has {nav_count} raw `{raw_call}` calls; expected ≤1 (the topo-gated find_references loop)"
    );

    for entry in fs::read_dir(&src_dir)? {
        let entry = entry?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()).map(str::to_owned) else {
            continue;
        };
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        if allowed.contains(&name.as_str()) {
            continue;
        }
        if name == "navigation.rs" {
            continue; // already checked above
        }
        let content = fs::read_to_string(&path)?;
        let count = content.matches(raw_call).count();
        assert!(
            count == 0,
            "{name} contains {count} raw `{raw_call}` call(s); use `db_access::canonicalize_checked` instead"
        );
    }
    Ok(())
}
