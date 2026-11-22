//! `docs/topics/shapes.md`'s shape table never drifts from
//! [`ipe::init::InitShape::ALL`], the single source of truth for which
//! scaffold shapes `ipe init` offers.
//!
//! The table is the page's load-bearing content: a reader who counts its rows
//! must get the same answer `ipe init` gives. Rather than hand-sync a shape
//! count into the page's prose, this test extracts every bolded shape name
//! from the table's first column and asserts the sequence equals `ALL`, in
//! order — so a shape added to, removed from, or reordered in `InitShape`
//! fails this test the moment the page falls out of step.

use ipe::init::InitShape;
use std::path::PathBuf;

/// The repository root, two levels above this crate's manifest directory
/// (`<root>/src/ipe-cli`).
fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

/// Every shape name in the table's first column, in row order: a line shaped
/// like `| **Web** ... |` yields `"Web"`, with any trailing note (` *(default)*`)
/// dropped.
fn table_shape_names(markdown: &str) -> Vec<String> {
    let mut names = Vec::new();
    for line in markdown.lines() {
        let Some(after_bar) = line.strip_prefix("| **") else {
            continue;
        };
        let Some(end) = after_bar.find("**") else {
            continue;
        };
        names.push(after_bar[..end].to_owned());
    }
    names
}

#[test]
fn shapes_table_matches_init_shape_all() -> Result<(), Box<dyn std::error::Error>> {
    let path = repo_root().join("docs/topics/shapes.md");
    let markdown = std::fs::read_to_string(&path)?;

    let found = table_shape_names(&markdown);
    let expected: Vec<String> = InitShape::ALL
        .iter()
        .map(|shape| format!("{shape:?}"))
        .collect();

    assert_eq!(
        found,
        expected,
        "docs/topics/shapes.md's shape table rows must equal InitShape::ALL, \
         in order; read from {}",
        path.display()
    );
    Ok(())
}
