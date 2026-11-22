//! User-facing docs and explain pages never carry the contributor-boilerplate
//! sentence about code examples being illustrative snippets, not shell commands.
//!
//! That sentence is a leftover content bug, not a renderer concern: a reader
//! is never told the obvious at every page's top. This test reads every
//! Markdown page under the repository's `docs/` tree and this crate's
//! `explain/` tree, and fails the moment the sentence reappears anywhere.

use std::path::{Path, PathBuf};

/// The banned sentence's load-bearing fragment, present in both wordings the
/// removed sentence used ("in this page" and "below").
const BANNED_FRAGMENT: &str = "illustrative Ipê source snippets, not shell commands";

/// This crate's manifest directory, three levels under the repository root
/// (`<root>/src/compiler/diagnostics`).
fn repo_root() -> PathBuf {
    e2e_support::manifest_dir!()
        .join("..")
        .join("..")
        .join("..")
}

/// Every `.md` file under `dir`, recursively, skipping hidden directories.
fn collect_markdown(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_owned();
        if path.is_dir() {
            if !name.starts_with('.') {
                collect_markdown(&path, out)?;
            }
        } else if name.ends_with(".md") {
            out.push(path);
        }
    }
    Ok(())
}

#[test]
fn docs_and_explain_pages_carry_no_boilerplate_sentence() -> Result<(), Box<dyn std::error::Error>>
{
    let root = repo_root();

    let mut files = Vec::new();
    collect_markdown(&root.join("docs"), &mut files)?;
    collect_markdown(&e2e_support::manifest_dir!().join("explain"), &mut files)?;
    files.sort();
    assert!(
        !files.is_empty(),
        "the scan found no Markdown page at all under {}; the walk is broken",
        root.display()
    );

    let mut offenders = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file)?;
        if text.contains(BANNED_FRAGMENT) {
            offenders.push(file.display().to_string());
        }
    }
    assert!(
        offenders.is_empty(),
        "the contributor-boilerplate sentence must not appear in user-facing docs \
         or explain pages:\n{}",
        offenders.join("\n")
    );
    Ok(())
}

#[test]
fn the_banned_fragment_is_detected() {
    let hit = "The code examples in this page are illustrative Ipê source snippets, \
               not shell commands.";
    assert!(hit.contains(BANNED_FRAGMENT));
}
