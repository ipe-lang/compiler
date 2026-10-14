#![forbid(unsafe_code)]
//! Pins which workspace Rust files write the HTML less-than entity.
//!
//! An HTML escaper is the code that writes the `lt` entity for `<`. Each side
//! of the compiler/runtime boundary has one owner (`ipe_docs::html::escape` on
//! the compiler side, `ipe_runtime::escape` on the runtime side), and every other site calls it. A pasted copy is the bug class
//! this scan closes: a copy that misses `'` or `"` is an attribute-injection
//! foothold. The scan is an inventory, never a denylist of spellings: every
//! tracked `.rs` file under `src/`, `tools/`, `examples/` and `editors/` that
//! holds the entity in any of its three spellings (named, decimal, hex; any
//! case) is listed below with exact counts, production and test separately. A
//! file outside the inventory, a count that moves, or an inventoried file that
//! no longer holds the entity goes red.
//!
//! What it refuses: the three entity spellings written literally. It does not
//! claim to see an entity assembled at run time from pieces; review owns that.
//! Emitted goldens under the root `tests/golden/` are generated output and not
//! scanned. This file spells the entities through `concat!`, so it holds none.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

/// The named spelling of the HTML less-than entity.
const NAMED: &str = concat!("&", "lt;");

/// The decimal spelling of the HTML less-than entity.
const DECIMAL: &str = concat!("&", "#60;");

/// The hex spelling of the HTML less-than entity, lowercase.
const HEX: &str = concat!("&", "#x3c;");

/// The three spellings, lowercase.
const ENTITY_SPELLINGS: [&str; 3] = [NAMED, DECIMAL, HEX];

/// Every file that writes the entity, as (workspace-relative path, production
/// occurrences, test occurrences).
///
/// Test occurrences are those in a `tests/` tree or after a file's first
/// inline `#[cfg(test)]` module.
const INVENTORY: &[(&str, usize, usize)] = &[
    // Doc CLI: the JS search script's `esc()` (browser-side source).
    ("src/ipe-cli/src/doc.rs", 1, 1),
    // Tests of the doc bundle's escaped reference pages.
    ("src/ipe-cli/src/doc_bundle.rs", 0, 2),
    // XML escaping for plists and manifests (a different grammar).
    ("src/ipe-cli/src/pack.rs", 1, 5),
    // Golden tests asserting rendered HTML.
    ("src/ipe-cli/tests/g_stdui/golden_html_attrs.rs", 0, 2),
    ("src/ipe-cli/tests/g_stdui/golden_html_render_raw.rs", 0, 1),
    // Tests of the docs site generator's escaped headings.
    ("src/ipe-docs/src/bin/gen_site.rs", 0, 1),
    // The compiler-side owner (`ipe_docs::html::escape`).
    ("src/ipe-docs/src/html.rs", 1, 0),
    // Tests of the Markdown walker's escaping.
    ("src/ipe-docs/src/markdown/walker.rs", 0, 3),
    // Tests of the highlighted-code escaping.
    ("src/ipe-docs/src/render.rs", 0, 2),
    // The compiler-side owner's byte contract.
    ("src/ipe-docs/tests/html_escape_contract.rs", 0, 3),
    // Tests of the debugger overlay's escaped label.
    ("src/runtime/rust/src/debugger/server.rs", 0, 3),
    // The runtime owner: its byte-contract doc and the escaper itself.
    ("src/runtime/rust/src/escape.rs", 2, 2),
    // Tests of the render sink's escaping.
    ("src/runtime/rust/src/html.rs", 0, 7),
    ("src/runtime/rust/src/ui/template.rs", 0, 2),
    // The dev console page's JS `esc()` (browser-side source).
    ("src/runtime/rust/src/web/console.rs", 1, 0),
    ("src/runtime/rust/src/web/mod.rs", 0, 2),
    ("src/runtime/rust/src/web/template.rs", 0, 3),
];

/// The runtime owner's workspace-relative path.
const RUNTIME_OWNER: &str = "src/runtime/rust/src/escape.rs";

/// The workspace root.
fn workspace() -> PathBuf {
    e2e_support::manifest_dir!().join("../..")
}

/// Every scanned `.rs` file, as `(workspace-relative path, text)`.
///
/// The set is what git would commit: tracked files plus untracked ones not
/// ignored, so build output is never scanned while a new, unadded source is.
/// Hidden directories are skipped.
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
        let dir = rel.rsplit_once('/').map_or("", |(dir, _)| dir);
        if rel.is_empty() || !is_rust || dir.split('/').any(|d| d.starts_with('.')) {
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

/// The byte offset where the test part of `text` starts.
///
/// A file in a `tests/` tree is all test. Otherwise the test part starts at
/// the first `#[cfg(test)]` line whose item (after further attributes) is an
/// inline `mod ... {`; a file with none is all production.
fn test_region_start(rel: &str, text: &str) -> usize {
    let dir = rel.rsplit_once('/').map_or("", |(dir, _)| dir);
    if dir.split('/').any(|d| d == "tests") {
        return 0;
    }
    let lines: Vec<&str> = text.split('\n').collect();
    let mut offset = 0usize;
    for (at, line) in lines.iter().enumerate() {
        if line.trim() == "#[cfg(test)]" {
            let item = lines
                .iter()
                .skip(at.saturating_add(1))
                .copied()
                .map(str::trim)
                .find(|l| !l.starts_with("#["));
            if item.is_some_and(|l| {
                (l.starts_with("mod ") || l.starts_with("pub mod ")) && l.ends_with('{')
            }) {
                return offset;
            }
        }
        offset = offset.saturating_add(line.len()).saturating_add(1);
    }
    text.len()
}

/// Occurrences of every entity spelling in `text`, case-insensitively.
fn entity_count(text: &str) -> usize {
    let lower = text.to_ascii_lowercase();
    ENTITY_SPELLINGS
        .iter()
        .map(|needle| lower.matches(needle).count())
        .sum()
}

/// One line per file whose (production, test) entity counts differ from
/// [`INVENTORY`]; empty when the tree matches it exactly.
fn inventory_drift(files: &[(String, String)]) -> Vec<String> {
    let mut found: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
    for (rel, text) in files {
        let split = test_region_start(rel, text);
        let production = text.get(..split).map_or(0, entity_count);
        let test = text.get(split..).map_or(0, entity_count);
        if production > 0 || test > 0 {
            found.insert(rel.as_str(), (production, test));
        }
    }
    let expected: BTreeMap<&str, (usize, usize)> = INVENTORY
        .iter()
        .map(|(rel, production, test)| (*rel, (*production, *test)))
        .collect();
    let names: BTreeSet<&str> = found.keys().chain(expected.keys()).copied().collect();
    names
        .into_iter()
        .filter_map(|rel| {
            let got = found.get(rel).copied().unwrap_or((0, 0));
            let want = expected.get(rel).copied().unwrap_or((0, 0));
            (got != want)
                .then(|| format!("{rel}: (production, test) = {got:?}, inventory {want:?}"))
        })
        .collect()
}

/// The inventoried files as an in-memory tree, each holding exactly its
/// inventoried counts.
fn inventory_tree() -> Vec<(String, String)> {
    let body = |n: usize| format!("const E: &str = \"{NAMED}\";\n").repeat(n);
    INVENTORY
        .iter()
        .map(|(rel, production, test)| {
            let text = if *test == 0 {
                body(*production)
            } else if rel.split('/').any(|d| d == "tests") {
                body(*test)
            } else {
                format!(
                    "{}#[cfg(test)]\nmod tests {{\n{}}}\n",
                    body(*production),
                    body(*test)
                )
            };
            ((*rel).to_owned(), text)
        })
        .collect()
}

/// A pasted escaper arm writing `entity`.
fn pasted_arm(entity: &str) -> String {
    format!(
        "fn esc(c: char, out: &mut String) {{ match c {{ '<' => out.push_str(\"{entity}\"), _ => out.push(c) }} }}\n"
    )
}

/// The drift after `edit` changes the synthetic inventory tree.
fn drift_after(edit: impl FnOnce(&mut Vec<(String, String)>)) -> Vec<String> {
    let mut tree = inventory_tree();
    edit(&mut tree);
    inventory_drift(&tree)
}

/// Adds `extra` to the start (`prepend`) or end of the synthetic runtime owner.
fn append_to_owner(tree: &mut [(String, String)], prepend: bool, extra: &str) {
    let owner = tree.iter_mut().find(|(rel, _)| rel == RUNTIME_OWNER);
    assert!(owner.is_some(), "the runtime owner must be inventoried");
    if let Some((_, text)) = owner {
        *text = if prepend {
            format!("{extra}{text}")
        } else {
            format!("{text}{extra}")
        };
    }
}

#[test]
fn html_entity_writers_are_exactly_the_inventory() {
    let files = scanned_files();
    assert!(
        files
            .iter()
            .any(|(rel, _)| rel == "src/ipe-cli/tests/html_entity_owner_scan.rs"),
        "the scan must list this file (the listing is not vacuous)"
    );
    let drift = inventory_drift(&files);
    assert!(
        drift.is_empty(),
        "HTML entity writers drifted from the inventory. Call the sink's one \
         escaper (`ipe_docs::html::escape`, runtime `escape::html_text`/`html_attr`) instead of pasting \
         one; update INVENTORY only for a new owner:\n{}",
        drift.join("\n")
    );
}

#[test]
fn the_synthetic_inventory_tree_is_clean() {
    assert_eq!(inventory_drift(&inventory_tree()), Vec::<String>::new());
}

#[test]
fn a_pasted_escaper_in_a_new_file_is_refused() {
    let drift = drift_after(|tree| {
        tree.push((
            "src/runtime/rust/src/new_page.rs".to_owned(),
            pasted_arm(NAMED),
        ));
    });
    assert_eq!(
        drift,
        vec![
            "src/runtime/rust/src/new_page.rs: (production, test) = (1, 0), inventory (0, 0)"
                .to_owned()
        ]
    );
}

#[test]
fn a_pasted_escaper_in_an_inventoried_file_is_refused() {
    let drift = drift_after(|tree| append_to_owner(tree, true, &pasted_arm(NAMED)));
    assert_eq!(
        drift,
        vec![format!(
            "{RUNTIME_OWNER}: (production, test) = (3, 2), inventory (2, 2)"
        )]
    );
}

#[test]
fn a_paste_into_a_test_module_moves_the_test_count() {
    let drift = drift_after(|tree| append_to_owner(tree, false, &pasted_arm(NAMED)));
    assert_eq!(
        drift,
        vec![format!(
            "{RUNTIME_OWNER}: (production, test) = (2, 3), inventory (2, 2)"
        )]
    );
}

#[test]
fn decimal_and_uppercase_hex_spellings_are_refused() {
    for entity in [DECIMAL.to_owned(), HEX.to_ascii_uppercase()] {
        let drift = drift_after(|tree| {
            tree.push((
                "src/ipe-docs/src/new_page.rs".to_owned(),
                pasted_arm(&entity),
            ));
        });
        assert_eq!(
            drift,
            vec![
                "src/ipe-docs/src/new_page.rs: (production, test) = (1, 0), inventory (0, 0)"
                    .to_owned()
            ],
            "{entity}"
        );
    }
}

#[test]
fn an_inventoried_file_that_no_longer_writes_the_entity_is_refused() {
    let drift = drift_after(|tree| {
        tree.retain(|(rel, _)| rel != "src/runtime/rust/src/web/console.rs");
    });
    assert_eq!(
        drift,
        vec![
            "src/runtime/rust/src/web/console.rs: (production, test) = (0, 0), inventory (1, 0)"
                .to_owned()
        ]
    );
}
