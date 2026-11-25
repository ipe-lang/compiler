#![forbid(unsafe_code)]
//! Refuses every hand-written FFI crate root outside the crate-scope SSOT.
//!
//! A crate that compiles an emitted `src/ffi.rs` resolves the bindings' `use
//! crate::*;` against its own root. Every such root takes its items from
//! `ipe_intern::FFI_SCOPE_ITEMS`, the scope the backend's template is held to
//! at build time; a root spelled by hand drifts from it the moment the scope
//! gains an item, and a binding that builds under the hand root then fails in
//! the shipped crate (or the reverse).
//!
//! The scan walks every file under `src/` and `tools/` and refuses a string
//! or byte-string literal, or a `concat!`-joined one, whose text holds a
//! scope item or declares the bindings module (`mod ffi`): a root assembled
//! from `format!` pieces still has to declare the module it compiles. Text is
//! compared with its whitespace removed, so neither reflowing nor re-indenting
//! a copy hides it. Attribute content (a doc comment included) is prose, not a
//! crate root, so it is not scanned. A `.rs` file the lexer turns away is
//! checked over its raw text, and so is every other non-Markdown file (a
//! template an `include_str!` reads), so what the scan cannot read is never a
//! pass by default.

use std::path::{Path, PathBuf};
use std::str::FromStr;

use proc_macro2::{Delimiter, TokenStream, TokenTree};

/// The crate-scope-scan fixtures, relative to this crate's manifest directory.
const FIXTURES: &str = "tests/fixtures/crate_scope_scan";

/// The same fixtures, workspace-relative: planted roots this scan owns.
const FIXTURES_REL: &str = "tools/e2e-support/tests/fixtures/crate_scope_scan/";

/// The bindings module every crate root that compiles emitted `src/ffi.rs`
/// declares. Kept apart from the keyword so this file spells no declaration.
const BINDINGS_MODULE: &str = "ffi";

/// What may follow a module declaration's name: `;` or an inline body.
const DECLARATION_ENDS: [char; 2] = [';', '{'];

/// The trees the scan walks, relative to the workspace root.
const ROOTS: &[&str] = &["src", "tools"];

/// Paths that own the scope's text: the SSOT, the template it is asserted
/// against, and this scan's planted fixtures.
const OWNERS: &[&str] = &[SSOT, "src/compiler/backend/rust/templates/", FIXTURES_REL];

/// The crate-scope SSOT, workspace-relative.
const SSOT: &str = "src/compiler/intern/src/ffi_scope.rs";

/// Exempt files: `(path, reason)`. Every entry needs a reason, and a test
/// fails once the file no longer trips the scan.
const ALLOWLIST: &[(&str, &str)] = &[
    (
        "src/compiler/backend/rust/src/project.rs",
        "reads the template's own text: the entry-spine cut starts at the error \
         import and the env barrel splices after the runtime glob; both are \
         anchors into the template, never a crate root of their own",
    ),
    (
        "src/ipe-cli/src/audit_native.rs",
        "the native audit's probe root is spelled by hand; rendering it from the \
         scope is its own planned change to that file",
    ),
];

/// One refused literal: its 1-based line, or 0 for an unlexable file.
type Finding = usize;

/// The scope items as the scan compares them (whitespace removed, the
/// closing `;` trimmed so a copy without it still matches), then the
/// bindings-module declarations.
fn needles() -> Vec<String> {
    ipe_intern::FFI_SCOPE_ITEMS
        .iter()
        .map(|item| squash(item.trim_end_matches(';')))
        .chain(
            DECLARATION_ENDS
                .iter()
                .map(|end| format!("mod{BINDINGS_MODULE}{end}")),
        )
        .collect()
}

/// `text` with every whitespace character removed.
fn squash(text: &str) -> String {
    text.chars().filter(|c| !c.is_whitespace()).collect()
}

fn holds_item(text: &str, needles: &[String]) -> bool {
    let squashed = squash(text);
    needles.iter().any(|n| squashed.contains(n.as_str()))
}

/// Every refused literal in `text`.
fn scan_source(text: &str, needles: &[String]) -> Vec<Finding> {
    let Ok(tokens) = TokenStream::from_str(text) else {
        return if holds_item(text, needles) {
            vec![0]
        } else {
            Vec::new()
        };
    };
    let mut out = Vec::new();
    scan_tokens(tokens, needles, &mut out);
    out.sort_unstable();
    out
}

fn scan_tokens(tokens: TokenStream, needles: &[String], out: &mut Vec<Finding>) {
    let trees: Vec<TokenTree> = tokens.into_iter().collect();
    let mut i = 0;
    while let Some(tree) = trees.get(i) {
        match tree {
            // An attribute (`#[…]`, `#![…]`) is skipped whole.
            TokenTree::Punct(p) if p.as_char() == '#' => {
                let bang =
                    matches!(trees.get(i + 1), Some(TokenTree::Punct(b)) if b.as_char() == '!');
                let body = if bang { i + 2 } else { i + 1 };
                let is_attr = matches!(
                    trees.get(body),
                    Some(TokenTree::Group(g)) if g.delimiter() == Delimiter::Bracket
                );
                i = if is_attr { body + 1 } else { i + 1 };
            }
            // `concat!(…)` is judged on its joined pieces.
            TokenTree::Ident(id)
                if id == "concat"
                    && matches!(trees.get(i + 1), Some(TokenTree::Punct(b)) if b.as_char() == '!') =>
            {
                if let Some(TokenTree::Group(g)) = trees.get(i + 2) {
                    let joined: String = g
                        .stream()
                        .into_iter()
                        .filter_map(|t| match t {
                            TokenTree::Literal(l) => str_value(&l),
                            _ => None,
                        })
                        .collect();
                    if holds_item(&joined, needles) {
                        out.push(g.span().start().line);
                    }
                    scan_tokens(g.stream(), needles, out);
                    i += 3;
                } else {
                    i += 1;
                }
            }
            TokenTree::Literal(l) => {
                if str_value(l).is_some_and(|v| holds_item(&v, needles)) {
                    out.push(l.span().start().line);
                }
                i += 1;
            }
            TokenTree::Group(g) => {
                scan_tokens(g.stream(), needles, out);
                i += 1;
            }
            _ => i += 1,
        }
    }
}

/// The text of a string, byte-string or C-string literal.
fn str_value(lit: &proc_macro2::Literal) -> Option<String> {
    match syn::Lit::new(lit.clone()) {
        syn::Lit::Str(s) => Some(s.value()),
        syn::Lit::ByteStr(b) => Some(String::from_utf8_lossy(&b.value()).into_owned()),
        syn::Lit::CStr(c) => Some(c.value().to_string_lossy().into_owned()),
        _ => None,
    }
}

/// The workspace root: two levels above this crate's manifest directory.
fn workspace_root() -> PathBuf {
    let dir = e2e_support::manifest_dir!();
    dir.ancestors()
        .nth(2)
        .map_or_else(|| dir.clone(), Path::to_path_buf)
}

/// Every file under `dir`, workspace-relative, skipping build output and
/// hidden directories. Links are not followed.
fn rust_files(root: &Path, dir: &Path, out: &mut Vec<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        let path = entry.path();
        if kind.is_dir() {
            if name.starts_with('.') || name == "target" || name == "node_modules" {
                continue;
            }
            rust_files(root, &path, out);
        } else if kind.is_file()
            && let Ok(rel) = path.strip_prefix(root)
        {
            out.push(rel.to_string_lossy().replace('\\', "/"));
        }
    }
}

/// The findings in one file: a `.rs` file is lexed, Markdown is prose, and
/// any other text is judged raw. The extensions match exactly, so an
/// odd-case one is judged raw, the stricter reading. A file that is not
/// UTF-8 can be neither compiled as Rust nor read by `include_str!`, so it
/// holds no crate root.
fn scan_file(rel: &str, path: &Path, needles: &[String]) -> Vec<Finding> {
    let extension = Path::new(rel).extension().and_then(|e| e.to_str());
    if extension == Some("md") {
        return Vec::new();
    }
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    if extension == Some("rs") {
        scan_source(&text, needles)
    } else if holds_item(&text, needles) {
        vec![0]
    } else {
        Vec::new()
    }
}

fn is_owner(rel: &str) -> bool {
    OWNERS
        .iter()
        .any(|o| rel == *o || (o.ends_with('/') && rel.starts_with(o)))
}

/// Every non-owner file holding a scope item, with its findings.
fn tree_findings() -> Vec<(String, Vec<Finding>)> {
    let root = workspace_root();
    let mut files = Vec::new();
    for top in ROOTS {
        rust_files(&root, &root.join(top), &mut files);
    }
    assert!(
        files.iter().any(|f| f == SSOT),
        "the walk must reach the crate-scope SSOT; it read {} files under {}",
        files.len(),
        root.display()
    );
    files.sort();
    let needles = needles();
    files
        .into_iter()
        .filter(|rel| !is_owner(rel))
        .filter_map(|rel| {
            let found = scan_file(&rel, &root.join(&rel), &needles);
            (!found.is_empty()).then_some((rel, found))
        })
        .collect()
}

#[allow(clippy::expect_used)] // a missing fixture IS the failure
fn fixture(name: &str) -> Vec<Finding> {
    let path = e2e_support::manifest_dir!().join(FIXTURES).join(name);
    let text = std::fs::read_to_string(&path).expect("read the crate-scope-scan fixture");
    scan_source(&text, &needles())
}

#[test]
fn a_hand_written_crate_root_is_refused() {
    let found = fixture("hand_root.rs.txt");
    assert!(
        found.len() >= 3,
        "the plain, reflowed and concat-joined roots must each be refused: {found:?}"
    );
}

#[test]
fn prose_and_unrelated_literals_pass() {
    let found = fixture("prose_only.rs.txt");
    assert!(found.is_empty(), "prose is not a crate root: {found:?}");
}

#[test]
fn a_root_assembled_from_pieces_or_bytes_is_refused() {
    let found = fixture("pieces_root.rs.txt");
    assert_eq!(
        found.len(),
        3,
        "the format!-built, byte-string and inline-module roots must each be refused: {found:?}"
    );
}

#[test]
fn a_template_outside_rust_source_is_refused() {
    let root = workspace_root();
    let rel = format!("{FIXTURES_REL}template_root.txt");
    assert_eq!(
        scan_file(&rel, &root.join(&rel), &needles()),
        vec![0],
        "a non-Rust template holding a crate root is judged raw"
    );
    let md = format!("{FIXTURES_REL}prose.md");
    assert!(
        scan_file(&md, &root.join(&md), &needles()).is_empty(),
        "Markdown is prose, never a crate root"
    );
}

#[test]
fn an_unlexable_file_holding_a_root_is_refused() {
    let text = format!("\"unterminated {}", ipe_intern::RUNTIME_GLOB_ITEM);
    assert_eq!(scan_source(&text, &needles()), vec![0]);
}

#[test]
fn every_crate_root_takes_the_scope_from_its_ssot() {
    let findings = tree_findings();
    let unexpected: Vec<String> = findings
        .iter()
        .filter(|(rel, _)| !ALLOWLIST.iter().any(|(path, _)| path == rel))
        .map(|(rel, lines)| format!("{rel}: lines {lines:?}"))
        .collect();
    assert!(
        unexpected.is_empty(),
        "hand-written FFI crate roots; render them from `ipe_intern::ffi_crate_root()` or `ffi_crate_scope()`:\n{}",
        unexpected.join("\n")
    );
    let stale: Vec<&str> = ALLOWLIST
        .iter()
        .filter(|(path, _)| !findings.iter().any(|(rel, _)| rel == path))
        .map(|(path, _)| *path)
        .collect();
    assert!(
        stale.is_empty(),
        "allowlist entries that no longer trip the scan; drop them:\n{}",
        stale.join("\n")
    );
}
