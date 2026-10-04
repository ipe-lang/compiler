#![forbid(unsafe_code)]
//! Every fenced `ipe` block on every explain page and doc page meets its verdict.
//!
//! The explain pages are the registry's own: every code in `ALL_CODES` whose
//! `explain_page` exists is scanned, so a new code's page is checked the moment
//! it exists. The doc pages are every `docs/constructs` and `docs/topics` page.
//! Each block is judged in-process through the build front end
//! (`ipe::front_check_entry`: type-check, decoder gate, lowering, emit; no
//! cargo):
//!
//! - a check block (` ```ipe `) must be accepted;
//! - an error block must be refused with its expected code: the page's own code
//!   on an explain page, the code its info string names on a doc page; refused
//!   with any other code, or accepted, is a mismatch;
//! - a skip block (` ```ipe ipe:skip <reason> `) is not compiled.
//!
//! No import is ever injected; a block with no module header is only wrapped in
//! `module Main exposing (..)`. Every mismatch is reported at once.
//!
//! `explain_examples/known_rot.txt` lists the `page:line` blocks still failing:
//! a listed block must still mismatch, so the ledger can only shrink.

#[path = "explain_examples/fence.rs"]
mod fence;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use fence::{Block, Kind, Page};
use ipe_diagnostics::{ALL_CODES, Code, explain_page};

/// The blocks known to fail, one `page:line` per line.
const KNOWN_ROT: &str = include_str!("explain_examples/known_rot.txt");

/// What the front end made of one block.
#[derive(Debug)]
enum Outcome {
    /// The program was accepted.
    Accepted,
    /// The program was refused with this diagnostic code.
    Refused(Code),
    /// The check could not run (I/O, usage); the text says why.
    Failed(String),
}

/// One block whose outcome is not the one its fence asks for.
#[derive(Debug)]
struct Mismatch {
    /// `<page>:<line>`, the ledger key.
    key: String,
    /// Expected against actual.
    detail: String,
}

/// The full program for a block body: as-is with a module header, else wrapped.
fn program_source(body: &str) -> String {
    let has_header = body
        .lines()
        .find(|l| !l.trim().is_empty())
        .is_some_and(|l| l.trim_start().starts_with("module "));
    if has_header {
        format!("{body}\n")
    } else {
        format!("module Main exposing (..)\n\n{body}\n")
    }
}

/// Judge one program source in its own directory under `dir`.
fn front_check(dir: &Path, source: &str) -> Outcome {
    if let Err(e) = std::fs::create_dir_all(dir) {
        return Outcome::Failed(format!("create {}: {e}", dir.display()));
    }
    let entry = dir.join("Main.ipe");
    if let Err(e) = std::fs::write(&entry, source) {
        return Outcome::Failed(format!("write {}: {e}", entry.display()));
    }
    match ipe::front_check_entry(&entry) {
        Ok(()) => Outcome::Accepted,
        Err(ipe::CliError::Pipeline { diag, .. }) => Outcome::Refused(diag.code()),
        Err(other) => Outcome::Failed(other.to_string()),
    }
}

/// The mismatch text for `outcome` against `kind`, or `None` when it meets it.
fn verdict(kind: &Kind, outcome: &Outcome) -> Option<String> {
    match (kind, outcome) {
        (Kind::Skip(_), _) | (Kind::Check, Outcome::Accepted) => None,
        (Kind::Error(want), Outcome::Refused(got)) if want == got => None,
        (Kind::Check, Outcome::Refused(got)) => Some(format!(
            "expected the program to be accepted; refused with {}",
            got.as_str()
        )),
        (Kind::Error(want), Outcome::Refused(got)) => Some(format!(
            "expected a refusal with {}; refused with {}",
            want.as_str(),
            got.as_str()
        )),
        (Kind::Error(want), Outcome::Accepted) => Some(format!(
            "expected a refusal with {}; the program was accepted",
            want.as_str()
        )),
        (Kind::Check | Kind::Error(_), Outcome::Failed(why)) => {
            Some(format!("the check could not run: {why}"))
        }
    }
}

/// Every mismatch on one page: refused fences and blocks missing their verdict.
fn judge_page(name: &str, text: &str, page: Page, scratch: &Path) -> Vec<Mismatch> {
    let dir_stem: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    fence::scan(text, page)
        .into_iter()
        .filter_map(|item| match item {
            Err(refusal) => Some(Mismatch {
                key: format!("{name}:{}", refusal.line),
                detail: format!("fence refused: {:?}", refusal.error),
            }),
            Ok(Block {
                kind: Kind::Skip(_),
                ..
            }) => None,
            Ok(Block { line, kind, body }) => {
                let dir = scratch.join(format!("{dir_stem}_{line}"));
                let outcome = front_check(&dir, &program_source(&body));
                verdict(&kind, &outcome).map(|detail| Mismatch {
                    key: format!("{name}:{line}"),
                    detail,
                })
            }
        })
        .collect()
}

/// The ledger's `page:line` entries, comments and blank lines dropped.
fn ledger(text: &str) -> BTreeSet<&str> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect()
}

/// Every reason the corpus under `prefix` is red against the ledger.
///
/// A mismatch the ledger does not list is red, and so is a ledger entry under
/// `prefix` that no longer mismatches.
fn reconcile(prefix: &str, mismatches: &[Mismatch], ledger: &BTreeSet<&str>) -> Vec<String> {
    let failing: BTreeSet<&str> = mismatches.iter().map(|m| m.key.as_str()).collect();
    let unlisted = mismatches
        .iter()
        .filter(|m| !ledger.contains(m.key.as_str()))
        .map(|m| format!("{}: {}", m.key, m.detail));
    let healed = ledger
        .iter()
        .filter(|k| k.starts_with(prefix) && !failing.contains(*k))
        .map(|k| format!("{k}: no longer fails; remove it from known_rot.txt"));
    unlisted.chain(healed).collect()
}

/// A fresh scratch directory for one corpus, outside every checkout so no
/// enclosing manifest roots a block's imports.
fn scratch(corpus: &str) -> PathBuf {
    let dir = ipe_test_temp::temp_root().join(format!(
        "ipe_explain_examples_{corpus}_{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// Fail once, listing every problem.
fn assert_clean(corpus: &str, problems: &[String]) {
    assert!(
        problems.is_empty(),
        "{} {corpus} block(s) do not meet their verdict:\n{}",
        problems.len(),
        problems.join("\n")
    );
}

/// The codes with an explain page, the universe the explain corpus covers.
fn codes_with_pages() -> BTreeSet<&'static str> {
    ALL_CODES
        .iter()
        .filter(|c| explain_page(**c).is_some())
        .map(|c| c.as_str())
        .collect()
}

/// Every explain page the registry holds, with its code.
fn explain_corpus() -> Vec<(Code, &'static str)> {
    ALL_CODES
        .iter()
        .filter_map(|code| explain_page(*code).map(|text| (*code, text)))
        .collect()
}

/// Judge every `.md` page under `docs/<dir>` but its `README.md`.
#[allow(clippy::expect_used)] // an unreadable docs tree IS the failure
fn judge_doc_dir(dir: &str, scratch: &Path) -> Vec<Mismatch> {
    let root = e2e_support::manifest_dir!().join("../../docs").join(dir);
    let mut pages: Vec<PathBuf> = std::fs::read_dir(&root)
        .expect("read the docs directory")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "md"))
        .filter(|p| p.file_name().is_some_and(|n| n != "README.md"))
        .collect();
    pages.sort();
    assert!(!pages.is_empty(), "no pages under {}", root.display());
    let mut mismatches = Vec::new();
    for path in pages {
        let text = std::fs::read_to_string(&path).expect("read a docs page");
        let file = path
            .file_name()
            .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
        let name = format!("docs/{dir}/{file}");
        mismatches.extend(judge_page(&name, &text, Page::Doc, scratch));
    }
    mismatches
}

#[test]
fn explain_pages() {
    let scratch = scratch("explain");
    let mismatches: Vec<Mismatch> = explain_corpus()
        .into_iter()
        .flat_map(|(code, text)| {
            let name = format!("explain/{}.md", code.as_str());
            judge_page(&name, text, Page::Explain(code), &scratch)
        })
        .collect();
    assert_clean(
        "explain-page",
        &reconcile("explain/", &mismatches, &ledger(KNOWN_ROT)),
    );
}

#[test]
fn construct_pages() {
    let mismatches = judge_doc_dir("constructs", &scratch("constructs"));
    assert_clean(
        "construct-page",
        &reconcile("docs/constructs/", &mismatches, &ledger(KNOWN_ROT)),
    );
}

#[test]
fn topic_pages() {
    let mismatches = judge_doc_dir("topics", &scratch("topics"));
    assert_clean(
        "topic-page",
        &reconcile("docs/topics/", &mismatches, &ledger(KNOWN_ROT)),
    );
}

#[test]
#[allow(clippy::expect_used)] // an unreadable explain directory IS the failure
fn every_registered_code_page_was_visited() {
    let visited: BTreeSet<&str> = explain_corpus()
        .into_iter()
        .map(|(code, _)| code.as_str())
        .collect();
    assert_eq!(visited, codes_with_pages());
    let dir = e2e_support::manifest_dir!().join("../compiler/diagnostics/explain");
    let on_disk: BTreeSet<String> = std::fs::read_dir(&dir)
        .expect("read the explain directory")
        .filter_map(Result::ok)
        .filter_map(|e| {
            e.file_name()
                .to_str()
                .and_then(|n| n.strip_suffix(".md"))
                .map(str::to_owned)
        })
        .collect();
    let visited_owned: BTreeSet<String> = visited.iter().map(|c| (*c).to_owned()).collect();
    assert_eq!(
        visited_owned, on_disk,
        "every explain page on disk is a visited registry page"
    );
}

#[test]
fn every_ledger_entry_names_a_scanned_corpus() {
    let stray: Vec<&str> = ledger(KNOWN_ROT)
        .into_iter()
        .filter(|k| {
            !["explain/", "docs/constructs/", "docs/topics/"]
                .iter()
                .any(|p| k.starts_with(p))
        })
        .collect();
    assert!(
        stray.is_empty(),
        "ledger entries outside every corpus: {stray:?}"
    );
}

/// Judge a synthetic page through the same path the corpora take.
fn judge_synthetic(test_name: &str, text: &str, page: Page) -> Vec<Mismatch> {
    judge_page("synthetic.md", text, page, &scratch(test_name))
}

#[test]
fn error_block_failing_with_other_code_is_a_mismatch() {
    // A parse error on a page for a name-resolution code: the vacuous pass.
    let text = "```ipe ipe:error\nx = = 1\n```\n";
    let found = judge_synthetic(
        "error_block_failing_with_other_code_is_a_mismatch",
        text,
        Page::Explain(ipe_diagnostics::IPE_N0004),
    );
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(
        found
            .iter()
            .all(|m| m.detail.contains("refused with IPE-P")),
        "{found:?}"
    );
}

#[test]
fn error_block_refused_with_its_own_code_meets_its_verdict() {
    let text = "```ipe ipe:error\nmain : Task ()\nmain =\n    Io.println \"hi\"\n```\n";
    let found = judge_synthetic(
        "error_block_refused_with_its_own_code_meets_its_verdict",
        text,
        Page::Explain(ipe_diagnostics::IPE_N0004),
    );
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn error_block_that_compiles_is_a_mismatch() {
    let text = "```ipe ipe:error\nx : Int\nx = 1\n```\n";
    let found = judge_synthetic(
        "error_block_that_compiles_is_a_mismatch",
        text,
        Page::Explain(ipe_diagnostics::IPE_N0004),
    );
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(
        found.iter().all(|m| m.detail.contains("was accepted")),
        "{found:?}"
    );
}

#[test]
fn check_block_needing_an_import_is_a_mismatch() {
    let text = "```ipe\nmain : Task ()\nmain =\n    Io.println \"hi\"\n```\n";
    let found = judge_synthetic(
        "check_block_needing_an_import_is_a_mismatch",
        text,
        Page::Doc,
    );
    assert_eq!(found.len(), 1, "{found:?}");
    let imported =
        "```ipe\nimport Ipe.Io as Io\n\nmain : Task ()\nmain =\n    Io.println \"hi\"\n```\n";
    let found = judge_synthetic(
        "check_block_needing_an_import_is_a_mismatch_imported",
        imported,
        Page::Doc,
    );
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn lowering_code_error_block_is_judged_past_typecheck() {
    // Type-checks, then lowering refuses a `Float` `Set` element.
    let text = "```ipe ipe:error\nimport Ipe.Set as Set\n\ns : Set.Set Float\ns =\n    Set.fromList [ 1.5 ]\n```\n";
    let found = judge_synthetic(
        "lowering_code_error_block_is_judged_past_typecheck",
        text,
        Page::Explain(ipe_diagnostics::IPE_L0117),
    );
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn skip_block_is_not_compiled() {
    let text = "```ipe ipe:skip needs a second module\nx = = 1\n```\n";
    assert!(judge_synthetic("skip_block_is_not_compiled", text, Page::Doc).is_empty());
}

fn mismatch(key: &str) -> Mismatch {
    Mismatch {
        key: key.to_owned(),
        detail: "expected the program to be accepted; refused with IPE-N0004".to_owned(),
    }
}

#[test]
fn ledgered_block_that_passes_is_red() {
    let ledgered = ledger("# known\nexplain/IPE-N0004.md:12\n");
    let red = reconcile("explain/", &[], &ledgered);
    assert_eq!(
        red,
        vec!["explain/IPE-N0004.md:12: no longer fails; remove it from known_rot.txt".to_owned()]
    );
    // An entry of another corpus is that corpus's to reconcile.
    assert!(reconcile("docs/topics/", &[], &ledgered).is_empty());
    assert!(
        reconcile(
            "explain/",
            &[mismatch("explain/IPE-N0004.md:12")],
            &ledgered
        )
        .is_empty()
    );
}

#[test]
fn unledgered_mismatch_is_red() {
    let red = reconcile(
        "explain/",
        &[mismatch("explain/IPE-N0004.md:40")],
        &ledger("explain/IPE-N0004.md:12\n"),
    );
    assert_eq!(red.len(), 2, "{red:?}");
    assert!(
        red.iter()
            .any(|r| r.starts_with("explain/IPE-N0004.md:40: expected"))
    );
}
