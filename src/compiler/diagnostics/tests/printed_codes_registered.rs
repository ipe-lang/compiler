//! Every diagnostic wire string the shipped source prints is a registered code.
//!
//! A code that is printed but absent from [`ALL_CODES`] has no explain page, no
//! title and no typed producer, yet `ipe explain` and the JSON schema still
//! advertise it. This test reads the non-test Rust source and the CLI message
//! catalog, and fails the moment an `IPE-X0000`-shaped string appears without a
//! registry row.

use std::path::{Path, PathBuf};

use ipe_diagnostics::ALL_CODES;

/// Wire-shaped strings the production source prints that are deliberately not
/// registered codes: the shape placeholder docs use to describe a code, and the
/// example row in the `code!` table's own documentation. Each must still occur
/// in the scanned text, so a stale entry cannot linger as a blind spot.
const NOT_CODES: &[&str] = &["IPE-X0000", "IPE-P0099"];

/// The CLI message catalog, relative to the `src/` tree.
const MESSAGE_CATALOG: &str = "ipe-cli/text/messages.md";

/// The shipped non-Rust text trees, relative to the `src/` tree, with the file
/// suffixes each prints: the CLI help pages, the `ipe init` templates, and the
/// stdlib whose doc comments `ipe doc` renders. Each file is scanned whole.
const SHIPPED_TEXT: &[(&str, &[&str])] = &[
    ("ipe-cli/help", &[".md"]),
    ("ipe-cli/templates", &[".in", ".ipe"]),
    ("stdlib", &[".ipe"]),
];

/// Length of a wire string: `IPE-` plus a family letter plus four digits.
const WIRE_LEN: usize = 9;

fn source_root() -> PathBuf {
    e2e_support::manifest_dir!().join("..").join("..")
}

/// Whether `bytes` is `IPE-` followed by an uppercase letter and four digits.
fn is_wire_shape(bytes: &[u8]) -> bool {
    matches!(
        bytes,
        [b'I', b'P', b'E', b'-', letter, d1, d2, d3, d4]
            if letter.is_ascii_uppercase()
                && [d1, d2, d3, d4].iter().all(|d| d.is_ascii_digit())
    )
}

/// Every `IPE-[A-Z][0-9]{4}` wire string in `text`, not followed by a further digit.
fn wire_strings(text: &str) -> Vec<&str> {
    text.match_indices("IPE-")
        .filter_map(|(start, _)| {
            let wire = text.get(start..start + WIRE_LEN)?;
            let trailing_digit = text
                .as_bytes()
                .get(start + WIRE_LEN)
                .is_some_and(u8::is_ascii_digit);
            (is_wire_shape(wire.as_bytes()) && !trailing_digit).then_some(wire)
        })
        .collect()
}

/// The wire strings in `text` that name no registered code and are not a
/// declared non-code.
fn unregistered(text: &str) -> Vec<&str> {
    wire_strings(text)
        .into_iter()
        .filter(|wire| !NOT_CODES.contains(wire))
        .filter(|wire| ALL_CODES.iter().all(|code| code.as_str() != *wire))
        .collect()
}

/// `source` without its `#[cfg(test)]` items.
///
/// Only lines provably inside a test item drop out (see [`skip_test_item`]);
/// anything the reading cannot place stays in view, so a misread item can only
/// fail this test, never hide a production string from it.
fn without_test_items(source: &str) -> String {
    let lines: Vec<&str> = source.lines().collect();
    let mut kept = String::new();
    let mut at = 0;
    while let Some(line) = lines.get(at) {
        if line.trim() == "#[cfg(test)]" {
            at = skip_test_item(&lines, at);
        } else {
            kept.push_str(line);
            kept.push('\n');
            at += 1;
        }
    }
    kept
}

/// Width of `line`'s leading whitespace.
fn indent_of(line: &str) -> usize {
    line.chars().take_while(|c| c.is_whitespace()).count()
}

/// Index of the first line past the test item whose `#[cfg(test)]` is at `attr`.
///
/// The item may be a module, a function, a `use`, a struct field, an enum
/// variant, a match arm or a statement. Skipped, at the attribute's own
/// indentation `base`: further attributes and comments (with their deeper
/// continuation lines), then the head line. A head that ends its item (`;`, `,`,
/// or a one-line `{ … }`) is the whole item. Otherwise the lines blank or deeper
/// than `base` are its body, and one following line at `base` that starts with
/// `}`, `)` or `]` is its closer. No other line at or left of `base` is skipped.
fn skip_test_item(lines: &[&str], attr: usize) -> usize {
    let base = lines.get(attr).map_or(0, |line| indent_of(line));
    let mut at = attr + 1;
    while let Some(line) = lines.get(at) {
        let text = line.trim();
        let indent = indent_of(line);
        let continuation = !text.is_empty() && indent > base;
        let preamble = !text.is_empty()
            && indent == base
            && (text.starts_with("#[")
                || text.starts_with("//")
                || text.starts_with(")]")
                || text.starts_with(']'));
        if continuation || preamble {
            at += 1;
        } else {
            break;
        }
    }
    let Some(head) = lines.get(at) else {
        return at;
    };
    if head.trim().is_empty() || indent_of(head) != base {
        return at;
    }
    at += 1;
    let head = head.trim_end();
    let complete =
        head.ends_with(';') || head.ends_with(',') || (head.ends_with('}') && head.contains('{'));
    if complete {
        return at;
    }
    let opens = head.ends_with(['{', '(', '[']);
    let body_start = at;
    while lines
        .get(at)
        .is_some_and(|line| line.trim().is_empty() || indent_of(line) > base)
    {
        at += 1;
    }
    let closes = lines.get(at).is_some_and(|line| {
        indent_of(line) == base && line.trim_start().starts_with(['}', ')', ']'])
    });
    if closes && (opens || at > body_start) {
        at += 1;
    }
    at
}

/// Collect every production file under `dir` whose name ends with one of
/// `suffixes`: no `tests` directory, no build output, no hidden directory.
fn collect_files(dir: &Path, suffixes: &[&str], out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_owned();
        if path.is_dir() {
            if name != "tests" && name != "target" && !name.starts_with('.') {
                collect_files(&path, suffixes, out)?;
            }
        } else if suffixes.iter().any(|suffix| name.ends_with(suffix)) {
            out.push(path);
        }
    }
    Ok(())
}

/// Every shipped text file of [`SHIPPED_TEXT`] under `root`, sorted.
///
/// # Errors
/// A tree that cannot be read, or one that yields no file at all, so a moved
/// or renamed tree fails the scan instead of silently dropping out of it.
fn shipped_text_files(root: &Path) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let mut files = Vec::new();
    for (tree, suffixes) in SHIPPED_TEXT {
        let before = files.len();
        collect_files(&root.join(tree), suffixes, &mut files)?;
        if files.len() == before {
            return Err(format!("the shipped text tree {tree} yields no {suffixes:?} file").into());
        }
    }
    files.sort();
    Ok(files)
}

#[test]
fn every_printed_code_is_registered() -> Result<(), Box<dyn std::error::Error>> {
    let root = source_root();
    let mut files = Vec::new();
    collect_files(&root, &[".rs"], &mut files)?;
    files.sort();

    let mut texts: Vec<(PathBuf, String)> = Vec::new();
    for file in &files {
        let source = std::fs::read_to_string(file)?;
        texts.push((file.clone(), without_test_items(&source)));
    }
    let catalog = root.join(MESSAGE_CATALOG);
    texts.push((catalog.clone(), std::fs::read_to_string(&catalog)?));
    for file in shipped_text_files(&root)? {
        let text = std::fs::read_to_string(&file)?;
        texts.push((file, text));
    }

    let scanned: usize = texts.iter().map(|(_, text)| wire_strings(text).len()).sum();
    assert!(
        scanned > 0,
        "the scan found no wire string at all under {}; the walk is broken",
        root.display()
    );

    let stale: Vec<&str> = NOT_CODES
        .iter()
        .copied()
        .filter(|not_code| {
            texts
                .iter()
                .all(|(_, text)| !wire_strings(text).contains(not_code))
        })
        .collect();
    assert!(
        stale.is_empty(),
        "NOT_CODES entries no scanned file prints; drop them: {stale:?}"
    );

    let mut offenders = Vec::new();
    for (path, text) in &texts {
        for wire in unregistered(text) {
            offenders.push(format!("{}: {wire}", path.display()));
        }
    }
    assert!(
        offenders.is_empty(),
        "printed diagnostic codes with no `code!` row in diagnostics/src/code.rs:\n{}",
        offenders.join("\n")
    );
    Ok(())
}

#[test]
fn an_unregistered_wire_string_is_detected() {
    assert_eq!(unregistered("error[IPE-S9998]: made up"), ["IPE-S9998"]);
    assert_eq!(unregistered("see IPE-P0022 and IPE-Q0001"), ["IPE-Q0001"]);
}

#[test]
fn a_registered_code_and_a_declared_non_code_pass() {
    assert!(unregistered("error[IPE-S0001]: consent").is_empty());
    assert!(unregistered("a code looks like IPE-X0000").is_empty());
}

#[test]
fn a_wire_string_needs_the_exact_shape() {
    assert!(wire_strings("IPE-S001").is_empty(), "too few digits");
    assert!(wire_strings("IPE-s0001").is_empty(), "lowercase family");
    assert!(wire_strings("IPE-S00012").is_empty(), "too many digits");
    assert_eq!(wire_strings("(IPE-S0001)"), ["IPE-S0001"]);
}

#[test]
fn test_items_are_skipped_and_the_rest_is_kept() {
    let source = "\
const A: &str = \"IPE-S9998\";
#[cfg(test)]
mod tests {
    const B: &str = \"IPE-S9997\";
}
#[cfg(test)]
use helper::IPE_S9996;
mod inner {
    #[cfg(test)]
    fn fixture() -> &'static str { \"IPE-S9995\" }
    const C: &str = \"IPE-S9994\";
}
";
    let production = without_test_items(source);
    assert_eq!(
        unregistered(&production),
        ["IPE-S9998", "IPE-S9994"],
        "production strings stay in view, test items drop out"
    );
}

#[test]
fn a_test_field_variant_arm_or_statement_hides_only_itself() {
    let source = "\
pub struct Proxy {
    #[cfg(test)]
    pub probe: u8,
    pub name: &'static str,
}
const A: &str = \"IPE-S9993\";
enum Kind {
    #[cfg(test)]
    Probe,
    Real,
}
const B: &str = \"IPE-S9992\";
fn pick(k: Kind) -> &'static str {
    match k {
        #[cfg(test)]
        Kind::Probe => {
            \"IPE-S9991\"
        }
        Kind::Real => \"IPE-S9990\",
    }
}
fn run() {
    #[cfg(test)]
    let seen = record(
        \"IPE-S9989\",
    );
    emit(\"IPE-S9988\");
}
#[cfg(test)]
#[allow(
    dead_code
)]
const C: &str = \"IPE-S9987\";
const D: &str = \"IPE-S9986\";
";
    let production = without_test_items(source);
    assert_eq!(
        unregistered(&production),
        [
            "IPE-S9993",
            "IPE-S9992",
            "IPE-S9990",
            "IPE-S9988",
            "IPE-S9986"
        ],
        "every production string after a test field, variant, arm, statement or \
         multi-line attribute stays in view"
    );
}

#[test]
fn an_unreadable_test_item_keeps_its_text_in_view() {
    let source = "\
#[cfg(test)]

const A: &str = \"IPE-S9985\";
";
    assert_eq!(
        unregistered(&without_test_items(source)),
        ["IPE-S9985"],
        "a blank line where the head should be ends the item: nothing past it is skipped"
    );
}

#[test]
fn the_shipped_text_trees_are_scanned() -> Result<(), Box<dyn std::error::Error>> {
    let root = source_root();
    let files = shipped_text_files(&root)?;
    for (tree, _) in SHIPPED_TEXT {
        let tree = root.join(tree);
        assert!(
            files.iter().any(|file| file.starts_with(&tree)),
            "no scanned file under {}",
            tree.display()
        );
    }
    let doc_help = root.join("ipe-cli/help/doc.md");
    assert!(
        files.contains(&doc_help),
        "the `ipe doc` help page, which prints codes, must be scanned"
    );
    Ok(())
}

#[test]
fn a_suffix_no_file_carries_collects_nothing() -> std::io::Result<()> {
    let mut files = Vec::new();
    collect_files(
        &source_root().join("ipe-cli/help"),
        &[".nomatch"],
        &mut files,
    )?;
    assert!(files.is_empty(), "collected {files:?}");
    Ok(())
}
