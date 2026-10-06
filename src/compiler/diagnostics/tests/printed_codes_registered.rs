//! Every diagnostic wire string the shipped source prints is a registered code.
//!
//! A code that is printed but absent from [`ALL_CODES`] has no explain page, no
//! title and no typed producer, yet `ipe explain` and the JSON schema still
//! advertise it. This test reads the non-test Rust source and the CLI message
//! catalog, and fails the moment an `IPE-X0000`-shaped string appears without a
//! registry row.

use std::path::{Path, PathBuf};

use ipe_diagnostics::ALL_CODES;

/// Wire-shaped strings that are deliberately not registered codes: the shape
/// placeholder docs use to describe a code, and the fixtures tests feed through
/// the renderer.
const NOT_CODES: &[&str] = &["IPE-X0000", "IPE-T0099", "IPE-T9999"];

/// The CLI message catalog, relative to the `src/` tree.
const MESSAGE_CATALOG: &str = "ipe-cli/text/messages.md";

/// Length of a wire string: `IPE-` plus a family letter plus four digits.
const WIRE_LEN: usize = 9;

fn source_root() -> PathBuf {
    let manifest = ipe_env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| String::from("."));
    PathBuf::from(manifest).join("..").join("..")
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
/// A test item is skipped up to the closing brace at its own indentation, or to
/// its `;` for a one-line item. The source is `rustfmt`-formatted, so a block's
/// closing brace is the only line equal to its opener's indentation plus `}`.
fn without_test_items(source: &str) -> String {
    let lines: Vec<&str> = source.lines().collect();
    let mut kept = String::new();
    let mut at = 0;
    while let Some(line) = lines.get(at) {
        if line.trim() != "#[cfg(test)]" {
            kept.push_str(line);
            kept.push('\n');
            at += 1;
            continue;
        }
        let indent: String = line.chars().take_while(|c| c.is_whitespace()).collect();
        let closer = format!("{indent}}}");
        at += 1;
        while lines
            .get(at)
            .is_some_and(|next| next.trim_start().starts_with("#["))
        {
            at += 1;
        }
        let head = lines.get(at).map_or("", |next| next.trim_end());
        if head.ends_with(';') || (head.ends_with('}') && head.contains('{')) {
            at += 1;
        } else {
            while lines.get(at).is_some_and(|next| *next != closer) {
                at += 1;
            }
            at += 1;
        }
    }
    kept
}

/// Collect every production `.rs` file under `dir`: no `tests` directory, no
/// build output, no hidden directory.
fn collect_rust_files(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_owned();
        if path.is_dir() {
            if name != "tests" && name != "target" && !name.starts_with('.') {
                collect_rust_files(&path, out)?;
            }
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
    Ok(())
}

#[test]
fn every_printed_code_is_registered() -> Result<(), Box<dyn std::error::Error>> {
    let root = source_root();
    let mut files = Vec::new();
    collect_rust_files(&root, &mut files)?;
    files.sort();

    let mut texts: Vec<(PathBuf, String)> = Vec::new();
    for file in &files {
        let source = std::fs::read_to_string(file)?;
        texts.push((file.clone(), without_test_items(&source)));
    }
    let catalog = root.join(MESSAGE_CATALOG);
    texts.push((catalog.clone(), std::fs::read_to_string(&catalog)?));

    let scanned: usize = texts.iter().map(|(_, text)| wire_strings(text).len()).sum();
    assert!(
        scanned > 0,
        "the scan found no wire string at all under {}; the walk is broken",
        root.display()
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
