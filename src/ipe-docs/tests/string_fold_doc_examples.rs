//! The documented `-->` examples of `String.casefold` and `String.equalFold` hold at runtime.
//!
//! Every `-->` line inside an `ipe` fence of either symbol's doc must parse as
//! one of the two shapes below and agree with the runtime kernel; a line of any
//! other shape fails the test, so an example cannot escape the check.

use ipe_docs::stdlib_docs::{ExportDoc, all_module_docs};
use ipe_runtime_rust::string::{string_casefold, string_equal_fold};

/// The symbols whose doc examples this test pins.
const PINNED: [&str; 2] = ["casefold", "equalFold"];

/// One documented example, parsed.
#[derive(Debug, PartialEq, Eq)]
enum Example<'a> {
    /// `casefold "<input>" --> "<expected>"`.
    Casefold { input: &'a str, expected: &'a str },
    /// `equalFold "<a>" "<b>" --> True|False`.
    EqualFold {
        a: &'a str,
        b: &'a str,
        expected: bool,
    },
}

/// Split a leading `"…"` literal (no `"` or `\` inside) off `s`.
fn literal(s: &str) -> Option<(&str, &str)> {
    let (lit, rest) = s.strip_prefix('"')?.split_once('"')?;
    (!lit.contains('\\')).then_some((lit, rest))
}

/// Parse one example line; `None` for any shape this test cannot check.
fn parse_example(line: &str) -> Option<Example<'_>> {
    let (lhs, rhs) = line.trim().split_once(" --> ")?;
    if let Some(args) = lhs.strip_prefix("casefold ") {
        let (input, "") = literal(args)? else {
            return None;
        };
        let (expected, "") = literal(rhs)? else {
            return None;
        };
        return Some(Example::Casefold { input, expected });
    }
    let args = lhs.strip_prefix("equalFold ")?;
    let (a, rest) = literal(args)?;
    let (b, "") = literal(rest.strip_prefix(' ')?)? else {
        return None;
    };
    let expected = match rhs {
        "True" => true,
        "False" => false,
        _ => return None,
    };
    Some(Example::EqualFold { a, b, expected })
}

/// The `-->` lines inside the `ipe` fences of `doc`.
fn example_lines(doc: &str) -> Vec<&str> {
    let mut in_fence = false;
    let mut out = Vec::new();
    for line in doc.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("```") {
            in_fence = !in_fence && trimmed == "```ipe";
        } else if in_fence && trimmed.contains("-->") {
            out.push(trimmed);
        }
    }
    out
}

/// The doc exports of `Ipe.String` named in [`PINNED`].
fn pinned_exports() -> Vec<ExportDoc> {
    all_module_docs()
        .into_iter()
        .filter(|m| m.dotted == "Ipe.String")
        .flat_map(|m| m.exports)
        .filter(|e| PINNED.contains(&e.name.as_str()))
        .collect()
}

#[test]
fn fold_doc_examples_hold() {
    let exports = pinned_exports();
    assert_eq!(
        exports.len(),
        PINNED.len(),
        "Ipe.String must document each of {PINNED:?} once"
    );
    for export in &exports {
        let doc = export.doc.as_deref().unwrap_or_default();
        let lines = example_lines(doc);
        assert!(
            lines.len() >= 2,
            "`{}` must keep at least 2 checked examples, found {}",
            export.name,
            lines.len()
        );
        for line in lines {
            let example = parse_example(line);
            assert!(
                example.is_some(),
                "`{}` doc example has a shape this test cannot check: {line}",
                export.name
            );
            match example {
                Some(Example::Casefold { input, expected }) => assert_eq!(
                    string_casefold(input.to_owned()),
                    expected,
                    "doc example disagrees with the runtime: {line}"
                ),
                Some(Example::EqualFold { a, b, expected }) => assert_eq!(
                    string_equal_fold(a.to_owned(), b.to_owned()),
                    expected,
                    "doc example disagrees with the runtime: {line}"
                ),
                None => {}
            }
        }
    }
}

#[test]
fn fold_doc_examples_refuse_unknown_shape() {
    for refused in [
        "casefold (x) --> \"y\"",
        "casefold \"a\" \"b\" --> \"a\"",
        "casefold \"a\\\"b\" --> \"a\"",
        "casefold \"A\" --> a",
        "equalFold \"a\" \"b\" --> Maybe",
        "equalFold \"a\" --> True",
        "toLower \"A\" --> \"a\"",
        "casefold \"A\"",
    ] {
        assert_eq!(parse_example(refused), None, "admitted: {refused}");
    }
    assert_eq!(
        parse_example("casefold \"Straße\" --> \"strasse\""),
        Some(Example::Casefold {
            input: "Straße",
            expected: "strasse"
        })
    );
    assert_eq!(
        parse_example("equalFold \"i\" \"İ\" --> False"),
        Some(Example::EqualFold {
            a: "i",
            b: "İ",
            expected: false
        })
    );
}

#[test]
fn fold_doc_example_lines_skip_other_fences() {
    let doc = "prose --> not code\n```text\ncasefold (x) --> y\n```\n```ipe\ncasefold \"A\" --> \"a\"\n```\n";
    assert_eq!(example_lines(doc), ["casefold \"A\" --> \"a\""]);
}
