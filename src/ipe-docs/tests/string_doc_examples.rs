//! The documented `-->` examples of `String.casefold` and the two-string `String` predicates hold at runtime.
//!
//! Every `-->` line inside an `ipe` fence of a pinned symbol's doc must parse as
//! one of the shapes below and agree with the runtime kernel; a line of any
//! other shape fails the test, so an example cannot escape the check.

use ipe_docs::stdlib_docs::{ExportDoc, all_module_docs};
use ipe_runtime_rust::string::{
    string_casefold, string_contains_in, string_ends_with_in, string_equal_fold,
    string_starts_with_in,
};

/// A two-string `Ipe.String` predicate whose doc examples this test pins.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Predicate {
    EqualFold,
    ContainsIn,
    StartsWithIn,
    EndsWithIn,
}

impl Predicate {
    const ALL: [Self; 4] = [
        Self::EqualFold,
        Self::ContainsIn,
        Self::StartsWithIn,
        Self::EndsWithIn,
    ];

    /// The Ipê name of the predicate.
    const fn name(self) -> &'static str {
        match self {
            Self::EqualFold => "equalFold",
            Self::ContainsIn => "containsIn",
            Self::StartsWithIn => "startsWithIn",
            Self::EndsWithIn => "endsWithIn",
        }
    }

    /// The predicate an Ipê name spells, if it is one of [`Self::ALL`].
    fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.name() == name)
    }

    /// The runtime kernel applied in Ipê argument order.
    fn eval(self, first: &str, second: &str) -> bool {
        let (first, second) = (first.to_owned(), second.to_owned());
        match self {
            Self::EqualFold => string_equal_fold(first, second),
            Self::ContainsIn => string_contains_in(first, second),
            Self::StartsWithIn => string_starts_with_in(first, second),
            Self::EndsWithIn => string_ends_with_in(first, second),
        }
    }
}

/// The names whose doc examples this test pins.
fn pinned_names() -> Vec<&'static str> {
    std::iter::once("casefold")
        .chain(Predicate::ALL.map(Predicate::name))
        .collect()
}

/// One documented example, parsed.
#[derive(Debug, PartialEq, Eq)]
enum Example<'a> {
    /// `casefold "<input>" --> "<expected>"`.
    Casefold { input: &'a str, expected: &'a str },
    /// `<pred> "<first>" "<second>" --> True|False`, or the pipe form
    /// `"<second>" |> <pred> "<first>" --> True|False`.
    Apply {
        pred: Predicate,
        first: &'a str,
        second: &'a str,
        expected: bool,
    },
}

/// Split a leading `"…"` literal (no `"` or `\` inside) off `s`.
fn literal(s: &str) -> Option<(&str, &str)> {
    let (lit, rest) = s.strip_prefix('"')?.split_once('"')?;
    (!lit.contains('\\')).then_some((lit, rest))
}

/// `s` as exactly one `"…"` literal and nothing else.
fn only_literal(s: &str) -> Option<&str> {
    let (lit, "") = literal(s)? else {
        return None;
    };
    Some(lit)
}

/// Parse one example line; `None` for any shape this test cannot check.
fn parse_example(line: &str) -> Option<Example<'_>> {
    let (lhs, rhs) = line.trim().split_once(" --> ")?;
    if let Some(args) = lhs.strip_prefix("casefold ") {
        let input = only_literal(args)?;
        let expected = only_literal(rhs)?;
        return Some(Example::Casefold { input, expected });
    }
    let expected = match rhs {
        "True" => true,
        "False" => false,
        _ => return None,
    };
    let (pred, first, second) = if lhs.starts_with('"') {
        let (second, call) = literal(lhs)?;
        let (name, arg) = call.strip_prefix(" |> ")?.split_once(' ')?;
        (Predicate::from_name(name)?, only_literal(arg)?, second)
    } else {
        let (name, args) = lhs.split_once(' ')?;
        let (first, rest) = literal(args)?;
        let second = only_literal(rest.strip_prefix(' ')?)?;
        (Predicate::from_name(name)?, first, second)
    };
    Some(Example::Apply {
        pred,
        first,
        second,
        expected,
    })
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

/// The doc exports of `Ipe.String` named by [`pinned_names`].
fn pinned_exports() -> Vec<ExportDoc> {
    let names = pinned_names();
    all_module_docs()
        .into_iter()
        .filter(|m| m.dotted == "Ipe.String")
        .flat_map(|m| m.exports)
        .filter(|e| names.contains(&e.name.as_str()))
        .collect()
}

#[test]
fn string_doc_examples_hold() {
    let names = pinned_names();
    let exports = pinned_exports();
    assert_eq!(
        exports.len(),
        names.len(),
        "Ipe.String must document each of {names:?} once"
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
                Some(Example::Apply {
                    pred,
                    first,
                    second,
                    expected,
                }) => assert_eq!(
                    pred.eval(first, second),
                    expected,
                    "doc example disagrees with the runtime: {line}"
                ),
                None => {}
            }
        }
    }
}

#[test]
fn string_doc_examples_refuse_unknown_shape() {
    for refused in [
        "casefold (x) --> \"y\"",
        "casefold \"a\" \"b\" --> \"a\"",
        "casefold \"a\\\"b\" --> \"a\"",
        "casefold \"A\" --> a",
        "equalFold \"a\" \"b\" --> Maybe",
        "equalFold \"a\" --> True",
        "toLower \"A\" --> \"a\"",
        "contains \"a\" \"b\" --> True",
        "\"a\" |> casefold --> \"a\"",
        "\"a\" |> toLower \"b\" --> True",
        "\"a\" |> containsIn --> True",
        "\"a\" |> containsIn \"b\" \"c\" --> True",
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
        Some(Example::Apply {
            pred: Predicate::EqualFold,
            first: "i",
            second: "İ",
            expected: false
        })
    );
    assert_eq!(
        parse_example("\"world\" |> containsIn \"hello world\" --> True"),
        Some(Example::Apply {
            pred: Predicate::ContainsIn,
            first: "hello world",
            second: "world",
            expected: true
        })
    );
}

#[test]
fn haystack_first_predicates_take_the_haystack_first() {
    assert!(Predicate::ContainsIn.eval("hello world", "world"));
    assert!(!Predicate::ContainsIn.eval("world", "hello world"));
    assert!(Predicate::StartsWithIn.eval("/api/users", "/api"));
    assert!(!Predicate::StartsWithIn.eval("/api", "/api/users"));
    assert!(Predicate::EndsWithIn.eval("image.png", ".png"));
    assert!(!Predicate::EndsWithIn.eval(".png", "image.png"));
}

#[test]
fn string_doc_example_lines_skip_other_fences() {
    let doc = "prose --> not code\n```text\ncasefold (x) --> y\n```\n```ipe\ncasefold \"A\" --> \"a\"\n```\n";
    assert_eq!(example_lines(doc), ["casefold \"A\" --> \"a\""]);
}
