//! Layout normal form of every emitted Rust file.
//!
//! The emitter places the blank lines between items through one joiner
//! (`Items`), so every emitted file — each golden `main.rs` and each split
//! `ipe_mods/*.rs` — must satisfy the same whitespace normal form:
//!
//! - a top-level item's closing `}` is followed by a blank line before the next
//!   item, never by the item itself;
//! - a block opened by `{` never starts with a blank line, and a closing `}`
//!   never follows one (so an empty body renders `{}`);
//! - never two consecutive blank lines (rustfmt's maximum is one);
//! - no trailing whitespace, and exactly one final newline.
//!
//! The goldens are regenerated from the emitter (`cargo run -p regen-goldens`,
//! drift-checked in CI), so walking them checks the emitter's output for every
//! golden program. The refusal tests pin that each malformed shape is caught.

use std::path::{Path, PathBuf};

/// A line that opens a top-level Rust item.
const ITEM_STARTS: &[&str] = &[
    "pub ",
    "pub(",
    "fn ",
    "async fn ",
    "impl",
    "#[",
    "//",
    "struct ",
    "enum ",
    "type ",
    "use ",
    "mod ",
    "const ",
    "static ",
    "trait ",
];

/// One layout violation: the 1-based line and the rule it breaks.
#[derive(Debug, PartialEq, Eq)]
struct Violation {
    line: usize,
    rule: &'static str,
}

/// Every layout violation in `text`, in line order.
fn layout_violations(text: &str) -> Vec<Violation> {
    let mut found = Vec::new();
    if !text.is_empty() && (!text.ends_with('\n') || text.ends_with("\n\n")) {
        found.push(Violation {
            line: text.lines().count(),
            rule: "the file ends with exactly one newline",
        });
    }
    let lines: Vec<&str> = text.lines().collect();
    for (idx, pair) in lines.windows(2).enumerate() {
        let [line, next] = pair else {
            continue;
        };
        let at = idx + 1;
        if *line == "}" && ITEM_STARTS.iter().any(|start| next.starts_with(start)) {
            found.push(Violation {
                line: at,
                rule: "a closed item is followed by a blank line",
            });
        }
        if line.ends_with('{') && next.is_empty() {
            found.push(Violation {
                line: at,
                rule: "a block never opens with a blank line",
            });
        }
        if line.is_empty() && next.trim_start().starts_with('}') {
            found.push(Violation {
                line: at,
                rule: "a block never closes after a blank line",
            });
        }
        if line.is_empty() && next.is_empty() {
            found.push(Violation {
                line: at,
                rule: "never two consecutive blank lines",
            });
        }
    }
    for (idx, line) in lines.iter().enumerate() {
        if line.len() != line.trim_end().len() {
            found.push(Violation {
                line: idx + 1,
                rule: "no trailing whitespace",
            });
        }
    }
    found
}

/// The repository's `tests/golden` directory.
fn golden_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../tests/golden")
}

/// Every emitted golden Rust file.
///
/// Each case's `main.rs` and each split `ipe_mods/*.rs`.
#[allow(clippy::expect_used)] // a missing golden tree is a broken checkout, not a test input
fn emitted_golden_files() -> Vec<PathBuf> {
    let mut files = Vec::new();
    let cases = std::fs::read_dir(golden_root()).expect("tests/golden is readable");
    for case in cases {
        let dir = case.expect("golden entry is readable").path();
        let main = dir.join("main.rs");
        if main.is_file() {
            files.push(main);
        }
        let mods = dir.join("ipe_mods");
        if mods.is_dir() {
            for entry in std::fs::read_dir(&mods).expect("ipe_mods is readable") {
                let path = entry.expect("ipe_mods entry is readable").path();
                if path.extension().is_some_and(|ext| ext == "rs") {
                    files.push(path);
                }
            }
        }
    }
    files.sort();
    files
}

#[test]
#[allow(clippy::expect_used)] // a golden the walk listed but cannot read is a broken checkout
fn every_emitted_golden_file_is_in_layout_normal_form() {
    let files = emitted_golden_files();
    assert!(!files.is_empty(), "no emitted golden files found");
    let mut report = String::new();
    for file in &files {
        let text = std::fs::read_to_string(file).expect("golden is readable");
        for v in layout_violations(&text) {
            report.push_str(&format!("{}:{}: {}\n", file.display(), v.line, v.rule));
        }
    }
    assert!(
        report.is_empty(),
        "emitted Rust breaks the layout normal form:\n{report}"
    );
}

#[test]
fn a_normal_form_file_has_no_violations() {
    let text =
        "use a::b;\n\npub struct A {}\n\nimpl A {\n    fn f() {}\n}\n\npub fn g() {\n    x\n}\n";
    assert_eq!(layout_violations(text), Vec::new());
}

#[test]
fn an_item_directly_after_a_closing_brace_is_refused() {
    let text = "pub enum E {\n    A,\n}\nimpl E {}\n";
    assert_eq!(
        layout_violations(text),
        vec![Violation {
            line: 3,
            rule: "a closed item is followed by a blank line",
        }]
    );
}

#[test]
fn an_empty_body_with_a_blank_line_is_refused() {
    let found = layout_violations("pub struct A {\n\n}\n");
    assert!(
        found
            .iter()
            .any(|v| v.rule == "a block never opens with a blank line")
    );
    assert!(
        found
            .iter()
            .any(|v| v.rule == "a block never closes after a blank line")
    );
}

#[test]
fn two_consecutive_blank_lines_are_refused() {
    assert_eq!(
        layout_violations("fn a() {}\n\n\nfn b() {}\n"),
        vec![Violation {
            line: 2,
            rule: "never two consecutive blank lines",
        }]
    );
}

#[test]
fn trailing_whitespace_is_refused() {
    assert_eq!(
        layout_violations("fn a() {} \n"),
        vec![Violation {
            line: 1,
            rule: "no trailing whitespace",
        }]
    );
}

#[test]
fn a_missing_or_doubled_final_newline_is_refused() {
    for text in ["fn a() {}", "fn a() {}\n\n"] {
        assert!(
            layout_violations(text)
                .iter()
                .any(|v| v.rule == "the file ends with exactly one newline")
        );
    }
}
