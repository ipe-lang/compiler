//! Exact outputs for comment runs: each golden is the formatter's output for
//! its source and a fixed point of a second pass.

/// Assert `src` formats to exactly `expected`, and `expected` to itself.
#[allow(clippy::expect_used)] // a refusal is the failure these tests report
fn golden(src: &str, expected: &str) {
    let once = ipe_fmt::format_source(src).expect("formats");
    assert_eq!(once, expected, "output differs for:\n{src}");
    let twice = ipe_fmt::format_source(&once).expect("second pass formats");
    assert_eq!(twice, once, "not a fixed point:\n{once}");
}

/// A section comment set apart from its declaration keeps its blank lines.
#[test]
fn section_comment_keeps_its_gap() {
    let src = "module M exposing (x)\n\n\n-- section\n\n\nx =\n    1\n";
    golden(src, src);
}

/// Adjacent comments stay adjacent, and a blank line inside a run stays.
#[test]
fn adjacent_comments_stay_adjacent() {
    let src = "module M exposing (x, y)\n\n\n-- one\n-- two\nx =\n    1\n\n\n-- three\n\n-- four\ny =\n    2\n";
    golden(src, src);
}

/// A module doc stays glued to `module`.
#[test]
fn module_doc_stays_attached() {
    let src = "-- | Module doc.\n-- | More.\nmodule M exposing (x)\n\n\nx =\n    1\n";
    golden(src, src);
}

/// A comment after the exposing list's `(` stays there, above its item.
#[test]
fn exposing_first_item_comment_stays_in_place() {
    let src =
        "module M exposing\n    ( -- c\n      a\n    , b\n    )\n\n\na =\n    1\n\n\nb =\n    2\n";
    golden(src, src);
}

/// A comment inside the header moves above the run at `module`, a blank line
/// apart; the run at `module`, and the comments after the last declaration,
/// keep their gaps.
#[test]
fn header_trailing_and_missed_runs_keep_gaps() {
    golden(
        "-- top\n\nmodule M exposing -- public API\n    (f)\n\n\n-- | doc\nf =\n    1\n\n-- end one\n\n-- end two\n",
        "-- public API\n\n-- top\n\n\nmodule M exposing (f)\n\n\n-- | doc\nf =\n    1\n\n-- end one\n\n-- end two\n",
    );
    golden(
        "module M exposing -- public API\n    (f)\n\n\nf =\n    1\n",
        "-- public API\n\n\nmodule M exposing (f)\n\n\nf =\n    1\n",
    );
}

/// A comment run above a `case` arm stays adjacent and glued to its pattern.
#[test]
fn case_arm_run_stays_glued() {
    let src = "module M exposing (f)\n\n\nf x =\n    case x of\n        0 ->\n            1\n\n        -- one\n        -- two\n        _ ->\n            2\n";
    golden(src, src);
}

/// A comment inside a signature prints after it, and a parameter comment at
/// the start of the body, so neither joins the doc above the signature.
#[test]
fn annotation_and_parameter_comments_keep_the_doc() {
    golden(
        "module M exposing (f)\n\n\n-- | doc\nf : -- ann\n    Int -> Int\nf -- p\n  x =\n    x\n",
        "module M exposing (f)\n\n\n-- | doc\nf : Int -> Int\n-- ann\nf x =\n    -- p\n    x\n",
    );
}
