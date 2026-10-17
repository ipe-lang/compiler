//! Positive and refusal tests for `unsafe-convention`: an `unsafe*` reference
//! is reported exactly once wherever it sits, whichever sub-expression of
//! whichever construct holds it.
//!
//! Every fixture is asserted to parse first, and its body to be the construct
//! it names, so a fixture the parser reads differently fails instead of
//! passing vacuously.

use ipe_intern::Interner;
use ipe_syntax::Expr_;

use crate::{Finding, LintConfig, SourceModule, run};

const RULE: &str = "unsafe-convention";

fn source(body: &str) -> String {
    format!("module Main exposing (main)\n\nmain c r t =\n{body}\n")
}

/// The `unsafe-convention` findings over `body`, after asserting the fixture
/// parses and `main`'s body satisfies `shape`.
fn findings(body: &str, shape: fn(&Expr_) -> bool) -> Vec<Finding> {
    let src = source(body);
    let mut interner = Interner::new();
    let parsed = ipe_parse::parse_module(&src, &mut interner).expect("fixture must parse");
    let main = parsed.values.first().expect("fixture defines `main`");
    assert!(
        shape(&main.value.body.value),
        "fixture body is not the construct under test:\n{src}\n{:?}",
        main.value.body.value
    );
    let m = SourceModule {
        module: vec!["Main".to_owned()],
        source: src,
    };
    let Ok(report) = run(&[m], &LintConfig::default(), &crate::NeverCancel);
    report
        .findings
        .into_iter()
        .filter(|f| f.rule == RULE)
        .collect()
}

/// A fixture: the child position it exercises, `main`'s body, and the
/// construct that body must parse to.
type Fixture = (&'static str, &'static str, fn(&Expr_) -> bool);

/// Each child position of each child-bearing construct, holding the one
/// `unsafeX` reference of its fixture. Skipping any child in the walk leaves
/// its fixture with no finding.
const CHILD_POSITIONS: &[Fixture] = &[
    ("call callee", "    unsafeX 1", |e| {
        matches!(e, Expr_::Call(..))
    }),
    ("call argument", "    c unsafeX", |e| {
        matches!(e, Expr_::Call(..))
    }),
    (
        "case scrutinee",
        "    case unsafeX of\n        _ ->\n            1",
        |e| matches!(e, Expr_::Case(..)),
    ),
    (
        "case arm",
        "    case c of\n        _ ->\n            unsafeX",
        |e| matches!(e, Expr_::Case(..)),
    ),
    ("lambda body", "    \\x -> unsafeX", |e| {
        matches!(e, Expr_::Lambda(..))
    }),
    ("binops operand", "    unsafeX + 1", |e| {
        matches!(e, Expr_::Binops(..))
    }),
    ("binops last", "    1 + unsafeX", |e| {
        matches!(e, Expr_::Binops(..))
    }),
    (
        "let binding",
        "    let\n        y =\n            unsafeX\n    in\n    y",
        |e| matches!(e, Expr_::Let(..)),
    ),
    (
        "let body",
        "    let\n        y =\n            1\n    in\n    unsafeX",
        |e| matches!(e, Expr_::Let(..)),
    ),
    (
        "if condition",
        "    if unsafeX then\n        1\n\n    else\n        2",
        |e| matches!(e, Expr_::If(..)),
    ),
    (
        "if branch",
        "    if c then\n        unsafeX\n\n    else\n        2",
        |e| matches!(e, Expr_::If(..)),
    ),
    (
        "if otherwise",
        "    if c then\n        1\n\n    else\n        unsafeX",
        |e| matches!(e, Expr_::If(..)),
    ),
    ("tuple item", "    ( 1, unsafeX )", |e| {
        matches!(e, Expr_::Tuple(..))
    }),
    ("list item", "    [ 1, unsafeX ]", |e| {
        matches!(e, Expr_::List(..))
    }),
    ("record field", "    { a = unsafeX }", |e| {
        matches!(e, Expr_::Record(..))
    }),
    ("access base", "    (c unsafeX).a", |e| {
        matches!(e, Expr_::Access(..))
    }),
    ("update base", "    { unsafeX | a = 1 }", |e| {
        matches!(e, Expr_::Update(..))
    }),
    ("update field", "    { r | a = unsafeX }", |e| {
        matches!(e, Expr_::Update(..))
    }),
    (
        "do bind task",
        "    do\n        x <- unsafeX\n        t",
        |e| matches!(e, Expr_::Call(callee, _) if matches!(callee.value, Expr_::TaskAndThen)),
    ),
    (
        "do bind continuation",
        "    do\n        x <- t\n        unsafeX",
        |e| matches!(e, Expr_::Call(callee, _) if matches!(callee.value, Expr_::TaskAndThen)),
    ),
];

#[test]
fn every_child_position_is_walked_and_reported_once() {
    for (position, body, shape) in CHILD_POSITIONS {
        let found = findings(body, *shape);
        assert_eq!(
            found.len(),
            1,
            "{position}: expected exactly one finding, got {found:?}\n{body}"
        );
    }
}

/// The refusal: the same constructs with no `unsafe*` name report nothing.
#[test]
fn no_unsafe_name_no_finding() {
    for (position, body, shape) in CHILD_POSITIONS {
        let clean = body.replace("unsafeX", "safeX");
        let found = findings(&clean, *shape);
        assert!(found.is_empty(), "{position}: {found:?}\n{clean}");
    }
}
