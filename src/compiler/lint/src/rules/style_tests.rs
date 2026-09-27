//! Positive and refusal tests for the style rules: `prefer-pipeline`,
//! `multiline-lambda-arg`, `no-bool-literal-compare`, `no-redundant-bool-if`,
//! and `no-simple-let-body`.
//!
//! Every fixture is asserted to parse first: the engine skips a module that
//! fails to parse, so an unparsed negative fixture would pass vacuously.

use ipe_intern::Interner;
use ipe_syntax::Expr_;

use crate::rules::{Ctx, is_source_call, visit_exprs};
use crate::{Finding, LintConfig, SourceModule, apply_fixes, run};

fn module(body: &str) -> SourceModule {
    SourceModule {
        module: vec!["Main".to_owned()],
        source: format!("module Main exposing (main)\n\nmain =\n{body}\n"),
    }
}

fn parses(src: &str) -> bool {
    ipe_parse::parse_module(src, &mut Interner::new()).is_ok()
}

/// The findings of `rule` over `body`, after asserting the fixture parses.
fn findings(rule: &str, body: &str) -> Vec<Finding> {
    let m = module(body);
    assert!(parses(&m.source), "fixture must parse:\n{}", m.source);
    run(&[m], &LintConfig::default())
        .findings
        .into_iter()
        .filter(|f| f.rule == rule)
        .collect()
}

fn help_of(rule: &str, body: &str) -> String {
    findings(rule, body)
        .iter()
        .map(|f| f.help.join("\n"))
        .collect::<Vec<_>>()
        .join("\n")
}

// ── prefer-pipeline ──────────────────────────────────────────────────────────

const PIPE: &str = "prefer-pipeline";

#[test]
fn pipeline_offers_both_directions() {
    let help = help_of(
        PIPE,
        "    String.concat (List.map fmt (List.filter live records))",
    );
    assert!(
        help.contains("records |> List.filter live |> List.map fmt |> String.concat"),
        "{help}"
    );
    assert!(
        help.contains("String.concat <| List.map fmt <| List.filter live records"),
        "{help}"
    );
}

#[test]
fn pipeline_operator_subject_counts_as_a_level() {
    let help = help_of(PIPE, "    max 0 (min a (model.length + 1))");
    assert!(
        help.contains("model.length + 1 |> min a |> max 0"),
        "{help}"
    );
    assert!(
        help.contains("max 0 <| min a <| model.length + 1"),
        "{help}"
    );
}

#[test]
fn pipeline_ignores_shallow_nesting() {
    assert!(findings(PIPE, "    List.map fmt (List.filter live records)").is_empty());
    assert!(findings(PIPE, "    f (g x)").is_empty());
}

#[test]
fn pipeline_ignores_a_do_bind() {
    let body = concat!(
        "    do\n",
        "        rows <- Db.query conn (Sql.select table)\n",
        "        Task.succeed rows",
    );
    assert!(findings(PIPE, body).is_empty());
}

#[test]
fn pipeline_anchors_a_deep_bind_rhs_on_its_source() {
    let body = concat!(
        "    do\n",
        "        rows <- Db.query conn (Sql.where p (Sql.select table))\n",
        "        Task.succeed rows",
    );
    let help = help_of(PIPE, body);
    assert!(
        help.contains("table |> Sql.select |> Sql.where p |> Db.query conn"),
        "{help}"
    );
    assert!(!help.contains("<-"), "{help}");
}

#[test]
fn pipeline_fix_keeps_parens_of_a_non_last_arg() {
    let m = module("    g (String.concat (List.map f (List.filter p xs))) y");
    let outcome = apply_fixes(&[m], &LintConfig::default());
    assert_eq!(outcome.applied, 1, "expected one rewrite");
    let Some(fixed) = outcome.rewritten.get(&vec!["Main".to_owned()]) else {
        return;
    };
    assert!(
        fixed.contains("g (xs |> List.filter p |> List.map f |> String.concat) y"),
        "{fixed}"
    );
}

#[test]
fn pipeline_fix_does_not_double_parenthesise() {
    let m = module("    n * (String.length (List.map f (List.filter p xs)))");
    let outcome = apply_fixes(&[m], &LintConfig::default());
    assert_eq!(outcome.applied, 1, "expected one rewrite");
    let Some(fixed) = outcome.rewritten.get(&vec!["Main".to_owned()]) else {
        return;
    };
    assert!(
        fixed.contains("n * (xs |> List.filter p |> List.map f |> String.length)"),
        "{fixed}"
    );
    assert!(!fixed.contains("(("), "{fixed}");
}

#[test]
fn desugared_do_bind_is_not_a_source_call() {
    let src = concat!(
        "module Main exposing (main)\n\nmain =\n",
        "    do\n",
        "        rows <- Db.query conn q\n",
        "        Task.succeed rows\n",
    );
    assert!(parses(src), "fixture must parse");
    let mut interner = Interner::new();
    let Ok(ast) = ipe_parse::parse_module(src, &mut interner) else {
        return;
    };
    let module = vec!["Main".to_owned()];
    let ctx = Ctx {
        module: &module,
        source: src,
        interner: &interner,
        ast: &ast,
    };
    let mut and_then_calls = 0_usize;
    let mut source_calls = Vec::new();
    visit_exprs(&ctx, &mut |expr| {
        let Expr_::Call(callee, _) = &expr.value else {
            return;
        };
        if let Expr_::VarQual(_, name) = &callee.value
            && ctx.text(*name) == "andThen"
        {
            and_then_calls += 1;
            assert!(!is_source_call(expr), "synthetic bind is not source");
        } else if is_source_call(expr) {
            source_calls.push(ctx.slice(expr.span).to_owned());
        }
    });
    assert_eq!(and_then_calls, 1);
    assert!(
        source_calls.contains(&"Db.query conn q".to_owned()),
        "{source_calls:?}"
    );
}

// ── multiline-lambda-arg ─────────────────────────────────────────────────────

const LAMBDA: &str = "multiline-lambda-arg";

#[test]
fn multiline_lambda_arg_fires() {
    let body = concat!("    List.map (\\row ->\n", "        row + 1) rows",);
    assert_eq!(findings(LAMBDA, body).len(), 1);
}

#[test]
fn one_line_lambda_arg_is_fine() {
    assert!(findings(LAMBDA, "    List.map (\\row -> row + 1) rows").is_empty());
}

#[test]
fn do_bind_continuation_is_not_a_lambda_arg() {
    let body = concat!(
        "    do\n",
        "        rows <- Db.query conn q\n",
        "        n <- Task.succeed 1\n",
        "        Task.succeed rows",
    );
    assert!(findings(LAMBDA, body).is_empty());
}

#[test]
fn backward_pipe_lambda_is_fine() {
    let body = concat!(
        "    Task.andThen t <| \\row ->\n",
        "        Task.succeed row",
    );
    assert!(findings(LAMBDA, body).is_empty());
}

// ── no-bool-literal-compare ──────────────────────────────────────────────────

const CMP: &str = "no-bool-literal-compare";

#[test]
fn bool_literal_compare_fires() {
    assert!(help_of(CMP, "    done == True").contains("write `done`"));
    assert!(help_of(CMP, "    done /= True").contains("write `not done`"));
    assert!(help_of(CMP, "    False == done").contains("write `not done`"));
    assert!(help_of(CMP, "    isOk r == False").contains("write `not (isOk r)`"));
}

#[test]
fn non_literal_compare_is_fine() {
    assert!(findings(CMP, "    x == y").is_empty());
    assert!(findings(CMP, "    True == False").is_empty());
    assert!(findings(CMP, "    a && b == True || c").is_empty());
}

// ── no-redundant-bool-if ─────────────────────────────────────────────────────

const IF: &str = "no-redundant-bool-if";

#[test]
fn redundant_bool_if_fires() {
    assert!(help_of(IF, "    if ok then True else False").contains("`ok`"));
    assert!(help_of(IF, "    if ok then False else True").contains("`not ok`"));
}

#[test]
fn meaningful_if_is_fine() {
    assert!(findings(IF, "    if ok then a else False").is_empty());
    assert!(findings(IF, "    if ok then True else if b then x else False").is_empty());
}

// ── no-simple-let-body ───────────────────────────────────────────────────────

const LET: &str = "no-simple-let-body";

#[test]
fn simple_let_body_fires() {
    let body = concat!(
        "    let\n",
        "        total = a + b\n",
        "    in\n",
        "    total",
    );
    assert_eq!(findings(LET, body).len(), 1);
}

#[test]
fn let_body_doing_work_is_fine() {
    let other = concat!(
        "    let\n",
        "        total = a + b\n",
        "    in\n",
        "    other",
    );
    assert!(findings(LET, other).is_empty());
    let used = concat!(
        "    let\n",
        "        total = a + b\n",
        "    in\n",
        "    total * 2",
    );
    assert!(findings(LET, used).is_empty());
    let named_fn = concat!(
        "    let\n",
        "        step x = x + 1\n",
        "    in\n",
        "    step",
    );
    assert!(findings(LET, named_fn).is_empty());
}
