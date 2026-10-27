//! Refusal and shape tests for parser front-end corrections.
//!
//! Each pins a path that must be rejected (a dotted binder, a dotted lowercase
//! type, an unindented `do` block) or a legal shape that must now parse (field
//! access on a qualified value). A rejection no test drives is one edit from
//! silently vanishing.

use std::fmt::Write as _;

use ipe_diagnostics::nesting::{COMPOSE_NESTING, SOURCE_NESTING_LIMIT};
use ipe_diagnostics::{Diagnostic, ParseError};
use ipe_intern::Interner;
use ipe_parse::parse_module;
use ipe_syntax::{Expr_, Pattern_};

/// Wrap `body` as the single `main` binding of a minimal module.
fn module_with_main(body: &str) -> String {
    format!("module Main exposing (main)\n\nmain =\n    {body}\n")
}

/// A dotted lowercase identifier in binder position (`\a.b -> a.b`) is not a
/// value binder and must be rejected rather than minted as a `PVar` with a
/// dotted name.
#[test]
fn dotted_lowercase_lambda_param_is_rejected() {
    let mut i = Interner::new();
    let src = module_with_main("\\a.b -> a.b");
    assert!(parse_module(&src, &mut i).is_err());
}

/// A dotted lowercase top-level parameter is likewise rejected.
#[test]
fn dotted_lowercase_top_level_param_is_rejected() {
    let mut i = Interner::new();
    let src = "module Main exposing (f)\n\nf a.b = a.b\n";
    assert!(parse_module(src, &mut i).is_err());
}

/// A dotted lowercase-head identifier in type position (`f : a.b -> a.b`) is
/// not a type variable; it is rejected instead of silently generalising.
#[test]
fn dotted_lowercase_type_is_rejected() {
    let mut i = Interner::new();
    let src = "module Main exposing (f)\n\nf : a.b -> a.b\nf x = x\n";
    assert!(parse_module(src, &mut i).is_err());
}

/// An unindented `do` block whose statements sit at or before the enclosing
/// layout threshold must be rejected, not silently swallow the following
/// top-level declaration.
#[test]
fn unindented_do_block_is_rejected() {
    let mut i = Interner::new();
    let src = "module Main exposing (main)\n\nmain = do\nx = 1\n\nother = 2\n";
    assert!(parse_module(src, &mut i).is_err());
}

/// Field access on a qualified value parses as a `VarQual` followed by an
/// `Access` chain, not a `VarQual` with a dotted qualifier.
#[test]
fn field_access_on_qualified_value_is_access_chain() {
    let mut i = Interner::new();
    let src = module_with_main("Http.defaultConfig.timeout");
    let m = parse_module(&src, &mut i).expect("qualified field access must parse");
    let body = &m.values.first().expect("main binding").value.body.value;
    let ok = matches!(body, Expr_::Access(inner, field)
        if i.resolve(field.value) == Some("timeout")
            && matches!(&inner.value, Expr_::VarQual(q, name)
                if i.resolve(*q) == Some("Http") && i.resolve(*name) == Some("defaultConfig")));
    assert!(
        ok,
        "expected Access(VarQual(Http, defaultConfig), timeout), got {body:?}"
    );
}

/// A plain qualified constructor reference (`Maybe.Nothing`, all-uppercase run)
/// still parses as a bare `VarQual` with no accessor tail.
#[test]
fn all_uppercase_qualified_name_stays_var_qual() {
    let mut i = Interner::new();
    let src = module_with_main("Result.Ok");
    let m = parse_module(&src, &mut i).expect("qualified ctor ref must parse");
    let body = &m.values.first().expect("main binding").value.body.value;
    assert!(
        matches!(body, Expr_::VarQual(q, name)
            if i.resolve(*q) == Some("Result") && i.resolve(*name) == Some("Ok")),
        "expected VarQual(Result, Ok), got {body:?}"
    );
}

/// A parenthesised pattern's span covers the whole `( … )` range, not just the
/// opening paren.
#[test]
fn parenthesised_pattern_span_covers_full_range() {
    let mut i = Interner::new();
    let src = "module Main exposing (f)\n\nf (x) = x\n";
    let m = parse_module(src, &mut i).expect("parenthesised param must parse");
    let value = &m.values.first().expect("f binding").value;
    let pat = value.patterns.first().expect("one parameter");
    assert!(
        matches!(pat.value, Pattern_::PVar(_)),
        "grouped pattern unwraps to its inner PVar"
    );
    // The span must be wider than a single byte (the lone `(` bug produced a
    // 1-byte span); `(x)` spans three bytes.
    assert!(
        pat.span.hi - pat.span.lo >= 3,
        "span must cover `(x)`, got {}..{}",
        pat.span.lo,
        pat.span.hi
    );
}

// ── Bounded-by-construction: deep-nesting refusals ───────────────────────────
//
// Each test builds an adversarially deep source fragment (50 000 levels, well
// beyond MAX_DEPTH = 256) and asserts the parser returns `Err` carrying code
// `IPE-P0003 NestingTooDeep` — NOT a stack overflow, NOT `Ok`.
//
// These pin every recursive-descent branch that carries a depth counter, so
// removing or misthreading a `depth + 1` call causes at least one test to fail
// (it would either panic/overflow, or produce `Ok` instead of the P0003 error).
//
// Depth chosen: 50 000 — identical to the binop-chain probe, far above MAX_DEPTH,
// but small enough not to OOM the test runner.

const DEPTH: usize = 50_000;

/// Assert a parse `Err` carries `IPE-P0003`, failing the test otherwise. Uses
/// `assert!`/`assert_eq!` (never the `panic!` macro, which the repo denies even
/// in tests).
fn assert_nesting_too_deep(result: Result<ipe_syntax::Module, Diagnostic>, label: &str) {
    assert!(
        result.is_err(),
        "{label}: expected Err(NestingTooDeep) but parse succeeded"
    );
    let Err(diag) = result else {
        return; // unreachable after the assert above — avoids `panic!`/`unreachable!`
    };
    assert_eq!(
        diag.code().as_str(),
        "IPE-P0003",
        "{label}: expected IPE-P0003 NestingTooDeep, got {}",
        diag.code().as_str()
    );
}

/// A deeply-nested parenthesised expression `(((…)))` must be rejected with
/// `IPE-P0003`. Guards `parse_paren_or_tuple` / `parse_atom` depth branch.
#[test]
fn deep_paren_expr_is_p0003() {
    let hdr = "module Main exposing (main)\n\nmain =\n    ";
    let mut src = String::with_capacity(hdr.len() + DEPTH * 2 + 10);
    src.push_str(hdr);
    for _ in 0..DEPTH {
        src.push('(');
    }
    src.push('1');
    for _ in 0..DEPTH {
        src.push(')');
    }
    src.push('\n');

    let mut i = Interner::new();
    assert_nesting_too_deep(parse_module(&src, &mut i), "deep paren expr");
}

/// A deeply-nested list literal `[[[…]]]` must be rejected with `IPE-P0003`.
/// Guards `parse_list` depth branch.
#[test]
fn deep_list_expr_is_p0003() {
    let hdr = "module Main exposing (main)\n\nmain =\n    ";
    let mut src = String::with_capacity(hdr.len() + DEPTH * 2 + 10);
    src.push_str(hdr);
    for _ in 0..DEPTH {
        src.push('[');
    }
    src.push('1');
    for _ in 0..DEPTH {
        src.push(']');
    }
    src.push('\n');

    let mut i = Interner::new();
    assert_nesting_too_deep(parse_module(&src, &mut i), "deep list expr");
}

/// A deeply-parenthesised type annotation `f : (((Int)))` must be rejected with
/// `IPE-P0003`. Guards `parse_type_atom` depth branch.
#[test]
fn deep_paren_type_is_p0003() {
    let mut src = String::with_capacity(DEPTH * 2 + 64);
    src.push_str("module Main exposing (f)\n\nf : ");
    for _ in 0..DEPTH {
        src.push('(');
    }
    src.push_str("Int");
    for _ in 0..DEPTH {
        src.push(')');
    }
    src.push_str("\nf = 1\n");

    let mut i = Interner::new();
    assert_nesting_too_deep(parse_module(&src, &mut i), "deep paren type");
}

/// A deeply-nested paren pattern `(((x)))` in a `case` arm must be rejected
/// with `IPE-P0003`. Guards `parse_paren_pattern` / `parse_pattern` depth branch.
#[test]
fn deep_paren_pattern_is_p0003() {
    // Build:  case 1 of\n    (((…x…))) -> 1
    let hdr = "module Main exposing (main)\n\nmain =\n    case 1 of\n        ";
    let tail = " -> 1\n";
    let mut src = String::with_capacity(hdr.len() + DEPTH * 2 + 8 + tail.len());
    src.push_str(hdr);
    for _ in 0..DEPTH {
        src.push('(');
    }
    src.push('x');
    for _ in 0..DEPTH {
        src.push(')');
    }
    src.push_str(tail);

    let mut i = Interner::new();
    assert_nesting_too_deep(parse_module(&src, &mut i), "deep paren pattern");
}

/// A deeply-nested list pattern `[[[x]]]` in a `case` arm must be rejected with
/// `IPE-P0003`. Guards `parse_list_pattern` depth branch.
#[test]
fn deep_list_pattern_is_p0003() {
    let hdr = "module Main exposing (main)\n\nmain =\n    case 1 of\n        ";
    let tail = " -> 1\n";
    let mut src = String::with_capacity(hdr.len() + DEPTH * 2 + 8 + tail.len());
    src.push_str(hdr);
    for _ in 0..DEPTH {
        src.push('[');
    }
    src.push('1');
    for _ in 0..DEPTH {
        src.push(']');
    }
    src.push_str(tail);

    let mut i = Interner::new();
    assert_nesting_too_deep(parse_module(&src, &mut i), "deep list pattern");
}

/// A deeply-nested record literal `{ x = { x = … } }` must be rejected with
/// `IPE-P0003`. Guards `parse_record` depth branch.
#[test]
fn deep_record_expr_is_p0003() {
    // Each nesting level: "{ x = " … " }" — 7 chars open, 2 chars close.
    let hdr = "module Main exposing (main)\n\nmain =\n    ";
    let open = "{ x = ";
    let close = " }";
    let mut src = String::with_capacity(hdr.len() + DEPTH * (open.len() + close.len()) + 4);
    src.push_str(hdr);
    for _ in 0..DEPTH {
        src.push_str(open);
    }
    src.push('1');
    for _ in 0..DEPTH {
        src.push_str(close);
    }
    src.push('\n');

    let mut i = Interner::new();
    assert_nesting_too_deep(parse_module(&src, &mut i), "deep record expr");
}

// ── Manufactured nesting: `do` and `let` blocks charge the ceiling ──────────
//
// A flat block of N statements lowers to N nested binders, so the block, not
// the source indentation, decides the depth every later stage walks. The
// boundary is found by search (the enclosing frames' cost is the parser's
// business), then pinned: the block one statement shorter parses, and the
// block at the boundary is refused with `NestingTooDeep` spanning the whole
// offending sequence, from its first statement, operand or `if` to the token
// that crossed the ceiling.

/// A block module's source plus the exact span its refusal must carry.
type Block = (String, (u32, u32));

/// The module text before `main`'s body.
const HEADER: &str = "module Main exposing (main)\n\nmain =\n";

/// The `u32` byte offset of `at`.
fn offset(at: usize) -> u32 {
    u32::try_from(at).unwrap_or(u32::MAX)
}

/// The token a block's refusal crosses the ceiling at.
#[derive(Clone, Copy)]
enum Crossing {
    /// The last token of the block's last statement.
    LastStatement,
    /// The last token of the block's closing text.
    Close,
}

/// A module whose `main` is a block of `n` statements framed by `open` / `close`.
fn block_module(
    n: usize,
    open: &str,
    stmt: impl Fn(usize) -> String,
    close: &str,
    crossing: Crossing,
) -> Block {
    let mut src = String::from(HEADER);
    src.push_str(open);
    let first = stmt(0);
    let start = src.len() + first.len() - first.trim_start().len();
    let mut last_end = src.len();
    for i in 0..n {
        src.push_str(&stmt(i));
        last_end = src.len();
        src.push('\n');
    }
    src.push_str(close);
    let end = match crossing {
        Crossing::LastStatement => last_end,
        Crossing::Close => src.trim_end().len(),
    };
    (src, (offset(start), offset(end)))
}

/// A module whose `main` is `head` followed by `n` copies of `step`, refused
/// from `head`'s first token through byte `crossing_end` of the last copy.
fn chain_module(
    head: &str,
    n: usize,
    step: impl Fn(usize) -> String,
    crossing_end: usize,
) -> Block {
    let mut src = format!("{HEADER}    {head}");
    let start = HEADER.len() + 4;
    let mut last = src.len();
    for i in 0..n {
        last = src.len();
        src.push_str(&step(i));
    }
    src.push('\n');
    (src, (offset(start), offset(last + crossing_end)))
}

/// The ceiling as a statement count.
fn ceiling() -> usize {
    usize::try_from(SOURCE_NESTING_LIMIT).unwrap_or(usize::MAX)
}

/// The first statement count `build` refuses, searched up to twice the ceiling.
fn first_refused(build: impl Fn(usize) -> Block) -> Option<usize> {
    (1..=2 * ceiling()).find(|n| {
        let (src, _) = build(*n);
        parse_module(&src, &mut Interner::new()).is_err()
    })
}

/// Assert the block of `boundary - 1` statements parses and the block of
/// `boundary` is refused as `NestingTooDeep` spanning exactly the offending
/// sequence `build` names.
///
/// Returns the boundary.
fn assert_block_boundary(build: impl Fn(usize) -> Block, label: &str) -> usize {
    let found = first_refused(&build);
    assert!(
        found.is_some(),
        "{label}: no statement count up to twice the ceiling is refused"
    );
    let Some(boundary) = found else {
        return 0;
    };
    assert!(boundary > 1, "{label}: a one-statement block is refused");

    let (below, _) = build(boundary - 1);
    let ok = parse_module(&below, &mut Interner::new());
    assert!(
        ok.is_ok(),
        "{label}: {} statements must parse: {ok:?}",
        boundary - 1
    );

    let (at, expected) = build(boundary);
    let refused = parse_module(&at, &mut Interner::new());
    assert!(
        matches!(
            refused,
            Err(Diagnostic::Parse {
                msg: ParseError::NestingTooDeep { .. },
                ..
            })
        ),
        "{label}: {boundary} statements: expected NestingTooDeep, got {refused:?}"
    );
    let Err(Diagnostic::Parse {
        span,
        msg: ParseError::NestingTooDeep { limit, .. },
    }) = refused
    else {
        return boundary;
    };
    assert_eq!(
        u32::from(limit),
        SOURCE_NESTING_LIMIT,
        "{label}: the refusal names the ceiling"
    );
    assert_eq!(
        (span.lo, span.hi),
        expected,
        "{label}: the refusal spans the offending sequence"
    );
    boundary
}

// The exact boundaries. A declaration body's block opens at depth 4 (the
// body's expression, application, postfix and atom frames), so its statements
// start at depth 5, and an operand atom sits four frames below the depth its
// statement is charged at.

/// Frames between a block's statement depth and its operand atom's depth.
const STATEMENT_TO_ATOM: usize = 4;

/// Depth a declaration body's block statements start at.
const FIRST_STATEMENT_DEPTH: usize = 5;

/// A `do` block of binds charges two levels per bind (the `Task.andThen` call
/// and its continuation lambda): bind `k`'s operand sits at depth `9 + 2k`, so
/// the first bind past the ceiling is the boundary.
#[test]
fn do_block_of_binds_is_refused_at_the_ceiling() {
    let build = |n: usize| {
        block_module(
            n,
            "    do\n",
            |i| format!("        x{i} <- t"),
            "        t\n",
            Crossing::LastStatement,
        )
    };
    let boundary = assert_block_boundary(build, "do binds");
    let first_atom = FIRST_STATEMENT_DEPTH + STATEMENT_TO_ATOM;
    assert_eq!(
        boundary,
        (ceiling() - first_atom) / 2 + 1,
        "each bind charges two levels"
    );
}

/// A `do` block of bare runs charges one level per run, and its final run one
/// more: with `n` runs the final run's operand sits at depth `10 + n`.
#[test]
fn do_block_of_runs_is_refused_at_the_ceiling() {
    let build = |n: usize| {
        block_module(
            n,
            "    do\n",
            |i| format!("        t{i}"),
            "        t\n",
            Crossing::Close,
        )
    };
    let boundary = assert_block_boundary(build, "do runs");
    let final_atom = FIRST_STATEMENT_DEPTH + STATEMENT_TO_ATOM + 1;
    assert_eq!(
        boundary,
        ceiling() + 1 - final_atom,
        "each run charges one level"
    );
}

/// A `let` block charges one level per binding: binding `k`'s operand sits at
/// depth `9 + k`, and the body below the last binding one level shallower.
#[test]
fn let_block_is_refused_at_the_ceiling() {
    let build = |n: usize| {
        block_module(
            n,
            "    let\n",
            |i| format!("        x{i} = 1"),
            "    in\n    1\n",
            Crossing::LastStatement,
        )
    };
    let boundary = assert_block_boundary(build, "let bindings");
    let first_atom = FIRST_STATEMENT_DEPTH + STATEMENT_TO_ATOM;
    assert_eq!(
        boundary,
        ceiling() + 1 - first_atom,
        "each binding charges one level"
    );
}

/// An operator chain charges one level per operator from its expression's
/// depth. A declaration body's expression is at depth 0, so the ceiling admits
/// exactly that many operators and the next one is refused, spanning the chain
/// from its first operand to that operator.
#[test]
fn operator_chain_is_refused_one_past_the_ceiling() {
    let build = |n: usize| chain_module("1", n, |_| " + 1".to_owned(), 2);
    let boundary = assert_block_boundary(build, "operator chain");
    assert_eq!(boundary, ceiling() + 1, "each operator charges one level");
}

/// The parentheses around the deep operand of a chain-depth test.
const OPERAND_PARENS: usize = 8;

/// The levels each parenthesis adds over the atom it sits in: its own frame
/// and the expression, application, postfix and atom frames of its contents.
const LEVELS_PER_PAREN: usize = 5;

/// `1` wrapped in [`OPERAND_PARENS`] parentheses.
fn deep_operand() -> String {
    format!(
        "{}1{}",
        "(".repeat(OPERAND_PARENS),
        ")".repeat(OPERAND_PARENS)
    )
}

/// A chain whose first operand nests deep is charged the whole chain over
/// that operand's depth, since re-association puts it under every operator;
/// the refusal spans from that operand's first `(` to the crossing operator.
#[test]
fn deep_first_operand_charges_the_chain() {
    let build = |n: usize| chain_module(&deep_operand(), n, |_| " + 1".to_owned(), 2);
    let boundary = assert_block_boundary(build, "deep first operand");
    assert_eq!(
        boundary,
        ceiling() + 1 - LEVELS_PER_PAREN * OPERAND_PARENS,
        "the chain is charged over its deepest operand"
    );
}

/// A chain whose last operand nests deep is refused once that operand is
/// parsed, by the same count as a deep first one, spanning from the chain's
/// first operand to the operator before the deep one.
#[test]
fn deep_last_operand_charges_the_chain() {
    let build = |n: usize| {
        let step = move |i: usize| {
            if i + 1 == n {
                format!(" + {}", deep_operand())
            } else {
                " + 1".to_owned()
            }
        };
        chain_module("1", n, step, 2)
    };
    let boundary = assert_block_boundary(build, "deep last operand");
    assert_eq!(
        boundary,
        ceiling() + 1 - LEVELS_PER_PAREN * OPERAND_PARENS,
        "the chain is charged over its deepest operand"
    );
}

/// An `else if` chain lowers to right-nested `If`s, so each `else if` charges
/// one level: the `if` opens at depth 4 and its arms at 5, so the `k`-th
/// `else if`'s condition atom sits at depth `8 + k`, and the refusal spans
/// from the `if` to that condition.
#[test]
fn else_if_chain_is_refused_at_the_ceiling() {
    let build = |n: usize| {
        let (mut src, span) = chain_module(
            "if True then 1",
            n,
            |_| " else if True then 1".to_owned(),
            13,
        );
        src.pop();
        src.push_str(" else 1\n");
        (src, span)
    };
    let boundary = assert_block_boundary(build, "else if chain");
    let arm_atom = FIRST_STATEMENT_DEPTH + STATEMENT_TO_ATOM - 1;
    assert_eq!(
        boundary,
        ceiling() + 1 - arm_atom,
        "each `else if` charges one level"
    );
}

/// A composition desugars to a lambda over two calls, so each `>>` charges
/// `COMPOSE_NESTING` levels from its expression's depth: a declaration body's
/// expression is at depth 0, so the first `>>` whose cumulative charge passes
/// the ceiling is refused, spanning the chain from `f` to that operator.
#[test]
fn composition_chain_is_refused_at_its_charged_ceiling() {
    let build = |n: usize| chain_module("f", n, |_| " >> f".to_owned(), 3);
    let boundary = assert_block_boundary(build, "composition chain");
    let charge = usize::try_from(COMPOSE_NESTING).unwrap_or(usize::MAX);
    assert_eq!(
        boundary,
        ceiling() / charge + 1,
        "each `>>` charges its desugar's levels"
    );
}

// ── Field-access chains charge the ceiling from where they sit ──────────────
//
// A dotted run `r.a.….a` is one token but builds one nested `Access` per
// segment, so each segment costs one level over the depth of the atom it
// wraps; the segment past the ceiling is refused spanning the chain from its
// base through that segment.

/// Depth a declaration body's atom is parsed at: below the body's expression,
/// application and postfix frames.
const BODY_ATOM_DEPTH: usize = 3;

/// A module whose `main` is `before` followed by `n` `.a` segments, refused
/// from the chain's base at byte `base` of `before` through the last segment.
fn access_module(before: &str, base: usize, n: usize) -> Block {
    let mut src = format!("{HEADER}{before}");
    let start = HEADER.len() + base;
    let mut last = src.len();
    for _ in 0..n {
        last = src.len();
        src.push_str(".a");
    }
    src.push('\n');
    (src, (offset(start), offset(last + 2)))
}

/// `r.a.….a` in a declaration body: the identifier's atom sits at depth 3,
/// so the ceiling admits that many fewer segments.
#[test]
fn access_chain_is_refused_at_the_ceiling() {
    let boundary = assert_block_boundary(|n| access_module("    r", 4, n), "access chain");
    assert_eq!(
        boundary,
        ceiling() + 1 - BODY_ATOM_DEPTH,
        "each segment charges one level"
    );
}

/// `(r).a.….a` charges from the parenthesised atom's depth, the same depth a
/// bare dotted identifier sits at.
#[test]
fn postfix_access_chain_is_refused_at_the_ceiling() {
    let boundary = assert_block_boundary(|n| access_module("    (r)", 4, n), "postfix access");
    assert_eq!(
        boundary,
        ceiling() + 1 - BODY_ATOM_DEPTH,
        "each segment charges one level"
    );
}

/// The accessor `.a.….a` reads its chain inside the getter lambda it
/// desugars to, one level below the atom.
#[test]
fn accessor_chain_is_refused_at_the_ceiling() {
    let boundary = assert_block_boundary(|n| access_module("    ", 4, n), "accessor chain");
    assert_eq!(
        boundary,
        ceiling() + 1 - (BODY_ATOM_DEPTH + 1),
        "the getter's chain sits one level below the atom"
    );
}

/// Binds in the `do` block a mixed chain closes.
const MIXED_BINDS: usize = 120;

/// A `do` block of `MIXED_BINDS` binds whose final statement is `r` and `n`
/// segments, refused as the access chain from `r` on.
fn do_then_access(n: usize) -> Block {
    let mut block = String::from("    do\n");
    for i in 0..MIXED_BINDS {
        let _ = writeln!(block, "        x{i} <- t");
    }
    block.push_str("        r");
    let base = block.len() - 1;
    access_module(&block, base, n)
}

/// A chain closing a `do` block charges from the block's charged depth, so a
/// chain a declaration body admits on its own is refused at parse when it
/// ends a long block, instead of reaching the emitter's IR ceiling.
#[test]
fn access_chain_after_do_block_is_refused_at_parse() {
    let boundary = assert_block_boundary(do_then_access, "do block then access chain");
    // The final run is charged one level past the binds' `2 * MIXED_BINDS`,
    // and its operand atom sits `STATEMENT_TO_ATOM` frames below that.
    let final_atom = FIRST_STATEMENT_DEPTH + 2 * MIXED_BINDS + 1 + STATEMENT_TO_ATOM;
    assert_eq!(
        boundary,
        ceiling() + 1 - final_atom,
        "the chain charges from the block's charged depth"
    );

    let long = ceiling() - BODY_ATOM_DEPTH;
    let (alone, _) = access_module("    r", 4, long);
    let admitted = parse_module(&alone, &mut Interner::new());
    assert!(
        admitted.is_ok(),
        "{long} segments in a declaration body must parse: {admitted:?}"
    );
    let (mixed, _) = do_then_access(long);
    let base = mixed
        .find("        r.a")
        .map_or(0, |at| at + "        ".len());
    let expected = (offset(base), offset(base + 1 + 2 * boundary));
    let refused = parse_module(&mixed, &mut Interner::new());
    assert!(
        matches!(
            refused,
            Err(Diagnostic::Parse {
                msg: ParseError::NestingTooDeep { .. },
                ..
            })
        ),
        "{long} segments closing the block: expected NestingTooDeep, got {refused:?}"
    );
    let (at_lo, at_hi) = match refused {
        Err(Diagnostic::Parse { span, .. }) => (span.lo, span.hi),
        _ => (0, 0),
    };
    assert_eq!(
        (at_lo, at_hi),
        expected,
        "the refusal spans the chain from `r` through segment {boundary}"
    );
}
