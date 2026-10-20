//! Refusal and shape tests for parser front-end corrections.
//!
//! Each pins a path that must be rejected (a dotted binder, a dotted lowercase
//! type, an unindented `do` block) or a legal shape that must now parse (field
//! access on a qualified value). A rejection no test drives is one edit from
//! silently vanishing.

use ipe_diagnostics::nesting::SOURCE_NESTING_LIMIT;
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
// block at the boundary is refused with `NestingTooDeep` in the tail the last
// statement pushed past the ceiling: that statement or the block's result.

/// A block module's source plus the byte range from its last statement to the end.
type Block = (String, (u32, u32));

/// A module whose `main` is a block of `n` statements framed by `open` / `close`.
fn block_module(n: usize, open: &str, stmt: impl Fn(usize) -> String, close: &str) -> Block {
    let mut src = String::from("module Main exposing (main)\n\nmain =\n");
    src.push_str(open);
    let mut last = 0;
    for i in 0..n {
        last = src.len();
        src.push_str(&stmt(i));
        src.push('\n');
    }
    src.push_str(close);
    let offset = |at: usize| u32::try_from(at).unwrap_or(u32::MAX);
    let tail = (offset(last), offset(src.len()));
    (src, tail)
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
/// `boundary` is refused as `NestingTooDeep` in the tail statement `boundary`
/// starts.
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

    let (at, (lo, hi)) = build(boundary);
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
    assert!(
        span.lo >= lo && span.hi <= hi,
        "{label}: span {}..{} lies in the crossing tail {lo}..{hi}",
        span.lo,
        span.hi
    );
    boundary
}

/// A `do` block of binds charges two levels per bind (the `Task.andThen` call
/// and its continuation lambda), so the ceiling stops it within half the limit.
#[test]
fn do_block_of_binds_is_refused_at_the_ceiling() {
    let build = |n: usize| {
        block_module(
            n,
            "    do\n",
            |i| format!("        x{i} <- t"),
            "        t\n",
        )
    };
    let boundary = assert_block_boundary(build, "do binds");
    assert!(
        boundary <= ceiling() / 2,
        "each bind charges two levels: refused at {boundary}, past half of {}",
        ceiling()
    );
}

/// A `do` block of bare runs charges one level per run.
#[test]
fn do_block_of_runs_is_refused_at_the_ceiling() {
    let build = |n: usize| block_module(n, "    do\n", |i| format!("        t{i}"), "        t\n");
    let boundary = assert_block_boundary(build, "do runs");
    assert!(
        boundary <= ceiling(),
        "each run charges one level: refused at {boundary}, past {}",
        ceiling()
    );
}

/// A `let` block charges one level per binding.
#[test]
fn let_block_is_refused_at_the_ceiling() {
    let build = |n: usize| {
        block_module(
            n,
            "    let\n",
            |i| format!("        x{i} = 1"),
            "    in\n    1\n",
        )
    };
    let boundary = assert_block_boundary(build, "let bindings");
    assert!(
        boundary <= ceiling(),
        "each binding charges one level: refused at {boundary}, past {}",
        ceiling()
    );
}
