//! The declared compile stack holds every shape the parser admits.
//!
//! The nesting a body reaches every later stage is bounded by the parser's
//! ceiling, but the frames each level costs are not provable statically. Each
//! shape that builds deep nesting is compiled through emit, at the deepest
//! depth the parser admits, on the one compile door the commands use
//! ([`crate::threads::run_compile`], a thread of exactly
//! [`crate::threads::COMPILE_STACK_BYTES`]); one level deeper is refused by the
//! parser with `NestingTooDeep` inside its innermost level, never by a later
//! stage or a stack overflow. Under `IPE_E2E=1` the at-ceiling program of each
//! shape is also built with cargo.
//!
//! A source ceiling and a type ceiling bound different things: an access chain
//! as long as the source ceiling admits reads through more record levels than
//! the type ceiling lets one record have, so at its source ceiling it is
//! refused by the type checker, and its type ceiling is pinned on its own.
//!
//! The deepest count of each shape is pinned. A body's expression opens at
//! depth 0; an application adds one frame, its head or argument a postfix and
//! an atom frame, a construct the atom opens one more, and that construct's
//! inner expression one more, so a nesting construct costs five levels.

#![cfg(test)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use ipe_diagnostics::nesting::{
    COMPOSE_NESTING, LAMBDA_CHAIN_TYPE_DEPTH_AT_SOURCE_CEILING, SOURCE_NESTING_LIMIT,
    TYPE_DEPTH_LIMIT,
};
use ipe_diagnostics::{Diagnostic, IPE_T0022, ParseError};

use crate::CliError;
use crate::driver::{
    BuildOptions, SettingsSource, compile_prepared, create_source_root, emit_settings,
};

/// The imports every shape's module opens with.
const HEADER: &str = "module Main exposing (main)\n\n\
                      import Ipe.Io as Io\n\
                      import Ipe.List as List\n\
                      import Ipe.String as String\n\
                      import Ipe.Task as Task\n\n\n";

/// A `main` that prints `deep 1`, then the head of `deep : Int -> Int`.
const DEEP_HEAD: &str = "main =\n    Io.println (String.fromInt (deep 1))\n\n\n\
                         deep : Int -> Int\ndeep x =\n";

/// A shape's source and the byte range its refusal one level past the ceiling
/// must lie in: the innermost nesting level, or a sequence's last element
/// through the end.
struct Shaped {
    src: String,
    tail: (u32, u32),
}

/// A source generator of one nesting shape, by depth.
type Shape = fn(usize) -> Shaped;

/// What compiling a shape at its source ceiling yields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AtCeiling {
    /// The program compiles through emit and builds with cargo.
    Builds,
    /// The type checker refuses the program, after every earlier stage ran
    /// on the declared stack.
    TypeRefused,
}

/// The ceiling as a count.
fn ceiling() -> usize {
    usize::try_from(SOURCE_NESTING_LIMIT).unwrap_or(usize::MAX)
}

/// A byte offset as a span bound.
fn offset(at: usize) -> u32 {
    u32::try_from(at).unwrap_or(u32::MAX)
}

/// `before`, `n` nested copies of `open`, `core`, `n` copies of `close`, then
/// `after`; the tail is the innermost level.
fn nested(n: usize, before: &str, open: &str, core: &str, close: &str, after: &str) -> Shaped {
    let mut src = String::from(HEADER);
    src.push_str(before);
    let mut lo = src.len();
    for _ in 0..n {
        lo = src.len();
        src.push_str(open);
    }
    src.push_str(core);
    let mut hi = src.len();
    for level in 0..n {
        src.push_str(close);
        if level == 0 {
            hi = src.len();
        }
    }
    src.push_str(after);
    Shaped {
        src,
        tail: (offset(lo), offset(hi)),
    }
}

/// `before`, `n` steps, then `after`; the tail runs from the last step to the end.
fn sequence(n: usize, before: &str, step: impl Fn(usize) -> String, after: &str) -> Shaped {
    let mut src = String::from(HEADER);
    src.push_str(before);
    let mut lo = src.len();
    for i in 0..n {
        lo = src.len();
        src.push_str(&step(i));
    }
    src.push_str(after);
    let tail = (offset(lo), offset(src.len()));
    Shaped { src, tail }
}

/// A `do` block of `n` binds.
fn do_binds(n: usize) -> Shaped {
    sequence(
        n,
        "main =\n    do\n",
        |_| "        _ <- Io.println \"s\"\n".to_owned(),
        "        Io.println \"e\"\n",
    )
}

/// A `let` block of `n` bindings after `x0`, each reading the one before it.
fn let_block(n: usize) -> Shaped {
    let body = format!("    in\n    Io.println (String.fromInt x{n})\n");
    sequence(
        n,
        "main =\n    let\n        x0 = 0\n",
        |i| format!("        x{} = x{i} + 1\n", i + 1),
        &body,
    )
}

/// A chain of `n` `+` operators.
fn binop_chain(n: usize) -> Shaped {
    sequence(
        n,
        "main =\n    Io.println (String.fromInt (1",
        |_| " + 1".to_owned(),
        "))\n",
    )
}

/// A composition of `n + 1` `inc`s by `>>`, applied to `1`.
fn compose_chain(n: usize) -> Shaped {
    sequence(
        n,
        "main =\n    Io.println (String.fromInt ((inc",
        |_| " >> inc".to_owned(),
        ") 1))\n\n\ninc : Int -> Int\ninc x =\n    x + 1\n",
    )
}

/// The bindings `{name}1 = { a = {name}0 }` through `{name}{n}` of a `let`
/// block, each wrapping the one before it in a record.
fn record_wraps(name: &str, n: usize) -> String {
    let mut bindings = String::new();
    for i in 0..n {
        let _ = writeln!(bindings, "        {name}{} = {{ a = {name}{i} }}", i + 1);
    }
    bindings
}

/// `n` field accesses `r.a.a.….a` in one dotted identifier, over a record
/// nested `n` deep.
fn access_chain(n: usize) -> Shaped {
    access_over(n, n)
}

/// `n` field accesses `r.a.a.….a` in one dotted identifier, over a record
/// nested exactly as deep as the type ceiling admits.
///
/// Past that many accesses the chain reads a field of an `Int`, so the type
/// checker refuses the program once the parser has admitted it.
fn ceiling_record_access_chain(n: usize) -> Shaped {
    access_over(usize::from(TYPE_DEPTH_LIMIT), n)
}

/// `n` field accesses `r.a.a.….a` in one dotted identifier, over a record
/// nested `depth` deep.
///
/// The record is built by two top-level `let` blocks of about `depth / 2`
/// bindings each, so building it stays far under the source ceiling.
fn access_over(depth: usize, n: usize) -> Shaped {
    let inner = depth / 2;
    let outer = depth - inner;
    let after = format!(
        ")\n\n\ninner =\n    let\n        x0 = 1\n{}    in\n    x{inner}\n\n\n\
         r =\n    let\n        y0 = inner\n{}    in\n    y{outer}\n",
        record_wraps("x", inner),
        record_wraps("y", outer)
    );
    sequence(
        n,
        "main =\n    Io.println (String.fromInt r",
        |_| ".a".to_owned(),
        &after,
    )
}

/// A `do` of `n` named binds inside a `Task` lambda over a handle, every
/// bind read by the final statement.
fn do_fan_in(n: usize) -> Shaped {
    let names: Vec<String> = (1..=n).map(|i| format!("x{i}")).collect();
    let after = format!(
        "                report [ {} ]\n        )\n\n\n\
         withHandle : (Int -> Task Error ()) -> Task Error ()\n\
         withHandle f =\n    f 0\n\n\n\
         report : List Int -> Task Error ()\n\
         report xs =\n    Io.println (String.fromInt (List.length xs))\n",
        names.join(", ")
    );
    sequence(
        n,
        "main =\n    withHandle\n        (\\h ->\n            do\n",
        |i| format!("                x{} <- Task.succeed h\n", i + 1),
        &after,
    )
}

/// The parentheses around the first operand of [`deep_operand_chain`].
const OPERAND_PARENS: usize = 8;

/// A chain of `n` `+` operators whose first operand is `1` inside
/// [`OPERAND_PARENS`] parentheses.
fn deep_operand_chain(n: usize) -> Shaped {
    let before = format!(
        "main =\n    Io.println (String.fromInt ({}1{}",
        "(".repeat(OPERAND_PARENS),
        ")".repeat(OPERAND_PARENS)
    );
    sequence(n, &before, |_| " + 1".to_owned(), "))\n")
}

/// A pipeline of `n` `Task.andThen` continuations.
fn pipeline(n: usize) -> Shaped {
    sequence(
        n,
        "main =\n    Io.println \"s\"",
        |_| " |> Task.andThen (\\_ -> Io.println \"s\")".to_owned(),
        "\n",
    )
}

/// `n` continuation lambdas, each nested inside the last.
fn nested_lambda(n: usize) -> Shaped {
    nested(
        n,
        "main =\n    ",
        "Io.println \"s\" |> Task.andThen (\\_ -> ",
        "Io.println \"end\"",
        ")",
        "\n",
    )
}

/// `n` nested applications `inc (inc (… 0))`.
fn nested_application(n: usize) -> Shaped {
    nested(
        n,
        "main =\n    Io.println (String.fromInt (",
        "inc (",
        "0",
        ")",
        "))\n\n\ninc : Int -> Int\ninc x =\n    x + 1\n",
    )
}

/// `n` nested parentheses.
fn nested_parens(n: usize) -> Shaped {
    nested(
        n,
        "main =\n    Io.println (String.fromInt (",
        "(",
        "1",
        ")",
        "))\n",
    )
}

/// `n` nested `case` expressions, each in the last one's fallback arm.
fn nested_case(n: usize) -> Shaped {
    let mut src = String::from(HEADER);
    src.push_str(DEEP_HEAD);
    let mut lo = src.len();
    for level in 0..n {
        let indent = " ".repeat(4 + 8 * level);
        lo = src.len();
        for line in ["case x of\n", "    0 ->\n", "        0\n\n", "    _ ->\n"] {
            src.push_str(&indent);
            src.push_str(line);
        }
    }
    src.push_str(&" ".repeat(4 + 8 * n));
    src.push_str("x\n");
    let tail = (offset(lo), offset(src.len()));
    Shaped { src, tail }
}

/// `n` nested `if` expressions, each in the last one's `then` branch.
fn nested_if(n: usize) -> Shaped {
    let before = format!("{DEEP_HEAD}    ");
    nested(n, &before, "if x > 0 then ", "x", " else 0", "\n")
}

/// An `if` with `n` `else if` arms.
fn else_if_chain(n: usize) -> Shaped {
    let before = format!("{DEEP_HEAD}    if x > 0 then 1");
    sequence(
        n,
        &before,
        |_| " else if x > 1 then 1".to_owned(),
        " else 0\n",
    )
}

/// `n` nested records `{ a = { a = … } }`, read back through `n` accesses.
fn nested_record(n: usize) -> Shaped {
    let after = format!(
        "\n    in\n    Io.println (String.fromInt r{})\n",
        ".a".repeat(n)
    );
    nested(
        n,
        "main =\n    let\n        r =\n            ",
        "{ a = ",
        "1",
        " }",
        &after,
    )
}

/// `n` nested list literals, measured by `List.length`.
fn nested_list(n: usize) -> Shaped {
    nested(
        n,
        "main =\n    Io.println (String.fromInt (List.length ",
        "[",
        "1",
        "]",
        "))\n",
    )
}

/// A chain of `n` one-parameter lambdas `\_ -> \_ -> … -> 7`, applied to `n` zeros.
fn lambda_chain(n: usize) -> Shaped {
    let before = format!(
        "main =\n    Io.println (String.fromInt (chain{}))\n\n\nchain : {}Int\nchain =\n    ",
        " 0".repeat(n),
        "Int -> ".repeat(n)
    );
    nested(n, &before, "\\_ -> ", "7", "", "\n")
}

/// Every nesting shape, by name, with the deepest count the parser admits.
///
/// `L` is the ceiling. A shape's deepest count is the largest `n` whose
/// deepest atom (named per entry) still sits at depth `L` or less.
fn shapes() -> [(&'static str, Shape, usize, AtCeiling); 17] {
    use AtCeiling::{Builds, TypeRefused};
    let limit = ceiling();
    let compose = usize::try_from(COMPOSE_NESTING).unwrap_or(usize::MAX);
    let lambdas = usize::try_from(LAMBDA_CHAIN_TYPE_DEPTH_AT_SOURCE_CEILING).unwrap_or(usize::MAX);
    [
        // Bind `k`'s operand atom at depth `9 + 2k`, the final run's at `10 + 2n`.
        ("do_bind", do_binds, (limit - 10) / 2, Builds),
        // The `do` atom at depth 13 in the lambda body, the final statement's
        // list element atom at `25 + 2n`.
        ("do_fan_in", do_fan_in, (limit - 25) / 2, Builds),
        // The body's `String.fromInt` atom at depth `14 + n`.
        ("let_block", let_block, limit - 14, Builds),
        // The chain's expression at depth 10, each operator one level more.
        ("binop_chain", binop_chain, limit - 10, Builds),
        // The same chain charged over its first operand, whose atom sits five
        // levels deeper per parenthesis.
        (
            "deep_operand_chain",
            deep_operand_chain,
            limit - 10 - 5 * OPERAND_PARENS,
            Builds,
        ),
        // The chain's expression at depth 15, each `>>` charged its desugar's levels.
        (
            "compose_chain",
            compose_chain,
            (limit - 15) / compose,
            Builds,
        ),
        // The dotted identifier's atom at depth 8, each segment one level more.
        (
            "access_chain",
            ceiling_record_access_chain,
            limit - 8,
            TypeRefused,
        ),
        // Each operator one level more, charged over the chain's deepest
        // operand: a continuation's body atom sits at depth 13, ten past the
        // depth 3 a chain of bare atoms is measured from.
        ("pipeline", pipeline, limit - 10, Builds),
        // Ten levels per continuation; the innermost atom at depth `10n + 3`.
        ("nested_lambda", nested_lambda, (limit - 3) / 10, Builds),
        // The innermost atom at depth `13 + 5n` inside `String.fromInt (…)`.
        (
            "nested_application",
            nested_application,
            (limit - 13) / 5,
            Builds,
        ),
        ("nested_parens", nested_parens, (limit - 13) / 5, Builds),
        ("nested_list", nested_list, (limit - 13) / 5, Builds),
        // The innermost atom at depth `10 + 5n` inside a `let` binding.
        ("nested_record", nested_record, (limit - 10) / 5, Builds),
        // The innermost atom at depth `3 + 5n` in a declaration body.
        ("nested_case", nested_case, (limit - 3) / 5, Builds),
        ("nested_if", nested_if, (limit - 3) / 5, Builds),
        ("lambda_chain", lambda_chain, lambdas, Builds),
        // Arm `k`'s condition atom at depth `8 + k`.
        ("else_if_chain", else_if_chain, limit - 8, Builds),
    ]
}

/// A multiline string of `n` interpolations.
fn interpolation(n: usize) -> String {
    let chunks = "{{tag}}".repeat(n);
    format!(
        "{HEADER}main =\n    let\n        tag = \"o\"\n        msg =\n            \"\"\"\n            \
         {chunks}\n            \"\"\"\n    in\n    Io.println msg\n"
    )
}

/// The deepest `n` whose `shape(n)` the parser admits, searched up to twice its ceiling.
fn parser_ceiling(shape: Shape) -> Option<usize> {
    (0..=2 * ceiling())
        .take_while(|n| {
            ipe_parse::parse_module(&shape(*n).src, &mut ipe_intern::Interner::new()).is_ok()
        })
        .last()
}

/// Compile the `Main` module `src` through emit on the compile door.
fn compile_on_compile_door(src: String) -> Result<(), CliError> {
    crate::threads::run_compile(move || compile_here(src))?
}

/// Compile the `Main` module `src` through emit on the calling thread.
fn compile_here(src: String) -> Result<(), CliError> {
    let main = vec!["Main".to_owned()];
    let blame = Path::new("Main.ipe");
    let mut sources: BTreeMap<Vec<String>, (PathBuf, String)> = BTreeMap::new();
    sources.insert(main.clone(), (blame.to_path_buf(), src));
    let mut discovered = Vec::new();
    let injected = crate::project::inject_compiled_std_closure(&mut sources, &mut discovered);
    let db = ipe_db::IpeDatabase::new();
    let root = create_source_root(&db, &sources, &injected, &BTreeSet::new());
    let options = BuildOptions {
        target: ipe_ir::Target::Native,
        intent: ipe_backend_rust::BuildIntent::Development,
        ..BuildOptions::default()
    };
    let settings = emit_settings(
        &SettingsSource::Loose,
        &options,
        crate::runtime_embed::BundleRole::Out,
    );
    let config = ipe_db::BuildConfig::new(&db, settings);
    compile_prepared(&db, root, &sources, &main, blame, config).map(|_| ())
}

/// The span of `result` when it is the parser's `NestingTooDeep` refusal.
fn parser_refusal_span(result: &Result<(), CliError>) -> Option<(u32, u32)> {
    let Err(CliError::Pipeline { diag, .. }) = result else {
        return None;
    };
    let Diagnostic::Parse {
        span,
        msg: ParseError::NestingTooDeep { .. },
        ..
    } = &**diag
    else {
        return None;
    };
    Some((span.lo, span.hi))
}

/// Assert `result` is the parser's `NestingTooDeep` refusal inside `tail`.
fn assert_refused_in(result: &Result<(), CliError>, (lo, hi): (u32, u32), name: &str) {
    let span = parser_refusal_span(result);
    assert!(
        span.is_some(),
        "{name}: one level past the ceiling must be refused by the parser, got {result:?}"
    );
    let Some((at_lo, at_hi)) = span else {
        return;
    };
    assert!(
        at_lo >= lo && at_hi <= hi,
        "{name}: the refusal at {at_lo}..{at_hi} lies in the innermost level {lo}..{hi}"
    );
}

/// Whether `result` is a type checker refusal.
fn is_type_refusal(result: &Result<(), CliError>) -> bool {
    matches!(result, Err(CliError::Pipeline { diag, .. }) if matches!(**diag, Diagnostic::Type { .. }))
}

/// Assert `result` is what `expected` says a shape at its ceiling yields.
fn assert_at_ceiling(result: &Result<(), CliError>, expected: AtCeiling, name: &str, n: usize) {
    match expected {
        AtCeiling::Builds => assert!(
            result.is_ok(),
            "{name}: depth {n} must compile through emit: {result:?}"
        ),
        AtCeiling::TypeRefused => assert!(
            is_type_refusal(result),
            "{name}: depth {n} must be refused by the type checker: {result:?}"
        ),
    }
}

/// Every nesting shape compiles at the parser's ceiling on the declared stack,
/// or is refused there by the type checker when the shape's types pass the
/// type ceiling first, and one level deeper is refused by the parser inside
/// its innermost level.
#[test]
fn at_ceiling_shapes_fit_declared_stack() {
    for (name, shape, deepest, expected) in shapes() {
        let found = parser_ceiling(shape);
        assert_eq!(
            found,
            Some(deepest),
            "{name}: the deepest count the parser admits"
        );
        let admitted = compile_on_compile_door(shape(deepest).src);
        assert_at_ceiling(&admitted, expected, name, deepest);
        let past = shape(deepest + 1);
        let refused = compile_on_compile_door(past.src);
        assert_refused_in(&refused, past.tail, name);
    }
}

/// Build the project whose `Main` module is `src` into `out`.
fn build_shape(src: &str, out: &Path, runtime: &Path) -> Result<(), CliError> {
    let fixture = crate::RootFixture::main(src)?;
    crate::build_fixture(&fixture, out, runtime).map(|_| ())
}

/// Emit `src` into `out` and build the emitted crate with cargo as `bin`.
fn assert_builds_with_cargo(src: &str, out: &Path, runtime: &Path, bin: &str) {
    let emitted = build_shape(src, out, runtime);
    assert!(emitted.is_ok(), "{bin}: must emit: {emitted:?}");
    let built = e2e_support::build_rust_binary(bin, out);
    assert!(
        built.is_ok(),
        "{bin}: the emitted crate must build with cargo: {}",
        built.err().unwrap_or_default()
    );
}

/// Every nesting shape's at-ceiling program builds with cargo (or, for a
/// shape whose types pass the type ceiling first, is refused by the type
/// checker), and one level deeper is refused at ipe time by the parser. Gated
/// on `IPE_E2E=1` (the CI `e2e` job): the seal cargo-builds each emitted crate.
#[test]
fn at_ceiling_shapes_build_with_cargo() {
    if e2e_support::e2e_tier() == e2e_support::Tier::E2e {
        let runtime = e2e_support::require_runtime().into_path_buf();
        let scratch =
            ipe_test_temp::temp_root().join(format!("ipe_nesting_ceiling_{}", std::process::id()));
        for (name, shape, deepest, expected) in shapes() {
            let out = scratch.join(name);
            let at = shape(deepest).src;
            match expected {
                AtCeiling::Builds => {
                    assert_builds_with_cargo(
                        &at,
                        &out,
                        &runtime,
                        &format!("nesting_ceiling_{name}"),
                    );
                }
                AtCeiling::TypeRefused => {
                    assert_at_ceiling(&build_shape(&at, &out, &runtime), expected, name, deepest);
                }
            }
            let past = shape(deepest + 1);
            let refused = build_shape(&past.src, &scratch.join(format!("{name}_past")), &runtime);
            assert_refused_in(&refused, past.tail, name);
        }
        let _ = std::fs::remove_dir_all(&scratch);
    }
}

/// The code of `result`'s pipeline diagnostic, if it is one.
fn refusal_code(result: &Result<(), CliError>) -> Option<ipe_diagnostics::Code> {
    match result {
        Err(CliError::Pipeline { diag, .. }) => Some(diag.code()),
        _ => None,
    }
}

/// An access chain over a record exactly as deep as the type ceiling admits
/// compiles through emit on the declared stack; over a record one level
/// deeper it is refused by the type checker with IPE-T0022.
#[test]
fn access_chain_at_the_type_ceiling_compiles_and_one_level_deeper_is_refused() {
    let limit = usize::from(TYPE_DEPTH_LIMIT);
    let admitted = compile_on_compile_door(access_chain(limit).src);
    assert!(
        admitted.is_ok(),
        "a record {limit} levels deep must compile through emit: {admitted:?}"
    );
    let refused = compile_on_compile_door(access_chain(limit + 1).src);
    assert_eq!(
        refusal_code(&refused),
        Some(IPE_T0022),
        "a record one level past the type ceiling: {refused:?}"
    );
}

/// The access chain at the type ceiling builds with cargo. Gated on
/// `IPE_E2E=1` (the CI `e2e` job).
#[test]
fn access_chain_at_the_type_ceiling_builds_with_cargo() {
    if e2e_support::e2e_tier() == e2e_support::Tier::E2e {
        let runtime = e2e_support::require_runtime().into_path_buf();
        let out = ipe_test_temp::temp_root()
            .join(format!("ipe_type_ceiling_access_{}", std::process::id()));
        let src = access_chain(usize::from(TYPE_DEPTH_LIMIT)).src;
        assert_builds_with_cargo(&src, &out, &runtime, "type_ceiling_access_chain");
        let _ = std::fs::remove_dir_all(&out);
    }
}

/// The interpolations of [`interpolation_past_the_source_ceiling_compiles`],
/// sixteen times the source ceiling.
const INTERPOLATION_CHUNKS: usize = 4096;

/// An interpolation of far more chunks than the source ceiling counts compiles
/// through emit on the declared stack: its chunks join in a balanced tree, as
/// deep as the logarithm of their count.
#[test]
fn interpolation_past_the_source_ceiling_compiles() {
    let admitted = compile_on_compile_door(interpolation(INTERPOLATION_CHUNKS));
    assert!(
        admitted.is_ok(),
        "{INTERPOLATION_CHUNKS} interpolations must compile through emit: {admitted:?}"
    );
}
