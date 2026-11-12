//! Every source nesting shape, generated at any depth, with the deepest count
//! the parser admits.
//!
//! The native compile-stack tests (the `ipe` crate's `compile_stack`) and the
//! in-browser ones (`ipe-wasm`'s `nesting_ceiling`) compile the same table, so
//! a shape added for one stack is proved on both. Each shape renders a whole
//! `Main` module and records where the parser's refusal one level past its
//! ceiling must sit.
//!
//! A body's expression opens at depth 0; an application adds one frame, its
//! head or argument a postfix and an atom frame, a construct the atom opens one
//! more, and that construct's inner expression one more, so a nesting construct
//! costs five levels.

use std::fmt::Write as _;

use ipe_diagnostics::nesting::{
    COMPOSE_NESTING, LAMBDA_CHAIN_TYPE_DEPTH_AT_SOURCE_CEILING, SOURCE_NESTING_LIMIT,
    TYPE_DEPTH_LIMIT,
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

/// A shape's source and where its refusal one level past the ceiling must sit.
///
/// The refusal ends in `tail`: the innermost nesting level, or a sequence's
/// last element through the end. For a sequence it starts exactly at `start`,
/// the sequence's first byte; otherwise it lies wholly in `tail`.
pub struct Shaped {
    /// The module source.
    pub src: String,
    /// The byte range the refusal one level past the ceiling must end in.
    pub tail: (u32, u32),
    /// The byte the refusal must start at, for a sequence shape.
    pub start: Option<u32>,
}

impl Shaped {
    /// This shape, refused as the sequence that begins at byte `at`.
    fn starting_at(self, at: usize) -> Self {
        Self {
            start: Some(offset(at)),
            ..self
        }
    }
}

/// A source generator of one nesting shape, by depth.
pub type Shape = fn(usize) -> Shaped;

/// What compiling a shape at its source ceiling yields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AtCeiling {
    /// The program compiles through emit and builds with cargo.
    Builds,
    /// The type checker refuses the program, after every earlier stage ran
    /// on the declared stack.
    TypeRefused,
}

/// The ceiling as a count.
#[must_use]
pub fn ceiling() -> usize {
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
        start: None,
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
    Shaped {
        src,
        tail,
        start: None,
    }
}

/// The indentation of a `do` or `let` block's statements under `main`.
const BLOCK_INDENT: usize = 8;

/// A `do` block of `n` binds, refused from its first statement.
fn do_binds(n: usize) -> Shaped {
    let before = "main =\n    do\n";
    sequence(
        n,
        before,
        |_| "        _ <- Io.println \"s\"\n".to_owned(),
        "        Io.println \"e\"\n",
    )
    .starting_at(HEADER.len() + before.len() + BLOCK_INDENT)
}

/// A `let` block of `n` bindings after `x0`, each reading the one before it,
/// refused from `x0`.
fn let_block(n: usize) -> Shaped {
    let before = "main =\n    let\n";
    let body = format!("    in\n    Io.println (String.fromInt x{n})\n");
    sequence(
        n,
        &format!("{before}        x0 = 0\n"),
        |i| format!("        x{} = x{i} + 1\n", i + 1),
        &body,
    )
    .starting_at(HEADER.len() + before.len() + BLOCK_INDENT)
}

/// A chain of `n` `+` operators, refused from its first operand.
fn binop_chain(n: usize) -> Shaped {
    let before = "main =\n    Io.println (String.fromInt (1";
    sequence(n, before, |_| " + 1".to_owned(), "))\n")
        .starting_at(HEADER.len() + before.len() - "1".len())
}

/// A composition of `n + 1` `inc`s by `>>`, applied to `1`, refused from the
/// first `inc`.
fn compose_chain(n: usize) -> Shaped {
    let before = "main =\n    Io.println (String.fromInt ((inc";
    sequence(
        n,
        before,
        |_| " >> inc".to_owned(),
        ") 1))\n\n\ninc : Int -> Int\ninc x =\n    x + 1\n",
    )
    .starting_at(HEADER.len() + before.len() - "inc".len())
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
#[must_use]
pub fn access_chain(n: usize) -> Shaped {
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
/// nested `depth` deep, refused from `r`.
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
    let before = "main =\n    Io.println (String.fromInt r";
    sequence(n, before, |_| ".a".to_owned(), &after)
        .starting_at(HEADER.len() + before.len() - "r".len())
}

/// A `do` of `n` named binds inside a `Task` lambda over a handle, every
/// bind read by the final statement, refused from the first bind.
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
    let before = "main =\n    withHandle\n        (\\h ->\n            do\n";
    let indent = "                ";
    sequence(
        n,
        before,
        |i| format!("{indent}x{} <- Task.succeed h\n", i + 1),
        &after,
    )
    .starting_at(HEADER.len() + before.len() + indent.len())
}

/// The parentheses around the first operand of [`deep_operand_chain`].
const OPERAND_PARENS: usize = 8;

/// A chain of `n` `+` operators whose first operand is `1` inside
/// [`OPERAND_PARENS`] parentheses, refused from that operand's first `(`.
fn deep_operand_chain(n: usize) -> Shaped {
    let group = "main =\n    Io.println (String.fromInt (";
    let before = format!(
        "{group}{}1{}",
        "(".repeat(OPERAND_PARENS),
        ")".repeat(OPERAND_PARENS)
    );
    sequence(n, &before, |_| " + 1".to_owned(), "))\n").starting_at(HEADER.len() + group.len())
}

/// A pipeline of `n` `Task.andThen` continuations, refused from its first
/// operand.
fn pipeline(n: usize) -> Shaped {
    let body = "main =\n    ";
    sequence(
        n,
        &format!("{body}Io.println \"s\""),
        |_| " |> Task.andThen (\\_ -> Io.println \"s\")".to_owned(),
        "\n",
    )
    .starting_at(HEADER.len() + body.len())
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
    Shaped {
        src,
        tail,
        start: None,
    }
}

/// `n` nested `if` expressions, each in the last one's `then` branch.
fn nested_if(n: usize) -> Shaped {
    let before = format!("{DEEP_HEAD}    ");
    nested(n, &before, "if x > 0 then ", "x", " else 0", "\n")
}

/// An `if` with `n` `else if` arms, refused from the `if`.
fn else_if_chain(n: usize) -> Shaped {
    let body = format!("{DEEP_HEAD}    ");
    let before = format!("{body}if x > 0 then 1");
    sequence(
        n,
        &before,
        |_| " else if x > 1 then 1".to_owned(),
        " else 0\n",
    )
    .starting_at(HEADER.len() + body.len())
}

/// `n` nested records `{ a = { a = … } }`, read back through `n` accesses.
///
/// The records are the `let` block's binding, so the refusal spans the block
/// from that binding's name.
fn nested_record(n: usize) -> Shaped {
    let block = "main =\n    let\n";
    let after = format!(
        "\n    in\n    Io.println (String.fromInt r{})\n",
        ".a".repeat(n)
    );
    nested(
        n,
        &format!("{block}        r =\n            "),
        "{ a = ",
        "1",
        " }",
        &after,
    )
    .starting_at(HEADER.len() + block.len() + BLOCK_INDENT)
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
#[must_use]
pub fn shapes() -> [(&'static str, Shape, usize, AtCeiling); 17] {
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
#[must_use]
pub fn interpolation(n: usize) -> String {
    let chunks = "{{tag}}".repeat(n);
    format!(
        "{HEADER}main =\n    let\n        tag = \"o\"\n        msg =\n            \"\"\"\n            \
         {chunks}\n            \"\"\"\n    in\n    Io.println msg\n"
    )
}
