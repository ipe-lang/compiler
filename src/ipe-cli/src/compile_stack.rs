//! The declared compile stack holds every shape the parser admits.
//!
//! The nesting a body reaches every later stage is bounded by the parser's
//! ceiling, but the frames each level costs are not provable statically. Each
//! shape that builds deep nesting is compiled through emit, at the deepest
//! depth the parser admits, on the one compile door the commands use
//! ([`crate::threads::run_compile`], a thread of exactly
//! [`crate::threads::COMPILE_STACK_BYTES`]); one level deeper is refused by the
//! parser with `NestingTooDeep`, never by a later stage or a stack overflow.

#![cfg(test)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use ipe_diagnostics::nesting::SOURCE_NESTING_LIMIT;
use ipe_diagnostics::{Diagnostic, ParseError};

use crate::CliError;
use crate::driver::{
    BuildOptions, SettingsSource, compile_prepared, create_source_root, emit_settings,
};

/// The imports every shape's module opens with.
const HEADER: &str = "module Main exposing (main)\n\n\
                      import Ipe.Io as Io\n\
                      import Ipe.String as String\n\
                      import Ipe.Task as Task\n\n\n";

/// The ceiling as a count.
fn ceiling() -> usize {
    usize::try_from(SOURCE_NESTING_LIMIT).unwrap_or(usize::MAX)
}

/// A `do` block of `n` binds.
fn do_binds(n: usize) -> String {
    let mut src = format!("{HEADER}main =\n    do\n");
    for _ in 0..n {
        src.push_str("        _ <- Io.println \"s\"\n");
    }
    src.push_str("        Io.println \"e\"\n");
    src
}

/// A `let` block of `n` bindings, each reading the one before it.
fn let_block(n: usize) -> String {
    let bindings: String = (1..=n)
        .map(|i| format!("        x{i} = x{} + 1\n", i - 1))
        .collect();
    format!(
        "{HEADER}main =\n    let\n        x0 = 0\n{bindings}    in\n    Io.println (String.fromInt x{n})\n"
    )
}

/// A chain of `n` `+` operators.
fn binop_chain(n: usize) -> String {
    let terms = vec!["1"; n + 1].join(" + ");
    format!("{HEADER}main =\n    Io.println (String.fromInt ({terms}))\n")
}

/// A pipeline of `n` `Task.andThen` continuations.
fn pipeline(n: usize) -> String {
    let mut body = String::from("Io.println \"s\"");
    for _ in 0..n {
        body.push_str(" |> Task.andThen (\\_ -> Io.println \"s\")");
    }
    format!("{HEADER}main =\n    {body}\n")
}

/// `n` continuation lambdas, each nested inside the last.
fn nested_lambda(n: usize) -> String {
    let mut body = String::from("Io.println \"end\"");
    for _ in 0..n {
        body = format!("Io.println \"s\" |> Task.andThen (\\_ -> {body})");
    }
    format!("{HEADER}main =\n    {body}\n")
}

/// A multiline string of `n` interpolations.
fn interpolation(n: usize) -> String {
    let chunks = "{{tag}}".repeat(n);
    format!(
        "{HEADER}main =\n    let\n        tag = \"o\"\n        msg =\n            \"\"\"\n            \
         {chunks}\n            \"\"\"\n    in\n    Io.println msg\n"
    )
}

/// The deepest `n` whose `source(n)` the parser admits, searched up to twice its ceiling.
fn parser_ceiling(source: fn(usize) -> String) -> Option<usize> {
    (0..=2 * ceiling())
        .take_while(|n| {
            ipe_parse::parse_module(&source(*n), &mut ipe_intern::Interner::new()).is_ok()
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

/// Whether `result` is the parser's `NestingTooDeep` refusal.
fn refused_by_parser(result: &Result<(), CliError>) -> bool {
    matches!(
        result,
        Err(CliError::Pipeline { diag, .. })
            if matches!(
                **diag,
                Diagnostic::Parse {
                    msg: ParseError::NestingTooDeep { .. },
                    ..
                }
            )
    )
}

/// Every nesting shape compiles at the parser's ceiling on the declared stack,
/// and one level deeper is refused by the parser.
#[test]
fn at_ceiling_shapes_fit_declared_stack() {
    type Shape = fn(usize) -> String;
    let shapes: [(&str, Shape); 5] = [
        ("do-bind", do_binds),
        ("let-block", let_block),
        ("binop chain", binop_chain),
        ("pipeline", pipeline),
        ("nested lambda", nested_lambda),
    ];
    for (name, source) in shapes {
        let found = parser_ceiling(source);
        assert!(
            found.is_some_and(|n| n > 0 && n < 2 * ceiling()),
            "{name}: the parser must admit some depth and refuse a deeper one: {found:?}"
        );
        let Some(deepest) = found else {
            continue;
        };
        let admitted = compile_on_compile_door(source(deepest));
        assert!(
            admitted.is_ok(),
            "{name}: depth {deepest} must compile through emit: {admitted:?}"
        );
        let refused = compile_on_compile_door(source(deepest + 1));
        assert!(
            refused_by_parser(&refused),
            "{name}: depth {} must be refused by the parser, got {refused:?}",
            deepest + 1
        );
    }
}

/// An interpolation of as many chunks as the ceiling counts compiles through
/// emit on the declared stack.
#[test]
fn ceiling_count_interpolation_fits_declared_stack() {
    let admitted = compile_on_compile_door(interpolation(ceiling()));
    assert!(
        admitted.is_ok(),
        "{} interpolations must compile through emit: {admitted:?}",
        ceiling()
    );
}
