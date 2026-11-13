//! The declared compile stack holds every shape the parser admits.
//!
//! The nesting a body reaches every later stage is bounded by the parser's
//! ceiling, but the frames each level costs are not provable statically. Each
//! shape that builds deep nesting is compiled through emit, at the deepest
//! depth the parser admits, on the one compile door the commands use
//! ([`crate::threads::run_compile`], a thread of exactly
//! [`crate::threads::COMPILE_STACK_BYTES`]); one level deeper is refused by the
//! parser with `NestingTooDeep` at its innermost level, never by a later stage
//! or a stack overflow. A shape built as a sequence (a statement run, an
//! operator chain, an `else if` chain) is refused spanning that whole sequence,
//! from its first statement, operand or `if` to the token that crossed. Under `IPE_E2E=1` the at-ceiling program of each
//! shape is also built with cargo.
//!
//! A source ceiling and a type ceiling bound different things: an access chain
//! as long as the source ceiling admits reads through more record levels than
//! the type ceiling lets one record have, so at its source ceiling it is
//! refused by the type checker, and its type ceiling is pinned on its own.
//!
//! The deepest count of each shape is pinned in the `nesting_shapes` table,
//! which the in-browser compiler's own ceiling test compiles too.

#![cfg(test)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use ipe_diagnostics::nesting::TYPE_DEPTH_LIMIT;
use ipe_diagnostics::{Diagnostic, IPE_T0022, ParseError};
use nesting_shapes::{AtCeiling, Shape, access_chain, ceiling, interpolation, shapes};

use crate::CliError;
use crate::driver::{
    BuildOptions, SettingsSource, compile_prepared, create_source_root, emit_settings,
};

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

/// Assert `result` is the parser's `NestingTooDeep` refusal where `tail` and
/// `start` place it (see [`nesting_shapes::Shaped`]).
fn assert_refused_in(
    result: &Result<(), CliError>,
    (lo, hi): (u32, u32),
    start: Option<u32>,
    name: &str,
) {
    let span = parser_refusal_span(result);
    assert!(
        span.is_some(),
        "{name}: one level past the ceiling must be refused by the parser, got {result:?}"
    );
    let Some((at_lo, at_hi)) = span else {
        return;
    };
    assert!(
        at_hi > lo && at_hi <= hi,
        "{name}: the refusal at {at_lo}..{at_hi} ends in the innermost level {lo}..{hi}"
    );
    assert_eq!(
        at_lo,
        start.unwrap_or_else(|| at_lo.max(lo)),
        "{name}: the refusal at {at_lo}..{at_hi} starts where its sequence does"
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
/// type ceiling first, and one level deeper is refused by the parser at its
/// innermost level, spanning the whole sequence for a sequence shape.
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
        assert_refused_in(&refused, past.tail, past.start, name);
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
            assert_refused_in(&refused, past.tail, past.start, name);
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
