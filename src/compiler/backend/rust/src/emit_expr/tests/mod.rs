// Cmd-wiring emit composition is exercised end to end in
// [`crate::emit_web`]'s `hot_appearance_tests` (a `Cmd.perform` arm composes the
// `fire_cmd_wiring` dispatch; a `Cmd.none` arm and the flag-off case do not) and
// the wiring VOCABULARY in [`crate::transition_classify`]'s `tests`, so no
// standalone emit test lives here.

use super::{BoxedSub, DResult, IrType, ModPath, Pat};
use ipe_diagnostics::Diagnostic;
use ipe_intern::Interner;
use ipe_ir::{SharedAlts, SliceOwnership};

#[test]
fn every_pattern_shape_has_one_boxed_field_class() -> DResult<()> {
    let mut interner = Interner::new();
    let x = interner.intern("x")?;
    let node = interner.intern("Node")?;
    let left = interner.intern("left")?;
    let var = Pat::Var(x);
    let pair = Pat::Tuple(vec![Pat::Var(x), Pat::Wildcard]);
    let record = Pat::Record(vec![(left, Pat::Var(x))]);
    let alias = Pat::Alias(Box::new(Pat::Wildcard), x);
    let blank_pair = Pat::Tuple(vec![Pat::Wildcard, Pat::Wildcard]);
    assert_eq!(BoxedSub::of(&Pat::Wildcard), BoxedSub::Ignore);
    assert_eq!(BoxedSub::of(&blank_pair), BoxedSub::Ignore);
    assert_eq!(BoxedSub::of(&var), BoxedSub::Bind(x));
    assert_eq!(BoxedSub::of(&pair), BoxedSub::Destructure(&pair));
    assert_eq!(BoxedSub::of(&record), BoxedSub::Destructure(&record));
    assert_eq!(BoxedSub::of(&alias), BoxedSub::Destructure(&alias));
    let literal_alts =
        SharedAlts::new(vec![Pat::Int(0), Pat::Int(1)]).ok_or_else(|| Diagnostic::CompilerBug {
            where_: "emit_expr::tests",
            detail: "two Int alternatives are a valid SharedAlts".to_owned(),
        })?;
    let dispatching = [
        Pat::Ctor {
            home: ModPath(Vec::new()),
            ty: node,
            variant: node,
            args: Vec::new(),
        },
        Pat::Slice {
            prefix: Vec::new(),
            rest: None,
            own: SliceOwnership::BorrowClone,
            elem: IrType::Int,
        },
        Pat::Int(0),
        Pat::Bool(true),
        Pat::Char("c".to_owned()),
        Pat::Str("s".to_owned()),
        Pat::Or(literal_alts),
    ];
    for pat in &dispatching {
        assert_eq!(BoxedSub::of(pat), BoxedSub::Dispatch, "{pat:?}");
    }
    Ok(())
}

#[test]
fn a_test_nested_in_a_boxed_destructure_dispatches() -> DResult<()> {
    let mut interner = Interner::new();
    let x = interner.intern("x")?;
    let whole = interner.intern("whole")?;
    let done = interner.intern("Done")?;
    let left = interner.intern("left")?;
    let nested_ctor = Pat::Tuple(vec![
        Pat::Ctor {
            home: ModPath(Vec::new()),
            ty: done,
            variant: done,
            args: Vec::new(),
        },
        Pat::Var(x),
    ]);
    let nested_literal = Pat::Tuple(vec![Pat::Var(x), Pat::Int(0)]);
    let alias_over_literal = Pat::Alias(Box::new(Pat::Int(0)), whole);
    let record_with_alias = Pat::Record(vec![(left, Pat::Alias(Box::new(Pat::Wildcard), whole))]);
    for pat in [
        &nested_ctor,
        &nested_literal,
        &alias_over_literal,
        &record_with_alias,
    ] {
        assert_eq!(BoxedSub::of(pat), BoxedSub::Dispatch, "{pat:?}");
    }
    let alias_over_pair = Pat::Alias(
        Box::new(Pat::Tuple(vec![Pat::Var(x), Pat::Wildcard])),
        whole,
    );
    assert_eq!(
        BoxedSub::of(&alias_over_pair),
        BoxedSub::Destructure(&alias_over_pair)
    );
    Ok(())
}
