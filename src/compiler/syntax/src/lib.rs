#![forbid(unsafe_code)]
//! Source AST for the Ipê compiler. This is the raw parse tree the parser
//! produces and name resolution (`ipe_canon`) consumes, covering the
//! supported subset of the surface language.

mod ast;

pub use ast::{
    Ctor, DocString, Exposed, Exposing, Expr, Expr_, ForeignDecl, Import, LetBinding, Module,
    Pattern, Pattern_, Privacy, TypeAlias, TypeAnnotation, Union, Value, strip_anchor_margin,
};

#[cfg(test)]
mod tests {
    use super::*;
    use ipe_diagnostics::{DResult, Located, Span};
    use ipe_intern::{Interner, Symbol};

    fn sp() -> Span {
        Span::DUMMY
    }

    fn loc<T>(v: T) -> Located<T> {
        Located::new(sp(), v)
    }

    /// Build, by hand, the Source AST the parser is expected to produce for
    /// `tests/golden/basics/Main.ipe`. Returns the module plus the interner so the
    /// caller can resolve symbols if needed.
    fn golden_module(i: &mut Interner) -> DResult<Module> {
        let main = i.intern("main")?;
        let msg_ty = i.intern("Msg")?;
        let int_ty = i.intern("Int")?;
        let increment = i.intern("Increment")?;
        let decrement = i.intern("Decrement")?;
        let update = i.intern("update")?;
        let msg_arg = i.intern("msg")?;
        let count = i.intern("count")?;
        let plus = i.intern("+")?;
        let minus = i.intern("-")?;
        let println = i.intern("println")?;
        let string_mod = i.intern("String")?;
        let from_int = i.intern("fromInt")?;
        let empty = i.intern("")?;

        // type Msg = Increment | Decrement
        let union = Union {
            type_kw: sp(),
            name: loc(msg_ty),
            vars: Vec::new(),
            ctors: vec![
                loc(Ctor {
                    name: increment,
                    args: Vec::new(),
                }),
                loc(Ctor {
                    name: decrement,
                    args: Vec::new(),
                }),
            ],
            doc: None,
        };

        // update : Msg -> Int -> Int
        let ty = TypeAnnotation::TLambda(
            Box::new(TypeAnnotation::TType(empty, vec![msg_ty], Vec::new())),
            Box::new(TypeAnnotation::TLambda(
                Box::new(TypeAnnotation::TType(empty, vec![int_ty], Vec::new())),
                Box::new(TypeAnnotation::TType(empty, vec![int_ty], Vec::new())),
            )),
        );

        // case msg of Increment -> count + 1 ; Decrement -> count - 1
        let arm_inc = (
            loc(Pattern_::PCtor(increment, Vec::new(), Vec::new())),
            loc(Expr_::Binops(
                vec![(loc(Expr_::VarLocal(count)), loc(plus))],
                Box::new(loc(Expr_::Int(1))),
            )),
        );
        let arm_dec = (
            loc(Pattern_::PCtor(decrement, Vec::new(), Vec::new())),
            loc(Expr_::Binops(
                vec![(loc(Expr_::VarLocal(count)), loc(minus))],
                Box::new(loc(Expr_::Int(1))),
            )),
        );
        let update_body = loc(Expr_::Case(
            Box::new(loc(Expr_::VarLocal(msg_arg))),
            vec![arm_inc, arm_dec],
        ));
        let update_value = Value {
            name: loc(update),
            patterns: vec![loc(Pattern_::PVar(msg_arg)), loc(Pattern_::PVar(count))],
            body: update_body,
            type_annotation: Some(loc(ty)),
            doc: None,
        };

        // main = Io.println (String.fromInt (update Increment 0))
        let inner_call = loc(Expr_::Call(
            Box::new(loc(Expr_::VarLocal(update))),
            vec![loc(Expr_::VarLocal(increment)), loc(Expr_::Int(0))],
        ));
        let from_int_call = loc(Expr_::Call(
            Box::new(loc(Expr_::VarQual(string_mod, from_int))),
            vec![inner_call],
        ));
        let main_body = loc(Expr_::Call(
            Box::new(loc(Expr_::VarLocal(println))),
            vec![from_int_call],
        ));
        let main_value = Value {
            name: loc(main),
            patterns: Vec::new(),
            body: main_body,
            type_annotation: None,
            doc: None,
        };

        let main_mod = i.intern("Main")?;
        let ipe = i.intern("Ipe")?;
        let core = i.intern("Core")?;
        let prelude = i.intern("Prelude")?;
        Ok(Module {
            module_kw: sp(),
            name: loc(vec![main_mod]),
            exposing: loc(Exposing::List(vec![loc(Exposed::Value(main))])),
            imports: vec![Import {
                span: sp(),
                import_kw: sp(),
                name: loc(vec![ipe, core, prelude]),
                alias: None,
                exposing: loc(Exposing::All),
            }],
            values: vec![loc(update_value), loc(main_value)],
            unions: vec![loc(union)],
            aliases: Vec::new(),
            foreigns: Vec::new(),
        })
    }

    #[test]
    fn golden_ast_constructs_and_field_access_compiles() -> DResult<()> {
        let mut i = Interner::new();
        let m = golden_module(&mut i)?;

        // Module-level field access compiles.
        assert_eq!(m.imports.len(), 1);
        assert_eq!(m.unions.len(), 1);
        assert_eq!(m.values.len(), 2);

        // Drill into the union (iterate to avoid fallible indexing).
        let msg_ty = i.intern("Msg")?;
        for u in &m.unions {
            assert_eq!(u.value.ctors.len(), 2);
            assert_eq!(u.value.name.value, msg_ty);
        }

        // Inspect each value: `update` carries a type annotation + two
        // patterns + a `case` body; `main` carries none + a `Call` body.
        let update_sym = i.intern("update")?;
        let main_sym = i.intern("main")?;
        let mut saw_update = false;
        let mut saw_main = false;
        for v in &m.values {
            let val = &v.value;
            if val.name.value == update_sym {
                saw_update = true;
                assert!(val.type_annotation.is_some());
                assert_eq!(val.patterns.len(), 2);
                assert!(matches!(val.body.value, Expr_::Case(_, _)));
            } else if val.name.value == main_sym {
                saw_main = true;
                assert!(val.type_annotation.is_none());
                assert!(val.patterns.is_empty());
                assert!(matches!(val.body.value, Expr_::Call(_, _)));
            }
        }
        assert!(saw_update && saw_main);
        Ok(())
    }

    #[test]
    fn ast_partial_eq_round_trips() -> DResult<()> {
        let mut i = Interner::new();
        let a = golden_module(&mut i)?;
        let b = a.clone();
        assert_eq!(a, b);

        // A targeted, observable difference must compare unequal.
        let mut c = a.clone();
        c.imports.clear();
        assert_ne!(a, c);
        Ok(())
    }

    #[test]
    fn unused_variants_construct_and_compare() -> DResult<()> {
        // PAnything, TVar are not in the golden program; exercise them so the
        // whole enum surface is covered by PartialEq.
        let anything: Pattern_ = Pattern_::PAnything;
        assert_eq!(anything, Pattern_::PAnything);

        let mut i = Interner::new();
        let a: Symbol = i.intern("a")?;
        assert_eq!(TypeAnnotation::TVar(a), TypeAnnotation::TVar(a));
        let b = i.intern("b")?;
        assert_ne!(TypeAnnotation::TVar(a), TypeAnnotation::TVar(b));
        Ok(())
    }
}
