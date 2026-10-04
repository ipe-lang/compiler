use super::{
    BTreeMap, Builder, DResult, Diagnostic, FieldAccess, FlatType, STAGE, Span, Symbol, TypeError,
    VarId, canon,
};

impl Builder<'_> {
    /// Constrain a `case` arm pattern against the scrutinee's variable, binding
    /// any pattern variables into `local`.
    #[allow(clippy::too_many_lines)]
    pub fn constrain_pattern(
        &mut self,
        local: &mut BTreeMap<Symbol, VarId>,
        pat: &canon::Pattern,
        scrut_var: VarId,
    ) -> DResult<()> {
        match &pat.value {
            // `_` and the dev-only `Debug._` both match any value and bind
            // nothing, so neither constrains the scrutinee's type.
            canon::Pattern_::PAnything | canon::Pattern_::PDebugAnything => Ok(()),
            // The unit pattern `()` pins the scrutinee to the unit type and binds
            // nothing — the pattern-position counterpart of the unit expression.
            canon::Pattern_::PUnit => {
                let unit = self.structure(FlatType::Unit)?;
                self.eq(pat.span, unit, scrut_var)?;
                Ok(())
            }
            canon::Pattern_::PVar(s) => {
                local.insert(*s, scrut_var);
                Ok(())
            }
            canon::Pattern_::PCtor {
                home,
                type_name,
                name,
                args,
                ..
            } => {
                // Look up by the canon-resolved `(home, type_name, name)`
                // identity, not the bare name: a same-named constructor in a
                // different module (or type) is a DIFFERENT entry, so this
                // module's own pattern checks against its own declared arity.
                let key = (home.clone(), *type_name, *name);
                if let Some(scheme) = self.ctors.get(&key).cloned() {
                    // A constructor pattern binds exactly its declared fields. A
                    // mismatch (`Just` with no payload, `Node l r` for a three-field
                    // `Node`) is a user error, surfaced as IPE-T0013 rather than
                    // silently constraining a prefix.
                    if args.len() != scheme.arg_tys.len() {
                        return Err(self.ctor_pattern_arity(
                            pat.span,
                            *name,
                            scheme.arg_tys.len(),
                            args.len(),
                        ));
                    }
                    // Instantiate the scheme fresh, tie the result to the
                    // scrutinee, and constrain each payload sub-pattern against its
                    // field's (now use-site) type. Recursing handles a nested
                    // sub-pattern's typing too; the lowerer is what restricts
                    // payloads to variables / wildcards.
                    let (arg_vars, result_var) = self.instantiate_ctor(&scheme)?;
                    self.eq(pat.span, result_var, scrut_var)?;
                    for (sub, av) in args.iter().zip(arg_vars) {
                        self.constrain_pattern(local, sub, av)?;
                        // Record this sub-pattern's own instantiated field type so
                        // the lowerer can recover a NESTED record / list sub-pattern's
                        // complete shape the same way a top-level `case` / `let` binder
                        // already does (identical precedent in `constrain_lambda`, the
                        // `regions.insert` on every lambda-parameter span below).
                        // Class 4 item C —
                        // docs/adr/0002-codegen-soundness-and-the-seal.md.
                        self.regions
                            .insert((self.home()?.into_path(), sub.span), av);
                    }
                } else {
                    // A constructor with no registered scheme (imported, outside the
                    // single-module subset): fall back to the bare enum type.
                    // We still must recurse into every argument sub-pattern so that
                    // pattern variables (e.g. `Chunk text` where `Chunk` is an
                    // imported ctor) get bound into `local`.  Without the recursion
                    // the body sees `VarLocal("text")` that is absent from the local
                    // map and fires the "unbound local" ICE.  Use a fresh flex
                    // variable per arg since the field types are unknown.
                    let ctor = self.con_var(home.clone(), *type_name, Vec::new())?;
                    self.eq(pat.span, ctor, scrut_var)?;
                    for sub in args {
                        let av = self.flex()?;
                        self.constrain_pattern(local, sub, av)?;
                    }
                }
                Ok(())
            }
            canon::Pattern_::PTuple(elems) => {
                // A tuple pattern matches a Tuple type element-wise: mint one
                // fresh variable per element, tie the scrutinee to the product
                // over them, and constrain each sub-pattern against its element's
                // variable. Nested sub-patterns recurse; the lowerer restricts
                // which element shapes it can actually emit.
                let mut elem_vars = Vec::with_capacity(elems.len());
                for _ in elems {
                    elem_vars.push(self.flex()?);
                }
                let tuple = self.structure(FlatType::Tuple(elem_vars.clone()))?;
                self.eq(pat.span, tuple, scrut_var)?;
                for (sub, ev) in elems.iter().zip(elem_vars) {
                    self.constrain_pattern(local, sub, ev)?;
                    // Same region-threading as the `PCtor` arm above so a record
                    // (or list) nested inside a TUPLE element (`(Ok {name}, y)`)
                    // recovers its complete shape in the lowerer. Class 4 item C.
                    self.regions
                        .insert((self.home()?.into_path(), sub.span), ev);
                }
                Ok(())
            }
            canon::Pattern_::PRecord(fields) => {
                // A field-pun record pattern `{ x, y }` binds each named field of
                // the scrutinee record. Closed records carry no row variable, so
                // the scrutinee's full field set may not be settled here; instead
                // of forcing an exact-shape unification (which would reject the
                // legal subset pattern `{ x }` on a `{ x, y }` record), each
                // field is pulled out with the SAME deferred field-access channel
                // a `record.field` expression uses. After the main solve,
                // `resolve_field_accesses` links each binder to the field's type.
                for f in fields {
                    let result = self.flex()?;
                    self.field_accesses.push(FieldAccess {
                        record: scrut_var,
                        field: f.value,
                        result,
                        span: f.span,
                        home: self.home()?,
                    });
                    local.insert(f.value, result);
                }
                Ok(())
            }
            // A literal pattern pins the scrutinee to the literal's type. It
            // binds no names. A mismatch (`case n of "x" -> …` with `n : Int`)
            // surfaces as the ordinary IPE-T0001 type mismatch.
            canon::Pattern_::PInt(_) => {
                let lit = self.int_var()?;
                self.eq(pat.span, lit, scrut_var)?;
                Ok(())
            }
            canon::Pattern_::PBool(_) => {
                let lit = self.bool_var()?;
                self.eq(pat.span, lit, scrut_var)?;
                Ok(())
            }
            canon::Pattern_::PChar(_) => {
                let lit = self.char_var()?;
                self.eq(pat.span, lit, scrut_var)?;
                Ok(())
            }
            canon::Pattern_::PStr(_) => {
                let lit = self.string_var()?;
                self.eq(pat.span, lit, scrut_var)?;
                Ok(())
            }
            // An alias `inner as name` binds `name` to the whole scrutinee and
            // additionally constrains the inner pattern against it.
            canon::Pattern_::PAlias(inner, name) => {
                local.insert(name.value, scrut_var);
                self.constrain_pattern(local, inner, scrut_var)
            }
            // A list pattern `[a, b]` matches a `List elem`: each element
            // sub-pattern is constrained against one shared element variable, and
            // the scrutinee is tied to the list over it.
            canon::Pattern_::PList(elems) => {
                let elem = self.flex()?;
                let list = self.list_var(elem)?;
                self.eq(pat.span, list, scrut_var)?;
                for sub in elems {
                    self.constrain_pattern(local, sub, elem)?;
                }
                Ok(())
            }
            // A cons pattern `head :: tail` matches a `List elem`: `head : elem`,
            // `tail : List elem` (the scrutinee's own type), scrutinee `List elem`.
            canon::Pattern_::PCons(head, tail) => {
                let elem = self.flex()?;
                let list = self.list_var(elem)?;
                self.eq(pat.span, list, scrut_var)?;
                self.constrain_pattern(local, head, elem)?;
                self.constrain_pattern(local, tail, list)
            }
            // An or-pattern `p1 | p2 | …`: every alternative is constrained
            // against the SAME scrutinee variable, and its binders are unified
            // name-by-name with the first alternative's, so the arm body reads
            // one binder environment. Canon already proved the alternatives bind
            // the identical name set (IPE-T0019); unifying each shared name's
            // var here is the same-type half of the rule — a failure surfaces as
            // the ordinary IPE-T0001 mismatch attributed to the alternative. The
            // body is constrained ONCE afterwards, in `local`, never per
            // alternative.
            canon::Pattern_::POr(alts) => {
                let Some((first, rest)) = alts.split_first() else {
                    return Err(Diagnostic::CompilerBug {
                        where_: STAGE,
                        detail: "an or-pattern reached type inference with no alternatives"
                            .to_owned(),
                    });
                };
                // The first alternative binds directly into the shared `local`.
                self.constrain_pattern(local, first, scrut_var)?;
                for alt in rest {
                    let mut alt_local: BTreeMap<Symbol, VarId> = BTreeMap::new();
                    self.constrain_pattern(&mut alt_local, alt, scrut_var)?;
                    // Unify each of this alternative's binders with the reference
                    // binder of the same name established by the first alternative.
                    for (name, var) in alt_local {
                        if let Some(reference) = local.get(&name).copied() {
                            self.eq(alt.span, reference, var)?;
                        } else {
                            // Unreachable: canon proved every alternative binds
                            // the same names. Adopt the binder rather than drop it.
                            local.insert(name, var);
                        }
                    }
                }
                Ok(())
            }
        }
    }

    /// Build the IPE-T0013 diagnostic for a constructor pattern that binds the
    /// wrong number of payload fields. A forged constructor symbol surfaces the
    /// underlying intern bug instead.
    pub fn ctor_pattern_arity(
        &self,
        span: Span,
        ctor: Symbol,
        expected: usize,
        found: usize,
    ) -> Diagnostic {
        self.interner.resolve(ctor).map_or_else(
            || Diagnostic::CompilerBug {
                where_: "intern.resolve",
                detail: format!("no backing string for constructor symbol {}", ctor.as_raw()),
            },
            |s| Diagnostic::Type {
                span,
                msg: TypeError::CtorPatternArity {
                    ctor: Box::from(s),
                    expected,
                    found,
                },
            },
        )
    }
}
