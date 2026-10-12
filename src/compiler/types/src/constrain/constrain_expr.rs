use super::{
    BTreeMap, Builder, Content, DResult, Diagnostic, FieldAccess, FlatType, RecordUpdate, STAGE,
    Span, Symbol, TyBounds, VarId, canon,
};

impl Builder<'_> {
    #[allow(clippy::too_many_lines)] // one arm per canonical expression form
    pub fn constrain_expr(
        &mut self,
        local: &BTreeMap<Symbol, VarId>,
        e: &canon::Expr,
    ) -> DResult<VarId> {
        let span = e.span;
        let var = match &e.value {
            // An integer literal is `Number`-polymorphic (Elm/Ipê `number`): it
            // may resolve to `Int` OR `Float` depending on context, and defaults
            // to `Int` when the program never pins it (the post-solve defaulting
            // loop closes an unpinned `Super { Number }` to `Int`).  This lets
            // `pct 100` — where `pct : Float -> Length` — accept the literal `100`
            // as a `Float`, matching the reference compiler.  A *float* literal
            // (`1.6`) is concretely `Float`, never `Int` (Elm keeps `1.6 : Float`
            // distinct from the polymorphic `number`).
            canon::Expr_::Int(_) => self.super_var(TyBounds::add(), span)?,
            canon::Expr_::Float(_) => self.float_var()?,
            canon::Expr_::Str(_) => self.string_var()?,
            canon::Expr_::CustomElementCtor(_) => self.custom_element_var()?,
            canon::Expr_::Char(_) => self.char_var()?,
            canon::Expr_::Unit => self.structure(FlatType::Unit)?,
            canon::Expr_::VarLocal(s) => match local.get(s) {
                Some(v) => *v,
                None => {
                    return Err(Diagnostic::CompilerBug {
                        where_: STAGE,
                        detail: format!(
                            "unbound local `{}`",
                            self.interner.resolve(*s).unwrap_or("<unknown symbol>")
                        ),
                    });
                }
            },
            canon::Expr_::VarTopLevel { module, name } => {
                self.constrain_var_top_level(module, *name, span)?
            }
            canon::Expr_::VarKernel { id, module, name } => {
                // the pre-resolved `id` selects the parse-once
                // registry scheme (`stdlib_scheme`) for migrated families,
                // falling back to the legacy symbol-keyed table otherwise.
                self.constrain_var_kernel(*id, *module, *name, span)?
            }
            canon::Expr_::ForeignCall { args, .. } => {
                // A foreign wrapper call is the annotation-trusted boundary:
                // the enclosing FfiInterface binding is REQUIRED to carry a
                // full annotation (canon fails closed otherwise), and that
                // annotation pins every parameter and the result. Arguments
                // are constrained so their vars exist for the lowerer's
                // region map; the call's own type is a fresh flexible var the
                // annotation immediately determines.
                for a in args {
                    self.constrain_expr(local, a)?;
                }
                self.flex()?
            }
            canon::Expr_::VarCtor {
                home,
                type_name,
                name,
                ..
            } => self.constrain_var_ctor(span, home, *type_name, *name)?,
            canon::Expr_::Call(callee, args) => {
                let callee_var = self.constrain_expr(local, callee)?;
                // Each argument gets a FRESH param var rather than flowing its
                // own var straight into the callee's arrow shape. Two payoffs:
                //  1. the callee-vs-shape constraint below is solved FIRST, so
                //     each param var adopts the callee's DECLARED param type;
                //  2. the per-arg constraint then unifies found=actual-arg
                //     against expected=declared-param AT THE ARG'S SPAN —
                //     `Task.fail "str"` reads "expected Error, found String",
                //     never the inversion (and blames the argument, not the
                //     callee name).
                // A non-function callee still reports found=callee's type,
                // expected=`a -> b` via the callee-vs-shape constraint.
                let mut arg_pairs = Vec::with_capacity(args.len());
                for a in args {
                    let arg_var = self.constrain_expr(local, a)?;
                    let param_var = self.flex()?;
                    // The callee's declared slot is exactly the type this
                    // argument position expects: after the callee-vs-shape
                    // constraint solves, `param_var` adopts the declared param
                    // type, so completion at this span offers only candidates
                    // whose type unifies with the declared parameter.
                    self.record_expected(a.span, param_var)?;
                    arg_pairs.push((a.span, arg_var, param_var));
                }
                let ret = self.flex()?;
                // Fold a right-associative arrow over the fresh param vars:
                // p0 -> p1 -> … -> ret.
                let mut fun_shape = ret;
                for (_, _, param_var) in arg_pairs.iter().rev() {
                    fun_shape = self.structure(FlatType::Fun(*param_var, fun_shape))?;
                }
                // Order matters: callee-vs-shape first (see above).
                self.eq(callee.span, callee_var, fun_shape)?;
                for (arg_span, arg_var, param_var) in arg_pairs {
                    self.eq(arg_span, arg_var, param_var)?;
                }
                ret
            }
            canon::Expr_::Case(scrut, branches) => self.constrain_case(local, scrut, branches)?,
            canon::Expr_::Lambda(params, body) => self.constrain_lambda(local, params, body)?,
            canon::Expr_::Binop { func, lhs, rhs, .. } => {
                self.constrain_binop(local, *func, lhs, rhs)?
            }
            canon::Expr_::Let(bindings, body) => {
                // Sequential, monomorphic `let`: each binding's value is
                // constrained against the scope built so far, and its name binds
                // to that value's variable for the bindings that follow and the
                // `in` body. The whole `let`'s type is the body's type. It does
                // not generalise let-bound names — no let-polymorphism.
                let mut let_local = local.clone();
                for b in bindings {
                    let bv = self.constrain_expr(&let_local, &b.body)?;
                    // The binder may be a plain name or an irrefutable destructure
                    // (tuple / record); `constrain_pattern` ties the binder's
                    // shape to the value's type and binds every leaf variable.
                    self.constrain_pattern(&mut let_local, &b.pat, bv)?;
                }
                self.constrain_expr(&let_local, body)?
            }
            canon::Expr_::If(branches, else_expr) => {
                // Every condition is `Bool`; every branch and the final `else`
                // unify to one shared result type, which is the whole `if`'s
                // type. Mirrors `Ipe.Type.Constrain.Expression.constrainIf`.
                let result = self.flex()?;
                for (cond, body) in branches {
                    let cond_var = self.constrain_expr(local, cond)?;
                    let want_bool = self.bool_var()?;
                    // A condition expects `Bool`; a branch body expects the
                    // shared `if` result type.
                    self.record_expected(cond.span, want_bool)?;
                    self.eq(cond.span, cond_var, want_bool)?;
                    let body_var = self.constrain_expr(local, body)?;
                    self.record_expected(body.span, result)?;
                    self.eq(body.span, body_var, result)?;
                }
                let else_var = self.constrain_expr(local, else_expr)?;
                self.record_expected(else_expr.span, result)?;
                self.eq(else_expr.span, else_var, result)?;
                result
            }
            canon::Expr_::Tuple(elems) => {
                // A tuple's type is the product of its elements' types, each
                // constrained independently. Mirrors
                // `Ipe.Type.Constrain.Expression`'s tuple arm.
                let mut elem_vars = Vec::with_capacity(elems.len());
                for elem in elems {
                    elem_vars.push(self.constrain_expr(local, elem)?);
                }
                self.structure(FlatType::Tuple(elem_vars))?
            }
            canon::Expr_::List(elems) => self.constrain_list(local, elems)?,
            canon::Expr_::Cons(head, tail) => self.constrain_cons(local, head, tail)?,
            canon::Expr_::Record(fields) => self.constrain_record(local, fields)?,
            canon::Expr_::Access(record, field) => {
                self.constrain_access(local, record, *field, span)?
            }
            canon::Expr_::Update(base, fields) => {
                self.constrain_update(local, base, fields, span)?
            }
        };
        self.regions.insert((self.home()?.into_path(), span), var);
        Ok(var)
    }

    /// Constrain a lambda `\p0 p1 ... -> body`. Each parameter gets a fresh
    /// flexible variable bound in the body's scope; the body is constrained
    /// there. The lambda's type is the right-nested arrow `p0 -> p1 -> … -> body`,
    /// so a surrounding `Call` unifies its callee against exactly this shape.
    /// Mirrors `Ipe.Type.Constrain.Expression`'s lambda arm.
    pub fn constrain_lambda(
        &mut self,
        local: &BTreeMap<Symbol, VarId>,
        params: &[canon::Pattern],
        body: &canon::Expr,
    ) -> DResult<VarId> {
        let mut lam_local = local.clone();
        let mut param_vars = Vec::with_capacity(params.len());
        for p in params {
            let v = self.flex()?;
            self.constrain_pattern(&mut lam_local, p, v)?;
            // Record each lambda param's region so the lowerer can source a
            // record-param's complete field set from its solved type (one path
            // shared with the typed-def sites).  Keyed by `(current_home, span)`
            // to prevent cross-module span collisions.
            self.regions.insert((self.home()?.into_path(), p.span), v);
            param_vars.push(v);
        }
        let mut arrow = self.constrain_expr(&lam_local, body)?;
        for pv in param_vars.into_iter().rev() {
            arrow = self.structure(FlatType::Fun(pv, arrow))?;
        }
        Ok(arrow)
    }

    /// Constrain a record literal `{ name = value, ... }`. Its type is the
    /// closed record `{ name : <field type>, ... }`, each field value
    /// constrained independently. Canonicalisation has already rejected a
    /// duplicate field name, so the resulting field map is exact.
    ///
    /// User-written record literals are always **closed** — they carry an
    /// `EmptyRecord` tail so the unifier rejects extra fields on either side.
    pub fn constrain_record(
        &mut self,
        local: &BTreeMap<Symbol, VarId>,
        fields: &[(Symbol, canon::Expr)],
    ) -> DResult<VarId> {
        let mut field_vars = BTreeMap::new();
        for (name, value) in fields {
            let v = self.constrain_expr(local, value)?;
            field_vars.insert(*name, v);
        }
        let ext = self.empty_record_tail()?;
        self.structure(FlatType::Record(field_vars, ext))
    }
    /// Follow a variable's settled structure, peeling leading `_ -> rest`
    /// arrows, and return the final non-arrow result. Bounded fuel guards a
    /// pathological cyclic chain.
    pub fn peel_arrow_result(&mut self, var: VarId) -> DResult<VarId> {
        let mut cur = self.uf.find(var)?;
        let mut fuel: u32 = 1024;
        while fuel > 0 {
            match self.uf.content(cur)? {
                Content::Structure(FlatType::Fun(_, ret)) => cur = self.uf.find(ret)?,
                _ => break,
            }
            fuel -= 1;
        }
        Ok(cur)
    }

    /// Constrain a record field access `record.field`. With closed records (no
    /// row variable), the field cannot be resolved until the record's type
    /// settles, so the access is deferred: a fresh result variable is its region
    /// type now, and [`crate::resolve_field_accesses`] links it to the field's
    /// type after the main solve.
    pub fn constrain_access(
        &mut self,
        local: &BTreeMap<Symbol, VarId>,
        record: &canon::Expr,
        field: Symbol,
        span: Span,
    ) -> DResult<VarId> {
        let record_var = self.constrain_expr(local, record)?;
        let result = self.flex()?;
        self.field_accesses.push(FieldAccess {
            record: record_var,
            field,
            result,
            span,
            home: self.home()?,
        });
        Ok(result)
    }

    /// Constrain a record update `{ base | field = value, ... }`. The result
    /// type is the base record's type (an update copies-and-replaces, changing
    /// no field's type), so the update's region variable *is* the base's. The
    /// field-existence + per-field type checks are deferred — closed records
    /// carry no row variable, so the base's type may not be settled yet —
    /// recorded here and discharged by [`crate::resolve_record_updates`] after
    /// the main solve.
    pub fn constrain_update(
        &mut self,
        local: &BTreeMap<Symbol, VarId>,
        base: &canon::Expr,
        fields: &[(Symbol, canon::Expr)],
        span: Span,
    ) -> DResult<VarId> {
        let record_var = self.constrain_expr(local, base)?;
        let mut field_vars = Vec::with_capacity(fields.len());
        for (name, value) in fields {
            let v = self.constrain_expr(local, value)?;
            field_vars.push((*name, v));
        }
        self.record_updates.push(RecordUpdate {
            record: record_var,
            fields: field_vars,
            span,
            home: self.home()?,
        });
        Ok(record_var)
    }

    /// Constrain a `case scrut of …`: the scrutinee shares one type, every arm
    /// pattern is checked against it, and every arm body unifies to one shared
    /// result — the whole `case`'s type.
    pub fn constrain_case(
        &mut self,
        local: &BTreeMap<Symbol, VarId>,
        scrut: &canon::Expr,
        branches: &[canon::CaseBranch],
    ) -> DResult<VarId> {
        let scrut_var = self.constrain_expr(local, scrut)?;
        let result = self.flex()?;
        for br in branches {
            let mut br_local = local.clone();
            self.constrain_pattern(&mut br_local, &br.pat, scrut_var)?;
            let body_var = self.constrain_expr(&br_local, &br.body)?;
            // Every arm body expects the shared `case` result type.
            self.record_expected(br.body.span, result)?;
            self.eq(br.body.span, body_var, result)?;
        }
        Ok(result)
    }
}
