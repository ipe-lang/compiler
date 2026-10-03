use strum::EnumCount as _;

use super::{
    BTreeMap, BTreeSet, BinopClass, Builder, Builtins, Constraint, Content, CtorScheme, DResult,
    Diagnostic, FlatType, Generated, InferError, Interner, ModuleHome, Rc, RefCell, RowTail,
    SchemeSlot, Span, StdlibKernel, SuperVar, Symbol, Ty, TyBounds, UnionFind, VarId, canon,
    classify_binop, from_canon, is_solver_var, pin_any_in_ty,
};

impl<'a> Builder<'a> {
    /// Build a constraint set for the whole module.
    ///
    /// # Errors
    /// [`InferError::Sited`] at the owning def's or union's module for a
    /// source error in it (an annotation error, a constraint-generation
    /// refusal); [`InferError::Program`] carrying a [`Diagnostic::CompilerBug`]
    /// on an internal invariant violation (e.g. an arity mismatch between a
    /// binding's pattern count and its annotation, or an unbound local — both
    /// ruled out by canonicalisation).
    pub fn run(
        uf: &'a mut UnionFind<Content>,
        interner: &'a mut Interner,
        module: &canon::Module,
    ) -> Result<Generated, InferError> {
        Self::run_seeded(uf, interner, module, &[], BTreeMap::new())
    }

    /// [`Self::run`] over ONE module of a multi-module program, seeded with
    /// its dependencies' typed interfaces: `dep_unions` registers the deps'
    /// constructor schemes (so a cross-module constructor reference or
    /// pattern instantiates exactly as it does over the linked merge), and
    /// `seed_top_level` pre-populates the `(home, name)` scheme table with
    /// the deps' exported binding schemes (so a cross-module `VarTopLevel`
    /// reference takes the ordinary instantiate-fresh-per-use-site path).
    /// With empty seeds this IS [`Self::run`] — one code path, no drift.
    ///
    /// # Errors
    /// Same conditions as [`Self::run`].
    #[allow(clippy::too_many_lines)] // declarative registration loops — every case listed explicitly for safety
    pub fn run_seeded(
        uf: &'a mut UnionFind<Content>,
        interner: &'a mut Interner,
        module: &canon::Module,
        dep_unions: &[&canon::Union],
        seed_top_level: BTreeMap<(Vec<Symbol>, Symbol), Rc<Ty>>,
    ) -> Result<Generated, InferError> {
        let builtins = Builtins::new(interner).map_err(InferError::unsited)?;
        let mut builder = Self {
            uf,
            interner,
            builtins,
            regions: BTreeMap::new(),
            expected: BTreeMap::new(),
            current_home: None,
            constraints: Vec::new(),
            top_level: seed_top_level, // (home, name) → Ty
            untyped: BTreeMap::new(),  // (home, name) → VarId
            field_accesses: Vec::new(),
            record_updates: Vec::new(),
            routed_web_checks: Vec::new(),
            route_witness_checks: Vec::new(),
            wildcard_any_return_bodies: BTreeMap::new(),
            wildcard_any_return_bindings: BTreeSet::new(),
            wildcard_any_use_results: Vec::new(),
            ctors: BTreeMap::new(),
            typed_rigids: Vec::new(),
            scheme_apps: Vec::new(),
            super_vars: Vec::new(),
            signature_wildcards: Vec::new(),
            typed_wildcards: Vec::new(),
            wildcard_log: None,
            pending_instantiations: Vec::new(),
            scheme_cache: RefCell::new(vec![SchemeSlot::Unresolved; StdlibKernel::COUNT]),
        };

        // Register the Prelude-built-in constructor schemes (`True` / `False` /
        // `Just` / `Nothing` / `Ok` / `Err`) first, so a reference or pattern
        // instantiates `Maybe a` / `Result e a` / `Bool` fresh per use site. A
        // user `type` cannot shadow these names (the canon §3.2 gate rejects it),
        // so the module-union loop below never collides with them.
        for (name, scheme) in builder.builtins.ctor_schemes() {
            // Every built-in scheme's `result` is the enum type it builds, a
            // home-less `Ty::Con` (`Bool` / `Maybe` / `Result` / …). Its
            // `(module, name)` is exactly the `(home, type_name)` half of the
            // qualified key — the same empty-home identity canon stamps on a
            // `PCtor` for these ambient built-ins — so the key agrees with the
            // lookup side by construction. A non-`Con` result would be a
            // built-in table bug, not user input, so fall back to the empty
            // home + the constructor's own name rather than panic.
            let (home, type_name) = match &scheme.result {
                Ty::Con {
                    module, name: ty, ..
                } => (module.clone(), *ty),
                _ => (Vec::new(), name),
            };
            builder
                .ctors
                .insert((home, type_name, name), Rc::new(scheme));
        }

        // Register every data constructor's scheme up front, so a `VarCtor`
        // reference or a constructor pattern can instantiate it fresh. A
        // constructor `C : field0 -> … -> T vars`; the result type applies the
        // union to its declared type variables (as `Ty::Var`s), and the field
        // types carry those same variables, so one shared instantiation map
        // alpha-renames a generic constructor per use site. Seeded dep unions
        // register after the module's own, mirroring how the linked merge
        // carries every module's unions in one list.
        for union in module.unions.iter().chain(dep_unions.iter().copied()) {
            // Use the union's own `home` (its original defining module path)
            // rather than `module.name`. After `link::link` merges N canonical
            // modules into one, every union retains its source-module path in
            // `home`; `module.name` would always be the entry module's name
            // (e.g. `["Main"]`), causing cross-module constructor result types
            // (`Main.Color`) to diverge from cross-module type annotations
            // (`Helper.Color`) and fail unification (IPE-T0001).
            let result = Ty::Con {
                module: union.home.clone(),
                name: union.name,
                args: union.vars.iter().map(|v| Ty::Var(v.as_raw())).collect(),
            };
            // Pre-compute once per union (Copy types, no borrow conflict with
            // builder.ctors below).
            let dict_sym = builder.builtins.dict;
            let string_sym = builder.builtins.string;
            for ctor in &union.ctors {
                let mut arg_tys = Vec::with_capacity(ctor.args.len());
                for ct in &ctor.args {
                    // A payload field is a user-written type like any annotation,
                    // so it takes the same normalisation (`Task Error a` to the
                    // internal unary `Task a`, error-channel and arity checks)
                    // before a pattern binder or constructor use unifies with it.
                    let normalized = builder
                        .normalize_annotation_ty(from_canon(ct), ctor.span)
                        .map_err(|d| InferError::sited_at_path(d, &union.home))?;
                    // Pin `any` wildcard fields to Dict String String so every
                    // instantiation site (pattern binder, ctor-as-value,
                    // Sub.subscribeTopic) sees the concrete carrier, never a
                    // free Ty::Var that the lowerer would reject (IPE-L0102).
                    arg_tys.push(pin_any_in_ty(
                        normalized,
                        &union.vars,
                        builder.interner,
                        dict_sym,
                        string_sym,
                    ));
                }
                builder.ctors.insert(
                    (union.home.clone(), union.name, ctor.name),
                    Rc::new(CtorScheme {
                        arg_tys,
                        result: result.clone(),
                    }),
                );
            }
        }

        // First pass: register every binding so any binding can reference any
        // other (forward references resolve).
        //
        // * Typed bindings record their annotation type — the binding's *scheme*,
        //   instantiated fresh (flex) at each reference (`VarTopLevel`).
        // * Untyped bindings mint one shared monomorphic variable up front. Every
        //   reference resolves to that *same* variable, so a reference is checked
        //   against the binding's inferred type instead of being left
        //   unconstrained. The variable's settled type is read back into `env`.
        //   (Generalising an *un*annotated binding so it can be used at several
        //   concrete types in one module needs rank-based let-generalisation,
        //   which the solver does not yet model — so an untyped polymorphic
        //   binding is monomorphic at its use sites. Sound, not yet complete;
        //   write an annotation to get full polymorphism.)
        for def in &module.defs {
            // Key by (home_module_path, bare_name) so same-named defs from
            // different source modules never overwrite each other after
            // `link::link` merges them into a single flat def list.
            let home_key = def.home().to_vec();
            match def {
                canon::Def::Typed {
                    name, ty, patterns, ..
                } => {
                    let raw = from_canon(ty);
                    // ex15: a binding annotated `Handler` is really
                    // `Request -> Task Response` at call sites.  The internal
                    // constrain_def pass already expands Handler for the body so
                    // `req` gets type `Request`; here we must also expand for the
                    // top_level table so callers (e.g. Server.get) unify correctly.
                    let expanded = if let Ty::Con {
                        name: tname, args, ..
                    } = &raw
                    {
                        if *tname == builder.builtins.handler
                            && args.is_empty()
                            && !patterns.is_empty()
                        {
                            Ty::Fun(
                                Box::new(Ty::Con {
                                    module: Vec::new(),
                                    name: builder.builtins.server_request,
                                    args: Vec::new(),
                                }),
                                Box::new(Ty::Con {
                                    module: Vec::new(),
                                    name: builder.builtins.task,
                                    args: vec![Ty::Con {
                                        module: Vec::new(),
                                        name: builder.builtins.server_response,
                                        args: Vec::new(),
                                    }],
                                }),
                            )
                        } else {
                            raw
                        }
                    } else {
                        raw
                    };
                    let normalized = builder
                        .normalize_annotation_ty(expanded, name.span)
                        .map_err(|d| InferError::sited_at_path(d, def.home()))?;
                    // A bare wildcard `any` in the annotation's RETURN position
                    // severs the body from every use (see
                    // [`Builder::tie_wildcard_any_uses_to_bodies`]); record the
                    // binding so each reference is tied back to its body.
                    if builder.annotation_returns_wildcard_any(&normalized) {
                        builder
                            .wildcard_any_return_bindings
                            .insert((home_key.clone(), name.value));
                    }
                    builder
                        .top_level
                        .insert((home_key, name.value), Rc::new(normalized));
                }
                canon::Def::Untyped { name, .. } => {
                    let v = builder.flex().map_err(InferError::unsited)?;
                    builder.untyped.insert((home_key, name.value), v);
                }
            }
        }

        // Second pass: constrain each binding's body.
        for def in &module.defs {
            builder
                .constrain_def(def)
                .map_err(|d| InferError::sited_at_path(d, def.home()))?;
        }

        // With every binding constrained, `wildcard_any_return_bodies` is
        // complete: tie every wildcard-`any`-return reference to its body so the
        // body's real type flows to each use before the solver runs, regardless
        // of the source order in which a use and its binding appeared.
        builder
            .tie_wildcard_any_uses_to_bodies()
            .map_err(InferError::unsited)?;

        // `module.defs` is already dependency-first topo order (link::link
        // concatenates each source module's whole def list in the
        // caller-supplied topo order) — a single first-encounter dedup pass
        // recovers the distinct module homes in that same order.
        let mut module_order: Vec<Vec<Symbol>> = Vec::new();
        for def in &module.defs {
            let home = def.home();
            if module_order.iter().all(|h| h.as_slice() != home) {
                module_order.push(home.to_vec());
            }
        }

        Ok(Generated {
            regions: builder.regions,
            expected: builder.expected,
            constraints: builder.constraints,
            top_level: builder.top_level,
            untyped: builder.untyped,
            field_accesses: builder.field_accesses,
            record_updates: builder.record_updates,
            routed_web_checks: builder.routed_web_checks,
            route_witness_checks: builder.route_witness_checks,
            typed_rigids: builder.typed_rigids,
            scheme_apps: builder.scheme_apps,
            super_vars: builder.super_vars,
            signature_wildcards: builder.signature_wildcards,
            typed_wildcards: builder.typed_wildcards,
            pending_instantiations: builder.pending_instantiations,
            module_order,
        })
    }

    // ── solver-var construction helpers ────────────────────────────────────

    pub fn flex(&mut self) -> DResult<VarId> {
        self.uf.fresh(Content::Flex)
    }

    pub fn rigid(&mut self) -> DResult<VarId> {
        self.uf.fresh(Content::Rigid)
    }

    pub fn structure(&mut self, f: FlatType) -> DResult<VarId> {
        self.uf.fresh(Content::Structure(f))
    }

    /// Mint a fresh [`FlatType::EmptyRecord`] variable — the closed-tail
    /// sentinel for closed records. Every `FlatType::Record(fields, ext)`
    /// whose `ext` points here is a closed record (field set exact).
    ///
    /// Each closed record gets its own `EmptyRecord` node rather than sharing
    /// one, so the occurs-check can distinguish different records' tails;
    /// this matches the the compiler reference's `UF.fresh EmptyRecord1` per
    /// record literal.
    pub fn empty_record_tail(&mut self) -> DResult<VarId> {
        self.structure(FlatType::EmptyRecord)
    }

    pub fn int_var(&mut self) -> DResult<VarId> {
        let name = self.builtins.int;
        self.structure(FlatType::Con {
            module: Vec::new(),
            name,
            args: Vec::new(),
        })
    }

    pub fn bool_var(&mut self) -> DResult<VarId> {
        let name = self.builtins.bool;
        self.structure(FlatType::Con {
            module: Vec::new(),
            name,
            args: Vec::new(),
        })
    }

    pub fn float_var(&mut self) -> DResult<VarId> {
        let name = self.builtins.float;
        self.structure(FlatType::Con {
            module: Vec::new(),
            name,
            args: Vec::new(),
        })
    }

    pub fn string_var(&mut self) -> DResult<VarId> {
        let name = self.builtins.string;
        self.structure(FlatType::Con {
            module: Vec::new(),
            name,
            args: Vec::new(),
        })
    }

    pub fn char_var(&mut self) -> DResult<VarId> {
        let name = self.builtins.char;
        self.structure(FlatType::Con {
            module: Vec::new(),
            name,
            args: Vec::new(),
        })
    }

    /// The type of a `customElement "<js-path>"` constructor node: `CustomElement
    /// down up` with two fresh flexible parameters. The annotation on the binding
    /// (a resolved `CustomElement down up`) unifies with these, pinning the seal
    /// types; the arity + SEAL of that annotation were already enforced at canon.
    pub fn custom_element_var(&mut self) -> DResult<VarId> {
        let name = self.builtins.custom_element;
        let down = self.flex()?;
        let up = self.flex()?;
        self.structure(FlatType::Con {
            module: Vec::new(),
            name,
            args: vec![down, up],
        })
    }

    /// Mint a fresh super-typed flexible variable carrying `bounds` — a value
    /// the body has constrained to a Ipê super-type (numeric / ordered /
    /// equatable) but not yet to a concrete type. It pins to any matching type,
    /// or — when it meets an annotation skolem — lifts that skolem's obligations
    /// so the generic parameter is emitted with the matching trait bound.
    /// `span` is the operand span blamed if the variable later pins to a
    /// concrete type that does not actually support the operation.
    pub fn super_var(&mut self, bounds: TyBounds, span: Span) -> DResult<VarId> {
        let v = self.uf.fresh(Content::Super {
            rigid: false,
            bounds,
        })?;
        let home = self.home()?;
        self.super_vars.push(SuperVar {
            var: v,
            bounds,
            span,
            home,
        });
        Ok(v)
    }

    /// Constrain a binary operation by the type discipline of its operator. The
    /// returned [`VarId`] is the result type's variable. Mirrors the core
    /// subset of `Ipe.Type.Constrain.Expression.binopTypes`.
    pub fn constrain_binop(
        &mut self,
        local: &BTreeMap<Symbol, VarId>,
        func: Symbol,
        lhs: &canon::Expr,
        rhs: &canon::Expr,
    ) -> DResult<VarId> {
        // A binop operator symbol that does not resolve is a broken internal
        // invariant, not an unknown-but-named operator: fail closed to the
        // compiler-bug channel rather than let an empty string fall through to
        // `BinopClass::Poly` and silently defer the failure downstream.
        let func_name = self
            .interner
            .resolve(func)
            .ok_or_else(|| Diagnostic::CompilerBug {
                where_: "ipe_types::constrain_binop",
                detail: "interned operator symbol did not resolve".to_owned(),
            })?;
        let class = classify_binop(func_name);
        let lv = self.constrain_expr(local, lhs)?;
        let rv = self.constrain_expr(local, rhs)?;
        match class {
            BinopClass::Num(bounds) => {
                // `+ - *` are Number-polymorphic: operands and result share one
                // numeric variable. A concrete operand (`x + 1`) pins it to that
                // type; an all-variable use (`x + x`) leaves it generic, carrying
                // the operator's obligation so generalisation emits the bound.
                let s = self.super_var(bounds, lhs.span)?;
                self.eq(lhs.span, lv, s)?;
                self.eq(rhs.span, rv, s)?;
                Ok(s)
            }
            BinopClass::IntDiv => {
                let li = self.int_var()?;
                self.eq(lhs.span, lv, li)?;
                let ri = self.int_var()?;
                self.eq(rhs.span, rv, ri)?;
                self.int_var()
            }
            BinopClass::FloatDiv => {
                let lf = self.float_var()?;
                self.eq(lhs.span, lv, lf)?;
                let rf = self.float_var()?;
                self.eq(rhs.span, rv, rf)?;
                self.float_var()
            }
            BinopClass::Order => {
                // `< > <= >=` are Comparable-polymorphic: operands share one
                // ordered type (carrying the ordering obligation), result Bool.
                let s = self.super_var(TyBounds::ord(), lhs.span)?;
                self.eq(lhs.span, lv, s)?;
                self.eq(rhs.span, rv, s)?;
                self.bool_var()
            }
            BinopClass::Equality => {
                // `== /=` are Equatable-polymorphic: operands share one equatable
                // type (carrying the equality obligation), result Bool. A
                // concrete operand pins it (`n == 1` → `Int`); an all-variable
                // use (`p == q`) leaves it generic, so generalisation emits a
                // `PartialEq` bound rather than an unbounded `T{n}` the backend
                // could not compare. A function operand fails the pin and a
                // function instantiation fails the post-solve gate (IPE-T0014).
                let s = self.super_var(TyBounds::eq(), lhs.span)?;
                self.eq(lhs.span, lv, s)?;
                self.eq(rhs.span, rv, s)?;
                self.bool_var()
            }
            BinopClass::Boolean => {
                let lb = self.bool_var()?;
                self.eq(lhs.span, lv, lb)?;
                let rb = self.bool_var()?;
                self.eq(rhs.span, rv, rb)?;
                self.bool_var()
            }
            BinopClass::Append => {
                // `++` is `Appendable a => a -> a -> a`: both operands and the
                // result share one super-typed variable carrying the appendable
                // obligation. The unifier pins it to `String` or `List _` at
                // the head; a non-appendable operand (Int, Bool, record, …)
                // fails at the pin and surfaces as IPE-T0014 before reaching
                // the backend.
                let s = self.super_var(TyBounds::appendable(), lhs.span)?;
                self.eq(lhs.span, lv, s)?;
                self.eq(rhs.span, rv, s)?;
                Ok(s)
            }
            BinopClass::Poly => {
                // `a -> a -> a`: operands and result share one type.
                self.eq(rhs.span, lv, rv)?;
                Ok(lv)
            }
        }
    }

    pub fn con_var(
        &mut self,
        module: Vec<Symbol>,
        name: Symbol,
        args: Vec<VarId>,
    ) -> DResult<VarId> {
        self.structure(FlatType::Con { module, name, args })
    }

    /// A `List elem` type variable over the element variable `elem`. The built-in
    /// `List` carries an empty module path, matching the other builtins.
    pub fn list_var(&mut self, elem: VarId) -> DResult<VarId> {
        let name = self.builtins.list;
        self.con_var(Vec::new(), name, vec![elem])
    }

    /// Constrain a list literal `[]` / `[a, b, c]`: every element shares one
    /// element variable, and the whole expression is the `List` over it. An empty
    /// list leaves the element variable flexible (inferred from context, else
    /// numeric-defaulted like any unpinned variable). Returns the result variable.
    pub fn constrain_list(
        &mut self,
        local: &BTreeMap<Symbol, VarId>,
        elems: &[canon::Expr],
    ) -> DResult<VarId> {
        let elem = self.flex()?;
        for e in elems {
            let ev = self.constrain_expr(local, e)?;
            // Every list element expects the shared element type — an empty
            // slot in `[ ⟨|⟩ ]` where sibling elements pin `elem` completes to
            // that element type.
            self.record_expected(e.span, elem)?;
            self.eq(e.span, ev, elem)?;
        }
        self.list_var(elem)
    }

    /// Constrain a cons `head :: tail`: `head : elem`, `tail : List elem`, result
    /// `List elem`. Imposing the `a -> List a -> List a` discipline directly makes
    /// a non-list tail or a mismatched element a type error, not a backend crash.
    pub fn constrain_cons(
        &mut self,
        local: &BTreeMap<Symbol, VarId>,
        head: &canon::Expr,
        tail: &canon::Expr,
    ) -> DResult<VarId> {
        let elem = self.constrain_expr(local, head)?;
        let list = self.list_var(elem)?;
        let tail_var = self.constrain_expr(local, tail)?;
        // The tail of `head :: tail` expects `List elem`.
        self.record_expected(tail.span, list)?;
        self.eq(tail.span, tail_var, list)?;
        Ok(list)
    }

    /// Constrain `lhs` to equal `rhs`, blaming `span` in the def being constrained.
    ///
    /// # Errors
    /// [`Diagnostic::CompilerBug`] when no def is being constrained.
    pub fn eq(&mut self, span: Span, lhs: VarId, rhs: VarId) -> DResult<()> {
        let home = self.home()?;
        self.eq_at(home, span, lhs, rhs);
        Ok(())
    }

    /// Constrain `lhs` to equal `rhs`, blaming `span` in the module `home`.
    pub fn eq_at(&mut self, home: ModuleHome, span: Span, lhs: VarId, rhs: VarId) {
        self.constraints.push(Constraint {
            span,
            lhs,
            rhs,
            home,
        });
    }

    /// The module owning the def being constrained.
    ///
    /// # Errors
    /// [`Diagnostic::CompilerBug`] when no def is being constrained: a record
    /// minted then would carry no module to frame its span against.
    pub fn home(&self) -> DResult<ModuleHome> {
        self.current_home
            .clone()
            .ok_or_else(|| Diagnostic::CompilerBug {
                where_: "ipe_types::Builder::home",
                detail: "a home-carrying record was minted outside any def".to_owned(),
            })
    }

    /// Record the solver variable the enclosing context EXPECTS at `span` —
    /// the type-directed-completion sidecar (see [`Self::expected`]).
    ///
    /// Pure bookkeeping: it inserts into a map the solver never reads and mints
    /// no variable, so it cannot perturb inference. First writer wins — the
    /// tightest (innermost-recorded) expectation for a span is kept; an outer
    /// context that revisits the same span (rare, only under span-sharing
    /// desugarings) does not overwrite it.
    ///
    /// # Errors
    /// [`Diagnostic::CompilerBug`] when no def is being constrained.
    pub fn record_expected(&mut self, span: Span, var: VarId) -> DResult<()> {
        let home = self.home()?.into_path();
        self.expected.entry((home, span)).or_insert(var);
        Ok(())
    }

    // ── Ty ⇄ solver bridges ────────────────────────────────────────────────

    /// Instantiate a resolved [`Ty`] into fresh union-find structure, with every
    /// type variable replaced by a fresh **flexible** variable.
    ///
    /// This is the per-call-site instantiation (the the compiler `CForeign` path):
    /// each reference to a polymorphic top-level binding alpha-renames the
    /// binding's scheme into fresh flex variables, so the call unifies against the
    /// concrete argument types at *this* site without pinning the binding's other
    /// uses. Type variables alpha-rename consistently *within this call* via a
    /// fresh `vars` map (`a -> a` becomes `f -> f`, one shared flex), so calling
    /// `identity` at `Int` and at `Bool` in the same module yields two
    /// independent, separately-satisfiable instantiations.
    ///
    /// The alpha-renaming map (scheme type-variable raw id → fresh variable) is
    /// returned alongside the type. It lets a use site be checked post-solve
    /// against the binding's super-type obligations: each obligated scheme
    /// variable's fresh variable reveals the concrete type this use pinned it to.
    ///
    /// The fresh flex of each wildcard `any` occurrence is returned third, in
    /// signature order, for the same post-solve check of a wildcard obligation.
    pub fn instantiate_tracked(
        &mut self,
        ty: &Ty,
    ) -> DResult<(VarId, BTreeMap<u32, VarId>, Vec<VarId>)> {
        let mut vars = BTreeMap::new();
        let mut wildcards = Vec::new();
        let var = self.instantiate_logging_wildcards(ty, &mut vars, false, &mut wildcards)?;
        Ok((var, vars, wildcards))
    }

    /// [`Self::instantiate_in`], appending the fresh flex of every wildcard
    /// `any` occurrence of `ty` to `wildcards` in traversal order. The log is
    /// active for this one instantiation only, so a constructor or pattern
    /// instantiated between two signature pieces never enters it.
    pub fn instantiate_logging_wildcards(
        &mut self,
        ty: &Ty,
        vars: &mut BTreeMap<u32, VarId>,
        rigid: bool,
        wildcards: &mut Vec<VarId>,
    ) -> DResult<VarId> {
        let outer = self.wildcard_log.replace(Vec::new());
        let var = self.instantiate_in(ty, vars, rigid);
        let logged = std::mem::replace(&mut self.wildcard_log, outer);
        wildcards.extend(logged.unwrap_or_default());
        var
    }

    /// Instantiate a constructor scheme through one shared variable map, returning
    /// the fresh variables of its payload fields and of its result enum type.
    /// Sharing the map keeps a generic constructor's field and result variables
    /// linked at this use site (`Just : a -> Maybe a` instantiated at `a = Int`
    /// ties the payload to the result), exactly like [`Self::instantiate_tracked`] over the
    /// equivalent arrow — but decomposed, so a pattern can bind each field and a
    /// value reference can rebuild the arrow.
    pub fn instantiate_ctor(&mut self, scheme: &CtorScheme) -> DResult<(Vec<VarId>, VarId)> {
        let mut vars = BTreeMap::new();
        let mut arg_vars = Vec::with_capacity(scheme.arg_tys.len());
        for t in &scheme.arg_tys {
            arg_vars.push(self.instantiate_in(t, &mut vars, /* rigid */ false)?);
        }
        let result_var = self.instantiate_in(&scheme.result, &mut vars, /* rigid */ false)?;
        Ok((arg_vars, result_var))
    }

    pub fn instantiate_in(
        &mut self,
        ty: &Ty,
        vars: &mut BTreeMap<u32, VarId>,
        rigid: bool,
    ) -> DResult<VarId> {
        match ty {
            Ty::Unit => self.structure(FlatType::Unit),
            Ty::Tuple(elems) => {
                let mut elem_vars = Vec::with_capacity(elems.len());
                for e in elems {
                    elem_vars.push(self.instantiate_in(e, vars, rigid)?);
                }
                self.structure(FlatType::Tuple(elem_vars))
            }
            Ty::Record(fields, tail) => {
                let mut field_vars = BTreeMap::new();
                for (name, field_ty) in fields {
                    let v = self.instantiate_in(field_ty, vars, rigid)?;
                    field_vars.insert(*name, v);
                }
                // Open records: instantiate the row tail variable via the same
                // `vars` map so the same source-level row var (`appExt`) maps
                // to a single UF node across all uses in the same binding.
                // Closed records: mint a fresh EmptyRecord sentinel.
                let ext = match tail {
                    RowTail::Closed => self.empty_record_tail()?,
                    RowTail::Open(raw_id) => {
                        if let Some(v) = vars.get(raw_id).copied() {
                            v
                        } else {
                            let v = if rigid { self.rigid()? } else { self.flex()? };
                            vars.insert(*raw_id, v);
                            v
                        }
                    }
                };
                self.structure(FlatType::Record(field_vars, ext))
            }
            Ty::Var(id) => {
                // `any` is Ipê's wildcard type-variable name. In annotations it
                // means "I don't care about this type" — each occurrence is an
                // INDEPENDENT fresh flex UV, NOT a shared rigid skolem. Sharing
                // would force all occurrences to the same type; rigid would
                // prevent the body from assigning a concrete type.  Mirrors the
                // the compiler compiler's `Instantiate.fromAnnotation` filtering
                // `"any"` out of the skolem set and `buildEnv` giving each
                // occurrence its own fresh UF var.
                // AUD-13: a solver-representative id (tagged by `zonk`) is
                // structurally never an annotation symbol — skip the
                // interner resolution entirely rather than risk a spurious
                // numeric collision with the interned "any" string.
                let is_any = !is_solver_var(*id)
                    && self
                        .interner
                        .resolve(ipe_intern::Symbol::from_raw(*id))
                        .is_some_and(|name| name == "any");
                if is_any {
                    // Fresh flex UV per occurrence — intentionally NOT inserted
                    // into `vars` so the next occurrence also gets its own UV.
                    // A signature's own wildcard (`rigid`) is a generic
                    // parameter defaulting must leave alone.
                    let v = self.flex()?;
                    if rigid {
                        self.signature_wildcards.push(v);
                    }
                    if let Some(log) = self.wildcard_log.as_mut() {
                        log.push(v);
                    }
                    return Ok(v);
                }
                if let Some(v) = vars.get(id).copied() {
                    return Ok(v);
                }
                let v = if rigid { self.rigid()? } else { self.flex()? };
                vars.insert(*id, v);
                Ok(v)
            }
            Ty::Fun(a, b) => {
                let av = self.instantiate_in(a, vars, rigid)?;
                let bv = self.instantiate_in(b, vars, rigid)?;
                self.structure(FlatType::Fun(av, bv))
            }
            Ty::Con { module, name, args } => {
                let mut arg_vars = Vec::with_capacity(args.len());
                for a in args {
                    arg_vars.push(self.instantiate_in(a, vars, rigid)?);
                }
                self.structure(FlatType::Con {
                    module: module.clone(),
                    name: *name,
                    args: arg_vars,
                })
            }
        }
    }

    // ── the walk ────────────────────────────────────────────────────────────
}
