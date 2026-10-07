use ipe_diagnostics::{Candidates, NameError};

use super::{
    BTreeMap, Builder, CtorKey, DResult, Diagnostic, Feature, FlatType, LowerError, ModuleHome,
    PendingInstantiation, RouteWitnessCheck, RoutedWebCheck, STAGE, SchemeApp, SchemeKey, Span,
    StdlibKernel, Symbol, Ty, TyBounds, TypeError, VarId, WildcardAnyUse, WildcardEntry, canon,
    canon_type_to_doc, from_canon,
};

/// The role a pinned kernel-obligation slot plays in its kernel's scheme.
///
/// Each variant identifies WHICH scheme variable a `constrain_var_kernel` tie
/// site must bound; the concrete raw index lives in [`OBLIGATION_SLOTS`] (the
/// `SqlParam` index differs across the `Db` family — var 0 for
/// `exec`/`query`/`findProjection`/`findProjectionOrdered`, var 1 for the
/// `queryDecode` shapes that carry a decoder var ahead of the bind list — so
/// the index cannot live on the kind alone).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ObligationKind {
    /// Dict/Set element-key or `Ipe.Cache` key (`comparable` / `PartialEq`).
    Key,
    /// `Set.map` result element (also backs a `BTreeSet`, so also `Ord`).
    SetMapResult,
    /// `Db.*` params-list element carrying the SQL-bind-parameter bound.
    SqlParam,
    /// `Debug.log` stringified value (Show).
    Show,
    /// `Log.*With` attribute-list element (the closed interpolable scalar set).
    Interpolable,
    /// `Web.tea` / `Web.embed` Model var (routed-Web page-field check).
    WebModel,
    /// `Web.tea` / `Web.embed` notFound var (routed-Web page-field check).
    WebNotFound,
    /// `Web.tea` / `Web.embed` message var (the `onNavigate` result).
    WebMsg,
    /// `Web.tea` / `Web.embed` cfg row tail (absorbs `onNavigate`).
    WebCfgTail,
    /// `Web.route` result page var (per-route page witness).
    WebPage,
    /// `Web.route` page-builder var (per-route page witness).
    WebBuilder,
    /// A scheme var the kernel's runtime function bounds by `PartialOrd`.
    Ordered,
    /// A scheme var the kernel's runtime function bounds by `PartialEq`.
    Equatable,
}

impl ObligationKind {
    /// The super-type bound the shared table-driven tie attaches to a slot of this kind.
    ///
    /// `Some` for a kind that mirrors a trait bound of the kernel's runtime
    /// Rust function: `Builder::tie_bound_obligations` ties every such row
    /// after any instantiation, so adding a row is all it takes to enforce it.
    /// `None` for a kind whose own `constrain_var_kernel` arm reads its slot
    /// (a module-selected key, a SQL bind, a stringify, a Web witness).
    #[must_use]
    pub const fn generic_bound(self) -> Option<TyBounds> {
        match self {
            Self::Ordered => Some(TyBounds::ord()),
            Self::Equatable => Some(TyBounds::eq()),
            Self::Key
            | Self::SetMapResult
            | Self::SqlParam
            | Self::Show
            | Self::Interpolable
            | Self::WebModel
            | Self::WebNotFound
            | Self::WebMsg
            | Self::WebCfgTail
            | Self::WebPage
            | Self::WebBuilder => None,
        }
    }
}

/// Single source of truth for every pinned kernel-obligation slot: the
/// `(kernel, raw-scheme-var, role)` each `constrain_var_kernel` tie site
/// bounds. The tie sites read the slot index from here (never an inline
/// literal), and `obligation_slots_match_scheme_shapes` asserts every entry's
/// scheme literally contains `Ty::Var(slot)` — so a scheme-var reorder that
/// would silently drop a `comparable` / SQL-param / Show bound (or a Web
/// witness) breaks the build instead. The `Key` family is qualifier-selected by
/// [`Builder::key_obligation_for`] over the WHOLE `Set`/`Dict`/`Cache` module —
/// a superset of the keyed kernels pinned here. The non-keyed majority
/// (`Dict.size`, `Set.toList`, `Cache.clear`, …) carry no bindable key var and
/// are DELIBERATELY absent; for them the tie site treats a missing `Key` slot as
/// the legitimate no-obligation case, returning the scheme unbounded.
pub const OBLIGATION_SLOTS: &[(StdlibKernel, u32, ObligationKind)] = {
    use ObligationKind as O;
    use StdlibKernel as K;
    &[
        // Dict/Set/Cache key — raw scheme-var 0 in every keyed kernel.
        (K::SetInsert, 0, O::Key),
        (K::SetMap, 0, O::Key),
        (K::DictInsert, 0, O::Key),
        (K::DictGet, 0, O::Key),
        (K::DictRemove, 0, O::Key),
        (K::CacheGet, 0, O::Key),
        (K::CachePut, 0, O::Key),
        (K::CacheRemove, 0, O::Key),
        // `Set.map` result element — raw scheme-var 1.
        (K::SetMap, 1, O::SetMapResult),
        // `Db.*` bind-list element — var 0 (exec/query/findProjection/
        // findProjectionOrdered), var 1 (queryDecode, whose var 0 is the
        // decoder's result type).
        (K::DbExec, 0, O::SqlParam),
        (K::DbQuery, 0, O::SqlParam),
        (K::DbQueryDecode, 1, O::SqlParam),
        (K::DbConnQueryDecode, 1, O::SqlParam),
        (K::DbFindProjection, 0, O::SqlParam),
        (K::DbFindProjectionOrdered, 0, O::SqlParam),
        // `Log.*With` list element / `Debug.log` value — Show, raw var 0.
        (K::LogInfoWith, 0, O::Interpolable),
        (K::LogDebugWith, 0, O::Interpolable),
        (K::LogWarnWith, 0, O::Interpolable),
        (K::LogErrorWith, 0, O::Interpolable),
        (K::DebugLog, 0, O::Show),
        // `Web.tea` / `Web.embed` / `Web.appWith` — Model var 0, Msg var 1,
        // notFound var 2, cfg row tail 3.
        (K::WebApp, 0, O::WebModel),
        (K::WebApp, 1, O::WebMsg),
        (K::WebApp, 2, O::WebNotFound),
        (K::WebApp, 3, O::WebCfgTail),
        (K::WebEmbed, 0, O::WebModel),
        (K::WebEmbed, 1, O::WebMsg),
        (K::WebEmbed, 2, O::WebNotFound),
        (K::WebEmbed, 3, O::WebCfgTail),
        (K::WebAppWith, 0, O::WebModel),
        (K::WebAppWith, 1, O::WebMsg),
        (K::WebAppWith, 2, O::WebNotFound),
        (K::WebAppWith, 3, O::WebCfgTail),
        // `Web.route` — page var 0, builder var 1.
        (K::WebRoute, 0, O::WebPage),
        (K::WebRoute, 1, O::WebBuilder),
        // `List.sortBy : (a -> b) -> List a -> List a` — the key `b` (raw var
        // 1) is the runtime `list_sort_by`'s `B: PartialOrd`.
        (K::ListSortBy, 1, O::Ordered),
        // `List.member` / `List.unique` — the element (raw var 0) is the
        // runtime `list_member`'s `T0: PartialEq` / `list_unique`'s
        // `T: PartialEq`.
        (K::ListMember, 0, O::Equatable),
        (K::ListUnique, 0, O::Equatable),
    ]
};

/// Whether every bound-carrying [`OBLIGATION_SLOTS`] row names a var its kernel's scheme shape carries.
///
/// One pass over the rows: a row whose kind has an
/// [`ObligationKind::generic_bound`] needs a [`StdlibKernel::scheme_shape`] in
/// which [`ipe_kernels::shape_aligns_var`] finds the row's slot, otherwise the
/// tie would miss the variable the runtime bound sits on.
const fn bound_rows_are_aligned(rows: &[(StdlibKernel, u32, ObligationKind)]) -> bool {
    let mut rest = rows;
    while let Some((&(kernel, slot, kind), tail)) = rest.split_first() {
        if kind.generic_bound().is_some() {
            let Some(shape) = kernel.scheme_shape() else {
                return false;
            };
            if slot > 0xFF {
                return false;
            }
            #[allow(clippy::cast_possible_truncation)] // bounded by the check above
            let var = slot as u8;
            if !ipe_kernels::shape_aligns_var(shape, var) {
                return false;
            }
        }
        rest = tail;
    }
    true
}

// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if a bound-carrying obligation row names a scheme var its kernel's scheme shape does not carry, the kernel-obligation SEAL invariant
#[allow(clippy::assertions_on_constants)] // the constant IS the tripwire
const _: () = assert!(
    bound_rows_are_aligned(OBLIGATION_SLOTS),
    "an OBLIGATION_SLOTS row with a generic bound names a scheme var its kernel's scheme_shape does not carry at an aligned position",
);

/// The frozen size of [`OBLIGATION_SLOTS`], pinned by
/// `obligation_slots_match_scheme_shapes` so adding/removing a pinned slot must
/// update this count — a silently dropped entry (obligation removed → hazard
/// reopened) fails the build.
#[cfg(test)]
pub const EXPECTED_OBLIGATION_SLOT_COUNT: usize = 37;

impl Builder<'_> {
    /// Constrain one def's body with `current_home` set to the def's module
    /// for exactly the walk: every record minted inside it names that module,
    /// and once it returns a mint names no module, so it fails closed instead
    /// of inheriting the last def's home.
    pub fn constrain_def(&mut self, def: &canon::Def) -> DResult<()> {
        // Track which source module this def belongs to so every `regions.insert`
        // in the sub-expression walk uses `(home, span)` as the key, preventing
        // cross-module span collisions after `link::link` merges dep modules.
        self.current_home = ModuleHome::new(def.home().to_vec());
        let walked = self.constrain_def_body(def);
        self.current_home = None;
        walked
    }

    #[allow(clippy::too_many_lines)] // the Handler expansion block pushes it over 100
    fn constrain_def_body(&mut self, def: &canon::Def) -> DResult<()> {
        match def {
            canon::Def::Typed {
                name,
                patterns,
                body,
                ty,
                free_vars,
                ..
            } => {
                // Instantiate the WHOLE signature through one shared map so every
                // occurrence of an annotation variable (`a` in `a -> a`) becomes
                // the *same* rigid (skolem) node, and distinct variables become
                // distinct rigids. Checking the body against rigids is what makes
                // the annotation a genuine contract: `f : a -> a; f x = x + 1`
                // (body pins `a` to `Int`) and `f : a -> b; f x = x` (body
                // conflates `a` and `b`) are both mismatches rather than silently
                // accepted. Per-call-site uses instead instantiate the binding's
                // type as fresh *flex* variables (see [`Self::instantiate_tracked`]).
                // ── Handler alias expansion (T0004 fix) ───────────────
                // `Handler` is the stdlib alias `Request -> Task Error Response`
                // (Ipe.Http.Server).  A binding annotated as `Handler` with one
                // parameter (e.g. `handleHome : Handler; handleHome req = …`)
                // would fire T0004 because the annotation is a nullary `Con`, not
                // a `Lambda`.  Expand it to the full arrow type here, before the
                // parameter-loop runs, so the loop can peel the arrow normally.
                //
                // The expansion is purely canonical — it mirrors exactly what
                // `canonicalise_type` would produce for an explicit
                // `Request -> Task Error Response` annotation.  `handler_expansion`
                // is kept as an owned `canon::Type` so `cursor` (a reference) can
                // point into it when the annotation is `Handler`.
                let handler_expansion: Option<canon::Type> = {
                    if let canon::Type::Con {
                        name: tname, args, ..
                    } = ty
                    {
                        if *tname == self.builtins.handler
                            && args.is_empty()
                            && !patterns.is_empty()
                        {
                            let task_resp = canon::Type::Con {
                                home: Vec::new(),
                                name: self.builtins.task,
                                args: vec![
                                    canon::Type::Con {
                                        home: Vec::new(),
                                        name: self.builtins.error,
                                        args: Vec::new(),
                                    },
                                    canon::Type::Con {
                                        home: Vec::new(),
                                        name: self.builtins.server_response,
                                        args: Vec::new(),
                                    },
                                ],
                            };
                            Some(canon::Type::Lambda(
                                Box::new(canon::Type::Con {
                                    home: Vec::new(),
                                    name: self.builtins.server_request,
                                    args: Vec::new(),
                                }),
                                Box::new(task_resp),
                            ))
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                };
                let mut rigid_vars = BTreeMap::new();
                let mut wildcards = Vec::new();
                let mut param_counts = Vec::with_capacity(patterns.len());
                let mut bare_params = Vec::with_capacity(patterns.len());
                let mut local = BTreeMap::new();
                let mut cursor: &canon::Type = handler_expansion.as_ref().unwrap_or(ty);
                for pat in patterns {
                    let (arg_ty, rest) = match cursor {
                        canon::Type::Lambda(a, b) => (a.as_ref(), b.as_ref()),
                        // The binding writes more parameter patterns than its
                        // annotation has arrows (`f a b = …` with `f : Int`).
                        // Parse-don't-validate: surface a user-facing
                        // IPE-T0004 with the binding span + the written
                        // signature, not a CompilerBug.
                        _ => return Err(self.too_many_parameters(name, ty)),
                    };
                    let arg = self.normalize_annotation_ty(from_canon(arg_ty), name.span)?;
                    let before = wildcards.len();
                    let arg_var = self.instantiate_logging_wildcards(
                        &arg,
                        &mut rigid_vars,
                        true,
                        &mut wildcards,
                    )?;
                    param_counts.push(wildcards.len().saturating_sub(before));
                    bare_params.push(self.is_wildcard_any_ty(&arg));
                    self.constrain_pattern(&mut local, pat, arg_var)?;
                    // Record the param pattern's region so the lowerer can read the
                    // solved param type (record-param field-set completion, IPE-T0015
                    // path). Keyed by `(current_home, pat.span)` to prevent collisions
                    // across dep modules (see `Builder::regions` doc comment).
                    self.regions
                        .insert((self.home()?.into_path(), pat.span), arg_var);
                    cursor = rest;
                }
                let ret_ty = self.normalize_annotation_ty(from_canon(cursor), name.span)?;
                let ret_var = self.instantiate_logging_wildcards(
                    &ret_ty,
                    &mut rigid_vars,
                    true,
                    &mut wildcards,
                )?;
                let body_var = self.constrain_expr(&local, body)?;
                // A typed binding's body expects its annotation return type —
                // the strongest completion signal: `f : Color; f = ⟨|⟩` offers
                // `Color`'s constructors first.
                self.record_expected(body.span, ret_var)?;
                self.eq(body.span, body_var, ret_var)?;
                // A binding whose RETURN annotation is the bare wildcard `any`
                // severs its body's settled type from every use site (each `any`
                // occurrence instantiates its own fresh flex). Record the body
                // var so [`Self::tie_wildcard_any_uses_to_bodies`] can re-connect
                // it to every use, undoing the severance at its root (a
                // `view = <this binding>` with an `Html` body then reaches the
                // shape's `Element` requirement as an ordinary mismatch). The
                // guard mirrors the registration pass exactly
                // ([`Self::annotation_returns_wildcard_any`]): a point-free def
                // (`alias : Model -> any; alias = view`, zero written patterns)
                // leaves `ret_ty` as the whole `Model -> any` arrow, which the
                // tie peels along with the use — so both def forms are recorded.
                if self.annotation_returns_wildcard_any(&ret_ty) {
                    self.wildcard_any_return_bodies
                        .insert((self.home()?.into_path(), name.value), body_var);
                }
                // Record the skolem each annotation variable instantiated to, so
                // its body-imposed super-type obligations can be read back for
                // generalisation. Keyed by the variable's symbol (the lowerer's
                // `free_vars` are these same symbols).
                let mut var_rigids = BTreeMap::new();
                for fv in free_vars {
                    if let Some(rigid) = rigid_vars.get(&fv.as_raw()) {
                        var_rigids.insert(*fv, *rigid);
                    }
                }
                self.typed_rigids
                    .push(((self.home()?.into_path(), name.value), var_rigids));
                if !wildcards.is_empty() {
                    self.typed_wildcards.push(WildcardEntry {
                        key: (self.home()?.into_path(), name.value),
                        wildcards,
                        param_counts,
                        bare_params,
                        span: name.span,
                    });
                }
                Ok(())
            }
            canon::Def::Untyped {
                name,
                patterns,
                body,
                ..
            } => {
                let mut local = BTreeMap::new();
                let mut param_vars = Vec::with_capacity(patterns.len());
                for pat in patterns {
                    let v = self.flex()?;
                    self.constrain_pattern(&mut local, pat, v)?;
                    self.regions.insert((self.home()?.into_path(), pat.span), v);
                    param_vars.push(v);
                }
                let body_var = self.constrain_expr(&local, body)?;
                // Reconstruct the binding's full type as the right-nested arrow
                // `p0 -> p1 -> … -> body`, so `env[f]` for `f a b = a` is
                // `a -> b -> a`, not just the body's type. A binding with no
                // parameters is just its body's type.
                let mut arrow = body_var;
                for pv in param_vars.into_iter().rev() {
                    arrow = self.structure(FlatType::Fun(pv, arrow))?;
                }
                // Tie the reconstructed type to the shared variable minted in the
                // registration pass, which every reference resolves to.
                // Use the same (home, name) key that the registration pass used.
                let shared_key = (def.home().to_vec(), name.value);
                let Some(shared) = self.untyped.get(&shared_key).copied() else {
                    return Err(Diagnostic::CompilerBug {
                        where_: STAGE,
                        detail: format!(
                            "untyped binding `{}` was not registered",
                            self.interner.resolve(name.value).unwrap_or("<unknown>")
                        ),
                    });
                };
                self.eq(name.span, arrow, shared)?;
                Ok(())
            }
        }
    }

    /// Build the IPE-T0004 diagnostic for a binding with more parameter
    /// patterns than its annotation has arrows. Resolving the name / rendering
    /// the signature can itself only fail on a forged symbol, in which case
    /// that internal bug is surfaced instead.
    pub fn too_many_parameters(
        &self,
        name: &ipe_diagnostics::Located<Symbol>,
        ty: &canon::Type,
    ) -> Diagnostic {
        let binding = match self.interner.resolve(name.value) {
            Some(s) => Box::from(s),
            None => {
                return Diagnostic::CompilerBug {
                    where_: "intern.resolve",
                    detail: format!("no backing string for symbol {}", name.value.as_raw()),
                };
            }
        };
        match canon_type_to_doc(ty, self.interner) {
            Ok(signature) => Diagnostic::Type {
                span: name.span,
                msg: TypeError::TooManyParameters {
                    binding,
                    signature: Box::new(signature),
                },
            },
            Err(bug) => bug,
        }
    }
    /// Constrain a reference to a top-level binding. A typed binding is
    /// instantiated fresh (flex) at this use site so it unifies against its own
    /// concrete arguments without pinning the binding's other call sites, and the
    /// alpha-renaming map is recorded for the post-solve super-type obligation
    /// check. An untyped binding resolves to its shared monomorphic variable; a
    /// name that is not a binding of this module stays fully flexible.
    ///
    /// `module` is the **home** module path carried by the `VarTopLevel` node —
    /// i.e. the path of the module that *declares* the binding, not the module
    /// that *uses* it.  Using this path as part of the lookup key (see
    /// [`Builder::top_level`]) ensures that a `Lib.helper` reference resolves to
    /// `Lib.helper`'s own annotation type even when a same-named `Main.helper`
    /// exists in the merged def list.
    pub fn constrain_var_top_level(
        &mut self,
        module: &[Symbol],
        name: Symbol,
        span: Span,
    ) -> DResult<VarId> {
        let key = (module.to_vec(), name);
        if let Some(ty) = self.top_level.get(&key).cloned() {
            let (var, vars, wildcards) = self.instantiate_tracked(&ty)?;
            let use_home = self.home()?;
            self.scheme_apps.push(SchemeApp {
                home: module.to_vec(),
                use_home: use_home.clone(),
                name,
                vars,
                wildcards,
                span,
            });
            // A reference to a wildcard-`any`-return binding: record this use's
            // instantiated arrow so [`Self::tie_wildcard_any_uses_to_bodies`]
            // (after all defs are constrained) ties its result to the binding's
            // body — undoing the wildcard severance so the body's real type
            // reaches this use site.
            if self.wildcard_any_return_bindings.contains(&key) {
                self.wildcard_any_use_results.push(WildcardAnyUse {
                    arrow: var,
                    binding: key,
                    span,
                    use_home,
                });
            }
            Ok(var)
        } else if let Some(v) = self.untyped.get(&key).copied() {
            if self
                .current_home
                .as_ref()
                .is_some_and(|home| home.path() == key.0.as_slice())
            {
                // Same-module: still the one shared monomorphic var — an
                // untyped binding is monomorphic *within its home module*
                // (matches the reference's `CLocal` semantics exactly; see
                // `untyped_polymorphic_use_at_two_types_is_rejected`).
                Ok(v)
            } else {
                // Cross-module: isolate this reference behind its own fresh
                // placeholder instead of sharing the binding's program-wide
                // var. `promote_untyped_boundaries` (in `lib.rs`, post-solve)
                // discharges it against the source binding's generalized
                // scheme, once that scheme exists.
                let placeholder = self.flex()?;
                self.pending_instantiations.push(PendingInstantiation {
                    source: key,
                    placeholder,
                    use_home: self.home()?,
                    span,
                });
                Ok(placeholder)
            }
        } else {
            Err(Diagnostic::CompilerBug {
                where_: "ipe_types::constrain_var_top_level",
                detail: format!(
                    "unknown top-level binding (symbol {}); \
                     post-link every name must be in top_level or untyped",
                    name.as_raw()
                ),
            })
        }
    }

    /// The Ipê `comparable`-key obligation a kernel's element/key variable
    /// carries, keyed off the resolved [`StdlibKernel`] id via its
    /// `decl().qualifier` (parse-once — never a re-inspected module string).
    /// `Set`'s element is keyed by `BTreeSet` (`Ord`) and `Dict`'s key by a
    /// determinism-sorted `HashMap` (`Hash + Eq + Ord`); the obligation is
    /// attached to raw scheme-variable 0, the element/key in every `Set` /
    /// `Dict` kernel scheme.
    pub fn key_obligation_for(k: StdlibKernel) -> Option<TyBounds> {
        match k.decl().qualifier {
            "Set" => Some(TyBounds::set_elem()),
            "Dict" => Some(TyBounds::dict_key()),
            // `Ipe.Cache`'s key variable is raw scheme-var 0 in `get` /
            // `put` / `remove` (`Int -> k -> …`), and the runtime scans keys by
            // `PartialEq` (`cache_get`/`cache_put`/`cache_remove` bound
            // `K: PartialEq`). Attaching the EQ obligation lifts `PartialEq`
            // onto the emitted `Ipe.Cache` wrapper's key type parameter. The
            // key-less kernels (`newRaw`/`clear`/`size`/`stats`) have no
            // scheme-var 0, so the `vars.get(&0)` tie is a no-op for them.
            "Cache" => Some(TyBounds::eq()),
            _ => None,
        }
    }

    /// The raw scheme-var slot of a kernel obligation, read from the
    /// [`OBLIGATION_SLOTS`] SSOT rather than an inline literal at the tie site —
    /// so a scheme-var reorder cannot leave the tie index and the scheme shape
    /// disagreeing. `None` iff the `(k, kind)` pair is not a pinned obligation —
    /// a fail-closed miss for the exact-domain Web selectors, and the benign
    /// no-obligation case for the broad `Key` module selector and for every
    /// kernel without a SQL bind list (a `Db` kernel taking one cannot lack its
    /// row: `every_db_list_var_argument_has_a_sql_param_slot` walks them all).
    fn obligation_slot(k: StdlibKernel, kind: ObligationKind) -> Option<u32> {
        OBLIGATION_SLOTS
            .iter()
            .find(|(kk, _, kd)| *kk == k && *kd == kind)
            .map(|(_, slot, _)| *slot)
    }

    /// Tie each callback final-result variable of kernel `k` to a function-refusing variable.
    ///
    /// A higher-order kernel applies its callback at an exact arity, while the
    /// IR flattens a curried function into one multi-parameter `Fun`, so a
    /// callback whose final result is itself an arrow has no sound lowering.
    /// [`StdlibKernel::hof_result_vars`] names those variables from the
    /// kernel's scheme shape; each is tied to a fresh super-typed variable
    /// carrying [`TyBounds::hof_kernel_result`]. The obligation rides the
    /// union-find variable minted for this kernel reference, so it holds
    /// through every aliasing of the reference: piped, `let`-bound,
    /// re-exported, passed as an argument, or stored in a record. A classified
    /// variable absent from the instantiated scheme is a registry drift and
    /// fails closed.
    fn tie_hof_results(
        &mut self,
        k: StdlibKernel,
        vars: &BTreeMap<u32, VarId>,
        span: Span,
    ) -> DResult<()> {
        for raw in k.hof_result_vars().vars() {
            let result_var = *vars.get(&u32::from(raw)).ok_or(Diagnostic::Lower {
                span,
                msg: LowerError::Unsupported(Feature::Kernels),
            })?;
            let s = self.super_var(TyBounds::hof_kernel_result(), span)?;
            self.eq(span, result_var, s)?;
        }
        Ok(())
    }

    /// Tie every bound-carrying [`OBLIGATION_SLOTS`] row of kernel `k` to a super-typed variable.
    ///
    /// A row whose kind has an [`ObligationKind::generic_bound`] names the raw
    /// scheme variable its kernel's runtime Rust function bounds by a trait
    /// (`list_sort_by`'s `B: PartialOrd`, `list_member`'s `T0: PartialEq`).
    /// Tying it here, on the union-find variable minted for this reference,
    /// makes a concrete pin that Rust cannot satisfy fail closed at type-check
    /// and lifts the bound onto an enclosing generic's annotation skolem. A row
    /// whose variable is absent from the instantiated scheme is a registry
    /// drift and fails closed.
    fn tie_bound_obligations(
        &mut self,
        k: StdlibKernel,
        vars: &BTreeMap<u32, VarId>,
        span: Span,
    ) -> DResult<()> {
        for &(kernel, slot, kind) in OBLIGATION_SLOTS {
            if kernel != k {
                continue;
            }
            let Some(bound) = kind.generic_bound() else {
                continue;
            };
            let slot_var = *vars.get(&slot).ok_or(Diagnostic::Lower {
                span,
                msg: LowerError::Unsupported(Feature::Kernels),
            })?;
            let s = self.super_var(bound, span)?;
            self.eq(span, slot_var, s)?;
        }
        Ok(())
    }

    /// Tie every scheme-declared obligation of an instantiated kernel `k`.
    ///
    /// The one call each instantiation site makes, so no site can tie the
    /// callback-result restriction yet skip a table-declared bound.
    fn tie_scheme_obligations(
        &mut self,
        k: StdlibKernel,
        vars: &BTreeMap<u32, VarId>,
        span: Span,
    ) -> DResult<()> {
        self.tie_hof_results(k, vars, span)?;
        self.tie_bound_obligations(k, vars, span)
    }

    /// The type of a kernel reference (`Math.min`, `Set.insert`, …).
    ///
    /// Most kernels take the declarative scheme from [`Self::resolve_scheme`] via
    /// `instantiate`. Two families instead mint super-typed obligations so a
    /// generic use lifts the matching Rust trait bound onto its annotation
    /// skolem and a non-comparable argument fails closed at type-check:
    ///
    /// * `Math.min` / `Math.max` — `Comparable a => a -> a -> a`: the shared
    ///   variable carries the ORDERING obligation, exactly as the `< > <= >=`
    ///   operators and the user-fn `maxOf` do, so a generic use emits Rust
    ///   `T: PartialOrd` and a function / record argument is rejected rather than
    ///   emitting an unbounded `math_min<T>(…)` that `cargo` rejects.
    /// * `Set` / `Dict` kernels — the element / key (raw scheme-variable 0 in
    ///   every Set / Dict kernel) carries the Ipê `comparable`-key obligation
    ///   ([`Self::key_obligation_for`]). The base scheme (from
    ///   [`Self::resolve_scheme`]) is instantiated, then variable 0 is tied to a
    ///   fresh super-typed variable carrying that obligation, so a
    ///   non-comparable element / key (record, ADT, function) fails closed
    ///   instead of emitting an unbounded `set_insert::<T>` / `dict_insert::<T>`
    ///   call `cargo` rejects, and a generic `a -> Set a` lifts `Ord` (Set) /
    ///   `Hash + Eq + Ord` (Dict) onto its annotation skolem (see `bounds_for`).
    ///   This is also more conservative than Ipê's runtime, which keys a Set /
    ///   Dict on a stringified value.
    /// * Every instantiated kernel — each [`OBLIGATION_SLOTS`] row with an
    ///   [`ObligationKind::generic_bound`] (the `List.sortBy` key, the
    ///   `List.member` / `List.unique` element) is tied by
    ///   `Self::tie_bound_obligations`, so a record, custom-type, tuple or
    ///   function key and a function-bearing element fail closed instead of
    ///   reaching `cargo` as an unmet `PartialOrd` / `PartialEq`.
    #[allow(clippy::too_many_lines)]
    pub fn constrain_var_kernel(
        &mut self,
        id: Option<StdlibKernel>,
        module: Symbol,
        name: Symbol,
        span: Span,
    ) -> DResult<VarId> {
        // ── Obligation pre-checks (keyed off the resolved `id`,
        //    not a re-inspected module string). They live OUTSIDE the scheme
        //    tables and must fire BEFORE the registry/legacy delegation, so the
        //    bounded super-var reaches the caller instead of the bare base
        //    scheme now sitting in `stdlib_scheme`. ──
        if let Some(k) = id {
            // `Math.min` / `Math.max`: `Comparable a => a -> a -> a`. The bounded
            // super-var (reused across BOTH arrow argument positions AND the
            // result) is what rejects `Math.min f g` / `Math.min recA recB`
            // (`golden_m4c_math_gate`). This is a DIRECT-build bounded
            // scheme, NOT `stdlib_scheme` + a tie, because min/max's base scheme
            // has three independent `var(0)`s and the gate needs all three tied
            // to one bounded var.
            if matches!(k, StdlibKernel::MathMin | StdlibKernel::MathMax) {
                let s = self.super_var(TyBounds::ord(), span)?;
                let inner = self.structure(FlatType::Fun(s, s))?;
                return self.structure(FlatType::Fun(s, inner));
            }
            // `Basics.clamp lo hi x : comparable -> comparable -> comparable ->
            // comparable`. Same ORDERING obligation as min/max, but arity 3:
            // ONE bounded super-var reused across all three argument positions
            // AND the result, so `clamp recA recB recC` (records / functions /
            // ADTs) fails closed instead of emitting an unbounded
            // `basics_clamp::<T>` that `cargo` rejects. DIRECT-build (not
            // `stdlib_scheme` + tie) because the base scheme has three
            // independent `var(0)`s that must collapse to one bounded var.
            if matches!(k, StdlibKernel::BasicsClamp) {
                let s = self.super_var(TyBounds::ord(), span)?;
                let inner1 = self.structure(FlatType::Fun(s, s))?;
                let inner2 = self.structure(FlatType::Fun(s, inner1))?;
                return self.structure(FlatType::Fun(s, inner2));
            }
            // ── Basics numerics ────────────────────────────────────────
            // `negate / abs : number a => a -> a`. SUB obligation (Number
            // super-type — same as the unary-minus operator). A function / record
            // argument fails closed (T0001) before reaching a runtime that would
            // panic. Base scheme for the totality gate is in `stdlib_scheme`.
            if matches!(k, StdlibKernel::BasicsNegate | StdlibKernel::BasicsAbs) {
                let s = self.super_var(TyBounds::sub(), span)?;
                return self.structure(FlatType::Fun(s, s));
            }
            // `Store.add / .sub / .mul : number a => a -> a -> a` — the
            // arithmetic projection operators.  ONE Number-bounded super-var is
            // reused across both argument positions AND the result, so a
            // non-numeric operand (String / Bool / record / function) fails
            // closed (T0001) instead of emitting an unbounded scheme, and the
            // two operands must share the same numeric type.  The obligation is
            // the same one `+` / `-` / `*` mint (ADD / SUB / MUL).  DIRECT-build
            // (not `stdlib_scheme` + tie) so all three positions collapse to the
            // one bounded var.
            if let Some(bound) = match k {
                StdlibKernel::StoreAdd => Some(TyBounds::add()),
                StdlibKernel::StoreSub => Some(TyBounds::sub()),
                StdlibKernel::StoreMul => Some(TyBounds::mul()),
                _ => None,
            } {
                let s = self.super_var(bound, span)?;
                let inner = self.structure(FlatType::Fun(s, s))?;
                return self.structure(FlatType::Fun(s, inner));
            }
            // `min / max : comparable a => a -> a -> a` — same Comparable (Ord)
            // obligation as `Math.min` / `Math.max`. DIRECT-build (not
            // `stdlib_scheme` + tie) so all three positions collapse to ONE
            // bounded super-var, rejecting function / record arguments closed.
            if matches!(k, StdlibKernel::BasicsMin | StdlibKernel::BasicsMax) {
                let s = self.super_var(TyBounds::ord(), span)?;
                let inner = self.structure(FlatType::Fun(s, s))?;
                return self.structure(FlatType::Fun(s, inner));
            }
            // `compare : comparable a => a -> a -> Order`. Direct-build
            // (not stdlib_scheme + tie): both argument positions share one
            // Ord-bounded super-var; the return is the monomorphic Order type.
            if matches!(k, StdlibKernel::BasicsCompare) {
                let s = self.super_var(TyBounds::ord(), span)?;
                let order_var = self.structure(FlatType::Con {
                    module: Vec::new(),
                    name: self.builtins.order,
                    args: Vec::new(),
                })?;
                let inner = self.structure(FlatType::Fun(s, order_var))?;
                return self.structure(FlatType::Fun(s, inner));
            }
            // ── end Basics numerics ────────────────────────────────────
            // `List.sum : number a => List a -> a` / `List.product`. The list
            // element and the result share ONE number-bounded super-var (ADD for
            // sum, MUL for product — the same obligation `+` / `*` mint), so a
            // non-numeric element fails closed instead of emitting an unbounded
            // `list_sum::<T>`. Direct-build (not `stdlib_scheme` + tie) so both
            // the element and the result collapse to one bounded var.
            if matches!(k, StdlibKernel::ListSum | StdlibKernel::ListProduct) {
                let bound = if matches!(k, StdlibKernel::ListSum) {
                    TyBounds::add()
                } else {
                    TyBounds::mul()
                };
                let s = self.super_var(bound, span)?;
                let list_s = self.list_var(s)?;
                return self.structure(FlatType::Fun(list_s, s));
            }
            // `List.maximum / minimum : comparable a => List a -> Maybe a`. The
            // element carries the ORDERING obligation (same as `Math.min/max`);
            // the result is `Maybe a` over that bounded var. Direct-build so the
            // element and the Maybe payload share the one bounded super-var.
            if matches!(k, StdlibKernel::ListMaximum | StdlibKernel::ListMinimum) {
                let s = self.super_var(TyBounds::ord(), span)?;
                let list_s = self.list_var(s)?;
                let maybe_s = self.structure(FlatType::Con {
                    module: Vec::new(),
                    name: self.builtins.maybe,
                    args: vec![s],
                })?;
                return self.structure(FlatType::Fun(list_s, maybe_s));
            }
            // `List.sort : comparable a => List a -> List a`. The element carries
            // the ORDERING obligation; input and output share the one bounded
            // super-var. Direct-build (not `stdlib_scheme` + tie).
            if matches!(k, StdlibKernel::ListSort) {
                let s = self.super_var(TyBounds::ord(), span)?;
                let list_s = self.list_var(s)?;
                let list_s2 = self.list_var(s)?;
                return self.structure(FlatType::Fun(list_s, list_s2));
            }
            // `{{expr}}` interpolation (`Interpolate : a -> String`). The
            // argument carries the INTERPOLABLE obligation (a bounded super-var
            // → the sealed Rust `IpeInterpolate`): only the closed scalar set
            // `String` / `Int` / `Float` / `Bool` / `Char` satisfies it; a
            // record, ADT, container, opaque runtime type or function fails
            // CLOSED at type-check (IPE-T0014) rather than reaching a Debug
            // rendering or an unbounded `interpolate_to_string::<T>` that
            // `cargo` rejects. Direct-build (not stdlib_scheme + tie): only the
            // argument position is bounded.
            if matches!(k, StdlibKernel::Interpolate) {
                let s = self.super_var(TyBounds::interpolable(), span)?;
                let string_ty = self.string_var()?;
                return self.structure(FlatType::Fun(s, string_ty));
            }
            // `Error.toString`. The argument carries the STRINGIFY obligation
            // (a bounded super-var → Rust `IpeStringify`): a bare function (or a
            // value nesting one) fails CLOSED at type-check.
            if matches!(k, StdlibKernel::ErrorToString) {
                let s = self.super_var(TyBounds::show(), span)?;
                let string_ty = self.string_var()?;
                return self.structure(FlatType::Fun(s, string_ty));
            }
            // Dict / Set element-key `comparable` obligation. The base
            // scheme is relocated into `stdlib_scheme`; we instantiate
            // it and tie key-position raw var 0 to a bounded super-var. Only
            // key-position `var(0)` carries the bound, so this is `stdlib_scheme`
            // + a tie (unlike min/max's direct-build shape above).
            if let Some(bound) = Self::key_obligation_for(k) {
                let ty = self.resolve_scheme(SchemeKey(k)).ok_or(Diagnostic::Lower {
                    span,
                    msg: LowerError::Unsupported(Feature::Kernels),
                })?;
                let (var, vars, _) = self.instantiate_tracked(&ty)?;
                self.tie_scheme_obligations(k, &vars, span)?;
                // The key qualifier (`Set`/`Dict`/`Cache` in `key_obligation_for`)
                // selects the WHOLE module. The key/element is raw scheme-var 0 by
                // construction across every kernel in it — the convention the
                // `OBLIGATION_SLOTS` `Key` entries assert (each has `Ty::Var(0)`,
                // checked by `obligation_slots_match_scheme_shapes`). Bind that var
                // WHENEVER the instantiated scheme carries it, reading slot 0
                // directly rather than the pinned table: this is what makes key
                // coverage COMPLETE. Every key-BEARING kernel — `insert`/`get`/
                // `remove` AND `singleton`/`member`/`update`/`fromList`/… , a
                // superset of the pinned rows — thus fails closed on a
                // non-`comparable` key. The genuinely key-LESS kernels (`Dict.size`,
                // `Set.toList`, `Cache.newRaw`/`clear`/`size`/`stats`) have no
                // scheme-var 0, so this is a correct no-op for them; a reader like
                // `Dict.values` whose var 0 IS the key takes the (already-satisfied)
                // bound harmlessly, since a `Dict k v` value can only exist for a
                // `comparable k`. A table lookup here (the prior shape) fails OPEN
                // the instant a keyed kernel is unpinned — the `Dict.singleton`
                // hole this closes; slot 0 cannot drift out of coverage.
                if let Some(&key_var) = vars.get(&0) {
                    let s = self.super_var(bound, span)?;
                    self.eq(span, key_var, s)?;
                }
                // `Set.map : (a -> b) -> Set a -> Set b` — the RESULT element
                // `b` (raw scheme-var 1) also backs a `BTreeSet<b>`, so it
                // carries the same `set_elem` (Ord) obligation as the source
                // element. Without this a generic `Set.map` would emit an
                // unbounded `set_map::<A, B>` that `cargo` rejects (B: Ord unmet).
                if matches!(k, StdlibKernel::SetMap) {
                    let res_slot = Self::obligation_slot(k, ObligationKind::SetMapResult).ok_or(
                        Diagnostic::Lower {
                            span,
                            msg: LowerError::Unsupported(Feature::Kernels),
                        },
                    )?;
                    let res_var = *vars.get(&res_slot).ok_or(Diagnostic::Lower {
                        span,
                        msg: LowerError::Unsupported(Feature::Kernels),
                    })?;
                    let s = self.super_var(bound, span)?;
                    self.eq(span, res_var, s)?;
                }
                return Ok(var);
            }
            // Every kernel with a SQL bind list: the list ELEMENT (the raw
            // scheme var `OBLIGATION_SLOTS` names for it) carries the
            // SQL-bind-parameter obligation. Same `stdlib_scheme` + tie shape
            // as the Set/Dict key obligation directly above: only the
            // bind-element position is bounded, so a generic wrapper around a
            // Db kernel (`Database.exec label queryStr args` in
            // `examples/17-ipemon`) lifts `Into<SqlParam>` onto its own
            // emitted Rust generic (closing the E0277 half), and an
            // empty-list call site whose element type is otherwise
            // completely unconstrained defaults to `SqlValue` at solve time
            // instead of the wildcard-`any` fallback (closing the E0283
            // half — see the `sql_param` arm of the numeric-defaulting loop
            // in `crate::lib`), rather than emitting a bare `Vec::new()`
            // `cargo` cannot infer. The kernel set is the table's rows, so a
            // Db kernel cannot take a bind list without the bound.
            if let Some(raw_idx) = Self::obligation_slot(k, ObligationKind::SqlParam) {
                let ty = self.resolve_scheme(SchemeKey(k)).ok_or(Diagnostic::Lower {
                    span,
                    msg: LowerError::Unsupported(Feature::Kernels),
                })?;
                let (var, vars, _) = self.instantiate_tracked(&ty)?;
                self.tie_scheme_obligations(k, &vars, span)?;
                let params_var = *vars.get(&raw_idx).ok_or(Diagnostic::Lower {
                    span,
                    msg: LowerError::Unsupported(Feature::Kernels),
                })?;
                let s = self.super_var(TyBounds::sql_param(), span)?;
                self.eq(span, params_var, s)?;
                return Ok(var);
            }
            // `Log.*With : String -> List a -> Task Error ()` — the attr-list
            // ELEMENT `a` carries the INTERPOLABLE obligation (the same closed
            // scalar set as `{{…}}`). Same `stdlib_scheme` + tie shape as
            // Dict/Set: instantiate the base scheme and tie its list-element
            // `var(0)` to an interpolable super-var, so a record, ADT,
            // container, opaque runtime type (a `Secret`, a `Request`) or
            // function element fails closed at type-check.
            if matches!(
                k,
                StdlibKernel::LogInfoWith
                    | StdlibKernel::LogDebugWith
                    | StdlibKernel::LogWarnWith
                    | StdlibKernel::LogErrorWith
            ) {
                let ty = self.resolve_scheme(SchemeKey(k)).ok_or(Diagnostic::Lower {
                    span,
                    msg: LowerError::Unsupported(Feature::Kernels),
                })?;
                let (var, vars, _) = self.instantiate_tracked(&ty)?;
                self.tie_scheme_obligations(k, &vars, span)?;
                let slot = Self::obligation_slot(k, ObligationKind::Interpolable).ok_or(
                    Diagnostic::Lower {
                        span,
                        msg: LowerError::Unsupported(Feature::Kernels),
                    },
                )?;
                let elem_var = *vars.get(&slot).ok_or(Diagnostic::Lower {
                    span,
                    msg: LowerError::Unsupported(Feature::Kernels),
                })?;
                let s = self.super_var(TyBounds::interpolable(), span)?;
                self.eq(span, elem_var, s)?;
                return Ok(var);
            }
            // `Debug.log : String -> a -> a` — the value `a` (shared by the
            // argument and result, raw scheme-var 0) carries the STRINGIFY
            // obligation (the runtime stringifies it through `IpeStringify`).
            // Same `stdlib_scheme` + tie shape as `Log.*With`: tying the ONE super-var to both
            // positions keeps `Debug.log Int 5` (concrete, satisfies `show`)
            // accepted while a bare-function value fails closed — no spurious
            // IPE-L0108 for a well-typed showable value.
            if matches!(k, StdlibKernel::DebugLog) {
                let ty = self.resolve_scheme(SchemeKey(k)).ok_or(Diagnostic::Lower {
                    span,
                    msg: LowerError::Unsupported(Feature::Kernels),
                })?;
                let (var, vars, _) = self.instantiate_tracked(&ty)?;
                self.tie_scheme_obligations(k, &vars, span)?;
                let slot =
                    Self::obligation_slot(k, ObligationKind::Show).ok_or(Diagnostic::Lower {
                        span,
                        msg: LowerError::Unsupported(Feature::Kernels),
                    })?;
                let value_var = *vars.get(&slot).ok_or(Diagnostic::Lower {
                    span,
                    msg: LowerError::Unsupported(Feature::Kernels),
                })?;
                let s = self.super_var(TyBounds::show(), span)?;
                self.eq(span, value_var, s)?;
                return Ok(var);
            }
            // `Web.tea` / `Web.embed` / `Web.appWith` — post-solve routed-Web check.
            //
            // The open-record cfg scheme for K::WebApp is shared by both routed
            // apps (Model has a `page : Page` field) and non-routed apps (Model
            // has no `page` field).  We cannot express the conditional
            // `Model.page ≡ notFound` constraint at build time because a blanket
            // `var(0) ≡ { page : var(2) | ρ }` would break every non-routed
            // app whose Model has no `page` field.
            //
            // Instead: instantiate the scheme with `instantiate_tracked`, record
            // the Model, Msg, notFound and cfg-tail vars, then push a
            // `RoutedWebCheck` so `resolve_routed_web_checks` can run the gate
            // after the HM solver settles.
            if matches!(
                k,
                StdlibKernel::WebApp | StdlibKernel::WebEmbed | StdlibKernel::WebAppWith
            ) {
                let ty = self.resolve_scheme(SchemeKey(k)).ok_or(Diagnostic::Lower {
                    span,
                    msg: LowerError::Unsupported(Feature::Kernels),
                })?;
                let (var, vars, _) = self.instantiate_tracked(&ty)?;
                self.tie_scheme_obligations(k, &vars, span)?;
                let model_slot = Self::obligation_slot(k, ObligationKind::WebModel).ok_or(
                    Diagnostic::Lower {
                        span,
                        msg: LowerError::Unsupported(Feature::Kernels),
                    },
                )?;
                let not_found_slot = Self::obligation_slot(k, ObligationKind::WebNotFound).ok_or(
                    Diagnostic::Lower {
                        span,
                        msg: LowerError::Unsupported(Feature::Kernels),
                    },
                )?;
                let model_var = *vars.get(&model_slot).ok_or(Diagnostic::Lower {
                    span,
                    msg: LowerError::Unsupported(Feature::Kernels),
                })?;
                let not_found_var = *vars.get(&not_found_slot).ok_or(Diagnostic::Lower {
                    span,
                    msg: LowerError::Unsupported(Feature::Kernels),
                })?;
                let slot_var = |kind| {
                    Self::obligation_slot(k, kind)
                        .and_then(|slot| vars.get(&slot).copied())
                        .ok_or(Diagnostic::Lower {
                            span,
                            msg: LowerError::Unsupported(Feature::Kernels),
                        })
                };
                let msg_var = slot_var(ObligationKind::WebMsg)?;
                let cfg_tail_var = slot_var(ObligationKind::WebCfgTail)?;
                self.routed_web_checks.push(RoutedWebCheck {
                    model_var,
                    msg_var,
                    not_found_var,
                    cfg_tail_var,
                    span,
                    home: self.home()?,
                });
                return Ok(var);
            }
            // `Web.route` — per-route page witness.
            //
            // The scheme types the page-builder argument with var(1) DISTINCT
            // from the result's page var(0): the argument is EITHER a nullary
            // page value (`Web.route "/" HomePage`) OR a params-consuming
            // constructor (`Web.route "/apps/:slug" AppDetailPage` — type
            // `String -> Page`).  That disjunction is not expressible as a
            // plain HM constraint, so — like `RoutedWebCheck` above — the
            // relation is deferred: record both instantiated vars and push a
            // `RouteWitnessCheck`; `resolve_route_witness_checks` peels the
            // builder's settled leading arrows and unifies the resulting page
            // type with var(0) after the main solve.
            if matches!(k, StdlibKernel::WebRoute) {
                let ty = self.resolve_scheme(SchemeKey(k)).ok_or(Diagnostic::Lower {
                    span,
                    msg: LowerError::Unsupported(Feature::Kernels),
                })?;
                let (var, vars, _) = self.instantiate_tracked(&ty)?;
                self.tie_scheme_obligations(k, &vars, span)?;
                let page_slot =
                    Self::obligation_slot(k, ObligationKind::WebPage).ok_or(Diagnostic::Lower {
                        span,
                        msg: LowerError::Unsupported(Feature::Kernels),
                    })?;
                let builder_slot = Self::obligation_slot(k, ObligationKind::WebBuilder).ok_or(
                    Diagnostic::Lower {
                        span,
                        msg: LowerError::Unsupported(Feature::Kernels),
                    },
                )?;
                let page_var = *vars.get(&page_slot).ok_or(Diagnostic::Lower {
                    span,
                    msg: LowerError::Unsupported(Feature::Kernels),
                })?;
                let builder_var = *vars.get(&builder_slot).ok_or(Diagnostic::Lower {
                    span,
                    msg: LowerError::Unsupported(Feature::Kernels),
                })?;
                self.route_witness_checks.push(RouteWitnessCheck {
                    builder_var,
                    page_var,
                    span,
                    home: self.home()?,
                });
                return Ok(var);
            }
        }
        // ── Parse-once registry lookup ──
        //
        // `stdlib_scheme` is TOTAL over the reachable kernel set and
        // WILDCARD-FREE, so every reachable kernel resolves via the
        // `StdlibKernel` id. There is no legacy string-keyed `kernel_ty`
        // table carrying a `Ty::Var(u32::MAX)` exit-0 sentinel for un-typed
        // kernels. A `None` id (FFI `Rust.*`) or an excluded bucket
        // (`WebAppRouted` — unlowered) misses the registry and is
        // fail-closed with IPE-L0108 (loud) via `kernel_scheme_or_unsupported`,
        // never silently typed as a free variable that `cargo` later rejects.
        let _ = (module, name); // retained for diagnostics
        // Route through `resolve_scheme`, not `stdlib_scheme` directly, so a
        // kernel carrying a structural `TyShape` resolves via the interpreter and
        // one without a shape resolves through the table — a single adapter, so
        // the two paths can never resolve to different types.
        let registry = id.and_then(|k| self.resolve_scheme(SchemeKey(k)));
        let ty = Self::kernel_scheme_or_unsupported(registry, None, span)?;
        let (var, vars, _) = self.instantiate_tracked(&ty)?;
        if let Some(k) = id {
            self.tie_scheme_obligations(k, &vars, span)?;
        }
        Ok(var)
    }

    /// Combine the parse-once registry scheme (`id` path) with the legacy
    /// string-table scheme, failing closed with IPE-L0108 (`Feature::Kernels`,
    /// the same shape lower raises at `lower_callee`) when NEITHER supplies a
    /// type. Extracted as a pure fn so the fail-closed arm is unit-testable
    /// independently of the (currently total) legacy table — see
    /// `both_miss_is_fail_closed`.
    pub fn kernel_scheme_or_unsupported(
        registry: Option<Ty>,
        legacy: Option<Ty>,
        span: Span,
    ) -> DResult<Ty> {
        registry.or(legacy).ok_or(Diagnostic::Lower {
            span,
            msg: LowerError::Unsupported(Feature::Kernels),
        })
    }
    /// Tie each reference to a wildcard-`any`-return binding to that binding's
    /// body result, so the body's settled type flows to every use site — closing
    /// the wildcard severance at its root. Run once EVERY def is constrained
    /// (so all body vars exist and the tie is independent of source order),
    /// before the main solve, so the tied type propagates through the same
    /// unification the use participates in. A `view = <binding>` whose body is
    /// `Html` therefore reaches the shape's `Element` requirement as an ordinary
    /// mismatch (rendered as IPE-T0020), rather than passing ipe and failing
    /// `cargo build`. Covers every indirection — direct reference, `let` alias
    /// chains, eta-expansion — because it is plain unification, not a syntactic
    /// reference walk.
    pub fn tie_wildcard_any_uses_to_bodies(&mut self) -> DResult<()> {
        let ties = std::mem::take(&mut self.wildcard_any_use_results);
        for tie in ties {
            let Some(&body_var) = self.wildcard_any_return_bodies.get(&tie.binding) else {
                continue;
            };
            // Peel BOTH the use's instantiated arrow and the recorded body to
            // their final results, then tie the two result slots. The use arrow
            // is `param0 -> … -> any`; the body is either the applied result
            // (a def written with parameters) OR the same arrow shape (a
            // point-free def, `alias = view`), so peeling both reaches the
            // matching `any`/`Html` slot regardless of the def form or arity.
            let use_result = self.peel_arrow_result(tie.arrow)?;
            let body_result = self.peel_arrow_result(body_var)?;
            self.eq_at(tie.use_home, tie.span, use_result, body_result);
        }
        Ok(())
    }
    /// Constrain a constructor referenced as a value: its scheme instantiated fresh.
    ///
    /// A nullary constructor's value type is the enum itself; a payload
    /// constructor's is the curried arrow `field0 -> … -> T vars`. Each reference
    /// instantiates independently, so the same generic constructor used at `Int`
    /// and at `Bool` in one module yields two separately-satisfiable types.
    ///
    /// # Errors
    /// See [`Self::ctor_scheme_miss`] for a constructor with no scheme.
    pub fn constrain_var_ctor(
        &mut self,
        span: Span,
        home: &[Symbol],
        type_name: Symbol,
        name: Symbol,
    ) -> DResult<VarId> {
        // Same qualified-identity lookup as the pattern site: a constructor
        // referenced as a value resolves against its own declaring module's
        // scheme, never a same-named constructor from another module.
        let key = (home.to_vec(), type_name, name);
        let Some(scheme) = self.ctors.get(&key).cloned() else {
            return Err(self.ctor_scheme_miss(span, &key));
        };
        let (arg_vars, result_var) = self.instantiate_ctor(&scheme)?;
        let mut t = result_var;
        for av in arg_vars.into_iter().rev() {
            t = self.structure(FlatType::Fun(av, t))?;
        }
        Ok(t)
    }

    /// The refusal for a constructor `key` that has no registered scheme.
    ///
    /// A sealed builtin capability handle (`StreamId`) is a user error,
    /// `ConstructorNotFound` with no suggestions. Any other miss means canon
    /// resolved a constructor the table does not carry: a `CompilerBug`, never
    /// an unconstrained fallback type.
    pub fn ctor_scheme_miss(&self, span: Span, key: &CtorKey) -> Diagnostic {
        let (_, type_name, name) = key;
        let resolved = self.interner.resolve(*name);
        match resolved {
            Some(s) if self.sealed_ctors.contains(key) => Diagnostic::Name {
                span,
                msg: NameError::ConstructorNotFound {
                    name: Box::from(s),
                    suggestions: Candidates::at(None, Box::new([])),
                },
            },
            _ => Diagnostic::CompilerBug {
                where_: "constrain.ctor_scheme",
                detail: format!(
                    "constructor `{}` of type `{}` has no registered scheme",
                    resolved.unwrap_or("<unresolved>"),
                    self.interner.resolve(*type_name).unwrap_or("<unresolved>"),
                ),
            },
        }
    }
}
