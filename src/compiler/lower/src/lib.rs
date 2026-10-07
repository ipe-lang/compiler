#![forbid(unsafe_code)]
//! `ipe_lower` — the sequential integration point of the Milestone-0 pipeline.
//!
//! Entry point: [`lower`]. It consumes a name-resolved [`ipe_canon::ast::Module`]
//! together with the [`ipe_types::SolvedTypes`] produced by inference and emits
//! a backend-agnostic [`ipe_ir::Program`]. This is a faithful but narrowed port
//! of the reference compiler's `Ipe.Build.Compile` lowering core plus
//! `Ipe.Build.LowerCtx`:
//!
//! * union declarations → [`ipe_ir::TypeDef::Enum`];
//! * each top-level binding → a [`ipe_ir::Func`] (its `case` body lowered to an
//!   exhaustive [`ipe_ir::Match`] built through the validating
//!   [`ipe_ir::Match::new`], its binops to [`ipe_ir::BinOp`]);
//! * `main` → the module's `entry` function;
//! * kernel references (`Io.println`, `String.fromInt`) → [`ipe_ir::Callee::Kernel`];
//! * top-level references (`Main.update`) → [`ipe_ir::Callee::Func`].
//!
//! Lowering is *type-directed*: every [`ipe_ir::IrType`] slot is filled from the
//! region/binding types in [`ipe_types::SolvedTypes`]. A slot whose region type
//! is absent is an internal-invariant violation and surfaces as
//! [`ipe_diagnostics::Diagnostic::CompilerBug`] — never a panic.

mod capabilities;
mod lower;
mod once_check;

/// Whole-program capability inference: the exact security-capability set a
/// lowered program exercises. Consumed by `ipe capabilities` (SP1) and, ahead,
/// by manifest generation (SP2) and sandbox configuration (SP4).
pub use capabilities::program_capabilities;

/// Root-seeded capability reachability: the kernel-derived capabilities a set of
/// root modules reaches, with the home of every reached function. Consumed by
/// the package capability audit.
pub use capabilities::{ReachedCapabilities, capabilities_reached_from};

/// The generated `ipe-ce-<hex16>` custom-element tag for a widget hook at a
/// cleaned, in-project path. The SINGLE definition the lowerer uses to render the
/// `CustomElement.node` view node — re-exported so the build stage that serves the widget
/// asset (and generates its registration glue) mints the identical tag, never a
/// drifting second hash of the same path.
pub use lower::custom_element_tag;

/// Test-only surface: the crate-private TCO analysis/rewrite,
/// re-exported so the integration-test binary can drive them directly. Hidden
/// from the public docs; not part of the stable API.
#[doc(hidden)]
pub use lower::tco_analysis;

use ipe_canon::ast as canon;
use ipe_diagnostics::Diagnostic;
use ipe_intern::Interner;
use ipe_types::SolvedTypes;

/// Lower a canonical module + its solved types into the typed IR.
///
/// # Errors
/// * Returns [`ipe_diagnostics::Diagnostic::Lower`] when the input is valid Ipê
///   that the supported subset does not model yet (polymorphism, higher-order values,
///   non-`Task ()` results, extra kernels, non-constructor patterns, …),
///   carrying the offending node's span and its `IPE-L01##` feature.
/// * Returns [`ipe_diagnostics::Diagnostic::CompilerBug`] when an internal
///   invariant is violated — a missing region type for an `IrType` slot, an
///   unresolved scrutinee enum, or a match arm set that fails
///   [`ipe_ir::Match::new`]'s exhaustiveness proof. These are unreachable for
///   well-typed, well-canonicalised input.
#[allow(clippy::too_many_lines)]
pub fn lower(
    m: &canon::Module,
    types: &SolvedTypes,
    interner: &mut Interner,
    source_path: &str,
    source_text: &str,
) -> Result<ipe_ir::Program, (Diagnostic, Vec<ipe_intern::Symbol>)> {
    // Widest callable arity — the ceiling for the eta / capture pools below.
    // Declared first (an item before any statement) so the `homeless` closure
    // that follows does not trip `clippy::items_after_statements`.
    const MAX_CALLEE_ARITY: usize = 16;
    // Pre-lowering setup below (fresh-symbol pool minting + Prelude built-in
    // interning) raises only homeless `CompilerBug`/intern diagnostics — each
    // such `?` is mapped to an EMPTY home via `homeless`, so the driver falls
    // back to its byte-offset heuristic for those (as it already does for
    // homeless type errors). The per-def home attribution that fixes
    // cross-module misattribution lives inside `Lowerer::run`, at the
    // `lower_def` boundary.
    let homeless = |d: Diagnostic| (d, Vec::<ipe_intern::Symbol>::new());
    // Eta-expansion synthesises fresh closure parameters that must not capture
    // any name free in the supplied arguments. Mint the pool up front through the
    // one `&mut Interner` the entry point owns, so the lowering walk itself stays
    // over a shared `&`; `fresh_symbols` guarantees the names dodge every user
    // identifier (all interned by now) and each other.
    //
    // The eta pool is handed out through a PER-DEF monotonic cursor
    // ([`Lowerer::eta_base`] / [`Lowerer::eta_sym`]): each binding site reserves
    // its block and the cursor only advances within a def, so a nested eta-lambda
    // (a composed higher-order combinator such as `a |> andThen (\x -> b |>
    // andThen …)`) draws DISJOINT names rather than shadowing a still-live outer
    // one. Sizing therefore covers the SUM of eta demand along the deepest nesting
    // path per def, which `module_symbol_pool_counts` bounds; the `MAX_CALLEE_ARITY`
    // floor keeps a single partial-application gap covered in a `main`-only program
    // with no local defs. An overrun fails closed as a `CompilerBug`, never an
    // index panic, never a silent reuse.
    // The widest first-class / partial constructor draws one `eta_` (and, for a
    // hoisted complex arg, one `cap_`) symbol per remaining payload position. A
    // union constructor's arity is uncapped at the language surface, so it — not
    // the `MAX_CALLEE_ARITY` floor, which assumes stdlib-callable residuals — can
    // govern both pool sizes. Fold it into each so a wide first-class constructor
    // never overruns (which would fail closed as a `CompilerBug`, never compile).
    let max_ctor_arity = lower::max_ctor_arity_per_module(m);
    // Every body-derived pool size in ONE module walk, ahead of the mutable
    // mints below (the count is an immutable borrow; the two would otherwise
    // conflict within one `fresh_symbols` expression). Each field equals its
    // former standalone `count_*` / `max_*` walker.
    let pool_counts = lower::module_symbol_pool_counts(m, interner);
    // Mapper wraps draw an eta block sized by the mapper's solved type, which
    // the per-site charges above do not see; reserve it on top.
    let eta_params = interner
        .fresh_symbols(
            "eta_",
            pool_counts
                .max_live_eta_params
                .saturating_add(lower::max_mapper_wrap_eta_demand(m, types))
                .max(max_ctor_arity)
                .max(MAX_CALLEE_ARITY),
        )
        .map_err(homeless)?;
    // `cap_` (the hoisted-argument capture pool) is drawn positionally within a
    // single partial-application site, whose body is a `Call`/`Ctor` over already-
    // lowered args — no nested lowering, so its scope-local reuse is collision-free
    // and its sizing stays the per-module widest arity.
    let cap_params = interner
        .fresh_symbols(
            "cap_",
            lower::max_def_arity_per_module(m)
                .max(max_ctor_arity)
                .max(MAX_CALLEE_ARITY),
        )
        .map_err(homeless)?;
    // A destructuring parameter (tuple / record / alias / wildcard) has no single
    // source name; the lowerer gives it a synthetic binder from this pool and
    // (for the destructuring shapes) prepends a `Destructure` to the body. Sized
    // to the TOTAL number of non-variable param sites across every def head AND
    // every (possibly nested) lambda, and handed out through a monotonic cursor
    // so each site gets a GLOBALLY-unique name — a def param and a lambda param
    // inside its body can never collide on `arg_i` (no reliance on shadowing).
    // Minted through the same owned `&mut Interner`.
    let param_binders = interner
        .fresh_symbols("arg_", pool_counts.destructure_param_sites)
        .map_err(homeless)?;
    // AUD-01 seal fix: one fresh symbol per bare `any`-in-param-position
    // occurrence, so `split_typed_sig` never shares the single interned
    // `"any"` Symbol across two occurrences the checker independently pinned
    // to different concrete types. The count (an immutable borrow of
    // `interner`) is computed in its OWN statement, ahead of and separate
    // from the `fresh_symbols` mutable-mint call — the two borrows would
    // otherwise conflict within one expression.
    let any_param_site_count = lower::count_any_param_sites(m, interner);
    let any_param_binders = interner
        .fresh_symbols("anyp_", any_param_site_count)
        .map_err(homeless)?;
    // One bounded group of fresh binders per `Store.selectToList` /
    // `Store.selectToMaybe` call site, for the concrete per-column decode the
    // intercept emits there.
    let projection_decode_binders = interner
        .fresh_symbols("projdec_", pool_counts.projection_decode_sites)
        .map_err(homeless)?;
    // one fresh thunk-binder symbol per syntactic destructure-binder
    // `let` / single-arm product `case` site, consumed only when the bound
    // value's solved type contains a Decoder (the type gate runs post-solve,
    // inside the lowerer; this count is purely syntactic, so it over-counts
    // harmlessly).
    let destructure_thunk_binders = interner
        .fresh_symbols("destr_thunk_", pool_counts.destructure_thunk_sites)
        .map_err(homeless)?;
    // C2: one fresh `Vec` payload binder per `case`-arm site that nests a
    // list / cons sub-pattern inside a constructor payload.
    let nested_cons_binders = interner
        .fresh_symbols("ncons_", pool_counts.nested_cons_payload_sites)
        .map_err(homeless)?;
    // Sibling desugaring: one fresh `String` payload binder per `case`-arm site
    // that nests a string-literal sub-pattern directly inside a constructor
    // payload (`Just "live"`).
    let nested_strlit_binders = interner
        .fresh_symbols("nstrlit_", pool_counts.nested_strlit_payload_sites)
        .map_err(homeless)?;
    // One fresh binder per tuple-element position for the tuple-elem-rebind
    // synthesis: a multi-arm `case` on a non-literal tuple scrutinee with
    // direct list / cons columns is rewritten to bind the scrutinee's elements
    // to fresh temps and construct a synthetic literal-tuple scrutinee, enabling
    // the coerced-column backend path. Sized as an upper bound.
    let tuple_elem_binders = interner
        .fresh_symbols("telem_", pool_counts.tuple_elem_rebind_sites)
        .map_err(homeless)?;
    // The built-in `Maybe` / `Result` types + constructors are Prelude
    // built-ins (no `type` declaration), so the lowerer needs their symbols to
    // seed the variant-set / arity tables it would otherwise read from
    // `module.unions`. Mint them here through the owned `&mut Interner`.
    //
    // `SqlValue` / `SqlField` are Db Prelude built-ins following the same
    // pattern: they appear in typed Ipê code as if user-declared, but have no
    // `type` declaration in any Ipê source file — the compiler synthesises their
    // `EnumDef`s at lowering time when a Db kernel call is detected.
    let builtins = lower::BuiltinCtors {
        maybe: interner.intern("Maybe").map_err(homeless)?,
        result: interner.intern("Result").map_err(homeless)?,
        just: interner.intern("Just").map_err(homeless)?,
        nothing: interner.intern("Nothing").map_err(homeless)?,
        ok: interner.intern("Ok").map_err(homeless)?,
        err: interner.intern("Err").map_err(homeless)?,
        // ── SqlValue ──────────────────────────────────────────────────────────
        sqlvalue: interner.intern("SqlValue").map_err(homeless)?,
        sql_string: interner.intern("SqlString").map_err(homeless)?,
        sql_int: interner.intern("SqlInt").map_err(homeless)?,
        sql_float: interner.intern("SqlFloat").map_err(homeless)?,
        sql_bool: interner.intern("SqlBool").map_err(homeless)?,
        sql_bytes: interner.intern("SqlBytes").map_err(homeless)?,
        sql_time: interner.intern("SqlTime").map_err(homeless)?,
        sql_decimal: interner.intern("SqlDecimal").map_err(homeless)?,
        sql_money: interner.intern("SqlMoney").map_err(homeless)?,
        sql_null: interner.intern("SqlNull").map_err(homeless)?,
        // ── SqlField ──────────────────────────────────────────────────────────
        sqlfield: interner.intern("SqlField").map_err(homeless)?,
        set_field: interner.intern("SetField").map_err(homeless)?,
        omit_field: interner.intern("OmitField").map_err(homeless)?,
        // ── ProjectionTerm / ProjectionOperand ──────────────────────────
        projection_term: interner.intern("ProjectionTerm").map_err(homeless)?,
        column_term: interner.intern("ColumnTerm").map_err(homeless)?,
        literal_term: interner.intern("LiteralTerm").map_err(homeless)?,
        upper_term: interner.intern("UpperTerm").map_err(homeless)?,
        lower_term: interner.intern("LowerTerm").map_err(homeless)?,
        coalesce_term: interner.intern("CoalesceTerm").map_err(homeless)?,
        arith_term: interner.intern("ArithTerm").map_err(homeless)?,
        projection_operand: interner.intern("ProjectionOperand").map_err(homeless)?,
        operand_column: interner.intern("OperandColumn").map_err(homeless)?,
        operand_literal: interner.intern("OperandLiteral").map_err(homeless)?,
        arith_op: interner.intern("ArithOp").map_err(homeless)?,
        arith_add: interner.intern("ArithAdd").map_err(homeless)?,
        arith_sub: interner.intern("ArithSub").map_err(homeless)?,
        arith_mul: interner.intern("ArithMul").map_err(homeless)?,
        // ── Order ADT ─────────────────────────────────────────────────
        order: interner.intern("Order").map_err(homeless)?,
        lt: interner.intern("LT").map_err(homeless)?,
        eq: interner.intern("EQ").map_err(homeless)?,
        gt: interner.intern("GT").map_err(homeless)?,
        // ── Error / ErrorKind ────────────────────────────────────
        error: interner.intern("Error").map_err(homeless)?,
        errorkind: interner.intern("ErrorKind").map_err(homeless)?,
        ek_io: interner.intern("Io").map_err(homeless)?,
        ek_network: interner.intern("Network").map_err(homeless)?,
        ek_ffi: interner.intern("Ffi").map_err(homeless)?,
        ek_decode: interner.intern("Decode").map_err(homeless)?,
        ek_timeout: interner.intern("Timeout").map_err(homeless)?,
        ek_not_found: interner.intern("NotFound").map_err(homeless)?,
        ek_permission_denied: interner.intern("PermissionDenied").map_err(homeless)?,
        ek_invalid_input: interner.intern("InvalidInput").map_err(homeless)?,
        ek_conflict: interner.intern("Conflict").map_err(homeless)?,
        ek_unavailable: interner.intern("Unavailable").map_err(homeless)?,
        ek_unexpected: interner.intern("Unexpected").map_err(homeless)?,
        // ── ErrorDetails ─────────────────────────────────────────────────────
        errordetails: interner.intern("ErrorDetails").map_err(homeless)?,
        ed_ffi_panic: interner.intern("FfiPanic").map_err(homeless)?,
        ed_type_mismatch: interner.intern("TypeMismatch").map_err(homeless)?,
        ed_http_status: interner.intern("HttpStatus").map_err(homeless)?,
        ed_json_decode: interner.intern("JsonDecode").map_err(homeless)?,
        ed_custom: interner.intern("Custom").map_err(homeless)?,
        ed_database: interner.intern("Database").map_err(homeless)?,
        // ── DbFailure ADT ────────────────────────────────────────────────────
        db_failure: interner.intern("DbFailure").map_err(homeless)?,
        db_failure_ctors: lower::intern_db_failure_ctors(interner).map_err(homeless)?,
        http_method: interner.intern("HttpMethod").map_err(homeless)?,
        hm_get: interner.intern("Get").map_err(homeless)?,
        hm_post: interner.intern("Post").map_err(homeless)?,
        hm_put: interner.intern("Put").map_err(homeless)?,
        hm_delete: interner.intern("Delete").map_err(homeless)?,
        hm_patch: interner.intern("Patch").map_err(homeless)?,
        hm_head: interner.intern("Head").map_err(homeless)?,
        hm_options: interner.intern("Options").map_err(homeless)?,
        // ── BackoffStrategy ADT ─────────────────────────────────
        backoffstrategy: interner.intern("BackoffStrategy").map_err(homeless)?,
        bs_linear: interner.intern("Linear").map_err(homeless)?,
        bs_linear_with_jitter: interner.intern("LinearWithJitter").map_err(homeless)?,
        bs_exponential: interner.intern("Exponential").map_err(homeless)?,
        bs_exponential_with_jitter: interner.intern("ExponentialWithJitter").map_err(homeless)?,
        // ── RedirectPolicy ADT ─────────────────────────────────
        redirect_policy: interner.intern("RedirectPolicy").map_err(homeless)?,
        no_redirects: interner.intern("NoRedirects").map_err(homeless)?,
        follow_redirects: interner.intern("FollowRedirects").map_err(homeless)?,
        kernel_types: ipe_types::Builtins::new(interner).map_err(homeless)?,
    };
    lower::Lowerer::new(
        m,
        types,
        &*interner,
        lower::SymbolPools {
            eta_params,
            cap_params,
            param_binders,
            any_param_binders,
            projection_decode_binders,
            destructure_thunk_binders,
            nested_cons_binders,
            nested_strlit_binders,
            tuple_elem_binders,
        },
        &builtins,
        source_path,
        source_text,
    )
    .run()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipe_diagnostics::{Diagnostic, Feature, LowerError};
    use ipe_ir::{BinOp, Callee, Expr, IrType, KernelFn, Pat, TypeDef};

    /// Structural cross-check: every variant in the SSOT
    /// (`StdlibKernel::ACCESSOR_INTERCEPT_PLACEHOLDERS`) must be recognised by
    /// `is_accessor_intercept_placeholder`, and no other variant may be.
    ///
    /// This makes the predicate–SSOT agreement a compile-time or test-time
    /// invariant rather than a convention enforced only by review.  The lowering
    /// dispatch arms in `lower.rs` enumerate the same variants by kernel family
    /// and arity (those arms cannot be mechanically derived from a slice const —
    /// Rust `match` requires literal/const patterns); they are checked for
    /// correctness by the IPE-L0146 golden test and the
    /// `every_kernel_name_resolves` test in `ipe-runtime-rust`.
    #[test]
    fn accessor_intercept_placeholder_predicate_covers_ssot() {
        use ipe_kernels::StdlibKernel;

        // Every SSOT variant must satisfy the predicate.
        for &k in StdlibKernel::ACCESSOR_INTERCEPT_PLACEHOLDERS {
            assert!(
                k.is_accessor_intercept_placeholder(),
                "{k:?} is in ACCESSOR_INTERCEPT_PLACEHOLDERS but \
                 is_accessor_intercept_placeholder() returned false"
            );
        }

        // No other variant may satisfy the predicate (no phantom members).
        for k in StdlibKernel::ALL {
            let expected = StdlibKernel::ACCESSOR_INTERCEPT_PLACEHOLDERS.contains(k);
            assert_eq!(
                k.is_accessor_intercept_placeholder(),
                expected,
                "{k:?}: predicate={} but SSOT membership={}",
                k.is_accessor_intercept_placeholder(),
                expected
            );
        }
    }

    const GOLDEN: &str = include_str!("../../../../tests/golden/basics/Main.ipe");

    /// Parse → canonicalise → infer the golden module, then return the
    /// lowered program alongside the interner. Returns `None` (failing the
    /// caller's assertions) rather than panicking, per the no-panic gate.
    fn lower_golden() -> Option<(ipe_ir::Program, Interner)> {
        let mut i = Interner::new();
        let src = ipe_parse::parse_module(GOLDEN, &mut i).ok()?;
        let m = ipe_canon::canonicalise(&src, &mut i).ok()?;
        let types = ipe_types::infer(&m, &mut i).ok()?;
        let program = lower(&m, &types, &mut i, "", "").ok()?;
        Some((program, i))
    }

    fn find_func<'a>(
        module: &'a ipe_ir::Module,
        i: &Interner,
        name: &str,
    ) -> Option<&'a ipe_ir::Func> {
        module
            .funcs
            .iter()
            .find(|f| i.resolve(f.name) == Some(name))
    }

    #[test]
    fn lowers_one_module_with_main_entry() {
        let opt = lower_golden();
        assert!(opt.is_some(), "golden must lower");
        let Some((program, i)) = opt else { return };

        assert_eq!(program.modules.len(), 1);
        let Some(module) = program.modules.first() else {
            return;
        };
        assert_eq!(
            module
                .name
                .0
                .iter()
                .filter_map(|&s| i.resolve(s))
                .collect::<Vec<_>>(),
            vec!["Main"]
        );

        // entry points at the `main` func.
        let Some(main) = find_func(module, &i, "main") else {
            return;
        };
        assert_eq!(module.entry, Some(main.id));
    }

    // A `Msg` enum reached from `main` (via `toLabel`), so dead-type elimination
    // keeps it — the declaration-order lock below needs a *live* enum, since a
    // dead one is correctly pruned from the lowered module.
    const LIVE_ENUM: &str = "module Main exposing (main)\n\
         import Ipe.System as System\n\
         \n\
         type Msg = Increment | Decrement\n\
         \n\
         toLabel : Msg -> String\n\
         toLabel msg =\n\
         \x20   case msg of\n\
         \x20       Increment -> \"inc\"\n\
         \x20       Decrement -> \"dec\"\n\
         \n\
         main =\n\
         \x20   System.setenv \"M\" (toLabel Increment)\n";

    #[test]
    fn lowers_msg_enum_in_declaration_order() {
        let mut i = Interner::new();
        let opt = ipe_parse::parse_module(LIVE_ENUM, &mut i)
            .ok()
            .and_then(|s| ipe_canon::canonicalise(&s, &mut i).ok())
            .and_then(|m| ipe_types::infer(&m, &mut i).ok().map(|t| (m, t)))
            .and_then(|(m, t)| lower(&m, &t, &mut i, "", "").ok());
        assert!(opt.is_some(), "live-enum module must lower");
        let Some(program) = opt else { return };
        let Some(module) = program.modules.first() else {
            return;
        };

        assert_eq!(module.types.len(), 1);
        let Some(TypeDef::Enum(en)) = module.types.first() else {
            return;
        };
        assert_eq!(i.resolve(en.name), Some("Msg"));
        let variants: Vec<&str> = en
            .variants
            .iter()
            .filter_map(|v| i.resolve(v.name))
            .collect();
        assert_eq!(variants, vec!["Increment", "Decrement"]);
    }

    #[test]
    fn lowers_update_to_typed_func_with_exhaustive_match() {
        let opt = lower_golden();
        assert!(opt.is_some(), "golden");
        let Some((program, i)) = opt else { return };
        let Some(module) = program.modules.first() else {
            return;
        };

        let Some(update) = find_func(module, &i, "update") else {
            return;
        };

        // params: msg : Enum(Msg), count : Int.
        assert_eq!(update.params.len(), 2);
        let Some((p0, t0)) = update.params.first() else {
            return;
        };
        let Some((p1, t1)) = update.params.get(1) else {
            return;
        };
        assert_eq!(i.resolve(*p0), Some("msg"));
        assert!(
            matches!(t0, IrType::Enum { name, args, .. } if i.resolve(*name) == Some("Msg") && args.is_empty())
        );
        assert_eq!(i.resolve(*p1), Some("count"));
        assert_eq!(*t1, IrType::Int);

        // return type : Int.
        assert_eq!(update.ret, IrType::Int);

        // body: an exhaustive match with two arms.
        assert!(
            matches!(&update.body, Expr::Match(_)),
            "update body must be a Match"
        );
        let Expr::Match(m) = &update.body else { return };
        assert!(matches!(m.scrutinee(), Expr::Var(s) if i.resolve(*s) == Some("msg")));
        assert_eq!(m.arms().len(), 2);

        // first arm: Increment -> (count + 1).
        let Some(arm0) = m.arms().first() else { return };
        let ipe_ir::Pat::Ctor { variant, .. } = &arm0.pat else {
            return;
        };
        assert_eq!(i.resolve(*variant), Some("Increment"));
        assert!(matches!(
            &arm0.body,
            Expr::BinOp {
                op: BinOp::IntAdd,
                ..
            }
        ));

        // second arm: Decrement -> (count - 1).
        let Some(arm1) = m.arms().get(1) else { return };
        assert!(matches!(
            &arm1.body,
            Expr::BinOp {
                op: BinOp::IntSub,
                ..
            }
        ));
    }

    #[test]
    fn lowers_main_to_kernel_call_chain() {
        let opt = lower_golden();
        assert!(opt.is_some(), "golden");
        let Some((program, i)) = opt else { return };
        let Some(module) = program.modules.first() else {
            return;
        };

        let Some(main) = find_func(module, &i, "main") else {
            return;
        };
        assert!(main.params.is_empty());
        assert_eq!(main.ret, IrType::Task(Box::new(IrType::Unit)));

        // main = System.setenv "HOME" "x"
        assert!(
            matches!(&main.body, Expr::Call { .. }),
            "main body is a call"
        );
        let Expr::Call { callee, args, .. } = &main.body else {
            return;
        };
        assert_eq!(*callee, Callee::Kernel(KernelFn::SystemSetenv));
        assert_eq!(args.len(), 2);

        // Both args are string literals.
        assert!(matches!(args.first(), Some(Expr::Str(_))));
        assert!(matches!(args.get(1), Some(Expr::Str(_))));
    }

    /// Lower a free-standing module and return the body of `which`.
    fn lower_body(source: &str, which: &str) -> Option<(Expr, Interner)> {
        let mut i = Interner::new();
        let src = ipe_parse::parse_module(source, &mut i).ok()?;
        let m = ipe_canon::canonicalise(&src, &mut i).ok()?;
        let types = ipe_types::infer(&m, &mut i).ok()?;
        let program = lower(&m, &types, &mut i, "", "").ok()?;
        let module = program.modules.into_iter().next()?;
        let func = module
            .funcs
            .into_iter()
            .find(|f| i.resolve(f.name) == Some(which))?;
        Some((func.body, i))
    }

    /// Lower a free-standing module and return the whole [`ipe_ir::Func`] of
    /// `which` (so a test can inspect `type_params` / `params` / `ret`).
    fn lower_func(source: &str, which: &str) -> Option<(ipe_ir::Func, Interner)> {
        let mut i = Interner::new();
        let src = ipe_parse::parse_module(source, &mut i).ok()?;
        let m = ipe_canon::canonicalise(&src, &mut i).ok()?;
        let types = ipe_types::infer(&m, &mut i).ok()?;
        let program = lower(&m, &types, &mut i, "", "").ok()?;
        let module = program.modules.into_iter().next()?;
        let func = module
            .funcs
            .into_iter()
            .find(|f| i.resolve(f.name) == Some(which))?;
        Some((func, i))
    }

    #[test]
    fn tuple_parameter_lowers_to_synthetic_binder_plus_destructure() {
        // `fst (a, b) = a` — the tuple parameter has no single name, so it
        // becomes one synthetic parameter whose tuple type is `(a, b)` and the
        // body opens with a `Destructure` binding `(a, b) = <synthetic>`.
        let opt = lower_func(
            "module Main exposing (fst)\nfst : (a, b) -> a\nfst (a, b) =\n    a\n",
            "fst",
        );
        assert!(opt.is_some(), "fst must lower");
        let Some((func, i)) = opt else { return };
        assert_eq!(func.params.len(), 1, "one (synthetic) parameter");
        assert!(
            matches!(func.params.first(), Some((_, IrType::Tuple(es))) if es.len() == 2),
            "the parameter's type is a 2-element tuple, got {:?}",
            func.params.first().map(|(_, t)| t)
        );
        let Expr::Destructure {
            binder,
            value,
            body,
        } = &func.body
        else {
            assert!(false_marker(), "body is a Destructure, got {:?}", func.body);
            return;
        };
        assert!(
            matches!(binder, Pat::Tuple(es)
                if es.len() == 2
                    && matches!(es.first(), Some(Pat::Var(_)))
                    && matches!(es.get(1), Some(Pat::Var(_)))),
            "binder is `(a, b)`"
        );
        assert!(
            matches!(value.as_ref(), Expr::Var(s) if i.resolve(*s).is_some_and(|n| n.starts_with("arg_"))),
            "destructured value is the synthetic parameter"
        );
        assert!(
            matches!(body.as_ref(), Expr::Var(s) if i.resolve(*s) == Some("a")),
            "body returns `a`"
        );
    }

    #[test]
    fn single_arm_tuple_case_lowers_to_a_destructure() {
        // `case (1, 2) of (a, b) -> a + b` is an irrefutable destructure, not an
        // enum match — it lowers to a `Destructure`, not an `Expr::Match`.
        let opt = lower_body(
            "module Main exposing (v)\nv : Int\nv =\n    case (1, 2) of\n        (a, b) -> a + b\n",
            "v",
        );
        assert!(opt.is_some(), "v must lower");
        let Some((body, _i)) = opt else { return };
        let Expr::Destructure {
            binder,
            value,
            body,
        } = &body
        else {
            assert!(false_marker(), "body is a Destructure, got {body:?}");
            return;
        };
        assert!(
            matches!(binder, Pat::Tuple(es) if es.len() == 2),
            "binder is a 2-tuple"
        );
        assert!(
            matches!(value.as_ref(), Expr::Tuple(es) if es.len() == 2),
            "destructured value is the `(1, 2)` tuple"
        );
        assert!(
            matches!(
                body.as_ref(),
                Expr::BinOp {
                    op: BinOp::IntAdd,
                    ..
                }
            ),
            "body is `a + b`"
        );
    }

    #[test]
    fn unit_value_lowers_to_expr_unit() {
        // The `()` argument lowers to `Expr::Unit`.
        let opt = lower_body(
            "module Main exposing (v)\nuseUnit : () -> Int\nuseUnit u =\n    7\nv : Int\nv =\n    useUnit ()\n",
            "v",
        );
        assert!(opt.is_some(), "v must lower");
        let Some((body, _i)) = opt else { return };
        assert!(
            matches!(&body, Expr::Call { args, .. }
                if matches!(args.first(), Some(Expr::Unit))),
            "the call argument is `Expr::Unit`, got {body:?}"
        );
    }

    /// Lower a free-standing module, returning just the lowering diagnostic so a
    /// test can assert a not-yet gap surfaces as a `Diagnostic::Lower`. The
    /// `home` half of `lower`'s error tuple is irrelevant to these single-module
    /// gap assertions, so it is dropped here.
    fn lower_result(source: &str) -> Result<(), Diagnostic> {
        let mut i = Interner::new();
        let src = ipe_parse::parse_module(source, &mut i)?;
        let m = ipe_canon::canonicalise(&src, &mut i)?;
        let types = ipe_types::infer(&m, &mut i)?;
        lower(&m, &types, &mut i, "", "")
            .map(|_| ())
            .map_err(|(d, _home)| d)
    }

    #[test]
    fn generic_record_signature_lowers_to_generic_struct_field() {
        // `wrap : a -> { value : a }` — the parameter and the record field both
        // lower to `IrType::Generic(a)`, and `wrap` quantifies `[a]`.
        let opt = lower_func(
            "module Main exposing (wrap)\nwrap : a -> { value : a }\nwrap x =\n    { value = x }\n",
            "wrap",
        );
        assert!(opt.is_some(), "wrap must lower");
        let Some((func, i)) = opt else { return };
        // One type parameter, named `a`.
        assert_eq!(func.type_params.len(), 1, "wrap quantifies one type var");
        assert_eq!(
            func.type_params.first().and_then(|(s, _)| i.resolve(*s)),
            Some("a")
        );
        let Some(&(param_sym, bounds)) = func.type_params.first() else {
            return;
        };
        // A structurally-parametric variable carries no bounds.
        assert!(bounds.is_unbounded(), "wrap's `a` is an unbounded generic");
        // The single parameter is `IrType::Generic(a)`.
        assert!(
            matches!(func.params.first(), Some((_, IrType::Generic(s))) if *s == param_sym),
            "parameter lowers to Generic(a), got {:?}",
            func.params
        );
        // The return type is `{ value : Generic(a) }`.
        let IrType::Record(fields) = &func.ret else {
            assert!(false_marker(), "ret is a record, got {:?}", func.ret);
            return;
        };
        assert!(
            fields
                .values()
                .all(|t| matches!(t, IrType::Generic(s) if *s == param_sym)),
            "record field lowers to Generic(a), got {fields:?}"
        );
    }

    #[test]
    fn record_type_alias_lowers_to_concrete_struct() {
        // `type alias Box a = { value : a }`; `mkBox : Int -> Box Int` expands to
        // a concrete record `{ value : Int }` in the signature.
        let opt = lower_func(
            "module Main exposing (mkBox)\ntype alias Box a = { value : a }\nmkBox : Int -> Box Int\nmkBox n =\n    { value = n }\n",
            "mkBox",
        );
        assert!(opt.is_some(), "mkBox must lower");
        let Some((func, _)) = opt else { return };
        assert!(func.type_params.is_empty(), "mkBox is monomorphic");
        let IrType::Record(fields) = &func.ret else {
            assert!(false_marker(), "ret is a record, got {:?}", func.ret);
            return;
        };
        assert!(
            fields.values().all(|t| matches!(t, IrType::Int)),
            "alias field expands to Int, got {fields:?}"
        );
    }

    #[test]
    fn generic_record_update_is_a_lower_gap() {
        // Updating a generic record needs a `Clone`-bounded type parameter
        // (bounded generics are unsupported) — it surfaces as IPE-L0111, NOT broken Rust.
        let err = lower_result(
            "module Main exposing (setValue)\nsetValue : { value : a } -> a -> { value : a }\nsetValue r x =\n    { r | value = x }\n",
        );
        assert!(
            matches!(
                err,
                Err(Diagnostic::Lower {
                    msg: LowerError::Unsupported(Feature::BoundedRecordUpdate),
                    ..
                })
            ),
            "generic record update must be IPE-L0111, got {err:?}"
        );
    }

    #[test]
    fn monomorphic_record_update_still_lowers() {
        // A concrete record update keeps the b3 behaviour (no gate).
        let opt = lower_body(
            "module Main exposing (moveX)\nmoveX : { x : Int, y : Int } -> { x : Int, y : Int }\nmoveX p =\n    { p | x = 99 }\n",
            "moveX",
        );
        assert!(opt.is_some(), "monomorphic update must lower");
        let Some((body, _)) = opt else { return };
        assert!(
            matches!(&body, Expr::Update { .. }),
            "body is a record update, got {body:?}"
        );
    }

    #[test]
    fn lowers_full_arithmetic_with_precedence() {
        // `2 + 3 * 4` ⇒ Add(2, Mul(3, 4)).
        let opt = lower_body(
            "module Main exposing (v)\nv : Int\nv =\n    2 + 3 * 4\n",
            "v",
        );
        assert!(opt.is_some(), "v must lower");
        let Some((body, _)) = opt else { return };
        assert!(
            matches!(
                &body,
                Expr::BinOp {
                    op: BinOp::IntAdd,
                    ..
                }
            ),
            "body is Add(_, _)"
        );
        let Expr::BinOp { lhs, rhs, .. } = &body else {
            return;
        };
        assert!(matches!(lhs.as_ref(), Expr::Int(2)));
        assert!(
            matches!(
                rhs.as_ref(),
                Expr::BinOp {
                    op: BinOp::IntMul,
                    ..
                }
            ),
            "rhs is Mul(3, 4)"
        );
    }

    #[test]
    fn lowers_comparison_and_boolean_ops() {
        // `n > 10 && n < 100` ⇒ And(Gt(..), Lt(..)).
        let opt = lower_body(
            "module Main exposing (f)\nf : Int -> Bool\nf n =\n    n > 10 && n < 100\n",
            "f",
        );
        assert!(opt.is_some(), "f must lower");
        let Some((body, _)) = opt else { return };
        assert!(
            matches!(&body, Expr::BinOp { op: BinOp::And, .. }),
            "body is And(_, _)"
        );
        let Expr::BinOp { lhs, rhs, .. } = &body else {
            return;
        };
        assert!(matches!(lhs.as_ref(), Expr::BinOp { op: BinOp::Gt, .. }));
        assert!(matches!(rhs.as_ref(), Expr::BinOp { op: BinOp::Lt, .. }));
    }

    #[test]
    fn lowers_multi_binding_let_to_nested_lets() {
        // `let a = 1; b = a in a + b` ⇒ Let a (Let b (Add a b)).
        let opt = lower_body(
            "module Main exposing (v)\nv : Int\nv =\n    let\n        a = 1\n        b = a\n    in\n    a + b\n",
            "v",
        );
        assert!(opt.is_some(), "v must lower");
        let Some((body, i)) = opt else { return };
        let Expr::Let { name, value, body } = &body else {
            assert!(false_marker(), "outer is a Let, got {body:?}");
            return;
        };
        assert_eq!(i.resolve(*name), Some("a"), "outer binds a");
        assert!(matches!(value.as_ref(), Expr::Int(1)), "a = 1");
        // Inner: Let b = (Var a) in (Add a b).
        let Expr::Let {
            name: n2,
            value: v2,
            body: b2,
        } = body.as_ref()
        else {
            assert!(false_marker(), "inner is a Let");
            return;
        };
        assert_eq!(i.resolve(*n2), Some("b"), "inner binds b");
        assert!(
            matches!(v2.as_ref(), Expr::Var(s) if i.resolve(*s) == Some("a")),
            "b = a"
        );
        assert!(
            matches!(
                b2.as_ref(),
                Expr::BinOp {
                    op: BinOp::IntAdd,
                    ..
                }
            ),
            "in-body is a + b"
        );
    }

    #[test]
    fn lowers_inline_let_in_function_body() {
        // `let d = n + n in d` inside a typed function lowers to a single Let.
        let opt = lower_body(
            "module Main exposing (f)\nf : Int -> Int\nf n =\n    let d = n + n in d\n",
            "f",
        );
        assert!(opt.is_some(), "f must lower");
        let Some((body, i)) = opt else { return };
        assert!(
            matches!(&body, Expr::Let { name, .. } if i.resolve(*name) == Some("d")),
            "body is `let d = …`, got {body:?}"
        );
    }

    #[test]
    fn lowers_multi_way_if_to_nested_ifs() {
        // `if n > 0 then 1 else if n < 0 then 2 else 0` ⇒
        // If (n>0) 1 (If (n<0) 2 0): a right-nested chain of binary `If`s.
        let opt = lower_body(
            "module Main exposing (f)\nf : Int -> Int\nf n =\n    if n > 0 then\n        1\n    else if n < 0 then\n        2\n    else\n        0\n",
            "f",
        );
        assert!(opt.is_some(), "f must lower");
        let Some((body, _i)) = opt else { return };
        let Expr::If { cond, then_, else_ } = &body else {
            assert!(false_marker(), "outer is an If, got {body:?}");
            return;
        };
        assert!(
            matches!(cond.as_ref(), Expr::BinOp { op: BinOp::Gt, .. }),
            "outer cond is n > 0"
        );
        assert!(matches!(then_.as_ref(), Expr::Int(1)), "outer then is 1");
        // The else arm is the nested `if n < 0 then 2 else 0`.
        let Expr::If {
            cond: c2,
            then_: t2,
            else_: e2,
        } = else_.as_ref()
        else {
            assert!(false_marker(), "inner else is an If");
            return;
        };
        assert!(
            matches!(c2.as_ref(), Expr::BinOp { op: BinOp::Lt, .. }),
            "inner cond is n < 0"
        );
        assert!(matches!(t2.as_ref(), Expr::Int(2)), "inner then is 2");
        assert!(matches!(e2.as_ref(), Expr::Int(0)), "final else is 0");
    }

    /// A runtime `false` the optimiser cannot fold, so `assert!(false_marker())`
    /// fails the test without tripping `clippy::assertions_on_constants`.
    fn false_marker() -> bool {
        std::hint::black_box(false)
    }

    #[test]
    fn lowers_lambda_to_typed_closure_and_application_to_apply() {
        // `let inc = \x -> x + 1 in inc 41`: the binding value is a typed
        // `Lambda`, and `inc 41` (a local callee) lowers to `Apply`.
        let opt = lower_body(
            "module Main exposing (v)\nv : Int\nv =\n    let inc = \\x -> x + 1 in inc 41\n",
            "v",
        );
        assert!(opt.is_some(), "v must lower");
        let Some((body, i)) = opt else { return };
        let Expr::Let { value, body, .. } = &body else {
            assert!(false_marker(), "outer is a Let, got {body:?}");
            return;
        };
        // The let value is a one-parameter `Int -> Int` lambda.
        assert!(
            matches!(
                value.as_ref(),
                Expr::Lambda { params, ret, .. }
                    if params.len() == 1
                        && params.first().map(|(_, t)| t) == Some(&IrType::Int)
                        && *ret == IrType::Int
            ),
            "inc is a typed Int->Int lambda, got {value:?}"
        );
        // The `in` body applies the local `inc` via Apply.
        assert!(
            matches!(
                body.as_ref(),
                Expr::Apply { func, args }
                    if matches!(func.as_ref(), Expr::Var(s) if i.resolve(*s) == Some("inc"))
                        && args.len() == 1
            ),
            "inc 41 lowers to Apply, got {body:?}"
        );
    }

    #[test]
    fn lowers_inline_capturing_lambda_application() {
        // `let n = 10 in (\x -> x + n) 5`: the inline lambda is the callee, so
        // the application lowers to `Apply` over a `Lambda` (capturing `n`).
        let opt = lower_body(
            "module Main exposing (v)\nv : Int\nv =\n    let n = 10 in (\\x -> x + n) 5\n",
            "v",
        );
        assert!(opt.is_some(), "v must lower");
        let Some((body, _)) = opt else { return };
        let Expr::Let { body, .. } = &body else {
            assert!(false_marker(), "outer is a Let, got {body:?}");
            return;
        };
        assert!(
            matches!(
                body.as_ref(),
                Expr::Apply { func, args }
                    if matches!(func.as_ref(), Expr::Lambda { .. }) && args.len() == 1
            ),
            "applied inline lambda lowers to Apply over a Lambda, got {body:?}"
        );
    }

    #[test]
    fn lowers_remaining_operators() {
        // Cover Sub, Div, Eq, Neq, Le, Ge, Or paths through `binop`.
        for (src_op, want) in [
            ("a - b", BinOp::IntSub),
            ("a / b", BinOp::Div),
            ("a == b", BinOp::Eq),
            ("a /= b", BinOp::Neq),
            ("a <= b", BinOp::Le),
            ("a >= b", BinOp::Ge),
            ("a || b", BinOp::Or),
        ] {
            // Annotate to keep operand/result types concrete for each operator.
            // `/` (fdiv) is Float-typed, matching the backend.
            let sig = match want {
                BinOp::IntSub => "f : Int -> Int -> Int",
                BinOp::Div => "f : Float -> Float -> Float",
                BinOp::Or => "f : Bool -> Bool -> Bool",
                _ => "f : Int -> Int -> Bool",
            };
            let source = format!("module Main exposing (f)\n{sig}\nf a b =\n    {src_op}\n");
            let opt = lower_body(&source, "f");
            assert!(
                matches!(&opt, Some((Expr::BinOp { .. }, _))),
                "{src_op} must lower to a binop"
            );
            let Some((Expr::BinOp { op, .. }, _)) = opt else {
                continue;
            };
            assert_eq!(op, want, "operator {src_op}");
        }
    }

    #[test]
    fn lowers_int_and_float_arithmetic_to_typed_binop_variants() {
        // Int-typed `+`, `-`, `*` must lower to Int-specific wrapping variants.
        for (src_op, want) in [
            ("a + b", BinOp::IntAdd),
            ("a - b", BinOp::IntSub),
            ("a * b", BinOp::IntMul),
        ] {
            let source =
                format!("module Main exposing (f)\nf : Int -> Int -> Int\nf a b =\n    {src_op}\n");
            let opt = lower_body(&source, "f");
            assert!(
                matches!(&opt, Some((Expr::BinOp { .. }, _))),
                "{src_op} must lower to a binop"
            );
            let Some((Expr::BinOp { op, .. }, _)) = opt else {
                continue;
            };
            assert_eq!(op, want, "Int operator {src_op}");
        }
        // Float-typed `+`, `-`, `*` must lower to Float-specific infix variants.
        for (src_op, want) in [
            ("a + b", BinOp::FloatAdd),
            ("a - b", BinOp::FloatSub),
            ("a * b", BinOp::FloatMul),
        ] {
            let source = format!(
                "module Main exposing (f)\nf : Float -> Float -> Float\nf a b =\n    {src_op}\n"
            );
            let opt = lower_body(&source, "f");
            assert!(
                matches!(&opt, Some((Expr::BinOp { .. }, _))),
                "{src_op} must lower to a binop"
            );
            let Some((Expr::BinOp { op, .. }, _)) = opt else {
                continue;
            };
            assert_eq!(op, want, "Float operator {src_op}");
        }
    }

    #[test]
    fn tuple_value_lowers_to_ir_tuple() {
        // `v = (1, 2)` lowers to the IR tuple constructor over two Int literals.
        let opt = lower_body("module Main exposing (v)\nv =\n    (1, 2)\n", "v");
        assert!(
            matches!(&opt, Some((Expr::Tuple(es), _))
                if es.len() == 2
                    && matches!(es.first(), Some(Expr::Int(1)))
                    && matches!(es.get(1), Some(Expr::Int(2)))),
            "v lowers to `Tuple([Int(1), Int(2)])`, got {:?}",
            opt.as_ref().map(|(b, _)| b)
        );
    }

    #[test]
    fn tuple_return_type_lowers_to_ir_tuple_type() {
        // An untyped no-param binding's inferred tuple type flows to the func's
        // IR return type as `IrType::Tuple`.
        let mut i = Interner::new();
        let pipeline = (|| {
            let src =
                ipe_parse::parse_module("module Main exposing (v)\nv =\n    (1, 2)\n", &mut i)
                    .ok()?;
            let m = ipe_canon::canonicalise(&src, &mut i).ok()?;
            let types = ipe_types::infer(&m, &mut i).ok()?;
            lower(&m, &types, &mut i, "", "").ok()
        })();
        assert!(pipeline.is_some(), "v must lower");
        let Some(program) = pipeline else { return };
        let Some(module) = program.modules.first() else {
            return;
        };
        let Some(v) = find_func(module, &i, "v") else {
            return;
        };
        assert!(
            matches!(&v.ret, IrType::Tuple(es)
                if es.len() == 2
                    && matches!(es.first(), Some(IrType::Int))
                    && matches!(es.get(1), Some(IrType::Int))),
            "v's IR return type is `(Int, Int)`, got {:?}",
            v.ret
        );
    }

    /// Regression: `init : any -> Model` (any in PARAM position).
    ///
    /// Filtering the `any` symbol from `type_params` causes the backend's
    /// `GenericScope::rust_name` to ICE (IPE-I0001) because `params` still holds
    /// `IrType::Generic(any_sym)` while `type_params` is empty.
    ///
    /// The principled fix computes `type_params` from the structurally-used
    /// `IrType::Generic` set of the solved `params + ret`.  For `any` in param
    /// position the generic is structurally present → included in `type_params`.
    ///
    /// AUD-01 note: a SINGLE `any`-in-param occurrence now ALSO goes through
    /// the per-occurrence fresh-symbol substitution (`split_typed_sig`) — a
    /// lone occurrence isn't the AUD-01 bug (nothing to collide with), but the
    /// substitution applies uniformly regardless of occurrence count, so the
    /// `type_param`'s symbol is a synthetic `anyp_N` name here, not the
    /// literal `"any"` interned symbol. The backend renders `Generic` by
    /// TYPE-PARAM POSITION, not spelling (see `ipe_ir::ir`'s `Generic` doc
    /// comment), so this is not a behavior change worth asserting against —
    /// only that exactly one `type_param` exists and the param's `IrType`
    /// matches it.
    #[test]
    fn any_in_param_position_lowers_without_ice() {
        // `wrap : any -> Int` — `any` is in parameter position.
        // Before Bug-28 fix this would ICE (IPE-I0001 / CompilerBug via the
        // backend's GenericScope::rust_name); with the fix it must lower.
        let opt = lower_func(
            "module Main exposing (wrap)\nwrap : any -> Int\nwrap _ =\n    42\n",
            "wrap",
        );
        assert!(
            opt.is_some(),
            "wrap : any -> Int must lower without ICE (Bug-28 regression)"
        );
        let Some((func, i)) = opt else { return };

        // Exactly one type_param.
        assert_eq!(
            func.type_params.len(),
            1,
            "type_params must have exactly one entry, got {:?}",
            func.type_params
                .iter()
                .map(|(s, _)| i.resolve(*s))
                .collect::<Vec<_>>()
        );
        let Some((any_sym, _)) = func.type_params.first() else {
            return;
        };

        // The parameter's IrType is Generic(any_sym).
        assert_eq!(func.params.len(), 1, "one parameter");
        let Some((_, param_ty)) = func.params.first() else {
            return;
        };
        assert!(
            matches!(param_ty, IrType::Generic(s) if *s == *any_sym),
            "param type must be Generic(any_sym), got {param_ty:?}"
        );

        // Return type is Int (the annotation's explicit return).
        assert_eq!(func.ret, IrType::Int, "return type must be Int");
    }

    /// Regression for AUD-01 (seal): TWO `any` occurrences in one param-position
    /// annotation must lower to TWO DISTINCT `Generic` symbols, each declared
    /// in `type_params` — not collapse onto one shared `Generic(any_sym)`.
    ///
    /// The checker gives every `any` occurrence a fresh flex UV per occurrence
    /// (`ipe_types::constrain`), so `f : any -> any -> Int` called `f "x" 3` is
    /// well-typed and `ipe` accepts it. Pre-fix, BOTH params lowered to the
    /// SAME `IrType::Generic(any_sym)` (the interned `"any"` Symbol is shared),
    /// so the backend emitted `fn main_f<T1>(a: T1, b: T1) -> i64` — a call
    /// passing a `String` and an `Int` at the two positions failed `cargo build`
    /// with E0308 despite `ipe` having accepted the program
    /// (exit-0-then-cargo-fail). Post-fix, `split_typed_sig` gives each
    /// occurrence its OWN fresh symbol from `any_param_binders`, and
    /// `type_params` includes both (unioned in alongside `free_vars`) — the
    /// backend renders `IrType::Generic` by TYPE-PARAM POSITION, not by symbol
    /// spelling, so two distinct symbols is sufficient for two distinct Rust
    /// generics (`fn f<T1, T2>(a: T1, b: T2)`), each independently
    /// monomorphized at the call site by rustc.
    #[test]
    fn any_params_get_distinct_generics_not_a_shared_one() {
        let opt = lower_func(
            "module Main exposing (f)\nf : any -> any -> Int\nf _ _ =\n    0\n",
            "f",
        );
        assert!(
            opt.is_some(),
            "f : any -> any -> Int (two `any` occurrences) must lower"
        );
        let Some((func, i)) = opt else { return };

        assert_eq!(func.params.len(), 2, "two parameters");
        let (Some((_, a_ty)), Some((_, b_ty))) = (func.params.first(), func.params.get(1)) else {
            return;
        };

        // Both params ARE Generic (this is legitimate structural polymorphism
        // once each occurrence is independent) — but with DISTINCT symbols.
        let (IrType::Generic(a_sym), IrType::Generic(b_sym)) = (a_ty, b_ty) else {
            assert!(
                false_marker(),
                "both params must be IrType::Generic, got a={a_ty:?} b={b_ty:?}"
            );
            return;
        };
        assert_ne!(
            a_sym, b_sym,
            "the two `any` occurrences must NOT share one Generic symbol — \
             a shared symbol is exactly the AUD-01 bug (fn f<T1>(a:T1,b:T1))"
        );

        // Both fresh symbols must be DECLARED in `type_params` — an emitted
        // Generic with no matching type_params entry is an undeclared Rust
        // generic (invalid emission), the failure mode the type_params-union
        // fix (alongside the fresh-symbol fix) closes.
        let declared: Vec<_> = func.type_params.iter().map(|(s, _)| *s).collect();
        assert!(
            declared.contains(a_sym),
            "param `a`'s Generic symbol must be declared in type_params, got {:?}",
            declared.iter().map(|s| i.resolve(*s)).collect::<Vec<_>>()
        );
        assert!(
            declared.contains(b_sym),
            "param `b`'s Generic symbol must be declared in type_params, got {:?}",
            declared.iter().map(|s| i.resolve(*s)).collect::<Vec<_>>()
        );
        assert_eq!(func.ret, IrType::Int, "return type must be Int");
    }

    // ── Wildcard-`any` row-containment guard ──────────────────────────────────
    //
    // A wildcard-`any` param whose body reads a record field is lowered to a
    // row-generic. The ONLY routable use of that generic in the body is a direct
    // field read; every other flow (let-alias, call-arg, relay through another
    // function) reaches the backend as a bare generic and would cause
    // E0609/E0277 at `cargo build` time. The guard is scheduled AFTER the
    // erasure block so it catches both the explicit-row-annotation path and the
    // wildcard-erasure path.

    /// `let q = p in q.name` — the `any` param is aliased before the field is
    /// read. After erasure `p` is `RowGeneric`; the let-rebind makes `q` flow
    /// as the row value, which escapes direct-access containment.
    #[test]
    fn any_param_let_alias_before_field_read_is_rejected() {
        let err = lower_result(
            "module Main exposing (f)\n\
             f : any -> String\n\
             f p =\n\
             \x20   let\n\
             \x20       q = p\n\
             \x20   in\n\
             \x20   q.name\n",
        );
        assert!(
            matches!(
                err,
                Err(Diagnostic::Lower {
                    msg: LowerError::Unsupported(Feature::RowPolyRecordAnnotation),
                    ..
                })
            ),
            "let-alias of an `any` row param must be IPE-L0131, got {err:?}"
        );
    }

    /// `relay : any -> String; relay x = getField x` — the `any` param is
    /// passed as a call argument to another function. After erasure `x` is
    /// `RowGeneric`; it flows as an argument (escape) rather than only as a
    /// direct field-read receiver.
    #[test]
    fn any_param_passed_as_call_arg_is_rejected() {
        let err = lower_result(
            "module Main exposing (relay)\n\
             getField p = p.name\n\
             relay : any -> String\n\
             relay x =\n\
             \x20   getField x\n",
        );
        assert!(
            matches!(
                err,
                Err(Diagnostic::Lower {
                    msg: LowerError::Unsupported(Feature::RowPolyRecordAnnotation),
                    ..
                })
            ),
            "passing an `any` row param as a call arg must be IPE-L0131, got {err:?}"
        );
    }

    /// `firstName : any -> String; firstName p = snd p p` where `snd a b = a.name`
    /// — the `any` param appears in both argument positions of a two-argument
    /// call. After erasure `p` is `RowGeneric`; the escape guard fires on the
    /// first occurrence (call-arg position is not a direct-access receiver).
    #[test]
    fn any_param_in_two_arg_call_position_is_rejected() {
        let err = lower_result(
            "module Main exposing (firstName)\n\
             snd a b = a.name\n\
             firstName : any -> String\n\
             firstName p =\n\
             \x20   snd p p\n",
        );
        assert!(
            matches!(
                err,
                Err(Diagnostic::Lower {
                    msg: LowerError::Unsupported(Feature::RowPolyRecordAnnotation),
                    ..
                })
            ),
            "an `any` row param in call-arg position must be IPE-L0131, got {err:?}"
        );
    }
}
