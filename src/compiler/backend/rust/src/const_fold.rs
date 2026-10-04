//! Phase-2 partial evaluation — fold a pure literal builder pipeline to a
//! constant.
//!
//! A pure builder pipeline whose every leaf is a literal
//! (`defaultSpec "spin" |> withDuration 300 |> withEasing easeInOut |>
//! withKeyframes […]`, rendered through `buildShorthandTail` /
//! `buildKeyframesBody`) computes a value that does not depend on the `Model`,
//! any effect, or any run-time input. [`fold_const`] evaluates such an
//! expression to a [`ConstValue`] IFF every sub-expression is a literal OR an
//! application of a PROVEN-PURE function over already-constant arguments,
//! returning `None` the instant it meets anything else (a `Var` it cannot
//! resolve, a `Model` field access, an impure kernel, a non-constant argument).
//!
//! The point of folding early: a folded [`ConstValue::Str`] substituted back
//! into the kernel-call argument makes the argument a DIRECT [`Expr::Str`], so
//! the appearance-literal registry ([`crate::emit_ui_plan::appearance_literal_args`])
//! hot-swaps it under `IPE_WATCH_HOT_APPEARANCE` exactly as it already
//! hot-swaps a hand-written literal — no registry change. The folded literal
//! then flows through the SAME emit and render sink as an unfolded one (it is
//! the same value, computed at compile time instead of run time), so the sink
//! gates (`SafeCssValue` / `sink_safe_keyframes_body`) still run at render:
//! dev == prod, no sink bypass.
//!
//! ## Soundness
//!
//! * Evaluation is FUEL-BOUNDED: a step counter decremented on every
//!   sub-expression visit; exhaustion returns `None` rather than looping at
//!   compile time (the "bounded by construction" rule). A pipeline that would
//!   not terminate — or is merely larger than the budget — recompiles as an
//!   unfolded computed argument, which is correct, just slower.
//! * A function is evaluated through its body ONLY when it is proven pure: a
//!   [`KernelFn`] with no security-relevant [`Capability`] (the reused kernel
//!   analysis), or a user stdlib function on the explicit whitelist below. A
//!   `Model`-dependent, effectful, or non-constant argument never folds, so a
//!   `Model`-dependent duration correctly recompiles.
//!
//! ## Whitelist scope
//!
//! There is no general whole-program purity result for USER functions here, so
//! evaluation through a user function body is gated by an explicit whitelist:
//! the value builders of `Ipe.Ui.Animation` and `Ipe.Css`. This is the current
//! scope — the two appearance-builder modules whose pipelines the appearance
//! hot-swap targets. Any user function outside the whitelist yields `None` (the
//! conservative recompile fallback), never an unsound fold.

use std::collections::BTreeMap;

use ipe_intern::{Interner, Symbol};
use ipe_ir::{BinOp, Callee, Expr, Func, FuncId, KernelFn, ModPath, Pat, Program};

use crate::emit_ui_plan::{LitKind, appearance_literal_args};

/// The starting evaluation budget: the maximum number of sub-expression visits
/// one [`fold_const`] call may perform before giving up with `None`. Sized
/// generously for a realistic appearance pipeline (a `withKeyframes` list of a
/// few frames, each a handful of props) while staying finite — a pathological
/// or genuinely large input exhausts the budget and recompiles unfolded.
const FUEL: u32 = 100_000;

/// The maximum native recursion depth [`eval`] may reach before returning
/// `None`. Fuel bounds total WORK; this separately bounds DEPTH, so a
/// pathologically deep (but under-fuel) nested expression returns `None`
/// instead of overflowing the compile-time native stack. A realistic
/// appearance pipeline nests only a handful of levels, far under this bound.
const MAX_DEPTH: u32 = 512;

/// A compile-time constant produced by evaluating a pure literal pipeline.
///
/// Covers exactly the literal kinds the whitelisted pure builders produce and
/// consume: scalars (`Int` / `Float` / `Str` / `Bool`), homogeneous `List`s,
/// records (field name → value), and tagged-union constructor values. A value
/// the evaluator cannot represent here is never folded — [`fold_const`] returns
/// `None` instead of an approximate constant.
#[derive(Clone, Debug, PartialEq)]
pub enum ConstValue {
    Int(i64),
    Float(f64),
    Str(String),
    Bool(bool),
    /// A list value — its elements in order.
    List(Vec<Self>),
    /// A record value — field name → constant, keyed for order-independent
    /// field lookup during an `Access`.
    Record(BTreeMap<Symbol, Self>),
    /// A tagged-union constructor value: the constructor name and its (already
    /// constant) payload arguments in declared order. A nullary constructor has
    /// an empty payload.
    Ctor {
        variant: Symbol,
        args: Vec<Self>,
    },
    /// A tuple value — its elements in order.
    Tuple(Vec<Self>),
}

impl ConstValue {
    /// The [`Expr`] literal this constant substitutes back into the IR, when it
    /// has a direct literal form. A folded [`ConstValue::Str`] becomes an
    /// [`Expr::Str`] the downstream emit and the appearance registry treat
    /// exactly as a hand-written literal. Only the scalar kinds have a direct
    /// literal `Expr`; a folded list / record / ctor is an intermediate value
    /// on the way to a scalar, never itself substituted, so it returns `None`.
    #[must_use]
    pub fn to_literal_expr(&self) -> Option<Expr> {
        match self {
            Self::Int(n) => Some(Expr::Int(*n)),
            Self::Float(f) => Some(Expr::Float(*f)),
            Self::Str(s) => Some(Expr::Str(s.clone())),
            Self::Bool(b) => Some(Expr::Bool(*b)),
            Self::List(_) | Self::Record(_) | Self::Ctor { .. } | Self::Tuple(_) => None,
        }
    }
}

/// The evaluation environment: the whole-program function table (for evaluating
/// through a whitelisted user-function or kernel-wrapper body), the interner
/// (to resolve a module / function name against the whitelist), and the
/// per-call local bindings (a parameter symbol → its already-constant value).
pub struct FoldEnv<'a> {
    funcs: &'a BTreeMap<FuncId, &'a Func>,
    interner: &'a Interner,
    locals: BTreeMap<Symbol, ConstValue>,
}

impl<'a> FoldEnv<'a> {
    /// Build an environment over a whole-program `FuncId → Func` table and the
    /// interner. Locals start empty; a function body evaluation binds the
    /// parameters before descending.
    #[must_use]
    pub const fn new(funcs: &'a BTreeMap<FuncId, &'a Func>, interner: &'a Interner) -> Self {
        Self {
            funcs,
            interner,
            locals: BTreeMap::new(),
        }
    }
}

/// Evaluate `expr` to a [`ConstValue`] if it is a pure computation over
/// compile-time constants, else `None`.
///
/// This is the public entry: it seeds the fuel budget and delegates to the
/// recursive [`eval`]. `None` means "not a compile-time constant" — either
/// genuinely (a `Model`-dependent or effectful sub-expression) or
/// conservatively (an expression shape or function the evaluator does not
/// cover, or fuel exhaustion). Every `None` path is safe: the caller leaves the
/// expression unfolded and it emits exactly as before.
#[must_use]
pub fn fold_const(expr: &Expr, env: &FoldEnv) -> Option<ConstValue> {
    let mut budget = Budget {
        fuel: FUEL,
        depth: 0,
    };
    eval(expr, env, &mut budget)
}

/// Phase-2 partial evaluation over a whole [`Program`].
///
/// Folds every pure literal builder pipeline that feeds an appearance-kernel
/// argument into a direct literal, so the appearance-literal registry hot-swaps
/// it downstream.
///
/// For each `Call` to a kernel `k` in every function body, an argument sitting
/// in a hoist-eligible position of the registry ([`appearance_literal_args`])
/// whose [`fold_const`] result is a scalar literal of that position's
/// [`LitKind`] is REPLACED by the folded [`Expr`] literal. Every other argument
/// — and every
/// non-appearance kernel call — is left untouched. The substituted value is the
/// SAME value the runtime would have computed, so downstream emit and the render
/// sink are unaffected except that the argument is now a direct literal the
/// registry recognises (dev == prod).
///
/// The pass is:
/// * **Sound** — it only ever substitutes a proven-constant value equal to the
///   runtime computation, and only in a position the registry already marks as
///   inert appearance data; a `Model`-dependent argument folds to `None` and is
///   left to recompile.
/// * **Idempotent** — a second run sees a direct literal in the folded position,
///   which folds to the identical literal, a no-op substitution.
/// * **Order-independent** — the fold of one argument reads no mutable state the
///   fold of another writes; the whole-program function snapshot it evaluates
///   against is taken once, up front, and never mutated during the walk.
pub fn fold_program(program: &mut Program, interner: &Interner) {
    // A snapshot of every function keyed by id, taken before any body is
    // rewritten. The evaluator reads whitelisted builder bodies from this
    // immutable snapshot while the walk rewrites the program's own bodies — so a
    // fold never observes a half-rewritten body, keeping the pass
    // order-independent.
    let snapshot: BTreeMap<FuncId, Func> = program
        .modules
        .iter()
        .flat_map(|m| m.funcs.iter().cloned().map(|f| (f.id, f)))
        .collect();
    let func_refs: BTreeMap<FuncId, &Func> = snapshot.iter().map(|(id, f)| (*id, f)).collect();

    for module in &mut program.modules {
        for func in &mut module.funcs {
            let body = std::mem::replace(&mut func.body, Expr::Unit);
            func.body = fold_expr(body, &func_refs, interner);
        }
    }
}

/// Rewrite appearance-kernel arguments to folded literals throughout one owned
/// expression. Descends into every sub-expression first (so a nested appearance
/// call inside a larger body is reached), then, at each appearance-kernel
/// `Call`, substitutes any eligible argument whose fold produces a
/// kind-matching literal. Every other node is rebuilt unchanged.
#[allow(clippy::too_many_lines)] // one arm per Expr variant — the exhaustive rebuild IS the pass
fn fold_expr(expr: Expr, funcs: &BTreeMap<FuncId, &Func>, interner: &Interner) -> Expr {
    // A boxed sub-expression rewritten in place.
    let go_box = |b: Box<Expr>| -> Box<Expr> { Box::new(fold_expr(*b, funcs, interner)) };
    let go_vec = |v: Vec<Expr>| -> Vec<Expr> {
        v.into_iter()
            .map(|e| fold_expr(e, funcs, interner))
            .collect()
    };

    match expr {
        // Leaves and non-expression carriers pass through untouched.
        Expr::Int(_)
        | Expr::Bool(_)
        | Expr::Float(_)
        | Expr::Str(_)
        | Expr::CustomElementRef { .. }
        | Expr::Char(_)
        | Expr::Unit
        | Expr::Var(_)
        | Expr::CloneVar(_)
        | Expr::FuncValue { .. }
        | Expr::TailRecur { .. } => expr,

        Expr::Ctor {
            home,
            ty,
            variant,
            args,
        } => Expr::Ctor {
            home,
            ty,
            variant,
            args: go_vec(args),
        },
        Expr::BinOp { op, lhs, rhs } => Expr::BinOp {
            op,
            lhs: go_box(lhs),
            rhs: go_box(rhs),
        },
        Expr::Let { name, value, body } => Expr::Let {
            name,
            value: go_box(value),
            body: go_box(body),
        },
        Expr::Destructure {
            binder,
            value,
            body,
        } => Expr::Destructure {
            binder,
            value: go_box(value),
            body: go_box(body),
        },
        Expr::If { cond, then_, else_ } => Expr::If {
            cond: go_box(cond),
            then_: go_box(then_),
            else_: go_box(else_),
        },
        Expr::Match(m) => Expr::Match(m.map_bodies(
            |scrut| fold_expr(scrut, funcs, interner),
            |_pat, body, guard| {
                (
                    fold_expr(body, funcs, interner),
                    guard.map(|g| fold_expr(g, funcs, interner)),
                )
            },
        )),
        Expr::Tuple(elems) => Expr::Tuple(go_vec(elems)),
        Expr::List { elem, items } => Expr::List {
            elem,
            items: go_vec(items),
        },
        Expr::Cons { head, tail } => Expr::Cons {
            head: go_box(head),
            tail: go_box(tail),
        },
        Expr::ListIndexClone { list, index, elem } => Expr::ListIndexClone {
            list: go_box(list),
            index,
            elem,
        },
        Expr::ListLenCheck { list, len, exact } => Expr::ListLenCheck {
            list: go_box(list),
            len,
            exact,
        },
        Expr::Record { fields, ty } => Expr::Record {
            fields: fields
                .into_iter()
                .map(|(n, v)| (n, fold_expr(v, funcs, interner)))
                .collect(),
            ty,
        },
        Expr::Access {
            record,
            field,
            field_ty,
        } => {
            let folded_record = fold_expr(*record, funcs, interner);
            // Record projection: an access into a DIRECT record literal is the
            // field's own value. Reducing it here drops the surrounding record
            // literal wherever only one field is used — so a specialized builder's
            // residual (`(<inlined Spec>).respectReducedMotion`) no longer drags
            // the whole record, and every OTHER field's inline literal (an unused
            // `duration`) disappears with it. A field the literal does not carry
            // (impossible for well-typed source) leaves the access untouched.
            if let Expr::Record { fields, .. } = &folded_record
                && let Some((_, value)) = fields.iter().find(|(name, _)| *name == field)
            {
                return value.clone();
            }
            Expr::Access {
                record: Box::new(folded_record),
                field,
                field_ty,
            }
        }
        Expr::Update { record, fields } => Expr::Update {
            record: go_box(record),
            fields: fields
                .into_iter()
                .map(|(n, v)| (n, fold_expr(v, funcs, interner)))
                .collect(),
        },
        Expr::Lambda { params, ret, body } => Expr::Lambda {
            params,
            ret,
            body: go_box(body),
        },
        Expr::SharedLambda { params, ret, body } => Expr::SharedLambda {
            params,
            ret,
            body: go_box(body),
        },
        Expr::OnceLambda {
            params,
            ret,
            body,
            capture,
        } => Expr::OnceLambda {
            params,
            ret,
            body: go_box(body),
            capture,
        },
        Expr::Apply { func, args } => Expr::Apply {
            func: go_box(func),
            args: go_vec(args),
        },
        Expr::TaskSeq { effect, rest } => Expr::TaskSeq {
            effect: go_box(effect),
            rest: go_box(rest),
        },
        Expr::TailLoop { params, body } => Expr::TailLoop {
            params,
            body: go_box(body),
        },
        Expr::Call {
            callee,
            args,
            pin,
            on_form,
        } => {
            let args = go_vec(args);
            // A call to a whitelisted builder over all-constant arguments — e.g.
            // `Animation.attribute (defaultSpec "spin" |> withDuration 300 |>
            // …)` — specializes: its body is inlined with the constant argument
            // expressions substituted for the parameters, then that residual is
            // itself folded. The residual is the builder's `Ui.animate` (kernel)
            // call whose scalar arguments (`buildShorthandTail spec`, …) are now
            // closed constant pipelines that fold to direct literals, so the
            // appearance registry hot-swaps them. A call whose arguments are not
            // all constant does not specialize and emits unchanged.
            if let Some(residual) = specialize_whitelisted_call(&callee, &args, funcs, interner) {
                return residual;
            }
            let args = fold_appearance_args(&callee, args, funcs, interner);
            Expr::Call {
                callee,
                args,
                pin,
                on_form,
            }
        }
    }
}

/// Specialize a call to a whitelisted builder function whose every argument is
/// already a compile-time constant: inline the function body with each constant
/// argument EXPRESSION substituted for its parameter, then recursively fold the
/// residual (which surfaces the inner appearance-kernel call with now-constant
/// scalar arguments). Returns `None` — leaving the call unchanged — when the
/// callee is not a whitelisted function, an argument is not constant, or the
/// arity does not match.
///
/// Substituting the argument EXPRESSIONS (not their scalar values) is what lets
/// a record-typed argument (the `Spec`) inline: the residual body's
/// `spec.duration` becomes `(<literal record>).duration`, a closed constant the
/// downstream fold reduces. Only a call whose arguments are all constant
/// specializes, so the inlined body is fully determined and the residual carries
/// no free parameter.
fn specialize_whitelisted_call(
    callee: &Callee,
    args: &[Expr],
    funcs: &BTreeMap<FuncId, &Func>,
    interner: &Interner,
) -> Option<Expr> {
    let Callee::Kernel(_) = callee else {
        let Callee::Func(id) = callee else {
            return None;
        };
        let func = funcs.get(id)?;
        if !is_whitelisted_func(func, interner) || func.params.len() != args.len() {
            return None;
        }
        let env = FoldEnv::new(funcs, interner);

        // Scalar result: the whole call folds to a scalar constant (a
        // `lengthToString` / `colorToString` / `easingToCss` builder returns a
        // `String`). Replace the call outright with its compact direct literal —
        // no body inlining, so no bloat.
        let call = Expr::Call {
            callee: callee.clone(),
            args: args.to_vec(),
            pin: ipe_ir::CallPin::None,
            on_form: ipe_ir::OnFormKind::NotForm,
        };
        if let Some(lit) = fold_const(&call, &env).and_then(|c| c.to_literal_expr()) {
            return Some(lit);
        }

        // Non-scalar result (an `Attribute` / element the builder constructs,
        // e.g. `Animation.attribute`): the call itself has no scalar literal
        // form, but inlining its body surfaces the inner appearance-kernel call
        // whose SCALAR arguments then fold to direct literals. Only worth doing
        // when every argument is a proven constant, so the inlined body is fully
        // determined and carries no free (Model-dependent) sub-expression.
        //
        // The `image` veneer is exempt from the all-constant requirement: its
        // `<img>` config carries a computed `src` (a data-URI / URL builder that
        // never folds to a scalar) alongside the direct-literal `description` the
        // appearance registry targets. Inlining substitutes the argument
        // EXPRESSIONS verbatim, so a non-constant field reappears unchanged and in
        // its original scope (the inline replaces the call in place — no new
        // binder, no capture); the emit-time record-native hoist then hoists only
        // a field that is STILL a direct literal after projection, and a
        // `Model`-dependent `description` stays a non-literal and recompiles. So
        // the relaxation cannot hoist a computed value — it only lets the constant
        // `description` reach the registry past a computed `src`.
        let is_image_veneer = modpath_is(&func.home, &["Ipe", "Ui"], interner)
            && interner.resolve(func.name) == Some("image");
        // Fold each argument once. The all-constant gate reads these, and the
        // substitution below reuses a scalar fold as its already-reduced literal so
        // the inlined body's fold does not re-walk that argument a further time.
        let arg_folds: Vec<Option<ConstValue>> = args.iter().map(|a| fold_const(a, &env)).collect();
        if !is_image_veneer && arg_folds.iter().any(Option::is_none) {
            return None;
        }
        // A tail-recursive builder body carries a `TailLoop` / `TailRecur` that
        // is only valid in tail position; inlining it into a non-tail argument
        // position would strand the `TailRecur` on the non-tail emit path
        // (a `CompilerBug`). Such a body is never inlined — it recompiles,
        // correctly, unfolded.
        if body_has_tail_construct(&func.body) {
            return None;
        }
        let mut subst = BTreeMap::new();
        for (((param, _), arg), fold) in func.params.iter().zip(args).zip(&arg_folds) {
            // A scalar-folding argument substitutes as its direct literal (the value
            // the inlined body's fold would reduce it to anyway); every other argument
            // substitutes verbatim so its own expression re-folds in place.
            let replacement = fold
                .as_ref()
                .and_then(ConstValue::to_literal_expr)
                .unwrap_or_else(|| arg.clone());
            subst.insert(*param, replacement);
        }
        let inlined = substitute(func.body.clone(), &subst);
        return Some(fold_expr(inlined, funcs, interner));
    };
    // A kernel callee never specializes through this path (it has no user body
    // to inline); its appearance arguments fold via `fold_appearance_args`.
    None
}

/// Whether an expression contains a `TailLoop` or `TailRecur` anywhere — the
/// tail-position-only constructs the lowerer's TCO rewrite introduces. A body
/// carrying one cannot be inlined into a non-tail argument position, so
/// [`specialize_whitelisted_call`] refuses it.
fn body_has_tail_construct(expr: &Expr) -> bool {
    match expr {
        Expr::TailLoop { .. } | Expr::TailRecur { .. } => true,

        Expr::Int(_)
        | Expr::Bool(_)
        | Expr::Float(_)
        | Expr::Str(_)
        | Expr::CustomElementRef { .. }
        | Expr::Char(_)
        | Expr::Unit
        | Expr::Var(_)
        | Expr::CloneVar(_)
        | Expr::FuncValue { .. } => false,

        Expr::Ctor { args, .. } | Expr::Tuple(args) | Expr::Apply { args, .. } => {
            args.iter().any(body_has_tail_construct)
        }
        Expr::List { items, .. } => items.iter().any(body_has_tail_construct),
        Expr::BinOp { lhs, rhs, .. }
        | Expr::Cons {
            head: lhs,
            tail: rhs,
        } => body_has_tail_construct(lhs) || body_has_tail_construct(rhs),
        Expr::Let { value, body, .. } | Expr::Destructure { value, body, .. } => {
            body_has_tail_construct(value) || body_has_tail_construct(body)
        }
        Expr::If { cond, then_, else_ } => {
            body_has_tail_construct(cond)
                || body_has_tail_construct(then_)
                || body_has_tail_construct(else_)
        }
        Expr::Match(m) => {
            body_has_tail_construct(m.scrutinee())
                || m.arms().iter().any(|a| {
                    body_has_tail_construct(&a.body)
                        || a.guard.as_ref().is_some_and(body_has_tail_construct)
                })
        }
        Expr::ListIndexClone { list, .. } | Expr::ListLenCheck { list, .. } => {
            body_has_tail_construct(list)
        }
        Expr::Record { fields, .. } => fields.iter().any(|(_, v)| body_has_tail_construct(v)),
        Expr::Update { record, fields } => {
            body_has_tail_construct(record)
                || fields.iter().any(|(_, v)| body_has_tail_construct(v))
        }
        Expr::Access { record, .. } => body_has_tail_construct(record),
        Expr::Lambda { body, .. }
        | Expr::SharedLambda { body, .. }
        | Expr::OnceLambda { body, .. } => body_has_tail_construct(body),
        Expr::TaskSeq { effect, rest } => {
            body_has_tail_construct(effect) || body_has_tail_construct(rest)
        }
        Expr::Call { args, .. } => args.iter().any(body_has_tail_construct),
    }
}

/// Substitute constant argument expressions for a set of parameter symbols
/// throughout an expression. Used to inline a whitelisted builder's body at a
/// constant call site. Every bound parameter is replaced by its constant
/// argument; a `Let` / `Match` / lambda that RE-BINDS one of the substituted
/// symbols shadows it, so the substitution stops at that binder (the inner use
/// refers to the local binding, not the parameter). Because only whitelisted
/// builder bodies are inlined and their arguments are proven constant, the
/// substituted expressions are closed constants — capture is impossible.
#[allow(clippy::too_many_lines)] // one arm per Expr variant — the exhaustive rebuild IS the substitution
fn substitute(expr: Expr, subst: &BTreeMap<Symbol, Expr>) -> Expr {
    let go = |e: Expr| substitute(e, subst);
    let go_box = |b: Box<Expr>| -> Box<Expr> { Box::new(substitute(*b, subst)) };
    let go_vec =
        |v: Vec<Expr>| -> Vec<Expr> { v.into_iter().map(|e| substitute(e, subst)).collect() };

    match expr {
        // A substituted parameter becomes its constant argument. An
        // unsubstituted occurrence keeps its ORIGINAL variant: collapsing a
        // `CloneVar` to a bare `Var` would drop a `.clone()` the move-ownership
        // pass inserted for a multi-use binding, producing a use-after-move
        // (E0382) in the emitted Rust.
        Expr::Var(sym) => subst.get(&sym).cloned().unwrap_or(Expr::Var(sym)),
        Expr::CloneVar(sym) => subst.get(&sym).cloned().unwrap_or(Expr::CloneVar(sym)),
        Expr::Int(_)
        | Expr::Bool(_)
        | Expr::Float(_)
        | Expr::Str(_)
        | Expr::CustomElementRef { .. }
        | Expr::Char(_)
        | Expr::Unit
        | Expr::FuncValue { .. }
        | Expr::TailRecur { .. } => expr,

        Expr::Ctor {
            home,
            ty,
            variant,
            args,
        } => Expr::Ctor {
            home,
            ty,
            variant,
            args: go_vec(args),
        },
        Expr::BinOp { op, lhs, rhs } => Expr::BinOp {
            op,
            lhs: go_box(lhs),
            rhs: go_box(rhs),
        },
        // A `let` re-binding a substituted name shadows it in the body: descend
        // into the value with the full substitution, but drop the shadowed
        // binding from the substitution used for the body.
        Expr::Let { name, value, body } => {
            let value = go_box(value);
            let body = substitute_under_binders(*body, subst, &[name]);
            Expr::Let {
                name,
                value,
                body: Box::new(body),
            }
        }
        Expr::Destructure {
            binder,
            value,
            body,
        } => {
            let value = go_box(value);
            let bound = pat_binders(&binder);
            let body = substitute_under_binders(*body, subst, &bound);
            Expr::Destructure {
                binder,
                value,
                body: Box::new(body),
            }
        }
        Expr::If { cond, then_, else_ } => Expr::If {
            cond: go_box(cond),
            then_: go_box(then_),
            else_: go_box(else_),
        },
        Expr::Match(m) => Expr::Match(m.map_bodies(
            |scrut| substitute(scrut, subst),
            |pat, body, guard| {
                let bound = pat_binders(pat);
                (
                    substitute_under_binders(body, subst, &bound),
                    guard.map(|g| substitute_under_binders(g, subst, &bound)),
                )
            },
        )),
        Expr::Tuple(elems) => Expr::Tuple(go_vec(elems)),
        Expr::List { elem, items } => Expr::List {
            elem,
            items: go_vec(items),
        },
        Expr::Cons { head, tail } => Expr::Cons {
            head: go_box(head),
            tail: go_box(tail),
        },
        Expr::ListIndexClone { list, index, elem } => Expr::ListIndexClone {
            list: go_box(list),
            index,
            elem,
        },
        Expr::ListLenCheck { list, len, exact } => Expr::ListLenCheck {
            list: go_box(list),
            len,
            exact,
        },
        Expr::Record { fields, ty } => Expr::Record {
            fields: fields.into_iter().map(|(n, v)| (n, go(v))).collect(),
            ty,
        },
        Expr::Access {
            record,
            field,
            field_ty,
        } => Expr::Access {
            record: go_box(record),
            field,
            field_ty,
        },
        Expr::Update { record, fields } => Expr::Update {
            record: go_box(record),
            fields: fields.into_iter().map(|(n, v)| (n, go(v))).collect(),
        },
        Expr::Lambda { params, ret, body } => {
            let bound: Vec<Symbol> = params.iter().map(|(s, _)| *s).collect();
            let body = substitute_under_binders(*body, subst, &bound);
            Expr::Lambda {
                params,
                ret,
                body: Box::new(body),
            }
        }
        Expr::SharedLambda { params, ret, body } => {
            let bound: Vec<Symbol> = params.iter().map(|(s, _)| *s).collect();
            let body = substitute_under_binders(*body, subst, &bound);
            Expr::SharedLambda {
                params,
                ret,
                body: Box::new(body),
            }
        }
        Expr::OnceLambda {
            params,
            ret,
            body,
            capture,
        } => {
            let bound: Vec<Symbol> = params.iter().map(|(s, _)| *s).collect();
            let body = substitute_under_binders(*body, subst, &bound);
            Expr::OnceLambda {
                params,
                ret,
                body: Box::new(body),
                capture,
            }
        }
        Expr::Apply { func, args } => Expr::Apply {
            func: go_box(func),
            args: go_vec(args),
        },
        Expr::TaskSeq { effect, rest } => Expr::TaskSeq {
            effect: go_box(effect),
            rest: go_box(rest),
        },
        Expr::TailLoop { params, body } => {
            let bound: Vec<Symbol> = params.iter().map(|(s, _)| *s).collect();
            let body = substitute_under_binders(*body, subst, &bound);
            Expr::TailLoop {
                params,
                body: Box::new(body),
            }
        }
        Expr::Call {
            callee,
            args,
            pin,
            on_form,
        } => Expr::Call {
            callee,
            args: go_vec(args),
            pin,
            on_form,
        },
    }
}

/// Substitute within `body` after removing every symbol in `shadowed` from the
/// substitution map — the binder introduced by an enclosing `let` / lambda /
/// arm re-binds that name, so a use inside refers to the local binding, not the
/// substituted parameter.
fn substitute_under_binders(
    body: Expr,
    subst: &BTreeMap<Symbol, Expr>,
    shadowed: &[Symbol],
) -> Expr {
    if shadowed.iter().any(|s| subst.contains_key(s)) {
        let mut inner = subst.clone();
        for s in shadowed {
            inner.remove(s);
        }
        substitute(body, &inner)
    } else {
        substitute(body, subst)
    }
}

/// Every variable symbol a pattern binds (recursively) — the names it shadows
/// for the arm / destructure body.
fn pat_binders(pat: &Pat) -> Vec<Symbol> {
    let mut out = Vec::new();
    collect_pat_binders(pat, &mut out);
    out
}

fn collect_pat_binders(pat: &Pat, out: &mut Vec<Symbol>) {
    match pat {
        Pat::Var(s) => out.push(*s),
        Pat::Alias(inner, s) => {
            out.push(*s);
            collect_pat_binders(inner, out);
        }
        Pat::Ctor { args, .. } | Pat::Tuple(args) | Pat::Or(args) => {
            for a in args {
                collect_pat_binders(a, out);
            }
        }
        Pat::Record(entries) => {
            for (_, sub) in entries {
                collect_pat_binders(sub, out);
            }
        }
        Pat::Slice { prefix, rest, .. } => {
            for p in prefix {
                collect_pat_binders(p, out);
            }
            if let Some(r) = rest {
                collect_pat_binders(r, out);
            }
        }
        Pat::Wildcard | Pat::Int(_) | Pat::Bool(_) | Pat::Char(_) | Pat::Str(_) => {}
    }
}

/// At an appearance-kernel call, replace each argument that sits in a
/// hoist-eligible registry position and folds to a kind-matching literal with
/// that literal; leave every other argument (and every non-appearance call)
/// untouched. Reached only after the arguments have themselves been recursively
/// folded, so a nested appearance call inside an argument is already rewritten.
fn fold_appearance_args(
    callee: &Callee,
    mut args: Vec<Expr>,
    funcs: &BTreeMap<FuncId, &Func>,
    interner: &Interner,
) -> Vec<Expr> {
    let Callee::Kernel(k) = callee else {
        return args;
    };
    let positions = appearance_literal_args(*k);
    if positions.is_empty() {
        return args;
    }
    let env = FoldEnv::new(funcs, interner);
    for &(pos, kind) in positions {
        let Some(arg) = args.get_mut(pos) else {
            continue;
        };
        // A direct literal already sits in the target shape — nothing to fold
        // (this is also what makes the pass idempotent: a second run sees the
        // folded literal here and skips it).
        if is_direct_literal(arg) {
            continue;
        }
        if let Some(folded) = fold_const(arg, &env).and_then(|c| literal_of_kind(&c, kind)) {
            *arg = folded;
        }
    }
    args
}

/// Whether an expression is already a direct scalar literal — the shape the
/// appearance registry hoists without any folding.
const fn is_direct_literal(expr: &Expr) -> bool {
    matches!(
        expr,
        Expr::Int(_) | Expr::Float(_) | Expr::Str(_) | Expr::Bool(_)
    )
}

/// The direct-literal [`Expr`] for a folded constant, but ONLY when it matches
/// the appearance position's declared [`LitKind`]. A kind mismatch (a fold that
/// produced, say, an `Int` for a `Str` position) is rejected — the argument is
/// left unfolded rather than substituted with a wrong-kinded literal.
fn literal_of_kind(value: &ConstValue, kind: LitKind) -> Option<Expr> {
    match (kind, value) {
        (LitKind::Str, ConstValue::Str(_))
        | (LitKind::Int, ConstValue::Int(_))
        | (LitKind::Float, ConstValue::Float(_)) => value.to_literal_expr(),
        _ => None,
    }
}

/// The two hard bounds on evaluation, threaded through the recursion: `fuel`
/// caps total sub-expression visits (work), `depth` caps native recursion
/// depth (stack). Either bound reaching its limit aborts the fold with `None`.
struct Budget {
    fuel: u32,
    depth: u32,
}

/// The fuel- and depth-bounded recursive evaluator. Every call decrements
/// `fuel` and returns `None` on exhaustion (total visits ≤ [`FUEL`]); it also
/// returns `None` once native recursion reaches [`MAX_DEPTH`]. Together the two
/// bounds guarantee the evaluator can neither loop nor overflow the compile-time
/// stack, regardless of the input expression.
fn eval(expr: &Expr, env: &FoldEnv, budget: &mut Budget) -> Option<ConstValue> {
    if budget.fuel == 0 || budget.depth >= MAX_DEPTH {
        return None;
    }
    budget.fuel -= 1;
    budget.depth += 1;
    let result = eval_inner(expr, env, budget);
    budget.depth -= 1;
    result
}

/// The per-node evaluation body, entered only after [`eval`] has charged one
/// unit of fuel and one level of depth (and restored the depth on return).
fn eval_inner(expr: &Expr, env: &FoldEnv, budget: &mut Budget) -> Option<ConstValue> {
    match expr {
        Expr::Int(n) => Some(ConstValue::Int(*n)),
        Expr::Float(f) => Some(ConstValue::Float(*f)),
        Expr::Str(s) => Some(ConstValue::Str(s.clone())),
        Expr::Bool(b) => Some(ConstValue::Bool(*b)),

        // A local parameter bound to an already-constant argument resolves to
        // that value; any other variable (a free variable, a `Model` binder, a
        // captured symbol we did not bind) is not a compile-time constant.
        Expr::Var(sym) | Expr::CloneVar(sym) => env.locals.get(sym).cloned(),

        Expr::List { items, .. } => {
            let mut out = Vec::with_capacity(items.len());
            for it in items {
                out.push(eval(it, env, budget)?);
            }
            Some(ConstValue::List(out))
        }

        Expr::Cons { head, tail } => {
            let head_v = eval(head, env, budget)?;
            let ConstValue::List(mut rest) = eval(tail, env, budget)? else {
                return None;
            };
            rest.insert(0, head_v);
            Some(ConstValue::List(rest))
        }

        Expr::Tuple(elems) => {
            let mut out = Vec::with_capacity(elems.len());
            for e in elems {
                out.push(eval(e, env, budget)?);
            }
            Some(ConstValue::Tuple(out))
        }

        Expr::Record { fields, .. } => {
            let mut map = BTreeMap::new();
            for (name, value) in fields {
                map.insert(*name, eval(value, env, budget)?);
            }
            Some(ConstValue::Record(map))
        }

        Expr::Update { record, fields } => {
            let ConstValue::Record(mut map) = eval(record, env, budget)? else {
                return None;
            };
            for (name, value) in fields {
                map.insert(*name, eval(value, env, budget)?);
            }
            Some(ConstValue::Record(map))
        }

        Expr::Access { record, field, .. } => {
            let ConstValue::Record(map) = eval(record, env, budget)? else {
                return None;
            };
            map.get(field).cloned()
        }

        Expr::Ctor { variant, args, .. } => {
            let mut out = Vec::with_capacity(args.len());
            for a in args {
                out.push(eval(a, env, budget)?);
            }
            Some(ConstValue::Ctor {
                variant: *variant,
                args: out,
            })
        }

        Expr::BinOp { op, lhs, rhs } => {
            let l = eval(lhs, env, budget)?;
            let r = eval(rhs, env, budget)?;
            eval_binop(*op, &l, &r)
        }

        Expr::If { cond, then_, else_ } => match eval(cond, env, budget)? {
            ConstValue::Bool(true) => eval(then_, env, budget),
            ConstValue::Bool(false) => eval(else_, env, budget),
            _ => None,
        },

        Expr::Let { name, value, body } => {
            let v = eval(value, env, budget)?;
            eval_with_local(*name, v, body, env, budget)
        }

        Expr::Match(m) => eval_match(m, env, budget),

        Expr::Call { callee, args, .. } => eval_call(callee, args, env, budget),

        // Every remaining shape is either not a value (a tail-loop marker, a
        // task sequence), a first-class function value, or a form the evaluator
        // does not model. None of them is a compile-time scalar constant, so
        // folding conservatively stops here.
        _ => None,
    }
}

/// Evaluate `body` with one additional local binding in scope, restoring the
/// environment's locals afterwards. A fresh child map is cloned rather than
/// mutating the shared environment, so sibling evaluations never see a leaked
/// binding.
fn eval_with_local(
    name: Symbol,
    value: ConstValue,
    body: &Expr,
    env: &FoldEnv,
    budget: &mut Budget,
) -> Option<ConstValue> {
    let mut child_locals = env.locals.clone();
    child_locals.insert(name, value);
    let child = FoldEnv {
        funcs: env.funcs,
        interner: env.interner,
        locals: child_locals,
    };
    eval(body, &child, budget)
}

/// Evaluate a binary operation over two already-constant operands. Only the
/// total, deterministic operations the pure builders use are folded: string
/// append (`++`), integer/float arithmetic (wrapping / IEEE-754, matching the
/// runtime's total semantics), and the boolean / comparison operators. Integer
/// division by zero and any operand-kind mismatch yield `None` (unfolded), so a
/// fold never diverges from the runtime.
fn eval_binop(op: BinOp, l: &ConstValue, r: &ConstValue) -> Option<ConstValue> {
    use ConstValue::{Bool, Float, Int, Str};
    match (op, l, r) {
        (BinOp::Append, Str(a), Str(b)) => Some(Str(format!("{a}{b}"))),

        (BinOp::IntAdd | BinOp::Add, Int(a), Int(b)) => Some(Int(a.wrapping_add(*b))),
        (BinOp::IntSub | BinOp::Sub, Int(a), Int(b)) => Some(Int(a.wrapping_sub(*b))),
        (BinOp::IntMul | BinOp::Mul, Int(a), Int(b)) => Some(Int(a.wrapping_mul(*b))),
        // Integer division is total in the runtime only through the checked
        // helper (`b == 0` and `MIN / -1` are guarded there); rather than
        // reproduce that guard's exact result, division by zero simply does not
        // fold. A non-zero divisor folds to the same wrapping quotient.
        (BinOp::IntDiv, Int(a), Int(b)) if *b != 0 => Some(Int(a.wrapping_div(*b))),

        (BinOp::FloatAdd | BinOp::Add, Float(a), Float(b)) => Some(Float(a + b)),
        (BinOp::FloatSub | BinOp::Sub, Float(a), Float(b)) => Some(Float(a - b)),
        (BinOp::FloatMul | BinOp::Mul, Float(a), Float(b)) => Some(Float(a * b)),
        (BinOp::Div, Float(a), Float(b)) => Some(Float(a / b)),

        (BinOp::And, Bool(a), Bool(b)) => Some(Bool(*a && *b)),
        (BinOp::Or, Bool(a), Bool(b)) => Some(Bool(*a || *b)),

        (BinOp::Eq, _, _) => Some(Bool(l == r)),
        (BinOp::Neq, _, _) => Some(Bool(l != r)),
        (BinOp::Lt, Int(a), Int(b)) => Some(Bool(a < b)),
        (BinOp::Gt, Int(a), Int(b)) => Some(Bool(a > b)),
        (BinOp::Le, Int(a), Int(b)) => Some(Bool(a <= b)),
        (BinOp::Ge, Int(a), Int(b)) => Some(Bool(a >= b)),

        _ => None,
    }
}

/// Evaluate a `case` expression: fold the scrutinee, then take the first arm
/// whose pattern matches (binding its variables), evaluate that arm's body.
/// An arm with a guard is only taken when the guard folds to `true`. A
/// scrutinee or pattern shape the matcher does not model yields `None`.
fn eval_match(m: &ipe_ir::Match, env: &FoldEnv, budget: &mut Budget) -> Option<ConstValue> {
    let scrut = eval(m.scrutinee(), env, budget)?;
    for arm in m.arms() {
        let mut bindings = BTreeMap::new();
        if match_pat(&arm.pat, &scrut, &mut bindings) {
            let mut child_locals = env.locals.clone();
            child_locals.append(&mut bindings);
            let child = FoldEnv {
                funcs: env.funcs,
                interner: env.interner,
                locals: child_locals,
            };
            if let Some(guard) = &arm.guard {
                match eval(guard, &child, budget) {
                    Some(ConstValue::Bool(true)) => {}
                    // A `false` guard falls through to the next arm; an
                    // unfoldable guard aborts the whole fold (we cannot prove
                    // which arm the runtime takes).
                    Some(ConstValue::Bool(false)) => continue,
                    _ => return None,
                }
            }
            return eval(&arm.body, &child, budget);
        }
    }
    None
}

/// Try to match a constant value against a pattern, collecting variable
/// bindings on success. Returns `false` for a non-match (the caller tries the
/// next arm) and — conservatively — for any pattern shape the matcher does not
/// model, so an unmodelled pattern simply never matches rather than matching
/// unsoundly.
fn match_pat(pat: &Pat, value: &ConstValue, out: &mut BTreeMap<Symbol, ConstValue>) -> bool {
    match (pat, value) {
        (Pat::Wildcard, _) => true,
        (Pat::Var(sym), _) => {
            out.insert(*sym, value.clone());
            true
        }
        (Pat::Alias(inner, sym), _) => {
            out.insert(*sym, value.clone());
            match_pat(inner, value, out)
        }
        (Pat::Int(a), ConstValue::Int(b)) => a == b,
        (Pat::Bool(a), ConstValue::Bool(b)) => a == b,
        (Pat::Str(a), ConstValue::Str(b)) => a == b,
        (
            Pat::Ctor { variant, args, .. },
            ConstValue::Ctor {
                variant: v,
                args: vs,
            },
        ) if variant == v && args.len() == vs.len() => {
            args.iter().zip(vs).all(|(p, v)| match_pat(p, v, out))
        }
        (Pat::Tuple(ps), ConstValue::Tuple(vs)) if ps.len() == vs.len() => {
            ps.iter().zip(vs).all(|(p, v)| match_pat(p, v, out))
        }
        (Pat::Record(entries), ConstValue::Record(map)) => entries
            .iter()
            .all(|(name, sub)| map.get(name).is_some_and(|v| match_pat(sub, v, out))),
        (Pat::Slice { prefix, rest, .. }, ConstValue::List(items)) => {
            match_slice(prefix, rest.as_deref(), items, out)
        }
        _ => false,
    }
}

/// Match a slice pattern (`[]`, `[a, b]`, `x :: xs`) against a constant list.
fn match_slice(
    prefix: &[Pat],
    rest: Option<&Pat>,
    items: &[ConstValue],
    out: &mut BTreeMap<Symbol, ConstValue>,
) -> bool {
    match rest {
        // Closed, exact-length list pattern.
        None => {
            items.len() == prefix.len()
                && prefix.iter().zip(items).all(|(p, v)| match_pat(p, v, out))
        }
        // Open cons tail: at least `prefix.len()` elements; `rest` binds the
        // remainder as a list value.
        Some(tail) => {
            if items.len() < prefix.len() {
                return false;
            }
            let (head, remainder) = items.split_at(prefix.len());
            prefix.iter().zip(head).all(|(p, v)| match_pat(p, v, out))
                && match_pat(tail, &ConstValue::List(remainder.to_vec()), out)
        }
    }
}

/// Evaluate a `Call`: a kernel call folds through [`eval_kernel`] (only pure
/// kernels), a call to a whitelisted user function folds through its body with
/// the arguments bound as parameters. Anything else — an impure kernel, a
/// non-whitelisted user function, an FFI callee — yields `None`.
fn eval_call(
    callee: &Callee,
    args: &[Expr],
    env: &FoldEnv,
    budget: &mut Budget,
) -> Option<ConstValue> {
    // Evaluate every argument to a constant first; a single non-constant
    // argument means the call is not a compile-time constant.
    let mut arg_vals = Vec::with_capacity(args.len());
    for a in args {
        arg_vals.push(eval(a, env, budget)?);
    }

    match callee {
        Callee::Kernel(k) => eval_kernel(*k, &arg_vals),
        Callee::Func(id) => {
            let func = env.funcs.get(id)?;
            if !is_whitelisted_func(func, env.interner) {
                return None;
            }
            eval_func_body(func, &arg_vals, env, budget)
        }
        // A foreign FFI callee is never a compile-time constant.
        Callee::Ffi { .. } => None,
    }
}

/// Evaluate a whitelisted user function's body with its arguments bound to its
/// parameters. A parameter-count mismatch (a partial application reaching here)
/// aborts the fold.
fn eval_func_body(
    func: &Func,
    arg_vals: &[ConstValue],
    env: &FoldEnv,
    budget: &mut Budget,
) -> Option<ConstValue> {
    if func.params.len() != arg_vals.len() {
        return None;
    }
    let mut child_locals = BTreeMap::new();
    for ((param, _), value) in func.params.iter().zip(arg_vals) {
        child_locals.insert(*param, value.clone());
    }
    let child = FoldEnv {
        funcs: env.funcs,
        interner: env.interner,
        locals: child_locals,
    };
    eval(&func.body, &child, budget)
}

/// Whether a user function may be evaluated through its body.
///
/// There is no general whole-program purity result for user functions here, so
/// this is an EXPLICIT whitelist of the appearance-builder modules whose literal
/// pipelines the appearance hot-swap targets: `Ipe.Ui.Animation` and its
/// composed value-builder siblings `Ipe.Ui.Transition` (the `Easing` curve →
/// CSS builder an `Animation` spec's `easing` field pulls in) and
/// `Ipe.Ui.Transform` (the keyframe `Prop` → CSS-property builder a populated
/// `keyframes` list renders through), plus the `Ipe.Css` value builders. Every
/// listed module is a pure, total, `Model`-independent string/value builder. A
/// function in any other module is not evaluated (its call folds to `None`,
/// recompiling unfolded). This is the current scope; widening it is a
/// deliberate, separately-audited act, not an accident of a general analysis.
fn is_whitelisted_func(func: &Func, interner: &Interner) -> bool {
    modpath_is(&func.home, &["Ipe", "Ui", "Animation"], interner)
        || modpath_is(&func.home, &["Ipe", "Ui", "Transition"], interner)
        || modpath_is(&func.home, &["Ipe", "Ui", "Transform"], interner)
        || modpath_is(&func.home, &["Ipe", "Css"], interner)
        // `Ipe.Ui.image` is the record-native `<img>` veneer over the
        // `imageKernel` (`KernelFn::UiImage`); inlining its body at a constant
        // call surfaces the direct kernel call whose config's `description`
        // field the record-native appearance registry
        // (`appearance_literal_record_fields`) then hoists. This is scoped to the
        // single `image` builder — the rest of `Ipe.Ui` stays off the whitelist,
        // so no other veneer is inlined by accident. It is pure, total, and
        // `Model`-independent; a `Model`-dependent config field survives inlining
        // as a non-literal and stays a recompile, gated by the emit-time
        // direct-literal hoist check rather than the constant-argument precondition
        // `image` is exempted from in `specialize_whitelisted_call`.
        || (modpath_is(&func.home, &["Ipe", "Ui"], interner)
            && interner.resolve(func.name) == Some("image"))
}

/// Whether a module path resolves, segment for segment, to `expected`.
fn modpath_is(home: &ModPath, expected: &[&str], interner: &Interner) -> bool {
    home.0.len() == expected.len()
        && home
            .0
            .iter()
            .zip(expected)
            .all(|(seg, want)| interner.resolve(*seg) == Some(*want))
}

/// Evaluate a pure kernel over already-constant arguments.
///
/// Gated on [`KernelFn::capability`] being `None` (no security-relevant effect
/// — the reused kernel analysis): an effectful kernel is never folded even if a
/// case below happened to match its arity. The set of kernels with a folded
/// implementation is the pure string / numeric builders the appearance
/// pipelines reach (`String.fromInt` / `fromFloat` / `append` / `concat` /
/// `join`). A pure kernel with no case here yields `None` — unfolded, never a
/// wrong constant.
fn eval_kernel(k: KernelFn, args: &[ConstValue]) -> Option<ConstValue> {
    use ConstValue::{Float, Int, List, Str};

    // A kernel carrying any security-relevant capability is effectful; never
    // fold it, regardless of the arms below.
    if k.def().capability.is_some() {
        return None;
    }

    match (k, args) {
        (KernelFn::StringFromInt, [Int(n)]) => Some(Str(string_from_int(*n))),
        (KernelFn::StringFromFloat, [Float(f)]) => Some(Str(string_from_float(*f))),
        (KernelFn::StringAppend, [Str(a), Str(b)]) => Some(Str(format!("{a}{b}"))),
        (KernelFn::StringConcat, [List(parts)]) => {
            let mut out = String::new();
            for p in parts {
                let Str(s) = p else { return None };
                out.push_str(s);
            }
            Some(Str(out))
        }
        (KernelFn::StringJoin, [Str(sep), List(parts)]) => {
            let mut pieces = Vec::with_capacity(parts.len());
            for p in parts {
                let Str(s) = p else { return None };
                pieces.push(s.as_str());
            }
            Some(Str(pieces.join(sep)))
        }
        _ => None,
    }
}

/// `String.fromInt`: the runtime's `ipe_runtime::string::string_from_int` is
/// `format!("{i}")`. Reproduced here byte-for-byte; the conformance test
/// asserts equality against the real runtime function.
fn string_from_int(i: i64) -> String {
    format!("{i}")
}

/// `String.fromFloat`: a byte-for-byte reproduction of the runtime's
/// `ipe_runtime::string::string_from_float` shortest-round-trip `'g'`-style
/// formatter. Reproduced (rather than depending on the whole runtime crate)
/// because the backend does not link the runtime; the conformance test asserts
/// this reproduction is byte-identical to the real runtime function across a
/// representative float set, so a drift is caught in CI, not in a user's build.
fn string_from_float(f: f64) -> String {
    if f.is_nan() {
        return "NaN".to_string();
    }
    if f.is_infinite() {
        return if f < 0.0 { "-Inf" } else { "+Inf" }.to_string();
    }
    let neg = f.is_sign_negative();
    if f == 0.0 {
        return if neg { "-0" } else { "0" }.to_string();
    }

    let sci = format!("{:e}", f.abs());
    let Some((mantissa, exp_str)) = sci.split_once('e') else {
        return sci;
    };
    let sci_exp: i32 = exp_str.parse().unwrap_or(0);
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();

    let dp = sci_exp + 1;
    let exp = dp - 1;

    if (-4..6).contains(&exp) {
        fmt_g_positional(neg, &digits, dp)
    } else {
        fmt_g_exponent(neg, &digits, exp)
    }
}

/// `'g'`'s `%e` rendering (shortest mode) — mirrors the runtime's
/// `fmt_g_exponent`: `d[.ddd]e±NN`, sign always present, exponent ≥ two digits.
fn fmt_g_exponent(neg: bool, digits: &str, exp: i32) -> String {
    let mut out = String::new();
    if neg {
        out.push('-');
    }
    let mut chars = digits.chars();
    if let Some(first) = chars.next() {
        out.push(first);
    }
    let rest: String = chars.collect();
    if !rest.is_empty() {
        out.push('.');
        out.push_str(&rest);
    }
    out.push('e');
    let (sign, mag) = if exp < 0 { ('-', -exp) } else { ('+', exp) };
    out.push(sign);
    if mag < 10 {
        out.push('0');
    }
    out.push_str(&mag.to_string());
    out
}

/// `'g'`'s `%f` rendering (shortest mode) — mirrors the runtime's
/// `fmt_g_positional`: `ddd[.ddd]`, zero-padding the integer part and reading
/// fraction digits past the point.
// The `usize`↔`i32` casts mirror the runtime `fmt_g_positional` byte-for-byte;
// `digits` is a `{:e}`-mantissa (a handful of significant digits), so its length
// and every index derived from it are far inside `i32`/`usize` range — the casts
// cannot truncate, wrap, or lose a sign in practice. The conformance test pins
// this reproduction byte-identical to the runtime.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]
fn fmt_g_positional(neg: bool, digits: &str, dp: i32) -> String {
    let bytes = digits.as_bytes();
    let nd = bytes.len() as i32;
    let frac = (nd - dp).max(0);
    let mut out = String::new();
    if neg {
        out.push('-');
    }
    if dp > 0 {
        let take = nd.min(dp);
        for i in 0..take {
            if let Some(&b) = bytes.get(i as usize) {
                out.push(b as char);
            }
        }
        for _ in take..dp {
            out.push('0');
        }
    } else {
        out.push('0');
    }
    if frac > 0 {
        out.push('.');
        for i in 0..frac {
            let j = dp + i;
            let ch = if j < 0 {
                b'0'
            } else {
                bytes.get(j as usize).copied().unwrap_or(b'0')
            };
            out.push(ch as char);
        }
    }
    out
}

#[cfg(test)]
#[allow(
    clippy::unnecessary_wraps, // a `DResult<()>` test signature keeps the `?`-based intern calls uniform
    clippy::unreadable_literal, // float fixtures are read as written CSS/easing values
    clippy::approx_constant // a PI-ish fixture value exercises the float formatter, not a real constant
)]
mod tests {
    use super::*;
    use ipe_diagnostics::DResult;
    use ipe_ir::{CallPin, IrType, OnFormKind};
    // The runtime string builders are referenced fully-qualified
    // (`ipe_runtime_rust::string::…`) in the conformance tests so they never
    // alias the same-named `const_fold` reproductions under test.
    use ipe_runtime_rust::string as rt_string;

    /// A `Call` to a kernel with no pin / form classification — the common shape.
    fn kernel_call(k: KernelFn, args: Vec<Expr>) -> Expr {
        Expr::Call {
            callee: Callee::Kernel(k),
            args,
            pin: CallPin::None,
            on_form: OnFormKind::NotForm,
        }
    }

    /// A whitelisted-or-not user `Func` with a single string parameter whose
    /// body is the identity over that parameter — the fixture the whitelist
    /// tests evaluate through.
    fn passthrough_func(home: ModPath, name: Symbol, param: Symbol) -> Func {
        Func {
            id: FuncId::from_raw(0),
            name,
            home,
            type_params: vec![],
            row_params: vec![],
            params: vec![(param, IrType::Str)],
            ret: IrType::Str,
            body: Expr::Var(param),
        }
    }

    #[test]
    fn nested_pure_literal_pipeline_folds_to_str() -> DResult<()> {
        // `String.join " " [String.fromInt 300, "ms", "linear"]` — a nested pure
        // pipeline of only literals folds to a single constant string.
        let interner = Interner::new();
        let funcs = BTreeMap::new();
        let env = FoldEnv::new(&funcs, &interner);

        let pipeline = kernel_call(
            KernelFn::StringJoin,
            vec![
                Expr::Str(" ".to_string()),
                Expr::List {
                    elem: IrType::Str,
                    items: vec![
                        kernel_call(KernelFn::StringFromInt, vec![Expr::Int(300)]),
                        Expr::Str("ms".to_string()),
                        Expr::Str("linear".to_string()),
                    ],
                },
            ],
        );

        assert_eq!(
            fold_const(&pipeline, &env),
            Some(ConstValue::Str("300 ms linear".to_string()))
        );
        Ok(())
    }

    #[test]
    fn string_append_pipeline_folds() -> DResult<()> {
        let interner = Interner::new();
        let funcs = BTreeMap::new();
        let env = FoldEnv::new(&funcs, &interner);

        // `(String.fromInt 300 ++ "ms")` via the `Append` BinOp.
        let expr = Expr::BinOp {
            op: BinOp::Append,
            lhs: Box::new(kernel_call(KernelFn::StringFromInt, vec![Expr::Int(300)])),
            rhs: Box::new(Expr::Str("ms".to_string())),
        };
        assert_eq!(
            fold_const(&expr, &env),
            Some(ConstValue::Str("300ms".to_string()))
        );
        Ok(())
    }

    #[test]
    fn pipeline_with_a_free_variable_does_not_fold() -> DResult<()> {
        // A pipeline reaching an unbound variable (a `Model` field binder, a
        // free parameter) is not a compile-time constant — folds to `None`, so
        // the argument recompiles rather than baking a wrong value.
        let mut interner = Interner::new();
        let model_dur = interner.intern("modelDuration")?;
        let funcs = BTreeMap::new();
        let env = FoldEnv::new(&funcs, &interner);

        let expr = Expr::BinOp {
            op: BinOp::Append,
            lhs: Box::new(kernel_call(
                KernelFn::StringFromInt,
                vec![Expr::Var(model_dur)],
            )),
            rhs: Box::new(Expr::Str("ms".to_string())),
        };
        assert_eq!(fold_const(&expr, &env), None);
        Ok(())
    }

    #[test]
    fn model_field_access_does_not_fold() -> DResult<()> {
        // `record.duration` where `record` is an unbound variable — a
        // `Model`-dependent read never folds.
        let mut interner = Interner::new();
        let model = interner.intern("model")?;
        let field = interner.intern("duration")?;
        let funcs = BTreeMap::new();
        let env = FoldEnv::new(&funcs, &interner);

        let expr = Expr::Access {
            record: Box::new(Expr::Var(model)),
            field,
            field_ty: IrType::Int,
        };
        assert_eq!(fold_const(&expr, &env), None);
        Ok(())
    }

    #[test]
    fn fuel_exhaustion_returns_none() {
        // A wide input whose total sub-expression count exceeds the fuel budget
        // exhausts it and returns `None` rather than folding — the "bounded by
        // construction" guard. The shape is a single flat list of more than
        // `FUEL` literal items (shallow, so it drains fuel by breadth, not by
        // native recursion depth), each item visited once.
        let interner = Interner::new();
        let funcs = BTreeMap::new();
        let env = FoldEnv::new(&funcs, &interner);

        let items: Vec<Expr> = (0..(FUEL + 10)).map(|_| Expr::Int(0)).collect();
        let expr = Expr::List {
            elem: IrType::Int,
            items,
        };
        assert_eq!(fold_const(&expr, &env), None);
    }

    #[test]
    fn non_whitelisted_user_function_does_not_fold() -> DResult<()> {
        // A user function outside the whitelist is not evaluated through its
        // body, even over constant arguments.
        let mut interner = Interner::new();
        let home = ModPath(vec![interner.intern("Main")?]);
        let name = interner.intern("helper")?;
        let param = interner.intern("x")?;
        let func = passthrough_func(home, name, param);
        let mut funcs = BTreeMap::new();
        funcs.insert(FuncId::from_raw(0), &func);
        let env = FoldEnv::new(&funcs, &interner);

        let call = Expr::Call {
            callee: Callee::Func(FuncId::from_raw(0)),
            args: vec![Expr::Str("hi".to_string())],
            pin: CallPin::None,
            on_form: OnFormKind::NotForm,
        };
        assert_eq!(fold_const(&call, &env), None);
        Ok(())
    }

    #[test]
    fn whitelisted_user_function_folds_through_body() -> DResult<()> {
        // A function in `Ipe.Ui.Animation` folds through its body: an identity
        // over a constant string.
        let mut interner = Interner::new();
        let home = ModPath(vec![
            interner.intern("Ipe")?,
            interner.intern("Ui")?,
            interner.intern("Animation")?,
        ]);
        let name = interner.intern("passthrough")?;
        let param = interner.intern("s")?;
        let func = passthrough_func(home, name, param);
        let mut funcs = BTreeMap::new();
        funcs.insert(FuncId::from_raw(0), &func);
        let env = FoldEnv::new(&funcs, &interner);

        let call = Expr::Call {
            callee: Callee::Func(FuncId::from_raw(0)),
            args: vec![Expr::Str("hi".to_string())],
            pin: CallPin::None,
            on_form: OnFormKind::NotForm,
        };
        assert_eq!(
            fold_const(&call, &env),
            Some(ConstValue::Str("hi".to_string()))
        );
        Ok(())
    }

    // ── Record projection (drop the whole-record residual) ────────────────

    /// A three-field record literal whose `keep` field is a direct `Str` and
    /// whose other two fields carry distinct inert `Int` literals — the shape a
    /// specialized builder leaves behind, where only one field is later read.
    fn record_literal(
        interner: &mut Interner,
    ) -> Result<(Expr, Symbol), ipe_diagnostics::Diagnostic> {
        let keep = interner.intern("keep")?;
        let drop_a = interner.intern("dropA")?;
        let drop_b = interner.intern("dropB")?;
        let rec = Expr::Record {
            fields: vec![
                (keep, Expr::Str("kept".to_string())),
                (drop_a, Expr::Int(300)),
                (drop_b, Expr::Bool(true)),
            ],
            ty: Some(IrType::Int),
        };
        Ok((rec, keep))
    }

    #[test]
    fn access_into_literal_record_projects_the_field() -> DResult<()> {
        // `(<record literal>).keep` rewrites to that field's value — so the whole
        // record literal (and every OTHER field's inline literal) disappears from
        // the residual. This is what strips a specialized animation builder's dead
        // `spec` accesses, leaving no inline `duration` alongside the hoisted
        // shorthand.
        let mut interner = Interner::new();
        let (rec, keep) = record_literal(&mut interner)?;
        let funcs = BTreeMap::new();
        let access = Expr::Access {
            record: Box::new(rec),
            field: keep,
            field_ty: IrType::Str,
        };
        let folded = fold_expr(access, &funcs, &interner);
        assert_eq!(folded, Expr::Str("kept".to_string()));
        Ok(())
    }

    #[test]
    fn access_into_non_record_is_left_untouched() -> DResult<()> {
        // A field read off a NON-record (a free `Var` — a `Model` binder) is not a
        // literal projection: it stays an `Access`, so a `Model`-dependent read is
        // never rewritten to a bogus constant.
        let mut interner = Interner::new();
        let model = interner.intern("model")?;
        let field = interner.intern("count")?;
        let funcs = BTreeMap::new();
        let access = Expr::Access {
            record: Box::new(Expr::Var(model)),
            field,
            field_ty: IrType::Int,
        };
        let folded = fold_expr(access.clone(), &funcs, &interner);
        assert_eq!(folded, access);
        Ok(())
    }

    // ── Whitelist scope: `Ipe.Ui.image`, and only `image` ────────────────

    /// A `Func` in a chosen home + name whose body is irrelevant to the
    /// name/home-only whitelist check.
    fn named_func(home: ModPath, name: Symbol) -> Func {
        Func {
            id: FuncId::from_raw(0),
            name,
            home,
            type_params: vec![],
            row_params: vec![],
            params: vec![],
            ret: IrType::Str,
            body: Expr::Unit,
        }
    }

    #[test]
    fn ipe_ui_image_veneer_is_whitelisted() -> DResult<()> {
        let mut interner = Interner::new();
        let home = ModPath(vec![interner.intern("Ipe")?, interner.intern("Ui")?]);
        let image = interner.intern("image")?;
        let func = named_func(home, image);
        assert!(is_whitelisted_func(&func, &interner));
        Ok(())
    }

    #[test]
    fn other_ipe_ui_functions_are_not_whitelisted() -> DResult<()> {
        // The whitelist is scoped to the single `image` veneer: every other
        // `Ipe.Ui` builder (e.g. `column`, `button`) stays off it, so no unrelated
        // veneer is inlined by accident.
        let mut interner = Interner::new();
        let home = ModPath(vec![interner.intern("Ipe")?, interner.intern("Ui")?]);
        for other in ["column", "button", "row", "el", "link"] {
            let sym = interner.intern(other)?;
            let func = named_func(home.clone(), sym);
            assert!(
                !is_whitelisted_func(&func, &interner),
                "Ipe.Ui.{other} must not be whitelisted"
            );
        }
        Ok(())
    }

    // ── Conformance: fold == runtime (the dev == prod guarantee) ──────────
    //
    // A folded constant MUST be byte-identical to what the runtime builder
    // computes for the same inputs. These tests call the REAL runtime string
    // builders (`ipe_runtime_rust::string::*`, a dev-dependency) and assert
    // `const_fold`'s reproduction — and the folded pipeline value — match them
    // exactly. A drift in the reproduced float formatter, or in any folded
    // kernel, fails here in CI rather than in a user's build.

    #[test]
    fn string_from_int_matches_runtime() {
        for &n in &[0i64, 1, -1, 42, 300, -12345, i64::MAX, i64::MIN] {
            assert_eq!(
                string_from_int(n),
                ipe_runtime_rust::string::string_from_int(n),
                "const_fold string_from_int must match the runtime for {n}"
            );
        }
    }

    #[test]
    fn string_from_float_matches_runtime() {
        // A representative spread: whole numbers, sub-1 fractions, negatives,
        // the easing coordinates `cubicBezier` renders, and the boundary
        // exponents the `'g'`-mode formatter switches rendering at.
        let samples = [
            0.0f64,
            -0.0,
            1.0,
            -1.0,
            0.4,
            0.2,
            1.5,
            0.0001,
            123456.0,
            1_000_000.0,
            0.000_01,
            3.141_592_653_589_793,
            -2.5,
            100.0,
            0.5,
        ];
        for &f in &samples {
            assert_eq!(
                string_from_float(f),
                ipe_runtime_rust::string::string_from_float(f),
                "const_fold string_from_float must match the runtime for {f}"
            );
        }
    }

    #[test]
    fn animation_shorthand_tail_fold_matches_runtime_composition() {
        // Fold the `buildShorthandTail` pipeline shape for a concrete spec
        // (`duration = 300`, `easing = ease-in-out`, `delay = 0`,
        // `iterations = 1`, `fillMode = forwards`) — the exact string form
        // `String.fromInt dur ++ "ms " ++ easing ++ " " ++ …`. The expected
        // value is composed from the SAME runtime primitives, so the assertion
        // is fold == runtime, not fold == a hand-typed literal.
        let interner = Interner::new();
        let funcs = BTreeMap::new();
        let env = FoldEnv::new(&funcs, &interner);

        // `String.fromInt 300 ++ "ms " ++ "ease-in-out" ++ " " ++
        //  String.fromInt 0 ++ "ms " ++ "1" ++ " " ++ "forwards"`
        let append = |lhs: Expr, rhs: Expr| Expr::BinOp {
            op: BinOp::Append,
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
        };
        let from_int = |n: i64| kernel_call(KernelFn::StringFromInt, vec![Expr::Int(n)]);
        let pipeline = append(
            append(
                append(
                    append(
                        append(
                            append(
                                append(from_int(300), Expr::Str("ms ".to_string())),
                                Expr::Str("ease-in-out".to_string()),
                            ),
                            Expr::Str(" ".to_string()),
                        ),
                        from_int(0),
                    ),
                    Expr::Str("ms ".to_string()),
                ),
                Expr::Str("1".to_string()),
            ),
            append(
                Expr::Str(" ".to_string()),
                Expr::Str("forwards".to_string()),
            ),
        );

        // The runtime-composed expectation, via the real builders.
        let mut expected = rt_string::string_from_int(300);
        expected = rt_string::string_append(expected, "ms ".to_string());
        expected = rt_string::string_append(expected, "ease-in-out".to_string());
        expected = rt_string::string_append(expected, " ".to_string());
        expected = rt_string::string_append(expected, rt_string::string_from_int(0));
        expected = rt_string::string_append(expected, "ms ".to_string());
        expected = rt_string::string_append(expected, "1".to_string());
        expected = rt_string::string_append(expected, " ".to_string());
        expected = rt_string::string_append(expected, "forwards".to_string());

        assert_eq!(fold_const(&pipeline, &env), Some(ConstValue::Str(expected)));
    }

    #[test]
    fn cubic_bezier_fold_matches_runtime_join() {
        // `Ipe.Css` / `easingToCss`'s `cubic-bezier(...)` composition folds to
        // exactly what the runtime float builder + join produce for the same
        // coordinates — a `String.fromFloat`-heavy pipeline, the strongest
        // dev == prod check on the reproduced formatter.
        let interner = Interner::new();
        let funcs = BTreeMap::new();
        let env = FoldEnv::new(&funcs, &interner);

        let from_float = |f: f64| kernel_call(KernelFn::StringFromFloat, vec![Expr::Float(f)]);
        // `"cubic-bezier(" ++ ffloat x1 ++ ", " ++ ffloat y1 ++ ", " ++
        //  ffloat x2 ++ ", " ++ ffloat y2 ++ ")"`
        let append = |lhs: Expr, rhs: Expr| Expr::BinOp {
            op: BinOp::Append,
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
        };
        let (x1, y1, x2, y2) = (0.4f64, 0.0, 0.2, 1.0);
        let pipeline = append(
            append(
                append(
                    append(
                        append(
                            append(
                                append(Expr::Str("cubic-bezier(".to_string()), from_float(x1)),
                                Expr::Str(", ".to_string()),
                            ),
                            from_float(y1),
                        ),
                        Expr::Str(", ".to_string()),
                    ),
                    from_float(x2),
                ),
                Expr::Str(", ".to_string()),
            ),
            append(from_float(y2), Expr::Str(")".to_string())),
        );

        let mut expected = "cubic-bezier(".to_string();
        expected = rt_string::string_append(expected, rt_string::string_from_float(x1));
        expected = rt_string::string_append(expected, ", ".to_string());
        expected = rt_string::string_append(expected, rt_string::string_from_float(y1));
        expected = rt_string::string_append(expected, ", ".to_string());
        expected = rt_string::string_append(expected, rt_string::string_from_float(x2));
        expected = rt_string::string_append(expected, ", ".to_string());
        expected = rt_string::string_append(expected, rt_string::string_from_float(y2));
        expected = rt_string::string_append(expected, ")".to_string());

        assert_eq!(fold_const(&pipeline, &env), Some(ConstValue::Str(expected)));
    }
}
