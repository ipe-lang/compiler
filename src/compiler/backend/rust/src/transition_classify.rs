//! Recognise the data-describable `update` arms and reduce each to an inert
//! transition datum — the logic counterpart of [`crate::emit_template`]'s static
//! subtree partition.
//!
//! A Web/TEA `update` arm returns `(Model, Cmd Msg)`. An arm is DATA-DESCRIBABLE
//! iff its whole effect is one field of the Model set to a value drawn from a
//! tiny closed vocabulary, with `Cmd.none` — no control flow, no function call,
//! no branching, no real `Cmd`. [`transition_of_arm`] returns `Some` only for
//! such an arm and `None` for everything else, so an unprovable arm stays
//! compiled (the recompile path) — conservative by construction, exactly the
//! appearance-vs-logic split.
//!
//! ## Why a shape match, fail-closed
//!
//! The recognised shapes are exactly the four the runtime's `apply_transition`
//! executes: a `Set` from an int / bool / string literal or another field, an
//! `IntAdd` / `IntSub` of a literal against the same field, and a boolean
//! `not` of the same field (`Toggle`). EVERY other arm body — a different
//! operator, a non-literal operand, a multi-field update, a non-`none` `Cmd`, a
//! call, an `if` / `case` — refuses via a final wildcard-free decision and keeps
//! the arm compiled. A new arm shape is therefore never encoded by default.
//!
//! ## Inert by construction (dev == prod)
//!
//! A [`CompileTransition`] carries only a field NAME, a closed op tag, and an
//! inert source (a literal or a field name); it has no code and no nesting,
//! mirroring the runtime `web::transition::Transition`. Its JSON serialization
//! ([`CompileTransition::to_json`]) is byte-identical to the runtime
//! `Transition`'s serde form (pinned by a test), so the emitted baked datum
//! decodes back into exactly the transition it described and `apply_transition`
//! produces byte-identically what the direct compiled arm would — one update
//! semantics, dev == prod.

use crate::emit_template::write_json_string;
use ipe_intern::Symbol;
use ipe_ir::{BinOp, Callee, Expr, KernelFn};

/// The inert operand of a [`CompileTransition`]. Mirrors the runtime
/// `web::transition::Source` — a literal value or a named field read; never an
/// expression, call, or nested transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompileSource {
    Int(i64),
    Bool(bool),
    Str(String),
    /// A read of the value under a named `Model` field (the serde key).
    Field(String),
}

/// The closed op set. Exhaustive and wildcard-free, one-to-one with the runtime
/// `web::transition::TransitionOp`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompileOp {
    Set,
    IntAdd,
    IntSub,
    BoolNot,
}

/// An inert, fully-described single-field `update` transition reduced to data.
///
/// The `field` is the target field's serde KEY (the emitted Rust ident, i.e. the
/// `mangle_reserved` form the runtime keys the Model object by).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompileTransition {
    pub field: String,
    pub op: CompileOp,
    pub source: CompileSource,
}

impl CompileTransition {
    /// Serialize to the JSON the runtime `Transition` decodes — `serde_json`'s
    /// default externally-tagged representation of
    /// `{"field":…,"op":"IntAdd","source":{"Int":1}}`. Deterministic (fixed
    /// field order, deterministic string escaping); byte-identical to
    /// `serde_json::to_string(&Transition)` (pinned by a test).
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut out = String::new();
        out.push_str("{\"field\":");
        write_json_string(&self.field, &mut out);
        out.push_str(",\"op\":\"");
        out.push_str(match self.op {
            CompileOp::Set => "Set",
            CompileOp::IntAdd => "IntAdd",
            CompileOp::IntSub => "IntSub",
            CompileOp::BoolNot => "BoolNot",
        });
        out.push_str("\",\"source\":");
        self.write_source_json(&mut out);
        out.push('}');
        out
    }

    fn write_source_json(&self, out: &mut String) {
        match &self.source {
            CompileSource::Int(n) => {
                out.push_str("{\"Int\":");
                out.push_str(&n.to_string());
                out.push('}');
            }
            CompileSource::Bool(b) => {
                out.push_str("{\"Bool\":");
                out.push_str(if *b { "true" } else { "false" });
                out.push('}');
            }
            CompileSource::Str(s) => {
                out.push_str("{\"Str\":");
                write_json_string(s, out);
                out.push('}');
            }
            CompileSource::Field(name) => {
                out.push_str("{\"Field\":");
                write_json_string(name, out);
                out.push('}');
            }
        }
    }
}

/// Reduce a data-describable `update` arm to a [`CompileTransition`], or `None`.
///
/// Returns `None` when the arm is not provably a single-field data change (any
/// control flow, call, non-literal operand, multi-field update, non-`none`
/// `Cmd`, unrecognised operator) — the caller then keeps the arm compiled
/// (recompile path).
///
/// `model_param` is the `Model` parameter symbol the arm body updates (the
/// `update` function's second parameter); an update of any OTHER record refuses.
/// `resolve` maps a field [`Symbol`] to its serde key (the emitted Rust ident);
/// a symbol that does not resolve refuses.
///
/// Fail-closed everywhere: this is the conservative half of the appearance/logic
/// split for `update`. A false `None` is merely a slower rebuild; a false `Some`
/// that diverged from the compiled arm would be a correctness defect — so every
/// unrecognised shape refuses.
pub fn transition_of_arm(
    body: &Expr,
    model_param: Symbol,
    resolve: &impl Fn(Symbol) -> Option<String>,
) -> Option<CompileTransition> {
    // The arm body of a TEA `update` is `(Model, Cmd Msg)`. Only a two-element
    // tuple whose second element is exactly `Cmd.none` is data-describable; a
    // real `Cmd` (perform / batch / anything else) keeps the arm compiled.
    let Expr::Tuple(elems) = body else {
        return None;
    };
    let [model_expr, cmd_expr] = elems.as_slice() else {
        return None;
    };
    if !is_cmd_none(cmd_expr) {
        return None;
    }

    // The Model result may be a chain of pure `let` bindings ending in the record
    // update — the lowerer hoists a record-update's RHS into a temporary, so
    // `{ m | f = f + 1 }` reaches the backend as `let __upd = f + 1 in
    // { m | f = __upd }`. Peel those leading `let`s into a substitution
    // environment so a later `Var(__upd)` read resolves back to its value; this
    // makes the classifier robust to the LOWERED shape the backend actually sees,
    // not just the surface syntax.
    //
    // The compiled arm evaluates every leading `let` value, so a peeled value with
    // its own semantics (an abort like `1 // 0`, or any effect the emitted
    // transition datum would never reproduce) must refuse — otherwise the hot
    // `apply_transition` path silently drops that evaluation and diverges from the
    // compiled arm. Only a value drawn from the inert vocabulary (a literal, a
    // Model-field read, or a recognised int-op / `not` over those) is safe to peel;
    // anything else returns `None` (the arm stays compiled).
    let mut env: Vec<(Symbol, &Expr)> = Vec::new();
    let mut cursor = model_expr;
    while let Expr::Let { name, value, body } = cursor {
        if !is_inert_peelable(value.as_ref(), model_param, &env) {
            return None;
        }
        env.push((*name, value.as_ref()));
        cursor = body.as_ref();
    }

    single_field_update(cursor, model_param, resolve, &env)
}

/// Resolve `expr` through the peeled-`let` substitution environment: a bare
/// `Var`/`CloneVar` bound in `env` is replaced by its bound value, transitively
/// (a temporary bound to another temporary). Any non-variable expression is
/// itself. Total and terminating — the environment is a finite list built from a
/// straight-line `let` chain, so following bindings cannot cycle.
fn deref_subst<'e>(expr: &'e Expr, env: &[(Symbol, &'e Expr)]) -> &'e Expr {
    let mut current = expr;
    // Bounded by the environment length: each hop consumes one binding, and a
    // lowered `let` chain never rebinds a name, so this cannot loop.
    for _ in 0..=env.len() {
        let sym = match current {
            Expr::Var(s) | Expr::CloneVar(s) => *s,
            _ => return current,
        };
        match env.iter().find(|(name, _)| *name == sym) {
            Some((_, value)) => current = value,
            None => return current,
        }
    }
    current
}

/// Whether a peeled `let` value is drawn from the inert vocabulary the emitted
/// transition datum faithfully reproduces, so dropping its direct evaluation on
/// the hot path cannot diverge from the compiled arm.
///
/// Inert values, exhaustively: an int / bool / string literal; a read of the
/// `Model` parameter itself or of one of its fields; a variable already bound in
/// the peeled environment (a temporary whose own value was already vetted inert
/// when it was peeled); and an `IntAdd` / `IntSub` or a `not` whose operands are
/// themselves inert. Anything else — a division (which may abort), any other
/// operator, a call, a field expression, an unbound variable — is NOT inert and
/// refuses, keeping the arm compiled.
fn is_inert_peelable(expr: &Expr, model_param: Symbol, env: &[(Symbol, &Expr)]) -> bool {
    match expr {
        Expr::Int(_) | Expr::Bool(_) | Expr::Str(_) => true,
        // A read of the Model parameter, or of a temporary already peeled inert.
        Expr::Var(sym) | Expr::CloneVar(sym) => {
            *sym == model_param || env.iter().any(|(name, _)| name == sym)
        }
        // A field read on the Model parameter (`model.field`).
        Expr::Access { record, .. } => is_inert_peelable(record, model_param, env),
        // Only the closed int ops the transition vocabulary reproduces; a division
        // or any other operator can carry an abort and refuses.
        Expr::BinOp { op, lhs, rhs } => {
            matches!(op, BinOp::IntAdd | BinOp::IntSub)
                && is_inert_peelable(lhs, model_param, env)
                && is_inert_peelable(rhs, model_param, env)
        }
        // A boolean `not` over an inert operand.
        Expr::Call {
            callee: Callee::Kernel(KernelFn::BasicsNot),
            args,
            ..
        } => matches!(args.as_slice(), [arg] if is_inert_peelable(arg, model_param, env)),
        _ => false,
    }
}

/// Whether `expr` is exactly `Cmd.none` — the nullary `CmdNone` kernel call. Any
/// other `Cmd` (`Cmd.batch`, `Cmd.perform`, a variable) refuses.
const fn is_cmd_none(expr: &Expr) -> bool {
    matches!(
        expr,
        Expr::Call {
            callee: Callee::Kernel(KernelFn::CmdNone),
            args,
            ..
        } if args.is_empty()
    )
}

/// Reduce `{ model | field = rhs }` (a single-field update of the `Model`
/// parameter) to a transition, or `None`.
fn single_field_update(
    expr: &Expr,
    model_param: Symbol,
    resolve: &impl Fn(Symbol) -> Option<String>,
    env: &[(Symbol, &Expr)],
) -> Option<CompileTransition> {
    let Expr::Update { record, fields } = expr else {
        return None;
    };
    // The updated record must be the Model parameter itself — `{ m | … }`, never
    // `{ someOther | … }` (which would not be the arm's Model result). Deref
    // through the peeled-`let` environment in case the record is a temporary.
    if !is_var(deref_subst(record, env), model_param) {
        return None;
    }
    // Exactly one field changes. A multi-field update is not a single
    // data-describable transition (this slice's scope).
    let [(field_sym, rhs)] = fields.as_slice() else {
        return None;
    };
    let field = resolve(*field_sym)?;
    // Resolve the field RHS through the peeled-`let` environment: the lowerer
    // hoists `count + 1` into a temporary, so the update's RHS is a `Var` that
    // dereferences to the actual `BinOp` / literal.
    let rhs = deref_subst(rhs, env);
    let (op, source) = classify_rhs(rhs, &field, model_param, resolve, env)?;
    Some(CompileTransition { field, op, source })
}

/// Classify the right-hand side of a single-field update into `(op, source)`, or
/// `None` for anything outside the closed vocabulary.
///
/// The recognised shapes, exhaustively:
/// * an int / bool / string literal → `Set` from that literal;
/// * a read of another Model field → `Set` from that field;
/// * `field <int-op> <int-literal>` where the read is the SAME field being
///   assigned → `IntAdd` / `IntSub` from the literal (`count = count + 1`);
/// * `not field` where the read is the SAME field → `BoolNot` (`on = not on`).
///
/// Everything else — a different operator, a non-literal operand, an operand
/// that reads a DIFFERENT field in an arithmetic op, a nested expression —
/// refuses.
fn classify_rhs(
    rhs: &Expr,
    target_field: &str,
    model_param: Symbol,
    resolve: &impl Fn(Symbol) -> Option<String>,
    env: &[(Symbol, &Expr)],
) -> Option<(CompileOp, CompileSource)> {
    match rhs {
        // A bare literal set.
        Expr::Int(n) => Some((CompileOp::Set, CompileSource::Int(*n))),
        Expr::Bool(b) => Some((CompileOp::Set, CompileSource::Bool(*b))),
        Expr::Str(s) => Some((CompileOp::Set, CompileSource::Str(s.clone()))),
        // A set from another Model field: `{ m | a = b }` (b a field read on the
        // Model). The read must be `model.field`; anything else refuses.
        Expr::Access { .. } => {
            let name = field_read(rhs, model_param, resolve, env)?;
            Some((CompileOp::Set, CompileSource::Field(name)))
        }
        // `field + lit` / `field - lit` — the LHS must read the SAME field being
        // assigned (`count = count + 1`), the RHS an int literal. A cross-field
        // arithmetic (`count = other + 1`) or a non-literal RHS refuses: the
        // runtime `IntAdd`/`IntSub` reads the target field as its accumulator, so
        // only a same-field self-increment is faithful to it. Both operands are
        // dereferenced through the peeled-`let` environment first, since the
        // lowerer may bind them to temporaries.
        Expr::BinOp { op, lhs, rhs: rhs2 } => {
            let compile_op = match op {
                BinOp::IntAdd => CompileOp::IntAdd,
                BinOp::IntSub => CompileOp::IntSub,
                _ => return None,
            };
            let lhs_field = field_read(deref_subst(lhs, env), model_param, resolve, env)?;
            if lhs_field != target_field {
                return None;
            }
            let Expr::Int(n) = deref_subst(rhs2, env) else {
                return None;
            };
            Some((compile_op, CompileSource::Int(*n)))
        }
        // `not field` — the argument must read the SAME field being assigned
        // (`on = not on`). The runtime `BoolNot` negates the target field, so a
        // `not otherField` would diverge and refuses.
        Expr::Call {
            callee: Callee::Kernel(KernelFn::BasicsNot),
            args,
            ..
        } => {
            let [arg] = args.as_slice() else {
                return None;
            };
            let arg_field = field_read(deref_subst(arg, env), model_param, resolve, env)?;
            if arg_field != target_field {
                return None;
            }
            Some((
                CompileOp::BoolNot,
                CompileSource::Field(target_field.to_owned()),
            ))
        }
        _ => None,
    }
}

/// If `expr` is a read of a field on the `Model` parameter (`model.field`),
/// return that field's serde key; else `None`. The record sub-expression is
/// dereferenced through the peeled-`let` environment, so a `model` bound to a
/// temporary still resolves.
fn field_read(
    expr: &Expr,
    model_param: Symbol,
    resolve: &impl Fn(Symbol) -> Option<String>,
    env: &[(Symbol, &Expr)],
) -> Option<String> {
    let Expr::Access { record, field, .. } = expr else {
        return None;
    };
    if !is_var(deref_subst(record, env), model_param) {
        return None;
    }
    resolve(*field)
}

/// Whether `expr` is a variable read of exactly `sym`. A `CloneVar` (a
/// capture-clone of the same binder) is equally a read of that binder, so both
/// count — the Model parameter may be read either way inside the arm body.
fn is_var(expr: &Expr, sym: Symbol) -> bool {
    matches!(expr, Expr::Var(s) | Expr::CloneVar(s) if *s == sym)
}

// ─── data-describable `init` → an inert init datum ──────────────────────────
//
// The STARTING-`Model` counterpart of `transition_of_arm`. A Web/TEA `init`
// returns `(Model, Cmd Msg)`. An `init` is DATA-DESCRIBABLE iff its whole
// starting Model is a record LITERAL of closed leaf values (int/bool/string),
// with `Cmd.none` and no control flow, call, or field expression.
// [`init_datum_of_body`] returns `Some` only for such an `init` and `None` for
// everything else, so an unprovable `init` stays compiled (the recompile path)
// — conservative by construction, exactly the transition split. The reduced
// datum is a self-describing JSON object (the same field-keyed shape the runtime
// `InitDatum` strict-decodes into the real `Model`), so a hot-swap of the datum
// produces byte-identically what a full recompile of the same `init` would seed
// a fresh session with — one init semantics, dev == prod.

/// An inert, fully-described data-describable `init` reduced to data: the
/// starting `Model`'s fields as `(serde key, leaf source)` pairs, in the record
/// literal's order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompileInitDatum {
    /// Each starting `Model` field as `(serde KEY, leaf value)`. The key is the
    /// emitted Rust field ident (the `mangle_reserved` form the runtime keys the
    /// Model object by).
    pub fields: Vec<(String, CompileLeaf)>,
}

/// A closed leaf value in a data-describable `init` record. Only the three JSON
/// scalar leaves an `InitDatum` object body carries; anything else refuses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompileLeaf {
    Int(i64),
    Bool(bool),
    Str(String),
}

impl CompileInitDatum {
    /// Serialize to the JSON the runtime `InitDatum` decodes —
    /// `{"model":{<key>:<leaf>,...}}` in the record literal's field order.
    /// Deterministic (fixed key order, deterministic string escaping); the body
    /// is the same self-describing object shape the checkpoint codec uses, so it
    /// strict-decodes into the real `Model` (pinned by a conformance test).
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut out = String::new();
        out.push_str("{\"model\":{");
        for (i, (key, leaf)) in self.fields.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            write_json_string(key, &mut out);
            out.push(':');
            leaf.write_json(&mut out);
        }
        out.push_str("}}");
        out
    }
}

impl CompileLeaf {
    fn write_json(&self, out: &mut String) {
        match self {
            Self::Int(n) => out.push_str(&n.to_string()),
            Self::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Self::Str(s) => write_json_string(s, out),
        }
    }
}

/// Reduce a data-describable `init` body to a [`CompileInitDatum`], or `None`.
///
/// Returns `None` when the `init` is not provably a record literal of closed leaf
/// values with `Cmd.none` (any control flow, call, field expression, non-`none`
/// `Cmd`, a non-record starting Model, or an unresolvable field) — the caller
/// then keeps the `init` compiled (recompile path).
///
/// `resolve` maps a field [`Symbol`] to its serde key (the emitted Rust ident); a
/// symbol that does not resolve refuses.
///
/// Fail-closed everywhere: a false `None` is merely a slower rebuild; a false
/// `Some` that diverged from the compiled `init` would be a correctness defect —
/// so every unrecognised shape refuses.
pub fn init_datum_of_body(
    body: &Expr,
    resolve: &impl Fn(Symbol) -> Option<String>,
) -> Option<CompileInitDatum> {
    // The `init` body of a TEA app is `(Model, Cmd Msg)`. Only a two-element
    // tuple whose second element is exactly `Cmd.none` is data-describable; a
    // real `Cmd` keeps the `init` compiled.
    let Expr::Tuple(elems) = body else {
        return None;
    };
    let [model_expr, cmd_expr] = elems.as_slice() else {
        return None;
    };
    if !is_cmd_none(cmd_expr) {
        return None;
    }
    // The starting Model must be a record LITERAL — `{ f = lit, ... }`, never an
    // update, call, or `if`. Every field value must be a closed leaf; anything
    // else (a field read, an arithmetic, a nested record) refuses.
    let Expr::Record { fields, .. } = model_expr else {
        return None;
    };
    let mut out = Vec::with_capacity(fields.len());
    for (field_sym, value) in fields {
        let key = resolve(*field_sym)?;
        let leaf = leaf_of(value)?;
        out.push((key, leaf));
    }
    Some(CompileInitDatum { fields: out })
}

/// Reduce a field value to a closed [`CompileLeaf`], or `None` for anything
/// outside the closed leaf vocabulary (a field read, an operator, a call, a
/// nested record — all keep the `init` compiled).
fn leaf_of(value: &Expr) -> Option<CompileLeaf> {
    match value {
        Expr::Int(n) => Some(CompileLeaf::Int(*n)),
        Expr::Bool(b) => Some(CompileLeaf::Bool(*b)),
        Expr::Str(s) => Some(CompileLeaf::Str(s.clone())),
        _ => None,
    }
}

// ─── data-describable Cmd WIRING → an inert wiring datum ────────────────────
//
// The Cmd counterpart of `transition_of_arm`'s model half. An `update` arm's Cmd
// position — the SECOND element of its `(Model, Cmd Msg)` tuple — is classified
// into a closed wiring vocabulary: `Cmd.none` (fire no effect). The effect BODY
// (a real `Cmd.perform`/`Cmd.batch`) is NOT reduced — it stays compiled — but the
// WIRING (whether an effect fires, and eventually WHICH by stable id) becomes a
// datum. This slice recognises the `Cmd.none` wiring, so an arm whose model is
// data-describable can carry its Cmd position as data selected by the compiled
// `select_cmd_hot`; a real effect keeps the arm's Cmd compiled (recompile path),
// exactly the conservative body/wiring split the spec calls for.

/// The compile-time counterpart of the runtime `web::cmd_wiring::CmdWiring`: which
/// compiled effect (by stable id) an arm fires, or `None` for no effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompileCmdWiring {
    /// The stable id of the compiled effect the arm fires, or `None` for
    /// `Cmd.none`. An id indexes the arm's compiled effect table.
    pub effect: Option<u32>,
}

impl CompileCmdWiring {
    /// Serialize to the JSON the runtime `CmdWiring` decodes —
    /// `{"effect":null}` or `{"effect":<id>}`. Deterministic; byte-identical to
    /// `serde_json::to_string(&CmdWiring)` (pinned by a conformance test).
    #[must_use]
    pub fn to_json(&self) -> String {
        self.effect.map_or_else(
            || "{\"effect\":null}".to_owned(),
            |id| format!("{{\"effect\":{id}}}"),
        )
    }
}

/// An `update` arm's Cmd position reduced to a wiring datum PLUS the arm's sole
/// compiled effect expression (stable id 0).
///
/// The datum names WHICH effect fires (or none); the effect expression stays
/// compiled — the backend emits it as a lazy `FnOnce` thunk and the runtime fires
/// it only when selected. At most one effect has a representation, so no two
/// thunks can move the same binding.
#[derive(Clone, Debug)]
pub struct ArmWiring<'e> {
    /// Which compiled effect the arm fires, or `None` (`Cmd.none`).
    pub wiring: CompileCmdWiring,
    /// The arm's compiled effect expression, id 0: `None` for `Cmd.none`, the
    /// `Cmd.perform` itself for a single literal `Cmd.perform`. A `wiring.effect`
    /// id, when present, is 0 and names this effect by construction.
    pub effect: Option<&'e Expr>,
}

/// Classify an `update` arm's Cmd position (the second tuple element) into an
/// inert [`CompileCmdWiring`], or `None` when the Cmd is not a recognised wiring.
///
/// Recognised: `Cmd.none` → the no-effect wiring (`effect: None`); a single literal
/// `Cmd.perform` → the effect-0 wiring. Everything else — a `Cmd.batch`, a
/// `Cmd.map`, a variable, a computed Cmd — is not enumerable, so it returns `None`
/// (the arm's Cmd stays compiled). Conservative by construction: a false `None` is
/// a slower rebuild; a false `Some` that fired the wrong effect would be a
/// correctness defect, so every unrecognised Cmd refuses.
#[must_use]
pub fn cmd_wiring_of_arm(body: &Expr) -> Option<CompileCmdWiring> {
    arm_wiring_of_arm(body).map(|w| w.wiring)
}

/// Classify an `update` arm's Cmd position into an [`ArmWiring`] — the wiring datum
/// AND the arm's ordered compiled-effect table — or `None` for a non-enumerable Cmd.
///
/// The closed *choice* vocabulary, exhaustively:
/// * `Cmd.none` → the no-effect wiring (`effect: None`), an empty effect table;
/// * a single literal `Cmd.perform <task> <toMsg>` → the wiring `effect: Some(0)`
///   over a one-entry effect table holding that `Cmd.perform` expression.
///
/// Everything else — a `Cmd.batch`, a `Cmd.map`, a variable, a computed/dynamic
/// Cmd, an `if`/`case` over Cmds, or a `Cmd.perform` under any other spelling — is
/// NOT enumerable and refuses (`None`), keeping the arm's Cmd compiled. This is
/// fail-closed by construction: a false `None` is a slower rebuild; a false `Some`
/// that wired the wrong effect crosses the Msg/effect trust boundary, so every
/// non-enumerable Cmd refuses.
#[must_use]
pub const fn arm_wiring_of_arm(body: &Expr) -> Option<ArmWiring<'_>> {
    let Expr::Tuple(elems) = body else {
        return None;
    };
    let [_model_expr, cmd_expr] = elems.as_slice() else {
        return None;
    };
    if is_cmd_none(cmd_expr) {
        return Some(ArmWiring {
            wiring: CompileCmdWiring { effect: None },
            effect: None,
        });
    }
    if is_literal_perform(cmd_expr) {
        // A single literal `Cmd.perform` is the arm's sole compiled effect, id 0.
        return Some(ArmWiring {
            wiring: CompileCmdWiring { effect: Some(0) },
            effect: Some(cmd_expr),
        });
    }
    None
}

/// Whether `expr` is exactly a literal `Cmd.perform <task> <toMsg>` — the arity-2
/// `CmdPerform` kernel call. A `Task.attempt`, `Cmd.map`, `Cmd.batch`, a variable,
/// or a `Cmd.perform` with the wrong argument count is NOT this closed shape and
/// refuses (the arm's Cmd stays compiled). The task/toMsg arguments are NOT
/// inspected — the effect BODY stays compiled exactly as written; only the WIRING
/// (that this arm fires this one effect) becomes data.
const fn is_literal_perform(expr: &Expr) -> bool {
    matches!(
        expr,
        Expr::Call {
            callee: Callee::Kernel(KernelFn::CmdPerform),
            args,
            ..
        } if args.len() == 2
    )
}

#[cfg(test)]
mod tests {
    use super::{
        CompileOp, CompileSource, CompileTransition, transition_of_arm, write_json_string,
    };
    use ipe_intern::Symbol;
    use ipe_ir::{BinOp, CallPin, Callee, Expr, IrType, KernelFn, OnFormKind};

    // Fixed symbols for the test model + its fields. A resolver maps them to
    // serde keys.
    fn model_sym() -> Symbol {
        Symbol::from_raw(1)
    }
    fn count_sym() -> Symbol {
        Symbol::from_raw(2)
    }
    fn name_sym() -> Symbol {
        Symbol::from_raw(3)
    }
    fn on_sym() -> Symbol {
        Symbol::from_raw(4)
    }

    fn resolver(sym: Symbol) -> Option<String> {
        match sym.as_raw() {
            2 => Some("count".to_owned()),
            3 => Some("name".to_owned()),
            4 => Some("on".to_owned()),
            _ => None,
        }
    }

    fn cmd_none() -> Expr {
        Expr::Call {
            callee: Callee::Kernel(KernelFn::CmdNone),
            args: vec![],
            pin: CallPin::None,
            on_form: OnFormKind::NotForm,
        }
    }

    fn model_access(field: Symbol) -> Expr {
        Expr::Access {
            record: Box::new(Expr::Var(model_sym())),
            field,
            field_ty: IrType::Int,
        }
    }

    /// `( { m | <field> = <rhs> }, Cmd.none )` — the TEA arm body shape.
    fn arm_body(field: Symbol, rhs: Expr) -> Expr {
        Expr::Tuple(vec![
            Expr::Update {
                record: Box::new(Expr::Var(model_sym())),
                fields: vec![(field, rhs)],
            },
            cmd_none(),
        ])
    }

    fn classify(body: &Expr) -> Option<CompileTransition> {
        transition_of_arm(body, model_sym(), &resolver)
    }

    // ── the LOWERED shape the backend actually sees ───────────────────────
    //
    // `ipe_lower::lower_update` lowers `{ m | count = count + 1 }` to a DIRECT
    // `Expr::Update` whose one field's RHS is the lowered `count + 1` in place —
    // it does NOT hoist the RHS into a `let __upd = …` temporary. So the arm body
    // of `Increment -> ({ m | count = count + 1 }, Cmd.none)` reaches this
    // classifier as `( { m | count = <BinOp IntAdd (m.count) 1> }, Cmd.none )`,
    // the field RHS a direct `BinOp`. This fixture is that exact shape, built the
    // way the lowerer builds it, so the classifier test and the emit path agree by
    // construction — a fabricated let-hoisted shape (which the backend never emits)
    // previously masked the real match arm never being rewritten.
    #[test]
    fn lowered_direct_update_increment_classifies() {
        // Mirror `ipe_lower::lower_update`: a direct `Expr::Update` with the field
        // RHS lowered in place, no `let` temporary.
        let inc = Expr::BinOp {
            op: BinOp::IntAdd,
            lhs: Box::new(model_access(count_sym())),
            rhs: Box::new(Expr::Int(1)),
        };
        let body = Expr::Tuple(vec![
            Expr::Update {
                record: Box::new(Expr::Var(model_sym())),
                fields: vec![(count_sym(), inc)],
            },
            cmd_none(),
        ]);
        assert_eq!(
            classify(&body),
            Some(CompileTransition {
                field: "count".to_owned(),
                op: CompileOp::IntAdd,
                source: CompileSource::Int(1),
            }),
            "the direct lowered update arm the backend emits must classify"
        );
    }

    #[test]
    fn peeled_inert_let_still_classifies() {
        // `let t = count + 1 in ({ m | count = t }, Cmd.none)` — the peeled binding
        // is an inert int-op over a field read, so it is safe to peel and the arm
        // classifies to the same IntAdd transition.
        let t = Symbol::from_raw(200);
        let model_pos = Expr::Let {
            name: t,
            value: Box::new(Expr::BinOp {
                op: BinOp::IntAdd,
                lhs: Box::new(model_access(count_sym())),
                rhs: Box::new(Expr::Int(1)),
            }),
            body: Box::new(Expr::Update {
                record: Box::new(Expr::Var(model_sym())),
                fields: vec![(count_sym(), Expr::Var(t))],
            }),
        };
        let body = Expr::Tuple(vec![model_pos, cmd_none()]);
        assert_eq!(
            classify(&body),
            Some(CompileTransition {
                field: "count".to_owned(),
                op: CompileOp::IntAdd,
                source: CompileSource::Int(1),
            })
        );
    }

    #[test]
    fn peeled_non_inert_let_refuses() {
        // `let x = count // 0 in ({ m | count = 5 }, Cmd.none)` — the peeled binding
        // aborts when evaluated. The compiled arm takes that abort; the transition
        // datum would silently skip it, so the classifier must refuse (keep the arm
        // compiled) rather than emit a diverging Some.
        let x = Symbol::from_raw(201);
        let model_pos = Expr::Let {
            name: x,
            value: Box::new(Expr::BinOp {
                op: BinOp::IntDiv,
                lhs: Box::new(model_access(count_sym())),
                rhs: Box::new(Expr::Int(0)),
            }),
            body: Box::new(Expr::Update {
                record: Box::new(Expr::Var(model_sym())),
                fields: vec![(count_sym(), Expr::Int(5))],
            }),
        };
        let body = Expr::Tuple(vec![model_pos, cmd_none()]);
        assert_eq!(classify(&body), None);
    }

    // ── acceptance: the four data-describable shapes ──────────────────────

    #[test]
    fn increment_same_field_is_int_add() {
        // Increment -> ({ m | count = count + 1 }, Cmd.none)
        let rhs = Expr::BinOp {
            op: BinOp::IntAdd,
            lhs: Box::new(model_access(count_sym())),
            rhs: Box::new(Expr::Int(1)),
        };
        assert_eq!(
            classify(&arm_body(count_sym(), rhs)),
            Some(CompileTransition {
                field: "count".to_owned(),
                op: CompileOp::IntAdd,
                source: CompileSource::Int(1),
            })
        );
    }

    #[test]
    fn decrement_same_field_is_int_sub() {
        let rhs = Expr::BinOp {
            op: BinOp::IntSub,
            lhs: Box::new(model_access(count_sym())),
            rhs: Box::new(Expr::Int(2)),
        };
        assert_eq!(
            classify(&arm_body(count_sym(), rhs)),
            Some(CompileTransition {
                field: "count".to_owned(),
                op: CompileOp::IntSub,
                source: CompileSource::Int(2),
            })
        );
    }

    #[test]
    fn set_string_field_from_literal() {
        let rhs = Expr::Str("hello".to_owned());
        assert_eq!(
            classify(&arm_body(name_sym(), rhs)),
            Some(CompileTransition {
                field: "name".to_owned(),
                op: CompileOp::Set,
                source: CompileSource::Str("hello".to_owned()),
            })
        );
    }

    #[test]
    fn reset_int_field_to_literal_is_set() {
        assert_eq!(
            classify(&arm_body(count_sym(), Expr::Int(0))),
            Some(CompileTransition {
                field: "count".to_owned(),
                op: CompileOp::Set,
                source: CompileSource::Int(0),
            })
        );
    }

    #[test]
    fn toggle_bool_field_is_bool_not() {
        // Toggle -> ({ m | on = not on }, Cmd.none)
        let rhs = Expr::Call {
            callee: Callee::Kernel(KernelFn::BasicsNot),
            args: vec![model_access(on_sym())],
            pin: CallPin::None,
            on_form: OnFormKind::NotForm,
        };
        assert_eq!(
            classify(&arm_body(on_sym(), rhs)),
            Some(CompileTransition {
                field: "on".to_owned(),
                op: CompileOp::BoolNot,
                source: CompileSource::Field("on".to_owned()),
            })
        );
    }

    #[test]
    fn set_field_from_another_field() {
        // { m | count = <other-field-read> } via a field access RHS.
        let rhs = model_access(name_sym());
        assert_eq!(
            classify(&arm_body(count_sym(), rhs)),
            Some(CompileTransition {
                field: "count".to_owned(),
                op: CompileOp::Set,
                source: CompileSource::Field("name".to_owned()),
            })
        );
    }

    // ── refusal: everything not provably a single data change ─────────────

    #[test]
    fn real_cmd_refuses() {
        // ({ m | count = 0 }, Cmd.batch []) — a non-none Cmd keeps it compiled.
        let real_cmd = Expr::Call {
            callee: Callee::Kernel(KernelFn::CmdBatch),
            args: vec![Expr::List {
                elem: IrType::Int,
                items: vec![],
            }],
            pin: CallPin::None,
            on_form: OnFormKind::NotForm,
        };
        let body = Expr::Tuple(vec![
            Expr::Update {
                record: Box::new(Expr::Var(model_sym())),
                fields: vec![(count_sym(), Expr::Int(0))],
            },
            real_cmd,
        ]);
        assert_eq!(classify(&body), None);
    }

    #[test]
    fn cross_field_arithmetic_refuses() {
        // { m | count = name + 1 } — LHS reads a DIFFERENT field than the target.
        let rhs = Expr::BinOp {
            op: BinOp::IntAdd,
            lhs: Box::new(model_access(name_sym())),
            rhs: Box::new(Expr::Int(1)),
        };
        assert_eq!(classify(&arm_body(count_sym(), rhs)), None);
    }

    #[test]
    fn non_literal_arithmetic_operand_refuses() {
        // { m | count = count + count } — RHS operand is a field read, not a literal.
        let rhs = Expr::BinOp {
            op: BinOp::IntAdd,
            lhs: Box::new(model_access(count_sym())),
            rhs: Box::new(model_access(count_sym())),
        };
        assert_eq!(classify(&arm_body(count_sym(), rhs)), None);
    }

    #[test]
    fn unrecognised_operator_refuses() {
        // { m | count = count * 2 } — Mul is outside the closed op set.
        let rhs = Expr::BinOp {
            op: BinOp::IntMul,
            lhs: Box::new(model_access(count_sym())),
            rhs: Box::new(Expr::Int(2)),
        };
        assert_eq!(classify(&arm_body(count_sym(), rhs)), None);
    }

    #[test]
    fn multi_field_update_refuses() {
        // { m | count = 0, name = "x" } — more than one field changes.
        let body = Expr::Tuple(vec![
            Expr::Update {
                record: Box::new(Expr::Var(model_sym())),
                fields: vec![
                    (count_sym(), Expr::Int(0)),
                    (name_sym(), Expr::Str("x".to_owned())),
                ],
            },
            cmd_none(),
        ]);
        assert_eq!(classify(&body), None);
    }

    #[test]
    fn update_of_non_model_record_refuses() {
        // { other | count = 0 } — the updated record is not the Model parameter.
        let other = Symbol::from_raw(99);
        let body = Expr::Tuple(vec![
            Expr::Update {
                record: Box::new(Expr::Var(other)),
                fields: vec![(count_sym(), Expr::Int(0))],
            },
            cmd_none(),
        ]);
        assert_eq!(classify(&body), None);
    }

    #[test]
    fn branching_body_refuses() {
        // An `if` in the arm body is not a bare (Model, Cmd) tuple.
        let body = Expr::If {
            cond: Box::new(Expr::Bool(true)),
            then_: Box::new(arm_body(count_sym(), Expr::Int(1))),
            else_: Box::new(arm_body(count_sym(), Expr::Int(2))),
        };
        assert_eq!(classify(&body), None);
    }

    #[test]
    fn function_call_body_refuses() {
        // The arm delegates to a helper — not a bare update tuple.
        let body = Expr::Apply {
            func: Box::new(Expr::Var(Symbol::from_raw(50))),
            args: vec![Expr::Var(model_sym())],
        };
        assert_eq!(classify(&body), None);
    }

    #[test]
    fn toggle_of_different_field_refuses() {
        // { m | on = not count } — negates a DIFFERENT field than the target.
        let rhs = Expr::Call {
            callee: Callee::Kernel(KernelFn::BasicsNot),
            args: vec![model_access(count_sym())],
            pin: CallPin::None,
            on_form: OnFormKind::NotForm,
        };
        assert_eq!(classify(&arm_body(on_sym(), rhs)), None);
    }

    #[test]
    fn unresolved_field_symbol_refuses() {
        // A field symbol the resolver does not know refuses (never a guessed key).
        let unknown = Symbol::from_raw(77);
        assert_eq!(classify(&arm_body(unknown, Expr::Int(0))), None);
    }

    // ── data-describable `init` → an init datum ──────────────────────────

    use super::{CompileInitDatum, CompileLeaf, init_datum_of_body};

    /// `( { count = <c>, name = <n>, on = <o> }, Cmd.none )` — the TEA `init`
    /// body shape.
    fn init_body(fields: Vec<(Symbol, Expr)>) -> Expr {
        Expr::Tuple(vec![Expr::Record { fields, ty: None }, cmd_none()])
    }

    fn classify_init(body: &Expr) -> Option<CompileInitDatum> {
        init_datum_of_body(body, &resolver)
    }

    #[test]
    fn record_literal_init_classifies() {
        let body = init_body(vec![
            (count_sym(), Expr::Int(0)),
            (name_sym(), Expr::Str("start".to_owned())),
            (on_sym(), Expr::Bool(false)),
        ]);
        assert_eq!(
            classify_init(&body),
            Some(CompileInitDatum {
                fields: vec![
                    ("count".to_owned(), CompileLeaf::Int(0)),
                    ("name".to_owned(), CompileLeaf::Str("start".to_owned())),
                    ("on".to_owned(), CompileLeaf::Bool(false)),
                ],
            })
        );
    }

    #[test]
    fn init_datum_json_shape() {
        let d = CompileInitDatum {
            fields: vec![
                ("count".to_owned(), CompileLeaf::Int(0)),
                ("name".to_owned(), CompileLeaf::Str("a\"b".to_owned())),
                ("on".to_owned(), CompileLeaf::Bool(true)),
            ],
        };
        assert_eq!(
            d.to_json(),
            r#"{"model":{"count":0,"name":"a\"b","on":true}}"#
        );
    }

    #[test]
    fn init_with_real_cmd_refuses() {
        let real_cmd = Expr::Call {
            callee: Callee::Kernel(KernelFn::CmdBatch),
            args: vec![Expr::List {
                elem: IrType::Int,
                items: vec![],
            }],
            pin: CallPin::None,
            on_form: OnFormKind::NotForm,
        };
        let body = Expr::Tuple(vec![
            Expr::Record {
                fields: vec![(count_sym(), Expr::Int(0))],
                ty: None,
            },
            real_cmd,
        ]);
        assert_eq!(classify_init(&body), None);
    }

    #[test]
    fn init_with_field_expression_refuses() {
        // `{ count = someCall x }` — a non-leaf field value keeps `init` compiled.
        let call = Expr::Apply {
            func: Box::new(Expr::Var(Symbol::from_raw(50))),
            args: vec![Expr::Int(1)],
        };
        assert_eq!(classify_init(&init_body(vec![(count_sym(), call)])), None);
    }

    #[test]
    fn init_with_field_read_refuses() {
        // `{ count = m.count }` — a field read is not a closed leaf.
        assert_eq!(
            classify_init(&init_body(vec![(count_sym(), model_access(count_sym()))])),
            None
        );
    }

    #[test]
    fn init_non_record_model_refuses() {
        // `init _ = ( update_via_helper, Cmd.none )` — a non-record starting Model.
        let body = Expr::Tuple(vec![Expr::Var(Symbol::from_raw(60)), cmd_none()]);
        assert_eq!(classify_init(&body), None);
    }

    #[test]
    fn init_unresolved_field_refuses() {
        let unknown = Symbol::from_raw(77);
        assert_eq!(
            classify_init(&init_body(vec![(unknown, Expr::Int(0))])),
            None
        );
    }

    // ── Cmd wiring → an inert wiring datum ───────────────────────────────

    use super::{CompileCmdWiring, arm_wiring_of_arm, cmd_wiring_of_arm};

    fn cmd_perform() -> Expr {
        // `Cmd.perform <task> <toMsg>` — a literal arity-2 perform. The argument
        // exprs are opaque stand-ins; the classifier does not inspect them.
        Expr::Call {
            callee: Callee::Kernel(KernelFn::CmdPerform),
            args: vec![
                Expr::Var(Symbol::from_raw(80)),
                Expr::Var(Symbol::from_raw(81)),
            ],
            pin: CallPin::None,
            on_form: OnFormKind::NotForm,
        }
    }

    #[test]
    fn cmd_perform_arm_wires_effect_zero() {
        // A single literal `Cmd.perform` arm classifies as the effect-0 wiring over a
        // one-entry compiled effect table.
        let body = Expr::Tuple(vec![Expr::Int(0), cmd_perform()]);
        let arm = arm_wiring_of_arm(&body).expect("a literal Cmd.perform arm is enumerable");
        assert_eq!(arm.wiring, CompileCmdWiring { effect: Some(0) });
        let sole: Option<&Expr> = arm.effect;
        assert!(sole.is_some(), "the perform is the arm's sole effect");
    }

    #[test]
    fn cmd_none_arm_has_empty_effect_table() {
        // A `Cmd.none` arm is the no-effect wiring over an empty table.
        let body = Expr::Tuple(vec![Expr::Int(0), cmd_none()]);
        let arm = arm_wiring_of_arm(&body).expect("Cmd.none is enumerable");
        assert_eq!(arm.wiring, CompileCmdWiring { effect: None });
        assert!(arm.effect.is_none());
    }

    #[test]
    fn cmd_batch_arm_is_not_enumerable() {
        // A `Cmd.batch` (a dynamic list of effects) is NOT a closed choice — refuses.
        let real = Expr::Call {
            callee: Callee::Kernel(KernelFn::CmdBatch),
            args: vec![Expr::List {
                elem: IrType::Int,
                items: vec![],
            }],
            pin: CallPin::None,
            on_form: OnFormKind::NotForm,
        };
        let body = Expr::Tuple(vec![Expr::Int(0), real]);
        assert!(arm_wiring_of_arm(&body).is_none());
    }

    #[test]
    fn cmd_variable_arm_is_not_enumerable() {
        // A Cmd bound to a variable (a computed / passed-through effect) refuses.
        let body = Expr::Tuple(vec![Expr::Int(0), Expr::Var(Symbol::from_raw(90))]);
        assert!(arm_wiring_of_arm(&body).is_none());
    }

    #[test]
    fn cmd_map_arm_is_not_enumerable() {
        // `Cmd.map` (a retagged sub-component effect) is outside the closed vocabulary.
        let mapped = Expr::Call {
            callee: Callee::Kernel(KernelFn::CmdMap),
            args: vec![Expr::Var(Symbol::from_raw(91)), cmd_perform()],
            pin: CallPin::None,
            on_form: OnFormKind::NotForm,
        };
        let body = Expr::Tuple(vec![Expr::Int(0), mapped]);
        assert!(arm_wiring_of_arm(&body).is_none());
    }

    #[test]
    fn cmd_none_arm_wires_no_effect() {
        // `Increment -> ({ m | count = count + 1 }, Cmd.none)` — the Cmd position
        // is `Cmd.none`, the no-effect wiring.
        let rhs = Expr::BinOp {
            op: BinOp::IntAdd,
            lhs: Box::new(model_access(count_sym())),
            rhs: Box::new(Expr::Int(1)),
        };
        assert_eq!(
            cmd_wiring_of_arm(&arm_body(count_sym(), rhs)),
            Some(CompileCmdWiring { effect: None })
        );
    }

    #[test]
    fn cmd_wiring_json_shapes() {
        assert_eq!(
            CompileCmdWiring { effect: None }.to_json(),
            r#"{"effect":null}"#
        );
        assert_eq!(
            CompileCmdWiring { effect: Some(2) }.to_json(),
            r#"{"effect":2}"#
        );
    }

    #[test]
    fn real_cmd_arm_keeps_wiring_compiled() {
        // A real `Cmd.batch []` effect body is NOT a recognised wiring — the arm's
        // Cmd stays compiled (recompile path).
        let real_cmd = Expr::Call {
            callee: Callee::Kernel(KernelFn::CmdBatch),
            args: vec![Expr::List {
                elem: IrType::Int,
                items: vec![],
            }],
            pin: CallPin::None,
            on_form: OnFormKind::NotForm,
        };
        let body = Expr::Tuple(vec![
            Expr::Update {
                record: Box::new(Expr::Var(model_sym())),
                fields: vec![(count_sym(), Expr::Int(0))],
            },
            real_cmd,
        ]);
        assert_eq!(cmd_wiring_of_arm(&body), None);
    }

    // ── JSON shape ────────────────────────────────────────────────────────

    #[test]
    fn json_int_add_shape() {
        let t = CompileTransition {
            field: "count".to_owned(),
            op: CompileOp::IntAdd,
            source: CompileSource::Int(1),
        };
        assert_eq!(
            t.to_json(),
            r#"{"field":"count","op":"IntAdd","source":{"Int":1}}"#
        );
    }

    #[test]
    fn json_set_str_shape_escapes() {
        let t = CompileTransition {
            field: "na\"me".to_owned(),
            op: CompileOp::Set,
            source: CompileSource::Str("a\"b".to_owned()),
        };
        assert_eq!(
            t.to_json(),
            r#"{"field":"na\"me","op":"Set","source":{"Str":"a\"b"}}"#
        );
    }

    #[test]
    fn json_bool_not_shape() {
        let t = CompileTransition {
            field: "on".to_owned(),
            op: CompileOp::BoolNot,
            source: CompileSource::Field("on".to_owned()),
        };
        assert_eq!(
            t.to_json(),
            r#"{"field":"on","op":"BoolNot","source":{"Field":"on"}}"#
        );
    }

    #[test]
    fn json_string_escapes_control() {
        let mut out = String::new();
        write_json_string("\u{01}", &mut out);
        assert_eq!(out, "\"\\u0001\"");
    }
}

/// The dev == prod CRUX, proven at the compiler/runtime seam.
///
/// A data-describable arm is emitted as `apply_transition(<baked datum>, model)`;
/// the running program (dev and prod alike) executes that ONE compiled routine
/// over the baked datum. This module proves the two halves agree: for each op,
/// the [`CompileTransition`] the classifier produces, serialized by
/// [`CompileTransition::to_json`], decodes into the runtime
/// `web::transition::Transition` and, run through the compiled `apply_transition`,
/// yields EXACTLY the Model the direct compiled arm would have — so a hot-swap of
/// the datum can never diverge from a full recompile of the same source arm.
///
/// If these ever disagree, dev lies about what prod does — the one unacceptable
/// failure. The test therefore compares `apply_transition(interpret(datum))`
/// against a hand-written reproduction of the compiled arm's effect for every op.
#[cfg(test)]
mod conformance {
    use super::{CompileOp, CompileSource, CompileTransition};
    use ipe_runtime_rust::web::transition::{Transition, apply_transition};
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
    struct Model {
        count: i64,
        name: String,
        on: bool,
    }

    fn start() -> Model {
        Model {
            count: 5,
            name: "alice".to_owned(),
            on: false,
        }
    }

    /// Decode a compile-time datum into the runtime `Transition` through its JSON
    /// — the exact path a baked default takes at runtime. A decode failure is the
    /// test's failure (the serializer and codec disagree), surfaced by the
    /// `expect`, which only ever fires on a genuine drift.
    fn interpret(ct: &CompileTransition) -> Transition {
        serde_json::from_str(&ct.to_json())
            .expect("compile datum JSON must decode into runtime Transition")
    }

    #[test]
    fn int_add_matches_compiled_arm() {
        let ct = CompileTransition {
            field: "count".to_owned(),
            op: CompileOp::IntAdd,
            source: CompileSource::Int(1),
        };
        // The compiled arm `{ m | count = count + 1 }` on `start()`:
        let mut compiled = start();
        compiled.count += 1;
        assert_eq!(apply_transition(&interpret(&ct), start()), compiled);
    }

    #[test]
    fn int_sub_matches_compiled_arm() {
        let ct = CompileTransition {
            field: "count".to_owned(),
            op: CompileOp::IntSub,
            source: CompileSource::Int(2),
        };
        let mut compiled = start();
        compiled.count -= 2;
        assert_eq!(apply_transition(&interpret(&ct), start()), compiled);
    }

    #[test]
    fn set_int_literal_matches_compiled_arm() {
        let ct = CompileTransition {
            field: "count".to_owned(),
            op: CompileOp::Set,
            source: CompileSource::Int(0),
        };
        let mut compiled = start();
        compiled.count = 0;
        assert_eq!(apply_transition(&interpret(&ct), start()), compiled);
    }

    #[test]
    fn set_string_literal_matches_compiled_arm() {
        let ct = CompileTransition {
            field: "name".to_owned(),
            op: CompileOp::Set,
            source: CompileSource::Str("bob".to_owned()),
        };
        let mut compiled = start();
        compiled.name = "bob".to_owned();
        assert_eq!(apply_transition(&interpret(&ct), start()), compiled);
    }

    #[test]
    fn set_from_field_matches_compiled_arm() {
        let ct = CompileTransition {
            field: "count".to_owned(),
            op: CompileOp::Set,
            source: CompileSource::Field("count".to_owned()),
        };
        // `{ m | count = count }` — identity.
        let compiled = start();
        assert_eq!(apply_transition(&interpret(&ct), start()), compiled);
    }

    #[test]
    fn bool_not_matches_compiled_arm() {
        let ct = CompileTransition {
            field: "on".to_owned(),
            op: CompileOp::BoolNot,
            source: CompileSource::Field("on".to_owned()),
        };
        // The compiled arm `{ m | on = not on }`:
        let mut compiled = start();
        compiled.on = !compiled.on;
        assert_eq!(apply_transition(&interpret(&ct), start()), compiled);
    }

    /// The compile serializer's bytes ARE the runtime codec's bytes: a runtime
    /// `Transition` round-trips through `CompileTransition::to_json`'s exact shape.
    /// Pins that the two serde forms never drift (a drift would break `interpret`
    /// silently otherwise).
    #[test]
    fn compile_json_is_runtime_transition_serde_shape() {
        let ct = CompileTransition {
            field: "count".to_owned(),
            op: CompileOp::IntAdd,
            source: CompileSource::Int(1),
        };
        let runtime = Transition {
            field: "count".to_owned(),
            op: ipe_runtime_rust::web::transition::TransitionOp::IntAdd,
            source: ipe_runtime_rust::web::transition::Source::Int(1),
        };
        assert_eq!(
            ct.to_json(),
            serde_json::to_string(&runtime).expect("serialize")
        );
    }

    // ── init-datum dev == prod conformance ────────────────────────────────

    use super::{CompileInitDatum, CompileLeaf};
    use ipe_runtime_rust::web::init_datum::{InitDatum, apply_init};

    /// Decode a compile-time init datum into the runtime `InitDatum` through its
    /// JSON — the exact path a baked default takes at runtime.
    fn interpret_init(cd: &CompileInitDatum) -> InitDatum {
        serde_json::from_str(&cd.to_json())
            .expect("compile init datum JSON must decode into runtime InitDatum")
    }

    #[test]
    fn init_datum_matches_compiled_init() {
        // The compile datum for `init _ = ({ count = 7, name = "bob", on = true }, Cmd.none)`.
        let cd = CompileInitDatum {
            fields: vec![
                ("count".to_owned(), CompileLeaf::Int(7)),
                ("name".to_owned(), CompileLeaf::Str("bob".to_owned())),
                ("on".to_owned(), CompileLeaf::Bool(true)),
            ],
        };
        // The direct compiled `init` produces exactly this Model.
        let compiled = Model {
            count: 7,
            name: "bob".to_owned(),
            on: true,
        };
        // A DIFFERENT compiled fallback proves the datum drove the result (not the
        // fallback): decoding the well-typed datum yields the compiled Model.
        let fallback = Model {
            count: 0,
            name: String::new(),
            on: false,
        };
        assert_eq!(apply_init(&interpret_init(&cd), fallback), compiled);
    }

    /// The compile serializer's bytes ARE the runtime codec's bytes: a runtime
    /// `InitDatum` round-trips through `CompileInitDatum::to_json`'s exact shape.
    #[test]
    fn compile_init_json_is_runtime_init_datum_serde_shape() {
        let cd = CompileInitDatum {
            fields: vec![("count".to_owned(), CompileLeaf::Int(0))],
        };
        let runtime = InitDatum {
            model: serde_json::json!({ "count": 0 }),
        };
        assert_eq!(
            cd.to_json(),
            serde_json::to_string(&runtime).expect("serialize")
        );
    }

    // ── Cmd-wiring dev == prod conformance ────────────────────────────────

    use super::CompileCmdWiring;
    use ipe_runtime_rust::web::cmd_wiring::{CmdWiring, select_effect};

    /// Decode a compile-time wiring into the runtime `CmdWiring` through its JSON.
    fn interpret_wiring(cw: CompileCmdWiring) -> CmdWiring {
        serde_json::from_str(&cw.to_json())
            .expect("compile wiring JSON must decode into runtime CmdWiring")
    }

    #[test]
    fn cmd_none_wiring_selects_no_effect() {
        // The `Cmd.none` wiring fires no effect — byte-identical to a compiled
        // `Cmd.none` arm (dev == prod).
        let cw = CompileCmdWiring { effect: None };
        assert_eq!(select_effect(&interpret_wiring(cw), 0), None);
    }

    #[test]
    fn effect_wiring_selects_that_id() {
        // An effect wiring naming id 1 selects slot 1 when the arm's compiled
        // effect table has it.
        let cw = CompileCmdWiring { effect: Some(1) };
        assert_eq!(select_effect(&interpret_wiring(cw), 2), Some(1));
    }

    /// The compile serializer's bytes ARE the runtime codec's bytes: a runtime
    /// `CmdWiring` round-trips through `CompileCmdWiring::to_json`'s exact shape.
    #[test]
    fn compile_wiring_json_is_runtime_cmd_wiring_serde_shape() {
        for cw in [
            CompileCmdWiring { effect: None },
            CompileCmdWiring { effect: Some(3) },
        ] {
            let runtime = CmdWiring { effect: cw.effect };
            assert_eq!(
                cw.to_json(),
                serde_json::to_string(&runtime).expect("serialize")
            );
        }
    }
}
