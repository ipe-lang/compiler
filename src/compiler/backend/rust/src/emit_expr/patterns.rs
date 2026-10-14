use super::{
    Arm, DResult, Diagnostic, Expr, GenericScope, Match, ModPath, Pat, Symbol, emit_expr_at,
    int_pattern,
};
use crate::EmitCtx;
use core::fmt::Write as _;
use ipe_ir::free_vars::{
    free_vars, pat_bound_symbols, pat_has_str_guard_slot, pat_moves_nested_part,
};
use ipe_ir::{IrType, SliceOwnership};
use std::collections::BTreeSet;

use ipe_intern::rust_char_lit;
pub use ipe_intern::rust_str_lit;

/// Emit the scrutinee of a `Match` plus its two mode flags. A string scrutinee is
/// matched as `&str` (so literal patterns apply) — the presence of a `Pat::Str`
/// head is the reliable signal (the type checker proved the scrutinee a
/// `String`). A LIST scrutinee (the runtime's `Vec<T>`) is matched through its
/// [`ListView`] — a borrowed slice (`[]` / `[a, b]` / `[x, rest @ ..]`) for a
/// `Clone` element, the owned view `ipe_list_view_owned` returns for any other —
/// and a `Pat::Slice` head is the signal. Shared by the value-context (`emit_match`)
/// and tail-context (`emit_expr_tail`) match emitters so the two agree exactly.
/// How a `match` scrutinee is coerced for pattern matching. A WHOLE scrutinee is
/// matched as `&str` (string `case`), through its [`ListView`] (list `case`), or
/// as-is; a TUPLE
/// scrutinee (a multi-arm product `case`) is matched column-by-column, each
/// column carrying its own string / list coercion.
pub enum ScrutMode {
    Whole { str_mode: bool, list: ListView },
    Tuple(Vec<ColMode>),
}

/// How a list scrutinee, or a list column of a tuple scrutinee, is matched.
///
/// Decided from the [`SliceOwnership`] the lowerer stamped on the column's
/// slice arms; every arm of the column renders against the one view.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ListView {
    /// Not a list column: no arm head slices it.
    Off,
    /// Matched as a borrowed slice (`as_slice()`); each binder copies out.
    Borrow,
    /// Matched as the owned view `ipe_list_view_owned::<_, width>` returns;
    /// each binder moves out. `tag` keeps the view's temporaries apart from a
    /// sibling column's.
    Owned { width: usize, tag: usize },
}

/// The per-column coercion flags of a tuple-scrutinee `match`. A column is
/// matched as `&[T]` when some arm slices it (`… , x :: xs , …`) and as `&str`
/// when some arm matches it against a string literal.
#[derive(Clone, Copy)]
pub struct ColMode {
    str_mode: bool,
    list: ListView,
}

/// The arity of a tuple-scrutinee `match` — the element count of the first arm
/// whose head is a [`Pat::Tuple`], or `None` when no arm is a tuple pattern (the
/// whole-scrutinee shapes). The lowerer only builds a tuple-headed arm from a
/// literal-tuple scrutinee of the SAME arity, so this drives the tuple path.
pub fn tuple_arm_arity(arms: &[Arm]) -> Option<usize> {
    arms.iter().find_map(|a| match &a.pat {
        Pat::Tuple(elems) => Some(elems.len()),
        _ => None,
    })
}

/// Compute the per-column coercion flags of a tuple-scrutinee `match`: a column
/// is in list mode when some arm slices it, and in string mode when some arm
/// matches it against a string literal. (A column is never both — the scrutinee
/// element has a single type the checker pinned.)
pub fn tuple_col_modes(arms: &[Arm], arity: usize) -> DResult<Vec<ColMode>> {
    let mut cols = Vec::with_capacity(arity);
    for c in 0..arity {
        let column = arms.iter().filter_map(|arm| match &arm.pat {
            Pat::Tuple(elems) => elems.get(c),
            _ => None,
        });
        cols.push(ColMode {
            str_mode: column.clone().any(|sub| matches!(sub, Pat::Str(_))),
            list: list_view(column, c)?,
        });
    }
    Ok(cols)
}

/// The [`ListView`] of one list column: the arm heads `pats` matched against it.
///
/// The column is a list column when some head is a slice. Its view follows the
/// slices' [`SliceOwnership`], which every slice of the column, including one
/// under an alias or or-pattern head, must share. An owned view is one slot
/// wider than the longest slice prefix, so a closed prefix always has the
/// `None` slot that proves its length.
///
/// A column no head moves a part out of (every head binds nothing) is borrowed
/// whatever its slices' ownership: the lowerer's consume counter counts a
/// `case` over a variable as a move only when some head moves a part, so an
/// owned view there would move a list the counter still calls live.
pub fn list_view<'p>(pats: impl Iterator<Item = &'p Pat> + Clone, tag: usize) -> DResult<ListView> {
    if !pats.clone().any(|p| matches!(p, Pat::Slice { .. })) {
        return Ok(ListView::Off);
    }
    let moves = pats.clone().any(pat_moves_nested_part);
    let mut own = None;
    let mut longest: usize = 0;
    let mut pending: Vec<&Pat> = pats.collect();
    while let Some(pat) = pending.pop() {
        match pat {
            Pat::Slice {
                prefix, own: here, ..
            } => {
                if own.is_some_and(|seen| seen != *here) {
                    return Err(Diagnostic::CompilerBug {
                        where_: "ipe_backend_rust::list_view",
                        detail: "the slice arms of one list column disagree on their \
                                 ownership; the lowerer decides it once per element type"
                            .to_owned(),
                    });
                }
                own = Some(*here);
                longest = longest.max(prefix.len());
            }
            Pat::Alias(inner, _) => pending.push(inner),
            // A `SharedAlts` alternative holds no slice.
            Pat::Or(_)
            | Pat::Var(_)
            | Pat::Wildcard
            | Pat::Int(_)
            | Pat::Bool(_)
            | Pat::Char(_)
            | Pat::Str(_)
            | Pat::Ctor { .. }
            | Pat::Tuple(_)
            | Pat::Record(_) => {}
        }
    }
    match own {
        None => Ok(ListView::Off),
        Some(SliceOwnership::BorrowClone) => Ok(ListView::Borrow),
        Some(SliceOwnership::OwnedMove) if !moves => Ok(ListView::Borrow),
        Some(SliceOwnership::OwnedMove) => {
            let width = longest
                .checked_add(1)
                .ok_or_else(|| Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::list_view",
                    detail: "list pattern prefix length overflowed the view width".to_owned(),
                })?;
            Ok(ListView::Owned { width, tag })
        }
    }
}

/// Refuse an owned view of a bare variable scrutinee `s` that an arm still reads.
///
/// The owned view consumes `s`, so a read of it in an arm body or guard would
/// be a use after move. The lowerer's consume accounting refuses that program
/// first (IPE-L0135); this re-checks it independently over the arms' free
/// variables.
fn owned_scrutinee_reuse_refusal(scrutinee: &Expr, view: ListView, arms: &[Arm]) -> DResult<()> {
    let (ListView::Owned { .. }, Expr::Var(s)) = (view, scrutinee) else {
        return Ok(());
    };
    for arm in arms {
        let mut bound = BTreeSet::new();
        pat_bound_symbols(&arm.pat, &mut bound);
        if bound.contains(s) {
            continue;
        }
        let read = free_vars(&arm.body).contains(s)
            || arm.guard.as_ref().is_some_and(|g| free_vars(g).contains(s));
        if read {
            return Err(Diagnostic::CompilerBug {
                where_: "ipe_backend_rust::emit_match_scrutinee",
                detail: "an owned list view consumes its variable scrutinee, but an arm \
                         still reads it; the lowerer's consume gate refuses that reuse \
                         (IPE-L0135)"
                    .to_owned(),
            });
        }
    }
    Ok(())
}

/// Prove a list element type `Clone` before the emitter clones one out.
///
/// The lowerer emits a `.clone()` of a list element (a borrowed-view binder
/// copy-out, an index read under a nested list pattern) only over an element
/// type it classified `Clone`. This re-checks that decision against the
/// emitted Rust's own `Clone` facts, so a lowerer misclassification is an
/// internal error at emit time rather than a `cargo` failure.
pub fn elem_clone_proof(ctx: &EmitCtx, elem: &IrType) -> DResult<()> {
    if crate::fn_value_is_clone(elem, &|home, name| ctx.enum_is_clone(home, name)) {
        Ok(())
    } else {
        Err(Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::elem_clone_proof",
            detail: "a list element is cloned out, but its emitted type is not `Clone`; \
                     the lowerer takes an owned view of such a list"
                .to_owned(),
        })
    }
}

/// Prove every slice element type of a borrowed list column `Clone`.
///
/// A borrowed view copies each binder out with `.clone()` / `.to_vec()`, a
/// whole-list binder included, so the proof covers the column whenever some
/// head binds a part. A column no head binds anything from clones nothing.
fn borrowed_column_clone_proof<'p>(
    ctx: &EmitCtx,
    pats: impl Iterator<Item = &'p Pat> + Clone,
    view: ListView,
) -> DResult<()> {
    match view {
        ListView::Borrow => {}
        ListView::Off | ListView::Owned { .. } => return Ok(()),
    }
    if !pats.clone().any(pat_moves_nested_part) {
        return Ok(());
    }
    let mut pending: Vec<&Pat> = pats.collect();
    while let Some(pat) = pending.pop() {
        match pat {
            Pat::Slice { elem, .. } => elem_clone_proof(ctx, elem)?,
            Pat::Alias(inner, _) => pending.push(inner),
            // A `SharedAlts` alternative holds no slice.
            Pat::Or(_)
            | Pat::Var(_)
            | Pat::Wildcard
            | Pat::Int(_)
            | Pat::Bool(_)
            | Pat::Char(_)
            | Pat::Str(_)
            | Pat::Ctor { .. }
            | Pat::Tuple(_)
            | Pat::Record(_) => {}
        }
    }
    Ok(())
}

/// Render the list scrutinee `e` for its column's [`ListView`].
fn list_scrutinee(e: String, view: ListView) -> String {
    match view {
        ListView::Off => e,
        ListView::Borrow => format!("({e}).as_slice()"),
        ListView::Owned { width, .. } => {
            format!("ipe_runtime::list::ipe_list_view_owned::<_, {width}>({e})")
        }
    }
}

pub fn emit_match_scrutinee(
    ctx: &EmitCtx,
    m: &Match,
    indent: usize,
    depth: u16,
    generics: GenericScope,
) -> DResult<(String, ScrutMode)> {
    let child = depth + 1;
    // COERCED-COLUMN TUPLE mode: a multi-arm product `case` on a LITERAL-tuple
    // scrutinee. The scrutinee is built column-by-column with each column's own
    // slice / `&str` coercion — the only sound way to match `[a, rest @ ..]`
    // (needs `&[T]`) against a `Vec` element, or a string literal against a
    // `String` element. A NON-literal scrutinee whose arms are still tuple heads
    // (`case pair of (_, Passed) -> …`) carries no coercing column — the lowerer's
    // `tuple_case_supported` fail-closes any such column on the non-literal path —
    // so it falls through to WHOLE mode below, which matches the tuple value
    // directly (`match pair { (_, Passed) => … }`) via the alias-safe renderer.
    if let Some(arity) = tuple_arm_arity(m.arms())
        && let Expr::Tuple(elems) = m.scrutinee()
    {
        if elems.len() != arity {
            return Err(Diagnostic::CompilerBug {
                where_: "ipe_backend_rust::emit_match_scrutinee",
                detail: format!(
                    "tuple match scrutinee has {} elements but arms have arity {arity}",
                    elems.len()
                ),
            });
        }
        let cols = tuple_col_modes(m.arms(), arity)?;
        let mut parts = Vec::with_capacity(arity);
        for ((c, elem), col) in elems.iter().enumerate().zip(&cols) {
            let column = m.arms().iter().filter_map(|arm| match &arm.pat {
                Pat::Tuple(heads) => heads.get(c),
                _ => None,
            });
            borrowed_column_clone_proof(ctx, column, col.list)?;
            owned_scrutinee_reuse_refusal(elem, col.list, m.arms())?;
            let e = emit_expr_at(ctx, elem, indent, child, generics)?;
            let e = if col.str_mode {
                format!("({e}).as_str()")
            } else {
                list_scrutinee(e, col.list)
            };
            parts.push(e);
        }
        return Ok((format!("({})", parts.join(", ")), ScrutMode::Tuple(cols)));
    }

    let str_mode = m.arms().iter().any(|a| matches!(a.pat, Pat::Str(_)));
    let list = list_view(m.arms().iter().map(|a| &a.pat), 0)?;
    borrowed_column_clone_proof(ctx, m.arms().iter().map(|a| &a.pat), list)?;
    owned_scrutinee_reuse_refusal(m.scrutinee(), list, m.arms())?;
    let scrut_expr = emit_expr_at(ctx, m.scrutinee(), indent, child, generics)?;
    let scrut = if str_mode {
        format!("({scrut_expr}).as_str()")
    } else {
        list_scrutinee(scrut_expr, list)
    };
    Ok((scrut, ScrutMode::Whole { str_mode, list }))
}

/// AND together the two guard sources on a match arm: the synthesized
/// string-column `as_str()` guard and the arm's own IR guard. Either,
/// both, or neither may be present; both present are joined `synth && ir` (the
/// synthesized `as_str()` checks come from the pattern, so they read first).
/// `None` when neither is present, leaving the arm's `=> …` shape guardless.
pub fn combine_guards(synth: Option<String>, ir: Option<String>) -> Option<String> {
    match (synth, ir) {
        (Some(s), Some(i)) => Some(format!("{s} && {i}")),
        (Some(s), None) => Some(s),
        (None, Some(i)) => Some(i),
        (None, None) => None,
    }
}

/// Render one arm head to its Rust pattern, any leading prelude, and any
/// synthesized match guard (the `__sgN.as_str() == "lit"` check for a
/// by-value string-literal column, joined with `&&` when several columns carry
/// one). `None` when no guard is synthesized, so the
/// caller's `if <guard>` clause stays absent.
pub fn emit_arm_head(
    ctx: &EmitCtx,
    pat: &Pat,
    mode: &ScrutMode,
) -> DResult<(String, String, Option<String>)> {
    let mut sink = ArmSink::default();
    let rendered = match mode {
        ScrutMode::Whole { str_mode, list } => {
            emit_whole_arm_head(ctx, pat, *str_mode, *list, &mut sink)?
        }
        ScrutMode::Tuple(cols) => emit_tuple_arm_head(ctx, pat, cols, &mut sink)?,
    };
    let guard = if sink.guards.is_empty() {
        None
    } else {
        Some(sink.guards.join(" && "))
    };
    Ok((rendered, sink.prelude, guard))
}

/// Render a WHOLE-scrutinee arm head (the string / list / plain shapes) to its Rust pattern.
///
/// The leading binder-rebind/unbox prelude and any synthesized match GUARDS go
/// into `sink`. The guards are the `__sgN.as_str() == "lit"` checks for a
/// by-value string-literal column — the caller ANDs them onto the arm; they are
/// empty for every other shape. A constructor head is matched by value whatever
/// the column's coercion flags say, so it takes the by-value renderer.
pub fn emit_whole_arm_head(
    ctx: &EmitCtx,
    pat: &Pat,
    str_mode: bool,
    list: ListView,
    sink: &mut ArmSink,
) -> DResult<String> {
    let ctor_head = matches!(pat, Pat::Ctor { .. });
    if !ctor_head && str_mode {
        // STR mode: the scrutinee IS a reference (`.as_str()`), so
        // `render_pat`'s `name @ inner` is a borrow and sound for any inner
        // shape. A top-level `Pat::Str` matches the `&str`-wrapped scrutinee
        // directly (a literal pattern), so no guard is synthesized here.
        let rendered = render_pat(ctx, pat)?;
        sink.prelude.push_str(&str_binder_rebinds(ctx, pat)?);
        Ok(rendered)
    } else if !ctor_head && list != ListView::Off {
        list_arm_head(ctx, pat, list, sink)
    } else {
        // WHOLE mode, by value: a constructor head reads its boxed fields
        // through the box; a top-level dispatch-free alias head
        // (`(a, b) as w ->`) takes the alias-safe clone-rebuild path; a
        // by-value string-literal column (`( "transform", v )` on a variable
        // tuple scrutinee) accumulates its `as_str()` guard here.
        render_arm_pat_alias_safe(ctx, pat, sink)
    }
}

/// Render a TUPLE-scrutinee arm head — a `(c0, c1, …)` tuple pattern or a `_` catch-all.
///
/// Each column renders against its own coercion: a list column's binders
/// rebind from `&T` / `&[T]` to owned `T` / `Vec<T>`; a string column's binders
/// rebind from `&str` to `String`; a constructor column reads its boxed fields
/// through the box. Every column writes into the one arm `sink`, so a fresh
/// `__ipe_` name is unique across the whole head. The lowerer only produces a
/// tuple or wildcard head here (`tuple_case_supported`), so a whole-value
/// variable / alias binder — which would see the wrong per-column-coerced type —
/// is an internal invariant violation, surfaced as a `CompilerBug`.
pub fn emit_tuple_arm_head(
    ctx: &EmitCtx,
    pat: &Pat,
    cols: &[ColMode],
    sink: &mut ArmSink,
) -> DResult<String> {
    match pat {
        Pat::Tuple(elems) => {
            let mut rendered = Vec::with_capacity(elems.len());
            for (c, sub) in elems.iter().enumerate() {
                // `unwrap_or` on a missing column would silently coerce a
                // wider-than-known tuple pattern to `str_mode: false,
                // list: ListView::Off` — the WRONG per-column coercion emits a
                // binder of the wrong type, an exit-0-then-cargo-fail (E0308)
                // THE SEAL forbids. Fail closed instead: this is the same
                // "lowerer only produces columns it schemed" invariant the
                // wildcard/tuple-only match arm below already enforces.
                let col = cols.get(c).copied().ok_or_else(|| {
                    let found = cols.len();
                    Diagnostic::CompilerBug {
                        where_: "ipe_backend_rust::emit_tuple_arm_head",
                        detail: format!(
                            "tuple-scrutinee match arm has {found} column(s) but the pattern \
                             reached column {c}; the lowerer's column table drifted from the \
                             pattern width"
                        ),
                    }
                })?;
                rendered.push(emit_whole_arm_head(ctx, sub, col.str_mode, col.list, sink)?);
            }
            Ok(format!("({})", rendered.join(", ")))
        }
        Pat::Wildcard => Ok("_".to_owned()),
        _ => Err(Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::emit_tuple_arm_head",
            detail: "tuple-scrutinee match arm head is neither a tuple nor a wildcard".to_owned(),
        }),
    }
}

/// The accumulators one arm head threads through its sub-pattern renderers.
#[derive(Default)]
pub struct ArmSink {
    /// The fresh-name counter behind every `__ipe_` temp and `__sgN` guard slot.
    pub counter: usize,
    /// Statements spliced at the head of the arm body.
    pub prelude: String,
    /// Match guards joined onto the arm with a logical AND.
    pub guards: Vec<String>,
    /// Binders bound to a whole boxed field and unboxed in the prelude.
    pub unboxed: BTreeSet<Symbol>,
    /// Whether a boxed field was bound to a fresh temp and destructured from it.
    pub boxed_temp: bool,
}

impl ArmSink {
    /// A sink for one or-pattern alternative, numbering fresh names on from `self`.
    fn alternative(&self) -> Self {
        Self {
            counter: self.counter,
            ..Self::default()
        }
    }

    /// Take the next fresh-name number.
    const fn fresh(&mut self) -> usize {
        let n = self.counter;
        self.counter += 1;
        n
    }

    /// Append one prelude statement.
    fn push_stmt(&mut self, stmt: &str) {
        self.prelude.push_str(stmt);
        self.prelude.push(' ');
    }
}

/// How a constructor pattern's scrutinee is held, which decides how a boxed field is read.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FieldAccess {
    /// Matched by value: a boxed binder moves out of its box (`*x`).
    ByValue,
    /// Matched through a borrow: a boxed binder is `&Box<T>`, copied out with `(**x).clone()`.
    ByRef,
    /// Rendered with no prelude slot: a boxed position can only be ignored.
    NoPrelude,
}

/// A constructor pattern's parts, borrowed from a [`Pat::Ctor`].
#[derive(Clone, Copy)]
pub struct CtorPat<'p> {
    pub home: &'p ModPath,
    pub ty: Symbol,
    pub variant: Symbol,
    pub args: &'p [Pat],
}

/// How a sub-pattern at a boxed field position is honoured.
///
/// Rust cannot match through a `Box` on stable, so a boxed position takes a
/// binder that the arm prelude unboxes; a sub-pattern that must test the
/// field's value there has no rendering and is refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BoxedSub<'p> {
    /// A sub-pattern that binds nothing and tests nothing: the field is not read.
    Ignore,
    /// A variable bound to the whole field.
    Bind(Symbol),
    /// A tuple, record or alias that binds a name and tests nothing, rebuilt from the unboxed field.
    Destructure(&'p Pat),
    /// A sub-pattern that tests the field's value.
    Dispatch,
}

impl<'p> BoxedSub<'p> {
    /// Classify the sub-pattern at a boxed field position.
    #[must_use]
    pub fn of(pat: &'p Pat) -> Self {
        match pat {
            Pat::Wildcard => Self::Ignore,
            Pat::Var(name) => Self::Bind(*name),
            Pat::Tuple(_) | Pat::Record(_) | Pat::Alias(..) => {
                match (binds_without_dispatch(pat), binds_any(pat)) {
                    (false, _) => Self::Dispatch,
                    (true, true) => Self::Destructure(pat),
                    (true, false) => Self::Ignore,
                }
            }
            Pat::Ctor { .. }
            | Pat::Int(_)
            | Pat::Bool(_)
            | Pat::Char(_)
            | Pat::Str(_)
            | Pat::Slice { .. }
            | Pat::Or(_) => Self::Dispatch,
        }
    }
}

/// Can `pat` be bound by an irrefutable `let`, testing nothing?
///
/// A record field must also hold no alias: a by-value `let` renders it as
/// `name @ inner`, which moves the part twice.
fn binds_without_dispatch(pat: &Pat) -> bool {
    match pat {
        Pat::Wildcard | Pat::Var(_) => true,
        Pat::Alias(inner, _) => binds_without_dispatch(inner),
        Pat::Tuple(elems) => elems.iter().all(binds_without_dispatch),
        Pat::Record(fields) => fields
            .iter()
            .all(|(_, p)| !pat_contains_alias_in_arm(p) && binds_without_dispatch(p)),
        Pat::Ctor { .. }
        | Pat::Int(_)
        | Pat::Bool(_)
        | Pat::Char(_)
        | Pat::Str(_)
        | Pat::Slice { .. }
        | Pat::Or(_) => false,
    }
}

/// Render a constructor pattern, reading its boxed fields the same way at every depth.
///
/// A built-in runtime enum (`Maybe`, `Result`, …) has no boxed field, so each
/// argument renders through `plain`; a user enum's arguments go through
/// [`render_user_ctor_args`].
pub fn render_ctor_pat<F>(
    ctx: &EmitCtx,
    ctor: CtorPat<'_>,
    access: FieldAccess,
    sink: &mut ArmSink,
    plain: &mut F,
) -> DResult<String>
where
    F: FnMut(&Pat, &mut ArmSink) -> DResult<String>,
{
    let (path, subs) = if let Some(runtime) = ctx.builtin_runtime_enum(ctor.home, ctor.ty) {
        let path = format!("{runtime}::{}", ctx.emit_ident(ctor.variant)?);
        let mut subs = Vec::with_capacity(ctor.args.len());
        for sub in ctor.args {
            subs.push(plain(sub, sink)?);
        }
        (path, subs)
    } else {
        let path = format!(
            "{}::{}",
            ctx.enum_name(ctor.home, ctor.ty)?,
            ctx.emit_ident(ctor.variant)?
        );
        if ctor.args.is_empty() {
            return Ok(path);
        }
        (path, render_user_ctor_args(ctx, ctor, access, sink, plain)?)
    };
    if subs.is_empty() {
        Ok(path)
    } else {
        Ok(format!("{path}({})", subs.join(", ")))
    }
}

/// Render a user constructor pattern's arguments against the variant's declared fields.
///
/// The one place a pattern asks whether a field is boxed. An argument at a
/// boxed (cyclic self-edge) field is classified by [`BoxedSub::of`] and read
/// through the box as `access` dictates; every other argument renders through
/// `plain`.
pub fn render_user_ctor_args<F>(
    ctx: &EmitCtx,
    ctor: CtorPat<'_>,
    access: FieldAccess,
    sink: &mut ArmSink,
    plain: &mut F,
) -> DResult<Vec<String>>
where
    F: FnMut(&Pat, &mut ArmSink) -> DResult<String>,
{
    let fields = ctx.variant_fields(ctor.home, ctor.ty, ctor.variant)?;
    if fields.len() != ctor.args.len() {
        return Err(Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::emit_match",
            detail: format!(
                "constructor pattern {} of enum {} binds {} sub-patterns but the \
                 variant declares {} fields",
                ctor.variant.as_raw(),
                ctor.ty.as_raw(),
                ctor.args.len(),
                fields.len()
            ),
        });
    }
    let mut subs = Vec::with_capacity(ctor.args.len());
    for (sub, field_ty) in ctor.args.iter().zip(fields) {
        if ctx.is_cyclic_self_field(field_ty, ctor.home, ctor.ty) {
            subs.push(render_boxed_sub(ctx, sub, access, sink)?);
        } else {
            subs.push(plain(sub, sink)?);
        }
    }
    Ok(subs)
}

/// Render the sub-pattern at one boxed field position, unboxing what it binds in the prelude.
fn render_boxed_sub(
    ctx: &EmitCtx,
    sub: &Pat,
    access: FieldAccess,
    sink: &mut ArmSink,
) -> DResult<String> {
    let refuse = |detail: &str| Diagnostic::CompilerBug {
        where_: "ipe_backend_rust::render_user_ctor_args",
        detail: detail.to_owned(),
    };
    match (BoxedSub::of(sub), access) {
        (BoxedSub::Ignore, _) => Ok("_".to_owned()),
        (BoxedSub::Bind(name), FieldAccess::ByValue | FieldAccess::ByRef) => {
            let binder = ctx.emit_ident(name)?;
            let src = unboxed_read(access, &binder);
            sink.push_stmt(&format!("let {binder} = {src};"));
            sink.unboxed.insert(name);
            Ok(binder)
        }
        (BoxedSub::Destructure(part), FieldAccess::ByValue | FieldAccess::ByRef) => {
            let temp = format!("__ipe_box_{}", sink.fresh());
            let src = unboxed_read(access, &temp);
            for stmt in emit_binding_stmts(ctx, part, &src)? {
                sink.push_stmt(&stmt);
            }
            sink.boxed_temp = true;
            Ok(temp)
        }
        (BoxedSub::Bind(_) | BoxedSub::Destructure(_), FieldAccess::NoPrelude) => Err(refuse(
            "a binder at a boxed field position reached a renderer with no unbox prelude",
        )),
        (BoxedSub::Dispatch, _) => Err(refuse(
            "a sub-pattern that tests a boxed field's value reached the backend; Rust \
             cannot match through a `Box`, so it has no rendering",
        )),
    }
}

/// The owned payload read out of the boxed binder `boxed` under `access`.
fn unboxed_read(access: FieldAccess, boxed: &str) -> String {
    match access {
        FieldAccess::ByRef => format!("(**{boxed}).clone()"),
        FieldAccess::ByValue | FieldAccess::NoPrelude => format!("*{boxed}"),
    }
}

/// Render an or-pattern's alternatives, each into its own sink, and fold them into `sink`.
///
/// A Rust or-pattern binds one name set at one type in every alternative, and
/// the arm body runs one prelude whichever alternative matched. So every
/// alternative numbers its fresh names from the same base: alternatives that
/// mint the same temps for the same binders render the same prelude, and that
/// one prelude serves them all. Alternatives whose unboxed binders differ, that
/// destructure a boxed field through a fresh temp (its type is fixed by the
/// variant, not by the names it binds), or that mint fresh names into
/// different preludes or guards have no single prelude, and are refused.
/// Otherwise the first alternative's prelude and guards serve the arm: every
/// alternative binds and rebinds the same names.
fn render_or_alternatives<F>(alts: &[Pat], sink: &mut ArmSink, render: &mut F) -> DResult<String>
where
    F: FnMut(&Pat, &mut ArmSink) -> DResult<String>,
{
    let base = sink.counter;
    let mut parts = Vec::with_capacity(alts.len());
    let mut done = Vec::with_capacity(alts.len());
    for alt in alts {
        let mut alt_sink = sink.alternative();
        parts.push(render(alt, &mut alt_sink)?);
        done.push(alt_sink);
    }
    let Some((first, rest)) = done.split_first() else {
        return Err(Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::render_or_alternatives",
            detail: "an or-pattern reached the backend with no alternatives".to_owned(),
        });
    };
    let minted = done.iter().any(|alt| alt.counter != base);
    let uneven = rest.iter().any(|alt| alt.unboxed != first.unboxed);
    let boxed_temp = done.iter().any(|alt| alt.boxed_temp);
    let diverging_mints = minted
        && rest.iter().any(|alt| {
            alt.counter != first.counter
                || alt.prelude != first.prelude
                || alt.guards != first.guards
        });
    if uneven || boxed_temp || diverging_mints {
        return Err(Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::render_or_alternatives",
            detail: "or-pattern alternatives bind through different arm preludes (different \
                     unboxed binders, a boxed field destructured through a temp, or fresh \
                     names minted differently); no single prelude serves every alternative"
                .to_owned(),
        });
    }
    sink.counter = first.counter;
    sink.prelude.push_str(&first.prelude);
    sink.guards.extend(first.guards.iter().cloned());
    sink.unboxed.extend(first.unboxed.iter().copied());
    Ok(parts.join(" | "))
}

/// Build the `let name = name.to_string();` prelude that rebinds every top-level
/// binder a string-match arm introduces from `&str` to an owned `String`, so the
/// arm body sees the Ipê `String` type. A variable binds itself; an alias binds
/// its name and recurses into its inner pattern; a wildcard / literal binds
/// nothing.
pub fn str_binder_rebinds(ctx: &EmitCtx, pat: &Pat) -> DResult<String> {
    let mut out = String::new();
    collect_str_rebinds(ctx, pat, &mut out)?;
    Ok(out)
}

pub fn collect_str_rebinds(ctx: &EmitCtx, pat: &Pat, out: &mut String) -> DResult<()> {
    match pat {
        Pat::Var(s) => {
            let name = ctx.emit_ident(*s)?;
            write!(out, "let {name} = {name}.to_string(); ").map_err(|e| {
                Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::str_binder_rebinds",
                    detail: format!("writing rebind binder failed: {e}"),
                }
            })?;
            Ok(())
        }
        Pat::Alias(inner, name) => {
            let n = ctx.emit_ident(*name)?;
            write!(out, "let {n} = {n}.to_string(); ").map_err(|e| Diagnostic::CompilerBug {
                where_: "ipe_backend_rust::str_binder_rebinds",
                detail: format!("writing rebind binder failed: {e}"),
            })?;
            collect_str_rebinds(ctx, inner, out)
        }
        // A string scrutinee admits no constructor / tuple / record / non-string
        // literal head (the type checker proves the scrutinee a `String`); these
        // introduce no `String`-typed binder to rebind.
        Pat::Wildcard
        | Pat::Str(_)
        | Pat::Int(_)
        | Pat::Bool(_)
        | Pat::Char(_)
        | Pat::Ctor { .. }
        | Pat::Tuple(_)
        | Pat::Record(_)
        | Pat::Slice { .. }
        // A `SharedAlts` alternative is binder-free.
        | Pat::Or(_) => Ok(()),
    }
}

/// Render one arm head of a list column for the column's [`ListView`].
///
/// Every list-column arm head passes through here. A borrowed view renders the
/// slice pattern together with the copy-out rebinds of [`borrow_list_head`]; a
/// head that binds nothing has no rebind, whatever its slices' ownership. An
/// owned view renders the move-out pattern of [`owned_list_arm_head`].
pub fn list_arm_head(
    ctx: &EmitCtx,
    pat: &Pat,
    list: ListView,
    sink: &mut ArmSink,
) -> DResult<String> {
    match list {
        ListView::Borrow => borrow_list_head(ctx, pat, pat_moves_nested_part(pat), sink),
        ListView::Owned { width, tag } => owned_list_arm_head(ctx, pat, width, tag, sink),
        ListView::Off => Err(Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::list_arm_head",
            detail: "a list arm head was rendered for a column no slice arm matches".to_owned(),
        }),
    }
}

/// Render a list arm head over a borrowed slice, with its copy-out prelude.
///
/// Under [`SliceOwnership::BorrowClone`] the scrutinee is matched as a slice
/// (`(v).as_slice()`), so every binder a list arm introduces is a borrow: an
/// ELEMENT binder is `&T` and a REST / whole-list binder is `&[T]`. The
/// prelude rebinds each to the owned Ipê value the arm body expects — an
/// element via `.clone()` (so the body sees `T`), a rest / whole list via
/// `.to_vec()` (so the body sees `Vec<T>`). The lowerer stamps `BorrowClone`
/// only on an element type whose clone class is `Clone` (a bare type parameter
/// carries the emitted `Clone` bound), and the scrutinee emitter re-proves the
/// column's element type with [`elem_clone_proof`] before any arm renders, so
/// the `.clone()` / `.to_vec()` always resolve. A non-`Clone` element is
/// [`SliceOwnership::OwnedMove`], whose binders move out of the owned view and
/// have no copy-out prelude, so a binding head reaching here with it is an
/// internal error.
fn borrow_list_head(ctx: &EmitCtx, pat: &Pat, moves: bool, sink: &mut ArmSink) -> DResult<String> {
    match pat {
        Pat::Slice {
            prefix, rest, own, ..
        } => {
            if moves && *own != SliceOwnership::BorrowClone {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::borrow_list_head",
                    detail: "a list arm's slice ownership disagrees with its column's view"
                        .to_owned(),
                });
            }
            let mut parts = Vec::with_capacity(prefix.len().saturating_add(1));
            for sub in prefix {
                parts.push(borrow_elem(ctx, sub, sink)?);
            }
            if let Some(r) = rest {
                parts.push(render_rest_pat(ctx, r)?);
                collect_list_rebinds(ctx, r, &mut sink.prelude)?;
            }
            Ok(format!("[{}]", parts.join(", ")))
        }
        // A whole-list catch-all binder (`xs ->`) or an alias over a list arm
        // (`(x :: rest) as whole ->`): the matched value IS the list.
        Pat::Var(name) => {
            rebind_to_vec(ctx, *name, &mut sink.prelude)?;
            ctx.emit_ident(*name)
        }
        Pat::Alias(inner, name) => {
            rebind_to_vec(ctx, *name, &mut sink.prelude)?;
            let inner = borrow_list_head(ctx, inner, moves, sink)?;
            Ok(format!("{} @ {inner}", ctx.emit_ident(*name)?))
        }
        // Every alternative binds the same names at the same types, so the first
        // alternative's rebinds are the whole arm's set.
        Pat::Or(alts) => {
            render_or_alternatives(alts.as_slice(), sink, &mut |p: &Pat, s: &mut ArmSink| {
                borrow_list_head(ctx, p, moves, s)
            })
        }
        // A wildcard binds nothing; other heads never reach a list `case`.
        Pat::Wildcard
        | Pat::Str(_)
        | Pat::Int(_)
        | Pat::Bool(_)
        | Pat::Char(_)
        | Pat::Ctor { .. }
        | Pat::Tuple(_)
        | Pat::Record(_) => render_pat(ctx, pat),
    }
}

/// The slot-array name of the owned view tagged `tag`.
fn view_slots(tag: usize) -> String {
    format!("__ipe_v{tag}_a")
}

/// The tail name of the owned view tagged `tag`.
fn view_tail(tag: usize) -> String {
    format!("__ipe_v{tag}_t")
}

/// Does `pat` bind any name at any depth?
fn binds_any(pat: &Pat) -> bool {
    let mut bound = BTreeSet::new();
    pat_bound_symbols(pat, &mut bound);
    !bound.is_empty()
}

/// Write `let <name> = ipe_list_view_rest(<slots>, <tail>);` into `prelude`.
fn push_view_rest(
    ctx: &EmitCtx,
    name: Symbol,
    slots: &str,
    tail: &str,
    prelude: &mut String,
) -> DResult<()> {
    let name = ctx.emit_ident(name)?;
    write!(
        prelude,
        "let {name} = ipe_runtime::list::ipe_list_view_rest({slots}, {tail}); "
    )
    .map_err(|e| Diagnostic::CompilerBug {
        where_: "ipe_backend_rust::owned_list_arm_head",
        detail: format!("writing owned list rebind failed: {e}"),
    })
}

/// Render one arm head of an owned list view `width` slots wide, its prelude into `sink`.
///
/// The column is matched against `([Option<T>; width], Vec<T>)` by value, so
/// every binder moves out of the view and none is cloned:
///
/// * a closed prefix of `k` elements is `([Some(p0), …, None, ..], _)` — slot `k`
///   is `None` exactly when the list has `k` elements, since `k < width`;
/// * an open prefix of `k` with rest `r` binds the slots past `k` and the tail,
///   then rebuilds `r` from them (`ipe_list_view_rest`);
/// * a whole-list binder `xs` binds the slot array and the tail and rebuilds
///   `xs`; an alias whose inner binds nothing binds the slot array over the
///   inner shape the same way.
///
/// The lowerer refuses an alias or or-pattern that would own an element twice
/// (IPE-L0135, IPE-L0116), so reaching one here is an internal error.
pub fn owned_list_arm_head(
    ctx: &EmitCtx,
    pat: &Pat,
    width: usize,
    tag: usize,
    sink: &mut ArmSink,
) -> DResult<String> {
    if matches!(pat, Pat::Wildcard) {
        return Ok("_".to_owned());
    }
    let (slots, tail) = owned_view_shape(ctx, pat, width, tag, sink)?;
    Ok(format!("({slots}, {tail})"))
}

/// The slot-array pattern and tail pattern of an owned list arm head.
fn owned_view_shape(
    ctx: &EmitCtx,
    pat: &Pat,
    width: usize,
    tag: usize,
    sink: &mut ArmSink,
) -> DResult<(String, String)> {
    let fault = |detail: &str| Diagnostic::CompilerBug {
        where_: "ipe_backend_rust::owned_list_arm_head",
        detail: detail.to_owned(),
    };
    match pat {
        Pat::Wildcard => Ok(("_".to_owned(), "_".to_owned())),
        Pat::Var(name) => {
            let (slots, tail) = (view_slots(tag), view_tail(tag));
            push_view_rest(ctx, *name, &slots, &tail, &mut sink.prelude)?;
            Ok((slots, tail))
        }
        Pat::Slice {
            prefix,
            rest,
            own: SliceOwnership::OwnedMove,
            ..
        } => {
            let k = prefix.len();
            if k >= width {
                return Err(fault("a slice prefix is as wide as its owned view"));
            }
            let mut parts = Vec::with_capacity(width.saturating_add(1));
            for sub in prefix {
                parts.push(format!("Some({})", render_owned_elem(ctx, sub, sink)?));
            }
            let tail = match rest.as_deref() {
                None => {
                    parts.push("None".to_owned());
                    parts.push("..".to_owned());
                    "_".to_owned()
                }
                Some(Pat::Wildcard) => {
                    parts.push("..".to_owned());
                    "_".to_owned()
                }
                Some(Pat::Var(r)) => {
                    let spill: Vec<String> =
                        (k..width).map(|i| format!("__ipe_v{tag}_s{i}")).collect();
                    parts.extend(spill.iter().cloned());
                    let tail = view_tail(tag);
                    push_view_rest(
                        ctx,
                        *r,
                        &format!("[{}]", spill.join(", ")),
                        &tail,
                        &mut sink.prelude,
                    )?;
                    tail
                }
                Some(_) => return Err(fault("a slice rest is neither a variable nor a wildcard")),
            };
            Ok((format!("[{}]", parts.join(", ")), tail))
        }
        Pat::Slice {
            own: SliceOwnership::BorrowClone,
            ..
        } => Err(fault("a borrow-clone slice reached an owned list view")),
        Pat::Alias(inner, name) => {
            if binds_any(inner) {
                return Err(fault(
                    "an alias over a binding list pattern reached an owned list view; \
                     the lowerer refuses it (IPE-L0135)",
                ));
            }
            let (inner_slots, _) = owned_view_shape(ctx, inner, width, tag, sink)?;
            let (slots, tail) = (view_slots(tag), view_tail(tag));
            push_view_rest(ctx, *name, &slots, &tail, &mut sink.prelude)?;
            if inner_slots == "_" {
                Ok((slots, tail))
            } else {
                Ok((format!("{slots} @ {inner_slots}"), tail))
            }
        }
        // A `SharedAlts` alternative is binder-free, so it takes no slot.
        Pat::Or(alts) => {
            let mut parts = Vec::with_capacity(alts.as_slice().len());
            for alt in alts.as_slice() {
                parts.push(owned_view_shape(ctx, alt, width, tag, sink)?.0);
            }
            Ok((format!("({})", parts.join(" | ")), "_".to_owned()))
        }
        Pat::Int(_)
        | Pat::Bool(_)
        | Pat::Char(_)
        | Pat::Str(_)
        | Pat::Ctor { .. }
        | Pat::Tuple(_)
        | Pat::Record(_) => Err(fault("a non-list arm head reached an owned list view")),
    }
}

/// Render an element sub-pattern of an owned list view, matched by value.
///
/// Each binder moves its part out of the element; a binder at a boxed field
/// moves out of its box. An alias whose inner binds nothing renders `n @ p`,
/// which moves only `n`. An alias whose inner binds a name would own its part
/// twice and is refused at lowering (IPE-L0135); a string literal or a nested
/// list in an element is refused there too (IPE-L0116). Reaching any of the
/// three here is an internal error.
fn render_owned_elem(ctx: &EmitCtx, pat: &Pat, sink: &mut ArmSink) -> DResult<String> {
    if owned_elem_fault(pat) {
        return Err(Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::render_owned_elem",
            detail: "an owned list element holds a binding alias, a string literal or a \
                     nested list; the lowerer refuses each"
                .to_owned(),
        });
    }
    owned_elem(ctx, pat, sink)
}

/// Render an owned list element already cleared by [`owned_elem_fault`].
fn owned_elem(ctx: &EmitCtx, pat: &Pat, sink: &mut ArmSink) -> DResult<String> {
    match pat {
        Pat::Ctor {
            home,
            ty,
            variant,
            args,
        } => render_ctor_pat(
            ctx,
            CtorPat {
                home,
                ty: *ty,
                variant: *variant,
                args,
            },
            FieldAccess::ByValue,
            sink,
            &mut |p: &Pat, s: &mut ArmSink| owned_elem(ctx, p, s),
        ),
        Pat::Tuple(elems) => {
            let mut subs = Vec::with_capacity(elems.len());
            for sub in elems {
                subs.push(owned_elem(ctx, sub, sink)?);
            }
            Ok(format!("({})", subs.join(", ")))
        }
        Pat::Record(fields) => render_record_with(ctx, fields, |p| owned_elem(ctx, p, sink)),
        Pat::Alias(inner, name) => {
            let inner = owned_elem(ctx, inner, sink)?;
            Ok(format!("{} @ {inner}", ctx.emit_ident(*name)?))
        }
        Pat::Or(alts) => {
            render_or_alternatives(alts.as_slice(), sink, &mut |p: &Pat, s: &mut ArmSink| {
                owned_elem(ctx, p, s)
            })
        }
        Pat::Var(_)
        | Pat::Wildcard
        | Pat::Int(_)
        | Pat::Bool(_)
        | Pat::Char(_)
        | Pat::Str(_)
        | Pat::Slice { .. } => render_pat(ctx, pat),
    }
}

/// Does an owned list element hold a shape that cannot be matched by value?
fn owned_elem_fault(pat: &Pat) -> bool {
    match pat {
        Pat::Slice { .. } | Pat::Str(_) => true,
        Pat::Alias(inner, _) => binds_any(inner) || owned_elem_fault(inner),
        Pat::Tuple(subs) => subs.iter().any(owned_elem_fault),
        Pat::Ctor { args, .. } => args.iter().any(owned_elem_fault),
        Pat::Record(fields) => fields.iter().any(|(_, p)| owned_elem_fault(p)),
        // A `SharedAlts` alternative holds no alias, string or list.
        Pat::Or(_) | Pat::Var(_) | Pat::Wildcard | Pat::Int(_) | Pat::Bool(_) | Pat::Char(_) => {
            false
        }
    }
}

/// Render an ELEMENT sub-pattern of a borrowed slice, with its owned-by-`clone` rebinds.
///
/// Every variable / alias binder there is `&T` and is cloned to `T`; a binder
/// at a boxed field is `&Box<T>` and is copied out of its box. Nested tuple /
/// constructor / record element patterns recurse.
fn borrow_elem(ctx: &EmitCtx, pat: &Pat, sink: &mut ArmSink) -> DResult<String> {
    match pat {
        Pat::Var(name) => {
            rebind_clone(ctx, *name, &mut sink.prelude)?;
            ctx.emit_ident(*name)
        }
        Pat::Alias(inner, name) => {
            rebind_clone(ctx, *name, &mut sink.prelude)?;
            let inner = borrow_elem(ctx, inner, sink)?;
            Ok(format!("{} @ {inner}", ctx.emit_ident(*name)?))
        }
        Pat::Tuple(elems) => {
            let mut subs = Vec::with_capacity(elems.len());
            for sub in elems {
                subs.push(borrow_elem(ctx, sub, sink)?);
            }
            Ok(format!("({})", subs.join(", ")))
        }
        Pat::Ctor {
            home,
            ty,
            variant,
            args,
        } => render_ctor_pat(
            ctx,
            CtorPat {
                home,
                ty: *ty,
                variant: *variant,
                args,
            },
            FieldAccess::ByRef,
            sink,
            &mut |p: &Pat, s: &mut ArmSink| borrow_elem(ctx, p, s),
        ),
        Pat::Record(fields) => render_record_with(ctx, fields, |p| borrow_elem(ctx, p, sink)),
        // Every alternative binds the same names at the same types; the first
        // alternative's rebinds serve them all.
        Pat::Or(alts) => {
            render_or_alternatives(alts.as_slice(), sink, &mut |p: &Pat, s: &mut ArmSink| {
                borrow_elem(ctx, p, s)
            })
        }
        // A wildcard / literal element binds nothing. A nested slice element is
        // gated at lowering (it never reaches the backend), so it needs no rebind.
        Pat::Wildcard
        | Pat::Int(_)
        | Pat::Bool(_)
        | Pat::Char(_)
        | Pat::Str(_)
        | Pat::Slice { .. } => render_pat(ctx, pat),
    }
}

/// Collect the owned-by-`to_vec` rebinds for a REST / whole-list binder (`&[T]`
/// → `Vec<T>`). The lowerer admits only a variable / wildcard rest, so this is a
/// single binder (an alias recurses defensively).
pub fn collect_list_rebinds(ctx: &EmitCtx, pat: &Pat, out: &mut String) -> DResult<()> {
    match pat {
        Pat::Var(s) => rebind_to_vec(ctx, *s, out),
        Pat::Alias(inner, name) => {
            rebind_to_vec(ctx, *name, out)?;
            collect_list_rebinds(ctx, inner, out)
        }
        Pat::Wildcard
        | Pat::Int(_)
        | Pat::Bool(_)
        | Pat::Char(_)
        | Pat::Str(_)
        | Pat::Ctor { .. }
        | Pat::Tuple(_)
        | Pat::Record(_)
        | Pat::Slice { .. }
        // A `SharedAlts` alternative is binder-free.
        | Pat::Or(_) => Ok(()),
    }
}

/// Emit `let <name> = <name>.clone();` — rebind a slice ELEMENT binder (`&T`) to
/// the owned `T` the arm body expects.
pub fn rebind_clone(ctx: &EmitCtx, sym: Symbol, out: &mut String) -> DResult<()> {
    let name = ctx.emit_ident(sym)?;
    write!(out, "let {name} = {name}.clone(); ").map_err(|e| Diagnostic::CompilerBug {
        where_: "ipe_backend_rust::list_binder_rebinds",
        detail: format!("writing element rebind failed: {e}"),
    })
}

/// Emit `let <name> = <name>.to_vec();` — rebind a slice REST / whole-list binder
/// (`&[T]`) to the owned `Vec<T>` the arm body expects.
pub fn rebind_to_vec(ctx: &EmitCtx, sym: Symbol, out: &mut String) -> DResult<()> {
    let name = ctx.emit_ident(sym)?;
    write!(out, "let {name} = {name}.to_vec(); ").map_err(|e| Diagnostic::CompilerBug {
        where_: "ipe_backend_rust::list_binder_rebinds",
        detail: format!("writing rest rebind failed: {e}"),
    })
}

/// Render a pattern to its Rust spelling. Total and recursive over the entire
/// pattern set:
///
/// * a variable binder (the keyword-mangled name),
/// * a wildcard (`_`),
/// * a literal leaf — int (`0`), bool (`true`), char (`'a'`), string (`"hi"`),
/// * an alias / `as` pattern (`name @ <inner>`),
/// * a tuple pattern (`(sub0, sub1, …)`),
/// * a constructor pattern (`EnumName::Variant` / `EnumName::Variant(sub0, …)`),
/// * a record pattern (`RecXY { x: sub0, y: sub1, .. }`).
///
/// Every nested sub-position recurses through this same function, so an
/// arbitrarily nested shape (`Just (a, b)`, `Node (Node …) x r`,
/// `{ point = (a, b) }`) renders correctly. The renderer stays total: no arm
/// panics, and every fallible lookup is surfaced as a [`Diagnostic`].
pub fn render_pat(ctx: &EmitCtx, pat: &Pat) -> DResult<String> {
    match pat {
        Pat::Var(sym) => ctx.emit_ident(*sym),
        Pat::Wildcard => Ok("_".to_owned()),
        // Literal leaves render as Rust literals. Int renders through
        // `int_pattern` (unsuffixed, unparenthesised: a pattern is never a
        // receiver, and the type comes from the `i64` scrutinee); Bool maps to
        // the Rust keyword constant; Char and Str render through
        // `rust_char_lit` / `rust_str_lit`, a valid Rust literal with every
        // lexer hazard escaped.
        Pat::Int(n) => Ok(int_pattern(*n)),
        Pat::Bool(b) => Ok(if *b { "true" } else { "false" }.to_owned()),
        // A well-formed Char pattern carries exactly one character → Rust char
        // literal. A non-single-scalar value fails closed as a `CompilerBug`:
        // emitting a string literal in char-pattern position produces invalid
        // Rust (E0308, cargo-fails), violating THE SEAL. Symmetric with
        // `Expr::Char`, which applies the same fail-closed policy.
        Pat::Char(c) => {
            let mut chars = c.chars();
            match (chars.next(), chars.next()) {
                (Some(ch), None) => Ok(rust_char_lit(ch)),
                _ => Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::emit_pat(Pat::Char)",
                    detail: format!(
                        "Pat::Char carried {} characters ({c:?}), not the single \
                         character the lexer's char-literal invariant guarantees",
                        c.chars().count()
                    ),
                }),
            }
        }
        Pat::Str(s) => Ok(rust_str_lit(s)),
        // `inner as name` → Rust binding-with-subpattern `name @ <inner>`. The
        // inner sub-pattern recurses through this same total renderer.
        //
        // This spelling is correct ONLY in a by-REF / refutable MATCH-ARM
        // position, where default binding modes make the sub-bindings borrows
        // so no move occurs. A by-VALUE irrefutable binding (`Expr::Destructure`
        // — the desugaring of a `let`, a single-arm product `case`, and a
        // function/lambda parameter pattern) must NOT reach this arm: `name @
        // inner` would move BOTH the whole (`name`) and each sub-binding, which
        // is a partial move (E0382) for any non-`Copy` payload. Those sites go
        // through `emit_binding_stmts`, which intercepts every alias — at any
        // nesting depth — before it can reach this renderer.
        Pat::Alias(inner, name) => {
            let name = ctx.emit_ident(*name)?;
            let inner = render_pat(ctx, inner)?;
            Ok(format!("{name} @ {inner}"))
        }
        Pat::Tuple(elems) => {
            // A tuple pattern destructures element-by-element: `(p0, p1, …)`.
            // Stays total over any element vector (no arity assumption).
            let mut subs = Vec::with_capacity(elems.len());
            for sub in elems {
                subs.push(render_pat(ctx, sub)?);
            }
            Ok(format!("({})", subs.join(", ")))
        }
        // A constructor renders through the field-aware funnel. This renderer
        // has no prelude slot, so a binder at a boxed field is refused there.
        Pat::Ctor {
            home,
            ty,
            variant,
            args,
        } => render_ctor_pat(
            ctx,
            CtorPat {
                home,
                ty: *ty,
                variant: *variant,
                args,
            },
            FieldAccess::NoPrelude,
            &mut ArmSink::default(),
            &mut |p: &Pat, _: &mut ArmSink| render_pat(ctx, p),
        ),
        Pat::Record(fields) => render_record_pat(ctx, fields),
        // A list / cons pattern renders as a native Rust slice pattern. A closed
        // (exact-length) pattern is `[p0, p1]`; an open cons tail is
        // `[p0, p1, rest @ ..]` (binding the rest) or `[p0, p1, ..]` (ignoring
        // it). The leading element patterns recurse through this same renderer.
        Pat::Slice { prefix, rest, .. } => {
            let mut parts = Vec::with_capacity(prefix.len() + 1);
            for sub in prefix {
                parts.push(render_pat(ctx, sub)?);
            }
            match rest {
                Some(r) => {
                    parts.push(render_rest_pat(ctx, r)?);
                    Ok(format!("[{}]", parts.join(", ")))
                }
                None => Ok(format!("[{}]", parts.join(", "))),
            }
        }
        // An or-pattern renders as the native Rust or-pattern `p0 | p1 | …`,
        // joining each rendered alternative with ` | `. Every alternative binds
        // the same names (proved upstream), so the ONE arm body reads them
        // whichever alternative matched — no body duplication. Rust resolves
        // overlap and ordering across alternatives exactly as it does across
        // arms.
        Pat::Or(alts) => {
            let mut parts = Vec::with_capacity(alts.as_slice().len());
            for alt in alts.as_slice() {
                parts.push(render_pat(ctx, alt)?);
            }
            Ok(parts.join(" | "))
        }
    }
}

/// Does this irrefutable binder carry an `as`-alias anywhere in its shape?
///
/// A by-VALUE binding of an alias cannot use Rust's `name @ inner` spelling
/// (it moves the whole AND the sub-bindings — a partial move / `E0382` for any
/// non-`Copy` payload), so [`emit_binding_stmts`] takes the clone-splitting
/// path whenever this returns `true`. This walks exactly the shapes the
/// destructure-binder grammar admits — variable, wildcard, tuple, alias, and a
/// top-level record whose fields are only variables / wildcards. A record field
/// therefore never carries an alias (the lowerer forbids it — IPE-L0112), and a
/// constructor / slice / literal never appears in an irrefutable binder, so
/// those return `false`. The predicate and [`emit_binding_stmts`] special-case
/// the SAME two shapes (`Alias`, `Tuple`); any disagreement fails closed there.
pub fn pat_contains_alias(pat: &Pat) -> bool {
    match pat {
        Pat::Alias(..) => true,
        Pat::Tuple(elems) => elems.iter().any(pat_contains_alias),
        Pat::Var(_)
        | Pat::Wildcard
        | Pat::Int(_)
        | Pat::Bool(_)
        | Pat::Char(_)
        | Pat::Str(_)
        | Pat::Ctor { .. }
        | Pat::Record(_)
        | Pat::Slice { .. }
        // An or-pattern is refutable, so it never appears in a by-value
        // irrefutable binder.
        | Pat::Or(_) => false,
    }
}

/// Does this pattern contain a [`Pat::Alias`] ANYWHERE in its shape —
/// unlike [`pat_contains_alias`] (which only recurses into `Tuple`, because
/// it exists solely for the by-VALUE Destructure grammar where
/// `Ctor`/`Record`/`Slice` never legitimately appear), this ALSO recurses
/// into `Ctor` args, `Record` fields, and `Slice` prefix/rest — all of which
/// DO appear in a refutable match-arm pattern.
pub fn pat_contains_alias_in_arm(pat: &Pat) -> bool {
    match pat {
        Pat::Alias(..) => true,
        Pat::Tuple(elems) => elems.iter().any(pat_contains_alias_in_arm),
        Pat::Ctor { args, .. } => args.iter().any(pat_contains_alias_in_arm),
        Pat::Record(fields) => fields.iter().any(|(_, p)| pat_contains_alias_in_arm(p)),
        Pat::Slice { prefix, rest, .. } => {
            prefix.iter().any(pat_contains_alias_in_arm)
                || rest.as_deref().is_some_and(pat_contains_alias_in_arm)
        }
        // A `SharedAlts` alternative holds no alias.
        Pat::Or(_)
        | Pat::Var(_)
        | Pat::Wildcard
        | Pat::Int(_)
        | Pat::Bool(_)
        | Pat::Char(_)
        | Pat::Str(_) => false,
    }
}

/// Render a BY-VALUE (whole-scrutinee, non-str, non-list) match-arm sub-pattern.
///
/// Any [`Pat::Alias`] routes through the SAME "bind the whole, destructure the
/// inner shape from a CLONE" strategy [`emit_binding_stmts`] proves sound for
/// irrefutable Destructure positions — in THIS context the scrutinee is
/// matched BY VALUE (never `&str`/`&[T]`), so `render_pat`'s `name @ inner`
/// spelling (sound only under a by-REF default binding mode) would double-move
/// `name` and `inner`'s own bindings for any non-`Copy` payload. A constructor
/// with a payload renders through [`render_ctor_pat`], which reads its boxed
/// fields through the box.
///
/// A subtree with no alias, no by-value string literal and no constructor
/// payload renders through [`render_pat`]. `sink` accumulates the `let`
/// statements that re-derive every aliased or unboxed binder, and the
/// by-value string-literal guards.
#[allow(clippy::too_many_lines)] // one arm per IR pattern shape — a rendering table, not branching logic
pub fn render_arm_pat_alias_safe(ctx: &EmitCtx, pat: &Pat, sink: &mut ArmSink) -> DResult<String> {
    // Fast path: no alias, no by-value string-literal leaf and no constructor
    // payload → the plain renderer. A `Pat::Str` in a by-value position would
    // render as a `&str` literal pattern against an owned `String` field
    // (E0308), so its presence forces the guard walk below even when there is
    // no alias. `pat_has_str_guard_slot` is the one classifier the lowerer's
    // move gate (`PartialMove::of_pattern`) shares, so a guard slot minted here
    // is always counted there as a move of its part.
    if !pat_contains_alias_in_arm(pat) && !pat_has_str_guard_slot(pat) && !pat_has_ctor_payload(pat)
    {
        return render_pat(ctx, pat);
    }
    match pat {
        // A by-value string-literal column: Rust can't match an owned
        // `String` field against a `&str` literal pattern, so bind the field to a
        // fresh `__sgN` and emit an `if __sgN.as_str() == "lit"` match guard. The
        // caller ANDs the accumulated guards onto the arm — a false guard falls
        // through to the next arm, exactly matching the `case`'s literal-column
        // semantics.
        Pat::Str(s) => {
            let binder = format!("__sg{}", sink.fresh());
            sink.guards
                .push(format!("{binder}.as_str() == {}", rust_str_lit(s)));
            Ok(binder)
        }
        Pat::Alias(inner, _name) => {
            // IPE-L0128 (`gate_by_value_dispatch_needing_aliases`) guarantees
            // `inner` is dispatch-free by the time lowering succeeds; fail
            // closed rather than silently mis-emit if that invariant is ever
            // violated.
            if !ipe_ir::is_dispatch_free(inner) {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::render_arm_pat_alias_safe",
                    detail: "alias over a dispatch-needing inner pattern reached the \
                             backend; IPE-L0128 should have rejected this at lowering"
                        .to_owned(),
                });
            }
            let temp = format!("__ipe_arm_alias_{}", sink.fresh());
            // `emit_binding_stmts` handles `Pat::Alias` exactly this way:
            // `let <name> = <src>; let <inner-pattern> = <name>.clone();` —
            // pass the WHOLE alias node and the fresh temp as `src`.
            for stmt in emit_binding_stmts(ctx, pat, &temp)? {
                sink.push_stmt(&stmt);
            }
            Ok(temp)
        }
        Pat::Tuple(elems) => {
            let mut subs = Vec::with_capacity(elems.len());
            for e in elems {
                subs.push(render_arm_pat_alias_safe(ctx, e, sink)?);
            }
            Ok(format!("({})", subs.join(", ")))
        }
        Pat::Ctor {
            home,
            ty,
            variant,
            args,
        } => render_ctor_pat(
            ctx,
            CtorPat {
                home,
                ty: *ty,
                variant: *variant,
                args,
            },
            FieldAccess::ByValue,
            sink,
            &mut |p: &Pat, s: &mut ArmSink| render_arm_pat_alias_safe(ctx, p, s),
        ),
        Pat::Record(fields) => {
            render_record_with(ctx, fields, |p| render_arm_pat_alias_safe(ctx, p, sink))
        }
        // Every `Slice` head selects a list view (`list_arm_head`): a borrowed
        // view matches by reference, an owned view renders through
        // `owned_list_arm_head`. Neither reaches this by-value renderer, so
        // reaching here is an internal invariant violation.
        Pat::Slice { .. } => Err(Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::render_arm_pat_alias_safe",
            detail: "Pat::Slice reached the by-value alias-safe renderer; list-mode \
                     arms must route through list_arm_head"
                .to_owned(),
        }),
        // A per-alternative match guard cannot attach to one branch of a Rust
        // or-pattern, so a string-literal alternative is the residual
        // guarded-alternative case — fail closed rather than emit an invalid
        // guarded or-pattern. Every other or-pattern renders each alternative
        // through this same renderer and joins them with ` | `.
        Pat::Or(alts) => {
            if alts.as_slice().iter().any(pat_has_str_guard_slot) {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::render_arm_pat_alias_safe",
                    detail: "a by-value string-literal leaf inside an or-pattern \
                             alternative needs a per-alternative match guard, which \
                             a Rust or-pattern cannot carry; the lowerer's residual \
                             shared-continuation fallback should have handled it"
                        .to_owned(),
                });
            }
            render_or_alternatives(alts.as_slice(), sink, &mut |p: &Pat, s: &mut ArmSink| {
                render_arm_pat_alias_safe(ctx, p, s)
            })
        }
        // `Pat::Str` is intercepted above (binder + guard); the remaining
        // leaves render directly.
        Pat::Var(_) | Pat::Wildcard | Pat::Int(_) | Pat::Bool(_) | Pat::Char(_) => {
            render_pat(ctx, pat)
        }
    }
}

/// Does `pat` hold a constructor with a payload anywhere outside a slice?
fn pat_has_ctor_payload(pat: &Pat) -> bool {
    match pat {
        Pat::Ctor { args, .. } => !args.is_empty(),
        Pat::Alias(inner, _) => pat_has_ctor_payload(inner),
        Pat::Tuple(elems) => elems.iter().any(pat_has_ctor_payload),
        Pat::Record(fields) => fields.iter().any(|(_, p)| pat_has_ctor_payload(p)),
        Pat::Or(alts) => alts.as_slice().iter().any(pat_has_ctor_payload),
        Pat::Slice { .. }
        | Pat::Var(_)
        | Pat::Wildcard
        | Pat::Int(_)
        | Pat::Bool(_)
        | Pat::Char(_)
        | Pat::Str(_) => false,
    }
}
/// Emit the Rust `let` statement sequence for an irrefutable destructuring
/// binding `<binder> = <value>` (WITHOUT the trailing body). Shared by both
/// `Expr::Destructure` emit sites (value-context and tail-context), which is the
/// desugaring of a `let` destructure, a single-arm product `case`, and a
/// function / lambda parameter pattern.
///
/// The SEAL-upholding logic lives here: in a by-VALUE binding position an
/// `as`-alias must NOT render as `name @ inner`. That binds BOTH the whole
/// (`name`) and the sub-bindings by move, a partial move (`E0382`) for any
/// non-`Copy` payload (`\((a, b) as whole) -> …` over `(String, String)` is
/// otherwise `ipe`-0 then `cargo`-101). Instead the whole is bound first and
/// the inner shape is destructured from a CLONE:
///
/// ```ignore
/// let whole = <value>;
/// let (a, b) = whole.clone();
/// ```
///
/// The lowerer refuses (IPE-L0135) an alias whose inner pattern binds a name
/// over a non-`Clone` part, so the clone always resolves. An alias whose inner
/// binds nothing takes no part, so it binds the whole alone (`let whole =
/// <value>;`) with no clone, whatever the part's clone class.
/// When the binder carries NO alias the fast path emits the single flat
/// `let <pat> = <value>;`, a plain clone-free binding. Aliases nested inside
/// tuples (`let (x, (a, b) as inner) = …`) are
/// handled at any depth: each tuple element binds to a fresh, uniquely-numbered
/// temporary, so a nested alias clones from its OWN temp and never shares a move
/// with a sibling binder.
pub fn emit_binding_stmts(ctx: &EmitCtx, binder: &Pat, value: &str) -> DResult<Vec<String>> {
    let mut out = Vec::new();
    let mut counter: usize = 0;
    push_binding_stmts(ctx, binder, value, &mut counter, &mut out)?;
    Ok(out)
}

pub fn push_binding_stmts(
    ctx: &EmitCtx,
    pat: &Pat,
    src: &str,
    counter: &mut usize,
    out: &mut Vec<String>,
) -> DResult<()> {
    // Fast path: an alias-free binder binds every name via a single flat,
    // move-only `let <pat> = <src>;` — no clone.
    if !pat_contains_alias(pat) {
        let rendered = render_pat(ctx, pat)?;
        out.push(format!("let {rendered} = {src};"));
        return Ok(());
    }
    match pat {
        // `inner as name`: bind the whole first, then destructure the inner
        // shape from a CLONE so the whole binding and the sub-bindings never
        // both move the same value.
        Pat::Alias(inner, name) => {
            let name = ctx.emit_ident(*name)?;
            out.push(format!("let {name} = {src};"));
            if !binds_any(inner) {
                return Ok(());
            }
            push_binding_stmts(ctx, inner, &format!("{name}.clone()"), counter, out)
        }
        // A tuple carrying an alias in some element: bind each element to a
        // fresh, uniquely-numbered temp (a plain move-only destructure), then
        // recurse per element. The unique counter guarantees a nested aliased
        // tuple never re-uses an outer temp name.
        Pat::Tuple(elems) => {
            let base = *counter;
            *counter += elems.len();
            let temps: Vec<String> = (0..elems.len())
                .map(|i| format!("__ipe_bind_{}", base + i))
                .collect();
            out.push(format!("let ({}) = {src};", temps.join(", ")));
            for (elem, temp) in elems.iter().zip(&temps) {
                push_binding_stmts(ctx, elem, temp, counter, out)?;
            }
            Ok(())
        }
        // No other binder shape carries an alias (see [`pat_contains_alias`]).
        // If the predicate and this match ever disagree, fail closed rather
        // than silently emit a moving `name @ inner`.
        Pat::Var(_)
        | Pat::Wildcard
        | Pat::Int(_)
        | Pat::Bool(_)
        | Pat::Char(_)
        | Pat::Str(_)
        | Pat::Ctor { .. }
        | Pat::Record(_)
        | Pat::Slice { .. }
        // An or-pattern is refutable, so it is never a by-value irrefutable
        // binder; reaching here is an invariant violation.
        | Pat::Or(_) => Err(Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::push_binding_stmts",
            detail: "an aliased binder resolved to a non-alias, non-tuple shape".to_owned(),
        }),
    }
}

/// Render the open TAIL of a slice pattern — the `rest @ ..` / `..` suffix. A
/// variable binds the remaining slice (`name @ ..`); a wildcard ignores it
/// (`..`). The lowerer admits only these two rest shapes ([`crate`]-side
/// `lower_rest_pat` gates the rest), so the renderer is total over them.
pub fn render_rest_pat(ctx: &EmitCtx, pat: &Pat) -> DResult<String> {
    match pat {
        Pat::Var(s) => Ok(format!("{} @ ..", ctx.emit_ident(*s)?)),
        // A wildcard ignores the tail (`..`). No other rest shape is produced by
        // the lowerer, so the catch-all stays total — a bare `..` ignores the
        // tail rather than mis-rendering.
        _ => Ok("..".to_owned()),
    }
}

/// Render a record pattern `{ field0 = p0, … }` to a Rust struct pattern
/// `RecXY { field0: p0, …, .. }`.
pub fn render_record_pat(ctx: &EmitCtx, fields: &[(Symbol, Pat)]) -> DResult<String> {
    render_record_with(ctx, fields, |p| render_pat(ctx, p))
}

/// Render a record pattern, each field's sub-pattern through `sub`.
///
/// The struct is resolved by the pattern's field-name set, exactly as a record
/// LITERAL resolves its struct (Rust names struct-pattern fields, so write order
/// is free). The lowerer surfaces the complete field set, so this exact-set
/// lookup is unambiguous; a miss is an upstream-contract violation surfaced as a
/// [`Diagnostic::CompilerBug`] rather than a silent mis-emit.
///
/// A trailing `..` is always emitted: it both matches the canonical struct-
/// pattern shape and makes the rendering robust to a field the pattern does not
/// bind (zero remaining fields under the complete-set contract — a legal,
/// no-op `..`). A field whose sub-pattern is a variable bound to the field's own
/// name renders in Rust shorthand (`x` rather than the lint-flagged `x: x`).
/// `sub` runs on every field, a shorthand one included, so the prelude it
/// writes covers every binder.
fn render_record_with<F>(ctx: &EmitCtx, fields: &[(Symbol, Pat)], mut sub: F) -> DResult<String>
where
    F: FnMut(&Pat) -> DResult<String>,
{
    // Resolve the struct by the (sorted) set of bound field names.
    let mut key = Vec::with_capacity(fields.len());
    for (sym, _) in fields {
        key.push(ctx.resolve_ident(*sym)?.to_owned());
    }
    // A record pattern carries no field types to disambiguate a shared field-name
    // set; the unambiguous case resolves, and a genuinely-ambiguous one surfaces
    // a clear internal error rather than silently binding the wrong struct.
    let struct_name = ctx.record_name_for_literal(&key, None)?.to_owned();

    let mut parts = Vec::with_capacity(fields.len());
    for (sym, field_pat) in fields {
        let field_ident = ctx.emit_ident(*sym)?;
        let rendered = sub(field_pat)?;
        // Field-pun shorthand: `Rec { x, .. }` instead of `Rec { x: x, .. }`
        // (the latter trips rustc's `non_shorthand_field_patterns` lint). Only
        // when the sub-pattern is a variable whose emitted name equals the
        // field's emitted name.
        if let Pat::Var(var) = field_pat
            && ctx.emit_ident(*var)? == field_ident
        {
            parts.push(field_ident);
        } else {
            parts.push(format!("{field_ident}: {rendered}"));
        }
    }
    // An empty entry vector is degenerate (the lowerer never produces it), but
    // stay total: render `Rec { .. }` rather than the invalid `Rec { , .. }`.
    if parts.is_empty() {
        Ok(format!("{struct_name} {{ .. }}"))
    } else {
        Ok(format!("{struct_name} {{ {}, .. }}", parts.join(", ")))
    }
}
