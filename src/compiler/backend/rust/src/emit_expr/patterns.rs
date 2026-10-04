use super::{
    Arm, DResult, Diagnostic, Expr, GenericScope, Match, ModPath, Pat, Symbol, emit_expr_at,
    int_pattern,
};
use crate::EmitCtx;
use core::fmt::Write as _;
use ipe_ir::free_vars::pat_has_str_guard_slot;

/// Render `s` as a Rust double-quoted string literal through Rust's own
/// `Debug` grammar for `str`.
///
/// `{s:?}` escapes every character the Rust string-literal grammar cannot
/// carry raw: `\`, `"`, and every non-printable scalar (controls, format
/// characters, bidi overrides) as `\u{..}`. The one-escaper-per-grammar
/// property matters here because a raw bidi override (e.g. U+202E) in an
/// emitted literal trips rustc's deny-by-default
/// `text_direction_codepoint_in_literal` lint — an `ipe`-accepts-then-
/// `cargo`-fails SEAL break — while a hand-picked `\`/`"`-only escaper lets
/// it through. On printable ASCII, `Debug` escapes exactly `\` and `"`.
pub fn rust_str_lit(s: &str) -> String {
    format!("{s:?}")
}

/// Emit the scrutinee of a `Match` plus its two mode flags. A string scrutinee is
/// matched as `&str` (so literal patterns apply) — the presence of a `Pat::Str`
/// head is the reliable signal (the type checker proved the scrutinee a
/// `String`). A LIST scrutinee (the runtime's `Vec<T>`) is matched as a slice so
/// the native Rust slice patterns `[]` / `[a, b]` / `[x, rest @ ..]` apply — a
/// `Pat::Slice` head is the signal. Shared by the value-context (`emit_match`)
/// and tail-context (`emit_expr_tail`) match emitters so the two agree exactly.
/// How a `match` scrutinee is coerced for pattern matching. A WHOLE scrutinee is
/// matched as `&str` (string `case`) or `&[T]` (list `case`) or as-is; a TUPLE
/// scrutinee (a multi-arm product `case`) is matched column-by-column, each
/// column carrying its own string / list coercion.
pub enum ScrutMode {
    Whole { str_mode: bool, list_mode: bool },
    Tuple(Vec<ColMode>),
}

/// The per-column coercion flags of a tuple-scrutinee `match`. A column is
/// matched as `&[T]` when some arm slices it (`… , x :: xs , …`) and as `&str`
/// when some arm matches it against a string literal.
#[derive(Clone, Copy)]
pub struct ColMode {
    str_mode: bool,
    list_mode: bool,
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
pub fn tuple_col_modes(arms: &[Arm], arity: usize) -> Vec<ColMode> {
    let mut cols = vec![
        ColMode {
            str_mode: false,
            list_mode: false,
        };
        arity
    ];
    for arm in arms {
        if let Pat::Tuple(elems) = &arm.pat {
            for (c, sub) in elems.iter().enumerate() {
                if let Some(col) = cols.get_mut(c) {
                    if matches!(sub, Pat::Str(_)) {
                        col.str_mode = true;
                    }
                    if matches!(sub, Pat::Slice { .. }) {
                        col.list_mode = true;
                    }
                }
            }
        }
    }
    cols
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
        let cols = tuple_col_modes(m.arms(), arity);
        let mut parts = Vec::with_capacity(arity);
        for (elem, col) in elems.iter().zip(&cols) {
            let e = emit_expr_at(ctx, elem, indent, child, generics)?;
            let e = if col.str_mode {
                format!("({e}).as_str()")
            } else if col.list_mode {
                format!("({e}).as_slice()")
            } else {
                e
            };
            parts.push(e);
        }
        return Ok((format!("({})", parts.join(", ")), ScrutMode::Tuple(cols)));
    }

    let scrut_expr = emit_expr_at(ctx, m.scrutinee(), indent, child, generics)?;
    let str_mode = m.arms().iter().any(|a| matches!(a.pat, Pat::Str(_)));
    let list_mode = m.arms().iter().any(|a| matches!(a.pat, Pat::Slice { .. }));
    let scrut = if str_mode {
        format!("({scrut_expr}).as_str()")
    } else if list_mode {
        format!("({scrut_expr}).as_slice()")
    } else {
        scrut_expr
    };
    Ok((
        scrut,
        ScrutMode::Whole {
            str_mode,
            list_mode,
        },
    ))
}

/// Render one match-arm head to its Rust pattern plus any leading rebind/unbox
/// prelude. A constructor head goes through `emit_ctor_arm_pat` (which unboxes a
/// cyclic self-field binder); a flat-match leaf head — literal / wildcard /
/// variable / alias / slice — goes through `render_pat` (total over the whole
/// set), with a `String`/slice binder rebind prelude in string/list mode. Shared
/// by the value-context and tail-context match emitters.
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
    let (rendered, prelude, guards) = match mode {
        ScrutMode::Whole {
            str_mode,
            list_mode,
        } => emit_whole_arm_head(ctx, pat, *str_mode, *list_mode)?,
        ScrutMode::Tuple(cols) => emit_tuple_arm_head(ctx, pat, cols)?,
    };
    let guard = if guards.is_empty() {
        None
    } else {
        Some(guards.join(" && "))
    };
    Ok((rendered, prelude, guard))
}

/// Render a WHOLE-scrutinee arm head (the string / list / plain shapes) to its
/// Rust pattern, any leading binder-rebind/unbox prelude, and any synthesized
/// match GUARDS. The guards are the `__sgN.as_str() == "lit"` checks for a
/// by-value string-literal column — the caller ANDs them onto the arm; they are
/// empty for every other shape (so existing emission is byte-identical).
pub fn emit_whole_arm_head(
    ctx: &EmitCtx,
    pat: &Pat,
    str_mode: bool,
    list_mode: bool,
) -> DResult<(String, String, Vec<String>)> {
    if let Pat::Ctor {
        home,
        ty,
        variant,
        args,
    } = pat
    {
        emit_ctor_arm_pat(ctx, home, *ty, *variant, args)
    } else if str_mode || list_mode {
        // STR/LIST mode: the scrutinee IS a reference (`.as_str()` /
        // `.as_slice()`), so `render_pat`'s `name @ inner` is a borrow and
        // sound for any inner shape. A top-level `Pat::Str`
        // matches the `&str`-wrapped scrutinee directly (a literal pattern), so no
        // guard is synthesized here.
        let prelude = if str_mode {
            str_binder_rebinds(ctx, pat)?
        } else {
            list_binder_rebinds(ctx, pat)?
        };
        Ok((render_pat(ctx, pat)?, prelude, Vec::new()))
    } else {
        // WHOLE mode, by value: a top-level dispatch-free alias head
        // (`(a, b) as w ->`) takes the alias-safe clone-rebuild path; a
        // by-value string-literal column (`( "transform", v )` on a variable
        // tuple scrutinee) accumulates its `as_str()` guard here.
        let mut alias_counter: usize = 0;
        let mut prelude = String::new();
        let mut guards = Vec::new();
        let rendered =
            render_arm_pat_alias_safe(ctx, pat, &mut alias_counter, &mut prelude, &mut guards)?;
        Ok((rendered, prelude, guards))
    }
}

/// Render a TUPLE-scrutinee arm head — a `(c0, c1, …)` tuple pattern or a `_`
/// catch-all — plus any per-column binder-rebind prelude. Each column renders
/// against its own coercion: a list column's binders rebind from `&T` / `&[T]`
/// to owned `T` / `Vec<T>`; a string column's binders rebind from `&str` to
/// `String`; a constructor column reuses the whole-scrutinee constructor path
/// (so a cyclic self-edge payload binder is unboxed). The lowerer only produces
/// a tuple or wildcard head here (`tuple_case_supported`), so a whole-value
/// variable / alias binder — which would see the wrong per-column-coerced type —
/// is an internal invariant violation, surfaced as a `CompilerBug`.
pub fn emit_tuple_arm_head(
    ctx: &EmitCtx,
    pat: &Pat,
    cols: &[ColMode],
) -> DResult<(String, String, Vec<String>)> {
    match pat {
        Pat::Tuple(elems) => {
            let mut rendered = Vec::with_capacity(elems.len());
            let mut prelude = String::new();
            let mut guards = Vec::new();
            for (c, sub) in elems.iter().enumerate() {
                // `unwrap_or` on a missing column would silently coerce a
                // wider-than-known tuple pattern to `str_mode: false,
                // list_mode: false` — the WRONG per-column coercion emits a
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
                let (rp, pre, gs) = emit_whole_arm_head(ctx, sub, col.str_mode, col.list_mode)?;
                rendered.push(rp);
                prelude.push_str(&pre);
                guards.extend(gs);
            }
            Ok((format!("({})", rendered.join(", ")), prelude, guards))
        }
        Pat::Wildcard => Ok(("_".to_owned(), String::new(), Vec::new())),
        _ => Err(Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::emit_tuple_arm_head",
            detail: "tuple-scrutinee match arm head is neither a tuple nor a wildcard".to_owned(),
        }),
    }
}

/// Render a constructor arm head to its Rust pattern plus any leading unbox
/// statements. A cyclic self-edge payload field is boxed in the enum, so a
/// variable bound to it is unboxed (`let x = *x;`) at the arm body's head.
pub fn emit_ctor_arm_pat(
    ctx: &EmitCtx,
    home: &ModPath,
    ty: Symbol,
    variant: Symbol,
    args: &[Pat],
) -> DResult<(String, String, Vec<String>)> {
    // A built-in `Maybe` / `Result` pattern matches the runtime enum; its
    // payload is never a boxed self-edge field, so no unbox prelude is needed.
    if let Some(runtime) = ctx.builtin_runtime_enum(home, ty) {
        let path = format!("{runtime}::{}", ctx.emit_ident(variant)?);
        if args.is_empty() {
            return Ok((path, String::new(), Vec::new()));
        }
        // the concrete repro (`Just ((a, b) as w)`) lives HERE — a
        // builtin `Maybe`/`Result` payload matched by value. Route through
        // the alias-safe renderer; alias-free payloads are byte-identical. A
        // by-value string-literal payload (`Just "x"` on a `Maybe String`
        // scrutinee) accumulates its `as_str()` guard in `guards`.
        let mut alias_counter: usize = 0;
        let mut alias_prelude = String::new();
        let mut guards = Vec::new();
        let mut sub_pats = Vec::with_capacity(args.len());
        for sub in args {
            sub_pats.push(render_arm_pat_alias_safe(
                ctx,
                sub,
                &mut alias_counter,
                &mut alias_prelude,
                &mut guards,
            )?);
        }
        return Ok((
            format!("{path}({})", sub_pats.join(", ")),
            alias_prelude,
            guards,
        ));
    }
    let path = format!("{}::{}", ctx.enum_name(home, ty)?, ctx.emit_ident(variant)?);
    if args.is_empty() {
        return Ok((path, String::new(), Vec::new()));
    }
    let fields = ctx.variant_fields(home, ty, variant)?;
    if fields.len() != args.len() {
        return Err(Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::emit_match",
            detail: format!(
                "constructor pattern {} of enum {} binds {} sub-patterns but the \
                 variant declares {} fields",
                variant.as_raw(),
                ty.as_raw(),
                args.len(),
                fields.len()
            ),
        });
    }
    let mut sub_pats = Vec::with_capacity(args.len());
    let mut unbox_lines = String::new();
    let mut guards = Vec::new();
    // a dispatch-free `as`-alias in a by-value ctor payload renders via
    // the alias-safe clone-rebuild path; its re-derivation `let`s share the
    // arm's existing prelude slot. Alias-free sub-patterns take the
    // byte-identical `render_pat` fast path inside.
    let mut alias_counter: usize = 0;
    for (sub, field_ty) in args.iter().zip(fields.iter()) {
        let self_edge = ctx.is_cyclic_self_field(field_ty, home, ty);
        // self-edge fix: an ALIAS over a cyclic-self-edge (recursive)
        // field is boxed in the enum (`Box<Self>`), so the clone-rebuild
        // path must re-derive its binders from the UNBOXED temp — otherwise
        // both the alias binder and the inner bindings stay `Box<T>` where
        // `T` is required (ipe-0-then-cargo-E0308). Bind the field to a fresh
        // raw temp, then re-derive the whole alias shape via the
        // `emit_binding_stmts` machinery against `*temp`.
        if self_edge && pat_contains_alias_in_arm(sub) {
            let temp = format!("__ipe_selfedge_alias_{alias_counter}");
            alias_counter += 1;
            for stmt in emit_binding_stmts(ctx, sub, &format!("*{temp}"))? {
                unbox_lines.push_str(&stmt);
                unbox_lines.push(' ');
            }
            sub_pats.push(temp);
            continue;
        }
        sub_pats.push(render_arm_pat_alias_safe(
            ctx,
            sub,
            &mut alias_counter,
            &mut unbox_lines,
            &mut guards,
        )?);
        // A variable bound to a boxed self-edge field is unboxed so the body
        // sees the payload's own type, not `Box<…>`.
        if self_edge && let Pat::Var(s) = sub {
            let binder = ctx.emit_ident(*s)?;
            write!(unbox_lines, "let {binder} = *{binder}; ").map_err(|e| {
                Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::emit_match",
                    detail: format!("writing unbox binder failed: {e}"),
                }
            })?;
        }
    }
    Ok((
        format!("{path}({})", sub_pats.join(", ")),
        unbox_lines,
        guards,
    ))
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
        | Pat::Slice { .. } => Ok(()),
        // Every alternative of an or-pattern binds the same names at the same
        // types, so rebinding via the first alternative produces the one correct
        // set of `let` rebinds (one per name, never per-alternative).
        Pat::Or(alts) => alts
            .first()
            .map_or(Ok(()), |first| collect_str_rebinds(ctx, first, out)),
    }
}

/// In LIST mode the scrutinee is matched as a slice (`(v).as_slice()`), so every
/// binder a list arm introduces is a borrow: an ELEMENT binder is `&T` and a
/// REST / whole-list binder is `&[T]`. This builds the `let … = …;` prelude that
/// rebinds each to the owned Ipê value the arm body expects — an element via
/// `.clone()` (so the body sees `T`), a rest / whole list via `.to_vec()` (so the
/// body sees `Vec<T>`). Cloning is the sound owned destructure of a shared slice;
/// the lowerer gates a list `case` binding a still-generic (non-`Clone`) element
/// type (IPE-L0102), so the `.clone()` / `.to_vec()` always resolve.
pub fn list_binder_rebinds(ctx: &EmitCtx, pat: &Pat) -> DResult<String> {
    let mut out = String::new();
    match pat {
        Pat::Slice { prefix, rest } => {
            for sub in prefix {
                collect_elem_rebinds(ctx, sub, &mut out)?;
            }
            if let Some(r) = rest {
                collect_list_rebinds(ctx, r, &mut out)?;
            }
        }
        // A whole-list catch-all binder (`xs ->`) or an alias over a list arm
        // (`(x :: rest) as whole ->`): the matched value IS the list.
        Pat::Var(_) => collect_list_rebinds(ctx, pat, &mut out)?,
        Pat::Alias(inner, name) => {
            rebind_to_vec(ctx, *name, &mut out)?;
            out.push_str(&list_binder_rebinds(ctx, inner)?);
        }
        // A wildcard binds nothing; other heads never reach a list `case`.
        Pat::Wildcard
        | Pat::Str(_)
        | Pat::Int(_)
        | Pat::Bool(_)
        | Pat::Char(_)
        | Pat::Ctor { .. }
        | Pat::Tuple(_)
        | Pat::Record(_) => {}
        // Every alternative binds the same names at the same types, so the first
        // alternative's rebinds are the whole arm's set.
        Pat::Or(alts) => {
            if let Some(first) = alts.first() {
                out.push_str(&list_binder_rebinds(ctx, first)?);
            }
        }
    }
    Ok(out)
}

/// Collect the owned-by-`clone` rebinds for an ELEMENT sub-pattern (a head
/// position of a slice). Every variable / alias binder there is `&T` and is
/// cloned to `T`; nested tuple / constructor / record element patterns recurse.
pub fn collect_elem_rebinds(ctx: &EmitCtx, pat: &Pat, out: &mut String) -> DResult<()> {
    match pat {
        Pat::Var(s) => rebind_clone(ctx, *s, out),
        Pat::Alias(inner, name) => {
            rebind_clone(ctx, *name, out)?;
            collect_elem_rebinds(ctx, inner, out)
        }
        Pat::Tuple(subs) => {
            for sub in subs {
                collect_elem_rebinds(ctx, sub, out)?;
            }
            Ok(())
        }
        Pat::Ctor { args, .. } => {
            for sub in args {
                collect_elem_rebinds(ctx, sub, out)?;
            }
            Ok(())
        }
        Pat::Record(fields) => {
            for (_, sub) in fields {
                collect_elem_rebinds(ctx, sub, out)?;
            }
            Ok(())
        }
        // A wildcard / literal element binds nothing. A nested slice element is
        // gated at lowering (it never reaches the backend), so it needs no rebind.
        Pat::Wildcard
        | Pat::Int(_)
        | Pat::Bool(_)
        | Pat::Char(_)
        | Pat::Str(_)
        | Pat::Slice { .. } => Ok(()),
        // Every alternative binds the same names at the same types; rebind via
        // the first alternative.
        Pat::Or(alts) => alts
            .first()
            .map_or(Ok(()), |first| collect_elem_rebinds(ctx, first, out)),
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
        | Pat::Slice { .. } => Ok(()),
        // Every alternative binds the same names at the same types; rebind via
        // the first alternative.
        Pat::Or(alts) => alts
            .first()
            .map_or(Ok(()), |first| collect_list_rebinds(ctx, first, out)),
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
        // the Rust keyword constant; Char and Str escape via the `{:?}` Debug
        // form, which produces a valid Rust literal (quotes, backslashes and
        // control chars escaped) and is deterministic.
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
                (Some(ch), None) => Ok(format!("{ch:?}")),
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
        Pat::Str(s) => Ok(format!("{s:?}")),
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
        Pat::Ctor {
            home,
            ty,
            variant,
            args,
        } => {
            // A built-in `Maybe` / `Result` pattern routes to the runtime enum
            // path; otherwise it is a user enum resolved by `enum_name`.
            let path = match ctx.builtin_runtime_enum(home, *ty) {
                Some(runtime) => format!("{runtime}::{}", ctx.emit_ident(*variant)?),
                None => format!(
                    "{}::{}",
                    ctx.enum_name(home, *ty)?,
                    ctx.emit_ident(*variant)?
                ),
            };
            if args.is_empty() {
                Ok(path)
            } else {
                let mut subs = Vec::with_capacity(args.len());
                for sub in args {
                    subs.push(render_pat(ctx, sub)?);
                }
                Ok(format!("{path}({})", subs.join(", ")))
            }
        }
        Pat::Record(fields) => render_record_pat(ctx, fields),
        // A list / cons pattern renders as a native Rust slice pattern. A closed
        // (exact-length) pattern is `[p0, p1]`; an open cons tail is
        // `[p0, p1, rest @ ..]` (binding the rest) or `[p0, p1, ..]` (ignoring
        // it). The leading element patterns recurse through this same renderer.
        Pat::Slice { prefix, rest } => {
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
            let mut parts = Vec::with_capacity(alts.len());
            for alt in alts {
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
        Pat::Slice { prefix, rest } => {
            prefix.iter().any(pat_contains_alias_in_arm)
                || rest.as_deref().is_some_and(pat_contains_alias_in_arm)
        }
        // An or-pattern carries an alias iff any alternative does.
        Pat::Or(alts) => alts.iter().any(pat_contains_alias_in_arm),
        Pat::Var(_) | Pat::Wildcard | Pat::Int(_) | Pat::Bool(_) | Pat::Char(_) | Pat::Str(_) => {
            false
        }
    }
}

/// Render a BY-VALUE (whole-scrutinee, non-str, non-list) match-arm
/// sub-pattern, routing any [`Pat::Alias`] through the SAME "bind the whole,
/// destructure the inner shape from a CLONE" strategy
/// [`emit_binding_stmts`] already proves sound for irrefutable Destructure
/// positions — because in THIS context the scrutinee is matched BY VALUE
/// (never `&str`/`&[T]`), so `render_pat`'s `name @ inner` spelling (sound
/// only under a by-REF default binding mode) would double-move `name` and
/// `inner`'s own bindings for any non-`Copy` payload.
///
/// A subtree with no alias anywhere renders through the existing,
/// byte-identical [`render_pat`] (fast path — zero behavior change for the
/// overwhelmingly common alias-free case). `prelude` accumulates the `let`
/// statements that re-derive every aliased binder; the caller splices it
/// into the SAME prelude slot `emit_ctor_arm_pat`'s cyclic-self-edge
/// unboxing already uses (`unbox_lines`) or `emit_whole_arm_head`'s
/// `prelude` return.
#[allow(clippy::too_many_lines)] // one arm per IR pattern shape — a rendering table, not branching logic
pub fn render_arm_pat_alias_safe(
    ctx: &EmitCtx,
    pat: &Pat,
    counter: &mut usize,
    prelude: &mut String,
    guards: &mut Vec<String>,
) -> DResult<String> {
    // Fast path: no alias AND no by-value string-literal leaf → the plain,
    // byte-identical renderer. A `Pat::Str` in a by-value position would render
    // as a `&str` literal pattern against an owned `String` field (E0308), so
    // its presence forces the guard walk below even when there is no alias.
    // `pat_has_str_guard_slot` is the one classifier the lowerer's move gate
    // (`PartialMove::of_pattern`) shares, so a guard slot minted here is always
    // counted there as a move of its part.
    if !pat_contains_alias_in_arm(pat) && !pat_has_str_guard_slot(pat) {
        return render_pat(ctx, pat);
    }
    match pat {
        // A by-value string-literal column: Rust can't match an owned
        // `String` field against a `&str` literal pattern, so bind the field to a
        // fresh `__sgN` and emit an `if __sgN.as_str() == "lit"` match guard. The
        // caller ANDs the accumulated guards onto the arm — a false guard falls
        // through to the next arm, exactly matching the `case`'s literal-column
        // semantics. Mirrors the reference's `renderPatGuarded`.
        Pat::Str(s) => {
            let binder = format!("__sg{}", *counter);
            *counter += 1;
            guards.push(format!("{binder}.as_str() == {s:?}"));
            Ok(binder)
        }
        Pat::Alias(inner, _name) => {
            // IPE-L0128 (`gate_by_value_dispatch_needing_aliases`) guarantees
            // `inner` is dispatch-free by the time lowering succeeds; fail
            // closed rather than silently mis-emit if that invariant is ever
            // violated — never trust a backend-side "this can't happen"
            // silently.
            if !ipe_ir::is_dispatch_free(inner) {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::render_arm_pat_alias_safe",
                    detail: "alias over a dispatch-needing inner pattern reached the \
                             backend; IPE-L0128 should have rejected this at lowering"
                        .to_owned(),
                });
            }
            let temp = format!("__ipe_arm_alias_{}", *counter);
            *counter += 1;
            // `emit_binding_stmts` already handles
            // `Pat::Alias` exactly this way: `let <name> = <src>; let
            // <inner-pattern> = <name>.clone();` — reuse it verbatim, passing
            // the WHOLE alias node and the fresh temp as `src`.
            for stmt in emit_binding_stmts(ctx, pat, &temp)? {
                prelude.push_str(&stmt);
                prelude.push(' ');
            }
            Ok(temp)
        }
        Pat::Tuple(elems) => {
            let mut subs = Vec::with_capacity(elems.len());
            for e in elems {
                subs.push(render_arm_pat_alias_safe(ctx, e, counter, prelude, guards)?);
            }
            Ok(format!("({})", subs.join(", ")))
        }
        Pat::Ctor {
            home,
            ty,
            variant,
            args,
        } => {
            let path = match ctx.builtin_runtime_enum(home, *ty) {
                Some(runtime) => format!("{runtime}::{}", ctx.emit_ident(*variant)?),
                None => format!(
                    "{}::{}",
                    ctx.enum_name(home, *ty)?,
                    ctx.emit_ident(*variant)?
                ),
            };
            if args.is_empty() {
                Ok(path)
            } else {
                let mut subs = Vec::with_capacity(args.len());
                for a in args {
                    subs.push(render_arm_pat_alias_safe(ctx, a, counter, prelude, guards)?);
                }
                Ok(format!("{path}({})", subs.join(", ")))
            }
        }
        Pat::Record(fields) => {
            // Mirror [`render_record_pat`]'s struct-name resolution but
            // recurse sub-patterns through this alias-safe renderer instead
            // of the plain one.
            let mut key = Vec::with_capacity(fields.len());
            for (sym, _) in fields {
                key.push(ctx.resolve_ident(*sym)?.to_owned());
            }
            let struct_name = ctx.record_name_for_literal(&key, None)?.to_owned();
            let mut parts = Vec::with_capacity(fields.len());
            for (sym, sub) in fields {
                let field_ident = ctx.emit_ident(*sym)?;
                if let Pat::Var(var) = sub
                    && ctx.emit_ident(*var)? == field_ident
                {
                    parts.push(field_ident);
                } else {
                    let rendered = render_arm_pat_alias_safe(ctx, sub, counter, prelude, guards)?;
                    parts.push(format!("{field_ident}: {rendered}"));
                }
            }
            if parts.is_empty() {
                Ok(format!("{struct_name} {{ .. }}"))
            } else {
                Ok(format!("{struct_name} {{ {}, .. }}", parts.join(", ")))
            }
        }
        // A `Slice` carrying a nested alias reaches LIST mode, which matches
        // by reference and so needs no by-value alias-safety handling — this
        // by-VALUE renderer is never invoked from that path, so reaching here
        // is an internal invariant violation, not a real user program.
        Pat::Slice { .. } => Err(Diagnostic::CompilerBug {
            where_: "ipe_backend_rust::render_arm_pat_alias_safe",
            detail: "Pat::Slice reached the by-value alias-safe renderer; list-mode \
                     arms must route through render_pat directly"
                .to_owned(),
        }),
        // An or-pattern reaching the alias-safe body carries an alias or a
        // by-value string leaf inside SOME alternative. A per-alternative match
        // guard cannot attach to one branch of a Rust or-pattern, so a
        // string-literal alternative is the residual guarded-alternative case
        // (design §4.3) — fail closed rather than emit an invalid guarded
        // or-pattern. An alias-only or-pattern renders each alternative through
        // this same alias-safe renderer (its clone-split prelude binds the
        // shared names) and joins with ` | `.
        Pat::Or(alts) => {
            if alts.iter().any(pat_has_str_guard_slot) {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::render_arm_pat_alias_safe",
                    detail: "a by-value string-literal leaf inside an or-pattern \
                             alternative needs a per-alternative match guard, which \
                             a Rust or-pattern cannot carry; the lowerer's residual \
                             shared-continuation fallback should have handled it"
                        .to_owned(),
                });
            }
            let mut parts = Vec::with_capacity(alts.len());
            for alt in alts {
                parts.push(render_arm_pat_alias_safe(
                    ctx, alt, counter, prelude, guards,
                )?);
            }
            Ok(parts.join(" | "))
        }
        // `Pat::Str` is intercepted above (binder + guard); the remaining
        // leaves render directly.
        Pat::Var(_) | Pat::Wildcard | Pat::Int(_) | Pat::Bool(_) | Pat::Char(_) => {
            render_pat(ctx, pat)
        }
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
/// A destructure-position value is `Clone` — the derive-seal already
/// rejects any non-`Clone` payload upstream — so the clone always resolves.
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
pub fn render_record_pat(ctx: &EmitCtx, fields: &[(Symbol, Pat)]) -> DResult<String> {
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
    for (sym, sub) in fields {
        let field_ident = ctx.emit_ident(*sym)?;
        // Field-pun shorthand: `Rec { x, .. }` instead of `Rec { x: x, .. }`
        // (the latter trips rustc's `non_shorthand_field_patterns` lint). Only
        // when the sub-pattern is a variable whose emitted name equals the
        // field's emitted name.
        if let Pat::Var(var) = sub
            && ctx.emit_ident(*var)? == field_ident
        {
            parts.push(field_ident);
        } else {
            let rendered = render_pat(ctx, sub)?;
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
