//! AST walkers that produce the raw `AnnotatedToken` stream.
//!
//! Two walkers exist:
//!
//! * [`annotate_full`] — requires both the parse tree and the canonical AST;
//!   produces the richest classification (kernel, constructor, resolved def keys).
//! * [`annotate_syntax`] — parse tree only; produces coarser classification
//!   (`def` is always `None`, no kernel/constructor distinction).
//!
//! Both produce a sorted, deduplicated token stream.

use std::collections::BTreeMap;

use ipe_diagnostics::Span;
use ipe_intern::{Interner, Symbol};

use crate::{AnnotatedToken, DefKey, TokenClass};

// ---------------------------------------------------------------------------
// Internal raw token (before sorting / dedup)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct Raw {
    byte_start: u32,
    byte_len: u32,
    class: TokenClass,
    def: Option<DefKey>,
}

impl Raw {
    fn push(out: &mut Vec<Self>, span: Span, class: TokenClass, def: Option<DefKey>) {
        if span.lo >= span.hi {
            return;
        }
        out.push(Self {
            byte_start: span.lo,
            byte_len: span.hi - span.lo,
            class,
            def,
        });
    }

    fn keyword(out: &mut Vec<Self>, span: Span) {
        Self::push(out, span, TokenClass::Keyword, None);
    }

    fn operator(out: &mut Vec<Self>, span: Span) {
        Self::push(out, span, TokenClass::Operator, None);
    }
}

// ---------------------------------------------------------------------------
// Full annotate (parse + canon)
// ---------------------------------------------------------------------------

pub fn annotate_full(
    syntax: &ipe_syntax::Module,
    canon: &ipe_canon::ast::Module,
    interner: &Interner,
) -> Vec<AnnotatedToken> {
    let mut raw: Vec<Raw> = Vec::new();

    // Walk the canonical AST for semantically-classified tokens.
    canon_walk(&mut raw, syntax, canon, interner);

    finish(raw)
}

// ---------------------------------------------------------------------------
// Syntax-only annotate
// ---------------------------------------------------------------------------

pub fn annotate_syntax(syntax: &ipe_syntax::Module, interner: &Interner) -> Vec<AnnotatedToken> {
    let mut raw: Vec<Raw> = Vec::new();

    syntax_walk(&mut raw, syntax, interner);

    finish(raw)
}

// ---------------------------------------------------------------------------
// Shared finish: sort + dedup
// ---------------------------------------------------------------------------

fn finish(mut raw: Vec<Raw>) -> Vec<AnnotatedToken> {
    raw.sort_by_key(|r| r.byte_start);
    // First token at each byte_start wins; duplicates removed.
    raw.dedup_by_key(|r| r.byte_start);
    raw.into_iter()
        .map(|r| AnnotatedToken {
            byte_start: r.byte_start,
            byte_len: r.byte_len,
            class: r.class,
            def: r.def,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Canonical-AST walk
// ---------------------------------------------------------------------------

fn canon_walk(
    out: &mut Vec<Raw>,
    syntax: &ipe_syntax::Module,
    canon: &ipe_canon::ast::Module,
    interner: &Interner,
) {
    // Module keyword + name.
    Raw::keyword(out, syntax.module_kw);
    Raw::push(out, syntax.name.span, TokenClass::Module, None);

    // Imports — syntactic (canon AST does not retain import list post-resolution).
    for imp in &syntax.imports {
        Raw::keyword(out, imp.import_kw);
        Raw::push(out, imp.name.span, TokenClass::Module, None);
        push_exposing(out, &imp.exposing.value, interner);
    }

    // Union types — syntactic (canon carries unions with resolved ctors).
    for (syn_union, can_union) in syntax.unions.iter().zip(canon.unions.iter()) {
        Raw::keyword(out, syn_union.value.type_kw);
        Raw::push(out, syn_union.value.name.span, TokenClass::Type, None);
        for var in &syn_union.value.vars {
            Raw::push(out, var.span, TokenClass::TypeVar, None);
        }
        for (syn_ctor, can_ctor) in syn_union.value.ctors.iter().zip(can_union.ctors.iter()) {
            let name_len = interner.resolve(can_ctor.name).map_or(0, byte_len_u32);
            let ctor_span = Span::new(syn_ctor.span.lo, syn_ctor.span.lo + name_len);
            let def = resolve_sym(can_union.name, interner)
                .zip(resolve_sym(can_ctor.name, interner))
                .map(|(type_str, name_str)| DefKey::Constructor {
                    module: interner_join(&can_union.home, interner),
                    type_name: type_str,
                    name: name_str,
                });
            Raw::push(out, ctor_span, TokenClass::Constructor, def);
        }
    }

    // Value bindings — match each syntax value to its canonical def by name.
    //
    // Canon filters some syntax values out of `canon.defs` (a `Ffi.kernel` alias
    // binding leaves no ordinary def), so a positional pairing would attach the
    // wrong `DefKey` to every following value and silently drop the tail. Keying
    // by name pairs each value with its own def; a value with no matching def
    // (a kernel alias) is classified as a plain `Function` with no `DefKey`,
    // never mispaired with a neighbour's def.
    let defs_by_name: BTreeMap<Symbol, &ipe_canon::ast::Def> =
        canon.defs.iter().map(|d| (d.name().value, d)).collect();
    for syn_val in &syntax.values {
        let can_def = defs_by_name.get(&syn_val.value.name.value).copied();
        // The binding name itself — top-level Function; carry a DefKey::TopLevel
        // only when a canonical def backs this value.
        let def = can_def.and_then(|d| {
            resolve_sym(d.name().value, interner).map(|name_str| DefKey::TopLevel {
                module: interner_join(d.home(), interner),
                name: name_str,
            })
        });
        Raw::push(out, syn_val.value.name.span, TokenClass::Function, def);
        // Type annotation (syntactic spans not always available).
        if let Some(ann) = &syn_val.value.type_annotation {
            push_type_annotation(out, &ann.value);
        }
        // Parameter patterns.
        for pat in &syn_val.value.patterns {
            push_syn_pattern(out, pat, interner);
        }
        // Body expression — walk the canonical expr for semantic richness when a
        // canonical def exists; fall back to the syntax body for a value with no
        // def (a kernel alias) so its tokens are not dropped.
        match can_def {
            Some(
                ipe_canon::ast::Def::Untyped { body, .. } | ipe_canon::ast::Def::Typed { body, .. },
            ) => canon_expr(out, body, interner),
            None => push_syn_expr(out, &syn_val.value.body, interner),
        }
    }
}

/// Walk a canonical expression, emitting semantically-classified tokens.
// The length comes from the exhaustive match over all Expr_ variants; splitting
// it would obscure the structure without reducing complexity.
#[allow(clippy::too_many_lines)]
fn canon_expr(out: &mut Vec<Raw>, expr: &ipe_canon::ast::Expr, interner: &Interner) {
    use ipe_canon::ast::Expr_;
    match &expr.value {
        Expr_::VarLocal(_) => {
            Raw::push(out, expr.span, TokenClass::Variable, None);
        }
        Expr_::VarTopLevel { module, name } => {
            let def = resolve_sym(*name, interner).map(|name_str| DefKey::TopLevel {
                module: interner_join(module, interner),
                name: name_str,
            });
            Raw::push(out, expr.span, TokenClass::Function, def);
        }
        Expr_::VarKernel {
            id: _,
            module,
            name,
        } => {
            let def = resolve_sym(*module, interner)
                .zip(resolve_sym(*name, interner))
                .map(|(module_str, name_str)| DefKey::Kernel {
                    module: module_str,
                    name: name_str,
                });
            Raw::push(out, expr.span, TokenClass::Kernel, def);
        }
        Expr_::VarCtor {
            home,
            type_name,
            name,
            ..
        } => {
            let def = resolve_sym(*type_name, interner)
                .zip(resolve_sym(*name, interner))
                .map(|(type_str, name_str)| DefKey::Constructor {
                    module: interner_join(home, interner),
                    type_name: type_str,
                    name: name_str,
                });
            Raw::push(out, expr.span, TokenClass::Constructor, def);
        }
        Expr_::Int(_) | Expr_::Float(_) => {
            Raw::push(out, expr.span, TokenClass::Number, None);
        }
        Expr_::Str(_) | Expr_::Char(_) | Expr_::CustomElementCtor(_) => {
            Raw::push(out, expr.span, TokenClass::StringLit, None);
        }
        Expr_::Unit => {}
        Expr_::Call(f, args) => {
            canon_expr(out, f, interner);
            for a in args {
                canon_expr(out, a, interner);
            }
        }
        Expr_::ForeignCall { args, .. } => {
            for a in args {
                canon_expr(out, a, interner);
            }
        }
        Expr_::Case(scrutinee, branches) => {
            canon_expr(out, scrutinee, interner);
            for b in branches {
                canon_pattern(out, &b.pat, interner);
                canon_expr(out, &b.body, interner);
            }
        }
        Expr_::Lambda(params, body) => {
            for p in params {
                canon_pattern(out, p, interner);
            }
            canon_expr(out, body, interner);
        }
        Expr_::Binop {
            op: _,
            op_span,
            home,
            func,
            lhs,
            rhs,
        } => {
            // Use the exact lexer span of the operator glyph carried on the
            // node. Synthetic nodes (multiline-string desugar) carry a
            // zero-width span, which Raw::push drops — no token emitted.
            let def = resolve_sym(*home, interner)
                .zip(resolve_sym(*func, interner))
                .map(|(module_str, name_str)| DefKey::Kernel {
                    module: module_str,
                    name: name_str,
                });
            Raw::push(out, *op_span, TokenClass::Operator, def);
            canon_expr(out, lhs, interner);
            canon_expr(out, rhs, interner);
        }
        Expr_::Let(bindings, body) => {
            for b in &bindings[..] {
                canon_pattern(out, &b.pat, interner);
                canon_expr(out, &b.body, interner);
            }
            canon_expr(out, body, interner);
        }
        Expr_::If(branches, else_) => {
            for (cond, then_) in branches {
                canon_expr(out, cond, interner);
                canon_expr(out, then_, interner);
            }
            canon_expr(out, else_, interner);
        }
        Expr_::Tuple(elems) | Expr_::List(elems) => {
            for e in elems {
                canon_expr(out, e, interner);
            }
        }
        Expr_::Cons(h, t) => {
            canon_expr(out, h, interner);
            canon_expr(out, t, interner);
        }
        Expr_::Record(fields) => {
            for (_, v) in fields {
                canon_expr(out, v, interner);
            }
        }
        Expr_::Access(rec, _field) => {
            canon_expr(out, rec, interner);
        }
        Expr_::Update(base, fields) => {
            Raw::push(out, base.span, TokenClass::Variable, None);
            for (_, v) in fields {
                canon_expr(out, v, interner);
            }
        }
    }
}

/// Walk a canonical pattern, emitting semantically-classified tokens.
fn canon_pattern(out: &mut Vec<Raw>, pat: &ipe_canon::ast::Pattern, interner: &Interner) {
    use ipe_canon::ast::Pattern_;
    match &pat.value {
        Pattern_::PAnything | Pattern_::PDebugAnything | Pattern_::PUnit => {}
        Pattern_::PVar(_) => {
            Raw::push(out, pat.span, TokenClass::Variable, None);
        }
        Pattern_::PCtor {
            home,
            type_name,
            name,
            args,
            ..
        } => {
            let name_len = interner.resolve(*name).map_or(0, byte_len_u32);
            let ctor_span = Span::new(pat.span.lo, pat.span.lo + name_len);
            let def = resolve_sym(*type_name, interner)
                .zip(resolve_sym(*name, interner))
                .map(|(type_str, name_str)| DefKey::Constructor {
                    module: interner_join(home, interner),
                    type_name: type_str,
                    name: name_str,
                });
            Raw::push(out, ctor_span, TokenClass::Constructor, def);
            for a in args {
                canon_pattern(out, a, interner);
            }
        }
        Pattern_::PTuple(elems) | Pattern_::PList(elems) => {
            for e in elems {
                canon_pattern(out, e, interner);
            }
        }
        Pattern_::PRecord(fields) => {
            for f in fields {
                Raw::push(out, f.span, TokenClass::Variable, None);
            }
        }
        Pattern_::PInt(_) => {
            Raw::push(out, pat.span, TokenClass::Number, None);
        }
        Pattern_::PBool(_) => {
            Raw::push(out, pat.span, TokenClass::Constructor, None);
        }
        Pattern_::PChar(_) | Pattern_::PStr(_) => {
            Raw::push(out, pat.span, TokenClass::StringLit, None);
        }
        Pattern_::PAlias(inner, name) => {
            canon_pattern(out, inner, interner);
            Raw::push(out, name.span, TokenClass::Variable, None);
        }
        Pattern_::PCons(h, t) => {
            canon_pattern(out, h, interner);
            canon_pattern(out, t, interner);
        }
        Pattern_::POr(alts) => {
            for a in alts {
                canon_pattern(out, a, interner);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Syntax-only walk (parse tree, no canon)
// ---------------------------------------------------------------------------

fn syntax_walk(out: &mut Vec<Raw>, syntax: &ipe_syntax::Module, interner: &Interner) {
    Raw::keyword(out, syntax.module_kw);
    Raw::push(out, syntax.name.span, TokenClass::Module, None);

    for imp in &syntax.imports {
        Raw::keyword(out, imp.import_kw);
        Raw::push(out, imp.name.span, TokenClass::Module, None);
        push_exposing(out, &imp.exposing.value, interner);
    }

    for syn_union in &syntax.unions {
        Raw::keyword(out, syn_union.value.type_kw);
        Raw::push(out, syn_union.value.name.span, TokenClass::Type, None);
        for var in &syn_union.value.vars {
            Raw::push(out, var.span, TokenClass::TypeVar, None);
        }
        for ctor in &syn_union.value.ctors {
            let name_len = interner.resolve(ctor.value.name).map_or(0, byte_len_u32);
            let span = Span::new(ctor.span.lo, ctor.span.lo + name_len);
            Raw::push(out, span, TokenClass::Constructor, None);
        }
    }

    for syn_val in &syntax.values {
        Raw::push(out, syn_val.value.name.span, TokenClass::Function, None);
        if let Some(ann) = &syn_val.value.type_annotation {
            push_type_annotation(out, &ann.value);
        }
        for pat in &syn_val.value.patterns {
            push_syn_pattern(out, pat, interner);
        }
        push_syn_expr(out, &syn_val.value.body, interner);
    }
}

// ---------------------------------------------------------------------------
// Syntax-tree helpers (shared between full and syntax-only walkers)
// ---------------------------------------------------------------------------

fn push_exposing(out: &mut Vec<Raw>, exposing: &ipe_syntax::Exposing, _interner: &Interner) {
    match exposing {
        ipe_syntax::Exposing::All => {}
        ipe_syntax::Exposing::List(items) => {
            for item in items {
                match &item.value {
                    ipe_syntax::Exposed::Value(_) => {
                        Raw::push(out, item.span, TokenClass::Function, None);
                    }
                    ipe_syntax::Exposed::Type(_, _) => {
                        Raw::push(out, item.span, TokenClass::Type, None);
                    }
                }
            }
        }
    }
}

/// Type annotation spans are not fully tracked by the parser yet; this is a
/// named seam that gains richer output when span tracking lands.
const fn push_type_annotation(_out: &mut Vec<Raw>, _ty: &ipe_syntax::TypeAnnotation) {}

fn push_syn_pattern(out: &mut Vec<Raw>, pat: &ipe_syntax::Pattern, interner: &Interner) {
    match &pat.value {
        ipe_syntax::Pattern_::PAnything
        | ipe_syntax::Pattern_::PDebugAnything
        | ipe_syntax::Pattern_::PUnit => {}
        ipe_syntax::Pattern_::PVar(_) => {
            Raw::push(out, pat.span, TokenClass::Variable, None);
        }
        ipe_syntax::Pattern_::PCtor(name, _segs, args) => {
            let name_len = interner.resolve(*name).map_or(0, byte_len_u32);
            let span = Span::new(pat.span.lo, pat.span.lo + name_len);
            Raw::push(out, span, TokenClass::Constructor, None);
            for a in args {
                push_syn_pattern(out, a, interner);
            }
        }
        ipe_syntax::Pattern_::PTuple(elems) | ipe_syntax::Pattern_::PList(elems) => {
            for e in elems {
                push_syn_pattern(out, e, interner);
            }
        }
        ipe_syntax::Pattern_::PRecord(fields) => {
            for f in fields {
                Raw::push(out, f.span, TokenClass::Variable, None);
            }
        }
        ipe_syntax::Pattern_::PInt(_) => {
            Raw::push(out, pat.span, TokenClass::Number, None);
        }
        ipe_syntax::Pattern_::PBool(_) => {
            Raw::push(out, pat.span, TokenClass::Constructor, None);
        }
        ipe_syntax::Pattern_::PChar(_) | ipe_syntax::Pattern_::PStr(_) => {
            Raw::push(out, pat.span, TokenClass::StringLit, None);
        }
        ipe_syntax::Pattern_::PAlias(inner, name) => {
            push_syn_pattern(out, inner, interner);
            Raw::push(out, name.span, TokenClass::Variable, None);
        }
        ipe_syntax::Pattern_::PCons(h, t) => {
            push_syn_pattern(out, h, interner);
            push_syn_pattern(out, t, interner);
        }
        ipe_syntax::Pattern_::POr(alts) => {
            for a in alts {
                push_syn_pattern(out, a, interner);
            }
        }
    }
}

fn push_syn_expr(out: &mut Vec<Raw>, expr: &ipe_syntax::Expr, interner: &Interner) {
    match &expr.value {
        ipe_syntax::Expr_::VarLocal(_) => {
            Raw::push(out, expr.span, TokenClass::Variable, None);
        }
        ipe_syntax::Expr_::VarQual(_, _) => {
            Raw::push(out, expr.span, TokenClass::Function, None);
        }
        ipe_syntax::Expr_::Int(_) | ipe_syntax::Expr_::Float(_) => {
            Raw::push(out, expr.span, TokenClass::Number, None);
        }
        ipe_syntax::Expr_::Str(_)
        | ipe_syntax::Expr_::MultilineStr { .. }
        | ipe_syntax::Expr_::Char(_) => {
            Raw::push(out, expr.span, TokenClass::StringLit, None);
        }
        ipe_syntax::Expr_::Unit => {}
        ipe_syntax::Expr_::Call(f, args) => {
            push_syn_expr(out, f, interner);
            for a in args {
                push_syn_expr(out, a, interner);
            }
        }
        ipe_syntax::Expr_::Binops(pairs, last) => {
            for (lhs, op) in pairs {
                push_syn_expr(out, lhs, interner);
                Raw::operator(out, op.span);
            }
            push_syn_expr(out, last, interner);
        }
        ipe_syntax::Expr_::Lambda(params, body) => {
            for p in params {
                push_syn_pattern(out, p, interner);
            }
            push_syn_expr(out, body, interner);
        }
        ipe_syntax::Expr_::Let(bindings, body) => {
            for b in bindings {
                push_syn_pattern(out, &b.pat, interner);
                push_syn_expr(out, &b.body, interner);
            }
            push_syn_expr(out, body, interner);
        }
        ipe_syntax::Expr_::If(branches, else_) => {
            for (cond, then_) in branches {
                push_syn_expr(out, cond, interner);
                push_syn_expr(out, then_, interner);
            }
            push_syn_expr(out, else_, interner);
        }
        ipe_syntax::Expr_::Case(scrutinee, branches) => {
            push_syn_expr(out, scrutinee, interner);
            for (pat, body) in branches {
                push_syn_pattern(out, pat, interner);
                push_syn_expr(out, body, interner);
            }
        }
        ipe_syntax::Expr_::Tuple(elems) | ipe_syntax::Expr_::List(elems) => {
            for e in elems {
                push_syn_expr(out, e, interner);
            }
        }
        ipe_syntax::Expr_::Record(fields) => {
            for (name, val) in fields {
                Raw::push(out, name.span, TokenClass::Variable, None);
                push_syn_expr(out, val, interner);
            }
        }
        ipe_syntax::Expr_::Access(rec, field) => {
            push_syn_expr(out, rec, interner);
            Raw::push(out, field.span, TokenClass::Variable, None);
        }
        ipe_syntax::Expr_::Update(base, fields) => {
            // `base` is a `Located<Symbol>` (bare variable name).
            Raw::push(out, base.span, TokenClass::Variable, None);
            for (name, val) in fields {
                Raw::push(out, name.span, TokenClass::Variable, None);
                push_syn_expr(out, val, interner);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

fn byte_len_u32(s: &str) -> u32 {
    u32::try_from(s.len()).unwrap_or(u32::MAX)
}

fn interner_join(syms: &[Symbol], interner: &Interner) -> String {
    syms.iter()
        .map(|s| interner.resolve(*s).unwrap_or("?"))
        .collect::<Vec<_>>()
        .join(".")
}

/// Resolve a single symbol to an owned `String`, returning `None` when the
/// symbol is not present in `interner`.  A `None` result means the symbol
/// does not belong to this interner — an internal-consistency bug.  Callers
/// treat `None` as "emit no `def`" rather than forging an empty key.
fn resolve_sym(sym: Symbol, interner: &Interner) -> Option<String> {
    interner.resolve(sym).map(str::to_owned)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ipe_intern::Interner;
    use ipe_parse::parse_module;

    fn parse(src: &str) -> (ipe_syntax::Module, Interner) {
        let mut i = Interner::default();
        let m = parse_module(src, &mut i).expect("parse");
        (m, i)
    }

    #[test]
    fn finish_sorts_and_deduplicates() {
        let raw = vec![
            Raw {
                byte_start: 10,
                byte_len: 3,
                class: TokenClass::Keyword,
                def: None,
            },
            Raw {
                byte_start: 0,
                byte_len: 6,
                class: TokenClass::Keyword,
                def: None,
            },
            Raw {
                byte_start: 0,
                byte_len: 6,
                class: TokenClass::Module,
                def: None,
            },
        ];
        let result = finish(raw);
        assert_eq!(result.len(), 2, "dedup removes second token at byte 0");
        let first = result.first().expect("first token");
        let second = result.get(1).expect("second token");
        assert_eq!(first.byte_start, 0);
        assert_eq!(second.byte_start, 10);
        // First occurrence at byte 0 wins — Keyword.
        assert_eq!(first.class, TokenClass::Keyword);
    }

    #[test]
    fn syntax_walk_produces_tokens_for_valid_module() {
        let src = "module Main exposing (main)\n\nmain : Int\nmain =\n    42\n";
        let (syntax, interner) = parse(src);
        let tokens = annotate_syntax(&syntax, &interner);
        assert!(!tokens.is_empty(), "syntax walk produces tokens");
    }

    /// Keyword spans come from the lexer, not substring scans.
    ///
    /// A leading line comment contains the word "module"; the scanner approach
    /// would match inside the comment.  The lexer-span approach emits a keyword
    /// token only at the real keyword position.
    #[test]
    fn keyword_spans_are_exact_not_from_comment() {
        // "-- module comment\nmodule Main exposing (..)\n"
        // The real `module` keyword starts at byte 19.
        let src = "-- module comment\nmodule Main exposing (..)\n";
        let (syntax, interner) = parse(src);
        let tokens = annotate_syntax(&syntax, &interner);
        let kw = tokens
            .iter()
            .find(|t| t.class == TokenClass::Keyword)
            .expect("at least one keyword token");
        // The real keyword is at byte 18 (after the newline), not byte 3 inside the comment.
        assert!(
            kw.byte_start >= 18,
            "keyword token must be at the real `module` span (byte >= 18), got {}",
            kw.byte_start
        );
    }

    /// A `type` declaration preceded by a comment longer than 64 bytes must
    /// still produce a keyword token at the correct span.
    #[test]
    fn type_kw_span_survives_long_comment() {
        // Construct a comment that is > 64 bytes, then a `type` declaration.
        let long_comment = "-- ".to_owned() + &"x".repeat(70) + "\n";
        let src = format!("module Main exposing (..)\n\n{long_comment}type Color = Red | Blue\n");
        let (syntax, interner) = parse(&src);
        let tokens = annotate_syntax(&syntax, &interner);
        let type_kw = tokens
            .iter()
            .find(|t| {
                t.class == TokenClass::Keyword
                    && src.get(t.byte_start as usize..(t.byte_start + t.byte_len) as usize)
                        == Some("type")
            })
            .expect("a `type` keyword token must be present");
        let lexed =
            &src[type_kw.byte_start as usize..(type_kw.byte_start + type_kw.byte_len) as usize];
        assert_eq!(lexed, "type");
    }

    // Build an untyped canonical def whose body is a bare unit, so it can stand
    // in for a real value binding without materialising an expression tree.
    fn unit_def(name: Symbol, home: &[Symbol]) -> ipe_canon::ast::Def {
        ipe_canon::ast::Def::Untyped {
            home: home.to_vec(),
            name: ipe_diagnostics::Located::new(Span::new(0, 0), name),
            patterns: Vec::new(),
            body: ipe_diagnostics::Located::new(Span::new(0, 0), ipe_canon::ast::Expr_::Unit),
        }
    }

    // Regression for the positional-zip mispairing: canon filters a kernel-alias
    // binding out of `canon.defs`, so a value's DefKey must be resolved by NAME,
    // never by position. Here `aliased` is present in syntax but absent from
    // `canon.defs`; a positional zip would attach `aliased`'s slot to `first`
    // and drop `second` entirely.
    #[test]
    fn full_walk_pairs_defs_by_name_across_a_filtered_alias() {
        let src = concat!(
            "module Main exposing (first, second)\n\n",
            "aliased : Int\n",
            "aliased =\n    Kernel.kernel\n\n",
            "first : Int\n",
            "first =\n    1\n\n",
            "second : Int\n",
            "second =\n    2\n",
        );
        let (syntax, mut interner) = parse(src);
        let home = vec![interner.intern("Main").expect("intern Main")];
        let first_sym = interner.intern("first").expect("intern first");
        let second_sym = interner.intern("second").expect("intern second");

        // canon.defs OMITS `aliased` (the filtered kernel alias), keeping only
        // the two ordinary values — the exact shape canon produces.
        let canon = ipe_canon::ast::Module {
            name: home.clone(),
            unions: Vec::new(),
            defs: vec![unit_def(first_sym, &home), unit_def(second_sym, &home)],
            imports_unsafe_submodule: false,
            imported_web_capabilities: std::collections::BTreeSet::default(),
        };

        let tokens = annotate_full(&syntax, &canon, &interner);

        // Resolve a value's name token (by source byte offset) to the top-level
        // name its DefKey carries, or `None` when it has no top-level DefKey.
        let top_level_name = |needle: &str| -> Option<String> {
            let off = u32::try_from(src.find(&format!("{needle} =")).expect("value in source"))
                .expect("offset fits u32");
            tokens
                .iter()
                .find(|t| t.byte_start == off && t.class == TokenClass::Function)
                .and_then(|t| t.def.clone())
                .and_then(|def| match def {
                    DefKey::TopLevel { name, .. } => Some(name),
                    _ => None,
                })
        };

        // Each value keys to its OWN def, never a neighbour's — the property a
        // positional zip violates once the filtered alias shifts every pairing.
        assert_eq!(top_level_name("first").as_deref(), Some("first"));
        assert_eq!(top_level_name("second").as_deref(), Some("second"));
        // The filtered alias has no canonical def: it is a plain Function token
        // with no DefKey, never borrowing a neighbour's key.
        assert!(
            top_level_name("aliased").is_none(),
            "a value with no canonical def carries no DefKey"
        );
    }
}
