//! `unused-imports` — an import declaration whose bound names never appear in
//! the module body.
//!
//! An import introduces names in two ways:
//! 1. Module qualifiers — the spellings [`ipe_canon::import_qualifier_forms`]
//!    registers (the `as Alias` alias, or the last path segment plus the full
//!    dotted path), plus the canonical qualifier a bare stdlib import also
//!    answers to ([`ipe_canon::stdlib_canonical_qualifier`]). A qualifier
//!    appears in `VarQual` and as the qualifier of a `TType` annotation.
//! 2. Explicitly exposed names: `import Foo exposing (bar, Baz, Shape(Circle))`
//!    binds each name, and each listed constructor, unqualified.
//!
//! Every uncertain case counts as a use, so the rule never flags an import that
//! might be needed: an `exposing (..)` wildcard, an exposed `Type(..)` (its
//! constructor set is unknown at the parse level), a name re-exported by the
//! module's own `exposing` clause, and any module whose references are not all
//! visible in the parse tree (a triple-quoted string that interpolates, whose
//! `{{…}}` bodies the canonicaliser resolves from raw text).
//!
//! The fix deletes the declaration's whole lines: the parser-recorded
//! [`Import::span`] already covers the keyword through the last clause's last
//! token, comments and all, so nothing further needs re-deriving from the raw
//! text. The fix exists only when that deletion is provably confined to the
//! import — nothing but whitespace shares its first and last lines. Otherwise
//! the finding is reported without a fix.

use std::collections::HashSet;

use ipe_canon::{QualifierForm, import_qualifier_forms, stdlib_canonical_qualifier};
use ipe_diagnostics::Span;
use ipe_intern::{Interner, Symbol};
use ipe_syntax::{
    Exposed, Exposing, Expr, Expr_, Import, Module, Pattern, Pattern_, Privacy, TypeAnnotation,
};

use crate::finding::{Finding, Fix};
use crate::rules::Ctx;

/// The rule's stable name.
pub const RULE: &str = "unused-imports";

pub fn check(ctx: &Ctx) -> Vec<Finding> {
    let uses = Uses::of_module(ctx.ast);
    if uses.opaque {
        return Vec::new();
    }
    let qualifiers: HashSet<&str> = uses
        .qualifiers
        .iter()
        .filter_map(|s| ctx.interner.resolve(*s))
        .filter(|q| !q.is_empty())
        .collect();

    ctx.ast
        .imports
        .iter()
        .filter(|import| {
            !is_used(ctx.interner, import, &|q| qualifiers.contains(q), &|s| {
                uses.unqualified.contains(&s)
            })
        })
        .map(|import| finding(ctx, import))
        .collect()
}

/// Whether any name some import in `imports` binds may be referenced in
/// `ast`.
///
/// The usage walk is re-run on `ast` itself, so a caller that removed
/// `imports` from a module can re-prove on its *output* that nothing they
/// bound is still referenced. `imports` resolve through `import_interner`,
/// `ast` through `interner`; the two may differ, so names compare as text.
/// Fail-closed: an opaque module, an unresolvable symbol, a wildcard, or an
/// exposed `Type(..)` all count as referenced. An empty `imports` binds
/// nothing, so it is never referenced — even in an opaque module.
pub fn any_referenced(
    ast: &Module,
    interner: &Interner,
    imports: &[&Import],
    import_interner: &Interner,
) -> bool {
    if imports.is_empty() {
        return false;
    }
    let uses = Uses::of_module(ast);
    if uses.opaque {
        return true;
    }
    let texts = |syms: &HashSet<Symbol>| -> Option<HashSet<String>> {
        syms.iter()
            .map(|s| interner.resolve(*s).map(str::to_owned))
            .collect()
    };
    let (Some(qualifiers), Some(unqualified)) = (texts(&uses.qualifiers), texts(&uses.unqualified))
    else {
        return true;
    };
    imports.iter().any(|import| {
        is_used(import_interner, import, &|q| qualifiers.contains(q), &|s| {
            import_interner
                .resolve(s)
                .is_none_or(|t| unqualified.contains(t))
        })
    })
}

/// The finding for one unused import, with a fix only when its removal is clean.
fn finding(ctx: &Ctx, import: &Import) -> Finding {
    let module_text: String = import
        .name
        .value
        .iter()
        .map(|s| ctx.text(*s))
        .collect::<Vec<_>>()
        .join(".");
    let message = format!("`import {module_text}` is never used in this module");
    let help = vec![
        "remove the import or add an `exposing` clause for the names you need".to_owned(),
        "suppress: `-- ipe-lint: allow unused-imports`".to_owned(),
    ];
    match removal_range(ctx.source, import) {
        Some((lo, hi)) => ctx.with_fix(
            RULE,
            import.span,
            message,
            help,
            Fix {
                describe: "remove unused import".to_owned(),
                span: Span::new(byte_to_u32(lo), byte_to_u32(hi)),
                replacement: String::new(),
            },
        ),
        None => ctx.advisory(RULE, import.span, message, help),
    }
}

/// Whether any name `import` binds may be referenced.
///
/// Fail-closed: an unresolvable symbol, a wildcard, or an exposed `Type(..)`
/// all count as used.
///
/// `qualifier_used` answers for a qualifier spelling, `name_used` for an
/// unqualified name symbol of `interner`.
fn is_used(
    interner: &Interner,
    import: &Import,
    qualifier_used: &impl Fn(&str) -> bool,
    name_used: &impl Fn(Symbol) -> bool,
) -> bool {
    let Exposing::List(items) = &import.exposing.value else {
        return true;
    };
    if items
        .iter()
        .any(|item| exposed_is_used(&item.value, name_used))
    {
        return true;
    }
    import_qualifier_texts(interner, import)
        .is_none_or(|texts| texts.iter().any(|text| qualifier_used(text.as_str())))
}

/// Whether one exposed item may be referenced unqualified.
fn exposed_is_used(item: &Exposed, name_used: &impl Fn(Symbol) -> bool) -> bool {
    match item {
        Exposed::Value(name) | Exposed::Type(name, Privacy::Private) => name_used(*name),
        Exposed::Type(_, Privacy::Public) => true,
        Exposed::Type(name, Privacy::PublicCtors(ctors)) => {
            name_used(*name) || ctors.iter().any(|c| name_used(*c))
        }
    }
}

/// Every qualifier spelling under which `import` is reachable.
///
/// The resolver's own forms ([`import_qualifier_forms`]) plus, for a bare
/// import, the canonical stdlib qualifier. `None` when a symbol does not
/// resolve; the caller then treats the import as used.
pub fn import_qualifier_texts(interner: &Interner, import: &Import) -> Option<Vec<String>> {
    let segs: Vec<&str> = import
        .name
        .value
        .iter()
        .map(|s| interner.resolve(*s))
        .collect::<Option<_>>()?;
    let alias = match import.alias {
        Some(a) => Some(interner.resolve(a)?),
        None => None,
    };
    let mut texts = Vec::new();
    for form in import_qualifier_forms(alias.is_some(), segs.len()) {
        let text = match form {
            QualifierForm::Alias => alias?.to_owned(),
            QualifierForm::LastSegment => (*segs.last()?).to_owned(),
            QualifierForm::DottedPath => segs.join("."),
        };
        texts.push(text);
    }
    if alias.is_none()
        && let Some(canonical) = stdlib_canonical_qualifier(&segs)
    {
        texts.push(canonical.to_owned());
    }
    Some(texts)
}

/// The byte range whose deletion removes `import` and nothing else.
///
/// The range is the declaration's full lines: from the start of the `import`
/// keyword's line through the newline ending the line of its last token. The
/// endpoints come straight from the parser-recorded `import.span` — which
/// already covers any comment nested inside the declaration (a `--` or
/// `{- -}` between clauses parses as part of the same span, never as a false
/// terminator) — so no further text re-scan is needed to trust them. The
/// range exists only when that span begins with the keyword and only
/// whitespace shares those first and last lines; `None` is the refusal.
pub fn removal_range(text: &str, import: &Import) -> Option<(usize, usize)> {
    let lo = import.span.lo as usize;
    let hi = import.span.hi as usize;
    let body = text.get(lo..hi)?;
    if !body.starts_with("import") {
        return None;
    }
    let start = line_start(text, lo);
    let end = line_end(text, hi);
    let blank = |s: Option<&str>| s.is_some_and(|s| s.chars().all(char::is_whitespace));
    (blank(text.get(start..lo)) && blank(text.get(hi..end))).then_some((start, end))
}

/// Every name a module body may reference.
#[derive(Default)]
struct Uses {
    /// Qualifier symbols of `VarQual` and qualified `TType` references.
    qualifiers: HashSet<Symbol>,
    /// Unqualified names: values, binders, constructors, types, operators and
    /// re-exports.
    unqualified: HashSet<Symbol>,
    /// Whether some reference is invisible to this walk.
    ///
    /// Set by an interpolating triple-quoted string or a module-qualified
    /// constructor pattern; the rule then reports nothing for the module.
    opaque: bool,
}

impl Uses {
    /// Collect every reference in `ast` outside its import list.
    fn of_module(ast: &Module) -> Self {
        let mut uses = Self::default();
        for value in &ast.values {
            for p in &value.value.patterns {
                uses.pattern(p);
            }
            uses.expr(&value.value.body);
            if let Some(ann) = &value.value.type_annotation {
                uses.ty(&ann.value);
            }
        }
        for union in &ast.unions {
            for ctor in &union.value.ctors {
                for arg in &ctor.value.args {
                    uses.ty(arg);
                }
            }
        }
        for alias in &ast.aliases {
            uses.ty(&alias.value.body.value);
        }
        for foreign in &ast.foreigns {
            uses.expr(&foreign.value.body);
            if let Some(ann) = &foreign.value.type_annotation {
                uses.ty(&ann.value);
            }
        }
        // Re-exports: a name in the module's own `exposing` list may come from
        // an import, so it counts as used.
        if let Exposing::List(items) = &ast.exposing.value {
            for item in items {
                match &item.value {
                    Exposed::Value(s) | Exposed::Type(s, _) => {
                        uses.unqualified.insert(*s);
                    }
                }
            }
        }
        uses
    }

    fn expr(&mut self, expr: &Expr) {
        match &expr.value {
            Expr_::VarLocal(sym) => {
                self.unqualified.insert(*sym);
            }
            Expr_::VarQual(qualifier, _) => {
                self.qualifiers.insert(*qualifier);
            }
            Expr_::Call(callee, args) => {
                self.expr(callee);
                for arg in args {
                    self.expr(arg);
                }
            }
            Expr_::Case(scrut, arms) => {
                self.expr(scrut);
                for (pat, body) in arms {
                    self.pattern(pat);
                    self.expr(body);
                }
            }
            Expr_::Lambda(pats, body) => {
                for p in pats {
                    self.pattern(p);
                }
                self.expr(body);
            }
            Expr_::Binops(pairs, last) => {
                for (e, op) in pairs {
                    self.expr(e);
                    self.unqualified.insert(op.value);
                }
                self.expr(last);
            }
            Expr_::Let(bindings, body) => {
                for b in bindings {
                    self.pattern(&b.pat);
                    self.expr(&b.body);
                }
                self.expr(body);
            }
            Expr_::If(branches, otherwise) => {
                for (cond, then_) in branches {
                    self.expr(cond);
                    self.expr(then_);
                }
                self.expr(otherwise);
            }
            Expr_::Tuple(elems) | Expr_::List(elems) => {
                for e in elems {
                    self.expr(e);
                }
            }
            Expr_::Record(fields) => {
                for (_, v) in fields {
                    self.expr(v);
                }
            }
            // The update base is a bare variable name: a use of that name.
            Expr_::Update(base, fields) => {
                self.unqualified.insert(base.value);
                for (_, v) in fields {
                    self.expr(v);
                }
            }
            Expr_::Access(rec, _) => self.expr(rec),
            Expr_::MultilineStr { raw, .. } => {
                if raw.contains("{{") {
                    self.opaque = true;
                }
            }
            Expr_::Int(_) | Expr_::Float(_) | Expr_::Str(_) | Expr_::Char(_) | Expr_::Unit => {}
        }
    }

    fn pattern(&mut self, pat: &Pattern) {
        match &pat.value {
            Pattern_::PCtor(name, module_segs, sub_pats) => {
                self.unqualified.insert(*name);
                if !module_segs.is_empty() {
                    self.opaque = true;
                }
                for sp in sub_pats {
                    self.pattern(sp);
                }
            }
            Pattern_::PTuple(ps) | Pattern_::PList(ps) | Pattern_::POr(ps) => {
                for p in ps {
                    self.pattern(p);
                }
            }
            Pattern_::PCons(h, t) => {
                self.pattern(h);
                self.pattern(t);
            }
            Pattern_::PVar(sym) => {
                self.unqualified.insert(*sym);
            }
            Pattern_::PAlias(inner, _) => self.pattern(inner),
            Pattern_::PRecord(_)
            | Pattern_::PAnything
            | Pattern_::PDebugAnything
            | Pattern_::PUnit
            | Pattern_::PInt(_)
            | Pattern_::PBool(_)
            | Pattern_::PStr(_)
            | Pattern_::PChar(_) => {}
        }
    }

    fn ty(&mut self, ann: &TypeAnnotation) {
        match ann {
            TypeAnnotation::TLambda(a, b) => {
                self.ty(a);
                self.ty(b);
            }
            TypeAnnotation::TVar(_) | TypeAnnotation::TUnit => {}
            TypeAnnotation::TType(qualifier, segments, args) => {
                self.qualifiers.insert(*qualifier);
                self.unqualified.extend(segments.iter().copied());
                for arg in args {
                    self.ty(arg);
                }
            }
            TypeAnnotation::TTuple(ts) => {
                for t in ts {
                    self.ty(t);
                }
            }
            TypeAnnotation::TRecord(fields) | TypeAnnotation::TRecordOpen(_, fields) => {
                for (_, t) in fields {
                    self.ty(t);
                }
            }
        }
    }
}

/// The byte offset of the start of the line containing byte offset `at`.
///
/// `at` is clamped to `text.len()` and need not be a char boundary: the scan is
/// over bytes for the ASCII `\n`, so the result is always a char boundary.
pub fn line_start(text: &str, at: usize) -> usize {
    let at = at.min(text.len());
    text.as_bytes()
        .get(..at)
        .and_then(|s| s.iter().rposition(|&b| b == b'\n'))
        .map_or(0, |i| i + 1)
}

/// The byte offset just past the newline ending the line containing `at`.
///
/// Covers any `\r` before the `\n`, so deleting `line_start(at)..line_end(at)`
/// removes the whole physical line. Returns `text.len()` on an unterminated
/// last line.
pub fn line_end(text: &str, at: usize) -> usize {
    let at = at.min(text.len());
    text.as_bytes()
        .get(at..)
        .and_then(|s| s.iter().position(|&b| b == b'\n'))
        .map_or(text.len(), |i| at + i + 1)
}

/// Lossless `usize -> u32` for a byte offset within a real source file.
///
/// Saturates rather than panics on the unreachable overflow case.
fn byte_to_u32(x: usize) -> u32 {
    u32::try_from(x).unwrap_or(u32::MAX)
}
