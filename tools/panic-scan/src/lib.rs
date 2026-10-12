//! Syntax-tree scanner for Rust abrupt-failure constructs.
//!
//! It parses with `syn`, so a construct named inside a string literal or a
//! comment is invisible and a construct split across lines (`panic!\n(…)`,
//! `obj.\nunwrap()`) is still found. Test-only exemption is decided per syntax
//! node: a test-only `#[cfg(…)]` exempts exactly the item, arm, field,
//! statement, or expression it decorates and never reaches a sibling, so a
//! `,` or `;` can never carry the exemption past its node. A bare `#[test]`
//! exempts nothing: it names a shadowable attribute macro, not a cfg, so its
//! function compiles into production unless a `cfg(test)` scope encloses it.
//! An exemption or ban is never keyed on a name the program can rebind: a
//! renamed `process` module or `std` crate root is itself a hit. Macro bodies have no
//! syntax tree; their tokens are scanned flat, where a test-only attribute
//! exempts only a whole item it parses as, and a callee the macro's caller
//! names (`process::$f`, `$m::$f`, `.$m()`, `$m!()`, a `$( … )` path prefix
//! before a banned leaf) is a hit, since it can expand to a banned call the
//! body never spells.
//!
//! Scope: it finds every *authored, syntax-detectable* abrupt-failure construct.
//! Indexing (`a[i]`) and arithmetic overflow are deliberately out of scope —
//! they are not distinct constructs and are covered by clippy
//! (`indexing_slicing`, `arithmetic_side_effects`). Standard-library
//! precondition panics (`split_at`, `borrow_mut`, …) are not authored
//! constructs and cannot be found this way; they are the documented "no
//! *authored* panic" boundary.

use proc_macro2::{Delimiter, Ident, TokenStream, TokenTree};
use syn::ext::IdentExt;
use syn::visit::{self, Visit};
use syn::{
    Arm, Attribute, Expr, ExprLit, ExprMethodCall, ExprPath, Field, FieldValue, ForeignItem,
    ImplItem, Item, ItemExternCrate, ItemMod, ItemUse, Lit, LitStr, Local, Macro, MacroDelimiter,
    Meta, MetaList, Pat, Path, StmtMacro, TraitItem, Type, TypeParamBound, UseTree, Variant,
    Visibility,
};

mod bounded;
mod includes;
mod manifest;
mod test_lines;
mod test_path;

pub use bounded::{
    Measure, NestDepth, ParseStack, ScanError, SourceBytes, SourceReadError, TokenCeiling, measure,
    read_source, with_parsed, with_parsed_on,
};
pub use includes::{
    IncludeForm, IncludeTarget, IncludedSource, PathRefusal, TestPathInclude, judge_literal,
};
pub use manifest::{ManifestError, ManifestTargets, parse_manifest};
pub use test_lines::test_only_item_lines;
pub use test_path::{
    TestPathError, UngatedBy, check_manifest, check_test_path, is_template_path, is_test_path,
    is_verified_test_path,
};

/// Panic-invoking macros (each may be invoked with `()`, `[]`, or `{}`).
const MACROS: &[&str] = &[
    "panic",
    "unreachable",
    "todo",
    "unimplemented",
    "assert",
    "assert_eq",
    "assert_ne",
    "debug_assert",
    "debug_assert_eq",
    "debug_assert_ne",
    "assert_matches",
    "debug_assert_matches",
];

/// Panicking (or UB) methods: `x.unwrap()`, `x.expect(..)`, …
const METHODS: &[&str] = &[
    "unwrap",
    "expect",
    "unwrap_err",
    "expect_err",
    "unwrap_unchecked",
];

/// Free functions that abort/panic: `panic_any(..)`, `unreachable_unchecked()`.
const FNS: &[&str] = &["panic_any", "unreachable_unchecked"];

/// `process::abort` (panic-free hard abort) and `process::exit` (boundary-only).
const PROCESS_FNS: &[&str] = &["abort", "exit"];

/// The per-site sanction marker.
///
/// A hit is suppressed when this exact text appears on the hit line itself, or on the contiguous run of comment/attribute
/// lines directly above it — the annotation block *attached to that construct*.
/// The block ends at the first line above that is neither a comment (`//`,
/// `///`, `//!`) nor an attribute (`#[ … ]`): a marker on a preceding *code*
/// statement is not part of the construct's annotation and never suppresses it.
/// The marker lives in a comment; the lexer drops comments, so the suppression
/// is applied against the *raw source lines*, not the token stream. This is
/// deliberately per-site and explicit: an unannotated new construct still fails,
/// and a marker written for an earlier statement cannot blanket the constructs
/// beneath it, so the gate is never weakened.
pub const AUDIT_MARKER: &str = "IPE-RUST-AUDIT:ACCEPTED";

/// One flagged construct: its 1-based source line and a short token label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub line: usize,
    pub tok: String,
}

/// Attribute naming a module's source file.
const PATH_ATTR: &str = "path";

/// Attribute applying other attributes under a `cfg` predicate.
const CFG_ATTR: &str = "cfg_attr";

/// Macro compiling another file's tokens in place.
const INCLUDE_MACRO: &str = "include";

/// Module holding [`PROCESS_FNS`].
const PROCESS_MODULE: &str = "process";

/// Crate root that holds [`PROCESS_MODULE`].
const STD_CRATE: &str = "std";

/// Directory name of test code a production module must never declare.
const TESTS_MODULE: &str = "tests";

/// Scan Rust source, returning every unsanctioned production-region hit.
///
/// Test-only nodes are skipped: this scanner attests the *production* surface.
/// A node is test-only when a `#[cfg(…)]` whose predicate is guaranteed active
/// only under the `test` cfg decorates it.
///
/// # Errors
///
/// [`ScanError`] when `src` is over a ceiling or does not parse as a Rust file.
pub fn scan_str(src: &str) -> Result<Vec<Hit>, ScanError> {
    scan_source(src).map(|scan| scan.hits)
}

/// Everything a production scan of one source file finds.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Scan {
    /// Unsanctioned abrupt-failure constructs, in line order.
    pub hits: Vec<Hit>,
    /// Production sources refused because they cannot be audited.
    pub test_path_includes: Vec<TestPathInclude>,
    /// Legal production sources the caller must resolve and scan in turn.
    pub included_sources: Vec<IncludedSource>,
}

/// Scan Rust source for hits, refused sources, and legal sources in one parse.
///
/// Hits follow [`scan_str`]. A production `#[path = "…"]`, `include!("…")`, or
/// `mod tests;` is either refused ([`TestPathInclude`]) or handed back as an
/// [`IncludedSource`]; see [`judge_literal`].
///
/// # Errors
///
/// [`ScanError`] when `src` is over a ceiling or does not parse as a Rust file.
pub fn scan_source(src: &str) -> Result<Scan, ScanError> {
    scan_source_on(ParseStack::CEILING, src)
}

/// [`scan_source`] on a parse thread of `stack` bytes; see [`with_parsed_on`].
///
/// # Errors
///
/// As [`scan_source`].
pub fn scan_source_on(stack: ParseStack, src: &str) -> Result<Scan, ScanError> {
    with_parsed_on(stack, src, |file| scan_file(file, src))
}

/// Scan an already-parsed file; `src` is its text, read for audit markers.
pub(crate) fn scan_file(file: &syn::File, src: &str) -> Scan {
    if attrs_test_only(&file.attrs) {
        return Scan::default();
    }
    let mut scanner = Scanner::default();
    scanner.visit_file(file);
    let lines: Vec<&str> = src.lines().collect();
    let mut hits = scanner.hits;
    hits.retain(|h| !is_sanctioned(&lines, h.line));
    hits.sort_by_key(|h| h.line);
    Scan {
        hits,
        test_path_includes: scanner.test_path_includes,
        included_sources: scanner.included_sources,
    }
}

/// Whether `attrs` make their node test-only.
///
/// Only the builtin `cfg` exempts: a bare `#[test]` names an attribute macro
/// a program can shadow, so it never marks its node as test code.
pub(crate) fn attrs_test_only(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| meta_is_test_cfg(&attr.meta))
}

/// Whether `meta` is `cfg(P)` with a test-only predicate `P`.
pub(crate) fn meta_is_test_cfg(meta: &Meta) -> bool {
    matches!(
        meta,
        Meta::List(list)
            if list.path.is_ident("cfg")
                && matches!(list.delimiter, MacroDelimiter::Paren(_))
                && cfg_pred_is_test_only(&list.tokens)
    )
}

/// 1-based line an identifier starts on.
fn line_of(ident: &Ident) -> usize {
    ident.span().start().line
}

/// 1-based line a path's last segment starts on.
fn path_line(path: &Path) -> usize {
    path.segments.last().map_or(0, |seg| line_of(&seg.ident))
}

/// Whether `tok` is the punctuation character `ch`.
fn is_punct(tok: &TokenTree, ch: char) -> bool {
    matches!(tok, TokenTree::Punct(p) if p.as_char() == ch)
}

/// Whether `tok` begins a call: an argument list or a `::` turbofish.
fn opens_call(tok: Option<&TokenTree>) -> bool {
    match tok {
        Some(TokenTree::Group(g)) => g.delimiter() == Delimiter::Parenthesis,
        Some(tok) => is_punct(tok, ':'),
        None => false,
    }
}

/// An identifier's name without a raw `r#` prefix.
fn name_of(ident: &Ident) -> String {
    ident.unraw().to_string()
}

/// A path's segments joined by `::`.
fn path_text(path: &Path) -> String {
    path.segments
        .iter()
        .map(|seg| name_of(&seg.ident))
        .collect::<Vec<_>>()
        .join("::")
}

/// A short description of a non-literal attribute value.
fn describe(expr: &Expr) -> String {
    match expr {
        Expr::Path(p) => path_text(&p.path),
        Expr::Macro(m) => format!("{}!(…)", path_text(&m.mac.path)),
        Expr::Lit(ExprLit {
            lit: Lit::Str(s), ..
        }) => s.token().to_string(),
        Expr::Lit(_) => "a non-string literal".to_owned(),
        _ => "a non-literal expression".to_owned(),
    }
}

/// The outer attributes of an expression node.
fn expr_attrs(expr: &Expr) -> &[Attribute] {
    match expr {
        Expr::Array(e) => &e.attrs,
        Expr::Assign(e) => &e.attrs,
        Expr::Async(e) => &e.attrs,
        Expr::Await(e) => &e.attrs,
        Expr::Binary(e) => &e.attrs,
        Expr::Block(e) => &e.attrs,
        Expr::Break(e) => &e.attrs,
        Expr::Call(e) => &e.attrs,
        Expr::Cast(e) => &e.attrs,
        Expr::Closure(e) => &e.attrs,
        Expr::Const(e) => &e.attrs,
        Expr::Continue(e) => &e.attrs,
        Expr::Field(e) => &e.attrs,
        Expr::ForLoop(e) => &e.attrs,
        Expr::Group(e) => &e.attrs,
        Expr::If(e) => &e.attrs,
        Expr::Index(e) => &e.attrs,
        Expr::Infer(e) => &e.attrs,
        Expr::Let(e) => &e.attrs,
        Expr::Lit(e) => &e.attrs,
        Expr::Loop(e) => &e.attrs,
        Expr::Macro(e) => &e.attrs,
        Expr::Match(e) => &e.attrs,
        Expr::MethodCall(e) => &e.attrs,
        Expr::Paren(e) => &e.attrs,
        Expr::Path(e) => &e.attrs,
        Expr::Range(e) => &e.attrs,
        Expr::RawAddr(e) => &e.attrs,
        Expr::Reference(e) => &e.attrs,
        Expr::Repeat(e) => &e.attrs,
        Expr::Return(e) => &e.attrs,
        Expr::Struct(e) => &e.attrs,
        Expr::Try(e) => &e.attrs,
        Expr::TryBlock(e) => &e.attrs,
        Expr::Tuple(e) => &e.attrs,
        Expr::Unary(e) => &e.attrs,
        Expr::Unsafe(e) => &e.attrs,
        Expr::While(e) => &e.attrs,
        Expr::Yield(e) => &e.attrs,
        _ => &[],
    }
}

/// Whether an item is test-only.
pub(crate) fn item_test_only(item: &Item) -> bool {
    let attrs: &[Attribute] = match item {
        Item::Const(i) => &i.attrs,
        Item::Enum(i) => &i.attrs,
        Item::ExternCrate(i) => &i.attrs,
        Item::Fn(i) => &i.attrs,
        Item::ForeignMod(i) => &i.attrs,
        Item::Impl(i) => &i.attrs,
        Item::Macro(i) => &i.attrs,
        Item::Mod(i) => &i.attrs,
        Item::Static(i) => &i.attrs,
        Item::Struct(i) => &i.attrs,
        Item::Trait(i) => &i.attrs,
        Item::TraitAlias(i) => &i.attrs,
        Item::Type(i) => &i.attrs,
        Item::Union(i) => &i.attrs,
        Item::Use(i) => &i.attrs,
        _ => &[],
    };
    attrs_test_only(attrs)
}

/// Whether an impl item is test-only.
fn impl_item_test_only(item: &ImplItem) -> bool {
    match item {
        ImplItem::Const(i) => attrs_test_only(&i.attrs),
        ImplItem::Fn(i) => attrs_test_only(&i.attrs),
        ImplItem::Type(i) => attrs_test_only(&i.attrs),
        ImplItem::Macro(i) => attrs_test_only(&i.attrs),
        _ => false,
    }
}

/// Whether a trait item is test-only.
fn trait_item_test_only(item: &TraitItem) -> bool {
    match item {
        TraitItem::Const(i) => attrs_test_only(&i.attrs),
        TraitItem::Fn(i) => attrs_test_only(&i.attrs),
        TraitItem::Type(i) => attrs_test_only(&i.attrs),
        TraitItem::Macro(i) => attrs_test_only(&i.attrs),
        _ => false,
    }
}

/// Whether a foreign item is test-only.
fn foreign_item_test_only(item: &ForeignItem) -> bool {
    match item {
        ForeignItem::Fn(i) => attrs_test_only(&i.attrs),
        ForeignItem::Static(i) => attrs_test_only(&i.attrs),
        ForeignItem::Type(i) => attrs_test_only(&i.attrs),
        ForeignItem::Macro(i) => attrs_test_only(&i.attrs),
        _ => false,
    }
}

/// End index of the whole item a flat test-only attribute gates, if any.
///
/// `toks[start..]` follows the attribute. The item runs to the first top-level
/// `;` or brace group and must parse as one item; only a test-only `cfg`
/// gates it. Anything else is not exempted.
fn gated_item_end(meta: &Meta, toks: &[TokenTree], start: usize) -> Option<usize> {
    if !meta_is_test_cfg(meta) {
        return None;
    }
    let rest = toks.get(start..)?;
    let last = rest.iter().position(|tok| {
        is_punct(tok, ';')
            || matches!(tok, TokenTree::Group(g) if g.delimiter() == Delimiter::Brace)
    })?;
    let item: TokenStream = rest.get(..=last)?.iter().cloned().collect();
    syn::parse2::<Item>(item).ok()?;
    Some(start.saturating_add(last).saturating_add(1))
}

/// The module a rename would hide from the path checks, if `name` under
/// `parent` names one.
///
/// A banned call is matched on its `process::abort` / `process::exit` path, so
/// an alias of `process` (`use std::process as p`, `use std::process::{self as
/// p}`) or of the `std` root (`use ::std as s`, `extern crate std as s`) would
/// let `p::exit` or `s::process::exit` through. The rename itself is the hit.
fn renamed_root(name: &str, parent: Option<&Ident>) -> Option<&'static str> {
    let parent = parent.map(name_of);
    let named = |root: &str| name == root || (name == "self" && parent.as_deref() == Some(root));
    if named(PROCESS_MODULE) {
        Some(PROCESS_MODULE)
    } else if named(STD_CRATE) && (parent.is_none() || name == "self") {
        Some(STD_CRATE)
    } else {
        None
    }
}

/// Whether the flat declaration at `toks[at]` may be visible outside its module.
///
/// Only a declaration that a statement boundary, an attribute, or the start of
/// the body directly precedes is private; a `pub`, a `pub(…)`, a `$vis`
/// metavariable, or anything else is taken as exported.
fn flat_exported(toks: &[TokenTree], at: usize) -> bool {
    match at.checked_sub(1).and_then(|before| toks.get(before)) {
        None => false,
        Some(TokenTree::Punct(p)) => p.as_char() != ';',
        Some(TokenTree::Group(g)) => {
            !matches!(g.delimiter(), Delimiter::Brace | Delimiter::Bracket)
        }
        Some(TokenTree::Ident(_) | TokenTree::Literal(_)) => true,
    }
}

/// Whether `toks[at]` is the `*`, `+` or `?` closing a `$( … )` repetition,
/// with at most a two-token separator (`$( … )::+`) between.
fn ends_repetition(toks: &[TokenTree], at: usize) -> bool {
    let operator = toks
        .get(at)
        .is_some_and(|t| is_punct(t, '*') || is_punct(t, '+') || is_punct(t, '?'));
    operator
        && (1..=3_usize).any(|back| {
            let Some(group_at) = at.checked_sub(back) else {
                return false;
            };
            let group = matches!(
                toks.get(group_at),
                Some(TokenTree::Group(g)) if g.delimiter() == Delimiter::Parenthesis
            );
            let dollar = group_at
                .checked_sub(1)
                .and_then(|d| toks.get(d))
                .is_some_and(|t| is_punct(t, '$'));
            let separator = toks.get(group_at.saturating_add(1)..at).is_some_and(|sep| {
                sep.iter()
                    .all(|t| !matches!(t, TokenTree::Group(_)) && !is_punct(t, '$'))
            });
            group && dollar && separator
        })
}

/// Whether the path segment before the `::` starting at `toks[colon]` is one
/// only the macro's caller names: a metavariable (`$p::`) or a repetition
/// (`$($s)::+::`).
fn templated_segment_before(toks: &[TokenTree], colon: usize) -> bool {
    let before = |back: usize| colon.checked_sub(back).and_then(|k| toks.get(k));
    let metavariable = matches!(before(1), Some(TokenTree::Ident(_)))
        && before(2).is_some_and(|t| is_punct(t, '$'));
    metavariable
        || colon
            .checked_sub(1)
            .is_some_and(|op| ends_repetition(toks, op))
}

/// Visitor state for one file.
#[derive(Default)]
struct Scanner {
    hits: Vec<Hit>,
    test_path_includes: Vec<TestPathInclude>,
    included_sources: Vec<IncludedSource>,
    /// Names of the inline modules enclosing the current node, outermost first.
    inline_mods: Vec<String>,
    /// Whether the attributes being visited decorate an inline module.
    relocating_inline_mod: bool,
}

impl Scanner {
    fn hit(&mut self, line: usize, tok: String) {
        self.hits.push(Hit { line, tok });
    }

    fn refuse(&mut self, line: usize, form: IncludeForm, target: IncludeTarget) {
        self.test_path_includes
            .push(TestPathInclude { line, form, target });
    }

    /// Judge a string-literal source and record it as legal or refused.
    fn source(&mut self, form: IncludeForm, lit: &LitStr) {
        let line = lit.span().start().line;
        if !lit.suffix().is_empty() {
            self.refuse(line, form, IncludeTarget::Opaque(lit.token().to_string()));
            return;
        }
        let literal = lit.value();
        if form == IncludeForm::PathAttr && self.relocating_inline_mod {
            self.refuse(
                line,
                form,
                IncludeTarget::Refused {
                    path: literal,
                    reason: PathRefusal::InlineModule,
                },
            );
            return;
        }
        match judge_literal(&literal) {
            Ok(()) => self.included_sources.push(IncludedSource {
                line,
                form,
                literal,
                inline_mods: self.inline_mods.clone(),
            }),
            Err(target) => self.refuse(line, form, target),
        }
    }

    /// Visit a meta parsed locally rather than borrowed from the file's tree.
    fn visit_owned_meta(&mut self, meta: &Meta) {
        Visit::visit_meta(self, meta);
    }

    /// Visit the attributes a `cfg_attr` applies unless its predicate is test-only.
    fn cfg_attr(&mut self, list: &MetaList) {
        let mut operands = split_top_level_commas(&list.tokens).into_iter();
        let Some(pred) = operands.next() else {
            return;
        };
        if cfg_pred_is_test_only(&pred) {
            return;
        }
        for operand in operands {
            if operand.is_empty() {
                continue;
            }
            match syn::parse2::<Meta>(operand.clone()) {
                Ok(meta) => self.visit_owned_meta(&meta),
                Err(_) => self.refuse(
                    path_line(&list.path),
                    IncludeForm::PathAttr,
                    IncludeTarget::Opaque(operand.to_string()),
                ),
            }
        }
    }

    /// Judge the arguments of an `include!` invocation.
    fn include_args(&mut self, line: usize, args: &TokenStream) {
        match syn::parse2::<LitStr>(args.clone()) {
            Ok(lit) => self.source(IncludeForm::IncludeMacro, &lit),
            Err(_) => self.refuse(
                line,
                IncludeForm::IncludeMacro,
                IncludeTarget::Opaque(args.to_string()),
            ),
        }
    }

    /// Refuse a renamed or re-exported `include` macro.
    fn aliased(&mut self, line: usize) {
        self.refuse(
            line,
            IncludeForm::IncludeMacro,
            IncludeTarget::Aliased(INCLUDE_MACRO.to_owned()),
        );
    }

    /// Record banned names a `use` tree imports under another name or path.
    fn use_tree(&mut self, tree: &UseTree, parent: Option<&Ident>, exported: bool) {
        let under_process = parent.is_some_and(|p| name_of(p) == PROCESS_MODULE);
        match tree {
            UseTree::Path(p) => self.use_tree(&p.tree, Some(&p.ident), exported),
            UseTree::Name(n) => {
                let name = name_of(&n.ident);
                let line = line_of(&n.ident);
                if under_process && PROCESS_FNS.contains(&name.as_str()) {
                    self.hit(line, format!("process::{name}"));
                }
                if exported && name == INCLUDE_MACRO {
                    self.aliased(line);
                }
            }
            UseTree::Rename(r) => {
                let name = name_of(&r.ident);
                let line = line_of(&r.ident);
                let rename = name_of(&r.rename);
                if under_process && PROCESS_FNS.contains(&name.as_str()) {
                    self.hit(line, format!("process::{name}"));
                }
                if let Some(root) = renamed_root(&name, parent) {
                    self.hit(line, format!("{root} as {rename}"));
                }
                let banned = [MACROS, METHODS, FNS]
                    .iter()
                    .any(|names| names.contains(&name.as_str()));
                if banned {
                    self.hit(line, format!("{name} as {rename}"));
                }
                if name == INCLUDE_MACRO {
                    self.aliased(line);
                }
            }
            UseTree::Glob(g) => {
                if under_process {
                    let line = g.star_token.spans.first().map_or(0, |s| s.start().line);
                    self.hit(line, "process::*".to_owned());
                }
            }
            UseTree::Group(g) => {
                for item in &g.items {
                    self.use_tree(item, parent, exported);
                }
            }
        }
    }

    /// Scan tokens that have no syntax tree, such as a macro body.
    fn flat_scan(&mut self, ts: &TokenStream) {
        let toks: Vec<TokenTree> = ts.clone().into_iter().collect();
        let mut i = 0_usize;
        while let Some(tok) = toks.get(i) {
            let next = i.saturating_add(1);
            i = match tok {
                TokenTree::Punct(p) if p.as_char() == '#' => {
                    let inner = toks.get(next).is_some_and(|t| is_punct(t, '!'));
                    let at = if inner { next.saturating_add(1) } else { next };
                    match toks.get(at) {
                        Some(TokenTree::Group(g)) if g.delimiter() == Delimiter::Bracket => {
                            let after = at.saturating_add(1);
                            self.flat_attr(&g.stream(), inner, &toks, after)
                                .unwrap_or(after)
                        }
                        _ => next,
                    }
                }
                TokenTree::Punct(p) if p.as_char() == '.' => {
                    self.flat_method(&toks, i);
                    next
                }
                TokenTree::Punct(p) if p.as_char() == ':' => {
                    self.flat_path_leaf(&toks, i);
                    next
                }
                TokenTree::Punct(p) if p.as_char() == '$' => {
                    self.flat_metavariable_macro(&toks, next);
                    next
                }
                TokenTree::Punct(_) | TokenTree::Literal(_) => next,
                TokenTree::Ident(id) => self.flat_declaration(id, &toks, i).unwrap_or_else(|| {
                    self.flat_repeated_leaf(id, &toks, i);
                    self.flat_ident(id, &toks, next);
                    next
                }),
                TokenTree::Group(g) => {
                    self.flat_scan(&g.stream());
                    next
                }
            };
        }
    }

    /// Check the method a flat `.` at `toks[dot]` calls.
    ///
    /// A metavariable method (`.$m()`) is a hit: the caller may bind it to
    /// `unwrap`, which this body never spells.
    fn flat_method(&mut self, toks: &[TokenTree], dot: usize) {
        let next = dot.saturating_add(1);
        let after = |ahead: usize| toks.get(next.saturating_add(ahead));
        match toks.get(next) {
            Some(TokenTree::Ident(m)) => {
                let name = name_of(m);
                if METHODS.contains(&name.as_str()) && opens_call(after(1)) {
                    self.hit(line_of(m), format!(".{name}()"));
                }
            }
            Some(dollar) if is_punct(dollar, '$') => {
                let range = dot
                    .checked_sub(1)
                    .and_then(|k| toks.get(k))
                    .is_some_and(|t| is_punct(t, '.'));
                if let Some(TokenTree::Ident(m)) = after(1)
                    && !range
                    && opens_call(after(2))
                {
                    self.hit(line_of(m), ".$…()".to_owned());
                }
            }
            _ => {}
        }
    }

    /// Check the path leaf after a flat `::` starting at `toks[colon]`.
    ///
    /// A banned leaf behind a caller-named segment (`$p::exit`,
    /// `$($s)::+::abort`) reaches `process::exit` when the caller binds the
    /// segment to `std::process`. A caller-named leaf (`process::$f`,
    /// `$m::$f`) is a hit when its module is `process` or caller-named too.
    fn flat_path_leaf(&mut self, toks: &[TokenTree], colon: usize) {
        let next = colon.saturating_add(1);
        if !toks.get(next).is_some_and(|t| is_punct(t, ':')) {
            return;
        }
        let leaf_at = next.saturating_add(1);
        match toks.get(leaf_at) {
            Some(TokenTree::Ident(m)) => {
                let name = name_of(m);
                if METHODS.contains(&name.as_str())
                    && opens_call(toks.get(leaf_at.saturating_add(1)))
                {
                    self.hit(line_of(m), format!("::{name}()"));
                } else if PROCESS_FNS.contains(&name.as_str())
                    && templated_segment_before(toks, colon)
                {
                    self.hit(line_of(m), format!("$…::{name}"));
                }
            }
            Some(leaf) if is_punct(leaf, '$') => {
                let process = matches!(
                    colon.checked_sub(1).and_then(|k| toks.get(k)),
                    Some(TokenTree::Ident(m)) if name_of(m) == PROCESS_MODULE
                );
                if process || templated_segment_before(toks, colon) {
                    self.hit(leaf.span().start().line, "…::$…".to_owned());
                }
            }
            _ => {}
        }
    }

    /// Flag a metavariable macro (`$m!(…)`) whose name starts at `toks[at]`:
    /// the caller may bind it to `panic`, which this body never spells.
    fn flat_metavariable_macro(&mut self, toks: &[TokenTree], at: usize) {
        let after = |ahead: usize| toks.get(at.saturating_add(ahead));
        if let Some(TokenTree::Ident(m)) = toks.get(at)
            && after(1).is_some_and(|t| is_punct(t, '!'))
            && matches!(after(2), Some(TokenTree::Group(_)))
        {
            self.hit(line_of(m), "$…!".to_owned());
        }
    }

    /// Flag a banned leaf a `$( … )` repetition directly precedes
    /// (`$($s::)+exit`): the repetition expands to a path prefix only the
    /// caller names.
    fn flat_repeated_leaf(&mut self, id: &Ident, toks: &[TokenTree], at: usize) {
        let name = name_of(id);
        let called = opens_call(toks.get(at.saturating_add(1)));
        let banned =
            PROCESS_FNS.contains(&name.as_str()) || (called && METHODS.contains(&name.as_str()));
        if banned
            && at
                .checked_sub(1)
                .is_some_and(|op| ends_repetition(toks, op))
        {
            self.hit(line_of(id), format!("$(…){name}"));
        }
    }

    /// Handle a flat `#[…]` or `#![…]` body; returns the index to resume at
    /// when the attribute gates a whole test-only item.
    fn flat_attr(
        &mut self,
        body: &TokenStream,
        inner: bool,
        toks: &[TokenTree],
        next: usize,
    ) -> Option<usize> {
        if let Ok(meta) = syn::parse2::<Meta>(body.clone()) {
            if !inner && let Some(end) = gated_item_end(&meta, toks, next) {
                return Some(end);
            }
            self.visit_owned_meta(&meta);
            return None;
        }
        match body.clone().into_iter().next() {
            Some(TokenTree::Ident(id)) if id == PATH_ATTR || id == CFG_ATTR => {
                self.refuse(
                    line_of(&id),
                    IncludeForm::PathAttr,
                    IncludeTarget::Opaque(body.to_string()),
                );
            }
            _ => self.flat_scan(body),
        }
        None
    }

    /// Judge a flat `use` or `extern crate` declaration starting at `toks[at]`;
    /// returns the index just past it.
    ///
    /// A name it binds is read by the syntax-tree checks of the code that
    /// expands it, so it is judged by the same rules as a parsed declaration: a
    /// macro-body `use std::process as p;` is the same hit as a top-level one.
    /// A declaration that does not parse (a metavariable in its path) binds a
    /// name that cannot be judged here, so it is itself a hit and its tokens
    /// are scanned flat.
    fn flat_declaration(&mut self, id: &Ident, toks: &[TokenTree], at: usize) -> Option<usize> {
        let next = at.saturating_add(1);
        let is_use = id == "use" && !toks.get(next).is_some_and(|t| is_punct(t, '<'));
        let is_extern =
            id == "extern" && matches!(toks.get(next), Some(TokenTree::Ident(c)) if c == "crate");
        if !is_use && !is_extern {
            return None;
        }
        let rest = toks.get(at..)?;
        let end = rest
            .iter()
            .position(|t| is_punct(t, ';'))
            .map_or(toks.len(), |semi| at.saturating_add(semi).saturating_add(1));
        let decl: TokenStream = toks.get(at..end)?.iter().cloned().collect();
        if is_use {
            let Ok(item) = syn::parse2::<ItemUse>(decl) else {
                self.hit(line_of(id), format!("unparsed {id}"));
                return None;
            };
            self.use_tree(&item.tree, None, flat_exported(toks, at));
        } else {
            let Ok(item) = syn::parse2::<ItemExternCrate>(decl) else {
                self.hit(line_of(id), format!("unparsed {id} crate"));
                return None;
            };
            self.extern_crate(&item);
        }
        Some(end)
    }

    /// Record an `extern crate` that renames the `std` root.
    fn extern_crate(&mut self, item: &ItemExternCrate) {
        let name = name_of(&item.ident);
        if let (Some((_, rename)), Some(root)) = (&item.rename, renamed_root(&name, None)) {
            self.hit(
                line_of(&item.ident),
                format!("{root} as {}", name_of(rename)),
            );
        }
    }

    /// Check one flat identifier against the banned and source-naming forms.
    fn flat_ident(&mut self, id: &Ident, toks: &[TokenTree], next: usize) {
        let name = name_of(id);
        let line = line_of(id);
        let after = toks.get(next);
        let second = toks.get(next.saturating_add(1));
        let bang = after.is_some_and(|t| is_punct(t, '!'));
        if bang && MACROS.contains(&name.as_str()) {
            self.hit(line, format!("{name}!"));
        } else if name == INCLUDE_MACRO {
            if bang {
                match second {
                    Some(TokenTree::Group(g)) => self.include_args(line, &g.stream()),
                    _ => self.refuse(
                        line,
                        IncludeForm::IncludeMacro,
                        IncludeTarget::Opaque(INCLUDE_MACRO.to_owned()),
                    ),
                }
            } else if matches!(after, Some(TokenTree::Ident(a)) if a == "as") {
                self.aliased(line);
            }
        } else if FNS.contains(&name.as_str())
            && matches!(after, Some(TokenTree::Group(g)) if g.delimiter() == Delimiter::Parenthesis)
        {
            self.hit(line, format!("{name}()"));
        } else if name == "process"
            && after.is_some_and(|t| is_punct(t, ':'))
            && second.is_some_and(|t| is_punct(t, ':'))
        {
            if let Some(TokenTree::Ident(f)) = toks.get(next.saturating_add(2)) {
                let fname = name_of(f);
                if PROCESS_FNS.contains(&fname.as_str()) {
                    self.hit(line_of(f), format!("process::{fname}"));
                }
            }
        } else if name == "mod" {
            match (after, second) {
                (Some(TokenTree::Ident(m)), Some(semi)) => {
                    let module = name_of(m);
                    if is_punct(semi, ';') && module.eq_ignore_ascii_case(TESTS_MODULE) {
                        self.refuse(
                            line_of(m),
                            IncludeForm::ModDecl,
                            IncludeTarget::TestPath(module),
                        );
                    }
                }
                // A module named by a metavariable (`mod $n;`) or any other
                // non-identifier token resolves to a file only at expansion,
                // so the file it reaches cannot be judged here.
                (
                    Some(
                        named @ (TokenTree::Punct(_) | TokenTree::Group(_) | TokenTree::Literal(_)),
                    ),
                    _,
                ) => self.refuse(
                    line,
                    IncludeForm::ModDecl,
                    IncludeTarget::Opaque(format!("mod {named}")),
                ),
                _ => {}
            }
        }
    }
}

impl<'ast> Visit<'ast> for Scanner {
    fn visit_item(&mut self, item: &'ast Item) {
        if item_test_only(item) {
            return;
        }
        match item {
            Item::Verbatim(ts) => self.flat_scan(ts),
            _ => visit::visit_item(self, item),
        }
    }

    fn visit_impl_item(&mut self, item: &'ast ImplItem) {
        if impl_item_test_only(item) {
            return;
        }
        match item {
            ImplItem::Verbatim(ts) => self.flat_scan(ts),
            _ => visit::visit_impl_item(self, item),
        }
    }

    fn visit_trait_item(&mut self, item: &'ast TraitItem) {
        if trait_item_test_only(item) {
            return;
        }
        match item {
            TraitItem::Verbatim(ts) => self.flat_scan(ts),
            _ => visit::visit_trait_item(self, item),
        }
    }

    fn visit_foreign_item(&mut self, item: &'ast ForeignItem) {
        if foreign_item_test_only(item) {
            return;
        }
        match item {
            ForeignItem::Verbatim(ts) => self.flat_scan(ts),
            _ => visit::visit_foreign_item(self, item),
        }
    }

    fn visit_expr(&mut self, expr: &'ast Expr) {
        if attrs_test_only(expr_attrs(expr)) {
            return;
        }
        match expr {
            Expr::Verbatim(ts) => self.flat_scan(ts),
            _ => visit::visit_expr(self, expr),
        }
    }

    fn visit_pat(&mut self, pat: &'ast Pat) {
        match pat {
            Pat::Verbatim(ts) => self.flat_scan(ts),
            _ => visit::visit_pat(self, pat),
        }
    }

    fn visit_type(&mut self, ty: &'ast Type) {
        match ty {
            Type::Verbatim(ts) => self.flat_scan(ts),
            _ => visit::visit_type(self, ty),
        }
    }

    fn visit_type_param_bound(&mut self, bound: &'ast TypeParamBound) {
        match bound {
            TypeParamBound::Verbatim(ts) => self.flat_scan(ts),
            _ => visit::visit_type_param_bound(self, bound),
        }
    }

    fn visit_arm(&mut self, arm: &'ast Arm) {
        if !attrs_test_only(&arm.attrs) {
            visit::visit_arm(self, arm);
        }
    }

    fn visit_field_value(&mut self, field: &'ast FieldValue) {
        if !attrs_test_only(&field.attrs) {
            visit::visit_field_value(self, field);
        }
    }

    fn visit_field(&mut self, field: &'ast Field) {
        if !attrs_test_only(&field.attrs) {
            visit::visit_field(self, field);
        }
    }

    fn visit_variant(&mut self, variant: &'ast Variant) {
        if !attrs_test_only(&variant.attrs) {
            visit::visit_variant(self, variant);
        }
    }

    fn visit_local(&mut self, local: &'ast Local) {
        if !attrs_test_only(&local.attrs) {
            visit::visit_local(self, local);
        }
    }

    fn visit_stmt_macro(&mut self, stmt: &'ast StmtMacro) {
        if !attrs_test_only(&stmt.attrs) {
            visit::visit_stmt_macro(self, stmt);
        }
    }

    fn visit_item_mod(&mut self, module: &'ast ItemMod) {
        let relocating =
            std::mem::replace(&mut self.relocating_inline_mod, module.content.is_some());
        for attr in &module.attrs {
            self.visit_attribute(attr);
        }
        self.relocating_inline_mod = relocating;
        let name = name_of(&module.ident);
        match &module.content {
            None => {
                if name.eq_ignore_ascii_case(TESTS_MODULE) {
                    self.refuse(
                        line_of(&module.ident),
                        IncludeForm::ModDecl,
                        IncludeTarget::TestPath(name),
                    );
                }
            }
            Some((_, items)) => {
                self.inline_mods.push(name);
                for item in items {
                    self.visit_item(item);
                }
                self.inline_mods.pop();
            }
        }
    }

    fn visit_macro(&mut self, mac: &'ast Macro) {
        if let Some(seg) = mac.path.segments.last() {
            let name = name_of(&seg.ident);
            let line = line_of(&seg.ident);
            if MACROS.contains(&name.as_str()) {
                self.hit(line, format!("{name}!"));
            } else if name == INCLUDE_MACRO {
                self.include_args(line, &mac.tokens);
            }
        }
        visit::visit_macro(self, mac);
    }

    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        let name = name_of(&call.method);
        if METHODS.contains(&name.as_str()) {
            self.hit(line_of(&call.method), format!(".{name}()"));
        }
        visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_path(&mut self, expr: &'ast ExprPath) {
        if let Some(seg) = expr.path.segments.last() {
            let name = name_of(&seg.ident);
            let qualified = expr.qself.is_some() || expr.path.segments.len() >= 2;
            if qualified && METHODS.contains(&name.as_str()) {
                self.hit(line_of(&seg.ident), format!("::{name}()"));
            } else if FNS.contains(&name.as_str()) {
                self.hit(line_of(&seg.ident), format!("{name}()"));
            }
        }
        visit::visit_expr_path(self, expr);
    }

    fn visit_path(&mut self, path: &'ast Path) {
        let names: Vec<(String, usize)> = path
            .segments
            .iter()
            .map(|seg| (name_of(&seg.ident), line_of(&seg.ident)))
            .collect();
        for pair in names.windows(2) {
            if let [(module, _), (func, line)] = pair
                && module == "process"
                && PROCESS_FNS.contains(&func.as_str())
            {
                self.hit(*line, format!("process::{func}"));
            }
        }
        visit::visit_path(self, path);
    }

    fn visit_item_extern_crate(&mut self, item: &'ast ItemExternCrate) {
        self.extern_crate(item);
        visit::visit_item_extern_crate(self, item);
    }

    fn visit_item_use(&mut self, item: &'ast ItemUse) {
        let exported = !matches!(item.vis, Visibility::Inherited);
        self.use_tree(&item.tree, None, exported);
        visit::visit_item_use(self, item);
    }

    fn visit_meta(&mut self, meta: &'ast Meta) {
        match meta {
            Meta::NameValue(nv) if nv.path.is_ident(PATH_ATTR) => match &nv.value {
                Expr::Lit(ExprLit {
                    lit: Lit::Str(lit), ..
                }) => self.source(IncludeForm::PathAttr, lit),
                other => self.refuse(
                    path_line(&nv.path),
                    IncludeForm::PathAttr,
                    IncludeTarget::Opaque(describe(other)),
                ),
            },
            Meta::List(list) if list.path.is_ident(CFG_ATTR) => self.cfg_attr(list),
            _ => visit::visit_meta(self, meta),
        }
    }

    fn visit_token_stream(&mut self, tokens: &'ast TokenStream) {
        self.flat_scan(tokens);
    }
}

/// True when the [`AUDIT_MARKER`] annotates the construct on the 1-based `line`.
///
/// The construct's statement may span several source lines (`let x =\n    e.expect(..)`),
/// so the sanction attaches to any of those lines and to the contiguous comment/
/// attribute block directly above the statement's *first* line. The walk:
///
/// 1. From the hit line, walk upward across the statement's own continuation
///    lines — lines belonging to the same still-open statement as the hit. A
///    marker on any of them suppresses the hit.
/// 2. The statement's first line is the one just below the nearest *boundary*
///    above the hit: a line whose code part ends a statement or block (ends in
///    `;`, `{`, or `}`) or a blank line. The boundary line itself is NOT part of
///    the statement, so a *prior terminated* statement's marker can never leak
///    down.
/// 3. Above that first line, keep walking only through the directly-attached
///    annotation block (comment / attribute lines); the first non-annotation
///    line ends it.
fn is_sanctioned(lines: &[&str], line: usize) -> bool {
    // Phase 1 + 2: the hit line and its statement-continuation lines. Stop just
    // after crossing a boundary (a terminator/blank line above the statement).
    let mut idx = line; // 1-based; `lines[idx-1]` is the hit line.
    while idx >= 1 {
        let Some(text) = lines.get(idx - 1) else {
            return false;
        };
        if text.contains(AUDIT_MARKER) {
            return true;
        }
        // The line ABOVE the current one: if it's a boundary, the current line
        // is the statement's first line — stop the statement walk here.
        if idx == 1 {
            return false;
        }
        let Some(above) = lines.get(idx - 2) else {
            return false;
        };
        if is_statement_boundary(above) {
            break;
        }
        idx -= 1;
    }
    // `idx` is now the statement's first line. Phase 3: walk the annotation
    // block directly above it.
    idx -= 1;
    while idx >= 1 {
        let Some(text) = lines.get(idx - 1) else {
            break;
        };
        if !is_annotation_line(text) {
            break;
        }
        if text.contains(AUDIT_MARKER) {
            return true;
        }
        idx -= 1;
    }
    false
}

/// True when a source line ends the statement/block above it — the boundary that
/// closes the previous construct's scope. A blank line, or a line whose code part
/// (its text with any trailing `// …` comment stripped) ends in `;`, `{`, or `}`,
/// is a boundary; the line below such a boundary begins a fresh statement.
fn is_statement_boundary(text: &str) -> bool {
    let code = strip_trailing_line_comment(text);
    let code = code.trim_end();
    if code.is_empty() {
        return true;
    }
    matches!(code.chars().last(), Some(';' | '{' | '}'))
}

/// A source line with a trailing `// …` line comment removed, so a terminator
/// check inspects the code part only (`foo(); // note` ends in `;`). This is the
/// common case; it does not attempt to parse `/* … */` block comments or `//`
/// occurring inside a string literal — the terminator characters it looks for
/// (`;`, `{`, `}`) after such a strip are still a sound over-approximation of a
/// boundary for the marker walk.
fn strip_trailing_line_comment(text: &str) -> &str {
    text.find("//")
        .map_or(text, |pos| text.get(..pos).unwrap_or(text))
}

/// True when a trimmed source line is a comment (`//`, `///`, `//!`) or an
/// attribute (`#[ … ]`) — the only line kinds that form a construct's
/// directly-attached annotation block above it.
fn is_annotation_line(text: &str) -> bool {
    let t = text.trim_start();
    t.starts_with("//") || t.starts_with("#[")
}

/// True when a `cfg` predicate is guaranteed active only under the `test` cfg.
///
/// Structural, not string-based: it inspects the predicate's own tokens so
/// `test` inside a string literal (`feature = "testing"`) or as a substring of
/// another identifier (`contest`) never matches. A bare `test` identifier is
/// test-only. An `all( … )` is test-only when any of its comma-separated
/// operands is itself test-only (so `all(test, unix)` and `all(unix, test)`
/// qualify, as does a nested `all(all(test), …)`). `any( … )` and `not( … )`
/// never qualify: `any(test, X)` also compiles when `X` holds without `test`,
/// and `not(test)` is production-only.
pub(crate) fn cfg_pred_is_test_only(pred: &TokenStream) -> bool {
    let toks: Vec<TokenTree> = pred.clone().into_iter().collect();
    // Bare `test`.
    if let [TokenTree::Ident(id)] = toks.as_slice() {
        return id == "test";
    }
    // `all( … )` — test-only if any operand is test-only. Only `all` combines;
    // `any`/`not` (or anything else) are treated as possibly-production.
    if let [TokenTree::Ident(id), TokenTree::Group(g)] = toks.as_slice()
        && id == "all"
        && g.delimiter() == Delimiter::Parenthesis
    {
        return split_top_level_commas(&g.stream())
            .iter()
            .any(cfg_pred_is_test_only);
    }
    false
}

/// Split a `cfg` operand list on top-level commas, returning each operand as its
/// own token stream. Commas nested inside a delimiter group (an inner
/// `all(a, b)`, `any(…)`, or a `feature = "…"` value) are not split points.
pub(crate) fn split_top_level_commas(ts: &TokenStream) -> Vec<TokenStream> {
    let mut operands = Vec::new();
    let mut current: Vec<TokenTree> = Vec::new();
    for tt in ts.clone() {
        match &tt {
            TokenTree::Punct(p) if p.as_char() == ',' => {
                operands.push(
                    std::mem::take(&mut current)
                        .into_iter()
                        .collect::<TokenStream>(),
                );
            }
            _ => current.push(tt),
        }
    }
    if !current.is_empty() {
        operands.push(current.into_iter().collect());
    }
    operands
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// Lines a fixture marks with a trailing `//@HIT` are the exact set that
    /// must be found. Comment-only lines are ignored so prose that merely
    /// mentions the marker (e.g. this file's header) does not count as a case.
    fn wanted(src: &str) -> BTreeSet<usize> {
        src.lines()
            .enumerate()
            .filter(|(_, l)| l.contains("//@HIT") && !l.trim_start().starts_with("//"))
            .map(|(i, _)| i + 1)
            .collect()
    }

    #[test]
    fn positives_no_false_negatives_and_no_false_positives() {
        let src = include_str!("../fixtures/positives.rs");
        let res = scan_str(src);
        assert!(res.is_ok(), "fixture must lex: {:?}", res.err());
        let got: BTreeSet<usize> = res
            .unwrap_or_default()
            .into_iter()
            .map(|h| h.line)
            .collect();
        let want = wanted(src);
        let missed: Vec<_> = want.difference(&got).collect();
        let extra: Vec<_> = got.difference(&want).collect();
        assert!(missed.is_empty(), "FALSE NEGATIVES at lines {missed:?}");
        assert!(extra.is_empty(), "FALSE POSITIVES at lines {extra:?}");
    }

    /// A marker on an EARLIER code statement must NOT suppress a later, unmarked
    /// banned construct in the same blank-line-free block: the sanction is scoped
    /// to the construct's own attached annotation, never a blanket over what
    /// follows. This is the exact fail-open repro the scoping fix closes.
    #[test]
    fn earlier_statement_marker_does_not_suppress_later_construct() {
        let src = "\
fn f() {
    let a = compute(); // IPE-RUST-AUDIT:ACCEPTED — for something unrelated
    let b = other();
    let c = danger.unwrap();
}
";
        let hits = scan_str(src).expect("fixture must lex");
        // The `.unwrap()` on line 4 is unannotated → it MUST be reported.
        assert!(
            hits.iter().any(|h| h.line == 4),
            "earlier marker leaked downward, suppressing an unmarked .unwrap(): {hits:?}"
        );
    }

    /// A construct's statement can span several lines (`let x =\n    e.expect(..)`).
    /// A marker in the comment/attribute block directly above the statement's
    /// FIRST line must still suppress the hit on a *continuation* line — the
    /// exact multi-line shape (marker + `#[allow]` above `let mut mac =` then the
    /// `.expect(..)` below) that the production crypto sites use.
    #[test]
    fn multiline_statement_marker_suppresses_continuation_hit() {
        let src = "\
fn f() {
    let x = other();
    // IPE-RUST-AUDIT:ACCEPTED — reviewed, structurally-dead branch
    #[allow(clippy::expect_used)]
    let mut y =
        maybe.expect(\"infallible here\");
    consume(y);
}
";
        let hits = scan_str(src).expect("fixture must lex");
        assert!(
            hits.is_empty(),
            "multi-line-statement marker failed to suppress its continuation-line construct: {hits:?}"
        );
    }

    /// Negative twin of the multi-line case: a marker attached to a PRIOR,
    /// terminated statement must NOT reach into a later multi-line statement's
    /// continuation-line construct. The `;` after the marked statement is a
    /// boundary the walk stops at, so the `.expect(..)` below stays reported.
    #[test]
    fn prior_statement_marker_does_not_suppress_later_multiline_construct() {
        let src = "\
fn f() {
    // IPE-RUST-AUDIT:ACCEPTED — meant for the statement right below
    let a = safe();
    let mut y =
        maybe.expect(\"NOT covered by the marker above\");
    consume(y);
}
";
        let hits = scan_str(src).expect("fixture must lex");
        // The `.expect(..)` on line 5 is not the marked statement → MUST report.
        assert!(
            hits.iter().any(|h| h.line == 5),
            "prior-statement marker leaked into a later multi-line construct: {hits:?}"
        );
    }

    /// The documented sanction form — a marker in the contiguous comment/
    /// attribute block DIRECTLY above the construct — still suppresses it.
    #[test]
    fn adjacent_annotation_block_marker_suppresses() {
        let src = "\
fn f() {
    // IPE-RUST-AUDIT:ACCEPTED — reviewed, provably-dead branch
    let c = danger.unwrap();
}
";
        let hits = scan_str(src).expect("fixture must lex");
        assert!(
            hits.is_empty(),
            "adjacent-block marker failed to suppress its construct: {hits:?}"
        );
    }

    /// A marker on the hit line itself suppresses that construct.
    #[test]
    fn same_line_marker_suppresses() {
        let src = "fn f() { let c = danger.unwrap(); } // IPE-RUST-AUDIT:ACCEPTED — reviewed\n";
        let hits = scan_str(src).expect("fixture must lex");
        assert!(
            hits.is_empty(),
            "same-line marker failed to suppress: {hits:?}"
        );
    }

    /// A blank line between the marker and the construct breaks the attached
    /// block: the marker no longer applies.
    #[test]
    fn blank_line_breaks_annotation_block() {
        let src = "\
fn f() {
    // IPE-RUST-AUDIT:ACCEPTED — meant for something now deleted

    let c = danger.unwrap();
}
";
        let hits = scan_str(src).expect("fixture must lex");
        assert!(
            hits.iter().any(|h| h.line == 4),
            "marker separated by a blank line still suppressed the construct: {hits:?}"
        );
    }

    #[test]
    fn negatives_produce_no_hits() {
        let src = include_str!("../fixtures/negatives.rs");
        let res = scan_str(src);
        assert!(res.is_ok(), "fixture must lex: {:?}", res.err());
        let hits = res.unwrap_or_default();
        assert!(
            hits.is_empty(),
            "FALSE POSITIVES: {:?}",
            hits.iter()
                .map(|h| (h.line, h.tok.as_str()))
                .collect::<Vec<_>>()
        );
    }

    /// Lines of every hit in `src`, or an empty list when `src` does not parse.
    fn hit_lines(src: &str) -> Vec<usize> {
        scan_str(src)
            .unwrap_or_default()
            .into_iter()
            .map(|h| h.line)
            .collect()
    }

    /// A test-only attribute exempts only its own node: a sibling separated by
    /// `,` or `;` is still production code.
    #[test]
    fn test_cfg_never_leaks_past_its_node() {
        let cases: [(&str, usize); 5] = [
            (
                "fn f(o: Option<u8>) -> u8 {\n    match 1 {\n        #[cfg(test)]\n        0 => 0,\n        _ => o.unwrap(),\n    }\n}\n",
                5,
            ),
            (
                "fn f(o: Option<u8>) -> S {\n    S {\n        #[cfg(test)]\n        a: 0,\n        b: o.unwrap(),\n    }\n}\n",
                5,
            ),
            (
                "fn f(o: Option<u8>) -> [u8; 2] {\n    [\n        #[cfg(test)]\n        0,\n        o.unwrap(),\n    ]\n}\n",
                5,
            ),
            (
                "fn f(o: Option<u8>) {\n    #[cfg(test)]\n    let a = 0;\n    let b = o.unwrap();\n}\n",
                4,
            ),
            (
                "fn f(o: Option<u8>) {\n    #[cfg(test)]\n    g();\n    o.unwrap();\n}\n",
                4,
            ),
        ];
        for (src, line) in cases {
            assert_eq!(hit_lines(src), vec![line], "leak in:\n{src}");
        }
    }

    /// A test-only attribute exempts the whole node it decorates.
    #[test]
    fn test_cfg_exempts_its_own_node() {
        let cases = [
            "fn f(o: Option<u8>) -> u8 {\n    match 1 {\n        #[cfg(test)]\n        0 => o.unwrap(),\n        _ => 0,\n    }\n}\n",
            "fn f(o: Option<u8>) -> S {\n    S {\n        #[cfg(test)]\n        a: o.unwrap(),\n    }\n}\n",
            "fn f(o: Option<u8>) {\n    #[cfg(test)]\n    let a = o.unwrap();\n}\n",
            "#![cfg(test)]\nfn f(o: Option<u8>) {\n    o.unwrap();\n}\n",
            "impl S {\n    #[cfg(test)]\n    fn t() {\n        panic!();\n    }\n}\n",
        ];
        for src in cases {
            assert!(scan_str(src).is_ok(), "must parse:\n{src}");
            assert_eq!(hit_lines(src), Vec::<usize>::new(), "not exempt:\n{src}");
        }
    }

    /// A bare `#[test]` exempts nothing: it names a shadowable attribute macro,
    /// so outside a `cfg(test)` scope its function is production code.
    #[test]
    fn bare_test_attribute_is_production() {
        let cases: [(&str, usize); 4] = [
            ("#[test]\nfn t(o: Option<u8>) {\n    o.unwrap();\n}\n", 3),
            (
                "impl S {\n    #[test]\n    fn t() {\n        panic!();\n    }\n}\n",
                4,
            ),
            (
                "trait T {\n    #[test]\n    fn t() {\n        panic!();\n    }\n}\n",
                4,
            ),
            (
                "macro_rules! m {\n    () => {\n        #[test]\n        fn t() { o.unwrap(); }\n    };\n}\n",
                4,
            ),
        ];
        for (src, line) in cases {
            assert_eq!(hit_lines(src), vec![line], "exempted:\n{src}");
        }
        let gated = "#[cfg(test)]\nmod tests {\n    #[test]\n    fn t(o: Option<u8>) {\n        o.unwrap();\n    }\n}\n";
        assert_eq!(hit_lines(gated), Vec::<usize>::new());
    }

    /// Macro bodies are scanned flat; a test-only attribute there exempts only
    /// a whole item.
    #[test]
    fn macro_bodies_are_scanned_flat() {
        let leak = "macro_rules! m {\n    () => {\n        #[cfg(test)] 0, o.unwrap()\n    };\n}\n";
        assert_eq!(hit_lines(leak), vec![3]);
        let item = "macro_rules! m {\n    () => {\n        #[cfg(test)]\n        fn t() { o.unwrap(); }\n    };\n}\n";
        assert_eq!(hit_lines(item), Vec::<usize>::new());
    }

    /// A banned function imported under another name is a hit at the import.
    #[test]
    fn renamed_banned_names_are_hits() {
        for src in [
            "use std::process::exit as leave;\n",
            "use std::process::*;\n",
            "use std::panic::panic_any as boom;\n",
            "use std::process as p;\nfn f() { p::exit(0); }\n",
            "use std::process::{self as p};\n",
            "use ::std as s;\nfn f() { s::fs::read(p); }\n",
            "use std::{self as s};\n",
            "extern crate std as s;\nfn f() { s::fs::read(p); }\n",
            "use other::process as p;\n",
        ] {
            assert_eq!(hit_lines(src), vec![1], "missed:\n{src}");
        }
        for src in [
            "use other::std as s;\n",
            "extern crate core as c;\n",
            "use std::fs as f;\n",
        ] {
            assert_eq!(
                hit_lines(src),
                Vec::<usize>::new(),
                "not a hidden root:\n{src}"
            );
        }
    }

    /// A macro-body `use` or `extern crate` binds a name the expanded code's
    /// paths read, so a rename there is the same hit as a top-level one.
    #[test]
    fn macro_body_renames_are_hits() {
        let body =
            |decl: &str| format!("macro_rules! m {{\n    () => {{\n        {decl}\n    }};\n}}\n");
        for decl in [
            "use std::process as p;",
            "use std::process::{self as p};",
            "use std::{process as p};",
            "use ::std as s;",
            "extern crate std as s;",
            "use std::process::{exit as leave};",
            "use std::process::{exit};",
            "use std::panic::panic_any as boom;",
            "use $p as q;",
            "fn f() { $p::exit(0); }",
            "const F: fn() -> ! = $p::abort;",
        ] {
            assert_eq!(hit_lines(&body(decl)), vec![3], "missed:\n{decl}");
        }
        for decl in [
            "use std::fs as f;",
            "use super::*;",
            "fn f() { $p::read(0); m::exit(0); }",
            "fn f() -> impl Sized + use<> {}",
            "extern \"C\" { fn g(); }",
        ] {
            assert_eq!(
                hit_lines(&body(decl)),
                Vec::<usize>::new(),
                "not a hit:\n{decl}"
            );
        }
        let private = body("use core::include;");
        assert!(scan_source(&private).is_ok_and(|scan| scan.test_path_includes.is_empty()));
        let exported = body("pub use core::include;");
        assert!(scan_source(&exported).is_ok_and(|scan| scan.test_path_includes.len() == 1));
    }

    /// A macro-body callee the caller names (a metavariable leaf, method or
    /// macro, or a repetition prefix) can expand to a banned call the body
    /// never spells, so it is a hit.
    #[test]
    fn macro_body_caller_named_callees_are_hits() {
        let body =
            |stmt: &str| format!("macro_rules! m {{\n    () => {{\n        {stmt}\n    }};\n}}\n");
        for stmt in [
            "fn f() { std::process::$f(0); }",
            "fn f() { std::$m::$f(0); }",
            "fn f() { $($s::)+exit(0); }",
            "fn f() { $($s)::+::abort(); }",
            "fn f() { $($s::)*unwrap(o); }",
            "fn f() { o.$m(); }",
            "fn f() { $m!(); }",
        ] {
            assert_eq!(hit_lines(&body(stmt)), vec![3], "missed:\n{stmt}");
        }
        for stmt in [
            "fn f() { Self::$v; super::$name(); self.$i.show(); }",
            "fn f() { if $a != (b) {} a..$f(1); g($($x),*); }",
            "fn f() { $($s::)+read(0); $crate::g(); }",
        ] {
            assert_eq!(
                hit_lines(&body(stmt)),
                Vec::<usize>::new(),
                "not a hit:\n{stmt}"
            );
        }
    }

    /// A macro-body `mod` named by a metavariable resolves to a file only at
    /// expansion, so it is refused like a literal `mod tests;`.
    #[test]
    fn macro_body_metavariable_mod_is_refused() {
        let refused = |src: &str| {
            scan_source(src).is_ok_and(|scan| {
                matches!(
                    scan.test_path_includes.as_slice(),
                    [TestPathInclude {
                        form: IncludeForm::ModDecl,
                        target: IncludeTarget::Opaque(_),
                        ..
                    }]
                )
            })
        };
        assert!(refused(
            "macro_rules! d {\n    ($n:ident) => {\n        mod $n;\n    };\n}\n"
        ));
        assert!(refused(
            "macro_rules! d {\n    ($n:ident) => {\n        mod $n {}\n    };\n}\n"
        ));
        let literal = "macro_rules! d {\n    () => {\n        mod inner;\n    };\n}\n";
        assert!(scan_source(literal).is_ok_and(|scan| scan.test_path_includes.is_empty()));
    }

    /// Source that does not parse is an error, never an empty clean scan.
    #[test]
    fn unparseable_source_is_an_error() {
        assert!(scan_str("fn f( {").is_err());
    }
}
