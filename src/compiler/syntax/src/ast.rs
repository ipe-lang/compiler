//! Source AST — the raw parse tree before name resolution.
//!
//! This is the Rust port of the supported subset of the reference compiler's
//! `Ipê.AST.Source` (which is itself a derivative work of elm/compiler's
//! `AST.Source`, BSD-3-Clause). Only the nodes the supported grammar
//! exercises are modelled; unsupported source grammar (FFI imports, infix
//! decls) is deliberately omitted until needed.
//!
//! Identifiers are interned [`Symbol`]s; every node that has a source location
//! is wrapped in [`Located`].

use ipe_diagnostics::{Located, Span};
use ipe_intern::Symbol;

/// A doc-string attached to a top-level declaration.
///
/// Built from a `{-| … -}` block comment placed immediately above the
/// declaration with no intervening blank line. The `body` is the raw text
/// between `{-|` and `-}` (leading `|` stripped, surrounding whitespace
/// trimmed). `example_spans` are the source byte ranges of each fenced
/// ` ```ipe ` code block within `body`; they are recorded for later tooling
/// but are not executed during compilation.
///
/// Erasure: `DocString` never reaches lowering or emit. All downstream stages
/// past name resolution simply ignore the field and produce identical output.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DocString {
    /// Raw text of the doc comment (stripped of the `{-|` / `-}` delimiters
    /// and leading/trailing whitespace).
    pub body: String,
    /// Byte spans (within `body`) of each ` ```ipe ` … ` ``` ` block.
    pub example_spans: Vec<Span>,
}

impl DocString {
    /// Parse the raw text of a `{-| … -}` block (already stripped of the
    /// `{-|` / `-}` delimiters) into a [`DocString`], extracting the spans of
    /// any ` ```ipe ` … ` ``` ` fenced blocks within the body.
    #[must_use]
    pub fn from_raw(raw: &str) -> Self {
        let body = raw.trim().to_owned();
        let example_spans = extract_ipe_fences(&body);
        Self {
            body,
            example_spans,
        }
    }
}

/// Scan `text` for ` ```ipe ` … ` ``` ` fenced blocks and return one
/// [`Span`] (relative byte offsets within `text`) per block, spanning the
/// content between the opening and closing fences.
fn extract_ipe_fences(text: &str) -> Vec<Span> {
    const OPEN: &str = "```ipe";
    const FENCE: &str = "```";
    let mut spans = Vec::new();
    // Scan line by line. A fence is only honoured when its ` ``` ` sits at the
    // start of the line (after optional leading whitespace), so inline
    // triple-backticks inside prose or an example body never open or close a
    // span. Byte offsets are tracked so each [`Span`] stays relative to `text`.
    let mut line_start = 0usize;
    // When inside a fenced block, `content_start` is the byte offset just after
    // the opening fence line; otherwise the block is closed.
    let mut content_start: Option<usize> = None;
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim_start();
        let fence_at_line_start = trimmed.starts_with(FENCE);
        match content_start {
            None => {
                // Outside a block: only an ` ```ipe ` fence at line start opens one.
                if fence_at_line_start && trimmed.starts_with(OPEN) {
                    content_start = Some(line_start + line.len());
                }
            }
            Some(start) => {
                // Inside a block: any line-start ` ``` ` closes it.
                if fence_at_line_start {
                    // Content ends where the leading whitespace before the
                    // closing fence begins (i.e. at the start of this line).
                    let lo = u32::try_from(start).unwrap_or(u32::MAX);
                    let hi = u32::try_from(line_start).unwrap_or(u32::MAX);
                    spans.push(Span::new(lo, hi));
                    content_start = None;
                }
            }
        }
        line_start += line.len();
    }
    spans
}

/// An in-language Rust-FFI type declaration (`foreign Name = { crate = "…", kind = … }`).
///
/// The CLI lift pass reads these from `.ipe` source files and promotes them into
/// the inspection document, producing the same `ManifestDefineStruct` /
/// `ManifestDefineEnum` / `ManifestDefineClosure` values the TOML readers emit.
///
/// The `body` is an inert `Foreign` record literal
/// (`{ crate = "…", kind = <Struct|Enum|Closure>, derives = [ … ] }`); the CLI
/// lift pass walks it with the same record-reading discipline the package
/// manifest uses, never evaluating it. The compiler itself treats `foreign`
/// declarations as inert data — they do not participate in name resolution,
/// type-checking, or lowering, and are erased before canon.
///
/// `name` is the declared type name (upper-case), used as the struct / enum
/// name in the lifted `ManifestDefineStruct` / `ManifestDefineEnum`, or as the
/// wrapper name in the lifted `ManifestDefineClosure`. The `kind` field of the
/// record selects the shape, so the optional `type_annotation` is no longer
/// needed to distinguish a closure; it is accepted for readability but ignored.
#[derive(Clone, PartialEq, Debug)]
pub struct ForeignDecl {
    /// The declared name (upper-case for struct/enum, lower-camel for closure).
    pub name: Located<Symbol>,
    /// Optional type annotation (`counterUpdate : Ffi.Fn`).
    pub type_annotation: Option<Located<TypeAnnotation>>,
    /// The inert `Foreign` record literal body.
    pub body: Expr,
    /// Doc-string attached immediately above this declaration. Erased before
    /// lowering; does not affect emitted code.
    pub doc: Option<DocString>,
}

/// A parsed module.
//
// `Eq` is not derived: `values` hold [`Value`]s whose bodies may carry an `f64`
// float literal, so the tree is only `PartialEq`.
#[derive(Clone, PartialEq, Debug)]
pub struct Module {
    /// Span of the `module` keyword token.
    pub module_kw: Span,
    /// Dotted module-name segments, e.g. `Main` → `[Main]`.
    pub name: Located<Vec<Symbol>>,
    /// The `exposing (...)` clause of the `module` header, spanning the
    /// `exposing` keyword through its closing `)`.
    pub exposing: Located<Exposing>,
    pub imports: Vec<Import>,
    pub values: Vec<Located<Value>>,
    pub unions: Vec<Located<Union>>,
    /// `type alias Name [vars…] = T` declarations. Both the non-parametric form
    /// and the parametric form (`type alias F a = …`) are supported; a parametric
    /// alias carries its declared `vars` here, and canonicalisation substitutes
    /// each use site's type arguments for those parameters before expanding the
    /// body away.
    pub aliases: Vec<Located<TypeAlias>>,
    /// `foreign Name = { crate = "…", kind = … }` declarations. Read by the CLI lift
    /// pass; inert to the compiler proper (erased before canon).
    pub foreigns: Vec<Located<ForeignDecl>>,
}

/// Export / import exposing specification.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Exposing {
    /// `exposing (..)`
    All,
    /// `exposing (a, B, C(..))`
    List(Vec<Located<Exposed>>),
}

/// A single entry in an `exposing (...)` list.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Exposed {
    /// A value or function name.
    Value(Symbol),
    /// A type name plus the privacy of its constructors.
    Type(Symbol, Privacy),
}

/// Constructor visibility for an exposed type.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Privacy {
    /// `Type(..)` — all constructors exposed.
    Public,
    /// `Type` — opaque, no constructors exposed.
    Private,
    /// `Type(A, B)` — a selected subset of constructors exposed.
    PublicCtors(Vec<Symbol>),
}

/// An `import` declaration.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Import {
    /// Span of the whole declaration.
    ///
    /// Runs from the `import` keyword through the last token the parser
    /// consumed for it (module name, `as` alias, or the `exposing` list's
    /// closing `)`), however the declaration wraps across lines. Comments
    /// inside or after the declaration never move its end.
    pub span: Span,
    /// Span of the `import` keyword token.
    pub import_kw: Span,
    /// Dotted module-name segments, e.g. `Ipe.String`.
    pub name: Located<Vec<Symbol>>,
    /// Optional `as Alias`.
    pub alias: Option<Symbol>,
    /// The `exposing (…)` clause, spanning the `exposing` keyword through its
    /// closing `)`.
    ///
    /// An import without a clause holds an empty list at a zero-width span
    /// just past the declaration's last token.
    pub exposing: Located<Exposing>,
}

/// A top-level value / function declaration.
//
// `Eq` is not derived: `body` is an [`Expr`], which may carry an `f64` float
// literal and so is only `PartialEq`.
#[derive(Clone, PartialEq, Debug)]
pub struct Value {
    pub name: Located<Symbol>,
    /// Argument patterns (empty for a plain value binding).
    pub patterns: Vec<Pattern>,
    pub body: Expr,
    /// Optional `name : T` type annotation.
    pub type_annotation: Option<Located<TypeAnnotation>>,
    /// Doc-string attached immediately above this declaration (no blank line
    /// between the `{-| … -}` comment and the binding). Erased before
    /// lowering; does not affect emitted code.
    pub doc: Option<DocString>,
}

/// A `type` (union) declaration.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Union {
    /// Span of the `type` keyword token.
    pub type_kw: Span,
    pub name: Located<Symbol>,
    /// Type variables, e.g. `a` in `type Maybe a`.
    pub vars: Vec<Located<Symbol>>,
    pub ctors: Vec<Located<Ctor>>,
    /// Doc-string attached immediately above this declaration. Erased before
    /// lowering; does not affect emitted code.
    pub doc: Option<DocString>,
}

/// A `type alias Name = T` declaration.
///
/// Mirrors the reference compiler's `Ipe.AST.Source.Alias`, narrowed to the
/// supported subset. The aliased type `body` is expanded away at
/// canonicalisation, so no
/// stage after name resolution ever observes the alias name.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TypeAlias {
    pub name: Located<Symbol>,
    /// Declared type parameters (`a` in `type alias F a = …`). Empty for a
    /// non-parametric alias; a non-empty list is bound, at each use site, to the
    /// type arguments supplied there and substituted into `body` during
    /// canonicalisation. A use site whose argument count differs from this list's
    /// length is a [`ipe_diagnostics::NameError::AliasArity`] error.
    pub vars: Vec<Located<Symbol>>,
    /// The aliased type.
    pub body: Located<TypeAnnotation>,
    /// Doc-string attached immediately above this declaration. Erased before
    /// lowering; does not affect emitted code.
    pub doc: Option<DocString>,
}

/// A single union constructor.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Ctor {
    pub name: Symbol,
    pub args: Vec<TypeAnnotation>,
}

/// An expression with its source span.
pub type Expr = Located<Expr_>;

/// Expression node.
///
/// `Eq` is not derived: [`Expr_::Float`] carries an `f64`, which is only
/// `PartialEq`. No consumer keys a map / set on an expression, so `PartialEq`
/// (structural `==`, used in tests) is sufficient.
#[derive(Clone, PartialEq, Debug)]
pub enum Expr_ {
    /// An unqualified name reference (local var, top-level binding, or
    /// constructor used as a value — name resolution decides which).
    VarLocal(Symbol),
    /// A qualified name reference `Qualifier.name`.
    VarQual(Symbol, Symbol),
    /// An integer literal.
    Int(i64),
    /// A floating-point literal `1.5`, `3.0`, `1.5e3`, `2e-2`. The carried
    /// [`f64`] is the parsed value (the lexer resolves the lexeme), mirroring
    /// the reference compiler's `Src.Float`.
    Float(f64),
    /// A string literal `"hello"`. The carried [`String`] is the literal's
    /// already-unescaped value (the lexer resolves escape sequences), so the
    /// downstream stages see the runtime string verbatim. Mirrors the reference compiler
    /// compiler's `Src.Str`.
    Str(String),
    /// A triple-quoted string `"""..."""`.
    ///
    /// `raw` is the RAW content — the lexer does NOT resolve escape sequences or
    /// `{{expr}}` interpolation markers. The canonicaliser strips the anchor
    /// margin (see `anchor`), then desugars the result into a `++` chain of
    /// string literals and `Interpolate`-wrapped expressions (the internal renderer kernel).
    ///
    /// `anchor` is the 1-based source column of the first non-whitespace content
    /// character (the anchor column A). The margin strip removes up to `A - 1`
    /// leading whitespace characters from every physical line after the first.
    MultilineStr { raw: String, anchor: u32 },
    /// A character literal `'a'`. The carried [`String`] is the source character
    /// text — a single grapheme for an ordinary char, or a backslash-escape pair
    /// (`\n`, `\\`) for an escaped one — matching the reference compiler's
    /// `Src.Chr String` representation so the value round-trips to the backend.
    Char(String),
    /// The unit value `()` — the sole inhabitant of the unit type. Built by the
    /// parser from empty parentheses. Mirrors the reference compiler's `Src.Unit`.
    Unit,
    /// Function application: callee applied to one or more arguments.
    Call(Box<Expr>, Vec<Expr>),
    /// `case scrutinee of` with `(pattern, body)` arms.
    Case(Box<Expr>, Vec<(Pattern, Expr)>),
    /// An anonymous function `\p0 p1 ... -> body`. The parameter list has arity
    /// ≥ 1 (the parser rejects a zero-parameter `\ -> e`); each parameter is a
    /// pattern (a plain variable or `_`). Mirrors the reference compiler
    /// compiler's `Src.Lambda [Pattern] Expr`.
    Lambda(Vec<Pattern>, Box<Expr>),
    /// A precedence-climbed binary-operator chain: a sequence of
    /// `(operand, operator)` pairs followed by the final operand.
    Binops(Vec<(Expr, Located<Symbol>)>, Box<Expr>),
    /// `let <bindings> in <body>`. Models simple value bindings only
    /// (`name = expr`); function bindings (`f x = …`) and destructuring
    /// (`(a, b) = …`) are rejected at the parser. The bindings are scoped
    /// sequentially: each value sees the enclosing scope plus the bindings that
    /// precede it (`let*`), matching the non-recursive nested-`Let` IR.
    Let(Vec<LetBinding>, Box<Expr>),
    /// `if cond then a else b`, with optional `else if` branches. The list holds
    /// one or more `(condition, branch)` pairs in source order — the leading
    /// `if` plus every `else if` — followed by the mandatory final `else`
    /// expression. Mirrors the reference compiler's `Src.If [(Expr, Expr)] Expr`.
    If(Vec<(Expr, Expr)>, Box<Expr>),
    /// A tuple literal `(e1, e2, ...)`.
    ///
    /// Invariant: the element list has arity ≥ 2. A parenthesised single
    /// expression `(e)` is *not* a tuple — the parser unwraps it to `e` — and
    /// the empty parens `()` are the unit value (unsupported, rejected at
    /// the parser). Mirrors the reference compiler's `Src.Tuple e1 e2 [rest]`,
    /// flattened to one vector here.
    Tuple(Vec<Expr>),
    /// A list literal `[]` / `[a, b, c]`. Elements are in source order; the empty
    /// list carries an empty vector. The cons operator `::` is NOT a `List` node —
    /// it flows through [`Expr_::Binops`] like the other right-associative
    /// operators and is re-associated at canonicalisation. Mirrors the reference compiler
    /// compiler's `Src.List`.
    List(Vec<Expr>),
    /// A record literal `{ field = expr, ... }`. Fields are `(name, value)`
    /// pairs in source order; the field name is a located lowercase identifier.
    /// Mirrors the reference compiler's `Src.Record`, narrowed to the closed-record
    /// (no `{ r | ... }` extension) subset.
    Record(Vec<(Located<Symbol>, Expr)>),
    /// A record field access `record.field` (`record` lowercase). The parser
    /// builds this from a dotted lowercase identifier (`p.x`) and nests it for a
    /// chain (`p.x.y` -> `Access (Access p x) y`). Mirrors `Src.Access`.
    Access(Box<Expr>, Located<Symbol>),
    /// A record update `{ base | field = expr, ... }`. The `base` is a located
    /// lowercase variable naming the record to copy (Ipê restricts the update
    /// base to a bare variable, as Elm does); the field list carries each
    /// updated `(name, value)` pair in source order. Mirrors the reference compiler
    /// compiler's `Src.Update (Located String) [(Located String, Expr)]`,
    /// narrowed to the closed-record subset.
    Update(Located<Symbol>, Vec<(Located<Symbol>, Expr)>),
}

/// A single `let` binding: `<pat> = body`.
///
/// The binder is a [`Pattern`]: the common `name = body` case is a
/// [`Pattern_::PVar`], and an irrefutable destructure
/// (`(a, b) = e`, `{ x } = e`) is admitted as a tuple / record pattern. A
/// refutable binder (a constructor pattern) parses here but is rejected
/// fail-closed downstream — a `let` binder must always match. Subset of the
/// the reference compiler's `Ipe.AST.Source.Def`, extended with the destructure
/// form (`DestructDef`).
// `Eq` is not derived: `body` is an [`Expr`], only `PartialEq` (float literals).
#[derive(Clone, PartialEq, Debug)]
pub struct LetBinding {
    pub pat: Pattern,
    pub body: Expr,
}

/// A pattern with its source span.
pub type Pattern = Located<Pattern_>;

/// Pattern node.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Pattern_ {
    /// The wildcard `_`.
    PAnything,
    /// The development-only catch-all `Debug._`. Matches every value exactly
    /// like [`Self::PAnything`], but is a deliberate escape hatch: it satisfies
    /// exhaustiveness WITHOUT being subject to the closed-union catch-all error
    /// (IPE-T0018), so a developer can defer handling of some variants during
    /// development. Like every `Ipe.Debug` member it is rejected by `ipe
    /// release` (IPE-L0140): reaching a `Debug._` at lowering marks the module
    /// `uses_debug`, so the single production gate turns the release build back.
    PDebugAnything,
    /// A variable binding.
    PVar(Symbol),
    /// A constructor pattern: name, dotted module segments, sub-patterns.
    PCtor(Symbol, Vec<Symbol>, Vec<Pattern>),
    /// The unit pattern `()` — the sole inhabitant of the unit type. Binds
    /// nothing (like [`Self::PAnything`]) but is typed at `()`, so `Ok () -> …`
    /// and `case u of () -> …` are accepted where `u : ()`. Irrefutable: unit has
    /// exactly one value, so a lone `()` arm is an exhaustive cover.
    PUnit,
    /// A tuple pattern `(p0, p1, ...)`. Invariant: arity ≥ 2 — a parenthesised
    /// single pattern `(p)` is unwrapped to `p`, and empty parens `()` are the
    /// unit pattern [`Self::PUnit`], not a tuple. Elements may be variables,
    /// wildcards, nested constructor patterns, or nested tuples. Mirrors the the
    /// reference compiler's tuple pattern.
    PTuple(Vec<Pattern>),
    /// A record pattern `{ x, y }`. Field-pun only: every entry names a
    /// field of the scrutinee record and binds a variable of the same name, so
    /// the binder list is a non-empty set of located field names. Mirrors the
    /// the reference compiler's `Src.PRecord [A.Located String]` — there is no
    /// `{ field = sub-pattern }` form (the reference rejects it at parse), so
    /// a record pattern is always irrefutable. The empty record `{}` is outside
    /// the grammar; a `PRecord` always carries at least one field.
    PRecord(Vec<Located<Symbol>>),
    /// An integer literal pattern `0`, `42`. Refutable. Int is an OPEN
    /// (infinite) type, so a `case` over int literals needs a wildcard / var
    /// catch-all to be exhaustive. Mirrors the reference compiler's `Src.PInt`.
    PInt(i64),
    /// A boolean literal pattern `True` / `False`. Refutable in
    /// isolation, but a `True` + `False` pair is an exhaustive cover of `Bool`
    /// (a closed two-constructor type). Mirrors the reference compiler's `Src.PBool`.
    PBool(bool),
    /// A character literal pattern `'a'`. The carried [`String`] is the
    /// source character text (single grapheme, or a `\`-escape pair). Refutable;
    /// Char is OPEN. Mirrors the reference compiler's `Src.PChr`.
    PChar(String),
    /// A string literal pattern `"hi"`. The carried [`String`] is the
    /// already-unescaped value. Refutable; String is OPEN. Mirrors the reference compiler
    /// compiler's `Src.PStr`.
    PStr(String),
    /// An alias / `as` pattern `inner as name`. Matches `inner` and also
    /// binds the whole matched value to `name`. Mirrors the reference compiler's
    /// `Src.PAlias Pattern (A.Located String)`.
    PAlias(Box<Pattern>, Located<Symbol>),
    /// A list pattern `[]` / `[a, b, c]`. The empty list is the nil cover;
    /// a fixed-length `[a, b]` matches a list of exactly that length. Mirrors the
    /// the reference compiler's `Src.PList`.
    PList(Vec<Pattern>),
    /// A cons pattern `head :: tail` — the right-associative list
    /// deconstruction. `(x :: xs)` binds the first element to `head` and the rest
    /// to `tail`. Mirrors the reference compiler's `Src.PCons`.
    PCons(Box<Pattern>, Box<Pattern>),
    /// An or-pattern `p1 | p2 | …` — matches if ANY alternative matches. Every
    /// alternative binds the identical set of variables at identical types
    /// (enforced in canon/types); each alternative is an arbitrary sub-pattern
    /// and recurses. Invariant: length ≥ 2 — the parser never wraps a lone
    /// pattern, mirroring the arity-≥-2 invariant on [`Self::PTuple`]. The `|`
    /// binds looser than everything else in a pattern (ctor application, `::`,
    /// `as`), so each alternative is a complete cons/`as` pattern.
    POr(Vec<Pattern>),
}

/// Type-annotation node.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum TypeAnnotation {
    /// An arrow type `A -> B`.
    TLambda(Box<Self>, Box<Self>),
    /// A type variable, e.g. `a`.
    TVar(Symbol),
    /// A type constructor application: module qualifier, dotted name segments,
    /// type arguments. The qualifier is the empty symbol for unqualified types.
    TType(Symbol, Vec<Symbol>, Vec<Self>),
    /// The unit type `()`.
    TUnit,
    /// An anonymous product (tuple) type `(T1, T2, ...)`. Invariant: arity ≥ 2 —
    /// a 0-tuple is [`Self::TUnit`] and a parenthesised single type `(T)`
    /// unwraps to `T` (neither is a `TTuple`).
    TTuple(Vec<Self>),
    /// A closed record type `{ field : T, ... }`. Fields are `(name, type)` pairs
    /// in source order. The empty record `{}` is valid and produces an empty
    /// field list. Mirrors the reference compiler's `Src.TRecord`, narrowed to the
    /// closed-record subset (no row variable / extension form).
    TRecord(Vec<(Located<Symbol>, Self)>),
    /// A row-polymorphic (open) record type `{ r | field : T, ... }`. The row
    /// variable `r` names the unnamed tail of extra fields the record may
    /// carry; the named fields are the ones the annotation constrains. A value
    /// of this type is any record carrying *at least* the listed fields.
    /// Mirrors the reference compiler's `Src.TRecord fields (Just rowVar)`.
    TRecordOpen(Symbol, Vec<(Located<Symbol>, Self)>),
}

/// Strip the source indentation margin from a triple-quoted string body using
/// its anchor column.
///
/// The anchor column `A` (1-based) is the source column of the first
/// non-whitespace content character. This removes up to `A - 1` leading
/// whitespace characters from every physical line *after the first*, and drops
/// one leading newline immediately following the opening `"""`. The first line
/// is left untouched: its leading text is content the author placed on the
/// opening-delimiter line.
///
/// Only whitespace is removed, and never past a line's content: a line indented
/// less than `A - 1` is stripped only to its first content character, so a
/// content character is never dropped. Removing whole leading-whitespace
/// characters (not bytes) keeps every surviving character's source offset intact
/// relative to its line, which is what makes downstream `{{expr}}` sub-spans and
/// diagnostic offsets land correctly.
#[must_use]
pub fn strip_anchor_margin(raw: &str, anchor: u32) -> String {
    // A body whose first content character sits in column 1 (or an all-whitespace
    // / empty body, which anchors at 1) has no margin to remove. The leading
    // newline is still dropped below.
    let strip = anchor.saturating_sub(1);

    let mut out = String::with_capacity(raw.len());
    // `split_inclusive('\n')` keeps each line's trailing newline, so newlines are
    // preserved verbatim and only per-line leading whitespace is a strip target.
    // Line 0 is the opening-delimiter line; its leading text is content the
    // author placed there, never a margin, so it is copied verbatim.
    for (line_index, line) in raw.split_inclusive('\n').enumerate() {
        if line_index == 0 {
            out.push_str(line);
            continue;
        }
        // Count leading space/tab characters, capped at the margin width. Space
        // and tab are single-byte ASCII, so the character count is also the byte
        // offset at which the copied remainder begins.
        let consumed = line
            .bytes()
            .take(strip as usize)
            .take_while(|&b| b == b' ' || b == b'\t')
            .count();
        // The remainder (from the first content char, a newline, or end of line)
        // is copied verbatim, so a content character is never dropped.
        out.push_str(&line[consumed..]);
    }

    // Drop exactly one leading newline right after the opening `"""`, so a block
    // written as `"""<newline>first content line` starts at that content line.
    // A `\r\n` pair counts as the one such newline. This runs after the per-line
    // strip so "the first line" is the opening-delimiter line of the RAW body.
    if out.starts_with("\r\n") {
        out.drain(..2);
    } else if out.starts_with('\n') {
        out.drain(..1);
    }
    out
}

#[cfg(test)]
mod strip_tests {
    use super::strip_anchor_margin;

    #[test]
    fn non_indented_block_is_unchanged() {
        // Anchor column 1: nothing to strip; body round-trips verbatim.
        let raw = "line one\nline two\nline three";
        assert_eq!(strip_anchor_margin(raw, 1), raw);
    }

    #[test]
    fn strips_anchor_margin_from_lines_after_the_first() {
        // Opening `"""` at some column, content anchored at column 9 (A = 9),
        // so up to 8 leading whitespace chars come off every later line.
        let raw = "first\n        second\n        third";
        assert_eq!(strip_anchor_margin(raw, 9), "first\nsecond\nthird");
    }

    #[test]
    fn drops_one_leading_newline_after_opener() {
        // `"""` immediately followed by a newline: that newline is dropped and
        // the margin is stripped from the (now-first-physical, but still
        // after-opener) lines.
        let raw = "\n        first\n        second";
        assert_eq!(strip_anchor_margin(raw, 9), "first\nsecond");
    }

    #[test]
    fn line_indented_less_than_margin_strips_only_to_content() {
        // A = 9 (strip up to 8), but the second line has only 3 spaces before
        // content: strip stops at the content char, never consuming it.
        let raw = "first\n   short\n        deep";
        assert_eq!(strip_anchor_margin(raw, 9), "first\nshort\ndeep");
    }

    #[test]
    fn never_strips_content_characters() {
        // A line whose leading run is entirely whitespace-then-content: the
        // content `x` survives even when fewer than `strip` spaces precede it.
        let raw = "a\n x\n  y";
        // A = 4 → strip up to 3: ` x` → `x`, `  y` → `y`.
        assert_eq!(strip_anchor_margin(raw, 4), "a\nx\ny");
    }

    #[test]
    fn blank_line_is_preserved_as_empty() {
        // A fully blank interior line shorter than the margin collapses to empty
        // but keeps its newline; content lines strip to the margin.
        let raw = "first\n\n        third";
        assert_eq!(strip_anchor_margin(raw, 9), "first\n\nthird");
    }

    #[test]
    fn interpolation_marker_survives_margin_strip() {
        // Only leading whitespace is removed; `{{expr}}` markers and their inner
        // spans are untouched.
        let raw = "head\n        value={{count}}";
        assert_eq!(strip_anchor_margin(raw, 9), "head\nvalue={{count}}");
    }
}

#[cfg(test)]
mod fence_tests {
    use super::extract_ipe_fences;

    // Collect each span's `[lo, hi)` slice of the input, for readable assertions.
    fn slices(text: &str) -> Vec<String> {
        extract_ipe_fences(text)
            .into_iter()
            .map(|span| {
                let lo = span.lo as usize;
                let hi = span.hi as usize;
                text.get(lo..hi).unwrap_or("<oob>").to_owned()
            })
            .collect()
    }

    #[test]
    fn well_formed_block_spans_its_content() {
        let text = "intro\n```ipe\ngreet \"world\"\n```\ntail";
        assert_eq!(slices(text), vec!["greet \"world\"\n".to_owned()]);
    }

    #[test]
    fn inline_close_fence_does_not_terminate_early() {
        // The example body contains an inline ` ``` ` mid-line; it must NOT be
        // read as the closing fence.
        let text = "```ipe\nlet s = \"a ``` b\"\n```\n";
        assert_eq!(slices(text), vec!["let s = \"a ``` b\"\n".to_owned()]);
    }

    #[test]
    fn inline_open_fence_in_prose_opens_nothing() {
        // An ` ```ipe ` appearing mid-line in prose is not a fence.
        let text = "see the ```ipe``` marker inline here\nno block\n";
        assert!(slices(text).is_empty());
    }

    #[test]
    fn leading_whitespace_before_fence_is_honoured() {
        // Fences indented by whitespace are still line-start fences.
        let text = "  ```ipe\n  body\n  ```\n";
        assert_eq!(slices(text), vec!["  body\n".to_owned()]);
    }

    #[test]
    fn two_blocks_produce_two_spans() {
        let text = "```ipe\none\n```\nmid\n```ipe\ntwo\n```\n";
        assert_eq!(slices(text), vec!["one\n".to_owned(), "two\n".to_owned()]);
    }

    #[test]
    fn unclosed_block_yields_no_span() {
        let text = "```ipe\ndangling body with no closer\n";
        assert!(slices(text).is_empty());
    }
}
