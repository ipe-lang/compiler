//! Recursive-descent parser for the supported subset of Ipê.
//!
//! Port of `Ipe.Parse.{Module,Declaration,Type,Pattern,Expression}` narrowed to
//! the supported grammar: a module header, imports, `type` unions, top-level value
//! bindings with optional type annotations, `case … of`, function application,
//! and `+`/`-` binary-operator chains.
//!
//! Every raise site emits a **coded, structured** [`ParseError`]: the generic
//! "expected X, found Y" family funnels through [`ParseError::UnexpectedToken`]
//! (IPE-P0001) carrying the found [`TokenKind`] and an [`ExpectedSet`];
//! truncated input becomes [`ParseError::UnexpectedEof`] (IPE-P0002) tagged with
//! the enclosing [`Construct`]; and each construct (module header, exposing list,
//! definition, type declaration, `case`, parenthesised group) has its own
//! defect-precise variant. Recursion is bounded by [`MAX_DEPTH`]; every
//! recursive entry threads a depth counter and fails with
//! [`ParseError::NestingTooDeep`] (IPE-P0003) before the native stack can
//! overflow on adversarial input.
//!
//! Qualified upper-case names in **type** and **pattern** position are rejected
//! with a typed error rather than collapsed into a non-reference AST: the parser
//! does not yet model `Module.Type` annotations or `Module.Ctor` patterns, so the
//! parser fails fast instead of silently dropping the qualifier (which the
//! canonicaliser would then resolve against the wrong name).

use ipe_diagnostics::{
    CaseDefect, Construct, DResult, Diagnostic, Expected, ExpectedSet, ExposingDefect,
    HeaderDefect, IfDefect, LetDefect, Located, ParseError, Span, TokenKind, TypeDeclDefect,
};
use ipe_intern::{Interner, Symbol};
use ipe_syntax::{
    Ctor, DocString, Exposed, Exposing, Expr, Expr_, ForeignDecl, Import, LetBinding, Module,
    Pattern, Pattern_, Privacy, TypeAlias, TypeAnnotation, Union, Value,
};

use crate::layout;
use crate::lexer::{Tok, Token};

/// Maximum recursion depth before the parser bails with
/// [`ParseError::NestingTooDeep`].
pub const MAX_DEPTH: u32 = 256;

pub struct Parser<'a> {
    toks: Vec<Token>,
    pos: usize,
    interner: &'a mut Interner,
}

/// The result of splitting parsed declarations into their four kinds: value
/// bindings (with annotations attached), union types, type aliases, and foreign
/// FFI declarations.
type AssembledDecls = (
    Vec<Located<Value>>,
    Vec<Located<Union>>,
    Vec<Located<TypeAlias>>,
    Vec<Located<ForeignDecl>>,
);

/// One parsed top-level declaration, before annotations are matched to values.
enum Decl {
    Union(Located<Union>),
    Alias(Located<TypeAlias>),
    /// A standalone `name : T` type annotation line. Carries the doc-string
    /// that preceded it (if any) so `assemble` can forward it to the matching
    /// value binding — the common case is `{-| doc -}\nname : T\nname = …`.
    Annotation(Symbol, Located<TypeAnnotation>, Option<DocString>),
    Value {
        name: Located<Symbol>,
        patterns: Vec<Pattern>,
        body: Expr,
        doc: Option<DocString>,
    },
    /// A `foreign Name = { crate = "…", kind = … }` declaration.
    Foreign(Located<ForeignDecl>),
}

/// A standalone type annotation awaiting its value binding, tracked by
/// [`Parser::assemble`] so orphans and duplicates can be rejected rather than
/// silently dropped.
struct Annotation {
    name: Symbol,
    /// The span of the annotation line, retained for the orphan diagnostic
    /// after `ty` is moved into a matching value binding.
    span: Span,
    /// The annotation type; `take`n into the matching value binding. `None`
    /// once claimed, which marks the annotation consumed.
    ty: Option<Located<TypeAnnotation>>,
    /// The preceding doc-string; `take`n into the matching value binding.
    doc: Option<DocString>,
}

/// Map a concrete lexer token to its payload-free [`TokenKind`] category — the
/// "found" shape a [`ParseError::UnexpectedToken`] reports.
const fn tok_kind(t: &Tok) -> TokenKind {
    match t {
        Tok::Module => TokenKind::Module,
        Tok::Import => TokenKind::Import,
        Tok::Exposing => TokenKind::Exposing,
        Tok::As => TokenKind::As,
        Tok::Type => TokenKind::Type,
        Tok::Foreign => TokenKind::Foreign,
        Tok::Case => TokenKind::Case,
        Tok::Of => TokenKind::Of,
        Tok::Let => TokenKind::Let,
        Tok::In => TokenKind::In,
        Tok::If => TokenKind::If,
        Tok::Then => TokenKind::Then,
        Tok::Else => TokenKind::Else,
        Tok::Do => TokenKind::Do,
        Tok::LParen => TokenKind::LParen,
        Tok::RParen => TokenKind::RParen,
        // Doc-comments are consumed by `parse_decl` before any other dispatch;
        // if one appears in expression/type position the generic
        // `UnexpectedToken` path handles it via this `LBrace` mapping.
        Tok::LBrace | Tok::DocComment(_) => TokenKind::LBrace,
        Tok::RBrace => TokenKind::RBrace,
        Tok::LBracket => TokenKind::LBracket,
        Tok::RBracket => TokenKind::RBracket,
        Tok::ColonColon => TokenKind::ColonColon,
        Tok::Equals => TokenKind::Equals,
        Tok::Pipe => TokenKind::Pipe,
        Tok::Colon => TokenKind::Colon,
        Tok::Arrow => TokenKind::Arrow,
        Tok::LeftArrow => TokenKind::LeftArrow,
        Tok::Backslash => TokenKind::Backslash,
        Tok::DotDot => TokenKind::DotDot,
        Tok::Dot => TokenKind::Dot,
        Tok::Comma => TokenKind::Comma,
        Tok::Underscore => TokenKind::Underscore,
        Tok::Plus => TokenKind::Plus,
        Tok::PlusPlus => TokenKind::PlusPlus,
        Tok::Minus => TokenKind::Minus,
        Tok::Star => TokenKind::Star,
        Tok::Slash => TokenKind::Slash,
        Tok::SlashEq => TokenKind::SlashEq,
        Tok::SlashSlash => TokenKind::SlashSlash,
        Tok::EqEq => TokenKind::EqEq,
        Tok::Lt => TokenKind::Lt,
        Tok::Gt => TokenKind::Gt,
        Tok::Le => TokenKind::Le,
        Tok::Ge => TokenKind::Ge,
        Tok::AmpAmp => TokenKind::AmpAmp,
        Tok::PipePipe => TokenKind::PipePipe,
        Tok::PipeGt => TokenKind::PipeGt,
        Tok::LtPipe => TokenKind::LtPipe,
        Tok::PipeEq => TokenKind::PipeEq,
        Tok::PipeDot => TokenKind::PipeDot,
        Tok::GtGt => TokenKind::GtGt,
        Tok::LtLt => TokenKind::LtLt,
        Tok::Ident(_) => TokenKind::Ident,
        Tok::Int(_) => TokenKind::Int,
        Tok::Float(_) => TokenKind::Float,
        Tok::Str(_) | Tok::TripleStr { .. } => TokenKind::Str,
        Tok::Char(_) => TokenKind::Char,
    }
}

/// One statement inside a `do` block, before desugaring to `Task.andThen`.
///
/// `Bind` and `Let` carry the span of their `<-` / `=` operator token: the
/// desugar stamps its synthetic nodes with that span (never an operand's), so
/// the type checker's `(home, span)` region map cannot collide a synthetic node
/// with a real one — the same discipline the `>>` / `<<` desugar uses.
enum DoStmt {
    /// `p <- e` — run the task `e` and bind its result to `p` for the rest.
    Bind(Pattern, Span, Expr),
    /// `p = e` — a pure `let` binding in scope for the rest of the block.
    Let(Pattern, Span, Expr),
    /// `e` — run the task `e`; a non-final one discards its result, the final
    /// one is the block's value.
    Run(Expr),
}

/// Result of `peek_adjacent_neg_literal`: the raw (positive) magnitude from
/// the token immediately after the `-`, together with its span. The caller
/// is responsible for negating the value and for consuming the token.
enum NegLeaf {
    /// Raw `i64` magnitude from an adjacent `Int` token. `checked_neg()` on
    /// this value produces the final negative integer; if it returns `None`
    /// the caller emits `IntLiteralOutOfRange`.
    Int(i64, Span),
    /// Raw `f64` magnitude from an adjacent `Float` token. Caller negates it.
    Float(f64, Span),
}

impl<'a> Parser<'a> {
    pub const fn new(toks: Vec<Token>, interner: &'a mut Interner) -> Self {
        Self {
            toks,
            pos: 0,
            interner,
        }
    }

    // ---- token cursor -----------------------------------------------------

    fn peek(&self) -> Option<&Token> {
        self.toks.get(self.pos)
    }

    fn peek_kind(&self) -> Option<&Tok> {
        self.peek().map(|t| &t.kind)
    }

    /// Consume the next token. On end-of-input the error names `construct`, the
    /// enclosing grammar production that still required more tokens.
    fn bump(&mut self, construct: Construct) -> DResult<Token> {
        // Move the token out of the Vec without shifting elements — the slot is
        // never read again because `pos` only advances. `get_mut` returning
        // `None` is end-of-input.
        let Some(slot) = self.toks.get_mut(self.pos) else {
            return Err(Diagnostic::Parse {
                span: self.eof_err_span(),
                msg: ParseError::UnexpectedEof { construct },
            });
        };
        let tok = std::mem::replace(
            slot,
            Token {
                kind: Tok::Underscore,
                line: 0,
                col: 0,
                span: Span::DUMMY,
            },
        );
        self.pos += 1;
        Ok(tok)
    }

    /// Byte span to point at when input has run out: the end of the last token.
    fn eof_err_span(&self) -> Span {
        self.toks.last().map_or(Span::DUMMY, |t| t.span)
    }

    /// Byte span to point at "here": the next token, or end-of-input.
    fn err_here_span(&self) -> Span {
        self.peek().map_or_else(|| self.eof_err_span(), |t| t.span)
    }

    fn too_deep(&self, construct: Construct) -> Diagnostic {
        Diagnostic::Parse {
            span: self.err_here_span(),
            msg: ParseError::NestingTooDeep {
                construct,
                limit: u16::try_from(MAX_DEPTH).unwrap_or(u16::MAX),
            },
        }
    }

    // ---- typed-error constructors -----------------------------------------

    /// "found `<tok>`, expected `<set>`" — the IPE-P0001 funnel.
    fn unexpected_token(tok: &Token, expected: &[Expected]) -> Diagnostic {
        Diagnostic::Parse {
            span: tok.span,
            msg: ParseError::UnexpectedToken {
                found: tok_kind(&tok.kind),
                expected: ExpectedSet(expected.into()),
            },
        }
    }

    const fn malformed_header(span: Span, defect: HeaderDefect) -> Diagnostic {
        Diagnostic::Parse {
            span,
            msg: ParseError::MalformedModuleHeader(defect),
        }
    }

    const fn malformed_exposing(span: Span, defect: ExposingDefect) -> Diagnostic {
        Diagnostic::Parse {
            span,
            msg: ParseError::MalformedExposingList(defect),
        }
    }

    const fn malformed_type_decl(span: Span, defect: TypeDeclDefect) -> Diagnostic {
        Diagnostic::Parse {
            span,
            msg: ParseError::MalformedTypeDeclaration(defect),
        }
    }

    const fn malformed_case(span: Span, defect: CaseDefect) -> Diagnostic {
        Diagnostic::Parse {
            span,
            msg: ParseError::MalformedCase(defect),
        }
    }

    const fn malformed_let(span: Span, defect: LetDefect) -> Diagnostic {
        Diagnostic::Parse {
            span,
            msg: ParseError::MalformedLet(defect),
        }
    }

    const fn malformed_if(span: Span, defect: IfDefect) -> Diagnostic {
        Diagnostic::Parse {
            span,
            msg: ParseError::MalformedIf(defect),
        }
    }

    fn intern(&mut self, s: &str) -> DResult<Symbol> {
        self.interner.intern(s)
    }

    // ---- module -----------------------------------------------------------

    pub fn parse_module(&mut self) -> DResult<Module> {
        // The file must begin with `module`.
        let module_tok = match self.peek() {
            Some(t) if t.kind == Tok::Module => self.bump(Construct::ModuleHeader)?,
            Some(t) => {
                return Err(Self::malformed_header(
                    t.span,
                    HeaderDefect::NotModuleKeyword,
                ));
            }
            None => {
                return Err(Self::malformed_header(
                    self.eof_err_span(),
                    HeaderDefect::NotModuleKeyword,
                ));
            }
        };
        let name = self.parse_module_name()?;

        // The `exposing` keyword must follow the module name.
        let exposing_kw = match self.peek() {
            Some(t) if t.kind == Tok::Exposing => self.bump(Construct::ModuleHeader)?.span,
            Some(t) => {
                return Err(Self::malformed_header(
                    t.span,
                    HeaderDefect::MissingExposing,
                ));
            }
            None => {
                return Err(Self::malformed_header(
                    self.eof_err_span(),
                    HeaderDefect::MissingExposing,
                ));
            }
        };
        let (exposing, exposing_close) = self.parse_exposing()?;
        let exposing = Located::new(Self::span_merge(exposing_kw, exposing_close), exposing);

        // Imports may be preceded by a `{-| … -}` doc-comment. One before an
        // `import` documents the module, not the import, and is dropped; one
        // before a declaration is carried in `pending_doc` and attaches to it.
        // At most one doc-comment is consumed here per position — a second
        // consecutive doc-comment breaks out so `parse_decl` reports it as an
        // unexpected token rather than silently swallowing it.
        let mut imports = Vec::new();
        let mut pending_doc: Option<DocString> = None;
        loop {
            let is_doc = matches!(self.peek_kind(), Some(Tok::DocComment(_)));
            let is_import = self.peek_kind() == Some(&Tok::Import);
            if is_import {
                pending_doc = None;
                imports.push(self.parse_import()?);
            } else if is_doc && pending_doc.is_none() {
                let tok = self.bump(Construct::ModuleHeader)?;
                if let Tok::DocComment(raw) = tok.kind {
                    pending_doc = Some(DocString::from_raw(&raw));
                }
            } else {
                break;
            }
        }

        let mut decls = Vec::new();
        let mut first_doc = pending_doc.take();
        while self.peek().is_some() {
            decls.push(self.parse_decl(first_doc.take())?);
        }

        let (values, unions, aliases, foreigns) = self.assemble(decls)?;
        Ok(Module {
            module_kw: module_tok.span,
            name,
            exposing,
            imports,
            values,
            unions,
            aliases,
            foreigns,
        })
    }

    /// Split decls into values (with annotations attached), unions, aliases,
    /// and foreign FFI declarations.
    ///
    /// Every standalone `name : T` annotation must attach to exactly one value
    /// binding of the same `name`. A second annotation for a name is a
    /// duplicate ([`ParseError::DuplicateAnnotation`]); an annotation left
    /// unattached once all values are processed is an orphan
    /// ([`ParseError::AnnotationWithoutBinding`]). Both are rejected rather
    /// than silently dropped, so a typo like `nmae : Int` cannot discard the
    /// author's stated type.
    fn assemble(&self, decls: Vec<Decl>) -> DResult<AssembledDecls> {
        use std::collections::BTreeMap;
        let mut unions = Vec::new();
        let mut aliases = Vec::new();
        let mut foreigns = Vec::new();
        // Insertion-ordered annotation slots plus a name→index map for O(log n)
        // duplicate detection and value lookup. The `ty`/`doc` of a claimed
        // annotation are `take`n (not cloned) into its value binding; a slot
        // whose `ty` is still `Some` after all values are processed is an orphan.
        let mut annotations: Vec<Annotation> = Vec::new();
        let mut by_name: BTreeMap<Symbol, usize> = BTreeMap::new();
        let mut values = Vec::new();
        for d in decls {
            match d {
                Decl::Union(u) => unions.push(u),
                Decl::Alias(a) => aliases.push(a),
                Decl::Foreign(f) => foreigns.push(f),
                Decl::Annotation(name, ty, doc) => {
                    if by_name.contains_key(&name) {
                        return Err(Self::duplicate_annotation(ty.span, self.symbol_text(name)));
                    }
                    by_name.insert(name, annotations.len());
                    annotations.push(Annotation {
                        name,
                        span: ty.span,
                        ty: Some(ty),
                        doc,
                    });
                }
                Decl::Value {
                    name,
                    patterns,
                    body,
                    doc,
                } => {
                    let matched = by_name
                        .get(&name.value)
                        .and_then(|&i| annotations.get_mut(i));
                    let (type_annotation, ann_doc) = match matched {
                        Some(a) => (a.ty.take(), a.doc.take()),
                        None => (None, None),
                    };
                    // When the value has no inline doc but a preceding
                    // annotation carried one (the `{-| … -}\nname : T\nname
                    // = …` pattern), inherit the annotation's doc.
                    let effective_doc = doc.or(ann_doc);
                    let span = name.span;
                    values.push(Located::new(
                        span,
                        Value {
                            name,
                            patterns,
                            body,
                            type_annotation,
                            doc: effective_doc,
                        },
                    ));
                }
            }
        }
        if let Some(orphan) = annotations.iter().find(|a| a.ty.is_some()) {
            return Err(Self::orphan_annotation(
                orphan.span,
                self.symbol_text(orphan.name),
            ));
        }
        Ok((values, unions, aliases, foreigns))
    }

    /// The source text of `sym`, or a placeholder when it is somehow
    /// un-interned (unreachable for a symbol the parser itself minted).
    fn symbol_text(&self, sym: Symbol) -> Box<str> {
        self.interner.resolve(sym).unwrap_or("?").into()
    }

    const fn duplicate_annotation(span: Span, name: Box<str>) -> Diagnostic {
        Diagnostic::Parse {
            span,
            msg: ParseError::DuplicateAnnotation { name },
        }
    }

    const fn orphan_annotation(span: Span, name: Box<str>) -> Diagnostic {
        Diagnostic::Parse {
            span,
            msg: ParseError::AnnotationWithoutBinding { name },
        }
    }

    /// The module name in the header: a single (possibly dotted) identifier.
    /// A missing or non-identifier name is a malformed-header defect.
    fn parse_module_name(&mut self) -> DResult<Located<Vec<Symbol>>> {
        // Validate via peek before consuming, so errors can reference the right span.
        match self.peek() {
            None => {
                return Err(Self::malformed_header(
                    self.eof_err_span(),
                    HeaderDefect::MissingName,
                ));
            }
            Some(t) if !matches!(t.kind, Tok::Ident(_)) => {
                return Err(Self::malformed_header(
                    t.span,
                    HeaderDefect::NameNotIdentifier,
                ));
            }
            Some(_) => {}
        }
        let tok = self.bump(Construct::ModuleHeader)?;
        let tok_span = tok.span;
        // peek() confirmed Ident above; extract the text by value.
        if let Tok::Ident(text) = tok.kind {
            let segs = text
                .split('.')
                .map(|s| self.interner.intern(s))
                .collect::<DResult<Vec<Symbol>>>()?;
            Ok(Located::new(tok_span, segs))
        } else {
            // peek() and bump() are sequential in a single-threaded parser;
            // reaching this branch would be a compiler bug, not a user error.
            Err(Diagnostic::CompilerBug {
                where_: "ipe_parse::parse_module_name",
                detail: "token changed between peek and bump".to_owned(),
            })
        }
    }

    /// A dotted import name, e.g. `Ipe.String`.
    fn parse_dotted_name(&mut self) -> DResult<Located<Vec<Symbol>>> {
        let tok = self.bump(Construct::ModuleHeader)?;
        match &tok.kind {
            Tok::Ident(text) => {
                let segs = text
                    .split('.')
                    .map(|s| self.interner.intern(s))
                    .collect::<DResult<Vec<Symbol>>>()?;
                Ok(Located::new(tok.span, segs))
            }
            _ => Err(Self::unexpected_token(&tok, &[Expected::Identifier])),
        }
    }

    /// Parse an `exposing` clause's parenthesised list.
    ///
    /// Returns the list together with the span of its closing `)`.
    fn parse_exposing(&mut self) -> DResult<(Exposing, Span)> {
        // Opening `(`.
        match self.peek() {
            Some(t) if t.kind == Tok::LParen => {
                self.bump(Construct::ExposingList)?;
            }
            Some(t) => {
                return Err(Self::malformed_exposing(
                    t.span,
                    ExposingDefect::MissingOpenParen,
                ));
            }
            None => {
                return Err(Self::malformed_exposing(
                    self.eof_err_span(),
                    ExposingDefect::MissingOpenParen,
                ));
            }
        }
        if self.peek_kind() == Some(&Tok::DotDot) {
            self.bump(Construct::ExposingList)?;
            let close = self.expect_exposing_close()?;
            return Ok((Exposing::All, close));
        }
        let mut items = Vec::new();
        let close = loop {
            items.push(self.parse_exposed()?);
            match self.peek() {
                Some(t) if t.kind == Tok::Comma => {
                    self.bump(Construct::ExposingList)?;
                }
                Some(t) if t.kind == Tok::RParen => {
                    break self.bump(Construct::ExposingList)?.span;
                }
                Some(t) => {
                    return Err(Self::malformed_exposing(
                        t.span,
                        ExposingDefect::BadSeparator,
                    ));
                }
                None => {
                    return Err(Self::malformed_exposing(
                        self.eof_err_span(),
                        ExposingDefect::BadSeparator,
                    ));
                }
            }
        };
        Ok((Exposing::List(items), close))
    }

    /// Require the `)` that closes an `exposing (..)` clause, returning its span.
    fn expect_exposing_close(&mut self) -> DResult<Span> {
        match self.peek() {
            Some(t) if t.kind == Tok::RParen => Ok(self.bump(Construct::ExposingList)?.span),
            Some(t) => Err(Self::malformed_exposing(
                t.span,
                ExposingDefect::BadSeparator,
            )),
            None => Err(Self::malformed_exposing(
                self.eof_err_span(),
                ExposingDefect::BadSeparator,
            )),
        }
    }

    fn parse_exposed(&mut self) -> DResult<Located<Exposed>> {
        let tok = self.bump(Construct::ExposingList)?;
        let Tok::Ident(text) = &tok.kind else {
            return Err(Self::malformed_exposing(
                tok.span,
                ExposingDefect::NameNotIdentifier,
            ));
        };
        let sym = self.interner.intern(text)?;
        let is_type = text.chars().next().is_some_and(|c| c.is_ascii_uppercase());
        if is_type {
            let privacy = self.parse_privacy()?;
            Ok(Located::new(tok.span, Exposed::Type(sym, privacy)))
        } else {
            Ok(Located::new(tok.span, Exposed::Value(sym)))
        }
    }

    fn parse_privacy(&mut self) -> DResult<Privacy> {
        if self.peek_kind() != Some(&Tok::LParen) {
            return Ok(Privacy::Private);
        }
        self.bump(Construct::ExposingList)?; // (
        if self.peek_kind() == Some(&Tok::DotDot) {
            self.bump(Construct::ExposingList)?;
            self.expect_ctor_list_close()?;
            return Ok(Privacy::Public);
        }
        let mut ctors = Vec::new();
        loop {
            let tok = self.bump(Construct::ExposingList)?;
            match &tok.kind {
                Tok::Ident(text) => ctors.push(self.interner.intern(text)?),
                _ => {
                    return Err(Self::malformed_exposing(
                        tok.span,
                        ExposingDefect::MalformedCtorList,
                    ));
                }
            }
            match self.peek() {
                Some(t) if t.kind == Tok::Comma => {
                    self.bump(Construct::ExposingList)?;
                }
                Some(t) if t.kind == Tok::RParen => {
                    self.bump(Construct::ExposingList)?;
                    break;
                }
                Some(t) => {
                    return Err(Self::malformed_exposing(
                        t.span,
                        ExposingDefect::MalformedCtorList,
                    ));
                }
                None => {
                    return Err(Self::malformed_exposing(
                        self.eof_err_span(),
                        ExposingDefect::MalformedCtorList,
                    ));
                }
            }
        }
        Ok(Privacy::PublicCtors(ctors))
    }

    /// Require the `)` that closes a `Type(..)` constructor list.
    fn expect_ctor_list_close(&mut self) -> DResult<()> {
        match self.peek() {
            Some(t) if t.kind == Tok::RParen => {
                self.bump(Construct::ExposingList)?;
                Ok(())
            }
            Some(t) => Err(Self::malformed_exposing(
                t.span,
                ExposingDefect::MalformedCtorList,
            )),
            None => Err(Self::malformed_exposing(
                self.eof_err_span(),
                ExposingDefect::MalformedCtorList,
            )),
        }
    }

    fn parse_import(&mut self) -> DResult<Import> {
        // The caller has already peeked `import`.
        let import_tok = self.bump(Construct::ModuleHeader)?;
        let name = self.parse_dotted_name()?;
        // The span of the last token the declaration consumed: the recorded
        // declaration span ends exactly where its grammar does.
        let mut last = name.span;
        let alias = if self.peek_kind() == Some(&Tok::As) {
            self.bump(Construct::ModuleHeader)?;
            let tok = self.bump(Construct::ModuleHeader)?;
            match &tok.kind {
                Tok::Ident(text) => {
                    last = tok.span;
                    Some(self.interner.intern(text)?)
                }
                _ => {
                    return Err(Self::unexpected_token(&tok, &[Expected::Identifier]));
                }
            }
        } else {
            None
        };
        let exposing = if self.peek_kind() == Some(&Tok::Exposing) {
            let exposing_kw = self.bump(Construct::ModuleHeader)?.span;
            let (clause, close) = self.parse_exposing()?;
            last = close;
            Located::new(Self::span_merge(exposing_kw, close), clause)
        } else {
            // No clause in the source: a zero-width span where one would begin.
            Located::new(Span::new(last.hi, last.hi), Exposing::List(Vec::new()))
        };
        Ok(Import {
            span: Self::span_merge(import_tok.span, last),
            import_kw: import_tok.span,
            name,
            alias,
            exposing,
        })
    }

    // ---- declarations -----------------------------------------------------

    fn parse_decl(&mut self, pre_doc: Option<DocString>) -> DResult<Decl> {
        // A `{-| … -}` doc-comment that precedes a declaration in the token
        // stream attaches to that declaration. Attachment is by token order
        // alone: any blank lines between the doc-comment and the declaration are
        // insignificant, since the lexer emits `Tok::DocComment` unconditionally
        // and neither stage records line adjacency. `pre_doc` carries one the
        // caller already consumed in the import region that turned out to
        // precede a declaration rather than an `import`; otherwise the
        // doc-comment is consumed here.
        let doc = if pre_doc.is_some() {
            pre_doc
        } else if let Some(Token {
            kind: Tok::DocComment(_),
            ..
        }) = self.peek()
        {
            let tok = self.bump(Construct::Definition)?;
            if let Tok::DocComment(raw) = tok.kind {
                Some(DocString::from_raw(&raw))
            } else {
                None
            }
        } else {
            None
        };

        if self.peek_kind() == Some(&Tok::Type) {
            // `type alias …` and `type …` (a union) share the `type` keyword; the
            // disambiguator is the soft keyword `alias` (a plain identifier) in
            // the next slot.
            if self.peek_is_alias_keyword() {
                let mut alias = self.parse_type_alias()?;
                alias.value.doc = doc;
                return Ok(Decl::Alias(alias));
            }
            let mut union = self.parse_union()?;
            union.value.doc = doc;
            return Ok(Decl::Union(union));
        }
        if self.peek_kind() == Some(&Tok::Foreign) {
            let mut foreign = self.parse_foreign()?;
            foreign.value.doc = doc;
            return Ok(Decl::Foreign(foreign));
        }
        let tok = self.bump(Construct::Definition)?;
        let Tok::Ident(text) = &tok.kind else {
            return Err(Self::unexpected_token(&tok, &[Expected::Identifier]));
        };
        let binding_name: Box<str> = text.as_str().into();
        let name_sym = self.interner.intern(text)?;
        let name = Located::new(tok.span, name_sym);
        let name_col = tok.col;

        if self.peek_kind() == Some(&Tok::Colon) {
            self.bump(Construct::Definition)?; // :
            let ty = self.parse_type(name_col, 0)?;
            // Forward the doc-string through the annotation so `assemble` can
            // attach it to the matching value binding (the common pattern is
            // `{-| doc -}\nname : T\nname = …`).
            return Ok(Decl::Annotation(name_sym, ty, doc));
        }

        let mut patterns = Vec::new();
        while self.peek_is_binder_atom_start() {
            patterns.push(self.parse_pattern_atom(0)?);
        }

        // The patterns must be followed by `=` before the body.
        match self.peek() {
            Some(t) if t.kind == Tok::Equals => {
                self.bump(Construct::Definition)?;
            }
            Some(t) => {
                return Err(Diagnostic::Parse {
                    span: t.span,
                    msg: ParseError::MissingEquals {
                        binding: binding_name,
                    },
                });
            }
            None => {
                return Err(Diagnostic::Parse {
                    span: self.eof_err_span(),
                    msg: ParseError::MissingEquals {
                        binding: binding_name,
                    },
                });
            }
        }
        let body = self.parse_expr(name_col, 0)?;
        Ok(Decl::Value {
            name,
            patterns,
            body,
            doc,
        })
    }

    /// True when the token after the peeked `type` is the soft keyword `alias`.
    /// `alias` is a plain identifier (not a reserved token), so a union named by
    /// a user who happens to also write `alias` is distinguished only here, at
    /// the one site where the look-ahead is meaningful.
    fn peek_is_alias_keyword(&self) -> bool {
        matches!(
            self.toks.get(self.pos + 1).map(|t| &t.kind),
            Some(Tok::Ident(text)) if text.as_str() == "alias"
        )
    }

    /// Parse `type alias Name [vars…] = T`. Type parameters are captured in
    /// `vars` so canonicalisation can substitute each use site's type arguments
    /// for them and expand the alias body; both the parametric and the
    /// non-parametric form are supported.
    fn parse_type_alias(&mut self) -> DResult<Located<TypeAlias>> {
        // The caller has already established `type` followed by `alias`.
        let type_tok = self.bump(Construct::TypeDeclaration)?; // `type`
        let alias_col = type_tok.col;
        self.bump(Construct::TypeDeclaration)?; // `alias`

        let name_tok = self.bump(Construct::TypeDeclaration)?;
        let Tok::Ident(name_text) = &name_tok.kind else {
            return Err(Self::malformed_type_decl(
                name_tok.span,
                TypeDeclDefect::MissingName,
            ));
        };
        let name = Located::new(name_tok.span, self.interner.intern(name_text)?);

        // Declared type parameters (lowercase identifiers), mirroring `parse_union`.
        let mut vars = Vec::new();
        while self.peek_is_lowercase_ident() {
            let tok = self.bump(Construct::TypeDeclaration)?;
            if let Tok::Ident(text) = tok.kind {
                let sym = self.intern(&text)?;
                vars.push(Located::new(tok.span, sym));
            }
        }

        // The `=` before the aliased type.
        match self.peek() {
            Some(t) if t.kind == Tok::Equals => {
                self.bump(Construct::TypeDeclaration)?;
            }
            Some(t) => {
                return Err(Self::malformed_type_decl(
                    t.span,
                    TypeDeclDefect::MissingEquals,
                ));
            }
            None => {
                return Err(Self::malformed_type_decl(
                    self.eof_err_span(),
                    TypeDeclDefect::MissingEquals,
                ));
            }
        }

        let body = self.parse_type(alias_col, 0)?;
        let span = Self::span_merge(type_tok.span, body.span);
        Ok(Located::new(
            span,
            TypeAlias {
                name,
                vars,
                body,
                doc: None,
            },
        ))
    }

    fn parse_union(&mut self) -> DResult<Located<Union>> {
        // The caller has already peeked `type`.
        let type_tok = self.bump(Construct::TypeDeclaration)?;
        let union_col = type_tok.col;
        let name_tok = self.bump(Construct::TypeDeclaration)?;
        let Tok::Ident(name_text) = &name_tok.kind else {
            return Err(Self::malformed_type_decl(
                name_tok.span,
                TypeDeclDefect::MissingName,
            ));
        };
        let name = Located::new(name_tok.span, self.interner.intern(name_text)?);

        let mut vars = Vec::new();
        while self.peek_is_lowercase_ident() {
            let tok = self.bump(Construct::TypeDeclaration)?;
            if let Tok::Ident(text) = tok.kind {
                let sym = self.intern(&text)?;
                vars.push(Located::new(tok.span, sym));
            }
        }

        // The `=` before the constructors.
        match self.peek() {
            Some(t) if t.kind == Tok::Equals => {
                self.bump(Construct::TypeDeclaration)?;
            }
            Some(t) => {
                return Err(Self::malformed_type_decl(
                    t.span,
                    TypeDeclDefect::MissingEquals,
                ));
            }
            None => {
                return Err(Self::malformed_type_decl(
                    self.eof_err_span(),
                    TypeDeclDefect::MissingEquals,
                ));
            }
        }

        let mut ctors = Vec::new();
        loop {
            ctors.push(self.parse_ctor(union_col)?);
            if self.peek_kind() == Some(&Tok::Pipe) {
                self.bump(Construct::TypeDeclaration)?;
            } else {
                break;
            }
        }
        let last_span = ctors.last().map_or(name.span, |c| c.span);
        let span = Self::span_merge(type_tok.span, last_span);
        Ok(Located::new(
            span,
            Union {
                type_kw: type_tok.span,
                name,
                vars,
                ctors,
                doc: None,
            },
        ))
    }

    /// Parse a `foreign Name = { crate = "…", kind = … }` declaration.
    ///
    /// A type annotation is carried only in the inline `foreign name : T = …`
    /// form parsed here. A standalone `name : T` line preceding the binding is
    /// not matched to a foreign declaration — `assemble` pairs annotations with
    /// value bindings only, so a standalone annotation for a foreign name is
    /// rejected as an orphan. The lifted record's `kind` field selects the
    /// shape, so the inline annotation is accepted for readability but not
    /// required.
    ///
    /// The body is parsed as a full expression at the name's column so the layout
    /// rule treats the record's continuation lines as the body, not new
    /// declarations.
    fn parse_foreign(&mut self) -> DResult<Located<ForeignDecl>> {
        let foreign_tok = self.bump(Construct::Definition)?; // `foreign`
        let name_tok = self.bump(Construct::Definition)?;
        let Tok::Ident(name_text) = &name_tok.kind else {
            return Err(Self::unexpected_token(&name_tok, &[Expected::Identifier]));
        };
        let name_sym = self.interner.intern(name_text)?;
        let name = Located::new(name_tok.span, name_sym);
        let name_col = name_tok.col;

        // An optional `: T` type annotation immediately after the name (no `=` in
        // between). This is the `foreign counterUpdate : Ffi.Fn` form; a closure
        // declaration carries it; struct / enum declarations omit it.
        let type_annotation = if self.peek_kind() == Some(&Tok::Colon) {
            self.bump(Construct::Definition)?; // `:`
            let ty = self.parse_type(name_col, 0)?;
            Some(ty)
        } else {
            None
        };

        // The `=` before the body.
        match self.peek() {
            Some(t) if t.kind == Tok::Equals => {
                self.bump(Construct::Definition)?;
            }
            Some(t) => {
                let span = t.span;
                return Err(Diagnostic::Parse {
                    span,
                    msg: ParseError::MissingEquals {
                        binding: name_text.as_str().into(),
                    },
                });
            }
            None => {
                return Err(Diagnostic::Parse {
                    span: self.eof_err_span(),
                    msg: ParseError::MissingEquals {
                        binding: name_text.as_str().into(),
                    },
                });
            }
        }

        let body = self.parse_expr(name_col, 0)?;
        let span = Self::span_merge(foreign_tok.span, body.span);
        Ok(Located::new(
            span,
            ForeignDecl {
                name,
                type_annotation,
                body,
                doc: None,
            },
        ))
    }

    fn parse_ctor(&mut self, threshold: u32) -> DResult<Located<Ctor>> {
        let tok = self.bump(Construct::TypeDeclaration)?;
        let Tok::Ident(text) = &tok.kind else {
            return Err(Self::malformed_type_decl(
                tok.span,
                TypeDeclDefect::CtorNotIdentifier,
            ));
        };
        // Constructors must start with an uppercase letter.
        if !text.chars().next().is_some_and(|c| c.is_ascii_uppercase()) {
            return Err(Self::malformed_type_decl(
                tok.span,
                TypeDeclDefect::CtorNotUppercase,
            ));
        }
        let name = self.interner.intern(text)?;
        let mut args = Vec::new();
        while self.peek_is_type_atom_in_block(threshold) {
            args.push(self.parse_type_atom(0)?.value);
        }
        Ok(Located::new(tok.span, Ctor { name, args }))
    }

    // ---- types ------------------------------------------------------------

    /// Parse a full type expression, consuming ALL tokens in the stream.
    ///
    /// Called by [`ipe_parse::parse_type_query`] for doc type-search queries.
    /// Uses threshold 0 so every token continues the block (no layout context).
    /// Returns a typed error when any tokens remain unconsumed after the type,
    /// ensuring trailing garbage does not silently produce a partial parse.
    ///
    /// # Errors
    /// [`Diagnostic::Parse`] on a malformed type or unconsumed trailing tokens.
    pub fn parse_type_standalone(&mut self) -> DResult<TypeAnnotation> {
        let ann = self.parse_type(0, 0)?;
        // Fail-closed: trailing tokens after the type expression are an error.
        if let Some(trailing) = self.peek() {
            let span = trailing.span;
            let found = tok_kind(&trailing.kind);
            return Err(Diagnostic::Parse {
                span,
                msg: ParseError::UnexpectedToken {
                    found,
                    expected: ExpectedSet(Box::new([])),
                },
            });
        }
        Ok(ann.value)
    }

    fn parse_type(&mut self, threshold: u32, depth: u32) -> DResult<Located<TypeAnnotation>> {
        if depth > MAX_DEPTH {
            return Err(self.too_deep(Construct::Type));
        }
        let left = self.parse_type_app(threshold, depth + 1)?;
        let arrow_in_block = self
            .peek()
            .is_some_and(|t| t.kind == Tok::Arrow && layout::continues_block(t, threshold));
        if arrow_in_block {
            self.bump(Construct::Type)?;
            let right = self.parse_type(threshold, depth + 1)?;
            let span = Self::span_merge(left.span, right.span);
            Ok(Located::new(
                span,
                TypeAnnotation::TLambda(Box::new(left.value), Box::new(right.value)),
            ))
        } else {
            Ok(left)
        }
    }

    fn parse_type_app(&mut self, threshold: u32, depth: u32) -> DResult<Located<TypeAnnotation>> {
        if depth > MAX_DEPTH {
            return Err(self.too_deep(Construct::Type));
        }
        let head = self.parse_type_atom(depth + 1)?;
        let mut args = Vec::new();
        let mut end = head.span;
        while self.peek_is_type_atom_in_block(threshold) {
            let arg = self.parse_type_atom(depth + 1)?;
            end = arg.span;
            args.push(arg.value);
        }
        if args.is_empty() {
            return Ok(head);
        }
        match head.value {
            TypeAnnotation::TType(q, segs, _) => {
                let span = Self::span_merge(head.span, end);
                Ok(Located::new(span, TypeAnnotation::TType(q, segs, args)))
            }
            // A type variable / arrow cannot be applied in the grammar.
            _ => Err(Diagnostic::Parse {
                span: head.span,
                msg: ParseError::TypeArgsOnNonConstructor,
            }),
        }
    }

    fn parse_type_atom(&mut self, depth: u32) -> DResult<Located<TypeAnnotation>> {
        if depth > MAX_DEPTH {
            return Err(self.too_deep(Construct::Type));
        }
        let tok = self.bump(Construct::Type)?;
        match &tok.kind {
            Tok::LParen => {
                let opener = tok.span;
                // `()` — the unit type.
                if self.peek_kind() == Some(&Tok::RParen) {
                    let close = self.expect_rparen(opener, Construct::Type)?;
                    let span = Self::span_merge(opener, close);
                    return Ok(Located::new(span, TypeAnnotation::TUnit));
                }
                let first = self.parse_type(0, depth + 1)?;
                // No following comma → a parenthesised single type. Unwrap to the
                // inner type, spanning from the `(` to the `)` so explicit
                // grouping (e.g. `(a -> b) -> c`) is honoured.
                if self.peek_kind() != Some(&Tok::Comma) {
                    let close = self.expect_rparen(opener, Construct::Type)?;
                    let span = Self::span_merge(opener, close);
                    return Ok(Located::new(span, first.value));
                }
                // One or more comma-separated members → a tuple type.
                let mut elems = vec![first.value];
                while self.peek_kind() == Some(&Tok::Comma) {
                    self.bump(Construct::Type)?;
                    elems.push(self.parse_type(0, depth + 1)?.value);
                }
                let close = self.expect_rparen(opener, Construct::Type)?;
                let span = Self::span_merge(opener, close);
                Ok(Located::new(span, TypeAnnotation::TTuple(elems)))
            }
            // A closed record type `{ field : T, ... }`.
            Tok::LBrace => self.parse_record_type(tok.span, depth + 1),
            Tok::Ident(text) => {
                let first_upper = text.chars().next().is_some_and(|c| c.is_ascii_uppercase());
                if first_upper {
                    // A dotted uppercase name is a qualified type: split on `.` so
                    // the last segment is the type name and the rest is the module
                    // qualifier. E.g. `JsonDec.Decoder` → qualifier="JsonDec",
                    // name="Decoder". An unqualified name has an empty qualifier.
                    if text.contains('.') {
                        let dot = text.rfind('.').unwrap_or(0);
                        let qualifier = text.get(..dot).unwrap_or_default();
                        let name = text.get(dot + 1..).unwrap_or_default();
                        let q = self.interner.intern(qualifier)?;
                        let seg = self.interner.intern(name)?;
                        return Ok(Located::new(
                            tok.span,
                            TypeAnnotation::TType(q, vec![seg], Vec::new()),
                        ));
                    }
                    let empty = self.interner.intern("")?;
                    let seg = self.interner.intern(text)?;
                    Ok(Located::new(
                        tok.span,
                        TypeAnnotation::TType(empty, vec![seg], Vec::new()),
                    ))
                } else {
                    // A lowercase-head type name is a type variable, but a
                    // dotted one (`a.b`, or a typo like `json.Decoder`) is not:
                    // a qualified type must have an uppercase head. Reject it
                    // rather than mint a `TVar` whose dotted text canon would
                    // silently quantify as a free variable.
                    if text.contains('.') {
                        return Err(Diagnostic::Parse {
                            span: tok.span,
                            msg: ParseError::ExpectedType,
                        });
                    }
                    let sym = self.interner.intern(text)?;
                    Ok(Located::new(tok.span, TypeAnnotation::TVar(sym)))
                }
            }
            // A token that cannot begin a type.
            _ => Err(Diagnostic::Parse {
                span: tok.span,
                msg: ParseError::ExpectedType,
            }),
        }
    }

    fn peek_is_type_atom_in_block(&self, threshold: u32) -> bool {
        self.peek().is_some_and(|t| {
            layout::continues_block(t, threshold)
                && matches!(t.kind, Tok::LParen | Tok::LBrace | Tok::Ident(_))
        })
    }

    /// Parse a closed record type `{ field : T, ... }`, the opening `{` already
    /// consumed (its span is `opener`). The empty record `{}` is valid and
    /// produces a `TRecord` with an empty field list (mirrors the reference compiler
    /// compiler's behaviour). Each non-empty field is a lowercase name, a `:`,
    /// then its type; fields are comma-separated and the list is closed by `}`.
    /// Duplicate field names are not rejected here (a later stage owns that),
    /// matching how the record *literal* parser stays purely syntactic.
    fn parse_record_type(&mut self, opener: Span, depth: u32) -> DResult<Located<TypeAnnotation>> {
        if depth > MAX_DEPTH {
            return Err(self.too_deep(Construct::Type));
        }
        // `{}` (the empty record type) — valid, produces `TRecord []`.
        // Mirrors the reference compiler: `Just '}' -> char '}'  >> return (TRecord [] Nothing)`.
        if let Some(t) = self.peek().filter(|t| t.kind == Tok::RBrace) {
            let close = t.span;
            self.bump(Construct::Type)?;
            let span = Self::span_merge(opener, close);
            return Ok(Located::new(span, TypeAnnotation::TRecord(Vec::new())));
        }
        // The row-polymorphic (open) record type `{ r | field : T, ... }`: a
        // lowercase row variable followed by `|`, then the constrained fields.
        // A closed record's first field is a name followed by `:`, so a `|` in
        // the second token position disambiguates without backtracking. (A `|`
        // never appears here in its record-update meaning — that sigil lives in
        // expression land, never type land.)
        if self.peek_is_open_record_intro() {
            let row_var = self.parse_record_field_name()?;
            self.bump(Construct::Type)?; // the `|`
            let fields = self.parse_record_type_fields(depth)?;
            let close = self.expect_record_close()?;
            let span = Self::span_merge(opener, close);
            return Ok(Located::new(
                span,
                TypeAnnotation::TRecordOpen(row_var.value, fields),
            ));
        }
        let fields = self.parse_record_type_fields(depth)?;
        let close = self.expect_record_close()?;
        let span = Self::span_merge(opener, close);
        Ok(Located::new(span, TypeAnnotation::TRecord(fields)))
    }

    /// True when the record-type parser sits at a row-polymorphic opener
    /// `<lowerVar> |` — a lowercase identifier immediately followed by a `|`.
    /// Non-consuming (two-token lookahead), so the closed-record path is
    /// untouched when this returns false. A qualified/uppercase name is not a
    /// row variable, so only a bare lowercase `Ident` qualifies.
    fn peek_is_open_record_intro(&self) -> bool {
        let is_row_var = self.peek_kind().is_some_and(|k| match k {
            Tok::Ident(text) => {
                !text.contains('.') && text.chars().next().is_some_and(|c| !c.is_ascii_uppercase())
            }
            _ => false,
        });
        is_row_var && self.toks.get(self.pos + 1).map(|t| &t.kind) == Some(&Tok::Pipe)
    }

    /// Parse a non-empty, comma-separated `field : Type` list, stopping before
    /// the closing `}`. Shared by the closed and open record-type arms.
    fn parse_record_type_fields(
        &mut self,
        depth: u32,
    ) -> DResult<Vec<(Located<Symbol>, TypeAnnotation)>> {
        let mut fields = Vec::new();
        loop {
            let name = self.parse_record_field_name()?;
            self.expect_field_colon()?;
            let ty = self.parse_type(0, depth + 1)?;
            fields.push((name, ty.value));
            match self.peek() {
                Some(t) if t.kind == Tok::Comma => {
                    self.bump(Construct::Type)?;
                }
                _ => return Ok(fields),
            }
        }
    }

    /// Consume the `}` closing a record type, returning its span. Anything else
    /// (mid field-list) is the same "expected `,` or `}`" error the closed
    /// record loop reported before this was factored out.
    fn expect_record_close(&mut self) -> DResult<Span> {
        match self.peek() {
            Some(t) if t.kind == Tok::RBrace => {
                let close = t.span;
                self.bump(Construct::Type)?;
                Ok(close)
            }
            Some(t) => Err(Self::unexpected_token(
                t,
                &[Expected::Comma, Expected::RBrace],
            )),
            None => Err(self.record_eof()),
        }
    }

    /// Consume the `:` separating a record-type field name from its type.
    fn expect_field_colon(&mut self) -> DResult<()> {
        match self.peek() {
            Some(t) if t.kind == Tok::Colon => {
                self.bump(Construct::Type)?;
                Ok(())
            }
            Some(t) => Err(Self::unexpected_token(t, &[Expected::Colon])),
            None => Err(self.record_eof()),
        }
    }

    // ---- expressions ------------------------------------------------------

    fn parse_expr(&mut self, threshold: u32, depth: u32) -> DResult<Expr> {
        if depth > MAX_DEPTH {
            return Err(self.too_deep(Construct::Expression));
        }
        let first = self.parse_app(threshold, depth + 1)?;
        let mut ops: Vec<(Expr, Located<Symbol>)> = Vec::new();
        let mut operand = first;
        while let Some((op, op_span)) = self.peek_binop(threshold) {
            // A flat operator chain re-associates into a nesting-deep Binop/Cons
            // tree downstream, so each operator must cost one depth level here or
            // the chain escapes `MAX_DEPTH` and overflows the recursive walkers
            // (and Drop) that traverse the canonical tree.
            if depth.saturating_add(u32::try_from(ops.len()).unwrap_or(u32::MAX)) >= MAX_DEPTH {
                return Err(self.too_deep(Construct::Expression));
            }
            let op_sym = self.intern(op)?;
            self.bump(Construct::Expression)?;
            ops.push((operand, Located::new(op_span, op_sym)));
            operand = self.parse_app(threshold, depth + 1)?;
        }
        if ops.is_empty() {
            Ok(operand)
        } else {
            let lo = ops.first().map_or(operand.span, |(e, _)| e.span);
            let span = Self::span_merge(lo, operand.span);
            Ok(Located::new(span, Expr_::Binops(ops, Box::new(operand))))
        }
    }

    fn parse_app(&mut self, threshold: u32, depth: u32) -> DResult<Expr> {
        if depth > MAX_DEPTH {
            return Err(self.too_deep(Construct::Expression));
        }
        let head = self.parse_atom_postfix(threshold, depth + 1)?;
        let mut args = Vec::new();
        let mut end = head.span;
        while self.peek_is_simple_atom_in_block(threshold) {
            let arg = self.parse_atom_postfix(threshold, depth + 1)?;
            end = arg.span;
            args.push(arg);
        }
        if args.is_empty() {
            Ok(head)
        } else {
            let span = Self::span_merge(head.span, end);
            Ok(Located::new(span, Expr_::Call(Box::new(head), args)))
        }
    }

    const fn is_simple_atom_start(kind: &Tok) -> bool {
        matches!(
            kind,
            Tok::LParen
                | Tok::LBrace
                | Tok::LBracket
                | Tok::Int(_)
                | Tok::Float(_)
                | Tok::Str(_)
                | Tok::TripleStr { .. }
                | Tok::Char(_)
                | Tok::Ident(_)
                // A leading `.field` begins a first-class accessor atom, so
                // `List.map .name xs` gathers `.name` as an argument.
                | Tok::Dot
        )
    }

    /// Peek a binary operator that continues the current block. Recognises the
    /// full core set: arithmetic (`+ - * /`), string append (`++`),
    /// comparison (`== /= < > <= >=`), and boolean (`&& ||`). Precedence +
    /// associativity are resolved later, at canonicalisation, from the flat
    /// chain this records.
    fn peek_binop(&self, threshold: u32) -> Option<(&'static str, Span)> {
        let tok = self.peek()?;
        if !layout::continues_block(tok, threshold) {
            return None;
        }
        let op = match tok.kind {
            Tok::Plus => "+",
            Tok::PlusPlus => "++",
            Tok::Minus => "-",
            Tok::Star => "*",
            Tok::Slash => "/",
            Tok::SlashEq => "/=",
            Tok::SlashSlash => "//",
            Tok::EqEq => "==",
            Tok::Lt => "<",
            Tok::Gt => ">",
            Tok::Le => "<=",
            Tok::Ge => ">=",
            Tok::AmpAmp => "&&",
            Tok::PipePipe => "||",
            Tok::PipeGt => "|>",
            Tok::LtPipe => "<|",
            Tok::GtGt => ">>",
            Tok::LtLt => "<<",
            Tok::ColonColon => "::",
            Tok::PipeEq => "|=",
            Tok::PipeDot => "|.",
            _ => return None,
        };
        Some((op, tok.span))
    }

    fn peek_is_simple_atom_in_block(&self, threshold: u32) -> bool {
        self.peek().is_some_and(|t| {
            layout::continues_block(t, threshold) && Self::is_simple_atom_start(&t.kind)
        })
    }

    fn peek_aligned_at(&self, align: u32) -> bool {
        self.peek().is_some_and(|t| layout::aligned_at(t, align))
    }

    /// Parse an atom followed by zero or more postfix field accesses.
    ///
    /// A bare `ident.field` run is one [`Tok::Ident`] handled in [`Self::ident_expr`];
    /// this method covers field access on a *non-identifier* atom — most importantly
    /// a parenthesised expression, `(record).field` or `(wrap 1).value`. The lexer
    /// emits a [`Tok::Dot`] for each such `.`, each immediately followed by an
    /// identifier token; a chained access like `(r).a.b` lexes the `a.b` as a single
    /// dotted identifier, so its segments are split back out here. Field access binds
    /// tighter than application, so it is resolved per-atom before [`Self::parse_app`]
    /// gathers arguments.
    ///
    /// The `.` must sit flush against the atom (`(r).value`). A space before it —
    /// `f .value` — is the accessor-function reading (`.value` applied to `f`), a
    /// different program the type system cannot yet express; it is rejected with a
    /// teaching diagnostic rather than silently parsed as field access.
    fn parse_atom_postfix(&mut self, threshold: u32, depth: u32) -> DResult<Expr> {
        let mut expr = self.parse_atom(threshold, depth + 1)?;
        while self.peek_kind() == Some(&Tok::Dot) {
            let dot_span = self.err_here_span();
            if dot_span.lo != expr.span.hi {
                // A space before the `.` is NOT field access on `expr`; it is the
                // first-class accessor reading — `f .x` is `.x` (the getter
                // `\p -> p.x`) applied to `f`. Stop the postfix run and leave the
                // `.x` for `parse_app` to gather as an argument atom.
                break;
            }
            self.bump(Construct::Expression)?;
            let tok = self.bump(Construct::Expression)?;
            // Validate by reference, then own the text by move — no clone.
            if !matches!(tok.kind, Tok::Ident(_)) {
                return Err(Self::unexpected_token(&tok, &[Expected::Identifier]));
            }
            let tok_span = tok.span;
            let Tok::Ident(text) = tok.kind else {
                return Err(Diagnostic::CompilerBug {
                    where_: "ipe_parse::parse_atom_postfix",
                    detail: "token kind changed after Ident check".to_owned(),
                });
            };
            // `a.b.c` after a dot lexes as one dotted identifier; each segment
            // becomes a separate Access node with a distinct carved sub-span.
            expr = self.build_access_chain(expr, tok_span, &text)?;
        }
        Ok(expr)
    }

    fn parse_atom(&mut self, threshold: u32, depth: u32) -> DResult<Expr> {
        if depth > MAX_DEPTH {
            return Err(self.too_deep(Construct::Expression));
        }
        if self.peek_kind() == Some(&Tok::Case) {
            return self.parse_case(threshold, depth + 1);
        }
        if self.peek_kind() == Some(&Tok::Let) {
            return self.parse_let(threshold, depth + 1);
        }
        if self.peek_kind() == Some(&Tok::If) {
            return self.parse_if(threshold, depth + 1);
        }
        if self.peek_kind() == Some(&Tok::Do) {
            return self.parse_do(threshold, depth + 1);
        }
        if self.peek_kind() == Some(&Tok::Backslash) {
            return self.parse_lambda(threshold, depth + 1);
        }
        let tok = self.bump(Construct::Expression)?;
        let span = tok.span;
        match tok.kind {
            Tok::LParen => self.parse_paren_or_tuple(span, depth + 1),
            Tok::LBrace => self.parse_record(span, depth + 1),
            Tok::LBracket => self.parse_list(span, depth + 1),
            Tok::Int(n) => Ok(Located::new(span, Expr_::Int(n))),
            Tok::Float(f) => Ok(Located::new(span, Expr_::Float(f))),
            // String payloads move directly into the AST node — no secondary copy.
            Tok::Str(s) => Ok(Located::new(span, Expr_::Str(s))),
            // Triple-quoted strings carry raw content; the canonicaliser desugars
            // `{{expr}}` interpolation at name-resolution time. Mirrors the reference compiler
            // parser's `MultiLine str -> return (Src.MultilineStr str)` arm.
            Tok::TripleStr { raw, anchor } => {
                Ok(Located::new(span, Expr_::MultilineStr { raw, anchor }))
            }
            Tok::Char(c) => Ok(Located::new(span, Expr_::Char(c))),
            Tok::Minus => self.parse_negative_literal(span, threshold, depth),
            Tok::Ident(text) => {
                // `path "…"` — a contextual path literal. `path` is only
                // special when immediately followed (in the same layout block)
                // by a string literal; everywhere else it is a plain identifier.
                if text == "path"
                    && self
                        .peek()
                        .is_some_and(|next| matches!(&next.kind, Tok::Str(_)))
                {
                    let str_tok = self.bump(Construct::Expression)?;
                    if let Tok::Str(raw) = str_tok.kind {
                        let merged = Self::span_merge(span, str_tok.span);
                        return Ok(Located::new(merged, Expr_::PathLit(raw)));
                    }
                }
                let expr = self.ident_expr(&text, span)?;
                Ok(Located::new(span, expr))
            }
            // A leading `.field` in atom position is the first-class accessor — a
            // value of type `{ r | field : a } -> a`. It desugars here to the
            // getter lambda `\<fresh> -> <fresh>.field`, reusing the ordinary
            // record-access path (deferred field access + monomorphic pinning) so
            // no new type/canon/backend node is needed.
            Tok::Dot => self.parse_field_accessor(span, depth),
            kind => Err(Self::unexpected_token(
                &Token {
                    kind,
                    line: 0,
                    col: 0,
                    span,
                },
                &[Expected::Expression],
            )),
        }
    }

    /// Build the desugared getter lambda for a first-class accessor `.field`, the
    /// leading `.` already consumed (its span is `dot_span`). The next token is
    /// the field identifier (`lex_dot` only yields [`Tok::Dot`] when an identifier
    /// start follows). A dotted run `.a.b` lexes the `a.b` as one identifier; its
    /// segments become a nested `Access` chain over the synthesised parameter,
    /// exactly as [`Self::parse_atom_postfix`] does for `(r).a.b`.
    fn parse_field_accessor(&mut self, dot_span: Span, depth: u32) -> DResult<Expr> {
        if depth > MAX_DEPTH {
            return Err(self.too_deep(Construct::Expression));
        }
        let tok = self.bump(Construct::Expression)?;
        let tok_span = tok.span;
        // Validate before destructuring so the error can carry the found kind.
        if !matches!(tok.kind, Tok::Ident(_)) {
            return Err(Self::unexpected_token(&tok, &[Expected::Identifier]));
        }
        // The `matches!` guard above ensures this arm is always taken.
        let Tok::Ident(text) = tok.kind else {
            return Err(Diagnostic::CompilerBug {
                where_: "ipe_parse::parse_field_accessor",
                detail: "token kind changed after Ident check".to_owned(),
            });
        };
        // The synthesised parameter. Its name need only be a valid emitted Rust
        // identifier: the parameter is the innermost binder of this lambda, so the
        // body's `VarLocal` resolves to it by lexical scoping even if a user
        // binding of the same name exists further out (which the body never
        // references anyway).
        let param_sym = self.interner.intern("ipe_accessor_arg")?;
        let param = Located::new(dot_span, Pattern_::PVar(param_sym));
        let mut body = Located::new(dot_span, Expr_::VarLocal(param_sym));
        // Each field of a dotted accessor `.a.b` gets a distinct sub-span via
        // the shared helper, so no two Access nodes share a `(module, span)`
        // type-region key.
        body = self.build_access_chain(body, tok_span, &text)?;
        let span = Self::span_merge(dot_span, tok_span);
        Ok(Located::new(
            span,
            Expr_::Lambda(vec![param], Box::new(body)),
        ))
    }

    /// Build a left-nested `Access` chain over `base` from a dotted field text.
    ///
    /// Each dot-separated segment of `text` becomes one `Access` node. Every
    /// node gets a distinct sub-span carved from `tok_span` so no two nodes
    /// share a `(module, span)` type-region key. `cursor` tracks the byte
    /// offset at the end of the last-written segment; `.` separators each
    /// advance it by one byte.
    ///
    /// Called from three sites that all produce an `Access` chain from a single
    /// dotted identifier token: `parse_atom_postfix`, `parse_field_accessor`,
    /// and `ident_expr`.
    fn build_access_chain(&mut self, mut base: Expr, tok_span: Span, text: &str) -> DResult<Expr> {
        let mut cursor = tok_span.lo;
        for (seg_count, seg) in (0_u32..).zip(text.split('.')) {
            if seg_count > MAX_DEPTH {
                return Err(self.too_deep(Construct::Expression));
            }
            let seg_len = u32::try_from(seg.len()).unwrap_or(0);
            let field_lo = cursor;
            cursor = field_lo.saturating_add(seg_len);
            let field = Located::new(
                Span::from_start_width(field_lo, seg_len),
                self.interner.intern(seg)?,
            );
            let span = Span::new(base.span.lo, cursor);
            base = Located::new(span, Expr_::Access(Box::new(base), field));
            cursor = cursor.saturating_add(1); // step past the '.' before the next segment
        }
        Ok(base)
    }

    /// Parse a unary minus in atom (prefix) position, the `-` already consumed
    /// at `minus_span`.
    ///
    /// **Faithful port of the reference compiler `exprAtom_` `Negate` arm**
    /// (`Ipe.Parse.Expression`, lines 356–367 of the upstream reference):
    ///
    /// ```haskell
    /// do char mkError '-'
    ///    mc <- peek
    ///    case mc of
    ///        Just c | c >= '0' && c <= '9' -> do
    ///            e <- addLocation (exprAtom_ mkError)
    ///            return (Src.Negate e)
    ///        _ -> do
    ///            e <- addLocation (exprAtom_ mkError)
    ///            return (Src.Negate e)
    /// ```
    ///
    /// Both branches of the digit/non-digit dispatch produce `Src.Negate(e)` —
    /// the digit check is vestigial; the disambiguation between unary negation
    /// and binary subtraction is positional: `parse_negative_literal` is only
    /// reached when an atom (fresh operand) was expected, never after a complete
    /// expression (`peek_binop` in [`Self::parse_expr`] would have consumed the
    /// `-` as binary subtraction first).
    ///
    /// ## Operand forms
    ///
    /// * **Adjacent numeric literal** (`-5`, `-2.7`) — the sign is folded
    ///   directly into a signed [`Expr_::Int`] / [`Expr_::Float`] node.  No
    ///   downstream `Negate` AST arm is required, and the value is identical to
    ///   `negate 5`.
    ///
    /// * **Adjacent non-literal atom** (`-x`, `-(e)`, `-f x`) — desugared at
    ///   parse time to `Call(Basics.negate, [e])`. The callee is the QUALIFIED
    ///   `Basics.negate` reference, which resolves through the module catalog to
    ///   the `Basics_negate` kernel and is unshadowable, so a user binding named
    ///   `negate` never captures the unary-minus operator.
    ///
    /// * **Non-adjacent** (`- 5`, `- x`) — the reference compiler parser's `exprAtom_`
    ///   has no leading `spaces` call after consuming `-`, so a space before the
    ///   operand causes the nested atom parse to fail on the space character
    ///   (consumed error, no backtrack).  We mirror this by checking byte-span
    ///   adjacency and erroring when the gap is non-zero.
    fn parse_negative_literal(
        &mut self,
        minus_span: Span,
        threshold: u32,
        depth: u32,
    ) -> DResult<Expr> {
        // ── Attempt 1: adjacent numeric literal ──────────────────────────────
        match self.peek_adjacent_neg_literal(minus_span) {
            Some(NegLeaf::Int(n, lit_span)) => {
                self.bump(Construct::Expression)?;
                // A positive `Int` token is bounded to [0, i64::MAX] at lex
                // time (the lexer parses as `i64`, so the magnitude
                // 9223372036854775808 — i64::MIN's absolute value — overflows
                // and errors before reaching here). Therefore `checked_neg`
                // always returns `Some`; the `Err` branch is the fail-closed
                // guard ensuring the parser stays panic-free if that bound
                // ever changes.
                let value = n.checked_neg().ok_or_else(|| Diagnostic::Parse {
                    span: Self::span_merge(minus_span, lit_span),
                    msg: ParseError::IntLiteralOutOfRange,
                })?;
                return Ok(Located::new(
                    Self::span_merge(minus_span, lit_span),
                    Expr_::Int(value),
                ));
            }
            Some(NegLeaf::Float(f, lit_span)) => {
                self.bump(Construct::Expression)?;
                return Ok(Located::new(
                    Self::span_merge(minus_span, lit_span),
                    Expr_::Float(-f),
                ));
            }
            None => {}
        }

        // ── Attempt 2: adjacent non-literal atom → `negate(e)` ──────────────
        // Parse the sub-atom immediately following `-` and desugar to
        // `Call(Basics.negate, [e])`. The callee is a QUALIFIED `Basics.negate`
        // reference, never a bare `negate` name: qualified references resolve
        // through the module catalog to the `Basics_negate` kernel and cannot be
        // captured by a user binding named `negate`, so `-x` always means
        // arithmetic negation regardless of names in scope.
        //
        // Adjacency check: a space before the operand would cause the recursive
        // atom parse to fail on the space character (consumed error). The check
        // uses byte-span adjacency: `t.span.lo == minus_span.hi`.
        let is_adjacent = self.peek().is_some_and(|t| t.span.lo == minus_span.hi);
        if is_adjacent {
            let basics_sym = self.intern("Basics")?;
            let negate_sym = self.intern("negate")?;
            let negate_expr = Located::new(minus_span, Expr_::VarQual(basics_sym, negate_sym));
            let sub_expr = self.parse_atom_postfix(threshold, depth + 1)?;
            let call_span = Self::span_merge(minus_span, sub_expr.span);
            return Ok(Located::new(
                call_span,
                Expr_::Call(Box::new(negate_expr), vec![sub_expr]),
            ));
        }

        // ── No match: non-adjacent `-` in atom position ──────────────────────
        Err(Diagnostic::Parse {
            span: minus_span,
            msg: ParseError::UnexpectedToken {
                found: tok_kind(&Tok::Minus),
                expected: ExpectedSet([Expected::Expression].into()),
            },
        })
    }

    /// Parse what follows a just-consumed `(`: empty parens `()` are the unit
    /// value ([`Expr_::Unit`]); a single expression has its parens unwrapped
    /// (`(e)` is just `e`, preserving the outer span so explicit grouping is
    /// honoured); a comma-separated list is a tuple literal `(e1, e2, ...)` of
    /// arity ≥ 2.
    ///
    /// `opener` is the `(`'s span; `depth` bounds the inner-expression recursion.
    fn parse_paren_or_tuple(&mut self, opener: Span, depth: u32) -> DResult<Expr> {
        if depth > MAX_DEPTH {
            return Err(self.too_deep(Construct::Tuple));
        }
        // `()` — the unit value. Empty parentheses are the sole inhabitant of
        // the unit type; the closing `)` is consumed and the span spans both.
        if let Some(t) = self.peek().filter(|t| t.kind == Tok::RParen) {
            let close = t.span;
            self.bump(Construct::ParenGroup)?;
            let span = Self::span_merge(opener, close);
            return Ok(Located::new(span, Expr_::Unit));
        }
        let first = self.parse_expr(0, depth + 1)?;
        // No following comma → a plain parenthesised group. Unwrap to the inner
        // value, spanning from the `(` to the `)` so the grouping is honoured.
        if self.peek_kind() != Some(&Tok::Comma) {
            let close = self.expect_rparen(opener, Construct::ParenGroup)?;
            let span = Self::span_merge(opener, close);
            return Ok(Located::new(span, first.value));
        }
        // One or more comma-separated elements → a tuple literal.
        let mut elems = vec![first];
        while self.peek_kind() == Some(&Tok::Comma) {
            self.bump(Construct::Tuple)?;
            elems.push(self.parse_expr(0, depth + 1)?);
        }
        let close = self.expect_rparen(opener, Construct::Tuple)?;
        let span = Self::span_merge(opener, close);
        Ok(Located::new(span, Expr_::Tuple(elems)))
    }

    /// Parse what follows a just-consumed `[`: a list literal `[]` / `[a, b, c]`.
    /// Elements are comma-separated full expressions; a trailing comma is not
    /// permitted. `opener` is the `[`'s span; `depth` bounds inner recursion.
    fn parse_list(&mut self, opener: Span, depth: u32) -> DResult<Expr> {
        if depth > MAX_DEPTH {
            return Err(self.too_deep(Construct::Expression));
        }
        // `[]` — the empty list.
        if let Some(t) = self.peek().filter(|t| t.kind == Tok::RBracket) {
            let close = t.span;
            self.bump(Construct::Expression)?;
            let span = Self::span_merge(opener, close);
            return Ok(Located::new(span, Expr_::List(Vec::new())));
        }
        let mut elems = vec![self.parse_expr(0, depth + 1)?];
        while self.peek_kind() == Some(&Tok::Comma) {
            self.bump(Construct::Expression)?;
            elems.push(self.parse_expr(0, depth + 1)?);
        }
        let close = self.expect_rbracket(opener)?;
        let span = Self::span_merge(opener, close);
        Ok(Located::new(span, Expr_::List(elems)))
    }

    /// Require a closing `]`, returning its span.
    fn expect_rbracket(&mut self, opener: Span) -> DResult<Span> {
        match self.peek() {
            Some(t) if t.kind == Tok::RBracket => {
                let span = t.span;
                self.bump(Construct::Expression)?;
                Ok(span)
            }
            Some(t) => Err(Diagnostic::Parse {
                span: t.span,
                msg: ParseError::UnclosedDelimiter { opener },
            }),
            None => Err(Diagnostic::Parse {
                span: self.eof_err_span(),
                msg: ParseError::UnclosedDelimiter { opener },
            }),
        }
    }

    /// Require a closing `)`, returning its span so the caller can build the
    /// full bracketed span.
    fn expect_rparen(&mut self, opener: Span, construct: Construct) -> DResult<Span> {
        match self.peek() {
            Some(t) if t.kind == Tok::RParen => {
                let span = t.span;
                self.bump(construct)?;
                Ok(span)
            }
            Some(t) => Err(Diagnostic::Parse {
                span: t.span,
                msg: ParseError::UnclosedDelimiter { opener },
            }),
            None => Err(Diagnostic::Parse {
                span: self.eof_err_span(),
                msg: ParseError::UnclosedDelimiter { opener },
            }),
        }
    }

    /// Resolve a (possibly dotted) identifier token into an expression.
    ///
    /// The first segment's case decides the shape, mirroring Elm:
    /// * an **upper**-case head (`String.fromInt`, `Json.Decode.field`) is a
    ///   module-qualified name — everything but the last segment is the
    ///   qualifier, the last is the value (`VarQual`);
    /// * a **lower**-case head (`p`, `p.x`, `record.a.b`) is a local reference
    ///   followed by zero or more record-field accesses — `p.x.y` becomes
    ///   `Access (Access p x) y`. A bare `p` (no dots) is just `VarLocal p`.
    ///
    /// An upper-case head whose run continues into a lowercase segment
    /// (`Http.defaultConfig.timeout`) is a qualified var followed by field
    /// accesses: the qualifier is the leading uppercase segments, the value is
    /// the first lowercase segment, and any further segments are an `Access`
    /// chain over that `VarQual`.
    ///
    /// `span` is the whole identifier token's span. The lexer produces one token
    /// for the dotted run, so the sub-spans of the base var and each field access
    /// are computed from the token's byte range plus the segment lengths: the base
    /// `VarLocal` spans the first segment, and each `Access` widens the span up to
    /// the end of its own field segment. Distinct sub-spans keep every node's
    /// `(module, span)` key unique, which the type-region map relies on — a shared
    /// key lets a field's result type overwrite the record type at the same key.
    fn ident_expr(&mut self, text: &str, span: Span) -> DResult<Expr_> {
        let first = text.split('.').next().unwrap_or("");
        if !text.contains('.') {
            return Ok(Expr_::VarLocal(self.interner.intern(first)?));
        }
        let head_upper = first.chars().next().is_some_and(|c| c.is_ascii_uppercase());
        if head_upper {
            // The value ends the module qualifier at the first lowercase
            // segment: `Http.defaultConfig` is qualifier `Http`, value
            // `defaultConfig`; any segments past it (`…​.timeout`) are field
            // accesses. A run of only uppercase segments (`Json.Decode.field`
            // has its value at the first lowercase `field`, but `Foo.Bar` does
            // not) has no accessor tail and splits at the last '.'.
            let value_idx = text
                .split('.')
                .position(|s| s.chars().next().is_some_and(|c| c.is_ascii_lowercase()));
            let Some(value_idx) = value_idx else {
                // No lowercase segment: a plain qualified name `Module.Ctor`.
                // Slice at the last '.' — `rfind` at an ASCII '.' is a char
                // boundary, and `text` is dotted here so it always hits.
                let Some(idx) = text.rfind('.') else {
                    return Ok(Expr_::VarLocal(self.interner.intern(text)?));
                };
                let qualifier = text.get(..idx).unwrap_or_default();
                let last = text.get(idx + 1..).unwrap_or_default();
                let q = self.interner.intern(qualifier)?;
                let name = self.interner.intern(last)?;
                return Ok(Expr_::VarQual(q, name));
            };
            // Byte offset where the value segment starts: the qualifier is
            // `text[..qual_end]`, one '.' precedes the value, and the value
            // runs to `value_end`. All boundaries are ASCII '.' so slicing is
            // valid; a `value_idx` of 0 means there is no qualifier prefix.
            let segments: Vec<&str> = text.split('.').collect();
            let qual_len: usize = segments.iter().take(value_idx).map(|s| s.len() + 1).sum();
            let value = segments.get(value_idx).copied().unwrap_or_default();
            let value_len = value.len();
            let qualifier = text.get(..qual_len.saturating_sub(1)).unwrap_or_default();
            let q = self.interner.intern(qualifier)?;
            let name = self.interner.intern(value)?;
            let qual_len_u = u32::try_from(qual_len).unwrap_or(0);
            let value_len_u = u32::try_from(value_len).unwrap_or(0);
            let value_lo = span.lo.saturating_add(qual_len_u);
            let value_hi = value_lo.saturating_add(value_len_u);
            let var_qual = Located::new(Span::new(span.lo, value_hi), Expr_::VarQual(q, name));
            // No trailing segments → the bare qualified var.
            if value_idx + 1 >= segments.len() {
                return Ok(var_qual.value);
            }
            // Trailing lowercase segments are field accesses over the VarQual;
            // the access text starts one byte past the value segment (skipping
            // the '.' that follows it).
            let access_lo = value_hi.saturating_add(1);
            let access_start = qual_len.saturating_add(value_len).saturating_add(1);
            let access_text = text.get(access_start..).unwrap_or_default();
            let access_span = Span::new(access_lo, span.hi);
            let expr = self.build_access_chain(var_qual, access_span, access_text)?;
            return Ok(expr.value);
        }
        // Lower-case head: a local var with a chain of field accesses. Build the
        // base VarLocal for the first segment, then hand the rest to the shared
        // helper which carves distinct sub-spans for every field Access node.
        let base_len = u32::try_from(first.len()).unwrap_or(0);
        let base_span = Span::new(span.lo, span.lo.saturating_add(base_len));
        let base = Located::new(base_span, Expr_::VarLocal(self.interner.intern(first)?));
        // The rest segments start one byte after the base (past the first '.').
        // The suffix slice is the identity of `split('.')`→`join('.')` on the
        // tail, and `build_access_chain` re-splits it; '.' is ASCII so the slice
        // boundary is valid.
        let rest_lo = span.lo.saturating_add(base_len).saturating_add(1);
        let rest_text = text.get(first.len() + 1..).unwrap_or_default();
        let tok_span = Span::new(rest_lo, span.hi);
        let expr = self.build_access_chain(base, tok_span, rest_text)?;
        Ok(expr.value)
    }

    /// Parse a record literal `{ field = expr, ... }`, the `{` already consumed.
    ///
    /// After the opening `{` three forms are accepted:
    ///
    /// * `{}` — the **empty record literal**: zero fields. Mirrors the reference compiler
    ///   compiler's `Src.Record []` (line 309-311 of Expression.hs).
    /// * `{ name = value, ... }` — a record **literal**: a non-empty, comma-
    ///   separated list of `name = value` fields.
    /// * `{ base | field = value, ... }` — a record **update** (a `|` after the
    ///   first name): a copy of the record variable `base` with the listed
    ///   fields replaced. The base is a bare lowercase variable, matching Ipê's
    ///   (and Elm's) grammar.
    ///
    /// `opener` is the `{`'s span; `depth` bounds the field-value recursion.
    fn parse_record(&mut self, opener: Span, depth: u32) -> DResult<Expr> {
        if depth > MAX_DEPTH {
            return Err(self.too_deep(Construct::Record));
        }
        // `{}` (the empty record literal) — valid, produces `Record []`.
        // Mirrors the reference compiler: `Just '}' -> char '}' >> return (Record [])`.
        if let Some(t) = self.peek().filter(|t| t.kind == Tok::RBrace) {
            let close = t.span;
            self.bump(Construct::Record)?;
            let span = Self::span_merge(opener, close);
            return Ok(Located::new(span, Expr_::Record(Vec::new())));
        }
        // The first lowercase identifier is either the first field's name (a
        // literal) or the base record variable (an update); a following `|`
        // decides.
        let first = self.parse_record_field_name()?;
        if self.peek_kind() == Some(&Tok::Pipe) {
            self.bump(Construct::Record)?;
            return self.parse_record_update(opener, first, depth);
        }
        // Literal: `first` is the first field's name; `=` then its value.
        self.expect_field_equals()?;
        let value = self.parse_expr(0, depth + 1)?;
        let mut fields = vec![(first, value)];
        loop {
            // A `,` continues the field list; a `}` closes it.
            match self.peek() {
                Some(t) if t.kind == Tok::Comma => {
                    self.bump(Construct::Record)?;
                }
                Some(t) if t.kind == Tok::RBrace => {
                    let close = t.span;
                    self.bump(Construct::Record)?;
                    let span = Self::span_merge(opener, close);
                    return Ok(Located::new(span, Expr_::Record(fields)));
                }
                Some(t) => {
                    return Err(Self::unexpected_token(
                        t,
                        &[Expected::Comma, Expected::RBrace],
                    ));
                }
                None => return Err(self.record_eof()),
            }
            let name = self.parse_record_field_name()?;
            self.expect_field_equals()?;
            let value = self.parse_expr(0, depth + 1)?;
            fields.push((name, value));
        }
    }

    /// Parse the field list of a record update `{ base | field = value, ... }`,
    /// the `base |` prefix already consumed. At least one updated field is
    /// required; the list is comma-separated and closed by `}`. `opener` is the
    /// `{`'s span; `base` is the located base variable name.
    fn parse_record_update(
        &mut self,
        opener: Span,
        base: Located<Symbol>,
        depth: u32,
    ) -> DResult<Expr> {
        let mut fields = Vec::new();
        loop {
            let name = self.parse_record_field_name()?;
            self.expect_field_equals()?;
            let value = self.parse_expr(0, depth + 1)?;
            fields.push((name, value));
            match self.peek() {
                Some(t) if t.kind == Tok::Comma => {
                    self.bump(Construct::Record)?;
                }
                Some(t) if t.kind == Tok::RBrace => {
                    let close = t.span;
                    self.bump(Construct::Record)?;
                    let span = Self::span_merge(opener, close);
                    return Ok(Located::new(span, Expr_::Update(base, fields)));
                }
                Some(t) => {
                    return Err(Self::unexpected_token(
                        t,
                        &[Expected::Comma, Expected::RBrace],
                    ));
                }
                None => return Err(self.record_eof()),
            }
        }
    }

    /// Consume the `=` that separates a record field name from its value.
    fn expect_field_equals(&mut self) -> DResult<()> {
        match self.peek() {
            Some(t) if t.kind == Tok::Equals => {
                self.bump(Construct::Record)?;
                Ok(())
            }
            Some(t) => Err(Self::unexpected_token(t, &[Expected::Equals])),
            None => Err(self.record_eof()),
        }
    }

    /// The unexpected-EOF diagnostic for an unterminated record (literal or
    /// update).
    fn record_eof(&self) -> Diagnostic {
        Diagnostic::Parse {
            span: self.eof_err_span(),
            msg: ParseError::UnexpectedEof {
                construct: Construct::Record,
            },
        }
    }

    /// Parse a record field name: a plain lowercase identifier (no dots, no
    /// uppercase head). A qualified or upper-case token here is rejected rather
    /// than silently accepted as a label.
    fn parse_record_field_name(&mut self) -> DResult<Located<Symbol>> {
        let tok = self.bump(Construct::Record)?;
        let Tok::Ident(text) = &tok.kind else {
            return Err(Self::unexpected_token(&tok, &[Expected::Identifier]));
        };
        if text.contains('.') || text.chars().next().is_some_and(|c| c.is_ascii_uppercase()) {
            return Err(Self::unexpected_token(&tok, &[Expected::Identifier]));
        }
        let sym = self.interner.intern(text)?;
        Ok(Located::new(tok.span, sym))
    }

    fn parse_case(&mut self, threshold: u32, depth: u32) -> DResult<Expr> {
        if depth > MAX_DEPTH {
            return Err(self.too_deep(Construct::Expression));
        }
        // The caller has already peeked `case`.
        let case_tok = self.bump(Construct::Expression)?;
        let scrutinee = self.parse_expr(threshold, depth + 1)?;

        // `of` after the scrutinee.
        match self.peek() {
            Some(t) if t.kind == Tok::Of => {
                self.bump(Construct::CaseBranch)?;
            }
            Some(t) => {
                return Err(Self::malformed_case(t.span, CaseDefect::MissingOf));
            }
            None => {
                return Err(Self::malformed_case(
                    self.eof_err_span(),
                    CaseDefect::MissingOf,
                ));
            }
        }

        let (arm_col, first_span) = match self.peek() {
            Some(t) => (t.col, t.span),
            None => {
                return Err(Self::malformed_case(
                    self.eof_err_span(),
                    CaseDefect::NoBranches,
                ));
            }
        };
        if arm_col <= threshold {
            return Err(Self::malformed_case(
                first_span,
                CaseDefect::FirstBranchNotIndented,
            ));
        }

        let mut arms = Vec::new();
        let mut end = scrutinee.span;
        while self.peek_aligned_at(arm_col) {
            let pat = self.parse_pattern(depth + 1)?;
            // `->` in this branch.
            match self.peek() {
                Some(t) if t.kind == Tok::Arrow => {
                    self.bump(Construct::CaseBranch)?;
                }
                Some(t) => {
                    return Err(Self::malformed_case(t.span, CaseDefect::MissingArrow));
                }
                None => {
                    return Err(Self::malformed_case(
                        self.eof_err_span(),
                        CaseDefect::MissingArrow,
                    ));
                }
            }
            let body = self.parse_expr(arm_col, depth + 1)?;
            end = body.span;
            arms.push((pat, body));
        }
        if arms.is_empty() {
            return Err(Self::malformed_case(
                self.err_here_span(),
                CaseDefect::NoBranches,
            ));
        }
        let span = Self::span_merge(case_tok.span, end);
        Ok(Located::new(span, Expr_::Case(Box::new(scrutinee), arms)))
    }

    /// Parse `let <bindings> in <body>`. The first binding's column fixes the
    /// alignment for the block; every later binding must start at that column.
    /// Each binding is a simple value (`name = expr`) whose body parses with the
    /// binding column as its layout threshold, so it stops at the next aligned
    /// binding or at `in`. Bindings are scoped sequentially (`let*`): each value
    /// sees the bindings before it, which matches the non-recursive nested-`Let`
    /// the lowerer produces.
    fn parse_let(&mut self, threshold: u32, depth: u32) -> DResult<Expr> {
        if depth > MAX_DEPTH {
            return Err(self.too_deep(Construct::Expression));
        }
        // The caller has already peeked `let`.
        let let_tok = self.bump(Construct::Let)?;

        // The first binding establishes the alignment column for the block. A
        // `let` immediately followed by `in` (or end of input) has no bindings.
        let binding_col = match self.peek() {
            Some(t) if t.kind == Tok::In => {
                return Err(Self::malformed_let(t.span, LetDefect::NoBindings));
            }
            Some(t) => t.col,
            None => {
                return Err(Self::malformed_let(
                    self.eof_err_span(),
                    LetDefect::NoBindings,
                ));
            }
        };

        let mut bindings = Vec::new();
        loop {
            bindings.push(self.parse_let_binding(binding_col, depth + 1)?);
            // Another binding continues only when the next token is an
            // identifier aligned at the binding column. `in` is its own token
            // (never an `Ident`), so it always ends the binding list.
            let more = self.peek().is_some_and(|t| {
                layout::aligned_at(t, binding_col)
                    && matches!(
                        t.kind,
                        Tok::Ident(_) | Tok::LParen | Tok::LBrace | Tok::Underscore
                    )
            });
            if !more {
                break;
            }
        }

        // `in` after the bindings.
        match self.peek() {
            Some(t) if t.kind == Tok::In => {
                self.bump(Construct::Let)?;
            }
            Some(t) => return Err(Self::malformed_let(t.span, LetDefect::MissingIn)),
            None => {
                return Err(Self::malformed_let(
                    self.eof_err_span(),
                    LetDefect::MissingIn,
                ));
            }
        }

        let body = self.parse_expr(threshold, depth + 1)?;
        let span = Self::span_merge(let_tok.span, body.span);
        Ok(Located::new(span, Expr_::Let(bindings, Box::new(body))))
    }

    /// Parse a lambda `\p0 p1 ... -> body`, the `\` already peeked. One or more
    /// parameter patterns precede the `->`; the body parses as a full expression
    /// at `threshold`, so it extends as far right as the surrounding layout
    /// allows (`\x -> x + 1` captures the whole `x + 1`). A zero-parameter
    /// `\ -> e` and a missing `->` are clean parse errors, never a silently
    /// reshaped AST. Mirrors the reference compiler's `Ipe.Parse.Expression.lambda`.
    fn parse_lambda(&mut self, threshold: u32, depth: u32) -> DResult<Expr> {
        if depth > MAX_DEPTH {
            return Err(self.too_deep(Construct::Lambda));
        }
        // The caller has already peeked `\`.
        let lambda_tok = self.bump(Construct::Lambda)?;

        // At least one parameter pattern before the `->`.
        let mut params = Vec::new();
        while self.peek_is_binder_atom_start() {
            params.push(self.parse_pattern_atom(depth + 1)?);
        }
        if params.is_empty() {
            return Err(self.peek().map_or_else(
                || Diagnostic::Parse {
                    span: self.eof_err_span(),
                    msg: ParseError::UnexpectedEof {
                        construct: Construct::Lambda,
                    },
                },
                |t| Self::unexpected_token(t, &[Expected::Pattern]),
            ));
        }

        // `->` between the parameters and the body.
        match self.peek() {
            Some(t) if t.kind == Tok::Arrow => {
                self.bump(Construct::Lambda)?;
            }
            Some(t) => return Err(Self::unexpected_token(t, &[Expected::Arrow])),
            None => {
                return Err(Diagnostic::Parse {
                    span: self.eof_err_span(),
                    msg: ParseError::UnexpectedEof {
                        construct: Construct::Lambda,
                    },
                });
            }
        }

        let body = self.parse_expr(threshold, depth + 1)?;
        let span = Self::span_merge(lambda_tok.span, body.span);
        Ok(Located::new(span, Expr_::Lambda(params, Box::new(body))))
    }

    /// Parse `if <cond> then <a> else <b>`, including any `else if` chain. Each
    /// condition and branch parses as a full expression at `threshold`; the
    /// `then` / `else` / `if` keyword tokens delimit them, since the expression
    /// parser never consumes a keyword as an application argument or operator.
    /// The result is `If [(cond, branch), …] else`, mirroring the reference compiler
    /// compiler's `Src.If [(Expr, Expr)] Expr` — the leading `if` plus every
    /// `else if`, then the mandatory final `else`.
    fn parse_if(&mut self, threshold: u32, depth: u32) -> DResult<Expr> {
        if depth > MAX_DEPTH {
            return Err(self.too_deep(Construct::If));
        }
        // The caller has already peeked `if`.
        let if_tok = self.bump(Construct::If)?;

        let mut branches = Vec::new();
        loop {
            // Reject an absent condition cleanly rather than letting the
            // expression parser stumble over the `then` / `else` keyword.
            match self.peek() {
                Some(t) if matches!(t.kind, Tok::Then | Tok::Else) => {
                    return Err(Self::malformed_if(t.span, IfDefect::MissingCondition));
                }
                None => {
                    return Err(Self::malformed_if(
                        self.eof_err_span(),
                        IfDefect::MissingCondition,
                    ));
                }
                _ => {}
            }
            let cond = self.parse_expr(threshold, depth + 1)?;

            // `then` after the condition.
            match self.peek() {
                Some(t) if t.kind == Tok::Then => {
                    self.bump(Construct::If)?;
                }
                Some(t) => return Err(Self::malformed_if(t.span, IfDefect::MissingThen)),
                None => {
                    return Err(Self::malformed_if(
                        self.eof_err_span(),
                        IfDefect::MissingThen,
                    ));
                }
            }

            let branch = self.parse_expr(threshold, depth + 1)?;
            branches.push((cond, branch));

            // `else` after the `then` branch (mandatory — every `if` is an
            // expression with both outcomes).
            match self.peek() {
                Some(t) if t.kind == Tok::Else => {
                    self.bump(Construct::If)?;
                }
                Some(t) => return Err(Self::malformed_if(t.span, IfDefect::MissingElse)),
                None => {
                    return Err(Self::malformed_if(
                        self.eof_err_span(),
                        IfDefect::MissingElse,
                    ));
                }
            }

            // `else if` continues the chain with another `(cond, branch)` pair;
            // a plain `else` ends it with the final expression below.
            if self.peek_kind() == Some(&Tok::If) {
                self.bump(Construct::If)?;
                continue;
            }
            break;
        }

        let else_branch = self.parse_expr(threshold, depth + 1)?;
        let span = Self::span_merge(if_tok.span, else_branch.span);
        Ok(Located::new(
            span,
            Expr_::If(branches, Box::new(else_branch)),
        ))
    }

    /// Parse a single `name = body` let binding. `binding_col` is the block's
    /// alignment column, used as the body's layout threshold so the body stops
    /// at the next aligned binding or at `in`.
    fn parse_let_binding(&mut self, binding_col: u32, depth: u32) -> DResult<LetBinding> {
        if depth > MAX_DEPTH {
            return Err(self.too_deep(Construct::Let));
        }
        // The binder is either a destructure pattern — a tuple `(a, b)`, a record
        // `{ x }`, or a wildcard `_` — or the common `name = body` value
        // binding. The destructure forms start with a token that cannot begin a
        // plain value name, so peeking selects the path without lookahead beyond
        // one token. The simple path keeps its precise BindingNameNotLower
        // diagnostics for an uppercase / dotted name.
        let pat = if matches!(
            self.peek_kind(),
            Some(&(Tok::LParen | Tok::LBrace | Tok::Underscore))
        ) {
            self.parse_pattern(depth + 1)?
        } else {
            let name_tok = self.bump(Construct::Let)?;
            let Tok::Ident(text) = &name_tok.kind else {
                return Err(Self::malformed_let(
                    name_tok.span,
                    LetDefect::BindingNameNotLower,
                ));
            };
            // A value binding name is a plain lowercase identifier; reject an
            // uppercase (constructor) or dotted (qualified) name.
            if text.contains('.') || text.chars().next().is_some_and(|c| c.is_ascii_uppercase()) {
                return Err(Self::malformed_let(
                    name_tok.span,
                    LetDefect::BindingNameNotLower,
                ));
            }
            let name_sym = self.interner.intern(text)?;
            Located::new(name_tok.span, Pattern_::PVar(name_sym))
        };

        // `let _ = e` at user source level binds nothing and is rejected. Only
        // a whole-pattern `_` (bare PAnything) is disallowed here; a `_` nested
        // inside a larger pattern such as `(a, _)` reaches `parse_pattern`
        // recursively and is fine. The `desugar_do` path builds its synthetic
        // `LetBinding { pat: PAnything, … }` directly — bypassing this function
        // — so do-block bare-run statements are unaffected.
        if matches!(pat.value, Pattern_::PAnything) {
            return Err(Self::malformed_let(
                pat.span,
                LetDefect::BareWildcardBinding,
            ));
        }

        // Function-parameter sugar: `let f x y = body` desugars to
        // `let f = \x y -> body`. Parameters are collected only when the binder
        // is a simple `PVar` name (destructure binders like `{ x }` already
        // consumed their `=` in `parse_pattern`).
        //
        // We collect binder atoms as long as the next token can begin one AND
        // it is not `=`. A literal start (Int, Str, …) is not a binder atom, so
        // it falls through to the `MissingEquals` error below — exactly the
        // right behaviour for malformed input like `let x 2 in x`.
        let mut params: Vec<Pattern> = Vec::new();
        if matches!(pat.value, Pattern_::PVar(_)) {
            while self.peek_is_binder_atom_start()
                && !matches!(self.peek_kind(), Some(&Tok::Equals))
            {
                params.push(self.parse_pattern_atom(depth + 1)?);
            }
        }

        // `=` after the binder (and any collected parameters).
        match self.peek() {
            Some(t) if t.kind == Tok::Equals => {
                self.bump(Construct::Let)?;
            }
            Some(t) => return Err(Self::malformed_let(t.span, LetDefect::MissingEquals)),
            None => {
                return Err(Self::malformed_let(
                    self.eof_err_span(),
                    LetDefect::MissingEquals,
                ));
            }
        }

        let rhs = self.parse_expr(binding_col, depth + 1)?;
        // If we collected parameters, wrap the body in a Lambda so the let
        // binding holds the desugared function value. The lambda span runs from
        // the first parameter to the end of the body.
        let body = if params.is_empty() {
            rhs
        } else {
            let first_param_span = params.first().map_or(rhs.span, |p| p.span);
            let span = Self::span_merge(first_param_span, rhs.span);
            Located::new(span, Expr_::Lambda(params, Box::new(rhs)))
        };
        Ok(LetBinding { pat, body })
    }

    /// Parse a `do` block — an aligned sequence of statements desugared to a
    /// `Task.andThen` chain. Statement forms: `p <- e` (run `e`, bind its result
    /// to `p`), `p = e` (a pure `let`), and bare `e` (run for effect). The last
    /// statement is the block's result expression.
    ///
    /// Desugaring, bottom-up over the tail `rest`:
    /// - `⟦(p <- e); rest⟧ = Task.andThen (\p -> ⟦rest⟧) e`
    /// - `⟦(p =  e); rest⟧ = let p = e in ⟦rest⟧`
    /// - `⟦e ; rest⟧       = Task.andThen (\_ -> ⟦rest⟧) e`
    /// - `⟦e⟧              = e`
    ///
    /// Because the desugar names `Task.andThen`, the enclosing module must have
    /// `Ipe.Task` in scope as `Task` (the usual `import Ipe.Task as Task`).
    fn parse_do(&mut self, threshold: u32, depth: u32) -> DResult<Expr> {
        if depth > MAX_DEPTH {
            return Err(self.too_deep(Construct::Expression));
        }
        let do_tok = self.bump(Construct::Expression)?;
        let Some(first) = self.peek() else {
            return Err(Diagnostic::Parse {
                span: self.eof_err_span(),
                msg: ParseError::UnexpectedEof {
                    construct: Construct::Expression,
                },
            });
        };
        let block_col = first.col;
        // The first statement must be indented past the enclosing layout
        // threshold; otherwise a statement at or before it belongs to an outer
        // block, and consuming it would swallow following top-level
        // declarations. Fail closed, mirroring `parse_case`'s first-branch gate.
        if block_col <= threshold {
            return Err(Diagnostic::Parse {
                span: first.span,
                msg: ParseError::Unexpected,
            });
        }
        let mut stmts = Vec::new();
        loop {
            stmts.push(self.parse_do_statement(block_col, depth + 1)?);
            if !self
                .peek()
                .is_some_and(|t| layout::aligned_at(t, block_col))
            {
                break;
            }
        }
        self.desugar_do(do_tok.span, stmts)
    }

    /// Parse one `do`-block statement. A leading lowercase name (or `_`) directly
    /// followed by `<-` or `=` is a bind / let; anything else is a bare run.
    fn parse_do_statement(&mut self, block_col: u32, depth: u32) -> DResult<DoStmt> {
        let head_is_binder = matches!(self.peek_kind(), Some(Tok::Ident(_) | Tok::Underscore));
        let next = self.toks.get(self.pos + 1).map(|t| &t.kind);
        let is_bind = next == Some(&Tok::LeftArrow);
        let is_let = next == Some(&Tok::Equals);
        if head_is_binder && (is_bind || is_let) {
            let head = self.bump(Construct::Expression)?;
            let pat = match &head.kind {
                Tok::Underscore => Located::new(head.span, Pattern_::PAnything),
                Tok::Ident(text) => {
                    if text.contains('.')
                        || text.chars().next().is_some_and(|c| c.is_ascii_uppercase())
                    {
                        return Err(Self::malformed_let(
                            head.span,
                            LetDefect::BindingNameNotLower,
                        ));
                    }
                    let sym = self.interner.intern(text)?;
                    Located::new(head.span, Pattern_::PVar(sym))
                }
                _ => {
                    return Err(Diagnostic::Parse {
                        span: head.span,
                        msg: ParseError::Unexpected,
                    });
                }
            };
            let op = self.bump(Construct::Expression)?; // consume `<-` or `=`
            let rhs = self.parse_expr(block_col, depth + 1)?;
            Ok(if is_bind {
                DoStmt::Bind(pat, op.span, rhs)
            } else {
                DoStmt::Let(pat, op.span, rhs)
            })
        } else {
            let e = self.parse_expr(block_col, depth + 1)?;
            Ok(DoStmt::Run(e))
        }
    }

    /// Fold the parsed statements into the `Task.andThen` chain (see
    /// [`Self::parse_do`]). The block must end in a result expression.
    ///
    /// A block whose every statement is a `=` pure-let binding — no `<-` bind
    /// and no bare-run line anywhere, the final one included — is stepless:
    /// pure code dressed as `do`. That is rejected with
    /// [`ParseError::SteplessDo`] so authors use `let … in` for pure bindings
    /// instead. A `do` that ends in a bare run has a Task step and passes this
    /// purely structural gate; whether that final expression is genuinely
    /// effectful is a type-level question left to the lowering gates.
    fn desugar_do(&mut self, do_span: Span, stmts: Vec<DoStmt>) -> DResult<Expr> {
        // Stepless-do gate: a Task step is any `<-` bind or any bare run,
        // the trailing run included. The gate is purely structural because
        // the parser cannot see types; a `do` with no step is pure code.
        let has_task_step = stmts.iter().any(|s| match s {
            DoStmt::Bind(..) | DoStmt::Run(_) => true,
            DoStmt::Let(..) => false,
        });
        if !has_task_step {
            return Err(Diagnostic::Parse {
                span: do_span,
                msg: ParseError::SteplessDo,
            });
        }

        let mut rev = stmts.into_iter().rev();
        let Some(last) = rev.next() else {
            return Err(Diagnostic::Parse {
                span: do_span,
                msg: ParseError::Unexpected,
            });
        };
        let mut acc = match last {
            DoStmt::Run(e) => e,
            DoStmt::Bind(pat, ..) | DoStmt::Let(pat, ..) => {
                return Err(Diagnostic::Parse {
                    span: pat.span,
                    msg: ParseError::Unexpected,
                });
            }
        };
        for stmt in rev {
            acc = match stmt {
                DoStmt::Bind(pat, op_span, task) => {
                    // Lambda gets a zero-width span at the operator's start; the
                    // call/callee get the full operator span. Distinct, so the
                    // post-order parent `Call` cannot overwrite the lambda arrow.
                    let lam_span = Span::new(op_span.lo, op_span.lo);
                    self.task_and_then(pat, lam_span, op_span, acc, task)?
                }
                DoStmt::Run(task) => {
                    // A bare run — "run this effect, discard its result, continue"
                    // — is exactly `let _ = task in cont`, which lowers to the
                    // compiler's flat effect-sequence node with no closure. Emit it
                    // that way rather than `Task.andThen (\_ -> cont) task`: a long
                    // run of statements then stays a shallow chain of `_`-lets
                    // instead of a deep nest of lambdas, each of which would open its
                    // own inference scope and make type-checking a long `do` block
                    // super-linear.
                    //
                    // The synthetic outer `Let` node gets a zero-width span at the
                    // start of the task expression. The type checker records region
                    // types keyed by span: giving the wrapper `Let` a span distinct
                    // from the inner task expression ensures the wrapper's result
                    // type (the continuation type) cannot overwrite the task
                    // expression's own region entry. Without this, both nodes share
                    // `task.span` and the second insertion (the `Let`, typed as the
                    // continuation) stomps the first (the task, typed as `Task …`),
                    // causing `is_task_typed` to return `false` and silently drop
                    // the effect instead of raising IPE-L0141 in a sync context.
                    let let_span = Span::new(task.span.lo, task.span.lo);
                    let wild = Located::new(task.span, Pattern_::PAnything);
                    Located::new(
                        let_span,
                        Expr_::Let(
                            vec![LetBinding {
                                pat: wild,
                                body: task,
                            }],
                            Box::new(acc),
                        ),
                    )
                }
                DoStmt::Let(pat, op_span, body) => Located::new(
                    op_span,
                    Expr_::Let(vec![LetBinding { pat, body }], Box::new(acc)),
                ),
            };
        }
        // Re-stamp the whole block with the `do` keyword's (unique) span.
        Ok(Located::new(do_span, acc.value))
    }

    /// Build `Task.andThen (\pat -> cont) task`. The lambda carries `lam_span`
    /// and the call/callee carry `call_span` — distinct, and neither an
    /// operand's — so the type checker's post-order `(home, span)` region map
    /// records the lambda's arrow without the parent call overwriting it.
    fn task_and_then(
        &mut self,
        pat: Pattern,
        lam_span: Span,
        call_span: Span,
        cont: Expr,
        task: Expr,
    ) -> DResult<Expr> {
        let task_mod = self.interner.intern("Task")?;
        let and_then = self.interner.intern("andThen")?;
        let callee = Located::new(call_span, Expr_::VarQual(task_mod, and_then));
        let lam = Located::new(lam_span, Expr_::Lambda(vec![pat], Box::new(cont)));
        Ok(Located::new(
            call_span,
            Expr_::Call(Box::new(callee), vec![lam, task]),
        ))
    }

    // ---- patterns ---------------------------------------------------------

    /// A full pattern (case-arm position). The `|` or-pattern separator binds
    /// looser than everything else in a pattern (constructor application, `::`,
    /// `as`), so a full pattern is one-or-more cons/`as` alternatives joined by
    /// `|`. A single alternative is returned unwrapped; two or more become a
    /// [`Pattern_::POr`] spanning the first through the last.
    fn parse_pattern(&mut self, depth: u32) -> DResult<Pattern> {
        if depth > MAX_DEPTH {
            return Err(self.too_deep(Construct::Pattern));
        }
        let first = self.parse_cons_as(depth + 1)?;
        if self.peek_kind() != Some(&Tok::Pipe) {
            return Ok(first);
        }
        let start = first.span;
        let mut end = first.span;
        let mut alts = vec![first];
        while self.peek_kind() == Some(&Tok::Pipe) {
            self.bump(Construct::Pattern)?;
            let alt = self.parse_cons_as(depth + 1)?;
            end = alt.span;
            alts.push(alt);
        }
        let span = Self::span_merge(start, end);
        Ok(Located::new(span, Pattern_::POr(alts)))
    }

    /// A cons/`as` pattern — a full pattern *below* the or-pattern layer:
    /// constructor application, then `::`, then a postfix `as` alias. This is the
    /// grammar an or-pattern alternative and a cons tail both sit at, so neither
    /// consumes a following `|` (`x :: xs | []` parses as `(x :: xs) | []`).
    fn parse_cons_as(&mut self, depth: u32) -> DResult<Pattern> {
        if depth > MAX_DEPTH {
            return Err(self.too_deep(Construct::Pattern));
        }
        let head = self.parse_pattern_atom(depth + 1)?;
        // Only a constructor head may take sub-patterns. Peek by reference to
        // avoid cloning the whole pattern; destructure by move only on the
        // sub-pattern-bearing path.
        let pat = if matches!(head.value, Pattern_::PCtor(..)) {
            let mut sub = Vec::new();
            let mut end = head.span;
            while self.peek_is_pattern_atom_start() {
                let p = self.parse_pattern_atom(depth + 1)?;
                end = p.span;
                sub.push(p);
            }
            if sub.is_empty() {
                head
            } else if let Pattern_::PCtor(name, mods, _) = head.value {
                let span = Self::span_merge(head.span, end);
                Located::new(span, Pattern_::PCtor(name, mods, sub))
            } else {
                head
            }
        } else {
            head
        };
        // A cons pattern `head :: tail`. `::` is right-associative and
        // binds looser than constructor application, so the head parsed so far is
        // the first element and the tail is parsed recursively (which nests
        // rightward and consumes its own `as` alias). `a :: b :: rest` becomes
        // `PCons(a, PCons(b, rest))`.
        let pat = if self.peek_kind() == Some(&Tok::ColonColon) {
            self.bump(Construct::Pattern)?;
            let tail = self.parse_cons_as(depth + 1)?;
            let span = Self::span_merge(pat.span, tail.span);
            Located::new(span, Pattern_::PCons(Box::new(pat), Box::new(tail)))
        } else {
            pat
        };
        // An `as` alias binds the whole pattern parsed so far to a name
        // (`inner as name`). Mirrors the reference compiler's `pattern_` postfix
        // check; the inner sub-pattern keeps its shape and the alias wraps it.
        if self.peek_kind() == Some(&Tok::As) {
            self.bump(Construct::Pattern)?;
            let name = self.parse_lower_name()?;
            let span = Self::span_merge(pat.span, name.span);
            return Ok(Located::new(span, Pattern_::PAlias(Box::new(pat), name)));
        }
        Ok(pat)
    }

    /// Parse a lowercase identifier as a located binding name (the alias target
    /// of an `as` pattern). An upper-case identifier or any other token is a
    /// parse error — only a lowercase name can bind a value.
    fn parse_lower_name(&mut self) -> DResult<Located<Symbol>> {
        let tok = self.bump(Construct::Pattern)?;
        if let Tok::Ident(text) = &tok.kind
            && text.chars().next().is_some_and(|c| c.is_ascii_lowercase())
            && !text.contains('.')
        {
            let sym = self.interner.intern(text)?;
            return Ok(Located::new(tok.span, sym));
        }
        Err(Self::unexpected_token(&tok, &[Expected::Identifier]))
    }

    fn parse_pattern_atom(&mut self, depth: u32) -> DResult<Pattern> {
        if depth > MAX_DEPTH {
            return Err(self.too_deep(Construct::Pattern));
        }
        let tok = self.bump(Construct::Pattern)?;
        match &tok.kind {
            Tok::Underscore => Ok(Located::new(tok.span, Pattern_::PAnything)),
            // Literal leaves: int / string / char. Bool literals
            // (`True` / `False`) come through the `Ident` arm below. A float
            // literal is intentionally NOT a pattern leaf — equality on `f64`
            // is unsound to match on (Rust forbids float patterns), so a
            // `Tok::Float` falls through to the fail-closed catch-all below.
            Tok::Int(n) => Ok(Located::new(tok.span, Pattern_::PInt(*n))),
            Tok::Str(s) => Ok(Located::new(tok.span, Pattern_::PStr(s.clone()))),
            // A triple-quoted string in pattern position matches the same
            // margin-stripped value its expression form produces, so the strip
            // is applied here too (patterns carry no interpolation to desugar).
            Tok::TripleStr { raw, anchor } => Ok(Located::new(
                tok.span,
                Pattern_::PStr(ipe_syntax::strip_anchor_margin(raw, *anchor)),
            )),
            Tok::Char(c) => Ok(Located::new(tok.span, Pattern_::PChar(c.clone()))),
            // A negative integer literal pattern `-3`. The digit must be
            // byte-span adjacent to the `-` (no intervening whitespace); a gap
            // or a non-integer token is a parse error, matching the expression
            // grammar enforced by `peek_adjacent_neg_literal`.
            Tok::Minus => match self.peek_adjacent_neg_literal(tok.span) {
                Some(NegLeaf::Int(n, lit_span)) => {
                    self.bump(Construct::Pattern)?;
                    // `n` is in [0, i64::MAX] at lex time; `checked_neg` is
                    // the fail-closed guard in case that bound ever widens.
                    let value = n.checked_neg().ok_or_else(|| Diagnostic::Parse {
                        span: Self::span_merge(tok.span, lit_span),
                        msg: ParseError::IntLiteralOutOfRange,
                    })?;
                    Ok(Located::new(
                        Self::span_merge(tok.span, lit_span),
                        Pattern_::PInt(value),
                    ))
                }
                // Float patterns are unsound (f64 equality is not well-defined
                // for pattern matching), so a `-`+float is rejected.
                _ => Err(Self::unexpected_token(
                    self.peek().unwrap_or(&tok),
                    &[Expected::Pattern],
                )),
            },
            Tok::LParen => self.parse_paren_pattern(tok.span, depth),
            Tok::LBrace => {
                // A record pattern `{ x, y }`. Field-pun only: each entry
                // is a bare lowercase field name that also binds a local of the
                // same name. There is no `{ field = sub-pattern }` form (
                // reference rejects it at parse), and the empty record `{}` is
                // outside the grammar, so a record pattern carries ≥ 1 field.
                let opener = tok.span;
                if let Some(t) = self.peek().filter(|t| t.kind == Tok::RBrace) {
                    return Err(Self::unexpected_token(t, &[Expected::Identifier]));
                }
                let mut fields = vec![self.parse_record_field_name()?];
                loop {
                    match self.peek() {
                        Some(t) if t.kind == Tok::Comma => {
                            self.bump(Construct::Pattern)?;
                        }
                        Some(t) if t.kind == Tok::RBrace => {
                            let close = t.span;
                            self.bump(Construct::Pattern)?;
                            let span = Self::span_merge(opener, close);
                            return Ok(Located::new(span, Pattern_::PRecord(fields)));
                        }
                        Some(t) => {
                            return Err(Self::unexpected_token(
                                t,
                                &[Expected::Comma, Expected::RBrace],
                            ));
                        }
                        None => return Err(self.record_eof()),
                    }
                    fields.push(self.parse_record_field_name()?);
                }
            }
            Tok::LBracket => self.parse_list_pattern(tok.span, depth + 1),
            Tok::Ident(text) => {
                // `True` / `False` are the two Bool constructors; in pattern
                // position they are boolean literal patterns (a closed
                // two-constructor cover), matching the reference compiler's
                // `Src.PBool`. They are checked before the general ctor branch.
                if text == "True" {
                    return Ok(Located::new(tok.span, Pattern_::PBool(true)));
                }
                if text == "False" {
                    return Ok(Located::new(tok.span, Pattern_::PBool(false)));
                }
                // `Debug._` — the development-only catch-all. A reserved literal
                // spelling (the conventional `import Ipe.Debug as Debug` alias),
                // parsed here because pattern position has no qualifier-resolution
                // phase. Matches every value like `_`, but is exempt from the
                // closed-union catch-all error and is rejected at `ipe release`
                // (IPE-L0140), exactly like the other `Ipe.Debug` members.
                if text == "Debug._" {
                    return Ok(Located::new(tok.span, Pattern_::PDebugAnything));
                }
                let first_upper = text.chars().next().is_some_and(|c| c.is_ascii_uppercase());
                if first_upper {
                    // Qualified constructors (`Module.Ctor`) are not modelled in
                    // pattern position. Reject a dotted upper-case name rather than
                    // drop the qualifier into a non-reference AST.
                    if text.contains('.') {
                        return Err(Self::unexpected_token(&tok, &[Expected::Constructor]));
                    }
                    let name = self.interner.intern(text)?;
                    Ok(Located::new(
                        tok.span,
                        Pattern_::PCtor(name, Vec::new(), Vec::new()),
                    ))
                } else {
                    // A dotted lowercase name (`a.b`) is not a value binder — a
                    // binder is a single lowercase identifier. Reject it rather
                    // than mint a `PVar` whose interned text carries a `.`, which
                    // would emit an illegal Rust identifier at codegen.
                    if text.contains('.') {
                        return Err(Self::unexpected_token(&tok, &[Expected::Identifier]));
                    }
                    let sym = self.interner.intern(text)?;
                    Ok(Located::new(tok.span, Pattern_::PVar(sym)))
                }
            }
            _ => Err(Self::unexpected_token(&tok, &[Expected::Pattern])),
        }
    }

    /// Whether the next token can begin a pattern ATOM in a position that admits
    /// refutable literal sub-patterns — namely a constructor's argument list
    /// (`Just 0`, `MkWrap 'a'`). Includes the literal starts.
    /// Parse a list pattern `[]` / `[a, b, c]` after the `[` is consumed.
    /// Comma-separated sub-patterns; the empty brackets are the nil cover.
    /// `opener` is the `[`'s span.
    /// Parse the pattern after an opening `(`: the unit pattern `()`, a
    /// parenthesized grouping that unwraps to its inner pattern, or a tuple
    /// `(p0, p1, ...)`.
    fn parse_paren_pattern(&mut self, opener: Span, depth: u32) -> DResult<Pattern> {
        // Empty parens `()` are the unit pattern — the sole value of the unit
        // type — mirroring the unit EXPRESSION the parser builds from `()`.
        // Handled before `parse_pattern`, which cannot begin on a `)`.
        if self.peek_kind() == Some(&Tok::RParen) {
            let close = self.expect_rparen(opener, Construct::Pattern)?;
            let span = Self::span_merge(opener, close);
            return Ok(Located::new(span, Pattern_::PUnit));
        }
        let inner = self.parse_pattern(depth + 1)?;
        // A following `,` makes this a tuple `(p0, p1, ...)`; otherwise the
        // parens group a single pattern and unwrap.
        if self.peek_kind() == Some(&Tok::Comma) {
            let mut elems = vec![inner];
            while self.peek_kind() == Some(&Tok::Comma) {
                self.bump(Construct::Pattern)?;
                elems.push(self.parse_pattern(depth + 1)?);
            }
            let close = self.expect_rparen(opener, Construct::Pattern)?;
            let span = Self::span_merge(opener, close);
            return Ok(Located::new(span, Pattern_::PTuple(elems)));
        }
        let close = self.expect_rparen(opener, Construct::Pattern)?;
        let span = Self::span_merge(opener, close);
        Ok(Located::new(span, inner.value))
    }

    fn parse_list_pattern(&mut self, opener: Span, depth: u32) -> DResult<Pattern> {
        if depth > MAX_DEPTH {
            return Err(self.too_deep(Construct::Pattern));
        }
        if let Some(t) = self.peek().filter(|t| t.kind == Tok::RBracket) {
            let close = t.span;
            self.bump(Construct::Pattern)?;
            let span = Self::span_merge(opener, close);
            return Ok(Located::new(span, Pattern_::PList(Vec::new())));
        }
        let mut elems = vec![self.parse_pattern(depth + 1)?];
        while self.peek_kind() == Some(&Tok::Comma) {
            self.bump(Construct::Pattern)?;
            elems.push(self.parse_pattern(depth + 1)?);
        }
        let close = self.expect_rbracket(opener)?;
        let span = Self::span_merge(opener, close);
        Ok(Located::new(span, Pattern_::PList(elems)))
    }

    fn peek_is_pattern_atom_start(&self) -> bool {
        matches!(
            self.peek_kind(),
            Some(
                &(Tok::Underscore
                    | Tok::LParen
                    | Tok::LBrace
                    | Tok::LBracket
                    | Tok::Ident(_)
                    | Tok::Int(_)
                    | Tok::Str(_)
                    | Tok::TripleStr { .. }
                    | Tok::Char(_)
                    | Tok::Minus)
            )
        )
    }

    /// Whether the next token can begin a BINDER pattern atom — a function or
    /// lambda parameter. Literals are refutable and never bind a parameter, so a
    /// literal start STOPS the parameter list (`\x 1` reports a missing `->` at
    /// `1`, not a swallowed literal parameter).
    fn peek_is_binder_atom_start(&self) -> bool {
        matches!(
            self.peek_kind(),
            Some(&(Tok::Underscore | Tok::LParen | Tok::LBrace | Tok::Ident(_)))
        )
    }

    /// Whether the next token is a lowercase-headed identifier — a declared type
    /// parameter in a `type` / `type alias` header.
    fn peek_is_lowercase_ident(&self) -> bool {
        matches!(
            self.peek_kind(),
            Some(Tok::Ident(text)) if text.chars().next().is_some_and(|c| c.is_ascii_lowercase())
        )
    }

    // ---- leading-minus rule (single source of truth) ---------------------

    /// The shared leading-`-`-binds-a-numeric-literal rule used by both
    /// expression and pattern parsing.
    ///
    /// Returns the raw (positive) magnitude and its span when the next token
    /// is a numeric literal byte-span adjacent to `minus_span` (no whitespace
    /// gap). A gap, a non-numeric token, or end-of-input yields `None`; the
    /// caller then takes its own fail-closed error path. The caller is
    /// responsible for consuming the token (`bump`) and negating the value.
    fn peek_adjacent_neg_literal(&self, minus_span: Span) -> Option<NegLeaf> {
        let t = self.peek()?;
        if t.span.lo != minus_span.hi {
            return None; // whitespace between `-` and the token
        }
        match &t.kind {
            Tok::Int(n) => Some(NegLeaf::Int(*n, t.span)),
            Tok::Float(f) => Some(NegLeaf::Float(*f, t.span)),
            _ => None,
        }
    }

    // ---- span helper ------------------------------------------------------

    fn span_merge(a: Span, b: Span) -> Span {
        Span::new(a.lo.min(b.lo), a.hi.max(b.hi))
    }
}
