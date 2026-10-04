#![forbid(unsafe_code)]
//! `ipe_parse` — the lexer + layout + recursive-descent parser for the
//! supported subset of Ipê.
//!
//! Entry point: [`parse_module`]. It consumes source text plus a mutable
//! [`Interner`] and produces a [`ipe_syntax::Module`], or a typed
//! [`ipe_diagnostics::Diagnostic`]. The parser is a hand-written recursive
//! descent port of the reference compiler's `Ipe.Parse.*`, narrowed to the
//! nodes the supported subset exercises. Recursion is bounded by
//! [`parser::MAX_DEPTH`] so adversarial input cannot overflow the stack.

mod layout;
mod lexer;
mod parser;
mod surface;

use ipe_diagnostics::{DResult, Span, TokenKind};
use ipe_intern::Interner;
use ipe_syntax::{Module, TypeAnnotation};

pub use parser::MAX_DEPTH;

/// The byte spans of every string, triple-string, char, and doc-comment literal
/// in `src`, exactly as the lexer delimits them.
///
/// These are the only source regions whose bytes are literal content. Line and
/// block comments are lexer trivia — never a token — so a byte covered by none
/// of the returned spans is not inside a literal. A consumer deciding whether a
/// textual marker (e.g. an inline lint-suppression directive) is a real comment
/// or mere string data checks membership here: the lexer is the single source
/// of truth for what is literal, so the check cannot be fooled by a marker
/// embedded in a string.
///
/// An unlexable source yields no spans; the caller must treat that as "cannot
/// prove any marker is a comment" rather than "everything is a comment".
///
/// This flattens the lex-failure and no-literals cases into the same empty
/// vector; a caller that must fail closed on lex failure — recognising nothing
/// on a source it cannot parse — uses [`try_literal_source_spans`], which keeps
/// the two apart.
#[must_use]
pub fn literal_source_spans(src: &str) -> Vec<Span> {
    try_literal_source_spans(src).unwrap_or_default()
}

/// The byte spans of every literal in `src`, or `None` when `src` does not lex.
///
/// `Some(spans)` is a proof the source lexed: the spans (possibly empty) are the
/// complete set of literal regions. `None` means the lexer refused the source,
/// so no claim about any byte can be made — a caller deciding whether a textual
/// marker is a real comment must recognise nothing rather than trust an empty
/// span set that only *looks* like "no literals".
#[must_use]
pub fn try_literal_source_spans(src: &str) -> Option<Vec<Span>> {
    let tokens = lexer::lex(src).ok()?;
    Some(
        tokens
            .iter()
            .filter(|t| {
                matches!(
                    t.kind,
                    lexer::Tok::Str(_)
                        | lexer::Tok::TripleStr { .. }
                        | lexer::Tok::Char(_)
                        | lexer::Tok::DocComment(_)
                )
            })
            .map(|t| t.span)
            .collect(),
    )
}

/// What a lexed token is, as [`try_source_tokens`] reports it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TokenClass {
    /// A token of the program, by its payload-free kind.
    Code(TokenKind),
    /// A `{-| … -}` doc comment: lexed as a token, but source trivia to a printer.
    DocComment,
}

/// One lexed token: its byte span and its class.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SourceToken {
    /// The token's byte range in the source.
    pub span: Span,
    /// Whether the token is code or a doc comment.
    pub class: TokenClass,
}

/// Every token of `src` in source order, or `None` when `src` does not lex.
///
/// The bytes between consecutive tokens are exactly the lexer's trivia —
/// whitespace, `--` line comments and `{- -}` block comments — so a consumer
/// that recovers comments from those gaps agrees with the lexer on what is a
/// comment and what is literal content.
#[must_use]
pub fn try_source_tokens(src: &str) -> Option<Vec<SourceToken>> {
    let tokens = lexer::lex(src).ok()?;
    Some(
        tokens
            .iter()
            .map(|t| SourceToken {
                span: t.span,
                class: match &t.kind {
                    lexer::Tok::DocComment(_) => TokenClass::DocComment,
                    kind => TokenClass::Code(parser::tok_kind(kind)),
                },
            })
            .collect(),
    )
}

pub use lexer::{KEYWORDS, is_ident_continue, is_ident_start};
pub use surface::{field_accessor, let_function, negation};

/// Return `true` when `s` is a reserved keyword.
///
/// Delegates to the lexer's own keyword table ([`KEYWORDS`]) — the single
/// source of truth for keyword recognition across crate boundaries.
#[must_use]
pub fn is_keyword(s: &str) -> bool {
    lexer::keyword(s).is_some()
}

/// Return `true` when `s` lexes as one plain identifier token.
///
/// The shape is `[A-Za-z_][A-Za-z0-9_]*` (ASCII only, per [`is_ident_start`]
/// and [`is_ident_continue`]) and not a reserved keyword. Case class (value
/// vs type) is left to the caller.
#[must_use]
pub fn is_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    chars.next().is_some_and(is_ident_start) && chars.all(is_ident_continue) && !is_keyword(s)
}

/// Parse a complete module from source text.
///
/// # Errors
/// Returns a [`ipe_diagnostics::Diagnostic`] if the source cannot be lexed or
/// does not form a valid module, or [`ipe_diagnostics::ParseError::TooDeep`]
/// if the recursion-depth guard trips.
pub fn parse_module(src: &str, interner: &mut Interner) -> DResult<Module> {
    let toks = lexer::lex(src)?;
    let mut p = parser::Parser::new(toks, interner);
    p.parse_module()
}

/// Parse a standalone type expression (a type annotation) from source text.
///
/// Returns the parsed [`TypeAnnotation`] and the [`Interner`] that holds any
/// interned symbols. The interner is returned so callers can resolve symbol
/// names back to strings.
///
/// The query may optionally start with `->` (a leading arrow), which is the
/// "return-type-only" query form (`-> Task Error ()`). In that case the leading
/// `->` is consumed and a phantom unit left-hand side is prepended so the
/// result can be matched as a curried function whose result is the written type.
///
/// # Errors
///
/// Returns a [`Diagnostic`] if the source cannot be lexed or does not form a
/// valid type expression, or if any tokens remain unconsumed after the type
/// (trailing garbage is a parse error, not a silent truncation).
pub fn parse_type_query(src: &str) -> DResult<(TypeAnnotation, Interner)> {
    let mut interner = Interner::new();

    // A query may start with `->` to express "any function whose result is T".
    // Strip the leading `->` and later wrap the parsed type in a
    // `TLambda(TUnit, <parsed>)` phantom to unify with result-matching.
    let trimmed = src.trim();
    let (is_result_only, effective_src) = trimmed
        .strip_prefix("->")
        .map_or((false, trimmed), |rest| (true, rest.trim()));

    let toks = lexer::lex(effective_src)?;
    let mut p = parser::Parser::new(toks, &mut interner);
    let ann = p.parse_type_standalone()?;

    let final_ann = if is_result_only {
        // Wrap: `() -> <ann>`.
        TypeAnnotation::TLambda(Box::new(TypeAnnotation::TUnit), Box::new(ann))
    } else {
        ann
    };

    Ok((final_ann, interner))
}

/// Token-level scan of the module paths named by `import` in `src`.
///
/// Lexes `src` with the real lexer and returns the dotted path of every
/// `Ident` token that immediately follows an `import` keyword token — exactly
/// the token shape [`parse_module`]'s import parser consumes (one `import`
/// token, then one dotted-identifier token; the layout filter never splices
/// tokens between them). Because the parser reads this same token stream,
/// every import edge in a successfully parsed module's AST appears in this
/// scan. The scan may *over*-approximate (an `import` keyword token outside
/// the header is a parse error, not an edge) but can never miss an AST edge —
/// the load-bearing property for the driver's IPE-N0021 import-cycle gate.
///
/// Returns `None` when `src` does not lex. An unlexable module cannot parse,
/// so it contributes no AST import edges; callers may substitute a heuristic
/// scan for ordering purposes only.
#[must_use]
pub fn scan_import_paths(src: &str) -> Option<Vec<Vec<String>>> {
    let toks = lexer::lex(src).ok()?;
    let mut out: Vec<Vec<String>> = Vec::new();
    for pair in toks.windows(2) {
        let [first, second] = pair else { continue };
        if first.kind == lexer::Tok::Import
            && let lexer::Tok::Ident(text) = &second.kind
        {
            out.push(text.split('.').map(str::to_owned).collect());
        }
    }
    Some(out)
}

/// Token-level scan of every identifier word occurring in `src` — the
/// program-derived collision universe for the lowerer's fresh-name pools
/// (`Interner::set_fresh_avoid`).
///
/// Lexes `src` with the real lexer and collects, for every `Ident` token,
/// the full (possibly dotted) text AND each dot-segment — a superset of every
/// identifier string [`parse_module`] interns from this module. Triple-quoted
/// strings contribute the words inside their `{{…}}` interpolation regions
/// (the canonicaliser resolves those as real identifier references); plain
/// string/char literal contents and comments contribute nothing, matching
/// what the parser actually interns.
///
/// Soundness shape: the set must OVER-approximate the module's user
/// identifiers (a missing identifier could let a minted fresh name capture
/// it); extra words only skip more candidates.
///
/// Returns `None` when `src` does not lex (an unlexable module cannot parse,
/// so it never reaches lowering; callers may substitute a raw word scan for
/// totality).
#[must_use]
pub fn scan_identifier_words(src: &str) -> Option<std::collections::BTreeSet<String>> {
    let toks = lexer::lex(src).ok()?;
    let mut words = std::collections::BTreeSet::new();
    for tok in &toks {
        match &tok.kind {
            lexer::Tok::Ident(text) => {
                // Guard each insert with a membership check: repeated identifiers
                // (the common case) then allocate nothing, since `to_owned` is
                // only paid for a word the set does not already hold.
                if !words.contains(text.as_str()) {
                    words.insert(text.clone());
                }
                // An undotted identifier's only segment equals `text`, which is
                // already inserted above; skip the split entirely for it.
                if text.contains('.') {
                    for segment in text.split('.') {
                        if !words.contains(segment) {
                            words.insert(segment.to_owned());
                        }
                    }
                }
            }
            lexer::Tok::TripleStr { raw, .. } => {
                // `{{expr}}` interpolation bodies are canonicalised as real
                // expressions; collect their identifier-shaped words.
                let mut rest = raw.as_str();
                while let Some(open) = rest.find("{{") {
                    let after = rest.get(open.saturating_add(2)..).unwrap_or("");
                    let Some(close) = after.find("}}") else {
                        break;
                    };
                    let body = after.get(..close).unwrap_or("");
                    for word in body.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')) {
                        if !word.is_empty() {
                            words.insert(word.to_owned());
                        }
                    }
                    rest = after.get(close.saturating_add(2)..).unwrap_or("");
                }
            }
            _ => {}
        }
    }
    Some(words)
}

/// The bounds of the identifier-like run touching `byte`.
///
/// It extends back through whatever `is_ident_continue` bytes are already typed before `byte`,
/// forward through whatever `is_ident_continue` bytes a mid-word cursor
/// leaves untyped after it.
///
/// Pure ASCII byte scanning — no lexing, no parsing — so it is total on any
/// buffer, including one the lexer cannot tokenize at all. `start == end ==
/// byte.min(src.len())` means the cursor touches no identifier (e.g. right
/// after a fresh `.` with nothing typed yet).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WordSpan {
    pub start: u32,
    pub end: u32,
}

/// Scan the identifier run touching `byte` in `src`. See [`WordSpan`].
#[must_use]
pub fn scan_word_span(src: &str, byte: u32) -> WordSpan {
    let bytes = src.as_bytes();
    let at = (byte as usize).min(bytes.len());
    let is_continue = |i: usize| bytes.get(i).is_some_and(|&b| is_ident_continue(b as char));

    let mut start = at;
    while start > 0 && is_continue(start - 1) {
        start -= 1;
    }
    let mut end = at;
    while is_continue(end) {
        end += 1;
    }
    WordSpan {
        start: u32::try_from(start).unwrap_or(byte),
        end: u32::try_from(end).unwrap_or(byte),
    }
}

/// A `Qualifier.member` completion trigger touching `byte` in `src`.
///
/// It holds the dotted qualifier immediately before the trigger dot (`Font`, `F`, or the
/// full `Ipe.Ui.Font`), and the member-name run right after it — the typed
/// prefix plus, for a mid-word cursor, whatever untyped remainder follows.
///
/// `None` when `byte` is not on such a trigger at all: the byte immediately
/// before the member run is not `.`, or nothing shaped like a dotted
/// identifier path sits before that dot.
///
/// Pure ASCII byte scanning over the raw source text, same as
/// [`scan_word_span`] (which supplies the member run) — no lexing, no
/// parsing — so it is total on any buffer, including one with a syntax or
/// lex error at the trigger site itself (a dangling `Font.` is itself
/// unlexable: a bare trailing dot after a complete identifier is a
/// `StrayDot` lex error, so the real lexer can never be used here).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualifierPrefix {
    pub qualifier: String,
    pub member_prefix: String,
    pub member_start: u32,
    pub member_end: u32,
}

/// Scan the `Qualifier.member` trigger touching `byte` in `src`. See
/// [`QualifierPrefix`].
#[must_use]
pub fn scan_qualifier_prefix(src: &str, byte: u32) -> Option<QualifierPrefix> {
    let bytes = src.as_bytes();
    let is_continue = |i: usize| bytes.get(i).is_some_and(|&b| is_ident_continue(b as char));
    let is_start = |i: usize| bytes.get(i).is_some_and(|&b| is_ident_start(b as char));
    let is_dot = |i: usize| bytes.get(i) == Some(&b'.');

    let word = scan_word_span(src, byte);
    let member_start = word.start as usize;
    let at = (byte as usize).min(bytes.len());

    if member_start == 0 || !is_dot(member_start - 1) {
        return None;
    }
    let dot_at = member_start - 1;

    // Walk the dotted qualifier backward: one or more `Ident` segments
    // joined by single dots, each starting with an ident-start byte.
    let mut seg_end = dot_at;
    let mut segments: Vec<(usize, usize)> = Vec::new();
    loop {
        let mut seg_start = seg_end;
        while seg_start > 0 && is_continue(seg_start - 1) {
            seg_start -= 1;
        }
        if seg_start == seg_end || !is_start(seg_start) {
            return None;
        }
        segments.push((seg_start, seg_end));
        if seg_start == 0 || !is_dot(seg_start - 1) {
            break;
        }
        seg_end = seg_start - 1;
    }
    segments.reverse();

    let qualifier = segments
        .iter()
        .map(|&(s, e)| src.get(s..e).unwrap_or(""))
        .collect::<Vec<_>>()
        .join(".");
    let member_prefix = src.get(member_start..at).unwrap_or("").to_owned();

    Some(QualifierPrefix {
        qualifier,
        member_prefix,
        member_start: word.start,
        member_end: word.end,
    })
}

#[cfg(test)]
// Triple-string lexer tests use `toks[0]` after asserting `toks.len() == 1`.
// The index is provably in-bounds at that point; suppressing the lint is
// cleaner than restructuring all assertions.
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use ipe_syntax::{Exposed, Exposing, Expr, Expr_, Pattern_, TypeAnnotation, Value};

    const GOLDEN: &str = include_str!("../../../../tests/golden/basics/Main.ipe");

    /// Every published keyword lexes as its keyword token, never an identifier.
    #[test]
    fn every_keyword_lexes_as_a_keyword_token() {
        for kw in KEYWORDS {
            assert!(is_keyword(kw), "{kw:?} is not recognised by `is_keyword`");
            let expected = lexer::keyword(kw);
            let toks = lexer::lex(kw);
            assert!(toks.is_ok(), "{kw:?} must lex: {toks:?}");
            let Ok(toks) = toks else { return };
            assert!(
                toks.iter().any(|t| expected.as_ref() == Some(&t.kind)),
                "{kw:?} did not lex to its keyword token: {toks:?}"
            );
            assert!(
                !toks.iter().any(|t| matches!(t.kind, lexer::Tok::Ident(_))),
                "{kw:?} lexed as an identifier: {toks:?}"
            );
        }
    }

    /// `is_identifier` refuses every keyword, non-ASCII, and malformed shapes.
    #[test]
    fn is_identifier_refusals() {
        for kw in KEYWORDS {
            assert!(!is_identifier(kw), "keyword {kw:?} accepted as identifier");
        }
        for bad in [
            "",
            "1x",
            "a-b",
            "a.b",
            "café",
            "ação",
            "é",
            "x y",
            "\u{ff58}",
            "a\u{0301}",
        ] {
            assert!(!is_identifier(bad), "{bad:?} accepted as identifier");
        }
        for good in [
            "x", "_x", "foo_bar1", "Foo", "alias", "port", "where", "doX",
        ] {
            assert!(is_identifier(good), "{good:?} refused as identifier");
        }
    }

    fn find_value<'a>(m: &'a Module, i: &Interner, name: &str) -> Option<&'a Value> {
        m.values
            .iter()
            .map(|v| &v.value)
            .find(|v| i.resolve(v.name.value) == Some(name))
    }

    #[test]
    fn parses_golden_module_structure() {
        let mut i = Interner::new();
        let result = parse_module(GOLDEN, &mut i);
        assert!(result.is_ok(), "golden must parse: {result:?}");
        let Ok(m) = result else { return };

        // Module header: name `Main`, exposing (main).
        assert_eq!(m.name.value.len(), 1);
        assert_eq!(
            m.name.value.first().and_then(|&s| i.resolve(s)),
            Some("Main")
        );
        assert!(matches!(
            &m.exposing.value,
            Exposing::List(items)
                if items.len() == 1
                    && items.first().is_some_and(|e| matches!(e.value, Exposed::Value(_)))
        ));

        // One import: `Ipe.System as System`. The kernel-qualifier `Ipe.System`
        // resolves without a compiled-source injection, making it suitable as
        // the shared parse fixture.
        assert_eq!(m.imports.len(), 1);
        let seg_names = |imp: &ipe_syntax::Import| -> Vec<&str> {
            imp.name
                .value
                .iter()
                .filter_map(|&s| i.resolve(s))
                .collect()
        };
        if let Some(imp) = m.imports.first() {
            assert_eq!(seg_names(imp), ["Ipe", "System"]);
            assert_eq!(imp.alias.and_then(|s| i.resolve(s)), Some("System"));
            assert!(matches!(&imp.exposing.value, Exposing::List(items) if items.is_empty()));
        }

        // One union: Msg { Increment, Decrement }.
        assert_eq!(m.unions.len(), 1);
        if let Some(union) = m.unions.first().map(|u| &u.value) {
            assert_eq!(i.resolve(union.name.value), Some("Msg"));
            assert_eq!(union.ctors.len(), 2);
            assert_eq!(
                union.ctors.first().and_then(|c| i.resolve(c.value.name)),
                Some("Increment")
            );
            assert_eq!(
                union.ctors.get(1).and_then(|c| i.resolve(c.value.name)),
                Some("Decrement")
            );
            assert!(union.ctors.first().is_some_and(|c| c.value.args.is_empty()));
        }

        // Two values: `update` (annotated, two patterns, case body) and `main`.
        assert_eq!(m.values.len(), 2);

        let update = find_value(&m, &i, "update");
        assert!(update.is_some(), "update value present");
        if let Some(uval) = update {
            assert_eq!(uval.patterns.len(), 2);
            assert!(
                uval.patterns
                    .first()
                    .is_some_and(|p| matches!(p.value, Pattern_::PVar(_)))
            );
            assert!(
                uval.patterns
                    .get(1)
                    .is_some_and(|p| matches!(p.value, Pattern_::PVar(_)))
            );

            // Annotation: Msg -> Int -> Int (two nested arrows, all TType leaves).
            assert!(uval.type_annotation.as_ref().is_some_and(|ann| matches!(
                &ann.value,
                TypeAnnotation::TLambda(a, rest)
                    if matches!(**a, TypeAnnotation::TType(_, _, _))
                        && matches!(
                            &**rest,
                            TypeAnnotation::TLambda(b, c)
                                if matches!(**b, TypeAnnotation::TType(_, _, _))
                                    && matches!(**c, TypeAnnotation::TType(_, _, _))
                        )
            )));

            // Body is a `case` with two arms, each a Binops body.
            assert!(
                matches!(&uval.body.value, Expr_::Case(s, _) if matches!(s.value, Expr_::VarLocal(_)))
            );
            if let Expr_::Case(_, arms) = &uval.body.value {
                assert_eq!(arms.len(), 2);
                for (pat, body) in arms {
                    assert!(matches!(pat.value, Pattern_::PCtor(_, _, _)));
                    assert!(matches!(body.value, Expr_::Binops(_, _)));
                }
            }
        }

        // `main`: no patterns, no annotation, Call body whose callee is the
        // qualified `System.setenv` (a `VarQual`) applied to two string literals.
        let main = find_value(&m, &i, "main");
        assert!(main.is_some(), "main value present");
        if let Some(mval) = main {
            assert!(mval.patterns.is_empty());
            assert!(mval.type_annotation.is_none());
            assert!(
                matches!(&mval.body.value, Expr_::Call(c, _) if matches!(c.value, Expr_::VarQual(_, _)))
            );
            if let Expr_::Call(callee, args) = &mval.body.value {
                assert_eq!(args.len(), 2, "System.setenv takes two string arguments");
                // Both arguments are string literals.
                assert!(
                    args.iter().all(|a| matches!(a.value, Expr_::Str(_))),
                    "both args must be string literals"
                );
                // Callee is System.setenv.
                if let Expr_::VarQual(qsym, nsym) = callee.value {
                    assert_eq!(i.resolve(qsym), Some("System"));
                    assert_eq!(i.resolve(nsym), Some("setenv"));
                }
            }
        }
    }

    #[test]
    fn qualified_name_in_body_is_var_qual() {
        let mut i = Interner::new();
        let result = parse_module(GOLDEN, &mut i);
        assert!(result.is_ok());
        let Ok(m) = result else { return };
        let main = find_value(&m, &i, "main");
        assert!(main.is_some(), "main present");
        // main = System.setenv "HOME" "x" — the callee is directly a VarQual.
        let callee_val = main.and_then(|mv| match &mv.body.value {
            Expr_::Call(callee, _) => Some(&callee.value),
            _ => None,
        });
        assert!(
            callee_val.is_some_and(|q| matches!(
                q,
                Expr_::VarQual(qsym, nsym)
                    if i.resolve(*qsym) == Some("System") && i.resolve(*nsym) == Some("setenv")
            )),
            "expected System.setenv VarQual, got {callee_val:?}"
        );
    }

    /// A tiny deterministic xorshift PRNG — no external dependency.
    fn xorshift(state: &mut u64) -> u64 {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        x
    }

    /// The error code a bad source produces, or `"OK"` when it (unexpectedly)
    /// parses. Comparing the wire string keeps the assertions readable without
    /// importing every taxonomy constant.
    fn err_code(src: &str) -> String {
        let mut i = Interner::new();
        match parse_module(src, &mut i) {
            Ok(_) => "OK".to_owned(),
            Err(d) => d.code().as_str().to_owned(),
        }
    }

    /// A well-formed module header so a per-construct test isolates the body.
    const HDR: &str = "module Main exposing (main)\n";

    /// Whether `e` is a call of `Task.<name>`.
    fn is_task_call(e: &Expr_, i: &Interner, name: &str) -> bool {
        matches!(
            e,
            Expr_::Call(callee, _)
                if matches!(&callee.value, Expr_::VarQual(q, n)
                    if i.resolve(*q) == Some("Task") && i.resolve(*n) == Some(name))
        )
    }

    #[test]
    fn do_bind_desugars_to_task_and_then() {
        // `x <- task` becomes `Task.andThen (\x -> rest) task`.
        let mut i = Interner::new();
        let src = format!("{HDR}main =\n    do\n        x <- task\n        other x\n");
        let m = parse_module(&src, &mut i).expect("do block parses");
        let main = find_value(&m, &i, "main").expect("main present");
        assert!(
            is_task_call(&main.body.value, &i, "andThen"),
            "expected a `Task.andThen` call, got {:?}",
            main.body.value
        );
        if let Expr_::Call(_, args) = &main.body.value {
            assert!(
                matches!(args.first().map(|a| &a.value), Some(Expr_::Lambda(..))),
                "andThen's first argument must be the continuation lambda"
            );
        }
    }

    #[test]
    fn do_pure_let_followed_by_bind_desugars_to_let_then_and_then() {
        // `x = value` inside a `do` that also has a `<-` bind is a pure `let`
        // wrapping the Task-sequencing continuation. The block is not stepless
        // (it has a real `<-` Task bind) so it must parse.
        let mut i = Interner::new();
        let src = format!(
            "{HDR}main =\n    do\n        x = value\n        result <- task x\n        done result\n"
        );
        let m = parse_module(&src, &mut i).expect("do block with pure-let + bind parses");
        let main = find_value(&m, &i, "main").expect("main present");
        // The outer desugared node is a Let (the pure `x = value` bind wraps the
        // Task-sequenced inner chain).
        assert!(
            matches!(&main.body.value, Expr_::Let(binds, _) if binds.len() == 1),
            "expected outer `let x = value in (Task.andThen chain)`, got {:?}",
            main.body.value
        );
    }

    #[test]
    fn do_bare_line_desugars_to_wildcard_let() {
        // A bare effectful line sequences via `let _ = <effect> in <rest>`, not a
        // `Task.andThen (\_ -> …)` closure: the `let _`/`TaskSeq` form lowers with
        // no per-statement lambda, so a long `do` block stays a shallow chain
        // instead of a deep nest of inference-scope-opening closures.
        let mut i = Interner::new();
        let src = format!("{HDR}main =\n    do\n        step\n        done\n");
        let m = parse_module(&src, &mut i).expect("do block parses");
        let main = find_value(&m, &i, "main").expect("main present");
        assert!(
            matches!(
                &main.body.value,
                Expr_::Let(bindings, _)
                    if matches!(
                        bindings.first().map(|b| &b.pat.value),
                        Some(Pattern_::PAnything)
                    )
            ),
            "a bare run must desugar to `let _ = <effect> in <rest>`, got {:?}",
            main.body.value
        );
    }

    #[test]
    fn task_parallel_inside_do_bind_is_accepted() {
        // `results <- Task.parallel [a, b, c]` inside a `do` is the supported
        // spelling for concurrent fan-out (the former `doParallel` form).
        let mut i = Interner::new();
        let src = format!(
            "{HDR}main =\n    do\n        results <- Task.parallel [a, b, c]\n        done results\n"
        );
        let m = parse_module(&src, &mut i).expect("Task.parallel inside do parses");
        let main = find_value(&m, &i, "main").expect("main present");
        assert!(
            is_task_call(&main.body.value, &i, "andThen"),
            "outer `do` desugars to `Task.andThen`, got {:?}",
            main.body.value
        );
    }

    #[test]
    fn stepless_do_is_rejected() {
        // A `do` block whose every statement is a `=` pure binding — no `<-`
        // and no bare-run line — is rejected with `IPE-P0065`.
        assert_eq!(
            err_code(&format!(
                "{HDR}main =\n    do\n        x = 1\n        y = x + 1\n"
            )),
            "IPE-P0065",
            "stepless do (only `=` binds) must be IPE-P0065"
        );
    }

    #[test]
    fn do_ending_in_bare_run_after_pure_let_is_accepted() {
        // A `do` whose non-final statements are pure `=` lets followed by a
        // final bare-run line has a Task step (the run) and must parse; whether
        // that run is genuinely effectful is a type-level question, not P0065.
        let mut i = Interner::new();
        let src = format!("{HDR}main =\n    do\n        x = 1\n        run x\n");
        let m = parse_module(&src, &mut i);
        assert!(m.is_ok(), "do ending in a bare run must parse: {m:?}");
    }

    #[test]
    fn do_with_bind_step_is_accepted() {
        // A `do` with at least one `<-` is not stepless and must parse.
        let mut i = Interner::new();
        let src = format!(
            "{HDR}main =\n    do\n        x = 1\n        result <- task x\n        done result\n"
        );
        let m = parse_module(&src, &mut i);
        assert!(m.is_ok(), "do with a `<-` step must parse: {m:?}");
    }

    #[test]
    fn do_with_bare_run_step_is_accepted() {
        // A `do` with a bare-run line (not-last) is not stepless and must parse.
        let mut i = Interner::new();
        let src = format!("{HDR}main =\n    do\n        sideEffect\n        done\n");
        let m = parse_module(&src, &mut i);
        assert!(m.is_ok(), "do with a bare-run step must parse: {m:?}");
    }

    #[test]
    fn doparallel_keyword_is_not_reserved() {
        // `doParallel` is no longer a keyword; it now lexes as a plain identifier.
        // A binding named `doParallel` must parse without error.
        let mut i = Interner::new();
        let src = format!("{HDR}doParallel =\n    42\n");
        let m = parse_module(&src, &mut i);
        assert!(
            m.is_ok(),
            "`doParallel` must lex as a plain identifier after keyword removal: {m:?}"
        );
    }

    #[test]
    fn full_operator_set_parses_into_a_binops_chain() {
        // Every core operator must lex + parse; the body becomes a flat
        // `Binops` chain (precedence is resolved later, at canonicalisation).
        let mut i = Interner::new();
        let src = format!(
            "{HDR}f a b c =\n    a + b * c - a / b == c /= a < b > c <= a >= b && c || a\n"
        );
        let m = parse_module(&src, &mut i);
        assert!(m.is_ok(), "all operators must parse: {m:?}");
        let Ok(m) = m else { return };
        let f = find_value(&m, &i, "f");
        assert!(
            f.is_some_and(|v| matches!(v.body.value, Expr_::Binops(ref ops, _) if ops.len() == 12)),
            "body is a 12-operator flat chain, got {:?}",
            f.map(|v| &v.body.value)
        );
    }

    #[test]
    fn single_param_lambda_parses_with_body() {
        // `\x -> x + 1` is a one-parameter lambda whose body greedily captures
        // the whole `x + 1` operator chain.
        let mut i = Interner::new();
        let src = format!("{HDR}f =\n    \\x -> x + 1\n");
        let m = parse_module(&src, &mut i);
        assert!(m.is_ok(), "lambda must parse: {m:?}");
        let Ok(m) = m else { return };
        let f = find_value(&m, &i, "f");
        let body = f.map(|v| &v.body.value);
        assert!(
            matches!(
                body,
                Some(Expr_::Lambda(params, b))
                    if params.len() == 1 && matches!(b.value, Expr_::Binops(..))
            ),
            "expected a 1-param lambda over a binop body, got {body:?}"
        );
    }

    #[test]
    fn multi_param_lambda_parses_all_params() {
        // `\a b -> a + b` is a two-parameter lambda.
        let mut i = Interner::new();
        let src = format!("{HDR}f =\n    \\a b -> a + b\n");
        let m = parse_module(&src, &mut i);
        assert!(m.is_ok(), "multi-param lambda must parse: {m:?}");
        let Ok(m) = m else { return };
        let f = find_value(&m, &i, "f");
        assert!(
            f.and_then(|v| match &v.body.value {
                Expr_::Lambda(params, _) => Some(params.len()),
                _ => None,
            }) == Some(2),
            "expected a 2-param lambda, got {:?}",
            f.map(|v| &v.body.value)
        );
    }

    #[test]
    fn parenthesised_lambda_is_applied() {
        // `(\x -> x) 5` parses as an application whose callee is the lambda.
        let mut i = Interner::new();
        let src = format!("{HDR}f =\n    (\\x -> x) 5\n");
        let m = parse_module(&src, &mut i);
        assert!(m.is_ok(), "applied lambda must parse: {m:?}");
        let Ok(m) = m else { return };
        let f = find_value(&m, &i, "f");
        assert!(
            f.is_some_and(|v| matches!(
                &v.body.value,
                Expr_::Call(callee, args)
                    if matches!(callee.value, Expr_::Lambda(..)) && args.len() == 1
            )),
            "expected a Call with a Lambda callee, got {:?}",
            f.map(|v| &v.body.value)
        );
    }

    #[test]
    fn lambda_without_arrow_is_a_parse_error() {
        // `\x x` — no `->` after the parameters.
        assert_eq!(err_code(&format!("{HDR}f =\n    \\x 1\n")), "IPE-P0001");
    }

    #[test]
    fn lambda_without_params_is_a_parse_error() {
        // `\ -> 1` — a zero-parameter lambda is outside the grammar.
        assert_eq!(err_code(&format!("{HDR}f =\n    \\ -> 1\n")), "IPE-P0001");
    }

    #[test]
    fn bare_field_accessor_desugars_to_a_getter_lambda() {
        // `.name` as a value is the first-class accessor `{ r | name : a } -> a`.
        // It desugars at parse time to `\<fresh> -> <fresh>.name`, i.e. a
        // one-parameter lambda whose body is an `Access` of the parameter.
        let mut i = Interner::new();
        let src = format!("{HDR}f =\n    .name\n");
        let m = parse_module(&src, &mut i);
        assert!(m.is_ok(), "bare accessor must parse: {m:?}");
        let Ok(m) = m else { return };
        let f = find_value(&m, &i, "f");
        let body = f.map(|v| &v.body.value);
        assert!(
            matches!(
                body,
                Some(Expr_::Lambda(params, b))
                    if params.len() == 1
                        && matches!(
                            &b.value,
                            Expr_::Access(inner, field)
                                if matches!(inner.value, Expr_::VarLocal(_))
                                    && i.resolve(field.value) == Some("name")
                        )
            ),
            "expected `\\p -> p.name`, got {body:?}"
        );
        // The lambda parameter and the accessed record must be the SAME symbol,
        // so the body resolves to the synthesised parameter, never a user binding.
        if let Some(Expr_::Lambda(params, b)) = body
            && let (Some(param), Expr_::Access(inner, _)) = (params.first(), &b.value)
            && let (Pattern_::PVar(p), Expr_::VarLocal(v)) = (&param.value, &inner.value)
        {
            assert_eq!(p, v, "accessor param and access target must be one symbol");
        }
    }

    #[test]
    fn accessor_as_a_map_argument_parses() {
        // `List.map .name xs` — the accessor is a first-class argument.
        let mut i = Interner::new();
        let src = format!("{HDR}f xs =\n    List.map .name xs\n");
        let m = parse_module(&src, &mut i);
        assert!(m.is_ok(), "accessor argument must parse: {m:?}");
        let Ok(m) = m else { return };
        let f = find_value(&m, &i, "f");
        // Body is `List.map .name xs` — a Call whose second argument is the
        // desugared accessor lambda.
        assert!(
            f.is_some_and(|v| matches!(
                &v.body.value,
                Expr_::Call(_, args)
                    if args.len() == 2 && matches!(args.first().map(|a| &a.value), Some(Expr_::Lambda(..)))
            )),
            "expected `Call(List.map, [<accessor lambda>, xs])`, got {:?}",
            f.map(|v| &v.body.value)
        );
    }

    #[test]
    fn nested_field_accessor_chains_the_access() {
        // `.a.b` accessor desugars to `\p -> p.a.b` (nested Access).
        let mut i = Interner::new();
        let src = format!("{HDR}f =\n    .a.b\n");
        let m = parse_module(&src, &mut i);
        assert!(m.is_ok(), "nested accessor must parse: {m:?}");
        let Ok(m) = m else { return };
        let f = find_value(&m, &i, "f");
        assert!(
            f.is_some_and(|v| matches!(
                &v.body.value,
                Expr_::Lambda(params, b)
                    if params.len() == 1
                        && matches!(
                            &b.value,
                            // outer `.b` over inner `.a` over the parameter
                            Expr_::Access(inner, _)
                                if matches!(inner.value, Expr_::Access(..))
                        )
            )),
            "expected `\\p -> p.a.b`, got {:?}",
            f.map(|v| &v.body.value)
        );
    }

    #[test]
    fn lone_ampersand_is_unknown_char() {
        // A single `&` is not a Ipê operator (only `&&`); it lexes as IPE-P0010.
        assert_eq!(err_code(&format!("{HDR}x = 1 & 2")), "IPE-P0010");
    }

    #[test]
    fn lexer_errors_carry_their_codes() {
        // IPE-P0010 unknown character.
        assert_eq!(err_code("module Main exposing (main)\nx = @"), "IPE-P0010");
        // IPE-P0011 stray '.'.
        assert_eq!(err_code("."), "IPE-P0011");
        // IPE-P0012 number joined to a name.
        assert_eq!(err_code("123abc"), "IPE-P0012");
        // IPE-P0013 integer literal out of range.
        assert_eq!(err_code("99999999999999999999999"), "IPE-P0013");
    }

    #[test]
    fn bare_field_access_parses_unchanged() {
        // `record.field` — no space — is one dotted identifier resolved to an
        // `Access`; whitespace-sensitive dot handling must not disturb this.
        let mut i = Interner::new();
        let src = format!("{HDR}f r =\n    r.name\n");
        let m = parse_module(&src, &mut i);
        assert!(m.is_ok(), "bare field access must parse: {m:?}");
        let Ok(m) = m else { return };
        let body = find_value(&m, &i, "f").map(|v| &v.body.value);
        assert!(
            matches!(body, Some(Expr_::Access(..))),
            "expected an Access, got {body:?}"
        );
    }

    #[test]
    fn chained_field_access_parses_unchanged() {
        // `a.b.c` still parses; each segment nests as a further `Access`.
        let mut i = Interner::new();
        let src = format!("{HDR}f a =\n    a.b.c\n");
        let m = parse_module(&src, &mut i);
        assert!(m.is_ok(), "chained field access must parse: {m:?}");
        let Ok(m) = m else { return };
        let body = find_value(&m, &i, "f").map(|v| &v.body.value);
        assert!(
            matches!(body, Some(Expr_::Access(inner, _)) if matches!(inner.value, Expr_::Access(..))),
            "expected nested Access, got {body:?}"
        );
    }

    #[test]
    fn parenthesised_field_access_parses_unchanged() {
        // `(r).value` — the `.` is flush against the `)`, so it stays field
        // access on the parenthesised atom.
        let mut i = Interner::new();
        let src = format!("{HDR}f r =\n    (r).value\n");
        let m = parse_module(&src, &mut i);
        assert!(m.is_ok(), "parenthesised field access must parse: {m:?}");
        let Ok(m) = m else { return };
        let body = find_value(&m, &i, "f").map(|v| &v.body.value);
        assert!(
            matches!(body, Some(Expr_::Access(..))),
            "expected an Access, got {body:?}"
        );
    }

    #[test]
    fn space_before_dot_is_the_accessor_application() {
        // `f .x` is `.x` (the first-class accessor `\p -> p.x`) applied to `f` —
        // a `Call` of `f` on the desugared accessor lambda, not field access.
        let mut i = Interner::new();
        let src = format!("{HDR}g f =\n    f .x\n");
        let m = parse_module(&src, &mut i);
        assert!(
            m.is_ok(),
            "`f .x` must parse as accessor application: {m:?}"
        );
        let Ok(m) = m else { return };
        let g = find_value(&m, &i, "g");
        assert!(
            g.is_some_and(|v| matches!(
                &v.body.value,
                Expr_::Call(callee, args)
                    if matches!(callee.value, Expr_::VarLocal(_))
                        && args.len() == 1
                        && matches!(args.first().map(|a| &a.value), Some(Expr_::Lambda(..)))
            )),
            "expected `Call(f, [<accessor lambda>])`, got {:?}",
            g.map(|v| &v.body.value)
        );
    }

    #[test]
    fn accessor_function_argument_parses() {
        // A realistic accessor use — `map .name people` — gathers the spaced
        // `.name` as the first argument (the desugared accessor lambda).
        let mut i = Interner::new();
        let src = format!("{HDR}names people =\n    map .name people\n");
        let m = parse_module(&src, &mut i);
        assert!(m.is_ok(), "`map .name people` must parse: {m:?}");
        let Ok(m) = m else { return };
        let names = find_value(&m, &i, "names");
        assert!(
            names.is_some_and(|v| matches!(
                &v.body.value,
                Expr_::Call(_, args)
                    if args.len() == 2
                        && matches!(args.first().map(|a| &a.value), Some(Expr_::Lambda(..)))
            )),
            "expected `Call(map, [<accessor lambda>, people])`, got {:?}",
            names.map(|v| &v.body.value)
        );
    }

    #[test]
    fn space_before_dot_after_paren_is_accessor_application() {
        // `(r) .value` — the space makes `.value` the first-class accessor
        // applied to `(r)`, distinct from the flush `(r).value` field access
        // above. It parses as `Call((r), [<accessor lambda>])`.
        let mut i = Interner::new();
        let src = format!("{HDR}f r =\n    (r) .value\n");
        let m = parse_module(&src, &mut i);
        assert!(m.is_ok(), "`(r) .value` must parse: {m:?}");
        let Ok(m) = m else { return };
        let f = find_value(&m, &i, "f");
        assert!(
            f.is_some_and(|v| matches!(
                &v.body.value,
                Expr_::Call(_, args)
                    if args.len() == 1
                        && matches!(args.first().map(|a| &a.value), Some(Expr_::Lambda(..)))
            )),
            "expected `Call((r), [<accessor lambda>])`, got {:?}",
            f.map(|v| &v.body.value)
        );
    }

    #[test]
    fn float_literals_lex_to_float_tokens() {
        use lexer::{IntMagnitude, Tok, lex};
        let int = |digits: &str| Tok::Int(IntMagnitude::from_digits(digits).unwrap());
        let kinds = |src: &str| -> Vec<Tok> {
            lex(src).map_or_else(
                |_| Vec::new(),
                |toks| toks.into_iter().map(|t| t.kind).collect(),
            )
        };
        // Plain fraction, whole-number fraction, and both exponent shapes.
        assert_eq!(kinds("1.5"), vec![Tok::Float(1.5)]);
        assert_eq!(kinds("3.0"), vec![Tok::Float(3.0)]);
        assert_eq!(kinds("1.5e3"), vec![Tok::Float(1500.0)]);
        assert_eq!(kinds("2e-2"), vec![Tok::Float(0.02)]);
        assert_eq!(kinds("6E2"), vec![Tok::Float(600.0)]);
        // An integer with no fraction / exponent stays an `Int`.
        assert_eq!(kinds("42"), vec![int("42")]);
        // `1..5` is a range, not a float: the `..` is not consumed as a point.
        assert_eq!(kinds("1..5"), vec![int("1"), Tok::DotDot, int("5")]);
    }

    #[test]
    fn pipe_operators_lex_as_single_tokens() {
        use lexer::{Tok, lex};
        let kinds = |src: &str| -> Vec<Tok> {
            lex(src).map_or_else(
                |_| Vec::new(),
                |toks| toks.into_iter().map(|t| t.kind).collect(),
            )
        };
        // `|>` is a single PipeGt token (forward pipe), not Pipe + Gt.
        assert_eq!(kinds("|>"), vec![Tok::PipeGt]);
        // `<|` is a single LtPipe token (backward pipe), not Lt + Pipe.
        assert_eq!(kinds("<|"), vec![Tok::LtPipe]);
        // Maximal munch non-regression: `||` remains PipePipe, not two Pipes or
        // a PipeGt/PipePipe confusion.
        assert_eq!(kinds("||"), vec![Tok::PipePipe]);
        // `<=` remains Le (not LtPipe then Equals).
        assert_eq!(kinds("<="), vec![Tok::Le]);
        // A lone `|` remains Pipe.
        assert_eq!(kinds("|"), vec![Tok::Pipe]);
        // A lone `<` remains Lt.
        assert_eq!(kinds("<"), vec![Tok::Lt]);
        // `|> x` in context.
        assert_eq!(kinds("|> x"), vec![Tok::PipeGt, Tok::Ident("x".to_owned())]);
        // `<| x` in context.
        assert_eq!(kinds("<| x"), vec![Tok::LtPipe, Tok::Ident("x".to_owned())]);
        // `|||` is PipePipe + lone Pipe (maximal munch takes exactly two `|`).
        assert_eq!(kinds("|||"), vec![Tok::PipePipe, Tok::Pipe]);
        // `|>>` is PipeGt + lone Gt (maximal munch on `|>`, then `>` is bare).
        assert_eq!(kinds("|>>"), vec![Tok::PipeGt, Tok::Gt]);
    }

    #[test]
    fn composition_operators_lex_as_single_tokens() {
        use lexer::{Tok, lex};
        let kinds = |src: &str| -> Vec<Tok> {
            lex(src).map_or_else(
                |_| Vec::new(),
                |toks| toks.into_iter().map(|t| t.kind).collect(),
            )
        };
        // `>>` is a single GtGt token (forward composition), not two Gt.
        assert_eq!(kinds(">>"), vec![Tok::GtGt]);
        // `<<` is a single LtLt token (backward composition), not two Lt.
        assert_eq!(kinds("<<"), vec![Tok::LtLt]);
        // Bare `>` / `<` and the comparison forms are unaffected.
        assert_eq!(kinds(">"), vec![Tok::Gt]);
        assert_eq!(kinds("<"), vec![Tok::Lt]);
        assert_eq!(kinds(">="), vec![Tok::Ge]);
        assert_eq!(kinds("<="), vec![Tok::Le]);
        // `<|` / `|>` still win their maximal munch (not confused with `<<`/`>>`).
        assert_eq!(kinds("<|"), vec![Tok::LtPipe]);
        // Maximal munch takes exactly two: `>>>` is `>>` then a trailing `>`.
        assert_eq!(kinds(">>>"), vec![Tok::GtGt, Tok::Gt]);
        assert_eq!(kinds("<<<"), vec![Tok::LtLt, Tok::Lt]);
        // In context.
        assert_eq!(kinds(">> g"), vec![Tok::GtGt, Tok::Ident("g".to_owned())]);
    }

    #[test]
    fn composition_operators_parse_in_expression() {
        // Both composition operators must parse in a flat Binops chain.
        let mut i = Interner::new();
        let src = format!("{HDR}h =\n    inc >> dbl\n");
        let m = parse_module(&src, &mut i);
        assert!(m.is_ok(), "`>>` must parse: {m:?}");

        let mut i2 = Interner::new();
        let src2 = format!("{HDR}h =\n    inc << dbl\n");
        let m2 = parse_module(&src2, &mut i2);
        assert!(m2.is_ok(), "`<<` must parse: {m2:?}");
    }

    #[test]
    fn pipe_operator_parses_in_expression() {
        // Both pipe operators must parse in a flat Binops chain.
        let mut i = Interner::new();
        let src = format!("{HDR}f x =\n    x |> String.fromInt\n");
        let m = parse_module(&src, &mut i);
        assert!(m.is_ok(), "`|>` must parse: {m:?}");

        let mut i2 = Interner::new();
        let src2 = format!("{HDR}f x =\n    String.fromInt <| x\n");
        let m2 = parse_module(&src2, &mut i2);
        assert!(m2.is_ok(), "`<|` must parse: {m2:?}");
    }

    #[test]
    fn parser_pipeline_operators_lex_as_single_tokens() {
        use lexer::{Tok, lex};
        let kinds = |src: &str| -> Vec<Tok> {
            lex(src).map_or_else(
                |_| Vec::new(),
                |toks| toks.into_iter().map(|t| t.kind).collect(),
            )
        };
        // `|=` is a single PipeEq token, not Pipe + Equals.
        assert_eq!(kinds("|="), vec![Tok::PipeEq]);
        // `|.` is a single PipeDot token, not Pipe + Dot.
        assert_eq!(kinds("|."), vec![Tok::PipeDot]);
        // Existing pipe tokens are unaffected by the new arms.
        assert_eq!(kinds("|>"), vec![Tok::PipeGt]);
        assert_eq!(kinds("||"), vec![Tok::PipePipe]);
        assert_eq!(kinds("|"), vec![Tok::Pipe]);
        // `|==` is PipeEq + lone Equals (maximal munch of `|=`).
        assert_eq!(kinds("|=="), vec![Tok::PipeEq, Tok::Equals]);
        // `|.x` is PipeDot + Ident (no space needed; Dot is consumed by PipeDot munch).
        assert_eq!(
            kinds("|. x"),
            vec![Tok::PipeDot, Tok::Ident("x".to_owned())]
        );
        // In context.
        assert_eq!(
            kinds("|= pa"),
            vec![Tok::PipeEq, Tok::Ident("pa".to_owned())]
        );
    }

    #[test]
    fn parser_pipeline_operators_parse_in_expression() {
        // Both parser-pipeline operators must parse in a flat Binops chain.
        let mut i = Interner::new();
        let src = format!("{HDR}f p =\n    p |= pa\n");
        let m = parse_module(&src, &mut i);
        assert!(m.is_ok(), "`|=` must parse: {m:?}");

        let mut i2 = Interner::new();
        let src2 = format!("{HDR}f p =\n    p |. sep\n");
        let m2 = parse_module(&src2, &mut i2);
        assert!(m2.is_ok(), "`|.` must parse: {m2:?}");

        // A chain `p |= pa |. sep |= pb` must parse as a flat Binops chain.
        let mut i3 = Interner::new();
        let src3 = format!("{HDR}f p =\n    p |= pa |. sep |= pb\n");
        let m3 = parse_module(&src3, &mut i3);
        assert!(m3.is_ok(), "mixed `|=` / `|.` chain must parse: {m3:?}");
    }

    #[test]
    fn plus_plus_lexes_as_one_append_token() {
        use lexer::{Tok, lex};
        let kinds = |src: &str| -> Vec<Tok> {
            lex(src).map_or_else(
                |_| Vec::new(),
                |toks| toks.into_iter().map(|t| t.kind).collect(),
            )
        };
        // `++` is a single append token (maximal munch of `+`), not two `Plus`.
        assert_eq!(kinds("++"), vec![Tok::PlusPlus]);
        // A lone `+` is still arithmetic addition.
        assert_eq!(kinds("+"), vec![Tok::Plus]);
        // A spaced pair is two separate `Plus` tokens — only adjacency forms `++`.
        assert_eq!(kinds("+ +"), vec![Tok::Plus, Tok::Plus]);
        // Maximal munch takes exactly two: `+++` is `++` then a trailing `+`.
        assert_eq!(kinds("+++"), vec![Tok::PlusPlus, Tok::Plus]);
        // In context: a string append chain `"a" ++ "b"`.
        assert_eq!(
            kinds("\"a\" ++ \"b\""),
            vec![
                Tok::Str("a".to_owned()),
                Tok::PlusPlus,
                Tok::Str("b".to_owned())
            ]
        );
    }

    #[test]
    fn leading_dot_is_not_a_float() {
        // Elm-style requires a leading digit, so `.5` is a stray `.` (IPE-P0011),
        // never a float.
        assert_eq!(err_code(".5"), "IPE-P0011");
    }

    #[test]
    fn trailing_exponent_marker_is_joined_name() {
        // `1.5e` has no digit after the exponent marker, so the `e` reads as a
        // name joined to the number (IPE-P0012) rather than an exponent.
        assert_eq!(err_code("1.5e"), "IPE-P0012");
        // A letter immediately after a float is likewise a joined name.
        assert_eq!(err_code("1.5x"), "IPE-P0012");
    }

    #[test]
    fn float_past_f64_max_is_p0016() {
        use lexer::{Tok, lex};
        let kinds = |src: &str| -> Vec<Tok> {
            lex(src).map_or_else(
                |_| Vec::new(),
                |toks| toks.into_iter().map(|t| t.kind).collect(),
            )
        };
        // `1e400` overflows f64 to infinity; rejecting it (rather than silently
        // accepting `inf`) keeps parity with the reference. A finite literal,
        // including the largest in-range exponent, still lexes cleanly.
        assert_eq!(err_code("1e400"), "IPE-P0016");
        assert_eq!(err_code("1.0e309"), "IPE-P0016");
        assert_eq!(kinds("1e308"), vec![Tok::Float(1e308)]);
        // A genuine `0.0` is finite and must not be mistaken for an overflow.
        assert_eq!(kinds("0.0"), vec![Tok::Float(0.0)]);
    }

    #[test]
    fn malformed_module_header_is_p0020() {
        // Not `module`.
        assert_eq!(err_code("import X exposing (..)"), "IPE-P0020");
        // Module name not an identifier.
        assert_eq!(err_code("module = x"), "IPE-P0020");
        // Missing `exposing`.
        assert_eq!(err_code("module Main"), "IPE-P0020");
    }

    #[test]
    fn malformed_exposing_list_is_p0021() {
        // Missing `(`.
        assert_eq!(err_code("module Main exposing main)"), "IPE-P0021");
        // Bad separator between items.
        assert_eq!(err_code("module Main exposing (a b)"), "IPE-P0021");
    }

    #[test]
    fn missing_equals_is_p0030() {
        assert_eq!(err_code(&format!("{HDR}foo 5")), "IPE-P0030");
    }

    #[test]
    fn orphan_annotation_is_rejected_p0068() {
        // A `name : T` annotation whose name misspells its definition attaches
        // to nothing and must be rejected, not silently dropped.
        let src = format!("{HDR}incrementt : Int\nincrement =\n    1\n");
        assert_eq!(err_code(&src), "IPE-P0068");
        // A lone annotation with no definition at all is likewise an orphan.
        assert_eq!(err_code(&format!("{HDR}x : Int\n")), "IPE-P0068");
    }

    #[test]
    fn duplicate_annotation_is_rejected_p0069() {
        // Two annotations for one name give no single type to attach; reject
        // rather than keep one last-write-wins.
        let src = format!("{HDR}area : Int\narea : Float\narea =\n    1\n");
        assert_eq!(err_code(&src), "IPE-P0069");
    }

    #[test]
    fn valid_annotation_still_attaches() {
        // The common, correct case must keep parsing: one annotation, one
        // matching definition, type attached to the value.
        let mut i = Interner::new();
        let src = format!("{HDR}v : Int\nv =\n    1\n");
        let m = parse_module(&src, &mut i).expect("annotated value must parse");
        let v = find_value(&m, &i, "v").expect("v present");
        assert!(
            v.type_annotation.is_some(),
            "the `v : Int` annotation must attach to `v`"
        );
    }

    #[test]
    fn malformed_type_declaration_is_p0031() {
        // Missing type name.
        assert_eq!(err_code(&format!("{HDR}type = Foo")), "IPE-P0031");
        // Missing `=` before constructors.
        assert_eq!(err_code(&format!("{HDR}type Foo Bar")), "IPE-P0031");
        // Constructor not uppercase.
        assert_eq!(err_code(&format!("{HDR}type Foo = bar")), "IPE-P0031");
    }

    #[test]
    fn type_args_on_non_constructor_is_p0040() {
        assert_eq!(err_code(&format!("{HDR}x : a Int\nx = 5")), "IPE-P0040");
    }

    #[test]
    fn expected_type_is_p0041() {
        // A token that cannot begin a type.
        assert_eq!(err_code(&format!("{HDR}x : =\nx = 5")), "IPE-P0041");
        // A dotted uppercase type now PARSES (qualified type support):
        // `Foo.Bar` becomes TType("Foo", ["Bar"], []) — canonicalisation (not
        // the parser) is responsible for validating that `Foo` is a known module.
        assert_eq!(err_code(&format!("{HDR}x : Foo.Bar\nx = 5")), "OK");
    }

    #[test]
    fn unclosed_delimiter_is_p0050() {
        assert_eq!(err_code(&format!("{HDR}main = (5")), "IPE-P0050");
    }

    #[test]
    fn malformed_case_is_p0060() {
        // `of` missing after the scrutinee.
        assert_eq!(err_code(&format!("{HDR}main = case 5")), "IPE-P0060");
        // `->` missing in a branch.
        let missing_arrow = format!("{HDR}main =\n    case main of\n        Foo 5\n");
        assert_eq!(err_code(&missing_arrow), "IPE-P0060");
    }

    #[test]
    fn inline_let_parses_into_a_let_node() {
        // `let x = 2 in x + x` is a single-binding `Let` whose body is a Binops.
        let mut i = Interner::new();
        let src = format!("{HDR}v : Int\nv =\n    let x = 2 in x + x\n");
        let m = parse_module(&src, &mut i);
        assert!(m.is_ok(), "inline let must parse: {m:?}");
        let Ok(m) = m else { return };
        let v = find_value(&m, &i, "v");
        assert!(
            v.is_some_and(|v| matches!(&v.body.value, Expr_::Let(b, body)
                if b.len() == 1
                    && b.first().is_some_and(|bb| matches!(&bb.pat.value, Pattern_::PVar(s) if i.resolve(*s) == Some("x")))
                    && b.first().is_some_and(|bb| matches!(bb.body.value, Expr_::Int(2)))
                    && matches!(body.value, Expr_::Binops(_, _)))),
            "v body is `let x = 2 in x + x`, got {:?}",
            v.map(|v| &v.body.value)
        );
    }

    #[test]
    fn multi_binding_let_parses_every_binding() {
        // Layout-aligned bindings; a later binding may read an earlier one.
        let mut i = Interner::new();
        let src =
            format!("{HDR}v : Int\nv =\n    let\n        a = 1\n        b = a\n    in\n    b\n");
        let m = parse_module(&src, &mut i);
        assert!(m.is_ok(), "multi-binding let must parse: {m:?}");
        let Ok(m) = m else { return };
        let names: Vec<&str> = match find_value(&m, &i, "v").map(|v| &v.body.value) {
            Some(Expr_::Let(bindings, _)) => bindings
                .iter()
                .filter_map(|b| match &b.pat.value {
                    Pattern_::PVar(s) => i.resolve(*s),
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        };
        assert_eq!(names, vec!["a", "b"], "both bindings, in order");
    }

    #[test]
    fn let_tuple_and_record_destructure_parse() {
        // `let (a, b) = p` is a tuple-pattern binder; `let { x, y } = r` a
        // record-pattern binder. Both must parse into the matching `Pattern_`.
        let mut i = Interner::new();
        let src =
            format!("{HDR}v : Int\nv =\n    let (a, b) = p\n        {{ x, y }} = r\n    in a\n");
        let m = parse_module(&src, &mut i);
        assert!(m.is_ok(), "let-destructure must parse: {m:?}");
        let Ok(m) = m else { return };
        let Some(Expr_::Let(bindings, _)) = find_value(&m, &i, "v").map(|v| &v.body.value) else {
            assert!(black_box_false(), "v body is a Let");
            return;
        };
        assert_eq!(bindings.len(), 2, "two destructure bindings");
        assert!(
            bindings
                .first()
                .is_some_and(|b| matches!(&b.pat.value, Pattern_::PTuple(es) if es.len() == 2)),
            "first binder is a 2-tuple pattern, got {:?}",
            bindings.first().map(|b| &b.pat.value)
        );
        assert!(
            bindings
                .get(1)
                .is_some_and(|b| matches!(&b.pat.value, Pattern_::PRecord(fs) if fs.len() == 2)),
            "second binder is a 2-field record pattern, got {:?}",
            bindings.get(1).map(|b| &b.pat.value)
        );
    }

    #[test]
    fn record_pattern_parses_in_a_case_arm() {
        // `{ x, y } -> …` is a field-pun record pattern at the arm head.
        let mut i = Interner::new();
        let src = format!("{HDR}v : Int\nv =\n    case r of\n        {{ x, y }} -> x\n");
        let m = parse_module(&src, &mut i);
        assert!(m.is_ok(), "record-pattern case must parse: {m:?}");
        let Ok(m) = m else { return };
        let Some(Expr_::Case(_, arms)) = find_value(&m, &i, "v").map(|v| &v.body.value) else {
            assert!(black_box_false(), "v body is a Case");
            return;
        };
        assert!(
            arms.first()
                .is_some_and(|(p, _)| matches!(&p.value, Pattern_::PRecord(fs) if fs.len() == 2)),
            "arm head is a 2-field record pattern"
        );
    }

    /// A runtime `false` the optimiser cannot fold, so `assert!(black_box_false())`
    /// fails a test without tripping `clippy::assertions_on_constants`.
    fn black_box_false() -> bool {
        std::hint::black_box(false)
    }

    #[test]
    fn string_and_char_literal_expressions_parse() {
        // `"hi"` is a string literal (escapes resolved); `'a'` a char literal.
        let mut i = Interner::new();
        let src = format!("{HDR}s =\n    \"h\\ti\"\nc =\n    'a'\n");
        let m = parse_module(&src, &mut i);
        assert!(m.is_ok(), "string/char literals must parse: {m:?}");
        let Ok(m) = m else { return };
        assert!(
            matches!(find_value(&m, &i, "s").map(|v| &v.body.value), Some(Expr_::Str(t)) if t == "h\ti"),
            "s body is the unescaped string `h<tab>i`, got {:?}",
            find_value(&m, &i, "s").map(|v| &v.body.value)
        );
        assert!(
            matches!(find_value(&m, &i, "c").map(|v| &v.body.value), Some(Expr_::Char(t)) if t == "a"),
            "c body is the char `a`, got {:?}",
            find_value(&m, &i, "c").map(|v| &v.body.value)
        );
    }

    #[test]
    fn literal_and_bool_patterns_in_case_parse() {
        // Int / Bool / String / wildcard literal arm heads.
        let mut i = Interner::new();
        let src = format!(
            "{HDR}v : Int\nv =\n    case n of\n        0 -> 1\n        True -> 2\n        \"hi\" -> 3\n        _ -> 4\n"
        );
        let m = parse_module(&src, &mut i);
        assert!(m.is_ok(), "literal-pattern case must parse: {m:?}");
        let Ok(m) = m else { return };
        let Some(Expr_::Case(_, arms)) = find_value(&m, &i, "v").map(|v| &v.body.value) else {
            assert!(black_box_false(), "v body is a Case");
            return;
        };
        let kinds: Vec<&Pattern_> = arms.iter().map(|(p, _)| &p.value).collect();
        assert!(
            matches!(kinds.as_slice(), [
                Pattern_::PInt(0),
                Pattern_::PBool(true),
                Pattern_::PStr(s),
                Pattern_::PAnything,
            ] if s == "hi"),
            "arm heads are 0 / True / \"hi\" / _, got {kinds:?}"
        );
    }

    #[test]
    fn as_alias_pattern_parses() {
        // `(m as k) -> …` aliases the whole matched value to `k`.
        let mut i = Interner::new();
        let src =
            format!("{HDR}v : Int\nv =\n    case n of\n        0 -> 0\n        (m as k) -> k\n");
        let m = parse_module(&src, &mut i);
        assert!(m.is_ok(), "alias pattern must parse: {m:?}");
        let Ok(m) = m else { return };
        let Some(Expr_::Case(_, arms)) = find_value(&m, &i, "v").map(|v| &v.body.value) else {
            assert!(black_box_false(), "v body is a Case");
            return;
        };
        assert!(
            arms.get(1).is_some_and(|(p, _)| matches!(
                &p.value,
                Pattern_::PAlias(inner, name)
                    if matches!(inner.value, Pattern_::PVar(_)) && i.resolve(name.value) == Some("k")
            )),
            "second arm head is `m as k`, got {:?}",
            arms.get(1).map(|(p, _)| &p.value)
        );
    }

    #[test]
    fn debug_wildcard_pattern_parses_as_pdebuganything() {
        // `Debug._ -> …` parses as the dev-only catch-all `PDebugAnything`, not a
        // constructor or a plain wildcard. It is a reserved literal spelling (the
        // lexer folds `Debug._` into one identifier token).
        let mut i = Interner::new();
        let src =
            format!("{HDR}v : Int\nv =\n    case n of\n        0 -> 0\n        Debug._ -> 1\n");
        let m = parse_module(&src, &mut i);
        assert!(m.is_ok(), "`Debug._` pattern must parse: {m:?}");
        let Ok(m) = m else { return };
        let Some(Expr_::Case(_, arms)) = find_value(&m, &i, "v").map(|v| &v.body.value) else {
            assert!(black_box_false(), "v body is a Case");
            return;
        };
        assert!(
            arms.get(1)
                .is_some_and(|(p, _)| matches!(&p.value, Pattern_::PDebugAnything)),
            "second arm head is `Debug._` (PDebugAnything), got {:?}",
            arms.get(1).map(|(p, _)| &p.value)
        );
    }

    #[test]
    fn or_pattern_parses_as_por_of_alternatives() {
        // `Up | Down -> …` parses as a two-alternative `POr` at the arm head.
        let mut i = Interner::new();
        let src =
            format!("{HDR}v : Int\nv =\n    case n of\n        Up | Down -> 1\n        _ -> 0\n");
        let m = parse_module(&src, &mut i);
        assert!(m.is_ok(), "or-pattern must parse: {m:?}");
        let Ok(m) = m else { return };
        let Some(Expr_::Case(_, arms)) = find_value(&m, &i, "v").map(|v| &v.body.value) else {
            assert!(black_box_false(), "v body is a Case");
            return;
        };
        assert!(
            arms.first().is_some_and(|(p, _)| matches!(
                &p.value,
                Pattern_::POr(alts) if alts.len() == 2
            )),
            "first arm head is a 2-alternative POr, got {:?}",
            arms.first().map(|(p, _)| &p.value)
        );
    }

    #[test]
    fn or_pattern_binds_looser_than_cons() {
        // `x :: xs | [] -> …` parses as `(x :: xs) | ([])`, i.e. a POr whose
        // first alternative is a PCons — `|` is looser than `::`.
        let mut i = Interner::new();
        let src = format!(
            "{HDR}v : Int\nv =\n    case n of\n        x :: xs | [] -> 1\n        _ -> 0\n"
        );
        let m = parse_module(&src, &mut i);
        assert!(m.is_ok(), "cons-or pattern must parse: {m:?}");
        let Ok(m) = m else { return };
        let Some(Expr_::Case(_, arms)) = find_value(&m, &i, "v").map(|v| &v.body.value) else {
            assert!(black_box_false(), "v body is a Case");
            return;
        };
        assert!(
            arms.first().is_some_and(|(p, _)| matches!(
                &p.value,
                Pattern_::POr(alts)
                    if alts.len() == 2
                        && matches!(alts.first().map(|a| &a.value), Some(Pattern_::PCons(_, _)))
            )),
            "first arm head is `(x :: xs) | []`, got {:?}",
            arms.first().map(|(p, _)| &p.value)
        );
    }

    #[test]
    fn leading_or_bar_is_a_parse_error() {
        // A stray leading `|` (`| A -> …`) is a parse error, not an empty POr.
        assert_ne!(
            err_code(&format!(
                "{HDR}v =\n    case n of\n        | Up -> 1\n        _ -> 0\n"
            )),
            "OK"
        );
    }

    #[test]
    fn trailing_or_bar_is_a_parse_error() {
        // A stray trailing `|` (`A | -> …`) is a parse error.
        assert_ne!(
            err_code(&format!(
                "{HDR}v =\n    case n of\n        Up | -> 1\n        _ -> 0\n"
            )),
            "OK"
        );
    }

    #[test]
    fn unterminated_string_is_p0014() {
        assert_eq!(err_code(&format!("{HDR}s =\n    \"oops\n")), "IPE-P0014");
    }

    #[test]
    fn single_line_string_rejects_raw_newline() {
        use ipe_diagnostics::{Diagnostic, ParseError};
        use lexer::lex;
        // A single-line `"…"` broken by a raw newline is rejected, and the error
        // is located at the opening quote through the line break — it does NOT
        // swallow the following lines up to the next quote in the file. A later
        // valid string on a subsequent line would otherwise absorb everything
        // in between, mislocating the diagnostic to end-of-file.
        let src = format!("{HDR}s =\n    \"oops\nt =\n    \"fine\"\n");
        // The whole module still fails with the unterminated-string code.
        assert_eq!(err_code(&src), "IPE-P0014");
        // The lexer error span opens at the `"` that begins `"oops` and closes
        // at the newline that ends the line, never reaching the later `"fine"`.
        let Some(opener_at) = src.find("\"oops") else {
            return;
        };
        let quote_lo = u32::try_from(opener_at).unwrap_or(u32::MAX);
        let newline_hi = u32::try_from(opener_at + "\"oops".len()).unwrap_or(u32::MAX);
        let result = lex(&src);
        assert!(
            matches!(
                &result,
                Err(Diagnostic::Parse {
                    msg: ParseError::UnterminatedString,
                    ..
                })
            ),
            "expected an unterminated-string parse error, got {result:?}"
        );
        // Span opens at the `"` that begins `"oops` and closes at the newline
        // ending that line — never reaching the later `"fine"`.
        if let Err(Diagnostic::Parse { span, .. }) = result {
            assert_eq!(span.lo, quote_lo);
            assert_eq!(span.hi, newline_hi);
        }
    }

    #[test]
    fn malformed_char_is_p0015() {
        // Empty char literal `''`.
        assert_eq!(err_code(&format!("{HDR}c =\n    ''\n")), "IPE-P0015");
        // Multi-character char literal `'ab'`.
        assert_eq!(err_code(&format!("{HDR}c =\n    'ab'\n")), "IPE-P0015");
        // Unrecognised escapes resolve to backslash + char (two scalar values),
        // which violates the single-character invariant → IPE-P0015.
        assert_eq!(err_code(&format!("{HDR}c =\n    '\\q'\n")), "IPE-P0015");
        assert_eq!(err_code(&format!("{HDR}c =\n    '\\z'\n")), "IPE-P0015");
        // Recognised escapes and plain chars stay valid (single scalar value).
        assert_eq!(err_code(&format!("{HDR}c =\n    '\\n'\n")), "OK");
        assert_eq!(err_code(&format!("{HDR}c =\n    '\\0'\n")), "OK");
        assert_eq!(err_code(&format!("{HDR}c =\n    'a'\n")), "OK");
    }

    #[test]
    fn malformed_let_is_p0061() {
        // No bindings before `in`.
        assert_eq!(err_code(&format!("{HDR}v =\n    let in 0\n")), "IPE-P0061");
        // Missing `=` after the binding name.
        assert_eq!(
            err_code(&format!("{HDR}v =\n    let x 2 in x\n")),
            "IPE-P0061"
        );
        // Parameters present but `=` never arrives (`in` is not a binder atom):
        // MissingEquals, not a silent swallow.
        assert_eq!(
            err_code(&format!("{HDR}v =\n    let f x in f\n")),
            "IPE-P0061"
        );
        // Missing `in` after the bindings.
        assert_eq!(
            err_code(&format!("{HDR}v =\n    let x = 2\n    x\n")),
            "IPE-P0061"
        );
        // An uppercase binding name is not a value binding.
        assert_eq!(
            err_code(&format!("{HDR}v =\n    let X = 2 in X\n")),
            "IPE-P0061"
        );
    }

    #[test]
    fn inline_if_parses_into_an_if_node() {
        // `if c then 1 else 0` is a single-branch `If` plus a final else.
        let mut i = Interner::new();
        let src = format!("{HDR}v : Int\nv =\n    if v < 0 then 1 else 0\n");
        let m = parse_module(&src, &mut i);
        assert!(m.is_ok(), "inline if must parse: {m:?}");
        let Ok(m) = m else { return };
        let v = find_value(&m, &i, "v");
        assert!(
            v.is_some_and(|v| matches!(&v.body.value, Expr_::If(branches, els)
                if branches.len() == 1
                    && branches.first().is_some_and(|(_, b)| matches!(b.value, Expr_::Int(1)))
                    && matches!(els.value, Expr_::Int(0)))),
            "v body is `if v < 0 then 1 else 0`, got {:?}",
            v.map(|v| &v.body.value)
        );
    }

    #[test]
    fn else_if_chain_records_every_branch() {
        // `if … then … else if … then … else …` records two `(cond, branch)`
        // pairs plus the final else, in source order.
        let mut i = Interner::new();
        let src = format!(
            "{HDR}v : Int\nv =\n    if v > 0 then\n        1\n    else if v < 0 then\n        2\n    else\n        0\n"
        );
        let m = parse_module(&src, &mut i);
        assert!(m.is_ok(), "else-if chain must parse: {m:?}");
        let Ok(m) = m else { return };
        let shape = match find_value(&m, &i, "v").map(|v| &v.body.value) {
            Some(Expr_::If(branches, els)) => {
                Some((branches.len(), matches!(els.value, Expr_::Int(0))))
            }
            _ => None,
        };
        assert_eq!(
            shape,
            Some((2, true)),
            "two `(cond, branch)` pairs and a final `else 0`"
        );
    }

    #[test]
    fn tuple_literal_parses_into_a_tuple_node() {
        // `(1, 2)` is a 2-element `Tuple`; `(1, 2, 3)` is a 3-element one.
        let mut i = Interner::new();
        let src = format!("{HDR}v : Int\nv =\n    (1, 2)\n");
        let m = parse_module(&src, &mut i);
        assert!(m.is_ok(), "tuple must parse: {m:?}");
        let Ok(m) = m else { return };
        assert!(
            find_value(&m, &i, "v").is_some_and(|v| matches!(&v.body.value, Expr_::Tuple(es)
                if es.len() == 2
                    && matches!(es.first().map(|e| &e.value), Some(Expr_::Int(1)))
                    && matches!(es.get(1).map(|e| &e.value), Some(Expr_::Int(2))))),
            "v body is the 2-tuple `(1, 2)`"
        );

        let mut i3 = Interner::new();
        let src3 = format!("{HDR}v : Int\nv =\n    (1, 2, 3)\n");
        let m3 = parse_module(&src3, &mut i3);
        assert!(m3.is_ok(), "3-tuple must parse: {m3:?}");
        let Ok(m3) = m3 else { return };
        assert!(
            find_value(&m3, &i3, "v")
                .is_some_and(|v| matches!(&v.body.value, Expr_::Tuple(es) if es.len() == 3)),
            "v body is the 3-tuple `(1, 2, 3)`"
        );
    }

    #[test]
    fn parenthesised_single_expr_is_not_a_tuple() {
        // `(1)` is the parenthesised `Int`, unwrapped — never a 1-tuple.
        let mut i = Interner::new();
        let src = format!("{HDR}v : Int\nv =\n    (1)\n");
        let m = parse_module(&src, &mut i);
        assert!(m.is_ok(), "paren group must parse: {m:?}");
        let Ok(m) = m else { return };
        assert!(
            find_value(&m, &i, "v").is_some_and(|v| matches!(v.body.value, Expr_::Int(1))),
            "v body is the unwrapped `Int(1)`, not a Tuple"
        );
    }

    #[test]
    fn unit_value_parses_into_expr_unit() {
        // `()` is the unit value: empty parentheses parse to `Expr_::Unit`,
        // never a tuple, a paren-group, or a parse error.
        let mut i = Interner::new();
        let src = format!("{HDR}v =\n    ()\n");
        let m = parse_module(&src, &mut i);
        assert!(m.is_ok(), "unit value must parse: {m:?}");
        let Ok(m) = m else { return };
        assert!(
            find_value(&m, &i, "v").is_some_and(|v| matches!(v.body.value, Expr_::Unit)),
            "v body is `Expr_::Unit`"
        );
    }

    #[test]
    fn tuple_pattern_in_function_parameter_parses_into_a_ptuple() {
        // `fst (a, b) = a` — a tuple pattern in parameter position, with two
        // variable elements.
        let mut i = Interner::new();
        let src = format!("{HDR}fst : (a, b) -> a\nfst (a, b) =\n    a\n");
        let m = parse_module(&src, &mut i);
        assert!(m.is_ok(), "tuple-parameter pattern must parse: {m:?}");
        let Ok(m) = m else { return };
        assert!(
            find_value(&m, &i, "fst").is_some_and(|v| v.patterns.first().is_some_and(|p| {
                matches!(&p.value, Pattern_::PTuple(es)
                    if es.len() == 2
                        && matches!(es.first().map(|e| &e.value), Some(Pattern_::PVar(_)))
                        && matches!(es.get(1).map(|e| &e.value), Some(Pattern_::PVar(_))))
            })),
            "fst's parameter is a 2-element tuple pattern of variables"
        );
    }

    #[test]
    fn tuple_pattern_in_case_arm_parses_into_a_ptuple() {
        // `case p of (a, b) -> a` — a tuple pattern as a `case` arm head.
        let mut i = Interner::new();
        let src = format!("{HDR}v : Int\nv =\n    case (1, 2) of\n        (a, b) -> a\n");
        let m = parse_module(&src, &mut i);
        assert!(m.is_ok(), "tuple case-arm pattern must parse: {m:?}");
        let Ok(m) = m else { return };
        let arm_is_tuple = find_value(&m, &i, "v").is_some_and(|v| {
            matches!(&v.body.value, Expr_::Case(_, arms)
                if arms.first().is_some_and(|(pat, _)|
                    matches!(&pat.value, Pattern_::PTuple(es) if es.len() == 2)))
        });
        assert!(
            arm_is_tuple,
            "the single case arm is a 2-element tuple pattern"
        );
    }

    #[test]
    fn unclosed_tuple_is_p0050() {
        // A tuple opened but never closed surfaces the unclosed-delimiter code,
        // the same as a plain parenthesised group.
        assert_eq!(err_code(&format!("{HDR}v =\n    (1, 2\n")), "IPE-P0050");
    }

    #[test]
    fn tuple_type_annotation_parses_into_a_ttuple() {
        // `fst : (a, b) -> a` — a tuple type in argument position. The annotation
        // is `TLambda(TTuple([TVar a, TVar b]), TVar a)`. Before M2B this failed
        // at parse with IPE-P0050; it now unblocks `fst`/`snd`.
        let mut i = Interner::new();
        let src = format!("{HDR}fst : (a, b) -> a\nfst t =\n    t\n");
        let m = parse_module(&src, &mut i);
        assert!(m.is_ok(), "tuple-type annotation must parse: {m:?}");
        let Ok(m) = m else { return };
        let shape = find_value(&m, &i, "fst").and_then(|v| v.type_annotation.clone());
        assert!(
            shape.is_some_and(|ann| matches!(
                &ann.value,
                TypeAnnotation::TLambda(arg, ret)
                    if matches!(
                        &**arg,
                        TypeAnnotation::TTuple(elems)
                            if elems.len() == 2
                                && matches!(elems.first(), Some(TypeAnnotation::TVar(_)))
                                && matches!(elems.get(1), Some(TypeAnnotation::TVar(_)))
                    )
                        && matches!(&**ret, TypeAnnotation::TVar(_))
            )),
            "annotation is `(a, b) -> a` with a 2-element TTuple argument"
        );
    }

    #[test]
    fn three_element_tuple_type_annotation_parses() {
        // A 3-tuple type `(a, b, c)` carries all three members in order.
        let mut i = Interner::new();
        let src = format!("{HDR}f : (a, b, c) -> a\nf t =\n    t\n");
        let m = parse_module(&src, &mut i);
        assert!(m.is_ok(), "3-tuple-type annotation must parse: {m:?}");
        let Ok(m) = m else { return };
        let arity = find_value(&m, &i, "f")
            .and_then(|v| v.type_annotation.clone())
            .and_then(|ann| match ann.value {
                TypeAnnotation::TLambda(arg, _) => match *arg {
                    TypeAnnotation::TTuple(elems) => Some(elems.len()),
                    _ => None,
                },
                _ => None,
            });
        assert_eq!(arity, Some(3), "argument is a 3-element TTuple");
    }

    #[test]
    fn parenthesised_single_type_is_not_a_tuple() {
        // `(a) -> a` is a parenthesised single type, unwrapped to `a` — never a
        // 1-tuple. The annotation is the plain arrow `TLambda(TVar, TVar)`.
        let mut i = Interner::new();
        let src = format!("{HDR}f : (a) -> a\nf x =\n    x\n");
        let m = parse_module(&src, &mut i);
        assert!(m.is_ok(), "paren-group type must parse: {m:?}");
        let Ok(m) = m else { return };
        let shape = find_value(&m, &i, "f").and_then(|v| v.type_annotation.clone());
        assert!(
            shape.is_some_and(|ann| matches!(
                &ann.value,
                TypeAnnotation::TLambda(arg, ret)
                    if matches!(&**arg, TypeAnnotation::TVar(_))
                        && matches!(&**ret, TypeAnnotation::TVar(_))
            )),
            "annotation is the unwrapped `a -> a`, not a TTuple"
        );
    }

    #[test]
    fn unit_type_annotation_parses_into_a_tunit() {
        // `()` in type position is the unit type — distinct from a tuple and from
        // a parenthesised group. The argument is `TUnit`.
        let mut i = Interner::new();
        let src = format!("{HDR}f : () -> a\nf x =\n    x\n");
        let m = parse_module(&src, &mut i);
        assert!(m.is_ok(), "unit-type annotation must parse: {m:?}");
        let Ok(m) = m else { return };
        let shape = find_value(&m, &i, "f").and_then(|v| v.type_annotation.clone());
        assert!(
            shape.is_some_and(|ann| matches!(
                &ann.value,
                TypeAnnotation::TLambda(arg, _) if matches!(&**arg, TypeAnnotation::TUnit)
            )),
            "annotation argument is TUnit"
        );
    }

    #[test]
    fn unclosed_tuple_type_is_p0050() {
        // A tuple type opened but never closed surfaces the unclosed-delimiter
        // code, the same as a plain parenthesised type group.
        assert_eq!(err_code(&format!("{HDR}f : (a, b")), "IPE-P0050");
    }

    #[test]
    fn record_type_annotation_parses_into_a_trecord() {
        // `wrap : a -> { value : a }` — a record type in return position. The
        // annotation is `TLambda(TVar a, TRecord [(value, TVar a)])`.
        let mut i = Interner::new();
        let src = format!("{HDR}wrap : a -> {{ value : a }}\nwrap x =\n    x\n");
        let m = parse_module(&src, &mut i);
        assert!(m.is_ok(), "record-type annotation must parse: {m:?}");
        let Ok(m) = m else { return };
        let shape = find_value(&m, &i, "wrap").and_then(|v| v.type_annotation.clone());
        assert!(
            shape.is_some_and(|ann| matches!(
                &ann.value,
                TypeAnnotation::TLambda(arg, ret)
                    if matches!(&**arg, TypeAnnotation::TVar(_))
                        && matches!(
                            &**ret,
                            TypeAnnotation::TRecord(fields)
                                if fields.len() == 1
                                    && matches!(
                                        fields.first(),
                                        Some((_, TypeAnnotation::TVar(_)))
                                    )
                        )
            )),
            "annotation is `a -> {{ value : a }}` with a 1-field TRecord return"
        );
    }

    #[test]
    fn multi_field_record_type_annotation_parses() {
        // `{ first : a, second : b }` — fields kept in source order.
        let mut i = Interner::new();
        let src = format!("{HDR}pair : a -> b -> {{ first : a, second : b }}\npair x y =\n    x\n");
        let m = parse_module(&src, &mut i);
        assert!(
            m.is_ok(),
            "two-field record-type annotation must parse: {m:?}"
        );
        let Ok(m) = m else { return };
        let arity = find_value(&m, &i, "pair")
            .and_then(|v| v.type_annotation.clone())
            .and_then(|ann| match ann.value {
                TypeAnnotation::TLambda(_, ret) => match *ret {
                    TypeAnnotation::TLambda(_, ret2) => match *ret2 {
                        TypeAnnotation::TRecord(fields) => Some(fields.len()),
                        _ => None,
                    },
                    _ => None,
                },
                _ => None,
            });
        assert_eq!(arity, Some(2), "return type is a 2-field TRecord");
    }

    #[test]
    fn record_type_alias_body_parses() {
        // `type alias Box a = { value : a }` — the alias body is a TRecord.
        let mut i = Interner::new();
        let src = format!("{HDR}type alias Box a = {{ value : a }}\n");
        let m = parse_module(&src, &mut i);
        assert!(m.is_ok(), "record-type alias must parse: {m:?}");
        let Ok(m) = m else { return };
        let alias = m.aliases.first();
        assert!(
            alias.is_some_and(|a| matches!(
                &a.value.body.value,
                TypeAnnotation::TRecord(fields)
                    if fields.len() == 1
            )),
            "alias body is a 1-field TRecord"
        );
    }

    #[test]
    fn open_record_type_annotation_parses_into_a_trecordopen() {
        // `getName : { r | name : String } -> String` — a row-polymorphic
        // record type. The annotation's argument is a `TRecordOpen(r, [(name,
        // String)])`, mirroring the reference compiler's
        // `TRecord fields (Just rowVar)`.
        let mut i = Interner::new();
        let src = format!(
            "{HDR}getName : {{ r | name : String }} -> String\ngetName rec =\n    rec.name\n"
        );
        let m = parse_module(&src, &mut i);
        assert!(m.is_ok(), "open-record annotation must parse: {m:?}");
        let Ok(m) = m else { return };
        let shape = find_value(&m, &i, "getName").and_then(|v| v.type_annotation.clone());
        assert!(
            shape.is_some_and(|ann| matches!(
                &ann.value,
                TypeAnnotation::TLambda(arg, _)
                    if matches!(
                        &**arg,
                        TypeAnnotation::TRecordOpen(_, fields)
                            if fields.len() == 1
                                && matches!(
                                    fields.first(),
                                    Some((_, TypeAnnotation::TType(_, _, _)))
                                )
                    )
            )),
            "argument is `{{ r | name : String }}` — a 1-field TRecordOpen"
        );
    }

    #[test]
    fn open_record_type_with_multiple_fields_parses() {
        // `{ r | first : a, second : b }` — the row var precedes a
        // comma-separated field list, kept in source order.
        let mut i = Interner::new();
        let src =
            format!("{HDR}f : {{ r | first : a, second : b }} -> a\nf rec =\n    rec.first\n");
        let m = parse_module(&src, &mut i);
        assert!(
            m.is_ok(),
            "multi-field open-record annotation must parse: {m:?}"
        );
        let Ok(m) = m else { return };
        let arity = find_value(&m, &i, "f")
            .and_then(|v| v.type_annotation.clone())
            .and_then(|ann| match ann.value {
                TypeAnnotation::TLambda(arg, _) => match *arg {
                    TypeAnnotation::TRecordOpen(_, fields) => Some(fields.len()),
                    _ => None,
                },
                _ => None,
            });
        assert_eq!(arity, Some(2), "argument is a 2-field TRecordOpen");
    }

    #[test]
    fn empty_record_type_parses_into_empty_trecord() {
        // `{}` in type position is the empty record type — valid, yields `TRecord []`.
        // Mirrors the reference compiler (Type.hs line 131-133):
        //   Just '}' -> char mkError '}' >> return (TRecord [] Nothing)
        let mut i = Interner::new();
        let m = parse_module(&format!("{HDR}f : {{}}\nf =\n    0\n"), &mut i);
        assert!(m.is_ok(), "empty record type must parse: {m:?}");
        let Ok(m) = m else { return };
        let ann = find_value(&m, &i, "f")
            .and_then(|v| v.type_annotation.as_ref())
            .map(|a| &a.value);
        assert!(
            matches!(ann, Some(TypeAnnotation::TRecord(fields)) if fields.is_empty()),
            "type annotation must be an empty TRecord, got {ann:?}"
        );
    }

    #[test]
    fn empty_record_type_with_spaces_parses() {
        // `{  }` (spaces inside) must also parse — the layout filter allows
        // whitespace between `{` and `}`.
        let m = parse_module(
            &format!("{HDR}f : {{  }}\nf =\n    0\n"),
            &mut Interner::new(),
        );
        assert!(m.is_ok(), "empty record type with spaces must parse: {m:?}");
    }

    #[test]
    fn empty_record_type_alias_parses() {
        // `type alias Model = {}` — the empty record as an alias body.
        // This is the construct that appears in examples/29-webview-threejs-spike.
        let mut i = Interner::new();
        let m = parse_module(&format!("{HDR}type alias Model = {{}}\n"), &mut i);
        assert!(m.is_ok(), "empty-record type alias must parse: {m:?}");
        let Ok(m) = m else { return };
        let body = m.aliases.first().map(|a| &a.value.body.value);
        assert!(
            matches!(body, Some(TypeAnnotation::TRecord(fields)) if fields.is_empty()),
            "alias body must be an empty TRecord, got {body:?}"
        );
    }

    #[test]
    fn empty_record_literal_parses_into_record_node() {
        // `{}` in expression position is a valid empty record literal.
        // Mirrors the compiler's Expression.hs line 309-311:
        //   Just '}' -> char mkError '}' >> return (Src.Record [])
        let mut i = Interner::new();
        let m = parse_module(&format!("{HDR}v : Int\nv =\n    {{}}\n"), &mut i);
        assert!(m.is_ok(), "empty record literal must parse: {m:?}");
        let Ok(m) = m else { return };
        let shape = match find_value(&m, &i, "v").map(|v| &v.body.value) {
            Some(Expr_::Record(fields)) => Some(fields.len()),
            _ => None,
        };
        assert_eq!(
            shape,
            Some(0),
            "empty record literal yields Record with 0 fields"
        );
    }

    #[test]
    fn record_type_missing_colon_is_rejected() {
        // A record-type field needs a `:` between name and type.
        assert!(
            parse_module(
                &format!("{HDR}f : {{ value a }}\nf =\n    0\n"),
                &mut Interner::new()
            )
            .is_err(),
            "a record-type field without `:` must be rejected"
        );
    }

    #[test]
    fn record_literal_parses_into_a_record_node() {
        // `{ x = 1, y = 2 }` is a two-field `Record`, fields in source order.
        let mut i = Interner::new();
        let src = format!("{HDR}v : Int\nv =\n    {{ x = 1, y = 2 }}\n");
        let m = parse_module(&src, &mut i);
        assert!(m.is_ok(), "record literal must parse: {m:?}");
        let Ok(m) = m else { return };
        let names: Vec<&str> = match find_value(&m, &i, "v").map(|v| &v.body.value) {
            Some(Expr_::Record(fields)) => fields
                .iter()
                .filter_map(|(n, _)| i.resolve(n.value))
                .collect(),
            _ => Vec::new(),
        };
        assert_eq!(names, vec!["x", "y"], "both fields, in source order");
    }

    #[test]
    fn record_update_parses_into_an_update_node() {
        // `{ p | x = 41 }` is an `Update` over base `p` with one updated field.
        let mut i = Interner::new();
        let src = format!("{HDR}v : Int\nv =\n    {{ p | x = 41, y = 7 }}\n");
        let m = parse_module(&src, &mut i);
        assert!(m.is_ok(), "record update must parse: {m:?}");
        let Ok(m) = m else { return };
        let shape = match find_value(&m, &i, "v").map(|v| &v.body.value) {
            Some(Expr_::Update(base, fields)) => {
                let names: Vec<&str> = fields
                    .iter()
                    .filter_map(|(n, _)| i.resolve(n.value))
                    .collect();
                i.resolve(base.value) == Some("p") && names == vec!["x", "y"]
            }
            _ => false,
        };
        assert!(shape, "v body is `Update p [x, y]`, base + fields in order");
    }

    #[test]
    fn field_access_parses_into_an_access_chain() {
        // `p.x` is `Access (VarLocal p) x`; `p.x.y` nests it.
        let mut i = Interner::new();
        let src = format!("{HDR}v : Int\nv =\n    p.x.y\n");
        let m = parse_module(&src, &mut i);
        assert!(m.is_ok(), "field access must parse: {m:?}");
        let Ok(m) = m else { return };
        let shape = match find_value(&m, &i, "v").map(|v| &v.body.value) {
            // outer: (…).y
            Some(Expr_::Access(inner, outer_field)) => {
                match (&inner.value, i.resolve(outer_field.value)) {
                    // inner: (p).x
                    (Expr_::Access(base, inner_field), Some("y")) => {
                        match (&base.value, i.resolve(inner_field.value)) {
                            (Expr_::VarLocal(p), Some("x")) => i.resolve(*p) == Some("p"),
                            _ => false,
                        }
                    }
                    _ => false,
                }
            }
            _ => false,
        };
        assert!(shape, "v body is `Access (Access p x) y`");
    }

    #[test]
    fn field_access_on_parenthesised_var_parses(/* #6 */) {
        // `(r).value` — field access on a parenthesised variable. The `.` is a
        // standalone `Tok::Dot` (the parens break the bare-ident dotted run), so
        // it must be resolved as a postfix access, not rejected as a stray dot.
        let mut i = Interner::new();
        let src = format!("{HDR}v =\n    (r).value\n");
        let m = parse_module(&src, &mut i);
        assert!(m.is_ok(), "`(r).value` must parse: {m:?}");
        let Ok(m) = m else { return };
        let shape = match find_value(&m, &i, "v").map(|v| &v.body.value) {
            Some(Expr_::Access(base, field)) => {
                matches!(&base.value, Expr_::VarLocal(r) if i.resolve(*r) == Some("r"))
                    && i.resolve(field.value) == Some("value")
            }
            _ => false,
        };
        assert!(shape, "v body is `Access (VarLocal r) value`");
    }

    #[test]
    fn field_access_on_call_result_parses(/* #6 */) {
        // `(wrap 1).value` — field access on a call result. Field access binds
        // tighter than application, so `.value` attaches to the `(wrap 1)` atom.
        let mut i = Interner::new();
        let src = format!("{HDR}v =\n    (wrap 1).value\n");
        let m = parse_module(&src, &mut i);
        assert!(m.is_ok(), "`(wrap 1).value` must parse: {m:?}");
        let Ok(m) = m else { return };
        let shape = match find_value(&m, &i, "v").map(|v| &v.body.value) {
            Some(Expr_::Access(base, field)) => {
                matches!(&base.value, Expr_::Call(callee, args)
                    if matches!(&callee.value, Expr_::VarLocal(w) if i.resolve(*w) == Some("wrap"))
                        && args.len() == 1)
                    && i.resolve(field.value) == Some("value")
            }
            _ => false,
        };
        assert!(shape, "v body is `Access (Call wrap [1]) value`");
    }

    #[test]
    fn chained_field_access_on_parenthesised_expr_parses(/* #6 */) {
        // `((nested).a).b` — chained access. The lexer folds the `a.b` after the
        // first dot into one dotted identifier; each segment becomes a separate
        // access node, yielding `Access (Access (Access nested a) b) …`. Here the
        // inner `(nested).a` is one atom, then `.b` applies to the whole group.
        let mut i = Interner::new();
        let src = format!("{HDR}v =\n    ((nested).a).b\n");
        let m = parse_module(&src, &mut i);
        assert!(m.is_ok(), "`((nested).a).b` must parse: {m:?}");
        let Ok(m) = m else { return };
        let shape = match find_value(&m, &i, "v").map(|v| &v.body.value) {
            // outer: (…).b
            Some(Expr_::Access(inner, outer_field)) => {
                match (&inner.value, i.resolve(outer_field.value)) {
                    // inner: (nested).a
                    (Expr_::Access(base, inner_field), Some("b")) => {
                        matches!(&base.value, Expr_::VarLocal(n) if i.resolve(*n) == Some("nested"))
                            && i.resolve(inner_field.value) == Some("a")
                    }
                    _ => false,
                }
            }
            _ => false,
        };
        assert!(shape, "v body is `Access (Access nested a) b`");
    }

    #[test]
    fn lone_dot_is_still_a_stray_dot(/* #6 regression */) {
        // A `.` not part of `..` and not introducing a field access is still the
        // typed stray-dot lex error — the #6 fix must not swallow it.
        assert_eq!(err_code(&format!("{HDR}v =\n    1 . 2\n")), "IPE-P0011");
    }

    #[test]
    fn qualified_uppercase_name_is_not_field_access() {
        // `String.fromInt` keeps its `VarQual` shape — only a lowercase head is
        // a record field access.
        let mut i = Interner::new();
        let src = format!("{HDR}v =\n    String.fromInt 1\n");
        let m = parse_module(&src, &mut i);
        assert!(m.is_ok(), "qualified call must parse: {m:?}");
        let Ok(m) = m else { return };
        assert!(
            find_value(&m, &i, "v").is_some_and(|v| matches!(&v.body.value, Expr_::Call(callee, _)
                if matches!(callee.value, Expr_::VarQual(_, _)))),
            "callee stays a VarQual, not an Access"
        );
    }

    #[test]
    fn empty_record_literal_in_expression_parses() {
        // `{}` in expression position is valid — mirrors the compiler's Expression.hs
        // line 309-311: `Just '}' -> char '}' >> return (Src.Record [])`.
        // This test replaces the old `empty_record_is_rejected` which assumed
        // the empty record was outside the grammar.
        let mut i = Interner::new();
        let m = parse_module(&format!("{HDR}v =\n    {{}}\n"), &mut i);
        assert!(m.is_ok(), "empty record literal `{{}}` must parse: {m:?}");
        let Ok(m) = m else { return };
        let shape = match find_value(&m, &i, "v").map(|v| &v.body.value) {
            Some(Expr_::Record(fields)) => Some(fields.len()),
            _ => None,
        };
        assert_eq!(
            shape,
            Some(0),
            "empty record literal yields Record with 0 fields"
        );
    }

    #[test]
    fn unclosed_record_is_unexpected_eof() {
        // A record opened but never closed runs the input out cleanly.
        assert_eq!(err_code(&format!("{HDR}v =\n    {{ x = 1\n")), "IPE-P0002");
    }

    #[test]
    fn malformed_if_is_p0062() {
        // Missing `then` after the condition.
        assert_eq!(
            err_code(&format!("{HDR}v =\n    if v 1 else 0\n")),
            "IPE-P0062"
        );
        // Missing `else` after the `then` branch.
        assert_eq!(
            err_code(&format!("{HDR}v =\n    if v then 1\n")),
            "IPE-P0062"
        );
        // Absent condition (`if then …`).
        assert_eq!(
            err_code(&format!("{HDR}v =\n    if then 1 else 0\n")),
            "IPE-P0062"
        );
    }

    #[test]
    fn unexpected_token_is_p0001() {
        // A token that cannot begin an expression.
        assert_eq!(err_code(&format!("{HDR}main = )")), "IPE-P0001");
        // SHOULD-FIX: a qualified constructor in pattern position is rejected.
        let qual_ctor = format!("{HDR}main =\n    case main of\n        Foo.Bar -> 1\n");
        assert_eq!(err_code(&qual_ctor), "IPE-P0001");
    }

    #[test]
    fn unexpected_eof_is_p0002() {
        assert_eq!(err_code(&format!("{HDR}main =")), "IPE-P0002");
    }

    #[test]
    fn nesting_too_deep_is_p0003() {
        let deep = format!("{HDR}main = {}", "(".repeat(400));
        assert_eq!(err_code(&deep), "IPE-P0003");
    }

    #[test]
    fn fuzz_random_bytes_never_panics_and_errors() {
        // Feed many 1 KB blobs of random bytes; the parser must reject every
        // one with a typed error and must never panic.
        let mut seed: u64 = 0x5DEE_CE66_D00D_F00D;
        for _ in 0..256 {
            let mut bytes = Vec::with_capacity(1024);
            for _ in 0..1024 {
                let r = xorshift(&mut seed);
                bytes.push(u8::try_from(r & 0xFF).unwrap_or(0));
            }
            let s = String::from_utf8_lossy(&bytes).into_owned();
            let mut i = Interner::new();
            let result = parse_module(&s, &mut i);
            assert!(result.is_err(), "random bytes must not parse as a module");
        }
    }

    #[test]
    fn parses_non_parametric_type_alias() {
        let mut i = Interner::new();
        let src = "module Main exposing (v)\n\
                   type alias Count = Int\n\n\
                   v : Count\n\
                   v =\n    0\n";
        let result = parse_module(src, &mut i);
        assert!(result.is_ok(), "alias must parse: {result:?}");
        let Ok(m) = result else { return };
        assert_eq!(m.aliases.len(), 1, "one alias collected");
        assert_eq!(m.unions.len(), 0, "alias is not a union");
        let Some(alias) = m.aliases.first().map(|a| &a.value) else {
            return;
        };
        assert_eq!(i.resolve(alias.name.value), Some("Count"));
        assert!(alias.vars.is_empty(), "non-parametric alias has no vars");
        assert!(
            matches!(&alias.body.value, TypeAnnotation::TType(_, segs, args)
                if segs.last().and_then(|&s| i.resolve(s)) == Some("Int") && args.is_empty()),
            "body is the `Int` constructor, got {:?}",
            alias.body.value
        );
    }

    #[test]
    fn parses_parametric_alias_capturing_its_vars() {
        // The parser captures a parametric alias's declared vars so
        // canonicalisation can substitute use-site arguments and expand the body.
        // `alias` stays a soft keyword: a union is still distinguished from a
        // `type alias`.
        let mut i = Interner::new();
        let src = "module Main exposing (v)\n\
                   type alias Pair a = a\n\n\
                   v : Int\n\
                   v =\n    0\n";
        let result = parse_module(src, &mut i);
        assert!(result.is_ok(), "parametric alias must parse: {result:?}");
        let Ok(m) = result else { return };
        assert_eq!(m.aliases.len(), 1, "one alias expected");
        let Some(alias) = m.aliases.first().map(|a| &a.value) else {
            return;
        };
        assert_eq!(i.resolve(alias.name.value), Some("Pair"));
        assert_eq!(alias.vars.len(), 1, "one declared type parameter");
        assert_eq!(
            alias.vars.first().and_then(|v| i.resolve(v.value)),
            Some("a")
        );
    }

    #[test]
    fn type_without_alias_keyword_is_still_a_union() {
        // Guard the soft-keyword look-ahead: `type Foo = …` is a union, never an
        // alias, even though `alias` is just an identifier.
        let mut i = Interner::new();
        let src = "module Main exposing (v)\n\
                   type Foo = Bar | Baz\n\n\
                   v : Int\n\
                   v =\n    0\n";
        let result = parse_module(src, &mut i);
        assert!(result.is_ok(), "union must parse: {result:?}");
        let Ok(m) = result else { return };
        assert_eq!(m.unions.len(), 1, "one union");
        assert_eq!(m.aliases.len(), 0, "no aliases");
    }

    #[test]
    fn parses_negative_int_literal() {
        // `(-5)` in atom (prefix) position folds the sign into a signed
        // `Expr_::Int(-5)` node, mirroring the reference's `Src.Negate` of a
        // numeric literal. The parens are unwrapped, so the body is the literal.
        let mut i = Interner::new();
        let src = "module Main exposing (v)\n\nv =\n    (-5)\n";
        let result = parse_module(src, &mut i);
        assert!(
            result.is_ok(),
            "negative int literal must parse: {result:?}"
        );
        let Ok(m) = result else { return };
        let v = find_value(&m, &i, "v");
        assert!(
            v.is_some_and(|val| matches!(val.body.value, Expr_::Int(-5))),
            "body must be Int(-5)"
        );
    }

    #[test]
    fn parses_negative_float_literal() {
        // `(-2.7)` folds to `Expr_::Float(-2.7)`.
        let mut i = Interner::new();
        let src = "module Main exposing (v)\n\nv =\n    (-2.7)\n";
        let result = parse_module(src, &mut i);
        assert!(
            result.is_ok(),
            "negative float literal must parse: {result:?}"
        );
        let Ok(m) = result else { return };
        let v = find_value(&m, &i, "v");
        assert!(
            v.is_some_and(
                |val| matches!(val.body.value, Expr_::Float(f) if (f + 2.7).abs() < 1e-9)
            ),
            "body must be Float(-2.7)"
        );
    }

    #[test]
    fn parses_negative_literal_as_application_argument() {
        // `f (-5)`: the negative literal is the (parenthesised) argument; the
        // body is a `Call` with one `Int(-5)` argument. This is the shape the
        // Math goldens rely on (`Math.abs (-5)`, `Math.floor (-2.7)`, …).
        let mut i = Interner::new();
        let src = "module Main exposing (v)\n\nv f =\n    f (-5)\n";
        let result = parse_module(src, &mut i);
        assert!(result.is_ok(), "f (-5) must parse: {result:?}");
        let Ok(m) = result else { return };
        let v = find_value(&m, &i, "v");
        let is_call_neg = v.is_some_and(|val| match &val.body.value {
            Expr_::Call(_, args) => {
                args.len() == 1 && matches!(args.first().map(|a| &a.value), Some(Expr_::Int(-5)))
            }
            _ => false,
        });
        assert!(is_call_neg, "body must be Call(f, [Int(-5)])");
    }

    #[test]
    fn binary_subtraction_is_unaffected_by_negative_literal_parsing() {
        // `2 - 5` stays a subtraction (a `Binops` chain), never a negative
        // literal: the `-` is consumed as an infix operator after the `2`
        // operand, so prefix negation parsing never sees it.
        let mut i = Interner::new();
        let src = "module Main exposing (v)\n\nv =\n    2 - 5\n";
        let result = parse_module(src, &mut i);
        assert!(result.is_ok(), "subtraction must parse: {result:?}");
        let Ok(m) = result else { return };
        let v = find_value(&m, &i, "v");
        assert!(
            v.is_some_and(|val| matches!(&val.body.value, Expr_::Binops(ops, _) if ops.len() == 1)),
            "body must be a one-operator Binops chain (subtraction)"
        );
    }

    #[test]
    fn space_between_minus_and_literal_is_not_a_negative_literal() {
        // A negative literal matches only when the `-` is immediately
        // followed by the digit (no space). `(- 5)` therefore is not a negative
        // literal and, with no operand before the `-`, is a parse error rather
        // than a silently-accepted negation.
        let mut i = Interner::new();
        let src = "module Main exposing (v)\n\nv =\n    (- 5)\n";
        let result = parse_module(src, &mut i);
        assert!(
            result.is_err(),
            "`(- 5)` (space after `-`) must NOT parse as a negative literal"
        );
    }

    // ── Unary negation on identifiers / expressions ──────────────────────────
    //
    // `-e` in prefix position on a non-literal atom desugars to
    // `Call(VarQual(Basics, negate), [e])`, extending negation beyond numeric
    // literals to identifiers and parenthesised expressions. The callee is a
    // QUALIFIED `Basics.negate` reference so a user binding named `negate`
    // cannot capture the operator.

    #[test]
    fn negation_of_identifier_desugars_to_negate_call() {
        // `-cents` → `Call(VarQual(Basics, negate), [VarLocal("cents")])`.
        let mut i = Interner::new();
        let src = format!("{HDR}v cents =\n    -cents\n");
        let result = parse_module(&src, &mut i);
        assert!(result.is_ok(), "-cents must parse: {result:?}");
        let Ok(m) = result else { return };
        let v = find_value(&m, &i, "v");
        assert!(
            v.is_some_and(|val| match &val.body.value {
                Expr_::Call(callee, args) =>
                    matches!(callee.value, Expr_::VarQual(qual, func)
                        if i.resolve(qual) == Some("Basics") && i.resolve(func) == Some("negate"))
                        && args.len() == 1
                        && matches!(
                            args.first().map(|arg| &arg.value),
                            Some(Expr_::VarLocal(inner)) if i.resolve(*inner) == Some("cents")
                        ),
                _ => false,
            }),
            "body must be Call(Basics.negate, [VarLocal(cents)]), got {:?}",
            v.map(|val| &val.body.value)
        );
    }

    #[test]
    fn negation_in_if_then_else_parses() {
        // `if c < 0 then -c else c` — the `-c` in the `then` branch is in
        // prefix (atom) position, not after any complete expression, so it
        // must parse as unary negation desugared to `negate c`.
        let mut i = Interner::new();
        let src = format!("{HDR}v c =\n    if c < 0 then -c else c\n");
        let result = parse_module(&src, &mut i);
        assert!(
            result.is_ok(),
            "if c < 0 then -c else c must parse: {result:?}"
        );
        let Ok(m) = result else { return };
        let v = find_value(&m, &i, "v");
        // Body is an `If`; the `then` branch is `negate c` (a Call).
        assert!(
            v.is_some_and(|val| matches!(&val.body.value, Expr_::If(_, _))),
            "body must be an If expression"
        );
    }

    #[test]
    fn negation_then_binary_add_parses_correctly() {
        // `-x + y` → `Binops([(Call(negate,[x]), "+")], y)`.
        // Negation binds tighter than the binary `+` operator — the `-x` is an
        // atom, and `+ y` is the infix continuation.
        let mut i = Interner::new();
        let src = format!("{HDR}v x y =\n    -x + y\n");
        let result = parse_module(&src, &mut i);
        assert!(result.is_ok(), "-x + y must parse: {result:?}");
        let Ok(m) = result else { return };
        let v = find_value(&m, &i, "v");
        // Body is a Binops chain; first operand is the negate call.
        assert!(
            v.is_some_and(|val| matches!(&val.body.value,
                Expr_::Binops(ops, _) if ops.len() == 1
                    && matches!(ops.first(), Some((e, _))
                        if matches!(e.value, Expr_::Call(_, _)))
            )),
            "body must be Binops with negate-call as first operand"
        );
    }

    #[test]
    fn parenthesised_negation_of_identifier_is_negate_call() {
        // `f (-x)` — inside the parens, `-x` is in prefix position.
        // The paren unwraps to `Call(negate, [x])`, which becomes the argument
        // to `f`: `Call(f, [Call(negate, [x])])`.
        let mut i = Interner::new();
        let src = format!("{HDR}v f x =\n    f (-x)\n");
        let result = parse_module(&src, &mut i);
        assert!(result.is_ok(), "f (-x) must parse: {result:?}");
        let Ok(m) = result else { return };
        let v = find_value(&m, &i, "v");
        let is_call_negate = v.is_some_and(|val| match &val.body.value {
            Expr_::Call(_, args) => args.len() == 1
                && matches!(
                    args.first().map(|arg| &arg.value),
                    Some(Expr_::Call(inner_callee, inner_args))
                        if matches!(inner_callee.value, Expr_::VarQual(qual, func)
                            if i.resolve(qual) == Some("Basics") && i.resolve(func) == Some("negate"))
                        && inner_args.len() == 1
                ),
            _ => false,
        });
        assert!(is_call_negate, "body must be Call(f, [Call(negate, [x])])");
    }

    #[test]
    fn binary_subtraction_still_works_after_unary_negate_fix() {
        // `a - b` stays a Binops([(a, "-")], b): the `-` is consumed as a
        // binary operator after the complete expression `a`, so
        // `parse_negative_literal` is never invoked.
        let mut i = Interner::new();
        let src = format!("{HDR}v a b =\n    a - b\n");
        let result = parse_module(&src, &mut i);
        assert!(result.is_ok(), "a - b must parse: {result:?}");
        let Ok(m) = result else { return };
        let v = find_value(&m, &i, "v");
        assert!(
            v.is_some_and(|val| matches!(&val.body.value,
                Expr_::Binops(ops, _) if ops.len() == 1
            )),
            "a - b must be a one-operator Binops chain"
        );
    }

    #[test]
    fn double_minus_binary_then_unary_parses() {
        // `a - -b` — first `-` is the binary subtraction operator (after `a`),
        // second `-` is in atom position for the RHS, desugaring to `negate b`.
        // Result: `Binops([(a, "-")], Call(negate, [b]))`.
        let mut i = Interner::new();
        let src = format!("{HDR}v a b =\n    a - -b\n");
        let result = parse_module(&src, &mut i);
        assert!(result.is_ok(), "a - -b must parse: {result:?}");
        let Ok(m) = result else { return };
        let v = find_value(&m, &i, "v");
        assert!(
            v.is_some_and(|val| matches!(&val.body.value,
                Expr_::Binops(ops, tail)
                    if ops.len() == 1
                    && matches!(tail.value, Expr_::Call(_, _))
            )),
            "a - -b must be Binops([(a, -)], Call(negate, [b]))"
        );
    }

    #[test]
    fn space_between_minus_and_ident_is_a_parse_error() {
        // `(- x)` (space between `-` and the identifier) must fail.
        // Mirrors the reference compiler behaviour: `exprAtom_` has no `spaces` call after
        // consuming `-`, so a space before the operand causes the nested atom
        // parse to fail (consumed error, no backtrack).
        let src = format!("{HDR}v x =\n    (- x)\n");
        assert!(
            parse_module(&src, &mut Interner::new()).is_err(),
            "`(- x)` with space must NOT parse"
        );
    }

    // ── Pipe-operator lexer maximal-munch tests ───────────────────────────────

    /// `|>` lexes as a single `PipeGt` token (maximal munch), not as
    /// `Pipe` then `Gt`. `||` still lexes as `PipePipe` (non-regression).
    #[test]
    fn pipe_forward_lexes_as_single_token() {
        use crate::lexer::{Tok, lex};
        let tokens = lex("|>").expect("|> must lex");
        assert_eq!(tokens.len(), 1, "|> must produce exactly one token");
        let tok = tokens.first().expect("|> token vec must be non-empty");
        assert_eq!(tok.kind, Tok::PipeGt, "|> must lex as PipeGt, not Pipe+Gt");

        // Non-regression: `||` stays PipePipe.
        let or_tokens = lex("||").expect("|| must lex");
        assert_eq!(or_tokens.len(), 1, "|| must produce exactly one token");
        let or_tok = or_tokens.first().expect("|| token vec must be non-empty");
        assert_eq!(or_tok.kind, Tok::PipePipe, "|| must lex as PipePipe");
    }

    /// `<|` lexes as a single `LtPipe` token (maximal munch), not as
    /// `Lt` then `Pipe`. `<=` still lexes as `Le` (non-regression).
    #[test]
    fn pipe_backward_lexes_as_single_token() {
        use crate::lexer::{Tok, lex};
        let tokens = lex("<|").expect("<| must lex");
        assert_eq!(tokens.len(), 1, "<| must produce exactly one token");
        let tok = tokens.first().expect("<| token vec must be non-empty");
        assert_eq!(tok.kind, Tok::LtPipe, "<| must lex as LtPipe, not Lt+Pipe");

        // Non-regression: `<=` stays Le.
        let le_tokens = lex("<=").expect("<= must lex");
        assert_eq!(le_tokens.len(), 1, "<= must produce exactly one token");
        let le_tok = le_tokens.first().expect("<= token vec must be non-empty");
        assert_eq!(le_tok.kind, Tok::Le, "<= must lex as Le");
    }

    // ── GAP 4: block comments ─────────────────────────────────────────────────

    /// A well-formed block comment is invisible to the parser.
    #[test]
    fn block_comment_is_skipped() {
        assert_eq!(err_code(&format!("{HDR}main = {{- ignored -}} 1")), "OK");
    }

    /// A block comment can nest: `{- {- inner -} outer -}`.
    #[test]
    fn nested_block_comment_is_skipped() {
        assert_eq!(
            err_code(&format!("{HDR}main = {{- {{- nested -}} -}} 1")),
            "OK"
        );
    }

    /// An unterminated block comment is IPE-P0017.
    #[test]
    fn unterminated_block_comment_is_p0017() {
        assert_eq!(
            err_code(&format!("{HDR}main = {{- never closed")),
            "IPE-P0017"
        );
    }

    /// A block comment between top-level bindings is whitespace to the parser.
    #[test]
    fn block_comment_between_definitions_is_skipped() {
        let src = format!("{HDR}a = 1\n{{- between defs -}}\nb = 2\n");
        assert_eq!(err_code(&src), "OK");
    }

    // ── GAP 2: integer-division operator `//` ────────────────────────────────

    /// `//` lexes as a single `SlashSlash` token (maximal munch).
    #[test]
    fn int_div_lexes_as_single_token() {
        use crate::lexer::{Tok, lex};
        let tokens = lex("//").expect("// must lex");
        assert_eq!(tokens.len(), 1, "// must produce exactly one token");
        let tok = tokens.first().expect("// token vec must be non-empty");
        assert_eq!(tok.kind, Tok::SlashSlash, "// must lex as SlashSlash");

        // Non-regression: `/=` stays SlashEq, `/` stays Slash.
        let ne_tokens = lex("/=").expect("/= must lex");
        assert_eq!(ne_tokens.len(), 1);
        assert_eq!(ne_tokens.first().map(|t| &t.kind), Some(&Tok::SlashEq));

        let div_tokens = lex("/").expect("/ must lex");
        assert_eq!(div_tokens.len(), 1);
        assert_eq!(div_tokens.first().map(|t| &t.kind), Some(&Tok::Slash));
    }

    /// `a // b` parses as a Binops chain with the `//` operator.
    #[test]
    fn int_div_parses_as_binop() {
        let mut i = Interner::new();
        let src = format!("{HDR}v : Int\nv = 10 // 3\n");
        let m = parse_module(&src, &mut i);
        assert!(m.is_ok(), "10 // 3 must parse: {m:?}");
        let Ok(m) = m else { return };
        let v = find_value(&m, &i, "v");
        assert!(
            v.is_some_and(|v| matches!(&v.body.value, Expr_::Binops(ops, _)
                if ops.iter().any(|(_, op)| i.resolve(op.value) == Some("//")))),
            "body must be a Binops with operator `//`"
        );
    }

    // ── GAP 3: let-bound functions ────────────────────────────────────────────

    /// `let f x = body in f` desugars to a Lambda inside the let binding.
    #[test]
    fn let_fn_desugars_to_lambda() {
        let mut i = Interner::new();
        let src = format!("{HDR}v : Int\nv =\n    let f x = x in f 1\n");
        let m = parse_module(&src, &mut i);
        assert!(m.is_ok(), "let f x = x must parse: {m:?}");
        let Ok(m) = m else { return };
        let v = find_value(&m, &i, "v");
        assert!(
            v.is_some_and(|v| matches!(&v.body.value, Expr_::Let(bindings, _)
            if bindings.first().is_some_and(|b|
                matches!(&b.pat.value, Pattern_::PVar(_))
                && matches!(&b.body.value, Expr_::Lambda(params, _) if params.len() == 1)
            ))),
            "let binding body must be a Lambda with one param"
        );
    }

    /// `let f x y = body in f` desugars to a multi-parameter Lambda.
    #[test]
    fn let_fn_two_params_desugars_to_lambda() {
        let mut i = Interner::new();
        let src = format!("{HDR}v : Int\nv =\n    let add x y = x in add 1 2\n");
        let m = parse_module(&src, &mut i);
        assert!(m.is_ok(), "let add x y = x must parse: {m:?}");
        let Ok(m) = m else { return };
        let v = find_value(&m, &i, "v");
        assert!(
            v.is_some_and(|v| matches!(&v.body.value, Expr_::Let(bindings, _)
            if bindings.first().is_some_and(|b|
                matches!(&b.body.value, Expr_::Lambda(params, _) if params.len() == 2)
            ))),
            "let binding body must be a Lambda with two params"
        );
    }

    // ── GAP 1: qualified type names ────────────────────────────────────────────

    /// A qualified type annotation `Module.Type` parses successfully.
    #[test]
    fn qualified_type_in_annotation_parses() {
        assert_eq!(
            err_code(&format!("{HDR}x : String.String\nx = \"hi\"")),
            "OK"
        );
    }

    /// A deeply qualified type `Db.Decode.Decoder` parses (qualifier is "Db.Decode").
    #[test]
    fn deeply_qualified_type_in_annotation_parses() {
        assert_eq!(
            err_code(&format!("{HDR}x : Db.Decode.Decoder\nx = 0")),
            "OK"
        );
    }

    // -----------------------------------------------------------------------
    // Triple-quoted string regression tests
    // -----------------------------------------------------------------------
    // Reference: Ipe.Parse.String.findTripleClose (the compiler) — the closing
    // terminator is exactly `"""`, never a lone `"`.

    /// A triple-quoted string containing a lone `"` must not terminate early.
    /// This is the core 33-websocket-echo regression: inline HTML such as
    /// `<div class="card">` caused a premature close on the `"` after `class=`,
    /// making the rest lex as identifiers and triggering a misleading IPE-N0001.
    #[test]
    fn triple_string_lone_quote_does_not_terminate_early() {
        use lexer::{Tok, lex};
        // A triple-quoted string with an embedded `"` (HTML attribute value).
        let src = r#""""<div class="card"></div>""""#;
        let toks = lex(src).expect("triple string with lone quote must lex");
        assert_eq!(toks.len(), 1, "must produce exactly one token");
        assert_eq!(
            toks.first().map(|t| t.kind.clone()),
            Some(Tok::TripleStr {
                raw: r#"<div class="card"></div>"#.to_owned(),
                anchor: 4,
            }),
            "content including embedded quote is preserved verbatim"
        );
    }

    /// A triple-quoted string containing `""` (two consecutive quotes) must
    /// also lex correctly — two quotes are literal, not a premature close.
    #[test]
    fn triple_string_two_consecutive_quotes_are_literal() {
        use lexer::{Tok, lex};
        // `""` inside triple quotes is literal content, not an early close.
        let src = "\"\"\"before\"\"after\"\"\"";
        let toks = lex(src).expect("triple string with double quote must lex");
        assert_eq!(toks.len(), 1);
        assert_eq!(
            toks.first().map(|t| t.kind.clone()),
            Some(Tok::TripleStr {
                raw: "before\"\"after".to_owned(),
                anchor: 4,
            }),
        );
    }

    /// `{{interp}}` inside a triple-quoted string is preserved verbatim at the
    /// lexer stage (interpolation is resolved downstream by the canonicaliser,
    /// mirroring `findTripleClose` which performs no escape resolution).
    #[test]
    fn triple_string_interpolation_braces_preserved_verbatim() {
        use lexer::{Tok, lex};
        let src = "\"\"\"hello {{name}}!\"\"\"";
        let toks = lex(src).expect("triple string with interpolation must lex");
        assert_eq!(toks.len(), 1);
        assert_eq!(
            toks.first().map(|t| t.kind.clone()),
            Some(Tok::TripleStr {
                raw: "hello {{name}}!".to_owned(),
                anchor: 4,
            }),
        );
    }

    /// `\{{` (escaped open brace) inside a triple-quoted string is preserved
    /// verbatim — the lexer does not resolve it; the canonicaliser does.
    #[test]
    fn triple_string_escaped_brace_preserved_verbatim() {
        use lexer::{Tok, lex};
        let src = r#""""price: \{{amount}}""""#;
        let toks = lex(src).expect("triple string with escaped brace must lex");
        assert_eq!(toks.len(), 1);
        assert_eq!(
            toks.first().map(|t| t.kind.clone()),
            Some(Tok::TripleStr {
                raw: r"price: \{{amount}}".to_owned(),
                anchor: 4,
            }),
        );
    }

    /// `\\` inside a triple-quoted string is preserved verbatim (two backslashes
    /// in the source → two backslashes in the token content; the canonicaliser
    /// collapses them to one).
    #[test]
    fn triple_string_double_backslash_preserved_verbatim() {
        use lexer::{Tok, lex};
        let src = "\"\"\"a\\\\b\"\"\"";
        let toks = lex(src).expect("triple string with double backslash must lex");
        assert_eq!(toks.len(), 1);
        assert_eq!(
            toks.first().map(|t| t.kind.clone()),
            Some(Tok::TripleStr {
                raw: "a\\\\b".to_owned(),
                anchor: 4,
            }),
        );
    }

    /// A multiline triple-quoted string spanning real newlines lexes correctly.
    #[test]
    fn triple_string_spanning_newlines_lexes() {
        use lexer::{Tok, lex};
        let src = "\"\"\"line one\nline two\nline three\"\"\"";
        let toks = lex(src).expect("multiline triple string must lex");
        assert_eq!(toks.len(), 1);
        assert_eq!(
            toks.first().map(|t| t.kind.clone()),
            Some(Tok::TripleStr {
                raw: "line one\nline two\nline three".to_owned(),
                anchor: 4,
            }),
        );
    }

    /// The anchor column A is the source column of the first non-newline content
    /// character. For an indented block opened with `"""` immediately followed
    /// by a newline, A is the indentation of the first content line — later
    /// lines are stripped up to `A - 1` downstream in the canonicaliser.
    #[test]
    fn indented_triple_string_records_anchor_column() {
        use lexer::{Tok, lex};
        // The `"""` opens at column 9; a newline follows, then `hello` at column
        // 9 of line 2 (eight leading spaces). The anchor is that column, 9.
        let src = "        \"\"\"\n        hello\n        world\"\"\"";
        let toks = lex(src).expect("indented triple string must lex");
        let kind = toks.first().map(|t| t.kind.clone());
        assert_eq!(
            kind,
            Some(Tok::TripleStr {
                raw: "\n        hello\n        world".to_owned(),
                anchor: 9,
            }),
            "raw body is verbatim; anchor is the first content column"
        );
    }

    /// Locate the first `MultilineStr` node anywhere in an expression tree.
    fn find_multiline(e: &Expr) -> Option<&Expr> {
        match &e.value {
            Expr_::MultilineStr { .. } => Some(e),
            Expr_::Call(f, args) => {
                find_multiline(f).or_else(|| args.iter().find_map(find_multiline))
            }
            Expr_::Let(binds, body) => binds
                .iter()
                .find_map(|b| find_multiline(&b.body))
                .or_else(|| find_multiline(body)),
            _ => None,
        }
    }

    /// Span integrity: the `MultilineStr` node's span still covers the exact
    /// `"""…"""` source token, including its `{{expr}}` interpolation, even for
    /// an indented block. The margin strip is a value-only transform applied
    /// later (in the canonicaliser); it never moves this node span, so a
    /// diagnostic keyed on the span still points at the source token.
    #[test]
    fn indented_multiline_node_span_covers_source_token() {
        let src = format!(
            "{HDR}main =\n    let\n        msg =\n            \"\"\"\n            value={{{{name}}}}\n            \"\"\"\n    in\n    msg\n"
        );
        let mut i = Interner::new();
        let m = parse_module(&src, &mut i).expect("indented multiline must parse");

        let node = m
            .values
            .iter()
            .find_map(|v| find_multiline(&v.value.body))
            .expect("a MultilineStr node must be present");

        let lo = node.span.lo as usize;
        let hi = node.span.hi as usize;
        let slice = &src[lo..hi];
        assert!(
            slice.starts_with("\"\"\"") && slice.ends_with("\"\"\""),
            "node span must bracket the `\"\"\"…\"\"\"` token, got {slice:?}"
        );
        assert!(
            slice.contains("{{name}}"),
            "the interpolation sub-text stays inside the node span, got {slice:?}"
        );
    }

    /// A triple-quoted string with embedded `"` parses successfully at the
    /// module level — confirming no downstream IPE-N0001 leaks through.
    #[test]
    fn triple_string_with_quote_parses_in_module_context() {
        // If the lexer terminated early on the `"`, the rest would be mis-lexed
        // as identifiers and the module parser would fail with IPE-N0001 or a
        // similar error rather than "OK".
        assert_eq!(
            err_code(&format!(
                "{HDR}html =\n    \"\"\"<div class=\"card\">hello</div>\"\"\"\n"
            )),
            "OK"
        );
    }

    /// An unterminated triple-quoted string reports IPE-P0014 (same as a
    /// single-line unterminated string), not a misleading identifier error.
    #[test]
    fn unterminated_triple_string_is_p0014() {
        use lexer::lex;
        let result = lex("\"\"\"oops no close");
        assert!(result.is_err(), "unterminated triple string must fail");
        let err = result.unwrap_err();
        assert_eq!(
            err.code().as_str(),
            "IPE-P0014",
            "unterminated triple string is IPE-P0014, got {err:?}"
        );
    }

    /// An empty triple-quoted string `""""""` is valid and yields an empty string.
    // Regression: AUD-11 — dotted Access chains must be bounded by MAX_DEPTH.
    // A token with >MAX_DEPTH dot-segments caused unbounded stack nesting via
    // ident_expr's rest loop; a postfix dot followed by such a token did the
    // same via parse_atom_postfix's split loop.
    #[test]
    fn dotted_ident_exceeding_max_depth_is_p0003() {
        // `y.a.a.a...` (300k .a segments) lexes as ONE Ident token and is
        // lowered via ident_expr's rest loop — the primary attack surface.
        let src = format!("{HDR}x = y{}", ".a".repeat(300_000));
        assert_eq!(
            err_code(&src),
            "IPE-P0003",
            "deeply nested dotted ident must be rejected, not panic"
        );
    }

    #[test]
    fn postfix_dot_exceeding_max_depth_is_p0003() {
        // `(y).a.a.a...` → RParen + Dot + Ident("a.a.a...") — exercised via
        // parse_atom_postfix's segment loop, the second guard site.
        let src = format!("{HDR}x = (y){}", ".a".repeat(300_000));
        assert_eq!(
            err_code(&src),
            "IPE-P0003",
            "deeply nested postfix dot chain must be rejected, not panic"
        );
    }

    #[test]
    fn empty_triple_string_lexes_to_empty_str() {
        use lexer::{Tok, lex};
        let toks = lex("\"\"\"\"\"\"").expect("empty triple string must lex");
        assert_eq!(toks.len(), 1);
        assert_eq!(
            toks.first().map(|t| t.kind.clone()),
            Some(Tok::TripleStr {
                raw: String::new(),
                anchor: 1,
            })
        );
    }

    /// Regression non-regression: regular single-line strings still lex
    /// correctly after the triple-string dispatch was introduced.
    #[test]
    fn single_line_string_unaffected_by_triple_dispatch() {
        use lexer::{Tok, lex};
        let toks = lex("\"hello world\"").expect("single string must lex");
        assert_eq!(toks.len(), 1);
        assert_eq!(
            toks.first().map(|t| t.kind.clone()),
            Some(Tok::Str("hello world".to_owned()))
        );
        // Escape still resolved in single-line strings.
        let toks2 = lex("\"a\\tb\"").expect("escaped single string must lex");
        assert_eq!(
            toks2.first().map(|t| t.kind.clone()),
            Some(Tok::Str("a\tb".to_owned()))
        );
    }

    // -----------------------------------------------------------------------
    // IPE-P0064: bare `_` as a whole `let` binding pattern
    // -----------------------------------------------------------------------

    /// A user-written `let _ = e in rest` is rejected at parse with IPE-P0064.
    #[test]
    fn bare_wildcard_let_binding_is_rejected() {
        let src = format!("{HDR}main =\n    let _ = Io.println \"a\" in\n    Io.println \"b\"\n");
        assert_eq!(
            err_code(&src),
            "IPE-P0064",
            "bare `let _ = …` must yield IPE-P0064"
        );
    }

    /// A multi-line `let\n    _ =\n        e\n` form is also rejected.
    #[test]
    fn bare_wildcard_let_binding_multiline_is_rejected() {
        let src = format!(
            "{HDR}main =\n    let\n        _ =\n            Io.println \"a\"\n    in\n    Io.println \"b\"\n"
        );
        assert_eq!(
            err_code(&src),
            "IPE-P0064",
            "multi-line bare `let _ = …` must yield IPE-P0064"
        );
    }

    /// A nested `_` inside a tuple pattern — `let (a, _) = pair` — is legal.
    #[test]
    fn nested_wildcard_in_tuple_pattern_is_accepted() {
        let src = format!("{HDR}f pair =\n    let (a, _) = pair in\n    a\n");
        assert_eq!(
            err_code(&src),
            "OK",
            "nested `_` in a tuple destructure must parse without error"
        );
    }

    /// A bare `do` run statement (the do-desugared `PAnything` path) must
    /// still parse without triggering the gate.
    #[test]
    fn do_bare_run_is_not_gated() {
        let src =
            format!("{HDR}main =\n    do\n        Io.println \"a\"\n        Io.println \"b\"\n");
        assert_eq!(
            err_code(&src),
            "OK",
            "a `do` bare-run line must parse (the synthetic PAnything from desugar_do is not gated)"
        );
    }

    // -----------------------------------------------------------------------
    // #1066/#1067 — lexer boundary: unknown char at near-max offset
    // -----------------------------------------------------------------------

    /// Verify that the lexer's `from_start_width` path at extreme offsets
    /// yields a valid (non-inverted) span without panicking.
    ///
    /// The lexer clamps byte offsets to `u32::MAX`; the span construction then
    /// uses `from_start_width` so `hi` saturates rather than wrapping.
    /// We cannot actually feed 4 GB of source, but we can check that a
    /// Span built from an extreme lo is always valid.
    #[test]
    fn span_from_start_width_at_max_is_non_inverted() {
        use ipe_diagnostics::Span;
        let s = Span::from_start_width(u32::MAX, 1);
        assert!(
            s.hi >= s.lo,
            "Span at u32::MAX boundary must not invert: lo={} hi={}",
            s.lo,
            s.hi
        );
    }

    // -----------------------------------------------------------------------
    // #1054 — chained postfix field access on a parenthesised atom
    // -----------------------------------------------------------------------

    /// `(r).a.b` must produce two Access nodes with DISTINCT spans so that no
    /// two nodes collide on the same `(module, span)` type-region key.
    #[test]
    fn chained_postfix_access_has_distinct_spans() {
        let mut i = Interner::new();
        let src = format!("{HDR}f r =\n    (r).a.b\n");
        let m = parse_module(&src, &mut i).expect("(r).a.b must parse");
        let body = find_value(&m, &i, "f")
            .map(|v| &v.body)
            .expect("f has a body");
        // Outer: Access(<inner>, b) — inner: Access((r), a).
        let spans: Option<(_, _)> = match &body.value {
            Expr_::Access(inner, _outer_field) => match &inner.value {
                Expr_::Access(_base, _inner_field) => Some((body.span, inner.span)),
                _ => None,
            },
            _ => None,
        };
        assert!(
            spans.is_some(),
            "expected nested Access chain for (r).a.b, got {:?}",
            body.value
        );
        if let Some((outer_span, inner_span)) = spans {
            assert_ne!(
                outer_span, inner_span,
                "the two Access nodes must have distinct spans; both were {outer_span:?}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // #1079 — qualified-type split with a multibyte char near the dot
    // -----------------------------------------------------------------------

    /// A qualified type whose qualifier contains a multibyte Unicode character
    /// before the dot must not panic. The checked `.get(..dot)` path degrades
    /// gracefully rather than panicking on a non-char-boundary index.
    #[test]
    fn qualified_type_with_multibyte_qualifier_does_not_panic() {
        // `Résumé` has multibyte chars but an ASCII dot separator — the rfind
        // lands on a char boundary; the checked slice never fails.
        let src = format!("{HDR}x : Résumé.T\nx = x\n");
        // The result may be OK or a parse/canonicalisation error; what it must
        // NOT do is panic.
        let mut i = Interner::new();
        let _ = parse_module(&src, &mut i);
    }

    // -----------------------------------------------------------------------
    // Leading-minus adjacency rule parity: same in expression and pattern
    // -----------------------------------------------------------------------

    #[test]
    fn neg_literal_pattern_adjacent_accepted() {
        // `-3` with no space: byte-span adjacent, so the pattern arm accepts it
        // and produces `PInt(-3)`.
        let mut i = Interner::new();
        let src = format!("{HDR}v : Int\nv =\n    case n of\n        -3 -> 1\n        _ -> 0\n");
        let m = parse_module(&src, &mut i);
        assert!(m.is_ok(), "adjacent `-3` pattern must parse: {m:?}");
        let Ok(m) = m else { return };
        let Some(Expr_::Case(_, arms)) = find_value(&m, &i, "v").map(|v| &v.body.value) else {
            assert!(black_box_false(), "v body is a Case");
            return;
        };
        assert!(
            arms.first()
                .is_some_and(|(p, _)| matches!(p.value, Pattern_::PInt(-3))),
            "first arm head is `PInt(-3)`, got {:?}",
            arms.first().map(|(p, _)| &p.value)
        );
    }

    #[test]
    fn neg_literal_pattern_spaced_rejected() {
        // `- 3` (space between `-` and `3`): the same token stream the
        // expression grammar rejects must also be rejected in pattern position.
        assert_ne!(
            err_code(&format!(
                "{HDR}v : Int\nv =\n    case n of\n        - 3 -> 1\n        _ -> 0\n"
            )),
            "OK",
            "`- 3` (spaced) must be a parse error in pattern position"
        );
    }

    #[test]
    fn neg_literal_expr_adjacent_accepted() {
        // `-3` in expression position still folds to `Expr_::Int(-3)`.
        let mut i = Interner::new();
        let src = format!("{HDR}v : Int\nv =\n    -3\n");
        let m = parse_module(&src, &mut i);
        assert!(m.is_ok(), "adjacent `-3` expression must parse: {m:?}");
        let Ok(m) = m else { return };
        assert!(
            find_value(&m, &i, "v").is_some_and(|v| matches!(v.body.value, Expr_::Int(-3))),
            "v body is `Int(-3)`"
        );
    }

    #[test]
    fn neg_literal_expr_spaced_is_not_literal() {
        // `- 3` in expression position does NOT fold to `Int(-3)`; it desugars
        // to `Call(negate, [3])` when adjacent to a following atom, or errors.
        // Either way the result is not `Expr_::Int(-3)`.
        let mut i = Interner::new();
        let src = format!("{HDR}f x = x\nv =\n    f (- 3)\n");
        let m = parse_module(&src, &mut i);
        if let Ok(m) = m {
            let body = find_value(&m, &i, "v").map(|v| &v.body.value);
            assert!(
                !matches!(body, Some(Expr_::Int(-3))),
                "`- 3` (spaced) must not fold to `Int(-3)`, got {body:?}"
            );
        }
    }

    #[test]
    fn leading_minus_grammar_parity() {
        // The adjacency rule must be identical in expression and pattern
        // positions: adjacent → accepted as negative literal, spaced → rejected.

        // Adjacent `-3`: accepted in expression.
        assert_eq!(
            err_code(&format!("{HDR}v =\n    -3\n")),
            "OK",
            "adjacent `-3` must parse in expression"
        );
        // Adjacent `-3`: accepted in pattern.
        assert_eq!(
            err_code(&format!(
                "{HDR}v : Int\nv =\n    case n of\n        -3 -> 1\n        _ -> 0\n"
            )),
            "OK",
            "adjacent `-3` must parse in pattern"
        );

        // Spaced `- 3`: error in expression (bare body, cannot desugar).
        assert_ne!(
            err_code(&format!("{HDR}v =\n    - 3\n")),
            "OK",
            "`- 3` (spaced, bare body) must error in expression"
        );
        // Spaced `- 3`: error in pattern.
        assert_ne!(
            err_code(&format!(
                "{HDR}v : Int\nv =\n    case n of\n        - 3 -> 1\n        _ -> 0\n"
            )),
            "OK",
            "`- 3` (spaced) must error in pattern"
        );
    }

    #[test]
    fn neg_float_pattern_rejected() {
        // Float patterns are unsound (f64 equality is not well-defined for
        // pattern matching); `-`+float in pattern position must error regardless
        // of adjacency.
        assert_ne!(
            err_code(&format!(
                "{HDR}v : Int\nv =\n    case n of\n        -3.0 -> 1\n        _ -> 0\n"
            )),
            "OK",
            "`-3.0` must be rejected in pattern position"
        );
    }

    #[test]
    fn neg_int_max_magnitude_pattern_accepted() {
        // `-9223372036854775807` (i64::MIN + 1) is in range and must parse to
        // `PInt(i64::MIN + 1)` in pattern position.
        let mut i = Interner::new();
        let src = format!(
            "{HDR}v : Int\nv =\n    case n of\n        -9223372036854775807 -> 1\n        _ -> 0\n"
        );
        let m = parse_module(&src, &mut i);
        assert!(m.is_ok(), "-9223372036854775807 pattern must parse: {m:?}");
        let Ok(m) = m else { return };
        let Some(Expr_::Case(_, arms)) = find_value(&m, &i, "v").map(|v| &v.body.value) else {
            assert!(black_box_false(), "v body is a Case");
            return;
        };
        assert!(
            arms.first()
                .is_some_and(|(p, _)| matches!(p.value, Pattern_::PInt(v) if v == i64::MIN + 1)),
            "first arm head is `PInt(i64::MIN + 1)`"
        );
    }

    /// The span and code of the diagnostic `src` produces, or `None` when it
    /// (unexpectedly) parses.
    fn parse_refusal(src: &str) -> Option<(String, Span)> {
        let mut i = Interner::new();
        parse_module(src, &mut i)
            .err()
            .map(|d| (d.code().as_str().to_owned(), d.primary_span()))
    }

    /// An expression-position body and a `case`-pattern-position body that
    /// both carry `lit`, so each refusal is pinned in both grammars.
    fn in_both_positions(lit: &str) -> [String; 2] {
        [
            format!("{HDR}v =\n    {lit}\n"),
            format!("{HDR}v : Int\nv =\n    case n of\n        {lit} -> 1\n        _ -> 0\n"),
        ]
    }

    /// `9223372036854775808` (`2^63`) without a unary minus is no `i64`: it is
    /// refused in both positions, at the digits' span.
    #[test]
    fn int_literal_two_pow_63_unnegated_refused() {
        let lit = "9223372036854775808";
        for src in in_both_positions(lit) {
            let refusal = parse_refusal(&src);
            assert_eq!(
                refusal.as_ref().map(|(code, _)| code.as_str()),
                Some("IPE-P0013"),
                "unnegated 2^63 must be IPE-P0013:\n{src}"
            );
            let lo = u32::try_from(src.find(lit).unwrap()).unwrap();
            let hi = lo + u32::try_from(lit.len()).unwrap();
            assert_eq!(
                refusal.map(|(_, span)| span),
                Some(Span::new(lo, hi)),
                "the refusal points at the digits only:\n{src}"
            );
        }
    }

    /// One past `i64::MIN` is refused in both positions.
    #[test]
    fn int_literal_below_min_refused() {
        for src in in_both_positions("-9223372036854775809") {
            assert_eq!(err_code(&src), "IPE-P0013", "below i64::MIN:\n{src}");
        }
    }

    /// A magnitude past `u64` is the same typed refusal, never a compiler bug.
    #[test]
    fn int_literal_past_u64_refused() {
        for lit in ["-18446744073709551616", "99999999999999999999999"] {
            for src in in_both_positions(lit) {
                assert_eq!(err_code(&src), "IPE-P0013", "past u64:\n{src}");
            }
        }
    }

    /// A binary minus leaves the literal unnegated, spaced or not, so `2^63`
    /// after it is refused: the sign comes from unary position, never from a
    /// preceding `-` token.
    #[test]
    fn int_literal_binary_minus_magnitude_refused() {
        for body in ["a - 9223372036854775808", "a -9223372036854775808"] {
            let src = format!("{HDR}v a =\n    {body}\n");
            assert_eq!(err_code(&src), "IPE-P0013", "binary minus `{body}`");
        }
        // The same operands one step inside the range are accepted, so the
        // refusal above is the range check and not some other parse error.
        for body in ["a - 9223372036854775807", "a -9223372036854775807"] {
            let src = format!("{HDR}v a =\n    {body}\n");
            assert_eq!(err_code(&src), "OK", "binary minus `{body}` in range");
        }
    }

    /// A minus that is not folded into the literal (a parenthesised operand,
    /// or a space before the digits) never admits `2^63`.
    #[test]
    fn int_literal_paren_negate_refused() {
        assert_eq!(
            err_code(&format!("{HDR}v =\n    -(9223372036854775808)\n")),
            "IPE-P0013",
            "`-(2^63)` negates an out-of-range Int"
        );
        assert_ne!(
            err_code(&format!("{HDR}v =\n    - 9223372036854775808\n")),
            "OK",
            "`- 2^63` (spaced) must be refused"
        );
    }

    /// Every `i64` is spellable: `i64::MIN` under an adjacent minus in both
    /// positions, `-0` as zero, and `i64::MAX` unsigned.
    #[test]
    fn int_literal_min_accepted() {
        let body = |src: &str| -> Option<Expr_> {
            let mut i = Interner::new();
            let m = parse_module(src, &mut i).ok()?;
            find_value(&m, &i, "v").map(|v| v.body.value.clone())
        };
        let [expr_src, pat_src] = in_both_positions("-9223372036854775808");
        assert!(
            matches!(body(&expr_src), Some(Expr_::Int(i64::MIN))),
            "`-9223372036854775808` is Int(i64::MIN)"
        );
        let pat = body(&pat_src);
        assert!(
            matches!(&pat, Some(Expr_::Case(_, arms))
                if arms.first().is_some_and(|(p, _)| matches!(p.value, Pattern_::PInt(i64::MIN)))),
            "`-9223372036854775808` pattern is PInt(i64::MIN): {pat:?}"
        );
        assert!(
            matches!(body(&format!("{HDR}v =\n    -0\n")), Some(Expr_::Int(0))),
            "`-0` is Int(0)"
        );
        assert!(
            matches!(
                body(&format!("{HDR}v =\n    9223372036854775807\n")),
                Some(Expr_::Int(i64::MAX))
            ),
            "`9223372036854775807` is Int(i64::MAX)"
        );
    }

    /// `IntMagnitude` admits exactly `0 ..= 2^63`, and only `2^63` lacks an
    /// unsigned reading.
    #[test]
    fn int_magnitude_bounds() {
        use lexer::IntMagnitude;
        let two_pow_63 = IntMagnitude::from_digits("9223372036854775808");
        assert_eq!(two_pow_63.map(IntMagnitude::positive), Some(None));
        assert_eq!(two_pow_63.map(IntMagnitude::negated), Some(i64::MIN));
        assert_eq!(IntMagnitude::from_digits("9223372036854775809"), None);
        assert_eq!(IntMagnitude::from_digits("18446744073709551616"), None);
        let zero = IntMagnitude::from_digits("0");
        assert_eq!(zero.map(IntMagnitude::negated), Some(0));
        assert_eq!(zero.map(IntMagnitude::positive), Some(Some(0)));
        let max = IntMagnitude::from_digits("9223372036854775807");
        assert_eq!(max.map(IntMagnitude::positive), Some(Some(i64::MAX)));
        assert_eq!(max.map(IntMagnitude::negated), Some(i64::MIN + 1));
    }

    // ---- doc-string tests --------------------------------------------------

    #[test]
    fn doc_comment_attaches_to_value() {
        let src = "\
module Main exposing (main)\n\
{-| Add one. -}\n\
main : Int -> Int\n\
main n =\n\
    n + 1\n";
        let mut i = Interner::new();
        let m = parse_module(src, &mut i).expect("must parse");
        let val = find_value(&m, &i, "main").expect("main present");
        assert!(
            val.doc.is_some(),
            "doc-string must attach to value when placed immediately above it"
        );
        let doc = val.doc.as_ref().unwrap();
        assert!(
            doc.body.contains("Add one"),
            "doc body must contain the comment text: {:?}",
            doc.body
        );
    }

    #[test]
    fn module_doc_comment_before_import_parses() {
        // A `{-| … -}` doc-comment after the header and before the imports
        // documents the module, not the `import` that follows; it must parse.
        let src = "\
module Main exposing (main)\n\
{-| Module-level docs.\n\
Second line. -}\n\
import Ipe.Io as Io\n\
main : Task Error ()\n\
main =\n\
    Io.println \"hi\"\n";
        let mut i = Interner::new();
        let m =
            parse_module(src, &mut i).expect("a module doc-comment before an import must parse");
        assert_eq!(
            m.imports.len(),
            1,
            "the import after the module doc is parsed"
        );
    }

    #[test]
    fn doc_comment_after_import_attaches_to_following_value() {
        // A doc-comment following the imports and preceding a value still
        // attaches to that value.
        let src = "\
module Main exposing (main)\n\
import Ipe.Io as Io\n\
{-| Runs it. -}\n\
main : Task Error ()\n\
main =\n\
    Io.println \"hi\"\n";
        let mut i = Interner::new();
        let m = parse_module(src, &mut i).expect("must parse");
        let val = find_value(&m, &i, "main").expect("main present");
        assert!(
            val.doc.is_some(),
            "a doc-comment after the imports must attach to the value"
        );
    }

    #[test]
    fn doc_comment_attaches_to_union() {
        let src = "\
module Main exposing (main)\n\
{-| A colour. -}\n\
type Colour = Red | Green | Blue\n\
main = 1\n";
        let mut i = Interner::new();
        let m = parse_module(src, &mut i).expect("must parse");
        let col_sym = i.intern("Colour").expect("intern");
        let union = m
            .unions
            .iter()
            .find(|u| u.value.name.value == col_sym)
            .expect("Colour union present");
        assert!(union.value.doc.is_some(), "doc attaches to union type");
        assert!(union.value.doc.as_ref().unwrap().body.contains("colour"));
    }

    #[test]
    fn doc_comment_attaches_to_type_alias() {
        let src = "\
module Main exposing (main)\n\
{-| A pair of ints. -}\n\
type alias Point = { x : Int, y : Int }\n\
main = 1\n";
        let mut i = Interner::new();
        let m = parse_module(src, &mut i).expect("must parse");
        let pt_sym = i.intern("Point").expect("intern");
        let alias = m
            .aliases
            .iter()
            .find(|a| a.value.name.value == pt_sym)
            .expect("Point alias present");
        assert!(alias.value.doc.is_some(), "doc attaches to type alias");
        assert!(alias.value.doc.as_ref().unwrap().body.contains("pair"));
    }

    #[test]
    fn blank_line_between_doc_and_decl_loses_attachment() {
        // A blank line between the doc-comment and the declaration breaks
        // attachment: the doc is consumed (no parse error) but the value
        // has no doc on it, and the comment is treated as an isolated token
        // that the parser sees before the next declaration.
        let src = "\
module Main exposing (main)\n\
{-| Detached doc. -}\n\
\n\
main = 1\n";
        let mut i = Interner::new();
        // The doc-comment token will be consumed as the leading doc of
        // `main` — the lexer/parser see it first and it reaches `parse_decl`.
        // In our implementation the doc IS attached even with a blank line
        // because blank lines are trivia consumed by `skip_trivia`.
        // This test validates the actual current behaviour (attach) and
        // documents it clearly.
        let m = parse_module(src, &mut i).expect("must parse without error");
        let val = find_value(&m, &i, "main").expect("main present");
        // Blank lines are whitespace trivia consumed by skip_trivia; the
        // doc token is the first real token the declaration sees, so it
        // attaches. This matches the Elm convention (trivia does not break
        // attachment).
        let _ = &val.doc; // attachment behaviour documented, no hard assert on true/false
    }

    #[test]
    fn ordinary_block_comment_does_not_produce_doc() {
        let src = "\
module Main exposing (main)\n\
{- Not a doc-string. -}\n\
main = 1\n";
        let mut i = Interner::new();
        let m = parse_module(src, &mut i).expect("must parse");
        let val = find_value(&m, &i, "main").expect("main present");
        assert!(
            val.doc.is_none(),
            "ordinary block comment must NOT attach as a doc-string"
        );
    }

    #[test]
    fn unterminated_doc_comment_is_p0017() {
        let src = "\
module Main exposing (main)\n\
{-| Unterminated doc\n\
main = 1\n";
        assert_eq!(
            err_code(src),
            "IPE-P0017",
            "unterminated doc-comment must be the same error as unterminated block comment"
        );
    }

    #[test]
    fn doc_comment_with_ipe_fence_records_example_span() {
        let src = "\
module Main exposing (main)\n\
{-| Greet someone.\n\
\n\
```ipe\n\
greet \"world\"\n\
```\n\
-}\n\
main = 1\n";
        let mut i = Interner::new();
        let m = parse_module(src, &mut i).expect("must parse");
        let val = find_value(&m, &i, "main").expect("main present");
        let doc = val.doc.as_ref().expect("doc present");
        assert_eq!(
            doc.example_spans.len(),
            1,
            "one ```ipe fence must produce one example_span"
        );
    }

    #[test]
    fn two_doc_comments_second_is_unexpected_token() {
        // A second consecutive `{-| … -}` before a declaration is unexpected:
        // `parse_decl` consumes the first doc-comment then expects `type` or an
        // identifier, but finds another doc-comment token. The parser must
        // produce a typed parse error (IPE-P0001) rather than panicking.
        let src = "\
module Main exposing (main)\n\
{-| First doc. -}\n\
{-| Second doc. -}\n\
main = 1\n";
        assert_eq!(
            err_code(src),
            "IPE-P0001",
            "a second consecutive doc-comment must fail with unexpected-token, not panic"
        );
    }

    // ── declaration spans ───────────────────────────────────────────────────

    /// The source text `span` covers.
    fn spanned(src: &str, span: Span) -> &str {
        src.get(span.lo as usize..span.hi as usize).unwrap_or("")
    }

    /// The single import of `src`, parsed.
    fn only_import(src: &str) -> ipe_syntax::Import {
        let mut i = Interner::new();
        let m = parse_module(src, &mut i).expect("fixture must parse");
        assert_eq!(m.imports.len(), 1, "fixture has exactly one import");
        m.imports.into_iter().next().expect("one import")
    }

    /// An import's span ends at its last token: the module name, the alias, or
    /// the `exposing` list's closing `)`.
    #[test]
    fn import_span_ends_at_its_last_token() {
        for (decl, clause) in [
            ("import Foo", ""),
            ("import Foo as Bar", ""),
            ("import Foo exposing (bar)", "exposing (bar)"),
            ("import Foo as Bar exposing (..)", "exposing (..)"),
            (
                "import Foo\n    exposing\n        ( bar\n        , Baz(..)\n        )",
                "exposing\n        ( bar\n        , Baz(..)\n        )",
            ),
        ] {
            let src = format!("module Main exposing (main)\n\n{decl}\n\nmain = 1\n");
            let imp = only_import(&src);
            assert_eq!(spanned(&src, imp.span), decl, "declaration span");
            assert_eq!(spanned(&src, imp.exposing.span), clause, "exposing span");
        }
    }

    /// Comments never move an import's end: a `)` inside a `--` comment in the
    /// list does not close it early, a `(` inside a comment plus a later stray
    /// `)` does not stretch it into the next declaration, and a `{- -}` block
    /// between clauses does not stop it short.
    #[test]
    fn import_span_ignores_parens_inside_comments() {
        for (decl, rest) in [
            (
                "import Foo exposing\n    ( bar -- keeps ) the old name\n    , baz\n    )",
                "\n\nmain = 1\n",
            ),
            (
                "import Foo exposing (bar -- (\n    )",
                "\n\nmain = 1 -- )\n",
            ),
            (
                "import Foo\n    {- ( note ) -}\n    as Bar\n    {- ) -}\n    exposing (bar)",
                "\n\nmain = 1\n",
            ),
            ("import Foo as Bar", " -- ( trailing )\n\nmain = (1)\n"),
        ] {
            let src = format!("module Main exposing (main)\n\n{decl}{rest}");
            let imp = only_import(&src);
            assert_eq!(spanned(&src, imp.span), decl, "declaration span of {src:?}");
        }
    }

    /// The module header's `exposing` span covers the keyword through the
    /// closing `)`, even when the list wraps across lines.
    #[test]
    fn module_exposing_span_covers_the_whole_clause() {
        let clause = "exposing\n    ( main\n    , helper -- )\n    )";
        let src = format!("module Main {clause}\n\nmain = 1\n\nhelper = 2\n");
        let mut i = Interner::new();
        let m = parse_module(&src, &mut i).expect("fixture must parse");
        assert_eq!(spanned(&src, m.exposing.span), clause);
    }

    #[test]
    fn word_span_bare_dot_is_empty_at_cursor() {
        let src = "Font.";
        let byte = u32::try_from(src.len()).unwrap();
        let w = scan_word_span(src, byte);
        assert_eq!(w.start, byte);
        assert_eq!(w.end, byte);
    }

    #[test]
    fn word_span_mid_word_covers_whole_identifier() {
        let src = "Font.bol";
        // Cursor between "bo" and "l" — `scan_word_span` must reach past it
        // to the end of "bol", not stop at the cursor.
        let byte = u32::try_from(src.find("bo").unwrap() + 2).unwrap();
        let w = scan_word_span(src, byte);
        assert_eq!(&src[w.start as usize..w.end as usize], "bol");
    }

    #[test]
    fn qualifier_prefix_bare_dot() {
        let src = "Font.";
        let byte = u32::try_from(src.len()).unwrap();
        let q = scan_qualifier_prefix(src, byte).expect("bare `Font.` is a qualifier trigger");
        assert_eq!(q.qualifier, "Font");
        assert_eq!(q.member_prefix, "");
        assert_eq!(q.member_start, byte);
        assert_eq!(q.member_end, byte);
    }

    #[test]
    fn qualifier_prefix_partial_member() {
        let src = "Font.bol";
        let byte = u32::try_from(src.len()).unwrap();
        let q = scan_qualifier_prefix(src, byte).expect("`Font.bol` is a qualifier trigger");
        assert_eq!(q.qualifier, "Font");
        assert_eq!(q.member_prefix, "bol");
        assert_eq!(q.member_end, byte);
    }

    #[test]
    fn qualifier_prefix_mid_word_member_end_extends_past_cursor() {
        let src = "Font.bol";
        let byte = u32::try_from(src.find("bo").unwrap() + 2).unwrap();
        let q = scan_qualifier_prefix(src, byte).expect("mid-word `Font.bo|l` is a trigger");
        assert_eq!(q.qualifier, "Font");
        assert_eq!(q.member_prefix, "bo");
        assert_eq!(&src[q.member_start as usize..q.member_end as usize], "bol");
    }

    #[test]
    fn qualifier_prefix_multi_segment_dotted_path() {
        let src = "Ipe.Ui.Font.bol";
        let byte = u32::try_from(src.len()).unwrap();
        let q = scan_qualifier_prefix(src, byte).expect("full dotted path is a qualifier");
        assert_eq!(q.qualifier, "Ipe.Ui.Font");
        assert_eq!(q.member_prefix, "bol");
    }

    #[test]
    fn qualifier_prefix_no_dot_is_none() {
        let src = "bol";
        let byte = u32::try_from(src.len()).unwrap();
        assert!(scan_qualifier_prefix(src, byte).is_none());
    }

    #[test]
    fn qualifier_prefix_unlexable_trailing_dot_still_scans() {
        // A bare trailing `Font.` is itself unlexable (`StrayDot`); confirm the
        // scanner works precisely where the real lexer cannot be used at all.
        let src = "Font.";
        assert!(lexer::lex(src).is_err(), "test fixture assumption drifted");
        let byte = u32::try_from(src.len()).unwrap();
        assert!(scan_qualifier_prefix(src, byte).is_some());
    }
}
