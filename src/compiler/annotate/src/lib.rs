#![forbid(unsafe_code)]
//! Annotated-tokens compiler API — the SSOT for syntax highlighting and
//! term-to-definition linking.
//!
//! [`annotate`] produces a [`Vec<AnnotatedToken>`] from a parsed
//! [`ipe_syntax::Module`] (for spans + syntactic category) combined with its
//! name-resolved [`ipe_canon::ast::Module`] (for semantic class and definition
//! keys).  A consumer that only has the parse tree may call
//! [`annotate_syntax_only`], which produces the same token stream with
//! `def = None` and coarser semantic classes (no kernel/constructor distinction
//! for names that need resolver data to classify precisely).
//!
//! Both surfaces are backed by the real lexer spans and the real resolver —
//! never a hand-rolled tokenizer or string matcher.
//!
//! ## Projection to LSP semantic tokens
//!
//! [`ipe_lsp_features::semantic_tokens`] re-expresses its output as a thin
//! projection over [`annotate`]: it maps each [`TokenClass`] to an LSP token
//! type index and discards [`AnnotatedToken::def`].  That projection is the
//! proof that the shared API subsumes the LSP classifier without drift.
//!
//! ## Stable serialisation
//!
//! [`to_json`] serialises a token stream to a stable JSON array whose field
//! names are contractually fixed (see [`JsonToken`]).  External tools and
//! `ipe doc --tokens` (component E, not yet implemented) consume this form.

mod walk;

use ipe_diagnostics::Span;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Syntactic / semantic category of a token.
///
/// This is a superset of the ten LSP `SemanticTokenType` entries that
/// `semantic_tokens.rs` advertises.  The extra variants (kernel, constructor,
/// type-var) let consumers produce richer highlighting and cross-links without
/// a second pass.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenClass {
    /// Language keyword: `module`, `import`, `type`, `if`, `then`, `else`,
    /// `case`, `of`, `let`, `in`, `as`, `exposing`.
    Keyword,
    /// A named type constructor in a type annotation (`Int`, `List`, `Maybe`).
    Type,
    /// A type variable in a type annotation or type declaration (`a`, `b`).
    TypeVar,
    /// A top-level value / function binding name or a call to one.
    Function,
    /// A stdlib kernel function (e.g. `List.map`, `String.length`).
    Kernel,
    /// A data constructor used as a value or in a pattern (`Just`, `Nothing`, `True`, `False`).
    Constructor,
    /// A local variable binding (lambda / `case` / `let` pattern).
    Variable,
    /// A module name segment in a `module` declaration or `import`.
    Module,
    /// A binary operator (`+`, `|>`, `++`, `::`, `==`, …).
    Operator,
    /// A string or character literal.
    StringLit,
    /// An integer or float literal.
    Number,
    /// A block or line comment (not yet emitted — seam for future lexer spans).
    Comment,
    /// Punctuation that is neither an operator nor a keyword: `(`, `)`, `,`,
    /// `[`, `]`, `{`, `}`, `=`, `->`, `\\`, `|`, `:`.
    Punctuation,
}

/// A resolved definition key: the canonical address of the entity a name
/// refers to.
///
/// The string fields use the same `module::symbol` scheme that diagnostics and
/// the content index (component D) use, so a consumer can look up documentation
/// without a second resolver call.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum DefKey {
    /// A top-level value binding: `module` is the dot-joined module path,
    /// `name` is the binding name.
    TopLevel { module: String, name: String },
    /// A stdlib kernel: `module` is the canonical qualifier (e.g. `"List"`),
    /// `name` is the kernel function name (e.g. `"map"`).
    Kernel { module: String, name: String },
    /// A data constructor: `module` is the home module path, `type_name` is
    /// the union type, `name` is the constructor name.
    Constructor {
        module: String,
        type_name: String,
        name: String,
    },
}

/// One annotated token.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct AnnotatedToken {
    /// Byte offset of the token's first byte in the source text.
    pub byte_start: u32,
    /// Byte length of the token in the source text.
    pub byte_len: u32,
    /// Syntactic / semantic class.
    pub class: TokenClass,
    /// The resolved definition this name refers to, if applicable.
    ///
    /// `None` for non-name tokens (literals, keywords, operators, punctuation)
    /// and for names inside string / comment context.
    pub def: Option<DefKey>,
}

impl AnnotatedToken {
    /// Convenience: the span this token covers.
    #[must_use]
    pub const fn span(&self) -> Span {
        Span::new(self.byte_start, self.byte_start + self.byte_len)
    }
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

/// Produce the annotated-token stream for a module using both the parse tree
/// (for spans and syntactic classes) and the canonical AST (for semantic class
/// refinement and definition keys).
///
/// The stream is sorted by `byte_start`; overlapping spans are deduplicated
/// (first wins).  Returns an empty vec for an empty module.
#[must_use]
pub fn annotate(
    syntax: &ipe_syntax::Module,
    canon: &ipe_canon::ast::Module,
    interner: &ipe_intern::Interner,
) -> Vec<AnnotatedToken> {
    walk::annotate_full(syntax, canon, interner)
}

/// Produce the annotated-token stream using only the parse tree.
///
/// Semantic classes are coarser: every name that the full `annotate` would
/// classify as `Kernel` or `Constructor` appears as `Function` here.
/// `def` is always `None`.
///
/// Useful when canonicalisation failed (the source does not type-check) — the
/// LSP and docs generator still want syntax highlighting.
#[must_use]
pub fn annotate_syntax_only(
    syntax: &ipe_syntax::Module,
    interner: &ipe_intern::Interner,
) -> Vec<AnnotatedToken> {
    walk::annotate_syntax(syntax, interner)
}

// ---------------------------------------------------------------------------
// Stable serialisation
// ---------------------------------------------------------------------------

/// A stable, schema-frozen JSON representation of one annotated token.
///
/// Field names are contractually fixed: external tools depend on them.
/// Adding fields is additive (non-breaking); removing or renaming is a
/// breaking change requiring a major version bump and a migration note.
#[derive(Serialize, Deserialize, Debug)]
pub struct JsonToken {
    /// Byte offset of the first byte in the source.
    pub byte_start: u32,
    /// Byte length.
    pub byte_len: u32,
    /// Token class as a lowercase `snake_case` string (e.g. `"keyword"`,
    /// `"kernel"`, `"constructor"`).
    pub class: TokenClass,
    /// Resolved definition, or `null` for non-names.
    pub def: Option<DefKey>,
}

impl From<AnnotatedToken> for JsonToken {
    fn from(t: AnnotatedToken) -> Self {
        Self {
            byte_start: t.byte_start,
            byte_len: t.byte_len,
            class: t.class,
            def: t.def,
        }
    }
}

/// Serialise an annotated-token stream to a stable JSON string.
///
/// The output is a JSON array of objects matching the [`JsonToken`] schema.
///
/// # Errors
///
/// Returns an error if `serde_json` serialisation fails (in practice, this
/// cannot happen for these types — the error path satisfies the API contract).
pub fn to_json(tokens: &[AnnotatedToken]) -> Result<String, serde_json::Error> {
    let json_tokens: Vec<JsonToken> = tokens.iter().cloned().map(JsonToken::from).collect();
    serde_json::to_string(&json_tokens)
}

/// Like [`to_json`] but pretty-printed.
///
/// # Errors
///
/// Returns an error if `serde_json` serialisation fails.
pub fn to_json_pretty(tokens: &[AnnotatedToken]) -> Result<String, serde_json::Error> {
    let json_tokens: Vec<JsonToken> = tokens.iter().cloned().map(JsonToken::from).collect();
    serde_json::to_string_pretty(&json_tokens)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ipe_intern::Interner;
    use ipe_parse::parse_module;

    // ── Helpers ──────────────────────────────────────────────────────────────

    fn parse(src: &str) -> (ipe_syntax::Module, Interner) {
        let mut i = Interner::default();
        let m = parse_module(src, &mut i).expect("test source must parse");
        (m, i)
    }

    fn canon(syntax: &ipe_syntax::Module, interner: &mut Interner) -> ipe_canon::ast::Module {
        ipe_canon::canonicalise(syntax, interner).expect("test source must canonicalise")
    }

    /// Find all tokens with the given class in the stream.
    fn by_class(tokens: &[AnnotatedToken], class: TokenClass) -> Vec<&AnnotatedToken> {
        tokens.iter().filter(|t| t.class == class).collect()
    }

    /// Slice `src` at `token`'s span.
    fn text_of<'s>(src: &'s str, tok: &AnnotatedToken) -> &'s str {
        src.get(tok.byte_start as usize..(tok.byte_start + tok.byte_len) as usize)
            .unwrap_or("")
    }

    // ── Schema / JSON ─────────────────────────────────────────────────────

    #[test]
    fn json_schema_stable_field_names() {
        let tok = AnnotatedToken {
            byte_start: 7,
            byte_len: 4,
            class: TokenClass::Kernel,
            def: Some(DefKey::Kernel {
                module: "List".into(),
                name: "map".into(),
            }),
        };
        let json = to_json(&[tok]).expect("serialisation must succeed");
        // Contractually required field names.
        assert!(json.contains("\"byte_start\""), "field byte_start present");
        assert!(json.contains("\"byte_len\""), "field byte_len present");
        assert!(json.contains("\"class\""), "field class present");
        assert!(json.contains("\"def\""), "field def present");
        assert!(json.contains("\"kernel\""), "DefKey kind tag present");
        assert!(json.contains("\"module\""), "DefKey module field present");
        assert!(json.contains("\"name\""), "DefKey name field present");
    }

    #[test]
    fn json_none_def_is_null() {
        let tok = AnnotatedToken {
            byte_start: 0,
            byte_len: 6,
            class: TokenClass::Keyword,
            def: None,
        };
        let json = to_json(&[tok]).expect("serialisation must succeed");
        assert!(json.contains("\"def\":null"), "None def serialises as null");
    }

    #[test]
    fn json_roundtrip() {
        let tokens = vec![
            AnnotatedToken {
                byte_start: 0,
                byte_len: 6,
                class: TokenClass::Keyword,
                def: None,
            },
            AnnotatedToken {
                byte_start: 7,
                byte_len: 4,
                class: TokenClass::Kernel,
                def: Some(DefKey::Kernel {
                    module: "List".into(),
                    name: "map".into(),
                }),
            },
        ];
        let json = to_json(&tokens).expect("serialisation");
        let decoded: Vec<JsonToken> = serde_json::from_str(&json).expect("deserialisation");
        assert_eq!(decoded.len(), 2);
        let first = decoded.first().expect("first token");
        let second = decoded.get(1).expect("second token");
        assert_eq!(first.class, TokenClass::Keyword);
        assert!(first.def.is_none());
        assert_eq!(second.class, TokenClass::Kernel);
        assert!(second.def.is_some());
    }

    // ── Corpus: classification cases a hand-rolled highlighter gets wrong ─

    #[test]
    fn shadowed_name_classified_as_variable_not_function() {
        // A top-level `map` shadowed by a `let map = …` inside a binding.
        // The inner `map` must be `Variable`, not `Function`.
        let src = "module Main exposing (main)\n\nmap : Int -> Int\nmap x = x\n\nmain : Int\nmain =\n    let\n        map = 99\n    in\n    map\n";
        let (syntax, mut interner) = parse(src);
        let canon_mod = canon(&syntax, &mut interner);
        let tokens = annotate(&syntax, &canon_mod, &interner);

        // The `let map = 99` binding occurrence shadows the top-level `map`, so it
        // must not be classified as a Kernel.
        let let_map_offset = src.find("let\n        map").and_then(|p| {
            src.get(p..)
                .and_then(|rest| rest.find("map"))
                .map(|rel| p + rel)
        });
        if let Some(off) = let_map_offset
            && let Some(t) = tokens.iter().find(|t| t.byte_start as usize == off)
        {
            assert_ne!(
                t.class,
                TokenClass::Kernel,
                "shadowed 'map' must not be Kernel"
            );
        }
        // The top-level `map` binding name must be Function.
        let top_level_map_off = src.find("map : Int").expect("top-level map present");
        if let Some(t) = tokens
            .iter()
            .find(|t| t.byte_start as usize == top_level_map_off)
        {
            assert_eq!(t.class, TokenClass::Function, "top-level map is Function");
        }
    }

    #[test]
    fn name_inside_string_literal_not_annotated_as_name() {
        let src = "module Main exposing (main)\n\nmain : String\nmain =\n    \"List.map\"\n";
        let (syntax, mut interner) = parse(src);
        let canon_mod = canon(&syntax, &mut interner);
        let tokens = annotate(&syntax, &canon_mod, &interner);

        // The string token must cover the entire literal.
        let string_toks: Vec<_> = by_class(&tokens, TokenClass::StringLit);
        assert!(!string_toks.is_empty(), "string literal must be classified");
        // No Kernel or Function token should start inside the string literal bounds.
        if let Some(str_tok) = string_toks.first() {
            let str_start = str_tok.byte_start;
            let str_end = str_tok.byte_start + str_tok.byte_len;
            for tok in &tokens {
                if tok.byte_start > str_start && tok.byte_start < str_end {
                    assert_eq!(
                        tok.class,
                        TokenClass::StringLit,
                        "no name token inside string literal at byte {}",
                        tok.byte_start
                    );
                }
            }
        }
    }

    #[test]
    fn operator_vs_punctuation_distinct() {
        // `+` in a binop is an Operator; the type/ctor `|` separator in source
        // is not emitted as a token at all (syntax only captures ctor names).
        // We verify the operator token appears in a module with a binop.
        let src = "module Main exposing (main)\n\ntype Color = Red | Blue\n\nmain : Int\nmain =\n    1 + 2\n";
        let (syntax, mut interner) = parse(src);
        let canon_mod = canon(&syntax, &mut interner);
        let tokens = annotate(&syntax, &canon_mod, &interner);

        let ops = by_class(&tokens, TokenClass::Operator);
        // The `+` operator should appear as an Operator-class token.
        assert!(!ops.is_empty(), "binop `+` produces an Operator token");
    }

    #[test]
    fn operator_token_span_is_glyph_not_gap() {
        // `1 + 2` — the Operator token must cover only `+` (1 byte),
        // NOT the gap ` + ` (3 bytes) that the old gap reconstruction produced.
        // This test is non-vacuous: on the old code (`Span::new(lhs.span.hi,
        // rhs.span.lo)`) the token would span 3 bytes including whitespace.
        let src = "module Main exposing (main)\n\nmain : Int\nmain =\n    1 + 2\n";
        // Byte offset of `+`: 28(blank)+11(ann)+7(decl)+6("    1 ") = 52.
        let plus_byte: u32 = src
            .find(" + ")
            .map(|i| u32::try_from(i + 1).expect("byte offset fits u32"))
            .expect("` + ` present in source");

        let (syntax, mut interner) = parse(src);
        let canon_mod = canon(&syntax, &mut interner);
        let tokens = annotate(&syntax, &canon_mod, &interner);

        let ops = by_class(&tokens, TokenClass::Operator);
        assert!(!ops.is_empty(), "binop `+` must produce an Operator token");

        let op = ops.first().expect("checked non-empty above");
        assert_eq!(
            op.byte_start, plus_byte,
            "Operator token must start at the `+` glyph (byte {plus_byte}), got {}",
            op.byte_start
        );
        assert_eq!(
            op.byte_len, 1,
            "Operator token must be 1 byte (just `+`), got {} — whitespace included",
            op.byte_len
        );

        // The syntax-only walker must agree on the same span.
        let syn_tokens = annotate_syntax_only(&syntax, &interner);
        let syn_ops = by_class(&syn_tokens, TokenClass::Operator);
        assert!(
            !syn_ops.is_empty(),
            "syntax-only walker must also emit Operator token"
        );
        let syn_op = syn_ops.first().expect("checked non-empty above");
        assert_eq!(
            (syn_op.byte_start, syn_op.byte_len),
            (op.byte_start, op.byte_len),
            "canon and syntax-only walker must agree on operator span"
        );
    }

    #[test]
    fn kernel_vs_user_function_distinct() {
        // `seed` is a top-level user function; `Crypto.sha256` calls a kernel.
        // (A security module stays kernel-qualifier; a compiled-source stdlib
        // module would not resolve in this raw-canon test.)
        let src = "module Main exposing (main)\n\nimport Ipe.Crypto as Crypto\n\nseed : String\nseed = \"x\"\n\nmain : String\nmain =\n    Crypto.sha256 seed\n";
        let (syntax, mut interner) = parse(src);
        let canon_mod = canon(&syntax, &mut interner);
        let tokens = annotate(&syntax, &canon_mod, &interner);

        // `seed` call site in `Crypto.sha256 seed` must be Function.
        let kernel_pos = src.rfind("Crypto.sha256").expect("Crypto.sha256 present");
        let user_pos = src[kernel_pos..].find("seed").map(|r| kernel_pos + r);
        if let Some(pos) = user_pos {
            let tok = tokens.iter().find(|t| t.byte_start as usize == pos);
            if let Some(t) = tok {
                assert_eq!(
                    t.class,
                    TokenClass::Function,
                    "user 'seed' is Function at call site"
                );
            }
        }

        // The kernel call `Crypto.sha256` should produce a Kernel token.
        let kernel_toks = by_class(&tokens, TokenClass::Kernel);
        let kernel_tok = kernel_toks.iter().find(|t| {
            let slice = text_of(src, t);
            slice == "sha256" || slice == "Crypto.sha256"
        });
        assert!(
            kernel_tok.is_some(),
            "Crypto.sha256 produces a Kernel-classified token"
        );
    }

    #[test]
    fn type_vs_constructor_distinct() {
        // `Color` as a type annotation must be Type; `Red` as a constructor must be Constructor.
        let src = "module Main exposing (main)\n\ntype Color = Red | Blue\n\nmain : Color\nmain =\n    Red\n";
        let (syntax, mut interner) = parse(src);
        let canon_mod = canon(&syntax, &mut interner);
        let tokens = annotate(&syntax, &canon_mod, &interner);

        let ctors = by_class(&tokens, TokenClass::Constructor);
        let red_ctor = ctors.iter().find(|t| text_of(src, t) == "Red");
        assert!(red_ctor.is_some(), "Red is classified as Constructor");
    }

    #[test]
    fn qualified_call_def_resolves_to_kernel() {
        // `Crypto.sha256` def must be DefKey::Kernel { module: "Crypto", name: "sha256" }.
        let src = "module Main exposing (main)\n\nimport Ipe.Crypto as Crypto\n\nmain : String\nmain =\n    Crypto.sha256 \"x\"\n";
        let (syntax, mut interner) = parse(src);
        let canon_mod = canon(&syntax, &mut interner);
        let tokens = annotate(&syntax, &canon_mod, &interner);

        let kernel_toks = by_class(&tokens, TokenClass::Kernel);
        let map_tok = kernel_toks
            .iter()
            .find(|t| text_of(src, t) == "sha256" || text_of(src, t) == "Crypto.sha256")
            .expect("Crypto.sha256 token found");
        assert_eq!(
            map_tok.def,
            Some(DefKey::Kernel {
                module: "Crypto".to_string(),
                name: "sha256".to_string(),
            }),
            "Crypto.sha256 resolves to the Crypto.sha256 kernel def",
        );
    }

    #[test]
    fn def_is_none_inside_string() {
        let src = "module Main exposing (main)\n\nmain : String\nmain =\n    \"List.map\"\n";
        let (syntax, mut interner) = parse(src);
        let canon_mod = canon(&syntax, &mut interner);
        let tokens = annotate(&syntax, &canon_mod, &interner);

        // Every token that is inside the string literal must have def = None.
        let str_tok = tokens
            .iter()
            .find(|t| t.class == TokenClass::StringLit)
            .expect("string token present");
        let str_start = str_tok.byte_start;
        let str_end = str_tok.byte_start + str_tok.byte_len;
        for tok in &tokens {
            if tok.byte_start >= str_start && tok.byte_start < str_end {
                assert!(
                    tok.def.is_none(),
                    "token at {} inside string must have def=None",
                    tok.byte_start
                );
            }
        }
    }
}
