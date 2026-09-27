//! Typed compiler diagnostics. No stage ever returns a `String` error; every
//! failure is one of these enums. `CompilerBug.detail` is the only free-form
//! `String`, reserved for "this should never happen" contract violations.
//!
//! Payloads are **owned and structured**: a producer resolves every `Symbol`
//! and zonks every type at the failure point, so the reporter needs neither the
//! interner nor the type arena. Messages are rendered from data, never from a
//! pre-formatted string. Variants are **additive**: the coarse variants from
//! Milestone 0 (`ParseError::Unexpected`, `NameError::Unknown`, …) are retained
//! so existing call sites keep compiling while producers migrate.

use crate::code::{
    Code, Family, IPE_E0001, IPE_F4400, IPE_F4401, IPE_F4402, IPE_F4410, IPE_F4411, IPE_F4412,
    IPE_F4413, IPE_F4414, IPE_F4415, IPE_I0001, IPE_I0010, IPE_I0011, IPE_I0100, IPE_I0101,
    IPE_I0102, IPE_I0103, IPE_I0200, IPE_I0201, IPE_I0202, IPE_I0203, IPE_L0100, IPE_L0101,
    IPE_L0102, IPE_L0103, IPE_L0104, IPE_L0105, IPE_L0106, IPE_L0107, IPE_L0108, IPE_L0110,
    IPE_L0111, IPE_L0112, IPE_L0113, IPE_L0114, IPE_L0115, IPE_L0116, IPE_L0117, IPE_L0118,
    IPE_L0119, IPE_L0120, IPE_L0121, IPE_L0122, IPE_L0123, IPE_L0124, IPE_L0125, IPE_L0126,
    IPE_L0127, IPE_L0128, IPE_L0129, IPE_L0130, IPE_L0131, IPE_L0132, IPE_L0134, IPE_L0135,
    IPE_L0136, IPE_L0140, IPE_L0141, IPE_L0142, IPE_L0143, IPE_L0144, IPE_L0145, IPE_L0146,
    IPE_L0147, IPE_L0148, IPE_L0149, IPE_L0150, IPE_L0151, IPE_L0153, IPE_L0200, IPE_N0001,
    IPE_N0002, IPE_N0003, IPE_N0004, IPE_N0005, IPE_N0010, IPE_N0011, IPE_N0012, IPE_N0013,
    IPE_N0020, IPE_N0021, IPE_N0022, IPE_N0023, IPE_N0024, IPE_N0025, IPE_N0026, IPE_N0027,
    IPE_N0028, IPE_N0029, IPE_N0030, IPE_N0031, IPE_N0032, IPE_N0033, IPE_N0034, IPE_N0035,
    IPE_N0036, IPE_N0038, IPE_N0039, IPE_N0040, IPE_N0041, IPE_N0042, IPE_N0043, IPE_N0044,
    IPE_N0045, IPE_N0046, IPE_N0047, IPE_N0048, IPE_N0049, IPE_N0050, IPE_N0051, IPE_N0052,
    IPE_P0001, IPE_P0002, IPE_P0003, IPE_P0010, IPE_P0011, IPE_P0012, IPE_P0013, IPE_P0014,
    IPE_P0015, IPE_P0016, IPE_P0017, IPE_P0018, IPE_P0020, IPE_P0021, IPE_P0030, IPE_P0031,
    IPE_P0040, IPE_P0041, IPE_P0050, IPE_P0060, IPE_P0061, IPE_P0062, IPE_P0063, IPE_P0064,
    IPE_P0065, IPE_P0066, IPE_P0067, IPE_P0068, IPE_P0069, IPE_P0070, IPE_S0001, IPE_T0001,
    IPE_T0002, IPE_T0003, IPE_T0004, IPE_T0010, IPE_T0011, IPE_T0012, IPE_T0013, IPE_T0014,
    IPE_T0015, IPE_T0016, IPE_T0017, IPE_T0018, IPE_T0019, IPE_T0020, Severity,
};
use crate::span::Span;

// ===========================================================================
// Plain-old-data payload enums
// ===========================================================================

/// A set-valued list of names/patterns rendered in a diagnostic.
///
/// The elements are held in a canonical order that depends only on the strings
/// themselves — never on hash-map iteration order or interner-allocation order.
/// The only way to build one sorts and de-duplicates its input, so an unsorted
/// set-diagnostic is not representable and the rendered bytes are stable for a
/// given set, regardless of the order the producer discovered the elements.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SortedNames(Box<[Box<str>]>);

impl SortedNames {
    /// Collect an iterator of already-resolved names into canonical
    /// (lexicographic, de-duplicated) order.
    pub fn new(names: impl IntoIterator<Item = Box<str>>) -> Self {
        let mut names: Vec<Box<str>> = names.into_iter().collect();
        names.sort();
        names.dedup();
        Self(names.into_boxed_slice())
    }

    /// Collect a fallible iterator of names, short-circuiting on the first
    /// error, then canonicalise the successes. For producers that resolve each
    /// element through a fallible interner lookup.
    ///
    /// # Errors
    /// The first `Err` yielded by `names`.
    pub fn try_new<E>(names: impl IntoIterator<Item = Result<Box<str>, E>>) -> Result<Self, E> {
        let mut collected: Vec<Box<str>> = Vec::new();
        for name in names {
            collected.push(name?);
        }
        Ok(Self::new(collected))
    }

    #[must_use]
    pub fn as_slice(&self) -> &[Box<str>] {
        &self.0
    }
}

impl core::ops::Deref for SortedNames {
    type Target = [Box<str>];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// A lexical token category, with no payload — the structural shape a parser
/// reports as "found" without carrying the lexeme.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum TokenKind {
    Module,
    Import,
    Exposing,
    As,
    Type,
    /// The `foreign` keyword — opens an FFI type declaration.
    Foreign,
    Case,
    Of,
    Let,
    In,
    If,
    Then,
    Else,
    Do,
    LParen,
    RParen,
    LBrace,
    RBrace,
    /// `[` — opens a list literal / pattern.
    LBracket,
    /// `]` — closes a list literal / pattern.
    RBracket,
    /// `::` — the list cons operator / pattern head.
    ColonColon,
    Equals,
    Pipe,
    Colon,
    Arrow,
    /// `<-` — the `do`-block bind arrow.
    LeftArrow,
    /// A lambda lead-in `\`.
    Backslash,
    DotDot,
    /// A lone `.` field-access operator (`(r).field`).
    Dot,
    Comma,
    Underscore,
    Plus,
    /// The append operator `++`.
    PlusPlus,
    Minus,
    Star,
    Slash,
    SlashEq,
    /// `//` — the integer-division operator.
    SlashSlash,
    EqEq,
    Lt,
    Gt,
    Le,
    Ge,
    AmpAmp,
    PipePipe,
    /// The forward-pipe operator `|>`.
    PipeGt,
    /// The backward-pipe operator `<|`.
    LtPipe,
    /// The parser-pipeline keep operator `|=` — apply right parser, keep its result.
    PipeEq,
    /// The parser-pipeline ignore operator `|.` — apply right parser, discard its result.
    PipeDot,
    /// The forward-composition operator `>>`.
    GtGt,
    /// The backward-composition operator `<<`.
    LtLt,
    Ident,
    Int,
    /// A floating-point literal `1.5`, `3.0`, `1.5e3`.
    Float,
    /// A string literal `"…"`.
    Str,
    /// A character literal `'…'`.
    Char,
    /// End of input.
    Eof,
}

/// A single grammatical item the parser expected at the failure position.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Expected {
    ModuleKeyword,
    ExposingKeyword,
    OfKeyword,
    InKeyword,
    ThenKeyword,
    ElseKeyword,
    Equals,
    Arrow,
    Pipe,
    Comma,
    Colon,
    LParen,
    RParen,
    RBrace,
    Identifier,
    Constructor,
    TypeAtom,
    Expression,
    Pattern,
}

/// The set of items that would have been accepted where a token was rejected.
/// Owned and bounded; ordered by the producer for deterministic rendering.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct ExpectedSet(pub Box<[Expected]>);

/// The enclosing construct a parser was inside when input ran out or nesting
/// tripped a guard.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Construct {
    ModuleHeader,
    ExposingList,
    Definition,
    TypeDeclaration,
    CaseBranch,
    Type,
    ParenGroup,
    Expression,
    Pattern,
    Let,
    If,
    Tuple,
    Record,
    Lambda,
}

/// Which part of a module header is malformed.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum HeaderDefect {
    /// The file does not begin with `module`.
    NotModuleKeyword,
    /// The module name is missing.
    MissingName,
    /// The module name is not an identifier.
    NameNotIdentifier,
    /// The `exposing` keyword is missing.
    MissingExposing,
}

/// Which part of an `exposing (...)` list is malformed.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum ExposingDefect {
    /// The opening `(` is missing.
    MissingOpenParen,
    /// An item separator is neither `,` nor `)`.
    BadSeparator,
    /// An exposed name is not an identifier.
    NameNotIdentifier,
    /// A `Type(..)` constructor list is malformed.
    MalformedCtorList,
}

/// Which part of a `type` declaration is malformed.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum TypeDeclDefect {
    /// The type name is missing.
    MissingName,
    /// The `=` before the constructors is missing.
    MissingEquals,
    /// A constructor name does not start with an uppercase letter.
    CtorNotUppercase,
    /// A constructor name is not an identifier.
    CtorNotIdentifier,
}

/// Which part of a `case … of` expression is malformed.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum CaseDefect {
    /// `of` is missing after the scrutinee.
    MissingOf,
    /// A branch is missing its `->`.
    MissingArrow,
    /// The case has zero branches.
    NoBranches,
    /// The first branch is not indented past `case`.
    FirstBranchNotIndented,
}

/// Which part of a `let … in` expression is malformed.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum LetDefect {
    /// `let` is immediately followed by `in` (or end of input) — no bindings.
    NoBindings,
    /// A binding name is not a lowercase identifier.
    BindingNameNotLower,
    /// A binding name is not followed by `=` or any binder-atom-start token.
    /// This covers e.g. `let x 2 in x`, where a literal sits where `=` was
    /// expected (function parameters `let f x = …` are desugared, not rejected).
    MissingEquals,
    /// The `in` keyword is missing after the bindings.
    MissingIn,
    /// The entire bound pattern is a bare `_` wildcard, which binds nothing
    /// and silently discards the right-hand side. Use a `do` bare-run line or
    /// `|> Task.andThen (\_ -> …)` to sequence an effect. [IPE-P0064]
    BareWildcardBinding,
}

/// Which part of an `if … then … else …` expression is malformed.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum IfDefect {
    /// A condition is missing (e.g. `if then …` or end of input where the
    /// condition was expected).
    MissingCondition,
    /// The `then` keyword is missing after a condition.
    MissingThen,
    /// The `else` keyword is missing after a `then` branch.
    MissingElse,
}

// ===========================================================================
// Owned, pretty-printable type document
// ===========================================================================

/// A fully-resolved, interner-free rendering of a type.
///
/// Built by the type checker at the failure point (it zonks the type and
/// resolves every name), so the reporter renders this without touching
/// `VarId`s or the interner.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum TyDoc {
    /// A type constructor application, e.g. `List Int` or `Ipe.Maybe a`.
    Con {
        module: Box<str>,
        name: Box<str>,
        args: Box<[Self]>,
    },
    /// A function type `a -> b`.
    Fun(Box<Self>, Box<Self>),
    /// A type variable, e.g. `a`.
    Var(Box<str>),
    /// The unit type `()`.
    Unit,
    /// An anonymous product (tuple) type `(T1, T2, ...)`. Invariant: arity ≥ 2.
    Tuple(Box<[Self]>),
    /// A closed record type `{ x : Int, y : Bool }`. Fields are `(name, type)`
    /// pairs in field-name order (the producer sorts them, so rendering is
    /// deterministic).
    Record(Box<[(Box<str>, Self)]>),
}

// ===========================================================================
// Stage error enums (additive)
// ===========================================================================

/// Errors raised during lexing / parsing.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ParseError {
    /// Coarse "a token was unexpected" (Milestone 0 — retained additively).
    Unexpected,
    /// Coarse "recursion-depth guard tripped" (Milestone 0 — retained).
    TooDeep,
    /// A token was found where the grammar wanted one of `expected`. [IPE-P0001]
    UnexpectedToken {
        found: TokenKind,
        expected: ExpectedSet,
    },
    /// Input ended while `construct` still required more tokens. [IPE-P0002]
    UnexpectedEof { construct: Construct },
    /// Nesting of `construct` exceeded `limit`. [IPE-P0003]
    NestingTooDeep { construct: Construct, limit: u16 },
    /// A byte that is not a recognised character. [IPE-P0010]
    UnknownChar(char),
    /// A lone `.` not part of `..` or a qualified name. [IPE-P0011]
    StrayDot,
    /// A `.` with whitespace before it in expression position, e.g. `f .x`.
    /// No longer produced: `f .x` now parses as the first-class accessor `.x`
    /// (the getter `\r -> r.x`) applied to `f`. The code is retained in the
    /// catalog so historical diagnostics/explanations resolve. [IPE-P0018]
    SpaceBeforeDot,
    /// A digit immediately followed by an identifier character. [IPE-P0012]
    NumberJoinedToName(char),
    /// An integer literal that does not fit in `i64`. [IPE-P0013]
    IntLiteralOutOfRange,
    /// A float literal whose magnitude overflows `f64` to infinity
    /// (e.g. `1e400`). [IPE-P0016]
    FloatLiteralOutOfRange,
    /// A string literal `"…` whose closing `"` is missing before end of input
    /// (or before the line ends). [IPE-P0014]
    UnterminatedString,
    /// A character literal `'…` that is malformed — unterminated, empty (`''`),
    /// or carrying more than one character before the closing `'`. [IPE-P0015]
    MalformedChar,
    /// A block comment `{- … ` whose closing `-}` is missing before end of
    /// input. Nesting is supported (`{- {- -} -}`), so the scanner counts
    /// depth; depth > 0 at EOF triggers this error. [IPE-P0017]
    UnterminatedBlockComment,
    /// The module header is malformed. [IPE-P0020]
    MalformedModuleHeader(HeaderDefect),
    /// The `exposing (...)` list is malformed. [IPE-P0021]
    MalformedExposingList(ExposingDefect),
    /// A value binding's patterns are not followed by `=`. [IPE-P0030]
    MissingEquals { binding: Box<str> },
    /// A `type` declaration is malformed. [IPE-P0031]
    MalformedTypeDeclaration(TypeDeclDefect),
    /// Type arguments applied to a non-constructor. [IPE-P0040]
    TypeArgsOnNonConstructor,
    /// A token that cannot begin a type. [IPE-P0041]
    ExpectedType,
    /// A `(` opened something that never closed; `opener` is the `(` span. [IPE-P0050]
    UnclosedDelimiter { opener: Span },
    /// A `case … of` expression is malformed. [IPE-P0060]
    MalformedCase(CaseDefect),
    /// A `let … in` expression is malformed. [IPE-P0061]
    MalformedLet(LetDefect),
    /// An `if … then … else …` expression is malformed. [IPE-P0062]
    MalformedIf(IfDefect),
    /// A `path "…"` literal whose string fails compile-time validation.
    ///
    /// `reason` names which check failed: [`PathRejection::Nul`] (a NUL byte
    /// in the string) or [`PathRejection::Traversal`] (the cleaned path
    /// escapes its root via `..`). `literal` is the original unmodified source
    /// string. [IPE-P0063]
    InvalidPathLiteral {
        literal: Box<str>,
        reason: ipe_path_core::PathRejection,
    },
    /// A `do` block whose statements are all pure `=` bindings with no `<-`
    /// Task bind and no bare-run Task step — pure code masquerading as `do`.
    /// Use `let … in` for pure bindings; lift with `Task.succeed` if a `Task`
    /// result is genuinely needed. [IPE-P0065]
    SteplessDo,
    /// A doc-string (`{-| … -}`) is attached to a non-exported binding.
    ///
    /// Only exported symbols are reachable by doc-tooling; a doc-string on an
    /// unexported binding is unreachable and is likely misplaced. **Warning** —
    /// the program still compiles. [IPE-P0066]
    DocOnUnexported { name: Box<str> },
    /// An exported symbol has no doc-string. Emitted only when the opt-in lint
    /// (`--lint missing-docs`) is enabled; off by default. **Warning** — the
    /// program still compiles. [IPE-P0067]
    MissingDocString { name: Box<str> },
    /// A standalone `name : T` type annotation whose `name` has no matching
    /// value binding in the module — an orphan the compiler would otherwise
    /// silently drop, discarding the author's stated type. [IPE-P0068]
    AnnotationWithoutBinding { name: Box<str> },
    /// Two or more `name : T` type annotations declare the same `name`. Only
    /// one type can bind a value; the extras would otherwise be silently
    /// dropped last-write-wins. [IPE-P0069]
    DuplicateAnnotation { name: Box<str> },
    /// The source file exceeds the addressable span range: byte offsets are
    /// stored as `u32`, so a file larger than `u32::MAX` bytes cannot be given
    /// accurate spans. Rather than clamp offsets (which would misreport every
    /// position past the limit), the lexer turns the file away. [IPE-P0070]
    SourceTooLarge { bytes: usize },
}

/// Errors raised during name resolution / canonicalisation.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum NameError {
    /// Coarse "a name did not resolve" (Milestone 0 — retained additively).
    Unknown,
    /// A bare value name resolves to nothing. [IPE-N0001]
    ValueNotFound {
        name: Box<str>,
        suggestions: Box<[Box<str>]>,
    },
    /// A type name is undefined. [IPE-N0002]
    TypeNotFound {
        name: Box<str>,
        suggestions: Box<[Box<str>]>,
    },
    /// A constructor is undefined/misspelled. [IPE-N0003]
    ConstructorNotFound {
        name: Box<str>,
        suggestions: Box<[Box<str>]>,
    },
    /// A qualifier names no module/import alias. [IPE-N0004]
    UnknownModule {
        qualifier: Box<str>,
        suggestions: Box<[Box<str>]>,
    },
    /// A KNOWN Tier-C stdlib qualifier is used without importing its module
    /// (ADR 0001): `String.join` with no `import Ipe.String`. Distinct from
    /// [`Self::UnknownModule`] (a genuinely unknown qualifier): here the module
    /// exists and the fix is deterministic — add the named import. `qualifier` is
    /// the short-name at the use site; `import_path` is the exact
    /// `import` line to add (e.g. `Ipe.String`). [IPE-N0034]
    StdlibImportRequired {
        qualifier: Box<str>,
        import_path: Box<str>,
    },
    /// The qualifier resolves but the member is absent. [IPE-N0005]
    NoSuchMember {
        module: Box<str>,
        member: Box<str>,
        suggestions: Box<[Box<str>]>,
    },
    /// Two top-level values share a name; `first` is the earlier span. [IPE-N0010]
    DuplicateValue { name: Box<str>, first: Span },
    /// Two constructors share a name; `first` is the earlier span. [IPE-N0011]
    DuplicateConstructor { name: Box<str>, first: Span },
    /// Two types share a name; `first` is the earlier span. [IPE-N0012]
    DuplicateType { name: Box<str>, first: Span },
    /// A `type alias` is applied with the wrong number of type arguments —
    /// `Pair Int Bool` for a one-parameter `Pair a`, or a bare `Pair` where one
    /// argument is required. A type alias must be fully applied. [IPE-N0013]
    AliasArity {
        name: Box<str>,
        expected: usize,
        found: usize,
    },
    /// A local module named in an `import` cannot be found under `source_root`.
    /// `suggestions` lists close matches by Levenshtein distance. [IPE-N0020]
    ModuleNotFound {
        name: Box<str>,
        suggestions: Box<[Box<str>]>,
    },
    /// The import graph for the project contains a cycle; `path` lists the
    /// module names in cycle order (last element imports the first). [IPE-N0021]
    ImportCycle { path: Box<[Box<str>]> },
    /// An `import M exposing (x)` names a member `x` that `M` does not expose.
    /// `suggestions` lists close matches among `M`'s public exports. [IPE-N0022]
    NameNotExposed {
        module: Box<str>,
        name: Box<str>,
        suggestions: Box<[Box<str>]>,
    },
    /// The `module` declaration at the top of a `.ipe` file does not match the
    /// path I derived from the file's location under `source_root`. [IPE-N0023]
    ModulePathMismatch {
        declared: Box<str>,
        expected: Box<str>,
    },
    /// Two `import` statements bring the same unqualified name into scope;
    /// `modules` lists the origins. [IPE-N0024]
    AmbiguousImport {
        name: Box<str>,
        modules: SortedNames,
    },
    /// A local module's name starts with `Ipê` or `Std`, which are reserved for
    /// the standard library. [IPE-N0025]
    ReservedNamespace { name: Box<str> },
    /// A user `type` / `type alias` declaration reuses a name the compiler
    /// reserves for a built-in type constructor (`Int`, `Maybe`, `Html`, `Cmd`,
    /// `Length`, …). The lowerer matches these names ahead of the user-enum
    /// lookup, so accepting the shadow would silently override the user type and
    /// miscompile with no diagnostic; it is rejected at the declaration instead.
    /// [IPE-N0026]
    ReservedBuiltinType { name: Box<str> },
    /// Two `import` statements register the same qualifier (an explicit
    /// `as Alias`, or two module paths sharing a last segment) against
    /// DIFFERENT dep modules — `Utils.format` / `Http.get` would otherwise
    /// silently resolve to whichever import came last in source order, with
    /// no diagnostic. Re-importing the SAME dep module under the same
    /// qualifier (a diamond dependency) is NOT an error — only a genuine
    /// clash between two distinct dep modules is. `first` is the earlier
    /// import's span. [IPE-N0027]
    DuplicateQualifier { qualifier: Box<str>, first: Span },
    /// A standard-library binding `f = Kernel.kernel "Name"` (a Stage-4 kernel
    /// alias) names a kernel that is not registered in the kernel table. The
    /// `alias` is the raw string; `module` / `function` are its first-`_` split.
    /// FAIL-CLOSED (THE SEAL): accepting this would emit a call to a kernel that
    /// does not exist, type-checking in `ipe` but failing the downstream Rust
    /// build — so the alias is rejected at compile time. [IPE-N0028]
    UnknownKernelAlias {
        alias: Box<str>,
        module: Box<str>,
        function: Box<str>,
    },
    /// A kernel with no denotation for the browser-WASM target is named in a
    /// `--target wasm` build. The client bundle is fully public, so server
    /// effects (and their secrets) must be unrepresentable in it — the fix is
    /// to run the effect on the server and reach it via an HTTP route.
    /// [IPE-N0029]
    ServerOnlyKernelForWasm { qualifier: Box<str>, name: Box<str> },
    /// Layer 2 of the wasm security gate (spec Q5): the client entry's
    /// reachability closure transitively reaches a module classified
    /// `server` (one of its own defs directly names a kernel with no
    /// `WasmClient` denotation). `chain` names the exact import path from
    /// the entry to the offending module, e.g. `Main(client) -> View(shared)
    /// -> Data(server: imports Ipe.Db.query)` — never just "not allowed".
    /// [IPE-N0030]
    ServerModuleReachableFromWasmClient { chain: Box<str> },
    /// A built-in container type constructor is applied to the wrong number of
    /// type arguments — a bare `List`, a `Maybe (List String)` written
    /// unparenthesised as `Maybe List String` (`Maybe` seeing two args and
    /// `List` seeing none), `Dict String`, `Result Error`. These constructors
    /// have a fixed arity (`List`/`Maybe`/`Set` take 1, `Dict`/`Result` take
    /// 2); an under- or over-application is caught at name resolution, ahead of
    /// the lowerer's `ir_type_from_canon` — where a mis-arity builtin would
    /// otherwise reach the empty-home catch-all and ICE (IPE-I0001). The
    /// sibling of `AliasArity` for the closed builtin-container table.
    /// [IPE-N0031]
    BuiltinTypeArity {
        name: Box<str>,
        expected: usize,
        found: usize,
    },
    /// A `type alias` expansion exceeded the compiler's recursion-depth or
    /// node-count budget. `kind` names which of the two independent limits
    /// was hit; `limit` is the configured threshold.
    ///
    /// Two limits guard two distinct failure modes:
    ///
    /// * [`AliasExpansionKind::Depth`] — a long straight chain of distinct
    ///   aliases (`type alias A1 = A0`, `type alias A2 = A1`, …) grows the
    ///   native call stack by one frame per expansion. The depth cap (256)
    ///   mirrors the parser's `MAX_DEPTH` to stay safely below the thread
    ///   stack limit in every build profile.
    ///
    /// * [`AliasExpansionKind::Nodes`] — a diamond of aliases (`type alias
    ///   A1 = (A0, A0)`, …) is acyclic so the path-based cycle guard never
    ///   fires, but the total nodes produced double at every level. The node
    ///   budget (100 000) bounds this regardless of tree shape.
    ///
    /// [IPE-N0032]
    TypeExpansionTooDeep {
        kind: AliasExpansionKind,
        limit: u32,
    },
    /// A Program — a plain-`main` module whose `main` is not a managed-update-loop
    /// (TEA) app entry — imports a shape module under `Ipe.Tea.*`. The
    /// `Ipe.Tea.*` namespace holds only live-loop machinery; importing any part
    /// of it marks a module a TEA app, so a Program that does so is a
    /// contradiction rejected here. `module` is the offending `Ipe.Tea.*` import
    /// path. [IPE-N0033]
    ProgramImportsTeaShape { module: Box<str> },
    /// A TEA app imports another shape's `Cmd` / `Sub` re-export module. `Cmd`
    /// and `Sub` are shape-specific and reached through the app's own shape
    /// (`Ipe.Tea.Web.Cmd` in a `Web` app, `Ipe.Tea.Terminal.Sub` in a `Terminal`
    /// app, …). The app's shape is proven from its entry kernel; a `Cmd` / `Sub`
    /// import from a different shape has no denotation in this app and fails
    /// closed here. `imported` is the offending import path; `imported_shape` and
    /// `app_shape` name the two shapes; `expected` is the correct import path for
    /// the app's shape. [IPE-N0035]
    WrongShapeCmdSub(Box<CmdSubShapeMismatch>),
    /// A surface binding that has been intentionally removed from the stdlib.
    /// `qualifier.name` is the call site; `replacement` is the migration hint
    /// (empty when no direct replacement exists). [IPE-N0036]
    RemovedSurface {
        qualifier: Box<str>,
        name: Box<str>,
        replacement: Box<str>,
    },
    /// An asserted foreign call (`Rust.Ffi.call`) is malformed at its use
    /// site: applied to a non-literal path, referenced without application,
    /// carrying an invalid Rust path, or placed anywhere other than the whole
    /// body of an annotated top-level definition. `detail` names the specific
    /// rule broken. [IPE-N0038]
    AssertedCallMalformed { detail: Box<str> },
    /// A `CustomElement down up` boundary type parameter is not a plain, closed,
    /// concrete value type — the SEAL. Every value crossing the Ipê↔JS seam is
    /// encoded down / decoded up as canonical JSON, so a boundary parameter must
    /// be a primitive, record, list, tuple, `Maybe`, or user ADT over those,
    /// transitively. A function, an effect carrier (`Cmd`/`Task`/`Sub`), a view
    /// value (`Html`/`Element`/`Attribute`), a `Secret` or reserved sink type, an
    /// open row, or a type variable is rejected here at the type level rather
    /// than serialised across the seam (Security #6, fail-closed: absent proof
    /// that a crossing value is safe, it is refused). `seal_type` is the rendered
    /// offending parameter; `reason` names why it is illegal. [IPE-N0039]
    BoundarySealIllegal {
        seal_type: Box<str>,
        reason: SealRejection,
    },
    /// A `Db.Decode` / `Json.Decode.Pipeline` `required` / `optional` /
    /// `requiredAt` / `custom` combinator is hand-nested rather than threaded
    /// with `|>`. The combinators bind fields to the constructor in the order
    /// they RECEIVE the accumulator, so the innermost hand-nested call binds
    /// first — reversing source order and silently swapping any two same-typed
    /// fields with no type error. Rejected fail-closed; the message shows the
    /// order-preserving `|>` rewrite. [IPE-N0040]
    NestedDecoderPipeline,
    /// `Ipe.Codec.auto` cannot derive a codec for the witness it was applied to.
    /// The derive elaborates a record type into the field-by-field `Codec` a
    /// hand-written codec would build; a witness that is not an annotated record
    /// value, or a record carrying a field whose type has no derivable leaf codec
    /// (a function, a `Secret`, a data-carrying ADT, an opaque handle), has no
    /// such elaboration. Rejected fail-closed at the call site — there is no
    /// partial codec and no deferred emit failure. `reason` names the specific
    /// rule; `field` names the offending field (empty when the witness itself is
    /// wrong rather than one of its fields). [IPE-N0041]
    CodecAutoUnderivable {
        reason: CodecAutoRejection,
        field: Box<str>,
    },
    /// A `f = Kernel.kernel "Name"` kernel-alias binding appears in USER source. A
    /// kernel alias binds a name directly to a built-in kernel, bypassing the
    /// capability model: an unsafe-tier kernel (a raw-`<script>` sink, a secret
    /// reveal, a raw SQL exec) is reachable through it with no `unsafe`
    /// disclosure and no `.Unsafe` import to acknowledge. Minting a kernel is
    /// therefore the sole privilege of driver-vouched
    /// [`crate::resolve::ModuleOrigin::EmbeddedStdlib`] / `FfiInterface` modules
    /// (the standard library and the generated FFI interface); user code reaches
    /// a kernel only through the sanctioned surface that imports and discloses
    /// it. Mirrors the `Ffi.binding` origin gate — `Kernel.kernel` in user source
    /// is unrepresentable, not merely discouraged (Security #1, fail-closed).
    /// `alias` is the raw kernel string the binding named. [IPE-N0042]
    KernelAliasInUserSource { alias: Box<str> },
    /// A top-level `config` binding (the app's cross-cutting `List (Setting
    /// shape)`) is declared but never threaded into an app entry, so it is inert
    /// data the runtime never installs. Mirrors the discarded-`Task` lint
    /// posture (IPE-L0141): a value whose whole purpose is a runtime effect must
    /// reach the site that consumes it. A `config` binding is consumed only by
    /// being passed to a shape app entry (`Web.tea` / `Web.appWith`); one left
    /// unthreaded silently drops every setting it lists (a missed host bind, an
    /// un-enforced CSRF posture, an unset secret), so it is rejected here rather
    /// than compiled into an app that ignores it. [IPE-N0043]
    DiscardedConfig,
    /// The reserved `CustomElement.fromFile "<js-path>"` constructor is malformed at its
    /// use site. Like the `Kernel.kernel` literal gate, `CustomElement.fromFile` is legal ONLY
    /// as the entire body of a `CustomElement`-annotated binding, applied to a
    /// SINGLE STRING LITERAL naming the author's widget-hook JS file. Rejected
    /// fail-closed when: the argument is not a string literal (a variable, an
    /// expression — the file cannot be resolved at build time); the constructor is
    /// referenced bare / unapplied or from any other position; the path escapes the
    /// project root (`..` traversal); or the named file does not exist. The JS
    /// source is a VALUE argument, never a type parameter — the two seal params are
    /// the down/up types only. `detail` names the specific rule broken (Security
    /// #5, fail-closed: a build-time path is cleaned + in-project-checked +
    /// required to exist before the widget can be registered). [IPE-N0044]
    CustomElementCtorMalformed { detail: Box<str> },
    /// `main` selects its shape at runtime: after peeling application, `let`, and
    /// `\… ->` the head of `main`'s body is an `if` / `case` whose branches reach
    /// app entries (`Web.tea` / `Tui.tea` / `Cli.tea`). A program's shape is
    /// pinned by the entry head at compile
    /// time, not chosen from a runtime value — so a shape-branching `main` fails
    /// closed here (static pinning, Correctness #2). The carrying
    /// [`Diagnostic::Name`] span points at the branching head. [IPE-N0045]
    RuntimeBranchedMain,
    /// `Web.tea`'s `init` field has an annotation whose first argument is a free
    /// type variable (`a`, `req`, etc.) rather than the concrete `WebReq` type.
    /// The request type is always `WebReq` — the SSR/request-context shape is
    /// not user-choosable. Writing `init : a -> …` hides the concrete type and
    /// makes the app's init signature a lie: the function is compiled as if it
    /// accepts any type, defeating SSR path/query/cookie access. Use the concrete
    /// annotation `init : WebReq -> (Model, Cmd Msg)` or omit the annotation and
    /// let inference fill in `WebReq`. [IPE-N0046]
    WebInitPolyArg,
    /// A standard-library module is imported in a shape × runtime placement the
    /// library single-source-of-truth table does not admit (spec § 5). A
    /// program's placement is fixed by two orthogonal axes — its shape (what
    /// `view` renders, pinned by `main`) and, for the Web shape, its runtime
    /// (co-located `served` vs sandboxed `solo`). One table classifies every stdlib
    /// module by the placements it is admissible in; an import outside that set
    /// is refused here at resolve time, before any downstream cargo build (THE
    /// SEAL) can break and before a native effect could reach a sandboxed
    /// browser bundle (Security > ease of use, fail-closed). The carried
    /// [`ModulePlacementRejection`] names the module, the placement, and why the
    /// two axes forbid it, so the rendered message teaches the fix. [IPE-N0047]
    ModuleNotAllowedInPlacement(Box<ModulePlacementRejection>),
    /// Two DISTINCT Ipê definitions collapse to one generated Rust identifier
    /// after name mangling — the backend's `naming.rs` fold is not injective, so
    /// e.g. `Std.Ui.borderRounded` and `Std.Ui.Border.rounded` both fold to
    /// `std_ui_border_rounded`, and `firstName` / `first_name` both fold to the
    /// witness trait `IpeHasFirstName`. Emitting both items under one name is
    /// `rustc` E0428, so the backend fails closed here rather than emit a broken
    /// crate. Unlike [`NameError::DuplicateValue`] (a genuine same-name source
    /// redefinition, carrying real spans), this is a mangling collision between
    /// two differently-spelled Ipê definitions; the IR carries no source spans,
    /// so it names both Ipê definitions and the shared Rust name and asks for a
    /// rename. [IPE-N0048]
    RustNameFold {
        /// The first (already-claimed) Ipê definition, as a dotted path.
        first: Box<str>,
        /// The second Ipê definition that folds onto the same Rust name.
        second: Box<str>,
        /// The generated Rust identifier both definitions produce.
        rust_name: Box<str>,
        /// Whether the collision is in the value or type namespace — selects the
        /// noun the message uses.
        kind: RustNameFoldKind,
    },
    /// A single pattern binds the same variable name more than once (e.g.
    /// `( x, x )`). Each bound name is a distinct value in the branch body, so
    /// two bindings of one name are ambiguous; the pattern is rejected rather
    /// than silently shadowing one with the other. `first` is the span of the
    /// earlier binder. [IPE-N0049]
    DuplicatePatternBinder { name: Box<str>, first: Span },
    /// A **Script** (a `main : Task Error ()` whose head is a plain `Task`, not a
    /// shape entry) imports a shape's view/UI module. A Script renders nothing —
    /// it has no `view` — so the imported UI never reaches a screen. This is a
    /// **Warning**, not a rejection: the program is a legal Script and still
    /// compiles. The hint nudges toward the entry the author likely meant
    /// (`main = <Shape>.app { … }`). `shape_ui_module` is the offending imported
    /// UI path; `shape` is the shape it belongs to; `entry` is the app entry that
    /// would render it. [IPE-N0050]
    ScriptImportsShapeView {
        shape_ui_module: Box<str>,
        shape: Box<str>,
        entry: Box<str>,
    },
    /// An app entry (`Web.tea`, `Web.embed`, `Web.appWith`, `Tui.tea`,
    /// `Cli.tea`, `Worker.tea`, …) is referenced inside a definition generic
    /// over a type variable its cfg still mentions — a helper generic over `msg`
    /// that builds the cfg. The running app stores, serialises, compares, and
    /// prints its model and messages, which needs one concrete `Model` / `Msg`;
    /// an unfixed type variable there is refused rather than deferred to a
    /// failing Rust build (THE SEAL). `entry` is the entry's qualified name,
    /// `type_var` the offending variable, `reach` whether the entry is proven
    /// to mention it or only cannot be proven free of it. [IPE-N0051]
    GenericAppEntry {
        entry: Box<str>,
        type_var: Box<str>,
        reach: GenericAppEntryReach,
    },
    /// An app entry whose model or message type the program never fixes — an
    /// `update` that ignores its message and a view that emits none leave
    /// `msg` a type variable no definition is generic over. The running app
    /// needs one concrete `Model` / `Msg` exactly as for
    /// [`NameError::GenericAppEntry`]. `entry` is the entry's qualified name.
    /// [IPE-N0051]
    UnpinnedAppEntry { entry: Box<str> },
    /// A wasm build places an effect carrier (`Cmd`, `Sub`, `Task`, or a type
    /// holding one) where a `Decoder` element must be thread-shareable. A
    /// decoder is `Send` on every target while a wasm effect carrier is not, so
    /// the program is refused rather than deferred to a failing Rust build
    /// (THE SEAL). `found` names the offending carrier, or the type variable
    /// that could be instantiated at one. [IPE-N0052]
    EffectCarrierInDecoder { found: Box<str> },
}

/// How a [`NameError::GenericAppEntry`] refusal relates the entry to its
/// generic — selects the rendered message.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GenericAppEntryReach {
    /// The entry's solved instantiation mentions the generic.
    Mentioned,
    /// The generic is in scope and no type information shows whether the
    /// entry's model or message reaches it (a row generic of the annotation,
    /// or an entry reference with no solved type); refused fail-closed.
    Undetermined,
}

/// Which namespace a [`NameError::RustNameFold`] collision falls in — selects
/// the noun the rendered message uses ("value" vs "type").
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RustNameFoldKind {
    /// A value-namespace fold: two functions, or a record struct / row-witness
    /// trait, collapsing onto one Rust identifier.
    Value,
    /// A type-namespace fold: two enums collapsing onto one Rust type name.
    Type,
}

impl RustNameFoldKind {
    /// The noun for this namespace, used in the rendered message.
    #[must_use]
    pub const fn noun(self) -> &'static str {
        match self {
            Self::Value => "values",
            Self::Type => "types",
        }
    }
}

/// Why a standard-library module is not admissible in a shape × runtime
/// placement, reported inside [`NameError::ModuleNotAllowedInPlacement`].
///
/// Boxed on the `NameError` so `Diagnostic` stays under clippy's
/// `result_large_err` threshold. `module` is the offending import path;
/// `placement` is the human placement phrase (`script`, `terminal`, `server`,
/// `web served`, `web solo`); `reason` selects the kind-teacher sentence and its
/// suggested fix (spec § 6). The prose lives with the renderer so the message
/// set is itself a single source of truth.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ModulePlacementRejection {
    /// The offending stdlib import path, e.g. `Ipe.Db.Store`.
    pub module: Box<str>,
    /// The program's placement phrase, e.g. `web solo`.
    pub placement: Box<str>,
    /// Why this module family is inadmissible in that placement.
    pub reason: ModulePlacementReason,
}

/// The specific library-SSOT rule a rejected import broke (spec § 5, § 6).
///
/// Each variant selects a distinct kind-teacher sentence naming what is wrong,
/// the big-picture reason (which of the two axes forbids it), and the fix.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ModulePlacementReason {
    /// A native effect (`Ipe.Db` / `Ipe.File` / `Ipe.Http.Server` / a secret) in
    /// a sandboxed `solo` runtime — the DB/secret-to-browser leak. Move it behind
    /// an HTTP boundary, or deliver as `web` (served).
    NativeEffectInSandbox,
    /// A `Ipe.Browser.*` host capability in a placement with no JS host
    /// (`terminal` / `server` / `script`).
    BrowserOutsideBrowserHost,
}

/// Why `Ipe.Codec.auto` could not derive a codec.
///
/// Reported inside [`NameError::CodecAutoUnderivable`]. Each variant names a
/// distinct non-derivable category so the diagnostic teaches the specific rule
/// broken and points at the sanctioned explicit-codec escape.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CodecAutoRejection {
    /// The witness argument is not a bare reference to a top-level value carrying
    /// a record-type annotation — the one form whose fields the derive can read.
    WitnessNotRecordValue,
    /// `auto` was applied to the wrong number of arguments (it takes exactly one
    /// witness value).
    ArityMismatch,
    /// A field is a `Secret` or a reserved sink type — encoding it to JSON or a
    /// column is exactly the leak the Security principle forbids.
    SecretField,
    /// A field is a function type — not a serialisable value.
    FunctionField,
    /// A field is a data-carrying ADT, an opaque handle, an effect/decoder
    /// carrier, or otherwise has no derivable leaf codec. The escape is an
    /// explicit `Codec` (`taggedUnion`/`varN` for a data ADT).
    UnsupportedField,
}

/// Why a `CustomElement` boundary type parameter fails the SEAL.
///
/// Reported inside [`NameError::BoundarySealIllegal`]. Each variant names a
/// distinct non-serialisable category so the rendered diagnostic teaches the
/// specific rule broken rather than a blanket "not allowed".
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SealRejection {
    /// A function type (`a -> b`) — not a plain value, not serialisable.
    Function,
    /// An effect carrier — `Cmd`, `Task`, or `Sub`.
    EffectCarrier,
    /// A view value — `Html`, `Element`, `Attribute`, `Event`, or a `Ipe.Ui`
    /// plain type — clonable but not a boundary-serialisable data value.
    ViewValue,
    /// A `Secret` or a reserved sink type (`SqlFragment`, a CSS-safety marker):
    /// a secret- or sink-privileged value must never cross the JS seam.
    SecretOrSink,
    /// A type variable or an open row — the seal is monomorphic and concrete;
    /// prefer-concrete codegen generates one codec per concrete type.
    NonConcrete,
    /// Any other type the seal cannot PROVE is plain-and-safe (an opaque handle,
    /// an async/decoder type, a not-yet-classified builtin). Fail-closed: the
    /// conservative branch refuses it rather than guess.
    NotProvenPlain,
}

/// The four names IPE-N0035 reports.
///
/// Boxed inside [`NameError::WrongShapeCmdSub`] so `NameError` (and thus
/// [`Diagnostic`]) stays under clippy's `result_large_err` threshold on the
/// `Result<_, Diagnostic>` hot paths.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CmdSubShapeMismatch {
    pub imported: Box<str>,
    pub imported_shape: Box<str>,
    pub app_shape: Box<str>,
    pub expected: Box<str>,
}

/// Which expansion budget was exhausted, reported as part of
/// [`NameError::TypeExpansionTooDeep`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AliasExpansionKind {
    /// The recursion-depth limit was hit (a long straight alias chain).
    Depth,
    /// The node-count budget was exhausted (an exponentially-fanning diamond).
    Nodes,
}

/// Class label for the higher-order-kernel callback-result obligation.
///
/// `Maybe`/`Result` `map`/`map2..5`/`mapError`/`andMap` apply their callback
/// at one exact arity, so the callback's result must not itself be a
/// function. Shared between the constructor (`ipe_types::super_unsatisfied`)
/// and the renderer's tailored [`TypeError::SuperTypeUnsatisfied`] sentence so
/// the two sites cannot drift — the generic "`X` is not a `<class>` type"
/// template would read as a confusing double negative for this label.
pub const HOF_KERNEL_RESULT_CLASS: &str =
    "non-function callback result (Maybe/Result higher-order kernel)";

/// Errors raised during type inference / checking.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum TypeError {
    /// Coarse "two types failed to unify" (Milestone 0 — retained additively).
    Mismatch,
    /// Coarse "solver step budget exhausted" (Milestone 0 — retained).
    BudgetExceeded,
    /// Two types fail to unify, with rendered expected/found. [IPE-T0001]
    ///
    /// `TyDoc`s are boxed so the `Diagnostic` enum stays small (the `Err`
    /// half of every `DResult` in the compiler).
    TypeMismatch {
        expected: Box<TyDoc>,
        found: Box<TyDoc>,
        /// Optional secondary span of the definition that fixed the type.
        definition: Option<Span>,
        /// The diverging field/row path, e.g. `["user", "age"]`, if applicable.
        path: Box<[Box<str>]>,
    },
    /// Occurs-check failure: `var` would have to equal a type containing it. [IPE-T0002]
    InfiniteType { var: Box<str>, ty: Box<TyDoc> },
    /// The solver step budget `budget` was exhausted. [IPE-T0003]
    StepBudgetExceeded { budget: u64 },
    /// A typed binding has more parameter patterns than its annotation has
    /// arrows. [IPE-T0004]
    TooManyParameters {
        binding: Box<str>,
        signature: Box<TyDoc>,
    },
    /// A case does not cover every constructor; `missing` lists them. [IPE-T0010]
    NonExhaustiveCase { missing: SortedNames },
    /// Two arms cover the same constructor (warning). [IPE-T0011]
    RedundantCaseBranch { constructor: Box<str> },
    /// A `record.field` access whose `field` is not present in the (closed)
    /// record type `record` — or whose base is not a record at all. [IPE-T0012]
    NoSuchField { field: Box<str>, record: Box<TyDoc> },
    /// A record UPDATE (`{ p | message = … }`) on a nominal BUILTIN type
    /// (`PanicInfo` / `TypeInfo` / `ErrorInfo` / `Request`). Those types expose
    /// readable fields through a fixed table (`p.message` type-checks), but
    /// they are not structural records — there is no user-writable
    /// record-update form, and nowhere sound for the updated structural value
    /// to flow. A plain [`TypeError::NoSuchField`] here would be misleading
    /// ("no field `message`" for a field that IS readable). [IPE-T0017]
    BuiltinRecordUpdate { name: Box<str> },
    /// A constructor pattern binds a number of payload sub-patterns that differs
    /// from the constructor's declared field count (`Just` with no payload, or
    /// `Node l r` for a three-field `Node`). [IPE-T0013]
    CtorPatternArity {
        ctor: Box<str>,
        expected: usize,
        found: usize,
    },
    /// A generic binding whose body constrains a type variable to a Ipê
    /// super-type — `Number` (`+ - *`) or `Comparable` (`< > <= >=`) — is used
    /// at a type that does not provide those operations (`double True`, where
    /// `double` needs `Number`), or at a type that stays non-concrete (the
    /// obligation cannot be propagated across the use). `class` names the
    /// super-type; `found` is the offending type. A `class` equal to
    /// [`HOF_KERNEL_RESULT_CLASS`] renders through a tailored sentence — the
    /// generic "`X` is not a `<class>` type" template reads as a confusing
    /// double negative for that internal arity obligation. [IPE-T0014]
    SuperTypeUnsatisfied { class: Box<str>, found: Box<TyDoc> },
    /// A **parameter** pattern (lambda param, function-def head, or `let`
    /// binder) is **refutable** — it can fail to match some value of its type
    /// (`\(Just x) ->`, `\1 ->`, `\[a] ->`, `f (Just x) =`). A binding position
    /// must be irrefutable: it binds *every* value of its type and never
    /// discriminates. Rejecting it here — before lowering — makes a
    /// runtime match-failure on a well-typed program unrepresentable (no
    /// emitted panic arm, no `DoS`/500 surface). The offending sub-pattern's span
    /// rides on the wrapping [`Diagnostic::Type`]. [IPE-T0015]
    RefutablePatternParameter,
    /// A top-level catch-all (`_` or a bare variable) in a `case` over a FINITE,
    /// CLOSED, user-evolvable union (a `Head::Adt` — a user `type` or a Prelude
    /// built-in like `Maybe` / `Result`) where the catch-all absorbs a
    /// constructor no earlier arm named. Each remaining variant must be handled
    /// explicitly so that adding a new variant forces an update at this match
    /// site instead of falling through silently. (Error.) `Bool`, `List`, and
    /// open domains are excluded by the pass and never produce this diagnostic.
    /// `constructors` names each absorbed variant. [IPE-T0018]
    WildcardCoversKnownConstructors { constructors: SortedNames },
    /// An **or-pattern** `p1 | p2 | …` whose alternatives do not all bind the
    /// **same set of variable names**. The arm body reads a binder without
    /// knowing which alternative matched, so every name it might read must be
    /// bound on every alternative at one type. `names` lists the variables bound
    /// by some but not all alternatives (the name-set difference). Checked
    /// fail-fast in canon, before the
    /// solver runs; the same-name / different-type half rides the standard
    /// [`TypeError::TypeMismatch`] path instead. [IPE-T0019]
    OrPatternBindingMismatch { names: SortedNames },
    /// A `Task` type constructor applied to a number of type arguments other than
    /// 1 (the internal unary form `Task a`) or 2 (the canonical user annotation
    /// `Task Error a`). Reachable from source because canonicalisation validates
    /// arity only for type *aliases* (`NameError::AliasArity`), never for a
    /// non-alias type-constructor application like `Task Error Int Bool` (3 args)
    /// or a bare `Task` (0 args). Converts a former `CompilerBug` ICE into a clean
    /// fail-closed diagnostic naming the found argument count. [IPE-T0016]
    ///
    /// `carrier` is the async-carrier constructor name — `"Task"` (expects 1
    /// or 2 args), `"Cmd"` / `"Sub"` (expect exactly 1) — so the rendered
    /// message names the actual type the user mis-applied, not always `Task`.
    TaskArity { carrier: &'static str, found: usize },
    /// An `Html` value is used where an `Element` is required — most often a
    /// managed-update-loop (`Web.tea`) `view` whose body called
    /// `Ui.layout` / `Ui.layoutWith` (which turn an `Element` into `Html`) when
    /// the shape wanted the inner `Element` and applies the layout itself. The
    /// remedy is the same wherever it arises: wrap the `Html` with `Ui.html`, or
    /// return the `Element`. Emitted for any `Element`/`Html` unification clash,
    /// so the wildcard-`any` view case — which a plain type-mismatch would blame
    /// generically — reads as this tailored, actionable hint. For the view case
    /// this also keeps the SEAL: rejecting it here means the accepted program
    /// still `cargo build`s (the emitted `ui_layout` would otherwise reject an
    /// `Html` where it wants an `Element`, E0308). [IPE-T0020]
    WebViewReturnsHtml,
}

/// How `main`'s inadmissible return type should be named in the
/// [`LowerError::NonEntryMain`] message.
///
/// `Bare` carries a single type-name identifier (`"Int"`, `"String"`, …) that
/// the renderer will article-wrap: `an_article("Int")` → `` an `Int` ``.
/// `Phrase` carries a complete noun phrase that already contains backticks
/// (the catch-all "value that is not a `` `Task` ``"); the renderer emits it
/// verbatim — no article, no extra backticks.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum MainRetName {
    /// A bare type identifier: wrap with an article and backticks.
    Bare(&'static str),
    /// A complete noun phrase with embedded backticks: emit verbatim.
    Phrase(&'static str),
}

/// A language feature that the Milestone-0 lowerer does not yet support. Each
/// maps to an `IPE-L01##` code; the `[feature: …]` tag matches the spec.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Feature {
    /// Wildcard/variable/literal patterns. [IPE-L0100]
    CasePatternKinds,
    /// Binary operators other than `+`/`-`. [IPE-L0101]
    BinOps,
    /// A value whose type stays fully polymorphic — the solver never pinned it
    /// to a concrete instance, so the lowerer cannot monomorphise it (the
    /// backend emits generic *functions*, but cannot yet represent an
    /// under-determined polymorphic *value*). [IPE-L0102]
    Polymorphism,
    /// Function types in argument/return position of a value annotation. [IPE-L0103]
    HigherOrderValues,
    /// Task types other than `Task ()`. [IPE-L0104]
    TaskResults,
    /// Non-variable function parameters. [IPE-L0105]
    ParamPatterns,
    /// Unannotated top-level functions with parameters. [IPE-L0106]
    UntypedFunctions,
    /// Bare function references / non-name callees. [IPE-L0107]
    FirstClassFunctions,
    /// Kernel calls beyond the supported set. [IPE-L0108]
    Kernels,
    /// A call whose argument count differs from the callee's declared arity:
    /// partial application (`add 2` where `add` takes two) or over-application
    /// across the arity boundary (`f 1 2` where `f` takes one). [IPE-L0110]
    PartialOverApplication,
    /// A functional update `{ r | … }` on a record whose type is generic (a field
    /// typed by a type variable). The backend copies the base record with
    /// `.clone()`, which needs the type parameter to be `Clone`-bounded —
    /// bounded generics are unsupported, so this is a not-yet gap rather than
    /// broken Rust. Field access + construction on generic records DO work.
    /// [IPE-L0111]
    BoundedRecordUpdate,
    /// A RECORD sub-pattern nested inside a constructor payload or a tuple
    /// element (`Just { x }`, `( { x }, y )`). The lowerer handles nested
    /// variable / wildcard / constructor / tuple sub-patterns, and a record pattern at the
    /// `case` scrutinee or a `let` destructure — but a record pattern in a
    /// nested carrier needs that carrier's record type threaded to the lowerer,
    /// which lands later. The plain nested shapes (`Just (a, b)`,
    /// `Node (Node …) x r`) are accepted; only the nested-record carrier is
    /// gated here. [IPE-L0112]
    NestedPayloadPatterns,
    /// An `as`-alias in a REFUTABLE match-arm position whose inner pattern
    /// itself needs Rust-level runtime dispatch (a nested constructor,
    /// literal, or list/cons pattern anywhere) — `Just ((Ok x) as w)`. The
    /// common alias shape (`(a, b) as w`, dispatch-free) is fully supported;
    /// only a dispatch-NEEDING inner is gated here, because honoring it
    /// soundly by value would double-move a non-`Copy` payload
    /// and honoring it by reference would require matching the
    /// whole arm by reference — a materially larger redesign. [IPE-L0128]
    AliasOverRefutablePayload,
    /// A routed `Web.tea` (Model with a `page` field + `routes`) compiled
    /// with `--target wasm`. The browser client runs the single-page loop
    /// today; the client-side router is a staged follow-up. [IPE-L0129]
    WasmRoutedApp,
    /// A data constructor named as a first-class function *value* — referenced
    /// bare (`map Just xs`) or partially applied (`Node l 1` for a three-field
    /// `Node`). The lowerer handles a *saturated* construction (`Just 5`, `Node l 1 r`);
    /// constructor-as-function awaits the same first-class-value machinery as a
    /// partially-applied top-level function. [IPE-L0113]
    CtorAsFunction,
    /// A function value stored in a CONSTRUCTOR PAYLOAD — declared
    /// (`type Box = Mk (Int -> Int)`) or laundered there through a type variable
    /// (`type Box a = Mk a` applied as `Mk (\n -> n + 1)`). The generated Rust
    /// enum derives `Clone`/`Debug`/`PartialEq` + `IpeStringify`, none of which a
    /// `Box<dyn Fn>` payload field satisfies, so accepting it would emit
    /// cargo-failing Rust. The sibling of [`Self::FirstClassFunctions`] (a
    /// function in a *record* field), split out so the message names the
    /// constructor-payload carrier and blames the construction site. [IPE-L0114]
    CtorPayloadFunction,
    /// A tuple pattern used in a position the lowerer cannot yet handle: a
    /// `case` on a tuple with MORE THAN ONE arm (needs product/literal-pattern
    /// exhaustiveness), or a tuple destructure binder (a single-arm tuple `case`
    /// or a tuple function parameter) whose element is REFUTABLE — a constructor
    /// or literal — so the binding could fail at run time. The lowerer supports
    /// a single irrefutable tuple destructure (elements are variables / wildcards /
    /// nested irrefutable tuples); the richer shapes land later. [IPE-L0115]
    TuplePatternMatch,
    /// A refutable pattern-discrimination shape the lowerer cannot yet route to
    /// a Rust `match`. Several `case` arms head-matching the same CONSTRUCTOR and
    /// discriminating on their nested sub-patterns (`Som (Som x)` then `Som Non`
    /// then `Non`) ARE supported — each arm lowers one-to-one to a Rust arm in
    /// source order. This gate is reserved for the discrimination shapes that
    /// still lack their carrier: cons / list patterns and guarded arms. The
    /// exhaustiveness checker validates the `case` first (a non-exhaustive one is
    /// IPE-T0010), so an unsupported shape reaching here is gated cleanly rather
    /// than mis-lowered. [IPE-L0116]
    NestedCtorDiscrimination,
    /// A `Set Float` or `Dict Float v`. Ipê's `Float` is `comparable`, so the
    /// type checker accepts it (the typing follows Ipê); but the Rust backings
    /// — `BTreeSet<f64>` / `HashMap<f64, V>` — cannot exist, because `f64`
    /// implements neither `Ord` (no total order: NaN) nor `Hash` / `Eq`. This
    /// is a deliberate backend divergence, not an unimplemented feature: a
    /// `Float`-keyed collection has no sound Rust representation in the standard
    /// library, so it is rejected here at lowering rather than emitting Rust
    /// `cargo` rejects. Divergence from Ipê, rationale: Rust backend capability.
    /// [IPE-L0117]
    FloatKeyedCollection,
    /// `Web.appRouted` (the URL-routing variant of the `Ipe.Web` entry point)
    /// is not yet wired on the Rust backend. Use the non-routed `Web.tea` with
    /// `init`/`update`/`view`/`subscriptions` until routing support lands.
    /// [IPE-L0118]
    RoutedWebApp,
    /// The cfg record for an app entry point (`Web.tea` / `Tui.tea`
    /// / `Cli.tea`) was written as a let-bound
    /// variable (or any non-record expression) rather than an inline record
    /// literal. The Rust backend reads the cfg's field expressions directly at
    /// the call site to emit the runtime entry call, so a non-literal cfg has no
    /// fields to read. Inline the record until non-literal cfg lowering lands.
    /// [IPE-L0119]
    LetBoundAppCfg,
    /// A function/task/decoder value captured by a closure can only be
    /// called, not forwarded; bind the result outside the closure or wrap
    /// the forwarding in a named top-level function. [IPE-L0125]
    NonCloneCapture,
    /// A binding whose type embeds a function (a bare function value, or one
    /// held inside a `Maybe`/`Result`/user-union payload) was used more
    /// than once in a value-consuming (non-callee) position. `Box<dyn Fn>` is
    /// not `Clone`, so a second consuming use would double-move in the
    /// emitted Rust (E0382). Calling the function is unlimited (a call
    /// borrows, never moves); only a second non-call use is rejected. A
    /// narrow, conservative gate — superseded once a general last-use clone
    /// pass (an extension of [`Self::NonCloneCapture`]'s analysis) lands.
    /// [IPE-L0127]
    FunctionValueReuse,
    /// A foreign opaque handle bound from an FFI crate (`Rust.*` interface) was
    /// used more than once in a value-consuming position. The handle is the real
    /// foreign Rust type, which need not be `Clone` (e.g. `bevy_ecs::World`), so
    /// the multi-use `.clone()` the backend would insert may not compile. Fails
    /// closed here rather than emitting a `cargo`-rejecting clone. Thread the
    /// handle linearly (use a receiver-returning method, then read it once at the
    /// end) until borrow-threaded FFI receivers land. [IPE-L0130]
    ForeignHandleReuse,
    /// A row-polymorphic record annotation `{ r | f : T }` in a position with no
    /// backend emission. An argument-position open row of one or more
    /// closed-typed fields IS emittable — it erases to a rustc generic bounded by
    /// one field-witness trait per field, monomorphised per call-site shape. This
    /// feature gates the forms that have no emission yet: an open row in return
    /// position, nested under a container / record / tuple, or one whose field
    /// type itself embeds an open row. Use a closed record annotation, or drop
    /// the annotation and let the parameter's shape be inferred at its call site,
    /// until each such form lands. [IPE-L0131]
    RowPolyRecordAnnotation,
    /// A `Js.send` payload or a `Js.subscribe` decoder crossed the Ipê↔JS port
    /// seam with a type that is NOT seal-legal: a `Secret` or reserved-sink type
    /// (a secret must never be serialised to JS), an untyped `Value`/`Json` (the
    /// untyped channel cannot be spelled — name the payload with a declared ADT
    /// instead), a function, an effect carrier, or another non-plain value. The
    /// crossing value must be a plain, closed, concrete value type, exactly the
    /// seal the `CustomElement down up` boundary enforces. Fail closed here rather
    /// than serialise a value the boundary cannot prove safe. [IPE-L0148]
    JsPortBoundarySeal,
    /// A collection element that embeds a function reached a collection kernel
    /// that cannot represent it: an equality-/ordering-requiring kernel
    /// (`List.member` / `List.sort` / `List.unique` / `List.maximum` /
    /// `List.minimum`), or a higher-order kernel whose mapper/comparator frontier
    /// is not yet function-aware (`List.partition` / `List.map2`…`5` / `Dict.map`
    /// / `Dict.foldl`/`foldr` / `Dict.filter` / `Dict.partition`). A stored
    /// function value is carried on the `Clone` `Arc<dyn Fn>` carrier, so it CAN
    /// live in a `List`/`Dict` value and flow through the frontier-closed
    /// `List.map` family; but the equality/ordering kernels have no comparison for
    /// it, and the open-frontier kernels would pass it to a `Box`-carrier closure
    /// parameter (`Arc`-vs-`Box` mismatch). Rejected here at lowering — the
    /// element capability audit (`StdlibKernel::element_capability`) forbids these
    /// kernels over a function element — rather than emitting Rust `cargo`
    /// rejects. [IPE-L0134]
    FunctionElementEquality,
    /// A binding whose type is not `Clone` — a `Task`/`Cmd`/`Sub` effect value,
    /// bare or inside a `Maybe`/`Result`/tuple/record/user-union payload — was
    /// used more than once in a value-consuming position. A generic union
    /// derives `Clone where T: Clone`, but the concrete payload here is a
    /// `Task`/`Cmd`/`Sub` (an opaque boxed future — never `Clone`), so the
    /// value-reuse rewrite has no sound `.clone()` to insert: a second consuming
    /// use would double-move in the emitted Rust (E0382 / E0277). Sibling to
    /// [`Self::ForeignHandleReuse`] (an FFI foreign handle) and
    /// [`Self::FunctionValueReuse`] (an embedded function value) — the same
    /// non-`Clone`-reuse SEAL, for the effect-carrier payload those two do not
    /// cover. Thread the value linearly (use it once) instead. [IPE-L0135]
    NonCloneValueReuse,
}

/// The app shape whose entry point rejected an inadmissible Model. Drives the
/// required-trait wording rendered for [`LowerError::InadmissibleAppModel`].
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum AppShape {
    /// `Ipe.Web` — the Model is persisted to the session store, so
    /// it must be `serde`-serialisable (as well as `Clone` + `PartialEq`).
    Web,
    /// `Ipe.Tea.Tui` — the full-screen terminal app form. The Model is kept in
    /// memory, so it must be `Clone`. Folds onto the `Terminal` canonical shape.
    Tui,
    /// `Ipe.WebView` — the Model is kept in memory, so it must
    /// be `Clone`.
    WebView,
    /// `Ipe.Tea.Cli` — the line-oriented terminal app form. The Model is kept in
    /// memory, so it must be `Clone`. Folds onto the `Terminal` canonical shape.
    Cli,
}

/// The category of the non-admissible payload found inside a Model.
///
/// The leaf whose rendered Rust type lacks the trait the app entry requires. The
/// renderer owns the exact wording; this enum keeps the presentation-free
/// classification.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum ModelLeaf {
    /// A first-class function (`a -> b`).
    Function,
    /// A `Cmd` command.
    Command,
    /// A `Sub` subscription.
    Subscription,
    /// A `Task` effect.
    Task,
    /// A JSON `Decoder`.
    Decoder,
    /// An opaque `Db` / server / live request or response handle.
    Handle,
    /// A view value — `Html` / `Element` / a UI `Attribute` / a `Color` or other
    /// `Ipe.Ui` plain value. Clonable and comparable, but not serialisable; only
    /// reachable as the offending leaf for a `Ipe.Web` Model.
    ViewValue,
}

/// Errors raised during lowering / emission: "not supported yet" or
/// "inadmissible for the target" — distinct from `CompilerBug` ("the compiler is
/// broken").
///
/// Not `Copy`: [`LowerError::InadmissibleAppModel`] carries an owned field name.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum LowerError {
    /// A feature the lowerer does not implement. [IPE-L01##]
    Unsupported(Feature),
    /// A `Web`/`Terminal`/`WebView` app-entry Model type whose Rust rendering
    /// does not satisfy the runtime bound the entry requires (`Web` needs
    /// `serde::Serialize + serde::de::DeserializeOwned + Clone + PartialEq`;
    /// `Terminal`/`WebView` need `Clone`). `app` drives the wording, `field` names the
    /// offending Model field (empty when the Model is not a record), and `leaf`
    /// categorises the payload. Converts a would-be `cargo` trait-bound failure
    /// into a fail-closed `ipe` error. [IPE-L0120]
    InadmissibleAppModel {
        app: AppShape,
        field: Box<str>,
        leaf: ModelLeaf,
    },
    /// A `Web`/`Terminal`/`WebView` app-entry Msg type whose Rust rendering does
    /// not satisfy the runtime bound the entry requires (`Web`/`Terminal`/`WebView`
    /// all need `Clone + Send + 'static`; `Web` additionally needs `Sync +
    /// Debug`). The predicate used is `ir_type_is_derivable` (NOT serde), so
    /// `Html`/`Element`/`Color`-carrying Msg variants are accepted (they derive
    /// `Clone + Debug + PartialEq`). Converts a would-be `cargo` trait-bound
    /// failure into a fail-closed `ipe` error. [IPE-L0125]
    InadmissibleAppMsg {
        app: AppShape,
        field: Box<str>,
        leaf: ModelLeaf,
    },
    /// Expression nesting exceeded the backend's bounded emit depth. [IPE-L0200]
    BackendNestingTooDeep { limit: u16 },
    /// `JsonDec.succeed` / `Db.Decode.succeed` constructor has more than 10
    /// parameters, which exceeds the `curry1`..`curry10` helpers in the runtime.
    /// [IPE-L0121]
    DecodeSucceedArityTooHigh { n: usize },
    /// A `Web.route` pattern has a different number of `:param` segments than
    /// the page-constructor has payload fields. The extra params would be
    /// silently discarded or the constructor could never be fully applied.
    /// [IPE-L0122]
    RouteParamCountMismatch {
        /// The URL pattern string (e.g. `"/apps/:id/:slug"`).
        pattern: Box<str>,
        /// How many `:param` segments the pattern contains.
        param_count: usize,
        /// How many payload fields the page constructor declares.
        ctor_payload_count: usize,
    },
    /// A `Web.route` page builder is not a page constructor, inline lambda, or
    /// named function — the Rust backend cannot emit a type-directed params
    /// closure for a let-bound variable or computed expression. [IPE-L0123]
    RouteBuilderUnsupportedShape,
    /// A `Web.route` page-constructor payload field has a type that cannot be
    /// decoded from a URL `:param` string (only `String`, `Int`, `Float`, and
    /// `Bool` are supported). [IPE-L0123]
    RouteParamUnsupportedType {
        /// Zero-based index of the offending constructor payload field.
        field_index: usize,
        /// Short display name of the unsupported IR type.
        type_name: Box<str>,
    },
    /// A development-only `Debug.*` escape hatch — a `Debug.log` / `Debug.todo`
    /// / `Debug.explain` call OR a `Debug._` catch-all pattern — was used in an
    /// `ipe release` build. Debug constructs are for local inspection only; a
    /// release build rejects them rather than silently stripping the call,
    /// shipping a stray stderr write, or letting an unhandled variant fall
    /// through a dev-only catch-all. [IPE-L0140]
    DevOnlyKernelInProduction {
        /// The dotted family name reported to the user (`Debug.*`).
        kernel: Box<str>,
    },
    /// A committed source-text string LITERAL reached a `Secret`-typed
    /// position (e.g. `Secret.fromString "sk_live_…"` or a `Secret` field /
    /// argument set to a literal). A secret must not be baked into source: the
    /// recommended source is `App.fromEnvRequired "VAR"` (read at runtime), or
    /// sealing a `String` the program obtained at runtime. Carries no payload —
    /// the diagnostic must never echo the literal text. A runtime `String`
    /// reaching the same position is fine; only a literal is refused. The
    /// SECURITY-tier fail-closed gate converts a would-be committed-credential
    /// leak into an ipe-time error. [IPE-L0150]
    SecretFromStringLiteral,
    /// `Secret.fromString` was referenced without being fully applied — passed
    /// as a value (`List.map Secret.fromString …`), let-bound (`seal =
    /// Secret.fromString`), or otherwise used point-free. The committed-literal
    /// seal gate ([`Self::SecretFromStringLiteral`]) inspects the ARGUMENT of a
    /// saturated call; an un-applied reference routes around it (the argument is
    /// supplied later, out of the gate's sight), reopening the committed-secret
    /// leak. `Secret.fromString` is therefore legal only as a direct
    /// one-argument call, so every argument is seen. Carries no payload. The
    /// SECURITY-tier fail-closed gate makes the seal structural: every path into
    /// a `Secret` flows through the argument check. [IPE-L0151]
    SecretFromStringUnapplied,
    /// `Ui.cells` (a raw terminal cell grid) appears in a `Web`/`WebView`
    /// program. It paints directly to the terminal and has no denotation in a
    /// browser view, so it is admissible only under the `Terminal` shape
    /// (`Tui.tea` / `Cli.tea`). The carried [`AppShape`] is
    /// the web-family shape that rejected it — the SECURITY-tier fail-closed
    /// gate converts a would-be wrong-render into an ipe-time error. [IPE-L0132]
    UiCellsInWebShape(AppShape),
    /// `Ui.cells` (a raw terminal cell grid) appears in a `Cli`
    /// (`Cli.tea`) program. A Cli view returns `String` (line I/O),
    /// so a `Cells` grid has no string denotation. Rejected at ipe time.
    /// [IPE-L0153]
    UiCellsInCliShape(AppShape),
    /// `CustomElement.node` (a server-driven custom element) appears outside a browser
    /// shape. Its up-event handler is carried over the seal codec, which is
    /// present only when the `json` runtime feature is on — and only the browser
    /// shape (`Web.tea`) forces it. Under `Terminal` / `Program`
    /// the widget has no transport for its handler, so the node would be inert
    /// (a widget with no seam). The SECURITY-tier fail-closed gate converts that
    /// would-be dead element into an ipe-time refusal rather than emit a crate
    /// whose non-`json` runtime fallback leaves the up-event type parameter
    /// unconstrained (rustc E0282). Admissible only under `Web` / `WebView`.
    /// [IPE-L0147]
    UiWidgetInNonWebShape,
    /// A `Task`-typed value was discarded as `let _ = <task>` inside a
    /// non-`Task` context (a function whose return type is not itself a
    /// `Task`). Emitting this discard would run the effect through an implicit
    /// `task_run`, so a plainly-typed function (e.g. `String -> String`) would
    /// silently perform I/O — an effect escaping the `Task` discipline every
    /// other effect obeys. A `Task` runs only through `Task.run`, or by being
    /// sequenced inside a `Task`-returning function. [IPE-L0141]
    LawlessEffectDiscard,
    /// `Web.tea` carries a non-empty `routes` list but the Model type has no
    /// `page` field, so the routes are forwarded to the non-routed path and
    /// never update the Model (warning — the program still compiles, matching
    /// the reference's silent no-op). Usually a mis-named routed-page field.
    /// [IPE-L0124]
    RoutedAppMissingPageField {
        /// How many routes were declared.
        route_count: usize,
    },
    /// The program's `main` is not an entry a runnable program can have. A
    /// `main` is the one effect a program runs, so it must be a `Task Error ()`
    /// — either written directly (a script, `main = Io.println "…"`) or produced
    /// by an app entry (`Web.tea`, `Tui.tea`, `Cli.tea`, whose
    /// result is itself a `Task Error ()`). A `main` of any other type (an
    /// `Int`, a `String`, a function, …) has no effect to run. `found` is a
    /// short, plain-English name for what this `main`'s type is. Fails closed at
    /// `ipe` time — the emitted entry wraps `main` in the runtime's single run
    /// site, which needs a `Task`, so a non-`Task` `main` would otherwise ship a
    /// crate that cannot build. [IPE-L0136]
    NonEntryMain { found: MainRetName },
    /// A wildcard `any` in the RETURN type of a signature contributes a generic
    /// that no parameter type carries and the body does not pin to a concrete
    /// type. A wildcard `any` promises exactly one concrete type per position,
    /// so it must be *determinable* — read off the body, or shared with a
    /// parameter a caller supplies. A return-only `any` is determinable by
    /// neither: the emitted function would carry a type parameter that appears
    /// only in its result, which no call site can fix. Rejected fail-closed at
    /// `ipe` time rather than emitting Rust a caller can never satisfy.
    /// [IPE-L0142]
    UndeterminableReturnAny,
    /// A call site passes a record whose field type does not match the type the
    /// callee's body requires for that field. The callee's parameter is a
    /// wildcard `any` that the body reads as a record field — the body's solved
    /// region type pins the required field type to a concrete `IrType`, which
    /// the backend emits as an associated-type witness bound
    /// (`IpeHas<field><Name = required_ty>`). Because `any` severs caller-callee
    /// type-checker unification, a caller whose field has a different concrete
    /// type is accepted by the type checker but emits Rust that fails cargo with
    /// E0271 (`<RecName as IpeHas<field>>::Name == required_ty` unsatisfied).
    /// Rejected fail-closed here at lowering time. [IPE-L0143]
    WildcardAnyFieldTypeMismatch {
        /// The record field whose type mismatches (e.g. `"name"`).
        field: Box<str>,
        /// The type the callee's body requires for that field (e.g. `"String"`).
        required: Box<str>,
        /// The type the caller's record actually provides (e.g. `"Bool"`).
        found: Box<str>,
    },
    /// A non-record value is passed at a row-generic parameter position. The
    /// callee's parameter is a wildcard `any` whose body reads record fields,
    /// so the backend emits `IpeHas*` witness bounds on that parameter. Only a
    /// record type can carry those bounds; any other concrete type (`Int`,
    /// `Bool`, `String`, a custom ADT, …) causes the emitted Rust to fail cargo
    /// with `error[E0277]`. Because the type checker accepts the call (wildcard
    /// `any` severs caller-callee unification), this is caught fail-closed at
    /// lowering time. [IPE-L0144]
    WildcardAnyArgNotRecord {
        /// A short, plain-English name for the type the caller actually passed
        /// (e.g. `"Int"`, `"Bool"`).
        found: Box<str>,
    },
    /// A `Store.eq` / `Store.eqBy` column argument is not a usable field
    /// accessor. The typed query leaf reads its column from a bare `.field`
    /// accessor at lowering; the argument fell outside that shape. [IPE-L0145]
    StoreEqAccessorInvalid(StoreEqAccessorDefect),
    /// A `Store.select` projection lambda is not a lowerable column projection.
    /// The typed projection reads each column from a bare `cols.field` reference
    /// over one of the two bound side records at lowering; the lambda body fell
    /// outside that shape. [IPE-L0149]
    StoreSelectProjectionInvalid(StoreSelectProjectionDefect),
    /// An accessor-typed `Store.*` query leaf or column-spec builder
    /// (`Store.eq`, `Store.gt`, `Store.serial`, `Store.primaryKey`, …) was used
    /// point-free / partially applied, rather than applied directly with its
    /// accessor and value. These leaves have no runtime function: the lowering
    /// accessor-intercept rewrites the SATURATED call inline (the `.field`
    /// accessor becomes the validated column). A partial application routes
    /// through eta-expansion, which would emit the never-defined placeholder
    /// symbol (`store_eq_col`, `store_serial`, …) — accepted by the frontend
    /// but a `cargo` E0425. Rejected fail-closed here so the invariant holds:
    /// `ipe` accepts ⇒ the emitted Rust builds. `kernel` is the dotted name
    /// (e.g. `Store.eq`). [IPE-L0146]
    PointFreeAccessorKernel {
        /// The dotted kernel name that was partially applied (e.g. `Store.eq`).
        kernel: Box<str>,
    },
}

/// Why a `Store.eq` / `Store.eqBy` column argument was rejected at lowering.
/// Each variant names one fail-closed cause under [IPE-L0145].
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum StoreEqAccessorDefect {
    /// The column argument is not a bare field accessor (`.field`) — a
    /// let-bound name, a multi-statement lambda, a non-field body, etc.
    NotAnAccessor,
    /// The accessor names a field the row type does not have. `field` is the
    /// field name the accessor read.
    UnknownField {
        /// The field the accessor referenced.
        field: Box<str>,
    },
    /// Plain `eq` requires a scalar field type (`String` / `Int` / `Bool` /
    /// `Float`); this field is an enum, newtype, or other non-scalar. `field`
    /// names it; `found` is a short name for its type. Use `eqBy` with the
    /// field's codec.
    NonScalarField {
        /// The field whose type is not a scalar.
        field: Box<str>,
        /// A short, plain-English name for that field's type.
        found: Box<str>,
    },
    /// The column name derived from the accessor is not a valid SQL identifier.
    /// `column` is the offending name.
    InvalidColumn {
        /// The derived column name that failed the identifier charset gate.
        column: Box<str>,
    },
}

/// Why a `Store.select` projection lambda was rejected at lowering. Each variant
/// names one fail-closed cause under [IPE-L0149].
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum StoreSelectProjectionDefect {
    /// The projection lambda is not the expected `\( colsA, colsB ) -> body`
    /// shape (a two-binder tuple parameter over a projection body).
    NotAProjectionLambda,
    /// The projection body is not a single `cols.field` column reference over
    /// one of the two bound side records, nor a tuple whose every element is such
    /// a reference. A computed value, a literal, or a reference to something other
    /// than a bound side record takes this cause.
    UnsupportedProjectionBody,
    /// A projected tuple element is itself a tuple. A multi-column projection is
    /// a flat tuple of `side.field` references; nesting is not a column shape.
    NestedProjectionTuple,
    /// The projection references a field absent from the side's row type.
    /// `field` is the field name the projection read.
    UnknownField {
        /// The field the projection referenced.
        field: Box<str>,
    },
    /// The column name derived from the projected field is not a valid SQL
    /// identifier. `column` is the offending name.
    InvalidColumn {
        /// The derived column name that failed the identifier charset gate.
        column: Box<str>,
    },
    /// A `Store.literal` element's argument type is not one of the four scalar
    /// types the projection layer can read back (String / Int / Bool / Float).
    /// `ty` is a short human-readable label for the unsupported type.
    LiteralTypeUnsupported {
        /// Short human-readable Ipê type label for the unsupported type.
        ty: Box<str>,
    },
}

// ===========================================================================
// FFI / sandbox / consent payload types (canonical home; producer crates
// re-export from here so a single representation exists).
// ===========================================================================

/// The closed defect payload for FFI-generator diagnostics (`IPE-F44xx`).
///
/// Each variant names exactly one taxonomy code. Producer crates construct
/// these and convert them to [`Diagnostic::Ffi`]; the shared renderer is the
/// only place that turns a `FfiError` into bytes.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum FfiError {
    /// `IPE-F4400` — a foreign-call AST failed a structural check that makes
    /// rendering total; refused before emission.
    CallUnrenderable {
        /// The wrapper-reference name of the function whose call was refused.
        function: String,
        /// A short description of which structural check failed.
        detail: String,
    },
    /// `IPE-F4400` — a generic FFI call site (or its binding) cannot be
    /// soundly bound; the instantiation falls outside the closed bindable set.
    GenericNotBindable {
        /// The qualified Ipê callee.
        callee: String,
        /// A short description of which bindability rule was broken.
        detail: String,
    },
    /// `IPE-F4401` — inspector wire data carried a value outside its closed
    /// legal set.
    WireMalformed {
        /// Where in the wire document the defect was met.
        context: String,
        /// A short description of which wire rule was broken.
        detail: String,
    },
    /// `IPE-F4402` — a function's shape flags are contradictory.
    ShapeContradiction {
        /// The function whose flags contradict.
        function: String,
        /// The flag names that were simultaneously set.
        flags: Vec<String>,
    },
    /// `IPE-F4411` — an untrusted crate source was rejected at the driver
    /// gate.
    SourceRejected {
        /// The offending input, verbatim.
        source: String,
        /// A short description of which gate rule was broken.
        detail: String,
    },
    /// `IPE-F4412` — an FFI cache artifact could not be read, written, or
    /// removed.
    ArtifactIo {
        /// The artifact path.
        path: String,
        /// The rendered OS error.
        detail: String,
    },
    /// `IPE-F4414` — an author-asserted foreign call (`Rust.Ffi.call`) was
    /// refused at validation.
    AssertedRefused {
        /// The asserted Rust path, verbatim.
        path: String,
        /// A short description of which rule refused it.
        detail: String,
    },
    /// `IPE-F4415` — the inspector's build failed because a required system
    /// library is not installed on the host.
    SystemLibraryNotFound {
        /// The `pkg-config` library name that was not found.
        system_lib: String,
        /// The Rust crate whose `build.rs` required the library.
        crate_name: String,
        /// A short OS-aware install hint.
        install_hint: String,
    },
}

/// The closed defect payload for sandbox diagnostics (`IPE-F441x`).
///
/// Covers both the build-jail (`IPE-F4410`, produced by `ipe_sandbox`) and
/// the run-jail (`IPE-F4413`, produced by `ipe_sandbox::run_jail`). Producer
/// crates convert these to [`Diagnostic::Sandbox`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum SandboxError {
    /// `IPE-F4410` — no isolation jail could be established for compiling an
    /// untrusted crate (bubblewrap absent, cap helpers absent, spawn failed,
    /// or output cap exceeded).
    BuildJail {
        /// A short description of why the jail could not be established.
        detail: String,
    },
    /// `IPE-F4413` — no runtime jail could be established around the emitted
    /// app, or a jailed run failed.
    RunJail {
        /// A short description of why the jail could not be established or
        /// the run failed.
        detail: String,
    },
}

/// The payload for the unsafe-escape-hatch consent gate (`IPE-S0001`).
///
/// Produced by the CLI acknowledgment layer; converted to
/// [`Diagnostic::Consent`] so the shared renderer handles the message.
///
/// `body` is the pre-formatted per-module risk disclosure assembled by the
/// CLI (which knows the module vocabulary); the renderer folds it into the
/// prose band unchanged. This keeps module-specific risk wording in the CLI
/// (where it belongs) while routing the final output through the single
/// shared renderer.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ConsentError {
    /// Non-interactive build with no pre-recorded consent: fail closed.
    NonInteractive {
        /// The pre-formatted risk disclosure (which modules, what risk).
        body: String,
    },
    /// Interactive terminal: the user typed something other than `y`.
    InteractiveDenied {
        /// The pre-formatted risk disclosure (which modules, what risk).
        body: String,
    },
}

// ===========================================================================
// The diagnostic currency
// ===========================================================================

/// The single typed error currency of the compiler.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Diagnostic {
    Parse {
        span: Span,
        msg: ParseError,
    },
    Name {
        span: Span,
        msg: NameError,
    },
    Type {
        span: Span,
        msg: TypeError,
    },
    /// A feature that is not supported yet (distinct from a compiler bug).
    Lower {
        span: Span,
        msg: LowerError,
    },
    /// A violated internal invariant — illegal IR, missing region type, etc.
    /// `where_` names the stage; `detail` is the only free-form message.
    CompilerBug {
        where_: &'static str,
        detail: String,
    },
    /// An FFI-generator failure (`IPE-F44xx`). Span-free: the defect is in
    /// the foreign binding, not in a user source location.
    Ffi {
        msg: FfiError,
    },
    /// A sandbox establishment or run failure (`IPE-F4410` / `IPE-F4413`).
    /// Span-free: the defect is in the host environment, not in the source.
    Sandbox {
        msg: SandboxError,
    },
    /// The unsafe-escape-hatch consent gate refused (`IPE-S0001`). Span-free:
    /// the refusal is at build/run invocation time, not at a source location.
    Consent {
        msg: ConsentError,
    },
    /// The crate registry could not be reached while building the emitted crate
    /// (`IPE-E0001`). Span-free: the defect is in the host environment (network
    /// or DNS), not in the user's source.
    RegistryUnreachable {
        /// The cargo stderr detail, trimmed, for display.
        detail: String,
    },
}

/// Result alias used throughout the compiler.
pub type DResult<T> = Result<T, Diagnostic>;

// ===========================================================================
// Help lines (structured, payload-derived)
// ===========================================================================

/// The role a secondary span plays in a diagnostic.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum SpanRole {
    /// The earlier of two conflicting definitions.
    FirstDefinition,
    /// The opening delimiter of an unclosed group.
    Opener,
    /// The definition that fixed an inferred type.
    Definition,
}

/// A fixed, payload-free guidance line. Keeping these as an enum (not a
/// `String`) preserves the no-stringly-typed-channel invariant; the renderer
/// owns the wording.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Hint {
    /// Show the canonical module header `module Main exposing (main)`.
    ModuleHeaderExample,
    /// Suggest `..` or `Module.name` for a stray dot.
    UseDotDotOrQualified,
    /// Name both readings of a space before `.` and point to the field-access
    /// fix (remove the space); the accessor-function reading is unsupported.
    RemoveSpaceBeforeDot,
    /// Suggest separating a number and a name with a space.
    SeparateWithSpace,
    /// State the `i64` integer-literal range.
    IntegerLiteralRange,
    /// State the `f64` float-literal magnitude limit.
    FloatLiteralRange,
    /// Suggest adding a top-level type signature.
    AddTypeSignature,
    /// Explain how to raise the solver budget via `IPE_SOLVER_BUDGET`.
    RaiseSolverBudget,
    /// Explain that a nesting bound is deliberate (fail-fast).
    NestingBoundDeliberate,
    /// List the forms a type atom can take.
    TypeAtomForms,
    /// State that constructors must be uppercase.
    ConstructorMustBeUppercase,
    /// State that a feature is not supported yet (carries the feature).
    FeatureNotSupported(Feature),
    /// Explain that a parameter pattern must be irrefutable and suggest binding
    /// the whole value and using `case` (IPE-T0015).
    IrrefutableParameterRequired,
}

/// How confidently a [`Suggestion`] can be applied to source, mirroring rustc's
/// model. Governs whether `ipe fix` may auto-apply the edit.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Applicability {
    /// The replacement is correct and self-contained; eligible for auto-patch.
    MachineApplicable,
    /// The replacement is a best guess that may not be what the author meant.
    MaybeIncorrect,
    /// The replacement still contains placeholders the author must fill in.
    HasPlaceholders,
}

/// A typed, span-scoped source edit the compiler proposes as a fix.
///
/// The span is the region to replace; `replacement` is the literal text to write
/// there. Only [`Applicability::MachineApplicable`] suggestions are auto-applied;
/// the others are shown but require explicit per-edit confirmation.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Suggestion {
    /// The source region the edit replaces.
    pub span: Span,
    /// The literal text to substitute for the region.
    pub replacement: Box<str>,
    /// How safe the edit is to apply automatically.
    pub applicability: Applicability,
}

/// One line of help under a diagnostic. Names are carried as owned `Box<str>`;
/// everything else is a POD enum, so help text is rendered from data.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum HelpLine {
    /// "did you mean `<name>`?"
    DidYouMean(Box<str>),
    /// A free-form `note:` line whose text is built by the producer. Used when
    /// the message must carry producer-specific detail (e.g. the offending Model
    /// field name for [`LowerError::InadmissibleAppModel`]) and the diagnostic
    /// has no source span to hang a caret label on.
    Note(Box<str>),
    /// A fixed guidance line.
    Hint(Hint),
    /// Point at a related source location.
    SecondarySpan { span: Span, role: SpanRole },
    /// Name a constructor missing from an exhaustive match.
    MissingConstructor(Box<str>),
    /// A concrete, span-scoped fix the reader can apply (and `ipe fix` may
    /// auto-apply when [`Applicability::MachineApplicable`]).
    Suggest(Suggestion),
    /// Nudge toward an `ipe doc <topic>` teaching page.
    ///
    /// The string is either a topic-page name ingested from `docs/topics/` by
    /// `ipe-cli`'s `doc_bundle::ingest_markdown_dir` (e.g. `"effects"`,
    /// `"state"`, `"main"`) or a diagnostic code naming an explain page (e.g.
    /// `"IPE-L0142"`). The renderer appends a hint like `→ run ipe doc <name>`
    /// to the diagnostic's help output. The diagnostics crate carries only the
    /// static string, keeping the dependency direction clean (diagnostics → cli
    /// would be a cycle). A test in this crate asserts every referenced topic
    /// name resolves to a live page under `docs/topics/`.
    SeeExplain(&'static str),
}

// ===========================================================================
// Total accessors
// ===========================================================================

impl Diagnostic {
    /// The stable error code for this diagnostic. Total: every variant — and
    /// every inner enum variant — has an explicit arm.
    #[must_use]
    pub fn code(&self) -> Code {
        match self {
            Self::Parse { msg, .. } => parse_code(msg),
            Self::Name { msg, .. } => name_code(msg),
            Self::Type { msg, .. } => type_code(msg),
            Self::Lower { msg, .. } => lower_code(msg),
            Self::CompilerBug { where_, .. } => bug_code(where_),
            Self::Ffi { msg } => ffi_code(msg),
            Self::Sandbox { msg } => sandbox_code(msg),
            Self::Consent { .. } => IPE_S0001,
            Self::RegistryUnreachable { .. } => IPE_E0001,
        }
    }

    /// The severity of this diagnostic.
    #[must_use]
    pub const fn severity(&self) -> Severity {
        match self {
            Self::Parse {
                msg: ParseError::DocOnUnexported { .. } | ParseError::MissingDocString { .. },
                ..
            }
            // A Script that imports a shape's UI still compiles — the hint is a
            // Warning, never a rejection of a legal Script.
            | Self::Name {
                msg: NameError::ScriptImportsShapeView { .. },
                ..
            } => Severity::Warning,
            Self::Parse { .. }
            | Self::Name { .. }
            | Self::Ffi { .. }
            | Self::Sandbox { .. }
            | Self::Consent { .. }
            | Self::RegistryUnreachable { .. } => Severity::Error,
            Self::Lower { msg, .. } => match msg {
                LowerError::RoutedAppMissingPageField { .. } => Severity::Warning,
                _ => Severity::Error,
            },
            Self::Type { msg, .. } => match msg {
                TypeError::RedundantCaseBranch { .. } => Severity::Warning,
                // A catch-all over a closed, user-evolvable union is an error:
                // it lets a future variant fall through silently. Scoped to
                // `Head::Adt` in the exhaustiveness pass (Bool/List/open types
                // never produce this diagnostic).
                TypeError::WildcardCoversKnownConstructors { .. }
                | TypeError::Mismatch
                | TypeError::BudgetExceeded
                | TypeError::TypeMismatch { .. }
                | TypeError::InfiniteType { .. }
                | TypeError::StepBudgetExceeded { .. }
                | TypeError::TooManyParameters { .. }
                | TypeError::NonExhaustiveCase { .. }
                | TypeError::NoSuchField { .. }
                | TypeError::BuiltinRecordUpdate { .. }
                | TypeError::CtorPatternArity { .. }
                | TypeError::SuperTypeUnsatisfied { .. }
                | TypeError::RefutablePatternParameter
                | TypeError::OrPatternBindingMismatch { .. }
                | TypeError::TaskArity { .. }
                | TypeError::WebViewReturnsHtml => Severity::Error,
            },
            Self::CompilerBug { .. } => Severity::Bug,
        }
    }

    /// The primary source span. Span-free variants (`CompilerBug`, `Ffi`,
    /// `Sandbox`, `Consent`) return [`Span::DUMMY`].
    #[must_use]
    pub const fn primary_span(&self) -> Span {
        match self {
            Self::Parse { span, .. }
            | Self::Name { span, .. }
            | Self::Type { span, .. }
            | Self::Lower { span, .. } => *span,
            Self::CompilerBug { .. }
            | Self::Ffi { .. }
            | Self::Sandbox { .. }
            | Self::Consent { .. }
            | Self::RegistryUnreachable { .. } => Span::DUMMY,
        }
    }

    /// The structured help lines for this diagnostic, derived from its payload.
    /// Total over every variant.
    #[must_use]
    pub fn help(&self) -> Vec<HelpLine> {
        match self {
            Self::Parse { msg, .. } => parse_help(msg),
            Self::Name { msg, span } => name_help(msg, *span),
            Self::Type { msg, .. } => type_help(msg),
            Self::Lower { msg, .. } => lower_help(msg),
            Self::Ffi { msg } => ffi_help(msg),
            Self::Sandbox { msg } => sandbox_help(msg),
            Self::Consent { msg } => consent_help(msg),
            Self::CompilerBug { .. } | Self::RegistryUnreachable { .. } => Vec::new(),
        }
    }
}

// --- code() helpers --------------------------------------------------------
//
// The SEAL invariant (PRINCIPLES: "a diagnostic's code family with its prefix
// letter — assert that agreement at build time so the instant they drift the
// build breaks") is enforced here by routing every arm's returned [`Code`]
// through a family chokepoint. Each `in_<family>` const fn asserts the code's
// [`Code::family`] before returning it, so a mis-filed arm (e.g. a `TypeError`
// mapped to an `IPE-N` code by a one-character typo) makes the chokepoint's
// assertion the reachable outcome — turned back the moment any test or build
// drives that arm, never rendered as a mislabelled diagnostic. The per-producer
// `const _` blocks below force the family chokepoints to be exercised at
// compile time for the representative constant each producer's family owns, so a
// wrong chokepoint wiring (`parse_code` routing through `in_name`) is a build
// error, not a runtime one.

/// A family chokepoint: assert `c` belongs to `f`, then return it unchanged.
///
/// Const so it can gate a `const fn` producer's arms and be evaluated at
/// compile time. `debug_assert` is not enough — the guarantee must hold in
/// release builds too — so this is a hard `assert`; it is unreachable for a
/// correctly-wired arm (the code and its family are the same fact).
const fn in_family(c: Code, f: Family) -> Code {
    // IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); it fails the BUILD if a code's family disagrees with its producer's arm, the code-to-family SEAL invariant PRINCIPLES mandates be build-enforced [ledger #boundary]
    assert!(
        code_family_eq(c.family(), f),
        "diagnostic code family drift: this code does not belong to the producer's family"
    );
    c
}

/// `PartialEq` is not `const`-callable on [`Family`]; this is the const
/// equality the chokepoint needs.
const fn code_family_eq(a: Family, b: Family) -> bool {
    matches!(
        (a, b),
        (Family::Parse, Family::Parse)
            | (Family::Name, Family::Name)
            | (Family::Type, Family::Type)
            | (Family::Lower, Family::Lower)
            | (Family::Ffi, Family::Ffi)
            | (Family::Security, Family::Security)
            | (Family::Environment, Family::Environment)
            | (Family::Internal, Family::Internal)
    )
}

const fn in_parse(c: Code) -> Code {
    in_family(c, Family::Parse)
}
const fn in_name(c: Code) -> Code {
    in_family(c, Family::Name)
}
const fn in_type(c: Code) -> Code {
    in_family(c, Family::Type)
}
const fn in_lower(c: Code) -> Code {
    in_family(c, Family::Lower)
}
const fn in_ffi(c: Code) -> Code {
    in_family(c, Family::Ffi)
}
const fn in_internal(c: Code) -> Code {
    in_family(c, Family::Internal)
}

// Compile-time proof that each producer routes through the chokepoint of its own
// family: these const evaluations run at build time, so a chokepoint wired to
// the wrong family fails the build (not a deletable test). One representative
// constant per family is enough — every arm of a producer goes through the same
// chokepoint, so pinning the chokepoint pins the whole producer.
// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); one conjunction pins every producer to its family at build time (Consent/RegistryUnreachable return their code directly in `code()`, so pin those constants too), so a mis-wired chokepoint is a build error, not a mislabelled diagnostic [ledger #boundary]
const _: () = assert!(
    matches!(parse_code_family().family(), Family::Parse)
        && matches!(name_code_family().family(), Family::Name)
        && matches!(type_code_family().family(), Family::Type)
        && matches!(lower_code_family().family(), Family::Lower)
        && matches!(ffi_code_family().family(), Family::Ffi)
        && matches!(bug_code_family().family(), Family::Internal)
        && matches!(IPE_S0001.family(), Family::Security)
        && matches!(IPE_E0001.family(), Family::Environment),
    "diagnostic code family drift: a producer returns a code outside its family",
);

const fn parse_code_family() -> Code {
    in_parse(IPE_P0001)
}
const fn name_code_family() -> Code {
    in_name(IPE_N0001)
}
const fn type_code_family() -> Code {
    in_type(IPE_T0001)
}
const fn lower_code_family() -> Code {
    in_lower(IPE_L0100)
}
const fn ffi_code_family() -> Code {
    in_ffi(IPE_F4400)
}
const fn bug_code_family() -> Code {
    in_internal(IPE_I0001)
}

const fn parse_code(msg: &ParseError) -> Code {
    in_parse(match msg {
        ParseError::Unexpected | ParseError::UnexpectedToken { .. } => IPE_P0001,
        ParseError::UnexpectedEof { .. } => IPE_P0002,
        ParseError::TooDeep | ParseError::NestingTooDeep { .. } => IPE_P0003,
        ParseError::UnknownChar(_) => IPE_P0010,
        ParseError::StrayDot => IPE_P0011,
        ParseError::SpaceBeforeDot => IPE_P0018,
        ParseError::NumberJoinedToName(_) => IPE_P0012,
        ParseError::IntLiteralOutOfRange => IPE_P0013,
        ParseError::FloatLiteralOutOfRange => IPE_P0016,
        ParseError::UnterminatedString => IPE_P0014,
        ParseError::MalformedChar => IPE_P0015,
        ParseError::UnterminatedBlockComment => IPE_P0017,
        ParseError::MalformedModuleHeader(_) => IPE_P0020,
        ParseError::MalformedExposingList(_) => IPE_P0021,
        ParseError::MissingEquals { .. } => IPE_P0030,
        ParseError::MalformedTypeDeclaration(_) => IPE_P0031,
        ParseError::TypeArgsOnNonConstructor => IPE_P0040,
        ParseError::ExpectedType => IPE_P0041,
        ParseError::UnclosedDelimiter { .. } => IPE_P0050,
        ParseError::MalformedCase(_) => IPE_P0060,
        ParseError::MalformedLet(LetDefect::BareWildcardBinding) => IPE_P0064,
        ParseError::MalformedLet(_) => IPE_P0061,
        ParseError::MalformedIf(_) => IPE_P0062,
        ParseError::InvalidPathLiteral { .. } => IPE_P0063,
        ParseError::SteplessDo => IPE_P0065,
        ParseError::DocOnUnexported { .. } => IPE_P0066,
        ParseError::MissingDocString { .. } => IPE_P0067,
        ParseError::AnnotationWithoutBinding { .. } => IPE_P0068,
        ParseError::DuplicateAnnotation { .. } => IPE_P0069,
        ParseError::SourceTooLarge { .. } => IPE_P0070,
    })
}

const fn name_code(msg: &NameError) -> Code {
    in_name(match msg {
        NameError::Unknown | NameError::ValueNotFound { .. } => IPE_N0001,
        NameError::TypeNotFound { .. } => IPE_N0002,
        NameError::ConstructorNotFound { .. } => IPE_N0003,
        NameError::UnknownModule { .. } => IPE_N0004,
        NameError::StdlibImportRequired { .. } => IPE_N0034,
        NameError::NoSuchMember { .. } => IPE_N0005,
        NameError::DuplicateValue { .. } => IPE_N0010,
        NameError::DuplicateConstructor { .. } => IPE_N0011,
        NameError::DuplicateType { .. } => IPE_N0012,
        NameError::AliasArity { .. } => IPE_N0013,
        NameError::ModuleNotFound { .. } => IPE_N0020,
        NameError::ImportCycle { .. } => IPE_N0021,
        NameError::NameNotExposed { .. } => IPE_N0022,
        NameError::ModulePathMismatch { .. } => IPE_N0023,
        NameError::AmbiguousImport { .. } => IPE_N0024,
        NameError::ReservedNamespace { .. } => IPE_N0025,
        NameError::ReservedBuiltinType { .. } => IPE_N0026,
        NameError::DuplicateQualifier { .. } => IPE_N0027,
        NameError::UnknownKernelAlias { .. } => IPE_N0028,
        NameError::ServerOnlyKernelForWasm { .. } => IPE_N0029,
        NameError::ServerModuleReachableFromWasmClient { .. } => IPE_N0030,
        NameError::BuiltinTypeArity { .. } => IPE_N0031,
        NameError::TypeExpansionTooDeep { .. } => IPE_N0032,
        NameError::ProgramImportsTeaShape { .. } => IPE_N0033,
        NameError::WrongShapeCmdSub(..) => IPE_N0035,
        NameError::RemovedSurface { .. } => IPE_N0036,
        NameError::AssertedCallMalformed { .. } => IPE_N0038,
        NameError::BoundarySealIllegal { .. } => IPE_N0039,
        NameError::NestedDecoderPipeline => IPE_N0040,
        NameError::CodecAutoUnderivable { .. } => IPE_N0041,
        NameError::KernelAliasInUserSource { .. } => IPE_N0042,
        NameError::DiscardedConfig => IPE_N0043,
        NameError::CustomElementCtorMalformed { .. } => IPE_N0044,
        NameError::RuntimeBranchedMain => IPE_N0045,
        NameError::WebInitPolyArg => IPE_N0046,
        NameError::ModuleNotAllowedInPlacement(..) => IPE_N0047,
        NameError::RustNameFold { .. } => IPE_N0048,
        NameError::DuplicatePatternBinder { .. } => IPE_N0049,
        NameError::ScriptImportsShapeView { .. } => IPE_N0050,
        NameError::GenericAppEntry { .. } | NameError::UnpinnedAppEntry { .. } => IPE_N0051,
        NameError::EffectCarrierInDecoder { .. } => IPE_N0052,
    })
}

const fn type_code(msg: &TypeError) -> Code {
    in_type(match msg {
        TypeError::Mismatch | TypeError::TypeMismatch { .. } => IPE_T0001,
        TypeError::InfiniteType { .. } => IPE_T0002,
        TypeError::BudgetExceeded | TypeError::StepBudgetExceeded { .. } => IPE_T0003,
        TypeError::TooManyParameters { .. } => IPE_T0004,
        TypeError::NonExhaustiveCase { .. } => IPE_T0010,
        TypeError::RedundantCaseBranch { .. } => IPE_T0011,
        TypeError::WildcardCoversKnownConstructors { .. } => IPE_T0018,
        TypeError::NoSuchField { .. } => IPE_T0012,
        TypeError::BuiltinRecordUpdate { .. } => IPE_T0017,
        TypeError::CtorPatternArity { .. } => IPE_T0013,
        TypeError::SuperTypeUnsatisfied { .. } => IPE_T0014,
        TypeError::RefutablePatternParameter => IPE_T0015,
        TypeError::OrPatternBindingMismatch { .. } => IPE_T0019,
        TypeError::TaskArity { .. } => IPE_T0016,
        TypeError::WebViewReturnsHtml => IPE_T0020,
    })
}

const fn lower_code(msg: &LowerError) -> Code {
    in_lower(match msg {
        LowerError::Unsupported(f) => feature_code(*f),
        LowerError::InadmissibleAppModel { .. } => IPE_L0120,
        LowerError::InadmissibleAppMsg { .. } => IPE_L0125,
        LowerError::SecretFromStringLiteral => IPE_L0150,
        LowerError::SecretFromStringUnapplied => IPE_L0151,
        LowerError::BackendNestingTooDeep { .. } => IPE_L0200,
        LowerError::DecodeSucceedArityTooHigh { .. } => IPE_L0121,
        LowerError::RouteParamCountMismatch { .. } => IPE_L0122,
        LowerError::RouteBuilderUnsupportedShape | LowerError::RouteParamUnsupportedType { .. } => {
            IPE_L0123
        }
        LowerError::DevOnlyKernelInProduction { .. } => IPE_L0140,
        LowerError::UiCellsInWebShape(_) => IPE_L0132,
        LowerError::UiCellsInCliShape(_) => IPE_L0153,
        LowerError::UiWidgetInNonWebShape => IPE_L0147,
        LowerError::LawlessEffectDiscard => IPE_L0141,
        LowerError::RoutedAppMissingPageField { .. } => IPE_L0124,
        LowerError::NonEntryMain { .. } => IPE_L0136,
        LowerError::UndeterminableReturnAny => IPE_L0142,
        LowerError::WildcardAnyFieldTypeMismatch { .. } => IPE_L0143,
        LowerError::WildcardAnyArgNotRecord { .. } => IPE_L0144,
        LowerError::StoreEqAccessorInvalid(_) => IPE_L0145,
        LowerError::PointFreeAccessorKernel { .. } => IPE_L0146,
        LowerError::StoreSelectProjectionInvalid(_) => IPE_L0149,
    })
}

const fn feature_code(f: Feature) -> Code {
    in_lower(match f {
        Feature::CasePatternKinds => IPE_L0100,
        Feature::BinOps => IPE_L0101,
        Feature::Polymorphism => IPE_L0102,
        Feature::HigherOrderValues => IPE_L0103,
        Feature::TaskResults => IPE_L0104,
        Feature::ParamPatterns => IPE_L0105,
        Feature::UntypedFunctions => IPE_L0106,
        Feature::FirstClassFunctions => IPE_L0107,
        Feature::Kernels => IPE_L0108,
        Feature::PartialOverApplication => IPE_L0110,
        Feature::BoundedRecordUpdate => IPE_L0111,
        Feature::NestedPayloadPatterns => IPE_L0112,
        Feature::AliasOverRefutablePayload => IPE_L0128,
        Feature::WasmRoutedApp => IPE_L0129,
        Feature::CtorAsFunction => IPE_L0113,
        Feature::CtorPayloadFunction => IPE_L0114,
        Feature::TuplePatternMatch => IPE_L0115,
        Feature::NestedCtorDiscrimination => IPE_L0116,
        Feature::FloatKeyedCollection => IPE_L0117,
        Feature::RoutedWebApp => IPE_L0118,
        Feature::LetBoundAppCfg => IPE_L0119,
        Feature::NonCloneCapture => IPE_L0126,
        Feature::FunctionValueReuse => IPE_L0127,
        Feature::ForeignHandleReuse => IPE_L0130,
        Feature::RowPolyRecordAnnotation => IPE_L0131,
        Feature::FunctionElementEquality => IPE_L0134,
        Feature::NonCloneValueReuse => IPE_L0135,
        Feature::JsPortBoundarySeal => IPE_L0148,
    })
}

/// Maps a `CompilerBug.where_` tag to a stable `IPE-I####`. Unknown tags fall
/// back to the generic [`IPE_I0001`]; producers opt into a specific code by
/// stamping one of the recognised tags.
fn bug_code(where_: &str) -> Code {
    in_internal(match where_ {
        "intern.resolve" => IPE_I0010,
        "intern.capacity" => IPE_I0011,
        "ir.match.unknown_variant" => IPE_I0100,
        "ir.match.duplicate_arm" => IPE_I0101,
        "ir.match.non_exhaustive" => IPE_I0102,
        "ir.match.arm_enum_mismatch" => IPE_I0103,
        "backend.no_rust_name" => IPE_I0200,
        "backend.dangling_symbol" => IPE_I0201,
        "backend.type_name_collision" => IPE_I0202,
        "backend.golden_anchor" => IPE_I0203,
        _ => IPE_I0001,
    })
}

// --- help() helpers --------------------------------------------------------

fn parse_help(msg: &ParseError) -> Vec<HelpLine> {
    match msg {
        ParseError::MalformedModuleHeader(_) => vec![HelpLine::Hint(Hint::ModuleHeaderExample)],
        ParseError::StrayDot => vec![HelpLine::Hint(Hint::UseDotDotOrQualified)],
        ParseError::SpaceBeforeDot => vec![HelpLine::Hint(Hint::RemoveSpaceBeforeDot)],
        ParseError::NumberJoinedToName(_) => vec![HelpLine::Hint(Hint::SeparateWithSpace)],
        ParseError::IntLiteralOutOfRange => vec![HelpLine::Hint(Hint::IntegerLiteralRange)],
        ParseError::FloatLiteralOutOfRange => vec![HelpLine::Hint(Hint::FloatLiteralRange)],
        ParseError::ExpectedType => vec![HelpLine::Hint(Hint::TypeAtomForms)],
        ParseError::MalformedTypeDeclaration(_) => {
            vec![HelpLine::Hint(Hint::ConstructorMustBeUppercase)]
        }
        ParseError::TooDeep | ParseError::NestingTooDeep { .. } => {
            vec![HelpLine::Hint(Hint::NestingBoundDeliberate)]
        }
        ParseError::UnclosedDelimiter { opener } => vec![HelpLine::SecondarySpan {
            span: *opener,
            role: SpanRole::Opener,
        }],
        ParseError::Unexpected
        | ParseError::UnexpectedToken { .. }
        | ParseError::UnexpectedEof { .. }
        | ParseError::UnknownChar(_)
        | ParseError::UnterminatedString
        | ParseError::MalformedChar
        | ParseError::UnterminatedBlockComment
        | ParseError::MalformedExposingList(_)
        | ParseError::MissingEquals { .. }
        | ParseError::TypeArgsOnNonConstructor
        | ParseError::MalformedCase(_)
        | ParseError::MalformedLet(_)
        | ParseError::MalformedIf(_)
        | ParseError::InvalidPathLiteral { .. }
        | ParseError::SteplessDo
        | ParseError::DocOnUnexported { .. }
        | ParseError::MissingDocString { .. }
        | ParseError::AnnotationWithoutBinding { .. }
        | ParseError::DuplicateAnnotation { .. }
        | ParseError::SourceTooLarge { .. } => Vec::new(),
    }
}

fn name_help(msg: &NameError, span: Span) -> Vec<HelpLine> {
    match msg {
        NameError::ValueNotFound { suggestions, .. }
        | NameError::TypeNotFound { suggestions, .. }
        | NameError::ConstructorNotFound { suggestions, .. }
        | NameError::UnknownModule { suggestions, .. }
        | NameError::NoSuchMember { suggestions, .. }
        | NameError::ModuleNotFound { suggestions, .. }
        | NameError::NameNotExposed { suggestions, .. } => did_you_mean(suggestions, span),
        NameError::DuplicateValue { first, .. }
        | NameError::DuplicateConstructor { first, .. }
        | NameError::DuplicateType { first, .. }
        | NameError::DuplicatePatternBinder { first, .. }
        | NameError::DuplicateQualifier { first, .. } => vec![HelpLine::SecondarySpan {
            span: *first,
            role: SpanRole::FirstDefinition,
        }],
        NameError::WrongShapeCmdSub(m) => vec![HelpLine::Note(
            format!(
                "this app's shape reaches `Cmd` / `Sub` through `{}`",
                m.expected
            )
            .into_boxed_str(),
        )],
        // The IR carries no source spans, so there is no caret to hang the fix
        // label on; carry it as a note instead, which renders whether or not a
        // snippet is shown.
        NameError::RustNameFold {
            first,
            second,
            rust_name,
            kind,
        } => vec![HelpLine::Note(
            format!(
                "`{first}` and `{second}` are distinct Ipê {}, but after name mangling both \
                 become the Rust name `{rust_name}`, which can only be defined once. Rename one \
                 of the two so they fold to different Rust names.",
                kind.noun(),
            )
            .into_boxed_str(),
        )],
        NameError::Unknown
        | NameError::AliasArity { .. }
        | NameError::BuiltinTypeArity { .. }
        | NameError::ImportCycle { .. }
        | NameError::ModulePathMismatch { .. }
        | NameError::AmbiguousImport { .. }
        | NameError::ReservedNamespace { .. }
        | NameError::ReservedBuiltinType { .. }
        | NameError::UnknownKernelAlias { .. }
        | NameError::ServerOnlyKernelForWasm { .. }
        | NameError::ServerModuleReachableFromWasmClient { .. }
        | NameError::TypeExpansionTooDeep { .. }
        | NameError::ProgramImportsTeaShape { .. }
        | NameError::StdlibImportRequired { .. }
        | NameError::RemovedSurface { .. }
        | NameError::AssertedCallMalformed { .. }
        | NameError::BoundarySealIllegal { .. }
        | NameError::NestedDecoderPipeline
        | NameError::CodecAutoUnderivable { .. }
        | NameError::KernelAliasInUserSource { .. }
        | NameError::DiscardedConfig
        | NameError::CustomElementCtorMalformed { .. }
        | NameError::RuntimeBranchedMain
        | NameError::ModuleNotAllowedInPlacement(..)
        | NameError::ScriptImportsShapeView { .. }
        | NameError::GenericAppEntry { .. }
        | NameError::UnpinnedAppEntry { .. }
        | NameError::EffectCarrierInDecoder { .. }
        | NameError::WebInitPolyArg => Vec::new(), // no span-based help
    }
}

fn type_help(msg: &TypeError) -> Vec<HelpLine> {
    match msg {
        TypeError::TypeMismatch { definition, .. } => definition.map_or_else(Vec::new, |span| {
            vec![HelpLine::SecondarySpan {
                span,
                role: SpanRole::Definition,
            }]
        }),
        TypeError::BudgetExceeded | TypeError::StepBudgetExceeded { .. } => {
            vec![HelpLine::Hint(Hint::RaiseSolverBudget)]
        }
        TypeError::NonExhaustiveCase { missing } => missing
            .iter()
            .map(|c| HelpLine::MissingConstructor(c.clone()))
            .collect(),
        TypeError::RefutablePatternParameter => {
            vec![HelpLine::Hint(Hint::IrrefutableParameterRequired)]
        }
        TypeError::OrPatternBindingMismatch { names } => {
            let listed = names
                .iter()
                .map(|n| format!("`{n}`"))
                .collect::<Vec<_>>()
                .join(", ");
            vec![HelpLine::Note(
                format!(
                    "the arm body reads a bound variable without knowing which \
                     alternative matched, so every alternative must bind the same \
                     variables. {listed} is bound by some alternatives but not all. \
                     Add the missing binding to every alternative, or drop it."
                )
                .into_boxed_str(),
            )]
        }
        TypeError::WildcardCoversKnownConstructors { constructors } => constructors
            .iter()
            .map(|c| HelpLine::MissingConstructor(c.clone()))
            .collect(),
        TypeError::WebViewReturnsHtml => vec![HelpLine::Note(
            "wrap the `Html` with `Ui.html (…)` to get an `Element`. In a \
             `Web.tea` `view`, prefer returning the inner \
             `Element` directly (annotate `view : Model -> Element Msg`) and let \
             the shape apply `Ui.layout` for you."
                .into(),
        )],
        TypeError::Mismatch
        | TypeError::InfiniteType { .. }
        | TypeError::TooManyParameters { .. }
        | TypeError::RedundantCaseBranch { .. }
        | TypeError::NoSuchField { .. }
        | TypeError::BuiltinRecordUpdate { .. }
        | TypeError::CtorPatternArity { .. }
        | TypeError::SuperTypeUnsatisfied { .. }
        | TypeError::TaskArity { .. } => Vec::new(),
    }
}

/// The human message for [`LowerError::InadmissibleAppModel`], shared by the
/// `note:` help line (span-free path) and the render caret label (when a span is
/// present). Names the offending field, the leaf kind, and the required trait.
#[must_use]
pub fn inadmissible_model_message(app: AppShape, field: &str, leaf: ModelLeaf) -> String {
    let (shape, requirement) = match app {
        AppShape::Web => (
            "Ipe.Web",
            "serialisable (it is persisted to the session store)",
        ),
        AppShape::Tui | AppShape::Cli => ("Ipe.Terminal", "clonable"),
        AppShape::WebView => ("Ipe.WebView", "clonable"),
    };
    let leaf_phrase = match leaf {
        ModelLeaf::Function => "a function",
        ModelLeaf::Command => "a command (`Cmd`)",
        ModelLeaf::Subscription => "a subscription (`Sub`)",
        ModelLeaf::Task => "a task (`Task`)",
        ModelLeaf::Decoder => "a decoder (`Decoder`)",
        ModelLeaf::Handle => "an opaque handle (`Db` / server / live request)",
        ModelLeaf::ViewValue => "a view value (`Html` / `Element` / `Color`)",
    };
    if field.is_empty() {
        format!(
            "a {shape} Model must be {requirement}, but this Model is {leaf_phrase}, \
             which is not — keep only plain data in the Model"
        )
    } else {
        format!(
            "a {shape} Model must be {requirement}, but its field `{field}` is {leaf_phrase}, \
             which is not — keep only plain data in the Model"
        )
    }
}

/// The human message for [`LowerError::InadmissibleAppMsg`], shared by the
/// `note:` help line (span-free path) and the render caret label (when a span is
/// present). Names the offending variant/field, the leaf kind, and the required
/// trait. Mirrors [`inadmissible_model_message`] but uses the Msg wording.
#[must_use]
pub fn inadmissible_msg_message(app: AppShape, field: &str, leaf: ModelLeaf) -> String {
    let shape = match app {
        AppShape::Web => "Ipe.Web",
        AppShape::Tui | AppShape::Cli => "Ipe.Terminal",
        AppShape::WebView => "Ipe.WebView",
    };
    let leaf_phrase = match leaf {
        ModelLeaf::Function => "a function",
        ModelLeaf::Command => "a command (`Cmd`)",
        ModelLeaf::Subscription => "a subscription (`Sub`)",
        ModelLeaf::Task => "a task (`Task`)",
        ModelLeaf::Decoder => "a decoder (`Decoder`)",
        ModelLeaf::Handle => "an opaque handle (`Db` / server / live request)",
        ModelLeaf::ViewValue => "a view value (`Html` / `Element` / `Color`)",
    };
    if field.is_empty() {
        format!(
            "a {shape} Msg must be clonable and sendable, but this Msg is {leaf_phrase}, \
             which is not — keep only plain data in Msg variants"
        )
    } else {
        format!(
            "a {shape} Msg must be clonable and sendable, but its variant/field `{field}` \
             is {leaf_phrase}, which is not — keep only plain data in Msg variants"
        )
    }
}

#[allow(clippy::too_many_lines)] // one help arm per lowerer diagnostic variant
fn lower_help(msg: &LowerError) -> Vec<HelpLine> {
    match msg {
        LowerError::Unsupported(Feature::UntypedFunctions) => {
            vec![HelpLine::Hint(Hint::AddTypeSignature)]
        }
        // Function-in-record-field: direct the reader to the state topic, which
        // covers TEA-only state and why functions do not belong in records.
        LowerError::Unsupported(Feature::FirstClassFunctions) => vec![
            HelpLine::Hint(Hint::FeatureNotSupported(Feature::FirstClassFunctions)),
            HelpLine::SeeExplain("state"),
        ],
        LowerError::Unsupported(f) => vec![HelpLine::Hint(Hint::FeatureNotSupported(*f))],
        // The Model gate has no source span (the IR is span-free at emit), so the
        // field-naming message is carried as a `note:` line here — the caret
        // label at [`crate::render`] only renders when a snippet is present.
        LowerError::InadmissibleAppModel { app, field, leaf } => vec![HelpLine::Note(
            inadmissible_model_message(*app, field, *leaf).into_boxed_str(),
        )],
        // Same span-free note pattern as the Model gate.
        LowerError::InadmissibleAppMsg { app, field, leaf } => vec![HelpLine::Note(
            inadmissible_msg_message(*app, field, *leaf).into_boxed_str(),
        )],
        LowerError::BackendNestingTooDeep { .. } => {
            vec![HelpLine::Hint(Hint::NestingBoundDeliberate)]
        }
        LowerError::DecodeSucceedArityTooHigh { n } => vec![HelpLine::Note(
            format!(
                "the constructor passed to `succeed` has {n} parameters; \
                 the runtime's `curry1`..`curry10` helpers cap at 10. \
                 Split the record into multiple smaller decoders and combine \
                 them with `andThen`, or reduce the field count below 10."
            )
            .into_boxed_str(),
        )],
        LowerError::RouteParamCountMismatch {
            pattern,
            param_count,
            ctor_payload_count,
        } => vec![HelpLine::Note(
            format!(
                "pattern `{pattern}` has {param_count} `:param` segment(s) but the \
                 page constructor has {ctor_payload_count} payload field(s). \
                 Add or remove `:param` segments in the pattern to match the \
                 constructor's arity, or use a nullary constructor for routes \
                 without parameters."
            )
            .into_boxed_str(),
        )],
        LowerError::RouteBuilderUnsupportedShape => vec![HelpLine::Note(
            "inline the constructor or lambda directly at the `Web.route` call site; \
             a let-bound variable or computed expression cannot be used as a page builder."
                .into(),
        )],
        LowerError::RouteParamUnsupportedType {
            field_index,
            type_name,
        } => vec![HelpLine::Note(
            format!(
                "payload field {field_index} has type `{type_name}`, which cannot be \
                 decoded from a URL `:param` string. Change the field type to `String`, \
                 `Int`, `Float`, or `Bool`, or use a nullary constructor for routes \
                 without `:param` segments."
            )
            .into_boxed_str(),
        )],
        LowerError::DevOnlyKernelInProduction { kernel } => vec![HelpLine::Note(
            format!(
                "`{kernel}` is a development-only debugging tool. Remove it before \
                 releasing, or switch to `ipe build` / `ipe run` for development. \
                 To log in production, use `Io.eprintln` or `Log.info`."
            )
            .into_boxed_str(),
        )],
        LowerError::SecretFromStringLiteral => vec![HelpLine::Note(
            "a `Secret` must not be committed to source as a string literal. Read the \
             credential from the environment at runtime with `App.fromEnvRequired \"VAR\"` \
             (which returns a `Secret` directly), or seal a `String` the program obtained \
             at runtime with `Secret.fromString`. A runtime `String` is accepted here; only \
             a source-text literal is refused."
                .into(),
        )],
        LowerError::SecretFromStringUnapplied => vec![HelpLine::Note(
            "`Secret.fromString` seals its argument into a `Secret`, so it must be \
             applied directly to that argument — the seal gate that refuses a committed \
             literal reads the call's argument, and an un-applied reference hides the \
             argument from it. Write `Secret.fromString runtimeString` (or, to map a list, \
             `List.map (\\s -> Secret.fromString s) runtimeStrings`) instead of passing \
             `Secret.fromString` as a value or binding it to a name."
                .into(),
        )],
        LowerError::UiCellsInWebShape(_) => vec![HelpLine::Note(
            "`Ui.cells` paints a raw character grid onto the terminal, which a browser \
             cannot render. Use it only under `Tui.tea`; \
             for the same content in a Web/WebView view, render it with `Ui.text` (or a \
             `Ui.column` of rows) instead."
                .into(),
        )],
        LowerError::UiCellsInCliShape(_) => vec![HelpLine::Note(
            "`Ui.cells` paints a terminal character grid — a Cli (line-oriented) view \
             returns `String`, so there is no character-grid surface to paint on. \
             Use it only under `Tui.tea`; for line output, \
             format the content as a `String` instead."
                .into(),
        )],
        LowerError::UiWidgetInNonWebShape => vec![HelpLine::Note(
            "`CustomElement.node` mounts a server-driven custom element whose up-events ride the \
             seal codec, which exists only in a browser build. Use it only under \
             `Web.tea`. In a `Terminal` app, build the view from native \
             `Ipe.Ui` elements (`Ui.text`, `Ui.column`, inputs) instead."
                .into(),
        )],
        LowerError::LawlessEffectDiscard => lawless_effect_discard_help(),
        LowerError::RoutedAppMissingPageField { route_count } => {
            routed_app_missing_page_field_help(*route_count)
        }
        LowerError::NonEntryMain { .. } => non_entry_main_help(),
        LowerError::UndeterminableReturnAny => undeterminable_return_any_help(),
        LowerError::WildcardAnyFieldTypeMismatch {
            field, required, ..
        } => wildcard_any_field_type_mismatch_help(field, required),
        LowerError::WildcardAnyArgNotRecord { .. } => wildcard_any_arg_not_record_help(),
        LowerError::StoreEqAccessorInvalid(defect) => store_eq_accessor_invalid_help(defect),
        LowerError::PointFreeAccessorKernel { kernel } => point_free_accessor_kernel_help(kernel),
        LowerError::StoreSelectProjectionInvalid(defect) => {
            store_select_projection_invalid_help(defect)
        }
    }
}

/// The help lines for [`LowerError::StoreSelectProjectionInvalid`], factored out
/// so [`lower_help`] stays a thin per-variant dispatcher.
fn store_select_projection_invalid_help(defect: &StoreSelectProjectionDefect) -> Vec<HelpLine> {
    let note: Box<str> = match defect {
        StoreSelectProjectionDefect::NotAProjectionLambda => {
            "write the projection as `Store.select (\\( left, right ) -> right.name)` — a \
             two-binder tuple parameter over a column reference on one side."
                .into()
        }
        StoreSelectProjectionDefect::UnsupportedProjectionBody => {
            "project columns as bare `side.field` references — one column \
             `Store.select (\\( _, author ) -> author.name)`, or a tuple of \
             columns `Store.select (\\( book, author ) -> ( book.title, author.name ))`. \
             A computed value or a literal is not a column; do the transform in \
             ordinary code after `Store.selectToList`."
                .into()
        }
        StoreSelectProjectionDefect::NestedProjectionTuple => {
            "a multi-column projection is a flat tuple of `side.field` references, \
             such as `( book.title, author.name )` — a tuple element cannot itself \
             be a tuple."
                .into()
        }
        StoreSelectProjectionDefect::UnknownField { field } => format!(
            "the side's row type has no `{field}` field; name a field the store's \
             row declares (the same field its codec names)."
        )
        .into_boxed_str(),
        StoreSelectProjectionDefect::InvalidColumn { column } => format!(
            "the column name `{column}` is not a valid SQL identifier — use letters, \
             digits, and underscore only."
        )
        .into_boxed_str(),
        StoreSelectProjectionDefect::LiteralTypeUnsupported { ty } => format!(
            "`Store.literal` accepts String, Int, Bool, or Float — the projection \
             layer binds one of those scalars as a SQL parameter. `{ty}` is not a \
             supported scalar; do any transformation in ordinary code after \
             `Store.selectToList`."
        )
        .into_boxed_str(),
    };
    vec![HelpLine::Note(note)]
}

/// The help lines for [`LowerError::PointFreeAccessorKernel`], factored out so
/// [`lower_help`] stays a thin per-variant dispatcher.
fn point_free_accessor_kernel_help(kernel: &str) -> Vec<HelpLine> {
    vec![HelpLine::Note(
        format!(
            "`{kernel}` reads its column from the `.field` accessor at compile time, \
             so it has no value you can pass around: apply it directly, `{kernel} \
             .field value`. If you need a function value (say for `List.map` or \
             `Result.map`), wrap it in a lambda that supplies the accessor: \
             `\\x -> {kernel} .field x`."
        )
        .into_boxed_str(),
    )]
}

/// The help lines for [`LowerError::StoreEqAccessorInvalid`], factored out so
/// [`lower_help`] stays a thin per-variant dispatcher.
fn store_eq_accessor_invalid_help(defect: &StoreEqAccessorDefect) -> Vec<HelpLine> {
    let note: Box<str> = match defect {
        StoreEqAccessorDefect::NotAnAccessor => {
            "write the column as a bare field accessor — `Store.eq .age 18` — so the \
             accessor names the column; a let-bound name or a computed lambda cannot \
             be read as a column."
                .into()
        }
        StoreEqAccessorDefect::UnknownField { field } => format!(
            "the row type has no `{field}` field; name a field the store's row \
             declares (the same field its codec or column list names)."
        )
        .into_boxed_str(),
        StoreEqAccessorDefect::NonScalarField { field, found } => format!(
            "`{field}` is `{found}`; plain `Store.eq` binds only scalar fields \
             (String / Int / Bool / Float). For an enum or newtype column, use \
             `Store.eqBy` with the field's codec so its wire form is bound."
        )
        .into_boxed_str(),
        StoreEqAccessorDefect::InvalidColumn { column } => format!(
            "the column name `{column}` is not a valid SQL identifier — use letters, \
             digits, and underscore only."
        )
        .into_boxed_str(),
    };
    vec![HelpLine::Note(note)]
}

/// The help lines for [`LowerError::LawlessEffectDiscard`], factored out so
/// [`lower_help`] stays a thin per-variant dispatcher.
fn lawless_effect_discard_help() -> Vec<HelpLine> {
    vec![
        HelpLine::Note(
            "a `Task` runs its effect only through `Task.run`, or by being sequenced \
             inside a function whose own return type is a `Task`. Discarding it with \
             `let _ = <task>` in a non-`Task` function would run it through a hidden \
             `Task.run`. Give the enclosing function a `Task e ()` return type and let \
             its result be the sequenced tasks, or run the effect explicitly with \
             `Task.run`. To print a value while debugging, use `Debug.log` (rejected in \
             production builds)."
                .into(),
        ),
        HelpLine::SeeExplain("effects"),
    ]
}

/// The help lines for [`LowerError::WildcardAnyFieldTypeMismatch`], factored out
/// so [`lower_help`] stays a thin per-variant dispatcher.
fn wildcard_any_field_type_mismatch_help(field: &str, required: &str) -> Vec<HelpLine> {
    vec![HelpLine::Note(
        format!(
            "the callee's body reads the `.{field}` field and requires it to be \
             `{required}`; change the record field's value to match, or annotate \
             the callee's parameter with a closed record type such as \
             `{{ {field} : {required} }}` so the type-checker enforces the \
             constraint at every call site"
        )
        .into_boxed_str(),
    )]
}

/// The help lines for [`LowerError::WildcardAnyArgNotRecord`], factored out so
/// [`lower_help`] stays a thin per-variant dispatcher.
fn wildcard_any_arg_not_record_help() -> Vec<HelpLine> {
    vec![HelpLine::Note(
        "the callee's parameter is `any`, but its body reads record fields — \
         only a record can satisfy the `IpeHas*` witness bounds the backend emits. \
         Pass a record value, or annotate the callee's parameter with a closed \
         record type so the type-checker enforces the constraint at every call site."
            .into(),
    )]
}

/// The help lines for [`LowerError::NonEntryMain`], factored out so
/// [`lower_help`] stays a thin per-variant dispatcher.
fn non_entry_main_help() -> Vec<HelpLine> {
    vec![
        HelpLine::Note(
            "`main` is the one effect your whole program runs, so it has to be a \
             `Task Error ()`. Write it directly — `main = Io.println \"hello\"` prints a \
             line, `main = someTask` runs any task you built — or start an app with \
             `Web.tea { … }`, `Tui.tea { … }`, or `Cli.tea { … }`, each \
             of which is itself a `Task Error ()`. To turn a plain value into an effect, \
             do something with it: `main = Io.println (String.fromInt 42)`."
                .into(),
        ),
        HelpLine::SeeExplain("main"),
    ]
}

/// The help lines for [`LowerError::RoutedAppMissingPageField`], factored out
/// so [`lower_help`] stays a thin per-variant dispatcher.
fn routed_app_missing_page_field_help(route_count: usize) -> Vec<HelpLine> {
    vec![HelpLine::Note(
        format!(
            "the `routes` list has {route_count} route(s) but the Model has no \
             `page` field, so routing is disabled and every URL serves the same \
             app. The routed-page field must be named exactly `page` (of the \
             `Page` ADT whose constructors appear as route destinations). Rename \
             the field to `page`, or remove the `routes` list if routing is not \
             needed."
        )
        .into_boxed_str(),
    )]
}

/// The help lines for [`LowerError::UndeterminableReturnAny`], factored out so
/// [`lower_help`] stays a thin per-variant dispatcher.
fn undeterminable_return_any_help() -> Vec<HelpLine> {
    vec![
        HelpLine::Note(
            "a wildcard `any` stands for one concrete type the compiler must be able to \
             work out. In the return type it can only be worked out from the body — the \
             body must produce a concrete value. Here it does not, so no caller could ever \
             pin it. Annotate a concrete return type, or return a concrete value from the \
             body. To keep it genuinely polymorphic instead — letting each caller choose \
             the type — use a named type variable such as `a`, not a wildcard `any`."
                .into(),
        ),
        HelpLine::SeeExplain("IPE-L0142"),
    ]
}

// --- ffi_code / sandbox_code / ffi_help / sandbox_help / consent_help -------

const fn ffi_code(msg: &FfiError) -> Code {
    in_ffi(match msg {
        FfiError::CallUnrenderable { .. } | FfiError::GenericNotBindable { .. } => IPE_F4400,
        FfiError::WireMalformed { .. } => IPE_F4401,
        FfiError::ShapeContradiction { .. } => IPE_F4402,
        FfiError::SourceRejected { .. } => IPE_F4411,
        FfiError::ArtifactIo { .. } => IPE_F4412,
        FfiError::AssertedRefused { .. } => IPE_F4414,
        FfiError::SystemLibraryNotFound { .. } => IPE_F4415,
    })
}

/// The sandbox is the FFI jail, so its diagnostics deliberately live in the
/// `IPE-F` family rather than a family of their own — the one sanctioned
/// family cross in the taxonomy. Routing through `in_ffi` (not `in_internal`)
/// encodes that as an explicit, asserted choice: a sandbox arm that returned a
/// non-`IPE-F` code would fail the chokepoint, so the exception cannot silently
/// widen into an unremarked hole in the family invariant.
const fn sandbox_code(msg: &SandboxError) -> Code {
    in_ffi(match msg {
        SandboxError::BuildJail { .. } => IPE_F4410,
        SandboxError::RunJail { .. } => IPE_F4413,
    })
}

fn ffi_help(msg: &FfiError) -> Vec<HelpLine> {
    match msg {
        FfiError::SystemLibraryNotFound {
            system_lib,
            crate_name,
            ..
        } => vec![
            HelpLine::Note(
                format!(
                    "install the `{system_lib}` development package and re-run \
                     `ipe rust add {crate_name}`"
                )
                .into_boxed_str(),
            ),
            HelpLine::Note(
                "if the library is in a non-standard location, set PKG_CONFIG_PATH \
                 before re-running"
                    .into(),
            ),
            HelpLine::SeeExplain("IPE-F4415"),
        ],
        FfiError::CallUnrenderable { .. }
        | FfiError::GenericNotBindable { .. }
        | FfiError::WireMalformed { .. }
        | FfiError::ShapeContradiction { .. }
        | FfiError::SourceRejected { .. }
        | FfiError::ArtifactIo { .. }
        | FfiError::AssertedRefused { .. } => Vec::new(),
    }
}

fn sandbox_help(msg: &SandboxError) -> Vec<HelpLine> {
    match msg {
        SandboxError::BuildJail { .. } => vec![HelpLine::Note(
            "install bubblewrap (bwrap), coreutils (timeout), and util-linux (prlimit) \
             to enable the isolation jail for compiling untrusted crates"
                .into(),
        )],
        SandboxError::RunJail { .. } => vec![
            HelpLine::Note(
                "this program reaches native Rust code whose effects cannot be proven \
                 safe; install bubblewrap (bwrap on Linux) or sandbox-exec (macOS) to \
                 confine it"
                    .into(),
            ),
            HelpLine::Note(
                "set IPE_ALLOW_UNSANDBOXED=1 to run unconfined at your own risk \
                 (never in CI)"
                    .into(),
            ),
        ],
    }
}

fn consent_help(msg: &ConsentError) -> Vec<HelpLine> {
    let remedy = HelpLine::Note(
        "re-run with --accept-risks to take responsibility and proceed, or add \
         `accept = [\"unsafe\"]` under [capabilities] in package.ipe for durable consent"
            .into(),
    );
    match msg {
        ConsentError::NonInteractive { .. } => vec![
            remedy,
            HelpLine::Note(
                "this is a non-interactive build; it will not prompt — \
                 pre-accept with --accept-risks or the manifest token"
                    .into(),
            ),
        ],
        ConsentError::InteractiveDenied { .. } => vec![remedy],
    }
}

// --- did_you_mean ------------------------------------------------------------

/// Turns already-sorted suggestion names into help lines. A single candidate is
/// confident enough to offer as a [`Applicability::MachineApplicable`]
/// suggestion over `span` (the misspelled name's region); two or more stay
/// non-committal "did you mean" lines. The producer is responsible for the
/// stable `(Levenshtein, name)` ordering.
fn did_you_mean(suggestions: &[Box<str>], span: Span) -> Vec<HelpLine> {
    match suggestions {
        [only] => vec![HelpLine::Suggest(Suggestion {
            span,
            replacement: only.clone(),
            applicability: Applicability::MachineApplicable,
        })],
        many => many
            .iter()
            .map(|s| HelpLine::DidYouMean(s.clone()))
            .collect(),
    }
}

#[cfg(test)]
mod code_family_tests {
    use super::{
        ConsentError, Diagnostic, Feature, FfiError, LowerError, NameError, ParseError,
        SandboxError, TypeError,
    };
    use crate::code::{Family, Severity};
    use crate::span::Span;

    /// One representative [`Diagnostic`] for every family, paired with the
    /// family its rendered [`Diagnostic::code`] must belong to. `Sandbox` is
    /// deliberately paired with [`Family::Ffi`] — the one sanctioned family
    /// cross (the sandbox is the FFI jail) — so this table pins the exception
    /// too, not only the rule.
    fn family_representatives() -> Vec<(Diagnostic, Family)> {
        vec![
            (
                Diagnostic::Parse {
                    span: Span::DUMMY,
                    msg: ParseError::Unexpected,
                },
                Family::Parse,
            ),
            (
                Diagnostic::Name {
                    span: Span::DUMMY,
                    msg: NameError::Unknown,
                },
                Family::Name,
            ),
            (
                Diagnostic::Type {
                    span: Span::DUMMY,
                    msg: TypeError::Mismatch,
                },
                Family::Type,
            ),
            (
                Diagnostic::Lower {
                    span: Span::DUMMY,
                    msg: LowerError::Unsupported(Feature::CasePatternKinds),
                },
                Family::Lower,
            ),
            (
                Diagnostic::Ffi {
                    msg: FfiError::WireMalformed {
                        context: "test".to_owned(),
                        detail: "test".to_owned(),
                    },
                },
                Family::Ffi,
            ),
            (
                Diagnostic::Sandbox {
                    msg: SandboxError::BuildJail {
                        detail: "test".to_owned(),
                    },
                },
                Family::Ffi,
            ),
            (
                Diagnostic::Consent {
                    msg: ConsentError::NonInteractive {
                        body: "test".to_owned(),
                    },
                },
                Family::Security,
            ),
            (
                Diagnostic::RegistryUnreachable {
                    detail: "test".to_owned(),
                },
                Family::Environment,
            ),
            (
                Diagnostic::CompilerBug {
                    where_: "ir.match.non_exhaustive",
                    detail: "test".to_owned(),
                },
                Family::Internal,
            ),
        ]
    }

    /// Every representative diagnostic's rendered code belongs to the family it
    /// is filed under — the runtime companion to the compile-time chokepoints in
    /// `code()`'s helpers. Drives the real `code()` path, so a producer arm that
    /// returned a wrong-family code (a typo one edit could introduce) is turned
    /// back here even for a variant no const-eval representative exercises.
    #[test]
    fn every_representative_code_matches_its_family() {
        for (diag, family) in family_representatives() {
            assert_eq!(
                diag.code().family(),
                family,
                "{} has family {:?}, expected {family:?}",
                diag.code().as_str(),
                diag.code().family()
            );
        }
    }

    /// The severity/family biconditional the SEAL demands:
    /// `severity == Bug` **iff** `family == Internal`. A `Bug` outside the
    /// internal family, or an internal code that is not a `Bug`, mislabels the
    /// diagnostic's exit policy and "please report" framing — so both directions
    /// are pinned.
    #[test]
    fn bug_severity_iff_internal_family() {
        for (diag, _) in family_representatives() {
            let is_bug = matches!(diag.severity(), Severity::Bug);
            let is_internal = matches!(diag.code().family(), Family::Internal);
            assert_eq!(
                is_bug,
                is_internal,
                "{}: severity==Bug is {is_bug} but family==Internal is {is_internal}",
                diag.code().as_str()
            );
        }
    }

    /// A code's derived family round-trips its wire prefix over the whole
    /// taxonomy: every `IPE-I####` derives [`Family::Internal`] and every other
    /// code derives a non-`Internal` family. This is the fail-closed guard on
    /// [`crate::code::Code::family`]'s byte-4 derivation across all shipped codes.
    #[test]
    fn every_taxonomy_code_derives_a_prefix_consistent_family() {
        for &c in crate::code::ALL_CODES {
            let internal = matches!(c.family(), Family::Internal);
            assert_eq!(
                internal,
                c.as_str().starts_with("IPE-I"),
                "{} derives Internal={internal} but its wire prefix disagrees",
                c.as_str()
            );
        }
    }
}

#[cfg(test)]
mod sorted_names_tests {
    use super::SortedNames;

    fn boxed(items: &[&str]) -> Vec<Box<str>> {
        items.iter().map(|s| (*s).into()).collect()
    }

    #[test]
    fn canonicalises_to_string_order() {
        let names = SortedNames::new(boxed(&["zebra", "alpha", "mango"]));
        let rendered: Vec<&str> = names.iter().map(AsRef::as_ref).collect();
        assert_eq!(rendered, vec!["alpha", "mango", "zebra"]);
    }

    #[test]
    fn collapses_duplicates() {
        let names = SortedNames::new(boxed(&["dup", "dup", "one", "one", "two"]));
        let rendered: Vec<&str> = names.iter().map(AsRef::as_ref).collect();
        assert_eq!(rendered, vec!["dup", "one", "two"]);
    }

    #[test]
    fn output_is_independent_of_input_order() {
        // Every permutation of one set must produce byte-identical output —
        // this encodes that no representable value is unsorted, so discovery
        // order (hash-map iteration, interner id) can never leak into a message.
        let base = ["gamma", "alpha", "beta"];
        let permutations = [
            ["gamma", "alpha", "beta"],
            ["gamma", "beta", "alpha"],
            ["alpha", "gamma", "beta"],
            ["alpha", "beta", "gamma"],
            ["beta", "alpha", "gamma"],
            ["beta", "gamma", "alpha"],
        ];
        let canonical = SortedNames::new(boxed(&base));
        for perm in permutations {
            assert_eq!(
                SortedNames::new(boxed(&perm)),
                canonical,
                "permutation {perm:?} must canonicalise identically"
            );
        }
    }

    #[test]
    fn try_new_short_circuits_on_error() {
        let result: Result<SortedNames, &str> =
            SortedNames::try_new([Ok("ok".into()), Err("boom"), Ok("late".into())]);
        assert!(matches!(result, Err("boom")));
    }

    #[test]
    fn try_new_canonicalises_successes() {
        let result: Result<SortedNames, ()> =
            SortedNames::try_new([Ok("z".into()), Ok("a".into()), Ok("a".into())]);
        let names = result.expect("try_new over all-Ok must succeed");
        let rendered: Vec<&str> = names.iter().map(AsRef::as_ref).collect();
        assert_eq!(rendered, vec!["a", "z"]);
    }
}

#[cfg(test)]
mod see_explain_topic_tests {
    /// Every `SeeExplain` argument that names a topic page (not an `IPE-` code)
    /// must resolve to a live `docs/topics/<name>.md` — the drift-guard the
    /// `SeeExplain` doc promises. A code argument is covered by the explain-page
    /// build gate instead, so it is excluded here.
    #[test]
    fn every_see_explain_topic_has_a_live_page() {
        let this_file = include_str!("diagnostic.rs");
        let topics_dir =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../docs/topics");

        // Assembled from parts so the needle does not appear verbatim in this
        // file — otherwise the scan would match its own literal.
        let needle = format!("SeeExplain({}", '"');

        let mut checked = 0usize;
        for (idx, _) in this_file.match_indices(&needle) {
            // The argument is the text between the opening quote (just past the
            // needle) and the next quote. `match_indices` yields the match, not
            // the tail, so slice the tail from the file at the match offset.
            let tail = this_file.get(idx + needle.len()..).unwrap_or("");
            let arg = tail.split('"').next().unwrap_or("");
            // A code argument is covered by the explain-page build gate; an
            // empty match is not a topic.
            if arg.is_empty() || arg.starts_with("IPE-") {
                continue;
            }
            let page = topics_dir.join(format!("{arg}.md"));
            assert!(
                page.is_file(),
                "SeeExplain({arg:?}) has no live topic page at {}",
                page.display()
            );
            checked += 1;
        }
        assert!(
            checked > 0,
            "found no SeeExplain topic literals to check — scan is broken"
        );
    }
}
