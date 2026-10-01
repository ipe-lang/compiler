//! Canonical AST — the name-resolved tree the type checker consumes.
//!
//! Rust port of the supported subset of the reference compiler's
//! `Ipê.AST.Canonical` (itself a derivative work of elm/compiler's
//! `AST.Canonical`, BSD-3-Clause). Every variable is fully resolved: a
//! reference is classified as a local binding, a top-level binding of a named
//! module, a stdlib kernel function, or a data constructor. Only the nodes the
//! supported subset exercises are modelled.
//!
//! Identifiers are interned [`Symbol`]s; located nodes are wrapped in
//! [`Located`]. Module names are dotted segment vectors (`Main` → `[Main]`).

use std::collections::BTreeSet;

use ipe_diagnostics::{Located, Span};
use ipe_intern::Symbol;
use ipe_kernels::{StdlibKernel, WebCapability};

/// A name-resolved module.
//
// `Eq` is not derived: `defs` carry [`Expr`] bodies that may hold a float
// literal (only `PartialEq`).
#[derive(Clone, PartialEq, Debug)]
pub struct Module {
    /// Dotted module-name segments, e.g. `Main` → `[Main]`.
    pub name: Vec<Symbol>,
    pub unions: Vec<Union>,
    pub defs: Vec<Def>,
    /// `true` when this module's source imported at least one `Ipe.<M>.Unsafe`
    /// submodule — the reviewable act of reaching for a trust-escape hatch.
    ///
    /// Import-derived, computed at canonicalisation from the source import list
    /// (which is discarded before lowering), then OR'd across every module by
    /// [`crate::link::link`] and read by the lowerer to set the whole-program
    /// fact the `unsafe` capability scan discloses. The import — not the call of
    /// a specific member — is the signal, so a module that imports an `.Unsafe`
    /// submodule discloses even if a path to its members is dead code.
    pub imports_unsafe_submodule: bool,
    /// The web capabilities this module's source disclosed by importing reserved
    /// `Ipe.Browser.<Api>` submodules — an import-derived fact, keyed on the
    /// canonical module path via [`WebCapability::for_browser_module`] (the same
    /// reviewable-import discipline as `imports_unsafe_submodule`, but a set: one
    /// module may import several browser submodules). Union-folded across every
    /// linked module by [`crate::link::link`] and read by the lowerer to seed the
    /// whole-program `js-port:<axis>` disclosure. Importing the module is the
    /// signal, regardless of dead code.
    pub imported_web_capabilities: BTreeSet<WebCapability>,
}

/// A resolved union type and its constructors.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Union {
    /// The module that defines this union type. For a single-file compilation
    /// this equals `Module::name`; after `link::link` merges several modules
    /// into one, every union retains the path of its *original* source module
    /// here. The type-checker uses this to build the correct [`Ty::Con`] result
    /// type for each constructor, ensuring that a cross-module annotation
    /// `Color -> String` (home = `["Helper"]`) unifies with the constructor
    /// scheme for `Red : Color` (also home = `["Helper"]`), not with the merged
    /// module's synthetic name.
    pub home: Vec<Symbol>,
    pub name: Symbol,
    /// The `type` declaration's name-token source span, for diagnostic blame
    /// (the first-declaration site of a cross-module duplicate). `Span::DUMMY`
    /// in interface-identity and test-fixture contexts that have no source.
    pub name_span: Span,
    /// The type variables this union quantifies, in declaration order
    /// (`a` in `type Maybe a = …`). Empty for a monomorphic union. The order is
    /// load-bearing: the lowerer carries it through to the IR enum's
    /// `type_params`, where each parameter's position fixes its Rust generic name
    /// and aligns with the positional type arguments at every use site.
    pub vars: Vec<Symbol>,
    pub ctors: Vec<Ctor>,
}

/// A single resolved constructor: name, positional index, arity, declared
/// payload field types, and source span.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Ctor {
    pub name: Symbol,
    pub index: usize,
    pub arity: usize,
    /// The constructor's payload field types in declaration order
    /// (`[a]` for `Just a`, `[Tree, Int, Tree]` for `Node Tree Int Tree`). A
    /// nullary constructor has an empty list; `args.len() == arity`. A field type
    /// variable resolves to a [`Type::Var`] naming one of the union's `vars`.
    pub args: Vec<Type>,
    /// The constructor declaration's source span, for blame on a lowering gap
    /// that concerns the declared field types (e.g. an unsupported field shape).
    pub span: Span,
}

/// A top-level definition. Mirrors `Can.Def` / `Can.TypedDef`: a binding either
/// carries a canonical type annotation (`Typed`) or it does not (`Untyped`).
// `Eq` is not derived: a binding body is an [`Expr`] that may carry a float
// literal (only `PartialEq`).
#[derive(Clone, PartialEq, Debug)]
pub enum Def {
    /// A binding with no type annotation.
    Untyped {
        /// The module that declares this binding. For a single-file compilation
        /// this equals `Module::name`; after `link::link` merges several modules
        /// into one every def retains the path of its *original* source module
        /// here. The lowerer uses this to key `func_ids` and the backend uses it
        /// to prefix emitted Rust function names, preventing same-named defs from
        /// different modules from colliding (e.g. `Lib.helper` + `Main.helper`
        /// both compile cleanly to `lib_helper` + `main_helper`).
        home: Vec<Symbol>,
        name: Located<Symbol>,
        patterns: Vec<Pattern>,
        body: Expr,
    },
    /// A binding with an annotation, carrying its free type variables and the
    /// canonicalised annotation type.
    Typed {
        /// See [`Self::Untyped::home`].
        home: Vec<Symbol>,
        name: Located<Symbol>,
        free_vars: Vec<Symbol>,
        patterns: Vec<Pattern>,
        body: Expr,
        ty: Type,
    },
}

impl Def {
    /// The bound name, regardless of typed/untyped shape.
    #[must_use]
    pub const fn name(&self) -> Located<Symbol> {
        match self {
            Self::Untyped { name, .. } | Self::Typed { name, .. } => *name,
        }
    }

    /// The defining module's path, regardless of typed/untyped shape.
    #[must_use]
    pub fn home(&self) -> &[Symbol] {
        match self {
            Self::Untyped { home, .. } | Self::Typed { home, .. } => home,
        }
    }
}

/// An expression with its source span.
pub type Expr = Located<Expr_>;

/// Name-resolved expression node.
///
/// `Eq` is not derived: [`Expr_::Float`] carries an `f64` (only `PartialEq`).
#[derive(Clone, PartialEq, Debug)]
pub enum Expr_ {
    /// A locally-bound variable (function parameter, `let`, or `case` binding).
    VarLocal(Symbol),
    /// A top-level binding of a named module.
    VarTopLevel { module: Vec<Symbol>, name: Symbol },
    /// A stdlib kernel function.  `id` carries the pre-resolved
    /// [`StdlibKernel`] variant when the kernel is registered in the
    /// `stdlib_index`.  It is `None` for a reference with no registry backing:
    /// a reachable-but-unbacked reserved member (which then fails closed with
    /// IPE-L0108 at type-check), or a node routed through the string-match
    /// fallback path in `lower_callee`.  `module` and `name` are retained for
    /// diagnostics, the type-constraint kernel-scheme lookup, and that
    /// fallback.
    VarKernel {
        id: Option<StdlibKernel>,
        module: Symbol,
        name: Symbol,
    },
    /// A data constructor used as a value.
    VarCtor {
        home: Vec<Symbol>,
        type_name: Symbol,
        name: Symbol,
        index: usize,
    },
    /// An integer literal.
    Int(i64),
    /// A floating-point literal `1.5`, `3.0`, `1.5e3` — carries its parsed value.
    Float(f64),
    /// A string literal `"hello"` — carries its already-unescaped value.
    Str(String),
    /// A character literal `'a'` — carries its single unescaped character's text.
    Char(String),
    /// The reserved `CustomElement.fromFile "<js-path>"` constructor — legal ONLY as the
    /// entire body of a `CustomElement`-annotated binding, applied to a single
    /// string literal. The carried [`String`] is the CLEANED, NUL-free,
    /// non-escaping relative path to the author's widget-hook JS file, validated
    /// at canonicalisation with `ipe_diagnostics::path_check::PathLitText::seal` (the
    /// all-targets path seal shared through `ipe_path_core`); a non-literal argument,
    /// a bare `CustomElement.fromFile` value, or a traversing path is a compile error
    /// emitted before this node is ever constructed. The file's existence is
    /// checked later, at the build stage that owns the project root.
    ///
    /// The node has type `CustomElement down up` — an opaque widget handle.
    /// Its runtime denotation (generated glue + content-addressed tag) is
    /// emitted by the shipped widget transport.
    CustomElementCtor(String),
    /// The unit value `()` — the sole inhabitant of the unit type. Introduces no
    /// bindings and resolves no names.
    Unit,
    /// Function application.
    Call(Box<Expr>, Vec<Expr>),
    /// A foreign-crate FFI wrapper call — the canonical form of the
    /// `Ffi.binding "<wrapper_fn_ident>" arg0 …` body a driver-generated
    /// FFI interface module carries ([`crate::resolve::ModuleOrigin::FfiInterface`]
    /// only; unrepresentable from user source). `ident` is the emitted
    /// `_bindings.rs` wrapper `pub fn` identifier; the enclosing binding's
    /// annotation is the trusted HM signature.
    ///
    /// `asserted` marks the `Ffi.asserted "<ident>" arg0 …` spelling — a shim
    /// whose signature was author-asserted via `Rust.Ffi.call` rather than
    /// derived from crate inspection. Decided at the same origin-gated mint,
    /// so a user module can no more forge the flag than the node; it flows to
    /// the lowered call and flips the `ffi-raw` capability.
    ForeignCall {
        ident: Symbol,
        args: Vec<Expr>,
        asserted: bool,
    },
    /// `case scrutinee of` with resolved arms.
    Case(Box<Expr>, Vec<CaseBranch>),
    /// An anonymous function `\p0 p1 ... -> body`. The parameter patterns are
    /// resolved (each variable becomes a local in `body`); any free variable in
    /// `body` that is not a parameter is captured from the enclosing scope by
    /// ordinary name resolution. Arity ≥ 1 (the parser rejects `\ -> e`).
    Lambda(Vec<Pattern>, Box<Expr>),
    /// A resolved binary operation. `op` is the source operator symbol;
    /// `home` / `func` is the kernel it resolves to (e.g. `Basics` / `add`).
    /// `op_span` is the exact lexer span of the operator glyph (e.g. just `+`,
    /// not the surrounding whitespace). Synthetic nodes (multiline string
    /// desugar) carry a zero-width span at `lhs.span.hi`, which the token
    /// walker drops rather than emitting a zero-length token.
    Binop {
        op: Symbol,
        op_span: Span,
        home: Symbol,
        func: Symbol,
        lhs: Box<Expr>,
        rhs: Box<Expr>,
    },
    /// `let <bindings> in <body>`. Bindings are scoped sequentially: each value
    /// was resolved against the enclosing scope plus the bindings before it, and
    /// every binding name is a local within `body`.
    Let(Vec<LetBinding>, Box<Expr>),
    /// `if cond then a else b`, with optional `else if` branches. The list holds
    /// one or more `(condition, branch)` pairs (the leading `if` plus every
    /// `else if`), followed by the mandatory final `else` expression. Every
    /// sub-expression is resolved against the same enclosing scope — `if`
    /// introduces no bindings.
    If(Vec<(Expr, Expr)>, Box<Expr>),
    /// A tuple literal `(e1, e2, ...)`. Invariant: arity ≥ 2 (a parenthesised
    /// single expression was unwrapped by the parser). Every element is resolved
    /// against the same enclosing scope — a tuple introduces no bindings.
    Tuple(Vec<Expr>),
    /// A list literal `[]` / `[a, b, c]`. Elements are resolved in source order;
    /// the empty list carries an empty vector. Introduces no bindings.
    List(Vec<Expr>),
    /// A cons `head :: tail` — the right-associative list-prepend. `head` is an
    /// element; `tail` is a list. The parser's `::` operator chain is
    /// re-associated to this node at canonicalisation.
    Cons(Box<Expr>, Box<Expr>),
    /// A record literal `{ field = value, ... }`. Fields are `(name, value)`
    /// pairs; the name is a label (not a resolvable reference), the value is
    /// resolved against the enclosing scope. A record introduces no bindings.
    Record(Vec<(Symbol, Expr)>),
    /// A record field access `record.field`. The record sub-expression is
    /// resolved against the enclosing scope; the field is a label.
    Access(Box<Expr>, Symbol),
    /// A record update `{ base | field = value, ... }`. The base is the resolved
    /// reference to the record being copied (a variable, in the current grammar); the
    /// field list carries each updated `(name, value)` pair, names being labels
    /// and values resolved against the enclosing scope. An update introduces no
    /// bindings.
    Update(Box<Expr>, Vec<(Symbol, Expr)>),
}

/// A resolved `let` binding: `<pat> = body`.
///
/// The binder is a resolved [`Pattern`]: a [`Pattern_::PVar`] for the common
/// `name = body` case, or an irrefutable tuple / record destructure. A
/// refutable binder is rejected fail-closed at lowering.
// `Eq` is not derived: `body` is an [`Expr`], only `PartialEq` (float literals).
#[derive(Clone, PartialEq, Debug)]
pub struct LetBinding {
    pub pat: Pattern,
    pub body: Expr,
}

/// One arm of a `case`: a resolved pattern and the body it guards.
//
// `Eq` is not derived: `body` is an [`Expr`], only `PartialEq` (float literals).
#[derive(Clone, PartialEq, Debug)]
pub struct CaseBranch {
    pub pat: Pattern,
    pub body: Expr,
}

/// A pattern with its source span.
pub type Pattern = Located<Pattern_>;

/// Name-resolved pattern node.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Pattern_ {
    /// The wildcard `_`.
    PAnything,
    /// The development-only catch-all `Debug._`. Covers every value like
    /// [`Self::PAnything`] and is likewise irrefutable, but is EXEMPT from the
    /// closed-union catch-all error (IPE-T0018) and, at lowering, marks its
    /// module `uses_debug` so `ipe release` rejects it (IPE-L0140) — the same
    /// development-only posture as every other `Ipe.Debug` member.
    PDebugAnything,
    /// The unit pattern `()` — the sole value of the unit type. Binds nothing,
    /// typed at `()`. Irrefutable: unit has exactly one value.
    PUnit,
    /// A variable binding.
    PVar(Symbol),
    /// A resolved constructor pattern.
    PCtor {
        home: Vec<Symbol>,
        type_name: Symbol,
        name: Symbol,
        index: usize,
        args: Vec<Pattern>,
    },
    /// A tuple pattern `(p0, p1, ...)`. Invariant: arity ≥ 2. Each element is a
    /// resolved sub-pattern; every variable it introduces is bound as a local.
    PTuple(Vec<Pattern>),
    /// A record pattern `{ x, y }`. Field-pun only: each entry is a
    /// located field name that also binds a local of the same name. Always
    /// irrefutable; carries at least one field.
    PRecord(Vec<Located<Symbol>>),
    /// An integer literal pattern `0`. Refutable; Int is OPEN.
    PInt(i64),
    /// A boolean literal pattern `True` / `False`. A `True` + `False`
    /// pair is an exhaustive cover of the closed `Bool` type.
    PBool(bool),
    /// A character literal pattern `'a'` — carries the single unescaped
    /// character's text. Refutable; Char is OPEN.
    PChar(String),
    /// A string literal pattern `"hi"` — carries the unescaped value.
    /// Refutable; String is OPEN.
    PStr(String),
    /// An alias / `as` pattern `inner as name`: matches `inner` and also
    /// binds the whole matched value to `name`.
    PAlias(Box<Pattern>, Located<Symbol>),
    /// A list pattern `[]` / `[a, b, c]`. The empty list is the nil cover;
    /// a fixed-length list matches exactly that many elements.
    PList(Vec<Pattern>),
    /// A cons pattern `head :: tail` — binds the first element and the rest.
    PCons(Box<Pattern>, Box<Pattern>),
    /// An or-pattern `p1 | p2 | …` — matches if ANY alternative matches. Every
    /// alternative binds the identical set of variables (name-set equality is
    /// proved fail-fast in canon; per-name type equality post-solve in types).
    /// Each alternative is an arbitrary sub-pattern and recurses. Invariant:
    /// length ≥ 2.
    POr(Vec<Pattern>),
}

impl Pattern_ {
    /// Is this pattern **irrefutable** — does it match *every* value of its
    /// type, binding names only and never discriminating on a value?
    ///
    /// This is the single, purely-**syntactic** contract shared by the
    /// exhaustiveness gate (which rejects a refutable *parameter* pattern with
    /// IPE-T0015) and the lowerer (which `bug()`-asserts irrefutability before
    /// desugaring a param to an irrefutable `Destructure`). Keeping it one
    /// predicate makes the gate and the lowerer's capability set structurally
    /// impossible to desync.
    ///
    /// Deliberately no type-directed single-constructor leniency: even a
    /// single-variant ctor param (`\(Wrapper x) ->`) is refutable here, so the
    /// rule is total and needs no type lookup.
    ///
    /// | Variant | irrefutable? |
    /// |---|---|
    /// | [`Self::PVar`], [`Self::PAnything`], [`Self::PDebugAnything`] | `true` |
    /// | [`Self::PRecord`] | `true` (field-pun; always matches once the record type is fixed) |
    /// | [`Self::PTuple`] | all elements irrefutable |
    /// | [`Self::PAlias`] | inner irrefutable |
    /// | [`Self::PCtor`], [`Self::PInt`], [`Self::PBool`], [`Self::PChar`], [`Self::PStr`], [`Self::PList`], [`Self::PCons`] | `false` |
    /// | [`Self::POr`] | all alternatives irrefutable (in practice never — a well-formed or-pattern discriminates) |
    #[must_use]
    pub fn is_irrefutable(&self) -> bool {
        match self {
            Self::PVar(_)
            | Self::PAnything
            | Self::PDebugAnything
            | Self::PUnit
            | Self::PRecord(_) => true,
            Self::PTuple(elems) => elems.iter().all(|e| e.value.is_irrefutable()),
            Self::PAlias(inner, _) => inner.value.is_irrefutable(),
            Self::POr(alts) => alts.iter().all(|a| a.value.is_irrefutable()),
            Self::PCtor { .. }
            | Self::PInt(_)
            | Self::PBool(_)
            | Self::PChar(_)
            | Self::PStr(_)
            | Self::PList(_)
            | Self::PCons(_, _) => false,
        }
    }
}

/// Canonical type. Mirrors `Can.Type` narrowed to arrows, type
/// variables, and constructor applications.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Type {
    /// An arrow `A -> B`.
    Lambda(Box<Self>, Box<Self>),
    /// A type variable.
    Var(Symbol),
    /// A type-constructor application. `home` is the defining module (empty for
    /// built-ins like `Int`); `name` the type name; `args` its arguments.
    Con {
        home: Vec<Symbol>,
        name: Symbol,
        args: Vec<Self>,
    },
    /// The unit type `()`.
    Unit,
    /// An anonymous product (tuple) type `(T1, T2, ...)`. Invariant: arity ≥ 2 —
    /// a 0-tuple is [`Self::Unit`] and a 1-tuple is just its element.
    Tuple(Vec<Self>),
    /// A closed record type `{ field : T, ... }`. Fields are `(name, type)` pairs
    /// in source order; the empty record is outside the grammar so the list is
    /// non-empty. A field type variable participates in the binding's
    /// quantification exactly like one in any other position.
    Record(Vec<(Symbol, Self)>),
    /// A row-polymorphic (open) record type `{ r | field : T, ... }`. The first
    /// element is the row variable; the fields are the ones the annotation
    /// constrains. The row variable and any field type variables are quantified
    /// by the binding exactly like a top-level [`Self::Var`]. The type layer
    /// turns this into an [`crate`]-independent `Ty::Record(_, RowTail::Open)`.
    RecordOpen(Symbol, Vec<(Symbol, Self)>),
}

#[cfg(test)]
mod is_irrefutable_tests {
    use super::*;
    use ipe_diagnostics::{Located, Span};
    use ipe_intern::Symbol;

    fn sp<T>(v: T) -> Located<T> {
        Located::new(Span::new(0, 0), v)
    }

    fn sym(n: u32) -> Symbol {
        Symbol::from_raw(n)
    }

    #[test]
    fn var_and_anything_and_record_are_irrefutable() {
        assert!(Pattern_::PVar(sym(1)).is_irrefutable());
        assert!(Pattern_::PAnything.is_irrefutable());
        assert!(Pattern_::PRecord(vec![sp(sym(1)), sp(sym(2))]).is_irrefutable());
    }

    #[test]
    fn literals_and_ctor_and_list_and_cons_are_refutable() {
        assert!(!Pattern_::PInt(0).is_irrefutable());
        assert!(!Pattern_::PBool(true).is_irrefutable());
        assert!(!Pattern_::PChar("a".into()).is_irrefutable());
        assert!(!Pattern_::PStr("hi".into()).is_irrefutable());
        assert!(!Pattern_::PList(vec![]).is_irrefutable());
        assert!(
            !Pattern_::PCons(
                Box::new(sp(Pattern_::PVar(sym(1)))),
                Box::new(sp(Pattern_::PVar(sym(2)))),
            )
            .is_irrefutable()
        );
        assert!(
            !Pattern_::PCtor {
                home: vec![],
                type_name: sym(1),
                name: sym(2),
                index: 0,
                args: vec![],
            }
            .is_irrefutable()
        );
    }

    #[test]
    fn tuple_is_irrefutable_iff_every_element_is() {
        let all_binders =
            Pattern_::PTuple(vec![sp(Pattern_::PVar(sym(1))), sp(Pattern_::PAnything)]);
        assert!(all_binders.is_irrefutable());

        let with_literal =
            Pattern_::PTuple(vec![sp(Pattern_::PVar(sym(1))), sp(Pattern_::PInt(0))]);
        assert!(!with_literal.is_irrefutable());

        // Nested tuple: refutability propagates from the leaf.
        let nested_refutable = Pattern_::PTuple(vec![
            sp(Pattern_::PVar(sym(1))),
            sp(Pattern_::PTuple(vec![
                sp(Pattern_::PAnything),
                sp(Pattern_::PBool(false)),
            ])),
        ]);
        assert!(!nested_refutable.is_irrefutable());
    }

    #[test]
    fn alias_follows_its_inner_pattern() {
        let over_var = Pattern_::PAlias(Box::new(sp(Pattern_::PVar(sym(1)))), sp(sym(2)));
        assert!(over_var.is_irrefutable());

        let over_ctor = Pattern_::PAlias(
            Box::new(sp(Pattern_::PCtor {
                home: vec![],
                type_name: sym(1),
                name: sym(2),
                index: 0,
                args: vec![],
            })),
            sp(sym(3)),
        );
        assert!(!over_ctor.is_irrefutable());

        // Alias over an all-binder tuple stays irrefutable.
        let over_tuple = Pattern_::PAlias(
            Box::new(sp(Pattern_::PTuple(vec![
                sp(Pattern_::PVar(sym(1))),
                sp(Pattern_::PVar(sym(2))),
            ]))),
            sp(sym(3)),
        );
        assert!(over_tuple.is_irrefutable());
    }
}
