//! The two type levels of inference, ported from the supported subset of
//! `Ipe.Type.Type` (derivative of elm/compiler's `Type.Type`, BSD-3-Clause).
//!
//! * [`Ty`] — the *resolved*, immutable, canonical type read back after the
//!   solver settles. This is what [`crate::SolvedTypes`] hands to the lowerer.
//! * [`Content`] / [`FlatType`] — the *solver-level* descriptors stored inside
//!   union-find nodes during inference. The lattice spans functions,
//!   type-constructor applications, unit, tuples, records with a row tail, and
//!   super-typed variables (`comparable` / `number`, see [`TyBounds`]).
//!
//! # Open records (`RoutedWebApp` / row-poly)
//!
//! Row-polymorphic records mirror `../ipe`'s `TRecord (Map …) (Maybe var)` /
//! `Record1 map var` / `EmptyRecord1`.
//!
//! * [`RowTail::Closed`] — field set is exact (the common case for all
//!   user-written records).
//! * [`RowTail::Open(u32)`] — the record can absorb extra fields via the row
//!   variable whose representative id is carried here; the `u32` is consistent
//!   with [`Ty::Var`]'s id space.
//!
//! At the solver level, [`FlatType::EmptyRecord`] is the closed-tail sentinel
//! (mirrors `EmptyRecord1`); an open tail is a plain [`Content::Flex`] variable.
//! The only open record currently is the `Web.tea` kernel cfg record, which
//! absorbs optional fields (`head` / `consoleAuth` / `guard` / `status` …)
//! without forcing every app to enumerate empty optionals.

use std::collections::BTreeMap;
use std::num::NonZeroU32;

use ipe_canon::ast as canon;
use ipe_intern::Symbol;

use crate::unionfind::VarId;

/// A resolved type (post-solve, immutable).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Ty {
    /// A type variable. Carries a raw `u32` from ONE OF TWO DISJOINT id
    /// spaces (AUD-13):
    ///
    /// 1. **Annotation-symbol space** — [`ipe_intern::Symbol::as_raw`] of a
    ///    source-level type-variable name (`a`, `msg`, `any`, a kernel
    ///    scheme's `tv_a`/`tv_e` placeholder, a declared ADT type param).
    ///    Every `Ty` built from a canonicalized annotation
    ///    ([`crate::ty::from_canon`], ctor schemes, kernel schemes) lives
    ///    here. [`crate::constrain::Builder::instantiate_in`]'s wildcard-
    ///    `"any"` detection is sound ONLY for ids from this space — it
    ///    resolves the raw through the interner and compares the string.
    /// 2. **Solver-representative space** — a [`crate::unionfind::VarId`]
    ///    (itself a bare `u32` alias, see `unionfind.rs`) surviving past
    ///    [`crate::constrain::zonk`]. These ids are tagged with
    ///    [`SOLVER_VAR_TAG`] before being stored here specifically so they
    ///    can NEVER numerically collide with an annotation-symbol raw and
    ///    misfire the wildcard-`any` check — both spaces are independent
    ///    small sequential counters starting at 0, so an untagged collision
    ///    is not just theoretical, it is a near-certainty on any
    ///    sufficiently large compiled program.
    ///
    /// A `Ty` containing a tagged (solver-space) `Var` must never be fed to
    /// `instantiate_in`/`instantiate_tracked`/`instantiate_logging_wildcards` — those
    /// only handle annotation-space ids. A tagged raw is an opaque key
    /// (`crate::doc::ty_to_doc`'s `VarNamer`, `SolvedTypes::poly_var_map`):
    /// readers compare it whole and never recover the bare
    /// [`crate::unionfind::VarId`].
    Var(u32),
    /// A function `arg -> result`.
    Fun(Box<Self>, Box<Self>),
    /// A type-constructor application. `module` is the defining module (empty
    /// for built-ins like `Int` / `String` that have no user home); `name` is
    /// the interned type name; `args` its type arguments.
    Con {
        module: Vec<Symbol>,
        name: Symbol,
        args: Vec<Self>,
    },
    /// The unit type `()`.
    Unit,
    /// An anonymous product (tuple) type `(T1, T2, ...)`. Invariant: arity ≥ 2 —
    /// a 0-tuple is [`Ty::Unit`] and a 1-tuple is just its element.
    Tuple(Vec<Self>),
    /// A record type `{ x : Int, y : Bool }`, keyed by field name. The
    /// [`BTreeMap`] fixes iteration order (by [`Symbol`]); consumers that need a
    /// source-like order re-sort by the resolved field name.
    ///
    /// The [`RowTail`] distinguishes closed records (most user records — field
    /// set exact) from open records (kernel cfg records that absorb optional
    /// extra fields via a row variable).
    Record(BTreeMap<Symbol, Self>, RowTail),
}

/// Reserved high bit marking a [`Ty::Var`] raw as solver-representative space
/// (a tagged [`VarId`]) rather than annotation-symbol space (a
/// [`ipe_intern::Symbol`] raw). See [`Ty::Var`]'s doc comment (AUD-13) for the
/// full rationale. Both id spaces are independent counters starting at 0 and
/// allocate nowhere near 2^31 entries in any real compiled program, so this
/// bit can never collide with a genuine id from either space.
const SOLVER_VAR_TAG: u32 = 1 << 31;

// The tag is a single non-zero bit, so every id below it is untagged and
// `VarCeiling::SOLVER` is exactly the count of distinct tagged ids.
// IPE-RUST-AUDIT:ACCEPTED — compile-time `const` assertion (not a runtime panic); it fails the build if the tag stops being a single non-zero bit
const _: () = assert!(SOLVER_VAR_TAG.is_power_of_two() && SOLVER_VAR_TAG > 0);

/// Tag a solver [`VarId`] for storage in a [`Ty::Var`].
///
/// Marks it as solver-representative space (from [`crate::constrain::zonk`])
/// so `instantiate_in`'s wildcard-`"any"` check cannot misinterpret it as an
/// annotation symbol.
#[must_use]
pub const fn tag_solver_var(id: VarId) -> u32 {
    id | SOLVER_VAR_TAG
}

/// True iff a [`Ty::Var`] raw is solver-representative space.
///
/// I.e. tagged by [`tag_solver_var`] rather than an annotation-symbol raw.
/// Callers that resolve a `Ty::Var` raw through the interner (e.g. the
/// wildcard-`"any"` check) MUST skip that resolution when this returns
/// true — a tagged raw is structurally guaranteed to never be a real
/// interned symbol. Every table keyed by solver variables
/// (`SolvedTypes::poly_var_map`) stores the tagged form only, so a reader
/// answers for a tagged raw by exact lookup and for an untagged raw (an
/// annotation symbol) not at all; probing both forms would match a symbol
/// against a variable key.
#[must_use]
pub const fn is_solver_var(raw: u32) -> bool {
    raw & SOLVER_VAR_TAG != 0
}

/// A solver variable as a table key: always the tagged raw `zonk` writes into a [`Ty::Var`].
///
/// The field is private, so a key is built only from a [`VarId`] (tagging
/// it) or from a raw that already carries the tag; an annotation-symbol raw
/// has no `SolverVar`. A table keyed by solver variables
/// (`SolvedTypes::poly_var_map`) therefore cannot hold, or be probed with,
/// an untagged raw.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct SolverVar(u32);

impl SolverVar {
    /// The key of a union-find variable.
    #[must_use]
    pub const fn from_var(id: VarId) -> Self {
        Self(tag_solver_var(id))
    }

    /// The key a [`Ty::Var`] raw names, or `None` for an annotation-symbol raw.
    #[must_use]
    pub const fn from_raw(raw: u32) -> Option<Self> {
        if is_solver_var(raw) {
            Some(Self(raw))
        } else {
            None
        }
    }

    /// The tagged [`Ty::Var`] raw.
    #[must_use]
    pub const fn raw(self) -> u32 {
        self.0
    }
}

/// The exclusive upper bound on the dense ids a renumbering may mint.
///
/// Held in `1..=SOLVER_VAR_TAG`: an id below the bound never carries the tag
/// bit, so tagging it can neither alias another id nor read back as an
/// annotation symbol. Built only through [`Self::SOLVER`] or [`Self::at_most`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct VarCeiling(u32);

impl VarCeiling {
    /// The full solver-variable space: ids `0..2^31`.
    pub const SOLVER: Self = Self(SOLVER_VAR_TAG);

    /// A ceiling of `n` ids, clamped to the solver-variable space.
    #[must_use]
    pub const fn at_most(n: NonZeroU32) -> Self {
        if n.get() > SOLVER_VAR_TAG {
            Self::SOLVER
        } else {
            Self(n.get())
        }
    }

    /// The exclusive upper bound.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// The tail of a record type's row variable — whether the record is closed
/// (field set exact) or open (extra fields flow into a named row variable).
///
/// Mirrors `Maybe String` on `TRecord (Map …) (Maybe String)` in
/// `../ipe/src/Ipe/AST/Canonical.hs:159`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum RowTail {
    /// Closed record — no extension variable; the field set is exact.
    /// Corresponds to `Nothing` on the reference compiler `TRecord` / `EmptyRecord1`
    /// at the solver level.
    Closed,
    /// Open record — extra fields are absorbed by the row variable whose raw
    /// representative id is carried here. The id space is the same as
    /// [`Ty::Var`]'s, so `Open(n)` is the open tail linked to type variable
    /// `n`. Corresponds to `Just var` / `Content::Flex` at the solver level.
    Open(u32),
}

/// The field names of the kernel-managed `RetryPolicy e` record.
///
/// In [`BTreeMap`]/alphabetical order — the order the emitted Rust struct also
/// uses: `{ baseMs : Int, maxAttempts : Int, shouldRetry : e -> Bool,
/// strategy : BackoffStrategy }`.
///
/// This is the single source of truth for the field-name set. The type
/// checker interns exactly these strings for the `RetryPolicy` scheme, and the
/// lowering gate recognises the closed record by matching this exact set — a
/// record that is not exactly these four closed fields is not a `RetryPolicy`
/// and must not take the kernel-struct exemption.
pub const RETRY_POLICY_FIELDS: [&str; 4] = ["baseMs", "maxAttempts", "shouldRetry", "strategy"];

/// The super-type obligations a type variable carries: the operations a body
/// performs on it that only *some* types support.
///
/// A bare type variable is structurally parametric — the body passes it through
/// untouched, so any type works. The moment a body adds it (`x + x`), orders
/// it (`a > b`), or compares it for equality (`a == b`), the variable is no
/// longer "any type": it must be a type that supports that operation. Ipê's
/// relevant super-types are **Number** (the numeric operators `+ - *`, satisfied
/// by `Int` / `Float`), **Comparable** (the ordering comparisons `< > <= >=`,
/// satisfied by the scalar primitives), and **Equatable** (the equality
/// comparisons `== /=`, satisfied by every non-function type — Rust's
/// `PartialEq` is derivable for primitives, tuples, records, and enums but never
/// for a function).
///
/// Each obligation is one bit, so two variables that unify merge their
/// obligations with a bitwise OR ([`Self::union`]) — the merged variable owes
/// everything either side owed. The set is read back when generalising: a
/// variable that owes `Add` becomes a generic parameter bounded by Rust's
/// `Add` trait, and so on.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct TyBounds(u16);

impl TyBounds {
    const ADD: u16 = 1 << 0;
    const SUB: u16 = 1 << 1;
    const MUL: u16 = 1 << 2;
    const ORD: u16 = 1 << 3;
    const EQ: u16 = 1 << 4;
    const SET_ELEM: u16 = 1 << 5;
    const DICT_KEY: u16 = 1 << 6;
    const SHOW: u16 = 1 << 7;
    /// The append obligation (`++` → `Appendable a ⊇ { String, List a }`).
    const APPEND: u16 = 1 << 8;
    /// The higher-order-kernel callback-result obligation.
    ///
    /// This variable is the final RESULT of a callback arrow that a
    /// higher-order kernel FULLY APPLIES at runtime — `b` in `List.map`'s
    /// `(a -> b)`, the accumulator in `foldl`'s `(a -> b -> b)`, `v` in
    /// `map2..5`'s `(a -> … -> v)`, and `b` in `andMap`'s payload
    /// `Con (a -> b)`. `StdlibKernel::hof_result_vars` derives the set from
    /// each kernel's scheme shape. It must not itself be a function: every
    /// such runtime kernel takes an exact-arity closure, while the IR
    /// FLATTENS a curried Ipê function into one multi-parameter `Fun` — so a
    /// callback with residual arity (its result is another arrow) has no
    /// sound lowering and would reach `cargo build` as E0593/E0277/E0308.
    /// A callback whose result is `Con`-headed in the scheme (`andThen`,
    /// `traverse`) needs no bit: a curried callback there is already a plain
    /// type mismatch. `Task`/`Cmd`/`Sub`/`Decoder` kernels box their
    /// callbacks and are exempt. Deliberately SHALLOW on structure
    /// (only the head, never nested — see [`Self::has_hof_kernel_result`]):
    /// a collection-of-functions payload is a different, already-gated
    /// hazard. Fails CLOSED on a bare variable, exactly like every sibling
    /// bit. See `docs/adr/0001-language-semantics-and-types.md`.
    const HOF_KERNEL_RESULT: u16 = 1 << 9;
    /// The SQL-bind-parameter obligation: this variable is the ELEMENT type of
    /// a `List a` argument bound into `Db.exec` / `Db.query` / `Db.queryDecode`'s
    /// params position (raw scheme-var 0 for `exec`/`query`, var 1 for
    /// `queryDecode`). The Rust runtime can bind a bare `String` / `Int` /
    /// `Float` / `Bool` or the `SqlValue` ADT as a SQL parameter (each has a
    /// `From<T> for SqlParam` impl in `ipe_runtime::db`); nothing else does.
    /// Backend realises this as `T{n}: Into<ipe_runtime::db::SqlParam>`.
    /// Mirrors the Set/Dict comparable-key obligation shape: attached to a
    /// kernel's scheme var, propagated through union-find unification, and
    /// (unlike the comparable-key obligations) defaulted to `SqlValue` when a
    /// call-site instantiation is left completely unconstrained (an empty
    /// `List a` argument) — see the `sql_param` arm of the numeric-defaulting
    /// loop in `crate::lib`.
    const SQL_PARAM: u16 = 1 << 10;
    /// The interpolation obligation: this variable is rendered by `{{…}}`
    /// string interpolation or passed as a `Log.*With` attribute. Satisfied by
    /// exactly the closed scalar set in `crate::super_bounds::INTERPOLABLE`
    /// (`String`, `Int`, `Float`, `Bool`, `Char`); the backend realises it as
    /// the sealed runtime trait `IpeInterpolate`, implemented for those five
    /// types only. Defaulted to `String` when a call-site instantiation is
    /// left completely unconstrained (an empty `Log.*With` attribute list).
    const INTERPOLABLE: u16 = 1 << 11;

    /// No obligation — a structurally-parametric variable.
    pub const EMPTY: Self = Self(0);

    /// The single-obligation sets, one per operator family.
    #[must_use]
    pub const fn add() -> Self {
        Self(Self::ADD)
    }
    #[must_use]
    pub const fn sub() -> Self {
        Self(Self::SUB)
    }
    #[must_use]
    pub const fn mul() -> Self {
        Self(Self::MUL)
    }
    /// The ordering obligation (`< > <= >=` → Rust `PartialOrd`).
    #[must_use]
    pub const fn ord() -> Self {
        Self(Self::ORD)
    }
    /// The equality obligation (`== /=` → Rust `PartialEq`).
    #[must_use]
    pub const fn eq() -> Self {
        Self(Self::EQ)
    }
    /// The Set-element obligation: this variable is used as a `Set` element, so
    /// it must be a Ipê `comparable` whose Rust backing — `BTreeSet<A>` —
    /// requires `A : Ord`. Distinct from [`Self::ord`] (which renders Rust
    /// `PartialOrd`, insufficient for `BTreeSet`'s key requirement): a generic
    /// `a -> Set a` must lift `Ord` onto its emitted type parameter.
    #[must_use]
    pub const fn set_elem() -> Self {
        Self(Self::SET_ELEM)
    }
    /// The Dict-key obligation: this variable is used as a `Dict` key, so it
    /// must be a Ipê `comparable` whose Rust backing — `HashMap<K, V>` with
    /// determinism-sorted key iteration — requires `K : Hash + Eq + Ord`.
    /// Distinct from [`Self::ord`] / [`Self::eq`] (which render `PartialOrd` /
    /// `PartialEq`, neither of which satisfies `HashMap`'s `Hash + Eq` nor the
    /// sorted-iteration `Ord`): a generic `a -> Dict a v` must lift the full
    /// trait set onto its emitted type parameter.
    #[must_use]
    pub const fn dict_key() -> Self {
        Self(Self::DICT_KEY)
    }
    /// The stringify obligation (`Debug.log` / `Error.toString` → Rust
    /// `IpeStringify`). Satisfied by every NON-FUNCTION type — every scalar
    /// primitive plus every codegen-emitted record/ADT gets a `IpeStringify` impl;
    /// a bare function does not. Same head/deep discipline as [`Self::eq`]: a
    /// function at the head (or nested) fails closed at type-check rather than
    /// emitting an unbounded generic `cargo` rejects.
    #[must_use]
    pub const fn show() -> Self {
        Self(Self::SHOW)
    }
    /// The append obligation (`++`). Satisfied by `String` and `List a` only.
    /// The lowerer dispatches to [`ipe_ir::BinOp::Append`] for `String` and
    /// [`ipe_ir::KernelFn::ListAppend`] for `List a`.
    #[must_use]
    pub const fn appendable() -> Self {
        Self(Self::APPEND)
    }
    /// The higher-order-kernel callback-result obligation — see
    /// [`Self::HOF_KERNEL_RESULT`].
    #[must_use]
    pub const fn hof_kernel_result() -> Self {
        Self(Self::HOF_KERNEL_RESULT)
    }
    /// The SQL-bind-parameter obligation — see [`Self::SQL_PARAM`].
    #[must_use]
    pub const fn sql_param() -> Self {
        Self(Self::SQL_PARAM)
    }
    /// The interpolation obligation — see [`Self::INTERPOLABLE`].
    #[must_use]
    pub const fn interpolable() -> Self {
        Self(Self::INTERPOLABLE)
    }

    /// Whether this set carries no obligation at all.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
    #[must_use]
    pub const fn has_add(self) -> bool {
        self.0 & Self::ADD != 0
    }
    #[must_use]
    pub const fn has_sub(self) -> bool {
        self.0 & Self::SUB != 0
    }
    #[must_use]
    pub const fn has_mul(self) -> bool {
        self.0 & Self::MUL != 0
    }
    #[must_use]
    pub const fn has_ord(self) -> bool {
        self.0 & Self::ORD != 0
    }
    #[must_use]
    pub const fn has_eq(self) -> bool {
        self.0 & Self::EQ != 0
    }
    /// Whether the Set-element obligation is set.
    #[must_use]
    pub const fn has_set_elem(self) -> bool {
        self.0 & Self::SET_ELEM != 0
    }
    /// Whether the Dict-key obligation is set.
    #[must_use]
    pub const fn has_dict_key(self) -> bool {
        self.0 & Self::DICT_KEY != 0
    }
    /// Whether the stringify obligation is set (`→ Rust IpeStringify`).
    #[must_use]
    pub const fn has_show(self) -> bool {
        self.0 & Self::SHOW != 0
    }
    /// Whether the append obligation is set (`++` on `String` or `List _`).
    #[must_use]
    pub const fn has_append(self) -> bool {
        self.0 & Self::APPEND != 0
    }
    /// Whether the higher-order-kernel callback-result obligation is set —
    /// see [`Self::HOF_KERNEL_RESULT`].
    #[must_use]
    pub const fn has_hof_kernel_result(self) -> bool {
        self.0 & Self::HOF_KERNEL_RESULT != 0
    }
    /// Whether the SQL-bind-parameter obligation is set — see
    /// [`Self::SQL_PARAM`].
    #[must_use]
    pub const fn has_sql_param(self) -> bool {
        self.0 & Self::SQL_PARAM != 0
    }
    /// Whether the interpolation obligation is set — see
    /// [`Self::INTERPOLABLE`].
    #[must_use]
    pub const fn has_interpolable(self) -> bool {
        self.0 & Self::INTERPOLABLE != 0
    }
    /// Whether this variable carries a Ipê `comparable`-key obligation — used as
    /// a `Set` element or a `Dict` key. Both are satisfied by exactly the Ipê
    /// `comparable` scalar primitives at type-check; the per-container Rust
    /// trait differences (`Ord` vs `Hash + Eq + Ord`) surface only at emission.
    #[must_use]
    pub const fn has_comparable_key(self) -> bool {
        self.0 & (Self::SET_ELEM | Self::DICT_KEY) != 0
    }

    /// Whether any numeric operator (`+ - *`) constrains this variable — i.e. it
    /// must be a `Number` (`Int` / `Float`).
    #[must_use]
    pub const fn has_number(self) -> bool {
        self.0 & (Self::ADD | Self::SUB | Self::MUL) != 0
    }

    /// The union of two obligation sets — what a merged variable owes.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Every individual obligation bit as a single-bit set, one entry per raw
    /// flag. The use-site super-bound gate's completeness test walks this so a
    /// newly-added bit that no gate clause covers fails the build (an uncovered
    /// bit would vacuously admit a function type at a generic emission — the
    /// exact ipe-accepts-then-cargo-rejects seal break this guards).
    pub const ALL_BITS: &'static [Self] = &[
        Self(Self::ADD),
        Self(Self::SUB),
        Self(Self::MUL),
        Self(Self::ORD),
        Self(Self::EQ),
        Self(Self::SET_ELEM),
        Self(Self::DICT_KEY),
        Self(Self::SHOW),
        Self(Self::APPEND),
        Self(Self::HOF_KERNEL_RESULT),
        Self(Self::SQL_PARAM),
        Self(Self::INTERPOLABLE),
    ];

    /// The OR of every real obligation flag — the SSOT the completeness link
    /// checks [`Self::ALL_BITS`] against. A new `1 << n` flag added with its
    /// `has_*` accessor and gate clause but forgotten in `ALL_BITS` would leave
    /// the use-site-clause walk vacuous (fail-open — the flag's clause admits a
    /// function type unchecked); listing the new flag here without also adding
    /// its `ALL_BITS` entry breaks the `build` below instead.
    const ALL: u16 = Self::ADD
        | Self::SUB
        | Self::MUL
        | Self::ORD
        | Self::EQ
        | Self::SET_ELEM
        | Self::DICT_KEY
        | Self::SHOW
        | Self::APPEND
        | Self::HOF_KERNEL_RESULT
        | Self::SQL_PARAM
        | Self::INTERPOLABLE;

    /// The OR-fold of every entry in [`Self::ALL_BITS`] — a `const fn` so the
    /// completeness link below is a compile-time check, not a skippable test.
    const fn all_bits_union() -> u16 {
        let mut acc = 0u16;
        let mut rest = Self::ALL_BITS;
        while let [first, tail @ ..] = rest {
            acc |= first.0;
            rest = tail;
        }
        acc
    }
}

/// Build-time completeness link: `ALL_BITS` must enumerate EXACTLY the flags in
/// `ALL`, each exactly once. The union equality catches a flag left out of (or
/// duplicated in) `ALL_BITS`; the length-vs-popcount equality additionally
/// rejects a duplicate entry that would still union to `ALL`. Either drift
/// fails the build, so the use-site-clause completeness walk can never pass
/// vacuously over a missing bit.
const _: () = {
    // IPE-RUST-AUDIT:ACCEPTED compile-time completeness assert — a `const` build
    // check evaluated at compile time, never a runtime panic path. The union
    // equality catches a flag left out of (or duplicated in) `ALL_BITS`; the
    // length-vs-popcount equality additionally rejects a duplicate that would
    // still union to `ALL`. Either drift fails the build.
    assert!(
        TyBounds::all_bits_union() == TyBounds::ALL
            && TyBounds::ALL_BITS.len() == TyBounds::ALL.count_ones() as usize,
        "TyBounds::ALL_BITS must enumerate exactly the flags in TyBounds::ALL, each \
         once — a flag added to ALL without an ALL_BITS entry, or a duplicate/missing \
         single-bit entry, breaks this build"
    );
};

/// What a union-find variable resolves to during inference.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Content {
    /// An unconstrained (flexible) inference variable.
    Flex,
    /// A *rigid* (skolem) variable minted from a user annotation's type variable
    /// while checking that binding's body. Mirrors the compiler `Content.RigidVar`.
    ///
    /// A rigid variable may unify with a flexible one (the flex adopts it), but
    /// never with a concrete [`FlatType`] nor with a *different* rigid — so a body
    /// cannot force an annotated `a` to a concrete shape (`f : a -> a; f x = x + 1`
    /// is a mismatch, not silently accepted) nor collapse two distinct annotated
    /// variables (`f : a -> b; f x = x` is a mismatch). Distinctness is by
    /// union-find identity: two occurrences of the *same* annotation variable
    /// share one rigid node (via the per-signature instantiation map), so they are
    /// `equivalent`; two different variables are separate nodes that cannot unify.
    Rigid,
    /// A variable constrained to a Ipê super-type ([`TyBounds`]) but not yet
    /// pinned to a concrete structure. `rigid` distinguishes a super-typed
    /// *annotation skolem* (it must stay generic, surfacing its obligations as
    /// trait bounds on the emitted type parameter) from a super-typed *flex* (an
    /// inferred variable that may still pin to a matching concrete type).
    ///
    /// A super-typed flex pins to any structure that satisfies its obligations
    /// (`Int` / `Float` for Number; the scalar primitives for Comparable; any
    /// non-function type for Equatable); a
    /// super-typed rigid against a concrete structure is a mismatch, exactly as a
    /// plain rigid is — the annotation promised a generic the body is now trying
    /// to pin down.
    Super { rigid: bool, bounds: TyBounds },
    /// A resolved concrete structure.
    Structure(FlatType),
}

/// A concrete type structure whose children are union-find variables (so
/// unification can refine them in place). Mirrors the compiler `FlatType`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum FlatType {
    /// Function `arg -> result`.
    Fun(VarId, VarId),
    /// Type-constructor application over variable arguments.
    Con {
        module: Vec<Symbol>,
        name: Symbol,
        args: Vec<VarId>,
    },
    /// Unit `()`.
    Unit,
    /// Anonymous product (tuple) over variable elements. Invariant: arity ≥ 2.
    Tuple(Vec<VarId>),
    /// Record `{ name : var, ... }`, keyed by field name; each value is the
    /// union-find variable of that field's type, refined in place by
    /// unification. The second `VarId` is the **extension variable**: when it
    /// resolves to [`FlatType::EmptyRecord`] the record is closed (field set
    /// exact); when it resolves to [`Content::Flex`] the record is open and can
    /// absorb additional fields. This mirrors `Record1 (Map …) Variable` in
    /// `../ipe/src/Ipe/Type/Type.hs:75`.
    Record(BTreeMap<Symbol, VarId>, VarId),
    /// The closed-tail sentinel — mirrors `EmptyRecord1` in `Type.hs:75`.
    ///
    /// An extension variable that resolves to `EmptyRecord` means the record it
    /// belongs to is closed: no extra fields are allowed. A plain
    /// [`Content::Flex`] extension variable means the record is open.
    EmptyRecord,
}

/// Convert a canonical annotation type into a resolved [`Ty`].
///
/// Used to seed `env[update]` directly from its written signature and to
/// instantiate annotated parameter/return types into the solver. A type
/// variable's interned [`Symbol`] is carried through via its raw id so distinct
/// variables stay distinct.
#[must_use]
pub fn from_canon(t: &canon::Type) -> Ty {
    match t {
        canon::Type::Lambda(a, b) => Ty::Fun(Box::new(from_canon(a)), Box::new(from_canon(b))),
        canon::Type::Var(s) => Ty::Var(s.as_raw()),
        canon::Type::Con { home, name, args } => Ty::Con {
            module: home.clone(),
            name: *name,
            args: args.iter().map(from_canon).collect(),
        },
        canon::Type::Unit => Ty::Unit,
        canon::Type::Tuple(elems) => Ty::Tuple(elems.iter().map(from_canon).collect()),
        // A closed record annotation `{ field : T, ... }`. Keyed by field name in
        // the [`BTreeMap`] (fixing iteration order); a field type variable carries
        // through via its raw id exactly as a top-level [`canon::Type::Var`] does,
        // so an annotated record field var becomes a rigid skolem when the
        // signature is instantiated to check the body.
        // User-written annotations never carry a row tail, so always `RowTail::Closed`.
        canon::Type::Record(fields) => Ty::Record(
            fields
                .iter()
                .map(|(name, fty)| (*name, from_canon(fty)))
                .collect(),
            RowTail::Closed,
        ),
        // A row-polymorphic annotation `{ r | field : T, ... }` carries an OPEN
        // tail keyed by the row variable's raw id, so unification lets the
        // record absorb extra fields (mechanism 1, `unifyRecords`). The row var
        // is quantified by the binding's scheme exactly like a field type
        // variable, so instantiating the signature freshens the tail id per use
        // site — the same freshening the closed case gives its field vars.
        canon::Type::RecordOpen(row_var, fields) => Ty::Record(
            fields
                .iter()
                .map(|(name, fty)| (*name, from_canon(fty)))
                .collect(),
            RowTail::Open(row_var.as_raw()),
        ),
    }
}

#[cfg(test)]
mod aud13_tag_tests {
    use super::{SolverVar, is_solver_var, tag_solver_var};

    /// An annotation-symbol raw has no solver-variable key; a tagged raw is the key of its variable.
    #[test]
    fn solver_var_key_refuses_an_untagged_raw() {
        for id in [0u32, 7, 1_000_000, u32::MAX >> 1] {
            assert_eq!(
                SolverVar::from_raw(id),
                None,
                "untagged raw {id} is a symbol"
            );
            assert_eq!(
                SolverVar::from_raw(tag_solver_var(id)),
                Some(SolverVar::from_var(id)),
                "tagged raw names the key of variable {id}"
            );
            assert_eq!(SolverVar::from_var(id).raw(), tag_solver_var(id));
        }
    }

    #[test]
    fn tag_is_detectable_and_preserves_the_id_bits() {
        for raw in [0u32, 1, 42, 1_000_000, u32::MAX >> 1] {
            let tagged = tag_solver_var(raw);
            assert!(
                is_solver_var(tagged),
                "tagged raw must report as solver-space"
            );
            assert_eq!(
                tagged & !(1u32 << 31),
                raw,
                "tagging must only set the reserved bit, never touch the id's own bits"
            );
        }
    }

    #[test]
    fn untagged_raw_never_reports_as_solver_var() {
        for raw in [0u32, 1, 42, 1_000_000] {
            assert!(
                !is_solver_var(raw),
                "a plain annotation-symbol raw must never look tagged"
            );
        }
    }
}

#[cfg(test)]
mod var_ceiling_tests {
    use super::{SOLVER_VAR_TAG, VarCeiling};
    use std::num::NonZeroU32;

    /// A ceiling above the solver tag would let a dense id carry the tag bit, so it clamps to the tag.
    #[test]
    fn ceiling_never_exceeds_the_solver_tag() {
        for n in [SOLVER_VAR_TAG + 1, u32::MAX] {
            let Some(n) = NonZeroU32::new(n) else {
                return;
            };
            assert_eq!(VarCeiling::at_most(n), VarCeiling::SOLVER);
        }
        assert_eq!(VarCeiling::SOLVER.get(), SOLVER_VAR_TAG);
    }

    /// A ceiling at or below the tag is kept exactly.
    #[test]
    fn ceiling_below_the_tag_is_kept() {
        for n in [1, 2, 1_000, SOLVER_VAR_TAG] {
            let Some(nz) = NonZeroU32::new(n) else {
                return;
            };
            assert_eq!(VarCeiling::at_most(nz).get(), n);
        }
    }
}
