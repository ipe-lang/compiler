//! End-of-checking exhaustiveness + redundancy analysis for `case`.
//!
//! Runs after the constraint solver has settled, walking the canonical AST and
//! judging every `case` against the constructor signature of its scrutinee.
//! Two findings are surfaced, both as owned, structured diagnostics:
//!
//! * **IPE-T0010 `NonExhaustiveCase`** — the arms do not cover every value; the
//!   missing patterns are listed (in declaration order for the top column).
//! * **IPE-T0011 `RedundantCaseBranch`** — a later arm matches no value the
//!   earlier arms left open.
//!
//! ## Why a full usefulness algorithm (not a shallow head check)
//!
//! The Rust backend renders each `case` arm as a native `match` arm and relies
//! on rustc to type-check it; a Ipê `case` that is non-exhaustive over NESTED
//! patterns (`Just (Just a) -> …`, missing `Just Nothing`) would compile here
//! and then fail downstream with rustc's `E0004` — an exit-0-then-cargo-fail.
//! So this pass must be at least as strong as Rust's for nested patterns: it
//! ports Maranget's usefulness/matrix algorithm ("Warnings for pattern
//! matching", JFP 2007). The wildcard row `_` is *useful* against the arm
//! matrix exactly when the `case` is non-exhaustive, and the algorithm returns
//! the precise missing pattern(s) as the witness.
//!
//! ## Pattern abstraction
//!
//! Records are field-pun only in the source grammar, so a record pattern always
//! matches its (single-constructor) record value and binds variables only — it
//! is irrefutable. It therefore abstracts to a wildcard ([`UPat::Wild`]) for
//! coverage purposes. Tuples are single-constructor product types, abstracted to
//! [`UPat::Ctor`] with a [`Head::Tuple`] head whose element sub-patterns recurse.
//! ADT constructors abstract to [`Head::Adt`]. Literal patterns abstract to a
//! zero-arity head of their value, alias patterns are transparent (they cover
//! exactly their inner pattern), and list / cons patterns are judged with the
//! built-in closed `Nil | Cons` signature. Every pattern shape the grammar
//! admits in `case` is analysed here — so list/cons exhaustiveness is THIS
//! pass's responsibility (do not weaken it assuming the lowerer rejects them).

use std::collections::{BTreeMap, BTreeSet};

use ipe_canon::ast as canon;
use ipe_diagnostics::{DResult, Diagnostic, SortedNames, Span, TypeError};
use ipe_intern::{Interner, Symbol};

use crate::homed::{HomedWarning, InferError};
use crate::ty::Ty;

/// Solved scrutinee types, keyed the way [`crate::SolvedTypes::regions`] is:
/// `(owning-module home, expression span)`. A `case` scrutinee's entry gives
/// the pass the union identity a bare `_`-only match cannot recover from its
/// patterns.
type Regions = BTreeMap<(Vec<Symbol>, Span), Ty>;

/// `where_` tag for any internal-invariant bug raised while checking.
const STAGE: &str = "intern.resolve";

/// `where_` tag for a lookup the signature tables must answer but do not.
const SIGNATURE_STAGE: &str = "exhaust.signature";

/// The compiler bug a constructor absent from its union's signature raises.
///
/// Every ADT head the matrix walk meets names a constructor of a union in
/// [`Sigs`] at its declared arity: constraint generation refuses any other, and
/// witness heads are read back from the same tables. A miss or an arity
/// disagreement is therefore a broken invariant, refused rather than read as
/// arity `0`, an incomplete column, or a skipped `case`.
fn ctor_not_in_signature() -> Diagnostic {
    Diagnostic::CompilerBug {
        where_: SIGNATURE_STAGE,
        detail: "exhaust: constructor not in its union's signature".to_owned(),
    }
}

/// Upper bound on the number of distinct missing-pattern witnesses reported for
/// one non-exhaustive `case`. Keeps the diagnostic bounded (and the witness
/// search from fanning out) without losing the common small cases.
const WITNESS_CAP: usize = 32;

/// Work ceiling for the exhaustiveness analysis of a SINGLE `case`.
///
/// Or-pattern row expansion and the usefulness recursion are both worst-case
/// exponential in pattern breadth (`[True | False]` repeated N times expands to
/// `2^N` rows), so an adversarial-but-small `case` can otherwise exhaust memory
/// and abort the process instead of yielding a typed error. Every expanded row
/// and every usefulness node ticks one unit of this budget; exhausting it fails
/// closed with [`TypeError::StepBudgetExceeded`] rather than allocating without
/// bound. The ceiling is generous — a real `case` consumes a few dozen units —
/// so it never changes the accept/reject verdict of a normal match, only turns
/// a would-be out-of-memory death into a bounded diagnostic.
const DEFAULT_EXHAUST_BUDGET: u64 = 2_000_000;

/// Environment override for [`DEFAULT_EXHAUST_BUDGET`], mirroring the solver's
/// three-mode resolution (unset → default; `0` → unbounded; `N` → absolute).
const EXHAUST_BUDGET_ENV: &str = "IPE_EXHAUST_BUDGET";

/// Ceiling on the length of a list-literal pattern (`[e0, e1, …]`).
///
/// A flat `[e0, …, eN]` pattern desugars to a depth-`N` `Nil | Cons` spine, and
/// the usefulness walk descends one native recursion frame per spine level. The
/// per-node work budget bounds breadth but not native-stack depth, so an
/// otherwise-legal source file with a thousands-long list pattern would overflow
/// the native stack and abort the process. A list literal wider than this fails
/// closed with [`TypeError::StepBudgetExceeded`] — a typed limit far below native
/// stack capacity, well above any list pattern a real program writes by hand.
const MAX_LIST_PATTERN_LEN: usize = 1024;

/// A decrementing work budget for one `case`'s exhaustiveness analysis.
///
/// Each unit of expansion / usefulness work ticks it; reaching zero raises
/// [`TypeError::StepBudgetExceeded`] carrying the configured `limit` (so the
/// help line can name the value to raise). A `remaining` of `None` is disabled
/// (the `IPE_EXHAUST_BUDGET=0` escape hatch). This mirrors the solver's
/// [`crate::Budget`] so the two guard rails behave identically, but stays a
/// per-`case` counter so one large module's many small matches never share (and
/// prematurely exhaust) a single pool.
struct ExhaustBudget {
    remaining: Option<u64>,
    limit: u64,
}

impl ExhaustBudget {
    /// A budget with an explicit work cap.
    const fn with_limit(steps: u64) -> Self {
        Self {
            remaining: Some(steps),
            limit: steps,
        }
    }

    /// A disabled (unbounded) budget — never charges.
    const fn unbounded() -> Self {
        Self {
            remaining: None,
            limit: 0,
        }
    }

    /// A fresh per-`case` budget resolved from the environment (unset → default;
    /// `0` → unbounded; `N` → absolute; malformed → default).
    fn from_env() -> Self {
        ipe_env::var(EXHAUST_BUDGET_ENV).map_or_else(
            |_| Self::with_limit(DEFAULT_EXHAUST_BUDGET),
            |raw| match raw.trim().parse::<u64>() {
                Ok(0) => Self::unbounded(),
                Ok(n) => Self::with_limit(n),
                Err(_) => Self::with_limit(DEFAULT_EXHAUST_BUDGET),
            },
        )
    }

    /// Consume `n` units of work.
    ///
    /// # Errors
    /// [`TypeError::StepBudgetExceeded`] when the budget is exhausted, carrying
    /// the configured `limit`.
    const fn charge(&mut self, n: u64) -> DResult<()> {
        if let Some(remaining) = self.remaining.as_mut() {
            if let Some(next) = remaining.checked_sub(n) {
                *remaining = next;
            } else {
                *remaining = 0;
                return Err(Diagnostic::Type {
                    span: Span::DUMMY,
                    msg: TypeError::StepBudgetExceeded { budget: self.limit },
                });
            }
        }
        Ok(())
    }
}

/// A type's nominal identity: its DEFINING module (home) paired with its bare
/// name [`Symbol`]. Two modules each declaring `type Color` share the bare name
/// but differ in home, so keying the constructor tables by `(home, name)` —
/// never by `name` alone — keeps their constructor sets DISTINCT. A bare-`Symbol`
/// key would let the second `type Color` overwrite the first's variant set,
/// making a `case` over EITHER `Color` judged against the WRONG constructor set
/// (a spurious or missed IPE-T0010) once both are linked.
type TyId = (Vec<Symbol>, Symbol);

/// A union's identity paired with its constructors and their payload arities,
/// in declaration order.
type UnionSig<'a> = (&'a TyId, &'a [(Symbol, usize)]);

/// Constructor-signature tables, built once per module from its `type` decls.
struct Sigs {
    /// Home module → (constructor name → its owning union's identity). Nesting on
    /// the home path lets a lookup borrow the home as a `&[Symbol]` slice instead
    /// of cloning it to build a composite `(home, ctor)` key.
    ctor_to_union: BTreeMap<Vec<Symbol>, BTreeMap<Symbol, TyId>>,
    /// Union identity `(home, name)` → its constructors in declaration (`index`)
    /// order, each paired with its payload arity.
    union_ctors: BTreeMap<TyId, Vec<(Symbol, usize)>>,
    /// Home module → (constructor name → payload arity). Nested for the same
    /// borrow-not-clone lookup as `ctor_to_union`.
    ctor_arity: BTreeMap<Vec<Symbol>, BTreeMap<Symbol, usize>>,
}

impl Sigs {
    fn build(
        module: &canon::Module,
        extra_unions: &[&canon::Union],
        interner: &mut Interner,
    ) -> DResult<Self> {
        let mut ctor_to_union: BTreeMap<Vec<Symbol>, BTreeMap<Symbol, TyId>> = BTreeMap::new();
        let mut union_ctors: BTreeMap<TyId, Vec<(Symbol, usize)>> = BTreeMap::new();
        let mut ctor_arity: BTreeMap<Vec<Symbol>, BTreeMap<Symbol, usize>> = BTreeMap::new();

        // Seed EVERY Prelude-built-in closed union from the ONE shared table
        // (`ipe_canon::builtins`) that canon and lower also consume, so a `case`
        // over ANY of them — `Maybe` / `Result` / `SqlValue` / `ErrorKind` /
        // `ChunkEvent` / … — is ANALYSED for exhaustiveness rather than skipped
        // as an unknown-constructor scrutinee. A hand-kept subset here was the
        // drift that let a non-exhaustive `case` over a built-in ADT other than
        // Maybe/Result slip past this soundness floor and reach cargo as E0004.
        // `Bool` (`True` / `False`) is judged through the dedicated
        // [`Head::Bool`] literal path, so the shared table excludes it from the
        // exhaust unions (`exhaust_union == false`).
        //
        // Prelude built-ins carry the empty home (matching how canonicalisation
        // registers them with `home: Vec::new()`), so a `Just` pattern's
        // `(home=[], name=Just)` identity keys these entries.
        let builtins = ipe_canon::builtins::intern_builtins(interner)?;
        let ph: Vec<Symbol> = Vec::new();
        for (&union, ctors) in &builtins.exhaust_union_ctors {
            for &(ctor, arity) in ctors {
                ctor_to_union
                    .entry(ph.clone())
                    .or_default()
                    .insert(ctor, (ph.clone(), union));
                ctor_arity
                    .entry(ph.clone())
                    .or_default()
                    .insert(ctor, arity);
            }
            union_ctors.insert((ph.clone(), union), ctors.clone());
        }

        for union in module.unions.iter().chain(extra_unions.iter().copied()) {
            // The union's DEFINING module — its nominal identity is `(home, name)`,
            // distinct from a same-short-named type in another module.
            let uhome = union.home.clone();
            let ukey = (uhome.clone(), union.name);
            let mut ctors: Vec<&canon::Ctor> = union.ctors.iter().collect();
            ctors.sort_by_key(|c| c.index);
            let mut list = Vec::with_capacity(ctors.len());
            for c in ctors {
                ctor_to_union
                    .entry(uhome.clone())
                    .or_default()
                    .insert(c.name, ukey.clone());
                ctor_arity
                    .entry(uhome.clone())
                    .or_default()
                    .insert(c.name, c.arity);
                list.push((c.name, c.arity));
            }
            union_ctors.insert(ukey, list);
        }
        Ok(Self {
            ctor_to_union,
            union_ctors,
            ctor_arity,
        })
    }

    /// The payload arity of a head constructor.
    ///
    /// A [`Head::Tuple`] carries its own arity; an ADT head is looked up, and a
    /// miss is [`ctor_not_in_signature`].
    fn arity(&self, head: &Head) -> DResult<usize> {
        match head {
            Head::Tuple(n) => Ok(*n),
            Head::Adt(h, c) => self
                .ctor_arity
                .get(h.as_slice())
                .and_then(|by_ctor| by_ctor.get(c))
                .copied()
                .ok_or_else(ctor_not_in_signature),
            // Literal heads carry no sub-patterns; the empty-list `[]` (`Nil`) is
            // likewise nullary.
            Head::Bool(_) | Head::Int(_) | Head::Char(_) | Head::Str(_) | Head::Nil => Ok(0),
            // The cons constructor `head :: tail` carries the head element and the
            // tail list.
            Head::Cons => Ok(2),
        }
    }

    /// The union an ADT head's constructor belongs to, with its constructors.
    ///
    /// A miss is [`ctor_not_in_signature`].
    fn union_of(&self, home: &[Symbol], ctor: Symbol) -> DResult<UnionSig<'_>> {
        let union = self
            .ctor_to_union
            .get(home)
            .and_then(|by_ctor| by_ctor.get(&ctor))
            .ok_or_else(ctor_not_in_signature)?;
        let all = self
            .union_ctors
            .get(union)
            .ok_or_else(ctor_not_in_signature)?;
        Ok((union, all))
    }
}

/// A head constructor in the usefulness matrix.
#[derive(Clone, PartialEq, Eq)]
enum Head {
    /// An ADT constructor, identified by its owning type's HOME module plus the
    /// constructor name — the `(home, name)` nominal identity. Home is
    /// carried so two same-short-named types' constructors never conflate in the
    /// usefulness matrix.
    Adt(Vec<Symbol>, Symbol),
    /// The single constructor of a tuple type of the given arity.
    Tuple(usize),
    /// A boolean literal head — `Bool` is a CLOSED two-constructor type, so a
    /// `True` + `False` pair completes the signature.
    Bool(bool),
    /// An integer literal head. `Int` is an OPEN (infinite) type, so a literal
    /// column never completes a signature — a wildcard / var is required.
    Int(i64),
    /// A character literal head. OPEN, like [`Head::Int`].
    Char(String),
    /// A string literal head. OPEN, like [`Head::Int`].
    Str(String),
    /// The empty-list constructor `[]` (arity 0). `List` is the CLOSED
    /// two-constructor type `Nil | Cons`, so a [`Head::Nil`] + [`Head::Cons`]
    /// pair completes its signature.
    Nil,
    /// The cons constructor `head :: tail` (arity 2: the head element and the
    /// tail list).
    Cons,
}

/// A pattern abstracted for the usefulness algorithm: either a wildcard (which
/// also represents a variable binder and an always-matching record pattern) or a
/// head constructor applied to abstracted sub-patterns.
#[derive(Clone)]
enum UPat {
    Wild,
    Ctor(Head, Vec<Self>),
}

/// Abstract a resolved pattern into one-or-more [`UPat`] rows.
///
/// Every non-or pattern abstracts to a single [`UPat`] (variables, wildcards,
/// and field-pun records become [`UPat::Wild`]; constructor / tuple / list
/// patterns recurse). An **or-pattern** `p1 | p2 | …` expands by *row
/// expansion* — the standard Maranget treatment — into the union of its
/// alternatives' abstractions, so `A | B` becomes the two rows `A` and `B`. A
/// nested or-pattern inside a constructor / tuple / cons sub-position multiplies
/// its column, so the enclosing pattern expands into the **cartesian product**
/// over every sub-position's abstractions (two independent 2-way or-patterns in
/// one pattern produce 4 rows). Because the expanded matrix is literally the
/// one the hand-written alternatives would produce, the usefulness algorithm's
/// coverage / redundancy proofs carry over unchanged — no new [`Head`] and no
/// re-proving.
fn expand_upats(
    p: &canon::Pattern_,
    sigs: &Sigs,
    budget: &mut ExhaustBudget,
) -> DResult<Vec<UPat>> {
    match p {
        // The unit pattern matches the single value of the unit type, so — like a
        // wildcard, the dev-only `Debug._`, a variable, or a field-pun record —
        // it covers its whole type in one arm.
        canon::Pattern_::PAnything
        | canon::Pattern_::PDebugAnything
        | canon::Pattern_::PVar(_)
        | canon::Pattern_::PUnit
        | canon::Pattern_::PRecord(_) => {
            budget.charge(1)?;
            Ok(vec![UPat::Wild])
        }
        canon::Pattern_::PCtor {
            home, name, args, ..
        } => {
            // A constructor outside every signature, or one whose sub-pattern
            // count disagrees with its declared arity, is a broken invariant
            // (constraint generation already refused both): never padded,
            // truncated, or skipped.
            let head = Head::Adt(home.clone(), *name);
            if sigs.arity(&head)? != args.len() {
                return Err(ctor_not_in_signature());
            }
            let mut columns = Vec::with_capacity(args.len());
            for a in args {
                columns.push(expand_upats(&a.value, sigs, budget)?);
            }
            let combos = cartesian(columns, budget)?;
            Ok(combos
                .into_iter()
                .map(|combo| UPat::Ctor(head.clone(), combo))
                .collect())
        }
        canon::Pattern_::PTuple(elems) => {
            let mut columns = Vec::with_capacity(elems.len());
            for e in elems {
                columns.push(expand_upats(&e.value, sigs, budget)?);
            }
            let combos = cartesian(columns, budget)?;
            Ok(combos
                .into_iter()
                .map(|combo| UPat::Ctor(Head::Tuple(elems.len()), combo))
                .collect())
        }
        // Literal leaves abstract to a zero-arity head of their value.
        canon::Pattern_::PInt(n) => {
            budget.charge(1)?;
            Ok(vec![UPat::Ctor(Head::Int(*n), Vec::new())])
        }
        canon::Pattern_::PBool(b) => {
            budget.charge(1)?;
            Ok(vec![UPat::Ctor(Head::Bool(*b), Vec::new())])
        }
        canon::Pattern_::PChar(c) => {
            budget.charge(1)?;
            Ok(vec![UPat::Ctor(Head::Char(c.clone()), Vec::new())])
        }
        canon::Pattern_::PStr(s) => {
            budget.charge(1)?;
            Ok(vec![UPat::Ctor(Head::Str(s.clone()), Vec::new())])
        }
        // An alias is transparent for coverage — it matches exactly what its
        // inner pattern matches (and expands the same way).
        canon::Pattern_::PAlias(inner, _) => expand_upats(&inner.value, sigs, budget),
        // `List` is the closed two-constructor type `Nil | Cons`. A cons pattern
        // `head :: tail` abstracts to a [`Head::Cons`] over its two sub-patterns;
        // a list literal `[a, b, c]` desugars to the right-nested cons spine
        // `a :: b :: c :: []` so its coverage (and a missing-case witness) is
        // judged with the SAME `Nil | Cons` signature. Each sub-position expands,
        // so a nested or-pattern multiplies the rows cartesian-wise.
        canon::Pattern_::PCons(head, tail) => {
            let head_rows = expand_upats(&head.value, sigs, budget)?;
            let tail_rows = expand_upats(&tail.value, sigs, budget)?;
            let combos = cartesian(vec![head_rows, tail_rows], budget)?;
            Ok(combos
                .into_iter()
                .map(|combo| UPat::Ctor(Head::Cons, combo))
                .collect())
        }
        canon::Pattern_::PList(elems) => {
            // The spine this builds is as deep as the list is long, and the
            // usefulness walk recurses natively once per level. Refuse a spine
            // deep enough to overflow the native stack, before building it.
            if elems.len() > MAX_LIST_PATTERN_LEN {
                return Err(Diagnostic::Type {
                    span: Span::DUMMY,
                    msg: TypeError::StepBudgetExceeded {
                        budget: MAX_LIST_PATTERN_LEN as u64,
                    },
                });
            }
            let mut rows = vec![UPat::Ctor(Head::Nil, Vec::new())];
            for e in elems.iter().rev() {
                let heads = expand_upats(&e.value, sigs, budget)?;
                // Every product row is charged before allocation, so a breadth
                // blow-up (a wide list of or-patterns) fails closed rather than
                // exhausting memory.
                budget.charge((heads.len() as u64).saturating_mul(rows.len() as u64))?;
                let mut next = Vec::with_capacity(heads.len() * rows.len());
                for h in &heads {
                    for tail in &rows {
                        next.push(UPat::Ctor(Head::Cons, vec![h.clone(), tail.clone()]));
                    }
                }
                rows = next;
            }
            Ok(rows)
        }
        // An or-pattern expands to the union of its alternatives' rows.
        canon::Pattern_::POr(alts) => {
            let mut out = Vec::new();
            for a in alts {
                out.extend(expand_upats(&a.value, sigs, budget)?);
            }
            budget.charge(out.len() as u64)?;
            Ok(out)
        }
    }
}

/// The cartesian product of per-column row sets: given each sub-position's
/// abstraction rows, produce every combination that picks one row per position,
/// in column order. An empty input (a nullary constructor) yields the single
/// empty combination `[[]]`; an empty column (unreachable — every abstraction
/// yields ≥ 1 row) short-circuits to no combinations, keeping the function total.
fn cartesian(columns: Vec<Vec<UPat>>, budget: &mut ExhaustBudget) -> DResult<Vec<Vec<UPat>>> {
    let mut acc: Vec<Vec<UPat>> = vec![Vec::new()];
    for column in columns {
        // Charge the product size before allocating it, so a combinatorial
        // blow-up (independent or-patterns across sub-positions) surfaces a
        // typed limit error instead of an out-of-memory abort.
        budget.charge((acc.len() as u64).saturating_mul(column.len() as u64))?;
        let mut next = Vec::with_capacity(acc.len() * column.len());
        for prefix in &acc {
            for choice in &column {
                let mut row = prefix.clone();
                row.push(choice.clone());
                next.push(row);
            }
        }
        acc = next;
    }
    Ok(acc)
}

/// Locate the outermost **refutable** sub-pattern of a parameter / binder
/// pattern, returning its span, or `None` if the whole pattern is irrefutable.
///
/// This is a pure *blame-locator* — it runs only after
/// [`canon::Pattern_::is_irrefutable`] has already decided the pattern is
/// refutable, so it never influences the accept/reject decision (that is the
/// single shared predicate's job). It merely points the diagnostic at the most
/// specific offending node: for `(a, Just x)` it blames `Just x`, not the whole
/// tuple. Mirrors `is_irrefutable`'s structure so the two cannot diverge on
/// *which* nodes are refutable.
fn refutable_span(pat: &canon::Pattern) -> Option<Span> {
    match &pat.value {
        canon::Pattern_::PVar(_)
        | canon::Pattern_::PAnything
        | canon::Pattern_::PDebugAnything
        | canon::Pattern_::PUnit
        | canon::Pattern_::PRecord(_) => None,
        canon::Pattern_::PTuple(elems) => elems.iter().find_map(refutable_span),
        canon::Pattern_::PAlias(inner, _) => refutable_span(inner),
        canon::Pattern_::PCtor { .. }
        | canon::Pattern_::PInt(_)
        | canon::Pattern_::PBool(_)
        | canon::Pattern_::PChar(_)
        | canon::Pattern_::PStr(_)
        | canon::Pattern_::PList(_)
        | canon::Pattern_::PCons(_, _)
        // An or-pattern discriminates (it selects between alternatives), so in a
        // binding position it is refutable and blamed as a whole (IPE-T0015).
        | canon::Pattern_::POr(_) => Some(pat.span),
    }
}

/// The irrefutability gate for a **binding** position (a lambda / function-def
/// parameter or a `let` binder). A binding must match *every* value of its
/// type; a refutable pattern (`Just x`, `1`, `[a]`, `x :: xs`) is rejected here
/// — before lowering — as IPE-T0015, so a well-typed program can never fail a
/// pattern match at runtime (no emitted panic arm, no `DoS` surface).
///
/// The decision is [`canon::Pattern_::is_irrefutable`] — the ONE predicate the
/// lowerer also consumes, so the gate and the lowerer's capability set cannot
/// desync. [`refutable_span`] only refines the blame location.
///
/// # Errors
/// [`TypeError::RefutablePatternParameter`] (IPE-T0015) when `pat` is refutable.
fn check_param_irrefutable(pat: &canon::Pattern) -> DResult<()> {
    if pat.value.is_irrefutable() {
        return Ok(());
    }
    Err(Diagnostic::Type {
        span: refutable_span(pat).unwrap_or(pat.span),
        msg: TypeError::RefutablePatternParameter,
    })
}

/// Check every `case` in `module` for exhaustiveness + redundancy, and every
/// **parameter / binder** pattern for irrefutability (IPE-T0015).
///
/// `extra_unions` supplies union definitions declared outside `module` (a
/// scoped per-module solve passes its dependencies' interface unions;
/// the whole-program solve passes none — the linked merge already carries
/// every union), so a `case` over an imported ADT is analysed against the
/// full constructor signature instead of being skipped as unknown.
///
/// Redundant-branch findings ([`TypeError::RedundantCaseBranch`], IPE-T0011)
/// are pushed onto `warnings`, each paired with its owning definition's home,
/// instead of being returned as errors — they are severity-Warning and must not
/// abort compilation. A finding [`HomedWarning::new`] refuses (any non-Warning
/// severity) becomes the returned error instead.
///
/// Every returned source error is sited at the `home` of the definition that owns it. In a
/// linked program spans are byte offsets local to their own source file, so a
/// span alone cannot name its file: two modules overlap freely, and a finding
/// in one would otherwise be framed against whichever module's definition
/// happens to enclose the same offsets.
///
/// # Errors
/// * [`TypeError::RefutablePatternParameter`] when a param / binder is refutable.
/// * [`TypeError::NonExhaustiveCase`] when the arms miss a value.
/// * [`TypeError::WildcardCoversKnownConstructors`] (the first one, in
///   definition order) when a catch-all arm hides constructors of a closed union.
/// * [`InferError::Program`] carrying a [`Diagnostic::CompilerBug`] if a
///   constructor symbol cannot be resolved (it belongs to no single definition).
pub fn check(
    module: &canon::Module,
    extra_unions: &[&canon::Union],
    regions: &Regions,
    interner: &mut Interner,
    warnings: &mut Vec<HomedWarning>,
) -> Result<(), InferError> {
    let sigs = Sigs::build(module, extra_unions, interner).map_err(InferError::unsited)?;
    let mut first_error: Option<InferError> = None;
    for def in &module.defs {
        let home = def.home();
        let (patterns, body) = match def {
            canon::Def::Untyped { patterns, body, .. }
            | canon::Def::Typed { patterns, body, .. } => (patterns, body),
        };
        // Every function-def head parameter is a binding position.
        for p in patterns {
            check_param_irrefutable(p).map_err(|d| InferError::sited_at_path(d, home))?;
        }
        let mut findings: Vec<Diagnostic> = Vec::new();
        check_expr(body, home, &sigs, regions, interner, &mut findings)
            .map_err(|d| InferError::sited_at_path(d, home))?;
        for finding in findings {
            match HomedWarning::new(finding, home) {
                Ok(warning) => warnings.push(warning),
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
    }
    first_error.map_or(Ok(()), Err)
}

/// The read-only context threaded through the recursive `case` walk: the
/// signature tables, the owning module's `home` (the [`Regions`] key prefix),
/// the solved scrutinee-type map, and the interner. Bundling them keeps the
/// recursion's argument list to `(expr, ctx)`.
struct Ctx<'a> {
    sigs: &'a Sigs,
    home: &'a [Symbol],
    regions: &'a Regions,
    interner: &'a Interner,
}

/// Recursively check a single expression (and its sub-expressions) for `case`
/// defects. The recursion depth is bounded by the parser's nesting cap.
fn check_expr(
    e: &canon::Expr,
    home: &[Symbol],
    sigs: &Sigs,
    regions: &Regions,
    interner: &Interner,
    warnings: &mut Vec<Diagnostic>,
) -> DResult<()> {
    let ctx = Ctx {
        sigs,
        home,
        regions,
        interner,
    };
    check_expr_ctx(e, &ctx, warnings)
}

fn check_expr_ctx(e: &canon::Expr, ctx: &Ctx<'_>, warnings: &mut Vec<Diagnostic>) -> DResult<()> {
    match &e.value {
        canon::Expr_::Int(_)
        | canon::Expr_::Float(_)
        | canon::Expr_::Str(_)
        | canon::Expr_::CustomElementCtor(_)
        | canon::Expr_::Char(_)
        | canon::Expr_::Unit
        | canon::Expr_::VarLocal(_)
        | canon::Expr_::VarTopLevel { .. }
        | canon::Expr_::VarKernel { .. }
        | canon::Expr_::VarCtor { .. } => Ok(()),
        canon::Expr_::Call(callee, args) => {
            check_expr_ctx(callee, ctx, warnings)?;
            for a in args {
                check_expr_ctx(a, ctx, warnings)?;
            }
            Ok(())
        }
        // An FFI wrapper call has no callee sub-expression; only its value
        // arguments carry checkable structure.
        canon::Expr_::ForeignCall { args, .. } => {
            for a in args {
                check_expr_ctx(a, ctx, warnings)?;
            }
            Ok(())
        }
        canon::Expr_::Binop { lhs, rhs, .. } => {
            check_expr_ctx(lhs, ctx, warnings)?;
            check_expr_ctx(rhs, ctx, warnings)
        }
        canon::Expr_::Case(scrut, branches) => {
            check_case(scrut, branches, ctx, warnings)?;
            check_expr_ctx(scrut, ctx, warnings)?;
            for br in branches {
                check_expr_ctx(&br.body, ctx, warnings)?;
            }
            Ok(())
        }
        canon::Expr_::Let(bindings, body) => {
            // A `let` binder is a binding position: it must be irrefutable (a name
            // or an irrefutable destructure). Assert that invariant here — a
            // refutable `let (Just x) = …` is IPE-T0015, not a latent runtime
            // panic. (`let f p = …` desugars to a name binder over a `Lambda`,
            // whose params are swept by the Lambda arm below.)
            for b in bindings {
                check_param_irrefutable(&b.pat)?;
                check_expr_ctx(&b.body, ctx, warnings)?;
            }
            check_expr_ctx(body, ctx, warnings)
        }
        canon::Expr_::If(branches, else_expr) => {
            for (cond, body) in branches {
                check_expr_ctx(cond, ctx, warnings)?;
                check_expr_ctx(body, ctx, warnings)?;
            }
            check_expr_ctx(else_expr, ctx, warnings)
        }
        canon::Expr_::Tuple(elems) | canon::Expr_::List(elems) => {
            for elem in elems {
                check_expr_ctx(elem, ctx, warnings)?;
            }
            Ok(())
        }
        canon::Expr_::Cons(head, tail) => {
            check_expr_ctx(head, ctx, warnings)?;
            check_expr_ctx(tail, ctx, warnings)
        }
        canon::Expr_::Record(fields) => {
            for (_, value) in fields {
                check_expr_ctx(value, ctx, warnings)?;
            }
            Ok(())
        }
        canon::Expr_::Lambda(params, body) => {
            // Every lambda parameter is a binding position — sweep each for
            // irrefutability (IPE-T0015) before recursing into the body. The
            // pre-existing arm dropped the params entirely.
            for p in params {
                check_param_irrefutable(p)?;
            }
            check_expr_ctx(body, ctx, warnings)
        }
        canon::Expr_::Access(record, _) => check_expr_ctx(record, ctx, warnings),
        canon::Expr_::Update(base, fields) => {
            check_expr_ctx(base, ctx, warnings)?;
            for (_, value) in fields {
                check_expr_ctx(value, ctx, warnings)?;
            }
            Ok(())
        }
    }
}

/// Check one `case`: first redundancy (a later arm useless against the earlier
/// ones), then exhaustiveness (the wildcard row useful against the whole arm
/// matrix), and finally the wildcard-covers-known-constructors lint. A `case`
/// mentioning a constructor outside every known signature is a `CompilerBug`
/// ([`ctor_not_in_signature`]), never skipped unjudged.
///
/// Redundant-branch findings are pushed onto `warnings` (IPE-T0011 is a
/// Warning-severity diagnostic that must not abort compilation).
/// Wildcard-lint findings (IPE-T0018) share that sink; [`check`] promotes the
/// first Error-severity one to its home-attributed `Err`.
fn check_case(
    scrut: &canon::Expr,
    branches: &[canon::CaseBranch],
    ctx: &Ctx<'_>,
    warnings: &mut Vec<Diagnostic>,
) -> DResult<()> {
    let sigs = ctx.sigs;
    let interner = ctx.interner;
    // A per-`case` work budget bounds both the or-pattern row expansion and the
    // usefulness walk. A crafted-but-small `case` (e.g. many independent
    // 2-alternative or-patterns whose product is exponential) would otherwise
    // allocate without ceiling and abort the process; exhausting the budget
    // instead surfaces IPE-T0003 (StepBudgetExceeded), fail-closed.
    let mut budget = ExhaustBudget::from_env();

    // Redundancy: an arm is redundant when its pattern is not useful against the
    // arms before it (those already cover every value it would match). An
    // or-pattern is checked at ALTERNATIVE granularity — each alternative
    // expands to its own row(s), so a covered alternative is flagged at its own
    // span even when the rest of the arm is still reachable (`Red | Green` then
    // `Green | Blue` flags only the second `Green`). The prior matrix grows one
    // row per expanded alternative, so no indexing is needed.
    //
    // The loop also collects `prior_heads_before` so the wildcard-covers-known-
    // constructors lint (IPE-T0018) can inspect, for each wildcard/variable arm,
    // which column heads appeared in the arms before it.
    let mut prior: Vec<Vec<UPat>> = Vec::new();
    // The span of the FIRST top-level catch-all arm — a bare `_` or a variable
    // binder that matches every value. The closed-union check (IPE-T0018) below
    // reports at this span. A `Debug._` catch-all is deliberately NOT recorded:
    // it is the explicit development-only escape hatch (release-rejected via the
    // `Debug.*` gate at lowering), so it must be exempt from the closed-union
    // error exactly as `Debug.log` is exempt from the ordinary kernel rules.
    let mut catch_all_span: Option<Span> = None;
    for br in branches {
        let is_top_level_catch_all = matches!(
            br.pat.value,
            canon::Pattern_::PAnything | canon::Pattern_::PVar(_)
        );
        if is_top_level_catch_all && catch_all_span.is_none() {
            catch_all_span = Some(br.pat.span);
        }

        // A tuple / record arm is reported through the dedicated multi-arm
        // product gate at lowering (IPE-L0115), which gives a clearer message
        // than "redundant branch"; redundancy reporting covers the constructor /
        // literal / wildcard / variable / alias arm shapes.
        let is_product = matches!(
            br.pat.value,
            canon::Pattern_::PTuple(_) | canon::Pattern_::PRecord(_)
        );
        // The redundancy unit is the alternative: `(span, label-pattern, rows)`.
        // A non-or arm is a single unit spanning the whole pattern.
        let units: Vec<(Span, &canon::Pattern_)> = match &br.pat.value {
            canon::Pattern_::POr(alts) => alts.iter().map(|a| (a.span, &a.value)).collect(),
            other => vec![(br.pat.span, other)],
        };
        for (span, unit_pat) in units {
            let rows = expand_upats(unit_pat, sigs, &mut budget)?;
            let mut alternative_covered = true;
            for row in &rows {
                if !useful(&prior, std::slice::from_ref(row), sigs, 1, &mut budget)?.is_empty() {
                    alternative_covered = false;
                    break;
                }
            }
            if !is_product && alternative_covered {
                // IPE-T0011 is Severity::Warning: collect it but do not abort.
                warnings.push(Diagnostic::Type {
                    span,
                    msg: TypeError::RedundantCaseBranch {
                        constructor: arm_label(unit_pat, interner)?,
                    },
                });
            }
            for row in rows {
                prior.push(vec![row]);
            }
        }
    }

    // Exhaustiveness: the wildcard row is useful against the arm matrix exactly
    // when some value escapes every arm. Each witness is a missing pattern. Every
    // branch expands (an or-pattern into one row per alternative), so an arm
    // enumerating a union via `A | B | C` covers all three constructors.
    let mut matrix: Vec<Vec<UPat>> = Vec::new();
    for br in branches {
        for p in expand_upats(&br.pat.value, sigs, &mut budget)? {
            matrix.push(vec![p]);
        }
    }
    let witnesses = useful(&matrix, &[UPat::Wild], sigs, WITNESS_CAP, &mut budget)?;
    if !witnesses.is_empty() {
        let mut missing: Vec<Box<str>> = Vec::with_capacity(witnesses.len());
        for w in &witnesses {
            // Each witness is a single-column row; render its one pattern.
            let head = w.first().unwrap_or(&UPat::Wild);
            missing.push(render_upat(head, interner, false)?.into_boxed_str());
        }
        return Err(Diagnostic::Type {
            span: scrut.span,
            msg: TypeError::NonExhaustiveCase {
                missing: SortedNames::new(missing),
            },
        });
    }

    // Catch-all-over-a-closed-union error (IPE-T0018): the `case` is exhaustive,
    // but a bare `_` / variable arm swallows one or more constructors a finite
    // closed union (a user `type` or a Prelude built-in ADT) could name
    // explicitly. Adding a variant to that union later would fall through the
    // catch-all silently — a make-invalid-states hazard — so this is an ERROR
    // (fail-closed), in both development and release builds. A `Debug._` arm is
    // the sanctioned dev-only escape and was excluded from `catch_all_span`.
    //
    // The union identity is taken from the SCRUTINEE'S SOLVED TYPE, not from the
    // constructor heads named in earlier arms. That closes the bare-`_`-only gap
    // — `case c of _ -> …` over a closed union names no constructor, so a
    // column-head-driven check saw nothing and let it through; the scrutinee's
    // settled type carries the union identity regardless.
    //
    // `Bool` and `List` are closed too, but frozen by the language — no one adds
    // a variant — so a catch-all over them is a safe idiom, not an evolution
    // hazard; they are `Head::Bool` / `Head::Nil` / `Head::Cons`, never a
    // `union_ctors` ADT entry, so they never reach this branch. Open types
    // (`Int` / `Char` / `String`) and tuples are likewise not ADT unions here.
    if let Some(span) = catch_all_span
        && let Some((union_key, all_ctors)) = scrutinee_union(scrut, ctx)?
    {
        // Constructors the arms name EXPLICITLY (a top-level constructor arm, or
        // any alternative of a top-level or-pattern). Whatever the catch-all
        // absorbs is the union set minus these.
        let mut named: BTreeSet<Symbol> = BTreeSet::new();
        for br in branches {
            collect_named_ctors(&br.pat.value, &mut named);
        }
        let uhome = &union_key.0;
        let remaining: Vec<UPat> = all_ctors
            .iter()
            .filter(|(name, _)| !named.contains(name))
            .map(|(name, ar)| UPat::Ctor(Head::Adt(uhome.clone(), *name), vec![UPat::Wild; *ar]))
            .collect();
        if !remaining.is_empty() {
            let mut ctors: Vec<Box<str>> = Vec::with_capacity(remaining.len());
            for p in &remaining {
                ctors.push(render_upat(p, interner, false)?.into_boxed_str());
            }
            warnings.push(Diagnostic::Type {
                span,
                msg: TypeError::WildcardCoversKnownConstructors {
                    constructors: SortedNames::new(ctors),
                },
            });
        }
    }

    Ok(())
}

/// The scrutinee's closed union, identity and constructors, or `None` when its
/// solved type is no union.
///
/// `None` is reached only through a named arm: an unsolved variable (the pass
/// cannot prove the domain is a finite closed union, so the ordinary
/// exhaustiveness check stands and no T0018 fires), a function, unit, tuple or
/// record, or a builtin head that carries no union (`Int`, `Dict`, `Html`, …).
///
/// The head is matched by [`crate::unify::con_heads_compatible`], the one
/// head-identity rule the solver unifies by: a builtin re-exported under a
/// stdlib home (`Ipe.Result exposing (Result(..))` solves to
/// `Con { module: [Ipe, Result], name: Result }`) is the empty-home builtin
/// union, so its catch-all is judged against the builtin's constructors.
///
/// # Errors
/// A [`Diagnostic::CompilerBug`] when the scrutinee has no recorded type, or
/// when its head is a declared type (a home no builtin answers to) absent from
/// [`Sigs`]: every union a module can reach is in its signature tables, so a
/// miss is a broken closure, never a type without constructors.
fn scrutinee_union<'a>(scrut: &canon::Expr, ctx: &'a Ctx<'_>) -> DResult<Option<UnionSig<'a>>> {
    let ty = ctx
        .regions
        .get(&(ctx.home.to_vec(), scrut.span))
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: SIGNATURE_STAGE,
            detail: "exhaust: case scrutinee has no solved type".to_owned(),
        })?;
    let (module, name) = match ty {
        // An unsolved scrutinee (`Var`): its domain is unknown, so no catch-all
        // can be proven to swallow a constructor. The structural types carry no
        // constructors at all.
        Ty::Var(_) | Ty::Fun(..) | Ty::Unit | Ty::Tuple(_) | Ty::Record(..) => return Ok(None),
        Ty::Con { module, name, .. } => (module, *name),
    };
    let lookup = |key: &TyId| {
        ctx.sigs
            .union_ctors
            .get_key_value(key)
            .map(|(k, ctors)| (k, ctors.as_slice()))
    };
    if let Some(hit) = lookup(&(module.clone(), name)) {
        return Ok(Some(hit));
    }
    if crate::unify::con_heads_compatible(module, name, &[], name, ctx.interner) {
        // A builtin head: the builtin union when it is one, else a builtin
        // without constructors.
        return Ok(lookup(&(Vec::new(), name)));
    }
    Err(Diagnostic::CompilerBug {
        where_: SIGNATURE_STAGE,
        detail: "exhaust: union head absent from the exhaustiveness signatures".to_owned(),
    })
}

/// Accumulate the constructor names a pattern refers to at the TOP column —
/// a constructor arm names its own constructor; an or-pattern contributes each
/// alternative's; an alias is transparent. Wildcards / variables / literals /
/// tuples / records name no ADT constructor. Only the head constructor matters
/// for the closed-union cover check (payload sub-patterns are irrelevant to
/// which top-level variants are explicitly handled).
fn collect_named_ctors(p: &canon::Pattern_, out: &mut BTreeSet<Symbol>) {
    match p {
        canon::Pattern_::PCtor { name, .. } => {
            out.insert(*name);
        }
        canon::Pattern_::PAlias(inner, _) => collect_named_ctors(&inner.value, out),
        canon::Pattern_::POr(alts) => {
            for a in alts {
                collect_named_ctors(&a.value, out);
            }
        }
        _ => {}
    }
}

/// Maranget usefulness with witness collection. Returns up to `cap` witness rows
/// — each a value vector matched by `q` but by no row of `matrix`. An empty
/// result means `q` is not useful (every value it matches is already covered).
///
/// `matrix` rows and `q` all share the same width; the recursion peels one
/// column at a time. The implementation is total (no panic, no raw indexing).
fn useful(
    matrix: &[Vec<UPat>],
    q: &[UPat],
    sigs: &Sigs,
    cap: usize,
    budget: &mut ExhaustBudget,
) -> DResult<Vec<Vec<UPat>>> {
    // One tick per recursion node bounds the walk's depth AND breadth: a deep
    // cons spine or a wide complete-signature fan-out each spend proportional
    // budget, so a pathological matrix fails closed instead of recursing until
    // the native stack or the allocator gives out.
    budget.charge(1)?;
    if cap == 0 {
        return Ok(Vec::new());
    }
    let Some((first, rest_q)) = q.split_first() else {
        // Base case: the empty row is useful iff the matrix has no rows.
        return Ok(if matrix.is_empty() {
            vec![Vec::new()]
        } else {
            Vec::new()
        });
    };

    match first {
        UPat::Ctor(c, args) => {
            let arity = sigs.arity(c)?;
            let specialised = specialise(matrix, c, arity);
            let mut sub_q = args.clone();
            sub_q.extend_from_slice(rest_q);
            Ok(useful(&specialised, &sub_q, sigs, cap, budget)?
                .into_iter()
                .map(|w| rebuild(c, arity, w))
                .collect())
        }
        UPat::Wild => {
            let roots = column_heads(matrix);
            if let Some(signature) = complete_signature(&roots, sigs)? {
                // The first column's constructors are complete: a witness must
                // refine the wildcard into one of them. Try each in turn.
                let mut out: Vec<Vec<UPat>> = Vec::new();
                for (head, arity) in signature {
                    let specialised = specialise(matrix, &head, arity);
                    let mut sub_q = vec![UPat::Wild; arity];
                    sub_q.extend_from_slice(rest_q);
                    for w in useful(&specialised, &sub_q, sigs, cap - out.len(), budget)? {
                        out.push(rebuild(&head, arity, w));
                        if out.len() >= cap {
                            return Ok(out);
                        }
                    }
                }
                Ok(out)
            } else {
                // The first column is missing constructors (or has none): drop it
                // via the default matrix and witness the gap with a missing head
                // (or a wildcard when the column carries no constructor).
                let defaulted = default_matrix(matrix);
                let tails = useful(&defaulted, rest_q, sigs, cap, budget)?;
                if tails.is_empty() {
                    return Ok(Vec::new());
                }
                let heads = missing_heads(&roots, sigs)?;
                let mut out: Vec<Vec<UPat>> = Vec::new();
                for head in &heads {
                    for tail in &tails {
                        let mut row = Vec::with_capacity(tail.len() + 1);
                        row.push(head.clone());
                        row.extend_from_slice(tail);
                        out.push(row);
                        if out.len() >= cap {
                            return Ok(out);
                        }
                    }
                }
                Ok(out)
            }
        }
    }
}

/// Specialise `matrix` by head constructor `c` (Maranget's `S(c, P)`): rows whose
/// first pattern is `c` expand its sub-patterns into the leading columns; rows
/// with a wildcard first contribute `arity` (the payload arity of `c`) fresh
/// wildcards; rows with a different head are dropped.
fn specialise(matrix: &[Vec<UPat>], c: &Head, arity: usize) -> Vec<Vec<UPat>> {
    let mut out = Vec::new();
    for row in matrix {
        let Some((first, rest)) = row.split_first() else {
            continue;
        };
        match first {
            UPat::Ctor(head, args) if head == c => {
                let mut new_row = args.clone();
                new_row.extend_from_slice(rest);
                out.push(new_row);
            }
            UPat::Ctor(_, _) => {}
            UPat::Wild => {
                let mut new_row = vec![UPat::Wild; arity];
                new_row.extend_from_slice(rest);
                out.push(new_row);
            }
        }
    }
    out
}

/// The default matrix (Maranget's `D(P)`): keep only rows whose first pattern is
/// a wildcard, dropping that column.
fn default_matrix(matrix: &[Vec<UPat>]) -> Vec<Vec<UPat>> {
    let mut out = Vec::new();
    for row in matrix {
        if let Some((UPat::Wild, rest)) = row.split_first() {
            out.push(rest.to_vec());
        }
    }
    out
}

/// The distinct head constructors appearing in `matrix`'s first column, in
/// first-seen order.
fn column_heads(matrix: &[Vec<UPat>]) -> Vec<Head> {
    let mut seen: Vec<Head> = Vec::new();
    for row in matrix {
        if let Some(UPat::Ctor(head, _)) = row.first()
            && !seen.contains(head)
        {
            seen.push(head.clone());
        }
    }
    seen
}

/// If the column's `roots` form a complete constructor signature, return the full
/// signature to branch over (each head with its arity), in declaration order for
/// ADTs. A tuple column has a single constructor and is always complete. An empty
/// or constructor-incomplete column returns `None` (use the default matrix); an
/// ADT head absent from `sigs` is [`ctor_not_in_signature`].
fn complete_signature(roots: &[Head], sigs: &Sigs) -> DResult<Option<Vec<(Head, usize)>>> {
    let Some(first) = roots.first() else {
        return Ok(None);
    };
    Ok(match first {
        Head::Tuple(n) => Some(vec![(Head::Tuple(*n), *n)]),
        // `Bool` is closed: the signature is complete once both `True` and
        // `False` appear in the column.
        Head::Bool(_) => {
            let has_true = roots.contains(&Head::Bool(true));
            let has_false = roots.contains(&Head::Bool(false));
            if has_true && has_false {
                Some(vec![(Head::Bool(true), 0), (Head::Bool(false), 0)])
            } else {
                None
            }
        }
        // Int / Char / String are OPEN — a finite set of literals never covers
        // the type, so the signature is never complete (a wildcard is required).
        Head::Int(_) | Head::Char(_) | Head::Str(_) => None,
        // `List` is closed: the signature is complete once BOTH `[]` (`Nil`) and
        // `_ :: _` (`Cons`) appear in the column.
        Head::Nil | Head::Cons => {
            let has_nil = roots.contains(&Head::Nil);
            let has_cons = roots.contains(&Head::Cons);
            if has_nil && has_cons {
                Some(vec![(Head::Nil, 0), (Head::Cons, 2)])
            } else {
                None
            }
        }
        Head::Adt(h, c) => {
            let (union, all) = sigs.union_of(h, *c)?;
            // The union's home fixes each missing/present head's identity. All
            // roots in one column share this union (the type checker pins the
            // scrutinee's type before exhaustiveness runs), so comparing bare
            // ctor names against `all` is sound.
            let uhome = &union.0;
            let present: BTreeSet<Symbol> = roots
                .iter()
                .filter_map(|h| match h {
                    Head::Adt(_, name) => Some(*name),
                    _ => None,
                })
                .collect();
            if all.iter().all(|(name, _)| present.contains(name)) {
                Some(
                    all.iter()
                        .map(|(name, ar)| (Head::Adt(uhome.clone(), *name), *ar))
                        .collect(),
                )
            } else {
                None
            }
        }
    })
}

/// The witness heads for an incomplete first column: each ADT constructor the
/// column is missing (with wildcard arguments), in declaration order — or a bare
/// wildcard when the column carries no constructor at all (nothing to refine).
/// An ADT head absent from `sigs` is [`ctor_not_in_signature`].
fn missing_heads(roots: &[Head], sigs: &Sigs) -> DResult<Vec<UPat>> {
    Ok(match roots.first() {
        // A `Bool` column missing one literal: the precise witness is that
        // literal (`True` / `False`), not a bare wildcard.
        Some(Head::Bool(_)) => {
            let mut out = Vec::new();
            if !roots.contains(&Head::Bool(true)) {
                out.push(UPat::Ctor(Head::Bool(true), Vec::new()));
            }
            if !roots.contains(&Head::Bool(false)) {
                out.push(UPat::Ctor(Head::Bool(false), Vec::new()));
            }
            if out.is_empty() {
                out.push(UPat::Wild);
            }
            out
        }
        Some(Head::Adt(h, c)) => {
            let (union, all) = sigs.union_of(h, *c)?;
            let uhome = &union.0;
            let present: BTreeSet<Symbol> = roots
                .iter()
                .filter_map(|h| match h {
                    Head::Adt(_, name) => Some(*name),
                    _ => None,
                })
                .collect();
            let mut out: Vec<UPat> = all
                .iter()
                .filter(|(name, _)| !present.contains(name))
                .map(|(name, ar)| {
                    UPat::Ctor(Head::Adt(uhome.clone(), *name), vec![UPat::Wild; *ar])
                })
                .collect();
            if out.is_empty() {
                out.push(UPat::Wild);
            }
            out
        }
        // A `List` column missing one constructor: the precise witness is that
        // constructor — `[]` (`Nil`) or `_ :: _` (`Cons` over two wildcards).
        Some(Head::Nil | Head::Cons) => {
            let mut out = Vec::new();
            if !roots.contains(&Head::Nil) {
                out.push(UPat::Ctor(Head::Nil, Vec::new()));
            }
            if !roots.contains(&Head::Cons) {
                out.push(UPat::Ctor(Head::Cons, vec![UPat::Wild, UPat::Wild]));
            }
            if out.is_empty() {
                out.push(UPat::Wild);
            }
            out
        }
        // An OPEN literal column (Int / Char / String) is only completed by a
        // catch-all → witness `_`. An empty column, or a tuple column (always
        // complete, never reaches here), also witness `_`.
        Some(Head::Int(_) | Head::Char(_) | Head::Str(_) | Head::Tuple(_)) | None => {
            vec![UPat::Wild]
        }
    })
}

/// Re-wrap a specialised witness `w` (its leading `arity` columns are the
/// constructor's arguments, the remainder is the tail) back into a row whose head
/// is `Ctor(head, args)`.
fn rebuild(head: &Head, arity: usize, mut w: Vec<UPat>) -> Vec<UPat> {
    let take = arity.min(w.len());
    let tail = w.split_off(take);
    let mut row = Vec::with_capacity(tail.len() + 1);
    row.push(UPat::Ctor(head.clone(), w));
    row.extend(tail);
    row
}

/// Render a witness pattern to its Ipê surface spelling for the diagnostic.
/// `atom` requests parentheses when the pattern would otherwise be ambiguous as
/// a constructor argument (a non-nullary ADT application).
fn render_upat(p: &UPat, interner: &Interner, atom: bool) -> DResult<String> {
    match p {
        UPat::Wild => Ok("_".to_owned()),
        UPat::Ctor(Head::Bool(b), _) => Ok(if *b { "True" } else { "False" }.to_owned()),
        UPat::Ctor(Head::Int(n), _) => Ok(n.to_string()),
        UPat::Ctor(Head::Char(c), _) => Ok(format!("'{c}'")),
        UPat::Ctor(Head::Str(s), _) => Ok(format!("{s:?}")),
        UPat::Ctor(Head::Tuple(_), args) => {
            let mut parts = Vec::with_capacity(args.len());
            for a in args {
                parts.push(render_upat(a, interner, false)?);
            }
            Ok(format!("({})", parts.join(", ")))
        }
        // `[]` and `head :: tail` (right-associative). The head renders as an atom
        // so a nested cons head is parenthesised; the tail keeps the bare
        // right-associative spelling. The whole cons is parenthesised when it sits
        // in an atom position (a constructor / cons argument).
        UPat::Ctor(Head::Nil, _) => Ok("[]".to_owned()),
        UPat::Ctor(Head::Cons, args) => {
            let head = render_upat(args.first().unwrap_or(&UPat::Wild), interner, true)?;
            let tail = render_upat(args.get(1).unwrap_or(&UPat::Wild), interner, false)?;
            let inner = format!("{head} :: {tail}");
            if atom {
                Ok(format!("({inner})"))
            } else {
                Ok(inner)
            }
        }
        UPat::Ctor(Head::Adt(_home, name), args) => {
            let name = resolve(interner, *name)?;
            if args.is_empty() {
                return Ok(name.into());
            }
            let mut parts = Vec::with_capacity(args.len());
            for a in args {
                parts.push(render_upat(a, interner, true)?);
            }
            let inner = format!("{name} {}", parts.join(" "));
            if atom {
                Ok(format!("({inner})"))
            } else {
                Ok(inner)
            }
        }
    }
}

/// The surface spelling of a `case` arm's pattern, used to name a redundant arm
/// in the IPE-T0011 diagnostic. A constructor / variable resolves through the
/// interner; a literal spells itself; a wildcard is `_`; an alias spells its
/// inner pattern (the part that drives the match).
fn arm_label(p: &canon::Pattern_, interner: &Interner) -> DResult<Box<str>> {
    let s = match p {
        canon::Pattern_::PAnything => "_".to_owned(),
        canon::Pattern_::PDebugAnything => "Debug._".to_owned(),
        canon::Pattern_::PUnit => "()".to_owned(),
        canon::Pattern_::PVar(name) | canon::Pattern_::PCtor { name, .. } => {
            resolve(interner, *name)?.to_string()
        }
        canon::Pattern_::PInt(n) => n.to_string(),
        canon::Pattern_::PBool(b) => if *b { "True" } else { "False" }.to_owned(),
        canon::Pattern_::PChar(c) => format!("'{c}'"),
        canon::Pattern_::PStr(s) => format!("{s:?}"),
        canon::Pattern_::PAlias(inner, _) => return arm_label(&inner.value, interner),
        canon::Pattern_::PTuple(_) => "(…)".to_owned(),
        canon::Pattern_::PRecord(_) => "{…}".to_owned(),
        canon::Pattern_::PList(_) => "[…]".to_owned(),
        canon::Pattern_::PCons(_, _) => "_ :: _".to_owned(),
        // Label an or-pattern by its first alternative; a redundant SINGLE
        // alternative is reported against that alternative directly.
        canon::Pattern_::POr(alts) => match alts.first() {
            Some(first) => return arm_label(&first.value, interner),
            None => "_".to_owned(),
        },
    };
    Ok(s.into_boxed_str())
}

/// Resolve a constructor symbol to an owned name, or a `CompilerBug` on a forged
/// symbol.
fn resolve(interner: &Interner, sym: Symbol) -> DResult<Box<str>> {
    interner
        .resolve(sym)
        .map(Box::from)
        .ok_or_else(|| Diagnostic::CompilerBug {
            where_: STAGE,
            detail: format!("no backing string for constructor symbol {}", sym.as_raw()),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipe_diagnostics::Located;

    /// Signature tables with no unions, for patterns that name no constructor.
    const fn empty_sigs() -> Sigs {
        Sigs {
            ctor_to_union: BTreeMap::new(),
            union_ctors: BTreeMap::new(),
            ctor_arity: BTreeMap::new(),
        }
    }

    fn boolp(b: bool) -> canon::Pattern {
        Located::new(Span::DUMMY, canon::Pattern_::PBool(b))
    }

    /// `True | False` — a two-alternative or-pattern.
    fn true_or_false() -> canon::Pattern {
        Located::new(
            Span::DUMMY,
            canon::Pattern_::POr(vec![boolp(true), boolp(false)]),
        )
    }

    /// A tuple of `n` independent `True | False` sub-patterns. Its abstraction is
    /// the cartesian product of the columns, so it expands to `2^n` rows — the
    /// exact combinatorial blow-up the budget must bound.
    fn wide_or_tuple(n: usize) -> canon::Pattern_ {
        canon::Pattern_::PTuple((0..n).map(|_| true_or_false()).collect())
    }

    #[test]
    fn pathological_or_expansion_fails_closed_not_hangs() {
        // A 40-wide product is 2^40 rows — an out-of-memory abort without the
        // budget. A small budget must turn it into a typed limit error, and it
        // must do so promptly (charging the product size BEFORE allocating it),
        // never materialising the rows.
        let pat = wide_or_tuple(40);
        let mut budget = ExhaustBudget::with_limit(1_000);
        let result = expand_upats(&pat, &empty_sigs(), &mut budget);
        assert!(
            matches!(
                result,
                Err(Diagnostic::Type {
                    msg: TypeError::StepBudgetExceeded { budget: 1_000 },
                    ..
                })
            ),
            "pathological or-pattern must yield a bounded StepBudgetExceeded, got Ok={}",
            result.is_ok()
        );
    }

    #[test]
    fn disabled_budget_expands_pathological_case() {
        // The `IPE_EXHAUST_BUDGET=0` escape hatch (a `None` remaining) never
        // charges, so a moderate product still expands rather than erroring —
        // proving the ceiling is the only thing the trip depends on.
        let pat = wide_or_tuple(8);
        let mut budget = ExhaustBudget::unbounded();
        let rows =
            expand_upats(&pat, &empty_sigs(), &mut budget).expect("unbounded budget never errors");
        assert_eq!(rows.len(), 1 << 8, "8-wide product expands to 2^8 rows");
    }

    /// A list literal `[e0, …, eN]` desugars to a depth-`N` cons spine the
    /// usefulness walk recurses over natively. A list wider than the dedicated
    /// depth cap must fail closed with a typed limit error EVEN under an
    /// unbounded work budget — the cap, not the budget, is what keeps the native
    /// stack safe. One element past the cap is the boundary that must reject.
    #[test]
    fn over_length_list_pattern_is_rejected_even_when_budget_disabled() {
        let elems: Vec<canon::Pattern> = (0..=MAX_LIST_PATTERN_LEN)
            .map(|_| Located::new(Span::DUMMY, canon::Pattern_::PAnything))
            .collect();
        let pat = canon::Pattern_::PList(elems);
        let mut budget = ExhaustBudget::unbounded();
        let result = expand_upats(&pat, &empty_sigs(), &mut budget);
        assert!(
            matches!(
                result,
                Err(Diagnostic::Type {
                    msg: TypeError::StepBudgetExceeded { .. },
                    ..
                })
            ),
            "a list pattern past the depth cap must reject, got Ok={}",
            result.is_ok()
        );
    }

    /// A list literal exactly at the depth cap is still legal — the cap rejects
    /// only strictly longer spines, so a real (short) list pattern is never
    /// turned away.
    #[test]
    fn at_length_list_pattern_is_accepted() {
        let elems: Vec<canon::Pattern> = (0..MAX_LIST_PATTERN_LEN)
            .map(|_| Located::new(Span::DUMMY, canon::Pattern_::PAnything))
            .collect();
        let pat = canon::Pattern_::PList(elems);
        let mut budget = ExhaustBudget::unbounded();
        assert!(
            expand_upats(&pat, &empty_sigs(), &mut budget).is_ok(),
            "a list pattern at the cap must still expand"
        );
    }

    #[test]
    fn normal_pattern_unaffected_by_budget() {
        // A realistic small pattern expands to a handful of rows and spends only
        // a trickle of the default budget, so accept/reject is unchanged. A
        // single `True | False` is two rows.
        let pat = true_or_false().value;
        let mut budget = ExhaustBudget::from_env();
        let rows = expand_upats(&pat, &empty_sigs(), &mut budget)
            .expect("small pattern fits any default budget");
        assert_eq!(rows.len(), 2, "True | False expands to two rows");
    }

    /// The union a scrutinee of the solved type `build` makes is judged against.
    ///
    /// Spelled as `(home segments, name)` so calls with separate interners
    /// compare; the signature tables hold the builtins only.
    #[allow(clippy::expect_used)] // interning short literals cannot exhaust the interner
    fn union_of_scrutinee_ty(
        build: impl FnOnce(&mut Interner) -> Ty,
    ) -> DResult<Option<(Vec<String>, String)>> {
        let mut interner = Interner::new();
        let main = vec![interner.intern("Main").expect("intern Main")];
        let ty = build(&mut interner);
        let entry = canon::Module {
            name: main.clone(),
            unions: Vec::new(),
            defs: Vec::new(),
            imports_unsafe_submodule: false,
            imported_web_capabilities: BTreeSet::new(),
        };
        let sigs = Sigs::build(&entry, &[], &mut interner).expect("builtin signatures build");
        let scrut: canon::Expr = Located::new(Span::DUMMY, canon::Expr_::Unit);
        let mut regions = Regions::new();
        regions.insert((main.clone(), scrut.span), ty);
        let ctx = Ctx {
            sigs: &sigs,
            home: &main,
            regions: &regions,
            interner: &interner,
        };
        let spell = |sym: Symbol| {
            interner
                .resolve(sym)
                .expect("a union symbol resolves in its interner")
                .to_owned()
        };
        Ok(scrutinee_union(&scrut, &ctx)?
            .map(|((home, name), _)| (home.iter().copied().map(spell).collect(), spell(*name))))
    }

    /// The union a scrutinee of solved type `module.name` is judged against.
    #[allow(clippy::expect_used)] // interning short literals cannot exhaust the interner
    fn union_of_scrutinee(module: &[&str], name: &str) -> DResult<Option<(Vec<String>, String)>> {
        union_of_scrutinee_ty(|interner| Ty::Con {
            module: module
                .iter()
                .map(|seg| interner.intern(seg).expect("intern a home segment"))
                .collect(),
            name: interner.intern(name).expect("intern the type name"),
            args: Vec::new(),
        })
    }

    /// A builtin re-exported under its stdlib home is judged as the builtin union.
    ///
    /// `import Ipe.Result exposing (Result(..))` solves a `Result` scrutinee to
    /// the `Ipe.Result` home; the solver unifies that head with the empty-home
    /// builtin, so the catch-all check must see the same union or it fails open.
    #[test]
    fn a_stdlib_spelled_builtin_scrutinee_is_the_builtin_union() {
        let stdlib = union_of_scrutinee(&["Ipe", "Result"], "Result")
            .ok()
            .flatten();
        let ambient = union_of_scrutinee(&[], "Result").ok().flatten();
        assert!(
            stdlib.as_ref().is_some_and(|(home, _)| home.is_empty()),
            "an `Ipe.Result`-homed `Result` must key the builtin union, got {stdlib:?}"
        );
        assert_eq!(stdlib, ambient, "both spellings name one union");
    }

    /// A user-homed head absent from the signatures is a compiler bug.
    ///
    /// `Order` is a builtin union a user module may also declare; the solver
    /// keeps `Lib.Order` apart from it, so the catch-all check must never read
    /// it as the builtin. A declared union is always in the signature tables, so
    /// its absence is a broken closure, refused rather than skipped.
    #[test]
    fn a_user_homed_head_absent_from_the_signatures_is_a_compiler_bug() {
        assert!(
            union_of_scrutinee(&[], "Order").is_ok_and(|union| union.is_some()),
            "the ambient `Order` is a builtin union"
        );
        assert!(
            matches!(
                union_of_scrutinee(&["Lib"], "Order"),
                Err(Diagnostic::CompilerBug { .. })
            ),
            "a `Lib.Order` the signatures lack is neither the builtin nor skipped"
        );
    }

    /// A scrutinee whose type is no union is judged by no union.
    ///
    /// An unsolved variable, a structural type, and a builtin head without
    /// constructors each skip the catch-all judgement through a named arm.
    #[test]
    fn a_non_union_scrutinee_is_judged_by_no_union() {
        assert!(matches!(union_of_scrutinee_ty(|_| Ty::Var(0)), Ok(None)));
        assert!(matches!(union_of_scrutinee_ty(|_| Ty::Unit), Ok(None)));
        assert!(matches!(union_of_scrutinee(&[], "Int"), Ok(None)));
        assert!(matches!(
            union_of_scrutinee(&["Ipe", "Dict"], "Dict"),
            Ok(None)
        ));
    }

    /// A constructor absent from its union's signature is a compiler bug.
    ///
    /// A hand-built signature table that never saw `Ghost` must refuse its
    /// arity, its column completion, its witness heads, and the usefulness walk
    /// over it, never read it as nullary or as an incomplete column.
    #[test]
    #[allow(clippy::expect_used)] // interning short literals cannot exhaust the interner
    fn constructor_missing_from_signature_is_a_compiler_bug() {
        let mut interner = Interner::new();
        let main = vec![interner.intern("Main").expect("intern Main")];
        let ghost = interner.intern("Ghost").expect("intern Ghost");
        let entry = canon::Module {
            name: main.clone(),
            unions: Vec::new(),
            defs: Vec::new(),
            imports_unsafe_submodule: false,
            imported_web_capabilities: BTreeSet::new(),
        };
        let sigs = Sigs::build(&entry, &[], &mut interner).expect("builtin signatures build");
        let head = Head::Adt(main, ghost);
        let roots = std::slice::from_ref(&head);
        assert!(matches!(
            sigs.arity(&head),
            Err(Diagnostic::CompilerBug { .. })
        ));
        assert!(matches!(
            complete_signature(roots, &sigs),
            Err(Diagnostic::CompilerBug { .. })
        ));
        assert!(matches!(
            missing_heads(roots, &sigs),
            Err(Diagnostic::CompilerBug { .. })
        ));
        let matrix = vec![vec![UPat::Ctor(head.clone(), Vec::new())]];
        let mut budget = ExhaustBudget::unbounded();
        assert!(matches!(
            useful(&matrix, &[UPat::Wild], &sigs, WITNESS_CAP, &mut budget),
            Err(Diagnostic::CompilerBug { .. })
        ));
    }
}
