//! Unification of two solver variables, ported from the relevant arms of
//! `Ipe.Type.Unify` (derivative of elm/compiler's `Type.Unify`, BSD-3-Clause).
//!
//! Eager, in-place unification over the union-find arena. A flexible variable
//! adopts the other side's content; two structures must agree head-to-head and
//! then unify their children. A flexible variable bound to a structure
//! that *contains* it is an infinite type — rejected via an occurs check
//! (mirrors `Occurs.occurs`), so the read-back ([`crate::ty`] zonking) always
//! terminates.
//!
//! The child obligations are driven from an explicit heap-allocated work stack
//! of `(found, expected)` pairs rather than native recursion, so an
//! adversarially deep type spine (e.g. a curried lambda tens of thousands of
//! parameters wide) cannot overflow the native stack: it is bounded by the
//! shared [`Budget`] and turned back with a typed limit error. The sibling
//! walks [`occurs`] and [`crate::constrain::zonk`] are iterative for the same
//! reason.
//!
//! Every step decrements the shared [`Budget`]; an adversarial constraint set
//! that drives the unifier into a blow-up trips [`TypeError::StepBudgetExceeded`]
//! instead of exhausting the heap.
//!
//! Parse-don't-validate: a type error is built into an **owned** diagnostic
//! payload at the failure point — the diverging types are zonked + resolved into
//! [`TyDoc`](ipe_diagnostics::TyDoc)s here (via [`crate::doc`]), so the reporter
//! never touches the interner or the arena.

use std::collections::BTreeMap;

use ipe_diagnostics::{DResult, Diagnostic, Span, TypeError};
use ipe_intern::Interner;

use crate::constrain::zonk;
use crate::doc::{VarNamer, ty_to_doc};
use crate::solve::Budget;
use crate::ty::{Content, FlatType, Ty, TyBounds};
use crate::unionfind::{UnionFind, VarId};

/// Whether a concrete structure `flat` satisfies a variable's super-type
/// obligations `bounds` at the head.
///
/// This is the *pin* check: a super-typed flex variable may collapse onto a
/// concrete type only when that type really supports the operations the body
/// performed. Numeric obligations (`+ - *`) are met by `Int` / `Float`;
/// ordering (`< > <= >=`) is met by the scalar primitives `Int` / `Float` /
/// `Char` / `String` / `Bool` — both require a bare type constructor.
///
/// Equality (`== /=`) is far more permissive: structural equality is total over
/// every non-function type, so an equality obligation pins to any structure that
/// is not a function head (tuples, records, enums, and the primitives all derive
/// Rust's `PartialEq`). A *nested* function inside such a structure still makes
/// it non-equatable, but that is caught by the post-solve deep gate
/// ([`crate::concrete_super_ok`]), which has the resolved type in hand; here at
/// the head a function is the only outright rejection for equality.
fn super_concrete_ok(interner: &Interner, bounds: TyBounds, flat: &FlatType) -> bool {
    // A function supports none of the super-types: not numeric, not ordered, and
    // not equatable (Rust never derives `PartialEq` for a function).
    if matches!(flat, FlatType::Fun(_, _)) {
        return false;
    }
    // Numeric / ordering need a bare scalar primitive. Equality imposes no head
    // restriction beyond the non-function rejection above.
    let prim = match flat {
        FlatType::Con { module, name, args } if module.is_empty() && args.is_empty() => {
            interner.resolve(*name)
        }
        _ => None,
    };
    let number_ok = crate::super_bounds::prim_satisfies_number(prim);
    // Head-pin unification uses `ConcretePin`: `String` satisfies ordering
    // here (borrows; no `Copy` constraint at the unifier level).
    let ord_ok =
        crate::super_bounds::prim_satisfies_ord(prim, crate::super_bounds::BoundSite::ConcretePin);
    // `++` accepts `String` (bare scalar) or `List _` (one type arg). The `prim`
    // path already covers `String`; `List` must be checked separately because it
    // carries one argument and the `args.is_empty()` guard above excludes it.
    let appendable_ok = crate::super_bounds::prim_satisfies_append_prim(prim)
        || matches!(flat,
            FlatType::Con { module, name, args }
                if module.is_empty()
                    && args.len() == 1
                    && interner.resolve(*name) == Some("List")
        );
    // A `Set` element / `Dict` key obligation is a Ipê `comparable` — the same
    // scalar set ordering admits. `Float` passes here (it IS `comparable` in
    // Ipê, so the typing follows Ipê), and the Rust-backend reality that `f64`
    // is neither `Ord` nor `Hash` is enforced at lowering with a dedicated
    // diagnostic — not as a confusing type mismatch at this head pin.
    let key_ok = crate::super_bounds::prim_satisfies_comparable_key(prim);
    (!bounds.has_number() || number_ok)
        && (!bounds.has_ord() || ord_ok)
        && (!bounds.has_comparable_key() || key_ok)
        && (!bounds.has_append() || appendable_ok)
}

/// Unify the types of variables `a` and `b` in place.
///
/// `span` is attached to any [`TypeError::TypeMismatch`] for diagnostics; `a` is
/// the *found* (actual) side and `b` the *expected* side, matching the
/// `Constraint { lhs, rhs }` convention used by the constraint generator.
///
/// # Errors
/// * [`TypeError::TypeMismatch`] when two incompatible structures meet.
/// * [`TypeError::InfiniteType`] when a bind would create a cyclic type.
/// * [`TypeError::StepBudgetExceeded`] when the step budget is exhausted.
/// * [`Diagnostic::CompilerBug`] on a union-find invariant violation.
pub fn unify(
    uf: &mut UnionFind<Content>,
    budget: &mut Budget,
    interner: &Interner,
    span: Span,
    a: VarId,
    b: VarId,
) -> DResult<()> {
    // Explicit heap work stack of `(found, expected)` obligations. A structure's
    // children are pushed here instead of recursed, so a type spine of depth N
    // costs O(N) heap, never O(N) native stack. Children are pushed in reverse
    // of source order so that LIFO pops them in the original left-to-right
    // sequence — later obligations may depend on the merges an earlier one
    // performs, so the ordering is load-bearing, not cosmetic.
    let mut stack: Vec<(VarId, VarId)> = vec![(a, b)];
    while let Some((a, b)) = stack.pop() {
        unify_step(uf, budget, interner, span, a, b, &mut stack)?;
    }
    Ok(())
}

/// Process a single `(found, expected)` obligation: agree the two heads and
/// push any child obligations onto `stack`. Never recurses on children — that
/// is what keeps the whole unification bounded by the [`Budget`] rather than the
/// native stack.
#[allow(clippy::too_many_arguments)]
fn unify_step(
    uf: &mut UnionFind<Content>,
    budget: &mut Budget,
    interner: &Interner,
    span: Span,
    a: VarId,
    b: VarId,
    stack: &mut Vec<(VarId, VarId)>,
) -> DResult<()> {
    budget.tick()?;
    // Two finds, reused for both the same-class short-circuit and the content
    // reads below — the short-circuit is `find(a)? == find(b)?`, and path
    // compression runs on both chains as a side effect.
    let ra = uf.find(a)?;
    let rb = uf.find(b)?;
    if ra == rb {
        return Ok(());
    }
    // Clone a structure descriptor only when an arm actually MOVES one into the
    // union: peek both roots by reference and, if neither side carries a
    // structure, dispatch on the trivial `Flex`/`Rigid`/`Super` descriptors
    // (`bool` + `Copy` bounds) without ever deep-copying a record's field map or
    // a `Con`'s argument vector. Only the structure arms fetch an owned `Content`.
    let peek_a = uf.root_content(ra)?;
    if !matches!(peek_a, Content::Structure(_)) {
        let peek_b = uf.root_content(rb)?;
        if !matches!(peek_b, Content::Structure(_)) {
            // Both descriptors are the trivial `Flex`/`Rigid`/`Super` shapes
            // (a `bool` + `Copy` bounds); cloning them copies no heap data.
            let owned_a = peek_a.clone();
            let owned_b = peek_b.clone();
            return unify_nonstructure(uf, budget, interner, span, ra, rb, &owned_a, &owned_b);
        }
    }

    let ca = uf.content(ra)?;
    let cb = uf.content(rb)?;
    match (ca, cb) {
        // A flex adopts the other side's structure (occurs-checked).
        (Content::Flex, structure @ Content::Structure(_)) => {
            occurs_guard(uf, budget, interner, span, ra, rb)?;
            uf.union(ra, rb, structure)
        }
        (structure @ Content::Structure(_), Content::Flex) => {
            occurs_guard(uf, budget, interner, span, rb, ra)?;
            uf.union(ra, rb, structure)
        }
        // A super-typed variable meeting a concrete structure. A flex pins to the
        // structure when it satisfies the obligations; a rigid cannot be pinned
        // (the annotation promised a generic), and a structure that fails the
        // obligations is a mismatch either way.
        (Content::Super { rigid, bounds }, structure @ Content::Structure(_))
        | (structure @ Content::Structure(_), Content::Super { rigid, bounds }) => {
            let pins = match &structure {
                Content::Structure(flat) => !rigid && super_concrete_ok(interner, bounds, flat),
                _ => false,
            };
            if pins {
                uf.union(ra, rb, structure)
            } else {
                Err(mismatch(uf, budget, interner, span, ra, rb))
            }
        }
        // A rigid against a concrete structure is a mismatch — the annotation
        // promised a fully parametric variable the body is now trying to pin
        // down.
        (Content::Rigid, Content::Structure(_)) | (Content::Structure(_), Content::Rigid) => {
            Err(mismatch(uf, budget, interner, span, ra, rb))
        }
        (Content::Structure(fa), Content::Structure(fb)) => {
            unify_flat(uf, budget, interner, span, ra, rb, fa, fb, stack)
        }
        // At least one side is a structure here (the no-structure fast path
        // returned above), so every remaining combination pairs a structure with
        // a `Flex`/`Rigid`/`Super` already handled by an arm above. Delegating the
        // trivial descriptors keeps the match total without duplicating the
        // non-structure logic.
        (a, b) => unify_nonstructure(uf, budget, interner, span, ra, rb, &a, &b),
    }
}

/// Merge two variables NEITHER of which carries a structure descriptor — the
/// `Flex` / `Rigid` / `Super` combinations. Reads only the trivial `Copy`
/// payloads (`rigid: bool`, `bounds: TyBounds`) off the borrowed descriptors, so
/// the common inner-loop step (a numeric literal meeting a variable, two rigids
/// meeting) never deep-copies a descriptor.
#[allow(clippy::too_many_arguments)]
fn unify_nonstructure(
    uf: &mut UnionFind<Content>,
    budget: &mut Budget,
    interner: &Interner,
    span: Span,
    ra: VarId,
    rb: VarId,
    ca: &Content,
    cb: &Content,
) -> DResult<()> {
    match (ca, cb) {
        // Two flexes collapse into one flex class.
        (Content::Flex, Content::Flex) => uf.union(ra, rb, Content::Flex),
        // A flex adopts the other side's rigid (skolem). No occurs check is
        // needed: a rigid carries no transitive structure, so the merge cannot
        // build a cycle.
        (Content::Flex, Content::Rigid) | (Content::Rigid, Content::Flex) => {
            uf.union(ra, rb, Content::Rigid)
        }
        // A flex adopts a super-typed variable's obligations wholesale.
        (Content::Super { rigid, bounds }, Content::Flex)
        | (Content::Flex, Content::Super { rigid, bounds }) => uf.union(
            ra,
            rb,
            Content::Super {
                rigid: *rigid,
                bounds: *bounds,
            },
        ),
        // Two super-typed variables meet.
        //
        // Same rigidity → merge, the survivor owing the union of both obligation
        // sets.  DIFFERENT rigidity (one an annotation skolem, the other an
        // inference flex) → mismatch, mirroring `Rigid` vs `Structure`.
        //
        // The rigid super is an annotation type variable the body promised to keep
        // fully generic (surfacing its obligation as a trait bound); a super-typed
        // *flex* is an inference variable that WILL resolve to a concrete number —
        // most often a numeric literal (`Super { Number }`).  Letting the two merge
        // would silently accept `f : a -> a; f x = x + 1`, where the literal `1`
        // forces the annotated-generic `a` to a concrete numeric representation.
        // Elm (and the Ipê reference) reject exactly this: `a` was annotated fully
        // parametric, so a body that adds a concrete literal to it is a type error.
        // (`double : a -> a; double x = x + x` — no literal — never reaches this
        // arm: its operand super meets the rigid `x` as `Super{flex}` vs
        // `Content::Rigid` in the arm below, which correctly adopts the obligation
        // as a bound.)
        (
            Content::Super {
                rigid: r1,
                bounds: b1,
            },
            Content::Super {
                rigid: r2,
                bounds: b2,
            },
        ) => {
            // Two RIGID supers are two distinct annotation skolems — a same-class
            // pair already short-circuited at the `ra == rb` root check above, so
            // any rigid/rigid pair here promised the body two independently
            // generic variables. Merging them conflates the two, accepting a
            // program whose emitted Rust then fails to type-check (one type
            // parameter used where the other is expected). They never unify,
            // exactly as the plain `Rigid` vs `Rigid` path rejects.
            //
            // Number (`+ - *`) and Append (`++`) require the variable to resolve
            // to a concrete type at monomorphisation / lowering. Letting either
            // cross onto a rigid annotation var would pin an annotation-generic
            // to a concrete representation — the exact unsoundness we guard
            // against. All other obligations (Eq, Ord, Stringify, comparable-key)
            // lower as pure generic trait bounds, always valid Rust, so they may
            // accumulate across rigidity and survive as trait bounds on the param.
            let concrete_dispatch =
                b1.has_number() || b2.has_number() || b1.has_append() || b2.has_append();
            let can_union = !(*r1 && *r2) && ((r1 == r2) || !concrete_dispatch);
            if can_union {
                uf.union(
                    ra,
                    rb,
                    Content::Super {
                        rigid: *r1 || *r2,
                        bounds: b1.union(*b2),
                    },
                )
            } else {
                Err(mismatch(uf, budget, interner, span, ra, rb))
            }
        }
        // A super-typed FLEX meeting a rigid skolem: the rigid adopts the
        // obligations and stays rigid, so the body's super-typed use of an
        // annotated `a` becomes a trait bound on `a` rather than a rejection.
        (
            Content::Super {
                rigid: false,
                bounds,
            },
            Content::Rigid,
        )
        | (
            Content::Rigid,
            Content::Super {
                rigid: false,
                bounds,
            },
        ) => uf.union(
            ra,
            rb,
            Content::Super {
                rigid: true,
                bounds: *bounds,
            },
        ),
        // Mismatch for everything left: two distinct rigid skolems (a same-class
        // pair short-circuited at the root check) or a super-typed RIGID meeting a
        // plain rigid — the annotation promised a fully parametric variable the
        // body is now trying to pin down. Any structure-involving pair reaching
        // here would be a caller invariant break (`unify_step` handles those), and
        // rejecting it fails closed rather than mis-merging.
        _ => Err(mismatch(uf, budget, interner, span, ra, rb)),
    }
}

/// Whether two constructor heads `m1.n1` and `m2.n2` name the same type constructor.
///
/// The single head-identity rule: the names agree, and the homes agree or one
/// side is the empty builtin home and the other passes [`empty_home_compat`].
/// Arity is the caller's concern; the head alone decides identity, so two
/// distinct constructors of equal arity are never conflated.
#[must_use]
pub fn con_heads_compatible(
    m1: &[ipe_intern::Symbol],
    n1: ipe_intern::Symbol,
    m2: &[ipe_intern::Symbol],
    n2: ipe_intern::Symbol,
    interner: &Interner,
) -> bool {
    n1 == n2
        && (m1 == m2
            || (m1.is_empty() && empty_home_compat(m2, n2, interner))
            || (m2.is_empty() && empty_home_compat(m1, n1, interner)))
}

/// Whether an empty-home `Con` may unify with a `Con` of the same `name`
/// carrying the non-empty `other_home`.
///
/// The empty home is the builtin/kernel sentinel. A builtin legitimately appears
/// with a non-empty home in exactly two shapes, both admitted here:
///
/// * an `Ipe.*`-**rooted** home — the stdlib namespace, which a user module can
///   never occupy. A compiled-source stdlib module declares or re-exports the
///   type (`Ipe.Task`'s `BackoffStrategy`, `Ipe.Error`'s `ErrorKind`) so an
///   annotation there resolves to `[Ipe, …]` while a kernel scheme still mints
///   the empty home. An `Ipe`-rooted home is therefore always the stdlib
///   spelling of that builtin, never a user shadow.
/// * a **reserved** builtin reached through a non-stdlib-rooted qualifier
///   (`Http.HttpMethod` → `[Http]`). Reserved names can never be user-declared,
///   so any non-empty home for one is a builtin qualifier, never a user shadow.
///
/// Everything else — a name with a *user* home (`type Order` in `Main` →
/// `[Main]`) — is a genuinely distinct type and does NOT unify.
fn empty_home_compat(
    other_home: &[ipe_intern::Symbol],
    name: ipe_intern::Symbol,
    interner: &Interner,
) -> bool {
    let ipe_rooted = other_home
        .first()
        .and_then(|s| interner.resolve(*s))
        .is_some_and(|root| root == IPE_STDLIB_ROOT);
    ipe_rooted
        || interner
            .resolve(name)
            .is_some_and(ipe_canon::is_user_type_declaration_forbidden)
}

/// The reserved root module segment of every compiled-source stdlib home
/// (`Ipe.Error`, `Ipe.Task`, …). A user module can never occupy this namespace,
/// so an `Ipe`-rooted home is always the stdlib spelling of a builtin, never a
/// user shadow.
const IPE_STDLIB_ROOT: &str = "Ipe";

/// Whether merging `ra` and `rb` would make the surviving class a direct child
/// of itself — a depth-one cycle (`t = List t`) the structure-vs-structure path
/// would otherwise mint silently.
///
/// A structure-vs-structure union keeps one side's children and merges the two
/// roots into one class; if any of those kept children already resolves to the
/// other root, the merged class contains itself. The flex-vs-structure binds run
/// a full occurs check for the same reason, but two structures with matching
/// heads never take that path. This is the shallow guard for that path: it reads
/// only the direct child roots (each an already-compressed `find`), so it costs
/// O(children) per union rather than a recursive occurs walk — a deep spine
/// stays linear. A deeper indirect cycle can only close through a
/// flex-binds-structure step, which `occurs_guard` still covers.
fn merges_into_self(
    uf: &mut UnionFind<Content>,
    ra: VarId,
    rb: VarId,
    children: &[VarId],
) -> DResult<bool> {
    for &child in children {
        let root = uf.find(child)?;
        if root == ra || root == rb {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Unify two concrete structures that share representatives `ra` (found) / `rb`
/// (expected). Child obligations are pushed onto `stack` (in reverse of source
/// order, so LIFO replays them left-to-right) rather than unified in place, so
/// the driver loop stays bounded by the [`Budget`], not the native stack.
#[allow(clippy::too_many_arguments)]
fn unify_flat(
    uf: &mut UnionFind<Content>,
    budget: &mut Budget,
    interner: &Interner,
    span: Span,
    ra: VarId,
    rb: VarId,
    fa: FlatType,
    fb: FlatType,
    stack: &mut Vec<(VarId, VarId)>,
) -> DResult<()> {
    match (fa, fb) {
        (FlatType::Unit, FlatType::Unit) => uf.union(ra, rb, Content::Structure(FlatType::Unit)),
        (FlatType::Fun(a1, r1), FlatType::Fun(a2, r2)) => {
            // Merge the roots first so a recursive reference resolves, then
            // queue argument-with-argument and result-with-result. Push result
            // last so it pops after the argument (source order preserved).
            uf.union(ra, rb, Content::Structure(FlatType::Fun(a1, r1)))?;
            stack.push((r1, r2));
            stack.push((a1, a2));
            Ok(())
        }
        (
            FlatType::Con {
                module: m1,
                name: n1,
                args: as1,
            },
            FlatType::Con {
                module: m2,
                name: n2,
                args: as2,
            },
        ) => {
            // An empty module path (`module = []`) is the sentinel for a
            // kernel/builtin type: every builtin `Con` carries it, in kernel
            // schemes and in annotations alike. A user type always carries its
            // real declaring home, so a home disagreement between an empty and a
            // non-empty side is only compatible when the non-empty side is itself
            // a builtin spelling — a reserved builtin reached through a stdlib
            // qualifier (`Http.HttpMethod` → the empty-home kernel `Con`). A
            // shadowable builtin name carrying a non-empty home is a *user* type
            // of that name (`type Order` in `Main`), a genuinely distinct type
            // from the empty-home builtin; unifying them would let a wrong program
            // type-check and then lower to conflicting Rust representations.
            if !con_heads_compatible(&m1, n1, &m2, n2, interner) || as1.len() != as2.len() {
                return Err(mismatch(uf, budget, interner, span, ra, rb));
            }
            // Prefer the non-empty (more specific) module path as canonical.
            // m1 and m2 are not used after this expression; move them directly.
            let canonical_module = if m1.is_empty() { m2 } else { m1 };
            if merges_into_self(uf, ra, rb, &as2)? || merges_into_self(uf, ra, rb, &as1)? {
                return Err(infinite_type(uf, budget, interner, span, ra, rb));
            }
            // Queue each argument pair (child ids are `Copy`, read by reference)
            // BEFORE moving the surviving structure into the union — so `as1` is
            // moved, never cloned. Push in reverse so LIFO replays them in
            // ascending index order, matching the original in-place walk. The
            // driver processes this stack only after the union commits.
            for (x, y) in as1.iter().zip(as2.iter()).rev() {
                stack.push((*x, *y));
            }
            uf.union(
                ra,
                rb,
                Content::Structure(FlatType::Con {
                    module: canonical_module,
                    name: n1,
                    args: as1,
                }),
            )?;
            Ok(())
        }
        (FlatType::Tuple(es1), FlatType::Tuple(es2)) => {
            // Tuples unify only at the same arity, element-wise.
            if es1.len() != es2.len() {
                return Err(mismatch(uf, budget, interner, span, ra, rb));
            }
            if merges_into_self(uf, ra, rb, &es2)? || merges_into_self(uf, ra, rb, &es1)? {
                return Err(infinite_type(uf, budget, interner, span, ra, rb));
            }
            // Queue element pairs (ids are `Copy`, read by reference) before
            // moving `es1` into the union — so the surviving element vector is
            // moved, never cloned. Push in reverse so LIFO replays them in
            // ascending index order.
            for (x, y) in es1.iter().zip(es2.iter()).rev() {
                stack.push((*x, *y));
            }
            uf.union(ra, rb, Content::Structure(FlatType::Tuple(es1)))?;
            Ok(())
        }
        // ── Open-record unification (row-poly) ───────────────────────────────
        //
        // Faithful port of `unifyRecords` from
        // `../ipe/src/Ipe/Type/Unify.hs:468-512`.
        //
        // Algorithm (four cases):
        //   1. Unify every field present on BOTH sides pairwise.
        //   2. A CLOSED side cannot absorb the other's extra fields → mismatch
        //      (IPE-T0001).
        //   3. If both sides carry identical field sets → unify the two extension
        //      variables and merge.
        //   4. Both sides are open with differing fields → mint a fresh flex
        //      tail, merge as the union of both field maps under it (so future
        //      unifications can still constrain the merged open tail).
        //
        // `is_empty_record`: follow `v` to its root; `true` iff the content is
        // `FlatType::EmptyRecord` (the closed-tail sentinel).
        (FlatType::Record(fs1, ext1), FlatType::Record(fs2, ext2)) => {
            // Step 1 — queue shared fields for pairwise unification. Each shared
            // field's types are distinct solver variables from the extension
            // tails, so deferring them onto the stack cannot change the
            // `is_empty_record` tail reads or the merges below.
            // Both `.get()` calls are infallible: `name` came from `fs1.keys()`
            // and the filter already proved `fs2.contains_key(name)`.
            for name in fs1.keys().filter(|k| fs2.contains_key(*k)) {
                // Unreachable else: both keys are confirmed present.
                let Some((v1, v2)) = fs1.get(name).copied().zip(fs2.get(name).copied()) else {
                    continue;
                };
                stack.push((v1, v2));
            }

            // Partition into only-on-left and only-on-right.
            let only1: Vec<(_, _)> = fs1
                .iter()
                .filter(|(k, _)| !fs2.contains_key(*k))
                .map(|(k, v)| (*k, *v))
                .collect();
            let only2: Vec<(_, _)> = fs2
                .iter()
                .filter(|(k, _)| !fs1.contains_key(*k))
                .map(|(k, v)| (*k, *v))
                .collect();

            // Is the extension variable a closed tail (`EmptyRecord`)?
            let closed1 = is_empty_record(uf, ext1)?;
            let closed2 = is_empty_record(uf, ext2)?;

            // Step 2 — closed side cannot absorb the other's extras.
            let extras1_illegal = closed2 && !only1.is_empty();
            let extras2_illegal = closed1 && !only2.is_empty();
            if extras1_illegal || extras2_illegal {
                return Err(mismatch(uf, budget, interner, span, ra, rb));
            }

            if only1.is_empty() && only2.is_empty() {
                // Step 3 — identical field sets: merge first, then queue the
                // tail unification. `fs1` is moved into the union; no clone.
                uf.union(ra, rb, Content::Structure(FlatType::Record(fs1, ext1)))?;
                stack.push((ext1, ext2));
            } else {
                // Step 4 — differing extras: absorb each side's unique fields
                // into the other's extension so both original tails carry the
                // full field union and stay live for later constraints.
                unify_open_record_rows(uf, ra, rb, fs1, ext1, ext2, only1, only2, stack)?;
            }
            Ok(())
        }
        // Two closed-tail sentinels: identical structures, merge and succeed.
        // Mirrors the reference compiler `(EmptyRecord1, EmptyRecord1) -> return ()` arm
        // in `../ipe/src/Ipe/Type/Unify.hs`. Without this arm both roots would
        // fall through to the wildcard mismatch, producing a spurious
        // "TypeMismatch { expected: Unit, found: Unit }" (zonk renders
        // EmptyRecord as Unit for display purposes).
        (FlatType::EmptyRecord, FlatType::EmptyRecord) => {
            uf.union(ra, rb, Content::Structure(FlatType::EmptyRecord))
        }
        _ => Err(mismatch(uf, budget, interner, span, ra, rb)),
    }
}

/// Unify two open records whose field sets differ, so that after the merge each
/// original extension variable resolves to the full field union under a shared
/// tail — keeping both tails live for any later row constraint.
///
/// `only1` / `only2` are the fields unique to each side (the shared fields were
/// already unified). The construction absorbs each side's unique fields into the
/// *other* side's extension:
///
/// - Only one side has extras → that side's tail absorbs them under the OTHER
///   side's actual extension variable, preserving its openness or closedness.
///   Reusing the real tail (rather than a fresh flex) is what lets a closed
///   record stay closed: `{ a | ext1 }` unified with `{ | closed }` binds
///   `ext1 ← { a | closed }`, never a spurious `{ a | fresh }`.
/// - Both sides have extras → mint one shared fresh tail and bind
///   `ext1 ← { only2 | new_ext }`, `ext2 ← { only1 | new_ext }`; the two records
///   become equal, both open on `new_ext`.
///
/// The queued tail unifications run the occurs check (the Flex-vs-Structure
/// arm), so no cycle can form; fresh extension nodes are minted before pushing
/// so each obligation carries a resolved target.
#[allow(clippy::too_many_arguments)]
fn unify_open_record_rows(
    uf: &mut UnionFind<Content>,
    ra: VarId,
    rb: VarId,
    fs1: BTreeMap<ipe_intern::Symbol, VarId>,
    ext1: VarId,
    ext2: VarId,
    only1: Vec<(ipe_intern::Symbol, VarId)>,
    only2: Vec<(ipe_intern::Symbol, VarId)>,
    stack: &mut Vec<(VarId, VarId)>,
) -> DResult<()> {
    // Merged field map: the union of both sides' fields, used as the merged
    // record's structure. `fs1` is moved in; `only2` supplies the right-unique
    // fields. Its extension is chosen below to match each asymmetric case.
    let mut merged = fs1;
    for &(k, v) in &only2 {
        merged.insert(k, v);
    }

    match (only1.is_empty(), only2.is_empty()) {
        // Only side 2 carries extras: side 1's tail absorbs them, keeping side
        // 2's actual extension (open flex or closed sentinel) as the shared tail.
        (true, false) => {
            uf.union(ra, rb, Content::Structure(FlatType::Record(merged, ext2)))?;
            let only2_map: BTreeMap<_, _> = only2.into_iter().collect();
            let ext1_target = uf.fresh(Content::Structure(FlatType::Record(only2_map, ext2)))?;
            stack.push((ext1, ext1_target));
            Ok(())
        }
        // Only side 1 carries extras: symmetric to the case above.
        (false, true) => {
            uf.union(ra, rb, Content::Structure(FlatType::Record(merged, ext1)))?;
            let only1_map: BTreeMap<_, _> = only1.into_iter().collect();
            let ext2_target = uf.fresh(Content::Structure(FlatType::Record(only1_map, ext1)))?;
            stack.push((ext2, ext2_target));
            Ok(())
        }
        // Both sides carry unique fields: a shared fresh tail closes the union,
        // and each original tail absorbs the other side's extras onto it.
        // (Step 2 guaranteed neither side is closed here, since a closed side
        // rejects any of the other's extras.)
        (false, false) => {
            let new_ext = uf.fresh(Content::Flex)?;
            uf.union(
                ra,
                rb,
                Content::Structure(FlatType::Record(merged, new_ext)),
            )?;

            let only2_map: BTreeMap<_, _> = only2.into_iter().collect();
            let ext1_target = uf.fresh(Content::Structure(FlatType::Record(only2_map, new_ext)))?;

            let only1_map: BTreeMap<_, _> = only1.into_iter().collect();
            let ext2_target = uf.fresh(Content::Structure(FlatType::Record(only1_map, new_ext)))?;

            // Push in reverse so LIFO replays them as ext1-then-ext2, matching
            // the original sequential order.
            stack.push((ext2, ext2_target));
            stack.push((ext1, ext1_target));
            Ok(())
        }
        // Unreachable: the caller only enters step 4 when at least one side has
        // extras. Handle it as the identical-field-set merge for total safety.
        (true, true) => {
            uf.union(ra, rb, Content::Structure(FlatType::Record(merged, ext1)))?;
            stack.push((ext1, ext2));
            Ok(())
        }
    }
}

/// Reject binding flexible `var` to `structure` if `var` occurs inside it,
/// surfacing an owned [`TypeError::InfiniteType`] at the real `span`.
fn occurs_guard(
    uf: &mut UnionFind<Content>,
    budget: &mut Budget,
    interner: &Interner,
    span: Span,
    var: VarId,
    structure: VarId,
) -> DResult<()> {
    let target = uf.find(var)?;
    if occurs(uf, budget, target, structure)? {
        Err(infinite_type(uf, budget, interner, span, target, structure))
    } else {
        Ok(())
    }
}

/// Whether the extension variable `v` resolves to [`FlatType::EmptyRecord`]
/// (the closed-tail sentinel).
///
/// Mirrors `isClosedRecordExt` from `../ipe/src/Ipe/Type/Unify.hs:505`.
/// A record is closed iff this returns `true`; open iff it returns `false`
/// (the extension is still a flex variable or has been merged into another open
/// record).
fn is_empty_record(uf: &mut UnionFind<Content>, v: VarId) -> DResult<bool> {
    let root = uf.find(v)?;
    Ok(matches!(
        uf.content(root)?,
        Content::Structure(FlatType::EmptyRecord)
    ))
}

/// Whether `target`'s representative appears within the structure rooted at
/// `node`.
///
/// **Iterative.** Walks an explicit heap-allocated work stack instead of
/// recursing, so adversarial nesting cannot overflow the native stack; the
/// shared [`Budget`] (ticked per node) bounds total work. The structure is
/// acyclic at every call site (occurs runs *before* the bind that could create
/// a cycle), so the walk terminates.
fn occurs(
    uf: &mut UnionFind<Content>,
    budget: &mut Budget,
    target: VarId,
    node: VarId,
) -> DResult<bool> {
    let mut stack: Vec<VarId> = vec![node];
    while let Some(n) = stack.pop() {
        budget.tick()?;
        let here = uf.find(n)?;
        if here == target {
            return Ok(true);
        }
        // Read the descriptor by reference and copy only the child `VarId`s (each
        // `Copy`) onto the work stack — no per-node descriptor clone, so a record
        // node's whole field map is never duplicated just to enumerate its tails.
        match uf.root_content(here)? {
            // Leaves: a flexible, rigid, or super-typed variable, `Unit`, and the
            // `EmptyRecord` closed-tail sentinel carry no children.
            Content::Flex
            | Content::Rigid
            | Content::Super { .. }
            | Content::Structure(FlatType::Unit | FlatType::EmptyRecord) => {}
            Content::Structure(FlatType::Fun(a, r)) => {
                stack.push(*a);
                stack.push(*r);
            }
            Content::Structure(FlatType::Con { args, .. }) => {
                for arg in args {
                    stack.push(*arg);
                }
            }
            Content::Structure(FlatType::Tuple(elems)) => {
                for elem in elems {
                    stack.push(*elem);
                }
            }
            Content::Structure(FlatType::Record(fields, ext)) => {
                for v in fields.values() {
                    stack.push(*v);
                }
                // Also walk the extension variable: a row tail that points back
                // to the record itself would be a cyclic open record.
                stack.push(*ext);
            }
        }
    }
    Ok(false)
}

/// Build an owned [`TypeError::TypeMismatch`] from the two diverging variables.
/// `found` is the actual type, `expected` the wanted one; both are zonked +
/// rendered through a shared [`VarNamer`] so a shared variable reads identically
/// on both sides. If the read-back itself hits an internal invariant, that bug
/// is surfaced instead of the mismatch.
fn mismatch(
    uf: &mut UnionFind<Content>,
    budget: &mut Budget,
    interner: &Interner,
    span: Span,
    found: VarId,
    expected: VarId,
) -> Diagnostic {
    let mut namer = VarNamer::new();
    let expected_ty = match zonk(uf, budget, expected) {
        Ok(t) => t,
        Err(bug) => return bug,
    };
    let found_ty = match zonk(uf, budget, found) {
        Ok(t) => t,
        Err(bug) => return bug,
    };
    // A managed-loop `view` returns `Html` where the shape requires `Element`
    // (or the symmetric case): render the tailored IPE-T0020, which tells the
    // user to return an `Element` or wrap raw `Html` with `Ui.html`, instead of
    // the generic type-mismatch. `Ui.layout` / `Ui.layoutWith` turn an
    // `Element` into `Html`; the shape applies that wrapping itself, so a `view`
    // body ending in one is a first-order authoring mistake worth its own hint.
    if is_element_html_clash(interner, &expected_ty, &found_ty) {
        return Diagnostic::Type {
            span,
            msg: TypeError::WebViewReturnsHtml,
        };
    }
    let expected_doc = match ty_to_doc(&expected_ty, interner, &mut namer) {
        Ok(d) => d,
        Err(bug) => return bug,
    };
    let found_doc = match ty_to_doc(&found_ty, interner, &mut namer) {
        Ok(d) => d,
        Err(bug) => return bug,
    };
    Diagnostic::Type {
        span,
        msg: TypeError::TypeMismatch {
            expected: Box::new(expected_doc),
            found: Box::new(found_doc),
            definition: None,
            path: Box::new([]),
        },
    }
}

/// Whether the two diverging types are the Web view / `Html` pair (in either
/// order) — a managed-loop `view` returning `Html` where the shape requires the
/// Web view carrier (or the symmetric case). The Web view is the engine-tagged
/// carrier `View Web msg` (`Element msg` canonicalises to the same con); its
/// bare per-engine alias `Element` can also survive a read-back. Both view
/// spellings and `html_con` are unqualified nominal cons carrying no module for
/// the emitted type, so a name-string match is exact and cannot collide with a
/// user type.
fn is_element_html_clash(interner: &Interner, a: &Ty, b: &Ty) -> bool {
    let is_html =
        |t: &Ty| matches!(t, Ty::Con { name, .. } if interner.resolve(*name) == Some("Html"));
    (is_web_view(interner, a) && is_html(b)) || (is_html(a) && is_web_view(interner, b))
}

/// Whether the type is the Web view carrier — the engine-tagged `View Web msg`
/// (first argument the `Web` engine tag) or its bare per-engine alias `Element`.
/// Only the Web engine turns its `Element` body into `Html`, so the tailored
/// hint is scoped to it; a `View Tui msg` / `View Cli msg` clash falls through
/// to the generic mismatch.
fn is_web_view(interner: &Interner, t: &Ty) -> bool {
    match t {
        Ty::Con { name, args, .. } => match interner.resolve(*name) {
            Some("Element") => true,
            Some("View") => matches!(
                args.first(),
                Some(Ty::Con { name: tag, .. }) if interner.resolve(*tag) == Some("Web")
            ),
            _ => false,
        },
        _ => false,
    }
}

/// Build an owned [`TypeError::InfiniteType`] naming the offending variable and
/// the structure it would have to equal.
fn infinite_type(
    uf: &mut UnionFind<Content>,
    budget: &mut Budget,
    interner: &Interner,
    span: Span,
    var: VarId,
    structure: VarId,
) -> Diagnostic {
    let mut namer = VarNamer::new();
    // Name the variable first so it reads as `a` and any same var inside the
    // structure renders consistently.
    let var_ty = match zonk(uf, budget, var) {
        Ok(t) => t,
        Err(bug) => return bug,
    };
    let var_name = match ty_to_doc(&var_ty, interner, &mut namer) {
        Ok(ipe_diagnostics::TyDoc::Var(v)) => v,
        // The occurs target is always flexible at the guard site; any other
        // shape (or a read-back bug) is an internal invariant violation.
        Ok(_) => Box::from("?"),
        Err(bug) => return bug,
    };
    let structure_ty = match zonk(uf, budget, structure) {
        Ok(t) => t,
        Err(bug) => return bug,
    };
    let structure_doc = match ty_to_doc(&structure_ty, interner, &mut namer) {
        Ok(d) => d,
        Err(bug) => return bug,
    };
    Diagnostic::Type {
        span,
        msg: TypeError::InfiniteType {
            var: var_name,
            ty: Box::new(structure_doc),
        },
    }
}

#[cfg(test)]
mod tests {
    use ipe_diagnostics::Span;
    use ipe_intern::Interner;

    use super::*;
    use crate::solve::Budget;
    use crate::ty::TyBounds;
    use crate::unionfind::UnionFind;

    fn super_var(uf: &mut UnionFind<Content>, rigid: bool, bounds: TyBounds) -> VarId {
        uf.fresh(Content::Super { rigid, bounds })
            .expect("fresh var")
    }

    fn do_unify(
        uf: &mut UnionFind<Content>,
        a: VarId,
        b: VarId,
    ) -> Result<(), ipe_diagnostics::Diagnostic> {
        let mut budget = Budget::unbounded();
        let interner = Interner::new();
        unify(uf, &mut budget, &interner, Span::DUMMY, a, b)
    }

    /// Eq (rigid) ∪ Stringify (flex) — both are pure trait-bound obligations,
    /// so cross-rigidity union is allowed. Result: rigid:true, bounds = Eq|SHOW.
    #[test]
    fn super_super_eq_rigid_stringify_flex_unions() {
        let mut uf = UnionFind::new();
        let a = super_var(&mut uf, true, TyBounds::eq());
        let b = super_var(&mut uf, false, TyBounds::show());
        assert!(do_unify(&mut uf, a, b).is_ok(), "Eq+Stringify should union");
        let rep = uf.find(a).expect("find");
        let content = uf.content(rep).expect("content");
        assert_eq!(
            content,
            Content::Super {
                rigid: true,
                bounds: TyBounds::eq().union(TyBounds::show()),
            },
            "merged content must be rigid with Eq|SHOW"
        );
    }

    /// Add (rigid) ∪ Add (flex) — Add is a concrete-dispatch (Number) obligation.
    /// Cross-rigidity merge is forbidden: result is MISMATCH.
    #[test]
    fn super_super_number_rigid_number_flex_mismatch() {
        let mut uf = UnionFind::new();
        let a = super_var(&mut uf, true, TyBounds::add());
        let b = super_var(&mut uf, false, TyBounds::add());
        assert!(
            do_unify(&mut uf, a, b).is_err(),
            "Add rigid+flex cross-rigidity must mismatch"
        );
    }

    /// Append (rigid) ∪ Eq (flex) — Append is a concrete-dispatch obligation.
    /// Even though Eq is not, Append on EITHER side blocks cross-rigidity union.
    #[test]
    fn super_super_append_rigid_eq_flex_mismatch() {
        let mut uf = UnionFind::new();
        let a = super_var(&mut uf, true, TyBounds::appendable());
        let b = super_var(&mut uf, false, TyBounds::eq());
        assert!(
            do_unify(&mut uf, a, b).is_err(),
            "Append (rigid) ∪ Eq (flex) must mismatch"
        );
    }

    /// Eq (flex) ∪ Ord (flex) — same rigidity, always unioned regardless of
    /// bounds. Result: flex with Eq|Ord.
    #[test]
    fn super_super_same_rigidity_always_unions() {
        let mut uf = UnionFind::new();
        let a = super_var(&mut uf, false, TyBounds::eq());
        let b = super_var(&mut uf, false, TyBounds::ord());
        assert!(
            do_unify(&mut uf, a, b).is_ok(),
            "same-rigidity must always union"
        );
        let rep = uf.find(a).expect("find");
        let content = uf.content(rep).expect("content");
        assert_eq!(
            content,
            Content::Super {
                rigid: false,
                bounds: TyBounds::eq().union(TyBounds::ord()),
            },
        );
    }

    /// Two distinct RIGID supers are two independent annotation skolems; a
    /// same-class pair short-circuits at the root check, so any rigid/rigid pair
    /// reaching the Super×Super arm must MISMATCH — merging them would accept a
    /// program whose emitted Rust then fails to type-check. Holds even when both
    /// carry only pure trait-bound obligations (which cross rigidity when one
    /// side is flex).
    #[test]
    fn super_super_both_rigid_eq_mismatch() {
        let mut uf = UnionFind::new();
        let a = super_var(&mut uf, true, TyBounds::eq());
        let b = super_var(&mut uf, true, TyBounds::eq());
        assert!(
            do_unify(&mut uf, a, b).is_err(),
            "two distinct rigid annotation skolems must never merge"
        );
    }

    /// Merging two `List` structures whose element already IS the other root
    /// would make the class contain itself (`t = List t`); the structure-vs-
    /// structure path must reject it as an infinite type, not mint the cycle.
    #[test]
    fn cyclic_con_union_is_infinite_type() {
        let mut uf = UnionFind::new();
        let empty: Vec<ipe_intern::Symbol> = Vec::new();
        // `outer = List(inner)` where `inner` is a fresh flex.
        let inner = uf.fresh(Content::Flex).expect("fresh inner");
        let list_name = {
            let mut interner = Interner::new();
            interner.intern("List").expect("intern List")
        };
        let outer = uf
            .fresh(Content::Structure(FlatType::Con {
                module: empty.clone(),
                name: list_name,
                args: vec![inner],
            }))
            .expect("fresh outer");
        // `self_list = List(outer)`. Unifying it with `outer` forces
        // `inner = outer`, i.e. `outer = List outer` — an infinite type.
        let self_list = uf
            .fresh(Content::Structure(FlatType::Con {
                module: empty,
                name: list_name,
                args: vec![outer],
            }))
            .expect("fresh self_list");
        assert!(
            do_unify(&mut uf, outer, self_list).is_err(),
            "a structure that would contain itself must be rejected"
        );
    }

    // ── Open-record tail-propagation tests ──────────────────────────────────

    /// Build a fresh `Unit` solver variable (a concrete leaf with no children,
    /// used as a stand-in for a field's type in record tests).
    fn unit_var(uf: &mut UnionFind<Content>) -> VarId {
        uf.fresh(Content::Structure(FlatType::Unit))
            .expect("fresh unit var")
    }

    /// Build an open `Record` node with the given field→var pairs and a fresh
    /// flex extension variable; return `(record_var, ext_var)`.
    fn open_record(
        uf: &mut UnionFind<Content>,
        fields: BTreeMap<ipe_intern::Symbol, VarId>,
    ) -> (VarId, VarId) {
        let ext = uf.fresh(Content::Flex).expect("fresh ext");
        let rec = uf
            .fresh(Content::Structure(FlatType::Record(fields, ext)))
            .expect("fresh record");
        (rec, ext)
    }

    /// Build a CLOSED `Record` node (`EmptyRecord` extension) with the given
    /// fields; return the record var.
    fn closed_record(
        uf: &mut UnionFind<Content>,
        fields: BTreeMap<ipe_intern::Symbol, VarId>,
    ) -> VarId {
        let closed = uf
            .fresh(Content::Structure(FlatType::EmptyRecord))
            .expect("fresh empty-record sentinel");
        uf.fresh(Content::Structure(FlatType::Record(fields, closed)))
            .expect("fresh closed record")
    }

    /// A constraint routed through an original extension variable after the
    /// merge must reach the merged record's fields.
    ///
    /// `{ x : Unit | ext1 }` unified with `{ y : Unit | ext2 }` (both open,
    /// disjoint fields) merges to `{ x : Unit, y : Unit | new_ext }`, with
    /// `ext1` bound to `{ y : Unit | new_ext }`. A later `unify(ext1, { y : Unit
    /// })` therefore meets the absorbed `y` field and succeeds — the tail stayed
    /// connected to the merged record rather than pointing at an orphan.
    #[test]
    fn open_record_merge_tail_constraint_propagates() {
        let mut uf = UnionFind::new();
        let mut interner = Interner::new();

        let sx = interner.intern("x").expect("intern x");
        let sy = interner.intern("y").expect("intern y");

        let vx = unit_var(&mut uf);
        let vy1 = unit_var(&mut uf);
        let vy2 = unit_var(&mut uf);

        // R1 = { x : Unit | ext1 },  R2 = { y : Unit | ext2 }
        let (r1, ext1) = open_record(&mut uf, BTreeMap::from([(sx, vx)]));
        let (r2, _ext2) = open_record(&mut uf, BTreeMap::from([(sy, vy1)]));

        // Merge the two open records.
        let mut budget = Budget::unbounded();
        unify(&mut uf, &mut budget, &interner, Span::DUMMY, r1, r2)
            .expect("open-record merge must succeed");

        // Constrain ext1 further by closing it as `{ y : Unit }`. ext1 already
        // carries the absorbed `y` field, so this compatible constraint succeeds.
        let constraint = closed_record(&mut uf, BTreeMap::from([(sy, vy2)]));
        unify(
            &mut uf,
            &mut budget,
            &interner,
            Span::DUMMY,
            ext1,
            constraint,
        )
        .expect("tail constraint must reach the merged record and succeed");
    }

    /// A post-merge constraint routed through an original tail that *conflicts*
    /// with an already-merged field must be rejected (soundness).
    ///
    /// After merging `{ x : Unit | ext1 }` with `{ y : Unit | ext2 }`, `ext2` is
    /// bound to `{ x : Unit | new_ext }`. Sending `unify(ext2, { x : Unit -> Unit
    /// })` then forces `x`'s type to disagree (`Unit` vs a function), so the
    /// unifier fails instead of silently accepting the incompatible constraint.
    #[test]
    fn open_record_merge_conflicting_tail_constraint_is_rejected() {
        let mut uf = UnionFind::new();
        let mut interner = Interner::new();

        let sx = interner.intern("x").expect("intern x");
        let sy = interner.intern("y").expect("intern y");

        let vx = unit_var(&mut uf);
        let vy = unit_var(&mut uf);

        // R1 = { x : Unit | ext1 },  R2 = { y : Unit | ext2 }
        let (r1, _ext1) = open_record(&mut uf, BTreeMap::from([(sx, vx)]));
        let (r2, ext2) = open_record(&mut uf, BTreeMap::from([(sy, vy)]));

        let mut budget = Budget::unbounded();
        unify(&mut uf, &mut budget, &interner, Span::DUMMY, r1, r2)
            .expect("open-record merge must succeed");

        // Send a constraint through ext2 claiming `x : Unit -> Unit`. ext2
        // carries the absorbed `x : Unit`, so the field types disagree and the
        // constraint must fail.
        let arg = unit_var(&mut uf);
        let ret = unit_var(&mut uf);
        let fun_type = uf
            .fresh(Content::Structure(FlatType::Fun(arg, ret)))
            .expect("fresh fun type");
        // `x` field carries a Fun type — conflicts with the Unit already merged.
        let conflicting = closed_record(&mut uf, BTreeMap::from([(sx, fun_type)]));

        let result = unify(
            &mut uf,
            &mut budget,
            &interner,
            Span::DUMMY,
            ext2,
            conflicting,
        );
        assert!(
            result.is_err(),
            "conflicting type for already-merged field must be rejected (soundness)"
        );
    }

    /// An OPEN record with fewer fields unifies with a CLOSED record carrying an
    /// extra field: the open tail absorbs the extra and the record closes.
    ///
    /// This is the optional-config-field shape (an open kernel cfg record meeting
    /// a fully-specified literal). Only the closed side has a unique field, so the
    /// open tail must absorb it under the *closed* sentinel — never a fresh open
    /// tail, which would wrongly reject the program by pitting the closed tail
    /// against an empty open record.
    #[test]
    fn open_record_absorbs_closed_side_extra_field() {
        let mut uf = UnionFind::new();
        let mut interner = Interner::new();

        let sa = interner.intern("a").expect("intern a");
        let sb = interner.intern("b").expect("intern b");

        let va = unit_var(&mut uf);
        let vb = unit_var(&mut uf);
        let va2 = unit_var(&mut uf);

        // Open `{ a : Unit | ext }` vs closed `{ a : Unit, b : Unit }`.
        let (open, ext) = open_record(&mut uf, BTreeMap::from([(sa, va)]));
        let closed = closed_record(&mut uf, BTreeMap::from([(sa, va2), (sb, vb)]));

        let mut budget = Budget::unbounded();
        unify(&mut uf, &mut budget, &interner, Span::DUMMY, open, closed)
            .expect("open record must absorb the closed side's extra field");

        // The open tail became `{ b : Unit }` closed. A further closed record
        // that adds an unknown field `c` cannot be absorbed, proving the tail
        // closed rather than staying open.
        let sc = interner.intern("c").expect("intern c");
        let vb2 = unit_var(&mut uf);
        let vc = unit_var(&mut uf);
        let extra = closed_record(&mut uf, BTreeMap::from([(sb, vb2), (sc, vc)]));
        let result = unify(&mut uf, &mut budget, &interner, Span::DUMMY, ext, extra);
        assert!(
            result.is_err(),
            "the absorbed tail must be closed, rejecting a further field (soundness)"
        );
    }

    // ── Deep-spine stack-safety tests ───────────────────────────────────────

    /// Build a right-nested function spine `Unit -> Unit -> … -> leaf` of the
    /// given `depth`, returning the outermost variable. Depth zero is `leaf`.
    fn fun_spine(uf: &mut UnionFind<Content>, depth: usize, leaf: VarId) -> VarId {
        let mut result = leaf;
        for _ in 0..depth {
            let arg = unit_var(uf);
            result = uf
                .fresh(Content::Structure(FlatType::Fun(arg, result)))
                .expect("fresh fun node");
        }
        result
    }

    /// Two curried-lambda types tens of thousands of parameters deep unify
    /// without overflowing the native stack. Native recursion of this depth
    /// segfaults the type-checker on the default 8MB stack (issue #1840); the
    /// iterative work-stack turns it into ordinary bounded heap work.
    #[test]
    fn deep_fun_spine_unifies_without_stack_overflow() {
        const DEPTH: usize = 200_000;
        let mut uf = UnionFind::new();
        let interner = Interner::new();

        let leaf_a = unit_var(&mut uf);
        let leaf_b = unit_var(&mut uf);
        let a = fun_spine(&mut uf, DEPTH, leaf_a);
        let b = fun_spine(&mut uf, DEPTH, leaf_b);

        let mut budget = Budget::unbounded();
        unify(&mut uf, &mut budget, &interner, Span::DUMMY, a, b)
            .expect("deep matching spines must unify");
    }

    /// A deep spine whose leaf is incompatible surfaces a typed mismatch rather
    /// than crashing: the walk descends the whole spine iteratively and reports
    /// the leaf clash as an ordinary error.
    #[test]
    fn deep_fun_spine_leaf_mismatch_is_typed_error() {
        const DEPTH: usize = 200_000;
        let mut uf = UnionFind::new();
        let interner = Interner::new();

        let leaf_a = unit_var(&mut uf);
        // A function-typed leaf on the other side: `Unit` vs `Unit -> Unit`
        // cannot unify, so the deepest obligation is a mismatch.
        let arg = unit_var(&mut uf);
        let ret = unit_var(&mut uf);
        let leaf_b = uf
            .fresh(Content::Structure(FlatType::Fun(arg, ret)))
            .expect("fresh leaf fun");
        let a = fun_spine(&mut uf, DEPTH, leaf_a);
        let b = fun_spine(&mut uf, DEPTH, leaf_b);

        let mut budget = Budget::unbounded();
        let result = unify(&mut uf, &mut budget, &interner, Span::DUMMY, a, b);
        assert!(
            result.is_err(),
            "an incompatible leaf under a deep spine must be a typed error, not a crash"
        );
    }

    // ── Nominal-Con empty-home compatibility tests ──────────────────────────

    /// Build a nullary `Con` node with the given interned home path and name.
    fn con_var(
        uf: &mut UnionFind<Content>,
        home: Vec<ipe_intern::Symbol>,
        name: ipe_intern::Symbol,
    ) -> VarId {
        uf.fresh(Content::Structure(FlatType::Con {
            module: home,
            name,
            args: Vec::new(),
        }))
        .expect("fresh Con var")
    }

    /// A user-shadowable builtin (`Order`) declared in a user module carries a
    /// real home (`[Main]`). The builtin `Order` (from a kernel scheme such as
    /// `compare`) carries the empty home. They are DISTINCT types and must NOT
    /// unify — the empty-home wildcard is restricted to reserved builtins, so a
    /// shadowable-name home disagreement is a mismatch (soundness).
    #[test]
    fn shadowable_builtin_user_home_vs_empty_kernel_home_mismatch() {
        let mut uf = UnionFind::new();
        let mut interner = Interner::new();
        let order = interner.intern("Order").expect("intern Order");
        let main = interner.intern("Main").expect("intern Main");

        let user_order = con_var(&mut uf, vec![main], order);
        let builtin_order = con_var(&mut uf, Vec::new(), order);

        let mut budget = Budget::unbounded();
        let result = unify(
            &mut uf,
            &mut budget,
            &interner,
            Span::DUMMY,
            user_order,
            builtin_order,
        );
        assert!(
            result.is_err(),
            "user `type Order` ([Main]) must not unify with the empty-home builtin `Order`"
        );
    }

    /// A RESERVED builtin (`HttpMethod`, never user-declarable) reached through a
    /// stdlib qualifier carries a non-empty home; the kernel spelling carries the
    /// empty home. A non-empty home for a reserved name is always a builtin
    /// qualifier, so the two must still unify (no regression on qualified
    /// builtin annotations).
    #[test]
    fn reserved_builtin_qualified_home_vs_empty_kernel_home_unifies() {
        let mut uf = UnionFind::new();
        let mut interner = Interner::new();
        let method = interner.intern("HttpMethod").expect("intern HttpMethod");
        let http = interner.intern("Http").expect("intern Http");

        let qualified = con_var(&mut uf, vec![http], method);
        let kernel = con_var(&mut uf, Vec::new(), method);

        let mut budget = Budget::unbounded();
        unify(
            &mut uf,
            &mut budget,
            &interner,
            Span::DUMMY,
            qualified,
            kernel,
        )
        .expect("reserved builtin qualified home must unify with the empty-home kernel Con");
    }

    /// A shadowable builtin that a compiled-source `Ipe.*` stdlib module also
    /// declares/re-exports (`ErrorKind` from `Ipe.Error`) resolves to the stdlib
    /// home `[Ipe, Error]` in that module while a kernel scheme mints the empty
    /// home. These are the SAME builtin and must unify — an `Ipe`-rooted home is
    /// the stdlib spelling, never a user shadow.
    #[test]
    fn shadowable_builtin_stdlib_home_vs_empty_kernel_home_unifies() {
        let mut uf = UnionFind::new();
        let mut interner = Interner::new();
        let kind = interner.intern("ErrorKind").expect("intern ErrorKind");
        let ipe = interner.intern("Ipe").expect("intern Ipe");
        let error = interner.intern("Error").expect("intern Error");

        let stdlib = con_var(&mut uf, vec![ipe, error], kind);
        let kernel = con_var(&mut uf, Vec::new(), kind);

        let mut budget = Budget::unbounded();
        unify(&mut uf, &mut budget, &interner, Span::DUMMY, stdlib, kernel)
            .expect("stdlib-homed builtin must unify with its empty-home kernel Con");
    }

    /// Two empty-home builtin `Con`s of the same name always unify — the common
    /// kernel-implicit annotation path (both sides empty).
    #[test]
    fn two_empty_home_builtins_unify() {
        let mut uf = UnionFind::new();
        let mut interner = Interner::new();
        let order = interner.intern("Order").expect("intern Order");

        let a = con_var(&mut uf, Vec::new(), order);
        let b = con_var(&mut uf, Vec::new(), order);

        let mut budget = Budget::unbounded();
        unify(&mut uf, &mut budget, &interner, Span::DUMMY, a, b)
            .expect("two empty-home builtin Cons of the same name must unify");
    }

    /// A NON-builtin name with an empty home on one side is a mismatch against a
    /// user home: after fail-closed resolution an empty home can only be a
    /// builtin, so a home disagreement for an ordinary user type is a genuine
    /// clash rather than a wildcard match.
    #[test]
    fn non_builtin_name_empty_vs_user_home_mismatch() {
        let mut uf = UnionFind::new();
        let mut interner = Interner::new();
        let widget = interner.intern("Widget").expect("intern Widget");
        let main = interner.intern("Main").expect("intern Main");

        let user = con_var(&mut uf, vec![main], widget);
        let empty = con_var(&mut uf, Vec::new(), widget);

        let mut budget = Budget::unbounded();
        let result = unify(&mut uf, &mut budget, &interner, Span::DUMMY, user, empty);
        assert!(
            result.is_err(),
            "a non-builtin name with an empty home must not wildcard-match a user home"
        );
    }
}
