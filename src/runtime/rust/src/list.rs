//! Ipe.List kernel — the single home for the List runtime surface.

use super::IpeMaybe;
use super::basics::{IpeOrder, IpeWrappingAdd, IpeWrappingMul};

/// `Ipe.List.singleton : a -> List a` — the one-element list `[x]`. Total.
pub fn list_singleton<T>(x: T) -> Vec<T> {
    vec![x]
}

/// `Ipe.List.repeat : Int -> a -> List a` — `n` copies of `x`. Elm semantics:
/// `n <= 0` yields `[]`. `T: Clone` because each copy is a fresh clone.
pub fn list_repeat<T: Clone>(n: i64, x: T) -> Vec<T> {
    if n <= 0 {
        Vec::new()
    } else {
        // `n > 0` here, so `n as usize` is total on 64-bit targets.
        vec![x; n as usize]
    }
}

/// `Ipe.List.sum : number a => List a -> a` — the additive fold. Empty list
/// sums to the type's additive identity (`0` / `0.0`). Folds through the same
/// wrapping add Ipê's `(+)` lowers to, so the reduction wraps identically to
/// repeated inline `(+)` and never overflow-aborts under `overflow-checks=on`.
#[must_use]
pub fn list_sum<T: IpeWrappingAdd<T, Output = T>>(xs: Vec<T>) -> T {
    xs.into_iter()
        .fold(T::IPE_ADD_IDENTITY, |acc, x| acc.ipe_wrapping_add(x))
}

/// `Ipe.List.product : number a => List a -> a` — the multiplicative fold.
/// Empty list yields the multiplicative identity (`1` / `1.0`). Folds through
/// the same wrapping mul Ipê's `(*)` lowers to, so the reduction wraps
/// identically to repeated inline `(*)` and never overflow-aborts under
/// `overflow-checks=on`.
#[must_use]
pub fn list_product<T: IpeWrappingMul<T, Output = T>>(xs: Vec<T>) -> T {
    xs.into_iter()
        .fold(T::IPE_MUL_IDENTITY, |acc, x| acc.ipe_wrapping_mul(x))
}

/// `Ipe.List.maximum : comparable a => List a -> Maybe a` — the largest
/// element, or `Nothing` on the empty list. Total on NaN (`cmp_total` maps an
/// incomparable pair to `Equal`, so `max_by` never trips `Ord`).
pub fn list_maximum<T: PartialOrd>(xs: Vec<T>) -> IpeMaybe<T> {
    match xs.into_iter().max_by(cmp_total) {
        Some(x) => IpeMaybe::Just(x),
        None => IpeMaybe::Nothing,
    }
}

/// `Ipe.List.minimum : comparable a => List a -> Maybe a` — the smallest
/// element, or `Nothing` on the empty list. Total on NaN (see `list_maximum`).
pub fn list_minimum<T: PartialOrd>(xs: Vec<T>) -> IpeMaybe<T> {
    match xs.into_iter().min_by(cmp_total) {
        Some(x) => IpeMaybe::Just(x),
        None => IpeMaybe::Nothing,
    }
}

/// `Ipe.List.unique : List a -> List a` — the elements with duplicates removed,
/// keeping the FIRST occurrence of each and preserving that first-seen order.
/// `T: PartialEq` is the same equality bound `list_member` carries: membership is
/// tested with `==`, so an already-seen element is dropped. `T: Clone` because
/// each kept element is retained in the `seen` set while its original flows into
/// the output. Quadratic in the worst case (linear membership scan per element),
/// matching the equality-only contract — no `Ord`/`Hash` obligation is imposed on
/// the element type, so it is total for any equatable `a`.
pub fn list_unique<T: PartialEq + Clone>(xs: Vec<T>) -> Vec<T> {
    let mut seen: Vec<T> = Vec::new();
    let mut out: Vec<T> = Vec::new();
    for x in xs {
        if !seen.contains(&x) {
            seen.push(x.clone());
            out.push(x);
        }
    }
    out
}

/// `Ipe.List.intersperse : a -> List a -> List a` — place `sep` between each
/// pair of elements. `[]` and `[x]` are unchanged. `T: Clone` because `sep` is
/// cloned into every gap.
pub fn list_intersperse<T: Clone>(sep: T, xs: Vec<T>) -> Vec<T> {
    let mut out = Vec::with_capacity(xs.len().saturating_mul(2).saturating_sub(1));
    let mut first = true;
    for x in xs {
        if first {
            first = false;
        } else {
            out.push(sep.clone());
        }
        out.push(x);
    }
    out
}

/// `Ipe.List.partition : (a -> Bool) -> List a -> (List a, List a)` — split into
/// (satisfying, not-satisfying), preserving input order in each. `T: Clone` is
/// the element-clone bound the by-value Ipê closure ABI requires (same as
/// `list_filter`).
pub fn list_partition<T: Clone>(pred: impl Fn(T) -> bool, xs: Vec<T>) -> (Vec<T>, Vec<T>) {
    let mut yes = Vec::new();
    let mut no = Vec::new();
    for x in xs {
        if pred(x.clone()) {
            yes.push(x);
        } else {
            no.push(x);
        }
    }
    (yes, no)
}

/// `Ipe.List.unzip : List (a, b) -> (List a, List b)` — split a list of pairs
/// into a pair of lists. Total; consumes the input.
#[must_use]
pub fn list_unzip<A, B>(xs: Vec<(A, B)>) -> (Vec<A>, Vec<B>) {
    xs.into_iter().unzip()
}

/// `Ipe.List.sortWith : (a -> a -> Order) -> List a -> List a` — stable sort by
/// a user comparator returning a Ipê `Order` (`LT`/`EQ`/`GT`). The comparator
/// takes its two elements by value (the Ipê closure ABI), so `a` must be
/// `Clone`. Panic-safe: an inconsistent comparator (not a strict weak ordering)
/// leaves the slice in its safe, element-complete (unspecified-order) state
/// instead of panicking (std sort panics on such a comparator since Rust 1.81).
pub fn list_sort_with_order<A: Clone>(cmp: impl Fn(A, A) -> IpeOrder, list: Vec<A>) -> Vec<A> {
    let mut result = list;
    let order = &mut result;
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        order.sort_by(|a, b| match cmp(a.clone(), b.clone()) {
            IpeOrder::LT => std::cmp::Ordering::Less,
            IpeOrder::EQ => std::cmp::Ordering::Equal,
            IpeOrder::GT => std::cmp::Ordering::Greater,
        });
    }));
    if outcome.is_err() {
        crate::system::emit_runtime_log(
            "list",
            "List.sortWith: comparator is not a consistent total order; returning input in unspecified order",
        );
    }
    result
}

/// `Ipe.List.map2 : (a -> b -> r) -> List a -> List b -> List r` — combine two
/// lists element-wise, truncating to the shorter (Elm semantics).
pub fn list_map2<A, B, R>(f: impl Fn(A, B) -> R, a: Vec<A>, b: Vec<B>) -> Vec<R> {
    a.into_iter().zip(b).map(|(x, y)| f(x, y)).collect()
}

/// `Ipe.List.map3 : (a -> b -> c -> r) -> List a -> List b -> List c -> List r`
/// — combine three lists element-wise, truncating to the shortest.
pub fn list_map3<A, B, C, R>(f: impl Fn(A, B, C) -> R, a: Vec<A>, b: Vec<B>, c: Vec<C>) -> Vec<R> {
    a.into_iter()
        .zip(b)
        .zip(c)
        .map(|((x, y), z)| f(x, y, z))
        .collect()
}

/// `Ipe.List.map4` — combine four lists element-wise, truncating to the shortest.
pub fn list_map4<A, B, C, D, R>(
    f: impl Fn(A, B, C, D) -> R,
    a: Vec<A>,
    b: Vec<B>,
    c: Vec<C>,
    d: Vec<D>,
) -> Vec<R> {
    a.into_iter()
        .zip(b)
        .zip(c)
        .zip(d)
        .map(|(((w, x), y), z)| f(w, x, y, z))
        .collect()
}

/// `Ipe.List.map5` — combine five lists element-wise, truncating to the shortest.
pub fn list_map5<A, B, C, D, E, R>(
    f: impl Fn(A, B, C, D, E) -> R,
    a: Vec<A>,
    b: Vec<B>,
    c: Vec<C>,
    d: Vec<D>,
    e: Vec<E>,
) -> Vec<R> {
    a.into_iter()
        .zip(b)
        .zip(c)
        .zip(d)
        .zip(e)
        .map(|((((v, w), x), y), z)| f(v, w, x, y, z))
        .collect()
}

/// `Ipe.List.length` — element count (kernel-routed call sites; the pure-Ipê
/// `ipe_core_list_length` is the recursive stdlib form).
#[must_use]
pub fn list_length<T>(xs: Vec<T>) -> i64 {
    xs.len() as i64
}

/// `Ipe.List.head : List a -> Maybe a` — the first element, or `Nothing`
/// on the empty list. Total (no indexing panic).
#[must_use]
pub fn list_head<T>(xs: Vec<T>) -> IpeMaybe<T> {
    match xs.into_iter().next() {
        Some(x) => IpeMaybe::Just(x),
        None => IpeMaybe::Nothing,
    }
}

/// `Ipe.List.tail : List a -> Maybe (List a)` — everything after the first
/// element, or `Nothing` on the empty list. Total (no indexing panic); mirrors
/// the pure-Ipê `tail` (`[] -> Nothing`, `(_ :: rest) -> Just rest`).
#[must_use]
pub fn list_tail<T>(xs: Vec<T>) -> IpeMaybe<Vec<T>> {
    if xs.is_empty() {
        IpeMaybe::Nothing
    } else {
        // Drop the head; the remaining elements move into the tail vector.
        IpeMaybe::Just(xs.into_iter().skip(1).collect())
    }
}

/// `Ipe.List.reverse : List a -> List a` — the elements in reverse order.
/// Total; no `T: Clone` bound (the elements only MOVE).
#[must_use]
pub fn list_reverse<T>(xs: Vec<T>) -> Vec<T> {
    let mut xs = xs;
    xs.reverse();
    xs
}

/// `Ipe.List.drop : Int -> List a -> List a` — drops the first `n`
/// elements. `n <= 0` keeps the whole list; `n >= len` yields `[]`. Total.
#[must_use]
pub fn list_drop<T>(n: i64, xs: Vec<T>) -> Vec<T> {
    if n <= 0 {
        xs
    } else {
        xs.into_iter().skip(n as usize).collect()
    }
}

/// `Ipe.List.append : List a -> List a -> List a` — the two lists
/// concatenated. Iterative (`extend`, constant native stack); no `T: Clone`
/// bound (both inputs are consumed and MOVE).
#[must_use]
pub fn list_append<T>(xs: Vec<T>, ys: Vec<T>) -> Vec<T> {
    let mut xs = xs;
    xs.extend(ys);
    xs
}

/// `Ipe.List.concat : List (List a) -> List a` — flatten one level.
/// Iterative (`flatten`, constant native stack); consumes the input.
#[must_use]
pub fn list_concat<T>(xss: Vec<Vec<T>>) -> Vec<T> {
    xss.into_iter().flatten().collect()
}

/// `Ipe.List.take : Int -> List a -> List a` — the first `n` elements.
/// Elm semantics: `n <= 0` yields `[]`; `n >= len` yields the whole list.
/// `n.max(0)` is non-negative, so the `as usize` cast is total on 64-bit
/// targets (an `i64` in `0..=i64::MAX` fits `usize`); `truncate(k)` with
/// `k >= len` is a no-op. No indexing, no overflow, no panic.
#[must_use]
pub fn list_take<T>(n: i64, xs: Vec<T>) -> Vec<T> {
    let mut xs = xs;
    xs.truncate(n.max(0) as usize);
    xs
}

/// `Ipe.List.isEmpty : List a -> Bool`. Total.
#[must_use]
pub fn list_is_empty<T>(xs: Vec<T>) -> bool {
    xs.is_empty()
}

/// Ipê `filterMap : (a -> Maybe b) -> List a -> List b`.
/// Applies `f` to each element; keeps only `Just` results.
pub fn list_filter_map<A, B>(f: impl Fn(A) -> IpeMaybe<B>, xs: Vec<A>) -> Vec<B> {
    xs.into_iter()
        .filter_map(|x| match f(x) {
            IpeMaybe::Just(v) => Some(v),
            IpeMaybe::Nothing => None,
        })
        .collect()
}

// ── Core List kernels (relocated from core.rs so the List surface has one home) ──

/// Ipê `::` cons — emitted by codegen for the cons operator.
// No `T: Clone` bound — `once(x).chain(xs)` only MOVES, so cons works for
// move-only element types too (e.g. `Cmd.batch [IpeCmd, …]`; IpeCmd isn't Clone).
pub fn ipe_list_cons<T>(x: T, xs: Vec<T>) -> Vec<T> {
    std::iter::once(x).chain(xs).collect()
}

// The 8 HOF kernels below take `f: impl Fn(..) -> ..` with NO `+ Clone` bound
// on the CALLBACK: none of these implementations clones `f` — each calls it
// through a shared `&self` borrow (directly, or via a wrapping closure that
// MOVES `f` in once), which only needs `Fn`/`FnMut`. Rust's blanket impl
// (every `Fn` is also `FnMut`) covers every call shape below (`for` loop,
// `Iterator::map`/`filter`/`any`/`all`/`flat_map`). A stray `+ Clone` here
// would be unsatisfiable: codegen boxes lambda VALUES as
// `Box<dyn Fn(..) -> .. + Send>` (`ipe_backend_rust::emit_expr::emit_lambda`),
// and `Box<dyn Fn>` is NEVER `Clone` (trait objects can't derive it), so the
// FIRST closure — of ANY shape, capturing or not — would fail E0277. The bound
// stays `impl Fn` / `impl FnOnce`, matching every OTHER HOF kernel in this
// crate. (The element params `T0: Clone` / `A: Clone` are a separate, real
// requirement — see `list_filter`'s `x.clone()` and `list_sort_by`'s doc.)
pub fn list_foldl<T0, T1>(f: impl Fn(T0, T1) -> T1, init: T1, list: Vec<T0>) -> T1 {
    let mut acc = init;
    for item in list {
        acc = f(item, acc);
    }
    acc
}
pub fn list_foldr<T0, T1>(f: impl Fn(T0, T1) -> T1, init: T1, list: Vec<T0>) -> T1 {
    let mut acc = init;
    // `into_iter().rev()` yields OWNED items, so no clone (and no `T0: Clone`
    // bound) is needed — matching `ipe_list_cons`'s move-only-friendly shape.
    for item in list.into_iter().rev() {
        acc = f(item, acc);
    }
    acc
}
// Ipê `List.range` is INCLUSIVE: range 1 3 = [1, 2, 3].
#[must_use]
pub fn list_range(lo: i64, hi: i64) -> Vec<i64> {
    // Bound the allocation: lo/hi are caller-controlled; an absurd span (e.g.
    // 0..i64::MAX) would OOM. Cap at 10M elements (any real list is far smaller).
    // Over the cap, emit the first 10M (a correct PREFIX) plus a structured warn,
    // never a silently-wrong empty list — `[]` for `List.range 1 20000000` is a
    // wrong result for input Ipê's types accept, far more surprising than a
    // truncated-with-warning span.
    const CAP: usize = 10_000_000;
    if hi < lo {
        return Vec::new();
    }
    let n = i128::from(hi) - i128::from(lo) + 1;
    if n > CAP as i128 {
        crate::system::emit_runtime_log(
            "list",
            &format!(
                "List.range: span of {n} elements exceeds the {CAP}-element allocation cap; \
                 returning the first {CAP} only"
            ),
        );
        return (lo..=hi).take(CAP).collect();
    }
    (lo..=hi).collect()
}
pub fn list_indexed_map<T0, T1>(f: impl Fn(i64, T0) -> T1, list: Vec<T0>) -> Vec<T1> {
    list.into_iter()
        .enumerate()
        .map(|(i, x)| f(i as i64, x))
        .collect()
}
pub fn list_concat_map<T0, T1>(f: impl Fn(T0) -> Vec<T1>, list: Vec<T0>) -> Vec<T1> {
    list.into_iter().flat_map(f).collect()
}
#[must_use]
pub fn list_zip<T0, T1>(a: Vec<T0>, b: Vec<T1>) -> Vec<(T0, T1)> {
    a.into_iter().zip(b).collect()
}
// `T0: Clone` here is a genuine ELEMENT-clone bound (`x.clone()` below feeds
// the predicate while the original `x` flows into the kept output) — NOT a
// closure-Clone bound (see the note above `list_foldl`). Keep it.
pub fn list_filter<T0: Clone>(f: impl Fn(T0) -> bool, list: Vec<T0>) -> Vec<T0> {
    list.into_iter().filter(|x| f(x.clone())).collect()
}
pub fn list_member<T0: PartialEq>(x: T0, list: Vec<T0>) -> bool {
    list.contains(&x)
}
pub fn list_any<T0>(f: impl Fn(T0) -> bool, list: Vec<T0>) -> bool {
    list.into_iter().any(f)
}
pub fn list_all<T0>(f: impl Fn(T0) -> bool, list: Vec<T0>) -> bool {
    list.into_iter().all(f)
}

/// `Ipe.List.find : (a -> Bool) -> List a -> Maybe a` — the first element
/// satisfying the predicate, or `Nothing`. The predicate is by-value
/// `Fn(T0) -> bool` (the shape codegen emits — same as `list_filter`), so the
/// element is cloned before testing and the original returned on a hit.
/// Iterative (short-circuits); total. `T0: Clone` is the same element-clone
/// bound as `list_filter`; the predicate itself carries no `Clone` bound
/// (see the note above `list_foldl`).
pub fn list_find<T0: Clone>(f: impl Fn(T0) -> bool, list: Vec<T0>) -> IpeMaybe<T0> {
    for x in list {
        if f(x.clone()) {
            return IpeMaybe::Just(x);
        }
    }
    IpeMaybe::Nothing
}

// ── Sorting (implements List_sort / List_sortBy; sortWith added for Rust) ──
//
// All three are STABLE (Rust's `Vec::sort_by` / `sort_by_key` are stable, matching
//  `sort.SliceStable`). None can panic on well-typed input: ordering is total
// (`total_cmp` via `cmp_total`), so a NaN key never trips the `Ord` contract the
// way a naive `partial_cmp().unwrap()` would.

/// Best-effort total ordering for any `PartialOrd` element. `partial_cmp` returns
/// `None` only for incomparable values (floating-point NaN); we map that to
/// `Equal`. NOTE: with MORE THAN ONE NaN present this is NOT transitive (NaN≈1.0
/// and NaN≈2.0 yet 1.0<2.0), and since Rust 1.81 `slice::sort_by` PANICS on a
/// comparator that violates a strict weak ordering. NaN IS reachable at runtime
/// (`0.0 / 0.0`, `sqrt(-1)`, an FFI float) even though no Ipê literal spells it —
/// so the callers below wrap the sort in `catch_unwind` to stay total.
fn cmp_total<T: PartialOrd>(a: &T, b: &T) -> std::cmp::Ordering {
    a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal)
}

/// Run `sort_by` but never panic: a non-strict-weak-ordering comparator (e.g.
/// `cmp_total` over a multi-NaN float list) panics std's sort since Rust 1.81;
/// catch it and leave the slice in its safe, element-complete (unspecified-order)
/// state. Shared by `list_sort`/`list_sort_by` (and mirrors `list_sort_with`).
fn sort_by_total<T, F: Fn(&T, &T) -> std::cmp::Ordering>(result: &mut [T], cmp: F) {
    let order = std::panic::AssertUnwindSafe(|| result.sort_by(&cmp));
    if std::panic::catch_unwind(order).is_err() {
        crate::system::emit_runtime_log(
            "list",
            "sort: comparator is not a consistent total order (NaN?); unspecified order",
        );
    }
}

/// `Ipe.List.sort : List comparable -> List comparable` — stable ascending
/// sort by the element's natural order. Total (no panic on NaN).
pub fn list_sort<T: PartialOrd>(list: Vec<T>) -> Vec<T> {
    let mut result = list;
    sort_by_total(&mut result, cmp_total);
    result
}

/// `Ipe.List.sortBy : (a -> comparable) -> List a -> List a` — stable sort by
/// the `keyFn elem` projection. Decorate-sort-undecorate: `keyFn` is applied
/// exactly once per element (no repeated key recomputation during comparison).
/// `A: Clone` because the Ipê closure ABI takes its element by value — same bound
/// `list_filter` already carries for its predicate.
pub fn list_sort_by<A: Clone, B: PartialOrd>(key_fn: impl Fn(A) -> B, list: Vec<A>) -> Vec<A> {
    // Decorate: compute each key once, pairing it with its element. The key fn
    // consumes its argument (owned ABI), so clone the element for the key call
    // and keep the original to emit after the sort.
    let mut decorated: Vec<(B, A)> = list.into_iter().map(|x| (key_fn(x.clone()), x)).collect();
    // Stable sort on the key only (so equal keys preserve input order). Via the
    // panic-safe wrapper: a multi-NaN key set makes cmp_total non-transitive.
    sort_by_total(&mut decorated, |a, b| cmp_total(&a.0, &b.0));
    // Undecorate.
    decorated.into_iter().map(|(_, x)| x).collect()
}

/// `Ipe.List.sortWith : (a -> a -> Int) -> List a -> List a` — stable sort by
/// a user comparator returning a Ipê `Int` (negative → first arg orders before the
/// second, zero → equal, positive → after; matching `Basics.compare`'s -1/0/+1).
/// The comparator takes its two elements by value (the Ipê closure ABI), so `a`
/// must be `Clone`. The `Int` → `Ordering` map is total — every `i64` lands in
/// exactly one of Less / Equal / Greater.
pub fn list_sort_with<A: Clone>(cmp: impl Fn(A, A) -> i64, list: Vec<A>) -> Vec<A> {
    let mut result = list;
    // Soundness (no-panic thesis): the comparator is arbitrary user Ipê code.
    // Since Rust 1.81 the standard sort PANICS when a comparator violates a
    // strict weak ordering (e.g. `cmp a b` and `cmp b a` both return a positive
    // Int). A well-typed Ipê `List.sortWith` could supply exactly that, so the
    // bare `sort_by` is a Ipê-reachable panic. Catch the unwind and return the
    // list in its (safe, unspecified-order) post-sort state — std guarantees the
    // elements are all still present and no UB on a panicking comparator.
    let order = &mut result;
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        order.sort_by(|a, b| cmp(a.clone(), b.clone()).cmp(&0));
    }));
    if outcome.is_err() {
        crate::system::emit_runtime_log(
            "list",
            "List.sortWith: comparator is not a consistent total order; returning input in unspecified order",
        );
    }
    result
}

/// Split an owned list into a view of its first `W` slots and the remaining tail.
///
/// Slot `i` is `Some` of the `i`-th element while the list has one, then `None`
/// past the end; the tail holds every element after the first `W`. This is the
/// owned destructure a list `case` over a non-`Clone` element matches against:
/// every element moves into the view, none is cloned. Total.
#[must_use]
pub fn ipe_list_view_owned<T, const W: usize>(xs: Vec<T>) -> ([Option<T>; W], Vec<T>) {
    let mut it = xs.into_iter();
    let head = core::array::from_fn(|_| it.next());
    (head, it.collect())
}

/// Rebuild the list a run of view slots plus the view's tail stands for.
///
/// The slots are a suffix of a view built by [`ipe_list_view_owned`], so every
/// `None` sits after every `Some` and the elements keep their list order. Moves;
/// never clones. Total.
#[must_use]
pub fn ipe_list_view_rest<T, const N: usize>(spill: [Option<T>; N], tail: Vec<T>) -> Vec<T> {
    spill.into_iter().flatten().chain(tail).collect()
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;

    /// A non-`Clone` element: a stray clone in either view helper cannot compile.
    type Once = Box<dyn FnOnce() -> i64>;

    fn once_list(n: i64) -> Vec<Once> {
        (0..n).map(|i| Box::new(move || i) as Once).collect()
    }

    fn run_all(xs: Vec<Once>) -> Vec<i64> {
        xs.into_iter().map(|f| f()).collect()
    }

    fn run_slots<const W: usize>(slots: [Option<Once>; W]) -> Vec<Option<i64>> {
        slots.into_iter().map(|s| s.map(|f| f())).collect()
    }

    #[test]
    fn list_view_owned_splits_every_length_around_the_width() {
        // Width 3: lengths 0, W-1, W and W+1.
        let (slots, tail) = ipe_list_view_owned::<_, 3>(once_list(0));
        assert_eq!(run_slots(slots), vec![None, None, None]);
        assert!(tail.is_empty());

        let (slots, tail) = ipe_list_view_owned::<_, 3>(once_list(2));
        assert_eq!(run_slots(slots), vec![Some(0), Some(1), None]);
        assert!(tail.is_empty());

        let (slots, tail) = ipe_list_view_owned::<_, 3>(once_list(3));
        assert_eq!(run_slots(slots), vec![Some(0), Some(1), Some(2)]);
        assert!(tail.is_empty());

        let (slots, tail) = ipe_list_view_owned::<_, 3>(once_list(4));
        assert_eq!(run_slots(slots), vec![Some(0), Some(1), Some(2)]);
        assert_eq!(run_all(tail), vec![3]);
    }

    #[test]
    fn list_view_rest_round_trips_the_view() {
        for n in 0..6 {
            let (slots, tail) = ipe_list_view_owned::<_, 3>(once_list(n));
            assert_eq!(
                run_all(ipe_list_view_rest(slots, tail)),
                (0..n).collect::<Vec<_>>()
            );
        }
        // A suffix of the slots rebuilds the rest after the matched prefix.
        let ([first, s1, s2], tail) = ipe_list_view_owned::<_, 3>(once_list(5));
        assert_eq!(first.map(|f| f()), Some(0));
        assert_eq!(run_all(ipe_list_view_rest([s1, s2], tail)), vec![1, 2, 3, 4]);
    }

    // Every HOF kernel in this file must accept the EXACT shape
    // `ipe_backend_rust::emit_expr::emit_lambda` emits for every Ipê closure
    // VALUE — a boxed, non-`Clone` trait object `Box<dyn Fn(..) -> .. + Send>`
    // — directly, with no `.clone()` at the call site. A
    // `f: impl Fn(T0) -> bool + Clone` (etc.) bound would reject this exact
    // shape at compile time (E0277: `Box<dyn Fn(..) + Send>: Clone` is not
    // satisfied) for EVERY closure, not just ones that capture another closure
    // (a partial application). Building the trait object here the same way
    // codegen does — and never calling `.clone()` on it — pins the invariant:
    // no `Clone` bound, AND nothing downstream secretly needs the value to be
    // `Clone`.
    #[test]
    fn hof_kernels_accept_boxed_non_clone_closure() {
        // A predicate that is itself a partial application over a captured
        // value — the "closure capturing a value, boxed" shape
        // (`List.filter (isVisible session) items`).
        let threshold: i64 = 3;
        let above: Box<dyn Fn(i64) -> bool + Send> = Box::new(move |x| x > threshold);
        assert_eq!(list_filter(above, vec![1, 2, 3, 4, 5]), vec![4, 5]);

        let above: Box<dyn Fn(i64) -> bool + Send> = Box::new(move |x| x > threshold);
        assert!(list_any(above, vec![1, 2, 3, 4, 5]));

        let above: Box<dyn Fn(i64) -> bool + Send> = Box::new(move |x| x > threshold);
        assert!(!list_all(above, vec![1, 2, 3, 4, 5]));

        let above: Box<dyn Fn(i64) -> bool + Send> = Box::new(move |x| x > threshold);
        assert_eq!(list_find(above, vec![1, 2, 3, 4, 5]), IpeMaybe::Just(4));

        let max_fn: Box<dyn Fn(i64, i64) -> i64 + Send> =
            Box::new(|v, acc| if v > acc { v } else { acc });
        assert_eq!(list_foldl(max_fn, i64::MIN, vec![1, 5, 3]), 5);

        let max_fn: Box<dyn Fn(i64, i64) -> i64 + Send> =
            Box::new(|v, acc| if v > acc { v } else { acc });
        assert_eq!(list_foldr(max_fn, i64::MIN, vec![1, 5, 3]), 5);

        let plus_i: Box<dyn Fn(i64, i64) -> i64 + Send> = Box::new(|i, x| i + x);
        assert_eq!(list_indexed_map(plus_i, vec![10, 20, 30]), vec![10, 21, 32]);

        let dupe: Box<dyn Fn(i64) -> Vec<i64> + Send> = Box::new(|x| vec![x, x]);
        assert_eq!(list_concat_map(dupe, vec![1, 2]), vec![1, 1, 2, 2]);
    }

    // SOUNDNESS regression (no-panic thesis): a comparator that is NOT a strict
    // weak ordering makes std's sort panic since Rust 1.81. A well-typed Ipê
    // `List.sortWith` can supply one, so the kernel must NOT panic — it returns
    // the elements in unspecified (but safe, complete) order instead.
    // SOUNDNESS regression: a multi-NaN float list makes cmp_total non-transitive,
    // which panics std sort since Rust 1.81. list_sort / list_sort_by must stay total.
    #[test]
    fn sort_multi_nan_does_not_panic() {
        let nan = f64::NAN;
        let xs: Vec<f64> = vec![3.0, nan, 1.0, nan, 2.0, nan, 0.5];
        let out = list_sort(xs.clone());
        assert_eq!(out.len(), xs.len(), "no elements lost");
        let keyed = list_sort_by(|x: f64| x, xs.clone());
        assert_eq!(keyed.len(), xs.len());
    }

    #[test]
    fn sort_with_inconsistent_comparator_does_not_panic() {
        let xs: Vec<i64> = (0..64).collect();
        // Always-greater: cmp a b = 1 AND cmp b a = 1 — violates antisymmetry.
        let out = list_sort_with(|_a, _b| 1, xs.clone());
        // No panic; every element preserved (multiset equal).
        let mut got = out.clone();
        got.sort_unstable();
        assert_eq!(got, (0..64).collect::<Vec<i64>>());
    }

    // non-HOF List kernels: Elm edge-semantics + no-panic.
    #[test]
    fn append_concat_are_total_and_ordered() {
        assert_eq!(list_append(vec![1, 2], vec![3, 4]), vec![1, 2, 3, 4]);
        assert_eq!(list_append(Vec::<i64>::new(), vec![1]), vec![1]);
        assert_eq!(list_append(vec![1], Vec::<i64>::new()), vec![1]);
        assert_eq!(
            list_concat(vec![vec![1, 2], vec![], vec![3]]),
            vec![1, 2, 3]
        );
        assert_eq!(list_concat(Vec::<Vec<i64>>::new()), Vec::<i64>::new());
    }

    #[test]
    fn take_clamps_negative_and_overlength() {
        assert_eq!(list_take(2, vec![9, 8, 7]), vec![9, 8]);
        assert_eq!(list_take(5, vec![9, 8]), vec![9, 8]); // n > len → whole
        assert_eq!(list_take(0, vec![9, 8]), Vec::<i64>::new());
        assert_eq!(list_take(-3, vec![9, 8]), Vec::<i64>::new()); // n < 0 → []
    }

    #[test]
    fn is_empty_and_cons_and_zip_edges() {
        assert!(list_is_empty(Vec::<i64>::new()));
        assert!(!list_is_empty(vec![1]));
        assert_eq!(ipe_list_cons(0, vec![1, 2]), vec![0, 1, 2]);
        // zip truncates to the shorter operand (Elm/).
        assert_eq!(list_zip(vec![1, 2, 3], vec![4, 5]), vec![(1, 4), (2, 5)]);
    }

    #[test]
    fn test_filter_map_doubles_evens() {
        let xs: Vec<i64> = vec![1, 2, 3, 4];
        let result = list_filter_map(
            |x| {
                if x % 2 == 0 {
                    IpeMaybe::Just(x * 2)
                } else {
                    IpeMaybe::Nothing
                }
            },
            xs,
        );
        assert_eq!(result, vec![4i64, 8]);
    }

    #[test]
    fn test_filter_map_all_nothing() {
        let xs: Vec<i64> = vec![1, 2, 3];
        let result = list_filter_map(|_: i64| IpeMaybe::<i64>::Nothing, xs);
        assert!(result.is_empty());
    }

    #[test]
    fn test_filter_map_all_just() {
        let xs: Vec<i64> = vec![1, 2, 3];
        let result = list_filter_map(|x| IpeMaybe::Just(x + 10), xs);
        assert_eq!(result, vec![11i64, 12, 13]);
    }

    #[test]
    fn test_filter_map_empty() {
        let xs: Vec<i64> = vec![];
        let result = list_filter_map(IpeMaybe::Just, xs);
        assert!(result.is_empty());
    }

    #[test]
    fn test_sort_ints() {
        assert_eq!(list_sort(vec![3i64, 1, 2]), vec![1i64, 2, 3]);
        assert_eq!(list_sort(Vec::<i64>::new()), Vec::<i64>::new());
    }

    #[test]
    fn test_sort_strings() {
        assert_eq!(
            list_sort(vec!["banana".to_string(), "apple".into(), "cherry".into()]),
            vec!["apple".to_string(), "banana".into(), "cherry".into()]
        );
    }

    #[test]
    fn test_sort_floats_with_nan_no_panic() {
        // NaN must not panic the comparator (total order falls back to Equal).
        let r = list_sort(vec![3.0f64, f64::NAN, 1.0]);
        assert_eq!(r.len(), 3);
    }

    #[test]
    fn test_sort_by_key_applied_once_and_stable() {
        // sortBy String.length — stable: equal-length keep input order.
        let r = list_sort_by(
            |s: String| s.len() as i64,
            vec!["ccc".to_string(), "a".into(), "bb".into(), "dd".into()],
        );
        assert_eq!(
            r,
            vec!["a".to_string(), "bb".into(), "dd".into(), "ccc".into()]
        );
    }

    #[test]
    fn test_sort_with_reverse() {
        // Comparator b - a → descending.
        let r = list_sort_with(|a: i64, b: i64| b - a, vec![1i64, 3, 2]);
        assert_eq!(r, vec![3i64, 2, 1]);
    }

    #[test]
    fn test_sort_with_stable_on_equal() {
        // All-equal comparator preserves input order (stable).
        let r = list_sort_with(|_a: i64, _b: i64| 0, vec![3i64, 1, 2]);
        assert_eq!(r, vec![3i64, 1, 2]);
    }

    // ── New List fills — Elm-matching semantics ───────────────────────────

    #[test]
    fn singleton_and_repeat_match_elm() {
        assert_eq!(list_singleton(7i64), vec![7i64]);
        assert_eq!(list_repeat(3, 0i64), vec![0i64, 0, 0]);
        assert_eq!(list_repeat(0, 9i64), Vec::<i64>::new());
        assert_eq!(list_repeat(-2, 9i64), Vec::<i64>::new()); // Elm: n<=0 → []
    }

    #[test]
    // 1.5 + 2.5 = 4.0 exactly in IEEE 754.
    #[allow(clippy::float_cmp)]
    fn sum_product_match_elm() {
        assert_eq!(list_sum(vec![1i64, 2, 3, 4]), 10);
        assert_eq!(list_sum(Vec::<i64>::new()), 0); // Elm: sum [] == 0
        assert_eq!(list_product(vec![2i64, 3, 4]), 24);
        assert_eq!(list_product(Vec::<i64>::new()), 1); // Elm: product [] == 1
        assert_eq!(list_sum(vec![1.5f64, 2.5]), 4.0);
    }

    /// The additive/multiplicative fold wraps two's-complement, exactly like a
    /// repeated inline `(+)`/`(*)`, and never overflow-aborts — the fold routes
    /// through `ipe_wrapping_add`/`ipe_wrapping_mul`, so this holds under any
    /// Cargo profile's `overflow-checks` setting (the assertion could not even
    /// reach a value past `i64::MAX` if the fold panicked instead).
    #[test]
    fn sum_product_wrap_past_int_max_no_panic() {
        // sum [i64::MAX, 1] == i64::MAX.wrapping_add(1) == i64::MIN.
        assert_eq!(list_sum(vec![i64::MAX, 1]), i64::MIN);
        // Matches repeated inline `(+)`: MAX + 1 wraps to MIN.
        assert_eq!(list_sum(vec![i64::MAX, 1]), i64::MAX.wrapping_add(1));
        // sum [i64::MIN, -1] wraps forward to i64::MAX.
        assert_eq!(list_sum(vec![i64::MIN, -1]), i64::MAX);
        // product [i64::MAX, 2] == i64::MAX.wrapping_mul(2) == -2.
        assert_eq!(list_product(vec![i64::MAX, 2]), i64::MAX.wrapping_mul(2));
        assert_eq!(list_product(vec![i64::MAX, 2]), -2);
    }

    #[test]
    fn maximum_minimum_match_elm() {
        assert_eq!(list_maximum(vec![3i64, 1, 4, 1, 5]), IpeMaybe::Just(5));
        assert_eq!(list_minimum(vec![3i64, 1, 4, 1, 5]), IpeMaybe::Just(1));
        // Elm: maximum [] == Nothing.
        assert_eq!(list_maximum(Vec::<i64>::new()), IpeMaybe::Nothing);
        assert_eq!(list_minimum(Vec::<i64>::new()), IpeMaybe::Nothing);
    }

    #[test]
    fn unique_keeps_first_occurrence_order() {
        // Duplicates dropped; the FIRST occurrence's position is preserved.
        assert_eq!(list_unique(vec![1i64, 1, 2, 3, 2, 1]), vec![1i64, 2, 3]);
        // Already-unique input is returned unchanged (order preserved).
        assert_eq!(list_unique(vec![3i64, 1, 2]), vec![3i64, 1, 2]);
        // Empty and singleton edges.
        assert_eq!(list_unique(Vec::<i64>::new()), Vec::<i64>::new());
        assert_eq!(list_unique(vec![7i64]), vec![7i64]);
        // Equality-only bound: works for a non-Ord/non-Hash equatable type too.
        assert_eq!(
            list_unique(vec![
                "a".to_string(),
                "b".into(),
                "a".into(),
                "c".into(),
                "b".into()
            ]),
            vec!["a".to_string(), "b".into(), "c".into()]
        );
    }

    #[test]
    fn intersperse_matches_elm() {
        assert_eq!(
            list_intersperse(0i64, vec![1i64, 2, 3]),
            vec![1i64, 0, 2, 0, 3]
        );
        assert_eq!(list_intersperse(0i64, vec![1i64]), vec![1i64]);
        assert_eq!(list_intersperse(0i64, Vec::<i64>::new()), Vec::<i64>::new());
    }

    #[test]
    fn partition_matches_elm() {
        // Elm: partition (\x -> x > 2) [1,2,3,4] == ([3,4], [1,2]).
        let (yes, no) = list_partition(|x: i64| x > 2, vec![1i64, 2, 3, 4]);
        assert_eq!(yes, vec![3i64, 4]);
        assert_eq!(no, vec![1i64, 2]);
    }

    #[test]
    fn unzip_matches_elm() {
        // Elm: unzip [(0,True),(17,False),(1337,True)] == ([0,17,1337],[True,False,True]).
        let (a, b) = list_unzip(vec![(0i64, true), (17, false), (1337, true)]);
        assert_eq!(a, vec![0i64, 17, 1337]);
        assert_eq!(b, vec![true, false, true]);
    }

    #[test]
    fn sort_with_order_matches_elm() {
        // Descending via a flipped Order comparator.
        let desc = |a: i64, b: i64| match a.cmp(&b) {
            std::cmp::Ordering::Greater => IpeOrder::LT,
            std::cmp::Ordering::Less => IpeOrder::GT,
            std::cmp::Ordering::Equal => IpeOrder::EQ,
        };
        assert_eq!(
            list_sort_with_order(desc, vec![1i64, 3, 2]),
            vec![3i64, 2, 1]
        );
    }

    #[test]
    fn sort_with_order_inconsistent_does_not_panic() {
        let xs: Vec<i64> = (0..64).collect();
        // Always-LT comparator violates antisymmetry — must not panic.
        let out = list_sort_with_order(|_a, _b| IpeOrder::LT, xs);
        assert_eq!(out.len(), 64);
    }

    #[test]
    fn map2_through_map5_match_elm() {
        // map2 (+) [1,2,3] [10,20] → [11,22] (truncates to shorter).
        assert_eq!(
            list_map2(|a, b| a + b, vec![1i64, 2, 3], vec![10i64, 20]),
            vec![11i64, 22]
        );
        // map3 sum.
        assert_eq!(
            list_map3(
                |a, b, c| a + b + c,
                vec![1i64, 2],
                vec![10i64, 20],
                vec![100i64, 200]
            ),
            vec![111i64, 222]
        );
        // map4 sum.
        assert_eq!(
            list_map4(
                |a, b, c, d| a + b + c + d,
                vec![1i64],
                vec![10i64],
                vec![100i64],
                vec![1000i64]
            ),
            vec![1111i64]
        );
        // map5 sum, truncating to the shortest (length 1).
        assert_eq!(
            list_map5(
                |a, b, c, d, e| a + b + c + d + e,
                vec![1i64, 9],
                vec![10i64],
                vec![100i64, 9],
                vec![1000i64, 9],
                vec![10000i64, 9]
            ),
            vec![11111i64]
        );
    }
}
