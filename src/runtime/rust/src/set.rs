//! `Ipe.Set` kernels backed by `std::collections::BTreeSet<A>`.
//!
//! Ipê's `Set` is keyed on `comparable` values (Int, String, …), all of which
//! are `Ord` in Rust — so `BTreeSet<A>` is the natural backing.  runtime
//! Set is a `map[string]any` (unordered iteration), so Ipê guarantees no
//! particular Set order; `BTreeSet`'s sorted iteration is a CONFORMING and
//! strictly MORE deterministic choice (same rationale as `Dict.keys` returning
//! sorted keys on the Rust backend). Every op consumes its set(s) by value and
//! returns the modified copy (functional update) — no `Clone` bound is needed
//! on the element type for any kernel; a Ipê-level reuse of a Set value is
//! `.clone()`d at the use site by codegen, exactly like `HashMap`/`Vec`.
//!
//! Codegen: `TypeRenderer` renders `Set a` as `BTreeSet<a>`; the empty-set
//! turbofish (`EKSet`) pins `A` from the expected type, mirroring `dict_empty`.

use std::collections::BTreeSet;

/// `Set.empty : Set a`.
#[must_use]
pub fn set_empty<A>() -> BTreeSet<A> {
    BTreeSet::new()
}

/// `Set.fromList : List a -> Set a`. Duplicates collapse.
#[must_use]
pub fn set_from_list<A: Ord>(xs: Vec<A>) -> BTreeSet<A> {
    xs.into_iter().collect()
}

/// `Set.insert : a -> Set a -> Set a`. Functional update.
pub fn set_insert<A: Ord>(v: A, s: BTreeSet<A>) -> BTreeSet<A> {
    let mut s = s;
    s.insert(v);
    s
}

/// `Set.remove : a -> Set a -> Set a`. Absent element → unchanged.
pub fn set_remove<A: Ord>(v: A, s: BTreeSet<A>) -> BTreeSet<A> {
    let mut s = s;
    s.remove(&v);
    s
}

/// `Set.member : a -> Set a -> Bool`.
pub fn set_member<A: Ord>(v: A, s: BTreeSet<A>) -> bool {
    s.contains(&v)
}

/// `Set.toList : Set a -> List a`. Sorted (`BTreeSet` iterates in order).
#[must_use]
pub fn set_to_list<A>(s: BTreeSet<A>) -> Vec<A> {
    s.into_iter().collect()
}

/// `Set.size : Set a -> Int`.
#[must_use]
pub fn set_size<A>(s: BTreeSet<A>) -> i64 {
    s.len() as i64
}

/// `Set.union : Set a -> Set a -> Set a`. Every element of either set.
#[must_use]
pub fn set_union<A: Ord>(a: BTreeSet<A>, b: BTreeSet<A>) -> BTreeSet<A> {
    let mut a = a;
    a.extend(b);
    a
}

/// `Set.intersect : Set a -> Set a -> Set a`. Elements in BOTH sets.
#[must_use]
pub fn set_intersect<A: Ord>(a: BTreeSet<A>, b: BTreeSet<A>) -> BTreeSet<A> {
    a.into_iter().filter(|x| b.contains(x)).collect()
}

/// `Set.diff : Set a -> Set a -> Set a`. Elements in `a` but NOT in `b`.
#[must_use]
pub fn set_diff<A: Ord>(a: BTreeSet<A>, b: BTreeSet<A>) -> BTreeSet<A> {
    a.into_iter().filter(|x| !b.contains(x)).collect()
}

/// `Set.isEmpty : Set a -> Bool`.
#[must_use]
pub fn set_is_empty<A>(s: BTreeSet<A>) -> bool {
    s.is_empty()
}

/// `Set.singleton : a -> Set a` — the one-element set `{x}`.
pub fn set_singleton<A: Ord>(x: A) -> BTreeSet<A> {
    let mut s = BTreeSet::new();
    s.insert(x);
    s
}

/// `Set.foldl : (a -> b -> b) -> b -> Set a -> b` — fold in ascending element
/// order (`BTreeSet` iterates sorted). The callback takes the element then the
/// accumulator, matching Elm's `Set.foldl`.
pub fn set_foldl<A, B>(f: impl Fn(A, B) -> B, init: B, s: BTreeSet<A>) -> B {
    let mut acc = init;
    for x in s {
        acc = f(x, acc);
    }
    acc
}

/// `Set.foldr : (a -> b -> b) -> b -> Set a -> b` — fold in descending element
/// order. Matches Elm's `Set.foldr`.
pub fn set_foldr<A, B>(f: impl Fn(A, B) -> B, init: B, s: BTreeSet<A>) -> B {
    let mut acc = init;
    for x in s.into_iter().rev() {
        acc = f(x, acc);
    }
    acc
}

/// `Set.map : (a -> b) -> Set a -> Set b` — apply `f` to every element,
/// collapsing duplicate results. `B: Ord` because the result backs a
/// `BTreeSet<B>`.
pub fn set_map<A, B: Ord>(f: impl Fn(A) -> B, s: BTreeSet<A>) -> BTreeSet<B> {
    s.into_iter().map(f).collect()
}

/// `Set.filter : (a -> Bool) -> Set a -> Set a` — keep only satisfying elements.
/// The predicate takes its element by value (the Ipê closure ABI), so `A` is
/// `Ord + Clone` — cloned for the test, original kept for the output.
pub fn set_filter<A: Ord + Clone>(pred: impl Fn(A) -> bool, s: BTreeSet<A>) -> BTreeSet<A> {
    s.into_iter().filter(|x| pred(x.clone())).collect()
}

/// `Set.partition : (a -> Bool) -> Set a -> (Set a, Set a)` — split into
/// (satisfying, not-satisfying). By-value predicate ABI, so `A: Ord + Clone`.
pub fn set_partition<A: Ord + Clone>(
    pred: impl Fn(A) -> bool,
    s: BTreeSet<A>,
) -> (BTreeSet<A>, BTreeSet<A>) {
    s.into_iter().partition(|x| pred(x.clone()))
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;

    #[test]
    fn from_list_dedups_and_sorts() {
        let s = set_from_list(vec![3, 1, 2, 1, 3]);
        assert_eq!(set_to_list(s), vec![1, 2, 3]);
    }

    #[test]
    fn insert_remove_member_size() {
        let s = set_insert(2, set_insert(1, set_empty::<i64>()));
        assert!(set_member(1, s.clone()));
        assert!(!set_member(9, s.clone()));
        assert_eq!(set_size(s.clone()), 2);
        let s = set_remove(1, s);
        assert_eq!(set_to_list(s), vec![2]);
    }

    #[test]
    fn union_intersect_diff() {
        let a = set_from_list(vec![1, 2, 3]);
        let b = set_from_list(vec![2, 3, 4]);
        assert_eq!(
            set_to_list(set_union(a.clone(), b.clone())),
            vec![1, 2, 3, 4]
        );
        assert_eq!(set_to_list(set_intersect(a.clone(), b.clone())), vec![2, 3]);
        assert_eq!(set_to_list(set_diff(a, b)), vec![1]);
    }

    #[test]
    fn is_empty_and_singleton_match_elm() {
        assert!(set_is_empty(set_empty::<i64>()));
        assert!(!set_is_empty(set_singleton(1i64)));
        assert_eq!(set_to_list(set_singleton(9i64)), vec![9]);
    }

    #[test]
    fn fold_map_filter_partition_match_elm() {
        let s = set_from_list(vec![1i64, 2, 3, 4]);
        // foldl/foldr sum the same total; order differs but sum is invariant.
        assert_eq!(set_foldl(|x, a| x + a, 0i64, s.clone()), 10);
        assert_eq!(set_foldr(|x, a| x + a, 0i64, s.clone()), 10);
        // map doubling; duplicates would collapse (none here).
        assert_eq!(
            set_to_list(set_map(|x| x * 2, s.clone())),
            vec![2i64, 4, 6, 8]
        );
        // filter evens.
        assert_eq!(
            set_to_list(set_filter(|x: i64| x % 2 == 0, s.clone())),
            vec![2i64, 4]
        );
        // partition (> 2) → ({3,4}, {1,2}).
        let (yes, no) = set_partition(|x: i64| x > 2, s);
        assert_eq!(set_to_list(yes), vec![3i64, 4]);
        assert_eq!(set_to_list(no), vec![1i64, 2]);
    }

    #[test]
    fn map_collapses_duplicates() {
        // map (always 0) over {1,2,3} → {0}.
        let s = set_from_list(vec![1i64, 2, 3]);
        assert_eq!(set_to_list(set_map(|_x| 0i64, s)), vec![0i64]);
    }
}
