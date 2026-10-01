//! Ipe.Dict kernels backed by `std::collections::HashMap<K, V>`.
//!
//! Generic over the KEY type so a `Dict Int v` (chess board keyed by square
//! index, histogram counts, …) maps to `HashMap<i64, V>` and a `Dict String v`
//! to `HashMap<String, V>`. Keys are `Ord` for the deterministic sorted
//! iteration Ipê guarantees; `Hash + Eq` for the map ops. Codegen emits the
//! key type from the `Dict k v` annotation (`TypeRenderer` renders `HashMap<k,v>`;
//! empty-dict turbofish pins both K and V from the expected type). The
//! `IpeDict<T>` alias stays for the String-keyed runtime structs (db rows).

use super::IpeMaybe;
use std::collections::HashMap;
use std::hash::Hash;

pub type IpeDict<T> = HashMap<String, T>;

/// `Dict.empty : Dict k v`.
#[must_use]
pub fn dict_empty<K, V>() -> HashMap<K, V> {
    HashMap::new()
}

/// `Dict.insert : k -> v -> Dict k v -> Dict k v`.
/// Functional update — the input dict is consumed and the modified copy returned.
pub fn dict_insert<K: Hash + Eq, V>(k: K, v: V, d: HashMap<K, V>) -> HashMap<K, V> {
    let mut d = d;
    d.insert(k, v);
    d
}

/// `Dict.get : k -> Dict k v -> Maybe v`.
pub fn dict_get<K: Hash + Eq, V: Clone>(k: K, d: HashMap<K, V>) -> IpeMaybe<V> {
    match d.get(&k) {
        Some(v) => IpeMaybe::Just(v.clone()),
        None => IpeMaybe::Nothing,
    }
}

/// `Dict.keys : Dict k v -> List k`. Returns keys in sorted order so
/// iteration is deterministic (matches Ipê's _fieldIndex emission contract).
#[must_use]
pub fn dict_keys<K: Ord, V>(d: HashMap<K, V>) -> Vec<K> {
    let mut keys: Vec<K> = d.into_keys().collect();
    keys.sort();
    keys
}

/// `Dict.values : Dict k v -> List v`. Key-sorted for determinism, matching
/// `dict_keys` (Ipê Dicts iterate in sorted-key order).
#[must_use]
pub fn dict_values<K: Ord, V: Clone>(d: HashMap<K, V>) -> Vec<V> {
    let mut pairs: Vec<(K, V)> = d.into_iter().collect();
    pairs.sort_by(|a, b| a.0.cmp(&b.0));
    pairs.into_iter().map(|(_, v)| v).collect()
}

/// `Dict.toList : Dict k v -> List (k, v)`. Key-sorted for determinism,
/// matching `dict_keys` / `dict_values` (Ipê Dicts iterate in sorted-key order).
#[must_use]
pub fn dict_to_list<K: Ord, V: Clone>(d: HashMap<K, V>) -> Vec<(K, V)> {
    let mut pairs: Vec<(K, V)> = d.into_iter().collect();
    pairs.sort_by(|a, b| a.0.cmp(&b.0));
    pairs
}

/// `Dict.remove : k -> Dict k v -> Dict k v`.
pub fn dict_remove<K: Hash + Eq, V>(k: K, d: HashMap<K, V>) -> HashMap<K, V> {
    let mut d = d;
    d.remove(&k);
    d
}

/// `Dict.member : k -> Dict k v -> Bool`.
pub fn dict_member<K: Hash + Eq, V>(k: K, d: HashMap<K, V>) -> bool {
    d.contains_key(&k)
}

/// `Dict.fromList : List (k, v) -> Dict k v`.
#[must_use]
pub fn dict_from_list<K: Hash + Eq, V>(pairs: Vec<(K, V)>) -> HashMap<K, V> {
    pairs.into_iter().collect()
}

/// `Dict.size : Dict k v -> Int`. Returns the number of key/value pairs.
#[must_use]
pub fn dict_size<K, V>(d: HashMap<K, V>) -> i64 {
    d.len() as i64
}

/// `Dict.isEmpty : Dict k v -> Bool`.
#[must_use]
pub fn dict_is_empty<K, V>(d: HashMap<K, V>) -> bool {
    d.is_empty()
}

/// `Dict.union : Dict k v -> Dict k v -> Dict k v`.
/// Left-biased: `a`'s bindings win on collision (matches  `Dict_union` —
/// `mb` is inserted first then `ma` overwrites, so `ma` wins).
#[must_use]
pub fn dict_union<K: Hash + Eq + Clone, V: Clone>(
    a: HashMap<K, V>,
    b: HashMap<K, V>,
) -> HashMap<K, V> {
    let mut result = b; // b's entries as the base
    for (k, v) in a {
        result.insert(k, v); // a's entries overwrite → left-biased
    }
    result
}

/// `Dict.map : (k -> v -> w) -> Dict k v -> Dict k w`.
/// Applies `f k v` to every entry; returns a new dict with the transformed
/// values. Iteration order is sorted by key for determinism (matches `dict_keys`
/// / `dict_values` / `dict_foldl`).
pub fn dict_map<K: Ord + Hash + Eq + Clone, V: Clone, W, F>(f: F, d: HashMap<K, V>) -> HashMap<K, W>
where
    F: Fn(K, V) -> W,
{
    // Sort for determinism, then apply.
    let mut pairs: Vec<(K, V)> = d.into_iter().collect();
    pairs.sort_by(|a, b| a.0.cmp(&b.0));
    pairs
        .into_iter()
        .map(|(k, v)| {
            let w = f(k.clone(), v);
            (k, w)
        })
        .collect()
}

/// `Dict.foldl : (k -> v -> a -> a) -> a -> Dict k v -> a`.
/// Accumulates over every entry in **sorted-key order** (matches Ipê's
/// `_fieldIndex`/sorted-key iteration contract;  `Dict_foldl` iterates
/// map-order but the sorted-key guarantee is a Rust-backend strengthening that
/// matches `dict_keys` / `dict_values` / `dict_to_list` / `dict_map` here).
pub fn dict_foldl<K: Ord + Hash + Eq, V, A, F>(f: F, acc: A, d: HashMap<K, V>) -> A
where
    F: Fn(K, V, A) -> A,
{
    let mut pairs: Vec<(K, V)> = d.into_iter().collect();
    pairs.sort_by(|a, b| a.0.cmp(&b.0));
    pairs.into_iter().fold(acc, |a, (k, v)| f(k, v, a))
}

/// `Dict.singleton : k -> v -> Dict k v` — a one-entry dictionary.
pub fn dict_singleton<K: Hash + Eq, V>(k: K, v: V) -> HashMap<K, V> {
    let mut d = HashMap::new();
    d.insert(k, v);
    d
}

/// `Dict.foldr : (k -> v -> a -> a) -> a -> Dict k v -> a` — fold over every
/// entry in **descending** sorted-key order (mirror of `dict_foldl`'s ascending
/// order; the sorted-key guarantee is the same Rust-backend strengthening).
pub fn dict_foldr<K: Ord + Hash + Eq, V, A, F>(f: F, acc: A, d: HashMap<K, V>) -> A
where
    F: Fn(K, V, A) -> A,
{
    let mut pairs: Vec<(K, V)> = d.into_iter().collect();
    pairs.sort_by(|a, b| a.0.cmp(&b.0));
    pairs.into_iter().rev().fold(acc, |a, (k, v)| f(k, v, a))
}

/// `Dict.filter : (k -> v -> Bool) -> Dict k v -> Dict k v` — keep only the
/// entries for which `pred k v` holds. Keys/values are taken by value (the Ipê
/// closure ABI), so `K: Clone` and `V: Clone`.
pub fn dict_filter<K: Hash + Eq + Clone, V: Clone, F>(pred: F, d: HashMap<K, V>) -> HashMap<K, V>
where
    F: Fn(K, V) -> bool,
{
    d.into_iter()
        .filter(|(k, v)| pred(k.clone(), v.clone()))
        .collect()
}

/// `Dict.partition : (k -> v -> Bool) -> Dict k v -> (Dict k v, Dict k v)` —
/// split into (satisfying, not-satisfying).
pub fn dict_partition<K: Hash + Eq + Clone, V: Clone, F>(
    pred: F,
    d: HashMap<K, V>,
) -> (HashMap<K, V>, HashMap<K, V>)
where
    F: Fn(K, V) -> bool,
{
    d.into_iter().partition(|(k, v)| pred(k.clone(), v.clone()))
}

/// `Dict.intersect : Dict k v -> Dict k v -> Dict k v` — keep the entries of
/// the first dict whose key also appears in the second (values from the first).
#[must_use]
pub fn dict_intersect<K: Hash + Eq, V>(a: HashMap<K, V>, b: HashMap<K, V>) -> HashMap<K, V> {
    a.into_iter().filter(|(k, _)| b.contains_key(k)).collect()
}

/// `Dict.diff : Dict k v -> Dict k v -> Dict k v` — keep the entries of the
/// first dict whose key does NOT appear in the second.
#[must_use]
pub fn dict_diff<K: Hash + Eq, V>(a: HashMap<K, V>, b: HashMap<K, V>) -> HashMap<K, V> {
    a.into_iter().filter(|(k, _)| !b.contains_key(k)).collect()
}

/// `Dict.update : k -> (Maybe v -> Maybe v) -> Dict k v -> Dict k v` — apply
/// `f` to the current value at `k` (`Just v` if present, `Nothing` if absent);
/// `Just v'` re-binds `k`, `Nothing` removes it. Matches Elm exactly.
pub fn dict_update<K: Hash + Eq, V, F>(k: K, f: F, d: HashMap<K, V>) -> HashMap<K, V>
where
    F: Fn(IpeMaybe<V>) -> IpeMaybe<V>,
{
    let mut d = d;
    let current = match d.remove(&k) {
        Some(v) => IpeMaybe::Just(v),
        None => IpeMaybe::Nothing,
    };
    match f(current) {
        IpeMaybe::Just(v) => {
            d.insert(k, v);
        }
        IpeMaybe::Nothing => {}
    }
    d
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;

    #[test]
    fn test_dict_insert_get_roundtrip() {
        let d: IpeDict<i64> = dict_empty();
        let d = dict_insert("a".into(), 1, d);
        let d = dict_insert("b".into(), 2, d);
        match dict_get("a".into(), d.clone()) {
            IpeMaybe::Just(v) => assert_eq!(v, 1),
            IpeMaybe::Nothing => panic!("missing"),
        }
        match dict_get("b".into(), d.clone()) {
            IpeMaybe::Just(v) => assert_eq!(v, 2),
            IpeMaybe::Nothing => panic!("missing"),
        }
        match dict_get("missing".into(), d) {
            IpeMaybe::Just(_) => panic!("should be Nothing"),
            IpeMaybe::Nothing => (),
        }
    }

    #[test]
    fn test_dict_keys_sorted() {
        let mut d: IpeDict<i64> = dict_empty();
        d = dict_insert("c".into(), 3, d);
        d = dict_insert("a".into(), 1, d);
        d = dict_insert("b".into(), 2, d);
        assert_eq!(dict_keys(d), vec!["a".to_string(), "b".into(), "c".into()]);
    }

    #[test]
    fn test_dict_remove_and_member() {
        let mut d: IpeDict<i64> = dict_empty();
        d = dict_insert("x".into(), 10, d);
        assert!(dict_member("x".into(), d.clone()));
        let d = dict_remove("x".into(), d);
        assert!(!dict_member("x".into(), d));
    }

    #[test]
    fn test_dict_empty_keys() {
        let d: IpeDict<i64> = dict_empty();
        assert!(dict_keys(d).is_empty());
    }

    #[test]
    fn test_dict_size_and_is_empty() {
        let d: IpeDict<i64> = dict_empty();
        assert!(dict_is_empty(d.clone()));
        assert_eq!(dict_size(d.clone()), 0);
        let d = dict_insert("x".into(), 42, d);
        assert!(!dict_is_empty(d.clone()));
        assert_eq!(dict_size(d), 1);
    }

    #[test]
    fn test_dict_union_left_biased() {
        let a: IpeDict<i64> = dict_from_list(vec![("x".into(), 1), ("y".into(), 2)]);
        let b: IpeDict<i64> = dict_from_list(vec![
            ("y".into(), 99), // should be overwritten by a's y=2
            ("z".into(), 3),
        ]);
        let merged = dict_union(a, b);
        // a wins for "y"
        assert_eq!(merged.get("x"), Some(&1));
        assert_eq!(merged.get("y"), Some(&2));
        assert_eq!(merged.get("z"), Some(&3));
    }

    #[test]
    fn test_dict_map_sorted() {
        let d: IpeDict<i64> = dict_from_list(vec![("b".into(), 2), ("a".into(), 1)]);
        let result: HashMap<String, i64> = dict_map(|_k, v| v * 10, d);
        assert_eq!(result.get("a"), Some(&10));
        assert_eq!(result.get("b"), Some(&20));
    }

    #[test]
    fn test_dict_foldl_sorted_order() {
        let d: IpeDict<i64> =
            dict_from_list(vec![("c".into(), 3), ("a".into(), 1), ("b".into(), 2)]);
        // Collect keys in fold order; should be sorted (a, b, c).
        let keys_seen = dict_foldl(
            |k, _v, mut acc: Vec<String>| {
                acc.push(k);
                acc
            },
            vec![],
            d,
        );
        assert_eq!(keys_seen, vec!["a".to_string(), "b".into(), "c".into()]);
    }

    #[test]
    fn singleton_and_foldr_match_elm() {
        let d = dict_singleton("k".to_string(), 5i64);
        assert_eq!(dict_size(d.clone()), 1);
        assert_eq!(dict_get("k".to_string(), d), IpeMaybe::Just(5));

        // foldr visits keys in DESCENDING order.
        let d: IpeDict<i64> =
            dict_from_list(vec![("a".into(), 1), ("b".into(), 2), ("c".into(), 3)]);
        let keys = dict_foldr(
            |k, _v, mut acc: Vec<String>| {
                acc.push(k);
                acc
            },
            vec![],
            d,
        );
        assert_eq!(keys, vec!["c".to_string(), "b".into(), "a".into()]);
    }

    #[test]
    fn filter_partition_match_elm() {
        let d: IpeDict<i64> =
            dict_from_list(vec![("a".into(), 1), ("b".into(), 2), ("c".into(), 3)]);
        let evens = dict_filter(|_k, v| v % 2 == 0, d.clone());
        assert_eq!(dict_size(evens.clone()), 1);
        assert_eq!(dict_get("b".to_string(), evens), IpeMaybe::Just(2));

        let (big, small) = dict_partition(|_k, v| v > 1, d);
        assert_eq!(dict_size(big), 2);
        assert_eq!(dict_size(small), 1);
    }

    #[test]
    fn intersect_diff_match_elm() {
        let a: IpeDict<i64> =
            dict_from_list(vec![("a".into(), 1), ("b".into(), 2), ("c".into(), 3)]);
        let b: IpeDict<i64> =
            dict_from_list(vec![("b".into(), 20), ("c".into(), 30), ("d".into(), 40)]);
        // intersect keeps a's values for keys present in b.
        let inter = dict_intersect(a.clone(), b.clone());
        assert_eq!(dict_size(inter.clone()), 2);
        assert_eq!(dict_get("b".to_string(), inter.clone()), IpeMaybe::Just(2));
        assert_eq!(dict_get("a".to_string(), inter), IpeMaybe::Nothing);
        // diff keeps a's entries whose key is absent from b.
        let d = dict_diff(a, b);
        assert_eq!(dict_size(d.clone()), 1);
        assert_eq!(dict_get("a".to_string(), d), IpeMaybe::Just(1));
    }

    #[test]
    fn update_inserts_modifies_removes() {
        let d: IpeDict<i64> = dict_from_list(vec![("a".into(), 1)]);
        // Modify existing.
        let d = dict_update(
            "a".to_string(),
            |m| match m {
                IpeMaybe::Just(v) => IpeMaybe::Just(v + 10),
                IpeMaybe::Nothing => IpeMaybe::Just(0),
            },
            d,
        );
        assert_eq!(dict_get("a".to_string(), d.clone()), IpeMaybe::Just(11));
        // Insert new via Nothing → Just.
        let d = dict_update("b".to_string(), |_m| IpeMaybe::Just(2), d);
        assert_eq!(dict_get("b".to_string(), d.clone()), IpeMaybe::Just(2));
        // Remove via Just → Nothing.
        let d = dict_update("a".to_string(), |_m| IpeMaybe::Nothing, d);
        assert_eq!(dict_get("a".to_string(), d.clone()), IpeMaybe::Nothing);
        assert_eq!(dict_size(d), 1);
    }
}
