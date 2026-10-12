//! The bytes a value keeps alive, counted with checked arithmetic.
//!
//! [`RetainedBytes::retained_bytes`] is a value's inline size plus every heap
//! allocation it owns: a string's capacity, a container's reserved slots, and
//! each element's own measure. Every payload byte counts at least once, so the
//! measure never falls below the payload a value holds alive. An inline field
//! may count twice (inside its parent's inline size and in its own measure), so
//! the count errs high, never low. A container's internal layout (hash-table
//! buckets and control bytes, B-tree nodes) counts at an upper bound derived
//! from what the container reports; allocator bookkeeping is not counted.
//!
//! A shared `Arc` counts at every reference: each holder pays for what it keeps
//! alive, so sharing can never hide a payload from the holder's measure.
//!
//! Every sum and product is checked. `None` is the overflow refusal: a caller
//! budgeting memory treats it as over every budget.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::sync::Arc;

use crate::basics::IpeOrder;
use crate::core::{IpeMaybe, IpeResult};
use crate::error::{
    IpeAuthError, IpeDbFailure, IpeError, IpeErrorDetails, IpeErrorInfo, IpeErrorKind,
    IpePanicInfo, IpeTypeInfo,
};

/// A count of bytes.
///
/// Combined only through checked operations, so an overflow is a typed `None`,
/// never a wrapped or saturated count.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Bytes(u64);

/// Bytes in one mebibyte.
const MIB: u64 = 1 << 20;

impl Bytes {
    /// No bytes.
    pub const ZERO: Self = Self(0);

    /// The count `n`.
    #[must_use]
    pub const fn new(n: u64) -> Self {
        Self(n)
    }

    /// `n` mebibytes.
    ///
    /// A `u16` count times one mebibyte fits a `u64`, so this cannot overflow.
    #[must_use]
    pub const fn mib(n: u16) -> Self {
        Self((n as u64) * MIB)
    }

    /// The count as a `u64`.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// `n` bytes, or `None` when `n` does not fit a `u64`.
    #[must_use]
    pub fn count(n: usize) -> Option<Self> {
        u64::try_from(n).ok().map(Self)
    }

    /// The inline size of `T`.
    #[must_use]
    pub fn inline<T>() -> Option<Self> {
        Self::count(size_of::<T>())
    }

    /// The inline size of `n` values of `T`, or `None` on overflow.
    #[must_use]
    pub fn slots<T>(n: usize) -> Option<Self> {
        Self::inline::<T>()?.checked_mul(u64::try_from(n).ok()?)
    }

    /// `self + other`, or `None` on overflow.
    #[must_use]
    pub fn checked_add(self, other: Self) -> Option<Self> {
        self.0.checked_add(other.0).map(Self)
    }

    /// `self * factor`, or `None` on overflow.
    #[must_use]
    pub fn checked_mul(self, factor: u64) -> Option<Self> {
        self.0.checked_mul(factor).map(Self)
    }

    /// `self` plus `n` bytes, or `None` on overflow.
    #[must_use]
    pub fn plus_count(self, n: usize) -> Option<Self> {
        self.checked_add(Self::count(n)?)
    }

    /// `self` plus the bytes `value` retains, or `None` on overflow.
    #[must_use]
    pub fn plus<T: RetainedBytes + ?Sized>(self, value: &T) -> Option<Self> {
        self.checked_add(value.retained_bytes()?)
    }

    /// `self` plus the bytes every item retains, or `None` on overflow.
    #[must_use]
    pub fn plus_all<'a, T: RetainedBytes + 'a>(
        self,
        items: impl IntoIterator<Item = &'a T>,
    ) -> Option<Self> {
        items.into_iter().try_fold(self, Self::plus)
    }
}

/// The bytes a value keeps alive.
///
/// Implemented for every carrier a Web `Model` or a wire-decoded `Msg` can
/// hold; the backend emits an impl beside every `IpeStringify` impl it emits.
pub trait RetainedBytes {
    /// This value's inline size plus every allocation it owns, or `None` on overflow.
    fn retained_bytes(&self) -> Option<Bytes>;
}

/// Implement [`RetainedBytes`] as the inline size, for types owning no allocation.
macro_rules! inline_measure {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl $crate::retained::RetainedBytes for $ty {
                fn retained_bytes(&self) -> Option<$crate::retained::Bytes> {
                    $crate::retained::Bytes::inline::<Self>()
                }
            }
        )+
    };
}
pub(crate) use inline_measure;

crate::retained::inline_measure!(
    bool,
    char,
    (),
    u8,
    u16,
    u32,
    u64,
    u128,
    usize,
    i8,
    i16,
    i32,
    i64,
    i128,
    isize,
    f32,
    f64,
);

crate::retained::inline_measure!(IpeOrder, IpeErrorKind, IpeDbFailure, IpeAuthError);

// ─── Strings ─────────────────────────────────────────────────────────────────

impl RetainedBytes for str {
    // The bytes of the slice itself; its holder counts the pointer.
    fn retained_bytes(&self) -> Option<Bytes> {
        Bytes::count(self.len())
    }
}

impl RetainedBytes for String {
    // The whole allocation: spare capacity is held as surely as the text.
    fn retained_bytes(&self) -> Option<Bytes> {
        Bytes::inline::<Self>()?.plus_count(self.capacity())
    }
}

// ─── Owning pointers ─────────────────────────────────────────────────────────

impl<T: RetainedBytes + ?Sized> RetainedBytes for Box<T> {
    fn retained_bytes(&self) -> Option<Bytes> {
        Bytes::inline::<Self>()?.plus(&**self)
    }
}

impl<T: RetainedBytes + ?Sized> RetainedBytes for Arc<T> {
    // Every reference counts the pointee and its two reference counters.
    fn retained_bytes(&self) -> Option<Bytes> {
        Bytes::inline::<Self>()?
            .checked_add(Bytes::inline::<[usize; 2]>()?)?
            .plus(&**self)
    }
}

// ─── Sequences ───────────────────────────────────────────────────────────────

impl<T: RetainedBytes> RetainedBytes for Vec<T> {
    fn retained_bytes(&self) -> Option<Bytes> {
        let spare = self.capacity().checked_sub(self.len())?;
        Bytes::inline::<Self>()?
            .checked_add(Bytes::slots::<T>(spare)?)?
            .plus_all(self)
    }
}

impl<T: RetainedBytes> RetainedBytes for [T] {
    fn retained_bytes(&self) -> Option<Bytes> {
        Bytes::ZERO.plus_all(self)
    }
}

impl<T: RetainedBytes> RetainedBytes for VecDeque<T> {
    fn retained_bytes(&self) -> Option<Bytes> {
        let spare = self.capacity().checked_sub(self.len())?;
        Bytes::inline::<Self>()?
            .checked_add(Bytes::slots::<T>(spare)?)?
            .plus_all(self)
    }
}

// ─── Maps and sets ───────────────────────────────────────────────────────────

/// Control bytes a hash table keeps past its last bucket (the widest probe group).
const HASH_GROUP_WIDTH: usize = 16;

/// An upper bound on the buckets a hash table reporting `capacity` allocates.
///
/// A table keeps at most seven of every eight buckets full, and a table under
/// eight buckets keeps one empty, so `capacity + ⌈capacity / 7⌉ + 1` covers
/// both. A zero capacity allocates nothing.
fn hash_buckets(capacity: usize) -> Option<usize> {
    if capacity == 0 {
        return Some(0);
    }
    capacity.checked_add(capacity.div_ceil(7))?.checked_add(1)
}

/// An upper bound on the bytes a hash table of `T` slots reporting `capacity` allocates.
///
/// Every bucket counts a padded `T` slot and a control byte, plus the trailing
/// probe group.
pub(crate) fn hash_table<T>(capacity: usize) -> Option<Bytes> {
    let buckets = hash_buckets(capacity)?;
    if buckets == 0 {
        return Some(Bytes::ZERO);
    }
    Bytes::slots::<T>(buckets)?.plus_count(buckets.checked_add(HASH_GROUP_WIDTH)?)
}

impl<K: RetainedBytes, V: RetainedBytes, S> RetainedBytes for HashMap<K, V, S> {
    // The table at its reported capacity; every entry then counts its own measure.
    fn retained_bytes(&self) -> Option<Bytes> {
        let table = Bytes::inline::<Self>()?.checked_add(hash_table::<(K, V)>(self.capacity())?)?;
        self.iter()
            .try_fold(table, |acc, (k, v)| acc.plus(k)?.plus(v))
    }
}

/// Keys one B-tree node holds at most.
const BTREE_NODE_KEYS: usize = 11;

/// Keys every B-tree node but the root holds at least.
const BTREE_MIN_NODE_KEYS: usize = 5;

/// An upper bound on the bytes the nodes of a B-tree of `len` entries allocate.
///
/// Every key lives in one node and every node but the root holds at least
/// [`BTREE_MIN_NODE_KEYS`], so `1 + len / 5` bounds the node count. Each node
/// counts as an internal one: its parent link and lengths, its full key and
/// value arrays, and a child pointer per key plus one. An empty tree
/// allocates no node.
fn btree_nodes<K, V>(len: usize) -> Option<Bytes> {
    if len == 0 {
        return Some(Bytes::ZERO);
    }
    let nodes = (len / BTREE_MIN_NODE_KEYS).checked_add(1)?;
    let node = Bytes::inline::<[usize; 2]>()?
        .checked_add(Bytes::slots::<K>(BTREE_NODE_KEYS)?)?
        .checked_add(Bytes::slots::<V>(BTREE_NODE_KEYS)?)?
        .checked_add(Bytes::slots::<usize>(BTREE_NODE_KEYS.checked_add(1)?)?)?;
    node.checked_mul(u64::try_from(nodes).ok()?)
}

impl<K: RetainedBytes, V: RetainedBytes> RetainedBytes for BTreeMap<K, V> {
    fn retained_bytes(&self) -> Option<Bytes> {
        let nodes = Bytes::inline::<Self>()?.checked_add(btree_nodes::<K, V>(self.len())?)?;
        self.iter()
            .try_fold(nodes, |acc, (k, v)| acc.plus(k)?.plus(v))
    }
}

impl<T: RetainedBytes> RetainedBytes for BTreeSet<T> {
    // A set is a map to `()`, so its nodes hold no value array.
    fn retained_bytes(&self) -> Option<Bytes> {
        Bytes::inline::<Self>()?
            .checked_add(btree_nodes::<T, ()>(self.len())?)?
            .plus_all(self)
    }
}

// ─── Sums ────────────────────────────────────────────────────────────────────

impl<T: RetainedBytes> RetainedBytes for Option<T> {
    fn retained_bytes(&self) -> Option<Bytes> {
        let inline = Bytes::inline::<Self>()?;
        match self {
            Some(v) => inline.plus(v),
            None => Some(inline),
        }
    }
}

impl<A: RetainedBytes, E: RetainedBytes> RetainedBytes for Result<A, E> {
    fn retained_bytes(&self) -> Option<Bytes> {
        let inline = Bytes::inline::<Self>()?;
        match self {
            Ok(a) => inline.plus(a),
            Err(e) => inline.plus(e),
        }
    }
}

impl<T: RetainedBytes> RetainedBytes for IpeMaybe<T> {
    fn retained_bytes(&self) -> Option<Bytes> {
        let inline = Bytes::inline::<Self>()?;
        match self {
            Self::Just(v) => inline.plus(v),
            Self::Nothing => Some(inline),
        }
    }
}

impl<E: RetainedBytes, A: RetainedBytes> RetainedBytes for IpeResult<E, A> {
    fn retained_bytes(&self) -> Option<Bytes> {
        let inline = Bytes::inline::<Self>()?;
        match self {
            Self::Ok(a) => inline.plus(a),
            Self::Err(e) => inline.plus(e),
        }
    }
}

// ─── Tuples ──────────────────────────────────────────────────────────────────

macro_rules! tuple_measures {
    ($(($($t:ident $i:tt),+);)*) => {
        $(
            impl<$($t: RetainedBytes),+> RetainedBytes for ($($t,)+) {
                fn retained_bytes(&self) -> Option<Bytes> {
                    let total = Bytes::inline::<Self>()?;
                    $(let total = total.plus(&self.$i)?;)+
                    Some(total)
                }
            }
        )*
    };
}

tuple_measures! {
    (A 0);
    (A 0, B 1);
    (A 0, B 1, C 2);
    (A 0, B 1, C 2, D 3);
    (A 0, B 1, C 2, D 3, E 4);
    (A 0, B 1, C 2, D 3, E 4, F 5);
    (A 0, B 1, C 2, D 3, E 4, F 5, G 6);
    (A 0, B 1, C 2, D 3, E 4, F 5, G 6, H 7);
    (A 0, B 1, C 2, D 3, E 4, F 5, G 6, H 7, I 8);
    (A 0, B 1, C 2, D 3, E 4, F 5, G 6, H 7, I 8, J 9);
    (A 0, B 1, C 2, D 3, E 4, F 5, G 6, H 7, I 8, J 9, K 10);
    (A 0, B 1, C 2, D 3, E 4, F 5, G 6, H 7, I 8, J 9, K 10, L 11);
}

// ─── `Ipe.Error` ─────────────────────────────────────────────────────────────

impl RetainedBytes for IpePanicInfo {
    fn retained_bytes(&self) -> Option<Bytes> {
        Bytes::inline::<Self>()?
            .plus(&self.message)?
            .plus(&self.stack)
    }
}

impl RetainedBytes for IpeTypeInfo {
    fn retained_bytes(&self) -> Option<Bytes> {
        Bytes::inline::<Self>()?
            .plus(&self.expected)?
            .plus(&self.actual)
    }
}

impl RetainedBytes for IpeErrorDetails {
    fn retained_bytes(&self) -> Option<Bytes> {
        let inline = Bytes::inline::<Self>()?;
        match self {
            Self::FfiPanic(p) => inline.plus(p),
            Self::TypeMismatch(t) => inline.plus(t),
            Self::HttpStatus(n) => inline.plus(n),
            Self::JsonDecode(s) | Self::Custom(s) => inline.plus(s),
            Self::Database(f) => inline.plus(f),
        }
    }
}

impl RetainedBytes for IpeErrorInfo {
    fn retained_bytes(&self) -> Option<Bytes> {
        Bytes::inline::<Self>()?
            .plus(&self.message)?
            .plus(&self.details)
    }
}

impl RetainedBytes for IpeError {
    fn retained_bytes(&self) -> Option<Bytes> {
        match self {
            Self::Error(kind, info) => Bytes::inline::<Self>()?.plus(kind)?.plus(info),
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    /// A value whose measure is the largest count, so any sum with it overflows.
    struct Huge;

    impl RetainedBytes for Huge {
        fn retained_bytes(&self) -> Option<Bytes> {
            Some(Bytes::new(u64::MAX))
        }
    }

    /// The measure of `v`, which must not overflow.
    fn measure<T: RetainedBytes + ?Sized>(v: &T) -> u64 {
        v.retained_bytes().map(Bytes::get).unwrap()
    }

    /// `n` distinct strings of `k` bytes each.
    fn strings(n: usize, k: usize) -> Vec<String> {
        (0..n)
            .map(|i| {
                let mut s = format!("{i:0k$}");
                s.truncate(k);
                s
            })
            .collect()
    }

    #[test]
    fn retained_bytes_bounds_payload_from_below() {
        let (n, k) = (64_usize, 100_usize);
        let payload = u64::try_from(n * k).unwrap();

        let list = strings(n, k);
        assert!(measure(&list) >= payload);

        let nested: Vec<(String, IpeMaybe<Vec<String>>)> = strings(n, k)
            .into_iter()
            .map(|s| (s.clone(), IpeMaybe::Just(vec![s])))
            .collect();
        assert!(measure(&nested) >= payload * 2);

        let dict: HashMap<String, String> = strings(n, k)
            .into_iter()
            .zip(strings(n, k).into_iter().rev())
            .collect();
        assert!(measure(&dict) >= payload);

        let shared = Arc::new("s".repeat(n * k));
        let twice = vec![Arc::clone(&shared), Arc::clone(&shared)];
        assert!(measure(&twice) >= payload * 2);
    }

    #[test]
    fn retained_bytes_is_monotone_under_growth() {
        let mut list: Vec<String> = Vec::new();
        let mut last = measure(&list);
        for s in strings(32, 40) {
            list.push(s);
            let now = measure(&list);
            assert!(now > last, "growing the list must grow its measure");
            last = now;
        }
        let mut longer = list.clone();
        if let Some(first) = longer.first_mut() {
            first.push_str(&"x".repeat(4096));
        }
        assert!(measure(&longer) > measure(&list));
    }

    #[test]
    fn an_overflowing_sum_is_refused() {
        assert_eq!(vec![Huge, Huge].retained_bytes(), None);
        assert_eq!((Huge, 1_i64).retained_bytes(), None);
        assert_eq!(Some(Huge).retained_bytes(), None);
        assert_eq!(Bytes::new(u64::MAX).checked_add(Bytes::new(1)), None);
        assert_eq!(Bytes::new(u64::MAX).checked_mul(2), None);
        assert_eq!(Bytes::new(u64::MAX).plus(&0_u8), None);
    }

    #[test]
    fn a_shared_arc_counts_at_every_reference() {
        let k = 10_000_usize;
        let shared: Arc<String> = Arc::new("a".repeat(k));
        let mut one = Vec::with_capacity(2);
        one.push(Arc::clone(&shared));
        let two = vec![Arc::clone(&shared), Arc::clone(&shared)];
        let k = u64::try_from(k).unwrap();
        assert!(measure(&two) >= measure(&one) + k);

        let text: Arc<str> = Arc::from("b".repeat(10_000));
        let pair = (Arc::clone(&text), Arc::clone(&text));
        assert!(measure(&pair) >= 2 * k);
    }

    #[test]
    fn a_string_counts_its_capacity_not_its_length() {
        let mut s = String::with_capacity(8192);
        s.push('a');
        assert!(measure(&s) >= 8192);

        let mut v: Vec<u8> = Vec::with_capacity(8192);
        v.push(1);
        assert!(measure(&v) >= 8192);
    }

    #[test]
    fn an_error_counts_its_messages() {
        let message = "m".repeat(5000);
        let err = IpeError::invalid_input(message);
        assert!(measure(&err) >= 5000);
        let details = IpeErrorDetails::FfiPanic(IpePanicInfo {
            message: "p".repeat(3000),
            stack: vec!["s".repeat(3000)],
        });
        assert!(measure(&details) >= 6000);
    }

    // A hash table allocates a padded slot and a control byte per bucket, and
    // more buckets than its reported capacity.
    #[test]
    fn a_hash_map_counts_its_buckets_at_their_padded_size() {
        let map: HashMap<u8, u64> = (0..=u8::MAX).map(|k| (k, u64::from(k))).collect();
        let capacity = map.capacity();
        let buckets = if capacity < 8 {
            capacity + 1
        } else {
            (capacity * 8 / 7).next_power_of_two()
        };
        let table = buckets * size_of::<(u8, u64)>() + buckets + HASH_GROUP_WIDTH;
        assert!(measure(&map) >= u64::try_from(table).unwrap());
        assert_eq!(
            measure(&HashMap::<u8, u64>::new()),
            u64::try_from(size_of::<HashMap<u8, u64>>()).unwrap()
        );
    }

    // A one-entry B-tree allocates a whole node, not one entry's inline size.
    #[test]
    fn a_btree_counts_its_nodes() {
        let one: BTreeSet<i64> = std::iter::once(7).collect();
        let node = BTREE_NODE_KEYS * size_of::<i64>();
        assert!(measure(&one) >= u64::try_from(node).unwrap());

        let n = 1000_usize;
        let map: BTreeMap<i64, i64> = (0..1000).map(|k| (k, k)).collect();
        // At least `n / 11` nodes, each holding its parent link and full arrays.
        let nodes = n.div_ceil(BTREE_NODE_KEYS);
        let floor = nodes * (size_of::<usize>() + BTREE_NODE_KEYS * 2 * size_of::<i64>());
        assert!(measure(&map) >= u64::try_from(floor).unwrap());
        assert_eq!(
            measure(&BTreeSet::<i64>::new()),
            u64::try_from(size_of::<BTreeSet<i64>>()).unwrap()
        );
    }

    #[test]
    fn a_mebibyte_is_two_to_the_twentieth() {
        assert_eq!(Bytes::mib(1).get(), 1 << 20);
        assert_eq!(Bytes::mib(u16::MAX).get(), u64::from(u16::MAX) << 20);
    }
}
