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
//!
//! The walk is bounded in depth as well as in count. Every measure that
//! descends into a part does so through [`Bytes::plus`], which holds one level
//! of [`MEASURE_DEPTH`] for as long as the part is measured; a value nested
//! deeper than the ceiling, or whose levels spend more than `MEASURE_STACK`
//! bytes of stack, measures `None`, the same refusal as an overflow, before its
//! nesting can exhaust the measuring thread's stack. Siblings are
//! measured one after another, so a wide value spends one level, not one per
//! item.

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::num::NonZeroU32;
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

    /// `self` plus the bytes `value` retains, or `None` on overflow or past [`MEASURE_DEPTH`].
    ///
    /// The one place a measure descends into a part: `value` is measured one
    /// level deeper than the caller, and the level is released when its measure
    /// returns, whatever it answers.
    #[must_use]
    pub fn plus<T: RetainedBytes + ?Sized>(self, value: &T) -> Option<Self> {
        let _level = Descent::enter()?;
        self.checked_add(value.retained_bytes()?)
    }

    /// `self` plus the bytes every item retains, or `None` on overflow or past [`MEASURE_DEPTH`].
    ///
    /// Each item is measured through [`Bytes::plus`] in turn, so the items
    /// share one level of depth.
    #[must_use]
    pub fn plus_all<'a, T: RetainedBytes + 'a>(
        self,
        items: impl IntoIterator<Item = &'a T>,
    ) -> Option<Self> {
        items.into_iter().try_fold(self, Self::plus)
    }
}

/// The deepest nesting of parts a measure walks before it answers `None`.
///
/// A level is one [`Bytes::plus`] call live on the measuring thread's stack.
/// The ceiling counts levels; `MEASURE_STACK` bounds the bytes they take, so a
/// walk stops at whichever it reaches first.
pub const MEASURE_DEPTH: NonZeroU32 = match NonZeroU32::new(4096) {
    Some(n) => n,
    None => NonZeroU32::MIN,
};

/// The most stack, in bytes, one measure spends below the frame its first level starts in.
///
/// A level's frame is as large as the measured type's measure makes it: an
/// unoptimized measure of an enum with many payload-carrying variants takes
/// kilobytes a level, so [`MEASURE_DEPTH`] alone does not bound the stack. Past
/// this many bytes the measure answers `None`, however few levels it holds.
/// Half the 2 MiB a tokio worker thread runs on, so the measure's caller keeps
/// the other half.
#[cfg(not(target_arch = "wasm32"))]
pub const MEASURE_STACK: usize = 1 << 20;

thread_local! {
    /// The levels of [`MEASURE_DEPTH`] the measures running on this thread hold.
    static DEPTH: Cell<u32> = const { Cell::new(0) };
    /// The stack address the outermost level held on this thread started at.
    #[cfg(not(target_arch = "wasm32"))]
    static ANCHOR: Cell<usize> = const { Cell::new(0) };
}

/// An approximation of the stack pointer: the address of a stack local.
///
/// The same probe as the recursion guard's (`core::approx_stack_pointer`),
/// kept off AddressSanitizer's fake stack the same way, so the anchor and every
/// later probe read the real stack. The address is read, never dereferenced.
#[cfg(not(target_arch = "wasm32"))]
#[cfg_attr(ipe_asan, sanitize(address = "off"), inline(never))]
#[cfg_attr(not(ipe_asan), inline)]
fn stack_address() -> usize {
    let anchor: u8 = 0;
    std::ptr::from_ref(&anchor).addr()
}

/// Whether a level taken now stays within [`MEASURE_STACK`] of the outermost level.
///
/// The outermost level (`held == 0`) records where the measure starts and is
/// always within.
#[cfg(not(target_arch = "wasm32"))]
fn within_stack(held: u32) -> bool {
    let here = stack_address();
    ANCHOR.with(|anchor| {
        if held == 0 {
            anchor.set(here);
            true
        } else {
            anchor.get().abs_diff(here) <= MEASURE_STACK
        }
    })
}

/// Every level is within the stack bound on wasm32, whose engine stack is not
/// addressable; [`MEASURE_DEPTH`] alone bounds the walk there.
#[cfg(target_arch = "wasm32")]
const fn within_stack(_held: u32) -> bool {
    true
}

/// One level of [`MEASURE_DEPTH`], held while one part is measured.
///
/// Released on drop, so the thread's count returns to where it was however the
/// part's measure ends, refusal or unwind included.
struct Descent(());

impl Descent {
    /// Take one more level, or `None` when the thread already holds
    /// [`MEASURE_DEPTH`] levels or the walk has spent `MEASURE_STACK`.
    fn enter() -> Option<Self> {
        DEPTH.with(|depth| {
            let held = depth.get();
            (held < MEASURE_DEPTH.get() && within_stack(held)).then(|| {
                depth.set(held.saturating_add(1));
                Self(())
            })
        })
    }
}

impl Drop for Descent {
    fn drop(&mut self) {
        DEPTH.with(|depth| depth.set(depth.get().saturating_sub(1)));
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
        deque_frame(self)?.plus_all(self)
    }
}

/// The bytes a deque keeps besides its items: its inline size and its spare slots.
///
/// The one formula every deque-backed measure charges its frame with.
#[must_use]
pub(crate) fn deque_frame<T>(deque: &VecDeque<T>) -> Option<Bytes> {
    let spare = deque.capacity().checked_sub(deque.len())?;
    Bytes::inline::<VecDeque<T>>()?.checked_add(Bytes::slots::<T>(spare)?)
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
    use super::depth_fixture::{Link, chain};
    use super::*;

    /// A value whose measure is the largest count, so any sum with it overflows.
    struct Huge;

    impl RetainedBytes for Huge {
        fn retained_bytes(&self) -> Option<Bytes> {
            Some(Bytes::new(u64::MAX))
        }
    }

    /// The measure of `v`, which must not overflow.
    #[allow(clippy::unwrap_used)] // a test helper: an unmeasurable value is the failure
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

    /// The levels of [`MEASURE_DEPTH`] this thread holds.
    fn held_depth() -> u32 {
        DEPTH.with(Cell::get)
    }

    /// A chain measured through the generic `Option` and `Box` impls, as an emitted recursive type is.
    struct Boxed {
        next: Option<Box<Self>>,
    }

    impl Drop for Boxed {
        // Unlinked one link at a time, so a deep chain drops without recursion.
        fn drop(&mut self) {
            let mut next = self.next.take();
            while let Some(mut link) = next {
                next = link.next.take();
            }
        }
    }

    impl RetainedBytes for Boxed {
        fn retained_bytes(&self) -> Option<Bytes> {
            Bytes::inline::<Self>()?.plus(&self.next)
        }
    }

    /// A `Boxed` chain of `links` links, which `Bytes::plus` measures three levels a link.
    fn boxed(links: u32) -> Boxed {
        let mut head = Boxed { next: None };
        for _ in 1..links {
            head = Boxed {
                next: Some(Box::new(head)),
            };
        }
        head
    }

    // Refusal: one level past the ceiling measures `None`; the ceiling itself
    // measures.
    #[test]
    fn a_value_nested_past_the_depth_ceiling_measures_none() {
        let at = MEASURE_DEPTH.get();
        assert!(Bytes::ZERO.plus(&chain(at)).is_some());
        assert_eq!(Bytes::ZERO.plus(&chain(at + 1)), None);
        // A root measure holds no level for the root itself.
        assert!(chain(at + 1).retained_bytes().is_some());
        assert_eq!(chain(at + 2).retained_bytes(), None);
        // A container spends a level of its own, and a too-deep part refuses
        // the whole container.
        assert!(Bytes::ZERO.plus(&vec![chain(at - 1)]).is_some());
        assert_eq!(Bytes::ZERO.plus(&vec![chain(at)]), None);
        assert_eq!(Bytes::ZERO.plus(&(1_u8, Some(chain(at - 1)))), None);
    }

    // Siblings share one level: a wide, shallow value never reads as deep.
    #[test]
    fn siblings_spend_one_level_not_one_each() {
        let at = MEASURE_DEPTH.get();
        let siblings: Vec<Link> = (0..3).map(|_| chain(at - 1)).collect();
        assert!(Bytes::ZERO.plus(&siblings).is_some());
        let wide: Vec<Link> = (0..100_000).map(|_| chain(1)).collect();
        assert!(wide.retained_bytes().is_some());
        let dict: HashMap<u32, Vec<String>> =
            (0..10_000).map(|k| (k, vec![k.to_string()])).collect();
        assert!(dict.retained_bytes().is_some());
    }

    // A refused measure releases every level it took, so the thread's next
    // measure starts from the top and answers the same.
    #[test]
    fn a_refused_measure_leaves_no_level_held() {
        let at = MEASURE_DEPTH.get();
        let deep = chain(at + 1);
        let fits = chain(at);
        assert_eq!(held_depth(), 0);
        assert_eq!(Bytes::ZERO.plus(&deep), None);
        assert_eq!(held_depth(), 0);
        assert_eq!(Bytes::ZERO.plus(&deep), None);
        let first = Bytes::ZERO.plus(&fits);
        assert!(first.is_some());
        assert_eq!(held_depth(), 0);
        assert_eq!(Bytes::ZERO.plus(&deep), None);
        assert_eq!(Bytes::ZERO.plus(&fits), first);
        assert_eq!(held_depth(), 0);
    }

    // The ceiling's stack fits the 2 MiB a tokio worker runs on, through the
    // generic impls an emitted recursive type measures with, and a chain far
    // past it is refused on that stack rather than overflowing it.
    #[test]
    #[allow(clippy::expect_used)] // test: a failed spawn or a crashed measuring thread is the failure
    fn the_depth_ceiling_fits_a_worker_thread_stack() {
        let measured = std::thread::Builder::new()
            .stack_size(2 * 1024 * 1024)
            .spawn(|| {
                let at = MEASURE_DEPTH.get();
                let links = at / 3;
                (
                    Bytes::ZERO.plus(&boxed(links)).is_some(),
                    Bytes::ZERO.plus(&boxed(links + 1)),
                    Bytes::ZERO.plus(&chain(at)).is_some(),
                    Bytes::ZERO.plus(&chain(1_000_000)),
                )
            })
            .expect("a measuring thread spawns")
            .join()
            .expect("the measuring thread returns");
        assert_eq!(measured, (true, None, true, None));
    }

    /// A chain whose measure keeps an 8 KiB local live at every level, as an
    /// unoptimized measure of a many-variant enum does.
    struct Fat {
        next: Option<Box<Self>>,
    }

    impl Drop for Fat {
        // Unlinked one link at a time, so a deep chain drops without recursion.
        fn drop(&mut self) {
            let mut next = self.next.take();
            while let Some(mut link) = next {
                next = link.next.take();
            }
        }
    }

    impl RetainedBytes for Fat {
        fn retained_bytes(&self) -> Option<Bytes> {
            let pad = std::hint::black_box([0_u8; 8 * 1024]);
            Bytes::inline::<Self>()?
                .plus_count(usize::from(pad.first().copied().unwrap_or_default()))?
                .plus(&self.next)
        }
    }

    /// A `Fat` chain of `links` links.
    fn fat(links: u32) -> Fat {
        let mut head = Fat { next: None };
        for _ in 1..links {
            head = Fat {
                next: Some(Box::new(head)),
            };
        }
        head
    }

    // Refusal: levels whose frames are large spend the stack bound long before
    // the depth ceiling. A chain of 8 KiB frames, a third of the ceiling deep,
    // would take over 10 MiB of stack; on a 2 MiB stack it measures `None`
    // instead, and releases every level it took.
    #[test]
    #[allow(clippy::expect_used)] // test: a failed spawn or a crashed measuring thread is the failure
    fn fat_frames_are_refused_at_the_stack_bound_before_the_depth_ceiling() {
        let measured = std::thread::Builder::new()
            .stack_size(2 * 1024 * 1024)
            .spawn(|| {
                let shallow = fat(8);
                let deep = fat(MEASURE_DEPTH.get() / 3);
                let fits = Bytes::ZERO.plus(&shallow).is_some();
                let refused = Bytes::ZERO.plus(&deep);
                let held_after = held_depth();
                (
                    fits,
                    refused,
                    held_after,
                    Bytes::ZERO.plus(&shallow).is_some(),
                )
            })
            .expect("a measuring thread spawns")
            .join()
            .expect("the measuring thread returns");
        assert_eq!(measured, (true, None, 0, true));
    }

    // The stack bound reads the same stack the recursion guard's red-zone
    // probe reads: both probes, taken in one frame, land within one page.
    #[test]
    fn the_stack_probe_agrees_with_the_recursion_guard_probe() {
        let ours = stack_address();
        let guard = crate::core::stack_pointer_for_test();
        assert!(ours.abs_diff(guard) <= 4096, "{ours:#x} vs {guard:#x}");
    }

    // The choke point is the only descent: no measure in this file reaches a
    // part's `retained_bytes` except through `Bytes::plus`, so every recursion
    // holds a level of the ceiling.
    #[test]
    fn plus_is_the_only_descent_in_this_file() {
        let source = include_str!("retained.rs");
        let production = source
            .split("#[cfg(all(test, not(target_arch = \"wasm32\")))]")
            .next()
            .unwrap_or_default();
        assert!(production.contains("pub fn plus<"));
        let code: Vec<&str> = production
            .lines()
            .map(str::trim)
            .filter(|line| !line.starts_with("//"))
            .collect();
        let descents: Vec<&str> = code
            .iter()
            .copied()
            .filter(|line| line.contains("retained_bytes()"))
            .collect();
        assert_eq!(
            descents,
            vec!["self.checked_add(value.retained_bytes()?)"],
            "only `Bytes::plus` measures a part"
        );
        assert!(
            !code
                .iter()
                .any(|line| line.contains("::retained_bytes") || line.contains("retained_bytes)")),
            "no measure is passed or called by path around `Bytes::plus`"
        );
    }
}

/// A chain value whose nesting depth a test picks, measured one level a link.
#[cfg(all(test, not(target_arch = "wasm32")))]
pub(crate) mod depth_fixture {
    use super::{Bytes, RetainedBytes};

    /// One link of a chain; dropping it unlinks the rest iteratively.
    #[derive(Clone)]
    pub(crate) struct Link {
        next: Option<Box<Self>>,
    }

    impl Drop for Link {
        // Unlinked one link at a time, so a deep chain drops without recursion.
        fn drop(&mut self) {
            let mut next = self.next.take();
            while let Some(mut link) = next {
                next = link.next.take();
            }
        }
    }

    impl RetainedBytes for Link {
        fn retained_bytes(&self) -> Option<Bytes> {
            let inline = Bytes::inline::<Self>()?;
            match &self.next {
                Some(next) => inline.plus(&**next),
                None => Some(inline),
            }
        }
    }

    /// A chain of `links` links (at least one), which `Bytes::plus` measures `links` levels deep.
    pub(crate) fn chain(links: u32) -> Link {
        let mut head = Link { next: None };
        for _ in 1..links {
            head = Link {
                next: Some(Box::new(head)),
            };
        }
        head
    }
}
