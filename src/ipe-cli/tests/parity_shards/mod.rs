//! Fan-out of the golden fixture population over parity test shards.
//!
//! [`parity_shards!`] declares one `#[test]` per listed shard index and derives
//! the shard count from that same list, so the modulus a shard filters by and
//! the set of shard tests are one fact: a gap, a duplicate, or an out-of-order
//! index fails the build instead of silently dropping fixtures from the gate.

/// Declare one `#[test]` per shard, each calling `$driver(index, count)`.
macro_rules! parity_shards {
    ($driver:ident; $($test:ident = $index:literal),+ $(,)?) => {
        const PARITY_SHARDS: &[usize] = &[$($index),+];
        const _: () = assert!(
            $crate::parity_shards::dense(PARITY_SHARDS),
            "parity shard indices must be exactly 0..count, in order"
        );
        $(
            #[test]
            fn $test() {
                $driver($index, PARITY_SHARDS.len());
            }
        )+
    };
}

/// Whether `indices` is exactly `0, 1, …, len - 1`.
pub const fn dense(indices: &[usize]) -> bool {
    let mut rest = indices;
    let mut expected = 0usize;
    while let [first, tail @ ..] = rest {
        if *first != expected {
            return false;
        }
        expected = expected.saturating_add(1);
        rest = tail;
    }
    true
}

/// Whether the fixture at position `position` belongs to shard `shard` of `count`.
pub const fn owns(position: usize, shard: usize, count: usize) -> bool {
    matches!(position.checked_rem(count), Some(r) if r == shard)
}
