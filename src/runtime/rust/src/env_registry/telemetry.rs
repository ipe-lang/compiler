//! The runtime's own observability limits.

use super::{CeilingKey, Doc, EnvEntry, Feature, Lifetime, Subsystem};
use crate::env_grammar::Class;
use crate::system::{EnvCeiling, ZeroCeiling};

/// The recursion-depth ceiling, bounded above by `bound` when given.
#[must_use]
pub const fn recursion_ceiling(bound: Option<u64>) -> EnvCeiling {
    let ceiling = EnvCeiling::new(
        "IPE_RECURSION_LIMIT",
        crate::core::DEFAULT_RECURSION_LIMIT as u64,
        ZeroCeiling::Refused,
        "decimal recursion depth",
    );
    match bound {
        Some(max) => ceiling.at_most(max),
        None => ceiling,
    }
}

/// The maximum Ipê call-stack depth; on wasm32 at most the target's bound.
pub const RECURSION_LIMIT: CeilingKey = CeilingKey::new(
    recursion_ceiling(if cfg!(target_arch = "wasm32") {
        Some(crate::core::WASM_RECURSION_BOUND)
    } else {
        None
    }),
    Doc {
        class: Class::Tunable,
        feature: Feature::Always,
        lifetime: Lifetime::Startup,
        subsystem: Subsystem::Observability,
        purpose: "Maximum Ipê call-stack depth before a recursion-limit error is \
                  raised. Prevents stack-overflow crashes from unbounded recursion. \
                  Read once, at process start; a value that is not a positive \
                  decimal integer (`0` included) refuses the program before its \
                  first line. On wasm32 the maximum is `10000`: a larger value is \
                  refused too, lowering stays possible.",
    },
);

/// This subsystem's entries.
pub const ENTRIES: &[EnvEntry] = &[RECURSION_LIMIT.entry()];
