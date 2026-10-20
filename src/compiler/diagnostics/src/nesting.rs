//! The one expression-nesting ceiling every compiler stage derives its bound from.
//!
//! The parser refuses source nested past [`SOURCE_NESTING_LIMIT`]. The IR
//! walkers and the emitter bound their recursion by [`IR_NESTING_LIMIT`], the
//! source ceiling times [`LOWER_FRAMES_PER_LEVEL`]. The parser's charge keeps
//! `do`/`let` blocks, operator chains (a composition charged
//! [`COMPOSE_NESTING`] levels), pipelines, lambdas, `else if` chains and
//! field-access chains under that IR ceiling. The clone `let`s a capture
//! rewrite adds and an interpolation's `++` spine are not charged at the
//! parser, so the emitter's guard may still refuse them.
//! [`COMPILE_STACK_BYTES`] is the native stack every compile thread is spawned
//! with, sized so the at-ceiling shapes fit it.
//!
//! A bounded source still derives unbounded structure: a flat `let` chain
//! builds a type one level deeper per binding. [`TYPE_DEPTH_LIMIT`] and
//! [`TYPE_SIZE_LIMIT`] bound every type the checker accepts, and
//! [`EMITTED_RECURSION_LIMIT`] is the `#![recursion_limit]` the emitted crate
//! declares, tied to the type ceiling by a build-time relation so every
//! accepted type is one rustc can build.

/// Deepest source nesting the parser admits.
///
/// Every source construct the AST nests, and every desugar that manufactures
/// nesting from a flat sequence, is charged against it where it is built.
pub const SOURCE_NESTING_LIMIT: u32 = 256;

/// Most IR levels one source level lowers to.
///
/// A `do` bind lowers to a call plus its continuation lambda, which the
/// emitter enters as two levels.
pub const LOWER_FRAMES_PER_LEVEL: u32 = 2;

/// IR levels one `>>` / `<<` desugars to: a lambda over two nested calls.
pub const COMPOSE_IR_LEVELS: u32 = 3;

/// Source levels one `>>` / `<<` is charged, so its IR levels fit the IR
/// budget its source levels buy.
pub const COMPOSE_NESTING: u32 = COMPOSE_IR_LEVELS.div_ceil(LOWER_FRAMES_PER_LEVEL);

/// Deepest IR nesting the IR walkers and the emitter recurse through.
///
/// Derived, never typed: it is the source ceiling times the per-level lowering
/// factor, so the parser and the emitter cannot drift onto unrelated ceilings.
pub const IR_NESTING_LIMIT: u32 = SOURCE_NESTING_LIMIT * LOWER_FRAMES_PER_LEVEL;

/// Native stack every compile thread is spawned with.
///
/// It is reserved address space, not committed memory. The at-ceiling shape of
/// every nesting form is compiled through emit on a thread of exactly this
/// size, so a frame-size regression fails a test rather than a build.
pub const COMPILE_STACK_BYTES: usize = 64 << 20;

/// Deepest type the checker accepts, in type-former levels.
///
/// Every function arrow, type application, tuple and record is one level;
/// variables, `()` and nullary types are leaves.
pub const TYPE_DEPTH_LIMIT: u16 = 64;

/// Most Rust type levels one Ipê type level renders to.
///
/// `Task a` renders as `Pin<Box<dyn Future<Output = IpeResult<E, A>> + Send>>`,
/// five syntactic levels, plus the runtime carrier's own fields.
pub const RUSTC_LEVELS_PER_TYPE_LEVEL: u16 = 8;

/// Rust levels reserved for runtime-internal nesting and derive expansion.
pub const RUSTC_BASE_DEPTH: u16 = 64;

/// Most IR type levels lowering adds over the checked type.
///
/// A builtin alias expands at lowering (`Handler` becomes a function from a
/// request to a `Task` of a response).
pub const IR_EXPANSION_SLACK: u16 = 8;

/// Most nodes one type may unfold to.
///
/// A type shared through the solver graph is counted once per occurrence, the
/// size the checker's read-back and every downstream tree walker pay.
pub const TYPE_SIZE_LIMIT: u64 = 1 << 16;

/// The `#![recursion_limit]` the emitted crate root declares.
pub const EMITTED_RECURSION_LIMIT: u16 = 1024;

/// Type depth of the deepest lambda chain the source ceiling admits.
///
/// Each nested `\_ ->` costs five source levels and adds one arrow; the chain
/// sits under three levels of enclosing definition.
pub const LAMBDA_CHAIN_TYPE_DEPTH_AT_SOURCE_CEILING: u32 = (SOURCE_NESTING_LIMIT - 3) / 5;

// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if the IR ceiling stops fitting the `u16` depth the IR walkers and the emitter thread [ledger #boundary]
const _: () = assert!(IR_NESTING_LIMIT <= u16::MAX as u32);
// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if the emitter ceiling drops below the source ceiling, so a program the parser admits could be refused at emit [ledger #boundary]
const _: () = assert!(IR_NESTING_LIMIT >= SOURCE_NESTING_LIMIT);
// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if a source level is charged no lowered frame at all [ledger #boundary]
const _: () = assert!(LOWER_FRAMES_PER_LEVEL >= 1);
// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if a composition's charge stops buying the IR levels it desugars to [ledger #boundary]
const _: () = assert!(COMPOSE_NESTING * LOWER_FRAMES_PER_LEVEL >= COMPOSE_IR_LEVELS);
// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if the deepest Rust type an accepted Ipê type renders to stops fitting the emitted recursion limit [ledger #boundary]
const _: () = assert!(
    (TYPE_DEPTH_LIMIT as u32 + IR_EXPANSION_SLACK as u32) * RUSTC_LEVELS_PER_TYPE_LEVEL as u32
        + RUSTC_BASE_DEPTH as u32
        <= EMITTED_RECURSION_LIMIT as u32
);
// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if the type ceiling refuses a lambda chain the source ceiling admits [ledger #boundary]
const _: () = assert!(TYPE_DEPTH_LIMIT as u32 > LAMBDA_CHAIN_TYPE_DEPTH_AT_SOURCE_CEILING);
// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if the size ceiling refuses the fourteen-deep shared type the read-back certifies, which unfolds to 2^15 - 1 nodes [ledger #boundary]
const _: () = assert!(TYPE_SIZE_LIMIT > 1 << 15);
