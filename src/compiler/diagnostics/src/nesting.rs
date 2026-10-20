//! The one expression-nesting ceiling every compiler stage derives its bound from.
//!
//! The parser refuses source nested past [`SOURCE_NESTING_LIMIT`]. The IR
//! walkers and the emitter bound their recursion by [`IR_NESTING_LIMIT`], the
//! source ceiling times [`LOWER_FRAMES_PER_LEVEL`]. The parser's charge keeps
//! `do`/`let` blocks, operator chains, pipelines, lambdas and `else if` chains
//! under that IR ceiling. The clone `let`s a capture rewrite adds and an
//! interpolation's `++` spine are not charged at the parser, so the emitter's
//! guard may still refuse them. [`COMPILE_STACK_BYTES`] is the native stack
//! every compile thread is spawned with, sized so the at-ceiling shapes fit it.

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

// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if the IR ceiling stops fitting the `u16` depth the IR walkers and the emitter thread [ledger #boundary]
const _: () = assert!(IR_NESTING_LIMIT <= u16::MAX as u32);
// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if the emitter ceiling drops below the source ceiling, so a program the parser admits could be refused at emit [ledger #boundary]
const _: () = assert!(IR_NESTING_LIMIT >= SOURCE_NESTING_LIMIT);
// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if a source level is charged no lowered frame at all [ledger #boundary]
const _: () = assert!(LOWER_FRAMES_PER_LEVEL >= 1);
