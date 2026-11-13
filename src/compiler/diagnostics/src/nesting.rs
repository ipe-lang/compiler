//! The one expression-nesting ceiling every compiler stage derives its bound from.
//!
//! The parser refuses source nested past [`SOURCE_NESTING_LIMIT`]. The IR
//! walkers and the emitter bound their recursion by [`IR_NESTING_LIMIT`], the
//! source ceiling times [`LOWER_FRAMES_PER_LEVEL`]. The parser's charge keeps
//! `do`/`let` blocks, operator chains (a composition charged
//! [`COMPOSE_NESTING`] levels), pipelines, lambdas, `else if` chains and
//! field-access chains under that IR ceiling, an operator chain charged over
//! its deepest operand. Lowering adds no nesting of its own past that charge:
//! the clones a capture rewrite takes are one flat node however many it takes,
//! and an interpolation's chunks join in a balanced tree as deep as the
//! logarithm of their count.
//! [`COMPILE_STACK_BYTES`] is the native stack every compile thread is spawned
//! with, sized so the at-ceiling shapes fit it, and
//! [`WASM_SHADOW_STACK_BYTES`] is the linear-memory stack the in-browser
//! compiler is linked with. [`on_compile_stack`] is the one door onto either: it
//! alone mints the [`CompileStack`] proof, and a stack it cannot provide is a
//! typed [`StackRefused`].
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
/// emitter enters as two levels. The at-ceiling shapes in the `ipe` crate's
/// `compile_stack` tests (a `do` read back at its end, an operator chain over
/// a deep operand, an interpolation sixteen times the ceiling) and the IR
/// tests of the flat capture-clone node prove the factor holds.
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

/// Bytes in one WebAssembly linear-memory page.
pub const WASM_PAGE_BYTES: usize = 64 << 10;

/// Linear-memory stack the in-browser compiler is linked with.
///
/// The `ipe-wasm` build script hands it to the linker, so the module's stack
/// is sized from this constant, never from the target's 1 MiB default. Under
/// the target's stack-first layout the stack spans the first this many bytes of
/// linear memory, and an overflow traps below address zero instead of
/// overwriting the heap.
pub const WASM_SHADOW_STACK_BYTES: usize = 8 << 20;

/// Shadow stack the front end must have left when it enters the wasm door.
///
/// The door refuses to run the front end with less, so a wasm32 artifact not
/// linked through the `ipe-wasm` build script fails closed with a typed
/// refusal instead of trapping on deep source.
pub const WASM_FRONT_END_SHADOW_NEED: usize = 4 << 20;

/// Deepest type the checker accepts, in type-former levels.
///
/// Every type application, tuple and record is one level, and every function
/// arrow is [`TYPE_LEVELS_PER_ARROW`]. A user type costs at least its declared
/// nesting: the levels its constructors' payloads render to, so a nullary user
/// type over a chain of declarations is that chain deep. A recursive group of
/// user types costs the sum, over every distinct instantiation of its members
/// it reaches, of that member's payload over its arguments, so the ceiling
/// also bounds how many instantiations one group may build: each costs at
/// least one level. Variables, `()` and builtin nullary types are leaves.
pub const TYPE_DEPTH_LIMIT: u16 = 64;

/// Type levels one function arrow costs.
///
/// The checker charges it per arrow and the emitter per parameter of a curried
/// `Box<dyn FnOnce>` chain, so both count one unit.
pub const TYPE_LEVELS_PER_ARROW: u16 = 1;

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

use std::fmt;
use std::io;
use std::marker::PhantomData;
#[cfg(not(target_arch = "wasm32"))]
use std::thread;

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
// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if an arrow is charged no type level, so a function spine could pass the ceiling at any length [ledger #boundary]
const _: () = assert!(TYPE_LEVELS_PER_ARROW >= 1);
// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if the wasm shadow stack falls below the target's own default [ledger #boundary]
const _: () = assert!(WASM_SHADOW_STACK_BYTES >= 1 << 20);
// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if the wasm shadow stack is not a whole number of linear-memory pages [ledger #boundary]
const _: () = assert!(WASM_SHADOW_STACK_BYTES.is_multiple_of(WASM_PAGE_BYTES));
// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if the wasm shadow stack outgrows the native compile stack it mirrors [ledger #boundary]
const _: () = assert!(WASM_SHADOW_STACK_BYTES <= COMPILE_STACK_BYTES);
// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if the door's need stops fitting the linked shadow stack with a page to spare for the frames above the door [ledger #boundary]
const _: () = assert!(WASM_FRONT_END_SHADOW_NEED <= WASM_SHADOW_STACK_BYTES - WASM_PAGE_BYTES);
// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if the size ceiling refuses the fourteen-deep shared type the read-back certifies, which unfolds to 2^15 - 1 nodes [ledger #boundary]
const _: () = assert!(TYPE_SIZE_LIMIT > 1 << 15);

/// Proof that the current call runs on a stack sized for the nesting ceiling.
///
/// Only [`on_compile_stack`] mints one, and only for the body it runs. The
/// raw-pointer marker keeps it `!Send` and `!Sync`, so the proof cannot leave
/// the stack it was minted on.
pub struct CompileStack {
    _here: PhantomData<*const ()>,
}

impl CompileStack {
    /// The proof for the stack the door just entered.
    const fn minted() -> Self {
        Self { _here: PhantomData }
    }
}

/// Why the door could not run a body on a stack sized for the ceiling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StackRefused {
    /// The OS refused the compile thread.
    ThreadRefused(io::ErrorKind),
    /// The body stopped on a panic instead of returning.
    BodyPanicked,
    /// The wasm shadow stack left at the door is short of the front end's need.
    ShadowStackShort {
        /// Bytes of shadow stack left at the door.
        available: usize,
        /// Bytes the front end needs at the ceiling.
        required: usize,
    },
}

impl fmt::Display for StackRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ThreadRefused(kind) => {
                write!(f, "the compiler could not start its compile thread: {kind}")
            }
            Self::BodyPanicked => f.write_str(
                "the compiler stopped on an internal error before finishing this program",
            ),
            Self::ShadowStackShort {
                available,
                required,
            } => write!(
                f,
                "this WebAssembly build of the compiler has {available} bytes of stack left, \
                 short of the {required} bytes it needs for the deepest nesting it accepts"
            ),
        }
    }
}

impl std::error::Error for StackRefused {}

/// Run `body` on a stack sized for the nesting ceiling, handing it the proof.
///
/// Natively the body runs on a thread of [`COMPILE_STACK_BYTES`]. On wasm32 it
/// runs inline on the module's shadow stack, once at least
/// [`WASM_FRONT_END_SHADOW_NEED`] bytes of it are left.
///
/// # Errors
///
/// [`StackRefused`] when the OS refuses the thread, the body panics, or the
/// wasm shadow stack left at the door is short of the front end's need.
pub fn on_compile_stack<T: Send>(
    body: impl FnOnce(&CompileStack) -> T + Send,
) -> Result<T, StackRefused> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        run_on(compile_thread(), body)
    }
    #[cfg(target_arch = "wasm32")]
    {
        run_inline(body)
    }
}

/// The builder of the native compile thread.
#[cfg(not(target_arch = "wasm32"))]
fn compile_thread() -> thread::Builder {
    thread::Builder::new()
        .name("ipe-compile".to_owned())
        .stack_size(COMPILE_STACK_BYTES)
}

/// Run `body` on a scoped thread `builder` starts, typing each failure.
#[cfg(not(target_arch = "wasm32"))]
fn run_on<T: Send>(
    builder: thread::Builder,
    body: impl FnOnce(&CompileStack) -> T + Send,
) -> Result<T, StackRefused> {
    thread::scope(|scope| {
        let handle = builder
            .spawn_scoped(scope, || body(&CompileStack::minted()))
            .map_err(|e| StackRefused::ThreadRefused(e.kind()))?;
        handle.join().map_err(|_| StackRefused::BodyPanicked)
    })
}

/// Run `body` inline once the shadow stack left here covers the front end's need.
///
/// Under the stack-first layout the shadow stack spans `[0, size)` and grows
/// toward zero, so the address of a local is the bytes still available.
#[cfg(target_arch = "wasm32")]
fn run_inline<T>(body: impl FnOnce(&CompileStack) -> T) -> Result<T, StackRefused> {
    let probe = core::hint::black_box(0_u8);
    let available = core::hint::black_box(&raw const probe).addr();
    if !shadow_available_suffices(available, WASM_FRONT_END_SHADOW_NEED) {
        return Err(StackRefused::ShadowStackShort {
            available,
            required: WASM_FRONT_END_SHADOW_NEED,
        });
    }
    Ok(body(&CompileStack::minted()))
}

/// Whether `available` bytes of shadow stack cover a need of `required`.
#[cfg(any(target_arch = "wasm32", test))]
const fn shadow_available_suffices(available: usize, required: usize) -> bool {
    available >= required
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One byte short of the need is refused; exactly the need is admitted.
    #[test]
    fn shadow_short_is_refused() {
        let required = WASM_FRONT_END_SHADOW_NEED;
        assert!(!shadow_available_suffices(required - 1, required));
        assert!(shadow_available_suffices(required, required));
    }

    /// The door runs its body on the compile thread and returns its value.
    #[test]
    fn door_runs_the_body_on_the_compile_thread() {
        let name = on_compile_stack(|_| thread::current().name().map(str::to_owned));
        assert_eq!(name, Ok(Some("ipe-compile".to_owned())));
    }

    /// A thread the OS refuses comes back as a typed refusal, never a panic.
    #[test]
    fn door_thread_refusal_is_typed() {
        let unbackable = (usize::MAX >> 1) & !(WASM_PAGE_BYTES - 1);
        let refused = run_on(thread::Builder::new().stack_size(unbackable), |_| ());
        assert!(
            matches!(refused, Err(StackRefused::ThreadRefused(_))),
            "an unbackable stack must be refused: {refused:?}"
        );
    }

    /// A body that panics comes back as a typed refusal, never an unwound caller.
    #[test]
    fn door_body_panic_is_typed() {
        let refused = on_compile_stack(|_| "not a number".parse::<u8>().unwrap());
        assert_eq!(refused, Err(StackRefused::BodyPanicked));
    }
}
