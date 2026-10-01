// Ffi.* polyfill stubs.
//
// The Rust codegen's peephole rewriter handles the static-dispatch shape of
// `Ffi.callPure "<Kernel>" [args]` — kernel name + args list both literal — by
// emitting a direct kernel call. `Ffi.toAny` is the one remaining runtime
// wrapper (an identity: the codegen retains concrete types, so no erasure
// occurs).

/// Identity wrapper. Matches `Ffi.toAny`'s static signature `a -> any` but
/// performs no type erasure at runtime — the codegen retains concrete types.
/// Only reached when `Ffi.toAny` appears outside a peephole-matched
/// `Ffi.callPure` argument list and outside the standalone-toAny peephole.
pub fn ffi_to_any_polyfill<T>(x: T) -> T {
    x
}

// The dynamic-dispatch `Ffi.callPure` / `Ffi.callTask` shape (non-literal kernel
// name or non-literal args) has no denotation on `target=rust`. No stdlib surface
// exposes it to Ipê source and the codegen emits no call to it, so the former
// `ffi_call_pure_polyfill` / `ffi_call_task_polyfill` runtime guards — which
// returned an unconstrained generic `T` and could signal the refusal only by
// panicking — were dead code and are removed. Effectful kernels reach Rust via
// `Kernel.kernel` direct dispatch; the static `Ffi.callPure "<Kernel>" [lit]` shape
// is peephole-resolved to a direct kernel call before emit.

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;

    #[test]
    fn to_any_is_identity_i64() {
        assert_eq!(ffi_to_any_polyfill::<i64>(42), 42);
    }

    #[test]
    fn to_any_is_identity_string() {
        assert_eq!(
            ffi_to_any_polyfill::<String>("hi".to_string()),
            "hi".to_string()
        );
    }
}
