//! The crate-root names emitted `src/ffi.rs` resolves through `use crate::*;`.
//!
//! Every crate that compiles emitted FFI bindings — the emitted program, the
//! Tier-2 probe, the FFI seal apps — takes its crate root from these items, so
//! a binding builds in one crate exactly when it builds in all of them. The
//! backend's `templates/main.rs` is held to carry each item verbatim by a
//! build-time assertion in the backend's preamble module.

/// The runtime's whole public surface, glob-re-exported at the crate root.
pub const RUNTIME_GLOB_ITEM: &str = "pub use ipe_runtime::*;";

/// The error type every carrier names.
pub const ERROR_USE_ITEM: &str = "pub use ipe_runtime::error::IpeError;";

/// The one-argument task carrier every effectful binding returns.
pub const TASK_ALIAS_ITEM: &str = "pub type IpeTask<A> = ipe_runtime::IpeTask<IpeError, A>;";

/// The one-argument success constructor effectful bindings resolve.
pub const OK_RES_ITEM: &str =
    "pub fn ok_res<A>(a: A) -> IpeResult<IpeError, A> {\n    ipe_runtime::core::ok_res(a)\n}";

/// The recursion guard every Ipê function body opens with.
pub const RECURSION_GUARD_ITEM: &str = "pub fn recursion_guard() -> ipe_runtime::core::RecursionGuard {\n    ipe_runtime::core::recursion_guard()\n}";

/// Every crate-root item emitted FFI bindings resolve, each the template's exact text.
pub const FFI_SCOPE_ITEMS: [&str; 5] = [
    RUNTIME_GLOB_ITEM,
    ERROR_USE_ITEM,
    TASK_ALIAS_ITEM,
    OK_RES_ITEM,
    RECURSION_GUARD_ITEM,
];

/// The crate-root alias an effectful binding's task type names.
pub const FFI_TASK_ALIAS: &str = "IpeTask";

/// The FFI crate scope as crate-root source, one item per line.
#[must_use]
pub fn ffi_crate_scope() -> String {
    FFI_SCOPE_ITEMS.join("\n")
}

/// The whole crate root a crate that compiles emitted `src/ffi.rs` opens
/// with: the FFI crate scope, then the bindings module's declaration.
#[must_use]
pub fn ffi_crate_root() -> String {
    format!("{}\nmod ffi;\n", ffi_crate_scope())
}

/// The task type carrying `inner`, spelled through the scope's one-argument alias.
#[must_use]
pub fn ffi_task_type(inner: &str) -> String {
    format!("{FFI_TASK_ALIAS}<{inner}>")
}

#[cfg(test)]
mod tests {
    use super::{
        FFI_SCOPE_ITEMS, FFI_TASK_ALIAS, TASK_ALIAS_ITEM, ffi_crate_root, ffi_crate_scope,
        ffi_task_type,
    };

    #[test]
    fn the_scope_carries_every_item_once() {
        let scope = ffi_crate_scope();
        for item in FFI_SCOPE_ITEMS {
            assert_eq!(scope.matches(item).count(), 1, "{item}");
        }
    }

    #[test]
    fn the_crate_root_is_the_scope_then_the_bindings_module() {
        let root = ffi_crate_root();
        assert!(root.starts_with(&ffi_crate_scope()));
        assert_eq!(root.matches("mod ffi;").count(), 1);
    }

    #[test]
    fn the_task_type_names_the_alias_the_scope_declares() {
        assert_eq!(ffi_task_type("i64"), "IpeTask<i64>");
        assert!(TASK_ALIAS_ITEM.starts_with(&format!("pub type {FFI_TASK_ALIAS}<A> =")));
    }
}
