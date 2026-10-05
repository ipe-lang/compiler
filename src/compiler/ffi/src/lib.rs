//! Shim-free Rust-crate FFI binding generator.
//!
//! Turns the `ipe-ffi-inspector` JSON (`PkgInfo`) into three artifacts: a
//! `.ipei` type-environment seed, a `kernel.json` call registry, and a
//! `<crate>_bindings.rs` wrapper file.
//!
//! There are exactly two typed decode boundaries (`pkginfo`, `call`), so
//! every downstream emitter is a total function over already-validated data.
//!
//! Governing invariant: `ipe dev build` ⇒ `cargo build`. The only sound error
//! direction is over-drop at introspection (a bindable symbol omitted) plus
//! reject-at-decode with `IPE-F4400` (an unrenderable foreign call refused
//! before emission). Under-bind — emitting a binding cargo then rejects — is
//! forbidden.
//!
//! Module DAG (leaf-first): `num_coerce` → `diag` → `naming` → `carrier` /
//! `transparency` / `pkginfo` / `typeref` → `call` → `emit` / `bindings` →
//! `instance` → `driver` → `unify`.

pub mod asserted;
pub mod bindings;
pub mod call;
pub mod capability_scan;
pub mod carrier;
pub mod crate_refs;
pub mod diag;
pub mod driver;
pub mod emit;
pub mod instance;
pub mod interface;
pub mod naming;
pub mod num_coerce;
pub mod pkginfo;
pub mod probe;
pub mod transparency;
pub mod typeref;
pub mod unify;
pub mod wrapper;
