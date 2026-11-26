#![forbid(unsafe_code)]
//! Consolidated harness for source scans; each `mod` is one scan.
//!
//! A new source scan of this crate is a module here, never a new top-level
//! `tests/<name>.rs`: `test_binaries` refuses a test target the committed
//! allowlist does not name.
#![cfg(not(target_arch = "wasm32"))]

#[path = "../../../runtime/rust/tests/support/cfg_scan.rs"]
mod cfg_scan;
#[path = "../../../runtime/rust/tests/support/source_tree.rs"]
mod source_tree;

mod lower_span_homing;
