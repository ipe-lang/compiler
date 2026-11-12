//! The `e2e-support` test harness: the resolver refusals and the
//! workspace-wide source scans, one module each, in one test binary.
//!
//! A new test of this crate is a module here, never a new top-level
//! `tests/<name>.rs`: `test_binaries` refuses a test target the committed
//! allowlist does not name.

#[path = "../common/mod.rs"]
mod common;

mod build_warnings;
mod resolve;
mod skip_scan;
mod target_scan;
mod test_binaries;
