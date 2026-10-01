//! Under nextest, the runtime `CARGO_BIN_EXE_ipe` names the built `ipe` binary.
//!
//! `e2e_support::require_bin` prefers the runtime variable over the
//! compile-time path, so a runner that stops exporting it (or points it at a
//! file an archive did not carry) must fail here, once, by name, rather than
//! leave every end-to-end test resolving a stale baked path.

use std::path::{Path, PathBuf};

#[test]
fn nextest_exports_an_existing_ipe_binary() {
    if ipe_env::var_os("NEXTEST").is_some() {
        let bin = ipe_env::var_os("CARGO_BIN_EXE_ipe").map(PathBuf::from);
        assert!(
            bin.as_deref().is_some_and(Path::is_file),
            "nextest must export `CARGO_BIN_EXE_ipe` naming an existing file; got {bin:?}"
        );
    }
}
