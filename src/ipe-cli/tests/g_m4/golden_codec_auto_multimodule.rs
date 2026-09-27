//! `Ipe.Codec.auto` in a DEPENDENCY module of a multi-module program.
//!
//! The record type, its annotated witness, and the `Codec.auto` derive all live
//! in `Lib.Rows`, a non-entry module whose `import Ipe.Codec as Codec` exposes
//! only the `Codec` type — NOT its constructors (`Codec(..)`, `Shape(..)`,
//! `ColType(..)`). The entry module imports the derived codec and round-trips a
//! value through it.
//!
//! Regression guard: the derive synthesises references to its own building-block
//! constructors (`Codec`, `SRecord`, `CText`/…), all defined in `Ipe.Codec`. A
//! version that resolved them only through the unqualified constructor table
//! required every witness module to `exposing (Codec(..), Shape(..),
//! ColType(..))`; a plain qualified import in a dependency module failed at `ipe`
//! time with IPE-N0041 ("cannot derive"), even though the witness was a correct
//! top-level annotated record value. Resolving the constructors through the
//! recognised codec qualifier (`qual_ctors`, always populated regardless of the
//! `exposing` clause) makes the derive work in every module of the program.
//!
//! The fixture prints a single `codec-auto-multimodule-ok` line iff the derived
//! codec round-trips both a full sample and the blank witness, so any regression
//! flips it to `-FAIL` (or fails to build).
//!
//! Gated on `IPE_E2E=1` (build-and-run); without it only the `ipe`-time derive
//! is checked (that IPE-N0041 does not fire).
//!
//! ```text
//! IPE_E2E=1 cargo test -p ipe --test g_m4 codec_auto_multimodule
//! ```

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn golden_dir(root: &Path, name: &str) -> PathBuf {
    root.join("tests").join("golden").join(name)
}

/// `ipe build` (multi-module, sibling discovery) must succeed — the derive in
/// the dependency module resolves its constructors without an `exposing (..)`
/// clause. Checked unconditionally (no `cargo`), since IPE-N0041 fired here
/// before the fix.
fn assert_ipe_derive_succeeds(name: &str) {
    let root = repo_root();
    let entry = golden_dir(&root, name).join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}_ipe_out"));
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        eprintln!("SKIP {name}: runtime not available");
        return;
    };

    let built = ipe::build_with_sibling_discovery(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for {name} (Codec.auto in a dependency module, \
         no `exposing (Codec(..), Shape(..), ColType(..))`); got: {:?}",
        built.err()
    );
}

/// cargo-0 ∧ run-0 for the emitted project, and stdout matches the oracle. Gated
/// on `IPE_E2E=1`.
fn assert_runs_and_matches_oracle(name: &str) {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let root = repo_root();
    let dir = golden_dir(&root, name);
    let entry = dir.join("Main.ipe");
    let out = crate::support::scratch_root().join(format!("ipec_{name}_e2e"));
    let _ = std::fs::remove_dir_all(&out);

    let Ok(runtime) = ipe::resolve_runtime() else {
        eprintln!("SKIP {name}: runtime not available");
        return;
    };

    let built = ipe::build_with_sibling_discovery(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed for {name}: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted(name, &out);
    crate::support::assert_go_parity(name, &dir, &outcome.stdout);
    assert_eq!(outcome.exit_code, Some(0), "exit 0, matching the oracle");
}

/// The derive runs (no IPE-N0041) for a witness + `Codec.auto` in a dependency
/// module that imports `Ipe.Codec` under a plain qualifier only.
#[test]
fn codec_auto_multimodule_derives() {
    assert_ipe_derive_succeeds("codec_auto_multimodule");
}

/// The emitted program round-trips a value through the dependency-derived codec.
/// Output: `codec-auto-multimodule-ok`.
#[test]
fn codec_auto_multimodule_roundtrips() {
    assert_runs_and_matches_oracle("codec_auto_multimodule");
}
