//! Test-artifact resolution that fails the calling test rather than skipping it.
//!
//! Every resolver here returns a proof of the artifact's existence or panics
//! with the full [`ResolveError`]: inside a test a panic is a test failure,
//! which is the designed outcome for a missing binary, runtime tree, or
//! manifest directory. None of them reports "absent" to a caller that could
//! then return early and pass without having run. The resolution logic itself
//! lives in [`ipe_env::artifact`], shared with the production resolvers.
//!
//! The one sanctioned early exit from a test body is the tier gate,
//! `if e2e_tier() == Tier::Unit { return; }`, and [`e2e_tier`] is the one
//! reader of `IPE_E2E`.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::path::{Path, PathBuf};

pub use ipe_env::artifact::{
    ProvenBin, ProvenRuntime, ResolveError, Source, Tried, resolve_bin, resolve_bin_from,
    resolve_runtime_src,
};

/// The tier-selecting variable.
pub const E2E_VAR: &str = "IPE_E2E";

/// The only value of [`E2E_VAR`] that selects the end-to-end tier.
pub const E2E_ON: &str = "1";

/// Which test tier this run is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// `IPE_E2E` unset: the fast tier; heavy build-and-run checks are skipped.
    Unit,
    /// `IPE_E2E=1`: the end-to-end tier; every heavy check runs.
    E2e,
}

/// Parse an `IPE_E2E` value into a [`Tier`].
///
/// # Errors
///
/// The raw value when it is set to anything but [`E2E_ON`] (including empty):
/// an unrecognised value is refused rather than read as either tier.
pub fn parse_tier(raw: Option<&OsStr>) -> Result<Tier, OsString> {
    match raw {
        None => Ok(Tier::Unit),
        Some(v) if v == E2E_ON => Ok(Tier::E2e),
        Some(v) => Err(v.to_os_string()),
    }
}

/// The current test tier, read from `IPE_E2E`.
///
/// # Panics
///
/// When `IPE_E2E` is set to anything but `1`: a malformed value fails the test.
#[must_use]
pub fn e2e_tier() -> Tier {
    parse_tier(ipe_env::var_os(E2E_VAR).as_deref()).unwrap_or_else(|raw| {
        fail(format_args!(
            "{E2E_VAR}=`{}` is neither unset nor `{E2E_ON}`; refusing to guess the test tier",
            raw.display()
        ))
    })
}

/// Fail the calling test with `msg`.
#[allow(clippy::panic)] // a failed artifact resolution IS a failed test: the designed outcome
fn fail(msg: fmt::Arguments<'_>) -> ! {
    // IPE-RUST-AUDIT:ACCEPTED — test-support failure path; a panic fails the calling test
    panic!("{msg}")
}

/// Resolve cargo bin target `name`; the body of [`cargo_bin!`](crate::cargo_bin).
///
/// Reads the run-time `CARGO_BIN_EXE_<name>` (re-exported by nextest, correct
/// under an archive) before the compile-time `baked` path.
///
/// # Panics
///
/// With the [`ResolveError`] when neither path is an existing regular file.
#[must_use]
pub fn require_bin(name: &'static str, baked: &str) -> ProvenBin {
    let runtime = ipe_env::var_os(format!("CARGO_BIN_EXE_{name}"));
    resolve_bin(name, runtime, Path::new(baked)).unwrap_or_else(|e| fail(format_args!("{e}")))
}

/// Resolve the runtime module tree (`src/runtime/rust/src`).
///
/// `$IPE_RUNTIME_DIR` when set (authoritative), else the upward walk from the
/// current directory.
///
/// # Panics
///
/// With the [`ResolveError`] when no runtime tree resolves.
#[must_use]
pub fn require_runtime() -> ProvenRuntime {
    let cwd = std::env::current_dir()
        .unwrap_or_else(|e| fail(format_args!("current directory unreadable: {e}")));
    resolve_runtime_src(ipe_env::var_os(ipe_env::artifact::RUNTIME_DIR_VAR), &cwd)
        .unwrap_or_else(|e| fail(format_args!("{e}")))
}

/// Resolve the runtime crate root, the directory holding its `Cargo.toml`.
///
/// The crate root is the resolved module tree itself when it holds the
/// manifest, else its parent.
///
/// # Panics
///
/// When no runtime tree resolves, or neither it nor its parent holds a
/// `Cargo.toml`.
#[must_use]
pub fn require_runtime_crate() -> PathBuf {
    let tree = require_runtime();
    let root = [Some(tree.path()), tree.path().parent()]
        .into_iter()
        .flatten()
        .find(|dir| dir.join("Cargo.toml").is_file())
        .map(Path::to_path_buf);
    root.unwrap_or_else(|| {
        fail(format_args!(
            "runtime tree {} has no Cargo.toml at or directly above it",
            tree.path().display()
        ))
    })
}

/// Resolve the calling crate's manifest directory; the body of [`manifest_dir!`](crate::manifest_dir).
///
/// Reads the run-time `CARGO_MANIFEST_DIR` (set by cargo and nextest, correct
/// under an archive's workspace remap) before the compile-time `baked` path;
/// the winner must be an existing directory.
///
/// # Panics
///
/// With the [`ResolveError`] when neither path is an existing directory.
#[must_use]
pub fn require_manifest_dir(baked: &str) -> PathBuf {
    let runtime = ipe_env::var_os("CARGO_MANIFEST_DIR")
        .filter(|v| !v.is_empty())
        .map(|v| (Source::RuntimeEnv("CARGO_MANIFEST_DIR"), PathBuf::from(v)));
    let candidates = runtime.into_iter().chain(std::iter::once((
        Source::CompileTimeBaked,
        PathBuf::from(baked),
    )));
    let mut tried = Tried::new();
    for (source, path) in candidates {
        if path.is_dir() {
            return path;
        }
        tried.push((source, path));
    }
    let e = ResolveError::Missing {
        name: "CARGO_MANIFEST_DIR",
        tried,
    };
    fail(format_args!("{e}"))
}

/// Resolve cargo bin target `$name` of the calling test crate into a [`ProvenBin`].
///
/// A macro because `CARGO_BIN_EXE_<name>` is only defined at compile time in
/// the integration-test crate that calls it. Never falls back to a `PATH`
/// lookup.
#[macro_export]
macro_rules! cargo_bin {
    ($name:literal) => {
        $crate::bin::require_bin(
            $name,
            ::core::env!(::core::concat!("CARGO_BIN_EXE_", $name)),
        )
    };
}

/// The calling crate's manifest directory as a proven-existing `PathBuf`.
///
/// A macro so the compile-time fallback is the CALLING crate's
/// `CARGO_MANIFEST_DIR`, not this crate's.
#[macro_export]
macro_rules! manifest_dir {
    () => {
        $crate::bin::require_manifest_dir(::core::env!("CARGO_MANIFEST_DIR"))
    };
}
