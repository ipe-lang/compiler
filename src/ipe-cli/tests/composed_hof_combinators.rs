//! Regression for #1657: composed higher-order combinators must LOWER and RUN,
//! not merely type-check.
//!
//! A pure parser-combinator surface where a parser is a bare polymorphic closure
//! `State -> PStep a`. The composed combinators — `map2`, a nested `andThen`
//! chain, and a `map2`-of-`map2` sum threaded through `map` — each return a fresh
//! closure that captures polymorphic parser values and applies a returned parser
//! to the threaded state. Before #1657 these type-checked but did not lower: the
//! emitted Rust hit a `Send + Sync` boxing gap (a threaded generic moved out of a
//! re-callable `Fn` closure) and a dropped returned-function application (a curried
//! application of a function-returning lambda lost its trailing argument). This
//! test proves the whole surface now emits AND runs to a deterministic line.

use std::path::PathBuf;

mod support;

#[allow(clippy::expect_used)]
fn runtime() -> PathBuf {
    e2e_support::require_runtime().into_path_buf()
}

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn manifest() -> PathBuf {
    repo_root()
        .join("tests")
        .join("fixtures")
        .join("composed-hof-combinators")
        .join("package.ipe")
}

/// The project builds: every composed combinator lowers to emitted Rust. Before
/// #1657 the build failed at `cargo` (E0277 `Send + Sync` / E0308 dropped
/// application) after `ipe` exit 0 — a SEAL break — so a green `build_project` is
/// itself the lowering proof.
#[test]
fn composed_combinators_lower() {
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("composed_hof_combinators");
    let _ = std::fs::remove_dir_all(&out);

    let res = ipe::build_project(&manifest(), &out, &runtime());
    assert!(
        res.is_ok(),
        "composed-hof-combinators build_project must succeed (composed combinators must lower): {:?}",
        res.err()
    );

    let emitted = support::read_all_emitted_src(&out);
    // The composed combinators are present as boxed-closure-returning functions.
    assert!(
        emitted.contains("fn main_map2") && emitted.contains("fn main_and_then"),
        "emitted Rust must carry the composed combinator functions:\n{emitted}"
    );
}

/// GREEN GATE end-to-end: under `IPE_E2E=1` the emitted binary runs and prints the
/// deterministic line the composed parsers compute. `pairViaAndThen [1,2]` →
/// `1,2`, `pairViaMap2 [3,4]` → `3,4`, `sumThree [10,20,30]` → `60`. A wrong
/// state-thread (the pre-#1657 dropped-application bug) would print a different
/// pair or fail to run at all.
#[test]
fn composed_combinators_run_deterministically() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("composed_hof_combinators_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let res = ipe::build_project(&manifest(), &out, &runtime());
    assert!(res.is_ok(), "build must succeed: {:?}", res.err());

    let outcome = support::build_and_run_emitted("composed_hof_combinators", &out);
    assert_eq!(
        outcome.stdout, "1,2 3,4 60\n",
        "the composed parser combinators must thread state correctly and print the deterministic line"
    );
    assert_eq!(outcome.exit_code, Some(0), "exit 0");
}
