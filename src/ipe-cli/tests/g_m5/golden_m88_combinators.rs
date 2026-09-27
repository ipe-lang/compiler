//! `Result` / `Maybe` applicative-combinator parity gate — the `mapN` /
//! `andMap` / `combine` / `traverse` family wired as kernels.
//!
//! Exercises, end-to-end (ipe → emitted Cargo project → build → run):
//!
//! * `Result.map3` over three `Ok`s → `Ok 6`, and short-circuit on the first
//!   `Err` (the middle argument) → the `Err` arm.  The N-ary builder
//!   (`combine3`) is a MULTI-ARG function value — a Ipê arity-N function lowers
//!   to `impl Fn(A, .., N) -> V`, boxed at the call site, satisfying the
//!   runtime's `impl FnOnce(A, .., N) -> V`.
//! * `Result.map4` / `Result.map5` (max arity) — sum + short-circuit.
//! * `Result.combine` over a `List (Result e a)` → `Ok (List a)`; first `Err`
//!   short-circuits.
//! * `Result.traverse` — one-pass map + collect; first `Err` short-circuits.
//! * `Maybe.map3` + `Maybe.combine` — the `Nothing`-short-circuit mirror.
//!
//! Output (ipe, verified correct by construction — every value is a
//! hand-computable pure fold):
//!
//! ```text
//! 6        <- Result.map3 (Ok+Ok+Ok)
//! ERR      <- Result.map3 short-circuit (middle Err)
//! [1,2,3]  <- Result.combine (all Ok)
//! ERR      <- Result.combine short-circuit
//! [2,4,6]  <- Result.traverse (all Ok)
//! ERR      <- Result.traverse short-circuit
//! 60       <- Maybe.map3 (Just+Just+Just)
//! nothing  <- Maybe.map3 short-circuit (middle Nothing)
//! [1,2,3]  <- Maybe.combine (all Just)
//! nothing  <- Maybe.combine short-circuit
//! 10       <- Result.map4 (1+2+3+4)
//! 15       <- Result.map5 (1+..+5)
//! ERR      <- Result.map5 short-circuit
//! done
//! ```
//!
//! ORACLE DIVERGENCE (`oracle_divergence = true`): the reference compiler
//! cannot produce a reference for this exact program — its `Error` module
//! surface differs (the Rust port exposes the `Error.*` constructors as a
//! prelude kernel qualifier) AND
//! `Result.traverse` is not in the golden reference's `ipe-stdlib/Ipe/Core/Result.ipe`
//! `exposing` list.  Both are pre-existing, sanctioned divergences; the cached
//! expected output is ipe's own, per `docs/architecture/divergence-policy.md`.
//! The load-bearing guarantee this gate enforces is the SEAL: well-typed use of
//! these kernels emits cargo-buildable Rust that runs with the correct
//! short-circuit semantics — NOT byte-parity-locked.
//!
//! Gated on `IPE_E2E=1`; without it the test returns early.  Run:
//!
//! ```text
//! IPE_E2E=1 cargo test -p ipe --test golden_m88_combinators
//! ```

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn golden_dir(root: &Path, name: &str) -> PathBuf {
    root.join("tests").join("golden").join(name)
}

/// Compile `tests/golden/<name>/Main.ipe`, build the emitted Cargo project,
/// run it, and assert its stdout matches the cached oracle.  Gated on
/// `IPE_E2E=1`.
fn assert_runs_and_matches_oracle(name: &str) {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let root = repo_root();
    let dir = golden_dir(&root, name);
    let entry = dir.join("Main.ipe");
    let out = crate::support::scratch_root().join(format!("ipec_{name}_e2e"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve for E2E");
    let Ok(runtime) = runtime else { return };
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed for {name}: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted(name, &out);
    crate::support::assert_go_parity(name, &dir, &outcome.stdout);
    assert_eq!(outcome.exit_code, Some(0), "exit 0, matching the oracle");
}

/// The full `Result` / `Maybe` applicative-combinator family, including
/// short-circuit behaviour on the first `Err` / `Nothing`.
#[test]
fn result_maybe_combinators() {
    assert_runs_and_matches_oracle("result_maybe_combinators");
}

/// SEAL positive — `Result.mapError` with a wildcard handler `\_ -> …`
/// over a genuinely-free error var, called UNPINNED (no result-type
/// annotation). Defaulting the handler's `PAnything` param to
/// `IrType::Json` while the `Ok "concrete"` value side defaults the same
/// free `e` to `IrType::Error` (`IpeError`) would leave the emitted
/// `FnOnce(JsonVal)` closure unable to unify with the `IpeResult<IpeError, _>`
/// value, so cargo rejects it with E0277 despite ipe exit-0. The handler
/// binder retypes to `IpeError`; this gate proves the whole pipeline
/// (ipe → cargo build → run) succeeds and prints `concrete`.
#[test]
fn result_map_error_wildcard_handler() {
    assert_runs_and_matches_oracle("result_map_error_wildcard");
}
