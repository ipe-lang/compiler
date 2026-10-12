//! Regression: polymorphic-kernel turbofish on genuinely-free result types.
//!
//! When the HM solver leaves a polymorphic kernel's result type parameter
//! GENUINELY UNCONSTRAINED — a discarded / empty / phantom position — the
//! emitted Rust must carry a default turbofish so `cargo build` succeeds. Before
//! the fix these shapes `ipe dev build`-accepted (exit 0) but the emitted
//! `ipe_mod_main.rs` failed `cargo build` with `E0282`/`E0283` "type annotations
//! needed" — the exit-0-then-cargo-fail SEAL violation.
//!
//! The fixture exercises every covered kernel shape in an ambiguous position:
//!   * `List.head []` / `List.tail []`   — free element, discarded `Maybe`.
//!   * `List.isEmpty []` / `List.length []` — free element, argument-driven.
//!   * `Dict.keys Dict.empty`            — free key AND value.
//!   * `Set.toList Set.empty`            — free element.
//!   * `Result.mapError (…) (Err …)`     — free (discarded) `Ok` type.
//!   * `Decimal.fromString "abc"`        — free (discarded) error channel.
//!   * `Task.run (Task.fail …)`          — free (phantom) success type.
//!
//! The compile check is a PURE ipe dev build (no cargo) — the ipe-exit-0 half of
//! the SEAL. The run check is `IPE_E2E`-gated: it builds the emitted project
//! (the cargo-exit-0 half) and runs it, asserting the RUNTIME behaviour is still
//! correct (every discarded/empty shape yields its expected value, not just that
//! it compiles with a default type).

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn golden_entry(name: &str) -> PathBuf {
    repo_root()
        .join("tests")
        .join("golden")
        .join(name)
        .join("Main.ipe")
}

const FIXTURE: &str = "ambiguous_kernel_turbofish";

/// ipe must ACCEPT the program (this is never a type error).
/// Pure ipe compile: no cargo, always runs.
#[test]
fn ambiguous_kernel_turbofish_compiles() {
    let entry = golden_entry(FIXTURE);
    let out = crate::support::scratch_root().join("ipec_i181_ambiguous_kernel");
    let _ = std::fs::remove_dir_all(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipec must compile the ambiguous-kernel shapes, got: {:?}",
        built.err()
    );
}

/// The emitted project must `cargo build` (the SEAL) AND run correctly: every
/// discarded / empty / phantom shape yields its expected value. `ok` means all
/// six boolean checks passed; `0,0,0` are the three empty-collection lengths
/// (`List.length []`, `Dict.keys Dict.empty`, `Set.toList Set.empty`).
#[test]
fn ambiguous_kernel_turbofish_builds_and_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let entry = golden_entry(FIXTURE);
    let out = crate::support::scratch_root().join("ipec_i181_ambiguous_kernel_e2e");
    let _ = std::fs::remove_dir_all(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    ipe::build(&entry, &out, &runtime).expect("build must succeed");
    let outcome = crate::support::build_and_run_emitted("i181_ambiguous_kernel", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "clean exit expected (SEAL: ipe-0 ⟹ cargo-0 ⟹ runs); stdout:\n{}",
        outcome.stdout
    );
    assert_eq!(
        outcome.stdout.trim(),
        "ok 0,0,0",
        "every ambiguous shape must yield its expected value"
    );
}
