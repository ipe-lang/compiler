//! `Ipe.Dict` + `Ipe.Set` parity gate.
//!
//! Dict golden tests exercise the `Dict` kernel family end-to-end:
//!
//! * `Dict.get` on a present key     → `42`
//! * `Dict.get` on an absent key     → `-1` (via `Maybe.withDefault`)
//! * `Dict.fromList |> Dict.toList |> List.length` → `3` (round-trip count)
//! * `Dict.keys` count               → `3`
//!
//! Set golden tests exercise the `Set` kernel family:
//!
//! * `Set.member`                    → `True` (`oracle_divergence` = true — see
//!   `set_member_divergence`; ipe output is the reference)
//! * Set union / diff / intersect / dedup sizes → `4 1 2 3` (golden parity)
//!
//! Every test is gated on `IPE_E2E=1`; without it the test returns early. Run:
//!
//! ```text
//! IPE_E2E=1 cargo test golden_m4d
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

// ── Dict.get — present key ────────────────────────────────────────────────────

/// `Dict.get "a" (Dict.insert "a" 42 Dict.empty)` → `42`.
#[test]
fn dict_get_present() {
    assert_runs_and_matches_oracle("dict_get");
}

// ── Dict.get — absent key ─────────────────────────────────────────────────────

/// `Maybe.withDefault (-1) (Dict.get "b" …)` → `-1`.
#[test]
fn dict_get_absent() {
    assert_runs_and_matches_oracle("dict_absent");
}

// ── Dict.fromList → Dict.toList → List.length ─────────────────────────────────

/// `List.length (Dict.toList (Dict.fromList [(…, …), …]))` → `3`.
#[test]
fn dict_round_trip_length() {
    assert_runs_and_matches_oracle("dict_length");
}

// ── Dict.keys count ───────────────────────────────────────────────────────────

/// `List.length (Dict.keys (Dict.fromList [(…, …), …]))` → `3`.
#[test]
fn dict_keys_count() {
    assert_runs_and_matches_oracle("dict_keys");
}

// ── Set.member ────────────────────────────────────────────────────────────────

/// `Set.member 3 (Set.fromList [1, 2, 3])` → `True`.
///
/// `oracle_divergence` = true — `Set_member` panicked in the prior backend;
/// ipe's correct output (`True`) is the reference.
#[test]
fn set_member_present() {
    assert_runs_and_matches_oracle("set_member");
}

// ── Set union / diff / intersect / dedup sizes ───────────────────────────────

/// Set operations: union size `4`, diff size `1`, intersect size `2`,
/// dedup-fromList size `3` → `"4 1 2 3"`.
#[test]
fn set_ops_sizes() {
    assert_runs_and_matches_oracle("set_ops");
}

// ── Generic `a -> Set a` — the comparable-key bound lifts onto the skolem ─────

/// `addTo : a -> Set a -> Set a` whose body is `Set.insert x s`. The Set element
/// obligation lifts `Ord` onto the emitted Rust type parameter
/// (`fn main_addTo<T1: Ord>(x: T1, s: BTreeSet<T1>) -> BTreeSet<T1>`), so the
/// generic compiles and `Set.size (addTo 4 (Set.fromList [1, 2, 3]))` → `4`.
/// Without the bound the emitted `BTreeSet<T1>` would lack `T1: Ord` and `cargo`
/// would reject it.
///
/// `oracle_divergence` = true — the golden oracle program exits non-zero on this
/// shape; ipe's `4` is the reference (same class as `set_member`).
#[test]
fn set_generic_add_to() {
    assert_runs_and_matches_oracle("set_generic");
}
