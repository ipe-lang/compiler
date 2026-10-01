//! `Ipe.Math` parity gate — two classes of golden in one file:
//!
//! 1. **Divergence from Ipê**. `Math.min` / `Math.max` are polymorphic
//!    `comparable` (`a -> a -> a`, Elm `Basics.min`/`max`). Ipê routes BOTH
//!    arguments through `AsInt` before the compare, coercing floats to `Int`
//!    (`AsInt 0.4 = 0`, `AsInt 1.3 = 1`) and yielding a meaningless compare for
//!    `String`. Ipê-Rust compares at the argument's actual type and returns the
//!    lesser / greater value unchanged. These goldens assert against Ipê-Rust's
//!    own recorded output via a `sanctioned.divergence` marker tagged
//!    `divergence:`. Rationale: Elm-conformance.
//!
//!      * `Math.min 0.4 1.3` → `0.4`   (Ipê's `AsInt` coercion gives `0`)
//!      * `Math.max 0.4 1.3` → `1.3`   (Ipê's `AsInt` coercion gives `1`)
//!      * `Math.min "b" "a"` → `"a"`   (lexicographic; Ipê's `AsInt` compare is
//!        not meaningful on String)
//!      * `Math.max "b" "a"` → `"b"`
//!
//! 2. **golden parity** — the rest. Here Ipê's output is the target, so the cached
//!    oracle is the cached output (`oracle_divergence = false`) and Ipê must
//!    match it byte-for-byte: `Math.min` / `Math.max` on `Int` (Ipê's `AsInt`
//!    path gives the correct result for integers), `abs`, `sqrt` (incl. the
//!    `sqrt (-1.0)` NaN domain edge), `pow`, `round` (half-away-from-zero, both
//!    signs), `floor` / `ceil` / `trunc` on a negative (the three round
//!    differently), `mod` vs `remainder`, and the `pi` / `nan` constants.
//!
//! Every test is gated on `IPE_E2E=1`; without it the test returns early. Run:
//!
//! ```text
//! IPE_E2E=1 cargo test golden_m4c_math
//! ```

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn golden_dir(root: &Path, name: &str) -> PathBuf {
    root.join("tests").join("golden").join(name)
}

/// Compile `tests/golden/<name>/Main.ipe`, build the emitted Cargo project,
/// run it, and assert its stdout matches the cached oracle (the golden reference
/// for a parity case, or Ipê-Rust's own recorded output for a `divergence:`
/// entry). Gated on `IPE_E2E=1`.
fn assert_runs_and_matches_oracle(name: &str) {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let dir = golden_dir(&root, name);
    let entry = dir.join("Main.ipe");
    let out = crate::support::scratch_root().join(format!("ipec_{name}_e2e"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed for {name}: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted(name, &out);
    crate::support::assert_go_parity(name, &dir, &outcome.stdout);
    assert_eq!(outcome.exit_code, Some(0), "exit 0, matching the oracle");
}

// ── min / max — Int (TRUE golden parity: AsInt path is correct on integers) ───────

/// `Math.min 3 7` → `3`.
#[test]
fn math_min_int() {
    assert_runs_and_matches_oracle("math_min_int");
}

/// `Math.max 3 7` → `7`.
#[test]
fn math_max_int() {
    assert_runs_and_matches_oracle("math_max_int");
}

// ── min / max — Float (divergence-from-ipe: polymorphic compare, no AsInt coercion) ──

/// `Math.min 0.4 1.3` → `0.4`. Ipê's `AsInt` coercion gives `0`; Ipê-Rust
/// compares `f64`s directly and returns `0.4` unchanged. Divergence from Ipê,
/// rationale: Elm-conformance.
#[test]
fn math_min_float_no_truncation() {
    assert_runs_and_matches_oracle("math_min_float");
}

/// `Math.max 0.4 1.3` → `1.3`. Ipê's `AsInt` coercion gives `1`; Ipê-Rust
/// returns `1.3`. Divergence from Ipê, rationale: Elm-conformance.
#[test]
fn math_max_float_no_truncation() {
    assert_runs_and_matches_oracle("math_max_float");
}

// ── min / max — String (divergence-from-ipe: lexicographic polymorphic compare) ──

/// `Math.min "b" "a"` → `"a"`. Polymorphic compare on `String` (lexicographic).
/// Ipê's `AsInt` compare is not meaningful on String. Divergence from Ipê,
/// rationale: Elm-conformance.
#[test]
fn math_min_string_lexicographic() {
    assert_runs_and_matches_oracle("math_min_string");
}

/// `Math.max "b" "a"` → `"b"`. Divergence from Ipê, rationale: Elm-conformance.
#[test]
fn math_max_string_lexicographic() {
    assert_runs_and_matches_oracle("math_max_string");
}

// ── abs ──────────────────────────────────────────────────────────────────────

/// `Math.abs (-5)` → `5`. Integer absolute value (`AsInt` is correct here).
#[test]
fn math_abs() {
    assert_runs_and_matches_oracle("math_abs");
}

// ── sqrt + NaN domain edge ────────────────────────────────────────────────────

/// `Math.sqrt 2.0` → `1.4142135623730951`.
#[test]
fn math_sqrt() {
    assert_runs_and_matches_oracle("math_sqrt");
}

/// `Math.sqrt (-1.0)` → `NaN`. Domain edge: `string_from_float` special-cases NaN.
#[test]
fn math_sqrt_negative_is_nan() {
    assert_runs_and_matches_oracle("math_sqrt_neg");
}

// ── pow ──────────────────────────────────────────────────────────────────────

/// `Math.pow 2.0 10.0` → `1024`. Arity-2 exponentiation.
#[test]
fn math_pow() {
    assert_runs_and_matches_oracle("math_pow");
}

// ── round — half-away-from-zero, both signs ───────────────────────────────────

/// `Math.round 2.5` → `3`. IEEE 754 round-half-away-from-zero rounds halves away from zero.
#[test]
fn math_round_half_away() {
    assert_runs_and_matches_oracle("math_round");
}

/// `Math.round (-2.5)` → `-3`. Half-away-from-zero on the negative side.
#[test]
fn math_round_negative_half_away() {
    assert_runs_and_matches_oracle("math_round_neg");
}

// ── floor / ceil / trunc — the three round a negative differently ─────────────

/// `Math.floor (-2.7)` → `-3`. Toward −∞.
#[test]
fn math_floor_negative() {
    assert_runs_and_matches_oracle("math_floor");
}

/// `Math.ceil (-2.7)` → `-2`. Toward +∞.
#[test]
fn math_ceil_negative() {
    assert_runs_and_matches_oracle("math_ceil");
}

/// `Math.trunc (-2.7)` → `-2`. Toward zero.
#[test]
fn math_trunc_negative() {
    assert_runs_and_matches_oracle("math_trunc");
}

// ── mod vs remainder ──────────────────────────────────────────────────────────

/// `Math.mod 7.0 3.0` → `1`. Modulo carrying the dividend's sign (signed-dividend modulo).
#[test]
fn math_mod() {
    assert_runs_and_matches_oracle("math_mod");
}

/// `Math.remainder 7.0 3.0` → `1`. IEEE 754 remainder semantics.
#[test]
fn math_remainder() {
    assert_runs_and_matches_oracle("math_remainder");
}

// ── constants ─────────────────────────────────────────────────────────────────

/// `Math.pi` → `3.141592653589793`. Zero-arity Float constant.
#[test]
fn math_pi() {
    assert_runs_and_matches_oracle("math_pi");
}

/// `Math.nan` → `NaN`. `string_from_float` special-cases NaN.
#[test]
fn math_nan() {
    assert_runs_and_matches_oracle("math_nan");
}

/// `Math.isNaN Math.nan` → `True`; `Math.isNaN 1.0` → `False`.
#[test]
fn math_is_nan() {
    assert_runs_and_matches_oracle("math_is_nan");
}
