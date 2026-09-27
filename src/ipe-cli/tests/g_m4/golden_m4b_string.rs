//! Ipe.String parity gate: String and Char kernel functions compile
//! and run with golden parity (rune-correct, byte-for-byte output match).
//!
//! Surfaces the full `Ipe.String` and `Ipe.Char` kernel sets,
//! mirroring the runtime's `String_*` / `Char_*` helpers. Key semantic
//! invariants verified here:
//!
//! * `String.toUpper "hi"` → `"HI"` — ASCII toUpper.
//! * `String.length "héllo"` → `5` — rune count (not byte count); 'é' is U+00E9,
//!   one Unicode scalar value, so the 2-byte UTF-8 encoding must NOT inflate the
//!   count.
//! * `String.slice 1 3 "hello"` → `"el"` — rune-indexed slice, exclusive end.
//! * `String.split "," "a,b,c" |> List.length` → `3` — split produces three
//!   segments.
//! * `String.join "-" ["a","b"]` → `"a-b"` — join with separator.
//! * `String.dropLeft 2 "héllo"` → `"llo"` — rune-based drop: drops 'h' and 'é'
//!   (each one rune) and returns the three remaining runes.
//!
//! Every test is gated on `IPE_E2E=1`; without it the test returns early (the
//! compile-output gates above it still run). Run with:
//!
//! ```text
//! IPE_E2E=1 cargo test golden_m4b_string
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
/// run it, and assert its stdout matches the golden oracle cached in
/// `expected_go.txt` / `oracle.meta`. Gated on `IPE_E2E=1`.
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
    assert_eq!(outcome.exit_code, Some(0), "exit 0");
}

// ── toUpper ──────────────────────────────────────────────────────────────────

/// `String.toUpper "hi"` → `"HI"`.
#[test]
fn string_to_upper_hi() {
    assert_runs_and_matches_oracle("string_to_upper");
}

// ── length — rune count ───────────────────────────────────────────────────────

/// `String.length "héllo"` → `5` (five Unicode scalar values, not 6 bytes).
#[test]
fn string_length_unicode_rune_count() {
    assert_runs_and_matches_oracle("string_length");
}

// ── slice — rune-indexed ──────────────────────────────────────────────────────

/// `String.slice 1 3 "hello"` → `"el"`.
#[test]
fn string_slice_hello() {
    assert_runs_and_matches_oracle("string_slice");
}

// ── split + List.length ───────────────────────────────────────────────────────

/// `String.split "," "a,b,c" |> List.length` → `3`.
#[test]
fn string_split_three_segments() {
    assert_runs_and_matches_oracle("string_split_len");
}

// ── join ──────────────────────────────────────────────────────────────────────

/// `String.join "-" ["a","b"]` → `"a-b"`.
#[test]
fn string_join_with_separator() {
    assert_runs_and_matches_oracle("string_join");
}

// ── dropLeft — rune-based ─────────────────────────────────────────────────────

/// `String.dropLeft 2 "héllo"` → `"llo"` (drops 'h' and 'é', one rune each).
#[test]
fn string_drop_left_unicode_rune_based() {
    assert_runs_and_matches_oracle("string_drop_left");
}

// ── Char.toUpper ──────────────────────────────────────────────────────────────

/// `Char.toUpper 'a'` → `"A"`. Returns a single-rune String.
#[test]
fn char_to_upper_ascii() {
    assert_runs_and_matches_oracle("char_to_upper");
}

// ── Char.isDigit ──────────────────────────────────────────────────────────────

/// `Char.isDigit '5'` → `True` (printed via `if` to avoid Bool→String conv).
#[test]
fn char_is_digit_ascii_five() {
    assert_runs_and_matches_oracle("char_is_digit");
}

// ── Char.isAlpha ──────────────────────────────────────────────────────────────

/// `Char.isAlpha 'x'` → `True`.
#[test]
fn char_is_alpha_ascii_x() {
    assert_runs_and_matches_oracle("char_is_alpha");
}

// ── Predicate golden-verified edges (exact General_Category, not Rust's broader std) ──

/// `Char.isDigit '²'` → `False`. U+00B2 SUPERSCRIPT TWO is category No, not Nd
/// (Rust's `char::is_numeric` would accept it, but Ipê uses the stricter Nd gate).
#[test]
fn char_is_digit_superscript_two_is_false() {
    assert_runs_and_matches_oracle("char_is_digit_superscript");
}

/// `Char.isLower 'ª'` → `False`. U+00AA FEMININE ORDINAL INDICATOR is category
/// Lo (with the `Other_Lowercase` property); Ipê rejects it
/// (Rust's `char::is_lowercase` would accept via `Other_Lowercase`).
#[test]
fn char_is_lower_feminine_ordinal_is_false() {
    assert_runs_and_matches_oracle("char_is_lower_ordinal");
}

// ── String.split "" — rune split, no boundary sentinels ──────────────────────

/// `String.split "" "abc" |> List.length` → `3` (one segment per rune; no
/// leading/trailing "" entries that Rust's `str::split("")` would emit).
#[test]
fn string_split_empty_sep_ascii_three_runes() {
    assert_runs_and_matches_oracle("string_split_empty_ascii");
}

/// `String.split "" "héllo" |> List.length` → `5` (rune-based, so the 2-byte
/// 'é' counts as ONE segment).
#[test]
fn string_split_empty_sep_unicode_five_runes() {
    assert_runs_and_matches_oracle("string_split_empty_unicode");
}

// ── String.toInt — trims surrounding Unicode whitespace ────────────────────────

/// `String.toInt " 42 "` → `Just 42` (printed `42`). Leading and trailing
/// Unicode whitespace is trimmed before parsing, consistent with `toFloat`.
#[test]
fn string_to_int_surrounding_space_trims() {
    assert_runs_and_matches_oracle("string_to_int_trim");
}

/// `String.toInt "1 "` → `Just 1` (printed `1`) — a single trailing space is
/// trimmed away before the parse.
#[test]
fn string_to_int_trailing_space_trims() {
    assert_runs_and_matches_oracle("string_to_int_trailing");
}

// ── String.toFloat — trims surrounding Unicode whitespace ──────────────────────

/// `String.toFloat " 1.5 "` → `Just 1.5` (printed `1.5`). Leading and trailing
/// Unicode whitespace is trimmed before parsing, consistent with `toInt`.
#[test]
fn string_to_float_surrounding_space_is_just() {
    assert_runs_and_matches_oracle("string_to_float_trim");
}

// ── ADR 0001 (#231): Tier-A/B ambient + Tier-C explicit-import SEAL ────────────

/// SEAL for the three-tier auto-import model: Tier-A (`identity`/`not`/
/// `always`) and Tier-B (`Maybe`/`Just`/`Nothing`, `True`/`False`) resolve with
/// NO import, while the Tier-C module `Ipe.String` is reached through its
/// explicit `import Ipe.String as String`. The program compiles and runs to
/// exit 0, printing `a-b`.
#[test]
fn basics_ambient_with_explicit_tier_c_import_runs() {
    assert_runs_and_matches_oracle("basics_ambient_seal");
}
