//! `Ipe.Json.Decode` + `Ipe.Json.Decode.Pipeline` parity gate —
//! JSON decoder combinators with byte-for-byte golden parity.
//!
//! Tests exercise the `JsonDec` and `JsonDecP` kernel families end-to-end:
//!
//! * `JsonDec.int` + `JsonDec.string` via `JsonDec.decodeString` — primitive
//!   decoders on bare JSON values.  `JsonDec.int` yields an integer or a typed
//!   rejection (parse, don't validate): `"3.0"`/`"1e2"` decode to `3`/`100`
//!   (integral magnitudes), while `"3.5"` is rejected as non-integral rather
//!   than silently truncated.
//!   (`json_dec_primitives`)
//!
//! * `JsonDec.list JsonDec.int` on `"[1,2,3]"` — the list combinator wraps its
//!   element decoder in a factory so it can be reused per element.
//!   (`json_dec_list`)
//!
//! * `JsonDec.field`, `JsonDec.at`, `JsonDec.index` — structural access into
//!   JSON objects and arrays.
//!   (`json_dec_field_at_index`)
//!
//! * `JsonDec.int` on a string value — verifies that a type mismatch produces
//!   `Err _`, not a panic.
//!   (`json_dec_fail`)
//!
//! * `JsonDec.oneOf [map fromInt int, string]` — tries decoders in order;
//!   first success wins.
//!   (`json_dec_one_of`)
//!
//! * `JsonDec.succeed makePerson |> JsonDecP.required "name" string |>
//!   JsonDecP.required "age" int |> JsonDecP.optional "nickname" string "unknown"` —
//!   pipeline-style record decoder; the optional field supplies a default when
//!   absent.
//!   (`json_dec_pipeline`)
//!
//! Every test is gated on `IPE_E2E=1`; without it the test returns early.  Run:
//!
//! ```text
//! IPE_E2E=1 cargo test golden_m4h
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
/// run it, and assert its stdout matches the cached oracle.  Gated on
/// `IPE_E2E=1`.
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

// ── primitives ───────────────────────────────────────────────────────────────

/// `JsonDec.int` on `"3.0"`/`"3.5"`/`"1e2"` → `Ok 3`/`Err _`/`Ok 100` — the
/// non-integral `"3.5"` is rejected (shown as `"reject"`), not truncated;
/// `JsonDec.string "\"hello\""` → "hello".  Output: `"3 reject 100 hello"`.
#[test]
fn json_dec_primitives() {
    assert_runs_and_matches_oracle("json_dec_primitives");
}

// ── list combinator ──────────────────────────────────────────────────────────

/// `JsonDec.list JsonDec.int "[1,2,3]"` → `[1,2,3]`; print `List.length`.
/// Output: `"3"`.
#[test]
fn json_dec_list() {
    assert_runs_and_matches_oracle("json_dec_list");
}

// ── structural access ────────────────────────────────────────────────────────

/// `field "name"`, `at ["nested","score"]`, `index 1 bool` access.
/// Output: `"Alice 99 y"`.
#[test]
fn json_dec_field_at_index() {
    assert_runs_and_matches_oracle("json_dec_field_at_index");
}

// ── failing decode ───────────────────────────────────────────────────────────

/// `JsonDec.int "\"not an int\""` → `Err _`.  Output: `"got error"`.
#[test]
fn json_dec_fail() {
    assert_runs_and_matches_oracle("json_dec_fail");
}

// ── oneOf ────────────────────────────────────────────────────────────────────

/// `oneOf [map fromInt int, string]` on `42` → `"42"`, on `"hello"` → `"hello"`.
/// Output: `"42 hello"`.
#[test]
fn json_dec_one_of() {
    assert_runs_and_matches_oracle("json_dec_one_of");
}

// ── pipeline ─────────────────────────────────────────────────────────────────

/// `succeed makePerson |> required "name" string |> required "age" int |>
/// optional "nickname" string "unknown"`.  First JSON has no nickname;
/// second has `"Bobby"`.
/// Output:
/// ```text
/// Alice|30|unknown
/// Bob|25|Bobby
/// ```
#[test]
fn json_dec_pipeline() {
    assert_runs_and_matches_oracle("json_dec_pipeline");
}

// ── Fix A: lambda curry ───────────────────────────────────────────────────────

/// `succeed (\name age -> name ++ "|" ++ fromInt age)` — 2-arg lambda passed
/// to `succeed`; the emitter wraps it in `curry2(move |name, age| ...)` and
/// feeds the result to `decode_succeed`.
/// Output: `"Alice|30"`.
#[test]
fn json_dec_pipeline_lambda() {
    assert_runs_and_matches_oracle("json_dec_pipeline_lambda");
}

/// `succeed (\name -> name ++ "!")` — 1-arg lambda; emits `curry1(move |name| ...)`.
/// Output: `"Alice!"`.
#[test]
fn json_dec_pipeline_lambda1() {
    assert_runs_and_matches_oracle("json_dec_pipeline_lambda1");
}

// ── Fix A: plain-value factory-wrap ──────────────────────────────────────────

/// `succeed 42` — plain integer value; the emitter factory-wraps it as
/// `decode_succeed({ let __ipe_succeed = 42; Box::new(move || __ipe_succeed.clone()) })`.
/// Output: `"42"`.
#[test]
fn json_dec_succeed_value() {
    assert_runs_and_matches_oracle("json_dec_succeed_value");
}

// ── Fix C: thunk-rewrite for let-bound decoder reuse ─────────────────────────

/// A `let d = ...` decoder used twice in the same scope — Fix C wraps it in a
/// zero-arg lambda so each `decodeString d` call gets a fresh `Decoder` value
/// rather than double-moving out of the binding.
/// Output:
/// ```text
/// Alice|30
/// Bob|25
/// ```
#[test]
fn json_dec_pipeline_reuse() {
    assert_runs_and_matches_oracle("json_dec_pipeline_reuse");
}

/// `let d = JsonDec.int` reused inside `JsonDec.list d` — Fix C × list factory.
/// Output: `"2"`.
#[test]
fn json_dec_list_letbound() {
    assert_runs_and_matches_oracle("json_dec_list_letbound");
}

// ── R9: named-function FuncValue control ─────────────────────────────────────

/// `succeed makeProfile |> required "username" string |> optional "followers" int 0`.
/// Named `makeProfile` function is a `FuncValue` — the pre-existing passing
/// shape; confirms Fix A case 1 is not regressed.
/// Output: `"ipedev 0"`.
#[test]
fn json_dec_pipeline_record() {
    assert_runs_and_matches_oracle("json_dec_pipeline_record");
}
