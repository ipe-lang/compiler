//! THE SEAL for user enums whose variant payloads hold a `Box`-carried function.
//!
//! A function directly in a constructor payload is stored on the `Clone`
//! `Arc<dyn Fn>` carrier, so its enum is `Clone` and reuse is sound. A function
//! under a `Maybe` payload stays on the non-`Clone` `Box` carrier (the
//! `Maybe` kernels consume it as an owned `FnOnce`), so the enum gets no
//! `Clone` impl. The fn-value reuse gate must see that function through the
//! enum's variant payloads: reusing such a value fails closed at `ipe` time
//! instead of reaching `cargo build` as a use-after-move.
//!
//! | Test | Shape | Outcome |
//! |---|---|---|
//! | `boxed_fn_payload_enum_reuse_fails_closed` | `H (Maybe (Int -> Int))` param reused | IPE-L0127 |
//! | `boxed_fn_payload_enum_linear_builds` | same enum used once | builds + prints `42` |
//! | `shared_fn_payload_enum_reuse_builds` | `G (Int -> Int)` param reused | builds + prints `30` |
//! | `enum_recursive_through_a_task_builds` | `Next Int (Task Error Stream)` param | builds + prints `7` |
//! | `enums_mutually_recursive_through_tasks_build` | `Ping` / `Pong` through `Task` | builds + prints `3` |
//!
//! ```text
//! cargo test -p ipe --test g_misc golden_enum_fn_payload_reuse_seal
//! IPE_E2E=1 cargo test -p ipe --test g_misc golden_enum_fn_payload_reuse_seal
//! ```

use std::path::{Path, PathBuf};

use ipe::CliError;

/// A runtime `false` the optimiser cannot fold — a deliberate failure marker.
const fn false_marker() -> bool {
    std::hint::black_box(false)
}

/// Write `source` as a single-file `Main.ipe` under a fresh scratch dir keyed by
/// `name`, returning the entry path; a failed scratch setup fails the test.
fn write_single(name: &str, source: &str) -> PathBuf {
    let dir = crate::support::scratch_root()
        .join("ipec_enum_fn_payload_reuse")
        .join(name);
    let _ = std::fs::remove_dir_all(&dir);
    let src = dir.join("src");
    let entry = src.join("Main.ipe");
    let written = std::fs::create_dir_all(&src).and_then(|()| std::fs::write(&entry, source));
    assert!(
        written.is_ok(),
        "{name}: must write the fixture source to a scratch dir: {written:?}"
    );
    entry
}

/// The scratch output dir for `name`, cleared.
fn out_dir(name: &str) -> PathBuf {
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("enum_fn_payload_reuse_out")
        .join(name);
    let _ = std::fs::remove_dir_all(&out);
    out
}

/// Assert `ipe` rejects the build of `entry` with the typed `expected` code.
#[track_caller]
fn assert_rejected(name: &str, entry: &Path, expected: ipe_diagnostics::Code) {
    // A refusal test proves nothing if it skips silently: a missing runtime
    // would let the fail-closed assertion pass without driving the pipeline.
    let runtime = e2e_support::require_runtime().into_path_buf();
    let out = out_dir(name);
    match ipe::build_loose_file(entry, &out, &runtime) {
        Err(CliError::Pipeline { diag, .. }) => assert_eq!(
            diag.code(),
            expected,
            "{name}: expected a fail-closed {expected:?}, got a different diagnostic"
        ),
        Ok(()) => assert!(
            false_marker(),
            "{name}: ipe ACCEPTED a reuse of a non-Clone fn-payload enum (exit 0) — \
             the emitted crate would fail cargo with a use-after-move, a SEAL break"
        ),
        Err(other) => assert!(
            false_marker(),
            "{name}: non-pipeline build error: {other:?}"
        ),
    }
}

/// Build `entry` and return its output dir; an `ipe` refusal fails the test.
#[track_caller]
fn accepted_out(name: &str, entry: &Path) -> PathBuf {
    let runtime = e2e_support::require_runtime().into_path_buf();
    let out = out_dir(name);
    let built = ipe::build_loose_file(entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "{name}: ipe REJECTED a well-formed program — a false rejection: {built:?}"
    );
    out
}

/// Under `IPE_E2E`, `cargo build` + run the crate in `out` and check its stdout.
#[track_caller]
fn assert_runs(name: &str, out: &Path, expected_stdout: &str) {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return; // emit-only fast pass
    }
    let outcome = crate::support::build_and_run_emitted(name, out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "{name}: emitted crate must build and run to exit 0; stdout:\n{}",
        outcome.stdout
    );
    assert_eq!(
        outcome.stdout.trim_end(),
        expected_stdout,
        "{name}: emitted crate built (SEAL held) but ran to the wrong output"
    );
}

/// `H` holds a `Box`-carried function under `Maybe`; `twice` reuses the param.
const BOXED_FN_PAYLOAD_ENUM_REUSE: &str = r#"module Main exposing (main)

import Ipe.Io as Io


type H = H (Maybe (Int -> Int))


twice : H -> ( H, H )
twice h =
    ( h, h )


main =
    Io.println "x"
"#;

/// The same `H` consumed once — a bare move that needs no `Clone`.
const BOXED_FN_PAYLOAD_ENUM_LINEAR: &str = r"module Main exposing (main)

import Ipe.Io as Io
import Ipe.String as String


type H = H (Maybe (Int -> Int))


apply : H -> Int -> Int
apply h x =
    case h of
        H m ->
            case m of
                Just f ->
                    f x

                Nothing ->
                    x


main =
    Io.println (String.fromInt (apply (H (Just (\n -> n + 1))) 41))
";

/// A function directly in the payload rides the `Arc` carrier, so `G` is
/// `Clone` and reusing the param stays accepted.
const SHARED_FN_PAYLOAD_ENUM_REUSE: &str = r"module Main exposing (main)

import Ipe.Io as Io
import Ipe.String as String


type G = G (Int -> Int)


run : G -> Int -> Int
run g x =
    case g of
        G f ->
            f x


both : G -> Int
both g =
    run g 1 + run g 2


main =
    Io.println (String.fromInt (both (G (\n -> n * 10))))
";

/// A type recursive through the value a `Task` yields; classifying the `Stream`
/// parameter walks that cycle and must terminate.
const ENUM_RECURSIVE_THROUGH_A_TASK: &str = r"module Main exposing (main)

import Ipe.Io as Io
import Ipe.String as String


type Stream
    = Next Int (Task Error Stream)
    | End


headOr : Int -> Stream -> Int
headOr fallback s =
    case s of
        Next n _ ->
            n

        End ->
            fallback


main =
    Io.println (String.fromInt (headOr 7 End))
";

/// Two types recursive through each other's `Task` results.
const ENUMS_MUTUALLY_RECURSIVE_THROUGH_TASKS: &str = r"module Main exposing (main)

import Ipe.Io as Io
import Ipe.String as String


type Ping
    = Go (Task Error Pong)
    | Stop Int


type Pong
    = Back Int (Task Error Ping)


pingOr : Int -> Ping -> Int
pingOr fallback p =
    case p of
        Go _ ->
            fallback

        Stop n ->
            n


main =
    Io.println (String.fromInt (pingOr 0 (Stop 3)))
";

#[test]
fn boxed_fn_payload_enum_reuse_fails_closed() {
    let name = "boxed_fn_payload_enum_reuse";
    let entry = write_single(name, BOXED_FN_PAYLOAD_ENUM_REUSE);
    assert_rejected(name, &entry, ipe_diagnostics::IPE_L0127);
}

#[test]
fn boxed_fn_payload_enum_linear_builds() {
    let name = "boxed_fn_payload_enum_linear";
    let entry = write_single(name, BOXED_FN_PAYLOAD_ENUM_LINEAR);
    let out = accepted_out(name, &entry);
    assert_runs(name, &out, "42");
}

#[test]
fn shared_fn_payload_enum_reuse_builds() {
    let name = "shared_fn_payload_enum_reuse";
    let entry = write_single(name, SHARED_FN_PAYLOAD_ENUM_REUSE);
    let out = accepted_out(name, &entry);
    assert_runs(name, &out, "30");
}

#[test]
fn enum_recursive_through_a_task_builds() {
    let name = "enum_recursive_through_a_task";
    let entry = write_single(name, ENUM_RECURSIVE_THROUGH_A_TASK);
    let out = accepted_out(name, &entry);
    assert_runs(name, &out, "7");
}

#[test]
fn enums_mutually_recursive_through_tasks_build() {
    let name = "enums_mutually_recursive_through_tasks";
    let entry = write_single(name, ENUMS_MUTUALLY_RECURSIVE_THROUGH_TASKS);
    let out = accepted_out(name, &entry);
    assert_runs(name, &out, "3");
}
