//! A runaway recursion ends as the typed `LimitExceeded` trip, never a
//! foreign-panic record, on both emitted runtime shapes.
//!
//! The tokio shape runs the recursion inside the entry task, so the entry
//! boundary converts the trip into `LimitExceeded` and the program exits 1
//! through the error funnel. The std-only program computes its value while
//! `fn main` builds the entry task, outside the entry catch, so this test pins
//! only what holds there: the classifier names the trip by its type, no
//! foreign-panic record is written, and the exit is a code, not a signal. Its
//! exit code is deliberately left unpinned: the defect is that the emitted
//! entry builds the task before the catch (any shape, the tokio one included,
//! when the work is not deferred behind `Task.andThen`); the required outcome
//! is the tokio shape's `LimitExceeded` and exit 1.
//!
//! Gated on `IPE_E2E=1`; without it the test returns early.

/// Runaway non-tail recursion deferred into the task behind `Task.andThen`.
/// Every `Task` kernel is reactor-requiring, so this emits the tokio entry.
const TOKIO_SHAPE: &str = "module Main exposing (main)
import Ipe.Task as Task
import Ipe.String as String
import Ipe.Io as Io

bounce : Int -> Int
bounce n =
    1 + settle n

settle : Int -> Int
settle n =
    1 + bounce n

main =
    Task.succeed 0
        |> Task.andThen (\\n -> Io.println (String.fromInt (bounce n)))
";

/// The same recursion under only reactor-free kernels: the std-only entry.
const STD_SHAPE: &str = "module Main exposing (main)
import Ipe.String as String
import Ipe.Io as Io

bounce : Int -> Int
bounce n =
    1 + settle n

settle : Int -> Int
settle n =
    1 + bounce n

main =
    Io.println (String.fromInt (bounce 0))
";

/// Build `source` as a one-module project and run it, capturing stderr.
#[allow(clippy::expect_used)] // a fixture that cannot be written must fail the test loudly
fn run_program(name: &str, source: &str) -> crate::support::RunOutcomeWithStderr {
    let fixture = ipe::RootFixture::main(source).expect("the project fixture must be written");
    let out = crate::support::scratch_root().join(format!("ipec_{name}_e2e"));
    let _ = std::fs::remove_dir_all(&out);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build_fixture(&fixture, &out, &runtime);
    assert!(built.is_ok(), "build failed for {name}: {:?}", built.err());
    crate::support::build_and_run_emitted_capturing_stderr(name, &out)
}

/// The trip is named by its type on stderr and never recorded as foreign.
fn assert_classified_trip(name: &str, stderr: &str) {
    assert!(
        stderr.contains("RecursionLimit"),
        "{name}: stderr must name the RecursionLimit trip\n--- stderr ---\n{stderr}"
    );
    assert!(
        stderr.contains("maximum recursion depth exceeded"),
        "{name}: stderr must carry the fixed trip message\n--- stderr ---\n{stderr}"
    );
    assert!(
        !stderr.contains("ForeignPanic"),
        "{name}: a runtime trip is never a foreign-panic record\n--- stderr ---\n{stderr}"
    );
    assert!(
        !stderr.contains("Unexpected:"),
        "{name}: a runtime trip is never an Unexpected error\n--- stderr ---\n{stderr}"
    );
}

/// Runs in the `e2e` CI job (`IPE_E2E=1`).
#[test]
fn deep_recursion_is_typed_on_both_shapes() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let tokio = run_program("deep_recursion_tokio", TOKIO_SHAPE);
    assert_eq!(
        tokio.exit_code,
        Some(1),
        "the entry boundary must end a trip through the error funnel (exit 1)\n\
         --- stderr ---\n{}",
        tokio.stderr
    );
    assert!(
        tokio
            .stderr
            .contains("LimitExceeded: maximum recursion depth exceeded"),
        "the entry boundary must type the trip as LimitExceeded\n--- stderr ---\n{}",
        tokio.stderr
    );
    assert_classified_trip("deep_recursion_tokio", &tokio.stderr);
    assert_eq!(tokio.stdout, "", "no value is printed once the trip fires");

    let std_only = run_program("deep_recursion_std", STD_SHAPE);
    assert!(
        std_only.exit_code.is_some_and(|code| code != 0),
        "a trip must exit with a nonzero CODE, never a signal death; got {:?}\n\
         --- stderr ---\n{}",
        std_only.exit_code,
        std_only.stderr
    );
    assert_classified_trip("deep_recursion_std", &std_only.stderr);
    assert_eq!(
        std_only.stdout, "",
        "no value is printed once the trip fires"
    );
}
