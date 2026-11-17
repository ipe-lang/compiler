//! A runaway recursion ends as the typed `LimitExceeded` trip and exit 1, never
//! a foreign-panic record, on every emitted entry.
//!
//! The emitted `fn main` hands `ipe_main` to the entry unbuilt, so a value
//! `main` computes eagerly while it builds its task (or its shape-app leaf) is
//! computed inside the entry catch, the same as work deferred into the task
//! behind `Task.andThen`. Each fixture pins that on one entry: the tokio entry
//! with deferred and with eager work, the std-only entry, and a `Cli.tea`
//! shape app whose `main` trips before the leaf exists.
//!
//! Gated on `IPE_E2E=1`; without it the test returns early.

/// Runaway non-tail recursion deferred into the task behind `Task.andThen`.
/// Every `Task` kernel is reactor-requiring, so this emits the tokio entry.
const TOKIO_DEFERRED: &str = "module Main exposing (main)
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

/// The same recursion computed while `main` builds its task, under the tokio
/// entry: `bounce 0` is the argument of `Task.succeed`, evaluated eagerly.
const TOKIO_EAGER: &str = "module Main exposing (main)
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
    Task.succeed (bounce 0)
        |> Task.andThen (\\n -> Io.println (String.fromInt n))
";

/// The same recursion under only reactor-free kernels: the std-only entry,
/// computed while `main` builds its task.
const STD_EAGER: &str = "module Main exposing (main)
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

/// A `Cli.tea` shape app whose `main` computes the recursion before it builds
/// the `CliApp` leaf: the trip fires while `ipe_main` runs, before any leaf.
const CLI_TEA_EAGER: &str = "module Main exposing (main)
import Ipe.Tea.Cli as Cli
import Ipe.Ui.Cli as Ui
import Ipe.Tea.Terminal.Cmd
import Ipe.Tea.Cli.Sub

type Msg = Line String

type alias Model = { count : Int }

bounce : Int -> Int
bounce n =
    1 + settle n

settle : Int -> Int
settle n =
    1 + bounce n

update msg model =
    case msg of
        Line _ ->
            ( { model | count = model.count + 1 }, Cmd.none )

view _model =
    Ui.text \"ok\"

subscriptions _model =
    Sub.onLine onLine

onLine s =
    Line s

main =
    let
        start =
            bounce 0
    in
    Cli.tea
        { init = \\_ -> ( { count = start }, Cmd.none )
        , update = update
        , view = view
        , subscriptions = subscriptions
        }
";

/// Build `source` as a one-module project and run it, capturing stderr.
#[allow(clippy::expect_used)] // a fixture that cannot be written must fail the test loudly
fn run_program(name: &str, source: &str) -> crate::support::RunOutcomeWithStderr {
    let fixture = ipe::RootFixture::main(source).expect("the project fixture must be written");
    let out = crate::support::scratch_root().join(format!("ipec_{name}_e2e"));
    e2e_support::scratch::fresh(&out);
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

/// The entry types the trip as `LimitExceeded` and ends through the error
/// funnel with exit 1, printing nothing to stdout.
fn assert_typed_limit_exit(name: &str, source: &str) {
    let run = run_program(name, source);
    assert_eq!(
        run.exit_code,
        Some(1),
        "{name}: the entry must end a trip through the error funnel (exit 1)\n\
         --- stderr ---\n{}",
        run.stderr
    );
    assert!(
        run.stderr
            .contains("LimitExceeded: maximum recursion depth exceeded"),
        "{name}: the entry must type the trip as LimitExceeded\n--- stderr ---\n{}",
        run.stderr
    );
    assert_classified_trip(name, &run.stderr);
    assert_eq!(
        run.stdout, "",
        "{name}: no value is printed once the trip fires"
    );
}

/// Runs in the `e2e` CI job (`IPE_E2E=1`).
#[test]
fn deep_recursion_is_typed_on_every_entry() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    assert_typed_limit_exit("deep_recursion_tokio", TOKIO_DEFERRED);
    assert_typed_limit_exit("deep_recursion_tokio_eager", TOKIO_EAGER);
    assert_typed_limit_exit("deep_recursion_std", STD_EAGER);
    assert_typed_limit_exit("deep_recursion_cli_tea", CLI_TEA_EAGER);
}
