//! THE SEAL for a container-first TEA kernel whose function argument captures
//! a binding the effect expression also consumes by value.
//!
//! `Task.attempt f t`, `Cmd.map f c` and `Sub.map f s` render effect-first in
//! the runtime (`cmd_perform(t, f)`, `cmd_map(c, f)`, `sub_map(s, f)`). Rust
//! evaluates arguments left-to-right, so the effect runs BEFORE `f`'s closure
//! is built: a non-Copy `label` the effect moves (`loadLabel label`) is gone
//! when the closure's `let label = label.clone()` capture reads it — `ipe
//! dev build` exit 0, then `cargo build` E0382. Each is declared
//! `ArgOrder::ContainerFirst`, so the lowerer's last-use clone rewrite walks it
//! in evaluation order and clones the effect's read.
//!
//! | Kernel | Shape |
//! |---|---|
//! | `Task.attempt` | `Task.attempt (\r -> Loaded label r) (loadLabel label)` |
//! | `Cmd.map` | `Cmd.map (\c -> FromChild label c) (childCmd label)` |
//! | `Sub.map` | `Sub.map (\c -> FromChild label c) (childSub label)` |
//!
//! ```text
//! # emit check only (fast):
//! cargo test -p ipe --test g_issues golden_swapped_effect_capture
//! # full (cargo build):
//! IPE_E2E=1 cargo test -p ipe --test g_issues golden_swapped_effect_capture
//! ```

use std::path::PathBuf;

use ipe::CliError;

/// A runtime `false` the optimiser cannot fold, so `assert!(false_marker(), …)`
/// reads as a deliberate unconditional failure rather than a suspicious constant
/// condition.
const fn false_marker() -> bool {
    std::hint::black_box(false)
}

/// Write `source` as a single-file `Main.ipe` under a fresh scratch dir keyed by
/// `name`, returning the entry path (or `None` if scratch setup fails).
fn write_single(name: &str, source: &str) -> Option<PathBuf> {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("swapped-effect-capture")
        .join(name);
    let _ = std::fs::remove_dir_all(&dir);
    let src = dir.join("src");
    std::fs::create_dir_all(&src).ok()?;
    let entry = src.join("Main.ipe");
    std::fs::write(&entry, source).ok()?;
    Some(entry)
}

/// The scratch output dir for `name`, cleared.
fn out_dir(name: &str) -> PathBuf {
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("swapped-effect-capture-out")
        .join(name);
    let _ = std::fs::remove_dir_all(&out);
    out
}

/// Assert that `source` is ACCEPTED by `ipe` (exit 0) and — under `IPE_E2E` —
/// that the emitted crate `cargo build`s.
#[track_caller]
fn assert_accepted(name: &str, source: &str) {
    let Some(entry) = write_single(name, source) else {
        assert!(
            false_marker(),
            "{name}: could not write the fixture into the scratch dir"
        );
        return;
    };
    let out = out_dir(name);
    let runtime = e2e_support::require_runtime().into_path_buf();
    match ipe::build(&entry, &out, &runtime) {
        Ok(()) => crate::support::assert_seal_builds(name, &out),
        Err(CliError::Pipeline { diag, .. }) => assert!(
            false_marker(),
            "{name}: ipe REJECTED a well-formed program with {}",
            diag.code().as_str()
        ),
        Err(other) => assert!(
            false_marker(),
            "{name}: non-pipeline build error: {other:?}"
        ),
    }
}

/// A `Cli.tea` app whose `init` and `subscriptions` attempt and retag effects
/// through functions capturing the `String` the effect expression moves.
const SWAPPED_EFFECT_CAPTURE: &str = r#"module Main exposing (main)

import Ipe.String as String
import Ipe.Task as Task
import Ipe.Tea.Cli as Cli
import Ipe.Tea.Terminal.Cmd
import Ipe.Tea.Cli.Sub
import Ipe.Ui.Cli as Ui
import Ipe.Ui.Cli exposing (Lines)


type ChildMsg
    = ChildLoaded (Result Error String)


type Msg
    = Loaded String (Result Error String)
    | FromChild String ChildMsg
    | GotLine String


type alias Model =
    { attempted : String, mapped : String }


loadLabel : String -> Task Error String
loadLabel s =
    Task.succeed s


childCmd : String -> Cmd ChildMsg
childCmd s =
    Task.attempt ChildLoaded (loadLabel s)


childSub : String -> Sub ChildMsg
childSub _s =
    Sub.none


attemptWith : String -> Cmd Msg
attemptWith label =
    Task.attempt (\r -> Loaded label r) (loadLabel label)


mapWith : String -> Cmd Msg
mapWith label =
    Cmd.map (\c -> FromChild label c) (childCmd label)


subWith : String -> Sub Msg
subWith label =
    Sub.map (\c -> FromChild label c) (childSub label)


init : () -> ( Model, Cmd Msg )
init _unit =
    ( { attempted = "", mapped = "" }, Cmd.batch [ attemptWith "a", mapWith "m" ] )


update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    case msg of
        Loaded tag result ->
            case result of
                Ok v ->
                    ( { model | attempted = tag ++ v }, Cmd.none )

                Err _ ->
                    ( model, Cmd.none )

        FromChild tag child ->
            case child of
                ChildLoaded result ->
                    case result of
                        Ok v ->
                            ( { model | mapped = tag ++ v }, Cmd.none )

                        Err _ ->
                            ( model, Cmd.none )

        GotLine _line ->
            ( model, Cmd.none )


view : Model -> Lines Msg
view model =
    Ui.text ("attempted: " ++ model.attempted ++ " mapped: " ++ model.mapped)


subscriptions : Model -> Sub Msg
subscriptions _model =
    Sub.batch [ subWith "s", Sub.onLine onLine ]


onLine : String -> Msg
onLine line =
    GotLine line


main =
    Cli.tea
        { init = init
        , update = update
        , view = view
        , subscriptions = subscriptions
        }
"#;

#[test]
fn swapped_effect_capture_builds() {
    assert_accepted("swapped_effect_capture", SWAPPED_EFFECT_CAPTURE);
}
