//! THE SEAL for a callee's runtime bound at a concrete instance.
//!
//! A kernel's runtime function or an emitted user generic may demand a Rust
//! bound (`Clone`, `PartialEq`, `Sync`) its Ipê type scheme does not state:
//! `list_repeat<T: Clone>`, `ident<T1: Clone>`. Instantiating that variable
//! with a type whose carrier lacks the bound (a `Task`, a `Cmd`, a boxed
//! function) would pass `ipe` and fail `cargo build` with E0277. Every such
//! instance is refused at `ipe` time with IPE-L0164; the comparison case
//! (`==`, `List.member`) is refused by the type checker's `Equatable` rule.
//!
//! The refusals run without `IPE_E2E` (no Rust is emitted); the acceptances
//! build and run the emitted crate under `IPE_E2E=1`, so the gate never
//! over-refuses a carrier that is `Clone`.
//!
//! ```text
//! cargo test -p ipe --test g_issues golden_list_repeat_clone_seal
//! IPE_E2E=1 cargo test -p ipe --test g_issues golden_list_repeat_clone_seal
//! ```

use std::path::PathBuf;

use ipe::CliError;

/// A runtime `false` the optimiser cannot fold, for a deliberate failure.
const fn false_marker() -> bool {
    std::hint::black_box(false)
}

/// The scratch output dir for `name`, cleared.
fn out_dir(name: &str) -> PathBuf {
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("l0164-out")
        .join(name);
    e2e_support::scratch::fresh(&out);
    out
}

/// Assert `source` is refused by `ipe` with `expected`, before any Rust is emitted.
#[track_caller]
fn assert_rejected(name: &str, source: &str, expected: ipe_diagnostics::Code) {
    let fixture = crate::root_fixture::main(source);
    let out = out_dir(name);
    let runtime = e2e_support::require_runtime().into_path_buf();
    match crate::root_fixture::build(&fixture, &out, &runtime) {
        Err(CliError::Pipeline { diag, .. }) => assert_eq!(
            diag.code(),
            expected,
            "{name}: expected a fail-closed {expected:?}, got a different diagnostic"
        ),
        Ok(()) => assert!(
            false_marker(),
            "{name}: ipe ACCEPTED a callee instance whose runtime bound is unmet \
             (exit 0); the emitted crate fails cargo with E0277, a SEAL break"
        ),
        Err(other) => assert!(
            false_marker(),
            "{name}: non-pipeline build error: {other:?}"
        ),
    }
}

/// Assert `source` is refused with IPE-L0164.
#[track_caller]
fn assert_l0164(name: &str, source: &str) {
    assert_rejected(name, source, ipe_diagnostics::IPE_L0164);
}

/// Assert `source` is accepted and, under `IPE_E2E`, builds and prints `expected_stdout`.
#[track_caller]
fn assert_accepted(name: &str, source: &str, expected_stdout: &str) {
    let fixture = crate::root_fixture::main(source);
    let out = out_dir(name);
    let runtime = e2e_support::require_runtime().into_path_buf();
    match crate::root_fixture::build(&fixture, &out, &runtime) {
        Ok(()) => {}
        Err(CliError::Pipeline { diag, .. }) => {
            assert!(
                false_marker(),
                "{name}: ipe REJECTED a well-formed program with {}, a false refusal",
                diag.code().as_str()
            );
            return;
        }
        Err(other) => {
            assert!(
                false_marker(),
                "{name}: non-pipeline build error: {other:?}"
            );
            return;
        }
    }
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let outcome = crate::support::build_and_run_emitted(name, &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "{name}: emitted crate must run to exit 0"
    );
    assert_eq!(
        outcome.stdout.trim_end(),
        expected_stdout,
        "{name}: emitted crate built (SEAL held) but ran to the wrong output"
    );
}

/// The prelude every fixture shares.
const HEAD: &str = "module Main exposing (main)

import Ipe.Dict as Dict
import Ipe.Io as Io
import Ipe.List as List
import Ipe.String as String
import Ipe.Task as Task

";

/// `HEAD` followed by `body`.
fn program(body: &str) -> String {
    format!("{HEAD}{body}")
}

#[test]
fn repeat_task_refused() {
    let src = program(
        "main : Task Error ()
main =
    Task.map (\\_ -> ()) (Task.sequence (List.repeat 3 (Io.println \"x\")))
",
    );
    assert_l0164("repeat_task", &src);
}

#[test]
fn repeat_task_piped_refused() {
    let src = program(
        "main : Task Error ()
main =
    Io.println \"x\"
        |> List.repeat 3
        |> Task.sequence
        |> Task.map (\\_ -> ())
",
    );
    assert_l0164("repeat_task_piped", &src);
}

#[test]
fn repeat_point_free_refused() {
    let src = program(
        "main : Task Error ()
main =
    Io.println (String.fromInt (List.length (List.map (List.repeat 2) [ Io.println \"x\" ])))
",
    );
    assert_l0164("repeat_point_free", &src);
}

#[test]
fn repeat_partial_refused() {
    let src = program(
        "main : Task Error ()
main =
    let
        twice =
            List.repeat 2
    in
    Task.map (\\_ -> ()) (Task.sequence (twice (Io.println \"x\")))
",
    );
    assert_l0164("repeat_partial", &src);
}

#[test]
fn repeat_maybe_task_refused() {
    let src = program(
        "main : Task Error ()
main =
    Io.println (String.fromInt (List.length (List.repeat 2 (Just (Io.println \"x\")))))
",
    );
    assert_l0164("repeat_maybe_task", &src);
}

#[test]
fn repeat_record_holding_task_refused() {
    let src = program(
        "main : Task Error ()
main =
    Io.println (String.fromInt (List.length (List.repeat 2 { run = Io.println \"x\" })))
",
    );
    assert_l0164("repeat_record_holding_task", &src);
}

#[test]
fn dict_get_task_value_refused() {
    let src = program(
        "main : Task Error ()
main =
    case Dict.get \"k\" (Dict.fromList [ ( \"k\", Io.println \"x\" ) ]) of
        Just t ->
            t

        Nothing ->
            Io.println \"none\"
",
    );
    assert_l0164("dict_get_task_value", &src);
}

#[test]
fn list_filter_task_refused() {
    let src = program(
        "main : Task Error ()
main =
    Task.map (\\_ -> ()) (Task.sequence (List.filter (\\_ -> True) [ Io.println \"x\" ]))
",
    );
    assert_l0164("list_filter_task", &src);
}

#[test]
fn random_shuffle_task_refused() {
    let src = program(
        "import Ipe.Random as Random


main : Task Error ()
main =
    Random.shuffle [ Io.println \"x\" ]
        |> Task.andThen Task.sequence
        |> Task.map (\\_ -> ())
",
    );
    assert_l0164("random_shuffle_task", &src);
}

/// A Web TEA app publishing a `Task` payload: `Cmd.publish` clones the payload per subscriber.
const CMD_PUBLISH_TASK: &str = "module Main exposing (main)

import Ipe.PubSub as PubSub
import Ipe.Task as Task
import Ipe.Tea.Web as Web
import Ipe.Tea.Web.Cmd as Cmd
import Ipe.Tea.Web.Sub as Sub
import Ipe.Ui as Ui


type Msg
    = Publish
    | Ignored


type alias Model =
    {}


topic =
    PubSub.topic \"seal-task\"


init _req =
    ( {}, Cmd.none )


update msg model =
    case msg of
        Publish ->
            ( model, Cmd.publish topic (Task.succeed 1) )

        Ignored ->
            ( model, Cmd.none )


subscriptions _model =
    Sub.none


view _model =
    Ui.html (Ui.layout [] (Ui.text \"ok\"))


main =
    Web.tea
        { init = init
        , update = update
        , view = view
        , subscriptions = subscriptions
        , routes = []
        , notFound = Ignored
        }
";

#[test]
fn cmd_publish_task_payload_refused() {
    assert_l0164("cmd_publish_task_payload", CMD_PUBLISH_TASK);
}

#[test]
fn user_generic_task_instance_refused() {
    let src = program(
        "ident : a -> a
ident x =
    x


main : Task Error ()
main =
    ident (Io.println \"x\")
",
    );
    assert_l0164("user_generic_task_instance", &src);
}

#[test]
fn user_generic_forwarded_then_concrete_refused() {
    let src = program(
        "ident : a -> a
ident x =
    x


wrap : a -> a
wrap x =
    ident x


main : Task Error ()
main =
    wrap (Io.println \"x\")
",
    );
    assert_l0164("user_generic_forwarded_then_concrete", &src);
}

#[test]
fn task_equality_refused() {
    let src = program(
        "main : Task Error ()
main =
    if Io.println \"x\" == Io.println \"y\" then
        Io.println \"same\"

    else
        Io.println \"different\"
",
    );
    assert_rejected("task_equality", &src, ipe_diagnostics::IPE_T0014);
}

#[test]
fn list_member_task_refused() {
    let src = program(
        "main : Task Error ()
main =
    if List.member (Io.println \"x\") [ Io.println \"y\" ] then
        Io.println \"member\"

    else
        Io.println \"absent\"
",
    );
    assert_rejected("list_member_task", &src, ipe_diagnostics::IPE_T0014);
}

#[test]
fn repeat_int_builds() {
    let src = program(
        "main : Task Error ()
main =
    Io.println (String.fromInt (List.sum (List.repeat 3 2)))
",
    );
    assert_accepted("repeat_int", &src, "6");
}

#[test]
fn repeat_fn_element_builds() {
    let src = program(
        "main : Task Error ()
main =
    Io.println (String.fromInt (List.sum (List.map (\\f -> f 1) (List.repeat 2 (\\x -> x + 1)))))
",
    );
    assert_accepted("repeat_fn_element", &src, "4");
}

#[test]
fn user_generic_concrete_instances_build() {
    let src = program(
        "ident : a -> a
ident x =
    x


main : Task Error ()
main =
    Io.println (String.fromInt (ident 3) ++ ident \"x\")
",
    );
    assert_accepted("user_generic_concrete_instances", &src, "3x");
}

#[test]
fn mapper_rewrite_builds() {
    let src = program(
        "main : Task Error ()
main =
    Task.map (\\_ -> ()) (Task.sequence (List.map (\\_ -> Io.println \"x\") (List.repeat 3 ())))
",
    );
    assert_accepted("mapper_rewrite", &src, "x\nx\nx");
}

#[test]
fn repeat_every_clone_carrier_builds() {
    let src = program(
        "okOne : Result String Int
okOne =
    Ok 1


type Shade
    = Light
    | Dark Int


main : Task Error ()
main =
    let
        lengths =
            [ List.length (List.repeat 2 1)
            , List.length (List.repeat 2 1.5)
            , List.length (List.repeat 2 True)
            , List.length (List.repeat 2 \"s\")
            , List.length (List.repeat 2 'c')
            , List.length (List.repeat 2 ())
            , List.length (List.repeat 2 (Just 1))
            , List.length (List.repeat 2 okOne)
            , List.length (List.repeat 2 [ 1 ])
            , List.length (List.repeat 2 ( 1, \"t\" ))
            , List.length (List.repeat 2 { n = 1 })
            , List.length (List.repeat 2 (Dark 1))
            , List.length (List.repeat 2 Light)
            , List.length (List.repeat 2 (Dict.fromList [ ( \"k\", 1 ) ]))
            ]
    in
    Io.println (String.fromInt (List.sum lengths))
",
    );
    assert_accepted("repeat_every_clone_carrier", &src, "28");
}
