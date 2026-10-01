//! THE SEAL for an app entry built inside an UNANNOTATED definition whose
//! parameter the entry's model is read through.
//!
//! `mk m = Web.embed { init = \_ -> ( m, Cmd.none ), … }` with a `view` that
//! reads `model.count`. An unannotated binding never generalizes a record row,
//! so `m` is pinned to the use site's `Model`. Each fixture must land on
//! exactly one of the two sound outcomes:
//!
//! - refused by `ipe` with IPE-N0051 (the entry's model or message is still a
//!   type variable), or
//! - accepted, and then — under `IPE_E2E` — the emitted crate `cargo build`s.
//!
//! Any other diagnostic, or an accept whose crate fails cargo, fails the test.
//! The unpinned-message fixture's `update` ignores its message and its view
//! emits none (`notFound` is the route fallback, not a message), so nothing
//! fixes `msg`; the pinned-message fixture matches on it. The entry is a
//! mounted server app, so the emitted binary listens forever; the positive leg
//! proves the build, not a run.
//!
//! ```text
//! # emit / refusal check only (fast):
//! cargo test -p ipe --test g_issues golden_untyped_app_entry_row
//! # full (cargo build of an accepted program):
//! IPE_E2E=1 cargo test -p ipe --test g_issues golden_untyped_app_entry_row
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
        .join("untyped-app-entry-row")
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
        .join("untyped-app-entry-row-out")
        .join(name);
    let _ = std::fs::remove_dir_all(&out);
    out
}

/// An unannotated `mk` whose `Web.embed` model is the parameter `m`, read
/// through `model.count` in `view`, and whose message type nothing fixes.
const UNTYPED_EMBED_ROW_MODEL: &str = r#"module Main exposing (main)

import Ipe.Server.Http as Server
import Ipe.String as String
import Ipe.Task as Task exposing (Task)
import Ipe.Tea.Web as Web
import Ipe.Tea.Web.Cmd as Cmd
import Ipe.Tea.Web.Sub as Sub
import Ipe.Ui as Ui


type alias Model =
    { count : Int }


type Msg
    = Noop


initialModel : Model
initialModel =
    { count = 0 }


mk m =
    Web.embed
        { init = \_ -> ( m, Cmd.none )
        , update = \_ model -> ( model, Cmd.none )
        , view = \model -> Ui.text (String.fromInt model.count)
        , subscriptions = \_ -> Sub.none
        , routes = []
        , notFound = Noop
        }


main : Task Error ()
main =
    Server.listen 8000 [ Server.mountApp "/" (mk initialModel) ]
"#;

/// [`UNTYPED_EMBED_ROW_MODEL`] with `update` matching on its `Msg`, so the
/// message type is fixed and only the model flows through the parameter.
const UNTYPED_EMBED_ROW_MODEL_PINNED_MSG: &str = r#"module Main exposing (main)

import Ipe.Server.Http as Server
import Ipe.String as String
import Ipe.Task as Task exposing (Task)
import Ipe.Tea.Web as Web
import Ipe.Tea.Web.Cmd as Cmd
import Ipe.Tea.Web.Sub as Sub
import Ipe.Ui as Ui


type alias Model =
    { count : Int }


type Msg
    = Noop


initialModel : Model
initialModel =
    { count = 0 }


mk m =
    Web.embed
        { init = \_ -> ( m, Cmd.none )
        , update =
            \msg model ->
                case msg of
                    Noop ->
                        ( model, Cmd.none )
        , view = \model -> Ui.text (String.fromInt model.count)
        , subscriptions = \_ -> Sub.none
        , routes = []
        , notFound = Noop
        }


main : Task Error ()
main =
    Server.listen 8000 [ Server.mountApp "/" (mk initialModel) ]
"#;

#[test]
fn untyped_embed_row_model_refused_or_builds() {
    let name = "untyped_embed_row_model";
    let (built, out) = build_fixture(name, UNTYPED_EMBED_ROW_MODEL);
    match built {
        Ok(()) => crate::support::assert_seal_builds(name, &out),
        Err(CliError::Pipeline { diag, .. }) => assert_eq!(
            diag.code(),
            ipe_diagnostics::IPE_N0051,
            "{name}: a refusal must be the app-entry IPE-N0051, not another reason"
        ),
        Err(other) => assert!(
            false_marker(),
            "{name}: non-pipeline build error: {other:?}"
        ),
    }
}

/// With its message type fixed nothing is generic, so the entry must be
/// accepted and its crate must `cargo build` (the mounted app's `init` captures
/// `m`).
#[test]
fn untyped_embed_row_model_pinned_msg_builds() {
    let name = "untyped_embed_row_model_pinned_msg";
    let (built, out) = build_fixture(name, UNTYPED_EMBED_ROW_MODEL_PINNED_MSG);
    match built {
        Ok(()) => crate::support::assert_seal_builds(name, &out),
        Err(err) => assert!(
            false_marker(),
            "{name}: a fully concrete app entry must be accepted, got: {err:?}"
        ),
    }
}

/// Build `source` as `name`, returning the build result and its output dir.
#[allow(clippy::panic)] // a refused well-formed program is the test failure
fn build_fixture(name: &str, source: &str) -> (Result<(), CliError>, PathBuf) {
    let Some(entry) = write_single(name, source) else {
        panic!("{name}: could not write the fixture into the scratch dir");
    };
    let out = out_dir(name);
    let runtime = e2e_support::require_runtime().into_path_buf();
    (ipe::build(&entry, &out, &runtime), out)
}
