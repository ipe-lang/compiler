//! End-to-end refusal of a malformed operator variable at startup.
//!
//! A built program run with a set port variable that is not a TCP port, or a
//! switch that spells neither on nor off, must exit `1` before it listens, and
//! its stderr must name the variable and the accepted form, so a typo never
//! silently serves on another port or with a security check turned off.
//!
//! Gated on `IPE_E2E=1`, like every test that builds an emitted project.

use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

/// Shared error type for the test helpers.
type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// A server whose port is a literal, so only the operator layer can be wrong.
const SERVER_PROGRAM: &str = r#"module Main exposing (main)

import Ipe.Http.Server as Server
import Ipe.Task

main =
    Server.listen 8000
        [ Server.get "/" (\req -> Task.succeed (Server.text "ok"))
        ]
"#;

/// A minimal `Web.tea` app listening on the default web port.
const WEB_PROGRAM: &str = r#"module Main exposing (main)

import Ipe.Tea.Web as Web
import Ipe.Ui as Ui
import Ipe.Tea.Web.Cmd as Cmd
import Ipe.Tea.Web.Sub as Sub

type Msg
    = Noop

type alias Model =
    { count : Int }

init : WebReq -> ( Model, Cmd Msg )
init _req =
    ( { count = 0 }, Cmd.none )

update : Msg -> Model -> ( Model, Cmd Msg )
update _msg model =
    ( model, Cmd.none )

view : Model -> Element Msg
view _model =
    Ui.text "ok"

subscriptions : Model -> Sub Msg
subscriptions _model =
    Sub.none

main =
    Web.tea
        { init = init
        , update = update
        , view = view
        , subscriptions = subscriptions
        , routes = []
        , notFound = Noop
        }
"#;

/// Compile `ipe_source` as `ipe dev build` does, build the emitted project, and
/// return the binary.
///
/// # Errors
///
/// Returns an error on any pipeline or Cargo build failure.
fn compile_and_build(
    test_name: &str,
    ipe_source: &str,
) -> Result<e2e_support::SharedBuild, BoxError> {
    let tmp = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let fixture = ipe::RootFixture::main(ipe_source)
        .map_err(|e| -> BoxError { format!("{test_name}: fixture: {e}").into() })?;

    let out_dir = tmp.join(format!("env_startup_refusal_{test_name}_emitted"));
    let _ = std::fs::remove_dir_all(&out_dir);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let options = ipe::BuildOptions {
        intent: ipe_backend_rust::BuildIntent::Development,
        ..ipe::BuildOptions::from_env()
    };
    ipe::build_fixture_with_options(&fixture, &out_dir, &runtime, &options)
        .map_err(|e| -> BoxError { format!("{test_name}: ipe dev build failed: {e}").into() })?;
    let exe = e2e_support::build_rust_binary(test_name, &out_dir)
        .map_err(|e| -> BoxError { format!("{test_name}: cargo build failed: {e}").into() })?;
    Ok(exe)
}

/// Run `exe` with `env` set and return its exit status and stderr; a program
/// still running after the deadline is killed and reported as an error, since
/// a refused start must not wait on a listener.
///
/// # Errors
///
/// Returns an error if the binary cannot be spawned or does not exit in time.
fn run_to_exit(
    test_name: &str,
    exe: &std::path::Path,
    env: &[(&str, &str)],
) -> Result<(ExitStatus, String), BoxError> {
    let mut cmd = Command::new(exe);
    cmd.env("IPE_HTTP_BIND", "127.0.0.1")
        .env("IPE_CONSOLE_EMBED", "off")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    for (key, value) in env {
        cmd.env(key, value);
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| -> BoxError { format!("{test_name}: cannot spawn: {e}").into() })?;
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|e| -> BoxError { format!("{test_name}: cannot wait: {e}").into() })?
        {
            break status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(
                format!("{test_name}: the program kept running instead of refusing").into(),
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        pipe.read_to_string(&mut stderr)
            .map_err(|e| -> BoxError { format!("{test_name}: cannot read stderr: {e}").into() })?;
    }
    Ok((status, stderr))
}

/// The prefixes the listener's own at-use refusal carries. The startup check
/// refuses before the program's first line, so its refusal carries neither; a
/// start that reached the listener first was not refused at startup.
const LISTEN_TIME_PREFIXES: &[&str] = &["Server.listen:", "Web.tea:"];

/// The accepted form a refused port variable's stderr names.
const PORT_FORM: &str = "1..=65535";

/// The accepted form a refused switch variable's stderr names.
const FLAG_FORM: &str = "one of 1, true, on, 0, false, off";

/// Assert a refused start: exit `1`, stderr naming `var` and its accepted
/// `form`, written by the startup check rather than the listener, and no
/// listening line.
fn assert_refused(test_name: &str, var: &str, form: &str, status: ExitStatus, stderr: &str) {
    assert_eq!(
        status.code(),
        Some(1),
        "{test_name}: a malformed {var} must exit 1\n--- stderr ---\n{stderr}"
    );
    assert!(
        stderr.contains(var) && stderr.contains(form),
        "{test_name}: stderr must name {var} and {form}\n--- stderr ---\n{stderr}"
    );
    assert!(
        !LISTEN_TIME_PREFIXES
            .iter()
            .any(|prefix| stderr.contains(prefix)),
        "{test_name}: {var} must be refused by the startup check, not at the listener\n\
         --- stderr ---\n{stderr}"
    );
    assert!(
        !stderr.contains("listening on"),
        "{test_name}: a refused start must never listen\n--- stderr ---\n{stderr}"
    );
}

/// A server run with `IPE_SERVER_PORT=99999` refuses to start.
///
/// # Errors
///
/// Propagates any pipeline, build, or spawn error as a test error.
#[test]
fn malformed_server_port_refuses_the_start() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }
    let test_name = "malformed_server_port_refuses_the_start";
    let exe = compile_and_build(test_name, SERVER_PROGRAM)?;
    let (status, stderr) = run_to_exit(test_name, &exe, &[("IPE_SERVER_PORT", "99999")])?;
    assert_refused(test_name, "IPE_SERVER_PORT", PORT_FORM, status, &stderr);
    Ok(())
}

/// A `Web.tea` app run with `IPE_WEB_PORT=abc` refuses to start.
///
/// # Errors
///
/// Propagates any pipeline, build, or spawn error as a test error.
#[test]
fn malformed_web_port_refuses_the_start() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }
    let test_name = "malformed_web_port_refuses_the_start";
    let exe = compile_and_build(test_name, WEB_PROGRAM)?;
    let (status, stderr) = run_to_exit(test_name, &exe, &[("IPE_WEB_PORT", "abc")])?;
    assert_refused(test_name, "IPE_WEB_PORT", PORT_FORM, status, &stderr);
    Ok(())
}

/// A `Web.tea` app run with `IPE_WEB_CSRF_ORIGIN_CHECK=maybe` refuses to start,
/// never reading the unknown spelling as off.
///
/// # Errors
///
/// Propagates any pipeline, build, or spawn error as a test error.
#[test]
fn malformed_csrf_origin_check_refuses_the_start() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }
    let test_name = "malformed_csrf_origin_check_refuses_the_start";
    let exe = compile_and_build(test_name, WEB_PROGRAM)?;
    let (status, stderr) = run_to_exit(test_name, &exe, &[("IPE_WEB_CSRF_ORIGIN_CHECK", "maybe")])?;
    assert_refused(
        test_name,
        "IPE_WEB_CSRF_ORIGIN_CHECK",
        FLAG_FORM,
        status,
        &stderr,
    );
    Ok(())
}
