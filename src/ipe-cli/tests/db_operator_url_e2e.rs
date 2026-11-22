//! The operator database URL, end to end through a built program.
//!
//! `Db.connect` reads `DATABASE_URL`, then the `Db.url` setting, then opens a
//! runtime-authored default. An unset URL warns once and creates `ipe.db` in
//! the working directory; a set-but-bad URL refuses a server start before it
//! binds, and the refusal never echoes the value. A `Db.open`-only program
//! never reads `DATABASE_URL` at all.
//!
//! Gated on `IPE_E2E=1`, like every test that builds an emitted project.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Shared error type for the test helpers.
type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// The variable the runtime reads the operator URL from.
const DATABASE_URL: &str = "DATABASE_URL";

/// The warning's fixed opening, as the runtime log tags it.
const WARNING: &str = "[ipe.db] warning: DATABASE_URL is not set";

/// A malformed URL carrying a credential the refusal must never echo.
const CREDENTIAL_URL: &str = "postgres://u:hunter2@dbhost:99999/db";

/// The credential inside [`CREDENTIAL_URL`].
const CREDENTIAL: &str = "hunter2";

/// A script that opens the operator store twice.
const CONNECT_TWICE_PROGRAM: &str = r#"module Main exposing (main)

import Ipe.Db as Db
import Ipe.Io as Io
import Ipe.Task as Task

main =
    Task.andThen
        (\_ -> Task.andThen (\_ -> Io.println "connected twice") (Db.connect ()))
        (Db.connect ())
"#;

/// A server whose every request opens the operator store.
const SERVER_CONNECT_PROGRAM: &str = r#"module Main exposing (main)

import Ipe.Db as Db
import Ipe.Http.Server as Server
import Ipe.Maybe
import Ipe.String
import Ipe.System
import Ipe.Task as Task

main =
    let port = Maybe.withDefault 8080 (String.toInt (System.getenvOr "IPE_SERVER_PORT" "8080"))
    in
    Server.listen port
        [ Server.get "/" (\req -> Task.map (\_ -> Server.text "ok") (Db.connect ()))
        ]
"#;

/// A server that only opens an explicit in-memory store.
const SERVER_OPEN_ONLY_PROGRAM: &str = r#"module Main exposing (main)

import Ipe.Db as Db
import Ipe.Db.Location as Location
import Ipe.Http.Server as Server
import Ipe.Maybe
import Ipe.String
import Ipe.System
import Ipe.Task as Task

main =
    let port = Maybe.withDefault 8080 (String.toInt (System.getenvOr "IPE_SERVER_PORT" "8080"))
    in
    Server.listen port
        [ Server.get "/" (\req -> Task.map (\_ -> Server.text "ok") (Db.open Location.memory))
        ]
"#;

/// A `Web.tea` app whose `init` opens the operator store.
const WEB_CONNECT_PROGRAM: &str = r#"module Main exposing (main)

import Ipe.Db as Db
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
    ( { count = 0 }, Cmd.perform (Db.connect ()) (\_result -> Noop) )

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
    let out_dir = tmp.join(format!("db_operator_url_{test_name}_emitted"));
    e2e_support::scratch::fresh(&out_dir);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let options = ipe::BuildOptions {
        intent: ipe_backend_rust::BuildIntent::Development,
        ..ipe::BuildOptions::from_env()
            .map_err(|e| -> BoxError { format!("{test_name}: emit options refused: {e}").into() })?
    };
    ipe::build_fixture_with_options(&fixture, &out_dir, &runtime, &options)
        .map_err(|e| -> BoxError { format!("{test_name}: ipe dev build failed: {e}").into() })?;
    let exe = e2e_support::build_rust_binary(test_name, &out_dir)
        .map_err(|e| -> BoxError { format!("{test_name}: cargo build failed: {e}").into() })?;
    Ok(exe)
}

/// A fresh, canonical working directory for one run of `test_name`.
///
/// # Errors
///
/// Returns an error when the directory cannot be created or resolved.
fn fresh_cwd(test_name: &str) -> Result<PathBuf, BoxError> {
    let dir =
        PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("db_operator_url_{test_name}_cwd"));
    e2e_support::scratch::fresh(&dir);
    std::fs::create_dir_all(&dir)
        .map_err(|e| -> BoxError { format!("{test_name}: create cwd: {e}").into() })?;
    std::fs::canonicalize(&dir)
        .map_err(|e| -> BoxError { format!("{test_name}: canonicalize cwd: {e}").into() })
}

/// The command for `exe` in `cwd`, with `database_url` set or, when `None`,
/// removed from the inherited environment.
fn command(exe: &Path, cwd: &Path, database_url: Option<&str>) -> Command {
    let mut cmd = Command::new(exe);
    cmd.current_dir(cwd)
        .env("IPE_HTTP_BIND", "127.0.0.1")
        .env("IPE_CONSOLE_EMBED", "off")
        .stdin(Stdio::null());
    match database_url {
        Some(url) => cmd.env(DATABASE_URL, url),
        None => cmd.env_remove(DATABASE_URL),
    };
    cmd
}

/// Run `cmd` to its exit and return its status and stderr; a program still
/// running after the deadline is killed and reported as an error, since a
/// refused start must not wait on a listener.
///
/// # Errors
///
/// Returns an error if the binary cannot be spawned or does not exit in time.
fn run_to_exit(test_name: &str, mut cmd: Command) -> Result<(ExitStatus, String), BoxError> {
    let mut child = cmd
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
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
            return Err(format!("{test_name}: the program kept running instead of exiting").into());
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

/// A running server, killed on drop, whose stderr lines are collected.
struct Server {
    child: Child,
    lines: Arc<Mutex<Vec<String>>>,
    drain: Option<std::thread::JoinHandle<()>>,
}

impl Server {
    /// Kill the server and return every stderr line it wrote.
    fn finish(mut self) -> Vec<String> {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(drain) = self.drain.take() {
            let _ = drain.join();
        }
        self.lines
            .lock()
            .map(|lines| lines.clone())
            .unwrap_or_default()
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// An ephemeral loopback port, free at the moment of the call.
///
/// # Errors
///
/// Returns an error when no port can be bound.
fn free_port() -> Result<u16, BoxError> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}

/// Spawn `cmd` as a server on `port` and wait for its listening line.
///
/// # Errors
///
/// Returns an error when the server cannot spawn or exits before listening.
fn spawn_server(test_name: &str, mut cmd: Command, port: u16) -> Result<Server, BoxError> {
    let mut child = cmd
        .env("IPE_SERVER_PORT", port.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| -> BoxError { format!("{test_name}: cannot spawn: {e}").into() })?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| -> BoxError { format!("{test_name}: no stderr pipe").into() })?;
    let lines = Arc::new(Mutex::new(Vec::new()));
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let sink = Arc::clone(&lines);
    let drain = std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines() {
            let Ok(line) = line else { break };
            if line.contains("listening on") {
                let _ = ready_tx.send(());
            }
            if let Ok(mut lines) = sink.lock() {
                lines.push(line);
            }
        }
    });
    let server = Server {
        child,
        lines,
        drain: Some(drain),
    };
    if ready_rx.recv_timeout(Duration::from_secs(30)).is_err() {
        let lines = server.finish();
        return Err(format!(
            "{test_name}: the server never listened\n--- stderr ---\n{}",
            lines.join("\n")
        )
        .into());
    }
    Ok(server)
}

/// Send `GET /` to the server on `port` and return the raw response.
///
/// # Errors
///
/// Returns an error when the request cannot be sent or read.
fn get_root(port: u16) -> Result<String, BoxError> {
    let mut stream = TcpStream::connect(("127.0.0.1", port))?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response)
}

/// How many lines of `stderr` open the default-store warning.
fn warning_count(stderr: &str) -> usize {
    stderr
        .lines()
        .filter(|line| line.starts_with(WARNING))
        .count()
}

/// T13: an unset `DATABASE_URL` warns once for two `Db.connect` calls, names
/// the absolute `ipe.db` in the working directory, and creates it there.
///
/// # Errors
///
/// Propagates any pipeline, build, or spawn error as a test error.
#[test]
fn db_connect_unset_warns_once_and_creates_cwd_ipe_db() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }
    let test_name = "db_connect_unset_warns_once_and_creates_cwd_ipe_db";
    let exe = compile_and_build(test_name, CONNECT_TWICE_PROGRAM)?;
    let cwd = fresh_cwd(test_name)?;
    let (status, stderr) = run_to_exit(test_name, command(&exe, &cwd, None))?;
    assert!(
        status.success(),
        "{test_name}: must exit 0\n--- stderr ---\n{stderr}"
    );
    assert_eq!(
        warning_count(&stderr),
        1,
        "{test_name}: exactly one warning for two connects\n--- stderr ---\n{stderr}"
    );
    let store = cwd.join("ipe.db");
    assert!(
        stderr.contains(&format!("{} (created if missing)", store.display())),
        "{test_name}: the warning names the absolute store\n--- stderr ---\n{stderr}"
    );
    assert!(
        store.is_file(),
        "{test_name}: `{}` must exist",
        store.display()
    );
    Ok(())
}

/// T14: a `Web.tea` app with an empty or a credential-bearing malformed
/// `DATABASE_URL` refuses to start before it binds, naming the variable and
/// never the value.
///
/// # Errors
///
/// Propagates any pipeline, build, or spawn error as a test error.
#[test]
fn web_app_bad_database_url_refuses_to_start() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }
    let test_name = "web_app_bad_database_url_refuses_to_start";
    let exe = compile_and_build(test_name, WEB_CONNECT_PROGRAM)?;
    let cwd = fresh_cwd(test_name)?;
    for url in ["", CREDENTIAL_URL] {
        let port = free_port()?;
        let mut cmd = command(&exe, &cwd, Some(url));
        cmd.env("IPE_WEB_PORT", port.to_string());
        let (status, stderr) = run_to_exit(test_name, cmd)?;
        assert!(
            !status.success(),
            "{test_name}: {url:?} must refuse the start\n--- stderr ---\n{stderr}"
        );
        assert!(
            stderr.contains(DATABASE_URL) && !stderr.contains(CREDENTIAL),
            "{test_name}: the refusal names {DATABASE_URL} and never the value\n--- stderr ---\n{stderr}"
        );
        assert!(
            !stderr.contains("listening on") && TcpStream::connect(("127.0.0.1", port)).is_err(),
            "{test_name}: a refused start never binds\n--- stderr ---\n{stderr}"
        );
        assert!(
            !cwd.join("ipe.db").exists(),
            "{test_name}: a refused URL never falls through to the default store"
        );
    }
    Ok(())
}

/// T15: a server with a malformed `DATABASE_URL` refuses at `Server.listen`
/// before it binds; with the variable unset it starts silently and warns
/// exactly once across two requests that each open the store.
///
/// # Errors
///
/// Propagates any pipeline, build, or spawn error as a test error.
#[test]
fn server_bad_database_url_refuses_and_unset_warns_on_first_connect() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }
    let test_name = "server_bad_database_url_refuses_and_unset_warns_on_first_connect";
    let exe = compile_and_build(test_name, SERVER_CONNECT_PROGRAM)?;
    let cwd = fresh_cwd(test_name)?;

    let port = free_port()?;
    let mut refused = command(&exe, &cwd, Some(CREDENTIAL_URL));
    refused.env("IPE_SERVER_PORT", port.to_string());
    let (status, stderr) = run_to_exit(test_name, refused)?;
    assert!(
        !status.success(),
        "{test_name}: a malformed URL must refuse the start\n--- stderr ---\n{stderr}"
    );
    assert!(
        stderr.contains("Server.listen:")
            && stderr.contains(DATABASE_URL)
            && !stderr.contains(CREDENTIAL),
        "{test_name}: `Server.listen` refuses, naming {DATABASE_URL} and never the value\n\
         --- stderr ---\n{stderr}"
    );
    assert!(
        !stderr.contains("listening on"),
        "{test_name}: a refused start never binds\n--- stderr ---\n{stderr}"
    );

    let port = free_port()?;
    let server = spawn_server(test_name, command(&exe, &cwd, None), port)?;
    let at_start = server
        .lines
        .lock()
        .map(|lines| lines.join("\n"))
        .unwrap_or_default();
    assert_eq!(
        warning_count(&at_start),
        0,
        "{test_name}: the start itself does not warn\n--- stderr ---\n{at_start}"
    );
    for _ in 0..2 {
        let response = get_root(port)?;
        assert!(
            response.contains("ok"),
            "{test_name}: each request answers\n{response}"
        );
    }
    let stderr = server.finish().join("\n");
    assert_eq!(
        warning_count(&stderr),
        1,
        "{test_name}: two connects warn exactly once\n--- stderr ---\n{stderr}"
    );
    Ok(())
}

/// T16: a server that only calls `Db.open` never reads `DATABASE_URL`: a
/// malformed value neither refuses its start nor warns.
///
/// # Errors
///
/// Propagates any pipeline, build, or spawn error as a test error.
#[test]
fn db_open_only_program_ignores_database_url() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }
    let test_name = "db_open_only_program_ignores_database_url";
    let exe = compile_and_build(test_name, SERVER_OPEN_ONLY_PROGRAM)?;
    let cwd = fresh_cwd(test_name)?;
    let port = free_port()?;
    let server = spawn_server(test_name, command(&exe, &cwd, Some("mysql://x")), port)?;
    let response = get_root(port)?;
    let stderr = server.finish().join("\n");
    assert!(
        response.contains("ok"),
        "{test_name}: the request answers\n{response}\n--- stderr ---\n{stderr}"
    );
    assert!(
        !stderr.contains("[ipe.db]") && !stderr.contains(DATABASE_URL),
        "{test_name}: a `Db.open`-only program never judges {DATABASE_URL}\n--- stderr ---\n{stderr}"
    );
    Ok(())
}
