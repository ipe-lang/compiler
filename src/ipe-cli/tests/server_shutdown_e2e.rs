#![forbid(unsafe_code)]
#![cfg(target_os = "linux")]
//! Served-app shutdown proofs on the real process: its exit status, its stdout
//! and stderr lines, and the database files it leaves behind.
//!
//! Each test compiles an Ipê program, builds the emitted project, runs the
//! binary on a loopback port, signals it with `kill`, and asserts what the
//! process itself did. The first SIGTERM or SIGINT writes exactly one
//! `shutting down` line, drains in-flight work under
//! `IPE_WEB_SHUTDOWN_GRACE_MS`, closes the owned database pools (no `-wal` or
//! `-shm` sidecar is left) and exits 0. A second signal ends the process at
//! once with 143 (SIGTERM) or 130 (SIGINT). A signal that arrives before the
//! listener is armed takes the OS default.
//!
//! Gated on `IPE_E2E=1`; every wait carries an explicit budget.
//!
//! ```text
//! IPE_E2E=1 cargo nextest run -p ipe --test server_shutdown_e2e --profile ci
//! ```

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Budget for a built binary to bind its listener.
const READY_BUDGET: Duration = Duration::from_secs(30);

/// Budget for a signalled process to exit.
const EXIT_BUDGET: Duration = Duration::from_secs(20);

/// Budget for an expected output line after the event that causes it.
const LINE_BUDGET: Duration = Duration::from_secs(10);

/// Budget for any one client read.
const CLIENT_BUDGET: Duration = Duration::from_secs(20);

/// The longest the runtime's stop takes past the grace
/// (`shutdown::POOLS_CLOSE_BOUND`): the 500 ms work-cancel deadline, then one
/// 2 s deadline per close stage, two stages one after another.
const POOLS_CLOSE_BOUND: Duration = Duration::from_millis(4500);

/// The stdout line the first signal writes.
const SHUTDOWN_LINE: &str = "shutting down";

/// The stderr line the second signal writes.
const FORCING_LINE: &str = "forcing exit (second signal)";

/// Env vars that would change a run's posture; cleared on every spawn so a
/// test's posture comes only from its own env.
const POSTURE_ENV: [&str; 4] = [
    "IPE_WEB_SHUTDOWN_GRACE_MS",
    "IPE_WEB_STORE",
    "IPE_WEB_STORE_PATH",
    "IPE_SERVER_PORT",
];

/// An `Http.Server` app over a SQLite file named by `STORE_DB`.
///
/// * `GET /write` creates the table and inserts one row; body `1`.
/// * `GET /slow/:ms` answers `slept` after `ms` milliseconds.
/// * `GET /check` answers the `PRAGMA integrity_check` verdict.
/// * `GET /rows` answers the stored values joined by `;`.
const DB_SERVER: &str = r#"module Main exposing (main)

import Ipe.Db as Db exposing (Db)
import Ipe.Db.Location as Location exposing (Mode(..))
import Ipe.Db.Unsafe as Unsafe
import Ipe.Dict as Dict
import Ipe.Duration as Duration
import Ipe.Error as Error exposing (Error)
import Ipe.Http.Server as Server
import Ipe.Http.Server exposing (Request, Response)
import Ipe.List as List
import Ipe.Maybe as Maybe
import Ipe.Path as Path
import Ipe.Result as Result
import Ipe.String as String
import Ipe.System as System
import Ipe.Task as Task exposing (Task)
import Ipe.Time as Time


connect : Task Error Db
connect =
    Path.fromString (System.getenvOr "STORE_DB" "shutdown-e2e.db")
        |> Result.andThen (Location.file CreateIfMissing)
        |> Task.fromResult
        |> Task.andThen (\location -> Db.open location)


orError : Task Error Response -> Task Error Response
orError task =
    Task.onError
        (\e -> Task.succeed (Server.text (String.concat [ "err:", Error.message e ])))
        task


handleWrite : Request -> Task Error Response
handleWrite _ =
    orError
        (Task.andThen
            (\db ->
                Task.andThen
                    (\_ ->
                        Task.map
                            (\n -> Server.text (String.fromInt n))
                            (Unsafe.unsafeExecRaw db "INSERT INTO t (v) VALUES ('kept')")
                    )
                    (Unsafe.unsafeExecRaw db "CREATE TABLE IF NOT EXISTS t (v TEXT NOT NULL)")
            )
            connect
        )


handleSlow : Request -> Task Error Response
handleSlow req =
    let
        ms =
            Maybe.withDefault 0 (Maybe.andThen String.toInt (Server.param "ms" req))
    in
    Task.map (\_ -> Server.text "slept") (Time.sleep (Duration.millis ms))


column : String -> String -> Task Error Response
column name sql =
    orError
        (Task.andThen
            (\db ->
                Task.map
                    (\rows -> Server.text (String.join ";" (List.map (cellText name) rows)))
                    (Unsafe.unsafeQuery db sql [])
            )
            connect
        )


cellText : String -> Dict.Dict String (Maybe String) -> String
cellText key row =
    case Dict.get key row of
        Just (Just s) ->
            s

        Just Nothing ->
            "NULL"

        Nothing ->
            ""


handleCheck : Request -> Task Error Response
handleCheck _ =
    column "integrity_check" "PRAGMA integrity_check"


handleRows : Request -> Task Error Response
handleRows _ =
    column "v" "SELECT v FROM t ORDER BY v"


main : Task Error ()
main =
    Server.listen
        (Maybe.withDefault 8080 (String.toInt (System.getenvOr "IPE_SERVER_PORT" "8080")))
        [ Server.get "/write" handleWrite
        , Server.get "/slow/:ms" handleSlow
        , Server.get "/check" handleCheck
        , Server.get "/rows" handleRows
        ]
"#;

/// An `Http.Server`-only app: no `Db`, no `Ipe.Web`.
const PLAIN_SERVER: &str = r#"module Main exposing (main)

import Ipe.Http.Server as Server
import Ipe.Maybe
import Ipe.String
import Ipe.System
import Ipe.Task

main =
    let port = Maybe.withDefault 8080 (String.toInt (System.getenvOr "IPE_SERVER_PORT" "8080"))
    in
    Server.listen port
        [ Server.get "/" (\req -> Task.succeed (Server.text "plain")) ]
"#;

/// An `Http.Server` app that sleeps five seconds before it listens.
const SLOW_START: &str = r#"module Main exposing (main)

import Ipe.Duration as Duration
import Ipe.Error exposing (Error)
import Ipe.Http.Server as Server
import Ipe.Maybe as Maybe
import Ipe.String as String
import Ipe.System as System
import Ipe.Task as Task exposing (Task)
import Ipe.Time as Time

main : Task Error ()
main =
    Task.andThen
        (\_ ->
            Server.listen
                (Maybe.withDefault 8080 (String.toInt (System.getenvOr "IPE_SERVER_PORT" "8080")))
                [ Server.get "/" (\req -> Task.succeed (Server.text "late")) ]
        )
        (Time.sleep (Duration.millis 5000))
"#;

/// An `Http.Server` app with one websocket endpoint at `/ws`.
const WS_SERVER: &str = r#"module Main exposing (main)

import Ipe.Error exposing (Error)
import Ipe.Http.Server as Server
import Ipe.Http.Server exposing (Request, Response)
import Ipe.Http.Server.WebSocket as Ws
import Ipe.Maybe as Maybe
import Ipe.String as String
import Ipe.System as System
import Ipe.Task as Task exposing (Task)

handleWs : Request -> Task Error Response
handleWs req =
    Ws.upgrade req Ws.defaultCfg

main : Task Error ()
main =
    Server.listen
        (Maybe.withDefault 8080 (String.toInt (System.getenvOr "IPE_SERVER_PORT" "8080")))
        [ Server.get "/ws" handleWs ]
"#;

/// A `Web.tea` counter app; its page mints the session its SSE stream needs.
const WEB_COUNTER: &str = r"module Main exposing (main)

import Ipe.Tea.Web as Web
import Ipe.Ui as Ui
import Ipe.Tea.Web.Cmd
import Ipe.Tea.Web.Sub
import Ipe.String

type Msg = Increment

type alias Model = { count : Int }

init : WebReq -> ( Model, Cmd Msg )
init _req =
    ( { count = 0 }, Cmd.none )

update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    case msg of
        Increment ->
            ( { model | count = model.count + 1 }, Cmd.none )

subscriptions : Model -> Sub Msg
subscriptions _model =
    Sub.none

view : Model -> Element Msg
view model =
    Ui.el [ Ui.onClick Increment ] (Ui.text (String.fromInt model.count))

main =
    Web.tea
        { init = init
        , update = update
        , view = view
        , subscriptions = subscriptions
        , routes = []
        , notFound = Increment
        }
";

/// A `Web.tea` app whose `init` opens the session-store file through
/// `Ipe.Db`: the `Db` use builds the store's `db` feature in, and the open
/// switches the file to WAL, so the session store's own connections run in WAL
/// and leave a `-wal` behind unless their pool closes.
const WEB_SESSION_DB: &str = r#"module Main exposing (main)

import Ipe.Db as Db
import Ipe.Db.Location as Location exposing (Mode(..))
import Ipe.Error exposing (Error)
import Ipe.Path as Path
import Ipe.Result as Result
import Ipe.String
import Ipe.System as System
import Ipe.Task as Task exposing (Task)
import Ipe.Tea.Web as Web
import Ipe.Tea.Web.Cmd
import Ipe.Tea.Web.Sub
import Ipe.Ui as Ui

type Msg = Increment | Opened (Result Error ())

type alias Model = { count : Int }

openStoreFile : Task Error ()
openStoreFile =
    Path.fromString (System.getenvOr "IPE_WEB_STORE_PATH" "sessions.db")
        |> Result.andThen (Location.file CreateIfMissing)
        |> Task.fromResult
        |> Task.andThen (\location -> Db.open location)
        |> Task.map (\_ -> ())

init : WebReq -> ( Model, Cmd Msg )
init _req =
    ( { count = 0 }, Cmd.perform openStoreFile Opened )

update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    case msg of
        Increment ->
            ( { model | count = model.count + 1 }, Cmd.none )

        Opened _result ->
            ( model, Cmd.none )

subscriptions : Model -> Sub Msg
subscriptions _model =
    Sub.none

view : Model -> Element Msg
view model =
    Ui.el [ Ui.onClick Increment ] (Ui.text (String.fromInt model.count))

main =
    Web.tea
        { init = init
        , update = update
        , view = view
        , subscriptions = subscriptions
        , routes = []
        , notFound = Increment
        }
"#;

/// A `Web.tea` app whose session ticks every 50 ms, so a driver turn and its
/// checkpoint write are running whenever the shutdown closes. Its `init` opens
/// the session-store file through `Ipe.Db`: the `Db` use builds the store's `db`
/// feature in, and the open switches the file to WAL.
const WEB_SESSION_TICKS: &str = r#"module Main exposing (main)

import Ipe.Db as Db
import Ipe.Db.Location as Location exposing (Mode(..))
import Ipe.Error exposing (Error)
import Ipe.Path as Path
import Ipe.Result as Result
import Ipe.String
import Ipe.System as System
import Ipe.Task as Task exposing (Task)
import Ipe.Tea.Web as Web
import Ipe.Tea.Web.Cmd
import Ipe.Tea.Web.Sub
import Ipe.Ui as Ui

type Msg = Tick | Reset | Opened (Result Error ())

type alias Model = { count : Int }

openStoreFile : Task Error ()
openStoreFile =
    Path.fromString (System.getenvOr "IPE_WEB_STORE_PATH" "sessions.db")
        |> Result.andThen (Location.file CreateIfMissing)
        |> Task.fromResult
        |> Task.andThen (\location -> Db.open location)
        |> Task.map (\_ -> ())

init : WebReq -> ( Model, Cmd Msg )
init _req =
    ( { count = 0 }, Cmd.perform openStoreFile Opened )

update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    case msg of
        Tick ->
            ( { model | count = model.count + 1 }, Cmd.none )

        Reset ->
            ( { model | count = 0 }, Cmd.none )

        Opened _result ->
            ( model, Cmd.none )

subscriptions : Model -> Sub Msg
subscriptions _model =
    Sub.every 50 Tick

view : Model -> Element Msg
view model =
    Ui.el [ Ui.onClick Reset ] (Ui.text (String.fromInt model.count))

main =
    Web.tea
        { init = init
        , update = update
        , view = view
        , subscriptions = subscriptions
        , routes = []
        , notFound = Reset
        }
"#;

/// A `Web.tea` app whose `init` Cmd opens the `STORE_DB` file through `Ipe.Db`,
/// writes a row (so the file has a `-wal`), logs that it opened, then queries
/// the table back to back, writing a failed query to stderr: a Cmd always on
/// its owned pool when the grace ends.
const WEB_CMD_DB: &str = r#"module Main exposing (main)

import Ipe.Db as Db exposing (Db)
import Ipe.Db.Location as Location exposing (Mode(..))
import Ipe.Db.Unsafe as Unsafe
import Ipe.Error as Error exposing (Error)
import Ipe.Log as Log
import Ipe.Path as Path
import Ipe.Result as Result
import Ipe.String
import Ipe.System as System
import Ipe.Task as Task exposing (Step(..), Task)
import Ipe.Tea.Web as Web
import Ipe.Tea.Web.Cmd
import Ipe.Tea.Web.Sub
import Ipe.Ui as Ui

type Msg = Increment | Probed (Result Error ())

type alias Model = { count : Int }

connect : Task Error Db
connect =
    Path.fromString (System.getenvOr "STORE_DB" "shutdown-e2e.db")
        |> Result.andThen (Location.file CreateIfMissing)
        |> Task.fromResult
        |> Task.andThen (\location -> Db.open location)

setup : Db -> Task Error Db
setup db =
    Unsafe.unsafeExecRaw db "CREATE TABLE IF NOT EXISTS probe (v INTEGER NOT NULL)"
        |> Task.andThen (\_ -> Unsafe.unsafeExecRaw db "INSERT INTO probe (v) VALUES (1)")
        |> Task.andThen (\_ -> Log.info "probe opened its pool")
        |> Task.map (\_ -> db)

probeOnce : Db -> Int -> Task Error (Step Int ())
probeOnce db n =
    Unsafe.unsafeQuery db "SELECT v FROM probe" []
        |> Task.map (\_ -> Continue (n + 1))

probe : Task Error ()
probe =
    connect
        |> Task.andThen setup
        |> Task.andThen (\db -> Task.loop 1000000000 0 (probeOnce db))
        |> Task.onError (\e -> Log.warnWith "probe failed" [ Error.toString e ])

init : WebReq -> ( Model, Cmd Msg )
init _req =
    ( { count = 0 }, Cmd.perform probe Probed )

update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    case msg of
        Increment ->
            ( { model | count = model.count + 1 }, Cmd.none )

        Probed _result ->
            ( model, Cmd.none )

subscriptions : Model -> Sub Msg
subscriptions _model =
    Sub.none

view : Model -> Element Msg
view model =
    Ui.el [ Ui.onClick Increment ] (Ui.text (String.fromInt model.count))

main =
    Web.tea
        { init = init
        , update = update
        , view = view
        , subscriptions = subscriptions
        , routes = []
        , notFound = Increment
        }
"#;

/// Compile `source` with the dev-loop intent, build it, and return the binary.
///
/// # Errors
///
/// Any pipeline or Cargo build failure.
fn compile(test_name: &str, source: &str) -> Result<e2e_support::SharedBuild, BoxError> {
    let scratch = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let fixture = ipe::RootFixture::main(source).map_err(|e| -> BoxError {
        format!("{test_name}: cannot write the fixture: {e}").into()
    })?;
    let out_dir = scratch.join(format!("server_shutdown_e2e_{test_name}_emitted"));
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

/// A fresh database path for `test_name`, with no file or sidecar left over.
fn fresh_db(test_name: &str) -> PathBuf {
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("server_shutdown_e2e_{test_name}.db"));
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(sidecar(&path, suffix));
    }
    path
}

/// The file `suffix` names next to `db`.
fn sidecar(db: &Path, suffix: &str) -> PathBuf {
    let mut name = db.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// Assert that `db` exists and has no `-wal` or `-shm` sidecar.
fn assert_no_sidecars(test_name: &str, db: &Path) {
    assert!(db.exists(), "{test_name}: the database file exists");
    assert!(
        !sidecar(db, "-wal").exists(),
        "{test_name}: the shutdown checkpoints the WAL and leaves no -wal"
    );
    assert!(
        !sidecar(db, "-shm").exists(),
        "{test_name}: the shutdown leaves no -shm"
    );
}

/// An unused loopback port.
///
/// # Errors
///
/// The OS refuses the bind.
fn pick_ephemeral_port() -> Result<u16, BoxError> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}

/// Which pipe a line came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Pipe {
    Out,
    Err,
}

/// A running binary, its output lines, and a kill on drop.
struct Served {
    child: Child,
    lines: mpsc::Receiver<(Pipe, String)>,
    seen: Vec<(Pipe, String)>,
}

impl Drop for Served {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Forward every line of `pipe` to `tx`.
fn forward(
    pipe: impl Read + Send + 'static,
    tag: Pipe,
    tx: mpsc::Sender<(Pipe, String)>,
) -> std::io::Result<()> {
    std::thread::Builder::new().spawn(move || {
        for line in BufReader::new(pipe).lines() {
            let Ok(line) = line else {
                return;
            };
            if tx.send((tag, line)).is_err() {
                return;
            }
        }
    })?;
    Ok(())
}

impl Served {
    /// Spawn `exe` on `port` with `env` over a cleared posture.
    ///
    /// # Errors
    ///
    /// The binary cannot start.
    fn spawn(exe: &Path, port: u16, env: &[(&str, &str)]) -> Result<Self, BoxError> {
        let mut command = Command::new(exe);
        for var in POSTURE_ENV {
            command.env_remove(var);
        }
        command
            .env("IPE_SERVER_PORT", port.to_string())
            .env("IPE_HTTP_BIND", "127.0.0.1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (key, value) in env {
            command.env(key, value);
        }
        let mut child = command.spawn()?;
        let (tx, lines) = mpsc::channel();
        if let Some(out) = child.stdout.take() {
            forward(out, Pipe::Out, tx.clone())?;
        }
        if let Some(err) = child.stderr.take() {
            forward(err, Pipe::Err, tx)?;
        }
        Ok(Self {
            child,
            lines,
            seen: Vec::new(),
        })
    }

    /// Spawn `exe` and wait until it reports its listener bound.
    ///
    /// # Errors
    ///
    /// The binary cannot start or never binds within [`READY_BUDGET`].
    fn ready(exe: &Path, port: u16, env: &[(&str, &str)]) -> Result<Self, BoxError> {
        let mut served = Self::spawn(exe, port, env)?;
        served.wait_for("listening on", READY_BUDGET)?;
        Ok(served)
    }

    /// Wait until a line containing `what` arrives.
    ///
    /// # Errors
    ///
    /// No such line within `budget`, or the process closed its output first.
    fn wait_for(&mut self, what: &str, budget: Duration) -> Result<(), BoxError> {
        let deadline = Instant::now() + budget;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(format!(
                    "no line with {what:?} within {budget:?}; seen {:?}",
                    self.seen
                )
                .into());
            }
            match self.lines.recv_timeout(left) {
                Ok(line) => {
                    let hit = line.1.contains(what);
                    self.seen.push(line);
                    if hit {
                        return Ok(());
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(
                        format!("output closed before {what:?}; seen {:?}", self.seen).into(),
                    );
                }
            }
        }
    }

    /// Send `signal` (a `kill` flag such as `-TERM`) to the process.
    ///
    /// # Errors
    ///
    /// `kill` cannot run or reports a failure.
    fn signal(&self, signal: &str) -> Result<(), BoxError> {
        let pid = self.child.id().to_string();
        let status = Command::new("kill").args([signal, pid.as_str()]).status()?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("kill {signal} {pid} failed: {status}").into())
        }
    }

    /// Wait for the process to exit, then collect its remaining output.
    ///
    /// # Errors
    ///
    /// The process is still running after `budget`.
    fn wait_exit(&mut self, budget: Duration) -> Result<ExitStatus, BoxError> {
        let deadline = Instant::now() + budget;
        loop {
            if let Some(status) = self.child.try_wait()? {
                self.collect_rest();
                return Ok(status);
            }
            if Instant::now() >= deadline {
                return Err(format!("still running after {budget:?}; seen {:?}", self.seen).into());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Collect the lines still in flight once the process has exited.
    fn collect_rest(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while let Ok(line) = self
            .lines
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        {
            self.seen.push(line);
        }
    }

    /// How many lines on `pipe` end with `suffix`.
    fn ending_with(&self, pipe: Pipe, suffix: &str) -> usize {
        self.seen
            .iter()
            .filter(|(from, line)| *from == pipe && line.trim_end().ends_with(suffix))
            .count()
    }

    /// How many lines on `pipe` contain `text`.
    fn containing(&self, pipe: Pipe, text: &str) -> usize {
        self.seen
            .iter()
            .filter(|(from, line)| *from == pipe && line.contains(text))
            .count()
    }
}

/// `GET path` over a fresh connection; the whole response, headers included.
///
/// # Errors
///
/// The connection, write or read fails.
fn get(port: u16, path: &str) -> Result<String, BoxError> {
    let mut stream = TcpStream::connect(("127.0.0.1", port))?;
    stream.set_read_timeout(Some(CLIENT_BUDGET))?;
    let request = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes())?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// The body of a whole HTTP response.
fn body(response: &str) -> &str {
    response.split_once("\r\n\r\n").map_or("", |(_, body)| body)
}

/// `GET path` on a thread, so the caller can signal while it is in flight.
fn get_in_flight(
    port: u16,
    path: &str,
) -> std::io::Result<std::thread::JoinHandle<Result<String, String>>> {
    let path = path.to_owned();
    std::thread::Builder::new().spawn(move || get(port, &path).map_err(|e| e.to_string()))
}

/// Seed the database through the app and assert the write landed.
///
/// # Errors
///
/// The request fails.
fn write_one_row(test_name: &str, port: u16) -> Result<(), BoxError> {
    let response = get(port, "/write")?;
    assert_eq!(
        body(&response),
        "1",
        "{test_name}: the write lands: {response}"
    );
    Ok(())
}

/// E1: one write, SIGTERM: exit 0, one shutdown line, no sidecar, and the
/// file reopens intact with its row.
#[test]
fn sigterm_closes_the_pools_and_leaves_an_intact_database() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }
    let test_name = "sigterm_db";
    let exe = compile(test_name, DB_SERVER)?;
    let db = fresh_db(test_name);
    let db_env = db.to_string_lossy().into_owned();
    let env = [("STORE_DB", db_env.as_str())];

    let port = pick_ephemeral_port()?;
    let mut served = Served::ready(&exe, port, &env)?;
    write_one_row(test_name, port)?;
    assert!(
        sidecar(&db, "-wal").exists(),
        "{test_name}: a live WAL write keeps its sidecar"
    );
    served.signal("-TERM")?;
    let status = served.wait_exit(EXIT_BUDGET)?;
    assert_eq!(
        status.code(),
        Some(0),
        "{test_name}: {status}; seen {:?}",
        served.seen
    );
    assert_eq!(
        served.ending_with(Pipe::Out, SHUTDOWN_LINE),
        1,
        "{test_name}: exactly one shutdown line; seen {:?}",
        served.seen
    );
    assert_eq!(served.containing(Pipe::Err, FORCING_LINE), 0);
    assert_no_sidecars(test_name, &db);
    drop(served);

    let port = pick_ephemeral_port()?;
    let mut reopened = Served::ready(&exe, port, &env)?;
    let check = get(port, "/check")?;
    assert_eq!(body(&check), "ok", "{test_name}: integrity_check: {check}");
    let rows = get(port, "/rows")?;
    assert_eq!(
        body(&rows),
        "kept",
        "{test_name}: the write survives: {rows}"
    );
    reopened.signal("-TERM")?;
    let status = reopened.wait_exit(EXIT_BUDGET)?;
    assert_eq!(
        status.code(),
        Some(0),
        "{test_name}: reopened run: {status}"
    );
    assert_no_sidecars(test_name, &db);
    Ok(())
}

/// Run a second-signal case: `signal` twice while a slow request holds the
/// drain; return the exited process.
///
/// # Errors
///
/// Build, spawn, request or signal failure.
fn signalled_twice(test_name: &str, signal: &str) -> Result<(Served, ExitStatus), BoxError> {
    let exe = compile(test_name, DB_SERVER)?;
    let db = fresh_db(test_name);
    let db_env = db.to_string_lossy().into_owned();
    let env = [
        ("STORE_DB", db_env.as_str()),
        ("IPE_WEB_SHUTDOWN_GRACE_MS", "15000"),
    ];
    let port = pick_ephemeral_port()?;
    let mut served = Served::ready(&exe, port, &env)?;
    write_one_row(test_name, port)?;
    let slow = get_in_flight(port, "/slow/30000")?;
    std::thread::sleep(Duration::from_millis(300));
    served.signal(signal)?;
    served.wait_for(SHUTDOWN_LINE, LINE_BUDGET)?;
    served.signal(signal)?;
    let status = served.wait_exit(EXIT_BUDGET)?;
    let _ = slow.join();
    Ok((served, status))
}

/// E2: a second SIGTERM during the drain exits 143 with one forcing line.
#[test]
fn a_second_sigterm_forces_exit_143() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }
    let test_name = "second_sigterm";
    let (served, status) = signalled_twice(test_name, "-TERM")?;
    assert_eq!(
        status.code(),
        Some(143),
        "{test_name}: {status}; seen {:?}",
        served.seen
    );
    assert_eq!(
        served.containing(Pipe::Err, FORCING_LINE),
        1,
        "{test_name}: one forcing line; seen {:?}",
        served.seen
    );
    assert_eq!(
        served.ending_with(Pipe::Out, SHUTDOWN_LINE),
        1,
        "{test_name}: one shutdown line"
    );
    Ok(())
}

/// E3: a second SIGINT during the drain exits 130.
#[test]
fn a_second_sigint_forces_exit_130() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }
    let test_name = "second_sigint";
    let (served, status) = signalled_twice(test_name, "-INT")?;
    assert_eq!(
        status.code(),
        Some(130),
        "{test_name}: {status}; seen {:?}",
        served.seen
    );
    assert_eq!(
        served.containing(Pipe::Err, FORCING_LINE),
        1,
        "{test_name}: one forcing line"
    );
    assert_eq!(
        served.ending_with(Pipe::Out, SHUTDOWN_LINE),
        1,
        "{test_name}: one shutdown line"
    );
    Ok(())
}

/// E4: a signal before the listener is armed takes the OS default: the
/// process ends by SIGTERM, with no shutdown line.
#[test]
fn a_signal_before_the_listener_takes_the_os_default() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }
    let test_name = "before_bind";
    let exe = compile(test_name, SLOW_START)?;
    let port = pick_ephemeral_port()?;
    let mut served = Served::spawn(&exe, port, &[])?;
    std::thread::sleep(Duration::from_millis(1000));
    assert_eq!(served.containing(Pipe::Err, "listening on"), 0);
    served.signal("-TERM")?;
    let status = served.wait_exit(EXIT_BUDGET)?;
    assert_eq!(
        status.signal(),
        Some(15),
        "{test_name}: {status}; seen {:?}",
        served.seen
    );
    assert_eq!(
        served.ending_with(Pipe::Out, SHUTDOWN_LINE),
        0,
        "{test_name}: never armed"
    );
    Ok(())
}

/// E5: a request in flight inside the grace gets its full 200, then exit 0.
#[test]
fn a_request_in_flight_completes_before_the_exit() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }
    let test_name = "in_flight";
    let exe = compile(test_name, DB_SERVER)?;
    let db = fresh_db(test_name);
    let db_env = db.to_string_lossy().into_owned();
    let env = [
        ("STORE_DB", db_env.as_str()),
        ("IPE_WEB_SHUTDOWN_GRACE_MS", "5000"),
    ];
    let port = pick_ephemeral_port()?;
    let mut served = Served::ready(&exe, port, &env)?;
    write_one_row(test_name, port)?;
    let slow = get_in_flight(port, "/slow/1000")?;
    std::thread::sleep(Duration::from_millis(300));
    served.signal("-TERM")?;
    let response = slow
        .join()
        .map_err(|_| -> BoxError { format!("{test_name}: client thread failed").into() })??;
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "{test_name}: {response}"
    );
    assert_eq!(
        body(&response),
        "slept",
        "{test_name}: the full body: {response}"
    );
    let status = served.wait_exit(EXIT_BUDGET)?;
    assert_eq!(
        status.code(),
        Some(0),
        "{test_name}: {status}; seen {:?}",
        served.seen
    );
    assert_eq!(served.ending_with(Pipe::Out, SHUTDOWN_LINE), 1);
    assert_no_sidecars(test_name, &db);
    Ok(())
}

/// E6: a request stuck far past a 300 ms grace never holds the exit past its
/// bound: grace, settle and both pool-close stages, plus slack.
#[test]
fn a_stuck_request_never_holds_the_exit_past_its_bound() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }
    let test_name = "stuck";
    let exe = compile(test_name, DB_SERVER)?;
    let db = fresh_db(test_name);
    let db_env = db.to_string_lossy().into_owned();
    let env = [
        ("STORE_DB", db_env.as_str()),
        ("IPE_WEB_SHUTDOWN_GRACE_MS", "300"),
    ];
    let port = pick_ephemeral_port()?;
    let mut served = Served::ready(&exe, port, &env)?;
    write_one_row(test_name, port)?;
    let _stuck = get_in_flight(port, "/slow/120000")?;
    std::thread::sleep(Duration::from_millis(300));
    let signalled = Instant::now();
    served.signal("-TERM")?;
    let status = served.wait_exit(EXIT_BUDGET)?;
    let elapsed = signalled.elapsed();
    let bound = Duration::from_millis(300) * 2 + POOLS_CLOSE_BOUND + Duration::from_secs(3);
    assert_eq!(
        status.code(),
        Some(0),
        "{test_name}: {status}; seen {:?}",
        served.seen
    );
    assert!(
        elapsed < bound,
        "{test_name}: exit took {elapsed:?}, bound {bound:?}"
    );
    assert_eq!(served.ending_with(Pipe::Out, SHUTDOWN_LINE), 1);
    assert_no_sidecars(test_name, &db);
    Ok(())
}

/// The `ipe_sid` value a response's `Set-Cookie` carries.
fn session_cookie(response: &str) -> Option<String> {
    let headers = response
        .split_once("\r\n\r\n")
        .map_or(response, |(head, _)| head);
    headers.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if !name.trim().eq_ignore_ascii_case("set-cookie") {
            return None;
        }
        let pair = value.trim().split(';').next()?;
        let sid = pair.strip_prefix("ipe_sid=")?;
        Some(sid.to_owned())
    })
}

/// E7: an open SSE stream ends with a clean EOF after SIGTERM, and the
/// process exits 0 with one shutdown line.
#[test]
fn an_open_sse_stream_ends_cleanly_on_sigterm() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }
    let test_name = "web_sse";
    let exe = compile(test_name, WEB_COUNTER)?;
    let port = pick_ephemeral_port()?;
    let port_env = port.to_string();
    let env = [
        ("IPE_WEB_PORT", port_env.as_str()),
        ("IPE_CSRF", "off"),
        ("IPE_CONSOLE_EMBED", "off"),
    ];
    let mut served = Served::ready(&exe, port, &env)?;
    let page = get(port, "/")?;
    let sid = session_cookie(&page)
        .ok_or_else(|| -> BoxError { format!("{test_name}: no ipe_sid cookie: {page}").into() })?;

    let mut stream = TcpStream::connect(("127.0.0.1", port))?;
    stream.set_read_timeout(Some(CLIENT_BUDGET))?;
    let request = format!(
        "GET /_ipe/sse?path=%2F HTTP/1.1\r\nHost: 127.0.0.1\r\n\
         Accept: text/event-stream\r\nCookie: ipe_sid={sid}\r\n\r\n"
    );
    stream.write_all(request.as_bytes())?;
    let mut acc = Vec::new();
    let mut chunk = [0u8; 8192];
    while !String::from_utf8_lossy(&acc).contains("event:") {
        let n = stream.read(&mut chunk)?;
        assert!(n > 0, "{test_name}: the stream opens before the signal");
        acc.extend_from_slice(chunk.get(..n).unwrap_or_default());
    }
    assert!(
        String::from_utf8_lossy(&acc).starts_with("HTTP/1.1 200"),
        "{test_name}: {}",
        String::from_utf8_lossy(&acc)
    );

    served.signal("-TERM")?;
    let ended = Instant::now() + LINE_BUDGET;
    loop {
        assert!(
            Instant::now() < ended,
            "{test_name}: the stream never ended"
        );
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => acc.extend_from_slice(chunk.get(..n).unwrap_or_default()),
            Err(e) => {
                return Err(
                    format!("{test_name}: the stream ended by {e}, not a clean EOF").into(),
                );
            }
        }
    }
    let status = served.wait_exit(EXIT_BUDGET)?;
    assert_eq!(
        status.code(),
        Some(0),
        "{test_name}: {status}; seen {:?}",
        served.seen
    );
    assert_eq!(
        served.ending_with(Pipe::Out, SHUTDOWN_LINE),
        1,
        "{test_name}: one shutdown line"
    );
    Ok(())
}

/// Read one websocket frame from `stream`: its opcode and payload.
///
/// # Errors
///
/// The read fails or the frame is malformed.
fn read_frame(stream: &mut TcpStream) -> Result<(u8, Vec<u8>), BoxError> {
    let mut head = [0u8; 2];
    stream.read_exact(&mut head)?;
    let [first, second] = head;
    let len = match second & 0x7f {
        126 => {
            let mut ext = [0u8; 2];
            stream.read_exact(&mut ext)?;
            u64::from(u16::from_be_bytes(ext))
        }
        127 => {
            let mut ext = [0u8; 8];
            stream.read_exact(&mut ext)?;
            u64::from_be_bytes(ext)
        }
        short => u64::from(short),
    };
    if len > 1 << 20 {
        return Err(format!("frame of {len} bytes").into());
    }
    let mut payload = vec![0u8; usize::try_from(len)?];
    stream.read_exact(&mut payload)?;
    Ok((first & 0x0f, payload))
}

/// E8: a connected websocket client receives close code 1001 on SIGTERM, and
/// the process exits 0.
#[test]
fn a_websocket_client_receives_going_away_on_sigterm() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }
    let test_name = "websocket";
    let exe = compile(test_name, WS_SERVER)?;
    let port = pick_ephemeral_port()?;
    let mut served = Served::ready(&exe, port, &[])?;

    let mut stream = TcpStream::connect(("127.0.0.1", port))?;
    stream.set_read_timeout(Some(CLIENT_BUDGET))?;
    stream.write_all(
        b"GET /ws HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
          Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
    )?;
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        assert!(
            head.len() < 16 * 1024,
            "{test_name}: an unbounded handshake"
        );
        stream.read_exact(&mut byte)?;
        head.extend_from_slice(&byte);
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    assert!(head.starts_with("HTTP/1.1 101"), "{test_name}: {head}");

    served.signal("-TERM")?;
    let mut close = None;
    for _ in 0..64 {
        let (opcode, payload) = read_frame(&mut stream)?;
        if opcode == 0x8 {
            close = Some(payload);
            break;
        }
    }
    let close =
        close.ok_or_else(|| -> BoxError { format!("{test_name}: no close frame").into() })?;
    assert!(
        close.starts_with(&1001u16.to_be_bytes()),
        "{test_name}: close code 1001 (going away), got {close:?}"
    );
    let status = served.wait_exit(EXIT_BUDGET)?;
    assert_eq!(
        status.code(),
        Some(0),
        "{test_name}: {status}; seen {:?}",
        served.seen
    );
    assert_eq!(
        served.ending_with(Pipe::Out, SHUTDOWN_LINE),
        1,
        "{test_name}: one shutdown line"
    );
    Ok(())
}

/// E9: an `Http.Server`-only app builds, and SIGTERM exits 0 with one line.
#[test]
fn a_server_only_app_exits_zero_on_sigterm() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }
    let test_name = "server_only";
    let exe = compile(test_name, PLAIN_SERVER)?;
    let port = pick_ephemeral_port()?;
    let mut served = Served::ready(&exe, port, &[])?;
    let response = get(port, "/")?;
    assert_eq!(body(&response), "plain", "{test_name}: {response}");
    served.signal("-TERM")?;
    let status = served.wait_exit(EXIT_BUDGET)?;
    assert_eq!(
        status.code(),
        Some(0),
        "{test_name}: {status}; seen {:?}",
        served.seen
    );
    assert_eq!(
        served.ending_with(Pipe::Out, SHUTDOWN_LINE),
        1,
        "{test_name}: one shutdown line; seen {:?}",
        served.seen
    );
    Ok(())
}

/// `GET path` carrying the session cookie `sid`.
///
/// # Errors
///
/// The request fails.
fn get_with_session(port: u16, path: &str, sid: &str) -> Result<String, BoxError> {
    let mut stream = TcpStream::connect(("127.0.0.1", port))?;
    stream.set_read_timeout(Some(CLIENT_BUDGET))?;
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nCookie: ipe_sid={sid}\r\n\
         Connection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes())?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// E10: an `Ipe.Web` app over a SQLite session store exits 0 on SIGTERM with
/// one shutdown line, and its session file keeps no `-wal` or `-shm`.
#[test]
fn a_sqlite_session_store_closes_on_sigterm() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }
    let test_name = "web_session_db";
    let exe = compile(test_name, WEB_SESSION_DB)?;
    let db = fresh_db(test_name);
    let db_env = db.to_string_lossy().into_owned();
    let port = pick_ephemeral_port()?;
    let port_env = port.to_string();
    let env = [
        ("IPE_WEB_PORT", port_env.as_str()),
        ("IPE_CSRF", "off"),
        ("IPE_CONSOLE_EMBED", "off"),
        ("IPE_WEB_STORE", "sqlite"),
        ("IPE_WEB_STORE_PATH", db_env.as_str()),
    ];
    let mut served = Served::ready(&exe, port, &env)?;
    let page = get(port, "/")?;
    let sid = session_cookie(&page)
        .ok_or_else(|| -> BoxError { format!("{test_name}: no ipe_sid cookie: {page}").into() })?;
    let switched = Instant::now() + LINE_BUDGET;
    while !sidecar(&db, "-wal").exists() {
        assert!(
            Instant::now() < switched,
            "{test_name}: the session file never ran in WAL; seen {:?}",
            served.seen
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let again = get_with_session(port, "/", &sid)?;
    assert!(
        again.starts_with("HTTP/1.1 200"),
        "{test_name}: the session reloads: {again}"
    );
    served.signal("-TERM")?;
    let status = served.wait_exit(EXIT_BUDGET)?;
    assert_eq!(
        status.code(),
        Some(0),
        "{test_name}: {status}; seen {:?}",
        served.seen
    );
    assert_eq!(
        served.ending_with(Pipe::Out, SHUTDOWN_LINE),
        1,
        "{test_name}: one shutdown line; seen {:?}",
        served.seen
    );
    assert_eq!(served.containing(Pipe::Err, FORCING_LINE), 0);
    // A store that failed to open degrades to memory; the file's WAL would
    // then be the `Db.open` pool's alone, proving nothing of the store.
    assert!(
        served.containing(Pipe::Err, "session store: sqlite @ ") > 0,
        "{test_name}: the SQLite session store opened; seen {:?}",
        served.seen
    );
    assert_no_sidecars(test_name, &db);
    Ok(())
}

/// E11: a web Cmd still running on an owned pool past the grace is cancelled
/// before the pools close: it never reports a closed pool, the one cancel line
/// counts it, and the database keeps no `-wal` or `-shm`.
#[test]
fn a_web_cmd_past_the_grace_is_cancelled_before_the_pools_close() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }
    let test_name = "web_cmd_db";
    let exe = compile(test_name, WEB_CMD_DB)?;
    let db = fresh_db(test_name);
    let db_env = db.to_string_lossy().into_owned();
    let port = pick_ephemeral_port()?;
    let port_env = port.to_string();
    let env = [
        ("IPE_WEB_PORT", port_env.as_str()),
        ("IPE_CSRF", "off"),
        ("IPE_CONSOLE_EMBED", "off"),
        ("IPE_WEB_SHUTDOWN_GRACE_MS", "300"),
        ("STORE_DB", db_env.as_str()),
    ];
    let mut served = Served::ready(&exe, port, &env)?;
    let page = get(port, "/")?;
    assert!(
        page.starts_with("HTTP/1.1 200"),
        "{test_name}: the page renders: {page}"
    );
    served.wait_for("probe opened its pool", LINE_BUDGET)?;
    assert!(
        sidecar(&db, "-wal").exists(),
        "{test_name}: the init Cmd's write opened the file's WAL; seen {:?}",
        served.seen
    );
    std::thread::sleep(Duration::from_millis(200));
    served.signal("-TERM")?;
    let status = served.wait_exit(EXIT_BUDGET)?;
    let closed_pool = served.containing(Pipe::Err, "connection pool closed")
        + served.containing(Pipe::Out, "connection pool closed");
    assert_eq!(
        closed_pool, 0,
        "{test_name}: no Cmd outlives the pool it uses; seen {:?}",
        served.seen
    );
    assert_eq!(
        status.code(),
        Some(0),
        "{test_name}: {status}; seen {:?}",
        served.seen
    );
    assert_eq!(
        served.ending_with(Pipe::Out, SHUTDOWN_LINE),
        1,
        "{test_name}: one shutdown line; seen {:?}",
        served.seen
    );
    assert_eq!(
        served.containing(Pipe::Err, "cancelled 1 task still running"),
        1,
        "{test_name}: the grace's end cancels the running Cmd; seen {:?}",
        served.seen
    );
    assert_eq!(served.containing(Pipe::Err, FORCING_LINE), 0);
    assert_no_sidecars(test_name, &db);
    Ok(())
}

/// E12: a ticking session on the SQLite session store, signalled with no
/// grace, ends cleanly: the exit is 0, no unit of work outlives its cancel
/// deadline (a parked driver counted as work would), nothing panics, and the
/// session file keeps no `-wal` or `-shm`.
///
/// The store writes no line when a checkpoint fails, so a turn cut by the
/// pool close is not visible here; the turn's hold on the close is proved by
/// `a_driver_turn_at_closing_writes_its_checkpoint_then_ends` in the runtime.
#[test]
fn a_ticking_session_stops_its_turns_before_the_store_closes() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }
    let test_name = "web_session_ticks";
    let exe = compile(test_name, WEB_SESSION_TICKS)?;
    let db = fresh_db(test_name);
    let db_env = db.to_string_lossy().into_owned();
    let port = pick_ephemeral_port()?;
    let port_env = port.to_string();
    let env = [
        ("IPE_WEB_PORT", port_env.as_str()),
        ("IPE_CSRF", "off"),
        ("IPE_CONSOLE_EMBED", "off"),
        ("IPE_WEB_SHUTDOWN_GRACE_MS", "0"),
        ("IPE_WEB_STORE", "sqlite"),
        ("IPE_WEB_STORE_PATH", db_env.as_str()),
    ];
    let mut served = Served::ready(&exe, port, &env)?;
    let page = get(port, "/")?;
    assert!(
        page.starts_with("HTTP/1.1 200"),
        "{test_name}: the page renders: {page}"
    );
    let switched = Instant::now() + LINE_BUDGET;
    while !sidecar(&db, "-wal").exists() {
        assert!(
            Instant::now() < switched,
            "{test_name}: the session file never ran in WAL; seen {:?}",
            served.seen
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    // Several ticks, each a turn and a checkpoint write, run before the signal.
    std::thread::sleep(Duration::from_millis(400));
    served.signal("-TERM")?;
    let status = served.wait_exit(EXIT_BUDGET)?;
    assert_eq!(
        status.code(),
        Some(0),
        "{test_name}: {status}; seen {:?}",
        served.seen
    );
    assert_eq!(
        served.ending_with(Pipe::Out, SHUTDOWN_LINE),
        1,
        "{test_name}: one shutdown line; seen {:?}",
        served.seen
    );
    assert_eq!(
        served.containing(Pipe::Err, "session store: sqlite @ "),
        1,
        "{test_name}: the SQLite session store opened, and no other store line; seen {:?}",
        served.seen
    );
    let failures: usize = ["checkpoint", "pool closed", "did not stop", "panicked"]
        .iter()
        .map(|text| served.containing(Pipe::Err, text) + served.containing(Pipe::Out, text))
        .sum();
    assert_eq!(
        failures, 0,
        "{test_name}: no turn outlives the store it writes; seen {:?}",
        served.seen
    );
    assert_eq!(served.containing(Pipe::Err, FORCING_LINE), 0);
    assert_no_sidecars(test_name, &db);
    Ok(())
}
