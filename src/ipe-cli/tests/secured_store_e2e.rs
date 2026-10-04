//! End-to-end proof that a secured `Store` write keeps only a row its policy
//! admits, and never rewrites an owner column.
//!
//! All tests are gated on `IPE_E2E=1`; without it they return early.
//!
//! The Ipê program below serves:
//!
//! * `GET /token/:who`: a bearer token for `alice`, `editor` (subject `alice`
//!   with the `editor` role) or `bob`, signed with the program's own key;
//! * `GET /setup`: the tables and seed rows, created through raw SQL;
//! * `GET /share`: one share row granting document `d1`;
//! * `GET /dump/:table`: a table's rows through a raw read, ordered by `id`,
//!   as `id|author|status|body` joined with `;` (`NULL` spelled out);
//! * `POST /run/:case`: one secured write as the bearer, answering the count
//!   or `err:<message>`.
//!
//! The test builds the program once, serves it on a loopback port against a
//! SQLite file under the test scratch root, and drives every case over raw
//! HTTP/1.1 with socket timeouts and a bounded start. Each refused write is
//! checked twice: the count is `0` and the table dump shows nothing changed.
//!
//! Run:
//!
//! ```text
//! IPE_E2E=1 cargo test -p ipe --test secured_store_e2e
//! ```

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

/// Shared error type for the helpers.
type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// The longest the server may take to report that it is listening.
const READY_TIMEOUT: Duration = Duration::from_secs(10);

/// The read and write timeout of every request socket. Each case commits a
/// write to a file database, so a slow disk's `fsync` is inside this bound.
const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// The served Ipê program: one route per secured write, plus setup and dumps.
const PROGRAM: &str = r#"module Main exposing (main)

import Ipe.Auth as Auth
import Ipe.Codec as Codec exposing (Codec)
import Ipe.Db as Db exposing (Db)
import Ipe.Db.Store as Store exposing (Draft, Secured, Store)
import Ipe.Db.Unsafe as Unsafe
import Ipe.Dict as Dict
import Ipe.Error as Error exposing (Error)
import Ipe.Http.Server as Server
import Ipe.Http.Server exposing (Request, Response)
import Ipe.List as List
import Ipe.Maybe as Maybe exposing (Maybe(..))
import Ipe.Result as Result exposing (Result(..))
import Ipe.Secret as Secret
import Ipe.String as String
import Ipe.System as System
import Ipe.Task as Task exposing (Task)


type alias Note =
    { id : String
    , author : String
    , status : String
    , body : String
    }


blankNote : Note
blankNote =
    { id = "", author = "", status = "", body = "" }


note : String -> String -> String -> String -> Note
note id author status body =
    { id = id, author = author, status = status, body = body }


type alias Share =
    { id : String
    , docId : String
    }


blankShare : Share
blankShare =
    { id = "", docId = "" }


noteDraft : String -> Result Error (Draft Note)
noteDraft table =
    Result.map (\d -> Store.primaryKey .id d) (Store.fromCodec table (Codec.auto blankNote))


securedNotes : String -> Store.Policy Note -> Result Error (Secured Note)
securedNotes table policy =
    Result.andThen (Store.secured policy) (noteDraft table)


publicNotes : String -> Result Error (Store Note)
publicNotes table =
    Result.map Store.public (noteDraft table)


shareDraft : Result Error (Draft Share)
shareDraft =
    Result.map (\d -> Store.primaryKey .id d) (Store.fromCodec "shares" (Codec.auto blankShare))


securedShares : Result Error (Secured Share)
securedShares =
    Result.andThen (Store.secured (Store.readOnly Store.always)) shareDraft


sharedInsertPolicy : Secured Share -> Store.Policy Note
sharedInsertPolicy shares =
    Store.readOnly Store.always
        |> Store.alsoInsert
            (Store.existsIn shares (\share doc -> Store.correlate share.docId doc.id))


draftOnlyPolicy : Store.Policy Note
draftOnlyPolicy =
    Store.ownerColumn .author
        |> Store.andPolicy
            (Store.unrestricted
                |> Store.alsoUpdate (Store.matchWhere (Store.eq .status "draft"))
            )


-- Owner-scoped, but every caller may update every row: the owner column must
-- still never change.
openEditPolicy : Store.Policy Note
openEditPolicy =
    Store.ownerColumn .author |> Store.alsoUpdate Store.always


stampedDraft : Result Error (Draft Note)
stampedDraft =
    Result.map (\d -> Store.defaultNow .status d) (noteDraft "stamped")


signingKey : Secret.Secret
signingKey =
    Secret.fromString (System.getenvOr "SIGNING_KEY" "secured-store-e2e-signing-key-of-32-bytes-or-more")


authCfg : Server.AuthConfig
authCfg =
    Server.authConfig signingKey Server.bearerToken


connect : Task Error Db
connect =
    Db.open "sqlite" (System.getenvOr "STORE_DB" "secured-store-e2e.db")


-- A count, or the error text, as the response body.
answer : Task Error Int -> Task Error Response
answer task =
    Task.onError
        (\e -> Task.succeed (Server.text (String.concat [ "err:", Error.message e ])))
        (Task.map (\n -> Server.text (String.fromInt n)) task)


withSecured : Result Error (Secured a) -> (Secured a -> Task Error Int) -> Task Error Int
withSecured built run =
    case built of
        Ok secured ->
            run secured

        Err e ->
            Task.fail e


withStore : Result Error (Store a) -> (Store a -> Task Error Int) -> Task Error Int
withStore built run =
    case built of
        Ok store ->
            run store

        Err e ->
            Task.fail e


-- One secured write per case; `principal` is the bearer of the request.
runCase : String -> Auth.Principal -> Db -> Task Error Int
runCase name principal db =
    case name of
        "read-only-insert" ->
            withSecured (securedNotes "read_only" (Store.readOnly Store.always))
                (\s -> Store.insertAs principal db s (note "n1" "alice" "draft" "new"))

        "role-insert" ->
            withSecured
                (securedNotes "by_role"
                    (Store.readOnly Store.always |> Store.alsoInsert (Store.role "editor"))
                )
                (\s -> Store.insertAs principal db s (note "n1" "alice" "draft" "new"))

        "owner-update" ->
            withSecured (securedNotes "owned" (Store.ownerColumn .author))
                (\s -> Store.updateAs principal db s (note "n1" "bob" "draft" "edited"))

        "owner-kept" ->
            withSecured (securedNotes "open_edit" openEditPolicy)
                (\s -> Store.updateAs principal db s (note "n1" "bob" "draft" "bob-edit"))

        "draft-publish" ->
            withSecured (securedNotes "drafts" draftOnlyPolicy)
                (\s -> Store.updateAs principal db s (note "n1" "alice" "published" "edited"))

        "draft-edit" ->
            withSecured (securedNotes "drafts" draftOnlyPolicy)
                (\s -> Store.updateAs principal db s (note "n2" "alice" "draft" "edited"))

        "shared-insert" ->
            withSecured (Result.andThen (\shares -> securedNotes "docs" (sharedInsertPolicy shares)) securedShares)
                (\s -> Store.insertAs principal db s (note "d1" "alice" "draft" "new"))

        "transaction" ->
            Db.withTransaction db
                (\tx ->
                    withSecured (securedNotes "txn" (Store.readOnly Store.always))
                        (\s ->
                            Task.andThen
                                (\refused ->
                                    withStore (publicNotes "txn")
                                        (\p ->
                                            Task.map
                                                (\kept -> refused * 10 + kept)
                                                (Store.insert tx p (note "n2" "alice" "draft" "public"))
                                        )
                                )
                                (Store.insertAs principal tx s (note "n1" "alice" "draft" "secured"))
                        )
                )

        "null-check" ->
            withSecured
                (Result.andThen
                    (Store.secured
                        (Store.readOnly Store.always
                            |> Store.alsoInsert (Store.matchWhere (Store.neq .status "z"))
                        )
                    )
                    stampedDraft
                )
                (\s -> Store.insertAs principal db s (note "n1" "alice" "client" "new"))

        "non-null-check" ->
            withSecured
                (Result.andThen
                    (Store.secured
                        (Store.readOnly Store.always
                            |> Store.alsoInsert (Store.matchWhere (Store.neq .body "z"))
                        )
                    )
                    stampedDraft
                )
                (\s -> Store.insertAs principal db s (note "n2" "alice" "client" "new"))

        _ ->
            Task.fail (Error.invalidInput (String.concat [ "unknown case ", name ]))


handleRun : Request -> Auth.Principal -> Task Error Response
handleRun req principal =
    answer
        (Task.andThen
            (runCase (Maybe.withDefault "" (Server.param "case" req)) principal)
            connect
        )


setupStatements : List String
setupStatements =
    [ "CREATE TABLE read_only (id TEXT PRIMARY KEY, author TEXT NOT NULL, status TEXT NOT NULL, body TEXT NOT NULL)"
    , "CREATE TABLE by_role (id TEXT PRIMARY KEY, author TEXT NOT NULL, status TEXT NOT NULL, body TEXT NOT NULL)"
    , "CREATE TABLE owned (id TEXT PRIMARY KEY, author TEXT NOT NULL, status TEXT NOT NULL, body TEXT NOT NULL)"
    , "INSERT INTO owned (id, author, status, body) VALUES ('n1', 'alice', 'draft', 'seed')"
    , "CREATE TABLE open_edit (id TEXT PRIMARY KEY, author TEXT NOT NULL, status TEXT NOT NULL, body TEXT NOT NULL)"
    , "INSERT INTO open_edit (id, author, status, body) VALUES ('n1', 'alice', 'draft', 'seed')"
    , "CREATE TABLE drafts (id TEXT PRIMARY KEY, author TEXT NOT NULL, status TEXT NOT NULL, body TEXT NOT NULL)"
    , "INSERT INTO drafts (id, author, status, body) VALUES ('n1', 'alice', 'draft', 'seed')"
    , "INSERT INTO drafts (id, author, status, body) VALUES ('n2', 'alice', 'draft', 'seed')"
    , "CREATE TABLE docs (id TEXT PRIMARY KEY, author TEXT NOT NULL, status TEXT NOT NULL, body TEXT NOT NULL)"
    , "CREATE TABLE shares (id TEXT PRIMARY KEY, doc_id TEXT NOT NULL)"
    , "CREATE TABLE txn (id TEXT PRIMARY KEY, author TEXT NOT NULL, status TEXT NOT NULL, body TEXT NOT NULL)"
    , "CREATE TABLE stamped (id TEXT PRIMARY KEY, author TEXT NOT NULL, status TEXT, body TEXT NOT NULL)"
    ]


handleSetup : Request -> Task Error Response
handleSetup _ =
    answer
        (Task.andThen
            (\db ->
                Db.withTransaction db
                    (\tx ->
                        List.foldl
                            (\stmt acc -> Task.andThen (\n -> Task.map (\m -> n + m) (Unsafe.unsafeExecRaw tx stmt)) acc)
                            (Task.succeed 0)
                            setupStatements
                    )
            )
            connect
        )


handleShare : Request -> Task Error Response
handleShare _ =
    answer
        (Task.andThen
            (\db -> Unsafe.unsafeExecRaw db "INSERT INTO shares (id, doc_id) VALUES ('s1', 'd1')")
            connect
        )


dumpQuery : String -> Maybe String
dumpQuery table =
    if List.member table [ "read_only", "by_role", "owned", "open_edit", "drafts", "docs", "txn", "stamped" ] then
        Just
            (String.concat
                [ "SELECT id, author, COALESCE(status, 'NULL') AS status, body FROM "
                , table
                , " ORDER BY id"
                ]
            )

    else
        Nothing


dumpRow : Dict.Dict String String -> String
dumpRow row =
    String.join "|"
        (List.map (\col -> Unsafe.unsafeGetString col row) [ "id", "author", "status", "body" ])


handleDump : Request -> Task Error Response
handleDump req =
    case dumpQuery (Maybe.withDefault "" (Server.param "table" req)) of
        Just sql ->
            Task.onError
                (\e -> Task.succeed (Server.text (String.concat [ "err:", Error.message e ])))
                (Task.andThen
                    (\db ->
                        Task.map
                            (\rows -> Server.text (String.join ";" (List.map dumpRow rows)))
                            (Unsafe.unsafeQuery db sql [])
                    )
                    connect
                )

        Nothing ->
            Task.succeed (Server.text "err:unknown table")


claimsFor : String -> Maybe (Dict.Dict String String)
claimsFor who =
    case who of
        "alice" ->
            Just (Dict.fromList [ ( "sub", "alice" ) ])

        "editor" ->
            Just (Dict.fromList [ ( "sub", "alice" ), ( "roles", "editor" ) ])

        "bob" ->
            Just (Dict.fromList [ ( "sub", "bob" ) ])

        _ ->
            Nothing


handleToken : Request -> Task Error Response
handleToken req =
    case claimsFor (Maybe.withDefault "" (Server.param "who" req)) of
        Just claims ->
            case Auth.signToken signingKey claims 3600 of
                Ok token ->
                    Task.succeed (Server.text token)

                Err e ->
                    Task.succeed (Server.text (String.concat [ "err:", Error.message e ]))

        Nothing ->
            Task.succeed (Server.text "err:unknown caller")


main : Task Error ()
main =
    Server.listen
        (Maybe.withDefault 8080 (String.toInt (System.getenvOr "IPE_SERVER_PORT" "8080")))
        [ Server.get "/token/:who" handleToken
        , Server.get "/setup" handleSetup
        , Server.get "/share" handleShare
        , Server.get "/dump/:table" handleDump
        , Server.postAuthed "/run/:case" authCfg handleRun
        ]
"#;

/// Compiles [`PROGRAM`] with the dev-loop intent and builds the emitted crate.
///
/// # Errors
///
/// Returns an error on any pipeline or Cargo build failure.
fn compile_and_build(test_name: &str) -> Result<PathBuf, BoxError> {
    let scratch = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let ipe_dir = scratch.join(format!("secured_store_e2e_{test_name}_ipe"));
    let _ = std::fs::remove_dir_all(&ipe_dir);
    std::fs::create_dir_all(&ipe_dir).map_err(|e| -> BoxError {
        format!("{test_name}: cannot create source dir: {e}").into()
    })?;
    let entry = ipe_dir.join("Main.ipe");
    std::fs::write(&entry, PROGRAM)
        .map_err(|e| -> BoxError { format!("{test_name}: cannot write Main.ipe: {e}").into() })?;

    let out_dir = scratch.join(format!("secured_store_e2e_{test_name}_emitted"));
    let _ = std::fs::remove_dir_all(&out_dir);
    let runtime = e2e_support::require_runtime().into_path_buf();
    let options = ipe::BuildOptions {
        intent: ipe_backend_rust::BuildIntent::Development,
        ..ipe::BuildOptions::from_env()
    };
    ipe::build_with_options(&entry, &out_dir, &runtime, options)
        .map_err(|e| -> BoxError { format!("{test_name}: ipe build failed: {e}").into() })?;
    let exe = e2e_support::build_rust_binary(test_name, &out_dir)
        .map_err(|e| -> BoxError { format!("{test_name}: cargo build failed: {e}").into() })?;
    Ok(PathBuf::from(exe))
}

/// A fresh, empty directory for the test's SQLite file.
///
/// # Errors
///
/// Returns an error if the directory cannot be recreated.
fn fresh_db_path(test_name: &str) -> Result<PathBuf, BoxError> {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("secured_store_e2e_{test_name}_db"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)
        .map_err(|e| -> BoxError { format!("{test_name}: cannot create db dir: {e}").into() })?;
    Ok(dir.join("secured.db"))
}

/// Reserves a loopback port by binding and dropping a listener.
///
/// # Errors
///
/// Returns an error if the OS refuses to bind.
fn pick_ephemeral_port() -> Result<u16, BoxError> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|e| -> BoxError { format!("cannot bind ephemeral port: {e}").into() })?;
    Ok(listener
        .local_addr()
        .map_err(|e| -> BoxError { format!("cannot read ephemeral port: {e}").into() })?
        .port())
}

/// Kills and reaps the wrapped server process on drop.
struct ProcessGuard(Child);

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Spawns the server and waits, at most [`READY_TIMEOUT`], for its ready line.
///
/// # Errors
///
/// Returns an error if the binary cannot start or never reports readiness.
fn spawn_server(
    test_name: &str,
    exe: &Path,
    port: u16,
    db: &Path,
) -> Result<ProcessGuard, BoxError> {
    let mut child = Command::new(exe)
        .env("IPE_SERVER_PORT", port.to_string())
        .env("IPE_HTTP_BIND", "127.0.0.1")
        .env("STORE_DB", db)
        .stderr(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .map_err(|e| -> BoxError { format!("{test_name}: cannot spawn server: {e}").into() })?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| -> BoxError { format!("{test_name}: no stderr pipe").into() })?;
    let guard = ProcessGuard(child);

    // `read_line` blocks, so the stderr reader runs on its own thread and the
    // deadline is enforced on the channel. The thread keeps draining stderr
    // so the server never blocks on a full pipe; it ends when the guard kills
    // the server and the pipe closes.
    let (tx, rx) = std::sync::mpsc::channel::<bool>();
    std::thread::Builder::new().spawn(move || {
        let mut reader = BufReader::new(stderr);
        let mut line = String::new();
        let mut signalled = false;
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    if !signalled && line.contains("[ipe.http.server] listening on") {
                        signalled = true;
                        let _ = tx.send(true);
                    }
                }
            }
        }
        if !signalled {
            let _ = tx.send(false);
        }
    })?;
    match rx.recv_timeout(READY_TIMEOUT) {
        Ok(true) => Ok(guard),
        Ok(false) => Err(format!("{test_name}: server exited before it was ready").into()),
        Err(_) => Err(format!("{test_name}: server not ready within {READY_TIMEOUT:?}").into()),
    }
}

/// The bearer tokens the cases run under.
struct Tokens {
    alice: String,
    editor: String,
    bob: String,
}

/// A connection target for the served program.
struct Client {
    test_name: &'static str,
    addr: String,
}

impl Client {
    /// Sends one request and returns its body, requiring status 200.
    ///
    /// # Errors
    ///
    /// Returns an error on a socket failure, a malformed response, or a
    /// status other than 200.
    fn send(&self, request: &str) -> Result<String, BoxError> {
        let name = self.test_name;
        let mut stream = TcpStream::connect(&self.addr)
            .map_err(|e| -> BoxError { format!("{name}: cannot connect: {e}").into() })?;
        stream
            .set_read_timeout(Some(IO_TIMEOUT))
            .map_err(|e| -> BoxError { format!("{name}: set_read_timeout: {e}").into() })?;
        stream
            .set_write_timeout(Some(IO_TIMEOUT))
            .map_err(|e| -> BoxError { format!("{name}: set_write_timeout: {e}").into() })?;
        stream
            .write_all(request.as_bytes())
            .map_err(|e| -> BoxError { format!("{name}: write failed: {e}").into() })?;
        let mut buf = Vec::with_capacity(4096);
        stream
            .read_to_end(&mut buf)
            .map_err(|e| -> BoxError { format!("{name}: read failed: {e}").into() })?;
        let response = String::from_utf8_lossy(&buf).into_owned();
        let (head, body) = response.split_once("\r\n\r\n").ok_or_else(|| -> BoxError {
            format!("{name}: no header/body separator in {response:?}").into()
        })?;
        let status = head.split_whitespace().nth(1).unwrap_or("");
        if status != "200" {
            return Err(format!("{name}: status {status} for {request:?}: {response:?}").into());
        }
        Ok(body.to_owned())
    }

    /// Sends `GET path`.
    ///
    /// # Errors
    ///
    /// As [`Client::send`].
    fn get(&self, path: &str) -> Result<String, BoxError> {
        self.send(&format!(
            "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
        ))
    }

    /// Runs one secured-write case as the bearer of `token`.
    ///
    /// # Errors
    ///
    /// As [`Client::send`].
    fn run(&self, token: &str, case: &str) -> Result<String, BoxError> {
        self.send(&format!(
            "POST /run/{case} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {token}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        ))
    }

    /// Returns the rows of `table`, as `GET /dump/:table` renders them.
    ///
    /// # Errors
    ///
    /// As [`Client::send`].
    fn dump(&self, table: &str) -> Result<String, BoxError> {
        self.get(&format!("/dump/{table}"))
    }

    /// Returns a signed token for `who`.
    ///
    /// # Errors
    ///
    /// As [`Client::send`], or when the body is an `err:` answer.
    fn token(&self, who: &str) -> Result<String, BoxError> {
        let body = self.get(&format!("/token/{who}"))?;
        if body.is_empty() || body.starts_with("err:") {
            return Err(format!("{}: no token for {who}: {body:?}", self.test_name).into());
        }
        Ok(body)
    }
}

/// Asserts a case's count and the table it wrote, in one labelled check.
fn expect(case: &str, count: &str, want_count: &str, dump: &str, want_dump: &str) {
    assert_eq!(count, want_count, "{case}: unexpected count");
    assert_eq!(dump, want_dump, "{case}: unexpected table contents");
}

/// Checks the insert predicate of `readOnly` and `alsoInsert (role ..)`.
///
/// `readOnly always` refuses an insert; `alsoInsert (role "editor")` keeps it
/// only for a caller holding the role.
///
/// # Errors
///
/// Propagates any request error.
fn insert_policy_cases(c: &Client, t: &Tokens) -> Result<(), BoxError> {
    let n = c.run(&t.alice, "read-only-insert")?;
    expect("read-only insert", &n, "0", &c.dump("read_only")?, "");

    let n = c.run(&t.alice, "role-insert")?;
    expect(
        "role insert without the role",
        &n,
        "0",
        &c.dump("by_role")?,
        "",
    );
    let n = c.run(&t.editor, "role-insert")?;
    expect(
        "role insert with the role",
        &n,
        "1",
        &c.dump("by_role")?,
        "n1|alice|draft|new",
    );
    Ok(())
}

/// Checks the owner column and the update predicate of `updateAs`.
///
/// An update never rewrites the owner column, even for a caller the update
/// predicate admits on another owner's row; it cannot reach another caller's
/// row under the owner scope; and it is rolled back when the stored row leaves the update predicate.
///
/// # Errors
///
/// Propagates any request error.
fn update_policy_cases(c: &Client, t: &Tokens) -> Result<(), BoxError> {
    let n = c.run(&t.alice, "owner-update")?;
    expect(
        "owner update",
        &n,
        "1",
        &c.dump("owned")?,
        "n1|alice|draft|edited",
    );
    let n = c.run(&t.bob, "owner-update")?;
    expect(
        "update of another owner's row",
        &n,
        "0",
        &c.dump("owned")?,
        "n1|alice|draft|edited",
    );

    // Another caller may update the row, but the owner column stays put.
    let n = c.run(&t.bob, "owner-kept")?;
    expect(
        "update by another caller under an open update predicate",
        &n,
        "1",
        &c.dump("open_edit")?,
        "n1|alice|draft|bob-edit",
    );

    let n = c.run(&t.alice, "draft-publish")?;
    expect(
        "update out of the update predicate",
        &n,
        "0",
        &c.dump("drafts")?,
        "n1|alice|draft|seed;n2|alice|draft|seed",
    );
    let n = c.run(&t.alice, "draft-edit")?;
    expect(
        "update within the update predicate",
        &n,
        "1",
        &c.dump("drafts")?,
        "n1|alice|draft|seed;n2|alice|draft|edited",
    );
    Ok(())
}

/// Checks a correlated `existsIn`, a transaction, and a `NULL` check value.
///
/// The share check is a correlated subquery over the stored row; the refused
/// write inside `Db.withTransaction` leaves the transaction usable; a check
/// that reads `NULL` refuses, while the same insert under a non-`NULL` check
/// is kept.
///
/// # Errors
///
/// Propagates any request error.
fn check_shape_cases(c: &Client, t: &Tokens) -> Result<(), BoxError> {
    let n = c.run(&t.alice, "shared-insert")?;
    expect("insert without a share", &n, "0", &c.dump("docs")?, "");
    assert_eq!(c.get("/share")?, "1", "share row inserted");
    let n = c.run(&t.alice, "shared-insert")?;
    expect(
        "insert with a share",
        &n,
        "1",
        &c.dump("docs")?,
        "d1|alice|draft|new",
    );

    // `refused * 10 + kept`: the refused secured insert counts 0 and the
    // public insert after it, in the same transaction, counts 1.
    let n = c.run(&t.alice, "transaction")?;
    expect(
        "refused write inside a transaction",
        &n,
        "1",
        &c.dump("txn")?,
        "n2|alice|draft|public",
    );

    let n = c.run(&t.alice, "null-check")?;
    expect("check over a NULL column", &n, "0", &c.dump("stamped")?, "");
    let n = c.run(&t.alice, "non-null-check")?;
    expect(
        "check over a non-NULL column",
        &n,
        "1",
        &c.dump("stamped")?,
        "n2|alice|NULL|new",
    );
    Ok(())
}

/// The scratch-directory and diagnostic name of the one e2e test.
const NAME: &str = "secured_writes_keep_only_admitted_rows";

/// Every secured write keeps only a row its policy admits, over a live server.
///
/// # Errors
///
/// Propagates any pipeline, build, spawn, or request error.
#[test]
fn secured_writes_keep_only_admitted_rows() -> Result<(), BoxError> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }
    let exe = compile_and_build(NAME)?;
    let db = fresh_db_path(NAME)?;
    let port = pick_ephemeral_port()?;
    let _server = spawn_server(NAME, &exe, port, &db)?;
    let client = Client {
        test_name: NAME,
        addr: format!("127.0.0.1:{port}"),
    };

    // SQLite reports a DDL statement's count as the last DML's, so the setup
    // total is not a row count; the seed rows are checked through the dumps.
    let setup = client.get("/setup")?;
    assert!(
        setup.parse::<u64>().is_ok(),
        "setup must answer a count, got {setup:?}"
    );
    assert_eq!(
        client.dump("owned")?,
        "n1|alice|draft|seed",
        "setup: the seed row"
    );
    let tokens = Tokens {
        alice: client.token("alice")?,
        editor: client.token("editor")?,
        bob: client.token("bob")?,
    };

    insert_policy_cases(&client, &tokens)?;
    update_policy_cases(&client, &tokens)?;
    check_shape_cases(&client, &tokens)?;
    Ok(())
}
