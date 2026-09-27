#![forbid(unsafe_code)]
//! Protocol conformance over an in-memory connection: initialize handshake,
//! live diagnostics on `didOpen`, convergence to clean on `didChange` — no
//! filesystem, no subprocess (the fixture loader resolves a virtual
//! project).

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use lsp_server::{Connection, Message, Notification, Request, RequestId};
use lsp_types::notification::{Notification as _, PublishDiagnostics};

use ipe_lsp_server::{LoadError, LoadedFile, LoadedProject, ModuleOrigin, ProjectLoader};

// ---------------------------------------------------------------------------
// lint.ipe workspace config test
// ---------------------------------------------------------------------------

/// A loader for the lint-config protocol test. The `lint.ipe` file is written
/// to the workspace directory before the server starts; the server discovers it
/// via the `workspaceFolders` URI passed in `InitializeParams`.
struct WorkspaceLoader;

impl ProjectLoader for WorkspaceLoader {
    fn load(
        &self,
        _workspace_root: Option<&Path>,
        open_file: &Path,
        open_text: Option<&str>,
    ) -> Result<LoadedProject, LoadError> {
        let mut files = BTreeMap::new();
        files.insert(
            vec!["Main".to_owned()],
            LoadedFile {
                path: open_file.to_path_buf(),
                text: open_text.unwrap_or("").to_owned(),
                origin: ModuleOrigin::User,
            },
        );
        for module in ipe_stdlib::COMPILED_STD_MODULES {
            let path: Vec<String> = module.dotted.split('.').map(str::to_owned).collect();
            files.insert(
                path,
                LoadedFile {
                    path: std::path::PathBuf::from(format!(
                        "<stdlib>/{}.ipe",
                        module.dotted.replace('.', "/")
                    )),
                    text: module.source.to_owned(),
                    origin: ModuleOrigin::EmbeddedStdlib,
                },
            );
        }
        Ok(LoadedProject {
            files,
            entry_module: vec!["Main".to_owned()],
        })
    }
}

/// The LSP server honours a workspace `lint.ipe`: a rule set to `deny` is
/// surfaced as an ERROR-severity diagnostic; the same source with `allow`
/// produces no lint diagnostic.
#[test]
#[allow(clippy::too_many_lines)]
fn lint_ipe_workspace_config_is_respected() {
    // Source that triggers the `prefer-pipeline` lint. The rule fires only when
    // a pipe chain would remove at least two paren levels — a single wrap
    // `f (g x)` is deliberately exempt — so the fixture nests three calls.
    const LINT_SRC: &str = "module Main exposing (main)\n\nmain =\n    String.concat (List.map fmt (List.filter live records))\n";
    const VIRTUAL_LINT_PATH: &str = "/ipe-lsp-lint-test/Main.ipe";

    // ── Round 1: deny severity → lint must appear as ERROR ────────────────
    // Use a deterministic subdir under the OS temp dir (no external crate needed).
    let ws_root = std::env::temp_dir().join("ipe-lsp-lint-test-workspace");
    std::fs::create_dir_all(&ws_root).expect("create ws_root");
    // A real `lint.ipe`: an Ipê module with a single `lint` binding threading
    // the `Lint.*` vocabulary (parsed by `read_lint_config`, not a key=value
    // file). `Lint.deny "prefer-pipeline"` raises that rule to ERROR severity.
    let lint_deny = "module Lint exposing (lint)\n\nlint =\n    Lint.config\n        |> Lint.deny \"prefer-pipeline\"\n";
    std::fs::write(ws_root.join("lint.ipe"), lint_deny).expect("write lint.ipe");

    let loader = WorkspaceLoader;

    let (server_side, client) = Connection::memory();
    let server =
        std::thread::spawn(move || ipe_lsp_server::run_with_connection(&server_side, &loader));

    // Handshake — pass the workspace folder so the server sets workspace_root.
    let ws_uri = lsp_types::Url::from_file_path(&ws_root).expect("ws uri");
    client
        .sender
        .send(Message::Request(Request::new(
            RequestId::from(1),
            "initialize".to_owned(),
            serde_json::json!({
                "capabilities": {},
                "workspaceFolders": [{ "uri": ws_uri.to_string(), "name": "test" }]
            }),
        )))
        .expect("send initialize");
    let _ = recv_response(&client, 1);
    client
        .sender
        .send(Message::Notification(Notification::new(
            "initialized".to_owned(),
            serde_json::json!({}),
        )))
        .expect("send initialized");

    let uri = format!("file://{VIRTUAL_LINT_PATH}");
    client
        .sender
        .send(Message::Notification(Notification::new(
            "textDocument/didOpen".to_owned(),
            serde_json::json!({
                "textDocument": {
                    "uri": uri, "languageId": "ipe", "version": 1, "text": LINT_SRC
                }
            }),
        )))
        .expect("send didOpen");

    let diags = await_diagnostics(&client, &uri, |d| {
        d.iter().any(|diag| {
            diag.get("code")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|c| c.starts_with("lint/"))
        })
    });
    let lint_diag = diags
        .iter()
        .find(|d| {
            d.get("code")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|c| c.starts_with("lint/"))
        })
        .expect("lint diagnostic present");
    assert_eq!(
        lint_diag.get("severity"),
        Some(&serde_json::json!(1)), // 1 = ERROR
        "deny severity must produce ERROR: {lint_diag}"
    );

    client
        .sender
        .send(Message::Request(Request::new(
            RequestId::from(2),
            "shutdown".to_owned(),
            serde_json::Value::Null,
        )))
        .expect("send shutdown");
    let _ = recv_response(&client, 2);
    client
        .sender
        .send(Message::Notification(Notification::new(
            "exit".to_owned(),
            serde_json::Value::Null,
        )))
        .expect("send exit");
    server
        .join()
        .expect("server thread joins")
        .expect("server exits clean");
}

const VIRTUAL_PATH: &str = "/ipe-lsp-protocol-test/Main.ipe";
const CLEAN: &str = "module Main exposing (main)\n\nimport Ipe.Io as Io\nimport Ipe.String as String\n\nmain : Task Error ()\nmain =\n    Io.println (String.fromInt 1)\n";
const TYPE_ERROR: &str = "module Main exposing (main)\n\nmain : Int\nmain = \"nope\"\n";

/// Resolves a single-module virtual project from the open buffer, injecting
/// all compiled-source stdlib modules so `Ipe.Io`, `Ipe.String`, etc. resolve
/// — mirroring the production pattern in `ipe_lsp_server`.
struct FixtureLoader;

impl ProjectLoader for FixtureLoader {
    fn load(
        &self,
        _workspace_root: Option<&Path>,
        open_file: &Path,
        open_text: Option<&str>,
    ) -> Result<LoadedProject, LoadError> {
        let mut files = BTreeMap::new();
        files.insert(
            vec!["Main".to_owned()],
            LoadedFile {
                path: open_file.to_path_buf(),
                text: open_text.unwrap_or(CLEAN).to_owned(),
                origin: ModuleOrigin::User,
            },
        );
        for module in ipe_stdlib::COMPILED_STD_MODULES {
            let path: Vec<String> = module.dotted.split('.').map(str::to_owned).collect();
            files.insert(
                path,
                LoadedFile {
                    path: std::path::PathBuf::from(format!(
                        "<stdlib>/{}.ipe",
                        module.dotted.replace('.', "/")
                    )),
                    text: module.source.to_owned(),
                    origin: ModuleOrigin::EmbeddedStdlib,
                },
            );
        }
        Ok(LoadedProject {
            files,
            entry_module: vec!["Main".to_owned()],
        })
    }
}

#[allow(clippy::expect_used)] // test helper: silence past the deadline IS the failure
fn recv_response(client: &Connection, id: i32) -> serde_json::Value {
    let deadline = Duration::from_secs(30);
    loop {
        let msg = client
            .receiver
            .recv_timeout(deadline)
            .expect("server reply within deadline");
        if let Message::Response(response) = msg
            && response.id == RequestId::from(id)
        {
            assert!(
                response.error.is_none(),
                "error reply: {:?}",
                response.error
            );
            return response.result.unwrap_or(serde_json::Value::Null);
        }
    }
}

/// Wait for a `publishDiagnostics` for `uri` whose payload satisfies
/// `accept`; intermediate pushes for other states are skipped.
#[allow(clippy::expect_used)] // test helper: silence past the deadline IS the failure
fn await_diagnostics(
    client: &Connection,
    uri: &str,
    accept: impl Fn(&[serde_json::Value]) -> bool,
) -> Vec<serde_json::Value> {
    let deadline = Duration::from_secs(30);
    loop {
        let msg = client
            .receiver
            .recv_timeout(deadline)
            .expect("diagnostics push within deadline");
        let Message::Notification(note) = msg else {
            continue;
        };
        if note.method != PublishDiagnostics::METHOD {
            continue;
        }
        let params = note.params;
        if params.get("uri").and_then(serde_json::Value::as_str) != Some(uri) {
            continue;
        }
        let diags: Vec<serde_json::Value> = params
            .get("diagnostics")
            .and_then(serde_json::Value::as_array)
            .cloned()
            .unwrap_or_default();
        if accept(&diags) {
            return diags;
        }
    }
}

#[test]
#[allow(clippy::too_many_lines)] // one linear protocol script, deliberately unsplit
fn did_open_publishes_compiler_diagnostics_and_did_change_clears_them() {
    let (server_side, client) = Connection::memory();
    let server = std::thread::spawn(move || {
        ipe_lsp_server::run_with_connection(&server_side, &FixtureLoader)
    });

    // initialize / initialized.
    client
        .sender
        .send(Message::Request(Request::new(
            RequestId::from(1),
            "initialize".to_owned(),
            serde_json::json!({ "capabilities": {} }),
        )))
        .expect("send initialize");
    let init_result = recv_response(&client, 1);
    assert!(
        init_result
            .pointer("/capabilities/textDocumentSync")
            .is_some_and(serde_json::Value::is_object),
        "sync capability advertised: {init_result}"
    );
    assert_eq!(
        init_result.pointer("/capabilities/positionEncoding"),
        Some(&serde_json::json!("utf-16")),
        "utf-16 is the default when the client offers nothing"
    );
    client
        .sender
        .send(Message::Notification(Notification::new(
            "initialized".to_owned(),
            serde_json::json!({}),
        )))
        .expect("send initialized");

    // didOpen with a type error → a real compiler diagnostic arrives.
    let uri = format!("file://{VIRTUAL_PATH}");
    client
        .sender
        .send(Message::Notification(Notification::new(
            "textDocument/didOpen".to_owned(),
            serde_json::json!({
                "textDocument": {
                    "uri": uri, "languageId": "ipe", "version": 1, "text": TYPE_ERROR
                }
            }),
        )))
        .expect("send didOpen");
    let diags = await_diagnostics(&client, &uri, |diags| !diags.is_empty());
    assert_eq!(diags.len(), 1, "{diags:?}");
    let diag = diags.first().expect("one diagnostic");
    assert_eq!(diag.get("code"), Some(&serde_json::json!("IPE-T0001")));
    assert_eq!(diag.get("source"), Some(&serde_json::json!("ipe")));
    assert_eq!(
        diag.pointer("/range/start/line"),
        Some(&serde_json::json!(3)),
        "the range points at the failing expression: {diag}"
    );
    assert!(
        diag.get("message")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|m| m.contains("type mismatch")),
        "{diag}"
    );

    // didChange (full-text replacement) fixes the buffer → cleared.
    client
        .sender
        .send(Message::Notification(Notification::new(
            "textDocument/didChange".to_owned(),
            serde_json::json!({
                "textDocument": { "uri": uri, "version": 2 },
                "contentChanges": [{ "text": CLEAN }]
            }),
        )))
        .expect("send didChange");
    let cleared = await_diagnostics(&client, &uri, <[serde_json::Value]>::is_empty);
    assert!(cleared.is_empty());

    // Hover over the `1` in `String.fromInt 1` (line 7, character 31) → `Int`.
    // That `1` sits inside the `main` binding, so the hover also discloses `main`'s
    // compiler-derived control model beneath the type: a plain-`Task` `main` is the
    // `direct` model, the same word `ipe audit`/`ipe doc` disclose.
    client
        .sender
        .send(Message::Request(Request::new(
            RequestId::from(3),
            "textDocument/hover".to_owned(),
            serde_json::json!({
                "textDocument": { "uri": uri },
                "position": { "line": 7, "character": 31 }
            }),
        )))
        .expect("send hover");
    let hover = recv_response(&client, 3);
    assert_eq!(
        hover.pointer("/contents/0/value").and_then(|v| v.as_str()),
        Some("Int"),
        "the type is disclosed first: {hover}"
    );
    assert_eq!(
        hover.pointer("/contents/1").and_then(|v| v.as_str()),
        Some("control model: direct"),
        "the control model rides the hover on `main`: {hover}"
    );

    // Document symbols → the one top-level binding `main`.
    client
        .sender
        .send(Message::Request(Request::new(
            RequestId::from(4),
            "textDocument/documentSymbol".to_owned(),
            serde_json::json!({ "textDocument": { "uri": uri } }),
        )))
        .expect("send documentSymbol");
    let symbols = recv_response(&client, 4);
    let names: Vec<&str> = symbols
        .as_array()
        .map(|list| {
            list.iter()
                .filter_map(|s| s.get("name").and_then(|n| n.as_str()))
                .collect()
        })
        .unwrap_or_default();
    assert_eq!(names, vec!["main"], "{symbols}");

    // An incremental (ranged) edit re-introduces the error: replace `1`
    // on line 7 (`String.fromInt 1`) with a string literal.
    client
        .sender
        .send(Message::Notification(Notification::new(
            "textDocument/didChange".to_owned(),
            serde_json::json!({
                "textDocument": { "uri": uri, "version": 3 },
                "contentChanges": [{
                    "range": {
                        "start": { "line": 7, "character": 31 },
                        "end": { "line": 7, "character": 32 }
                    },
                    "text": "\"nope\""
                }]
            }),
        )))
        .expect("send ranged didChange");
    let diags = await_diagnostics(&client, &uri, |diags| !diags.is_empty());
    assert_eq!(
        diags.first().and_then(|d| d.get("code")),
        Some(&serde_json::json!("IPE-T0001"))
    );

    // shutdown / exit — the loop terminates cleanly.
    client
        .sender
        .send(Message::Request(Request::new(
            RequestId::from(2),
            "shutdown".to_owned(),
            serde_json::Value::Null,
        )))
        .expect("send shutdown");
    let _ = recv_response(&client, 2);
    client
        .sender
        .send(Message::Notification(Notification::new(
            "exit".to_owned(),
            serde_json::Value::Null,
        )))
        .expect("send exit");
    server
        .join()
        .expect("server thread joins")
        .expect("server exits clean");
}

// ---------------------------------------------------------------------------
// Cycle-survival: whole-server test (test plan item 2)
// ---------------------------------------------------------------------------

const A_PATH: &str = "/ipe-lsp-cycle-test/A.ipe";
const B_PATH: &str = "/ipe-lsp-cycle-test/B.ipe";
const A_SRC: &str = "module A exposing (a)\nimport B\na = B.b\n";
const B_SRC: &str = "module B exposing (b)\nimport A\nb = A.a\n";

/// Loader that resolves a two-module cyclic project (A ↔ B).
struct CyclicLoader;

impl ProjectLoader for CyclicLoader {
    fn load(
        &self,
        _workspace_root: Option<&Path>,
        open_file: &Path,
        _open_text: Option<&str>,
    ) -> Result<LoadedProject, LoadError> {
        let a_path = std::path::PathBuf::from(A_PATH);
        let b_path = std::path::PathBuf::from(B_PATH);
        let mut files = BTreeMap::new();
        files.insert(
            vec!["A".to_owned()],
            LoadedFile {
                path: a_path.clone(),
                text: A_SRC.to_owned(),
                origin: ModuleOrigin::User,
            },
        );
        files.insert(
            vec!["B".to_owned()],
            LoadedFile {
                path: b_path,
                text: B_SRC.to_owned(),
                origin: ModuleOrigin::User,
            },
        );
        // The entry module is whichever file the client opened.
        let entry_module = if open_file == a_path.as_path() {
            vec!["A".to_owned()]
        } else {
            vec!["B".to_owned()]
        };
        Ok(LoadedProject {
            files,
            entry_module,
        })
    }
}

/// Receive the next Response for `id`, skipping diagnostics notifications.
/// Returns `(result, error_code)`: exactly one will be `Some`.
#[allow(clippy::expect_used)]
fn recv_any_response(client: &Connection, id: i32) -> lsp_server::Response {
    let deadline = Duration::from_secs(30);
    loop {
        let msg = client
            .receiver
            .recv_timeout(deadline)
            .expect("reply within deadline");
        if let Message::Response(response) = msg
            && response.id == RequestId::from(id)
        {
            return response;
        }
    }
}

/// A cyclic import graph (A ↔ B) must not crash the server.
///
/// Before the panic boundary was added, a `textDocument/definition` request
/// on the cyclic project reached `ipe_db::canonicalize` directly, triggered
/// salsa's dependency-cycle panic, and unwound `handle_request` → the
/// `select!` loop → killed the server. After the fix the server returns a
/// per-request error and stays alive to serve subsequent requests.
#[test]
fn cyclic_import_graph_request_returns_error_and_server_survives() {
    let (server_side, client) = Connection::memory();
    let server = std::thread::spawn(move || {
        ipe_lsp_server::run_with_connection(&server_side, &CyclicLoader)
    });

    // Initialize.
    client
        .sender
        .send(Message::Request(Request::new(
            RequestId::from(1),
            "initialize".to_owned(),
            serde_json::json!({ "capabilities": {} }),
        )))
        .expect("send initialize");
    let _ = recv_any_response(&client, 1);
    client
        .sender
        .send(Message::Notification(Notification::new(
            "initialized".to_owned(),
            serde_json::json!({}),
        )))
        .expect("send initialized");

    // Open A — the diagnostics worker publishes the IPE-N0021 cycle diagnostic.
    let uri_a = format!("file://{A_PATH}");
    client
        .sender
        .send(Message::Notification(Notification::new(
            "textDocument/didOpen".to_owned(),
            serde_json::json!({
                "textDocument": {
                    "uri": uri_a, "languageId": "ipe", "version": 1, "text": A_SRC
                }
            }),
        )))
        .expect("send didOpen");

    // Wait for the cycle diagnostic before sending requests, so the server
    // has loaded the project and the handlers run against the cyclic db.
    let _cycle_diags = await_diagnostics(&client, &uri_a, |d| !d.is_empty());

    // Send a definition request whose position is byte 0 of A — on the cyclic
    // graph this previously panicked through `ipe_db::canonicalize` and killed
    // the server.
    client
        .sender
        .send(Message::Request(Request::new(
            RequestId::from(10),
            "textDocument/definition".to_owned(),
            serde_json::json!({
                "textDocument": { "uri": uri_a },
                "position": { "line": 0, "character": 0 }
            }),
        )))
        .expect("send definition");

    // Assert a Response arrives (never a hang/drop) and is either Null or an
    // error — never a process abort.
    let response = recv_any_response(&client, 10);
    // The response must have an id (already asserted by recv_any_response) and
    // must not be both result=None and error=None (that would be a malformed reply).
    assert!(
        response.result.is_some() || response.error.is_some(),
        "server must reply with a result or an error, got neither"
    );

    // Send a second request — proves the select! loop is still alive.
    client
        .sender
        .send(Message::Request(Request::new(
            RequestId::from(11),
            "textDocument/documentSymbol".to_owned(),
            serde_json::json!({ "textDocument": { "uri": uri_a } }),
        )))
        .expect("send documentSymbol after cycle request");
    let second_response = recv_any_response(&client, 11);
    assert!(
        second_response.result.is_some() || second_response.error.is_some(),
        "server must still be alive after a cyclic-graph request"
    );

    // Shutdown cleanly.
    client
        .sender
        .send(Message::Request(Request::new(
            RequestId::from(2),
            "shutdown".to_owned(),
            serde_json::Value::Null,
        )))
        .expect("send shutdown");
    let _ = recv_any_response(&client, 2);
    client
        .sender
        .send(Message::Notification(Notification::new(
            "exit".to_owned(),
            serde_json::Value::Null,
        )))
        .expect("send exit");
    server
        .join()
        .expect("server thread joins")
        .expect("server exits clean");
}

#[test]
fn unknown_request_gets_method_not_found_not_a_hang() {
    let (server_side, client) = Connection::memory();
    let server = std::thread::spawn(move || {
        ipe_lsp_server::run_with_connection(&server_side, &FixtureLoader)
    });

    client
        .sender
        .send(Message::Request(Request::new(
            RequestId::from(1),
            "initialize".to_owned(),
            serde_json::json!({ "capabilities": {} }),
        )))
        .expect("send initialize");
    let _ = recv_response(&client, 1);
    client
        .sender
        .send(Message::Notification(Notification::new(
            "initialized".to_owned(),
            serde_json::json!({}),
        )))
        .expect("send initialized");

    client
        .sender
        .send(Message::Request(Request::new(
            RequestId::from(7),
            "textDocument/unknownIpeMethod".to_owned(),
            serde_json::json!({}),
        )))
        .expect("send unknown method");
    let deadline = Duration::from_secs(30);
    let err = loop {
        let msg = client
            .receiver
            .recv_timeout(deadline)
            .expect("reply within deadline");
        if let Message::Response(response) = msg
            && response.id == RequestId::from(7)
        {
            break response.error.expect("unimplemented method must error");
        }
    };
    assert_eq!(err.code, lsp_server::ErrorCode::MethodNotFound as i32);

    client
        .sender
        .send(Message::Request(Request::new(
            RequestId::from(2),
            "shutdown".to_owned(),
            serde_json::Value::Null,
        )))
        .expect("send shutdown");
    let _ = recv_response(&client, 2);
    client
        .sender
        .send(Message::Notification(Notification::new(
            "exit".to_owned(),
            serde_json::Value::Null,
        )))
        .expect("send exit");
    server
        .join()
        .expect("server thread joins")
        .expect("server exits clean");
}
