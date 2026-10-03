#![forbid(unsafe_code)]
//! End-to-end: the real `ipe lsp` binary over stdio JSON-RPC framing,
//! against a real on-disk project (sibling discovery + embedded-stdlib
//! injection). Proves the full vertical slice: handshake → didOpen (buffer
//! overlay shadows disk) → compiler diagnostics → didChange → cleared.

use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

mod support;

const CLEAN: &str = "module Main exposing (main)\n\n\
    import Ipe.Io as Io\n\n\
    main = Io.println \"hi\"\n";
const TYPE_ERROR: &str = "module Main exposing (main)\n\n\
    import Ipe.Io as Io\n\n\
    answer : Int\n\
    answer = \"nope\"\n\n\
    main = Io.println \"hi\"\n";

/// Kills the spawned server on scope exit so a failing assertion never
/// leaks an `ipe lsp` process.
struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[allow(clippy::expect_used)] // test helper: a broken pipe IS the failure
fn write_msg(stdin: &mut impl Write, value: &serde_json::Value) {
    let body = value.to_string();
    write!(stdin, "Content-Length: {}\r\n\r\n{body}", body.len()).expect("write frame");
    stdin.flush().expect("flush frame");
}

fn read_msg(reader: &mut BufReader<impl Read>) -> Option<serde_json::Value> {
    let mut content_length: Option<usize> = None;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).ok()? == 0 {
            return None;
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some(value) = line.strip_prefix("Content-Length:") {
            content_length = value.trim().parse().ok();
        }
    }
    let len = content_length?;
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).ok()?;
    serde_json::from_slice(&buf).ok()
}

#[allow(clippy::expect_used)] // test helper: silence past the deadline IS the failure
fn await_diagnostics(
    rx: &mpsc::Receiver<serde_json::Value>,
    uri: &str,
    accept: impl Fn(&[serde_json::Value]) -> bool,
) -> Vec<serde_json::Value> {
    loop {
        let msg = rx
            .recv_timeout(Duration::from_mins(1))
            .expect("diagnostics push within deadline");
        if msg.get("method").and_then(serde_json::Value::as_str)
            != Some("textDocument/publishDiagnostics")
        {
            continue;
        }
        let params = msg.get("params").cloned().unwrap_or_default();
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

#[allow(clippy::expect_used)] // test helper: silence past the deadline IS the failure
fn await_response(rx: &mpsc::Receiver<serde_json::Value>, id: i64) -> serde_json::Value {
    loop {
        let msg = rx
            .recv_timeout(Duration::from_mins(1))
            .expect("response within deadline");
        if msg.get("id").and_then(serde_json::Value::as_i64) == Some(id) {
            assert!(
                msg.get("error").is_none_or(serde_json::Value::is_null),
                "error reply: {msg}"
            );
            return msg.get("result").cloned().unwrap_or_default();
        }
    }
}

#[test]
#[allow(clippy::too_many_lines)] // one linear protocol script, deliberately unsplit
fn stdio_server_serves_live_diagnostics_for_a_real_project() {
    // A real project on disk: sibling discovery, disk starts CLEAN.
    let dir = crate::support::scratch_root().join(format!("ipe_lsp_e2e_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create project dir");
    let dir = std::fs::canonicalize(&dir).expect("canonical project dir");
    let main_path: PathBuf = dir.join("Main.ipe");
    std::fs::write(&main_path, CLEAN).expect("write Main.ipe");
    let uri = format!("file://{}", main_path.display());

    let mut child = ChildGuard(
        Command::new(support::ipe_bin())
            .arg("lsp")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn ipe lsp"),
    );
    let mut stdin = child.0.stdin.take().expect("child stdin");
    let stdout = child.0.stdout.take().expect("child stdout");

    // Reader thread → channel, so every wait is timeout-bounded.
    let (tx, rx) = mpsc::channel::<serde_json::Value>();
    std::thread::Builder::new()
        .spawn(move || {
            let mut reader = BufReader::new(stdout);
            while let Some(msg) = read_msg(&mut reader) {
                if tx.send(msg).is_err() {
                    return;
                }
            }
        })
        .expect("spawn test thread");

    write_msg(
        &mut stdin,
        &serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "capabilities": {},
                "rootUri": format!("file://{}", dir.display())
            }
        }),
    );
    let init = await_response(&rx, 1);
    assert!(
        init.get("capabilities")
            .and_then(|c| c.get("textDocumentSync"))
            .is_some(),
        "{init}"
    );
    write_msg(
        &mut stdin,
        &serde_json::json!({
            "jsonrpc": "2.0", "method": "initialized", "params": {}
        }),
    );

    // Open with a type error the DISK does not have — the overlay must win.
    write_msg(
        &mut stdin,
        &serde_json::json!({
            "jsonrpc": "2.0", "method": "textDocument/didOpen",
            "params": { "textDocument": {
                "uri": uri, "languageId": "ipe", "version": 1, "text": TYPE_ERROR
            } }
        }),
    );
    let diags = await_diagnostics(&rx, &uri, |diags| !diags.is_empty());
    assert_eq!(diags.len(), 1, "{diags:?}");
    let diag = diags.first().expect("one diagnostic");
    assert_eq!(
        diag.get("code").and_then(serde_json::Value::as_str),
        Some("IPE-T0001"),
        "{diag}"
    );
    assert_eq!(
        diag.pointer("/range/start/line")
            .and_then(serde_json::Value::as_i64),
        Some(5),
        "range points at the failing literal: {diag}"
    );

    // Fix the buffer → the diagnostic clears.
    write_msg(
        &mut stdin,
        &serde_json::json!({
            "jsonrpc": "2.0", "method": "textDocument/didChange",
            "params": {
                "textDocument": { "uri": uri, "version": 2 },
                "contentChanges": [{ "text": CLEAN }]
            }
        }),
    );
    let cleared = await_diagnostics(&rx, &uri, <[serde_json::Value]>::is_empty);
    assert!(cleared.is_empty());

    // Clean shutdown.
    write_msg(
        &mut stdin,
        &serde_json::json!({
            "jsonrpc": "2.0", "id": 2, "method": "shutdown", "params": null
        }),
    );
    let _ = await_response(&rx, 2);
    write_msg(
        &mut stdin,
        &serde_json::json!({ "jsonrpc": "2.0", "method": "exit", "params": null }),
    );
    // Bounded exit wait — a wedged shutdown must fail the test, not hang it.
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.0.try_wait().expect("poll child") {
            break status;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "server did not exit within 30s of `exit`"
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(status.success(), "server exits 0, got {status}");
    let _ = std::fs::remove_dir_all(&dir);
}
