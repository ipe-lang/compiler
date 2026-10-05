//! Integration tests for the machine-readable (`--json`) diagnostic output on
//! `ipe dev build`, `ipe dev run`, and `ipe type-check`.
//!
//! Verifies:
//! - A failing compile under `--json` emits valid, schema-conforming JSON on
//!   stderr and exits non-zero (fail-closed; SEAL unchanged).
//! - A successful type-check under `--json` emits the shared machine envelope
//!   (`ipe.cli.type-check/1`, `status:ok`, empty payload) on stdout and exits zero.
//! - Two successive runs of the same failing compile are byte-identical
//!   (determinism).
//! - Without `--json`, the human layout is still rendered (not broken).
//! - `--plain` and `--json` together are rejected as a usage error.
//!
//! All assertions run the built binary as a subprocess so exit codes and stream
//! routing are observable.
#![forbid(unsafe_code)]
// Fixture setup: a panicking `expect` IS the test failure signal.
#![allow(clippy::expect_used)]

use std::path::PathBuf;
use std::process::Command;

mod support;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

struct Run {
    ok: bool,
    stdout: String,
    stderr: String,
}

fn run_ipe(args: &[&str]) -> Run {
    match Command::new(support::ipe_bin())
        .args(args)
        .env("NO_COLOR", "1")
        .output()
    {
        Ok(output) => Run {
            ok: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        },
        Err(e) => Run {
            ok: false,
            stdout: String::new(),
            stderr: format!("failed to spawn ipe: {e}"),
        },
    }
}

fn fixture(name: &str) -> String {
    support::manifest_dir()
        .join("tests/fixtures/type_check")
        .join(name)
        .to_string_lossy()
        .into_owned()
}

// ---------------------------------------------------------------------------
// Schema contract check — applied to every line emitted by --json on failure.
// ---------------------------------------------------------------------------

/// Assert that `json` is a single well-formed JSON object carrying every field
/// in the stable schema. A field disappearing or changing type fails here.
fn assert_diagnostic_schema(json: &str) {
    // Parse as real JSON first, so a future invalid-escape regression in the
    // hand-rolled writer fails here — the substring checks below would not catch
    // malformed escaping.
    let parsed: serde_json::Value =
        serde_json::from_str(json).expect("diagnostic JSON must be well-formed JSON");
    assert!(
        parsed.is_object(),
        "diagnostic JSON must be a single object, got: {json:?}"
    );

    // Required string-valued fields.
    for field in &["code", "severity", "title", "message", "explain_ref"] {
        assert!(
            json.contains(&format!("\"{field}\":")),
            "diagnostic JSON missing {field:?} field, got: {json:?}"
        );
    }

    // Required array-valued fields (may be empty `[]`).
    for field in &["secondary_spans", "hints", "suggestions"] {
        assert!(
            json.contains(&format!("\"{field}\":")),
            "diagnostic JSON missing {field:?} field, got: {json:?}"
        );
    }

    // `primary_span` is required (object or `null`).
    assert!(
        json.contains("\"primary_span\":"),
        "diagnostic JSON missing \"primary_span\" field, got: {json:?}"
    );

    // Code must look like an IPE- code.
    assert!(
        json.contains("\"IPE-"),
        "code field must contain an IPE- prefix, got: {json:?}"
    );
}

// ---------------------------------------------------------------------------
// ipe type-check --json
// ---------------------------------------------------------------------------

#[test]
fn type_check_json_on_error_exits_nonzero_with_schema_conforming_json() {
    let r = run_ipe(&["type-check", "--json", &fixture("type_error.ipe")]);
    assert!(!r.ok, "a type-error program must exit non-zero");

    let stderr = r.stderr.trim();
    assert!(
        !stderr.is_empty(),
        "--json error output must not be empty; stdout: {:?}",
        r.stdout
    );

    // Every non-empty stderr line must be a schema-conforming JSON object.
    for line in stderr.lines().filter(|l| !l.trim().is_empty()) {
        assert_diagnostic_schema(line);
    }

    // stdout must be silent on failure.
    assert!(
        r.stdout.trim().is_empty(),
        "--json failure must not write to stdout, got: {:?}",
        r.stdout
    );
}

#[test]
fn type_check_json_on_success_exits_zero_with_ok_object() {
    let r = run_ipe(&["type-check", "--json", &fixture("well_typed.ipe")]);
    assert!(
        r.ok,
        "a well-typed program must exit 0; stderr: {}",
        r.stderr
    );

    assert_eq!(
        r.stdout.trim(),
        "{\"schema\":\"ipe.cli.type-check/1\",\"status\":\"ok\",\
         \"command\":\"type-check\",\"payload\":{}}",
        "--json success must emit the shared machine envelope, got: {:?}",
        r.stdout
    );

    assert!(
        r.stderr.trim().is_empty(),
        "--json success must not write to stderr, got: {:?}",
        r.stderr
    );
}

#[test]
fn type_check_json_diagnostic_is_deterministic() {
    let r1 = run_ipe(&["type-check", "--json", &fixture("type_error.ipe")]);
    let r2 = run_ipe(&["type-check", "--json", &fixture("type_error.ipe")]);
    assert_eq!(
        r1.stderr, r2.stderr,
        "--json diagnostic output must be byte-identical across runs"
    );
}

#[test]
fn type_check_json_contains_required_span_and_code_fields() {
    let r = run_ipe(&["type-check", "--json", &fixture("type_error.ipe")]);
    let stderr = r.stderr.trim();

    // type_error.ipe triggers IPE-T0001 (type mismatch).
    assert!(
        stderr.contains("IPE-T0001"),
        "IPE-T0001 must appear in the JSON output, got: {stderr}"
    );
    assert!(
        stderr.contains("\"severity\":\"error\""),
        "severity must be 'error', got: {stderr}"
    );
    // Primary span must carry source-position fields.
    assert!(
        stderr.contains("\"line\":"),
        "primary_span must carry 'line', got: {stderr}"
    );
    assert!(
        stderr.contains("\"col\":"),
        "primary_span must carry 'col', got: {stderr}"
    );
    assert!(
        stderr.contains("\"file\":"),
        "primary_span must carry 'file', got: {stderr}"
    );
    // explain_ref must name the exact code (now uses ipe doc).
    assert!(
        stderr.contains("\"explain_ref\":\"ipe doc IPE-T0001\""),
        "explain_ref must be 'ipe doc IPE-T0001', got: {stderr}"
    );
}

/// A field-type mismatch in the user's file, linked beside an embedded stdlib
/// module, is framed against the user's file.
///
/// Every linked module shares one byte-offset space, so the file must come
/// from the error's owning module, never from the stdlib def whose bytes
/// happen to enclose the span.
#[test]
fn field_mismatch_beside_stdlib_frames_user_file() {
    let r = run_ipe(&[
        "type-check",
        "--json",
        &fixture("field_mismatch_beside_stdlib/src/Main.ipe"),
    ]);
    assert!(!r.ok, "a field-type mismatch must exit non-zero");
    let stderr = r.stderr.trim();
    assert!(
        stderr.contains("IPE-T0001"),
        "the fixture must be refused with IPE-T0001, got: {stderr}"
    );
    let files: Vec<String> = stderr
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter_map(|diag| {
            diag.get("primary_span")
                .and_then(|span| span.get("file"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .collect();
    assert!(
        !files.is_empty(),
        "the mismatch must carry a primary span file, got: {stderr}"
    );
    for file in &files {
        assert!(
            file.ends_with("Main.ipe") && !file.starts_with("<embedded-stdlib>"),
            "the mismatch must be framed against the user's Main.ipe, got {file:?} in: {stderr}"
        );
    }
}

#[test]
fn type_check_human_output_unchanged_without_json_flag() {
    let r = run_ipe(&["type-check", &fixture("type_error.ipe")]);
    assert!(!r.ok, "type-error must exit non-zero without --json");
    // Human layout renders the code and title on stderr.
    assert!(
        r.stderr.contains("IPE-T0001"),
        "human layout must contain IPE-T0001, got: {:?}",
        r.stderr
    );
    assert!(
        r.stderr.contains("TYPE MISMATCH"),
        "human layout must contain 'TYPE MISMATCH', got: {:?}",
        r.stderr
    );
}

#[test]
fn type_check_plain_and_json_together_are_a_usage_error() {
    let r = run_ipe(&[
        "type-check",
        "--plain",
        "--json",
        &fixture("well_typed.ipe"),
    ]);
    assert!(
        !r.ok,
        "--plain --json together must be a usage error, got ok=true"
    );
}

// ---------------------------------------------------------------------------
// ipe dev build --json
// ---------------------------------------------------------------------------

#[test]
fn build_json_on_type_error_exits_nonzero_with_schema_conforming_json() {
    let tmp = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("diag_json_build")
        .join("type_error");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).expect("create tmp dir");

    // A minimal source file with a deliberate type error.
    let src = tmp.join("Main.ipe");
    std::fs::write(
        &src,
        "module Main exposing (main)\n\
         import Ipe.String as String\n\
         import Ipe.Io as Io\n\
         main : Task ()\n\
         main =\n\
             Io.println (String.toUpper 42)\n",
    )
    .expect("write source file");

    let out_dir = tmp.join("out");
    // Entry path must come first (before flags) — `parse_build` uses `take_leading_entry`.
    let r = run_ipe(&[
        "dev",
        "build",
        &src.to_string_lossy(),
        "--json",
        "--out",
        &out_dir.to_string_lossy(),
    ]);

    assert!(!r.ok, "a type-error build must exit non-zero under --json");

    let stderr = r.stderr.trim();
    assert!(
        !stderr.is_empty(),
        "--json build error must write to stderr"
    );

    for line in stderr.lines().filter(|l| !l.trim().is_empty()) {
        assert_diagnostic_schema(line);
    }

    // No artifact must be emitted for a rejected build.
    assert!(
        !out_dir.exists(),
        "a rejected build must not produce an artifact directory"
    );
}

#[test]
fn build_json_unknown_flag_renders_the_machine_error_envelope() {
    // Under `--json`, an unknown-flag usage error must render through the machine
    // error envelope — never fall through to the human usage/banner path (that
    // human-furniture-in-a-machine-stream leak is exactly what resolving the
    // output format BEFORE the parse closes). It is the compact
    // `ipe.cli.error/1` usage envelope, not the rich diagnostic object.
    let r = run_ipe(&["dev", "build", "--json", "--completely-unknown-flag-xyz"]);
    assert!(!r.ok, "an unknown flag must exit non-zero");
    let stderr = r.stderr.trim();
    assert!(
        stderr.starts_with('{') && stderr.contains("ipe.cli.error/1"),
        "an unknown flag under --json must render the machine error envelope, got: {stderr:?}"
    );
    assert!(
        !stderr.contains("Ipê lang"),
        "no human banner may reach the machine stream, got: {stderr:?}"
    );
}

#[test]
fn machine_error_command_field() {
    // The machine error envelope names the grouped verb a caller typed, so a
    // consumer keying on `command` sees `dev build`, never a bare verb.
    for verb in [["dev", "build"], ["dev", "run"], ["release", "build"]] {
        let r = run_ipe(&[verb[0], verb[1], "--json", "--bad-flag"]);
        assert!(!r.ok, "{verb:?} with an unknown flag must exit non-zero");
        let command = serde_json::from_str::<serde_json::Value>(r.stderr.trim())
            .ok()
            .and_then(|v| v.get("command").and_then(|c| c.as_str()).map(str::to_owned));
        assert_eq!(
            command.as_deref(),
            Some(verb.join(" ").as_str()),
            "the envelope must name the grouped verb, got: {:?}",
            r.stderr
        );
    }
}

// ---------------------------------------------------------------------------
// mimalloc note must not reach a machine stream (#2590)
// ---------------------------------------------------------------------------

/// On `--json` or `--plain`, the mimalloc opt-in `note:` must not appear on
/// stderr. The note is human furniture — it belongs only in `--human` mode.
///
/// The test drives `ipe dev build --static --allocator mimalloc <format>` against a
/// non-existent entry. The process fails (preflight cannot find the musl
/// toolchain, or the entry file is absent), but the failing path that MATTERS
/// here is `resolve_static_plan`, which runs at plan-resolution time, before
/// any filesystem access. Regardless of where the failure fires, the machine
/// stderr must be free of the mimalloc note.
#[test]
fn mimalloc_note_absent_from_machine_stderr() {
    for format in ["--json", "--plain"] {
        for cmd in ["build", "run"] {
            let r = run_ipe(&[
                "dev",
                cmd,
                "NoSuchEntry.ipe",
                "--static",
                "--allocator",
                "mimalloc",
                format,
            ]);
            // The run must fail (no musl toolchain or no file) — but whatever
            // error fires, the mimalloc human note must not be on stderr.
            assert!(
                !r.stderr.contains("note: mimalloc"),
                "`ipe {cmd} {format}` must not emit the mimalloc note on a \
                 machine stream; stderr was: {:?}",
                r.stderr,
            );
        }
    }
}

// ---------------------------------------------------------------------------
// ipe dev run --json
// ---------------------------------------------------------------------------

#[test]
fn run_json_on_type_error_exits_nonzero_with_schema_conforming_json() {
    let tmp = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("diag_json_run")
        .join("type_error");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).expect("create tmp dir");

    let src = tmp.join("Main.ipe");
    std::fs::write(
        &src,
        "module Main exposing (main)\n\
         import Ipe.String as String\n\
         import Ipe.Io as Io\n\
         main : Task ()\n\
         main =\n\
             Io.println (String.toUpper 42)\n",
    )
    .expect("write source file");

    let out_dir = tmp.join("out");
    // Entry path must come first — `parse_run` uses `take_leading_entry`.
    let r = run_ipe(&[
        "dev",
        "run",
        &src.to_string_lossy(),
        "--json",
        "--out",
        &out_dir.to_string_lossy(),
    ]);

    assert!(!r.ok, "a type-error run must exit non-zero under --json");

    let stderr = r.stderr.trim();
    assert!(!stderr.is_empty(), "--json run error must write to stderr");

    for line in stderr.lines().filter(|l| !l.trim().is_empty()) {
        assert_diagnostic_schema(line);
    }
}
