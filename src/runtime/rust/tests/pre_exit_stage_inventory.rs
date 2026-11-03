//! Every exit-time effect of a driver runs as a `system::pre_exit` stage.
//!
//! A driver's teardown or session dump written after its loop is skipped by
//! `System.exit`, which ends the process from inside the loop. The scan pins
//! that the drivers reach the recorder only through `record_sink::start`
//! (whose dump runs as the session-dump stage, at exit or at `finish`) and
//! that no single-slot exit hook survives beside the stages.

#[path = "support/source_tree.rs"]
mod source_tree;

use std::path::Path;

/// The one `record_sink` entry a driver may name.
const DRIVER_RECORD_ENTRY: &str = "start";

/// The record-sink items that write a dump; a driver names none of them.
const DUMP_ITEMS: &[&str] = &[
    "dump_recorded",
    "render_replay_blob",
    "write_blob",
    "write_typed_log",
    "dump_session",
];

/// The single-slot exit hook the stages replace.
const RETIRED_EXIT_HOOK: &[&str] = &["register_exit_hook", "run_exit_hook", "run_pre_exit_stages"];

fn runtime_sources() -> Vec<(String, String)> {
    source_tree::rust_sources(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src"))
}

/// Whether `path` is a driver: `tea.rs` or a file under `tui/`.
fn is_driver(path: &str) -> bool {
    path == "tea.rs" || path.starts_with("tui/")
}

/// The identifier that follows each `record_sink::` in `text`.
fn record_sink_entries(text: &str) -> Vec<&str> {
    text.match_indices("record_sink::")
        .filter_map(|(at, needle)| text.get(at + needle.len()..))
        .map(|rest| {
            let end = rest
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .unwrap_or(rest.len());
            rest.get(..end).unwrap_or_default()
        })
        .collect()
}

/// A word occurrence of `item` in `text`, not a prefix of a longer name.
fn names(text: &str, item: &str) -> bool {
    text.match_indices(item).any(|(at, _)| {
        let before = text.get(..at).and_then(|s| s.chars().next_back());
        let after = text.get(at + item.len()..).and_then(|s| s.chars().next());
        let ident = |c: Option<char>| c.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
        !ident(before) && !ident(after)
    })
}

#[test]
fn dump_has_no_caller_outside_the_stage() {
    let mut offenders = Vec::new();
    let mut drivers = 0usize;
    for (path, text) in runtime_sources() {
        if !is_driver(&path) {
            continue;
        }
        drivers += 1;
        for entry in record_sink_entries(&text) {
            if entry != DRIVER_RECORD_ENTRY {
                offenders.push(format!("{path}: record_sink::{entry}"));
            }
        }
        for item in DUMP_ITEMS {
            if names(&text, item) {
                offenders.push(format!("{path}: {item}"));
            }
        }
    }
    assert!(drivers > 1, "the scan found no driver source");
    assert!(
        offenders.is_empty(),
        "a driver reaches a session dump outside its pre-exit stage:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn no_teardown_follows_a_driver_loop() {
    let mut offenders = Vec::new();
    for (path, text) in runtime_sources() {
        for item in RETIRED_EXIT_HOOK {
            if names(&text, item) {
                offenders.push(format!("{path}: {item}"));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "a single-slot exit hook survives beside the pre-exit stages:\n{}",
        offenders.join("\n")
    );
}

#[test]
fn the_scan_sees_a_record_sink_entry_and_a_named_item() {
    assert_eq!(
        record_sink_entries("a::record_sink::start(x); record_sink::dump_session(y)"),
        ["start", "dump_session"]
    );
    assert!(names("run_exit_hook()", "run_exit_hook"));
    assert!(!names("run_exit_hooks()", "run_exit_hook"));
}
