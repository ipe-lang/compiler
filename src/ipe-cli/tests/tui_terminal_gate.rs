//! CLI-level proof that `ipe dev run` and `ipe dev watch` refuse a `Tui`-shape entry
//! BEFORE any compile or build when the process has no interactive terminal —
//! wired end-to-end through `ipe::run_cli`, exactly the boundary a real
//! invocation crosses.
//!
//! `classify_entry_shape` only parses the entry file (no canon/infer/lower,
//! no cargo), and the terminal gate fires immediately after — before
//! `discover_manifest`'s emit step or any cargo work — so these two tests are
//! unconditional: no `IPE_E2E`, no build, no process replacement. Calling
//! `ipe::run_cli` in process is safe here specifically because the refusal
//! returns an `Err` before `run_run` / the watch loop ever reaches the point
//! that would `exec` this process (`run`, on success) or block it forever
//! (`watch`'s dev loop). A `Script`-shape entry does NOT stop this early —
//! `run_subcommand.rs` itself notes that calling `run_cli("run", …)` on a
//! buildable entry would `exec`-replace this very test process on success —
//! so the negative control (a non-`Tui` shape is never gated on the
//! terminal) is proven instead where it is both exhaustive and safe: the
//! pure `gate_terminal_decision` table test in `driver/tests/mod.rs`, which
//! covers every non-`Tui` shape, not just `Script`.
//!
//! The refusal below depends on the test process's own stdio genuinely not
//! being an interactive terminal. That holds under every automated test
//! runner (`cargo test` / `cargo nextest`: stdin is not a tty and
//! stdout/stderr are captured) — the very condition
//! `ipe_runtime_rust::terminal_access::probe` exists to detect, so relying on
//! it here tests the real thing rather than a simulation of it.

use std::fs;

/// A minimal entry whose `main` pins the `Tui` shape — enough for
/// `classify_entry_shape`'s parse-only check. `Tui.tea`'s callee is never
/// resolved, so `cfg` need not exist.
const TUI_ENTRY: &str = "module Main exposing (main)\n\nimport Ipe.Tea.Tui\n\nmain = Tui.tea cfg\n";

/// Write `src` as `Main.ipe` under a fresh per-test directory and return its
/// path.
fn write_entry(dir_name: &str, src: &str) -> std::path::PathBuf {
    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(dir_name);
    let _ = fs::remove_dir_all(&dir);
    let entry = dir.join("Main.ipe");
    let created = fs::create_dir_all(&dir).and_then(|()| fs::write(&entry, src));
    assert!(created.is_ok(), "write fixture entry: {created:?}");
    entry
}

/// `ipe dev run <tui-entry>` under the test runner's non-interactive stdio must
/// refuse before any build: a `run` command-usage error whose reason names
/// the missing interactive terminal.
#[test]
fn run_refuses_a_tui_entry_without_an_interactive_terminal() {
    let entry = write_entry("ipe_run_tui_gate", TUI_ENTRY);
    let args: Vec<String> = vec![
        "dev".to_owned(),
        "run".to_owned(),
        entry.to_string_lossy().into_owned(),
    ];
    let result = ipe::run_cli(&args);
    assert!(
        matches!(
            &result,
            Err(ipe::CliError::CommandUsage { command, reason })
                if *command == "dev run" && reason.as_str().contains("interactive terminal")
        ),
        "expected a `run` command-usage error naming the missing interactive terminal, got: {result:?}"
    );
}

/// `ipe dev watch <tui-entry>` must refuse the same way, before the watch loop
/// itself ever starts — so this call returns promptly instead of looping.
#[test]
fn watch_refuses_a_tui_entry_without_an_interactive_terminal() {
    let entry = write_entry("ipe_watch_tui_gate", TUI_ENTRY);
    let args: Vec<String> = vec![
        "dev".to_owned(),
        "watch".to_owned(),
        entry.to_string_lossy().into_owned(),
    ];
    let result = ipe::run_cli(&args);
    assert!(
        matches!(
            &result,
            Err(ipe::CliError::CommandUsage { command, reason })
                if *command == "dev watch" && reason.as_str().contains("interactive terminal")
        ),
        "expected a `watch` command-usage error naming the missing interactive terminal, got: {result:?}"
    );
}
