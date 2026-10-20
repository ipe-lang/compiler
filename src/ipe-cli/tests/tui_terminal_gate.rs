//! CLI-level proof that `ipe dev run` and `ipe dev watch` refuse a `Tui`-shape entry
//! BEFORE any compile or build when the process has no interactive terminal —
//! wired end-to-end through `ipe::run_cli`, exactly the boundary a real
//! invocation crosses.
//!
//! The shape is classified from the entry's text in the held source snapshot
//! (no canon/infer/lower, no cargo), and the terminal gate fires immediately after — before any
//! emit step or cargo work — so these two tests are
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

use ipe::RootFixture;

/// A minimal entry whose `main` pins the `Tui` shape — enough for
/// the snapshot's shape classification. `Tui.tea`'s callee is never
/// resolved, so `cfg` need not exist.
const TUI_ENTRY: &str = "module Main exposing (main)\n\nimport Ipe.Tea.Tui\n\nmain = Tui.tea cfg\n";

/// A project whose `src/Main.ipe` is [`TUI_ENTRY`].
fn tui_project() -> RootFixture {
    RootFixture::main(TUI_ENTRY).expect("the TUI project resolves")
}

/// `ipe dev run <tui-project>` under the test runner's non-interactive stdio must
/// refuse before any build: a `run` command-usage error whose reason names
/// the missing interactive terminal.
#[test]
fn run_refuses_a_tui_entry_without_an_interactive_terminal() {
    let project = tui_project();
    let args: Vec<String> = vec![
        "dev".to_owned(),
        "run".to_owned(),
        project.path().to_string_lossy().into_owned(),
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

/// `ipe dev watch <tui-project>` must refuse the same way, before the watch loop
/// itself ever starts — so this call returns promptly instead of looping.
#[test]
fn watch_refuses_a_tui_entry_without_an_interactive_terminal() {
    let project = tui_project();
    let args: Vec<String> = vec![
        "dev".to_owned(),
        "watch".to_owned(),
        project.path().to_string_lossy().into_owned(),
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
