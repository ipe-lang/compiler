//! oracle parity check for `Cli.tea`'s view printer. A
//! `view` that doesn't append its own trailing newline gets renders glued
//! together with NOTHING in between, and exactly ONE trailing newline after
//! the event loop exits. This matches the runtime's
//! `cliPrintView` contract byte-for-byte: it "writes the result to stdout
//! WITHOUT a trailing newline (the user's prompt formatting decides whether
//! to add one)".
//!
//! Forcing a newline after every render would break `examples/shapes/terminal/simple-counter`'s
//! REPL-prompt UX (`view` returns `"count=... > "` with no trailing newline so
//! the cursor stays on the prompt line) and diverge from the golden reference.
//! This test asserts the CORRECT (golden-verified) glued-together behavior so
//! a future "fix" doesn't reintroduce that divergence.
//!
//! Gated on `IPE_E2E=1`. Run:
//!
//! ```text
//! IPE_E2E=1 cargo test -p ipe --test golden_i122_console_app_separator
//! ```

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

#[test]
fn console_app_glues_consecutive_renders_matching_go_oracle() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let dir = root
        .join("tests")
        .join("golden")
        .join("console_app_view_separator");
    let entry = dir.join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_i122_console_app_view_separator_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "ipe build must succeed: {:?}", built.err());

    // Two stdin lines → two loop-body renders (count 0 → 1 → 2), then EOF.
    let outcome = crate::support::build_and_run_emitted_with_stdin(
        "console_app_view_separator",
        &out,
        b"a\nb\n",
    );

    assert_eq!(outcome.exit_code, Some(0));
    // golden-verified: renders glue together (view supplies no separator of its
    // own), with exactly ONE trailing newline after the loop exits.
    let expected = "lines: 0lines: 1lines: 2\n";
    assert_eq!(
        outcome.stdout, expected,
        "Cli.tea must match the view-printer contract (no per-render \
         newline, one trailing newline at exit), got: {:?}",
        outcome.stdout
    );
}
