//! `Cli.tea`'s frame separator when stdout is not a terminal.
//!
//! A `view` that supplies no trailing newline of its own is glued to the next
//! render ON A TERMINAL, so a prompt line keeps the cursor (see
//! `ipe_runtime::tui::LineOutput::Terminal`). Into a pipe the same program
//! writes plain lines, each frame terminated by its own newline, and nothing
//! after the last one: piped output is line-oriented text a script can read.
//!
//! Gated on `IPE_E2E=1`. Run:
//!
//! ```text
//! IPE_E2E=1 cargo nextest run -p ipe --test g_issues golden_i122
//! ```

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

#[test]
fn piped_console_app_writes_one_line_per_render() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let dir = root
        .join("tests")
        .join("golden")
        .join("console_app_view_separator");
    let out = crate::support::scratch_root().join("ipec_i122_console_app_view_separator_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = crate::support::build_golden(&dir, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe dev build must succeed: {:?}",
        built.err()
    );

    // Two stdin lines → two loop-body renders (count 0 → 1 → 2), then EOF.
    let outcome = crate::support::build_and_run_emitted_with_stdin(
        "console_app_view_separator",
        &out,
        b"a\nb\n",
    );

    assert_eq!(outcome.exit_code, Some(0));
    // Piped stdout: each render is its own newline-terminated plain line, and
    // no extra newline follows the last one.
    let expected = "lines: 0\nlines: 1\nlines: 2\n";
    assert_eq!(
        outcome.stdout, expected,
        "a piped Cli.tea must write one plain line per render, got: {:?}",
        outcome.stdout
    );
    assert!(
        !outcome.stdout.contains('\u{1b}') && !outcome.stdout.contains('\r'),
        "piped output carries no escape sequence and no CR: {:?}",
        outcome.stdout
    );
}
