//! `Cli.tea`'s piped output on the `System.exit` path.
//!
//! `process::exit` skips the loop's own closing write, so the line surface
//! must already have ended every frame, and the exit hook must add nothing
//! when no line is open. Into a pipe each frame of the prompt view
//! (`echoed N [last] > `) is its own newline-ended plain line, its trailing
//! space kept, with no escape sequence, CR, or padding.
//!
//! Gated on `IPE_E2E=1`. Run:
//!
//! ```text
//! IPE_E2E=1 cargo nextest run -p ipe --test g_issues golden_i3943
//! ```

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

#[test]
fn piped_console_app_ends_every_frame_before_system_exit() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let dir = root.join("tests").join("golden").join("cli_exit_path");
    let out = crate::support::scratch_root().join("ipec_i3943_cli_exit_path_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    let built = crate::support::build_golden(&dir, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe dev build must succeed: {:?}",
        built.err()
    );

    // `hello` renders frame 1; `quit` ends the process through `System.exit 0`
    // before any further frame.
    let outcome =
        crate::support::build_and_run_emitted_with_stdin("cli_exit_path", &out, b"hello\nquit\n");

    assert_eq!(outcome.exit_code, Some(0));
    let expected = "echoed 0 [] > \nechoed 1 [hello] > \n";
    assert_eq!(
        outcome.stdout, expected,
        "a piped Cli.tea must end every frame before System.exit and add nothing after: {:?}",
        outcome.stdout
    );
    assert!(
        !outcome.stdout.contains('\u{1b}') && !outcome.stdout.contains('\r'),
        "piped output carries no escape sequence and no CR: {:?}",
        outcome.stdout
    );
}
