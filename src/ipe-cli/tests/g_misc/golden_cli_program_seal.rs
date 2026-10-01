//! Seal — `Cli.tea` app-entry kernel, end to end.
//!
//! The `Cli.tea` cfg record carries four function-typed fields
//! (init/update/view/subscriptions), so without `KernelFn::TerminalAppLines`
//! in the app-entry cfg intercept (`lower.rs`) EVERY real call would trip
//! `IPE-L0107: function value in a record field` and the `emit_console` path
//! would be unreachable.  This test pins the full pipeline:
//! constrain scheme (closed 4-field cfg, `RowTail::Closed`) → lower
//! app-entry intercept → `emit_console_call` → `ipe_runtime::console_app`, with
//! line input subscribed through `Cli.Sub.onLine` → `cli_sub_on_line`.
//!
//! Asserts ipe-0 ∧ cargo-0 ∧ run-0.  The runtime prints `view model` once at
//! start; the harness runs the binary with stdin at EOF (`Command::output`
//! nulls stdin), so the program renders the initial state and exits 0.
//!
//! Gated on `IPE_E2E=1`. Run:
//!
//! ```text
//! IPE_E2E=1 cargo test -p ipe --test golden_i111_console_app_seal
//! ```

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

#[test]
fn console_app_ipec_cargo_and_run_zero() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let dir = root.join("tests").join("golden").join("console_app_seal");
    let entry = dir.join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_i111_console_app_seal_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();

    // ipe-0: compiler must succeed (this shape can fail with IPE-L0107).
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for console_app_seal: {:?}",
        built.err()
    );

    // The emitted main must route through the Cli runtime entry.
    let emitted = std::fs::read_to_string(out.join("src").join("main.rs"))
        .expect("emitted main.rs must exist");
    assert!(
        emitted.contains("ipe_runtime::console_app("),
        "emitted main.rs must call ipe_runtime::console_app; got:\n{emitted}"
    );

    // cargo-0 ∧ run-0: the binary builds, renders the initial view, exits 0.
    let outcome = crate::support::build_and_run_emitted("console_app_seal", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "Cli.tea binary must exit 0 on stdin EOF; got {:?}",
        outcome.exit_code
    );
    assert!(
        outcome.stdout.contains("lines: 0"),
        "Cli.tea must render the initial view on start; got: {:?}",
        outcome.stdout
    );
}
