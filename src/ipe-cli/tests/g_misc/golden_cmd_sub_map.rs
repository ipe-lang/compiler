//! `Cmd.map` / `Sub.map` are CALLABLE from user code and complete the SEAL.
//!
//! A child sub-component's `Cmd ChildMsg` / `Sub ChildMsg` are folded into a
//! parent `Cli.tea` via `Cmd.map` / `Sub.map`, retagging them into the
//! parent's `Msg` (`tests/golden/cmd_sub_map/Main.ipe`). This pins ipe-0 ∧
//! cargo-0 ∧ run-0 (THE SEAL: ipe exit 0 ⇒ emitted Rust builds and runs) and
//! that the emitted main routes through the Cli runtime entry. The runtime
//! unit tests (`ipe_runtime::tea::map_tests`) cover the retagging semantics.
//!
//! Gated on `IPE_E2E=1`. Run:
//! `IPE_E2E=1 cargo test -p ipe --test golden_cmd_sub_map`.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    let joined = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

#[test]
fn cmd_sub_map_ipec_cargo_and_run_zero() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }

    let root = repo_root();
    let dir = root.join("tests").join("golden").join("cmd_sub_map");
    let entry = dir.join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_cmd_sub_map_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = ipe::resolve_runtime();
    assert!(runtime.is_ok(), "runtime must resolve for E2E");
    let Ok(runtime) = runtime else { return };

    // ipe-0: compiling a program that calls Cmd.map / Sub.map must succeed.
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for cmd_sub_map: {:?}",
        built.err()
    );

    // The emitted main routes through the Cli runtime entry (the map calls
    // lower to cmd_map / sub_map inside init / subscriptions).
    let emitted = std::fs::read_to_string(out.join("src").join("main.rs"))
        .expect("emitted main.rs must exist");
    assert!(
        emitted.contains("cmd_map(") && emitted.contains("sub_map("),
        "emitted main.rs must call cmd_map and sub_map; got:\n{emitted}"
    );

    // cargo-0 ∧ run-0: the binary builds, renders the initial view, exits 0.
    let outcome = crate::support::build_and_run_emitted("cmd_sub_map", &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "cmd_sub_map binary must exit 0 on stdin EOF; got {:?}",
        outcome.exit_code
    );
    assert!(
        outcome.stdout.contains("mapped lines: 0"),
        "must render the initial mapped view on start; got: {:?}",
        outcome.stdout
    );
}
