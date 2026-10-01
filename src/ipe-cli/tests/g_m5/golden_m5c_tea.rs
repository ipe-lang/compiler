//! TEA construct-only gate — `Cmd` / `Sub` construction wiring.
//!
//! These tests compile Ipê programs that construct `Cmd` and `Sub` values and
//! immediately discard them, then print `"ok"`.  This confirms that:
//!
//! * `Cmd.none`, `Cmd.batch`, `Cmd.perform`, `Sub.none`, `Sub.batch`,
//!   `Sub.every`, `Time.every` are wired through the type-checker, lowerer,
//!   and emitter.
//! * The emitted Rust project links against `ipe_runtime::tea` correctly.
//! * Type inference works without explicit annotations when a `Cmd.perform`
//!   or `Sub.every` call anchors the `msg` type parameter.
//! * A plain-`main` Program reaching for a shape-scoped `Cmd` / `Sub` is the
//!   IPE-N0033 Program-importing-a-shape contradiction, rejected before emit.
//!
//! The positive fixtures are minimal `Cli.tea` apps: `Cmd` / `Sub`
//! are shape-scoped, so they are exercised inside the shape's own managed loop.
//! Each renders its `view` (`"ok"`) once at stdin EOF and exits 0.
//!
//! Positive tests are gated on `IPE_E2E=1`; gate (error) tests run without it.
//!
//! ## Oracle provenance
//!
//! Marked `oracle_divergence = true` (sanctioned): the reference compiler
//! has no equivalent Rust TEA constructors; Ipê-Rust's own output is the
//! authoritative reference.
//!
//! ## Golden catalogue
//!
//! * `perform_ctor` — an `init` command `Cmd.perform (Task.succeed 1) …`;
//!   proves type+emit+link for `cmd_perform`.
//! * `cmd_ctors` — an `init` command `Cmd.batch [Cmd.perform …, Cmd.none]`;
//!   proves `cmd_none` infers `msg` from a sibling in the batch.
//! * `sub_ctors` — `subscriptions` `Sub.batch [Sub.none, Sub.every 500 Tick]`;
//!   proves `sub_none` infers `msg` from a sibling.
//! * `gate_undetermined_msg` — a plain-`main` Program reaching for
//!   `Ipe.Tea.Terminal.Cmd.none` must surface IPE-N0033, never emit any Rust.
//!
//! Run:
//!
//! ```text
//! IPE_E2E=1 cargo test golden_m5c_tea
//! ```

use std::path::{Path, PathBuf};

use ipe::CliError;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn golden_dir(root: &Path, name: &str) -> PathBuf {
    root.join("tests").join("golden").join(name)
}

/// Compile `tests/golden/<name>/Main.ipe`, build the emitted Cargo project,
/// run it, and assert its stdout matches the cached oracle.  Gated on
/// `IPE_E2E=1`.
fn assert_runs_and_matches_oracle(name: &str) {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let root = repo_root();
    let dir = golden_dir(&root, name);
    let entry = dir.join("Main.ipe");
    let out = crate::support::scratch_root().join(format!("ipec_{name}_e2e"));
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(built.is_ok(), "build failed for {name}: {:?}", built.err());

    let outcome = crate::support::build_and_run_emitted(name, &out);
    crate::support::assert_go_parity(name, &dir, &outcome.stdout);
    assert_eq!(outcome.exit_code, Some(0), "exit 0, matching the oracle");
}

// ── Cmd.perform construct-only ────────────────────────────────────────────────

/// `let _ = Cmd.perform (Task.succeed 1) (\_ -> 0) in Io.println "ok"`.
/// Constructs a `IpeCmd<i64>` thunk and discards it; confirms `cmd_perform`
/// wiring through type-checker, lowerer, emitter, and runtime link.
/// Output: `"ok"`.
#[test]
fn perform_ctor() {
    assert_runs_and_matches_oracle("perform_ctor");
}

// ── Cmd.none / Cmd.batch construct-only ──────────────────────────────────────

/// `Cmd.batch [Cmd.perform (Task.succeed 1) (\_ -> 0), Cmd.none]` discarded.
/// `Cmd.none` infers `msg = i64` from the sibling `Cmd.perform` in the batch.
/// Output: `"ok"`.
#[test]
fn cmd_ctors() {
    assert_runs_and_matches_oracle("cmd_ctors");
}

// ── Sub.none / Sub.batch / Sub.every construct-only ──────────────────────────

/// `Sub.every 1000 0` and `Sub.batch [Sub.none, Sub.every 500 1]` discarded.
/// `Sub.none` infers `msg = i64` from the sibling `Sub.every` in the batch.
/// Output: `"ok"`.
#[test]
fn sub_ctors() {
    assert_runs_and_matches_oracle("sub_ctors");
}

// ── Under-determined-msg gate ─────────────────────────────────────────────────

/// Build the named golden fixture and assert it surfaces exactly `expected` as a
/// pipeline diagnostic.  Fails if the build succeeds, or if a different error
/// code is returned.  A skip occurs only when the runtime cannot be resolved.
fn assert_gate(fixture: &str, out_suffix: &str, expected: ipe_diagnostics::Code) {
    let root = repo_root();
    let entry = root
        .join("tests")
        .join("golden")
        .join(fixture)
        .join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(out_suffix);
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    let got = match &built {
        Err(CliError::Pipeline { diag, .. }) => Some(diag.code()),
        _ => None,
    };
    assert_eq!(
        got,
        Some(expected),
        "fixture {fixture}: expected {expected:?}, got build result {built:?}"
    );
}

/// `let _ = Cmd.none in Io.println "ok"` in a plain-`main` module — reaching for
/// a shape-scoped `Cmd.none` from a Program is a Program-importing-a-shape
/// contradiction, so ipe must exit 1 with IPE-N0033 before generating any Rust.
/// This is the structural successor to the old free-`msg` gate: a Program can no
/// longer express an un-anchored `Cmd.none` (it cannot name `Cmd` at all), so
/// the ambiguous-`IpeCmd<_>` route the emitter once had to reject is closed by
/// construction one gate earlier.
#[test]
fn program_reaching_shape_cmd_is_ipe_n0033() {
    assert_gate(
        "gate_undetermined_msg",
        "m5c_gate_undetermined_msg_emit",
        ipe_diagnostics::IPE_N0033,
    );
}

/// A `Terminal` app importing the `Web` shape's `Cmd` — `Cmd` is shape-specific
/// and reached through the app's own shape, so the wrong-shape import fails
/// closed with IPE-N0035 before any Rust is generated.
#[test]
fn wrong_shape_cmd_import_is_ipe_n0035() {
    assert_gate(
        "gate_wrong_shape_cmd",
        "m5c_gate_wrong_shape_cmd_emit",
        ipe_diagnostics::IPE_N0035,
    );
}

/// A `cli` app (a terminal-lines shape, no browser) importing
/// `Ipe.Browser.Clipboard` — a browser host capability that needs a JS host. The
/// library single-source-of-truth table admits a browser capability only in a
/// placement with a browser (a web app), so the import is a placement
/// contradiction rejected with IPE-N0047 at resolve, before any Rust is
/// generated. This is the gate's uniquely-owned row (no other gate covers a
/// browser capability in a live-rendering terminal shape).
#[test]
fn browser_capability_in_cli_is_ipe_n0047() {
    assert_gate(
        "gate_browser_in_cli",
        "m5c_gate_browser_in_cli_emit",
        ipe_diagnostics::IPE_N0047,
    );
}
