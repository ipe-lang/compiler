//! Integration tests for the compiled-source stdlib subsystem.
//!
//! These lock every seam on the `Ipe.Palette` spike module:
//!   * embed → inject → topo → canonicalise-as-stdlib → link → emit of a
//!     Std-homed union constructor, with mixed kernel + source imports;
//!   * a hostile user file named `Ipe.Palette` stays IPE-N0025-rejected;
//!   * (`IPE_E2E`) the emitted Cargo project builds and runs to `#000 42`.

use std::path::PathBuf;

mod support;

#[allow(clippy::expect_used)]
fn runtime() -> PathBuf {
    e2e_support::require_runtime().into_path_buf()
}

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

fn spike_manifest() -> PathBuf {
    repo_root()
        .join("tests")
        .join("fixtures")
        .join("spike-std-source")
        .join("package.ipe")
}

/// The compiled-source module resolves IDENTICALLY to a user module: the
/// project builds (no IPE-N0020 / N0025), and the emitted Rust carries the
/// Std-homed constructor + its case-match — the exact thing a kernel cannot do.
/// Also proves the MIXED import set (kernel `Ipe.String` + source
/// `Ipe.Palette`) both resolve.
#[test]
fn spike_project_builds_and_injects_compiled_source() {
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("spike_std_source");
    let _ = std::fs::remove_dir_all(&out);

    let res = ipe::build_project(&spike_manifest(), &out, &runtime());
    assert!(
        res.is_ok(),
        "spike build_project must succeed (inject → canon-as-stdlib → emit): {:?}",
        res.err()
    );

    // Read `main.rs` PLUS every `ipe_mods/*.rs` the per-Ipê-module split
    // may have written: the compiled `Ipe.Palette` source
    // is emitted into its own `ipe_mods/ipe_mod_std_palette.rs`, not inline
    // in `main.rs`. The shared helper keeps the substring assertions below
    // robust to WHICH file the split placed each symbol in (same discrimination
    // the golden harness uses).
    let emitted = support::read_all_emitted_src(&out);
    // The Ipe.Palette function is homed + prefixed as compiled source.
    assert!(
        emitted.contains("ipe_palette_to_hex"),
        "emitted Rust must carry the compiled Ipe.Palette function:\n{emitted}"
    );
    // Its own constructors were defined AND matched (kernel-impossible).
    assert!(
        emitted.contains("\"#000\"") && emitted.contains("\"#fff\""),
        "emitted Rust must carry the case-match arms of toHex:\n{emitted}"
    );
    // The Spacing type uses its own constructor (distinct from any Ipe.Css type).
    assert!(
        emitted.contains("ipe_palette_spacing_px"),
        "emitted Rust must carry the compiled Ipe.Palette `spacingPx` fn:\n{emitted}"
    );
}

/// SECURITY: a user file literally named `Ipe.Palette` (`ModuleOrigin::User`)
/// stays IPE-N0025-rejected — bundled stdlib is authoritative; a `Ipe.*` user
/// file is a hard error, never a silent supply-chain override of the audited
/// implementation.
#[test]
fn hostile_std_squat_is_ipe_n0025() {
    let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("spike_hostile_squat");
    let _ = std::fs::remove_dir_all(&root);
    let std_dir = root.join("src").join("Ipe");
    std::fs::create_dir_all(&std_dir).expect("mk hostile project dirs");

    std::fs::write(
        root.join("package.ipe"),
        "module Package exposing (package)\n\n\npackage =\n    { name = \"hostile\", version = \"0.1.0\" }\n",
    )
    .expect("write manifest");
    // The attacker's payload: a poisoned toHex inside the reserved `Ipe.`
    // namespace. The unforgeable `ModuleOrigin::User` tag means this file gets
    // NEITHER the N0025 namespace exemption NOR the N0026 reserved-builtin
    // exemption — the namespace gate (N0025) fires first, so a hostile author
    // can never obtain the `EmbeddedStdlib`-only capability.
    std::fs::write(
        std_dir.join("Palette.ipe"),
        "module Ipe.Palette exposing (Shade(..), toHex, Spacing(..))\n\
         type Shade = Dark | Light\n\
         type Spacing = Sp Int\n\
         toHex : Shade -> String\n\
         toHex shade =\n    \"PWNED\"\n",
    )
    .expect("write hostile Ipe/Palette.ipe");
    std::fs::write(
        root.join("src").join("Main.ipe"),
        "module Main exposing (main)\n\
         import Ipe.Palette exposing (Shade(..), toHex)\n\
         main = Io.println (toHex Dark)\n",
    )
    .expect("write Main.ipe");

    let out = root.join("out");
    let res = ipe::build_project(&root.join("package.ipe"), &out, &runtime());
    assert!(res.is_err(), "hostile Ipe.Palette squat must be rejected");
    let err = res.expect_err("`res` must be rejected");
    let code = match &err {
        ipe::CliError::Pipeline { diag, .. } => Some(diag.code()),
        _ => None,
    };
    assert_eq!(
        code,
        Some(ipe_diagnostics::IPE_N0025),
        "hostile Ipe.Palette must be IPE-N0025 (not a silent override): {err}"
    );
}

/// The GREEN GATE end-to-end: under `IPE_E2E=1` the emitted Cargo project
/// compiles and RUNS, printing `#000` (`toHex Dark`) — proving the whole seam
/// from Std-source to a running binary, matching the reference value.
#[test]
fn spike_e2e_runs_and_prints_hex() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("spike_std_source_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let res = ipe::build_project(&spike_manifest(), &out, &runtime());
    assert!(res.is_ok(), "spike build must succeed: {:?}", res.err());

    let outcome = support::build_and_run_emitted("spike_std_source", &out);
    assert_eq!(
        outcome.stdout, "#000 42\n",
        "the emitted binary must print `#000 42` (toHex Dark + spacingPx (Sp 42))"
    );
    assert_eq!(outcome.exit_code, Some(0), "exit 0, matching the reference");
}
