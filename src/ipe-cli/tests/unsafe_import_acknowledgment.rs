//! SEAL / behavior coverage for the `.Unsafe`-import acknowledgment (IPE-S0001).
//!
//! Proves the whole chain the CLI wires: a real program importing an
//! `Ipe.<M>.Unsafe` submodule flips the disclosed `unsafe` capability, the
//! source scan recovers the `via …` module list, and the gate then requires
//! consent — while a program with NO `.Unsafe` import is untouched, and a
//! non-interactive build without consent fails closed (never blocks).

use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::io::Cursor;

use ipe::unsafe_ack;
use ipe_ir::Capability;

/// Write a throwaway project rooted at a unique temp dir and return its root.
fn scratch_project(name: &str, main_src: &str) -> Result<std::path::PathBuf, Box<dyn Error>> {
    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("ipe_unsafe_ack_{name}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("src"))?;
    fs::write(
        dir.join("package.ipe"),
        format!(
            "module Package exposing (package)\n\n\npackage =\n    {{ name = \"{name}\", version = \"0.1.0\" }}\n"
        ),
    )?;
    fs::write(dir.join("src/Main.ipe"), main_src)?;
    Ok(dir)
}

const UNSAFE_MAIN: &str = "module Main exposing (main)\n\
     import Ipe.Html exposing (render, section)\n\
     import Ipe.Html.Unsafe exposing (unsafeScript)\n\
     import Ipe.Io as Io\n\n\n\
     main =\n\
     \x20   Io.println (render (section [] [ unsafeScript \"console.log(1)\" ]))\n";

const SAFE_MAIN: &str = "module Main exposing (main)\n\
     import Ipe.Html exposing (render, section, text)\n\
     import Ipe.Io as Io\n\n\n\
     main =\n\
     \x20   Io.println (render (section [] [ text \"hello\" ]))\n";

/// A program importing `Ipe.Html.Unsafe` discloses the `unsafe` capability, and
/// the source scan recovers the offending module for the `via` detail.
#[test]
fn unsafe_import_discloses_capability_and_is_scannable() -> Result<(), Box<dyn Error>> {
    let dir = scratch_project("discloses", UNSAFE_MAIN)?;

    let inferred = ipe::infer_package_capabilities(&dir.join("package.ipe"))?;
    assert!(
        inferred.contains(&Capability::Unsafe),
        "importing Ipe.Html.Unsafe must disclose the `unsafe` capability, got {inferred:?}"
    );

    let via = unsafe_ack::unsafe_modules_in_sources([UNSAFE_MAIN]);
    assert_eq!(via, vec!["Ipe.Html.Unsafe"]);

    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

/// A non-interactive build of an unsafe-importing program WITHOUT consent fails
/// closed with IPE-S0001, names the module and risk and the remedy, and states
/// it will not prompt — proving the headless path never hangs.
#[test]
fn non_interactive_unsafe_without_consent_fails_closed() -> Result<(), Box<dyn Error>> {
    let dir = scratch_project("failclosed", UNSAFE_MAIN)?;
    let inferred = ipe::infer_package_capabilities(&dir.join("package.ipe"))?;
    let via = unsafe_ack::unsafe_modules_in_sources([UNSAFE_MAIN]);

    let mut stdin = Cursor::new(Vec::new());
    let mut stderr = Vec::new();
    let err = unsafe_ack::gate(
        &inferred,
        /* manifest_accept */ &BTreeSet::new(),
        &via,
        /* interactive */ false,
        &mut stdin,
        &mut stderr,
    )
    .expect_err("a headless build without consent must fail closed");

    let msg = err.to_string();
    assert!(msg.contains("IPE-S0001"), "carries the code: {msg}");
    assert!(msg.contains("Ipe.Html.Unsafe"), "names the module: {msg}");
    assert!(
        msg.contains("cross-site scripting"),
        "names the risk: {msg}"
    );
    assert!(!msg.contains("--accept-risks"), "offers no flag: {msg}");
    assert!(
        msg.contains("[capabilities]"),
        "offers the manifest token: {msg}"
    );
    assert!(
        msg.contains("will not prompt"),
        "states it will not block: {msg}"
    );
    // A headless gate reads nothing and writes no prompt to stderr.
    assert!(
        stderr.is_empty(),
        "headless path prints no interactive prompt"
    );

    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

/// A `Package.accepts [ Capability.unsafe ]` manifest stage parses into the
/// typed accept set and pre-accepts durably — the one way a headless build
/// proceeds.
#[test]
fn manifest_accept_token_parses_and_proceeds() -> Result<(), Box<dyn Error>> {
    let dir = scratch_project("manifest", UNSAFE_MAIN)?;
    // Rewrite with the durable acceptance stage.
    fs::write(
        dir.join("package.ipe"),
        "module Package exposing (package)\n\n\npackage =\n\
         \x20   { name = \"manifest\"\n\
         \x20   , version = \"0.1.0\"\n\
         \x20   , capabilities = { accepts = [ Unsafe ] }\n\
         \x20   }\n",
    )?;

    let manifest = ipe::project::parse_manifest(&dir.join("package.ipe"))?;
    assert!(
        manifest.capabilities_accept.contains(&Capability::Unsafe),
        "the accept token parses into the typed set"
    );

    let inferred = ipe::infer_package_capabilities(&dir.join("package.ipe"))?;
    let via = unsafe_ack::unsafe_modules_in_sources([UNSAFE_MAIN]);
    let mut stdin = Cursor::new(Vec::new());
    let mut stderr = Vec::new();
    unsafe_ack::gate(
        &inferred,
        &manifest.capabilities_accept,
        &via,
        /* interactive */ false,
        &mut stdin,
        &mut stderr,
    )
    .expect("the manifest token pre-accepts");
    assert!(stderr.is_empty());

    let _ = fs::remove_dir_all(&dir);
    Ok(())
}

/// A program with NO `.Unsafe` import is unaffected: no disclosed `unsafe`
/// capability, and the gate proceeds silently with no consent at all.
#[test]
fn safe_program_is_unaffected() -> Result<(), Box<dyn Error>> {
    let dir = scratch_project("safe", SAFE_MAIN)?;
    let inferred = ipe::infer_package_capabilities(&dir.join("package.ipe"))?;
    assert!(
        !inferred.contains(&Capability::Unsafe),
        "a program with no .Unsafe import discloses no `unsafe` capability, got {inferred:?}"
    );
    assert!(unsafe_ack::unsafe_modules_in_sources([SAFE_MAIN]).is_empty());

    let mut stdin = Cursor::new(Vec::new());
    let mut stderr = Vec::new();
    unsafe_ack::gate(
        &inferred,
        &BTreeSet::new(),
        &[],
        false,
        &mut stdin,
        &mut stderr,
    )
    .expect("the safe path is never gated");
    assert!(stderr.is_empty(), "the safe path is completely silent");

    let _ = fs::remove_dir_all(&dir);
    Ok(())
}
