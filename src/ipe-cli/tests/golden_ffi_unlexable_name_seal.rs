//! THE SEAL for foreign names the Ipê lexer cannot tokenize: a foreign function
//! whose Rust name is the Ipê keyword `foreign`, and one whose foreign type is
//! the non-ASCII Rust identifier `Ñandu`, are both legal Rust but neither can
//! appear in the generated `Rust.Kw` interface module. The interface skips
//! them, so a program importing the crate still builds against its other
//! bindings.
//!
//! The default gate proves `ipe dev build` exits 0 and the interface names neither
//! binding. The `IPE_E2E=1` gate proves THE SEAL end to end: the emitted crate
//! builds against a real foreign crate that defines all three functions, and
//! runs.
//!
//! ```text
//! cargo test -p ipe --test golden_ffi_unlexable_name_seal
//! ```
#![allow(clippy::expect_used, clippy::panic)] // test setup: a failed build/write IS the failure

use std::fs;
use std::path::{Path, PathBuf};

use ipe_ffi::driver::{FfiCache, install_from_inspection};

/// Seed the project's FFI cache with an inspection for a crate `kw`: `foreign`
/// (an Ipê keyword), `nandu` (returns the non-ASCII `kw::Ñandu`), and the
/// ordinary `shift` the program calls.
fn seed_ffi_cache(project_root: &Path) -> bool {
    let cache = FfiCache::at_project_root(project_root);
    let doc = serde_json::json!({
        "pkg": "kw",
        "name": "kw",
        "version": "0.1.0",
        "functions": [
            {
                "name": "foreign",
                "params": [{"name": "n", "type": "i64"}],
                "results": [{"name": "", "type": "i64"}],
                "effect": "pure"
            },
            {
                "name": "nandu",
                "params": [],
                "results": [{"name": "", "type": "kw::\u{d1}andu"}],
                "effect": "pure"
            },
            {
                "name": "shift",
                "params": [{"name": "n", "type": "i64"}],
                "results": [{"name": "", "type": "i64"}],
                "effect": "pure"
            }
        ],
        "errors": [],
        "transitiveDeps": [
            {"ident": "kw", "name": "kw", "version": "0.1.0"}
        ]
    });
    install_from_inspection(&cache, &doc.to_string()).is_ok()
}

/// The fixture program: imports the generated `Rust.Kw` module and calls the
/// one binding whose names all lex.
const MAIN_IPE: &str = "module Main exposing (main)\n\
    import Ipe.Io as Io\n\
    import Ipe.String as String\n\
    import Rust.Kw as Kw\n\n\
    main =\n\
    \x20   case Kw.shift 41 of\n\
    \x20       Ok n -> Io.println (\"shift \" ++ String.fromInt n)\n\
    \x20       Err _ -> Io.println \"err shift\"\n";

fn write_project(dir: &Path) -> bool {
    let src = dir.join("src");
    let _ = fs::remove_dir_all(dir);
    if fs::create_dir_all(&src).is_err() {
        return false;
    }
    if !seed_ffi_cache(dir) {
        return false;
    }
    fs::write(src.join("Main.ipe"), MAIN_IPE).is_ok()
}

/// Read one emitted file, failing with a directory listing when absent.
fn read_emitted(out: &Path, rel: &str) -> String {
    fs::read_to_string(out.join(rel)).unwrap_or_else(|e| {
        let listing: Vec<String> = walk(out).iter().map(|p| p.display().to_string()).collect();
        panic!(
            "emitted file `{rel}` unreadable ({e}); emitted tree:\n{}",
            listing.join("\n")
        );
    })
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() {
            out.extend(walk(&p));
        } else {
            out.push(p);
        }
    }
    out
}

/// Default gate: the keyword-named and non-ASCII-typed bindings are skipped,
/// so `ipe dev build` exits 0 and the forwarder module names neither.
#[test]
fn unlexable_foreign_names_are_skipped_and_the_import_builds() {
    let runtime = e2e_support::require_runtime().into_path_buf();

    let tmp = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ipec_ffi_unlexable_name");
    assert!(
        write_project(&tmp),
        "must write the fixture project + FFI cache"
    );

    let entry = tmp.join("src").join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ffi_unlexable_name_out");
    let _ = fs::remove_dir_all(&out);
    if let Err(err) = ipe::build_loose_file(&entry, &out, &runtime) {
        panic!("a crate with unlexable foreign names must still import, got: {err}")
    }

    let forwarders = read_emitted(&out, "src/ipe_mods/ipe_mod_rust_kw.rs");
    assert!(
        !forwarders.contains('\u{d1}'),
        "the non-ASCII foreign type reached the forwarder module:\n{forwarders}"
    );

    let _ = fs::remove_dir_all(&tmp);
}

/// SEAL proof under `IPE_E2E=1`: the emitted crate builds against a REAL
/// foreign crate that defines `foreign`, `nandu`, and `shift`, and runs. The
/// registry pin is repointed at a local path crate, which changes WHERE `kw`
/// comes from, never what the emitted code says.
#[test]
fn unlexable_foreign_names_emitted_crate_builds_and_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let runtime = e2e_support::require_runtime().into_path_buf();

    let tmp = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ipec_ffi_unlexable_name_e2e");
    assert!(
        write_project(&tmp),
        "must write the fixture project + FFI cache"
    );

    let entry = tmp.join("src").join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ffi_unlexable_name_e2e_out");
    let _ = fs::remove_dir_all(&out);
    if let Err(err) = ipe::build_loose_file(&entry, &out, &runtime) {
        panic!("a crate with unlexable foreign names must still import, got: {err}")
    }

    let kw_dir = tmp.join("kw");
    fs::create_dir_all(kw_dir.join("src")).expect("mkdir kw");
    fs::write(
        kw_dir.join("Cargo.toml"),
        "[package]\nname = \"kw\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .expect("kw Cargo.toml");
    fs::write(
        kw_dir.join("src/lib.rs"),
        "pub struct \u{d1}andu;\n\
         pub fn foreign(n: i64) -> i64 { n * 100 }\n\
         pub fn nandu() -> \u{d1}andu { \u{d1}andu }\n\
         pub fn shift(n: i64) -> i64 { n + 1 }\n",
    )
    .expect("kw lib.rs");

    let manifest_path = out.join("Cargo.toml");
    let manifest = fs::read_to_string(&manifest_path).expect("emitted Cargo.toml");
    assert!(
        manifest.contains("kw = \"=0.1.0\""),
        "emitted manifest must pin the foreign crate; got:\n{manifest}"
    );
    let patched = manifest.replace(
        "kw = \"=0.1.0\"",
        &format!("kw = {{ path = {:?} }}", kw_dir.display().to_string()),
    );
    fs::write(&manifest_path, patched).expect("patched Cargo.toml");

    let cargo = ipe_env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    let run = std::process::Command::new(cargo)
        .arg("run")
        .arg("--quiet")
        .current_dir(&out)
        .output()
        .expect("cargo run spawns");
    let stdout = String::from_utf8_lossy(&run.stdout);
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert!(
        run.status.success(),
        "emitted crate must build and run exit 0.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("shift 42"),
        "the lexable binding must round-trip through foreign code.\nstdout: {stdout}"
    );

    let _ = fs::remove_dir_all(&tmp);
}
