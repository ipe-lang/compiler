//! THE SEAL for the transparent-import write side: a foreign struct surfaces
//! as an Ipê record and a foreign enum as an Ipê closed union, with the
//! conversion glue at the wrapper seam — record⇄struct, union⇄enum — emitted
//! by the backend.
//!
//! The default gate proves the whole pipeline emits: the interface module
//! declares the record alias and the closed union, the lowerer emits a real
//! app enum for the union (instead of skipping it as an opaque placeholder),
//! and the forwarder bodies carry both conversion directions. The
//! `IPE_E2E=1` gate then proves THE SEAL end to end: the emitted crate
//! builds against a real foreign crate and RUNS, round-tripping a struct and
//! an enum through actual foreign code.
//!
//! ```text
//! cargo test -p ipe --test golden_ffi_transparent_import_seal
//! ```
#![allow(clippy::expect_used, clippy::panic)] // test setup: a failed build/write IS the failure

use std::fs;
use std::path::{Path, PathBuf};

use ipe_ffi::driver::{FfiCache, install_from_inspection};

/// Seed the project's FFI cache with a hand-crafted inspection document for a
/// crate `tm` carrying one transparent struct (`Point`), one transparent enum
/// (`Shade` — unit, tuple, and struct variants), and three functions that
/// exercise every glue direction: struct in/out (`shift`), struct in / enum
/// out (`classify`), and enum in (`brightness`).
fn seed_transparent_ffi_cache(project_root: &Path) -> bool {
    let cache = FfiCache::at_project_root(project_root);
    let doc = serde_json::json!({
        "pkg": "tm",
        "name": "tm",
        "version": "0.1.0",
        "functions": [
            {
                "name": "shift",
                "params": [{"name": "p", "type": "Point", "ipeType": "Point",
                            "rustType": "tm::Point"}],
                "results": [{"name": "", "type": "Point", "rustType": "tm::Point"}],
                "effect": "pure"
            },
            {
                "name": "classify",
                "params": [{"name": "p", "type": "Point", "ipeType": "Point",
                            "rustType": "tm::Point"}],
                "results": [{"name": "", "type": "Shade", "rustType": "tm::Shade"}],
                "effect": "pure"
            },
            {
                "name": "brightness",
                "params": [{"name": "s", "type": "Shade", "ipeType": "Shade",
                            "rustType": "tm::Shade"}],
                "results": [{"name": "", "type": "Int", "rustType": "i64"}],
                "effect": "pure"
            }
        ],
        "errors": [],
        "transitiveDeps": [
            {"ident": "tm", "name": "tm", "version": "0.1.0"}
        ],
        "types": [
            {
                "name": "Point",
                "rustPath": "tm::Point",
                "kind": "struct",
                "fields": [
                    {"name": "x", "type": "Int", "rustType": "i64"},
                    {"name": "y", "type": "Float", "rustType": "f64"}
                ]
            },
            {
                "name": "Shade",
                "rustPath": "tm::Shade",
                "kind": "enum",
                "variants": [
                    {"name": "On", "kind": "unit"},
                    {"name": "Level", "kind": "tuple",
                     "members": [{"name": "0", "type": "Int", "rustType": "i64"}]},
                    {"name": "Mix", "kind": "struct",
                     "members": [
                        {"name": "amount", "type": "Int", "rustType": "i64"},
                        {"name": "label", "type": "String", "rustType": "String"}
                     ]}
                ]
            }
        ]
    });
    install_from_inspection(&cache, &doc.to_string()).is_ok()
}

/// The fixture program: constructs a `Point` record, threads it through
/// `shift` (record→struct→record), classifies it (union comes back and is
/// exhaustively `case`d, struct-variant included), and CONSTRUCTS a union
/// value Ipê-side (`Tm.Level 3`) that crosses into the foreign enum.
const MAIN_IPE: &str = "module Main exposing (main)\n\
    import Ipe.Io as Io\n\
    import Ipe.String as String\n\
    import Rust.Tm as Tm exposing (Shade(..))\n\n\
    describe : Tm.Shade -> String\n\
    describe s =\n\
    \x20   case s of\n\
    \x20       On -> \"on\"\n\
    \x20       Level n -> \"level \" ++ String.fromInt n\n\
    \x20       Mix amount label -> label ++ \" \" ++ String.fromInt amount\n\n\
    main =\n\
    \x20   case Tm.shift { x = 1, y = 2.5 } of\n\
    \x20       Ok q ->\n\
    \x20           case Tm.classify q of\n\
    \x20               Ok s ->\n\
    \x20                   case Tm.brightness (Level 3) of\n\
    \x20                       Ok n -> Io.println (describe s ++ \" \" ++ String.fromInt n)\n\
    \x20                       Err _ -> Io.println \"err brightness\"\n\
    \x20               Err _ -> Io.println \"err classify\"\n\
    \x20       Err _ -> Io.println \"err shift\"\n";

fn write_project(dir: &Path) -> bool {
    write_project_with(dir, MAIN_IPE)
}

/// Write a project whose `src/Main.ipe` is `main`, with the `tm` FFI cache seeded.
fn write_project_with(dir: &Path, main: &str) -> bool {
    let src = dir.join("src");
    let _ = fs::remove_dir_all(dir);
    if fs::create_dir_all(&src).is_err() {
        return false;
    }
    if !seed_transparent_ffi_cache(dir) {
        return false;
    }
    fs::write(src.join("Main.ipe"), main).is_ok()
}

/// Read one emitted file, failing the test with a directory listing when the
/// expected path is absent (a layout drift, not a silent skip).
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

/// Write the real foreign crate `tm` under `tmp`, repoint the emitted crate at
/// `out` to it (the fixture crate cannot live on crates.io, so this changes
/// WHERE `tm` comes from, never what the emitted code says), and `cargo run` it.
fn cargo_run_against_local_tm(tmp: &Path, out: &Path) -> std::process::Output {
    // The real foreign crate the emitted wrappers bind.
    let tm_dir = tmp.join("tm");
    fs::create_dir_all(tm_dir.join("src")).expect("mkdir tm");
    fs::write(
        tm_dir.join("Cargo.toml"),
        "[package]\nname = \"tm\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .expect("tm Cargo.toml");
    fs::write(
        tm_dir.join("src/lib.rs"),
        r#"pub struct Point { pub x: i64, pub y: f64 }
pub enum Shade { On, Level(i64), Mix { amount: i64, label: String } }
pub fn shift(p: Point) -> Point { Point { x: p.x + 1, y: p.y } }
pub fn classify(p: Point) -> Shade {
    if p.x > 1 { Shade::Mix { amount: p.x, label: String::from("mix") } } else { Shade::On }
}
pub fn brightness(s: Shade) -> i64 {
    match s { Shade::On => 0, Shade::Level(n) => n, Shade::Mix { amount, .. } => amount }
}
"#,
    )
    .expect("tm lib.rs");

    // Repoint the registry pin at the local fixture crate.
    let manifest_path = out.join("Cargo.toml");
    let manifest = fs::read_to_string(&manifest_path).expect("emitted Cargo.toml");
    assert!(
        manifest.contains("tm = \"=0.1.0\""),
        "emitted manifest must pin the foreign crate; got:\n{manifest}"
    );
    let patched = manifest.replace(
        "tm = \"=0.1.0\"",
        &format!("tm = {{ path = {:?} }}", tm_dir.display().to_string()),
    );
    fs::write(&manifest_path, patched).expect("patched Cargo.toml");

    let cargo = ipe_env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    std::process::Command::new(cargo)
        .arg("run")
        .arg("--quiet")
        .current_dir(out)
        .output()
        .expect("cargo run spawns")
}

/// Default gate: `ipe dev build` exits 0 and the emitted crate carries the whole
/// transparent surface — the app enum for the union, the foreign struct
/// literal (record→struct), the foreign-enum match (union→enum and back),
/// and wrappers typed at the REAL foreign types.
#[test]
fn transparent_import_emits_the_conversion_seam() {
    let runtime = e2e_support::require_runtime().into_path_buf();

    let tmp =
        std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ipec_ffi_transparent_import");
    assert!(
        write_project(&tmp),
        "must write the fixture project + FFI cache"
    );

    let entry = tmp.join("src").join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ffi_transparent_import_out");
    let _ = fs::remove_dir_all(&out);

    if let Err(err) = ipe::build_loose_file(&entry, &out, &runtime) {
        panic!("transparent-import fixture must build, got: {err}")
    }

    // The forwarder module carries the app enum for the transparent union
    // (a REAL declaration, not an opaque placeholder) and both glue
    // directions of both shapes.
    let forwarders = read_emitted(&out, "src/ipe_mods/ipe_mod_rust_tm.rs");
    assert!(
        forwarders.contains("enum RustTmShade"),
        "the transparent union must emit an app enum; forwarders:\n{forwarders}"
    );
    assert!(
        forwarders.contains("::tm::Point {"),
        "record→struct glue missing; forwarders:\n{forwarders}"
    );
    assert!(
        forwarders.contains("=> RustTmShade::Mix(__ipe_ffi_p0, __ipe_ffi_p1)")
            && forwarders
                .contains("RustTmShade::Mix(__ipe_ffi_p0, __ipe_ffi_p1) => ::tm::Shade::Mix"),
        "struct-variant union glue missing in a direction; forwarders:\n{forwarders}"
    );
    assert!(
        forwarders.contains("IpeResult::Ok(__ipe_ffi_v)"),
        "result conversion under the Ok arm missing; forwarders:\n{forwarders}"
    );

    // The wrappers stay typed at the REAL foreign types — conversion happens
    // at the call seam, never by weakening the wrapper's signature.
    let ffi_rs = read_emitted(&out, "src/ffi.rs");
    assert!(
        ffi_rs.contains("pub fn tm_shift(arg0: ::tm::Point) -> IpeResult<IpeError, ::tm::Point>"),
        "wrapper signature must keep the foreign types; ffi.rs:\n{ffi_rs}"
    );

    let _ = fs::remove_dir_all(&tmp);
}

/// SEAL proof under `IPE_E2E=1`: the emitted crate builds against a REAL
/// foreign crate and runs, round-tripping the struct and the enum through
/// foreign code. The registry pin is repointed at a local path crate — the
/// fixture crate cannot live on crates.io — which changes WHERE `tm` comes
/// from, never what the emitted code says.
#[test]
fn transparent_import_emitted_crate_builds_and_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let runtime = e2e_support::require_runtime().into_path_buf();

    let tmp = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("ipec_ffi_transparent_import_e2e");
    assert!(
        write_project(&tmp),
        "must write the fixture project + FFI cache"
    );

    let entry = tmp.join("src").join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ffi_transparent_import_e2e_out");
    let _ = fs::remove_dir_all(&out);
    if let Err(err) = ipe::build_loose_file(&entry, &out, &runtime) {
        panic!("transparent-import fixture must build, got: {err}")
    }

    let run = cargo_run_against_local_tm(&tmp, &out);
    let stdout = String::from_utf8_lossy(&run.stdout);
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert!(
        run.status.success(),
        "emitted transparent-import crate must build and run exit 0.\n\
         stdout: {stdout}\nstderr: {stderr}"
    );
    // shift {x=1,y=2.5} → x=2 → classify → Mix(2, "mix") → describe "mix 2";
    // brightness (Level 3) → 3.
    assert!(
        stdout.contains("mix 2 3"),
        "the struct and enum must round-trip through foreign code.\nstdout: {stdout}"
    );

    let _ = fs::remove_dir_all(&tmp);
}

/// The repo root, for the `tests/golden` fixtures.
fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    fs::canonicalize(&joined).unwrap_or(joined)
}

/// A transparent `Rust.*` union has a registered enum and an emitted
/// `IpeStringify` impl, so showing it (directly and as a user union's payload)
/// is accepted, and under `IPE_E2E=1` the emitted crate builds and runs,
/// rendering the constructors. The opaque-handle refusal is
/// `g_misc::golden_show_policy::showing_a_rust_handle_is_refused_before_cargo`.
#[test]
fn showing_a_transparent_union_builds_and_renders_it() {
    let runtime = e2e_support::require_runtime().into_path_buf();
    let source = repo_root()
        .join("tests")
        .join("golden")
        .join("show_transparent_foreign")
        .join("Main.ipe");
    let main =
        fs::read_to_string(&source).unwrap_or_else(|e| panic!("read {}: {e}", source.display()));
    let tmp = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ipec_show_transparent_foreign");
    assert!(
        write_project_with(&tmp, &main),
        "must write the fixture project + FFI cache"
    );
    let entry = tmp.join("src").join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("show_transparent_foreign_out");
    let _ = fs::remove_dir_all(&out);
    if let Err(err) = ipe::build_loose_file(&entry, &out, &runtime) {
        panic!("showing a transparent union must be accepted, got: {err}")
    }
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        let _ = fs::remove_dir_all(&tmp);
        return;
    }
    let run = cargo_run_against_local_tm(&tmp, &out);
    let stdout = String::from_utf8_lossy(&run.stdout);
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert!(
        run.status.success(),
        "the emitted crate showing a transparent union must build and run exit 0.\n\
         stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.lines().any(|l| l == "shade: Level 3"),
        "the transparent union renders its constructor:\n{stdout}"
    );
    assert!(
        stdout
            .lines()
            .any(|l| l.starts_with("holder: Holder Mix 2 ") && l.contains("mix")),
        "a user union renders its transparent-union payload:\n{stdout}"
    );
    let _ = fs::remove_dir_all(&tmp);
}
