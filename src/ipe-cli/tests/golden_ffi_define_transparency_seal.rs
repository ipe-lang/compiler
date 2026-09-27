//! THE SEAL for define-transparency: an all-identity-carrier
//! `[rust.define.struct]` surfaces as an Ipê record and a
//! `[rust.define.enum]` as an Ipê closed union — the SAME record⇄struct /
//! union⇄enum conversion glue the transparent-import side rides, pointed at
//! the crate-local `crate::ffi::<slug>::<Name>` where the defined Rust type
//! lives.
//!
//! The default gate proves the whole pipeline emits: the interface module
//! declares the record alias and the closed union, the lowerer emits a real
//! app enum for the union, and every constructor forwarder converts its
//! foreign result at the seam. The `IPE_E2E=1` gate then proves THE SEAL end
//! to end: the emitted crate builds and RUNS with no external foreign crate
//! at all — the defined types are self-contained in `_bindings.rs`.
//!
//! ```text
//! cargo test -p ipe --test golden_ffi_define_transparency_seal
//! ```
#![allow(clippy::expect_used, clippy::panic)] // test setup: a failed build/write IS the failure

use std::fs;
use std::path::{Path, PathBuf};

use ipe_ffi::driver::{FfiCache, install_from_inspection};

/// A runtime `false` the optimiser cannot fold — a deliberate failure marker.
const fn false_marker() -> bool {
    std::hint::black_box(false)
}

/// Seed the project's FFI cache with an inspection document for a crate
/// `demo` that DEFINES one all-identity-carrier struct (`Counter`) and one
/// enum (`Message` — a unit and a payload variant): both must surface
/// transparently.
fn seed_define_ffi_cache(project_root: &Path) -> bool {
    let cache = FfiCache::at_project_root(project_root);
    let doc = serde_json::json!({
        "pkg": "demo", "name": "demo", "version": "0.1.0",
        "functions": [
            {
                "name": "counter_new", "effect": "pure", "isStructCtor": true,
                "structName": "Counter",
                "structFields": [{ "name": "value", "type": "i64" }],
                "structDerives": ["Default", "Clone"]
            },
            {
                "name": "message_new", "effect": "pure", "isEnumDef": true,
                "enumName": "Message",
                "enumVariants": [
                    { "name": "Increment", "payload": [] },
                    { "name": "SetValue", "payload": ["i64"] }
                ],
                "enumDerives": ["Clone", "Debug"]
            }
        ],
        "errors": []
    });
    install_from_inspection(&cache, &doc.to_string()).is_ok()
}

/// The fixture program: builds a `Counter` through its constructor forwarder
/// and reads the record field back, builds a `Message` through the nullary
/// and the payload forwarders, constructs a union value NATIVELY
/// (`Increment`), and exhaustively `case`s all of them.
const MAIN_IPE: &str = "module Main exposing (main)\n\
    import Ipe.Io as Io\n\
    import Ipe.String as String\n\
    import Rust.Demo as Demo exposing (Message(..))\n\n\
    describe : Demo.Message -> String\n\
    describe m =\n\
    \x20   case m of\n\
    \x20       Increment -> \"inc\"\n\
    \x20       SetValue n -> \"set \" ++ String.fromInt n\n\n\
    count : Demo.Counter -> Int\n\
    count c = c.value\n\n\
    main =\n\
    \x20   Io.println\n\
    \x20       (String.fromInt (count (Demo.counter_new 41))\n\
    \x20           ++ \" \" ++ describe (Demo.message_new_set_value 1)\n\
    \x20           ++ \" \" ++ describe (Demo.message_new_increment ())\n\
    \x20           ++ \" \" ++ describe Increment)\n";

fn write_project(dir: &Path) -> bool {
    let src = dir.join("src");
    let _ = fs::remove_dir_all(dir);
    if fs::create_dir_all(&src).is_err() {
        return false;
    }
    if !seed_define_ffi_cache(dir) {
        return false;
    }
    fs::write(src.join("Main.ipe"), MAIN_IPE).is_ok()
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

/// Default gate: `ipe build` exits 0 and the emitted crate carries the whole
/// transparent define surface — the app enum for the union, the crate-local
/// conversion glue on every constructor forwarder, and the `_bindings.rs`
/// definitions typed at the defined Rust types.
#[test]
fn define_transparency_emits_the_conversion_seam() {
    let Ok(runtime) = ipe::resolve_runtime() else {
        return; // runtime unavailable in this environment — skip silently
    };

    let tmp =
        std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ipec_ffi_define_transparency");
    assert!(
        write_project(&tmp),
        "must write the fixture project + FFI cache"
    );

    let entry = tmp.join("src").join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ffi_define_transparency_out");
    let _ = fs::remove_dir_all(&out);

    if let Err(err) = ipe::build_with_sibling_discovery(&entry, &out, &runtime) {
        assert!(
            false_marker(),
            "define-transparency fixture must build, got: {err}"
        );
        return;
    }

    // The forwarder module carries the app enum for the transparent union and
    // converts every constructor's foreign result at the crate-local path.
    let forwarders = read_emitted(&out, "src/ipe_mods/ipe_mod_rust_demo.rs");
    assert!(
        forwarders.contains("enum RustDemoMessage"),
        "the transparent define union must emit an app enum; forwarders:\n{forwarders}"
    );
    assert!(
        forwarders.contains("crate::ffi::demo::Message::Increment => RustDemoMessage::Increment"),
        "union foreign→app glue must match at the crate-local path; forwarders:\n{forwarders}"
    );
    assert!(
        forwarders.contains("__ipe_ffi_v.value"),
        "record foreign→app glue must move the field; forwarders:\n{forwarders}"
    );

    // The `_bindings.rs` region keeps the real definitions + constructors —
    // the write side of the representation axis is unchanged by transparency.
    let ffi_rs = read_emitted(&out, "src/ffi.rs");
    assert!(
        ffi_rs.contains("pub struct Counter {") && ffi_rs.contains("pub enum Message {"),
        "the defined Rust types must be emitted; ffi.rs:\n{ffi_rs}"
    );
    assert!(
        ffi_rs.contains("pub fn demo_counter_new(arg0: i64) -> Counter {"),
        "the constructor must stay typed at the defined type; ffi.rs:\n{ffi_rs}"
    );

    let _ = fs::remove_dir_all(&tmp);
}

/// SEAL proof under `IPE_E2E=1`: the emitted crate builds and runs with no
/// external foreign crate — the defined types are self-contained — and the
/// record field, both forwarder-built union values, and the natively
/// constructed union value all round-trip.
#[test]
fn define_transparency_emitted_crate_builds_and_runs() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }
    let Ok(runtime) = ipe::resolve_runtime() else {
        return;
    };

    let tmp = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("ipec_ffi_define_transparency_e2e");
    assert!(
        write_project(&tmp),
        "must write the fixture project + FFI cache"
    );

    let entry = tmp.join("src").join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ffi_define_transparency_e2e_out");
    let _ = fs::remove_dir_all(&out);
    if let Err(err) = ipe::build_with_sibling_discovery(&entry, &out, &runtime) {
        assert!(
            false_marker(),
            "define-transparency fixture must build, got: {err}"
        );
        return;
    }

    // The manifest pins the bound crate (the define surface rides `ipe rust
    // add <crate>`, so the crate is a real dependency in the shipped flow).
    // The fixture crate cannot live on crates.io — repoint the pin at an
    // empty local stand-in; the defined types themselves are self-contained
    // in `_bindings.rs` and reference nothing from it.
    let demo_dir = tmp.join("demo");
    fs::create_dir_all(demo_dir.join("src")).expect("mkdir demo");
    fs::write(
        demo_dir.join("Cargo.toml"),
        "[package]\nname = \"demo\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .expect("demo Cargo.toml");
    fs::write(demo_dir.join("src/lib.rs"), "").expect("demo lib.rs");
    let manifest_path = out.join("Cargo.toml");
    let manifest = fs::read_to_string(&manifest_path).expect("emitted Cargo.toml");
    assert!(
        manifest.contains("demo = \"=0.1.0\""),
        "emitted manifest must pin the bound crate; got:\n{manifest}"
    );
    let patched = manifest.replace(
        "demo = \"=0.1.0\"",
        &format!("demo = {{ path = {:?} }}", demo_dir.display().to_string()),
    );
    fs::write(&manifest_path, patched).expect("patched Cargo.toml");

    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
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
        "emitted define-transparency crate must build and run exit 0.\n\
         stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("41 set 1 inc inc"),
        "the record field and every union value must round-trip.\nstdout: {stdout}"
    );

    let _ = fs::remove_dir_all(&tmp);
}

/// A program that reads a field the marshalled value-struct does NOT have
/// (`Counter` surfaces exactly `{ value : Int }` from `structFields`).
const MISMATCHED_RECORD_IPE: &str = "module Main exposing (main)\n\
    import Ipe.Io as Io\n\
    import Ipe.String as String\n\
    import Rust.Demo as Demo\n\n\
    count : Demo.Counter -> Int\n\
    count c = c.nonexistent\n\n\
    main =\n\
    \x20   Io.println (String.fromInt (count (Demo.counter_new 41)))\n";

fn write_mismatched_project(dir: &Path) -> bool {
    let src = dir.join("src");
    let _ = fs::remove_dir_all(dir);
    if fs::create_dir_all(&src).is_err() {
        return false;
    }
    if !seed_define_ffi_cache(dir) {
        return false;
    }
    fs::write(src.join("Main.ipe"), MISMATCHED_RECORD_IPE).is_ok()
}

/// PIECE-2 REFUSAL SEAL (value-struct auto-marshal): a `.fn` returns a value
/// struct that surfaces by shape as an Ipê record (`Counter` ⇒ `{ value :
/// Int }`, no `.type`). An Ipê program whose record shape MISMATCHES the real
/// struct fields — reading a field the struct does not have — is REJECTED at
/// build, never silently dropped to a render no-op. The field-exact marshal is
/// the checker of record; the emitted `__ipe_ffi_v.<field>` move would be the
/// rustc backstop for any mismatch that slipped past.
#[test]
fn value_struct_marshal_refuses_a_mismatched_record_shape() {
    let Ok(runtime) = ipe::resolve_runtime() else {
        return; // runtime unavailable in this environment — skip silently
    };

    let tmp = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("ipec_ffi_value_struct_mismatch");
    assert!(
        write_mismatched_project(&tmp),
        "must write the mismatched-record fixture project + FFI cache"
    );

    let entry = tmp.join("src").join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ffi_value_struct_mismatch_out");
    let _ = fs::remove_dir_all(&out);

    let result = ipe::build_with_sibling_discovery(&entry, &out, &runtime);
    assert!(
        result.is_err(),
        "a record shape that mismatches the marshalled value struct's real \
         fields must be REFUSED, never silently accepted"
    );

    let _ = fs::remove_dir_all(&tmp);
}
