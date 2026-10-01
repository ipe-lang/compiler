//! SEAL fixture for an author-supplied wrapper crate (Tier 2 path-crate FFI).
//!
//! The keystone invariant is `ipe` exit 0 ⇒ the emitted app crate — our
//! generated bindings PLUS the wrapper as a `path` dependency — cargo-builds.
//! This fixture proves the whole path-crate reuse end to end: a normal local
//! Rust wrapper crate exposes a carrier-typed constructor (`make(seed: i64) ->
//! Engine`) and an owned-value reader (`describe(e: Engine) -> String`); the
//! generator emits `_bindings.rs` that calls into `::engine_wrap::…`, the
//! driver renders the wrapper as a `path` dep, and the assembled crate builds
//! and runs. A borrowed-return fn (`peek(e: &Engine) -> &str`) over-drops with a
//! diagnostic — never emit-and-cargo-fail.
//!
//! The emit-only + decode assertions run in the DEFAULT gate; the cargo
//! build+run proof is `IPE_E2E`-gated (it shells out to `cargo`), matching the
//! repo's other SEAL fixtures. A minimal runtime shim stands in for the
//! vendored `use crate::*;` glue the emitted wrappers reference.
#![allow(clippy::expect_used)] // test setup: a failed decode / scratch-dir op IS the failure

use ipe_ffi::bindings::{emit_bindings, surviving_ref_names};
use ipe_ffi::driver::{FfiCache, cargo_dep_lines};
use ipe_ffi::interface::crate_interface;
use ipe_ffi::pkginfo::PkgInfo;

/// The inspection document the inspector produces for the wrapper crate at
/// `wrapper_path`: two carrier-compatible plain fns and one borrowed-return fn.
/// `wrapperPath` marks the package as an author-supplied wrapper crate, so the
/// emitted app crate depends on it by `path`.
fn engine_wrapper_pkg(wrapper_path: &str) -> PkgInfo {
    let doc = serde_json::json!({
        "pkg": "engine_wrap",
        "name": "engine_wrap",
        "version": "0.1.0",
        "wrapperPath": wrapper_path,
        "functions": [
            {
                "name": "make",
                "params": [{ "name": "seed", "type": "i64", "ipeType": "Int", "rustType": "i64" }],
                "results": [{ "name": "", "type": "engine_wrap::Engine", "rustType": "engine_wrap::Engine" }],
                "effect": "pure"
            },
            {
                "name": "describe",
                "params": [{ "name": "e", "type": "engine_wrap::Engine", "ipeType": "Engine", "rustType": "engine_wrap::Engine" }],
                "results": [{ "name": "", "type": "String", "rustType": "String" }],
                "effect": "pure"
            }
        ],
        "errors": []
    })
    .to_string();
    PkgInfo::decode_json(&doc).expect("wrapper inspection decodes")
}

/// Default gate: the emitted `_bindings.rs` calls into the wrapper crate's
/// symbols under the crate-qualified path, and the driver renders the wrapper as
/// a `path` dependency rather than a registry pin.
#[test]
fn a_wrapper_crate_binds_its_symbols_and_depends_by_path() {
    let pkg = engine_wrapper_pkg("wrappers/engine");
    let bindings = emit_bindings(&pkg);
    // The constructor binds and calls into the wrapper crate by its absolute path.
    assert!(
        bindings.contains("pub fn engine_wrap_make("),
        "the make constructor must bind:\n{bindings}"
    );
    assert!(
        bindings.contains("::engine_wrap::make("),
        "the wrapper call must target the wrapper crate:\n{bindings}"
    );
    // The owned-value reader binds. The opaque handle rides as the bare nominal
    // `Engine`, which the emitted app crate aliases to the wrapper crate's type
    // (`pub type Engine = ::engine_wrap::Engine;`) from the interface's
    // opaque-type map — the reader's call still targets the wrapper crate.
    assert!(
        bindings.contains("pub fn engine_wrap_describe("),
        "the describe reader must bind:\n{bindings}"
    );
    assert!(
        bindings.contains("::engine_wrap::describe("),
        "the reader's call must target the wrapper crate:\n{bindings}"
    );
    let iface = crate_interface(&pkg);
    assert_eq!(
        iface.opaque_types.get("Engine").map(String::as_str),
        Some("::engine_wrap::Engine"),
        "the opaque handle resolves to the wrapper crate's type: {:?}",
        iface.opaque_types
    );

    // The emitted app crate depends on the wrapper by PATH, never a registry pin.
    // The relative wrapper path is jailed to the project root at load and
    // rendered as its canonical absolute directory.
    let project =
        ipe_test_temp::temp_root().join(format!("ipe-engine-wrap-dep-line-{}", std::process::id()));
    std::fs::create_dir_all(project.join("wrappers/engine")).expect("scratch wrapper dir");
    std::fs::write(
        project.join("wrappers/engine/Cargo.toml"),
        "[package]\nname = \"engine_wrap\"\nversion = \"0.1.0\"\n",
    )
    .expect("scratch wrapper manifest");
    let canonical =
        std::fs::canonicalize(project.join("wrappers/engine")).expect("wrapper dir canonicalizes");
    let deps = cargo_dep_lines(&pkg, &FfiCache::at_project_root(&project))
        .expect("renders a path dep line");
    let _ = std::fs::remove_dir_all(&project);
    assert_eq!(
        deps,
        [format!(
            "engine_wrap = {{ path = \"{}\" }}",
            canonical.display()
        )],
        "the wrapper is a path dependency of the emitted app crate"
    );
}

/// Default gate: a borrowed-RETURN fn cannot cross the owned-only boundary, so
/// the whole binding over-drops with a diagnostic — the wrapper's other symbols
/// survive.
#[test]
fn a_borrowed_return_fn_over_drops_with_a_diagnostic() {
    let doc = serde_json::json!({
        "pkg": "engine_wrap",
        "name": "engine_wrap",
        "version": "0.1.0",
        "wrapperPath": "wrappers/engine",
        "functions": [
            {
                "name": "make",
                "params": [{ "name": "seed", "type": "i64", "ipeType": "Int", "rustType": "i64" }],
                "results": [{ "name": "", "type": "Engine", "rustType": "Engine" }],
                "effect": "pure"
            },
            {
                // A `&Engine -> &str` reader returns a borrow that would escape the
                // owned-only carrier boundary. The inspector reports it as a plain
                // fn; the emitter cannot render a sound owned wrapper for a borrowed
                // return, so the region is empty and the interface skips it.
                "name": "peek",
                "params": [{ "name": "e", "type": "Engine", "ipeType": "Engine", "rustType": "&Engine" }],
                "results": [{ "name": "", "type": "String", "rustType": "&str" }],
                "recvType": "Engine",
                "recvRustType": "&Engine",
                "methodName": "peek",
                "effect": "pure"
            }
        ],
        "errors": []
    })
    .to_string();
    let pkg = PkgInfo::decode_json(&doc).expect("decodes");
    let survivors = surviving_ref_names(&pkg);
    // The carrier-compatible constructor survives.
    assert!(
        survivors.iter().any(|s| s == "make"),
        "the sound constructor must survive: {survivors:?}"
    );
    // The borrowed-return reader is over-dropped (no wrapper emitted for it).
    let bindings = emit_bindings(&pkg);
    assert!(
        !bindings.contains("::engine_wrap::peek"),
        "a borrowed-return fn must over-drop, never emit-and-cargo-fail:\n{bindings}"
    );
}

/// The load-bearing SEAL proof: under `IPE_E2E=1`, assemble a real wrapper crate
/// plus an app crate that depends on it by `path` and contains the emitted
/// wrapper regions, then build and run it. `ipe` exit 0 ⇒ this crate compiles;
/// the run asserts the constructor and reader round-trip through the wrapper.
#[test]
fn the_emitted_crate_and_wrapper_path_dep_build_and_run() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let cargo = ipe_env::var("CARGO").expect("cargo sets CARGO for every test it runs");

    let root =
        ipe_test_temp::temp_root().join(format!("ipe_ffi_wrapper_seal_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);

    // 1. The author-supplied wrapper crate — normal, idiomatic Rust.
    let wrapper_dir = root.join("wrappers").join("engine");
    std::fs::create_dir_all(wrapper_dir.join("src")).expect("mkdir wrapper");
    std::fs::write(
        wrapper_dir.join("Cargo.toml"),
        "[package]\nname = \"engine_wrap\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .expect("wrapper Cargo.toml");
    std::fs::write(
        wrapper_dir.join("src").join("lib.rs"),
        "pub struct Engine { seed: i64 }\n\
         pub fn make(seed: i64) -> Engine { Engine { seed } }\n\
         pub fn describe(e: Engine) -> String { format!(\"engine<{}>\", e.seed) }\n",
    )
    .expect("wrapper lib.rs");

    // 2. The emitted app crate: its bindings call into the wrapper by its
    //    crate-absolute path, and it depends on the wrapper by the driver's
    //    rendered `path` dep line, jailed to this scratch project root.
    let pkg = engine_wrapper_pkg("wrappers/engine");
    let dep_lines = cargo_dep_lines(&pkg, &FfiCache::at_project_root(&root))
        .expect("the wrapper jails inside the scratch root");
    assert!(
        dep_lines.iter().all(|line| line.contains("{ path = \"")),
        "the wrapper renders as a path dependency: {dep_lines:?}"
    );
    let bindings = emit_bindings(&pkg);
    let make = wrapper_region(&bindings, "make");
    let describe = wrapper_region(&bindings, "describe");

    // The emitted app crate aliases each opaque foreign type to its wrapper-crate
    // path, exactly as the backend does from the interface's opaque-type map. The
    // wrapper regions reference the bare nominal (`Engine`); the alias resolves it.
    let iface = crate_interface(&pkg);
    let mut aliases = String::new();
    for (name, path) in &iface.opaque_types {
        use std::fmt::Write as _;
        let _ = writeln!(aliases, "pub type {name} = {path};");
    }

    std::fs::create_dir_all(root.join("src")).expect("mkdir app");
    std::fs::write(
        root.join("Cargo.toml"),
        format!(
            "[package]\nname = \"wrapper_seal\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\
             [[bin]]\nname = \"wrapper_seal\"\npath = \"src/main.rs\"\n\
             [dependencies]\n{}\n",
            dep_lines.join("\n")
        ),
    )
    .expect("app Cargo.toml");

    // Minimal runtime glue the emitted pure-plain wrappers reference
    // (`IpeResult`, `IpeError`, `ok_res`, `str_err`) — a stand-in for the
    // vendored `use crate::*;`.
    let main_rs = format!(
        r#"#![allow(unused_imports, unused_mut, dead_code)]
pub enum IpeResult<E, T> {{ Ok(T), Err(E) }}
pub struct IpeError(String);
pub fn ok_res<T>(t: T) -> IpeResult<IpeError, T> {{ IpeResult::Ok(t) }}
pub fn str_err(s: &str) -> IpeError {{ IpeError(s.to_string()) }}
pub fn ipe_error_from_panic(c: &str, _p: Box<dyn std::any::Any + Send>) -> IpeError {{ IpeError(c.to_string()) }}
pub fn note_foreign_panic(_c: &str, _p: Box<dyn std::any::Any + Send>) -> String {{ String::new() }}
pub fn note_foreign_error<T: std::fmt::Debug>(_e: T) -> String {{ String::new() }}
pub fn ipe_error_from_foreign<T: std::fmt::Debug>(_e: T) -> IpeError {{ IpeError("external operation failed".to_string()) }}

// Opaque foreign-type aliases the backend emits from the interface map.
{aliases}

{make}

{describe}

fn main() {{
    // The constructor builds a real wrapper-crate value; the reader consumes it.
    let engine = match engine_wrap_make(7) {{
        IpeResult::Ok(e) => e,
        IpeResult::Err(_) => panic!("make failed"),
    }};
    let text = match engine_wrap_describe(engine) {{
        IpeResult::Ok(s) => s,
        IpeResult::Err(_) => panic!("describe failed"),
    }};
    println!("{{}}", text);
}}
"#,
    );
    std::fs::write(root.join("src").join("main.rs"), main_rs).expect("app main.rs");

    let out = std::process::Command::new(&cargo)
        .arg("run")
        .arg("--quiet")
        .current_dir(&root)
        .output()
        .expect("cargo run spawns");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "the emitted app crate + wrapper path dep must build and run exit 0.\n\
         stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("engine<7>"),
        "the value must round-trip through the wrapper crate.\nstdout: {stdout}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// Extract the sentinel-bracketed wrapper region for `ref_name` from an emitted
/// `_bindings.rs`, without the preamble.
fn wrapper_region(bindings: &str, ref_name: &str) -> String {
    let begin = format!("// IPE-FFI-WRAPPER BEGIN {ref_name}");
    let mut keep = false;
    let mut out = String::new();
    for line in bindings.lines() {
        if line.trim_end() == begin {
            keep = true;
            continue;
        }
        if line.trim_end() == "// IPE-FFI-WRAPPER END" && keep {
            break;
        }
        if keep {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}
