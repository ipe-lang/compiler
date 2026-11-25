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
//! repo's other SEAL fixtures. The app crate depends on the real runtime and
//! opens with the FFI crate scope the backend's template carries, so the
//! wrappers' `use crate::*;` resolves exactly what a shipped program provides.
//! An effectful wrapper builds both in that app and in the Tier-2 probe, whose
//! crate root takes the same scope.
#![allow(clippy::expect_used)] // test setup: a failed decode / scratch-dir op IS the failure

use std::path::Path;

use ipe_ffi::bindings::{emit_bindings, surviving_ref_names};
use ipe_ffi::driver::{FfiCache, cargo_dep_lines};
use ipe_ffi::interface::crate_interface;
use ipe_ffi::pkginfo::PkgInfo;
use ipe_ffi::probe::{emit_probe_main, surviving_wrapper_paths};

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
/// bindings, then build and run it. `ipe` exit 0 ⇒ this crate compiles;
/// the run asserts the constructor and reader round-trip through the wrapper.
#[test]
fn the_emitted_crate_and_wrapper_path_dep_build_and_run() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
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
    let ffi_rs = e2e_support::ffi_app::package_module("engine_wrap", &bindings);

    // The bindings name the wrapper crate's opaque `Engine` at its
    // crate-absolute path, so the app's own code needs no alias.
    let main_rs = r#"#[allow(clippy::panic)] // a test-environment setup failure fails the test with its cause
fn main() {
    // The constructor builds a real wrapper-crate value; the reader consumes it.
    let engine = match ffi::engine_wrap_make(7) {
        IpeResult::Ok(e) => e,
        IpeResult::Err(_) => panic!("make failed"),
    };
    let text = match ffi::engine_wrap_describe(engine) {
        IpeResult::Ok(s) => s,
        IpeResult::Err(_) => panic!("describe failed"),
    };
    println!("{}", text);
}
"#;
    e2e_support::ffi_app::FfiApp {
        name: "wrapper_seal",
        runtime_features: &[],
        dependencies: &dep_lines,
        ffi_rs: &ffi_rs,
        main_rs,
    }
    .write(&root)
    .expect("the app crate is written");

    let ran = e2e_support::build_and_run_rust("ffi_wrapper_crate", &root);
    assert!(
        ran.is_ok(),
        "{}",
        ran.as_ref().err().map_or("", String::as_str)
    );
    let run = ran.expect("asserted Ok above");
    let stdout = &run.stdout;
    assert_eq!(
        run.exit_code,
        Some(0),
        "the emitted app crate + wrapper path dep must build and run exit 0.\n\
         stdout: {stdout}"
    );
    assert!(
        stdout.contains("engine<7>"),
        "the value must round-trip through the wrapper crate.\nstdout: {stdout}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// The package slug, wrapper crate name and app crate prefix of the async seals.
const ASYNC_WRAP: &str = "async_wrap";

/// The inspection document for an async wrapper crate at `wrapper_path`.
///
/// `greet` is an `async fn` the inspector reports as effectful. `drive` takes a
/// boxed future, which no Ipê task lowers to: the foreign future yields a bare
/// `String`, an Ipê task a result.
fn async_wrapper_pkg(wrapper_path: &str) -> PkgInfo {
    let doc = serde_json::json!({
        "pkg": ASYNC_WRAP,
        "name": ASYNC_WRAP,
        "version": "0.1.0",
        "wrapperPath": wrapper_path,
        "functions": [
            {
                "name": "greet",
                "params": [{ "name": "name", "type": "String", "ipeType": "String", "rustType": "String" }],
                "results": [{ "name": "", "type": "String", "rustType": "String" }],
                "effect": "effectful"
            },
            {
                "name": "drive",
                "params": [{
                    "name": "fut",
                    "type": "Task Error String",
                    "ipeType": "Task Error String",
                    "rustType": "Pin<Box<dyn Future<Output = String> + Send>>"
                }],
                "results": [{ "name": "", "type": "String", "rustType": "String" }],
                "effect": "pure"
            }
        ],
        "errors": []
    })
    .to_string();
    PkgInfo::decode_json(&doc).expect("async wrapper inspection decodes")
}

/// Write the async wrapper crate and its app crate under `root`.
///
/// The app crate reaches the runtime's `async` feature, as an emitted program
/// with an effectful binding does; `main_rs` is the program's own items.
fn write_async_app(root: &Path, name: &str, main_rs: &str) -> PkgInfo {
    let wrapper_dir = root.join("wrappers").join(ASYNC_WRAP);
    std::fs::create_dir_all(wrapper_dir.join("src")).expect("mkdir wrapper");
    std::fs::write(
        wrapper_dir.join("Cargo.toml"),
        format!("[package]\nname = \"{ASYNC_WRAP}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"),
    )
    .expect("wrapper Cargo.toml");
    std::fs::write(
        wrapper_dir.join("src").join("lib.rs"),
        "use std::future::Future;\n\
         use std::pin::Pin;\n\
         pub async fn greet(name: String) -> String { let mut s = String::from(\"hello \"); s.push_str(&name); s }\n\
         pub fn drive(fut: Pin<Box<dyn Future<Output = String> + Send>>) -> String {\n    \
         drop(fut);\n    String::from(\"driven\")\n}\n",
    )
    .expect("wrapper lib.rs");
    let pkg = async_wrapper_pkg(&format!("wrappers/{ASYNC_WRAP}"));
    let dep_lines = cargo_dep_lines(&pkg, &FfiCache::at_project_root(root))
        .expect("the wrapper jails inside the scratch root");
    let ffi_rs = e2e_support::ffi_app::package_module(ASYNC_WRAP, &emit_bindings(&pkg));
    e2e_support::ffi_app::FfiApp {
        name,
        runtime_features: &["async"],
        dependencies: &dep_lines,
        ffi_rs: &ffi_rs,
        main_rs,
    }
    .write(root)
    .expect("the app crate is written");
    pkg
}

/// Default gate: the async surface binds `greet` as a task and over-drops `drive`.
///
/// A future parameter has no Ipê lowering, so its wrapper is never emitted;
/// the probe's surface is exactly the effectful wrapper.
#[test]
fn a_future_param_over_drops_and_the_effectful_fn_binds_a_task() {
    let pkg = async_wrapper_pkg("wrappers/async_wrap");
    let survivors = surviving_ref_names(&pkg);
    assert!(
        survivors.iter().any(|s| s == "greet"),
        "the effectful fn survives: {survivors:?}"
    );
    assert!(
        !survivors.iter().any(|s| s == "drive"),
        "a future parameter over-drops: {survivors:?}"
    );
    let bindings = emit_bindings(&pkg);
    assert!(
        bindings.contains(&format!(") -> {} {{", ipe_intern::ffi_task_type("String"))),
        "the effectful wrapper returns the scope's task alias:\n{bindings}"
    );
    assert!(
        !bindings.contains("::async_wrap::drive"),
        "a future parameter must over-drop, never emit-and-cargo-fail:\n{bindings}"
    );
    assert_eq!(
        surviving_wrapper_paths(&pkg, ASYNC_WRAP).len(),
        1,
        "the probe surface is the effectful wrapper alone"
    );
}

/// Under `IPE_E2E=1`, an effectful wrapper builds and runs under the FFI crate scope.
///
/// The driver mirrors the template's `fn main`: the runtime's panic classifier,
/// then the runtime's own entry driving the wrapper's task.
#[test]
fn an_effectful_wrapper_builds_under_the_scope() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let root =
        ipe_test_temp::temp_root().join(format!("ipe_ffi_async_wrap_seal_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let main_rs = r#"fn main() {
    ipe_runtime::core::install_panic_classifier();
    match block_on_entry(|| ffi::async_wrap_greet("seal".to_owned())) {
        IpeResult::Ok(text) => println!("{text}"),
        IpeResult::Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}
"#;
    write_async_app(&root, "async_wrap_seal", main_rs);

    let ran = e2e_support::build_and_run_rust("ffi_async_wrapper_crate", &root);
    assert!(
        ran.is_ok(),
        "{}",
        ran.as_ref().err().map_or("", String::as_str)
    );
    let run = ran.expect("asserted Ok above");
    assert_eq!(run.exit_code, Some(0), "stdout: {}", run.stdout);
    assert!(
        run.stdout.contains("hello seal"),
        "the task's value must round-trip through the wrapper.\nstdout: {}",
        run.stdout
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// Under `IPE_E2E=1`, the Tier-2 probe over an effectful surface cargo-builds.
///
/// The probe's crate root is the FFI crate scope plus `mod ffi;`, the same
/// scope the app crate opens with, so the probe builds exactly the bindings a
/// shipped program builds.
#[test]
fn the_tier2_probe_builds_an_effectful_surface() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let root =
        ipe_test_temp::temp_root().join(format!("ipe_ffi_async_wrap_probe_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let pkg = write_async_app(&root, "async_wrap_probe", "fn main() {}\n");
    let paths = surviving_wrapper_paths(&pkg, ASYNC_WRAP);
    assert!(!paths.is_empty(), "the effectful wrapper survives");
    let probe = emit_probe_main(&paths, &ipe_intern::ffi_crate_root());
    std::fs::write(root.join("src").join("main.rs"), probe).expect("the probe root is written");

    let built = e2e_support::build_rust_binary("ffi_async_wrapper_probe", &root);
    assert!(
        built.is_ok(),
        "{}",
        built.as_ref().err().map_or("", String::as_str)
    );
    let _ = std::fs::remove_dir_all(&root);
}
