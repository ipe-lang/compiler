//! SEAL fixture for OPAQUE-return closure adapters (the opaque-map threaded
//! into the closure-adapter emitter).
//!
//! The neighbouring `closure_adapter_seal` fixture proves a SCALAR
//! `Result<Int>` closure round-trips. This fixture proves the next link: a
//! closure whose `Result` Ok carrier is an OPAQUE handle (`Fn(Counter) ->
//! Result<Counter, E>` — the shape an Iced `update` fn folding a model needs).
//! The emitted adapter must resolve the opaque through the crate's opaque-map:
//!
//!  * a define-DEFINED opaque (`Counter`, defined in the same `pub mod <slug>`
//!    region) resolves to the bare in-module name and round-trips;
//!  * a lifetime/generic-parameterised inspected opaque (`Element<'a, Message>`)
//!    is unsound to emit as a stripped bare-arg path, so the whole adapter
//!    OVER-DROPS (no wrapper) rather than breach the `ipe dev build ⇒ cargo build`
//!    keystone. This is why Iced's `view : Model -> Element Message` stays
//!    refused: the bare-handle carrier cannot carry `Element`'s generic args.
//!
//! The emit-only assertions run in the DEFAULT gate; the cargo build+run proof
//! is `IPE_E2E`-gated (it shells out to `cargo`), matching the repo's other SEAL
//! fixtures.
#![allow(clippy::expect_used)] // test setup: a failed decode / scratch-dir op IS the failure

use ipe_ffi::bindings::{emit_bindings, surviving_ref_names};
use ipe_ffi::pkginfo::PkgInfo;

/// A one-crate package that DEFINES a `Counter` (define.struct) and declares a
/// closure adapter `Fn(Counter) -> Result<Counter, E>` over it — the exact
/// opaque-return shape a TEA `update` fold needs.
fn counter_update_pkg() -> PkgInfo {
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
                "name": "update_fn", "effect": "pure", "isClosureAdapter": true,
                "closureSig": "Fn(Counter) -> Result<Counter, Error> + Send + Sync + 'static"
            }
        ],
        "errors": []
    })
    .to_string();
    PkgInfo::decode_json(&doc).expect("define surface decodes")
}

/// Default gate: a `Result<opaque>` closure over a define-defined type emits a
/// wrapper naming the in-module opaque on BOTH box sides (received + returned),
/// with the panic-fold-to-`Err` arm intact.
#[test]
fn a_define_defined_opaque_result_closure_emits_a_resolvable_wrapper() {
    let out = emit_bindings(&counter_update_pkg());
    // The opaque return resolves to the in-module `Counter` on the received box
    // AND the handle alias; the wrapper returns the opaque handle nominal.
    assert!(
        out.contains(
            "pub type UpdateFnClosure = Box<dyn Fn(Counter) -> Result<Counter, IpeError> \
             + Send + Sync + 'static>;"
        ),
        "the handle alias resolves the opaque return to the in-module `Counter`:\n{out}"
    );
    assert!(
        out.contains(
            "pub fn demo_update_fn(__ipe_fn: Box<dyn Fn(Counter) -> Result<Counter, IpeError> \
             + Send + Sync + 'static>) -> UpdateFnClosure {"
        ),
        "the received box resolves `Counter`; the return is the handle:\n{out}"
    );
    assert!(
        out.contains("Err(__p) => Err(ipe_error_from_panic(\"foreign closure panicked\", __p))"),
        "the per-call panic folds to Err:\n{out}"
    );
    assert!(
        surviving_ref_names(&counter_update_pkg()).contains("update_fn"),
        "the survivor gate admits the resolvable adapter"
    );
}

/// Default gate: a lifetime/generic-parameterised inspected opaque return
/// (`iced::Element<'a, Message>`) over-drops the whole adapter — the marquee
/// Iced `view` case stays refused, and the survivor gate agrees (no phantom).
#[test]
fn a_parameterised_opaque_return_over_drops() {
    let doc = serde_json::json!({
        "pkg": "iced", "name": "iced", "version": "0.12.1",
        "functions": [
            {
                "name": "make_view", "params": [],
                "results": [{ "name": "", "type": "Element",
                              "rustType": "iced::Element<'a, Message>" }],
                "effect": "pure"
            },
            {
                "name": "view_fn", "effect": "pure", "isClosureAdapter": true,
                "closureSig": "Fn(Counter) -> Result<Element, Error> + Send + Sync + 'static"
            }
        ],
        "errors": []
    })
    .to_string();
    let pkg = PkgInfo::decode_json(&doc).expect("decodes");
    let out = emit_bindings(&pkg);
    assert!(
        !out.contains("iced_view_fn"),
        "a parameterised opaque return must over-drop the adapter:\n{out}"
    );
    assert!(
        !surviving_ref_names(&pkg).contains("view_fn"),
        "the survivor gate must not admit the over-dropped adapter"
    );
}

/// The load-bearing SEAL proof: under `IPE_E2E=1`, assemble a crate with the
/// emitted define-`Counter` definition + the emitted opaque-return closure
/// adapter, supply an Ipê closure folding the model, pass it through the
/// adapter, and RUN — proving the resolved opaque return builds and both the
/// happy-path and the panic-fold-to-`Err` arms behave.
#[test]
fn opaque_return_closure_builds_and_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let cargo = ipe_env::var("CARGO").expect("cargo sets CARGO for every test it runs");

    // The full emitted `_bindings.rs`: the `Counter` definition + ctor AND the
    // opaque-return adapter, wrapped as the backend's `pub mod <slug>` region.
    let bindings = emit_bindings(&counter_update_pkg());
    let slug = "demo";
    let ffi_body = format!("pub mod {slug} {{\n{bindings}}}\npub use {slug}::*;\n");

    let dir =
        ipe_test_temp::temp_root().join(format!("ipe_ffi_opaque_ret_seal_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src")).expect("mkdir");
    std::fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"opaque_ret_seal\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\
         [[bin]]\nname = \"opaque_ret_seal\"\npath = \"src/main.rs\"\n\
         # catch_unwind soundness requires panic=unwind (the emitter's own fence)\n\
         [profile.dev]\npanic = \"unwind\"\n",
    )
    .expect("Cargo.toml");

    // The emitted bindings' preamble is `use crate::*;`, so the crate root must
    // supply the runtime glue the adapter names (`IpeError`, `str_err`). A
    // minimal stand-in stands in for the real `ipe_runtime`.
    let main_rs = format!(
        r#"// Minimal runtime glue the emitted Result adapter references, at the
// crate root so the bindings' `use crate::*;` brings it into scope.
#[derive(Debug)]
pub struct IpeError(String);
pub fn str_err<E: From<String>>(s: &str) -> E {{ s.to_string().into() }}
pub fn ipe_error_from_panic<E: From<String>>(c: &str, _p: Box<dyn std::any::Any + Send>) -> E {{ c.to_string().into() }}
pub fn note_foreign_panic(_c: &str, _p: Box<dyn std::any::Any + Send>) -> String {{ String::new() }}
pub fn note_foreign_error<T: std::fmt::Debug>(_e: T) -> String {{ String::new() }}
pub fn ipe_error_from_foreign<T: std::fmt::Debug, E: From<String>>(_e: T) -> E {{ "external operation failed".to_string().into() }}
impl From<String> for IpeError {{ fn from(s: String) -> Self {{ IpeError(s) }} }}

mod ffi {{
    use crate::*;
    {ffi_body}
}}

use ffi::demo::Counter;

// A tiny "crate" driver that takes the boxed closure the adapter returns and
// folds a model with it — the exact shape an Iced `update` loop would.
fn crate_folds(
    f: Box<dyn Fn(Counter) -> Result<Counter, IpeError> + Send + Sync + 'static>,
) -> i64 {{
    let mut c = ffi::demo_counter_new(0);
    for _ in 0..3 {{
        c = f(c).unwrap_or_else(|_| ffi::demo_counter_new(-100));
    }}
    c.value
}}
fn crate_folds_panicking(
    f: Box<dyn Fn(Counter) -> Result<Counter, IpeError> + Send + Sync + 'static>,
) -> i64 {{
    // A panicking Ipê closure must fold to Err, never abort the process.
    match f(ffi::demo_counter_new(0)) {{
        Ok(c) => c.value,
        Err(_) => -1,
    }}
}}

fn main() {{
    // The Ipê function value: on the app side, exactly a
    // `Box<dyn Fn(Counter) -> Result<Counter, IpeError> + Send + Sync + 'static>`.
    let ipe_ok: Box<dyn Fn(Counter) -> Result<Counter, IpeError> + Send + Sync + 'static> =
        Box::new(|c| Ok(ffi::demo_counter_new(c.value + 1)));
    let adapted = ffi::demo_update_fn(ipe_ok);
    let folded = crate_folds(adapted); // 0 -> 1 -> 2 -> 3

    let ipe_panics: Box<dyn Fn(Counter) -> Result<Counter, IpeError> + Send + Sync + 'static> =
        Box::new(|_| panic!("boom"));
    let adapted_panic = ffi::demo_update_fn(ipe_panics);
    let panicked = crate_folds_panicking(adapted_panic); // folds to Err -> -1

    assert_eq!(folded, 3, "opaque-return closure folds the model");
    assert_eq!(panicked, -1, "a panicking closure folds to Err, never aborts");
    println!("{{folded}} {{panicked}}");
}}
"#
    );
    std::fs::write(dir.join("src").join("main.rs"), main_rs).expect("main.rs");

    let out = std::process::Command::new(&cargo)
        .arg("run")
        .arg("--quiet")
        .current_dir(&dir)
        .output()
        .expect("cargo run spawns");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "the emitted opaque-return adapter crate must build and run exit 0.\n\
         stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("3 -1"),
        "the opaque-return closure must fold the model and fold a panic to Err.\nstdout: {stdout}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
