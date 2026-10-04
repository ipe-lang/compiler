//! SEAL fixture for OPAQUE `define.struct` fields and `define.enum` variant
//! payloads (the crate opaque-map threaded into the definition emitter).
//!
//! The neighbouring `define_struct_seal` / `define_enum_seal` fixtures prove a
//! struct of SCALAR fields and an enum of scalar/unit variants round-trip. This
//! fixture proves the next link: a `define.struct` FIELD or a `define.enum`
//! variant PAYLOAD whose type is a crate-opaque handle (the shape an Iced `Model`
//! holding a sub-widget, or a `Message` variant carrying one, needs). The emitted
//! definition must resolve the opaque through the crate's opaque-map:
//!
//!  * a define-DEFINED opaque (`Counter`, defined in the same `pub mod <slug>`
//!    region) resolves to the bare in-module name and round-trips;
//!  * a lifetime/generic-parameterised inspected opaque (`Element<'a, Message>`)
//!    is unsound to emit as a stripped bare-arg path (an E0107), so the whole
//!    definition OVER-DROPS (no wrapper) rather than breach the `ipe dev build ⇒
//!    cargo build` keystone — and the interface, keyed off the same survivor
//!    gate, never surfaces a forwarder onto the absent wrapper fn.
//!
//! The emit-only assertions run in the DEFAULT gate; the cargo build+run proof is
//! `IPE_E2E`-gated (it shells out to `cargo`), matching the repo's other SEAL
//! fixtures.
#![allow(clippy::expect_used)] // test setup: a failed decode / scratch-dir op IS the failure

use ipe_ffi::bindings::{emit_bindings, surviving_ref_names};
use ipe_ffi::interface::crate_interface;
use ipe_ffi::pkginfo::PkgInfo;

/// A one-crate package that DEFINES a `Counter` (define.struct scalar), a
/// `Model` (define.struct holding a `Counter` opaque field), and a `Message`
/// (define.enum with a variant carrying a `Counter` opaque payload) — the exact
/// opaque-field / opaque-payload shapes a TEA model + message need.
fn model_message_pkg() -> PkgInfo {
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
                "name": "model_new", "effect": "pure", "isStructCtor": true,
                "structName": "Model",
                "structFields": [
                    { "name": "counter", "type": "Counter" },
                    { "name": "tick", "type": "i64" }
                ],
                "structDerives": ["Clone"]
            },
            {
                "name": "message", "effect": "pure", "isEnumDef": true,
                "enumName": "Message",
                "enumVariants": [
                    { "name": "Increment", "payload": [] },
                    { "name": "SetCounter", "payload": ["Counter"] }
                ],
                "enumDerives": ["Clone"]
            }
        ],
        "errors": []
    })
    .to_string();
    PkgInfo::decode_json(&doc).expect("define surface decodes")
}

/// Default gate: a define-defined opaque FIELD resolves to the bare in-module
/// name in the emitted struct definition + constructor, and the survivor gate +
/// interface admit the forwarder (no phantom).
#[test]
fn a_define_defined_opaque_field_resolves_in_module() {
    let out = emit_bindings(&model_message_pkg());
    assert!(
        out.contains("pub struct Model {"),
        "the Model definition emits:\n{out}"
    );
    assert!(
        out.contains("    pub counter: Counter,"),
        "the opaque field resolves to the in-module `Counter`:\n{out}"
    );
    assert!(
        out.contains("pub fn demo_model_new(arg0: Counter, arg1: i64) -> Model {"),
        "the constructor param names the same resolved opaque:\n{out}"
    );
    assert!(
        surviving_ref_names(&model_message_pkg()).contains("model_new"),
        "the survivor gate admits the resolvable struct"
    );
    let iface = crate_interface(&model_message_pkg());
    assert!(
        iface.define_types.contains("Model"),
        "the interface registers the Model nominal"
    );
    assert!(
        iface.bindings.iter().any(|b| b.ref_name == "model_new"),
        "the interface admits the model_new forwarder"
    );
}

/// Default gate: a define-defined opaque PAYLOAD resolves to the bare in-module
/// name in the emitted enum definition + variant constructor.
#[test]
fn a_define_defined_opaque_payload_resolves_in_module() {
    let out = emit_bindings(&model_message_pkg());
    assert!(
        out.contains("pub enum Message {"),
        "the Message definition emits:\n{out}"
    );
    assert!(
        out.contains("    SetCounter(Counter),"),
        "the opaque payload resolves to the in-module `Counter`:\n{out}"
    );
    assert!(
        out.contains("pub fn demo_message_set_counter(arg0: Counter) -> Message {"),
        "the variant constructor param names the same resolved opaque:\n{out}"
    );
    let iface = crate_interface(&model_message_pkg());
    assert!(
        iface
            .bindings
            .iter()
            .any(|b| b.ref_name == "message_set_counter"),
        "the interface admits the opaque-payload variant forwarder"
    );
}

/// Default gate: a lifetime/generic-parameterised inspected opaque field
/// (`iced::Element<'a, Message>`) over-drops the WHOLE struct — the marquee Iced
/// `Model` holding a bare `Element` stays refused, and neither the survivor gate
/// nor the interface surfaces a forwarder onto the absent wrapper.
#[test]
fn a_parameterised_opaque_field_over_drops() {
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
                "name": "model_new", "effect": "pure", "isStructCtor": true,
                "structName": "Model",
                "structFields": [{ "name": "view", "type": "Element" }],
                "structDerives": []
            }
        ],
        "errors": []
    })
    .to_string();
    let pkg = PkgInfo::decode_json(&doc).expect("decodes");
    let out = emit_bindings(&pkg);
    assert!(
        !out.contains("pub struct Model"),
        "a parameterised opaque field must over-drop the definition:\n{out}"
    );
    assert!(
        !surviving_ref_names(&pkg).contains("model_new"),
        "the survivor gate must not admit the over-dropped struct"
    );
    let iface = crate_interface(&pkg);
    assert!(
        !iface.define_types.contains("Model"),
        "the interface must not register the over-dropped Model nominal"
    );
    assert!(
        !iface.bindings.iter().any(|b| b.ref_name == "model_new"),
        "the interface must not surface a forwarder onto the absent wrapper"
    );
}

/// Default gate: a parameterised opaque PAYLOAD (`Element<'a, Message>` carried by
/// a `Message` variant) over-drops the WHOLE enum — every variant forwarder gone.
#[test]
fn a_parameterised_opaque_payload_over_drops() {
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
                "name": "message", "effect": "pure", "isEnumDef": true,
                "enumName": "Msg",
                "enumVariants": [
                    { "name": "Tick", "payload": [] },
                    { "name": "Render", "payload": ["Element"] }
                ],
                "enumDerives": []
            }
        ],
        "errors": []
    })
    .to_string();
    let pkg = PkgInfo::decode_json(&doc).expect("decodes");
    let out = emit_bindings(&pkg);
    assert!(
        !out.contains("pub enum Msg"),
        "a parameterised opaque payload must over-drop the whole enum:\n{out}"
    );
    assert!(
        !surviving_ref_names(&pkg).contains("message"),
        "the survivor gate must not admit the over-dropped enum"
    );
    let iface = crate_interface(&pkg);
    assert!(
        !iface
            .bindings
            .iter()
            .any(|b| b.ref_name.starts_with("message")),
        "no variant forwarder survives the over-drop, not even the unit `Tick`"
    );
}

/// Default gate — the TRANSITIVE over-drop: a define type `Outer` that resolves
/// in isolation (its only opaque field is another define type `Inner`) MUST
/// over-drop when `Inner` itself over-drops (Inner's own field is a parameterised
/// `Element`). Otherwise `Outer` would emit `pub struct Outer { inner: Inner }`
/// referencing an `Inner` that was never emitted (an E0425 the SEAL forbids). The
/// survivor fixed point removes `Outer` because its dependency `Inner` is gone.
#[test]
fn a_define_type_referencing_an_over_dropped_define_type_also_over_drops() {
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
                // Inner holds a PARAMETERISED opaque → over-drops on its own.
                "name": "inner_new", "effect": "pure", "isStructCtor": true,
                "structName": "Inner",
                "structFields": [{ "name": "view", "type": "Element" }],
                "structDerives": []
            },
            {
                // Outer's only opaque field is Inner — resolvable IN ISOLATION,
                // but must fall with Inner.
                "name": "outer_new", "effect": "pure", "isStructCtor": true,
                "structName": "Outer",
                "structFields": [{ "name": "inner", "type": "Inner" }],
                "structDerives": []
            }
        ],
        "errors": []
    })
    .to_string();
    let pkg = PkgInfo::decode_json(&doc).expect("decodes");
    let out = emit_bindings(&pkg);
    assert!(
        !out.contains("pub struct Inner"),
        "the parameterised-field Inner over-drops:\n{out}"
    );
    assert!(
        !out.contains("pub struct Outer"),
        "Outer must over-drop transitively with Inner, not reference an absent type:\n{out}"
    );
    let survivors = surviving_ref_names(&pkg);
    assert!(
        !survivors.contains("inner_new") && !survivors.contains("outer_new"),
        "neither the over-dropped Inner nor the transitively-dropped Outer survives"
    );
    let iface = crate_interface(&pkg);
    assert!(
        !iface.define_types.contains("Outer") && !iface.define_types.contains("Inner"),
        "the interface registers neither over-dropped nominal"
    );
    assert!(
        !iface
            .bindings
            .iter()
            .any(|b| b.ref_name == "outer_new" || b.ref_name == "inner_new"),
        "the interface surfaces no forwarder onto an absent wrapper"
    );
}

/// Default gate — a resolvable CHAIN survives end to end: `Outer` holds `Middle`
/// holds a scalar-only `Leaf`, all define-defined, so every link resolves and the
/// whole chain emits. Guards the fixed point against over-dropping a sound chain.
#[test]
fn a_resolvable_define_type_chain_all_survives() {
    let doc = serde_json::json!({
        "pkg": "demo", "name": "demo", "version": "0.1.0",
        "functions": [
            {
                "name": "leaf_new", "effect": "pure", "isStructCtor": true,
                "structName": "Leaf",
                "structFields": [{ "name": "n", "type": "i64" }],
                "structDerives": ["Clone"]
            },
            {
                "name": "middle_new", "effect": "pure", "isStructCtor": true,
                "structName": "Middle",
                "structFields": [{ "name": "leaf", "type": "Leaf" }],
                "structDerives": ["Clone"]
            },
            {
                "name": "outer_new", "effect": "pure", "isStructCtor": true,
                "structName": "Outer",
                "structFields": [{ "name": "middle", "type": "Middle" }],
                "structDerives": ["Clone"]
            }
        ],
        "errors": []
    })
    .to_string();
    let pkg = PkgInfo::decode_json(&doc).expect("decodes");
    let out = emit_bindings(&pkg);
    assert!(out.contains("    pub leaf: Leaf,"), "{out}");
    assert!(out.contains("    pub middle: Middle,"), "{out}");
    let survivors = surviving_ref_names(&pkg);
    assert!(
        survivors.contains("leaf_new")
            && survivors.contains("middle_new")
            && survivors.contains("outer_new"),
        "every link of a resolvable define chain survives"
    );
}

/// The load-bearing SEAL proof: under `IPE_E2E=1`, assemble a crate with the
/// emitted `Counter` + `Model` (opaque field) + `Message` (opaque payload)
/// definitions and their constructors, build a model holding a counter, drive a
/// message that replaces it, and RUN — proving the resolved opaque field/payload
/// build and round-trip.
#[test]
fn opaque_field_and_payload_build_and_run() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let cargo = ipe_env::var("CARGO").expect("cargo sets CARGO for every test it runs");

    // The full emitted `_bindings.rs`: the three definitions + their ctors,
    // wrapped as the backend's `pub mod <slug>` region.
    let bindings = emit_bindings(&model_message_pkg());
    let slug = "demo";
    let ffi_body = format!("pub mod {slug} {{\n{bindings}}}\npub use {slug}::*;\n");

    let dir = ipe_test_temp::temp_root()
        .join(format!("ipe_ffi_opaque_field_seal_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src")).expect("mkdir");
    std::fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"opaque_field_seal\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\
         [[bin]]\nname = \"opaque_field_seal\"\npath = \"src/main.rs\"\n",
    )
    .expect("Cargo.toml");

    let main_rs = format!(
        r#"mod ffi {{
    {ffi_body}
}}

use ffi::demo::{{Counter, Message, Model}};

// A tiny "crate" fn that consumes the Ipê-defined model + message — the exact
// shape an Iced/TEA `update : Message -> Model -> Model` loop would.
fn crate_update(model: Model, msg: Message) -> Model {{
    match msg {{
        Message::Increment => ffi::demo_model_new(
            ffi::demo_counter_new(model.counter.value + 1),
            model.tick + 1,
        ),
        Message::SetCounter(c) => ffi::demo_model_new(c, model.tick + 1),
    }}
}}

fn main() {{
    // The opaque field: a Model holds a Counter (a nominal defined in the same
    // crate), built through the emitted constructors.
    let m0: Model = ffi::demo_model_new(ffi::demo_counter_new(10), 0);
    let m1 = crate_update(m0.clone(), ffi::demo_message_increment(()));
    // The opaque payload: a Message variant CARRIES a Counter.
    let m2 = crate_update(m1, ffi::demo_message_set_counter(ffi::demo_counter_new(99)));
    assert_eq!(m0.counter.value, 10, "opaque field round-trips");
    assert_eq!(m2.counter.value, 99, "opaque payload round-trips through update");
    assert_eq!(m2.tick, 2, "the scalar field advances alongside the opaque one");
    println!("{{}} {{}}", m2.counter.value, m2.tick);
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
        "the emitted opaque-field/payload crate must build and run exit 0.\n\
         stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("99 2"),
        "the opaque field/payload must round-trip through the update loop.\nstdout: {stdout}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
