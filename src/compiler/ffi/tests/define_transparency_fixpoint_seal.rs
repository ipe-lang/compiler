//! SEAL fixture for the DEFINE-TRANSPARENCY LEAST-FIXPOINT.
//!
//! Transparency of a define type is a least-fixpoint over the define types it
//! references: a define type surfaces transparent only when EVERY define type it
//! names at a member seam (another define's field or variant payload, a closure
//! signature slot) is itself transparent and survived decode. A define type that
//! holds an opaque or dropped member is NOT transparent — it un-flips to the
//! opaque nominal, or falls with the member. A record surfaced over a
//! non-transparent field is exactly an `ipe`-exit-0-then-cargo-fail (a missing
//! type or an `E0308`), the keystone breach the fixpoint forbids.
//!
//! This fixture pins that transitive invariant fail-closed: it proves a define
//! type that references another define type as a member NEVER surfaces
//! transparent while the referenced type is held opaque, in either direction and
//! whether the referenced type qualifies in isolation or not. The scalar-only
//! transparent floor (`define_forwarder_seal`) and the opaque-field survivor
//! floor (`define_opaque_field_seal`) are the neighbours this fixture sits
//! between: it is the SEAL that the transparent surface can never leak past a
//! member the conversion glue does not cover.
//!
//! The classification/interface assertions run in the DEFAULT gate; the negative
//! build proof (a define holding an opaque member fails closed — no transparent
//! record over an opaque field ever reaches `cargo`) is `IPE_E2E`-gated, matching
//! the repo's other SEAL fixtures.
#![allow(clippy::expect_used)] // test setup: a failed decode / scratch-dir op IS the failure

use ipe_ffi::bindings::{emit_bindings, surviving_ref_names};
use ipe_ffi::interface::crate_interface;
use ipe_ffi::pkginfo::PkgInfo;

/// A package where a scalar-only `Counter` qualifies transparent in isolation,
/// and a `Model` holds it as a field. The referenced `Counter` sits at a member
/// seam, so the fixpoint pins BOTH to the opaque representation — the conversion
/// glue does not cover a transparent member.
fn model_holds_counter_pkg() -> PkgInfo {
    let doc = serde_json::json!({
        "pkg": "demo", "name": "demo", "version": "0.1.0",
        "functions": [
            {
                "name": "counter_new", "effect": "pure", "isStructCtor": true,
                "structName": "Counter",
                "structFields": [{ "name": "value", "type": "i64" }],
                "structDerives": ["Clone"]
            },
            {
                "name": "model_new", "effect": "pure", "isStructCtor": true,
                "structName": "Model",
                "structFields": [
                    { "name": "counter", "type": "Counter" },
                    { "name": "tick", "type": "i64" }
                ],
                "structDerives": ["Clone"]
            }
        ],
        "errors": []
    })
    .to_string();
    PkgInfo::decode_json(&doc).expect("define surface decodes")
}

/// The transitive fixpoint, struct field seam: a `Counter` that qualifies
/// transparent in isolation is pinned OPAQUE the moment another define type holds
/// it as a member — and the holder `Model` is opaque too. Neither surfaces a
/// transparent record. Default gate.
#[test]
fn a_referenced_define_member_pins_both_types_opaque() {
    let iface = crate_interface(&model_holds_counter_pkg());
    // The referenced `Counter` is a member seam of `Model`, so the fixpoint holds
    // it opaque even though it is scalar-only (it would qualify in isolation).
    assert!(
        !iface.transparent_types.contains_key("Counter"),
        "a define type held as another define's member must not surface transparent: {:?}",
        iface.transparent_types.keys().collect::<Vec<_>>()
    );
    assert!(
        iface.define_types.contains("Counter"),
        "the referenced member keeps the opaque nominal"
    );
    // The holder `Model` has a non-scalar (define-nominal) field, so it never
    // qualified transparent on its own; it stays the opaque nominal.
    assert!(
        !iface.transparent_types.contains_key("Model"),
        "the holder of a define member must not surface transparent"
    );
    assert!(
        iface.define_types.contains("Model"),
        "the holder keeps the opaque nominal"
    );
    // Both constructor forwarders still survive — the opaque representation is
    // sound (`define_opaque_field_seal` proves it builds); the fixpoint only
    // forbids the TRANSPARENT surface, never the opaque one.
    let survivors = surviving_ref_names(&model_holds_counter_pkg());
    assert!(
        survivors.contains("counter_new") && survivors.contains("model_new"),
        "the opaque representation of both types survives"
    );
    // The un-flip reason is recorded — the over-drop is visible, never silent.
    assert!(
        iface
            .skipped
            .iter()
            .any(|s| s.ref_name == "type Counter" && s.reason.contains("opaque")),
        "the un-flip of the referenced member is recorded: {:?}",
        iface.skipped
    );
}

/// The transitive fixpoint, enum payload seam: a `Counter` carried by a
/// `Message` variant is pinned opaque exactly as the struct-field seam pins it.
#[test]
fn a_referenced_define_payload_pins_both_types_opaque() {
    let doc = serde_json::json!({
        "pkg": "demo", "name": "demo", "version": "0.1.0",
        "functions": [
            {
                "name": "counter_new", "effect": "pure", "isStructCtor": true,
                "structName": "Counter",
                "structFields": [{ "name": "value", "type": "i64" }],
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
    let pkg = PkgInfo::decode_json(&doc).expect("decodes");
    let iface = crate_interface(&pkg);
    assert!(
        !iface.transparent_types.contains_key("Counter"),
        "a define type carried by an enum payload must not surface transparent"
    );
    assert!(
        !iface.transparent_types.contains_key("Message"),
        "the carrying enum must not surface transparent"
    );
    assert!(
        iface.define_types.contains("Counter") && iface.define_types.contains("Message"),
        "both keep the opaque nominal"
    );
}

/// The transitive fixpoint, closure signature seam: a define type named by a
/// `define.closure` parameter/return is pinned opaque — the adapter's
/// `Box<dyn Fn(..)>` names the defined Rust type directly, a seam the conversion
/// glue does not cover.
#[test]
fn a_define_referenced_by_a_closure_signature_pins_it_opaque() {
    let doc = serde_json::json!({
        "pkg": "demo", "name": "demo", "version": "0.1.0",
        "functions": [
            {
                "name": "counter_new", "effect": "pure", "isStructCtor": true,
                "structName": "Counter",
                "structFields": [{ "name": "value", "type": "i64" }],
                "structDerives": ["Clone"]
            },
            {
                "name": "apply_fn", "effect": "pure", "isClosureAdapter": true,
                "closureSig": "Fn(Counter) -> Int + Send + Sync + 'static"
            }
        ],
        "errors": []
    })
    .to_string();
    let pkg = PkgInfo::decode_json(&doc).expect("decodes");
    let iface = crate_interface(&pkg);
    assert!(
        !iface.transparent_types.contains_key("Counter"),
        "a define type named by a closure signature must not surface transparent"
    );
    assert!(
        iface.define_types.contains("Counter"),
        "the closure-referenced type keeps the opaque nominal"
    );
}

/// The control: a define type NO member seam references keeps the transparent
/// surface. The fixpoint only pins types held at a member seam — it never
/// over-drops a type that qualifies AND is unreferenced by any seam. Guards the
/// fixpoint against collapsing the whole transparent surface.
#[test]
fn an_unreferenced_qualifying_define_still_surfaces_transparent() {
    let doc = serde_json::json!({
        "pkg": "demo", "name": "demo", "version": "0.1.0",
        "functions": [
            {
                "name": "counter_new", "effect": "pure", "isStructCtor": true,
                "structName": "Counter",
                "structFields": [{ "name": "value", "type": "i64" }],
                "structDerives": ["Clone"]
            }
        ],
        "errors": []
    })
    .to_string();
    let pkg = PkgInfo::decode_json(&doc).expect("decodes");
    let iface = crate_interface(&pkg);
    assert!(
        iface.transparent_types.contains_key("Counter"),
        "an unreferenced scalar-only define type still surfaces transparent: {:?}",
        iface.skipped
    );
    assert!(
        !iface.define_types.contains("Counter"),
        "a transparent define type is not also an opaque nominal"
    );
}

/// The load-bearing NEGATIVE SEAL proof: under `IPE_E2E=1`, assemble the crate
/// the emitter produces for a `Model` holding a `Counter` member and BUILD it.
/// The emitter renders `Model`/`Counter` as opaque nominals (`pub struct Counter
/// { pub value: i64 }`, `pub struct Model { pub counter: Counter, .. }`), never a
/// transparent record over the member — so the crate compiles. This proves the
/// fixpoint's fail-closed choice IS sound: the representation it kept builds,
/// where a transparent record over the opaque member would have been an `E0308`.
#[test]
fn the_fail_closed_opaque_representation_builds() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let cargo = ipe_env::var("CARGO").expect("cargo sets CARGO for every test it runs");

    let bindings = emit_bindings(&model_holds_counter_pkg());
    // The emitter must NEVER surface a transparent record here — the member is
    // an opaque nominal both in the definition and the constructor.
    assert!(
        bindings.contains("    pub counter: Counter,"),
        "the member field keeps the opaque nominal:\n{bindings}"
    );
    let slug = "demo";
    let ffi_body = format!("pub mod {slug} {{\n{bindings}}}\npub use {slug}::*;\n");

    let dir =
        ipe_test_temp::temp_root().join(format!("ipe_ffi_fixpoint_seal_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src")).expect("mkdir");
    std::fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"fixpoint_seal\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\
         [[bin]]\nname = \"fixpoint_seal\"\npath = \"src/main.rs\"\n",
    )
    .expect("Cargo.toml");

    let main_rs = format!(
        r#"mod ffi {{
    {ffi_body}
}}

use ffi::demo::{{Counter, Model}};

fn main() {{
    // The fail-closed representation: a Model holds a Counter as an opaque
    // nominal, both built through the emitted constructors. This compiles
    // because neither is a transparent record over the member.
    let m: Model = ffi::demo_model_new(ffi::demo_counter_new(7), 0);
    let _c: Counter = m.counter.clone();
    assert_eq!(m.counter.value, 7, "the opaque member round-trips");
    println!("{{}}", m.counter.value);
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
        "the fail-closed opaque representation must build and run exit 0.\n\
         stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains('7'),
        "the opaque member must round-trip.\nstdout: {stdout}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
