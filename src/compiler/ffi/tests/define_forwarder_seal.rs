//! SEAL fixture for the `[rust.define.*]` Ipê-side FORWARDER plumbing.
//!
//! The earlier `define_struct_seal` / `define_enum_seal` fixtures prove the
//! emitted `_bindings.rs` DEFINITION + constructors compile. This fixture proves
//! the next link: the FFI interface admits those constructors as Ipê-callable
//! FORWARDERS (an all-identity-carrier define surfaces transparently — a record
//! alias / closed union with result-conversion glue — beside its `counter_new`
//! binding), and the emitted app-crate — the `src/ffi.rs` module tree the
//! backend assembles — resolves the define type at its crate-absolute path
//! `crate::ffi::<slug>::<T>` and CALLS every forwarder.
//!
//! The keystone invariant is `ipe build ⇒ cargo build`. The interface-admission
//! assertions run in the DEFAULT gate; the cargo build+run proof of the
//! assembled module tree is `IPE_E2E`-gated (it shells out to `cargo`), matching
//! the repo's other SEAL fixtures.
#![allow(clippy::expect_used)] // test setup: a failed decode / scratch-dir op IS the failure

use ipe_ffi::bindings::emit_bindings;
use ipe_ffi::interface::crate_interface;
use ipe_ffi::pkginfo::PkgInfo;

/// A one-crate package with a `define.struct` (a `Counter` model) and a
/// `define.enum` (a `Message` sum: one unit + one payload variant) — the exact
/// create-types surface an Iced/TEA counter needs.
fn counter_pkg() -> PkgInfo {
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
    })
    .to_string();
    PkgInfo::decode_json(&doc).expect("define surface decodes")
}

/// The interface surfaces each all-identity-carrier define type transparently
/// (a record alias / closed union) and admits a forwarder per constructor,
/// with arity + signature taken from the def (never the empty fn params) and
/// the result conversion marked for the seam glue. Default gate — no cargo.
#[test]
fn forwarders_and_nominals_are_admitted() {
    let iface = crate_interface(&counter_pkg());
    assert!(
        iface.transparent_types.contains_key("Counter"),
        "{:?}",
        iface.skipped
    );
    assert!(
        iface.transparent_types.contains_key("Message"),
        "{:?}",
        iface.skipped
    );
    assert!(iface.define_types.is_empty(), "{:?}", iface.define_types);

    let by = |n: &str| iface.bindings.iter().find(|b| b.ref_name == n);
    let cn = by("counter_new").expect("counter_new forwarder");
    assert_eq!((cn.arity, cn.sig.as_str()), (1, "Int -> Counter"));
    let inc = by("message_new_increment").expect("unit-variant forwarder");
    assert_eq!((inc.arity, inc.sig.as_str()), (1, "() -> Message"));
    let sv = by("message_new_set_value").expect("payload-variant forwarder");
    assert_eq!((sv.arity, sv.sig.as_str()), (1, "Int -> Message"));
    for b in [cn, inc, sv] {
        assert!(
            b.transparent_result.is_some(),
            "constructor `{}` must convert its foreign result through the glue",
            b.ref_name
        );
    }

    // The module renders both transparent shapes and the (nullary + arity-1)
    // forwarders.
    let src = &iface.source;
    assert!(
        src.contains("\ntype alias Counter = { value : Int }\n"),
        "{src}"
    );
    assert!(
        src.contains("\ntype Message = Increment | SetValue Int\n"),
        "{src}"
    );
    assert!(
        src.contains(
            "\nmessage_new_increment : () -> Message\nmessage_new_increment arg0 =\n    Ffi.binding \"demo_message_new_increment\" arg0\n"
        ),
        "{src}"
    );
}

/// The load-bearing SEAL proof: under `IPE_E2E=1`, assemble the app-crate module
/// tree the backend emits — `src/ffi.rs` wrapping the bindings as
/// `pub mod <slug> { … } pub use <slug>::*;`, the define types referenced at
/// their crate-absolute path `crate::ffi::<slug>::<T>` — and a `main` that calls
/// every forwarder and folds the sum. Proves the crate-absolute path resolves
/// and the nullary forwarders build.
#[test]
fn assembled_module_tree_builds_and_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let cargo = ipe_env::var("CARGO").expect("cargo sets CARGO for every test it runs");

    let pkg = counter_pkg();
    let bindings = emit_bindings(&pkg);
    let slug = "demo";

    // Mirror `ipe_backend_rust::project` + `ipe-cli::assemble_emit`: `src/ffi.rs`
    // wraps the generated bindings in `pub mod <slug> { … } pub use <slug>::*;`.
    let ffi_rs = format!("pub mod {slug} {{\n{bindings}}}\npub use {slug}::*;\n");

    // The `main` references the define types at their CRATE-ABSOLUTE path — the
    // exact `foreign_types` value `assemble_emit` renders (`crate::ffi::<slug>::T`)
    // — and calls each forwarder fn (also under `crate::ffi::`).
    let main_rs = format!(
        r#"mod ffi;

fn apply(m: &crate::ffi::{slug}::Message, c: crate::ffi::{slug}::Counter) -> crate::ffi::{slug}::Counter {{
    match m {{
        crate::ffi::{slug}::Message::Increment => crate::ffi::demo_counter_new(c.value + 1),
        crate::ffi::{slug}::Message::SetValue(v) => crate::ffi::demo_counter_new(*v),
    }}
}}

fn main() {{
    let c0: crate::ffi::{slug}::Counter = crate::ffi::demo_counter_new(0);
    let inc = crate::ffi::demo_message_new_increment(());
    let set = crate::ffi::demo_message_new_set_value(40);
    let c1 = apply(&inc, c0.clone());
    let c2 = apply(&inc, c1);
    let c3 = apply(&set, c2);
    // 0 -> +1 -> +1 -> SetValue(40) = 40; print 42.
    let _dbg = format!("{{:?}}", inc); // the Debug derive resolves
    println!("{{}}", c3.value + 2);
}}
"#
    );

    let dir =
        ipe_test_temp::temp_root().join(format!("ipe_ffi_forwarder_seal_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src")).expect("mkdir");
    std::fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"forwarder_seal\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\
         [[bin]]\nname = \"forwarder_seal\"\npath = \"src/main.rs\"\n",
    )
    .expect("Cargo.toml");
    std::fs::write(dir.join("src").join("ffi.rs"), ffi_rs).expect("ffi.rs");
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
        "the assembled define-forwarder module tree must build and run exit 0.\n\
         stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("42"),
        "the forwarders must construct + fold the value.\nstdout: {stdout}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
