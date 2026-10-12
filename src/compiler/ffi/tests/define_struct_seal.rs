//! SEAL fixture for the `[rust.define.struct]` type-definition + constructor.
//!
//! The keystone invariant is `ipe dev build ⇒ cargo build ⇒ the type is usable`.
//! This fixture proves the emitted definition + constructor are not just
//! well-shaped text but real, compilable Rust: Ipê DEFINES a nominal Rust
//! `struct` (a record of owned scalar carriers, with an allowlisted `#[derive]`
//! set), the constructor builds it from inbound values, and a small "crate" fn
//! reads a field back — the value round-trips.
//!
//! The emit-only assertion runs in the DEFAULT gate; the cargo build+run proof
//! is `IPE_E2E`-gated (matching the repo's other SEAL fixtures), because it
//! shells out to `cargo`.
#![allow(clippy::expect_used)] // test setup: a failed decode / scratch-dir op IS the failure

use ipe_ffi::bindings::emit_bindings;
use ipe_ffi::pkginfo::PkgInfo;

/// Decode a one-crate inspection document carrying a single `define.struct`
/// entry, and return the emitted `_bindings.rs`.
fn emit_struct(
    struct_name: &str,
    fields: &serde_json::Value,
    derives: &serde_json::Value,
) -> String {
    let doc = serde_json::json!({
        "pkg": "demo",
        "name": "demo",
        "version": "0.1.0",
        "functions": [{
            "name": "make",
            "effect": "pure",
            "isStructCtor": true,
            "structName": struct_name,
            "structFields": fields,
            "structDerives": derives
        }],
        "errors": []
    })
    .to_string();
    let pkg = PkgInfo::decode_json(&doc).expect("define.struct decodes");
    emit_bindings(&pkg)
}

/// A derived and a derive-free struct both emit a `#[derive]`ed (or bare)
/// definition + a `pub fn demo_make` constructor (default-gate — no cargo).
#[test]
fn define_struct_emits_a_definition_and_a_constructor() {
    let derived = emit_struct(
        "Counter",
        &serde_json::json!([{ "name": "value", "type": "i64" }]),
        &serde_json::json!(["Default", "Clone"]),
    );
    assert!(derived.contains("#[derive(Clone, Default)]"), "{derived}");
    assert!(derived.contains("pub struct Counter {"), "{derived}");
    assert!(derived.contains("    pub value: i64,"), "{derived}");
    assert!(
        derived.contains("pub fn demo_make(arg0: i64) -> Counter {"),
        "{derived}"
    );
    assert!(derived.contains("Counter { value: arg0 }"), "{derived}");

    let bare = emit_struct(
        "Pair",
        &serde_json::json!([
            { "name": "a", "type": "i64" },
            { "name": "b", "type": "bool" }
        ]),
        &serde_json::json!([]),
    );
    assert!(!bare.contains("#[derive"), "{bare}");
    assert!(
        bare.contains("pub fn demo_make(arg0: i64, arg1: bool) -> Pair {"),
        "{bare}"
    );
}

/// The rejection paths: an ill-formed or unsound `define.struct` over-drops the
/// whole entry at decode (no wrapper emitted), never emit-and-cargo-fail.
#[test]
fn unsound_define_structs_emit_no_wrapper() {
    // A total-Eq derive on a Float field (IEEE-754 has no total Eq/Ord/Hash).
    let float_eq = emit_struct(
        "Bad",
        &serde_json::json!([{ "name": "x", "type": "f64" }]),
        &serde_json::json!(["Eq"]),
    );
    assert!(!float_eq.contains("pub struct Bad"), "{float_eq}");

    // A derive outside the closed allowlist.
    let bad_derive = emit_struct(
        "Bad",
        &serde_json::json!([{ "name": "x", "type": "i64" }]),
        &serde_json::json!(["Serialize"]),
    );
    assert!(!bad_derive.contains("pub struct Bad"), "{bad_derive}");

    // A field type outside the carrier set.
    let bad_field = emit_struct(
        "Bad",
        &serde_json::json!([{ "name": "x", "type": "u32" }]),
        &serde_json::json!([]),
    );
    assert!(!bad_field.contains("pub struct Bad"), "{bad_field}");
}

/// The load-bearing SEAL proof: under `IPE_E2E=1`, build a tiny cargo crate
/// around the emitted definition + constructor and RUN it, asserting the type
/// constructs and its field round-trips. Without the emitter, an Ipê record
/// could not become a nominal Rust type at all; with it, the emitted definition
/// must compile and the constructor must build a real value.
#[test]
fn define_struct_builds_and_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let cargo = ipe_env::var("CARGO").expect("cargo sets CARGO for every test it runs");

    let region = emit_struct(
        "Counter",
        &serde_json::json!([{ "name": "value", "type": "i64" }]),
        &serde_json::json!(["Default", "Clone"]),
    );
    let make = wrapper_region(&region, "make");

    let dir =
        ipe_test_temp::temp_root().join(format!("ipe_ffi_struct_seal_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src")).expect("mkdir");
    std::fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"struct_seal\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\
         [[bin]]\nname = \"struct_seal\"\npath = \"src/main.rs\"\n",
    )
    .expect("Cargo.toml");

    let main_rs = format!(
        r#"// A tiny "crate" fn that consumes the Ipê-defined type and reads a
// field back — the exact shape a Bevy `Resource` / Iced `Model` would.
fn crate_reads_value(c: &Counter) -> i64 {{ c.value }}

{make}

fn main() {{
    // The Ipê-side constructor builds the nominal Rust type from an inbound
    // value; the derived `Default`/`Clone` and the field read all resolve.
    let c = demo_make(41);
    let c2 = c.clone();
    let d = Counter::default();
    assert_eq!(crate_reads_value(&c), 41, "field round-trip");
    assert_eq!(crate_reads_value(&c2), 41, "derived Clone round-trip");
    assert_eq!(crate_reads_value(&d), 0, "derived Default is zero");
    println!("{{}} {{}}", c.value + 1, d.value);
}}
"#,
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
        "emitted define.struct crate must build and run exit 0.\n\
         stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("42 0"),
        "the constructed struct's field must round-trip.\nstdout: {stdout}"
    );
    let _ = std::fs::remove_dir_all(&dir);
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
