//! SEAL fixture for the `[rust.define.enum]` type-definition + per-variant
//! constructors.
//!
//! The keystone invariant is `ipe dev build ⇒ cargo build ⇒ the type is usable`.
//! This fixture proves the emitted `enum` definition + variant constructors are
//! not just well-shaped text but real, compilable Rust: Ipê DEFINES a nominal
//! Rust `enum` (a sum of unit / tuple-payload variants over owned carriers, with
//! an allowlisted `#[derive]` set), each constructor builds its variant, and a
//! small "crate" fn matches on it — the exact shape an Iced/TEA `Message` needs.
//!
//! The emit-only assertion runs in the DEFAULT gate; the cargo build+run proof
//! is `IPE_E2E`-gated (matching the repo's other SEAL fixtures), because it
//! shells out to `cargo`.
#![allow(clippy::expect_used)] // test setup: a failed decode / scratch-dir op IS the failure

use ipe_ffi::bindings::emit_bindings;
use ipe_ffi::pkginfo::PkgInfo;

/// Decode a one-crate inspection document carrying a single `define.enum`
/// entry, and return the emitted `_bindings.rs`.
fn emit_enum(enum_name: &str, variants: &serde_json::Value, derives: &serde_json::Value) -> String {
    let doc = serde_json::json!({
        "pkg": "demo",
        "name": "demo",
        "version": "0.1.0",
        "functions": [{
            "name": "msg",
            "effect": "pure",
            "isEnumDef": true,
            "enumName": enum_name,
            "enumVariants": variants,
            "enumDerives": derives
        }],
        "errors": []
    })
    .to_string();
    let pkg = PkgInfo::decode_json(&doc).expect("define.enum decodes");
    emit_bindings(&pkg)
}

/// A unit-variant enum (the Iced/TEA `Message` shape) emits a `#[derive]`ed
/// definition + one nullary constructor per variant (default-gate — no cargo).
#[test]
fn define_enum_emits_a_definition_and_unit_constructors() {
    let msg = emit_enum(
        "Message",
        &serde_json::json!([
            { "name": "Increment", "payload": [] },
            { "name": "Decrement", "payload": [] }
        ]),
        &serde_json::json!(["Clone"]),
    );
    assert!(msg.contains("#[derive(Clone)]"), "{msg}");
    assert!(msg.contains("pub enum Message {"), "{msg}");
    assert!(msg.contains("    Increment,"), "{msg}");
    assert!(msg.contains("    Decrement,"), "{msg}");
    // One constructor per variant, `<ctor>_<snake(variant)>`.
    assert!(
        msg.contains("pub fn demo_msg_increment(_: ()) -> Message {"),
        "{msg}"
    );
    assert!(msg.contains("Message::Increment"), "{msg}");
    assert!(
        msg.contains("pub fn demo_msg_decrement(_: ()) -> Message {"),
        "{msg}"
    );
}

/// A tuple-payload variant emits a constructor with one owned-carrier parameter
/// per payload position, folded into `E::V(a0, …)`.
#[test]
fn define_enum_emits_tuple_payload_constructors() {
    let ev = emit_enum(
        "Event",
        &serde_json::json!([
            { "name": "Tick", "payload": [] },
            { "name": "SetValue", "payload": ["i64"] },
            { "name": "Move", "payload": ["i64", "i64"] }
        ]),
        &serde_json::json!([]),
    );
    assert!(!ev.contains("#[derive"), "{ev}");
    assert!(ev.contains("    SetValue(i64),"), "{ev}");
    assert!(ev.contains("    Move(i64, i64),"), "{ev}");
    assert!(
        ev.contains("pub fn demo_msg_set_value(arg0: i64) -> Event {"),
        "{ev}"
    );
    assert!(ev.contains("Event::SetValue(arg0)"), "{ev}");
    assert!(
        ev.contains("pub fn demo_msg_move(arg0: i64, arg1: i64) -> Event {"),
        "{ev}"
    );
    assert!(ev.contains("Event::Move(arg0, arg1)"), "{ev}");
}

/// The rejection paths: an ill-formed or unsound `define.enum` over-drops the
/// whole entry at decode (no wrapper emitted), never emit-and-cargo-fail.
#[test]
fn unsound_define_enums_emit_no_wrapper() {
    // A total-Eq derive on a Float payload (IEEE-754 has no total Eq/Ord/Hash).
    let float_eq = emit_enum(
        "Bad",
        &serde_json::json!([{ "name": "A", "payload": ["f64"] }]),
        &serde_json::json!(["Eq"]),
    );
    assert!(!float_eq.contains("pub enum Bad"), "{float_eq}");

    // A derive outside the closed allowlist.
    let bad_derive = emit_enum(
        "Bad",
        &serde_json::json!([{ "name": "A", "payload": [] }]),
        &serde_json::json!(["Serialize"]),
    );
    assert!(!bad_derive.contains("pub enum Bad"), "{bad_derive}");

    // A payload type outside the carrier set.
    let bad_payload = emit_enum(
        "Bad",
        &serde_json::json!([{ "name": "A", "payload": ["u32"] }]),
        &serde_json::json!([]),
    );
    assert!(!bad_payload.contains("pub enum Bad"), "{bad_payload}");

    // A variantless enum (uninhabited — no constructor can build it).
    let void = emit_enum("Void", &serde_json::json!([]), &serde_json::json!([]));
    assert!(!void.contains("pub enum Void"), "{void}");
}

/// The load-bearing SEAL proof: under `IPE_E2E=1`, build a tiny cargo crate
/// around the emitted definition + constructors and RUN it, asserting each
/// variant constructs and a `match` over the sum resolves — the exact shape an
/// Iced `update : Message -> Model -> Model` consumes.
#[test]
fn define_enum_builds_and_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let cargo = ipe_env::var("CARGO").expect("cargo sets CARGO for every test it runs");

    let region = emit_enum(
        "Message",
        &serde_json::json!([
            { "name": "Increment", "payload": [] },
            { "name": "Decrement", "payload": [] },
            { "name": "SetValue", "payload": ["i64"] }
        ]),
        &serde_json::json!(["Clone"]),
    );
    let msg = wrapper_region(&region, "msg");

    let dir = ipe_test_temp::temp_root().join(format!("ipe_ffi_enum_seal_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src")).expect("mkdir");
    std::fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"enum_seal\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\
         [[bin]]\nname = \"enum_seal\"\npath = \"src/main.rs\"\n",
    )
    .expect("Cargo.toml");

    let main_rs = format!(
        r#"// A tiny "crate" fn that consumes the Ipê-defined sum and folds it —
// the exact shape an Iced `update : Message -> Model -> Model` would.
fn apply(m: &Message, acc: i64) -> i64 {{
    match m {{
        Message::Increment => acc + 1,
        Message::Decrement => acc - 1,
        Message::SetValue(v) => *v,
    }}
}}

{msg}

fn main() {{
    let inc = demo_msg_increment(());
    let dec = demo_msg_decrement(());
    let set = demo_msg_set_value(40);
    // The derived `Clone` resolves; each variant constructs; the match folds.
    let inc2 = inc.clone();
    let mut acc = 0;
    acc = apply(&inc, acc);
    acc = apply(&inc2, acc);
    acc = apply(&dec, acc);
    acc = apply(&set, acc);
    // 0 +1 +1 -1, then SetValue(40) overrides → 40; print 42.
    println!("{{}}", acc + 2);
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
        "emitted define.enum crate must build and run exit 0.\n\
         stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("42"),
        "the constructed variants must construct and match-fold.\nstdout: {stdout}"
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
