//! SEAL fixture for RECURSIVE `define.struct` / `define.enum` definitions.
//!
//! A directly- or mutually-recursive define type (`Tree { child: Tree }`, or
//! `A { inner: B }` + `B { inner: A }`) has no boxed indirection in the closed
//! carrier set, so emitting it would be an infinitely-sized Rust type
//! (`error[E0072]`) — an `ipe`-exit-0-then-cargo-fail SEAL breach. The decode
//! boundary refuses every def on a cycle in the define-type reference graph:
//! the def-bearing binding is over-dropped with a package-author diagnostic, and
//! the emitter's survivor fixed point fans the over-drop out to every reference.
//!
//! A NON-recursive chain (`A { b: B }`, `B { c: i64 }`) is acyclic, so it
//! survives whole and — under `IPE_E2E` — builds and runs. The refusal
//! assertions run in the DEFAULT gate; the cargo build+run proof is
//! `IPE_E2E`-gated (it shells out to `cargo`), matching the repo's other SEAL
//! fixtures.
#![allow(clippy::expect_used)] // test setup: a failed decode / scratch-dir op IS the failure

use ipe_ffi::bindings::{emit_bindings, surviving_ref_names};
use ipe_ffi::diag::{Diagnostic, WireDefect};
use ipe_ffi::interface::crate_interface;
use ipe_ffi::pkginfo::PkgInfo;

/// A one-crate package whose only define type is a self-recursive `Tree`.
fn self_recursive_pkg() -> PkgInfo {
    let doc = serde_json::json!({
        "pkg": "demo", "name": "demo", "version": "0.1.0",
        "functions": [
            {
                "name": "tree_new", "effect": "pure", "isStructCtor": true,
                "structName": "Tree",
                "structFields": [{ "name": "child", "type": "Tree" }],
                "structDerives": ["Clone"]
            }
        ],
        "errors": []
    })
    .to_string();
    PkgInfo::decode_json(&doc).expect("the package survives; the def is over-dropped")
}

/// A one-crate package whose two define types close a cycle through each other.
fn mutually_recursive_pkg() -> PkgInfo {
    let doc = serde_json::json!({
        "pkg": "demo", "name": "demo", "version": "0.1.0",
        "functions": [
            {
                "name": "a_new", "effect": "pure", "isStructCtor": true,
                "structName": "A",
                "structFields": [{ "name": "inner", "type": "B" }],
                "structDerives": ["Clone"]
            },
            {
                "name": "b_new", "effect": "pure", "isStructCtor": true,
                "structName": "B",
                "structFields": [{ "name": "inner", "type": "A" }],
                "structDerives": ["Clone"]
            }
        ],
        "errors": []
    })
    .to_string();
    PkgInfo::decode_json(&doc).expect("the package survives; both defs are over-dropped")
}

/// Default gate: a self-recursive `Tree` emits NO type — no `pub struct Tree`
/// reaches `_bindings.rs`, the survivor gate rejects it, and the interface
/// surfaces neither the nominal nor a forwarder onto the absent wrapper.
#[test]
fn a_self_recursive_define_struct_emits_nothing() {
    let pkg = self_recursive_pkg();
    let out = emit_bindings(&pkg);
    assert!(
        !out.contains("struct Tree"),
        "a recursive def must never emit an infinitely-sized type:\n{out}"
    );
    assert!(
        !surviving_ref_names(&pkg).contains("tree_new"),
        "the survivor gate must not admit the recursive def"
    );
    let iface = crate_interface(&pkg);
    assert!(
        !iface.define_types.contains("Tree"),
        "the interface must not register the refused nominal"
    );
    assert!(
        !iface.bindings.iter().any(|b| b.ref_name == "tree_new"),
        "the interface surfaces no forwarder onto an absent wrapper"
    );
}

/// Default gate: the refusal carries a loud package-author diagnostic — the
/// dropped ledger records a `RecursiveDefineType` for the refused def.
#[test]
fn a_self_recursive_define_struct_records_a_diagnostic() {
    let pkg = self_recursive_pkg();
    assert!(
        pkg.dropped().iter().any(|d| matches!(
            d,
            Diagnostic::WireMalformed {
                defect: WireDefect::RecursiveDefineType { name, .. },
                ..
            } if name == "Tree"
        )),
        "the refused recursive def is recorded with a clear diagnostic: {:?}",
        pkg.dropped()
    );
}

/// Default gate: a mutual `A`/`B` cycle refuses BOTH defs — neither type emits,
/// neither survives, and both are recorded.
#[test]
fn a_mutually_recursive_define_pair_emits_nothing() {
    let pkg = mutually_recursive_pkg();
    let out = emit_bindings(&pkg);
    assert!(
        !out.contains("struct A ") && !out.contains("struct A{") && !out.contains("struct B"),
        "neither side of a mutual cycle may emit:\n{out}"
    );
    let survivors = surviving_ref_names(&pkg);
    assert!(
        !survivors.contains("a_new") && !survivors.contains("b_new"),
        "the survivor gate admits neither side of the cycle"
    );
    let refused: std::collections::BTreeSet<&str> = pkg
        .dropped()
        .iter()
        .filter_map(|d| match d {
            Diagnostic::WireMalformed {
                defect: WireDefect::RecursiveDefineType { name, .. },
                ..
            } => Some(name.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(
        refused,
        ["A", "B"]
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>(),
        "both cyclic defs are recorded as refused"
    );
}

/// Default gate — the acyclic control: `A { b: B }`, `B { c: i64 }` is a chain,
/// not a cycle, so both survive whole and nothing is dropped as recursive.
#[test]
fn a_non_recursive_chain_survives_decode() {
    let pkg = non_recursive_chain_pkg();
    let out = emit_bindings(&pkg);
    assert!(out.contains("pub struct A {"), "{out}");
    assert!(out.contains("    pub b: B,"), "{out}");
    assert!(out.contains("pub struct B {"), "{out}");
    let survivors = surviving_ref_names(&pkg);
    assert!(
        survivors.contains("a_new") && survivors.contains("b_new"),
        "both links of the acyclic chain survive"
    );
    assert!(
        !pkg.dropped().iter().any(|d| matches!(
            d,
            Diagnostic::WireMalformed {
                defect: WireDefect::RecursiveDefineType { .. },
                ..
            }
        )),
        "an acyclic chain is never refused as recursive: {:?}",
        pkg.dropped()
    );
}

/// A one-crate package with an acyclic chain `A { b: B }`, `B { c: i64 }`.
fn non_recursive_chain_pkg() -> PkgInfo {
    let doc = serde_json::json!({
        "pkg": "demo", "name": "demo", "version": "0.1.0",
        "functions": [
            {
                "name": "a_new", "effect": "pure", "isStructCtor": true,
                "structName": "A",
                "structFields": [{ "name": "b", "type": "B" }],
                "structDerives": ["Clone"]
            },
            {
                "name": "b_new", "effect": "pure", "isStructCtor": true,
                "structName": "B",
                "structFields": [{ "name": "c", "type": "i64" }],
                "structDerives": ["Clone"]
            }
        ],
        "errors": []
    })
    .to_string();
    PkgInfo::decode_json(&doc).expect("the acyclic chain decodes whole")
}

/// The load-bearing SEAL proof: under `IPE_E2E=1`, assemble a crate from the
/// emitted NON-recursive chain (`A` holding `B` holding a scalar), build it, and
/// RUN — proving the acyclic chain still emits compilable Rust. The recursive
/// cases emit nothing, so there is no uncompilable crate to assemble for them;
/// their SEAL proof is the emit-nothing assertions above.
#[test]
fn a_non_recursive_chain_builds_and_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let cargo = ipe_env::var("CARGO").expect("cargo sets CARGO for every test it runs");

    let bindings = emit_bindings(&non_recursive_chain_pkg());
    let slug = "demo";
    let ffi_body = format!("pub mod {slug} {{\n{bindings}}}\npub use {slug}::*;\n");

    let dir =
        ipe_test_temp::temp_root().join(format!("ipe_ffi_recursive_seal_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src")).expect("mkdir");
    std::fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"recursive_seal\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\
         [[bin]]\nname = \"recursive_seal\"\npath = \"src/main.rs\"\n",
    )
    .expect("Cargo.toml");

    let main_rs = format!(
        r#"mod ffi {{
    {ffi_body}
}}

use ffi::demo::{{A, B}};

fn main() {{
    // The acyclic chain: an `A` holds a `B` holds a scalar, all built through
    // the emitted constructors.
    let a: A = ffi::demo_a_new(ffi::demo_b_new(7));
    assert_eq!(a.b.c, 7, "the acyclic chain round-trips");
    println!("{{}}", a.b.c);
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
        "the emitted acyclic-chain crate must build and run exit 0.\n\
         stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains('7'),
        "the acyclic chain must round-trip.\nstdout: {stdout}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
