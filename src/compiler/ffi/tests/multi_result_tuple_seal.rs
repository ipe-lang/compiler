//! SEAL fixture for the widened multi-result-tuple binding.
//!
//! A free fn returning a tuple of numeric / owned `String` / `bool` components
//! (`(u64, String, bool)`) now ADMITS as an Ipê forwarder whose signature is
//! `() -> Result Error (Int, String, Bool)`. The wrapper destructures the raw
//! tuple and coerces each slot — the wide unsigned saturates into the `Int`
//! carrier, the owned `String` and `bool` ride identity — so the declared
//! `(i64, String, bool)` matches the Ipê `(Int, String, Bool)` signature
//! carrier-for-carrier.
//!
//! The keystone invariant is `ipe` exit 0 ⇒ the emitted crate cargo-builds. The
//! interface-admission + over-drop assertions run in the DEFAULT gate; the cargo
//! build+run proof of the assembled wrapper is `IPE_E2E`-gated (it shells out to
//! `cargo`), matching the repo's other SEAL fixtures.
#![allow(clippy::expect_used)] // test setup: a failed decode / scratch-dir op IS the failure

use ipe_ffi::bindings::emit_bindings;
use ipe_ffi::interface::crate_interface;
use ipe_ffi::pkginfo::PkgInfo;

/// A one-crate package with one free fn returning a mixed owned tuple
/// (`(u64, String, bool)`), plus a negative sibling whose tuple carries an
/// opaque handle (`(u64, Version)`) that must STILL over-drop.
fn tuple_pkg() -> PkgInfo {
    let doc = serde_json::json!({
        "pkg": "geom", "name": "geom", "version": "0.1.0",
        "functions": [
            {
                "name": "extent",
                "params": [],
                "results": [{"name": "", "type": "(Int, String, Bool)",
                             "rustType": "(u64, String, bool)"}],
                "effect": "pure"
            },
            {
                "name": "handle_extent",
                "params": [],
                "results": [{"name": "", "type": "(Int, Version)",
                             "rustType": "(u64, Version)"}],
                "effect": "pure"
            }
        ],
        "errors": []
    })
    .to_string();
    PkgInfo::decode_json(&doc).expect("tuple surface decodes")
}

/// The interface admits the owned-scalar tuple forwarder and STILL over-drops the
/// opaque-carrying one. Default gate — no cargo.
#[test]
fn owned_tuple_admits_and_opaque_tuple_over_drops() {
    let iface = crate_interface(&tuple_pkg());

    let extent = iface.bindings.iter().find(|b| b.ref_name == "extent");
    assert!(
        extent.is_some(),
        "the owned (Int, String, Bool) tuple must be admitted:\n{:?}",
        iface.skipped
    );
    assert_eq!(
        extent.expect("asserted present").sig,
        "() -> Result Error (Int, String, Bool)"
    );

    // The opaque-carrying tuple stays refused — its ownership/path wiring is not
    // in the tuple emitter (fail-closed, never emit-and-cargo-fail).
    assert!(
        iface.bindings.iter().all(|b| b.ref_name != "handle_extent"),
        "the opaque-component tuple must over-drop:\n{:?}",
        iface.bindings
    );
    assert!(
        iface.skipped.iter().any(
            |s| s.ref_name == "handle_extent" && s.reason.contains("component scalar coercion")
        ),
        "the over-drop must record the tuple-gate reason:\n{:?}",
        iface.skipped
    );
}

/// The load-bearing SEAL proof: under `IPE_E2E=1`, assemble the emitted wrapper
/// against a stub `geom` crate + the runtime glue and RUN it, proving the
/// per-component coercion cargo-builds and the widened tuple round-trips.
#[test]
fn assembled_tuple_wrapper_builds_and_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let cargo = ipe_env::var("CARGO").expect("cargo sets CARGO for every test it runs");

    // Emit against a package with ONLY the admitted `extent` binding — the
    // emitted wrapper names `::geom::extent`, so `geom` must be a REAL external
    // crate (a path dependency), not a crate-root module (`::geom` = external).
    let doc = serde_json::json!({
        "pkg": "geom", "name": "geom", "version": "0.1.0",
        "functions": [{
            "name": "extent", "params": [],
            "results": [{"name": "", "type": "(Int, String, Bool)",
                         "rustType": "(u64, String, bool)"}],
            "effect": "pure"
        }],
        "errors": []
    })
    .to_string();
    let pkg = PkgInfo::decode_json(&doc).expect("extent-only surface decodes");
    let bindings = emit_bindings(&pkg);
    let slug = "geom";
    let ffi_body = format!("pub mod {slug} {{\n{bindings}}}\npub use {slug}::*;\n");

    let root =
        ipe_test_temp::temp_root().join(format!("ipe_ffi_tuple_seal_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);

    // The foreign `geom` crate the wrapper calls at `::geom::extent`. A `u64`
    // above `i64::MAX` proves the saturating widen; the String/bool ride
    // identity.
    let wrapper_dir = root.join("wrappers").join("geom");
    std::fs::create_dir_all(wrapper_dir.join("src")).expect("mkdir wrapper");
    std::fs::write(
        wrapper_dir.join("Cargo.toml"),
        "[package]\nname = \"geom\"\nversion = \"0.0.0\"\nedition = \"2021\"\n",
    )
    .expect("wrapper Cargo.toml");
    std::fs::write(
        wrapper_dir.join("src").join("lib.rs"),
        "pub fn extent() -> (u64, String, bool) { (u64::MAX, \"wide\".to_string(), true) }\n",
    )
    .expect("wrapper lib.rs");

    // The app crate: the emitted bindings' preamble is `use crate::*;`, so the
    // crate root supplies the runtime glue the wrapper names (`IpeResult`,
    // `IpeError`, `ok_res`, `str_err`). Minimal stand-ins for `ipe_runtime`.
    let main_rs = format!(
        r#"// Runtime glue the emitted wrapper references, at the crate root so the
// bindings' `use crate::*;` brings it into scope.
#[derive(Debug)]
pub enum IpeResult<E, A> {{ Ok(A), Err(E) }}
#[derive(Debug)]
pub struct IpeError(String);
pub fn ok_res<E, A>(a: A) -> IpeResult<E, A> {{ IpeResult::Ok(a) }}
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

fn main() {{
    match ffi::geom_extent(()) {{
        IpeResult::Ok((n, s, b)) => {{
            // u64::MAX saturates to i64::MAX; the String + bool are preserved.
            assert_eq!(n, i64::MAX, "wide unsigned saturates into the Int carrier");
            assert_eq!(s, "wide", "owned String rides identity");
            assert!(b, "bool rides identity");
            println!("ok {{}} {{}} {{}}", n, s, b);
        }}
        IpeResult::Err(e) => panic!("unexpected Err: {{:?}}", e),
    }}
}}
"#
    );

    std::fs::create_dir_all(root.join("src")).expect("mkdir app");
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"tuple_seal\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\
         [[bin]]\nname = \"tuple_seal\"\npath = \"src/main.rs\"\n\
         [dependencies]\ngeom = { path = \"wrappers/geom\" }\n\
         # catch_unwind soundness requires panic=unwind (the emitter's own fence)\n\
         [profile.dev]\npanic = \"unwind\"\n",
    )
    .expect("Cargo.toml");
    std::fs::write(root.join("src").join("main.rs"), main_rs).expect("main.rs");

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
        "the assembled multi-result-tuple wrapper must build and run exit 0.\n\
         stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.trim() == "ok 9223372036854775807 wide true",
        "the tuple wrapper must coerce every component.\nstdout: {stdout}"
    );
    let _ = std::fs::remove_dir_all(&root);
}
