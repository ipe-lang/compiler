//! SEAL fixture for the `[rust.define.closure]` sync closure adapter.
//!
//! The keystone invariant is `ipe dev build ⇒ cargo build ⇒ the closure runs`. This
//! fixture proves the emitted adapter wrapper is not just well-shaped text but
//! real, compilable Rust: it takes an Ipê function value (already a
//! `Box<dyn Fn(..) -> R + Send + Sync + 'static>` on the app side), hands a
//! small "crate" fn the boxed closure the adapter returns, and the crate calls
//! it — the result round-trips.
//!
//! Two return shapes are exercised:
//!  * a `Total(scalar)` adapter, whose emitted region needs only `std` (the
//!    happy path returns the value; a panic would abort — proven not taken);
//!  * a `Result` adapter, whose panic-fold arm needs the runtime `str_err` /
//!    `IpeError` glue (a tiny shim stands in for `use crate::*`).
//!
//! The emit-only assertion runs in the DEFAULT gate; the cargo build+run proof
//! is `IPE_E2E`-gated (matching the repo's other SEAL fixtures), because it
//! shells out to `cargo`.
#![allow(clippy::expect_used)] // test setup: a failed decode / scratch-dir op IS the failure

use ipe_ffi::bindings::emit_bindings;
use ipe_ffi::pkginfo::PkgInfo;

/// Decode a one-crate inspection document carrying a single `define.closure`
/// entry, and return the emitted `_bindings.rs`.
fn emit_closure(sig: &str) -> String {
    let doc = serde_json::json!({
        "pkg": "demo",
        "name": "demo",
        "version": "0.1.0",
        "functions": [{
            "name": "apply_fn",
            "effect": "pure",
            "isClosureAdapter": true,
            "closureSig": sig
        }],
        "errors": []
    })
    .to_string();
    let pkg = PkgInfo::decode_json(&doc).expect("define.closure decodes");
    emit_bindings(&pkg)
}

/// The adapter region for a `Total` and a `Result` closure must both emit a
/// `pub fn demo_apply_fn` wrapper (default-gate assertion — no cargo).
#[test]
fn closure_adapter_emits_a_wrapper_for_both_return_shapes() {
    let total = emit_closure("Fn(Int) -> Int + Send + Sync + 'static");
    // The returned boxed closure is surfaced as an opaque handle nominal whose
    // full box type the region's own `pub type` alias carries.
    assert!(
        total
            .contains("pub type ApplyFnClosure = Box<dyn Fn(i64) -> i64 + Send + Sync + 'static>;"),
        "{total}"
    );
    assert!(
        total.contains(
            "pub fn demo_apply_fn(__ipe_fn: Box<dyn Fn(i64) -> i64 + Send + Sync + 'static>) \
             -> ApplyFnClosure"
        ),
        "{total}"
    );
    assert!(total.contains("std::process::abort()"), "{total}");

    let res = emit_closure("Fn(Int) -> Result<Int, Error> + Send + Sync + 'static");
    assert!(
        res.contains(
            "pub type ApplyFnClosure = \
             Box<dyn Fn(i64) -> Result<i64, IpeError> + Send + Sync + 'static>;"
        ),
        "{res}"
    );
    assert!(res.contains("-> ApplyFnClosure {"), "{res}");
    assert!(
        res.contains("Err(__p) => Err(ipe_error_from_panic(\"foreign closure panicked\", __p))"),
        "{res}"
    );
    // The catch_unwind boundary is sound only under panic=unwind. The emitted
    // module must carry the fence that refuses a panic=abort build — the
    // adapter shares that compilation unit, so it inherits the fence.
    assert!(
        total.contains("#[cfg(panic = \"abort\")]")
            && total.contains("catch_unwind boundary requires panic=unwind"),
        "the emitted bindings module must fence out panic=abort:\n{total}"
    );
}

/// The rejection paths: an ill-formed or unsound signature over-drops the whole
/// define entry at decode (no wrapper emitted), never emit-and-cargo-fail.
#[test]
fn unsound_closure_signatures_emit_no_wrapper() {
    for bad in [
        // A borrowed return is outside the carrier set.
        "Fn(Int) -> &Int + Send + Sync + 'static",
        // A total opaque return has no default to yield on a panic-abort.
        "Fn(Int) -> Widget + Send + Sync + 'static",
        // A bound outside the closed {Send, Sync, 'static} set.
        "Fn(Int) -> Int + Clone",
        // An injection payload in the return position.
        "Fn(Int) -> Int; std::process::exit(1) + Send",
    ] {
        let out = emit_closure(bad);
        assert!(
            !out.contains("pub fn demo_apply_fn"),
            "{bad:?} must over-drop — no wrapper:\n{out}"
        );
    }
}

/// The load-bearing SEAL proof: under `IPE_E2E=1`, build a tiny cargo crate
/// around the emitted adapters and RUN it, asserting the closures fire and
/// their values round-trip. Without the emitter, an Ipê fn could not become a
/// Rust `dyn Fn` at all; with it, the emitted wrapper must compile and run.
#[test]
fn closure_adapter_builds_and_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let cargo = ipe_env::var("CARGO").expect("cargo sets CARGO for every test it runs");

    let total_region = emit_closure("Fn(Int) -> Int + Send + Sync + 'static");
    let result_region = emit_closure("Fn(Int) -> Result<Int, Error> + Send + Sync + 'static");
    // Keep only the sentinel-bracketed wrapper regions; drop the emitted
    // preamble (`use crate::*;`, the panic fence) — this fixture supplies its
    // own minimal glue instead of the runtime crate.
    let total_fn = wrapper_region(&total_region, "apply_fn");
    let result_fn = wrapper_region(&result_region, "apply_fn");

    let dir =
        ipe_test_temp::temp_root().join(format!("ipe_ffi_closure_seal_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src")).expect("mkdir");
    std::fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"closure_seal\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\
         [[bin]]\nname = \"closure_seal\"\npath = \"src/main.rs\"\n\
         # catch_unwind soundness requires panic=unwind (the emitter's own fence)\n\
         [profile.dev]\npanic = \"unwind\"\n",
    )
    .expect("Cargo.toml");

    // A minimal stand-in for the runtime glue the emitted arms name
    // (`str_err`, `IpeError`, the panic funnel). The `Total` arm names only
    // `note_foreign_panic` before its abort.
    let main_rs = format!(
        r#"// Minimal runtime glue the emitted Result adapter references.
#[derive(Debug)]
pub struct IpeError(String);
pub fn str_err<E: From<String>>(s: &str) -> E {{ s.to_string().into() }}
pub fn ipe_error_from_panic<E: From<String>>(c: &str, _p: Box<dyn std::any::Any + Send>) -> E {{ c.to_string().into() }}
pub fn note_foreign_panic(_c: &str, _p: Box<dyn std::any::Any + Send>) -> String {{ String::new() }}
pub fn note_foreign_error<T: std::fmt::Debug>(_e: T) -> String {{ String::new() }}
pub fn ipe_error_from_foreign<T: std::fmt::Debug, E: From<String>>(_e: T) -> E {{ "external operation failed".to_string().into() }}
impl From<String> for IpeError {{ fn from(s: String) -> Self {{ IpeError(s) }} }}

// A tiny "crate" fn that takes the boxed closure and calls it — the exact
// shape an Iced `update` / Ratatui `draw` driver would.
fn crate_takes_total(f: Box<dyn Fn(i64) -> i64 + Send + Sync + 'static>) -> i64 {{
    // Multi-call: the boxed closure fires more than once.
    f(20) + f(22)
}}
fn crate_takes_result(
    f: Box<dyn Fn(i64) -> Result<i64, IpeError> + Send + Sync + 'static>,
) -> i64 {{
    f(41).map(|n| n + 1).unwrap_or(-1)
}}

{total_fn}

{result_fn}

fn main() {{
    // The Ipê function value: on the app side this is exactly a
    // `Box<dyn Fn(..) -> R + Send + Sync + 'static>`. Supply one and pass it
    // through the adapter, then hand the crate the boxed closure it returns.
    let ipe_total: Box<dyn Fn(i64) -> i64 + Send + Sync + 'static> = Box::new(|x| x + 1);
    let adapted_total = demo_apply_fn_total(ipe_total);
    let total = crate_takes_total(adapted_total);

    let ipe_result: Box<dyn Fn(i64) -> Result<i64, IpeError> + Send + Sync + 'static> =
        Box::new(|x| Ok(x));
    let adapted_result = demo_apply_fn_result(ipe_result);
    let result = crate_takes_result(adapted_result);

    // (20+1) + (22+1) = 43 ; (41 -> Ok(41)) + 1 = 42
    assert_eq!(total, 44, "total-return closure round-trip");
    assert_eq!(result, 42, "result-return closure round-trip");
    println!("{{total}} {{result}}");
}}
"#,
        // Rename the two wrappers AND their handle aliases so both regions can
        // coexist in one bin (the alias name is region-derived, so both emit
        // `ApplyFnClosure` — disambiguate them here). A type alias IS the
        // underlying box, so the renamed-alias return still passes to the
        // `crate_takes_*` fns that take the raw `Box<dyn Fn …>`.
        total_fn = total_fn
            .replace("pub fn demo_apply_fn(", "pub fn demo_apply_fn_total(")
            .replace("ApplyFnClosure", "ApplyFnClosureTotal"),
        result_fn = result_fn
            .replace("pub fn demo_apply_fn(", "pub fn demo_apply_fn_result(")
            .replace("ApplyFnClosure", "ApplyFnClosureResult"),
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
        "emitted closure adapter crate must build and run exit 0.\n\
         stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("44 42"),
        "both closures must fire and round-trip their values.\nstdout: {stdout}"
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
