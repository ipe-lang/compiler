//! SEAL fixture for foreign sequence parameters of a non-carrier numeric width.
//!
//! Ipê carries every integer as `i64` and every float as `f64`, so a foreign
//! `Vec<i32>` / `&[u16]` / `[i8; 3]` / `&[f32]` / `Option<Vec<u32>>` parameter
//! receives a carrier sequence the wrapper narrows element-wise through the
//! same saturating rule a scalar argument follows. A shape no coercion renders
//! (`Option<[T; N]>`) over-drops at admission with its own reason.
//!
//! The keystone invariant is `ipe` exit 0 ⇒ the emitted crate cargo-builds. The
//! interface-admission + over-drop assertions run in the DEFAULT gate; the cargo
//! build+run proof of the assembled wrappers is `IPE_E2E`-gated (it shells out
//! to `cargo`), matching the repo's other SEAL fixtures.
#![allow(clippy::expect_used)] // test setup: a failed decode / scratch-dir op IS the failure

use ipe_ffi::bindings::emit_bindings;
use ipe_ffi::interface::crate_interface;
use ipe_ffi::pkginfo::PkgInfo;

/// One echo fn per admitted sequence shape: `(name, Ipê param, raw param,
/// Ipê result, raw result)`.
const ECHOES: [(&str, &str, &str, &str, &str); 7] = [
    ("echo_i32", "List Int", "Vec<i32>", "List Int", "Vec<i64>"),
    ("echo_u16", "List Int", "&[u16]", "List Int", "Vec<i64>"),
    ("echo_i8_arr", "List Int", "[i8; 3]", "List Int", "Vec<i64>"),
    ("echo_f32", "List Float", "&[f32]", "List Float", "Vec<f64>"),
    (
        "echo_u32_opt",
        "Maybe (List Int)",
        "Option<Vec<u32>>",
        "List Int",
        "Vec<i64>",
    ),
    ("echo_i64", "List Int", "&[i64]", "List Int", "Vec<i64>"),
    (
        "echo_f64",
        "List Float",
        "Vec<f64>",
        "List Float",
        "Vec<f64>",
    ),
];

fn echo_fn(name: &str, ipe: &str, raw: &str, ipe_ret: &str, raw_ret: &str) -> serde_json::Value {
    serde_json::json!({
        "name": name,
        "params": [{"name": "v", "type": ipe, "ipeType": ipe, "rustType": raw}],
        "results": [{"name": "", "type": ipe_ret, "rustType": raw_ret}],
        "effect": "pure"
    })
}

/// The `nums` package: every echo, plus `opt_arr` (`Option<[i32; 3]>`) that
/// must over-drop.
fn nums_pkg(with_refused: bool) -> PkgInfo {
    let mut fns: Vec<serde_json::Value> = ECHOES
        .iter()
        .map(|&(n, i, r, ir, rr)| echo_fn(n, i, r, ir, rr))
        .collect();
    if with_refused {
        fns.push(echo_fn(
            "opt_arr",
            "Maybe (List Int)",
            "Option<[i32; 3]>",
            "List Int",
            "Vec<i64>",
        ));
    }
    let doc = serde_json::json!({
        "pkg": "nums", "name": "nums", "version": "0.1.0",
        "functions": fns,
        "errors": []
    })
    .to_string();
    PkgInfo::decode_json(&doc).expect("nums surface decodes")
}

/// Every echo admits, the narrowing element form is emitted, and the
/// optional-array shape over-drops with the renderer's own reason. Default
/// gate — no cargo.
#[test]
fn narrowed_sequences_admit_and_an_optional_array_over_drops() {
    let pkg = nums_pkg(true);
    let iface = crate_interface(&pkg);
    for (name, ..) in ECHOES {
        assert!(
            iface.bindings.iter().any(|b| b.ref_name == name),
            "{name} must be admitted:\n{:?}",
            iface.skipped
        );
    }
    assert!(
        iface.bindings.iter().all(|b| b.ref_name != "opt_arr"),
        "Option<[i32; 3]> must over-drop:\n{:?}",
        iface.bindings
    );
    assert!(
        iface
            .skipped
            .iter()
            .any(|s| s.ref_name == "opt_arr" && s.reason.contains("optional fixed-size array")),
        "the over-drop must record the renderer's reason:\n{:?}",
        iface.skipped
    );

    let out = emit_bindings(&pkg);
    for needle in [
        "::nums::echo_i32(arg0.iter().map(|&x| (x).clamp(i32::MIN as i64, i32::MAX as i64) as i32).collect::<Vec<i32>>())",
        "::nums::echo_u16(&arg0.iter().map(|&x| (x).clamp(0, u16::MAX as i64) as u16).collect::<Vec<u16>>())",
        "to_array::<IpeError, i8, 3>(&arg0.iter().map(|&x| (x).clamp(i8::MIN as i64, i8::MAX as i64) as i8).collect::<Vec<i8>>())",
        "::nums::echo_f32(&arg0.iter().map(|&x| (x) as f32).collect::<Vec<f32>>())",
        "::nums::echo_u32_opt(ipe_maybe_to_option(arg0).map(|v| v.iter().map(|&x| (x).clamp(0, u32::MAX as i64) as u32).collect::<Vec<u32>>()))",
        "::nums::echo_i64(arg0.as_slice())",
        "::nums::echo_f64(arg0)",
        "(arg0: IpeMaybe<Vec<i64>>)",
    ] {
        assert!(out.contains(needle), "missing `{needle}` in:\n{out}");
    }
    assert!(
        !out.contains("::nums::opt_arr("),
        "the refused wrapper must not be emitted:\n{out}"
    );
}

/// The foreign `nums` crate: each fn echoes its narrowed elements back,
/// widened losslessly, so the app sees exactly what crossed the boundary.
const STUB_LIB: &str = r"pub fn echo_i32(v: Vec<i32>) -> Vec<i64> { v.into_iter().map(i64::from).collect() }
pub fn echo_u16(v: &[u16]) -> Vec<i64> { v.iter().map(|&x| i64::from(x)).collect() }
pub fn echo_i8_arr(v: [i8; 3]) -> Vec<i64> { v.iter().map(|&x| i64::from(x)).collect() }
pub fn echo_f32(v: &[f32]) -> Vec<f64> { v.iter().map(|&x| f64::from(x)).collect() }
pub fn echo_u32_opt(v: Option<Vec<u32>>) -> Vec<i64> {
    v.unwrap_or_default().into_iter().map(i64::from).collect()
}
pub fn echo_i64(v: &[i64]) -> Vec<i64> { v.to_vec() }
pub fn echo_f64(v: Vec<f64>) -> Vec<f64> { v }
";

/// The app crate. The emitted bindings' preamble is `use crate::*;`, so the
/// crate root supplies minimal stand-ins for the `ipe_runtime` glue the
/// wrappers name; `{FFI_BODY}` is replaced by the emitted module.
const APP_MAIN: &str = r#"// Runtime glue the emitted wrappers reference, at the crate root so the
// bindings' `use crate::*;` brings it into scope. Minimal stand-ins for
// `ipe_runtime` with the same length check.
#[derive(Debug)]
pub enum IpeResult<E, A> { Ok(A), Err(E) }
#[derive(Debug)]
pub struct IpeError(String);
#[derive(Debug, Clone, PartialEq)]
pub enum IpeMaybe<T> { Nothing, Just(T) }
pub fn ipe_maybe_to_option<T>(m: IpeMaybe<T>) -> Option<T> {
    match m { IpeMaybe::Just(v) => Some(v), IpeMaybe::Nothing => None }
}
pub fn ok_res<E, A>(a: A) -> IpeResult<E, A> { IpeResult::Ok(a) }
pub fn str_err<E: From<String>>(s: &str) -> E { s.to_string().into() }
pub fn ipe_error_from_panic<E: From<String>>(c: &str, _p: Box<dyn std::any::Any + Send>) -> E { c.to_string().into() }
pub fn note_foreign_panic(_c: &str, _p: Box<dyn std::any::Any + Send>) -> String { String::new() }
pub fn note_foreign_error<T: std::fmt::Debug>(_e: T) -> String { String::new() }
pub fn ipe_error_from_foreign<T: std::fmt::Debug, E: From<String>>(_e: T) -> E { "external operation failed".to_string().into() }
impl From<String> for IpeError { fn from(s: String) -> Self { IpeError(s) } }
pub fn to_array<E: From<String>, T: Clone, const N: usize>(xs: &[T]) -> IpeResult<E, [T; N]> {
    match <[T; N]>::try_from(xs.to_vec()) {
        Ok(a) => IpeResult::Ok(a),
        Err(_) => IpeResult::Err(format!("expected array of length {}, got {}", N, xs.len()).into()),
    }
}

mod ffi {
    use crate::*;
    {FFI_BODY}
}

const EDGES: [i64; 13] = [i64::MIN, -256, -1, 0, 1, 127, 128, 255, 256, 257, 300, 1 << 32, i64::MAX];

fn sat(x: i64, lo: i64, hi: i64) -> i64 { x.clamp(lo, hi) }

fn ok<A: std::fmt::Debug>(r: IpeResult<IpeError, A>, what: &str) -> A {
    match r {
        IpeResult::Ok(a) => a,
        IpeResult::Err(e) => { eprintln!("{what}: unexpected Err {e:?}"); std::process::exit(1) }
    }
}

fn check(got: Vec<i64>, want: Vec<i64>, what: &str) {
    if got != want { eprintln!("{what}: got {got:?} want {want:?}"); std::process::exit(1) }
}

fn main() {
    let edges = EDGES.to_vec();
    let want = |lo: i64, hi: i64| edges.iter().map(|&x| sat(x, lo, hi)).collect::<Vec<i64>>();
    check(ok(ffi::nums_echo_i32(edges.clone()), "i32"), want(i64::from(i32::MIN), i64::from(i32::MAX)), "i32");
    check(ok(ffi::nums_echo_u16(edges.clone()), "u16"), want(0, i64::from(u16::MAX)), "u16");
    check(
        ok(ffi::nums_echo_u32_opt(IpeMaybe::Just(edges.clone())), "u32 opt"),
        want(0, i64::from(u32::MAX)),
        "u32 opt",
    );
    check(ok(ffi::nums_echo_u32_opt(IpeMaybe::Nothing), "u32 none"), Vec::new(), "u32 none");
    check(ok(ffi::nums_echo_i64(edges.clone()), "i64"), edges.clone(), "i64");
    check(ok(ffi::nums_echo_i8_arr(vec![-300, 5, 300]), "i8 arr"), vec![-128, 5, 127], "i8 arr");
    // A wrong-length array is a typed Err, never a panic.
    if let IpeResult::Ok(v) = ffi::nums_echo_i8_arr(vec![1, 2]) {
        eprintln!("short array must be Err, got {v:?}");
        std::process::exit(1)
    }
    let floats = vec![0.0_f64, 1.5, f64::MAX, f64::NEG_INFINITY];
    let narrowed = ok(ffi::nums_echo_f32(floats.clone()), "f32");
    let want_f = vec![0.0_f64, 1.5, f64::INFINITY, f64::NEG_INFINITY];
    if narrowed != want_f { eprintln!("f32: got {narrowed:?}"); std::process::exit(1) }
    if ok(ffi::nums_echo_f64(floats.clone()), "f64") != floats { eprintln!("f64 identity"); std::process::exit(1) }
    println!("ok");
}
"#;

/// The load-bearing SEAL proof: under `IPE_E2E=1`, assemble the emitted
/// wrappers against a stub `nums` crate + the runtime glue and RUN them,
/// proving every element narrowing cargo-builds and saturates.
#[test]
fn assembled_sequence_wrappers_build_and_saturate() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let bindings = emit_bindings(&nums_pkg(false));
    let slug = "nums";
    let ffi_body = format!("pub mod {slug} {{\n{bindings}}}\npub use {slug}::*;\n");

    let root = ipe_test_temp::temp_root().join(format!("ipe_ffi_seq_seal_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);

    let wrapper_dir = root.join("wrappers").join("nums");
    std::fs::create_dir_all(wrapper_dir.join("src")).expect("mkdir wrapper");
    std::fs::write(
        wrapper_dir.join("Cargo.toml"),
        "[package]\nname = \"nums\"\nversion = \"0.0.0\"\nedition = \"2021\"\n",
    )
    .expect("wrapper Cargo.toml");
    std::fs::write(wrapper_dir.join("src").join("lib.rs"), STUB_LIB).expect("wrapper lib.rs");

    let main_rs = APP_MAIN.replace("{FFI_BODY}", &ffi_body);

    std::fs::create_dir_all(root.join("src")).expect("mkdir app");
    std::fs::write(
        root.join("Cargo.toml"),
        "[package]\nname = \"seq_seal\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\
         [[bin]]\nname = \"seq_seal\"\npath = \"src/main.rs\"\n\
         [dependencies]\nnums = { path = \"wrappers/nums\" }\n\
         # catch_unwind soundness requires panic=unwind (the emitter's own fence)\n\
         [profile.dev]\npanic = \"unwind\"\n",
    )
    .expect("Cargo.toml");
    std::fs::write(root.join("src").join("main.rs"), main_rs).expect("main.rs");

    let ran = e2e_support::build_and_run_rust("ffi_seq_narrow", &root);
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
        "the assembled sequence wrappers must build and run exit 0.\nstdout: {stdout}"
    );
    assert_eq!(
        stdout.trim(),
        "ok",
        "every narrowing must saturate.\nstdout: {stdout}"
    );
    let _ = std::fs::remove_dir_all(&root);
}
