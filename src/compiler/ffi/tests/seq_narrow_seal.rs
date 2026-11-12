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

/// One echo fn per admitted sequence or borrowed-scalar shape: `(name, Ipê
/// param, raw param, Ipê result, raw result)`.
const ECHOES: [(&str, &str, &str, &str, &str); 11] = [
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
    ("echo_ref_u16", "Int", "&u16", "Int", "i64"),
    ("echo_ref_i8", "Int", "&i8", "Int", "i64"),
    ("echo_ref_i64", "Int", "&i64", "Int", "i64"),
    ("echo_ref_bool", "Bool", "&bool", "Bool", "bool"),
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
        "::nums::echo_ref_u16(&((arg0).clamp(0, u16::MAX as i64) as u16))",
        "::nums::echo_ref_i8(&((arg0).clamp(i8::MIN as i64, i8::MAX as i64) as i8))",
        "::nums::echo_ref_i64(&arg0)",
        "::nums::echo_ref_bool(&arg0)",
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
pub fn echo_ref_u16(x: &u16) -> i64 { i64::from(*x) }
pub fn echo_ref_i8(x: &i8) -> i64 { i64::from(*x) }
pub fn echo_ref_i64(x: &i64) -> i64 { *x }
pub fn echo_ref_bool(x: &bool) -> bool { !*x }
";

/// The app crate's program items; the bindings' `use crate::*;` resolves the
/// runtime items the wrappers name through the crate-root prelude.
const APP_MAIN: &str = r#"const EDGES: [i64; 13] = [i64::MIN, -256, -1, 0, 1, 127, 128, 255, 256, 257, 300, 1 << 32, i64::MAX];

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
    for (x, w) in [(70000, 65535), (-5, 0), (7, 7)] {
        if ok(ffi::nums_echo_ref_u16(x), "ref u16") != w { eprintln!("ref u16 {x}"); std::process::exit(1) }
    }
    for (x, w) in [(-300, -128), (300, 127), (-7, -7)] {
        if ok(ffi::nums_echo_ref_i8(x), "ref i8") != w { eprintln!("ref i8 {x}"); std::process::exit(1) }
    }
    if ok(ffi::nums_echo_ref_i64(i64::MIN), "ref i64") != i64::MIN { eprintln!("ref i64"); std::process::exit(1) }
    if ok(ffi::nums_echo_ref_bool(true), "ref bool") { eprintln!("ref bool"); std::process::exit(1) }
    println!("ok");
}
"#;

/// The load-bearing SEAL proof: under `IPE_E2E=1`, assemble the emitted
/// wrappers against a stub `nums` crate + the real runtime and RUN them,
/// proving every element narrowing cargo-builds and saturates.
#[test]
fn assembled_sequence_wrappers_build_and_saturate() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let bindings = emit_bindings(&nums_pkg(false));
    let slug = "nums";
    let ffi_rs = e2e_support::ffi_app::package_module(slug, &bindings);

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

    e2e_support::ffi_app::FfiApp {
        name: "seq_seal",
        runtime_features: &[],
        dependencies: &["nums = { path = \"wrappers/nums\" }".to_owned()],
        ffi_rs: &ffi_rs,
        main_rs: APP_MAIN,
    }
    .write(&root)
    .expect("the app crate is written");

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
