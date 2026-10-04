//! THE SEAL for the taxonomy-native native-binding surface
//! (`Ipe.Ffi.Rust.fn "<crate>" "<path>"`): the two-literal spelling of the
//! asserted native binding, sharing one generated forwarder + one exact-carrier
//! panic-bounded shim with the legacy `Rust.Ffi.call "<crate>::<path>"`.
//!
//! The default gate proves the whole pipeline emits: the driver scans the
//! `Rust.fn` definitions, generates the `Rust.Ffi` interface module, appends the
//! `ipe_asserted` shim region (exact carriers, `catch_unwind`, no coercion), and
//! the app compiles against it. The refusal tests prove the fail-closed edges: a
//! `Rust.fn` applied to the wrong argument shape is refused (IPE-N0038); a
//! clamp-requiring assertion is refused naming the real carrier; a `Rust.fn`
//! naming an uninstalled crate is refused (the un-introspectable target — never
//! blind-trusted). The `IPE_E2E=1` gate proves THE SEAL end to end: the emitted
//! crate builds against a real foreign crate and runs.
//!
//! ```text
//! cargo test -p ipe --test golden_ffi_rust_fn_seal
//! ```
#![allow(clippy::expect_used, clippy::panic)] // test setup: a failed build/write IS the failure

use std::fs;
use std::path::{Path, PathBuf};

use ipe_ffi::driver::{FfiCache, install_from_inspection};

/// Seed the project's FFI cache with an inspection for a crate `tm`: `shift` is
/// inspected with exact `i64` carriers (the compile-time check passes) and
/// `clamped` is inspected with `u32` carriers (the exact-carrier refusal).
/// `hidden_double` / `boom` are NOT inspected — the over-drop case rustc backs.
fn seed_ffi_cache(project_root: &Path) -> bool {
    let cache = FfiCache::at_project_root(project_root);
    let doc = serde_json::json!({
        "pkg": "tm",
        "name": "tm",
        "version": "0.1.0",
        "functions": [
            {
                "name": "shift",
                "params": [{"name": "n", "type": "i64"}],
                "results": [{"name": "", "type": "i64"}],
                "effect": "pure"
            },
            {
                "name": "clamped",
                "params": [{"name": "n", "type": "u32"}],
                "results": [{"name": "", "type": "u32"}],
                "effect": "pure"
            }
        ],
        "errors": [],
        "transitiveDeps": [
            {"ident": "tm", "name": "tm", "version": "0.1.0"}
        ]
    });
    install_from_inspection(&cache, &doc.to_string()).is_ok()
}

/// The fixture program in the `Rust.fn` spelling: three native bindings — one
/// against an inspected symbol, two against uninspected ones — threaded so the
/// printed output proves the round-trip AND the panic→`Err` fold. Both the
/// native-binding qualifier (`import Ipe.Ffi.Rust as Rust`) and the
/// driver-generated forwarder module (`import Rust.Ffi`) are in scope.
const MAIN_IPE: &str = "module Main exposing (main)\n\
    import Ipe.Io as Io\n\
    import Ipe.String as String\n\
    import Ipe.Ffi.Rust as Rust\n\
    import Rust.Ffi\n\n\
    shifted : Int -> Result Error Int\n\
    shifted =\n\
    \x20   Rust.fn \"tm\" \"shift\"\n\n\
    double : Int -> Result Error Int\n\
    double =\n\
    \x20   Rust.fn \"tm\" \"hidden_double\"\n\n\
    boom : Int -> Result Error Int\n\
    boom =\n\
    \x20   Rust.fn \"tm\" \"boom\"\n\n\
    main =\n\
    \x20   case shifted 20 of\n\
    \x20       Ok a ->\n\
    \x20           case double a of\n\
    \x20               Ok b ->\n\
    \x20                   case boom 13 of\n\
    \x20                       Ok _ -> Io.println \"no-panic\"\n\
    \x20                       Err _ -> Io.println (\"panic-err \" ++ String.fromInt b)\n\
    \x20               Err _ -> Io.println \"err double\"\n\
    \x20       Err _ -> Io.println \"err shift\"\n";

fn write_project(dir: &Path, main_ipe: &str) -> bool {
    let src = dir.join("src");
    let _ = fs::remove_dir_all(dir);
    if fs::create_dir_all(&src).is_err() {
        return false;
    }
    if !seed_ffi_cache(dir) {
        return false;
    }
    fs::write(src.join("Main.ipe"), main_ipe).is_ok()
}

/// Read one emitted file, failing with a directory listing when absent.
fn read_emitted(out: &Path, rel: &str) -> String {
    fs::read_to_string(out.join(rel)).unwrap_or_else(|e| {
        let listing: Vec<String> = walk(out).iter().map(|p| p.display().to_string()).collect();
        panic!(
            "emitted file `{rel}` unreadable ({e}); emitted tree:\n{}",
            listing.join("\n")
        );
    })
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() {
            out.extend(walk(&p));
        } else {
            out.push(p);
        }
    }
    out
}

/// Ergonomic gate (#1762): `Rust.fn` resolves with ONLY `import Ipe.Ffi.Rust as
/// Rust` — no `import Rust.Ffi` required. The forwarder qualifier is
/// auto-injected by the resolver when `Ipe.Ffi.Rust` is in scope.
#[test]
fn rust_fn_resolves_without_import_rust_ffi() {
    let runtime = e2e_support::require_runtime().into_path_buf();

    // Identical program to MAIN_IPE but with `import Rust.Ffi` removed.
    let main_no_ffi_import = "module Main exposing (main)\n\
        import Ipe.Io as Io\n\
        import Ipe.String as String\n\
        import Ipe.Ffi.Rust as Rust\n\n\
        shifted : Int -> Result Error Int\n\
        shifted =\n\
        \x20   Rust.fn \"tm\" \"shift\"\n\n\
        double : Int -> Result Error Int\n\
        double =\n\
        \x20   Rust.fn \"tm\" \"hidden_double\"\n\n\
        boom : Int -> Result Error Int\n\
        boom =\n\
        \x20   Rust.fn \"tm\" \"boom\"\n\n\
        main =\n\
        \x20   case shifted 20 of\n\
        \x20       Ok a ->\n\
        \x20           case double a of\n\
        \x20               Ok b ->\n\
        \x20                   case boom 13 of\n\
        \x20                       Ok _ -> Io.println \"no-panic\"\n\
        \x20                       Err _ -> Io.println (\"panic-err \" ++ String.fromInt b)\n\
        \x20               Err _ -> Io.println \"err double\"\n\
        \x20       Err _ -> Io.println \"err shift\"\n";

    let tmp = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("ipec_ffi_rust_fn_no_ffi_import");
    assert!(
        write_project(&tmp, main_no_ffi_import),
        "must write the fixture project + FFI cache"
    );

    let entry = tmp.join("src").join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ffi_rust_fn_no_ffi_import_out");
    let _ = fs::remove_dir_all(&out);

    if let Err(err) = ipe::build_loose_file(&entry, &out, &runtime) {
        panic!(
            "Rust.fn must build with only `import Ipe.Ffi.Rust as Rust` (no `import Rust.Ffi`): {err}"
        )
    }

    let forwarders = read_emitted(&out, "src/ipe_mods/ipe_mod_rust_ffi.rs");
    assert!(
        forwarders.contains("ipe_asserted_tm_shift__"),
        "forwarder must be emitted even without explicit `import Rust.Ffi`:\n{forwarders}"
    );

    let _ = fs::remove_dir_all(&tmp);
}

/// Default gate: `ipe dev build` exits 0 and the emitted crate carries the SAME
/// asserted surface the legacy spelling emits — the `Rust.Ffi` forwarder module
/// and the `ipe_asserted` shim region with exact carriers, the panic boundary,
/// and no coercion. The two spellings share one forwarder by construction.
#[test]
fn rust_fn_emits_the_shared_exact_carrier_shim() {
    let runtime = e2e_support::require_runtime().into_path_buf();

    let tmp = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ipec_ffi_rust_fn");
    assert!(
        write_project(&tmp, MAIN_IPE),
        "must write the fixture project + FFI cache"
    );

    let entry = tmp.join("src").join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ffi_rust_fn_out");
    let _ = fs::remove_dir_all(&out);

    if let Err(err) = ipe::build_loose_file(&entry, &out, &runtime) {
        panic!("rust-fn fixture must build, got: {err}")
    }

    let ffi_rs = read_emitted(&out, "src/ffi.rs");
    let region_start = ffi_rs
        .find("pub mod ipe_asserted")
        .expect("the asserted shim region must be emitted");
    let region = &ffi_rs[region_start..];
    for target in [
        "::tm::shift(arg0)",
        "::tm::hidden_double(arg0)",
        "::tm::boom(arg0)",
    ] {
        assert!(
            region.contains(target),
            "missing shim call {target}:\n{region}"
        );
    }
    assert!(
        region.contains("(arg0: i64) -> IpeResult<IpeError, i64>"),
        "the shim must carry the exact asserted carriers:\n{region}"
    );
    assert!(
        region.contains("catch_unwind"),
        "every native shim is born inside the panic boundary:\n{region}"
    );
    for forbidden in ["num_coerce", "clamp", " as i", " as u", " as f"] {
        assert!(
            !region.contains(forbidden),
            "no coercion may hide in a native shim ({forbidden}):\n{region}"
        );
    }

    let forwarders = read_emitted(&out, "src/ipe_mods/ipe_mod_rust_ffi.rs");
    assert!(
        forwarders.contains("ipe_asserted_tm_shift__"),
        "the Rust.Ffi forwarder must reference the shim:\n{forwarders}"
    );

    let _ = fs::remove_dir_all(&tmp);
}

/// A `Rust.fn` whose target carrier the crate does not declare EXACTLY is
/// refused at build preparation, naming the real Rust carrier — never clamped.
#[test]
fn a_clamp_requiring_rust_fn_is_refused() {
    let runtime = e2e_support::require_runtime().into_path_buf();
    let main = "module Main exposing (main)\n\
            import Ipe.Io as Io\n\
        import Ipe.Ffi.Rust as Rust\n\
        import Rust.Ffi\n\n\
        clamped : Int -> Result Error Int\n\
        clamped =\n\
        \x20   Rust.fn \"tm\" \"clamped\"\n\n\
        main =\n\
        \x20   case clamped 1 of\n\
        \x20       Ok _ -> Io.println \"ok\"\n\
        \x20       Err _ -> Io.println \"err\"\n";
    let tmp = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("ipec_ffi_rust_fn_clamp_refusal");
    assert!(write_project(&tmp, main), "must write the fixture project");
    let entry = tmp.join("src").join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ffi_rust_fn_clamp_out");
    let _ = fs::remove_dir_all(&out);
    let err = ipe::build_loose_file(&entry, &out, &runtime)
        .expect_err("a clamp-requiring native binding must be refused");
    let msg = err.to_string();
    assert!(
        msg.contains("u32") && msg.contains("exact-carrier"),
        "the refusal must name the real carrier and the rule: {msg}"
    );
    let _ = fs::remove_dir_all(&tmp);
}

/// A `Rust.fn` applied to the wrong argument shape (one literal, not two) is
/// refused with the teachable IPE-N0038 — never silently mis-parsed.
#[test]
fn a_malformed_rust_fn_is_refused() {
    let runtime = e2e_support::require_runtime().into_path_buf();
    let main = "module Main exposing (main)\n\
            import Ipe.Io as Io\n\
        import Ipe.Ffi.Rust as Rust\n\
        import Rust.Ffi\n\n\
        shifted : Int -> Result Error Int\n\
        shifted =\n\
        \x20   Rust.fn \"tm::shift\"\n\n\
        main =\n\
        \x20   case shifted 1 of\n\
        \x20       Ok _ -> Io.println \"ok\"\n\
        \x20       Err _ -> Io.println \"err\"\n";
    let tmp =
        std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ipec_ffi_rust_fn_malformed");
    assert!(write_project(&tmp, main), "must write the fixture project");
    let entry = tmp.join("src").join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ffi_rust_fn_malformed_out");
    let _ = fs::remove_dir_all(&out);
    let err = ipe::build_loose_file(&entry, &out, &runtime)
        .expect_err("a one-literal Rust.fn must be refused");
    let msg = err.to_string();
    assert!(
        msg.contains("IPE-N0038") || msg.contains("two string literals"),
        "the refusal must be the teachable IPE-N0038 naming the two-literal shape: {msg}"
    );
    let _ = fs::remove_dir_all(&tmp);
}

/// A `Rust.fn` naming an UNINSTALLED crate is refused — the un-introspectable
/// target is rejected, never blind-trusted into an emitted binding.
#[test]
fn a_rust_fn_on_an_uninstalled_crate_is_refused() {
    let runtime = e2e_support::require_runtime().into_path_buf();
    let main = "module Main exposing (main)\n\
            import Ipe.Io as Io\n\
        import Ipe.Ffi.Rust as Rust\n\
        import Rust.Ffi\n\n\
        ghost : Int -> Result Error Int\n\
        ghost =\n\
        \x20   Rust.fn \"nope\" \"phantom\"\n\n\
        main =\n\
        \x20   case ghost 1 of\n\
        \x20       Ok _ -> Io.println \"ok\"\n\
        \x20       Err _ -> Io.println \"err\"\n";
    let tmp =
        std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ipec_ffi_rust_fn_uninstalled");
    assert!(write_project(&tmp, main), "must write the fixture project");
    let entry = tmp.join("src").join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ffi_rust_fn_uninstalled_out");
    let _ = fs::remove_dir_all(&out);
    let err = ipe::build_loose_file(&entry, &out, &runtime)
        .expect_err("a Rust.fn on an uninstalled crate must be refused");
    let msg = err.to_string();
    assert!(
        msg.contains("nope"),
        "the refusal must name the uninstalled crate: {msg}"
    );
    let _ = fs::remove_dir_all(&tmp);
}

/// SEAL proof under `IPE_E2E=1`: the emitted crate builds against a REAL foreign
/// crate and runs. `shift`/`hidden_double` round-trip values through actual
/// foreign code, and `boom` panics inside the crate — surfacing as a typed
/// `Err`, proven by the printed branch. Identical behaviour to the legacy
/// spelling, since both compile to the same forwarder + shim.
#[test]
fn rust_fn_emitted_crate_builds_and_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let runtime = e2e_support::require_runtime().into_path_buf();

    let tmp = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ipec_ffi_rust_fn_e2e");
    assert!(
        write_project(&tmp, MAIN_IPE),
        "must write the fixture project + FFI cache"
    );

    let entry = tmp.join("src").join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ffi_rust_fn_e2e_out");
    let _ = fs::remove_dir_all(&out);
    if let Err(err) = ipe::build_loose_file(&entry, &out, &runtime) {
        panic!("rust-fn fixture must build, got: {err}")
    }

    let tm_dir = tmp.join("tm");
    fs::create_dir_all(tm_dir.join("src")).expect("mkdir tm");
    fs::write(
        tm_dir.join("Cargo.toml"),
        "[package]\nname = \"tm\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .expect("tm Cargo.toml");
    fs::write(
        tm_dir.join("src/lib.rs"),
        r#"pub fn shift(n: i64) -> i64 { n + 1 }
pub fn clamped(n: u32) -> u32 { n }
pub fn hidden_double(n: i64) -> i64 { n * 2 }
pub fn boom(n: i64) -> i64 {
    assert!(n != 13, "boom");
    n
}
"#,
    )
    .expect("tm lib.rs");

    let manifest_path = out.join("Cargo.toml");
    let manifest = fs::read_to_string(&manifest_path).expect("emitted Cargo.toml");
    assert!(
        manifest.contains("tm = \"=0.1.0\""),
        "emitted manifest must pin the foreign crate; got:\n{manifest}"
    );
    let patched = manifest.replace(
        "tm = \"=0.1.0\"",
        &format!("tm = {{ path = {:?} }}", tm_dir.display().to_string()),
    );
    fs::write(&manifest_path, patched).expect("patched Cargo.toml");

    let cargo = ipe_env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    let run = std::process::Command::new(cargo)
        .arg("run")
        .arg("--quiet")
        .current_dir(&out)
        .output()
        .expect("cargo run spawns");
    let stdout = String::from_utf8_lossy(&run.stdout);
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert!(
        run.status.success(),
        "emitted rust-fn crate must build and run exit 0.\n\
         stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("panic-err 42"),
        "the native bindings must round-trip and the panic must fold to Err.\nstdout: {stdout}"
    );

    let _ = fs::remove_dir_all(&tmp);
}
