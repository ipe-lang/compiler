//! THE SEAL for the asserted-call surface (`Rust.Ffi.call`): a low-ceremony
//! typed escape hatch whose shim carries the author-asserted signature under
//! the exact-carrier rule and inside the panic boundary.
//!
//! The default gate proves the whole pipeline emits: the driver scans the
//! asserted definitions, generates the `Rust.Ffi` interface module, appends
//! the `ipe_asserted` shim region (exact carriers, `catch_unwind`, no
//! coercion), and the app compiles against it. The refusal tests prove the
//! fail-closed edges: an inspected target whose carrier has no exact Ipê
//! match is refused naming the real carrier, and a misplaced use is refused
//! with IPE-N0038. The `IPE_E2E=1` gate then proves THE SEAL end to end: the
//! emitted crate builds against a real foreign crate and RUNS — a valid
//! asserted call round-trips values, and a panicking foreign call comes back
//! as a typed `Err`, never an escaping unwind.
//!
//! ```text
//! cargo test -p ipe --test golden_ffi_asserted_call_seal
//! ```
#![allow(clippy::expect_used, clippy::panic)] // test setup: a failed build/write IS the failure

use std::fs;
use std::path::{Path, PathBuf};

use ipe_ffi::driver::{FfiCache, install_from_inspection};

/// Seed the project's FFI cache with an inspection for a crate `tm` whose
/// surface exercises both checker arms: `shift` is inspected with exact `i64`
/// carriers (compile-time check passes), `clamped` is inspected with `u32`
/// carriers (the exact-carrier refusal), and `hidden_double` / `boom` are NOT
/// in the inspection (the over-drop case the escape hatch exists for — rustc
/// is the checker of record).
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
        "constants": [
            {"path": "SHIFT_BASE", "type": "i64"},
            {"path": "consts::LABEL", "type": "&'static str"}
        ],
        "errors": [],
        "transitiveDeps": [
            {"ident": "tm", "name": "tm", "version": "0.1.0"}
        ]
    });
    install_from_inspection(&cache, &doc.to_string()).is_ok()
}

/// The fixture program: three asserted definitions — one against an inspected
/// symbol, two against uninspected ones — threaded so the printed output
/// proves the round-trip AND the panic→`Err` fold.
const MAIN_IPE: &str = "module Main exposing (main)\n\
    import Ipe.Io as Io\n\
    import Ipe.String as String\n\
    import Rust.Ffi\n\n\
    shifted : Int -> Result Error Int\n\
    shifted =\n\
    \x20   Rust.Ffi.call \"tm::shift\"\n\n\
    double : Int -> Result Error Int\n\
    double =\n\
    \x20   Rust.Ffi.call \"tm::hidden_double\"\n\n\
    boom : Int -> Result Error Int\n\
    boom =\n\
    \x20   Rust.Ffi.call \"tm::boom\"\n\n\
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

/// Read one emitted file, failing the test with a directory listing when the
/// expected path is absent (a layout drift, not a silent skip).
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

/// Default gate: `ipe dev build` exits 0 and the emitted crate carries the whole
/// asserted surface — the `Rust.Ffi` forwarder module and the `ipe_asserted`
/// shim region with exact carriers, the panic boundary, and no coercion.
#[test]
fn asserted_call_emits_the_exact_carrier_shim() {
    let runtime = e2e_support::require_runtime().into_path_buf();

    let tmp = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ipec_ffi_asserted_call");
    assert!(
        write_project(&tmp, MAIN_IPE),
        "must write the fixture project + FFI cache"
    );

    let entry = tmp.join("src").join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ffi_asserted_call_out");
    let _ = fs::remove_dir_all(&out);

    if let Err(err) = ipe::build_loose_file(&entry, &out, &runtime) {
        panic!("asserted-call fixture must build, got: {err}")
    }

    // The shim region: exact declared carriers, the panic boundary, no
    // coercion anywhere in the asserted module.
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
        "every asserted shim is born inside the panic boundary:\n{region}"
    );
    for forbidden in ["num_coerce", "clamp", " as i", " as u", " as f"] {
        assert!(
            !region.contains(forbidden),
            "no coercion may hide in an asserted shim ({forbidden}):\n{region}"
        );
    }

    // The generated forwarder module for `Rust.Ffi` exists and forwards each
    // asserted definition to its shim.
    let forwarders = read_emitted(&out, "src/ipe_mods/ipe_mod_rust_ffi.rs");
    assert!(
        forwarders.contains("ipe_asserted_tm_shift__"),
        "the Rust.Ffi forwarder must reference the shim:\n{forwarders}"
    );

    let _ = fs::remove_dir_all(&tmp);
}

/// A carrier the target does not declare EXACTLY is refused at build
/// preparation, naming the real Rust carrier — never silently clamped.
#[test]
fn a_clamp_requiring_assertion_is_refused() {
    let runtime = e2e_support::require_runtime().into_path_buf();
    let main = "module Main exposing (main)\n\
            import Ipe.Io as Io\n\
        import Rust.Ffi\n\n\
        clamped : Int -> Result Error Int\n\
        clamped =\n\
        \x20   Rust.Ffi.call \"tm::clamped\"\n\n\
        main =\n\
        \x20   case clamped 1 of\n\
        \x20       Ok _ -> Io.println \"ok\"\n\
        \x20       Err _ -> Io.println \"err\"\n";
    let tmp = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("ipec_ffi_asserted_clamp_refusal");
    assert!(write_project(&tmp, main), "must write the fixture project");
    let entry = tmp.join("src").join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ffi_asserted_clamp_out");
    let _ = fs::remove_dir_all(&out);
    let err = ipe::build_loose_file(&entry, &out, &runtime)
        .expect_err("a clamp-requiring assertion must be refused");
    let msg = err.to_string();
    assert!(
        msg.contains("u32") && msg.contains("exact-carrier"),
        "the refusal must name the real carrier and the rule: {msg}"
    );
    let _ = fs::remove_dir_all(&tmp);
}

/// A `Rust.Ffi.call` buried inside a larger expression is refused with the
/// teachable IPE-N0038 — never silently ignored, never a confusing miss.
#[test]
fn a_misplaced_asserted_call_is_refused() {
    let runtime = e2e_support::require_runtime().into_path_buf();
    let main = "module Main exposing (main)\n\
            import Ipe.Io as Io\n\
        import Rust.Ffi\n\n\
        main =\n\
        \x20   case (Rust.Ffi.call \"tm::shift\") 1 of\n\
        \x20       Ok _ -> Io.println \"ok\"\n\
        \x20       Err _ -> Io.println \"err\"\n";
    let tmp =
        std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ipec_ffi_asserted_misplaced");
    assert!(write_project(&tmp, main), "must write the fixture project");
    let entry = tmp.join("src").join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ffi_asserted_misplaced_out");
    let _ = fs::remove_dir_all(&out);
    let err = ipe::build_loose_file(&entry, &out, &runtime)
        .expect_err("a misplaced asserted call must be refused");
    let msg = err.to_string();
    assert!(
        msg.contains("IPE-N0038") || msg.contains("ENTIRE body"),
        "the refusal must be the teachable IPE-N0038: {msg}"
    );
    let _ = fs::remove_dir_all(&tmp);
}

/// The asserted escape is a DISCLOSED capability: the whole-program
/// capability set of the fixture carries `ffi-raw` beside `native-ffi`, so
/// package admission and the runtime consent model see the assertion.
#[test]
fn asserted_program_discloses_ffi_raw() {
    let tmp = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ipec_ffi_asserted_caps");
    assert!(
        write_project(&tmp, MAIN_IPE),
        "must write the fixture project + FFI cache"
    );
    let entry = tmp.join("src").join("Main.ipe");

    // The same front-end seam the build runs: stdlib injection → FFI
    // preparation (scan + interface injection) → lower → capability scan.
    let mut sources: std::collections::BTreeMap<Vec<String>, (PathBuf, String)> =
        std::collections::BTreeMap::new();
    sources.insert(
        vec!["Main".to_owned()],
        (entry.clone(), MAIN_IPE.to_owned()),
    );
    let mut discovered = Vec::new();
    let injected = ipe::project::inject_compiled_std_closure(&mut sources, &mut discovered);
    let prep = ipe::ffi::prepare_ffi(&mut sources, &entry).expect("FFI preparation succeeds");
    let db = ipe_db::IpeDatabase::new();
    let root = ipe::create_source_root(&db, &sources, &injected, &prep.injected);
    let entry_file = root
        .files(&db)
        .get(&vec!["Main".to_owned()])
        .copied()
        .expect("entry module present");
    let program = match ipe_db::lower_program(&db, root, entry_file) {
        Ok(p) => p,
        Err(err) => panic!("fixture must lower: {err:?}"),
    };
    let caps = ipe_lower::program_capabilities(program);
    assert!(
        caps.contains(&ipe_ir::Capability::FfiRaw),
        "an asserted call must flip ffi-raw: {caps:?}"
    );
    assert!(
        caps.contains(&ipe_ir::Capability::NativeFfi),
        "every asserted call is also a native crossing: {caps:?}"
    );

    let _ = fs::remove_dir_all(&tmp);
}

/// The ANALYSIS entrypoints run the same FFI seam the build does: the real
/// `ipe type-check` dispatch type-checks an asserted program, and package
/// capability inference (the jail/admission input) reports `ffi-raw` instead
/// of refusing on an unresolvable `Rust.Ffi` import.
#[test]
fn analysis_entrypoints_accept_an_asserted_program() {
    let tmp =
        std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ipec_ffi_asserted_analysis");
    assert!(
        write_project(&tmp, MAIN_IPE),
        "must write the fixture project + FFI cache"
    );
    fs::write(
        tmp.join("package.ipe"),
        "module Package exposing (package)\n\n\npackage =\n    { name = \"asserted-fixture\", version = \"0.1.0\" }\n",
    )
    .expect("package.ipe");

    let entry = tmp.join("src").join("Main.ipe");
    ipe::run_cli(&["type-check".to_owned(), entry.display().to_string()])
        .expect("`ipe type-check` must accept an asserted program");

    let caps = ipe::infer_package_capabilities(&tmp.join("package.ipe"))
        .expect("package capability inference must lower an asserted program");
    assert!(
        caps.contains(&ipe_ir::Capability::FfiRaw) && caps.contains(&ipe_ir::Capability::NativeFfi),
        "package inference must disclose the asserted crossing: {caps:?}"
    );

    let _ = fs::remove_dir_all(&tmp);
}

/// SEAL proof under `IPE_E2E=1`: the emitted crate builds against a REAL
/// foreign crate and runs. `shift`/`hidden_double` round-trip values through
/// actual foreign code (`hidden_double` was never inspected — the rustc
/// checker of record accepted the assertion), and `boom` panics inside the
/// crate — surfacing as a typed `Err`, proven by the printed branch.
#[test]
fn asserted_call_emitted_crate_builds_and_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let runtime = e2e_support::require_runtime().into_path_buf();

    let tmp =
        std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ipec_ffi_asserted_call_e2e");
    assert!(
        write_project(&tmp, MAIN_IPE),
        "must write the fixture project + FFI cache"
    );

    let entry = tmp.join("src").join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ffi_asserted_call_e2e_out");
    let _ = fs::remove_dir_all(&out);
    if let Err(err) = ipe::build_loose_file(&entry, &out, &runtime) {
        panic!("asserted-call fixture must build, got: {err}")
    }

    // The real foreign crate: `hidden_double` and `boom` exist here but were
    // never inspected — exactly the over-dropped-symbol case the escape hatch
    // is for.
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

    // Repoint the registry pin at the local fixture crate.
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
        "emitted asserted-call crate must build and run exit 0.\n\
         stdout: {stdout}\nstderr: {stderr}"
    );
    // shift 20 → 21 → hidden_double → 42; boom 13 panics INSIDE the foreign
    // crate and comes back as a typed Err — the printed branch proves both.
    assert!(
        stdout.contains("panic-err 42"),
        "the asserted calls must round-trip and the panic must fold to Err.\nstdout: {stdout}"
    );

    let _ = fs::remove_dir_all(&tmp);
}

// ── native constants (`Rust.const`) ─────────────────────────────────────────

/// A program that reads two native constants of a bare scalar type. No
/// `Result`, no parentheses, no unit parameter — a constant is an infallible
/// value.
const CONST_MAIN_IPE: &str = "module Main exposing (main)\n\
    import Ipe.Io as Io\n\
    import Ipe.String as String\n\
    import Ipe.Ffi.Rust as Rust\n\n\
    shiftBase : Int\n\
    shiftBase =\n\
    \x20   Rust.const \"tm\" \"SHIFT_BASE\"\n\n\
    label : String\n\
    label =\n\
    \x20   Rust.const \"tm\" \"consts::LABEL\"\n\n\
    main =\n\
    \x20   Io.println (label ++ \" \" ++ String.fromInt shiftBase)\n";

/// Default gate: an accepted `.const` program builds, and the emitted shim
/// reads the constant BARE — `::tm::SHIFT_BASE` with no call parens, no
/// `IpeResult`, no `catch_unwind`.
#[test]
fn const_read_emits_a_bare_infallible_shim() {
    let runtime = e2e_support::require_runtime().into_path_buf();

    let tmp = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ipec_ffi_const_read");
    assert!(
        write_project(&tmp, CONST_MAIN_IPE),
        "must write the const fixture project + FFI cache"
    );

    let entry = tmp.join("src").join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ffi_const_read_out");
    let _ = fs::remove_dir_all(&out);
    if let Err(err) = ipe::build_loose_file(&entry, &out, &runtime) {
        panic!("const fixture must build, got: {err}")
    }

    let ffi_rs = read_emitted(&out, "src/ffi.rs");
    assert!(
        ffi_rs.contains("pub mod ipe_asserted_const {"),
        "the const shim region must be emitted; ffi.rs:\n{ffi_rs}"
    );
    // The SEAL of the const read: a bare `::tm::PATH` value, no call parens,
    // no panic boundary, no `IpeResult` on the const shims.
    assert!(
        ffi_rs.contains("::tm::SHIFT_BASE") && !ffi_rs.contains("::tm::SHIFT_BASE("),
        "SHIFT_BASE must be a bare read, no call parens; ffi.rs:\n{ffi_rs}"
    );
    assert!(
        ffi_rs.contains("::tm::consts::LABEL.to_owned()"),
        "a String const must own its &str source; ffi.rs:\n{ffi_rs}"
    );

    let _ = fs::remove_dir_all(&tmp);
}

/// A `.const` whose asserted type is a `Result` (not a bare scalar) is REFUSED
/// — a native constant is a single infallible value.
#[test]
fn a_result_typed_const_is_refused() {
    let runtime = e2e_support::require_runtime().into_path_buf();

    let tmp =
        std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ipec_ffi_const_result_refused");
    let main = "module Main exposing (main)\n\
        import Ipe.Io as Io\n\
        import Ipe.Ffi.Rust as Rust\n\n\
        bad : Result Error Int\n\
        bad =\n\
        \x20   Rust.const \"tm\" \"SHIFT_BASE\"\n\n\
        main =\n\
        \x20   Io.println \"unreached\"\n";
    assert!(write_project(&tmp, main), "must write the fixture project");

    let entry = tmp.join("src").join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ffi_const_result_refused_out");
    let _ = fs::remove_dir_all(&out);
    let err = ipe::build_loose_file(&entry, &out, &runtime)
        .expect_err("a Result-typed .const must be refused");
    assert!(
        err.to_string().contains("bare scalar"),
        "the refusal must name the bare-scalar rule; got: {err}"
    );

    let _ = fs::remove_dir_all(&tmp);
}

/// SEAL proof under `IPE_E2E=1`: an accepted `.const` program builds against a
/// REAL foreign crate exposing the constants and runs, reading both values.
#[test]
fn const_read_emitted_crate_builds_and_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let runtime = e2e_support::require_runtime().into_path_buf();

    let tmp = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ipec_ffi_const_read_e2e");
    assert!(
        write_project(&tmp, CONST_MAIN_IPE),
        "must write the const fixture project + FFI cache"
    );

    let entry = tmp.join("src").join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ffi_const_read_e2e_out");
    let _ = fs::remove_dir_all(&out);
    if let Err(err) = ipe::build_loose_file(&entry, &out, &runtime) {
        panic!("const fixture must build, got: {err}")
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
        "pub const SHIFT_BASE: i64 = 20;\n\
         pub mod consts { pub const LABEL: &str = \"tm-label\"; }\n",
    )
    .expect("tm lib.rs");

    let manifest_path = out.join("Cargo.toml");
    let manifest = fs::read_to_string(&manifest_path).expect("emitted Cargo.toml");
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
        "emitted const crate must build and run exit 0.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("tm-label 20"),
        "both native constants must be read.\nstdout: {stdout}"
    );

    let _ = fs::remove_dir_all(&tmp);
}
