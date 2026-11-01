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

use ipe::RootFixture;
use ipe::project_root::SourceTree;
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
                "params": [{"name": "n", "type": "Int", "ipeType": "Int", "rustType": "i64"}],
                "results": [{"name": "", "type": "Int", "rustType": "i64"}],
                "effect": "pure"
            },
            {
                "name": "clamped",
                "params": [{"name": "n", "type": "Int", "ipeType": "Int", "rustType": "u32"}],
                "results": [{"name": "", "type": "Int", "rustType": "u32"}],
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

/// The fixture's declared foreign crate: an FFI fixture is filtered by its
/// declared `rustDependencies`, so it names the crate it binds.
const TM_DEPENDENCY: &str = "rustDependencies = [ rustDep \"tm\" \"=0.1.0\" ]";

/// A project fixture whose `Main` holds `main_ipe`, declaring `tm`, with its FFI cache seeded.
fn ffi_fixture(main_ipe: &str) -> RootFixture {
    ffi_fixture_of(SourceTree::main(main_ipe))
}

/// The project fixture of `tree` declaring `tm`, with its FFI cache seeded.
fn ffi_fixture_of(tree: SourceTree) -> RootFixture {
    let fixture = RootFixture::from_tree(&tree.field(TM_DEPENDENCY))
        .expect("the fixture project must be written and resolved");
    assert!(
        seed_ffi_cache(fixture.path()),
        "must seed the fixture project's FFI cache"
    );
    fixture
}

/// A fresh scratch directory `name` for files that sit outside the project.
fn scratch(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = fs::remove_dir_all(&dir);
    dir
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

    let fixture = ffi_fixture(MAIN_IPE);
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ffi_asserted_call_out");
    let _ = fs::remove_dir_all(&out);

    if let Err(err) = ipe::build_fixture(&fixture, &out, &runtime) {
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
    let fixture = ffi_fixture(main);
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ffi_asserted_clamp_out");
    let _ = fs::remove_dir_all(&out);
    let err = ipe::build_fixture(&fixture, &out, &runtime)
        .expect_err("a clamp-requiring assertion must be refused");
    let msg = err.to_string();
    assert!(
        msg.contains("u32") && msg.contains("exact-carrier"),
        "the refusal must name the real carrier and the rule: {msg}"
    );
    assert!(
        !msg.contains("Rust.Ffi.ipe"),
        "the refusal must not be attributed to the generated module: {msg}"
    );
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
    let fixture = ffi_fixture(main);
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ffi_asserted_misplaced_out");
    let _ = fs::remove_dir_all(&out);
    let err = ipe::build_fixture(&fixture, &out, &runtime)
        .expect_err("a misplaced asserted call must be refused");
    let msg = err.to_string();
    assert!(
        msg.contains("IPE-N0038") || msg.contains("ENTIRE body"),
        "the refusal must be the teachable IPE-N0038: {msg}"
    );
}

/// The asserted escape is a DISCLOSED capability: the whole-program
/// capability set of the fixture carries `ffi-raw` beside `native-ffi`, so
/// package admission and the runtime consent model see the assertion.
#[test]
fn asserted_program_discloses_ffi_raw() {
    let fixture = ffi_fixture(MAIN_IPE);
    let entry = fixture.path().join("src").join("Main.ipe");

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
}

/// The ANALYSIS entrypoints run the same FFI seam the build does: the real
/// `ipe type-check` dispatch type-checks an asserted program, and package
/// capability inference (the jail/admission input) reports `ffi-raw` instead
/// of refusing on an unresolvable `Rust.Ffi` import.
#[test]
fn analysis_entrypoints_accept_an_asserted_program() {
    let fixture = ffi_fixture_of(
        SourceTree::main(MAIN_IPE)
            .named("asserted-fixture")
            .field("version = \"0.1.0\""),
    );

    ipe::run_cli(&[
        "type-check".to_owned(),
        fixture.path().display().to_string(),
    ])
    .expect("`ipe type-check` must accept an asserted program");

    let caps = ipe::infer_package_capabilities(&fixture.manifest_path())
        .expect("package capability inference must lower an asserted program");
    assert!(
        caps.contains(&ipe_ir::Capability::FfiRaw) && caps.contains(&ipe_ir::Capability::NativeFfi),
        "package inference must disclose the asserted crossing: {caps:?}"
    );
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

    let fixture = ffi_fixture(MAIN_IPE);
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ffi_asserted_call_e2e_out");
    let _ = fs::remove_dir_all(&out);
    if let Err(err) = ipe::build_fixture(&fixture, &out, &runtime) {
        panic!("asserted-call fixture must build, got: {err}")
    }

    // The real foreign crate: `hidden_double` and `boom` exist here but were
    // never inspected — exactly the over-dropped-symbol case the escape hatch
    // is for.
    let tmp = scratch("ipec_ffi_asserted_call_e2e");
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

    let ran = e2e_support::build_and_run_rust("ffi_asserted_call", &out);
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
        "emitted asserted-call crate must build and run exit 0.\n\
         stdout: {stdout}"
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

    let fixture = ffi_fixture(CONST_MAIN_IPE);
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ffi_const_read_out");
    let _ = fs::remove_dir_all(&out);
    if let Err(err) = ipe::build_fixture(&fixture, &out, &runtime) {
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
}

/// A `.const` whose asserted type is a `Result` (not a bare scalar) is REFUSED
/// — a native constant is a single infallible value.
#[test]
fn a_result_typed_const_is_refused() {
    let runtime = e2e_support::require_runtime().into_path_buf();

    let main = "module Main exposing (main)\n\
        import Ipe.Io as Io\n\
        import Ipe.Ffi.Rust as Rust\n\n\
        bad : Result Error Int\n\
        bad =\n\
        \x20   Rust.const \"tm\" \"SHIFT_BASE\"\n\n\
        main =\n\
        \x20   Io.println \"unreached\"\n";
    let fixture = ffi_fixture(main);
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ffi_const_result_refused_out");
    let _ = fs::remove_dir_all(&out);
    let err = ipe::build_fixture(&fixture, &out, &runtime)
        .expect_err("a Result-typed .const must be refused");
    let msg = err.to_string();
    assert!(
        msg.contains("bare scalar"),
        "the refusal must name the bare-scalar rule; got: {msg}"
    );
    assert!(
        !msg.contains("Rust.Ffi.ipe"),
        "the refusal must not be attributed to the generated module: {msg}"
    );
}

/// SEAL proof under `IPE_E2E=1`: an accepted `.const` program builds against a
/// REAL foreign crate exposing the constants and runs, reading both values.
#[test]
fn const_read_emitted_crate_builds_and_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let runtime = e2e_support::require_runtime().into_path_buf();

    let fixture = ffi_fixture(CONST_MAIN_IPE);
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ffi_const_read_e2e_out");
    let _ = fs::remove_dir_all(&out);
    if let Err(err) = ipe::build_fixture(&fixture, &out, &runtime) {
        panic!("const fixture must build, got: {err}")
    }

    let tmp = scratch("ipec_ffi_const_read_e2e");
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

    let ran = e2e_support::build_and_run_rust("ffi_asserted_const", &out);
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
        "emitted const crate must build and run exit 0.\nstdout: {stdout}"
    );
    assert!(
        stdout.contains("tm-label 20"),
        "both native constants must be read.\nstdout: {stdout}"
    );

    let _ = fs::remove_dir_all(&tmp);
}

// ── carrier identity (home crate, not spelling) ─────────────────────────────

/// Seed `crate_name`'s inspection: one pure `open_client` fn returning the
/// crate's own opaque `Client` (the same nominal in every seeded crate).
fn client_crate_doc(crate_name: &str) -> serde_json::Value {
    serde_json::json!({
        "pkg": crate_name,
        "name": crate_name,
        "version": "0.1.0",
        "functions": [
            {
                "name": "open_client",
                "params": [{"name": "n", "type": "Int", "ipeType": "Int", "rustType": "i64"}],
                "results": [{"name": "", "type": "Client", "rustType": format!("{crate_name}::Client")}],
                "effect": "pure"
            }
        ],
        "errors": [],
        "transitiveDeps": [
            {"ident": crate_name, "name": crate_name, "version": "0.1.0"}
        ]
    })
}

/// A project fixture whose `Main` holds `main_ipe`, declaring `field`, with
/// each inspection in `docs` installed into its FFI cache.
fn seeded_fixture(main_ipe: &str, field: &str, docs: &[serde_json::Value]) -> RootFixture {
    let fixture = RootFixture::from_tree(&SourceTree::main(main_ipe).field(field))
        .expect("the fixture project must be written and resolved");
    let cache = FfiCache::at_project_root(fixture.path());
    for doc in docs {
        assert!(
            install_from_inspection(&cache, &doc.to_string()).is_ok(),
            "must seed the fixture project's FFI cache with {doc}"
        );
    }
    fixture
}

/// Two crates each declaring an opaque `Client`: the generated `Rust.Ffi`
/// module names each by its home (`Rust.Ta.Client`, `Rust.Tb.Client`).
const TWO_CLIENTS_MAIN_IPE: &str = "module Main exposing (main)\n\
    import Ipe.Io as Io\n\
    import Rust.Ffi\n\
    import Rust.Ta\n\
    import Rust.Tb\n\n\
    openA : Int -> Result Error Rust.Ta.Client\n\
    openA =\n\
    \x20   Rust.Ffi.call \"ta::open_client\"\n\n\
    openB : Int -> Result Error Rust.Tb.Client\n\
    openB =\n\
    \x20   Rust.Ffi.call \"tb::open_client\"\n\n\
    main =\n\
    \x20   case openA 1 of\n\
    \x20       Ok _ ->\n\
    \x20           case openB 2 of\n\
    \x20               Ok _ -> Io.println \"both-clients\"\n\
    \x20               Err _ -> Io.println \"err b\"\n\
    \x20       Err _ -> Io.println \"err a\"\n";

const TWO_CLIENTS_DEPENDENCIES: &str =
    "rustDependencies = [ rustDep \"ta\" \"=0.1.0\", rustDep \"tb\" \"=0.1.0\" ]";

fn two_clients_fixture() -> RootFixture {
    seeded_fixture(
        TWO_CLIENTS_MAIN_IPE,
        TWO_CLIENTS_DEPENDENCIES,
        &[client_crate_doc("ta"), client_crate_doc("tb")],
    )
}

/// Same-named opaques from two crates are two carriers: each asserted
/// signature resolves to its own home and the generated module imports both.
#[test]
fn same_named_opaques_from_two_crates_are_accepted() {
    let runtime = e2e_support::require_runtime().into_path_buf();
    let fixture = two_clients_fixture();
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ffi_asserted_two_clients_out");
    let _ = fs::remove_dir_all(&out);
    let built = ipe::build_fixture(&fixture, &out, &runtime);
    assert!(
        built.is_ok(),
        "two same-named opaques must build: {:?}",
        built.err().map(|e| e.to_string())
    );
    let ffi_rs = read_emitted(&out, "src/ffi.rs");
    for carrier in ["::ta::Client", "::tb::Client"] {
        assert!(
            ffi_rs.contains(carrier),
            "each shim must carry its home's carrier {carrier}:\n{ffi_rs}"
        );
    }
}

/// SEAL proof under `IPE_E2E=1`: the two-`Client` program builds against two
/// real crates and runs.
#[test]
fn same_named_opaques_emitted_crate_builds_and_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let runtime = e2e_support::require_runtime().into_path_buf();
    let fixture = two_clients_fixture();
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ffi_asserted_two_clients_e2e_out");
    let _ = fs::remove_dir_all(&out);
    let built = ipe::build_fixture(&fixture, &out, &runtime);
    assert!(
        built.is_ok(),
        "two same-named opaques must build: {:?}",
        built.err().map(|e| e.to_string())
    );

    let tmp = scratch("ipec_ffi_asserted_two_clients_e2e");
    let manifest_path = out.join("Cargo.toml");
    let mut manifest = fs::read_to_string(&manifest_path).expect("emitted Cargo.toml");
    for name in ["ta", "tb"] {
        let dir = tmp.join(name);
        fs::create_dir_all(dir.join("src")).expect("mkdir crate");
        fs::write(
            dir.join("Cargo.toml"),
            format!("[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"),
        )
        .expect("crate Cargo.toml");
        fs::write(
            dir.join("src/lib.rs"),
            "#[derive(Clone, Debug, PartialEq)]\n\
             pub struct Client(pub i64);\n\
             pub fn open_client(n: i64) -> Client { Client(n) }\n",
        )
        .expect("crate lib.rs");
        let pin = format!("{name} = \"=0.1.0\"");
        assert!(
            manifest.contains(&pin),
            "emitted manifest must pin {name}; got:\n{manifest}"
        );
        manifest = manifest.replace(
            &pin,
            &format!("{name} = {{ path = {:?} }}", dir.display().to_string()),
        );
    }
    fs::write(&manifest_path, manifest).expect("patched Cargo.toml");

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
        "emitted two-client crate must build and run exit 0.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("both-clients"),
        "both asserted calls must succeed.\nstdout: {stdout}"
    );

    let _ = fs::remove_dir_all(&tmp);
}

/// A `define` nominal used as an asserted carrier is imported from its home
/// crate's module.
#[test]
fn a_define_nominal_asserted_carrier_is_accepted() {
    let runtime = e2e_support::require_runtime().into_path_buf();
    let doc = serde_json::json!({
        "pkg": "td", "name": "td", "version": "0.1.0",
        "functions": [{
            "name": "blob_new", "effect": "pure", "isStructCtor": true,
            "structName": "Blob",
            "structFields": [{ "name": "data", "type": "Bytes" }],
            "structDerives": ["Clone"]
        }],
        "errors": [],
        "transitiveDeps": [
            {"ident": "td", "name": "td", "version": "0.1.0"}
        ]
    });
    let main = "module Main exposing (main)\n\
        import Ipe.Io as Io\n\
        import Rust.Ffi\n\
        import Rust.Td\n\n\
        blobLen : Rust.Td.Blob -> Result Error Int\n\
        blobLen =\n\
        \x20   Rust.Ffi.call \"td::blob_len\"\n\n\
        main =\n\
        \x20   Io.println \"define-ok\"\n";
    let fixture = seeded_fixture(
        main,
        "rustDependencies = [ rustDep \"td\" \"=0.1.0\" ]",
        &[doc],
    );
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ffi_asserted_define_out");
    let _ = fs::remove_dir_all(&out);
    let built = ipe::build_fixture(&fixture, &out, &runtime);
    assert!(
        built.is_ok(),
        "a define-nominal asserted carrier must build: {:?}",
        built.err().map(|e| e.to_string())
    );
}

/// A type alias the module declares is not a foreign carrier, even when its
/// name is a wire spelling (`Str`): the refusal names the alias and is
/// attributed to the user's assertion, never to the generated `Rust.Ffi`.
#[test]
fn a_local_alias_carrier_is_refused() {
    let runtime = e2e_support::require_runtime().into_path_buf();
    let main = "module Main exposing (main)\n\
        import Ipe.Io as Io\n\
        import Rust.Ffi\n\n\
        type alias Str = Int\n\n\
        shifted : Str -> Result Error Int\n\
        shifted =\n\
        \x20   Rust.Ffi.call \"tm::shift\"\n\n\
        main =\n\
        \x20   case shifted 1 of\n\
        \x20       Ok _ -> Io.println \"ok\"\n\
        \x20       Err _ -> Io.println \"err\"\n";
    let fixture = ffi_fixture(main);
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ffi_asserted_local_alias_out");
    let _ = fs::remove_dir_all(&out);
    let built = ipe::build_fixture(&fixture, &out, &runtime);
    assert!(built.is_err(), "a local alias carrier must be refused");
    let msg = built.err().map(|e| e.to_string()).unwrap_or_default();
    assert!(
        msg.contains("`Str` is a type alias this module declares"),
        "the refusal must name the alias as the cause: {msg}"
    );
    assert!(
        !msg.contains("Rust.Ffi.ipe"),
        "the refusal must not be attributed to the generated module: {msg}"
    );
}
