//! SEAL: a generic carried under a `Cmd` / `Sub` / `Task` is bounded `Send` per target.
//!
//! On wasm32 the runtime's `Cmd`, `Sub` and `Task` carriers drop `Send` and
//! keep `'static`. The fixture's helpers carry their generic `a` under a `Sub`,
//! a `Cmd`, and a `Task` inside the body and are each used at `a = Cmd Msg`;
//! built for the wasm-client target, every helper's `a` (its first generic,
//! `T1`) must be `'static` without `Send`. Built for the native target, every
//! helper's `a` carries `Send`.
//!
//! Under `IPE_E2E=1` the emitted wasm crate must `cargo check` for
//! `wasm32-unknown-unknown`; a `Send` bound anywhere on those instantiations
//! fails that check, so the leg discriminates.

use std::path::{Path, PathBuf};

use ipe::BuildOptions;

const GOLDEN: &str = "generic_carrier_send_wasm_seal";

/// The helpers carrying their generic `a` under a `Sub`, a `Cmd` and a `Task`.
const EFFECT_HELPERS: [&str; 3] = ["subDiscarded", "cmdBatched", "taskDiscarded"];

fn fixture_entry(root: &Path) -> PathBuf {
    root.join("tests")
        .join("golden")
        .join(GOLDEN)
        .join("Main.ipe")
}

/// The bounds of the first generic `T1` of the `Main` function spelled `ipe_name`.
///
/// Matches the emitted `main_<snake_case>` name with its underscores removed
/// against the lower-cased Ipê name, so the check does not re-derive the
/// backend's snake-casing, then returns the text of `T1`'s entry in the generic
/// parameter list (up to the next parameter or the list's end).
fn first_generic_of<'a>(main_rs: &'a str, ipe_name: &str) -> Option<&'a str> {
    let wanted = format!("main{}", ipe_name.to_lowercase());
    main_rs.lines().find_map(|line| {
        let (_, rest) = line.split_once("fn ")?;
        let name_len = rest
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(rest.len());
        let (name, tail) = rest.split_at(name_len);
        let normalized: String = name.chars().filter(|c| *c != '_').collect();
        if normalized != wanted {
            return None;
        }
        let generics = tail.split_once('(').map_or(tail, |(generics, _)| generics);
        let (_, first) = generics.split_once("T1")?;
        Some(first.split_once(", T").map_or(first, |(bounds, _)| bounds))
    })
}

/// Emit the fixture for `target` into a fresh `out` directory; `None` when the runtime does not resolve.
fn emit(target: ipe_ir::Target, out: &Path) -> Option<String> {
    let _ = std::fs::remove_dir_all(out);
    let runtime = ipe::resolve_runtime().ok()?;
    let entry = fixture_entry(&crate::support::repo_root());
    let options = BuildOptions {
        target,
        ..BuildOptions::default()
    };
    let built = ipe::build_with_options(&entry, out, &runtime, options);
    assert!(
        built.is_ok(),
        "{GOLDEN}: ipe build ({target:?}) must accept the program, got: {built:?}"
    );
    Some(crate::support::read_all_emitted_src(out))
}

/// Emit gate, wasm-client: a `Cmd` / `Sub` / `Task` payload is `'static` without `Send`.
#[test]
fn wasm_effect_carrier_generic_is_static_not_send() {
    let out = std::env::temp_dir().join(format!("ipec_{GOLDEN}_wasm_emit"));
    let Some(emitted) = emit(ipe_ir::Target::WasmClient, &out) else {
        return;
    };
    for name in EFFECT_HELPERS {
        let bounds = first_generic_of(&emitted, name);
        assert!(
            bounds.is_some_and(|b| b.contains("'static") && !b.contains("Send")),
            "{GOLDEN}: on wasm32 `{name}`'s `a` must be `'static` without `Send` (the \
             target's effect carriers are not `Send`), got bounds: {bounds:?}"
        );
    }
}

/// Emit gate, native: every helper's `a` carries `Send + 'static`.
#[test]
fn native_carrier_generic_requires_send() {
    let out = std::env::temp_dir().join(format!("ipec_{GOLDEN}_native_emit"));
    let Some(emitted) = emit(ipe_ir::Target::Native, &out) else {
        return;
    };
    for name in EFFECT_HELPERS {
        let bounds = first_generic_of(&emitted, name);
        assert!(
            bounds.is_some_and(|b| b.contains("Send") && b.contains("'static")),
            "{GOLDEN}: on a native host `{name}`'s `a` must carry `Send + 'static`, got \
             bounds: {bounds:?}"
        );
    }
}

/// THE SEAL: under `IPE_E2E=1` the emitted wasm crate must `cargo check` for `wasm32-unknown-unknown`.
///
/// Outside CI a missing `wasm32-unknown-unknown` target degrades to a clean
/// skip — an environment gap, not a codegen defect.
#[test]
#[allow(clippy::expect_used)] // test setup: a failed cargo spawn IS the failure
fn generic_carrier_send_wasm_seal_checks() {
    if std::env::var("IPE_E2E").is_err() {
        return;
    }
    let target_installed = std::process::Command::new("rustc")
        .args(["--print", "sysroot"])
        .output()
        .is_ok_and(|o| {
            Path::new(String::from_utf8_lossy(&o.stdout).trim())
                .join("lib/rustlib/wasm32-unknown-unknown")
                .is_dir()
        });
    // CI installs the target for this leg, so a missing target there is a failure.
    assert!(
        target_installed || std::env::var_os("CI").is_none(),
        "{GOLDEN}: the wasm32-unknown-unknown target is not installed under CI"
    );
    if !target_installed {
        return;
    }
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("{GOLDEN}_{}", std::process::id()))
        .join("out");
    if emit(ipe_ir::Target::WasmClient, &out).is_none() {
        return;
    }
    let Ok(runtime) = ipe::resolve_runtime() else {
        return;
    };
    let wasm_target = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{GOLDEN}_target"));
    let status = std::process::Command::new("cargo")
        .args(["check", "--target", "wasm32-unknown-unknown"])
        .current_dir(&out)
        .env("CARGO_TARGET_DIR", &wasm_target)
        .env("IPE_RUNTIME_DIR", &runtime)
        .status()
        .expect("spawn cargo check");
    assert!(
        status.success(),
        "{GOLDEN}: ipe accepted the program but the emitted wasm crate FAILED to \
         `cargo check` for wasm32-unknown-unknown — a SEAL break"
    );
}
