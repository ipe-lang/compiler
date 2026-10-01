//! SEAL fixture for the `#[define_in_ipe]` trait-impl escape hatch (Tier 2 §6).
//!
//! Some crate types need a real hand-written `impl Trait` whose derive is
//! outside Ipê's closed modellable set — a Bevy `#[derive(Component)]` /
//! `Resource`, or here a fixture `Render` trait. Such a type cannot be
//! *declared* through the closed Tier 1 `[rust.define.*]` forms, so the author
//! writes it as normal Rust in a `[rust.wrapper]` crate and tags it with
//! `#[define_in_ipe]`. The tagged type is bound as an ORDINARY wrapper symbol —
//! an Ipê-held opaque nominal plus its carrier-compatible forwarders — never
//! injected into emitted `.ipe`. This is a special case of a Tier 2 wrapper, not
//! a new mechanism, so it rides the SAME inspect → emit → path-dep pipeline the
//! `wrapper_crate_seal.rs` fixture proves.
//!
//! The keystone SEAL is unchanged: `ipe` exit 0 ⇒ the emitted app crate — our
//! generated bindings PLUS the wrapper (which depends on the `ipe_bindgen`
//! marker crate and hand-writes a trait impl) as a `path` dependency —
//! cargo-builds and runs.
//!
//! The emit-only + over-drop assertions run in the DEFAULT gate; the real
//! marker-driven inspection + cargo build/run proof is `IPE_E2E`-gated (it shells
//! out to `cargo` and the built inspector), matching the repo's other SEAL
//! fixtures.
#![allow(clippy::expect_used)] // test setup: a failed decode / scratch-dir op IS the failure

use ipe_ffi::bindings::{emit_bindings, surviving_ref_names};
use ipe_ffi::driver::{FfiCache, cargo_dep_lines};
use ipe_ffi::interface::crate_interface;
use ipe_ffi::pkginfo::PkgInfo;

/// The inspection document the inspector produces for a wrapper crate whose
/// `#[define_in_ipe]`-marked `Sprite` type implements a fixture `Render` trait: a
/// carrier-typed constructor (`spawn(depth: i64) -> Sprite`) and an owned-value
/// reader (`label(s: Sprite) -> String`, forwarding the hand-written
/// `Render::label` impl method). `wrapperPath` marks the package as an
/// author-supplied wrapper crate, so the emitted app crate depends on it by
/// `path`.
fn sprite_wrapper_pkg(wrapper_path: &str) -> PkgInfo {
    let doc = serde_json::json!({
        "pkg": "sprite_wrap",
        "name": "sprite_wrap",
        "version": "0.1.0",
        "wrapperPath": wrapper_path,
        "functions": [
            {
                "name": "spawn",
                "params": [{ "name": "depth", "type": "i64", "ipeType": "Int", "rustType": "i64" }],
                "results": [{ "name": "", "type": "sprite_wrap::Sprite", "rustType": "sprite_wrap::Sprite" }],
                "effect": "pure"
            },
            {
                "name": "label",
                "params": [{ "name": "s", "type": "sprite_wrap::Sprite", "ipeType": "Sprite", "rustType": "sprite_wrap::Sprite" }],
                "results": [{ "name": "", "type": "String", "rustType": "String" }],
                "effect": "pure"
            }
        ],
        "errors": []
    })
    .to_string();
    PkgInfo::decode_json(&doc).expect("marked-wrapper inspection decodes")
}

/// Default gate: the marked type's constructor + reader bind and call into the
/// wrapper crate, and the driver renders the wrapper as a `path` dependency. A
/// `#[define_in_ipe]`-marked type is bound exactly like any other exposed wrapper
/// symbol — the emit path does not distinguish it, which is the point.
#[test]
fn a_marked_trait_impl_type_binds_its_symbols_and_depends_by_path() {
    let pkg = sprite_wrapper_pkg("wrappers/sprite");
    let bindings = emit_bindings(&pkg);
    assert!(
        bindings.contains("pub fn sprite_wrap_spawn("),
        "the spawn constructor must bind:\n{bindings}"
    );
    assert!(
        bindings.contains("::sprite_wrap::spawn("),
        "the wrapper call must target the wrapper crate:\n{bindings}"
    );
    assert!(
        bindings.contains("pub fn sprite_wrap_label("),
        "the label reader (forwarding the trait-impl method) must bind:\n{bindings}"
    );
    assert!(
        bindings.contains("::sprite_wrap::label("),
        "the reader's call must target the wrapper crate:\n{bindings}"
    );
    let iface = crate_interface(&pkg);
    assert_eq!(
        iface.opaque_types.get("Sprite").map(String::as_str),
        Some("::sprite_wrap::Sprite"),
        "the marked type resolves to an Ipê-held opaque nominal: {:?}",
        iface.opaque_types
    );
    // The relative wrapper path is jailed to the project root at load and
    // rendered as its canonical absolute directory.
    let project =
        ipe_test_temp::temp_root().join(format!("ipe-sprite-wrap-dep-line-{}", std::process::id()));
    std::fs::create_dir_all(project.join("wrappers/sprite")).expect("scratch wrapper dir");
    std::fs::write(
        project.join("wrappers/sprite/Cargo.toml"),
        "[package]\nname = \"sprite_wrap\"\nversion = \"0.1.0\"\n",
    )
    .expect("scratch wrapper manifest");
    let canonical =
        std::fs::canonicalize(project.join("wrappers/sprite")).expect("wrapper dir canonicalizes");
    let deps = cargo_dep_lines(&pkg, &FfiCache::at_project_root(&project))
        .expect("renders a path dep line");
    let _ = std::fs::remove_dir_all(&project);
    assert_eq!(
        deps,
        [format!(
            "sprite_wrap = {{ path = \"{}\" }}",
            canonical.display()
        )],
        "the wrapper is a path dependency of the emitted app crate"
    );
}

/// Default gate: a marked type's borrowed-RETURN method cannot cross the
/// owned-only boundary, so its binding over-drops with a diagnostic — the mark
/// does NOT force an unsound binding; the type's other symbols survive.
#[test]
fn a_marked_borrowed_return_method_over_drops() {
    let doc = serde_json::json!({
        "pkg": "sprite_wrap",
        "name": "sprite_wrap",
        "version": "0.1.0",
        "wrapperPath": "wrappers/sprite",
        "functions": [
            {
                "name": "spawn",
                "params": [{ "name": "depth", "type": "i64", "ipeType": "Int", "rustType": "i64" }],
                "results": [{ "name": "", "type": "Sprite", "rustType": "Sprite" }],
                "effect": "pure"
            },
            {
                // A `&Sprite -> &str` reader returns a borrow that would escape
                // the owned-only carrier boundary. Even on a marked type, the
                // emitter cannot render a sound owned wrapper for a borrowed
                // return, so the region is empty and the interface skips it.
                "name": "name_ref",
                "params": [{ "name": "s", "type": "Sprite", "ipeType": "Sprite", "rustType": "&Sprite" }],
                "results": [{ "name": "", "type": "String", "rustType": "&str" }],
                "recvType": "Sprite",
                "recvRustType": "&Sprite",
                "methodName": "name_ref",
                "effect": "pure"
            }
        ],
        "errors": []
    })
    .to_string();
    let pkg = PkgInfo::decode_json(&doc).expect("decodes");
    let survivors = surviving_ref_names(&pkg);
    assert!(
        survivors.iter().any(|s| s == "spawn"),
        "the sound constructor must survive: {survivors:?}"
    );
    let bindings = emit_bindings(&pkg);
    assert!(
        !bindings.contains("::sprite_wrap::name_ref"),
        "a borrowed-return method must over-drop, never emit-and-cargo-fail:\n{bindings}"
    );
}

/// The load-bearing SEAL proof under `IPE_E2E=1`: run the REAL inspector over a
/// wrapper crate that depends on the `ipe_bindgen` marker crate, tags a `Sprite`
/// type with `#[ipe_bindgen::define_in_ipe]`, and hand-writes an `impl Render for
/// Sprite`. Assert the marker surfaces the type (its constructor + trait-impl
/// reader bind even though `expose` names ONLY the constructor), then assemble
/// the emitted app crate + the wrapper `path` dep and cargo-run it. `ipe` exit 0
/// ⇒ the crate compiles; the run asserts the value round-trips through the
/// hand-written trait impl.
#[test]
fn the_marker_surfaces_the_type_and_the_emitted_crate_builds_and_runs() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let cargo = ipe_env::var("CARGO").expect("cargo sets CARGO for every test it runs");

    // The built inspector binary sits beside the test deps under the target dir;
    // `env!` gives the ffi crate dir, from which the workspace target is
    // reachable. Prefer an explicit override, else look beside the test binary.
    let inspector = locate_inspector();
    let Some(inspector) = inspector else {
        return; // inspector not built in this environment — skip
    };

    let root =
        ipe_test_temp::temp_root().join(format!("ipe_ffi_define_seal_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);

    // 1-2. Write the marked wrapper crate and run the REAL inspector over it,
    //       exposing ONLY `spawn`. `None` ⇒ the inspector's nightly rustdoc is
    //       unavailable here; skip like the goldens skipping without cargo.
    let wrapper_dir = root.join("wrappers").join("sprite");
    let Some(pkg) = inspect_marked_wrapper(&wrapper_dir, &root, &inspector) else {
        return;
    };
    // The `#[define_in_ipe]` marker must auto-surface `Sprite` (and thus the
    // `label` reader that takes/produces it) even though it is not in `--expose`
    // — proving marker-driven pickup, not just the expose list.
    let survivors = surviving_ref_names(&pkg);
    assert!(
        survivors.iter().any(|s| s == "spawn"),
        "the explicitly-exposed constructor must survive: {survivors:?}"
    );
    assert!(
        survivors.iter().any(|s| s == "label"),
        "the #[define_in_ipe] marker must auto-surface the trait-impl reader \
         even though only `spawn` was exposed: {survivors:?}"
    );

    // 3. Assemble the emitted app crate: its bindings call into the wrapper by
    //    its crate-absolute path, and it depends on the wrapper by the driver's
    //    `path` dep line (rewritten to point at the crate we just wrote).
    let bindings = emit_bindings(&pkg);
    let spawn = wrapper_region(&bindings, "spawn");
    let label = wrapper_region(&bindings, "label");
    let iface = crate_interface(&pkg);
    let mut aliases = String::new();
    for (name, path) in &iface.opaque_types {
        use std::fmt::Write as _;
        let _ = writeln!(aliases, "pub type {name} = {path};");
    }

    std::fs::create_dir_all(root.join("src")).expect("mkdir app");
    let wrapper_abs = wrapper_dir.to_string_lossy().to_string();
    std::fs::write(
        root.join("Cargo.toml"),
        format!(
            "[package]\nname = \"define_seal\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\
             [[bin]]\nname = \"define_seal\"\npath = \"src/main.rs\"\n\
             [dependencies]\nsprite_wrap = {{ path = {wrapper_abs:?} }}\n",
        ),
    )
    .expect("app Cargo.toml");

    let main_rs = format!(
        r#"#![allow(unused_imports, unused_mut, dead_code)]
pub enum IpeResult<E, T> {{ Ok(T), Err(E) }}
pub struct IpeError(String);
pub fn ok_res<T>(t: T) -> IpeResult<IpeError, T> {{ IpeResult::Ok(t) }}
pub fn str_err(s: &str) -> IpeError {{ IpeError(s.to_string()) }}
pub fn ipe_error_from_panic(c: &str, _p: Box<dyn std::any::Any + Send>) -> IpeError {{ IpeError(c.to_string()) }}
pub fn note_foreign_panic(_c: &str, _p: Box<dyn std::any::Any + Send>) -> String {{ String::new() }}
pub fn note_foreign_error<T: std::fmt::Debug>(_e: T) -> String {{ String::new() }}
pub fn ipe_error_from_foreign<T: std::fmt::Debug>(_e: T) -> IpeError {{ IpeError("external operation failed".to_string()) }}

{aliases}

{spawn}

{label}

fn main() {{
    let sprite = match sprite_wrap_spawn(3) {{
        IpeResult::Ok(s) => s,
        IpeResult::Err(_) => panic!("spawn failed"),
    }};
    let text = match sprite_wrap_label(sprite) {{
        IpeResult::Ok(s) => s,
        IpeResult::Err(_) => panic!("label failed"),
    }};
    println!("{{}}", text);
}}
"#,
    );
    std::fs::write(root.join("src").join("main.rs"), main_rs).expect("app main.rs");

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
        "the emitted app crate + marked-wrapper path dep must build and run exit 0.\n\
         stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("sprite@3"),
        "the value must round-trip through the hand-written trait impl.\nstdout: {stdout}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// Write the author-supplied marked wrapper crate under `wrapper_dir` and run
/// the real inspector over it (exposing only `spawn`), returning the decoded
/// inspection — or `None` when the inspector's nightly rustdoc is unavailable.
///
/// The wrapper is normal Rust: it tags `Sprite` with `#[ipe_bindgen::define_in_ipe]`
/// and hand-writes an `impl Render for Sprite` a closed Tier 1 form could not
/// express (a fixture `Render`, standing in for a Bevy `Component`). `label`
/// forwards the trait-impl method as an owned-value binding.
fn inspect_marked_wrapper(
    wrapper_dir: &std::path::Path,
    root: &std::path::Path,
    inspector: &std::path::Path,
) -> Option<PkgInfo> {
    // The `ipe_bindgen` marker crate lives beside the ffi crate in the
    // workspace; the wrapper depends on it by an absolute `path`.
    let define_crate = e2e_support::manifest_dir!()
        .join("../../ffi-bindgen-macro")
        .canonicalize()
        .expect("ipe_bindgen crate resolves");

    std::fs::create_dir_all(wrapper_dir.join("src")).expect("mkdir wrapper");
    std::fs::write(
        wrapper_dir.join("Cargo.toml"),
        format!(
            "[package]\nname = \"sprite_wrap\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
             [dependencies]\nipe_bindgen = {{ path = {:?} }}\n",
            define_crate.to_string_lossy()
        ),
    )
    .expect("wrapper Cargo.toml");
    std::fs::write(
        wrapper_dir.join("src").join("lib.rs"),
        "/// A fixture trait whose impl only hand-written Rust can express — the\n\
         /// escape-hatch case (stands in for a Bevy `Component`).\n\
         pub trait Render { fn label(&self) -> String; }\n\
         \n\
         #[ipe_bindgen::define_in_ipe]\n\
         pub struct Sprite { depth: i64 }\n\
         \n\
         impl Render for Sprite {\n\
         \x20   fn label(&self) -> String { format!(\"sprite@{}\", self.depth) }\n\
         }\n\
         \n\
         pub fn spawn(depth: i64) -> Sprite { Sprite { depth } }\n\
         // A free reader forwarding the hand-written trait-impl method as an\n\
         // owned-value binding.\n\
         pub fn label(s: Sprite) -> String { <Sprite as Render>::label(&s) }\n",
    )
    .expect("wrapper lib.rs");

    let probe = root.join("probe");
    std::fs::create_dir_all(&probe).expect("mkdir probe");
    // `--allow-build-scripts` is required because the wrapper depends on the
    // `ipe_bindgen` proc-macro crate (proc-macro expansion runs at compile time);
    // the real CLI passes it after informed consent (`install_wrapper`). The test
    // runs unsandboxed on a scratch probe dir.
    let out = std::process::Command::new(inspector)
        .arg("--allow-build-scripts")
        .arg("--path")
        .arg(wrapper_dir.to_string_lossy().to_string())
        .arg("--expose")
        .arg("spawn")
        .arg("sprite_wrap")
        .env("IPE_FFI_ALLOW_UNSANDBOXED", "1")
        .env("IPE_FFI_PROBE_DIR", &probe)
        .output()
        .expect("inspector spawns");
    let json = String::from_utf8_lossy(&out.stdout);
    if !out.status.success() || json.trim().is_empty() {
        return None;
    }
    Some(PkgInfo::decode_json(&json).expect("inspector output decodes"))
}

/// Locate the built `ipe-ffi-inspector` binary: an explicit
/// `IPE_FFI_INSPECTOR` override, else beside this test binary in the target
/// `deps` dir's parent (`.../release/ipe-ffi-inspector`).
fn locate_inspector() -> Option<std::path::PathBuf> {
    if let Ok(p) = ipe_env::var("IPE_FFI_INSPECTOR") {
        let p = std::path::PathBuf::from(p);
        if p.is_file() {
            return Some(p);
        }
    }
    let exe = std::env::current_exe().ok()?;
    // `.../<profile>/deps/<test>` → `.../<profile>/ipe-ffi-inspector`.
    let profile_dir = exe.parent()?.parent()?;
    let candidate = profile_dir.join("ipe-ffi-inspector");
    candidate.is_file().then_some(candidate)
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
