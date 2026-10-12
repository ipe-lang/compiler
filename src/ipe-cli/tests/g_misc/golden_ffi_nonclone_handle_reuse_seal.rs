//! Regression — THE SEAL for a NON-`Clone` FFI opaque handle used non-linearly.
//!
//! A shim-free FFI binding maps an Ipe opaque type onto the REAL foreign Rust
//! type. When that type is not `Clone` (e.g. `bevy_ecs::World`), reusing the
//! same handle binding twice in a value-consuming position cannot be lowered as
//! `handle.clone()` — the emitted crate would fail `cargo build` (E0599) AFTER
//! `ipe dev build` already reported exit 0. That exit-0-then-cargo-fail hole is the
//! exact SEAL break `PRINCIPLES.md` forbids.
//!
//! The lowerer now classifies a `Rust.*`-homed opaque `Enum` as non-`Clone` and
//! fails closed on its non-linear reuse with IPE-L0130, so `ipe dev build` can never
//! exit 0 with uncompilable Rust for this shape.
//!
//! ```text
//! cargo test -p ipe --test golden_ffi_nonclone_handle_reuse_seal
//! ```

use std::fs;
use std::path::{Path, PathBuf};

use ipe_ffi::driver::{FfiCache, install_from_inspection};

use crate::support;

/// Seed the project's FFI cache with a hand-crafted inspection document for a
/// non-`Clone` foreign crate published as `handle-demo` (its Rust extern ident
/// is the dash-normalised `handle_demo`): an opaque `Widget` handle, a `new`
/// constructor, and a `&self` reader `slot_count(&self) -> usize` (binds as
/// `Widget -> Result Error Int`). The wire `name` is the verbatim package name
/// `handle-demo`, so the emitted Cargo dependency KEY is `handle-demo` while the
/// generated code imports `::handle_demo::`. Returns false if the cache could
/// not be written.
fn seed_nonclone_ffi_cache(project_root: &Path) -> bool {
    let cache = FfiCache::at_project_root(project_root);
    // Mirrors the inspector wire shape (see `ipe_ffi` bindings fixtures): a
    // static `new` returning the opaque type, and a `&self` non-`Self`-returning
    // reader. The `rustType` `&handle_demo::Widget` receiver marks the method as
    // by-borrow; the wrapper today takes the handle by value.
    let doc = serde_json::json!({
        "pkg": "handle_demo",
        "name": "handle-demo",
        "version": "0.1.0",
        "functions": [
            {
                "name": "new",
                "params": [],
                "results": [{"name": "", "type": "Widget", "ipeType": "Widget", "rustType": "handle_demo::Widget"}],
                "effect": "pure",
                "recvType": "Widget",
                "recvRustType": "handle_demo::Widget",
                "methodName": "new"
            },
            {
                "name": "slot_count",
                "params": [
                    {"name": "self", "type": "Widget", "ipeType": "Widget", "rustType": "&handle_demo::Widget"}
                ],
                "results": [{"name": "", "type": "Int", "rustType": "usize"}],
                "effect": "pure",
                "recvType": "Widget",
                "recvRustType": "handle_demo::Widget",
                "methodName": "slot_count"
            }
        ],
        "errors": []
    });
    install_from_inspection(&cache, &doc.to_string()).is_ok()
}

/// Write `main` as `src/Main.ipe` under a fresh `dir` whose FFI cache is seeded
/// with the non-`Clone` `handle-demo` crate. Returns false on any I/O failure.
pub fn write_project(dir: &Path, main: &str) -> bool {
    let src = dir.join("src");
    let _ = fs::remove_dir_all(dir);
    if fs::create_dir_all(&src).is_err() {
        return false;
    }
    if !seed_nonclone_ffi_cache(dir) {
        return false;
    }
    fs::write(src.join("Main.ipe"), main).is_ok()
}

/// FAIL-CLOSED BACKSTOP: the `w` handle (a non-`Clone` `Rust.Handle_demo.Widget`)
/// is read by TWO calls that each consume the ORIGINAL binding — ignoring the
/// receiver each reader threads back. That is still a non-linear use, so the
/// lowerer must reject it with IPE-L0130 instead of emitting a `.clone()` the
/// foreign type does not support.
#[test]
#[allow(clippy::panic)] // a refused precondition is the test failure
fn nonclone_handle_reused_fails_closed_before_cargo() {
    let runtime = e2e_support::require_runtime().into_path_buf();

    let tmp = crate::support::scratch_root().join("ipec_ffi_nonclone_handle_reuse");
    // `w` is bound once, then read by TWO `slot_count` calls that both discard
    // the threaded-back receiver and re-use the ORIGINAL `w` — a non-linear use
    // of a non-`Clone` foreign handle. `slot_count` now binds as
    // `Widget -> Result Error (Int, Widget)`; each read drops its `.second`.
    let wrote = write_project(
        &tmp,
        "module Main exposing (main)\n\
         import Ipe.Io as Io\n\
         import Ipe.Result as Result\n\
         import Ipe.String as String\n\
         import Rust.Handle_demo as H\n\n\
         readTwice : H.Widget -> Result Error Int\n\
         readTwice w =\n\
         \x20   let\n\
         \x20       a = Result.map (\\( n, _ ) -> n) (H.slot_count_from_widget w)\n\
         \x20       b = Result.map (\\( n, _ ) -> n) (H.slot_count_from_widget w)\n\
         \x20   in\n\
         \x20       Result.map2 (\\x y -> x + y) a b\n\n\
         main =\n\
         \x20   case Result.andThen readTwice (H.new_from_widget ()) of\n\
         \x20       Ok n -> Io.println (String.fromInt n)\n\
         \x20       Err _ -> Io.println \"err\"\n",
    );
    assert!(
        wrote,
        "must write the fixture project + FFI cache to a temp dir"
    );

    let entry = tmp.join("src").join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ffi_nonclone_handle_reuse_out");
    let _ = fs::remove_dir_all(&out);

    let built = ipe::build_loose_file(&entry, &out, &runtime);
    let Err(err) = built else {
        panic!(
            "expected IPE-L0130 rejection for reusing a non-`Clone` FFI handle, \
             but ipe dev build SUCCEEDED — an exit-0-then-cargo-fail SEAL hole"
        )
    };
    let ipe::CliError::Pipeline { diag, .. } = &err else {
        panic!("expected a Pipeline diagnostic, got: {err}")
    };
    let code = diag.code();
    assert_eq!(
        code.as_str(),
        "IPE-L0130",
        "reusing a non-`Clone` FFI handle must fail closed with IPE-L0130, got {code:?}: {err}"
    );
}

/// ERGONOMIC PATH: a by-borrow reader threads its receiver back, so the handle
/// flows on linearly with NO clone and NO IPE-L0130 gate. Destructuring the
/// `(Int, Widget)` result and feeding the returned handle to the next call
/// must both ipe-accept AND the emitted crate must `cargo build` (THE SEAL).
/// Routed through `support::assert_seal_builds` so the cargo build step runs
/// under `IPE_E2E=1`.
#[test]
#[allow(clippy::panic)] // a refused precondition is the test failure
fn nonclone_handle_threaded_linearly_builds() {
    let runtime = e2e_support::require_runtime().into_path_buf();

    let tmp = crate::support::scratch_root().join("ipec_ffi_nonclone_handle_thread");
    // Each read consumes the world and hands the RETURNED handle to the next —
    // one linear chain, so the non-`Clone` handle never needs a clone.
    let wrote = write_project(
        &tmp,
        "module Main exposing (main)\n\
         import Ipe.Io as Io\n\
         import Ipe.Result as Result\n\
         import Ipe.String as String\n\
         import Rust.Handle_demo as H\n\n\
         readTwice : H.Widget -> Result Error Int\n\
         readTwice w =\n\
         \x20   H.slot_count_from_widget w\n\
         \x20       |> Result.andThen\n\
         \x20           (\\( count, w1 ) ->\n\
         \x20               H.slot_count_from_widget w1\n\
         \x20                   |> Result.map (\\( more, _ ) -> count + more)\n\
         \x20           )\n\n\
         main =\n\
         \x20   case Result.andThen readTwice (H.new_from_widget ()) of\n\
         \x20       Ok n -> Io.println (String.fromInt n)\n\
         \x20       Err _ -> Io.println \"err\"\n",
    );
    assert!(
        wrote,
        "must write the fixture project + FFI cache to a temp dir"
    );

    let entry = tmp.join("src").join("Main.ipe");
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ffi_nonclone_handle_thread_out");
    let _ = fs::remove_dir_all(&out);

    match ipe::build_loose_file(&entry, &out, &runtime) {
        Ok(()) => {}
        Err(err) => {
            panic!("linear borrow-threaded handle use must ipe-accept, got: {err}")
        }
    }

    provision_handle_demo(&tmp, &out);

    support::assert_seal_builds("ffi_nonclone_handle_thread", &out);
}

/// Under `IPE_E2E`, write the `handle_demo` fixture crate beside `project` and
/// repoint the emitted manifest in `out` at it.
///
/// The emitted `Cargo.toml` carries `handle-demo = "=0.1.0"` (an exact
/// `crates.io` pin), which fails offline and in CI shards where the crate is
/// not published; the local path dependency stands in for it.
#[allow(clippy::expect_used)] // fixture-setup failure must fail the seal test loudly
pub fn provision_handle_demo(project: &Path, out: &Path) {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let handle_demo_dir = project.join("handle_demo");
    let handle_demo_src = handle_demo_dir.join("src");
    fs::create_dir_all(&handle_demo_src).expect("create handle_demo fixture crate directory");
    fs::write(
        handle_demo_dir.join("Cargo.toml"),
        "[package]\nname = \"handle-demo\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .expect("write handle_demo Cargo.toml");
    fs::write(
        handle_demo_src.join("lib.rs"),
        "pub struct Widget { slots: usize }\n\
         impl Widget {\n\
         \x20   pub fn new() -> Self { Widget { slots: 3 } }\n\
         \x20   pub fn slot_count(&self) -> usize { self.slots }\n\
         }\n",
    )
    .expect("write handle_demo src/lib.rs");

    let manifest_path = out.join("Cargo.toml");
    let manifest = fs::read_to_string(&manifest_path)
        .expect("read emitted Cargo.toml for handle_demo path-dep repoint");
    assert!(
        manifest.contains("handle-demo"),
        "emitted manifest must declare the handle-demo dependency; got:\n{manifest}"
    );
    let patched = manifest.replace(
        "handle-demo = \"=0.1.0\"",
        &format!(
            "handle-demo = {{ path = {:?} }}",
            handle_demo_dir.display().to_string()
        ),
    );
    fs::write(&manifest_path, patched).expect("write patched Cargo.toml with handle_demo path dep");
}
