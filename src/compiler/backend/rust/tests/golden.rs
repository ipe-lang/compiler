//! End-to-end byte-equality gate for the Rust backend.
//!
//! Builds the canonical golden IR `Program` by hand (the same program the full
//! pipeline lowers `tests/golden/basics/Main.ipe` into) and asserts that
//! [`RustBackend::emit`] reproduces the golden `main.rs` and `Cargo.toml`
//! byte-for-byte. The golden is the correctness contract.

use std::path::{Path, PathBuf};

use ipe_backend::Backend;
use ipe_backend_rust::{RuntimeDep, RustBackend};
use ipe_diagnostics::{DResult, Diagnostic};
use ipe_intern::Interner;
use ipe_ir::{
    CallPin, Callee, Expr, Func, FuncId, IrType, KernelFn, ModPath, Module, OnFormKind, Program,
};

const GOLDEN_MAIN: &str = include_str!("../../../../../tests/golden/basics/main.rs");
const GOLDEN_CARGO: &str = include_str!("../../../../../tests/golden/basics/Cargo.toml");

/// The placeholder the blessed golden `Cargo.toml` stores in place of the
/// machine-specific dependency-model runtime path. Kept in sync with the CLI
/// test support's `RUNTIME_PATH_PLACEHOLDER`.
const RUNTIME_PATH_PLACEHOLDER: &str = "__IPE_RUNTIME_PATH__";

/// Locate the runtime crate root (`src/runtime/rust`) by walking up from the
/// crate manifest dir — the same in-repo resolution the driver performs. Used
/// to build the [`RuntimeDep`] the dependency-model emit needs.
#[allow(clippy::expect_used)]
fn runtime_crate_root() -> PathBuf {
    let manifest = e2e_support::manifest_dir!();
    let mut here: Option<&Path> = Some(&manifest);
    let found = std::iter::from_fn(|| {
        let dir = here?;
        here = dir.parent();
        Some(dir.join("src").join("runtime").join("rust"))
    })
    .find(|candidate| candidate.join("Cargo.toml").is_file())
    .expect("the ipe-runtime-rust crate root (src/runtime/rust) must resolve for the golden test");
    found
        .canonicalize()
        .expect("runtime crate root canonicalizes")
}

/// Rewrite the dependency-model runtime `path = "<absolute root>"` in an emitted
/// manifest to [`RUNTIME_PATH_PLACEHOLDER`] so the byte-compare against the
/// portable blessed golden is machine-independent. The emit itself keeps the
/// real resolvable path — only the golden text is normalized (SEAL stays
/// honest).
fn normalize_runtime_dep_path(manifest: &str) -> String {
    manifest
        .lines()
        .map(|line| {
            if line.contains("package = \"ipe-runtime-rust\"")
                && let Some(start) = line.find("path = \"")
            {
                let val_start = start + "path = \"".len();
                if let Some(rel_end) = line[val_start..].find('"') {
                    let end = val_start + rel_end;
                    return format!(
                        "{}{}{}",
                        &line[..val_start],
                        RUNTIME_PATH_PLACEHOLDER,
                        &line[end..]
                    );
                }
            }
            line.to_owned()
        })
        .collect::<Vec<_>>()
        .join("\n")
        + if manifest.ends_with('\n') { "\n" } else { "" }
}

/// The dependency-model backend the golden emit now exercises (the default
/// native emit shape).
fn dep_backend(interner: &Interner) -> RustBackend<'_> {
    RustBackend::new(interner).with_runtime_dep(Some(RuntimeDep {
        root: runtime_crate_root(),
    }))
}

/// Build the golden program:
/// ```ipe
/// main = System.setenv "HOME" "x"
/// ```
/// The `Msg` enum and `update` function `basics/Main.ipe` also declares are
/// unreachable from `main`, so dead-code elimination drops them — the lowered
/// program the full pipeline produces (and this hand-built mirror) carries only
/// the live `main`.
#[allow(clippy::too_many_lines)]
fn build_m0(interner: &mut Interner) -> DResult<Program> {
    let main_mod = interner.intern("Main")?;
    let main = interner.intern("main")?;

    let main_id = FuncId::from_raw(0);

    let main_fn = Func {
        id: main_id,
        name: main,
        home: ModPath(vec![]),
        type_params: vec![],
        row_params: vec![],
        params: vec![],
        ret: IrType::Task(Box::new(IrType::Unit)),
        body: Expr::Call {
            callee: Callee::Kernel(KernelFn::SystemSetenv),
            args: vec![Expr::Str("HOME".to_string()), Expr::Str("x".to_string())],
            pin: CallPin::None,
            on_form: OnFormKind::NotForm,
        },
    };

    Ok(Program {
        imports_unsafe_submodule: false,
        imported_web_capabilities: std::collections::BTreeSet::new(),
        modules: vec![Module {
            name: ModPath(vec![main_mod]),
            types: vec![],
            funcs: vec![main_fn],
            entry: Some(main_id),
            records: vec![],
            uses_tea: false,
            uses_server: false,
            uses_http: false,
            uses_config: false,
            uses_compression: false,
            uses_csv: false,
            uses_cache: false,
            uses_encoding: false,
            uses_regex: false,
            uses_uuid: false,
            uses_random: false,
            uses_log: false,
            uses_decimal: false,
            uses_char_category: false,
            uses_crypto_core: false,
            uses_secret: false,
            uses_json: false,
            uses_crypto: false,
            uses_jwt: false,
            uses_url: false,
            uses_ui: false,
            uses_web: false,
            uses_tui: false,
            uses_console: false,
            uses_webview: false,
            uses_css: false,
            uses_auth: false,
            uses_principal: false,
            uses_websocket: false,
            uses_email: false,
            uses_locale: false,
            uses_time: false,
            uses_env_public: false,
            uses_debug: false,
            uses_ffi: false,
            uses_async_runtime: false,
        }],
    })
}

fn missing(detail: &str) -> Diagnostic {
    Diagnostic::CompilerBug {
        where_: "golden test",
        detail: detail.to_owned(),
    }
}

#[test]
fn m0_emits_byte_identical_main_rs() -> DResult<()> {
    let mut interner = Interner::new();
    let program = build_m0(&mut interner)?;

    let backend = dep_backend(&interner);
    let emitted = backend.emit(&program)?;

    let main_rs = emitted
        .files
        .get("src/main.rs")
        .ok_or_else(|| missing("no src/main.rs"))?;
    assert_eq!(
        main_rs.as_str(),
        GOLDEN_MAIN,
        "src/main.rs must match the golden byte-for-byte"
    );
    Ok(())
}

#[test]
fn m0_emits_byte_identical_cargo_toml() -> DResult<()> {
    let mut interner = Interner::new();
    let program = build_m0(&mut interner)?;

    let backend = dep_backend(&interner);
    let emitted = backend.emit(&program)?;

    assert_eq!(
        normalize_runtime_dep_path(&emitted.cargo_toml),
        GOLDEN_CARGO,
        "Cargo.toml must match the golden (runtime path normalized to the placeholder)"
    );
    Ok(())
}

#[test]
fn m0_backend_name_is_rust() {
    let interner = Interner::new();
    let backend = RustBackend::new(&interner);
    assert_eq!(backend.name(), "rust");
}

/// A program with no user types and no user functions in `main.rs`. Exercises
/// the emitter's empty-section branches: the USER-TYPES banner is followed
/// directly by the runtime bindings, and the bindings are followed directly by
/// the epilogue, each separated by exactly one blank line.
fn build_no_user_items(interner: &mut Interner) -> DResult<Program> {
    let main_mod = interner.intern("Main")?;
    let main = interner.intern("main")?;
    let main_id = FuncId::from_raw(0);

    // `main = Io.println "hi"` — no user types, and the single `main` function's
    // body is a kernel call, so no user-defined helper functions are emitted.
    let main_fn = Func {
        id: main_id,
        name: main,
        home: ModPath(vec![]),
        type_params: vec![],
        row_params: vec![],
        params: vec![],
        ret: IrType::Task(Box::new(IrType::Unit)),
        body: Expr::Call {
            callee: Callee::Kernel(KernelFn::IoPrintln),
            args: vec![Expr::Str("hi".to_owned())],
            pin: CallPin::None,
            on_form: OnFormKind::NotForm,
        },
    };

    Ok(Program {
        imports_unsafe_submodule: false,
        imported_web_capabilities: std::collections::BTreeSet::new(),
        modules: vec![Module {
            name: ModPath(vec![main_mod]),
            types: vec![],
            funcs: vec![main_fn],
            entry: Some(main_id),
            records: vec![],
            uses_tea: false,
            uses_server: false,
            uses_http: false,
            uses_config: false,
            uses_compression: false,
            uses_csv: false,
            uses_cache: false,
            uses_encoding: false,
            uses_regex: false,
            uses_uuid: false,
            uses_random: false,
            uses_log: false,
            uses_decimal: false,
            uses_char_category: false,
            uses_crypto_core: false,
            uses_secret: false,
            uses_json: false,
            uses_crypto: false,
            uses_jwt: false,
            uses_url: false,
            uses_ui: false,
            uses_web: false,
            uses_tui: false,
            uses_console: false,
            uses_webview: false,
            uses_css: false,
            uses_auth: false,
            uses_principal: false,
            uses_websocket: false,
            uses_email: false,
            uses_locale: false,
            uses_time: false,
            uses_env_public: false,
            uses_debug: false,
            uses_ffi: false,
            uses_async_runtime: false,
        }],
    })
}

/// The emitter never produces two consecutive blank lines, so its raw
/// (pre-rustfmt) output already satisfies rustfmt's max-one-consecutive-blank
/// rule. This pins the empty-section blank-line guards: without them, a program
/// with no user types (banner immediately followed by the runtime bindings) or
/// no `main.rs` functions (bindings immediately followed by the epilogue)
/// emitted a double blank that only the rustfmt pass papered over — a silent
/// drift from `cargo fmt --check`-clean the moment the pass is skipped (the
/// `ipe watch` hot loop, and the whole `wasm32` playground, which cannot spawn
/// rustfmt).
///
/// Uses [`RustBackend::emit_spine`], which returns the raw pre-rustfmt spine
/// text directly (no environment toggle, so no cross-test formatting race). The
/// spine carries no user functions, exercising the bindings-to-epilogue guard;
/// `build_m0` (user types present) and `build_no_user_items` (types absent)
/// exercise the banner-to-bindings guard on both branches.
#[test]
fn emitter_spine_has_no_consecutive_blank_lines() -> DResult<()> {
    for build in [
        build_m0 as fn(&mut Interner) -> DResult<Program>,
        build_no_user_items,
    ] {
        let mut interner = Interner::new();
        let program = build(&mut interner)?;
        let backend = RustBackend::new(&interner);
        let spine = backend.emit_spine(&program)?;
        assert!(
            !spine.contains("\n\n\n"),
            "raw emitter output must not contain two consecutive blank lines \
             (rustfmt collapses them, so this drifts from fmt-clean whenever the \
             fmt pass is skipped):\n{spine}"
        );
    }
    Ok(())
}
