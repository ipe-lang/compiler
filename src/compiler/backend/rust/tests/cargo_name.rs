#![forbid(unsafe_code)]
//! SEAL: the emitted Cargo project's `[package] name` matches the sanitized
//! project name from `package.ipe`, and the renamed crate actually `cargo build`s.
//!
//! Gated on `IPE_E2E=1` so the default `cargo test` stays fast and offline.

mod seal_e2e;

use ipe_backend::Backend;
use ipe_backend_rust::RustBackend;
use ipe_diagnostics::DResult;
use ipe_intern::Interner;
use ipe_ir::{
    CallPin, Callee, Expr, Func, FuncId, IrType, KernelFn, ModPath, Module, OnFormKind, Program,
};

/// The minimal program: `main = Io.println ""` — a valid Task entry.
fn trivial_program(interner: &mut Interner) -> DResult<Program> {
    let main_mod = interner.intern("Main")?;
    let main_sym = interner.intern("main")?;
    let main_fn = Func {
        id: FuncId::from_raw(0),
        name: main_sym,
        home: ModPath(vec![main_mod]),
        type_params: vec![],
        row_params: vec![],
        params: vec![],
        ret: IrType::Task(Box::new(IrType::Unit)),
        body: Expr::Call {
            callee: Callee::Kernel(KernelFn::IoPrintln),
            args: vec![Expr::Str(String::new())],
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
            entry: Some(FuncId::from_raw(0)),
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
            uses_async_runtime: false,
            uses_debug: false,
            uses_ffi: false,
        }],
    })
}

/// SEAL: `with_project_name` rewrites the emitted `Cargo.toml`'s `[package]
/// name` to the sanitized project name, and the resulting crate successfully
/// `cargo build`s under that name.
///
/// Covers pathological inputs: uppercase, spaces, leading digit.
#[test]
fn sanitized_name_project_cargo_builds() -> DResult<()> {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return Ok(());
    }

    let cases: &[(&str, &str)] = &[
        ("My App", "my-app"),
        ("1game", "app-1game"),
        ("Hello World", "hello-world"),
    ];

    for (raw_name, expected_cargo_name) in cases {
        let mut interner = Interner::new();
        let prog = trivial_program(&mut interner)?;

        let emitted = RustBackend::new(&interner)
            .with_project_name(raw_name)
            .emit(&prog)?;

        // The `[package] name` in the emitted Cargo.toml must match the
        // sanitized form, not the raw package.ipe value.
        assert!(
            emitted
                .cargo_toml
                .contains(&format!("name = \"{expected_cargo_name}\"")),
            "raw name {raw_name:?}: expected Cargo.toml to contain \
             `name = \"{expected_cargo_name}\"`, got:\n{}",
            emitted.cargo_toml,
        );

        // Full build gate: the renamed crate must cargo build without error.
        let runtime = e2e_support::require_runtime().into_path_buf();
        let slot = format!("ipe_cargo_name_seal_{expected_cargo_name}");
        let status = seal_e2e::vendor_and_run(&emitted, &runtime, &slot, "build")?;
        assert!(
            matches!(&status, Ok(s) if s.success()),
            "sanitized name {expected_cargo_name:?} (from {raw_name:?}): \
             emitted crate must cargo build: {status:?}"
        );
    }

    Ok(())
}
