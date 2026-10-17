//! M7 gate: hydration-state field-type gate (spec:
//! `docs/adr/0005-delivery-shapes-runtimes-hosts-targets.md` §M7 field-type gate).
//!
//! When `wasm_hydrate_mode = true` (set by `[wasm] mode = "hydrate"` in
//! `package.ipe`), the backend inspects the island parse-target type — the
//! `fromHydrationState` projection's parameter type, whatever the user named it
//! — and rejects any field whose `IrType` is non-serialisable (server-surface
//! handles, async primitives, function types, etc.). Keying on the projection
//! parameter (not a literal `HydrationState` name) is what makes the gate catch
//! a leak in a program that names its island type differently.
//!
//! Gate properties proven here:
//!   * A projection target with a `Secret` field → compile error (the
//!     canonical containment predicate from the spec).
//!   * A projection target with all-primitive fields → compiles clean.
//!   * A projection target NAMED something other than `HydrationState` but with
//!     a `Secret` field is STILL rejected (the gate keys on the real target,
//!     not the literal type name).
//!   * A program with NO `fromHydrationState` projection passes the gate (no
//!     island parse target ⇒ nothing serialised ⇒ nothing to leak).
//!   * The gate is a no-op when `wasm_hydrate_mode = false` — the same
//!     `Secret`-fielded target compiles cleanly in non-hydrate native mode.
//!   * The emitted `hydrate` glue references the SAME Rust type its
//!     `main_from_hydration_state` signature names — the structural `RecCount`
//!     record-alias struct, never the nonexistent `MainHydrationState`
//!     convention name (issue #224). The compile-level SEAL (the emitted crate
//!     actually `cargo check`s for wasm) lives in `ipe-cli`'s
//!     `wasm_target_gate` integration test.
//!   * A hydrate-mode program with no `fromHydrationState` projection emits no
//!     `hydrate` glue (no island type to name).

use ipe_backend_rust::RustBackend;
use ipe_diagnostics::DResult;
use ipe_intern::Interner;
use ipe_ir::{EnumDef, Expr, Func, FuncId, IrType, ModPath, Module, Program, TypeDef, Variant};
use std::collections::{BTreeMap, BTreeSet};

// ── helpers ──────────────────────────────────────────────────────────────────

/// Build a minimal wasm-hydrate-mode `Program` whose `Main` module declares an
/// island type named `type_name` (a single-ctor alias) carrying `fields`, AND a
/// `fromHydrationState` projection that takes that type — so the emitted
/// `hydrate` export actually serialises it. This is the real leak path the gate
/// guards: the gate walks the PROJECTION TARGET's fields, whatever it is named.
fn hydrate_program_named(
    interner: &mut Interner,
    type_name: &str,
    fields: Vec<IrType>,
) -> DResult<Program> {
    let main = interner.intern("Main")?;
    let hs_name = interner.intern(type_name)?;
    let hs_def = EnumDef {
        name: hs_name,
        home: ModPath(vec![main]),
        type_params: vec![],
        variants: vec![Variant {
            name: hs_name,
            fields,
        }],
    };
    let hs_ty = IrType::Enum {
        home: ModPath(vec![main]),
        name: hs_name,
        args: vec![],
    };
    let from_hs = interner.intern("fromHydrationState")?;
    let hs_param = interner.intern("hs")?;
    let from_hs_fn = Func {
        id: FuncId::from_raw(1),
        name: from_hs,
        home: ModPath(vec![main]),
        type_params: vec![],
        row_params: vec![],
        params: vec![(hs_param, hs_ty)],
        ret: IrType::Int,
        body: Expr::Var(hs_param),
    };
    Ok(Program {
        imports_unsafe_submodule: false,
        imported_web_capabilities: std::collections::BTreeSet::new(),
        modules: vec![Module {
            name: ModPath(vec![main]),
            types: vec![TypeDef::Enum(hs_def)],
            funcs: vec![from_hs_fn],
            entry: None,
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

/// Convenience: an island type named `HydrationState` carrying `fields`, with
/// the `fromHydrationState` projection over it.
fn hydrate_program(interner: &mut Interner, fields: Vec<IrType>) -> DResult<Program> {
    hydrate_program_named(interner, "HydrationState", fields)
}

/// Build the wasm-hydrate-mode `RustBackend`.
const fn hydrate_backend(interner: &Interner) -> RustBackend<'_> {
    RustBackend::new(interner)
        .with_target(ipe_ir::Target::WasmClient)
        .with_wasm_hydrate_mode(true)
}

// ── gate tests ────────────────────────────────────────────────────────────────

/// A `HydrationState` whose sole field is `IrType::Secret` must produce a
/// compile error — `Secret` is the spec's canonical "non-serialisable" example.
#[test]
fn hydration_state_secret_field_is_compile_error() -> DResult<()> {
    let mut interner = Interner::new();
    let prog = hydrate_program(&mut interner, vec![IrType::Secret])?;
    let err = hydrate_backend(&interner)
        .emit_spine(&prog)
        .expect_err("Secret-fielded HydrationState must be rejected");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("non-serialisable") || msg.contains("HydrationState"),
        "error should mention non-serialisable or HydrationState: {msg}"
    );
    Ok(())
}

/// A `HydrationState` with a `Db` field must also be rejected.
#[test]
fn hydration_state_db_field_is_compile_error() -> DResult<()> {
    let mut interner = Interner::new();
    let prog = hydrate_program(&mut interner, vec![IrType::Db])?;
    let err = hydrate_backend(&interner)
        .emit_spine(&prog)
        .expect_err("Db-fielded HydrationState must be rejected");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("non-serialisable") || msg.contains("HydrationState"),
        "error should mention non-serialisable or HydrationState: {msg}"
    );
    Ok(())
}

/// A projection target with only `Int` and `String` fields compiles cleanly.
#[test]
fn hydration_state_primitive_fields_compile_clean() -> DResult<()> {
    let mut interner = Interner::new();
    let prog = hydrate_program(&mut interner, vec![IrType::Int, IrType::Str])?;
    hydrate_backend(&interner).emit_spine(&prog).map(|_| ())
}

/// The gate keys on the real parse target, NOT a literal `HydrationState` name:
/// a projection whose target is named `AppState` (anything but `HydrationState`)
/// but carries a `Secret` field is STILL rejected. Under a literal-name lookup
/// this leak would slip through the gate and reach the emitted `hydrate` export
/// (a secret-leak / SEAL break); driving the gate off the projection parameter
/// closes it regardless of the type's name.
#[test]
fn aliased_target_name_with_secret_field_is_still_rejected() -> DResult<()> {
    let mut interner = Interner::new();
    let prog = hydrate_program_named(&mut interner, "AppState", vec![IrType::Secret])?;
    let err = hydrate_backend(&interner)
        .emit_spine(&prog)
        .expect_err("a Secret-fielded island target must be rejected whatever its name");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("non-serialisable"),
        "error should flag the non-serialisable field: {msg}"
    );
    Ok(())
}

/// A program with NO `fromHydrationState` projection passes the gate — with no
/// island parse target, nothing is serialised, so there is nothing to leak.
#[test]
fn no_hydration_state_type_passes_gate() -> DResult<()> {
    let mut interner = Interner::new();
    let main = interner.intern("Main")?;
    let prog = Program {
        imports_unsafe_submodule: false,
        imported_web_capabilities: std::collections::BTreeSet::new(),
        modules: vec![Module {
            name: ModPath(vec![main]),
            types: vec![],
            funcs: vec![],
            entry: None,
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
    };
    hydrate_backend(&interner).emit_spine(&prog).map(|_| ())
}

/// The gate is a no-op for native mode: the same `Secret`-fielded
/// `HydrationState` compiles cleanly when `wasm_hydrate_mode = false`.
#[test]
fn gate_is_noop_for_native_mode() -> DResult<()> {
    let mut interner = Interner::new();
    let prog = hydrate_program(&mut interner, vec![IrType::Secret])?;
    // Native mode, no hydrate flag — gate must not fire.
    RustBackend::new(&interner).emit_spine(&prog).map(|_| ())
}

/// Build a wasm-hydrate `Program` whose `Main` module declares a
/// `fromHydrationState : { count : Int } -> { count : Int }` projection — the
/// shape of the `examples/wasm/hydration` example. The `HydrationState` type is
/// a RECORD ALIAS, so the backend synthesises it as a structural `RecCount`
/// struct (NOT `MainHydrationState`) — the exact regression of issue #224.
fn hydrate_program_with_record_projection(interner: &mut Interner) -> DResult<Program> {
    let main = interner.intern("Main")?;
    let count = interner.intern("count")?;
    let hs = interner.intern("hs")?;
    let from_hs = interner.intern("fromHydrationState")?;
    let rec = || IrType::Record(BTreeMap::from([(count, IrType::Int)]));
    let from_hs_fn = Func {
        id: FuncId::from_raw(1),
        name: from_hs,
        home: ModPath(vec![main]),
        type_params: vec![],
        row_params: vec![],
        params: vec![(hs, rec())],
        ret: rec(),
        // Body is irrelevant to the glue↔type-name contract this test proves;
        // the signature's parameter type is what the glue must agree with.
        body: Expr::Var(hs),
    };
    Ok(Program {
        imports_unsafe_submodule: false,
        imported_web_capabilities: std::collections::BTreeSet::new(),
        modules: vec![Module {
            name: ModPath(vec![main]),
            types: vec![],
            funcs: vec![from_hs_fn],
            entry: None,
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

/// The emitted `hydrate` glue references the SAME Rust type the emitted
/// `main_from_hydration_state` signature names — the structural `RecCount`
/// struct the record-alias emitter produces — never the nonexistent
/// `MainHydrationState` convention name (issue #224). This is the string-level
/// witness of the fix; the compile-level SEAL is
/// `wasm_target_gate::hydrate_glue_type_name_matches_emitted_struct_and_compiles_for_wasm`.
#[test]
fn hydrate_glue_references_the_emitted_record_struct_name() -> DResult<()> {
    let mut interner = Interner::new();
    let prog = hydrate_program_with_record_projection(&mut interner)?;
    let spine = hydrate_backend(&interner).emit_spine(&prog)?;

    assert!(
        spine.contains("pub fn hydrate(model_json: &str)"),
        "hydrate export must be present in wasm_hydrate_mode spine:\n{spine}"
    );
    assert!(
        spine.contains("pub fn ipe_start()"),
        "ipe_start export must still be present:\n{spine}"
    );
    // The record alias `{ count : Int }` is emitted structurally as `RecCount`.
    // The struct is synthesised and the glue names that SAME struct (resolved
    // through the shared `render_type`, not a hardcoded convention name).
    assert!(
        spine.contains("pub struct RecCount"),
        "the `{{ count : Int }}` record alias must be synthesised as `RecCount`:\n{spine}"
    );
    assert!(
        spine.contains("serde_json::from_str::<crate::RecCount>"),
        "the hydrate glue must parse the island JSON as the SAME struct the \
         projection takes (`RecCount`), not the nonexistent `MainHydrationState`:\n{spine}"
    );
    assert!(
        !spine.contains("MainHydrationState"),
        "the glue must not reference the convention type the emitter never \
         produces (issue #224 regression):\n{spine}"
    );
    Ok(())
}

/// A hydrate-mode program with NO `fromHydrationState` projection has no island
/// type to name, so the backend emits only the `ipe_start` entry — never a
/// dangling `hydrate` glue that would reference an absent type. (Parse, don't
/// validate: the glue exists only when its type source exists.)
#[test]
fn no_projection_emits_no_hydrate_glue() -> DResult<()> {
    let mut interner = Interner::new();
    let main = interner.intern("Main")?;
    let prog = Program {
        imports_unsafe_submodule: false,
        imported_web_capabilities: std::collections::BTreeSet::new(),
        modules: vec![Module {
            name: ModPath(vec![main]),
            types: vec![],
            funcs: vec![],
            entry: None,
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
    };
    let spine = hydrate_backend(&interner).emit_spine(&prog)?;
    assert!(
        spine.contains("pub fn ipe_start()"),
        "ipe_start export must still be present:\n{spine}"
    );
    assert!(
        !spine.contains("pub fn hydrate(model_json: &str)"),
        "no `fromHydrationState` projection ⇒ no hydrate glue (it would reference \
         an absent island type):\n{spine}"
    );
    Ok(())
}

/// Build a wasm-hydrate `Program` where `HydrationState` has ONE field whose
/// type is a named user ADT `Inner`, and `Inner`'s variant carries `inner_fields`.
///
/// This exercises the nested-ADT path of the field-safety gate (#2550): a
/// `Secret` buried in `Inner` must be caught even though the outer
/// `HydrationState` field type is `IrType::Enum { Inner }`, not `IrType::Secret`.
fn hydrate_program_with_nested_adt(
    interner: &mut Interner,
    inner_fields: Vec<IrType>,
) -> DResult<Program> {
    let main = interner.intern("Main")?;
    let hs_name = interner.intern("HydrationState")?;
    let inner_name = interner.intern("Inner")?;

    // `type Inner = Inner <inner_fields...>`
    let inner_def = EnumDef {
        name: inner_name,
        home: ModPath(vec![main]),
        type_params: vec![],
        variants: vec![Variant {
            name: inner_name,
            fields: inner_fields,
        }],
    };
    let inner_ty = IrType::Enum {
        home: ModPath(vec![main]),
        name: inner_name,
        args: vec![],
    };

    // `type HydrationState = HydrationState Inner`
    let hs_def = EnumDef {
        name: hs_name,
        home: ModPath(vec![main]),
        type_params: vec![],
        variants: vec![Variant {
            name: hs_name,
            fields: vec![inner_ty],
        }],
    };
    let hs_ty = IrType::Enum {
        home: ModPath(vec![main]),
        name: hs_name,
        args: vec![],
    };

    let from_hs = interner.intern("fromHydrationState")?;
    let hs_param = interner.intern("hs")?;
    let from_hs_fn = Func {
        id: FuncId::from_raw(1),
        name: from_hs,
        home: ModPath(vec![main]),
        type_params: vec![],
        row_params: vec![],
        params: vec![(hs_param, hs_ty)],
        ret: IrType::Int,
        body: Expr::Int(0),
    };

    Ok(Program {
        imports_unsafe_submodule: false,
        imported_web_capabilities: BTreeSet::new(),
        modules: vec![Module {
            name: ModPath(vec![main]),
            types: vec![TypeDef::Enum(inner_def), TypeDef::Enum(hs_def)],
            funcs: vec![from_hs_fn],
            entry: None,
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

/// The gate must fire on the FULL public emission path, not only the isolated
/// `emit_spine` entry the tests above drive. A single-`Main`-module program
/// collapses to `emit_program`'s single-file branch — which renders `main.rs`
/// inline and NEVER calls `emit_spine` — so if the gate lived only in
/// `emit_spine`, a `Secret`-fielded hydration island would sail through
/// `emit()` and leak into the client JSON island. This pins the rejection on
/// `Backend::emit` itself, matching the split path's existing refusal.
#[test]
fn single_module_emit_rejects_secret_hydration_field() -> DResult<()> {
    use ipe_backend::Backend;

    let mut interner = Interner::new();
    let prog = hydrate_program(&mut interner, vec![IrType::Secret])?;
    let err = hydrate_backend(&interner)
        .emit(&prog)
        .expect_err("single-module emit() must reject a Secret-fielded hydration island");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("non-serialisable"),
        "single-module emit() must flag the non-serialisable field: {msg}"
    );
    Ok(())
}

/// The same single-module public-path gate accepts an all-primitive island —
/// proving the `emit()` rejection above is the gate firing on a real leak, not
/// a blanket failure of the single-file branch under hydrate mode.
#[test]
fn single_module_emit_accepts_primitive_hydration_fields() -> DResult<()> {
    use ipe_backend::Backend;

    let mut interner = Interner::new();
    let prog = hydrate_program(&mut interner, vec![IrType::Int, IrType::Str])?;
    hydrate_backend(&interner).emit(&prog).map(|_| ())
}

/// A `Secret` buried in a nested user ADT field must be REJECTED by the gate
/// with a clean IPE diagnostic — not silently reach `cargo` as an opaque E0277.
///
/// Layout: `HydrationState` has one field of type `Inner`; `Inner` carries a
/// `Secret`. The gate must descend into `Inner`'s variant fields and catch the
/// `Secret` at ipe-compile time. (#2550)
#[test]
fn nested_adt_with_secret_field_is_rejected() -> DResult<()> {
    let mut interner = Interner::new();
    let prog = hydrate_program_with_nested_adt(&mut interner, vec![IrType::Secret])?;
    let err = hydrate_backend(&interner)
        .emit_spine(&prog)
        .expect_err("Secret in nested ADT must be rejected by the gate");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("non-serialisable"),
        "gate error must flag the non-serialisable field: {msg}"
    );
    Ok(())
}

/// A nested user ADT whose fields are all serde-safe must NOT be rejected —
/// only non-serde leaves poison the gate. (#2550 positive / no-false-rejection)
#[test]
fn nested_adt_with_serde_only_fields_is_accepted() -> DResult<()> {
    let mut interner = Interner::new();
    // `Inner` carries only `Int` and `Str` — both serde-safe.
    let prog = hydrate_program_with_nested_adt(&mut interner, vec![IrType::Int, IrType::Str])?;
    hydrate_backend(&interner).emit_spine(&prog).map(|_| ())
}
