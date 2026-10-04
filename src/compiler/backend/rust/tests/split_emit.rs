//! The `emit_spine` / `emit_module_file` rendering entry points, tested in
//! isolation.
//!
//! These two functions are ADDITIVE — nothing in the public emission path
//! (`RustBackend::emit` → `project::emit_program`) calls them yet. This binary
//! proves they exist, are individually callable, and
//! route items to the two output tiers the design doc §2.1/§2.2 mandates:
//!
//! * `emit_spine` → preamble banner + kernel-wrapper prelude + `fn main()` +
//!   record structs + (for a Db-using program) the `SqlValue`/`SqlField` enum
//!   declarations immediately before the record structs — but NEITHER
//!   module's own `Func`/`EnumDef`.
//! * `emit_module_file(program, &home)` → ONLY that home's `EnumDef`s +
//!   `Func`s, each `pub(crate)`-prefixed, opening with `use crate::*;`.
//!
//! The hand-built `Program`s mirror `tests/golden.rs`'s `build_m0` shape,
//! extended with a second `home` (and, for the Db fixture, the two synthetic
//! `SqlValue`/`SqlField` Prelude built-ins the lowerer injects, carrying the
//! empty canonical home — see design doc §2.2).

use ipe_backend::Backend;
use ipe_backend_rust::RustBackend;
use ipe_diagnostics::DResult;
use ipe_intern::Interner;
use ipe_ir::{EnumDef, Expr, Func, FuncId, IrType, ModPath, Module, Program, TypeDef, Variant};

/// A no-op module with every `uses_*` flag `false` and no items — callers
/// override `types`/`funcs` as needed.
const fn empty_module(name: ModPath) -> Module {
    Module {
        name,
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
    }
}

/// A nullary-variant enum owned by `home`.
fn enum_def(name: ipe_intern::Symbol, variant: ipe_intern::Symbol, home: ModPath) -> EnumDef {
    EnumDef {
        name,
        home,
        type_params: vec![],
        variants: vec![Variant {
            name: variant,
            fields: vec![],
        }],
    }
}

/// A zero-param `-> Int` function returning `0`, owned by `home`.
const fn int_func(id: u32, name: ipe_intern::Symbol, home: ModPath) -> Func {
    Func {
        id: FuncId::from_raw(id),
        name,
        home,
        type_params: vec![],
        row_params: vec![],
        params: vec![],
        ret: IrType::Int,
        body: Expr::Int(0),
    }
}

/// Two-module program: `Lib` owns `Color`/`libHelper`, `Main` owns
/// `Msg`/`main`. No Db usage — `uses_db` is false.
fn build_two_module(interner: &mut Interner) -> DResult<(Program, ModPath, ModPath)> {
    let lib_mod = interner.intern("Lib")?;
    let main_mod = interner.intern("Main")?;
    let color = interner.intern("Color")?;
    let red = interner.intern("Red")?;
    let msg = interner.intern("Msg")?;
    let increment = interner.intern("Increment")?;
    let lib_helper = interner.intern("libHelper")?;
    let main_fn = interner.intern("main")?;

    let lib_home = ModPath(vec![lib_mod]);
    let main_home = ModPath(vec![main_mod]);

    let mut module = empty_module(main_home.clone());
    module.types = vec![
        TypeDef::Enum(enum_def(color, red, lib_home.clone())),
        TypeDef::Enum(enum_def(msg, increment, main_home.clone())),
    ];
    module.funcs = vec![
        int_func(0, lib_helper, lib_home.clone()),
        int_func(1, main_fn, main_home.clone()),
    ];

    Ok((
        Program {
            imports_unsafe_submodule: false,
            imported_web_capabilities: std::collections::BTreeSet::new(),
            modules: vec![module],
        },
        lib_home,
        main_home,
    ))
}

/// Two-module program AS ABOVE, plus the two synthetic `SqlValue`/`SqlField`
/// Prelude built-ins (empty canonical home) the lowerer injects for a
/// Db-using program. Their presence makes the backend's `uses_db` scan fire.
fn build_two_module_db(interner: &mut Interner) -> DResult<(Program, ModPath, ModPath)> {
    let lib_mod = interner.intern("Lib")?;
    let main_mod = interner.intern("Main")?;
    let color = interner.intern("Color")?;
    let red = interner.intern("Red")?;
    let msg = interner.intern("Msg")?;
    let increment = interner.intern("Increment")?;
    let lib_helper = interner.intern("libHelper")?;
    let main_fn = interner.intern("main")?;
    let sqlvalue = interner.intern("SqlValue")?;
    let sqlfield = interner.intern("SqlField")?;
    let sql_string = interner.intern("SqlString")?;
    let set_field = interner.intern("SetField")?;

    let lib_home = ModPath(vec![lib_mod]);
    let main_home = ModPath(vec![main_mod]);
    let empty_home = ModPath(vec![]);

    let mut module = empty_module(main_home.clone());
    // The `uses_db` scan keys off the presence of the SqlValue/SqlField enums.
    module.types = vec![
        TypeDef::Enum(enum_def(color, red, lib_home.clone())),
        TypeDef::Enum(enum_def(msg, increment, main_home.clone())),
        TypeDef::Enum(enum_def(sqlvalue, sql_string, empty_home.clone())),
        TypeDef::Enum(enum_def(sqlfield, set_field, empty_home)),
    ];
    module.funcs = vec![
        int_func(0, lib_helper, lib_home.clone()),
        int_func(1, main_fn, main_home.clone()),
    ];

    Ok((
        Program {
            imports_unsafe_submodule: false,
            imported_web_capabilities: std::collections::BTreeSet::new(),
            modules: vec![module],
        },
        lib_home,
        main_home,
    ))
}

#[test]
fn emit_spine_holds_program_wide_content_not_module_items() -> DResult<()> {
    let mut interner = Interner::new();
    let (program, _lib_home, _main_home) = build_two_module(&mut interner)?;
    let backend = RustBackend::new(&interner);

    let spine = backend.emit_spine(&program)?;

    // Program-wide content is present.
    assert!(
        spine.contains("fn main()"),
        "spine must carry the entry point `fn main()`"
    );
    assert!(
        spine.contains("pub use ipe_runtime::error::IpeError;"),
        "spine must carry the fixed kernel-wrapper prelude"
    );

    // Neither module's OWN items appear in the spine.
    assert!(
        !spine.contains("enum LibColor"),
        "Lib's enum must NOT be in the spine"
    );
    assert!(
        !spine.contains("enum MainMsg"),
        "Main's enum must NOT be in the spine"
    );
    assert!(
        !spine.contains("lib_lib_helper") && !spine.contains("fn main_main"),
        "neither module's user funcs may be in the spine"
    );
    Ok(())
}

#[test]
fn emit_module_file_holds_only_that_homes_items_pub_crate_and_barrel() -> DResult<()> {
    let mut interner = Interner::new();
    let (program, lib_home, main_home) = build_two_module(&mut interner)?;
    let backend = RustBackend::new(&interner);

    let lib_file = backend.emit_module_file(&program, &lib_home)?;

    // Opens with the flat-barrel glob import (design doc §2.1).
    assert!(
        lib_file.trim_start().starts_with("use crate::*;"),
        "module file must open with `use crate::*;`, got:\n{lib_file}"
    );
    // Lib's OWN items, pub(crate)-prefixed.
    assert!(
        lib_file.contains("pub(crate) enum LibColor"),
        "Lib's enum must be present, pub(crate)-prefixed, got:\n{lib_file}"
    );
    assert!(
        lib_file.contains("pub(crate) fn lib_lib_helper"),
        "Lib's func must be present, pub(crate)-prefixed, got:\n{lib_file}"
    );
    // NO bare `pub ` item declarations leak through (only `pub(crate)`).
    assert!(
        !lib_file.contains("pub enum ") && !lib_file.contains("pub fn "),
        "module-file items must be pub(crate), never bare pub, got:\n{lib_file}"
    );
    // Main's items must NOT appear in Lib's file.
    assert!(
        !lib_file.contains("MainMsg") && !lib_file.contains("main_main"),
        "Lib's file must contain ONLY Lib's items, got:\n{lib_file}"
    );

    // And the reciprocal for Main's file.
    let main_file = backend.emit_module_file(&program, &main_home)?;
    assert!(
        main_file.contains("pub(crate) enum MainMsg"),
        "Main's enum must be present in Main's file, got:\n{main_file}"
    );
    assert!(
        !main_file.contains("LibColor"),
        "Main's file must NOT contain Lib's enum, got:\n{main_file}"
    );
    Ok(())
}

#[test]
fn emit_spine_carries_sqlvalue_sqlfield_before_record_structs_for_db() -> DResult<()> {
    let mut interner = Interner::new();
    let (program, lib_home, _main_home) = build_two_module_db(&mut interner)?;
    let backend = RustBackend::new(&interner);

    let spine = backend.emit_spine(&program)?;

    // The synthetic Db enums route to Spine (design doc §2.2 fix).
    let sqlvalue_pos = spine
        .find("enum MainSqlValue")
        .expect("SqlValue enum must be declared in the spine");
    let sqlfield_pos = spine
        .find("enum MainSqlField")
        .expect("SqlField enum must be declared in the spine");
    assert!(
        sqlvalue_pos < sqlfield_pos,
        "SqlValue must be declared before SqlField (insertion order)"
    );

    // They must NOT appear in either module file (they belong to Spine only).
    let lib_file = backend.emit_module_file(&program, &lib_home)?;
    assert!(
        !lib_file.contains("SqlValue") && !lib_file.contains("SqlField"),
        "the Db enums must never land in a IpeModule file, got:\n{lib_file}"
    );
    Ok(())
}

/// A split program that only NAMES a `db`-gated type (a `Dsn` parameter, no Db
/// kernel, so no injected `SqlValue` / `SqlField`) turns `uses_db` on through
/// the type-closure fold. The spine must still emit, with no projection impls:
/// both emit paths share the one injected-enum gate, so the split path cannot
/// reach for an enum that was never injected.
#[test]
fn emit_spine_of_a_program_naming_only_a_db_type_has_no_projection() -> DResult<()> {
    let mut interner = Interner::new();
    let (mut program, lib_home, _main_home) = build_two_module(&mut interner)?;
    let dsn_param = interner.intern("dsn")?;
    let takes_dsn = interner.intern("takesDsn")?;
    let mut func = int_func(2, takes_dsn, lib_home);
    func.params = vec![(dsn_param, IrType::Dsn)];
    program
        .modules
        .first_mut()
        .expect("build_two_module returns one module")
        .funcs
        .push(func);
    let backend = RustBackend::new(&interner);

    let spine = backend.emit_spine(&program)?;
    assert!(
        !spine.contains("into_sql_param"),
        "no SqlValue was injected, so no projection impl may be emitted, got:\n{spine}"
    );
    backend.emit(&program)?;
    Ok(())
}
