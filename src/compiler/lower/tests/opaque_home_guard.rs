//! Home-guarded lowering of kernel-implicit opaque type names.
//!
//! Several opaque runtime types are reachable by a BARE constructor name at the
//! annotation level: the shape app-leaves (`WebApp` / `TuiApp` / `CliApp`)
//! minted by `Web.tea` / `Tui.tea` / …, and the `Ipe.Server`
//! nominals (`Request` / `Response` / `Route` / `Cookie`). The genuine kernel
//! type carries the EMPTY home (`ipe_types::constrain` builds every one with
//! `module: Vec::new()`), so the lowerer maps a bare name to its runtime `IrType`
//! ONLY on that empty-home identity.
//!
//! The shape-leaf names are NOT reserved, so a user program may soundly declare
//! `type WebApp = …`. Such a union is keyed in the lowerer's `enum_variants`
//! under its OWN module home. Without a home guard the bare-name arm would sit
//! above the `enum_variants` guard and hijack a signature `f : WebApp -> …` to
//! the opaque runtime leaf — an `ipe`-exit-0 whose emitted Rust `cargo` cannot
//! build (the user constructor `W` has no matching runtime variant), a SEAL
//! break. These tests pin that the USER union wins: its param type lowers to
//! `IrType::Enum` under the user's home, never `IrType::WebApp`.

#![allow(clippy::unwrap_used)] // `.intern().unwrap()` is acceptable in test helpers

use std::collections::BTreeMap;

use ipe_canon::ast as canon;
use ipe_diagnostics::{Located, Span};
use ipe_intern::{Interner, Symbol};
use ipe_ir::{IrType, ModPath};
use ipe_lower::lower;
use ipe_types::{SolvedTypes, Ty};

/// A runtime `false` the optimiser cannot fold, so `assert!(false_marker(), …)`
/// reads as a deliberate unconditional failure — mirrors the compiler crates'
/// own test helper and keeps this file free of the `clippy::panic` deny.
const fn false_marker() -> bool {
    std::hint::black_box(false)
}

/// The opaque runtime `IrType` a bare-name hijack would have produced for `leaf`,
/// or `None` for a name outside the shape-leaf set. A guard regression makes the
/// user-union probe below return exactly this.
fn opaque_leaf_ir(leaf: &str) -> Option<IrType> {
    match leaf {
        "WebApp" => Some(IrType::WebApp),
        "TuiApp" => Some(IrType::TuiApp),
        "CliApp" => Some(IrType::CliApp),
        "StreamWriter" => Some(IrType::StreamWriter),
        "WebSocketServer" => Some(IrType::WebSocketServer),
        "WebSocketServerCfg" => Some(IrType::WebSocketServerCfg),
        _ => None,
    }
}

/// The pieces `lower_leaf_param_ty` needs to call `lower`: the interner that
/// minted every symbol in `module`/`types`, and `tag`'s own symbol so the
/// caller can find its lowered function back among `program.modules`.
struct LeafFixture {
    interner: Interner,
    module: canon::Module,
    types: SolvedTypes,
    tag: Symbol,
}

/// Build (without lowering) a single-module program `tag : <Leaf> -> Int;
/// tag x = 0`. The leaf-type annotation Con carries `home` (empty for the
/// genuine kernel leaf, `["Main"]` for a user union); `declare_union` seeds the
/// matching `type <Leaf> = W` when the home is the user module, exactly as a
/// real `.ipe` file would.
fn build_leaf_fixture(leaf: &str, leaf_home: &[Symbol], declare_union: bool) -> LeafFixture {
    let mut i = Interner::new();
    let main = i.intern("Main").unwrap();
    let leaf_name = i.intern(leaf).unwrap();
    let ctor_w = i.intern("W").unwrap();
    let tag = i.intern("tag").unwrap();
    let x = i.intern("x").unwrap();
    let int = i.intern("Int").unwrap();
    let user_home = vec![main];

    let mut unions = Vec::new();
    if declare_union {
        unions.push(canon::Union {
            home: leaf_home.to_vec(),
            name: leaf_name,
            name_span: Span::DUMMY,
            vars: Vec::new(),
            ctors: vec![canon::Ctor {
                name: ctor_w,
                index: 0,
                arity: 0,
                args: Vec::new(),
                span: Span::new(0, 1),
            }],
        });
    }

    let leaf_con = canon::Type::Con {
        home: leaf_home.to_vec(),
        name: leaf_name,
        args: Vec::new(),
    };
    let int_con = canon::Type::Con {
        home: Vec::new(),
        name: int,
        args: Vec::new(),
    };

    let sig_span = Span::new(10, 11);
    let param_span = Span::new(12, 13);
    let body_span = Span::new(14, 15);
    let tag_def = canon::Def::Typed {
        home: user_home.clone(),
        name: Located::new(sig_span, tag),
        free_vars: Vec::new(),
        patterns: vec![Located::new(param_span, canon::Pattern_::PVar(x))],
        body: Located::new(body_span, canon::Expr_::Int(0)),
        ty: canon::Type::Lambda(Box::new(leaf_con), Box::new(int_con)),
    };

    let solved_int = Ty::Con {
        module: Vec::new(),
        name: int,
        args: Vec::new(),
    };
    let solved_leaf = Ty::Con {
        module: leaf_home.to_vec(),
        name: leaf_name,
        args: Vec::new(),
    };
    let mut env: BTreeMap<(Vec<Symbol>, Symbol), Ty> = BTreeMap::new();
    env.insert(
        (user_home.clone(), tag),
        Ty::Fun(Box::new(solved_leaf), Box::new(solved_int.clone())),
    );
    let mut regions: BTreeMap<(Vec<Symbol>, Span), Ty> = BTreeMap::new();
    regions.insert((user_home, body_span), solved_int);

    let m = canon::Module {
        imports_unsafe_submodule: false,
        imported_web_capabilities: std::collections::BTreeSet::new(),
        name: vec![main],
        unions,
        defs: vec![tag_def],
    };
    let types = SolvedTypes {
        env,
        regions,
        expected: BTreeMap::new(),
        bounds: BTreeMap::new(),
        warnings: Vec::new(),
        poly_var_map: BTreeMap::new(),
        untyped_type_params: BTreeMap::new(),
        msg_defaulted_vars: BTreeMap::new(),
        signature_wildcards: BTreeMap::new(),
    };

    LeafFixture {
        interner: i,
        module: m,
        types,
        tag,
    }
}

/// Build and lower a single-module program `tag : <Leaf> -> Int; tag x = 0`,
/// returning `tag`'s lowered parameter `IrType`. See `build_leaf_fixture` for
/// what `leaf`/`leaf_home`/`declare_union` control.
fn lower_leaf_param_ty(leaf: &str, leaf_home: &[Symbol], declare_union: bool) -> IrType {
    let LeafFixture {
        mut interner,
        module: m,
        types,
        tag,
    } = build_leaf_fixture(leaf, leaf_home, declare_union);

    let program = match lower(&m, &types, &mut interner, "", "") {
        Ok(p) => p,
        Err((d, _)) => {
            // The assert fails the test; the sentinel is never inspected.
            assert!(false_marker(), "lowering `{leaf}` must succeed, got {d:?}");
            return IrType::Unit;
        }
    };
    let param = program
        .modules
        .iter()
        .flat_map(|module| &module.funcs)
        .find(|f| f.name == tag)
        .and_then(|f| f.params.first())
        .map(|ipe_ir::Param { ty, .. }| ty.clone());
    param.unwrap_or_else(|| {
        assert!(
            false_marker(),
            "lowered `{leaf}` is missing `tag`'s parameter"
        );
        IrType::Unit
    })
}

/// Assert a user `type <Leaf>` (home `["Main"]`) wins over the opaque runtime
/// leaf: its parameter lowers to `IrType::Enum` under the user's home.
fn assert_user_union_wins(leaf: &str) {
    let mut probe = Interner::new();
    let main = probe.intern("Main").unwrap();
    let leaf_sym = probe.intern(leaf).unwrap();

    let got = lower_leaf_param_ty(leaf, &[main], true);
    if let Some(opaque) = opaque_leaf_ir(leaf) {
        assert_ne!(
            got, opaque,
            "user `type {leaf}` param was hijacked to the opaque runtime leaf — a SEAL break"
        );
    }
    match got {
        IrType::Enum { home, name, args } => {
            assert_eq!(
                home,
                ModPath(vec![main]),
                "user `type {leaf}` must lower under its own module home"
            );
            assert_eq!(
                name, leaf_sym,
                "user `type {leaf}` lowered to the wrong enum"
            );
            assert!(args.is_empty(), "user `type {leaf}` is nullary");
        }
        other => {
            assert!(
                false_marker(),
                "user `type {leaf}` must lower to IrType::Enum, got {other:?}"
            );
        }
    }
}

/// Assert the genuine kernel leaf — a bare `Con` with the EMPTY home, exactly
/// what `ipe_types::constrain` mints for a `Web.tea` / `Tui.tea`
/// result — still maps to its opaque runtime `IrType`. The empty-home guard must
/// not regress the legitimate shape entry.
fn assert_kernel_leaf_maps_to_opaque(leaf: &str) {
    let got = lower_leaf_param_ty(leaf, &[], false);
    let Some(opaque) = opaque_leaf_ir(leaf) else {
        assert!(false_marker(), "no opaque runtime leaf for {leaf}");
        return;
    };
    assert_eq!(
        got, opaque,
        "the genuine empty-home kernel `{leaf}` must still map to its opaque runtime IrType"
    );
}

#[test]
fn user_type_webapp_wins_over_opaque_shape_leaf() {
    assert_user_union_wins("WebApp");
}

#[test]
fn user_type_tuiapp_wins_over_opaque_shape_leaf() {
    assert_user_union_wins("TuiApp");
}

#[test]
fn user_type_cliapp_wins_over_opaque_shape_leaf() {
    assert_user_union_wins("CliApp");
}

#[test]
fn kernel_webapp_still_maps_to_opaque() {
    assert_kernel_leaf_maps_to_opaque("WebApp");
}

#[test]
fn kernel_tuiapp_still_maps_to_opaque() {
    assert_kernel_leaf_maps_to_opaque("TuiApp");
}

#[test]
fn kernel_cliapp_still_maps_to_opaque() {
    assert_kernel_leaf_maps_to_opaque("CliApp");
}

// The kernel-implicit stream / WebSocket opaque handles (`StreamWriter` /
// `WebSocketServer` / `WebSocketServerCfg`) share the shape leaves' hazard: a
// bare-name arm above the `enum_variants` guard would hijack a user
// `type StreamWriter = …` to the unemitted opaque runtime handle — an
// `ipe`-exit-0-then-cargo-fail SEAL break. The same empty-home guard closes it.

#[test]
fn user_type_streamwriter_wins_over_opaque_handle() {
    assert_user_union_wins("StreamWriter");
}

#[test]
fn user_type_websocketserver_wins_over_opaque_handle() {
    assert_user_union_wins("WebSocketServer");
}

#[test]
fn user_type_websocketservercfg_wins_over_opaque_handle() {
    assert_user_union_wins("WebSocketServerCfg");
}

#[test]
fn kernel_streamwriter_still_maps_to_opaque() {
    assert_kernel_leaf_maps_to_opaque("StreamWriter");
}

#[test]
fn kernel_websocketserver_still_maps_to_opaque() {
    assert_kernel_leaf_maps_to_opaque("WebSocketServer");
}

#[test]
fn kernel_websocketservercfg_still_maps_to_opaque() {
    assert_kernel_leaf_maps_to_opaque("WebSocketServerCfg");
}
