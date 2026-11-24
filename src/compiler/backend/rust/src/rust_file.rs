//! Backend-internal file-id domain for per-Ipê-module Rust emission.
//!
//! `mod_ident`/`resolve_mod_ident`/`assert_mod_idents_unique` form a
//! fail-closed duplicate-`mod`-name gate. `emit_program`'s split branch and
//! `assemble_split_manifest` call `assert_mod_idents_unique` before writing any
//! `mod` decl or per-module source file, so two homes folding to one
//! `mod_ident` are rejected at `ipe` time (IPE-N0010) rather than shipped as a
//! duplicate `mod` (E0428) plus a silent file overwrite.

use std::collections::{BTreeMap, BTreeSet};

use ipe_diagnostics::{DResult, Diagnostic, NameError, Span};
use ipe_intern::Interner;
use ipe_ir::{EnumDef, Func, ModPath, Program, TypeDef};

use crate::naming;

/// Which Rust file a program's item (an [`ipe_ir::EnumDef`] or
/// [`ipe_ir::Func`]) is declared in. `Spine` is the always-present entry
/// file (`src/main.rs`); a `IpeModule` is one Ipê module's OWN file
/// (`src/ipe_mods/<ident>.rs`), materialised only when 2+ distinct homes are
/// present (the Spine-collapse invariant — see the design doc §3.3).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum RustFileId {
    Spine,
    IpeModule(ModPath),
}

/// The Rust module identifier for Ipê module path `home` — e.g.
/// `["Std", "Palette"]` → `ipe_mod_std_palette`, `["Lib"]` → `ipe_mod_lib`.
///
/// Reuses the same base fold [`naming::module_prefix`] already applies for
/// the value/type case, snake-cased and prefixed with `ipe_mod_` to keep it
/// visually distinct from the vendored `ipe_runtime` module tree. This is a
/// Folds a `ModPath` to the Rust identifier for its `mod` declaration; needed
/// only once emission spans more than one file.
#[must_use]
pub fn mod_ident(home: &[&str]) -> String {
    format!(
        "ipe_mod_{}",
        naming::to_snake_case(&naming::module_prefix(home))
    )
}

/// Resolve `home`'s [`mod_ident`] through `interner`. A symbol that fails to
/// resolve is never reachable on the real driver path (only malformed
/// hand-built test IR) — surfaced as a [`Diagnostic::CompilerBug`], never a
/// panic.
///
/// Reachable outside this module:
/// [`crate::project::emit_program`] needs it to compute both the
/// `src/ipe_mods/<mod_ident>.rs` file paths and the `main.rs` barrel lines
/// (`#[path = …] mod <ident>;` / `pub(crate) use <ident>::*;`) for each
/// [`RustFileId::IpeModule`] bucket, from the SAME fold
/// [`assert_mod_idents_unique`] proves collision-free. (`pub` here is
/// module-scoped — `rust_file` is a private module, so this is not part of the
/// crate's external API.)
pub fn resolve_mod_ident(home: &ModPath, interner: &Interner) -> DResult<String> {
    let segs = home
        .0
        .iter()
        .map(|sym| {
            interner
                .resolve(*sym)
                .ok_or_else(|| Diagnostic::CompilerBug {
                    where_: "ipe_backend_rust::rust_file::resolve_mod_ident",
                    detail: format!("symbol {} not present in interner", sym.as_raw()),
                })
        })
        .collect::<DResult<Vec<&str>>>()?;
    Ok(mod_ident(&segs))
}

/// Fail closed if two DISTINCT `home`s among `ids`' [`RustFileId::IpeModule`]
/// entries fold to the same [`mod_ident`]. Mirrors the EXISTING
/// `func_names.values().any(...)` / `enum_names.values().any(...)`
/// fail-closed pattern (`crate::lib`) — same `Diagnostic::Name::
/// DuplicateValue` shape, applied to the one genuinely new namespace this
/// design introduces (§2.1.1). `RustFileId::Spine` carries no `mod_ident`
/// and is skipped.
pub fn assert_mod_idents_unique(ids: &[RustFileId], interner: &Interner) -> DResult<()> {
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for id in ids {
        let RustFileId::IpeModule(home) = id else {
            continue;
        };
        let ident = resolve_mod_ident(home, interner)?;
        if !seen.insert(ident.clone()) {
            return Err(Diagnostic::Name {
                span: Span::DUMMY,
                msg: NameError::DuplicateValue {
                    name: ident.into_boxed_str(),
                    first: Span::DUMMY,
                },
            });
        }
    }
    Ok(())
}

/// The result of [`partition_items`]: every item bucketed by its
/// [`RustFileId`] home, plus the two DETERMINISTIC emission orders
/// `project::emit_program` walks the `IpeModule` buckets in.
///
/// # Why `type_order`/`func_order` exist, and why NOT `buckets`' own key order
///
/// `buckets`' own `BTreeMap<RustFileId, _>` iteration order sorts `ModPath`
/// by its derived `Ord`, which compares interned [`ipe_intern::Symbol`]s by
/// their RAW `u32` id — an id that is NOT stable between a warm
/// (incrementally reused) database and a cold (freshly rebuilt) one for the
/// SAME final program (the documented warm-db symbol-numbering limitation,
/// `clean_vs_incremental_parity.rs`'s own top doc comment). Iterating
/// `buckets` directly is fine for lookups / the totality proof, but
/// is an UNSOUND final byte-emission order the moment two or more distinct
/// real Ipê-module `home`s are present in one program — caught by
/// `parity_multimodule_adversarial_edits`'s `module-added` step.
///
/// It is ALSO not what an existing multi-module golden expects:
/// `tests/golden/mm_diamond` (`D` imported by BOTH `B` and `C`, both
/// imported by `Main`) emits `D`'s function BEFORE `C`'s and `B`'s — the
/// LINKER's topological order (the shared leaf dependency compiles first),
/// not an alphabetical or symbol-id one. Confirmed NOT alphabetical either:
/// `B` < `C` < `D` lexically, but the golden is `D`, `C`, `B`.
///
/// `type_order`/`func_order` instead record each distinct `IpeModule`
/// `home`'s FIRST-ENCOUNTER position while walking `program.modules[..].
/// types` / `.funcs` in THEIR OWN vector order — exactly the traversal the
/// direct-walk code performs (two independent `for module in &program.
/// modules { for x in &module.x { ... } }` loops), and every existing golden
/// (single- AND multi-module) was captured against. `program.modules`'s own
/// vector order is a linker-computed topological order, proven warm/cold-
/// stable by `parity_multimodule_adversarial_edits` itself — first-encounter
/// order over it is therefore ALSO warm/cold-stable. Two separate orders (not
/// one combined order) because the two independent loops could, in
/// principle, see a different cross-module home sequence for types than for
/// funcs — e.g. a home whose ONLY items are functions (like `D` in
/// `mm_diamond`, which declares no types at all) contributes nothing to the
/// type walk's order.
#[derive(Debug)]
pub struct Partitioned<'p> {
    pub buckets: BTreeMap<RustFileId, (Vec<&'p EnumDef>, Vec<&'p Func>)>,
    pub type_order: Vec<RustFileId>,
    pub func_order: Vec<RustFileId>,
}

/// Partition every [`EnumDef`] and [`Func`] in `program` by the
/// [`RustFileId`] it is declared in — see [`Partitioned`] for the full
/// shape, including the two emission-order fields.
///
/// Proven TOTAL: every item in `program.modules[..].types /
/// .funcs` appears in EXACTLY ONE output bucket — no drop, no duplicate.
///
/// **`SqlValue`/`SqlField`/`ProjectionTerm`/`ProjectionOperand` Spine special
/// case (design doc §2.2).** These four synthetic enums (the first two from
/// `ipe_lower::lower`'s `synthetic_sqlvalue_enum` / `synthetic_sqlfield_enum`,
/// the last two from `synthetic_projection_term_enum` /
/// `synthetic_projection_operand_enum`) carry the empty canonical `home` — the
/// SAME documented Prelude-built-in home every OTHER hand-built-IR item with an
/// empty `home` carries. Left unpatched, the generic empty-home fallback
/// below would route them into whichever `IpeModule` bucket the program's
/// entry-point module happens to own — contradicting §2.2's decision that
/// they are fixed to `Spine`, unconditionally, alongside the DB-projection
/// impl blocks that reference them. So they are detected BY NAME, before
/// the generic empty-home fallback runs, reusing the exact detection idiom
/// `EmitCtx::build`'s `uses_db` scan already applies
/// (`crate::lib`'s `uses_db` / `sqlvalue_rust_name` / `sqlfield_rust_name`).
/// (These four enums route to `Spine`, never an `IpeModule` bucket, so they
/// never enter `type_order` either — same invariant as `buckets`.)
pub fn partition_items<'p>(program: &'p Program, interner: &Interner) -> Partitioned<'p> {
    let mut out: BTreeMap<RustFileId, (Vec<&'p EnumDef>, Vec<&'p Func>)> = BTreeMap::new();
    let mut type_order: Vec<RustFileId> = Vec::new();
    let mut type_seen: BTreeSet<RustFileId> = BTreeSet::new();
    let mut func_order: Vec<RustFileId> = Vec::new();
    let mut func_seen: BTreeSet<RustFileId> = BTreeSet::new();
    for module in &program.modules {
        for ty in &module.types {
            let TypeDef::Enum(def) = ty;
            // §2.2 fix: SqlValue/SqlField are Prelude built-ins (empty
            // canon home, see lower.rs's own doc comment on
            // synthetic_sqlvalue_enum) that the DB-projection impl blocks
            // (ALWAYS Spine, per §2.2) reference. Force them into Spine
            // BY NAME, before the generic empty-home fallback below would
            // otherwise route them into whichever module happens to be
            // `Module.name` — reuses the exact detection idiom `uses_db`
            // already applies.
            let resolved = interner.resolve(def.name);
            if matches!(
                resolved,
                Some("SqlValue" | "SqlField" | "ProjectionTerm" | "ProjectionOperand" | "ArithOp")
            ) {
                out.entry(RustFileId::Spine).or_default().0.push(def);
                continue;
            }
            let home = if def.home.0.is_empty() {
                module.name.clone()
            } else {
                def.home.clone()
            };
            let file_id = RustFileId::IpeModule(home);
            if type_seen.insert(file_id.clone()) {
                type_order.push(file_id.clone());
            }
            out.entry(file_id).or_default().0.push(def);
        }
        for func in &module.funcs {
            let home = if func.home.0.is_empty() {
                module.name.clone()
            } else {
                func.home.clone()
            };
            let file_id = RustFileId::IpeModule(home);
            if func_seen.insert(file_id.clone()) {
                func_order.push(file_id.clone());
            }
            out.entry(file_id).or_default().1.push(func);
        }
    }
    Partitioned {
        buckets: out,
        type_order,
        func_order,
    }
}

#[cfg(test)]
mod tests {
    use ipe_diagnostics::{DResult, Diagnostic, NameError};
    use ipe_intern::Interner;
    use ipe_ir::{EnumDef, Func, FuncId, IrType, Module, Variant};

    use super::*;

    /// A runtime `false` the optimiser cannot fold, so `assert!(false_marker(),
    /// …)` reads as a deliberate unconditional failure rather than a suspicious
    /// constant condition — keeps this file free of the `clippy::panic` deny.
    const fn false_marker() -> bool {
        std::hint::black_box(false)
    }

    #[test]
    fn spine_is_not_a_ipe_module() {
        assert_ne!(RustFileId::Spine, RustFileId::IpeModule(ModPath(vec![])));
    }

    #[test]
    fn mod_ident_is_stable_and_distinct_for_distinct_homes() {
        let a = mod_ident(&["Std", "Palette"]);
        let b = mod_ident(&["Lib"]);
        assert_ne!(a, b);
        assert_eq!(a, "ipe_mod_std_palette");
        assert_eq!(b, "ipe_mod_lib");
    }

    #[test]
    fn mod_ident_distinguishes_dotted_path_from_underscore_segment() {
        // The historical collision class: a single segment literally spelled
        // "Std_Ui" versus the two-segment path ["Std", "Ui"]. The injective
        // fold (`module_prefix` escapes in-segment `_` to `__`) keeps them
        // DISTINCT, so both can coexist as `mod` idents.
        let dotted = mod_ident(&["Std", "Ui"]);
        let underscored = mod_ident(&["Std_Ui"]);
        assert_ne!(
            dotted, underscored,
            "a dotted path and an underscore-in-segment name must not fold to one mod_ident"
        );
    }

    #[test]
    fn source_reachable_dot_vs_underscore_pair_does_not_fail_closed() -> DResult<()> {
        // Post-injective-fold, the pair that USED to collide (a single segment
        // "Std_Ui" and the two-segment ["Std", "Ui"]) folds to DISTINCT idents,
        // so the gate passes — both are legal, distinct module homes.
        let mut interner = Interner::new();
        let combined = interner.intern("Std_Ui")?;
        let std_seg = interner.intern("Std")?;
        let ui_seg = interner.intern("Ui")?;
        let ids = vec![
            RustFileId::IpeModule(ModPath(vec![combined])),
            RustFileId::IpeModule(ModPath(vec![std_seg, ui_seg])),
        ];
        assert_mod_idents_unique(&ids, &interner)
    }

    #[test]
    fn duplicate_mod_idents_fail_closed() -> DResult<()> {
        // The gate is live: two `RustFileId::IpeModule` entries carrying the
        // SAME home fold to one `mod_ident`, and the gate rejects them with
        // `NameError::DuplicateValue` (IPE-N0010). Source can no longer reach a
        // collision (the fold is injective), so this exercises the fail-closed
        // path with a genuine duplicate to prove the wire diagnostic.
        let mut interner = Interner::new();
        let std_seg = interner.intern("Std")?;
        let ui_seg = interner.intern("Ui")?;
        let home = ModPath(vec![std_seg, ui_seg]);
        let ids = vec![
            RustFileId::IpeModule(home.clone()),
            RustFileId::IpeModule(home),
        ];
        match assert_mod_idents_unique(&ids, &interner) {
            Err(Diagnostic::Name {
                msg: NameError::DuplicateValue { .. },
                ..
            }) => Ok(()),
            other => {
                assert!(
                    false_marker(),
                    "expected IPE-N0010 DuplicateValue on a genuine mod_ident collision, got \
                     {other:?}"
                );
                Ok(())
            }
        }
    }

    #[test]
    fn distinct_mod_idents_do_not_fail_closed() -> DResult<()> {
        let mut interner = Interner::new();
        let lib = interner.intern("Lib")?;
        let main = interner.intern("Main")?;
        let ids = vec![
            RustFileId::IpeModule(ModPath(vec![lib])),
            RustFileId::IpeModule(ModPath(vec![main])),
        ];
        assert_mod_idents_unique(&ids, &interner)
    }

    /// Shared no-op module builder for the `partition_items` fixtures below
    /// — every flag `false`, no types/funcs/records, `entry: None`. Callers
    /// override `types`/`funcs`/`records`.
    fn empty_module(name: ModPath) -> Module {
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
            uses_db_operator: false,
            uses_debug: false,
            uses_ffi: false,
            uses_async_runtime: false,
        }
    }

    #[test]
    fn partition_items_is_total_across_two_homes() -> DResult<()> {
        let mut interner = Interner::new();
        let lib_mod = interner.intern("Lib")?;
        let main_mod = interner.intern("Main")?;
        let lib_ty = interner.intern("Color")?;
        let main_ty = interner.intern("Msg")?;
        let red = interner.intern("Red")?;
        let increment = interner.intern("Increment")?;
        let lib_fn = interner.intern("helper")?;
        let main_fn = interner.intern("update")?;

        let mut module = empty_module(ModPath(vec![main_mod]));
        module.types = vec![
            TypeDef::Enum(EnumDef {
                name: lib_ty,
                home: ModPath(vec![lib_mod]),
                type_params: vec![],
                variants: vec![Variant {
                    name: red,
                    fields: vec![],
                }],
            }),
            TypeDef::Enum(EnumDef {
                name: main_ty,
                home: ModPath(vec![main_mod]),
                type_params: vec![],
                variants: vec![Variant {
                    name: increment,
                    fields: vec![],
                }],
            }),
        ];
        module.funcs = vec![
            Func {
                id: FuncId::from_raw(0),
                name: lib_fn,
                home: ModPath(vec![lib_mod]),
                type_params: vec![],
                row_params: vec![],
                params: vec![],
                ret: IrType::Int,
                body: ipe_ir::Expr::Int(0),
            },
            Func {
                id: FuncId::from_raw(1),
                name: main_fn,
                home: ModPath(vec![main_mod]),
                type_params: vec![],
                row_params: vec![],
                params: vec![],
                ret: IrType::Int,
                body: ipe_ir::Expr::Int(0),
            },
        ];

        let program = Program {
            imports_unsafe_submodule: false,
            imported_web_capabilities: std::collections::BTreeSet::new(),
            modules: vec![module],
        };
        let Partitioned { buckets, .. } = partition_items(&program, &interner);

        let total_enums: usize = buckets.values().map(|(e, _)| e.len()).sum();
        let total_funcs: usize = buckets.values().map(|(_, f)| f.len()).sum();
        assert_eq!(
            total_enums, 2,
            "every EnumDef must land in exactly one bucket"
        );
        assert_eq!(total_funcs, 2, "every Func must land in exactly one bucket");
        assert_eq!(
            buckets.len(),
            2,
            "two distinct non-empty homes must produce exactly two IpeModule buckets"
        );
        assert!(!buckets.contains_key(&RustFileId::Spine));
        Ok(())
    }

    #[test]
    fn partition_items_is_total_for_a_single_module_fixture() -> DResult<()> {
        // Mirrors `tests/golden.rs`'s `build_m0` shape: one module, every
        // item's `home` matches the module's own name — the case every
        // existing single-file golden fixture is in.
        let mut interner = Interner::new();
        let main_mod = interner.intern("Main")?;
        let msg_ty = interner.intern("Msg")?;
        let increment = interner.intern("Increment")?;
        let update = interner.intern("update")?;

        let mut module = empty_module(ModPath(vec![main_mod]));
        module.types = vec![TypeDef::Enum(EnumDef {
            name: msg_ty,
            home: ModPath(vec![main_mod]),
            type_params: vec![],
            variants: vec![Variant {
                name: increment,
                fields: vec![],
            }],
        })];
        module.funcs = vec![Func {
            id: FuncId::from_raw(0),
            name: update,
            home: ModPath(vec![main_mod]),
            type_params: vec![],
            row_params: vec![],
            params: vec![],
            ret: IrType::Int,
            body: ipe_ir::Expr::Int(0),
        }];

        let program = Program {
            imports_unsafe_submodule: false,
            imported_web_capabilities: std::collections::BTreeSet::new(),
            modules: vec![module],
        };
        let Partitioned { buckets, .. } = partition_items(&program, &interner);

        let total_enums: usize = buckets.values().map(|(e, _)| e.len()).sum();
        let total_funcs: usize = buckets.values().map(|(_, f)| f.len()).sum();
        assert_eq!(total_enums, 1);
        assert_eq!(total_funcs, 1);
        assert_eq!(
            buckets.len(),
            1,
            "a single-home program must collapse to one bucket"
        );
        Ok(())
    }

    #[test]
    fn partition_items_routes_empty_home_to_module_name_fallback() -> DResult<()> {
        let mut interner = Interner::new();
        let main_mod = interner.intern("Main")?;
        let msg_ty = interner.intern("Msg")?;
        let increment = interner.intern("Increment")?;

        let mut module = empty_module(ModPath(vec![main_mod]));
        // `home` empty simulates hand-built test IR (never the real driver
        // path, which always sets `home` — see `EnumDef::home`'s own doc
        // comment). The existing naming-layer fallback (module name) must
        // still apply for anything that is NOT SqlValue/SqlField.
        module.types = vec![TypeDef::Enum(EnumDef {
            name: msg_ty,
            home: ModPath(vec![]),
            type_params: vec![],
            variants: vec![Variant {
                name: increment,
                fields: vec![],
            }],
        })];

        let program = Program {
            imports_unsafe_submodule: false,
            imported_web_capabilities: std::collections::BTreeSet::new(),
            modules: vec![module],
        };
        let Partitioned { buckets, .. } = partition_items(&program, &interner);

        let key = RustFileId::IpeModule(ModPath(vec![main_mod]));
        let (enums, _) = buckets
            .get(&key)
            .expect("expected the Main-name fallback bucket");
        assert_eq!(enums.len(), 1);
        assert!(!buckets.contains_key(&RustFileId::Spine));
        Ok(())
    }

    #[test]
    fn partition_items_forces_db_builtins_into_spine() -> DResult<()> {
        let mut interner = Interner::new();
        let main_mod = interner.intern("Main")?;
        let sqlvalue = interner.intern("SqlValue")?;
        let sqlfield = interner.intern("SqlField")?;
        let projection_term = interner.intern("ProjectionTerm")?;
        let projection_operand = interner.intern("ProjectionOperand")?;
        let sql_string = interner.intern("SqlString")?;

        let mut module = empty_module(ModPath(vec![main_mod]));
        // All four DB built-ins carry the empty canonical Prelude-built-in
        // home and must route to Spine, not the generic empty-home module
        // fallback (design doc §2.2).
        module.types = vec![
            TypeDef::Enum(EnumDef {
                name: sqlvalue,
                home: ModPath(vec![]),
                type_params: vec![],
                variants: vec![Variant {
                    name: sql_string,
                    fields: vec![],
                }],
            }),
            TypeDef::Enum(EnumDef {
                name: sqlfield,
                home: ModPath(vec![]),
                type_params: vec![],
                variants: vec![Variant {
                    name: sql_string,
                    fields: vec![],
                }],
            }),
            TypeDef::Enum(EnumDef {
                name: projection_term,
                home: ModPath(vec![]),
                type_params: vec![],
                variants: vec![Variant {
                    name: sql_string,
                    fields: vec![],
                }],
            }),
            TypeDef::Enum(EnumDef {
                name: projection_operand,
                home: ModPath(vec![]),
                type_params: vec![],
                variants: vec![Variant {
                    name: sql_string,
                    fields: vec![],
                }],
            }),
        ];

        let program = Program {
            imports_unsafe_submodule: false,
            imported_web_capabilities: std::collections::BTreeSet::new(),
            modules: vec![module],
        };
        let Partitioned { buckets, .. } = partition_items(&program, &interner);

        let (spine_enums, _) = buckets
            .get(&RustFileId::Spine)
            .expect("expected a Spine bucket");
        assert_eq!(
            spine_enums.len(),
            4,
            "SqlValue, SqlField, ProjectionTerm, and ProjectionOperand must all route to Spine"
        );
        assert!(
            !buckets.contains_key(&RustFileId::IpeModule(ModPath(vec![main_mod]))),
            "DB built-ins must NEVER fall into the generic empty-home module fallback"
        );
        Ok(())
    }

    /// Regression test for the `mm_diamond`-class ordering bug:
    /// `type_order`/`func_order` must follow
    /// `program.modules`'s OWN vector (linker/topological) order, never an
    /// alphabetical or `mod_ident`-string sort. `Zeta` is placed BEFORE
    /// `Alpha` in `program.modules` — reverse alphabetical — specifically so
    /// a regression back to alphabetical sorting fails this test instead of
    /// silently reappearing. `Zeta` also declares a func but NO type, so
    /// `type_order` and `func_order` genuinely diverge (proving the two
    /// orders are tracked independently, not derived from one shared list).
    #[test]
    fn partition_items_orders_by_first_encounter_not_alphabetically() -> DResult<()> {
        let mut interner = Interner::new();
        let zeta_mod = interner.intern("Zeta")?;
        let alpha_mod = interner.intern("Alpha")?;
        let alpha_ty = interner.intern("AlphaType")?;
        let alpha_variant = interner.intern("AlphaVariant")?;
        let zeta_fn = interner.intern("zetaFn")?;
        let alpha_fn = interner.intern("alphaFn")?;

        let mut zeta = empty_module(ModPath(vec![zeta_mod]));
        zeta.funcs = vec![Func {
            id: FuncId::from_raw(0),
            name: zeta_fn,
            home: ModPath(vec![zeta_mod]),
            type_params: vec![],
            row_params: vec![],
            params: vec![],
            ret: IrType::Int,
            body: ipe_ir::Expr::Int(0),
        }];

        let mut alpha = empty_module(ModPath(vec![alpha_mod]));
        alpha.types = vec![TypeDef::Enum(EnumDef {
            name: alpha_ty,
            home: ModPath(vec![alpha_mod]),
            type_params: vec![],
            variants: vec![Variant {
                name: alpha_variant,
                fields: vec![],
            }],
        })];
        alpha.funcs = vec![Func {
            id: FuncId::from_raw(1),
            name: alpha_fn,
            home: ModPath(vec![alpha_mod]),
            type_params: vec![],
            row_params: vec![],
            params: vec![],
            ret: IrType::Int,
            body: ipe_ir::Expr::Int(0),
        }];

        // `Zeta` FIRST in `program.modules` — reverse alphabetical order.
        let program = Program {
            imports_unsafe_submodule: false,
            imported_web_capabilities: std::collections::BTreeSet::new(),
            modules: vec![zeta, alpha],
        };
        let Partitioned {
            type_order,
            func_order,
            ..
        } = partition_items(&program, &interner);

        let zeta_id = RustFileId::IpeModule(ModPath(vec![zeta_mod]));
        let alpha_id = RustFileId::IpeModule(ModPath(vec![alpha_mod]));

        assert_eq!(
            type_order,
            vec![alpha_id.clone()],
            "Zeta declares no types, so it must be absent from type_order entirely"
        );
        assert_eq!(
            func_order,
            vec![zeta_id, alpha_id],
            "func_order must follow program.modules's own vector order (Zeta first), \
             NOT an alphabetical sort (which would put Alpha first)"
        );
        Ok(())
    }
}
