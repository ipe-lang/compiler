//! Rename operation: resolver-accurate cross-module symbol rename.
//!
//! # Resolver accuracy
//!
//! References come from [`ReferenceIndex`], built from the canonical AST —
//! alias resolution, shadowing exclusion, and cross-module disambiguation are
//! already baked in.  This module adds only the defining-site edit and the
//! capture-avoidance check.
//!
//! # Capture avoidance (fail-closed)
//!
//! A rename `old_name → new_name` is refused when `new_name` is already
//! defined as a top-level symbol (value or constructor) in any module that
//! will be touched (defining module or any module containing a use site).
//! Conservative by design: a false refusal is safe; a silent capture is not.
//!
//! # Edit set
//!
//! Each [`Edit`] carries the module path, the byte span to replace, and the
//! replacement text.  Edits are span-disjoint by construction (the index
//! records one span per reference node; the defining span is the name token
//! only).

use ipe_diagnostics::Span;
use ipe_intern::{Interner, Symbol};
use ipe_parse::{is_ident_continue, is_ident_start, is_keyword};

use crate::ast::Module;
use crate::ref_index::ReferenceIndex;

// ── Public types ──────────────────────────────────────────────────────────────

/// A single source replacement produced by a rename.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Edit {
    /// Module path of the file that contains this edit.
    pub file: Vec<Symbol>,
    /// Byte range of the identifier to replace.
    pub span: Span,
    /// The replacement text (the validated new name).
    pub replacement: String,
}

/// The full set of edits that atomically renames a symbol.
///
/// Edits within a single file are span-disjoint and may be applied in any
/// order.  Applying the same set twice leaves source unchanged after the
/// first application (idempotent).
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct EditSet {
    pub edits: Vec<Edit>,
}

/// Reasons a rename can be refused.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum RenameError {
    /// The `(module, old_name)` defining site was not found in the supplied
    /// modules (kernel, external dep, or typo).
    SymbolNotFound {
        module: Vec<Symbol>,
        old_name: Symbol,
    },
    /// `new_name` is not a valid Ipê identifier: empty, non-ASCII, starts with
    /// a digit, is a keyword, or has the wrong case class.
    InvalidIdentifier { new_name: String, reason: String },
    /// Emitting the rename would introduce a capture: `new_name` is already
    /// defined as a top-level name in one of the touched modules.
    CaptureConflict {
        new_name: String,
        /// Module where the conflict was found.
        in_module: Vec<Symbol>,
        /// The existing symbol whose name matches `new_name`.
        existing_name: Symbol,
    },
}

// ── Identifier validation ─────────────────────────────────────────────────────
//
// Charset and keyword checks delegate to the lexer (`ipe_parse`), the single
// source of truth for what spells one identifier token.

/// Whether a renamed symbol is a type/constructor (uppercase) or a value
/// (lowercase / `_`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SymbolClass {
    /// Type alias, custom type, or constructor — first char must be uppercase.
    Type,
    /// Value binding or function — first char must be lowercase or `_`.
    Value,
}

impl SymbolClass {
    fn of(name: &str) -> Self {
        match name.chars().next() {
            Some(c) if c.is_ascii_uppercase() => Self::Type,
            _ => Self::Value,
        }
    }
}

fn validate_new_name(raw: &str, class: SymbolClass) -> Result<(), RenameError> {
    let mut chars = raw.chars();
    let first = chars.next().ok_or_else(|| RenameError::InvalidIdentifier {
        new_name: raw.to_owned(),
        reason: "empty identifier".to_owned(),
    })?;
    if !is_ident_start(first) {
        return Err(RenameError::InvalidIdentifier {
            new_name: raw.to_owned(),
            reason: format!("first character {first:?} is not a letter or underscore"),
        });
    }
    for c in chars {
        if !is_ident_continue(c) {
            return Err(RenameError::InvalidIdentifier {
                new_name: raw.to_owned(),
                reason: format!("character {c:?} is not alphanumeric or underscore"),
            });
        }
    }
    if is_keyword(raw) {
        return Err(RenameError::InvalidIdentifier {
            new_name: raw.to_owned(),
            reason: format!("{raw:?} is a reserved keyword"),
        });
    }
    match class {
        SymbolClass::Type if !first.is_ascii_uppercase() => {
            return Err(RenameError::InvalidIdentifier {
                new_name: raw.to_owned(),
                reason: "type/constructor names must start with an uppercase letter".to_owned(),
            });
        }
        SymbolClass::Value if first.is_ascii_uppercase() => {
            return Err(RenameError::InvalidIdentifier {
                new_name: raw.to_owned(),
                reason: "value names must start with a lowercase letter or underscore".to_owned(),
            });
        }
        _ => {}
    }
    Ok(())
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Compute the edit set for renaming `(module_path, old_name)` → `new_name`.
///
/// `interner` is used to resolve symbol strings for identifier validation and
/// capture-avoidance checks.  `index` must have been built from at least every
/// module in `all_modules`.
///
/// Returns `Ok(EditSet)` — defining site + every use site — on success.
///
/// # Errors
///
/// * [`RenameError::SymbolNotFound`] — defining site not found.
/// * [`RenameError::InvalidIdentifier`] — `new_name` fails lexical or case
///   checks.
/// * [`RenameError::CaptureConflict`] — `new_name` would shadow or be
///   shadowed by an existing top-level name in a touched module; no edits are
///   produced.
pub fn rename(
    interner: &Interner,
    index: &ReferenceIndex,
    all_modules: &[(&Module, &[Symbol])],
    module_path: &[Symbol],
    old_name: Symbol,
    new_name: &str,
) -> Result<EditSet, RenameError> {
    // ── 1. Locate defining site ───────────────────────────────────────────────

    let (def_path, def_span, old_name_str) =
        find_defining_site(interner, all_modules, module_path, old_name).ok_or_else(|| {
            RenameError::SymbolNotFound {
                module: module_path.to_owned(),
                old_name,
            }
        })?;

    // ── 2. Validate new_name ──────────────────────────────────────────────────

    let class = SymbolClass::of(&old_name_str);
    validate_new_name(new_name, class)?;

    // ── 3. Gather use sites ───────────────────────────────────────────────────

    let refs = index.references_of(module_path, old_name);

    // ── 4. Capture-avoidance check ────────────────────────────────────────────
    //
    // Build a module-path → Module map, then check each touched module for an
    // existing top-level name equal to `new_name`.

    let module_map: std::collections::BTreeMap<&[Symbol], &Module> =
        all_modules.iter().map(|(m, p)| (*p, *m)).collect();

    // Collect the set of touched module paths: defining module + use-site modules.
    let mut touched: Vec<&[Symbol]> = vec![def_path];
    for r in refs {
        touched.push(r.in_module.as_slice());
    }
    touched.sort_unstable();
    touched.dedup();

    for path in &touched {
        if let Some(m) = module_map.get(path) {
            check_capture(interner, m, path, new_name)?;
        }
    }

    // ── 5. Build edits ────────────────────────────────────────────────────────

    let mut edits: Vec<Edit> = Vec::with_capacity(refs.len() + 1);

    // Defining-site edit.
    edits.push(Edit {
        file: def_path.to_owned(),
        span: def_span,
        replacement: new_name.to_owned(),
    });

    // Use-site edits.
    for r in refs {
        edits.push(Edit {
            file: r.in_module.clone(),
            span: r.span,
            replacement: new_name.to_owned(),
        });
    }

    Ok(EditSet { edits })
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Find the name-token span of `old_name` in the defining module `module_path`.
///
/// The defining site is either a top-level value binding or a data constructor
/// declared in a `type` union — both are renameable top-level symbols. A
/// constructor's canonical [`Ctor`](crate::ast::Ctor) span begins at its name
/// token, so the name-token span is `[span.lo, span.lo + name_len)`, mirroring
/// the go-to-definition walker's convention; this keeps the defining-site edit a
/// single-token replacement rather than rewriting the whole constructor clause.
///
/// Returns `(module_path_slice, name_span, name_string)` on success.
fn find_defining_site<'a>(
    interner: &Interner,
    all_modules: &'a [(&'a Module, &'a [Symbol])],
    module_path: &[Symbol],
    old_name: Symbol,
) -> Option<(&'a [Symbol], Span, String)> {
    for (m, path) in all_modules {
        if *path != module_path {
            continue;
        }
        for def in &m.defs {
            let def_name = def.name();
            if def_name.value == old_name {
                let name_str = interner.resolve(old_name).unwrap_or("").to_owned();
                return Some((path, def_name.span, name_str));
            }
        }
        for union in &m.unions {
            for ctor in &union.ctors {
                if ctor.name == old_name {
                    let name_str = interner.resolve(old_name).unwrap_or("").to_owned();
                    let len = u32::try_from(name_str.len()).unwrap_or(0);
                    let name_span = Span::new(ctor.span.lo, ctor.span.lo.saturating_add(len));
                    return Some((path, name_span, name_str));
                }
            }
        }
    }
    None
}

/// Refuse with [`RenameError::CaptureConflict`] if any top-level name in
/// `module` (value defs or union constructors) resolves to `new_name`.
fn check_capture(
    interner: &Interner,
    module: &Module,
    path: &[Symbol],
    new_name: &str,
) -> Result<(), RenameError> {
    for def in &module.defs {
        let sym = def.name().value;
        if interner.resolve(sym) == Some(new_name) {
            return Err(RenameError::CaptureConflict {
                new_name: new_name.to_owned(),
                in_module: path.to_owned(),
                existing_name: sym,
            });
        }
    }
    for union in &module.unions {
        // Check the union type name.
        if interner.resolve(union.name) == Some(new_name) {
            return Err(RenameError::CaptureConflict {
                new_name: new_name.to_owned(),
                in_module: path.to_owned(),
                existing_name: union.name,
            });
        }
        // Check constructor names.
        for ctor in &union.ctors {
            if interner.resolve(ctor.name) == Some(new_name) {
                return Err(RenameError::CaptureConflict {
                    new_name: new_name.to_owned(),
                    in_module: path.to_owned(),
                    existing_name: ctor.name,
                });
            }
        }
    }
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    //! TDD: rename edit-set accuracy and capture-avoidance refusal.
    //!
    //! Fixture: four modules.
    //!
    //! * `Lib` — defines `helper`.
    //! * `Main` — three refs to `Lib.helper` (qualified / alias-resolved /
    //!   unqualified; all canonicalise to `VarTopLevel { [Lib], helper }`).
    //! * `Consumer` — one ref to `Lib.helper`.
    //! * `Shadow` — a `VarLocal(helper)` that the resolver did NOT classify as
    //!   a top-level ref; must not appear in the index or the edit set.
    //!
    //! Rename `Lib.helper → renamed` must:
    //!   1. Include the defining span in `Lib` (span 10..16).
    //!   2. Include all three use-site spans in `Main`.
    //!   3. Include the one span in `Consumer`.
    //!   4. NOT include `Shadow`'s local.
    //!   5. REFUSE when `new_name` is already a top-level name in a touched
    //!      module (`CaptureConflict`).
    //!   6. REFUSE for invalid identifiers (`InvalidIdentifier`).
    //!   7. REFUSE for an unknown symbol (`SymbolNotFound`).
    //!   8. Be idempotent.

    use std::collections::BTreeSet;

    use ipe_diagnostics::{Located, Span};
    use ipe_intern::{Interner, Symbol};

    use crate::ast::{Def, Expr, Expr_, Module};
    use crate::ref_index::ReferenceIndex;

    use super::{RenameError, SymbolClass, rename, validate_new_name};

    // ── helpers ───────────────────────────────────────────────────────────────

    fn sym(i: &mut Interner, s: &str) -> Symbol {
        i.intern(s).expect("intern ok in test")
    }

    fn span(lo: u32, hi: u32) -> Span {
        Span::new(lo, hi)
    }

    fn expr(sp: Span, v: Expr_) -> Expr {
        Located::new(sp, v)
    }

    fn bare_module(name: Vec<Symbol>, defs: Vec<Def>) -> Module {
        Module {
            name,
            unions: vec![],
            defs,
            imports_unsafe_submodule: false,
            imported_web_capabilities: BTreeSet::new(),
        }
    }

    fn value_def(name_span: Span, name_sym: Symbol, home: Vec<Symbol>, body: Expr) -> Def {
        Def::Untyped {
            home,
            name: Located::new(name_span, name_sym),
            patterns: vec![],
            body,
        }
    }

    // ── fixture ───────────────────────────────────────────────────────────────

    fn build_fixture(
        i: &mut Interner,
    ) -> (
        Module, // Lib
        Module, // Main  (3 refs to Lib.helper)
        Module, // Consumer (1 ref to Lib.helper)
        Module, // Shadow (VarLocal, not in index)
        Symbol, // helper_sym
        Symbol, // lib_sym
    ) {
        let lib_sym = sym(i, "Lib");
        let main_sym = sym(i, "Main");
        let consumer_sym = sym(i, "Consumer");
        let shadow_sym = sym(i, "Shadow");
        let helper_sym = sym(i, "helper");
        let f_sym = sym(i, "f");
        let g_sym = sym(i, "g");
        let h_sym = sym(i, "h");
        let consume_fn_sym = sym(i, "consume");
        let shadow_fn_sym = sym(i, "shadow_fn");
        let local_sym = sym(i, "local");

        // Lib: defines `helper` at name-span 10..16.
        let lib_mod = bare_module(
            vec![lib_sym],
            vec![value_def(
                span(10, 16),
                helper_sym,
                vec![lib_sym],
                expr(span(20, 24), Expr_::Unit),
            )],
        );

        // Main: three defs each holding a VarTopLevel ref to Lib.helper.
        let mk_ref = |lo, hi| {
            expr(
                span(lo, hi),
                Expr_::VarTopLevel {
                    module: vec![lib_sym],
                    name: helper_sym,
                },
            )
        };
        let main_mod = bare_module(
            vec![main_sym],
            vec![
                value_def(span(90, 91), f_sym, vec![main_sym], mk_ref(100, 106)),
                value_def(span(190, 191), g_sym, vec![main_sym], mk_ref(200, 206)),
                value_def(span(290, 291), h_sym, vec![main_sym], mk_ref(300, 306)),
            ],
        );

        // Consumer: one ref to Lib.helper.
        let consumer_mod = bare_module(
            vec![consumer_sym],
            vec![value_def(
                span(390, 397),
                consume_fn_sym,
                vec![consumer_sym],
                expr(
                    span(400, 406),
                    Expr_::VarTopLevel {
                        module: vec![lib_sym],
                        name: helper_sym,
                    },
                ),
            )],
        );

        // Shadow: VarLocal — the resolver already classified this as a local;
        // it does NOT produce a VarTopLevel node, so it is invisible to the index.
        let shadow_mod = bare_module(
            vec![shadow_sym],
            vec![value_def(
                span(500, 509),
                shadow_fn_sym,
                vec![shadow_sym],
                expr(span(510, 516), Expr_::VarLocal(local_sym)),
            )],
        );

        (
            lib_mod,
            main_mod,
            consumer_mod,
            shadow_mod,
            helper_sym,
            lib_sym,
        )
    }

    // ── test 1: correct edit set ──────────────────────────────────────────────

    #[test]
    fn produces_defining_site_and_all_use_sites() {
        let mut i = Interner::new();
        let (lib_mod, main_mod, consumer_mod, shadow_mod, helper_sym, lib_sym) =
            build_fixture(&mut i);

        let lib_path = lib_mod.name.clone();
        let main_path = main_mod.name.clone();
        let consumer_path = consumer_mod.name.clone();
        let shadow_path = shadow_mod.name.clone();

        let all: &[(&Module, &[Symbol])] = &[
            (&lib_mod, &lib_path),
            (&main_mod, &main_path),
            (&consumer_mod, &consumer_path),
            (&shadow_mod, &shadow_path),
        ];
        let index = ReferenceIndex::build(all);

        let result = rename(&i, &index, all, &[lib_sym], helper_sym, "renamed");
        let edit_set = result.expect("rename must succeed");

        // 1 defining + 3 Main + 1 Consumer = 5 total.
        assert_eq!(
            edit_set.edits.len(),
            5,
            "expected 5 edits, got: {:?}",
            edit_set.edits
        );
        for e in &edit_set.edits {
            assert_eq!(e.replacement, "renamed");
        }

        // Defining site at span 10..16 in Lib.
        assert!(
            edit_set
                .edits
                .iter()
                .any(|e| e.file == lib_path && e.span == Span::new(10, 16)),
            "defining-site edit missing"
        );

        // Three edits in Main.
        let mut main_spans: Vec<_> = edit_set
            .edits
            .iter()
            .filter(|e| e.file == main_path)
            .map(|e| (e.span.lo, e.span.hi))
            .collect();
        main_spans.sort_unstable();
        assert_eq!(main_spans, vec![(100, 106), (200, 206), (300, 306)]);

        // One edit in Consumer.
        let consumer_edits: Vec<_> = edit_set
            .edits
            .iter()
            .filter(|e| e.file == consumer_path)
            .collect();
        assert_eq!(consumer_edits.len(), 1);
        assert_eq!(
            consumer_edits.first().expect("one consumer edit").span,
            Span::new(400, 406)
        );

        // No edits in Shadow.
        assert!(
            edit_set.edits.iter().all(|e| e.file != shadow_path),
            "shadowed VarLocal must not produce an edit"
        );
    }

    // ── test 2: invalid new_name ──────────────────────────────────────────────

    #[test]
    fn refuses_invalid_new_name() {
        let mut i = Interner::new();
        let (lib_mod, main_mod, consumer_mod, shadow_mod, helper_sym, lib_sym) =
            build_fixture(&mut i);

        let lib_path = lib_mod.name.clone();
        let main_path = main_mod.name.clone();
        let consumer_path = consumer_mod.name.clone();
        let shadow_path = shadow_mod.name.clone();
        let all: &[(&Module, &[Symbol])] = &[
            (&lib_mod, &lib_path),
            (&main_mod, &main_path),
            (&consumer_mod, &consumer_path),
            (&shadow_mod, &shadow_path),
        ];
        let index = ReferenceIndex::build(all);

        for bad in &["", "1bad", "foo bar", "let", "Uppercase"] {
            let err = rename(&i, &index, all, &[lib_sym], helper_sym, bad);
            assert!(
                matches!(err, Err(RenameError::InvalidIdentifier { .. })),
                "expected InvalidIdentifier for {bad:?}, got {err:?}"
            );
        }
    }

    /// Every lexer keyword and every non-ASCII name is refused, for both
    /// case classes — the charset and keyword table are the lexer's own.
    #[test]
    fn refuses_every_keyword_and_non_ascii() {
        for class in [SymbolClass::Value, SymbolClass::Type] {
            for kw in ipe_parse::KEYWORDS {
                assert!(
                    matches!(
                        validate_new_name(kw, class),
                        Err(RenameError::InvalidIdentifier { .. })
                    ),
                    "keyword {kw:?} accepted as a {class:?} name"
                );
            }
            for bad in ["caf\u{e9}", "\u{c9}t\u{e9}", "x\u{0301}", "\u{ff58}"] {
                assert!(
                    matches!(
                        validate_new_name(bad, class),
                        Err(RenameError::InvalidIdentifier { .. })
                    ),
                    "non-ASCII {bad:?} accepted as a {class:?} name"
                );
            }
        }
    }

    // ── test 3: symbol not found ──────────────────────────────────────────────

    #[test]
    fn refuses_unknown_symbol() {
        let mut i = Interner::new();
        let (lib_mod, main_mod, consumer_mod, shadow_mod, _helper_sym, lib_sym) =
            build_fixture(&mut i);
        let never_sym = sym(&mut i, "neverDefined");

        let lib_path = lib_mod.name.clone();
        let main_path = main_mod.name.clone();
        let consumer_path = consumer_mod.name.clone();
        let shadow_path = shadow_mod.name.clone();
        let all: &[(&Module, &[Symbol])] = &[
            (&lib_mod, &lib_path),
            (&main_mod, &main_path),
            (&consumer_mod, &consumer_path),
            (&shadow_mod, &shadow_path),
        ];
        let index = ReferenceIndex::build(all);

        let err = rename(&i, &index, all, &[lib_sym], never_sym, "renamed");
        assert!(
            matches!(err, Err(RenameError::SymbolNotFound { .. })),
            "expected SymbolNotFound, got {err:?}"
        );
    }

    // ── test 4: idempotent ────────────────────────────────────────────────────

    #[test]
    fn edit_set_is_identical_on_repeated_calls() {
        let mut i = Interner::new();
        let (lib_mod, main_mod, consumer_mod, shadow_mod, helper_sym, lib_sym) =
            build_fixture(&mut i);

        let lib_path = lib_mod.name.clone();
        let main_path = main_mod.name.clone();
        let consumer_path = consumer_mod.name.clone();
        let shadow_path = shadow_mod.name.clone();
        let all: &[(&Module, &[Symbol])] = &[
            (&lib_mod, &lib_path),
            (&main_mod, &main_path),
            (&consumer_mod, &consumer_path),
            (&shadow_mod, &shadow_path),
        ];
        let index = ReferenceIndex::build(all);

        let r1 =
            rename(&i, &index, all, &[lib_sym], helper_sym, "renamed").expect("first rename ok");
        let r2 =
            rename(&i, &index, all, &[lib_sym], helper_sym, "renamed").expect("second rename ok");
        assert_eq!(r1, r2, "repeated calls must produce the same edit set");
    }

    // ── test 5: capture refusal ───────────────────────────────────────────────

    #[test]
    fn refuses_when_new_name_collides_with_existing_toplevel() {
        // Lib defines both `helper` and `other`.
        // Renaming `helper` → `other` must be refused (CaptureConflict in Lib).
        let mut i = Interner::new();

        let lib_sym = sym(&mut i, "Lib");
        let helper_sym = sym(&mut i, "helper");
        let other_sym = sym(&mut i, "other");
        let main_sym = sym(&mut i, "Main");
        let use_it_sym = sym(&mut i, "use_it");

        let lib_mod = Module {
            name: vec![lib_sym],
            unions: vec![],
            defs: vec![
                value_def(
                    span(10, 16),
                    helper_sym,
                    vec![lib_sym],
                    expr(span(30, 34), Expr_::Unit),
                ),
                value_def(
                    span(20, 25),
                    other_sym,
                    vec![lib_sym],
                    expr(span(35, 39), Expr_::Unit),
                ),
            ],
            imports_unsafe_submodule: false,
            imported_web_capabilities: BTreeSet::new(),
        };
        let lib_path = lib_mod.name.clone();

        let main_mod = bare_module(
            vec![main_sym],
            vec![value_def(
                span(90, 96),
                use_it_sym,
                vec![main_sym],
                expr(
                    span(100, 106),
                    Expr_::VarTopLevel {
                        module: vec![lib_sym],
                        name: helper_sym,
                    },
                ),
            )],
        );
        let main_path = main_mod.name.clone();

        let all: &[(&Module, &[Symbol])] = &[(&lib_mod, &lib_path), (&main_mod, &main_path)];
        let index = ReferenceIndex::build(all);

        let err = rename(&i, &index, all, &[lib_sym], helper_sym, "other");
        assert!(
            matches!(err, Err(RenameError::CaptureConflict { ref new_name, .. }) if new_name == "other"),
            "expected CaptureConflict for 'other', got {err:?}"
        );
    }

    // ── test 6: constructor rename covers declaration, value use, pattern ─────
    //
    // A data constructor is a renameable top-level symbol. Renaming `Red` must
    // edit its declaration in the `type` union, its value use (`VarCtor`), and
    // its `case`-pattern use (`PCtor`) — every site, or the refactor leaves a
    // dangling reference. This pins the constructor path through
    // `find_defining_site`, which value-only lookup skipped (SymbolNotFound).

    #[test]
    fn renames_constructor_declaration_value_use_and_pattern() {
        use crate::ast::{CaseBranch, Ctor, Pattern, Pattern_, Union};

        let mut i = Interner::new();
        let main_sym = sym(&mut i, "Main");
        let color_sym = sym(&mut i, "Color");
        let red_sym = sym(&mut i, "Red");
        let green_sym = sym(&mut i, "Green");
        let pick_sym = sym(&mut i, "pick");
        let describe_sym = sym(&mut i, "describe");
        let c_sym = sym(&mut i, "c");

        // `type Color = Red | Green` — `Red`'s canonical Ctor span begins at its
        // name token, so the declaration name-token span is [40, 43).
        let union = Union {
            home: vec![main_sym],
            name: color_sym,
            vars: vec![],
            ctors: vec![
                Ctor {
                    name: red_sym,
                    index: 0,
                    arity: 0,
                    args: vec![],
                    span: span(40, 43),
                },
                Ctor {
                    name: green_sym,
                    index: 1,
                    arity: 0,
                    args: vec![],
                    span: span(46, 51),
                },
            ],
        };

        // `pick = Red` — a constructor value use (`VarCtor`) at [100, 103).
        let pick_def = value_def(
            span(90, 94),
            pick_sym,
            vec![main_sym],
            expr(
                span(100, 103),
                Expr_::VarCtor {
                    home: vec![main_sym],
                    type_name: color_sym,
                    name: red_sym,
                    index: 0,
                },
            ),
        );

        // `describe c = case c of Red -> ...` — a constructor pattern (`PCtor`)
        // whose name token begins at the pattern's low offset, span [200, 203).
        let red_pat = Pattern {
            span: span(200, 203),
            value: Pattern_::PCtor {
                home: vec![main_sym],
                type_name: color_sym,
                name: red_sym,
                index: 0,
                args: vec![],
            },
        };
        let describe_body = expr(
            span(170, 210),
            Expr_::Case(
                Box::new(expr(span(165, 166), Expr_::VarLocal(c_sym))),
                vec![CaseBranch {
                    pat: red_pat,
                    body: expr(span(207, 208), Expr_::Int(1)),
                }],
            ),
        );
        let describe_def = value_def(span(150, 158), describe_sym, vec![main_sym], describe_body);

        let main_mod = Module {
            name: vec![main_sym],
            unions: vec![union],
            defs: vec![pick_def, describe_def],
            imports_unsafe_submodule: false,
            imported_web_capabilities: BTreeSet::new(),
        };
        let main_path = main_mod.name.clone();
        let all: &[(&Module, &[Symbol])] = &[(&main_mod, &main_path)];
        let index = ReferenceIndex::build(all);

        let edit_set = rename(&i, &index, all, &[main_sym], red_sym, "Crimson")
            .expect("constructor rename must reach the engine and succeed");

        for e in &edit_set.edits {
            assert_eq!(e.replacement, "Crimson");
            assert_eq!(e.file, main_path);
        }

        let mut spans: Vec<(u32, u32)> = edit_set
            .edits
            .iter()
            .map(|e| (e.span.lo, e.span.hi))
            .collect();
        spans.sort_unstable();
        // Declaration name token, value use, pattern name token — all three.
        assert_eq!(
            spans,
            vec![(40, 43), (100, 103), (200, 203)],
            "constructor rename must edit declaration + value use + pattern, got {:?}",
            edit_set.edits
        );
    }
}
