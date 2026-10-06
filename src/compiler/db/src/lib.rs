#![forbid(unsafe_code)]
//! `ipe_db` — the salsa incremental-compilation database.
//!
//! Decision record: `docs/adr/0007-build-incrementality-and-release-infra.md`.
//!
//! The earliest front-end stages sit behind memoized salsa queries:
//!
//! - **Inputs** (the parse-don't-validate boundary): [`SourceFile`] (module
//!   path + text, one per in-scope `.ipe` module) and [`SourceRoot`] (the
//!   in-scope file set — the design spec's `file_set()`).
//! - **Tracked queries**: [`parse`] (per-file AST, errors as values) and
//!   [`imports`] (per-file import list via the same string-scan the driver's
//!   topological sort uses).
//!
//! The canonicalisation tier (spec §5 row 2): [`resolve_imports`] (the
//! closed-enum module-resolution edge, AST-derived), [`canonicalize`]
//! (per-module name resolution), and [`module_interface`] (the export-surface
//! firewall — importers early-cut on dep body-only edits via salsa
//! backdating).
//!
//! INV-1 (no hidden inputs): no query here touches `std::fs`, `std::env`, or
//! the clock. File reading stays in the driver, which is where inputs are set.
//!
//! The interning story is the plan's Option 3a: the database owns a
//! [`SharedInterner`] (`Arc<Mutex<ipe_intern::Interner>>`) shared with the
//! driver. Interning is **append-only** — symbols are never freed or
//! renumbered — so a memoized `Module` from an earlier revision always
//! resolves against the current interner. Symbol *numbering* depends on the
//! query-demand order; the one-shot `ipe` driver demands queries in a fixed
//! topological order against a cold database, so emitted bytes are identical
//! to the non-incremental pipeline (enforced by the golden-oracle suite).
//! Warm-db reuse in production (`ipe dev watch`, the LSP session) is covered by
//! the clean-vs-incremental parity gate
//! (`src/ipe-cli/tests/clean_vs_incremental_parity.rs`), which drives the
//! same [`sync_source_root`] + `compile_prepared` primitives `ipe dev watch`
//! calls and proves warm output byte-identical to a cold build across the
//! full golden corpus plus a dedicated identifier-adding edit sequence. The
//! LSP session never reaches emission (diagnostics-only), so the byte-level
//! hazard this gate guards does not apply to it.

mod metadata;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

/// Re-exported so drivers and tests can name the trust tag and interface
/// type without a direct `ipe_canon` dependency.
pub use ipe_canon::{ModuleExports, ModuleOrigin};
use ipe_diagnostics::Diagnostic;
use ipe_intern::{Interner, Symbol};
use ipe_syntax::Module;
use salsa::Setter as _;

pub use metadata::{ProgramMetadata, ProgramMetadataResult, program_metadata};

// ---------------------------------------------------------------------------
// The shared interner (Option 3a)
// ---------------------------------------------------------------------------

/// A database-owned, append-only interner shared between salsa queries and
/// the (non-salsa) driver stages that still take `&mut Interner`.
///
/// Cloning is cheap (an `Arc` bump) and every clone refers to the same
/// underlying table — symbol identity is preserved across the whole build.
#[derive(Clone, Default)]
pub struct SharedInterner(Arc<Mutex<Interner>>);

impl SharedInterner {
    /// A fresh, empty interner.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Lock the interner for use.
    ///
    /// Poison-safe: interning is append-only, so a panic mid-`intern` cannot
    /// leave the table in a logically-invalid state — recovering the guard
    /// from a poisoned mutex is sound (the same pattern the runtime uses for
    /// its poison-safe locks).
    pub fn lock(&self) -> MutexGuard<'_, Interner> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The underlying `Arc<Mutex<Interner>>` handle.
    ///
    /// Exists alongside [`Self::lock`] for callers that need the Arc ITSELF
    /// rather than a guard — specifically `ipe::cache`'s on-disk lowered-IR
    /// tier, which installs this database's interner as
    /// the ambient `serde` context for `ipe_intern::Symbol`
    /// (`ipe_intern::SerdeInternerGuard::install`) around a
    /// `ipe_ir::Program` (de)serialize call. Cloning the `Arc` is cheap (a
    /// refcount bump); the underlying table is unaffected.
    #[must_use]
    pub const fn as_arc(&self) -> &Arc<Mutex<Interner>> {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// Database
// ---------------------------------------------------------------------------

/// The database trait tracked functions run against: salsa plus access to
/// the shared interner.
#[salsa::db]
pub trait Db: salsa::Database {
    /// The build-wide shared interner (see [`SharedInterner`]).
    fn interner(&self) -> &SharedInterner;
}

/// The concrete Ipê compiler database.
#[salsa::db]
#[derive(Clone, Default)]
pub struct IpeDatabase {
    storage: salsa::Storage<Self>,
    interner: SharedInterner,
}

impl IpeDatabase {
    /// A fresh (cold) database with a fresh interner.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A fresh database that forwards every salsa runtime event to
    /// `callback` — the observability hook the incrementality tests use to
    /// assert memo hits (`EventKind::WillExecute` absence/presence).
    #[must_use]
    pub fn with_event_callback(
        callback: Box<dyn Fn(salsa::Event) + Send + Sync + 'static>,
    ) -> Self {
        Self {
            storage: salsa::Storage::new(Some(callback)),
            interner: SharedInterner::new(),
        }
    }
}

#[salsa::db]
impl salsa::Database for IpeDatabase {}

#[salsa::db]
impl Db for IpeDatabase {
    fn interner(&self) -> &SharedInterner {
        &self.interner
    }
}

// ---------------------------------------------------------------------------
// Inputs (the parse-don't-validate boundary; the driver sets these)
// ---------------------------------------------------------------------------

/// One in-scope `.ipe` module: its module path (identity/diagnostic key) and
/// full UTF-8 source text (the real input).
#[salsa::input(debug)]
pub struct SourceFile {
    /// Module path segments, e.g. `["Std", "List"]`.
    #[returns(ref)]
    pub module_path: Vec<String>,
    /// Full source text.
    #[returns(ref)]
    pub text: String,
    /// The driver-vouched trust tag. `EmbeddedStdlib` is only ever
    /// set by the driver for module paths it injected from the compiler's own
    /// embed table — a user file squatting on `Ipe.Foo` arrives as `User` and
    /// stays IPE-N0025-rejected. Unforgeable from module text by construction:
    /// inputs are set exclusively at the driver boundary.
    pub origin: ModuleOrigin,
}

/// The in-scope file set — the design spec's `file_set()` input. Makes the
/// "ALL modules" quantifier an explicit input rather than an implicit walk.
#[salsa::input]
pub struct SourceRoot {
    /// Module path → source file, for every module in the build.
    #[returns(ref)]
    pub files: BTreeMap<Vec<String>, SourceFile>,
}

/// Driver-boundary helper: update `file`'s text only when the bytes changed.
///
/// Salsa dirties on every `set_*` regardless of value, so the
/// byte-equal-re-save no-op lives here, at the boundary. Returns `true` when
/// a set happened.
pub fn set_text_if_changed(db: &mut IpeDatabase, file: SourceFile, new_text: &str) -> bool {
    if file.text(db) == new_text {
        return false;
    }
    file.set_text(db).to(new_text.to_owned());
    true
}

// ---------------------------------------------------------------------------
// Tracked queries: parse + imports
// ---------------------------------------------------------------------------

/// The memoized result of parsing one module. Errors are **values** — a
/// query must be total, so a red parse yields `Err(diagnostic)` for every
/// downstream consumer instead of unwinding.
pub type ParseResult = Result<Arc<Module>, Diagnostic>;

/// Parse one module. Keyed on `file` — depends only on `text(self)` (plus
/// the append-only shared interner), so an edit to module B never re-parses
/// module A.
#[salsa::tracked]
pub fn parse(db: &dyn Db, file: SourceFile) -> ParseResult {
    let text = file.text(db);
    let mut interner = db.interner().lock();
    ipe_parse::parse_module(text, &mut interner).map(Arc::new)
}

/// The import list of one module, keyed on `file`'s text.
///
/// Backed by [`extract_imports_from_source`] — a token-level scan (real
/// lexer) whose edge set is a superset-or-equal of the AST's import edges,
/// which is what makes the driver's IPE-N0021 cycle gate sound.
/// Deliberately pre-parse rather than derived from [`parse`]: the topo sort
/// must still work on files whose parse would fail (a lex-failing file falls
/// back to the line scan for ordering only — it contributes no AST edges),
/// and deriving from the AST is an observable ordering change that belongs
/// behind the clean-vs-incremental parity gate.
#[salsa::tracked]
pub fn imports(db: &dyn Db, file: SourceFile) -> Arc<Vec<Vec<String>>> {
    Arc::new(extract_imports_from_source(file.text(db)))
}

// ---------------------------------------------------------------------------
// Tracked queries: resolve_imports + module_interface + canonicalize
// ---------------------------------------------------------------------------

/// Closed-enum result of resolving one `import` path against the file set.
///
/// `Ambiguous` (two files claiming one module path) is deliberately absent:
/// [`SourceRoot`]'s `files` map is a `BTreeMap` keyed by module path — the
/// same invariant the driver's source map enforces (its stdlib injection
/// skips pre-existing keys) — so a double claim is *unrepresentable* at the
/// input boundary, not merely checked here.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ImportResolution {
    /// The import names an in-scope project module (user source or injected
    /// compiled-source stdlib).
    Resolved(SourceFile),
    /// Not in the file set: either a kernel module (canonicalisation resolves
    /// those against its built-in table) or a genuinely missing module
    /// (canonicalisation emits IPE-N0020).
    Unresolved,
}

/// Per-import resolutions in import-declaration order, or the module's parse
/// diagnostic (the resolution of an unparseable module is *unknown*, not
/// empty — parse-don't-validate).
pub type ImportResolutions = Result<Arc<Vec<(Vec<String>, ImportResolution)>>, Diagnostic>;

/// Resolve every `import` of `file` against the project file set.
///
/// Derived from the parsed AST, NOT the pre-parse string-scan [`imports`]
/// query — this query's consumer is [`canonicalize`], which iterates the
/// AST's import declarations, so the two must agree exactly. The string-scan
/// stays in service of the driver's topological sort only (recorded parity
/// choice, spec §3.4).
///
/// Reads the whole `files` field, so adding/removing/renaming ANY file
/// re-validates every module's resolutions (the set-vs-contents gate);
/// unchanged results backdate and cut dependents.
#[salsa::tracked]
pub fn resolve_imports(db: &dyn Db, root: SourceRoot, file: SourceFile) -> ImportResolutions {
    let module = parse(db, file).clone()?;
    let files = root.files(db);
    let interner = db.interner().lock();
    let mut resolutions = Vec::with_capacity(module.imports.len());
    for import in &module.imports {
        let path = import
            .name
            .value
            .iter()
            .map(|&segment| {
                interner.resolve(segment).map(str::to_owned).ok_or_else(|| {
                    Diagnostic::CompilerBug {
                        where_: "ipe_db.resolve_imports",
                        detail: "parsed import path contains an unresolvable symbol".to_owned(),
                    }
                })
            })
            .collect::<Result<Vec<String>, Diagnostic>>()?;
        let resolution = files
            .get(&path)
            .map_or(ImportResolution::Unresolved, |dep| {
                ImportResolution::Resolved(*dep)
            });
        resolutions.push((path, resolution));
    }
    Ok(Arc::new(resolutions))
}

/// The output of canonicalising one module: the name-resolved AST plus its
/// export surface.
#[derive(Clone, PartialEq, Debug)]
pub struct CanonicalModule {
    /// The name-resolved module.
    pub module: ipe_canon::ast::Module,
    /// The module's cross-module-observable export surface.
    pub exports: ModuleExports,
}

/// The memoized result of canonicalising one module.
pub type CanonResult = Result<Arc<CanonicalModule>, Diagnostic>;

/// Canonicalise one module: `parse(self)` + `resolve_imports(self)` +
/// `module_interface(dep)` for each resolved dep.
///
/// Import cycles: the driver's topological sort rejects cycles (IPE-N0021)
/// before any `canonicalize` demand. That gate is sound because the topo
/// sort's edge set ([`extract_imports_from_source`], a token-level scan via
/// the real lexer) is a superset-or-equal of the AST import edges this query
/// walks — a scan that missed lexer-legal edges (`import\tB`,
/// `import {- c -} B`) would let a scan-invisible cycle reach salsa's
/// dependency-cycle panic on the production path. A *direct* demand on a
/// cyclic import graph (test/LSP misuse, bypassing the driver's gate) still
/// hits salsa's cycle panic — fail-loud, never a stale or fixpointed value.
#[salsa::tracked]
pub fn canonicalize(db: &dyn Db, root: SourceRoot, file: SourceFile) -> CanonResult {
    let parsed = parse(db, file).clone()?;
    let resolutions = resolve_imports(db, root, file).clone()?;

    // Demand every dep interface BEFORE taking the interner lock: a cold
    // demand recurses into `canonicalize(dep)`, which locks the
    // (non-reentrant) interner itself.
    let mut dep_interfaces: Vec<(Vec<String>, Arc<ModuleExports>)> = Vec::new();
    // Track whether this module imports `Ipe.Ffi.Rust` — the taxonomy-native
    // native-binding qualifier (#1762 ergonomic fix). When it does, the
    // resolver's `canonicalise_asserted_call` rewrites `Rust.fn` calls to
    // references in the driver-generated `Rust.Ffi` forwarder module. Without
    // an explicit `import Rust.Ffi`, that module would be absent from `deps`,
    // causing IPE-N0038 despite a valid call. The fix: auto-inject the
    // `Rust.Ffi` interface when (a) `Ipe.Ffi.Rust` is imported and (b) the
    // driver generated the `Rust.Ffi` module (it is present in `root.files`).
    let mut imports_ipe_ffi_rust = false;
    for (path, resolution) in resolutions.iter() {
        if let ImportResolution::Resolved(dep) = resolution {
            dep_interfaces.push((path.clone(), module_interface(db, root, *dep).clone()?));
        }
        if path.as_slice() == ["Ipe", "Ffi", "Rust"] {
            imports_ipe_ffi_rust = true;
        }
    }
    // Auto-inject `Rust.Ffi` when needed (ergonomic fix for #1762).
    let rust_ffi_path = vec!["Rust".to_owned(), "Ffi".to_owned()];
    if imports_ipe_ffi_rust {
        let files = root.files(db);
        if let Some(rust_ffi_file) = files.get(&rust_ffi_path) {
            // Only inject when not already explicitly imported (already in
            // dep_interfaces at this path) — idempotent.
            let already_present = dep_interfaces
                .iter()
                .any(|(p, _)| p.as_slice() == ["Rust", "Ffi"]);
            if !already_present {
                dep_interfaces.push((
                    rust_ffi_path,
                    module_interface(db, root, *rust_ffi_file).clone()?,
                ));
            }
        }
    }

    // The importable-module catalog: project files plus compiled-source stdlib
    // modules (the kernel paths are seeded by the catalog itself). Read only on
    // diagnostic paths (IPE-N0020 did-you-mean, IPE-N0034 for an unbound
    // qualifier). Strings only: interning module paths here (before their own
    // canonicalize runs) would perturb the build-wide symbol numbering the
    // byte-identity SEAL pins.
    let catalog = ipe_canon::ModuleCatalog::new(
        root.files(db)
            .keys()
            .map(|path| path.join(".").into_boxed_str())
            .chain(
                ipe_stdlib::COMPILED_STD_MODULES
                    .iter()
                    .map(|module| Box::<str>::from(module.dotted)),
            ),
    );
    let origin = file.origin(db);

    // One lock scope covers expected-path interning + canonicalisation — the
    // exact interning sequence the pre-salsa driver produced (dep paths were
    // interned when each dep's own canonicalize ran, so those interns below
    // are lookups, not appends).
    let mut interner = db.interner().lock();
    let expected_path: Vec<Symbol> = file
        .module_path(db)
        .iter()
        .map(|segment| interner.intern(segment))
        .collect::<Result<_, _>>()?;
    let mut deps: BTreeMap<Vec<Symbol>, &ModuleExports> = BTreeMap::new();
    for (path, interface) in &dep_interfaces {
        let key: Vec<Symbol> = path
            .iter()
            .map(|segment| interner.intern(segment))
            .collect::<Result<_, _>>()?;
        deps.insert(key, interface.as_ref());
    }
    let (module, exports) = ipe_canon::canonicalise_module_in_project(
        &parsed,
        &expected_path,
        &deps,
        &catalog,
        *origin,
        &mut interner,
    )?;
    Ok(Arc::new(CanonicalModule { module, exports }))
}

/// The cross-module interface of one module — its export surface, projected
/// out of [`canonicalize`].
///
/// This is the PRIMARY invalidation firewall: when a body-only edit re-runs
/// `canonicalize(A)` but the exports come out **equal**, salsa
/// backdates this query's memo and every importer's `canonicalize` stays
/// valid without re-executing. Deliberately a projection of `canonicalize`
/// rather than a second parse-only summarizer: one export-computation code
/// path can never drift from what canonicalisation actually injects
/// (correctness > efficiency).
///
/// Minimal-invalidation note: [`ModuleExports`] is span-free — every field is
/// keyed by `Symbol`, and exported alias bodies are span-free `TypeAnnotation`s
/// — so a span-only edit (reformatting, a comment) leaves the interface value
/// unchanged and does not re-canonicalise importers. Dependency tracking at
/// this seam is already minimal in both directions: no under-invalidation, and
/// no span-shift over-invalidation to erase.
#[salsa::tracked]
pub fn module_interface(
    db: &dyn Db,
    root: SourceRoot,
    file: SourceFile,
) -> Result<Arc<ModuleExports>, Diagnostic> {
    let canonical = canonicalize(db, root, file).clone()?;
    Ok(Arc::new(canonical.exports.clone()))
}

// ---------------------------------------------------------------------------
// Tracked queries: topo_order + linked_program + kernel_types
// ---------------------------------------------------------------------------

/// An import cycle detected during topological ordering.
///
/// `path` holds the dot-joined module names along the DFS path, ending with
/// the back-edge target (so the first and last entries name the same module
/// when the cycle closes on the DFS root).
#[derive(Clone, Debug)]
pub struct CycleError {
    /// The cycle, in DFS-discovery order (dot-joined module names).
    pub path: Vec<String>,
}

/// DFS stack frame: (`module_path`, `remaining_deps`, `dfs_path_for_cycle_report`).
type DfsFrame = (Vec<String>, Vec<Vec<String>>, Vec<String>);

/// Three-colour DFS node state.
#[derive(PartialEq)]
enum Color {
    White,
    Gray,
    Black,
}

/// Build a dependency-first topological order of `modules` (module paths),
/// given `imports_of(module_path)` returning the modules each source module
/// imports.
///
/// This is the SINGLE topo-sort algorithm: the driver's
/// `ipe::project::topological_order` delegates here (mapping its
/// `DiscoveredModule`s to paths and back), and the memoized [`topo_order`]
/// query calls it directly — one code path, so the two orders can never
/// drift.
///
/// Only modules whose path appears in `modules` are followed; stdlib /
/// kernel imports are silently ignored. The DFS starts from `entry_path`, so
/// the traversal (and therefore the dep-first prefix of the result) is
/// independent of the order of `modules`; modules NOT reachable from the
/// entry are then visited by the SAME DFS in `modules` order, so the whole
/// file set — reachable prefix and orphan suffix alike — is cycle-checked.
///
/// # Errors
/// Returns [`CycleError`] when an import cycle is detected ANYWHERE in the
/// file set, orphans included — this gate is what keeps a cyclic graph away
/// from the recursive `canonicalize` / `module_interface` demands (whose
/// direct misuse would hit salsa's dependency-cycle panic).
pub fn topological_order_paths<F>(
    modules: &[Vec<String>],
    entry_path: &[String],
    imports_of: F,
) -> Result<Vec<Vec<String>>, CycleError>
where
    F: Fn(&[String]) -> Vec<Vec<String>>,
{
    let module_set: BTreeSet<&[String]> = modules.iter().map(Vec::as_slice).collect();

    let mut color: BTreeMap<&[String], Color> = modules
        .iter()
        .map(|m| (m.as_slice(), Color::White))
        .collect();

    let mut result: Vec<Vec<String>> = Vec::new();

    // One stack-based 3-colour DFS, seeded from an arbitrary White root. Both
    // the entry seed and every orphan seed run THIS traversal, so a cycle is
    // detected identically whether or not it is reachable from the entry — the
    // whole file set is cycle-checked, matching the modules `linked_program`
    // will `canonicalize`.
    let dfs_from = |seed: &[String],
                    color: &mut BTreeMap<&[String], Color>,
                    result: &mut Vec<Vec<String>>|
     -> Result<(), CycleError> {
        // Explicit stack avoids recursion-stack overflow on deep dep graphs.
        let mut stack: Vec<DfsFrame> = Vec::new();
        let seed_deps = imports_of(seed)
            .into_iter()
            .filter(|d| module_set.contains(d.as_slice()))
            .collect();
        if let Some(color_seed) = color.get_mut(seed) {
            *color_seed = Color::Gray;
        }
        stack.push((seed.to_vec(), seed_deps, vec![seed.join(".")]));

        while let Some((node, mut deps, dfs_path)) = stack.pop() {
            if let Some(next_dep) = deps.pop() {
                match color.get(next_dep.as_slice()) {
                    Some(Color::Gray) => {
                        // Back edge → cycle. Build the cycle path from this
                        // node's ancestor path (owned here — the node was
                        // popped, not yet re-pushed).
                        let target = next_dep.join(".");
                        let mut cycle_path = dfs_path;
                        cycle_path.push(target);
                        return Err(CycleError { path: cycle_path });
                    }
                    Some(Color::Black) | None => {
                        // Black: already fully visited — skip.
                        // None: not in module_set (stdlib import) — skip;
                        // IPE-N0020 fires later if it's a real local dep that's
                        // missing. Re-push the current node with its remaining
                        // deps, reusing the ancestor path — no child frame needs
                        // a copy here.
                        stack.push((node, deps, dfs_path));
                    }
                    Some(Color::White) => {
                        // First visit — push with its deps. The child's ancestor
                        // path extends this node's, so it is the only copy taken;
                        // the current node is re-pushed with the original.
                        let sub_deps: Vec<Vec<String>> = imports_of(&next_dep)
                            .into_iter()
                            .filter(|d| module_set.contains(d.as_slice()))
                            .collect();
                        if let Some(c) = color.get_mut(next_dep.as_slice()) {
                            *c = Color::Gray;
                        }
                        let mut sub_path = dfs_path.clone();
                        sub_path.push(next_dep.join("."));
                        stack.push((node, deps, dfs_path));
                        stack.push((next_dep, sub_deps, sub_path));
                    }
                }
            } else {
                // All deps processed — mark node Black and record it.
                if let Some(c) = color.get_mut(node.as_slice()) {
                    *c = Color::Black;
                }
                result.push(node);
            }
        }
        Ok(())
    };

    // Seed from `entry_path` first so the reachable prefix (and therefore the
    // byte-identity SEAL against the driver's interning order) is independent
    // of the order of `modules`.
    dfs_from(entry_path, &mut color, &mut result)?;

    // Then seed the SAME cycle-detecting DFS from every module the entry never
    // reached (orphans), in `modules` order. A cycle among orphans surfaces as
    // `CycleError` exactly like a reachable one, so every module
    // `linked_program` canonicalises is cycle-checked — the recursive
    // `canonicalize` / `module_interface` demand can never hit salsa's
    // dependency-cycle panic.
    for m in modules {
        if matches!(color.get(m.as_slice()), Some(Color::White)) {
            dfs_from(m, &mut color, &mut result)?;
        }
    }

    Ok(result)
}

/// The memoized dep-first module order of the whole project, or the
/// IPE-N0021 import-cycle diagnostic.
pub type TopoOrderResult = Result<Arc<Vec<Vec<String>>>, Diagnostic>;

/// The project's dependency-first module order, rooted at `entry`.
///
/// Depends on `files(root)` plus [`imports`] of every file — so an edit that
/// does not change any module's import list backdates every import memo and
/// this order validates without re-sorting. Modules unreachable from the
/// entry are appended after the reachable prefix in sorted module-path order
/// (`SourceRoot.files` is a `BTreeMap`).
///
/// Cycle handling: returns the IPE-N0021 diagnostic as a **value**. This
/// query itself never recurses (the DFS is internal, `imports` is per-file),
/// so demanding it on a cyclic graph is safe — which is exactly why
/// [`linked_program`] routes through it BEFORE demanding any `canonicalize`.
#[salsa::tracked]
pub fn topo_order(db: &dyn Db, root: SourceRoot, entry: SourceFile) -> TopoOrderResult {
    let files = root.files(db);
    let module_paths: Vec<Vec<String>> = files.keys().cloned().collect();
    let entry_path = entry.module_path(db);
    topological_order_paths(&module_paths, entry_path, |path| {
        files
            .get(path)
            .map(|file| (**imports(db, *file)).clone())
            .unwrap_or_default()
    })
    .map(Arc::new)
    .map_err(|cycle| Diagnostic::Name {
        span: ipe_diagnostics::Span::DUMMY,
        msg: ipe_diagnostics::NameError::ImportCycle {
            path: cycle.path.into_iter().map(String::into_boxed_str).collect(),
        },
    })
}

/// The whole-program output of the canonicalisation tier: every module
/// canonicalised and merged (`ipe_canon::link`) into the single module the
/// back half (infer → lower → emit) consumes.
#[derive(Clone, PartialEq, Debug)]
pub struct LinkedProgram {
    /// The entry module's interned path (what `link` keyed the merge on).
    pub entry_name: Vec<Symbol>,
    /// The merged whole-program module.
    pub module: ipe_canon::ast::Module,
}

/// The memoized result of linking the whole program.
pub type LinkedProgramResult = Result<Arc<LinkedProgram>, Diagnostic>;

/// Assemble the per-module [`canonicalize`] results into the linked
/// whole-program module — the COARSE spine.
///
/// Deliberately coarse: any edit that re-canonicalises any module re-links
/// the world (link output value-equality still backdates dependents-to-be).
/// The point is the query **seam**: a per-module `typecheck` / `lower`
/// refinement replaces the consumer side of this query without the driver
/// changing shape, and the clean-vs-incremental parity gate guards that
/// refinement.
///
/// Demand order: modules are canonicalised in the [`topo_order`] dep-first
/// order, which on a cold database reproduces the driver's interning
/// sequence exactly (byte-identity SEAL). The cycle gate runs FIRST, so a
/// cyclic graph yields the IPE-N0021 diagnostic as a value — never salsa's
/// dependency-cycle panic — even on a direct demand.
#[salsa::tracked]
pub fn linked_program(db: &dyn Db, root: SourceRoot, entry: SourceFile) -> LinkedProgramResult {
    let order = topo_order(db, root, entry).clone()?;
    let files = root.files(db);
    let mut modules: Vec<ipe_canon::ast::Module> = Vec::with_capacity(order.len());
    for path in order.iter() {
        let Some(file) = files.get(path) else {
            // Unreachable by construction: `topo_order` only emits keys of
            // `files(root)`. Fail loud as a value, never panic.
            return Err(Diagnostic::CompilerBug {
                where_: "ipe_db.linked_program",
                detail: format!("topo order names unknown module {}", path.join(".")),
            });
        };
        let canonical = canonicalize(db, root, *file).clone()?;
        modules.push(canonical.module.clone());
    }

    // One lock scope for the entry-path interning (lookups — the entry's own
    // canonicalize already interned it) and the link pass (which only reads).
    let mut interner = db.interner().lock();
    let entry_name: Vec<Symbol> = entry
        .module_path(db)
        .iter()
        .map(|segment| interner.intern(segment))
        .collect::<Result<_, _>>()?;
    let module = ipe_canon::link::link(entry_name.clone(), modules, &interner)?;
    // Link was the guard's last consumer; release it before constructing the
    // return value (clippy::significant_drop_tightening).
    drop(interner);
    Ok(Arc::new(LinkedProgram { entry_name, module }))
}

/// The memoized kernel type-scheme table.
pub type KernelTypesResult =
    Result<Arc<Vec<(ipe_kernels::StdlibKernel, ipe_types::Ty)>>, Diagnostic>;

/// The kernel type-scheme table: every schemed
/// [`ipe_kernels::StdlibKernel`] paired with the inference scheme
/// constraint generation applies at its call sites, materialized once per
/// database via [`ipe_types::kernel_type_table`] (the same code path
/// inference reads — no second scheme table to drift).
///
/// Keyed on `root` as the forward seam: when FFI package interfaces become
/// salsa inputs (the parked `ffi_package_interface(PackageId)` query), this
/// query unions them in per project and re-executes only when a package
/// interface changes. Today it reads no input at all, so it never re-executes
/// within a database revision history — a source edit does not re-derive the
/// table.
#[salsa::tracked]
pub fn kernel_types(db: &dyn Db, root: SourceRoot) -> KernelTypesResult {
    // `root` is deliberately unread today (see the doc above); silence the
    // unused-binding without changing the key shape.
    let _ = root;
    let mut interner = db.interner().lock();
    ipe_types::kernel_type_table(&mut interner).map(Arc::new)
}

// ---------------------------------------------------------------------------
// Tracked queries: typecheck + lower — the coarse per-program SEAM
// ---------------------------------------------------------------------------

/// Why [`typecheck`] produced no solved program.
///
/// A link refusal and a type-checker refusal are distinct stages: the link
/// diagnostic is [`linked_program`]'s own, carried verbatim, and is never
/// re-classified as a type-checker error (which must name its owning module).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum TypecheckError {
    /// [`linked_program`] refused the program, so the type checker never ran.
    Link(Diagnostic),
    /// The type checker refused the linked program.
    Infer(ipe_types::InferError),
}

impl TypecheckError {
    /// The refusing diagnostic, whichever stage produced it.
    #[must_use]
    pub const fn diagnostic(&self) -> &Diagnostic {
        match self {
            Self::Link(diag) => diag,
            Self::Infer(err) => err.diagnostic(),
        }
    }
}

/// The memoized result of type-checking [`linked_program`]'s merge.
///
/// The error is why it was refused: the link diagnostic, or the type-checker
/// error sited at its owning module (see [`ipe_types::infer_attributed`]).
pub type TypecheckResult = Result<Arc<ipe_types::SolvedTypes>, TypecheckError>;

/// Type-check the linked whole-program module.
///
/// **This is the coarse per-program SEAM, not per-module typecheck.** Keyed on
/// `(root, entry)` and depending on [`linked_program`], so it inherits exactly
/// the same coarseness: an edit anywhere in the reachable module graph
/// re-executes this query in full, the same work `ipe_types::infer_attributed`
/// does. The result is **memoized**: a repeat demand, or a demand after a
/// byte-equal re-save, executes nothing. Memoizing here is what makes a warm
/// no-op rebuild skip the whole solver instead of re-running it.
///
/// Why not genuinely per-module: `ipe_types::infer_attributed` builds ONE
/// [`ipe_types::unionfind`]-backed constraint graph over the ENTIRE linked
/// module (`Builder::run`), and its post-solve passes — Boundary Scheme
/// Promotion, the field-access/record-update deferred-resolution fixpoint,
/// routed-`Web.tea` witness checks — all operate over that single joint
/// constraint set. Splitting this into a true `typecheck(ModuleId)` query
/// would require re-deriving Ipê's cross-module generalization semantics on
/// top of a scoped per-module solve seeded from deps' TYPED interfaces
/// (schemes, not just the canon-level `ModuleExports` [`module_interface`]
/// carries today) — a structural redesign of `constrain.rs`, not a
/// refactor. See the Phase-4 section of
/// `docs/architecture/salsa-incremental-compilation-2026-07-11.md` for the
/// full analysis and the recorded follow-up scope.
#[salsa::tracked]
pub fn typecheck(db: &dyn Db, root: SourceRoot, entry: SourceFile) -> TypecheckResult {
    let linked = linked_program(db, root, entry)
        .clone()
        .map_err(TypecheckError::Link)?;
    let mut interner = db.interner().lock();
    ipe_types::infer_attributed(&linked.module, &mut interner)
        .map(Arc::new)
        .map_err(TypecheckError::Infer)
}

/// The type-checker's results for ONE module, projected out of the
/// whole-program solve — the per-module query SEAM the LSP consumes.
///
/// Every map is the `(home, _)`-keyed slice of the corresponding
/// [`ipe_types::SolvedTypes`] field where `home` equals this module's path, so
/// a handler that asks for one module's types reads exactly what the
/// whole-program solve produced for that module — never a re-analysis, never a
/// divergent value.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ModuleTypes {
    /// Type of each top-level binding this module declares, keyed by bare name
    /// (the home is fixed to this module, so it drops out of the key).
    pub env: BTreeMap<Symbol, ipe_types::Ty>,
    /// Inferred type of each sub-expression region in this module, keyed by
    /// span.
    pub regions: BTreeMap<ipe_diagnostics::Span, ipe_types::Ty>,
    /// Contextually-expected type at each region in this module (the
    /// type-directed-completion sidecar), keyed by span.
    pub expected: BTreeMap<ipe_diagnostics::Span, ipe_types::Ty>,
    /// Super-type obligations of this module's typed bindings' generic
    /// variables, keyed by bare def name.
    pub bounds: BTreeMap<Symbol, BTreeMap<Symbol, ipe_types::TyBounds>>,
}

/// The memoized per-module result of [`typecheck_module`].
///
/// On the scoped path the module's own solve; on the fallback path the
/// whole-program projection, including the whole-program failure (the same
/// error a whole-program demand surfaces).
pub type ModuleTypesResult = Result<Arc<ModuleTypes>, TypecheckError>;

/// One module's `(home, _)`-slice of a whole-program
/// [`ipe_types::SolvedTypes`] — the [`ModuleTypes`] projection.
#[must_use]
pub fn project_module_types(solved: &ipe_types::SolvedTypes, home: &[Symbol]) -> ModuleTypes {
    use std::ops::Bound;

    // Each map is keyed `(home, _)` and a `BTreeMap` orders by the tuple, so
    // every entry for one `home` is a contiguous run. Range from the run's
    // start (the smallest possible second component) and stop at the first key
    // whose home differs — a scan of one module's slice, not the whole program.
    // The `owned_home` is the range's lower bound; the second component's
    // minimum is the type's own minimum (`Symbol` id `0` / `Span::DUMMY`).
    let owned_home = home.to_vec();
    let regions = solved
        .regions
        .range((
            Bound::Included((owned_home.clone(), ipe_diagnostics::Span::DUMMY)),
            Bound::Unbounded,
        ))
        .take_while(|((h, _), _)| h.as_slice() == home)
        .map(|((_, span), ty)| (*span, ty.clone()))
        .collect();
    let expected = solved
        .expected
        .range((
            Bound::Included((owned_home.clone(), ipe_diagnostics::Span::DUMMY)),
            Bound::Unbounded,
        ))
        .take_while(|((h, _), _)| h.as_slice() == home)
        .map(|((_, span), ty)| (*span, ty.clone()))
        .collect();
    let env = solved
        .env
        .range((
            Bound::Included((owned_home.clone(), Symbol::from_raw(0))),
            Bound::Unbounded,
        ))
        .take_while(|((h, _), _)| h.as_slice() == home)
        .map(|((_, name), ty)| (*name, ty.clone()))
        .collect();
    let bounds = solved
        .bounds
        .range((
            Bound::Included((owned_home, Symbol::from_raw(0))),
            Bound::Unbounded,
        ))
        .take_while(|((h, _), _)| h.as_slice() == home)
        .map(|((_, name), b)| (*name, b.clone()))
        .collect();
    ModuleTypes {
        env,
        regions,
        expected,
        bounds,
    }
}

/// Canonically renumber every TAGGED solver variable in a [`ModuleTypes`]
/// value.
///
/// First-encounter order over the deterministic `env` → `regions` →
/// `expected` iteration; annotation-symbol variables are untouched.
///
/// Residual solver-variable NUMBERING is an artifact of the producing solve
/// (the whole-program union-find numbers variables across every module; a
/// scoped solve numbers its own) — no consumer reads the raw id (hover
/// renders through [`ipe_types::VarNamer`]; completion classifies by type
/// head). Normalizing at the query boundary makes the scoped result and the
/// whole-program projection byte-comparable (the scoped-vs-whole parity
/// gate), and stabilizes this query's memo against joint-solve renumbering
/// noise after unrelated edits (backdating that the raw ids would defeat).
#[must_use]
pub fn normalize_module_types(types: ModuleTypes) -> ModuleTypes {
    fn renumber(ty: &ipe_types::Ty, map: &mut BTreeMap<u32, u32>) -> ipe_types::Ty {
        use ipe_types::{RowTail, Ty};
        let fresh = |raw: u32, map: &mut BTreeMap<u32, u32>| -> u32 {
            if !ipe_types::is_solver_var(raw) {
                return raw;
            }
            let next = u32::try_from(map.len()).unwrap_or(u32::MAX);
            ipe_types::tag_solver_var(*map.entry(raw).or_insert(next))
        };
        match ty {
            Ty::Var(raw) => Ty::Var(fresh(*raw, map)),
            Ty::Unit => Ty::Unit,
            Ty::Fun(a, b) => Ty::Fun(Box::new(renumber(a, map)), Box::new(renumber(b, map))),
            Ty::Tuple(elems) => Ty::Tuple(elems.iter().map(|e| renumber(e, map)).collect()),
            Ty::Record(fields, tail) => Ty::Record(
                fields
                    .iter()
                    .map(|(name, t)| (*name, renumber(t, map)))
                    .collect(),
                match tail {
                    RowTail::Closed => RowTail::Closed,
                    RowTail::Open(raw) => RowTail::Open(fresh(*raw, map)),
                },
            ),
            Ty::Con { module, name, args } => Ty::Con {
                module: module.clone(),
                name: *name,
                args: args.iter().map(|a| renumber(a, map)).collect(),
            },
        }
    }

    let mut map: BTreeMap<u32, u32> = BTreeMap::new();
    let env = types
        .env
        .iter()
        .map(|(name, ty)| (*name, renumber(ty, &mut map)))
        .collect();
    let regions = types
        .regions
        .iter()
        .map(|(span, ty)| (*span, renumber(ty, &mut map)))
        .collect();
    let expected = types
        .expected
        .iter()
        .map(|(span, ty)| (*span, renumber(ty, &mut map)))
        .collect();
    ModuleTypes {
        env,
        regions,
        expected,
        bounds: types.bounds,
    }
}

/// The memoized outcome of one module's scoped solve — either a genuinely
/// per-module result, or the honest verdict that only the whole-program
/// solve is faithful for this module.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ScopedModuleTypes {
    /// The module's scoped solve is green, every dep interface is closed,
    /// and the module's own interface is closed — the per-module result
    /// stands for the joint solve's slice (the scoped-vs-whole parity gate
    /// proves the equivalence over the golden corpus).
    PerModule {
        /// The module's [`ModuleTypes`], normalized.
        types: Arc<ModuleTypes>,
        /// The module's closed typed interface, for importers' scoped solves.
        interface: Arc<ipe_types::TypedInterface>,
    },
    /// The module's interface is closed, so its importers solve against it,
    /// but its own solved facts read its importers' use sites: the module's
    /// own types come from the whole-program solve.
    InterfaceOnly {
        /// The module's closed typed interface, for importers' scoped solves.
        interface: Arc<ipe_types::TypedInterface>,
    },
    /// Fall back to the whole-program solve: the module's scoped solve was
    /// red, a dep's (or its own) interface is open (an importer can pin a
    /// residual variable — information flows against the import direction),
    /// or the import graph is cyclic. Under-invalidation outranks latency:
    /// a scoped result that could disagree with the joint solve is never
    /// served.
    WholeProgram,
}

/// One module's scoped solve over its deps' typed interfaces — the
/// genuinely-per-module tier behind [`typecheck_module`].
///
/// Demands `typed_interface(dep)` for every resolved dep BEFORE running
/// [`ipe_types::infer_module`] over this module's own canonical AST: the
/// cross-module generalization order (Boundary Scheme Promotion's
/// dependency-first `module_order` walk in the joint solve) is expressed as
/// a salsa dependency EDGE, so the invalidation firewall is structural. A
/// dep body edit re-runs the dep's scoped solve; when the dep's interface
/// comes out equal, `typed_interface` backdates and THIS query's memo
/// stands without re-executing.
///
/// Total (never `Err`): every shortfall — cycle, red parse/canon/solve,
/// open interface anywhere — yields [`ScopedModuleTypes::WholeProgram`],
/// and [`typecheck_module`] surfaces the joint solve's own result (and its
/// exact diagnostics) for such modules. The cycle gate reuses [`topo_order`]
/// with this module as the DFS root, so a cyclic graph resolves as a value
/// here and never reaches the recursive `typed_interface` demand (salsa's
/// dependency-cycle panic stays unreachable on this path).
#[salsa::tracked]
pub fn infer_module_scoped(db: &dyn Db, root: SourceRoot, module: SourceFile) -> ScopedModuleTypes {
    if topo_order(db, root, module).is_err() {
        return ScopedModuleTypes::WholeProgram;
    }
    let Ok(canonical) = canonicalize(db, root, module) else {
        return ScopedModuleTypes::WholeProgram;
    };
    let Ok(resolutions) = resolve_imports(db, root, module) else {
        return ScopedModuleTypes::WholeProgram;
    };

    // Demand every dep interface BEFORE taking the interner lock: a cold
    // demand recurses into `infer_module_scoped(dep)`, which locks the
    // (non-reentrant) interner itself.
    let mut dep_interfaces: Vec<(Vec<String>, Arc<ipe_types::TypedInterface>)> = Vec::new();
    for (path, resolution) in resolutions.iter() {
        if let ImportResolution::Resolved(dep) = resolution {
            let Some(interface) = typed_interface(db, root, *dep) else {
                return ScopedModuleTypes::WholeProgram;
            };
            dep_interfaces.push((path.clone(), interface.clone()));
        }
    }

    let mut interner = db.interner().lock();
    let intern_path =
        |interner: &mut ipe_intern::Interner, path: &[String]| -> Result<Vec<Symbol>, Diagnostic> {
            path.iter()
                .map(|segment| interner.intern(segment))
                .collect::<Result<_, _>>()
        };
    let mut deps: BTreeMap<Vec<Symbol>, Arc<ipe_types::TypedInterface>> = BTreeMap::new();
    for (path, interface) in dep_interfaces {
        let Ok(key) = intern_path(&mut interner, &path) else {
            return ScopedModuleTypes::WholeProgram;
        };
        deps.insert(key, interface);
    }
    let Ok(home) = intern_path(&mut interner, module.module_path(db)) else {
        return ScopedModuleTypes::WholeProgram;
    };

    match ipe_types::infer_module(&canonical.module, &canonical.exports, &deps, &mut interner) {
        Ok(inference) => match inference.interface {
            ipe_types::InterfaceStatus::Closed(interface) => {
                drop(interner);
                let types = normalize_module_types(project_module_types(&inference.solved, &home));
                ScopedModuleTypes::PerModule {
                    types: Arc::new(types),
                    interface: Arc::new(interface),
                }
            }
            ipe_types::InterfaceStatus::ImporterDependent(interface) => {
                ScopedModuleTypes::InterfaceOnly {
                    interface: Arc::new(interface),
                }
            }
            ipe_types::InterfaceStatus::Open => ScopedModuleTypes::WholeProgram,
        },
        Err(_) => ScopedModuleTypes::WholeProgram,
    }
}

/// The typed cross-module interface of one module, projected out of
/// [`infer_module_scoped`] — the typed tier's invalidation firewall, the
/// [`module_interface`] sibling one level up.
///
/// `None` means OPEN: no per-module interface is faithful for this module
/// (see [`ScopedModuleTypes::WholeProgram`]), and every importer's scoped
/// solve must fall back to the whole-program path. Deliberately a projection
/// of the scoped solve rather than a second scheme summarizer: one
/// scheme-computation code path can never drift from what the scoped solve
/// actually instantiates.
#[salsa::tracked]
pub fn typed_interface(
    db: &dyn Db,
    root: SourceRoot,
    module: SourceFile,
) -> Option<Arc<ipe_types::TypedInterface>> {
    match infer_module_scoped(db, root, module) {
        ScopedModuleTypes::PerModule { interface, .. }
        | ScopedModuleTypes::InterfaceOnly { interface } => Some(interface.clone()),
        ScopedModuleTypes::WholeProgram => None,
    }
}

/// Type-check `module` (the per-module query).
///
/// Keyed `(root, entry, module)`; consumers read one module's types by name.
/// Two bodies behind one contract:
///
/// - **Scoped path** (the common case): [`infer_module_scoped`] solved this
///   module over its deps' CLOSED typed interfaces. The result depends on
///   this module's own canonicalisation and its deps' `typed_interface`
///   values only — an edit to an unrelated module leaves this memo
///   untouched, and a dep body edit that preserves the dep's exported
///   schemes backdates away before reaching it. On this path a red edit
///   elsewhere in the program does not blank this module's types
///   (diagnostics still come from the whole-program [`typecheck`]).
/// - **Fallback path**: the whole-program projection, for modules the
///   scoped tier cannot faithfully stand for (open interfaces, own facts
///   that read an importer's use site, red scoped solve, import cycle) — exactly the joint solve's slice, with the joint
///   solve's own error surfaced verbatim on a red program.
///
/// Both paths return NORMALIZED values (see [`normalize_module_types`]);
/// the scoped-vs-whole parity gate proves them equal wherever the scoped
/// path engages.
#[salsa::tracked]
pub fn typecheck_module(
    db: &dyn Db,
    root: SourceRoot,
    entry: SourceFile,
    module: SourceFile,
) -> ModuleTypesResult {
    match infer_module_scoped(db, root, module) {
        ScopedModuleTypes::PerModule { types, .. } => Ok(types.clone()),
        ScopedModuleTypes::InterfaceOnly { .. } | ScopedModuleTypes::WholeProgram => {
            let solved = typecheck(db, root, entry).clone()?;
            let home: Vec<Symbol> = {
                let mut interner = db.interner().lock();
                module
                    .module_path(db)
                    .iter()
                    .map(|segment| interner.intern(segment))
                    .collect::<Result<_, _>>()
                    .map_err(|d| TypecheckError::Infer(ipe_types::InferError::unsited(d)))?
            };
            Ok(Arc::new(normalize_module_types(project_module_types(
                &solved, &home,
            ))))
        }
    }
}

/// Why the pipeline up to lowering refused a program.
///
/// A type-checker error keeps its typed site; a link or lowering error is the
/// diagnostic paired with the module path the lowerer blamed, empty when it
/// blamed none.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum PipelineError {
    /// The type checker refused the program.
    Infer(ipe_types::InferError),
    /// Linking or lowering refused the program.
    Lower(Diagnostic, Vec<Symbol>),
}

impl From<TypecheckError> for PipelineError {
    /// A link refusal is the link diagnostic with no blamed module, exactly as
    /// [`lower_program`] reports a link refusal of its own.
    fn from(err: TypecheckError) -> Self {
        match err {
            TypecheckError::Link(diag) => Self::Lower(diag, Vec::new()),
            TypecheckError::Infer(err) => Self::Infer(err),
        }
    }
}

impl From<PipelineError> for (Diagnostic, Vec<Symbol>) {
    /// The diagnostic with its owning module path, empty for a whole-program one.
    fn from(err: PipelineError) -> Self {
        match err {
            PipelineError::Infer(ipe_types::InferError::Sited { diag, home }) => {
                (diag, home.into_path())
            }
            PipelineError::Infer(ipe_types::InferError::Program(program)) => {
                (program.into_diagnostic(), Vec::new())
            }
            PipelineError::Lower(diag, home) => (diag, home),
        }
    }
}

/// The memoized result of lowering [`linked_program`]'s whole-program merge
/// against [`typecheck`]'s solved types into the backend-agnostic IR.
pub type LowerResult = Result<Arc<ipe_ir::Program>, PipelineError>;

/// Lower the linked whole-program module.
///
/// **Coarse per-program SEAM**, the [`typecheck`] sibling: depends on
/// [`linked_program`] and [`typecheck`], so it re-executes exactly when
/// either would re-run `ipe_lower::lower`, now as a memoized salsa node — a
/// repeat demand or a no-op re-save executes nothing.
///
/// Why not genuinely per-module: beyond inheriting `typecheck`'s coupling
/// (lowering reads [`ipe_types::SolvedTypes`], itself whole-program), the
/// monotonic-cursor fresh-symbol pools (`arg_`, `anyp_`, `destr_thunk_`,
/// `ncons_`, `nstrlit_`) number each site from `lower::count_*_sites(m)` over
/// every def in the merged module, so a site's name depends on how many sites
/// precede it program-wide. A per-module lowering pass needs those pools
/// restructured into a per-module allocation scheme (module-base offset + local
/// index) that reproduces the whole-program numbering the golden-oracle SEAL
/// pins — not yet wired. The position-indexed
/// `eta_` / `cap_` pools are already per-module-decoupled
/// (`lower::max_def_arity_per_module`).
#[salsa::tracked]
pub fn lower_program(db: &dyn Db, root: SourceRoot, entry: SourceFile) -> LowerResult {
    let linked = linked_program(db, root, entry)
        .clone()
        .map_err(|d| PipelineError::Lower(d, Vec::new()))?;
    let types = typecheck(db, root, entry)
        .clone()
        .map_err(PipelineError::from)?;
    let mut interner = db.interner().lock();
    // Provide the entry file's display path and source text so the lowerer
    // can inject `<file>:<line>` into `Debug.todo` call sites.
    let src_path = entry.module_path(db).join(".");
    let src_path = format!("{src_path}.ipe");
    let src_text = entry.text(db).clone();
    ipe_lower::lower(&linked.module, &types, &mut interner, &src_path, &src_text)
        .map(Arc::new)
        .map_err(|(diag, home)| PipelineError::Lower(diag, home))
}

/// [`lower_program`]'s IR after Phase-2 partial evaluation — the ONE program the
/// backend emits from.
///
/// Runs [`ipe_backend_rust::fold_program`] over the lowered program: a pure
/// literal builder pipeline feeding an appearance-kernel argument
/// (`Ipe.Ui.Animation` / `Ipe.Css`) folds to a direct literal, so the
/// appearance-literal registry hot-swaps it downstream. The fold is
/// value-preserving, so a folded program emits the same behaviour as the
/// unfolded one — only the appearance argument is now a direct literal the
/// registry recognises.
///
/// Every emit entry ([`emit_project`], [`emit_spine_file`], [`emit_rust_file`],
/// [`emit_manifest`]) reads THIS query rather than [`lower_program`] directly,
/// so the fold applies uniformly across the single-file and the multi-module
/// split paths — the two paths render from the identical folded IR.
#[salsa::tracked]
pub fn folded_program(db: &dyn Db, root: SourceRoot, entry: SourceFile) -> LowerResult {
    let lowered = lower_program(db, root, entry).clone()?;
    let mut program = (*lowered).clone();
    let interner = db.interner().lock();
    ipe_backend_rust::fold_program(&mut program, &interner);
    Ok(Arc::new(program))
}

// ---------------------------------------------------------------------------
// Per-Rust-file salsa domain
// (spec: `docs/architecture/phase5-emit-rust-file-design-2026-07-12.md` §4.1)
// ---------------------------------------------------------------------------

/// One Rust source file the backend emits for a Ipê module's OWN
/// declarations (§4.1). A genuine `#[salsa::interned]` key: interning the
/// same `home` twice returns the same salsa id, so a per-file emit query
/// keyed on it memoizes independently of every OTHER file.
///
/// **Distinct from [`ipe_backend_rust`]'s own `RustFileId`.** That backend
/// type is a plain, non-interned `enum { Spine, IpeModule(ModPath) }`
/// used internally for partitioning; it never reaches salsa. This one is the
/// salsa domain: it carries ONLY a `home` (`Spine` is NOT a `RustFileId` —
/// it is always present and never added/removed by a module add/delete, so it
/// is produced by the separate [`emit_spine_file`] query, §4.2).
///
/// [`ipe_ir::ModPath`] already derives `Clone + Eq + Ord + Hash`
/// (`crates/ipe_ir/src/ir.rs`) — usable as a `#[salsa::interned]` field with
/// no new trait work.
#[salsa::interned(debug)]
pub struct RustFileId {
    /// The Ipê module's defining path (`ipe_ir::Func::home` /
    /// `EnumDef::home`'s value) — never empty on the real driver path.
    pub home: ipe_ir::ModPath,
}

// ---------------------------------------------------------------------------
// Tracked queries: `BuildConfig` + emit_project
// ---------------------------------------------------------------------------

/// The build-wide, driver-supplied configuration that affects **emission**
/// but nothing upstream of it — today exactly the `package.ipe [database]
/// driver` selection.
///
/// This is the incremental plan's `project_config()` seam (design doc Q1b),
/// deliberately narrowed to the ONE field that has a real tracked-query
/// consumer today ([`emit_project`]) rather than the full parsed-`package.ipe`
/// shape the design doc sketches (`entry`, `codegen_flags`, `[log]`
/// fields, …). The discipline: reserved seams stay design-level until a real
/// consumer exists — a `ProjectConfig` with fields nothing reads is a
/// dead-surface trap. `db_driver` earns its place because [`emit_project`]
/// genuinely reads it (routing `RustBackend::with_db_driver`), and nothing
/// upstream of emission (`canonicalize`, `typecheck`, `lower_program`) is
/// affected by the SQL driver choice — `package.ipe`'s driver key changes the
/// emitted `Cargo.toml`/`ipe_runtime/config.rs` shape only.
///
/// **Field-granularity, honestly scoped.** Salsa's `#[salsa::input]` macro
/// already tracks reads PER FIELD (verified against the `salsa-0.27.2`
/// source: `IngredientImpl::field` reports a tracked read keyed on
/// `(ingredient_index.successor(field_index), id)`, not on the whole
/// struct) — so a struct with two build-relevant fields would already get
/// the design doc's "editing field A doesn't invalidate a query that only
/// reads field B" property for free, with no hand-rolled projection query
/// needed. `BuildConfig` has exactly ONE field today because no second
/// field has a real consumer yet — so the MULTI-field half of the
/// field-granularity story
/// (`config_entry()` vs `config_log_level()` both projected off one
/// `ProjectConfig`) is honestly out of scope until a second field earns its
/// place. What this DOES prove today or scope, and what the
/// `emit_project_config_change_does_not_retrigger_lower` test asserts, is
/// the field's other half: a `BuildConfig`-only change never re-executes
/// [`linked_program`] / [`typecheck`] / [`lower_program`] — config lives on
/// its own input, entirely separate from [`SourceRoot`]/[`SourceFile`].
#[salsa::input]
pub struct BuildConfig {
    /// The SQL driver the emitted project targets (from `package.ipe`).
    /// See [`ipe_backend_rust::DbDriver`].
    pub db_driver: ipe_backend_rust::DbDriver,
    /// The consumer-side FFI emission inputs (installed foreign-crate
    /// bindings + opaque-type map + pinned dep lines), assembled by the
    /// driver from the project's FFI artifact cache. `None` for a project
    /// with no installed FFI crates. See [`ipe_backend_rust::FfiEmit`].
    #[returns(ref)]
    pub ffi: Option<ipe_backend_rust::FfiEmit>,
    /// The compilation target (`Native` | `WasmClient` under
    /// `ipe dev build --target wasm`) — selects the emitted manifest template,
    /// vendored runtime module set, and entry shape.
    pub target: ipe_ir::Target,
    /// The `[wasm] publicEnv` allowlist from `package.ipe`, already validated
    /// against the secret-name denylist at PARSE time. Empty when the
    /// section/key is absent. See [`ipe_backend_rust::RustBackend::with_wasm_public_env`].
    #[returns(ref)]
    pub wasm_public_env: Vec<String>,
    /// The mount base the emitted browser shell is served under, parsed once
    /// from the manifest's `browser.basePath`; the root for a single file.
    /// See [`ipe_backend_rust::RustBackend::with_mount_base`].
    #[returns(ref)]
    pub mount_base: ipe_backend_rust::MountBase,
    /// `true` when `[wasm] mode = "hydrate"` is set in `package.ipe`. Passed
    /// through to [`ipe_backend_rust::RustBackend::with_wasm_hydrate_mode`]
    /// to emit the `#[wasm_bindgen] pub fn hydrate(…)` export (M7 SSR +
    /// hydration island parse + adopt path).
    pub wasm_hydrate_mode: bool,
    /// The verb family the build serves. A `Release` build rejects
    /// development-only escape hatches (`Debug.*`) at emit demand (IPE-L0140)
    /// so a shipped program never carries a debug window; a `Development`
    /// build selects the runtime `dev-posture` feature (see
    /// [`ipe_backend_rust::RustBackend::with_build_intent`]). Lives on
    /// `BuildConfig` (not `SourceRoot`) so toggling it re-runs only
    /// [`emit_project`], never [`lower_program`] / [`typecheck`].
    pub intent: ipe_backend_rust::BuildIntent,
    /// The dependency-model emit selector (opt-in `IPE_RUNTIME_DEP`). `Some` —
    /// the emitted native project declares the runtime as the resolved path
    /// dependency with a `runtime_features`-selected feature list and vendors no
    /// runtime source; `None` (the default) emits the byte-identical vendored
    /// project. Threaded to [`ipe_backend_rust::RustBackend::with_runtime_dep`].
    #[returns(ref)]
    pub runtime_dep: Option<ipe_backend_rust::RuntimeDep>,
    /// `true` when `ipe dev build/run --debugger` selected the development-only
    /// time-travelling debugger. Threaded to
    /// [`ipe_backend_rust::RustBackend::with_debugger`], which adds the runtime
    /// `debugger` feature to the emitted project's dependency feature list so the
    /// TEA driver records each step. Lives on `BuildConfig` (not `SourceRoot`) so
    /// toggling it re-runs only the emit demand, never lower/typecheck. Never set
    /// for `ipe release` — the release command does not expose the flag, so no
    /// production artifact carries recorder code.
    pub debugger: bool,
    /// The project name from `package.ipe`, already sanitized via
    /// [`ipe_backend_rust::sanitize_cargo_name`] by the driver before storage.
    /// Threaded to [`ipe_backend_rust::RustBackend::with_project_name`] so the
    /// emitted crate carries `[package] name = "<cargo_name>"` rather than the
    /// fixed `"ipe-app"`. An empty string signals "use the `ipe-app` default".
    #[returns(ref)]
    pub cargo_name: String,
    /// `true` when the dev-only `IPE_WATCH_HOT_APPEARANCE` flag is set. Threaded
    /// to [`ipe_backend_rust::RustBackend::with_hot_appearance`], which routes
    /// style-value literals through a per-view `LiteralTable` for appearance
    /// hot-swap. Lives on `BuildConfig` (not `SourceRoot`) so toggling it re-runs
    /// only the emit demand, never lower/typecheck. Read from the environment
    /// once by the CLI when the config is built; default off ⇒ byte-identical
    /// emit.
    pub hot_appearance: bool,
    /// `true` when the resolved delivery is `web desktop` (webview-native).
    /// Threaded to [`ipe_backend_rust::RustBackend::with_webview_host`], which
    /// forces the `uses_webview` signal so the emitted project selects the
    /// webview executor and promotes `webview` to the default feature list. The
    /// webview delivery is a resolved HOST decision (from the CLI's
    /// shape × runtime × host), not a source entry — lives on `BuildConfig` so
    /// toggling it re-runs only the emit demand. Default off ⇒ served `web`.
    pub webview_host: bool,
}

/// The memoized result of emitting the linked, lowered program to Rust
/// source text.
// Error carries the owning-module `home` (empty for a homeless backend/emit
// diagnostic) so the driver attributes a LOWERING error surfaced through the
// emit demand to the correct source file, mirroring [`TypecheckResult`]. A
// pure-backend emit error is homeless → driver heuristic.
pub type EmitResult = Result<Arc<ipe_backend::EmittedProject>, (Diagnostic, Vec<Symbol>)>;

/// The production `Debug.*` gate (IPE-L0140): a `release` build rejects any
/// reachable development-only escape hatch (`Debug.log` / `Debug.todo` /
/// `Debug.explain`) fail-closed. Membership in `Ipe.Debug` is the gate — the
/// lowerer sets `uses_debug` unconditionally on any module whose surviving
/// (DCE-reachable) IR names a dev-only kernel, so a dead-code `Debug.*` that
/// prunes away never trips it.
///
/// This is the SINGLE gate site, called from every emit route: the
/// single-home collapse ([`emit_project`]) AND the multi-home split assembly
/// ([`emit_manifest`]). Both must gate — a program that pulls in a
/// compiled-source stdlib module (`Ipe.Ui`, `Ipe.Tea.Web`, …) has two or more
/// emitted homes and takes the split path, so gating only the collapse path
/// would let a reachable `Debug.explain` in a rendered view ship.
fn reject_dev_only_in_production(
    db: &dyn Db,
    program: &ipe_ir::Program,
    config: BuildConfig,
) -> Result<(), (Diagnostic, Vec<Symbol>)> {
    if *config.intent(db) == ipe_backend_rust::BuildIntent::Release
        && let Some(home) = program
            .modules
            .iter()
            .find(|m| m.uses_debug)
            .map(|m| m.name.0.clone())
    {
        let diag = Diagnostic::Lower {
            span: ipe_diagnostics::Span::DUMMY,
            msg: ipe_diagnostics::LowerError::DevOnlyKernelInProduction {
                kernel: "Debug.*".into(),
            },
        };
        return Err((diag, home));
    }
    Ok(())
}

/// Emit [`lower_program`]'s IR to a Rust [`ipe_backend::EmittedProject`].
///
/// **Coarse per-program SEAM**, the [`lower_program`] sibling: depends on
/// [`lower_program`] (the IR) and [`BuildConfig::db_driver`] (the ONE
/// emit-relevant config field), so it re-executes exactly when either would
/// re-run [`ipe_backend_rust::RustBackend::emit`], now as a memoized salsa
/// node. Memoizing here — the same win [`typecheck`]/[`lower_program`] get one
/// layer up the pipeline — is what lets a warm no-op rebuild skip the whole
/// backend pass instead of re-running it.
///
/// Depending on `config` (not just `root`/`entry`) is what makes the
/// field-granularity property observable: a `db_driver` edit re-executes
/// THIS query without touching [`linked_program`] / [`typecheck`] /
/// [`lower_program`] at all — proven by
/// `emit_project_config_change_does_not_retrigger_lower`
/// (`crates/ipe_db/tests/phase6_build_config.rs`).
#[salsa::tracked]
pub fn emit_project(
    db: &dyn Db,
    root: SourceRoot,
    entry: SourceFile,
    config: BuildConfig,
) -> EmitResult {
    use ipe_backend::Backend as _;

    let program = folded_program(db, root, entry).clone()?;

    reject_dev_only_in_production(db, &program, config)?;

    let driver = *config.db_driver(db);
    let ffi = config.ffi(db).clone();
    let target = *config.target(db);
    let wasm_public_env = config.wasm_public_env(db).clone();
    let mount_base = config.mount_base(db).clone();
    let wasm_hydrate_mode = *config.wasm_hydrate_mode(db);
    let runtime_dep = config.runtime_dep(db).clone();
    let debugger = *config.debugger(db);
    let cargo_name = config.cargo_name(db).clone();
    let hot_appearance = *config.hot_appearance(db);
    let webview_host = *config.webview_host(db);
    let intent = *config.intent(db);
    let interner = db.interner().lock();
    ipe_backend_rust::RustBackend::new(&interner)
        .with_db_driver(driver)
        .with_ffi(ffi)
        .with_target(target)
        .with_wasm_public_env(wasm_public_env)
        .with_mount_base(mount_base)
        .with_wasm_hydrate_mode(wasm_hydrate_mode)
        .with_runtime_dep(runtime_dep)
        .with_debugger(debugger)
        .with_project_name(&cargo_name)
        .with_hot_appearance(hot_appearance)
        .with_webview_host(webview_host)
        .with_build_intent(intent)
        .emit(&program)
        .map(Arc::new)
        .map_err(|d| (d, Vec::new()))
}

// ---------------------------------------------------------------------------
// The per-Rust-file tracked query graph
// (spec: `docs/architecture/phase5-emit-rust-file-design-2026-07-12.md` §4.2)
// ---------------------------------------------------------------------------

/// The memoized text of ONE emitted Rust file.
///
/// `Spine`'s content, or a single Ipê-module's own file. Same
/// `Result<Arc<..>, Diagnostic>` shape as [`EmitResult`], carrying the
/// rendered `String` rather than a whole project.
pub type EmitTextResult = Result<Arc<String>, (Diagnostic, Vec<Symbol>)>;

/// The set of [`RustFileId`]s the program emits an OWN Ipê-module file for —
/// the `home`-set quantifier (§4.2). Mirrors `program_metadata`'s
/// `program_modules()` role in the original design doc: it makes "which files
/// exist" a first-class, salsa-tracked value, so an add/delete of a Ipê module
/// (which changes the `home` set) is a VISIBLE dependency edge, not an implicit
/// side effect of [`lower_program`] re-running.
///
/// Depends only on [`lower_program`] (the IR) — the `home` set is a pure
/// function of the lowered program's items, independent of the emit config.
/// Wraps the thin backend helper [`ipe_backend_rust::rust_file_homes`]
/// (`partition_items`' `IpeModule` bucket keys, `Spine` excluded).
///
/// **Return shape — honest deviation from §4.2's `Arc<BTreeSet<RustFileId>>`.**
/// A `#[salsa::interned]` key derives `Eq`/`Hash` but NOT `Ord`, so it cannot
/// populate a `BTreeSet`; and its `'db` lifetime cannot be memoized inside an
/// `Arc<_>` container from a `#[salsa::tracked]` fn taking a `&dyn Db` trait
/// object (salsa's `Update` machinery demands `'static` there). So this query
/// returns the home set as an OWNED, `'static`, DETERMINISTICALLY-ORDERED
/// `Vec<ModPath>` — built straight from the backend's `BTreeSet<ModPath>`
/// (`rust_file_homes`), so its order and uniqueness are the `BTreeSet`'s.
/// The salsa `RustFileId` domain remains load-bearing where it matters — as
/// the per-file KEY of [`emit_rust_file`]; callers intern each `home` to a
/// `RustFileId` at the demand site ([`emit_manifest`] does exactly this). This
/// preserves §4.2's whole point for THIS query — making "which files exist" a
/// first-class, salsa-tracked value whose change (a module add/delete) is a
/// visible dependency edge — without paying a container-of-interned-keys
/// lifetime tax that buys nothing here.
#[salsa::tracked]
pub fn program_rust_file_ids(
    db: &dyn Db,
    root: SourceRoot,
    entry: SourceFile,
) -> Result<Arc<Vec<ipe_ir::ModPath>>, (Diagnostic, Vec<Symbol>)> {
    let program = lower_program(db, root, entry).clone()?;
    let homes = {
        let interner = db.interner().lock();
        ipe_backend_rust::rust_file_homes(&program, &interner)
    };
    Ok(Arc::new(homes.into_iter().collect()))
}

/// The `Spine` tier's text (§4.2): preamble, kernel-wrapper prelude, record
/// structs, DB-projection impls, TEA/Auth aliases, epilogue, `fn main()`, and
/// the `Spine`-bucket `SqlValue`/`SqlField` enums — everything that is
/// program-wide rather than Ipê-module-owned. The `mod`/`pub(crate) use`
/// barrel lines are NOT baked in here (they are a pure function of
/// [`program_rust_file_ids`]); [`emit_manifest`] appends them during assembly,
/// keeping this query's memoized value byte-stable under a barrel-only change.
///
/// Depends on [`lower_program`] and [`BuildConfig::db_driver`] — re-executes
/// exactly when either would re-run the backend's spine render, now as a
/// memoized salsa node.
#[salsa::tracked]
pub fn emit_spine_file(
    db: &dyn Db,
    root: SourceRoot,
    entry: SourceFile,
    config: BuildConfig,
) -> EmitTextResult {
    let program = folded_program(db, root, entry).clone()?;
    let driver = *config.db_driver(db);
    let ffi = config.ffi(db).clone();
    let target = *config.target(db);
    let wasm_public_env = config.wasm_public_env(db).clone();
    let mount_base = config.mount_base(db).clone();
    let wasm_hydrate_mode = *config.wasm_hydrate_mode(db);
    let runtime_dep = config.runtime_dep(db).clone();
    let hot_appearance = *config.hot_appearance(db);
    let interner = db.interner().lock();
    ipe_backend_rust::RustBackend::new(&interner)
        .with_db_driver(driver)
        .with_ffi(ffi)
        .with_target(target)
        .with_wasm_public_env(wasm_public_env)
        .with_mount_base(mount_base)
        .with_wasm_hydrate_mode(wasm_hydrate_mode)
        .with_runtime_dep(runtime_dep)
        .with_hot_appearance(hot_appearance)
        .emit_spine(&program)
        .map(Arc::new)
        .map_err(|d| (d, Vec::new()))
}

/// One `IpeModule` file's text (§4.2): that `home`'s `EnumDef`s + `Func`s only,
/// each `pub(crate)` behind a `use crate::*;` glob header.
///
/// Depends on [`lower_program`], [`BuildConfig::db_driver`], AND the `file` key
/// — the `file` key is what makes this SEPARATELY memoized per module. §4.3's
/// honest divergence: because it depends on the COARSE whole-program
/// [`lower_program`] (per-module lowering does not exist yet), a body edit
/// ANYWHERE forces this query to RE-EXECUTE for every file. The
/// incrementality win is the RED-GREEN one: for an UNRELATED module's
/// `file`, the re-execution reads a byte-identical slice of the freshly-lowered
/// program and produces a byte-identical `String`, so salsa backdates its memo
/// and [`emit_manifest`]'s dependency on it early-cuts — the on-disk write
/// skips, preserving `cargo`'s per-compilation-unit incrementality.
#[salsa::tracked]
pub fn emit_rust_file<'db>(
    db: &'db dyn Db,
    root: SourceRoot,
    entry: SourceFile,
    config: BuildConfig,
    file: RustFileId<'db>,
) -> EmitTextResult {
    let program = folded_program(db, root, entry).clone()?;
    let driver = *config.db_driver(db);
    let ffi = config.ffi(db).clone();
    let target = *config.target(db);
    let runtime_dep = config.runtime_dep(db).clone();
    let hot_appearance = *config.hot_appearance(db);
    let home = file.home(db);
    let interner = db.interner().lock();
    ipe_backend_rust::RustBackend::new(&interner)
        .with_db_driver(driver)
        .with_ffi(ffi)
        .with_target(target)
        .with_runtime_dep(runtime_dep)
        .with_hot_appearance(hot_appearance)
        .emit_module_file(&program, home)
        .map(Arc::new)
        .map_err(|d| (d, Vec::new()))
}

/// The complete intended [`ipe_backend::EmittedProject`] — the top-level driver
/// demand, replacing [`emit_project`] as `compile_prepared`'s call site (§4.4).
///
/// Assembles from the per-file query graph so the incrementality win is real:
/// it demands [`emit_spine_file`] + every [`emit_rust_file`] for the homes in
/// [`program_rust_file_ids`], so a body edit to an UNRELATED module early-cuts
/// that module's `emit_rust_file` (byte-identical value → salsa backdate →
/// [`assemble_split_manifest`](ipe_backend_rust::RustBackend::assemble_split_manifest)
/// sees no change → the on-disk write skips, §4.3).
///
/// **Spine-collapse routing (§3.3/§4.4).** With 0 or 1 distinct `IpeModule`
/// home the project is a single `src/main.rs` — this query delegates straight
/// to [`emit_project`], which is BYTE-IDENTICAL to the pre-split single-file
/// output (there is no cross-module early-cut to gain in a single-module
/// program anyway — its own edit forces the whole coarse floor to re-run). The
/// per-file assembly path fires only for genuine 2+-home programs. Either way
/// the return SHAPE is [`EmitResult`], so `compile_prepared` /
/// `write_emitted_project` need zero changes (§4.4). [`emit_project`] remains
/// live — the whole-program non-split oracle (`ipe_backend_rust`'s golden
/// tests) calls it directly.
#[salsa::tracked]
pub fn emit_manifest(
    db: &dyn Db,
    root: SourceRoot,
    entry: SourceFile,
    config: BuildConfig,
) -> EmitResult {
    let homes = program_rust_file_ids(db, root, entry).clone()?;

    // Spine-collapse: 0 or 1 distinct IpeModule home → the byte-identical
    // single-`main.rs` path. `emit_project` IS the collapse rendering.
    if homes.len() < 2 {
        return emit_project(db, root, entry, config).clone();
    }

    // Real split: demand the per-file query outputs (creating the salsa
    // dependency edges that make the §4.3 early-cut observable), then hand the
    // verbatim texts to the backend's file-count-agnostic assembler.
    let program = folded_program(db, root, entry).clone()?;

    // The production `Debug.*` gate must fire on this multi-home path too, not
    // only on the single-home collapse: a program that pulls in a
    // compiled-source stdlib module (`Ipe.Ui`, `Ipe.Tea.Web`, …) has two or
    // more emitted homes and reaches here, so a reachable `Debug.explain` in a
    // rendered view would otherwise ship past the gate.
    reject_dev_only_in_production(db, &program, config)?;

    let spine = emit_spine_file(db, root, entry, config).clone()?;
    let mut module_texts: BTreeMap<ipe_ir::ModPath, String> = BTreeMap::new();
    for home in homes.iter() {
        let file = RustFileId::new(db, home.clone());
        let text = emit_rust_file(db, root, entry, config, file).clone()?;
        module_texts.insert(home.clone(), (*text).clone());
    }

    let driver = *config.db_driver(db);
    let ffi = config.ffi(db).clone();
    let target = *config.target(db);
    let wasm_public_env = config.wasm_public_env(db).clone();
    let mount_base = config.mount_base(db).clone();
    let wasm_hydrate_mode = *config.wasm_hydrate_mode(db);
    let runtime_dep = config.runtime_dep(db).clone();
    let debugger = *config.debugger(db);
    let hot_appearance = *config.hot_appearance(db);
    let webview_host = *config.webview_host(db);
    let intent = *config.intent(db);
    let interner = db.interner().lock();
    ipe_backend_rust::RustBackend::new(&interner)
        .with_db_driver(driver)
        .with_ffi(ffi)
        .with_target(target)
        .with_wasm_public_env(wasm_public_env)
        .with_mount_base(mount_base)
        .with_wasm_hydrate_mode(wasm_hydrate_mode)
        .with_runtime_dep(runtime_dep)
        .with_debugger(debugger)
        .with_hot_appearance(hot_appearance)
        .with_webview_host(webview_host)
        .with_build_intent(intent)
        .assemble_split_manifest(&program, &spine, &module_texts)
        .map(Arc::new)
        .map_err(|d| (d, Vec::new()))
}

/// The identifier words of one module's source text — the per-file slice of
/// the fresh-name collision universe (`Interner::set_fresh_avoid`).
///
/// Primary path: [`ipe_parse::scan_identifier_words`] (real lexer — exactly
/// the identifier strings the parser interns, plus `{{…}}` interpolation
/// words). Fallback for source that does not lex: a raw word scan over the
/// whole text — a sound over-approximation (an unlexable module never
/// reaches lowering anyway; totality keeps the query panic-free).
///
/// Keyed on `file`'s text only, so the union the driver builds re-validates
/// cheaply: an edit that adds no new identifier words backdates this memo.
#[salsa::tracked]
pub fn identifier_words(db: &dyn Db, file: SourceFile) -> Arc<BTreeSet<String>> {
    let text = file.text(db);
    Arc::new(ipe_parse::scan_identifier_words(text).unwrap_or_else(|| raw_word_scan(text)))
}

/// Every maximal `[A-Za-z0-9_]+` run in `src` — the totality fallback for
/// [`identifier_words`]. Over-approximates identifiers (comments and string
/// contents contribute words), which is the sound direction for a collision
/// universe.
fn raw_word_scan(src: &str) -> BTreeSet<String> {
    src.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|w| !w.is_empty())
        .map(str::to_owned)
        .collect()
}

// ---------------------------------------------------------------------------
// Driver-boundary input reconciliation
// ---------------------------------------------------------------------------

/// Reconcile the database inputs against `desired` — the driver-computed
/// "module path → (text, origin)" map for the current build (user sources +
/// injected stdlib closure).
///
/// Boundary discipline (same family as [`set_text_if_changed`]): existing
/// files are updated ONLY when their text/origin actually changed, new files
/// get fresh [`SourceFile`] inputs, and `root.files` is re-set only when the
/// membership (or any handle) changed — a byte-identical re-sync dirties
/// nothing. Removed module paths simply drop out of the map; their orphaned
/// `SourceFile` inputs stay in the database (unreachable from any query once
/// no resolution points at them).
pub fn sync_source_root<T: AsRef<str>>(
    db: &mut IpeDatabase,
    root: SourceRoot,
    desired: &BTreeMap<Vec<String>, (T, ModuleOrigin)>,
) {
    let current = root.files(db).clone();
    let mut next: BTreeMap<Vec<String>, SourceFile> = BTreeMap::new();
    for (path, (text, origin)) in desired {
        let text = text.as_ref();
        if let Some(&file) = current.get(path) {
            set_text_if_changed(db, file, text);
            if *file.origin(db) != *origin {
                file.set_origin(db).to(*origin);
            }
            next.insert(path.clone(), file);
        } else {
            // Own the text only at the real mutation point — a fresh input.
            next.insert(
                path.clone(),
                SourceFile::new(db, path.clone(), text.to_owned(), *origin),
            );
        }
    }
    if next != current {
        root.set_files(db).to(next);
    }
}

/// Extract `import A.B.C` module paths from raw source.
///
/// Primary path: [`ipe_parse::scan_import_paths`] — a token-level scan using
/// the REAL lexer, so the returned edge set is a guaranteed
/// superset-or-equal of the import edges in the parsed AST (the parser
/// consumes the same token stream). That superset property is load-bearing:
/// the driver's topological sort uses these edges for its IPE-N0021
/// import-cycle gate, and a missed edge would let a cyclic
/// `module_interface` demand reach salsa's dependency-cycle panic. A plain
/// line scan that keyed on the literal prefix `"import "` would miss
/// lexer-legal edges such as `import\tB` or `import {- c -} B`; the
/// token-level scan does not.
///
/// Fallback (source that does not lex): the line scan, for topo *ordering*
/// only. An unlexable module cannot parse, so it contributes
/// no AST import edges — the fallback's under-approximation cannot bypass
/// the cycle gate.
///
/// Kernel imports are included verbatim; the caller filters against its
/// known-module set (unknown paths are skipped by the topo sort and later
/// surface as IPE-N0020 in canonicalisation). Returns a `Vec<Vec<String>>`
/// of path segments.
#[must_use]
pub fn extract_imports_from_source(source: &str) -> Vec<Vec<String>> {
    if let Some(imports) = ipe_parse::scan_import_paths(source) {
        return imports;
    }
    line_scan_imports(source)
}

/// Best-effort line scan (`import <path>` at line start), used ONLY when the
/// source does not lex — see [`extract_imports_from_source`].
fn line_scan_imports(source: &str) -> Vec<Vec<String>> {
    scan_import_spellings(source)
        .into_iter()
        .map(|spelling| spelling.path)
        .collect()
}

/// One `import <path>[ as <alias>]` header line: the dotted path plus its
/// optional alias, exactly as written — no `exposing(...)` clause is parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportSpelling {
    pub path: Vec<String>,
    pub alias: Option<String>,
}

/// Best-effort line scan of every `import <path>[ as <alias>]` header line in
/// `source`, capturing the alias the [`extract_imports_from_source`] path
/// scan drops.
///
/// Pure text scanning (`str::lines`/`split`, no lexing), so it is total on
/// any buffer — including one that does not lex at all, such as a buffer
/// with a completion trigger's dangling `Font.` at the cursor. A qualifier
/// resolver reads this alongside `ipe_canon::import_qualifiers` to learn
/// which import a typed qualifier spelling names, without re-implementing
/// canon's own alias/full-path rule.
#[must_use]
pub fn scan_import_spellings(source: &str) -> Vec<ImportSpelling> {
    let mut imports = Vec::new();
    for line in source.lines() {
        let trimmed = line.trim();
        let Some(after_import) = trimmed.strip_prefix("import ") else {
            continue;
        };
        let rest = after_import.trim_start();
        let Some(path_end) = rest.find(|c: char| c.is_whitespace() || c == '(') else {
            let path: Vec<String> = rest.split('.').map(str::to_owned).collect();
            if path.first().is_some_and(|s| !s.is_empty()) {
                imports.push(ImportSpelling { path, alias: None });
            }
            continue;
        };
        let path_str = rest.get(..path_end).unwrap_or("");
        let path: Vec<String> = path_str.split('.').map(str::to_owned).collect();
        if path.first().is_none_or(String::is_empty) {
            continue;
        }
        let after_path = rest.get(path_end..).unwrap_or("").trim_start();
        let alias = after_path.strip_prefix("as ").and_then(|rest| {
            let alias_str = rest
                .trim_start()
                .split(|c: char| c.is_whitespace() || c == '(')
                .next()
                .unwrap_or("");
            (!alias_str.is_empty()).then(|| alias_str.to_owned())
        });
        imports.push(ImportSpelling { path, alias });
    }
    imports
}

#[cfg(test)]
mod import_spelling_tests {
    use super::{ImportSpelling, scan_import_spellings};

    #[test]
    fn bare_import_has_no_alias() {
        let src = "module Main exposing (main)\nimport Ipe.Ui.Font\nmain = 1\n";
        assert_eq!(
            scan_import_spellings(src),
            vec![ImportSpelling {
                path: vec!["Ipe".to_owned(), "Ui".to_owned(), "Font".to_owned()],
                alias: None,
            }]
        );
    }

    #[test]
    fn aliased_import_captures_alias() {
        let src = "module Main exposing (main)\nimport Ipe.Ui.Font as F\nmain = 1\n";
        assert_eq!(
            scan_import_spellings(src),
            vec![ImportSpelling {
                path: vec!["Ipe".to_owned(), "Ui".to_owned(), "Font".to_owned()],
                alias: Some("F".to_owned()),
            }]
        );
    }

    #[test]
    fn import_with_exposing_after_path_has_no_alias() {
        let src = "module Main exposing (main)\nimport Ipe.Ui.Font exposing (bold)\nmain = 1\n";
        assert_eq!(
            scan_import_spellings(src),
            vec![ImportSpelling {
                path: vec!["Ipe".to_owned(), "Ui".to_owned(), "Font".to_owned()],
                alias: None,
            }]
        );
    }

    #[test]
    fn aliased_import_on_an_otherwise_unlexable_buffer_still_scans() {
        // The buffer's own trailing completion trigger (`Font.`) is a lex
        // error; the import header line above it must still scan.
        let src = "module Main exposing (main)\nimport Ipe.Ui.Font as F\nmain = F.\n";
        assert_eq!(
            scan_import_spellings(src),
            vec![ImportSpelling {
                path: vec!["Ipe".to_owned(), "Ui".to_owned(), "Font".to_owned()],
                alias: Some("F".to_owned()),
            }]
        );
    }
}
