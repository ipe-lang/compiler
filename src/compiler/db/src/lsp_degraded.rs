//! Degraded analysis: a module that does not build, analysed declaration by declaration.
//!
//! The language server answers hover and navigation on a module whose build
//! is refused. Each query here serves the strict result whenever the strict
//! query succeeds, so degraded and strict agree on every module without an
//! error. Otherwise:
//!
//! - [`canonicalize`] leaves each failed value declaration out of the module
//!   and poisons every occurrence of its name, so that occurrence answers
//!   nothing and never resolves to an import of the same name.
//! - [`typecheck_module`] solves the module without each declaration that
//!   fails, together with every declaration that reads one of them, a
//!   bounded number of times. A failed declaration whose annotation resolved
//!   keeps that annotation as its type for the declarations that read it.
//!   Every type that still holds a solver variable is withheld, since a
//!   pruned solve may leave a variable the full program would have pinned.
//!
//! None of these results is a build input: the compiler's own pipeline and
//! every diagnostic read the strict queries in the crate root.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use ipe_canon::DeclaredSignature;
use ipe_canon::name_index::{NameIndex, Target};
use ipe_diagnostics::Span;
use ipe_intern::Symbol;

use crate::{
    CanonicalModule, Db, ImportResolution, ModuleExports, ModuleTypes, SourceFile, SourceRoot,
    intern_module_path, project_module_types,
};

/// The most solves one degraded module analysis runs.
const PRUNE_CAP: usize = 32;

/// A top-level value occurrence: its span, the declaring module, and the name.
type TopLevelRef = (Span, Vec<Symbol>, Symbol);

/// One module canonicalised declaration by declaration.
#[derive(Clone, PartialEq, Debug)]
struct DegradedCanonical {
    /// The module without its failed declarations, their occurrences poisoned.
    canonical: Arc<CanonicalModule>,
    /// The annotations that resolved on failed declarations.
    declared: Vec<DeclaredSignature>,
    /// The failed declarations whose annotation did not resolve, or that had none.
    dropped: BTreeSet<Symbol>,
    /// Whether a whole-module check refused the module.
    refused: bool,
    /// Every top-level value occurrence, as resolved before poisoning.
    refs: Vec<TopLevelRef>,
}

impl DegradedCanonical {
    /// The names of the module's failed declarations.
    fn poisoned(&self) -> BTreeSet<Symbol> {
        self.declared
            .iter()
            .map(|signature| signature.name.value)
            .chain(self.dropped.iter().copied())
            .collect()
    }
}

/// Every top-level value occurrence an index holds.
fn top_level_refs(names: &NameIndex) -> Vec<TopLevelRef> {
    names
        .entries()
        .filter_map(|(span, target)| match target {
            Target::TopLevel { home, name } => Some((span, home.clone(), *name)),
            _ => None,
        })
        .collect()
}

/// Canonicalise `file`, leaving out each value declaration that fails.
///
/// `None` when the module cannot be analysed at all: an import cycle, a parse
/// error, an import that does not resolve, a dependency with no degraded
/// interface, or a failure outside one value declaration.
#[salsa::tracked]
fn canonicalize_degraded(
    db: &dyn Db,
    root: SourceRoot,
    file: SourceFile,
) -> Option<Arc<DegradedCanonical>> {
    crate::topo_order(db, root, file).as_ref().ok()?;
    if let Ok(canonical) = crate::canonicalize(db, root, file) {
        return Some(Arc::new(DegradedCanonical {
            canonical: canonical.clone(),
            declared: Vec::new(),
            dropped: BTreeSet::new(),
            refused: false,
            refs: top_level_refs(&canonical.names),
        }));
    }
    let parsed = crate::parse(db, file).clone().ok()?;
    // Every dep interface is demanded before the interner lock is taken.
    let mut dep_interfaces: Vec<(Vec<String>, Arc<ModuleExports>)> = Vec::new();
    let mut dep_poisoned: Vec<(Vec<String>, BTreeSet<Symbol>)> = Vec::new();
    for (path, dep) in crate::canon_dep_files(db, root, file).ok()? {
        let interface = module_interface_degraded(db, root, dep).clone()?;
        dep_poisoned.push((path.clone(), interface.poisoned.clone()));
        dep_interfaces.push((path, interface.exports.clone()));
    }
    crate::canonicalise_against(
        db,
        root,
        file,
        &dep_interfaces,
        |input, interner| {
            let partial = ipe_canon::canonicalise_module_partial(
                input.module,
                input.expected_path,
                input.deps,
                input.catalog,
                input.origin,
                interner,
            )?;
            let mut poisoned_at: BTreeMap<Vec<Symbol>, BTreeSet<Symbol>> = BTreeMap::new();
            for (path, names) in dep_poisoned {
                if !names.is_empty() {
                    poisoned_at.insert(intern_module_path(interner, &path)?, names);
                }
            }
            let ipe_canon::PartialModule {
                module,
                exports,
                mut names,
                failures,
                module_errors,
            } = partial;
            let refs = top_level_refs(&names);
            let mut declared = Vec::new();
            let mut dropped = BTreeSet::new();
            for failure in failures {
                match failure.signature {
                    Some(signature) => declared.push(signature),
                    None => {
                        dropped.insert(failure.name);
                    }
                }
            }
            let own = poisoned_at.entry(module.name.clone()).or_default();
            own.extend(declared.iter().map(|signature| signature.name.value));
            own.extend(dropped.iter().copied());
            names.poison(|home, name| poisoned_at.get(home).is_some_and(|set| set.contains(&name)));
            Ok(Arc::new(DegradedCanonical {
                canonical: Arc::new(CanonicalModule {
                    module,
                    exports,
                    names,
                }),
                declared,
                dropped,
                refused: !module_errors.is_empty(),
                refs,
            }))
        },
        &parsed,
    )
    .ok()
}

/// A module's degraded export surface and the exported names that failed.
#[derive(Clone, PartialEq, Debug)]
struct DegradedInterface {
    /// The export surface, every failed declaration's name still bound.
    exports: Arc<ModuleExports>,
    /// The names of the module's failed declarations.
    poisoned: BTreeSet<Symbol>,
}

/// The export surface of [`canonicalize_degraded`].
#[salsa::tracked]
fn module_interface_degraded(
    db: &dyn Db,
    root: SourceRoot,
    file: SourceFile,
) -> Option<Arc<DegradedInterface>> {
    let degraded = canonicalize_degraded(db, root, file).clone()?;
    Some(Arc::new(DegradedInterface {
        exports: Arc::new(degraded.canonical.exports.clone()),
        poisoned: degraded.poisoned(),
    }))
}

/// A degraded solve of one module.
#[derive(Clone, PartialEq, Eq, Debug)]
struct DegradedSolve {
    /// The module's solved slice in canonical form, when its interface is closed.
    solved: Option<Arc<ipe_types::CanonicalTypes>>,
    /// The module's typed interface, when no exported scheme is open.
    interface: Option<Arc<ipe_types::TypedInterface>>,
    /// The values whose type is an annotation, kept even when polymorphic.
    annotated: BTreeSet<Symbol>,
    /// The extents, ordered by start, of the kept declarations a left-out body
    /// may share a solver variable with: their types are withheld whole.
    shared: Vec<Span>,
    /// The kept unannotated values among them.
    shared_names: BTreeSet<Symbol>,
}

/// The typed interface of `file`: the strict one, else its degraded solve's.
#[salsa::tracked]
fn typed_interface_degraded(
    db: &dyn Db,
    root: SourceRoot,
    file: SourceFile,
) -> Option<Arc<ipe_types::TypedInterface>> {
    if let Some(interface) = crate::typed_interface(db, root, file) {
        return Some(interface.clone());
    }
    infer_module_degraded(db, root, file)
        .as_ref()?
        .interface
        .clone()
}

/// Which declarations a degraded solve leaves out, and which it knows by annotation only.
struct Prune<'a> {
    /// Each value declaration's extent and name, ordered by start.
    extents: &'a [(Span, Symbol)],
    /// Every top-level value occurrence in the module.
    refs: &'a [TopLevelRef],
    /// The module's own path.
    home: &'a [Symbol],
    /// The module's own canonical declarations.
    defs: &'a [ipe_canon::ast::Def],
    /// The typed interface of each dependency.
    deps: &'a BTreeMap<Vec<Symbol>, Arc<ipe_types::TypedInterface>>,
    /// The declarations left out entirely.
    dropped: BTreeSet<Symbol>,
    /// The declarations known by their annotation only.
    declared: Vec<DeclaredSignature>,
}

impl Prune<'_> {
    /// The value declaration whose extent holds `span`.
    fn owner(&self, span: Span) -> Option<Symbol> {
        let after = self
            .extents
            .partition_point(|(extent, _)| extent.lo <= span.lo);
        let (extent, name) = self.extents.get(after.checked_sub(1)?)?;
        (span.hi <= extent.hi).then_some(*name)
    }

    /// Whether `name` is known by its annotation only.
    fn is_declared(&self, name: Symbol) -> bool {
        self.declared
            .iter()
            .any(|signature| signature.name.value == name)
    }

    /// Whether the solve cannot type the occurrence of `name` in module `home`.
    fn unresolvable(&self, home: &[Symbol], name: Symbol) -> bool {
        if home == self.home {
            self.dropped.contains(&name)
        } else {
            !self
                .deps
                .get(home)
                .is_some_and(|interface| interface.values.contains_key(&name))
        }
    }

    /// Leave out every declaration that reads a value the solve cannot type.
    ///
    /// `false` when such an occurrence lies in no value declaration, or the
    /// closure does not settle: the module then has no degraded solve.
    #[must_use]
    fn close(&mut self) -> bool {
        // Each round that changes anything leaves out one more declaration.
        for _ in 0..=self.extents.len() {
            let mut grew = false;
            for (span, home, name) in self.refs {
                if !self.unresolvable(home, *name) {
                    continue;
                }
                let Some(owner) = self.owner(*span) else {
                    return false;
                };
                if !self.is_declared(owner) && self.dropped.insert(owner) {
                    grew = true;
                }
            }
            if !grew {
                return true;
            }
        }
        false
    }

    /// Know `signature`'s declaration by its annotation, or leave it out when
    /// the annotation's meaning depends on the body.
    fn declare(&mut self, signature: DeclaredSignature) {
        if mentions_wildcard(&signature.ty) {
            self.dropped.insert(signature.name.value);
        } else {
            self.declared.push(signature);
        }
    }

    /// Prune the declaration a solve refusal names, reporting whether the refusal was attributable
    /// and the pruned module still closes.
    ///
    /// A declaration with an annotation is then known by that annotation;
    /// one already known so, or with none, is left out.
    fn prune_at(&mut self, err: &ipe_types::InferError) -> bool {
        if err.home().is_none_or(|home| home.path() != self.home) {
            return false;
        }
        let span = err.diagnostic().primary_span();
        if span.lo >= span.hi {
            return false;
        }
        let Some(owner) = self.owner(span) else {
            return false;
        };
        if self.dropped.contains(&owner) {
            return false;
        }
        if self.is_declared(owner) {
            self.declared
                .retain(|signature| signature.name.value != owner);
            self.dropped.insert(owner);
        } else if let Some(signature) = self.defs.iter().find_map(|def| match def {
            ipe_canon::ast::Def::Typed {
                name,
                free_vars,
                patterns,
                ty,
                ..
            } if name.value == owner => Some(DeclaredSignature {
                name: *name,
                free_vars: free_vars.clone(),
                ty: ty.clone(),
                has_params: !patterns.is_empty(),
            }),
            _ => None,
        }) {
            self.declare(signature);
        } else {
            self.dropped.insert(owner);
        }
        self.close()
    }

    /// Whether the solve left out a body the module declares.
    fn pruned(&self) -> bool {
        !self.dropped.is_empty() || !self.declared.is_empty()
    }

    /// Whether the solve keeps `name`'s body.
    fn keeps(&self, name: Symbol) -> bool {
        !self.dropped.contains(&name) && !self.is_declared(name)
    }

    /// The kept declarations a left-out body may share a solver variable with.
    ///
    /// An unannotated top-level value is one variable across its module, so a
    /// left-out body that reads it may pin it, and with it every declaration
    /// that reads it, transitively; a default the solve then applies (an
    /// unpinned number to `Int`) is not the full program's. A left-out body
    /// may have failed to canonicalise, so what it reads is taken from its
    /// source text: every word spelled as a kept unannotated value counts.
    /// `untyped` maps each kept unannotated value to its spelling.
    fn shared_with_left_out(
        &self,
        untyped: &BTreeMap<Symbol, String>,
        text: &str,
    ) -> BTreeSet<Symbol> {
        let by_spelling: BTreeMap<&str, Symbol> = untyped
            .iter()
            .map(|(name, spelling)| (spelling.as_str(), *name))
            .collect();
        let mut shared: BTreeSet<Symbol> = BTreeSet::new();
        for (extent, name) in self.extents {
            if self.keeps(*name) {
                continue;
            }
            let body = usize::try_from(extent.lo)
                .ok()
                .zip(usize::try_from(extent.hi).ok())
                .and_then(|(lo, hi)| text.get(lo..hi));
            let Some(body) = body else {
                // Unreadable: it may read every one of them.
                return self.extents.iter().map(|(_, name)| *name).collect();
            };
            shared.extend(
                body.split(|c: char| !ipe_parse::is_ident_continue(c))
                    .filter_map(|word| by_spelling.get(word).copied()),
            );
        }
        let mut adjacent: BTreeMap<Symbol, Vec<Symbol>> = BTreeMap::new();
        for (span, home, name) in self.refs {
            if home != self.home || !untyped.contains_key(name) {
                continue;
            }
            let Some(owner) = self.owner(*span) else {
                continue;
            };
            if self.keeps(owner) {
                adjacent.entry(owner).or_default().push(*name);
                adjacent.entry(*name).or_default().push(owner);
            }
        }
        let mut pending: Vec<Symbol> = shared.iter().copied().collect();
        while let Some(name) = pending.pop() {
            for next in adjacent.get(&name).into_iter().flatten() {
                if shared.insert(*next) {
                    pending.push(*next);
                }
            }
        }
        shared
    }
}

/// Solve `module` without its failing declarations.
///
/// `None` when the module has no degraded canonical form, a dependency has
/// no typed interface, or a solve refusal names no declaration of the module.
/// Runs at most [`PRUNE_CAP`] solves.
#[salsa::tracked]
fn infer_module_degraded(
    db: &dyn Db,
    root: SourceRoot,
    module: SourceFile,
) -> Option<Arc<DegradedSolve>> {
    let degraded = canonicalize_degraded(db, root, module).clone()?;
    if degraded.refused {
        return None;
    }
    let parsed = crate::parse(db, module).clone().ok()?;
    let text = module.text(db);
    let resolutions = crate::resolve_imports(db, root, module).clone().ok()?;
    // Every dep interface is demanded before the interner lock is taken.
    let mut dep_interfaces: Vec<(Vec<String>, Arc<ipe_types::TypedInterface>)> = Vec::new();
    for (path, resolution) in resolutions.iter() {
        if let ImportResolution::Resolved(dep) = resolution {
            dep_interfaces.push((
                path.clone(),
                typed_interface_degraded(db, root, *dep).clone()?,
            ));
        }
    }
    let unimported = imported_by_none(db, root, module)?;
    let limits = crate::solve_limits(db).ok()?;
    let mut extents: Vec<(Span, Symbol)> = parsed
        .values
        .iter()
        .map(|value| (ipe_canon::decl_extent(value), value.value.name.value))
        .collect();
    extents.sort_by_key(|(extent, _)| extent.lo);

    let mut interner = db.interner().lock();
    let mut deps: BTreeMap<Vec<Symbol>, Arc<ipe_types::TypedInterface>> = BTreeMap::new();
    for (path, interface) in dep_interfaces {
        deps.insert(intern_module_path(&mut interner, &path).ok()?, interface);
    }
    let canonical = &degraded.canonical;
    let home = canonical.module.name.as_slice();
    let mut prune = Prune {
        extents: &extents,
        refs: &degraded.refs,
        home,
        defs: &canonical.module.defs,
        deps: &deps,
        dropped: degraded.dropped.clone(),
        declared: Vec::new(),
    };
    for signature in degraded.declared.iter().cloned() {
        prune.declare(signature);
    }
    if !prune.close() {
        return None;
    }
    // Every attributable refusal prunes one more declaration, and a
    // declaration is pruned at most twice.
    let attempts = extents
        .len()
        .saturating_mul(2)
        .saturating_add(1)
        .min(PRUNE_CAP);
    for _ in 0..attempts {
        let mut pruned = canonical.module.clone();
        pruned.defs.retain(|def| prune.keeps(def.name().value));
        let mut exports = canonical.exports.clone();
        exports.values.retain(|name| !prune.dropped.contains(name));
        match ipe_types::infer_module_declared(
            &pruned,
            &exports,
            &deps,
            &prune.declared,
            &mut interner,
            limits.steps,
        ) {
            Ok(inference) => {
                let untyped: BTreeMap<Symbol, String> = pruned
                    .defs
                    .iter()
                    .filter(|def| !matches!(def, ipe_canon::ast::Def::Typed { .. }))
                    .map(|def| {
                        let name = def.name().value;
                        interner
                            .resolve(name)
                            .map(|spelling| (name, spelling.to_owned()))
                    })
                    .collect::<Option<_>>()?;
                drop(interner);
                return Some(settle(
                    &prune, &pruned, &untyped, text, inference, unimported, limits,
                ));
            }
            Err(err) => {
                if !prune.prune_at(&err) {
                    return None;
                }
            }
        }
    }
    None
}

/// The degraded result of a solve of `pruned` that succeeded.
///
/// `untyped` maps each kept unannotated value to its spelling; `unimported`
/// says no module of the root imports this one.
fn settle(
    prune: &Prune<'_>,
    pruned: &ipe_canon::ast::Module,
    untyped: &BTreeMap<Symbol, String>,
    text: &str,
    inference: ipe_types::ModuleInference,
    unimported: bool,
    limits: crate::SolveLimits,
) -> Arc<DegradedSolve> {
    let shared_names = prune.shared_with_left_out(untyped, text);
    let shared: Vec<Span> = prune
        .extents
        .iter()
        .filter(|(_, name)| shared_names.contains(name))
        .map(|(extent, _)| *extent)
        .collect();
    let bodied: BTreeSet<Symbol> = pruned
        .defs
        .iter()
        .filter(|def| matches!(def, ipe_canon::ast::Def::Typed { .. }))
        .map(|def| def.name().value)
        .collect();
    let annotated: BTreeSet<Symbol> = bodied
        .iter()
        .copied()
        .chain(prune.declared.iter().map(|signature| signature.name.value))
        .collect();
    // The module's own solve is faithful when no importer's use
    // site can pin it: a closed interface, or no importer at all.
    let (own_faithful, interface) = match inference.interface {
        ipe_types::InterfaceStatus::Closed(interface) => (true, Some(interface)),
        ipe_types::InterfaceStatus::ImporterDependent(interface) => (unimported, Some(interface)),
        ipe_types::InterfaceStatus::Open => (unimported, None),
    };
    let solved = if own_faithful {
        crate::scoped_module_slice(&inference.solved, prune.home, prune.deps)
            .ok()
            .and_then(|slice| {
                ipe_types::canonicalize(slice, ipe_types::VarScope::PerHome, limits.var_ceiling)
                    .ok()
            })
            .map(Arc::new)
    } else {
        None
    };
    let interface = interface.map(|mut interface| {
        if prune.pruned() {
            // A left-out body may have pinned a variable of an
            // unannotated value's scheme, and a declaration known
            // by its annotation has unknown obligations: only a
            // scheme without a variable, or a solved annotated
            // body's, still stands for the module.
            interface
                .values
                .retain(|name, scheme| bodied.contains(name) || !scheme.ty.holds_variable());
        }
        Arc::new(interface)
    });
    Arc::new(DegradedSolve {
        solved,
        interface,
        annotated,
        shared,
        shared_names,
    })
}

/// Whether no module of `root` imports `module`; `None` when some module's imports do not resolve.
fn imported_by_none(db: &dyn Db, root: SourceRoot, module: SourceFile) -> Option<bool> {
    for file in root.files(db).values() {
        let resolutions = crate::resolve_imports(db, root, *file).as_ref().ok()?;
        if resolutions
            .iter()
            .any(|(_, resolution)| *resolution == ImportResolution::Resolved(module))
        {
            return Some(false);
        }
    }
    Some(true)
}

/// Whether a wildcard `any` occurs in `ty`.
fn mentions_wildcard(ty: &ipe_canon::ast::Type) -> bool {
    use ipe_canon::ast::Type;
    let mut pending = vec![ty];
    while let Some(ty) = pending.pop() {
        match ty {
            Type::Wildcard => return true,
            Type::Var(_) | Type::Unit => {}
            Type::Lambda(arg, result) => {
                pending.push(arg);
                pending.push(result);
            }
            Type::Con { args, .. } | Type::Tuple(args) => pending.extend(args),
            Type::Record(fields) | Type::RecordOpen(_, fields) => {
                pending.extend(fields.iter().map(|(_, field)| field));
            }
        }
    }
    false
}

/// Withhold every type a pruned solve may have left unpinned.
///
/// A region, an expected type, or an unannotated value's type that holds a
/// solver variable is withheld, as is a region with no width, and every
/// type inside a declaration a left-out body may share a variable with.
fn withhold_residuals(types: ModuleTypes, solve: &DegradedSolve) -> ModuleTypes {
    let ModuleTypes {
        env,
        regions,
        expected,
        bounds,
    } = types;
    let shared = |span: Span| {
        let after = solve.shared.partition_point(|extent| extent.lo <= span.lo);
        after
            .checked_sub(1)
            .and_then(|at| solve.shared.get(at))
            .is_some_and(|extent| span.hi <= extent.hi)
    };
    let pinned = |(span, ty): &(Span, ipe_types::Ty)| {
        span.lo < span.hi && !ty.holds_variable() && !shared(*span)
    };
    ModuleTypes {
        env: env
            .into_iter()
            .filter(|(name, ty)| {
                solve.annotated.contains(name)
                    || (!ty.holds_variable() && !solve.shared_names.contains(name))
            })
            .collect(),
        regions: regions.into_iter().filter(pinned).collect(),
        expected: expected.into_iter().filter(pinned).collect(),
        bounds,
    }
}

/// The types of `module` within the program rooted at `entry`, solved without its failing declarations.
#[salsa::tracked]
fn typecheck_module_degraded(
    db: &dyn Db,
    root: SourceRoot,
    entry: SourceFile,
    module: SourceFile,
) -> Option<Arc<ModuleTypes>> {
    if let Ok(types) = crate::typecheck_module(db, root, entry, module) {
        return Some(types.clone());
    }
    let solve = infer_module_degraded(db, root, module).clone()?;
    let solved = solve.solved.clone()?;
    let home = {
        let mut interner = db.interner().lock();
        intern_module_path(&mut interner, module.module_path(db)).ok()?
    };
    Some(Arc::new(withhold_residuals(
        project_module_types(solved.as_solved(), &home),
        &solve,
    )))
}

/// The canonical form of `file`, each failed value declaration left out and its occurrences poisoned.
///
/// The strict [`crate::canonicalize`] result whenever that succeeds. `None`
/// when no declaration-level analysis of the module exists.
#[must_use]
pub fn canonicalize(
    db: &dyn Db,
    root: SourceRoot,
    file: SourceFile,
) -> Option<Arc<CanonicalModule>> {
    canonicalize_degraded(db, root, file)
        .as_ref()
        .map(|degraded| degraded.canonical.clone())
}

/// The export surface of [`canonicalize`], every failed declaration's name still bound.
#[must_use]
pub fn module_interface(
    db: &dyn Db,
    root: SourceRoot,
    file: SourceFile,
) -> Option<Arc<ModuleExports>> {
    module_interface_degraded(db, root, file)
        .as_ref()
        .map(|interface| interface.exports.clone())
}

/// The types of `module`, solved without its failing declarations.
///
/// The strict [`crate::typecheck_module`] result whenever that succeeds.
/// Otherwise every type that holds a solver variable is withheld. `None` when
/// no degraded solve of the module exists.
#[must_use]
pub fn typecheck_module(
    db: &dyn Db,
    root: SourceRoot,
    entry: SourceFile,
    module: SourceFile,
) -> Option<Arc<ModuleTypes>> {
    typecheck_module_degraded(db, root, entry, module).clone()
}
