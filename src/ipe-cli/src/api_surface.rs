//! Extract a package's public API surface from its typed module interfaces.
//!
//! `ipe diff` compares two package versions by their exported values and types.
//! The comparable surface is projected out of each module's
//! [`ipe_types::TypedInterface`] — the exported-name → generalized-scheme
//! boundary the compiler already computes — into a canonical, order-independent
//! [`PublicApi`]: every value name maps to its α-canonicalised signature string,
//! every exported union to its parameter arity and its constructors' argument
//! signatures. Two structurally-equal public APIs (up to source order and
//! type-variable spelling) project to an EQUAL `PublicApi`, so the diff in
//! [`crate::diff`] is a pure structural comparison.
//!
//! Fail closed (Security first): a module whose interface is OPEN (a scheme
//! reaches a residual variable an importer could pin) or a package that does not
//! typecheck is a hard [`DiffError`], never a partial surface — an API we cannot
//! faithfully type is one we must not silently diff.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use ipe_diagnostics::{Diagnostic, TyDoc, render_ty};
use ipe_types::{Ty, TypedInterface, VarNamer, canon_type_to_doc, ty_to_doc};

use crate::project;

/// A module path as dot-free segments (`["Lib", "Utils"]`), the key space of a
/// [`PublicApi`]'s modules.
pub type ModulePath = Vec<String>;

/// The canonical, order-independent public API of one package version.
///
/// Keyed by module path; each module carries its exported values and unions.
/// `BTreeMap` ordering makes the whole structure a deterministic function of the
/// API alone — source order cannot perturb it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicApi {
    /// Exported module path → its public surface.
    pub modules: BTreeMap<ModulePath, ModuleApi>,
}

/// One module's exported values and union types.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ModuleApi {
    /// Exported value name → its α-canonicalised type signature.
    pub values: BTreeMap<String, String>,
    /// Exported value name → its resolved type document.
    ///
    /// The same type the string in [`Self::values`] renders, kept in its
    /// structured [`TyDoc`] form so a consumer (`ipe doc`'s cross-reference
    /// linker) can reach each constructor's already-resolved module + name
    /// rather than re-parsing the flat string. `ipe diff` reads only the string;
    /// this is threaded alongside it, not in place of it.
    pub value_types: BTreeMap<String, TyDoc>,
    /// Exported union type name → its exported shape.
    pub unions: BTreeMap<String, UnionApi>,
}

/// One exported union type's diff-relevant shape: its type-parameter arity and
/// its constructors' argument signatures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnionApi {
    /// The number of type parameters the union quantifies (`Maybe a` → 1).
    pub params: usize,
    /// Constructor name → its argument signatures, in declaration order.
    pub ctors: BTreeMap<String, Vec<String>>,
    /// Constructor name → its arguments' resolved type documents, in declaration
    /// order (parallel to [`Self::ctors`]). Threaded for cross-reference linking;
    /// `ipe diff` reads only the string form above.
    pub ctor_types: BTreeMap<String, Vec<TyDoc>>,
}

/// Why a package's public API could not be extracted.
///
/// Every variant is a hard failure: the diff cannot proceed on an API it cannot
/// faithfully type. Typed, not stringly — the CLI maps each to a message and the
/// gate can branch on the cause.
#[derive(Debug)]
pub enum DiffError {
    /// A source file (or the tree root) could not be read.
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    /// The package did not typecheck; carries the first compiler diagnostic.
    Typecheck {
        module: ModulePath,
        diag: Box<Diagnostic>,
    },
    /// A module's exported interface is OPEN — a scheme reaches a residual
    /// variable an importer could pin, so no per-module interface is faithful
    /// and the API cannot be soundly compared.
    OpenInterface { module: ModulePath },
    /// The tree carries no `.ipe` modules to compare.
    Empty { path: PathBuf },
    /// The required bump overflows a version component of the predecessor.
    FloorOverflow(crate::diff::FloorOverflow),
}

impl std::fmt::Display for DiffError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "io error at {}: {source}", path.display()),
            Self::Typecheck { module, .. } => {
                write!(
                    f,
                    "package does not typecheck (module {})",
                    module.join(".")
                )
            }
            Self::OpenInterface { module } => write!(
                f,
                "module {} has an open public interface — its exported types are \
                 not fully determined, so its API cannot be compared",
                module.join(".")
            ),
            Self::Empty { path } => {
                write!(f, "no Ipê modules found under {}", path.display())
            }
            Self::FloorOverflow(overflow) => write!(f, "{overflow}"),
        }
    }
}

impl std::error::Error for DiffError {}

impl From<crate::diff::FloorOverflow> for DiffError {
    fn from(overflow: crate::diff::FloorOverflow) -> Self {
        Self::FloorOverflow(overflow)
    }
}

/// Read every `.ipe` module under a package source tree into `(path, source)`
/// pairs keyed by module path.
///
/// `root` may be a directory (walked for `*.ipe`) or a single `.ipe` file
/// (taken as a one-module `Main`-shaped package).
///
/// Public so `ipe doc` (which documents the same tree `ipe diff` compares) reads
/// modules through the identical discovery rule — one `src/`-aware walk, one
/// single-file fallback — rather than a divergent second copy.
///
/// # Errors
/// [`DiffError::Io`] on a read failure and [`DiffError::Empty`] when the tree
/// carries no `.ipe` modules.
pub fn read_tree(root: &Path) -> Result<BTreeMap<ModulePath, (PathBuf, String)>, DiffError> {
    let discovered = if root.is_dir() {
        // A conventional package keeps modules under `src/`; fall back to the
        // root itself when there is no `src/` (a flat fixture tree).
        let src_root = {
            let candidate = root.join("src");
            if candidate.is_dir() {
                candidate
            } else {
                root.to_path_buf()
            }
        };
        project::discover_modules(&src_root).map_err(|_| DiffError::Empty {
            path: root.to_path_buf(),
        })?
    } else {
        // A single `.ipe` file is its own module; name it by its stem.
        let stem = root
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("Main")
            .to_owned();
        vec![project::DiscoveredModule {
            path: root.to_path_buf(),
            module_path: vec![stem],
        }]
    };

    let mut sources = BTreeMap::new();
    for m in discovered {
        let src =
            crate::io_bounded::read_to_string_capped(&m.path, crate::io_bounded::SOURCE_READ_CAP)
                .map_err(|e| match e {
                crate::CliError::Io { path, source } => DiffError::Io { path, source },
                other => DiffError::Io {
                    path: m.path.clone(),
                    source: std::io::Error::other(other.to_string()),
                },
            })?;
        sources.insert(m.module_path, (m.path, src));
    }
    if sources.is_empty() {
        return Err(DiffError::Empty {
            path: root.to_path_buf(),
        });
    }
    Ok(sources)
}

/// Render a generalized scheme's [`Ty`] into its resolved [`TyDoc`].
///
/// A FRESH [`VarNamer`] per scheme assigns type variables stable first-seen
/// letters, so two schemes render to the same string (via [`render_ty`]) exactly
/// when they are equal up to variable renaming (α-equivalence) — the equivalence
/// a public type signature must be compared under. The `TyDoc`'s `Con` nodes also
/// carry each type's resolved module + name, which `ipe doc` threads through for
/// cross-reference linking.
fn signature_doc(ty: &Ty, interner: &ipe_intern::Interner) -> Result<TyDoc, Diagnostic> {
    let mut namer = VarNamer::new();
    ty_to_doc(ty, interner, &mut namer)
}

/// Project one module's [`TypedInterface`] into a [`ModuleApi`].
fn project_interface(
    interface: &TypedInterface,
    interner: &ipe_intern::Interner,
    module: &ModulePath,
) -> Result<ModuleApi, DiffError> {
    let typecheck_err = |diag: Diagnostic| DiffError::Typecheck {
        module: module.clone(),
        diag: Box::new(diag),
    };

    let mut values = BTreeMap::new();
    let mut value_types = BTreeMap::new();
    for (name, scheme) in &interface.values {
        let Some(name) = interner.resolve(*name) else {
            continue;
        };
        let doc = signature_doc(&scheme.ty, interner).map_err(typecheck_err)?;
        values.insert(name.to_owned(), render_ty(&doc));
        value_types.insert(name.to_owned(), doc);
    }

    let mut unions = BTreeMap::new();
    for union in &interface.unions {
        let Some(name) = interner.resolve(union.name) else {
            continue;
        };
        let mut ctors = BTreeMap::new();
        let mut ctor_types = BTreeMap::new();
        for ctor in &union.ctors {
            let Some(ctor_name) = interner.resolve(ctor.name) else {
                continue;
            };
            let mut args = Vec::with_capacity(ctor.args.len());
            let mut arg_docs = Vec::with_capacity(ctor.args.len());
            for arg in &ctor.args {
                args.push(type_signature(arg, interner).map_err(typecheck_err)?);
                arg_docs.push(canon_type_to_doc(arg, interner).map_err(typecheck_err)?);
            }
            ctors.insert(ctor_name.to_owned(), args);
            ctor_types.insert(ctor_name.to_owned(), arg_docs);
        }
        unions.insert(
            name.to_owned(),
            UnionApi {
                params: union.vars.len(),
                ctors,
                ctor_types,
            },
        );
    }

    Ok(ModuleApi {
        values,
        value_types,
        unions,
    })
}

/// α-canonicalising name assignment for a constructor's type variables: each
/// distinct annotation symbol gets a stable first-seen letter, so two unions
/// differing only in variable spelling render identically.
#[derive(Default)]
struct CtorVars {
    names: BTreeMap<u32, String>,
}

impl CtorVars {
    fn name_of(&mut self, sym: ipe_intern::Symbol) -> String {
        let raw = sym.as_raw();
        if let Some(existing) = self.names.get(&raw) {
            return existing.clone();
        }
        let name =
            ipe_types::letters(u32::try_from(self.names.len()).unwrap_or(u32::MAX)).to_string();
        self.names.insert(raw, name.clone());
        name
    }
}

/// Render a canon-level [`ipe_canon::ast::Type`] (a constructor's declared
/// argument) into a stable signature string, α-canonicalising its variables.
fn type_signature(
    ty: &ipe_canon::ast::Type,
    interner: &ipe_intern::Interner,
) -> Result<String, Diagnostic> {
    let mut vars = CtorVars::default();
    canon_type_to_string(ty, interner, &mut vars)
}

/// Recursively render a canon type. Type variables are named by first-seen
/// order (shared across one constructor's argument list via `vars`), matching
/// the α-canonicalisation the value signatures use.
fn canon_type_to_string(
    ty: &ipe_canon::ast::Type,
    interner: &ipe_intern::Interner,
    vars: &mut CtorVars,
) -> Result<String, Diagnostic> {
    use ipe_canon::ast::Type;
    let render_symbol = |sym: ipe_intern::Symbol| -> Result<String, Diagnostic> {
        interner
            .resolve(sym)
            .map(str::to_owned)
            .ok_or_else(|| Diagnostic::CompilerBug {
                where_: "diff.canon_type",
                detail: format!("no backing string for symbol {}", sym.as_raw()),
            })
    };
    match ty {
        Type::Var(sym) => Ok(vars.name_of(*sym)),
        Type::Con { home, name, args } => {
            let mut head = String::new();
            for seg in home {
                head.push_str(&render_symbol(*seg)?);
                head.push('.');
            }
            head.push_str(&render_symbol(*name)?);
            if args.is_empty() {
                return Ok(head);
            }
            let mut rendered = Vec::with_capacity(args.len());
            for a in args {
                rendered.push(canon_type_arg(a, interner, vars)?);
            }
            Ok(format!("{head} {}", rendered.join(" ")))
        }
        Type::Lambda(a, b) => {
            let a = canon_type_arg(a, interner, vars)?;
            let b = canon_type_to_string(b, interner, vars)?;
            Ok(format!("{a} -> {b}"))
        }
        Type::Tuple(elems) => {
            let mut rendered = Vec::with_capacity(elems.len());
            for e in elems {
                rendered.push(canon_type_to_string(e, interner, vars)?);
            }
            Ok(format!("({})", rendered.join(", ")))
        }
        Type::Unit => Ok("()".to_owned()),
        Type::Record(fields) => {
            let mut entries = Vec::with_capacity(fields.len());
            for (fname, fty) in fields {
                entries.push(format!(
                    "{} : {}",
                    render_symbol(*fname)?,
                    canon_type_to_string(fty, interner, vars)?
                ));
            }
            entries.sort();
            Ok(format!("{{ {} }}", entries.join(", ")))
        }
        Type::RecordOpen(row_var, fields) => {
            let mut entries = Vec::with_capacity(fields.len());
            for (fname, fty) in fields {
                entries.push(format!(
                    "{} : {}",
                    render_symbol(*fname)?,
                    canon_type_to_string(fty, interner, vars)?
                ));
            }
            entries.sort();
            Ok(format!(
                "{{ {} | {} }}",
                vars.name_of(*row_var),
                entries.join(", ")
            ))
        }
    }
}

/// Render a canon type in argument position, parenthesising applications and
/// arrows so `List (Maybe a)` and `(a -> b) -> c` read unambiguously.
fn canon_type_arg(
    ty: &ipe_canon::ast::Type,
    interner: &ipe_intern::Interner,
    vars: &mut CtorVars,
) -> Result<String, Diagnostic> {
    use ipe_canon::ast::Type;
    let inner = canon_type_to_string(ty, interner, vars)?;
    let needs_parens =
        matches!(ty, Type::Lambda(..)) || matches!(ty, Type::Con { args, .. } if !args.is_empty());
    if needs_parens {
        Ok(format!("({inner})"))
    } else {
        Ok(inner)
    }
}

/// Extract the public API surface of the package rooted at `root`.
///
/// Reads every module, typechecks the package, and projects each module's typed
/// interface into a canonical [`PublicApi`].
///
/// # Errors
/// [`DiffError`] on a read failure, a typecheck failure, an open interface, or an
/// empty tree.
pub fn extract_tree(root: &Path) -> Result<PublicApi, DiffError> {
    let sources = read_tree(root)?;

    let db = ipe_db::IpeDatabase::new();
    let mut prepared: BTreeMap<Vec<String>, (PathBuf, String)> = sources.clone();
    let mut discovered: Vec<project::DiscoveredModule> = sources
        .iter()
        .map(|(p, (path, _))| project::DiscoveredModule {
            path: path.clone(),
            module_path: p.clone(),
        })
        .collect();
    let injected = project::inject_compiled_std_closure(&mut prepared, &mut discovered);
    let source_root = crate::create_source_root(&db, &prepared, &injected, &BTreeSet::new());

    let user_modules: BTreeSet<Vec<String>> = sources.keys().cloned().collect();
    extract_from_db(&db, source_root, &user_modules)
}

/// Extract the public API surface of one compiled-source stdlib module.
///
/// The module declares into the reserved `Ipe.*` namespace, which a *user* module
/// may not — so classifying it as a user module rejects it with a
/// reserved-namespace error. Here the target carries
/// [`ipe_canon::ModuleOrigin::EmbeddedStdlib`], the same origin it has inside a
/// real project's injected stdlib closure, so name resolution accepts the
/// reserved declaration and its interface projects with full signatures.
///
/// `segments` names the module (`["Ipe", "Url"]`); `source` is its embedded Ipê
/// text. The module's own compiled-source imports are injected as dependencies.
///
/// # Errors
/// [`DiffError`] on a typecheck failure or open interface.
pub fn extract_stdlib_module(segments: &[String], source: &str) -> Result<PublicApi, DiffError> {
    let db = ipe_db::IpeDatabase::new();

    let mut prepared: BTreeMap<Vec<String>, (PathBuf, String)> = BTreeMap::new();
    let synth_path = PathBuf::from("<embedded-stdlib>").join(segments.join("."));
    prepared.insert(segments.to_vec(), (synth_path.clone(), source.to_owned()));

    let mut discovered = vec![project::DiscoveredModule {
        path: synth_path,
        module_path: segments.to_vec(),
    }];

    // Inject the module's compiled-source import closure, then mark the target
    // itself as embedded stdlib so it may declare into the reserved namespace.
    let mut injected = project::inject_compiled_std_closure(&mut prepared, &mut discovered);
    injected.insert(segments.to_vec());

    let source_root = crate::create_source_root(&db, &prepared, &injected, &BTreeSet::new());

    // Project only the target module — its injected dependencies are not part of
    // the surface being documented.
    let target: BTreeSet<Vec<String>> = std::iter::once(segments.to_vec()).collect();
    extract_from_db(&db, source_root, &target)
}

/// Project the public API of `user_modules` out of an already-populated database.
///
/// Separated from [`extract_tree`] so the extraction logic is exercised over a
/// controlled source set (the user modules only — never the injected stdlib
/// closure, which is not part of the package's own public API).
fn extract_from_db(
    db: &ipe_db::IpeDatabase,
    source_root: ipe_db::SourceRoot,
    user_modules: &BTreeSet<Vec<String>>,
) -> Result<PublicApi, DiffError> {
    use ipe_db::Db as _;

    let files: BTreeMap<Vec<String>, ipe_db::SourceFile> = source_root
        .files(db)
        .iter()
        .map(|(p, f)| (p.clone(), *f))
        .collect();

    let mut modules = BTreeMap::new();
    for (path, file) in &files {
        if !user_modules.contains(path) {
            continue;
        }
        match ipe_db::typed_interface(db, source_root, *file) {
            Some(interface) => {
                // Scope the interner lock to the projection only — it must not
                // outlive this arm, and the mutex is not reentrant.
                let module_api = {
                    let interner = db.interner().lock();
                    project_interface(interface, &interner, path)?
                };
                modules.insert(path.clone(), module_api);
            }
            None => {
                // `None` is either an open interface or a red program. Demand the
                // scoped types to tell them apart: a red module yields a typed
                // diagnostic (fail closed on a package that does not typecheck);
                // a green-but-open module reports the open-interface refusal.
                match ipe_db::typecheck_module(db, source_root, *file, *file) {
                    Ok(_) => {
                        return Err(DiffError::OpenInterface {
                            module: path.clone(),
                        });
                    }
                    Err((diag, _home)) => {
                        return Err(DiffError::Typecheck {
                            module: path.clone(),
                            diag: Box::new(diag.clone()),
                        });
                    }
                }
            }
        }
    }

    if modules.is_empty() {
        return Err(DiffError::OpenInterface { module: Vec::new() });
    }
    Ok(PublicApi { modules })
}
