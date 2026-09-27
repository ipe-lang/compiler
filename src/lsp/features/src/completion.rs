//! Completion: in-scope identifiers at a cursor position, ranked by the type
//! the surrounding context expects (type-directed completion).
//!
//! Reads `canonicalize` (for every in-scope name and its resolved kind),
//! `typecheck` (for rendered type strings AND the `expected` sidecar) from the
//! same memoized `ipe_db` queries the compiler runs. A program that does not
//! type-check still yields completion items — the provider degrades gracefully
//! to kind-only, scope-only items rather than returning nothing.
//!
//! ## Type-directed ranking (ADR 0007 / LSP plan §6)
//!
//! When the cursor sits in a position with a contextual expected type (a call
//! argument, a typed body, an `if`/`case` branch, a list element — see
//! `ipe_types`' `expected` sidecar), each candidate is classified against that
//! type by the closed enum [`Compat`]:
//!
//! - [`Compat::ExactType`] — the candidate produces exactly the expected type
//!   head (a constructor of the expected union; a value whose result type head
//!   matches). Ranked first.
//! - [`Compat::Unifiable`] — the candidate's result type could unify with the
//!   expected type (the expected type is an unbound variable, or a shared
//!   constructor head with compatible arity). Ranked next.
//! - [`Compat::InScopeOnly`] — no type evidence relates the candidate to the
//!   expected type.
//!
//! When an expected type exists, [`Compat::InScopeOnly`] candidates are
//! **dropped** — an expected-`Int` slot never offers a `String`. When no
//! expected type exists (the common case away from an expecting context),
//! every candidate is kept and ranked by name only, exactly as before this
//! sidecar existed. The classification order is encoded into each item's
//! `sort_text` so the editor renders it deterministically.
//!
//! Lock discipline: salsa queries (which acquire the interner internally) are
//! all demanded BEFORE the caller acquires the interner lock — no nested
//! locking.

use std::collections::BTreeMap;

use ipe_db::{Db as _, IpeDatabase, SourceRoot};
use ipe_intern::Symbol;
use ipe_types::Ty;
use lsp_types::{CompletionItem, CompletionItemKind, InsertTextFormat};

use crate::expected_type::expected_type_at;

/// Represents a collected completion candidate before string resolution.
struct Candidate {
    name: Symbol,
    home: Vec<Symbol>,
    kind: CandidateKind,
    /// The `(module, type-name)` head of the type this candidate *produces*,
    /// when statically known: a constructor produces its owning union; a value
    /// produces the head of its (arrow-peeled) result type, resolved from the
    /// solved env at render time. `None` when no head is determinable (e.g. a
    /// polymorphic or unsolved value). Drives type-directed classification.
    result_head: Option<(Vec<Symbol>, Symbol)>,
    /// Payload arity of this constructor (0 for nullary). Used to generate
    /// snippet tab-stops so editors insert the right number of argument
    /// placeholders. Always 0 for non-`Ctor` kinds.
    arity: usize,
}

enum CandidateKind {
    Value,
    Ctor,
    Type,
}

/// How a candidate relates to the type the cursor context expects.
///
/// A closed enum with a deterministic total order (`ExactType` < `Unifiable` <
/// `InScopeOnly`) encoded into `sort_text`, so the ranking is stable and the
/// editor renders best-first.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Compat {
    /// The candidate produces exactly the expected type head.
    ExactType,
    /// The candidate's result type could unify with the expected type.
    Unifiable,
    /// No type evidence relates the candidate to the expected type.
    InScopeOnly,
}

impl Compat {
    /// The `sort_text` rank prefix — lexicographically ordered so the editor
    /// sorts `ExactType` above `Unifiable` above `InScopeOnly`, and keywords
    /// (rank `3`) last of all.
    const fn rank(self) -> char {
        match self {
            Self::ExactType => '0',
            Self::Unifiable => '1',
            Self::InScopeOnly => '2',
        }
    }
}

/// A module qualifier and its partial name at the cursor.
///
/// E.g. the cursor right after `d` in `Util.d` parses to
/// `{ qualifier: "Util", prefix: "d" }`; the cursor right after the dot in
/// `Util.` parses to an empty `prefix`.
struct QualifiedCursor {
    qualifier: String,
    prefix: String,
}

/// Scan raw source text for a `Qualifier.prefix` access ending at `byte`.
///
/// Reads `text` directly — never the lexer or parser — so it still resolves
/// while the surrounding buffer fails to lex. Returns `None` when the cursor
/// is not immediately preceded by an uppercase-led qualifier and a dot: an
/// unqualified position, which the caller completes against ordinary scope
/// instead.
fn qualified_cursor(text: &str, byte: u32) -> Option<QualifiedCursor> {
    let byte = usize::try_from(byte).ok()?;
    let head = text.get(..byte)?;

    let mut chars = head.char_indices().rev();
    let mut prefix_start = byte;
    let mut next = chars.next();
    while let Some((idx, c)) = next {
        if !is_ident_continue(c) {
            break;
        }
        prefix_start = idx;
        next = chars.next();
    }
    let prefix = head.get(prefix_start..byte)?.to_owned();

    // `next` now holds the first non-identifier char before the prefix, if
    // any — it must be the qualifier's dot.
    let (dot_idx, dot) = next?;
    if dot != '.' {
        return None;
    }

    let before_dot = head.get(..dot_idx)?;
    let mut chars = before_dot.char_indices().rev();
    let mut qual_start = dot_idx;
    let mut next = chars.next();
    while let Some((idx, c)) = next {
        if !is_ident_continue(c) {
            break;
        }
        qual_start = idx;
        next = chars.next();
    }
    let qualifier = head.get(qual_start..dot_idx)?.to_owned();
    if !qualifier.starts_with(|c: char| c.is_ascii_uppercase()) {
        return None;
    }

    Some(QualifiedCursor { qualifier, prefix })
}

const fn is_ident_continue(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// All completion candidates visible in `module`, ranked by the type expected
/// at `byte`.
///
/// Returns an empty list for an unknown module or an unparseable project.
#[must_use]
pub fn completions(
    db: &IpeDatabase,
    root: SourceRoot,
    entry: ipe_db::SourceFile,
    module: &[String],
    byte: u32,
    docs: Option<&ipe_docs::Index>,
) -> Vec<CompletionItem> {
    let files = root.files(db);
    let Some(&file) = files.get(module) else {
        return Vec::new();
    };

    // A `Qualifier.prefix` cursor delegates entirely to the qualified path:
    // only that qualifier's own exports, filtered by prefix — never the
    // current module's scope, never other deps, never keywords. Scanned from
    // raw text (never the lexer), so it still resolves while this very file
    // fails to lex (e.g. a bare trailing `.` typed mid-edit, which fails this
    // file's parse and cascades to canonicalize/resolve_imports/typecheck all
    // failing for it) — completion's fallback to last-good module info.
    if let Some(cursor) = qualified_cursor(file.text(db), byte) {
        return qualified_completions(db, root, entry, file, &cursor, docs);
    }

    // Demand all salsa queries before locking the interner — each query
    // internally acquires + releases the interner lock, and the Mutex is not
    // reentrant. All results are cloned out of their `Arc` wrappers here so
    // the interner is free when we acquire it below.
    let canonical = crate::db_access::canonicalize_checked(db, root, entry, file);
    let dep_canonicals = collect_dep_canonicals(db, root, entry, file);
    // This module's own binding types, from the per-module `typecheck_module`
    // projection (keyed by bare name — the home is fixed to this module).
    let module_env: Option<BTreeMap<Symbol, Ty>> = ipe_db::typecheck_module(db, root, entry, file)
        .as_ref()
        .ok()
        .map(|types| types.env.clone());
    // Dep bindings' types come from the deps' own per-module projections, so a
    // cross-module value candidate still carries its solved type for ranking.
    let dep_envs: Vec<(Vec<Symbol>, BTreeMap<Symbol, Ty>)> =
        collect_dep_envs(db, root, entry, file);
    // The type the surrounding context expects at the cursor, if any. `None`
    // away from an expecting context (or on a non-type-checking program) — the
    // provider then ranks by name only, keeping every candidate.
    let expected = expected_type_at(db, root, entry, file, byte);

    // Acquire the interner once — all subsequent work is resolution-only.
    let mut interner = db.interner().lock();

    let home_syms: Vec<Symbol> = module
        .iter()
        .map(|s| interner.intern(s).ok())
        .collect::<Option<Vec<_>>>()
        .unwrap_or_default();

    let candidates = build_candidates(
        &mut interner,
        canonical.as_ref(),
        &home_syms,
        &dep_canonicals,
    );

    // Reassemble the `home → (name → Ty)` lookup the renderer keys on, from the
    // per-module projections: this module's env under `home_syms`, plus each
    // dep's env under its own home. Nesting by home lets the renderer look up by
    // a borrowed home slice (no per-candidate key allocation) and moves each
    // per-module env in wholesale rather than re-inserting entry by entry.
    let mut solved_env: BTreeMap<Vec<Symbol>, BTreeMap<Symbol, Ty>> = BTreeMap::new();
    if let Some(env) = module_env {
        solved_env.insert(home_syms, env);
    }
    for (dep_home, env) in dep_envs {
        solved_env.entry(dep_home).or_default().extend(env);
    }

    let mut items: Vec<CompletionItem> = render_candidates(
        &candidates,
        Some(&solved_env),
        expected.as_ref(),
        &interner,
        docs,
    );

    drop(interner);

    for kw in KEYWORDS {
        items.push(keyword_item(kw));
    }

    // Deduplicate by label — first occurrence wins (current-module names
    // have priority over imported names; both beat keywords).
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    items.retain(|item| seen.insert(item.label.clone()));

    // Stable sort by (sort_text, label) so the type-directed rank leads and the
    // editor sees a deterministic best-first order without relying on its own
    // fuzzy sort. Items always carry a `sort_text` (set in the renderers).
    items.sort_by(|a, b| {
        let ka = (a.sort_text.as_deref().unwrap_or(""), a.label.as_str());
        let kb = (b.sort_text.as_deref().unwrap_or(""), b.label.as_str());
        ka.cmp(&kb)
    });

    items
}

/// Fetch the canonical module for each resolved import, before the interner
/// is locked. Returns `(dep_path, canonical_module)` pairs.
fn collect_dep_canonicals(
    db: &IpeDatabase,
    root: SourceRoot,
    entry: ipe_db::SourceFile,
    file: ipe_db::SourceFile,
) -> Vec<(Vec<String>, std::sync::Arc<ipe_db::CanonicalModule>)> {
    let Ok(resolutions) = ipe_db::resolve_imports(db, root, file) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (dep_path, resolution) in resolutions.iter() {
        if let ipe_db::ImportResolution::Resolved(dep_file) = resolution
            && let Some(dep_canon) =
                crate::db_access::canonicalize_checked(db, root, entry, *dep_file)
        {
            // Keep the salsa `Arc` — the consumers only borrow it, so a
            // refcount bump replaces a full deep-copy of the canonical module.
            out.push((dep_path.clone(), dep_canon));
        }
    }
    out
}

/// Fetch each resolved dep's per-module env (its binding types), keyed by the
/// dep's interned home path. Demanded before the interner is locked, like
/// [`collect_dep_canonicals`]. A dep that does not project (its own error) is
/// skipped — its value candidates simply carry no type detail.
fn collect_dep_envs(
    db: &IpeDatabase,
    root: SourceRoot,
    entry: ipe_db::SourceFile,
    file: ipe_db::SourceFile,
) -> Vec<(Vec<Symbol>, BTreeMap<Symbol, Ty>)> {
    let Ok(resolutions) = ipe_db::resolve_imports(db, root, file) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (dep_path, resolution) in resolutions.iter() {
        if let ipe_db::ImportResolution::Resolved(dep_file) = resolution
            && let Ok(dep_types) = ipe_db::typecheck_module(db, root, entry, *dep_file)
        {
            let dep_home: Vec<Symbol> = {
                let mut interner = db.interner().lock();
                dep_path
                    .iter()
                    .filter_map(|s| interner.intern(s).ok())
                    .collect()
            };
            out.push((dep_home, dep_types.env.clone()));
        }
    }
    out
}

/// One `import` declaration found in raw source text: its dotted module path
/// and `as`-alias, if any.
///
/// Scanned line by line from the raw buffer — independent of the
/// lexer/parser — so the import list survives even when the rest of the file
/// fails to lex. This is qualified completion's "last-good module info" for
/// resolving a qualifier.
struct RawImport {
    path: Vec<String>,
    alias: Option<String>,
}

/// Scan every `import <Path>[ as <Alias>]` line in `text`.
///
/// Anything after the path and an optional alias (e.g. an `exposing (...)`
/// clause) is ignored — resolving a qualifier needs neither.
fn scan_raw_imports(text: &str) -> Vec<RawImport> {
    let mut out = Vec::new();
    for line in text.lines() {
        let Some(rest) = line.trim_start().strip_prefix("import ") else {
            continue;
        };
        let mut words = rest.trim_start().split_whitespace();
        let Some(path_word) = words.next() else {
            continue;
        };
        let path: Vec<String> = path_word.split('.').map(str::to_owned).collect();
        if path.iter().any(String::is_empty) {
            continue;
        }
        let mut alias = None;
        if words.next() == Some("as") {
            alias = words.next().map(str::to_owned);
        }
        out.push(RawImport { path, alias });
    }
    out
}

/// Resolve a written qualifier (e.g. `Util` in `Util.foo`) to the dotted
/// module path it names.
///
/// Checks every import's `as`-alias before any import's own last path
/// segment — an alias shadows a same-spelled leaf module name, mirroring
/// `canon::shape_source::resolve_qualifier_to_module_path`. `None` when no
/// import names this qualifier.
fn resolve_qualifier(qualifier: &str, imports: &[RawImport]) -> Option<Vec<String>> {
    imports
        .iter()
        .find(|import| import.alias.as_deref() == Some(qualifier))
        .or_else(|| {
            imports.iter().find(|import| {
                import.alias.is_none() && import.path.last().map(String::as_str) == Some(qualifier)
            })
        })
        .map(|import| import.path.clone())
}

/// Completion for a `Qualifier.prefix` cursor: only the resolved qualifier's
/// own exports, filtered by `prefix`.
///
/// Never falls back to the whole scope or to keywords — an unresolved
/// qualifier, or a resolved dep that fails to canonicalize, yields no
/// candidates (fail-closed): a typo should offer nothing sooner than noise.
fn qualified_completions(
    db: &IpeDatabase,
    root: SourceRoot,
    entry: ipe_db::SourceFile,
    file: ipe_db::SourceFile,
    cursor: &QualifiedCursor,
    docs: Option<&ipe_docs::Index>,
) -> Vec<CompletionItem> {
    let imports = scan_raw_imports(file.text(db));
    let Some(path) = resolve_qualifier(&cursor.qualifier, &imports) else {
        return Vec::new();
    };
    let files = root.files(db);
    let Some(&dep_file) = files.get(&path) else {
        return Vec::new();
    };
    let Some(dep_canon) = crate::db_access::canonicalize_checked(db, root, entry, dep_file) else {
        return Vec::new();
    };
    // Demanded before the interner is locked below, like `completions` itself.
    let dep_env: BTreeMap<Symbol, Ty> = ipe_db::typecheck_module(db, root, entry, dep_file)
        .as_ref()
        .ok()
        .map(|types| types.env.clone())
        .unwrap_or_default();

    let mut interner = db.interner().lock();
    let dep_home: Vec<Symbol> = path
        .iter()
        .map(|s| interner.intern(s).ok())
        .collect::<Option<Vec<_>>>()
        .unwrap_or_default();
    let candidates = push_dep_candidates(&dep_home, &dep_canon);

    let mut solved_env: BTreeMap<Vec<Symbol>, BTreeMap<Symbol, Ty>> = BTreeMap::new();
    solved_env.insert(dep_home, dep_env);

    let items = render_candidates(&candidates, Some(&solved_env), None, &interner, docs);
    drop(interner);

    items
        .into_iter()
        .filter(|item| item.label.starts_with(&cursor.prefix))
        .collect()
}

/// A resolved dep's exported values, constructors, and types as candidates
/// under `dep_home`.
///
/// Shared by unqualified scope completion (every resolved dep, from
/// [`build_candidates`]) and qualified completion (one resolved dep, from
/// [`qualified_completions`]) so both paths build candidates identically.
fn push_dep_candidates(dep_home: &[Symbol], dep_canon: &ipe_db::CanonicalModule) -> Vec<Candidate> {
    let mut out = Vec::new();
    for &name_sym in &dep_canon.exports.values {
        out.push(Candidate {
            name: name_sym,
            home: dep_home.to_vec(),
            kind: CandidateKind::Value,
            result_head: None,
            arity: 0,
        });
    }
    for &ctor_sym in dep_canon.exports.ctors.keys() {
        // A dep constructor's owning-union head is recoverable from the
        // dep's own unions (the export map records the ctor→type link).
        let head = dep_ctor_head(dep_canon, ctor_sym);
        let arity = dep_ctor_arity(dep_canon, ctor_sym);
        out.push(Candidate {
            name: ctor_sym,
            home: dep_home.to_vec(),
            kind: CandidateKind::Ctor,
            result_head: head,
            arity,
        });
    }
    for &type_sym in dep_canon.exports.types.keys() {
        out.push(Candidate {
            name: type_sym,
            home: dep_home.to_vec(),
            kind: CandidateKind::Type,
            result_head: None,
            arity: 0,
        });
    }
    out
}

/// Collect all raw candidates (symbol + home + kind + result-type head) while
/// the interner is held, so that intern calls for dep paths are batched in one
/// lock window.
fn build_candidates(
    interner: &mut ipe_intern::Interner,
    canonical: Option<&std::sync::Arc<ipe_db::CanonicalModule>>,
    home_syms: &[Symbol],
    dep_canonicals: &[(Vec<String>, std::sync::Arc<ipe_db::CanonicalModule>)],
) -> Vec<Candidate> {
    let mut out: Vec<Candidate> = Vec::new();

    if let Some(canon) = canonical {
        for def in &canon.module.defs {
            out.push(Candidate {
                name: def.name().value,
                home: home_syms.to_vec(),
                kind: CandidateKind::Value,
                result_head: None, // resolved from the solved env at render time
                arity: 0,
            });
        }
        for union in &canon.module.unions {
            out.push(Candidate {
                name: union.name,
                home: home_syms.to_vec(),
                kind: CandidateKind::Type,
                result_head: None,
                arity: 0,
            });
            for ctor in &union.ctors {
                out.push(Candidate {
                    name: ctor.name,
                    home: home_syms.to_vec(),
                    kind: CandidateKind::Ctor,
                    // A constructor produces its owning union type — the head
                    // that makes it an ExactType match for an expected union.
                    result_head: Some((union.home.clone(), union.name)),
                    arity: ctor.arity,
                });
            }
        }
    }

    for (dep_path, dep_canon) in dep_canonicals {
        let dep_home: Vec<Symbol> = dep_path
            .iter()
            .map(|s| interner.intern(s).ok())
            .collect::<Option<Vec<_>>>()
            .unwrap_or_default();
        out.extend(push_dep_candidates(&dep_home, dep_canon));
    }
    out
}

/// The `(module, type-name)` head of the union a dep constructor produces,
/// found by scanning the dep's canonical unions for the one that declares it.
fn dep_ctor_head(
    dep_canon: &ipe_db::CanonicalModule,
    ctor: Symbol,
) -> Option<(Vec<Symbol>, Symbol)> {
    for union in &dep_canon.module.unions {
        if union.ctors.iter().any(|c| c.name == ctor) {
            return Some((union.home.clone(), union.name));
        }
    }
    None
}

/// The payload arity of a dep constructor, found by scanning the dep's unions.
/// Returns 0 when the constructor is not found (nullary / unknown).
fn dep_ctor_arity(dep_canon: &ipe_db::CanonicalModule, ctor: Symbol) -> usize {
    for union in &dep_canon.module.unions {
        for c in &union.ctors {
            if c.name == ctor {
                return c.arity;
            }
        }
    }
    0
}

/// Resolve each candidate to a `CompletionItem`, adding type detail for values
/// and a type-directed `sort_text` rank. When `expected` is present, drop
/// candidates that carry no type relation to it (`InScopeOnly`).
fn render_candidates(
    candidates: &[Candidate],
    solved_env: Option<&BTreeMap<Vec<Symbol>, BTreeMap<Symbol, Ty>>>,
    expected: Option<&Ty>,
    interner: &ipe_intern::Interner,
    docs: Option<&ipe_docs::Index>,
) -> Vec<CompletionItem> {
    let mut items = Vec::new();
    for c in candidates {
        let Some(name_str) = interner.resolve(c.name) else {
            continue;
        };
        // The candidate's own solved type (values only), used for both the
        // detail string and result-head classification. The home is looked up by
        // a borrowed slice, so no key is allocated per candidate.
        let value_ty: Option<&Ty> = match c.kind {
            CandidateKind::Value => {
                solved_env.and_then(|env| env.get(c.home.as_slice())?.get(&c.name))
            }
            CandidateKind::Ctor | CandidateKind::Type => None,
        };

        let compat = classify(c, value_ty, expected);
        // Type-directed filter: with an expected type present, a candidate that
        // bears no relation to it is not offered at all.
        if expected.is_some() && compat == Compat::InScopeOnly {
            continue;
        }

        let detail = value_ty.and_then(|ty| {
            let mut namer = ipe_types::VarNamer::new();
            ipe_types::ty_to_doc(ty, interner, &mut namer)
                .ok()
                .map(|doc| ipe_diagnostics::render_ty(&doc))
        });

        let sort_text = format!("{}{}", compat.rank(), name_str);
        let mut item = match c.kind {
            CandidateKind::Value => value_item(name_str.to_owned(), detail, sort_text),
            CandidateKind::Ctor => ctor_item(name_str.to_owned(), c.arity, sort_text),
            CandidateKind::Type => type_item(name_str.to_owned(), sort_text),
        };
        // Enrich with the symbol's real doc from the `ipe_docs` index, keyed on
        // the candidate's exact home module + name. A user binding or an
        // undocumented symbol resolves nothing and stays doc-less (fail-closed).
        if let Some(index) = docs {
            let home: Option<Vec<String>> = c
                .home
                .iter()
                .map(|&s| interner.resolve(s).map(str::to_owned))
                .collect();
            if let Some(home) = home
                && let Some(doc) = crate::docs_lookup::symbol_doc(index, &home, name_str)
            {
                item.documentation = Some(crate::docs_lookup::as_documentation(doc));
            }
        }
        items.push(item);
    }
    items
}

/// Classify a candidate against the expected type.
///
/// The comparison is by TYPE HEAD — the outermost constructor of the candidate's
/// produced type versus the expected type — which is the sound, conservative
/// core of unification for ranking: a constructor of the expected union, or a
/// value whose (arrow-peeled) result head equals the expected head, is an
/// `ExactType`; an expected type variable admits anything (`Unifiable`); a
/// shared head with differing args is `Unifiable` (a full arg-wise unify is a
/// later refinement, tracked in the plan); everything else is `InScopeOnly`.
fn classify(c: &Candidate, value_ty: Option<&Ty>, expected: Option<&Ty>) -> Compat {
    let Some(expected) = expected else {
        return Compat::InScopeOnly;
    };
    // An expected type variable is satisfied by any candidate — it constrains
    // nothing, so keep the candidate but do not privilege it.
    if matches!(expected, Ty::Var(_)) {
        return Compat::Unifiable;
    }
    let Some((exp_mod, exp_name)) = con_head(expected) else {
        // Expected is a function / tuple / record / unit — head-based ranking
        // does not apply; keep the candidate as merely in-scope.
        return Compat::InScopeOnly;
    };

    // Constructor / type candidates carry their produced head statically.
    if let Some((head_mod, head_name)) = &c.result_head {
        return head_compat(head_mod, *head_name, exp_mod, exp_name);
    }

    // A value candidate: peel its result type's head from the solved env.
    if let Some(ty) = value_ty
        && let Some((head_mod, head_name)) = con_head(result_of(ty))
    {
        return head_compat(head_mod, head_name, exp_mod, exp_name);
    }

    Compat::InScopeOnly
}

/// Compare two type heads (`(module, name)`), yielding `ExactType` on an exact
/// match and `InScopeOnly` otherwise. (Cross-module same-name heads are treated
/// as distinct — module identity is part of the head.)
fn head_compat(
    head_mod: &[Symbol],
    head_name: Symbol,
    exp_mod: &[Symbol],
    exp_name: Symbol,
) -> Compat {
    if head_name == exp_name && head_mod == exp_mod {
        Compat::ExactType
    } else {
        Compat::InScopeOnly
    }
}

/// The result type of a (possibly curried) function type — peel every leading
/// arrow. A non-function type is its own result.
fn result_of(ty: &Ty) -> &Ty {
    let mut cur = ty;
    while let Ty::Fun(_, ret) = cur {
        cur = ret;
    }
    cur
}

/// The `(module, name)` head of a `Ty::Con`, if the type is a constructor
/// application. `None` for variables, functions, tuples, records, unit.
const fn con_head(ty: &Ty) -> Option<(&[Symbol], Symbol)> {
    match ty {
        Ty::Con { module, name, .. } => Some((module.as_slice(), *name)),
        _ => None,
    }
}

fn value_item(label: String, detail: Option<String>, sort_text: String) -> CompletionItem {
    // `insert_text` mirrors the label so editors that do not verbatim-apply the
    // label (e.g. those that strip a type suffix) still insert the bare name.
    CompletionItem {
        insert_text: Some(label.clone()),
        insert_text_format: Some(InsertTextFormat::PLAIN_TEXT),
        label,
        kind: Some(CompletionItemKind::FUNCTION),
        detail,
        sort_text: Some(sort_text),
        ..CompletionItem::default()
    }
}

/// Build a completion item for a data constructor.
///
/// When the constructor is nullary (`arity == 0`) the insert text is the bare
/// name (plain text). When it carries payload fields (`arity > 0`) the insert
/// text is a snippet with one tab-stop per field (`${1:arg1}`, `${2:arg2}`, …),
/// so the editor positions the cursor inside the first argument and the user can
/// tab through the rest.
fn ctor_item(label: String, arity: usize, sort_text: String) -> CompletionItem {
    let (insert_text, format) = if arity == 0 {
        (label.clone(), InsertTextFormat::PLAIN_TEXT)
    } else {
        // Build `Name ${1:arg1} ${2:arg2} … ${N:argN}` — one space-separated
        // tab-stop per payload field. The placeholder names are generic (`arg1`
        // …) because the canonical AST does not carry field names for positional
        // constructor arguments.
        let stops: String = (1..=arity)
            .map(|i| format!("${{{i}:arg{i}}}"))
            .collect::<Vec<_>>()
            .join(" ");
        (format!("{label} {stops}"), InsertTextFormat::SNIPPET)
    };
    CompletionItem {
        insert_text: Some(insert_text),
        insert_text_format: Some(format),
        label,
        kind: Some(CompletionItemKind::ENUM_MEMBER),
        sort_text: Some(sort_text),
        ..CompletionItem::default()
    }
}

fn type_item(label: String, sort_text: String) -> CompletionItem {
    CompletionItem {
        insert_text: Some(label.clone()),
        insert_text_format: Some(InsertTextFormat::PLAIN_TEXT),
        label,
        kind: Some(CompletionItemKind::CLASS),
        sort_text: Some(sort_text),
        ..CompletionItem::default()
    }
}

fn keyword_item(label: &'static str) -> CompletionItem {
    CompletionItem {
        label: label.to_owned(),
        kind: Some(CompletionItemKind::KEYWORD),
        // Keywords sort after every user identifier (rank '3').
        sort_text: Some(format!("3{label}")),
        ..CompletionItem::default()
    }
}

/// Ipê keywords offered at every cursor position. Every entry is a real
/// reserved word per the lexer's own table (`ipe_parse::is_keyword`);
/// `completion_keywords_match_the_lexer` pins the two against drift.
const KEYWORDS: &[&str] = &[
    "module", "import", "exposing", "as", "type", "foreign", "case", "of", "let", "in", "if",
    "then", "else", "do",
];

#[cfg(test)]
mod tests {
    use ipe_db::{IpeDatabase, ModuleOrigin, SourceFile, SourceRoot};

    use super::{Candidate, CandidateKind, KEYWORDS, completions, render_candidates};

    /// Every completion keyword must be a real reserved word per the lexer's own
    /// table — no invented entry (a past list offered `alias`, which is not a
    /// keyword) and no drift from the lexer SSOT.
    #[test]
    fn completion_keywords_match_the_lexer() {
        for kw in KEYWORDS {
            assert!(
                ipe_parse::is_keyword(kw),
                "completion offers {kw:?}, which is not a lexer keyword"
            );
        }
        for kw in [
            "module", "import", "exposing", "as", "type", "foreign", "case", "of", "let", "in",
            "if", "then", "else", "do",
        ] {
            assert!(
                KEYWORDS.contains(&kw),
                "completion is missing the keyword {kw:?}"
            );
        }
    }

    fn file(db: &IpeDatabase, path: &[&str], text: &str) -> SourceFile {
        SourceFile::new(
            db,
            path.iter().map(|s| (*s).to_owned()).collect(),
            text.to_owned(),
            ModuleOrigin::User,
        )
    }

    fn root_of(db: &IpeDatabase, files: &[(&[&str], SourceFile)]) -> SourceRoot {
        SourceRoot::new(
            db,
            files
                .iter()
                .map(|(path, f)| (path.iter().map(|s| (*s).to_owned()).collect(), *f))
                .collect(),
        )
    }

    const HELPER: &str = "module Helper exposing (three, Color(..))\n\nthree : Int\nthree = 3\n\ntype Color = Red | Blue\n";
    const MAIN: &str = "module Main exposing (main)\n\nimport Helper exposing (three, Color(..))\n\nmain : Int\nmain = three\n";

    /// A cursor at byte 0 is in no expecting context → scope-only behavior
    /// (every name kept), preserving the pre-sidecar contract.
    #[test]
    fn own_module_names_and_imported_names_appear() {
        let db = IpeDatabase::new();
        let helper = file(&db, &["Helper"], HELPER);
        let entry = file(&db, &["Main"], MAIN);
        let root = root_of(&db, &[(&["Helper"], helper), (&["Main"], entry)]);

        let items = completions(&db, root, entry, &["Main".to_owned()], 0, None);
        let labels: Vec<&str> = items.iter().map(|i| i.label.as_str()).collect();

        assert!(labels.contains(&"main"), "main missing: {labels:?}");
        assert!(labels.contains(&"three"), "three missing: {labels:?}");
        assert!(labels.contains(&"Red"), "Red missing: {labels:?}");
        assert!(labels.contains(&"Blue"), "Blue missing: {labels:?}");
        assert!(labels.contains(&"Color"), "Color missing: {labels:?}");
        assert!(labels.contains(&"let"), "let missing: {labels:?}");
    }

    #[test]
    fn type_annotation_appears_in_detail_when_program_type_checks() {
        let db = IpeDatabase::new();
        let helper = file(&db, &["Helper"], HELPER);
        let entry = file(&db, &["Main"], MAIN);
        let root = root_of(&db, &[(&["Helper"], helper), (&["Main"], entry)]);

        let items = completions(&db, root, entry, &["Main".to_owned()], 0, None);
        let main_item = items
            .iter()
            .find(|i| i.label == "main")
            .expect("main item present");
        // `main : Int` — detail renders as "Int"
        assert_eq!(
            main_item.detail.as_deref(),
            Some("Int"),
            "wrong detail: {:?}",
            main_item.detail
        );
    }

    #[test]
    fn no_duplicates_in_completion_list() {
        let db = IpeDatabase::new();
        let helper = file(&db, &["Helper"], HELPER);
        let entry = file(&db, &["Main"], MAIN);
        let root = root_of(&db, &[(&["Helper"], helper), (&["Main"], entry)]);

        let items = completions(&db, root, entry, &["Main".to_owned()], 0, None);
        let mut seen = std::collections::BTreeSet::new();
        for item in &items {
            assert!(
                seen.insert(item.label.clone()),
                "duplicate label: {}",
                item.label
            );
        }
    }

    /// Type-directed ranking: in a `Color`-expecting body, the union's
    /// constructors rank first (`ExactType`) and an unrelated `Int` value is
    /// filtered out.
    #[test]
    fn expected_color_ranks_constructors_first_and_drops_int_value() {
        const SRC: &str = "module Main exposing (main)\n\ntype Color = Red | Blue\n\nn : Int\nn = 3\n\nfavorite : Color\nfavorite = Red\n\nmain = favorite\n";
        let db = IpeDatabase::new();
        let entry = file(&db, &["Main"], SRC);
        let root = root_of(&db, &[(&["Main"], entry)]);

        // Byte offset of `Red` in `favorite = Red` — the typed body position
        // that expects `Color`. (Target the def body, not the `= Red` that also
        // appears in the union declaration.)
        let byte =
            u32::try_from(SRC.find("favorite = Red").expect("has body") + "favorite = ".len())
                .expect("offset fits u32");
        let items = completions(&db, root, entry, &["Main".to_owned()], byte, None);
        let labels: Vec<&str> = items.iter().map(|i| i.label.as_str()).collect();

        // Constructors of the expected type are offered.
        assert!(labels.contains(&"Red"), "Red missing: {labels:?}");
        assert!(labels.contains(&"Blue"), "Blue missing: {labels:?}");
        // The `Int` value `n` bears no relation to `Color` → dropped.
        assert!(
            !labels.contains(&"n"),
            "an Int value must be filtered from a Color slot: {labels:?}"
        );
        // `Red`/`Blue` carry the ExactType rank ('0'), sorting ahead of any
        // Unifiable/InScopeOnly item.
        let red = items.iter().find(|i| i.label == "Red").unwrap();
        assert!(
            red.sort_text.as_deref().is_some_and(|s| s.starts_with('0')),
            "Red must rank ExactType: {:?}",
            red.sort_text
        );
    }

    /// Nullary constructors get `insert_text = label` (plain text). Payload
    /// constructors get a snippet with one tab-stop per field.
    #[test]
    fn ctor_insert_text_matches_arity() {
        use lsp_types::InsertTextFormat;
        // `Rect Int` has arity 1; `Circle` has arity 0. Complete at a body
        // position whose expected type is `Shape`, so both constructors are
        // offered — a bare module-scope position (offset 0) offers none.
        const SRC: &str = "module Main exposing (main)\n\ntype Shape = Circle | Rect Int\n\ns : Shape\ns = Circle\n\nmain = s\n";
        let db = IpeDatabase::new();
        let entry = file(&db, &["Main"], SRC);
        let root = root_of(&db, &[(&["Main"], entry)]);
        let byte = u32::try_from(SRC.find("s = Circle").expect("has body") + "s = ".len())
            .expect("offset fits u32");
        let items = completions(&db, root, entry, &["Main".to_owned()], byte, None);

        let circle = items
            .iter()
            .find(|i| i.label == "Circle")
            .expect("Circle present");
        assert_eq!(
            circle.insert_text.as_deref(),
            Some("Circle"),
            "nullary ctor insert_text must be the bare name"
        );
        assert_eq!(
            circle.insert_text_format,
            Some(InsertTextFormat::PLAIN_TEXT),
            "nullary ctor must use PLAIN_TEXT"
        );

        let rect = items
            .iter()
            .find(|i| i.label == "Rect")
            .expect("Rect present");
        let rect_text = rect.insert_text.as_deref().expect("Rect has insert_text");
        assert!(
            rect_text.starts_with("Rect "),
            "payload ctor insert_text must start with the name: {rect_text}"
        );
        assert!(
            rect_text.contains("${1:"),
            "payload ctor insert_text must contain a snippet tab-stop: {rect_text}"
        );
        assert_eq!(
            rect.insert_text_format,
            Some(InsertTextFormat::SNIPPET),
            "payload ctor must use SNIPPET format"
        );
    }

    /// Graceful degradation: a program that canonicalizes but does NOT
    /// type-check (a type mismatch) still yields scope-only completion — no
    /// expected type is inferable, so every in-scope name is kept, never empty.
    #[test]
    fn type_error_program_degrades_to_scope_only() {
        // `bad : Int ; bad = Red` canonicalizes (Red resolves) but fails to
        // type-check (Color ≠ Int) — so `typecheck` errors and no expected type
        // is available, yet the names still surface from `canonicalize`.
        const SRC: &str = "module Main exposing (main)\n\ntype Color = Red | Blue\n\nbad : Int\nbad = Red\n\nmain = bad\n";
        let db = IpeDatabase::new();
        let entry = file(&db, &["Main"], SRC);
        let root = root_of(&db, &[(&["Main"], entry)]);

        // A cursor inside the (type-erroring) `bad = Red` body.
        let byte = u32::try_from(SRC.find("bad = Red").expect("has body") + "bad = ".len())
            .expect("offset fits u32");
        let items = completions(&db, root, entry, &["Main".to_owned()], byte, None);
        let labels: Vec<&str> = items.iter().map(|i| i.label.as_str()).collect();
        // Names still surface (canonicalize succeeds even though typecheck fails);
        // no candidate is dropped because no expected type was inferable.
        assert!(
            labels.contains(&"Red"),
            "Red missing on type-error prog: {labels:?}"
        );
        assert!(
            labels.contains(&"bad"),
            "bad missing on type-error prog: {labels:?}"
        );
        assert!(
            labels.contains(&"main"),
            "main missing on type-error prog: {labels:?}"
        );
    }

    /// A candidate whose home + name resolves in the `ipe_docs` index carries
    /// that symbol's real documentation; a user-module candidate carries none.
    /// Proves the doc-enrichment path both fires (stdlib) and refuses (user).
    #[test]
    fn render_attaches_doc_for_stdlib_and_not_for_user_symbol() {
        let mut interner = ipe_intern::Interner::new();
        let ipe = interner.intern("Ipe").expect("intern Ipe");
        let maybe_mod = interner.intern("Maybe").expect("intern Maybe module");
        let with_default = interner.intern("withDefault").expect("intern withDefault");
        let user_mod = interner.intern("MyApp").expect("intern MyApp");
        let handler = interner.intern("handler").expect("intern handler");

        let candidates = vec![
            Candidate {
                name: with_default,
                home: vec![ipe, maybe_mod],
                kind: CandidateKind::Value,
                result_head: None,
                arity: 0,
            },
            Candidate {
                name: handler,
                home: vec![user_mod],
                kind: CandidateKind::Value,
                result_head: None,
                arity: 0,
            },
        ];

        let idx = ipe_docs::Index::build_embedded().expect("embedded docs index builds");
        let items = render_candidates(&candidates, None, None, &interner, Some(&idx));

        let std_item = items
            .iter()
            .find(|i| i.label == "withDefault")
            .expect("stdlib candidate rendered");
        assert!(
            std_item.documentation.is_some(),
            "a documented stdlib symbol must carry its doc"
        );

        let user_item = items
            .iter()
            .find(|i| i.label == "handler")
            .expect("user candidate rendered");
        assert!(
            user_item.documentation.is_none(),
            "a user-module symbol must carry no stdlib doc (fail-closed)"
        );
    }

    /// A bare trailing `Util.` (an aliased import) offers exactly that module's
    /// exports — never the current module's own names, never keywords.
    #[test]
    fn qualified_dot_offers_aliased_module_exports() {
        const SRC: &str = "module Main exposing (main)\n\nimport Helper as Util exposing (three, Color(..))\n\nmain = Util.\n";
        let db = IpeDatabase::new();
        let helper = file(&db, &["Helper"], HELPER);
        let entry = file(&db, &["Main"], SRC);
        let root = root_of(&db, &[(&["Helper"], helper), (&["Main"], entry)]);

        let byte = u32::try_from(SRC.find("Util.").expect("has qualifier") + "Util.".len())
            .expect("offset fits u32");
        let items = completions(&db, root, entry, &["Main".to_owned()], byte, None);
        let labels: Vec<&str> = items.iter().map(|i| i.label.as_str()).collect();

        assert!(labels.contains(&"three"), "three missing: {labels:?}");
        assert!(labels.contains(&"Color"), "Color missing: {labels:?}");
        assert!(labels.contains(&"Red"), "Red missing: {labels:?}");
        assert!(labels.contains(&"Blue"), "Blue missing: {labels:?}");
        assert!(
            !labels.contains(&"main"),
            "qualified completion must not include the current module: {labels:?}"
        );
        assert!(
            !labels.contains(&"let"),
            "qualified completion must not include keywords: {labels:?}"
        );
    }

    /// A qualified prefix (`Util.d`) filters the qualifier's exports down to
    /// names starting with that prefix.
    #[test]
    fn qualified_prefix_filters_aliased_module_exports() {
        const QUALIFIED_HELPER: &str = "module Helper exposing (three, double, Color(..))\n\nthree : Int\nthree = 3\n\ndouble : Int\ndouble = 6\n\ntype Color = Red | Blue\n";
        const SRC: &str = "module Main exposing (main)\n\nimport Helper as Util exposing (three, double, Color(..))\n\nmain = Util.d\n";
        let db = IpeDatabase::new();
        let helper = file(&db, &["Helper"], QUALIFIED_HELPER);
        let entry = file(&db, &["Main"], SRC);
        let root = root_of(&db, &[(&["Helper"], helper), (&["Main"], entry)]);

        let byte = u32::try_from(SRC.find("Util.d").expect("has qualifier") + "Util.d".len())
            .expect("offset fits u32");
        let items = completions(&db, root, entry, &["Main".to_owned()], byte, None);
        let labels: Vec<&str> = items.iter().map(|i| i.label.as_str()).collect();

        assert!(labels.contains(&"double"), "double missing: {labels:?}");
        assert!(
            !labels.contains(&"three"),
            "three must be filtered by prefix d: {labels:?}"
        );
        assert!(
            !labels.contains(&"Color"),
            "Color must be filtered by prefix d: {labels:?}"
        );
    }

    /// An unresolvable qualifier (no matching import alias or leaf module name)
    /// offers no candidates — fail-closed, never a fallback to the whole scope.
    #[test]
    fn unknown_qualifier_offers_no_candidates() {
        const SRC: &str = "module Main exposing (main)\n\nimport Helper as Util exposing (three)\n\nmain = Bogus.\n";
        let db = IpeDatabase::new();
        let helper = file(&db, &["Helper"], HELPER);
        let entry = file(&db, &["Main"], SRC);
        let root = root_of(&db, &[(&["Helper"], helper), (&["Main"], entry)]);

        let byte = u32::try_from(SRC.find("Bogus.").expect("has qualifier") + "Bogus.".len())
            .expect("offset fits u32");
        let items = completions(&db, root, entry, &["Main".to_owned()], byte, None);
        let labels: Vec<&str> = items.iter().map(|i| i.label.as_str()).collect();
        assert!(
            labels.is_empty(),
            "unknown qualifier must offer nothing: {labels:?}"
        );
    }
}
