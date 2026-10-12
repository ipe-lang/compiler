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
use ipe_diagnostics::Span;
use ipe_intern::Symbol;
use ipe_types::Ty;
use lsp_types::{
    CompletionItem, CompletionItemKind, CompletionTextEdit, InsertTextFormat, TextEdit,
};

use crate::expected_type::expected_type_at;
use crate::offset::{PositionEncoding, span_to_range};

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
    encoding: PositionEncoding,
    docs: Option<&ipe_docs::Index>,
) -> Vec<CompletionItem> {
    let files = root.files(db);
    let Some(&file) = files.get(module) else {
        return Vec::new();
    };
    let source = file.text(db);

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

    for kw in ipe_parse::KEYWORDS {
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

    // Scope every item (identifiers AND keywords alike) to the identifier run
    // touching the cursor, so accepting one REPLACES whatever is already
    // typed there instead of merely inserting at the cursor position — the
    // one edit-construction choke point both this path and
    // [`qualified_completions`] route through.
    let word = ipe_parse::scan_word_span(source, byte);
    scope_items_to_word(&mut items, source, word.start, word.end, encoding);

    items
}

/// `Qualifier.member` completion candidates for a trigger touching `byte` in
/// `module`'s source, scoped to exactly that qualifier's exposed members.
///
/// A bare `Q.`, a partial `Q.mem`, or a full dotted
/// `A.B.Q.` must offer ONLY `Q`'s exports, never the module's whole
/// in-scope list, and must keep working when the surrounding buffer does
/// not lex at all — the trigger itself (a dangling `Font.`) is unlexable
/// (`StrayDot`), so every step here is pure text scanning, never the real
/// lexer/parser on this file's own text.
///
/// Returns `None` when `byte` is not on a `Qualifier.member` trigger at all;
/// the caller then falls back to [`completions`]. Returns `Some(vec![])` —
/// a closed, empty answer, never the global list — for a qualifier that
/// resolves to no known import.
///
/// Qualifier resolution reuses canon's OWN alias/full-path spelling rule
/// ([`ipe_canon::import_qualifiers`]) against every import header line
/// scanned from the source ([`ipe_db::scan_import_spellings`]), rather than
/// re-implementing import resolution: the same rule that accepts `F.` and
/// `Ipe.Ui.Font.` alike for `import Ipe.Ui.Font as F` governs which import a
/// typed qualifier names here. The dep file itself is looked up directly in
/// `root.files(db)` (the same map [`ipe_db::resolve_imports`] consults
/// internally) rather than via `resolve_imports`, which demands
/// `parse(db, file)` on the CURRENT file — a demand a buffer with an
/// unlexable trigger can never satisfy.
#[must_use]
pub fn qualified_completions(
    db: &IpeDatabase,
    root: SourceRoot,
    entry: ipe_db::SourceFile,
    module: &[String],
    byte: u32,
    encoding: PositionEncoding,
    docs: Option<&ipe_docs::Index>,
) -> Option<Vec<CompletionItem>> {
    let files = root.files(db);
    let &file = files.get(module)?;
    let source = file.text(db);
    let trigger = ipe_parse::scan_qualifier_prefix(source, byte)?;

    let spellings = ipe_db::scan_import_spellings(source);
    // Demanded before any interner lock below, like every other salsa query
    // in this module (see the module doc comment's lock-discipline note).
    // `None` away from an expecting context, or when the current buffer does
    // not type-check (e.g. the trigger's own dangling dot) — ranking then
    // degrades to name-only, same as the unqualified path.
    let expected = expected_type_at(db, root, entry, file, byte);

    // Resolve the typed qualifier spelling to one import's dep path, trying
    // each imported path's own valid spellings (alias, or last-segment +
    // full-dotted for a bare import) via canon's own rule.
    let dep_path = {
        let mut interner = db.interner().lock();
        spellings.into_iter().find_map(|spelling| {
            let alias_sym = spelling
                .alias
                .as_deref()
                .and_then(|a| interner.intern(a).ok());
            let dep_syms: Vec<Symbol> = spelling
                .path
                .iter()
                .filter_map(|s| interner.intern(s).ok())
                .collect();
            if dep_syms.len() != spelling.path.len() {
                return None;
            }
            let qualifiers =
                ipe_canon::import_qualifiers(alias_sym, &dep_syms, &mut interner).ok()?;
            let matches = qualifiers
                .iter()
                .any(|&q| interner.resolve(q) == Some(trigger.qualifier.as_str()));
            matches.then_some(spelling.path)
        })
    };
    let Some(dep_path) = dep_path else {
        return Some(Vec::new());
    };
    let Some(&dep_file) = files.get(&dep_path) else {
        return Some(Vec::new());
    };
    let Some(dep_canon) = crate::db_access::canonicalize_checked(db, root, entry, dep_file) else {
        return Some(Vec::new());
    };
    let dep_env: BTreeMap<Symbol, Ty> = ipe_db::typecheck_module(db, root, entry, dep_file)
        .as_ref()
        .ok()
        .map(|t| t.env.clone())
        .unwrap_or_default();

    let mut interner = db.interner().lock();
    let dep_home: Vec<Symbol> = dep_path
        .iter()
        .map(|s| interner.intern(s).ok())
        .collect::<Option<Vec<_>>>()
        .unwrap_or_default();

    let candidates = dep_candidates(&dep_home, &dep_canon);
    let mut solved_env: BTreeMap<Vec<Symbol>, BTreeMap<Symbol, Ty>> = BTreeMap::new();
    solved_env.insert(dep_home, dep_env);

    let mut items = render_candidates(
        &candidates,
        Some(&solved_env),
        expected.as_ref(),
        &interner,
        docs,
    );
    drop(interner);

    // Scope to the typed member prefix — never the whole dep export list.
    items.retain(|item| item.label.starts_with(&trigger.member_prefix));

    items.sort_by(|a, b| {
        let ka = (a.sort_text.as_deref().unwrap_or(""), a.label.as_str());
        let kb = (b.sort_text.as_deref().unwrap_or(""), b.label.as_str());
        ka.cmp(&kb)
    });

    scope_items_to_word(
        &mut items,
        source,
        trigger.member_start,
        trigger.member_end,
        encoding,
    );

    Some(items)
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
        out.extend(dep_candidates(&dep_home, dep_canon));
    }
    out
}

/// One dep's own export surface as candidates, filed under `dep_home` — the
/// SAME candidate shape [`build_candidates`] uses for a normal (unqualified)
/// dep, reused as-is by [`qualified_completions`] so a qualified trigger
/// (`Font.`) and the module's own scope both answer from one export-walking
/// implementation.
fn dep_candidates(dep_home: &[Symbol], dep_canon: &ipe_db::CanonicalModule) -> Vec<Candidate> {
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
        // A dep constructor's owning-union head is recoverable from the dep's
        // own unions (the export map records the ctor→type link).
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
    // An expected type variable or wildcard is satisfied by any candidate — it
    // constrains nothing, so keep the candidate but do not privilege it.
    if matches!(expected, Ty::Var(_) | Ty::Wildcard) {
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
        Ty::Var(_) | Ty::Wildcard | Ty::Unit | Ty::Fun(..) | Ty::Tuple(_) | Ty::Record(..) => None,
    }
}

/// Scope every item's edit to `[word_start, word_end)` in `source` so
/// accepting it REPLACES that whole identifier run — both what is already
/// typed before the cursor AND, for a mid-word cursor, whatever untyped
/// remainder follows — rather than merely inserting at the cursor: at
/// `Font.bol`, picking `bold` must give `Font.bold`, never `Font.bolbold`.
///
/// The one edit-construction step both [`completions`] and
/// [`qualified_completions`] route every item through, so no completion
/// item — identifier, constructor, type, or keyword, qualified or not —
/// ever depends on the client's own word-boundary guess or on
/// `insert_text` alone. `word_start == word_end` (nothing typed yet) still
/// produces a well-formed empty-range edit at the cursor.
fn scope_items_to_word(
    items: &mut [CompletionItem],
    source: &str,
    word_start: u32,
    word_end: u32,
    encoding: PositionEncoding,
) {
    let range = span_to_range(source, Span::new(word_start, word_end), encoding);
    for item in items {
        item.filter_text = Some(item.label.clone());
        item.text_edit = Some(CompletionTextEdit::Edit(TextEdit {
            range,
            new_text: item.label.clone(),
        }));
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

#[cfg(test)]
mod tests {
    use ipe_db::{IpeDatabase, ModuleOrigin, SourceFile, SourceRoot};

    use super::{Candidate, CandidateKind, completions, qualified_completions, render_candidates};
    use crate::offset::PositionEncoding;

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

    const FONT_MODULE: &str = "module Font exposing (bold, italic, size)\n\nbold : Int\nbold = 1\n\nitalic : Int\nitalic = 2\n\nsize : Int\nsize = 3\n";
    const SHAPE_MODULE: &str =
        "module Shape exposing (Shape(..))\n\ntype Shape = Circle | Rect Int\n";
    /// `FONT_MODULE` declared at the multi-segment path `Acme.Ui.Font` — a file
    /// must declare the module name its path implies.
    const DOTTED_FONT_MODULE: &str = "module Acme.Ui.Font exposing (bold, italic, size)\n\nbold : Int\nbold = 1\n\nitalic : Int\nitalic = 2\n\nsize : Int\nsize = 3\n";

    /// Extract the `Edit` variant of a completion item's `text_edit`, panicking
    /// (test-only) with the item's label if it carries no edit at all — every
    /// item [`scope_items_to_word`] touches must carry one.
    fn edit_of(item: &lsp_types::CompletionItem) -> &lsp_types::TextEdit {
        match &item.text_edit {
            Some(lsp_types::CompletionTextEdit::Edit(edit)) => Some(edit),
            _ => None,
        }
        .expect("every scoped item carries a plain Edit text_edit")
    }

    /// A cursor at byte 0 is in no expecting context → scope-only behavior
    /// (every name kept), preserving the pre-sidecar contract.
    #[test]
    fn own_module_names_and_imported_names_appear() {
        let db = IpeDatabase::new();
        let helper = file(&db, &["Helper"], HELPER);
        let entry = file(&db, &["Main"], MAIN);
        let root = root_of(&db, &[(&["Helper"], helper), (&["Main"], entry)]);

        let items = completions(
            &db,
            root,
            entry,
            &["Main".to_owned()],
            0,
            PositionEncoding::Utf16,
            None,
        );
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

        let items = completions(
            &db,
            root,
            entry,
            &["Main".to_owned()],
            0,
            PositionEncoding::Utf16,
            None,
        );
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

        let items = completions(
            &db,
            root,
            entry,
            &["Main".to_owned()],
            0,
            PositionEncoding::Utf16,
            None,
        );
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
        let items = completions(
            &db,
            root,
            entry,
            &["Main".to_owned()],
            byte,
            PositionEncoding::Utf16,
            None,
        );
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
        let items = completions(
            &db,
            root,
            entry,
            &["Main".to_owned()],
            byte,
            PositionEncoding::Utf16,
            None,
        );

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
        let items = completions(
            &db,
            root,
            entry,
            &["Main".to_owned()],
            byte,
            PositionEncoding::Utf16,
            None,
        );
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

    // -----------------------------------------------------------------------
    // Qualified completion: `Q.`, `Q.partial`, aliases, full
    // dotted paths, unknown qualifiers, ctors/types, and unparseable buffers.
    // -----------------------------------------------------------------------

    /// Shape 1: a bare `Font.` offers ONLY `Font`'s exposed members —
    /// never the bare-keywords-only regression, never the whole scope.
    #[test]
    fn bare_qualifier_dot_offers_only_that_modules_members() {
        const SRC: &str = "module Main exposing (main)\n\nimport Font\n\nmain = Font.\n";
        let db = IpeDatabase::new();
        let font = file(&db, &["Font"], FONT_MODULE);
        let entry = file(&db, &["Main"], SRC);
        let root = root_of(&db, &[(&["Font"], font), (&["Main"], entry)]);

        let byte = u32::try_from(SRC.find("Font.").expect("has trigger") + "Font.".len())
            .expect("offset fits u32");
        let items = qualified_completions(
            &db,
            root,
            entry,
            &["Main".to_owned()],
            byte,
            PositionEncoding::Utf16,
            None,
        )
        .expect("bare qualifier dot recognized as a trigger");
        let labels: Vec<&str> = items.iter().map(|i| i.label.as_str()).collect();
        assert!(labels.contains(&"bold"), "bold missing: {labels:?}");
        assert!(labels.contains(&"italic"), "italic missing: {labels:?}");
        assert!(labels.contains(&"size"), "size missing: {labels:?}");
        assert!(
            !labels.contains(&"main"),
            "qualified completion must never leak the global scope: {labels:?}"
        );
        assert!(
            !labels.iter().any(|l| ipe_parse::KEYWORDS.contains(l)),
            "qualified completion must never fall back to keywords-only: {labels:?}"
        );
    }

    /// Shape 2: a partial `Font.b` scopes to members whose name starts
    /// with `b` — not "every in-scope name" (the pre-fix regression).
    #[test]
    fn partial_qualifier_member_filters_to_matching_prefix() {
        const SRC: &str = "module Main exposing (main)\n\nimport Font\n\nmain = Font.b\n";
        let db = IpeDatabase::new();
        let font = file(&db, &["Font"], FONT_MODULE);
        let entry = file(&db, &["Main"], SRC);
        let root = root_of(&db, &[(&["Font"], font), (&["Main"], entry)]);

        let byte = u32::try_from(SRC.find("Font.b").expect("has trigger") + "Font.b".len())
            .expect("offset fits u32");
        let items = qualified_completions(
            &db,
            root,
            entry,
            &["Main".to_owned()],
            byte,
            PositionEncoding::Utf16,
            None,
        )
        .expect("partial qualifier member recognized as a trigger");
        let labels: Vec<&str> = items.iter().map(|i| i.label.as_str()).collect();
        assert!(labels.contains(&"bold"), "bold missing: {labels:?}");
        assert!(
            !labels.contains(&"italic"),
            "italic must not match prefix 'b': {labels:?}"
        );
        assert!(
            !labels.contains(&"size"),
            "size must not match prefix 'b': {labels:?}"
        );
    }

    /// Shape 3: qualifier resolution reads the source text directly, so
    /// it still works on a buffer whose trailing `Font.` makes the WHOLE file
    /// unlexable (and a further-broken tail makes it doubly so) — the "last
    /// good parse" robustness requirement.
    #[test]
    fn unparseable_buffer_still_yields_correctly_scoped_completions() {
        const SRC: &str = "module Main exposing (main)\n\nimport Font\n\nmain = Font. +++ ((\n";
        let db = IpeDatabase::new();
        let font = file(&db, &["Font"], FONT_MODULE);
        let entry = file(&db, &["Main"], SRC);
        let root = root_of(&db, &[(&["Font"], font), (&["Main"], entry)]);

        // Confirm this buffer really does not parse (the dangling `Font.` is
        // a `StrayDot`, and the lexer's total-failure propagation aborts the
        // WHOLE buffer's tokenization on it, which `parse_module` calls
        // first) — otherwise this test would not be exercising the claimed
        // robustness at all.
        let mut probe_interner = ipe_intern::Interner::new();
        assert!(
            ipe_parse::parse_module(SRC, &mut probe_interner).is_err(),
            "fixture must be unparseable to exercise the class property"
        );

        let byte = u32::try_from(SRC.find("Font.").expect("has trigger") + "Font.".len())
            .expect("offset fits u32");
        let items = qualified_completions(
            &db,
            root,
            entry,
            &["Main".to_owned()],
            byte,
            PositionEncoding::Utf16,
            None,
        )
        .expect("qualifier trigger recognized on an unparseable buffer");
        let labels: Vec<&str> = items.iter().map(|i| i.label.as_str()).collect();
        assert!(
            labels.contains(&"bold"),
            "bold missing on unparseable buffer: {labels:?}"
        );
    }

    /// An aliased import (`import Font as F`) is completed the same way under
    /// its alias spelling — reusing canon's own alias rule, not a
    /// reimplementation.
    #[test]
    fn aliased_qualifier_offers_the_same_members() {
        const SRC: &str = "module Main exposing (main)\n\nimport Font as F\n\nmain = F.b\n";
        let db = IpeDatabase::new();
        let font = file(&db, &["Font"], FONT_MODULE);
        let entry = file(&db, &["Main"], SRC);
        let root = root_of(&db, &[(&["Font"], font), (&["Main"], entry)]);

        let byte = u32::try_from(SRC.find("F.b").expect("has trigger") + "F.b".len())
            .expect("offset fits u32");
        let items = qualified_completions(
            &db,
            root,
            entry,
            &["Main".to_owned()],
            byte,
            PositionEncoding::Utf16,
            None,
        )
        .expect("aliased qualifier recognized as a trigger");
        let labels: Vec<&str> = items.iter().map(|i| i.label.as_str()).collect();
        assert!(labels.contains(&"bold"), "bold missing: {labels:?}");
        assert!(
            !labels.contains(&"italic"),
            "italic must not match prefix 'b': {labels:?}"
        );
    }

    /// A full dotted path (`Acme.Ui.Font.`-shaped) resolves the same import as
    /// its bare last-segment spelling (`Font.`) — canon's own bare-import
    /// qualifier rule yields both spellings for a multi-segment path.
    #[test]
    fn full_dotted_path_and_last_segment_both_resolve_the_same_import() {
        const SRC: &str =
            "module Main exposing (main)\n\nimport Acme.Ui.Font\n\nmain = Acme.Ui.Font.b\n";
        const SRC_SHORT: &str =
            "module Main exposing (main)\n\nimport Acme.Ui.Font\n\nmain = Font.b\n";
        let db = IpeDatabase::new();
        let font = file(&db, &["Acme", "Ui", "Font"], DOTTED_FONT_MODULE);
        let entry = file(&db, &["Main"], SRC);
        let root = root_of(&db, &[(&["Acme", "Ui", "Font"], font), (&["Main"], entry)]);

        let byte = u32::try_from(
            SRC.find("Acme.Ui.Font.b").expect("has trigger") + "Acme.Ui.Font.b".len(),
        )
        .expect("offset fits u32");
        let items = qualified_completions(
            &db,
            root,
            entry,
            &["Main".to_owned()],
            byte,
            PositionEncoding::Utf16,
            None,
        )
        .expect("full dotted path recognized as a trigger");
        let labels: Vec<&str> = items.iter().map(|i| i.label.as_str()).collect();
        assert!(labels.contains(&"bold"), "bold missing: {labels:?}");

        let db2 = IpeDatabase::new();
        let font2 = file(&db2, &["Acme", "Ui", "Font"], DOTTED_FONT_MODULE);
        let entry2 = file(&db2, &["Main"], SRC_SHORT);
        let root2 = root_of(
            &db2,
            &[(&["Acme", "Ui", "Font"], font2), (&["Main"], entry2)],
        );
        let byte2 = u32::try_from(SRC_SHORT.find("Font.b").expect("has trigger") + "Font.b".len())
            .expect("offset fits u32");
        let items2 = qualified_completions(
            &db2,
            root2,
            entry2,
            &["Main".to_owned()],
            byte2,
            PositionEncoding::Utf16,
            None,
        )
        .expect("last-segment spelling recognized as a trigger");
        let labels2: Vec<&str> = items2.iter().map(|i| i.label.as_str()).collect();
        assert!(labels2.contains(&"bold"), "bold missing: {labels2:?}");
    }

    /// An unknown qualifier (no import spells it) yields a closed, EMPTY list
    /// — `Some(vec![])`, never `None` (which would fall back to the global
    /// scope list) and never the module's own scope.
    #[test]
    fn unknown_qualifier_yields_empty_not_global_list() {
        const SRC: &str = "module Main exposing (main)\n\nimport Font\n\nmain = Nope.\n";
        let db = IpeDatabase::new();
        let font = file(&db, &["Font"], FONT_MODULE);
        let entry = file(&db, &["Main"], SRC);
        let root = root_of(&db, &[(&["Font"], font), (&["Main"], entry)]);

        let byte = u32::try_from(SRC.find("Nope.").expect("has trigger") + "Nope.".len())
            .expect("offset fits u32");
        let items = qualified_completions(
            &db,
            root,
            entry,
            &["Main".to_owned()],
            byte,
            PositionEncoding::Utf16,
            None,
        );
        let items = items.expect("an unknown-but-dotted qualifier is still a recognized trigger");
        assert!(
            items.is_empty(),
            "an unknown qualifier must yield a closed EMPTY list, never the global scope: {:?}",
            items.iter().map(|i| i.label.as_str()).collect::<Vec<_>>()
        );
    }

    /// Qualified constructors and types are offered too, not just values.
    #[test]
    fn qualified_completions_offers_ctors_and_types() {
        const SRC: &str = "module Main exposing (main)\n\nimport Shape\n\nmain = Shape.\n";
        let db = IpeDatabase::new();
        let shape = file(&db, &["Shape"], SHAPE_MODULE);
        let entry = file(&db, &["Main"], SRC);
        let root = root_of(&db, &[(&["Shape"], shape), (&["Main"], entry)]);

        let byte = u32::try_from(SRC.find("Shape.").expect("has trigger") + "Shape.".len())
            .expect("offset fits u32");
        let items = qualified_completions(
            &db,
            root,
            entry,
            &["Main".to_owned()],
            byte,
            PositionEncoding::Utf16,
            None,
        )
        .expect("qualifier trigger recognized");
        let labels: Vec<&str> = items.iter().map(|i| i.label.as_str()).collect();
        assert!(labels.contains(&"Circle"), "Circle missing: {labels:?}");
        assert!(labels.contains(&"Rect"), "Rect missing: {labels:?}");
        assert!(labels.contains(&"Shape"), "Shape type missing: {labels:?}");
    }

    // -----------------------------------------------------------------------
    // Replace-not-append: every item's `text_edit` spans the WHOLE identifier
    // already typed, so accepting it replaces rather than appends.
    // -----------------------------------------------------------------------

    /// `Font.bol|` (cursor at the end of a fully-typed prefix): the edit range
    /// covers exactly `bol`, and applying it (replacing that range with the
    /// item's `new_text`) yields `Font.bold`, never `Font.bolbold`.
    #[test]
    fn qualified_edit_range_covers_typed_prefix_and_replaces_not_appends() {
        const SRC: &str = "module Main exposing (main)\n\nimport Font\n\nmain = Font.bol\n";
        let db = IpeDatabase::new();
        let font = file(&db, &["Font"], FONT_MODULE);
        let entry = file(&db, &["Main"], SRC);
        let root = root_of(&db, &[(&["Font"], font), (&["Main"], entry)]);

        let member_start =
            u32::try_from(SRC.find("Font.bol").expect("has trigger") + "Font.".len())
                .expect("offset fits u32");
        let byte = member_start + 3; // cursor right after "bol"
        let items = qualified_completions(
            &db,
            root,
            entry,
            &["Main".to_owned()],
            byte,
            PositionEncoding::Utf16,
            None,
        )
        .expect("qualifier trigger recognized");
        let bold = items
            .iter()
            .find(|i| i.label == "bold")
            .expect("bold offered");
        let edit = edit_of(bold);
        assert_eq!(edit.new_text, "bold");

        // Apply the edit against the source text and confirm the result.
        let line = "main = Font.bol";
        let member_col_start =
            u32::try_from(line.find("bol").expect("bol in line")).expect("offset fits u32");
        assert_eq!(edit.range.start.character, member_col_start);
        assert_eq!(edit.range.end.character, member_col_start + 3);

        let mut applied = line.to_owned();
        let start = usize::try_from(edit.range.start.character).unwrap();
        let end = usize::try_from(edit.range.end.character).unwrap();
        applied.replace_range(start..end, &edit.new_text);
        assert_eq!(applied, "main = Font.bold");
    }

    /// `Font.|` (nothing typed after the dot yet): the edit range is EMPTY at
    /// the cursor — no characters are ever deleted for a fresh trigger.
    #[test]
    fn qualified_edit_range_is_empty_at_cursor_for_bare_dot() {
        const SRC: &str = "module Main exposing (main)\n\nimport Font\n\nmain = Font.\n";
        let db = IpeDatabase::new();
        let font = file(&db, &["Font"], FONT_MODULE);
        let entry = file(&db, &["Main"], SRC);
        let root = root_of(&db, &[(&["Font"], font), (&["Main"], entry)]);

        let byte = u32::try_from(SRC.find("Font.").expect("has trigger") + "Font.".len())
            .expect("offset fits u32");
        let items = qualified_completions(
            &db,
            root,
            entry,
            &["Main".to_owned()],
            byte,
            PositionEncoding::Utf16,
            None,
        )
        .expect("bare qualifier dot recognized as a trigger");
        let bold = items
            .iter()
            .find(|i| i.label == "bold")
            .expect("bold offered");
        let edit = edit_of(bold);
        assert_eq!(
            edit.range.start, edit.range.end,
            "a fresh `Font.` trigger must carry an EMPTY edit range: {edit:?}"
        );
    }

    /// Mid-word `Font.bo|l` (cursor between `bo` and `l`): the edit range
    /// covers the WHOLE identifier `bol` — both the typed prefix before the
    /// cursor AND the untyped remainder after it — not just the prefix.
    #[test]
    fn qualified_edit_range_extends_past_a_mid_word_cursor() {
        const SRC: &str = "module Main exposing (main)\n\nimport Font\n\nmain = Font.bol\n";
        let db = IpeDatabase::new();
        let font = file(&db, &["Font"], FONT_MODULE);
        let entry = file(&db, &["Main"], SRC);
        let root = root_of(&db, &[(&["Font"], font), (&["Main"], entry)]);

        let member_start =
            u32::try_from(SRC.find("Font.bol").expect("has trigger") + "Font.".len())
                .expect("offset fits u32");
        let byte = member_start + 2; // cursor between "bo" and "l"
        let items = qualified_completions(
            &db,
            root,
            entry,
            &["Main".to_owned()],
            byte,
            PositionEncoding::Utf16,
            None,
        )
        .expect("qualifier trigger recognized");
        let bold = items
            .iter()
            .find(|i| i.label == "bold")
            .expect("bold offered");
        let edit = edit_of(bold);
        let line = "main = Font.bol";
        let member_col_start =
            u32::try_from(line.find("bol").expect("bol in line")).expect("offset fits u32");
        assert_eq!(
            edit.range.start.character, member_col_start,
            "range must start at the beginning of the identifier, not the cursor"
        );
        assert_eq!(
            edit.range.end.character,
            member_col_start + 3,
            "range must extend past the cursor to the identifier's end (covers 'l' too)"
        );
    }

    /// A multi-byte character earlier on the SAME line as the trigger makes
    /// the UTF-8 byte offset and the UTF-16 code-unit offset of the edit
    /// range diverge; the range must be reported in UTF-16 units (the
    /// negotiated encoding), proving the conversion goes through the shared
    /// `offset` module rather than reusing raw byte offsets.
    #[test]
    fn qualified_edit_range_converts_utf16_past_a_multibyte_identifier() {
        const SRC: &str = "module Main exposing (main)\n\nimport Font\n\nmain = café Font.bol\n";
        let db = IpeDatabase::new();
        let font = file(&db, &["Font"], FONT_MODULE);
        let entry = file(&db, &["Main"], SRC);
        let root = root_of(&db, &[(&["Font"], font), (&["Main"], entry)]);

        let byte = u32::try_from(SRC.find("Font.bol").expect("has trigger") + "Font.bol".len())
            .expect("offset fits u32");
        let items = qualified_completions(
            &db,
            root,
            entry,
            &["Main".to_owned()],
            byte,
            PositionEncoding::Utf16,
            None,
        )
        .expect("qualifier trigger recognized");
        let bold = items
            .iter()
            .find(|i| i.label == "bold")
            .expect("bold offered");
        let edit = edit_of(bold);

        // `café ` is 6 UTF-8 bytes but only 5 UTF-16 code units (é is one BMP
        // unit) — the byte-offset and UTF-16-unit counts of the prefix before
        // the member diverge, so a bug reusing byte offsets as UTF-16 units
        // would land the range one unit too far right.
        let prefix_to_dot = "main = café Font.";
        let expected_start =
            u32::try_from(prefix_to_dot.encode_utf16().count()).expect("count fits u32");
        let expected_end = u32::try_from(format!("{prefix_to_dot}bol").encode_utf16().count())
            .expect("count fits u32");
        assert_ne!(
            usize::try_from(expected_start).unwrap(),
            prefix_to_dot.len(),
            "fixture must actually diverge in byte vs UTF-16 count to be a real test"
        );
        assert_eq!(edit.range.start.line, 4);
        assert_eq!(edit.range.start.character, expected_start);
        assert_eq!(edit.range.end.character, expected_end);
    }

    /// The unqualified path routes through the SAME `scope_items_to_word`
    /// choke point — proving the replace-not-append guarantee is not a
    /// qualified-only special case.
    #[test]
    fn unqualified_completion_text_edit_replaces_whole_word() {
        const SRC: &str =
            "module Main exposing (main)\n\nimport Helper exposing (three)\n\nmain = thr\n";
        let db = IpeDatabase::new();
        let helper = file(&db, &["Helper"], HELPER);
        let entry = file(&db, &["Main"], SRC);
        let root = root_of(&db, &[(&["Helper"], helper), (&["Main"], entry)]);

        let byte = u32::try_from(SRC.find("= thr").expect("has trigger") + "= thr".len())
            .expect("offset fits u32");
        let items = completions(
            &db,
            root,
            entry,
            &["Main".to_owned()],
            byte,
            PositionEncoding::Utf16,
            None,
        );
        let three = items
            .iter()
            .find(|i| i.label == "three")
            .expect("three offered");
        let edit = edit_of(three);
        assert_eq!(edit.new_text, "three");
        let line = "main = thr";
        let word_col_start =
            u32::try_from(line.find("thr").expect("thr in line")).expect("offset fits u32");
        assert_eq!(edit.range.start.character, word_col_start);
        assert_eq!(edit.range.end.character, word_col_start + 3);
    }
}
