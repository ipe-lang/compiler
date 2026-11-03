//! Go-to-definition and find-references over the resolver's name index.
//!
//! Every query here reads one recorded fact: the [`NameIndex`] the resolver
//! fills while it canonicalises a module, mapping each name occurrence's own
//! source span to what it resolved to. No query walks the canonical tree to
//! find a name, so a desugar (a `do` block's chain of binds) cannot hide one.
//!
//! **Targets** — an occurrence resolves to a declaration (a top-level value, a
//! data constructor, or a kernel reached through its Ipê declaration) or to a
//! local binder (a parameter, a `let`, `case` or `do` binder). A local's
//! identity is its binder's span, so two same-named locals never merge and a
//! local never stands in for a same-named top-level value.
//!
//! **Definition** — a declaration's name token in its declaring module's parse
//! tree, or a local's binder token.
//!
//! **References** — every recorded occurrence of the target, narrowed to its
//! name token: across every project module for a declaration, inside the
//! binder's own module for a local. The definition site is not included.
//!
//! An occurrence the resolver does not record (an operator, a type reference,
//! an interpolated name, a kernel-only function) resolves to nothing, never
//! to a guess.
//!
//! [`NameIndex`]: ipe_canon::name_index::NameIndex

use ipe_canon::name_index::Target;
use ipe_db::{Db as _, IpeDatabase, SourceRoot};
use ipe_diagnostics::{Span, TokenKind};
use ipe_intern::Symbol;
use ipe_parse::TokenClass;

// ---------------------------------------------------------------------------
// Public API types
// ---------------------------------------------------------------------------

/// A located reference to a name: the module that contains it and the byte
/// span of the name token.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NameRef {
    /// The module the reference appears in (its source file's module path).
    pub module: Vec<String>,
    /// The byte span of the name token in that module's source text.
    pub span: Span,
}

/// The definition site of a name.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Definition {
    /// The module that declares the name.
    pub module: Vec<String>,
    /// The byte span of the name token at the declaration site.
    pub span: Span,
    /// What the name resolved to.
    pub target: NameTarget,
}

/// What a name occurrence resolved to, in source-string form.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum NameTarget {
    /// A module-level declaration: a top-level value, a data constructor, or
    /// the Ipê declaration a kernel reference reached.
    Declared {
        /// The declaring module's path.
        module: Vec<String>,
        /// The declared name.
        name: String,
    },
    /// A lexical binder, identified by its binder token's span.
    Local {
        /// The module the binder (and every one of its uses) lives in.
        module: Vec<String>,
        /// The binder's spelling.
        name: String,
        /// The binder token's span, the local's identity.
        binder: Span,
    },
}

impl NameTarget {
    /// The module that declares the name or holds the binder.
    #[must_use]
    pub fn module(&self) -> &[String] {
        match self {
            Self::Declared { module, .. } | Self::Local { module, .. } => module,
        }
    }

    /// The name's spelling.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Declared { name, .. } | Self::Local { name, .. } => name,
        }
    }
}

/// The name the cursor sits on and the span of its token.
///
/// Two positions resolve: a recorded occurrence (a use, or a binder) read from
/// the module's name index, and a declaration's own name token (a top-level
/// value binding or a `type` union constructor), which the resolver does not
/// record as an occurrence.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ResolvedName {
    /// What the name resolved to.
    pub target: NameTarget,
    /// The byte span of the name token under the cursor, in the requesting
    /// module's source.
    pub span: Span,
}

// ---------------------------------------------------------------------------
// Name-token narrowing
// ---------------------------------------------------------------------------

/// The source text a span covers, or `None` when it is out of range.
#[must_use]
pub fn span_text(text: &str, span: Span) -> Option<&str> {
    let lo = usize::try_from(span.lo).ok()?;
    let hi = usize::try_from(span.hi).ok()?;
    text.get(lo..hi)
}

/// The span of the name token `spelling` inside a recorded occurrence `span`.
///
/// The occurrence's text is split by the language lexer. A recorded span is
/// the name's own identifier token, a qualified value (`Lib.total`, one
/// dotted identifier token whose name is the member suffix), or a constructor
/// pattern with arguments (`Circle r`, `(Circle r)`, whose name token is the
/// first token after the opening parentheses). Any other shape — text that
/// does not lex, a head that is not an identifier, an identifier that is not
/// `spelling` behind module qualifiers — yields `None`: the caller must
/// refuse rather than edit or report text that is not the name.
#[must_use]
pub fn name_token(text: &str, span: Span, spelling: &str) -> Option<Span> {
    let slice = span_text(text, span)?;
    let tokens = ipe_parse::try_source_tokens(slice)?;
    let mut code = tokens
        .iter()
        .filter(|token| token.class != TokenClass::Code(TokenKind::Eof));
    let head = if spelling.starts_with(|c: char| c.is_ascii_uppercase()) {
        // Only a constructor occurrence is recorded at a whole pattern.
        code.find(|token| token.class != TokenClass::Code(TokenKind::LParen))?
    } else {
        let only = code.next()?;
        if code.next().is_some() {
            return None;
        }
        only
    };
    if head.class != TokenClass::Code(TokenKind::Ident) {
        return None;
    }
    let offset = member_offset(span_text(slice, head.span)?, spelling)?;
    let head_lo = usize::try_from(head.span.lo).ok()?;
    offset_span(span, head_lo.checked_add(offset)?, spelling)
}

/// The byte offset of `spelling` in `token` when `token` is `spelling` itself
/// or `spelling` behind module qualifiers (`Q.R.spelling`).
fn member_offset(token: &str, spelling: &str) -> Option<usize> {
    if token == spelling {
        return Some(0);
    }
    let qualifier = token.strip_suffix(spelling)?.strip_suffix('.')?;
    qualifier
        .split('.')
        .all(|segment| {
            segment.starts_with(|c: char| c.is_ascii_uppercase())
                && ipe_parse::is_identifier(segment)
        })
        .then_some(token.len().saturating_sub(spelling.len()))
}

/// The span of `spelling` starting `offset` bytes into `span`.
fn offset_span(span: Span, offset: usize, spelling: &str) -> Option<Span> {
    let lo = span.lo.checked_add(u32::try_from(offset).ok()?)?;
    let hi = lo.checked_add(u32::try_from(spelling.len()).ok()?)?;
    (hi <= span.hi).then_some(Span::new(lo, hi))
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

/// The declaration `(home, name)` as source strings.
fn declared(db: &IpeDatabase, home: &[Symbol], name: Symbol) -> Option<NameTarget> {
    let interner = db.interner().lock();
    let module = home
        .iter()
        .map(|&sym| interner.resolve(sym).map(str::to_owned))
        .collect::<Option<Vec<_>>>()?;
    let name = interner.resolve(name)?.to_owned();
    drop(interner);
    Some(NameTarget::Declared { module, name })
}

/// The source-string target of one recorded occurrence in `module`.
///
/// A kernel-only function (no Ipê declaration) and a synthesised binder (no
/// source location) have no target.
fn name_target(
    db: &IpeDatabase,
    module: &[String],
    text: &str,
    target: &Target,
) -> Option<NameTarget> {
    match target {
        Target::TopLevel { home, name } | Target::Ctor { home, name, .. } => {
            declared(db, home, *name)
        }
        Target::Kernel {
            declared: Some(decl),
            ..
        } => declared(db, &decl.module, decl.name),
        Target::Kernel { declared: None, .. } | Target::Poisoned => None,
        Target::Local(site) => {
            let binder = site.location()?;
            let name = span_text(text, binder)?;
            ipe_parse::is_identifier(name).then(|| NameTarget::Local {
                module: module.to_vec(),
                name: name.to_owned(),
                binder,
            })
        }
    }
}

/// Resolve the name the cursor sits on.
///
/// The single "what name is under this position" query shared by
/// [`goto_definition`], the references handler, hover's doc lookup, signature
/// help and `prepare_rename`, so they never disagree about a position. The
/// innermost recorded occurrence at `byte` answers first; only a position the
/// index holds nothing for falls back to a declaration's own name token.
///
/// Returns `None` when the position is on no name (whitespace, a comment, a
/// keyword, a type annotation), on an occurrence the resolver does not record,
/// or on one with no source-located target.
#[must_use]
pub fn resolve_name_at(
    db: &IpeDatabase,
    root: SourceRoot,
    entry: ipe_db::SourceFile,
    module: &[String],
    byte: u32,
) -> Option<ResolvedName> {
    let files = root.files(db);
    let &file = files.get(module)?;
    let canonical = crate::db_access::analysis(db, root, entry, file)?.canonical;
    if let Some((span, recorded)) = canonical.names.at(byte) {
        let text = file.text(db);
        let target = name_target(db, module, text, recorded)?;
        let span = name_token(text, span, target.name()).unwrap_or(span);
        return Some(ResolvedName { target, span });
    }
    let parsed = ipe_db::parse(db, file).as_ref().ok()?;
    def_name_at(parsed, byte, db).map(|(name, span)| ResolvedName {
        target: NameTarget::Declared {
            module: module.to_vec(),
            name,
        },
        span,
    })
}

/// The name and name-token span of a declaration whose own name token contains
/// `byte` — a top-level value binding or a `type` union constructor. Returns
/// `None` when the cursor is not on any declaration name token.
fn def_name_at(parsed: &ipe_syntax::Module, byte: u32, db: &IpeDatabase) -> Option<(String, Span)> {
    let interner = db.interner().lock();
    for value in &parsed.values {
        let name_span = value.value.name.span;
        if name_span.lo <= byte && byte < name_span.hi {
            let name = interner
                .resolve(value.value.name.value)
                .map(str::to_owned)?;
            return Some((name, name_span));
        }
    }
    for union in &parsed.unions {
        for ctor in &union.value.ctors {
            let Some(ctor_name) = interner.resolve(ctor.value.name) else {
                continue;
            };
            let len = u32::try_from(ctor_name.len()).unwrap_or(0);
            let name_span = Span::new(ctor.span.lo, ctor.span.lo.saturating_add(len));
            if name_span.lo <= byte && byte < name_span.hi {
                return Some((ctor_name.to_owned(), name_span));
            }
        }
    }
    drop(interner);
    None
}

// ---------------------------------------------------------------------------
// Go-to-definition
// ---------------------------------------------------------------------------

/// The definition site of the name under `byte` in `module`, if any.
///
/// A local answers its binder token; a declaration answers its name token in
/// the declaring module's parse tree. Returns `None` when the position
/// resolves to nothing, the module does not canonicalise, or the declaring
/// module is not part of the project (kernel / stdlib).
#[must_use]
pub fn goto_definition(
    db: &IpeDatabase,
    root: SourceRoot,
    entry: ipe_db::SourceFile,
    module: &[String],
    byte: u32,
) -> Option<Definition> {
    let target = resolve_name_at(db, root, entry, module, byte)?.target;
    let span = match &target {
        NameTarget::Local { binder, .. } => *binder,
        NameTarget::Declared { module, name } => {
            let files = root.files(db);
            let &def_file = files.get(module)?;
            let parsed = ipe_db::parse(db, def_file).as_ref().ok()?;
            definition_span_in_parse(parsed, name, db)?
        }
    };
    Some(Definition {
        module: target.module().to_vec(),
        span,
        target,
    })
}

/// The declaration site of the *type* of the expression under `byte`
/// (`textDocument/typeDefinition`).
///
/// Reads the solved type of the innermost region at the cursor from the
/// per-module region map — the same span-keyed types [`crate::hover`] shows —
/// takes its constructor head `(module, name)`, and locates that type's `type`
/// / `type alias` declaration name token in the declaring module's parse tree.
///
/// Returns `None` when the cursor is on no solved region, the type is not a
/// named constructor (a function, tuple, record, unit, or type variable has no
/// declaration to jump to), or the declaring module is not in the project
/// (a kernel / stdlib type). Never a guess.
#[must_use]
pub fn type_definition(
    db: &IpeDatabase,
    root: SourceRoot,
    entry: ipe_db::SourceFile,
    module: &[String],
    byte: u32,
) -> Option<Definition> {
    let files = root.files(db);
    let &file = files.get(module)?;
    let types = crate::db_access::module_types(db, root, entry, file)?;

    // Innermost solved region at the cursor — same resolution as hover.
    let mut best: Option<(u32, u32)> = None; // (width, lo)
    for span in types.regions.keys() {
        if span.lo <= byte && byte < span.hi {
            let width = span.hi.saturating_sub(span.lo);
            if best.is_none_or(|(bw, blo)| width < bw || (width == bw && span.lo > blo)) {
                best = Some((width, span.lo));
            }
        }
    }
    let (width, lo) = best?;
    let region_span = Span::new(lo, lo.saturating_add(width));
    let ty = types.regions.get(&region_span)?;

    // The type must be a named constructor to have a declaration to jump to.
    let ipe_types::Ty::Con {
        module: ty_module,
        name: ty_name,
        ..
    } = ty
    else {
        return None;
    };

    let (type_module, type_name): (Vec<String>, String) = {
        let interner = db.interner().lock();
        let m: Option<Vec<String>> = ty_module
            .iter()
            .map(|&s| interner.resolve(s).map(str::to_owned))
            .collect();
        let n = interner.resolve(*ty_name).map(str::to_owned);
        drop(interner);
        (m?, n?)
    };

    let &def_file = files.get(&type_module)?;
    let parsed = ipe_db::parse(db, def_file).as_ref().ok()?;
    let span = type_decl_span_in_parse(parsed, &type_name, db)?;
    Some(Definition {
        module: type_module.clone(),
        span,
        target: NameTarget::Declared {
            module: type_module,
            name: type_name,
        },
    })
}

/// The name-token span of a `type` union or `type alias` declaration named
/// `name` in one module's parse tree, or `None` when no such type is declared.
fn type_decl_span_in_parse(
    parsed: &ipe_syntax::Module,
    name: &str,
    db: &IpeDatabase,
) -> Option<Span> {
    let interner = db.interner().lock();
    for union in &parsed.unions {
        if interner.resolve(union.value.name.value) == Some(name) {
            return Some(union.value.name.span);
        }
    }
    for alias in &parsed.aliases {
        if interner.resolve(alias.value.name.value) == Some(name) {
            return Some(alias.value.name.span);
        }
    }
    drop(interner);
    None
}

/// Find the name-token span of a declaration named `name` in the parse tree of
/// one module — a top-level value binding, or a data constructor within a
/// `type` union. A constructor's `Located<Ctor>` span begins at its name token;
/// the name width is that identifier's byte length, mirroring the semantic-token
/// walker's convention.
fn definition_span_in_parse(
    parsed: &ipe_syntax::Module,
    name: &str,
    db: &IpeDatabase,
) -> Option<Span> {
    let interner = db.interner().lock();
    for value in &parsed.values {
        if interner.resolve(value.value.name.value) == Some(name) {
            return Some(value.value.name.span);
        }
    }
    for union in &parsed.unions {
        for ctor in &union.value.ctors {
            let Some(ctor_name) = interner.resolve(ctor.value.name) else {
                continue;
            };
            if ctor_name == name {
                let len = u32::try_from(ctor_name.len()).unwrap_or(0);
                return Some(Span::new(ctor.span.lo, ctor.span.lo.saturating_add(len)));
            }
        }
    }
    drop(interner);
    None
}

// ---------------------------------------------------------------------------
// Find-references
// ---------------------------------------------------------------------------

/// A [`NameTarget`] in the index's symbol form.
enum Wanted {
    /// A declaration's `(home, name)`.
    Declared {
        /// The declaring module's path.
        home: Vec<Symbol>,
        /// The declared name.
        name: Symbol,
    },
    /// A local, by its binder span.
    Local {
        /// The binder token's span.
        binder: Span,
    },
}

impl Wanted {
    /// The symbol form of `target`, or `None` when its strings were never
    /// interned (so nothing can have resolved to it).
    fn of(db: &IpeDatabase, target: &NameTarget) -> Option<Self> {
        match target {
            NameTarget::Declared { module, name } => {
                let interner = db.interner().lock();
                let home = module
                    .iter()
                    .map(|segment| interner.lookup(segment))
                    .collect::<Option<Vec<_>>>()?;
                let name = interner.lookup(name)?;
                drop(interner);
                Some(Self::Declared { home, name })
            }
            NameTarget::Local { binder, .. } => Some(Self::Local { binder: *binder }),
        }
    }

    /// Whether the occurrence at `span` resolved to this target. A local's own
    /// binder entry is its definition, not a reference.
    fn matches(&self, span: Span, recorded: &Target) -> bool {
        match (self, recorded) {
            (
                Self::Declared { home, name },
                Target::TopLevel {
                    home: at_home,
                    name: at_name,
                }
                | Target::Ctor {
                    home: at_home,
                    name: at_name,
                    ..
                },
            ) => at_home == home && at_name == name,
            (
                Self::Declared { home, name },
                Target::Kernel {
                    declared: Some(decl),
                    ..
                },
            ) => decl.module == *home && decl.name == *name,
            (Self::Local { binder }, Target::Local(site)) => {
                span != *binder && site.location() == Some(*binder)
            }
            (
                Self::Declared { .. },
                Target::Local(_) | Target::Kernel { declared: None, .. } | Target::Poisoned,
            )
            | (
                Self::Local { .. },
                Target::TopLevel { .. }
                | Target::Ctor { .. }
                | Target::Kernel { .. }
                | Target::Poisoned,
            ) => false,
        }
    }
}

/// Every recorded occurrence of `target`, as `(module, recorded span)`.
///
/// A declaration's occurrences come from every project module; a local's only
/// from its binder's module. The recorded span is the resolver's, not yet
/// narrowed to the name token.
#[must_use]
pub fn occurrences(
    db: &IpeDatabase,
    root: SourceRoot,
    entry: ipe_db::SourceFile,
    target: &NameTarget,
) -> Vec<NameRef> {
    // Dependency-first module order for consistent output. A cycle means no
    // safe canonicalize demand is possible — return empty rather than
    // iterating files and hitting salsa's dependency-cycle panic.
    let Ok(order) = ipe_db::topo_order(db, root, entry) else {
        return Vec::new();
    };
    let files = root.files(db);
    let canonical: Vec<_> = order
        .iter()
        .filter(|module_path| {
            !matches!(target, NameTarget::Local { module, .. } if module != *module_path)
        })
        .filter_map(|module_path| {
            let &file = files.get(module_path)?;
            let analysis = crate::db_access::analysis(db, root, entry, file)?;
            Some((module_path, analysis.canonical))
        })
        .collect();
    // Only after canonicalising: the target's strings are interned by the
    // queries that record its occurrences, so a lookup before them can miss.
    let Some(wanted) = Wanted::of(db, target) else {
        return Vec::new();
    };
    canonical
        .iter()
        .flat_map(|(module_path, canonical)| {
            canonical
                .names
                .entries()
                .filter(|&(span, recorded)| wanted.matches(span, recorded))
                .map(|(span, _)| NameRef {
                    module: (*module_path).clone(),
                    span,
                })
        })
        .collect()
}

/// Every use site of `target`, each narrowed to its name token.
///
/// Does not include the definition span — callers that want
/// "definition + all references" union the two themselves. An occurrence
/// whose token cannot be narrowed keeps its recorded span.
#[must_use]
pub fn find_references(
    db: &IpeDatabase,
    root: SourceRoot,
    entry: ipe_db::SourceFile,
    target: &NameTarget,
) -> Vec<NameRef> {
    let files = root.files(db);
    occurrences(db, root, entry, target)
        .into_iter()
        .map(|occurrence| {
            let span = files
                .get(&occurrence.module)
                .and_then(|file| name_token(file.text(db), occurrence.span, target.name()))
                .unwrap_or(occurrence.span);
            NameRef {
                module: occurrence.module,
                span,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use ipe_db::{IpeDatabase, ModuleOrigin, SourceFile, SourceRoot};

    use super::{NameTarget, find_references, goto_definition, resolve_name_at};

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

    fn declared(module: &[&str], name: &str) -> NameTarget {
        NameTarget::Declared {
            module: module.iter().map(|s| (*s).to_owned()).collect(),
            name: name.to_owned(),
        }
    }

    const HELPER: &str = "module Helper exposing (three)\n\nthree : Int\nthree = 3\n";
    const MAIN: &str = "module Main exposing (main)\n\nimport Helper exposing (three)\n\nmain : Int\nmain = three\n";

    fn ref_byte() -> u32 {
        u32::try_from(MAIN.rfind("three").expect("three in main")).expect("fits u32")
    }

    #[test]
    fn goto_definition_resolves_cross_module_reference() {
        let db = IpeDatabase::new();
        let helper = file(&db, &["Helper"], HELPER);
        let entry = file(&db, &["Main"], MAIN);
        let root = root_of(&db, &[(&["Helper"], helper), (&["Main"], entry)]);

        let def = goto_definition(&db, root, entry, &["Main".to_owned()], ref_byte())
            .expect("definition found");

        assert_eq!(def.module, vec!["Helper".to_owned()]);
        let lo = def.span.lo as usize;
        let hi = def.span.hi as usize;
        assert_eq!(
            HELPER.get(lo..hi),
            Some("three"),
            "definition span covers identifier"
        );
    }

    #[test]
    fn find_references_returns_all_use_sites() {
        let db = IpeDatabase::new();
        let helper = file(&db, &["Helper"], HELPER);
        let entry = file(&db, &["Main"], MAIN);
        let root = root_of(&db, &[(&["Helper"], helper), (&["Main"], entry)]);

        let refs = find_references(&db, root, entry, &declared(&["Helper"], "three"));

        assert_eq!(refs.len(), 1, "expected 1 reference, got: {refs:?}");
        let first = refs.first().expect("one reference");
        assert_eq!(first.module, vec!["Main".to_owned()]);
        let lo = first.span.lo as usize;
        let hi = first.span.hi as usize;
        assert_eq!(MAIN.get(lo..hi), Some("three"), "span covers identifier");
    }

    // ── Constructor coverage (issue #2653) ───────────────────────────────────
    //
    // `Red` is declared in a `type` union, used as a value in `pick`, and
    // matched as a `case` pattern in `describe`. Both use sites must be visible
    // to find-references, and go-to-definition from the value use must land on
    // the constructor's name token in the union declaration.

    const CTOR_MAIN: &str = "module Main exposing (main)\n\
                             \n\
                             type Color = Red | Green\n\
                             \n\
                             pick : Color\n\
                             pick = Red\n\
                             \n\
                             describe : Color -> Int\n\
                             describe c =\n\
                             \x20   case c of\n\
                             \x20       Red -> 1\n\
                             \x20       Green -> 2\n\
                             \n\
                             main : Int\n\
                             main = describe pick\n";

    fn ctor_value_use_byte() -> u32 {
        // The `Red` in `pick = Red` (the value use), not the declaration.
        let decl = CTOR_MAIN.find("Red | Green").expect("union decl has Red");
        let use_off = CTOR_MAIN[decl + 3..]
            .find("Red")
            .map(|o| decl + 3 + o)
            .expect("value use of Red follows the declaration");
        u32::try_from(use_off).expect("fits u32")
    }

    #[test]
    fn find_references_includes_constructor_value_and_pattern_uses() {
        let db = IpeDatabase::new();
        let entry = file(&db, &["Main"], CTOR_MAIN);
        let root = root_of(&db, &[(&["Main"], entry)]);

        let refs = find_references(&db, root, entry, &declared(&["Main"], "Red"));

        // Two use sites: the value use in `pick`, and the `case` pattern in
        // `describe`. The declaration site itself is not a reference.
        assert_eq!(
            refs.len(),
            2,
            "expected value use + pattern use, got: {refs:?}"
        );
        for r in &refs {
            assert_eq!(r.module, vec!["Main".to_owned()]);
            let lo = r.span.lo as usize;
            let hi = r.span.hi as usize;
            assert_eq!(
                CTOR_MAIN.get(lo..hi),
                Some("Red"),
                "each reference span covers exactly the constructor name"
            );
        }
        // The two spans are distinct positions (value use precedes the pattern).
        let mut los: Vec<u32> = refs.iter().map(|r| r.span.lo).collect();
        los.sort_unstable();
        los.dedup();
        assert_eq!(los.len(), 2, "the two references are at distinct offsets");
    }

    #[test]
    fn goto_definition_resolves_constructor_to_its_union_declaration() {
        let db = IpeDatabase::new();
        let entry = file(&db, &["Main"], CTOR_MAIN);
        let root = root_of(&db, &[(&["Main"], entry)]);

        let def = goto_definition(
            &db,
            root,
            entry,
            &["Main".to_owned()],
            ctor_value_use_byte(),
        )
        .expect("constructor definition found");

        assert_eq!(def.module, vec!["Main".to_owned()]);
        let lo = def.span.lo as usize;
        let hi = def.span.hi as usize;
        assert_eq!(
            CTOR_MAIN.get(lo..hi),
            Some("Red"),
            "definition span covers the constructor name token in the union"
        );
        // The definition is the declaration, not the value use.
        let decl_off = CTOR_MAIN.find("Red | Green").expect("union decl");
        assert_eq!(
            lo, decl_off,
            "definition points at the declaration site, not the use"
        );
    }

    // ── Definition-site resolution (issue #2655) ─────────────────────────────
    //
    // The most natural place a user invokes find-references and goto-definition
    // is the cursor on the definition's OWN name token. That token is not an
    // expression node, so the use-only walker never sees it; the shared
    // `resolve_name_at` def-site fallback makes the position resolvable, and the
    // references handler (goto_definition → def name → find_references) then
    // returns the definition plus every use.

    /// The `three` in `three : Int` / `three = 3` — the definition name token in
    /// `Helper`, not any use of it.
    fn helper_def_name_byte() -> u32 {
        // The declaration `three = 3` (skip the `three : Int` signature).
        let sig = HELPER.find("three : Int").expect("signature");
        let decl = HELPER[sig + 3..]
            .find("three")
            .map(|o| sig + 3 + o)
            .expect("declaration of three follows its signature");
        u32::try_from(decl).expect("fits u32")
    }

    /// Mirror the references handler in `main_loop.rs`: resolve the definition,
    /// check its span spells the target's name, then collect every use site. Returns
    /// `(def, references)` so a test can union them.
    fn references_via_handler(
        db: &IpeDatabase,
        root: SourceRoot,
        entry: SourceFile,
        module: &[&str],
        byte: u32,
        def_text: &str,
    ) -> Option<(super::Definition, Vec<super::NameRef>)> {
        let module: Vec<String> = module.iter().map(|s| (*s).to_owned()).collect();
        let def = goto_definition(db, root, entry, &module, byte)?;
        let lo = def.span.lo as usize;
        let hi = def.span.hi as usize;
        if def_text.get(lo..hi)? != def.target.name() {
            return None;
        }
        let refs = find_references(db, root, entry, &def.target);
        Some((def, refs))
    }

    #[test]
    fn resolve_name_at_definition_name_token_resolves() {
        let db = IpeDatabase::new();
        let helper = file(&db, &["Helper"], HELPER);
        let entry = file(&db, &["Main"], MAIN);
        let root = root_of(&db, &[(&["Helper"], helper), (&["Main"], entry)]);

        let resolved = resolve_name_at(
            &db,
            root,
            entry,
            &["Helper".to_owned()],
            helper_def_name_byte(),
        )
        .expect("cursor on the definition name resolves");
        assert_eq!(resolved.target, declared(&["Helper"], "three"));
        let lo = resolved.span.lo as usize;
        let hi = resolved.span.hi as usize;
        assert_eq!(HELPER.get(lo..hi), Some("three"));
    }

    #[test]
    fn find_references_from_definition_name_returns_def_and_uses() {
        let db = IpeDatabase::new();
        let helper = file(&db, &["Helper"], HELPER);
        let entry = file(&db, &["Main"], MAIN);
        let root = root_of(&db, &[(&["Helper"], helper), (&["Main"], entry)]);

        let (def, refs) = references_via_handler(
            &db,
            root,
            entry,
            &["Helper"],
            helper_def_name_byte(),
            HELPER,
        )
        .expect("caret on the definition name resolves a target");

        assert_eq!(def.module, vec!["Helper".to_owned()]);
        // The use in `Main` (`main = three`) must be found from the def site.
        assert_eq!(refs.len(), 1, "expected the one use site, got: {refs:?}");
        let r = refs.first().expect("one reference");
        assert_eq!(r.module, vec!["Main".to_owned()]);
        // Union def + refs is non-empty (what the handler returns to the client).
        assert!(
            !refs.is_empty(),
            "def-name find-references must be non-empty"
        );
    }

    #[test]
    fn goto_definition_from_definition_name_is_idempotent() {
        let db = IpeDatabase::new();
        let helper = file(&db, &["Helper"], HELPER);
        let entry = file(&db, &["Main"], MAIN);
        let root = root_of(&db, &[(&["Helper"], helper), (&["Main"], entry)]);

        let def = goto_definition(
            &db,
            root,
            entry,
            &["Helper".to_owned()],
            helper_def_name_byte(),
        )
        .expect("goto-definition on the definition name resolves");
        assert_eq!(def.module, vec!["Helper".to_owned()]);
        let lo = def.span.lo as usize;
        let hi = def.span.hi as usize;
        assert_eq!(HELPER.get(lo..hi), Some("three"));
    }

    /// The `Red` in the union declaration `type Color = Red | Green`.
    fn ctor_decl_name_byte() -> u32 {
        let off = CTOR_MAIN.find("Red | Green").expect("union decl has Red");
        u32::try_from(off).expect("fits u32")
    }

    #[test]
    fn find_references_from_constructor_declaration_name() {
        let db = IpeDatabase::new();
        let entry = file(&db, &["Main"], CTOR_MAIN);
        let root = root_of(&db, &[(&["Main"], entry)]);

        let (def, refs) = references_via_handler(
            &db,
            root,
            entry,
            &["Main"],
            ctor_decl_name_byte(),
            CTOR_MAIN,
        )
        .expect("caret on the constructor declaration name resolves");

        assert_eq!(def.module, vec!["Main".to_owned()]);
        // The value use in `pick` and the `case` pattern in `describe`.
        assert_eq!(
            refs.len(),
            2,
            "expected value use + pattern use from the ctor decl, got: {refs:?}"
        );
        for r in &refs {
            let lo = r.span.lo as usize;
            let hi = r.span.hi as usize;
            assert_eq!(CTOR_MAIN.get(lo..hi), Some("Red"));
        }
    }

    #[test]
    fn use_site_references_still_resolve() {
        // Regression: the use site path must keep working after the def-site
        // fallback is added.
        let db = IpeDatabase::new();
        let helper = file(&db, &["Helper"], HELPER);
        let entry = file(&db, &["Main"], MAIN);
        let root = root_of(&db, &[(&["Helper"], helper), (&["Main"], entry)]);

        let (def, refs) = references_via_handler(&db, root, entry, &["Main"], ref_byte(), HELPER)
            .expect("caret on a use site resolves");
        assert_eq!(def.module, vec!["Helper".to_owned()]);
        assert_eq!(refs.len(), 1, "the single use site, got: {refs:?}");
    }

    #[test]
    fn cursor_on_nothing_resolves_to_none() {
        let db = IpeDatabase::new();
        let helper = file(&db, &["Helper"], HELPER);
        let entry = file(&db, &["Main"], MAIN);
        let root = root_of(&db, &[(&["Helper"], helper), (&["Main"], entry)]);

        // Byte 0 is the `m` of `module` — a keyword, on no name-bearing token.
        assert!(
            resolve_name_at(&db, root, entry, &["Main".to_owned()], 0).is_none(),
            "keyword position must not resolve"
        );
        assert!(
            goto_definition(&db, root, entry, &["Main".to_owned()], 0).is_none(),
            "keyword position yields no definition"
        );
    }
}
