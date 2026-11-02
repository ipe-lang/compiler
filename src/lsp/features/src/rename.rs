//! Rename: `textDocument/rename` and `textDocument/prepareRename`.
//!
//! The renamed name is whatever the resolver recorded at the cursor: a
//! top-level declaration or constructor (renamed across every project module
//! through [`ipe_canon::rename`]) or a local binder (renamed within its scope
//! only, by binder identity). This module owns the LSP boundary: positions,
//! the `WorkspaceEdit`, and the URI/text callbacks from the server layer.
//!
//! Every edit replaces exactly one token spelling the old name. The rename is
//! refused (`None`) — never applied partially — when an occurrence's token
//! cannot be isolated, when a touched module does not canonicalise or lex,
//! when the new name could capture or be captured, when a site is a record
//! pattern's field label, or when a string interpolation may mention either
//! spelling (the resolver records no occurrence inside one).
//!
//! The `new_name` string from the LSP client is untrusted: [`ValidatedIdentifier`]
//! is the parse-don't-validate boundary; only the validated form reaches the
//! edit builder.

use std::collections::BTreeMap;
use std::sync::Arc;

use ipe_canon::name_index::NameIndex;
use ipe_canon::ref_index::ReferenceIndex;
use ipe_canon::rename::rename as canon_rename;
use ipe_db::{CanonicalModule, Db as _, IpeDatabase, ModuleOrigin, SourceRoot};
use ipe_diagnostics::{Span, TokenKind};
use ipe_intern::{Interner, Symbol};
use ipe_parse::{SourceToken, TokenClass};
use ipe_syntax::{Exposed, Exposing};
use lsp_types::{TextEdit, Url, WorkspaceEdit};

use crate::navigation::{
    NameRef, NameTarget, goto_definition, name_token, occurrences, resolve_name_at, span_text,
};
use crate::offset::{PositionEncoding, span_to_range};
use crate::workspace_edit::workspace_edit;

// ── Case class ───────────────────────────────────────────────────────────────

/// Whether a renamed symbol is a type/constructor (uppercase) or a value
/// (lowercase / `_`). Mirrors the lexer's `Tok::UpperIdent` / `Tok::LowerIdent`
/// split.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SymbolKind {
    /// Type alias, custom type, or constructor — first char must be uppercase.
    Type,
    /// Value binding or function — first char must be lowercase or `_`.
    Value,
}

// ── ValidatedIdentifier ──────────────────────────────────────────────────────

/// A single well-formed Ipê identifier that passed all rename guards: correct
/// lexical shape, not a keyword, and matching case class for the renamed symbol.
///
/// Only constructible via [`ValidatedIdentifier::parse`] — invalid names cannot
/// be represented by this type.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ValidatedIdentifier(String);

impl ValidatedIdentifier {
    /// Parse `raw` into a validated identifier for a rename of `kind`.
    ///
    /// Returns `None` when `raw` is empty, contains spaces or non-ASCII chars,
    /// is not a single `[A-Za-z_][A-Za-z0-9_]*` token, is a keyword, or has
    /// the wrong case class for `kind`.
    #[must_use]
    pub fn parse(raw: &str, kind: SymbolKind) -> Option<Self> {
        // Gate on the lexer's own identifier shape and keyword table (the
        // single source of truth) so a rename can never produce a keyword or a
        // non-token — renaming to `foreign`, `do`, or any other reserved word
        // rewrites references into unparseable source.
        if !ipe_parse::is_identifier(raw) {
            return None;
        }
        let first = raw.chars().next()?;
        match kind {
            SymbolKind::Type => {
                if !first.is_ascii_uppercase() {
                    return None;
                }
            }
            SymbolKind::Value => {
                if first.is_ascii_uppercase() {
                    return None;
                }
            }
        }
        Some(Self(raw.to_owned()))
    }

    /// The validated identifier text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Infer the [`SymbolKind`] of an identifier from its first character.
fn symbol_kind_of(name: &str) -> SymbolKind {
    match name.chars().next() {
        Some(c) if c.is_ascii_uppercase() => SymbolKind::Type,
        _ => SymbolKind::Value,
    }
}

/// The identifier and its span at a position, returned by `prepare_rename`.
///
/// The client uses the span to pre-fill the rename input box with the current
/// name.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PrepareRename {
    /// The current name of the identifier under the cursor.
    pub name: String,
    /// The byte span of that identifier in the requesting module's source.
    pub span: Span,
}

/// Validate that the position is renameable and return the current name.
///
/// Returns `None` when the position resolves to nothing, when the token under
/// the cursor is not exactly the name, or when the name is declared outside
/// the user's project — the client should show no rename UI in that case.
#[must_use]
pub fn prepare_rename(
    db: &IpeDatabase,
    root: SourceRoot,
    entry: ipe_db::SourceFile,
    module: &[String],
    byte: u32,
) -> Option<PrepareRename> {
    // The same "resolve the name under this position" query used by
    // goto-definition and find-references, so all three agree about whether a
    // position — use site, binder or declaration name token — is resolvable.
    let resolved = resolve_name_at(db, root, entry, module, byte)?;
    let files = root.files(db);
    let text = files.get(module)?.text(db);
    let name = resolved.target.name();
    let renameable = span_text(text, resolved.span)? == name
        && is_user_module(db, root, resolved.target.module());
    renameable.then(|| PrepareRename {
        name: name.to_owned(),
        span: resolved.span,
    })
}

/// Whether `module` is a project module the user wrote.
fn is_user_module(db: &IpeDatabase, root: SourceRoot, module: &[String]) -> bool {
    root.files(db)
        .get(module)
        .is_some_and(|file| *file.origin(db) == ModuleOrigin::User)
}

/// Supplies URI and text for a module path, forwarded from the server layer
/// so the features crate never touches the filesystem.
pub struct ModuleResolver<'a> {
    /// Maps a module path to its document URI.
    pub uri_of_module: &'a dyn Fn(&[String]) -> Option<Url>,
    /// Maps a module path to its current source text.
    pub text_of_module: &'a dyn Fn(&[String]) -> Option<String>,
    /// The known version of the open overlay at a URI, or `None` when the
    /// client lacks the `documentChanges` capability or the document is not
    /// a tracked overlay. The single source [`rename`] reads to decide
    /// whether each touched document's edit can be versioned.
    pub version_of: &'a dyn Fn(&Url) -> Option<i32>,
}

/// The cursor position and replacement text for a rename request.
///
/// `new_name` is the raw string from the LSP client. [`rename`] parses it
/// into a [`ValidatedIdentifier`] at the boundary — if validation fails,
/// `rename` returns `None` and no edits are emitted.
pub struct RenameRequest<'a> {
    /// Cursor byte offset within `module`.
    pub byte: u32,
    /// The replacement name the user typed (validated inside [`rename`]).
    pub new_name: &'a str,
    /// Position encoding in use for the session.
    pub encoding: PositionEncoding,
    /// Whether the client accepts versioned `documentChanges`
    /// (`workspace.workspaceEdit.documentChanges`); mirrors
    /// `resolver.version_of`'s capability gate.
    pub document_changes_supported: bool,
}

/// Apply a rename to the name at `req.byte` in `module`.
///
/// Returns the `WorkspaceEdit` the client should apply, or `None` when the
/// position is not renameable or the rename cannot be proven safe. Every edit
/// replaces exactly one token spelling the old name; an occurrence whose
/// token cannot be isolated refuses the whole rename rather than rewrite more
/// text than the name.
///
/// `resolver` supplies URI and text callbacks; they are injected by the server
/// because URI construction requires filesystem paths the features crate never
/// touches.
#[must_use]
pub fn rename(
    db: &IpeDatabase,
    root: SourceRoot,
    entry: ipe_db::SourceFile,
    module: &[String],
    req: &RenameRequest<'_>,
    resolver: &ModuleResolver<'_>,
) -> Option<WorkspaceEdit> {
    let def = goto_definition(db, root, entry, module, req.byte)?;
    if !is_user_module(db, root, &def.module) {
        return None;
    }
    let files = root.files(db);
    // A rename edits every occurrence, so a module whose index misses the
    // occurrences of a failed declaration refuses it.
    if !crate::db_access::analysis(db, root, entry, *files.get(&def.module)?)?.complete {
        return None;
    }
    let old_name = def.target.name();
    if span_text(files.get(&def.module)?.text(db), def.span)? != old_name {
        return None;
    }
    // Parse-don't-validate gate on the untrusted client string.
    let new_name = ValidatedIdentifier::parse(req.new_name, symbol_kind_of(old_name))?;
    let new_name = new_name.as_str();

    let (recorded, scanned): (Vec<NameRef>, Vec<Vec<String>>) = match &def.target {
        NameTarget::Local { .. } => {
            let mut sites = vec![NameRef {
                module: def.module.clone(),
                span: def.span,
            }];
            sites.extend(occurrences(db, root, entry, &def.target));
            (sites, vec![def.module.clone()])
        }
        NameTarget::Declared { .. } => {
            let mut sites = declared_sites(db, root, entry, &def.module, old_name, new_name)?;
            sites.extend(signature_sites(db, root, &def.module, old_name)?);
            let user_modules = files
                .iter()
                .filter(|(_, file)| *file.origin(db) == ModuleOrigin::User)
                .map(|(path, _)| path.clone())
                .collect();
            (sites, user_modules)
        }
    };
    let sites = narrowed_sites(db, root, recorded, old_name)?;
    refuse_capture(db, root, entry, &sites, new_name)?;
    refuse_interpolation(db, root, &scanned, old_name, new_name)?;

    let mut edits_by_uri = edits_by_uri(&sites, new_name, resolver, req.encoding)?;
    if matches!(def.target, NameTarget::Declared { .. }) {
        let mut interner = db.interner().lock();
        let old_name_sym = interner.intern(old_name).ok();
        drop(interner);
        let old_name_sym = old_name_sym?;
        patch_exposing_headers(
            db,
            root,
            &def.module,
            old_name_sym,
            new_name,
            resolver,
            req.encoding,
            &mut edits_by_uri,
        )?;
    }
    Some(workspace_edit(
        edits_by_uri,
        req.document_changes_supported,
        resolver.version_of,
    ))
}

// ── Edit sites ────────────────────────────────────────────────────────────────

/// A module path in symbol form, or `None` when a segment cannot be interned.
fn intern_path(interner: &mut Interner, path: &[String]) -> Option<Vec<Symbol>> {
    path.iter()
        .map(|segment| interner.intern(segment).ok())
        .collect()
}

/// The canonical module and symbol path of one project module.
type CanonEntry = (Arc<CanonicalModule>, Vec<Symbol>);

/// The definition and every recorded use of the declaration `(home, old_name)`,
/// from the canon rename engine over every project module's name index.
///
/// Refuses (`None`) when any project module does not canonicalise — its uses
/// would be missed — or when the engine reports a capture conflict.
fn declared_sites(
    db: &IpeDatabase,
    root: SourceRoot,
    entry: ipe_db::SourceFile,
    home: &[String],
    old_name: &str,
    new_name: &str,
) -> Option<Vec<NameRef>> {
    let Ok(order) = ipe_db::topo_order(db, root, entry) else {
        return None;
    };
    let files = root.files(db);
    let mut canon: Vec<CanonEntry> = Vec::new();
    for module_path in order.iter() {
        let Some(&module_file) = files.get(module_path) else {
            continue;
        };
        let analysis = crate::db_access::analysis(db, root, entry, module_file)?;
        if !analysis.complete {
            return None;
        }
        let canonical = analysis.canonical;
        let mut interner = db.interner().lock();
        let path = intern_path(&mut interner, module_path);
        drop(interner);
        canon.push((canonical, path?));
    }
    let (home_syms, old_sym) = {
        let mut interner = db.interner().lock();
        let home_syms = intern_path(&mut interner, home);
        let old_sym = interner.intern(old_name).ok();
        drop(interner);
        (home_syms?, old_sym?)
    };
    let modules: Vec<(&ipe_canon::ast::Module, &[Symbol])> = canon
        .iter()
        .map(|(canonical, path)| (&canonical.module, path.as_slice()))
        .collect();
    let indexes: Vec<(&NameIndex, &[Symbol])> = canon
        .iter()
        .map(|(canonical, path)| (&canonical.names, path.as_slice()))
        .collect();
    let index = ReferenceIndex::from_name_indexes(&indexes);
    let interner = db.interner().lock();
    let edits = canon_rename(&interner, &index, &modules, &home_syms, old_sym, new_name)
        .ok()
        .and_then(|edit_set| {
            edit_set
                .edits
                .iter()
                .map(|edit| {
                    let module = edit
                        .file
                        .iter()
                        .map(|&sym| interner.resolve(sym).map(str::to_owned))
                        .collect::<Option<Vec<_>>>()?;
                    Some(NameRef {
                        module,
                        span: edit.span,
                    })
                })
                .collect::<Option<Vec<_>>>()
        });
    drop(interner);
    edits
}

/// The name token of the `old_name : T` signature of a top-level value in
/// `module`, when it has one.
///
/// Refuses (`None`) when the value is annotated but the signature's name token
/// cannot be located: renaming the definition alone would orphan the signature.
fn signature_sites(
    db: &IpeDatabase,
    root: SourceRoot,
    module: &[String],
    old_name: &str,
) -> Option<Vec<NameRef>> {
    let files = root.files(db);
    let &file = files.get(module)?;
    let Ok(parsed) = ipe_db::parse(db, file) else {
        return None;
    };
    let interner = db.interner().lock();
    let annotation_lo = parsed
        .values
        .iter()
        .find(|value| interner.resolve(value.value.name.value) == Some(old_name))
        .and_then(|value| value.value.type_annotation.as_ref())
        .map(|annotation| annotation.span.lo);
    drop(interner);
    let Some(annotation_lo) = annotation_lo else {
        return Some(Vec::new());
    };
    let text = file.text(db);
    let tokens = ipe_parse::try_source_tokens(text)?;
    let colon_at = tokens.iter().rposition(|token| {
        token.span.hi <= annotation_lo && token.class == TokenClass::Code(TokenKind::Colon)
    })?;
    let after_colon = tokens.get(colon_at.checked_add(1)?)?;
    let name = tokens.get(colon_at.checked_sub(1)?)?;
    let located = after_colon.span.lo == annotation_lo
        && name.class == TokenClass::Code(TokenKind::Ident)
        && span_text(text, name.span)? == old_name;
    located.then(|| {
        vec![NameRef {
            module: module.to_vec(),
            span: name.span,
        }]
    })
}

/// Every site narrowed to its `old_name` token, deduplicated.
///
/// Refuses (`None`) when any site's token cannot be isolated — a rewrite there
/// would replace more text than the name.
fn narrowed_sites(
    db: &IpeDatabase,
    root: SourceRoot,
    recorded: Vec<NameRef>,
    old_name: &str,
) -> Option<Vec<NameRef>> {
    let files = root.files(db);
    let mut sites = recorded
        .into_iter()
        .map(|site| {
            let text = files.get(&site.module)?.text(db);
            let span = name_token(text, site.span, old_name)?;
            Some(NameRef {
                module: site.module,
                span,
            })
        })
        .collect::<Option<Vec<_>>>()?;
    sites.sort_by(|a, b| (&a.module, a.span.lo, a.span.hi).cmp(&(&b.module, b.span.lo, b.span.hi)));
    sites.dedup();
    Some(sites)
}

/// Refuse (`None`) when the new name could change what an occurrence in a
/// touched module resolves to, or a site is a record-pattern field label.
///
/// Any recorded occurrence in a touched module already spelled `new_name` (a
/// local binder, an import, a top-level value) could capture or be captured
/// by the renamed sites. A record-pattern field (`{ size }`) names both the
/// binder and the field, so renaming it would change the field it matches.
fn refuse_capture(
    db: &IpeDatabase,
    root: SourceRoot,
    entry: ipe_db::SourceFile,
    sites: &[NameRef],
    new_name: &str,
) -> Option<()> {
    let files = root.files(db);
    let mut touched: Vec<&[String]> = sites.iter().map(|site| site.module.as_slice()).collect();
    touched.dedup();
    for module in touched {
        let &file = files.get(module)?;
        let text = file.text(db);
        let analysis = crate::db_access::analysis(db, root, entry, file)?;
        if !analysis.complete {
            return None;
        }
        if analysis
            .canonical
            .names
            .entries()
            .any(|(span, _)| name_token(text, span, new_name).is_some())
        {
            return None;
        }
        let labels = record_pattern_labels(&ipe_parse::try_source_tokens(text)?);
        let on_label = sites.iter().any(|site| {
            site.module.as_slice() == module
                && labels
                    .iter()
                    .any(|label| label.lo <= site.span.lo && site.span.hi <= label.hi)
        });
        if on_label {
            return None;
        }
    }
    Some(())
}

/// The spans of identifier tokens standing as a record-pattern field label:
/// directly inside `{ }`, between `{`/`,` and `,`/`}`.
fn record_pattern_labels(tokens: &[SourceToken]) -> Vec<Span> {
    let code = |at: Option<usize>| match at.and_then(|i| tokens.get(i)).map(|t| t.class) {
        Some(TokenClass::Code(kind)) => Some(kind),
        Some(TokenClass::DocComment) | None => None,
    };
    let mut open: Vec<TokenKind> = Vec::new();
    let mut labels = Vec::new();
    for (at, token) in tokens.iter().enumerate() {
        let TokenClass::Code(kind) = token.class else {
            continue;
        };
        match kind {
            TokenKind::LParen | TokenKind::LBrace | TokenKind::LBracket => open.push(kind),
            TokenKind::RParen | TokenKind::RBrace | TokenKind::RBracket => {
                open.pop();
            }
            TokenKind::Ident => {
                let in_braces = open.last() == Some(&TokenKind::LBrace);
                let after = matches!(
                    code(at.checked_sub(1)),
                    Some(TokenKind::LBrace | TokenKind::Comma)
                );
                let before = matches!(
                    code(at.checked_add(1)),
                    Some(TokenKind::RBrace | TokenKind::Comma)
                );
                if in_braces && after && before {
                    labels.push(token.span);
                }
            }
            TokenKind::Module
            | TokenKind::Import
            | TokenKind::Exposing
            | TokenKind::As
            | TokenKind::Type
            | TokenKind::Foreign
            | TokenKind::Case
            | TokenKind::Of
            | TokenKind::Let
            | TokenKind::In
            | TokenKind::If
            | TokenKind::Then
            | TokenKind::Else
            | TokenKind::Do
            | TokenKind::ColonColon
            | TokenKind::Equals
            | TokenKind::Pipe
            | TokenKind::Colon
            | TokenKind::Arrow
            | TokenKind::LeftArrow
            | TokenKind::Backslash
            | TokenKind::DotDot
            | TokenKind::Dot
            | TokenKind::Comma
            | TokenKind::Underscore
            | TokenKind::Plus
            | TokenKind::PlusPlus
            | TokenKind::Minus
            | TokenKind::Star
            | TokenKind::Slash
            | TokenKind::SlashEq
            | TokenKind::SlashSlash
            | TokenKind::EqEq
            | TokenKind::Lt
            | TokenKind::Gt
            | TokenKind::Le
            | TokenKind::Ge
            | TokenKind::AmpAmp
            | TokenKind::PipePipe
            | TokenKind::PipeGt
            | TokenKind::LtPipe
            | TokenKind::PipeEq
            | TokenKind::PipeDot
            | TokenKind::GtGt
            | TokenKind::LtLt
            | TokenKind::Int
            | TokenKind::Float
            | TokenKind::Str
            | TokenKind::Char
            | TokenKind::Eof => {}
        }
    }
    labels
}

/// Refuse (`None`) when a string literal in `modules` may interpolate the old
/// or the new name.
///
/// The resolver records no occurrence inside an interpolation, so a rename
/// cannot rewrite one; a `{{ … }}` string mentioning either spelling as a word
/// would silently keep the old name or start naming the renamed value.
fn refuse_interpolation(
    db: &IpeDatabase,
    root: SourceRoot,
    modules: &[Vec<String>],
    old_name: &str,
    new_name: &str,
) -> Option<()> {
    let files = root.files(db);
    for module in modules {
        let text = files.get(module)?.text(db);
        let tokens = ipe_parse::try_source_tokens(text)?;
        let interpolates = tokens
            .iter()
            .filter(|token| token.class == TokenClass::Code(TokenKind::Str))
            .filter_map(|token| span_text(text, token.span))
            .any(|literal| {
                literal.contains("{{")
                    && (has_word(literal, old_name) || has_word(literal, new_name))
            });
        if interpolates {
            return None;
        }
    }
    Some(())
}

/// Whether `word` occurs in `hay` with no identifier character on either side.
fn has_word(hay: &str, word: &str) -> bool {
    hay.match_indices(word).any(|(at, _)| {
        let before = hay.get(..at).and_then(|s| s.chars().next_back());
        let after = at
            .checked_add(word.len())
            .and_then(|end| hay.get(end..))
            .and_then(|s| s.chars().next());
        !before.is_some_and(ipe_parse::is_ident_continue)
            && !after.is_some_and(ipe_parse::is_ident_continue)
    })
}

/// Group the sites into `new_name` edits keyed by document URI.
///
/// Refuses (`None`) when a touched module has no URI or text: dropping its
/// edits would leave a partial rename.
fn edits_by_uri(
    sites: &[NameRef],
    new_name: &str,
    resolver: &ModuleResolver<'_>,
    encoding: PositionEncoding,
) -> Option<BTreeMap<Url, Vec<TextEdit>>> {
    let mut edits_by_uri: BTreeMap<Url, Vec<TextEdit>> = BTreeMap::new();
    for site in sites {
        let uri = (resolver.uri_of_module)(&site.module)?;
        let text = (resolver.text_of_module)(&site.module)?;
        let range = span_to_range(&text, site.span, encoding);
        edits_by_uri.entry(uri).or_default().push(TextEdit {
            range,
            new_text: new_name.to_owned(),
        });
    }
    (!edits_by_uri.is_empty()).then_some(edits_by_uri)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Patch `exposing (Name)` in the defining module's header and every
/// `import DefModule exposing (Name)` in consumer modules.
///
/// The canon rename engine operates on body-expression and binding-name spans;
/// it never visits module headers or import clauses. This pass adds those edits
/// so the rename stays syntactically valid.
///
/// A module that does not parse holds no exposing list to patch (every module
/// the rename resolved parsed; one outside the import graph that spells the
/// name already refused it). Refuses (`None`) when a list naming `old_name`
/// sits in a module with no URI or text: dropping that edit would leave a
/// partial rename.
#[allow(clippy::too_many_arguments)] // internal helper; extracting a struct adds ceremony without benefit
fn patch_exposing_headers(
    db: &IpeDatabase,
    root: SourceRoot,
    def_module: &[String],
    old_name: Symbol,
    new_name: &str,
    resolver: &ModuleResolver<'_>,
    encoding: PositionEncoding,
    edits_by_uri: &mut BTreeMap<Url, Vec<TextEdit>>,
) -> Option<()> {
    for (module_path, &file) in root.files(db) {
        let Ok(parsed) = ipe_db::parse(db, file) else {
            continue;
        };
        let mut lists: Vec<&Exposing> = Vec::new();
        if module_path.as_slice() == def_module {
            lists.push(&parsed.exposing.value);
        }
        for import in &parsed.imports {
            let interner = db.interner().lock();
            let imports_def = import.name.value.len() == def_module.len()
                && import
                    .name
                    .value
                    .iter()
                    .zip(def_module)
                    .all(|(&sym, segment)| interner.resolve(sym) == Some(segment.as_str()));
            drop(interner);
            if imports_def {
                lists.push(&import.exposing.value);
            }
        }
        for exposing in lists {
            let Some(span) = exposed_name_span(exposing, old_name) else {
                continue;
            };
            let uri = (resolver.uri_of_module)(module_path)?;
            let text = (resolver.text_of_module)(module_path)?;
            add_edit(
                edits_by_uri,
                uri,
                TextEdit {
                    range: span_to_range(&text, span, encoding),
                    new_text: new_name.to_owned(),
                },
            );
        }
    }
    Some(())
}

/// The span of `old_name` inside an `Exposing::List`, or `None` when the
/// exposing clause is `(..)` or does not mention `old_name`.
///
/// A `Type(Name, Privacy::Public)` exposes `Name(..)`; its span covers only
/// the type name token, so replacing just that span is correct.
fn exposed_name_span(exposing: &Exposing, old_name: Symbol) -> Option<Span> {
    let Exposing::List(items) = exposing else {
        return None;
    };
    items.iter().find_map(|item| {
        let (Exposed::Value(sym) | Exposed::Type(sym, _)) = &item.value;
        (*sym == old_name).then_some(item.span)
    })
}

/// Insert `edit` for `uri` into `edits_by_uri`, appending to any existing
/// edits for that URI. Creates the entry when absent.
fn add_edit(edits_by_uri: &mut BTreeMap<Url, Vec<TextEdit>>, uri: Url, edit: TextEdit) {
    edits_by_uri.entry(uri).or_default().push(edit);
}

#[cfg(test)]
mod tests {
    use ipe_db::{IpeDatabase, ModuleOrigin, SourceFile, SourceRoot};
    use lsp_types::Url;

    use crate::offset::PositionEncoding;

    use super::{SymbolKind, ValidatedIdentifier, prepare_rename, rename};

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

    const HELPER: &str = "module Helper exposing (three)\n\nthree : Int\nthree = 3\n";
    const MAIN: &str = "module Main exposing (main)\n\nimport Helper exposing (three)\n\nmain : Int\nmain = three\n";

    fn ref_byte() -> u32 {
        u32::try_from(MAIN.rfind("three").expect("three in main")).expect("u32")
    }

    fn make_uri(module: &[String]) -> Option<Url> {
        let path = format!("/fake/{}.ipe", module.join("/"));
        Url::from_file_path(path).ok()
    }

    fn make_text(module: &[String]) -> Option<String> {
        match module.first().map(String::as_str) {
            Some("Helper") => Some(HELPER.to_owned()),
            Some("Main") => Some(MAIN.to_owned()),
            _ => None,
        }
    }

    fn no_version(_uri: &Url) -> Option<i32> {
        None
    }

    // ── ValidatedIdentifier boundary tests ───────────────────────────────────

    #[test]
    fn valid_value_identifiers_are_accepted() {
        for name in ["foo", "bar_baz", "_private", "x1", "camelCase"] {
            assert!(
                ValidatedIdentifier::parse(name, SymbolKind::Value).is_some(),
                "{name:?} should be a valid value identifier"
            );
        }
    }

    #[test]
    fn valid_type_identifiers_are_accepted() {
        for name in ["Foo", "MyType", "A1"] {
            assert!(
                ValidatedIdentifier::parse(name, SymbolKind::Type).is_some(),
                "{name:?} should be a valid type identifier"
            );
        }
    }

    #[test]
    fn illegal_names_are_rejected_for_value_rename() {
        // Spaces, leading digit, empty, operator chars, non-ASCII
        for name in ["foo bar", "1x", "", "foo.bar", "foo;drop", "café"] {
            assert!(
                ValidatedIdentifier::parse(name, SymbolKind::Value).is_none(),
                "{name:?} should be rejected for value rename"
            );
        }
    }

    #[test]
    fn keywords_are_rejected() {
        // Driven off the lexer's own table so a new keyword is covered on add.
        for kw in ipe_parse::KEYWORDS {
            assert!(
                ValidatedIdentifier::parse(kw, SymbolKind::Value).is_none(),
                "keyword {kw:?} must be rejected"
            );
        }
    }

    #[test]
    fn wrong_case_class_is_rejected() {
        // Uppercase name for a value rename
        assert!(
            ValidatedIdentifier::parse("Foo", SymbolKind::Value).is_none(),
            "uppercase name must be rejected for value rename"
        );
        // Lowercase name for a type rename
        assert!(
            ValidatedIdentifier::parse("foo", SymbolKind::Type).is_none(),
            "lowercase name must be rejected for type rename"
        );
        // Wrong-case for mixed: "Foo bar" is doubly wrong
        assert!(
            ValidatedIdentifier::parse("Foo bar", SymbolKind::Value).is_none(),
            "Foo bar must be rejected for value rename"
        );
    }

    // ── Integration: rename with illegal names emits no edits ─────────────────

    fn do_rename(new_name: &str) -> Option<lsp_types::WorkspaceEdit> {
        do_rename_versioned(new_name, None, false)
    }

    fn do_rename_versioned(
        new_name: &str,
        version: Option<i32>,
        document_changes_supported: bool,
    ) -> Option<lsp_types::WorkspaceEdit> {
        let db = IpeDatabase::new();
        let helper = file(&db, &["Helper"], HELPER);
        let entry = file(&db, &["Main"], MAIN);
        let root = root_of(&db, &[(&["Helper"], helper), (&["Main"], entry)]);
        let version_of = move |_: &Url| version;
        rename(
            &db,
            root,
            entry,
            &["Main".to_owned()],
            &super::RenameRequest {
                byte: ref_byte(),
                new_name,
                encoding: PositionEncoding::Utf16,
                document_changes_supported,
            },
            &super::ModuleResolver {
                uri_of_module: &make_uri,
                text_of_module: &make_text,
                version_of: &version_of,
            },
        )
    }

    #[test]
    fn rename_with_illegal_name_returns_none() {
        for bad in ["foo bar", "1x", "", "Uppercase", "let"] {
            assert!(
                do_rename(bad).is_none(),
                "rename to {bad:?} must return None (no edits)"
            );
        }
    }

    // ── Existing integration tests ─────────────────────────────────────────────

    #[test]
    fn prepare_rename_finds_identifier_at_reference_site() {
        let db = IpeDatabase::new();
        let helper = file(&db, &["Helper"], HELPER);
        let entry = file(&db, &["Main"], MAIN);
        let root = root_of(&db, &[(&["Helper"], helper), (&["Main"], entry)]);

        let result = prepare_rename(&db, root, entry, &["Main".to_owned()], ref_byte());
        let r = result.expect("prepare_rename returned Some");
        assert_eq!(r.name, "three");
    }

    #[test]
    fn prepare_rename_finds_identifier_at_definition_site() {
        // The def-site path goes through the shared `resolve_name_at`; the cursor
        // on the definition's own name token must still be renameable.
        let db = IpeDatabase::new();
        let helper = file(&db, &["Helper"], HELPER);
        let entry = file(&db, &["Main"], MAIN);
        let root = root_of(&db, &[(&["Helper"], helper), (&["Main"], entry)]);

        let sig = HELPER.find("three : Int").expect("signature");
        let decl = HELPER[sig + 3..]
            .find("three")
            .map(|o| sig + 3 + o)
            .expect("declaration follows the signature");
        let byte = u32::try_from(decl).expect("fits u32");

        let r = prepare_rename(&db, root, entry, &["Helper".to_owned()], byte)
            .expect("prepare_rename resolves the definition name");
        assert_eq!(r.name, "three");
        let lo = r.span.lo as usize;
        let hi = r.span.hi as usize;
        assert_eq!(HELPER.get(lo..hi), Some("three"));
    }

    #[test]
    fn rename_produces_edits_for_definition_and_all_references() {
        let ws_edit = do_rename("four").expect("rename returned Some");

        let changes = ws_edit.changes.expect("has changes");
        // Two files should have edits: Helper (definition) and Main (reference).
        assert_eq!(
            changes.len(),
            2,
            "edits in 2 files: {:?}",
            changes.keys().collect::<Vec<_>>()
        );
        for edits in changes.values() {
            for edit in edits {
                assert_eq!(edit.new_text, "four");
            }
        }
    }

    // ── Constructor rename (issue #2654) ─────────────────────────────────────
    //
    // A rename with the cursor on a constructor value use must reach the canon
    // rename engine and rewrite EVERY site: the declaration in the `type` union,
    // the value use, and the `case` pattern. Before this fix the request gated
    // on a value-only defining-site lookup and returned a silent no-op.

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
        // The `Red` in `pick = Red` (a value use), not the declaration.
        let decl = CTOR_MAIN.find("Red | Green").expect("union decl has Red");
        let use_off = CTOR_MAIN[decl + 3..]
            .find("Red")
            .map(|o| decl + 3 + o)
            .expect("value use of Red follows the declaration");
        u32::try_from(use_off).expect("fits u32")
    }

    fn ctor_uri(_module: &[String]) -> Option<Url> {
        Url::from_file_path("/fake/Main.ipe").ok()
    }

    fn ctor_text(module: &[String]) -> Option<String> {
        match module.first().map(String::as_str) {
            Some("Main") => Some(CTOR_MAIN.to_owned()),
            _ => None,
        }
    }

    #[test]
    fn rename_constructor_edits_declaration_value_use_and_pattern() {
        let db = IpeDatabase::new();
        let entry = file(&db, &["Main"], CTOR_MAIN);
        let root = root_of(&db, &[(&["Main"], entry)]);

        let ws_edit = rename(
            &db,
            root,
            entry,
            &["Main".to_owned()],
            &super::RenameRequest {
                byte: ctor_value_use_byte(),
                new_name: "Crimson",
                encoding: PositionEncoding::Utf16,
                document_changes_supported: false,
            },
            &super::ModuleResolver {
                uri_of_module: &ctor_uri,
                text_of_module: &ctor_text,
                version_of: &no_version,
            },
        )
        .expect("constructor rename must reach the engine and return Some");

        let changes = ws_edit.changes.expect("has changes");
        let edits: Vec<_> = changes.values().flatten().collect();
        // Declaration in the union + value use + `case` pattern = 3 edits.
        assert_eq!(
            edits.len(),
            3,
            "constructor rename must edit declaration + value use + pattern, got: {edits:?}"
        );
        for edit in &edits {
            assert_eq!(edit.new_text, "Crimson");
        }
    }

    // ── Exposing-header patching (issue #2709-D) ─────────────────────────────
    //
    // A rename must also rewrite the defining module's `exposing (Name)` header
    // and every consumer's `import DefModule exposing (Name)` line. Before this
    // fix the canon engine only touched body-expression spans and the `module
    // … exposing` / `import … exposing` tokens were left stale.

    #[test]
    fn rename_also_updates_defining_module_exposing_header() {
        // HELPER: `module Helper exposing (three)` — `three` must become `four`.
        let ws_edit = do_rename("four").expect("rename returned Some");
        let changes = ws_edit.changes.expect("has changes");

        // Every text edit across all files must replace with "four".
        for edits in changes.values() {
            for edit in edits {
                assert_eq!(edit.new_text, "four", "stale old name in edit: {edit:?}");
            }
        }

        // The Helper file must have at least 2 edits: the definition-name token
        // AND the exposing-header token.
        let helper_uri = make_uri(&["Helper".to_owned()]).expect("helper uri");
        let helper_edits = changes.get(&helper_uri).expect("Helper must have edits");
        assert!(
            helper_edits.len() >= 2,
            "Helper must have ≥2 edits (definition + exposing header), got {}: {helper_edits:?}",
            helper_edits.len()
        );
        // At least one edit must be on line 0 (the `module Helper exposing (three)` header).
        let has_header_edit = helper_edits.iter().any(|e| e.range.start.line == 0);
        assert!(
            has_header_edit,
            "no edit on line 0 (exposing header) in Helper: {helper_edits:?}"
        );
    }

    #[test]
    fn rename_also_updates_consumer_import_exposing_list() {
        // MAIN imports `Helper exposing (three)` — `three` must become `four`.
        let ws_edit = do_rename("four").expect("rename returned Some");
        let changes = ws_edit.changes.expect("has changes");

        let main_uri = make_uri(&["Main".to_owned()]).expect("main uri");
        let main_edits = changes.get(&main_uri).expect("Main must have edits");

        // Main has: the use-site `three` in `main = three` (line 5) AND the
        // `import Helper exposing (three)` header (line 2). So ≥ 2 edits.
        assert!(
            main_edits.len() >= 2,
            "Main must have ≥2 edits (use site + import exposing), got {}: {main_edits:?}",
            main_edits.len()
        );
        // All new_text must be the new name.
        for edit in main_edits {
            assert_eq!(edit.new_text, "four", "stale old name: {edit:?}");
        }
        // At least one edit must be on line 2 (the `import Helper exposing (three)` line).
        let has_import_edit = main_edits.iter().any(|e| e.range.start.line == 2);
        assert!(
            has_import_edit,
            "no edit on line 2 (import exposing) in Main: {main_edits:?}"
        );
    }

    // ── Versioned `documentChanges` (issue #3116) ────────────────────────────

    #[test]
    fn a_known_version_yields_versioned_document_changes() {
        let ws_edit = do_rename_versioned("four", Some(9), true).expect("rename returned Some");
        assert!(ws_edit.changes.is_none(), "{ws_edit:?}");
        assert!(
            matches!(&ws_edit.document_changes, Some(lsp_types::DocumentChanges::Edits(edits))
                if edits.len() == 2
                    && edits.iter().all(|e| e.text_document.version == Some(9))),
            "{ws_edit:?}"
        );
    }

    #[test]
    fn no_known_version_falls_back_to_unversioned_flat_changes() {
        let ws_edit = do_rename_versioned("four", None, false).expect("rename returned Some");
        assert!(ws_edit.document_changes.is_none(), "{ws_edit:?}");
        assert!(
            matches!(&ws_edit.changes, Some(m) if !m.is_empty()),
            "{ws_edit:?}"
        );
    }

    // ── Token-exact edits and fail-closed refusals ───────────────────────────

    /// One module of a rename scenario: its single-segment name, text, origin.
    type Source<'a> = (&'a str, &'a str, ModuleOrigin);

    /// The texts after applying `edits` to `text` (ranges in UTF-8 units).
    fn apply(text: &str, edits: &[lsp_types::TextEdit]) -> String {
        let mut spans: Vec<(usize, usize, &str)> = edits
            .iter()
            .map(|edit| {
                (
                    crate::offset::position_to_offset(
                        text,
                        edit.range.start,
                        PositionEncoding::Utf8,
                    ),
                    crate::offset::position_to_offset(text, edit.range.end, PositionEncoding::Utf8),
                    edit.new_text.as_str(),
                )
            })
            .collect();
        spans.sort_by_key(|&(lo, _, _)| std::cmp::Reverse(lo));
        let mut out = text.to_owned();
        for (lo, hi, new_text) in spans {
            out.replace_range(lo..hi, new_text);
        }
        out
    }

    /// Rename the `nth` occurrence of `needle` in module `at` to `new_name`,
    /// returning every module's text after the edit, or `None` when refused.
    fn rename_texts(
        sources: &[Source<'_>],
        at: &str,
        needle: &str,
        nth: usize,
        new_name: &str,
    ) -> Option<std::collections::BTreeMap<String, String>> {
        rename_texts_without_uri(sources, at, needle, nth, new_name, &[])
    }

    /// [`rename_texts`] with a server that has no URI for the `no_uri` modules.
    fn rename_texts_without_uri(
        sources: &[Source<'_>],
        at: &str,
        needle: &str,
        nth: usize,
        new_name: &str,
        no_uri: &[&str],
    ) -> Option<std::collections::BTreeMap<String, String>> {
        let uri_of = |module: &[String]| {
            let served = module
                .first()
                .is_none_or(|name| !no_uri.contains(&name.as_str()));
            served.then(|| make_uri(module)).flatten()
        };
        let db = IpeDatabase::new();
        let files: Vec<(Vec<String>, SourceFile)> = sources
            .iter()
            .map(|&(name, text, origin)| {
                let path = vec![name.to_owned()];
                let source = SourceFile::new(&db, path.clone(), text.to_owned(), origin);
                (path, source)
            })
            .collect();
        let root = SourceRoot::new(&db, files.iter().cloned().collect());
        let entry = files
            .iter()
            .find(|(path, _)| path.first().map(String::as_str) == Some(at))?
            .1;
        let at_text = sources.iter().find(|s| s.0 == at)?.1;
        let byte = at_text.match_indices(needle).nth(nth)?.0;
        let text_of = |module: &[String]| {
            sources
                .iter()
                .find(|s| module.first().map(String::as_str) == Some(s.0))
                .map(|s| s.1.to_owned())
        };
        let edit = rename(
            &db,
            root,
            entry,
            &[at.to_owned()],
            &super::RenameRequest {
                byte: u32::try_from(byte).ok()?,
                new_name,
                encoding: PositionEncoding::Utf8,
                document_changes_supported: false,
            },
            &super::ModuleResolver {
                uri_of_module: &uri_of,
                text_of_module: &text_of,
                version_of: &no_version,
            },
        )?;
        let changes = edit.changes?;
        Some(
            sources
                .iter()
                .map(|&(name, text, _)| {
                    let uri = make_uri(&[name.to_owned()]);
                    let edits = uri
                        .and_then(|u| changes.get(&u).cloned())
                        .unwrap_or_default();
                    (name.to_owned(), apply(text, &edits))
                })
                .collect(),
        )
    }

    const LOCALS: &str = "module Main exposing (main)\n\nbump : Int -> Int\nbump n =\n    n + 1\n\ntwice : Int -> Int\ntwice n =\n    n * 2\n\nmain : Int\nmain = twice (bump 1)\n";

    #[test]
    fn a_local_rename_edits_only_its_own_scope() {
        let user = ModuleOrigin::User;
        let texts = rename_texts(&[("Main", LOCALS, user)], "Main", "n + 1", 0, "count")
            .expect("a local rename is applied");
        assert_eq!(
            texts.get("Main").map(String::as_str),
            Some(
                "module Main exposing (main)\n\nbump : Int -> Int\nbump count =\n    count + 1\n\ntwice : Int -> Int\ntwice n =\n    n * 2\n\nmain : Int\nmain = twice (bump 1)\n"
            )
        );
    }

    #[test]
    fn a_local_rename_onto_a_name_in_scope_is_refused() {
        let src = "module Main exposing (main)\n\nadd : Int -> Int -> Int\nadd a b =\n    a + b\n\nmain : Int\nmain = add 1 2\n";
        let user = ModuleOrigin::User;
        assert!(rename_texts(&[("Main", src, user)], "Main", "a + b", 0, "b").is_none());
    }

    #[test]
    fn a_qualified_use_edits_only_the_member_and_the_signature_follows() {
        let lib = "module Lib exposing (helper)\n\nhelper : Int\nhelper = 2\n";
        let main = "module Main exposing (main)\n\nimport Lib\n\nmain : Int\nmain = Lib.helper\n";
        let user = ModuleOrigin::User;
        let texts = rename_texts(
            &[("Lib", lib, user), ("Main", main, user)],
            "Main",
            "helper",
            0,
            "aid",
        )
        .expect("a qualified-use rename is applied");
        assert_eq!(
            texts.get("Lib").map(String::as_str),
            Some("module Lib exposing (aid)\n\naid : Int\naid = 2\n")
        );
        assert_eq!(
            texts.get("Main").map(String::as_str),
            Some("module Main exposing (main)\n\nimport Lib\n\nmain : Int\nmain = Lib.aid\n")
        );
    }

    #[test]
    fn a_constructor_pattern_edits_only_the_constructor_token() {
        let src = "module Main exposing (main)\n\ntype Shape = Circle Int | Dot\n\narea : Shape -> Int\narea s =\n    case s of\n        Circle r -> r\n        Dot -> 0\n\nmain : Int\nmain = area (Circle 2)\n";
        let user = ModuleOrigin::User;
        let texts = rename_texts(&[("Main", src, user)], "Main", "Circle", 0, "Disc")
            .expect("a constructor rename is applied");
        assert_eq!(
            texts.get("Main").map(String::as_str),
            Some(
                "module Main exposing (main)\n\ntype Shape = Disc Int | Dot\n\narea : Shape -> Int\narea s =\n    case s of\n        Disc r -> r\n        Dot -> 0\n\nmain : Int\nmain = area (Disc 2)\n"
            )
        );
    }

    #[test]
    fn a_name_an_interpolation_mentions_is_refused() {
        let src = "module Main exposing (main)\n\ngreet : String -> String\ngreet name =\n    \"\"\"hi {{name}}\"\"\"\n\nmain : String\nmain = greet \"x\"\n";
        let user = ModuleOrigin::User;
        assert!(rename_texts(&[("Main", src, user)], "Main", "name", 0, "who").is_none());
    }

    #[test]
    fn a_record_pattern_field_binder_is_refused() {
        let src = "module Main exposing (main)\n\nwidth : { w : Int } -> Int\nwidth r =\n    case r of\n        { w } -> w\n\nmain : Int\nmain = width { w = 1 }\n";
        let user = ModuleOrigin::User;
        assert!(rename_texts(&[("Main", src, user)], "Main", "w\n\nmain", 0, "x").is_none());
        assert!(rename_texts(&[("Main", src, user)], "Main", "w }", 0, "x").is_none());
    }

    #[test]
    fn a_rename_onto_a_top_level_name_is_refused() {
        let src = "module Main exposing (main)\n\none : Int\none = 1\n\ntwo : Int\ntwo = 2\n\nmain : Int\nmain = one + two\n";
        let user = ModuleOrigin::User;
        assert!(rename_texts(&[("Main", src, user)], "Main", "one + two", 0, "two").is_none());
    }

    #[test]
    fn a_name_declared_outside_the_project_is_not_renameable() {
        let lib = "module Lib exposing (helper)\n\nhelper : Int\nhelper = 2\n";
        let main = "module Main exposing (main)\n\nimport Lib\n\nmain : Int\nmain = Lib.helper\n";
        let sources = [
            ("Lib", lib, ModuleOrigin::EmbeddedStdlib),
            ("Main", main, ModuleOrigin::User),
        ];
        assert!(rename_texts(&sources, "Main", "helper", 0, "aid").is_none());
    }

    #[test]
    fn an_exposing_list_in_a_module_with_no_uri_refuses_the_rename() {
        let lib = "module Lib exposing (helper)\n\nhelper : Int\nhelper = 2\n";
        let other =
            "module Other exposing (one)\n\nimport Lib exposing (helper)\n\none : Int\none = 1\n";
        let main = "module Main exposing (main)\n\nimport Lib\nimport Other\n\nmain : Int\nmain = Lib.helper + Other.one\n";
        let user = ModuleOrigin::User;
        let sources = [
            ("Lib", lib, user),
            ("Other", other, user),
            ("Main", main, user),
        ];
        let served = rename_texts(&sources, "Main", "helper", 0, "aid")
            .expect("with every URI served the rename is applied");
        assert_eq!(
            served.get("Other").map(String::as_str),
            Some(
                "module Other exposing (one)\n\nimport Lib exposing (aid)\n\none : Int\none = 1\n"
            )
        );
        assert!(
            rename_texts_without_uri(&sources, "Main", "helper", 0, "aid", &["Other"]).is_none()
        );
    }

    #[test]
    fn a_project_module_outside_the_import_graph_is_renamed_too() {
        let lib = "module Lib exposing (helper)\n\nhelper : Int\nhelper = 2\n";
        let main = "module Main exposing (main)\n\nimport Lib\n\nmain : Int\nmain = Lib.helper\n";
        let orphan =
            "module Orphan exposing (twice)\n\nimport Lib\n\ntwice : Int\ntwice = Lib.helper * 2\n";
        let user = ModuleOrigin::User;
        let sources = [
            ("Lib", lib, user),
            ("Main", main, user),
            ("Orphan", orphan, user),
        ];
        let renamed = rename_texts(&sources, "Main", "helper", 0, "aid")
            .expect("a use in an unimported project module is renamed, not refused");
        assert_eq!(
            renamed.get("Orphan").map(String::as_str),
            Some(
                "module Orphan exposing (twice)\n\nimport Lib\n\ntwice : Int\ntwice = Lib.aid * 2\n"
            )
        );
    }

    #[test]
    fn a_lambda_binder_spelling_the_new_name_refuses_a_local_rename() {
        let src = "module Main exposing (main)\n\nbump : Int -> Int\nbump n =\n    (\\x -> n + 1) 0\n\nmain : Int\nmain = bump 1\n";
        let user = ModuleOrigin::User;
        assert!(rename_texts(&[("Main", src, user)], "Main", "n + 1", 0, "y").is_some());
        assert!(rename_texts(&[("Main", src, user)], "Main", "n + 1", 0, "x").is_none());
    }

    #[test]
    fn a_recorded_site_whose_token_cannot_be_isolated_refuses_every_edit() {
        let db = IpeDatabase::new();
        let text = "module Main exposing (main)\n\nmain : Int\nmain = helper 1\n";
        let main = file(&db, &["Main"], text);
        let root = root_of(&db, &[(&["Main"], main)]);
        let site = |needle: &str| {
            let lo = u32::try_from(text.find(needle)?).ok()?;
            let hi = lo.checked_add(u32::try_from(needle.len()).ok()?)?;
            Some(crate::navigation::NameRef {
                module: vec!["Main".to_owned()],
                span: ipe_diagnostics::Span::new(lo, hi),
            })
        };
        let token = site("helper").expect("fixture spells the name");
        let wide = site("helper 1").expect("fixture spells the call");
        assert!(super::narrowed_sites(&db, root, vec![token.clone()], "helper").is_some());
        assert!(super::narrowed_sites(&db, root, vec![token, wide], "helper").is_none());
    }
}
