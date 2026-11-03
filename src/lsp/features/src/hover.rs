//! Hover: the solved type of the innermost expression at a position.
//!
//! Reads `typecheck`'s home-keyed region map — the exact types
//! type-directed lowering consumes — so the hover can never disagree with
//! the compiler. On a program that does not type-check (or a position on no
//! expression) the answer is `None`, never a guess.

use ipe_db::{Db as _, IpeDatabase, SourceRoot};
use ipe_diagnostics::Span;

/// A successful hover: the rendered type plus the region it belongs to.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HoverInfo {
    /// The type in Ipê surface syntax (e.g. `List (Maybe Int)`).
    pub ty: String,
    /// The source region carrying that type (byte offsets into the module).
    pub span: Span,
    /// When the hover is on this module's `main`, its compiler-derived control
    /// model word (`tea` / `server` / `direct`) — the SAME projection `ipe audit`
    /// and `ipe doc` disclose, read from [`ipe_canon::shape_source`], never a
    /// second derivation. `None` on any other hover target.
    pub control_model: Option<&'static str>,
    /// The `{-| … -}` doc-string attached to the top-level binding whose solved
    /// region the cursor is inside, if any. `None` when the hovered region does
    /// not belong to a documented binding (e.g. a sub-expression inside an
    /// unannotated lambda), or when the binding has no doc-string.
    pub doc: Option<String>,
}

/// The type of the innermost solved region containing `byte` in `module_file`.
///
/// Reads the per-module `typecheck_module` projection — its `regions` map holds
/// only this module's home-scoped regions, so the lookup needs no home
/// comparison and the handler is unchanged the day the underlying solve becomes
/// genuinely per-module.
#[must_use]
pub fn hover(
    db: &IpeDatabase,
    root: SourceRoot,
    entry: ipe_db::SourceFile,
    module_file: ipe_db::SourceFile,
    module: &[String],
    byte: u32,
    docs: Option<&ipe_docs::Index>,
) -> Option<HoverInfo> {
    let types = crate::db_access::module_types(db, root, entry, module_file)?;
    // Innermost wins: narrowest containing span, latest start as tiebreaker.
    let mut best: Option<(u32, u32)> = None; // (width, lo)
    for span in types.regions.keys() {
        if span.lo <= byte && byte < span.hi {
            let width = span.hi.saturating_sub(span.lo);
            if best.is_none_or(|(best_width, best_lo)| {
                width < best_width || (width == best_width && span.lo > best_lo)
            }) {
                best = Some((width, span.lo));
            }
        }
    }
    let (width, lo) = best?;
    let span = Span::new(lo, lo.saturating_add(width));
    // `parse` and `control_model_at` both acquire the interner lock internally.
    // Call them before the explicit lock below so we never hold nested locks.
    let parsed = ipe_db::parse(db, module_file).clone().ok();
    let control_model = control_model_at(db, module_file, byte);
    // Find the doc-string of the top-level binding whose body span contains
    // `byte`. The parsed `Value` carries the `{-| … -}` doc-string; the hover
    // surfaces it so editors can show it alongside the type.
    let doc: Option<String> = parsed.as_ref().and_then(|m| {
        m.values
            .iter()
            .find(|v| {
                let lo = v.value.name.span.lo;
                let hi = v.value.body.span.hi.max(v.value.name.span.hi);
                lo <= byte && byte < hi
            })
            .and_then(|v| v.value.doc.as_ref())
            .map(|ds| ds.body.trim().to_owned())
    });
    // When the hovered binding carries no `{-| … -}` doc of its own, fall back
    // to the `ipe_docs` index: resolve the identifier under the cursor to its
    // declaration and surface the stdlib symbol's or module's real doc. This
    // never overrides a binding's own doc, and an identifier that resolves to
    // no documented entry (a user binding, a local binder) yields nothing —
    // fail-closed. `resolve_name_at` acquires the interner internally, so it is
    // called before the explicit lock below.
    let doc = doc.or_else(|| {
        let index = docs?;
        let resolved = crate::navigation::resolve_name_at(db, root, entry, module, byte)?;
        let crate::navigation::NameTarget::Declared { module, name } = resolved.target else {
            return None;
        };
        crate::docs_lookup::symbol_doc(index, &module, &name)
            .or_else(|| crate::docs_lookup::module_doc(index, &module))
    });
    let interner = db.interner().lock();
    let mut namer = ipe_types::VarNamer::new();
    let ty_doc = types
        .regions
        .get(&span)
        .and_then(|ty| ipe_types::ty_to_doc(ty, &interner, &mut namer).ok());
    drop(interner);
    Some(HoverInfo {
        ty: ipe_diagnostics::render_ty(&ty_doc?),
        span,
        control_model,
        doc,
    })
}

/// The control-model word to disclose when the cursor is anywhere in this
/// module's `main` binding, or `None` otherwise.
///
/// Reuses [`ipe_canon::shape_source::classify_main_shape`] and its
/// [`ipe_canon::shape_source::ControlModel`] projection — the SAME single source
/// of truth `ipe audit` and `ipe doc` read — so the hover can never disclose a
/// model that disagrees with the compiler's own classification. A module with no
/// `main`, or a cursor outside the `main` binding, discloses nothing.
///
/// The gate is the whole `main` binding span (name through body) rather than the
/// name alone: the type-solved regions a hover fires on are body expression
/// spans, so gating on the binding is what lets the disclosure ride the hover a
/// user actually triggers on `main`.
fn control_model_at(
    db: &IpeDatabase,
    module_file: ipe_db::SourceFile,
    byte: u32,
) -> Option<&'static str> {
    let module = ipe_db::parse(db, module_file).as_ref().ok()?;
    let interner = db.interner().lock();
    let main_sym = interner.lookup("main")?;
    let main = module
        .values
        .iter()
        .find(|v| v.value.name.value == main_sym)?;
    // The binding's full extent: its name through its body. Gating on this — not
    // the name token alone — is what lets the disclosure ride the type-solved body
    // region a user's hover on `main` actually fires on.
    let lo = main.value.name.span.lo;
    let hi = main.value.body.span.hi.max(main.value.name.span.hi);
    let shape = ipe_canon::shape_source::classify_main_shape(module, &interner);
    // Every interner use is done; release the lock before the byte-gate and the
    // lock-free control-model projection.
    drop(interner);
    // The disclosure is a `main`-only fact: a cursor outside the `main` binding
    // discloses nothing.
    if !(lo <= byte && byte < hi) {
        return None;
    }
    Some(ipe_canon::shape_source::ControlModel::from_shape(shape).word())
}

#[cfg(test)]
mod tests {
    use ipe_db::{IpeDatabase, ModuleOrigin, SourceFile, SourceRoot};

    use super::hover;

    fn file(db: &IpeDatabase, path: &[&str], text: &str) -> SourceFile {
        ipe_db::SourceFile::new(
            db,
            path.iter().map(|s| (*s).to_owned()).collect(),
            text.to_owned(),
            ModuleOrigin::User,
        )
    }

    fn root_of(db: &IpeDatabase, files: &[(&[&str], SourceFile)]) -> SourceRoot {
        ipe_db::SourceRoot::new(
            db,
            files
                .iter()
                .map(|(path, f)| (path.iter().map(|s| (*s).to_owned()).collect(), *f))
                .collect(),
        )
    }

    /// A doc-commented binding must surface its doc-string in `HoverInfo.doc`.
    #[test]
    fn hover_surfaces_doc_comment() {
        const SRC: &str = "\
module Main exposing (main)\n\
\n\
{-| The answer to everything. -}\n\
main : Int\n\
main =\n\
    42\n";
        let db = IpeDatabase::new();
        let entry = file(&db, &["Main"], SRC);
        let root = root_of(&db, &[(&["Main"], entry)]);
        // Byte offset of `42` (inside the `main` body).
        let byte = u32::try_from(SRC.find("42").expect("`42` in source")).expect("u32");
        let info = hover(&db, root, entry, entry, &["Main".to_owned()], byte, None)
            .expect("hover on `42` in a typed binding must return Some");
        assert_eq!(
            info.ty, "Int",
            "type of `42` must be `Int`, got: {}",
            info.ty
        );
        let doc = info
            .doc
            .expect("a doc-commented binding must surface its doc");
        assert!(
            doc.contains("answer"),
            "doc must contain the comment text; got: {doc:?}"
        );
    }

    /// An undocumented binding must yield `doc: None`.
    #[test]
    fn hover_no_doc_when_no_comment() {
        const SRC: &str = "module Main exposing (main)\n\nmain : Int\nmain =\n    42\n";
        let db = IpeDatabase::new();
        let entry = file(&db, &["Main"], SRC);
        let root = root_of(&db, &[(&["Main"], entry)]);
        let byte = u32::try_from(SRC.find("42").expect("`42`")).expect("u32");
        let info = hover(&db, root, entry, entry, &["Main".to_owned()], byte, None)
            .expect("hover on `42` must return Some");
        assert!(
            info.doc.is_none(),
            "binding without doc-comment must yield doc: None; got: {:?}",
            info.doc
        );
    }
}
