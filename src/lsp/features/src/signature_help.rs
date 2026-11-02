//! Signature help: `textDocument/signatureHelp`.
//!
//! When the cursor is inside a function-call argument list, returns the
//! callee's type signature and highlights the active parameter.
//!
//! **Algorithm:**
//! 1. Walk the canonical AST for the innermost `Call(f, args)` containing
//!    `byte` — any callee kind (`VarTopLevel`, `VarLocal`, `VarCtor`,
//!    `VarKernel`, lambda).
//! 2. Look up the callee's solved type in the per-module region map by the
//!    callee expression's source span. This covers all callee forms without
//!    per-variant env-key logic.
//! 3. Decompose the type into parameter types (one per `->` arrow).
//! 4. Count fully-typed arguments before `byte` to pick the active parameter.
//!
//! Returns `None` when the cursor is not inside a call, the program does not
//! type-check, or the callee is not a function type.

use ipe_canon::ast::{Def, Expr_};
use ipe_db::{Db as _, IpeDatabase, SourceRoot};
use ipe_diagnostics::{Located, Span};
use ipe_intern::Symbol;
use ipe_types::{Ty, VarNamer, ty_to_doc};
use lsp_types::{ParameterInformation, ParameterLabel, SignatureHelp, SignatureInformation};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Signature help at `byte` in `module`. Returns `None` when the position is
/// not inside a function-call or the type environment cannot answer.
///
/// Resolves the callee's type from the per-module region map, which covers
/// all callee forms: top-level bindings, local variables, constructors,
/// qualified references, and kernel calls. The region map holds the solved
/// type of every sub-expression span, so `regions[callee_span]` is the
/// function type regardless of how the callee was written.
#[must_use]
pub fn signature_help(
    db: &IpeDatabase,
    root: SourceRoot,
    entry: ipe_db::SourceFile,
    module: &[String],
    byte: u32,
    docs: Option<&ipe_docs::Index>,
) -> Option<SignatureHelp> {
    let files = root.files(db);
    let &file = files.get(module)?;
    let canonical = crate::db_access::canonicalize_checked(db, root, entry, file)?;
    let types = ipe_db::typecheck_module(db, root, entry, file)
        .as_ref()
        .ok()?;

    // Find the innermost Call(…, …) containing `byte` — any callee kind.
    let (callee_span, callee_name_sym, active_param) = find_call_at(&canonical.module, byte)?;

    // Resolve the callee's function type from the region map. This covers every
    // callee form (VarTopLevel, VarLocal, VarCtor, VarQual, VarKernel) without
    // per-variant env-key logic: the region map holds the solved type of each
    // callee sub-expression by its source span.
    let callee_ty = types.regions.get(&callee_span)?.clone();

    // Decompose into parameter types.
    let params = fn_params(&callee_ty);
    if params.is_empty() {
        return None;
    }

    // Resolve the callee's documentation from the `ipe_docs` index, keyed on
    // its home + name. `resolve_name_at` locks the interner internally, so it
    // runs before the explicit lock below. A local, lambda, or undocumented
    // callee resolves nothing — the signature then carries no doc (fail-closed).
    let signature_doc: Option<String> = docs.and_then(|index| {
        let resolved = crate::navigation::resolve_name_at(db, root, entry, module, callee_span.lo)?;
        let crate::navigation::NameTarget::Declared { module, name } = resolved.target else {
            return None;
        };
        crate::docs_lookup::symbol_doc(index, &module, &name)
    });

    // Render signature and parameters.
    let interner = db.interner().lock();
    let callee_name = callee_name_sym
        .and_then(|s| interner.resolve(s))
        .unwrap_or("?");
    let mut namer = VarNamer::new();
    let sig_doc = ty_to_doc(&callee_ty, &interner, &mut namer).ok()?;
    let sig_label = format!("{callee_name} : {}", ipe_diagnostics::render_ty(&sig_doc));

    let mut param_infos: Vec<ParameterInformation> = Vec::with_capacity(params.len());
    for param_ty in &params {
        let doc = ty_to_doc(param_ty, &interner, &mut namer).ok()?;
        param_infos.push(ParameterInformation {
            label: ParameterLabel::Simple(ipe_diagnostics::render_ty(&doc)),
            documentation: None,
        });
    }
    drop(interner);

    // Clamp to the last parameter index, then narrow to u32 (LSP's wire type);
    // a signature never has u32::MAX parameters, so the saturating fallback is
    // unreachable in practice but keeps the conversion total.
    let last_param = param_infos.len().saturating_sub(1);
    let active = u32::try_from(active_param.min(last_param)).unwrap_or(u32::MAX);

    Some(SignatureHelp {
        signatures: vec![SignatureInformation {
            label: sig_label,
            documentation: signature_doc.map(|text| {
                lsp_types::Documentation::MarkupContent(lsp_types::MarkupContent {
                    kind: lsp_types::MarkupKind::Markdown,
                    value: text,
                })
            }),
            parameters: Some(param_infos),
            active_parameter: Some(active),
        }],
        active_signature: Some(0),
        active_parameter: Some(active),
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Decompose a function type into parameter types (the left side of each
/// `->` arrow). Returns an empty list for non-function types.
fn fn_params(ty: &Ty) -> Vec<Ty> {
    let mut params = Vec::new();
    let mut cur = ty;
    while let Ty::Fun(param, ret) = cur {
        params.push(*param.clone());
        cur = ret;
    }
    params
}

/// One candidate call: its span width, callee span, callee name, and active
/// argument index.
type CallHit = (u32, Span, Option<Symbol>, usize);

/// Walk the canonical module's defs looking for the innermost `Call(f, args)`
/// node whose span contains `byte`, for ANY callee kind.
///
/// Returns `(callee_span, Option<name_symbol>, active_arg_index)`.
/// `callee_span` is the source span of the callee sub-expression, keyed in
/// the region map. `name_symbol` is the bare name when statically known
/// (for the signature label), `None` for lambda or complex callee expressions.
fn find_call_at(
    module: &ipe_canon::ast::Module,
    byte: u32,
) -> Option<(Span, Option<Symbol>, usize)> {
    let mut best: Option<CallHit> = None;

    for def in &module.defs {
        let body = match def {
            Def::Untyped { body, .. } | Def::Typed { body, .. } => body,
        };
        walk_call(body, byte, &mut best);
    }

    best.map(|(_, callee_span, name_sym, active)| (callee_span, name_sym, active))
}

/// Extract the bare name symbol from a callee expression, when statically
/// available. Used only for the human-readable signature label.
const fn callee_name(f: &Located<Expr_>) -> Option<Symbol> {
    match &f.value {
        Expr_::VarTopLevel { name, .. }
        | Expr_::VarLocal(name)
        | Expr_::VarCtor { name, .. }
        | Expr_::VarKernel { name, .. } => Some(*name),
        _ => None,
    }
}

/// Visit every call in `expr`, keeping the innermost one containing `byte`.
///
/// The walk never prunes on a node's span: a desugar (a `do` block's chain of
/// binds) builds nodes whose spans do not nest inside their parent's, so a
/// pruning walk would skip calls the cursor is on. Every variant is named, so
/// a new expression form cannot be silently skipped.
fn walk_call(expr: &Located<Expr_>, byte: u32, best: &mut Option<CallHit>) {
    match &expr.value {
        Expr_::Call(f, args) => {
            if expr.span.lo <= byte && byte < expr.span.hi {
                let active = args.iter().take_while(|a| a.span.hi <= byte).count();
                let width = expr.span.hi.saturating_sub(expr.span.lo);
                if best.as_ref().is_none_or(|&(w, _, _, _)| width < w) {
                    *best = Some((width, f.span, callee_name(f), active));
                }
            }
            walk_call(f, byte, best);
            for arg in args {
                walk_call(arg, byte, best);
            }
        }
        Expr_::ForeignCall { args, .. } | Expr_::Tuple(args) | Expr_::List(args) => {
            for arg in args {
                walk_call(arg, byte, best);
            }
        }
        Expr_::Lambda(_, body) | Expr_::Access(body, _) => walk_call(body, byte, best),
        Expr_::Let(bindings, body) => {
            for b in bindings {
                walk_call(&b.body, byte, best);
            }
            walk_call(body, byte, best);
        }
        Expr_::Case(scrutinee, branches) => {
            walk_call(scrutinee, byte, best);
            for branch in branches {
                walk_call(&branch.body, byte, best);
            }
        }
        Expr_::Binop { lhs, rhs, .. } | Expr_::Cons(lhs, rhs) => {
            walk_call(lhs, byte, best);
            walk_call(rhs, byte, best);
        }
        Expr_::If(branches, else_expr) => {
            for (cond, then_) in branches {
                walk_call(cond, byte, best);
                walk_call(then_, byte, best);
            }
            walk_call(else_expr, byte, best);
        }
        Expr_::Record(fields) => {
            for (_, v) in fields {
                walk_call(v, byte, best);
            }
        }
        Expr_::Update(base, fields) => {
            walk_call(base, byte, best);
            for (_, v) in fields {
                walk_call(v, byte, best);
            }
        }
        Expr_::VarLocal(_)
        | Expr_::VarTopLevel { .. }
        | Expr_::VarKernel { .. }
        | Expr_::VarCtor { .. }
        | Expr_::Int(_)
        | Expr_::Float(_)
        | Expr_::Str(_)
        | Expr_::Char(_)
        | Expr_::CustomElementCtor(_)
        | Expr_::Unit => {}
    }
}

#[cfg(test)]
mod tests {
    use ipe_db::{IpeDatabase, ModuleOrigin, SourceFile, SourceRoot};

    use super::signature_help;

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

    const HELPER: &str =
        "module Helper exposing (add)\n\nadd : Int -> Int -> Int\nadd x y =\n    x + y\n";
    const MAIN: &str = "module Main exposing (main)\n\nimport Helper exposing (add)\n\nmain : Int\nmain =\n    add 1 2\n";

    /// Byte offset of `1` in the `add 1 2` call.
    fn call_arg_byte() -> u32 {
        u32::try_from(MAIN.rfind(" 1 ").expect("` 1 ` in main") + 1).expect("u32")
    }

    /// Outside a call site, `signature_help` must return `None` (not panic).
    #[test]
    fn signature_help_outside_call_returns_none() {
        let db = IpeDatabase::new();
        let helper = file(&db, &["Helper"], HELPER);
        let entry = file(&db, &["Main"], MAIN);
        let root = root_of(&db, &[(&["Helper"], helper), (&["Main"], entry)]);
        // Byte 0 is the `m` in `module` — not a call site.
        let result = signature_help(&db, root, entry, &["Main".to_owned()], 0, None);
        assert!(
            result.is_none(),
            "byte 0 is not inside a call; expected None, got {result:?}"
        );
    }

    /// Inside the `add 1 2` call, `signature_help` must return `Some` with the
    /// `add` signature and 2 parameters.
    #[test]
    fn signature_help_resolves_top_level_call() {
        let db = IpeDatabase::new();
        let helper = file(&db, &["Helper"], HELPER);
        let entry = file(&db, &["Main"], MAIN);
        let root = root_of(&db, &[(&["Helper"], helper), (&["Main"], entry)]);
        let result = signature_help(
            &db,
            root,
            entry,
            &["Main".to_owned()],
            call_arg_byte(),
            None,
        );
        let help = result.expect("cursor inside `add 1 2` must yield Some");
        let sig = help.signatures.first().expect("at least one signature");
        assert!(
            sig.label.contains("add"),
            "signature label must mention `add`: {}",
            sig.label
        );
        let params = sig.parameters.as_ref().expect("parameters present");
        assert_eq!(params.len(), 2, "add : Int -> Int -> Int has 2 parameters");
        // Cursor is on the first argument → active parameter 0.
        assert_eq!(
            help.active_parameter,
            Some(0),
            "active parameter must be 0 at the first arg"
        );
    }

    /// A local-var call: `apply f x = f x`. The cursor inside `f x` must resolve
    /// the signature of the local `f` parameter via the region map.
    #[test]
    fn signature_help_resolves_local_var_call() {
        // `apply` takes a function and an Int, applies the function.
        const SRC: &str = "module Main exposing (main)\n\napply : (Int -> Int) -> Int -> Int\napply f x =\n    f x\n\nmain : Int\nmain =\n    apply (\\n -> n) 0\n";
        let db = IpeDatabase::new();
        let entry = file(&db, &["Main"], SRC);
        let root = root_of(&db, &[(&["Main"], entry)]);
        // Byte offset of `x` in `f x` (the argument to the local-var call).
        let byte =
            u32::try_from(SRC.find("    f x").expect("`    f x` in apply body") + "    f ".len())
                .expect("u32");
        let result = signature_help(&db, root, entry, &["Main".to_owned()], byte, None);
        let help = result.expect("cursor inside local-var call `f x` must yield Some");
        let sig = help.signatures.first().expect("signature present");
        // The resolved type of `f` is `Int -> Int` — 1 parameter.
        let params = sig.parameters.as_ref().expect("parameters present");
        assert_eq!(
            params.len(),
            1,
            "local `f : Int -> Int` has 1 parameter; got {params:?}"
        );
    }
}
