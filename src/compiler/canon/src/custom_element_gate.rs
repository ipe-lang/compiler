//! Widget-file collection for the `CustomElement.fromFile "<js-path>"` constructor.
//!
//! The constructor's shape gate (single string literal) and its path seal (an
//! all-targets clean + traversal check, reusing `ipe_path_core`) run in canon,
//! where they are pure. The remaining check — that the named JS file actually EXISTS
//! inside the project root — needs the filesystem and the project root, which the
//! salsa canon queries deliberately do not touch (a query keyed on source text
//! must stay a pure function of that text). So this module only COLLECTS the
//! cleaned path of every constructor in a linked program, each with its span; the
//! build stage that owns the project root turns a missing file into the
//! fail-closed IPE-N0044 (Security #5: a widget cannot register against a file
//! that is not there).
//!
//! The same walk judges placement: a program that links no `web` runtime
//! refuses every constructor it links with IPE-L0147
//! ([`check_widget_placement`]). The judged set is the one
//! [`collect_widget_files`] returns, the pre-elimination linked set, because
//! the build ships a registration for every linked constructor whether or not
//! the entry reaches it. The `web` runtime fact is the lowered program's own
//! (the one the backend reads), never the entry's shape: a script that mounts a
//! `Web.embed` app serves a browser page too.
//!
//! By construction a `CustomElementCtor` node appears only as the whole body of a
//! `CustomElement`-annotated binding (`resolve::detect_custom_element_constructor`
//! is the sole mint site), but this walk is exhaustive over the expression tree
//! anyway — defence in depth, so a future node placement cannot slip past the
//! existence check.

use ipe_diagnostics::{DResult, Diagnostic, LowerError, NonWebShape, Span};

use crate::ast::{CaseBranch, Def, Expr, Expr_, LetBinding, Module};
use crate::shape_runtime::Shape;

/// One `CustomElement.fromFile "<js-path>"` constructor reached in a linked program: its
/// CLEANED, in-project-checked relative path and the span to blame if the file
/// is absent.
#[derive(Clone, Debug)]
pub struct WidgetFile {
    /// The cleaned relative path the constructor named, ready to resolve against
    /// the project root.
    pub cleaned_path: String,
    /// The constructor's source span, for the missing-file diagnostic.
    pub span: Span,
}

/// Every `CustomElement.fromFile` constructor reached in `module`, each carrying the
/// cleaned path and its span. Empty when the program uses no widget.
#[must_use]
pub fn collect_widget_files(module: &Module) -> Vec<WidgetFile> {
    let mut out = Vec::new();
    for def in &module.defs {
        match def {
            Def::Untyped { body, .. } | Def::Typed { body, .. } => walk(body, &mut out),
        }
    }
    out
}

/// Whether the lowered program links the `web` runtime module, the one that
/// serves a custom element's JS.
///
/// Read off the lowered program's own per-module web fact, so the gate and the
/// backend that picks the runtime features judge the same thing.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WebRuntime {
    /// Some lowered module reaches a `web` kernel (`Web.tea`, `Web.embed`, ...).
    Linked,
    /// No lowered module reaches a `web` kernel.
    Absent,
}

/// Refuse every `CustomElement.fromFile` constructor in `linked` when the
/// program links no `web` runtime.
///
/// A `CustomElement.node` needs a handle and `fromFile` is the only way to make
/// one, so refusing every constructor also refuses every mount. The first
/// constructor in source order is the one reported, naming the entry's shape.
///
/// # Errors
/// IPE-L0147 at the first constructor's span when `web` is
/// [`WebRuntime::Absent`] and the entry is not [`Shape::Web`];
/// [`Diagnostic::CompilerBug`] when a [`Shape::Web`] entry links no `web`
/// runtime yet holds a constructor, since every Web entry kernel is a `web`
/// kernel.
pub fn check_widget_placement(linked: &Module, entry_shape: Shape, web: WebRuntime) -> DResult<()> {
    match web {
        WebRuntime::Linked => return Ok(()),
        WebRuntime::Absent => {}
    }
    let Some(widget) = collect_widget_files(linked)
        .into_iter()
        .min_by_key(|widget| (widget.span.lo, widget.span.hi))
    else {
        return Ok(());
    };
    match non_web_shape(entry_shape) {
        Some(shape) => Err(Diagnostic::Lower {
            span: widget.span,
            msg: LowerError::UiWidgetInNonWebShape { shape },
        }),
        None => Err(Diagnostic::CompilerBug {
            where_: "ipe_canon::custom_element_gate::check_widget_placement",
            detail: "a `Web.tea` entry lowered to a program that links no `web` runtime".to_owned(),
        }),
    }
}

/// The browser-less shape `shape` names, or `None` for the Web shape.
const fn non_web_shape(shape: Shape) -> Option<NonWebShape> {
    match shape {
        Shape::Script => Some(NonWebShape::Script),
        Shape::Tui => Some(NonWebShape::Tui),
        Shape::Cli => Some(NonWebShape::Cli),
        Shape::Worker => Some(NonWebShape::Worker),
        Shape::Web => None,
    }
}

fn walk(e: &Expr, out: &mut Vec<WidgetFile>) {
    match &e.value {
        Expr_::CustomElementCtor(path) => out.push(WidgetFile {
            cleaned_path: path.clone(),
            span: e.span,
        }),
        Expr_::Call(f, args) => {
            walk(f, out);
            for a in args {
                walk(a, out);
            }
        }
        Expr_::ForeignCall { args, .. } => {
            for a in args {
                walk(a, out);
            }
        }
        Expr_::Case(scrut, branches) => {
            walk(scrut, out);
            for CaseBranch { body, .. } in branches {
                walk(body, out);
            }
        }
        Expr_::Lambda(_, body) => walk(body, out),
        Expr_::Let(bindings, body) => {
            for LetBinding { body: b, .. } in bindings {
                walk(b, out);
            }
            walk(body, out);
        }
        Expr_::If(branches, els) => {
            for (cond, then) in branches {
                walk(cond, out);
                walk(then, out);
            }
            walk(els, out);
        }
        Expr_::Binop { lhs, rhs, .. } => {
            walk(lhs, out);
            walk(rhs, out);
        }
        Expr_::Record(fields) => {
            for (_, v) in fields {
                walk(v, out);
            }
        }
        Expr_::Update(base, fields) => {
            walk(base, out);
            for (_, v) in fields {
                walk(v, out);
            }
        }
        Expr_::Access(base, _) => walk(base, out),
        Expr_::Cons(head, tail) => {
            walk(head, out);
            walk(tail, out);
        }
        Expr_::Tuple(elems) | Expr_::List(elems) => {
            for el in elems {
                walk(el, out);
            }
        }
        // Leaves that carry no sub-expression.
        Expr_::VarLocal(_)
        | Expr_::VarTopLevel { .. }
        | Expr_::VarKernel { .. }
        | Expr_::VarCtor { .. }
        | Expr_::Int(_)
        | Expr_::Float(_)
        | Expr_::Str(_)
        | Expr_::Char(_)
        | Expr_::Unit => {}
    }
}
