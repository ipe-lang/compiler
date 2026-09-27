//! `prefer-pipeline` — a deeply nested call chain that reads outside-in,
//! offered as a left-to-right `|>` pipeline or a paren-free `<|` chain.
//!
//! `max 0 (min a (model.length + 1))` threads one value through two calls but
//! buries it under two paren levels. Either direction removes the nesting and is
//! equally idiomatic:
//!
//! - `model.length + 1 |> min a |> max 0` reads in evaluation order;
//! - `max 0 <| min a <| model.length + 1` keeps the outside-in order, paren-free.
//!
//! `x |> f` and `f <| x` both desugar to exactly `f x`, so either rewrite is
//! provably equivalent. The rule fires only when the rewrite removes at least
//! [`MIN_PAREN_LEVELS`] paren levels: `f (g x)` and
//! `List.map fmt (List.filter live xs)` read fine as-is and are left alone.
//!
//! The matcher reasons on node kind and span structure, never on text: only a
//! source application (see [`is_source_call`]) forms a chain link, so the
//! `Task.andThen` node a `do`-block `x <- task` bind desugars into is never
//! mistaken for a nested call. Rewrites slice the author's own source spans
//! verbatim. `--fix` applies the `|>` form (one deterministic choice); the help
//! lists both forms as equal alternatives.

use ipe_diagnostics::Span;
use ipe_syntax::{Expr, Expr_};

use crate::finding::{Finding, Fix};
use crate::rules::{Ctx, is_source_call};

/// Fewest paren levels a rewrite must remove before the rule fires.
const MIN_PAREN_LEVELS: usize = 2;

pub fn check(ctx: &Ctx) -> Vec<Finding> {
    let mut findings = Vec::new();
    for value in &ctx.ast.values {
        walk(ctx, &value.value.body, &mut findings, false);
    }
    findings
}

/// Walk every sub-expression, testing each for a qualifying call chain.
///
/// `in_binop_operand` is `true` when `expr` sits as a direct operand of a
/// `Binops` node: `|>`/`<|` (precedence 0) bind looser than every binary
/// operator there, so an unparenthesised replacement must gain parens.
fn walk(ctx: &Ctx, expr: &Expr, out: &mut Vec<Finding>, in_binop_operand: bool) {
    if let Some(chain) = Chain::of(expr)
        && let Some(finding) = chain.finding(ctx, expr, in_binop_operand)
    {
        out.push(finding);
        // The chain links are covered by this one rewrite; only their
        // leading arguments and the subject can hold further nests.
        for link in &chain.links {
            walk(ctx, link.callee, out, false);
            for arg in link.leading {
                walk(ctx, arg, out, false);
            }
        }
        walk(ctx, chain.subject, out, false);
        return;
    }
    match &expr.value {
        Expr_::Call(callee, args) => {
            walk(ctx, callee, out, false);
            for arg in args {
                walk(ctx, arg, out, false);
            }
        }
        Expr_::Case(scrut, arms) => {
            walk(ctx, scrut, out, false);
            for (_pat, body) in arms {
                walk(ctx, body, out, false);
            }
        }
        Expr_::Lambda(_p, body) => walk(ctx, body, out, false),
        Expr_::Binops(pairs, last) => {
            for (operand, _op) in pairs {
                walk(ctx, operand, out, true);
            }
            walk(ctx, last, out, true);
        }
        Expr_::Let(bindings, body) => {
            for binding in bindings {
                walk(ctx, &binding.body, out, false);
            }
            walk(ctx, body, out, false);
        }
        Expr_::If(branches, otherwise) => {
            for (cond, body) in branches {
                walk(ctx, cond, out, false);
                walk(ctx, body, out, false);
            }
            walk(ctx, otherwise, out, false);
        }
        Expr_::Tuple(items) | Expr_::List(items) => {
            for item in items {
                walk(ctx, item, out, false);
            }
        }
        Expr_::Record(fields) | Expr_::Update(_, fields) => {
            for (_name, value) in fields {
                walk(ctx, value, out, false);
            }
        }
        Expr_::Access(base, _field) => walk(ctx, base, out, false),
        Expr_::VarLocal(_)
        | Expr_::VarQual(_, _)
        | Expr_::Int(_)
        | Expr_::Float(_)
        | Expr_::Str(_)
        | Expr_::MultilineStr { .. }
        | Expr_::Char(_)
        | Expr_::PathLit(_)
        | Expr_::Unit => {}
    }
}

/// One source application in a chain: its callee and every argument but the
/// threaded last one.
struct Link<'a> {
    callee: &'a Expr,
    leading: &'a [Expr],
}

/// A maximal run of source applications, each threading the next as its last
/// argument, outermost first, ending at a non-call `subject`.
struct Chain<'a> {
    links: Vec<Link<'a>>,
    subject: &'a Expr,
    /// The outermost call's own text: callee through last argument, excluding
    /// any parens around the call itself.
    text: Span,
}

impl<'a> Chain<'a> {
    /// The chain rooted at `expr`, or `None` when `expr` is not a source call.
    fn of(expr: &'a Expr) -> Option<Self> {
        let mut links = Vec::new();
        let mut text = None;
        let mut cur = expr;
        while let Expr_::Call(callee, args) = &cur.value {
            if !is_source_call(cur) {
                break;
            }
            let (last, leading) = args.split_last()?;
            text.get_or_insert_with(|| Span::new(callee.span.lo, last.span.hi));
            links.push(Link { callee, leading });
            cur = last;
        }
        Some(Self {
            links,
            subject: cur,
            text: text?,
        })
    }

    /// The finding for this chain when the rewrite removes enough nesting.
    fn finding(&self, ctx: &Ctx, expr: &Expr, in_binop_operand: bool) -> Option<Finding> {
        // A chain ending in a desugared call has no faithful source text.
        if matches!(self.subject.value, Expr_::Call(..)) {
            return None;
        }
        let subject_kind = SubjectKind::of(ctx, self.subject);
        let levels =
            self.links.len().saturating_sub(1) + usize::from(subject_kind != SubjectKind::Atomic);
        if levels < MIN_PAREN_LEVELS {
            return None;
        }
        let prefixes = self
            .links
            .iter()
            .map(|link| link_prefix(ctx, link))
            .collect::<Option<Vec<_>>>()?;
        let (fwd_subject, back_subject) = subject_forms(ctx, self.subject, subject_kind)?;

        let mut forward = fwd_subject;
        for prefix in prefixes.iter().rev() {
            forward.push_str(" |> ");
            forward.push_str(prefix);
        }
        let mut backward = prefixes.join(" <| ");
        backward.push_str(" <| ");
        backward.push_str(&back_subject);

        // Replace the call's own text (callee through last argument), leaving
        // any source parens around the whole chain in place.
        let inner = self.text;
        let parenthesised = expr.span.lo < inner.lo;
        let replacement = if in_binop_operand && !parenthesised {
            format!("({forward})")
        } else {
            forward.clone()
        };
        Some(Finding {
            rule: "prefer-pipeline",
            module: ctx.module.to_vec(),
            span: expr.span,
            message: format!(
                "{levels} nested paren levels read outside-in; a pipe chain removes them"
            ),
            help: vec![
                format!("left-to-right: `{forward}`"),
                format!("right-to-left: `{backward}`"),
                "both forms are equally valid and exactly equivalent — `x |> f` and `f <| x` \
                 each desugar to `f x`"
                    .to_owned(),
                "suppress: `-- ipe-lint: allow prefer-pipeline`".to_owned(),
            ],
            fix: Some(Fix {
                describe: "rewrite the nested call as a `|>` pipeline".to_owned(),
                span: inner,
                replacement,
            }),
            sig_fix: None,
        })
    }
}

/// How the chain's subject must be written in each pipe form.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SubjectKind {
    /// A self-delimiting atom (name, literal, record, field access, …).
    Atomic,
    /// An operator chain with no pipe operator: bare in both forms.
    Operators,
    /// An operator chain that itself pipes: parenthesised in both forms.
    PipedOperators,
    /// A form that extends rightward (`\x ->`, `if`, `case`, `let`): bare
    /// only as the last `<|` operand.
    Open,
}

impl SubjectKind {
    fn of(ctx: &Ctx, subject: &Expr) -> Self {
        match &subject.value {
            Expr_::Binops(pairs, _) => {
                if pairs
                    .iter()
                    .any(|(_, op)| matches!(ctx.text(op.value), "|>" | "<|"))
                {
                    Self::PipedOperators
                } else {
                    Self::Operators
                }
            }
            Expr_::Lambda(..) | Expr_::If(..) | Expr_::Case(..) | Expr_::Let(..) => Self::Open,
            Expr_::VarLocal(_)
            | Expr_::VarQual(_, _)
            | Expr_::Int(_)
            | Expr_::Float(_)
            | Expr_::Str(_)
            | Expr_::MultilineStr { .. }
            | Expr_::Char(_)
            | Expr_::PathLit(_)
            | Expr_::Unit
            | Expr_::Call(..)
            | Expr_::Tuple(_)
            | Expr_::List(_)
            | Expr_::Record(_)
            | Expr_::Update(..)
            | Expr_::Access(..) => Self::Atomic,
        }
    }
}

/// The subject's text for the `|>` form and the `<|` form.
fn subject_forms(ctx: &Ctx, subject: &Expr, kind: SubjectKind) -> Option<(String, String)> {
    let bare = match &subject.value {
        // A paren-wrapped operator chain's span includes its parens; its
        // operands' spans do not.
        Expr_::Binops(pairs, last) => {
            let lo = pairs.first().map_or(last.span.lo, |(e, _)| e.span.lo);
            ctx.slice(Span::new(lo, last.span.hi)).trim()
        }
        _ => ctx.slice(subject.span).trim(),
    };
    if bare.is_empty() {
        return None;
    }
    let wrapped = || {
        if bare.starts_with('(') {
            bare.to_owned()
        } else {
            format!("({bare})")
        }
    };
    Some(match kind {
        SubjectKind::Atomic | SubjectKind::Operators => (bare.to_owned(), bare.to_owned()),
        SubjectKind::PipedOperators => (format!("({bare})"), format!("({bare})")),
        SubjectKind::Open => (wrapped(), bare.to_owned()),
    })
}

/// The source of one link with its threaded argument dropped: `List.filter
/// live` for `List.filter live records`, the bare callee for `f x`.
fn link_prefix<'a>(ctx: &'a Ctx, link: &Link) -> Option<&'a str> {
    let hi = link
        .leading
        .last()
        .map_or(link.callee.span.hi, |a| a.span.hi);
    let prefix = ctx.slice(Span::new(link.callee.span.lo, hi)).trim();
    (!prefix.is_empty()).then_some(prefix)
}
