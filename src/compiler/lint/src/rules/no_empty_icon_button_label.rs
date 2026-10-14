//! `no-empty-icon-button-label` — `Ui.iconButton`'s `label` becomes the
//! control's `aria-label`, its ONLY accessible name (the visible content is an
//! icon a screen reader cannot read). A `label` that is empty or whitespace-only
//! renders `aria-label=""` / `aria-label="   "`, which assistive tech treats as
//! NO accessible name — the icon button is nameless to the exact user the field
//! exists to include.
//!
//! **What is flagged:** an `Ui.iconButton attrs { …, label = <literal>, … }`
//! whose `label` is a string *literal* that is empty or trims to empty. The
//! `label : String` type guarantees the attribute is present; this rule
//! guarantees the common literal case is meaningful.
//!
//! **Fail-closed (PRINCIPLES.md — Community-centered / Security):** absent proof
//! the name is meaningful, the empty literal is flagged. A computed empty
//! `String` cannot be caught by a literal check — that gap is the honest limit
//! of a lint (a full guarantee would need a `NonEmptyString` type on the field);
//! the literal case is the realistic hole and is closed here.
//!
//! **Not flagged:**
//!   * `Ui.iconButton attrs { label = "Close" }` — a real name.
//!   * a non-literal `label` (a `let`-bound or computed `String`) — outside a
//!     literal check's reach.
//!   * the `ipe-lint: allow no-empty-icon-button-label` inline suppression.

use ipe_diagnostics::Located;
use ipe_intern::Symbol;
use ipe_syntax::{Expr, Expr_};

use crate::finding::Finding;
use crate::rules::Ctx;

pub fn check(ctx: &Ctx) -> Vec<Finding> {
    let mut findings = Vec::new();
    for value in &ctx.ast.values {
        walk_expr(ctx, &value.value.body, &mut findings);
    }
    findings
}

// ── Recognisers ──────────────────────────────────────────────────────────────

/// True when `expr` references `Ui.iconButton` — qualified under any module
/// segment ending `Ui` (`Ipe.Ui.iconButton` / `Ui.iconButton`), or as a local
/// bound by `import Ipe.Ui exposing (iconButton)`.
fn is_ui_icon_button(ctx: &Ctx, expr: &Expr) -> bool {
    match &expr.value {
        Expr_::VarQual(module, name) => {
            let m = ctx.text(*module);
            (m == "Ui" || m.ends_with(".Ui")) && ctx.text(*name) == "iconButton"
        }
        Expr_::VarLocal(name) => ctx.text(*name) == "iconButton",
        _ => false,
    }
}

/// If `expr` is a string literal, return its value; else `None`.
///
/// An empty/whitespace triple-quoted label parses to `MultilineStr`, not `Str`
/// (`""""""` / `""" """` → a nameless/whitespace `aria-label`), so it must be
/// caught here too. A triple-quote carrying `{{…}}` interpolation is computed,
/// not a literal — out of a lint's reach, so it is left alone.
fn str_val(expr: &Expr) -> Option<&str> {
    match &expr.value {
        Expr_::Str(s) => Some(s.as_str()),
        Expr_::MultilineStr { raw, .. } if !raw.contains("{{") => Some(raw.as_str()),
        _ => None,
    }
}

/// True when `raw` is an empty or whitespace-only accessible name — both render
/// an `aria-label` that assistive tech reads as no name at all.
fn is_meaningless_name(raw: &str) -> bool {
    raw.trim().is_empty()
}

// ── Tree walk ─────────────────────────────────────────────────────────────────

/// Walk `expr`, recording a finding for each `Ui.iconButton` call whose `label`
/// record field is an empty/whitespace-only string literal.
fn walk_expr(ctx: &Ctx, expr: &Expr, out: &mut Vec<Finding>) {
    if let Expr_::Call(callee, args) = &expr.value {
        if is_ui_icon_button(ctx, callee) {
            // `iconButton attrs { icon, label, onPress }` — inspect any record
            // argument for a `label` field (argument order is not assumed).
            for arg in args {
                if let Expr_::Record(fields) = &arg.value {
                    check_record(ctx, fields, out);
                }
            }
        }
        walk_expr(ctx, callee, out);
        for arg in args {
            walk_expr(ctx, arg, out);
        }
        return;
    }
    walk_children(ctx, expr, out);
}

/// Flag a `label` field bound to an empty/whitespace-only string literal.
fn check_record(ctx: &Ctx, fields: &[(Located<Symbol>, Expr)], out: &mut Vec<Finding>) {
    for (name, value) in fields {
        if ctx.text(name.value) != "label" {
            continue;
        }
        if let Some(raw) = str_val(value)
            && is_meaningless_name(raw)
        {
            out.push(
                ctx.advisory(
                    "no-empty-icon-button-label",
                    value.span,
                    "`Ui.iconButton`'s `label` is the control's only accessible name \
                 (its `aria-label`); an empty or whitespace-only label leaves the \
                 icon button nameless to assistive tech"
                        .to_owned(),
                    vec![
                        "give the button a real, concise name describing its action: \
                     `label = \"Close\"`, `label = \"Search\"`"
                            .to_owned(),
                        "if the icon truly conveys the name and duplicating it is wrong, \
                     the control is not icon-only — use `Ui.button` with visible text"
                            .to_owned(),
                        "suppress: `-- ipe-lint: allow no-empty-icon-button-label`".to_owned(),
                    ],
                ),
            );
        }
    }
}

/// Recurse into all sub-expressions not already handled by `walk_expr`.
fn walk_children(ctx: &Ctx, expr: &Expr, out: &mut Vec<Finding>) {
    match &expr.value {
        Expr_::Call(callee, args) => {
            walk_expr(ctx, callee, out);
            for arg in args {
                walk_expr(ctx, arg, out);
            }
        }
        Expr_::Case(scrut, arms) => {
            walk_expr(ctx, scrut, out);
            for (_pat, body) in arms {
                walk_expr(ctx, body, out);
            }
        }
        Expr_::Lambda(_params, body) => walk_expr(ctx, body, out),
        Expr_::Binops(pairs, last) => {
            for (operand, _op) in pairs {
                walk_expr(ctx, operand, out);
            }
            walk_expr(ctx, last, out);
        }
        Expr_::Let(bindings, body) => {
            for binding in bindings {
                walk_expr(ctx, &binding.body, out);
            }
            walk_expr(ctx, body, out);
        }
        Expr_::If(branches, otherwise) => {
            for (cond, body) in branches {
                walk_expr(ctx, cond, out);
                walk_expr(ctx, body, out);
            }
            walk_expr(ctx, otherwise, out);
        }
        Expr_::Tuple(items) | Expr_::List(items) => {
            for item in items {
                walk_expr(ctx, item, out);
            }
        }
        Expr_::Record(fields) => {
            for (_name, value) in fields {
                walk_expr(ctx, value, out);
            }
        }
        Expr_::Access(base, _field) => walk_expr(ctx, base, out),
        Expr_::Update(_base, fields) => {
            for (_name, value) in fields {
                walk_expr(ctx, value, out);
            }
        }
        _ => {}
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SourceModule;

    fn module(source: &str) -> SourceModule {
        SourceModule {
            module: vec!["Main".to_owned()],
            source: source.to_owned(),
        }
    }

    fn findings_for(source: &str) -> Vec<Finding> {
        let m = module(source);
        let modules = [m];
        let config = crate::LintConfig::default();
        let Ok(report) = crate::run(&modules, &config, &crate::NeverCancel);
        report
            .findings
            .into_iter()
            .filter(|f| f.rule == "no-empty-icon-button-label")
            .collect()
    }

    // Prove the refusal: an empty label literal is flagged.
    #[test]
    fn empty_label_is_flagged() {
        let src = r#"
module Main exposing (view)
import Ipe.Ui as Ui

view : Ui.Element msg
view =
    Ui.iconButton [] { icon = Ui.none, label = "", onPress = Nothing }
"#;
        let found = findings_for(src);
        assert!(
            !found.is_empty(),
            "expected a finding for an empty iconButton label"
        );
        assert_eq!(
            found.first().expect("a finding present").rule,
            "no-empty-icon-button-label"
        );
    }

    // Prove the refusal: a whitespace-only label is equally nameless to AT.
    #[test]
    fn whitespace_only_label_is_flagged() {
        let src = r#"
module Main exposing (view)
import Ipe.Ui as Ui

view : Ui.Element msg
view =
    Ui.iconButton [] { icon = Ui.none, label = "   ", onPress = Nothing }
"#;
        assert!(
            !findings_for(src).is_empty(),
            "a whitespace-only label must be flagged"
        );
    }

    // Prove the refusal: an empty TRIPLE-quoted label parses to `MultilineStr`,
    // not `Str` — it must still be flagged, else `label = """"""` is a
    // fail-open nameless control.
    #[test]
    fn empty_multiline_label_is_flagged() {
        let src = r#"
module Main exposing (view)
import Ipe.Ui as Ui

view : Ui.Element msg
view =
    Ui.iconButton [] { icon = Ui.none, label = """""", onPress = Nothing }
"#;
        assert!(
            !findings_for(src).is_empty(),
            "an empty triple-quoted label (MultilineStr) must be flagged"
        );
    }

    // Prove compliance: a real label passes.
    #[test]
    fn real_label_passes() {
        let src = r#"
module Main exposing (view)
import Ipe.Ui as Ui

view : Ui.Element msg
view =
    Ui.iconButton [] { icon = Ui.none, label = "Close", onPress = Nothing }
"#;
        assert!(
            findings_for(src).is_empty(),
            "a real label must not be flagged"
        );
    }

    // Field order is not assumed — `label` first still flagged.
    #[test]
    fn empty_label_first_field_is_flagged() {
        let src = r#"
module Main exposing (view)
import Ipe.Ui as Ui

view : Ui.Element msg
view =
    Ui.iconButton [] { label = "", icon = Ui.none, onPress = Nothing }
"#;
        assert!(
            !findings_for(src).is_empty(),
            "an empty label as the first field must still be flagged"
        );
    }

    // A `label = ""` on a DIFFERENT function is not our concern.
    #[test]
    fn empty_label_on_other_call_is_not_flagged() {
        let src = r#"
module Main exposing (view)
import Ipe.Ui as Ui

view : Ui.Element msg
view =
    Ui.button [] { label = Ui.text "", onPress = Nothing }
"#;
        assert!(
            findings_for(src).is_empty(),
            "an empty label on Ui.button (not iconButton) must not be flagged"
        );
    }

    // The inline suppression silences the finding.
    #[test]
    fn suppression_silences_the_finding() {
        let src = r#"
module Main exposing (view)
import Ipe.Ui as Ui

view : Ui.Element msg
view =
    -- ipe-lint: allow no-empty-icon-button-label
    Ui.iconButton [] { icon = Ui.none, label = "", onPress = Nothing }
"#;
        assert!(
            findings_for(src).is_empty(),
            "the inline suppression must silence the finding"
        );
    }
}
