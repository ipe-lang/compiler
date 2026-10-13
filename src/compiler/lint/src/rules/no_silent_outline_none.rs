//! `no-silent-outline-none` — a `:focus`/`:focus-visible` block that removes
//! the outline without providing a visible replacement is a keyboard-a11y
//! regression: every keyboard user loses their cursor.
//!
//! **What is flagged:** any call to `Ui.style "outline" "none"` (or `"0"`)
//! that appears inside a list argument to `Ui.focus`, `Ui.focusVisible`, or
//! `Ui.onPseudo` — i.e. the caller is erasing the default focus ring on a
//! focusable control — unless that same list also contains a compensating
//! visible indicator (a non-`none`/non-`0` `"outline"`, `"border"`,
//! `"box-shadow"`, or `"background-color"` `Ui.style` call).
//!
//! **Fail-closed (PRINCIPLES.md — Security):** absent proof of a visible
//! replacement, the removal is flagged. A false positive the author can
//! suppress (with `-- ipe-lint: allow no-silent-outline-none`) is preferable
//! to a silent regression that locks out keyboard users.
//!
//! **Not flagged:**
//!   * `Ui.style "outline" "none"` outside a focus pseudo-class context —
//!     fine on hover, transitions, etc.
//!   * `Ui.style "outline" "2px solid …"` inside focus — an explicit outline
//!     replaces the default; fine.
//!   * The `ipe-lint: allow no-silent-outline-none` inline suppression.

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

/// True when `expr` is `Ui.focus`, `Ui.focusVisible`, or `Ui.onPseudo`
/// (any qualifier for the last — `Ipe.Ui.onPseudo` / local `onPseudo` bound
/// from an import alias are both valid spellings). We match on the bare name
/// only (`focus` / `focusVisible` / `onPseudo`) qualified under any module
/// segment ending `Ui`, or as a local if the module exposes it.
fn is_focus_pseudo_fn(ctx: &Ctx, expr: &Expr) -> bool {
    match &expr.value {
        Expr_::VarQual(module, name) => {
            let m = ctx.text(*module);
            let n = ctx.text(*name);
            // Module must end with `Ui` (handles `Ipe.Ui` / `Ui` / aliased `U`
            // only when the segment is exactly `Ui`).
            let module_is_ui = m == "Ui" || m.ends_with(".Ui");
            module_is_ui && matches!(n, "focus" | "focusVisible" | "onPseudo")
        }
        // A locally-bound import: `import Ipe.Ui exposing (focusVisible)`.
        Expr_::VarLocal(name) => {
            matches!(ctx.text(*name), "focus" | "focusVisible" | "onPseudo")
        }
        _ => false,
    }
}

/// True when `expr` is a `Ui.style` call that REMOVES the outline: property
/// `outline` (CSS property names are case-insensitive) set to an effectively
/// invisible value (`none`/`0`/`0px`/`0em`/a zero-width or transparent
/// shorthand). Matching only the exact `"none"`/`"0"` strings let CSS-equivalent
/// removals (`0px`, `OUTLINE`) slip past.
fn is_outline_none(ctx: &Ctx, expr: &Expr) -> bool {
    let Expr_::Call(callee, args) = &expr.value else {
        return false;
    };
    if !is_ui_style(ctx, callee) {
        return false;
    }
    let (Some(Some(prop)), Some(Some(val))) = (args.first().map(str_val), args.get(1).map(str_val))
    else {
        return false;
    };
    prop.eq_ignore_ascii_case("outline") && is_invisible_value("outline", val)
}

/// True when `expr` references `Ui.style` (qualified or local alias).
fn is_ui_style(ctx: &Ctx, expr: &Expr) -> bool {
    match &expr.value {
        Expr_::VarQual(module, name) => {
            let m = ctx.text(*module);
            let n = ctx.text(*name);
            (m == "Ui" || m.ends_with(".Ui")) && n == "style"
        }
        Expr_::VarLocal(name) => ctx.text(*name) == "style",
        _ => false,
    }
}

/// True when the attribute list carries a VISIBLE focus replacement: a
/// `Ui.style` call on `outline`/`border`/`box-shadow`/`background(-color)`
/// (property matched case-insensitively) whose value actually renders — i.e. is
/// NOT invisible per [`is_invisible_value`]. Accepting any non-`none` value would
/// let a `transparent` box-shadow or a `0px` border pose as a replacement.
fn has_visible_replacement(ctx: &Ctx, attrs: &[Expr]) -> bool {
    attrs.iter().any(|e| {
        let Expr_::Call(callee, args) = &e.value else {
            return false;
        };
        if !is_ui_style(ctx, callee) {
            return false;
        }
        let (Some(Some(prop)), Some(Some(val))) =
            (args.first().map(str_val), args.get(1).map(str_val))
        else {
            return false;
        };
        let prop = prop.to_ascii_lowercase();
        matches!(
            prop.as_str(),
            "outline" | "border" | "box-shadow" | "background-color" | "background"
        ) && !is_invisible_value(&prop, val)
    })
}

/// Whether a CSS `raw` value for `prop` renders no visible focus indicator — a
/// removal keyword, a zero-width length, a transparent/zero-alpha colour, or a
/// zero-width shorthand. Both the removal check and the replacement check
/// normalise through here, so `outline: 0px`, `OUTLINE: none`, a `transparent`
/// box-shadow, and a `0px` border are all treated as "nothing visible".
fn is_invisible_value(prop: &str, raw: &str) -> bool {
    let v = raw.trim().to_ascii_lowercase();
    if matches!(v.as_str(), "none" | "hidden") || is_zero_length(&v) {
        return true;
    }
    if v.contains("transparent") || is_zero_alpha_color(&v) {
        return true;
    }
    match prop {
        // `<width> <style> <color>` — a zero leading width paints nothing.
        "outline" | "border" => v.split_whitespace().next().is_some_and(is_zero_length),
        // `<offx> <offy> <blur> <spread> <color>` — invisible only when every
        // length component is zero (a non-zero blur or spread still shows).
        "box-shadow" => {
            let lengths: Vec<&str> = v
                .split_whitespace()
                .filter(|t| is_length_token(t))
                .collect();
            !lengths.is_empty() && lengths.iter().copied().all(is_zero_length)
        }
        _ => false,
    }
}

/// A single CSS length token that is exactly zero.
fn is_zero_length(tok: &str) -> bool {
    matches!(tok, "0" | "0px" | "0em" | "0rem" | "0%" | "0.0" | "0.0px")
}

/// Whether `tok` is a CSS length literal (digits with an optional unit),
/// e.g. `3px`, `0`, `.5em` — used to isolate the length components of a
/// `box-shadow` from its colour.
fn is_length_token(tok: &str) -> bool {
    let digits = tok.trim_end_matches(|c: char| c.is_ascii_alphabetic() || c == '%');
    !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit() || c == '.')
}

/// Whether `v` is an `rgba()`/`hsla()` colour whose alpha component is zero.
fn is_zero_alpha_color(v: &str) -> bool {
    for prefix in ["rgba(", "hsla("] {
        if let Some(inner) = v.strip_prefix(prefix)
            && let Some(alpha) = inner.trim_end_matches(')').rsplit(',').next()
        {
            let a = alpha.trim().trim_end_matches('%');
            return matches!(a, "0" | "0.0" | "0.00");
        }
    }
    false
}

/// If `expr` is a string literal, return its value; else `None`.
const fn str_val(expr: &Expr) -> Option<&str> {
    match &expr.value {
        Expr_::Str(s) => Some(s.as_str()),
        _ => None,
    }
}

// ── Tree walk ─────────────────────────────────────────────────────────────────

/// Walk `expr`, recording a finding for each silent outline removal.
fn walk_expr(ctx: &Ctx, expr: &Expr, out: &mut Vec<Finding>) {
    // A call whose callee is a focus-pseudo function — inspect its argument list.
    if let Expr_::Call(callee, args) = &expr.value {
        if is_focus_pseudo_fn(ctx, callee) {
            // `Ui.focus attrs` / `Ui.focusVisible attrs` — attrs is first arg.
            // `Ui.onPseudo pseudo attrs` — attrs is second arg.
            let callee_name = match &callee.value {
                Expr_::VarQual(_, n) | Expr_::VarLocal(n) => ctx.text(*n),
                _ => "",
            };
            let attr_arg_idx = usize::from(callee_name == "onPseudo");
            if let Some(attr_expr) = args.get(attr_arg_idx)
                && let Expr_::List(items) = &attr_expr.value
            {
                check_attr_list(ctx, items, expr, out);
            }
        }
        // Also descend into callee + args.
        walk_expr(ctx, callee, out);
        for arg in args {
            walk_expr(ctx, arg, out);
        }
        return;
    }
    walk_children(ctx, expr, out);
}

/// Given the attribute list inside a focus pseudo call, flag any `outline:none`
/// without a visible replacement.
fn check_attr_list(ctx: &Ctx, attrs: &[Expr], call_site: &Expr, out: &mut Vec<Finding>) {
    for attr in attrs {
        if is_outline_none(ctx, attr) && !has_visible_replacement(ctx, attrs) {
            out.push(
                ctx.advisory(
                    "no-silent-outline-none",
                    attr.span,
                    "`outline: none` inside a focus pseudo-class removes the keyboard focus \
                 indicator without a visible replacement"
                        .to_owned(),
                    vec![
                    "add a visible replacement in the same attribute list: \
                     `Ui.style \"outline\" \"3px solid #0060df\"`, \
                     `Ui.style \"box-shadow\" \"0 0 0 3px #0060df\"`, or similar"
                        .to_owned(),
                    "the default Ipe.Ui focus ring (injected by the runtime) is contrast-safe; \
                     only override it with an equally visible alternative"
                        .to_owned(),
                    "suppress: `-- ipe-lint: allow no-silent-outline-none`".to_owned(),
                ],
                ),
            );
            // One finding per call site — the call_site span is the enclosing
            // focus call, useful for fix guidance; report at the `outline:none`
            // attribute expression so the editor underlines the exact problem.
            let _ = call_site; // span already used above via `attr.span`
            break;
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
            .filter(|f| f.rule == "no-silent-outline-none")
            .collect()
    }

    // Prove the refusal: outline:none without replacement is flagged.
    #[test]
    fn outline_none_in_focus_visible_is_flagged() {
        let src = r#"
module Main exposing (view)
import Ipe.Ui as Ui

view : Ui.Element msg
view =
    Ui.button
        [ Ui.focusVisible [ Ui.style "outline" "none" ]
        ]
        (Ui.text "click me")
"#;
        let found = findings_for(src);
        assert!(
            !found.is_empty(),
            "expected a finding for outline:none in focusVisible block"
        );
        assert_eq!(
            found.first().expect("a finding present").rule,
            "no-silent-outline-none"
        );
    }

    // Prove the refusal: outline:0 is equally flagged.
    #[test]
    fn outline_zero_in_focus_is_flagged() {
        let src = r#"
module Main exposing (view)
import Ipe.Ui as Ui

view : Ui.Element msg
view =
    Ui.button
        [ Ui.focus [ Ui.style "outline" "0" ]
        ]
        (Ui.text "click me")
"#;
        let found = findings_for(src);
        assert!(
            !found.is_empty(),
            "expected a finding for outline:0 in focus block"
        );
    }

    // Prove compliance: outline:none replaced by a box-shadow passes.
    #[test]
    fn outline_none_with_box_shadow_replacement_passes() {
        let src = r#"
module Main exposing (view)
import Ipe.Ui as Ui

view : Ui.Element msg
view =
    Ui.button
        [ Ui.focusVisible
            [ Ui.style "outline" "none"
            , Ui.style "box-shadow" "0 0 0 3px #0060df"
            ]
        ]
        (Ui.text "click me")
"#;
        let found = findings_for(src);
        assert!(
            found.is_empty(),
            "outline:none with box-shadow replacement must not be flagged"
        );
    }

    // Prove compliance: a visible outline replacement passes.
    #[test]
    fn visible_outline_replacement_passes() {
        let src = r#"
module Main exposing (view)
import Ipe.Ui as Ui

view : Ui.Element msg
view =
    Ui.button
        [ Ui.focusVisible
            [ Ui.style "outline" "none"
            , Ui.style "outline" "3px solid #0060df"
            ]
        ]
        (Ui.text "click me")
"#;
        let found = findings_for(src);
        assert!(
            found.is_empty(),
            "visible outline replacement must not be flagged"
        );
    }

    // Prove the refusal: `outline: 0px` is a CSS-equivalent removal and must be
    // flagged even though the value is not the literal `"0"`.
    #[test]
    fn outline_zero_px_is_flagged() {
        let src = r#"
module Main exposing (view)
import Ipe.Ui as Ui

view : Ui.Element msg
view =
    Ui.button
        [ Ui.focus [ Ui.style "outline" "0px" ]
        ]
        (Ui.text "click me")
"#;
        assert!(
            !findings_for(src).is_empty(),
            "outline:0px must be flagged as a removal"
        );
    }

    // Prove the refusal: CSS property names are case-insensitive, so an
    // uppercase `OUTLINE` removal must still be flagged.
    #[test]
    fn uppercase_outline_none_is_flagged() {
        let src = r#"
module Main exposing (view)
import Ipe.Ui as Ui

view : Ui.Element msg
view =
    Ui.button
        [ Ui.focusVisible [ Ui.style "OUTLINE" "none" ]
        ]
        (Ui.text "click me")
"#;
        assert!(
            !findings_for(src).is_empty(),
            "OUTLINE:none (uppercase) must be flagged"
        );
    }

    // Prove the refusal: an INVISIBLE replacement (transparent box-shadow, or a
    // zero-width border) does not count — the focus indicator is still gone.
    #[test]
    fn invisible_replacements_do_not_exempt() {
        let transparent_shadow = r#"
module Main exposing (view)
import Ipe.Ui as Ui

view : Ui.Element msg
view =
    Ui.button
        [ Ui.focusVisible
            [ Ui.style "outline" "none"
            , Ui.style "box-shadow" "0 0 0 3px transparent"
            ]
        ]
        (Ui.text "click me")
"#;
        assert!(
            !findings_for(transparent_shadow).is_empty(),
            "a transparent box-shadow is not a visible replacement"
        );

        let zero_border = r#"
module Main exposing (view)
import Ipe.Ui as Ui

view : Ui.Element msg
view =
    Ui.button
        [ Ui.focusVisible
            [ Ui.style "outline" "none"
            , Ui.style "border" "0px"
            ]
        ]
        (Ui.text "click me")
"#;
        assert!(
            !findings_for(zero_border).is_empty(),
            "a 0px border is not a visible replacement"
        );
    }

    // outline:none outside any focus pseudo-class is not flagged.
    #[test]
    fn outline_none_outside_focus_context_is_not_flagged() {
        let src = r#"
module Main exposing (view)
import Ipe.Ui as Ui

view : Ui.Element msg
view =
    Ui.button
        [ Ui.style "outline" "none"
        ]
        (Ui.text "click me")
"#;
        let found = findings_for(src);
        assert!(
            found.is_empty(),
            "outline:none outside a focus block must not be flagged"
        );
    }

    // onPseudo with a focus PseudoClass and outline:none is flagged.
    #[test]
    fn outline_none_in_on_pseudo_focus_is_flagged() {
        let src = r#"
module Main exposing (view)
import Ipe.Ui as Ui

view : Ui.Element msg
view =
    Ui.button
        [ Ui.onPseudo Ui.focusVisible [ Ui.style "outline" "none" ]
        ]
        (Ui.text "click me")
"#;
        let found = findings_for(src);
        assert!(
            !found.is_empty(),
            "outline:none in onPseudo focusVisible block must be flagged"
        );
    }
}
