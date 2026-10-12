//! The server-free HTML page scaffold shared by every render host.
//!
//! `page_shell`, its `BASE_CSS` reset and its `STATUS_CSS` banner rules are pure
//! `format!` over compile-time literals — no axum, no session, no server dependency — so they belong to the
//! render core, not the HTTP `web` server. The full `web` module re-exports
//! `page_shell` from here, and the lean render-core `web` shell (native
//! `webview` + browser-WASM `wasm-client`) does too, so the ONE definition backs
//! every host (single source of truth).

/// Minimal CSS reset injected into every rendered page.
///
/// The `:focus-visible` block is the `Ipe.Ui` default focus ring — a
/// keyboard-user's cursor, guaranteed visible with zero author effort.
/// Design choices:
///   * `:focus-visible` only — mouse clicks do not show the ring (per WCAG 2.5.7
///     / pointer-accessible controls), but every keyboard-focus does.
///   * `outline: 3px solid` at `offset: 2px` — meets the WCAG 2.2 non-text
///     contrast floor of 3:1 against any background: a `3px transparent` outline
///     at `2px` offset is the browser UA baseline for the `:focus-visible`
///     pseudo-class; we replace it with a solid visible ring.
///   * Colour: `#0060df` (a11y-vetted accent blue, ≥ 3:1 against white and most
///     mid-range backgrounds) with a white `box-shadow` halo for contrast against
///     dark backgrounds — the two-layer technique (ring + halo) achieves ≥ 3:1 on
///     any background without querying the element's computed background color.
///   * `@media (forced-colors: active)` preserves the `Highlight` system color
///     for high-contrast / Windows HCM modes.
///
/// Authors can override per-element with `Ui.focusVisible [Ui.style "outline" "…"]`
/// — but the `no-silent-outline-none` lint fires if they erase it without a
/// visible replacement, keeping the default path accessible by construction.
const BASE_CSS: &str = concat!(
    "*,*::before,*::after{box-sizing:border-box}",
    "html,body{margin:0;padding:0;min-height:100%}",
    "body{min-height:100vh;display:flex;flex-direction:column;font-family:-apple-system,BlinkMacSystemFont,\"Segoe UI\",Roboto,\"Helvetica Neue\",Arial,sans-serif;line-height:1.4}",
    "#ipe-root{display:flex;flex-direction:column;flex:1 0 auto;min-height:0}",
    "h1,h2,h3,h4,h5,h6,p,ul,ol,li,figure,blockquote,pre,dl,dd{margin:0;padding:0;font-weight:inherit;font-size:inherit}",
    "button,input,select,textarea{font:inherit;color:inherit}",
    "button{background:none;border:0;padding:0;cursor:pointer;text-align:inherit}",
    "a{color:inherit;text-decoration:none}",
    "img,video,canvas,svg{display:block;max-width:100%}",
    // Default accessible focus ring — keyboard user's cursor.
    // Two-layer technique: a solid accent ring + white box-shadow halo gives ≥ 3:1
    // non-text contrast (WCAG 2.2 §1.4.11) against any background.
    ":focus-visible{outline:3px solid #0060df;outline-offset:2px;box-shadow:0 0 0 5px #fff}",
    // High-contrast / forced-colours mode: browser picks the `Highlight` system
    // colour, which is guaranteed to meet the user's chosen contrast.
    "@media (forced-colors:active){:focus-visible{outline-color:Highlight;box-shadow:none}}",
);

/// Status-banner rules for the live client's `#__ipe-status` element.
///
/// A compile-time constant emitted in the page head next to [`BASE_CSS`], so the
/// client never creates a `<style>` element and every inline style the shell
/// carries is a fixed literal a hash can admit. The client sets the banner's
/// base layout through CSSOM; these rules map each state class to its colour.
const STATUS_CSS: &str = concat!(
    "#__ipe-status.ipe-status--connected{display:none}",
    "#__ipe-status.ipe-status--reconnecting{background:#b45309}",
    "#__ipe-status.ipe-status--offline{background:#b91c1c}",
    "#__ipe-status.ipe-status--recompiling{background:#b45309}",
    "#__ipe-status.ipe-status--build-ok{background:#166534}",
    "#__ipe-status.ipe-status--build-failed{background:#991b1b;pointer-events:auto;cursor:default}",
    "@media(prefers-color-scheme:dark){",
    "#__ipe-status.ipe-status--recompiling{background:#92400e}",
    "#__ipe-status.ipe-status--build-ok{background:#14532d}",
    "#__ipe-status.ipe-status--build-failed{background:#7f1d1d}",
    "}",
);

/// Shared HTML page scaffold used by every render path.
///
/// Emits, in order:
///   1. Standard HTML5 boilerplate (`<!DOCTYPE html><html>`).
///   2. A `<head>` containing:
///      - `<meta charset="utf-8">` (character encoding, always first).
///      - `<meta name="viewport" …>` (full-bleed on mobile and native webview).
///      - `<style>{BASE_CSS}</style>` (the compile-time reset; no user data).
///      - `<style>{STATUS_CSS}</style>` (the status-banner rules; no user data).
///      - `head_extra` — any additional per-backend head content (empty string
///        for backends that need none).
///   3. `<body>{body_inner}</body>` — the pre-rendered HTML body.
///   4. `tail_scripts` — `<script>` tags appended after `</body>` (empty string
///      for backends that carry no scripts).
///
/// `body_inner` must already be HTML-escaped (produced by `render_html`).
/// `head_extra` and `tail_scripts` are compile-time or session-derived
/// literals assembled by the caller; no user-controlled text reaches them.
#[must_use]
pub fn page_shell(head_extra: &str, body_inner: &str, tail_scripts: &str) -> String {
    format!(
        "<!DOCTYPE html><html><head>\
         <meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <style>{BASE_CSS}</style>\
         <style>{STATUS_CSS}</style>\
         {head_extra}\
         </head>\
         <body>{body_inner}</body>\
         {tail_scripts}\
         </html>"
    )
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;

    /// The default focus ring CSS is present in every page and meets the
    /// contrast floor by construction (3px solid accent at offset 2px + white
    /// halo — the two-layer technique gives ≥ 3:1 non-text contrast against any
    /// background per WCAG 2.2 §1.4.11).
    #[test]
    fn base_css_contains_focus_visible_ring() {
        assert!(
            BASE_CSS.contains(":focus-visible"),
            "BASE_CSS must contain a :focus-visible rule"
        );
        assert!(
            BASE_CSS.contains("outline:3px solid"),
            "focus ring must be at least 3px solid"
        );
        assert!(
            BASE_CSS.contains("outline-offset:2px"),
            "focus ring must use outline-offset:2px for separation"
        );
        assert!(
            BASE_CSS.contains("box-shadow"),
            "focus ring must include a box-shadow halo for dark-background contrast"
        );
    }

    /// The forced-colours (Windows HCM) override is present so the ring
    /// survives high-contrast mode.
    #[test]
    fn base_css_contains_forced_colors_override() {
        assert!(
            BASE_CSS.contains("forced-colors"),
            "BASE_CSS must include a forced-colors media query for HCM support"
        );
        assert!(
            BASE_CSS.contains("Highlight"),
            "forced-colors block must use the Highlight system colour"
        );
    }

    /// `page_shell` embeds `BASE_CSS` verbatim so the ring reaches every page.
    #[test]
    fn page_shell_embeds_focus_ring() {
        let html = page_shell("", "<p>hi</p>", "");
        assert!(
            html.contains(":focus-visible"),
            "page_shell output must contain the :focus-visible ring from BASE_CSS"
        );
    }

    /// `page_shell` embeds `STATUS_CSS` inside the head.
    #[test]
    fn page_shell_embeds_status_css_in_head() {
        let html = page_shell("<meta name=\"x\">", "<p>hi</p>", "");
        let status = format!("<style>{STATUS_CSS}</style>");
        let at = html.find(&status);
        let head_end = html.find("</head>");
        assert!(
            matches!((at, head_end), (Some(a), Some(h)) if a < h),
            "STATUS_CSS must be emitted inside <head>: {html}"
        );
        assert!(STATUS_CSS.contains("#__ipe-status.ipe-status--offline"));
    }
}
