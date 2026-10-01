//! The shared CSS length-unit renderer — the single place the `<n><unit>`
//! spelling is produced for every Ipê surface.
//!
//! `Ipe.Ui.Length` and `Ipe.Css.Length` are two distinct surface types (layout
//! intent vs typography), deliberately not merged. They share exactly the
//! `Px`/`Vh`/`Vw` shapes — an integer magnitude plus a unit suffix — whose CSS
//! output must be byte-identical across surfaces. This module owns that
//! spelling so no surface re-derives it, exactly as `crate::color` owns the one
//! CSS colour spelling. Byte-equivalence with the pure-Ipê `Css.lengthToString`
//! (a different language, so it cannot call in here) is held by the
//! `css_length_color_ssot` equivalence guards.

/// A CSS length unit whose spelling is shared across every Ipê surface.
///
/// The set is closed to the genuinely-shared, integer-magnitude units; a
/// surface-specific unit (`Ipe.Ui`'s layout `Fill`/`Content`, `Ipe.Css`'s
/// typographic `Rem`/`Em`/`Ch`/`Fr`) is rendered by its own surface, never
/// here — so this carrier stays the SSOT only for what is actually shared.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CssUnit {
    /// CSS `px` — device-independent pixels.
    Px,
    /// CSS `vh` — percent of viewport height.
    Vh,
    /// CSS `vw` — percent of viewport width.
    Vw,
}

impl CssUnit {
    /// The unit suffix as it appears in CSS.
    const fn suffix(self) -> &'static str {
        match self {
            Self::Px => "px",
            Self::Vh => "vh",
            Self::Vw => "vw",
        }
    }

    /// The one place a shared length is spelled for CSS: an integer magnitude
    /// followed by the unit suffix (`16` + `Px` → `"16px"`).
    #[must_use]
    pub fn css(self, n: i64) -> String {
        format!("{n}{}", self.suffix())
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;

    #[test]
    fn spells_each_shared_unit() {
        assert_eq!(CssUnit::Px.css(0), "0px");
        assert_eq!(CssUnit::Px.css(16), "16px");
        assert_eq!(CssUnit::Vh.css(50), "50vh");
        assert_eq!(CssUnit::Vw.css(100), "100vw");
    }
}
