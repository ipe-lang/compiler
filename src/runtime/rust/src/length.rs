//! The shared CSS length-unit renderer — the single place the `<n><unit>`
//! spelling is produced for every Ipê surface — and [`PxBounds`], the one fold
//! of `Ui.minimum` / `Ui.maximum` bounds every `Ipe.Ui` backend reads.
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

/// A non-negative px interval `lo <= hi`, built only by folding bounds in nesting order.
///
/// The one fold of `Ui.minimum` / `Ui.maximum` wrappers. A bounded length's
/// used size is `max(lo, min(hi, v))` for its base size `v`; wrapping that in
/// `max(n, ·)` or `min(n, ·)` maps `lo` and `hi` monotonically, so the folded
/// interval equals the nested composition exactly and keeps `lo <= hi`. A
/// negative bound clamps to 0, the smallest size any backend can lay out.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct PxBounds {
    lo: Option<i64>,
    hi: Option<i64>,
}

impl PxBounds {
    /// No bound on either side.
    pub const NONE: Self = Self { lo: None, hi: None };

    /// Wrap in `minimum n`: the used size becomes `max(n, v)`.
    #[must_use]
    pub fn at_least(self, n: i64) -> Self {
        let n = n.max(0);
        Self {
            lo: Some(self.lo.map_or(n, |l| l.max(n))),
            hi: self.hi.map(|h| h.max(n)),
        }
    }

    /// Wrap in `maximum n`: the used size becomes `min(n, v)`.
    #[must_use]
    pub fn at_most(self, n: i64) -> Self {
        let n = n.max(0);
        Self {
            lo: self.lo.map(|l| l.min(n)),
            hi: Some(self.hi.map_or(n, |h| h.min(n))),
        }
    }

    /// The floor in px, if any.
    #[must_use]
    pub const fn lower(self) -> Option<i64> {
        self.lo
    }

    /// The cap in px, if any.
    #[must_use]
    pub const fn upper(self) -> Option<i64> {
        self.hi
    }

    /// Clamp `v` into the interval after mapping each px bound through `to`.
    ///
    /// `to` must be monotone (px → px, or px → terminal cells), so the mapped
    /// floor never exceeds the mapped cap.
    #[must_use]
    pub fn clamp_with<T: Ord + Copy>(self, v: T, to: impl Fn(i64) -> T) -> T {
        let capped = self.hi.map_or(v, |h| v.min(to(h)));
        self.lo.map_or(capped, |l| capped.max(to(l)))
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

    /// One bound wrapper, as a program writes it.
    #[derive(Clone, Copy, Debug)]
    enum Op {
        AtLeast(i64),
        AtMost(i64),
    }

    /// Every op chain of depth `0..=max_depth`, innermost op first.
    fn chains(ops: &[Op], max_depth: usize) -> Vec<Vec<Op>> {
        let mut all: Vec<Vec<Op>> = vec![Vec::new()];
        let mut frontier: Vec<Vec<Op>> = vec![Vec::new()];
        for _ in 0..max_depth {
            let mut next = Vec::new();
            for chain in &frontier {
                for op in ops {
                    let mut longer = chain.clone();
                    longer.push(*op);
                    next.push(longer);
                }
            }
            all.extend(next.iter().cloned());
            frontier = next;
        }
        all
    }

    /// Refusal of the order-insensitive fold: for every chain of `minimum` /
    /// `maximum` wrappers up to depth 4, the folded interval clamps every size
    /// exactly as the nested composition does, and stays `0 <= lo <= hi`.
    #[test]
    fn px_bounds_fold_equals_nested_semantics() {
        let ns = [-5, 0, 40, 96, 200, i64::MAX];
        let ops: Vec<Op> = ns
            .iter()
            .flat_map(|n| [Op::AtLeast(*n), Op::AtMost(*n)])
            .collect();
        let sizes = [-1, 0, 39, 40, 97, 150, 250];
        for chain in chains(&ops, 4) {
            let bounds = chain.iter().fold(PxBounds::NONE, |b, op| match op {
                Op::AtLeast(n) => b.at_least(*n),
                Op::AtMost(n) => b.at_most(*n),
            });
            if let (Some(lo), Some(hi)) = (bounds.lower(), bounds.upper()) {
                assert!(lo <= hi, "{chain:?}: lo {lo} > hi {hi}");
            }
            assert!(bounds.lower().is_none_or(|lo| lo >= 0), "{chain:?}");
            assert!(bounds.upper().is_none_or(|hi| hi >= 0), "{chain:?}");
            for v in sizes {
                let nested = chain.iter().fold(v, |acc, op| match op {
                    Op::AtLeast(n) => acc.max((*n).max(0)),
                    Op::AtMost(n) => acc.min((*n).max(0)),
                });
                assert_eq!(bounds.clamp_with(v, |px| px), nested, "{chain:?} over {v}");
            }
        }
    }

    /// The fold keeps the outermost wrapper's word: `maximum 10 (minimum 30 x)`
    /// is exactly 10 for every `x`.
    #[test]
    fn maximum_outside_minimum_is_exact() {
        let b = PxBounds::NONE.at_least(30).at_most(10);
        assert_eq!((b.lower(), b.upper()), (Some(10), Some(10)));
        let b = PxBounds::NONE.at_most(-5);
        assert_eq!((b.lower(), b.upper()), (None, Some(0)));
    }
}
