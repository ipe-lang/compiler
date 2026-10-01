//! `Ipe.Color` — the single colour type shared by every Ipê surface.
//!
//! One opaque representation (sRGB with an alpha channel, each component a
//! `f64` clamped to `[0.0, 1.0]`) feeds CSS (`Ui`/`Html`/`Css`) via [`Color::to_css`],
//! hex via [`Color::to_hex`], and the terminal (`Tui`/`Cli`) via the single
//! down-sampling point [`Color::to_ansi`]. No surface re-derives how to spell a
//! colour, and no representable value is out of gamut: every constructor clamps
//! or parses at the boundary (parse-don't-validate), so an illegal colour has no
//! representation.
//!
//! sRGB is the interchange space of CSS, hex, and terminals, so the common
//! conversions are lossless and allocation-light; linear-light is computed only
//! where the maths needs it (WCAG luminance, perceptual `mix`), documented at
//! each site.

/// A colour: sRGB channels plus alpha, each held as an `f64` in `[0.0, 1.0]`.
///
/// The fields are private: the only way to obtain a `Color` is through a
/// constructor, all of which clamp or parse into the gamut, so no code path can
/// fabricate an out-of-range value (make-invalid-states-unrepresentable).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Color {
    r: f64,
    g: f64,
    b: f64,
    a: f64,
}

/// A typed parse error for the string-input constructors ([`Color::from_hex`],
/// [`Color::from_name`]). String input can be genuinely malformed, so it parses
/// to this typed channel rather than a silent bad colour.
#[derive(Clone, Debug, PartialEq)]
pub enum ColorError {
    /// A hex string contained a non-hex character.
    BadHexDigit(char),
    /// A hex string had a length that is not 3, 4, 6, or 8 (after an optional `#`).
    BadHexLength(i64),
    /// A name was not in the curated named-colour set.
    UnknownColorName(String),
}

/// The terminal capability profile that [`Color::to_ansi`] targets. Resolved
/// once, deterministically, and passed explicitly — never re-read from the
/// environment per style — so the same program yields the same SGR every run.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum TermProfile {
    /// 24-bit truecolour.
    TrueColor,
    /// The 256-colour xterm palette.
    Ansi256,
    /// The 16 SGR palette entries.
    Ansi16,
    /// No colour: everything degrades to the terminal default.
    NoColor,
}

/// The result of down-sampling a [`Color`] for a terminal: exactly the shape a
/// terminal backend renders (mirrors `ratatui::style::Color` / `termcolor`).
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum AnsiColor {
    /// The terminal's own default colour.
    Default,
    /// One of the 16 named SGR palette entries, by index `0..=15`.
    Named(i64),
    /// A 256-palette index `0..=255`.
    Indexed(i64),
    /// A 24-bit truecolour.
    Rgb(i64, i64, i64),
}

impl AnsiColor {
    /// The single portable SGR palette code for a `Named` entry: `30..=37`
    /// (`fg`) / `40..=47` (`bg`) for indices `0..=7`, and the bright base
    /// `90..=97` / `100..=107` for `8..=15`. The one place this palette
    /// arithmetic lives — the truecolour degradation path
    /// ([`crate::tui::layout`]) and the terminal-attribute translation
    /// ([`crate::tui`]) both read it here. `None` for the non-palette variants
    /// (`Default`, `Indexed`, `Rgb`), which each carry their own escape.
    #[must_use]
    pub fn named_sgr_code(self, fg: bool) -> Option<i64> {
        match self {
            AnsiColor::Named(idx) => {
                let idx = idx.clamp(0, 15);
                let (lo, hi) = if fg { (30, 90) } else { (40, 100) };
                Some(if idx < 8 { lo + idx } else { hi + (idx - 8) })
            }
            AnsiColor::Default | AnsiColor::Indexed(_) | AnsiColor::Rgb(..) => None,
        }
    }
}

/// A WCAG conformance level: the pass threshold `meets_wcag` checks against.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum WcagLevel {
    /// WCAG AA — `4.5:1` normal text, `3.0:1` large text.
    AA,
    /// WCAG AAA — `7.0:1` normal text, `4.5:1` large text.
    AAA,
}

/// The text size band a WCAG threshold applies to (large text tolerates a lower
/// ratio: `>=18pt`, or `>=14pt` bold).
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum TextSize {
    /// Normal-size body text.
    NormalText,
    /// Large text — `>=18pt`, or `>=14pt` bold.
    LargeText,
}

/// A colour-vision deficiency (CVD) type, for `simulate` previews.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Deficiency {
    /// Red-blind.
    Protanopia,
    /// Green-blind.
    Deuteranopia,
    /// Blue-blind.
    Tritanopia,
}

/// Clamp an `f64` into `[0.0, 1.0]`; a `NaN` maps to `0.0` (fail-closed).
fn clamp_unit(v: f64) -> f64 {
    if v.is_nan() { 0.0 } else { v.clamp(0.0, 1.0) }
}

/// Map a byte-oriented `i64` channel (`0..=255`) to the `[0,1]` float rep,
/// clamping out-of-range inputs into the byte range first.
fn byte_to_unit(v: i64) -> f64 {
    f64::from(v.clamp(0, 255) as u16) / 255.0
}

/// Round a `[0,1]` channel to its nearest `0..=255` byte for CSS / hex output.
fn unit_to_byte(v: f64) -> i64 {
    // `v` is already clamped into `[0,1]` at construction, so the product is in
    // `[0,255]`; `round` is total and the cast cannot overflow `i64`.
    (clamp_unit(v) * 255.0).round() as i64
}

impl Color {
    // ── Smart constructors (parse-don't-validate at the boundary) ────────────

    /// `Ipe.Color.rgb r g b` — byte channels `0..=255`, opaque. Out-of-range
    /// channels clamp into the byte range (the nearest legal colour).
    #[must_use]
    pub fn rgb(r: i64, g: i64, b: i64) -> Self {
        Self {
            r: byte_to_unit(r),
            g: byte_to_unit(g),
            b: byte_to_unit(b),
            a: 1.0,
        }
    }

    /// `Ipe.Color.rgba r g b a` — byte channels + alpha `0..1` (alpha clamped).
    #[must_use]
    pub fn rgba(r: i64, g: i64, b: i64, a: f64) -> Self {
        Self {
            r: byte_to_unit(r),
            g: byte_to_unit(g),
            b: byte_to_unit(b),
            a: clamp_unit(a),
        }
    }

    /// `Ipe.Color.fromRgba { red, green, blue, alpha }` — avh4-compatible float
    /// channels in `[0,1]` (clamped).
    #[must_use]
    pub fn from_rgba(red: f64, green: f64, blue: f64, alpha: f64) -> Self {
        Self {
            r: clamp_unit(red),
            g: clamp_unit(green),
            b: clamp_unit(blue),
            a: clamp_unit(alpha),
        }
    }

    /// `Ipe.Color.hsl h s l` — hue in degrees (wrapped mod 360), saturation and
    /// lightness as percentages `0..100` (clamped). Opaque.
    #[must_use]
    pub fn hsl(h: f64, s: f64, l: f64) -> Self {
        Self::hsla(h, s, l, 1.0)
    }

    /// `Ipe.Color.hsla h s l a` — HSL degrees/percent plus alpha `0..1`.
    #[must_use]
    pub fn hsla(h: f64, s: f64, l: f64, a: f64) -> Self {
        let (r, g, b) = hsl_to_rgb(h, clamp_unit(pct(s)), clamp_unit(pct(l)));
        Self {
            r,
            g,
            b,
            a: clamp_unit(a),
        }
    }

    /// `Ipe.Color.fromHsla { hue, saturation, lightness, alpha }` —
    /// avh4-compatible: saturation / lightness are `[0,1]` fractions, hue in
    /// degrees (wrapped).
    #[must_use]
    pub fn from_hsla(hue: f64, saturation: f64, lightness: f64, alpha: f64) -> Self {
        let (r, g, b) = hsl_to_rgb(hue, clamp_unit(saturation), clamp_unit(lightness));
        Self {
            r,
            g,
            b,
            a: clamp_unit(alpha),
        }
    }

    /// `Ipe.Color.hex "#rrggbb"` — parse a hex string (`#rgb`, `#rgba`,
    /// `#rrggbb`, `#rrggbbaa`; the leading `#` is optional) to a typed `Result`.
    ///
    /// # Errors
    /// Returns [`ColorError::BadHexLength`] if the digit count is not 3/4/6/8,
    /// or [`ColorError::BadHexDigit`] on the first non-hex character.
    pub fn from_hex(input: &str) -> Result<Self, ColorError> {
        let digits = input.strip_prefix('#').unwrap_or(input);
        let chars: Vec<char> = digits.chars().collect();
        // Each nibble parsed via a total helper (no indexing, no unwrap).
        let nib = |c: char| -> Result<u8, ColorError> {
            c.to_digit(16)
                .map(|d| d as u8)
                .ok_or(ColorError::BadHexDigit(c))
        };
        // Read two nibbles from an iterator position; the caller guarantees the
        // length, so a missing pair is an internal invariant, reported as the
        // matching length error rather than panicking.
        match chars.as_slice() {
            [r, g, b] => Ok(Self::rgb(short(nib(*r)?), short(nib(*g)?), short(nib(*b)?))),
            [r, g, b, a] => Ok(Self::rgba(
                short(nib(*r)?),
                short(nib(*g)?),
                short(nib(*b)?),
                byte_to_unit(short(nib(*a)?)),
            )),
            [r1, r0, g1, g0, b1, b0] => Ok(Self::rgb(
                pair(nib(*r1)?, nib(*r0)?),
                pair(nib(*g1)?, nib(*g0)?),
                pair(nib(*b1)?, nib(*b0)?),
            )),
            [r1, r0, g1, g0, b1, b0, a1, a0] => Ok(Self::rgba(
                pair(nib(*r1)?, nib(*r0)?),
                pair(nib(*g1)?, nib(*g0)?),
                pair(nib(*b1)?, nib(*b0)?),
                byte_to_unit(pair(nib(*a1)?, nib(*a0)?)),
            )),
            other => Err(ColorError::BadHexLength(other.len() as i64)),
        }
    }

    /// `Ipe.Color.fromName "red"` — look up a curated named colour.
    ///
    /// # Errors
    /// Returns [`ColorError::UnknownColorName`] if the name is not in the
    /// curated set (case-insensitive).
    pub fn from_name(name: &str) -> Result<Self, ColorError> {
        named_color(&name.to_ascii_lowercase())
            .ok_or_else(|| ColorError::UnknownColorName(name.to_owned()))
    }

    // ── Curated named palette (total, no failure) ────────────────────────────

    /// `Ipe.Color.white`.
    #[must_use]
    pub fn white() -> Self {
        Self::rgb(255, 255, 255)
    }
    /// `Ipe.Color.black`.
    #[must_use]
    pub fn black() -> Self {
        Self::rgb(0, 0, 0)
    }
    /// `Ipe.Color.red`.
    #[must_use]
    pub fn red() -> Self {
        Self::rgb(255, 0, 0)
    }
    /// `Ipe.Color.green`.
    #[must_use]
    pub fn green() -> Self {
        Self::rgb(0, 128, 0)
    }
    /// `Ipe.Color.blue`.
    #[must_use]
    pub fn blue() -> Self {
        Self::rgb(0, 0, 255)
    }
    /// `Ipe.Color.transparent` — fully transparent black.
    #[must_use]
    pub fn transparent() -> Self {
        Self::rgba(0, 0, 0, 0.0)
    }

    // ── Conversions OUT — the SSOT feeds every surface ───────────────────────

    /// `Ipe.Color.toCss` — canonical CSS: `rgb(r,g,b)` when opaque, else
    /// `rgba(r,g,b,a)`. The `a`-format matches the pre-existing `Ui`/`Css`
    /// spelling (`'g'`-style float: `1.0`→`1`, `0.5`→`0.5`) so shared goldens
    /// stay byte-exact.
    #[must_use]
    pub fn to_css(&self) -> String {
        let (r, g, b) = (
            unit_to_byte(self.r),
            unit_to_byte(self.g),
            unit_to_byte(self.b),
        );
        if (self.a - 1.0).abs() < f64::EPSILON {
            format!("rgb({r},{g},{b})")
        } else {
            // `'g'`-style float spelling (`0.5`→`0.5`), matching the pre-existing
            // `Ui`/`Css` alpha format so shared CSS goldens stay byte-exact.
            format!("rgba({r},{g},{b},{})", self.a)
        }
    }

    /// The always-`rgba(r,g,b,a)` CSS spelling — the exact form the `Ipe.Ui` and
    /// `Ipe.Css` surfaces have always emitted (alpha never collapses to `rgb(…)`).
    /// This is the shared renderer both DOM surfaces call so a single site owns
    /// how a colour is spelled for CSS; [`Color::to_css`] is the newer
    /// alpha-collapsing form reserved for surfaces that opt into it.
    ///
    /// Alpha is spelled with the default `f64` `Display` (`1.0`→`1`, `0.5`→`0.5`),
    /// matching the pre-existing `Ui`/`Css` byte-for-byte so shared CSS goldens
    /// stay exact.
    #[must_use]
    pub fn to_css_rgba(&self) -> String {
        let (r, g, b) = (
            unit_to_byte(self.r),
            unit_to_byte(self.g),
            unit_to_byte(self.b),
        );
        format!("rgba({r},{g},{b},{})", self.a)
    }

    /// `Ipe.Color.toHex` — `#rrggbb`, or `#rrggbbaa` when alpha `< 1`.
    #[must_use]
    pub fn to_hex(&self) -> String {
        let (r, g, b) = (
            unit_to_byte(self.r),
            unit_to_byte(self.g),
            unit_to_byte(self.b),
        );
        if (self.a - 1.0).abs() < f64::EPSILON {
            format!("#{r:02x}{g:02x}{b:02x}")
        } else {
            format!("#{r:02x}{g:02x}{b:02x}{:02x}", unit_to_byte(self.a))
        }
    }

    /// `Ipe.Color.toRgba` — read back the float channels (avh4 parity).
    /// Returns `(red, green, blue, alpha)` in `[0,1]`.
    #[must_use]
    pub fn to_rgba(&self) -> (f64, f64, f64, f64) {
        (self.r, self.g, self.b, self.a)
    }

    /// Read back as byte channels `(r, g, b, a)`: `r`/`g`/`b` in `0..=255`, `a`
    /// as the stored `[0,1]` float. The exact round-trip of the byte
    /// constructors ([`Color::rgb`] / [`Color::rgba`]), so a surface that stores
    /// a colour in byte form (the persisted UI template) rebuilds the same value.
    #[must_use]
    pub fn to_rgba_bytes(&self) -> (i64, i64, i64, f64) {
        (
            unit_to_byte(self.r),
            unit_to_byte(self.g),
            unit_to_byte(self.b),
            self.a,
        )
    }

    /// `Ipe.Color.toHsla` — read back as `(hue-degrees, saturation, lightness,
    /// alpha)`, saturation/lightness as `[0,1]` fractions.
    #[must_use]
    pub fn to_hsla(&self) -> (f64, f64, f64, f64) {
        let (h, s, l) = rgb_to_hsl(self.r, self.g, self.b);
        (h, s, l, self.a)
    }

    // ── Terminal degradation — the single down-sampling point ────────────────

    /// `Ipe.Color.toAnsi profile` — the one truecolour→256→16 degradation,
    /// shared by both `Tui` and `Cli`. Deterministic for a given profile.
    ///
    /// A fully-transparent colour degrades to the terminal default (a terminal
    /// cell has no alpha channel).
    #[must_use]
    pub fn to_ansi(&self, profile: TermProfile) -> AnsiColor {
        if self.a <= 0.0 {
            return AnsiColor::Default;
        }
        let (r, g, b) = (
            unit_to_byte(self.r),
            unit_to_byte(self.g),
            unit_to_byte(self.b),
        );
        match profile {
            TermProfile::NoColor => AnsiColor::Default,
            TermProfile::TrueColor => AnsiColor::Rgb(r, g, b),
            TermProfile::Ansi256 => AnsiColor::Indexed(nearest_256(r, g, b)),
            TermProfile::Ansi16 => AnsiColor::Named(nearest_16(r, g, b)),
        }
    }

    // ── Manipulation (all total, all returning `Color`) ──────────────────────

    /// `Ipe.Color.withAlpha a` — replace the alpha channel (clamped `0..1`).
    #[must_use]
    pub fn with_alpha(&self, a: f64) -> Self {
        Self {
            a: clamp_unit(a),
            ..*self
        }
    }

    /// `Ipe.Color.mix t a b` — perceptual (linear-light) blend, `t` in `[0,1]`.
    /// `t = 0` yields `a`, `t = 1` yields `b`.
    #[must_use]
    pub fn mix(t: f64, a: Self, b: Self) -> Self {
        let t = clamp_unit(t);
        // Return the endpoints exactly: the sRGB↔linear round-trip is not the
        // identity in float, so `t = 0`/`t = 1` must short-circuit to stay exact.
        if t <= 0.0 {
            return a;
        }
        if t >= 1.0 {
            return b;
        }
        let lerp_lin = |x: f64, y: f64| to_srgb(to_linear(x) * (1.0 - t) + to_linear(y) * t);
        Self {
            r: clamp_unit(lerp_lin(a.r, b.r)),
            g: clamp_unit(lerp_lin(a.g, b.g)),
            b: clamp_unit(lerp_lin(a.b, b.b)),
            a: clamp_unit(a.a * (1.0 - t) + b.a * t),
        }
    }

    /// `Ipe.Color.blend src dst` — straight-alpha source-over compositing.
    #[must_use]
    pub fn blend(src: Self, dst: Self) -> Self {
        let out_a = src.a + dst.a * (1.0 - src.a);
        if out_a <= 0.0 {
            return Self::transparent();
        }
        let over = |s: f64, d: f64| (s * src.a + d * dst.a * (1.0 - src.a)) / out_a;
        Self {
            r: clamp_unit(over(src.r, dst.r)),
            g: clamp_unit(over(src.g, dst.g)),
            b: clamp_unit(over(src.b, dst.b)),
            a: clamp_unit(out_a),
        }
    }

    /// `Ipe.Color.lighten amount` — add `amount` to HSL lightness (clamped).
    #[must_use]
    pub fn lighten(&self, amount: f64) -> Self {
        let (h, s, l) = rgb_to_hsl(self.r, self.g, self.b);
        Self::from_hsla(h, s, clamp_unit(l + amount), self.a)
    }

    /// `Ipe.Color.darken amount` — subtract `amount` from HSL lightness.
    #[must_use]
    pub fn darken(&self, amount: f64) -> Self {
        self.lighten(-amount)
    }

    /// `Ipe.Color.saturate amount` — add `amount` to HSL saturation (clamped).
    #[must_use]
    pub fn saturate(&self, amount: f64) -> Self {
        let (h, s, l) = rgb_to_hsl(self.r, self.g, self.b);
        Self::from_hsla(h, clamp_unit(s + amount), l, self.a)
    }

    /// `Ipe.Color.desaturate amount` — subtract `amount` from HSL saturation.
    #[must_use]
    pub fn desaturate(&self, amount: f64) -> Self {
        self.saturate(-amount)
    }

    /// `Ipe.Color.rotateHue degrees` — rotate hue by `degrees` (wrapped 360).
    #[must_use]
    pub fn rotate_hue(&self, degrees: f64) -> Self {
        let (h, s, l) = rgb_to_hsl(self.r, self.g, self.b);
        Self::from_hsla(h + degrees, s, l, self.a)
    }

    /// `Ipe.Color.complementary` — hue rotated 180°.
    #[must_use]
    pub fn complementary(&self) -> Self {
        self.rotate_hue(180.0)
    }

    /// `Ipe.Color.grayscale` — luminance-preserving full desaturation.
    #[must_use]
    pub fn grayscale(&self) -> Self {
        let (h, _s, l) = rgb_to_hsl(self.r, self.g, self.b);
        Self::from_hsla(h, 0.0, l, self.a)
    }

    // ── Accessibility (WCAG) ─────────────────────────────────────────────────

    /// `Ipe.Color.luminance` — WCAG relative luminance (linear-light, `0..1`).
    #[must_use]
    pub fn luminance(&self) -> f64 {
        0.2126 * to_linear(self.r) + 0.7152 * to_linear(self.g) + 0.0722 * to_linear(self.b)
    }

    /// `Ipe.Color.contrastRatio a b` — WCAG `(L1+0.05)/(L2+0.05)`, `1.0..21.0`.
    #[must_use]
    pub fn contrast_ratio(a: Self, b: Self) -> f64 {
        let (la, lb) = (a.luminance(), b.luminance());
        let (hi, lo) = if la >= lb { (la, lb) } else { (lb, la) };
        (hi + 0.05) / (lo + 0.05)
    }

    /// `Ipe.Color.readableTextOn bg` — pick black or white for max contrast.
    #[must_use]
    pub fn readable_text_on(bg: Self) -> Self {
        let on_black = Self::contrast_ratio(Self::black(), bg);
        let on_white = Self::contrast_ratio(Self::white(), bg);
        if on_black >= on_white {
            Self::black()
        } else {
            Self::white()
        }
    }

    /// `Ipe.Color.meetsWCAG level size fg bg` — does the `fg`/`bg` pair meet the
    /// WCAG contrast threshold for `level` at `size`? AA is `4.5`(normal)/`3.0`
    /// (large); AAA is `7.0`/`4.5`.
    #[must_use]
    pub fn meets_wcag(level: WcagLevel, size: TextSize, fg: Self, bg: Self) -> bool {
        let threshold = match (level, size) {
            (WcagLevel::AA, TextSize::NormalText) => 4.5,
            (WcagLevel::AA, TextSize::LargeText) => 3.0,
            (WcagLevel::AAA, TextSize::NormalText) => 7.0,
            (WcagLevel::AAA, TextSize::LargeText) => 4.5,
        };
        Self::contrast_ratio(fg, bg) >= threshold
    }

    /// `Ipe.Color.maximumContrast target candidates` — the candidate with the
    /// greatest contrast against `target` (gleam parity). An empty candidate
    /// list yields [`readable_text_on`](Self::readable_text_on) as the safe
    /// fallback, so the result is always a legible colour.
    #[must_use]
    pub fn maximum_contrast(target: Self, candidates: &[Self]) -> Self {
        let mut best: Option<(f64, Self)> = None;
        for &c in candidates {
            let ratio = Self::contrast_ratio(target, c);
            if best.is_none_or(|(bd, _)| ratio > bd) {
                best = Some((ratio, c));
            }
        }
        best.map_or_else(|| Self::readable_text_on(target), |(_, c)| c)
    }

    /// `Ipe.Color.simulate deficiency` — simulate how a colour is perceived under
    /// a colour-vision deficiency (for previews and tests). Uses the Brettel/
    /// Viénot LMS-projection matrices applied in linear-light sRGB.
    #[must_use]
    pub fn simulate(&self, deficiency: Deficiency) -> Self {
        // Convert to linear-light, project onto the confusion plane with the
        // published CVD matrix, convert back. Alpha is untouched.
        let (lr, lg, lb) = (to_linear(self.r), to_linear(self.g), to_linear(self.b));
        // Row-major 3x3 simulation matrices (Viénot, Brettel & Mollon 1999),
        // operating on linear-light RGB.
        let m: [[f64; 3]; 3] = match deficiency {
            Deficiency::Protanopia => [
                [0.152_286, 1.052_583, -0.204_868],
                [0.114_503, 0.786_281, 0.099_216],
                [-0.003_882, -0.048_116, 1.051_998],
            ],
            Deficiency::Deuteranopia => [
                [0.367_322, 0.860_646, -0.227_968],
                [0.280_085, 0.672_501, 0.047_413],
                [-0.011_820, 0.042_940, 0.968_881],
            ],
            Deficiency::Tritanopia => [
                [1.255_528, -0.076_749, -0.178_779],
                [-0.078_411, 0.930_809, 0.147_602],
                [0.004_733, 0.691_367, 0.303_900],
            ],
        };
        let apply = |row: [f64; 3]| row[0] * lr + row[1] * lg + row[2] * lb;
        Self {
            r: clamp_unit(to_srgb(clamp_unit(apply(m[0])))),
            g: clamp_unit(to_srgb(clamp_unit(apply(m[1])))),
            b: clamp_unit(to_srgb(clamp_unit(apply(m[2])))),
            a: self.a,
        }
    }

    /// `Ipe.Color.gradient n a b` — `n` perceptual (linear-light) steps from `a`
    /// to `b` inclusive. `n < 2` yields just the endpoints (`[a, b]`), never an
    /// empty or single-element list, so downstream code always has both ends.
    #[must_use]
    pub fn gradient(n: i64, a: Self, b: Self) -> Vec<Self> {
        if n < 2 {
            return vec![a, b];
        }
        // `n >= 2`, so `n - 1 >= 1`; the division is well-defined and the loop
        // yields exactly `n` stops with the first `a` and the last `b`.
        let last = n - 1;
        (0..n)
            .map(|i| {
                let t = i as f64 / last as f64;
                Self::mix(t, a, b)
            })
            .collect()
    }

    /// `Ipe.Color.steps n stops` — resample a stop list to exactly `n` evenly
    /// spaced perceptual samples across the piecewise-linear path through
    /// `stops`. An empty `stops` yields an empty list; a single stop yields that
    /// colour repeated `n` times.
    #[must_use]
    pub fn steps(n: i64, stops: &[Self]) -> Vec<Self> {
        if n <= 0 || stops.is_empty() {
            return Vec::new();
        }
        let seg_count = stops.len() - 1;
        if seg_count == 0 || n == 1 {
            // One stop, or one requested sample: repeat / take the first stop.
            // `stops` is non-empty, so `first()` is `Some`.
            let head = stops.first().copied().unwrap_or_else(Self::transparent);
            return (0..n).map(|_| head).collect();
        }
        // Map each output index `i` in `0..n` to a position `p` in `[0, seg_count]`
        // along the stop path, then interpolate within the enclosing segment.
        let last = n - 1;
        (0..n)
            .map(|i| {
                let frac = i as f64 / last as f64; // 0..1 inclusive
                let pos = frac * seg_count as f64; // 0..seg_count
                let idx = (pos.floor() as usize).min(seg_count - 1);
                let local = pos - idx as f64;
                // `idx <= seg_count - 1` and `idx + 1 <= seg_count = len - 1`, so
                // both lookups are in bounds; `get` keeps it total regardless.
                let lo = stops.get(idx).copied().unwrap_or_else(Self::transparent);
                let hi = stops
                    .get(idx + 1)
                    .copied()
                    .unwrap_or_else(Self::transparent);
                Self::mix(local, lo, hi)
            })
            .collect()
    }
}

/// Expand a single hex nibble to a byte by digit-doubling (`f`→`0xff`).
fn short(n: u8) -> i64 {
    i64::from(n) * 16 + i64::from(n)
}

/// Combine two hex nibbles into a byte value.
fn pair(hi: u8, lo: u8) -> i64 {
    i64::from(hi) * 16 + i64::from(lo)
}

/// Interpret a percentage `0..100` as a `[0,1]` fraction (unclamped; the caller
/// clamps).
fn pct(v: f64) -> f64 {
    v / 100.0
}

/// sRGB → linear-light for one channel (WCAG / perceptual maths).
fn to_linear(c: f64) -> f64 {
    if c <= 0.040_45 {
        c / 12.92
    } else {
        ((c + 0.055) / 1.055).powf(2.4)
    }
}

/// linear-light → sRGB for one channel.
fn to_srgb(c: f64) -> f64 {
    if c <= 0.003_130_8 {
        c * 12.92
    } else {
        1.055 * c.powf(1.0 / 2.4) - 0.055
    }
}

/// HSL (hue degrees wrapped; s,l fractions in `[0,1]`) → sRGB `[0,1]` channels.
fn hsl_to_rgb(h_deg: f64, s: f64, l: f64) -> (f64, f64, f64) {
    let h = h_deg.rem_euclid(360.0) / 360.0;
    if s <= 0.0 {
        return (l, l, l);
    }
    let q = if l < 0.5 {
        l * (1.0 + s)
    } else {
        l + s - l * s
    };
    let p = 2.0 * l - q;
    let hue = |t: f64| -> f64 {
        let t = t.rem_euclid(1.0);
        if t < 1.0 / 6.0 {
            p + (q - p) * 6.0 * t
        } else if t < 1.0 / 2.0 {
            q
        } else if t < 2.0 / 3.0 {
            p + (q - p) * (2.0 / 3.0 - t) * 6.0
        } else {
            p
        }
    };
    (hue(h + 1.0 / 3.0), hue(h), hue(h - 1.0 / 3.0))
}

/// sRGB `[0,1]` channels → HSL `(hue-degrees, saturation, lightness)`.
fn rgb_to_hsl(r: f64, g: f64, b: f64) -> (f64, f64, f64) {
    let max = r.max(g).max(b);
    let min = r.min(g).min(b);
    let l = (max + min) / 2.0;
    let d = max - min;
    if d <= 0.0 {
        return (0.0, 0.0, l);
    }
    let s = if l > 0.5 {
        d / (2.0 - max - min)
    } else {
        d / (max + min)
    };
    let h = if (max - r).abs() < f64::EPSILON {
        (g - b) / d + if g < b { 6.0 } else { 0.0 }
    } else if (max - g).abs() < f64::EPSILON {
        (b - r) / d + 2.0
    } else {
        (r - g) / d + 4.0
    };
    (h * 60.0, s, l)
}

/// The 16 SGR palette in sRGB bytes, indexed `0..=15` (standard xterm values).
const PALETTE_16: [(i64, i64, i64); 16] = [
    (0, 0, 0),
    (128, 0, 0),
    (0, 128, 0),
    (128, 128, 0),
    (0, 0, 128),
    (128, 0, 128),
    (0, 128, 128),
    (192, 192, 192),
    (128, 128, 128),
    (255, 0, 0),
    (0, 255, 0),
    (255, 255, 0),
    (0, 0, 255),
    (255, 0, 255),
    (0, 255, 255),
    (255, 255, 255),
];

/// Squared Euclidean distance between two sRGB byte triples.
fn dist2(a: (i64, i64, i64), b: (i64, i64, i64)) -> i64 {
    let dr = a.0 - b.0;
    let dg = a.1 - b.1;
    let db = a.2 - b.2;
    dr * dr + dg * dg + db * db
}

/// Nearest of the 16 SGR palette entries by squared sRGB distance.
fn nearest_16(r: i64, g: i64, b: i64) -> i64 {
    let mut best = 0i64;
    let mut best_d = i64::MAX;
    for (i, &p) in PALETTE_16.iter().enumerate() {
        let d = dist2((r, g, b), p);
        if d < best_d {
            best_d = d;
            best = i as i64;
        }
    }
    best
}

/// Nearest xterm-256 index: the 6×6×6 colour cube (`16..=231`) or the greyscale
/// ramp (`232..=255`), whichever is closer.
fn nearest_256(r: i64, g: i64, b: i64) -> i64 {
    // 6-level cube: the canonical xterm level values.
    let levels = [0i64, 95, 135, 175, 215, 255];
    let nearest_level = |v: i64| -> usize {
        let mut best = 0usize;
        let mut best_d = i64::MAX;
        for (i, &lv) in levels.iter().enumerate() {
            let d = (v - lv) * (v - lv);
            if d < best_d {
                best_d = d;
                best = i;
            }
        }
        best
    };
    let (ri, gi, bi) = (nearest_level(r), nearest_level(g), nearest_level(b));
    let cube_index = 16 + 36 * ri as i64 + 6 * gi as i64 + bi as i64;
    // `ri`, `gi`, `bi` each come from `nearest_level`, which scans `levels`
    // (length 6) and only updates the index inside the iteration — the result
    // is always a valid index into `levels`.
    let cube_rgb = (
        levels.get(ri).copied().unwrap_or(255),
        levels.get(gi).copied().unwrap_or(255),
        levels.get(bi).copied().unwrap_or(255),
    );
    let cube_d = dist2((r, g, b), cube_rgb);

    // Greyscale ramp 232..=255: grey level 8 + 10*n for n in 0..24.
    let grey_avg = (r + g + b) / 3;
    let grey_n = ((grey_avg - 8).clamp(0, 238) + 5) / 10;
    let grey_n = grey_n.clamp(0, 23);
    let grey_v = 8 + 10 * grey_n;
    let grey_index = 232 + grey_n;
    let grey_d = dist2((r, g, b), (grey_v, grey_v, grey_v));

    if grey_d < cube_d {
        grey_index
    } else {
        cube_index
    }
}

/// Resolve the terminal colour capability once, deterministically, from the
/// environment — the single place `Tui`/`Cli` decide how far a truecolour must
/// degrade (the lipgloss/termenv resolution order, made total and explicit).
///
/// * `NO_COLOR` set (any value, per <https://no-color.org>) → [`TermProfile::NoColor`].
/// * `COLORTERM` = `truecolor` / `24bit` → [`TermProfile::TrueColor`].
/// * `TERM` containing `256color` → [`TermProfile::Ansi256`].
/// * `TERM` = `dumb` → [`TermProfile::NoColor`].
/// * otherwise → [`TermProfile::TrueColor`] — the conservative default keeps the
///   full-fidelity `38;2;r;g;b` path (and every existing terminal golden) intact
///   unless the environment explicitly asks for less.
#[must_use]
pub fn resolve_term_profile() -> TermProfile {
    // `NO_COLOR` present and non-empty (<https://no-color.org>) forces no colour,
    // matching the terminal renderer's own `no_color()` gate.
    if matches!(crate::system::read_env_var("NO_COLOR"), Ok(v) if !v.is_empty()) {
        return TermProfile::NoColor;
    }
    if let Ok(ct) = crate::system::read_env_var("COLORTERM") {
        let ct = ct.to_ascii_lowercase();
        if ct == "truecolor" || ct == "24bit" {
            return TermProfile::TrueColor;
        }
    }
    match crate::system::read_env_var("TERM") {
        Ok(term) if term == "dumb" => TermProfile::NoColor,
        Ok(term) if term.contains("256color") => TermProfile::Ansi256,
        _ => TermProfile::TrueColor,
    }
}

/// The curated named-colour set (`fromName`). Deliberately small — the CSS
/// Level-4 basic + common set, not all 148 names. Community palettes ship their
/// own tables returning `Color` values.
fn named_color(lower: &str) -> Option<Color> {
    let c = match lower {
        "black" => Color::black(),
        "white" => Color::white(),
        "red" => Color::red(),
        "green" => Color::green(),
        "blue" => Color::blue(),
        "transparent" => Color::transparent(),
        "yellow" => Color::rgb(255, 255, 0),
        "cyan" | "aqua" => Color::rgb(0, 255, 255),
        "magenta" | "fuchsia" => Color::rgb(255, 0, 255),
        "gray" | "grey" => Color::rgb(128, 128, 128),
        "silver" => Color::rgb(192, 192, 192),
        "maroon" => Color::rgb(128, 0, 0),
        "olive" => Color::rgb(128, 128, 0),
        "lime" => Color::rgb(0, 255, 0),
        "teal" => Color::rgb(0, 128, 128),
        "navy" => Color::rgb(0, 0, 128),
        "purple" => Color::rgb(128, 0, 128),
        "orange" => Color::rgb(255, 165, 0),
        _ => return None,
    };
    Some(c)
}

impl crate::stringify::IpeStringify for Color {
    fn ipe_show(&self) -> String {
        self.to_hex()
    }
}

impl crate::stringify::IpeStringify for ColorError {
    fn ipe_show(&self) -> String {
        match self {
            ColorError::BadHexDigit(c) => format!("BadHexDigit {c}"),
            ColorError::BadHexLength(n) => format!("BadHexLength {n}"),
            ColorError::UnknownColorName(s) => format!("UnknownColorName {s}"),
        }
    }
}

impl crate::stringify::IpeStringify for TermProfile {
    fn ipe_show(&self) -> String {
        "<term-profile>".to_owned()
    }
}

impl crate::stringify::IpeStringify for AnsiColor {
    fn ipe_show(&self) -> String {
        "<ansi-color>".to_owned()
    }
}

impl crate::stringify::IpeStringify for WcagLevel {
    fn ipe_show(&self) -> String {
        match self {
            WcagLevel::AA => "AA".to_owned(),
            WcagLevel::AAA => "AAA".to_owned(),
        }
    }
}

impl crate::stringify::IpeStringify for TextSize {
    fn ipe_show(&self) -> String {
        match self {
            TextSize::NormalText => "NormalText".to_owned(),
            TextSize::LargeText => "LargeText".to_owned(),
        }
    }
}

impl crate::stringify::IpeStringify for Deficiency {
    fn ipe_show(&self) -> String {
        match self {
            Deficiency::Protanopia => "Protanopia".to_owned(),
            Deficiency::Deuteranopia => "Deuteranopia".to_owned(),
            Deficiency::Tritanopia => "Tritanopia".to_owned(),
        }
    }
}

// ── Ipe.Color kernel shims ──────────────────────────────────────────────────
//
// The backend emits a free-function call per `Ipe.Color` kernel (the emit symbol
// in `ipe_kernels::StdlibKernel::def().runtime_fn`). Each shim is a thin
// passthrough to the corresponding `Color` associated function or method — the
// algorithm lives ONLY on `Color`, so no colour maths is duplicated at the emit
// boundary. Data-last argument order (colour last) matches the Ipê pipe idiom.

/// `Color.rgb : Int -> Int -> Int -> Color`
#[must_use]
pub fn color_rgb(r: i64, g: i64, b: i64) -> Color {
    Color::rgb(r, g, b)
}

/// `Color.rgba : Int -> Int -> Int -> Float -> Color`
#[must_use]
pub fn color_rgba(r: i64, g: i64, b: i64, a: f64) -> Color {
    Color::rgba(r, g, b, a)
}

/// `Color.hsl : Float -> Float -> Float -> Color`
#[must_use]
pub fn color_hsl(h: f64, s: f64, l: f64) -> Color {
    Color::hsl(h, s, l)
}

/// `Color.hsla : Float -> Float -> Float -> Float -> Color`
#[must_use]
pub fn color_hsla(h: f64, s: f64, l: f64, a: f64) -> Color {
    Color::hsla(h, s, l, a)
}

/// `Color.white : Color`
#[must_use]
pub fn color_white() -> Color {
    Color::white()
}

/// `Color.black : Color`
#[must_use]
pub fn color_black() -> Color {
    Color::black()
}

/// `Color.red : Color`
#[must_use]
pub fn color_red() -> Color {
    Color::red()
}

/// `Color.green : Color`
#[must_use]
pub fn color_green() -> Color {
    Color::green()
}

/// `Color.blue : Color`
#[must_use]
pub fn color_blue() -> Color {
    Color::blue()
}

/// `Color.transparent : Color`
#[must_use]
pub fn color_transparent() -> Color {
    Color::transparent()
}

// ── Ipe.Color accessors ─────────────────────────────────────────────────────

/// `Color.toCss : Color -> String`
#[must_use]
pub fn color_to_css(c: Color) -> String {
    c.to_css()
}

/// `Color.toCssRgba : Color -> String`
#[must_use]
pub fn color_to_css_rgba(c: Color) -> String {
    c.to_css_rgba()
}

/// `Color.toHex : Color -> String`
#[must_use]
pub fn color_to_hex(c: Color) -> String {
    c.to_hex()
}

/// `Color.luminance : Color -> Float`
#[must_use]
pub fn color_luminance(c: Color) -> f64 {
    c.luminance()
}

// ── Ipe.Color manipulation (data-last: the subject colour is the final arg) ──

/// `Color.withAlpha : Float -> Color -> Color`
#[must_use]
pub fn color_with_alpha(a: f64, c: Color) -> Color {
    c.with_alpha(a)
}

/// `Color.mix : Float -> Color -> Color -> Color`
#[must_use]
pub fn color_mix(t: f64, a: Color, b: Color) -> Color {
    Color::mix(t, a, b)
}

/// `Color.blend : Color -> Color -> Color` (source-over)
#[must_use]
pub fn color_blend(src: Color, dst: Color) -> Color {
    Color::blend(src, dst)
}

/// `Color.lighten : Float -> Color -> Color`
#[must_use]
pub fn color_lighten(amount: f64, c: Color) -> Color {
    c.lighten(amount)
}

/// `Color.darken : Float -> Color -> Color`
#[must_use]
pub fn color_darken(amount: f64, c: Color) -> Color {
    c.darken(amount)
}

/// `Color.saturate : Float -> Color -> Color`
#[must_use]
pub fn color_saturate(amount: f64, c: Color) -> Color {
    c.saturate(amount)
}

/// `Color.desaturate : Float -> Color -> Color`
#[must_use]
pub fn color_desaturate(amount: f64, c: Color) -> Color {
    c.desaturate(amount)
}

/// `Color.rotateHue : Float -> Color -> Color`
#[must_use]
pub fn color_rotate_hue(degrees: f64, c: Color) -> Color {
    c.rotate_hue(degrees)
}

/// `Color.complementary : Color -> Color`
#[must_use]
pub fn color_complementary(c: Color) -> Color {
    c.complementary()
}

/// `Color.grayscale : Color -> Color`
#[must_use]
pub fn color_grayscale(c: Color) -> Color {
    c.grayscale()
}

// ── Ipe.Color parse boundary (typed `Result ColorError Color`) ──────────────
//
// String input is genuinely untrusted, so it parses to the typed `ColorError`
// channel rather than a silent bad colour (parse-don't-validate, fail-closed):
// a malformed hex or an unknown name is turned back with the typed error the
// runtime SSOT (`Color::from_hex` / `Color::from_name`) already produces. No
// parsing is re-implemented at the emit boundary. The shim returns the Ipê
// `IpeResult<E, A>` carrier the emitted `case` arms match on (error type first),
// with `ColorError` as the concrete error — never the std `Result`.

/// `Color.fromHex : String -> Result ColorError Color`
#[must_use]
pub fn color_from_hex(input: String) -> crate::core::IpeResult<ColorError, Color> {
    match Color::from_hex(&input) {
        Ok(c) => crate::core::IpeResult::Ok(c),
        Err(e) => crate::core::IpeResult::Err(e),
    }
}

/// `Color.fromName : String -> Result ColorError Color`
#[must_use]
pub fn color_from_name(name: String) -> crate::core::IpeResult<ColorError, Color> {
    match Color::from_name(&name) {
        Ok(c) => crate::core::IpeResult::Ok(c),
        Err(e) => crate::core::IpeResult::Err(e),
    }
}

// ── Ipe.Color terminal-profile constructors (nullary `TermProfile`) ──────────

/// `Color.trueColorProfile : TermProfile`
#[must_use]
pub fn color_true_color_profile() -> TermProfile {
    TermProfile::TrueColor
}

/// `Color.ansi256Profile : TermProfile`
#[must_use]
pub fn color_ansi256_profile() -> TermProfile {
    TermProfile::Ansi256
}

/// `Color.ansi16Profile : TermProfile`
#[must_use]
pub fn color_ansi16_profile() -> TermProfile {
    TermProfile::Ansi16
}

/// `Color.noColorProfile : TermProfile`
#[must_use]
pub fn color_no_color_profile() -> TermProfile {
    TermProfile::NoColor
}

/// `Color.toAnsi : TermProfile -> Color -> AnsiColor`
///
/// The single truecolour→256→16 down-sampling point; `to_ansi` on `Color` is the
/// nearest-16 SSOT, never a re-derived brightness threshold here.
#[must_use]
pub fn color_to_ansi(profile: TermProfile, c: Color) -> AnsiColor {
    c.to_ansi(profile)
}

// ── Ipe.Color WCAG / contrast (a11y) ─────────────────────────────────────────

/// `Color.wcagAa : WcagLevel`
#[must_use]
pub fn color_wcag_aa() -> WcagLevel {
    WcagLevel::AA
}

/// `Color.wcagAaa : WcagLevel`
#[must_use]
pub fn color_wcag_aaa() -> WcagLevel {
    WcagLevel::AAA
}

/// `Color.normalText : TextSize`
#[must_use]
pub fn color_normal_text() -> TextSize {
    TextSize::NormalText
}

/// `Color.largeText : TextSize`
#[must_use]
pub fn color_large_text() -> TextSize {
    TextSize::LargeText
}

/// `Color.contrastRatio : Color -> Color -> Float`
#[must_use]
pub fn color_contrast_ratio(a: Color, b: Color) -> f64 {
    Color::contrast_ratio(a, b)
}

/// `Color.readableTextOn : Color -> Color` — black or white, whichever contrasts
/// more against the background.
#[must_use]
pub fn color_readable_text_on(bg: Color) -> Color {
    Color::readable_text_on(bg)
}

/// `Color.meetsWcag : WcagLevel -> TextSize -> Color -> Color -> Bool`
#[must_use]
pub fn color_meets_wcag(level: WcagLevel, size: TextSize, fg: Color, bg: Color) -> bool {
    Color::meets_wcag(level, size, fg, bg)
}

/// `Color.maximumContrast : Color -> List Color -> Color` — the candidate with
/// the highest contrast against `target` (the target itself on an empty list).
#[must_use]
pub fn color_maximum_contrast(target: Color, candidates: Vec<Color>) -> Color {
    Color::maximum_contrast(target, &candidates)
}

// ── Ipe.Color colour-vision-deficiency simulation ────────────────────────────

/// `Color.protanopia : Deficiency`
#[must_use]
pub fn color_protanopia() -> Deficiency {
    Deficiency::Protanopia
}

/// `Color.deuteranopia : Deficiency`
#[must_use]
pub fn color_deuteranopia() -> Deficiency {
    Deficiency::Deuteranopia
}

/// `Color.tritanopia : Deficiency`
#[must_use]
pub fn color_tritanopia() -> Deficiency {
    Deficiency::Tritanopia
}

/// `Color.simulate : Deficiency -> Color -> Color` — preview `c` under a
/// colour-vision deficiency.
#[must_use]
pub fn color_simulate(deficiency: Deficiency, c: Color) -> Color {
    c.simulate(deficiency)
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;

    #[test]
    fn rgb_clamps_out_of_range_channels() {
        assert_eq!(Color::rgb(-5, 300, 128), Color::rgb(0, 255, 128));
    }

    #[test]
    fn to_css_matches_pre_existing_spelling() {
        assert_eq!(Color::rgb(0, 128, 255).to_css(), "rgb(0,128,255)");
        assert_eq!(
            Color::rgba(255, 128, 0, 0.5).to_css(),
            "rgba(255,128,0,0.5)"
        );
        // opaque alpha collapses to rgb()
        assert_eq!(Color::rgba(0, 0, 0, 1.0).to_css(), "rgb(0,0,0)");
    }

    #[test]
    fn to_css_rgba_never_collapses_alpha() {
        // The shared DOM spelling: alpha always present, `1.0`→`1` (byte-exact
        // with the pre-existing `Ui`/`Css` `rgba(…)` goldens).
        assert_eq!(Color::rgba(0, 0, 0, 1.0).to_css_rgba(), "rgba(0,0,0,1)");
        assert_eq!(Color::rgba(255, 0, 0, 1.0).to_css_rgba(), "rgba(255,0,0,1)");
        assert_eq!(
            Color::rgba(0, 128, 255, 1.0).to_css_rgba(),
            "rgba(0,128,255,1)"
        );
        assert_eq!(Color::rgba(0, 0, 0, 0.0).to_css_rgba(), "rgba(0,0,0,0)");
        assert_eq!(
            Color::rgba(255, 128, 0, 0.5).to_css_rgba(),
            "rgba(255,128,0,0.5)"
        );
    }

    #[test]
    fn to_hex_round_trips_through_from_hex() {
        let c = Color::rgb(18, 52, 86);
        assert_eq!(c.to_hex(), "#123456");
        assert_eq!(Color::from_hex("#123456"), Ok(c));
        assert_eq!(Color::from_hex("123456"), Ok(c));
    }

    #[test]
    fn from_hex_short_form_expands() {
        assert_eq!(Color::from_hex("#f00"), Ok(Color::rgb(255, 0, 0)));
        assert_eq!(Color::from_hex("#abc"), Ok(Color::rgb(170, 187, 204)));
    }

    #[test]
    fn from_hex_rejects_bad_input() {
        assert_eq!(Color::from_hex("#12"), Err(ColorError::BadHexLength(2)));
        assert_eq!(Color::from_hex("#12345"), Err(ColorError::BadHexLength(5)));
        assert!(matches!(
            Color::from_hex("#12zz56"),
            Err(ColorError::BadHexDigit('z'))
        ));
    }

    #[test]
    fn from_name_curated_set() {
        assert_eq!(Color::from_name("Red"), Ok(Color::red()));
        assert_eq!(Color::from_name("aqua"), Ok(Color::rgb(0, 255, 255)));
        assert!(matches!(
            Color::from_name("chartreuse"),
            Err(ColorError::UnknownColorName(_))
        ));
    }

    #[test]
    fn to_ansi_truecolor_is_exact() {
        assert_eq!(
            Color::rgb(10, 20, 30).to_ansi(TermProfile::TrueColor),
            AnsiColor::Rgb(10, 20, 30)
        );
    }

    #[test]
    fn to_ansi_nocolor_and_transparent_default() {
        assert_eq!(
            Color::rgb(200, 10, 10).to_ansi(TermProfile::NoColor),
            AnsiColor::Default
        );
        assert_eq!(
            Color::transparent().to_ansi(TermProfile::TrueColor),
            AnsiColor::Default
        );
    }

    #[test]
    fn to_ansi_16_picks_nearest_named() {
        // Pure red maps to palette index 9 (bright red).
        assert_eq!(
            Color::rgb(255, 0, 0).to_ansi(TermProfile::Ansi16),
            AnsiColor::Named(9)
        );
        // Pure black maps to index 0.
        assert_eq!(
            Color::rgb(0, 0, 0).to_ansi(TermProfile::Ansi16),
            AnsiColor::Named(0)
        );
    }

    #[test]
    fn to_ansi_256_indexes_in_range() {
        for c in [
            Color::rgb(0, 0, 0),
            Color::rgb(255, 255, 255),
            Color::rgb(128, 128, 128),
            Color::rgb(200, 30, 90),
        ] {
            match c.to_ansi(TermProfile::Ansi256) {
                AnsiColor::Indexed(i) => assert!((16..=255).contains(&i)),
                other => panic!("expected Indexed, got {other:?}"),
            }
        }
    }

    #[test]
    fn contrast_ratio_black_white_is_max() {
        let ratio = Color::contrast_ratio(Color::black(), Color::white());
        assert!((ratio - 21.0).abs() < 0.01, "got {ratio}");
    }

    #[test]
    fn readable_text_on_light_bg_is_black() {
        assert_eq!(Color::readable_text_on(Color::white()), Color::black());
        assert_eq!(Color::readable_text_on(Color::black()), Color::white());
    }

    #[test]
    fn hsl_round_trip_primary() {
        // Pure red is hue 0, full saturation, half lightness.
        let (h, s, l, _a) = Color::red().to_hsla();
        assert!(h.abs() < 0.01, "hue {h}");
        assert!((s - 1.0).abs() < 0.01, "sat {s}");
        assert!((l - 0.5).abs() < 0.01, "light {l}");
    }

    #[test]
    fn mix_endpoints_are_the_inputs() {
        let a = Color::rgb(255, 0, 0);
        let b = Color::rgb(0, 0, 255);
        assert_eq!(Color::mix(0.0, a, b), a);
        assert_eq!(Color::mix(1.0, a, b), b);
    }

    #[test]
    fn with_alpha_clamps() {
        assert_eq!(
            Color::white().with_alpha(2.0),
            Color::rgba(255, 255, 255, 1.0)
        );
        assert_eq!(
            Color::white().with_alpha(-1.0),
            Color::rgba(255, 255, 255, 0.0)
        );
    }

    #[test]
    fn complementary_is_180_rotation() {
        let c = Color::rgb(255, 0, 0);
        let comp = c.complementary();
        let (h, _, _, _) = comp.to_hsla();
        assert!((h - 180.0).abs() < 1.0, "hue {h}");
    }

    #[test]
    fn luminance_matches_wcag_reference_vectors() {
        // WCAG reference relative luminances (sRGB): black 0, white 1.
        assert!(Color::black().luminance().abs() < 1e-9);
        assert!((Color::white().luminance() - 1.0).abs() < 1e-9);
        // Pure sRGB red relative luminance = 0.2126 (channel is fully on).
        assert!(
            (Color::red().luminance() - 0.2126).abs() < 1e-4,
            "{}",
            Color::red().luminance()
        );
        // #777777 mid-grey: documented ~0.184 relative luminance.
        let grey = Color::from_hex("#777777").expect("valid hex");
        assert!(
            (grey.luminance() - 0.184_5).abs() < 2e-3,
            "{}",
            grey.luminance()
        );
    }

    #[test]
    fn contrast_ratio_reference_pair() {
        // #595959 on white is the canonical 7.0:1 AAA-normal boundary pair.
        let fg = Color::from_hex("#595959").expect("valid hex");
        let ratio = Color::contrast_ratio(fg, Color::white());
        assert!((ratio - 7.0).abs() < 0.05, "got {ratio}");
    }

    #[test]
    fn meets_wcag_thresholds() {
        let black = Color::black();
        let white = Color::white();
        // 21:1 clears every level.
        assert!(Color::meets_wcag(
            WcagLevel::AAA,
            TextSize::NormalText,
            black,
            white
        ));
        // #767676 on white ~ 4.54:1: passes AA-normal (4.5), fails AAA-normal (7).
        let mid = Color::from_hex("#767676").expect("valid hex");
        assert!(Color::meets_wcag(
            WcagLevel::AA,
            TextSize::NormalText,
            mid,
            white
        ));
        assert!(!Color::meets_wcag(
            WcagLevel::AAA,
            TextSize::NormalText,
            mid,
            white
        ));
        // ~3.0:1 grey passes AA-large but not AA-normal.
        let light = Color::from_hex("#949494").expect("valid hex");
        assert!(Color::meets_wcag(
            WcagLevel::AA,
            TextSize::LargeText,
            light,
            white
        ));
        assert!(!Color::meets_wcag(
            WcagLevel::AA,
            TextSize::NormalText,
            light,
            white
        ));
    }

    #[test]
    fn maximum_contrast_picks_best_and_falls_back() {
        // White target: black wins over dark-grey.
        let best = Color::maximum_contrast(
            Color::white(),
            &[
                Color::rgb(50, 50, 50),
                Color::black(),
                Color::rgb(200, 200, 200),
            ],
        );
        assert_eq!(best, Color::black());
        // Empty list falls back to a legible readable-text pick.
        assert_eq!(
            Color::maximum_contrast(Color::white(), &[]),
            Color::readable_text_on(Color::white())
        );
    }

    #[test]
    fn simulate_is_deterministic_and_preserves_alpha() {
        let c = Color::rgba(200, 30, 90, 0.4);
        let s1 = c.simulate(Deficiency::Deuteranopia);
        let s2 = c.simulate(Deficiency::Deuteranopia);
        assert_eq!(s1, s2, "simulate must be deterministic");
        let (_, _, _, a) = s1.to_rgba();
        assert!((a - 0.4).abs() < 1e-9, "alpha preserved");
        // Grey is on the achromatic axis: CVD simulation leaves it (near) unchanged.
        let grey = Color::rgb(128, 128, 128);
        let sg = grey.simulate(Deficiency::Protanopia);
        let (gr, gg, gb, _) = sg.to_rgba();
        assert!(
            (gr - gg).abs() < 0.05 && (gg - gb).abs() < 0.05,
            "grey stays grey"
        );
    }

    #[test]
    fn gradient_has_n_stops_with_exact_endpoints() {
        let a = Color::rgb(255, 0, 0);
        let b = Color::rgb(0, 0, 255);
        let g = Color::gradient(5, a, b);
        assert_eq!(g.len(), 5);
        assert_eq!(g.first().copied(), Some(a));
        assert_eq!(g.last().copied(), Some(b));
        // n < 2 degrades to the two endpoints.
        assert_eq!(Color::gradient(1, a, b), vec![a, b]);
        assert_eq!(Color::gradient(0, a, b), vec![a, b]);
    }

    #[test]
    fn steps_resamples_stop_list() {
        let stops = [
            Color::rgb(0, 0, 0),
            Color::rgb(255, 0, 0),
            Color::rgb(255, 255, 255),
        ];
        let s = Color::steps(3, &stops);
        assert_eq!(s.len(), 3);
        // Endpoints preserved, midpoint lands on the middle stop.
        assert_eq!(s.first().copied(), Some(Color::rgb(0, 0, 0)));
        assert_eq!(s.last().copied(), Some(Color::rgb(255, 255, 255)));
        assert_eq!(s.get(1).copied(), Some(Color::rgb(255, 0, 0)));
        // Degenerate inputs are total.
        assert!(Color::steps(0, &stops).is_empty());
        assert!(Color::steps(4, &[]).is_empty());
        assert_eq!(Color::steps(3, &[Color::red()]).len(), 3);
    }

    // ── S3 kernel-shim boundary tests (the emit-boundary free functions) ──

    #[test]
    fn color_from_hex_shim_parses_and_round_trips() {
        // The shim returns the Ipê `IpeResult` carrier (not std `Result`).
        let got = match color_from_hex("#ff8800".to_owned()) {
            crate::core::IpeResult::Ok(c) => c,
            crate::core::IpeResult::Err(e) => panic!("expected Ok, got {e:?}"),
        };
        assert_eq!(got, Color::rgb(255, 136, 0));
        // The shim is the exact SSOT parser, so `toHex` round-trips.
        assert_eq!(color_to_hex(got), "#ff8800");
    }

    #[test]
    fn color_from_hex_shim_rejects_bad_input_typed() {
        use crate::core::IpeResult;
        // Bad digit → typed `ColorError`, never a panic or a default colour.
        match color_from_hex("#gg0000".to_owned()) {
            IpeResult::Err(ColorError::BadHexDigit(c)) => assert_eq!(c, 'g'),
            other => panic!("expected BadHexDigit, got {other:?}"),
        }
        // Bad length → typed `ColorError::BadHexLength`, not a silent fallback.
        match color_from_hex("#12345".to_owned()) {
            IpeResult::Err(ColorError::BadHexLength(n)) => assert_eq!(n, 5),
            other => panic!("expected BadHexLength, got {other:?}"),
        }
    }

    #[test]
    fn color_from_name_shim_parses_and_refuses_unknown() {
        use crate::core::IpeResult;
        assert_eq!(
            color_from_name("red".to_owned()),
            IpeResult::Ok(Color::red())
        );
        // An unknown name is turned back with the typed error, not defaulted.
        match color_from_name("chartreusey".to_owned()) {
            IpeResult::Err(ColorError::UnknownColorName(n)) => assert_eq!(n, "chartreusey"),
            other => panic!("expected UnknownColorName, got {other:?}"),
        }
    }

    #[test]
    fn color_to_ansi_shim_delegates_to_nearest_16_ssot() {
        // The shim degrades through `Color::to_ansi` (the nearest-16 SSOT); it
        // must NOT re-derive a brightness threshold. Pure black on the 16-palette
        // maps to the named index the SSOT table dictates.
        let black16 = color_to_ansi(color_ansi16_profile(), Color::black());
        assert_eq!(black16, Color::black().to_ansi(TermProfile::Ansi16));
        assert!(matches!(black16, AnsiColor::Named(_)));
        // Truecolour is exact; no-colour degrades to the terminal default.
        assert_eq!(
            color_to_ansi(color_true_color_profile(), Color::rgb(10, 20, 30)),
            AnsiColor::Rgb(10, 20, 30)
        );
        assert_eq!(
            color_to_ansi(color_no_color_profile(), Color::red()),
            AnsiColor::Default
        );
    }

    #[test]
    fn color_wcag_shims_delegate() {
        // contrastRatio black/white is the WCAG maximum (21:1).
        assert!((color_contrast_ratio(Color::black(), Color::white()) - 21.0).abs() < 1e-9);
        // Black-on-white passes AA normal text; a low-contrast pair fails.
        assert!(color_meets_wcag(
            color_wcag_aa(),
            color_normal_text(),
            Color::black(),
            Color::white()
        ));
        assert!(!color_meets_wcag(
            color_wcag_aaa(),
            color_large_text(),
            Color::rgb(200, 200, 200),
            Color::white()
        ));
        // readableTextOn a light bg is black; the empty candidate list falls back
        // to the readable-text colour for the target (black on white) — total.
        assert_eq!(color_readable_text_on(Color::white()), Color::black());
        assert_eq!(
            color_maximum_contrast(Color::white(), Vec::new()),
            Color::readable_text_on(Color::white())
        );
        assert_eq!(
            color_maximum_contrast(
                Color::white(),
                vec![Color::black(), Color::rgb(240, 240, 240)]
            ),
            Color::black()
        );
    }

    #[test]
    fn color_simulate_shim_delegates_and_preserves_alpha() {
        let c = Color::rgba(200, 50, 50, 0.5);
        for deficiency in [color_protanopia(), color_deuteranopia(), color_tritanopia()] {
            let sim = color_simulate(deficiency, c);
            // Delegates to the `Color::simulate` SSOT (identical result)…
            assert_eq!(sim, c.simulate(deficiency));
            // …and the alpha channel survives the projection.
            let (.., a) = sim.to_rgba();
            assert!((a - 0.5).abs() < 1e-9);
        }
    }
}
