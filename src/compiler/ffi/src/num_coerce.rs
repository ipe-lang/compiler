//! Scalar numeric coercion at the Ipê↔Rust FFI boundary — the DAG leaf.
//!
//! Exactly ONE source of every scalar width cast in generated wrapper code:
//! `num_saturate` narrows an Ipê carrier (`i64`/`f64`) into a foreign
//! parameter width, `num_widen_scalar` widens a foreign return into the
//! carrier. Both are TOTAL and SATURATING — a value outside the target's
//! range clamps to the nearest representable bound, never wraps, never
//! panics, never sign-flips (`u64::MAX as i64 == -1` is the defect class
//! this module exists to kill).
//!
//! Platform correctness by construction: `usize`/`isize` are platform-width,
//! so they route through `try_from` — a bare `as` would truncate on 32-bit,
//! which all-64-bit CI can never catch.
//!
//! Sanctioned divergence from the golden oracle: a value above `i64::MAX`
//! saturates rather than wraps or errors (`oracle_divergence = true`; the
//! clamp is total and documented, satisfying "no silent numeric coercion").

/// One Rust numeric primitive width, parsed once from its spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NumWidth {
    I8,
    I16,
    I32,
    I64,
    I128,
    Isize,
    U8,
    U16,
    U32,
    U64,
    U128,
    Usize,
    F32,
    F64,
}

/// The Ipê carrier a foreign numeric width travels as.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NumCarrier {
    /// Ipê `Int`, Rust `i64`.
    Int,
    /// Ipê `Float`, Rust `f64`.
    Float,
}

impl NumCarrier {
    /// The carrier's Rust spelling (`i64` / `f64`).
    #[must_use]
    pub const fn rust(self) -> &'static str {
        match self {
            Self::Int => "i64",
            Self::Float => "f64",
        }
    }

    /// The carrier's Ipê type name (`Int` / `Float`).
    #[must_use]
    pub const fn ipe(self) -> &'static str {
        match self {
            Self::Int => "Int",
            Self::Float => "Float",
        }
    }
}

impl NumWidth {
    /// Every width, in declaration order.
    pub const ALL: [Self; 14] = [
        Self::I8,
        Self::I16,
        Self::I32,
        Self::I64,
        Self::I128,
        Self::Isize,
        Self::U8,
        Self::U16,
        Self::U32,
        Self::U64,
        Self::U128,
        Self::Usize,
        Self::F32,
        Self::F64,
    ];

    /// The width an exact Rust spelling names; the only spelling-to-width map.
    ///
    /// `None` for any other text, including a padded or differently cased
    /// spelling: the caller trims, never this parser.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        Some(match raw {
            "i8" => Self::I8,
            "i16" => Self::I16,
            "i32" => Self::I32,
            "i64" => Self::I64,
            "i128" => Self::I128,
            "isize" => Self::Isize,
            "u8" => Self::U8,
            "u16" => Self::U16,
            "u32" => Self::U32,
            "u64" => Self::U64,
            "u128" => Self::U128,
            "usize" => Self::Usize,
            "f32" => Self::F32,
            "f64" => Self::F64,
            _ => return None,
        })
    }

    /// The width's Rust spelling.
    #[must_use]
    pub const fn rust(self) -> &'static str {
        match self {
            Self::I8 => "i8",
            Self::I16 => "i16",
            Self::I32 => "i32",
            Self::I64 => "i64",
            Self::I128 => "i128",
            Self::Isize => "isize",
            Self::U8 => "u8",
            Self::U16 => "u16",
            Self::U32 => "u32",
            Self::U64 => "u64",
            Self::U128 => "u128",
            Self::Usize => "usize",
            Self::F32 => "f32",
            Self::F64 => "f64",
        }
    }

    /// The Ipê carrier this width travels as across the FFI boundary.
    #[must_use]
    pub const fn carrier(self) -> NumCarrier {
        match self {
            Self::I8
            | Self::I16
            | Self::I32
            | Self::I64
            | Self::I128
            | Self::Isize
            | Self::U8
            | Self::U16
            | Self::U32
            | Self::U64
            | Self::U128
            | Self::Usize => NumCarrier::Int,
            Self::F32 | Self::F64 => NumCarrier::Float,
        }
    }

    /// True when the width IS its carrier, so no coercion applies.
    #[must_use]
    pub const fn is_carrier(self) -> bool {
        matches!(self, Self::I64 | Self::F64)
    }
}

/// Render the expression that coerces an Ipê carrier (`i64` / `f64`) INTO a
/// foreign numeric param of width `w`, saturating.
///
/// Every form evaluates `expr` exactly once.
#[must_use]
pub fn num_saturate(w: NumWidth, expr: &str) -> String {
    let par = format!("({expr})");
    let raw = w.rust();
    match w {
        // Precision-lossy but total.
        NumWidth::F32 => format!("{par} as f32"),
        // Identity: the carrier IS the width.
        NumWidth::F64 | NumWidth::I64 => expr.to_owned(),
        // Signed narrowing: clamp into [MIN, MAX] of the target, lossless `as`.
        NumWidth::I8 | NumWidth::I16 | NumWidth::I32 => {
            format!("{par}.clamp({raw}::MIN as i64, {raw}::MAX as i64) as {raw}")
        }
        // Unsigned narrowing: clamp into [0, MAX], then a lossless `as`.
        NumWidth::U8 | NumWidth::U16 | NumWidth::U32 => {
            format!("{par}.clamp(0, {raw}::MAX as i64) as {raw}")
        }
        // Every non-negative i64 fits u64; negatives saturate to 0.
        NumWidth::U64 => format!("{par}.max(0) as u64"),
        // Wider than i64: i128 is a pure sign-preserving widen; u128 saturates
        // negatives to 0 (a bare `as u128` would sign-extend -1 to ~3.4e38).
        NumWidth::I128 => format!("{par} as i128"),
        NumWidth::U128 => format!("{par}.max(0) as u128"),
        // Platform-width → try_from (32-bit-correct by construction).
        NumWidth::Usize => format!("usize::try_from({par}.max(0)).unwrap_or(usize::MAX)"),
        NumWidth::Isize => format!(
            "{{ let __n: i64 = {expr}; isize::try_from(__n).unwrap_or(if __n < 0 {{ isize::MIN }} else {{ isize::MAX }}) }}"
        ),
    }
}

/// A scalar RETURN widening: the Ipê carrier the value arrives as, plus the
/// rendered coercion expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WidenedScalar {
    /// The Ipê carrier type the widened value travels as (`"i64"` / `"f64"`).
    pub carrier: &'static str,
    /// The rendered Rust expression producing the carrier-typed value.
    pub expr: String,
}

/// Widen a foreign scalar return of width `w` to its Ipê carrier, total and
/// saturating for widths that exceed `i64`.
///
/// `expr` may be any Rust expression, including a side-effecting foreign call.
/// Every generated form evaluates `expr` exactly once.
#[must_use]
pub fn num_widen_scalar(w: NumWidth, expr: &str) -> WidenedScalar {
    let raw = w.rust();
    let carrier = w.carrier().rust();
    let expr = match w {
        // Lossless: every value fits in i64 after widening (isize ≤ i64).
        NumWidth::I8
        | NumWidth::I16
        | NumWidth::I32
        | NumWidth::I64
        | NumWidth::U8
        | NumWidth::U16
        | NumWidth::U32
        | NumWidth::Isize => format!("({expr}) as i64"),
        // Unsigned ≥ i64 range: a bare `as i64` would sign-flip
        // (`u64::MAX as i64 == -1`). Saturate via min into i64::MAX.
        NumWidth::U64 | NumWidth::Usize | NumWidth::U128 => {
            format!("({expr}).min(i64::MAX as {raw}) as i64")
        }
        // Signed wide: bind once to avoid evaluating a potentially
        // side-effecting expression twice in the unwrap_or branch.
        NumWidth::I128 => format!(
            "{{ let __w = {expr}; i64::try_from(__w).unwrap_or(if __w < 0 {{ i64::MIN }} else {{ i64::MAX }}) }}"
        ),
        NumWidth::F32 | NumWidth::F64 => format!("({expr}) as f64"),
    };
    WidenedScalar { carrier, expr }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_round_trips_every_width_and_rejects_every_other_spelling() {
        for w in NumWidth::ALL {
            assert_eq!(NumWidth::parse(w.rust()), Some(w), "{w:?} round-trips");
        }
        for bad in [
            "i31", "u256", "", "I32", " i32", "i32 ", "String", "bool", "char", "Vec<u8>", "&u8",
            "f16",
        ] {
            assert_eq!(NumWidth::parse(bad), None, "`{bad}` names no width");
        }
    }

    #[test]
    fn every_width_has_its_carrier() {
        for w in NumWidth::ALL {
            let want = if matches!(w, NumWidth::F32 | NumWidth::F64) {
                NumCarrier::Float
            } else {
                NumCarrier::Int
            };
            assert_eq!(w.carrier(), want, "{w:?}");
            assert_eq!(
                w.is_carrier(),
                w.rust() == w.carrier().rust(),
                "{w:?} is its own carrier exactly when the spellings agree"
            );
        }
    }

    #[test]
    fn saturate_identity_on_the_carriers() {
        assert_eq!(num_saturate(NumWidth::I64, "x"), "x");
        assert_eq!(num_saturate(NumWidth::F64, "x"), "x");
    }

    #[test]
    fn saturate_signed_and_unsigned_narrowing_clamps() {
        assert_eq!(
            num_saturate(NumWidth::I8, "x"),
            "(x).clamp(i8::MIN as i64, i8::MAX as i64) as i8"
        );
        assert_eq!(
            num_saturate(NumWidth::U16, "x"),
            "(x).clamp(0, u16::MAX as i64) as u16"
        );
    }

    #[test]
    fn saturate_u64_floors_negatives_instead_of_sign_extending() {
        assert_eq!(num_saturate(NumWidth::U64, "x"), "(x).max(0) as u64");
        assert_eq!(num_saturate(NumWidth::U128, "x"), "(x).max(0) as u128");
    }

    #[test]
    fn saturate_platform_widths_route_through_try_from() {
        assert_eq!(
            num_saturate(NumWidth::Usize, "x"),
            "usize::try_from((x).max(0)).unwrap_or(usize::MAX)"
        );
        assert_eq!(
            num_saturate(NumWidth::Isize, "x"),
            "{ let __n: i64 = x; isize::try_from(__n).unwrap_or(if __n < 0 { isize::MIN } else { isize::MAX }) }"
        );
    }

    #[test]
    fn saturate_evaluates_its_operand_once_for_every_width() {
        let call = "side_effect()";
        for w in NumWidth::ALL {
            let form = num_saturate(w, call);
            assert_eq!(form.matches(call).count(), 1, "{w:?}: {form}");
        }
    }

    #[test]
    fn widen_lossless_widths_are_a_plain_as() {
        for w in [
            NumWidth::I8,
            NumWidth::I16,
            NumWidth::I32,
            NumWidth::I64,
            NumWidth::U8,
            NumWidth::U16,
            NumWidth::U32,
            NumWidth::Isize,
        ] {
            let ws = num_widen_scalar(w, "r");
            assert_eq!(ws.carrier, "i64");
            assert_eq!(ws.expr, "(r) as i64");
        }
    }

    #[test]
    fn widen_unsigned_wide_saturates_instead_of_sign_flipping() {
        for w in [NumWidth::U64, NumWidth::Usize, NumWidth::U128] {
            let ws = num_widen_scalar(w, "r");
            assert_eq!(ws.carrier, "i64");
            assert_eq!(ws.expr, format!("(r).min(i64::MAX as {}) as i64", w.rust()));
        }
    }

    #[test]
    fn widen_i128_saturates_both_directions() {
        let ws = num_widen_scalar(NumWidth::I128, "r");
        assert_eq!(ws.carrier, "i64");
        assert_eq!(
            ws.expr,
            "{ let __w = r; i64::try_from(__w).unwrap_or(if __w < 0 { i64::MIN } else { i64::MAX }) }"
        );
    }

    #[test]
    fn widen_evaluates_its_operand_once_for_every_width() {
        // A side-effecting foreign call passed as expr must not be duplicated
        // in the generated code — each evaluation would invoke the foreign fn
        // again, producing a different value in the overflow branch.
        let call = "some_foreign_fn()";
        for w in NumWidth::ALL {
            let ws = num_widen_scalar(w, call);
            assert_eq!(ws.expr.matches(call).count(), 1, "{w:?}: {}", ws.expr);
        }
    }

    #[test]
    fn widen_floats_go_to_f64() {
        let ws = num_widen_scalar(NumWidth::F32, "r");
        assert_eq!(ws.carrier, "f64");
        assert_eq!(ws.expr, "(r) as f64");
    }

    /// The emitted saturation forms must themselves be sound Rust: evaluate
    /// each shape at the extremes here so the generated-code behaviour is
    /// pinned by a real computation, not just by string equality.
    #[test]
    #[allow(
        clippy::cast_sign_loss,
        clippy::cast_possible_truncation,
        clippy::cast_lossless,
        clippy::cast_possible_wrap
    )] // evaluates the exact emitted cast forms at the extremes — the casts ARE the subject
    fn saturation_semantics_at_the_extremes() {
        let x: i64 = -1;
        assert_eq!((x).max(0) as u64, 0);
        assert_eq!((x).clamp(0, u16::MAX as i64) as u16, 0);
        assert_eq!((x).clamp(i8::MIN as i64, i8::MAX as i64) as i8, -1);
        let big: i64 = i64::MAX;
        assert_eq!((big).clamp(i8::MIN as i64, i8::MAX as i64) as i8, i8::MAX);
        assert_eq!(usize::try_from((x).max(0)).unwrap_or(usize::MAX), 0);
        let isz = {
            let __n: i64 = big;
            isize::try_from(__n).unwrap_or(if __n < 0 { isize::MIN } else { isize::MAX })
        };
        assert_eq!(isz, isize::MAX);
        let r: u64 = u64::MAX;
        assert_eq!((r).min(i64::MAX as u64) as i64, i64::MAX);
        let r128: i128 = i128::MIN;
        let __w = r128;
        assert_eq!(
            i64::try_from(__w).unwrap_or(if __w < 0 { i64::MIN } else { i64::MAX }),
            i64::MIN
        );
    }
}
