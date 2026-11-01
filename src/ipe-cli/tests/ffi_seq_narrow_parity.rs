//! An element inside a foreign `Vec<T>` / `&[T]` / `[T; N]` / `Option<Vec<T>>`
//! parameter of a non-carrier numeric width narrows exactly as a scalar `T`
//! FFI argument does.
//!
//! The scalar rule is the text `ipe_ffi::num_coerce::num_saturate` renders; the
//! sequence rule is the text `ipe_ffi::bindings::foreign_seq_arg` renders. Each
//! width's scalar form is pinned, the sequence rendering must apply that same
//! form to every element, and the pinned form, evaluated over the edge set,
//! must equal the mathematical saturation into the width.

use ipe_ffi::bindings::foreign_seq_arg;
use ipe_ffi::num_coerce::{NumWidth, num_saturate};

/// Each out-of-range edge sits on the far side of a wrap for some width.
const EDGES: [i64; 13] = [
    i64::MIN,
    -256,
    -1,
    0,
    1,
    127,
    128,
    255,
    256,
    257,
    300,
    1 << 32,
    i64::MAX,
];

/// One integer width: its pinned scalar form and that form, evaluated (widened
/// to `i128` so every width compares on one axis).
struct IntRule {
    width: NumWidth,
    form: &'static str,
    eval: fn(i64) -> i128,
    min: i128,
    max: i128,
}

/// The pinned forms, evaluated verbatim.
#[allow(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_lossless
)] // evaluates the emitted cast forms verbatim — the casts ARE the subject
fn int_rules() -> [IntRule; 10] {
    [
        IntRule {
            width: NumWidth::I8,
            form: "(x).clamp(i8::MIN as i64, i8::MAX as i64) as i8",
            eval: |x| i128::from((x).clamp(i8::MIN as i64, i8::MAX as i64) as i8),
            min: i128::from(i8::MIN),
            max: i128::from(i8::MAX),
        },
        IntRule {
            width: NumWidth::I16,
            form: "(x).clamp(i16::MIN as i64, i16::MAX as i64) as i16",
            eval: |x| i128::from((x).clamp(i16::MIN as i64, i16::MAX as i64) as i16),
            min: i128::from(i16::MIN),
            max: i128::from(i16::MAX),
        },
        IntRule {
            width: NumWidth::I32,
            form: "(x).clamp(i32::MIN as i64, i32::MAX as i64) as i32",
            eval: |x| i128::from((x).clamp(i32::MIN as i64, i32::MAX as i64) as i32),
            min: i128::from(i32::MIN),
            max: i128::from(i32::MAX),
        },
        IntRule {
            width: NumWidth::U16,
            form: "(x).clamp(0, u16::MAX as i64) as u16",
            eval: |x| i128::from((x).clamp(0, u16::MAX as i64) as u16),
            min: 0,
            max: i128::from(u16::MAX),
        },
        IntRule {
            width: NumWidth::U32,
            form: "(x).clamp(0, u32::MAX as i64) as u32",
            eval: |x| i128::from((x).clamp(0, u32::MAX as i64) as u32),
            min: 0,
            max: i128::from(u32::MAX),
        },
        IntRule {
            width: NumWidth::U64,
            form: "(x).max(0) as u64",
            eval: |x| i128::from((x).max(0) as u64),
            min: 0,
            max: i128::from(u64::MAX),
        },
        IntRule {
            width: NumWidth::I128,
            form: "(x) as i128",
            eval: |x| x as i128,
            min: i128::MIN,
            max: i128::MAX,
        },
        IntRule {
            width: NumWidth::U128,
            form: "(x).max(0) as u128",
            eval: |x| i128::try_from((x).max(0) as u128).unwrap_or(i128::MAX),
            min: 0,
            max: i128::MAX,
        },
        IntRule {
            width: NumWidth::Usize,
            form: "usize::try_from((x).max(0)).unwrap_or(usize::MAX)",
            eval: |x| {
                i128::try_from(usize::try_from((x).max(0)).unwrap_or(usize::MAX))
                    .unwrap_or(i128::MAX)
            },
            min: 0,
            max: i128::try_from(usize::MAX).unwrap_or(i128::MAX),
        },
        IntRule {
            width: NumWidth::Isize,
            form: "{ let __n: i64 = x; isize::try_from(__n).unwrap_or(if __n < 0 { isize::MIN } else { isize::MAX }) }",
            eval: |x| {
                let n: i64 = x;
                let v = isize::try_from(n).unwrap_or(if n < 0 { isize::MIN } else { isize::MAX });
                i128::try_from(v).unwrap_or(i128::MAX)
            },
            min: i128::try_from(isize::MIN).unwrap_or(i128::MIN),
            max: i128::try_from(isize::MAX).unwrap_or(i128::MAX),
        },
    ]
}

/// The pinned `f32` form, evaluated: `as` from `f64` rounds to nearest,
/// saturates to `±inf`, and keeps `NaN`.
#[allow(clippy::as_conversions, clippy::cast_possible_truncation)] // the emitted cast IS the subject
const fn eval_f32(x: f64) -> f32 {
    x as f32
}

/// The element form every sequence shape must apply for width `w`.
fn elem_map(w: NumWidth) -> String {
    format!(".map(|&x| {})", num_saturate(w, "x"))
}

#[test]
fn each_scalar_form_is_pinned_and_saturates_over_the_edges() {
    for rule in int_rules() {
        assert_eq!(
            num_saturate(rule.width, "x"),
            rule.form,
            "the scalar {} FFI rule changed: update its evaluated form here",
            rule.width.rust()
        );
        for x in EDGES {
            assert_eq!(
                (rule.eval)(x),
                i128::from(x).clamp(rule.min, rule.max),
                "{} saturation of {x}",
                rule.width.rust()
            );
        }
    }
    assert_eq!(num_saturate(NumWidth::F32, "x"), "(x) as f32");
}

#[test]
fn every_sequence_shape_applies_the_scalar_form_to_each_element() {
    let mut widths: Vec<NumWidth> = int_rules().iter().map(|r| r.width).collect();
    widths.push(NumWidth::F32);
    for w in widths {
        let t = w.rust();
        let elem = elem_map(w);
        for raw in [
            format!("Vec<{t}>"),
            format!("&[{t}]"),
            format!("[{t}; 4]"),
            format!("&[{t}; 4]"),
            format!("Option<Vec<{t}>>"),
            format!("Option<&[{t}]>"),
        ] {
            let rendered = foreign_seq_arg(&raw).ok().flatten().unwrap_or_default();
            assert!(
                rendered.contains(&elem),
                "{raw} must narrow each element as a scalar {t} argument does: {rendered}"
            );
        }
        assert_eq!(
            foreign_seq_arg(&format!("Vec<{t}>")),
            Ok(Some(format!(
                "arg0.iter().map(|&x| {}).collect::<Vec<{t}>>()",
                num_saturate(w, "x")
            ))),
            "Vec<{t}>"
        );
    }
}

#[test]
fn f32_elements_follow_the_scalar_cast_at_every_edge() {
    let edges = [
        0.0_f64,
        -0.0,
        1.5,
        f64::MAX,
        f64::MIN,
        f64::INFINITY,
        f64::NEG_INFINITY,
    ];
    let expect = [
        0.0_f32,
        -0.0,
        1.5,
        f32::INFINITY,
        f32::NEG_INFINITY,
        f32::INFINITY,
        f32::NEG_INFINITY,
    ];
    for (x, want) in edges.into_iter().zip(expect) {
        let got = eval_f32(x);
        assert_eq!(got.to_bits(), want.to_bits(), "f32 narrowing of {x}");
    }
    assert!(eval_f32(f64::NAN).is_nan(), "NaN stays NaN");
}
