use crate::*;

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum IpeCssLength {
    Px(i64),
    Rem(f64),
    Em(f64),
    Pct(f64),
    Vh(i64),
    Vw(i64),
    Ch(f64),
    Fr(i64),
    Num(f64),
    LenAuto,
    LenZero,
    LenRaw(String),
}

impl IpeStringify for IpeCssLength {
    fn ipe_show(&self) -> String {
        match self {
            IpeCssLength::Px(p0) => {
                format!("Px {}", (&ipe_runtime::stringify::Wrap(p0)).dispatch())
            }
            IpeCssLength::Rem(p0) => {
                format!("Rem {}", (&ipe_runtime::stringify::Wrap(p0)).dispatch())
            }
            IpeCssLength::Em(p0) => {
                format!("Em {}", (&ipe_runtime::stringify::Wrap(p0)).dispatch())
            }
            IpeCssLength::Pct(p0) => {
                format!("Pct {}", (&ipe_runtime::stringify::Wrap(p0)).dispatch())
            }
            IpeCssLength::Vh(p0) => {
                format!("Vh {}", (&ipe_runtime::stringify::Wrap(p0)).dispatch())
            }
            IpeCssLength::Vw(p0) => {
                format!("Vw {}", (&ipe_runtime::stringify::Wrap(p0)).dispatch())
            }
            IpeCssLength::Ch(p0) => {
                format!("Ch {}", (&ipe_runtime::stringify::Wrap(p0)).dispatch())
            }
            IpeCssLength::Fr(p0) => {
                format!("Fr {}", (&ipe_runtime::stringify::Wrap(p0)).dispatch())
            }
            IpeCssLength::Num(p0) => {
                format!("Num {}", (&ipe_runtime::stringify::Wrap(p0)).dispatch())
            }
            IpeCssLength::LenAuto => "LenAuto".to_string(),
            IpeCssLength::LenZero => "LenZero".to_string(),
            IpeCssLength::LenRaw(p0) => {
                format!("LenRaw {}", (&ipe_runtime::stringify::Wrap(p0)).dispatch())
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum IpeCssColor {
    Hex(String),
    Rgb(i64, i64, i64),
    Rgba(i64, i64, i64, IpeCssOpacity),
    Hsl(i64, i64, i64),
    Hsla(i64, i64, i64, IpeCssOpacity),
    ColorTransparent,
    ColorCurrent,
    ColorRaw(String),
}

impl IpeStringify for IpeCssColor {
    fn ipe_show(&self) -> String {
        match self {
            IpeCssColor::Hex(p0) => {
                format!("Hex {}", (&ipe_runtime::stringify::Wrap(p0)).dispatch())
            }
            IpeCssColor::Rgb(p0, p1, p2) => format!(
                "Rgb {} {} {}",
                (&ipe_runtime::stringify::Wrap(p0)).dispatch(),
                (&ipe_runtime::stringify::Wrap(p1)).dispatch(),
                (&ipe_runtime::stringify::Wrap(p2)).dispatch()
            ),
            IpeCssColor::Rgba(p0, p1, p2, p3) => format!(
                "Rgba {} {} {} {}",
                (&ipe_runtime::stringify::Wrap(p0)).dispatch(),
                (&ipe_runtime::stringify::Wrap(p1)).dispatch(),
                (&ipe_runtime::stringify::Wrap(p2)).dispatch(),
                (&ipe_runtime::stringify::Wrap(p3)).dispatch()
            ),
            IpeCssColor::Hsl(p0, p1, p2) => format!(
                "Hsl {} {} {}",
                (&ipe_runtime::stringify::Wrap(p0)).dispatch(),
                (&ipe_runtime::stringify::Wrap(p1)).dispatch(),
                (&ipe_runtime::stringify::Wrap(p2)).dispatch()
            ),
            IpeCssColor::Hsla(p0, p1, p2, p3) => format!(
                "Hsla {} {} {} {}",
                (&ipe_runtime::stringify::Wrap(p0)).dispatch(),
                (&ipe_runtime::stringify::Wrap(p1)).dispatch(),
                (&ipe_runtime::stringify::Wrap(p2)).dispatch(),
                (&ipe_runtime::stringify::Wrap(p3)).dispatch()
            ),
            IpeCssColor::ColorTransparent => "ColorTransparent".to_string(),
            IpeCssColor::ColorCurrent => "ColorCurrent".to_string(),
            IpeCssColor::ColorRaw(p0) => format!(
                "ColorRaw {}",
                (&ipe_runtime::stringify::Wrap(p0)).dispatch()
            ),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum IpeCssOpacity {
    Opacity(f64),
}

impl IpeStringify for IpeCssOpacity {
    fn ipe_show(&self) -> String {
        match self {
            IpeCssOpacity::Opacity(p0) => {
                format!("Opacity {}", (&ipe_runtime::stringify::Wrap(p0)).dispatch())
            }
        }
    }
}

pub(crate) fn user_ipe_css_opacity_of(n: f64) -> IpeCssOpacity {
    let _ipe_recursion_guard = crate::recursion_guard();
    (if math_is_nan(n) {
        IpeCssOpacity::Opacity(0.0)
    } else {
        IpeCssOpacity::Opacity(basics_clamp(0.0, 1.0, n))
    })
}

pub(crate) fn user_ipe_css_opacity_to_string(o: IpeCssOpacity) -> String {
    let _ipe_recursion_guard = crate::recursion_guard();
    match o {
        IpeCssOpacity::Opacity(n) => crate::user_ipe_css_float_str(n),
    }
}

pub(crate) fn user_ipe_css_float_str(n: f64) -> String {
    let _ipe_recursion_guard = crate::recursion_guard();
    string_from_float(n)
}

pub(crate) fn user_ipe_css_length_to_string(lengthVal: IpeCssLength) -> String {
    let _ipe_recursion_guard = crate::recursion_guard();
    match lengthVal {
        IpeCssLength::Px(n) => crate::user_ipe_length_to_css(n, IpeLengthUnit::Px),
        IpeCssLength::Rem(n) => format!("{}{}", crate::user_ipe_css_float_str(n), "rem".to_string()),
        IpeCssLength::Em(n) => format!("{}{}", crate::user_ipe_css_float_str(n), "em".to_string()),
        IpeCssLength::Pct(n) => format!("{}{}", crate::user_ipe_css_float_str(n), "%".to_string()),
        IpeCssLength::Vh(n) => crate::user_ipe_length_to_css(n, IpeLengthUnit::Vh),
        IpeCssLength::Vw(n) => crate::user_ipe_length_to_css(n, IpeLengthUnit::Vw),
        IpeCssLength::Ch(n) => format!("{}{}", crate::user_ipe_css_float_str(n), "ch".to_string()),
        IpeCssLength::Fr(n) => format!("{}{}", string_from_int(n), "fr".to_string()),
        IpeCssLength::Num(n) => crate::user_ipe_css_float_str(n),
        IpeCssLength::LenAuto => "auto".to_string(),
        IpeCssLength::LenZero => "0".to_string(),
        IpeCssLength::LenRaw(s) => s,
    }
}

pub(crate) fn user_ipe_css_color_to_string(c: IpeCssColor) -> String {
    let _ipe_recursion_guard = crate::recursion_guard();
    match c {
        IpeCssColor::Hex(s) => format!("{}{}", "#".to_string(), s),
        IpeCssColor::Rgb(r, g, b) => format!(
            "{}{}",
            "rgb(".to_string(),
            format!(
                "{}{}",
                string_from_int(r),
                format!(
                    "{}{}",
                    ",".to_string(),
                    format!(
                        "{}{}",
                        string_from_int(g),
                        format!(
                            "{}{}",
                            ",".to_string(),
                            format!("{}{}", string_from_int(b), ")".to_string())
                        )
                    )
                )
            )
        ),
        IpeCssColor::Rgba(r, g, b, a) => format!(
            "{}{}",
            "rgba(".to_string(),
            format!(
                "{}{}",
                string_from_int(r),
                format!(
                    "{}{}",
                    ",".to_string(),
                    format!(
                        "{}{}",
                        string_from_int(g),
                        format!(
                            "{}{}",
                            ",".to_string(),
                            format!(
                                "{}{}",
                                string_from_int(b),
                                format!(
                                    "{}{}",
                                    ",".to_string(),
                                    format!(
                                        "{}{}",
                                        crate::user_ipe_css_opacity_to_string(a),
                                        ")".to_string()
                                    )
                                )
                            )
                        )
                    )
                )
            )
        ),
        IpeCssColor::Hsl(h, s, l) => format!(
            "{}{}",
            "hsl(".to_string(),
            format!(
                "{}{}",
                string_from_int(h),
                format!(
                    "{}{}",
                    ",".to_string(),
                    format!(
                        "{}{}",
                        string_from_int(s),
                        format!(
                            "{}{}",
                            "%,".to_string(),
                            format!("{}{}", string_from_int(l), "%)".to_string())
                        )
                    )
                )
            )
        ),
        IpeCssColor::Hsla(h, s, l, a) => format!(
            "{}{}",
            "hsla(".to_string(),
            format!(
                "{}{}",
                string_from_int(h),
                format!(
                    "{}{}",
                    ",".to_string(),
                    format!(
                        "{}{}",
                        string_from_int(s),
                        format!(
                            "{}{}",
                            "%,".to_string(),
                            format!(
                                "{}{}",
                                string_from_int(l),
                                format!(
                                    "{}{}",
                                    "%,".to_string(),
                                    format!(
                                        "{}{}",
                                        crate::user_ipe_css_opacity_to_string(a),
                                        ")".to_string()
                                    )
                                )
                            )
                        )
                    )
                )
            )
        ),
        IpeCssColor::ColorTransparent => "transparent".to_string(),
        IpeCssColor::ColorCurrent => "currentColor".to_string(),
        IpeCssColor::ColorRaw(s) => s,
    }
}

pub(crate) fn user_ipe_css_px(n: i64) -> IpeCssLength {
    let _ipe_recursion_guard = crate::recursion_guard();
    IpeCssLength::Px(n)
}

pub(crate) fn user_ipe_css_vh(n: i64) -> IpeCssLength {
    let _ipe_recursion_guard = crate::recursion_guard();
    IpeCssLength::Vh(n)
}

pub(crate) fn user_ipe_css_vw(n: i64) -> IpeCssLength {
    let _ipe_recursion_guard = crate::recursion_guard();
    IpeCssLength::Vw(n)
}

pub(crate) fn user_ipe_css_rgba(r: i64, g: i64, b: i64, a: IpeCssOpacity) -> IpeCssColor {
    let _ipe_recursion_guard = crate::recursion_guard();
    IpeCssColor::Rgba(r, g, b, a)
}
