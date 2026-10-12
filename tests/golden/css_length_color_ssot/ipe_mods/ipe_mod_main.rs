use crate::*;

pub(crate) fn main_lengths() -> String {
    let _ipe_recursion_guard = crate::recursion_guard();
    static CELL: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    CELL.get_or_init(|| {
        format!(
            "{}{}",
            match IpeCssLength::Px(0i64) {
                IpeCssLength::Px(n) => crate::user_ipe_length_to_css(n, IpeLengthUnit::Px),
                IpeCssLength::Rem(n) => {
                    format!("{}{}", crate::user_ipe_css_float_str(n), "rem".to_string())
                }
                IpeCssLength::Em(n) => {
                    format!("{}{}", crate::user_ipe_css_float_str(n), "em".to_string())
                }
                IpeCssLength::Pct(n) => {
                    format!("{}{}", crate::user_ipe_css_float_str(n), "%".to_string())
                }
                IpeCssLength::Vh(n) => crate::user_ipe_length_to_css(n, IpeLengthUnit::Vh),
                IpeCssLength::Vw(n) => crate::user_ipe_length_to_css(n, IpeLengthUnit::Vw),
                IpeCssLength::Ch(n) => {
                    format!("{}{}", crate::user_ipe_css_float_str(n), "ch".to_string())
                }
                IpeCssLength::Fr(n) => format!("{}{}", string_from_int(n), "fr".to_string()),
                IpeCssLength::Num(n) => crate::user_ipe_css_float_str(n),
                IpeCssLength::LenAuto => "auto".to_string(),
                IpeCssLength::LenZero => "0".to_string(),
                IpeCssLength::LenRaw(s) => s,
            },
            format!(
                "{}{}",
                "\n".to_string(),
                format!(
                    "{}{}",
                    match IpeCssLength::Px(16i64) {
                        IpeCssLength::Px(n) => crate::user_ipe_length_to_css(n, IpeLengthUnit::Px),
                        IpeCssLength::Rem(n) => {
                            format!("{}{}", crate::user_ipe_css_float_str(n), "rem".to_string())
                        }
                        IpeCssLength::Em(n) => {
                            format!("{}{}", crate::user_ipe_css_float_str(n), "em".to_string())
                        }
                        IpeCssLength::Pct(n) => {
                            format!("{}{}", crate::user_ipe_css_float_str(n), "%".to_string())
                        }
                        IpeCssLength::Vh(n) => crate::user_ipe_length_to_css(n, IpeLengthUnit::Vh),
                        IpeCssLength::Vw(n) => crate::user_ipe_length_to_css(n, IpeLengthUnit::Vw),
                        IpeCssLength::Ch(n) => {
                            format!("{}{}", crate::user_ipe_css_float_str(n), "ch".to_string())
                        }
                        IpeCssLength::Fr(n) => {
                            format!("{}{}", string_from_int(n), "fr".to_string())
                        }
                        IpeCssLength::Num(n) => crate::user_ipe_css_float_str(n),
                        IpeCssLength::LenAuto => "auto".to_string(),
                        IpeCssLength::LenZero => "0".to_string(),
                        IpeCssLength::LenRaw(s) => s,
                    },
                    format!(
                        "{}{}",
                        "\n".to_string(),
                        format!(
                            "{}{}",
                            match IpeCssLength::Px(100i64) {
                                IpeCssLength::Px(n) => {
                                    crate::user_ipe_length_to_css(n, IpeLengthUnit::Px)
                                }
                                IpeCssLength::Rem(n) => {
                                    format!(
                                        "{}{}",
                                        crate::user_ipe_css_float_str(n),
                                        "rem".to_string()
                                    )
                                }
                                IpeCssLength::Em(n) => {
                                    format!(
                                        "{}{}",
                                        crate::user_ipe_css_float_str(n),
                                        "em".to_string()
                                    )
                                }
                                IpeCssLength::Pct(n) => {
                                    format!(
                                        "{}{}",
                                        crate::user_ipe_css_float_str(n),
                                        "%".to_string()
                                    )
                                }
                                IpeCssLength::Vh(n) => {
                                    crate::user_ipe_length_to_css(n, IpeLengthUnit::Vh)
                                }
                                IpeCssLength::Vw(n) => {
                                    crate::user_ipe_length_to_css(n, IpeLengthUnit::Vw)
                                }
                                IpeCssLength::Ch(n) => {
                                    format!(
                                        "{}{}",
                                        crate::user_ipe_css_float_str(n),
                                        "ch".to_string()
                                    )
                                }
                                IpeCssLength::Fr(n) => {
                                    format!("{}{}", string_from_int(n), "fr".to_string())
                                }
                                IpeCssLength::Num(n) => crate::user_ipe_css_float_str(n),
                                IpeCssLength::LenAuto => "auto".to_string(),
                                IpeCssLength::LenZero => "0".to_string(),
                                IpeCssLength::LenRaw(s) => s,
                            },
                            format!(
                                "{}{}",
                                "\n".to_string(),
                                format!(
                                    "{}{}",
                                    match IpeCssLength::Vh(50i64) {
                                        IpeCssLength::Px(n) => {
                                            crate::user_ipe_length_to_css(n, IpeLengthUnit::Px)
                                        }
                                        IpeCssLength::Rem(n) => {
                                            format!(
                                                "{}{}",
                                                crate::user_ipe_css_float_str(n),
                                                "rem".to_string()
                                            )
                                        }
                                        IpeCssLength::Em(n) => {
                                            format!(
                                                "{}{}",
                                                crate::user_ipe_css_float_str(n),
                                                "em".to_string()
                                            )
                                        }
                                        IpeCssLength::Pct(n) => {
                                            format!(
                                                "{}{}",
                                                crate::user_ipe_css_float_str(n),
                                                "%".to_string()
                                            )
                                        }
                                        IpeCssLength::Vh(n) => {
                                            crate::user_ipe_length_to_css(n, IpeLengthUnit::Vh)
                                        }
                                        IpeCssLength::Vw(n) => {
                                            crate::user_ipe_length_to_css(n, IpeLengthUnit::Vw)
                                        }
                                        IpeCssLength::Ch(n) => {
                                            format!(
                                                "{}{}",
                                                crate::user_ipe_css_float_str(n),
                                                "ch".to_string()
                                            )
                                        }
                                        IpeCssLength::Fr(n) => {
                                            format!("{}{}", string_from_int(n), "fr".to_string())
                                        }
                                        IpeCssLength::Num(n) => crate::user_ipe_css_float_str(n),
                                        IpeCssLength::LenAuto => "auto".to_string(),
                                        IpeCssLength::LenZero => "0".to_string(),
                                        IpeCssLength::LenRaw(s) => s,
                                    },
                                    format!(
                                        "{}{}",
                                        "\n".to_string(),
                                        format!(
                                            "{}{}",
                                            match IpeCssLength::Vh(100i64) {
                                                IpeCssLength::Px(n) => {
                                                    crate::user_ipe_length_to_css(
                                                        n,
                                                        IpeLengthUnit::Px,
                                                    )
                                                }
                                                IpeCssLength::Rem(n) => {
                                                    format!(
                                                        "{}{}",
                                                        crate::user_ipe_css_float_str(n),
                                                        "rem".to_string()
                                                    )
                                                }
                                                IpeCssLength::Em(n) => {
                                                    format!(
                                                        "{}{}",
                                                        crate::user_ipe_css_float_str(n),
                                                        "em".to_string()
                                                    )
                                                }
                                                IpeCssLength::Pct(n) => {
                                                    format!(
                                                        "{}{}",
                                                        crate::user_ipe_css_float_str(n),
                                                        "%".to_string()
                                                    )
                                                }
                                                IpeCssLength::Vh(n) => {
                                                    crate::user_ipe_length_to_css(
                                                        n,
                                                        IpeLengthUnit::Vh,
                                                    )
                                                }
                                                IpeCssLength::Vw(n) => {
                                                    crate::user_ipe_length_to_css(
                                                        n,
                                                        IpeLengthUnit::Vw,
                                                    )
                                                }
                                                IpeCssLength::Ch(n) => {
                                                    format!(
                                                        "{}{}",
                                                        crate::user_ipe_css_float_str(n),
                                                        "ch".to_string()
                                                    )
                                                }
                                                IpeCssLength::Fr(n) => {
                                                    format!(
                                                        "{}{}",
                                                        string_from_int(n),
                                                        "fr".to_string()
                                                    )
                                                }
                                                IpeCssLength::Num(n) => {
                                                    crate::user_ipe_css_float_str(n)
                                                }
                                                IpeCssLength::LenAuto => "auto".to_string(),
                                                IpeCssLength::LenZero => "0".to_string(),
                                                IpeCssLength::LenRaw(s) => s,
                                            },
                                            format!(
                                                "{}{}",
                                                "\n".to_string(),
                                                format!(
                                                    "{}{}",
                                                    match IpeCssLength::Vw(50i64) {
                                                        IpeCssLength::Px(n) => {
                                                            crate::user_ipe_length_to_css(
                                                                n,
                                                                IpeLengthUnit::Px,
                                                            )
                                                        }
                                                        IpeCssLength::Rem(n) => {
                                                            format!(
                                                                "{}{}",
                                                                crate::user_ipe_css_float_str(n),
                                                                "rem".to_string()
                                                            )
                                                        }
                                                        IpeCssLength::Em(n) => {
                                                            format!(
                                                                "{}{}",
                                                                crate::user_ipe_css_float_str(n),
                                                                "em".to_string()
                                                            )
                                                        }
                                                        IpeCssLength::Pct(n) => {
                                                            format!(
                                                                "{}{}",
                                                                crate::user_ipe_css_float_str(n),
                                                                "%".to_string()
                                                            )
                                                        }
                                                        IpeCssLength::Vh(n) => {
                                                            crate::user_ipe_length_to_css(
                                                                n,
                                                                IpeLengthUnit::Vh,
                                                            )
                                                        }
                                                        IpeCssLength::Vw(n) => {
                                                            crate::user_ipe_length_to_css(
                                                                n,
                                                                IpeLengthUnit::Vw,
                                                            )
                                                        }
                                                        IpeCssLength::Ch(n) => {
                                                            format!(
                                                                "{}{}",
                                                                crate::user_ipe_css_float_str(n),
                                                                "ch".to_string()
                                                            )
                                                        }
                                                        IpeCssLength::Fr(n) => {
                                                            format!(
                                                                "{}{}",
                                                                string_from_int(n),
                                                                "fr".to_string()
                                                            )
                                                        }
                                                        IpeCssLength::Num(n) => {
                                                            crate::user_ipe_css_float_str(n)
                                                        }
                                                        IpeCssLength::LenAuto => "auto".to_string(),
                                                        IpeCssLength::LenZero => "0".to_string(),
                                                        IpeCssLength::LenRaw(s) => s,
                                                    },
                                                    format!(
                                                        "{}{}",
                                                        "\n".to_string(),
                                                        match IpeCssLength::Vw(100i64) {
                                                            IpeCssLength::Px(n) => {
                                                                crate::user_ipe_length_to_css(
                                                                    n,
                                                                    IpeLengthUnit::Px,
                                                                )
                                                            }
                                                            IpeCssLength::Rem(n) => {
                                                                format!(
                                                                    "{}{}",
                                                                    crate::user_ipe_css_float_str(n),
                                                                    "rem".to_string()
                                                                )
                                                            }
                                                            IpeCssLength::Em(n) => {
                                                                format!(
                                                                    "{}{}",
                                                                    crate::user_ipe_css_float_str(n),
                                                                    "em".to_string()
                                                                )
                                                            }
                                                            IpeCssLength::Pct(n) => {
                                                                format!(
                                                                    "{}{}",
                                                                    crate::user_ipe_css_float_str(n),
                                                                    "%".to_string()
                                                                )
                                                            }
                                                            IpeCssLength::Vh(n) => {
                                                                crate::user_ipe_length_to_css(
                                                                    n,
                                                                    IpeLengthUnit::Vh,
                                                                )
                                                            }
                                                            IpeCssLength::Vw(n) => {
                                                                crate::user_ipe_length_to_css(
                                                                    n,
                                                                    IpeLengthUnit::Vw,
                                                                )
                                                            }
                                                            IpeCssLength::Ch(n) => {
                                                                format!(
                                                                    "{}{}",
                                                                    crate::user_ipe_css_float_str(n),
                                                                    "ch".to_string()
                                                                )
                                                            }
                                                            IpeCssLength::Fr(n) => {
                                                                format!(
                                                                    "{}{}",
                                                                    string_from_int(n),
                                                                    "fr".to_string()
                                                                )
                                                            }
                                                            IpeCssLength::Num(n) => {
                                                                crate::user_ipe_css_float_str(n)
                                                            }
                                                            IpeCssLength::LenAuto => {
                                                                "auto".to_string()
                                                            }
                                                            IpeCssLength::LenZero => "0".to_string(),
                                                            IpeCssLength::LenRaw(s) => s,
                                                        }
                                                    )
                                                )
                                            )
                                        )
                                    )
                                )
                            )
                        )
                    )
                )
            )
        )
    })
    .clone()
}

pub(crate) fn main_colors() -> String {
    let _ipe_recursion_guard = crate::recursion_guard();
    static CELL: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    CELL.get_or_init(|| {
        format!(
            "{}{}",
            crate::user_ipe_css_color_to_string(
                crate::user_ipe_css_rgba(
                    0i64,
                    0i64,
                    0i64,
                    (if math_is_nan(1.0) {
                        IpeCssOpacity::Opacity(0.0)
                    } else {
                        IpeCssOpacity::Opacity(basics_clamp(0.0, 1.0, 1.0))
                    }),
                ),
            ),
            format!(
                "{}{}",
                "\n".to_string(),
                format!(
                    "{}{}",
                    crate::user_ipe_css_color_to_string(
                        crate::user_ipe_css_rgba(
                            255i64,
                            0i64,
                            0i64,
                            (if math_is_nan(1.0) {
                                IpeCssOpacity::Opacity(0.0)
                            } else {
                                IpeCssOpacity::Opacity(basics_clamp(0.0, 1.0, 1.0))
                            }),
                        ),
                    ),
                    format!(
                        "{}{}",
                        "\n".to_string(),
                        format!(
                            "{}{}",
                            crate::user_ipe_css_color_to_string(
                                crate::user_ipe_css_rgba(
                                    0i64,
                                    128i64,
                                    255i64,
                                    (if math_is_nan(1.0) {
                                        IpeCssOpacity::Opacity(0.0)
                                    } else {
                                        IpeCssOpacity::Opacity(basics_clamp(0.0, 1.0, 1.0))
                                    }),
                                ),
                            ),
                            format!(
                                "{}{}",
                                "\n".to_string(),
                                format!(
                                    "{}{}",
                                    crate::user_ipe_css_color_to_string(
                                        crate::user_ipe_css_rgba(
                                            0i64,
                                            0i64,
                                            0i64,
                                            (if math_is_nan(0.0) {
                                                IpeCssOpacity::Opacity(0.0)
                                            } else {
                                                IpeCssOpacity::Opacity(basics_clamp(0.0, 1.0, 0.0))
                                            }),
                                        ),
                                    ),
                                    format!(
                                        "{}{}",
                                        "\n".to_string(),
                                        crate::user_ipe_css_color_to_string(
                                            crate::user_ipe_css_rgba(
                                                255i64,
                                                128i64,
                                                0i64,
                                                (if math_is_nan(0.5) {
                                                    IpeCssOpacity::Opacity(0.0)
                                                } else {
                                                    IpeCssOpacity::Opacity(
                                                        basics_clamp(0.0, 1.0, 0.5),
                                                    )
                                                }),
                                            ),
                                        )
                                    )
                                )
                            )
                        )
                    )
                )
            )
        )
    })
    .clone()
}

pub(crate) fn ipe_main() -> IpeTask<()> {
    let _ipe_recursion_guard = crate::recursion_guard();
    io_println(format!(
        "{}{}",
        crate::main_lengths(),
        format!("{}{}", "\n".to_string(), crate::main_colors())
    ))
}
