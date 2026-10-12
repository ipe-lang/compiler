use crate::*;

pub(crate) fn main_show_result(m: IpeMaybe<IpeMoneyCurrency>) -> String {
    let _ipe_recursion_guard = crate::recursion_guard();
    match m {
        IpeMaybe::Just(c) => format!(
            "{}{}",
            "Just ".to_string(),
            crate::user_ipe_money_currency_code(c)
        ),
        IpeMaybe::Nothing => "Nothing".to_string(),
    }
}

pub(crate) fn ipe_main() -> IpeTask<()> {
    let _ipe_recursion_guard = crate::recursion_guard();
    io_println(format!(
        "{}{}",
        crate::main_show_result(crate::user_ipe_money_parse_currency("USD".to_string())),
        format!(
            "{}{}",
            "\n".to_string(),
            format!(
                "{}{}",
                crate::main_show_result(crate::user_ipe_money_parse_currency("BOGUS".to_string())),
                format!(
                    "{}{}",
                    "\n".to_string(),
                    crate::main_show_result(crate::user_ipe_money_parse_currency("".to_string()))
                )
            )
        )
    ))
}
