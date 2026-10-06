use crate::*;

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum IpeLengthUnit {
    Px,
    Vh,
    Vw,
}

impl IpeStringify for IpeLengthUnit {
    fn ipe_show(&self) -> String {
        match self {
            IpeLengthUnit::Px => "Px".to_string(),
            IpeLengthUnit::Vh => "Vh".to_string(),
            IpeLengthUnit::Vw => "Vw".to_string(),
        }
    }
}

pub(crate) fn user_ipe_length_to_css(n: i64, unit: IpeLengthUnit) -> String {
    let _ipe_recursion_guard = crate::recursion_guard();
    match unit {
        IpeLengthUnit::Px => format!("{}{}", string_from_int(n), "px".to_string()),
        IpeLengthUnit::Vh => format!("{}{}", string_from_int(n), "vh".to_string()),
        IpeLengthUnit::Vw => format!("{}{}", string_from_int(n), "vw".to_string()),
    }
}
