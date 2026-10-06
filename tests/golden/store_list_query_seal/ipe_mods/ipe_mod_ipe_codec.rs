use crate::*;

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum IpeCodecColType {
    CText,
    CInt,
    CReal,
    CBool,
    CBlob,
    CTime,
    CDecimal,
    CMoney,
    CNull(Box<IpeCodecColType>),
}

impl IpeStringify for IpeCodecColType {
    fn ipe_show(&self) -> String {
        match self {
            IpeCodecColType::CText => "CText".to_string(),
            IpeCodecColType::CInt => "CInt".to_string(),
            IpeCodecColType::CReal => "CReal".to_string(),
            IpeCodecColType::CBool => "CBool".to_string(),
            IpeCodecColType::CBlob => "CBlob".to_string(),
            IpeCodecColType::CTime => "CTime".to_string(),
            IpeCodecColType::CDecimal => "CDecimal".to_string(),
            IpeCodecColType::CMoney => "CMoney".to_string(),
            IpeCodecColType::CNull(p0) => format!("CNull {}", IpeStringify::ipe_show(p0)),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum IpeCodecShape {
    SRecord(Vec<(String, IpeCodecColType)>),
    SScalar(IpeCodecColType),
    SBlob,
}

impl IpeStringify for IpeCodecShape {
    fn ipe_show(&self) -> String {
        match self {
            IpeCodecShape::SRecord(p0) => format!("SRecord {}", IpeStringify::ipe_show(p0)),
            IpeCodecShape::SScalar(p0) => format!("SScalar {}", IpeStringify::ipe_show(p0)),
            IpeCodecShape::SBlob => "SBlob".to_string(),
        }
    }
}

pub(crate) enum IpeCodecCodec<T1: 'static> {
    Codec(RecEncMkDecShp<T1>),
}

impl<T1: Clone + 'static> Clone for IpeCodecCodec<T1> {
    fn clone(&self) -> Self {
        match self {
            IpeCodecCodec::Codec(p0) => IpeCodecCodec::Codec(p0.clone()),
        }
    }
}

impl<T1: IpeStringify + 'static> IpeStringify for IpeCodecCodec<T1> {
    fn ipe_show(&self) -> String {
        match self {
            IpeCodecCodec::Codec(_) => format!("Codec {}", "<function>"),
        }
    }
}
