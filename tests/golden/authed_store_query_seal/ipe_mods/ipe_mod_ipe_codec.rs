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
            IpeCodecColType::CNull(p0) => {
                format!("CNull {}", (&ipe_runtime::stringify::Wrap(p0)).dispatch())
            }
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
            IpeCodecShape::SRecord(p0) => {
                format!("SRecord {}", (&ipe_runtime::stringify::Wrap(p0)).dispatch())
            }
            IpeCodecShape::SScalar(p0) => {
                format!("SScalar {}", (&ipe_runtime::stringify::Wrap(p0)).dispatch())
            }
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

impl<T1: IpeStringify + std::fmt::Debug + 'static> IpeStringify for IpeCodecCodec<T1> {
    fn ipe_show(&self) -> String {
        match self {
            IpeCodecCodec::Codec(_) => format!("Codec {}", "<fn>"),
        }
    }
}

pub(crate) fn user_ipe_codec_shape<T1: Clone>(codec: IpeCodecCodec<T1>) -> IpeCodecShape {
    let _ipe_recursion_guard = crate::recursion_guard();
    match codec {
        IpeCodecCodec::Codec(r) => (r).shp.clone(),
    }
}
