use crate::*;

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum IpeDbCodecCell {
    CellAbsent,
    CellNull,
    CellText(String),
}

impl IpeStringify for IpeDbCodecCell {
    fn ipe_show(&self) -> String {
        match self {
            IpeDbCodecCell::CellAbsent => "CellAbsent".to_string(),
            IpeDbCodecCell::CellNull => "CellNull".to_string(),
            IpeDbCodecCell::CellText(p0) => format!(
                "CellText {}",
                (&ipe_runtime::stringify::Wrap(p0)).dispatch()
            ),
        }
    }
}

pub(crate) fn user_ipe_db_codec_codec_from_row<T1: 'static + Send + Clone>(
    codec: IpeCodecCodec<T1>,
    row: HashMap<String, IpeMaybe<String>>,
) -> IpeResult<ipe_runtime::error::IpeError, T1> {
    let _ipe_recursion_guard = crate::recursion_guard();
    match codec {
        IpeCodecCodec::Codec(r) => match (r.clone()).shp.clone() {
            IpeCodecShape::SRecord(columns) => match crate::user_ipe_db_codec_value_from_row(row, columns)
            {
                IpeResult::Ok(value) => decode_from_json_value((r).mkDec.clone()(Rec_ {}), value),
                IpeResult::Err(e) => IpeResult::Err(e),
            },
            IpeCodecShape::SScalar(_) => {
                IpeResult::Err(crate::user_ipe_db_codec_not_a_record_error())
            }
            IpeCodecShape::SBlob => IpeResult::Err(crate::user_ipe_db_codec_not_a_record_error()),
        },
    }
}

pub(crate) fn user_ipe_db_codec_value_from_row(
    row: HashMap<String, IpeMaybe<String>>,
    columns: Vec<(String, IpeCodecColType)>,
) -> IpeResult<ipe_runtime::error::IpeError, JsonVal> {
    let _ipe_recursion_guard = crate::recursion_guard();
    match crate::user_ipe_db_codec_fields_from_row(row, columns) {
        IpeResult::Ok(fields) => IpeResult::Ok(json_enc_object(fields)),
        IpeResult::Err(e) => IpeResult::Err(e),
    }
}

pub(crate) fn user_ipe_db_codec_fields_from_row(
    row: HashMap<String, IpeMaybe<String>>,
    columns: Vec<(String, IpeCodecColType)>,
) -> IpeResult<ipe_runtime::error::IpeError, Vec<(String, JsonVal)>> {
    let _ipe_recursion_guard = crate::recursion_guard();
    list_foldr(
        {
            let __ipe_fn: Box<
                dyn Fn((String, IpeCodecColType), IpeResult<ipe_runtime::error::IpeError, Vec<(String, JsonVal)>>) -> IpeResult<ipe_runtime::error::IpeError, Vec<(String, JsonVal)>>
                    + Send
                    + Sync
                    + 'static,
            > = Box::new(
                move |col: (String, IpeCodecColType), acc: IpeResult<ipe_runtime::error::IpeError, Vec<(String, JsonVal)>>| -> IpeResult<ipe_runtime::error::IpeError, Vec<(String, JsonVal)>> {
                    crate::user_ipe_db_codec_cons_field(row.clone(), col, acc)
                },
            );
            __ipe_fn
        },
        IpeResult::Ok(Vec::<(String, JsonVal)>::new()),
        columns,
    )
}

pub(crate) fn user_ipe_db_codec_cons_field(
    row: HashMap<String, IpeMaybe<String>>,
    col: (String, IpeCodecColType),
    acc: IpeResult<ipe_runtime::error::IpeError, Vec<(String, JsonVal)>>,
) -> IpeResult<ipe_runtime::error::IpeError, Vec<(String, JsonVal)>> {
    let _ipe_recursion_guard = crate::recursion_guard();
    match acc {
        IpeResult::Err(e) => IpeResult::Err(e),
        IpeResult::Ok(rest) => {
            ({
                let (name, colType) = col;
                match crate::user_ipe_db_codec_cell_to_value(name.clone(), colType, crate::user_ipe_db_codec_lookup_cell(name.clone(), row))
                {
                    IpeResult::Ok(node) => {
                        IpeResult::Ok(ipe_runtime::list::ipe_list_cons((name, node), rest))
                    }
                    IpeResult::Err(e) => IpeResult::Err(e),
                }
            })
        }
    }
}

pub(crate) fn user_ipe_db_codec_lookup_cell(
    name: String,
    row: HashMap<String, IpeMaybe<String>>,
) -> IpeDbCodecCell {
    let _ipe_recursion_guard = crate::recursion_guard();
    match dict_get(name, row.clone()) {
        IpeMaybe::Nothing => IpeDbCodecCell::CellAbsent,
        IpeMaybe::Just(maybeText) => match maybeText {
            IpeMaybe::Nothing => IpeDbCodecCell::CellNull,
            IpeMaybe::Just(text) => IpeDbCodecCell::CellText(text),
        },
    }
}

pub(crate) fn user_ipe_db_codec_cell_to_value(
    name: String,
    colType: IpeCodecColType,
    cell: IpeDbCodecCell,
) -> IpeResult<ipe_runtime::error::IpeError, JsonVal> {
    let _ipe_recursion_guard = crate::recursion_guard();
    let mut name = name;
    let mut colType = colType;
    let mut cell = cell;
    loop {
        match colType.clone() {
            IpeCodecColType::CNull(inner) => {
                let inner = *inner;
                match cell.clone() {
                    IpeDbCodecCell::CellNull => {
                        return IpeResult::Ok(json_enc_null());
                    }
                    IpeDbCodecCell::CellAbsent => {
                        return IpeResult::Err(crate::user_ipe_db_codec_missing_column_error(name));
                    }
                    IpeDbCodecCell::CellText(_) => {
                        let __tco_0 = name;
                        let __tco_1 = inner;
                        let __tco_2 = cell;
                        name = __tco_0;
                        colType = __tco_1;
                        cell = __tco_2;
                        continue;
                    }
                }
            }
            IpeCodecColType::CText => {
                return crate::user_ipe_db_codec_require_text(name.clone(), cell, move |eta_0: String| -> IpeResult<ipe_runtime::error::IpeError, JsonVal> { crate::user_ipe_db_codec_scalar_cell_to_value(name.clone(), colType.clone(), eta_0) });
            }
            IpeCodecColType::CInt => {
                return crate::user_ipe_db_codec_require_text(name.clone(), cell, move |eta_1: String| -> IpeResult<ipe_runtime::error::IpeError, JsonVal> { crate::user_ipe_db_codec_scalar_cell_to_value(name.clone(), colType.clone(), eta_1) });
            }
            IpeCodecColType::CReal => {
                return crate::user_ipe_db_codec_require_text(name.clone(), cell, move |eta_2: String| -> IpeResult<ipe_runtime::error::IpeError, JsonVal> { crate::user_ipe_db_codec_scalar_cell_to_value(name.clone(), colType.clone(), eta_2) });
            }
            IpeCodecColType::CBool => {
                return crate::user_ipe_db_codec_require_text(name.clone(), cell, move |eta_3: String| -> IpeResult<ipe_runtime::error::IpeError, JsonVal> { crate::user_ipe_db_codec_scalar_cell_to_value(name.clone(), colType.clone(), eta_3) });
            }
            IpeCodecColType::CTime => {
                return crate::user_ipe_db_codec_require_text(name.clone(), cell, move |eta_4: String| -> IpeResult<ipe_runtime::error::IpeError, JsonVal> { crate::user_ipe_db_codec_scalar_cell_to_value(name.clone(), colType.clone(), eta_4) });
            }
            IpeCodecColType::CDecimal => {
                return crate::user_ipe_db_codec_require_text(name.clone(), cell, move |eta_5: String| -> IpeResult<ipe_runtime::error::IpeError, JsonVal> { crate::user_ipe_db_codec_scalar_cell_to_value(name.clone(), colType.clone(), eta_5) });
            }
            IpeCodecColType::CMoney => {
                return crate::user_ipe_db_codec_require_text(name.clone(), cell, move |eta_6: String| -> IpeResult<ipe_runtime::error::IpeError, JsonVal> { crate::user_ipe_db_codec_scalar_cell_to_value(name.clone(), colType.clone(), eta_6) });
            }
            IpeCodecColType::CBlob => {
                return crate::user_ipe_db_codec_require_text(name.clone(), cell, move |eta_7: String| -> IpeResult<ipe_runtime::error::IpeError, JsonVal> { crate::user_ipe_db_codec_scalar_cell_to_value(name.clone(), colType.clone(), eta_7) });
            }
        }
    }
}

pub(crate) fn user_ipe_db_codec_require_text<
    FN2: Fn(String) -> IpeResult<ipe_runtime::error::IpeError,
    JsonVal> + Send + Sync + 'static,
>(
    name: String,
    cell: IpeDbCodecCell,
    parse: FN2,
) -> IpeResult<ipe_runtime::error::IpeError, JsonVal> {
    let _ipe_recursion_guard = crate::recursion_guard();
    match cell {
        IpeDbCodecCell::CellText(text) => (parse)(text),
        IpeDbCodecCell::CellNull => IpeResult::Err(crate::user_ipe_db_codec_null_cell_error(name)),
        IpeDbCodecCell::CellAbsent => {
            IpeResult::Err(crate::user_ipe_db_codec_missing_column_error(name))
        }
    }
}

pub(crate) fn user_ipe_db_codec_scalar_cell_to_value(
    name: String,
    colType: IpeCodecColType,
    cell: String,
) -> IpeResult<ipe_runtime::error::IpeError, JsonVal> {
    let _ipe_recursion_guard = crate::recursion_guard();
    let mut name = name;
    let mut colType = colType;
    let mut cell = cell;
    loop {
        match colType.clone() {
            IpeCodecColType::CText => {
                return IpeResult::Ok(json_enc_string(cell));
            }
            IpeCodecColType::CInt => {
                match string_to_int(cell.clone()) {
                    IpeMaybe::Just(n) => {
                        return IpeResult::Ok(json_enc_int(n));
                    }
                    IpeMaybe::Nothing => {
                        return IpeResult::Err(crate::user_ipe_db_codec_bad_cell_error(name, colType, cell));
                    }
                }
            }
            IpeCodecColType::CReal => {
                match string_to_float(cell.clone()) {
                    IpeMaybe::Just(f) => {
                        return IpeResult::Ok(json_enc_float(f));
                    }
                    IpeMaybe::Nothing => {
                        return IpeResult::Err(crate::user_ipe_db_codec_bad_cell_error(name, colType, cell));
                    }
                }
            }
            IpeCodecColType::CBool => {
                match crate::user_ipe_db_codec_bool_from_cell(cell.clone()) {
                    IpeMaybe::Just(b) => {
                        return IpeResult::Ok(json_enc_bool(b));
                    }
                    IpeMaybe::Nothing => {
                        return IpeResult::Err(crate::user_ipe_db_codec_bad_cell_error(name, colType, cell));
                    }
                }
            }
            IpeCodecColType::CTime => {
                match string_to_int(cell.clone()) {
                    IpeMaybe::Just(ms) => {
                        return IpeResult::Ok(json_enc_int(ms));
                    }
                    IpeMaybe::Nothing => {
                        return IpeResult::Err(crate::user_ipe_db_codec_bad_cell_error(name, colType, cell));
                    }
                }
            }
            IpeCodecColType::CDecimal => {
                match decimal_from_string::<IpeError>(cell.clone()) {
                    IpeResult::Ok(_) => {
                        return IpeResult::Ok(json_enc_string(cell));
                    }
                    IpeResult::Err(_) => {
                        return IpeResult::Err(crate::user_ipe_db_codec_bad_cell_error(name, colType, cell));
                    }
                }
            }
            IpeCodecColType::CMoney => {
                return IpeResult::Ok(json_enc_string(cell));
            }
            IpeCodecColType::CBlob => {
                return decode_from_json_string(decode_value_identity::<IpeError>(), cell);
            }
            IpeCodecColType::CNull(inner) => {
                let inner = *inner;
                let __tco_0 = name;
                let __tco_1 = inner;
                let __tco_2 = cell;
                name = __tco_0;
                colType = __tco_1;
                cell = __tco_2;
                continue;
            }
        }
    }
}

pub(crate) fn user_ipe_db_codec_bool_from_cell(cell: String) -> IpeMaybe<bool> {
    let _ipe_recursion_guard = crate::recursion_guard();
    match (cell).as_str() {
        "1" => IpeMaybe::Just(true),
        "0" => IpeMaybe::Just(false),
        "true" => IpeMaybe::Just(true),
        "false" => IpeMaybe::Just(false),
        _ => IpeMaybe::Nothing,
    }
}

pub(crate) fn user_ipe_db_codec_not_a_record_error() -> ipe_runtime::error::IpeError {
    let _ipe_recursion_guard = crate::recursion_guard();
    ipe_error_invalid_input(
        "Ipe.Db.Codec: the codec's shape is not a record, so it has no columns to bind or read"
            .to_string(),
    )
}

pub(crate) fn user_ipe_db_codec_missing_column_error(name: String) -> ipe_runtime::error::IpeError {
    let _ipe_recursion_guard = crate::recursion_guard();
    ipe_error_invalid_input(string_concat(vec![
        "Ipe.Db.Codec: row is missing the required column \"".to_string(),
        name,
        "\"".to_string(),
    ]))
}

pub(crate) fn user_ipe_db_codec_null_cell_error(name: String) -> ipe_runtime::error::IpeError {
    let _ipe_recursion_guard = crate::recursion_guard();
    ipe_error_invalid_input(string_concat(vec![
        "Ipe.Db.Codec: column \"".to_string(),
        name,
        "\" is NULL but its field is not a Maybe".to_string(),
    ]))
}

pub(crate) fn user_ipe_db_codec_bad_cell_error(
    name: String,
    colType: IpeCodecColType,
    cell: String,
) -> ipe_runtime::error::IpeError {
    let _ipe_recursion_guard = crate::recursion_guard();
    ipe_error_invalid_input(string_concat(vec![
        "Ipe.Db.Codec: column \"".to_string(),
        name,
        "\" cell \"".to_string(),
        cell,
        "\" is not a ".to_string(),
        crate::user_ipe_db_codec_col_type_name(colType),
    ]))
}

pub(crate) fn user_ipe_db_codec_col_type_name(colType: IpeCodecColType) -> String {
    let _ipe_recursion_guard = crate::recursion_guard();
    let mut colType = colType;
    loop {
        match colType {
            IpeCodecColType::CText => {
                return "text value".to_string();
            }
            IpeCodecColType::CInt => {
                return "integer".to_string();
            }
            IpeCodecColType::CReal => {
                return "real number".to_string();
            }
            IpeCodecColType::CBool => {
                return "boolean".to_string();
            }
            IpeCodecColType::CTime => {
                return "integer timestamp".to_string();
            }
            IpeCodecColType::CDecimal => {
                return "exact decimal string".to_string();
            }
            IpeCodecColType::CMoney => {
                return "money string (AMOUNT ISO_CODE)".to_string();
            }
            IpeCodecColType::CBlob => {
                return "JSON value".to_string();
            }
            IpeCodecColType::CNull(inner) => {
                let inner = *inner;
                let __tco_0 = inner;
                colType = __tco_0;
                continue;
            }
        }
    }
}
