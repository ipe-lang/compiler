use crate::*;

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum IpeDbStoreColumn {
    Column(RecColTypeName),
}

impl IpeStringify for IpeDbStoreColumn {
    fn ipe_show(&self) -> String {
        match self {
            IpeDbStoreColumn::Column(p0) => format!("Column {}", IpeStringify::ipe_show(p0)),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum IpeDbStoreColumnSpec {
    PrimaryKey(String),
    Serial(String),
    Unique(String),
    DefaultNow(String),
    DefaultText(String, String),
    DefaultInt(String, i64),
    TouchOnUpdate(String),
}

impl IpeStringify for IpeDbStoreColumnSpec {
    fn ipe_show(&self) -> String {
        match self {
            IpeDbStoreColumnSpec::PrimaryKey(p0) => {
                format!("PrimaryKey {}", IpeStringify::ipe_show(p0))
            }
            IpeDbStoreColumnSpec::Serial(p0) => format!("Serial {}", IpeStringify::ipe_show(p0)),
            IpeDbStoreColumnSpec::Unique(p0) => format!("Unique {}", IpeStringify::ipe_show(p0)),
            IpeDbStoreColumnSpec::DefaultNow(p0) => {
                format!("DefaultNow {}", IpeStringify::ipe_show(p0))
            }
            IpeDbStoreColumnSpec::DefaultText(p0, p1) => format!(
                "DefaultText {} {}",
                IpeStringify::ipe_show(p0),
                IpeStringify::ipe_show(p1)
            ),
            IpeDbStoreColumnSpec::DefaultInt(p0, p1) => format!(
                "DefaultInt {} {}",
                IpeStringify::ipe_show(p0),
                IpeStringify::ipe_show(p1)
            ),
            IpeDbStoreColumnSpec::TouchOnUpdate(p0) => {
                format!("TouchOnUpdate {}", IpeStringify::ipe_show(p0))
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum IpeDbStorePrimaryKeyDecl {
    NoPk,
    SinglePk(String),
    CompositePk(String, String, Vec<String>),
}

impl IpeStringify for IpeDbStorePrimaryKeyDecl {
    fn ipe_show(&self) -> String {
        match self {
            IpeDbStorePrimaryKeyDecl::NoPk => "NoPk".to_string(),
            IpeDbStorePrimaryKeyDecl::SinglePk(p0) => {
                format!("SinglePk {}", IpeStringify::ipe_show(p0))
            }
            IpeDbStorePrimaryKeyDecl::CompositePk(p0, p1, p2) => format!(
                "CompositePk {} {} {}",
                IpeStringify::ipe_show(p0),
                IpeStringify::ipe_show(p1),
                IpeStringify::ipe_show(p2)
            ),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum IpeDbStoreIndexSpec {
    Index(Vec<String>),
    IndexNamed(String, Vec<String>),
}

impl IpeStringify for IpeDbStoreIndexSpec {
    fn ipe_show(&self) -> String {
        match self {
            IpeDbStoreIndexSpec::Index(p0) => format!("Index {}", IpeStringify::ipe_show(p0)),
            IpeDbStoreIndexSpec::IndexNamed(p0, p1) => format!(
                "IndexNamed {} {}",
                IpeStringify::ipe_show(p0),
                IpeStringify::ipe_show(p1)
            ),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum IpeDbStoreSchemaOp {
    RenameColumn(String, String),
    RenameTable(String, String),
}

impl IpeStringify for IpeDbStoreSchemaOp {
    fn ipe_show(&self) -> String {
        match self {
            IpeDbStoreSchemaOp::RenameColumn(p0, p1) => format!(
                "RenameColumn {} {}",
                IpeStringify::ipe_show(p0),
                IpeStringify::ipe_show(p1)
            ),
            IpeDbStoreSchemaOp::RenameTable(p0, p1) => format!(
                "RenameTable {} {}",
                IpeStringify::ipe_show(p0),
                IpeStringify::ipe_show(p1)
            ),
        }
    }
}

pub(crate) enum IpeDbStoreDraft<T1: 'static> {
    Draft(RecCodecCurrentColumnsFrozenColumnsFrozenTableIndexesOpsPkSpecsTable<T1>),
}

impl<T1: Clone + 'static> Clone for IpeDbStoreDraft<T1> {
    fn clone(&self) -> Self {
        match self {
            IpeDbStoreDraft::Draft(p0) => IpeDbStoreDraft::Draft(p0.clone()),
        }
    }
}

impl<T1: IpeStringify + 'static> IpeStringify for IpeDbStoreDraft<T1> {
    fn ipe_show(&self) -> String {
        match self {
            IpeDbStoreDraft::Draft(_) => format!("Draft {}", "<function>"),
        }
    }
}

pub(crate) enum IpeDbStoreStore<T1: 'static> {
    Store(RecCodecCurrentColumnsFrozenColumnsFrozenTableIndexesOpsPkSpecsTable<T1>),
}

impl<T1: Clone + 'static> Clone for IpeDbStoreStore<T1> {
    fn clone(&self) -> Self {
        match self {
            IpeDbStoreStore::Store(p0) => IpeDbStoreStore::Store(p0.clone()),
        }
    }
}

impl<T1: IpeStringify + 'static> IpeStringify for IpeDbStoreStore<T1> {
    fn ipe_show(&self) -> String {
        match self {
            IpeDbStoreStore::Store(_) => format!("Store {}", "<function>"),
        }
    }
}

pub(crate) fn user_ipe_db_store_valid_sql_ident_plain(name: String) -> bool {
    let _ipe_recursion_guard = crate::recursion_guard();
    (basics_not(string_is_empty(name.clone()))
    && string_all(
        {
            let __ipe_fn: Box<dyn Fn(char) -> bool + Send + Sync + 'static> =
                Box::new(crate::user_ipe_db_store_plain_ident_char);
            __ipe_fn
        },
        name,
    ))
}

pub(crate) fn user_ipe_db_store_plain_ident_char(c: char) -> bool {
    let _ipe_recursion_guard = crate::recursion_guard();
    ({
        let code = char_to_code(c);
        (crate::user_ipe_db_store_is_ascii_digit(code)
            || (crate::user_ipe_db_store_is_ascii_upper(code)
                || (crate::user_ipe_db_store_is_ascii_lower(code)
                    || (code == crate::user_ipe_db_store_underscore_code()))))
    })
}

pub(crate) fn user_ipe_db_store_is_ascii_digit(code: i64) -> bool {
    let _ipe_recursion_guard = crate::recursion_guard();
    ((code >= 48i64) && (code <= 57i64))
}

pub(crate) fn user_ipe_db_store_is_ascii_upper(code: i64) -> bool {
    let _ipe_recursion_guard = crate::recursion_guard();
    ((code >= 65i64) && (code <= 90i64))
}

pub(crate) fn user_ipe_db_store_is_ascii_lower(code: i64) -> bool {
    let _ipe_recursion_guard = crate::recursion_guard();
    ((code >= 97i64) && (code <= 122i64))
}

pub(crate) fn user_ipe_db_store_underscore_code() -> i64 {
    let _ipe_recursion_guard = crate::recursion_guard();
    static CELL: std::sync::OnceLock<i64> = std::sync::OnceLock::new();
    CELL.get_or_init(|| 95i64).clone()
}

pub(crate) fn user_ipe_db_store_column(name: String, colType: IpeCodecColType) -> IpeDbStoreColumn {
    let _ipe_recursion_guard = crate::recursion_guard();
    IpeDbStoreColumn::Column(RecColTypeName {
        colType: colType,
        name: name,
    })
}

pub(crate) fn user_ipe_db_store_text_column(name: String) -> IpeDbStoreColumn {
    let _ipe_recursion_guard = crate::recursion_guard();
    crate::user_ipe_db_store_column(name, IpeCodecColType::CText)
}

pub(crate) fn user_ipe_db_store_from_columns(
    table: String,
    columns: Vec<IpeDbStoreColumn>,
) -> IpeResult<ipe_runtime::error::IpeError, IpeDbStoreDraft<HashMap<String, String>>> {
    let _ipe_recursion_guard = crate::recursion_guard();
    crate::user_ipe_db_store_build_store(
        table,
        columns.clone(),
        crate::user_ipe_db_store_row_codec(columns),
    )
}

pub(crate) fn user_ipe_db_store_build_store<T1: Clone>(
    table: String,
    columns: Vec<IpeDbStoreColumn>,
    codec: IpeCodecCodec<T1>,
) -> IpeResult<ipe_runtime::error::IpeError, IpeDbStoreDraft<T1>> {
    let _ipe_recursion_guard = crate::recursion_guard();
    (if basics_not(crate::user_ipe_db_store_valid_sql_ident_plain(
        table.clone(),
    )) {
        IpeResult::Err(
            crate::user_ipe_db_store_invalid_ident_error("table".to_string(), table),
        )
    } else {
        match crate::user_ipe_db_store_first_invalid_column(columns.clone()) {
            IpeMaybe::Just(bad) => IpeResult::Err(
                crate::user_ipe_db_store_invalid_ident_error("column".to_string(), bad),
            ),
            IpeMaybe::Nothing => IpeResult::Ok(IpeDbStoreDraft::Draft(
                RecCodecCurrentColumnsFrozenColumnsFrozenTableIndexesOpsPkSpecsTable {
                    codec: codec,
                    currentColumns: columns.clone(),
                    frozenColumns: columns,
                    frozenTable: table.clone(),
                    indexes: Vec::<IpeDbStoreIndexSpec>::new(),
                    ops: Vec::<IpeDbStoreSchemaOp>::new(),
                    pk: IpeResult::Ok(IpeDbStorePrimaryKeyDecl::NoPk),
                    specs: Vec::<IpeDbStoreColumnSpec>::new(),
                    table: table,
                },
            )),
        }
    })
}

pub(crate) fn user_ipe_db_store_first_invalid_column(
    columns: Vec<IpeDbStoreColumn>,
) -> IpeMaybe<String> {
    let _ipe_recursion_guard = crate::recursion_guard();
    let mut columns = columns;
    loop {
        match (columns).as_slice() {
            [] => {
                return IpeMaybe::Nothing;
            }
            [first, rest @ ..] => {
                let first = first.clone();
                let rest = rest.to_vec();
                let name = crate::user_ipe_db_store_column_name(first);
                if crate::user_ipe_db_store_valid_sql_ident_plain(name.clone()) {
                    let __tco_0 = rest;
                    columns = __tco_0;
                    continue;
                } else {
                    return IpeMaybe::Just(name);
                }
            }
        }
    }
}

pub(crate) fn user_ipe_db_store_column_name(col: IpeDbStoreColumn) -> String {
    let _ipe_recursion_guard = crate::recursion_guard();
    match col {
        IpeDbStoreColumn::Column(r) => (r).name.clone(),
    }
}

pub(crate) fn user_ipe_db_store_row_codec(
    columns: Vec<IpeDbStoreColumn>,
) -> IpeCodecCodec<HashMap<String, String>> {
    let _ipe_recursion_guard = crate::recursion_guard();
    ({
        let names = list_map_consume(
            {
                let __ipe_fn: Box<dyn Fn(IpeDbStoreColumn) -> String + Send + Sync + 'static> =
                    Box::new(crate::user_ipe_db_store_column_name);
                __ipe_fn
            },
            columns,
        );
        IpeCodecCodec::Codec(RecEncMkDecShp {
            enc: ({
                let names = names.clone();
                {
                    let __ipe_fn: ::std::sync::Arc<
                        dyn Fn(HashMap<String, String>) -> JsonVal + Send + Sync + 'static,
                    > = ::std::sync::Arc::new(move |row: HashMap<String, String>| -> JsonVal {
                        json_enc_object(crate::user_ipe_db_store_row_fields(names.clone(), row))
                    });
                    __ipe_fn
                }
            }),
            mkDec: {
                let __ipe_fn: ::std::sync::Arc<
                    dyn Fn(Rec_) -> Decoder<HashMap<String, String>> + Send + Sync + 'static,
                > = ::std::sync::Arc::new(move |arg_13: Rec_| -> Decoder<HashMap<String, String>> {
                    config_dict(decode_map(({ let cap_0 = "".to_string(); { let __ipe_fn: Box<dyn Fn(IpeMaybe<String>) -> String + Send + Sync + 'static> = Box::new(move |eta_0: IpeMaybe<String>| -> String { maybe_with_default(cap_0.clone(), eta_0) }); __ipe_fn } }), config_nullable(json_decode_string::<IpeError>())))
                });
                __ipe_fn
            },
            shp: IpeCodecShape::SRecord(list_map_consume(
                {
                    let __ipe_fn: Box<
                        dyn Fn(String) -> (String, IpeCodecColType) + Send + Sync + 'static,
                    > = Box::new(move |name: String| -> (String, IpeCodecColType) {
                        (
                            name,
                            IpeCodecColType::CNull(Box::new(IpeCodecColType::CText)),
                        )
                    });
                    __ipe_fn
                },
                names,
            )),
        })
    })
}

pub(crate) fn user_ipe_db_store_row_fields(
    names: Vec<String>,
    row: HashMap<String, String>,
) -> Vec<(String, JsonVal)> {
    let _ipe_recursion_guard = crate::recursion_guard();
    list_map_consume(
        {
            let __ipe_fn: Box<dyn Fn(String) -> (String, JsonVal) + Send + Sync + 'static> =
                Box::new(move |name: String| -> (String, JsonVal) {
                    (
                        name.clone(),
                        json_enc_string(crate::user_ipe_db_store_row_cell(name, row.clone())),
                    )
                });
            __ipe_fn
        },
        names,
    )
}

pub(crate) fn user_ipe_db_store_row_cell(name: String, row: HashMap<String, String>) -> String {
    let _ipe_recursion_guard = crate::recursion_guard();
    match dict_get(name, row.clone()) {
        IpeMaybe::Just(s) => s,
        IpeMaybe::Nothing => "".to_string(),
    }
}

pub(crate) fn user_ipe_db_store_public<T1: Clone>(
    draft: IpeDbStoreDraft<T1>,
) -> IpeDbStoreStore<T1> {
    let _ipe_recursion_guard = crate::recursion_guard();
    match draft {
        IpeDbStoreDraft::Draft(r) => IpeDbStoreStore::Store(
            RecCodecCurrentColumnsFrozenColumnsFrozenTableIndexesOpsPkSpecsTable {
                codec: (r.clone()).codec.clone(),
                currentColumns: (r.clone()).currentColumns.clone(),
                frozenColumns: (r.clone()).frozenColumns.clone(),
                frozenTable: (r.clone()).frozenTable.clone(),
                indexes: (r.clone()).indexes.clone(),
                ops: (r.clone()).ops.clone(),
                pk: (r.clone()).pk.clone(),
                specs: (r.clone()).specs.clone(),
                table: (r).table.clone(),
            },
        ),
    }
}

pub(crate) fn user_ipe_db_store_key_decl_fault(
    pk: IpeResult<ipe_runtime::error::IpeError, IpeDbStorePrimaryKeyDecl>,
) -> IpeMaybe<ipe_runtime::error::IpeError> {
    let _ipe_recursion_guard = crate::recursion_guard();
    match pk {
        IpeResult::Err(e) => IpeMaybe::Just(e),
        IpeResult::Ok(_) => IpeMaybe::Nothing,
    }
}

pub(crate) fn user_ipe_db_store_all<T1: 'static + Send + Sync + Clone>(
    conn: Db,
    store: IpeDbStoreStore<T1>,
) -> IpeTask<Vec<T1>> {
    let _ipe_recursion_guard = crate::recursion_guard();
    match store.clone() {
        IpeDbStoreStore::Store(r) => match crate::user_ipe_db_store_key_decl_fault((r.clone()).pk.clone())
        {
            IpeMaybe::Just(e) => task_fail(e),
            IpeMaybe::Nothing => task_and_then(
                crate::user_ipe_db_store_read_cells(
                    conn,
                    store,
                    crate::user_ipe_db_store_always_true(),
                ),
                Box::new(move |rows: Vec<HashMap<String, IpeMaybe<String>>>| -> IpeTask<Vec<T1>> {
                    crate::user_ipe_db_store_decode_rows((r.clone()).codec.clone(), rows)
                }),
            ),
        },
    }
}

pub(crate) fn user_ipe_db_store_always_true() -> ipe_runtime::db::SqlFragment {
    let _ipe_recursion_guard = crate::recursion_guard();
    sql_eq(
        sql_param(MainSqlValue::SqlInt(1i64)),
        sql_param(MainSqlValue::SqlInt(1i64)),
    )
}

pub(crate) fn user_ipe_db_store_read_cells<T1: 'static + Send + Clone>(
    conn: Db,
    store: IpeDbStoreStore<T1>,
    cond: ipe_runtime::db::SqlFragment,
) -> IpeTask<Vec<HashMap<String, IpeMaybe<String>>>> {
    let _ipe_recursion_guard = crate::recursion_guard();
    match store {
        IpeDbStoreStore::Store(r) => db_find_where_masked(conn.clone(), (r.clone()).table.clone(), list_map_consume({ let __ipe_fn: Box<dyn Fn(IpeDbStoreColumn) -> ipe_runtime::db::SqlFragment + Send + Sync + 'static> = Box::new(move |col: IpeDbStoreColumn| -> ipe_runtime::db::SqlFragment { sql_column(crate::user_ipe_db_store_column_name(col)) }); __ipe_fn }, (r).currentColumns.clone()), cond, crate::user_ipe_db_store_cells_decoder()),
    }
}

pub(crate) fn user_ipe_db_store_cells_decoder() -> Decoder<HashMap<String, IpeMaybe<String>>> {
    let _ipe_recursion_guard = crate::recursion_guard();
    config_dict(config_nullable(decode_one_of(vec![json_decode_string::<IpeError>(), decode_map({ let __ipe_fn: Box<dyn Fn(i64) -> String + Send + Sync + 'static> = Box::new(string_from_int); __ipe_fn }, json_decode_int::<IpeError>()), decode_map({ let __ipe_fn: Box<dyn Fn(f64) -> String + Send + Sync + 'static> = Box::new(string_from_float); __ipe_fn }, json_decode_float::<IpeError>()), decode_map({ let __ipe_fn: Box<dyn Fn(bool) -> String + Send + Sync + 'static> = Box::new(string_from_bool); __ipe_fn }, json_decode_bool::<IpeError>())])))
}

pub(crate) fn user_ipe_db_store_decode_rows<T1: 'static + Send + Sync + Clone>(
    codec: IpeCodecCodec<T1>,
    rows: Vec<HashMap<String, IpeMaybe<String>>>,
) -> IpeTask<Vec<T1>> {
    let _ipe_recursion_guard = crate::recursion_guard();
    match (rows).as_slice() {
        [] => task_succeed(Vec::<T1>::new()),
        [first, rest @ ..] => {
            let first = first.clone();
            let rest = rest.to_vec();
            match crate::user_ipe_db_codec_codec_from_row(codec.clone(), first) {
                IpeResult::Err(e) => task_fail(e),
                IpeResult::Ok(value) => task_map(
                    {
                        let __ipe_fn: Box<dyn Fn(Vec<T1>) -> Vec<T1> + Send + Sync + 'static> =
                            Box::new(move |more: Vec<T1>| -> Vec<T1> {
                                ipe_runtime::list::ipe_list_cons(value.clone(), more)
                            });
                        __ipe_fn
                    },
                    crate::user_ipe_db_store_decode_rows(codec, rest),
                ),
            }
        }
    }
}

pub(crate) fn user_ipe_db_store_read_text(
    name: String,
    row: HashMap<String, String>,
) -> IpeResult<ipe_runtime::error::IpeError, String> {
    let _ipe_recursion_guard = crate::recursion_guard();
    match dict_get(name.clone(), row.clone()) {
        IpeMaybe::Just(s) => IpeResult::Ok(s),
        IpeMaybe::Nothing => IpeResult::Err(crate::user_ipe_db_store_missing_column_error(name)),
    }
}

pub(crate) fn user_ipe_db_store_invalid_ident_error(
    kind: String,
    name: String,
) -> ipe_runtime::error::IpeError {
    let _ipe_recursion_guard = crate::recursion_guard();
    ipe_error_invalid_input(string_concat(vec![
        "Ipe.Db.Store: rejected ".to_string(),
        kind,
        " identifier \"".to_string(),
        name,
        "\" — not a valid SQL identifier".to_string(),
    ]))
}

pub(crate) fn user_ipe_db_store_missing_column_error(name: String) -> ipe_runtime::error::IpeError {
    let _ipe_recursion_guard = crate::recursion_guard();
    ipe_error_invalid_input(string_concat(vec![
        "Ipe.Db.Store: row is missing column \"".to_string(),
        name,
        "\"".to_string(),
    ]))
}
