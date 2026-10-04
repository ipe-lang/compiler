use crate::*;

pub(crate) fn main_read_name(
    row: HashMap<String, String>,
) -> IpeResult<ipe_runtime::error::IpeError, String> {
    let _ipe_recursion_guard = crate::recursion_guard();
    crate::user_ipe_db_store_read_text("name".to_string(), row)
}

pub(crate) fn main_fetch_names(
    db: Db,
    store: IpeDbStoreStore<HashMap<String, String>>,
) -> IpeTask<Vec<String>> {
    let _ipe_recursion_guard = crate::recursion_guard();
    task_and_then(crate::user_ipe_db_store_all(db, store), {
        let __ipe_fn: Box<
            dyn Fn(Vec<HashMap<String, String>>) -> IpeTask<Vec<String>> + Send + Sync + 'static,
        > = Box::new(crate::main_decode_names);
        __ipe_fn
    })
}

pub(crate) fn main_decode_names(rows: Vec<HashMap<String, String>>) -> IpeTask<Vec<String>> {
    let _ipe_recursion_guard = crate::recursion_guard();
    match result_combine(list_map_consume({ let __ipe_fn: Box<dyn Fn(HashMap<String, String>) -> IpeResult<ipe_runtime::error::IpeError, String> + Send + Sync + 'static> = Box::new(crate::main_read_name); __ipe_fn }, rows))
    {
        IpeResult::Ok(names) => task_succeed(names),
        IpeResult::Err(e) => task_fail(e),
    }
}

pub(crate) fn ipe_main() -> IpeTask<()> {
    let _ipe_recursion_guard = crate::recursion_guard();
    task_and_then(
        task_on_error(
            {
                let __ipe_fn: Box<
                    dyn Fn(ipe_runtime::error::IpeError) -> IpeTask<()> + Send + Sync + 'static,
                > = Box::new(move |arg_17: ipe_runtime::error::IpeError| -> IpeTask<()> {
                    task_succeed(())
                });
                __ipe_fn
            },
            task_and_then(
                db_connect(()),
                Box::new(move |db: Db| -> IpeTask<()> {
                    task_and_then(
                        task_from_result(ipe_result_map(
                            crate::user_ipe_db_store_from_columns("names".to_string(), vec![
                                crate::user_ipe_db_store_text_column("name".to_string()),
                            ]),
                            {
                                let __ipe_fn: Box<
                                    dyn Fn(IpeDbStoreDraft<HashMap<String, String>>) -> IpeDbStoreStore<HashMap<String, String>>
                                        + Send
                                        + Sync
                                        + 'static,
                                > = Box::new(crate::user_ipe_db_store_public);
                                __ipe_fn
                            },
                        )),
                        Box::new(move |store: IpeDbStoreStore<HashMap<String, String>>| -> IpeTask<()> {
                            task_and_then(
                                crate::main_fetch_names(db.clone(), store),
                                Box::new(move |arg_18: Vec<String>| -> IpeTask<()> {
                                    task_succeed(())
                                }),
                            )
                        }),
                    )
                }),
            ),
        ),
        Box::new(move |arg_16: ()| -> IpeTask<()> {
            io_println("store-list-query-seal".to_string())
        }),
    )
}
