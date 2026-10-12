use crate::*;

pub(crate) fn main_doc_codec() -> IpeCodecCodec<RecAuthorBody> {
    let _ipe_recursion_guard = crate::recursion_guard();
    IpeCodecCodec::Codec(RecEncMkDecShp {
        enc: {
            let __ipe_fn: ::std::sync::Arc<
                dyn Fn(RecAuthorBody) -> JsonVal + Send + Sync + 'static,
            > = ::std::sync::Arc::new(move |codec_rec_4026639940: RecAuthorBody| -> JsonVal {
                json_enc_object(vec![
                    (
                        "author".to_string(),
                        json_enc_string((codec_rec_4026639940.clone()).author.clone()),
                    ),
                    (
                        "body".to_string(),
                        json_enc_string((codec_rec_4026639940).body.clone()),
                    ),
                ])
            });
            __ipe_fn
        },
        mkDec: {
            let __ipe_fn: ::std::sync::Arc<
                dyn Fn(Rec_) -> Decoder<RecAuthorBody> + Send + Sync + 'static,
            > = ::std::sync::Arc::new(move |arg_16: Rec_| -> Decoder<RecAuthorBody> {
                ({
                    let cap_0 = "body".to_string();
                    ({
                        let cap_1 = json_decode_string::<IpeError>();
                        {
                            let __ipe_fn: Box<
                                dyn Fn(Decoder<Box<dyn FnOnce(String) -> RecAuthorBody + Send + 'static>>) -> Decoder<RecAuthorBody>
                                    + Send
                                    + Sync
                                    + 'static,
                            > = Box::new(
                                move |eta_1: Decoder<Box<dyn FnOnce(String) -> RecAuthorBody + Send + 'static>>| -> Decoder<RecAuthorBody> {
                                    decode_pipeline_required(cap_0.clone(), cap_1.clone(), eta_1)
                                },
                            );
                            __ipe_fn
                        }
                    })
                })(
                    ({
                        let cap_0 = "author".to_string();
                        ({
                            let cap_1 = json_decode_string::<IpeError>();
                            {
                                let __ipe_fn: Box<
                                    dyn Fn(Decoder<Box<dyn FnOnce(String) -> Box<dyn FnOnce(String) -> RecAuthorBody + Send + 'static> + Send + 'static>>) -> Decoder<Box<dyn FnOnce(String) -> RecAuthorBody + Send + 'static>>
                                        + Send
                                        + Sync
                                        + 'static,
                                > = Box::new(
                                    move |eta_0: Decoder<Box<dyn FnOnce(String) -> Box<dyn FnOnce(String) -> RecAuthorBody + Send + 'static> + Send + 'static>>| -> Decoder<Box<dyn FnOnce(String) -> RecAuthorBody + Send + 'static>> {
                                        decode_pipeline_required(
                                            cap_0.clone(),
                                            cap_1.clone(),
                                            eta_0,
                                        )
                                    },
                                );
                                __ipe_fn
                            }
                        })
                    })(
                        decode_succeed(curry2(move |author: String, body: String| -> RecAuthorBody { RecAuthorBody { author: author, body: body } })),
                    ),
                )
            });
            __ipe_fn
        },
        shp: IpeCodecShape::SRecord(vec![("author".to_string(), IpeCodecColType::CText), (
            "body".to_string(),
            IpeCodecColType::CText,
        )]),
    })
}

pub(crate) fn main_doc_policy() -> IpeDbStorePolicy {
    let _ipe_recursion_guard = crate::recursion_guard();
    crate::user_ipe_db_store_owner_column_named("author".to_string())
}

pub(crate) fn main_secured_docs() -> IpeResult<
    ipe_runtime::error::IpeError, IpeDbStoreSecured<RecAuthorBody>,
> {
    let _ipe_recursion_guard = crate::recursion_guard();
    match crate::user_ipe_db_store_from_codec("docs".to_string(), crate::main_doc_codec()) {
        IpeResult::Err(e) => IpeResult::Err(e),
        IpeResult::Ok(store) => crate::user_ipe_db_store_secured(crate::main_doc_policy(), store),
    }
}

pub(crate) fn main_share_codec() -> IpeCodecCodec<RecDocRefMember> {
    let _ipe_recursion_guard = crate::recursion_guard();
    IpeCodecCodec::Codec(RecEncMkDecShp {
        enc: {
            let __ipe_fn: ::std::sync::Arc<
                dyn Fn(RecDocRefMember) -> JsonVal + Send + Sync + 'static,
            > = ::std::sync::Arc::new(move |codec_rec_4026691588: RecDocRefMember| -> JsonVal {
                json_enc_object(vec![
                    (
                        "doc_ref".to_string(),
                        json_enc_string((codec_rec_4026691588.clone()).docRef.clone()),
                    ),
                    (
                        "member".to_string(),
                        json_enc_string((codec_rec_4026691588).member.clone()),
                    ),
                ])
            });
            __ipe_fn
        },
        mkDec: {
            let __ipe_fn: ::std::sync::Arc<
                dyn Fn(Rec_) -> Decoder<RecDocRefMember> + Send + Sync + 'static,
            > = ::std::sync::Arc::new(move |arg_17: Rec_| -> Decoder<RecDocRefMember> {
                ({
                    let cap_0 = "member".to_string();
                    ({
                        let cap_1 = json_decode_string::<IpeError>();
                        {
                            let __ipe_fn: Box<
                                dyn Fn(Decoder<Box<dyn FnOnce(String) -> RecDocRefMember + Send + 'static>>) -> Decoder<RecDocRefMember>
                                    + Send
                                    + Sync
                                    + 'static,
                            > = Box::new(
                                move |eta_1: Decoder<Box<dyn FnOnce(String) -> RecDocRefMember + Send + 'static>>| -> Decoder<RecDocRefMember> {
                                    decode_pipeline_required(cap_0.clone(), cap_1.clone(), eta_1)
                                },
                            );
                            __ipe_fn
                        }
                    })
                })(
                    ({
                        let cap_0 = "doc_ref".to_string();
                        ({
                            let cap_1 = json_decode_string::<IpeError>();
                            {
                                let __ipe_fn: Box<
                                    dyn Fn(Decoder<Box<dyn FnOnce(String) -> Box<dyn FnOnce(String) -> RecDocRefMember + Send + 'static> + Send + 'static>>) -> Decoder<Box<dyn FnOnce(String) -> RecDocRefMember + Send + 'static>>
                                        + Send
                                        + Sync
                                        + 'static,
                                > = Box::new(
                                    move |eta_0: Decoder<Box<dyn FnOnce(String) -> Box<dyn FnOnce(String) -> RecDocRefMember + Send + 'static> + Send + 'static>>| -> Decoder<Box<dyn FnOnce(String) -> RecDocRefMember + Send + 'static>> {
                                        decode_pipeline_required(
                                            cap_0.clone(),
                                            cap_1.clone(),
                                            eta_0,
                                        )
                                    },
                                );
                                __ipe_fn
                            }
                        })
                    })(
                        decode_succeed(curry2(move |docRef: String, member: String| -> RecDocRefMember { RecDocRefMember { docRef: docRef, member: member } })),
                    ),
                )
            });
            __ipe_fn
        },
        shp: IpeCodecShape::SRecord(vec![("doc_ref".to_string(), IpeCodecColType::CText), (
            "member".to_string(),
            IpeCodecColType::CText,
        )]),
    })
}

pub(crate) fn main_share_policy() -> IpeDbStorePolicy {
    let _ipe_recursion_guard = crate::recursion_guard();
    crate::user_ipe_db_store_owner_column_named("member".to_string())
}

pub(crate) fn main_secured_shares() -> IpeResult<
    ipe_runtime::error::IpeError, IpeDbStoreSecured<RecDocRefMember>,
> {
    let _ipe_recursion_guard = crate::recursion_guard();
    match crate::user_ipe_db_store_from_codec("shares".to_string(), crate::main_share_codec()) {
        IpeResult::Err(e) => IpeResult::Err(e),
        IpeResult::Ok(store) => crate::user_ipe_db_store_secured(crate::main_share_policy(), store),
    }
}

pub(crate) fn main_shared_docs_policy(
    securedShare: IpeDbStoreSecured<RecDocRefMember>,
) -> IpeDbStorePolicy {
    let _ipe_recursion_guard = crate::recursion_guard();
    crate::user_ipe_db_store_read_only(
        crate::user_ipe_db_store_exists_in_named(
            securedShare,
            "doc_ref".to_string(),
            "author".to_string(),
        ),
    )
}

pub(crate) fn main_secured_shared_docs() -> IpeResult<
    ipe_runtime::error::IpeError, IpeDbStoreSecured<RecAuthorBody>,
> {
    let _ipe_recursion_guard = crate::recursion_guard();
    match (crate::user_ipe_db_store_from_codec("docs".to_string(), crate::main_doc_codec()), crate::main_secured_shares())
    {
        (IpeResult::Ok(store), IpeResult::Ok(securedShare)) => {
            crate::user_ipe_db_store_secured(crate::main_shared_docs_policy(securedShare), store)
        }
        (IpeResult::Err(e), _) => IpeResult::Err(e),
        (_, IpeResult::Err(e)) => IpeResult::Err(e),
    }
}

pub(crate) fn main_handle_shared_docs(
    req: ServerRequest,
    principal: ipe_runtime::principal::Principal,
) -> IpeTask<ServerResponse> {
    let _ipe_recursion_guard = crate::recursion_guard();
    task_on_error(
        {
            let __ipe_fn: Box<
                dyn Fn(ipe_runtime::error::IpeError) -> IpeTask<ServerResponse>
                    + Send
                    + Sync
                    + 'static,
            > = Box::new(move |arg_18: ipe_runtime::error::IpeError| -> IpeTask<ServerResponse> {
                task_succeed(server_text("none".to_string()))
            });
            __ipe_fn
        },
        task_and_then(
            db_connect(()),
            Box::new(move |db: Db| -> IpeTask<ServerResponse> {
                match crate::main_secured_shared_docs() {
                    IpeResult::Err(_) => task_succeed(server_text("policy-error".to_string())),
                    IpeResult::Ok(secured) => task_and_then(
                        crate::user_ipe_db_store_all_as(principal.clone(), db, secured),
                        Box::new(move |docs: Vec<RecAuthorBody>| -> IpeTask<ServerResponse> {
                            task_succeed(server_text(string_join(
                                "\n".to_string(),
                                list_map_consume(
                                    {
                                        let __ipe_fn: Box<
                                            dyn Fn(RecAuthorBody) -> String + Send + Sync + 'static,
                                        > = Box::new(
                                            move |ipe_accessor_arg: RecAuthorBody| -> String {
                                                (ipe_accessor_arg).body.clone()
                                            },
                                        );
                                        __ipe_fn
                                    },
                                    docs,
                                ),
                            )))
                        }),
                    ),
                }
            }),
        ),
    )
}

pub(crate) fn main_handle_my_docs(
    req: ServerRequest,
    principal: ipe_runtime::principal::Principal,
) -> IpeTask<ServerResponse> {
    let _ipe_recursion_guard = crate::recursion_guard();
    task_on_error(
        {
            let __ipe_fn: Box<
                dyn Fn(ipe_runtime::error::IpeError) -> IpeTask<ServerResponse>
                    + Send
                    + Sync
                    + 'static,
            > = Box::new(move |arg_19: ipe_runtime::error::IpeError| -> IpeTask<ServerResponse> {
                task_succeed(server_text("none".to_string()))
            });
            __ipe_fn
        },
        task_and_then(
            db_connect(()),
            Box::new(move |db: Db| -> IpeTask<ServerResponse> {
                match crate::main_secured_docs() {
                    IpeResult::Err(_) => task_succeed(server_text("policy-error".to_string())),
                    IpeResult::Ok(secured) => task_and_then(
                        crate::user_ipe_db_store_all_as(principal.clone(), db, secured),
                        Box::new(move |docs: Vec<RecAuthorBody>| -> IpeTask<ServerResponse> {
                            task_succeed(server_text(string_join(
                                "\n".to_string(),
                                list_map_consume(
                                    {
                                        let __ipe_fn: Box<
                                            dyn Fn(RecAuthorBody) -> String + Send + Sync + 'static,
                                        > = Box::new(
                                            move |ipe_accessor_arg: RecAuthorBody| -> String {
                                                (ipe_accessor_arg).body.clone()
                                            },
                                        );
                                        __ipe_fn
                                    },
                                    docs,
                                ),
                            )))
                        }),
                    ),
                }
            }),
        ),
    )
}

pub(crate) fn main_mask_codec() -> IpeCodecCodec<RecOwnerSsn> {
    let _ipe_recursion_guard = crate::recursion_guard();
    IpeCodecCodec::Codec(RecEncMkDecShp {
        enc: {
            let __ipe_fn: ::std::sync::Arc<
                dyn Fn(RecOwnerSsn) -> JsonVal + Send + Sync + 'static,
            > = ::std::sync::Arc::new(move |d: RecOwnerSsn| -> JsonVal {
                json_enc_object(vec![
                    (
                        "owner".to_string(),
                        json_enc_string((d.clone()).owner.clone()),
                    ),
                    (
                        "ssn".to_string(),
                        crate::main_encode_maybe_string((d).ssn.clone()),
                    ),
                ])
            });
            __ipe_fn
        },
        mkDec: {
            let __ipe_fn: ::std::sync::Arc<
                dyn Fn(Rec_) -> Decoder<RecOwnerSsn> + Send + Sync + 'static,
            > = ::std::sync::Arc::new(move |arg_20: Rec_| -> Decoder<RecOwnerSsn> {
                decode_map2(
                    {
                        let __ipe_fn: Box<
                            dyn Fn(String, IpeMaybe<String>) -> RecOwnerSsn + Send + Sync + 'static,
                        > = Box::new(move |o: String, s: IpeMaybe<String>| -> RecOwnerSsn {
                            RecOwnerSsn { owner: o, ssn: s }
                        });
                        __ipe_fn
                    },
                    decode_field("owner".to_string(), json_decode_string::<IpeError>()),
                    decode_field(
                        "ssn".to_string(),
                        decode_nullable(json_decode_string::<IpeError>()),
                    ),
                )
            });
            __ipe_fn
        },
        shp: IpeCodecShape::SRecord(vec![("owner".to_string(), IpeCodecColType::CText), (
            "ssn".to_string(),
            IpeCodecColType::CNull(Box::new(IpeCodecColType::CText)),
        )]),
    })
}

pub(crate) fn main_encode_maybe_string(m: IpeMaybe<String>) -> JsonVal {
    let _ipe_recursion_guard = crate::recursion_guard();
    match m {
        IpeMaybe::Just(s) => json_enc_string(s),
        IpeMaybe::Nothing => json_enc_null(),
    }
}

pub(crate) fn main_mask_policy() -> IpeDbStorePolicy {
    let _ipe_recursion_guard = crate::recursion_guard();
    ({
        let cap_0 = crate::user_ipe_db_store_mask_named(
            "ssn".to_string(),
            crate::user_ipe_db_store_match_where(
                IpeDbStoreCond::Compare(
                    IpeDbStoreCompareOp::OpEq,
                    "owner".to_string(),
                    MainSqlValue::SqlString("admin".to_string()),
                ),
            ),
            crate::user_ipe_db_store_read_only(crate::user_ipe_db_store_always()),
        );
        {
            let __ipe_fn: Box<
                dyn Fn(IpeDbStorePolicy) -> IpeDbStorePolicy + Send + Sync + 'static,
            > = Box::new(move |eta_0: IpeDbStorePolicy| -> IpeDbStorePolicy {
                crate::user_ipe_db_store_and_policy(cap_0.clone(), eta_0)
            });
            __ipe_fn
        }
    })(crate::user_ipe_db_store_owner_column_named("owner".to_string()))
}

pub(crate) fn main_secured_mask_docs() -> IpeResult<
    ipe_runtime::error::IpeError, IpeDbStoreSecured<RecOwnerSsn>,
> {
    let _ipe_recursion_guard = crate::recursion_guard();
    match crate::user_ipe_db_store_from_codec("mask_docs".to_string(), crate::main_mask_codec()) {
        IpeResult::Err(e) => IpeResult::Err(e),
        IpeResult::Ok(store) => crate::user_ipe_db_store_secured(crate::main_mask_policy(), store),
    }
}

pub(crate) fn main_handle_mask_docs(
    req: ServerRequest,
    principal: ipe_runtime::principal::Principal,
) -> IpeTask<ServerResponse> {
    let _ipe_recursion_guard = crate::recursion_guard();
    task_on_error(
        {
            let __ipe_fn: Box<
                dyn Fn(ipe_runtime::error::IpeError) -> IpeTask<ServerResponse>
                    + Send
                    + Sync
                    + 'static,
            > = Box::new(move |arg_21: ipe_runtime::error::IpeError| -> IpeTask<ServerResponse> {
                task_succeed(server_text("none".to_string()))
            });
            __ipe_fn
        },
        task_and_then(
            db_connect(()),
            Box::new(move |db: Db| -> IpeTask<ServerResponse> {
                match crate::main_secured_mask_docs() {
                    IpeResult::Err(_) => task_succeed(server_text("policy-error".to_string())),
                    IpeResult::Ok(secured) => task_and_then(
                        crate::user_ipe_db_store_all_as(principal.clone(), db, secured),
                        Box::new(move |docs: Vec<RecOwnerSsn>| -> IpeTask<ServerResponse> {
                            task_succeed(server_text(string_join(
                                "\n".to_string(),
                                list_map_consume(
                                    {
                                        let __ipe_fn: Box<
                                            dyn Fn(RecOwnerSsn) -> String + Send + Sync + 'static,
                                        > = Box::new(move |d: RecOwnerSsn| -> String {
                                            maybe_with_default("•".to_string(), (d).ssn.clone())
                                        });
                                        __ipe_fn
                                    },
                                    docs,
                                ),
                            )))
                        }),
                    ),
                }
            }),
        ),
    )
}

pub(crate) fn main_auth_cfg() -> ipe_runtime::server::AuthConfig {
    let _ipe_recursion_guard = crate::recursion_guard();
    server_auth_config(
        secret_from_string(system_getenv_or(
            "SIGNING_KEY".to_string(),
            "this-is-a-32-byte-or-longer-secret-key-value".to_string(),
        )),
        server_token_bearer(),
    )
}

pub(crate) fn ipe_main() -> IpeTask<()> {
    let _ipe_recursion_guard = crate::recursion_guard();
    task_on_error(
        {
            let __ipe_fn: Box<
                dyn Fn(ipe_runtime::error::IpeError) -> IpeTask<()> + Send + Sync + 'static,
            > = Box::new(move |arg_22: ipe_runtime::error::IpeError| -> IpeTask<()> {
                io_println("authed-store-query-seal".to_string())
            });
            __ipe_fn
        },
        task_and_then(
            server_listen(8000i64, vec![
                server_get_authed("/my/docs".to_string(), crate::main_auth_cfg(), {
                    let __ipe_fn: Box<
                        dyn Fn(ServerRequest, ipe_runtime::principal::Principal) -> IpeTask<ServerResponse>
                            + Send
                            + Sync
                            + 'static,
                    > = Box::new(crate::main_handle_my_docs);
                    __ipe_fn
                }),
                server_get_authed("/shared/docs".to_string(), crate::main_auth_cfg(), {
                    let __ipe_fn: Box<
                        dyn Fn(ServerRequest, ipe_runtime::principal::Principal) -> IpeTask<ServerResponse>
                            + Send
                            + Sync
                            + 'static,
                    > = Box::new(crate::main_handle_shared_docs);
                    __ipe_fn
                }),
                server_get_authed("/mask/docs".to_string(), crate::main_auth_cfg(), {
                    let __ipe_fn: Box<
                        dyn Fn(ServerRequest, ipe_runtime::principal::Principal) -> IpeTask<ServerResponse>
                            + Send
                            + Sync
                            + 'static,
                    > = Box::new(crate::main_handle_mask_docs);
                    __ipe_fn
                }),
            ]),
            Box::new(move |arg_23: ()| -> IpeTask<()> {
                io_println("authed-store-query-seal".to_string())
            }),
        ),
    )
}
