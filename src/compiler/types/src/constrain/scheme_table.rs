use super::{
    BTreeMap, Builder, BuiltinTag, Builtins, FieldTag, RowTail, RowTailShape, SchemeKey,
    SchemeSlot, Symbol, Ty, TyShape,
};
use crate::pairing::ConHead;

impl Builder<'_> {
    /// Resolve a [`SchemeKey`] carried on a [`ipe_kernels::KernelDef`] to its
    /// concrete HM type scheme.
    ///
    /// A [`SchemeKey`] names a kernel's scheme without carrying it (the scheme is
    /// built from interned `Symbol`s that exist only after the `Interner` runs,
    /// so it cannot be a `'static` value on the descriptor). This is the single
    /// interpreter that turns the key back into a `Ty`: it reads the kernel's
    /// structural [`ipe_kernels::TyShape`] — the one scheme source — and
    /// interprets it via [`Self::interpret_shape`]. `None` means the kernel has no
    /// scheme (a routed / unlowered bucket), so the caller fails closed.
    pub fn resolve_scheme(&self, key: SchemeKey) -> Option<Ty> {
        // Memoised per kernel: a kernel's scheme depends only on the interned
        // built-in names, fixed for the builder's lifetime, so it is built at
        // most once and cloned thereafter. A cached value is byte-identical to a
        // rebuild by construction (same pure inputs); `instantiate_in` still
        // alpha-renames per use site, so instantiation is unaffected.
        let idx = key.0 as usize;
        if let Some(SchemeSlot::Resolved(cached)) = self.scheme_cache.borrow().get(idx) {
            return cached.clone();
        }
        // Every schemed kernel carries a structural `TyShape`, resolved by
        // interpreting it — the single scheme source. A kernel WITHOUT a shape
        // (`shape == None`) is genuinely unschemed (a routed / unlowered
        // bucket), so it resolves to `None` and the caller fails closed.
        let resolved = key.0.def().shape.map(|shape| self.interpret_shape(shape));
        if let Some(slot) = self.scheme_cache.borrow_mut().get_mut(idx) {
            *slot = SchemeSlot::Resolved(resolved.clone());
        }
        resolved
    }

    /// Interpret a `'static` [`TyShape`] into a concrete [`Ty`], resolving each
    /// [`BuiltinTag`] against the interned-symbol cache.
    ///
    /// The single interpreter a structural kernel scheme routes through — the one
    /// source that turns a kernel's `TyShape` into its concrete HM scheme `Ty`.
    ///
    /// It touches no union-find state even for the polymorphic [`TyShape::Var`]
    /// node: a scheme var interprets to a placeholder `Ty::Var` at its bare
    /// positional index (annotation-symbol space), NOT a fresh union-find var.
    /// Generalization / instantiation with fresh solver vars happens later at the
    /// use site (`instantiate_in`), so this interpreter still takes `&self`.
    /// Because `Ty::Var` is `Eq`, repeating an index reuses one variable
    /// structurally without any shared-cell handling.
    pub fn interpret_shape(&self, shape: &TyShape) -> Ty {
        match shape {
            TyShape::Fun(arg, res) => Ty::Fun(
                Box::new(self.interpret_shape(arg)),
                Box::new(self.interpret_shape(res)),
            ),
            TyShape::Con(tag, args) => Ty::Con {
                module: self.builtins.builtin_con_module(*tag).to_vec(),
                name: self.builtins.builtin_symbol(*tag),
                args: args.iter().map(|a| self.interpret_shape(a)).collect(),
            },
            // Element order is significant and preserved.
            TyShape::Tuple(elems) => {
                Ty::Tuple(elems.iter().map(|e| self.interpret_shape(e)).collect())
            }
            // The `BTreeMap` re-sorts by the resolved field `Symbol`, so the
            // materialised `Ty::Record`'s key order is independent of the declared
            // slice order.
            TyShape::Record { fields, tail } => {
                let mut map = BTreeMap::new();
                for (name, field) in *fields {
                    map.insert(
                        self.builtins.field_symbol(*name),
                        self.interpret_shape(field),
                    );
                }
                let tail = match tail {
                    RowTailShape::Closed => RowTail::Closed,
                    RowTailShape::Open(i) => RowTail::Open(u32::from(*i)),
                };
                Ty::Record(map, tail)
            }
            // A scheme-local variable's raw is its bare positional index.
            TyShape::Var(i) => Ty::Var(u32::from(*i)),
            // `()` materialises the bare `Ty::Unit` leaf.
            TyShape::Unit => Ty::Unit,
        }
    }
}

impl Builtins {
    /// Resolve a structural [`BuiltinTag`] to the interned type-constructor
    /// [`Symbol`] the interpreter puts in the `Ty::Con` for that built-in.
    #[allow(clippy::too_many_lines)] // one arm per BuiltinTag variant, deliberately exhaustive
    #[must_use]
    pub const fn builtin_symbol(&self, tag: BuiltinTag) -> Symbol {
        match tag {
            BuiltinTag::Int => self.int,
            BuiltinTag::Float => self.float,
            BuiltinTag::Bool => self.bool,
            BuiltinTag::String => self.string,
            BuiltinTag::Char => self.char,
            BuiltinTag::Bytes => self.bytes,
            BuiltinTag::List => self.list,
            BuiltinTag::Maybe => self.maybe,
            BuiltinTag::Result => self.result,
            BuiltinTag::Set => self.set,
            BuiltinTag::Dict => self.dict,
            BuiltinTag::Order => self.order,
            BuiltinTag::Error => self.error,
            BuiltinTag::ErrorKind => self.errorkind,
            BuiltinTag::ErrorDetails => self.errordetails,
            BuiltinTag::Decimal => self.decimal,
            BuiltinTag::Task => self.task,
            BuiltinTag::Cmd => self.cmd,
            BuiltinTag::Sub => self.sub,
            BuiltinTag::Topic => self.topic_con,
            BuiltinTag::Decoder => self.decoder,
            BuiltinTag::Db => self.db,
            BuiltinTag::SqlValue => self.sqlvalue,
            BuiltinTag::SqlField => self.sqlfield,
            BuiltinTag::SqlFragment => self.sqlfragment,
            BuiltinTag::ProjectionTerm => self.projection_term,
            BuiltinTag::ProjectionOperand => self.projection_operand,
            BuiltinTag::Secret => self.secret,
            BuiltinTag::Path => self.path,
            BuiltinTag::Regex => self.regex,
            BuiltinTag::Url => self.url,
            BuiltinTag::UrlRelative => self.url_relative,
            BuiltinTag::Dsn => self.dsn,
            BuiltinTag::Connection => self.connection,
            BuiltinTag::ConnReadOnly => self.conn_read_only,
            BuiltinTag::ConnReadWrite => self.conn_read_write,
            BuiltinTag::Setting => self.setting,
            BuiltinTag::ShapeWeb => self.shape_web,
            BuiltinTag::ShapeWebView => self.shape_webview,
            BuiltinTag::ShapeTerminal => self.shape_terminal,
            BuiltinTag::Program => self.program,
            BuiltinTag::ProgramShapeWeb => self.program_shape_web,
            BuiltinTag::ProgramShapeTui => self.program_shape_tui,
            BuiltinTag::ProgramShapeCli => self.program_shape_cli,
            BuiltinTag::ProgramShapeWorker => self.program_shape_worker,
            BuiltinTag::HostMode => self.host_mode,
            BuiltinTag::LogLevel => self.log_level,
            BuiltinTag::CsrfMode => self.csrf_mode,
            BuiltinTag::RevocationMode => self.revocation_mode,
            BuiltinTag::Locale => self.locale,
            BuiltinTag::HttpMethod => self.http_method,
            BuiltinTag::RedirectPolicy => self.redirect_policy,
            BuiltinTag::DbFailure => self.db_failure,
            BuiltinTag::AuthError => self.auth_error,
            BuiltinTag::Duration => self.duration,
            BuiltinTag::CryptoKey => self.crypto_key,
            BuiltinTag::CryptoMac => self.crypto_mac,
            BuiltinTag::EmailAddress => self.email_address,
            BuiltinTag::Principal => self.principal,
            BuiltinTag::Claims => self.jwt_claims,
            BuiltinTag::Algorithm => self.jwt_algorithm,
            BuiltinTag::JsonValue => self.json_value,
            BuiltinTag::StreamId => self.stream_id,
            BuiltinTag::StreamWriter => self.stream_writer,
            BuiltinTag::WsServer => self.ws_server,
            BuiltinTag::WsServerCfg => self.ws_server_cfg,
            BuiltinTag::ServerRequest => self.server_request,
            BuiltinTag::ServerCookie => self.server_cookie,
            BuiltinTag::ServerRoute => self.server_route,
            BuiltinTag::AuthConfig => self.auth_config,
            BuiltinTag::TokenSource => self.token_source,
            // `Ipe.Ui.Attribute` and `Ipe.Html.Attribute` share this interned
            // `Attribute` name; they differ only in the module path
            // (`builtin_con_module`).
            BuiltinTag::UiAttribute | BuiltinTag::HtmlAttribute => self.attribute,
            BuiltinTag::View => self.view,
            BuiltinTag::UiElement => self.element,
            BuiltinTag::Cells => self.cells,
            BuiltinTag::TuiAttr => self.tui_attr,
            BuiltinTag::CliLines => self.cli_lines,
            BuiltinTag::CliAttr => self.cli_attr,
            // The unified `Color` and the legacy `Ui.Color` share the interned
            // `"Color"` name; they collapse into one carrier as the migration removes
            // `UiColor`.
            BuiltinTag::Color | BuiltinTag::UiColor => self.color,
            BuiltinTag::ColorError => self.color_error,
            BuiltinTag::TermProfile => self.term_profile,
            BuiltinTag::AnsiColor => self.ansi_color,
            BuiltinTag::WcagLevel => self.wcag_level,
            BuiltinTag::TextSize => self.text_size,
            BuiltinTag::Deficiency => self.deficiency,
            BuiltinTag::CustomElement => self.custom_element,
            BuiltinTag::Html => self.html_con,
            BuiltinTag::UiLength => self.length,
            BuiltinTag::UiDescription => self.description,
            BuiltinTag::UiPseudoClass => self.pseudo_class,
            BuiltinTag::InputLabel => self.input_label_con,
            BuiltinTag::InputPlaceholder => self.input_placeholder_con,
            BuiltinTag::InputRadioOption => self.input_radio_option_con,
            BuiltinTag::WebReq => self.web_req,
            BuiltinTag::SessionHandle => self.session_handle,
            BuiltinTag::WebRoute => self.live_route_con,
            BuiltinTag::EmailProvider => self.email_provider,
            BuiltinTag::BackoffStrategy => self.backoffstrategy,
            BuiltinTag::TaskStep => self.task_step,
            BuiltinTag::WebApp => self.web_app,
            BuiltinTag::TuiApp => self.tui_app,
            BuiltinTag::CliApp => self.cli_app,
            BuiltinTag::DbStore => self.store_con,
            BuiltinTag::DbDraft => self.draft_con,
            BuiltinTag::DbJoined => self.joined_con,
            BuiltinTag::DbSelect => self.select_con,
            BuiltinTag::DbPolicy => self.policy_con,
            BuiltinTag::DbCond => self.cond_con,
            BuiltinTag::DbPred => self.pred_con,
            BuiltinTag::DbSecured => self.secured_con,
            BuiltinTag::DbOrder => self.order_con,
            BuiltinTag::Codec => self.codec_con,
        }
    }

    /// Resolve a structural [`FieldTag`] to the interned field-name [`Symbol`]
    /// the interpreter uses as the `Ty::Record` `BTreeMap` key for that field.
    #[must_use]
    pub const fn field_symbol(&self, tag: FieldTag) -> Symbol {
        match tag {
            FieldTag::MigrationName => self.migration_f_name,
            FieldTag::MigrationSql => self.migration_f_sql,
            FieldTag::HttpBody => self.http_f_body,
            FieldTag::HttpHeaders => self.http_f_headers,
            FieldTag::HttpStatus => self.http_f_status,
            FieldTag::HttpMethod => self.http_f_method,
            FieldTag::HttpUrl => self.http_f_url,
            FieldTag::HttpTimeout => self.http_f_timeout,
            FieldTag::HttpRedirects => self.http_f_redirects,
            FieldTag::ServerContentType => self.server_f_content_type,
            FieldTag::CsvHeader => self.csv_f_header,
            FieldTag::CsvRows => self.csv_f_rows,
            FieldTag::CacheMaxEntries => self.cache_f_max_entries,
            FieldTag::CacheTtlMs => self.cache_f_ttl_ms,
            FieldTag::CacheMaxBytes => self.cache_f_max_bytes,
            FieldTag::CacheHits => self.cache_f_hits,
            FieldTag::CacheMisses => self.cache_f_misses,
            FieldTag::CacheEvictions => self.cache_f_evictions,
            FieldTag::WsUrl => self.ws_f_url,
            FieldTag::WsHeaders => self.ws_f_headers,
            FieldTag::WsTimeout => self.ws_f_timeout,
            FieldTag::WsPingInterval => self.ws_f_ping_interval,
            FieldTag::EmailFrom => self.email_f_from,
            FieldTag::EmailTo => self.email_f_to,
            FieldTag::EmailCc => self.email_f_cc,
            FieldTag::EmailBcc => self.email_f_bcc,
            FieldTag::EmailSubject => self.email_f_subject,
            FieldTag::EmailTextBody => self.email_f_text_body,
            FieldTag::EmailHtmlBody => self.email_f_html_body,
            FieldTag::EmailAttachments => self.email_f_attachments,
            FieldTag::EmailReplyTo => self.email_f_reply_to,
            FieldTag::EmailFilename => self.email_f_filename,
            FieldTag::EmailMimeType => self.email_f_mime_type,
            FieldTag::EmailContent => self.email_f_content,
            FieldTag::RetryBaseMs => self.retry_f_base_ms,
            FieldTag::RetryMaxAttempts => self.retry_f_max_attempts,
            FieldTag::RetryShouldRetry => self.retry_f_should_retry,
            FieldTag::RetryStrategy => self.retry_f_strategy,
            FieldTag::LayoutWrapperAttrs => self.lw_wrapper_attrs,
            FieldTag::LayoutRootAttrs => self.lw_root_attrs,
            FieldTag::ButtonOnPress => self.btn_f_on_press,
            FieldTag::Label => self.btn_f_label,
            FieldTag::AppInit => self.live_f_init,
            FieldTag::AppUpdate => self.live_f_update,
            FieldTag::AppView => self.live_f_view,
            FieldTag::AppSubscriptions => self.live_f_subscriptions,
            FieldTag::AppRoutes => self.live_f_routes,
            FieldTag::AppNotFound => self.live_f_not_found,
            FieldTag::TerminalKeyKind => self.tui_f_key_kind,
            FieldTag::TerminalKeyValue => self.tui_f_key_value,
            FieldTag::EdgeTop => self.edge_f_top,
            FieldTag::EdgeRight => self.edge_f_right,
            FieldTag::EdgeBottom => self.edge_f_bottom,
            FieldTag::EdgeLeft => self.edge_f_left,
            FieldTag::InputOnChange => self.input_f_on_change,
            FieldTag::InputText => self.input_f_text,
            FieldTag::InputPlaceholder => self.input_f_placeholder,
            FieldTag::InputIcon => self.input_f_icon,
            FieldTag::InputChecked => self.input_f_checked,
            FieldTag::InputSpellcheck => self.input_f_spellcheck,
            FieldTag::InputValue => self.input_f_value,
            FieldTag::InputMin => self.input_f_min,
            FieldTag::InputMax => self.input_f_max,
            FieldTag::InputStep => self.input_f_step,
            FieldTag::InputOptions => self.input_f_options,
            FieldTag::InputSelected => self.input_f_selected,
            FieldTag::ShadowOffsetX => self.shadow_f_offset_x,
            FieldTag::ShadowOffsetY => self.shadow_f_offset_y,
            FieldTag::ShadowBlur => self.shadow_f_blur,
            FieldTag::ShadowSpread => self.shadow_f_spread,
            FieldTag::ShadowColor => self.shadow_f_color,
            FieldTag::ImageSrc => self.img_f_src,
            FieldTag::ImageDescription => self.img_f_description,
            FieldTag::ProcessCommand => self.process_f_command,
            FieldTag::ProcessArgs => self.process_f_args,
            FieldTag::ProcessCwd => self.process_f_cwd,
            FieldTag::ProcessEnv => self.process_f_env,
            FieldTag::ProcessExitCode => self.process_f_exit_code,
            FieldTag::ProcessStdout => self.process_f_stdout,
            FieldTag::ProcessStderr => self.process_f_stderr,
            FieldTag::ProcessCols => self.process_f_cols,
            FieldTag::ProcessRows => self.process_f_rows,
            FieldTag::ProcessOutput => self.process_f_output,
        }
    }

    /// The module path an interpreted [`TyShape::Con`] carries for a given
    /// [`BuiltinTag`] in the `Ty::Con { module, .. }`.
    ///
    /// Most tags are empty-module (unqualified). The homed exceptions carry a
    /// real module home so a point-free reference to the scheme lowers to the
    /// emitted enum instead of missing the lowerer's home-keyed variant lookup:
    /// [`BuiltinTag::HtmlAttribute`] (the `Html` constructor symbol, so
    /// `ir_type_from_ty`'s disambiguation selects the `Html` attribute variant
    /// distinct from the unqualified [`BuiltinTag::UiAttribute`]),
    /// [`BuiltinTag::EmailProvider`], [`BuiltinTag::Duration`],
    /// [`BuiltinTag::TaskStep`], the
    /// `Ipe.Db.Store` query-algebra ADTs, and [`BuiltinTag::Codec`].
    #[must_use]
    pub fn builtin_con_module(&self, tag: BuiltinTag) -> &[Symbol] {
        match tag {
            BuiltinTag::HtmlAttribute => std::slice::from_ref(&self.html_con),
            // The `send` kernel takes `EmailProvider` as its first parameter.
            // Carrying the real `Ipe.Email` home lets a point-free reference to
            // the interpreted scheme lower to the emitted enum; without it the
            // unhomed `Con` misses the lowerer's home-keyed variant lookup and
            // drops into the unknown-builtin internal-compiler-error arm.
            BuiltinTag::EmailProvider => &self.email_home,
            // `Duration` is a compiled-source ADT (`Ipe.Duration.Duration`), not a
            // folded builtin — its `Http.withTimeout` scheme reference must carry
            // the real `["Ipe", "Duration"]` home so a point-free use lowers to the
            // emitted enum, exactly as `EmailProvider` does.
            BuiltinTag::Duration => &self.duration_home,
            // `Step` is a compiled-source ADT (`Ipe.Task.Step`) — the `Task.loop`
            // scheme carries the real `["Ipe", "Task"]` home so its `Step` is the
            // type `Ipe.Task` declares and a point-free use lowers to the emitted
            // enum, exactly as `Duration` does.
            BuiltinTag::TaskStep => &self.task_home,
            // The `Ipe.Db.Store` query-algebra ADTs carry the store home so a
            // point-free reference lowers to the emitted enum, exactly as the
            // hand-built `store` / `draft` / … helpers did.
            BuiltinTag::DbStore
            | BuiltinTag::DbDraft
            | BuiltinTag::DbJoined
            | BuiltinTag::DbSelect
            | BuiltinTag::DbPolicy
            | BuiltinTag::DbCond
            | BuiltinTag::DbPred
            | BuiltinTag::DbSecured => &self.db_store_home,
            BuiltinTag::Codec => &self.codec_home,
            _ => &[],
        }
    }

    /// The constructor head `tag` names, applied to `args`.
    ///
    /// Carries the tag's home and symbol, so a walk pairing a kernel scheme
    /// shape against a solved type compares heads through
    /// [`crate::HeadIdentity::paired_args`], never by arity alone.
    #[must_use]
    pub fn builtin_con_head<'a, T>(&'a self, tag: BuiltinTag, args: &'a [T]) -> ConHead<'a, T> {
        ConHead {
            home: self.builtin_con_module(tag),
            name: self.builtin_symbol(tag),
            args,
        }
    }
}
