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
            BuiltinTag::DbLocation => self.db_location,
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
            BuiltinTag::Remote => self.remote_con,
            BuiltinTag::RemoteAuth => self.remote_auth_con,
        }
    }

    /// Resolve a structural [`FieldTag`] to the interned field-name [`Symbol`]
    /// the interpreter uses as the `Ty::Record` `BTreeMap` key for that field.
    #[must_use]
    pub const fn field_symbol(&self, tag: FieldTag) -> Symbol {
        self.fields.get(tag)
    }

    /// The module path an interpreted [`TyShape::Con`] carries for a given
    /// [`BuiltinTag`] in the `Ty::Con { module, .. }`.
    ///
    /// Read from [`BuiltinTag::scheme_home`], the one owner of the scheme-side
    /// home: an empty-home tag is unqualified, a module-homed tag carries its
    /// module's interned segments so a point-free reference to the scheme lowers
    /// to the emitted enum.
    #[must_use]
    pub fn builtin_con_module(&self, tag: BuiltinTag) -> &[Symbol] {
        match tag.scheme_home() {
            ipe_kernels::KernelHome::Builtin => &[],
            ipe_kernels::KernelHome::Module(path) => {
                self.scheme_homes.get(path).map_or(&[], Vec::as_slice)
            }
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
