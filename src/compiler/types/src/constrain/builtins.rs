use super::{
    BTreeSet, BuiltinTag, CtorKey, CtorScheme, DResult, Diagnostic, Interner, Symbol, Ty, TyBounds,
};

/// Interned symbols of every built-in type, constructor, and field name.
pub struct Builtins {
    pub int: Symbol,
    pub float: Symbol,
    pub bool: Symbol,
    pub string: Symbol,
    pub char: Symbol,
    pub task: Symbol,
    pub maybe: Symbol,
    pub result: Symbol,
    pub list: Symbol,
    /// Interned `Just` / `Nothing` / `Ok` / `Err` / `True` / `False` — the
    /// Prelude-exposed built-in constructor names.
    pub just: Symbol,
    pub nothing: Symbol,
    pub ok: Symbol,
    pub err: Symbol,
    pub true_: Symbol,
    pub false_: Symbol,
    /// `Ipe.Dict` type constructor symbol.
    pub dict: Symbol,
    /// `Ipe.Set` type constructor symbol.
    pub set: Symbol,
    /// `Ipe.Bytes` type constructor symbol.
    /// Divergence from Ipê: Bytes is a distinct primitive in Ipê-Rust (Vec<u8>),
    /// not a String alias as in the the reference.
    pub bytes: Symbol,
    /// The interned `Error` symbol, used to validate the error channel in
    /// `Task Error a` annotations (normalised to unary `Task a`) and to pin the
    /// handler parameter type in `mapError` / `onError` so a bare lambda `\e ->
    /// ...` infers `e : Error` without leaving a free variable.
    pub error: Symbol,
    /// `ErrorKind` — the 11-variant classification carried by `Error`'s first
    /// field. Registered as a Prelude built-in exactly
    /// like `Order` — see `ipe_lower`'s `enum_variants`/`ctor_arity`
    /// (E-12), which already validate `Error kind info ->` patterns.
    pub errorkind: Symbol,
    /// The 11 `ErrorKind` nullary constructor symbols, in canon's registered
    /// index order (`crates/ipe_canon/src/env.rs`) — do not reorder.
    pub ek_io: Symbol,
    pub ek_network: Symbol,
    pub ek_ffi: Symbol,
    pub ek_decode: Symbol,
    pub ek_timeout: Symbol,
    pub ek_not_found: Symbol,
    pub ek_permission_denied: Symbol,
    pub ek_invalid_input: Symbol,
    pub ek_conflict: Symbol,
    pub ek_unavailable: Symbol,
    pub ek_unexpected: Symbol,
    /// `ErrorDetails` — the 5-variant enrichment union carried on
    /// `ErrorInfo.details`. Registered as a Prelude
    /// built-in exactly like `ErrorKind` — see `ipe_lower`'s
    /// `enum_variants`/`ctor_arity` seeding.
    pub errordetails: Symbol,
    /// `BackoffStrategy` — the 4-constructor retry-backoff strategy ADT
    /// (`Linear | LinearWithJitter | Exponential | ExponentialWithJitter`).
    /// Registered as a Prelude built-in; seeded by `ipe_lower`'s
    /// `enum_variants`/`ctor_arity` (via `BuiltinTag::BackoffStrategy`).
    pub backoffstrategy: Symbol,
    /// The 5 `ErrorDetails` constructor symbols, in canon's registered index
    /// order (`crates/ipe_canon/src/env.rs`) — do not reorder.
    pub ed_ffi_panic: Symbol,
    pub ed_type_mismatch: Symbol,
    pub ed_http_status: Symbol,
    pub ed_json_decode: Symbol,
    pub ed_custom: Symbol,
    /// `PanicInfo` / `TypeInfo` / `ErrorInfo` — NOMINAL type-constructor
    /// symbols (SEAL fix, see
    /// `docs/adr/0001-language-semantics-and-types.md`). The three payload
    /// record types are opaque nominal Cons (like the server `Request`), NOT
    /// structural records: a bare record literal must not unify with them —
    /// the runtime backs them with concrete structs (`IpePanicInfo` /
    /// `IpeTypeInfo` / `IpeErrorInfo`), so a structural lowering
    /// (project-local synthesized struct) would fail `cargo build` after a
    /// clean `ipe` exit. Field ACCESS on them stays available through
    /// `resolve_deferred`'s builtin-record field tables.
    pub panicinfo: Symbol,
    pub typeinfo: Symbol,
    pub errorinfo: Symbol,
    /// Two distinct scheme type-variable symbols (`a`, `e`) used to build the
    /// built-in constructor schemes. Their identity links a constructor's
    /// payload to its result type, exactly like a user union's declared vars;
    /// each use site instantiates them fresh through one shared map.
    pub tv_a: Symbol,
    pub tv_e: Symbol,
    // ── Http field-name symbols ──────────────────────────────────────────────
    // Pre-interned because `kernel_ty` takes `&self` (the interner is immutable
    // at that point); these symbols give `Ty::Record` the correct BTreeMap keys
    // for `HttpResponse` and `HttpRequest` so the emit prepass registers both
    // record shapes.
    /// `"body"` — shared by `HttpResponse` and `HttpRequest`.
    pub http_f_body: Symbol,
    /// `"headers"` — shared by `HttpResponse` (`Dict String String`) and
    /// `HttpRequest` (`List (String, String)`).
    pub http_f_headers: Symbol,
    /// `"status"` — `HttpResponse` only.
    pub http_f_status: Symbol,
    /// `"method"` — `HttpRequest` only.
    pub http_f_method: Symbol,
    /// `"HttpMethod"` — the `Ipe.Http.HttpMethod` ADT type constructor.
    pub http_method: Symbol,
    /// `"url"` — `HttpRequest` only.
    pub http_f_url: Symbol,
    /// `"timeout"` — `HttpRequest` only.
    pub http_f_timeout: Symbol,
    /// `"redirects"` — `HttpRequest` only.
    pub http_f_redirects: Symbol,
    /// `"RedirectPolicy"` — the `Ipe.Http.RedirectPolicy` ADT type constructor.
    pub redirect_policy: Symbol,
    /// `"Duration"` — the `Ipe.Duration.Duration` opaque ADT type constructor.
    /// Consumed by the `Http.withTimeout` kernel (its typed timeout argument);
    /// homed via [`Self::duration_home`] so a point-free reference lowers to the
    /// compiled-module enum, mirroring `EmailProvider` / [`Self::email_home`].
    pub duration: Symbol,
    /// `"NoRedirects"` — nullary `RedirectPolicy` constructor.
    pub no_redirects: Symbol,
    /// `"FollowRedirects"` — `Int -> RedirectPolicy` constructor.
    pub follow_redirects: Symbol,
    /// `"contentType"` — `Ipe.Http.Server.Response` record field (camelCase).
    pub server_f_content_type: Symbol,
    /// `"name"` — `Ipe.Db.Migration` record field.
    pub migration_f_name: Symbol,
    /// `"sql"` — `Ipe.Db.Migration` record field.
    pub migration_f_sql: Symbol,
    // ── Db type symbols ──────────────────────────────────────────────────────
    /// `"Db"` — the opaque database connection pool type constructor.
    pub db: Symbol,
    /// `"SqlValue"` — the sum type for typed SQL parameter values.
    pub sqlvalue: Symbol,
    /// `"SqlField"` — the sum type for PATCH-style field-set / field-omit SQL params.
    pub sqlfield: Symbol,
    /// `"SqlFragment"` — `Ipe.Db.Sql`'s opaque, parameterized WHERE-fragment
    /// type.
    pub sqlfragment: Symbol,
    /// `"Secret"` — `Ipe.Secret`'s opaque, sealed secret-string wrapper
    /// type.
    pub secret: Symbol,
    /// `"Path"` — `Ipe.Path`'s opaque, validated filesystem-path type.
    pub path: Symbol,
    /// `"Regex"` — `Ipe.Regex`'s opaque compiled-pattern handle. Built ONLY by
    /// `Regex.compile : String -> Result Error Regex`. Zero type arguments.
    /// Lowered to `IrType::Regex`.
    pub regex: Symbol,
    // ── SqlValue constructor name symbols ─────────────────────────────────────
    pub sql_string: Symbol,
    pub sql_int: Symbol,
    pub sql_float: Symbol,
    pub sql_bool: Symbol,
    pub sql_bytes: Symbol,
    pub sql_time: Symbol,
    /// `"SqlDecimal"` — carries a native `Decimal`, bound as lossless TEXT.
    pub sql_decimal: Symbol,
    /// `"SqlMoney"` — wraps a `String` in `"ISO_CODE AMOUNT"` format (TEXT).
    pub sql_money: Symbol,
    pub sql_null: Symbol,
    // ── SqlField constructor name symbols ─────────────────────────────────────
    pub set_field: Symbol,
    pub omit_field: Symbol,
    // ── Shared row-decoder type (JSON) ────────────────────────────────────────
    /// `"Decoder"` — the opaque decoder type constructor shared by `Ipe.Json.Decode`
    /// and `Ipe.Db.Decode`. Represented in the IR as `IrType::Decoder(Box<IrType>)`.
    pub decoder: Symbol,
    // ── TEA Cmd / Sub type constructor symbols ────────────────────────────────
    /// `"Cmd"` — the opaque command type constructor `Cmd msg`.
    /// Represented in the IR as `IrType::Cmd(Box<IrType>)`.
    pub cmd: Symbol,
    /// `"Sub"` — the opaque subscription type constructor `Sub msg`.
    /// Represented in the IR as `IrType::Sub(Box<IrType>)`.
    pub sub: Symbol,
    // ── Ipe.Http.Server opaque type constructor symbols ───────────────────────
    /// `"Request"` — the opaque server request type.
    pub server_request: Symbol,
    /// `"Response"` — the opaque server response type.
    pub server_response: Symbol,
    /// `"Route"` — the opaque server route type.
    pub server_route: Symbol,
    /// `"Cookie"` — the opaque server cookie type.
    pub server_cookie: Symbol,
    /// `"AuthConfig"` — the opaque authed-route configuration type
    /// (`ipe_runtime::server::AuthConfig`). Built only through `Server.authConfig`;
    /// the sole value the authed-route kernels accept. Lowered to
    /// `IrType::AuthConfig`.
    pub auth_config: Symbol,
    /// `"TokenSource"` — the opaque descriptor of where the authed middleware
    /// reads the session token (`ipe_runtime::server::TokenSource`). Built only
    /// through the `Server` token-source kernels. Lowered to
    /// `IrType::TokenSource`.
    pub token_source: Symbol,
    /// `"Handler"` — the `Request -> Task Error Response` alias from
    /// `Ipe.Http.Server`. Pre-interned so `constrain_def` can detect a
    /// `handler : Handler` annotation and expand it to the full arrow type
    /// before the parameter-loop runs (fixes IPE-T0004 for handler bindings).
    pub handler: Symbol,
    // ── Ipe.Http.Server.Stream opaque type constructor symbol ───────────
    /// `"StreamWriter"` — the opaque stream writer handle passed to the
    /// `Stream.stream` callback and consumed by `Stream.emit` /
    /// `Stream.finish` / `Stream.withContentType`.
    pub stream_writer: Symbol,
    // ── Ipe.Http.Server.WebSocket opaque type constructor symbols ────────
    /// `"WebSocketServer"` — the opaque per-peer WebSocket handle (`WsHandle`).
    pub ws_server: Symbol,
    /// `"WebSocketServerCfg"` — the opaque WebSocket server configuration
    /// (`WsServerCfg<IpeError>`).
    pub ws_server_cfg: Symbol,
    // ── Ipe.Ui / Ipe.Html parametric type constructor symbols ─────────────────
    /// `"Attribute"` — Ipe.Ui attribute type constructor `Attribute msg`.
    ///
    /// Used to build Ui kernel type schemes so the HM solver constrains
    /// `List (Attribute msg)` arguments (e.g. `layout [] child`) to a concrete
    /// element type rather than leaving them as free variables.  Without these
    /// entries the empty-attrs list `[]` keeps `List (Ty::Var)` as its region
    /// type, `list_elem_ir` returns `IrType::Json`, and `emit_list` emits the
    /// bare `Vec::new()` that Rust rejects with E0283 when M cannot be inferred
    /// from elsewhere in the expression.
    pub attribute: Symbol,
    /// `"View"` — the engine-tagged view carrier `View engine msg`. The SSOT
    /// surface every engine's view collapses into: `View Web msg` IS `Element
    /// msg`, `View Tui msg` IS `Screen msg`, `View Cli msg` IS `Lines msg`.
    pub view: Symbol,
    /// `"Element"` — Ipe.Ui element type constructor `Element msg`. Retained as
    /// the canon alias `View Web msg`.
    pub element: Symbol,
    /// `"Screen"` — Tui-only view type constructor `Screen msg`. Distinct from
    /// `Element msg`; produced by `Ipe.Ui.Tui.*` builders.
    pub cells: Symbol,
    /// `"TuiAttr"` — the cell-native attribute type constructor
    /// `Ipe.Ui.Tui.Attribute msg`. Distinct from the DOM `Attribute msg`
    /// (`attribute`): only terminal-honorable attributes (spacing/padding/
    /// align/bold/underline/color/bg) inhabit it, so a DOM attribute
    /// (`Ui.onClick`, `Ui.scrollbars`, …) is unnameable in a `Screen` view —
    /// a type error, never a silent render-time drop.
    pub tui_attr: Symbol,
    /// `"Lines"` — the Cli-only line-oriented view type constructor `Lines msg`.
    /// Distinct from both `Element msg` and `Screen msg`; produced by
    /// `Ipe.Ui.Cli.*` builders. Line-scoped, so 2D cell and DOM builders are
    /// unnameable in it.
    pub cli_lines: Symbol,
    /// `"CliAttr"` — the line-native attribute type constructor
    /// `Ipe.Ui.Cli.Attribute msg`. Only line-scoped styles
    /// (bold/underline/dim/reverse/color/bg) inhabit it, so a 2D cell attribute
    /// or a DOM attribute is unnameable in a `Lines` view.
    pub cli_attr: Symbol,
    /// `"ColorError"` — the typed parse-error channel of the string-input colour
    /// constructors (`fromHex` / `fromName`). Backs `ipe_runtime::color::ColorError`.
    pub color_error: Symbol,
    /// `"TermProfile"` — the terminal capability profile `Color.toAnsi` targets.
    /// Backs `ipe_runtime::color::TermProfile`.
    pub term_profile: Symbol,
    /// `"AnsiColor"` — the terminal colour type: the palette `Ipe.Color`
    /// constructors (`black`…`brightWhite`, `default`, `rgb`) build it, and
    /// `Color.toAnsi` down-samples an sRGB `Color` to it. Backs
    /// `ipe_runtime::color::AnsiColor`.
    pub ansi_color: Symbol,
    /// `"WcagLevel"` — the WCAG conformance level `Color.meetsWcag` checks
    /// against. Backs `ipe_runtime::color::WcagLevel`.
    pub wcag_level: Symbol,
    /// `"TextSize"` — the text-size band a WCAG threshold applies to. Backs
    /// `ipe_runtime::color::TextSize`.
    pub text_size: Symbol,
    /// `"Deficiency"` — the colour-vision deficiency `Color.simulate` previews.
    /// Backs `ipe_runtime::color::Deficiency`.
    pub deficiency: Symbol,
    /// `"CustomElement"` — the JS-widget boundary type constructor
    /// `CustomElement down up`. Empty-module opaque handle; consumed only by the
    /// `CustomElement.node` kernel scheme.
    pub custom_element: Symbol,
    /// `"Html"` — Html type constructor `Html msg` (shared by Ipe.Html and
    /// Ipe.Ui render entry points).
    pub html_con: Symbol,
    /// `"Length"` — Ipe.Ui nullary length type produced by `Ui.px` / `Ui.fill`
    /// / `Ui.minimum` / …. Lowered to `IrType::UiPlain(UiPlain::Length)` via the
    /// `"Length"` arm in `ipe_lower::ir_type_from_ty`.
    pub length: Symbol,
    /// `"Color"` — Ipe.Ui nullary colour type produced by `Ui.rgb` / `Ui.rgba`
    /// / `Ui.white` / …. Lowered to `IrType::UiPlain(UiPlain::Color)`.
    pub color: Symbol,
    /// `"Description"` — Ipe.Ui semantic description type produced by `Ui.descMain`
    /// / `Ui.descNavigation` / …. Lowered to `IrType::UiPlain(UiPlain::Description)`
    /// via the `"Description"` arm in `ipe_lower::ir_type_from_ty`.
    pub description: Symbol,
    /// `"PseudoClass"` — Ipe.Ui nullary pseudo-class-selector type produced by
    /// `Ui.hover` / `Ui.focus` / `Ui.focusVisible` / `Ui.active` / `Ui.disabled`
    /// and consumed by `Ui.onPseudo`. Lowered to
    /// `IrType::UiPlain(UiPlain::PseudoClass)` via the
    /// `"PseudoClass"` arm in `ipe_lower::ir_type_from_ty`.
    pub pseudo_class: Symbol,
    /// `"Value"` — the opaque JSON value type (`Value = any` in Ipê) produced /
    /// consumed by the `JsonEnc.*` encoders. Lowered to `IrType::Json`
    /// (`serde_json::Value`, re-exported as `JsonVal`) via the `"Value"` arm in
    /// `ipe_lower::ir_type_from_ty`. A distinct interned symbol so the `JsonEnc`
    /// scheme can produce a *concrete* `Value` region type (closing the former
    /// `Ty::Var(u32::MAX)` exit-0 hole) rather than leaning on the lowerer's
    /// free-`Ty::Var` → `Json` fallback.
    pub json_value: Symbol,
    /// `"wrapperAttrs"` — field name in the `Ui.layoutWith` config record.
    /// Pre-interned because `kernel_ty` builds a `Ty::Record` for the first
    /// argument of `Ui.layoutWith : { wrapperAttrs, rootAttrs } -> ...` and
    /// needs the key as a `Symbol`.
    pub lw_wrapper_attrs: Symbol,
    /// `"rootAttrs"` — the second field in the `Ui.layoutWith` config record.
    pub lw_root_attrs: Symbol,
    // ── Ipe.Web / Ipe.Web opaque type constructor symbols ───────────────────
    /// `"WebReq"` — opaque request threaded through `Web.tea`'s `init`.
    pub web_req: Symbol,
    /// `"SessionHandle"` — the opaque `Ipe.Ffi.Js` session-stream handle,
    /// obtained only from `Js.openSession`. Backed by the runtime session id.
    pub session_handle: Symbol,
    /// `"WebRoute"` — opaque route descriptor returned by `Web.route`.
    pub live_route_con: Symbol,
    // ── Web cfg record field name symbols ───────────────────────────────────────
    /// `"init"` — the init field of the `Web.tea` config record.
    pub live_f_init: Symbol,
    /// `"update"` — the update field of the `Web.tea` config record.
    pub live_f_update: Symbol,
    /// `"view"` — the view field of the `Web.tea` config record.
    pub live_f_view: Symbol,
    /// `"subscriptions"` — the subscriptions field of the `Web.tea` config record.
    pub live_f_subscriptions: Symbol,
    /// `"routes"` — the routes field of the `Web.appRouted` config record.
    /// Reserved for a future split scheme between `app` and `appRouted`.
    #[allow(dead_code)]
    pub live_f_routes: Symbol,
    /// `"notFound"` — the notFound field of the `Web.appRouted` config record.
    /// Reserved for a future split scheme between `app` and `appRouted`.
    #[allow(dead_code)]
    pub live_f_not_found: Symbol,
    // ── Tui.Sub.onKey `KeyEvent` record field name symbols ────────────────────
    /// `"kind"` — a field of the pinned `Tui.Sub.onKey` `KeyEvent` record.
    ///
    /// The backend bridges the record handler onto the runtime's flat
    /// `Fn(String, String) -> Msg` key handler.
    pub tui_f_key_kind: Symbol,
    /// `"value"` — a field of the pinned `Tui.Sub.onKey` `KeyEvent` record.
    pub tui_f_key_value: Symbol,
    // ── Ui.button cfg record field name symbols ───────────────────────────────
    /// `"onPress"` — the onPress field of the `Ui.button` config record.
    /// Typed as `Maybe msg`.
    pub btn_f_on_press: Symbol,
    /// `"label"` — the label field of the `Ui.button` config record.
    /// Typed as `Element msg`.
    pub btn_f_label: Symbol,
    // ── Ipe.Ui.Input type constructor + cfg field symbols ─────────────
    /// `"Label"` — the `Label msg` type constructor from `Ipe.Ui.Input`.
    /// Lowered to `IrType::Ui { ctor: UiCtor::Label, msg }`.
    pub input_label_con: Symbol,
    /// `"Placeholder"` — the `Placeholder msg` type constructor from `Ipe.Ui.Input`.
    /// Lowered to `IrType::Ui { ctor: UiCtor::Placeholder, msg }`.
    pub input_placeholder_con: Symbol,
    /// `"RadioOption"` — the `RadioOption msg` type constructor from `Ipe.Ui.Input`.
    /// Lowered to `IrType::Ui { ctor: UiCtor::RadioOption, msg }`.
    pub input_radio_option_con: Symbol,
    /// `"onChange"` — the onChange field of Input text/multiline/password cfg records.
    pub input_f_on_change: Symbol,
    /// `"text"` — the text field of text/multiline/email/username/search/password cfg records.
    pub input_f_text: Symbol,
    /// `"placeholder"` — the placeholder field of text-variant cfg records.
    pub input_f_placeholder: Symbol,
    /// `"checked"` — the checked field of the checkbox cfg record.
    pub input_f_checked: Symbol,
    /// `"icon"` — the icon field of the checkbox cfg record.
    pub input_f_icon: Symbol,
    /// `"spellcheck"` — the spellcheck field of the multiline cfg record.
    pub input_f_spellcheck: Symbol,
    /// `"value"` — the value field of the slider cfg record (current value as String).
    pub input_f_value: Symbol,
    /// `"min"` — the min field of the slider cfg record.
    pub input_f_min: Symbol,
    /// `"max"` — the max field of the slider cfg record.
    pub input_f_max: Symbol,
    /// `"step"` — the step field of the slider cfg record.
    pub input_f_step: Symbol,
    /// `"options"` — the options field of the radio/radioRow cfg record.
    pub input_f_options: Symbol,
    /// `"selected"` — the selected field of the radio/radioRow cfg record.
    pub input_f_selected: Symbol,
    // ── Ipe.Http.Stream opaque StreamId type constructor ─────────────────
    /// `"StreamId"` — the opaque stream identifier type constructor from
    /// `Ipe.Http.Stream`. Backed by `ipe_runtime::http_stream::IpeStreamId`.
    /// No synthetic `EnumDef` is injected; the backend handles it via a special
    /// case in `enum_name` that maps the symbol to the runtime struct.
    pub stream_id: Symbol,
    // ── Order ADT ─────────────────────────────────────────────────────
    /// `"Order"` — the type constructor for three-way comparison results.
    pub order: Symbol,
    /// `"LT"` — the LT constructor of the Order ADT (less-than).
    pub lt: Symbol,
    /// `"EQ"` — the EQ constructor of the Order ADT (equal).
    pub eq: Symbol,
    /// `"GT"` — the GT constructor of the Order ADT (greater-than).
    pub gt: Symbol,
    // ── Task.RetryPolicy field name symbols (retry surface) ───────────────────
    /// `"maxAttempts"` — maximum number of attempts in `RetryPolicy e`.
    pub retry_f_max_attempts: Symbol,
    /// `"baseMs"` — base delay in milliseconds in `RetryPolicy e`.
    pub retry_f_base_ms: Symbol,
    /// `"shouldRetry"` — predicate field `e -> Bool` in `RetryPolicy e`.
    pub retry_f_should_retry: Symbol,
    /// `"strategy"` — the `BackoffStrategy` ADT field in `RetryPolicy e`.
    pub retry_f_strategy: Symbol,
    // ── Border/padding edge field name symbols (Border.widthEach) ────────────
    /// `"top"` — top edge field of `Border.widthEach { top, right, bottom, left }`.
    pub edge_f_top: Symbol,
    /// `"right"` — right edge field.
    pub edge_f_right: Symbol,
    /// `"bottom"` — bottom edge field.
    pub edge_f_bottom: Symbol,
    /// `"left"` — left edge field.
    pub edge_f_left: Symbol,
    // ── Border.shadow record field name symbols ──────────────────────────────
    /// `"offsetX"` — horizontal offset field of `Border.shadow { offsetX, … }`.
    pub shadow_f_offset_x: Symbol,
    /// `"offsetY"` — vertical offset field.
    pub shadow_f_offset_y: Symbol,
    /// `"blur"` — blur radius field.
    pub shadow_f_blur: Symbol,
    /// `"spread"` — spread field.
    pub shadow_f_spread: Symbol,
    /// `"color"` — shadow colour field.
    pub shadow_f_color: Symbol,
    // ── Ui.image record field name symbols ──────────────────────────────
    /// `"src"` — image source URL field of `Ui.image _ { src, description }`.
    pub img_f_src: Symbol,
    /// `"description"` — alt-text field of `Ui.image _ { src, description }`.
    pub img_f_description: Symbol,
    // ── Process.runWith input / output record field name symbols ──────────
    /// `"command"` — `Process.runWith` input: executable name or path.
    pub process_f_command: Symbol,
    /// `"args"` — `Process.runWith` input: argument vector.
    pub process_f_args: Symbol,
    /// `"cwd"` — `Process.runWith` input: optional per-child working directory.
    pub process_f_cwd: Symbol,
    /// `"env"` — `Process.runWith` input: per-child env overrides.
    pub process_f_env: Symbol,
    /// `"exitCode"` — `Process.runWith` output: exit status code.
    pub process_f_exit_code: Symbol,
    /// `"stdout"` — `Process.runWith` output: captured standard output.
    pub process_f_stdout: Symbol,
    /// `"stderr"` — `Process.runWith` output: captured standard error.
    pub process_f_stderr: Symbol,
    /// `"cols"` — `Process.runInPty` input: pty window width in columns.
    pub process_f_cols: Symbol,
    /// `"rows"` — `Process.runInPty` input: pty window height in rows.
    pub process_f_rows: Symbol,
    /// `"output"` — `Process.runInPty` output: combined pty-master stream.
    pub process_f_output: Symbol,
    // ── JWT builder opaque type constructor symbols (D-00) ────────────────────
    /// `"Claims"` — opaque JWT claims builder object.  Backed at runtime by
    /// `serde_json::Value` (a JSON object accumulator).  Used as the input /
    /// output of the `Jwt.subject`, `Jwt.issuer`, … builder chain functions
    /// and the final `Jwt.encode` call.
    pub jwt_claims: Symbol,
    /// `"Algorithm"` — JWT signing algorithm descriptor.  Backed at runtime by
    /// a sealed `Ipe.Secret` wrapping the string `"HS256:<secret>"` or
    /// `"RS256:<pem>"`.  Built by `Jwt.hs256` / `Jwt.rs256` and consumed by
    /// `Jwt.encode` / `Jwt.decode`.
    pub jwt_algorithm: Symbol,
    // ── Ipe.Decimal opaque type constructor symbol ────────────────────────────
    /// `"Decimal"` — the opaque arbitrary-precision decimal type constructor
    /// from `Ipe.Decimal`.  Backed by `ipe_runtime::decimal::Decimal` (wrapping
    /// `rust_decimal::Decimal`).  Zero type arguments.  Lowered to
    /// `IrType::Decimal` by `ir_type_from_ty` / `ir_type_from_canon`.
    pub decimal: Symbol,
    // ── Ipe.Csv record field symbols ─────────────────────────────────────
    /// `"header"` — `Ipe.Csv.Csv.header : List String`.
    pub csv_f_header: Symbol,
    /// `"rows"` — `Ipe.Csv.Csv.rows : List (List String)`.
    pub csv_f_rows: Symbol,
    // ── Ipe.Cache record field symbols ───────────────────────────────────
    /// `"maxEntries"` — `Ipe.Cache.CacheCfg.maxEntries : Int`.
    pub cache_f_max_entries: Symbol,
    /// `"ttlMs"` — `Ipe.Cache.CacheCfg.ttlMs : Int`.
    pub cache_f_ttl_ms: Symbol,
    /// `"maxBytes"` — `Ipe.Cache.CacheCfg.maxBytes : Int`.
    pub cache_f_max_bytes: Symbol,
    /// `"hits"` — `Ipe.Cache.stats` return field `hits : Int`.
    pub cache_f_hits: Symbol,
    /// `"misses"` — `Ipe.Cache.stats` return field `misses : Int`.
    pub cache_f_misses: Symbol,
    /// `"evictions"` — `Ipe.Cache.stats` return field `evictions : Int`.
    pub cache_f_evictions: Symbol,
    // ── Ipe.WebSocket.WebSocketCfg record field symbols ─────────────
    /// `"url"` — `Ipe.WebSocket.WebSocketCfg.url : String`.
    pub ws_f_url: Symbol,
    /// `"headers"` — `WebSocketCfg.headers : List (String, String)`.
    pub ws_f_headers: Symbol,
    /// `"timeout"` — `WebSocketCfg.timeout : Int`.
    pub ws_f_timeout: Symbol,
    /// `"pingInterval"` — `WebSocketCfg.pingInterval : Int`.
    pub ws_f_ping_interval: Symbol,
    // ── Ipe.Email type + record field symbols ────────────────────────────
    /// `"EmailProvider"` — the opaque `Ipe.Email.EmailProvider` ADT constructor
    /// (`Resend`/`Ses`/`SendGrid`/`Smtp`).  Backed by
    /// `ipe_runtime::email::EmailProvider`; lowered to `IrType::EmailProvider`.
    pub email_provider: Symbol,
    /// `EmailMessage` record field names (`ipe_runtime::email::EmailMessage`).
    pub email_f_from: Symbol,
    pub email_f_to: Symbol,
    pub email_f_cc: Symbol,
    pub email_f_bcc: Symbol,
    pub email_f_subject: Symbol,
    pub email_f_text_body: Symbol,
    pub email_f_html_body: Symbol,
    pub email_f_attachments: Symbol,
    pub email_f_reply_to: Symbol,
    /// `Attachment` record field names (`ipe_runtime::email::EmailAttachment`)
    /// — the `attachments` element shape carried inside `EmailMessage`.
    pub email_f_filename: Symbol,
    pub email_f_mime_type: Symbol,
    pub email_f_content: Symbol,
    // `SesConfig` / `SmtpConfig` record shapes are folded by the lowerer via
    // field-name string constants (`ipe_lower`), not through a kernel scheme, so
    // no interned field symbols for them are needed here.
    // ── Ipe.Crypto typed-key newtypes ──────────────────────────────────────
    /// `"Key"` — opaque role-typed crypto key (`ipe_runtime::crypto::Key`).
    /// The ONLY constructor is `Key.fromString`/`Key.fromBytes`; no implicit
    /// `String` coercion. Lowered to `IrType::CryptoKey`.
    pub crypto_key: Symbol,
    /// `"Mac"` — opaque role-typed MAC output (`ipe_runtime::crypto::Mac`).
    /// Produced exclusively by `hmacSha256WithKey`/`hmacSha512WithKey`; extracted
    /// via `Mac.toHex`.  Lowered to `IrType::CryptoMac`.
    pub crypto_mac: Symbol,
    // ── Ipe.Email.EmailAddress ──────────────────────────────────────────────
    /// `"EmailAddress"` — opaque validated email address
    /// (`ipe_runtime::email::EmailAddress`).  The ONLY constructor is
    /// `EmailAddress.parse : String -> Maybe EmailAddress`; extracted via
    /// `EmailAddress.toString`.  Lowered to `IrType::EmailAddress`.
    pub email_address: Symbol,
    // ── Ipe.Auth.Principal ────────────────────────────────────────────────────
    /// `"Principal"` — the opaque authenticated subject (`ipe_runtime::
    /// principal::Principal`). NO Ipê constructor: a value only ever comes from
    /// the server auth middleware's mint. Read via `Ipe.Auth.subject :
    /// Principal -> String`. Zero type arguments. Lowered to `IrType::Principal`.
    pub principal: Symbol,
    // ── Ipe.Url ─────────────────────────────────────────────────────────────
    /// `"Url"` — `Ipe.Url`'s opaque validated URL type (`ipe_runtime::url::Url`).
    /// The ONLY constructor is `Url.fromString : String -> Result Error Url`;
    /// extracted via `Url.toString`. Zero type arguments. Lowered to
    /// `IrType::Url`.
    pub url: Symbol,
    /// `"Relative"` — `Ipe.Url`'s opaque validated same-origin relative
    /// reference (`ipe_runtime::url::UrlRelative`). The ONLY constructor is
    /// `Url.relative : String -> Result Error Relative`; zero type arguments.
    /// Lowered to `IrType::UrlRelative`.
    pub url_relative: Symbol,
    // ── Ipe.Db.Dsn ──────────────────────────────────────────────────────────
    /// `"Dsn"` — `Ipe.Db.Dsn`'s opaque validated connection descriptor
    /// (`ipe_runtime::dsn::Dsn`). Constructed only by `Db.Dsn.parse` /
    /// `Db.Dsn.build`; zero type arguments. Lowered to `IrType::Dsn`.
    pub dsn: Symbol,
    // ── Ipe.Db external Connection ──────────────────────────────────────────
    /// `"Connection"` — the external-DB connection handle constructor
    /// `Connection mode` (`ipe_runtime::external_conn::ExternalConnection`).
    /// Minted only by `Db.Dsn.open`. The phantom
    /// `mode` distinguishes `ReadOnly` from `ReadWrite` at inference and is
    /// erased at emit. Lowered to `IrType::Connection`.
    pub connection: Symbol,
    /// `"ReadOnly"` — the phantom read-only access-mode marker. Appears only as
    /// `Connection`'s argument; never a standalone value. Lowered to
    /// `IrType::ConnReadOnly`.
    pub conn_read_only: Symbol,
    /// `"ReadWrite"` — the phantom mutable access-mode marker. Appears only as
    /// `Connection`'s argument; never a standalone value. Lowered to
    /// `IrType::ConnReadWrite`.
    pub conn_read_write: Symbol,
    // ── Ipe.App runtime-config Setting ──────────────────────────────────────
    /// `"Setting"` — the runtime-config carrier constructor `Setting shape`
    /// (`ipe_runtime::app_config::Setting`). Built only by the setting kernels
    /// (`Host.bind` / `Log.level` / `Db.url` / `Web.csrf` / …). The phantom
    /// `shape` marker keeps a `Web`-only setting from unifying into a
    /// `Terminal` app's settings list; erased at emit. Lowered to
    /// `IrType::Setting`.
    pub setting: Symbol,
    /// `"Web"` — the phantom shape marker pinning a setting to the web shape.
    /// Appears only as `Setting`'s argument; never a standalone value. Lowered
    /// to `IrType::ShapeWeb`.
    pub shape_web: Symbol,
    /// `"WebView"` — the phantom shape marker pinning a setting to the webview
    /// shape. Appears only as `Setting`'s argument. Lowered to
    /// `IrType::ShapeWebView`.
    pub shape_webview: Symbol,
    /// `"Terminal"` — the phantom shape marker pinning a setting to the terminal
    /// shape. Appears only as `Setting`'s argument. Lowered to
    /// `IrType::ShapeTerminal`.
    pub shape_terminal: Symbol,
    /// `"Program"` — the shape-carrier constructor `Program shape msg`, the
    /// uniform result of every TEA entry (`Web.tea`/`Tui.tea`/`Cli.tea`). Arity 2;
    /// the phantom `shape` tag and `msg` both erase at lower, so a `Program`
    /// lowers to the shape's existing app leaf (`WebApp`/`TuiApp`/`CliApp`).
    pub program: Symbol,
    /// `"Web"` — the phantom program-shape tag for the web shape. Appears only as
    /// `Program`'s first argument; erased at lower. Shares the interned name `Web`
    /// with [`Self::shape_web`] but is a distinct carrier tag.
    pub program_shape_web: Symbol,
    /// `"Tui"` — the phantom program-shape tag for the terminal-cells shape.
    /// Appears only as `Program`'s first argument; erased at lower.
    pub program_shape_tui: Symbol,
    /// `"Cli"` — the phantom program-shape tag for the terminal-lines shape.
    /// Appears only as `Program`'s first argument; erased at lower.
    pub program_shape_cli: Symbol,
    /// `"Worker"` — the phantom program-shape tag for the view-less co-located
    /// worker shape. Appears only as `Program`'s first argument; erased at lower.
    pub program_shape_worker: Symbol,
    /// `"HostMode"` — the closed host-bind ADT, the argument type of
    /// `Host.bind`. Built only by its constructor kernels; each projects to the
    /// raw `Int` host-bind tag at emit, so `HostMode` erases to `Int`.
    pub host_mode: Symbol,
    /// `"LogLevel"` — the closed log-severity ADT, the argument type of
    /// `Log.level`. Built only by its constructor kernels; erases to `Int`.
    pub log_level: Symbol,
    /// `"CsrfMode"` — the closed CSRF-policy ADT, the argument type of
    /// `Web.csrf`. Built only by its constructor kernels; carries no disabling
    /// variant, and erases to `Int`.
    pub csrf_mode: Symbol,
    /// `"RevocationMode"` — the closed revocation-gate ADT (`Off` / `Store`),
    /// the argument type of `Web.withRevocation` / `Server.withRevocation`.
    /// Stricter-only monotonic; erases to `Int`.
    pub revocation_mode: Symbol,
    // ── Ipe.Locale ─────────────────────────────────────────────────────────
    /// `"Locale"` — opaque BCP-47 locale handle (`ipe_runtime::locale::Locale`).
    /// The ONLY constructor is `Locale.fromTag : String -> Maybe Locale`;
    /// extracted via `Locale.toTag : Locale -> String`.  Lowered to
    /// `IrType::Locale`.
    pub locale: Symbol,
    // ── Ipe.PubSub.Topic ───────────────────────────────────────────────────
    /// `"Topic"` — the phantom topic-handle type constructor `Topic a`.
    /// Erases to `String` at runtime (`ir_type_from_ty` maps `Topic a → Str`).
    /// Used only in kernel type schemes (`CmdPublish`/`SubSubscribeTopic`/
    /// `PubSubPublish`/`PubSubPublishNoEcho`/`PubSubTopic`) to share the
    /// payload type variable `a` between publisher and subscriber.
    pub topic_con: Symbol,
    // ── Ipe.Db.Store.Cond ──────────────────────────────────────────────────
    /// `"Cond"` — the typed `WHERE`-predicate ADT built by the accessor-typed
    /// query leaves. Used as the result type of the `StoreEqCol` kernel scheme;
    /// its constructors (`Compare` / …) lower normally as an emitted enum.
    pub cond_con: Symbol,
    /// `"Pred"` — the `Ipe.Db.Store.Pred row` row-security predicate algebra ADT.
    /// The `row` argument is phantom (the runtime `Pred` carries only data). It is
    /// the result of the `StoreCorrelate` kernel scheme and the lambda result the
    /// `StoreExistsIn` kernel scheme requires, so a correlated-subquery predicate's
    /// share and outer row types stay pinned to their stores.
    pub pred_con: Symbol,
    /// `"Secured"` — the `Ipe.Db.Store.Secured row` classified, policy-attached
    /// table ADT. The first argument of the `StoreExistsIn` kernel scheme: the
    /// referenced share store whose own read policy composes into the `EXISTS`
    /// subquery. Its `row` argument ties the share store's row type to the
    /// correlation the `existsIn` lambda names.
    pub secured_con: Symbol,
    /// `"Codec"` — the `Ipe.Codec` codec ADT. Used as the first parameter of the
    /// `StoreEqBy` kernel scheme (`Codec t -> …`), so an enum/newtype column's
    /// comparison value is projected to a bound `SqlValue` through its own codec.
    pub codec_con: Symbol,
    /// `"Step"` — the `Ipe.Task.Step` loop-step ADT (`Continue s | Done a`).
    /// Consumed by the `Task.loop` kernel scheme; homed via
    /// [`Self::task_home`] so the scheme's `Step` is the compiled-module enum.
    pub task_step: Symbol,
    /// `"Store"` — the `Ipe.Db.Store.Store a` ADT, the classified, queryable
    /// table. Reads and writes accept a `Store a`; it is reachable only via
    /// `public` / `secured` applied to a `Draft a` (deny-by-default).
    pub store_con: Symbol,
    /// `"Draft"` — the `Ipe.Db.Store.Draft a` ADT, the unclassified table
    /// `fromCodec` returns. Used as the parameter and result of the accessor-typed
    /// schema-shaping builder kernel schemes (`StorePrimaryKey` / `StoreSerial` /
    /// … / `StoreDefaultInt`): they refine a `Draft`, before classification. No
    /// read or write kernel accepts a `Draft`, so an unclassified table is
    /// unqueryable by construction.
    pub draft_con: Symbol,
    /// `"Joined"` — the `Ipe.Db.Store.Joined a b` two-store inner-join ADT, the
    /// result of the `StoreJoin` kernel scheme
    /// (`Store a -> (a -> k) -> Store b -> (b -> k) -> Joined a b`). It carries
    /// both stores' row types so `toList` decodes each side through its own
    /// codec.
    pub joined_con: Symbol,
    /// `"Select"` — the `Ipe.Db.Store.Select row` column-projection ADT, the
    /// result of the `StoreSelect` kernel scheme
    /// (`(( Cols a, Cols b ) -> row) -> Joined a b -> Select row`). Its `row`
    /// argument is the projected shape the lambda returns.
    pub select_con: Symbol,
    /// `"Policy"` — the `Ipe.Db.Store.Policy row` operation-scoped row-security
    /// ADT. The `row` argument is phantom (the runtime `Policy` carries per-
    /// operation `Pred` data and validated column names, no `row` value), but it
    /// ties the accessor's record type to the store's row type in the
    /// `StoreOwnerColumn` / `StoreImmutable` kernel schemes, so `secured`
    /// (`Policy row -> Store row -> …`) pins the policy's columns to the store.
    pub policy_con: Symbol,
    /// `"Order"` — the `Ipe.Db.Store.Order` nullary ADT (`Asc | Desc`), the
    /// sort-direction argument of `orderByLeft` / `orderByRight`. It has no
    /// type parameters; the scheme just names the ADT so inference pins the
    /// second argument of each kernel to `Order`.
    pub order_con: Symbol,
    // ── Ipe.Db.Store.ProjectionTerm / ProjectionOperand ─────────────────────────
    /// `"ProjectionTerm"` — typed representation of a single named-select
    /// projection, backing `selectNamed`. Defined in `ipe_runtime::db` and
    /// exported via a type alias from the Spine. Zero type arguments.
    pub projection_term: Symbol,
    /// `"ColumnTerm"` — `ColumnTerm String String` constructor of `ProjectionTerm`
    /// (left-table column, right-table column).
    pub column_term: Symbol,
    /// `"LiteralTerm"` — `LiteralTerm` nullary constructor of `ProjectionTerm`
    /// (a `?` literal placeholder).
    pub literal_term: Symbol,
    /// `"UpperTerm"` — `UpperTerm String` constructor of `ProjectionTerm`
    /// (upper-cased column reference).
    pub upper_term: Symbol,
    /// `"LowerTerm"` — `LowerTerm String` constructor of `ProjectionTerm`
    /// (lower-cased column reference).
    pub lower_term: Symbol,
    /// `"CoalesceTerm"` — `CoalesceTerm ProjectionOperand ProjectionOperand`
    /// constructor of `ProjectionTerm` (SQL COALESCE of two operands).
    pub coalesce_term: Symbol,
    /// `"ProjectionOperand"` — companion type for the two operands of `CoalesceTerm`.
    /// Defined in `ipe_runtime::db` alongside `ProjectionTerm`.
    pub projection_operand: Symbol,
    /// `"OperandColumn"` — `OperandColumn String` constructor of `ProjectionOperand`
    /// (a dotted column reference).
    pub operand_column: Symbol,
    /// `"OperandLiteral"` — `OperandLiteral` nullary constructor of `ProjectionOperand`
    /// (a `?` literal placeholder).
    pub operand_literal: Symbol,
    /// `"ArithTerm"` — `ArithTerm ArithOp ProjectionOperand ProjectionOperand`
    /// constructor of `ProjectionTerm` (SQL arithmetic over two operands).
    pub arith_term: Symbol,
    /// `"ArithOp"` — the closed operator tag of `ArithTerm`. Zero type arguments.
    pub arith_op: Symbol,
    /// `"ArithAdd"` — nullary `ArithOp` constructor (SQL `+`).
    pub arith_add: Symbol,
    /// `"ArithSub"` — nullary `ArithOp` constructor (SQL `-`).
    pub arith_sub: Symbol,
    /// `"ArithMul"` — nullary `ArithOp` constructor (SQL `*`).
    pub arith_mul: Symbol,
    // ── Shape opaque app-leaf type constructor symbols ────────────────────────
    /// `"WebApp"` — opaque app handle returned by `Web.tea` / `Web.appRouted` /
    /// `Web.appWith`. Nullary; backed by `ipe_runtime::tea::WebApp`.
    pub web_app: Symbol,
    /// `"TuiApp"` — opaque app handle returned by `Tui.tea`. Nullary;
    /// backed by `ipe_runtime::tea::TuiApp`.
    pub tui_app: Symbol,
    /// `"CliApp"` — opaque app handle returned by `Cli.tea`. Nullary;
    /// backed by `ipe_runtime::tea::CliApp`.
    pub cli_app: Symbol,
    /// The interned module segments `["Ipe", "Db", "Store"]` — the real home of
    /// the `Cond` / `Store` / `Draft` / `Joined` / `Select` / `Policy` / `Order`
    /// ADTs. A kernel scheme returning one of these carries this home so the
    /// lowerer's home-keyed variant lookup finds its emitted enum instead of
    /// treating an unhomed name as an unknown builtin.
    pub db_store_home: Vec<Symbol>,
    /// The interned module segments `["Ipe", "Codec"]` — the real home of the
    /// `Codec` ADT.
    pub codec_home: Vec<Symbol>,
    /// The interned module segments `["Ipe", "Email"]` — the real home of the
    /// `EmailProvider` ADT. The `send` kernel scheme carries this home so a
    /// point-free reference lowers to the emitted enum instead of dropping
    /// through the lowerer's home-keyed variant lookup into the unknown-builtin
    /// internal-compiler-error arm.
    pub email_home: Vec<Symbol>,
    /// The interned module segments `["Ipe", "Duration"]` — the real home of the
    /// `Duration` ADT. The `Http.withTimeout` kernel scheme carries this home so a
    /// point-free reference lowers to the compiled-module enum instead of dropping
    /// through the lowerer's home-keyed variant lookup into the unknown-builtin
    /// internal-compiler-error arm (mirrors [`Self::email_home`]).
    pub duration_home: Vec<Symbol>,
    /// The interned module segments `["Ipe", "Task"]` — the real home of the
    /// `Step` ADT. The `Task.loop` kernel scheme carries this home so its `Step`
    /// is the same nominal type `Ipe.Task` declares, and a point-free reference
    /// lowers to that emitted enum (mirrors [`Self::duration_home`]).
    pub task_home: Vec<Symbol>,
}

impl Builtins {
    /// Interns every built-in name into `interner`; re-interning is idempotent.
    ///
    /// # Errors
    ///
    /// Fails when the interner refuses a name (its symbol space is exhausted).
    #[allow(clippy::too_many_lines)] // declarative intern table — each field listed explicitly for exhaustiveness
    pub fn new(interner: &mut Interner) -> DResult<Self> {
        Ok(Self {
            int: interner.intern("Int")?,
            float: interner.intern("Float")?,
            bool: interner.intern("Bool")?,
            string: interner.intern("String")?,
            char: interner.intern("Char")?,
            task: interner.intern("Task")?,
            maybe: interner.intern("Maybe")?,
            result: interner.intern("Result")?,
            list: interner.intern("List")?,
            dict: interner.intern("Dict")?,
            set: interner.intern("Set")?,
            bytes: interner.intern("Bytes")?,
            just: interner.intern("Just")?,
            nothing: interner.intern("Nothing")?,
            ok: interner.intern("Ok")?,
            err: interner.intern("Err")?,
            true_: interner.intern("True")?,
            false_: interner.intern("False")?,
            error: interner.intern("Error")?,
            errorkind: interner.intern("ErrorKind")?,
            ek_io: interner.intern("Io")?,
            ek_network: interner.intern("Network")?,
            ek_ffi: interner.intern("Ffi")?,
            ek_decode: interner.intern("Decode")?,
            ek_timeout: interner.intern("Timeout")?,
            ek_not_found: interner.intern("NotFound")?,
            ek_permission_denied: interner.intern("PermissionDenied")?,
            ek_invalid_input: interner.intern("InvalidInput")?,
            ek_conflict: interner.intern("Conflict")?,
            ek_unavailable: interner.intern("Unavailable")?,
            ek_unexpected: interner.intern("Unexpected")?,
            errordetails: interner.intern("ErrorDetails")?,
            backoffstrategy: interner.intern("BackoffStrategy")?,
            ed_ffi_panic: interner.intern("FfiPanic")?,
            ed_type_mismatch: interner.intern("TypeMismatch")?,
            ed_http_status: interner.intern("HttpStatus")?,
            ed_json_decode: interner.intern("JsonDecode")?,
            ed_custom: interner.intern("Custom")?,
            panicinfo: interner.intern("PanicInfo")?,
            typeinfo: interner.intern("TypeInfo")?,
            errorinfo: interner.intern("ErrorInfo")?,
            tv_a: interner.intern("a")?,
            tv_e: interner.intern("e")?,
            // Http field names (camelCase, as they appear in Ipê source).
            http_f_body: interner.intern("body")?,
            http_f_headers: interner.intern("headers")?,
            http_f_status: interner.intern("status")?,
            server_f_content_type: interner.intern("contentType")?,
            migration_f_name: interner.intern("name")?,
            migration_f_sql: interner.intern("sql")?,
            http_f_method: interner.intern("method")?,
            http_method: interner.intern("HttpMethod")?,
            http_f_url: interner.intern("url")?,
            http_f_timeout: interner.intern("timeout")?,
            http_f_redirects: interner.intern("redirects")?,
            redirect_policy: interner.intern("RedirectPolicy")?,
            duration: interner.intern("Duration")?,
            no_redirects: interner.intern("NoRedirects")?,
            follow_redirects: interner.intern("FollowRedirects")?,
            // Db symbols.
            db: interner.intern("Db")?,
            sqlvalue: interner.intern("SqlValue")?,
            sqlfield: interner.intern("SqlField")?,
            sqlfragment: interner.intern("SqlFragment")?,
            secret: interner.intern("Secret")?,
            path: interner.intern("Path")?,
            regex: interner.intern("Regex")?,
            sql_string: interner.intern("SqlString")?,
            sql_int: interner.intern("SqlInt")?,
            sql_float: interner.intern("SqlFloat")?,
            sql_bool: interner.intern("SqlBool")?,
            sql_bytes: interner.intern("SqlBytes")?,
            sql_time: interner.intern("SqlTime")?,
            sql_decimal: interner.intern("SqlDecimal")?,
            sql_money: interner.intern("SqlMoney")?,
            sql_null: interner.intern("SqlNull")?,
            set_field: interner.intern("SetField")?,
            omit_field: interner.intern("OmitField")?,
            decoder: interner.intern("Decoder")?,
            // TEA Cmd / Sub type constructors.
            cmd: interner.intern("Cmd")?,
            sub: interner.intern("Sub")?,
            // Ipe.Http.Server opaque types.
            server_request: interner.intern("Request")?,
            server_response: interner.intern("Response")?,
            server_route: interner.intern("Route")?,
            server_cookie: interner.intern("Cookie")?,
            auth_config: interner.intern("AuthConfig")?,
            token_source: interner.intern("TokenSource")?,
            handler: interner.intern("Handler")?,
            // Ipe.Http.Server.Stream opaque handle.
            stream_writer: interner.intern("StreamWriter")?,
            // Ipe.Http.Server.WebSocket opaque handles.
            ws_server: interner.intern("WebSocketServer")?,
            ws_server_cfg: interner.intern("WebSocketServerCfg")?,
            // Ipe.Ui / Ipe.Html parametric type constructor symbols.
            attribute: interner.intern("Attribute")?,
            view: interner.intern("View")?,
            element: interner.intern("Element")?,
            cells: interner.intern("Screen")?,
            tui_attr: interner.intern("TuiAttr")?,
            cli_lines: interner.intern("Lines")?,
            cli_attr: interner.intern("CliAttr")?,
            color_error: interner.intern("ColorError")?,
            term_profile: interner.intern("TermProfile")?,
            ansi_color: interner.intern("AnsiColor")?,
            wcag_level: interner.intern("WcagLevel")?,
            text_size: interner.intern("TextSize")?,
            deficiency: interner.intern("Deficiency")?,
            custom_element: interner.intern("CustomElement")?,
            html_con: interner.intern("Html")?,
            length: interner.intern("Length")?,
            color: interner.intern("Color")?,
            description: interner.intern("Description")?,
            pseudo_class: interner.intern("PseudoClass")?,
            json_value: interner.intern("Value")?,
            lw_wrapper_attrs: interner.intern("wrapperAttrs")?,
            lw_root_attrs: interner.intern("rootAttrs")?,
            // Ipe.Web / Ipe.Web opaque types + cfg field names.
            web_req: interner.intern("WebReq")?,
            session_handle: interner.intern("SessionHandle")?,
            live_route_con: interner.intern("WebRoute")?,
            live_f_init: interner.intern("init")?,
            live_f_update: interner.intern("update")?,
            live_f_view: interner.intern("view")?,
            live_f_subscriptions: interner.intern("subscriptions")?,
            live_f_routes: interner.intern("routes")?,
            live_f_not_found: interner.intern("notFound")?,
            // Tui.Sub.onKey `KeyEvent` field names.
            tui_f_key_kind: interner.intern("kind")?,
            tui_f_key_value: interner.intern("value")?,
            // Ui.button cfg field names.
            btn_f_on_press: interner.intern("onPress")?,
            btn_f_label: interner.intern("label")?,
            // Ipe.Ui.Input type constructors + cfg field names.
            input_label_con: interner.intern("Label")?,
            input_placeholder_con: interner.intern("Placeholder")?,
            input_radio_option_con: interner.intern("RadioOption")?,
            input_f_on_change: interner.intern("onChange")?,
            input_f_text: interner.intern("text")?,
            input_f_placeholder: interner.intern("placeholder")?,
            input_f_checked: interner.intern("checked")?,
            input_f_icon: interner.intern("icon")?,
            input_f_spellcheck: interner.intern("spellcheck")?,
            // Ipe.Ui.Input.slider cfg fields.
            input_f_value: interner.intern("value")?,
            input_f_min: interner.intern("min")?,
            input_f_max: interner.intern("max")?,
            input_f_step: interner.intern("step")?,
            // Ipe.Ui.Input.radio / radioRow cfg fields.
            input_f_options: interner.intern("options")?,
            input_f_selected: interner.intern("selected")?,
            // Ipe.Http.Stream: StreamId opaque handle type.
            stream_id: interner.intern("StreamId")?,
            csv_f_header: interner.intern("header")?,
            csv_f_rows: interner.intern("rows")?,
            // ── Ipe.Cache record field symbols ──────────────────────────
            cache_f_max_entries: interner.intern("maxEntries")?,
            cache_f_ttl_ms: interner.intern("ttlMs")?,
            cache_f_max_bytes: interner.intern("maxBytes")?,
            cache_f_hits: interner.intern("hits")?,
            cache_f_misses: interner.intern("misses")?,
            cache_f_evictions: interner.intern("evictions")?,
            // ── Ipe.WebSocket.WebSocketCfg record field symbols ────
            ws_f_url: interner.intern("url")?,
            ws_f_headers: interner.intern("headers")?,
            ws_f_timeout: interner.intern("timeout")?,
            ws_f_ping_interval: interner.intern("pingInterval")?,
            // ── Ipe.Email type + record field symbols ───────────────────
            email_provider: interner.intern("EmailProvider")?,
            email_f_from: interner.intern("from")?,
            email_f_to: interner.intern("to")?,
            email_f_cc: interner.intern("cc")?,
            email_f_bcc: interner.intern("bcc")?,
            email_f_subject: interner.intern("subject")?,
            email_f_text_body: interner.intern("textBody")?,
            email_f_html_body: interner.intern("htmlBody")?,
            email_f_attachments: interner.intern("attachments")?,
            email_f_reply_to: interner.intern("replyTo")?,
            email_f_filename: interner.intern("filename")?,
            email_f_mime_type: interner.intern("mimeType")?,
            email_f_content: interner.intern("content")?,
            // ── Order ADT ─────────────────────────────────────────────
            order: interner.intern("Order")?,
            lt: interner.intern("LT")?,
            eq: interner.intern("EQ")?,
            gt: interner.intern("GT")?,
            // ── Task.RetryPolicy field names (retry surface) ─────────────────────
            // Interned in BTreeMap / alphabetical order so the TyShape record
            // field slice order matches the symbol-key sort order.
            retry_f_base_ms: interner.intern("baseMs")?,
            retry_f_max_attempts: interner.intern("maxAttempts")?,
            retry_f_should_retry: interner.intern("shouldRetry")?,
            retry_f_strategy: interner.intern("strategy")?,
            // ── Border/padding edge field names (Border.widthEach) ───────────────
            edge_f_top: interner.intern("top")?,
            edge_f_right: interner.intern("right")?,
            edge_f_bottom: interner.intern("bottom")?,
            edge_f_left: interner.intern("left")?,
            // ── Border.shadow record field names ─────────────────────────────────
            shadow_f_offset_x: interner.intern("offsetX")?,
            shadow_f_offset_y: interner.intern("offsetY")?,
            shadow_f_blur: interner.intern("blur")?,
            shadow_f_spread: interner.intern("spread")?,
            shadow_f_color: interner.intern("color")?,
            // ── Ui.image record field names ────────────────────────────────
            img_f_src: interner.intern("src")?,
            img_f_description: interner.intern("description")?,
            // ── Process.runWith input / output record field names ─────────
            process_f_command: interner.intern("command")?,
            process_f_args: interner.intern("args")?,
            process_f_cwd: interner.intern("cwd")?,
            process_f_env: interner.intern("env")?,
            process_f_exit_code: interner.intern("exitCode")?,
            process_f_stdout: interner.intern("stdout")?,
            process_f_stderr: interner.intern("stderr")?,
            process_f_cols: interner.intern("cols")?,
            process_f_rows: interner.intern("rows")?,
            process_f_output: interner.intern("output")?,
            // ── JWT builder opaque type constructor symbols (D-00) ──────────────
            jwt_claims: interner.intern("Claims")?,
            jwt_algorithm: interner.intern("Algorithm")?,
            // ── Ipe.Decimal opaque type constructor ──────────────────────────────
            decimal: interner.intern("Decimal")?,
            // ── Ipe.Crypto typed-key newtypes ────────────────────────────────────
            crypto_key: interner.intern("Key")?,
            crypto_mac: interner.intern("Mac")?,
            // ── Ipe.Email.EmailAddress ────────────────────────────────────────────
            email_address: interner.intern("EmailAddress")?,
            // ── Ipe.Auth.Principal ────────────────────────────────────────────────
            principal: interner.intern("Principal")?,
            // ── Ipe.Url ───────────────────────────────────────────────────────────
            url: interner.intern("Url")?,
            url_relative: interner.intern("Relative")?,
            // ── Ipe.Db.Dsn ────────────────────────────────────────────────────────
            dsn: interner.intern("Dsn")?,
            connection: interner.intern("Connection")?,
            conn_read_only: interner.intern("ReadOnly")?,
            conn_read_write: interner.intern("ReadWrite")?,
            setting: interner.intern("Setting")?,
            shape_web: interner.intern("Web")?,
            shape_webview: interner.intern("WebView")?,
            shape_terminal: interner.intern("Terminal")?,
            program: interner.intern("Program")?,
            program_shape_web: interner.intern("Web")?,
            program_shape_tui: interner.intern("Tui")?,
            program_shape_cli: interner.intern("Cli")?,
            program_shape_worker: interner.intern("Worker")?,
            host_mode: interner.intern("HostMode")?,
            log_level: interner.intern("LogLevel")?,
            csrf_mode: interner.intern("CsrfMode")?,
            revocation_mode: interner.intern("RevocationMode")?,
            // ── Ipe.Locale ───────────────────────────────────────────────────────
            locale: interner.intern("Locale")?,
            // ── Ipe.PubSub.Topic ────────────────────────────────────────────────
            topic_con: interner.intern("Topic")?,
            cond_con: interner.intern("Cond")?,
            pred_con: interner.intern("Pred")?,
            secured_con: interner.intern("Secured")?,
            store_con: interner.intern("Store")?,
            draft_con: interner.intern("Draft")?,
            joined_con: interner.intern("Joined")?,
            select_con: interner.intern("Select")?,
            policy_con: interner.intern("Policy")?,
            order_con: interner.intern("Order")?,
            codec_con: interner.intern("Codec")?,
            task_step: interner.intern("Step")?,
            // ── ProjectionTerm / ProjectionOperand ──────────────────────────────
            projection_term: interner.intern("ProjectionTerm")?,
            column_term: interner.intern("ColumnTerm")?,
            literal_term: interner.intern("LiteralTerm")?,
            upper_term: interner.intern("UpperTerm")?,
            lower_term: interner.intern("LowerTerm")?,
            coalesce_term: interner.intern("CoalesceTerm")?,
            projection_operand: interner.intern("ProjectionOperand")?,
            operand_column: interner.intern("OperandColumn")?,
            operand_literal: interner.intern("OperandLiteral")?,
            arith_term: interner.intern("ArithTerm")?,
            arith_op: interner.intern("ArithOp")?,
            arith_add: interner.intern("ArithAdd")?,
            arith_sub: interner.intern("ArithSub")?,
            arith_mul: interner.intern("ArithMul")?,
            // ── Shape opaque app-leaf type constructor symbols ─────────────
            web_app: interner.intern("WebApp")?,
            tui_app: interner.intern("TuiApp")?,
            cli_app: interner.intern("CliApp")?,
            db_store_home: vec![
                interner.intern("Ipe")?,
                interner.intern("Db")?,
                interner.intern("Store")?,
            ],
            codec_home: vec![interner.intern("Ipe")?, interner.intern("Codec")?],
            email_home: vec![interner.intern("Ipe")?, interner.intern("Email")?],
            duration_home: vec![interner.intern("Ipe")?, interner.intern("Duration")?],
            task_home: vec![interner.intern("Ipe")?, interner.intern("Task")?],
        })
    }

    /// The built-in constructor table, derived from canon's `BUILTIN_UNIONS`.
    ///
    /// Every constructor canon registers maps to exactly one entry: a scheme
    /// (constructible and matchable from source) or a sealed key (a runtime-only
    /// capability handle such as `StreamId`). A union or constructor this walk
    /// does not know, or a payload whose arity disagrees with canon's, is a
    /// `CompilerBug` — the table can never drift into an unconstrained miss.
    ///
    /// # Errors
    /// `CompilerBug` (`constrain.builtin_ctor_payload`) on a canon entry with no
    /// payload arm, an arity mismatch, or a tag whose symbol disagrees.
    pub fn ctor_schemes(&self, interner: &mut Interner) -> DResult<BuiltinCtors> {
        let mut schemes = Vec::new();
        let mut sealed = BTreeSet::new();
        for union in ipe_canon::builtins::BUILTIN_UNIONS {
            let (tag, params) = self.builtin_union_head(union.type_name)?;
            let type_sym = interner.intern(union.type_name)?;
            if let Some(t) = tag
                && self.builtin_symbol(t) != type_sym
            {
                return Err(payload_bug(union.type_name, "<tag symbol>"));
            }
            let module = tag.map_or_else(Vec::new, |t| self.builtin_con_module(t).to_vec());
            let result = Ty::Con {
                module,
                name: type_sym,
                args: params,
            };
            for (ctor, _index, arity) in union.ctors.iter().copied() {
                let ctor_sym = interner.intern(ctor)?;
                let key: CtorKey = (Vec::new(), type_sym, ctor_sym);
                match self.builtin_ctor_payload(union.type_name, ctor)? {
                    CtorPayload::Scheme(arg_tys) if arg_tys.len() == arity => {
                        schemes.push((
                            key,
                            CtorScheme {
                                arg_tys,
                                result: result.clone(),
                            },
                        ));
                    }
                    CtorPayload::Scheme(_) => return Err(payload_bug(union.type_name, ctor)),
                    CtorPayload::Sealed => {
                        sealed.insert(key);
                    }
                }
            }
        }
        Ok(BuiltinCtors { schemes, sealed })
    }

    /// The tag and result type parameters of the canon builtin union `type_name`.
    ///
    /// `ChunkEvent` and `ArithOp` have no [`BuiltinTag`]; their result `Con`
    /// carries the empty module every builtin `Con` without a tag carries.
    fn builtin_union_head(&self, type_name: &str) -> DResult<(Option<BuiltinTag>, Vec<Ty>)> {
        let a = Ty::Var(self.tv_a.as_raw());
        let e = Ty::Var(self.tv_e.as_raw());
        let tag = match type_name {
            "Maybe" => return Ok((Some(BuiltinTag::Maybe), vec![a])),
            "Result" => return Ok((Some(BuiltinTag::Result), vec![e, a])),
            "ChunkEvent" | "ArithOp" => return Ok((None, Vec::new())),
            "Bool" => BuiltinTag::Bool,
            "Order" => BuiltinTag::Order,
            "SqlValue" => BuiltinTag::SqlValue,
            "SqlField" => BuiltinTag::SqlField,
            "ProjectionTerm" => BuiltinTag::ProjectionTerm,
            "ProjectionOperand" => BuiltinTag::ProjectionOperand,
            "StreamId" => BuiltinTag::StreamId,
            "HttpMethod" => BuiltinTag::HttpMethod,
            "RedirectPolicy" => BuiltinTag::RedirectPolicy,
            "Error" => BuiltinTag::Error,
            "ErrorKind" => BuiltinTag::ErrorKind,
            "ErrorDetails" => BuiltinTag::ErrorDetails,
            _ => return Err(payload_bug(type_name, "<union>")),
        };
        Ok((Some(tag), Vec::new()))
    }

    /// The payload of canon builtin constructor `ctor` of union `type_name`.
    ///
    /// One arm per canon constructor; the final arm refuses an unknown pair so a
    /// constructor added to canon without a payload here breaks every build.
    fn builtin_ctor_payload(&self, type_name: &str, ctor: &str) -> DResult<CtorPayload> {
        let a = || Ty::Var(self.tv_a.as_raw());
        let e = || Ty::Var(self.tv_e.as_raw());
        let tagged = |tag: BuiltinTag| Ty::Con {
            module: self.builtin_con_module(tag).to_vec(),
            name: self.builtin_symbol(tag),
            args: Vec::new(),
        };
        let untagged = |name: Symbol| Ty::Con {
            module: Vec::new(),
            name,
            args: Vec::new(),
        };
        let string = || tagged(BuiltinTag::String);
        let int = || tagged(BuiltinTag::Int);
        let operand = || tagged(BuiltinTag::ProjectionOperand);
        let args = match (type_name, ctor) {
            ("Bool", "True" | "False")
            | ("Maybe", "Nothing")
            | ("Order", "LT" | "EQ" | "GT")
            | ("SqlField", "OmitField")
            | ("ProjectionTerm", "LiteralTerm")
            | ("ProjectionOperand", "OperandLiteral")
            | ("ArithOp", "ArithAdd" | "ArithSub" | "ArithMul")
            | ("ChunkEvent", "Done")
            | ("HttpMethod", "Get" | "Post" | "Put" | "Delete" | "Patch" | "Head" | "Options")
            | ("RedirectPolicy", "NoRedirects")
            | (
                "ErrorKind",
                "Io" | "Network" | "Ffi" | "Decode" | "Timeout" | "NotFound" | "PermissionDenied"
                | "InvalidInput" | "Conflict" | "Unavailable" | "Unexpected",
            ) => Vec::new(),
            ("Maybe", "Just") | ("Result", "Ok") => vec![a()],
            ("Result", "Err") => vec![e()],
            ("SqlValue", "SqlString" | "SqlMoney")
            | ("ProjectionTerm", "UpperTerm" | "LowerTerm")
            | ("ProjectionOperand", "OperandColumn")
            | ("ChunkEvent", "Chunk")
            | ("ErrorDetails", "JsonDecode" | "Custom") => vec![string()],
            ("SqlValue", "SqlInt" | "SqlTime")
            | ("RedirectPolicy", "FollowRedirects")
            | ("ErrorDetails", "HttpStatus") => vec![int()],
            ("SqlValue", "SqlFloat") => vec![tagged(BuiltinTag::Float)],
            ("SqlValue", "SqlBool") => vec![tagged(BuiltinTag::Bool)],
            ("SqlValue", "SqlBytes") => vec![tagged(BuiltinTag::Bytes)],
            ("SqlValue", "SqlDecimal") => vec![tagged(BuiltinTag::Decimal)],
            ("SqlValue", "SqlNull") | ("SqlField", "SetField") => {
                vec![tagged(BuiltinTag::SqlValue)]
            }
            ("ProjectionTerm", "ColumnTerm") => vec![string(), string()],
            ("ProjectionTerm", "CoalesceTerm") => vec![operand(), operand()],
            ("ProjectionTerm", "ArithTerm") => {
                vec![untagged(self.arith_op), operand(), operand()]
            }
            ("ChunkEvent", "Errored") => vec![tagged(BuiltinTag::Error)],
            // `PanicInfo` / `TypeInfo` / `ErrorInfo` are NOMINAL opaque Cons,
            // not structural records: a bare record literal fails to unify at
            // ipe time instead of lowering to a struct the runtime rejects.
            // Source builds them only through the `Error` smart constructors.
            ("Error", "Error") => vec![tagged(BuiltinTag::ErrorKind), untagged(self.errorinfo)],
            ("ErrorDetails", "FfiPanic") => vec![untagged(self.panicinfo)],
            ("ErrorDetails", "TypeMismatch") => vec![untagged(self.typeinfo)],
            // A stream handle is minted only by the runtime; source never names it.
            ("StreamId", "StreamId") => return Ok(CtorPayload::Sealed),
            _ => return Err(payload_bug(type_name, ctor)),
        };
        Ok(CtorPayload::Scheme(args))
    }
}

/// How one canon builtin constructor enters the type checker.
pub enum CtorPayload {
    /// Constructible and matchable from source, with these payload types.
    Scheme(Vec<Ty>),
    /// A runtime-only capability handle: naming it from source is refused.
    Sealed,
}

/// The builtin constructor table derived from canon's `BUILTIN_UNIONS`.
pub struct BuiltinCtors {
    /// Source-visible constructors, keyed by canon's `(home, type, ctor)`.
    pub schemes: Vec<(CtorKey, CtorScheme)>,
    /// Capability-handle constructors source may never name.
    pub sealed: BTreeSet<CtorKey>,
}

/// The `CompilerBug` for a canon builtin entry this table cannot derive.
fn payload_bug(type_name: &str, ctor: &str) -> Diagnostic {
    Diagnostic::CompilerBug {
        where_: "constrain.builtin_ctor_payload",
        detail: format!("canon builtin `{type_name}.{ctor}` has no matching constructor payload"),
    }
}

/// The type discipline a binary operator imposes. Classified once from the
/// resolved kernel name so the constraint walk doesn't re-borrow the interner.
#[derive(Clone, Copy)]
pub enum BinopClass {
    /// `//`: integer division `Int -> Int -> Int`.
    IntDiv,
    /// `/`: `Float -> Float -> Float` (matches the the backend's float division).
    FloatDiv,
    /// `+ - *`: `Number a => a -> a -> a`. The operands and the result share one
    /// numeric variable carrying the named obligation, so the operation stays
    /// generic over `Int` / `Float` until a concrete operand pins it.
    Num(TyBounds),
    /// `< > <= >=`: `Comparable a => a -> a -> Bool` — operands share one
    /// ordered type; the result is `Bool`.
    Order,
    /// `== /=`: `Equatable a => a -> a -> Bool` — operands share one equatable
    /// type (structural equality is total over every non-function type); the
    /// result is `Bool`. The shared variable carries the equality obligation, so
    /// a generalised use emits a Rust `PartialEq` bound.
    Equality,
    /// `&& ||`: `Bool -> Bool -> Bool`.
    Boolean,
    /// `++`: `String -> String -> String`. The general `Appendable` super-type
    /// (which would also cover `List a -> List a -> List a`) is a later batch;
    /// for now both operands and the result are pinned to `String`, so applying
    /// `++` to any other type (a would-be `List`) is a fail-closed type error
    /// rather than a mis-typed pass-through.
    Append,
    /// Any other operator (`::`, …): `a -> a -> a`. The numeric/ordering
    /// super-types do not cover list cons, so it stays a plain pass-through here
    /// and is gated at lowering rather than mis-typed.
    Poly,
}

/// Classify a resolved operator kernel name (`add`, `eq`, `and`, …).
pub const fn classify_binop(func: &str) -> BinopClass {
    match func.as_bytes() {
        b"add" => BinopClass::Num(TyBounds::add()),
        b"sub" => BinopClass::Num(TyBounds::sub()),
        b"mul" => BinopClass::Num(TyBounds::mul()),
        b"idiv" => BinopClass::IntDiv,
        b"fdiv" => BinopClass::FloatDiv,
        b"lt" | b"gt" | b"le" | b"ge" => BinopClass::Order,
        b"eq" | b"neq" => BinopClass::Equality,
        b"and" | b"or" => BinopClass::Boolean,
        b"append" => BinopClass::Append,
        _ => BinopClass::Poly,
    }
}
