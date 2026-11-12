//! THE SEAL for a callee's runtime bound at a concrete instance.
//!
//! A kernel's runtime function or an emitted user generic may demand a Rust
//! bound (`Clone`, `PartialEq`, `Sync`) its Ipê type scheme does not state:
//! `list_repeat<T: Clone>`, `ident<T1: Clone>`. Instantiating that variable
//! with a type whose carrier lacks the bound (a `Task`, a `Cmd`, a boxed
//! function) would pass `ipe` and fail `cargo build` with E0277. Every such
//! instance is refused at `ipe` time with IPE-L0164; the comparison case
//! (`==`, `List.member`) is refused by the type checker's `Equatable` rule,
//! for a `Task`, a decoder, and every handle alike, bare or held in a record
//! or a union, with the lowering backstop (IPE-L0164) behind it.
//!
//! The refusals run without `IPE_E2E` (no Rust is emitted); the acceptances
//! build and run the emitted crate under `IPE_E2E=1`, so the gate never
//! over-refuses a carrier that is `Clone`.
//!
//! ```text
//! cargo test -p ipe --test g_issues golden_list_repeat_clone_seal
//! IPE_E2E=1 cargo test -p ipe --test g_issues golden_list_repeat_clone_seal
//! ```

use std::path::PathBuf;

use ipe::CliError;

/// A runtime `false` the optimiser cannot fold, for a deliberate failure.
const fn false_marker() -> bool {
    std::hint::black_box(false)
}

/// The scratch output dir for `name`, cleared.
fn out_dir(name: &str) -> PathBuf {
    let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("l0164-out")
        .join(name);
    e2e_support::scratch::fresh(&out);
    out
}

/// Assert `source` is refused by `ipe` with `expected`, before any Rust is emitted.
#[track_caller]
fn assert_rejected(name: &str, source: &str, expected: ipe_diagnostics::Code) {
    let fixture = crate::root_fixture::main(source);
    let out = out_dir(name);
    let runtime = e2e_support::require_runtime().into_path_buf();
    match crate::root_fixture::build(&fixture, &out, &runtime) {
        Err(CliError::Pipeline { diag, .. }) => assert_eq!(
            diag.code(),
            expected,
            "{name}: expected a fail-closed {expected:?}, got a different diagnostic"
        ),
        Ok(()) => assert!(
            false_marker(),
            "{name}: ipe ACCEPTED a callee instance whose runtime bound is unmet \
             (exit 0); the emitted crate fails cargo with E0277, a SEAL break"
        ),
        Err(other) => assert!(
            false_marker(),
            "{name}: non-pipeline build error: {other:?}"
        ),
    }
}

/// Assert `source` is refused with IPE-L0164.
#[track_caller]
fn assert_l0164(name: &str, source: &str) {
    assert_rejected(name, source, ipe_diagnostics::IPE_L0164);
}

/// Assert `source` is accepted and, under `IPE_E2E`, builds and prints `expected_stdout`.
#[track_caller]
fn assert_accepted(name: &str, source: &str, expected_stdout: &str) {
    let fixture = crate::root_fixture::main(source);
    let out = out_dir(name);
    let runtime = e2e_support::require_runtime().into_path_buf();
    match crate::root_fixture::build(&fixture, &out, &runtime) {
        Ok(()) => {}
        Err(CliError::Pipeline { diag, .. }) => {
            assert!(
                false_marker(),
                "{name}: ipe REJECTED a well-formed program with {}, a false refusal",
                diag.code().as_str()
            );
            return;
        }
        Err(other) => {
            assert!(
                false_marker(),
                "{name}: non-pipeline build error: {other:?}"
            );
            return;
        }
    }
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }
    let outcome = crate::support::build_and_run_emitted(name, &out);
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "{name}: emitted crate must run to exit 0"
    );
    assert_eq!(
        outcome.stdout.trim_end(),
        expected_stdout,
        "{name}: emitted crate built (SEAL held) but ran to the wrong output"
    );
}

/// The prelude every fixture shares.
const HEAD: &str = "module Main exposing (main)

import Ipe.Dict as Dict
import Ipe.Io as Io
import Ipe.List as List
import Ipe.String as String
import Ipe.Task as Task

";

/// `HEAD` followed by `body`.
fn program(body: &str) -> String {
    format!("{HEAD}{body}")
}

#[test]
fn repeat_task_refused() {
    let src = program(
        "main : Task Error ()
main =
    Task.map (\\_ -> ()) (Task.sequence (List.repeat 3 (Io.println \"x\")))
",
    );
    assert_l0164("repeat_task", &src);
}

#[test]
fn repeat_task_piped_refused() {
    let src = program(
        "main : Task Error ()
main =
    Io.println \"x\"
        |> List.repeat 3
        |> Task.sequence
        |> Task.map (\\_ -> ())
",
    );
    assert_l0164("repeat_task_piped", &src);
}

#[test]
fn repeat_point_free_refused() {
    let src = program(
        "main : Task Error ()
main =
    Io.println (String.fromInt (List.length (List.map (List.repeat 2) [ Io.println \"x\" ])))
",
    );
    assert_l0164("repeat_point_free", &src);
}

#[test]
fn repeat_partial_refused() {
    let src = program(
        "main : Task Error ()
main =
    let
        twice =
            List.repeat 2
    in
    Task.map (\\_ -> ()) (Task.sequence (twice (Io.println \"x\")))
",
    );
    assert_l0164("repeat_partial", &src);
}

#[test]
fn repeat_maybe_task_refused() {
    let src = program(
        "main : Task Error ()
main =
    Io.println (String.fromInt (List.length (List.repeat 2 (Just (Io.println \"x\")))))
",
    );
    assert_l0164("repeat_maybe_task", &src);
}

#[test]
fn repeat_record_holding_task_refused() {
    let src = program(
        "main : Task Error ()
main =
    Io.println (String.fromInt (List.length (List.repeat 2 { run = Io.println \"x\" })))
",
    );
    assert_l0164("repeat_record_holding_task", &src);
}

#[test]
fn dict_get_task_value_refused() {
    let src = program(
        "main : Task Error ()
main =
    case Dict.get \"k\" (Dict.fromList [ ( \"k\", Io.println \"x\" ) ]) of
        Just t ->
            t

        Nothing ->
            Io.println \"none\"
",
    );
    assert_l0164("dict_get_task_value", &src);
}

#[test]
fn list_filter_task_refused() {
    let src = program(
        "main : Task Error ()
main =
    Task.map (\\_ -> ()) (Task.sequence (List.filter (\\_ -> True) [ Io.println \"x\" ]))
",
    );
    assert_l0164("list_filter_task", &src);
}

#[test]
fn list_intersperse_task_refused() {
    let src = program(
        "main : Task Error ()
main =
    Task.map (\\_ -> ()) (Task.sequence (List.intersperse (Io.println \"x\") [ Io.println \"y\" ]))
",
    );
    assert_l0164("list_intersperse_task", &src);
}

#[test]
fn random_shuffle_task_refused() {
    let src = program(
        "import Ipe.Random as Random


main : Task Error ()
main =
    Random.shuffle [ Io.println \"x\" ]
        |> Task.andThen Task.sequence
        |> Task.map (\\_ -> ())
",
    );
    assert_l0164("random_shuffle_task", &src);
}

/// A Web TEA app publishing a `Task` payload: `Cmd.publish` clones the payload per subscriber.
const CMD_PUBLISH_TASK: &str = "module Main exposing (main)

import Ipe.PubSub as PubSub
import Ipe.Task as Task
import Ipe.Tea.Web as Web
import Ipe.Tea.Web.Cmd as Cmd
import Ipe.Tea.Web.Sub as Sub
import Ipe.Ui as Ui


type Msg
    = Publish
    | Ignored


type alias Model =
    {}


topic =
    PubSub.topic \"seal-task\"


init _req =
    ( {}, Cmd.none )


update msg model =
    case msg of
        Publish ->
            ( model, Cmd.publish topic (Task.succeed 1) )

        Ignored ->
            ( model, Cmd.none )


subscriptions _model =
    Sub.none


view _model =
    Ui.html (Ui.layout [] (Ui.text \"ok\"))


main =
    Web.tea
        { init = init
        , update = update
        , view = view
        , subscriptions = subscriptions
        , routes = []
        , notFound = Ignored
        }
";

#[test]
fn cmd_publish_task_payload_refused() {
    assert_l0164("cmd_publish_task_payload", CMD_PUBLISH_TASK);
}

/// A Tui TEA app whose model holds a `Task`: the terminal loop clones the model each frame.
const TUI_MODEL_TASK: &str = "module Main exposing (main)

import Ipe.Io as Io
import Ipe.Tea.Terminal.Cmd
import Ipe.Tea.Tui as Tui
import Ipe.Tea.Tui.Sub
import Ipe.Ui.Cells as Cells
import Ipe.Ui.Cells exposing (Screen)


type Msg
    = NoOp


type alias Model =
    { pending : Task Error () }


init : () -> ( Model, Cmd Msg )
init _unit =
    ( { pending = Io.println \"x\" }, Cmd.none )


update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    case msg of
        NoOp ->
            ( model, Cmd.none )


view : Model -> Screen Msg
view _model =
    Cells.text \"ok\"


subscriptions : Model -> Sub Msg
subscriptions _model =
    Sub.none


main =
    Tui.tea
        { init = init
        , update = update
        , view = view
        , subscriptions = subscriptions
        }
";

/// A `Task` in a Tui Model is refused as a Model (IPE-L0120), not as the app kernel's `Clone` bound.
#[test]
fn tui_model_holding_task_refused() {
    assert_rejected(
        "tui_model_holding_task",
        TUI_MODEL_TASK,
        ipe_diagnostics::IPE_L0120,
    );
}

#[test]
fn user_generic_task_instance_refused() {
    let src = program(
        "ident : a -> a
ident x =
    x


main : Task Error ()
main =
    ident (Io.println \"x\")
",
    );
    assert_l0164("user_generic_task_instance", &src);
}

#[test]
fn user_generic_forwarded_then_concrete_refused() {
    let src = program(
        "ident : a -> a
ident x =
    x


wrap : a -> a
wrap x =
    ident x


main : Task Error ()
main =
    wrap (Io.println \"x\")
",
    );
    assert_l0164("user_generic_forwarded_then_concrete", &src);
}

/// The prelude of the `Ipe.Parser` operator fixtures: `a |= b` desugars to
/// `Ipe.Parser.ignore a b`, whose head carries the call's own span.
const PARSER_HEAD: &str = "module Main exposing (main)

import Ipe.Io as Io
import Ipe.Parser as Parser exposing (Parser)
import Ipe.String as String

";

#[test]
fn parser_operator_task_instance_refused() {
    let src = format!(
        "{PARSER_HEAD}taskAfterComma : Parser (Task Error ())
taskAfterComma =
    Parser.symbol \",\" |= Parser.succeed (Io.println \"x\")


main : Task Error ()
main =
    Io.println \"x\"
"
    );
    assert_l0164("parser_operator_task_instance", &src);
}

#[test]
fn parser_operator_concrete_instance_builds() {
    let src = format!(
        "{PARSER_HEAD}commaThenInt : Parser Int
commaThenInt =
    Parser.symbol \",\" |= Parser.int


main : Task Error ()
main =
    case Parser.run commaThenInt \",42\" of
        Ok n ->
            Io.println (String.fromInt n)

        Err _ ->
            Io.println \"no parse\"
"
    );
    assert_accepted("parser_operator_concrete_instance", &src, "42");
}

#[test]
fn task_equality_refused() {
    let src = program(
        "main : Task Error ()
main =
    if Io.println \"x\" == Io.println \"y\" then
        Io.println \"same\"

    else
        Io.println \"different\"
",
    );
    assert_rejected("task_equality", &src, ipe_diagnostics::IPE_T0014);
}

#[test]
fn list_member_task_refused() {
    let src = program(
        "main : Task Error ()
main =
    if List.member (Io.println \"x\") [ Io.println \"y\" ] then
        Io.println \"member\"

    else
        Io.println \"absent\"
",
    );
    assert_rejected("list_member_task", &src, ipe_diagnostics::IPE_T0014);
}

/// Assert `source` is refused by `ipe` with one of `expected`, before any Rust is emitted.
///
/// For a comparison whose refusal boundary depends on where its type becomes
/// concrete: the type checker (IPE-T0014) or the lowering backstop (IPE-L0164).
#[track_caller]
fn assert_rejected_by_either(name: &str, source: &str, expected: [ipe_diagnostics::Code; 2]) {
    let fixture = crate::root_fixture::main(source);
    let out = out_dir(name);
    let runtime = e2e_support::require_runtime().into_path_buf();
    match crate::root_fixture::build(&fixture, &out, &runtime) {
        Err(CliError::Pipeline { diag, .. }) => assert!(
            expected.contains(&diag.code()),
            "{name}: expected a fail-closed {expected:?}, got {}",
            diag.code().as_str()
        ),
        Ok(()) => assert!(
            false_marker(),
            "{name}: ipe ACCEPTED an `==` over a type with no `PartialEq` \
             (exit 0); the emitted crate fails cargo with E0369, a SEAL break"
        ),
        Err(other) => assert!(
            false_marker(),
            "{name}: non-pipeline build error: {other:?}"
        ),
    }
}

/// `HEAD` plus `imports`, a two-argument `same` comparing values of `ty`, and a
/// `main` that never calls it: the comparison is refused in `same`'s body.
fn compare_program(imports: &str, ty: &str) -> String {
    program(&format!(
        "{imports}
same : {ty} -> {ty} -> Bool
same a b =
    a == b


main : Task Error ()
main =
    Io.println \"x\"
"
    ))
}

/// A `main` printing whether `condition` holds.
fn if_program(imports: &str, decls: &str, condition: &str) -> String {
    program(&format!(
        "{imports}
{decls}
main : Task Error ()
main =
    if {condition} then
        Io.println \"same\"

    else
        Io.println \"different\"
"
    ))
}

#[test]
fn decoder_equality_refused() {
    let src = if_program(
        "import Ipe.Config as Config\n",
        "",
        "Config.int == Config.int",
    );
    assert_rejected("decoder_equality", &src, ipe_diagnostics::IPE_T0014);
}

#[test]
fn decoder_member_refused() {
    let src = if_program(
        "import Ipe.Config as Config\n",
        "",
        "List.member Config.int [ Config.int ]",
    );
    assert_rejected("decoder_member", &src, ipe_diagnostics::IPE_T0014);
}

#[test]
fn db_equality_refused() {
    let src = compare_program("import Ipe.Db as Db exposing (Db)\n", "Db");
    assert_rejected("db_equality", &src, ipe_diagnostics::IPE_T0014);
}

#[test]
fn regex_equality_refused() {
    let src = compare_program("import Ipe.Regex as Regex\n", "Regex");
    assert_rejected("regex_equality", &src, ipe_diagnostics::IPE_T0014);
}

/// `HttpRequest` is a record alias the lowerer folds to the runtime's request
/// descriptor, so its refusal may land at either boundary.
#[test]
fn http_request_equality_refused() {
    let src = compare_program("import Ipe.Http as Http\n", "Http.HttpRequest");
    assert_rejected_by_either(
        "http_request_equality",
        &src,
        [ipe_diagnostics::IPE_T0014, ipe_diagnostics::IPE_L0164],
    );
}

#[test]
fn setting_equality_refused() {
    let src = compare_program("", "Setting Int");
    assert_rejected("setting_equality", &src, ipe_diagnostics::IPE_T0014);
}

#[test]
fn auth_config_equality_refused() {
    let src = compare_program("import Ipe.Http.Server as Server\n", "Server.AuthConfig");
    assert_rejected("auth_config_equality", &src, ipe_diagnostics::IPE_T0014);
}

#[test]
fn html_attribute_equality_refused() {
    let src = compare_program(
        "import Ipe.Html as Html exposing (Attribute)\n",
        "Attribute Int",
    );
    assert_rejected("html_attribute_equality", &src, ipe_diagnostics::IPE_T0014);
}

#[test]
fn record_holding_decoder_equality_refused() {
    let src = if_program(
        "import Ipe.Config as Config\n",
        "",
        "{ d = Config.int } == { d = Config.int }",
    );
    assert_rejected(
        "record_holding_decoder_equality",
        &src,
        ipe_diagnostics::IPE_T0014,
    );
}

#[test]
fn union_holding_decoder_equality_refused() {
    let src = if_program(
        "import Ipe.Config as Config\n",
        "type Field
    = Field (Config.Decoder Int)

",
        "Field Config.int == Field Config.int",
    );
    assert_rejected(
        "union_holding_decoder_equality",
        &src,
        ipe_diagnostics::IPE_T0014,
    );
}

/// The `Equatable` bound of an unannotated generic reaches its decoder
/// instance at the call: refused by the checker's call-site obligation, or by
/// the lowering backstop once the instance is concrete.
#[test]
fn generic_eq_at_decoder_refused() {
    let src = if_program(
        "import Ipe.Config as Config\n",
        "same a b =
    a == b

",
        "same Config.int Config.int",
    );
    assert_rejected_by_either(
        "generic_eq_at_decoder",
        &src,
        [ipe_diagnostics::IPE_T0014, ipe_diagnostics::IPE_L0164],
    );
}

#[test]
fn decoded_values_compare_builds() {
    let src = if_program(
        "import Ipe.Config as Config\n",
        "",
        "Config.decodeJson \"1\" Config.int == Ok 1",
    );
    assert_accepted("decoded_values_compare", &src, "same");
}

#[test]
fn int_field_record_compare_builds() {
    let src = if_program("", "", "{ n = 1, s = \"x\" } == { n = 1, s = \"x\" }");
    assert_accepted("int_field_record_compare", &src, "same");
}

#[test]
fn sql_value_union_compare_builds() {
    let src = if_program(
        "import Ipe.Db as Db\n",
        "type Cell
    = Cell SqlValue

",
        "Cell (SqlInt 1) == Cell (SqlInt 1)",
    );
    assert_accepted("sql_value_union_compare", &src, "same");
}

#[test]
fn repeat_int_builds() {
    let src = program(
        "main : Task Error ()
main =
    Io.println (String.fromInt (List.sum (List.repeat 3 2)))
",
    );
    assert_accepted("repeat_int", &src, "6");
}

#[test]
fn repeat_fn_element_builds() {
    let src = program(
        "main : Task Error ()
main =
    Io.println (String.fromInt (List.sum (List.map (\\f -> f 1) (List.repeat 2 (\\x -> x + 1)))))
",
    );
    assert_accepted("repeat_fn_element", &src, "4");
}

#[test]
fn user_generic_concrete_instances_build() {
    let src = program(
        "ident : a -> a
ident x =
    x


main : Task Error ()
main =
    Io.println (String.fromInt (ident 3) ++ ident \"x\")
",
    );
    assert_accepted("user_generic_concrete_instances", &src, "3x");
}

#[test]
fn mapper_rewrite_builds() {
    let src = program(
        "main : Task Error ()
main =
    Task.map (\\_ -> ()) (Task.sequence (List.map (\\_ -> Io.println \"x\") (List.repeat 3 ())))
",
    );
    assert_accepted("mapper_rewrite", &src, "x\nx\nx");
}

/// One family of `Clone` carriers a program reaches through the shared prelude.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum CloneFamily {
    Int,
    Float,
    Bool,
    Str,
    Char,
    Unit,
    Order,
    Maybe,
    Result,
    List,
    Tuple,
    Record,
    Enum,
    Dict,
}

impl CloneFamily {
    /// Every family, each an entry of the `repeat_every_clone_carrier` fixture.
    const ALL: [Self; 14] = [
        Self::Int,
        Self::Float,
        Self::Bool,
        Self::Str,
        Self::Char,
        Self::Unit,
        Self::Order,
        Self::Maybe,
        Self::Result,
        Self::List,
        Self::Tuple,
        Self::Record,
        Self::Enum,
        Self::Dict,
    ];

    /// The Ipê values the fixture repeats for this family.
    const fn values(self) -> &'static [&'static str] {
        match self {
            Self::Int => &["1"],
            Self::Float => &["1.5"],
            Self::Bool => &["True"],
            Self::Str => &["\"s\""],
            Self::Char => &["'c'"],
            Self::Unit => &["()"],
            Self::Order => &["(compare 1 2)"],
            Self::Maybe => &["(Just 1)"],
            Self::Result => &["okOne"],
            Self::List => &["[ 1 ]"],
            Self::Tuple => &["( 1, \"t\" )"],
            Self::Record => &["{ n = 1 }"],
            Self::Enum => &["(Dark 1)", "Light"],
            Self::Dict => &["(Dict.fromList [ ( \"k\", 1 ) ])"],
        }
    }

    /// A lowered type of this family; `name` is the record field and the union name.
    fn sample(self, name: ipe_intern::Symbol) -> ipe_ir::IrType {
        use ipe_ir::IrType;
        match self {
            Self::Int => IrType::Int,
            Self::Float => IrType::Float,
            Self::Bool => IrType::Bool,
            Self::Str => IrType::Str,
            Self::Char => IrType::Char,
            Self::Unit => IrType::Unit,
            Self::Order => IrType::Order,
            Self::Maybe => IrType::Maybe(Box::new(IrType::Int)),
            Self::Result => IrType::Result(Box::new(IrType::Str), Box::new(IrType::Int)),
            Self::List => IrType::List(Box::new(IrType::Int)),
            Self::Tuple => IrType::Tuple(vec![IrType::Int, IrType::Str]),
            Self::Record => IrType::Record(std::iter::once((name, IrType::Int)).collect()),
            Self::Enum => IrType::Enum {
                home: ipe_ir::ModPath(vec![name]),
                name,
                args: Vec::new(),
            },
            Self::Dict => IrType::Dict(Box::new(IrType::Str), Box::new(IrType::Int)),
        }
    }
}

/// The prelude family of a lowered type, `None` when it is not `Clone` or the
/// fixture's imports cannot reach it.
///
/// Exhaustive over [`ipe_ir::IrType`]: a new variant does not compile here
/// until it is placed in a family or named as out of reach.
const fn clone_family(ty: &ipe_ir::IrType) -> Option<CloneFamily> {
    use ipe_ir::IrType;
    match ty {
        IrType::Int => Some(CloneFamily::Int),
        IrType::Float => Some(CloneFamily::Float),
        IrType::Bool => Some(CloneFamily::Bool),
        IrType::Str => Some(CloneFamily::Str),
        IrType::Char => Some(CloneFamily::Char),
        IrType::Unit => Some(CloneFamily::Unit),
        IrType::Order => Some(CloneFamily::Order),
        IrType::Maybe(_) => Some(CloneFamily::Maybe),
        IrType::Result(_, _) => Some(CloneFamily::Result),
        IrType::List(_) => Some(CloneFamily::List),
        IrType::Tuple(_) => Some(CloneFamily::Tuple),
        IrType::Record(_) => Some(CloneFamily::Record),
        IrType::Enum { .. } => Some(CloneFamily::Enum),
        IrType::Dict(_, _) => Some(CloneFamily::Dict),
        // Not `Clone` on the default carrier: the IPE-L0164 cases above.
        IrType::Task(_)
        | IrType::Cmd(_)
        | IrType::Sub(_)
        | IrType::Fun(_, _)
        | IrType::FnOnceChain(_, _)
        | IrType::WebApp
        | IrType::TuiApp
        | IrType::CliApp
        | IrType::WorkerApp
        // A generic belongs to the referencing function: forwarded, never an instance.
        | IrType::Generic(_)
        | IrType::RowGeneric(_)
        // A promoted function carrier is a lowering choice, not a written value.
        | IrType::SharedFun(_, _)
        // Reached only through a module or an application shape the prelude
        // does not import.
        | IrType::Set(_)
        | IrType::Bytes
        | IrType::Json
        | IrType::Decoder(_)
        | IrType::Db
        | IrType::ServerRequest
        | IrType::ServerResponse
        | IrType::ServerRoute
        | IrType::ServerCookie
        | IrType::StreamWriter
        | IrType::HttpRequest
        | IrType::WebSocketServer
        | IrType::WebSocketServerCfg
        | IrType::Ui { .. }
        | IrType::UiPlain(_)
        | IrType::WebReq
        | IrType::SessionHandle
        | IrType::WebRoute(_)
        | IrType::CustomElement { .. }
        | IrType::BackoffStrategy
        | IrType::HttpMethod
        | IrType::Decimal
        | IrType::Principal
        | IrType::AuthConfig
        | IrType::TokenSource
        | IrType::ErrorKind
        | IrType::Error
        | IrType::ErrorDetails
        | IrType::ErrorInfo
        | IrType::PanicInfo
        | IrType::TypeInfo
        | IrType::SqlFragment
        | IrType::Secret
        | IrType::Path
        | IrType::Regex
        | IrType::ProcessRunWithCfg
        | IrType::ProcessRunInPtyCfg
        | IrType::CacheCfg
        | IrType::CacheStats
        | IrType::WebSocketClientCfg
        | IrType::CsvDoc
        | IrType::EmailMessage
        | IrType::EmailAttachment
        | IrType::EmailSesConfig
        | IrType::EmailSmtpConfig
        | IrType::EmailProvider
        | IrType::CryptoKey
        | IrType::CryptoMac
        | IrType::EmailAddress
        | IrType::Url
        | IrType::UrlRelative
        | IrType::Dsn
        | IrType::DbLocation
        | IrType::Connection
        | IrType::ConnReadOnly
        | IrType::ConnReadWrite
        | IrType::Setting
        | IrType::ShapeWeb
        | IrType::ShapeWebView
        | IrType::ShapeTerminal
        | IrType::Locale => None,
    }
}

/// Every prelude family is a `Clone` carrier and names itself back.
#[test]
fn every_clone_family_is_a_clone_carrier() {
    let mut interner = ipe_intern::Interner::new();
    let name = interner.intern("n");
    assert!(name.is_ok(), "interning a one-letter name");
    if let Ok(name) = name {
        let payloads = ipe_ir::EnumPayloadTable::new();
        for family in CloneFamily::ALL {
            let sample = family.sample(name);
            assert_eq!(
                clone_family(&sample),
                Some(family),
                "{family:?} round-trips"
            );
            assert!(
                ipe_ir::carrier_is_clone(&sample, &payloads),
                "{family:?} is a Clone carrier"
            );
            assert!(
                !family.values().is_empty(),
                "{family:?} has a value in the fixture"
            );
        }
    }
}

/// The `repeat_every_clone_carrier` source, one `List.repeat 2` per family value, and its total length.
fn every_clone_carrier_program() -> (String, usize) {
    let values: Vec<&str> = CloneFamily::ALL
        .into_iter()
        .flat_map(|family| family.values().iter().copied())
        .collect();
    let entries: Vec<String> = values
        .iter()
        .map(|value| format!("List.length (List.repeat 2 {value})"))
        .collect();
    let body = format!(
        "okOne : Result String Int
okOne =
    Ok 1


type Shade
    = Light
    | Dark Int


main : Task Error ()
main =
    let
        lengths =
            [ {}
            ]
    in
    Io.println (String.fromInt (List.sum lengths))
",
        entries.join("\n            , ")
    );
    (program(&body), values.len() * 2)
}

/// Every prelude family repeats, builds and runs: no over-refusal of a `Clone` carrier.
#[test]
fn repeat_every_clone_carrier_builds() {
    let (src, total) = every_clone_carrier_program();
    for family in CloneFamily::ALL {
        for value in family.values() {
            assert!(
                src.contains(&format!("List.repeat 2 {value})")),
                "{family:?} has a fixture entry"
            );
        }
    }
    assert_accepted("repeat_every_clone_carrier", &src, &total.to_string());
}
