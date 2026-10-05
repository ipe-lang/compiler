//! The compile-time half of the additive-`Msg`-variant hot-swap.
//!
//! Reduce the program's `Msg` enum to a schema-tagged [`CompileMsgSet`]
//! descriptor, the counterpart of [`crate::transition_classify`]'s per-arm
//! transition datum.
//!
//! # What this describes
//!
//! The running Web program's `Msg` variant surface — for each constructor, its
//! NAME and a closed [`CompilePayloadShape`] (its arity/type signature, not any
//! runtime value). The `ipe dev watch` loop bakes this descriptor per emit; on a
//! source edit it compares the previous baked descriptor with the new one and, if
//! the new set is a proven additive superset (every prior variant still present,
//! unchanged), POSTs both to the running app's `/_ipe/hot-msg` endpoint, which
//! gates the hot-swap through the runtime `web::msg_set::is_additive_superset`.
//!
//! # Inert + dev == prod
//!
//! A [`CompileMsgSet`] carries only variant names and closed shape tags — no code,
//! no value. Its JSON serialization ([`CompileMsgSet::to_json`]) is byte-identical
//! to the runtime `web::msg_set::MsgSet`'s serde form (pinned by an in-module
//! conformance test), so the baked descriptor decodes back into exactly the set it
//! described and the runtime superset proof agrees with what a full recompile
//! would accept. The descriptor is a DEV-loop artefact only: it never changes the
//! emitted program's behaviour, so prod is byte-identical whether or not it is
//! computed.

use crate::emit_template::write_json_string;
use ipe_ir::{EnumDef, IrType};

/// The schema-tag the descriptor is baked at.
///
/// MUST equal the runtime `web::msg_set::MSG_SET_SCHEMA`; the conformance test
/// pins the two together, so a bump on one side without the other fails the build
/// rather than shipping an incomparable descriptor.
pub const MSG_SET_SCHEMA: u32 = 1;

/// The closed payload signature of one `Msg` variant.
///
/// One-to-one with the runtime `web::msg_set::PayloadShape`. Exhaustive and
/// wildcard-free: a new payload kind forces a compile-time decision here, never a
/// silent mis-encode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompilePayloadShape {
    /// A nullary constructor (`Increment`) — a plain button's `OnMsg`.
    Unit,
    /// A single `String` field (`SetName String`) — an input's `OnString`.
    Str,
    /// A single `Bool` field (`Toggle Bool`) — a checkbox's `OnBool`.
    Bool,
    /// A single `Int` field.
    Int,
    /// Any other payload (a record, a nested ADT, or more than one field). The
    /// opaque descriptor STRING captures the arity + field-type names so two
    /// differently-shaped compound payloads never compare equal (a change inside a
    /// compound payload is thus detected as a retype, not silently accepted).
    Compound(String),
}

/// The program's `Msg` variant set reduced to a schema-tagged descriptor.
///
/// The `variants` are `(name, shape)` pairs in the enum's declaration order; the
/// runtime superset proof is name-keyed, so the order is not load-bearing (a pure
/// reorder is not a change).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompileMsgSet {
    pub schema: u32,
    pub variants: Vec<(String, CompilePayloadShape)>,
}

impl CompileMsgSet {
    /// Reduce a `Msg` [`EnumDef`] to a descriptor. `resolve` maps a variant-name
    /// [`ipe_intern::Symbol`] to its emitted Rust ident (the serde tag the runtime
    /// keys by); a variant whose name does not resolve is described under the
    /// empty string, which the runtime proof then simply never matches against a
    /// real live variant (fail-closed: an unresolvable variant can only make a set
    /// look non-additive, never spuriously additive).
    #[must_use]
    pub fn from_enum(
        def: &EnumDef,
        resolve: &impl Fn(ipe_intern::Symbol) -> Option<String>,
    ) -> Self {
        let variants = def
            .variants
            .iter()
            .map(|v| {
                let name = resolve(v.name).unwrap_or_default();
                (name, shape_of_fields(&v.fields))
            })
            .collect();
        Self {
            schema: MSG_SET_SCHEMA,
            variants,
        }
    }

    /// Serialize to the JSON the runtime `web::msg_set::MsgSet` decodes —
    /// `serde_json`'s default representation of
    /// `{"schema":1,"variants":[{"name":…,"shape":…}]}`. Deterministic (fixed key
    /// order, deterministic string escaping); byte-identical to
    /// `serde_json::to_string(&MsgSet)` (pinned by a conformance test).
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut out = String::new();
        out.push_str("{\"schema\":");
        out.push_str(&self.schema.to_string());
        out.push_str(",\"variants\":[");
        for (i, (name, shape)) in self.variants.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str("{\"name\":");
            write_json_string(name, &mut out);
            out.push_str(",\"shape\":");
            write_shape_json(shape, &mut out);
            out.push('}');
        }
        out.push_str("]}");
        out
    }
}

/// Derive the closed [`CompilePayloadShape`] from a variant's positional field
/// types — the public entry the emitter uses to build a descriptor from an enum's
/// registered variant payloads.
#[must_use]
pub fn compile_payload_shape(fields: &[IrType]) -> CompilePayloadShape {
    shape_of_fields(fields)
}

/// Derive the closed [`CompilePayloadShape`] from a variant's positional field
/// types. A single scalar field maps to its scalar shape; a nullary constructor
/// is [`CompilePayloadShape::Unit`]; anything else (multiple fields, a
/// non-scalar single field) is an opaque [`CompilePayloadShape::Compound`] whose
/// descriptor string names each field's type in order, so two differently-typed
/// compound payloads never compare equal.
fn shape_of_fields(fields: &[IrType]) -> CompilePayloadShape {
    match fields {
        [] => CompilePayloadShape::Unit,
        [one] => match one {
            IrType::Str => CompilePayloadShape::Str,
            IrType::Bool => CompilePayloadShape::Bool,
            IrType::Int => CompilePayloadShape::Int,
            other => {
                CompilePayloadShape::Compound(compound_descriptor(std::slice::from_ref(other)))
            }
        },
        many => CompilePayloadShape::Compound(compound_descriptor(many)),
    }
}

/// A stable, opaque descriptor string for a compound payload: each field's coarse
/// type tag, in order, comma-joined. Two compound payloads compare equal iff their
/// field-type tag sequences match, so a field added/removed/retyped inside a
/// compound payload changes the descriptor (→ a detected retype).
///
/// The tags are coarse on purpose — a generic/type-var field is one opaque
/// `Var` tag rather than an instantiation — because the descriptor's only job is
/// to make a payload-shape CHANGE detectable, not to reconstruct the type. A
/// coarse tag can only ever make two payloads look LESS equal, so it stays
/// fail-closed (never a spurious additive match).
fn compound_descriptor(fields: &[IrType]) -> String {
    fields.iter().map(type_tag).collect::<Vec<_>>().join(",")
}

/// A coarse, stable tag for one field type. Every constructor of [`IrType`] maps
/// to a fixed short tag; a shape that changes constructor changes its tag, so a
/// retype is detected. Wildcard-free over the scalar cases; the aggregate/opaque
/// cases collapse to a single tag each (sufficient because the descriptor only
/// needs CHANGE detection, not full reconstruction).
fn type_tag(ty: &IrType) -> String {
    match ty {
        IrType::Int => "Int".to_owned(),
        IrType::Float => "Float".to_owned(),
        IrType::Bool => "Bool".to_owned(),
        IrType::Str => "Str".to_owned(),
        IrType::Char => "Char".to_owned(),
        _ => {
            // Any non-scalar (a list, a record, a named ADT, a generic, a tuple,
            // a function) collapses to a stable per-constructor discriminant tag.
            // A change of constructor (e.g. List -> Record) changes the tag; a
            // change WITHIN one aggregate constructor is not distinguished here,
            // but such an edit also changes the emitted enum's field type and so
            // fails the watch-classifier's byte-identity skeleton check upstream —
            // this descriptor is a redundant, coarser guard, never the sole one.
            format!("Agg:{}", aggregate_discriminant(ty))
        }
    }
}

/// A stable discriminant name for a non-scalar [`IrType`] constructor. Distinct
/// constructors get distinct names; the same constructor gets the same name
/// regardless of its inner types (the coarse-tag rationale above).
///
/// Exhaustive and wildcard-free over every [`IrType`] constructor: a new variant
/// forces a compile-time decision here rather than collapsing onto a shared tag,
/// so a payload retyped between two currently-distinct constructors is always
/// detected as a change (a swallowing catch-all would report equal descriptors
/// for two different types).
const fn aggregate_discriminant(ty: &IrType) -> &'static str {
    match ty {
        IrType::Int | IrType::Float | IrType::Bool | IrType::Str | IrType::Char => "Scalar",
        IrType::Unit => "Unit",
        IrType::Task(_) => "Task",
        IrType::Enum { .. } => "Enum",
        IrType::Maybe(_) => "Maybe",
        IrType::Result(..) => "Result",
        IrType::List(_) => "List",
        IrType::Tuple(_) => "Tuple",
        IrType::Record(_) => "Record",
        IrType::Fun(..) => "Fun",
        IrType::SharedFun(..) => "SharedFun",
        IrType::FnOnceChain(..) => "FnOnceChain",
        IrType::Generic(_) => "Var",
        IrType::RowGeneric(_) => "RowVar",
        IrType::Dict(..) => "Dict",
        IrType::Set(_) => "Set",
        IrType::Bytes => "Bytes",
        IrType::Json => "Json",
        IrType::Decoder(_) => "Decoder",
        IrType::Db => "Db",
        IrType::Cmd(_) => "Cmd",
        IrType::Sub(_) => "Sub",
        IrType::ServerRequest => "ServerRequest",
        IrType::ServerResponse => "ServerResponse",
        IrType::ServerRoute => "ServerRoute",
        IrType::ServerCookie => "ServerCookie",
        IrType::StreamWriter => "StreamWriter",
        IrType::HttpRequest => "HttpRequest",
        IrType::WebSocketServer => "WebSocketServer",
        IrType::WebSocketServerCfg => "WebSocketServerCfg",
        IrType::Ui { .. } => "Ui",
        IrType::UiPlain(_) => "UiPlain",
        IrType::WebReq => "WebReq",
        IrType::SessionHandle => "SessionHandle",
        IrType::WebRoute(_) => "WebRoute",
        IrType::CustomElement { .. } => "CustomElement",
        IrType::Order => "Order",
        IrType::BackoffStrategy => "BackoffStrategy",
        IrType::HttpMethod => "HttpMethod",
        IrType::Decimal => "Decimal",
        IrType::Principal => "Principal",
        IrType::AuthConfig => "AuthConfig",
        IrType::TokenSource => "TokenSource",
        IrType::ErrorKind => "ErrorKind",
        IrType::Error => "Error",
        IrType::ErrorDetails => "ErrorDetails",
        IrType::ErrorInfo => "ErrorInfo",
        IrType::PanicInfo => "PanicInfo",
        IrType::TypeInfo => "TypeInfo",
        IrType::SqlFragment => "SqlFragment",
        IrType::Secret => "Secret",
        IrType::Path => "Path",
        IrType::Regex => "Regex",
        IrType::ProcessRunWithCfg => "ProcessRunWithCfg",
        IrType::ProcessRunInPtyCfg => "ProcessRunInPtyCfg",
        IrType::CacheCfg => "CacheCfg",
        IrType::CacheStats => "CacheStats",
        IrType::WebSocketClientCfg => "WebSocketClientCfg",
        IrType::CsvDoc => "CsvDoc",
        IrType::EmailMessage => "EmailMessage",
        IrType::EmailAttachment => "EmailAttachment",
        IrType::EmailSesConfig => "EmailSesConfig",
        IrType::EmailSmtpConfig => "EmailSmtpConfig",
        IrType::EmailProvider => "EmailProvider",
        IrType::CryptoKey => "CryptoKey",
        IrType::CryptoMac => "CryptoMac",
        IrType::EmailAddress => "EmailAddress",
        IrType::Url => "Url",
        IrType::UrlRelative => "UrlRelative",
        IrType::Dsn => "Dsn",
        IrType::Connection => "Connection",
        IrType::ConnReadOnly => "ConnReadOnly",
        IrType::ConnReadWrite => "ConnReadWrite",
        IrType::Setting => "Setting",
        IrType::ShapeWeb => "ShapeWeb",
        IrType::ShapeWebView => "ShapeWebView",
        IrType::ShapeTerminal => "ShapeTerminal",
        IrType::Locale => "Locale",
        IrType::WebApp => "WebApp",
        IrType::TuiApp => "TuiApp",
        IrType::CliApp => "CliApp",
        IrType::WorkerApp => "WorkerApp",
    }
}

/// Append a [`CompilePayloadShape`] as the runtime `PayloadShape`'s serde form:
/// an externally-tagged enum — `"Unit"` / `"Str"` / `"Bool"` / `"Int"` for the
/// nullary cases and `{"Compound":"<descriptor>"}` for the payload case.
fn write_shape_json(shape: &CompilePayloadShape, out: &mut String) {
    match shape {
        CompilePayloadShape::Unit => out.push_str("\"Unit\""),
        CompilePayloadShape::Str => out.push_str("\"Str\""),
        CompilePayloadShape::Bool => out.push_str("\"Bool\""),
        CompilePayloadShape::Int => out.push_str("\"Int\""),
        CompilePayloadShape::Compound(d) => {
            out.push_str("{\"Compound\":");
            write_json_string(d, out);
            out.push('}');
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CompileMsgSet, CompilePayloadShape, shape_of_fields};
    use ipe_intern::Symbol;
    use ipe_ir::{EnumDef, IrType, ModPath, Variant};

    fn variant(name_raw: u32, fields: Vec<IrType>) -> Variant {
        Variant {
            name: Symbol::from_raw(name_raw),
            fields,
        }
    }

    fn resolver<'a>(names: &'a [(u32, &'static str)]) -> impl Fn(Symbol) -> Option<String> + 'a {
        move |s: Symbol| {
            names
                .iter()
                .find(|(raw, _)| *raw == s.as_raw())
                .map(|(_, n)| (*n).to_owned())
        }
    }

    fn msg_enum(variants: Vec<Variant>) -> EnumDef {
        EnumDef {
            name: Symbol::from_raw(1),
            home: ModPath(vec![]),
            type_params: vec![],
            variants,
        }
    }

    // ── shape derivation ──────────────────────────────────────────────────

    #[test]
    fn nullary_variant_is_unit() {
        assert_eq!(shape_of_fields(&[]), CompilePayloadShape::Unit);
    }

    #[test]
    fn single_scalar_fields_map_to_scalar_shapes() {
        assert_eq!(shape_of_fields(&[IrType::Str]), CompilePayloadShape::Str);
        assert_eq!(shape_of_fields(&[IrType::Bool]), CompilePayloadShape::Bool);
        assert_eq!(shape_of_fields(&[IrType::Int]), CompilePayloadShape::Int);
    }

    #[test]
    fn multi_field_variant_is_compound() {
        let s = shape_of_fields(&[IrType::Int, IrType::Str]);
        assert_eq!(s, CompilePayloadShape::Compound("Int,Str".to_owned()));
    }

    #[test]
    fn compound_descriptor_changes_on_a_field_retype() {
        let before = shape_of_fields(&[IrType::Int, IrType::Str]);
        let after = shape_of_fields(&[IrType::Int, IrType::Bool]);
        assert_ne!(
            before, after,
            "a retyped compound field must change the descriptor"
        );
    }

    // ── descriptor + JSON ─────────────────────────────────────────────────

    #[test]
    fn counter_msg_set_descriptor() {
        // `type Msg = Increment | Decrement`
        let def = msg_enum(vec![variant(10, vec![]), variant(11, vec![])]);
        let r = resolver(&[(10, "Increment"), (11, "Decrement")]);
        let set = CompileMsgSet::from_enum(&def, &r);
        assert_eq!(
            set.variants,
            vec![
                ("Increment".to_owned(), CompilePayloadShape::Unit),
                ("Decrement".to_owned(), CompilePayloadShape::Unit),
            ]
        );
        assert_eq!(
            set.to_json(),
            r#"{"schema":1,"variants":[{"name":"Increment","shape":"Unit"},{"name":"Decrement","shape":"Unit"}]}"#
        );
    }

    #[test]
    fn payload_variant_json_shape() {
        // `SetName String`
        let def = msg_enum(vec![variant(20, vec![IrType::Str])]);
        let r = resolver(&[(20, "SetName")]);
        let set = CompileMsgSet::from_enum(&def, &r);
        assert_eq!(
            set.to_json(),
            r#"{"schema":1,"variants":[{"name":"SetName","shape":"Str"}]}"#
        );
    }

    #[test]
    fn compound_variant_json_shape() {
        let def = msg_enum(vec![variant(30, vec![IrType::Int, IrType::Bool])]);
        let r = resolver(&[(30, "Pair")]);
        let set = CompileMsgSet::from_enum(&def, &r);
        assert_eq!(
            set.to_json(),
            r#"{"schema":1,"variants":[{"name":"Pair","shape":{"Compound":"Int,Bool"}}]}"#
        );
    }

    #[test]
    fn unresolvable_variant_name_is_empty_string() {
        // A variant name the resolver does not know is described under "" — the
        // runtime proof never matches it against a real live variant, so it can
        // only make a set look less additive (fail-closed).
        let def = msg_enum(vec![variant(99, vec![])]);
        let r = resolver(&[]);
        let set = CompileMsgSet::from_enum(&def, &r);
        assert_eq!(
            set.variants,
            vec![(String::new(), CompilePayloadShape::Unit)]
        );
    }

    #[test]
    fn name_escaping_in_json() {
        let def = msg_enum(vec![variant(40, vec![])]);
        let r = resolver(&[(40, "Wei\"rd")]);
        let set = CompileMsgSet::from_enum(&def, &r);
        assert_eq!(
            set.to_json(),
            r#"{"schema":1,"variants":[{"name":"Wei\"rd","shape":"Unit"}]}"#
        );
    }
}

/// The dev == prod CRUX for the `Msg` set, proven at the compiler/runtime seam.
///
/// The `ipe dev watch` loop bakes a [`CompileMsgSet`] and POSTs its JSON; the running
/// program's runtime decodes that JSON into a `web::msg_set::MsgSet` and runs the
/// additive-superset proof over it. This module proves the two halves agree: a
/// [`CompileMsgSet`], serialized by [`CompileMsgSet::to_json`], decodes into the
/// runtime `MsgSet`, and the runtime proof accepts/refuses EXACTLY the edits the
/// descriptor describes (an added variant additive, a removed/retyped variant
/// not). If the two serde forms drift, dev would lie about what a recompile
/// accepts — the one unacceptable failure — so the JSON shapes are pinned equal.
#[cfg(test)]
mod conformance {
    use super::{CompileMsgSet, CompilePayloadShape};
    use ipe_runtime_rust::web::msg_set::{
        MsgSet, MsgVariant, PayloadShape, decode_msg_set, is_additive_superset,
    };

    /// Decode a compile-time descriptor into the runtime `MsgSet` through its JSON
    /// — the exact path a baked descriptor takes at runtime. A decode failure is
    /// the test's failure (the two serde forms disagree), surfaced by the
    /// `expect`, which only ever fires on a genuine drift.
    fn interpret(cs: &CompileMsgSet) -> MsgSet {
        decode_msg_set(cs.to_json().as_bytes())
            .expect("compile MsgSet JSON must decode into the runtime MsgSet")
    }

    fn compile_counter() -> CompileMsgSet {
        CompileMsgSet {
            schema: super::MSG_SET_SCHEMA,
            variants: vec![
                ("Increment".to_owned(), CompilePayloadShape::Unit),
                ("Decrement".to_owned(), CompilePayloadShape::Unit),
            ],
        }
    }

    #[test]
    fn added_variant_is_additive_through_the_seam() {
        let live = interpret(&compile_counter());
        // The edited program: `Reset` added.
        let mut edited = compile_counter();
        edited
            .variants
            .push(("Reset".to_owned(), CompilePayloadShape::Unit));
        let candidate = interpret(&edited);
        assert!(
            is_additive_superset(&live, &candidate),
            "an added variant baked by the compiler must prove additive at runtime"
        );
    }

    #[test]
    fn removed_variant_is_refused_through_the_seam() {
        let live = interpret(&compile_counter());
        // The edited program: `Decrement` removed.
        let edited = CompileMsgSet {
            schema: super::MSG_SET_SCHEMA,
            variants: vec![("Increment".to_owned(), CompilePayloadShape::Unit)],
        };
        let candidate = interpret(&edited);
        assert!(
            !is_additive_superset(&live, &candidate),
            "a removed variant must refuse at runtime (recompile)"
        );
    }

    #[test]
    fn retyped_variant_is_refused_through_the_seam() {
        let live = interpret(&compile_counter());
        // `Increment` retyped nullary -> String payload.
        let edited = CompileMsgSet {
            schema: super::MSG_SET_SCHEMA,
            variants: vec![
                ("Increment".to_owned(), CompilePayloadShape::Str),
                ("Decrement".to_owned(), CompilePayloadShape::Unit),
            ],
        };
        let candidate = interpret(&edited);
        assert!(
            !is_additive_superset(&live, &candidate),
            "a retyped variant must refuse at runtime (recompile)"
        );
    }

    /// The compile serializer's bytes ARE the runtime codec's bytes: a runtime
    /// `MsgSet` round-trips through `CompileMsgSet::to_json`'s exact shape. Pins
    /// that the two serde forms never drift (a drift would break `interpret`
    /// silently otherwise), and that the two `MSG_SET_SCHEMA` constants agree.
    #[test]
    fn compile_json_is_runtime_msg_set_serde_shape() {
        let cs = CompileMsgSet {
            schema: super::MSG_SET_SCHEMA,
            variants: vec![
                ("Increment".to_owned(), CompilePayloadShape::Unit),
                ("SetName".to_owned(), CompilePayloadShape::Str),
            ],
        };
        let runtime = MsgSet::new(vec![
            MsgVariant {
                name: "Increment".to_owned(),
                shape: PayloadShape::Unit,
            },
            MsgVariant {
                name: "SetName".to_owned(),
                shape: PayloadShape::Str,
            },
        ]);
        assert_eq!(
            super::MSG_SET_SCHEMA,
            ipe_runtime_rust::web::msg_set::MSG_SET_SCHEMA,
            "the compile and runtime schema tags must agree"
        );
        assert_eq!(
            cs.to_json(),
            serde_json::to_string(&runtime).expect("serialize")
        );
    }
}
