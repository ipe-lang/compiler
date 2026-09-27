//! The transparent-or-opaque representation decision — made ONCE, at decode.
//!
//! The inspector reports per-type structural FACTS (`types` in the inspection
//! document): member lists, the `#[non_exhaustive]` fact, and a hidden-members
//! fact. This module is the decode boundary that turns those facts into the
//! per-type representation classification of the FFI design's representation
//! axis: a type decodes **transparent** (a Rust struct surfaces as an Ipê
//! record, a Rust enum as an Ipê closed union) only when every fact
//! affirmatively qualifies — every member visible, every member type an exact
//! identity carrier, every name a validated identifier, the member set a
//! stable contract. Anything less keeps today's sound default: an **opaque**
//! nominal handle, with the disqualifying reason recorded for the coverage
//! ledger (over-drop is only honest when every drop names its reason).
//!
//! Fail-closed in both layers: the inspector reads detection failure as the
//! disqualifying fact, and this decode refuses any entry it cannot fully
//! validate — a forged or corrupted `types` entry can only ever produce an
//! opaque type, never an unsound transparent one.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::carrier::{Carrier, EnumDef, ScalarCarrier, StructDef};
use crate::naming::{IdentPath, RustIdent};

// ── wire layer ──────────────────────────────────────────────────────────────

/// One reported member on the wire: a struct field or a variant payload slot.
#[derive(Debug, Deserialize)]
pub(crate) struct WireTypeMember {
    #[serde(default)]
    name: String,
    #[serde(default, rename = "type")]
    ty: String,
    #[serde(default, rename = "rustType")]
    rust_type: String,
}

/// One reported enum variant on the wire.
#[derive(Debug, Deserialize)]
pub(crate) struct WireTypeVariant {
    #[serde(default)]
    name: String,
    #[serde(default)]
    kind: String,
    #[serde(default)]
    members: Vec<WireTypeMember>,
}

/// One reported foreign type's structural facts on the wire.
#[derive(Debug, Deserialize)]
pub(crate) struct WireForeignType {
    #[serde(default)]
    name: String,
    #[serde(default, rename = "rustPath")]
    rust_path: String,
    #[serde(default)]
    kind: String,
    #[serde(default, rename = "nonExhaustive")]
    non_exhaustive: bool,
    #[serde(default, rename = "hiddenMembers")]
    hidden_members: bool,
    #[serde(default)]
    fields: Vec<WireTypeMember>,
    #[serde(default)]
    variants: Vec<WireTypeVariant>,
}

// ── domain layer ────────────────────────────────────────────────────────────

/// A named member of a transparent foreign type: the Rust field name (also
/// the Ipê record field name) and its identity carrier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForeignMember {
    /// The validated member name.
    pub name: RustIdent,
    /// The member's scalar carrier — identical spelling on both sides of the
    /// boundary, so conversion glue is a total field-for-field move.
    pub carrier: ScalarCarrier,
}

/// The payload of one transparent enum variant.
///
/// Unit variants carry nothing, tuple variants carry positional carriers,
/// struct variants named members — a members-on-unit or names-on-tuple
/// confusion is unrepresentable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForeignVariantPayload {
    /// No payload.
    Unit,
    /// Positional payload carriers, in declaration order.
    Tuple(Vec<ScalarCarrier>),
    /// Named payload members, in declaration order.
    Struct(Vec<ForeignMember>),
}

/// One variant of a transparent foreign enum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForeignVariant {
    /// The validated, capitalized variant name (also the Ipê union ctor).
    pub name: RustIdent,
    /// The validated payload shape.
    pub payload: ForeignVariantPayload,
}

/// A foreign type that decoded transparent — the Ipê program sees its
/// structure instead of holding a sealed handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransparentType {
    /// A named-field Rust struct surfacing as an Ipê record.
    Struct {
        /// The validated, capitalized Ipê-visible nominal.
        name: RustIdent,
        /// The validated Rust path the conversion glue references.
        rust_path: IdentPath,
        /// The full field set, in declaration order.
        fields: Vec<ForeignMember>,
    },
    /// A Rust enum surfacing as an Ipê closed union, exhaustiveness intact.
    Enum {
        /// The validated, capitalized Ipê-visible nominal.
        name: RustIdent,
        /// The validated Rust path the conversion glue references.
        rust_path: IdentPath,
        /// The full variant set, in declaration order.
        variants: Vec<ForeignVariant>,
    },
}

impl TransparentType {
    /// The Ipê-visible nominal.
    #[must_use]
    pub const fn name(&self) -> &RustIdent {
        match self {
            Self::Struct { name, .. } | Self::Enum { name, .. } => name,
        }
    }

    /// The validated Rust path the conversion glue references.
    #[must_use]
    pub const fn rust_path(&self) -> &IdentPath {
        match self {
            Self::Struct { rust_path, .. } | Self::Enum { rust_path, .. } => rust_path,
        }
    }

    /// Decode one entry of the `transparentTypes` projection
    /// ([`crate::emit::transparent_type_json`]) back through the SAME
    /// validating newtypes the classification uses — a hand-edited projection
    /// can only yield a well-formed shape or a refusal, never an unvalidated
    /// name reaching emitted code.
    ///
    /// # Errors
    ///
    /// A message naming the malformed field.
    pub fn from_projection_json(v: &serde_json::Value) -> Result<Self, String> {
        let str_field = |key: &str| -> Result<&str, String> {
            v.get(key)
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| format!("transparent type entry missing string `{key}`"))
        };
        let name = RustIdent::parse(str_field("name")?)
            .map_err(|_| "transparent type name is not a legal identifier".to_owned())?;
        let rust_path = IdentPath::parse(str_field("rustPath")?)
            .map_err(|_| "transparent type rustPath is not a legal identifier path".to_owned())?;
        let member = |m: &serde_json::Value| -> Result<ForeignMember, String> {
            let get = |key: &str| -> Result<&str, String> {
                m.get(key)
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| format!("transparent member missing string `{key}`"))
            };
            let name = RustIdent::parse(get("name")?)
                .map_err(|_| "transparent member name is not a legal identifier".to_owned())?;
            let carrier = carrier_from_surface(get("carrier")?)?;
            Ok(ForeignMember { name, carrier })
        };
        let members = |key: &str, of: &serde_json::Value| -> Result<Vec<ForeignMember>, String> {
            of.get(key)
                .and_then(serde_json::Value::as_array)
                .ok_or_else(|| format!("transparent type entry missing array `{key}`"))?
                .iter()
                .map(member)
                .collect()
        };
        match str_field("kind")? {
            "struct" => Ok(Self::Struct {
                name,
                rust_path,
                fields: members("fields", v)?,
            }),
            "enum" => {
                let variants = v
                    .get("variants")
                    .and_then(serde_json::Value::as_array)
                    .ok_or_else(|| "transparent enum entry missing array `variants`".to_owned())?
                    .iter()
                    .map(|entry| -> Result<ForeignVariant, String> {
                        let get = |key: &str| -> Result<&str, String> {
                            entry
                                .get(key)
                                .and_then(serde_json::Value::as_str)
                                .ok_or_else(|| {
                                    format!("transparent variant missing string `{key}`")
                                })
                        };
                        let name = RustIdent::parse(get("name")?).map_err(|_| {
                            "transparent variant name is not a legal identifier".to_owned()
                        })?;
                        let payload = match get("kind")? {
                            "unit" => ForeignVariantPayload::Unit,
                            "tuple" => ForeignVariantPayload::Tuple(
                                entry
                                    .get("carriers")
                                    .and_then(serde_json::Value::as_array)
                                    .ok_or_else(|| {
                                        "tuple variant missing array `carriers`".to_owned()
                                    })?
                                    .iter()
                                    .map(|c| {
                                        c.as_str()
                                            .ok_or_else(|| {
                                                "tuple carrier is not a string".to_owned()
                                            })
                                            .and_then(carrier_from_surface)
                                    })
                                    .collect::<Result<Vec<_>, _>>()?,
                            ),
                            "struct" => ForeignVariantPayload::Struct(members("members", entry)?),
                            other => return Err(format!("unknown variant kind {other:?}")),
                        };
                        Ok(ForeignVariant { name, payload })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(Self::Enum {
                    name,
                    rust_path,
                    variants,
                })
            }
            other => Err(format!("unknown transparent type kind {other:?}")),
        }
    }
}

/// The [`ScalarCarrier`] for a stored Ipê carrier surface, refusing anything
/// outside the closed identity set.
fn carrier_from_surface(s: &str) -> Result<ScalarCarrier, String> {
    match s {
        "Int" => Ok(ScalarCarrier::Int),
        "Float" => Ok(ScalarCarrier::Float),
        "Bool" => Ok(ScalarCarrier::Bool),
        "Char" => Ok(ScalarCarrier::Char),
        "String" => Ok(ScalarCarrier::Str),
        other => Err(format!(
            "carrier {other:?} is outside the identity carrier set"
        )),
    }
}

/// One coverage row for a reported type that stays opaque: the nominal and
/// the disqualifying fact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpaqueTypeReason {
    /// The Ipê-visible nominal as reported (unvalidated — display only).
    pub name: String,
    /// Why the type stays an opaque handle.
    pub reason: String,
}

/// The decoded representation axis for one package: which reported types
/// surface transparently, and why each remaining reported type stays opaque.
///
/// A type the inspector reported nothing for appears in neither list — it is
/// opaque by default and was never a candidate.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ForeignTypeCatalog {
    transparent: BTreeMap<String, TransparentType>,
    opaque: Vec<OpaqueTypeReason>,
}

impl ForeignTypeCatalog {
    /// The types that decoded transparent, keyed by Ipê-visible nominal.
    #[must_use]
    pub const fn transparent(&self) -> &BTreeMap<String, TransparentType> {
        &self.transparent
    }

    /// The reported types that stay opaque, each with its reason.
    #[must_use]
    pub fn opaque_reasons(&self) -> &[OpaqueTypeReason] {
        &self.opaque
    }

    /// Classify every reported type. Per-entry failure is never a package
    /// failure: the entry falls back to opaque with its reason recorded.
    pub(crate) fn classify(wire: &[WireForeignType]) -> Self {
        let mut transparent: BTreeMap<String, TransparentType> = BTreeMap::new();
        let mut opaque: Vec<OpaqueTypeReason> = Vec::new();
        // Two entries claiming one nominal are ambiguous — neither may
        // surface structure under that name.
        let mut duplicated: Vec<String> = Vec::new();
        for w in wire {
            match classify_one(w) {
                Ok(t) => {
                    let key = t.name().as_str().to_owned();
                    if transparent.insert(key.clone(), t).is_some() {
                        duplicated.push(key);
                    }
                }
                Err(reason) => opaque.push(OpaqueTypeReason {
                    name: w.name.clone(),
                    reason,
                }),
            }
        }
        for name in duplicated {
            transparent.remove(&name);
            opaque.push(OpaqueTypeReason {
                reason: format!("two reported types claim the nominal `{name}`"),
                name,
            });
        }
        // The MIXED collision poisons too: a nominal claimed by one
        // transparent entry and one refused-to-opaque entry (two same-leaf
        // types from different modules, one qualifying) is the same Ipê-side
        // ambiguity — the record and the opaque handle would share a name.
        let mixed: Vec<String> = transparent
            .keys()
            .filter(|k| opaque.iter().any(|r| &r.name == *k))
            .cloned()
            .collect();
        for name in mixed {
            transparent.remove(&name);
            opaque.push(OpaqueTypeReason {
                reason: format!(
                    "the nominal `{name}` is also claimed by a non-transparent reported type"
                ),
                name,
            });
        }
        Self {
            transparent,
            opaque,
        }
    }
}

/// The identity-carrier pairs a transparent member may cross with: the Ipê
/// spelling and the Rust spelling must BOTH match one closed pair, so the
/// record surface and the conversion glue agree by construction and no
/// coercion (saturating, narrowing, or otherwise) ever hides inside a
/// transparent member.
fn member_carrier(ipe: &str, rust: &str) -> Option<ScalarCarrier> {
    match (ipe, rust) {
        ("Int", "i64") => Some(ScalarCarrier::Int),
        ("Float", "f64") => Some(ScalarCarrier::Float),
        ("Bool", "bool") => Some(ScalarCarrier::Bool),
        ("Char", "char") => Some(ScalarCarrier::Char),
        ("String", "String") => Some(ScalarCarrier::Str),
        _ => None,
    }
}

/// `true` when `name` can never be a member name.
///
/// Refuses every Rust keyword (a rendered `value.match` would not parse) and
/// every Ipê keyword (the lexer's own table — the record field would not parse
/// Ipê-side). [`RustIdent`] checks charset only, so the keyword gate lives here
/// at the classification.
fn is_reserved_member_name(name: &str) -> bool {
    ipe_intern::is_rust_keyword(name) || ipe_parse::is_keyword(name)
}

/// Validate one named member (a struct field or a struct-variant member).
fn named_member(context: &str, m: &WireTypeMember) -> Result<ForeignMember, String> {
    let name = RustIdent::parse(&m.name).map_err(|_| {
        format!(
            "{context} member name {:?} is not a legal identifier",
            m.name
        )
    })?;
    if !name.as_str().starts_with(|c: char| c.is_ascii_lowercase()) {
        return Err(format!(
            "{context} member `{name}` is not lowercase-led (required of an Ipê record field)"
        ));
    }
    if is_reserved_member_name(name.as_str()) {
        return Err(format!("{context} member `{name}` is a reserved keyword"));
    }
    let carrier = member_carrier(&m.ty, &m.rust_type).ok_or_else(|| {
        format!(
            "{context} member `{name}` type ({}, {}) is outside the identity carrier set",
            m.ty, m.rust_type
        )
    })?;
    Ok(ForeignMember { name, carrier })
}

/// Validate one enum variant against its declared kind.
fn variant(v: &WireTypeVariant) -> Result<ForeignVariant, String> {
    let name = RustIdent::parse(&v.name)
        .map_err(|_| format!("variant name {:?} is not a legal identifier", v.name))?;
    if !name.as_str().starts_with(|c: char| c.is_ascii_uppercase()) {
        return Err(format!(
            "variant `{name}` is not capitalized (required of an Ipê union constructor)"
        ));
    }
    let context = format!("variant `{name}`");
    let payload = match v.kind.as_str() {
        "unit" => {
            if !v.members.is_empty() {
                return Err(format!("{context} is unit-kind but reports members"));
            }
            ForeignVariantPayload::Unit
        }
        "tuple" => {
            let mut carriers = Vec::with_capacity(v.members.len());
            for (i, m) in v.members.iter().enumerate() {
                // A tuple slot's reported name is its decimal position; a
                // mismatch means the member list is not in declaration order.
                if m.name != i.to_string() {
                    return Err(format!("{context} tuple slot {i} is misnamed {:?}", m.name));
                }
                let carrier = member_carrier(&m.ty, &m.rust_type).ok_or_else(|| {
                    format!(
                        "{context} slot {i} type ({}, {}) is outside the identity carrier set",
                        m.ty, m.rust_type
                    )
                })?;
                carriers.push(carrier);
            }
            if carriers.is_empty() {
                return Err(format!("{context} is tuple-kind but reports no slots"));
            }
            ForeignVariantPayload::Tuple(carriers)
        }
        "struct" => {
            if v.members.is_empty() {
                return Err(format!("{context} is struct-kind but reports no members"));
            }
            let members = v
                .members
                .iter()
                .map(|m| named_member(&context, m))
                .collect::<Result<Vec<_>, _>>()?;
            ForeignVariantPayload::Struct(members)
        }
        other => return Err(format!("{context} has unknown kind {other:?}")),
    };
    Ok(ForeignVariant { name, payload })
}

/// Classify one reported type: transparent when every fact affirmatively
/// qualifies, else the disqualifying reason.
fn classify_one(w: &WireForeignType) -> Result<TransparentType, String> {
    if w.non_exhaustive {
        return Err("#[non_exhaustive]: the member set is not a stable contract".to_owned());
    }
    if w.hidden_members {
        return Err("has private, hidden, or unreportable members".to_owned());
    }
    let name = RustIdent::parse(&w.name)
        .map_err(|_| format!("type name {:?} is not a legal identifier", w.name))?;
    if !name.as_str().starts_with(|c: char| c.is_ascii_uppercase()) {
        return Err(format!("type name `{name}` is not capitalized"));
    }
    if crate::naming::IPE_BUILTIN_HEADS.contains(&name.as_str()) {
        return Err(format!("type name `{name}` shadows an Ipê builtin type"));
    }
    let rust_path = IdentPath::parse(&w.rust_path)
        .map_err(|_| format!("Rust path {:?} is not a legal identifier path", w.rust_path))?;
    // A bare (single-segment) Rust path is reserved for define-defined types,
    // whose crate-local module path resolves downstream where the cache slug
    // is known. An inspected crate type always carries its crate qualifier, so
    // a bare import path is a malformed report, not a resolvable type.
    if !rust_path.as_str().contains("::") {
        return Err(format!(
            "Rust path `{}` has no crate qualifier",
            rust_path.as_str()
        ));
    }
    match w.kind.as_str() {
        "struct" => {
            if !w.variants.is_empty() {
                return Err("struct entry reports enum variants".to_owned());
            }
            if w.fields.is_empty() {
                // An empty record surfaces nothing the opaque handle does not.
                return Err("reports no fields".to_owned());
            }
            let fields = w
                .fields
                .iter()
                .map(|m| named_member("field", m))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(TransparentType::Struct {
                name,
                rust_path,
                fields,
            })
        }
        "enum" => {
            if !w.fields.is_empty() {
                return Err("enum entry reports struct fields".to_owned());
            }
            if w.variants.is_empty() {
                return Err("reports no variants".to_owned());
            }
            let variants = w
                .variants
                .iter()
                .map(variant)
                .collect::<Result<Vec<_>, _>>()?;
            // A sole unit variant named like its type renders exactly the
            // opaque-handle placeholder (`type N = N`), so the two module
            // shapes could no longer be told apart downstream — the lowerer
            // and the conversion glue would disagree on the representation.
            // Refuse transparency; the opaque handle loses nothing here (a
            // one-unit-variant enum carries no data).
            if let [only] = variants.as_slice()
                && only.payload == ForeignVariantPayload::Unit
                && only.name.as_str() == name.as_str()
            {
                return Err(format!(
                    "sole unit variant `{}` spells the opaque-handle placeholder declaration",
                    only.name
                ));
            }
            Ok(TransparentType::Enum {
                name,
                rust_path,
                variants,
            })
        }
        other => Err(format!("unknown type kind {other:?}")),
    }
}

// ── define-defined types (the write side of the representation axis) ────────
//
// A `[[rust.define.struct/enum]]` type whose every member is an identity
// carrier is definitionally transparent: Ipê authored the shape, so the same
// record/union surface and conversion glue that serve a transparent IMPORT
// serve it too. The classification below applies the SAME member gates the
// import path uses; anything less than full qualification keeps the sound
// opaque-nominal default, with the reason recorded for the coverage ledger.
//
// A define-defined type lives at `crate::ffi::<slug>::<Name>` in the emitted
// app crate; the slug is unknown at this layer, so the recorded `rust_path`
// is the BARE nominal — the established define convention — and the glue
// assembler resolves it crate-locally where the slug is known. The import
// classification refuses bare paths, so the two provenances cannot blur.

/// The identity [`ScalarCarrier`] for a define member, or the refusal reason.
///
/// `Bytes` and opaque handles are outside the identity set the record/union
/// conversion glue moves field-for-field, so they disqualify transparency
/// (the member is still a legal OPAQUE define carrier).
fn identity_scalar(context: &str, c: &Carrier) -> Result<ScalarCarrier, String> {
    match c {
        Carrier::Int => Ok(ScalarCarrier::Int),
        Carrier::Float => Ok(ScalarCarrier::Float),
        Carrier::Bool => Ok(ScalarCarrier::Bool),
        Carrier::Char => Ok(ScalarCarrier::Char),
        Carrier::Str => Ok(ScalarCarrier::Str),
        Carrier::Bytes | Carrier::Opaque(_) => Err(format!(
            "{context} type `{}` is outside the identity carrier set",
            c.ipe_surface()
        )),
    }
}

/// Validate a define type's own nominal for the transparent surface.
fn define_nominal(name: &RustIdent) -> Result<(), String> {
    if !name.as_str().starts_with(|c: char| c.is_ascii_uppercase()) {
        return Err(format!("type name `{name}` is not capitalized"));
    }
    if name.as_str() == "Self" {
        return Err("type name `Self` is reserved".to_owned());
    }
    if crate::naming::IPE_BUILTIN_HEADS.contains(&name.as_str()) {
        return Err(format!("type name `{name}` shadows an Ipê builtin type"));
    }
    Ok(())
}

/// Classify one `define.struct` for the transparent record surface:
/// transparent when every fact affirmatively qualifies, else the reason it
/// stays an opaque nominal.
///
/// # Errors
///
/// A message naming the first disqualifying fact.
pub fn classify_define_struct(def: &StructDef) -> Result<TransparentType, String> {
    define_nominal(&def.name)?;
    if def.fields.is_empty() {
        // An empty record surfaces nothing the opaque handle does not.
        return Err("has no fields".to_owned());
    }
    let mut fields = Vec::with_capacity(def.fields.len());
    for (fname, carrier) in &def.fields {
        if !fname.as_str().starts_with(|c: char| c.is_ascii_lowercase()) {
            return Err(format!(
                "field `{fname}` is not lowercase-led (required of an Ipê record field)"
            ));
        }
        if is_reserved_member_name(fname.as_str()) {
            return Err(format!("field `{fname}` is a reserved keyword"));
        }
        let carrier = identity_scalar(&format!("field `{fname}`"), carrier)?;
        fields.push(ForeignMember {
            name: fname.clone(),
            carrier,
        });
    }
    let rust_path = IdentPath::parse(def.name.as_str())
        .map_err(|_| format!("nominal `{}` is not a legal path", def.name))?;
    Ok(TransparentType::Struct {
        name: def.name.clone(),
        rust_path,
        fields,
    })
}

/// Classify one `define.enum` for the transparent closed-union surface:
/// transparent when every fact affirmatively qualifies, else the reason it
/// stays an opaque nominal.
///
/// # Errors
///
/// A message naming the first disqualifying fact.
pub fn classify_define_enum(def: &EnumDef) -> Result<TransparentType, String> {
    define_nominal(&def.name)?;
    let mut variants = Vec::with_capacity(def.variants.len());
    for v in &def.variants {
        if !v
            .name
            .as_str()
            .starts_with(|c: char| c.is_ascii_uppercase())
        {
            return Err(format!(
                "variant `{}` is not capitalized (required of an Ipê union constructor)",
                v.name
            ));
        }
        if v.name.as_str() == "Self" {
            return Err("variant name `Self` is reserved".to_owned());
        }
        let payload = if v.payload.is_empty() {
            ForeignVariantPayload::Unit
        } else {
            let mut carriers = Vec::with_capacity(v.payload.len());
            for (i, c) in v.payload.iter().enumerate() {
                carriers.push(identity_scalar(
                    &format!("variant `{}` slot {i}", v.name),
                    c,
                )?);
            }
            ForeignVariantPayload::Tuple(carriers)
        };
        variants.push(ForeignVariant {
            name: v.name.clone(),
            payload,
        });
    }
    // A sole unit variant named like its type spells the opaque-handle
    // placeholder declaration (`type N = N`) — the same ambiguity the import
    // classification refuses, refused here for the same reason.
    if let [only] = variants.as_slice()
        && only.payload == ForeignVariantPayload::Unit
        && only.name.as_str() == def.name.as_str()
    {
        return Err(format!(
            "sole unit variant `{}` spells the opaque-handle placeholder declaration",
            only.name
        ));
    }
    let rust_path = IdentPath::parse(def.name.as_str())
        .map_err(|_| format!("nominal `{}` is not a legal path", def.name))?;
    Ok(TransparentType::Enum {
        name: def.name.clone(),
        rust_path,
        variants,
    })
}

#[cfg(test)]
#[allow(clippy::panic, reason = "test assertions")]
mod tests {
    use super::*;

    /// Every lexer keyword and every Rust keyword is a reserved member name.
    #[test]
    fn every_keyword_is_a_reserved_member_name() {
        for kw in ipe_parse::KEYWORDS.iter().chain(ipe_intern::RUST_KEYWORDS) {
            assert!(is_reserved_member_name(kw), "{kw:?} not reserved");
        }
        assert!(is_reserved_member_name("foreign"));
        assert!(!is_reserved_member_name("port"));
    }

    fn decode_types(v: &serde_json::Value) -> Vec<WireForeignType> {
        serde_json::from_value(v.clone()).expect("wire decode")
    }

    fn point_and_shade() -> serde_json::Value {
        serde_json::json!([
            {
                "name": "Point",
                "rustPath": "tm::Point",
                "kind": "struct",
                "fields": [
                    {"name": "x", "type": "Int", "rustType": "i64"},
                    {"name": "y", "type": "Float", "rustType": "f64"}
                ]
            },
            {
                "name": "Shade",
                "rustPath": "tm::Shade",
                "kind": "enum",
                "variants": [
                    {"name": "On", "kind": "unit"},
                    {"name": "Level", "kind": "tuple",
                     "members": [{"name": "0", "type": "Int", "rustType": "i64"}]},
                    {"name": "Mix", "kind": "struct",
                     "members": [{"name": "amount", "type": "Int", "rustType": "i64"}]}
                ]
            }
        ])
    }

    #[test]
    fn qualifying_struct_and_enum_decode_transparent() {
        let catalog = ForeignTypeCatalog::classify(&decode_types(&point_and_shade()));
        assert!(catalog.opaque_reasons().is_empty(), "{:?}", catalog.opaque);
        let point = catalog.transparent().get("Point").expect("Point");
        let TransparentType::Struct {
            rust_path, fields, ..
        } = point
        else {
            panic!("Point must be a transparent struct");
        };
        assert_eq!(rust_path.as_str(), "tm::Point");
        let got: Vec<(&str, ScalarCarrier)> = fields
            .iter()
            .map(|f| (f.name.as_str(), f.carrier))
            .collect();
        assert_eq!(
            got,
            vec![("x", ScalarCarrier::Int), ("y", ScalarCarrier::Float)]
        );
        let shade = catalog.transparent().get("Shade").expect("Shade");
        let TransparentType::Enum { variants, .. } = shade else {
            panic!("Shade must be a transparent enum");
        };
        assert_eq!(
            variants.iter().map(|v| v.name.as_str()).collect::<Vec<_>>(),
            vec!["On", "Level", "Mix"]
        );
        assert_eq!(
            variants.first().map(|v| &v.payload),
            Some(&ForeignVariantPayload::Unit)
        );
        assert_eq!(
            variants.get(1).map(|v| &v.payload),
            Some(&ForeignVariantPayload::Tuple(vec![ScalarCarrier::Int]))
        );
    }

    #[test]
    fn non_exhaustive_and_hidden_members_stay_opaque() {
        let wire = decode_types(&serde_json::json!([
            {"name": "A", "rustPath": "tm::A", "kind": "struct", "nonExhaustive": true,
             "fields": [{"name": "x", "type": "Int", "rustType": "i64"}]},
            {"name": "B", "rustPath": "tm::B", "kind": "struct", "hiddenMembers": true,
             "fields": [{"name": "x", "type": "Int", "rustType": "i64"}]}
        ]));
        let catalog = ForeignTypeCatalog::classify(&wire);
        assert!(catalog.transparent().is_empty());
        let reasons: Vec<&str> = catalog
            .opaque_reasons()
            .iter()
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(reasons, vec!["A", "B"]);
    }

    #[test]
    fn non_identity_carrier_members_stay_opaque() {
        // A saturating pair (Int, u64), a mismatched spoof (String, i64), and
        // a container are all outside the identity set.
        for (ipe, rust) in [("Int", "u64"), ("String", "i64"), ("List Int", "Vec<i64>")] {
            let wire = decode_types(&serde_json::json!([
                {"name": "T", "rustPath": "tm::T", "kind": "struct",
                 "fields": [{"name": "x", "type": ipe, "rustType": rust}]}
            ]));
            let catalog = ForeignTypeCatalog::classify(&wire);
            assert!(
                catalog.transparent().is_empty(),
                "({ipe}, {rust}) must not decode transparent"
            );
        }
    }

    #[test]
    fn malformed_names_and_paths_stay_opaque() {
        let cases = serde_json::json!([
            // Path injection.
            {"name": "Evil", "rustPath": "tm::Evil; use std::process::Command",
             "kind": "struct", "fields": [{"name": "x", "type": "Int", "rustType": "i64"}]},
            // Builtin shadow.
            {"name": "String", "rustPath": "tm::String", "kind": "struct",
             "fields": [{"name": "x", "type": "Int", "rustType": "i64"}]},
            // Keyword field.
            {"name": "Kw", "rustPath": "tm::Kw", "kind": "struct",
             "fields": [{"name": "type", "type": "Int", "rustType": "i64"}]},
            // Lowercase type nominal.
            {"name": "lower", "rustPath": "tm::lower", "kind": "struct",
             "fields": [{"name": "x", "type": "Int", "rustType": "i64"}]},
            // Unknown kind.
            {"name": "Un", "rustPath": "tm::Un", "kind": "union",
             "fields": [{"name": "x", "type": "Int", "rustType": "i64"}]},
            // Capitalized variant required.
            {"name": "E", "rustPath": "tm::E", "kind": "enum",
             "variants": [{"name": "lower", "kind": "unit"}]},
            // Tuple slot order must match declaration order.
            {"name": "F", "rustPath": "tm::F", "kind": "enum",
             "variants": [{"name": "V", "kind": "tuple",
                "members": [{"name": "1", "type": "Int", "rustType": "i64"}]}]},
            // Kind/member contradictions.
            {"name": "G", "rustPath": "tm::G", "kind": "enum",
             "variants": [{"name": "V", "kind": "unit",
                "members": [{"name": "0", "type": "Int", "rustType": "i64"}]}]},
            {"name": "H", "rustPath": "tm::H", "kind": "struct",
             "fields": [{"name": "x", "type": "Int", "rustType": "i64"}],
             "variants": [{"name": "V", "kind": "unit"}]},
            // Empty member sets gain nothing over the opaque handle.
            {"name": "I", "rustPath": "tm::I", "kind": "struct"},
            {"name": "J", "rustPath": "tm::J", "kind": "enum"}
        ]);
        let catalog = ForeignTypeCatalog::classify(&decode_types(&cases));
        assert!(
            catalog.transparent().is_empty(),
            "all malformed entries must stay opaque: {:?}",
            catalog.transparent
        );
        assert_eq!(catalog.opaque_reasons().len(), 11);
    }

    #[test]
    fn placeholder_shaped_enum_stays_opaque() {
        // `enum Marker { Marker }` would render `type Marker = Marker` — the
        // opaque-handle placeholder spelling — so it must classify opaque.
        let wire = decode_types(&serde_json::json!([
            {"name": "Marker", "rustPath": "tm::Marker", "kind": "enum",
             "variants": [{"name": "Marker", "kind": "unit"}]}
        ]));
        let catalog = ForeignTypeCatalog::classify(&wire);
        assert!(catalog.transparent().is_empty());
        assert!(
            catalog
                .opaque_reasons()
                .iter()
                .any(|r| r.name == "Marker" && r.reason.contains("placeholder")),
            "{:?}",
            catalog.opaque_reasons()
        );
        // A same-named unit variant among OTHERS is fine (no placeholder
        // ambiguity — the declaration has more than one constructor).
        let wire = decode_types(&serde_json::json!([
            {"name": "Mode", "rustPath": "tm::Mode", "kind": "enum",
             "variants": [
                {"name": "Mode", "kind": "unit"},
                {"name": "Alt", "kind": "unit"}
             ]}
        ]));
        let catalog = ForeignTypeCatalog::classify(&wire);
        assert!(catalog.transparent().contains_key("Mode"));
    }

    #[test]
    fn bare_import_paths_stay_opaque() {
        // A single-segment Rust path is reserved for define-defined types; an
        // inspected report carrying one is malformed and must stay opaque.
        let wire = decode_types(&serde_json::json!([
            {"name": "Point", "rustPath": "Point", "kind": "struct",
             "fields": [{"name": "x", "type": "Int", "rustType": "i64"}]}
        ]));
        let catalog = ForeignTypeCatalog::classify(&wire);
        assert!(catalog.transparent().is_empty());
        assert!(
            catalog
                .opaque_reasons()
                .iter()
                .any(|r| r.reason.contains("no crate qualifier")),
            "{:?}",
            catalog.opaque_reasons()
        );
    }

    #[test]
    fn qualifying_define_struct_and_enum_classify_transparent() {
        let s = StructDef::parse(
            "Counter",
            &[
                ("value".to_owned(), "i64".to_owned()),
                ("label".to_owned(), "String".to_owned()),
            ],
            &["Clone".to_owned()],
        )
        .expect("parses");
        let t = classify_define_struct(&s).expect("transparent");
        let TransparentType::Struct {
            rust_path, fields, ..
        } = &t
        else {
            panic!("Counter must classify as a transparent struct");
        };
        assert_eq!(rust_path.as_str(), "Counter", "bare define nominal");
        assert_eq!(
            fields
                .iter()
                .map(|f| (f.name.as_str(), f.carrier))
                .collect::<Vec<_>>(),
            vec![("value", ScalarCarrier::Int), ("label", ScalarCarrier::Str)]
        );

        let e = EnumDef::parse(
            "Message",
            &[
                ("Increment".to_owned(), vec![]),
                ("SetValue".to_owned(), vec!["i64".to_owned()]),
            ],
            &[],
        )
        .expect("parses");
        let t = classify_define_enum(&e).expect("transparent");
        let TransparentType::Enum { variants, .. } = &t else {
            panic!("Message must classify as a transparent enum");
        };
        assert_eq!(
            variants.iter().map(|v| v.name.as_str()).collect::<Vec<_>>(),
            vec!["Increment", "SetValue"]
        );
        assert_eq!(
            variants.first().map(|v| &v.payload),
            Some(&ForeignVariantPayload::Unit)
        );
        assert_eq!(
            variants.get(1).map(|v| &v.payload),
            Some(&ForeignVariantPayload::Tuple(vec![ScalarCarrier::Int]))
        );
    }

    #[test]
    fn disqualified_define_shapes_keep_the_opaque_default() {
        // Bytes is a legal define carrier but outside the identity set.
        let bytes = StructDef::parse("Blob", &[("data".to_owned(), "Bytes".to_owned())], &[])
            .expect("parses");
        assert!(
            classify_define_struct(&bytes).is_err(),
            "Bytes member must disqualify"
        );
        // An opaque handle field.
        let opaque = StructDef::parse("Wrap", &[("inner".to_owned(), "Widget".to_owned())], &[])
            .expect("parses");
        assert!(
            classify_define_struct(&opaque).is_err(),
            "opaque member must disqualify"
        );
        // A fieldless struct surfaces nothing the handle does not.
        let empty = StructDef::parse("Unit", &[], &[]).expect("parses");
        assert!(classify_define_struct(&empty).is_err());
        // A keyword field cannot be an Ipê record field.
        let keyword =
            StructDef::parse("Kw", &[("case".to_owned(), "i64".to_owned())], &[]).expect("parses");
        assert!(classify_define_struct(&keyword).is_err());
        // A reserved Rust keyword field cannot render as `value.try`.
        for kw in ["try", "gen"] {
            let rust_kw =
                StructDef::parse("Kw", &[(kw.to_owned(), "i64".to_owned())], &[]).expect("parses");
            let err = classify_define_struct(&rust_kw).err().unwrap_or_default();
            assert!(
                err.contains("reserved keyword"),
                "{kw} field should be refused, got: {err:?}"
            );
        }
        // The weak keyword `union` is a legal field name.
        let weak = StructDef::parse("Span", &[("union".to_owned(), "i64".to_owned())], &[])
            .expect("parses");
        assert!(
            classify_define_struct(&weak).is_ok(),
            "`union` is a legal Rust field name"
        );
        // The placeholder-shaped enum spells the opaque-handle declaration.
        let placeholder =
            EnumDef::parse("Marker", &[("Marker".to_owned(), vec![])], &[]).expect("parses");
        assert!(classify_define_enum(&placeholder).is_err());
        // A builtin shadow.
        let shadow = EnumDef::parse("Result", &[("Ok".to_owned(), vec![])], &[]).expect("parses");
        assert!(classify_define_enum(&shadow).is_err());
        // A reserved `Self` variant cannot render as a Rust constructor path.
        let selfish = EnumDef::parse("Mode", &[("Self".to_owned(), vec![])], &[]).expect("parses");
        assert!(classify_define_enum(&selfish).is_err());
        // A Bytes payload disqualifies the enum.
        let bytes_payload = EnumDef::parse(
            "Packet",
            &[("Data".to_owned(), vec!["Bytes".to_owned()])],
            &[],
        )
        .expect("parses");
        assert!(classify_define_enum(&bytes_payload).is_err());
    }

    #[test]
    fn define_classification_round_trips_through_the_projection_decoder() {
        let e = EnumDef::parse(
            "Message",
            &[
                ("Increment".to_owned(), vec![]),
                ("SetValue".to_owned(), vec!["i64".to_owned()]),
            ],
            &[],
        )
        .expect("parses");
        let original = classify_define_enum(&e).expect("transparent");
        let wire = crate::emit::transparent_type_json(&original);
        let decoded = TransparentType::from_projection_json(&wire).expect("round-trips");
        assert_eq!(decoded, original);
    }

    #[test]
    fn duplicate_nominals_poison_both_entries() {
        let wire = decode_types(&serde_json::json!([
            {"name": "Point", "rustPath": "tm::a::Point", "kind": "struct",
             "fields": [{"name": "x", "type": "Int", "rustType": "i64"}]},
            {"name": "Point", "rustPath": "tm::b::Point", "kind": "struct",
             "fields": [{"name": "y", "type": "Int", "rustType": "i64"}]}
        ]));
        let catalog = ForeignTypeCatalog::classify(&wire);
        assert!(
            catalog.transparent().is_empty(),
            "an ambiguous nominal must not surface structure"
        );
        assert!(
            catalog
                .opaque_reasons()
                .iter()
                .any(|r| r.name == "Point" && r.reason.contains("claim the nominal")),
            "the ambiguity must be recorded"
        );
    }

    #[test]
    fn mixed_transparent_and_opaque_nominal_collision_poisons_the_transparent_claimant() {
        // One qualifying `a::Point` plus one refused `b::Point` (hidden
        // members): the record and the opaque handle would share the Ipê
        // nominal, so the transparent claimant must fall back to opaque —
        // regardless of report order.
        let qualifying = serde_json::json!(
            {"name": "Point", "rustPath": "tm::a::Point", "kind": "struct",
             "fields": [{"name": "x", "type": "Int", "rustType": "i64"}]});
        let refused = serde_json::json!(
            {"name": "Point", "rustPath": "tm::b::Point", "kind": "struct",
             "hiddenMembers": true});
        for order in [
            serde_json::json!([qualifying, refused]),
            serde_json::json!([refused, qualifying]),
        ] {
            let catalog = ForeignTypeCatalog::classify(&decode_types(&order));
            assert!(
                catalog.transparent().is_empty(),
                "a mixed nominal collision must not surface structure"
            );
            assert!(
                catalog
                    .opaque_reasons()
                    .iter()
                    .any(|r| r.name == "Point" && r.reason.contains("also claimed")),
                "the mixed ambiguity must be recorded"
            );
        }
    }
}
