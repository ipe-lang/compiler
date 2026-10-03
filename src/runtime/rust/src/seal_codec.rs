//! The Ipê↔JS boundary-seal codec: a total, fail-closed decode gate.
//!
//! A value crossing the Ipê↔JS seam carries a concrete-ADT *seal* — a closed,
//! declared value type (primitives, records, tuples, `List`/`Set`/`Maybe`/
//! `Dict`/`Result`, and user ADTs transitively over those). The canon-level seal
//! predicate (`boundary_seal_rejection`) already proves, at compile time, that a
//! declared seal type is legal. This module is the *runtime* half: the bounded,
//! fail-closed entry that a generated per-seal-type decoder runs behind, so that
//! a value arriving from JS either decodes to the declared type or is turned away
//! whole — never a partial value, never an undecoded hole travelling inward.
//!
//! ## Not a second JSON dialect
//!
//! The seal codec does not invent its own wire format. It reuses the canonical
//! JSON substrate the two shipped crossings already share: the `Decoder<E, T>`
//! combinator library and `json_enc_canonical` in [`crate::json`] — the same
//! primitives the `EventBody` event path and the hydration island decode against.
//! What this module adds on top of that substrate is the one thing a boundary
//! decode needs that a plain decode does not: **explicit, bounded-by-construction
//! input limits** so the decode of attacker-controlled input can never be turned
//! into a resource-exhaustion (DoS) vector, and a **single typed rejection** that
//! makes a dropped value observable without constructing any part of it.
//!
//! ## Total and fail-closed
//!
//! [`seal_decode`] is total: every input maps to `Ok(value)` or
//! `Err(SealDecodeError)`. There is no third outcome — no panic, no partial
//! value, no default-filled record. A malformed input (oversized bytes,
//! over-nested JSON, a syntax error, or a value the declared-type decoder
//! rejects — wrong shape, wrong tag, wrong arity, missing field, out-of-range
//! integer) is rejected *before* any typed value is handed inward. This is the
//! runtime enforcement of the seal: absent proof the crossing value is safe,
//! the conservative branch — rejection — is the only reachable one.

#[cfg(feature = "json")]
use crate::json::{Decoder, JsonVal};
#[cfg(feature = "json")]
use crate::{IpeError, IpeResult};

/// Why a value was refused at the seal boundary.
///
/// A single closed vocabulary of rejection reasons — the boundary either yields
/// the declared value or one of these, and nothing else can be spelled
/// (make-invalid-states-unrepresentable). No variant carries a partially-decoded
/// value: a rejection is observable (a message for a dev console / server log)
/// but never a foothold to smuggle an undecoded value inward.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealDecodeError {
    /// The raw input exceeded the byte budget before parsing began. Reported with
    /// the observed length and the cap so a legitimate over-limit payload is
    /// diagnosable without echoing the (untrusted, unbounded) body.
    TooLarge { len: usize, max: usize },
    /// The JSON nests containers past the depth budget. Checked by a lexical
    /// scan before the parser runs, and again on the parsed value, so a
    /// deeply-nested document is refused here rather than blowing the stack.
    TooDeep { max: u8 },
    /// The JSON was syntactically invalid.
    Malformed { detail: String },
    /// The JSON parsed, but the declared-type decoder rejected it: a wrong shape,
    /// a wrong ADT tag, a wrong tuple arity, a missing required field, or an
    /// out-of-range integer. The inner message is the decoder's own diagnostic.
    TypeMismatch { detail: String },
}

impl core::fmt::Display for SealDecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SealDecodeError::TooLarge { len, max } => write!(
                f,
                "seal decode rejected: input is {len} bytes, over the {max}-byte boundary limit"
            ),
            SealDecodeError::TooDeep { max } => write!(
                f,
                "seal decode rejected: JSON nested past the {max}-level boundary limit"
            ),
            SealDecodeError::Malformed { detail } => {
                write!(f, "seal decode rejected: malformed JSON ({detail})")
            }
            SealDecodeError::TypeMismatch { detail } => {
                write!(
                    f,
                    "seal decode rejected: value does not match the declared seal type ({detail})"
                )
            }
        }
    }
}

impl SealDecodeError {
    /// Whether a declared ceiling (the byte or depth budget) turned the input
    /// back, as opposed to a syntax or shape refusal.
    #[must_use]
    pub const fn is_ceiling(&self) -> bool {
        match self {
            SealDecodeError::TooLarge { .. } | SealDecodeError::TooDeep { .. } => true,
            SealDecodeError::Malformed { .. } | SealDecodeError::TypeMismatch { .. } => false,
        }
    }
}

/// The bounds a seal decode enforces on attacker-controlled input, so the decode
/// is bounded by construction and cannot be turned into a DoS vector.
///
/// Both bounds are conservative caps on *input*, independent of the declared seal
/// type: they are checked before and during parsing, so a hostile payload is
/// turned away before the (potentially expensive) typed decode runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SealLimits {
    /// Maximum raw-input length in bytes. A larger input is rejected as
    /// [`SealDecodeError::TooLarge`] before any parse allocation. Mirrors the
    /// request-body cap the event path already imposes (`IPE_WEB_MAX_BODY_BYTES`),
    /// applied here at the value boundary so an off-web caller (a port, a wasm
    /// property setter) inherits the same protection.
    pub max_input_bytes: usize,
    /// Maximum JSON nesting depth. A document nested past it is rejected as
    /// [`SealDecodeError::TooDeep`] before the parser recurses into it.
    pub max_nesting_depth: u8,
}

/// Default maximum raw-input length: 5 MiB, matching the shipped
/// `IPE_WEB_MAX_BODY_BYTES` default so the event path and the seal boundary agree
/// on one figure.
pub const DEFAULT_SEAL_MAX_INPUT_BYTES: usize = 5 * 1024 * 1024;

/// Default maximum JSON nesting depth. `serde_json`'s own built-in default is
/// 128; the seal boundary pins the same figure explicitly so the bound is part of
/// the documented contract rather than an inherited library default that could
/// drift.
pub const DEFAULT_SEAL_MAX_NESTING_DEPTH: u8 = 128;

impl Default for SealLimits {
    fn default() -> Self {
        SealLimits {
            max_input_bytes: DEFAULT_SEAL_MAX_INPUT_BYTES,
            max_nesting_depth: DEFAULT_SEAL_MAX_NESTING_DEPTH,
        }
    }
}

/// Decode a raw JS-boundary input into the declared seal type, totally and
/// fail-closed.
///
/// `decoder` is the generated per-type decoder for the concrete seal type,
/// composed from the [`crate::json`] combinators — the same substrate every other
/// crossing decodes with (no second dialect). `limits` bounds the untrusted
/// input so the decode cannot be a DoS vector.
///
/// The steps are ordered cheapest-and-most-conservative first:
/// 1. Byte-length check — reject an oversized input before parsing allocates.
/// 2. Depth-bounded JSON parse — an over-nested document is refused as
///    `TooDeep` before the parser recurses, a syntax error as `Malformed`.
/// 3. Typed decode — the declared-type decoder runs; any mismatch is a typed
///    rejection, never a partial value.
///
/// Returns the decoded value or the single reason it was refused. It never
/// panics and never yields a partially-constructed value.
#[cfg(feature = "json")]
pub fn seal_decode<T>(
    input: &str,
    decoder: &Decoder<IpeError, T>,
    limits: SealLimits,
) -> Result<T, SealDecodeError> {
    // 1. Byte budget, before any parse allocation. A `&str` is valid UTF-8 by
    //    construction, so a malformed-UTF8 input can never reach this function;
    //    the caller's `&str` boundary already forecloses that class. What remains
    //    to bound is sheer size.
    if input.len() > limits.max_input_bytes {
        return Err(SealDecodeError::TooLarge {
            len: input.len(),
            max: limits.max_input_bytes,
        });
    }

    // 2. Depth-bounded parse into a `JsonVal`: an over-nested document is
    //    `TooDeep`, a syntax error `Malformed` — the typed decoder never sees
    //    either.
    let value = parse_depth_bounded(input, limits.max_nesting_depth)?;

    // 3. Typed decode. The declared-type decoder either yields the whole value or
    //    a typed error; on error nothing partial escapes.
    match (decoder.run)(&value) {
        IpeResult::Ok(t) => Ok(t),
        // `IpeError: Display` — the decoder's own diagnostic, surfaced as the
        // rejection detail. No part of the value survives the error branch.
        IpeResult::Err(e) => Err(SealDecodeError::TypeMismatch {
            detail: e.to_string(),
        }),
    }
}

/// Decode a raw JS-boundary input into a serde-derived seal type, totally and
/// fail-closed — the entry the generated `CustomElement.node` up-decoder composes.
///
/// A seal-legal type in a Web program is emitted with
/// `#[derive(serde::Serialize, serde::Deserialize)]` (the same derive the
/// session-store Model carries), so its concrete Rust type IS its own decoder —
/// no bespoke combinator generation is needed. This entry wraps `serde_json`
/// with the SAME conservative-first bounds as [`seal_decode`]:
///
/// 1. Byte-length check — reject an oversized input before parsing allocates.
/// 2. Depth-bounded parse — a syntax error or an over-nested document is refused
///    before the typed decode runs.
/// 3. Typed decode via `serde_json::from_value` — any shape/tag/field mismatch
///    is a single typed rejection, never a partial value.
///
/// Returns the decoded value or the single reason it was refused. It never
/// panics and never yields a partially-constructed value: a payload that does
/// not decode to `T` is dropped whole (the up-event's fail-closed contract).
#[cfg(feature = "json")]
pub fn seal_decode_serde<T: serde::de::DeserializeOwned>(
    input: &str,
    limits: SealLimits,
) -> Result<T, SealDecodeError> {
    if input.len() > limits.max_input_bytes {
        return Err(SealDecodeError::TooLarge {
            len: input.len(),
            max: limits.max_input_bytes,
        });
    }
    // Depth-bound the untrusted document first (same post-parse structural check
    // as `seal_decode`), so an adversarial `[[[[…]]]]` is refused before the
    // typed decode. `JsonVal` is `serde_json::Value`, so the parsed value feeds
    // `from_value` with no re-serialisation.
    let value = parse_depth_bounded(input, limits.max_nesting_depth)?;
    serde_json::from_value::<T>(value).map_err(|e| SealDecodeError::TypeMismatch {
        detail: e.to_string(),
    })
}

/// Fail-closed boundary gate for an untrusted raw JS-boundary input, applying the
/// SAME conservative-first bounds as [`seal_decode`] steps 1–2 (byte budget +
/// depth-bounded parse) WITHOUT a typed decode. It is the check an untyped ingress
/// route (the `Ipe.Ffi.Js` inbound port) runs before fanning a raw frame to its
/// per-session subscribers, each of which then runs its own typed [`seal_decode`].
///
/// A payload that exceeds the byte budget, is not valid JSON, or is nested past
/// the depth budget is refused here and dropped WHOLE at the boundary — the same
/// discipline as a typed decode failure, never a panic and never a partial frame.
#[cfg(feature = "json")]
pub fn seal_boundary_check(input: &str, limits: SealLimits) -> Result<(), SealDecodeError> {
    if input.len() > limits.max_input_bytes {
        return Err(SealDecodeError::TooLarge {
            len: input.len(),
            max: limits.max_input_bytes,
        });
    }
    parse_depth_bounded(input, limits.max_nesting_depth).map(|_| ())
}

/// Most containers `serde_json` nests before it refuses with its own recursion
/// error: its deserializer starts with a remaining depth of 128 and refuses the
/// container that brings it to 0.
#[cfg(feature = "json")]
const SERDE_CONTAINER_FLOOR: usize = 127;

/// Parse `input` into a [`JsonVal`], refusing a document nested past
/// `max_depth` as [`SealDecodeError::TooDeep`] and a syntax error as
/// [`SealDecodeError::Malformed`]. Never panics.
///
/// The container nesting is checked lexically first, against the smaller of
/// the seal budget and `serde_json`'s own floor, so the parser's recursion
/// error (a syntax-shaped error that cannot be told apart from a typo) never
/// refuses an over-nested document. The parsed value is then checked against
/// the seal budget by structural depth, where a scalar leaf counts one level.
#[cfg(feature = "json")]
fn parse_depth_bounded(input: &str, max_depth: u8) -> Result<JsonVal, SealDecodeError> {
    let lexical_cap = usize::from(max_depth).min(SERDE_CONTAINER_FLOOR);
    if !containers_nest_within(input, lexical_cap) {
        return Err(SealDecodeError::TooDeep { max: max_depth });
    }
    let value: JsonVal = serde_json::from_str(input).map_err(|e| SealDecodeError::Malformed {
        detail: format!("json parse: {e}"),
    })?;
    if json_depth(&value) > usize::from(max_depth) {
        return Err(SealDecodeError::TooDeep { max: max_depth });
    }
    Ok(value)
}

/// Whether `input` never has more than `cap` JSON containers (`[`, `{`) open at
/// once, counting brackets outside string literals only. A stray closing
/// bracket saturates at zero; the parser refuses it afterwards as a syntax
/// error. One pass, no allocation.
#[cfg(feature = "json")]
fn containers_nest_within(input: &str, cap: usize) -> bool {
    let mut open = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for byte in input.bytes() {
        if in_string {
            match (escaped, byte) {
                (true, _) => escaped = false,
                (false, b'\\') => escaped = true,
                (false, b'"') => in_string = false,
                (false, _) => {}
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'[' | b'{' => {
                open = open.saturating_add(1);
                if open > cap {
                    return false;
                }
            }
            b']' | b'}' => open = open.saturating_sub(1),
            _ => {}
        }
    }
    true
}

/// Structural nesting depth of a parsed JSON value: a scalar is depth 1, a
/// container is 1 + the deepest child. Iterative over an explicit work stack so a
/// pathological (but under-serde's-128-limit) document cannot recurse the native
/// stack while we re-check the seal's own, possibly stricter, depth budget.
#[cfg(feature = "json")]
fn json_depth(root: &JsonVal) -> usize {
    // (node, depth-at-node); the max depth seen is the answer.
    let mut stack: Vec<(&JsonVal, usize)> = vec![(root, 1)];
    let mut max_depth = 0usize;
    while let Some((node, depth)) = stack.pop() {
        if depth > max_depth {
            max_depth = depth;
        }
        match node {
            JsonVal::Array(items) => {
                for item in items {
                    stack.push((item, depth + 1));
                }
            }
            JsonVal::Object(map) => {
                for (_, v) in map {
                    stack.push((v, depth + 1));
                }
            }
            _ => {}
        }
    }
    max_depth
}

/// Encode a `JsonVal` (built by the generated per-type encoder from the
/// [`crate::json`] `json_enc_*` constructors) into the canonical, deterministic
/// wire string every crossing shares.
///
/// This is exactly `json_enc_canonical`: sorted-key, compact, HTML-escaped —
/// the one canonical form, never a seal-specific variant. Kept as a named seal
/// entry so the codec's two directions read as a pair and a future carrier
/// (attribute vs property vs posted body) threads through one function.
#[cfg(feature = "json")]
pub fn seal_encode(value: &JsonVal) -> String {
    crate::json::json_enc_canonical(value)
}

#[cfg(all(test, feature = "json"))]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;
    use crate::IpeError;
    use crate::json::{
        Decoder, JsonVal, decode_field, decode_list, decode_map4, json_decode_string, json_enc_int,
        json_enc_list, json_enc_object, json_enc_string,
    };

    // ── A representative seal type: a record with a nested ADT + a List + a
    //    Dict-shaped field. This is exactly the shape §0 of WP3 asks the
    //    adversarial tests to exercise, hand-built from the SAME json.rs
    //    combinators the backend will emit per concrete seal type.

    #[derive(Debug, Clone, PartialEq)]
    enum Priority {
        Low,
        High,
        // A payload-carrying variant, to exercise wrong-arity / wrong-payload.
        Custom(i64),
    }

    #[derive(Debug, Clone, PartialEq)]
    struct Item {
        name: String,
        priority: Priority,
        tags: Vec<String>,
        // A Dict is encoded as a JSON object of string→int; decoded field-wise
        // here through a small object-pairs decoder to keep the test self-contained.
        counts: Vec<(String, i64)>,
    }

    // ── Encoders (the `up`/`down` encode direction), composing json_enc_*. ──

    fn encode_priority(p: &Priority) -> JsonVal {
        // A closed ADT encodes as a tagged object `{tag, value?}` — the shape the
        // generated codec uses; the decoder below rejects any other tag/arity.
        match p {
            Priority::Low => json_enc_object(vec![("tag".into(), json_enc_string("Low".into()))]),
            Priority::High => json_enc_object(vec![("tag".into(), json_enc_string("High".into()))]),
            Priority::Custom(n) => json_enc_object(vec![
                ("tag".into(), json_enc_string("Custom".into())),
                ("value".into(), json_enc_int(*n)),
            ]),
        }
    }

    fn encode_item(it: &Item) -> JsonVal {
        json_enc_object(vec![
            ("name".into(), json_enc_string(it.name.clone())),
            ("priority".into(), encode_priority(&it.priority)),
            (
                "tags".into(),
                json_enc_list(json_enc_string, it.tags.clone()),
            ),
            (
                "counts".into(),
                json_enc_object(
                    it.counts
                        .iter()
                        .map(|(k, v)| (k.clone(), json_enc_int(*v)))
                        .collect(),
                ),
            ),
        ])
    }

    // ── Decoders, composing the json.rs combinators, fully fail-closed. ──

    fn decode_priority() -> Decoder<IpeError, Priority> {
        Decoder::new(
            Box::new(|v: &JsonVal| {
                let tag = match v.get("tag").and_then(|t| t.as_str()) {
                    Some(s) => s,
                    None => return crate::json::decode_err_str("priority: missing tag".into()),
                };
                match tag {
                    "Low" => crate::json::decode_ok(Priority::Low),
                    "High" => crate::json::decode_ok(Priority::High),
                    "Custom" => match v.get("value").and_then(|n| n.as_i64()) {
                        Some(n) => crate::json::decode_ok(Priority::Custom(n)),
                        None => crate::json::decode_err_str(
                            "priority: Custom needs an integer `value` field".into(),
                        ),
                    },
                    other => crate::json::decode_err_str(format!("priority: unknown tag {other}")),
                }
            }),
            vec!["tag".into()],
        )
    }

    fn decode_counts() -> Decoder<IpeError, Vec<(String, i64)>> {
        Decoder::new(
            Box::new(|v: &JsonVal| match v.as_object() {
                Some(map) => {
                    let mut out = Vec::with_capacity(map.len());
                    for (k, val) in map {
                        match val.as_i64() {
                            Some(n) => out.push((k.clone(), n)),
                            None => {
                                return crate::json::decode_err_str(format!(
                                    "counts[{k}]: expected integer"
                                ));
                            }
                        }
                    }
                    crate::json::decode_ok(out)
                }
                None => crate::json::decode_err_str("counts: expected object".into()),
            }),
            vec![],
        )
    }

    fn decode_item() -> Decoder<IpeError, Item> {
        // A 4-field record decodes through `decode_map4` over four field
        // decoders — the flat shape the backend emits per concrete record seal
        // type. Every field-level rejection (missing / wrong type / bad tag /
        // wrong arity / out-of-range) short-circuits the whole decode.
        decode_map4(
            |name, priority, tags, counts| Item {
                name,
                priority,
                tags,
                counts,
            },
            decode_field("name".into(), json_decode_string::<IpeError>()),
            decode_field("priority".into(), decode_priority()),
            decode_field("tags".into(), decode_list(json_decode_string::<IpeError>())),
            decode_field("counts".into(), decode_counts()),
        )
    }

    fn sample() -> Item {
        Item {
            name: "widget".into(),
            priority: Priority::Custom(7),
            tags: vec!["a".into(), "b".into()],
            counts: vec![("x".into(), 1)],
        }
    }

    #[test]
    fn well_formed_value_round_trips() {
        let it = sample();
        let wire = seal_encode(&encode_item(&it));
        let back = seal_decode(&wire, &decode_item(), SealLimits::default())
            .expect("a well-formed value must decode");
        assert_eq!(back, it, "encode∘decode must be the identity");
    }

    #[test]
    fn canonical_encode_is_sorted_and_stable() {
        // Two structurally-equal values encode to byte-identical wire strings,
        // regardless of field construction order — the canonical-JSON contract
        // this codec reuses (not a second dialect).
        let a = seal_encode(&encode_item(&sample()));
        let b = seal_encode(&encode_item(&sample()));
        assert_eq!(a, b);
        // Object keys appear in ascending order in the wire form.
        let name_at = a.find("\"name\"").unwrap();
        let priority_at = a.find("\"priority\"").unwrap();
        assert!(name_at < priority_at, "keys must be sorted ascending");
    }

    #[test]
    fn rejects_missing_required_field() {
        // `priority` omitted → reject, no partial Item.
        let wire = seal_encode(&json_enc_object(vec![
            ("name".into(), json_enc_string("w".into())),
            ("tags".into(), json_enc_list(json_enc_string, vec![])),
            ("counts".into(), json_enc_object(vec![])),
        ]));
        let got = seal_decode(&wire, &decode_item(), SealLimits::default());
        assert!(
            matches!(got, Err(SealDecodeError::TypeMismatch { .. })),
            "missing field must be a typed rejection, got {got:?}"
        );
    }

    #[test]
    fn ignores_extra_unknown_field_like_the_event_path() {
        // Convention parity: the shipped EventBody / hydration decode ignore
        // unknown fields (serde default). A well-formed value with an extra field
        // still decodes to the same value — the seal reads only its declared
        // fields; the extra is not a foothold.
        let mut obj = encode_item(&sample());
        if let JsonVal::Object(map) = &mut obj {
            map.insert("attacker".into(), json_enc_string("ignored".into()));
        }
        let wire = seal_encode(&obj);
        let back = seal_decode(&wire, &decode_item(), SealLimits::default())
            .expect("an extra unknown field is ignored, not fatal");
        assert_eq!(back, sample());
    }

    #[test]
    fn rejects_wrong_json_type_in_a_field() {
        // `name` is a number, not a string → reject.
        let wire = seal_encode(&json_enc_object(vec![
            ("name".into(), json_enc_int(42)),
            ("priority".into(), encode_priority(&Priority::Low)),
            ("tags".into(), json_enc_list(json_enc_string, vec![])),
            ("counts".into(), json_enc_object(vec![])),
        ]));
        let got = seal_decode(&wire, &decode_item(), SealLimits::default());
        assert!(
            matches!(got, Err(SealDecodeError::TypeMismatch { .. })),
            "wrong field type must reject, got {got:?}"
        );
    }

    #[test]
    fn rejects_wrong_adt_tag() {
        let wire = seal_encode(&json_enc_object(vec![
            ("name".into(), json_enc_string("w".into())),
            (
                "priority".into(),
                json_enc_object(vec![("tag".into(), json_enc_string("Nonexistent".into()))]),
            ),
            ("tags".into(), json_enc_list(json_enc_string, vec![])),
            ("counts".into(), json_enc_object(vec![])),
        ]));
        let got = seal_decode(&wire, &decode_item(), SealLimits::default());
        assert!(
            matches!(got, Err(SealDecodeError::TypeMismatch { .. })),
            "unknown ADT tag must reject, got {got:?}"
        );
    }

    #[test]
    fn rejects_wrong_variant_arity() {
        // `Custom` requires an integer `value`; omitting it is a wrong-arity
        // payload for that variant → reject, no default-filled Custom(0).
        let wire = seal_encode(&json_enc_object(vec![
            ("name".into(), json_enc_string("w".into())),
            (
                "priority".into(),
                json_enc_object(vec![("tag".into(), json_enc_string("Custom".into()))]),
            ),
            ("tags".into(), json_enc_list(json_enc_string, vec![])),
            ("counts".into(), json_enc_object(vec![])),
        ]));
        let got = seal_decode(&wire, &decode_item(), SealLimits::default());
        assert!(
            matches!(got, Err(SealDecodeError::TypeMismatch { .. })),
            "wrong variant arity must reject, got {got:?}"
        );
    }

    #[test]
    fn rejects_integer_past_range() {
        // A magnitude past i64 in the `Custom` value → the int decode fails
        // closed (no silent truncation / saturation).
        let too_big = "9223372036854775808"; // i64::MAX + 1
        let wire = format!(
            "{{\"counts\":{{}},\"name\":\"w\",\"priority\":{{\"tag\":\"Custom\",\"value\":{too_big}}},\"tags\":[]}}"
        );
        let got = seal_decode(&wire, &decode_item(), SealLimits::default());
        assert!(
            matches!(got, Err(SealDecodeError::TypeMismatch { .. })),
            "out-of-range integer must reject, got {got:?}"
        );
    }

    #[test]
    fn rejects_syntactically_malformed_json() {
        let got = seal_decode("{not json", &decode_item(), SealLimits::default());
        assert!(
            matches!(got, Err(SealDecodeError::Malformed { .. })),
            "a syntax error must reject as Malformed, got {got:?}"
        );
    }

    #[test]
    fn rejects_oversized_input_before_parsing() {
        let limits = SealLimits {
            max_input_bytes: 16,
            ..SealLimits::default()
        };
        let wire = seal_encode(&encode_item(&sample())); // well over 16 bytes
        let got = seal_decode(&wire, &decode_item(), limits);
        assert!(
            matches!(got, Err(SealDecodeError::TooLarge { .. })),
            "an oversized input must reject as TooLarge, got {got:?}"
        );
    }

    #[test]
    fn rejects_over_nested_input_as_bounded() {
        // A deeply-nested array, past a deliberately small seal depth budget, is
        // turned back with a typed limit error — the decode is bounded, not a DoS
        // vector. Depth is kept under serde_json's own 128 floor so THIS test
        // exercises the seal's own stricter post-parse depth check.
        let limits = SealLimits {
            max_nesting_depth: 8,
            ..SealLimits::default()
        };
        let deep = format!("{}{}", "[".repeat(40), "]".repeat(40));
        // The array-of-strings decoder would reject the innermost anyway; what we
        // assert is that the *depth* bound fires first, as TooDeep, before any
        // typed decode work.
        let got = seal_decode(
            &deep,
            &decode_list(json_decode_string::<IpeError>()),
            limits,
        );
        assert_eq!(got, Err(SealDecodeError::TooDeep { max: 8 }));
    }

    #[test]
    fn serde_default_depth_floor_rejects_pathological_nesting() {
        // Even with a generous seal depth budget, serde_json's built-in 128-level
        // parse limit backstops a pathological document: it never recurses the
        // native stack without bound.
        let limits = SealLimits {
            max_nesting_depth: 255,
            ..SealLimits::default()
        };
        let deep = format!("{}{}", "[".repeat(500), "]".repeat(500));
        let got = seal_decode(
            &deep,
            &decode_list(json_decode_string::<IpeError>()),
            limits,
        );
        assert_eq!(
            got,
            Err(SealDecodeError::TooDeep { max: 255 }),
            "500-level nesting is a depth refusal, never serde's syntax-shaped one"
        );
    }

    fn nested_arrays(levels: usize) -> String {
        format!("{}{}", "[".repeat(levels), "]".repeat(levels))
    }

    #[test]
    fn depth_refusals_are_ceilings_at_both_bounds() {
        let tight = SealLimits {
            max_nesting_depth: 8,
            ..SealLimits::default()
        };
        assert_eq!(seal_boundary_check(&nested_arrays(8), tight), Ok(()));
        assert_eq!(
            seal_boundary_check(&nested_arrays(9), tight),
            Err(SealDecodeError::TooDeep { max: 8 })
        );
        // At serde's own floor: 127 nested containers parse, 128 are refused
        // by the seal as a depth ceiling before serde's recursion error.
        let wide = SealLimits {
            max_nesting_depth: 255,
            ..SealLimits::default()
        };
        assert_eq!(seal_boundary_check(&nested_arrays(127), wide), Ok(()));
        let past_floor = seal_boundary_check(&nested_arrays(128), wide);
        assert_eq!(past_floor, Err(SealDecodeError::TooDeep { max: 255 }));
        assert!(past_floor.is_err_and(|e| e.is_ceiling()));
    }

    #[test]
    fn brackets_inside_strings_do_not_count_toward_depth() {
        let tight = SealLimits {
            max_nesting_depth: 2,
            ..SealLimits::default()
        };
        assert_eq!(seal_boundary_check(r#"["[[[[{{{{"]"#, tight), Ok(()));
        assert_eq!(seal_boundary_check(r#"["\"[[[[", "\\"]"#, tight), Ok(()));
        assert_eq!(
            seal_boundary_check(r#"["\\", [[1]]]"#, tight),
            Err(SealDecodeError::TooDeep { max: 2 })
        );
    }

    #[test]
    fn only_byte_and_depth_refusals_are_ceilings() {
        let too_large = SealDecodeError::TooLarge { len: 2, max: 1 };
        let too_deep = SealDecodeError::TooDeep { max: 1 };
        let malformed = seal_boundary_check("{not json", SealLimits::default());
        assert!(too_large.is_ceiling() && too_deep.is_ceiling());
        assert!(matches!(&malformed, Err(SealDecodeError::Malformed { .. })));
        assert!(malformed.is_err_and(|e| !e.is_ceiling()));
        assert!(
            !SealDecodeError::TypeMismatch {
                detail: String::new()
            }
            .is_ceiling()
        );
    }

    #[test]
    fn scalar_and_container_depths() {
        assert_eq!(json_depth(&json_enc_int(1)), 1);
        assert_eq!(json_depth(&json_enc_list(json_enc_int, vec![1, 2])), 2);
        let nested = json_enc_object(vec![("k".into(), json_enc_list(json_enc_int, vec![1]))]);
        assert_eq!(json_depth(&nested), 3);
    }
}
