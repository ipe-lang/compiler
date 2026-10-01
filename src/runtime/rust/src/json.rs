#![allow(clippy::type_complexity)]
// JSON encode/decode, pipeline, and currying helpers.
// Generic over E for error type.
use super::*;

pub type JsonVal = serde_json::Value;

/// `Decoder<E, T>` — the unified decoder type shared by JsonDec, DbDec, and Config.
///
/// Changed from a bare `Box<dyn Fn>` type alias to a struct carrying:
///   - `run`: the decoding function (called against a `&JsonVal`).
///   - `fields`: the object fields this decoder reads from the input JsonVal::Object.
///     ∅ for leaf / combinator decoders (succeed, fail, string, int, …).
///     Named fields for `decode_field` and the `db_decode_*` primitives.
///     Union of inner fields for combinators (map2..5, and_map).
///     Used by `db_decode_nullable`
///     to determine whether ALL the fields the inner decoder reads are NULL/absent
///     before delegating to the inner run.
///
/// The carrier is `Arc`, not `Box`, so a `Decoder` is `Clone` (a refcount bump):
/// a decoder stored in a value (a `Codec a`'s `dec` field) can be read back out
/// and reused, which the `Box` carrier — non-`Clone`, non-`Copy` — could not
/// support without a move-out-of-`Fn` (E0507). `run` is `Send + Sync` so the
/// `Arc` is `Send + Sync`, keeping every `T: Send` kernel bound and the
/// cross-thread decoder usage sound.
pub struct Decoder<E, T> {
    pub run: std::sync::Arc<dyn Fn(&JsonVal) -> IpeResult<E, T> + Send + Sync>,
    pub fields: Vec<String>,
}

// Manual `Clone` (not derived): the carrier `Arc` and `Vec<String>` are always
// `Clone` regardless of `E`/`T`, so a `Decoder` clones without bounding them —
// a derived `impl` would spuriously require `E: Clone, T: Clone`.
impl<E, T> Clone for Decoder<E, T> {
    fn clone(&self) -> Self {
        Decoder {
            run: std::sync::Arc::clone(&self.run),
            fields: self.fields.clone(),
        }
    }
}

impl<E, T> Decoder<E, T> {
    pub fn new(
        run: Box<dyn Fn(&JsonVal) -> IpeResult<E, T> + Send + Sync>,
        fields: Vec<String>,
    ) -> Self {
        Decoder {
            run: std::sync::Arc::from(run),
            fields,
        }
    }
}

/// Append every field from `extra` into `base` that isn't already present.
/// The shared field-union used by every multi-decoder combinator (map2..5,
/// and_map, the pipeline helpers) so the open-coded O(n²) merge lives in one
/// place instead of ~10 copies.
fn union_fields(base: &mut Vec<String>, extra: &[String]) {
    for fld in extra {
        if !base.contains(fld) {
            base.push(fld.clone());
        }
    }
}

pub fn decode_ok<E, T>(t: T) -> IpeResult<E, T> {
    IpeResult::Ok(t)
}
pub fn decode_err_str<E: From<String>, T>(s: String) -> IpeResult<E, T> {
    IpeResult::Err(str_err(&s))
}

// --- Encode ---
pub fn json_enc_encode(indent: i64, val: JsonVal) -> String {
    // serde_json never fails on a well-formed Value; unwrap_or_default preserves
    // the total `encode : Int -> Value -> String` (pure, no Task wrapper).
    // indent=0 → compact, indent=N → N-space pretty.
    //
    // `GoFormatter` wraps the inner formatter and overrides exactly two hooks:
    //   * string fragments are HTML-escaped (`<`,`>`,`&`,U+2028,U+2029), which
    //     serde_json does not do by default;
    //   * f64 values are reshaped (decimal vs. exponent threshold, `e±NN`
    //     exponent shape) rather than serde's Ryū form.
    let mut buf = Vec::new();
    if indent > 0 {
        // PrettyFormatter::with_indent honours the exact N-space indent;
        // `to_string_pretty` always emits 2 spaces and would diverge for indent ≠ 2.
        //
        // Clamp the indent width: `indent` is attacker-supplyable (e.g. a value
        // threaded from request input), and an unbounded `str::repeat` would let
        // a huge count blow up memory / CPU per emitted line. 16 spaces is far
        // beyond any legitimate pretty-print width; larger requests saturate to it.
        const MAX_JSON_INDENT: usize = 16;
        let indent_width = (indent as usize).min(MAX_JSON_INDENT);
        let indent_string = " ".repeat(indent_width);
        let inner = serde_json::ser::PrettyFormatter::with_indent(indent_string.as_bytes());
        let mut ser = serde_json::Serializer::with_formatter(&mut buf, GoFormatter(inner));
        serde::Serialize::serialize(&val, &mut ser).ok();
    } else {
        let mut ser = serde_json::Serializer::with_formatter(
            &mut buf,
            GoFormatter(serde_json::ser::CompactFormatter),
        );
        serde::Serialize::serialize(&val, &mut ser).ok();
    }
    String::from_utf8(buf).unwrap_or_default()
}

/// Format an `f64` for JSON serialisation: exponent ('e') form only when the
/// magnitude is `< 1e-6` or `>= 1e21`; every other finite value uses plain
/// decimal ('f') form. Both forms use the shortest round-tripping digit sequence.
///   * 'f' form: `format!("{f}")` — Rust Display never emits an exponent.
///   * 'e' form: reshape `format!("{f:e}")` into `e±NN` exponent (`+`/`-` sign
///     always present; positive exponents zero-padded to ≥2 digits; negative
///     exponents use minimum digits — `e-0N` → `e-N`).
fn go_format_f64(f: f64) -> String {
    if !f.is_finite() {
        // serde_json routes NaN/∞ to `write_null` before `write_f64`, so this
        // is unreachable on the real path; the finite fallback keeps the helper
        // total (no panic) regardless.
        return "0".to_string();
    }
    let abs = f.abs();
    // Exponent form when `abs < 1e-6 || abs >= 1e21`; `!(1e-6..1e21).contains`
    // is the half-open complement (clippy-preferred spelling).
    let use_exp = abs != 0.0 && !(1e-6..1e21).contains(&abs);
    if !use_exp {
        return format!("{f}");
    }
    let rust_e = format!("{f:e}");
    match rust_e.split_once('e') {
        Some((mantissa, exp)) => match exp.parse::<i32>() {
            Ok(e) if e < 0 => format!("{mantissa}e-{}", -e),
            Ok(e) => format!("{mantissa}e+{e:02}"),
            // Unreachable: `{:e}` always emits a parseable integer exponent.
            Err(_) => rust_e,
        },
        // Unreachable: `{:e}` always contains an 'e'.
        None => rust_e,
    }
}

/// A [`serde_json::ser::Formatter`] that wraps an inner formatter and produces
/// JSON byte-compatible with Ipê's JSON encoder. Every structural / scalar
/// method delegates to the inner formatter (preserving compact-vs-pretty
/// layout); only `write_f64` and `write_string_fragment` are overridden.
struct GoFormatter<F>(F);

impl<F: serde_json::ser::Formatter> serde_json::ser::Formatter for GoFormatter<F> {
    fn write_f64<W>(&mut self, writer: &mut W, value: f64) -> std::io::Result<()>
    where
        W: ?Sized + std::io::Write,
    {
        writer.write_all(go_format_f64(value).as_bytes())
    }

    fn write_string_fragment<W>(&mut self, writer: &mut W, fragment: &str) -> std::io::Result<()>
    where
        W: ?Sized + std::io::Write,
    {
        // HTML-escape inside every JSON string (values AND keys):
        // `<`→<, `>`→>, `&`→&, and the JS line/paragraph
        // separators U+2028/U+2029. None of them can occur outside a string in
        // valid JSON, so escaping per-fragment is sufficient and exact.
        let bytes = fragment.as_bytes();
        let mut start = 0usize;
        for (i, c) in fragment.char_indices() {
            let escaped: Option<&[u8]> = match c {
                '<' => Some(b"\\u003c"),
                '>' => Some(b"\\u003e"),
                '&' => Some(b"\\u0026"),
                '\u{2028}' => Some(b"\\u2028"),
                '\u{2029}' => Some(b"\\u2029"),
                _ => None,
            };
            if let Some(esc) = escaped {
                if let Some(seg) = bytes.get(start..i) {
                    writer.write_all(seg)?;
                }
                writer.write_all(esc)?;
                start = i + c.len_utf8();
            }
        }
        if let Some(seg) = bytes.get(start..) {
            writer.write_all(seg)?;
        }
        Ok(())
    }

    // ── delegate everything else to the inner formatter ──────────────────────
    fn write_null<W>(&mut self, writer: &mut W) -> std::io::Result<()>
    where
        W: ?Sized + std::io::Write,
    {
        self.0.write_null(writer)
    }
    fn write_bool<W>(&mut self, writer: &mut W, value: bool) -> std::io::Result<()>
    where
        W: ?Sized + std::io::Write,
    {
        self.0.write_bool(writer, value)
    }
    fn write_i8<W>(&mut self, writer: &mut W, value: i8) -> std::io::Result<()>
    where
        W: ?Sized + std::io::Write,
    {
        self.0.write_i8(writer, value)
    }
    fn write_i16<W>(&mut self, writer: &mut W, value: i16) -> std::io::Result<()>
    where
        W: ?Sized + std::io::Write,
    {
        self.0.write_i16(writer, value)
    }
    fn write_i32<W>(&mut self, writer: &mut W, value: i32) -> std::io::Result<()>
    where
        W: ?Sized + std::io::Write,
    {
        self.0.write_i32(writer, value)
    }
    fn write_i64<W>(&mut self, writer: &mut W, value: i64) -> std::io::Result<()>
    where
        W: ?Sized + std::io::Write,
    {
        self.0.write_i64(writer, value)
    }
    fn write_i128<W>(&mut self, writer: &mut W, value: i128) -> std::io::Result<()>
    where
        W: ?Sized + std::io::Write,
    {
        self.0.write_i128(writer, value)
    }
    fn write_u8<W>(&mut self, writer: &mut W, value: u8) -> std::io::Result<()>
    where
        W: ?Sized + std::io::Write,
    {
        self.0.write_u8(writer, value)
    }
    fn write_u16<W>(&mut self, writer: &mut W, value: u16) -> std::io::Result<()>
    where
        W: ?Sized + std::io::Write,
    {
        self.0.write_u16(writer, value)
    }
    fn write_u32<W>(&mut self, writer: &mut W, value: u32) -> std::io::Result<()>
    where
        W: ?Sized + std::io::Write,
    {
        self.0.write_u32(writer, value)
    }
    fn write_u64<W>(&mut self, writer: &mut W, value: u64) -> std::io::Result<()>
    where
        W: ?Sized + std::io::Write,
    {
        self.0.write_u64(writer, value)
    }
    fn write_u128<W>(&mut self, writer: &mut W, value: u128) -> std::io::Result<()>
    where
        W: ?Sized + std::io::Write,
    {
        self.0.write_u128(writer, value)
    }
    fn write_f32<W>(&mut self, writer: &mut W, value: f32) -> std::io::Result<()>
    where
        W: ?Sized + std::io::Write,
    {
        self.0.write_f32(writer, value)
    }
    fn write_number_str<W>(&mut self, writer: &mut W, value: &str) -> std::io::Result<()>
    where
        W: ?Sized + std::io::Write,
    {
        self.0.write_number_str(writer, value)
    }
    fn begin_string<W>(&mut self, writer: &mut W) -> std::io::Result<()>
    where
        W: ?Sized + std::io::Write,
    {
        self.0.begin_string(writer)
    }
    fn end_string<W>(&mut self, writer: &mut W) -> std::io::Result<()>
    where
        W: ?Sized + std::io::Write,
    {
        self.0.end_string(writer)
    }
    fn write_char_escape<W>(
        &mut self,
        writer: &mut W,
        char_escape: serde_json::ser::CharEscape,
    ) -> std::io::Result<()>
    where
        W: ?Sized + std::io::Write,
    {
        self.0.write_char_escape(writer, char_escape)
    }
    fn begin_array<W>(&mut self, writer: &mut W) -> std::io::Result<()>
    where
        W: ?Sized + std::io::Write,
    {
        self.0.begin_array(writer)
    }
    fn end_array<W>(&mut self, writer: &mut W) -> std::io::Result<()>
    where
        W: ?Sized + std::io::Write,
    {
        self.0.end_array(writer)
    }
    fn begin_array_value<W>(&mut self, writer: &mut W, first: bool) -> std::io::Result<()>
    where
        W: ?Sized + std::io::Write,
    {
        self.0.begin_array_value(writer, first)
    }
    fn end_array_value<W>(&mut self, writer: &mut W) -> std::io::Result<()>
    where
        W: ?Sized + std::io::Write,
    {
        self.0.end_array_value(writer)
    }
    fn begin_object<W>(&mut self, writer: &mut W) -> std::io::Result<()>
    where
        W: ?Sized + std::io::Write,
    {
        self.0.begin_object(writer)
    }
    fn end_object<W>(&mut self, writer: &mut W) -> std::io::Result<()>
    where
        W: ?Sized + std::io::Write,
    {
        self.0.end_object(writer)
    }
    fn begin_object_key<W>(&mut self, writer: &mut W, first: bool) -> std::io::Result<()>
    where
        W: ?Sized + std::io::Write,
    {
        self.0.begin_object_key(writer, first)
    }
    fn end_object_key<W>(&mut self, writer: &mut W) -> std::io::Result<()>
    where
        W: ?Sized + std::io::Write,
    {
        self.0.end_object_key(writer)
    }
    fn begin_object_value<W>(&mut self, writer: &mut W) -> std::io::Result<()>
    where
        W: ?Sized + std::io::Write,
    {
        self.0.begin_object_value(writer)
    }
    fn end_object_value<W>(&mut self, writer: &mut W) -> std::io::Result<()>
    where
        W: ?Sized + std::io::Write,
    {
        self.0.end_object_value(writer)
    }
    fn write_raw_fragment<W>(&mut self, writer: &mut W, fragment: &str) -> std::io::Result<()>
    where
        W: ?Sized + std::io::Write,
    {
        self.0.write_raw_fragment(writer, fragment)
    }
}
pub fn json_enc_string(s: String) -> JsonVal {
    JsonVal::String(s)
}
pub fn json_enc_int(i: i64) -> JsonVal {
    JsonVal::Number(i.into())
}
pub fn json_enc_float(f: f64) -> JsonVal {
    JsonVal::from(f)
}
pub fn json_enc_bool(b: bool) -> JsonVal {
    JsonVal::Bool(b)
}
pub fn json_enc_null() -> JsonVal {
    JsonVal::Null
}
pub fn json_enc_list<A>(f: impl Fn(A) -> JsonVal, items: Vec<A>) -> JsonVal {
    JsonVal::Array(items.into_iter().map(f).collect())
}
pub fn json_enc_object(pairs: Vec<(String, JsonVal)>) -> JsonVal {
    JsonVal::Object(pairs.into_iter().collect())
}

/// Recursively rebuild a value with every object's keys in ascending order,
/// regardless of the ambient `serde_json` object-order behaviour (the
/// `preserve_order` cargo feature makes `Value::Object` insertion-ordered, so a
/// plain re-encode is not canonical on its own).
fn sort_object_keys(val: &JsonVal) -> JsonVal {
    match val {
        JsonVal::Object(map) => {
            let mut entries: Vec<(&String, &JsonVal)> = map.iter().collect();
            entries.sort_by_key(|(k, _)| *k);
            JsonVal::Object(
                entries
                    .into_iter()
                    .map(|(k, v)| (k.clone(), sort_object_keys(v)))
                    .collect(),
            )
        }
        JsonVal::Array(items) => JsonVal::Array(items.iter().map(sort_object_keys).collect()),
        other => other.clone(),
    }
}

/// Serialize a value to deterministic sorted-key canonical JSON: object keys are
/// sorted ascending at every nesting depth, then encoded through the standard
/// compact encoder. Two values with the same key/value content always produce
/// identical bytes, which signed payloads (JWT, auth tokens) depend on for a
/// stable signature — a property proven here rather than inherited from a global
/// encoder-ordering setting.
pub fn json_enc_canonical(val: &JsonVal) -> String {
    json_enc_encode(0, sort_object_keys(val))
}

// --- Decode primitives ---
pub fn json_decode_string<E: From<String> + 'static>() -> Decoder<E, String> {
    Decoder::new(
        Box::new(|v| match v {
            JsonVal::String(s) => decode_ok(s.clone()),
            _ => decode_err_str("expected string".into()),
        }),
        vec![],
    )
}
pub fn json_decode_int<E: From<String> + 'static>() -> Decoder<E, i64> {
    Decoder::new(
        // Parse-don't-validate: an integer decoder yields an integer or a typed
        // rejection — never a silently truncated value. A fractional number
        // (`1.5`) or a magnitude past `i64` (`1e21`) is malformed input for an
        // `Int` field, so it fails closed rather than smuggling in a lossily
        // coerced value. An integral JSON number written in float form (`1.0`)
        // still decodes, matching a caller's intent. `serde_json::Number::as_i64`
        // performs exactly this: `Some` iff the number is an integer in range.
        Box::new(|v| match v {
            JsonVal::Number(n) => match n.as_i64() {
                Some(i) => decode_ok(i),
                // `1.0` is stored as a float; recover it when it is integral and
                // representable, rejecting `1.5` and out-of-range values. Both
                // bounds are *strict* because f64 cannot distinguish a boundary
                // from its out-of-range neighbour: `i64::MAX as f64` rounds up
                // to `2^63` and `i64::MIN-1` rounds down to `i64::MIN as f64`,
                // so `<=`/`>=` would admit an out-of-range integer and let
                // `f as i64` saturate to the limit — a silent wrong value. An
                // exact `i64::MIN`/`i64::MAX` arrives as an integer through
                // `as_i64` above; this fallback only admits the open interval.
                None => match n.as_f64() {
                    Some(f)
                        if f.fract() == 0.0 && f > (i64::MIN as f64) && f < (i64::MAX as f64) =>
                    {
                        decode_ok(f as i64)
                    }
                    _ => decode_err_str("expected int, got a non-integer number".into()),
                },
            },
            _ => decode_err_str("expected int".into()),
        }),
        vec![],
    )
}
pub fn json_decode_float<E: From<String> + 'static>() -> Decoder<E, f64> {
    Decoder::new(
        Box::new(|v| match v.as_f64() {
            Some(f) => decode_ok(f),
            None => decode_err_str("expected float".into()),
        }),
        vec![],
    )
}
pub fn json_decode_bool<E: From<String> + 'static>() -> Decoder<E, bool> {
    Decoder::new(
        Box::new(|v| match v.as_bool() {
            Some(b) => decode_ok(b),
            None => decode_err_str("expected bool".into()),
        }),
        vec![],
    )
}
pub fn json_decode_null<E: From<String> + 'static, A: Default + Send>() -> Decoder<E, A> {
    Decoder::new(
        Box::new(|v| match v {
            JsonVal::Null => decode_ok(A::default()),
            _ => decode_err_str("expected null".into()),
        }),
        vec![],
    )
}

// --- Decode combinators ---
pub fn decode_field<E: From<String> + 'static, T: 'static + Send>(
    name: String,
    decoder: Decoder<E, T>,
) -> Decoder<E, T> {
    let fields = vec![name.clone()];
    Decoder::new(
        Box::new(move |v| match v.get(&name) {
            Some(field) => (decoder.run)(field),
            None => decode_err_str(format!("missing field: {}", name)),
        }),
        fields,
    )
}

/// `JsonDec.index : Int -> Decoder a -> Decoder a` — decode the n-th element
/// of a JSON array. Out-of-bounds or non-array input is `Err`. The path prefix
/// `"[N]"` is inlined in the error message.
pub fn decode_index<E: From<String> + 'static, T: 'static + Send>(
    n: i64,
    decoder: Decoder<E, T>,
) -> Decoder<E, T> {
    let inner_fields = decoder.fields.clone();
    Decoder::new(
        Box::new(move |v| match v.as_array() {
            None => decode_err_str(format!("[{}]: expected array", n)),
            Some(arr) => {
                let idx = n as usize;
                match arr.get(idx) {
                    None => {
                        decode_err_str(format!("[{}]: index out of range (len={})", n, arr.len()))
                    }
                    Some(elem) => (decoder.run)(elem),
                }
            }
        }),
        inner_fields,
    )
}

pub fn decode_at<E: From<String> + 'static, T: 'static + Send>(
    path: Vec<String>,
    decoder: Decoder<E, T>,
) -> Decoder<E, T> {
    let inner_fields = decoder.fields.clone();
    Decoder::new(
        Box::new(move |v| {
            let mut cur = v;
            for key in &path {
                match cur.get(key) {
                    Some(n) => cur = n,
                    None => return decode_err_str(format!("missing path: {}", key)),
                }
            }
            (decoder.run)(cur)
        }),
        inner_fields,
    )
}
pub fn decode_list<E: From<String> + 'static, T: 'static + Send>(
    decoder: Decoder<E, T>,
) -> Decoder<E, Vec<T>> {
    Decoder::new(
        Box::new(move |v| match v.as_array() {
            Some(arr) => {
                let mut out = Vec::with_capacity(arr.len());
                // `Decoder::run` is a `Fn`, so one decoder instance decodes every
                // element of every document this list-decoder runs against — the
                // captured `decoder` is borrowed, never moved or rebuilt.
                let d = &decoder;
                for item in arr {
                    match (d.run)(item) {
                        IpeResult::Ok(t) => out.push(t),
                        // Surface the REAL inner-element error rather than
                        // collapsing it to a generic "decode error" — preserves
                        // the per-element diagnostic.
                        IpeResult::Err(e) => return IpeResult::Err(e),
                    }
                }
                decode_ok(out)
            }
            None => decode_err_str("expected array".into()),
        }),
        vec![],
    )
}
pub fn decode_map<E: From<String> + 'static, A: 'static + Send, B: 'static + Send>(
    f: impl Fn(A) -> B + Send + Sync + 'static,
    decoder: Decoder<E, A>,
) -> Decoder<E, B> {
    let inner_fields = decoder.fields.clone();
    Decoder::new(
        Box::new(move |v| match (decoder.run)(v) {
            IpeResult::Ok(a) => decode_ok(f(a)),
            IpeResult::Err(e) => IpeResult::Err(e),
        }),
        inner_fields,
    )
}
// `map2`/`map3`/`map4` — combine 2/3/4 decoders over the SAME JSON value with an
// N-ary function. Each runs against `v`; the first Err short-circuits (real
// error propagated, not collapsed to a generic string). Total, no panic.
pub fn decode_map2<
    E: From<String> + 'static,
    A: 'static + Send,
    B: 'static + Send,
    C: 'static + Send,
>(
    f: impl Fn(A, B) -> C + Send + Sync + 'static,
    da: Decoder<E, A>,
    db: Decoder<E, B>,
) -> Decoder<E, C> {
    let mut fields = da.fields.clone();
    union_fields(&mut fields, &db.fields);
    Decoder::new(
        Box::new(move |v| {
            let a = match (da.run)(v) {
                IpeResult::Ok(a) => a,
                IpeResult::Err(e) => return IpeResult::Err(e),
            };
            let b = match (db.run)(v) {
                IpeResult::Ok(b) => b,
                IpeResult::Err(e) => return IpeResult::Err(e),
            };
            decode_ok(f(a, b))
        }),
        fields,
    )
}
pub fn decode_map3<
    E: From<String> + 'static,
    A: 'static + Send,
    B: 'static + Send,
    C: 'static + Send,
    D: 'static + Send,
>(
    f: impl Fn(A, B, C) -> D + Send + Sync + 'static,
    da: Decoder<E, A>,
    db: Decoder<E, B>,
    dc: Decoder<E, C>,
) -> Decoder<E, D> {
    let mut fields = da.fields.clone();
    union_fields(&mut fields, &db.fields);
    union_fields(&mut fields, &dc.fields);
    Decoder::new(
        Box::new(move |v| {
            let a = match (da.run)(v) {
                IpeResult::Ok(a) => a,
                IpeResult::Err(e) => return IpeResult::Err(e),
            };
            let b = match (db.run)(v) {
                IpeResult::Ok(b) => b,
                IpeResult::Err(e) => return IpeResult::Err(e),
            };
            let c = match (dc.run)(v) {
                IpeResult::Ok(c) => c,
                IpeResult::Err(e) => return IpeResult::Err(e),
            };
            decode_ok(f(a, b, c))
        }),
        fields,
    )
}
pub fn decode_map4<
    E: From<String> + 'static,
    A: 'static + Send,
    B: 'static + Send,
    C: 'static + Send,
    D: 'static + Send,
    G: 'static + Send,
>(
    f: impl Fn(A, B, C, D) -> G + Send + Sync + 'static,
    da: Decoder<E, A>,
    db: Decoder<E, B>,
    dc: Decoder<E, C>,
    dd: Decoder<E, D>,
) -> Decoder<E, G> {
    let mut fields = da.fields.clone();
    union_fields(&mut fields, &db.fields);
    union_fields(&mut fields, &dc.fields);
    union_fields(&mut fields, &dd.fields);
    Decoder::new(
        Box::new(move |v| {
            let a = match (da.run)(v) {
                IpeResult::Ok(a) => a,
                IpeResult::Err(e) => return IpeResult::Err(e),
            };
            let b = match (db.run)(v) {
                IpeResult::Ok(b) => b,
                IpeResult::Err(e) => return IpeResult::Err(e),
            };
            let c = match (dc.run)(v) {
                IpeResult::Ok(c) => c,
                IpeResult::Err(e) => return IpeResult::Err(e),
            };
            let d = match (dd.run)(v) {
                IpeResult::Ok(d) => d,
                IpeResult::Err(e) => return IpeResult::Err(e),
            };
            decode_ok(f(a, b, c, d))
        }),
        fields,
    )
}
// `map5` — combine 5 decoders over the SAME value with a 5-arg function.
// Mirrors map2/map3/map4 exactly; first Err short-circuits with the real error.
pub fn decode_map5<
    E: From<String> + 'static,
    A: 'static + Send,
    B: 'static + Send,
    C: 'static + Send,
    D: 'static + Send,
    G: 'static + Send,
    H: 'static + Send,
>(
    f: impl Fn(A, B, C, D, G) -> H + Send + Sync + 'static,
    da: Decoder<E, A>,
    db: Decoder<E, B>,
    dc: Decoder<E, C>,
    dd: Decoder<E, D>,
    de: Decoder<E, G>,
) -> Decoder<E, H> {
    let mut fields = da.fields.clone();
    union_fields(&mut fields, &db.fields);
    union_fields(&mut fields, &dc.fields);
    union_fields(&mut fields, &dd.fields);
    union_fields(&mut fields, &de.fields);
    Decoder::new(
        Box::new(move |v| {
            let a = match (da.run)(v) {
                IpeResult::Ok(a) => a,
                IpeResult::Err(e) => return IpeResult::Err(e),
            };
            let b = match (db.run)(v) {
                IpeResult::Ok(b) => b,
                IpeResult::Err(e) => return IpeResult::Err(e),
            };
            let c = match (dc.run)(v) {
                IpeResult::Ok(c) => c,
                IpeResult::Err(e) => return IpeResult::Err(e),
            };
            let d = match (dd.run)(v) {
                IpeResult::Ok(d) => d,
                IpeResult::Err(e) => return IpeResult::Err(e),
            };
            let e = match (de.run)(v) {
                IpeResult::Ok(e) => e,
                IpeResult::Err(err) => return IpeResult::Err(err),
            };
            decode_ok(f(a, b, c, d, e))
        }),
        fields,
    )
}

// `map6`/`map7`/`map8` — combine 6/7/8 decoders over the SAME value with an
// N-ary function. Mirror map2..5 exactly; first Err short-circuits with the real
// error. Total, no panic.
#[allow(clippy::type_complexity, clippy::too_many_arguments)]
pub fn decode_map6<
    E: From<String> + 'static,
    A: 'static + Send,
    B: 'static + Send,
    C: 'static + Send,
    D: 'static + Send,
    G: 'static + Send,
    H: 'static + Send,
    R: 'static + Send,
>(
    f: impl Fn(A, B, C, D, G, H) -> R + Send + Sync + 'static,
    da: Decoder<E, A>,
    db: Decoder<E, B>,
    dc: Decoder<E, C>,
    dd: Decoder<E, D>,
    de: Decoder<E, G>,
    df: Decoder<E, H>,
) -> Decoder<E, R> {
    let mut fields = da.fields.clone();
    union_fields(&mut fields, &db.fields);
    union_fields(&mut fields, &dc.fields);
    union_fields(&mut fields, &dd.fields);
    union_fields(&mut fields, &de.fields);
    union_fields(&mut fields, &df.fields);
    Decoder::new(
        Box::new(move |v| {
            let a = match (da.run)(v) {
                IpeResult::Ok(a) => a,
                IpeResult::Err(e) => return IpeResult::Err(e),
            };
            let b = match (db.run)(v) {
                IpeResult::Ok(b) => b,
                IpeResult::Err(e) => return IpeResult::Err(e),
            };
            let c = match (dc.run)(v) {
                IpeResult::Ok(c) => c,
                IpeResult::Err(e) => return IpeResult::Err(e),
            };
            let d = match (dd.run)(v) {
                IpeResult::Ok(d) => d,
                IpeResult::Err(e) => return IpeResult::Err(e),
            };
            let g = match (de.run)(v) {
                IpeResult::Ok(g) => g,
                IpeResult::Err(e) => return IpeResult::Err(e),
            };
            let h = match (df.run)(v) {
                IpeResult::Ok(h) => h,
                IpeResult::Err(e) => return IpeResult::Err(e),
            };
            decode_ok(f(a, b, c, d, g, h))
        }),
        fields,
    )
}
#[allow(clippy::type_complexity, clippy::too_many_arguments)]
pub fn decode_map7<
    E: From<String> + 'static,
    A: 'static + Send,
    B: 'static + Send,
    C: 'static + Send,
    D: 'static + Send,
    G: 'static + Send,
    H: 'static + Send,
    I: 'static + Send,
    R: 'static + Send,
>(
    f: impl Fn(A, B, C, D, G, H, I) -> R + Send + Sync + 'static,
    da: Decoder<E, A>,
    db: Decoder<E, B>,
    dc: Decoder<E, C>,
    dd: Decoder<E, D>,
    de: Decoder<E, G>,
    df: Decoder<E, H>,
    dg: Decoder<E, I>,
) -> Decoder<E, R> {
    let mut fields = da.fields.clone();
    union_fields(&mut fields, &db.fields);
    union_fields(&mut fields, &dc.fields);
    union_fields(&mut fields, &dd.fields);
    union_fields(&mut fields, &de.fields);
    union_fields(&mut fields, &df.fields);
    union_fields(&mut fields, &dg.fields);
    Decoder::new(
        Box::new(move |v| {
            let a = match (da.run)(v) {
                IpeResult::Ok(a) => a,
                IpeResult::Err(e) => return IpeResult::Err(e),
            };
            let b = match (db.run)(v) {
                IpeResult::Ok(b) => b,
                IpeResult::Err(e) => return IpeResult::Err(e),
            };
            let c = match (dc.run)(v) {
                IpeResult::Ok(c) => c,
                IpeResult::Err(e) => return IpeResult::Err(e),
            };
            let d = match (dd.run)(v) {
                IpeResult::Ok(d) => d,
                IpeResult::Err(e) => return IpeResult::Err(e),
            };
            let g = match (de.run)(v) {
                IpeResult::Ok(g) => g,
                IpeResult::Err(e) => return IpeResult::Err(e),
            };
            let h = match (df.run)(v) {
                IpeResult::Ok(h) => h,
                IpeResult::Err(e) => return IpeResult::Err(e),
            };
            let i = match (dg.run)(v) {
                IpeResult::Ok(i) => i,
                IpeResult::Err(e) => return IpeResult::Err(e),
            };
            decode_ok(f(a, b, c, d, g, h, i))
        }),
        fields,
    )
}
#[allow(clippy::type_complexity, clippy::too_many_arguments)]
pub fn decode_map8<
    E: From<String> + 'static,
    A: 'static + Send,
    B: 'static + Send,
    C: 'static + Send,
    D: 'static + Send,
    G: 'static + Send,
    H: 'static + Send,
    I: 'static + Send,
    J: 'static + Send,
    R: 'static + Send,
>(
    f: impl Fn(A, B, C, D, G, H, I, J) -> R + Send + Sync + 'static,
    da: Decoder<E, A>,
    db: Decoder<E, B>,
    dc: Decoder<E, C>,
    dd: Decoder<E, D>,
    de: Decoder<E, G>,
    df: Decoder<E, H>,
    dg: Decoder<E, I>,
    dh: Decoder<E, J>,
) -> Decoder<E, R> {
    let mut fields = da.fields.clone();
    union_fields(&mut fields, &db.fields);
    union_fields(&mut fields, &dc.fields);
    union_fields(&mut fields, &dd.fields);
    union_fields(&mut fields, &de.fields);
    union_fields(&mut fields, &df.fields);
    union_fields(&mut fields, &dg.fields);
    union_fields(&mut fields, &dh.fields);
    Decoder::new(
        Box::new(move |v| {
            let a = match (da.run)(v) {
                IpeResult::Ok(a) => a,
                IpeResult::Err(e) => return IpeResult::Err(e),
            };
            let b = match (db.run)(v) {
                IpeResult::Ok(b) => b,
                IpeResult::Err(e) => return IpeResult::Err(e),
            };
            let c = match (dc.run)(v) {
                IpeResult::Ok(c) => c,
                IpeResult::Err(e) => return IpeResult::Err(e),
            };
            let d = match (dd.run)(v) {
                IpeResult::Ok(d) => d,
                IpeResult::Err(e) => return IpeResult::Err(e),
            };
            let g = match (de.run)(v) {
                IpeResult::Ok(g) => g,
                IpeResult::Err(e) => return IpeResult::Err(e),
            };
            let h = match (df.run)(v) {
                IpeResult::Ok(h) => h,
                IpeResult::Err(e) => return IpeResult::Err(e),
            };
            let i = match (dg.run)(v) {
                IpeResult::Ok(i) => i,
                IpeResult::Err(e) => return IpeResult::Err(e),
            };
            let j = match (dh.run)(v) {
                IpeResult::Ok(j) => j,
                IpeResult::Err(e) => return IpeResult::Err(e),
            };
            decode_ok(f(a, b, c, d, g, h, i, j))
        }),
        fields,
    )
}

/// `andMap : Decoder a -> Decoder (a -> b) -> Decoder b` — applicative apply.
/// Ipê's pipe form: `succeed Ctor |> andMap decA |> andMap decB` chains as
/// `andMap decB (andMap decA (succeed Ctor))` — the VALUE decoder is the first
/// arg, the FUNCTION decoder is the second.
/// Matches Ipê's `Ipe.Db.Decode.ipe` line: `andMap : Decoder a -> Decoder (a -> b) -> Decoder b`.
pub fn decode_and_map<E: From<String> + 'static, A: 'static + Send, B: 'static + Send>(
    dec_val: Decoder<E, A>,
    dec_fn: Decoder<E, Box<dyn FnOnce(A) -> B + Send>>,
) -> Decoder<E, B> {
    let mut fields = dec_fn.fields.clone();
    union_fields(&mut fields, &dec_val.fields);
    Decoder::new(
        Box::new(move |v| {
            // Evaluate the function decoder first (pipeline accumulator), then the value.
            let f = match (dec_fn.run)(v) {
                IpeResult::Ok(f) => f,
                IpeResult::Err(e) => return IpeResult::Err(e),
            };
            let a = match (dec_val.run)(v) {
                IpeResult::Ok(a) => a,
                IpeResult::Err(e) => return IpeResult::Err(e),
            };
            decode_ok(f(a))
        }),
        fields,
    )
}
pub fn decode_and_then<E: From<String> + 'static, A: 'static + Send, B: 'static + Send>(
    decoder: Decoder<E, A>,
    f: impl Fn(A) -> Decoder<E, B> + Send + Sync + 'static,
) -> Decoder<E, B> {
    let inner_fields = decoder.fields.clone();
    Decoder::new(
        Box::new(move |val| match (decoder.run)(val) {
            IpeResult::Ok(a) => (f(a).run)(val),
            IpeResult::Err(e) => IpeResult::Err(e),
        }),
        inner_fields,
    )
}

// --- Succeed / Fail / OneOf ---
/// `Decode.succeed : a -> Decoder a`
///
/// Accepts a **factory** `Box<dyn Fn() -> A + Send>` that produces a fresh `A`
/// on every call to the decoder's `run`.  This makes the decoder reusable across
/// multiple rows (`db_query_decode` calls `run` once per row).
///
/// The generated Rust code always calls this as `decode_succeed(curryN(ctor))`
/// where `curryN` now returns a factory closure that produces a fresh `FnOnce`
/// chain on each invocation.  Since `ctor` is either a `fn` pointer (Copy) or a
/// non-capturing closure (also Copy/Clone in Rust), the factory can capture it
/// by value and produce fresh chains on demand.
///
/// Multi-row correctness: each call to `succeed.run` calls `factory()` to get a
/// fresh `A`; the `FnOnce` chain is consumed exactly once per row by the
/// enclosing pipeline combinators — correct by construction.
pub fn decode_succeed<E: From<String> + 'static, A: 'static + Send>(
    factory: Box<dyn Fn() -> A + Send + Sync>,
) -> Decoder<E, A> {
    Decoder::new(Box::new(move |_| decode_ok((factory)())), vec![])
}
pub fn decode_fail<E: From<String> + 'static, A: 'static + Send>(msg: String) -> Decoder<E, A> {
    let m = msg;
    Decoder::new(Box::new(move |_| decode_err_str(m.clone())), vec![])
}
pub fn decode_one_of<E: From<String> + 'static, T: 'static + Send>(
    decoders: Vec<Decoder<E, T>>,
) -> Decoder<E, T> {
    Decoder::new(
        Box::new(move |v| {
            // Try each branch; on total failure surface the LAST branch's real
            // error rather than a generic "oneOf: no match".
            let mut last_err: Option<IpeResult<E, T>> = None;
            for d in &decoders {
                let r = (d.run)(v);
                if r.is_ok() {
                    return r;
                }
                last_err = Some(r);
            }
            last_err.unwrap_or_else(|| decode_err_str("oneOf: no match".into()))
        }),
        vec![],
    )
}
/// `nullable : Decoder a -> Decoder (Maybe a)` — a JSON `null` decodes to
/// `Nothing`; any other value decodes to `Just` of the inner decode, and an
/// inner failure on a present (non-null) value PROPAGATES (it is not swallowed).
/// Returns Ipê's `IpeMaybe` so the decoded value matches the `Maybe a` the Ipê
/// annotation lowers to. Shared by `Json.Decode`, `Config`, and `Db.Decode`
/// over the unified `Decoder` carrier.
pub fn decode_nullable<E: From<String> + 'static, T: 'static + Send>(
    decoder: Decoder<E, T>,
) -> Decoder<E, IpeMaybe<T>> {
    let inner_fields = decoder.fields.clone();
    Decoder::new(
        Box::new(move |v| match v {
            JsonVal::Null => IpeResult::Ok(IpeMaybe::Nothing),
            _ => match (decoder.run)(v) {
                IpeResult::Ok(t) => IpeResult::Ok(IpeMaybe::Just(t)),
                IpeResult::Err(e) => IpeResult::Err(e),
            },
        }),
        inner_fields,
    )
}

/// `keyValuePairs : Decoder a -> Decoder (List (String, a))` — decode every
/// entry of a JSON object, applying `decoder` to each value. Non-object input
/// is `Err`; the first entry whose value fails to decode short-circuits with
/// its real error. The one decoder instance is borrowed across entries and
/// across every document this decoder runs against (like `decode_list`).
pub fn decode_key_value_pairs<E: From<String> + 'static, T: 'static + Send>(
    decoder: Decoder<E, T>,
) -> Decoder<E, Vec<(String, T)>> {
    Decoder::new(
        Box::new(move |v| match v.as_object() {
            Some(obj) => {
                let d = &decoder;
                let mut out = Vec::with_capacity(obj.len());
                for (key, val) in obj {
                    match (d.run)(val) {
                        IpeResult::Ok(t) => out.push((key.clone(), t)),
                        IpeResult::Err(e) => return IpeResult::Err(e),
                    }
                }
                decode_ok(out)
            }
            None => decode_err_str("expected object".into()),
        }),
        vec![],
    )
}
pub fn decode_from_json_string<E: From<String> + 'static, T>(
    decoder: Decoder<E, T>,
    json: String,
) -> IpeResult<E, T> {
    match serde_json::from_str(&json) {
        Ok(val) => (decoder.run)(&val),
        Err(e) => decode_err_str(format!("json parse: {}", e)),
    }
}

/// `Json.Decode.value : Decoder Value` — the identity decoder.
///
/// Yields the JSON node it is run against, unchanged, so a caller can
/// re-serialise it (`Json.Encode.encode`) or run a further decoder on it. This
/// is the same node the encode direction of a codec produces, so no re-parse and
/// no second decoder are involved.
pub fn decode_value_identity<E: From<String> + 'static>() -> Decoder<E, JsonVal> {
    Decoder::new(Box::new(move |v| decode_ok(v.clone())), vec![])
}

/// `Json.Decode.decodeValue : Decoder a -> Value -> Result Error a` — run a
/// decoder against an in-memory `Value`.
///
/// This is exactly the tail of `decode_from_json_string` after its parse step:
/// the SAME `(decoder.run)(&val)` decode path, given a `Value` already in memory
/// rather than a string to parse. There is no second decoder and no string
/// round-trip; a value the decoder rejects is a typed `Err`, never a panic.
pub fn decode_from_json_value<E: From<String> + 'static, T>(
    decoder: Decoder<E, T>,
    val: JsonVal,
) -> IpeResult<E, T> {
    (decoder.run)(&val)
}

// --- Currying helpers (for pipeline decoder composition) ---
//
// Each helper now returns a FACTORY: `Box<dyn Fn() -> Box<dyn FnOnce(A1) -> ...> + Send>`.
//
// This is the key change that enables multi-row decoding.  `decode_succeed`
// stores this factory and calls it once per `run` invocation (once per DB row).
// Each factory call produces a fresh `FnOnce` chain that can be threaded through
// the pipeline combinators exactly once — which is all that's needed per row.
//
// Correctness argument:
//   - The factory closure captures `f` by COPY (fn pointers and non-capturing
//     closures in Rust are `Copy`, hence `Clone`; `F: Fn + Clone` covers both).
//   - Each factory call produces a genuinely fresh `Box<dyn FnOnce>` chain —
//     no shared state, no interior mutability, fully total.
//   - `decode_pipeline_required` / `db_decode_required` etc. call `(nd.run)(v)` once
//     per row, consuming the `FnOnce` exactly once — correct.
//   - Total: no panic, no unwrap — only `IpeResult::Err` on decode failure.
//
// Bounds: `F: Fn(A1,..) -> R + Clone + Send` — fn pointers are Copy ⊆ Clone;
// non-capturing closures in Rust are Copy ⊆ Clone.
pub fn curry1<
    A: 'static + Send,
    R: 'static + Send,
    F: Fn(A) -> R + Clone + Send + Sync + 'static,
>(
    f: F,
) -> Box<dyn Fn() -> Box<dyn FnOnce(A) -> R + Send> + Send + Sync> {
    Box::new(move || {
        let f = f.clone();
        Box::new(f)
    })
}
pub fn curry2<
    A1: 'static + Send,
    A2: 'static + Send,
    R: 'static + Send,
    F: Fn(A1, A2) -> R + Clone + Send + Sync + 'static,
>(
    f: F,
) -> Box<dyn Fn() -> Box<dyn FnOnce(A1) -> Box<dyn FnOnce(A2) -> R + Send> + Send> + Send + Sync> {
    Box::new(move || {
        let f = f.clone();
        Box::new(move |a1| {
            let f = f;
            Box::new(move |a2| f(a1, a2))
        })
    })
}
pub fn curry3<
    A1: 'static + Send,
    A2: 'static + Send,
    A3: 'static + Send,
    R: 'static + Send,
    F: Fn(A1, A2, A3) -> R + Clone + Send + Sync + 'static,
>(
    f: F,
) -> Box<
    dyn Fn() -> Box<
            dyn FnOnce(A1) -> Box<dyn FnOnce(A2) -> Box<dyn FnOnce(A3) -> R + Send> + Send> + Send,
        > + Send
        + Sync,
> {
    Box::new(move || {
        let f = f.clone();
        Box::new(move |a1| {
            let f = f;
            Box::new(move |a2| {
                let f = f;
                Box::new(move |a3| f(a1, a2, a3))
            })
        })
    })
}
pub fn curry4<
    A1: 'static + Send,
    A2: 'static + Send,
    A3: 'static + Send,
    A4: 'static + Send,
    R: 'static + Send,
    F: Fn(A1, A2, A3, A4) -> R + Clone + Send + Sync + 'static,
>(
    f: F,
) -> Box<
    dyn Fn() -> Box<
            dyn FnOnce(
                    A1,
                ) -> Box<
                    dyn FnOnce(A2) -> Box<dyn FnOnce(A3) -> Box<dyn FnOnce(A4) -> R + Send> + Send>
                        + Send,
                > + Send,
        > + Send
        + Sync,
> {
    Box::new(move || {
        let f = f.clone();
        Box::new(move |a1| {
            let f = f;
            Box::new(move |a2| {
                let f = f;
                Box::new(move |a3| {
                    let f = f;
                    Box::new(move |a4| f(a1, a2, a3, a4))
                })
            })
        })
    })
}
pub fn curry5<
    A1: 'static + Send,
    A2: 'static + Send,
    A3: 'static + Send,
    A4: 'static + Send,
    A5: 'static + Send,
    R: 'static + Send,
    F: Fn(A1, A2, A3, A4, A5) -> R + Clone + Send + Sync + 'static,
>(
    f: F,
) -> Box<
    dyn Fn() -> Box<
            dyn FnOnce(
                    A1,
                ) -> Box<
                    dyn FnOnce(
                            A2,
                        ) -> Box<
                            dyn FnOnce(
                                    A3,
                                ) -> Box<
                                    dyn FnOnce(A4) -> Box<dyn FnOnce(A5) -> R + Send> + Send,
                                > + Send,
                        > + Send,
                > + Send,
        > + Send
        + Sync,
> {
    Box::new(move || {
        let f = f.clone();
        Box::new(move |a1| {
            let f = f;
            Box::new(move |a2| {
                let f = f;
                Box::new(move |a3| {
                    let f = f;
                    Box::new(move |a4| {
                        let f = f;
                        Box::new(move |a5| f(a1, a2, a3, a4, a5))
                    })
                })
            })
        })
    })
}
pub fn curry6<
    A1: 'static + Send,
    A2: 'static + Send,
    A3: 'static + Send,
    A4: 'static + Send,
    A5: 'static + Send,
    A6: 'static + Send,
    R: 'static + Send,
    F: Fn(A1, A2, A3, A4, A5, A6) -> R + Clone + Send + Sync + 'static,
>(
    f: F,
) -> Box<
    dyn Fn() -> Box<
            dyn FnOnce(
                    A1,
                ) -> Box<
                    dyn FnOnce(
                            A2,
                        ) -> Box<
                            dyn FnOnce(
                                    A3,
                                ) -> Box<
                                    dyn FnOnce(
                                            A4,
                                        ) -> Box<
                                            dyn FnOnce(A5) -> Box<dyn FnOnce(A6) -> R + Send>
                                                + Send,
                                        > + Send,
                                > + Send,
                        > + Send,
                > + Send,
        > + Send
        + Sync,
> {
    Box::new(move || {
        let f = f.clone();
        Box::new(move |a1| {
            let f = f;
            Box::new(move |a2| {
                let f = f;
                Box::new(move |a3| {
                    let f = f;
                    Box::new(move |a4| {
                        let f = f;
                        Box::new(move |a5| {
                            let f = f;
                            Box::new(move |a6| f(a1, a2, a3, a4, a5, a6))
                        })
                    })
                })
            })
        })
    })
}
pub fn curry7<
    A1: 'static + Send,
    A2: 'static + Send,
    A3: 'static + Send,
    A4: 'static + Send,
    A5: 'static + Send,
    A6: 'static + Send,
    A7: 'static + Send,
    R: 'static + Send,
    F: Fn(A1, A2, A3, A4, A5, A6, A7) -> R + Clone + Send + Sync + 'static,
>(
    f: F,
) -> Box<
    dyn Fn() -> Box<
            dyn FnOnce(
                    A1,
                ) -> Box<
                    dyn FnOnce(
                            A2,
                        ) -> Box<
                            dyn FnOnce(
                                    A3,
                                ) -> Box<
                                    dyn FnOnce(
                                            A4,
                                        ) -> Box<
                                            dyn FnOnce(
                                                    A5,
                                                )
                                                    -> Box<
                                                    dyn FnOnce(
                                                            A6,
                                                        )
                                                            -> Box<dyn FnOnce(A7) -> R + Send>
                                                        + Send,
                                                > + Send,
                                        > + Send,
                                > + Send,
                        > + Send,
                > + Send,
        > + Send
        + Sync,
> {
    Box::new(move || {
        let f = f.clone();
        Box::new(move |a1| {
            let f = f;
            Box::new(move |a2| {
                let f = f;
                Box::new(move |a3| {
                    let f = f;
                    Box::new(move |a4| {
                        let f = f;
                        Box::new(move |a5| {
                            let f = f;
                            Box::new(move |a6| {
                                let f = f;
                                Box::new(move |a7| f(a1, a2, a3, a4, a5, a6, a7))
                            })
                        })
                    })
                })
            })
        })
    })
}
pub fn curry8<
    A1: 'static + Send,
    A2: 'static + Send,
    A3: 'static + Send,
    A4: 'static + Send,
    A5: 'static + Send,
    A6: 'static + Send,
    A7: 'static + Send,
    A8: 'static + Send,
    R: 'static + Send,
    F: Fn(A1, A2, A3, A4, A5, A6, A7, A8) -> R + Clone + Send + Sync + 'static,
>(
    f: F,
) -> Box<
    dyn Fn() -> Box<
            dyn FnOnce(
                    A1,
                ) -> Box<
                    dyn FnOnce(
                            A2,
                        ) -> Box<
                            dyn FnOnce(
                                    A3,
                                ) -> Box<
                                    dyn FnOnce(
                                            A4,
                                        ) -> Box<
                                            dyn FnOnce(
                                                    A5,
                                                )
                                                    -> Box<
                                                    dyn FnOnce(
                                                            A6,
                                                        )
                                                            -> Box<
                                                            dyn FnOnce(
                                                                    A7,
                                                                )
                                                                    -> Box<
                                                                    dyn FnOnce(A8) -> R + Send,
                                                                > + Send,
                                                        > + Send,
                                                > + Send,
                                        > + Send,
                                > + Send,
                        > + Send,
                > + Send,
        > + Send
        + Sync,
> {
    Box::new(move || {
        let f = f.clone();
        Box::new(move |a1| {
            let f = f;
            Box::new(move |a2| {
                let f = f;
                Box::new(move |a3| {
                    let f = f;
                    Box::new(move |a4| {
                        let f = f;
                        Box::new(move |a5| {
                            let f = f;
                            Box::new(move |a6| {
                                let f = f;
                                Box::new(move |a7| {
                                    let f = f;
                                    Box::new(move |a8| f(a1, a2, a3, a4, a5, a6, a7, a8))
                                })
                            })
                        })
                    })
                })
            })
        })
    })
}
// type_complexity (accepted, cosmetic): the nested `Box<dyn FnOnce>` tower IS the
// 9-arity curry shape; no type alias can simplify a per-arity boxed-closure
// chain. Not a soundness concern.
#[allow(clippy::type_complexity)]
pub fn curry9<
    A1: 'static + Send,
    A2: 'static + Send,
    A3: 'static + Send,
    A4: 'static + Send,
    A5: 'static + Send,
    A6: 'static + Send,
    A7: 'static + Send,
    A8: 'static + Send,
    A9: 'static + Send,
    R: 'static + Send,
    F: Fn(A1, A2, A3, A4, A5, A6, A7, A8, A9) -> R + Clone + Send + Sync + 'static,
>(
    f: F,
) -> Box<
    dyn Fn() -> Box<
            dyn FnOnce(
                    A1,
                ) -> Box<
                    dyn FnOnce(
                            A2,
                        ) -> Box<
                            dyn FnOnce(
                                    A3,
                                ) -> Box<
                                    dyn FnOnce(
                                            A4,
                                        ) -> Box<
                                            dyn FnOnce(
                                                    A5,
                                                )
                                                    -> Box<
                                                    dyn FnOnce(
                                                            A6,
                                                        )
                                                            -> Box<
                                                            dyn FnOnce(
                                                                    A7,
                                                                )
                                                                    -> Box<
                                                                    dyn FnOnce(
                                                                            A8,
                                                                        )
                                                                            -> Box<
                                                                            dyn FnOnce(A9) -> R
                                                                                + Send,
                                                                        > + Send,
                                                                > + Send,
                                                        > + Send,
                                                > + Send,
                                        > + Send,
                                > + Send,
                        > + Send,
                > + Send,
        > + Send
        + Sync,
> {
    Box::new(move || {
        let f = f.clone();
        Box::new(move |a1| {
            let f = f;
            Box::new(move |a2| {
                let f = f;
                Box::new(move |a3| {
                    let f = f;
                    Box::new(move |a4| {
                        let f = f;
                        Box::new(move |a5| {
                            let f = f;
                            Box::new(move |a6| {
                                let f = f;
                                Box::new(move |a7| {
                                    let f = f;
                                    Box::new(move |a8| {
                                        let f = f;
                                        Box::new(move |a9| f(a1, a2, a3, a4, a5, a6, a7, a8, a9))
                                    })
                                })
                            })
                        })
                    })
                })
            })
        })
    })
}
// type_complexity (accepted, cosmetic): the nested `Box<dyn FnOnce>` tower IS the
// 10-arity curry shape; no type alias can simplify a per-arity boxed-closure
// chain. Not a soundness concern.
#[allow(clippy::type_complexity)]
pub fn curry10<
    A1: 'static + Send,
    A2: 'static + Send,
    A3: 'static + Send,
    A4: 'static + Send,
    A5: 'static + Send,
    A6: 'static + Send,
    A7: 'static + Send,
    A8: 'static + Send,
    A9: 'static + Send,
    A10: 'static + Send,
    R: 'static + Send,
    F: Fn(A1, A2, A3, A4, A5, A6, A7, A8, A9, A10) -> R + Clone + Send + Sync + 'static,
>(
    f: F,
) -> Box<
    dyn Fn() -> Box<
            dyn FnOnce(
                    A1,
                ) -> Box<
                    dyn FnOnce(
                            A2,
                        ) -> Box<
                            dyn FnOnce(
                                    A3,
                                ) -> Box<
                                    dyn FnOnce(
                                            A4,
                                        ) -> Box<
                                            dyn FnOnce(
                                                    A5,
                                                )
                                                    -> Box<
                                                    dyn FnOnce(
                                                            A6,
                                                        )
                                                            -> Box<
                                                            dyn FnOnce(
                                                                    A7,
                                                                )
                                                                    -> Box<
                                                                    dyn FnOnce(
                                                                            A8,
                                                                        )
                                                                            -> Box<
                                                                            dyn FnOnce(
                                                                                    A9,
                                                                                )
                                                                                    -> Box<
                                                                                    dyn FnOnce(
                                                                                            A10,
                                                                                        )
                                                                                            -> R
                                                                                        + Send,
                                                                                > + Send,
                                                                        > + Send,
                                                                > + Send,
                                                        > + Send,
                                                > + Send,
                                        > + Send,
                                > + Send,
                        > + Send,
                > + Send,
        > + Send
        + Sync,
> {
    Box::new(move || {
        let f = f.clone();
        Box::new(move |a1| {
            let f = f;
            Box::new(move |a2| {
                let f = f;
                Box::new(move |a3| {
                    let f = f;
                    Box::new(move |a4| {
                        let f = f;
                        Box::new(move |a5| {
                            let f = f;
                            Box::new(move |a6| {
                                let f = f;
                                Box::new(move |a7| {
                                    let f = f;
                                    Box::new(move |a8| {
                                        let f = f;
                                        Box::new(move |a9| {
                                            let f = f;
                                            Box::new(move |a10| {
                                                f(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10)
                                            })
                                        })
                                    })
                                })
                            })
                        })
                    })
                })
            })
        })
    })
}

// --- Pipeline (curried decoder combinators) ---
// Curried by design. Pipeline-decoder helpers
// thread Box<dyn FnOnce> chains that Rust's static trait system can't
// express in tupled form. These are the ONLY functions in the runtime
// that intentionally return impl FnOnce.
// UNCURRIED: the codegen lowers `decode |> Pipeline.required "x" dec` to a
// direct 3-arg call `decode_pipeline_required("x", dec, decode)` (the accumulator
// decoder is the pipe's left side, threaded as the last arg). Taking
// next_decoder as a normal parameter — rather than returning a closure over it
// — matches that shape (35-composite-generics; was a 2-arg curried fn → E0061).
pub fn decode_pipeline_required<E: From<String> + 'static, T: 'static, F: 'static>(
    name: String,
    decoder: Decoder<E, T>,
    next_decoder: Decoder<E, Box<dyn FnOnce(T) -> F + Send>>,
) -> Decoder<E, F> {
    let mut fields = next_decoder.fields.clone();
    union_fields(&mut fields, &decoder.fields);
    let n = name;
    let d = decoder;
    let nd = next_decoder;
    Decoder::new(
        Box::new(move |v| {
            let field_val = match v.get(&n) {
                Some(f) => match (d.run)(f) {
                    IpeResult::Ok(t) => t,
                    IpeResult::Err(e) => return IpeResult::Err(e),
                },
                None => return decode_err_str(format!("missing required: {}", n)),
            };
            match (nd.run)(v) {
                IpeResult::Ok(f) => ok_res(f(field_val)),
                IpeResult::Err(e) => IpeResult::Err(e),
            }
        }),
        fields,
    )
}
pub fn decode_pipeline_optional<
    E: From<String> + 'static,
    T: Clone + 'static + Send + Sync,
    F: 'static,
>(
    name: String,
    decoder: Decoder<E, T>,
    default: T,
    next_decoder: Decoder<E, Box<dyn FnOnce(T) -> F + Send>>,
) -> Decoder<E, F> {
    let mut fields = next_decoder.fields.clone();
    union_fields(&mut fields, &decoder.fields);
    let n = name;
    let d = decoder;
    let nd = next_decoder;
    let def = default;
    Decoder::new(
        Box::new(move |v| {
            // `optional` contract: the default is used ONLY when the field is
            // genuinely ABSENT or null. A field that is PRESENT but fails to
            // decode (e.g. {"age":"x"} with an int decoder) must PROPAGATE the
            // decode error — swallowing it into the default would mask malformed
            // / adversarial input (a validation bypass).
            let field_val = match v.get(&n) {
                Some(val) if !val.is_null() => match (d.run)(val) {
                    IpeResult::Ok(t) => t,
                    IpeResult::Err(e) => return IpeResult::Err(e),
                },
                _ => def.clone(),
            };
            match (nd.run)(v) {
                IpeResult::Ok(f) => IpeResult::Ok(f(field_val)),
                IpeResult::Err(e) => IpeResult::Err(e),
            }
        }),
        fields,
    )
}

/// `JsonDecP.requiredAt : List String -> Decoder a -> Decoder (a -> b) -> Decoder b`.
/// Like `required` but walks a nested path before decoding. Iterates the
/// `List String` path by successive `.get(key)` calls, hard-erroring on any
/// missing segment or non-object node.
pub fn decode_pipeline_required_at<E: From<String> + 'static, T: 'static, F: 'static>(
    path: Vec<String>,
    decoder: Decoder<E, T>,
    next_decoder: Decoder<E, Box<dyn FnOnce(T) -> F + Send>>,
) -> Decoder<E, F> {
    let mut fields = next_decoder.fields.clone();
    union_fields(&mut fields, &decoder.fields);
    let p = path;
    let d = decoder;
    let nd = next_decoder;
    Decoder::new(
        Box::new(move |v| {
            // Walk the path into the JSON value.
            let mut cur: &JsonVal = v;
            for key in &p {
                match cur.get(key) {
                    Some(next) => cur = next,
                    None => {
                        return decode_err_str(format!(
                            "requiredAt: missing path segment {:?}",
                            key
                        ));
                    }
                }
            }
            // Decode the target value.
            let field_val = match (d.run)(cur) {
                IpeResult::Ok(t) => t,
                IpeResult::Err(e) => return IpeResult::Err(e),
            };
            // Apply the accumulator function from the pipeline.
            match (nd.run)(v) {
                IpeResult::Ok(f) => ok_res(f(field_val)),
                IpeResult::Err(e) => IpeResult::Err(e),
            }
        }),
        fields,
    )
}

/// `JsonDec.Pipeline.custom decoder next` — like `required`, but the custom
/// `decoder` runs on the WHOLE value (not a single field) and supplies the next
/// pipeline argument. A custom decode failure aborts the pipeline.
pub fn decode_pipeline_custom<E: From<String> + 'static, T: 'static, F: 'static>(
    decoder: Decoder<E, T>,
    next_decoder: Decoder<E, Box<dyn FnOnce(T) -> F + Send>>,
) -> Decoder<E, F> {
    let mut fields = next_decoder.fields.clone();
    union_fields(&mut fields, &decoder.fields);
    let d = decoder;
    let nd = next_decoder;
    Decoder::new(
        Box::new(move |v| {
            let t = match (d.run)(v) {
                IpeResult::Ok(t) => t,
                IpeResult::Err(e) => return IpeResult::Err(e),
            };
            match (nd.run)(v) {
                IpeResult::Ok(f) => IpeResult::Ok(f(t)),
                IpeResult::Err(e) => IpeResult::Err(e),
            }
        }),
        fields,
    )
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod enc_tests {
    use super::*;

    #[test]
    fn json_encode_indent_is_clamped() {
        // A pathological attacker-supplied indent must not trigger an unbounded
        // `str::repeat`: the per-level indent width saturates at 16 spaces.
        let val = json_enc_object(vec![("k".to_string(), json_enc_int(1))]);
        let out = json_enc_encode(1_000_000_000, val);
        let sixteen = " ".repeat(16);
        let seventeen = " ".repeat(17);
        assert!(
            out.contains(&sixteen),
            "expected clamped 16-space indent: {out:?}"
        );
        assert!(
            !out.contains(&seventeen),
            "indent exceeded the clamp: {out:?}"
        );
        assert!(
            out.len() < 1000,
            "output unexpectedly large ({} bytes)",
            out.len()
        );
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod optional_tests {
    use super::*;

    fn build() -> Decoder<String, i64> {
        // next_decoder is the identity continuation: Decoder<.., FnOnce(i64)->i64>.
        let nd: Decoder<String, Box<dyn FnOnce(i64) -> i64 + Send>> =
            decode_succeed(Box::new(|| {
                Box::new(|x: i64| x) as Box<dyn FnOnce(i64) -> i64 + Send>
            }));
        decode_pipeline_optional::<String, i64, i64>(
            "age".to_string(),
            json_decode_int(),
            -1, // default
            nd,
        )
    }

    #[test]
    fn optional_present_but_wrong_type_propagates_error() {
        // PRESENT-but-malformed field must PROPAGATE the decode error, not fall
        // back to the default (`optional` contract).
        let dec = build();
        let v: JsonVal = serde_json::json!({ "age": "not-an-int" });
        assert!(
            matches!((dec.run)(&v), IpeResult::Err(_)),
            "present-but-wrong-type must yield Err"
        );
    }

    #[test]
    fn optional_absent_uses_default() {
        let dec = build();
        let v: JsonVal = serde_json::json!({});
        assert!(matches!((dec.run)(&v), IpeResult::Ok(-1)));
    }

    #[test]
    fn optional_null_uses_default() {
        let dec = build();
        let v: JsonVal = serde_json::json!({ "age": null });
        assert!(matches!((dec.run)(&v), IpeResult::Ok(-1)));
    }

    #[test]
    fn optional_present_valid_decodes() {
        let dec = build();
        let v: JsonVal = serde_json::json!({ "age": 42 });
        assert!(matches!((dec.run)(&v), IpeResult::Ok(42)));
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod key_value_pairs_tests {
    use super::*;

    #[test]
    fn decodes_object_entries() {
        let dec = decode_key_value_pairs::<String, i64>(json_decode_int());
        let v: JsonVal = serde_json::json!({ "a": 1, "b": 2 });
        match (dec.run)(&v) {
            IpeResult::Ok(mut pairs) => {
                // serde_json's default Map is key-sorted, so the order is stable.
                pairs.sort();
                assert_eq!(pairs, vec![("a".to_owned(), 1), ("b".to_owned(), 2)]);
            }
            IpeResult::Err(e) => panic!("expected Ok, got Err({e})"),
        }
    }

    #[test]
    fn non_object_is_err() {
        let dec = decode_key_value_pairs::<String, i64>(json_decode_int());
        let v: JsonVal = serde_json::json!([1, 2, 3]);
        assert!(matches!((dec.run)(&v), IpeResult::Err(_)));
    }

    #[test]
    fn value_decode_error_propagates() {
        let dec = decode_key_value_pairs::<String, i64>(json_decode_int());
        let v: JsonVal = serde_json::json!({ "a": "not-an-int" });
        assert!(matches!((dec.run)(&v), IpeResult::Err(_)));
    }

    #[test]
    fn empty_object_is_empty_list() {
        let dec = decode_key_value_pairs::<String, i64>(json_decode_int());
        let v: JsonVal = serde_json::json!({});
        assert!(matches!((dec.run)(&v), IpeResult::Ok(ref p) if p.is_empty()));
    }
}

// Behaviour verdicts audited against Elm's documented `elm/json` semantics.
// Each test pins one verdict from `docs/topics/elm-coverage/behaviour-verdicts.md`.
#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod elm_behaviour_verdicts {
    use super::*;

    // Verdict: fix-to-most-correct. Elm's `Decode.int` rejects non-integer
    // numbers; parse-don't-validate forbids the old silent truncation. `1.5`
    // and `1e21` (past i64) fail closed; `1` and integral-float `1.0` decode.
    #[test]
    fn int_decoder_accepts_plain_integer() {
        let dec = json_decode_int::<String>();
        assert!(matches!(
            (dec.run)(&serde_json::json!(42)),
            IpeResult::Ok(42)
        ));
    }
    #[test]
    fn int_decoder_accepts_integral_float() {
        let dec = json_decode_int::<String>();
        assert!(matches!(
            (dec.run)(&serde_json::json!(1.0)),
            IpeResult::Ok(1)
        ));
    }
    #[test]
    fn int_decoder_rejects_fractional() {
        let dec = json_decode_int::<String>();
        assert!(matches!(
            (dec.run)(&serde_json::json!(1.5)),
            IpeResult::Err(_)
        ));
    }
    #[test]
    fn int_decoder_rejects_out_of_range_magnitude() {
        let dec = json_decode_int::<String>();
        assert!(matches!(
            (dec.run)(&serde_json::json!(1e21)),
            IpeResult::Err(_)
        ));
    }
    #[test]
    fn int_decoder_rejects_non_number() {
        let dec = json_decode_int::<String>();
        assert!(matches!(
            (dec.run)(&serde_json::json!("7")),
            IpeResult::Err(_)
        ));
    }

    // The i64 boundary: `i64::MAX as f64` rounds up to 2^63, so a naive
    // float-range gate would admit an out-of-range integer and let `f as i64`
    // saturate to the limit — a silently-wrong value at an attacker-controlled
    // boundary. The exact bounds must decode; one past either must reject.
    #[test]
    fn int_decoder_accepts_i64_max() {
        let dec = json_decode_int::<String>();
        let v: serde_json::Value = serde_json::from_str("9223372036854775807").unwrap();
        assert!(matches!((dec.run)(&v), IpeResult::Ok(i64::MAX)));
    }
    #[test]
    fn int_decoder_accepts_i64_min() {
        let dec = json_decode_int::<String>();
        let v: serde_json::Value = serde_json::from_str("-9223372036854775808").unwrap();
        assert!(matches!((dec.run)(&v), IpeResult::Ok(i64::MIN)));
    }
    #[test]
    fn int_decoder_rejects_i64_max_plus_one() {
        let dec = json_decode_int::<String>();
        let v: serde_json::Value = serde_json::from_str("9223372036854775808").unwrap();
        assert!(
            matches!((dec.run)(&v), IpeResult::Err(_)),
            "i64::MAX+1 must reject, not saturate to i64::MAX; got {:?}",
            (dec.run)(&v)
        );
    }
    #[test]
    fn int_decoder_rejects_i64_min_minus_one() {
        let dec = json_decode_int::<String>();
        let v: serde_json::Value = serde_json::from_str("-9223372036854775809").unwrap();
        assert!(
            matches!((dec.run)(&v), IpeResult::Err(_)),
            "i64::MIN-1 must reject, not saturate to i64::MIN; got {:?}",
            (dec.run)(&v)
        );
    }
    #[test]
    fn int_decoder_accepts_ordinary_in_range() {
        let dec = json_decode_int::<String>();
        assert!(matches!(
            (dec.run)(&serde_json::json!(-7)),
            IpeResult::Ok(-7)
        ));
        assert!(matches!(
            (dec.run)(&serde_json::json!(1_000_000_000_000_i64)),
            IpeResult::Ok(1_000_000_000_000)
        ));
    }

    // `Encode.object` takes an ordered `List (String, Value)` whose order is part
    // of the contract, so keys are emitted in list order — not sorted. The keys
    // here (`name`, `age`, `active`) are deliberately in reverse-alphabetical
    // order so a regression to sorted output changes the bytes and fails.
    #[test]
    fn encode_object_preserves_list_order() {
        let val = json_enc_object(vec![
            ("name".to_string(), json_enc_string("Alice".to_string())),
            ("age".to_string(), json_enc_int(30)),
            ("active".to_string(), json_enc_bool(true)),
        ]);
        let out = json_enc_encode(0, val);
        assert_eq!(out, r#"{"name":"Alice","age":30,"active":true}"#);
    }

    // A nested object follows its own list order independently of the outer one.
    #[test]
    fn encode_nested_object_preserves_list_order() {
        let inner = json_enc_object(vec![
            ("zeta".to_string(), json_enc_int(1)),
            ("alpha".to_string(), json_enc_int(2)),
        ]);
        let val = json_enc_object(vec![
            ("second".to_string(), json_enc_bool(false)),
            ("first".to_string(), inner),
        ]);
        let out = json_enc_encode(0, val);
        assert_eq!(out, r#"{"second":false,"first":{"zeta":1,"alpha":2}}"#);
    }

    // Verdict: keep-Elm (already matches). `nullable` yields `Nothing` on JSON
    // null, `Just x` on a value the inner decoder accepts, and propagates the
    // inner decoder's error otherwise — Elm's `Json.Decode.nullable` contract.
    #[cfg(feature = "config")]
    #[test]
    fn nullable_null_is_nothing() {
        let dec = super::super::config_decode::config_nullable::<String, i64>(json_decode_int());
        assert!(matches!(
            (dec.run)(&serde_json::json!(null)),
            IpeResult::Ok(IpeMaybe::Nothing)
        ));
    }
    #[cfg(feature = "config")]
    #[test]
    fn nullable_value_is_just() {
        let dec = super::super::config_decode::config_nullable::<String, i64>(json_decode_int());
        assert!(matches!(
            (dec.run)(&serde_json::json!(5)),
            IpeResult::Ok(IpeMaybe::Just(5))
        ));
    }
    #[cfg(feature = "config")]
    #[test]
    fn nullable_non_null_inner_failure_propagates() {
        let dec = super::super::config_decode::config_nullable::<String, i64>(json_decode_int());
        assert!(matches!(
            (dec.run)(&serde_json::json!("nope")),
            IpeResult::Err(_)
        ));
    }

    // `JsonDec.nullable` (backing `Decode.nullable` in the browser-sensor
    // whole-frame decoders): a JSON `null` yields `Nothing`, a well-typed value
    // yields `Just`, and a present-but-wrong-type value fails the decode CLOSED
    // rather than coercing to `Nothing` — so a type-mismatched field drops the
    // whole frame instead of fabricating a plausible-but-wrong partial reading.
    #[test]
    fn json_nullable_null_is_nothing() {
        let dec = decode_nullable::<String, f64>(json_decode_float());
        assert!(matches!(
            (dec.run)(&serde_json::json!(null)),
            IpeResult::Ok(IpeMaybe::Nothing)
        ));
    }
    #[test]
    fn json_nullable_number_is_just() {
        let dec = decode_nullable::<String, f64>(json_decode_float());
        assert!(matches!(
            (dec.run)(&serde_json::json!(1.5)),
            IpeResult::Ok(IpeMaybe::Just(_))
        ));
    }
    #[test]
    fn json_nullable_wrong_type_fails_closed() {
        let dec = decode_nullable::<String, f64>(json_decode_float());
        assert!(matches!(
            (dec.run)(&serde_json::json!("fast")),
            IpeResult::Err(_)
        ));
        assert!(matches!(
            (dec.run)(&serde_json::json!({})),
            IpeResult::Err(_)
        ));
    }

    // Verdict: keep-Elm (already matches). `oneOf` returns the first branch that
    // succeeds; an empty branch list (or all-failing) is an `Err`, never a panic.
    #[test]
    fn one_of_returns_first_success() {
        let decoders = vec![json_decode_int::<String>(), json_decode_int::<String>()];
        let dec = decode_one_of(decoders);
        assert!(matches!((dec.run)(&serde_json::json!(9)), IpeResult::Ok(9)));
    }
    #[test]
    fn one_of_empty_is_err_not_panic() {
        let dec = decode_one_of::<String, i64>(vec![]);
        assert!(matches!(
            (dec.run)(&serde_json::json!(1)),
            IpeResult::Err(_)
        ));
    }
    #[test]
    fn one_of_all_fail_is_err() {
        let decoders = vec![json_decode_int::<String>()];
        let dec = decode_one_of(decoders);
        assert!(matches!(
            (dec.run)(&serde_json::json!("x")),
            IpeResult::Err(_)
        ));
    }

    // Verdict: keep-ours (documented divergence). JSON number rendering drops
    // the fraction for integral floats (`1.0` -> `1`) and uses shortest
    // round-tripping digits (`0.1 + 0.2` -> `0.30000000000000004`).
    #[test]
    fn encode_float_integral_drops_fraction() {
        assert_eq!(json_enc_encode(0, json_enc_float(1.0)), "1");
    }
    #[test]
    fn encode_float_shortest_round_trip() {
        assert_eq!(
            json_enc_encode(0, json_enc_float(0.1 + 0.2)),
            "0.30000000000000004"
        );
    }
}
