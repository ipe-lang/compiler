# Codec

A `Codec a` bundles an *encoder* and a *decoder* for one type in a single value,
so the JSON you write and the JSON you read back cannot drift apart. You can't
hold a codec that encodes but doesn't decode; the round-trip law
`fromJson c (toJson c x) == Ok x` holds by construction, because `toJson` and
`fromJson` read the same codec.

## The mental model

Three knots.

- **One codec drives both directions.** A `Codec a` carries the encoder *and* the
  decoder together, so they are defined once from one source. This is the
  difference from a separate `encode`/`decode` pair, where the two can silently
  disagree: with a codec, if the type round-trips it round-trips, and the compiler
  is what guarantees it.
- **Composite codecs are built from scalars.** `Codec.string`, `Codec.int`,
  `Codec.bool` are the primitives; `Codec.list elem`, `Codec.maybe elem`, and
  `Codec.dict value` lift a codec over a container, deriving the container's
  encoder and decoder from the element's. You compose the shape you need rather
  than hand-writing a parser.
- **`enum` fails closed on an unknown tag.** `Codec.enum eq pairs` maps each
  constructor to a readable wire name; decoding a value that isn't in the list is
  an `Err`, never a silently-wrong constructor. An unrecognised tag takes the safe
  branch — rejection — not a guess.

## A worked example: a round-trip and a fail-closed enum

The example under
[`examples/shapes/script/codec-round-trip`](../../examples/shapes/script/codec-round-trip/src/Main.ipe)
round-trips a `List Int` through JSON and decodes a `Priority` enum, including an
unknown tag.

The `List Int` codec is *derived* from the `Int` codec — no separate array parser:

```ipe
numbersCodec : Codec (List Int)
numbersCodec =
    Codec.list Codec.int
```

Because `toJson` and `fromJson` read the same codec, encoding then decoding
recovers the original exactly — the round-trip law, live:

```ipe
roundTripNumbers xs =
    let
        json =
            Codec.toJson numbersCodec xs

        back =
            Codec.fromJson numbersCodec json
    in
    "encoded " ++ json ++ " ; decoded == original: " ++ boolText (back == Ok xs)
```

The `Priority` enum maps each constructor to a wire name. Decoding a tag that
isn't in the list is a typed `Err` — fail-closed, never a wrong constructor:

```ipe
priorityCodec : Codec Priority
priorityCodec =
    Codec.enum priorityEq [ ( Low, "low" ), ( High, "high" ) ]
```

Running it (`ipe dev run`):

```
encoded [3,1,4,1,5] ; decoded == original: yes
decode "high" -> High
decode "urgent" -> rejected (unknown tag — fail-closed)
```

For an untrusted body, `Codec.fromJsonSafe maxChars` rejects anything over a size
limit *before* decoding — the door for request payloads and webhooks.

## The why

Bundling both directions in one value is [make invalid states
unrepresentable][principles]: a codec that encoded but couldn't decode simply has
no representation, so the class of "the writer and reader disagree" bug can't be
written. The round-trip law is a property of the type, not a test you remember to
run.

`enum` rejecting an unknown tag is [security][principles]'s fail-closed rule at the
decode boundary: on input that isn't provably one of the known tags, the reachable
outcome is rejection, never a permissive guess. And decoding returning a `Result`
rather than panicking on malformed JSON is [soundness][principles] — a bad document
is an `Err` value the caller handles, and `fromJsonSafe`'s size guard plus the
decoder's own depth bound keep an adversarial payload from exhausting memory or the
stack.

[principles]: ../../PRINCIPLES.md

## References

- **Per-symbol reference:** `ipe doc Ipe.Codec` — every combinator with a verified
  example. `ipe doc Ipe.Codec.taggedUnion` builds a codec for a data-carrying
  union; `ipe doc Ipe.Codec.map` is the bijection newtype wrapper;
  `ipe doc Ipe.Codec.fromJsonSafe` the size-guarded decode.
- **Sibling guides:** [Result](result.md) — the failure type every decode returns.
  [Bytes](bytes.md) and [Compression](compression.md) — a codec's JSON can be gzip'd
  for transport. [Decimal](decimal.md) and [Money](money.md) — `Codec.decimal` /
  `Codec.money` encode exact amounts losslessly as a JSON string, never a `Float`.
  [Lists](list.md), [Maybe](maybe.md), [Dict](dict.md) — the containers the
  composite codecs lift over.
- **Concepts:** [The parse-don't-validate idiom](../idioms/parse-dont-validate.md)
  — a codec is the boundary where untyped JSON becomes a typed value. [Types and
  inference](types.md) — how a codec's `a` is tracked.
