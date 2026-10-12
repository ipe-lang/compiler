# Text encodings

`Ipe.Encoding` converts text to and from three transport-safe encodings —
**base64**, **percent (URL)**, and **hex** — as `String`-to-`String` codecs. Reach
for it whenever a value has to survive a channel that mangles raw bytes: a URL
query component, a header, a token in a JSON field.

## The mental model

Two knots, and they are the whole module.

- **Encoders are total; decoders are fallible.** Every encoder is
  `String -> String` — it cannot fail, because any string has a valid base64,
  URL, or hex form. Every decoder returns `Result Error String`, because the
  input it is handed *might not be valid* base64/percent/hex. That asymmetry is
  the design: encoding is a plain transformation, decoding is a **parse boundary**
  where malformed input becomes a typed `Err`, never a silent wrong answer and
  never a crash.
- **Text in, text out — for bytes, use `Ipe.Bytes`.** These codecs operate on
  Ipê `String`s (always valid UTF-8). When you have arbitrary binary — an image, a
  ciphertext, a hash digest — encode *that* through [`Ipe.Bytes`](bytes.md)
  (`toBase64`/`toHex`), which is built for non-UTF-8 payloads. `Ipe.Encoding` is
  for encoding *text*.

## A worked example: a round-trip

The example under
[`examples/shapes/script/encoding-round-trip`](../../examples/shapes/script/encoding-round-trip/src/Main.ipe)
sends one payload through each encoding and back, checking it survives, then shows
what a decoder does with malformed input.

The round-trip helper captures the asymmetry directly: `encode` is called
plainly, `decode` returns a `Result` that the verdict must handle:

```ipe
roundTrip : String -> (String -> String) -> (String -> Result Error String) -> String
roundTrip label encode decode =
    let
        encoded =
            encode payload

        verdict =
            case decode encoded of

                Ok back ->
                    if back == payload then
                        "round-trips"

                    else
                        "MISMATCH"

                Err _ ->
                    "decode failed"
    in
    label ++ ": " ++ encoded ++ "  (" ++ verdict ++ ")"
```

Malformed input is not an exception — it is an `Err` the caller pattern-matches.
`"!!!"` is not valid base64:

```ipe
badDecode : String
badDecode =
    case Encoding.base64Decode "!!!" of

        Ok _ ->
            "unexpectedly decoded"

        Err _ ->
            "rejected malformed base64 (Err, not a crash)"
```

Running it (`ipe dev run`) over a payload with non-ASCII text (`café ☕`) shows all
three encodings round-trip, and the malformed decode is rejected cleanly:

```
original: user=ada&note=café ☕
base64: dXNlcj1hZGEmbm90ZT1jYWbDqSDimJU=  (round-trips)
url   : user%3Dada%26note%3Dcaf%C3%A9+%E2%98%95  (round-trips)
hex   : 757365723d616461266e6f74653d636166c3a920e29895  (round-trips)
malformed: rejected malformed base64 (Err, not a crash)
```

## The why

The decoder returning `Result` is [parse, don't validate][principles] at the
boundary. Foreign data — a base64 field from a request, a hex string from a
config — is untrusted; the decode is the single point where it becomes a known-good
`String` or a typed failure. A decoder that returned a bare `String` (empty on
error, say) would push a silent-corruption bug downstream; returning `Result`
makes the malformed case impossible to ignore.

That the decoder cannot *crash* on bad input is the [soundness][principles]
guarantee: no byte sequence a remote party sends can make the program fall over —
the worst outcome is an `Err` you already handle.

[principles]: ../../PRINCIPLES.md

## References

- **Per-symbol reference:** `ipe doc Ipe.Encoding` — every codec with a verified
  example.
- **Sibling guides:** [Bytes](bytes.md) — for arbitrary binary payloads, with its
  own `toBase64`/`toHex`. [Result](result.md), which every decoder returns.
- **Concepts:** [The parse-don't-validate idiom](../idioms/parse-dont-validate.md)
  — why decoding is a parse boundary. [Types and inference](types.md).
