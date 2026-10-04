# Bytes

`Bytes` is a buffer of raw octets — any sequence of bytes, valid UTF-8 or not.
Reach for it whenever you hold binary that is *not* text: a hash digest,
ciphertext, an image, a length-prefixed frame.

## The mental model

Two knots.

- **`Bytes` is a distinct type, not `String`.** An Ipê `String` is always valid
  UTF-8; `Bytes` has no such constraint. They are kept apart on purpose — a
  `String` cannot hold arbitrary binary without corrupting it, so the compiler
  will not let you pass one where the other belongs. The consequence: the two
  conversions are **asymmetric**.
- **`fromString` is total; `toString` returns `Maybe`.**
  `Bytes.fromString : String -> Bytes` cannot fail — every string has a UTF-8 byte
  encoding. But `Bytes.toString : Bytes -> Maybe String` *can* come up `Nothing`,
  because an arbitrary buffer might not be valid UTF-8. The same split runs through
  the codecs: `toHex`/`toBase64` are total (any buffer has a hex/base64 form),
  while `fromHex`/`fromBase64` return `Maybe Bytes` (the input might be malformed).
  Encoding *out* of `Bytes` never fails; decoding *into* it might.

## A worked example: inspecting a buffer

The example under
[`examples/shapes/script/bytes-buffer`](../../examples/shapes/script/bytes-buffer/src/Main.ipe)
encodes a short message to bytes, shows it in hex and base64, slices a window, and
decodes back — including the case where a decode legitimately fails.

Encoding to bytes and out to the transport forms is all total — no `Maybe` in
sight, because none of these steps can fail:

```ipe
main =
    let
        buffer =
            Bytes.fromString message

        head4 =
            Bytes.slice 0 4 buffer
    in
    do
        Io.println ("message: " ++ message)
        Io.println ("byte length: " ++ String.fromInt (Bytes.length buffer))
        Io.println ("hex: " ++ Bytes.toHex buffer)
        Io.println ("base64: " ++ Bytes.toBase64 buffer)
        Io.println ("first 4 bytes (hex): " ++ Bytes.toHex head4)
        Io.println ("round-trip: " ++ decodeText buffer)
        Io.println ("truncated multibyte decode: " ++ decodeText head4)
```

Decoding *back* to text is the fallible half. `Bytes.toString` is `Maybe String`,
and the `Nothing` case is real here, not hypothetical: the message is `café ☕`,
and slicing the first four bytes cuts through the middle of a multi-byte
character, leaving a buffer that is not valid UTF-8:

```ipe
decodeText : Bytes -> String
decodeText buffer =
    case Bytes.toString buffer of

        Just text ->
            "\"" ++ text ++ "\""

        Nothing ->
            "(not valid UTF-8)"
```

Running it (`ipe dev run`) shows the full buffer round-trips but the truncated window
does not:

```
message: café ☕
byte length: 9
hex: 636166c3a920e29895
base64: Y2Fmw6kg4piV
first 4 bytes (hex): 636166c3
round-trip: "café ☕"
truncated multibyte decode: (not valid UTF-8)
```

The `636166c3` window ends on `c3` — the lead byte of `é` without its
continuation — so `toString` correctly refuses it.

## The why

Keeping `Bytes` and `String` as separate types is [make invalid states
unrepresentable][principles] at the type level. If binary data flowed through
`String`, every non-UTF-8 buffer would be a latent corruption waiting to surface;
the distinct type means a value's *role* — "arbitrary octets" versus "text" —
lives in its type, and the swap that would silently mangle a digest simply does
not compile.

Returning `Maybe` from `toString` (and `fromHex`/`fromBase64`) is the same
[soundness][principles] discipline the rest of the stdlib follows: a conversion
that might not have an answer says so in its type, so no malformed buffer can make
the program fall over — the worst case is a `Nothing` you handle.

[principles]: ../../PRINCIPLES.md

## References

- **Per-symbol reference:** `ipe doc Ipe.Bytes` — every function with a verified
  example. `ipe doc Ipe.Bytes.slice` covers the clamping index behaviour.
- **Sibling guides:** [Text encodings](encoding.md) — the `String`-to-`String`
  codecs, for when your payload *is* text. [Maybe](maybe.md), which `toString`
  and the decoders return. Hashing and encryption produce `Bytes` digests — see
  `ipe doc Ipe.Crypto`.
- **Concepts:** [Types and inference](types.md) — how a distinct primitive type
  keeps binary and text apart. [Pure functions and immutability](pure-functions.md).
