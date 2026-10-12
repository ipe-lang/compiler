# Compression

`Ipe.Compression` compresses and decompresses raw bytes with gzip or Zstandard.
Every operation is a `Task Error Bytes` — compression is CPU work, so it is an
effect you sequence, run in parallel, and whose failure (corrupt input) is a typed
`Err`, not a crash.

## The mental model

Three knots.

- **Compression works on `Bytes`, not `String`.** A compressed stream is arbitrary
  octets, not valid UTF-8, so the API takes and returns [`Bytes`](bytes.md). Convert
  at the boundary: `Bytes.fromString` to compress text, `Bytes.toString` (a `Maybe`,
  since not every byte sequence is text) to read it back, `Bytes.toBase64` to put a
  compressed blob in a text transport.
- **Every operation is a `Task`.** `gzip`, `gunzip`, `zstdCompress`, and
  `zstdDecompress` return `Task Error Bytes` because the work is CPU-bound — you
  bind them with `<-`, run several through `Task.parallel`, and a corrupt or
  truncated input surfaces as an `Err` you handle, never a panic.
- **Decompress reverses compress, exactly.** `gunzip (gzip x)` recovers `x`
  byte-for-byte — the round-trip is lossless. gzip (RFC 1952) is the interoperable
  default; Zstandard gives a better ratio at comparable decompression speed when
  both ends speak it.

## A worked example: a gzip round-trip

The example under
[`examples/shapes/script/compression-round-trip`](../../examples/shapes/script/compression-round-trip/src/Main.ipe)
compresses a repetitive payload, reports the size it saved, decompresses, and
confirms the bytes came back identical.

The payload is text converted to `Bytes` at the boundary — the same line repeated,
so gzip has real redundancy to squeeze:

```ipe
original : Bytes
original =
    Bytes.fromString (String.repeat 40 "the quick brown fox\n")
```

`main` binds the compress and decompress Tasks with `<-`, then compares sizes and
confirms the round-trip:

```ipe
main =
    do
        compressed <- Compression.gzip original
        restored <- Compression.gunzip compressed
        Io.println
            ("original " ++ String.fromInt (Bytes.length original)
                ++ " bytes -> gzip " ++ String.fromInt (Bytes.length compressed)
                ++ " bytes")
        Io.println
            ("round-trip recovers the original: "
                ++ boolText (Bytes.length restored == Bytes.length original))
```

Running it (`ipe dev run`):

```
original 800 bytes -> gzip 59 bytes
round-trip recovers the original: yes
first line back: the quick brown fox
```

## The why

Operating on `Bytes` rather than `String` is [make invalid states
unrepresentable][principles]: a compressed stream isn't text, so the type isn't
`String` — you can't accidentally treat a gzip blob as UTF-8, and the `Maybe` that
`Bytes.toString` returns forces you to handle the "not valid text" case. The role
of the data — raw octets — lives in its type.

Returning a `Task Error Bytes` rather than a bare value is [correctness][principles]
(CPU work is an effect, visible in the type and composable with `Task.parallel`) and
[soundness][principles] (truncated or corrupt input is an `Err` the caller handles,
never a decompressor that trips the process). The lossless round-trip is the
guarantee the whole module exists to provide.

[principles]: ../../PRINCIPLES.md

## Configuration

One env var sets the decompression safety ceiling. Use `ipe doc IPE_DECOMPRESS_MAX_BYTES`
to read the full entry.

| Variable | Default | Effect |
|----------|---------|--------|
| `IPE_DECOMPRESS_MAX_BYTES` | 268435456 (256 MiB) | Maximum bytes a single decompress call may produce. |

See the [**Compression** subsystem](../reference/env.md#compression) in the
environment variable reference.

## References

- **Per-symbol reference:** `ipe doc Ipe.Compression` — every function with a
  verified example. `ipe doc Ipe.Compression.zstdCompress` /
  `ipe doc Ipe.Compression.zstdDecompress` cover the Zstandard pair.
- **Sibling guides:** [Bytes](bytes.md) — the raw-octet type every operation reads
  and writes, and the `fromString`/`toString`/`toBase64` boundary. [Codec](codec.md)
  — a codec's JSON output is a natural thing to compress for transport.
  [Tasks](task.md) — how the compression effects are sequenced and parallelised, and
  their errors handled.
- **Concepts:** [Pure functions and immutability](pure-functions.md) — why CPU-bound
  work is modelled as a `Task`.
