# Byte sizes

`Ipe.ByteSize` is an opaque, unit-explicit byte quantity. It replaces the bare
byte-count `Int` that resource caps took — a read ceiling, a cache size cap — so a
`10` meaning ten mebibytes is never read as ten bytes.

## The mental model

Three knots.

- **The constructors name their unit at the call site.** `ByteSize.bytes 512`,
  `ByteSize.kib 256`, `ByteSize.mib 10` — you always write which unit a number is,
  so a magnitude can never be silently off by a factor of 1024. The units are
  binary: `kib` is 1024 bytes, `mib` is 1024 × 1024 bytes.
- **`ByteSize` is opaque and non-negative.** The constructor is not exported, and
  every builder clamps a negative input to zero (and saturates rather than wraps on
  overflow). A negative ceiling is not a representable cap — a `ByteSize` is a
  *proof* of non-negativity, so a resource limit downstream never has to guard
  against one.
- **The raw byte count comes back explicitly, at the boundary.** `ByteSize.toBytes`
  recovers the integer a runtime kernel enforces, and it is the *one* place a
  `ByteSize` becomes a nameless number — at the edge, not sprinkled through the
  program.

## A worked example: resource caps

The example under
[`examples/shapes/script/bytesize-caps`](../../examples/shapes/script/bytesize-caps/src/Main.ipe)
builds per-resource size caps from unit-explicit quantities, including a negative
one that clamps to zero.

Each cap carries a `ByteSize`, built with its unit named, and a deliberate
negative that becomes zero:

```ipe
caps =
    [ { resource = "upload", limit = ByteSize.mib 10 }
    , { resource = "avatar", limit = ByteSize.kib 256 }
    , { resource = "token", limit = ByteSize.bytes 512 }
    , { resource = "unset", limit = ByteSize.bytes (0 - 1) } -- clamps to zero
    ]
```

The quantity becomes a raw byte count only at the boundary, through `toBytes`:

```ipe
render cap =
    String.padRight 8 ' ' cap.resource
        ++ String.fromInt (ByteSize.toBytes cap.limit)
        ++ " bytes"
```

Running it (`ipe dev run`) expands each binary unit correctly and clamps the negative:

```
Resource caps:
  upload  10485760 bytes
  avatar  262144 bytes
  token   512 bytes
  unset   0 bytes
```

## The why

This is the same seal as [`Duration`](duration.md), applied to a byte quantity —
and the shared design is deliberate. Unit-explicit constructors are
[correctness][principles]: the off-by-1024 magnitude error (a `10` that was
mebibytes enforced as ten bytes) cannot be written, because there is no way to
build a `ByteSize` without naming the unit.

Clamping negatives and hiding the constructor is [make invalid states
unrepresentable][principles]: a negative cap is not a value the type can hold, so
`File.readFileLimit` and `Cache.withMaxBytes` never receive one. Zero is a
value, not a switch: `File.readFileLimit path ByteSize.zero` admits only an
empty file. And recovering the
raw integer only through `toBytes` at the boundary is [parse, don't
validate][principles] in reverse — the typed quantity travels through your code,
and the untyped byte count exists only at the runtime edge.

[principles]: ../../PRINCIPLES.md

## References

- **Per-symbol reference:** `ipe doc Ipe.ByteSize` — `bytes`, `kib`, `mib`, `zero`,
  and `toBytes` with verified examples.
- **Sibling guides:** [Durations](duration.md) — the identical seal for a time
  span; read either guide and you know both. [Bytes](bytes.md) — the byte *buffer*
  a `ByteSize` caps the length of. [Files](file.md) — where a read limit is a
  `ByteSize`.
- **Concepts:** [The parse-don't-validate idiom](../idioms/parse-dont-validate.md).
  [Types and inference](types.md) — how the opaque quantity keeps its unit off the
  raw `Int`.
