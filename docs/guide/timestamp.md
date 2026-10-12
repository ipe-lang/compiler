# Timestamp

A `Timestamp` is an opaque *instant* — a single point in time, carried as whole
milliseconds since the Unix epoch. Because an instant and a *span* (an
`Ipe.Duration`) are different types, only the operations that make physical sense
compile: you can shift an instant by a span, or measure the span between two
instants, but you cannot add two instants together.

## The mental model

Three ideas.

- **An instant is not a number.** The `Timestamp` constructor is not exported;
  the only way to build one is `fromUnixMillis`. So a bare `Int` — a config value,
  a loop counter, an epoch-millisecond literal — can never be mistaken for a real
  instant, and the reverse (recovering the raw millisecond count) is the explicit
  `toUnixMillis`.
- **Instant + span = instant.** `add span instant` shifts an instant forward by a
  `Duration`, giving a new `Timestamp`. There is no `add : Timestamp -> Timestamp`,
  because "3pm plus 4pm" is meaningless — the type system rules it out.
- **Instant − instant = span.** `diff later earlier` measures the `Duration`
  between two instants. The result is clamped to zero when the arguments are
  reversed, preserving the invariant that a `Duration` is never negative.

## A worked example: shift and measure

The example under
[`examples/shapes/script/timestamp-scheduling`](../../examples/shapes/script/timestamp-scheduling/src/Main.ipe)
takes a fixed instant, shifts it forward by an hour, and measures the span back
out.

The shift takes an instant and a span and returns an instant:

```ipe
oneHourLater : Timestamp
oneHourLater =
    Timestamp.add (Duration.minutes 60) start
```

The measurement takes two instants and returns a span, which we read out as
seconds:

```ipe
gapSeconds : Int
gapSeconds =
    Duration.toMillis (Timestamp.diff oneHourLater start) // 1000
```

Running it (`ipe dev run`):

```
start (unix ms): 1000000000000
one hour later:  1000003600000
gap between them: 3600 seconds
```

## The why

Keeping an instant and a span in different types is [make invalid states
unrepresentable][principles]: the meaningless operations — adding two clocks,
subtracting a span from nothing — have no representation, so they can't be written.
The hidden constructor is [parse-don't-validate][parse] at the time boundary: a raw
`Int` becomes a `Timestamp` only by passing through `fromUnixMillis`, so every
value typed `Timestamp` really is an instant, and nothing downstream re-checks it.
Clamping `diff` to a non-negative `Duration` is [soundness][principles] — the
"never negative" invariant is enforced at construction, not left to each caller to
remember.

[principles]: ../../PRINCIPLES.md
[parse]: ../idioms/parse-dont-validate.md

## References

- **Per-symbol reference:** `ipe doc Ipe.Time.Timestamp` — `fromUnixMillis`,
  `toUnixMillis`, `add`, `diff`, each with its signature.
- **Sibling guides:** [Durations](duration.md) — the span type `add` and `diff`
  work with (`minutes`, `seconds`, `millis`, `toMillis`). [Time](time.md) — reading
  the wall clock and calendar formatting. [Math](math.md) — the integer division
  used to convert milliseconds to seconds.
- **Concepts:** [Types and inference](types.md) — how the distinct `Timestamp` and
  `Duration` types are tracked.
