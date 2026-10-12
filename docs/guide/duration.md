# Durations

`Ipe.Duration` is an opaque, unit-explicit time span. It replaces the bare
millisecond `Int` that timeouts, delays, retry backoff, and cache TTLs used to
take — so a number is never silently read as the wrong unit.

## The mental model

Three knots.

- **The constructors name their unit at the call site.** `Duration.millis 750`,
  `Duration.seconds 5`, `Duration.minutes 2` — you always write *which unit* a
  number is, so a bare `5` can never be misread as milliseconds when you meant
  seconds. The unit lives at the point of construction, not in a comment or a
  variable name a reader has to trust.
- **`Duration` is opaque and non-negative.** The constructor is not exported, and
  every builder clamps a negative input to zero (and saturates rather than wraps on
  overflow). So a "minus-five-seconds timeout" is not a representable value — a
  `Duration` is a *proof* of non-negativity, and code that consumes one need not
  guard against a negative span.
- **The raw milliseconds come back explicitly, at the boundary.** `Duration.toMillis`
  recovers the whole-millisecond count a runtime kernel needs — and it is the *one*
  place a `Duration` becomes a nameless integer, at the edge, not scattered through
  the program.

## A worked example: a timeout schedule

The example under
[`examples/shapes/script/duration-timeouts`](../../examples/shapes/script/duration-timeouts/src/Main.ipe)
builds a per-stage timeout schedule from unit-explicit spans, including a negative
one that clamps to zero.

Each stage carries a `Duration`, built with its unit named — `seconds 5`,
`millis 750`, `minutes 2` — and a deliberate negative that becomes zero:

```ipe
schedule =
    [ { label = "connect", budget = Duration.seconds 5 }
    , { label = "handshake", budget = Duration.millis 750 }
    , { label = "download", budget = Duration.minutes 2 }
    , { label = "cleanup", budget = Duration.seconds (0 - 3) } -- clamps to zero
    ]
```

The span becomes a raw number only at the boundary, through `toMillis`:

```ipe
render stage =
    String.padRight 10 ' ' stage.label
        ++ String.fromInt (Duration.toMillis stage.budget)
        ++ " ms"
```

Running it (`ipe dev run`) converts each unit correctly and clamps the negative span:

```
Timeout schedule:
  connect   5000 ms
  handshake 750 ms
  download  120000 ms
  cleanup   0 ms
total budget: 125750 ms
```

## The why

Unit-explicit constructors are [correctness][principles] against a whole class of
silent bug: the unit-confusion error (a `30` that was seconds treated as
milliseconds) simply cannot be written, because there is no way to build a
`Duration` without saying `millis`/`seconds`/`minutes`.

Clamping negatives and hiding the constructor is [make invalid states
unrepresentable][principles]: a negative time span is not a value the type can
hold, so no timeout, delay, or TTL downstream has to defend against one. And
recovering the raw integer only through `toMillis` at the boundary is [parse,
don't validate][principles] run in reverse — the typed value travels through your
code, and the untyped integer exists only at the runtime edge where a kernel
demands it.

[principles]: ../../PRINCIPLES.md

## References

- **Per-symbol reference:** `ipe doc Ipe.Duration` — `millis`, `seconds`,
  `minutes`, `zero`, and `toMillis` with verified examples.
- **Sibling guides:** [Byte sizes](bytesize.md) — the exact same seal
  (opaque, unit-explicit, non-negative) applied to a byte quantity instead of a
  time span. [Tasks](task.md) — where durations become timeouts and retry backoff.
  [Lists](list.md) — the schedule is a list of spans folded to a total.
- **Concepts:** [The parse-don't-validate idiom](../idioms/parse-dont-validate.md)
  — the discipline the opaque `Duration` embodies. [Types and
  inference](types.md) — how the opaque span keeps its unit off the raw `Int`.
