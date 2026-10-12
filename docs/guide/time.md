# Time

`Ipe.Time` splits the clock into two halves: reading the current instant is an
*effect* (a `Task`, because two reads can disagree), while formatting an instant
and doing calendar arithmetic on it is *pure*. The instant itself is an opaque
`Timestamp`, and spans between instants are the typed `Ipe.Duration` — so the type
system rules out mixing an instant with a span the wrong way.

## The mental model

Three knots.

- **A clock read is an effect; everything on a held instant is pure.** `Time.now`
  returns a `Task Error Timestamp`, because reading the clock is a side effect
  whose result changes over time. Once you *have* a `Timestamp`, formatting it and
  doing arithmetic on it are ordinary pure functions — no `Task`, no `<-`. To make
  a program deterministic (and testable), pin an instant with
  `Timestamp.fromUnixMillis` rather than reading the clock.
- **Instants and spans are different types.** A `Timestamp` is an instant; a
  `Ipe.Duration` is a span. `Time.add` takes a duration and an instant and returns
  an instant; `Time.diff` takes two instants and returns a duration. Adding two
  instants, or subtracting a span from a span as if it were an instant, is a
  compile-time type error — the arithmetic that makes sense is the only arithmetic
  the types allow. `Duration` is non-negative, so spans move an instant *forward*.
- **UTC formatters are deterministic; local formatters are not.** `formatISO8601`
  and `formatRFC3339` render an instant in UTC, identically on every machine.
  `timeString` and a strftime `format` render in local time, which depends on the
  host timezone — reach for those for human display, and for the UTC forms when the
  output must be stable (logs, wire formats, tests).

## A worked example: a launch window

The example under
[`examples/shapes/script/time-calendar`](../../examples/shapes/script/time-calendar/src/Main.ipe)
pins a fixed instant, formats it in UTC, shifts it by a duration, measures the
span back, and reads two pure calendar helpers.

A fixed instant is built from milliseconds since the epoch, and a deadline is that
instant plus a duration:

```ipe
launch =
    Timestamp.fromUnixMillis 1709208000000

deadline =
    Time.add (Duration.minutes 120) launch
```

`formatISO8601 launch` and `formatRFC3339 deadline` render each instant as a stable
UTC string (the launch at noon, the deadline two hours later). `diff` recovers the
span between the two as a `Duration`, and the calendar helpers are pure `Int`
maths:

```ipe
Duration.toMillis (Time.diff deadline launch) // 60000   -- 120 (minutes)
Time.isLeapYear 2024                                     -- True
Time.daysInMonth 2024 2                                  -- 29
```

Running it (`ipe dev run`) prints the two UTC instants, then:

```
window span: 120 minutes
2024 is a leap year: yes
Feb 2024 has 29 days
```

## The why

Making a clock read a `Task` while keeping arithmetic pure is [correctness by
construction][principles]: a function that formats or shifts an instant depends
only on the instant it is given, so it has the "same input, same output" property
and can be tested without a clock. The effect lives only where time is actually
*read*, and it is visible in the type there.

Giving instants and spans distinct types is [make invalid states
unrepresentable][principles]: "an instant plus a span is an instant" and "an
instant minus an instant is a span" are the only sensible operations, and they are
the only ones that type-check. A single numeric "time" type would let you add two
timestamps — a meaningless value the compiler here refuses to produce.

[principles]: ../../PRINCIPLES.md

## References

- **Per-symbol reference:** `ipe doc Ipe.Time` — clock reads, formatters,
  arithmetic, subscriptions, and calendar helpers. `ipe doc Ipe.Time.Timestamp`
  for the opaque instant.
- **Sibling guides:** [Durations](duration.md) — the typed span type `add`/`diff`
  compose with. [Tasks](task.md) — how the effectful `now` is sequenced.
  [Standard I/O](io.md) — writing the formatted output.
