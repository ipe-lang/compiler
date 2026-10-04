# Tracing

`Ipe.Trace` adds **application-level spans** to a program: a named, logical unit
of work that groups the automatic runtime spans (HTTP request, DB query, session
load) underneath it. `Ipe.Debug.log` is its development-time companion — an
inline print that returns its value unchanged.

## The mental model

Three knots.

- **A span wraps a Task without changing it.** `Trace.span name task` runs `task`
  and returns *exactly* its result — same value, same error — plus a span in the
  trace tree. Output is opt-in (gated by `IPE_TRACE`), but the wrapped task always
  runs, so adding or removing a span never changes what the program computes. You
  can wrap freely without fear of altering behaviour.
- **Events and attributes annotate the active span.** `Trace.event name` marks a
  point in time ("cache miss", "retry"); `Trace.attr key value` records a
  `key = value` on the span (keys namespaced under `ipe.trace.` so they never
  collide with the runtime's own). Both are `Task Error ()` you sequence like any
  effect.
- **`Debug.log` is a returning print.** `Debug.log label value` prints
  `"label: value"` to stderr and hands back `value` untouched, so you can wrap any
  sub-expression in it without rewiring the surrounding code. It is a
  development-only hatch — `ipe release` rejects it — so it never ships silently.

## A worked example: a checkout span

The example under
[`examples/shapes/script/trace-checkout-span`](../../examples/shapes/script/trace-checkout-span/src/Main.ipe)
wraps a two-step checkout in one named span, records an event and an attribute on
it, and drops a `Debug.log` into the reserve step.

The whole flow is one span; the value the inner pipeline produces is exactly what
`checkout` returns — the span is transparent to the result:

```ipe
checkout : Int -> Task Error Int
checkout qty =
    Trace.span "checkout"
        (do
            Trace.event "reserve-start"
            reserved <- reserveStock qty
            Trace.attr "sku" "widget-42"
            total <- chargeCard reserved
            Task.succeed total
        )
```

`Debug.log` sits inside an expression and returns its argument, so the reserve
step's value flows straight through it:

```ipe
reserveStock : Int -> Task Error Int
reserveStock qty =
    Task.succeed (Debug.log "reserved" qty)
```

Running it (`ipe dev run`) prints the computed total on stdout:

```
checkout total (cents): 3000
```

The `Debug.log` line (`reserved: 3`) goes to stderr — always, since `Debug.log`
is unconditional. The span lines appear on stderr only when `IPE_TRACE` is set;
with `IPE_TRACE=1` the run's stderr adds the span frame and its event/attr:

```
[trace] span start checkout
[trace] event reserve-start
[trace] attr ipe.trace.sku = widget-42
[trace] span end checkout (0 ms, ok)
```

None of this changes the `3000` on stdout — the span is transparent to the result.

## The why

A span being transparent to its Task's result is [correctness][principles] as a
guarantee, not a hope: because `Trace.span name task` provably returns `task`'s
value, instrumenting code cannot introduce a behaviour change, so you never have
to reason about "did adding tracing break this?" Observability that could alter a
result would be a liability; one that cannot is free to apply generously.

Keeping `Debug.log` on a `release`-rejected surface is honesty at the ship
boundary: a debug print left in by accident is a compile error at release, not a
line leaking internal values into production stderr — [security][principles]'s
fail-closed rule applied to diagnostics. And routing structured spans through the
runtime's telemetry ring rather than ad-hoc prints means the trace tree the
console shows is built from the same values the program ran, with no second,
drift-prone source of truth.

[principles]: ../../PRINCIPLES.md

## References

- **Per-symbol reference:** `ipe doc Ipe.Trace` — `span`, `event`, `attr`.
  `ipe doc Ipe.Debug` — `log` (returning print), `todo` (mark an unfinished path),
  `explain` (visible layout outlines, Web/WebView only).
- **Sibling guides:** [Tasks](task.md) — the effect a span wraps and the discipline
  events and attributes sequence in. [Logging](log.md) — structured, levelled log
  records, the other half of observability. [Error](error.md) — the typed failure
  a wrapped task may carry, passed through the span untouched.
- **Concepts:** the automatic runtime spans (HTTP, DB, session) need no code; reach
  for `Ipe.Trace` only to add an application-level unit that groups them.
