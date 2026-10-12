# Analytics

`Ipe.Analytics` emits product-analytics events with three security properties
the type system enforces: consent is fail-closed, PII is a distinct type that
can only redact, and money is lossless. The config is an explicit value you
thread through the program — there is no mutable global to install and read back.

## The mental model

Three knots.

- **Consent is fail-closed.** `track` and `trackEvent` DROP the event and return
  a succeeding `Task` on any state other than `Granted`. There is no branch that
  reaches the sink without proof of `Granted` consent — the safe outcome is the
  only reachable one, and `defaultConfig` starts in the `Pending` state, so an
  un-consented session emits nothing by default.
- **PII is a distinct type, never a bare `String`.** A `PPii` prop wraps a sealed
  value whose only serialisation path produces `"[redacted]"` unconditionally.
  There is no reveal on this module's surface — string interpolation,
  `Debug.log`, and the JSON encode path all render the redacted sentinel, never
  the plaintext. The store never sees PII: the props are redacted
  *before* the line reaches any sink.
- **Money is lossless.** A `PMoney` prop encodes as an exact decimal string plus
  a currency code (`{"amount":"…","currency":"…"}`), never a floating-point
  number — the same discipline the [Money](money.md) guide describes, carried
  into the event payload.

## A worked example: redaction and the consent gate

The example under
[`examples/shapes/script/analytics-consent`](../../examples/shapes/script/analytics-consent/src/Main.ipe)
serialises a few prop values and fires one event in each consent state.

The config is a value you build and thread — `defaultConfig` starts fail-closed,
`setConsent` moves it:

```ipe
configWith : ConsentState -> Config
configWith state =
    Analytics.defaultConfig Analytics.Stderr
        |> Analytics.setConsent state
```

A `PPii` prop serialises to the redacted sentinel — calling the encode path does
not reveal the plaintext:

```ipe
showProp name value =
    name ++ " -> " ++ Encode.encode 0 (Analytics.encodePropValue value)
```

Running it (`ipe dev run`) redacts the PII, keeps the plain and numeric props, and
gates the event on consent — the `Granted` event reaches the stderr sink; the
`Pending` and `Denied` events are dropped, and their Tasks still succeed:

```
email -> "[redacted]"
plan -> "pro"
seats -> 5
consent-gated track: Granted emitted; Pending and Denied dropped
```

Beyond the fire-and-forget `track`, the module also persists events to a typed
database store: `persist` is consent-gated the same way, `erase`
deletes a user's rows regardless of current consent state (right-to-erasure is
the safe outcome), and the aggregate reads (`totals`, `uniqueUsers`,
`eventCounts`, `recent`) run over the injection-safe store surface. Each of
those needs a live database connection, so they are documented per-symbol rather
than in this script.

## The why

Dropping on any state but `Granted` is [security][principles]'s fail-closed rule
at the emit boundary: absent proof of consent, the reachable outcome is *not
emitting*, never a permissive default. PII being a sealed type with only a
redacting serialisation is [make invalid states unrepresentable][principles] —
the "a raw email ended up in an analytics line" bug has no representation,
because no path from the sealed value back to its plaintext exists on the
surface. And encoding money as an exact decimal string is [correctness][principles]:
an amount that a `Float` would round is carried losslessly.

[principles]: ../../PRINCIPLES.md

## References

- **Per-symbol reference:** `ipe doc Ipe.Analytics` — the event surface (`track`,
  `trackEvent`), the store-backed persistence (`eventsStore`, `persist`, `erase`),
  and the aggregate reads (`totals`, `uniqueUsers`, `eventCounts`, `recent`).
  `ipe doc Ipe.Analytics.pii` seals a PII string; `ipe doc Ipe.Analytics.trackEvent`
  routes a caller-supplied `Codec` through the active sink.
- **Sibling guides:** [Money](money.md) — the currency-typed amount a `PMoney`
  prop carries losslessly. [Codec](codec.md) — the `Codec.taggedUnion` you build
  a typed event ADT with for `trackEvent`. [Tasks](task.md) — the effect every
  emit returns. [Result](result.md) — the failure channel the store paths use.
- **Concepts:** [Pure functions and immutability](pure-functions.md) — why the
  config is a threaded value, not an installed global.
