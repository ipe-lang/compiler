# Logging

`Ipe.Log` writes **structured, single-line log records** at four severities, and
`Ipe.Level` supplies the `LogLevel` tags that configure the minimum severity an
app emits. Logging is an effect: every write is a `Task`, sequenced in the same
discipline as every other side effect.

## The mental model

Three knots.

- **The severity is the function you call.** `Log.debug`, `Log.info`, `Log.warn`,
  and `Log.error` each write a record *at* that level — there is no severity
  argument to get wrong, and every record carries a level. Warn and error go to
  stderr, debug and info to stdout, matching where an operator expects to find
  them.
- **A log write is a `Task Error ()`.** Logging is not a hidden side effect
  sprinkled through pure code; it is an effect value you sequence with the rest of
  a `do` block. This keeps the pure core pure and makes every place that logs
  visible in the effect flow.
- **The threshold is `Ipe.Level`, set once.** `Log.level` takes a `LogLevel`
  constructor from `Ipe.Level` (`Level.debug` / `info` / `warn` / `error`) and
  returns a cross-shape `Setting` for an app's settings list. A record below the
  configured level is dropped before it is formatted — you leave the `Log.debug`
  calls in place and raise the floor in configuration, rather than deleting them.

## A worked example: four severities

The example under
[`examples/shapes/script/log-severities`](../../examples/shapes/script/log-severities/src/Main.ipe)
emits one record at each of three severities plus one with structured context,
sequenced as tasks.

Each write names its severity in the call; the `*With` form attaches an ordered
list of scalar context values — each a `String`, `Int`, `Float`, `Bool` or
`Char` — alongside the message. A record, `Secret` or other opaque value is
refused at type-check; convert it first (`Error.toString e`, `Secret.redacted s`):

```ipe
main =
    do
        Log.info "service starting"
        Log.debug "config loaded from defaults"
        Log.warn "cache warm-up skipped"
        Log.infoWith "request handled" [ "GET", "/health", "200" ]
        Io.println "done — four log records emitted above"
```

Running it (`ipe dev run`) writes each record as a timestamped, level-tagged line —
the plain shape is `<timestamp> <LEVEL> <message>`:

```
<ts> INFO service starting
<ts> WARN cache warm-up skipped
<ts> INFO request handled GET /health 200
done — four log records emitted above
```

The `debug` line does not appear: the default threshold is `info`, so a
lower-severity record is dropped before it is formatted. Set `IPE_LOG_LEVEL=debug`
(or install `Log.level Level.debug` in an app's settings) to see it, and
`IPE_LOG_FORMAT=json` to switch every line to a JSON object. The timestamp is the
only non-deterministic part of the line.

## Setting the threshold in an app

`Log.level` is the in-code floor, taking a `LogLevel` from `Ipe.Level`:

```ipe
import Ipe.Level as Level

Web.appWith [ Log.level Level.warn ] { ... }
```

With that setting, only `warn` and `error` records are emitted. The precedence is
`env > setting-in-code > default`: `IPE_LOG_LEVEL` overrides the setting, which
overrides the built-in `info` default. `Ipe.Level`'s constructors are the *only*
source of `LogLevel` values, so a threshold is always one of the four known
severities — never a free string.

## The why

Choosing the severity by the function name rather than a `Level -> String -> …`
argument is [make invalid states unrepresentable][principles] for the call site:
there is no way to write a log call with a malformed or absent level, because the
level is baked into which function you reached for. `Ipe.Level`'s closed set of
constructors extends that to the *threshold* — a configured minimum is provably
one of four values.

Modelling a log write as a `Task Error ()` keeps logging honest about being an
effect: it composes in the same [Tasks](task.md) discipline as I/O and network
calls, so the pure parts of a program stay pure and every emitting site is visible
in the effect flow, rather than a `print` buried in a "pure" function. Dropping
sub-threshold records before formatting means leaving diagnostics in the source
costs nothing in production — [correctness][principles] without a runtime tax.

[principles]: ../../PRINCIPLES.md

## Configuration

Two env vars control runtime log output. Use `ipe doc <VAR>` for the full entry.

| Variable | Default | Effect |
|----------|---------|--------|
| `IPE_LOG_LEVEL` | unset (info) | Minimum severity emitted: `debug`, `info`, `warn`, or `error`. |
| `IPE_LOG_FORMAT` | unset (human) | Set to `json` for structured log lines suited to aggregation pipelines. |

See the [**Observability** subsystem](../reference/env.md#observability) in the
environment variable reference.

## References

- **Per-symbol reference:** `ipe doc Ipe.Log` — every severity and its `*With`
  context variant, plus `Log.level`. `ipe doc Ipe.Level` — the four `LogLevel`
  constructors.
- **Sibling guides:** [Tasks](task.md) — the effect discipline every log write
  lives in. [Standard I/O](io.md) — `Io.println` / `Io.eprintln` for bare,
  un-levelled line printing (no timestamp, no severity), the complement to a log
  record. [Tracing](trace.md) — spans and events, the other half of observability.
- **Concepts:** [Types and inference](types.md) — how the closed `LogLevel` set is
  tracked.
