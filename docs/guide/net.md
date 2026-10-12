# Network primitives

`Ipe.Net` provides typed network primitives. Today that is `Port` — an opaque,
range-validated TCP/UDP port number — the small type that stops an invalid port
from ever reaching a live socket.

## The mental model

Three knots.

- **`Port` is opaque — `fromInt` is the only door, and it rejects.** The only way
  to build a `Port` is `Net.fromInt`, which returns `Err` for anything outside
  `1..65535` (port `0` is the reserved "no port" sentinel, not dialable, so it too
  is rejected). The constructor is not exported, so a value of type `Port` is
  *proof* its number is in range — there is no unchecked `Port`.
- **Connection surfaces take a `Port`, not an `Int`.** `Db.Dsn.build`,
  `Email.SmtpConfig`, and every dialable surface require a `Port`, never a bare
  integer. So an out-of-range or zero port fails at *construction*, upstream of any
  socket — the type moves the check to the boundary and keeps it there.
- **`min`/`max` are total, known-valid ports.** `Net.min` (`1`) and `Net.max`
  (`65535`) are ordinary `Port` values, not `Result`s — useful as the seed for
  `Result.withDefault` when a config falls back to a compile-time-safe default port
  rather than threading a `Result` through the whole config.

## A worked example: guarding config ports

The example under
[`examples/shapes/script/net-port-guard`](../../examples/shapes/script/net-port-guard/src/Main.ipe)
runs a mix of candidate port numbers through the single gate, then builds a config
port with a safe default.

`fromInt` is the one gate: each candidate becomes `Ok Port` or a typed `Err`, and
the raw number is recovered with `toInt` only at the boundary:

```ipe
describe n =
    case Net.fromInt n of

        Ok port ->
            String.fromInt n ++ "  ->  ok (Port " ++ String.fromInt (Net.toInt port) ++ ")"

        Err _ ->
            String.fromInt n ++ "  ->  REJECTED (out of 1..65535)"
```

A config default runs through the *same* gate and falls back to `Net.min` — a
total, known-valid port — so the result is always a real `Port`, never a
half-checked integer:

```ipe
configPort raw =
    Result.withDefault Net.min (Net.fromInt raw)
```

Running it (`ipe dev run`) accepts the in-range ports, rejects `0`, `70000`, and `-1`,
and shows the default fallback:

```
Port validation:
  443  ->  ok (Port 443)
  8080  ->  ok (Port 8080)
  0  ->  REJECTED (out of 1..65535)
  70000  ->  REJECTED (out of 1..65535)
  22  ->  ok (Port 22)
  -1  ->  REJECTED (out of 1..65535)
default from 0 falls back to port 1
default from 5432 keeps port 5432
```

## The why

The opaque `Port` is [parse, don't validate][principles] at its sharpest: the
range check happens once, in `fromInt`, and its result is a type that *cannot*
hold an out-of-range value — so `Db.Dsn.build` and the SMTP config never re-check
and never can be handed a bad port. A bare-`Int` port passed around would force
every socket-facing function to re-validate or trust, exactly the ambiguity this
removes.

Rejecting the port at construction rather than at connect time is
[deny-by-default][principles]: the failure surfaces where the value is *built*,
close to the config that produced it, not deep in a dial that is harder to trace.
And exposing `min`/`max` as total values is [ease of use][principles] — a safe
default is a plain `Port`, so falling back does not drag a `Result` through code
that just wants a sensible port.

[principles]: ../../PRINCIPLES.md

## References

- **Per-symbol reference:** `ipe doc Ipe.Net` — `fromInt`, `toInt`, `min`, `max`,
  and the opaque `Port` type.
- **Sibling guides:** [URLs](url.md) — the opaque, validated `Url`; `Net.Port` is
  the same seal discipline for the port half of an address. [Results](result.md) —
  what `fromInt` returns, and `withDefault` for the safe fallback. `Ipe.Db.Dsn`
  (see `ipe doc Ipe.Db.Dsn`) is a connection surface that takes a `Port`.
- **Concepts:** [The parse-don't-validate idiom](../idioms/parse-dont-validate.md)
  — the discipline the opaque `Port` embodies. The
  [live/HTTP security invariants ADR](../adr/0003-security-render-and-data-access-invariants.md).
