# Browser ports

`Ipe.Js` is the typed transport across the Ipê↔JS seam — ports. A port carries an
imperative effect or out-of-band data that has no place in the view tree
(streaming, analytics, handing off to hand-written JS). It is not a new language
construct: outbound is an ordinary `Cmd msg` (`Js.send`), inbound an ordinary
`Sub msg` (`Js.subscribe`), reusing the machinery a web app already has.

## The mental model

Three knots.

- **One discipline governs every value crossing the seam: a concrete-ADT SEAL.**
  Only a closed, declared, monomorphic value type may cross — primitives, records,
  tuples, `List`/`Set`/`Maybe`/`Dict`/`Result`, and user ADTs transitively over
  those. A function, an effect carrier, a view value, an open row, a type
  variable, and — the security tightening — a `Secret` may NEVER cross. The seal is
  checked fail-closed at compile time on the concrete type; an illegal payload is
  a compile error, not a runtime surprise.
- **The published surface is deliberately narrow — two closed ADTs, one per
  direction.** `JsCmd` is the one outbound type; build a value and hand it to
  `send`. The inbound type is a narrow published ADT, deliberately *not* the
  internal `Msg`: the browser is attacker-controlled, so publishing `Msg` would
  hand an attacker every transition the state machine can reach. The `case` that
  folds an inbound value into a `Msg` is exhaustive — an unhandled inbound variant
  is a type error, not a silent drop.
- **The inbound decoder IS the security gate.** The far side is always untrusted,
  so every inbound value runs through the total, fail-closed, bounded seal
  decoder. A malformed, oversized, or mismatched message is dropped whole —
  observable, with no partial value and no panic. `Decoder Value` is rejected at
  compile time: the untyped channel cannot be spelled. A genuinely opaque payload
  is expressed by *naming* it (`type RawJson = RawJson String`), never left an
  untyped hole.

## Four port shapes

The same SEAL governs four transport shapes, chosen by the interaction:

- **`send : a -> Cmd msg`** — a fire-and-forget outbound effect.
- **`subscribe : Decoder a -> (a -> msg) -> Sub msg`** — a free-broadcast inbound
  stream (a latest-value sensor).
- **`request : a -> Decoder b -> Task b`** — a correlated *one-shot*
  request/reply, resolved as a `Task`.
- **A session** — a correlated, **bounded**, *many-frame* lifecycle
  (`open → N frames → close → terminal`). `openSession` mints an opaque
  `SessionHandle` (no constructor — you can only address a session you opened),
  `sessionFrames` streams that handle's inbound frames through the seal gate,
  `sendToSession` sends a control cmd, and `closeSession` awaits a terminal reply.
  Bounded by construction: a ceiling caps open sessions, a per-session frame
  budget + deadline cap one session, and an overflow/timeout resolves `closeSession`
  with a fail-closed terminal `Err` — an ordered stream never silently drops a
  frame. Use a session for a correlated ordered stream (a media recording, a
  progressive host operation); keep a free latest-value sensor a `subscribe`.

## A worked example: an outbound effect and a guarded inbound stream

The example under
[`examples/shapes/web/js-ports`](../../examples/shapes/web/js-ports/src/Main.ipe)
is a `Web.tea` that sends a closed `JsCmd` outbound and subscribes to a guarded
`Int` inbound stream.

The outbound surface is one closed ADT — the whole attack surface as a single
auditable object; `send` takes a value of it:

```ipe
type JsCmd
    = Chime Int


update msg model =
    case msg of
        Ring ->
            ( model, Js.send (Chime 1) )
        ...
```

The inbound decoder is the fail-closed gate — a value that does not decode is
dropped whole; a decoded value is folded in through a *narrow* message, never the
internal `Msg` directly:

```ipe
subscriptions : Model -> Sub.Sub Msg
subscriptions _model =
    Js.subscribe Decode.int Ticked
```

Building it (`ipe dev build`) compiles the app — reaching a built binary means both
`ipe` accepted the program and the emitted Rust compiled, which is the seal for a
port program: a seal-legal payload lowers to the shared transport with no
per-port adapter.

## The why

The concrete-ADT SEAL is [make invalid states unrepresentable][principles] at the
trust boundary: a function, an open row, or a `Secret` crossing to attacker
territory has no representation, so the whole class of "leaked a capability or a
credential over a port" cannot be written. The inbound decoder being total and
bounded, dropping anything that does not decode, is [security][principles]'s
fail-closed rule — on input not provably a legal message, the reachable outcome
is *drop*, never a partial or panicking parse (which also caps what an adversarial
sender can exhaust). And publishing a narrow inbound ADT rather than the internal
`Msg` is defence in depth: even past the decoder, the browser can only name the
transitions you deliberately exposed.

[principles]: ../../PRINCIPLES.md

## References

- **Per-symbol reference:** `ipe doc Ipe.Js` — `send` (outbound one-shot effect),
  `subscribe` (guarded inbound stream), `request` (correlated one-shot), and the
  session ops `openSession` / `sessionFrames` / `sendToSession` / `closeSession`
  (a correlated bounded stream). A module whose reachable code uses a port
  discloses the `js-port` capability.
- **Generic session example:**
  [`examples/wasm/session-stream`](../../examples/wasm/session-stream/src/Main.ipe)
  — a demo ticker session over a developer echo handler.
- **Sibling guides:** [The Elm Architecture](the-elm-architecture.md) — the
  `Cmd`/`Sub` machinery ports reuse. [Codec](codec.md) — the typed decode
  discipline `subscribe`'s gate applies at the boundary. [Result](result.md) and
  [Maybe](maybe.md) — seal-legal container payloads that may cross.
- **Concepts:** [The parse-don't-validate idiom](../idioms/parse-dont-validate.md)
  — the inbound decoder is the trust boundary where an untrusted message becomes a
  typed value or is dropped.
