# WebSocket

`Ipe.WebSocket` is the outbound WebSocket client — a long-lived, bidirectional
connection to a peer, for a chat stream, a collaborative editor, or a live feed.
Opening and driving a socket happens inside a `Ipe.Tea.Web` update loop; this
guide covers the typed values you build before connecting: the sealed URL and
the connect configuration.

## The mental model

Three knots.

- **A `WsUrl` is proof of scheme.** The only constructor, `WebSocket.url`, takes
  an already-validated `Ipe.Url.Url` and returns `Ok` only when the scheme is
  `ws` or `wss`; any other scheme is a typed `Err`. `connect` takes a `WsUrl`, so
  a non-WebSocket address — an `https://` URL, a bare string — cannot reach a live
  socket. Two parse boundaries compose: `Url.fromString` rejects a malformed URL,
  then `WebSocket.url` narrows the scheme.
- **The connect config is a typed record with builders.** Start from
  `WebSocket.defaultCfg wsUrl`, then override with `withHeaders` (say, an
  `Authorization` header on the upgrade handshake), `withTimeout`, and
  `withPingInterval`. Because you build from `defaultCfg` and refine with `with*`
  helpers, a future field addition never breaks your call site.
- **Durations are typed, not raw milliseconds.** `withTimeout` and
  `withPingInterval` take an `Ipe.Duration` (e.g. `Duration.seconds 10`), not a
  bare `Int`, so a unit mix-up is a type error rather than a socket that pings a
  thousand times too fast.

## A worked example: sealing URLs and building a config

The example under
[`examples/shapes/script/websocket-url-seal`](../../examples/shapes/script/websocket-url-seal/src/Main.ipe)
seals candidate URLs and builds a connect config — without opening a socket.

Sealing composes the two boundaries with `Result.andThen`:

```ipe
seal : String -> Result Error WebSocket.WsUrl
seal raw =
    Url.fromString raw
        |> Result.andThen WebSocket.url
```

A wrong scheme (`https://`) or a malformed string is rejected; only a `ws`/`wss`
URL seals:

```ipe
describe : String -> String
describe raw =
    case seal raw of

        Ok wsUrl ->
            raw
                ++ "  ->  sealed host="
                ++ Maybe.withDefault "?" (Url.host (WebSocket.toUrl wsUrl))

        Err _ ->
            raw ++ "  ->  REJECTED"
```

The config is a value built from typed durations — nothing connects:

```ipe
configFor : WebSocket.WsUrl -> WebSocket.WebSocketCfg
configFor wsUrl =
    WebSocket.defaultCfg wsUrl
        |> WebSocket.withHeaders [ ( "authorization", "Bearer token" ) ]
        |> WebSocket.withTimeout (Duration.seconds 10)
        |> WebSocket.withPingInterval (Duration.seconds 15)
```

Running it (`ipe dev run`) shows the `wss` and `ws` candidates sealed with their
hosts, the two wrong candidates rejected, and the config's timeout and ping
interval as milliseconds.

## Driving a live socket

Sealing and configuring are pure; the live lifecycle runs inside a
`Ipe.Tea.Web` app:

1. `Cmd.perform (WebSocket.connect wsUrl) Connected` — start the handshake; the
   task resolves to a `WebSocket` handle once it completes.
2. `subscriptions model = WebSocket.onMessage sock GotFrame` — each incoming
   `Text` or `Binary` frame flows through `update` as a `Msg`.
3. `WebSocket.send sock "hello"` — write a text frame.
4. `WebSocket.close sock` — release the connection (idempotent). When a web
   session is evicted, the runtime closes every socket it owns automatically, so
   app code is never responsible for cleanup on disconnect.

## The why

The `WsUrl` seal is [parse, don't validate][principles]: a value of that type is
proof the scheme was checked, and `connect`'s signature makes an unchecked
target unrepresentable. Typed durations are [make invalid states
unrepresentable][principles] at the unit boundary. Building from `defaultCfg`
with `with*` helpers is [correctness][principles] over time — the record can grow
without breaking existing call sites.

[principles]: ../../PRINCIPLES.md

## Configuration

Three env vars tune WebSocket behaviour at runtime. Use `ipe doc <VAR>` for the
full entry on any of them.

| Variable | Default | Effect |
|----------|---------|--------|
| `IPE_WS_HEARTBEAT` | 30 | Ping interval (seconds); two missed responses disconnect the peer. |
| `IPE_WS_MAX_MESSAGE_BYTES` | 1048576 (1 MiB) | Maximum message size for both client and server connections. |
| `IPE_WS_SEND_BUFFER` | 256 | Per-connection outbound frame buffer depth. |

See the [**WebSocket** subsystem](../reference/env.md#websocket) in the
environment variable reference.

## References

- **Per-symbol reference:** `ipe doc Ipe.WebSocket` — every function with its
  signature: `url` / `toUrl`, the `defaultCfg` / `with*` config builders,
  `connect` / `connectWith` / `send` / `close`, and the `onOpen` / `onMessage` /
  `onClose` / `onError` subscriptions.
- **Sibling guides:** [URLs](url.md) — the validated `Url` `WebSocket.url` seals.
  [HTTP](http.md) — request/response, for when you do not need a long-lived
  bidirectional channel. [Durations](duration.md) — the unit-explicit spans the
  config takes. [Tasks](task.md) — how `connect` / `send` are sequenced.
- **Concepts:** [The parse-don't-validate idiom](../idioms/parse-dont-validate.md).
