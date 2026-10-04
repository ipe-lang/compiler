# HTTP

`Ipe.Http` is the outbound HTTP client. Sending a request is a `Task` — an
effect the runtime performs — but the request itself is a typed value you build
purely before anything reaches the network. This guide covers that build side:
the typed target, the closed method set, and query parsing.

## The mental model

Three knots.

- **The request target is a typed, scheme-narrowed value, not a raw string.**
  A request carries a `Url` that was parsed once and narrowed to `http`/`https`
  at this layer. `Http.defaultRequestFromString` is the marked boundary: it runs
  the one URL parse and rejects any other scheme, returning `Result Error
  HttpRequest`. A `file:` or `ftp:` target is a typed `Err` at construction — it
  can never become a request that reaches the network, even when the runtime's
  SSRF guard is off in development.
- **`HttpMethod` is a closed set.** The verbs are constructors (`Get`, `Post`,
  `Put`, …), used directly in client code. `Http.methodFromString` is the single
  parse boundary for an inbound verb string (say, a method read off a request
  line); an unrecognised verb is `Nothing`, never a silent default.
- **Building is pure; sending is a task.** `defaultRequest` and the `with*`
  builders (`withMethod`, `withHeader`, `withBody`, `withTimeout`) are ordinary
  pure functions that refine the typed request. Only `get` / `post` / `request`
  are effects. So you assemble and inspect a request with no I/O at all.

## A worked example: assembling requests

The example under
[`examples/shapes/script/http-request-builder`](../../examples/shapes/script/http-request-builder/src/Main.ipe)
builds requests from raw string targets, parses inbound verbs, and decodes a
query string — all without sending.

Building runs the parse boundary, then refines the typed request with the pure
`with*` builders:

```ipe
buildRequest : String -> Result Error Http.HttpRequest
buildRequest raw =
    Http.defaultRequestFromString raw
        |> Result.map (Http.withMethod Http.Post)
        |> Result.map (Http.withHeader "content-type" "application/json")
        |> Result.map (Http.withBody "{\"ok\":true}")
```

Because the boundary narrows the scheme, a `file:` or `ftp:` target never yields
a request:

```ipe
describe : String -> String
describe raw =
    case buildRequest raw of

        Ok req ->
            raw ++ "  ->  " ++ Http.methodToString req.method ++ " " ++ req.url

        Err _ ->
            raw ++ "  ->  REJECTED"
```

Inbound verbs pass through the single parse boundary, and `Http.parseQuery`
decodes a query string into a `Dict`, percent-decoding each key and value. A
malformed escape or invalid UTF-8 anywhere refuses the whole query as an `Err`:

```ipe
case Http.parseQuery "?q=red%20shoes&page=2" of
    Ok params ->
        Maybe.withDefault "?" (Dict.get "q" params)

    Err _ ->
        "(refused)"
```

Running it (`ipe dev run`) shows the two http(s) targets assembled into `POST`
requests, the two wrong-scheme targets rejected, the verbs parsed, and the
decoded query value `red shoes`.

## The why

The typed `Url` target is [parse, don't validate][principles] at the SSRF
boundary: the raw string is parsed exactly once, and the scheme narrowing makes
a non-`http(s)` request unrepresentable — a fail-closed defence that does not
depend on the runtime guard being on. The closed `HttpMethod` ADT is
[make invalid states unrepresentable][principles]: there is no "unknown verb"
value to leak downstream, only a `Nothing` at the one parse point.

[principles]: ../../PRINCIPLES.md

## Configuration

Two env vars tune the HTTP client at runtime. Use `ipe doc <VAR>` to read the
full entry for any of them.

| Variable | Default | Effect |
|----------|---------|--------|
| `IPE_HTTP_MAX_BODY_BYTES` | 33554432 (32 MiB) | Cap on outbound response bodies. |
| `IPE_HTTP_DENY_PRIVATE` | auto (on in production) | Block SSRF-vector private/loopback targets. |
| `IPE_HTTP_BIND` | auto | Override the server bind address. |

All vars are in the **HTTP client** subsystem of the
[environment variable reference](../reference/env.md#http-client).

## References

- **Per-symbol reference:** `ipe doc Ipe.Http` — every function with its
  signature: the effect senders `get` / `post` / `request`, the builders, and the
  `HttpMethod` / `RedirectPolicy` helpers.
- **Sibling guides:** [URLs](url.md) — the typed, validated `Url` a request
  targets; `Url.fromString` is the one constructor the request boundary builds
  on. [WebSocket](websocket.md) — the long-lived bidirectional peer connection,
  for when request/response is the wrong shape. [Tasks](task.md) — how the effect
  senders are sequenced and recovered. [Result](result.md), which the request
  builders return.
- **Concepts:** [The parse-don't-validate idiom](../idioms/parse-dont-validate.md).
