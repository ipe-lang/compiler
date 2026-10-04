# Pub/sub

`Ipe.PubSub` broadcasts a payload on a typed topic to every subscribed web
session in the same process, and resolves to the number of subscribers that
received it. Its `publish` is a `Task`, so it is callable from anywhere you hold
a `Task` — a raw HTTP handler, a post-init task, a scheduled job, a callback from
an external system — not only from inside a managed update loop.

## The mental model

Three knots.

- **A topic is typed; publisher and subscriber must agree on the payload.**
  `PubSub.topic name` builds a `Topic a` handle. Sharing one `Topic a` value
  between the publisher and the subscriber makes the compiler enforce that both
  sides use the same payload type `a` — a mismatch is a compile error, not a
  runtime decode surprise. The handle carries `a` only at type-check time; at
  runtime it erases to the bare topic-name string, with no wrapper or allocation.
- **`publish` is a `Task`, so it composes anywhere.** Unlike the `Cmd`-shaped
  broadcast you fire from a web `update` return, `PubSub.publish : Topic a -> a ->
  Task Error Int` is an ordinary task. Bridge it into a managed loop with
  `Cmd.perform`, or run it from any other task context. It resolves with the
  subscriber count (0 for a topic with no live subscribers — not an error).
- **The bus lives in the running web runtime; no bus is a typed error.** The
  broadcast bus exists only while a web app is serving in this process. A publish
  from a plain CLI tool, an isolated unit test, or a pure HTTP-server process with
  no web app resolves to `Err Unavailable` — a value the caller handles, never a
  silent no-op. Fan-out is in-process only, fire-and-forget: pair it with a
  durable write (a database row, an append-only log) when persistence matters.

## A worked example: a Task-shaped broadcast in a web app

The example under
[`examples/shapes/web/task-publish`](../../examples/shapes/web/task-publish/src/Main.ipe)
is a `Web.tea` that broadcasts on a shared topic and shows the subscriber count.

The topic is one shared handle — its `String` payload type is what any publish
and any subscription on the same value must agree on:

```ipe
roomTopic : PubSub.Topic String
roomTopic =
    PubSub.topic "room"
```

Because `publish` is a `Task`, it composes into the update loop through
`Cmd.perform`, which runs it and routes its result back as a message:

```ipe
update msg model =
    case msg of
        Publish ->
            ( model
            , Cmd.perform (PubSub.publish roomTopic "hello") Published
            )

        Published (Ok count) ->
            ( { model | lastCount = count }, Cmd.none )

        Published (Err _) ->
            -- No bus in this process: keep the model unchanged.
            ( model, Cmd.none )
```

Building it (`ipe dev build`) compiles the app; serving it, a click broadcasts on the
topic and the resolved subscriber count lands back in the model.

## The why

The typed `Topic a` shared between both sides is [make invalid states
unrepresentable][principles]: the "publisher and subscriber disagree on the
payload type" bug has no representation, because the one handle carries the type
to both ends. Resolving to `Err Unavailable` when no bus is running rather than
silently succeeding is [correctness][principles] — the absence of a bus is a
defined, observable outcome, not a swallowed no-op. And keeping fan-out
in-process and fire-and-forget, with durability left to an explicit write, keeps
the guarantee honest: `publish` promises exactly the in-process broker's
invariant and nothing it cannot deliver.

[principles]: ../../PRINCIPLES.md

## References

- **Per-symbol reference:** `ipe doc Ipe.PubSub` — `topic`, `publish`, and
  `publishNoEcho` (which suppresses the publishing session's own subscription;
  a no-op for a server-side caller with an empty origin).
- **Sibling guides:** [Tasks](task.md) — the effect `publish` returns and
  `Cmd.perform` runs. [Result](result.md) — the `Err Unavailable` a busless
  process sees. [The Elm Architecture](the-elm-architecture.md) — the update loop
  the example bridges the task into.
