# Error

`Ipe.Error` is the structured error type carried by every `Task` and every
`Result Error a`. It is not a string: each constructor tags the *kind* of failure
at construction time, so downstream code decides what to do — retry, report, give
up — by reading the tag, never by pattern-matching a message.

## The mental model

Three knots.

- **An `Error` classifies the failure at construction.** You build one with a
  kind-naming constructor: `Error.network msg`, `Error.invalidInput msg`,
  `Error.timeout`, `Error.notFound`, `Error.permissionDenied`, and so on. The kind
  is part of the value, so the reason a thing failed is data, not prose to be
  re-parsed. Message-carrying constructors take a description; canonical ones
  (`timeout`, `notFound`, `permissionDenied`) carry a fixed message.
- **`isRetryable` reads the tag, so a policy is one query.** "Retry transient
  failures" is `Error.isRetryable err` — `True` for `timeout`, `network`, and
  `unavailable` — not a fragile substring search on the message. `Error.kind`
  extracts the tag itself, and `Error.kindName` its stable lowercase label, for
  richer branching or metrics.
- **`toString` renders `"<Kind>: <message>"`.** For a log line you get a compact,
  classified string. The structured `ErrorDetails` a value may carry (attached with
  `withDetails`) stay out of that rendering, so a log line doesn't accidentally leak
  a payload.

## A worked example: a retry policy by error kind

The example under
[`examples/shapes/script/error-retry-policy`](../../examples/shapes/script/error-retry-policy/src/Main.ipe)
takes a list of representative failures and decides, for each, whether to retry —
using the kind, not the message text.

The failures are built with kind-naming constructors, so each carries its
classification:

```ipe
samples : List Error
samples =
    [ Error.network "connection reset"
    , Error.invalidInput "port must be 1..65535"
    , Error.timeout
    , Error.notFound
    , Error.unavailable "upstream draining"
    ]
```

The decision is one `isRetryable` on the structured value — the message text is
never inspected, so a reworded message can't break the policy:

```ipe
policyLine : Error -> String
policyLine err =
    let
        verdict =
            if Error.isRetryable err then
                "RETRY"

            else
                "FAIL "
    in
    verdict ++ " " ++ Error.toString err
```

Running it (`ipe dev run`):

```
Failure -> retry policy (by error kind, not message text):
  RETRY Network: connection reset
  FAIL  InvalidInput: port must be 1..65535
  RETRY Timeout: operation timed out
  FAIL  NotFound: not found
  RETRY Unavailable: upstream draining
```

The transient kinds retry; the caller's mistake (`InvalidInput`) and the
definitive `NotFound` do not.

## The why

A structured `Error` rather than a `String` is [parse, don't
validate][principles] on the error channel: the failure's classification is
computed once, at construction, and every reader works from the typed tag instead
of re-deriving intent from prose. The fundamental rules say error channels are
typed (`Diagnostic` / `Error`), never bare strings — a string error forces every
consumer to guess, and a reworded message silently breaks a policy built on it.

Reading the kind with `isRetryable` / `kind` is [correctness][principles]: the
retry decision is a total function of the error's type, deterministic and
message-independent. And keeping structured details out of `toString` is a small
[security][principles] guard — the human-facing render carries the kind and
message, not whatever context a detail payload might hold, so a log line doesn't
become an accidental leak.

[principles]: ../../PRINCIPLES.md

## References

- **Per-symbol reference:** `ipe doc Ipe.Error` — every constructor and inspector
  with a verified example. `ipe doc Ipe.Error.isRetryable`, `ipe doc Ipe.Error.kind`,
  and `ipe doc Ipe.Error.withDetails` cover classification and structured context.
- **Sibling guides:** [Result](result.md) — `Result Error a`, where an `Error` is
  the failure payload. [Tasks](task.md) — the effect type whose implicit error
  channel is `Error`, recovered with `Task.onError` / `Task.mapError`.
- **Concepts:** [Types and inference](types.md) — how the `Error` channel is
  tracked through a `Task` / `Result`. [The parse-don't-validate
  idiom](../idioms/parse-dont-validate.md) — classifying a failure once, at the
  boundary.
