# Console authentication

`Ipe.Web.Console` provides the `Identity` type and its builders for the optional
`consoleAuth` field on a `Web.tea` config. When the framework gates the embedded
console in app-mode, it runs your callback per request *before* mounting console
routes, so the console inherits the app's own auth surface — no second token to
provision.

## The mental model

Three knots.

- **`consoleAuth` is a per-request gate, run before console routes mount.** The
  callback has shape `Request -> Task Error (Maybe Identity)`. `Nothing` denies
  the request — a 403 plus a structured `console.auth.denied` audit log entry.
  `Just identity` lets it continue; the identity rides the console's session
  cookie and is attached to subsequent telemetry for audit. The gate runs on
  every request, so there is no window where the console is reachable un-gated.
- **`Identity` is built through builders, not a record literal.**
  `defaultIdentity subject` starts an identity with an empty email and no claims;
  `withEmail`, `withClaim`, and `withClaims` layer on the rest. Building through
  the builder chain keeps call sites source-compatible as optional fields are
  added later — the same discipline the other typed records in the standard
  library follow.
- **It reuses the app's existing auth — one identity surface.** The point is to
  thread an app's SSO or multi-tenant session middleware straight into
  `consoleAuth`, so the console is gated by the same check the rest of the app
  uses. `subject` is the stable identifier, `email` is surfaced separately so the
  audit log line is human-scannable, and `claims` carries extra attributes a
  role-based-access layer consults.

## A worked example: gating the console

The example under
[`examples/shapes/web/console-auth`](../../examples/shapes/web/console-auth/src/Main.ipe)
is a `Web.tea` that supplies a `consoleAuth` callback building an identity with
the `Ipe.Web.Console` builders.

The callback is a `Task` returning `Maybe Identity` — a real app reads a session
from the request; returning `Nothing` denies with a 403 and an audit log:

```ipe
identify : Request -> Task Error (Maybe Identity)
identify _req =
    Task.succeed
        (Just
            (Console.defaultIdentity "user-42"
                |> Console.withEmail "alice@example.com"
                |> Console.withClaim "role" "admin"
            )
        )
```

It is wired through the optional `consoleAuth` field on `Web.tea`:

```ipe
main =
    Web.tea
        { init = init, update = update, view = view
        , subscriptions = subscriptions
        , routes = [], notFound = Ignored
        , consoleAuth = identify
        }
```

Building it (`ipe dev build`) compiles the app; when the console is gated in app-mode,
the callback runs per request and only an authorised identity reaches it.

## The why

Running the gate per request before the console mounts, and denying with a 403 on
`Nothing`, is [security][principles]'s fail-closed rule at the console boundary:
absent an identity the request is refused, and the refusal is audit-logged rather
than silently swallowed. Building `Identity` through builders rather than a record
literal is [ease of use][principles] carried forward — an added field does not
break existing call sites. And returning `Maybe Identity` inside a `Task` keeps
authentication an ordinary effect the app composes, reusing the same session
check the rest of the app already runs — one identity surface, not two.

[principles]: ../../PRINCIPLES.md

## Configuration

Several env vars control the embedded developer console. Use `ipe doc <VAR>` for
the full entry on any of them.

Two credential roles guard the surface. The **admin** token opens
`/_ipe/console*` and `/_ipe/metrics`; the **metrics** token opens `/_ipe/metrics`
only, so a Prometheus scrape credential can never read logs or spans. Either is
presented as `Authorization: Bearer <token>` or as the password of HTTP Basic auth.

`ipe dev build`, `ipe dev run`, `ipe test` and `ipe dev watch` produce development binaries:
with `IPE_CONSOLE_AUTH` unset, their console is open only while the server is
bound to loopback, and on an exposed bind it requires a credential. `ipe release`
artifacts keep the console closed until `IPE_CONSOLE_AUTH` (with its admin token)
is set, on every bind.

| Variable | Default | Effect |
|----------|---------|--------|
| `IPE_ADMIN_TOKEN` | unset | Admin token: opens the console and `/_ipe/metrics` in production or under `IPE_CONSOLE_AUTH=token`. Without it (or with a non-UTF-8 value) a production console is not mounted. |
| `IPE_CONSOLE_AUTH` | auto (token; open only in a dev build on loopback) | `token` requires a credential in every posture, dev included; `off` disables the console; `app` mounts it but answers 501 on the Rust runtime (the `consoleAuth` callback is not supported there). The posture picks the default only when the variable is unset or blank; any other value (including a non-UTF-8 one) disables it too. Startup logs the effective posture, mode, and source once (`[ipe.console] auth posture=… mode=… source=…`), never a token. |
| `IPE_CONSOLE_EMBED` | auto (on in dev) | Set to `off` to disable the embedded console. |
| `IPE_CONSOLE_HUB` | unset | Base URL of a remote Ipê Hub OTLP collector. |
| `IPE_DEV_BANNER` | auto (on in dev) | Set to `off` to suppress the dev-mode banner. |
| `IPE_METRICS_TOKEN` | unset | Metrics token: authorizes the `/_ipe/metrics` scrape only, never the console. The admin token is accepted on `/_ipe/metrics` too. |

See the [**Console** subsystem](../reference/env.md#console) in the
environment variable reference.

## References

- **Per-symbol reference:** `ipe doc Ipe.Web.Console` — the `Identity` record and
  its builders (`defaultIdentity`, `withEmail`, `withClaim`, `withClaims`).
- **Sibling guides:** [Tasks](task.md) — the effect the `consoleAuth` callback
  returns. [Maybe](maybe.md) — the `Just`/`Nothing` allow/deny result.
  [Dictionaries](dict.md) — the `claims` map an RBAC layer consults.
- **Concepts:** [The Elm Architecture](the-elm-architecture.md) — the `Web.tea`
  config `consoleAuth` extends.
