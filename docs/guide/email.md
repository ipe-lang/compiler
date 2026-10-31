# Email

`Ipe.Email` sends mail through Resend, AWS SES, SendGrid, or raw SMTP under one
API. Two invariants hold before a single byte leaves the process: an address is
typed at the parse boundary, and every credential is a sealed `Secret`. Sending
itself needs a live provider and network, so this guide teaches the shape and
points at `ipe doc Ipe.Email` for the per-symbol reference rather than a runnable
script.

## The mental model

Three knots.

- **The provider is passed explicitly — there is no ambient install.** Every send
  is `Email.send provider message`. Provider config is never installed into a
  global to be read back later, because that would admit a representable
  "used-before-installed" state. A send without a provider is a compile-time type
  error, not a runtime surprise.
- **An address is parse-don't-validate.** `EmailAddress` is opaque and can only be
  built through `Email.parseAddress`, which returns `Nothing` on an unparseable
  string — never a silent accept. Every address field of a message (`from`, `to`,
  `cc`, `bcc`, `replyTo`) *requires* an `EmailAddress`, so an invalid address
  cannot be put into a message in the first place; the bounce moves from runtime
  to the type checker.
- **Every credential is a sealed `Secret`.** The Resend / SendGrid API keys, the
  SES secret access key, and the SMTP password are all [`Secret`](#references)
  values — they cannot be `Debug`-printed, stringified, logged, or serialised, and
  a committed string literal cannot even become one (that is refused at compile
  time). The runtime reveals a credential only at the actual outbound call; no
  auth error or diagnostic from a failed send carries the plaintext.

## The shape

Build a message from the three required fields with `defaultMessage`, then layer
optional content with `with*` builders (never a record literal, so a future field
addition does not break call sites). The provider carries its credential read
from the environment at runtime:

```ipe
import Ipe.Email as Email
import Ipe.Secret
import Ipe.System as System


provider : Email.EmailProvider
provider =
    -- A Secret is read at runtime — a committed literal is refused (IPE-L0150).
    Email.Resend (Secret.fromString (System.getenvOr "RESEND_API_KEY" ""))


send : Email.EmailAddress -> Email.EmailAddress -> Task Error String
send from to =
    Email.defaultMessage { from = from, to = [ to ], subject = "Welcome" }
        |> Email.withTextBody "Thanks for signing up."
        |> Email.send provider
```

An `EmailAddress` is obtained only through the parse boundary:

```ipe
case Email.parseAddress "alice@example.com" of
    Just addr -> {- addr : EmailAddress -}
    Nothing   -> {- not a valid address -}
```

Explore the full surface — the `with*` builders, the SES / SMTP config records,
and `send` itself — with `ipe doc Ipe.Email`.

Address parsing and message building are pure and fully type-checked: a
malformed address is rejected at `parseAddress`, and a message can only be built
from typed fields. Actually delivering mail is `Email.send provider message`,
which needs a live provider and network — see `ipe doc Ipe.Email`.

## The why

Requiring the provider as an explicit argument is [make invalid states
unrepresentable][principles]: the "installed the provider, then a later send read
stale/absent config" bug has no representation. `EmailAddress` being constructible
only through `parseAddress` is [parse, don't validate][principles] — the untyped
string becomes a typed value at one boundary, and a malformed address is turned
away there, never carried as a doomed send. And every credential being a sealed
`Secret` is [security][principles]'s no-secret-leakage rule: the plaintext cannot
reach a log line, an error message, or a serialised value, and cannot be baked
into source.

[principles]: https://github.com/ipe-lang/compiler/blob/main/PRINCIPLES.md

## Configuration

One env var controls email delivery in non-production environments.
Use `ipe doc IPE_EMAIL_DRY_RUN` for the full entry.

| Variable | Default | Effect |
|----------|---------|--------|
| `IPE_EMAIL_DRY_RUN` | unset (false) | Skip SMTP delivery and return a synthetic message ID. |

See the [**Email** subsystem](https://github.com/ipe-lang/compiler/blob/main/docs/reference/env.md#email) in the
environment variable reference.

## References

- **Per-symbol reference:** `ipe doc Ipe.Email` — `send`, `parseAddress` /
  `addressToString`, `defaultMessage` + the `with*` builders, and the SES / SMTP
  config records. Every credential setter (`withSesSecret`, `withSmtpPass`) takes
  a `Secret`.
- **Sibling guides:** [Network primitives](net.md) — the range-validated `Port`
  `withSmtpPort` takes, so an out-of-range SMTP port cannot reach the transport.
  [Bytes](bytes.md) — the raw content an `Attachment` carries. [Tasks](task.md) —
  the effect `send` returns. `ipe doc Ipe.Secret` — the sealed credential type
  every provider holds.
- **Concepts:** [The parse-don't-validate idiom](../idioms/parse-dont-validate.md)
  — `parseAddress` is the address boundary.
