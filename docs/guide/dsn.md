# Database connection descriptors

`Ipe.Db.Dsn` is a typed, opaque **database connection descriptor**. A `Dsn` is a
parsed, validated proof that a connection string passed every check — its driver
is known, its port is in range, its transport is not cleartext — and its password
is a `Secret` with no accessor, so a descriptor cannot leak a credential.

## The mental model

Three knots.

- **`parse` and `build` are the only seals, and they enforce the same invariants.**
  You obtain a `Dsn` from a full URL string (`Dsn.parse`) or from typed parts
  (`Dsn.build`); both apply the same fail-closed rules in the runtime, `parse` to
  URL text and `build` to literal parts. An
  unknown driver, an out-of-range port, an explicit `sslmode=disable`, a smuggled
  duplicate credential, or a control character is a typed `Err`, never a
  silently-accepted descriptor. A `Dsn` in hand is a proof, not a hope.
- **The password is a `Secret` with no way out.** The descriptor captures its
  password as a `Secret`; there is no password accessor. The single display path
  is `Dsn.redacted`, which substitutes a placeholder. A `Dsn` therefore cannot be
  logged, interpolated, or printed into leaking its credential — the type removes
  the sink.
- **Parsing is pure; connecting is a separate capability.** A `Dsn` on its own
  performs no I/O and discloses no capability, so building and inspecting one is
  safe and side-effect-free. `Dsn.open` — which actually dials the host —
  discloses `network` and returns a `Connection ReadOnly`, whose read-only posture
  is a *type*, not a runtime flag: a write against it is a compile error.

## A worked example: parse, redact, reject

The example under
[`examples/shapes/script/dsn-parse-redact`](../../examples/shapes/script/dsn-parse-redact/src/Main.ipe)
parses a valid Postgres DSN, prints its redacted form and typed parts, then shows
a cleartext-transport DSN and an unknown-driver DSN both rejected.

`parse` returns `Result Error Dsn`, so an accepted and a rejected string are the
two arms of one `case`; `redacted` is the only rendering of a `Dsn`:

```ipe
describe : String -> String
describe raw =
    case Dsn.parse raw of
        Ok dsn ->
            "accepted: "
                ++ Dsn.redacted dsn
                ++ " | driver="
                ++ driverName (Dsn.driver dsn)
                ++ " host="
                ++ Dsn.host dsn
                ++ " port="
                ++ portText (Dsn.port dsn)

        Err _ ->
            "rejected (fail-closed): " ++ raw
```

Running it (`ipe dev run`) over three descriptors prints:

```
accepted: postgres://app@db.internal:5432/store (tls=require, password=[redacted]) | driver=postgres host=db.internal port=5432
rejected (fail-closed): postgres://app:s3cr3t@db.internal:5432/store?sslmode=disable
rejected (fail-closed): mysql://app@db.internal/store
```

The accepted line carries no password at all — `redacted` renders
`password=[redacted]`, so the raw `s3cr3t` never appears even though it was in the
input. The `sslmode=disable` string is rejected because a `Dsn` is never a proof
of a cleartext transport, and `mysql` is rejected because it is not one of the two
drivers the runtime links.

## The why

Making `parse` / `build` the only constructors is [parse, don't
validate][principles] at the connection boundary: past the one seal, a `Dsn` is a
validated value no downstream code re-checks, so there is no "is this DSN
actually safe?" question threaded through the connector. A driver outside the
known set, or a cleartext transport, simply has no `Dsn` representation — [make
invalid states unrepresentable][principles] applied to the descriptor.

Capturing the password as a `Secret` with no accessor and only a `redacted`
display path is [security][principles]'s fail-closed rule made structural: the
credential-leak sink is *removed*, not merely discouraged, so a `Dsn` cannot be
the source of a password in a log line. And splitting the pure parse from the
`network`-disclosing `open` keeps the capability honest — inspecting a descriptor
costs nothing and reaches nothing, while dialing a host is a separately-reviewed
step whose read-only result is enforced by the type, not a runtime check.

[principles]: ../../PRINCIPLES.md

## References

- **Per-symbol reference:** `ipe doc Ipe.Db.Dsn` — `parse` / `build`, the
  accessors (`driver` / `host` / `port` / `database` / `user` / `tls`),
  `redacted`, and the `network`-disclosing `open` / `close`.
- **Sibling guides:** [Result](result.md) — what `parse` and `build` return.
  [Network primitives](net.md) — the validated `Port` a DSN's port accessor
  yields. [Codec](codec.md) — how a row's columns are decoded once a connection is
  open. [Maybe](maybe.md) — the `Maybe Port` a file-backed sqlite descriptor
  returns (no port).
- **Concepts:** [The parse-don't-validate idiom](../idioms/parse-dont-validate.md)
  — a `Dsn` is the boundary where an untyped connection string becomes a typed,
  credential-safe descriptor.
