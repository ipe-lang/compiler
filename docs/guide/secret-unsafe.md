# The secret-reveal escape hatch

`Ipe.Secret.Unsafe` is the one home for the member that un-seals a `Secret` back
into a bare `String`. It exists for the rare case a scoped consume cannot express;
reaching for it is a deliberate act with a visible cost, not a convenience.

## When to reach for it

A `Secret` (`Ipe.Secret`) is a sealed value: it cannot be `Debug`-printed,
stringified, logged, or serialised, its bytes are zeroed on drop, and comparing
two secrets is constant-time. That sealing is what keeps a credential out of a log
line or an error message by construction.

The safe way to *use* a secret's plaintext stays on the native `Ipe.Secret`
surface: `Secret.use` applies a function to the plaintext inside a scope and
returns a non-secret result, so the plaintext never escapes the closure — and this
does **not** disclose the `unsafe` capability. Reach for
`Ipe.Secret.Unsafe.unsafeReveal` only for a residual case a scoped consume cannot
express, where you genuinely need the raw `String` to escape the seal and you take
ownership of where it lands.

```ipe
import Ipe.Secret.Unsafe exposing (unsafeReveal)

-- The plaintext now escapes the seal's protections — redaction, no-Debug,
-- zeroize-on-drop — and the caller owns where it goes from here.
raw : String
raw =
    unsafeReveal apiKey
```

## The safety boundary

`unsafeReveal` returns the plaintext outside the sealed newtype's protections. The
`unsafe` prefix names the secret-leak risk at every call site: the moment the
plaintext is a bare `String`, nothing stops it reaching a log, an error, or a
serialised payload — the very leaks the seal existed to prevent.

Two things make the cost visible rather than silent:

- **The reveal lives in a separate submodule.** It is not on the native
  `Ipe.Secret` surface, so it cannot be reached by accident — you must import
  `Ipe.Secret.Unsafe` on purpose.
- **Importing it discloses the `unsafe` capability program-wide.** A dependency's
  raw secret-reveal is visible before the program runs, so an auditor can see that
  some code un-seals secrets without reading every line.

## The why

Keeping the reveal off the default surface and behind a disclosed capability is
[security][principles] and [defence in depth][principles] together: the sealed
type is one boundary, and the fact that escaping it is both explicitly named
(`unsafe`) and program-visible (the capability) is the second. The safe default —
`Secret.use`'s scoped consume — covers the common case without ever un-sealing, so
the hatch stays reserved for the residual it was built for, and every use of it is
an auditable decision.

[principles]: https://github.com/ipe-lang/compiler/blob/main/PRINCIPLES.md

## References

- **Per-symbol reference:** `ipe doc Ipe.Secret.Unsafe` — `unsafeReveal`. The safe
  sibling is `ipe doc Ipe.Secret` — `Secret.use` (scoped consume, no capability
  disclosure), the sealing, and the constant-time compare.
- **Sibling guides:** [The unsafe database surface](db-unsafe.md) — the other
  escape hatch, and the same `unsafe`-capability disclosure model.
