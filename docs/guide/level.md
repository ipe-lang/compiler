# Log levels

`Ipe.Level` is the four-value severity tag — `debug`, `info`, `warn`, `error` —
that names a logging threshold. It is a small companion to [Logging](log.md): its
only job is to supply a `LogLevel` for `Log.level`, which sets the minimum
severity an application records.

This page is reference-only: `Ipe.Level` has no behaviour of its own to
demonstrate, and its one real use — configuring an app's log floor — is a running
app's setting, shown in the [Logging guide](log.md#setting-the-threshold-in-an-app).
The worked,
runnable example lives there.

## The mental model

- **`LogLevel` is a closed set of four constructors.** `Level.debug`,
  `Level.info`, `Level.warn`, and `Level.error` are the *only* `LogLevel` values —
  there is no fifth level to invent and no string to misspell. They are ordered by
  severity: `debug` is the most verbose, `error` the most severe.
- **The only sink is `Log.level`.** `Log.level Level.warn` produces a cross-shape
  `Setting` you place in an application's settings list; every record below the
  configured level is dropped before it is formatted. You never pattern-match a
  `LogLevel` yourself — you hand a constructor to `Log.level` and the runtime does
  the comparison.

## The why

Making severity a closed ADT rather than a string or an integer is
[make invalid states unrepresentable][principles]: a threshold is exactly one of
four named levels, so a typo or an out-of-range number cannot reach the log
configuration. Splitting the tag into its own tiny module lets both `Ipe.Log` and
any future severity-aware surface depend on the same four values without
depending on each other.

[principles]: https://github.com/ipe-lang/compiler/blob/main/PRINCIPLES.md

## References

- **Per-symbol reference:** `ipe doc Ipe.Level` — the four constructors.
- **Sibling guides:** [Logging](log.md) — where a `LogLevel` is actually used, with
  a runnable example of the four write functions and the `Log.level` threshold.
