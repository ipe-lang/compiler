# Characters

A `Char` is a single Unicode code point — the atom a `String` is made of.
`Ipe.Char` classifies characters and bridges them to the integer *rune* underneath,
which is what makes character arithmetic possible.

## The mental model

Three knots.

- **A Char is a code point — an integer rune underneath.** `Char.toCode 'A'` is
  `65`; `Char.fromCode 97` is `'a'`. This pair is the bridge to *arithmetic on
  characters*: to shift, compare, or offset a letter you work on its code point,
  then convert back. A `Char` is not a tiny string — it is one scalar value.
- **Classification predicates are the building blocks.** `isUpper`, `isLower`,
  `isDigit`, `isAlpha`, `isHexDigit` each answer a `Bool`. Real character code —
  tokenisers, validators, ciphers — is "decide what this character *is*, then act
  on it"; the predicates are how you decide, so the branch is explicit and total.
- **Case mapping can grow — `toLower`/`toUpper` return a `String`, not a `Char`.**
  One code point can upper-case to several (the classic is `ß` → `SS`), so
  `Char.toUpper : Char -> String`. When you only need same-length case shifts,
  code-point arithmetic relative to `'A'`/`'a'` stays in `Char`; reach for the
  `String`-returning case functions when true Unicode case folding is the point.

## A worked example: a Caesar cipher

The example under
[`examples/shapes/script/char-caesar`](../../examples/shapes/script/char-caesar/src/Main.ipe)
rotates each letter of a message by N places — the small program that shows all
three knots at once.

Shifting one character is code-point arithmetic *guarded by classification*: only
upper- and lower-case letters shift (each relative to its own base), and anything
else passes through unchanged:

```ipe
shiftChar n c =
    if Char.isUpper c then
        rotate n (Char.toCode 'A') c

    else if Char.isLower c then
        rotate n (Char.toCode 'a') c

    else
        c
```

`rotate` is the arithmetic itself: subtract the base to land in `0..25`, add the
shift, wrap with `modBy 26`, add the base back, and convert the code point to a
`Char`:

```ipe
rotate n base c =
    let
        offset =
            Char.toCode c - base
    in
    Char.fromCode (base + modBy 26 (offset + n))
```

Enciphering the whole string is `String.map` — the per-character shift applied
across the text, reassembled into a new `String`:

```ipe
encipher n text =
    String.map (shiftChar n) text
```

Running it (`ipe dev run`) shifts the letters by three, leaves the digits and
punctuation alone, and the inverse shift recovers the original:

```
plain:     Attack at Dawn! (07:00)
shift +3:  Dwwdfn dw Gdzq! (07:00)
recovered: Attack at Dawn! (07:00)
```

## The why

`toCode`/`fromCode` as an explicit bridge is [make invalid states
unrepresentable][principles] at the character level: a `Char` is a distinct type,
not silently an `Int`, so you cannot accidentally do arithmetic on a character
without saying you mean to — the conversion is a visible, deliberate step.

Making `toUpper`/`toLower` return a `String` rather than a `Char` is
[correctness][principles] over convenience: the type refuses to pretend that case
mapping is one-to-one, so code that assumes a same-length result cannot compile
against the Unicode-honest signature. And the classification predicates are [ease
of use][principles] — the branch on "what is this character" reads as plain
`if isUpper`, not a hand-rolled range check on rune values.

[principles]: ../../PRINCIPLES.md

## References

- **Per-symbol reference:** `ipe doc Ipe.Char` — every predicate and converter
  with a verified example. `ipe doc Ipe.Char.toCode` and `ipe doc Ipe.Char.fromCode`
  cover the code-point bridge; `ipe doc Ipe.Char.toUpper` shows the `String` return.
- **Sibling guides:** [Strings](string.md) — a `String` is a sequence of `Char`s;
  `String.map`, `String.toList`, and `String.foldl` are how you get at them.
  [Lists](list.md) — `String.toList` hands you a `List Char` for the full list
  toolkit.
- **Concepts:** [Types and inference](types.md) — how `Char` and `Int` are kept
  distinct so the `toCode`/`fromCode` bridge is explicit.
