# Locales

`Ipe.Locale` is the explicit-locale surface for text operations that depend on
language context. The default `String.toUpper` and `String.toLower` are
locale-independent and correct for most scripts. A small number of languages
change the result — `Ipe.Locale` handles those.

## The mental model

Two knots.

- **`Locale` is opaque — `fromTag` is the only door, and it rejects.** The
  single constructor is `Locale.fromTag`, which parses a
  [BCP-47](https://tools.ietf.org/rfc/rfc5646) language tag and returns
  `Nothing` for any string that is not structurally valid. A value of type
  `Locale` is therefore *proof* the tag parsed — there is no unchecked
  `Locale`, and an invalid tag can never silently become a default or
  fallback locale.

- **Case mapping is locale-dependent for some scripts.** The motivating case
  is Turkish and Azerbaijani: `String.toUpperIn tr "i"` yields `"İ"` (capital
  dotted I, U+0130), whereas the locale-independent `String.toUpper "i"` yields
  `"I"`. The reverse holds too — `String.toLowerIn tr "I"` yields `"ı"` (dotless
  i, U+0131), not `"i"`. For most scripts the locale-aware and
  locale-independent paths agree; the opt-in surface exists for the scripts
  where they diverge.

A reader who holds those two ideas can predict how any `Ipe.Locale` code behaves
without needing to tour the rest of the API.

## A worked example: the Turkish dotless-i

The example under
[`examples/shapes/script/locale-turkish-i`](../../examples/shapes/script/locale-turkish-i/src/Main.ipe)
parses two locales at the single boundary — `"tr"` (Turkish) and `"en"` (English)
— then compares their upper- and lower-casing of the same word, and shows `fromTag`
returning `Nothing` on a structurally invalid tag.

`fromTag` is the one gate. A valid tag becomes `Just Locale`; an invalid one
becomes `Nothing`. Only a parsed `Locale` can reach the locale-aware functions:

```ipe
showCase : String -> String -> String
showCase tag word =
    case Locale.fromTag tag of

        Just locale ->
            tag
                ++ ": toUpperIn \""
                ++ word
                ++ "\" = \""
                ++ String.toUpperIn locale word
                ++ "\""

        Nothing ->
            tag ++ ": invalid BCP-47 tag"
```

The program chains several IO steps with `do`, sequencing from the header line
through the case comparisons to the invalid-tag demonstration:

```ipe
main =
    do
        _ <- Io.println "-- locale-aware case mapping (Turkish-i demo) --"
        _ <- Io.println (localeIndependentUpper "istanbul")
        _ <- Io.println (showCase "tr" "istanbul")
        _ <- Io.println (showCase "en" "istanbul")
        _ <- Io.println (showLower "tr" "ISTANBUL")
        _ <- Io.println (showLower "en" "ISTANBUL")
        Io.println (showInvalid "!!invalid!!")
```

Running it (`ipe dev run`) confirms the Turkish and English paths diverge exactly
where they should, and the invalid tag is a `Nothing`:

```
-- locale-aware case mapping (Turkish-i demo) --
default toUpper "istanbul" = "ISTANBUL"
tr: toUpperIn "istanbul" = "İSTANBUL"
en: toUpperIn "istanbul" = "ISTANBUL"
tr: toLowerIn "ISTANBUL" = "ıstanbul"
en: toLowerIn "ISTANBUL" = "istanbul"
!!invalid!!: not a valid BCP-47 tag (Nothing)
```

The Turkish line uppercases the dotted `i` to `İ` (U+0130) throughout `"istanbul"`;
the English line produces the ASCII `I` the locale-independent default would give.
The lowercase side mirrors this: Turkish `I` → `ı` (U+0131), English `I` → `i`.

## The why

The opaque `Locale` is [parse, don't validate][principles] applied to language
tags: the BCP-47 check happens once, in `fromTag`, and produces a type that
*cannot* hold an invalid tag. Callers never re-check; no downstream function can
be handed a garbage tag. A `Bool`-returning validator that let the raw string
flow onward would reintroduce precisely the check-or-forget gap this design
removes.

Returning `Nothing` on an invalid tag — rather than silently substituting a
default locale — is [deny-by-default][principles]: the safe outcome when the input
is untrusted or unexpected is typed absence, not a silent best-guess that produces
wrong output in a language-sensitive context.

The locale-aware functions live on `String`, not on `Locale`, because they transform
a string *given* a locale. `Locale` itself is a pure parse-validated handle; the
transformation is the string's concern. This keeps `Ipe.Locale` small (only
`fromTag` and `toTag`) and `Ipe.String` the single home for all text transforms.

[principles]: ../../PRINCIPLES.md

## References

- **Per-symbol reference:** `ipe doc Ipe.Locale` — `fromTag`, `toTag`, and the
  opaque `Locale` type.
- **Locale-aware string functions:** `ipe doc Ipe.String` — `toUpperIn`,
  `toLowerIn`, `containsIn`, `startsWithIn`, `endsWithIn` (locale-sensitive
  search), and `casefold`/`equalFold` (locale-independent case folding for
  comparison).
- **Sibling guides:** [Strings](string.md) — the full text-transform surface,
  including the locale-independent case functions. [Characters](char.md) — Unicode
  code-point classification. [Results and Maybe](result.md) — what `fromTag`
  returns on the failure side.
- **Concepts:** [The parse-don't-validate idiom](../idioms/parse-dont-validate.md)
  — the discipline the opaque `Locale` embodies.
