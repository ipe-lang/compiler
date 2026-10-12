# The unsafe page-head surface

`Ipe.Web.Head.Unsafe` holds the one `<head>` member that emits a raw JSON-LD
`<script type="application/ld+json">` block. Because a `<script>` body is a
scripting context — not an HTML text context — the renderer emits it verbatim, so
no escaper runs. That raw sink lives here, behind a disclosed `unsafe` capability,
separate from the escaped-by-default [page head](web-head.md).

## The mental model

Two ideas.

- **A `<script>` body is emitted verbatim.** `unsafeJsonLd body` renders
  `<script type="application/ld+json">…body…</script>` with the body spliced in
  unescaped. That is correct for JSON-LD — escaping `<`, `>`, and `&` would corrupt
  the JSON — but it means the caller owns the invariant: the body must be trusted
  and cannot contain a `</script>` breakout.
- **Build the JSON from typed data.** The safe way to satisfy that invariant is to
  produce the JSON from a typed encoder over your own record types, never from
  request input. The string is then structurally trusted before it reaches the
  verbatim sink. Importing the module discloses the `unsafe` capability
  program-wide, accepted once with `capabilities = { accepts = [ Unsafe ] }`.

## A worked example: product structured data

The example under
[`examples/shapes/script/jsonld-structured-data`](../../examples/shapes/script/jsonld-structured-data/src/Main.ipe)
emits a JSON-LD block for a product page from a trusted constant.

```ipe
head : Html msg
head =
    HeadU.unsafeJsonLd productJsonLd
```

Running it (`ipe dev run`):

```
Rendered JSON-LD (script body emitted verbatim, not escaped):
<script type="application/ld+json">{"@context":"https://schema.org","@type":"Product","name":"Widget","sku":"W-1"}</script>
```

The JSON is emitted exactly as given — the `/`, quotes, and braces pass through
untouched, which is what a JSON-LD consumer needs.

## The why

Putting the one verbatim-`<script>` sink in a separately-imported,
capability-disclosed `Unsafe` module is [security][principles]'s safe-by-default
rule: the escaped `<head>` builders are what you reach for without asking, and the
raw JSON-LD sink is a deliberate, greppable act. The `unsafe` name states the
contract precisely — the caller guarantees the body is trusted, structurally-built
JSON, never spliced request input. Producing that JSON from a typed encoder is
[parse-don't-validate][parse] run in reverse: a typed value serialised to a string
you can trust, rather than a raw string you hope is well-formed.

[principles]: ../../PRINCIPLES.md
[parse]: ../idioms/parse-dont-validate.md

## References

- **Per-symbol reference:** `ipe doc Ipe.Web.Head.Unsafe` — `unsafeJsonLd`, with
  its signature.
- **Sibling guides:** [Page head](web-head.md) — the escaped-by-default `<head>`
  and SEO builders this extends. [HTML](html.md) — the element tree and the
  escaping render sink. [The unsafe HTML surface](html-unsafe.md) — the general
  raw-markup and inline-`<script>` hatch.
- **Concepts:** [The parse-don't-validate idiom](../idioms/parse-dont-validate.md)
  — building trusted JSON from typed data.
