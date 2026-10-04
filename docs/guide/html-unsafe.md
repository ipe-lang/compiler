# The unsafe HTML surface

`Ipe.Html.Unsafe` holds the raw-HTML escape hatch. The safe default —
`Html.text` — escapes its content at the render sink, so untrusted input can never
become live markup. `Unsafe.unsafeRaw` bypasses that escaping and emits its string
verbatim; `Unsafe.unsafeScript` emits an inline `<script>`. Both live behind a
disclosed `unsafe` capability.

## The mental model

Two ideas.

- **The safe path escapes; the unsafe path doesn't.** `Html.text s` sends `s`
  through the render sink's escaper, so `<em>` becomes `&lt;em&gt;` — inert text.
  `Unsafe.unsafeRaw s` sends `s` through verbatim, so `<em>` stays a live tag. Same
  input, opposite treatment — which is exactly why the unsafe form is for *trusted*
  content only, markup you wrote, never a string a user typed.
- **The risk is named and disclosed.** The `unsafe` prefix marks the hazard at
  every call site, and importing the module discloses the `unsafe` capability
  program-wide — a project accepts it once with
  `capabilities = { accepts = [ Unsafe ] }`, so a reviewer sees the raw sink before
  the program runs. The safe `Html.text` needs no such capability.

## A worked example: safe next to unsafe

The example under
[`examples/shapes/script/html-unsafe-boundary`](../../examples/shapes/script/html-unsafe-boundary/src/Main.ipe)
renders the *same* trusted string twice — once through `Html.text`, once through
`Unsafe.unsafeRaw` — so the difference is visible in one output.

```ipe
comparison : Html msg
comparison =
    Html.div
        [ Attr.class "compare" ]
        [ Html.p [ Attr.class "safe" ] [ Html.text trustedMarkup ]
        , Html.p [ Attr.class "raw" ] [ Unsafe.unsafeRaw trustedMarkup ]
        ]
```

The manifest pre-accepts the capability:

```ipe
package : Package
package =
    { name = "html-unsafe-boundary"
    , version = "0.1.0"
    , capabilities = { accepts = [ Unsafe ] }
    }
```

Running it (`ipe dev run`):

```
Same string, escaped (safe) then verbatim (unsafe):
<div class="compare"><p class="safe">&lt;em&gt;featured&lt;/em&gt;</p><p class="raw"><em>featured</em></p></div>
```

In the `safe` paragraph the markup is escaped to inert text; in the `raw`
paragraph it is emitted as a live `<em>` tag. That difference is the whole hazard —
run `unsafeRaw` only over content you control.

## The why

Making the safe default (`Html.text`) escape and putting the raw sink behind a
separately-imported, capability-disclosed `Unsafe` module is [security][principles]'s
safe-by-default rule: the escaping XSS barrier is what you get without asking, and
bypassing it is a deliberate, greppable, audited act — not an easy-to-reach flag.
The `unsafe` name states precisely what you are taking on: the caller now owns the
invariant that the content is trusted. Everything else — the escaping, the
structural tree — is unchanged.

Reach for this only for trusted, author-controlled markup the safe builders cannot
express.

[principles]: ../../PRINCIPLES.md

## References

- **Per-symbol reference:** `ipe doc Ipe.Html.Unsafe` — `unsafeRaw` (raw HTML) and
  `unsafeScript` (inline `<script>`), each with its signature.
- **Sibling guides:** [HTML](html.md) — the safe element builders and `Html.text`,
  the escaped default. [HTML attributes](html-attributes.md) — the attribute
  builders. [The unsafe database surface](db-unsafe.md) and [the secret-reveal
  hatch](secret-unsafe.md) — the other disclosed-capability escape hatches.
- **Concepts:** [The parse-don't-validate idiom](../idioms/parse-dont-validate.md)
  — why the safe boundary escapes by default.
