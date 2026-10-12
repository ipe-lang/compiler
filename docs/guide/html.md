# HTML

`Ipe.Html` builds an HTML document as a *tree of typed element builders* —
`Html.div`, `Html.p`, `Html.a` — rather than by concatenating strings. The tree
renders to a string once, at a sink that escapes every piece of user content, so
an injection attempt becomes inert text instead of a live tag.

## The mental model

Three knots.

- **`Html.text` is safe by construction.** A user-supplied string wrapped in
  `Html.text` is *escaped* at the render sink: `<script>` becomes `&lt;script&gt;`,
  visible text rather than an executed tag. You never hand-escape and never forget
  to — the only way to embed a string as content escapes it. (The un-escaped
  escape hatch is quarantined in `Ipe.Html.Unsafe`, so a raw insertion is
  explicit and greppable.)
- **A page is a tree, not a string.** Each builder takes a list of attributes and a
  list of children: `Html.div [ Attr.class "x" ] [ … ]`. Because the structure is
  values, not text, you cannot produce unbalanced or malformed markup — a closing
  tag is never forgotten, because you never write one.
- **`Html.render` is the one serialisation point.** The tree becomes a string
  exactly once, at the sink that is the XSS barrier. Attributes carrying a URL
  (`Attr.href`, `Attr.src`) are validated there too, so a `javascript:` URL is
  neutralised at the same boundary.

## A worked example: an XSS-safe comment card

The example under
[`examples/shapes/script/html-escaping`](../../examples/shapes/script/html-escaping/src/Main.ipe)
renders a comment card whose author name is a script-injection attempt, and shows
the render sink neutralising it.

The card is a tree of typed builders; the untrusted `author` goes through
`Html.text`, the safe-by-construction content node:

```ipe
commentCard : String -> String -> Html msg
commentCard author body =
    Html.div
        [ Attr.class "comment" ]
        [ Html.p [ Attr.class "author" ] [ Html.text author ]
        , Html.p [ Attr.class "body" ] [ Html.text body ]
        ]
```

Rendering a card whose author is `<script>steal()</script>` (`ipe dev run`) produces:

```html
<div class="comment"><p class="author">&lt;script&gt;steal()&lt;/script&gt;</p><p class="body">Nice article!</p></div>
```

The `<script>` tag arrived as escaped text — it renders as characters on the page,
it does not execute. No sanitisation call was needed; the type did it.

## The why

`Html.text` escaping by construction is [security][principles] as the *only*
reachable outcome: with no proof a string is safe HTML, the safe branch —
escaping — is the one the type takes, and the raw path is a separately-named
`Unsafe` module you have to reach for on purpose. This is fail-closed applied to
XSS, the most common web vulnerability, and it holds without the developer
remembering anything.

Building a tree rather than concatenating strings is [make invalid states
unrepresentable][principles]: unbalanced or malformed markup has no
representation, because tags are structure, not text. And routing URL attributes
and content through one render sink is [defend in depth][principles] — the escape
and the URL check sit at a single boundary every value must cross, so no page
built with these builders can skip them.

[principles]: ../../PRINCIPLES.md

## References

- **Per-symbol reference:** `ipe doc Ipe.Html` — every element builder and the
  serialisers. `ipe doc Ipe.Html.render` / `ipe doc Ipe.Html.renderStatic` cover
  the string and static-page render; `ipe doc Ipe.Html.Attributes` the attribute
  builders (`class`, `href`, `id`, `src`).
- **Sibling guides:** [Accessibility](accessibility.md) — typed `role` / `aria-*`
  and the accessible-by-default `Ipe.Ui` surface. [Markdown](markdown.md) —
  renders to a typed tree with the same no-raw-HTML guarantee, for chat-grade
  content. [Strings](string.md) — the text the builders wrap. [Tasks](task.md) —
  `renderStatic` renders a view to a file as a `Task`.
- **Concepts:** [Types and inference](types.md) — how an `Html msg` tree is typed.
  [Make invalid states unrepresentable](../../PRINCIPLES.md) — the principle the
  tree structure embodies.
