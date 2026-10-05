# HTML attributes

`Ipe.Html.Attributes` builds the attributes that go on an HTML element — the
`class`, `id`, `type`, `required`, and the rest. Each fixed-key builder takes just
the *value*; the key is baked in, so a mistyped attribute name is not something you
can write.

## The mental model

Three ideas.

- **Fixed-key builders take only the value.** `Attr.class "login"`,
  `Attr.type_ "text"`, `Attr.placeholder "you@example.com"` — the attribute name is
  part of the function, not a string you pass, so there is no `"clas"` typo to make.
  The general form `Attr.attribute key value` is there for a one-off custom key.
- **Boolean attributes are `Bool`, not strings.** `Attr.required`, `Attr.checked`,
  `Attr.disabled`, `Attr.autofocus` take a `Bool`: `True` includes the attribute,
  `False` omits it. Because the argument is a `Bool`, there is no stringly-typed
  `required="false"` — a value a browser would treat as present-and-true.
- **`Attr.noAttr` is the identity attribute.** "No attribute here" is a
  first-class value, so a conditional can pick an attribute *or nothing* without a
  `Maybe` or a magic sentinel: `if focus then Attr.autofocus True else Attr.noAttr`.

## A worked example: a login form

The example under
[`examples/shapes/script/attributes-form`](../../examples/shapes/script/attributes-form/src/Main.ipe)
builds a two-field form. Each field is a text input; `autofocus` is chosen
conditionally, falling back to `noAttr` when off.

```ipe
field : String -> String -> Bool -> Html msg
field fieldName label focus =
    Html.input
        [ Attr.type_ "text"
        , Attr.name fieldName
        , Attr.id fieldName
        , Attr.placeholder label
        , Attr.required True
        , if focus then
            Attr.autofocus True

          else
            Attr.noAttr
        ]
```

Running it (`ipe dev run`):

```
Rendered form (required is driven by a Bool, autofocus omitted when off):
<form class="login"><input autofocus="true" id="email" name="email" placeholder="you@example.com" required="true" type="text" /><input id="password" name="password" placeholder="password" required="true" type="text" /></form>
```

The first input carries `autofocus`, the second doesn't — the `noAttr` branch
rendered nothing at all. The attributes come out in sorted order, deterministically.

## The why

Baking the key into each builder is [make invalid states
unrepresentable][principles]: a misspelled attribute name has no representation, so
the "silently ignored `clas` attribute" bug can't be written. Making a boolean
attribute a `Bool` rather than a string closes the `required="false"` foot-gun — the
type carries the on/off meaning, not a string a reader might get backwards. And
`noAttr` as a real value keeps "an attribute or nothing" in the same list without a
`Maybe`, so a conditional attribute reads as ordinary data.

Values are escaped at the render sink, so a user-supplied attribute value cannot
break out of its quotes — the same XSS barrier [HTML](html.md) describes for text.

[principles]: ../../PRINCIPLES.md

## References

- **Per-symbol reference:** `ipe doc Ipe.Html.Attributes` — every fixed-key builder
  (`class`, `id`, `href`, `type_`, `placeholder`, `required`, `checked`, …), plus
  the general `attribute` / `boolAttribute` / `noAttr`, each with its signature.
- **Sibling guides:** [HTML](html.md) — the element builders these attributes
  attach to, and `Html.render`. [The unsafe HTML surface](html-unsafe.md) — the
  raw-markup escape hatch. [Markdown](markdown.md) — a typed block tree that renders
  to the same HTML.
- **Concepts:** [Types and inference](types.md) — how `Attribute msg` threads the
  message type through an event-free attribute.
