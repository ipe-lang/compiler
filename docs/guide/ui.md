# UI layout

`Ipe.Ui` is the element and attribute surface a `Ipe.Tea.Web` view returns. You
describe a page as a tree of typed `Element msg` values — `row`, `column`, `el`,
`text`, `button` — each carrying a list of typed `Attribute msg`. Layout is
composition of these builders, not markup you write by hand.

## The mental model

Three knots.

- **Layout is composition, not markup.** `row` places its children along the
  horizontal axis, `column` along the vertical, and `el` wraps a single child.
  You nest them to build structure. There are no tags to open and close and no
  chance of a mismatched one — a view is a value of type `Element msg`, built
  from functions.
- **Attributes are typed values, not CSS strings.** `spacing`, `padding`, and
  `width` take `Int` / `Length` values; colours come from `Ui.rgb` and render
  through `Ui.colorCss`. The runtime turns the tree into HTML safely — an
  attribute is a typed value, so it cannot smuggle raw style or script into the
  page.
- **Events carry your `Msg`.** `Ui.onClick Increment` attaches a typed message to
  an element. When the event fires in the browser, the runtime routes that exact
  `Msg` back through your `update`. The view is a pure function of the model; the
  only way it changes is a `Msg` updating the model.

## A worked example: a counter view

The example under
[`examples/shapes/web/ui-layout`](https://github.com/ipe-lang/compiler/blob/main/examples/shapes/web/ui-layout/src/Main.ipe)
is a minimal `Ipe.Tea.Web` counter. The whole page is one `view` function.

`column` stacks a heading and a counter row with `spacing`; the inner `row`
places two buttons and the live count side by side. Colours and padding are
typed attributes; each button carries a typed `Msg`:

```ipe
view : Model -> Element Msg
view model =
    Ui.column
        [ Ui.spacing 16
        , Ui.padding 24
        ]
        [ Ui.el
            [ Ui.style "font-weight" "bold" ]
            (Ui.text "Counter")
        , Ui.row
            [ Ui.spacing 12 ]
            [ Ui.button
                [ Ui.padding 8, Ui.onClick Decrement ]
                { onPress = Just Decrement, label = Ui.text "-" }
            , Ui.el
                [ Ui.style "color" (Ui.colorCss (Ui.rgb 30 30 60)) ]
                (Ui.text (String.fromInt model.count))
            , Ui.button
                [ Ui.padding 8, Ui.onClick Increment ]
                { onPress = Just Increment, label = Ui.text "+" }
            ]
        ]
```

`update` folds a `Msg` into the model, and the runtime re-renders the view:

```ipe
update : Msg -> Model -> ( Model, Cmd Msg )
update msg model =
    case msg of

        Increment ->
            ( { model | count = model.count + 1 }, Cmd.none )

        Decrement ->
            ( { model | count = model.count - 1 }, Cmd.none )
```

`ipe dev build` emits a web app; the buttons dispatch `Increment` / `Decrement` and
the count updates live.

## Keyboard navigation and focus

`Ipe.Ui` is accessible by default — an app built from `Ui` controls requires
no extra effort to be keyboard-operable.

**Tab order.** Every `Ui.button`, `Ui.input`, and `Ui.link` renders as a native
HTML element (`<button>`, `<input>`, `<a>`). Browsers assign them to the tab
sequence automatically. Tab moves focus forward; Shift+Tab moves it backward.

**Activation.** A focused `Ui.button` activates on Enter and Space (native
`<button>` behaviour). A focused `Ui.link` activates on Enter.

**Autofocus.** A control with `autofocus` takes focus at load, and when it
appears in answer to the user's own action in that tab: a panel opened by a key
press focuses its `autofocus` input. Focus moves only onto a control that was
not already `autofocus` in the render before, so a re-render while the user
types never moves the caret. A render the user did not cause in that tab (a
timer or subscription, another tab of the same session, a page reconnecting)
never moves focus, and neither does one that lands after the user has moved
focus elsewhere. An event a widget or a page script raises is not the
user's own action either, so its render never moves focus. Only a deliberate
input counts as the user's action: a click, a key, an edit, a submit. A focus
or blur event (the runtime raises one when it puts focus back) and a pointer
crossing (`onMouseOver`, `onMouseOut`, which a layout shift raises under a
pointer at rest) do not, so their render never moves focus. Nor does a key or
an edit an input method is still composing (an accented letter, a CJK
character): moving focus would cut the composition off. The load's own
`autofocus` is spent once the user presses a key or the pointer, or moves
focus, before the page is ready. After load the
runtime alone moves focus: the `autofocus`
attribute never reaches the live page from a later render, so the browser's
own focus-on-insertion never fires, and a CSS `[autofocus]` selector matches
at most the page as loaded.

**Focus across a render.** Where focus ends after a render depends on the view,
never on how the runtime changed the page. When a render leaves focus on the
page body (the focused control is gone, or became disabled, hidden or
untabbable), the runtime puts focus on the nearest enclosing element of the
new view that takes focus, else on the view's root, so a key handler on an
ancestor keeps receiving keys. It checks once the render lands and again two
animation frames later, after the browser has dropped focus from a control a
render made unfocusable. It never moves focus the user moved after the render,
focus a newer render owns, or focus outside the view.

**Frames.** A framed document never shares the app's origin, so it cannot
reach the page, its storage, or its session. Every `Html.iframe` is sandboxed:
the runtime paints `sandbox` on it at every render and patch, keeping only the
browser's known tokens, and always removes `allow-same-origin` and
`allow-popups-to-escape-sandbox`. Opt a frame into other tokens with
`Attr.attribute "sandbox" "allow-scripts allow-forms"`. An `embed` with a
`src`, an `object` with a `data`, or a `frame` with a `src` renders nothing,
since the browser gives them no sandbox; use `iframe`. Framed content in
`Ipe.Html.Unsafe.unsafeRaw` markup is the author's to sandbox.

**Focus ring.** The runtime injects a visible focus ring — a 3 px solid accent
outline with a white halo — into every page via the global CSS reset. The ring
appears only on `:focus-visible` (keyboard focus), not on mouse clicks. It meets
the WCAG 2.2 non-text contrast requirement (3:1) against any background through
the two-layer technique: the accent ring on light backgrounds, the white halo on
dark ones. High-contrast / Windows HCM modes use the system `Highlight` colour.

You can restyle the ring per control without losing it:

```ipe
Ui.button
    [ Ui.focusVisible
        [ Ui.style "outline" "3px solid #e63946"
        , Ui.style "outline-offset" "3px"
        ]
    ]
    { onPress = Just Submit, label = Ui.text "Submit" }
```

**Erasing it is a lint error.** The `no-silent-outline-none` rule fires when
`outline: none` (or `0`) appears inside a `Ui.focus` / `Ui.focusVisible` /
`Ui.onPseudo` block without a visible replacement (`box-shadow`, `border`, or a
non-none outline). Fail-closed: absent proof of a replacement, the removal is
flagged. To suppress intentionally:

```ipe
-- ipe-lint: allow no-silent-outline-none
Ui.focusVisible [ Ui.style "outline" "none", Ui.style "box-shadow" "0 0 0 4px #0060df" ]
```

(The example above would not need suppression — `box-shadow` is a visible
replacement and the lint passes it.)

## The why

A view as a typed `Element msg` tree is [make invalid states
unrepresentable][principles] applied to markup: a mismatched or unclosed tag is
not something you can even write, because you compose functions rather than
strings. Typed attributes and `Msg`-carrying events are [security][principles]
and [correctness][principles]: the runtime renders values, so raw style or script
cannot leak into the page, and an event can only produce a `Msg` your `update`
already handles.

[principles]: https://github.com/ipe-lang/compiler/blob/main/PRINCIPLES.md

## References

- **Per-symbol reference:** `ipe doc Ipe.Ui` — every builder with its signature:
  the containers (`el` / `row` / `column` / `grid` / `paragraph`), the attributes
  (`spacing` / `padding` / `width` / alignment), the events (`onClick` /
  `onInput` / `onSubmit`), the length and colour builders, and the accessibility
  `describe` roles.
- **Sibling guides:** [The Elm Architecture](the-elm-architecture.md) — the
  `init` / `update` / `view` loop a `Ui` view lives in. [HTML](html.md) — the
  lower-level typed element trees; `Ui.html` embeds one in a `Ui` view. [CSS](css.md)
  — the typed stylesheet DSL for shared styling.
- **Concepts:** [Pure functions and immutability](pure-functions.md) — the view
  is a pure function of the model.
