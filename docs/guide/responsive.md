# Responsive breakpoints

`Ipe.Ui.Responsive` classifies a viewport size into a `DeviceClass` — `Phone`,
`Tablet`, `Desktop`, or `BigDesktop` — so a view branches on a small closed set
instead of scattering raw pixel comparisons through the layout code. The breakpoint
thresholds live in one place, and the rest of the program pattern-matches the
result.

## The mental model

Two ideas.

- **One classification, then pattern-match.** `classifyDevice { width, height }`
  maps a viewport to one of four constructors at the standard breakpoints. Every
  layout decision downstream matches on the `DeviceClass`, so the thresholds
  (`< 600`, `< 1200`, `< 1920`) are defined once — change a breakpoint and every
  branch updates, because they all read the same classification.
- **A stable string tag when a string is handier.** `deviceClassToString` gives
  `"phone"`, `"tablet"`, `"desktop"`, `"big-desktop"` — the readable tags you want
  when setting a CSS class name from the device, where a full `case` would be
  noise.

## A worked example: classifying a range of widths

The example under
[`examples/shapes/script/responsive-breakpoints`](../../examples/shapes/script/responsive-breakpoints/src/Main.ipe)
classifies four representative viewport widths.

```ipe
describe : Int -> String
describe width =
    let
        deviceClass =
            Responsive.classifyDevice { width = width, height = 800 }
    in
    String.concat
        [ String.fromInt width
        , "px -> "
        , Responsive.deviceClassToString deviceClass
        ]
```

Running it (`ipe dev run`):

```
viewport width -> device class:
375px -> phone
768px -> tablet
1440px -> desktop
2560px -> big-desktop
```

Each width lands in the class its breakpoint dictates.

## The why

Turning a continuous pixel width into a four-value `DeviceClass` is [make invalid
states unrepresentable][principles] applied to layout: instead of scattering
`if width < 600` comparisons — which drift out of sync as soon as one is edited —
the program branches on a closed enum whose thresholds are defined once. A view that
matches on `DeviceClass` is total (the compiler checks every case is handled), so a
new device class can't be silently forgotten in one layout while handled in another.

In a live web app the width comes from a window-size subscription stashed in the
model; the view calls `classifyDevice` once and dispatches on the result.

[principles]: ../../PRINCIPLES.md

## References

- **Per-symbol reference:** `ipe doc Ipe.Ui.Responsive` — `classifyDevice`,
  `deviceClassToString`, the `DeviceClass` constructors, and the bare-value
  constants (`mobile`, `tablet`, `desktop`, `bigDesktop`), each with its signature.
- **Sibling guides:** [Grid tracks](grid.md) — the layout the chosen device class
  typically drives. [Net](net.md) — another example of a range collapsed into a
  validated typed value.
- **Concepts:** [Types and inference](types.md) — how matching on the `DeviceClass`
  enum is checked for totality.
