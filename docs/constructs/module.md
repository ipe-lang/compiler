---
kind: syntax
title: "module: module declarations"
summary: "Declare a module name and control which names it exposes to importers."
aliases: ["module-declaration", "exposing"]
see_also: ["import"]
---

# `module` — module declarations

Every Ipê source file begins with a `module` declaration that gives the file
its name and controls what it exposes to other modules.

## Basic form

```ipe
module MyModule exposing (..)
```

```ipe
module MyModule exposing (MyType, myFunction, MyType(..))
```

## Exposing everything

`exposing (..)` makes all top-level definitions visible to importers:

```ipe
module Geometry exposing (..)

type Shape
    = Circle Float
    | Square Float

area : Shape -> Float
area shape =
    case shape of
        Circle r ->
            3.14159 * r * r

        Square s ->
            s * s
```

## Exposing selectively

List only the names you want to be public. Anything not listed is private to
the module:

```ipe
module Geometry exposing (Shape, area)

type Shape
    = Circle Float
    | Square Float

-- helper is private — not in the exposing list
helper : Float -> Float
helper x =
    x * x

area : Shape -> Float
area shape =
    case shape of
        Circle r ->
            3.14159 * helper r

        Square s ->
            helper s
```

## Exposing constructors

To let importers pattern-match on a union type's constructors, expose them with
`TypeName(..)`:

```ipe
module Geometry exposing (Shape(..), area)
```

Without `(..)`, importers see `Shape` as an opaque type — they can hold values
of that type but cannot pattern-match on `Circle` or `Square`.

## Module path and file path

The module name must match the file's path from the project root. A module
named `Widgets.Button` must live at `src/Widgets/Button.ipe`. A mismatch is
IPE-N0023.

## Glossary

- **exposing** — the list of names visible outside the module.
- **opaque type** — a type exposed without `(..)`, hiding its constructors.
- **module path** — the dot-separated name that matches the file's directory path.
