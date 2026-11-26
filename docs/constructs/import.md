---
kind: syntax
title: "import: bringing modules into scope"
summary: "Make another module's names available in the current file, with optional alias and selective exposure."
aliases: ["import-as", "import-exposing"]
see_also: ["module"]
---

# `import` — bringing modules into scope

The code examples in this page are illustrative Ipê source snippets, not shell commands.

An `import` declaration makes the names from another module available in the
current file. By default you access them qualified; `exposing` and `as` let you
control how.

## Basic import (qualified access)

```ipe
import Ipe.List

sorted : List Int
sorted =
    Ipe.List.sort [ 3, 1, 2 ]
```

Access names with the full module path as a prefix.

## Alias with `as`

```ipe
import Ipe.List as List

sorted : List Int
sorted =
    List.sort [ 3, 1, 2 ]
```

`as` gives the module a shorter local name.

## Selective unqualified access with `exposing`

```ipe
import Ipe.List exposing (sort, filter)

result : List Int
result =
    filter (\n -> n > 0) (sort [ -1, 3, -2, 4 ])
```

`exposing` brings specific names into scope unqualified.

## Combining `as` and `exposing`

```ipe
import Ipe.Dict as Dict exposing (Dict)

emptyMap : Dict String Int
emptyMap =
    Dict.empty
```

## Exposing constructors

To use a type's constructors unqualified, include `TypeName(..)`:

```ipe
import Geometry exposing (Shape(..))

myArea : Float
myArea =
    case Circle 5.0 of
        Circle r -> 3.14159 * r * r
        Square s -> s * s
```

## Importing a standard-library module you omitted

If you use a qualified name like `Ipe.String.toUpper` without importing
`Ipe.String`, the compiler reports IPE-N0034 and suggests the missing import.

## Glossary

- **qualified access** — using `Module.name` syntax to call an imported name.
- **`as`** — gives a module a local alias (shorter prefix).
- **`exposing`** — brings specific names into scope unqualified.
- **`(..)`** — exposes all constructors of a union type unqualified.
