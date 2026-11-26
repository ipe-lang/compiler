---
kind: syntax
title: "type alias: named type abbreviations"
summary: "Give a shorter or more meaningful name to an existing type, including record shapes."
aliases: ["type-alias", "alias"]
see_also: ["type", "record"]
---

# `type alias` — named type abbreviations

The code examples in this page are illustrative Ipê source snippets, not shell commands.

A `type alias` declaration gives an alternative name to an existing type. The
compiler treats the alias and the original as interchangeable — they are the
same type, just spelled differently.

## Basic form

```ipe
type alias AliasName = ExistingType
```

## Abbreviating a long type

```ipe
type alias Name = String

greet : Name -> String
greet name =
    "Hello, " ++ name
```

`Name` and `String` are the same type. You can pass a `String` wherever a
`Name` is expected and vice versa.

## Record aliases

The most common use of `type alias` is naming a record shape:

```ipe
type alias Point =
    { x : Float
    , y : Float
    }

origin : Point
origin =
    { x = 0.0, y = 0.0 }

distance : Point -> Point -> Float
distance p q =
    let
        dx = p.x - q.x
        dy = p.y - q.y
    in
    sqrt (dx * dx + dy * dy)
```

A record alias also generates a **constructor function** with the same name as
the alias, taking fields in the order they appear:

```ipe
myPoint : Point
myPoint =
    Point 3.0 4.0
```

## Parameterised aliases

```ipe
type alias Pair a b =
    { first : a
    , second : b
    }

swap : Pair a b -> Pair b a
swap p =
    { first = p.second, second = p.first }
```

## `type alias` vs `type`

| | `type alias` | `type` |
|---|---|---|
| Creates a new type? | No — same type, new name | Yes — a distinct new type |
| Constructors? | Record alias gives one constructor | Each arm is a constructor |
| Pattern matching? | No | Yes, via `case` |

Use `type alias` for a record shape or a convenient abbreviation. Use `type` to
model disjoint alternatives (union types).

## Glossary

- **alias** — an alternative name for an existing type; no runtime cost.
- **record alias constructor** — the function generated when a `type alias` names a record shape.
