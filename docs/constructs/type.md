---
kind: syntax
title: "type: union type declarations"
summary: "Declare a named union type with one or more constructors, each optionally carrying payload."
aliases: ["union", "custom-type", "adt", "sum-type"]
see_also: ["type-alias", "record", "case"]
---

# `type` — union type declarations

The code examples in this page are illustrative Ipê source snippets, not shell commands.

A `type` declaration defines a new named type with one or more constructors.
Each constructor is a distinct shape the value can take, optionally carrying
payload. You inspect which constructor a value has with `case`.

## Basic form

```ipe
type TypeName
    = Constructor1
    | Constructor2
    | Constructor3
```

## Constructors without payload

The simplest union is a set of named alternatives:

```ipe
type Direction
    = North
    | South
    | East
    | West
```

## Constructors with payload

A constructor can carry one or more values of any type:

```ipe
type Shape
    = Circle Float
    | Rectangle Float Float
    | Point
```

`Circle` carries one `Float` (the radius). `Rectangle` carries two `Float`s
(width and height). `Point` carries nothing.

## Recursive types

A constructor can refer to the type being defined — this is how lists and trees
are built:

```ipe
type Tree a
    = Leaf
    | Node (Tree a) a (Tree a)
```

## Type parameters

A type can be parameterised. The parameter appears before `=` and inside
constructor payloads:

```ipe
type Result err ok
    = Err err
    | Ok ok
```

`Result` is built-in, but you can define your own parameterised types the same
way.

## Using constructors

Constructors are values. Apply them like functions to produce a value of the
union type:

```ipe
myShape : Shape
myShape =
    Circle 5.0

myDirection : Direction
myDirection =
    North
```

## Consuming with `case`

Inspect a union value with `case`. The compiler enforces exhaustiveness —
every constructor must have a branch:

```ipe
area : Shape -> Float
area shape =
    case shape of
        Circle r ->
            3.14159 * r * r

        Rectangle w h ->
            w * h

        Point ->
            0.0
```

See [`case`](case) for the full pattern-matching reference.

## Glossary

- **union type** — a type with multiple named constructors.
- **constructor** — one named form of a union type; both a name and a function.
- **payload** — the data a constructor carries.
- **type parameter** — a placeholder (`a`, `err`, `ok`) for a type supplied by the caller.
