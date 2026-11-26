---
kind: syntax
title: "record: named field collections"
summary: "Group related values under named fields. Records are immutable; update syntax creates a new record."
aliases: ["record-literal", "struct"]
see_also: ["type-alias", "record-update", "type"]
---

# `record` — named field collections

The code examples in this page are illustrative Ipê source snippets, not shell commands.

A record groups several values under named fields. Every field has a fixed name
and type. Records are immutable — updating a field produces a new record; the
original is unchanged.

## Record literal

```ipe
type alias Person =
    { name : String
    , age : Int
    }

alice : Person
alice =
    { name = "Alice", age = 30 }
```

## Accessing fields

Use `.fieldName` to read a field:

```ipe
greet : Person -> String
greet person =
    "Hello, " ++ person.name
```

`.name` is also a standalone accessor function of type `{ a | name : b } -> b`:

```ipe
names : List Person -> List String
names people =
    List.map .name people
```

## Record update

To produce a new record with one or more fields changed, use `{ old | field = newValue }`:

```ipe
birthday : Person -> Person
birthday person =
    { person | age = person.age + 1 }
```

This does not modify `person` — it creates a new record with `age` incremented.

## Pattern matching in function arguments

Destructure a record directly in a function parameter:

```ipe
greetFull : { name : String, age : Int } -> String
greetFull { name, age } =
    name ++ " is " ++ String.fromInt age ++ " years old"
```

## Functions in record fields are not supported

A record field may not hold a function value (IPE-L0107). Model behaviour
variation with a union type and `case` instead. See [`state`](state) for the
reasoning.

## Glossary

- **field** — a named slot in a record, accessed with `.fieldName`.
- **record update** — `{ r | f = v }` syntax; creates a new record, never mutates.
- **accessor** — `.fieldName` used as a function to extract a field.
