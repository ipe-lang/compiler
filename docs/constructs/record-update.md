---
kind: syntax
title: "record update: { r | field = value }"
summary: "Produce a new record with one or more fields replaced. The original record is unchanged."
aliases: ["record-update-syntax", "functional-update"]
see_also: ["record", "type-alias"]
---

# `record update` — `{ r | field = value }`

The code examples in this page are illustrative Ipê source snippets, not shell commands.

Record update syntax produces a new record that is identical to an existing one
except for the fields you name. It never mutates the original.

## Basic form

```ipe
{ originalRecord | fieldName = newValue }
```

You can update multiple fields in one expression:

```ipe
{ originalRecord | field1 = value1, field2 = value2 }
```

## Example

```ipe
type alias Config =
    { host : String
    , port : Int
    , debug : Bool
    }

defaultConfig : Config
defaultConfig =
    { host = "localhost", port = 8080, debug = False }

devConfig : Config
devConfig =
    { defaultConfig | debug = True }

stagingConfig : Config
stagingConfig =
    { defaultConfig | host = "staging.example.com", port = 443 }
```

`defaultConfig` is not changed. `devConfig` and `stagingConfig` are new records.

## In TEA update functions

Record update is the standard idiom in a TEA `update` function to change one
field of the model:

```ipe
type alias Model =
    { count : Int
    , label : String
    }

type Msg
    = Increment
    | Reset

update : Msg -> Model -> Model
update msg model =
    case msg of
        Increment ->
            { model | count = model.count + 1 }

        Reset ->
            { model | count = 0, label = "reset" }
```

## Cannot update built-in types

Record update syntax works only on user-defined record types, not on built-in
types such as `List` or `String` (IPE-T0017). Those types have their own
transformation functions in `Ipe.List`, `Ipe.String`, etc.

## Glossary

- **record update** — `{ r | f = v }` creates a new record; the original `r` is unchanged.
- **immutable** — no mutation; every "change" produces a fresh value.
