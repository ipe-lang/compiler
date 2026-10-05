# Configuration

`Ipe.Config` turns an untyped config document — TOML, YAML, or JSON — into a
**typed value** with a `Decoder`. A decoder describes *how* to pull a value of a
given type out of a document; running it yields either the fully-typed value or a
single typed error.

## The mental model

Three knots.

- **A `Decoder a` is a description, not the value.** `Config.string`,
  `Config.int`, `Config.field "port" Config.int` — each is a *recipe* for
  extracting an `a`, built up before any document exists. You compose the recipe,
  then run it against a document with `decodeToml`/`decodeYaml`/`decodeJson`. The
  decoder is data; decoding is the step that produces a value or an `Err`.
- **Build a record with `map2`..`map8`; the first failure wins.** To decode a
  record, apply its constructor to one decoder per field with `Config.map4`
  (or `map2`..`map8`). Every field decoder runs against the same document; the
  first one that fails — missing key, wrong type — short-circuits the whole decode
  into one `Err`. You never get a half-filled record.
- **`field` names a key, `at` drills a path.** `Config.field "port" int` decodes
  the `port` key at the current level; `Config.at [ "server", "host" ] string`
  drills into a nested table (the same as `field "server" (field "host"
  string)`). `list`, `nullable`, `maybe`, and `oneOf` handle arrays, optional
  values, and alternatives.

## A worked example: decoding an app config

The example under
[`examples/shapes/script/config-decode`](../../examples/shapes/script/config-decode/src/Main.ipe)
decodes a TOML document into a typed `AppConfig`, and shows a malformed document
being rejected.

The target record and its decoder sit side by side. `map4` applies the
`AppConfig` constructor to the four field decoders; `at` reaches into the nested
`[server]` table:

```ipe
type alias AppConfig =
    { host : String
    , port : Int
    , debug : Bool
    , tags : List String
    }


configDecoder : Decoder AppConfig
configDecoder =
    Config.map4 AppConfig
        (Config.at [ "server", "host" ] Config.string)
        (Config.at [ "server", "port" ] Config.int)
        (Config.field "debug" Config.bool)
        (Config.field "tags" (Config.list Config.string))
```

Running the decoder is a `decodeToml` that returns `Result Error AppConfig`. A
document whose `port` is a string where an int is expected fails the whole
decode — one typed error, not a silently-coerced value:

```ipe
report : String -> String -> String
report label toml =
    case Config.decodeToml toml configDecoder of

        Ok cfg ->
            label ++ ": OK " ++ cfg.host ++ ":" ++ String.fromInt cfg.port ++ " ..."

        Err _ ->
            label ++ ": rejected (typed decode error)"
```

Running it (`ipe dev run`) over a valid and a broken document prints:

```
valid : OK 0.0.0.0:8080 debug=on tags=web,api
broken: rejected (typed decode error)
```

## The why

A `Decoder` is [parse, don't validate][principles] for configuration. The one
place a raw document meets a type is `decodeToml`; past it, every value is a typed
`AppConfig` field, so no downstream code re-reads the document or re-checks a
type. A config API that returned a generic "config map" you indexed by string
would push a `.get("port")`-then-parse-then-hope onto every reader; a `Decoder`
does that work once and hands back a real record.

It is also [make invalid states unrepresentable][principles]: `map4` yields either
a complete `AppConfig` or an `Err` — there is no representation for a config with a
valid host but an unparsed port. And because a decode failure is an `Err` value,
not a panic, malformed config cannot make the program fall over — the
[soundness][principles] guarantee, at the config boundary.

[principles]: ../../PRINCIPLES.md

## Configuration

Two env vars cap the size of config files the runtime will parse.
Use `ipe doc <VAR>` for the full entry.

| Variable | Default | Effect |
|----------|---------|--------|
| `IPE_CONFIG_MAX_BYTES` | 16777216 (16 MiB) | Maximum size of any config file loaded via `Config.load*`. |
| `IPE_YAML_MAX_BYTES` | 16777216 (16 MiB) | Separate ceiling for YAML sources (`Config.loadYaml`). |

See the [**Config** subsystem](../reference/env.md#config) in the
environment variable reference.

## References

- **Per-symbol reference:** `ipe doc Ipe.Config` — every combinator with a
  verified example. `ipe doc Ipe.Config.loadFromFile` reads and decodes a file in
  one step (dispatching on the extension), taking a validated `Path`.
- **Sibling guides:** [Result](result.md), which every decode returns.
  [Files](file.md) — `Config.loadFromFile` builds on the typed `Path` boundary.
  [Dictionaries](dict.md) — `Config.dict` decodes an object into one.
- **Concepts:** [The parse-don't-validate idiom](../idioms/parse-dont-validate.md).
  [Types and inference](types.md) — how the decoded record's type is tracked.
