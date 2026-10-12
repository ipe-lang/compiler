# URLs

`Ipe.Url` turns an untrusted URL string into a typed value with two homes — an
absolute `Url` and a same-origin `Relative` reference — plus one injection-safe
query builder. Each home is opaque with a single fail-closed constructor, so a
value in hand is proof the string parsed, not a hope that it will.

## The mental model

Three knots.

- **`fromString` is the syntactic seal; `checkScheme` is the separate semantic
  gate.** `fromString` proves only that a string is a well-formed *absolute* URL —
  and an absolute URL legally carries *any* scheme, so `javascript:alert(1)`,
  `data:…`, and `ftp:…` are all valid `Url` values. A `Url` alone is therefore not
  safe to drop into an `href` or an outbound request. `checkScheme allowed`
  narrows an already-parsed `Url` against a per-surface allowlist, returning `Ok`
  only when the scheme is one you vetted. Parsing is not authorising; they are two
  steps because they answer two questions.
- **A `Url` is always absolute; a relative reference is a different type.** A
  same-origin reference like `/static/app.js` carries no scheme and no authority —
  exactly the parts a browser drops for a same-origin navigation — so it is *not*
  a `Url`. It is a `Relative`, built by `relative`, validated by the same parser
  the absolute path uses so the two boundaries cannot disagree on what parses.
  Fail-closed: a protocol-relative `//host`, a scheme-bearing or backslash or
  control-char string, a cross-origin resolution, or a `..`-traversal that pops
  past root to a leading `//` is a typed `Err`, never a rendered link.
- **`buildQuery` percent-encodes so you cannot forget.** Assembling a query by
  hand invites a `&`, `=`, space, or `#` in an untrusted value to split off an
  extra parameter. `buildQuery` encodes every key and value, so a metacharacter
  stays *inside* its value rather than forging a new parameter.

## A worked example: parse, narrow, and build

The example under
[`examples/shapes/script/url-safe-request`](../../examples/shapes/script/url-safe-request/src/Main.ipe)
runs a mix of candidates through `fromString` then `checkScheme`, triages a set
of relative references through `relative`, and builds one injection-safe query
from attacker-controlled values.

`fromString` accepts any absolute scheme, so `checkScheme` is the gate that turns
`ftp:` / `javascript:` away — only a vetted `Url` reaches the accessors:

```ipe
vet : String -> String
vet raw =
    case Url.fromString raw of
        Ok url ->
            case Url.checkScheme allowedSchemes url of
                Ok safe ->
                    raw
                        ++ "  ->  ok scheme="
                        ++ Url.scheme safe
                        ++ " host="
                        ++ Maybe.withDefault "?" (Url.host safe)
                        ++ " port="
                        ++ Maybe.withDefault "-" (Maybe.map String.fromInt (Url.port safe))

                Err _ ->
                    raw ++ "  ->  BLOCKED scheme (" ++ Url.scheme url ++ ")"

        Err _ ->
            raw ++ "  ->  not an absolute URL"
```

The allowlist is a single value the surface owns, not a check scattered across
call sites:

```ipe
allowedSchemes : List String
allowedSchemes =
    [ "http", "https" ]
```

A relative reference lives in its own type; `relative` validates it and rejects
anything that would escape the origin:

```ipe
triageRef : String -> String
triageRef raw =
    case Url.relative raw of
        Ok ref ->
            raw ++ "  ->  ok " ++ Url.relativeToString ref

        Err _ ->
            raw ++ "  ->  REJECTED"
```

And `buildQuery` is the only assembly of a query from untrusted parts:

```ipe
searchQuery : String
searchQuery =
    Url.buildQuery
        [ ( "q", "red shoes" )
        , ( "note", "a&admin=true" )
        ]
```

Running it (`ipe dev run`) prints:

```
parse + narrow (checkScheme):
  https://api.example.com:8443/v1/users  ->  ok scheme=https host=api.example.com port=8443
  http://example.com/search  ->  ok scheme=http host=example.com port=80
  ftp://files.example.com/data  ->  BLOCKED scheme (ftp)
  javascript:alert(1)  ->  BLOCKED scheme (javascript)
  /relative/path  ->  not an absolute URL
  not a url at all  ->  not an absolute URL
relative references:
  /static/app.js  ->  ok /static/app.js
  ./style.css?v=2  ->  ok /style.css?v=2
  //evil.example.com  ->  REJECTED
  /..//evil.example.com  ->  REJECTED
safe query: q=red+shoes&note=a%26admin%3Dtrue
```

Every rejection is the point. `ftp://…` and `javascript:alert(1)` *parse* — they
are valid absolute `Url` values — and are turned away by `checkScheme`, not by
`fromString`, which is exactly why the scheme gate is a separate step.
`//evil.example.com` is a protocol-relative reference to another origin, and
`/..//evil.example.com` resolves to the path `//evil.example.com`, which a browser
would read as protocol-relative too — both are rejected by `relative`, which
guards the *rendered* reference and not merely the input. The final line shows
`buildQuery` encoding `&`→`%26`, `=`→`%3D`, and the space→`+`, so the value
`a&admin=true` stays one parameter instead of forging an `admin=true`.

## The why

Splitting `fromString` from `checkScheme` is [parse, don't
validate][principles] with the two questions kept honest: the syntactic parse and
the scheme authorisation are different boundaries, and collapsing them is how a
`javascript:` URL reaches an `href`. Giving a relative reference its own
`Relative` type — rather than pretending it is a `Url` or leaving it a bare
`String` — is [make invalid states unrepresentable][principles]: a scheme or an
authority has no place to live in a value whose whole job is to be same-origin and
scheme-less, so the open-redirect string cannot be constructed, only rejected.
Validating `Relative` through the same `url` crate the absolute/SSRF path uses is
[defend in depth][principles] at the level of *agreement* — the relative-href
boundary and the outbound-request boundary cannot drift on what counts as a valid
same-origin reference. And `buildQuery` encoding by construction removes the
query-injection sink instead of documenting it: [security][principles]'s
fail-closed rule made structural, so the safe encoding is the only encoding a
caller can reach.

[principles]: ../../PRINCIPLES.md

## References

- **Per-symbol reference:** `ipe doc Ipe.Url` — `fromString` / `toString`, the
  accessors (`scheme` / `host` / `port` / `path` / `query` / `fragment`),
  `buildQuery`, `checkScheme`, and the relative family (`relative` /
  `relativePath` / `relativeQuery` / `relativeFragment` / `relativeToString`).
- **Consumers:** [HTML attributes](html-attributes.md) — `linkTarget` / `imageSrc`
  build an `href` / `src` from a scheme-narrowed `Url` or a validated `Relative`,
  so a bare string cannot reach a link or fetch sink. [Url routing](url-parser.md)
  — matching a parsed `Url` into typed routes with `Ipe.Url.Parser`.
  [Net](net.md) — host/IP classification, the other half of deny-by-default
  addressing.
- **Sibling guides:** [Results](result.md) — what every seal returns.
  [Strings](string.md) — raw URL text before it is parsed.
- **Concepts:** [The parse-don't-validate idiom](../idioms/parse-dont-validate.md)
  — a `Url` is the boundary where an untyped string becomes a typed, scheme-vetted
  value no downstream code re-checks. The [live/HTTP security invariants
  ADR](../adr/0003-security-render-and-data-access-invariants.md) — where URL validation
  sits in the request path.
