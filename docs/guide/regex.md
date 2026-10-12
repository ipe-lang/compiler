# Regular expressions

`Ipe.Regex` matches text against patterns. A pattern is **compiled once** into a
reusable `Regex`, then applied to test, find, replace, or split. The engine uses
RE2 syntax and runs in **linear time** — there is no catastrophic backtracking, so
an adversarial input cannot make a match hang.

## The mental model

Three knots.

- **Compiling is where a bad pattern is caught — and the only place.**
  `Regex.compile` returns `Result Error Regex`: an invalid pattern is a typed
  `Err` at that single call, never a silent no-match somewhere downstream. Because
  every other function takes the already-compiled, opaque `Regex`, a broken
  pattern cannot reach a `match`/`find`/`replace` as a false negative. Compile at a
  boundary, handle the `Err` once, and reuse the `Regex` everywhere after.
- **Linear-time, RE2 syntax — no backreferences.** The engine guarantees a match
  in time linear in the input, which is why there are no backreferences (`\1`) in
  the *pattern*. This is a security property: a pattern you compile cannot be
  turned into a denial-of-service by a crafted input. `replace`, on the other
  hand, *can* reference capture groups in its **replacement** string via `$1`,
  `$2`.
- **Pick the operation by the answer's shape.** `match` -> `Bool` (does it occur?),
  `find` -> `Maybe String` (the first match, if any), `findAll` -> `List String`
  (every non-overlapping match, in order), `replace` -> `String` (every match
  rewritten), `split` -> `List String` (the pieces between matches). The return
  type tells you which to reach for.

## A worked example: scrubbing a log

The example under
[`examples/shapes/script/regex-log-scrub`](../../examples/shapes/script/regex-log-scrub/src/Main.ipe)
redacts sensitive values from log lines before they are stored, and collects the
raw tokens for an audit trail.

Patterns are compiled **once**, at a boundary. `Result.combine` collects the list
of compile results into a single `Result` — a typo in any pattern is one
observable error here, never a silent miss later:

```ipe
rules : Result Error (List Rule)
rules =
    Result.combine
        [ compileRule "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+" "[email]"
        , compileRule "token=[A-Za-z0-9]+" "token=[redacted]"
        ]


compileRule : String -> String -> Result Error Rule
compileRule pattern replacement =
    Regex.compile pattern
        |> Result.map (\re -> { pattern = re, replacement = replacement })
```

Redaction is `Regex.replace`: every match of a rule's pattern becomes its
replacement text. Folding the rules over a line applies them all:

```ipe
scrub : List Rule -> String -> String
scrub ruleList line =
    List.foldl applyRule line ruleList


applyRule : Rule -> String -> String
applyRule rule line =
    Regex.replace rule.pattern rule.replacement line
```

The audit uses `Regex.findAll` to list every token seen — each non-overlapping
match, in order:

```ipe
leakedTokens : Rule -> String -> List String
leakedTokens tokenRule line =
    Regex.findAll tokenRule.pattern line
```

Running it (`ipe dev run`) prints the scrubbed log and the collected tokens:

```
Scrubbed log:
  user [email] logged in
  token=[redacted] issued for [email]
  healthcheck ok
  reset link sent to [email] token=[redacted]

Leaked tokens (pre-scrub):
  token=abc123DEF456
  token=zzz999
```

Note the whole program never `case`s on a compile failure past the single top
boundary: once `rules` is `Ok`, every downstream call holds a valid `Regex`.

## The why

Making `compile` return a `Result` is [parse, don't validate][principles] for
patterns: the string-to-`Regex` conversion happens once, and the opaque `Regex`
that comes out is proof of validity for every later use. A regex API that took a
raw pattern string on every call would re-parse (and re-risk failure) at every
match site; compiling once moves the failure to a single handled point.

The linear-time guarantee is [security][principles] by construction. A backtracking
engine lets a short adversarial pattern-and-input pair burn unbounded CPU — a
denial-of-service. RE2's linear bound means the time a match takes is bounded by
the input size, so untrusted input cannot exhaust the machine. That is the
soundness principle's "bounded by construction" applied to matching.

[principles]: ../../PRINCIPLES.md

## References

- **Per-symbol reference:** `ipe doc Ipe.Regex` — every function with a verified
  example. `ipe doc Ipe.Regex.replace` covers the `$1` capture substitution.
- **Sibling guides:** [Strings](../reference/stdlib/String.md) — `contains`,
  `startsWith`, `split`, and the fixed-string operations to prefer when you don't
  need a pattern. [Result](result.md), which `compile` returns.
- **Concepts:** [The parse-don't-validate idiom](../idioms/parse-dont-validate.md)
  — why a compiled `Regex` is a parsed value. [Types and inference](types.md).
