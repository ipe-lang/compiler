# Divergences from Elm

Ipê draws on Elm for its surface syntax, the Elm Architecture, and much of its
standard-library vocabulary. Where Ipê intentionally differs from an Elm API it
mirrors, the difference is recorded here with its reason, so a reader who knows
Elm is never surprised silently.

## `Ipe.Parser` (vs `elm/parser`)

`Ipe.Parser` is a pure parser-combinator library modelled on `elm/parser`. It
keeps Elm's names and semantics for `succeed`, `map`, `andThen`, `oneOf`,
`backtrackable`, `symbol`, `keyword`, `int`, `float`, `spaces`, `chompIf`,
`chompWhile`, `getChompedString`, `end`, `loop` (`Step = Loop | Done`),
`Problem`, and `DeadEnd`. It differs as follows.

- **`Parser a` is a transparent type alias**, `State -> PStep a`, not an opaque
  wrapper. Elm hides the step function inside an opaque
  `Parser context problem value`. The Rust backend cannot store a function value
  inside a union payload (IPE-L0107), so a `type Parser a = Parser (…)` wrapper
  does not lower, whereas a bare function-typed value does. The alias is the
  sound shape; users still compose only through the combinators.

- **Record building uses `map2` … `map5`, not the `|=` / `|.` pipeline.** Elm
  writes `succeed ctor |= partA |= partB`, threading a curried constructor
  through a parser accumulator. `map2` … `map5` apply the builder directly to
  already-parsed results, so no parser holds a function value. `keep` and
  `ignore` are two-parser sequencers for punctuation (run one, keep the other's
  value), not pipeline stages. The prefix combinators are the standing form;
  their infix aliases `|.` (`keep`) and `|=` (`ignore`) are available after
  `import Ipe.Parser` in any form.

- **No `Parser.Advanced` tier.** Elm's context stack and custom-`problem` type
  parameter are omitted; `Problem` is a fixed union.

The shipped example under `examples/shapes/script/parser-demo` composes the full
combinator surface — `map2`, `keep`, `ignore`, nested `andThen`, and `oneOf` —
and is exercised by the first-party examples sweep.
