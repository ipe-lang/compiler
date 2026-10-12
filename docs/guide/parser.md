# Parser combinators

`Ipe.Parser` builds parsers for small structured formats — a config line, a
token stream, a tiny DSL — by composing small, total pieces, no regular
expressions. It follows Elm's `elm/parser`: you start from `succeed`, pull in
token and character parsers, and combine them.

## The mental model

- **A `Parser a` reads from the front of the input and either succeeds with an
  `a` or fails at a definite position.** `run parser input` drives it and returns
  `Result (List DeadEnd) a` — the `Ok` value on success, or a list of dead ends
  (each a row, a column, and a `Problem`) on failure. Parsing is pure and total:
  no `Task`, no effect, no crash.

- **Character and token parsers are the leaves.** `int` and `float` read
  numbers; `symbol` and `keyword` match literal text; `chompWhile isGood`
  consumes a run of characters a predicate accepts, and `getChompedString` hands
  you the exact text it walked over; `spaces` skips whitespace; `end` requires
  the input be fully consumed.

- **`oneOf`, `map`, and `andThen` combine them.** `oneOf` tries alternatives in
  order and commits to the first that matches; `map` transforms a parsed value
  into a typed result; `andThen` sequences a step that depends on the previous
  result.

## A worked example

Classify each input as an integer, a word, or unknown:

```ipe
import Ipe.Parser as Parser exposing (Parser)
import Ipe.Char as Char
import Ipe.String as String

type Token
    = Number Int
    | Word String
    | Unknown

token : Parser Token
token =
    Parser.oneOf
        [ Parser.map Number Parser.int
        , Parser.map Word (Parser.getChompedString (Parser.chompWhile Char.isAlpha))
        , Parser.succeed Unknown
        ]

classify : String -> Token
classify raw =
    case Parser.run token raw of
        Ok tok ->
            tok

        Err _ ->
            Unknown
```

`Parser.run token "42"` is `Ok (Number 42)`; `Parser.run token "hello"` is
`Ok (Word "hello")`. The full runnable program is under
`examples/shapes/script/parser-demo`.

## Backtracking

`oneOf` follows Elm's rule: a parser that consumed input before failing does not
fall through to the next alternative — its dead ends are reported. Wrap a parser
in `backtrackable` when two alternatives share a prefix and a committed failure
should still retry the next branch.

## Divergences from Elm

`Ipe.Parser` keeps Elm's names and semantics, with a few deliberate differences
recorded in [`docs/divergences-from-elm.md`](../divergences-from-elm.md): record
building uses `map2` … `map5` (and `keep` / `ignore` for punctuation) rather than
Elm's `|=` / `|.` pipeline, and `Parser a` is a transparent `State -> PStep a`
alias instead of an opaque wrapper. The infix aliases `|.` (`keep`) and `|=`
(`ignore`) are available after `import Ipe.Parser` in any form.
