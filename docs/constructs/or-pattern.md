---
kind: syntax
title: "or-pattern: | in case branches"
summary: "Share one branch body between two or more patterns using | inside a case arm."
aliases: ["or-patterns", "pattern-alternation"]
see_also: ["case", "type"]
---

# `or-pattern` — `|` in case branches

The code examples in this page are illustrative Ipê source snippets, not shell commands.

An or-pattern lets two or more patterns share a single branch body inside a
`case` expression. Write the alternatives separated by `|` on the left side
of `->`.

## Basic form

```ipe
case value of
    PatternA | PatternB ->
        sharedResult

    PatternC ->
        otherResult
```

## Example

```ipe
type Weekday
    = Monday
    | Tuesday
    | Wednesday
    | Thursday
    | Friday
    | Saturday
    | Sunday

isWeekend : Weekday -> Bool
isWeekend day =
    case day of
        Saturday | Sunday ->
            True

        Monday | Tuesday | Wednesday | Thursday | Friday ->
            False
```

## Variables must match across alternatives

When an or-pattern arm binds a variable, every alternative in the arm must
bind the same variable at the same type. The compiler rejects mismatched
bindings (IPE-T0019):

```ipe ipe:error IPE-T0019
type Expr
    = Lit Int
    | Neg Int

-- Wrong: alternatives bind different variables
badMatch : Expr -> Int
badMatch e =
    case e of
        Lit x | Neg y ->
            x
```

```ipe
-- Correct: both alternatives bind the same variable name
goodMatch : Expr -> Int
goodMatch e =
    case e of
        Lit x | Neg x ->
            x
```

## When to use or-patterns

Or-patterns are best for a small number of constructors that share identical
behaviour. When the body needs to distinguish which alternative matched, use
separate arms instead.

## Glossary

- **or-pattern** — two or more patterns joined by `|` that share one branch body.
- **alternative** — one pattern in an or-pattern group.
