# Cache

`Ipe.Cache` is a bounded, in-memory **LRU cache** with an optional TTL. A
`Cache k v` stores values of type `v` under keys of type `k`, evicts the
least-recently-used entry when it would exceed its entry cap, and reports a miss
as a `Maybe`, never a failure.

## The mental model

Three knots.

- **A cache is configured, not defaulted.** You never get a cache "with some
  sensible size" by accident: `Cache.new` takes a `CacheCfg`, and the only way to
  build one is `Cache.defaultCfg` threaded through `withMaxEntries` / `withTTL` /
  `withMaxBytes`. A bound is always a choice made at the call site, so the memory
  ceiling is visible in the code that creates the cache. The entry count is the
  bound the runtime enforces: it has no per-value byte accounting, so
  `Cache.new` refuses a non-zero `withMaxBytes` cap instead of silently
  ignoring it.
- **Keys and values are typed.** `Cache k v` carries `k` and `v` as phantom
  parameters. A `Cache String User` accepts a `String` key and a `User` value and
  the compiler holds both sides to that; the runtime stringifies the key for its
  LRU map, but the surface never lets a `Bool` land where a `String` key was
  promised.
- **A miss is a value.** `Cache.get` returns `Task Error (Maybe v)`. A key that
  was never written, or whose TTL has expired, or that was evicted, is `Ok
  Nothing` — a case you pattern-match, not an exception you catch. The `Err`
  channel is for the cache being unreachable, not for an ordinary miss.

## A worked example: a hit, a miss, and an eviction

The example under
[`examples/shapes/script/cache-hit-miss`](../../examples/shapes/script/cache-hit-miss/src/Main.ipe)
creates a two-entry cache of string sessions, reads a hit, forces an LRU eviction
with a third key, and prints the running stats.

The cache is built once from an explicit config. `withMaxEntries 2` sets the cap;
`withTTL Duration.zero` disables expiry — a `Duration`, not a nameless
millisecond count:

```ipe
buildCache : Task Error (Cache String String)
buildCache =
    Cache.new
        (Cache.defaultCfg
            |> Cache.withMaxEntries 2
            |> Cache.withTTL Duration.zero
        )
```

`get` hands back a `Maybe`, so a hit and a miss are the two arms of one `case` —
absence is never an error path:

```ipe
lookupText : String -> Maybe String -> String
lookupText key found =
    case found of
        Just v ->
            "hit  " ++ key ++ " -> " ++ v

        Nothing ->
            "miss " ++ key ++ " (absent or evicted)"
```

With both slots full, writing a third key evicts the least-recently-used one.
Running it (`ipe dev run`) prints:

```
hit  alice -> editor
miss bob (absent or evicted)
hit  carol -> admin
size 2 ; hits 2 misses 1 evictions 1
```

`alice` was read just before `carol` was written, so `bob` was the
least-recently-used entry and the one evicted. `Cache.stats` returns running
totals of `{ hits, misses, evictions }`; `Cache.size` the live entry count after
lazy expiry.

The values here are strings, but any type works: a cache whose value type is
`Int` reads the stored value back on a hit, the same as any other payload type.

## The why

Making the bound a required `CacheCfg` argument is [make invalid states
unrepresentable][principles] applied to memory: there is no "unbounded cache"
value to construct by forgetting a flag, so the class of bug where a cache grows
without limit until the process is killed cannot be written — the cap is part of
the value's identity.

Returning `Maybe v` from `get` rather than a sentinel or a thrown error is [parse,
don't validate][principles] at the read: the one place "is this key present?" is
answered is the `case` on the `Maybe`, and past it the value is a real `v` with no
residual "but it might have been missing" to re-check. And because a miss is `Ok
Nothing` and only unreachability is `Err`, a cold cache never makes a program
fall over — the [soundness][principles] guarantee: an empty cache is the ordinary
case, handled by a value, not an exception.

[principles]: ../../PRINCIPLES.md

## References

- **Per-symbol reference:** `ipe doc Ipe.Cache` — every operation with a verified
  example. `ipe doc Ipe.Cache.stats` is the `{ hits, misses, evictions }`
  observability read; `ipe doc Ipe.Cache.remove` the idempotent delete;
  `ipe doc Ipe.Cache.clear` purges every entry while keeping the stats counters.
- **Sibling guides:** [Tasks](task.md) — every cache operation is a `Task` you
  sequence and recover. [Maybe](maybe.md) — the type a lookup returns.
  [Durations](duration.md) — how a TTL is spelled with its unit
  (`Duration.seconds 60`), never a bare millisecond count. [Byte sizes](bytesize.md)
  — the unit-explicit quantity `withMaxBytes` takes (any non-zero cap is refused
  by `Cache.new`).
- **Concepts:** [Types and inference](types.md) — how the `k` and `v` of a
  `Cache k v` are tracked across every read and write.
