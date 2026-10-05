# Randomness

`Ipe.Random` draws random values. It comes in two tiers — entropy-backed effects
and pure seeded generators — and knowing which tier you are in is most of the
mental model.

## The mental model

Three knots.

- **Two tiers: entropy is an effect, a seed is pure.** `Random.int`/`Random.float`
  read the OS RNG, so they are non-reproducible effects and return a `Task`. The
  seeded tier — `Ipe.Random.Generator` — is a *pure function*: a `Generator a` is
  a step `Seed -> ( value, nextSeed )`, and the same starting seed reproduces the
  same sequence every run. Reach for entropy when you want unpredictability (a
  token, a shuffle); reach for a seed when you want *reproducibility* (tests,
  content generation, anything a reviewer must be able to re-derive).
- **The seed is threaded, never reused.** Each seeded draw returns the *next*
  seed; feeding it forward is what advances the stream. Draw twice from the *same*
  seed and you get the *same* value — a bug. The combinators (`map2`, `map3`,
  `listOf`) thread the seed for you, so composed draws advance correctly and you
  cannot accidentally repeat one.
- **`Seed` is opaque.** The raw PRNG state is hidden behind the `Seed` type, so the
  only thing you can do with a seed is thread it. There is no way to peek at or
  fabricate the internal integer, which is exactly the discipline reproducibility
  needs.

## A worked example: a reproducible character sheet

The example under
[`examples/shapes/script/random-character-sheet`](../../examples/shapes/script/random-character-sheet/src/Main.ipe)
rolls a tabletop character sheet from a seed — three ability scores and six hit
dice — using the seeded generator tier so the same seed always rolls the same
character.

One ability score *is* a generator — `Gen.int 3 18` has type `Seed -> ( Int, nextSeed )`:

```ipe
ability : Gen.Seed -> ( Int, Gen.Seed )
ability =
    Gen.int 3 18
```

The whole sheet threads one seed through everything. `map3` runs three ability
draws and combines them, handing back the seed they left off at; `listOf`
continues from *that* seed to draw six dice. Each draw feeds the next — no seed is
ever reused:

```ipe
rollSheet seed0 =
    let
        ( abilities, seed1 ) =
            Gen.map3 (\s d w -> { strength = s, dexterity = d, wisdom = w })
                ability
                ability
                ability
                seed0

        ( dice, _ ) =
            Gen.listOf 6 (Gen.int 1 8) seed1
    in
    ...
```

Running it (`ipe dev run`) rolls seed 42 twice — identical both times — and seed 99
once, different, proving reproducibility:

```
seed 42:
  STR 6
  DEX 16
  WIS 5
  hit dice: 7 7 4 7 7 7
seed 42 again (identical):
  STR 6
  DEX 16
  WIS 5
  hit dice: 7 7 4 7 7 7
seed 99 (different):
  STR 14
  DEX 15
  WIS 18
  hit dice: 1 8 2 1 5 3
```

## The why

Splitting entropy from seeds along the `Task`/pure line is [soundness][principles]:
a function that reads the OS RNG is an effect and its type says so (`Task`), while
a seeded generator is a pure `Seed -> ( a, nextSeed )` you can call in a test and
get a deterministic answer. The tier you are in is visible in the type — you
cannot mistake a reproducible draw for a live one.

The opaque `Seed` is [make invalid states unrepresentable][principles]: because the
raw state cannot leak, there is no way to construct a "half-advanced" or
hand-forged seed, so the only legal use is threading — which is what keeps the
stream correct. And the seed-explicit combinators are [correctness][principles]
over a point-free convenience that the backend cannot yet soundly box (the
sanctioned divergence noted in `ipe doc Ipe.Random.Generator`): threading the seed
by return value is total and lowers cleanly.

[principles]: ../../PRINCIPLES.md

## References

- **Per-symbol reference:** `ipe doc Ipe.Random` (both tiers) and
  `ipe doc Ipe.Random.Generator` (the composable seeded combinators).
  `ipe doc Ipe.Random.Generator.map3` and `ipe doc Ipe.Random.Generator.listOf`
  cover the composition above; `ipe doc Ipe.Random.shuffle` is an entropy-tier draw.
- **Sibling guides:** [Uuid](uuid.md) — a UUID is a random identifier; the two are
  the "give me an unpredictable value" pair. [Tasks](task.md) — the effect type the
  entropy tier returns. [Tuples](tuple.md) — every seeded draw returns a
  `( value, nextSeed )` pair. [Lists](list.md) — `listOf` builds a `List` of draws.
- **Concepts:** [Types and inference](types.md) — how the `Task` vs pure split is
  tracked in the type. [Sanctioned divergence](../../PRINCIPLES.md) — why the
  generator combinators are seed-explicit.
