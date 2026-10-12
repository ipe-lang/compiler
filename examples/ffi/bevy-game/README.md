# bevy-game — a headless `bevy_ecs` world tick over the shim-free auto-FFI

A minimal headless ECS program driven from Ipê over the REAL crates.io
[`bevy_ecs`](https://crates.io/crates/bevy_ecs) `0.19` — Bevy's ECS core —
auto-FFI-bound with ZERO hand-written Rust shims. It creates a `World` and
threads it through a sequence of real ECS maintenance operations (the work a
schedule does between frames — flush command queues, clear trackers, clear
entities), then reads the final entity count as observable state.

Every `World.*` call in `src/Main.ipe` is a generated binding.

## Run it

```sh
# 1. Generate the bindings (sandboxed inspection of the real crate).
ipe install --yes --allow-build-scripts

# 2. Build + run.
ipe dev run .
```

Observed output:

```
bevy_ecs World created.
[world] flush command queue
[world] clear change trackers
[world] clear all entities
[world] flush command queue
headless bevy_ecs world tick finished; final entity count = 0
```

## Scope — what auto-binds, and where the wall is

`bevy_ecs` binds **619 functions** shim-free. The runnable surface is the
non-generic `World` API: `World::new`, `flush`, `clear_all` / `clear_entities` /
`clear_trackers`, `entity_count`, `change_tick` / `increment_change_tick`,
`despawn`, plus the `Tick` / `ComponentId` value types.

The world is threaded **linearly** — each step consumes it and returns it, so
the value is used exactly once per step. An opaque foreign handle for a
non-`Clone` Rust type (bevy's `World` is `!Clone`) cannot be duplicated, so a
linear thread is the only shape the shim-free FFI can compile.

Mutating steps take `&mut self` and return the world (`World -> Result Error
World`). Reads take `&self` / `&mut self` and are **receiver-threaded**: a reader
binds as `World -> Result Error (value, World)` — it hands the world back beside
the value, so two reads chain linearly (`entity_count` then `change_tick`) with
no clone. Reusing the ORIGINAL binding after a read instead of the returned one
still fails closed with `IPE-L0130`.

The wall is Bevy's generic core. `spawn` / `insert` are generic over `Bundle`,
systems are Rust `Fn` closures, and `Component` is a user-defined Rust type —
none of which the shim-free FFI can express from Ipê (a closure / `dyn` argument
and a `<T: Bundle>` method both over-drop by design).
