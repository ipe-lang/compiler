# iced-counter — an Iced binding spike

A minimal [Iced](https://iced.rs) counter, mapped onto Ipê's TEA over the REAL
crates.io `iced` crate (auto-FFI-bound, shim-free). Iced's Elm architecture is
Ipê's, so each piece maps to one `foreign` record in `src/Ffi/Iced.ipe`:

| Iced piece | Ipê shape | `foreign` record | Status |
|------------|-----------|-------------------------|--------|
| `Model` (`Counter`) | a struct | `foreign Counter = { kind = Struct … }` | emitted + Ipê forwarder wired |
| `Message` (`Increment`/`Decrement`) | an enum | `foreign Message = { kind = Enum … }` | emitted + Ipê forwarder wired |
| `update : Message -> Model -> Model` | a sync closure | `foreign counterUpdate = { kind = Closure … }` | scalar subset only; closure→run pending |
| `view : Model -> Element Message` | a sync closure | a `Closure` `foreign` record | opaque-map threaded; `Element<'a,Msg>` over-drops (parameterised) |

## What binds today (the SEAL that holds)

`ipe install` runs the sandboxed inspector over `iced = 0.12.1` and merges the
`foreign` records into the generated `_bindings.rs`. For the Model + the
Message, the driver emits **real, self-contained Rust**:

```rust
#[derive(Clone, Default)]
pub struct Counter { pub value: i64 }
pub fn iced_counter_new(arg0: i64) -> Counter { Counter { value: arg0 } }

#[derive(Clone, Debug)]
pub enum Message { Increment, Decrement }
pub fn iced_message_new_increment() -> Message { Message::Increment }
pub fn iced_message_new_decrement() -> Message { Message::Decrement }
```

These definitions **cargo-build against real Iced 0.12.1 as a working
`iced::Sandbox` counter** — the emitted `Counter` is the `Sandbox` Model, the
emitted `Message` is its `type Message`, and a real `update`/`view` folds over
them. (A GUI need not run headless; the cargo-build is the SEAL proof. See the
spike's build log.) The `Debug` derive is in the allowlist precisely because
Iced's `Sandbox::Message: Debug` bound requires it — `Debug` is total for every
closed carrier, so it carries no IEEE-754 hazard (unlike `Eq`/`Ord`/`Hash`).

## What's wired now (the forwarder plumbing)

The Ipê-side **forwarder plumbing** for define-defined TYPES is wired. After
`ipe install`, the `Rust.Iced` interface admits — for the `Counter` struct and
the `Message` enum — an Ipê-held opaque nominal plus a constructor forwarder the
Ipê program can call:

```elm
type Counter
type Message

counter_new           : Int -> Counter
message_new_increment : Message
message_new_decrement : Message
```

A define-defined type resolves at the crate-absolute path
`crate::ffi::<slug>::<Name>` (it lives in the emitted app crate's `src/ffi.rs`,
not an external `::iced::` path). A nullary constructor (a unit variant like
`Increment`, or a fieldless struct) binds a zero-arg forwarder; a name that would
shadow an Ipê builtin, or clash with an inspected opaque of the same crate, fails
closed. So an Ipê program can now **construct** the define-defined Rust types and
fold over them.

## The exact remaining block (why `Main.ipe` is still a placeholder)

One gap keeps the driver's own event loop from being *entered* from Ipê:

* **Closure→`run` handoff.** Handing a boxed Ipê closure (`update`/`view`) to
  Iced's `run` entrypoint is not wired — surfacing a boxed closure as an Ipê-held
  value to pass onward is the next, harder step. Until then the fold is entered
  from Ipê, but the driver is not handed our closure. This is the same gap the
  neighbouring `bevy-game` example documents for `Component`/system-fn.

Two Iced-specific gaps sit on top of that:

* **Opaque-return closures.** The closure adapter now threads the crate
  opaque-map, so a `Result`/`Option` closure whose Ok/Some carrier is an OPAQUE
  handle resolves — a define-defined type to its bare in-module name, an
  inspected crate-opaque to its absolute `::crate::path`, with the per-call panic
  still folding to `Err`/`None`. But `view` returns `Element<'a, Message>` — a
  LIFETIME/generic-parameterised handle the bare-handle carrier cannot carry
  (emitting the stripped `::iced::Element` would be an E0107), so that specific
  adapter over-drops rather than breach the SEAL. Opaque returns thus work today
  for owned, non-parameterised opaques; `Element<'a,Msg>` stays refused until a
  carrier that carries generic args exists. The remaining
  boxed-closure-as-Ipê-value `run`-handoff (above) is orthogonal.
* **`define.struct`/`define.enum` opaque fields/payloads.** A field or variant
  payload of a crate-opaque type (`Element`, `Command`) over-drops at decode
  until the opaque-map is threaded into the definition emitter.

`Main.ipe` deliberately stays a placeholder rather than importing `Rust.Iced`:
the interface module only exists after `ipe install` runs the sandboxed inspector
over real `iced` (network-gated), so a checked-in import of it could not build in
CI. These remaining gaps are filed to the FFI backlog (see the PR body).

## Regenerating the bindings

The workflow below is the standard define-surface flow (as used by
`bevy-game`). It is shown for reference: `ipe install` emits the
`_bindings.rs` shown above, but `ipe dev build` currently stops at the forwarder gap
documented above — the emitted definitions compile, but `Main.ipe` cannot yet
drive the Iced loop. The definitions' cargo-build against real Iced was proven
directly by the spike (a real `iced::Sandbox` around the verbatim emitter
output), not by the `ipe dev build` path.

```
cd examples/ffi/iced-counter
ipe install --yes --allow-build-scripts   # sandboxed; writes .ipe/cache/ffi/rust (gitignored)
ipe dev build                             # blocked at the forwarder gap (see above)
```
