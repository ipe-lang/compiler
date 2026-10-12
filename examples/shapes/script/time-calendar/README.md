# time-calendar

A `Program`-shape tool showing `Ipe.Time`: a fixed `Timestamp`, UTC formatting,
duration arithmetic (`add`/`diff` over `Ipe.Duration`), and the pure calendar
helpers (`isLeapYear`, `daysInMonth`). It pins a fixed instant so the output is
reproducible. The worked example for the [Time guide](../../../../docs/guide/time.md).

```
ipe dev build package.ipe
cargo run --manifest-path out/rust/Cargo.toml
```
