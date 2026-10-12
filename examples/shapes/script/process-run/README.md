# process-run

A `Program`-shape tool showing `Ipe.Process`: running a child process with no
shell. `Process.run` captures stdout; `Process.runWith` captures exit code,
stdout, and stderr independently. Arguments are literal — a `$HOME` argument is
echoed verbatim, never expanded, because there is no shell. The worked example for
the [Process guide](../../../../docs/guide/process.md).

```
ipe dev build package.ipe
cargo run --manifest-path out/rust/Cargo.toml
```
