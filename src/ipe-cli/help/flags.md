The command-line flags several `ipe` commands share, described once. A command page lists one with `- @<flag>`.

- `[--accept-risks]` — accept every disclosed .Unsafe escape-hatch import and proceed without prompting
- `[--allocator <auto|system|dlmalloc|talc|mimalloc>]` — select the global allocator (default: auto); `system` is the target libc's malloc, which on musl is several times slower than the default on allocation-heavy work
- `[--cfree]` — build without linking any C code (incompatible with allocators that require C, e.g. mimalloc)
- `[--emit-permissions <ios|macos|android>]` — read-only: print the OS-permission declarations the app's accepted web capabilities derive on the platform, and build nothing
- `[--json]` — emit each diagnostic as a stable JSON object (one per line) instead of the human layout
- `[--out <dir>]` — put build output under <dir> (default: out/ in the project)
- `[-q|--quiet]` — suppress progress chatter; only warnings and errors
- `[--runtime <dir>]` — vendor the Ipê runtime from <dir>
- `[--static]` — produce a statically linked binary
- `[--target <wasm|wasi|triple>]` — compile for `wasm` (a browser bundle), `wasi` (a wasm32-wasip1 module), or a musl-static native <triple>; a native triple needs --static on `dev build` and `dev run`, `release build` is always static (default: x86_64-unknown-linux-musl); `dev run` cannot execute `wasm`, and `release build` does not produce `wasi`
