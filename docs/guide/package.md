# The `package.ipe` manifest

Every project has a `package.ipe`. It is **inert data** the toolchain *reads,
never runs*: it declares one value, `package : Package`. Only
`import Ipe.Package exposing (..)` is allowed, and a typo (`Postgress`, a
misspelt field) is a hard error, never a silent default. Run `ipe doc
Ipe.Package` for the full type.

## Minimal

```ipe
module Package exposing (package)

import Ipe.Package exposing (..)


package : Package
package =
    { name = "my-app"
    , version = "0.1.0"
    }
```

`name` is the only required field; every other field has a default.

## Fields

| Field | Type | Default | Purpose |
|-------|------|---------|---------|
| `name` | `String` | *(required)* | Project name |
| `version` | `String` | — | Semver (`"1.2.0"`); validated when present |
| `sourceRoot` | `String` | `"src"` | Source directory |
| `icon` | `String` | — | Icon path (project-relative; must exist) |
| `dependencies` | `List Dependency` | `[]` | Ipê package deps |
| `rustDependencies` | `List RustDependency` | `[]` | Crates for FFI |
| `capabilities` | `Capabilities` | empty | Declared / accepted capabilities |
| `exposedModules` | `List String` | `[]` | Public modules (for a library) |
| `programs` | `List Program` | `[]` | Extra entry programs |
| `wasm` | `WasmClient` | `Off` | Web wasm client (see below) |
| `wrapper` | `WrapperSpec` | `NoWrapper` | Local native-crate wrapper |
| `build` | `Build` | defaults | Database, allocator, target, static |
| `delivery` | `Delivery` | defaults | Per-host packaging settings |

## Dependencies

Build each entry with a smart constructor — never hand-write the record:

```ipe
dependencies =
    [ dep "ipe-http" "^1.2"                                   -- from the index, by semver
    , depGit "lib" "https://github.com/example/lib.git"       -- git, latest
    , depGitRev "lib" "https://github.com/example/lib.git" "v2.0.0"  -- git, pinned rev
    , depPath "local" "../sibling"                            -- local path (manifest-relative)
    ]
```

`ipe add <pkg>[@<req>]` writes a `dep` line and pins it in `ipe.lock` for you;
`depGit`/`depPath` escapes are author-written and never rewritten. Rust crates
for FFI:

```ipe
rustDependencies =
    [ rustDep "uuid" "1.10"
    , rustDepWith "tokio" "1" [ "rt", "macros" ]
    ]
```

## Capabilities

A program's capabilities are *inferred*; `capabilities` lets you pin the
expected set (`declares`) and pre-accept an escape hatch (`accepts`):

```ipe
capabilities =
    { declares = [ Network, Clock, Database ]
    , accepts = [ JsPort Geolocation, Unsafe ]
    }
```

The vocabulary: `Network`, `Filesystem`, `Database`, `Env`, `Subprocess`,
`Clock`, `Random`, `NativeFfi`, `FfiRaw`, `Unsafe`, `CustomElement`, and
`JsPort <axis>` for a browser port (`Geolocation`, `Clipboard`, `Camera`,
`Microphone`, `Storage`, `Notification`, `WebAuthn`, …). See
[capabilities](../reference/capabilities.md).

## Web delivery: `wasm` and `delivery`

`wasm` turns on a WebAssembly client — required for a `solo` web app (browser
or mobile). Off by default:

```ipe
wasm = On { mode = Solo }          -- a self-contained SPA
-- On { mode = Hydrate }            -- hydrate a server-rendered page
-- optional: entry, mount ("#app"), publicEnv, optLevel
```

`delivery` holds per-host settings; every sub-record is optional and falls back
to its default:

```ipe
delivery =
    { ships = [ binary, desktop, soloAndroid ]   -- default: [ binary ]
    , desktop = { title = "My App", width = 1024, height = 768 }
    , mobile = { bundleId = "com.example.myapp", orientation = Portrait }  -- Portrait | Landscape | Any
    , browser = { basePath = "/" }
    }
```

`ships` constructors: `binary`, `staticBinary`, `crossBinary "<triple>"`,
`desktop`, `solo`, `soloDesktop`, `soloIos`, `soloAndroid`. See [Delivering an
app](delivery.md) for the build/run/simulate grammar these feed.

## Build

```ipe
build =
    { database = Sqlite          -- Sqlite | Postgres
    , static = False             -- link a fully-static musl binary
    , target = HostTarget        -- HostTarget | Cross "<triple>"
    , allocator = AutoAlloc      -- AutoAlloc | System | Dlmalloc | Talc | Mimalloc
    , cFree = False              -- link no C code
    }
```

## A fully-populated manifest

```ipe
module Package exposing (package)

import Ipe.Package exposing (..)


package : Package
package =
    { name = "my-app"
    , version = "1.2.0"
    , dependencies = [ dep "ipe-http" "^1.2" ]
    , rustDependencies = [ rustDepWith "tokio" "1" [ "rt", "macros" ] ]
    , capabilities =
        { declares = [ Network, Clock ]
        , accepts = [ JsPort Geolocation ]
        }
    , wasm = On { mode = Solo }
    , build = { database = Postgres, static = False, target = HostTarget, allocator = AutoAlloc, cFree = False }
    , delivery =
        { ships = [ binary, soloAndroid, soloIos ]
        , desktop = { title = "My App", width = 1200, height = 800 }
        , mobile = { bundleId = "com.example.myapp", orientation = Any }
        , browser = { basePath = "/" }
        }
    }
```

## See also

- [Delivering an app](delivery.md) — build, run, and simulate each host.
- [Publishing a package](publishing.md) — the index, signing, `ipe publish`.
- `ipe doc Ipe.Package` — every field, type, and constructor from source.
