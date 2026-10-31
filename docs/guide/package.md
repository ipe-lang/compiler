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
| `icon` | `String` | — | Icon path (project-relative; must exist); a square PNG of at least 192 px when `installable` |
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

`wasm` turns on a WebAssembly client — required for a `client` web app (browser
or mobile). Off by default:

```ipe
wasm = On { mode = Render }          -- a self-contained SPA
-- On { mode = Hydrate }            -- hydrate a server-rendered page
-- optional: entry, mount ("#app"), publicEnv, optLevel
```

`delivery` holds per-host settings; every sub-record is optional and falls back
to its default:

```ipe
delivery =
    { ships = [ binary, desktop, clientAndroid ]   -- default: [ binary ]
    , desktop = { title = "My App", width = 1024, height = 768 }
    , mobile = { bundleId = "io.acme.myapp", orientation = Any }  -- Any (default) | Portrait | Landscape
    , browser = { basePath = "/" }
    , servers = [ "https://api.example.com" ]   -- default: [] (offline)
    }
```

`bundleId` is the application identifier the Android and iOS shells install
the app under, verbatim. It is two or more `.`-separated labels, each an ASCII
letter then ASCII letters or digits, at most 128 bytes in all, with no label a
Java reserved word, a first label other than `java`, and not under a
store-reserved prefix (`com.apple`, `com.android`, `android`, `com.example`, in
any case) (`io.acme.myapp`, not `com.my-app`, `io.acme.class`, `java.myapp`, or
`com.example.myapp`); the manifest refuses any other value. An absent `bundleId` is `com.ipe.`
followed by the lowercased letters and digits of the package name.
`orientation` is the orientation the app runs in, `Any` (free rotation) when
absent; `Portrait` and `Landscape` lock it.

`basePath` is the URL path the client bundle is served at; the `web client`
host, static hosts, and mobile shells all serve the bundle under it. It is `"/"`
(or `""`) for the root, or one or more `/segment` parts made only of
`A-Z a-z 0-9 - . _ ~`, with no trailing `/`, no empty, `.`, or `..` segment, and
at most 1024 bytes in all; the manifest refuses any other value.

`installable` (default `False`): when `True`, a `web served` app offers browser
install: a web app manifest, a home-screen icon, and a standalone window. It
requires the top-level `icon`, a PNG that is square, at least 192 by 192 px,
and at most 2 MiB; any other icon stops the build with an error naming the
rule. The served base path comes from the server (`IPE_WEB_BASE_PATH` or
`Server.mountApp`), not from `basePath`.

```ipe
package : Package
package =
    { name = "todo"
    , icon = "assets/icon-512.png"
    , delivery = { browser = { basePath = "/", installable = True } }
    }
```

An installed app still needs a connection: its model lives on the server.
Offline it shows a notice and nothing else; it never imitates
a working app.

`servers` lists the origins a client bundle may reach. The bundle's
Content-Security-Policy allows `connect-src` to `'self'` plus each listed
origin over `https://` and `wss://`, and to nothing else; an empty or absent
list is an offline bundle. Each entry is exactly `https://` followed by a
host and an optional `:port`:

- the host is lowercase dot-separated labels of `a-z 0-9 -`, each 1 to 63
  bytes and not starting or ending with `-`, at most 253 bytes in all;
- the port is 1 to 65535 with no leading zero, and never `:443` (the
  `https` default is written without it);
- nothing follows the authority: no path, query or fragment, not even a
  trailing `/`;
- an IP address, a `user@` part, a `*` wildcard, uppercase and non-ASCII are
  refused.

At most 16 origins are listed, each once; the manifest refuses any other
value.

A mobile app that accepts `JsPort Push` names its push identifiers under
`delivery.mobile.push`:

```ipe
mobile =
    { bundleId = "io.acme.myapp"
    , push =
        { apns = Production                      -- Development | Production
        , fcm =
            { projectId = "example-app"
            , applicationId = "1:1234567890:android:abc123"
            , apiKey = "AIza..."
            , senderId = "1234567890"
            }
        }
    }
```

`apns` is the APNs environment the iOS shell registers in. The four `fcm`
fields are the Firebase client identifiers the Android shell registers with;
each is 1 to 128 bytes of `A-Z a-z 0-9 : _ . -`. Every field is required. The
manifest refuses `push` when `capabilities.accepts` lists no `JsPort Push`, and
an iOS or Android pack refuses an app that accepts `JsPort Push` without it.

`ships` constructors: `binary`, `staticBinary`, `crossBinary "<triple>"`,
`desktop`, `client`, `clientDesktop`, `clientIos`, `clientAndroid`. See [Delivering an
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
    , wasm = On { mode = Render }
    , build = { database = Postgres, static = False, target = HostTarget, allocator = AutoAlloc, cFree = False }
    , delivery =
        { ships = [ binary, clientAndroid, clientIos ]
        , desktop = { title = "My App", width = 1200, height = 800 }
        , mobile = { bundleId = "io.acme.myapp", orientation = Any }
        , browser = { basePath = "/" }
        }
    }
```

## See also

- [Delivering an app](delivery.md) — build, run, and simulate each host.
- [Publishing a package](publishing.md) — the index, signing, `ipe publish`.
- `ipe doc Ipe.Package` — every field, type, and constructor from source.
