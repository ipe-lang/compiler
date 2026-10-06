# Delivering an app

You have a working Ipê program; now you want to hand it to someone. This page
takes a `Web` app from source to a desktop bundle and to a mobile shell. Every
command here has been run as written.

## The mental model: shape, then delivery

Two independent questions decide how a program ships:

- **Shape** — what `view` renders. The head of `main` fixes it: `Web.tea` is a
  DOM app, `Tui.tea` terminal cells, `Cli.tea` terminal lines, `Server.listen`
  an HTTP server, and a bare `main : Task Error ()` renders nothing. The shape is
  never written in `package.ipe`; it is read from `main`.
- **Delivery** — for a `Web` app only, *how* the DOM app runs and *where* it is
  hosted. This is two sub-axes:
  - **runtime** — `served` (a co-located server loop; the unnamed default) or
    `solo` (a self-contained client compiled to WebAssembly).
  - **host** — where a resolved shape × runtime runs: served, `desktop`, `ios`,
    or `android`.

The knot to spot: **shape is not host.** A "desktop app" and a "mobile app" are
both the *`Web` shape* delivered to a different host — the same `main`, the same
`update`/`view` loop, packaged differently. You do not write a separate program
for each; you name the host in one uniform grammar: `ipe <verb> <shape> <host>`.
`build web <host>` lays out a fast development bundle; `release web <host>` the
production distributable.

Only the `Web` shape has these axes. A `tui`, `cli`, `worker`, or `script` app
builds one way, so it has no runtime or host to choose.

The full rationale — why webview is a host and not a shape, why `served` is never
spelled out — is [ADR 0005](../adr/0005-delivery-shapes-runtimes-hosts-targets.md).

## The `delivery` record

Per-host settings (a window title, a mobile bundle id) live in the `delivery`
record of `package.ipe`. Every field is optional; omit the record for the
defaults.

```ipe
package : Package
package =
    { name = "ui-layout"
    , version = "0.1.0"
    , delivery =
        { desktop = { title = "UI Layout", width = 1024, height = 768 }
        , mobile = { bundleId = "com.example.ui-layout", orientation = Portrait }
        , browser = { basePath = "/" }
        }
    }
```

`basePath` is the URL path the client bundle is served at; the `web solo`
host, static hosts, and mobile shells all serve the bundle under it. It is `"/"`
(or `""`) for the root, or one or more `/segment` parts made only of
`A-Z a-z 0-9 - . _ ~`, with no trailing `/`, no empty, `.`, or `..` segment, and
at most 1024 bytes in all; the manifest refuses any other value.

Run `ipe doc Ipe.Package` for every field.

## Desktop: a webview-native bundle

A desktop app is the `Web` shape run `served` inside a native window (a system
webview over a local bridge, not a browser tab). It needs no extra manifest —
the `main` head `Web.tea` is enough.

Package it:

```
ipe release build web desktop
```

This compiles the app and lays out a bundle for the host OS:

```
packaged `ui-layout` for linux → out/release/dist/linux/ui-layout
  This app requires WebKitGTK at runtime (Debian/Ubuntu: libwebkit2gtk-4.1-0).
```

The Linux bundle is a self-contained tree:

```
out/release/dist/linux/ui-layout/
  bin/                 the compiled binary
  ui-layout.desktop    the desktop-entry launcher
  RUNTIME.txt          the runtime dependency note
```

`build web desktop` lays out the same bundle (under `out/dist/`) from a fast, unoptimised build for
the inner loop; `release web desktop` produces the optimised distributable. The
bundle is always the **host OS's** — the **Linux** artifact is built end to end on
a Linux host; a macOS `.app` or a Windows `.exe` + zip has its *layout and
manifest* written for inspection here, but the signed, runnable artifact must be
finished on that OS's own runner (cross-OS toolchains are out of scope).

## Mobile: a wasm client in a system-webview shell

A mobile app is the `Web` shape delivered as a `solo` — the DOM app compiled to
WebAssembly and hosted offline from app assets inside a native iOS/Android
webview. Because it is the `solo` runtime, the app must enable the wasm client in
`package.ipe`:

```ipe
package : Package
package =
    { name = "ui-layout"
    , version = "0.1.0"
    , wasm = On { mode = Solo }
    }
```

Then package for a device OS. Because mobile is the `solo` runtime, the host is
spelled `web solo <os>`:

```
ipe release build web solo android
```

This builds the wasm bundle and materialises a native shell:

```
  wasm bundle ready at out/release/rust/www/
  bundle size: 196 KB (out/release/rust/www/pkg/ipe_app_bg.wasm)
packaged `ui-layout` for android → out/release/dist/android/ui-layout-android
  note: an Android shell project is written here; run `./gradlew assembleDebug`
        inside it with the Android SDK to produce an APK.
```

The Android shell is a ready-to-build Gradle project; the client rides under
`app/src/main/assets/www/` and a `WebViewAssetLoader` serves it same-origin, so
there is no remote host and no `file://` access. Finish the APK with
`./gradlew assembleDebug` where the Android SDK is present.

`ipe release build web solo ios` writes the equivalent Xcode project (`WKWebView` +
`WKURLSchemeHandler`). Its layout and derived-permission manifest are written for
inspection, but a signed `.ipa` must be produced on a macOS runner with Xcode and
a signing identity. As with desktop, `build web solo <os>` lays out the same shell
around a fast dev client; `release web solo <os>` hosts the production client.

## Running and simulating each host

Building lays out a bundle; here is how to actually *run* one locally — including
on a machine without a display (desktop) or without the device (mobile).

### Desktop

`ipe dev run web desktop` compiles and opens the app in a native webview window. To
run the packaged build instead, launch the emitted binary directly:

```
ipe release build web desktop
./out/release/dist/linux/<name>/bin/<name>
```

Linux needs WebKitGTK (`libwebkit2gtk-4.1-0`); macOS uses the system WebKit;
Windows needs the Edge WebView2 runtime. On a **headless** box (CI, a server),
run it under a virtual display:

```
xvfb-run -a ./out/release/dist/linux/<name>/bin/<name>
```

### Android (emulator)

`release web solo android` writes a Gradle project to
`out/release/dist/android/<name>-android/`. With the Android SDK on `PATH`:

```
cd out/release/dist/android/<name>-android
./gradlew assembleDebug          # → app/build/outputs/apk/debug/app-debug.apk
```

To **simulate**, boot an emulator and install the debug build onto it:

```
emulator -avd <your-avd> &       # or start one from Android Studio's Device Manager
./gradlew installDebug           # builds + installs onto the running emulator/device
# or: adb install app/build/outputs/apk/debug/app-debug.apk
```

`adb`, `emulator`, and `avdmanager` (to create an AVD once) all ship with the
Android SDK.

### iOS (simulator)

`release web solo ios` writes an Xcode project to `out/release/dist/ios/<name>-ios/` (a
`WKWebView` plus a scheme handler serving the wasm client). Simulating needs
**macOS + Xcode**:

```
open out/release/dist/ios/<name>-ios/          # open the Xcode project, pick an iOS Simulator, press ⌘R
# headless macOS:
xcrun simctl boot "iPhone 15"
xcodebuild -scheme App -destination 'platform=iOS Simulator,name=iPhone 15'
```

A distributable `.ipa` additionally needs a signing identity. iOS cannot be
built or simulated on Linux or Windows.

## OS permissions come from your capabilities

A packaged app may only touch an OS capability the app itself accepted. The
packager *derives* every iOS `Info.plist` key and Android `<uses-permission>`
line from the app's `[capabilities] accepts` set — it never hand-authors one, so
a bundle can neither under-declare nor smuggle a permission the app never took.

See exactly what a consent set yields, without building, with a read-only
dry-run:

```
ipe release build --emit-permissions android
```

For an app that accepts `JsPort Geolocation`, that prints:

```
OS permissions for `geo-clipboard` on android
  js-port:geolocation → android.permission.ACCESS_FINE_LOCATION, android.permission.ACCESS_COARSE_LOCATION

AndroidManifest.xml fragment:
  <uses-permission android:name="android.permission.ACCESS_COARSE_LOCATION" />
  <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
```

Pass `ios` or `macos` for the `Info.plist` keys instead. The optional trailing
path selects a project other than the current directory.

## Where to go next

- [ADR 0005](../adr/0005-delivery-shapes-runtimes-hosts-targets.md) — the two-axis delivery
  model in full: the four TEA shapes plus the direct bucket, the two web runtimes,
  and why each is where it is.
- `ipe doc Ipe.Package` — every `delivery`, `wasm`, and `capabilities` field.
- `ipe dev build --help` / `ipe release --help` — the one delivery grammar (`ipe
  <verb> [shape] [runtime] [host]`): `build` compiles or bundles a single
  delivery for the inner loop, `release` produces the production distributable.
