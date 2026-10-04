# Shape screenshots

Web runtime×host captures referenced by [`../topics/shapes.md`](../topics/shapes.md).

- `web-served-browser.png` — real capture: `ipe dev run` (served SSR+SSE) at `http://localhost:8000`.
- `web-solo-browser.png` — real capture: the `solo` wasm client (`ipe dev build web solo --target wasm`, served from `out/rust/www/`).

Desktop, iOS, and Android render the **identical DOM** (only the native shell
differs), so shapes.md reuses the browser captures for those rows. A native-frame
capture needs the target platform — a display for the desktop WebKitGTK window,
an Xcode iOS simulator (macOS) or the Android SDK emulator for mobile — none of
which run in a headless Linux box.
