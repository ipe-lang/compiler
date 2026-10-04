//! The capability vocabulary: what a program is permitted to do on the
//! security-relevant axis.
//!
//! A capability is coarse (whole-capability) for v1: [`Capability::Network`] is
//! *any* network access, not per-host; [`Capability::Filesystem`] is *any* file
//! access, not per-path. Each stdlib kernel is tagged with the one capability it
//! exercises (or none) via [`crate::StdlibKernel::capability`]; a whole program's
//! capability set is the union over its transitively-reachable kernels. Finer
//! granularity (per-host, per-path) is a tracked follow-up.

/// What a program is permitted to do, on the security-relevant axis.
///
/// The axes a sandbox can isolate independently. A kernel maps to at most
/// one; a program's set is the union over its reachable kernels plus
/// [`Capability::NativeFfi`] when it crosses into `Rust.` code (and
/// additionally [`Capability::FfiRaw`] when a crossing rides an
/// author-asserted `Rust.Ffi.call` signature).
#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum Capability {
    /// Outbound or inbound network access (HTTP client/server, WebSocket,
    /// email send).
    Network,
    /// Reading or writing the filesystem (files, directories, an `.env` or
    /// config file). Does not include database access — see [`Self::Database`].
    Filesystem,
    /// Structured database access (SQL queries, migrations, row decoders).
    ///
    /// Resolved by SP4 sandbox to filesystem or network per the `package.ipe` driver.
    Database,
    /// Reading or writing process environment (environment variables, argv).
    Env,
    /// Spawning or controlling a child process.
    Subprocess,
    /// Reading wall-clock or monotonic time, or sleeping / firing on a timer.
    Clock,
    /// Drawing non-deterministic randomness (RNG, random tokens, UUIDs).
    Random,
    /// Crossing into native `Rust.` code, which is opaque to capability
    /// inference. Its presence is the signal that a program's true capability
    /// set cannot be inferred from Ipê alone.
    NativeFfi,
    /// Crossing into native `Rust.` code through an author-asserted signature
    /// (`Rust.Ffi.call`) rather than an inspected binding. Always accompanied
    /// by [`Self::NativeFfi`] (every asserted call is a native crossing); its
    /// own presence discloses that the foreign signature was vouched by the
    /// author, not derived from crate introspection.
    FfiRaw,
    /// Reaching for a trust-escape hatch: the program imports an `Ipe.<M>.Unsafe`
    /// submodule, whose members mint a security-tier value by assertion rather
    /// than by parse. Like [`Self::NativeFfi`], this is a provenance disclosure,
    /// not a resource axis an OS jail can isolate — its presence marks that the
    /// program contains a value the compiler could not prove safe.
    Unsafe,
    /// Shipping a browser custom-element widget: the program's reachable code
    /// binds `CustomElement.node` over a `CustomElement.fromFile "<path>"` handle, so it serves
    /// author-written JavaScript that runs in the page with full DOM authority.
    /// Like [`Self::NativeFfi`], this is a disclosure of a declared-trust surface
    /// the server-side sandbox cannot see through — the browser JS is not an OS
    /// resource axis an OS jail confines. Its presence discloses that the package
    /// ships client JS whose behaviour is the package author's declared trust; the
    /// served bytes are SRI-pinned and CSP-constrained, but never sandboxed. It is
    /// deliberately NOT low-value: a shipped-JS surface must always surface to the
    /// consumer, exactly as [`Self::NativeFfi`] does.
    CustomElement,
    /// Using a JS port: the program's reachable code binds `Js.send` (outbound
    /// Ipê→JS) or `Js.subscribe` (inbound JS→Ipê), so it exchanges typed values
    /// with page JavaScript over the raw transport. Like [`Self::CustomElement`],
    /// this is a disclosure of a declared-trust surface the server-side sandbox
    /// cannot see through: the far side is attacker-controlled browser JS, gated
    /// only by the fail-closed seal decoder (inbound) and the seal type (outbound).
    /// Its presence discloses that the package exchanges data with page JS whose
    /// behaviour is the package author's declared trust. Deliberately NOT
    /// low-value: a JS-exchange surface must always surface to the consumer.
    ///
    /// The port carries a [`WebCapability`] sub-axis naming the specific Web API
    /// the far side reaches ([`WebCapability::Clipboard`], …), or
    /// [`WebCapability::Raw`] for an uncharacterised hand-rolled port. A bare
    /// `js-port` with no web axis is unrepresentable — every port discloses a
    /// concrete web capability, so one coarse grant can never re-authorise the
    /// whole browser surface.
    JsPort(WebCapability),
}

/// The closed per-Web-API axis a [`Capability::JsPort`] discloses.
///
/// A browser port reaches exactly one Web API; this names which. It is a
/// separate axis from the OS-jail capabilities because a web capability runs in
/// the client page, never in the server process — the whole `JsPort(_)` family
/// is uniformly the "no server-jail surface" partition. The vocabulary is
/// closed and compiler-owned: a new browser capability is one variant here plus
/// its [`Self::as_str`] arm and its `Ipe.Browser.<Api>` module→axis table row.
///
/// [`Self::Raw`] is the explicit, grantable axis for a port whose reached Web API
/// the compiler cannot characterise (a hand-rolled `Js.send`/`Js.subscribe` with
/// author-written JS). Granting `js-port:raw` admits ONLY uncharacterised ports;
/// it does not grant any characterised axis. This is the coarse-axis-as-bypass
/// designed out: the coarsest grantable web axis reaches nothing specific.
#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum WebCapability {
    /// `navigator.geolocation` — the device's location.
    Geolocation,
    /// `navigator.clipboard` — reading or writing the system clipboard.
    Clipboard,
    /// The Notification API — showing a system notification.
    Notification,
    /// `localStorage` / `sessionStorage` / `IndexedDB` — client-side persistence.
    Storage,
    /// `navigator.vibrate` — the vibration actuator.
    Vibration,
    /// `navigator.share` — the platform share sheet.
    Share,
    /// `navigator.getBattery` — battery status.
    Battery,
    /// `navigator.connection` — network-information hints.
    NetworkInfo,
    /// `<input type="file">` via the File API — opening a native file picker and
    /// reading the chosen file as a `data:` URL.
    File,
    /// `<input type="file" capture="environment" accept="image/*">` — directing
    /// the OS to open the device camera (mobile) or fall back to an image file
    /// picker (desktop). The result is a single captured image as a `data:` URL.
    Camera,
    /// `getUserMedia({ audio: true })` / `MediaRecorder` — capturing a bounded
    /// audio clip from the device microphone. The host records for at most
    /// `maxDurationMs` milliseconds, assembles the chunk stream into a single
    /// Blob, reads it via `FileReader.readAsDataURL`, and replies once with the
    /// full base-64 audio data URL. A permission denial or an absent
    /// `MediaRecorder` API traps to a typed inbound frame — never a throw.
    Microphone,
    /// `navigator.getGamepads()` — polled gamepad state, connect/disconnect events.
    Gamepad,
    /// `getUserMedia({ audio[, video] })` + `MediaRecorder` — recording a bounded
    /// audio (or audio + video) stream from the device. A start opens a
    /// session-stream: the host arms a `MediaRecorder` and pushes one typed data
    /// chunk frame per `ondataavailable` blob until stop, then a terminal frame;
    /// no chunk is ever emitted after close. This axis reaches BOTH the camera and
    /// the microphone through `getUserMedia`, so it is a distinct, strictly
    /// weightier axis than [`Self::Camera`] (a `<input capture>` photo picker) or
    /// [`Self::Microphone`] (a one-shot bounded audio clip). A permission denial or
    /// an absent `MediaRecorder` API traps to a typed inbound frame — never a throw.
    Recorder,
    /// `document.visibilityState` / `visibilitychange` event — the binary
    /// foreground/background state of the page. A one-shot query reads the
    /// current state; a watch subscription delivers a fresh reading on every
    /// `visibilitychange` event. An absent Page Visibility API traps to a typed
    /// inbound frame — never a throw.
    Visibility,
    /// `window.matchMedia(query)` — evaluate a CSS media query string and
    /// receive its current match result plus a stream of change events when the
    /// environment transitions in or out of the query. An absent `matchMedia`
    /// API traps to a typed inbound frame — never a throw.
    MediaQuery,
    /// `navigator.onLine` / `online`+`offline` window events — the binary
    /// connected/disconnected state from the browser's network event model.
    /// Distinct from [`Self::NetworkInfo`], which surfaces connection-quality
    /// hints; this axis carries ONLY the binary event stream. An absent
    /// `navigator.onLine` traps to a typed inbound frame — never a throw.
    Connectivity,
    /// A port with no characterised Web API: a hand-rolled `Js.send`/`Js.subscribe`
    /// reaching author-written JS. The reachability floor no port can slip below —
    /// an uncharacterised port discloses `js-port:raw`, never nothing.
    Raw,
    /// `speechSynthesis.speak` — one-shot text-to-speech synthesis with voice,
    /// rate, pitch, and volume options, plus queue control (`speechSynthesis.cancel`).
    /// `SpeechRecognition` is deliberately excluded (experimental).
    Speech,
    /// `navigator.permissions.query({ name })` — the Permissions API state for a
    /// named browser capability: `"granted"` / `"denied"` / `"prompt"`. Covers
    /// one-shot queries and the `PermissionStatus.onchange` continuous state stream.
    Permission,
    /// `deviceorientation` window event — the device's physical orientation as
    /// alpha/beta/gamma Euler angles. A watch subscription delivers typed frames on
    /// each event; an absent API traps to a typed inbound frame — never a throw.
    Orientation,
    /// `devicemotion` window event — the device's acceleration and rotation rate.
    /// A watch subscription delivers typed frames on each event; an absent API
    /// traps to a typed inbound frame — never a throw.
    Motion,
    /// `BroadcastChannel` — a named channel for exchanging typed message frames
    /// between tabs, workers, and iframes sharing the same origin. Covers open,
    /// send, receive, and close. An absent API traps to a typed inbound frame —
    /// never a throw.
    Channel,
    /// `document.documentElement.requestFullscreen` / `document.exitFullscreen` /
    /// `fullscreenchange` event — entering/exiting fullscreen mode and receiving
    /// change events. An absent or denied API traps to a typed inbound frame —
    /// never a throw.
    Fullscreen,
    /// `screen.orientation.lock` / `screen.orientation.unlock` /
    /// `screen.orientation.type` — locking, unlocking, and reading the current
    /// screen orientation. An absent or denied API traps to a typed inbound frame —
    /// never a throw.
    ScreenOrientation,
    /// `navigator.wakeLock.request("screen")` — acquiring a screen wake lock that
    /// prevents the device from dimming or sleeping, and releasing it. An absent or
    /// denied API traps to a typed inbound frame — never a throw.
    WakeLock,
    /// `navigator.credentials.create` / `navigator.credentials.get` — the Web
    /// Authentication API (WebAuthn): registering and authenticating a public-key
    /// credential (a passkey). A ceremony returns an OPAQUE base64url-encoded
    /// credential envelope — never raw key material — or, on a `NotAllowedError` /
    /// user cancellation / absent API, a typed denial / unavailable inbound frame,
    /// never a throw. This is a crypto-credential trust boundary: the far side
    /// mints authentication material the relying party server verifies.
    WebAuthn,
}

impl WebCapability {
    /// Every web axis, in declaration order — the closed vocabulary. Feeds the
    /// flattened [`Capability::ALL`] and the round-trip drift guards.
    pub const ALL: &'static [Self] = &[
        Self::Geolocation,
        Self::Clipboard,
        Self::Notification,
        Self::Storage,
        Self::Vibration,
        Self::Share,
        Self::Battery,
        Self::NetworkInfo,
        Self::File,
        Self::Camera,
        Self::Microphone,
        Self::Gamepad,
        Self::Recorder,
        Self::Visibility,
        Self::MediaQuery,
        Self::Connectivity,
        Self::Raw,
        Self::Speech,
        Self::Permission,
        Self::Orientation,
        Self::Motion,
        Self::Channel,
        Self::Fullscreen,
        Self::ScreenOrientation,
        Self::WakeLock,
        Self::WebAuthn,
    ];

    /// The stable lowercase wire suffix, the half after `js-port:` in the wire
    /// name (`js-port:clipboard` → `"clipboard"`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Geolocation => "geolocation",
            Self::Clipboard => "clipboard",
            Self::Notification => "notification",
            Self::Storage => "storage",
            Self::Vibration => "vibration",
            Self::Share => "share",
            Self::Battery => "battery",
            Self::NetworkInfo => "network-info",
            Self::File => "file",
            Self::Camera => "camera",
            Self::Microphone => "microphone",
            Self::Gamepad => "gamepad",
            Self::Recorder => "recorder",
            Self::Visibility => "visibility",
            Self::MediaQuery => "media-query",
            Self::Connectivity => "connectivity",
            Self::Raw => "raw",
            Self::Speech => "speech",
            Self::Permission => "permission",
            Self::Orientation => "orientation",
            Self::Motion => "motion",
            Self::Channel => "channel",
            Self::Fullscreen => "fullscreen",
            Self::ScreenOrientation => "screen-orientation",
            Self::WakeLock => "wake-lock",
            Self::WebAuthn => "web-authn",
        }
    }

    /// The web axis disclosed by importing a reserved `Ipe.Browser.<Api>` stdlib
    /// module, matched on the module's dotted path segments — the compiler-owned,
    /// closed SSOT for "which browser module discloses which Web API." A new
    /// browser module is one row here plus its `WebCapability` variant.
    ///
    /// Keyed on the `["Ipe", "Browser", <Api>, ..]` PREFIX, alias-immune exactly
    /// like the `Ipe.<M>.Unsafe` import rule: the canonical import path is what
    /// matches, never a local alias, and the reserved namespace cannot be forged by
    /// a user file. Matching the prefix (not the exact 3-segment path) closes the
    /// low-level submodule hole: importing `Ipe.Browser.Geolocation.Internals`
    /// discloses the same `js-port:geolocation` axis as the top-level module, so the
    /// full option surface cannot be reached undisclosed.
    #[must_use]
    pub fn for_browser_module(segments: &[&str]) -> Option<Self> {
        match segments {
            ["Ipe", "Browser", "Geolocation", ..] => Some(Self::Geolocation),
            ["Ipe", "Browser", "Clipboard", ..] => Some(Self::Clipboard),
            ["Ipe", "Browser", "Notification", ..] => Some(Self::Notification),
            ["Ipe", "Browser", "Storage", ..] => Some(Self::Storage),
            ["Ipe", "Browser", "Vibration", ..] => Some(Self::Vibration),
            ["Ipe", "Browser", "Share", ..] => Some(Self::Share),
            ["Ipe", "Browser", "Battery", ..] => Some(Self::Battery),
            ["Ipe", "Browser", "NetworkInfo", ..] => Some(Self::NetworkInfo),
            ["Ipe", "Browser", "FilePicker", ..] => Some(Self::File),
            ["Ipe", "Browser", "Camera", ..] => Some(Self::Camera),
            ["Ipe", "Browser", "Microphone", ..] => Some(Self::Microphone),
            ["Ipe", "Browser", "Gamepad", ..] => Some(Self::Gamepad),
            ["Ipe", "Browser", "Recorder", ..] => Some(Self::Recorder),
            ["Ipe", "Browser", "Visibility", ..] => Some(Self::Visibility),
            ["Ipe", "Browser", "MediaQuery", ..] => Some(Self::MediaQuery),
            ["Ipe", "Browser", "Connectivity", ..] => Some(Self::Connectivity),
            ["Ipe", "Browser", "Speech", ..] => Some(Self::Speech),
            ["Ipe", "Browser", "Permission", ..] => Some(Self::Permission),
            ["Ipe", "Browser", "Orientation", ..] => Some(Self::Orientation),
            ["Ipe", "Browser", "Motion", ..] => Some(Self::Motion),
            ["Ipe", "Browser", "Channel", ..] => Some(Self::Channel),
            ["Ipe", "Browser", "Fullscreen", ..] => Some(Self::Fullscreen),
            ["Ipe", "Browser", "ScreenOrientation", ..] => Some(Self::ScreenOrientation),
            ["Ipe", "Browser", "WakeLock", ..] => Some(Self::WakeLock),
            ["Ipe", "Browser", "WebAuthn", ..] => Some(Self::WebAuthn),
            _ => None,
        }
    }

    /// The reserved `Ipe.Browser.*` module segments that disclose this axis, or
    /// `None` for [`Self::Raw`] (the uncharacterised-port floor, which no module
    /// maps to). This is the exhaustive inverse of [`Self::for_browser_module`]:
    /// its match has no wildcard, so a newly added `WebCapability` variant fails to
    /// compile until it is given a module path here, and the
    /// `for_browser_module_covers_every_web_axis` drift test round-trips every
    /// non-`Raw` axis through both directions.
    #[must_use]
    pub const fn browser_module_segments(self) -> Option<&'static [&'static str]> {
        match self {
            Self::Geolocation => Some(&["Ipe", "Browser", "Geolocation"]),
            Self::Clipboard => Some(&["Ipe", "Browser", "Clipboard"]),
            Self::Notification => Some(&["Ipe", "Browser", "Notification"]),
            Self::Storage => Some(&["Ipe", "Browser", "Storage"]),
            Self::Vibration => Some(&["Ipe", "Browser", "Vibration"]),
            Self::Share => Some(&["Ipe", "Browser", "Share"]),
            Self::Battery => Some(&["Ipe", "Browser", "Battery"]),
            Self::NetworkInfo => Some(&["Ipe", "Browser", "NetworkInfo"]),
            Self::File => Some(&["Ipe", "Browser", "FilePicker"]),
            Self::Camera => Some(&["Ipe", "Browser", "Camera"]),
            Self::Microphone => Some(&["Ipe", "Browser", "Microphone"]),
            Self::Gamepad => Some(&["Ipe", "Browser", "Gamepad"]),
            Self::Recorder => Some(&["Ipe", "Browser", "Recorder"]),
            Self::Visibility => Some(&["Ipe", "Browser", "Visibility"]),
            Self::MediaQuery => Some(&["Ipe", "Browser", "MediaQuery"]),
            Self::Connectivity => Some(&["Ipe", "Browser", "Connectivity"]),
            Self::Speech => Some(&["Ipe", "Browser", "Speech"]),
            Self::Permission => Some(&["Ipe", "Browser", "Permission"]),
            Self::Orientation => Some(&["Ipe", "Browser", "Orientation"]),
            Self::Motion => Some(&["Ipe", "Browser", "Motion"]),
            Self::Channel => Some(&["Ipe", "Browser", "Channel"]),
            Self::Fullscreen => Some(&["Ipe", "Browser", "Fullscreen"]),
            Self::ScreenOrientation => Some(&["Ipe", "Browser", "ScreenOrientation"]),
            Self::WakeLock => Some(&["Ipe", "Browser", "WakeLock"]),
            Self::WebAuthn => Some(&["Ipe", "Browser", "WebAuthn"]),
            Self::Raw => None,
        }
    }

    /// The HTTP `Permissions-Policy` directive names a GRANTED axis must open to
    /// `(self)` so the served document may exercise the underlying powerful
    /// browser feature. Empty for an axis whose Web API needs no
    /// `Permissions-Policy` allowance (same-origin clipboard is default-allow;
    /// storage / notification / vibration / share / battery / … are not
    /// `Permissions-Policy`-gated features).
    ///
    /// This is the closed SSOT for the capability → response-header mapping: the
    /// runtime derives the served `Permissions-Policy` from the granted set
    /// through this table, and the exhaustive `match` (no wildcard) forces a
    /// deliberate directive decision for every new axis. Fail-closed by
    /// construction — an axis defaults to NO allowance (the header keeps the
    /// empty `()` deny), never a widened one; a feature is opened only where an
    /// explicit grant maps to its directive.
    ///
    /// `Recorder` reaches BOTH the camera and the microphone through
    /// `getUserMedia`, so a grant of it opens both directives (mirroring the
    /// native-permission derivation in `ipe-cli`'s `pack::permissions`).
    #[must_use]
    pub const fn permissions_policy_directives(self) -> &'static [&'static str] {
        match self {
            Self::Geolocation => &["geolocation"],
            Self::Camera => &["camera"],
            Self::Microphone => &["microphone"],
            Self::Recorder => &["camera", "microphone"],
            // The remaining axes exercise Web APIs that are not gated by a
            // `Permissions-Policy` directive (or, for clipboard, are
            // same-origin default-allow), so a grant opens no header allowance.
            Self::Clipboard
            | Self::Notification
            | Self::Storage
            | Self::Vibration
            | Self::Share
            | Self::Battery
            | Self::NetworkInfo
            | Self::File
            | Self::Gamepad
            | Self::Visibility
            | Self::MediaQuery
            | Self::Connectivity
            | Self::Speech
            | Self::Permission
            | Self::Orientation
            | Self::Motion
            | Self::Channel
            | Self::Fullscreen
            | Self::ScreenOrientation
            | Self::WakeLock
            | Self::WebAuthn
            | Self::Raw => &[],
        }
    }

    /// The closed, ordered set of `Permissions-Policy` directive names Ipê
    /// emits an allowlist for. Every powerful feature the runtime denies by
    /// default appears here; a granted axis flips its mapped directive from the
    /// empty `()` deny to `(self)`. `payment` is present as a permanent deny —
    /// no Ipê capability opens it, so it is always `()`.
    ///
    /// This is the SSOT for the header's directive vocabulary: the runtime
    /// renders exactly these keys, in this order, so the emitted header is
    /// deterministic and the drift test can round-trip the derivation.
    pub const POLICY_DIRECTIVES: &'static [&'static str] =
        &["geolocation", "microphone", "camera", "payment"];

    /// One-line description of what granting this web capability permits.
    ///
    /// Used by [`Capability::grants`] for the `JsPort(_)` case.
    #[must_use]
    pub const fn grants(self) -> &'static str {
        match self {
            Self::Geolocation => "Accessing navigator.geolocation — the device's location.",
            Self::Clipboard => "Reading or writing the system clipboard via navigator.clipboard.",
            Self::Notification => "Showing a system notification via the Notification API.",
            Self::Storage => {
                "Client-side persistence via localStorage / sessionStorage / IndexedDB."
            }
            Self::Vibration => "Activating the vibration actuator via navigator.vibrate.",
            Self::Share => "Invoking the platform share sheet via navigator.share.",
            Self::Battery => "Reading battery status via navigator.getBattery.",
            Self::NetworkInfo => "Reading network-information hints via navigator.connection.",
            Self::File => {
                "Opening a native file picker and reading the chosen file via the File API \
                 (FileReader.readAsDataURL)."
            }
            Self::Camera => {
                "Capturing a photo via the device camera (mobile) or an image file picker \
                 (desktop) using a <input capture> element and the File API."
            }
            Self::Microphone => {
                "Recording a bounded audio clip from the device microphone via \
                 getUserMedia({ audio: true }) / MediaRecorder; the assembled clip is \
                 returned as a base-64 data URL in a single one-shot reply."
            }
            Self::Gamepad => {
                "Polling gamepad state and receiving connect/disconnect events via \
                 navigator.getGamepads() and the Gamepad API event listeners."
            }
            Self::Recorder => {
                "Recording a bounded audio (or audio + video) stream from the camera and \
                 microphone via getUserMedia + MediaRecorder; recorded data arrives as a \
                 session-stream of typed base-64 data-URL chunks until stop."
            }
            Self::Visibility => {
                "Reading the document visibility state (foreground/background) via \
                 document.visibilityState / the visibilitychange event."
            }
            Self::MediaQuery => {
                "Evaluating CSS media queries via window.matchMedia and receiving \
                 change events when the environment transitions."
            }
            Self::Connectivity => {
                "Reading the binary online/offline state via navigator.onLine and \
                 the online/offline window events."
            }
            Self::Raw => {
                "Exchanging data with hand-rolled page JS over an uncharacterised port \
                 (Js.send / Js.subscribe with author-written JS)."
            }
            Self::Speech => {
                "Synthesising speech via speechSynthesis.speak — one-shot text-to-speech \
                 with voice, rate, pitch, and volume options, and queue control via \
                 speechSynthesis.cancel."
            }
            Self::Permission => {
                "Querying and watching browser permission state via \
                 navigator.permissions.query({ name }) and PermissionStatus.onchange."
            }
            Self::Orientation => {
                "Receiving device orientation readings (alpha/beta/gamma Euler angles) \
                 via the deviceorientation window event."
            }
            Self::Motion => {
                "Receiving device motion readings (acceleration and rotation rate) \
                 via the devicemotion window event."
            }
            Self::Channel => {
                "Opening a named BroadcastChannel for cross-tab typed message exchange \
                 within the same origin."
            }
            Self::Fullscreen => {
                "Requesting and exiting fullscreen mode via \
                 document.documentElement.requestFullscreen / document.exitFullscreen, \
                 and receiving fullscreenchange events."
            }
            Self::ScreenOrientation => {
                "Locking and unlocking the screen orientation via \
                 screen.orientation.lock / screen.orientation.unlock, and reading the \
                 current screen.orientation.type."
            }
            Self::WakeLock => {
                "Acquiring a screen wake lock via navigator.wakeLock.request(\"screen\") \
                 that prevents the device from dimming or sleeping, and releasing it."
            }
            Self::WebAuthn => {
                "Registering and authenticating a public-key credential (a passkey) via \
                 navigator.credentials.create / navigator.credentials.get; results are \
                 opaque base64url credential envelopes verified by the relying party server."
            }
        }
    }

    /// Parse a web-axis wire suffix, the inverse of [`Self::as_str`]. An
    /// unrecognised suffix is [`UnknownCapability`] carrying the full offending
    /// `js-port:<suffix>` token — fail-closed, never a silent drop.
    fn from_suffix(full: &str, suffix: &str) -> Result<Self, UnknownCapability> {
        match suffix {
            "geolocation" => Ok(Self::Geolocation),
            "clipboard" => Ok(Self::Clipboard),
            "notification" => Ok(Self::Notification),
            "storage" => Ok(Self::Storage),
            "vibration" => Ok(Self::Vibration),
            "share" => Ok(Self::Share),
            "battery" => Ok(Self::Battery),
            "network-info" => Ok(Self::NetworkInfo),
            "file" => Ok(Self::File),
            "camera" => Ok(Self::Camera),
            "microphone" => Ok(Self::Microphone),
            "gamepad" => Ok(Self::Gamepad),
            "recorder" => Ok(Self::Recorder),
            "visibility" => Ok(Self::Visibility),
            "media-query" => Ok(Self::MediaQuery),
            "connectivity" => Ok(Self::Connectivity),
            "raw" => Ok(Self::Raw),
            "speech" => Ok(Self::Speech),
            "permission" => Ok(Self::Permission),
            "orientation" => Ok(Self::Orientation),
            "motion" => Ok(Self::Motion),
            "channel" => Ok(Self::Channel),
            "fullscreen" => Ok(Self::Fullscreen),
            "screen-orientation" => Ok(Self::ScreenOrientation),
            "wake-lock" => Ok(Self::WakeLock),
            "web-authn" => Ok(Self::WebAuthn),
            _ => Err(UnknownCapability(full.to_owned())),
        }
    }

    /// The `Ipe.Package` constructor spelling for this web axis — the spelling
    /// a `package.ipe` author writes (`Geolocation`, `File`, `Camera`, …).
    ///
    /// This is the one canonical home of the constructor-name vocabulary; callers
    /// that need to map a string ctor-name to a variant use [`Self::from_ctor`].
    #[must_use]
    pub const fn ctor_name(self) -> &'static str {
        match self {
            Self::Geolocation => "Geolocation",
            Self::Clipboard => "Clipboard",
            Self::Notification => "Notification",
            Self::Storage => "Storage",
            Self::Vibration => "Vibration",
            Self::Share => "Share",
            Self::Battery => "Battery",
            Self::NetworkInfo => "NetworkInfo",
            Self::File => "File",
            Self::Camera => "Camera",
            Self::Microphone => "Microphone",
            Self::Gamepad => "Gamepad",
            Self::Recorder => "Recorder",
            Self::Visibility => "Visibility",
            Self::MediaQuery => "MediaQuery",
            Self::Connectivity => "Connectivity",
            Self::Raw => "Raw",
            Self::Speech => "Speech",
            Self::Permission => "Permission",
            Self::Orientation => "Orientation",
            Self::Motion => "Motion",
            Self::Channel => "Channel",
            Self::Fullscreen => "Fullscreen",
            Self::ScreenOrientation => "ScreenOrientation",
            Self::WakeLock => "WakeLock",
            Self::WebAuthn => "WebAuthn",
        }
    }

    /// Parse a `package.ipe` constructor spelling into a web axis, the inverse
    /// of [`Self::ctor_name`]. Returns `None` for a name outside the closed
    /// web-axis vocabulary.
    #[must_use]
    pub fn from_ctor(ctor: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|c| c.ctor_name() == ctor)
    }
}

impl Capability {
    /// The trust-boundary partition this capability belongs to.
    ///
    /// Three partitions cover the full vocabulary:
    ///
    /// - `"OS resource"` — axes an OS-level sandbox (seccomp, pledge, etc.)
    ///   can confine independently: network, filesystem, database, env,
    ///   subprocess. Each maps to a concrete system-call family the jail
    ///   controls.
    /// - `"Non-determinism"` — axes that are real OS effects but carry no
    ///   exfiltration risk on their own: clock, random. Sandboxes may or may
    ///   not confine these; they are never the primary isolation lever.
    /// - `"Native crossing"` — axes that disclose an opaque trust boundary
    ///   the compiler cannot see through: native FFI, raw FFI assertion,
    ///   Ipê-level unsafe escape, shipped browser JS, JS port data exchange.
    ///   No OS jail confines them; their disclosure is the enforcement
    ///   mechanism — the consumer decides whether to grant.
    #[must_use]
    pub const fn boundary_class(self) -> &'static str {
        match self {
            Self::Network | Self::Filesystem | Self::Database | Self::Env | Self::Subprocess => {
                "OS resource"
            }
            Self::Clock | Self::Random => "Non-determinism",
            Self::NativeFfi
            | Self::FfiRaw
            | Self::Unsafe
            | Self::CustomElement
            | Self::JsPort(_) => "Native crossing",
        }
    }

    /// One-line description of what granting this capability permits.
    ///
    /// Sourced from the variant's doc-comment; condensed for table display.
    #[must_use]
    pub const fn grants(self) -> &'static str {
        match self {
            Self::Network => {
                "Outbound or inbound network access (HTTP client/server, WebSocket, email send)."
            }
            Self::Filesystem => {
                "Reading or writing the filesystem (files, directories, config files)."
            }
            Self::Database => "Structured database access (SQL queries, migrations, row decoders).",
            Self::Env => "Reading or writing process environment variables and argv.",
            Self::Subprocess => "Spawning or controlling a child process.",
            Self::Clock => "Reading wall-clock or monotonic time, or sleeping / firing on a timer.",
            Self::Random => "Drawing non-deterministic randomness (RNG, random tokens, UUIDs).",
            Self::NativeFfi => {
                "Crossing into native Rust. code — the program's true capability set cannot be \
                 inferred from Ipê alone."
            }
            Self::FfiRaw => {
                "Crossing into native Rust. code through an author-asserted signature rather than \
                 an inspected binding (always accompanies NativeFfi)."
            }
            Self::Unsafe => {
                "Importing an Ipe.<M>.Unsafe submodule — the program contains a value the \
                 compiler could not prove safe."
            }
            Self::CustomElement => {
                "Shipping browser custom-element JS that runs in the page with full DOM \
                 authority; the served bytes are SRI-pinned and CSP-constrained."
            }
            Self::JsPort(w) => w.grants(),
        }
    }

    /// Every capability, in declaration order. The vocabulary is closed; a new
    /// axis is added here and, by the exhaustive match in
    /// [`crate::StdlibKernel::capability`], classified for every kernel.
    pub const ALL: &'static [Self] = &[
        Self::Network,
        Self::Filesystem,
        Self::Database,
        Self::Env,
        Self::Subprocess,
        Self::Clock,
        Self::Random,
        Self::NativeFfi,
        Self::FfiRaw,
        Self::Unsafe,
        Self::CustomElement,
        // The `JsPort(_)` sub-axis flattens to one entry per `WebCapability`, so
        // `ALL` stays the closed, enumerable list every drift guard iterates.
        Self::JsPort(WebCapability::Geolocation),
        Self::JsPort(WebCapability::Clipboard),
        Self::JsPort(WebCapability::Notification),
        Self::JsPort(WebCapability::Storage),
        Self::JsPort(WebCapability::Vibration),
        Self::JsPort(WebCapability::Share),
        Self::JsPort(WebCapability::Battery),
        Self::JsPort(WebCapability::NetworkInfo),
        Self::JsPort(WebCapability::File),
        Self::JsPort(WebCapability::Camera),
        Self::JsPort(WebCapability::Microphone),
        Self::JsPort(WebCapability::Gamepad),
        Self::JsPort(WebCapability::Recorder),
        Self::JsPort(WebCapability::Visibility),
        Self::JsPort(WebCapability::MediaQuery),
        Self::JsPort(WebCapability::Connectivity),
        Self::JsPort(WebCapability::Raw),
        Self::JsPort(WebCapability::Speech),
        Self::JsPort(WebCapability::Permission),
        Self::JsPort(WebCapability::Orientation),
        Self::JsPort(WebCapability::Motion),
        Self::JsPort(WebCapability::Channel),
        Self::JsPort(WebCapability::Fullscreen),
        Self::JsPort(WebCapability::ScreenOrientation),
        Self::JsPort(WebCapability::WakeLock),
        Self::JsPort(WebCapability::WebAuthn),
    ];

    /// Whether this capability carries no OS-isolatable resource surface — the
    /// low-value axes `clock`/`random`/`unsafe`.
    ///
    /// `clock` and `random` are non-determinism, not exfiltration; `unsafe` is a
    /// provenance disclosure over Ipê-level escape hatches, not a native OS
    /// effect. None of the three is a jail confinement axis, so none can ever be
    /// a member of a confined set. This is the SSOT for that grouping: every site
    /// that distinguishes the low-value axes from the runtime-enforced ones
    /// (network/filesystem/database/env/subprocess/native-ffi) reads it here
    /// rather than re-listing the trio and risking drift.
    #[must_use]
    pub const fn is_low_value(self) -> bool {
        matches!(self, Self::Clock | Self::Random | Self::Unsafe)
    }

    /// The stable lowercase wire name, used in the `ipe release capabilities` report and
    /// the generated manifest.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Network => "network",
            Self::Filesystem => "filesystem",
            Self::Database => "database",
            Self::Env => "env",
            Self::Subprocess => "subprocess",
            Self::Clock => "clock",
            Self::Random => "random",
            Self::NativeFfi => "native-ffi",
            Self::FfiRaw => "ffi-raw",
            Self::Unsafe => "unsafe",
            Self::CustomElement => "custom-element",
            // The dotted `js-port:<axis>` wire name, one static literal per web
            // axis — bare `js-port` is not among them (it is unrepresentable).
            Self::JsPort(w) => match w {
                WebCapability::Geolocation => "js-port:geolocation",
                WebCapability::Clipboard => "js-port:clipboard",
                WebCapability::Notification => "js-port:notification",
                WebCapability::Storage => "js-port:storage",
                WebCapability::Vibration => "js-port:vibration",
                WebCapability::Share => "js-port:share",
                WebCapability::Battery => "js-port:battery",
                WebCapability::NetworkInfo => "js-port:network-info",
                WebCapability::File => "js-port:file",
                WebCapability::Camera => "js-port:camera",
                WebCapability::Microphone => "js-port:microphone",
                WebCapability::Gamepad => "js-port:gamepad",
                WebCapability::Recorder => "js-port:recorder",
                WebCapability::Visibility => "js-port:visibility",
                WebCapability::MediaQuery => "js-port:media-query",
                WebCapability::Connectivity => "js-port:connectivity",
                WebCapability::Raw => "js-port:raw",
                WebCapability::Speech => "js-port:speech",
                WebCapability::Permission => "js-port:permission",
                WebCapability::Orientation => "js-port:orientation",
                WebCapability::Motion => "js-port:motion",
                WebCapability::Channel => "js-port:channel",
                WebCapability::Fullscreen => "js-port:fullscreen",
                WebCapability::ScreenOrientation => "js-port:screen-orientation",
                WebCapability::WakeLock => "js-port:wake-lock",
                WebCapability::WebAuthn => "js-port:web-authn",
            },
        }
    }
}

/// Parse a capability from its wire name, the inverse of [`Capability::as_str`].
/// An unrecognised name is [`UnknownCapability`] rather than a silent drop — a
/// typo'd `[capabilities]` entry in a manifest must be a loud rejection, never a
/// capability the sandbox then fails to enforce.
impl std::str::FromStr for Capability {
    type Err = UnknownCapability;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        match name {
            "network" => Ok(Self::Network),
            "filesystem" => Ok(Self::Filesystem),
            "database" => Ok(Self::Database),
            "env" => Ok(Self::Env),
            "subprocess" => Ok(Self::Subprocess),
            "clock" => Ok(Self::Clock),
            "random" => Ok(Self::Random),
            "native-ffi" => Ok(Self::NativeFfi),
            "ffi-raw" => Ok(Self::FfiRaw),
            "unsafe" => Ok(Self::Unsafe),
            "custom-element" => Ok(Self::CustomElement),
            // A web port is spelled `js-port:<axis>`; the suffix parses against the
            // closed `WebCapability` vocabulary. A bare `js-port` (no suffix) has
            // no arm here, so it falls through to `UnknownCapability` — the coarse
            // grant-everything token a manifest cannot spell.
            other => other.strip_prefix("js-port:").map_or_else(
                || Err(UnknownCapability(other.to_owned())),
                |suffix| WebCapability::from_suffix(other, suffix).map(Self::JsPort),
            ),
        }
    }
}

/// An unrecognised capability wire name, from [`Capability`]'s
/// [`FromStr`](std::str::FromStr). Carries the offending token so the caller can
/// name it in a diagnostic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnknownCapability(pub String);

impl std::fmt::Display for UnknownCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "unknown capability {:?} (expected one of: network, filesystem, \
             database, env, subprocess, clock, random, native-ffi, ffi-raw, unsafe, \
             custom-element, js-port:<axis> where <axis> is one of geolocation, \
             clipboard, notification, storage, vibration, share, battery, \
             network-info, file, camera, microphone, gamepad, recorder, visibility, \
             media-query, connectivity, raw, speech, permission, orientation, motion, \
             channel, fullscreen, screen-orientation, wake-lock, web-authn)",
            self.0
        )
    }
}

impl std::error::Error for UnknownCapability {}

/// The trait bound a collection kernel imposes on its ELEMENT type — the
/// soundness axis for storing a value inside a `List`/`Dict`/`Set`.
///
/// A stored function value is carried on the `Clone` `Arc<dyn Fn>` carrier, which
/// is `Clone` but neither `PartialEq`/`PartialOrd` nor `Ord`/`Hash`. A kernel
/// whose emitted Rust operates on the element only by move/clone
/// ([`Self::CloneOk`]) is therefore sound over a function element; a kernel that
/// compares elements for equality ([`Self::RequiresPartialEq`]) or orders them
/// ([`Self::RequiresOrd`]) is NOT, and a function-embedding element must be
/// rejected at `ipe` time with the equality/ordering diagnostic rather than
/// emitting Rust that `cargo` rejects (`Arc<dyn Fn>: !PartialEq`).
///
/// This makes the element requirement an explicit registry fact rather than an
/// implicit property of the hand-written runtime signature
/// (make-invalid-states-unrepresentable). Every `List`/`Dict`/`Set` kernel
/// carries one, verified by a coherence test.
///
/// The three forbidding variants encode *why* a function element is unsound for
/// a given kernel, so the set is exhaustive rather than an implicit allowlist of
/// the kernels whose function-element frontier happens to be closed:
///
/// - [`Self::RequiresPartialEq`] / [`Self::RequiresOrd`]: the emitted Rust
///   compares or orders the element — no `Arc<dyn Fn>` representation exists.
/// - [`Self::MapperFrontierOpen`]: the kernel passes the element into a mapper
///   closure whose parameter carrier the lowerer has NOT aligned to the stored
///   `Arc<dyn Fn>`, so a function element would emit an `Arc`-vs-`Box` mismatch.
///   [`Self::CloneOk`] is reserved for the higher-order kernels whose frontier
///   IS closed plus the pure move/clone/structural kernels.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum ElementCapability {
    /// The element is only moved / cloned, OR it is passed to a mapper closure
    /// whose parameter carrier the lowerer aligns to the stored `Arc<dyn Fn>` —
    /// sound for an `Arc<dyn Fn>` (function) element either way. Covers the pure
    /// structural kernels and the higher-order kernels whose function-element
    /// frontier is closed.
    CloneOk,
    /// The element is compared for equality (`==`) — requires `PartialEq`, which
    /// a function carrier does not satisfy. A function-embedding element is
    /// rejected.
    RequiresPartialEq,
    /// The element is ordered (`<`/`sort`/keyed) — requires `PartialOrd`/`Ord`,
    /// which a function carrier does not satisfy. A function-embedding element is
    /// rejected.
    RequiresOrd,
    /// The element is passed into a mapper/comparator closure whose parameter
    /// carrier the lowerer does NOT re-type to the stored `Arc<dyn Fn>` — the
    /// higher-order frontier is open. A function carrier would emit an
    /// `Arc`-vs-`Box` mismatch (`E0308`) or a `Box<dyn Fn>: Clone` failure
    /// (`E0277`), so a function-embedding element is rejected fail-closed rather
    /// than mis-emitted. Derived from the kernel scheme
    /// (`mapper_frontier_open`): a stored element feeding a mapper parameter
    /// that `mapper_param_binds_stored_element` does not name keeps the frontier
    /// open, and a build-time assert forbids any contradicting tag.
    MapperFrontierOpen,
}

impl ElementCapability {
    /// Does this capability forbid a function-carrying element? `true` for the
    /// equality/ordering requirements and the open-frontier mapper family;
    /// `false` only for [`Self::CloneOk`].
    #[must_use]
    pub const fn forbids_function_element(self) -> bool {
        matches!(
            self,
            Self::RequiresPartialEq | Self::RequiresOrd | Self::MapperFrontierOpen
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{Capability, WebCapability};

    #[test]
    fn all_lists_every_variant_once() {
        // A guard against `ALL` drifting from the enum: each name is distinct,
        // and the count matches the declared axes (11 flat + one `JsPort` per
        // `WebCapability`, so the sub-axis is enumerated, not wildcarded away).
        let names: Vec<&str> = Capability::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(names.len(), 11 + WebCapability::ALL.len()); // 11 flat + one JsPort per WebCapability
        let mut sorted = names.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), names.len(), "ALL has a duplicate");
    }

    #[test]
    fn all_enumerates_every_web_axis_under_js_port() {
        // MUST-FIX #3 drift guard: every `WebCapability` appears as a `JsPort(w)`
        // member of `ALL` — no web axis can be silently dropped from the closed set.
        for &w in WebCapability::ALL {
            assert!(
                Capability::ALL.contains(&Capability::JsPort(w)),
                "ALL is missing js-port sub-axis {w:?}"
            );
        }
    }

    #[test]
    fn permissions_policy_directives_are_a_subset_of_the_header_vocabulary() {
        // SEAL / drift guard: every directive any axis opens MUST be one the
        // runtime actually renders in the served `Permissions-Policy` (the
        // closed `POLICY_DIRECTIVES` vocabulary). A directive an axis opens but
        // the header never emits would be a grant the served policy silently
        // ignores — an `ipe`-accepts-then-runtime-vetoes gap. The exhaustive
        // per-axis `match` forces a directive decision for every new axis; this
        // ties that decision to the header vocabulary so the two cannot drift.
        let vocab: std::collections::BTreeSet<&str> =
            WebCapability::POLICY_DIRECTIVES.iter().copied().collect();
        for &w in WebCapability::ALL {
            for &dir in w.permissions_policy_directives() {
                assert!(
                    vocab.contains(dir),
                    "{w:?} opens {dir:?}, absent from POLICY_DIRECTIVES {vocab:?}"
                );
            }
        }
    }

    #[test]
    fn media_axes_open_their_getusermedia_directives() {
        // The powerful media axes open exactly their underlying feature's
        // directive; Recorder reaches both camera and microphone via
        // getUserMedia, so it opens both. Pins the specific mapping the runtime
        // header derivation depends on.
        assert_eq!(
            WebCapability::Geolocation.permissions_policy_directives(),
            &["geolocation"]
        );
        assert_eq!(
            WebCapability::Camera.permissions_policy_directives(),
            &["camera"]
        );
        assert_eq!(
            WebCapability::Microphone.permissions_policy_directives(),
            &["microphone"]
        );
        assert_eq!(
            WebCapability::Recorder.permissions_policy_directives(),
            &["camera", "microphone"]
        );
        // Same-origin clipboard is default-allow → no directive.
        assert!(
            WebCapability::Clipboard
                .permissions_policy_directives()
                .is_empty()
        );
    }

    #[test]
    fn for_browser_module_covers_every_web_axis() {
        // Every web axis except the uncharacterised-port floor must map to a
        // reserved `Ipe.Browser.*` module and round-trip back to itself. A missed
        // `for_browser_module` row would degrade that module's ports to the
        // `js-port:raw` floor, losing the specific-API disclosure; the exhaustive
        // `browser_module_segments` inverse forces a module path per variant at
        // compile time and this test round-trips both directions.
        for &w in WebCapability::ALL {
            if w == WebCapability::Raw {
                assert!(
                    w.browser_module_segments().is_none(),
                    "the raw floor has no module path"
                );
                continue;
            }
            let segments = w
                .browser_module_segments()
                .expect("every non-raw axis has a module path");
            assert_eq!(
                WebCapability::for_browser_module(segments),
                Some(w),
                "{w:?}: module path {segments:?} must resolve back to this axis"
            );
        }
    }

    #[test]
    fn as_str_is_the_wire_vocabulary() {
        assert_eq!(Capability::Network.as_str(), "network");
        assert_eq!(Capability::Filesystem.as_str(), "filesystem");
        assert_eq!(Capability::Database.as_str(), "database");
        assert_eq!(Capability::Env.as_str(), "env");
        assert_eq!(Capability::Subprocess.as_str(), "subprocess");
        assert_eq!(Capability::Clock.as_str(), "clock");
        assert_eq!(Capability::Random.as_str(), "random");
        assert_eq!(Capability::NativeFfi.as_str(), "native-ffi");
        assert_eq!(Capability::FfiRaw.as_str(), "ffi-raw");
        assert_eq!(Capability::Unsafe.as_str(), "unsafe");
        assert_eq!(Capability::CustomElement.as_str(), "custom-element");
        assert_eq!(
            Capability::JsPort(WebCapability::Clipboard).as_str(),
            "js-port:clipboard"
        );
        assert_eq!(
            Capability::JsPort(WebCapability::Raw).as_str(),
            "js-port:raw"
        );
    }

    #[test]
    fn from_str_round_trips_every_variant() {
        // `from_str` is the exact inverse of `as_str` over the whole vocabulary,
        // including every `js-port:<axis>` sub-axis (MUST-FIX #2 round-trip).
        use std::str::FromStr as _;
        for &cap in Capability::ALL {
            assert_eq!(Capability::from_str(cap.as_str()), Ok(cap));
        }
        for &w in WebCapability::ALL {
            let cap = Capability::JsPort(w);
            assert_eq!(Capability::from_str(cap.as_str()), Ok(cap));
        }
    }

    #[test]
    fn from_str_rejects_an_unknown_name() {
        use std::str::FromStr as _;
        let err = Capability::from_str("filesytem").unwrap_err();
        assert_eq!(err, super::UnknownCapability("filesytem".to_owned()));
    }

    #[test]
    fn from_str_hard_rejects_bare_js_port() {
        // MUST-FIX #2: a bare `js-port` (no `:<axis>` suffix) is NOT a member — a
        // manifest cannot spell the coarse grant-everything token.
        use std::str::FromStr as _;
        let err = Capability::from_str("js-port").unwrap_err();
        assert_eq!(err, super::UnknownCapability("js-port".to_owned()));
    }

    #[test]
    fn from_str_rejects_an_unknown_web_axis_suffix() {
        // An unrecognised `js-port:<axis>` suffix fails closed, carrying the full
        // offending token, exactly as any other typo does.
        use std::str::FromStr as _;
        let err = Capability::from_str("js-port:unknown-axis").unwrap_err();
        assert_eq!(
            err,
            super::UnknownCapability("js-port:unknown-axis".to_owned())
        );
    }

    #[test]
    fn from_str_accepts_file_camera_and_microphone_web_axes() {
        use std::str::FromStr as _;
        assert_eq!(
            Capability::from_str("js-port:file"),
            Ok(Capability::JsPort(WebCapability::File))
        );
        assert_eq!(
            Capability::from_str("js-port:camera"),
            Ok(Capability::JsPort(WebCapability::Camera))
        );
        assert_eq!(
            Capability::from_str("js-port:microphone"),
            Ok(Capability::JsPort(WebCapability::Microphone))
        );
    }

    #[test]
    fn recorder_axis_round_trips_and_names_the_browser_module() {
        // The media-recording axis is its own closed vocabulary member, distinct
        // from camera/microphone, and the `Ipe.Browser.Recorder` module (and its
        // Internals submodule) discloses it via the path-prefix key.
        use std::str::FromStr as _;
        assert_eq!(
            Capability::from_str("js-port:recorder"),
            Ok(Capability::JsPort(WebCapability::Recorder))
        );
        assert_eq!(WebCapability::Recorder.as_str(), "recorder");
        assert_eq!(WebCapability::Recorder.ctor_name(), "Recorder");
        assert_eq!(
            WebCapability::from_ctor("Recorder"),
            Some(WebCapability::Recorder)
        );
        assert_eq!(
            WebCapability::for_browser_module(&["Ipe", "Browser", "Recorder"]),
            Some(WebCapability::Recorder)
        );
        assert_eq!(
            WebCapability::for_browser_module(&["Ipe", "Browser", "Recorder", "Internals"]),
            Some(WebCapability::Recorder)
        );
    }

    #[test]
    fn web_authn_axis_round_trips_and_names_the_browser_module() {
        // The Web Authentication (WebAuthn) axis is its own closed vocabulary
        // member, and the `Ipe.Browser.WebAuthn` module (and its Internals
        // submodule) discloses it via the path-prefix key.
        use std::str::FromStr as _;
        assert_eq!(
            Capability::from_str("js-port:web-authn"),
            Ok(Capability::JsPort(WebCapability::WebAuthn))
        );
        assert_eq!(WebCapability::WebAuthn.as_str(), "web-authn");
        assert_eq!(WebCapability::WebAuthn.ctor_name(), "WebAuthn");
        assert_eq!(
            WebCapability::from_ctor("WebAuthn"),
            Some(WebCapability::WebAuthn)
        );
        assert_eq!(
            WebCapability::for_browser_module(&["Ipe", "Browser", "WebAuthn"]),
            Some(WebCapability::WebAuthn)
        );
        assert_eq!(
            WebCapability::for_browser_module(&["Ipe", "Browser", "WebAuthn", "Internals"]),
            Some(WebCapability::WebAuthn)
        );
    }

    #[test]
    fn low_value_is_exactly_clock_random_unsafe() {
        // Pins the SSOT low-value grouping against drift: exactly the three axes
        // with no OS-isolatable surface. A new capability defaults to high-value
        // (runtime-enforced) unless it is deliberately added here.
        let low: Vec<&str> = Capability::ALL
            .iter()
            .filter(|c| c.is_low_value())
            .map(|c| c.as_str())
            .collect();
        assert_eq!(low, vec!["clock", "random", "unsafe"]);
        assert!(Capability::Clock.is_low_value());
        assert!(Capability::Random.is_low_value());
        assert!(Capability::Unsafe.is_low_value());
        assert!(!Capability::Network.is_low_value());
        assert!(!Capability::NativeFfi.is_low_value());
        // `custom-element` is a disclosure of shipped browser JS, a declared-trust
        // surface analogous to `native-ffi`: it must always surface, never be
        // grouped with the clock/random/unsafe noise the low-value flag marks.
        assert!(!Capability::CustomElement.is_low_value());
        // `js-port` is the same class of declared-trust JS-exchange disclosure: it
        // must always surface to the consumer, never be grouped as low-value. Every
        // web sub-axis (including `:raw`) shares that posture.
        for &w in WebCapability::ALL {
            assert!(!Capability::JsPort(w).is_low_value());
        }
    }

    #[test]
    fn ordering_is_deterministic_for_a_btreeset() {
        // `program_capabilities` returns a `BTreeSet<Capability>`; the derived
        // `Ord` must give a stable, reproducible report order.
        use std::collections::BTreeSet;
        let set: BTreeSet<Capability> = [Capability::Random, Capability::Network, Capability::Env]
            .into_iter()
            .collect();
        let ordered: Vec<&str> = set.iter().map(|c| c.as_str()).collect();
        assert_eq!(ordered, vec!["network", "env", "random"]);
    }
}
