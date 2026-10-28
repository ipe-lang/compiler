//! Deriving a native shell's OS-permission declarations from the app's granted
//! web capabilities — the single source of truth for what a packaged app may do.
//!
//! A packaged Ipê app runs its client code inside a native shell (an iOS/macOS
//! bundle, an Android APK). Each native OS gates the device surfaces a page can
//! reach behind an explicit permission declaration: iOS/macOS require a
//! `Info.plist` usage-description key with a non-empty purpose string; Android
//! requires a `<uses-permission>` (and sometimes a `<uses-feature>`) manifest
//! entry. This module makes those declarations *derived*, never author-supplied:
//! the app's `[capabilities] accepts` set — the same grant the fail-closed
//! app-boundary consent gate reads ([`crate::web_consent`]) — is the sole input,
//! and the permission table here is the sole mapping.
//!
//! Two directions are fail-closed, and both are the security property:
//!
//! - **Accepted ⇒ merged.** Every granted web axis that needs an OS permission
//!   contributes it. The manifest is computed, so it can never under-declare
//!   relative to consent.
//! - **Merged ⇒ accepted.** An author-supplied override that adds an OS
//!   permission with no backing accepted axis is a hard, typed refusal naming
//!   the permission ([`reconcile_override`]). A package can never smuggle an OS
//!   permission the app did not consent to.
//!
//! The axis→permission table is exhaustive over the closed [`WebCapability`]
//! vocabulary: a new web axis added to the compiler forces a new arm here (there
//! is no wildcard), so a future device module cannot ship without its OS-permission
//! mapping considered.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use ipe_ir::{Capability, WebCapability};
use ipe_kernels::BridgeCap;

use crate::CliError;

/// A native packaging target whose OS-permission model this module renders for.
///
/// `MacOs` is a distinct member from `Ios` even though both render `Info.plist`
/// usage-description keys: a desktop-mac bundle and an iOS bundle differ in which
/// keys the OS honours (e.g. location-when-in-use is iOS-shaped), so the target
/// is carried explicitly rather than collapsed into a single "Apple" case.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum Platform {
    /// An iOS application bundle — `Info.plist` usage-description keys.
    Ios,
    /// A macOS desktop application bundle — `Info.plist` usage-description keys.
    MacOs,
    /// An Android application package — `<uses-permission>` / `<uses-feature>`.
    Android,
}

impl Platform {
    /// Whether this target renders an Apple `Info.plist` (iOS or macOS) rather
    /// than an Android manifest. The Apple targets require a non-empty
    /// usage-description purpose string for every plist key they declare.
    #[must_use]
    const fn is_apple(self) -> bool {
        matches!(self, Self::Ios | Self::MacOs)
    }

    /// The lowercase wire name of this platform, used in the CLI surface and
    /// diagnostics (`ios` / `macos` / `android`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ios => "ios",
            Self::MacOs => "macos",
            Self::Android => "android",
        }
    }
}

impl std::str::FromStr for Platform {
    type Err = UnknownPlatform;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        match name {
            "ios" => Ok(Self::Ios),
            "macos" => Ok(Self::MacOs),
            "android" => Ok(Self::Android),
            other => Err(UnknownPlatform(other.to_owned())),
        }
    }
}

/// An unrecognised platform name, from [`Platform`]'s
/// [`FromStr`](std::str::FromStr). Carries the offending token so the caller can
/// name it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnknownPlatform(pub String);

impl std::fmt::Display for UnknownPlatform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "unknown platform {:?} (expected one of: ios, macos, android)",
            self.0
        )
    }
}

impl std::error::Error for UnknownPlatform {}

/// An Apple `Info.plist` usage-description key a web axis can need.
///
/// A closed set: each key carries exactly one purpose string, so two axes that
/// reach the same surface contribute the same entry and a rendered plist never
/// holds one key twice. The purpose is the human-readable reason shown at the
/// permission prompt; it is invariantly non-empty (Apple rejects an empty usage
/// description at review), guaranteed by construction since every arm of
/// [`Self::purpose`] is a literal. Keys order by their plist spelling, so a
/// rendered plist lists them alphabetically whatever the declaration order.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum PlistKey {
    /// `NSLocationWhenInUseUsageDescription` — location while the app is in use.
    LocationWhenInUse,
    /// `NSCameraUsageDescription` — the camera.
    Camera,
    /// `NSMicrophoneUsageDescription` — the microphone.
    Microphone,
}

impl PlistKey {
    /// Every usage-description key the table can name, in declaration order.
    pub const ALL: &'static [Self] = &[Self::LocationWhenInUse, Self::Camera, Self::Microphone];

    /// The `NS…UsageDescription` plist key.
    #[must_use]
    pub const fn key(self) -> &'static str {
        match self {
            Self::LocationWhenInUse => "NSLocationWhenInUseUsageDescription",
            Self::Camera => "NSCameraUsageDescription",
            Self::Microphone => "NSMicrophoneUsageDescription",
        }
    }

    /// The non-empty default purpose string the OS displays at the prompt.
    #[must_use]
    pub const fn purpose(self) -> &'static str {
        match self {
            Self::LocationWhenInUse => {
                "This app uses your location to provide location-based features."
            }
            Self::Camera => "This app uses the camera to take photos and record video.",
            Self::Microphone => "This app uses the microphone to record audio.",
        }
    }
}

impl Ord for PlistKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.key().cmp(other.key())
    }
}

impl PartialOrd for PlistKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// An Android permission a web axis can need, without the `android.permission.`
/// prefix.
///
/// A closed set, so a permission is matched and de-duplicated by identity rather
/// than by text, and its runtime request code is a property of the permission
/// itself. Permissions order by their constant name, so a rendered manifest
/// lists them alphabetically whatever the declaration order.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum AndroidPermission {
    /// `ACCESS_FINE_LOCATION`.
    AccessFineLocation,
    /// `ACCESS_COARSE_LOCATION`.
    AccessCoarseLocation,
    /// `POST_NOTIFICATIONS`.
    PostNotifications,
    /// `VIBRATE`.
    Vibrate,
    /// `ACCESS_NETWORK_STATE`.
    AccessNetworkState,
    /// `RECORD_AUDIO`.
    RecordAudio,
    /// `CAMERA`.
    Camera,
}

impl AndroidPermission {
    /// Every Android permission the table can name, in declaration order.
    pub const ALL: &'static [Self] = &[
        Self::AccessFineLocation,
        Self::AccessCoarseLocation,
        Self::PostNotifications,
        Self::Vibrate,
        Self::AccessNetworkState,
        Self::RecordAudio,
        Self::Camera,
    ];

    /// The bare permission constant, without the `android.permission.` prefix.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::AccessFineLocation => "ACCESS_FINE_LOCATION",
            Self::AccessCoarseLocation => "ACCESS_COARSE_LOCATION",
            Self::PostNotifications => "POST_NOTIFICATIONS",
            Self::Vibrate => "VIBRATE",
            Self::AccessNetworkState => "ACCESS_NETWORK_STATE",
            Self::RecordAudio => "RECORD_AUDIO",
            Self::Camera => "CAMERA",
        }
    }

    /// Whether the shell asks for this permission at the moment of use, rather
    /// than the OS granting it at install.
    #[must_use]
    pub const fn is_runtime_requested(self) -> bool {
        match self {
            Self::AccessFineLocation
            | Self::AccessCoarseLocation
            | Self::PostNotifications
            | Self::RecordAudio
            | Self::Camera => true,
            Self::Vibrate | Self::AccessNetworkState => false,
        }
    }

    /// The stable request code the shell uses to ask for this permission at the
    /// moment of use, or `None` for a permission the OS grants at install.
    ///
    /// The code is one plus the number of runtime-requested permissions before
    /// this one in [`Self::ALL`], so permissions with distinct names never share
    /// a code. A permission absent from [`Self::ALL`] has no code, and the
    /// build-time agreement check below refuses a bridged row naming one.
    #[must_use]
    pub const fn runtime_request_code(self) -> Option<RequestCode> {
        if !self.is_runtime_requested() {
            return None;
        }
        let mut rest = Self::ALL;
        let mut code: u16 = 1;
        while let Some((candidate, tail)) = rest.split_first() {
            if const_str_eq(candidate.name(), self.name()) {
                return Some(RequestCode(code));
            }
            if candidate.is_runtime_requested() {
                match code.checked_add(1) {
                    Some(next) => code = next,
                    None => return None,
                }
            }
            rest = tail;
        }
        None
    }
}

impl Ord for AndroidPermission {
    fn cmp(&self, other: &Self) -> Ordering {
        self.name().cmp(other.name())
    }
}

impl PartialOrd for AndroidPermission {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// The stable request code of one runtime-requested Android permission.
///
/// Its own type so a code is never mistaken for a count or an index.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct RequestCode(u16);

impl RequestCode {
    /// The numeric code the shell passes to the permission request.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

/// One runtime permission request row: the permission and its stable code.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct RuntimeRequest {
    /// The permission requested at the moment of use.
    pub permission: AndroidPermission,
    /// The stable request code identifying the request.
    pub code: RequestCode,
}

/// One Android manifest element derived for a web axis: a `<uses-permission>`.
///
/// A typed kind rather than a raw XML string, so the renderer — not the table —
/// owns the XML surface. It is an enum (not a bare struct) so a future
/// feature-gated axis can add a `<uses-feature>` element as a second variant
/// without touching this one's call sites.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum AndroidEntry {
    /// `<uses-permission android:name="android.permission.NAME"/>`.
    UsesPermission(AndroidPermission),
}

/// An iOS entitlement a web axis needs.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum IosEntitlement {
    /// `aps-environment` — the push-notification service environment. Its value
    /// (development or production) comes from the app's push declaration.
    ApsEnvironment,
}

impl IosEntitlement {
    /// The entitlement key.
    #[must_use]
    pub const fn key(self) -> &'static str {
        match self {
            Self::ApsEnvironment => "aps-environment",
        }
    }
}

/// One member of the iOS `Info.plist` `UIBackgroundModes` array a web axis
/// needs.
///
/// The array key is the fixed [`UI_BACKGROUND_MODES_KEY`]; only these typed
/// members can appear in it, so the table carries no free-form plist key.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum IosBackgroundMode {
    /// `remote-notification` — waking the app for a delivered push message.
    RemoteNotification,
}

impl IosBackgroundMode {
    /// The array member's string value.
    #[must_use]
    pub const fn value(self) -> &'static str {
        match self {
            Self::RemoteNotification => "remote-notification",
        }
    }

    /// The member qualified by its array key, `UIBackgroundModes:<member>`.
    ///
    /// The identifier an override must name to declare this one member, never
    /// the bare array key that would stand for every member.
    #[must_use]
    pub fn qualified_name(self) -> String {
        format!("{UI_BACKGROUND_MODES_KEY}:{}", self.value())
    }
}

/// The `Info.plist` array key holding every [`IosBackgroundMode`].
pub const UI_BACKGROUND_MODES_KEY: &str = "UIBackgroundModes";

/// The per-axis OS-permission requirement across all platforms — the closed SSOT
/// row for one [`WebCapability`].
///
/// Every field is a (possibly empty) static list: an axis reaching no gated
/// surface contributes nothing, and one reaching several (media recording
/// reaches both the camera and the microphone) lists each.
struct AxisRequirement {
    /// The usage-description keys this axis needs on both Apple platforms.
    apple: &'static [PlistKey],
    /// The usage-description keys this axis needs on iOS only.
    ios_only: &'static [PlistKey],
    /// The Android permissions this axis needs.
    android: &'static [AndroidPermission],
    /// The iOS entitlements this axis needs.
    ios_entitlements: &'static [IosEntitlement],
    /// The iOS `UIBackgroundModes` members this axis needs.
    ios_background_modes: &'static [IosBackgroundMode],
}

/// The row of an axis that reaches no permission-gated OS surface.
const NO_OS_PERMISSION: AxisRequirement = AxisRequirement {
    apple: &[],
    ios_only: &[],
    android: &[],
    ios_entitlements: &[],
    ios_background_modes: &[],
};

/// The single source of truth: the OS-permission requirement for one web axis.
///
/// Exhaustive over the closed [`WebCapability`] vocabulary — there is no
/// wildcard arm, so adding a web axis to the compiler forces a new arm here and
/// the crate will not compile until its OS-permission mapping is decided. This is
/// the make-invalid-states-unrepresentable guarantee: no web axis can silently
/// ship un-permissioned. A `const fn`, so the build-time agreement check below
/// reads the same rows the derivation does.
#[deny(clippy::wildcard_enum_match_arm)]
const fn requirement_for(axis: WebCapability) -> AxisRequirement {
    match axis {
        WebCapability::Geolocation => AxisRequirement {
            apple: &[PlistKey::LocationWhenInUse],
            android: &[
                AndroidPermission::AccessFineLocation,
                AndroidPermission::AccessCoarseLocation,
            ],
            ..NO_OS_PERMISSION
        },
        // Apple: local notification authorisation is a runtime prompt, not a
        // static plist key. Android 13+ requires POST_NOTIFICATIONS.
        WebCapability::Notification => AxisRequirement {
            android: &[AndroidPermission::PostNotifications],
            ..NO_OS_PERMISSION
        },
        // A push subscription posts the delivered message as a notification, so
        // Android needs POST_NOTIFICATIONS. iOS needs the push-service
        // entitlement and the remote-notification background mode; its
        // authorisation prompt is a runtime request, not a usage key.
        WebCapability::Push => AxisRequirement {
            android: &[AndroidPermission::PostNotifications],
            ios_entitlements: &[IosEntitlement::ApsEnvironment],
            ios_background_modes: &[IosBackgroundMode::RemoteNotification],
            ..NO_OS_PERMISSION
        },
        // Apple has no vibration permission. Android gates the vibrator.
        WebCapability::Vibration => AxisRequirement {
            android: &[AndroidPermission::Vibrate],
            ..NO_OS_PERMISSION
        },
        // Network-information hints. Android reads them behind
        // ACCESS_NETWORK_STATE; Apple exposes them without a usage key.
        WebCapability::NetworkInfo => AxisRequirement {
            android: &[AndroidPermission::AccessNetworkState],
            ..NO_OS_PERMISSION
        },
        // `getUserMedia({ audio: true })` needs the microphone usage key on Apple
        // platforms and RECORD_AUDIO on Android before the prompt can appear.
        WebCapability::Microphone => AxisRequirement {
            apple: &[PlistKey::Microphone],
            android: &[AndroidPermission::RecordAudio],
            ..NO_OS_PERMISSION
        },
        // Media recording reaches BOTH the camera and the microphone through
        // `getUserMedia`, so it needs both usage keys on Apple platforms and
        // both permissions on Android.
        WebCapability::Recorder => AxisRequirement {
            apple: &[PlistKey::Camera, PlistKey::Microphone],
            android: &[AndroidPermission::Camera, AndroidPermission::RecordAudio],
            ..NO_OS_PERMISSION
        },
        // The capture element (`<input capture>`) opens the camera on iOS, and
        // iOS terminates an app that opens the camera without the camera usage
        // key, so iOS declares it. On macOS the capture element opens a file
        // picker, and Android's chooser needs no static declaration.
        WebCapability::Camera => AxisRequirement {
            ios_only: &[PlistKey::Camera],
            ..NO_OS_PERMISSION
        },
        // The iOS file picker offers to take a photo or record a video in place,
        // which opens the camera and the microphone, so iOS declares both keys.
        // The macOS and Android pickers open no capture device.
        WebCapability::File => AxisRequirement {
            ios_only: &[PlistKey::Camera, PlistKey::Microphone],
            ..NO_OS_PERMISSION
        },
        // The axes that reach no permission-gated OS surface on any target:
        // clipboard (user-initiated paste), storage (in-sandbox persistence),
        // share (user-initiated share sheet), battery (ungated status), gamepad
        // (an input device the browser mediates), visibility / media-query /
        // connectivity (user-context reads), the
        // `raw` floor (an uncharacterised port reaches no compiler-known surface;
        // its disclosure is enforced by the consent gate, not an OS
        // declaration), speech synthesis, the Permissions API (it queries
        // existing state), orientation and motion events, BroadcastChannel,
        // fullscreen and screen-orientation lock (user-gesture gated), wake lock,
        // and Web Authentication (the platform authenticator mediates the
        // ceremony; its user-verification prompt is not a declarable
        // permission). Named explicitly — no wildcard — so a new web axis stays
        // unmatched and forces a deliberate permission decision here.
        WebCapability::Clipboard
        | WebCapability::Storage
        | WebCapability::Share
        | WebCapability::Battery
        | WebCapability::Gamepad
        | WebCapability::Visibility
        | WebCapability::MediaQuery
        | WebCapability::Connectivity
        | WebCapability::Raw
        | WebCapability::Speech
        | WebCapability::Permission
        | WebCapability::Orientation
        | WebCapability::Motion
        | WebCapability::Channel
        | WebCapability::Fullscreen
        | WebCapability::ScreenOrientation
        | WebCapability::WakeLock
        | WebCapability::WebAuthn => NO_OS_PERMISSION,
    }
}

/// Whether two strings are byte-equal, usable in a `const`.
const fn const_str_eq(a: &str, b: &str) -> bool {
    let (mut left, mut right) = (a.as_bytes(), b.as_bytes());
    loop {
        match (left.split_first(), right.split_first()) {
            (Some((x, xs)), Some((y, ys))) => {
                if *x != *y {
                    return false;
                }
                left = xs;
                right = ys;
            }
            (None, None) => return true,
            (Some(_), None) | (None, Some(_)) => return false,
        }
    }
}

/// Whether `permission` appears in `listed`, compared by its constant name.
const fn lists_permission(listed: &[AndroidPermission], permission: AndroidPermission) -> bool {
    let mut rest = listed;
    while let Some((candidate, tail)) = rest.split_first() {
        if const_str_eq(candidate.name(), permission.name()) {
            return true;
        }
        rest = tail;
    }
    false
}

/// Whether the Android permission vocabulary `listed` names each permission
/// once. Distinct names give distinct request codes by construction of
/// [`AndroidPermission::runtime_request_code`].
const fn android_permissions_agree(listed: &[AndroidPermission]) -> bool {
    let mut rest = listed;
    while let Some((permission, tail)) = rest.split_first() {
        if lists_permission(tail, *permission) {
            return false;
        }
        rest = tail;
    }
    true
}

/// Whether `key` appears in `listed`, compared by its plist spelling.
const fn lists_plist_key(listed: &[PlistKey], key: PlistKey) -> bool {
    let mut rest = listed;
    while let Some((candidate, tail)) = rest.split_first() {
        if const_str_eq(candidate.key(), key.key()) {
            return true;
        }
        rest = tail;
    }
    false
}

/// Whether the usage-description vocabulary `listed` names each plist key once.
const fn plist_keys_agree(listed: &[PlistKey]) -> bool {
    let mut rest = listed;
    while let Some((key, tail)) = rest.split_first() {
        if lists_plist_key(tail, *key) {
            return false;
        }
        rest = tail;
    }
    true
}

/// Whether one table row agrees with its bridge status and with the
/// vocabularies `keys` and `permissions`.
///
/// Each plist key the row names is in `keys` (so the distinct-key check covers
/// it); each Android permission it names is in `permissions` (so the
/// request-code rows are complete); a `bridged` row declares at least one
/// Android permission and every one it declares is runtime-requested (the bridge
/// asks at the moment of use); and an iOS entitlement or background mode
/// appears only on a bridged row, since only native shell code uses one.
const fn row_agrees(
    row: &AxisRequirement,
    bridged: bool,
    keys: &[PlistKey],
    permissions: &[AndroidPermission],
) -> bool {
    if bridged && row.android.is_empty() {
        return false;
    }
    let native_only = !row.ios_entitlements.is_empty() || !row.ios_background_modes.is_empty();
    if native_only && !bridged {
        return false;
    }
    let mut apple = row.apple;
    while let Some((key, more)) = apple.split_first() {
        if !lists_plist_key(keys, *key) {
            return false;
        }
        apple = more;
    }
    let mut ios_only = row.ios_only;
    while let Some((key, more)) = ios_only.split_first() {
        if !lists_plist_key(keys, *key) {
            return false;
        }
        ios_only = more;
    }
    let mut android = row.android;
    while let Some((permission, more)) = android.split_first() {
        if !lists_permission(permissions, *permission) {
            return false;
        }
        if bridged && !permission.is_runtime_requested() {
            return false;
        }
        android = more;
    }
    true
}

/// Whether every row of the permission table over `axes` agrees with its bridge
/// status ([`BridgeCap::for_axis`]), [`PlistKey::ALL`] and
/// [`AndroidPermission::ALL`], per [`row_agrees`].
const fn permission_table_agrees(axes: &[WebCapability]) -> bool {
    let mut rest = axes;
    while let Some((axis, tail)) = rest.split_first() {
        let bridged = BridgeCap::for_axis(*axis).is_some();
        if !row_agrees(
            &requirement_for(*axis),
            bridged,
            PlistKey::ALL,
            AndroidPermission::ALL,
        ) {
            return false;
        }
        rest = tail;
    }
    true
}

// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if a natively bridged web axis lacks its runtime-requested Android permission, an entitlement or background mode sits on an axis no native code serves, or an Android permission or plist key is missing from or repeated in its vocabulary [ledger #boundary]
#[allow(clippy::assertions_on_constants)] // the constant IS the tripwire
const _: () = assert!(
    permission_table_agrees(WebCapability::ALL)
        && android_permissions_agree(AndroidPermission::ALL)
        && plist_keys_agree(PlistKey::ALL),
    "the OS-permission table disagrees with BridgeCap, the Android permission vocabulary or the plist key vocabulary",
);

/// The typed, per-platform OS-permission declarations derived for an app.
///
/// Constructed only by [`derive_permissions`] from a granted-capability set, so a
/// `PermissionSet` value is always a faithful projection of consent — it cannot
/// be built with a permission the app did not accept. The stored entries are
/// de-duplicated and deterministically ordered (via `BTreeSet`), so two derivations
/// of the same accept-set render byte-identically.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PermissionSet {
    /// The platform this set was derived for; the renderers project accordingly.
    platform: Platform,
    /// The Apple `Info.plist` usage-description keys (empty on Android).
    plist: BTreeSet<PlistKey>,
    /// The Android manifest elements (empty on Apple platforms).
    android: BTreeSet<AndroidEntry>,
    /// The iOS entitlements (empty off iOS).
    ios_entitlements: BTreeSet<IosEntitlement>,
    /// The iOS `UIBackgroundModes` members (empty off iOS).
    ios_background_modes: BTreeSet<IosBackgroundMode>,
}

impl PermissionSet {
    /// The platform this set targets.
    #[must_use]
    pub const fn platform(&self) -> Platform {
        self.platform
    }

    /// Whether this set declares no OS permissions at all (a pure app, or one
    /// whose granted axes need none on this platform).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.plist.is_empty()
            && self.android.is_empty()
            && self.ios_entitlements.is_empty()
            && self.ios_background_modes.is_empty()
    }

    /// The Apple `Info.plist` key/purpose pairs, sorted and de-duplicated.
    ///
    /// Empty on [`Platform::Android`]. Every returned purpose string is non-empty
    /// (an Apple-review invariant guaranteed by the table), and no key appears
    /// twice.
    #[must_use]
    pub fn to_info_plist_entries(&self) -> Vec<(String, String)> {
        self.plist
            .iter()
            .map(|k| (k.key().to_owned(), k.purpose().to_owned()))
            .collect()
    }

    /// The iOS entitlements, sorted and de-duplicated. Empty off iOS.
    #[must_use]
    pub fn ios_entitlements(&self) -> Vec<IosEntitlement> {
        self.ios_entitlements.iter().copied().collect()
    }

    /// The iOS `UIBackgroundModes` members, sorted and de-duplicated. Empty off
    /// iOS.
    #[must_use]
    pub fn ios_background_modes(&self) -> Vec<IosBackgroundMode> {
        self.ios_background_modes.iter().copied().collect()
    }

    /// The runtime permission request rows, one per declared Android permission
    /// the shell asks for at the moment of use, sorted. Empty on the Apple
    /// platforms.
    #[must_use]
    pub fn android_runtime_requests(&self) -> Vec<RuntimeRequest> {
        self.android
            .iter()
            .filter_map(|entry| match entry {
                AndroidEntry::UsesPermission(permission) => {
                    permission
                        .runtime_request_code()
                        .map(|code| RuntimeRequest {
                            permission: *permission,
                            code,
                        })
                }
            })
            .collect()
    }

    /// The Android manifest fragment (the `<uses-permission>` / `<uses-feature>`
    /// lines), sorted, de-duplicated, and rendered as XML.
    ///
    /// Empty on the Apple platforms.
    #[must_use]
    pub fn to_android_manifest_entries(&self) -> AndroidManifestFragment {
        let lines = self
            .android
            .iter()
            .copied()
            .map(render_android_entry)
            .collect::<Vec<_>>();
        AndroidManifestFragment { lines }
    }
}

/// A rendered Android manifest fragment: the ordered `<uses-permission>` /
/// `<uses-feature>` lines a packager splices under `<manifest>`.
///
/// A typed wrapper rather than a bare `String`, so a caller cannot confuse it
/// with arbitrary text and the line list stays inspectable.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AndroidManifestFragment {
    lines: Vec<String>,
}

impl AndroidManifestFragment {
    /// The individual manifest element lines, in deterministic order.
    #[must_use]
    pub fn lines(&self) -> &[String] {
        &self.lines
    }

    /// Whether the fragment declares no elements.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }

    /// The fragment as a single newline-joined XML block (no trailing newline).
    #[must_use]
    pub fn to_xml(&self) -> String {
        self.lines.join("\n")
    }
}

/// Render one [`AndroidEntry`] to its XML manifest line. The `android:name`
/// value is a fixed constant from the closed vocabulary, never user text, so no
/// XML escaping of untrusted input is required; the constants are ASCII
/// identifiers.
fn render_android_entry(entry: AndroidEntry) -> String {
    format!(
        "<uses-permission android:name=\"{}\" />",
        android_entry_name(entry)
    )
}

/// Derive the OS-permission declarations for `platform` from the app's granted
/// capability set `accepts` — the fail-closed, deny-by-default derivation.
///
/// Only the [`Capability::JsPort`] members of `accepts` contribute: those are the
/// browser web axes a native shell must map to OS permissions. Every other
/// capability (network, filesystem, native-ffi, …) is a server/Ipê-side axis with
/// no native-shell OS-permission surface and is ignored here. Each granted web
/// axis contributes exactly the entries [`requirement_for`] assigns it on
/// `platform`; an axis that needs no permission contributes nothing. Nothing is
/// contributed for an axis the app did not accept (deny-by-default).
///
/// # Errors
/// Infallible over the closed vocabulary today — the signature returns
/// `Result<_, CliError>` so a web axis whose derivation *can* fail (an axis
/// needing a per-platform decision the app must resolve) has a channel without
/// changing this public signature.
pub fn derive_permissions(
    accepts: &BTreeSet<Capability>,
    platform: Platform,
) -> Result<PermissionSet, CliError> {
    let mut plist = BTreeSet::new();
    let mut android = BTreeSet::new();
    let mut ios_entitlements = BTreeSet::new();
    let mut ios_background_modes = BTreeSet::new();

    for cap in accepts {
        let Capability::JsPort(axis) = cap else {
            // A non-web capability has no native-shell OS-permission surface.
            continue;
        };
        let row = requirement_for(*axis);
        match platform {
            Platform::Ios => {
                plist.extend(row.apple.iter().chain(row.ios_only).copied());
                ios_entitlements.extend(row.ios_entitlements.iter().copied());
                ios_background_modes.extend(row.ios_background_modes.iter().copied());
            }
            Platform::MacOs => plist.extend(row.apple.iter().copied()),
            Platform::Android => android.extend(
                row.android
                    .iter()
                    .copied()
                    .map(AndroidEntry::UsesPermission),
            ),
        }
    }

    Ok(PermissionSet {
        platform,
        plist,
        android,
        ios_entitlements,
        ios_background_modes,
    })
}

/// The set of OS permissions the app is entitled to on `platform`, as bare
/// identifiers: Apple plist keys, iOS entitlement keys and each
/// `UIBackgroundModes` member qualified by its array key, or Android permission
/// `android:name`s.
///
/// This is the completeness anchor for the fail-closed reconciliation: a merged
/// manifest may declare only permissions in this set. Built from the same
/// derivation as [`derive_permissions`], so it can never drift from what an app
/// actually derives.
fn entitled_permission_names(
    accepts: &BTreeSet<Capability>,
    platform: Platform,
) -> Result<BTreeSet<String>, CliError> {
    let derived = derive_permissions(accepts, platform)?;
    let mut names = BTreeSet::new();
    if platform.is_apple() {
        for (key, _purpose) in derived.to_info_plist_entries() {
            names.insert(key);
        }
        for entitlement in &derived.ios_entitlements {
            names.insert(entitlement.key().to_owned());
        }
        for mode in &derived.ios_background_modes {
            names.insert(mode.qualified_name());
        }
    } else {
        for entry in &derived.android {
            names.insert(android_entry_name(*entry));
        }
    }
    Ok(names)
}

/// The qualified `android:name` identifier of an Android entry, used in the
/// rendered manifest and to reconcile an override against the entitled set.
fn android_entry_name(entry: AndroidEntry) -> String {
    match entry {
        AndroidEntry::UsesPermission(permission) => {
            format!("android.permission.{}", permission.name())
        }
    }
}

/// Reconcile an author-supplied override manifest against the app's granted
/// capabilities — the **merged ⇒ accepted** fail-closed gate.
///
/// `override_permissions` is the set of OS-permission identifiers an author
/// hand-added to the packaged manifest (plist keys on Apple, `android:name`s on
/// Android). Any of them with no backing accepted web axis is a hard refusal
/// naming exactly which permission is un-consented and how to remedy it. A
/// package can therefore never declare an OS permission the app did not accept —
/// the derivation is the single source of truth, and an override may only
/// *annotate* (e.g. a custom purpose string for) a permission the app already
/// derives, never *introduce* one.
///
/// # Errors
/// [`CliError::Usage`] carrying the `IPE-P0001` refusal when any override
/// permission has no backing accepted axis.
pub fn reconcile_override(
    accepts: &BTreeSet<Capability>,
    platform: Platform,
    override_permissions: &BTreeSet<String>,
) -> Result<(), CliError> {
    let entitled = entitled_permission_names(accepts, platform)?;
    let unbacked: Vec<&String> = override_permissions
        .iter()
        .filter(|name| !entitled.contains(*name))
        .collect();
    if unbacked.is_empty() {
        return Ok(());
    }
    Err(unbacked_permission_refusal(platform, &unbacked))
}

/// The typed, fail-closed refusal naming each override permission with no backing
/// accepted axis, and the remedy.
fn unbacked_permission_refusal(platform: Platform, unbacked: &[&String]) -> CliError {
    CliError::Usage(crate::text::Message::lines(
        std::iter::once(crate::text::msg::permission_consent_header(
            &platform.as_str(),
        ))
        .chain(
            unbacked
                .iter()
                .map(|name| crate::text::msg::consent_item(name)),
        )
        .chain(std::iter::once(
            crate::text::msg::permission_consent_remedy(),
        )),
    ))
}

/// A structured, per-axis view of a derivation for the CLI surface — which web
/// axes were granted and, for each, the OS entries it contributed on the target.
///
/// Consumed by the `ipe release build --emit-permissions` dry-run to print a legible,
/// deterministic report without the CLI reaching into the private table. On iOS
/// an axis's entries also name its entitlements and its `UIBackgroundModes`
/// members (as `UIBackgroundModes:<member>`).
#[must_use]
pub fn per_axis_breakdown(
    accepts: &BTreeSet<Capability>,
    platform: Platform,
) -> BTreeMap<&'static str, Vec<String>> {
    let mut by_axis: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();
    for cap in accepts {
        let Capability::JsPort(axis) = cap else {
            continue;
        };
        let row = requirement_for(*axis);
        let entries = match platform {
            Platform::Ios => row
                .apple
                .iter()
                .chain(row.ios_only)
                .map(|k| k.key().to_owned())
                .chain(row.ios_entitlements.iter().map(|e| e.key().to_owned()))
                .chain(
                    row.ios_background_modes
                        .iter()
                        .copied()
                        .map(IosBackgroundMode::qualified_name),
                )
                .collect(),
            Platform::MacOs => row.apple.iter().map(|k| k.key().to_owned()).collect(),
            Platform::Android => row
                .android
                .iter()
                .map(|p| android_entry_name(AndroidEntry::UsesPermission(*p)))
                .collect(),
        };
        by_axis.insert(axis.as_str(), entries);
    }
    by_axis
}

#[cfg(test)]
mod tests {
    use super::*;

    fn accepts(items: &[Capability]) -> BTreeSet<Capability> {
        items.iter().copied().collect()
    }

    fn web(axis: WebCapability) -> Capability {
        Capability::JsPort(axis)
    }

    /// A one-element permission-override set, for the fail-closed reconciliation
    /// tests.
    fn one_override(name: &str) -> BTreeSet<String> {
        std::iter::once(name.to_owned()).collect()
    }

    // ── The table is exhaustive over the closed web vocabulary ────────────────

    #[test]
    fn every_web_axis_has_a_requirement_on_every_platform() {
        // Coverage guard: iterating `WebCapability::ALL` exercises every arm of
        // the exhaustive `requirement_for` match. A new axis added to the compiler
        // without an arm here fails to compile (no wildcard); this test then also
        // pins that the derivation runs for it on all three platforms.
        for &axis in WebCapability::ALL {
            for platform in [Platform::Ios, Platform::MacOs, Platform::Android] {
                let set = derive_permissions(&accepts(&[web(axis)]), platform)
                    .expect("derivation is total");
                assert_eq!(set.platform(), platform);
            }
        }
    }

    #[test]
    fn geolocation_derives_the_expected_entries_per_platform() {
        let a = accepts(&[web(WebCapability::Geolocation)]);

        let ios = derive_permissions(&a, Platform::Ios).expect("ios");
        assert_eq!(
            ios.to_info_plist_entries(),
            vec![(
                "NSLocationWhenInUseUsageDescription".to_owned(),
                "This app uses your location to provide location-based features.".to_owned(),
            )]
        );
        assert!(ios.to_android_manifest_entries().is_empty());

        let android = derive_permissions(&a, Platform::Android).expect("android");
        assert!(android.to_info_plist_entries().is_empty());
        // The fragment lists permissions by constant name, whatever the order
        // the table or the enum declares them in.
        assert_eq!(
            android.to_android_manifest_entries().lines(),
            [
                "<uses-permission android:name=\"android.permission.ACCESS_COARSE_LOCATION\" />",
                "<uses-permission android:name=\"android.permission.ACCESS_FINE_LOCATION\" />",
            ]
        );
    }

    #[test]
    fn plist_keys_render_in_key_order() {
        // A plist lists its usage keys by key spelling, whatever the order the
        // enum declares them in.
        let a = accepts(&[
            web(WebCapability::Recorder),
            web(WebCapability::Geolocation),
        ]);
        let keys: Vec<String> = derive_permissions(&a, Platform::Ios)
            .expect("ios")
            .to_info_plist_entries()
            .into_iter()
            .map(|(key, _purpose)| key)
            .collect();
        assert_eq!(
            keys,
            [
                "NSCameraUsageDescription",
                "NSLocationWhenInUseUsageDescription",
                "NSMicrophoneUsageDescription",
            ]
        );
    }

    #[test]
    fn an_ios_file_grant_declares_the_capture_usage_keys() {
        // The iOS file picker can open the camera and the microphone in place,
        // so a File grant declares both keys there and nothing elsewhere.
        let a = accepts(&[web(WebCapability::File)]);
        let keys: Vec<String> = derive_permissions(&a, Platform::Ios)
            .expect("ios")
            .to_info_plist_entries()
            .into_iter()
            .map(|(key, _purpose)| key)
            .collect();
        assert_eq!(
            keys,
            ["NSCameraUsageDescription", "NSMicrophoneUsageDescription"]
        );
        for platform in [Platform::MacOs, Platform::Android] {
            assert!(
                derive_permissions(&a, platform).expect("derive").is_empty(),
                "a file grant declares nothing on {platform:?}"
            );
        }
    }

    #[test]
    fn apple_purpose_strings_are_non_empty() {
        // The Apple-review invariant: every derived plist key carries a non-empty
        // purpose. Exercised over every axis on both Apple platforms.
        for &axis in WebCapability::ALL {
            for platform in [Platform::Ios, Platform::MacOs] {
                let set = derive_permissions(&accepts(&[web(axis)]), platform).expect("derive");
                for (key, purpose) in set.to_info_plist_entries() {
                    assert!(
                        !purpose.is_empty(),
                        "{key} on {platform:?} has empty purpose"
                    );
                }
            }
        }
    }

    #[test]
    fn a_pure_or_non_web_app_derives_no_permissions() {
        // deny-by-default: no accepted web axis ⇒ no OS permission. Non-web
        // capabilities (network, native-ffi) never contribute.
        let a = accepts(&[Capability::Network, Capability::NativeFfi]);
        for platform in [Platform::Ios, Platform::MacOs, Platform::Android] {
            let set = derive_permissions(&a, platform).expect("derive");
            assert!(
                set.is_empty(),
                "non-web app derived a permission on {platform:?}"
            );
        }
        let empty = accepts(&[]);
        for platform in [Platform::Ios, Platform::MacOs, Platform::Android] {
            assert!(
                derive_permissions(&empty, platform)
                    .expect("derive")
                    .is_empty()
            );
        }
    }

    #[test]
    fn a_multi_axis_app_derives_exactly_those_permissions() {
        // The geo-clipboard shape: geolocation + clipboard + raw. Clipboard and
        // raw contribute nothing; geolocation contributes location.
        let a = accepts(&[
            web(WebCapability::Geolocation),
            web(WebCapability::Clipboard),
            web(WebCapability::Raw),
        ]);
        let ios = derive_permissions(&a, Platform::Ios).expect("ios");
        assert_eq!(
            ios.to_info_plist_entries(),
            vec![(
                "NSLocationWhenInUseUsageDescription".to_owned(),
                "This app uses your location to provide location-based features.".to_owned(),
            )]
        );
        let android = derive_permissions(&a, Platform::Android).expect("android");
        let names: BTreeSet<String> = android
            .to_android_manifest_entries()
            .lines()
            .iter()
            .cloned()
            .collect();
        // Only the two location permissions; clipboard/raw add nothing.
        assert_eq!(names.len(), 2, "unexpected android entries: {names:?}");
    }

    #[test]
    fn derivation_is_deterministic() {
        // Two derivations of the same accept-set render byte-identically.
        let a = accepts(&[
            web(WebCapability::Geolocation),
            web(WebCapability::Notification),
            web(WebCapability::Vibration),
        ]);
        let first = derive_permissions(&a, Platform::Android).expect("first");
        let second = derive_permissions(&a, Platform::Android).expect("second");
        assert_eq!(
            first.to_android_manifest_entries(),
            second.to_android_manifest_entries()
        );
    }

    // ── Fail-closed: accepted ⇒ merged (completeness) ─────────────────────────

    #[test]
    fn accepted_axis_appears_in_the_derived_manifest() {
        // Completeness: a granted axis with an OS requirement MUST surface in the
        // entitled set the reconciler accepts.
        let a = accepts(&[web(WebCapability::Geolocation)]);
        let entitled_android = entitled_permission_names(&a, Platform::Android).expect("android");
        assert!(entitled_android.contains("android.permission.ACCESS_FINE_LOCATION"));
        let entitled_ios = entitled_permission_names(&a, Platform::Ios).expect("ios");
        assert!(entitled_ios.contains("NSLocationWhenInUseUsageDescription"));
    }

    #[test]
    fn a_backed_override_is_accepted() {
        // An override that only names permissions the app derives is accepted —
        // the author may annotate (e.g. a custom purpose) a derived permission.
        let a = accepts(&[web(WebCapability::Geolocation)]);
        let over = one_override("NSLocationWhenInUseUsageDescription");
        reconcile_override(&a, Platform::Ios, &over).expect("a backed override is accepted");
    }

    // ── Fail-closed: merged ⇒ accepted (the pinned security refusal) ──────────

    #[test]
    fn an_unbacked_camera_override_is_refused_naming_it() {
        // THE security property. An author hand-adds NSCameraUsageDescription to
        // the packaged Apple manifest, but the app accepted no camera-reaching
        // axis. This MUST be a hard,
        // typed refusal naming the smuggled permission — a package can never
        // declare an OS permission with no backing consent.
        let a = accepts(&[web(WebCapability::Geolocation)]);
        let over = one_override("NSCameraUsageDescription");
        let err = reconcile_override(&a, Platform::Ios, &over)
            .expect_err("an unbacked camera permission must be refused");
        let msg = err.to_string();
        assert!(msg.contains("IPE-P0001"), "carries the code: {msg}");
        assert!(
            msg.contains("NSCameraUsageDescription"),
            "names the smuggled permission: {msg}"
        );
    }

    #[test]
    fn an_unbacked_android_camera_permission_is_refused() {
        // The Android face of the same property: a hand-added CAMERA permission
        // with no accepted backing axis is refused naming it.
        let a = accepts(&[web(WebCapability::Geolocation)]);
        let over = one_override("android.permission.CAMERA");
        let err = reconcile_override(&a, Platform::Android, &over)
            .expect_err("an unbacked android camera permission must be refused");
        assert!(err.to_string().contains("android.permission.CAMERA"));
    }

    #[test]
    fn microphone_derives_ns_microphone_usage_description_and_record_audio() {
        // The microphone permission axis must derive:
        //   iOS / macOS → NSMicrophoneUsageDescription (non-empty purpose)
        //   Android     → android.permission.RECORD_AUDIO
        let a = accepts(&[web(WebCapability::Microphone)]);

        let ios = derive_permissions(&a, Platform::Ios).expect("ios");
        let ios_entries = ios.to_info_plist_entries();
        assert_eq!(
            ios_entries.len(),
            1,
            "exactly one plist entry for microphone on iOS"
        );
        // Use pattern-match destructuring to avoid clippy::indexing-slicing.
        if let Some((key, purpose)) = ios_entries.first() {
            assert_eq!(
                key, "NSMicrophoneUsageDescription",
                "iOS plist key must be NSMicrophoneUsageDescription"
            );
            assert!(
                !purpose.is_empty(),
                "iOS microphone purpose string must be non-empty"
            );
        }
        assert!(ios.to_android_manifest_entries().is_empty());

        let macos = derive_permissions(&a, Platform::MacOs).expect("macos");
        let macos_entries = macos.to_info_plist_entries();
        assert_eq!(
            macos_entries.len(),
            1,
            "exactly one plist entry for microphone on macOS"
        );
        if let Some((key, purpose)) = macos_entries.first() {
            assert_eq!(
                key, "NSMicrophoneUsageDescription",
                "macOS plist key must be NSMicrophoneUsageDescription"
            );
            assert!(
                !purpose.is_empty(),
                "macOS microphone purpose string must be non-empty"
            );
        }

        let android = derive_permissions(&a, Platform::Android).expect("android");
        assert!(android.to_info_plist_entries().is_empty());
        let xml = android.to_android_manifest_entries().to_xml();
        assert!(
            xml.contains("android.permission.RECORD_AUDIO"),
            "Android must declare RECORD_AUDIO for microphone: {xml}"
        );
    }

    #[test]
    fn recorder_derives_camera_and_microphone_on_every_platform() {
        // Media recording reaches BOTH the camera and the microphone through
        // getUserMedia, so it must derive:
        //   iOS / macOS → NSCameraUsageDescription + NSMicrophoneUsageDescription
        //                 (both with non-empty purpose)
        //   Android     → android.permission.CAMERA + android.permission.RECORD_AUDIO
        let a = accepts(&[web(WebCapability::Recorder)]);

        for platform in [Platform::Ios, Platform::MacOs] {
            let apple = derive_permissions(&a, platform).expect("apple");
            let keys: BTreeSet<String> = apple
                .to_info_plist_entries()
                .into_iter()
                .map(|(k, purpose)| {
                    assert!(!purpose.is_empty(), "{k} on {platform:?} has empty purpose");
                    k
                })
                .collect();
            assert!(
                keys.contains("NSCameraUsageDescription"),
                "recorder must declare NSCameraUsageDescription on {platform:?}: {keys:?}"
            );
            assert!(
                keys.contains("NSMicrophoneUsageDescription"),
                "recorder must declare NSMicrophoneUsageDescription on {platform:?}: {keys:?}"
            );
            assert!(apple.to_android_manifest_entries().is_empty());
        }

        let android = derive_permissions(&a, Platform::Android).expect("android");
        assert!(android.to_info_plist_entries().is_empty());
        let xml = android.to_android_manifest_entries().to_xml();
        assert!(
            xml.contains("android.permission.CAMERA"),
            "recorder must declare CAMERA on Android: {xml}"
        );
        assert!(
            xml.contains("android.permission.RECORD_AUDIO"),
            "recorder must declare RECORD_AUDIO on Android: {xml}"
        );
    }

    #[test]
    fn a_recorder_grant_backs_its_camera_and_mic_overrides() {
        // The completeness face: a recorder grant entitles both getUserMedia
        // usage keys, so an override naming either is accepted rather than refused.
        let a = accepts(&[web(WebCapability::Recorder)]);
        reconcile_override(&a, Platform::Ios, &one_override("NSCameraUsageDescription"))
            .expect("recorder backs the camera usage key");
        reconcile_override(
            &a,
            Platform::Ios,
            &one_override("NSMicrophoneUsageDescription"),
        )
        .expect("recorder backs the microphone usage key");
        reconcile_override(
            &a,
            Platform::Android,
            &one_override("android.permission.CAMERA"),
        )
        .expect("recorder backs the android CAMERA permission");
    }

    #[test]
    fn an_ios_camera_grant_declares_and_backs_the_camera_usage_key() {
        // iOS terminates an app that opens the camera without the camera usage
        // key, and the capture element opens the camera there, so a Camera grant
        // declares the key on iOS and backs an override naming it.
        let a = accepts(&[web(WebCapability::Camera)]);
        let ios = derive_permissions(&a, Platform::Ios).expect("ios");
        assert_eq!(
            ios.to_info_plist_entries(),
            vec![(
                "NSCameraUsageDescription".to_owned(),
                PlistKey::Camera.purpose().to_owned(),
            )]
        );
        reconcile_override(&a, Platform::Ios, &one_override("NSCameraUsageDescription"))
            .expect("an iOS camera grant backs the camera usage key");
    }

    #[test]
    fn a_macos_camera_grant_does_not_back_the_camera_usage_key() {
        // On macOS the capture element opens a file picker, never the camera, so
        // a Camera grant declares no key there and an override naming the camera
        // key is refused — only the getUserMedia Recorder axis backs it.
        let a = accepts(&[web(WebCapability::Camera)]);
        assert!(
            derive_permissions(&a, Platform::MacOs)
                .expect("macos")
                .is_empty()
        );
        let err = reconcile_override(
            &a,
            Platform::MacOs,
            &one_override("NSCameraUsageDescription"),
        )
        .expect_err("a macOS capture-element grant does not back the camera usage key");
        assert!(err.to_string().contains("NSCameraUsageDescription"));
        // The control: the getUserMedia Recorder grant backs it on macOS.
        reconcile_override(
            &accepts(&[web(WebCapability::Recorder)]),
            Platform::MacOs,
            &one_override("NSCameraUsageDescription"),
        )
        .expect("a recorder grant backs the camera usage key on macOS");
    }

    #[test]
    fn a_camera_grant_adds_no_android_permission() {
        let a = accepts(&[web(WebCapability::Camera)]);
        assert!(
            derive_permissions(&a, Platform::Android)
                .expect("android")
                .is_empty()
        );
    }

    #[test]
    fn axes_sharing_a_surface_declare_its_usage_key_once() {
        // Camera, Recorder and Microphone reach overlapping surfaces; a plist
        // must never hold one key twice, whatever mix of them is granted.
        let a = accepts(&[
            web(WebCapability::Camera),
            web(WebCapability::Recorder),
            web(WebCapability::Microphone),
        ]);
        let keys: Vec<String> = derive_permissions(&a, Platform::Ios)
            .expect("ios")
            .to_info_plist_entries()
            .into_iter()
            .map(|(key, _purpose)| key)
            .collect();
        assert_eq!(
            keys,
            vec![
                "NSCameraUsageDescription".to_owned(),
                "NSMicrophoneUsageDescription".to_owned(),
            ]
        );
    }

    // ── Push ──────────────────────────────────────────────────────────────────

    #[test]
    fn push_derives_its_entitlement_background_mode_and_notification_permission() {
        let a = accepts(&[web(WebCapability::Push)]);

        let ios = derive_permissions(&a, Platform::Ios).expect("ios");
        assert_eq!(ios.ios_entitlements(), vec![IosEntitlement::ApsEnvironment]);
        assert_eq!(
            ios.ios_background_modes(),
            vec![IosBackgroundMode::RemoteNotification]
        );
        assert!(ios.to_info_plist_entries().is_empty());
        assert!(ios.to_android_manifest_entries().is_empty());

        let macos = derive_permissions(&a, Platform::MacOs).expect("macos");
        assert!(
            macos.is_empty(),
            "push declares nothing on macOS: {macos:?}"
        );

        let android = derive_permissions(&a, Platform::Android).expect("android");
        assert_eq!(
            android.to_android_manifest_entries().to_xml(),
            "<uses-permission android:name=\"android.permission.POST_NOTIFICATIONS\" />"
        );
        assert!(android.ios_entitlements().is_empty());
        assert!(android.ios_background_modes().is_empty());
    }

    #[test]
    fn without_push_no_push_declaration_is_derived() {
        // Deny by default: the local-notification axis alone must not pull in the
        // push entitlement or background mode.
        let a = accepts(&[web(WebCapability::Notification)]);
        let ios = derive_permissions(&a, Platform::Ios).expect("ios");
        assert!(
            ios.is_empty(),
            "notification declares nothing on iOS: {ios:?}"
        );
        // The control: Push does.
        let with_push =
            derive_permissions(&accepts(&[web(WebCapability::Push)]), Platform::Ios).expect("ios");
        assert!(!with_push.ios_entitlements().is_empty());
    }

    #[test]
    fn push_backs_its_entitlement_and_background_mode_and_nothing_else_does() {
        let push = accepts(&[web(WebCapability::Push)]);
        let mode = IosBackgroundMode::RemoteNotification.qualified_name();
        assert_eq!(mode, "UIBackgroundModes:remote-notification");
        for name in ["aps-environment", mode.as_str()] {
            reconcile_override(&push, Platform::Ios, &one_override(name))
                .expect("a push grant backs its iOS declarations");
            let err = reconcile_override(
                &accepts(&[web(WebCapability::Notification)]),
                Platform::Ios,
                &one_override(name),
            )
            .expect_err("a notification grant does not back a push declaration");
            assert!(err.to_string().contains(name), "names {name}: {err}");
        }
    }

    #[test]
    fn a_bare_background_modes_override_is_refused_even_with_push() {
        // The bare array key would stand for every background mode; a push grant
        // entitles only its own member, so the bare key and any other member
        // are refused.
        let push = accepts(&[web(WebCapability::Push)]);
        for name in [UI_BACKGROUND_MODES_KEY, "UIBackgroundModes:audio"] {
            let err = reconcile_override(&push, Platform::Ios, &one_override(name))
                .expect_err("a push grant backs only its own background mode");
            assert!(err.to_string().contains(name), "names {name}: {err}");
        }
    }

    // ── Runtime request rows ──────────────────────────────────────────────────

    #[test]
    fn runtime_request_rows_cover_exactly_the_runtime_requested_permissions() {
        let a = accepts(&[
            web(WebCapability::Geolocation),
            web(WebCapability::Vibration),
            web(WebCapability::Push),
        ]);
        let android = derive_permissions(&a, Platform::Android).expect("android");
        let rows: Vec<(AndroidPermission, u16)> = android
            .android_runtime_requests()
            .into_iter()
            .map(|row| (row.permission, row.code.get()))
            .collect();
        // VIBRATE is install-time, so it has no request row. Rows follow the
        // rendered name order; each code is the permission's position among
        // the runtime-requested ones.
        assert_eq!(
            rows,
            vec![
                (AndroidPermission::AccessCoarseLocation, 2),
                (AndroidPermission::AccessFineLocation, 1),
                (AndroidPermission::PostNotifications, 3),
            ]
        );
        assert!(
            derive_permissions(&a, Platform::Ios)
                .expect("ios")
                .android_runtime_requests()
                .is_empty()
        );
    }

    #[test]
    fn the_android_permission_agreement_check_refuses_a_duplicate() {
        // The build-time check is live: the real vocabulary passes, and a list
        // naming one permission twice is refused.
        assert!(android_permissions_agree(AndroidPermission::ALL));
        assert!(!android_permissions_agree(&[
            AndroidPermission::Camera,
            AndroidPermission::Camera,
        ]));
        assert!(permission_table_agrees(WebCapability::ALL));
    }

    #[test]
    fn the_plist_key_agreement_check_refuses_a_duplicate() {
        assert!(plist_keys_agree(PlistKey::ALL));
        assert!(!plist_keys_agree(&[PlistKey::Camera, PlistKey::Camera]));
    }

    #[test]
    fn runtime_request_codes_are_distinct_and_absent_for_install_time_permissions() {
        let mut seen = BTreeSet::new();
        for &permission in AndroidPermission::ALL {
            match permission.runtime_request_code() {
                Some(code) => {
                    assert!(permission.is_runtime_requested(), "{permission:?}");
                    assert!(seen.insert(code.get()), "{permission:?} repeats a code");
                }
                None => assert!(!permission.is_runtime_requested(), "{permission:?}"),
            }
        }
        assert_eq!(
            AndroidPermission::ALL
                .iter()
                .copied()
                .filter_map(AndroidPermission::runtime_request_code)
                .map(RequestCode::get)
                .collect::<Vec<_>>(),
            [1, 2, 3, 4, 5]
        );
    }

    /// One synthetic table row, for driving each refusal of [`row_agrees`].
    const fn row(
        apple: &'static [PlistKey],
        android: &'static [AndroidPermission],
        ios_entitlements: &'static [IosEntitlement],
        ios_background_modes: &'static [IosBackgroundMode],
    ) -> AxisRequirement {
        AxisRequirement {
            apple,
            android,
            ios_entitlements,
            ios_background_modes,
            ..NO_OS_PERMISSION
        }
    }

    #[test]
    fn the_row_agreement_check_refuses_each_disagreement() {
        let keys = PlistKey::ALL;
        let all = AndroidPermission::ALL;
        let camera: &[PlistKey] = &[PlistKey::Camera];
        let post: &[AndroidPermission] = &[AndroidPermission::PostNotifications];
        let vibrate: &[AndroidPermission] = &[AndroidPermission::Vibrate];
        let aps: &[IosEntitlement] = &[IosEntitlement::ApsEnvironment];
        let remote: &[IosBackgroundMode] = &[IosBackgroundMode::RemoteNotification];
        // Controls: a bridged row with a runtime permission and native-only
        // entries, and an unbridged row with a plist key and an install-time
        // permission.
        assert!(row_agrees(&row(&[], post, aps, remote), true, keys, all));
        assert!(row_agrees(
            &row(camera, vibrate, &[], &[]),
            false,
            keys,
            all
        ));
        // A bridged row with no Android permission.
        assert!(!row_agrees(&row(&[], &[], aps, remote), true, keys, all));
        // An entitlement or a background mode on an unbridged row.
        assert!(!row_agrees(&row(&[], post, aps, &[]), false, keys, all));
        assert!(!row_agrees(&row(&[], post, &[], remote), false, keys, all));
        // A bridged row naming an install-time permission.
        assert!(!row_agrees(&row(&[], vibrate, &[], &[]), true, keys, all));
        // A permission or a plist key missing from its vocabulary.
        let only_camera: &[AndroidPermission] = &[AndroidPermission::Camera];
        assert!(!row_agrees(
            &row(&[], post, &[], &[]),
            false,
            keys,
            only_camera
        ));
        let only_microphone: &[PlistKey] = &[PlistKey::Microphone];
        assert!(!row_agrees(
            &row(camera, &[], &[], &[]),
            false,
            only_microphone,
            all
        ));
    }

    #[test]
    fn requirement_for_has_no_wildcard_arm() {
        // The permission table is exhaustive by construction; a `_` arm would let
        // a new web axis ship with no permission decision.
        let source = include_str!("permissions.rs");
        let body = source
            .split_once("const fn requirement_for(")
            .and_then(|(_, rest)| rest.split_once("\n}\n"))
            .map(|(body, _)| body);
        assert!(body.is_some(), "requirement_for found in its source");
        let wildcard = ["_", " =>"].concat();
        assert!(
            body.is_some_and(|b| !b.contains(&wildcard)),
            "requirement_for must not carry a wildcard arm"
        );
    }

    #[test]
    fn a_microphone_grant_does_not_back_an_unbacked_permission() {
        // A microphone grant does not entitle an unrelated permission such as
        // NSLocationWhenInUseUsageDescription — the permission is per-axis, not a
        // wildcard grant.
        let a = accepts(&[web(WebCapability::Microphone)]);
        let over = one_override("NSLocationWhenInUseUsageDescription");
        let err = reconcile_override(&a, Platform::Ios, &over)
            .expect_err("a microphone grant must not back a location permission");
        let msg = err.to_string();
        assert!(
            msg.contains("NSLocationWhenInUseUsageDescription"),
            "refusal names the smuggled key: {msg}"
        );
    }

    #[test]
    fn a_clipboard_grant_does_not_back_a_location_permission() {
        // A granted axis does not entitle a *different* axis's permission: the
        // grant is per-axis, so a clipboard grant cannot back a location key.
        let a = accepts(&[web(WebCapability::Clipboard)]);
        let over = one_override("NSLocationWhenInUseUsageDescription");
        let err = reconcile_override(&a, Platform::Ios, &over)
            .expect_err("a clipboard grant does not back a location permission");
        assert!(
            err.to_string()
                .contains("NSLocationWhenInUseUsageDescription")
        );
    }

    // ── Platform parsing ──────────────────────────────────────────────────────

    #[test]
    fn platform_round_trips_its_wire_name() {
        for platform in [Platform::Ios, Platform::MacOs, Platform::Android] {
            assert_eq!(platform.as_str().parse::<Platform>(), Ok(platform));
        }
    }

    #[test]
    fn an_unknown_platform_is_rejected() {
        assert_eq!(
            "windows".parse::<Platform>(),
            Err(UnknownPlatform("windows".to_owned()))
        );
    }

    // ── End-to-end on the real geo-clipboard fixture ──────────────────────────

    #[test]
    fn geo_clipboard_fixture_derives_the_expected_permissions_end_to_end() {
        // The derivation runs from a real project's `package.ipe` through the
        // actual manifest reader — proving the accept-set the reader produces is
        // exactly the input `derive_permissions` consumes. `geo-clipboard`
        // accepts `JsPort Geolocation`, `JsPort Clipboard`, `JsPort Raw`; only
        // geolocation carries an OS permission.
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/shapes/web/geo-clipboard/package.ipe");
        let manifest = crate::project::parse_manifest(&fixture)
            .expect("the geo-clipboard fixture manifest must parse");
        let accepts = &manifest.capabilities_accept;

        let ios = derive_permissions(accepts, Platform::Ios).expect("ios");
        assert_eq!(
            ios.to_info_plist_entries(),
            vec![(
                "NSLocationWhenInUseUsageDescription".to_owned(),
                "This app uses your location to provide location-based features.".to_owned(),
            )],
            "geo-clipboard on iOS declares exactly the location usage key"
        );

        let android = derive_permissions(accepts, Platform::Android).expect("android");
        let names: BTreeSet<String> = android
            .to_android_manifest_entries()
            .lines()
            .iter()
            .cloned()
            .collect();
        assert!(
            names
                .iter()
                .any(|l| l.contains("android.permission.ACCESS_FINE_LOCATION")),
            "geo-clipboard on Android declares fine location: {names:?}"
        );
        assert_eq!(
            names.len(),
            2,
            "only the two location permissions; clipboard/raw add nothing: {names:?}"
        );
    }
}
