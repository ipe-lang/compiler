//! The frame origins a program trusts, and what a trusted frame may be given.
//!
//! [`DELEGATION_FEATURES`] is the one table of permission features a frame may
//! be delegated, each with its [`FeatureClass`]; the `allow` attribute parser
//! ([`Delegation::parse`]) and the served `Permissions-Policy` read it, and a
//! build-time check ties it to the header's vocabulary. [`try_register`] takes the
//! manifest's origins and the app's granted web-capability suffixes, re-parses
//! every origin, and holds the result as the program's one [`FramePolicy`]; a
//! program that never registers holds [`FramePolicy::none`].

use std::sync::OnceLock;

use crate::inbound_authority::Authority;
#[cfg(feature = "encoding")]
use crate::inbound_authority::AuthorityHost;

#[cfg(feature = "encoding")]
pub use crate::encoding::FRAME_HEADER_BUDGET;
#[cfg(feature = "encoding")]
use crate::encoding::{
    FRAME_LIST_FIXED_COST, FRAME_UNDISCLOSED_FIXED_COST, FRAME_WIDENED_DIRECTIVES, FrameOrigin,
    FrameOriginRefusal, FrameOrigins, FrameOriginsRefusal, frame_header_cost,
};

/// A web-capability suffix that opens a capability-gated feature.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GrantSuffix {
    /// `camera`.
    Camera,
    /// `geolocation`.
    Geolocation,
    /// `microphone`.
    Microphone,
    /// `recorder`: camera and microphone through one capture.
    Recorder,
}

impl GrantSuffix {
    /// Every suffix, in order.
    pub const ALL: [Self; 4] = [
        Self::Camera,
        Self::Geolocation,
        Self::Microphone,
        Self::Recorder,
    ];

    /// The suffix as the capability names it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Camera => "camera",
            Self::Geolocation => "geolocation",
            Self::Microphone => "microphone",
            Self::Recorder => "recorder",
        }
    }

    /// The suffix `text` names, or `None` for any other text.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|suffix| suffix.as_str() == text)
    }

    /// The bit of this suffix in a [`FrameGrants`].
    const fn bit(self) -> u8 {
        match self {
            Self::Camera => 1,
            Self::Geolocation => 1 << 1,
            Self::Microphone => 1 << 2,
            Self::Recorder => 1 << 3,
        }
    }

    /// The capability-gated features this suffix opens, in table order.
    pub fn features(self) -> impl Iterator<Item = &'static str> {
        DELEGATION_FEATURES
            .iter()
            .filter_map(move |row| match row.class {
                FeatureClass::Gated(suffixes) if suffixes.contains(&self) => Some(row.name),
                FeatureClass::Gated(_)
                | FeatureClass::Plain
                | FeatureClass::Undisclosed
                | FeatureClass::Never => None,
            })
    }
}

/// The granted web-capability suffixes a frame verdict reads: a set over
/// [`GrantSuffix`], so a suffix outside that vocabulary has no representation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct FrameGrants(u8);

impl FrameGrants {
    /// No grant.
    #[must_use]
    pub const fn none() -> Self {
        Self(0)
    }

    /// The suffixes among `granted` the vocabulary names; every other text is
    /// dropped.
    #[must_use]
    pub fn from_suffixes(granted: &[&str]) -> Self {
        Self(
            granted
                .iter()
                .filter_map(|text| GrantSuffix::parse(text))
                .fold(0, |bits, suffix| bits | suffix.bit()),
        )
    }

    /// Whether `suffix` is granted.
    #[must_use]
    pub const fn holds(self, suffix: GrantSuffix) -> bool {
        self.0 & suffix.bit() != 0
    }

    /// Whether any of `suffixes` is granted.
    #[must_use]
    pub const fn holds_any(self, mut suffixes: &[GrantSuffix]) -> bool {
        while let [suffix, rest @ ..] = suffixes {
            if self.holds(*suffix) {
                return true;
            }
            suffixes = rest;
        }
        false
    }

    /// The granted suffixes, in order.
    pub fn suffixes(self) -> impl Iterator<Item = GrantSuffix> {
        GrantSuffix::ALL
            .into_iter()
            .filter(move |suffix| self.holds(*suffix))
    }
}

/// How a feature of [`DELEGATION_FEATURES`] may be delegated to a trusted frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeatureClass {
    /// Delegated when the author writes it.
    Plain,
    /// Delegated only when the app holds one of these web capabilities: the
    /// `Permissions-Policy` directives a capability opens.
    Gated(&'static [GrantSuffix]),
    /// Delegated when the author writes it, though no capability names it;
    /// the capability notice lists these rows.
    Undisclosed,
    /// Never delegated: the served `Permissions-Policy` denies it to every
    /// document.
    Never,
}

/// One row of [`DELEGATION_FEATURES`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DelegationFeature {
    /// The `allow` and `Permissions-Policy` feature name.
    pub name: &'static str,
    /// The feature as the capability notice names it to a user.
    pub display: &'static str,
    /// How the feature may be delegated.
    pub class: FeatureClass,
}

/// Shorthand for one table row.
const fn row(name: &'static str, display: &'static str, class: FeatureClass) -> DelegationFeature {
    DelegationFeature {
        name,
        display,
        class,
    }
}

/// Every permission feature a trusted frame may be delegated, sorted by name.
///
/// Closed: a name outside it is never delegated, so a feature a browser adds
/// later waits for a reviewed row and class. Names are matched by exact bytes
/// and never case-folded: the browser's identifiers are lowercase, and a
/// folded match would delegate a feature the browser itself ignores in the
/// author's spelling.
pub const DELEGATION_FEATURES: &[DelegationFeature] = &[
    row("accelerometer", "Accelerometer", FeatureClass::Undisclosed),
    row(
        "ambient-light-sensor",
        "Ambient light sensor",
        FeatureClass::Undisclosed,
    ),
    row("autoplay", "Autoplay", FeatureClass::Plain),
    row("bluetooth", "Bluetooth devices", FeatureClass::Undisclosed),
    row(
        "camera",
        "Camera",
        FeatureClass::Gated(&[GrantSuffix::Camera, GrantSuffix::Recorder]),
    ),
    row(
        "clipboard-read",
        "Clipboard reading",
        FeatureClass::Undisclosed,
    ),
    row("clipboard-write", "Clipboard writing", FeatureClass::Plain),
    row(
        "compute-pressure",
        "Compute pressure",
        FeatureClass::Undisclosed,
    ),
    row(
        "display-capture",
        "Screen capture",
        FeatureClass::Undisclosed,
    ),
    row("encrypted-media", "Encrypted media", FeatureClass::Plain),
    row("fullscreen", "Fullscreen", FeatureClass::Plain),
    row("gamepad", "Gamepads", FeatureClass::Plain),
    row(
        "geolocation",
        "Geolocation",
        FeatureClass::Gated(&[GrantSuffix::Geolocation]),
    ),
    row("gyroscope", "Gyroscope", FeatureClass::Undisclosed),
    row("hid", "HID devices", FeatureClass::Undisclosed),
    row(
        "identity-credentials-get",
        "Federated sign-in",
        FeatureClass::Undisclosed,
    ),
    row(
        "idle-detection",
        "Idle detection",
        FeatureClass::Undisclosed,
    ),
    row("local-fonts", "Local fonts", FeatureClass::Undisclosed),
    row("magnetometer", "Magnetometer", FeatureClass::Undisclosed),
    row(
        "microphone",
        "Microphone",
        FeatureClass::Gated(&[GrantSuffix::Microphone, GrantSuffix::Recorder]),
    ),
    row("midi", "MIDI devices", FeatureClass::Undisclosed),
    row(
        "otp-credentials",
        "One-time codes",
        FeatureClass::Undisclosed,
    ),
    row("payment", "Payments", FeatureClass::Never),
    row(
        "picture-in-picture",
        "Picture-in-picture",
        FeatureClass::Plain,
    ),
    row(
        "publickey-credentials-create",
        "Passkey creation",
        FeatureClass::Undisclosed,
    ),
    row(
        "publickey-credentials-get",
        "Passkey sign-in",
        FeatureClass::Undisclosed,
    ),
    row("screen-wake-lock", "Screen wake lock", FeatureClass::Plain),
    row("serial", "Serial ports", FeatureClass::Undisclosed),
    row(
        "storage-access",
        "Storage access",
        FeatureClass::Undisclosed,
    ),
    row("usb", "USB devices", FeatureClass::Undisclosed),
    row("web-share", "Sharing", FeatureClass::Plain),
    row(
        "window-management",
        "Window management",
        FeatureClass::Undisclosed,
    ),
    row(
        "xr-spatial-tracking",
        "XR spatial tracking",
        FeatureClass::Undisclosed,
    ),
];

/// The most rows a delegation table holds: one bit of a `u64` each.
const MAX_TABLE_ROWS: usize = 64;

/// The one feature no frame is ever delegated.
const NEVER_FEATURE: &str = "payment";

/// Whether two byte strings are equal, in a `const` context.
const fn bytes_eq(mut a: &[u8], mut b: &[u8]) -> bool {
    loop {
        match (a, b) {
            ([], []) => return true,
            ([x, xs @ ..], [y, ys @ ..]) if *x == *y => {
                a = xs;
                b = ys;
            }
            _ => return false,
        }
    }
}

/// Whether `a` sorts strictly before `b`, bytewise.
const fn bytes_lt(mut a: &[u8], mut b: &[u8]) -> bool {
    loop {
        match (a, b) {
            (_, []) => return false,
            ([], [_, ..]) => return true,
            ([x, xs @ ..], [y, ys @ ..]) => {
                if *x != *y {
                    return *x < *y;
                }
                a = xs;
                b = ys;
            }
        }
    }
}

/// Whether `name` lexes as an `allow` feature: one or more of `[a-z0-9-]`.
const fn lexes_as_feature(mut name: &[u8]) -> bool {
    if name.is_empty() {
        return false;
    }
    while let [b, rest @ ..] = name {
        if !matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-') {
            return false;
        }
        name = rest;
    }
    true
}

/// Whether `rows` is a delegation table: at most 64 rows (one bit each),
/// names that lex as features in strictly ascending order (so unique), a
/// display name on every row, a suffix on every gated row, and
/// [`NEVER_FEATURE`] as the one `Never` row. One pass over the rows.
#[must_use]
pub const fn table_is_well_formed(mut rows: &[DelegationFeature]) -> bool {
    if rows.len() > MAX_TABLE_ROWS {
        return false;
    }
    let mut previous: &[u8] = &[];
    let mut never_rows = 0usize;
    while let [row, rest @ ..] = rows {
        let name = row.name.as_bytes();
        if !lexes_as_feature(name) || !bytes_lt(previous, name) || row.display.is_empty() {
            return false;
        }
        match row.class {
            FeatureClass::Never => {
                if !bytes_eq(name, NEVER_FEATURE.as_bytes()) {
                    return false;
                }
                never_rows += 1;
            }
            FeatureClass::Gated(suffixes) => {
                if suffixes.is_empty() {
                    return false;
                }
            }
            FeatureClass::Plain | FeatureClass::Undisclosed => {}
        }
        previous = name;
        rows = rest;
    }
    never_rows == 1
}

// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if the delegation table loses its shape [ledger #boundary]
const _: () = assert!(table_is_well_formed(DELEGATION_FEATURES));

/// The bit of `name` in a set over `directives`, or `0` when it is absent.
const fn directive_bit(mut directives: &[&str], name: &str) -> u64 {
    let mut bit = 1u64;
    while let [directive, rest @ ..] = directives {
        if bytes_eq(directive.as_bytes(), name.as_bytes()) {
            return bit;
        }
        bit = bit.wrapping_shl(1);
        directives = rest;
    }
    0
}

/// Whether `policy_directives`, the served `Permissions-Policy` vocabulary,
/// is exactly the table's `Gated` and `Never` rows: every such row is a
/// directive, every directive is such a row, and no `Plain` or
/// `Undisclosed` row is one. One pass over the rows.
#[must_use]
pub const fn agrees_with_header(policy_directives: &[&str]) -> bool {
    if policy_directives.len() >= MAX_TABLE_ROWS {
        return false;
    }
    let mut all = 0u64;
    let mut bit = 1u64;
    let mut rest = policy_directives;
    while let [_, tail @ ..] = rest {
        all |= bit;
        bit = bit.wrapping_shl(1);
        rest = tail;
    }
    let mut matched = 0u64;
    let mut rows = DELEGATION_FEATURES;
    while let [row, tail @ ..] = rows {
        let found = directive_bit(policy_directives, row.name);
        match row.class {
            FeatureClass::Gated(_) | FeatureClass::Never => {
                if found == 0 {
                    return false;
                }
                matched |= found;
            }
            FeatureClass::Plain | FeatureClass::Undisclosed => {
                if found != 0 {
                    return false;
                }
            }
        }
        rows = tail;
    }
    matched == all
}

/// The number of rows the served `Permissions-Policy` widens to the listed
/// origins: the `Gated` and `Undisclosed` rows.
#[cfg(feature = "encoding")]
const fn widened_rows(mut rows: &[DelegationFeature]) -> usize {
    let mut count = 0usize;
    while let [row, rest @ ..] = rows {
        if matches!(
            row.class,
            FeatureClass::Gated(_) | FeatureClass::Undisclosed
        ) {
            count += 1;
        }
        rows = rest;
    }
    count
}

/// The header bytes the `Undisclosed` rows add for a non-empty list, each
/// written as `, <feature>=(self)`.
#[cfg(feature = "encoding")]
const fn undisclosed_fixed_cost(mut rows: &[DelegationFeature]) -> usize {
    let mut cost = 0usize;
    while let [row, rest @ ..] = rows {
        if matches!(row.class, FeatureClass::Undisclosed) {
            cost += ", =(self)".len() + row.name.len();
        }
        rows = rest;
    }
    cost
}

// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if the header-cost constants drift from the delegation table [ledger #boundary]
#[cfg(feature = "encoding")]
const _: () = assert!(
    widened_rows(DELEGATION_FEATURES) == FRAME_WIDENED_DIRECTIVES
        && undisclosed_fixed_cost(DELEGATION_FEATURES) == FRAME_UNDISCLOSED_FIXED_COST
        && undisclosed_fixed_cost(DELEGATION_FEATURES) - 2 * ("'self'".len() + 1)
            == FRAME_LIST_FIXED_COST
);

/// The header bytes a list of trusted origins adds to a served page's
/// `Content-Security-Policy` and `Permissions-Policy`, in the worst case
/// (every capability-gated directive granted).
#[cfg(feature = "encoding")]
#[must_use]
pub fn header_cost(origins: &[FrameOrigin]) -> usize {
    frame_header_cost(origins.iter().map(FrameOrigin::written_len))
}

/// The longest `allow` value the parser reads; a longer one is dropped whole.
pub const MAX_ALLOW_LEN: usize = 1024;

/// The most `;`-separated directives an `allow` value holds; more drops the
/// value whole.
pub const MAX_ALLOW_DIRECTIVES: usize = 64;

/// The one allowlist token a delegated feature may carry besides the frame's
/// own origin.
const SRC_TOKEN: &str = "'src'";

/// Whether `c` is `allow` whitespace: tab, line feed, form feed, carriage
/// return or space.
const fn is_allow_ws(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\u{c}' | '\r' | ' ')
}

/// The bit of the table row named `name`, with its row.
fn feature(name: &str) -> Option<(u64, &'static DelegationFeature)> {
    DELEGATION_FEATURES
        .iter()
        .zip(0u32..)
        .find(|(row, _)| row.name == name)
        .and_then(|(row, index)| 1u64.checked_shl(index).map(|bit| (bit, row)))
}

/// The features delegated to one trusted frame, each scoped to the frame's
/// own declared origin (`'src'`): a set over [`DELEGATION_FEATURES`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Delegation(u64);

impl Delegation {
    /// No delegated feature.
    #[must_use]
    pub const fn none() -> Self {
        Self(0)
    }

    /// Parse a trusted frame's `allow` value and `allowfullscreen` presence.
    ///
    /// `own_origin` is the frame's trusted origin in its written form, and
    /// `grants` the app's granted web capabilities. A value over
    /// [`MAX_ALLOW_LEN`] bytes, over [`MAX_ALLOW_DIRECTIVES`] directives, or
    /// holding a byte outside `0x21..=0x7E` and `allow` whitespace delegates
    /// nothing, `allowfullscreen` included. Otherwise each directive is a
    /// feature name and its tokens; it is dropped when the name is not a
    /// table row (exact bytes), when a token is neither `'src'` nor
    /// `own_origin`, or when its class withholds it (`Never`, or `Gated`
    /// without a granted suffix). A feature written twice is delegated only
    /// when no occurrence is dropped. `allowfullscreen` adds `fullscreen`.
    #[must_use]
    pub fn parse(
        allow: Option<&str>,
        allowfullscreen: bool,
        own_origin: &str,
        grants: FrameGrants,
    ) -> Self {
        let mut admitted = 0u64;
        let mut refused = 0u64;
        if let Some(value) = allow {
            let lexes = value.len() <= MAX_ALLOW_LEN
                && value
                    .chars()
                    .all(|c| c.is_ascii_graphic() || is_allow_ws(c))
                && value.split(';').count() <= MAX_ALLOW_DIRECTIVES;
            if !lexes {
                return Self::none();
            }
            for directive in value.split(';') {
                let mut words = directive.split(is_allow_ws).filter(|word| !word.is_empty());
                let Some((bit, row)) = words.next().and_then(feature) else {
                    continue;
                };
                let scoped = words.all(|token| token == SRC_TOKEN || token == own_origin);
                let delegable = match row.class {
                    FeatureClass::Plain | FeatureClass::Undisclosed => true,
                    FeatureClass::Gated(suffixes) => grants.holds_any(suffixes),
                    FeatureClass::Never => false,
                };
                if scoped && delegable {
                    admitted |= bit;
                } else {
                    refused |= bit;
                }
            }
        }
        if allowfullscreen && let Some((bit, _)) = feature("fullscreen") {
            admitted |= bit;
        }
        Self(admitted & !refused)
    }

    /// Whether no feature is delegated.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The delegated features, in table order.
    pub fn features(self) -> impl Iterator<Item = &'static DelegationFeature> {
        DELEGATION_FEATURES
            .iter()
            .zip(0u32..)
            .filter(move |(_, index)| {
                1u64.checked_shl(*index)
                    .is_some_and(|bit| self.0 & bit != 0)
            })
            .map(|(row, _)| row)
    }

    /// Append the canonical `allow` value, `<feature> 'src'` joined by `; `
    /// in table order, to `out`.
    pub fn write(self, out: &mut String) {
        for (index, row) in self.features().enumerate() {
            if index > 0 {
                out.push_str("; ");
            }
            out.push_str(row.name);
            out.push(' ');
            out.push_str(SRC_TOKEN);
        }
    }

    /// The canonical `allow` value, or `None` when nothing is delegated and
    /// the frame carries no `allow` at all.
    #[must_use]
    pub fn painted(self) -> Option<String> {
        if self.is_empty() {
            return None;
        }
        let mut out = String::new();
        self.write(&mut out);
        Some(out)
    }
}

/// One trusted frame origin, as the frame verdict reads it.
///
/// With `encoding` it is the re-parsed [`FrameOrigin`]. Without it no origin
/// can be parsed, so the type has no value and every verdict over it is
/// untrusted by construction.
#[cfg(feature = "encoding")]
pub type ListedOrigin = FrameOrigin;

/// One trusted frame origin, as the frame verdict reads it.
///
/// A build without `encoding` parses no origin, so this type has no value.
#[cfg(not(feature = "encoding"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ListedOrigin {}

#[cfg(not(feature = "encoding"))]
impl ListedOrigin {
    /// The written origin; no value reaches it.
    #[must_use]
    pub const fn written(&self) -> String {
        match *self {}
    }
}

/// The authority a page is served on, as its frame verdict reads it.
///
/// `Unknown` trusts no frame: a page whose own origin is not known cannot
/// prove a listed origin is not its own.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum PageAuthority {
    /// The authority the host admission judged, or the browser's location.
    Known(Authority),
    /// No judged authority.
    #[default]
    Unknown,
}

impl PageAuthority {
    /// The authority of a browser location's `host`.
    ///
    /// `host` is `host` or `host:port`; a value that does not parse gives
    /// `Unknown`.
    #[must_use]
    pub fn of_location_host(host: &str) -> Self {
        Authority::parse(host).map_or(Self::Unknown, Self::Known)
    }

    /// Whether `self` and `admitted` name the same host and port.
    ///
    /// `Unknown`, or an absent `admitted`, never does.
    #[must_use]
    pub fn is_admitted(&self, admitted: Option<&Authority>) -> bool {
        match (self, admitted) {
            (Self::Known(page), Some(admitted)) => page == admitted,
            (Self::Known(_) | Self::Unknown, _) => false,
        }
    }
}

/// Whether a popup a trusted frame opens may leave the frame's sandbox.
///
/// `Held` only where the page's `Cross-Origin-Opener-Policy: same-origin`
/// binds, so such a popup is opened with no handle on the app's tab: a
/// served page with a listed origin that is not framed by another site.
/// Everywhere else, the browser client's default included, it is `Dropped`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EscapedPopups {
    /// The escape token is kept where the author wrote it beside
    /// `allow-popups`.
    Held,
    /// The escape token is dropped from every frame.
    #[default]
    Dropped,
}

impl EscapedPopups {
    /// `Held` when `held`, else `Dropped`.
    #[must_use]
    pub const fn when(held: bool) -> Self {
        if held { Self::Held } else { Self::Dropped }
    }

    /// Whether popups escape.
    #[must_use]
    pub const fn is_held(self) -> bool {
        matches!(self, Self::Held)
    }
}

/// Whether `origin` may be the page's own origin, so its frame is untrusted.
///
/// True for an `Unknown` page; for an `https` origin whose host is the
/// page's name, at any port (cookies ignore the port); for an `https`
/// loopback-name origin on any loopback-name page; for a dev loopback
/// origin on a loopback page at its port; and for an origin whose host does
/// not parse as an authority. An IP-literal page never matches a listed
/// origin, since no listed origin names an IP literal.
#[must_use]
pub fn served_on(origin: &ListedOrigin, page: &PageAuthority) -> bool {
    match page {
        PageAuthority::Known(page) => origin_served_on(origin, page),
        PageAuthority::Unknown => true,
    }
}

/// Whether the listed `origin` may be served on the known `page`.
#[cfg(feature = "encoding")]
fn origin_served_on(origin: &ListedOrigin, page: &Authority) -> bool {
    match origin {
        FrameOrigin::Https(server) => Authority::parse(server.authority())
            .map_or(true, |listed| hosts_may_be_one(listed.host(), page.host())),
        #[cfg(feature = "dev-posture")]
        FrameOrigin::DevLoopback(port) => {
            matches!(page.host(), AuthorityHost::LoopbackName)
                && page.port().map(std::num::NonZeroU16::get) == Some(port.get())
        }
    }
}

/// Whether a listed origin's host `listed` may be the page's host `page`.
///
/// Every pair is named, so a new host kind is a build error here rather than
/// a silent "different". Two names are one only when equal. A loopback name
/// keeps no spelling, so any two may be one. A listed IP literal (which
/// `FrameOrigin` refuses) may be any page's host. A name and a loopback name,
/// and a name or a loopback name beside an IP literal, are distinct origins.
#[cfg(feature = "encoding")]
fn hosts_may_be_one(listed: &AuthorityHost, page: &AuthorityHost) -> bool {
    match (listed, page) {
        (AuthorityHost::Name(listed), AuthorityHost::Name(page)) => listed == page,
        (AuthorityHost::LoopbackName, AuthorityHost::LoopbackName)
        | (
            AuthorityHost::Ip(_),
            AuthorityHost::Ip(_) | AuthorityHost::LoopbackName | AuthorityHost::Name(_),
        ) => true,
        (AuthorityHost::Name(_), AuthorityHost::LoopbackName | AuthorityHost::Ip(_))
        | (AuthorityHost::LoopbackName, AuthorityHost::Name(_) | AuthorityHost::Ip(_)) => false,
    }
}

/// Whether the listed `origin` may be served on the known `page`.
///
/// No value reaches it without `encoding`.
#[cfg(not(feature = "encoding"))]
const fn origin_served_on(origin: &ListedOrigin, _page: &Authority) -> bool {
    match *origin {}
}

/// The value every frame verdict reads: the trusted origins and the app's
/// granted web capabilities.
///
/// Without `encoding` the only value is [`FramePolicy::none`], so a build
/// that cannot parse an origin trusts none.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FramePolicy {
    #[cfg(feature = "encoding")]
    origins: FrameOrigins,
    grants: FrameGrants,
}

impl FramePolicy {
    /// No trusted origin and no grant: every frame is untrusted.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            #[cfg(feature = "encoding")]
            origins: FrameOrigins::none(),
            grants: FrameGrants::none(),
        }
    }

    /// The policy trusting `origins` under `grants`.
    #[cfg(feature = "encoding")]
    #[must_use]
    pub const fn trusting(origins: FrameOrigins, grants: FrameGrants) -> Self {
        Self { origins, grants }
    }

    /// The trusted origins, in sorted order; none without `encoding`.
    #[must_use]
    pub const fn origins(&self) -> &[ListedOrigin] {
        #[cfg(feature = "encoding")]
        {
            self.origins.origins()
        }
        #[cfg(not(feature = "encoding"))]
        {
            &[]
        }
    }

    /// The app's granted web capabilities.
    #[must_use]
    pub const fn grants(&self) -> FrameGrants {
        self.grants
    }
}

/// The policy of a program that never registered one.
static NONE: FramePolicy = FramePolicy::none();

/// The program's registered policy; write-once, the first registration wins.
static REGISTERED: OnceLock<FramePolicy> = OnceLock::new();

/// The program's frame policy: the registered one, else [`FramePolicy::none`].
#[must_use]
pub fn policy() -> &'static FramePolicy {
    REGISTERED.get().unwrap_or(&NONE)
}

/// Why [`try_register`] refused the program's frame origins.
#[cfg(feature = "encoding")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameRegisterRefusal {
    /// The origin at zero-based `index` does not re-parse.
    Origin {
        index: usize,
        refusal: FrameOriginRefusal,
    },
    /// The re-parsed origins are not a list.
    List(FrameOriginsRefusal),
}

#[cfg(feature = "encoding")]
impl std::fmt::Display for FrameRegisterRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Origin { index, refusal } => {
                write!(
                    f,
                    "trusted frame origin {}: {refusal}",
                    index.saturating_add(1)
                )
            }
            Self::List(refusal) => write!(f, "trusted frame origins: {refusal}"),
        }
    }
}

/// The policy `origins` and `granted` name, every origin re-parsed.
///
/// # Errors
///
/// `Origin` for the first origin that does not re-parse, and `List` for a
/// list past [`crate::encoding::MAX_FRAME_ORIGINS`] or [`FRAME_HEADER_BUDGET`].
#[cfg(feature = "encoding")]
pub fn policy_of(origins: &[&str], granted: &[&str]) -> Result<FramePolicy, FrameRegisterRefusal> {
    let parsed = origins
        .iter()
        .enumerate()
        .map(|(index, text)| {
            FrameOrigin::parse(text)
                .map_err(|refusal| FrameRegisterRefusal::Origin { index, refusal })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let origins = FrameOrigins::new(parsed).map_err(FrameRegisterRefusal::List)?;
    Ok(FramePolicy::trusting(
        origins,
        FrameGrants::from_suffixes(granted),
    ))
}

/// Set `cell` to the policy `origins` and `granted` name, unless it is set.
#[cfg(feature = "encoding")]
fn register_into(
    cell: &OnceLock<FramePolicy>,
    origins: &[&str],
    granted: &[&str],
) -> Result<(), FrameRegisterRefusal> {
    let policy = policy_of(origins, granted)?;
    // A set policy is the first registration's; a later one never widens it.
    if let Err(repeat) = cell.set(policy) {
        drop(repeat);
    }
    Ok(())
}

/// Register the program's trusted frame origins and granted web-capability suffixes.
///
/// Each origin is re-parsed, so an emitted list cannot widen past the parser.
/// The first registration wins and is never widened.
///
/// # Errors
///
/// The [`FrameRegisterRefusal`] of origins that do not form a policy; nothing
/// is registered then.
#[cfg(feature = "encoding")]
pub fn try_register(origins: &[&str], granted: &[&str]) -> Result<(), FrameRegisterRefusal> {
    register_into(&REGISTERED, origins, granted)
}

/// Register the program's trusted frame origins, or stop the native program.
///
/// Called by the generated server before it binds. Origins that do not form
/// a policy stop the program with exit code 1 and the refusal on stderr. A
/// wasm32 build has no such form: its entry reports through
/// `wasm::install_panic_hook_trusting_frames` and never starts the program.
#[cfg(all(feature = "encoding", not(target_arch = "wasm32")))]
pub fn register(origins: &[&str], granted: &[&str]) {
    if let Err(refusal) = try_register(origins, granted) {
        crate::core::eprint_task_error(&refusal.to_string());
        crate::system::exit_process(crate::system::ProcessStatus::FAILURE);
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;

    /// The bit of the row named `name`.
    fn bit(name: &str) -> u64 {
        feature(name).map_or(0, |(bit, _)| bit)
    }

    /// The painted `allow` of `value` on a frame of `https://x.example`.
    fn painted(value: &str, grants: FrameGrants) -> Option<String> {
        Delegation::parse(Some(value), false, "https://x.example", grants).painted()
    }

    /// Each delegated feature is scoped to the frame's own origin; every
    /// other scope, an unknown or uppercase name, and a withheld class drop
    /// the directive; a malformed value delegates nothing; the painted value
    /// is canonical whatever the author's order.
    #[test]
    fn allow_list_parses_to_src_scoped_features() {
        let camera = FrameGrants::from_suffixes(&["camera"]);
        let src = Some("camera 'src'".to_owned());
        for value in [
            "camera",
            "camera 'src'",
            "camera https://x.example",
            "camera 'src' https://x.example",
            "\tcamera\n'src'\r",
            "; camera ;",
        ] {
            assert_eq!(painted(value, camera), src, "{value:?}");
        }
        for value in [
            "camera *",
            "camera 'self'",
            "camera 'none'",
            "camera https://y.example",
            "camera https://x.example/",
            "camera 'SRC'",
            "Camera",
            "camera; camera *",
            "camera *; camera",
            "teleport",
            "payment",
            "payment 'src'",
            "",
        ] {
            assert_eq!(painted(value, camera), None, "{value:?}");
        }
        assert_eq!(painted("camera", FrameGrants::none()), None);
        assert_eq!(painted("microphone", camera), None);
        assert_eq!(
            painted("usb; autoplay", FrameGrants::none()),
            Some("autoplay 'src'; usb 'src'".to_owned())
        );

        let recorder = FrameGrants::from_suffixes(&["recorder"]);
        let both = Some("camera 'src'; microphone 'src'".to_owned());
        assert_eq!(painted("microphone; camera", recorder), both);
        assert_eq!(painted("camera;microphone 'src'", recorder), both);

        for value in [
            "camera\0".to_owned(),
            "camera \u{e9}".to_owned(),
            "camera\u{b}".to_owned(),
            format!("camera{}", " ".repeat(MAX_ALLOW_LEN + 1 - "camera".len())),
            format!("camera{}", ";".repeat(MAX_ALLOW_DIRECTIVES)),
        ] {
            assert_eq!(painted(&value, camera), None, "{value:?}");
            assert!(Delegation::parse(Some(&value), true, "https://x.example", camera).is_empty());
        }
        let at_len = format!("camera{}", " ".repeat(MAX_ALLOW_LEN - "camera".len()));
        let at_count = format!("camera{}", ";".repeat(MAX_ALLOW_DIRECTIVES - 1));
        assert_eq!(painted(&at_len, camera), src);
        assert_eq!(painted(&at_count, camera), src);

        let fullscreen = Some("fullscreen 'src'".to_owned());
        let none = FrameGrants::none();
        let own = "https://x.example";
        assert_eq!(
            Delegation::parse(None, true, own, none).painted(),
            fullscreen
        );
        assert_eq!(
            Delegation::parse(Some("fullscreen *"), true, own, none).painted(),
            None
        );
        assert_eq!(Delegation::parse(None, false, own, none).painted(), None);
        assert_eq!(
            Delegation::parse(Some("camera"), true, own, camera).0,
            bit("camera") | bit("fullscreen")
        );
    }

    /// The page authority of `host`, which must parse.
    #[cfg(feature = "encoding")]
    #[allow(clippy::expect_used)] // every vector is a well-formed authority
    fn page(host: &str) -> PageAuthority {
        PageAuthority::Known(Authority::parse(host).expect("authority"))
    }

    /// R10: an origin is withdrawn on its own host at any port, kept on any
    /// other host, a subdomain, a suffix or an IP literal, and withdrawn for
    /// every origin on an `Unknown` page.
    #[cfg(feature = "encoding")]
    #[test]
    #[allow(clippy::expect_used)] // every vector is a well-formed origin
    fn own_origin_is_never_trusted() {
        let app = FrameOrigin::parse("https://app.example").expect("origin");
        let ported = FrameOrigin::parse("https://app.example:8443").expect("origin");
        for host in ["app.example", "app.example:8443", "APP.example"] {
            assert!(served_on(&app, &page(host)), "{host}");
        }
        for host in [
            "other.example",
            "app.example.evil",
            "sub.app.example",
            "127.0.0.1",
            "[::1]",
            "localhost:8443",
        ] {
            assert!(!served_on(&app, &page(host)), "{host}");
        }
        assert!(served_on(&ported, &page("app.example")));
        assert!(!served_on(&ported, &page("other.example:8443")));
        let local = FrameOrigin::parse("https://localhost:8443").expect("origin");
        let sub = FrameOrigin::parse("https://a.localhost").expect("origin");
        for origin in [&local, &sub] {
            for host in [
                "localhost:8443",
                "localhost",
                "a.localhost:3000",
                "b.localhost",
            ] {
                assert!(served_on(origin, &page(host)), "{host}");
            }
            for host in ["app.example", "127.0.0.1:8443", "[::1]:8443"] {
                assert!(!served_on(origin, &page(host)), "{host}");
            }
        }
        for origin in [&app, &ported] {
            assert!(served_on(origin, &PageAuthority::Unknown));
        }
        for host in ["app.example.", "", "a b"] {
            assert_eq!(
                PageAuthority::of_location_host(host),
                PageAuthority::Unknown,
                "{host:?}"
            );
        }
    }

    /// R10, dev copy: a loopback origin is withdrawn on the loopback page at
    /// its port and kept at another port or another host.
    #[cfg(all(feature = "dev-posture", feature = "encoding"))]
    #[test]
    #[allow(clippy::expect_used)] // every vector is a well-formed origin
    fn dev_posture_pin_own_loopback_origin_is_never_trusted() {
        let dev = FrameOrigin::parse("http://localhost:3000").expect("origin");
        assert!(served_on(&dev, &page("localhost:3000")));
        assert!(!served_on(&dev, &page("localhost:3001")));
        assert!(!served_on(&dev, &page("app.example")));
        assert!(served_on(&dev, &PageAuthority::Unknown));
    }

    /// The host judge answers "may be one" for every pair whose
    /// representation cannot prove two hosts apart: two loopback names, and a
    /// listed IP literal beside any page host.
    #[cfg(feature = "encoding")]
    #[test]
    #[allow(clippy::expect_used)] // every vector is a well-formed authority
    fn host_pairs_without_proof_may_be_one() {
        let host = |raw: &str| Authority::parse(raw).expect("authority").host().clone();
        let (name, other) = (host("app.example"), host("other.example"));
        let (local, sub) = (host("localhost"), host("a.localhost"));
        let (v4, v6) = (host("127.0.0.1"), host("[::1]"));
        for (listed, page) in [
            (&name, &name),
            (&local, &sub),
            (&sub, &local),
            (&v4, &v4),
            (&v4, &v6),
            (&v4, &local),
            (&v4, &name),
        ] {
            assert!(hosts_may_be_one(listed, page), "{listed:?} on {page:?}");
        }
        for (listed, page) in [
            (&name, &other),
            (&name, &local),
            (&name, &v4),
            (&local, &name),
            (&local, &v6),
        ] {
            assert!(!hosts_may_be_one(listed, page), "{listed:?} on {page:?}");
        }
    }

    /// A page authority narrows only to the authority it was admitted under.
    #[cfg(feature = "encoding")]
    #[test]
    #[allow(clippy::expect_used)] // every vector is well-formed
    fn page_authority_admits_only_its_own_authority() {
        let minted = page("app.example:8080");
        let same = Authority::parse("app.example:8080").expect("a well-formed vector");
        assert!(minted.is_admitted(Some(&same)));
        for other in ["app.example:8081", "other.example:8080", "app.example"] {
            let other = Authority::parse(other).expect("a well-formed vector");
            assert!(!minted.is_admitted(Some(&other)));
        }
        assert!(!minted.is_admitted(None));
        assert!(!PageAuthority::Unknown.is_admitted(Some(&same)));
    }

    /// R23: a gated feature needs its grant (`recorder` opens camera and
    /// microphone), `payment` is never delegated, and every `Undisclosed`
    /// row is delegated scoped to the frame with no grant at all, and
    /// dropped under any wider scope.
    #[test]
    fn gated_features_need_the_grant() {
        let none = FrameGrants::none();
        for (feature, suffix) in [
            ("camera", "camera"),
            ("microphone", "microphone"),
            ("geolocation", "geolocation"),
        ] {
            let expected = Some(format!("{feature} 'src'"));
            assert_eq!(painted(feature, none), None, "{feature}");
            assert_eq!(
                painted(feature, FrameGrants::from_suffixes(&[suffix])),
                expected,
                "{feature}"
            );
        }
        let recorder = FrameGrants::from_suffixes(&["recorder"]);
        assert_eq!(painted("camera", recorder), Some("camera 'src'".to_owned()));
        assert_eq!(
            painted("microphone", recorder),
            Some("microphone 'src'".to_owned())
        );
        assert_eq!(painted("geolocation", recorder), None);
        let every =
            FrameGrants::from_suffixes(&["camera", "geolocation", "microphone", "recorder"]);
        assert_eq!(painted("payment", every), None);
        assert_eq!(painted("payment 'src'", every), None);
        let undisclosed: Vec<&str> = DELEGATION_FEATURES
            .iter()
            .filter(|row| matches!(row.class, FeatureClass::Undisclosed))
            .map(|row| row.name)
            .collect();
        assert_eq!(undisclosed.len(), 21);
        for name in undisclosed {
            assert_eq!(painted(name, none), Some(format!("{name} 'src'")), "{name}");
            for scope in ["*", "'self'", "https://y.example"] {
                assert_eq!(
                    painted(&format!("{name} {scope}"), none),
                    None,
                    "{name} {scope}"
                );
            }
        }
        let own = "https://x.example";
        assert_eq!(
            Delegation::parse(None, true, own, none).painted(),
            Some("fullscreen 'src'".to_owned())
        );
    }

    /// The table has its shape, ties to the served header's vocabulary and to
    /// the capability → directive map, and a table or vocabulary off by one
    /// row fails the same checks.
    #[test]
    fn delegation_table_agrees_with_the_header() {
        use ipe_kernels::WebCapability;

        assert!(table_is_well_formed(DELEGATION_FEATURES));
        assert!(agrees_with_header(WebCapability::POLICY_DIRECTIVES));
        for capability in WebCapability::ALL {
            let mut opened: Vec<&str> = capability.permissions_policy_directives().to_vec();
            opened.sort_unstable();
            let derived: Vec<&str> = GrantSuffix::parse(capability.as_str())
                .map(|suffix| suffix.features().collect())
                .unwrap_or_default();
            assert_eq!(derived, opened, "{}", capability.as_str());
        }
        for suffix in GrantSuffix::ALL {
            assert!(
                WebCapability::ALL
                    .iter()
                    .any(|capability| capability.as_str() == suffix.as_str()),
                "{}",
                suffix.as_str()
            );
        }
        let never: Vec<&str> = DELEGATION_FEATURES
            .iter()
            .filter(|row| row.class == FeatureClass::Never)
            .map(|row| row.name)
            .collect();
        assert_eq!(never, ["payment"]);
        assert!(
            DELEGATION_FEATURES
                .iter()
                .all(|row| !row.display.is_empty())
        );

        assert!(!agrees_with_header(&[
            "geolocation",
            "microphone",
            "camera"
        ]));
        assert!(!agrees_with_header(&[
            "geolocation",
            "microphone",
            "camera",
            "payment",
            "usb"
        ]));
        assert!(!agrees_with_header(&[
            "geolocation",
            "microphone",
            "camera",
            "payment",
            "autoplay"
        ]));
        assert!(!agrees_with_header(&[
            "geolocation",
            "camera",
            "camera",
            "payment"
        ]));

        let gated = FeatureClass::Gated(&[GrantSuffix::Camera]);
        let payment = row("payment", "Payments", FeatureClass::Never);
        assert!(table_is_well_formed(&[row("a", "A", gated), payment]));
        assert!(!table_is_well_formed(&[row("a", "A", gated)]));
        assert!(!table_is_well_formed(&[payment, row("a", "A", gated)]));
        assert!(!table_is_well_formed(&[
            row("a", "A", gated),
            row("a", "A", gated),
            payment
        ]));
        assert!(!table_is_well_formed(&[row("A", "A", gated), payment]));
        assert!(!table_is_well_formed(&[row("a", "", gated), payment]));
        assert!(!table_is_well_formed(&[
            row("a", "A", FeatureClass::Gated(&[])),
            payment
        ]));
        assert!(!table_is_well_formed(&[
            row("a", "A", FeatureClass::Never),
            payment
        ]));
    }

    /// An unknown suffix is dropped, never kept.
    #[test]
    fn grants_hold_only_the_vocabulary() {
        let grants = FrameGrants::from_suffixes(&["camera", "usb", "Camera", "recorder"]);
        assert_eq!(
            grants.suffixes().collect::<Vec<_>>(),
            [GrantSuffix::Camera, GrantSuffix::Recorder]
        );
        assert_eq!(FrameGrants::from_suffixes(&["usb"]), FrameGrants::none());
    }

    /// A build without `encoding` holds only the empty policy.
    #[cfg(not(feature = "encoding"))]
    #[test]
    fn policy_without_encoding_is_none() {
        assert_eq!(policy(), &FramePolicy::none());
        assert_eq!(policy().grants(), FrameGrants::none());
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
#[cfg(feature = "encoding")]
mod register_tests {
    use super::*;
    use crate::encoding::MAX_FRAME_ORIGINS;
    use crate::encoding::frame_origin_tests::{shortest_origin_text, texts_at_budget};

    /// A bad origin refuses and sets nothing; an unknown grant suffix is
    /// dropped; a second registration widens neither origins nor grants.
    #[test]
    fn frame_register_refuses_and_never_widens() {
        let cell = OnceLock::new();
        assert_eq!(
            register_into(&cell, &["https://a.example", "null"], &[]),
            Err(FrameRegisterRefusal::Origin {
                index: 1,
                refusal: FrameOriginRefusal::Scheme
            })
        );
        assert!(cell.get().is_none());

        assert_eq!(
            register_into(
                &cell,
                &["https://a.example"],
                &["camera", "usb", "recorder"]
            ),
            Ok(())
        );
        let first = cell.get().cloned();
        assert_eq!(
            first
                .as_ref()
                .map(|p| p.grants().suffixes().collect::<Vec<_>>()),
            Some(vec![GrantSuffix::Camera, GrantSuffix::Recorder])
        );
        assert_eq!(
            first.as_ref().map(|p| p
                .origins()
                .iter()
                .map(FrameOrigin::written)
                .collect::<Vec<_>>()),
            Some(vec!["https://a.example".to_owned()])
        );

        assert_eq!(
            register_into(
                &cell,
                &["https://a.example", "https://b.example"],
                &["camera", "microphone", "geolocation"]
            ),
            Ok(())
        );
        assert_eq!(cell.get().cloned(), first);

        assert!(policy().origins().is_empty());
    }

    /// The runtime's re-parse holds the manifest's caps: a seventeenth origin
    /// and a list past the header budget are refused, a list at the budget
    /// admitted, and a repeated origin folded.
    #[test]
    fn frame_register_holds_cap_and_budget() {
        let texts: Vec<String> = (0..=MAX_FRAME_ORIGINS).map(shortest_origin_text).collect();
        let refs: Vec<&str> = texts.iter().map(String::as_str).collect();
        assert_eq!(
            policy_of(&refs, &[]),
            Err(FrameRegisterRefusal::List(
                FrameOriginsRefusal::LimitExceeded
            ))
        );
        let full = refs.get(..MAX_FRAME_ORIGINS).unwrap_or_default();
        assert_eq!(
            policy_of(full, &[]).map(|p| p.origins().len()),
            Ok(MAX_FRAME_ORIGINS)
        );

        let at = texts_at_budget();
        assert!(!at.is_empty());
        let at_refs: Vec<&str> = at.iter().map(String::as_str).collect();
        let admitted = policy_of(&at_refs, &[]);
        assert_eq!(
            admitted.as_ref().map(|p| header_cost(p.origins())),
            Ok(FRAME_HEADER_BUDGET)
        );

        let mut over = at;
        if let Some(first) = over.first_mut() {
            first.push('a');
        }
        let over_refs: Vec<&str> = over.iter().map(String::as_str).collect();
        assert!(matches!(
            policy_of(&over_refs, &[]),
            Err(FrameRegisterRefusal::List(FrameOriginsRefusal::OverBudget { cost }))
                if cost > FRAME_HEADER_BUDGET
        ));

        let folded = policy_of(
            &[
                "https://b.example",
                "https://a.example",
                "https://b.example",
            ],
            &[],
        );
        assert_eq!(folded.map(|p| p.origins().len()), Ok(2));
    }
}

#[cfg(all(test, feature = "web", not(target_arch = "wasm32")))]
mod header_cost_tests {
    use super::*;
    use crate::csp::{ContentSecurityPolicy, Guarded, Profile};
    use crate::telemetry::{FrameAllowlist, permissions_policy_from};
    use std::collections::BTreeSet;

    /// The `WebPage` CSP and `Permissions-Policy` bytes a page trusting
    /// `origins` sends under the granted suffixes `granted`.
    fn shipped(origins: &FrameOrigins, granted: &[&str]) -> usize {
        let guard = Guarded::sample(Profile::WebPage, 0x11);
        let policy = FramePolicy::trusting(origins.clone(), FrameGrants::none());
        let csp = ContentSecurityPolicy::for_guard_trusting(&guard, None, &policy).header_value();
        let set: BTreeSet<String> = granted.iter().map(|s| (*s).to_string()).collect();
        let allowlist = if origins.is_empty() {
            FrameAllowlist::none()
        } else {
            FrameAllowlist::of(origins.origins())
        };
        csp.len() + permissions_policy_from(Some(&set), &allowlist).len()
    }

    /// R16d: for one origin and two, with every `Gated` row granted, the bytes
    /// the widened headers add over the unframed ones are exactly
    /// [`header_cost`]; with fewer grants they are at most it.
    #[test]
    #[allow(clippy::expect_used)] // every vector is a well-formed origin
    fn frame_header_cost_is_the_shipped_delta() {
        let every_gated = ["camera", "geolocation", "microphone"];
        let none = FrameOrigins::none();
        for texts in [
            &["https://x.example"][..],
            &["https://player.example.com:8443", "https://a.example"][..],
        ] {
            let origins = FrameOrigins::new(
                texts
                    .iter()
                    .map(|text| FrameOrigin::parse(text).expect("origin")),
            )
            .expect("origins");
            let cost = header_cost(origins.origins());
            let delta = shipped(&origins, &every_gated) - shipped(&none, &every_gated);
            assert_eq!(delta, cost, "{texts:?}");
            for granted in [&[][..], &["camera"][..], &["recorder"][..]] {
                let delta = shipped(&origins, granted) - shipped(&none, granted);
                assert!(delta <= cost, "{texts:?} {granted:?}");
            }
        }
    }
}
