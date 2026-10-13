//! Security-boundary switches.

use super::{Doc, EnvEntry, Feature, FlagKey, Lifetime, Subsystem};
use crate::env_grammar::{Class, EnvFlag};

/// Whether a mutating `Ipe.Web` request's `Origin` must name the request's own authority.
pub const WEB_CSRF_ORIGIN_CHECK: FlagKey = FlagKey::new(
    "IPE_WEB_CSRF_ORIGIN_CHECK",
    EnvFlag::On,
    Doc {
        class: Class::SecurityTunable,
        feature: Feature::Web,
        lifetime: Lifetime::Startup,
        subsystem: Subsystem::Web,
        purpose: "Same-origin check on mutating `Ipe.Web` requests, on top of the \
                  double-submit CSRF token: a request carrying an `Origin` header is \
                  refused unless that origin names the request's authority (its \
                  `Host`, else the authority of its target URI), and a request with \
                  an `Origin` but no authority is refused too. On by default. `1`, \
                  `true`, `on`, `0`, `false` or `off`, ASCII case-insensitive; any \
                  other value, an empty one included, refuses startup. Set it `off` \
                  behind a reverse proxy that rewrites `Host`. Not applied while \
                  `IPE_WEB_FRAME_ANCESTORS` allows embedding. Read once at process \
                  start.",
    },
);

/// This subsystem's entries.
pub const ENTRIES: &[EnvEntry] = &[WEB_CSRF_ORIGIN_CHECK.entry()];
