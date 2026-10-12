//! The `Ipe.Web` listener's port variable.

use super::{DefaultValue, Doc, EnvEntry, Feature, Lifetime, PortKey, Subsystem};
use crate::env_grammar::Class;

/// The port an `Ipe.Web` app binds while [`WEB_PORT`] is unset.
pub const WEB_DEFAULT_PORT: u16 = 8000;

/// The operator's port for an `Ipe.Web` app.
pub const WEB_PORT: PortKey = PortKey::new(
    "IPE_WEB_PORT",
    DefaultValue::Port(WEB_DEFAULT_PORT),
    Doc {
        class: Class::Tunable,
        feature: Feature::Web,
        lifetime: Lifetime::AtUse,
        subsystem: Subsystem::Web,
        purpose: "TCP port an `Ipe.Web` app listens on, in `1..=65535`. Any other \
                  value (empty, non-numeric, signed, `0`, or too large) refuses \
                  startup, naming the variable. Under `ipe dev watch` the supervisor \
                  chooses the port and a valid value has no effect, but a malformed one \
                  still refuses.",
    },
);

/// This subsystem's entries.
pub const ENTRIES: &[EnvEntry] = &[WEB_PORT.entry()];
