//! The `Server.listen` HTTP listener's port variables.

use super::{DefaultValue, Doc, EnvEntry, Feature, Lifetime, PortKey, Subsystem};
use crate::env_grammar::Class;

/// The operator's port for an `Ipe.Http.Server` app.
pub const SERVER_PORT: PortKey = PortKey::new(
    "IPE_SERVER_PORT",
    DefaultValue::Text("the port passed to `Server.listen`"),
    Doc {
        class: Class::Tunable,
        feature: Feature::Server,
        lifetime: Lifetime::AtUse,
        subsystem: Subsystem::Http,
        purpose: "TCP port an `Ipe.Http.Server` app listens on, in `1..=65535`. Any \
                  other value (empty, non-numeric, signed, `0`, or too large) refuses \
                  startup, naming the variable. Under `ipe dev watch` the supervisor \
                  chooses the port and a valid value has no effect, but a malformed one \
                  still refuses.",
    },
);

/// The port the dev supervisor relocates a served app's listener to.
pub const LISTEN_PORT_RELOCATION: PortKey = PortKey::new(
    "IPE_INTERNAL_LISTEN_PORT",
    DefaultValue::Text("unset"),
    Doc {
        class: Class::Internal,
        feature: Feature::Server,
        lifetime: Lifetime::AtUse,
        subsystem: Subsystem::Runtime,
        purpose: "Set by the dev supervisor to the port it proxies to; outranks every \
                  operator and program port.",
    },
);

/// This subsystem's entries.
pub const ENTRIES: &[EnvEntry] = &[SERVER_PORT.entry(), LISTEN_PORT_RELOCATION.entry()];
