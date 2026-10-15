//! The HTTP app listener's variables.

use super::{DefaultValue, Doc, EnvEntry, Feature, HostNamesKey, Lifetime, PortKey, Subsystem};
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

/// The DNS names an app listener admits besides IP literals and loopback names.
pub const ALLOWED_HOSTS: HostNamesKey = HostNamesKey::new(
    "IPE_HTTP_ALLOWED_HOSTS",
    Doc {
        class: Class::SecurityTunable,
        feature: Feature::Server,
        lifetime: Lifetime::Startup,
        subsystem: Subsystem::Http,
        purpose: "Comma-separated DNS names an `Ipe.Http.Server` or `Ipe.Web` app \
                  serves besides IP literals and loopback names (`localhost` and \
                  `*.localhost`), each trimmed of spaces: `name` admits exactly that \
                  name, `.name` every name below it (not the name itself). A request \
                  whose `Host` is any other DNS name answers `421`, in every build, \
                  so a DNS name pointed at the app cannot reach it unless declared. \
                  Set it to the public name a reverse proxy forwards as `Host`. An \
                  empty value, an empty item, a port, `*`, an IP literal, a loopback \
                  name, or more than 64 items refuses startup, naming the variable \
                  and the item's position, never the value.",
    },
);

/// This subsystem's entries.
pub const ENTRIES: &[EnvEntry] = &[
    SERVER_PORT.entry(),
    LISTEN_PORT_RELOCATION.entry(),
    ALLOWED_HOSTS.entry(),
];
