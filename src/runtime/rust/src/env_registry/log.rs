//! The logger's variables.

use super::{ChoiceKey, DefaultValue, Doc, EnvEntry, Feature, Lifetime, Subsystem};
use crate::env_grammar::Class;

/// The minimum level the logger emits.
pub const LOG_LEVEL: ChoiceKey = ChoiceKey::new(
    "IPE_LOG_LEVEL",
    &["debug", "info", "warn", "warning", "error"],
    DefaultValue::Text("unset (info)"),
    Doc {
        class: Class::Tunable,
        feature: Feature::Log,
        lifetime: Lifetime::Startup,
        subsystem: Subsystem::Observability,
        purpose: "Minimum log level: `debug`, `info`, `warn` (or `warning`), or \
                  `error`, ASCII case-insensitive. Any other value, an empty or \
                  padded one included, refuses startup. Read once at process start, \
                  so a later `System.setenv` or `System.loadEnv` does not change it. \
                  Takes precedence over an installed `Log.level` setting.",
    },
);

/// This subsystem's entries.
pub const ENTRIES: &[EnvEntry] = &[LOG_LEVEL.entry()];
