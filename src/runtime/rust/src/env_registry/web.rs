//! The `Ipe.Web` listener's port and session-count variables.

use super::{CeilingKey, DefaultValue, Doc, EnvEntry, Feature, Lifetime, PortKey, Subsystem};
use crate::env_grammar::Class;
use crate::system::{EnvCeiling, ZeroCeiling};

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

/// The most session drivers an `Ipe.Web` app keeps live at once.
pub const MAX_SESSIONS: CeilingKey = CeilingKey::new(
    EnvCeiling::new(
        "IPE_WEB_MAX_SESSIONS",
        50_000,
        ZeroCeiling::Refused,
        "decimal session count",
    ),
    Doc {
        class: Class::Tunable,
        feature: Feature::Web,
        lifetime: Lifetime::Startup,
        subsystem: Subsystem::Web,
        purpose: "Maximum concurrent web sessions; a new or returning session past it \
                  answers 503. Independently, the measured state of all sessions together \
                  (model, rendered view, render history, queued browser events) is \
                  capped at 512 MiB, and of one session at 16 MiB. One session runs at \
                  most 64 commands at once; the next is refused with a `LimitExceeded` \
                  error delivered to the program, and the session stays live. Read once, at \
                  process start; a value that is not a positive decimal integer (`0` \
                  included) refuses the program before its first line, naming the \
                  variable.",
    },
);

/// This subsystem's entries.
pub const ENTRIES: &[EnvEntry] = &[WEB_PORT.entry(), MAX_SESSIONS.entry()];

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::env_grammar::EnvRefusal;
    use crate::env_registry::check_entries;

    /// The refusals the registry judges for `value`, unset when `None`.
    fn judged(value: Option<&str>) -> Vec<EnvRefusal> {
        let name = MAX_SESSIONS.entry().name();
        match value {
            Some(value) => crate::system::locked_set_var(name, value),
            None => crate::system::locked_remove_var(name),
        }
        let refusals = check_entries(&[MAX_SESSIONS.entry()]);
        crate::system::locked_remove_var(name);
        refusals
    }

    /// `0` and a malformed count refuse startup naming the variable; `1` and unset admit.
    #[test]
    fn max_sessions_zero_refuses_startup() {
        let compiled = MAX_SESSIONS.entry().feature().is_compiled();
        for refused in ["0", "lots", "", "-1", "1.5", "18446744073709551616"] {
            let refusals = judged(Some(refused));
            if compiled {
                assert_eq!(refusals.len(), 1, "{refused:?} must refuse: {refusals:?}");
                assert!(
                    refusals.iter().all(|r| r.name() == "IPE_WEB_MAX_SESSIONS"
                        && r.to_string().contains("IPE_WEB_MAX_SESSIONS")),
                    "{refusals:?}"
                );
            } else {
                assert!(refusals.is_empty(), "{refusals:?}");
            }
        }
        for admitted in [Some("1"), Some("50000"), None] {
            assert!(judged(admitted).is_empty(), "{admitted:?} must admit");
        }
    }

    /// The purpose text states the figures the web budgets enforce.
    #[cfg(feature = "web")]
    #[test]
    fn max_sessions_purpose_states_the_budget_figures() {
        use crate::web::budget::{SESSION_BUDGET, SESSION_CEILING, SESSION_CMD_CEILING};
        let mib = |bytes: crate::retained::Bytes| format!("{} MiB", bytes.get() / (1024 * 1024));
        let purpose = MAX_SESSIONS.entry().purpose();
        for figure in [
            mib(SESSION_BUDGET),
            mib(SESSION_CEILING),
            format!("at most {} commands at once", SESSION_CMD_CEILING.get()),
        ] {
            assert!(
                purpose.contains(&figure),
                "{figure:?} missing from {purpose:?}"
            );
        }
    }

    /// The ceiling keeps the shared refusal contract.
    #[test]
    fn max_sessions_keeps_the_ceiling_contract() {
        crate::system::assert_env_ceiling_contract(MAX_SESSIONS.ceiling());
    }
}
