//! Data-store and serialisation limits.

use super::{Doc, EnvEntry, Feature, JailRootsKey, Lifetime, Subsystem};
use crate::env_grammar::Class;
use crate::scratch_core::JailAttestation;

/// The directories the run jail's launcher proved trusted with real ids.
pub const JAIL_TRUSTED_ROOTS: JailRootsKey = JailRootsKey::new(
    "IPE_JAIL_TRUSTED_ROOTS",
    Doc {
        class: Class::Internal,
        feature: Feature::Always,
        lifetime: Lifetime::Startup,
        subsystem: Subsystem::Db,
        purpose: "Set by the `ipe release run` jail launcher to the `dev:ino` of each bind \
                  root whose directory chain it proved trusted on the host. A SQLite \
                  database path's ancestor walk stops at such a root once the root passes \
                  its own verdict inside the jail. A malformed value attests nothing.",
    },
);

/// This subsystem's entries.
pub const ENTRIES: &[EnvEntry] = &[JAIL_TRUSTED_ROOTS.entry()];

/// The process's jail attestation.
///
/// Fixed by [`super::startup_check`] before the program's first line, so a
/// value the program writes later is never read.
pub fn jail_attestation() -> &'static JailAttestation {
    static ATTESTATION: std::sync::OnceLock<JailAttestation> = std::sync::OnceLock::new();
    ATTESTATION.get_or_init(|| JAIL_TRUSTED_ROOTS.read())
}

/// Fixes [`jail_attestation`] for the process.
pub fn fix_jail_attestation() {
    jail_attestation();
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use std::env::VarError;

    /// Every lookup the launcher did not write as a well-formed list attests nothing.
    #[test]
    fn a_malformed_or_absent_attestation_value_attests_nothing() {
        let id = crate::scratch_core::DirId { dev: 7, ino: 9 };
        assert!(JAIL_TRUSTED_ROOTS.parse(Ok("7:9".to_owned())).covers(id));
        for raw in [
            Err(VarError::NotPresent),
            Err(VarError::NotUnicode(std::ffi::OsString::from("7:9"))),
            Ok(String::new()),
            Ok("7:9,".to_owned()),
            Ok("1:1,2:2,3:3,4:4,7:9".to_owned()),
        ] {
            assert_eq!(
                JAIL_TRUSTED_ROOTS.parse(raw.clone()),
                JailAttestation::none(),
                "{raw:?}"
            );
        }
        let entry = JAIL_TRUSTED_ROOTS.entry();
        assert!(
            entry
                .grammar()
                .check(entry.name(), entry.class(), Ok("not-a-pair".to_owned()))
                .is_ok(),
            "a malformed launcher value narrows trust and never refuses startup"
        );
    }
}
