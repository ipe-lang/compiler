//! The host environment re-exported, uninterpreted, into a jail's scrubbed env.
//!
//! A jail starts from an empty environment and receives only its arm's fixed
//! base set (on Windows, [`crate::run_jail::WindowsBaseEnv`]) plus the names the
//! profile's `env` capability granted. [`granted`] is the one raw read behind
//! every such re-export and is crate-private: only this crate's jail builders
//! call it, with a fixed base name or a name drawn from `profile.env_allowlist`.
//! Outside the crate the only passthrough is [`granted_env`], which reads
//! nothing but the profile's own allowlist. A consented name — a home variable
//! included — is forwarded verbatim to the jailed child and never decides a
//! compiler-side path. Compiler-side path decisions read the home only through
//! `crate::home::home_dir` and every other variable through `ipe_env`, which
//! refuses home names.

use std::ffi::OsString;

use crate::run_jail::SandboxProfile;

/// The variables only a jail launcher sets on the jailed app, each its own proof.
///
/// A host value of one of these never re-enters a jail, whatever the profile
/// grants: on an arm that attests, the launcher's own value is the only one;
/// on an arm that does not, the scrubbed environment never holds the name.
pub const LAUNCHER_OWNED: [&str; 1] = [crate::scratch::JAIL_TRUSTED_ROOTS_VAR];

/// Whether `name` is a [`LAUNCHER_OWNED`] variable, in any letter case.
///
/// The comparison ignores ASCII case because the Windows environment does.
#[must_use]
pub fn is_launcher_owned(name: &str) -> bool {
    LAUNCHER_OWNED
        .iter()
        .any(|owned| owned.eq_ignore_ascii_case(name))
}

/// The names of `profile`'s env grant a host value may re-enter a jail under.
///
/// The profile's allowlist without the [`LAUNCHER_OWNED`] names; every jail
/// arm's re-export loop reads its names from here.
pub fn reexported_names(profile: &SandboxProfile) -> impl Iterator<Item = &str> {
    profile
        .env_allowlist
        .iter()
        .map(String::as_str)
        .filter(|name| !is_launcher_owned(name))
}

/// The host value of `name`, for re-export into a jail's scrubbed environment.
///
/// A [`LAUNCHER_OWNED`] name has no host value to re-export.
#[must_use]
#[allow(clippy::disallowed_methods)] // capability passthrough: forwarded verbatim, never interpreted
pub(crate) fn granted(name: &str) -> Option<OsString> {
    if is_launcher_owned(name) {
        return None;
    }
    std::env::var_os(name)
}

/// The host values of `profile`'s granted env names, in allowlist order.
///
/// A granted name the host leaves unset is omitted (never an empty value), and
/// a name outside the allowlist is never read.
#[must_use]
pub fn granted_env(profile: &SandboxProfile) -> Vec<(String, OsString)> {
    granted_from(profile, granted)
}

/// The `(name, value)` pairs `lookup` yields for `profile`'s
/// [`reexported_names`], in allowlist order.
///
/// `lookup` is asked for those names only; a name it leaves unset is omitted.
fn granted_from(
    profile: &SandboxProfile,
    lookup: impl Fn(&str) -> Option<OsString>,
) -> Vec<(String, OsString)> {
    reexported_names(profile)
        .filter_map(|name| lookup(name).map(|value| (name.to_owned(), value)))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::ffi::OsString;

    use super::{granted_env, granted_from};
    use crate::run_jail::SandboxProfile;

    /// A name no host sets.
    const UNSET: &str = "IPE_HOST_ENV_TEST_UNSET_7F3A9C21D84E";

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|n| (*n).to_owned()).collect()
    }

    fn profile(list: &[&str]) -> SandboxProfile {
        SandboxProfile {
            env_allowlist: names(list),
            ..SandboxProfile::maximally_isolated()
        }
    }

    fn order(granted: &[(String, OsString)]) -> Vec<&str> {
        granted.iter().map(|(n, _)| n.as_str()).collect()
    }

    #[test]
    fn a_name_outside_the_allowlist_is_never_looked_up() {
        let asked = RefCell::new(Vec::new());
        let every_name_set = |name: &str| {
            asked.borrow_mut().push(name.to_owned());
            Some(OsString::from("v"))
        };
        let out = granted_from(&profile(&["A", "B"]), every_name_set);
        assert_eq!(asked.into_inner(), names(&["A", "B"]));
        assert_eq!(order(&out), ["A", "B"]);
    }

    #[test]
    fn an_unset_allowlisted_name_is_omitted() {
        let only_b_set = |name: &str| (name == "B").then(|| OsString::from("b"));
        let out = granted_from(&profile(&["A", "B", "C"]), only_b_set);
        assert_eq!(out, vec![("B".to_owned(), OsString::from("b"))]);
    }

    #[test]
    fn the_output_follows_the_allowlist_order() {
        let echo = |name: &str| Some(OsString::from(name));
        let out = granted_from(&profile(&["Z", "A", "M"]), echo);
        assert_eq!(order(&out), ["Z", "A", "M"]);
        assert!(out.iter().all(|(n, v)| v == n.as_str()));
    }

    #[test]
    fn an_empty_allowlist_grants_nothing() {
        let every_name_set = |_: &str| Some(OsString::from("v"));
        assert!(granted_from(&profile(&[]), every_name_set).is_empty());
        assert!(granted_env(&SandboxProfile::maximally_isolated()).is_empty());
    }

    /// A launcher-owned name, granted in any letter case, is never looked up nor re-exported.
    #[test]
    fn a_launcher_owned_name_never_reenters_from_the_host() {
        let owned = crate::scratch::JAIL_TRUSTED_ROOTS_VAR;
        let lower = owned.to_ascii_lowercase();
        let asked = RefCell::new(Vec::new());
        let every_name_set = |name: &str| {
            asked.borrow_mut().push(name.to_owned());
            Some(OsString::from("1:1"))
        };
        let out = granted_from(&profile(&[owned, &lower, "A"]), every_name_set);
        assert_eq!(order(&out), ["A"]);
        assert_eq!(asked.into_inner(), names(&["A"]));
        assert_eq!(super::granted(owned), None);
        assert!(super::is_launcher_owned(&lower));
        assert!(!super::is_launcher_owned("PATH"));
    }

    #[test]
    fn the_host_passthrough_withholds_a_set_name_it_was_not_granted() {
        // `PATH` is set in every test process: withheld until granted.
        assert!(granted_env(&profile(&[UNSET])).is_empty());
        assert_eq!(order(&granted_env(&profile(&[UNSET, "PATH"]))), ["PATH"]);
    }
}
