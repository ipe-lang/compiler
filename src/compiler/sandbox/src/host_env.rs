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

/// The host value of `name`, for re-export into a jail's scrubbed environment.
#[must_use]
#[allow(clippy::disallowed_methods)] // capability passthrough: forwarded verbatim, never interpreted
pub(crate) fn granted(name: &str) -> Option<OsString> {
    std::env::var_os(name)
}

/// The host values of `profile`'s granted env names, in allowlist order.
///
/// A granted name the host leaves unset is omitted (never an empty value), and
/// a name outside the allowlist is never read.
#[must_use]
pub fn granted_env(profile: &SandboxProfile) -> Vec<(String, OsString)> {
    granted_from(&profile.env_allowlist, granted)
}

/// The `(name, value)` pairs `lookup` yields for the `allowlist` names, in
/// allowlist order.
///
/// `lookup` is asked for allowlisted names only; a name it leaves unset is
/// omitted.
fn granted_from(
    allowlist: &[String],
    lookup: impl Fn(&str) -> Option<OsString>,
) -> Vec<(String, OsString)> {
    allowlist
        .iter()
        .filter_map(|name| lookup(name).map(|value| (name.clone(), value)))
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
        let out = granted_from(&names(&["A", "B"]), every_name_set);
        assert_eq!(asked.into_inner(), names(&["A", "B"]));
        assert_eq!(order(&out), ["A", "B"]);
    }

    #[test]
    fn an_unset_allowlisted_name_is_omitted() {
        let only_b_set = |name: &str| (name == "B").then(|| OsString::from("b"));
        let out = granted_from(&names(&["A", "B", "C"]), only_b_set);
        assert_eq!(out, vec![("B".to_owned(), OsString::from("b"))]);
    }

    #[test]
    fn the_output_follows_the_allowlist_order() {
        let echo = |name: &str| Some(OsString::from(name));
        let out = granted_from(&names(&["Z", "A", "M"]), echo);
        assert_eq!(order(&out), ["Z", "A", "M"]);
        assert!(out.iter().all(|(n, v)| v == n.as_str()));
    }

    #[test]
    fn an_empty_allowlist_grants_nothing() {
        let every_name_set = |_: &str| Some(OsString::from("v"));
        assert!(granted_from(&[], every_name_set).is_empty());
        assert!(granted_env(&SandboxProfile::maximally_isolated()).is_empty());
    }

    #[test]
    fn the_host_passthrough_withholds_a_set_name_it_was_not_granted() {
        // `PATH` is set in every test process: withheld until granted.
        assert!(granted_env(&profile(&[UNSET])).is_empty());
        assert_eq!(order(&granted_env(&profile(&[UNSET, "PATH"]))), ["PATH"]);
    }
}
