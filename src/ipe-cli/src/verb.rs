//! The typed identity of every build-producing CLI verb.
//!
//! A verb lives under exactly one umbrella group (`dev` or `release`), and the
//! umbrella alone fixes its build intent: [`Umbrella::Dev`] builds with
//! [`BuildIntent::Development`], [`Umbrella::Release`] with
//! [`BuildIntent::Release`]. A verb's
//! [`fmt::Display`] (`dev build`) is the one spelling of its name for help
//! pages, usage refusals, machine-output command fields, verb labels, and the
//! argv of a self-reinvocation.

use core::fmt;

use ipe_backend_rust::BuildIntent;

use crate::text;

/// The umbrella group a build-producing verb lives under.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Umbrella {
    /// `ipe dev …` — the development inner loop.
    Dev,
    /// `ipe release build|run|eject` — the production artifact.
    Release,
}

impl Umbrella {
    /// Every umbrella, in help order.
    pub const ALL: [Self; 2] = [Self::Dev, Self::Release];

    /// The group word typed after `ipe`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Dev => "dev",
            Self::Release => "release",
        }
    }

    /// The build intent every verb of this umbrella compiles with.
    #[must_use]
    pub const fn intent(self) -> BuildIntent {
        match self {
            Self::Dev => BuildIntent::Development,
            Self::Release => BuildIntent::Release,
        }
    }

    /// The umbrella named by the group word `name`, if any.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|u| u.name() == name)
    }
}

/// A verb of the `dev` umbrella.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DevVerb {
    /// `ipe dev build`.
    Build,
    /// `ipe dev run`.
    Run,
    /// `ipe dev watch`.
    Watch,
}

/// A verb of the `release` umbrella.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ReleaseVerb {
    /// `ipe release build`.
    Build,
    /// `ipe release run`.
    Run,
    /// `ipe release eject`.
    Eject,
}

/// A build-producing verb: an umbrella group plus the verb under it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Verb {
    /// A `dev` verb.
    Dev(DevVerb),
    /// A `release` verb.
    Release(ReleaseVerb),
}

impl Verb {
    /// `ipe dev build`.
    pub const DEV_BUILD: Self = Self::Dev(DevVerb::Build);
    /// `ipe dev run`.
    pub const DEV_RUN: Self = Self::Dev(DevVerb::Run);
    /// `ipe dev watch`.
    pub const DEV_WATCH: Self = Self::Dev(DevVerb::Watch);
    /// `ipe release build`.
    pub const RELEASE_BUILD: Self = Self::Release(ReleaseVerb::Build);
    /// `ipe release run`.
    pub const RELEASE_RUN: Self = Self::Release(ReleaseVerb::Run);
    /// `ipe release eject`.
    pub const RELEASE_EJECT: Self = Self::Release(ReleaseVerb::Eject);

    /// Every verb, grouped by umbrella in help order.
    pub const ALL: [Self; 6] = [
        Self::DEV_BUILD,
        Self::DEV_RUN,
        Self::DEV_WATCH,
        Self::RELEASE_BUILD,
        Self::RELEASE_RUN,
        Self::RELEASE_EJECT,
    ];

    /// The umbrella this verb lives under.
    #[must_use]
    pub const fn umbrella(self) -> Umbrella {
        match self {
            Self::Dev(_) => Umbrella::Dev,
            Self::Release(_) => Umbrella::Release,
        }
    }

    /// The build intent this verb compiles with, fixed by its umbrella.
    #[must_use]
    pub const fn intent(self) -> BuildIntent {
        self.umbrella().intent()
    }

    /// The verb word typed after the group word.
    #[must_use]
    pub const fn sub(self) -> &'static str {
        match self {
            Self::Dev(DevVerb::Build) | Self::Release(ReleaseVerb::Build) => "build",
            Self::Dev(DevVerb::Run) | Self::Release(ReleaseVerb::Run) => "run",
            Self::Dev(DevVerb::Watch) => "watch",
            Self::Release(ReleaseVerb::Eject) => "eject",
        }
    }

    /// The argv that invokes this verb: `["dev", "build"]`.
    #[must_use]
    pub const fn argv(self) -> [&'static str; 2] {
        [self.umbrella().name(), self.sub()]
    }

    /// The verb's display name: `dev build`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Dev(DevVerb::Build) => "dev build",
            Self::Dev(DevVerb::Run) => "dev run",
            Self::Dev(DevVerb::Watch) => "dev watch",
            Self::Release(ReleaseVerb::Build) => "release build",
            Self::Release(ReleaseVerb::Run) => "release run",
            Self::Release(ReleaseVerb::Eject) => "release eject",
        }
    }

    /// The verb's help-page key: `dev-build`.
    #[must_use]
    pub const fn help_key(self) -> &'static str {
        match self {
            Self::Dev(DevVerb::Build) => "dev-build",
            Self::Dev(DevVerb::Run) => "dev-run",
            Self::Dev(DevVerb::Watch) => "dev-watch",
            Self::Release(ReleaseVerb::Build) => "release-build",
            Self::Release(ReleaseVerb::Run) => "release-run",
            Self::Release(ReleaseVerb::Eject) => "release-eject",
        }
    }

    /// The verb `sub` under `umbrella`, if that umbrella has one.
    #[must_use]
    pub fn member(umbrella: Umbrella, sub: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|v| v.umbrella() == umbrella && v.sub() == sub)
    }

    /// The verb whose display name or help key is `name`, if any.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|v| v.name() == name || v.help_key() == name)
    }
}

impl fmt::Display for Verb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The command a usage refusal or machine-output record names.
///
/// A top-level command keeps its single word; a grouped verb is its typed
/// [`Verb`], so its spelling comes from [`Verb::name`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CommandName {
    /// A top-level command (`fmt`, `doc`, …).
    Command(&'static str),
    /// A grouped build-producing verb.
    Verb(Verb),
}

impl CommandName {
    /// The command's display name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Command(name) => name,
            Self::Verb(verb) => verb.name(),
        }
    }
}

impl From<&'static str> for CommandName {
    fn from(name: &'static str) -> Self {
        Self::Command(name)
    }
}

impl From<Verb> for CommandName {
    fn from(verb: Verb) -> Self {
        Self::Verb(verb)
    }
}

impl PartialEq<&str> for CommandName {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl fmt::Display for CommandName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Whether `whole` is `head`, then `sep`, then `tail`.
const fn joined_eq(whole: &[u8], head: &[u8], sep: u8, tail: &[u8]) -> bool {
    match (whole, head) {
        ([w, whole_rest @ ..], [h, head_rest @ ..]) => {
            *w == *h && joined_eq(whole_rest, head_rest, sep, tail)
        }
        ([w, whole_rest @ ..], []) => *w == sep && text::bytes_eq(whole_rest, tail),
        _ => false,
    }
}

/// Whether every verb's name and help key are its argv joined by a space and a hyphen.
const fn verb_tables_agree(verbs: &[Verb]) -> bool {
    match verbs {
        [] => true,
        [verb, rest @ ..] => {
            let [group, sub] = verb.argv();
            joined_eq(
                verb.name().as_bytes(),
                group.as_bytes(),
                b' ',
                sub.as_bytes(),
            ) && joined_eq(
                verb.help_key().as_bytes(),
                group.as_bytes(),
                b'-',
                sub.as_bytes(),
            ) && verb_tables_agree(rest)
        }
    }
}

// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if a verb's display name or help key drifts from its argv [ledger #boundary]
#[allow(clippy::assertions_on_constants)] // the constant IS the tripwire
const _: () = assert!(
    verb_tables_agree(&Verb::ALL),
    "every verb's name and help key must be its argv joined by ' ' and '-'"
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_umbrella_alone_fixes_the_posture() {
        for verb in Verb::ALL {
            let intent = match verb.umbrella() {
                Umbrella::Dev => BuildIntent::Development,
                Umbrella::Release => BuildIntent::Release,
            };
            assert_eq!(verb.intent(), intent, "{verb}");
        }
    }

    #[test]
    fn agreement_check_refuses_a_drifted_spelling() {
        assert!(joined_eq(b"dev build", b"dev", b' ', b"build"));
        assert!(!joined_eq(b"dev-build", b"dev", b' ', b"build"));
        assert!(!joined_eq(b"dev buil", b"dev", b' ', b"build"));
        assert!(!joined_eq(b"dev builds", b"dev", b' ', b"build"));
        assert!(!joined_eq(b"de build", b"dev", b' ', b"build"));
    }

    #[test]
    fn names_round_trip_through_lookup() {
        for verb in Verb::ALL {
            assert_eq!(Verb::from_name(verb.name()), Some(verb));
            assert_eq!(Verb::from_name(verb.help_key()), Some(verb));
            assert_eq!(Verb::member(verb.umbrella(), verb.sub()), Some(verb));
            assert_eq!(verb.to_string(), verb.argv().join(" "));
        }
        assert_eq!(Verb::member(Umbrella::Dev, "eject"), None);
        assert_eq!(Verb::member(Umbrella::Release, "watch"), None);
        assert_eq!(Verb::from_name("build"), None);
    }
}
