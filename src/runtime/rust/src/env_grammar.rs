//! The accepted forms of operator environment variables and their refusals.
//!
//! A [`Grammar`] names the one form a registered variable accepts. Every parser
//! here refuses a present value outside that form with an [`EnvRefusal`] that
//! names the variable and the form, so a typo never selects a default. The
//! registry ([`crate::env_registry`]) binds each variable name to one grammar.

/// How a variable's value may be shown and documented.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    /// A runtime knob that changes behaviour or performance.
    Tunable,
    /// A credential: its value never reaches a message or a log line.
    Secret,
    /// A security-boundary switch: loosening it widens the trust boundary.
    SecurityTunable,
    /// Set by an Ipê supervisor on a child process, never by an operator.
    Internal,
}

/// The one form a registered variable accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Grammar {
    /// A TCP port a listener may bind: ASCII digits, `1..=65535`.
    Port,
    /// A boolean switch: [`EnvFlag`].
    Flag,
    /// One name of a closed, lowercase set, matched after an ASCII-lowercase fold.
    Choice(&'static [&'static str]),
    /// A decimal ceiling under [`crate::system::EnvCeiling`]'s rules.
    Ceiling(crate::system::EnvCeiling),
    /// A host list under [`crate::inbound_authority::DeclaredNames::parse`]'s rules.
    HostNames,
    /// A name no longer read; setting it is refused.
    Retired {
        /// The variable that replaced it, if any.
        use_instead: Option<&'static str>,
    },
}

impl Grammar {
    /// The accepted form, as the phrase completing "`NAME` must be …".
    #[must_use]
    pub fn expected(&self) -> String {
        match self {
            Self::Port => "a TCP port in 1..=65535".to_owned(),
            Self::Flag => format!("one of {}", EnvFlag::SPELLINGS.join(", ")),
            Self::Choice(names) => format!("one of {}", names.join(", ")),
            Self::Ceiling(ceiling) => format!("a {}", ceiling.unit()),
            Self::HostNames => {
                "a comma-separated list of DNS names or dot-prefixed DNS suffixes".to_owned()
            }
            Self::Retired { use_instead } => use_instead.map_or_else(
                || "unset (it is no longer read)".to_owned(),
                |name| format!("unset (it is no longer read; use {name})"),
            ),
        }
    }

    /// Judges a raw lookup of `name` against this grammar.
    ///
    /// # Errors
    ///
    /// The refusal naming `name` when the value is present but not in this form,
    /// or present at all for a retired name.
    pub fn check(
        self,
        name: &'static str,
        class: Class,
        raw: Result<String, std::env::VarError>,
    ) -> Result<(), EnvRefusal> {
        match self {
            Self::Port => judge(name, self, class, raw, ListenPort::parse).map(drop),
            Self::Flag => judge(name, self, class, raw, EnvFlag::parse).map(drop),
            Self::Choice(names) => judge(name, self, class, raw, |v| choose(names, v)).map(drop),
            Self::Ceiling(ceiling) => ceiling.parse(raw).map(drop).map_err(EnvRefusal::Ceiling),
            Self::HostNames => host_names(name, raw).map(drop),
            Self::Retired { use_instead } => match raw {
                Err(std::env::VarError::NotPresent) => Ok(()),
                Ok(_) | Err(std::env::VarError::NotUnicode(_)) => {
                    Err(EnvRefusal::Retired { name, use_instead })
                }
            },
        }
    }
}

/// Judges a raw lookup of `name` with `parse`, the grammar's own parser.
///
/// An unset variable is `Ok(None)`; an empty or non-Unicode value is refused
/// before `parse` sees it.
///
/// # Errors
///
/// The refusal naming `name` and `grammar` when the value is present but empty,
/// not Unicode, or refused by `parse`.
pub fn judge<T>(
    name: &'static str,
    grammar: Grammar,
    class: Class,
    raw: Result<String, std::env::VarError>,
    parse: impl FnOnce(&str) -> Option<T>,
) -> Result<Option<T>, EnvRefusal> {
    match raw {
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(os)) => Err(EnvRefusal::NotUnicode {
            name,
            grammar,
            class,
            shown: Shown::of(class, os.as_encoded_bytes()),
        }),
        Ok(value) if value.is_empty() => Err(EnvRefusal::Empty {
            name,
            grammar,
            class,
        }),
        Ok(value) => parse(&value)
            .map(Some)
            .ok_or_else(|| EnvRefusal::Malformed {
                name,
                grammar,
                class,
                shown: Shown::of(class, value.as_bytes()),
            }),
    }
}

/// Judges a raw lookup of the host list `name`; unset is the empty set.
///
/// A refusal names the variable and the refused item's position, never the
/// value.
///
/// # Errors
///
/// [`EnvRefusal::HostNames`] naming `name` when the value is set but is not a
/// host list, a non-Unicode item refused as malformed.
pub fn host_names(
    name: &'static str,
    raw: Result<String, std::env::VarError>,
) -> Result<crate::inbound_authority::DeclaredNames, EnvRefusal> {
    use crate::inbound_authority::{DeclaredNames, HostListRefusal, MAX_DECLARED_NAMES};
    let refused = |refusal| EnvRefusal::HostNames { name, refusal };
    match raw {
        Err(std::env::VarError::NotPresent) => Ok(DeclaredNames::none()),
        Err(std::env::VarError::NotUnicode(os)) => {
            let index = os
                .as_encoded_bytes()
                .split(|b| *b == b',')
                .position(|item| std::str::from_utf8(item).is_err())
                .unwrap_or(0);
            Err(refused(if index < MAX_DECLARED_NAMES {
                HostListRefusal::Malformed { index }
            } else {
                HostListRefusal::TooMany
            }))
        }
        Ok(value) => DeclaredNames::parse(&value).map_err(refused),
    }
}

/// The member of `names` that `raw` spells, after an ASCII-lowercase fold.
#[must_use]
pub fn choose(names: &'static [&'static str], raw: &str) -> Option<&'static str> {
    names
        .iter()
        .copied()
        .find(|name| raw.eq_ignore_ascii_case(name))
}

/// A boolean switch: exactly `1`, `true`, `on` or `0`, `false`, `off`, after an
/// ASCII-lowercase fold.
///
/// Surrounding whitespace is refused, not trimmed, so a quoting slip in a
/// deployment file is reported instead of read as a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvFlag {
    /// `1`, `true` or `on`.
    On,
    /// `0`, `false` or `off`.
    Off,
}

impl EnvFlag {
    /// Every accepted spelling, as a refusal lists them.
    pub const SPELLINGS: [&'static str; 6] = ["1", "true", "on", "0", "false", "off"];

    /// The switch `raw` spells, or `None` for any other text.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        let on = ["1", "true", "on"];
        let off = ["0", "false", "off"];
        if on.iter().any(|s| raw.eq_ignore_ascii_case(s)) {
            Some(Self::On)
        } else if off.iter().any(|s| raw.eq_ignore_ascii_case(s)) {
            Some(Self::Off)
        } else {
            None
        }
    }
}

/// A TCP port an HTTP listener may bind: `1..=65535`.
///
/// `0` (an OS-chosen ephemeral port the caller cannot reach) has no
/// representation, so neither an environment value nor a program value can
/// request it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ListenPort(std::num::NonZeroU16);

impl ListenPort {
    /// The port an environment value spells, or `None` for empty, non-numeric,
    /// signed, padded, `0`, or out-of-range text.
    ///
    /// Only ASCII digits are admitted: `u16`'s `FromStr` alone also accepts a
    /// leading `+`.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        raw.parse::<u16>()
            .ok()
            .and_then(std::num::NonZeroU16::new)
            .map(Self)
    }

    /// The port a program's integer names, or `None` outside `1..=65535`.
    #[must_use]
    pub fn from_program(port: i64) -> Option<Self> {
        u16::try_from(port)
            .ok()
            .and_then(std::num::NonZeroU16::new)
            .map(Self)
    }

    /// The port number.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0.get()
    }
}

/// A refused value as its refusal shows it.
///
/// Built only by [`Shown::of`]: a [`Class::Secret`] value is shown by length
/// alone, so its text cannot reach a message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Shown {
    /// The value, truncated and escaped so it can neither flood nor forge a line.
    Escaped(String),
    /// A secret's value, shown only by its length.
    Redacted {
        /// The value's length in bytes.
        bytes: usize,
    },
}

impl Shown {
    /// The form `raw`, read from a variable of `class`, takes in a refusal.
    #[must_use]
    pub fn of(class: Class, raw: &[u8]) -> Self {
        match class {
            Class::Secret => Self::Redacted { bytes: raw.len() },
            Class::Tunable | Class::SecurityTunable | Class::Internal => {
                Self::Escaped(crate::system::shown_env_value(raw))
            }
        }
    }
}

impl std::fmt::Display for Shown {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Escaped(text) => write!(f, "\"{text}\""),
            Self::Redacted { bytes } => write!(f, "<redacted, {bytes} bytes>"),
        }
    }
}

/// A present environment value its variable's grammar refuses, naming the
/// variable and the accepted form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EnvRefusal {
    /// The value is not in the variable's form.
    Malformed {
        /// The variable.
        name: &'static str,
        /// The form it accepts.
        grammar: Grammar,
        /// How it is shown.
        class: Class,
        /// The refused value, as shown.
        shown: Shown,
    },
    /// The value is not valid Unicode.
    NotUnicode {
        /// The variable.
        name: &'static str,
        /// The form it accepts.
        grammar: Grammar,
        /// How it is shown.
        class: Class,
        /// The refused bytes, as shown.
        shown: Shown,
    },
    /// The variable is set to the empty string.
    Empty {
        /// The variable.
        name: &'static str,
        /// The form it accepts.
        grammar: Grammar,
        /// How it is shown.
        class: Class,
    },
    /// A ceiling's own refusal.
    Ceiling(crate::system::EnvCeilingRefusal),
    /// A host list's own refusal; it never echoes the value.
    HostNames {
        /// The variable.
        name: &'static str,
        /// Why the list is refused.
        refusal: crate::inbound_authority::HostListRefusal,
    },
    /// A name no longer read is set.
    Retired {
        /// The retired variable.
        name: &'static str,
        /// The variable that replaced it, if any.
        use_instead: Option<&'static str>,
    },
}

impl EnvRefusal {
    /// The refused variable.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Malformed { name, .. }
            | Self::NotUnicode { name, .. }
            | Self::Empty { name, .. }
            | Self::HostNames { name, .. }
            | Self::Retired { name, .. } => name,
            Self::Ceiling(refusal) => refusal.name(),
        }
    }
}

/// The advice closing a refusal of a variable of `class`.
fn class_note(f: &mut std::fmt::Formatter<'_>, class: Class) -> std::fmt::Result {
    match class {
        Class::Internal => f.write_str(
            "; it is set by the dev supervisor (`ipe dev watch` or the dev console), \
             so restart the supervisor",
        ),
        Class::Tunable | Class::Secret | Class::SecurityTunable => Ok(()),
    }
}

impl std::fmt::Display for EnvRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed {
                name,
                grammar,
                class,
                shown,
            } => {
                write!(f, "{name} must be {} (got {shown})", grammar.expected())?;
                class_note(f, *class)
            }
            Self::NotUnicode {
                name,
                grammar,
                class,
                shown,
            } => {
                write!(
                    f,
                    "{name} must be {} (got {shown}, which is not valid Unicode)",
                    grammar.expected()
                )?;
                class_note(f, *class)
            }
            Self::Empty {
                name,
                grammar,
                class,
            } => {
                write!(
                    f,
                    "{name} must be {} (got an empty value)",
                    grammar.expected()
                )?;
                class_note(f, *class)
            }
            Self::Ceiling(refusal) => refusal.fmt(f),
            Self::HostNames { name, refusal } => write!(f, "{name} {refusal}"),
            Self::Retired { name, use_instead } => match use_instead {
                Some(other) => write!(f, "{name} is no longer read; set {other} instead"),
                None => write!(f, "{name} is no longer read; unset it"),
            },
        }
    }
}

impl std::error::Error for EnvRefusal {}

impl From<EnvRefusal> for crate::error::IpeError {
    fn from(refusal: EnvRefusal) -> Self {
        Self::invalid_input(refusal.to_string())
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use std::env::VarError;

    const NAME: &str = "IPE_GRAMMAR_PROBE";

    fn port(raw: &str) -> Result<Option<ListenPort>, EnvRefusal> {
        judge(
            NAME,
            Grammar::Port,
            Class::Tunable,
            Ok(raw.to_owned()),
            ListenPort::parse,
        )
    }

    #[test]
    fn port_refuses_every_text_outside_one_to_65535() {
        for raw in [
            " 8080",
            "8080 ",
            "\t8080",
            "+8080",
            "-1",
            "0",
            "65536",
            "99999",
            "8o80",
            "0x1F90",
            "８０８０",
        ] {
            let refusal = port(raw);
            assert!(
                matches!(refusal, Err(EnvRefusal::Malformed { name: NAME, .. })),
                "{raw:?} must be refused: {refusal:?}"
            );
            let Err(refusal) = refusal else { return };
            let text = refusal.to_string();
            assert!(
                text.starts_with(&format!("{NAME} must be a TCP port in 1..=65535 (got \"")),
                "{text}"
            );
        }
        assert!(matches!(
            port(""),
            Err(EnvRefusal::Empty { name: NAME, .. })
        ));
    }

    #[test]
    fn port_accepts_both_bounds() {
        assert_eq!(port("1").ok().flatten().map(ListenPort::get), Some(1));
        assert_eq!(
            port("65535").ok().flatten().map(ListenPort::get),
            Some(65535)
        );
        assert_eq!(
            judge(
                NAME,
                Grammar::Port,
                Class::Tunable,
                Err(VarError::NotPresent),
                ListenPort::parse
            ),
            Ok(None)
        );
    }

    #[test]
    fn program_port_refuses_zero_and_out_of_range() {
        for port in [0, -1, 65_536, 70_000, i64::MAX, i64::MIN] {
            assert_eq!(ListenPort::from_program(port), None, "{port}");
        }
        assert_eq!(ListenPort::from_program(1).map(ListenPort::get), Some(1));
        assert_eq!(
            ListenPort::from_program(65_535).map(ListenPort::get),
            Some(65_535)
        );
    }

    #[test]
    fn flag_refuses_every_spelling_outside_its_six() {
        for raw in ["", " on", "on ", "yes", "no", "2", "enabled", "onn"] {
            assert_eq!(EnvFlag::parse(raw), None, "{raw:?}");
        }
        assert_eq!(EnvFlag::parse("ON"), Some(EnvFlag::On));
        assert_eq!(EnvFlag::parse("True"), Some(EnvFlag::On));
        assert_eq!(EnvFlag::parse("0"), Some(EnvFlag::Off));
    }

    /// Every case fold of the six spellings is accepted to its value, and no
    /// other spelling is.
    #[test]
    fn flag_accepted_set_is_exactly_six_spellings_case_folded() {
        for spelling in EnvFlag::SPELLINGS {
            let expected = if ["1", "true", "on"].contains(&spelling) {
                EnvFlag::On
            } else {
                EnvFlag::Off
            };
            let n = spelling.chars().count();
            for mask in 0u32..(1 << n) {
                let folded: String = spelling
                    .chars()
                    .enumerate()
                    .map(|(i, c)| {
                        if mask & (1 << i) == 0 {
                            c
                        } else {
                            c.to_ascii_uppercase()
                        }
                    })
                    .collect();
                assert_eq!(EnvFlag::parse(&folded), Some(expected), "{folded:?}");
            }
        }
    }

    /// Any string outside the six case-folded spellings is refused.
    #[test]
    fn flag_refuses_any_other_string() {
        let alphabet = [
            '0', '1', '2', 'e', 'f', 'n', 'o', 'r', 't', 'u', 'F', 'O', ' ', 'é',
        ];
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        for _ in 0..20_000 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let len = usize::try_from(state >> 61).unwrap_or(0);
            let text: String = (0..len)
                .map(|i| {
                    let pick = usize::try_from((state >> (i * 4)) & 0xF).unwrap_or(0);
                    alphabet.get(pick % alphabet.len()).copied().unwrap_or('x')
                })
                .collect();
            let accepted = EnvFlag::SPELLINGS
                .iter()
                .any(|s| text.eq_ignore_ascii_case(s));
            assert_eq!(EnvFlag::parse(&text).is_some(), accepted, "{text:?}");
        }
    }

    #[test]
    fn choice_refuses_unmatched_padded_and_empty() {
        const NAMES: &[&str] = &["debug", "info"];
        let grammar = Grammar::Choice(NAMES);
        let choice = |raw: &str| {
            judge(NAME, grammar, Class::Tunable, Ok(raw.to_owned()), |v| {
                choose(NAMES, v)
            })
        };
        assert_eq!(choice("INFO"), Ok(Some("info")));
        assert_eq!(choice("debug"), Ok(Some("debug")));
        for raw in ["verbose", " info", "info ", "inf"] {
            let refusal = choice(raw);
            assert!(
                matches!(refusal, Err(EnvRefusal::Malformed { .. })),
                "{raw:?}: {refusal:?}"
            );
            let Err(refusal) = refusal else { return };
            assert!(
                refusal
                    .to_string()
                    .starts_with(&format!("{NAME} must be one of debug, info (got ")),
                "{refusal}"
            );
        }
        assert!(matches!(choice(""), Err(EnvRefusal::Empty { .. })));
    }

    /// A secret's refused value never reaches the message, a line break included.
    #[test]
    fn secret_refusal_shows_only_the_length() {
        let token = "s3cr3t\n[ERROR] forged";
        let refusal = judge(
            NAME,
            Grammar::Port,
            Class::Secret,
            Ok(token.to_owned()),
            ListenPort::parse,
        );
        let Err(refusal) = refusal else {
            assert!(refusal.is_err(), "a token is not a port");
            return;
        };
        let text = refusal.to_string();
        assert!(!text.contains("s3cr3t") && !text.contains('\n'), "{text}");
        assert!(
            text.contains(&format!("<redacted, {} bytes>", token.len())),
            "{text}"
        );
    }

    /// A tunable's refused value is escaped onto one line.
    #[test]
    fn tunable_refusal_escapes_the_value() {
        let refusal = port("80\n[ERROR] forged");
        let Err(refusal) = refusal else {
            assert!(refusal.is_err(), "a forged line is not a port");
            return;
        };
        let text = refusal.to_string();
        assert!(!text.contains('\n') && text.contains("\\n"), "{text}");
    }

    #[cfg(unix)]
    #[test]
    fn non_unicode_value_is_refused_naming_the_variable() {
        use std::os::unix::ffi::OsStringExt;
        let raw = Err(VarError::NotUnicode(std::ffi::OsString::from_vec(vec![
            b'8', 0xFF,
        ])));
        let refusal = judge(NAME, Grammar::Port, Class::Tunable, raw, ListenPort::parse);
        assert!(
            matches!(refusal, Err(EnvRefusal::NotUnicode { name: NAME, .. })),
            "{refusal:?}"
        );
        let Err(refusal) = refusal else { return };
        assert!(refusal.to_string().contains("\\xFF"), "{refusal}");
    }

    #[test]
    fn internal_refusal_names_the_dev_supervisor() {
        let refusal = judge(
            NAME,
            Grammar::Port,
            Class::Internal,
            Ok("x".to_owned()),
            ListenPort::parse,
        );
        let Err(refusal) = refusal else {
            assert!(refusal.is_err(), "`x` is not a port");
            return;
        };
        assert!(refusal.to_string().contains("dev supervisor"), "{refusal}");
    }

    #[test]
    fn retired_name_is_refused_only_when_set() {
        let grammar = Grammar::Retired {
            use_instead: Some("IPE_GRAMMAR_NEW"),
        };
        assert_eq!(
            grammar.check(NAME, Class::Tunable, Err(VarError::NotPresent)),
            Ok(())
        );
        let refusal = grammar.check(NAME, Class::Tunable, Ok("1".to_owned()));
        assert_eq!(
            refusal,
            Err(EnvRefusal::Retired {
                name: NAME,
                use_instead: Some("IPE_GRAMMAR_NEW"),
            })
        );
        let Err(refusal) = refusal else { return };
        assert_eq!(
            refusal.to_string(),
            format!("{NAME} is no longer read; set IPE_GRAMMAR_NEW instead")
        );
    }

    /// A host list refusal names the variable and the item, never the value;
    /// unset is the empty set, and a list of exactly the most names parses.
    #[test]
    fn host_list_refusals_name_the_item_never_the_value() {
        use crate::inbound_authority::{HostListRefusal, MAX_DECLARED_NAMES};
        let check =
            |raw: &str| Grammar::HostNames.check(NAME, Class::SecurityTunable, Ok(raw.to_owned()));
        let list = |n: usize| {
            (0..n)
                .map(|i| format!("hidden{i}.example"))
                .collect::<Vec<_>>()
                .join(",")
        };
        let too_many = list(MAX_DECLARED_NAMES + 1);
        for (raw, refusal) in [
            ("", HostListRefusal::Empty),
            ("hidden.example:80", HostListRefusal::Malformed { index: 0 }),
            ("hidden.example, *", HostListRefusal::Malformed { index: 1 }),
            ("hidden.example,,", HostListRefusal::Malformed { index: 1 }),
            (
                "127.0.0.1, hidden.example",
                HostListRefusal::Malformed { index: 0 },
            ),
            ("hidden.localhost", HostListRefusal::Malformed { index: 0 }),
            (too_many.as_str(), HostListRefusal::TooMany),
        ] {
            let judged = check(raw);
            assert_eq!(
                judged,
                Err(EnvRefusal::HostNames {
                    name: NAME,
                    refusal
                }),
                "{raw:?}"
            );
            let Err(judged) = judged else { return };
            let text = judged.to_string();
            assert!(text.starts_with(&format!("{NAME} ")), "{text}");
            assert!(!text.contains("hidden"), "{text}");
        }
        assert_eq!(check(&list(MAX_DECLARED_NAMES)), Ok(()));
        assert_eq!(check("hidden.example, .sub.example"), Ok(()));
        assert_eq!(
            host_names(NAME, Err(VarError::NotPresent)),
            Ok(crate::inbound_authority::DeclaredNames::none())
        );
        assert_eq!(
            host_names(NAME, Ok("a.example, .b.example".to_owned()))
                .as_ref()
                .map(crate::inbound_authority::DeclaredNames::len),
            Ok(2)
        );
    }

    /// A non-Unicode host list item is refused as malformed by its position,
    /// never echoed.
    #[cfg(unix)]
    #[test]
    fn non_unicode_host_list_item_is_refused_by_position() {
        use crate::inbound_authority::HostListRefusal;
        use std::os::unix::ffi::OsStringExt;
        let raw = Err(VarError::NotUnicode(std::ffi::OsString::from_vec(
            b"ok.example,\xFFhidden".to_vec(),
        )));
        let refusal = host_names(NAME, raw);
        assert_eq!(
            refusal,
            Err(EnvRefusal::HostNames {
                name: NAME,
                refusal: HostListRefusal::Malformed { index: 1 }
            })
        );
        let Err(refusal) = refusal else { return };
        let text = refusal.to_string();
        assert!(
            !text.contains("hidden") && !text.contains("\\xFF"),
            "{text}"
        );
    }
}
