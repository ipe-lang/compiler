//! Security-boundary switches and credentials, and the posture they set.
//!
//! Every variable here is read once, before the program's first line, into the
//! process's [`SecurityPosture`]; consumers read that snapshot, never the
//! environment, so a value the program writes while it runs cannot move the
//! posture.

use super::{
    ChoiceKey, DefaultValue, Doc, EnvEntry, Feature, FlagKey, Lifetime, ScopedFlagKey, SecretKey,
    SecretSetting, Subsystem,
};
use crate::env_grammar::{Class, EnvFlag};

/// Whether a mutating `Ipe.Web` request's `Origin` must name the request's own authority.
pub const WEB_CSRF_ORIGIN_CHECK: FlagKey = FlagKey::new(
    "IPE_WEB_CSRF_ORIGIN_CHECK",
    EnvFlag::On,
    Doc {
        class: Class::SecurityTunable,
        feature: Feature::Web,
        lifetime: Lifetime::Startup,
        subsystem: Subsystem::Web,
        purpose: "Same-origin check on mutating `Ipe.Web` requests, on top of the \
                  double-submit CSRF token: a request carrying an `Origin` header is \
                  refused unless that origin names the request's authority (its \
                  `Host`, else the authority of its target URI), and a request with \
                  an `Origin` but no authority is refused too. On by default. `1`, \
                  `true`, `on`, `0`, `false` or `off`, ASCII case-insensitive; any \
                  other value, an empty one included, refuses startup. Set it `off` \
                  behind a reverse proxy that rewrites `Host`. Not applied while \
                  `IPE_WEB_FRAME_ANCESTORS` allows embedding. Read once at process \
                  start.",
    },
);

/// Whether `Ipe.Web` checks the double-submit CSRF token on mutating requests.
pub const CSRF: FlagKey = FlagKey::new(
    "IPE_CSRF",
    EnvFlag::On,
    Doc {
        class: Class::SecurityTunable,
        feature: Feature::Web,
        lifetime: Lifetime::Startup,
        subsystem: Subsystem::Web,
        purpose: "CSRF protection on mutating `Ipe.Web` requests. On by default; `0`, \
                  `false` or `off` disables it, which widens the trust boundary and is \
                  only safe on loopback in automated tests. A `Web.csrf` setting can \
                  enforce it but never disable it. `1`, `true`, `on`, `0`, `false` or \
                  `off`, ASCII case-insensitive; any other value, an empty one \
                  included, refuses startup. Read once at process start, so a later \
                  `System.setenv` or `System.loadEnv` does not change it.",
    },
);

/// Whether forwarding headers from a reverse proxy are trusted.
pub const TRUSTED_PROXY: FlagKey = FlagKey::new(
    "IPE_TRUSTED_PROXY",
    EnvFlag::Off,
    Doc {
        class: Class::SecurityTunable,
        feature: Feature::Server,
        lifetime: Lifetime::Startup,
        subsystem: Subsystem::Web,
        purpose: "Trust `X-Forwarded-For` / `X-Forwarded-Proto` for the remote address \
                  and TLS detection of `Ipe.Http.Server` and `Ipe.Web` requests. Off by \
                  default, so a client cannot forge these headers; set it on only when \
                  a trusted reverse proxy sits in front of this process. `1`, `true`, \
                  `on`, `0`, `false` or `off`, ASCII case-insensitive; any other value, \
                  an empty one included, refuses startup. Read once at process start, \
                  so a later `System.setenv` or `System.loadEnv` does not change it.",
    },
);

/// Whether CSV output quotes cells a spreadsheet would read as a formula.
pub const CSV_SANITIZE_FORMULAS: FlagKey = FlagKey::new(
    "IPE_CSV_SANITIZE_FORMULAS",
    EnvFlag::Off,
    Doc {
        class: Class::SecurityTunable,
        feature: Feature::Csv,
        lifetime: Lifetime::Startup,
        subsystem: Subsystem::Csv,
        purpose: "Prefix a CSV output cell starting with `=`, `+`, `-`, `@`, a tab or a \
                  carriage return with a single quote, so a spreadsheet does not run it \
                  as a formula. Off by default, because the prefix changes the data \
                  (`-5` becomes `'-5`) and breaks the parse/encode round trip; turn it \
                  on when serving CSV to spreadsheet users. `1`, `true`, `on`, `0`, \
                  `false` or `off`, ASCII case-insensitive; any other value, an empty \
                  one included, refuses startup. Read once at process start.",
    },
);

/// Whether outbound dials to private, loopback and link-local addresses are refused.
pub const HTTP_DENY_PRIVATE: ScopedFlagKey = ScopedFlagKey::new(
    "IPE_HTTP_DENY_PRIVATE",
    "unset (on; off only in a dev binary with no listener beyond loopback)",
    Doc {
        class: Class::SecurityTunable,
        feature: Feature::Dial,
        lifetime: Lifetime::Startup,
        subsystem: Subsystem::Http,
        purpose: "Refuse every outbound HTTP, WebSocket, SMTP and database connection \
                  to an RFC-1918 private, loopback or link-local address, closing the \
                  SSRF surface. Unset, the guard is on in every `ipe release` artifact \
                  and production posture, and off only in a development binary in a \
                  dev posture that has bound no listener beyond loopback. `1`, `true`, \
                  `on`, `0`, `false` or `off`, ASCII case-insensitive; any other value, \
                  an empty one included, refuses startup. Read once at process start, \
                  so a later `System.setenv` or `System.loadEnv` does not change it.",
    },
);

/// The console and metrics surface's authentication mode.
pub const CONSOLE_AUTH: ChoiceKey = ChoiceKey::new(
    "IPE_CONSOLE_AUTH",
    &["token", "app", "off"],
    DefaultValue::Text("unset (token; open only in a dev build on loopback)"),
    Doc {
        class: Class::SecurityTunable,
        feature: Feature::Web,
        lifetime: Lifetime::Startup,
        subsystem: Subsystem::Console,
        purpose: "Console authentication mode: `token` (admin-token gate, enforced in \
                  every posture, dev included), `off` (console disabled), `app` (app \
                  callback; mounted but answers 501 on the Rust runtime), ASCII \
                  case-insensitive. Any other value, an empty or padded one included, \
                  refuses startup. Unset, the posture picks the mode: a binary from \
                  `ipe dev build`, `ipe dev run`, `ipe test` or `ipe dev watch` in \
                  development posture bound to loopback defaults open; every other \
                  binary, including every `ipe release` artifact, and every exposed \
                  bind default to `token`, so the console stays closed until a \
                  credential is set. The effective posture, mode, and source are \
                  logged once at startup (`[ipe.console] auth posture=… mode=… \
                  source=env|posture-default`); no token is ever logged. Read once at \
                  process start.",
    },
);

/// The admin credential of the console and metrics surface.
pub const ADMIN_TOKEN: SecretKey = SecretKey::new(
    "IPE_ADMIN_TOKEN",
    Doc {
        class: Class::Secret,
        feature: Feature::Web,
        lifetime: Lifetime::Startup,
        subsystem: Subsystem::Console,
        purpose: "Admin token (`Bearer`, or the `Basic` password) granting access to the \
                  embedded developer console and `/_ipe/metrics` in production or under \
                  `IPE_CONSOLE_AUTH=token`. Provide via your secret manager; never \
                  commit. Falls back to the in-code `Console.adminToken`, then \
                  `IPE_CONSOLE_TOKEN`. An empty or non-UTF-8 value refuses startup. \
                  Read once at process start.",
    },
);

/// The deprecated alias of [`ADMIN_TOKEN`], last in the admin credential chain.
pub const CONSOLE_TOKEN: SecretKey = SecretKey::new(
    "IPE_CONSOLE_TOKEN",
    Doc {
        class: Class::Secret,
        feature: Feature::Web,
        lifetime: Lifetime::Startup,
        subsystem: Subsystem::Console,
        purpose: "Deprecated alias for `IPE_ADMIN_TOKEN`. Prefer `IPE_ADMIN_TOKEN`. \
                  Provide via your secret manager; never commit. An empty or non-UTF-8 \
                  value refuses startup. Read once at process start.",
    },
);

/// The metrics-scrape credential.
pub const METRICS_TOKEN: SecretKey = SecretKey::new(
    "IPE_METRICS_TOKEN",
    Doc {
        class: Class::Secret,
        feature: Feature::Web,
        lifetime: Lifetime::Startup,
        subsystem: Subsystem::Console,
        purpose: "Metrics-scrape token (`Bearer`, or the `Basic` password) authorizing \
                  `/_ipe/metrics` only, never the console; the admin token is accepted \
                  there too. Falls back to the in-code `Console.metricsToken`. An empty \
                  or non-UTF-8 value refuses startup. Provide via your secret manager; \
                  never commit. Read once at process start.",
    },
);

/// The credential the observability ingest gate checks.
pub const INGEST_TOKEN: SecretKey = SecretKey::new(
    "IPE_INGEST_TOKEN",
    Doc {
        class: Class::Secret,
        feature: Feature::Web,
        lifetime: Lifetime::Startup,
        subsystem: Subsystem::Console,
        purpose: "Bearer token the parent ingest gate checks on `X-Ipê-Ingest-Token`. \
                  Required when a sub-app pushes telemetry to a parent app's \
                  `/_ipe/ingest` endpoint. Falls back to the in-code \
                  `Console.ingestToken`. An empty or non-UTF-8 value refuses startup. \
                  Provide via your secret manager. Read once at process start.",
    },
);

/// This subsystem's entries.
pub const ENTRIES: &[EnvEntry] = &[
    WEB_CSRF_ORIGIN_CHECK.entry(),
    CSRF.entry(),
    TRUSTED_PROXY.entry(),
    CSV_SANITIZE_FORMULAS.entry(),
    HTTP_DENY_PRIVATE.entry(),
    CONSOLE_AUTH.entry(),
    ADMIN_TOKEN.entry(),
    CONSOLE_TOKEN.entry(),
    METRICS_TOKEN.entry(),
    INGEST_TOKEN.entry(),
];

/// Whether the forwarding headers of a request are believed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyTrust {
    /// The client's own forwarding headers are ignored.
    Untrusted,
    /// A trusted reverse proxy sets the forwarding headers.
    Trusted,
}

impl ProxyTrust {
    /// Whether forwarding headers are believed.
    #[must_use]
    pub const fn trusts(self) -> bool {
        matches!(self, Self::Trusted)
    }
}

/// The `IPE_CONSOLE_AUTH` reading.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsoleAuthSetting {
    /// The variable is unset: the posture picks the mode.
    Unset,
    /// The accepted mode name the variable spells, lowercase.
    Named(&'static str),
    /// The variable is set but refused: the surface is declared absent.
    Refused,
}

/// The security posture the operator's environment sets, read once per process.
///
/// `Debug` masks every credential setting, whatever its reading.
#[derive(Clone, PartialEq, Eq)]
pub struct SecurityPosture {
    /// `IPE_TRUSTED_PROXY`.
    pub trusted_proxy: ProxyTrust,
    /// `IPE_CSRF`.
    pub csrf: EnvFlag,
    /// `IPE_WEB_CSRF_ORIGIN_CHECK`.
    pub csrf_origin_check: EnvFlag,
    /// `IPE_CSV_SANITIZE_FORMULAS`.
    pub csv_formula_guard: EnvFlag,
    /// `IPE_HTTP_DENY_PRIVATE`; `None` while unset, where the process's posture picks.
    pub deny_private: Option<EnvFlag>,
    /// `IPE_CONSOLE_AUTH`.
    pub console_auth: ConsoleAuthSetting,
    /// `IPE_ADMIN_TOKEN`.
    pub admin_token: SecretSetting,
    /// `IPE_CONSOLE_TOKEN`.
    pub console_token: SecretSetting,
    /// `IPE_METRICS_TOKEN`.
    pub metrics_token: SecretSetting,
    /// `IPE_INGEST_TOKEN`.
    pub ingest_token: SecretSetting,
}

crate::redact::redacting_debug!(SecurityPosture {
    shown: [
        trusted_proxy,
        csrf,
        csrf_origin_check,
        csv_formula_guard,
        deny_private,
        console_auth,
    ],
    masked: [admin_token, console_token, metrics_token, ingest_token],
});

impl SecurityPosture {
    /// The posture `lookup` reports, each variable judged by its registered grammar.
    ///
    /// A refused value takes the closed position: startup refuses it first, so
    /// this is reached only where no startup check ran.
    #[must_use]
    pub fn from_lookup(lookup: impl Fn(&str) -> Result<String, std::env::VarError>) -> Self {
        let flag = |key: FlagKey, closed: EnvFlag| key.parse(lookup(key.name())).unwrap_or(closed);
        Self {
            trusted_proxy: match flag(TRUSTED_PROXY, EnvFlag::Off) {
                EnvFlag::On => ProxyTrust::Trusted,
                EnvFlag::Off => ProxyTrust::Untrusted,
            },
            csrf: flag(CSRF, EnvFlag::On),
            csrf_origin_check: flag(WEB_CSRF_ORIGIN_CHECK, EnvFlag::On),
            csv_formula_guard: flag(CSV_SANITIZE_FORMULAS, EnvFlag::On),
            deny_private: HTTP_DENY_PRIVATE
                .parse(lookup(HTTP_DENY_PRIVATE.name()))
                .unwrap_or(Some(EnvFlag::On)),
            console_auth: match CONSOLE_AUTH.parse(lookup(CONSOLE_AUTH.name())) {
                Ok(None) => ConsoleAuthSetting::Unset,
                Ok(Some(name)) => ConsoleAuthSetting::Named(name),
                Err(_) => ConsoleAuthSetting::Refused,
            },
            admin_token: ADMIN_TOKEN.parse(lookup(ADMIN_TOKEN.name())),
            console_token: CONSOLE_TOKEN.parse(lookup(CONSOLE_TOKEN.name())),
            metrics_token: METRICS_TOKEN.parse(lookup(METRICS_TOKEN.name())),
            ingest_token: INGEST_TOKEN.parse(lookup(INGEST_TOKEN.name())),
        }
    }
}

/// The process's security posture.
///
/// Fixed by [`super::startup_check`] before the program's first line, so a
/// value the program writes later is never read.
pub fn security_posture() -> &'static SecurityPosture {
    static POSTURE: std::sync::OnceLock<SecurityPosture> = std::sync::OnceLock::new();
    POSTURE.get_or_init(|| SecurityPosture::from_lookup(crate::system::read_env_var))
}

/// Fixes [`security_posture`] for the process.
pub fn fix_posture() {
    security_posture();
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::env_registry::check_entries;
    use std::env::VarError;

    /// A lookup answering `pairs`, every other name unset.
    fn lookup(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Result<String, VarError> {
        let pairs: Vec<(String, String)> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |name| {
            pairs
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.clone())
                .ok_or(VarError::NotPresent)
        }
    }

    /// Unset, every switch takes its declared default.
    #[test]
    fn unset_posture_takes_the_defaults() {
        let posture = SecurityPosture::from_lookup(lookup(&[]));
        assert_eq!(posture.trusted_proxy, ProxyTrust::Untrusted);
        assert_eq!(posture.csrf, EnvFlag::On);
        assert_eq!(posture.csrf_origin_check, EnvFlag::On);
        assert_eq!(posture.csv_formula_guard, EnvFlag::Off);
        assert_eq!(posture.deny_private, None);
        assert_eq!(posture.console_auth, ConsoleAuthSetting::Unset);
        assert_eq!(posture.admin_token, SecretSetting::Unset);
        assert_eq!(posture.ingest_token, SecretSetting::Unset);
    }

    /// A value outside a switch's grammar reads the closed position, never the open one.
    #[test]
    fn refused_values_read_closed() {
        let posture = SecurityPosture::from_lookup(lookup(&[
            ("IPE_TRUSTED_PROXY", "yes"),
            ("IPE_CSRF", "maybe"),
            ("IPE_WEB_CSRF_ORIGIN_CHECK", ""),
            ("IPE_CSV_SANITIZE_FORMULAS", "no "),
            ("IPE_HTTP_DENY_PRIVATE", "nope"),
            ("IPE_CONSOLE_AUTH", "open"),
            ("IPE_ADMIN_TOKEN", ""),
        ]));
        assert_eq!(posture.trusted_proxy, ProxyTrust::Untrusted);
        assert_eq!(posture.csrf, EnvFlag::On);
        assert_eq!(posture.csrf_origin_check, EnvFlag::On);
        assert_eq!(posture.csv_formula_guard, EnvFlag::On);
        assert_eq!(posture.deny_private, Some(EnvFlag::On));
        assert_eq!(posture.console_auth, ConsoleAuthSetting::Refused);
        assert_eq!(posture.admin_token, SecretSetting::Refused);
    }

    /// Each accepted spelling reads its position.
    #[test]
    fn accepted_values_read_their_position() {
        let posture = SecurityPosture::from_lookup(lookup(&[
            ("IPE_TRUSTED_PROXY", "TRUE"),
            ("IPE_CSRF", "off"),
            ("IPE_CSV_SANITIZE_FORMULAS", "1"),
            ("IPE_HTTP_DENY_PRIVATE", "0"),
            ("IPE_CONSOLE_AUTH", "Token"),
            ("IPE_METRICS_TOKEN", "m-token"),
        ]));
        assert_eq!(posture.trusted_proxy, ProxyTrust::Trusted);
        assert_eq!(posture.csrf, EnvFlag::Off);
        assert_eq!(posture.csv_formula_guard, EnvFlag::On);
        assert_eq!(posture.deny_private, Some(EnvFlag::Off));
        assert_eq!(posture.console_auth, ConsoleAuthSetting::Named("token"));
        assert!(matches!(&posture.metrics_token, SecretSetting::Set(s) if s.expose() == "m-token"));
    }

    /// A credential is never shown, neither by the posture's `Debug` nor by a refusal.
    #[test]
    fn credentials_are_never_shown() {
        let posture =
            SecurityPosture::from_lookup(lookup(&[("IPE_ADMIN_TOKEN", "hunter2-secret")]));
        let shown = format!("{posture:?}");
        assert!(!shown.contains("hunter2"), "{shown}");
        assert!(
            !shown.contains("Set("),
            "a set credential's reading shown: {shown}"
        );
        assert_eq!(
            format!("{INGEST_TOKEN:?}"),
            "SecretKey(\"IPE_INGEST_TOKEN\")"
        );
        crate::system::locked_set_var(INGEST_TOKEN.name(), "hunter2-secret");
        let refused = INGEST_TOKEN.entry().check();
        crate::system::locked_remove_var(INGEST_TOKEN.name());
        assert!(refused.is_ok(), "{refused:?}");
        let refusal = crate::env_grammar::judge(
            ADMIN_TOKEN.name(),
            crate::env_grammar::Grammar::Secret,
            Class::Secret,
            Err(VarError::NotUnicode(std::ffi::OsString::from(
                "hunter2-secret",
            ))),
            |_| Some(()),
        );
        let Err(refusal) = refusal else {
            assert!(refusal.is_err(), "a non-Unicode credential is refused");
            return;
        };
        let text = refusal.to_string();
        assert!(text.contains("IPE_ADMIN_TOKEN"), "{text}");
        assert!(!text.contains("hunter2"), "{text}");
    }

    /// A malformed switch refuses startup naming the variable.
    #[test]
    fn malformed_switch_refuses_startup_naming_it() {
        for entry in [
            CSRF.entry(),
            TRUSTED_PROXY.entry(),
            CSV_SANITIZE_FORMULAS.entry(),
            HTTP_DENY_PRIVATE.entry(),
        ] {
            crate::system::locked_set_var(entry.name(), "maybe");
            let refusals = check_entries(std::iter::once(&entry));
            crate::system::locked_remove_var(entry.name());
            if entry.feature().is_compiled() {
                assert_eq!(refusals.len(), 1, "{}: {refusals:?}", entry.name());
                assert!(refusals.iter().all(|r| r.name() == entry.name()));
            } else {
                assert!(refusals.is_empty(), "{refusals:?}");
            }
        }
    }

    /// The deny-private switch states no fixed default: unset, the process's
    /// posture picks, so the reference never shows one position as its default.
    #[test]
    fn deny_private_documents_a_posture_scoped_default() {
        let entry = HTTP_DENY_PRIVATE.entry();
        assert!(
            matches!(entry.default(), DefaultValue::Scoped(_)),
            "{:?}",
            entry.default()
        );
        assert!(entry.default_fits_grammar());
        let shown = entry.default().to_string();
        assert!(shown.starts_with("unset"), "{shown}");
        assert_ne!(shown, DefaultValue::Flag(EnvFlag::On).to_string());
        assert_eq!(SecurityPosture::from_lookup(lookup(&[])).deny_private, None);
    }

    /// Once fixed, the posture ignores a value written after startup.
    #[test]
    fn a_value_written_after_startup_does_not_move_the_posture() {
        let written = [
            ("IPE_CSRF", "off"),
            ("IPE_TRUSTED_PROXY", "1"),
            ("IPE_CSV_SANITIZE_FORMULAS", "0"),
            ("IPE_HTTP_DENY_PRIVATE", "off"),
            ("IPE_ADMIN_TOKEN", "planted"),
        ];
        for (name, _) in written {
            crate::system::locked_remove_var(name);
        }
        fix_posture();
        let before = security_posture().clone();
        for (name, value) in written {
            crate::system::locked_set_var(name, value);
        }
        let after = security_posture().clone();
        for (name, _) in written {
            crate::system::locked_remove_var(name);
        }
        assert_eq!(before, after);
        assert_eq!(after.trusted_proxy, ProxyTrust::Untrusted);
        assert_eq!(after.csrf, EnvFlag::On);
        assert_eq!(after.admin_token, SecretSetting::Unset);
    }
}
