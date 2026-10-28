//! Single source of truth for the crate versions, and the fixed feature sets,
//! the Rust codegen emits.
//!
//! The default native emit is the dependency model: third-party versions live
//! in the runtime crate's own `runtime/rust/Cargo.toml`, and the emitted native
//! `Cargo.toml` names only the `ipe_runtime` path dependency — it carries no
//! third-party versions. These specs still drive the versions the vendored
//! fallback and the WASM template surgeries emit, so they must not drift from
//! the runtime crate's manifest.
//!
//! A [`CrateSpec`] fixes a version only; the emitter composes that crate's
//! features per program. A [`PinnedCrate`] also fixes `default-features` and the
//! exact feature set, and renders its whole dependency line, so a manifest can
//! only spell the set the runtime is built and audited with (a TLS or root-store
//! feature arm is part of that set). The `crate_specs_match_manifests` test
//! below is the drift tripwire: it pins every version against
//! `runtime/rust/Cargo.toml`, every pinned feature set against the runtime line
//! in both directions, and, for any crate the golden base manifest still
//! declares, the version against `tests/golden/basics/Cargo.toml`.

/// One authoritative crate version. The emitter composes this crate's features.
#[derive(Clone, Copy, Debug)]
pub struct CrateSpec {
    pub name: &'static str,
    pub version: &'static str,
}

/// A crate whose version, `default-features` and exact feature set are all
/// fixed here: every manifest that names it spells this line.
#[derive(Clone, Copy, Debug)]
pub struct PinnedCrate {
    pub spec: CrateSpec,
    /// Whether the crate's default features stay on.
    pub default_features: bool,
    /// The exact features enabled on top of the defaults (or of none).
    pub features: &'static [&'static str],
}

impl PinnedCrate {
    /// The `name = ...` dependency line, enabling `features` followed by
    /// `extra` (program-specific additions the caller owns, such as the
    /// database drivers).
    #[must_use]
    pub fn dependency_line(&self, extra: &[&str]) -> String {
        let mut list = String::new();
        for (at, feature) in self.features.iter().chain(extra).enumerate() {
            if at > 0 {
                list.push_str(", ");
            }
            list.push('"');
            list.push_str(feature);
            list.push('"');
        }
        let name = self.spec.name;
        let version = self.spec.version;
        match (self.default_features, list.is_empty()) {
            (true, true) => format!("{name} = \"{version}\""),
            (true, false) => format!("{name} = {{ version = \"{version}\", features = [{list}] }}"),
            (false, _) => format!(
                "{name} = {{ version = \"{version}\", default-features = false, features = [{list}] }}"
            ),
        }
    }
}

pub const TOKIO: CrateSpec = CrateSpec {
    name: "tokio",
    version: "1",
};
/// `sqlx` with defaults off (no `any`, `macros` or `migrate`), on tokio, with
/// TLS through rustls on `ring` trusting `webpki-roots` 1.x.
pub const SQLX: PinnedCrate = PinnedCrate {
    spec: CrateSpec {
        name: "sqlx",
        version: "0.9",
    },
    default_features: false,
    features: &["runtime-tokio", "tls-rustls-ring-webpki", "json"],
};
/// The database drivers every database program links, after [`SQLX`]'s features.
///
/// `sqlite-bundled` rather than `sqlite`, which also enables deserialize,
/// load-extension and unlock-notify. Mirrors the `sqlx?/` entries of the
/// runtime's `db` feature.
pub const SQLX_DRIVERS: &[&str] = &["sqlite-bundled", "postgres"];
pub const AXUM: PinnedCrate = PinnedCrate {
    spec: CrateSpec {
        name: "axum",
        version: "0.7",
    },
    default_features: true,
    features: &["ws"],
};
pub const TOWER_HTTP: PinnedCrate = PinnedCrate {
    spec: CrateSpec {
        name: "tower-http",
        version: "0.5",
    },
    default_features: true,
    features: &["fs", "catch-panic", "timeout"],
};
// `tower` (the `limit` layer) backs the server front-door DoS ceiling:
// `GlobalConcurrencyLimitLayer` bounds in-flight requests. The vendored server
// module (`server.rs`) references it in non-test code, so the emitted native
// project must declare the crate alongside `tower-http`.
pub const TOWER: CrateSpec = CrateSpec {
    name: "tower",
    version: "0.5",
};
pub const ASYNC_TRAIT: CrateSpec = CrateSpec {
    name: "async-trait",
    version: "0.1",
};
// `rustix` is declared directly in the base `Cargo.toml` template (under
// `[target.'cfg(unix)'.dependencies]`, for the vendored runtime's termios / pty /
// parent-death syscalls), not by a surgery function — so this spec is consulted
// only by the drift guard, which walks `ALL` under `cfg(test)`.
#[cfg(test)]
pub const RUSTIX: CrateSpec = CrateSpec {
    name: "rustix",
    version: "1",
};
pub const CROSSTERM: CrateSpec = CrateSpec {
    name: "crossterm",
    version: "0.29",
};
pub const UNICODE_WIDTH: CrateSpec = CrateSpec {
    name: "unicode-width",
    version: "0.1",
};
pub const WRY: CrateSpec = CrateSpec {
    name: "wry",
    version: "0.55",
};
pub const TAO: CrateSpec = CrateSpec {
    name: "tao",
    version: "0.35",
};
/// The `WebSocket` handshake only: the runtime owns the `wss://` TLS through
/// [`TOKIO_RUSTLS`], so tungstenite carries no TLS or root-store feature.
pub const TOKIO_TUNGSTENITE: PinnedCrate = PinnedCrate {
    spec: CrateSpec {
        name: "tokio-tungstenite",
        version: "0.30",
    },
    default_features: false,
    features: &["handshake"],
};
pub const TOKIO_RUSTLS: PinnedCrate = PinnedCrate {
    spec: CrateSpec {
        name: "tokio-rustls",
        version: "0.26",
    },
    default_features: false,
    features: &["ring", "tls12", "logging"],
};
pub const RUSTLS: PinnedCrate = PinnedCrate {
    spec: CrateSpec {
        name: "rustls",
        version: "0.23",
    },
    default_features: false,
    features: &["ring", "std", "tls12"],
};
/// The one root store a runtime TLS client trusts.
pub const WEBPKI_ROOTS: PinnedCrate = PinnedCrate {
    spec: CrateSpec {
        name: "webpki-roots",
        version: "1",
    },
    default_features: true,
    features: &[],
};
/// SMTP over rustls trusting `webpki-roots`, never the OS store.
pub const LETTRE: PinnedCrate = PinnedCrate {
    spec: CrateSpec {
        name: "lettre",
        version: "0.11",
    },
    default_features: false,
    features: &[
        "builder",
        "hostname",
        "smtp-transport",
        "pool",
        "tokio1",
        "tokio1-rustls-tls",
    ],
};
// `icu_casemap` and `icu_locale_core`: locale-aware case mapping behind the
// `locale` cargo feature. The dep-model runtime pulls them transitively via
// `features = ["locale"]`; the vendored escape hatch adds them here.
pub const ICU_CASEMAP: CrateSpec = CrateSpec {
    name: "icu_casemap",
    version: "2.2",
};
pub const ICU_LOCALE_CORE: CrateSpec = CrateSpec {
    name: "icu_locale_core",
    version: "2.2",
};
/// Defaults off, so no `default-tls` (native-tls); `rustls-tls` trusts
/// `webpki-roots`.
pub const REQWEST: PinnedCrate = PinnedCrate {
    spec: CrateSpec {
        name: "reqwest",
        version: "0.12",
    },
    default_features: false,
    features: &["rustls-tls", "gzip", "stream"],
};
pub const TOML: CrateSpec = CrateSpec {
    name: "toml",
    version: "0.8",
};
/// The YAML parser, defaults off. `include` (file inclusion) and `properties`
/// (environment interpolation) widen what a config source can reach, so
/// neither is ever enabled.
pub const SERDE_SAPHYR: PinnedCrate = PinnedCrate {
    spec: CrateSpec {
        name: "serde-saphyr",
        version: "1.3",
    },
    default_features: false,
    features: &["deserialize"],
};
/// `serde_json` with insertion-ordered objects, so every model (dependency,
/// vendored, wasm, jail) encodes an object's keys in the order it was built.
pub const SERDE_JSON: PinnedCrate = PinnedCrate {
    spec: CrateSpec {
        name: "serde_json",
        version: "1",
    },
    default_features: true,
    features: &["preserve_order"],
};
// The map behind the runtime's `JsonMap`. Not surgery-emitted (the vendored and
// wasm templates spell it); consulted only by the drift guards under
// `cfg(test)`.
#[cfg(test)]
pub const INDEXMAP: CrateSpec = CrateSpec {
    name: "indexmap",
    version: "2",
};
pub const FLATE2: CrateSpec = CrateSpec {
    name: "flate2",
    version: "1",
};
pub const ZSTD: CrateSpec = CrateSpec {
    name: "zstd",
    version: "0.14",
};
pub const CSV: CrateSpec = CrateSpec {
    name: "csv",
    version: "1",
};
pub const SHA1: CrateSpec = CrateSpec {
    name: "sha1",
    version: "0.10",
};
pub const MD5: CrateSpec = CrateSpec {
    name: "md-5",
    version: "0.10",
};
pub const AES_GCM: CrateSpec = CrateSpec {
    name: "aes-gcm",
    version: "0.10",
};
pub const CHACHA20POLY1305: CrateSpec = CrateSpec {
    name: "chacha20poly1305",
    version: "0.10",
};
pub const PBKDF2: CrateSpec = CrateSpec {
    name: "pbkdf2",
    version: "0.12",
};
pub const JSONWEBTOKEN: CrateSpec = CrateSpec {
    name: "jsonwebtoken",
    version: "9",
};
pub const URL: CrateSpec = CrateSpec {
    name: "url",
    version: "2",
};
pub const RSA: PinnedCrate = PinnedCrate {
    spec: CrateSpec {
        name: "rsa",
        version: "0.9",
    },
    default_features: true,
    features: &["sha2"],
};
pub const FUTURES_UTIL: CrateSpec = CrateSpec {
    name: "futures-util",
    version: "0.3",
};
// Base `chrono` is not surgery-emitted (the dep-model manifest names only the
// `ipe_runtime` path dep; its version lives in the runtime crate). This spec is
// consulted only by the drift guard, which walks `ALL` under `cfg(test)`.
// Pinned exact to the one version the whole workspace graph reconciles to, so a
// newer patch cannot climb its transitive `wasm-bindgen` floor past the runtime.
#[cfg(test)]
pub const CHRONO: CrateSpec = CrateSpec {
    name: "chrono",
    version: "=0.4.45",
};
pub const CHRONO_TZ: CrateSpec = CrateSpec {
    name: "chrono-tz",
    version: "0.10",
};
// Like `CHRONO`, these are not surgery-emitted: the dependency-model manifest
// names only the `ipe_runtime` path dep, and their versions live in the runtime
// crate (behind the `decimal` / `char-category` features). Consulted only by the
// drift guard, which walks `ALL` under `cfg(test)`.
#[cfg(test)]
pub const RUST_DECIMAL: CrateSpec = CrateSpec {
    name: "rust_decimal",
    version: "1",
};
#[cfg(test)]
pub const UNICODE_GENERAL_CATEGORY: CrateSpec = CrateSpec {
    name: "unicode-general-category",
    version: "1",
};

/// Every spec emitted by the surgery functions, for drift-test iteration.
///
/// Test-only: the shipping emitter reads the individual `const`s by name; this
/// aggregate exists solely so the drift tripwire can walk the full set.
#[cfg(test)]
pub const ALL: &[CrateSpec] = &[
    TOKIO,
    SQLX.spec,
    AXUM.spec,
    TOWER_HTTP.spec,
    TOWER,
    ASYNC_TRAIT,
    RUSTIX,
    CROSSTERM,
    UNICODE_WIDTH,
    WRY,
    TAO,
    TOKIO_TUNGSTENITE.spec,
    TOKIO_RUSTLS.spec,
    RUSTLS.spec,
    WEBPKI_ROOTS.spec,
    LETTRE.spec,
    ICU_CASEMAP,
    ICU_LOCALE_CORE,
    REQWEST.spec,
    TOML,
    SERDE_SAPHYR.spec,
    FLATE2,
    ZSTD,
    CSV,
    SHA1,
    MD5,
    AES_GCM,
    CHACHA20POLY1305,
    PBKDF2,
    JSONWEBTOKEN,
    URL,
    RSA.spec,
    FUTURES_UTIL,
    CHRONO,
    CHRONO_TZ,
    RUST_DECIMAL,
    UNICODE_GENERAL_CATEGORY,
    SERDE_JSON.spec,
    INDEXMAP,
];

/// Every crate whose feature set is fixed here.
///
/// The manifest tripwires in this crate and in the `ipe` CLI tests walk it.
pub const ALL_PINNED: &[PinnedCrate] = &[
    SQLX,
    TOKIO_TUNGSTENITE,
    TOKIO_RUSTLS,
    RUSTLS,
    WEBPKI_ROOTS,
    SERDE_SAPHYR,
    REQWEST,
    LETTRE,
    AXUM,
    TOWER_HTTP,
    RSA,
    SERDE_JSON,
];

#[cfg(test)]
mod tests {
    use super::{
        ALL, ALL_PINNED, INDEXMAP, LETTRE, PinnedCrate, REQWEST, SERDE_SAPHYR, SQLX, SQLX_DRIVERS,
        WEBPKI_ROOTS,
    };
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::PathBuf;

    /// The table is non-empty, every entry has a non-empty name + version, and
    /// every pinned crate is also walked by the version check.
    #[test]
    fn table_is_well_formed() {
        assert!(!ALL.is_empty(), "crate spec table must not be empty");
        for spec in ALL {
            assert!(!spec.name.is_empty(), "empty crate name in ALL");
            assert!(!spec.version.is_empty(), "empty version for {}", spec.name);
        }
        assert_eq!(ALL.len(), 39, "expected 39 surgery-emitted crate specs");
        for pinned in ALL_PINNED {
            assert!(
                ALL.iter().any(|spec| spec.name == pinned.spec.name),
                "{} is pinned but absent from ALL",
                pinned.spec.name
            );
        }
    }

    /// Extract the version from a Cargo dependency value: `"0.4"` or
    /// `{ version = "0.4", ... }`. Parse-once into a bare version string; every
    /// step is total (`.get` / `strip_prefix` / `find`), never an unchecked
    /// index.
    fn version_of(value: &str) -> Option<String> {
        let v = value.trim();
        if let Some(rest) = v.strip_prefix('{') {
            let idx = rest.find("version")?;
            let after = rest.get(idx + "version".len()..)?.trim_start();
            let after = after.strip_prefix('=')?.trim_start();
            let after = after.strip_prefix('"')?;
            let end = after.find('"')?;
            after.get(..end).map(str::to_owned)
        } else if let Some(rest) = v.strip_prefix('"') {
            let end = rest.find('"')?;
            rest.get(..end).map(str::to_owned)
        } else {
            None
        }
    }

    /// Parse `name = <value>` dependency lines into name → version. When
    /// `only_dep_sections` is true, only lines under a `[...dependencies]`
    /// header are considered (skips `[features]`, `[profile.*]`, …). A crate is
    /// captured with first-insert-wins, so the primary `[dependencies]` table
    /// takes precedence over a later `[dev-dependencies]` entry.
    fn parse_deps(text: &str, only_dep_sections: bool) -> BTreeMap<String, String> {
        let mut out = BTreeMap::new();
        let mut in_deps = !only_dep_sections;
        for raw in text.lines() {
            let line = raw.trim();
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            if line.starts_with('[') {
                in_deps = line.contains("dependencies");
                continue;
            }
            if !in_deps {
                continue;
            }
            if let Some((name, value)) = line.split_once('=') {
                let name = name.trim();
                if name.is_empty() || name.contains(' ') || name.contains('"') {
                    continue;
                }
                if let Some(ver) = version_of(value) {
                    out.entry(name.to_owned()).or_insert(ver);
                }
            }
        }
        out
    }

    /// The SSOT MUST match `runtime/Cargo.toml` for every crate (the generated
    /// project vendors that runtime and must compile against the versions and
    /// features it was tested with), and the golden base manifest for every
    /// SSOT crate it declares. Every pinned feature set is compared in both
    /// directions, and so are the database drivers against the runtime's `db`
    /// feature. Bump a version or a feature in ONE place and this fails until
    /// the others are updated.
    #[test]
    fn crate_specs_match_manifests() {
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let runtime_path = manifest.join("../../../runtime/rust/Cargo.toml");
        let golden_path = manifest.join("../../../../tests/golden/basics/Cargo.toml");

        let runtime_txt = std::fs::read_to_string(&runtime_path)
            .expect("crate_specs drift guard: cannot read runtime/Cargo.toml");
        let golden_txt = std::fs::read_to_string(&golden_path)
            .expect("crate_specs drift guard: cannot read tests/golden/basics/Cargo.toml");

        let runtime = parse_deps(&runtime_txt, true);
        let golden = parse_deps(&golden_txt, true);

        let mut problems = Vec::new();
        for spec in ALL {
            match runtime.get(spec.name) {
                None => problems.push(format!(
                    "{}: in SSOT ({}) but absent from runtime/Cargo.toml",
                    spec.name, spec.version
                )),
                Some(rt_ver) if rt_ver != spec.version => problems.push(format!(
                    "{}: SSOT = {}, runtime/Cargo.toml = {rt_ver}",
                    spec.name, spec.version
                )),
                Some(_) => {}
            }
            // Golden check only where the base manifest declares the crate.
            if let Some(g_ver) = golden.get(spec.name)
                && g_ver != spec.version
            {
                problems.push(format!(
                    "{}: SSOT = {}, tests/golden/basics/Cargo.toml = {g_ver}",
                    spec.name, spec.version
                ));
            }
        }
        for pinned in ALL_PINNED {
            problems.extend(pin_drift(pinned, &runtime_txt, "runtime/Cargo.toml"));
        }
        problems.extend(driver_drift(&runtime_txt, "runtime/Cargo.toml"));
        let jail_path = manifest.join(
            "../../../../examples/wasm/language-playground/jail-runner/src/crate_template/Cargo.toml",
        );
        let jail_txt = std::fs::read_to_string(&jail_path)
            .expect("crate_specs drift guard: cannot read the jail-runner crate template");
        // The jail template must carry the YAML parser; any other pinned crate
        // it names must carry its pinned line too.
        for pinned in ALL_PINNED {
            if pinned.spec.name == SERDE_SAPHYR.spec.name
                || dep_line(&jail_txt, pinned.spec.name).is_some()
            {
                problems.extend(pin_drift(pinned, &jail_txt, "jail-runner crate template"));
            }
        }
        assert!(
            problems.is_empty(),
            "crate drift between the SSOT and the manifests:\n  {}",
            problems.join("\n  ")
        );
    }

    /// Every vendored manifest the backend emits spells each pinned crate it
    /// names exactly as the SSOT renders it, and the `indexmap` version the
    /// runtime builds with.
    #[test]
    fn a_vendored_manifest_names_every_pin_exactly() {
        let manifests = [
            ("templates/Cargo.toml", crate::project::CARGO_TOML),
            (
                "project.rs WASM_CARGO_TOML",
                crate::project::WASM_CARGO_TOML,
            ),
        ];
        let mut problems = Vec::new();
        for (origin, text) in manifests {
            for pinned in ALL_PINNED {
                if dep_line(text, pinned.spec.name).is_some() {
                    problems.extend(pin_drift(pinned, text, origin));
                }
            }
            if dep_line(text, super::SERDE_JSON.spec.name).is_none() {
                problems.push(format!("serde_json: absent from {origin}"));
            }
            let indexmap = dep_line(text, INDEXMAP.name)
                .and_then(|line| line.split_once('='))
                .and_then(|(_, value)| version_of(value));
            if indexmap.as_deref() != Some(INDEXMAP.version) {
                problems.push(format!(
                    "indexmap: SSOT = {}, {origin} = {indexmap:?}",
                    INDEXMAP.version
                ));
            }
        }
        assert!(
            problems.is_empty(),
            "vendored manifest drift from the SSOT:\n  {}",
            problems.join("\n  ")
        );
    }

    /// A vendored manifest whose `serde_json` line drops `preserve_order` is
    /// refused by the pin check the vendored-manifest test runs.
    #[test]
    fn a_vendored_manifest_without_preserve_order_is_refused() {
        let drifted = "[dependencies]\nserde_json = \"1\"\nindexmap = \"2\"\n";
        assert!(
            !pin_drift(&super::SERDE_JSON, drifted, "fixture").is_empty(),
            "a serde_json line without preserve_order must drift"
        );
        let pinned = format!(
            "[dependencies]\n{}\n",
            super::SERDE_JSON.dependency_line(&[])
        );
        assert_eq!(
            pin_drift(&super::SERDE_JSON, &pinned, "fixture"),
            Vec::<String>::new()
        );
    }

    /// The first non-comment `name = ...` line of a manifest, trimmed.
    fn dep_line<'a>(text: &'a str, name: &str) -> Option<&'a str> {
        text.lines()
            .map(str::trim)
            .filter(|line| !line.starts_with('#'))
            .find(|line| {
                line.split_once('=')
                    .is_some_and(|(key, _)| key.trim() == name)
            })
    }

    /// The quoted entries of the `features = [...]` list on one dependency line.
    ///
    /// The key must stand alone (after `{`, `,`, or a space), so the
    /// `features` inside `default-features` is never taken for it.
    fn features_of(line: &str) -> Option<Vec<&str>> {
        let (start, key) = line.match_indices("features").find(|(at, _)| {
            line.get(..*at)
                .and_then(|before| before.chars().next_back())
                .is_some_and(|c| c == '{' || c == ',' || c == ' ')
        })?;
        let after = line.get(start + key.len()..)?;
        let after = after.trim_start().strip_prefix('=')?.trim_start();
        let list = after.strip_prefix('[')?;
        let list = list.get(..list.find(']')?)?;
        Some(
            list.split(',')
                .map(|entry| entry.trim().trim_matches('"'))
                .filter(|entry| !entry.is_empty())
                .collect(),
        )
    }

    /// Every way a manifest's line for `pinned` departs from the SSOT: the
    /// version, `default-features`, and the feature set in both directions (a
    /// feature the SSOT names but the line lacks, and one the line enables but
    /// the SSOT does not).
    fn pin_drift(pinned: &PinnedCrate, text: &str, origin: &str) -> Vec<String> {
        let name = pinned.spec.name;
        let Some(line) = dep_line(text, name) else {
            return vec![format!("{name}: absent from {origin}")];
        };
        let mut problems = Vec::new();
        if version_of(line.split_once('=').map_or("", |(_, value)| value)).as_deref()
            != Some(pinned.spec.version)
        {
            problems.push(format!(
                "{name}: SSOT = {}, {origin} = `{line}`",
                pinned.spec.version
            ));
        }
        let defaults_off = line.contains("default-features = false");
        if pinned.default_features == defaults_off {
            problems.push(format!(
                "{name}: SSOT default features {}, {origin} = `{line}`",
                if pinned.default_features { "on" } else { "off" }
            ));
        }
        let want: BTreeSet<&str> = pinned.features.iter().copied().collect();
        let got: BTreeSet<&str> = features_of(line).unwrap_or_default().into_iter().collect();
        for missing in want.difference(&got) {
            problems.push(format!(
                "{name}: SSOT feature `{missing}` absent from {origin}"
            ));
        }
        for extra in got.difference(&want) {
            problems.push(format!(
                "{name}: {origin} enables `{extra}`, which the SSOT does not"
            ));
        }
        problems
    }

    /// The `sqlx?/` entries of the `[features]` table's `db` feature.
    fn sqlx_drivers_of(text: &str) -> Option<BTreeSet<&str>> {
        let mut in_features = false;
        for raw in text.lines() {
            let line = raw.trim();
            if line.starts_with('[') {
                in_features = line == "[features]";
                continue;
            }
            if !in_features {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            if key.trim() != "db" {
                continue;
            }
            let list = value.trim().strip_prefix('[')?;
            let list = list.get(..list.find(']')?)?;
            return Some(
                list.split(',')
                    .map(|entry| entry.trim().trim_matches('"'))
                    .filter_map(|entry| entry.strip_prefix("sqlx?/"))
                    .collect(),
            );
        }
        None
    }

    /// Every way the `db` feature's `sqlx?/` drivers depart from
    /// [`SQLX_DRIVERS`], in both directions.
    fn driver_drift(text: &str, origin: &str) -> Vec<String> {
        let Some(got) = sqlx_drivers_of(text) else {
            return vec![format!("db feature: absent from {origin}")];
        };
        let want: BTreeSet<&str> = SQLX_DRIVERS.iter().copied().collect();
        let mut problems = Vec::new();
        for missing in want.difference(&got) {
            problems.push(format!(
                "db feature: SSOT driver `sqlx?/{missing}` absent from {origin}"
            ));
        }
        for extra in got.difference(&want) {
            problems.push(format!(
                "db feature: {origin} enables `sqlx?/{extra}`, which the SSOT does not"
            ));
        }
        problems
    }

    /// The rendered line of every pinned crate passes its own drift check, and
    /// the database line spells the drivers after the pinned set.
    #[test]
    fn rendered_lines_are_the_pinned_lines() {
        for pinned in ALL_PINNED {
            let line = pinned.dependency_line(&[]);
            assert!(
                pin_drift(pinned, &line, "rendered").is_empty(),
                "`{line}` must pass its own drift check"
            );
        }
        assert_eq!(
            SQLX.dependency_line(SQLX_DRIVERS),
            r#"sqlx = { version = "0.9", default-features = false, features = ["runtime-tokio", "tls-rustls-ring-webpki", "json", "sqlite-bundled", "postgres"] }"#
        );
        assert_eq!(WEBPKI_ROOTS.dependency_line(&[]), r#"webpki-roots = "1""#);
    }

    /// A pin that adds or drops a feature, keeps default features on, or moves
    /// the version is drift; the exact pin, in any key order, is not.
    #[test]
    fn pin_drift_is_caught() {
        let exact = r#"serde-saphyr = { version = "1.3", default-features = false, features = ["deserialize"] }"#;
        assert!(pin_drift(&SERDE_SAPHYR, exact, "fixture").is_empty());
        assert_eq!(features_of(exact), Some(vec!["deserialize"]));
        let reordered = r#"serde-saphyr = { version = "1.3", features = ["deserialize"], default-features = false }"#;
        assert!(pin_drift(&SERDE_SAPHYR, reordered, "fixture").is_empty());
        for drifted in [
            r#"serde-saphyr = { version = "1.3", default-features = false, features = ["deserialize", "include"] }"#,
            r#"serde-saphyr = { version = "1.3", features = ["deserialize"] }"#,
            r#"serde-saphyr = { version = "1.4", default-features = false, features = ["deserialize"] }"#,
            r#"serde-saphyr = "1.3""#,
            "toml = \"0.8\"",
        ] {
            assert!(
                !pin_drift(&SERDE_SAPHYR, drifted, "fixture").is_empty(),
                "{drifted} must be reported as drift"
            );
        }

        let sqlx = r#"sqlx = { version = "0.9", default-features = false, features = ["json", "runtime-tokio", "tls-rustls-ring-webpki"], optional = true }"#;
        assert!(pin_drift(&SQLX, sqlx, "fixture").is_empty());
        for drifted in [
            r#"sqlx = { version = "0.9", default-features = false, features = ["runtime-tokio", "tls-rustls-ring-webpki", "json", "macros"] }"#,
            r#"sqlx = { version = "0.9", default-features = false, features = ["runtime-tokio", "tls-rustls-ring-webpki"] }"#,
            r#"sqlx = { version = "0.9", features = ["runtime-tokio", "tls-rustls-ring-webpki", "json"] }"#,
            r#"sqlx = { version = "0.8", default-features = false, features = ["runtime-tokio", "tls-rustls-ring-webpki", "json"] }"#,
            r#"sqlx = { version = "0.9", default-features = false, features = ["runtime-tokio-rustls", "json"] }"#,
        ] {
            assert!(
                !pin_drift(&SQLX, drifted, "fixture").is_empty(),
                "{drifted} must be reported as drift"
            );
        }
    }

    /// The HTTP and SMTP client lines are drift-checked.
    ///
    /// Each refuses an OS root store or native-tls feature, and its TLS
    /// defaults turned on; every fixture derives from the pinned line itself.
    #[test]
    fn tls_client_pin_drift_is_caught() {
        for pinned in [REQWEST, LETTRE] {
            let name = pinned.spec.name;
            assert!(
                ALL_PINNED.iter().any(|entry| entry.spec.name == name),
                "{name} must be in the drift-checked set"
            );
            let exact = pinned.dependency_line(&[]);
            assert!(pin_drift(&pinned, &exact, "fixture").is_empty(), "{exact}");
            for widening in [
                "rustls-platform-verifier",
                "rustls-native-certs",
                "native-tls",
            ] {
                let widened = pinned.dependency_line(&[widening]);
                assert!(
                    !pin_drift(&pinned, &widened, "fixture").is_empty(),
                    "{widened} must be reported as drift"
                );
            }
            let defaults_on = exact.replace("default-features = false, ", "");
            assert_ne!(defaults_on, exact, "{name} must pin its defaults off");
            assert!(
                !pin_drift(&pinned, &defaults_on, "fixture").is_empty(),
                "{defaults_on} must be reported as drift"
            );
        }
    }

    /// The `db` feature must enable exactly the SSOT drivers.
    #[test]
    fn driver_drift_is_caught() {
        let exact = "[features]\ndb = [\"sqlx\", \"sqlx?/sqlite-bundled\", \"sqlx?/postgres\", \"tokio\"]\n";
        assert!(driver_drift(exact, "fixture").is_empty());
        for drifted in [
            "[features]\ndb = [\"sqlx\", \"sqlx?/sqlite\", \"sqlx?/postgres\"]\n",
            "[features]\ndb = [\"sqlx\", \"sqlx?/sqlite-bundled\"]\n",
            "[features]\ndb = [\"sqlx\", \"sqlx?/sqlite-bundled\", \"sqlx?/postgres\", \"sqlx?/mysql\"]\n",
            "[dependencies]\ndb = [\"sqlx?/sqlite-bundled\", \"sqlx?/postgres\"]\n",
        ] {
            assert!(
                !driver_drift(drifted, "fixture").is_empty(),
                "{drifted} must be reported as drift"
            );
        }
    }
}
