//! Single source of truth for the crate VERSIONS the Rust codegen emits.
//!
//! The default native emit is the dependency model: third-party versions live
//! in the runtime crate's own `runtime/rust/Cargo.toml`, and the emitted native
//! `Cargo.toml` names only the `ipe_runtime` path dependency — it carries no
//! third-party versions. These specs still drive the versions the vendored
//! fallback and the WASM template surgeries emit, so they must not drift from
//! the runtime crate's manifest.
//!
//! Feature lists + `optional` flags stay inline in `project.rs` (they depend on
//! usage). Only the version SPEC lives here. The `crate_specs_match_manifests`
//! test below is the drift tripwire: it pins every spec against
//! `runtime/rust/Cargo.toml` and, for any crate the golden base manifest still
//! declares, against `tests/golden/basics/Cargo.toml` (empty under the
//! dependency model, so that arm is inert until the vendored/WASM surface
//! reintroduces one).

/// One authoritative crate version. Feature lists + `optional` flags stay in the
/// emitter (`project.rs`); only the version SPEC lives here.
pub struct CrateSpec {
    pub name: &'static str,
    pub version: &'static str,
}

pub const TOKIO: CrateSpec = CrateSpec {
    name: "tokio",
    version: "1",
};
pub const SQLX: CrateSpec = CrateSpec {
    name: "sqlx",
    version: "0.8",
};
pub const AXUM: CrateSpec = CrateSpec {
    name: "axum",
    version: "0.7",
};
pub const TOWER_HTTP: CrateSpec = CrateSpec {
    name: "tower-http",
    version: "0.5",
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
pub const TOKIO_TUNGSTENITE: CrateSpec = CrateSpec {
    name: "tokio-tungstenite",
    version: "0.24",
};
pub const LETTRE: CrateSpec = CrateSpec {
    name: "lettre",
    version: "0.11",
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
pub const REQWEST: CrateSpec = CrateSpec {
    name: "reqwest",
    version: "0.12",
};
pub const TOML: CrateSpec = CrateSpec {
    name: "toml",
    version: "0.8",
};
pub const SERDE_SAPHYR: CrateSpec = CrateSpec {
    name: "serde-saphyr",
    version: "1.3",
};
/// The exact `serde-saphyr` feature set every manifest enables, defaults off.
///
/// `include` (file inclusion) and `properties` (environment interpolation)
/// widen what a config source can reach, so neither is ever enabled.
pub const SERDE_SAPHYR_FEATURES: &[&str] = &["deserialize"];
pub const FLATE2: CrateSpec = CrateSpec {
    name: "flate2",
    version: "1",
};
pub const ZSTD: CrateSpec = CrateSpec {
    name: "zstd",
    version: "0.13",
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
pub const RSA: CrateSpec = CrateSpec {
    name: "rsa",
    version: "0.9",
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
    SQLX,
    AXUM,
    TOWER_HTTP,
    TOWER,
    ASYNC_TRAIT,
    RUSTIX,
    CROSSTERM,
    UNICODE_WIDTH,
    WRY,
    TAO,
    TOKIO_TUNGSTENITE,
    LETTRE,
    ICU_CASEMAP,
    ICU_LOCALE_CORE,
    REQWEST,
    TOML,
    SERDE_SAPHYR,
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
    RSA,
    FUTURES_UTIL,
    CHRONO,
    CHRONO_TZ,
    RUST_DECIMAL,
    UNICODE_GENERAL_CATEGORY,
];

#[cfg(test)]
mod tests {
    use super::{ALL, SERDE_SAPHYR, SERDE_SAPHYR_FEATURES};
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    /// The table is non-empty and every entry has a non-empty name + version.
    #[test]
    fn table_is_well_formed() {
        assert!(!ALL.is_empty(), "crate spec table must not be empty");
        for spec in ALL {
            assert!(!spec.name.is_empty(), "empty crate name in ALL");
            assert!(!spec.version.is_empty(), "empty version for {}", spec.name);
        }
        assert_eq!(ALL.len(), 34, "expected 34 surgery-emitted crate specs");
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

    /// The SSOT versions MUST match `runtime/Cargo.toml` for every crate (the
    /// generated project vendors that runtime and must compile against the
    /// versions it was tested with), and the golden base manifest for every
    /// SSOT crate it declares (tokio). Bump a version in ONE place and this
    /// fails until the others are updated — the invalid "manifest requests a
    /// version the runtime was not built against" state is unrepresentable
    /// without going red here.
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
        let jail_path = manifest.join(
            "../../../../examples/wasm/language-playground/jail-runner/src/crate_template/Cargo.toml",
        );
        let jail_txt = std::fs::read_to_string(&jail_path)
            .expect("crate_specs drift guard: cannot read the jail-runner crate template");
        for (origin, text) in [
            ("runtime/Cargo.toml", runtime_txt.as_str()),
            ("jail-runner crate template", jail_txt.as_str()),
        ] {
            problems.extend(yaml_parser_pin_drift(text, origin));
        }
        assert!(
            problems.is_empty(),
            "crate-version drift between the SSOT and the manifests:\n  {}",
            problems.join("\n  ")
        );
    }

    /// The `serde-saphyr` dependency line of a manifest, trimmed.
    fn yaml_parser_line(text: &str) -> Option<&str> {
        text.lines().map(str::trim).find(|line| {
            line.split_once('=')
                .is_some_and(|(name, _)| name.trim() == SERDE_SAPHYR.name)
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

    /// Every way a manifest's `serde-saphyr` pin departs from the SSOT.
    ///
    /// The version, `default-features = false`, and exactly
    /// `SERDE_SAPHYR_FEATURES` — so `include` / `properties` can never be
    /// switched on in one manifest alone.
    fn yaml_parser_pin_drift(text: &str, origin: &str) -> Vec<String> {
        let name = SERDE_SAPHYR.name;
        let Some(line) = yaml_parser_line(text) else {
            return vec![format!("{name}: absent from {origin}")];
        };
        let mut problems = Vec::new();
        if version_of(line.split_once('=').map_or("", |(_, value)| value)).as_deref()
            != Some(SERDE_SAPHYR.version)
        {
            problems.push(format!(
                "{name}: SSOT = {}, {origin} = `{line}`",
                SERDE_SAPHYR.version
            ));
        }
        if !line.contains("default-features = false") {
            problems.push(format!(
                "{name}: {origin} must set `default-features = false`"
            ));
        }
        if features_of(line).as_deref() != Some(SERDE_SAPHYR_FEATURES) {
            problems.push(format!(
                "{name}: {origin} features must be exactly {SERDE_SAPHYR_FEATURES:?}, got `{line}`"
            ));
        }
        problems
    }

    /// A pin that turns on `include`, keeps default features, or moves the
    /// version is drift; the exact pin is not.
    #[test]
    fn yaml_parser_pin_drift_is_caught() {
        let exact = r#"serde-saphyr = { version = "1.3", default-features = false, features = ["deserialize"] }"#;
        assert!(yaml_parser_pin_drift(exact, "fixture").is_empty());
        assert_eq!(features_of(exact), Some(vec!["deserialize"]));
        let reordered = r#"serde-saphyr = { version = "1.3", features = ["deserialize"], default-features = false }"#;
        assert!(yaml_parser_pin_drift(reordered, "fixture").is_empty());
        for drifted in [
            r#"serde-saphyr = { version = "1.3", default-features = false, features = ["deserialize", "include"] }"#,
            r#"serde-saphyr = { version = "1.3", features = ["deserialize"] }"#,
            r#"serde-saphyr = { version = "1.4", default-features = false, features = ["deserialize"] }"#,
            r#"serde-saphyr = "1.3""#,
            "toml = \"0.8\"",
        ] {
            assert!(
                !yaml_parser_pin_drift(drifted, "fixture").is_empty(),
                "{drifted} must be reported as drift"
            );
        }
    }
}
