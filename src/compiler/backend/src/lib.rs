#![forbid(unsafe_code)]
//! The backend boundary for the Ipê compiler. A backend consumes the
//! backend-agnostic typed [`ipe_ir::Program`] and produces an
//! [`EmittedProject`] — an in-memory project tree ready to be written to disk.
//!
//! This crate is the *only* contract a backend sees. It deliberately depends on
//! nothing from the frontend (parser / canonicaliser / type-checker / lowerer):
//! the only inputs are [`ipe_ir`] and [`ipe_diagnostics`]. A backend that names
//! a frontend crate breaks the architecture's acyclic boundary.

use std::borrow::Borrow;
use std::collections::BTreeMap;
use std::path::Path;

use ipe_diagnostics::{DResult, Diagnostic};
use ipe_ir::Program;

/// A validated project-relative path — the key type for [`EmittedProject::files`].
///
/// This newtype is the trust boundary between in-memory emission and the on-disk
/// materialiser. Parse-don't-validate: [`RelPath::new`] is the *only* way to
/// construct one, and it rejects any path that could escape the output directory
/// when fed to `out_dir.join(rel)` — an absolute path, a leading `/` or `\`, a
/// Windows drive-letter prefix (`C:`), or any `..` parent-directory component.
/// Once a `RelPath` exists the writer trusts it unconditionally: a bare `String`
/// key with an absolute or `..`-bearing value can no longer reach `fs::write`,
/// because `EmittedProject::files` cannot hold one.
///
/// The inner string is forward-slash separated (e.g. `"src/main.rs"`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RelPath(String);

impl RelPath {
    /// Construct a validated relative path, or a diagnostic if `path` could
    /// escape the output directory.
    ///
    /// # Errors
    ///
    /// Returns [`Diagnostic::CompilerBug`] (a backend emitting an unsafe key is
    /// an internal invariant violation, not a property of the user's program)
    /// when `path` is empty, absolute, root-/drive-rooted, or contains a `..`
    /// component. The offending path travels in `detail` — the only free-form
    /// channel — so the rejection is greppable without leaking a stringly error.
    pub fn new(path: impl Into<String>) -> DResult<Self> {
        let path = path.into();
        Self::validate(&path)?;
        Ok(Self(path))
    }

    /// Borrow the validated path as a forward-slash string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn validate(path: &str) -> DResult<()> {
        let reject = |reason: &str| -> DResult<()> {
            Err(Diagnostic::CompilerBug {
                where_: "backend.unsafe_rel_path",
                detail: format!("refusing unsafe emitted file key {path:?}: {reason}"),
            })
        };

        if path.is_empty() {
            return reject("empty path");
        }
        // A leading separator (either flavour) makes the path root-relative —
        // absolute on Unix, drive-root-relative on Windows.
        if path.starts_with('/') || path.starts_with('\\') {
            return reject("leading path separator (absolute / root-relative)");
        }
        // Windows drive-letter prefix, e.g. `C:` or `C:\\foo`. Checked
        // explicitly because `Path::is_absolute` does not flag it on a Unix host.
        // Byte iteration avoids raw indexing.
        let mut bytes = path.bytes();
        if let (Some(first), Some(second)) = (bytes.next(), bytes.next())
            && first.is_ascii_alphabetic()
            && second == b':'
        {
            return reject("Windows drive-letter prefix");
        }
        // Platform's own absolute check, for any root form the above misses.
        if Path::new(path).is_absolute() {
            return reject("absolute path");
        }
        // No `..` component may appear. Split on BOTH separators so a
        // Windows-style `..\\` is caught even on a Unix host, where `Path`'s
        // component iterator would not treat `\\` as a separator.
        if path.split(['/', '\\']).any(|comp| comp == "..") {
            return reject("parent-directory (`..`) component");
        }
        Ok(())
    }
}

/// Borrowing as `str` lets `files.get("src/main.rs")` look up by literal without
/// allocating a `RelPath`. `RelPath`'s derived `Ord` compares the inner string,
/// so the borrowed `str` ordering is consistent — the `BTreeMap` invariant the
/// `Borrow`/`Ord` contract requires.
impl Borrow<str> for RelPath {
    fn borrow(&self) -> &str {
        &self.0
    }
}

/// Serialises as the bare inner path string — the counterpart
/// [`Deserialize`](serde::Deserialize) impl below is what re-establishes the
/// safety invariant on the way back in.
impl serde::Serialize for RelPath {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

/// **Deliberately hand-written, never `#[derive(Deserialize)]`.** A derived
/// impl would reconstruct `RelPath(raw_string)` directly from the untrusted
/// bytes, bypassing [`RelPath::new`]'s path-traversal validation entirely —
/// exactly the "parse, don't validate" boundary this newtype exists to
/// enforce (see the type's own doc). This matters concretely for the
/// on-disk build cache (`ipe::cache`): a corrupted or tampered cache file
/// is untrusted input from the moment it is read off disk, so a `RelPath`
/// key inside a deserialized [`EmittedProject`] MUST re-run the same
/// rejection an in-process backend emission would. Routing through
/// `RelPath::new` here is what makes that true — a malicious `"../../etc/
/// passwd"` entry in a poisoned cache file is rejected at deserialize time,
/// never reaching `fs::write`.
impl<'de> serde::Deserialize<'de> for RelPath {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::new(raw).map_err(|diag| serde::de::Error::custom(format!("{diag:?}")))
    }
}

/// The bytes of one binary file an emitted project carries beside its text
/// files (an icon the emitted Rust pulls in with `include_bytes!`).
///
/// It serialises as lower-case hex, so the JSON build cache holds it as one
/// string. The hand-written [`Deserialize`](serde::Deserialize) refuses an
/// odd length or a non-hex digit: a cache file is untrusted input.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct Asset(Vec<u8>);

impl Asset {
    /// The asset holding `bytes`.
    #[must_use]
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The asset's bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for Asset {
    /// The length only: an asset can be megabytes.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Asset")
            .field("len", &self.0.len())
            .finish_non_exhaustive()
    }
}

/// The lower-case hex digits, indexed by nibble.
const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

impl serde::Serialize for Asset {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut text = String::with_capacity(self.0.len().saturating_mul(2));
        for byte in &self.0 {
            for nibble in [byte >> 4, byte & 0x0F] {
                let digit = HEX_DIGITS
                    .get(usize::from(nibble))
                    .copied()
                    .map_or('0', char::from);
                text.push(digit);
            }
        }
        text.serialize(serializer)
    }
}

/// The value of one hex digit, either case.
const fn hex_value(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        b'A'..=b'F' => Some(digit - b'A' + 10),
        _ => None,
    }
}

impl<'de> serde::Deserialize<'de> for Asset {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        let (pairs, rest) = text.as_bytes().as_chunks::<2>();
        if !rest.is_empty() {
            return Err(serde::de::Error::custom("an asset has an odd hex length"));
        }
        pairs
            .iter()
            .map(|[high, low]| {
                hex_value(*high)
                    .zip(hex_value(*low))
                    .map(|(high, low)| (high << 4) | low)
            })
            .collect::<Option<Vec<u8>>>()
            .map(Self)
            .ok_or_else(|| serde::de::Error::custom("an asset carries a non-hex digit"))
    }
}

/// An emitted project, fully materialised in memory.
///
/// `files` maps a validated project-relative [`RelPath`] to its file contents. A
/// [`BTreeMap`] is used so iteration order is deterministic — emission must never
/// depend on hash ordering. The [`RelPath`] key type enforces that no key can
/// escape the output directory at the disk boundary (see [`RelPath`]).
/// `cargo_toml` is the manifest emitted at the project root.
#[derive(Clone, Debug, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct EmittedProject {
    /// Validated relative path -> file contents. Deterministic iteration order.
    pub files: BTreeMap<RelPath, String>,
    /// The contents of the project-root `Cargo.toml`.
    pub cargo_toml: String,
    /// Whether this project links the system webview backend. The typed source
    /// of truth the driver reads to refuse a static (musl) build of a
    /// webview-hosted app — never a re-parse of `cargo_toml`'s default-feature
    /// list. Set by the backend from the resolved runtime/host, so it is present
    /// even on a cache-deserialized project.
    #[serde(default)]
    pub uses_webview: bool,
    /// Validated relative path -> binary file bytes, written beside
    /// [`Self::files`]. No key is also a key of [`Self::files`]; the writer
    /// refuses a project where one is.
    #[serde(default)]
    pub assets: BTreeMap<RelPath, Asset>,
}

/// A code-generation backend: turns a typed IR [`Program`] into an
/// [`EmittedProject`].
///
/// Implementations must be pure functions of their input `program` and must not
/// observe non-deterministic ordering. Failures are reported as a typed
/// [`ipe_diagnostics::Diagnostic`] — never a panic or a `String` error.
pub trait Backend {
    /// A stable, human-readable identifier for this backend (e.g. `"rust"`).
    fn name(&self) -> &'static str;

    /// Emit the project for `program`, or a typed diagnostic on failure.
    ///
    /// # Errors
    ///
    /// Returns a [`ipe_diagnostics::Diagnostic`] when the program cannot be
    /// emitted (for example, an internal invariant violation surfaces as
    /// [`ipe_diagnostics::Diagnostic::CompilerBug`]).
    fn emit(&self, program: &Program) -> DResult<EmittedProject>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NoopBackend;

    impl Backend for NoopBackend {
        fn name(&self) -> &'static str {
            "noop"
        }

        fn emit(&self, _program: &Program) -> DResult<EmittedProject> {
            Ok(EmittedProject::default())
        }
    }

    #[test]
    fn relpath_accepts_ordinary_relative_paths() -> DResult<()> {
        for ok in [
            "src/main.rs",
            "Cargo.toml",
            "a/b/c.rs",
            "src/ipe_runtime/mod.rs",
        ] {
            let rel = RelPath::new(ok)?;
            assert_eq!(rel.as_str(), ok);
        }
        Ok(())
    }

    #[test]
    fn relpath_rejects_escaping_keys() {
        // Absolute, root-/drive-rooted, parent-dir, and empty keys are the
        // path-traversal / absolute-write vectors the newtype must close.
        for bad in [
            "",
            "/etc/passwd",
            "/abs.rs",
            "\\windows\\system32",
            "C:/Windows/System32",
            "c:relative",
            "../escape.rs",
            "src/../../escape.rs",
            "a/b/../../../etc/passwd",
            "..",
            "foo/..\\bar",
        ] {
            assert!(
                matches!(RelPath::new(bad), Err(Diagnostic::CompilerBug { .. })),
                "RelPath::new({bad:?}) should be rejected as unsafe"
            );
        }
    }

    #[test]
    fn relpath_keyed_map_looks_up_by_str() -> DResult<()> {
        let mut files: BTreeMap<RelPath, String> = BTreeMap::new();
        files.insert(RelPath::new("src/main.rs")?, "fn main() {}".to_owned());
        assert_eq!(
            files.get("src/main.rs").map(String::as_str),
            Some("fn main() {}")
        );
        assert_eq!(files.get("nope.rs"), None);
        Ok(())
    }

    #[test]
    fn relpath_serde_round_trips_ordinary_paths() -> DResult<()> {
        let rel = RelPath::new("src/ipe_runtime/mod.rs")?;
        let json = serde_json::to_string(&rel).expect("serialize must succeed");
        assert_eq!(json, "\"src/ipe_runtime/mod.rs\"");
        let back: RelPath = serde_json::from_str(&json).expect("deserialize must succeed");
        assert_eq!(back, rel);
        Ok(())
    }

    /// The security-critical property: `RelPath`'s `Deserialize` impl is
    /// hand-written specifically so a malicious/corrupted on-disk cache
    /// entry cannot smuggle a path-traversal key past
    /// `RelPath::new`'s validation. A naive `#[derive(Deserialize)]` would
    /// have let this test fail.
    #[test]
    fn relpath_deserialize_rejects_escaping_paths() {
        for bad in ["../../etc/passwd", "/abs.rs", "a/../../b"] {
            let json = serde_json::to_string(bad).expect("string always serializes");
            let result: Result<RelPath, _> = serde_json::from_str(&json);
            assert!(
                result.is_err(),
                "RelPath deserialize must reject {bad:?}, got {result:?}"
            );
        }
    }

    #[test]
    fn emitted_project_serde_round_trips() -> DResult<()> {
        let mut files = BTreeMap::new();
        files.insert(RelPath::new("src/main.rs")?, "fn main() {}".to_owned());
        files.insert(
            RelPath::new("src/ipe_runtime/mod.rs")?,
            "pub mod config;\n".to_owned(),
        );
        let project = EmittedProject {
            files,
            cargo_toml: "[package]\nname = \"app\"\n".to_owned(),
            uses_webview: false,
            assets: BTreeMap::from([(
                RelPath::new("src/icon.png")?,
                Asset::new(vec![0x00, 0x89, 0xAB, 0xFF]),
            )]),
        };
        let json = serde_json::to_string(&project).expect("serialize must succeed");
        let back: EmittedProject = serde_json::from_str(&json).expect("deserialize must succeed");
        assert_eq!(back, project);
        Ok(())
    }

    #[test]
    fn an_asset_serialises_as_hex_and_refuses_a_malformed_hex_string() {
        let json = serde_json::to_string(&Asset::new(vec![0x00, 0x89, 0xAB, 0xFF]))
            .expect("serialize must succeed");
        assert_eq!(json, "\"0089abff\"");
        let back: Asset = serde_json::from_str("\"0089ABff\"").expect("either case decodes");
        assert_eq!(back.bytes(), &[0x00, 0x89, 0xAB, 0xFF]);
        for bad in ["\"0\"", "\"0g\"", "\"zz00\"", "\"00 1\""] {
            let result: Result<Asset, _> = serde_json::from_str(bad);
            assert!(result.is_err(), "{bad} must be refused, got {result:?}");
        }
    }

    #[test]
    fn an_asset_with_an_escaping_key_fails_the_whole_project() {
        let poisoned = r#"{"files":{},"cargo_toml":"","assets":{"../../icon.png":"00"}}"#;
        let result: Result<EmittedProject, _> = serde_json::from_str(poisoned);
        assert!(result.is_err(), "{result:?}");
    }

    /// A cache entry that has been tampered with to carry an escaping key
    /// must fail to deserialize as a WHOLE `EmittedProject` — never silently
    /// drop the bad entry and materialize the rest.
    #[test]
    fn emitted_project_deserialize_rejects_a_poisoned_key() {
        let poisoned = r#"{"files":{"../../etc/passwd":"pwned"},"cargo_toml":""}"#;
        let result: Result<EmittedProject, _> = serde_json::from_str(poisoned);
        assert!(
            result.is_err(),
            "a poisoned RelPath key must fail the whole deserialize, got {result:?}"
        );
    }

    #[test]
    fn noop_backend_name_and_empty_emit() {
        let backend = NoopBackend;
        assert_eq!(backend.name(), "noop");

        let program = Program {
            imports_unsafe_submodule: false,
            imported_web_capabilities: std::collections::BTreeSet::new(),
            modules: Vec::new(),
        };
        let emitted = backend.emit(&program);
        assert_eq!(emitted, Ok(EmittedProject::default()));
        assert!(matches!(&emitted, Ok(project) if project.files.is_empty()));
        assert!(matches!(emitted, Ok(project) if project.cargo_toml.is_empty()));
    }
}
