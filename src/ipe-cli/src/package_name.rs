//! Package-name newtype: a name proven safe to use as a single filesystem path
//! component.
//!
//! Package and dependency names arrive as bare strings from untrusted manifests,
//! lockfiles, and index files, then flow into `Path::join` to build cache and
//! index-entry paths. A name carrying `..`, a path separator, or an absolute
//! prefix reroots that join outside the intended directory — an arbitrary-read
//! and a delete-then-clone into an attacker-chosen location.
//!
//! [`PackageName::parse`] is the one constructor. It admits only the portable
//! registry-name shape — a lowercase-alphanumeric first character followed by
//! lowercase alphanumerics or single `-` separators, bounded in length — so a
//! value of this type is a single, non-traversing, portable path component by
//! construction. The path-building sinks ([`crate::resolve`]'s
//! `package_cache_dir`, [`crate::index`]'s `entry_path`) take `&PackageName`, so
//! an unvalidated name can no longer reach a join.

use crate::CliError;

/// The maximum length of a package name, in bytes. Registry names are short
/// identifiers; a ceiling keeps a hostile manifest from proposing an
/// unboundedly long path component.
const MAX_LEN: usize = 64;

/// A package name proven to be a single, portable, non-traversing filesystem
/// path component.
///
/// The only constructor is [`PackageName::parse`]; every value has already been
/// checked. Use [`PackageName::as_str`] to obtain the validated component for a
/// path join.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PackageName(String);

impl PackageName {
    /// Parse a raw name into a [`PackageName`], rejecting any value that is not a
    /// safe single path component.
    ///
    /// Accepted shape: non-empty, at most [`MAX_LEN`] bytes, first character an
    /// ASCII lowercase letter or digit, remaining characters ASCII lowercase
    /// letters, digits, or `-` (never a leading, trailing, or doubled `-`). This
    /// admits registry names like `http-extras` while rejecting every path-shaping
    /// value: `..`, `.`, a leading `/`, an embedded `/` or `\`, a drive prefix,
    /// whitespace, control characters, and uppercase or unicode homoglyphs.
    ///
    /// # Errors
    /// [`CliError::Resolve`] naming the offending value when it is not an accepted
    /// package name. Fail closed: absent proof the name is a safe component, it is
    /// refused rather than joined.
    pub fn parse(raw: &str) -> Result<Self, CliError> {
        if raw.is_empty() {
            return Err(Self::reject(raw, "a package name must not be empty"));
        }
        if raw.len() > MAX_LEN {
            return Err(Self::reject(
                raw,
                &format!("a package name must be at most {MAX_LEN} bytes"),
            ));
        }
        let mut chars = raw.chars();
        match chars.next() {
            Some(first) if first.is_ascii_lowercase() || first.is_ascii_digit() => {}
            _ => {
                return Err(Self::reject(
                    raw,
                    "a package name must start with an ASCII lowercase letter or digit",
                ));
            }
        }
        let mut prev_dash = false;
        for c in chars {
            if c == '-' {
                if prev_dash {
                    return Err(Self::reject(
                        raw,
                        "a package name must not contain a doubled `-`",
                    ));
                }
                prev_dash = true;
                continue;
            }
            prev_dash = false;
            if !c.is_ascii_lowercase() && !c.is_ascii_digit() {
                return Err(Self::reject(
                    raw,
                    "a package name may contain only ASCII lowercase letters, digits, and `-`",
                ));
            }
        }
        if raw.ends_with('-') {
            return Err(Self::reject(raw, "a package name must not end with `-`"));
        }
        Ok(Self(raw.to_owned()))
    }

    /// The validated name, safe to use as a single `Path::join` component.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Build the typed rejection for a name that is not a safe path component.
    fn reject(raw: &str, why: &str) -> CliError {
        CliError::Resolve(format!(
            "`{}` is not a valid package name: {why} — a name is joined into a \
             filesystem path, so it must be a single portable path component \
             (matching `[a-z0-9]([a-z0-9]|-[a-z0-9])*`)",
            raw.escape_debug()
        ))
    }
}

impl std::fmt::Display for PackageName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Accepted names ─────────────────────────────────────────────────────────

    #[test]
    fn accepts_plain_lowercase() {
        assert_eq!(PackageName::parse("http").expect("plain").as_str(), "http");
    }

    #[test]
    fn accepts_hyphenated() {
        assert_eq!(
            PackageName::parse("http-extras")
                .expect("hyphenated")
                .as_str(),
            "http-extras"
        );
    }

    #[test]
    fn accepts_digits() {
        assert_eq!(PackageName::parse("md5").expect("digits").as_str(), "md5");
        assert_eq!(
            PackageName::parse("2fa").expect("leading digit").as_str(),
            "2fa"
        );
    }

    #[test]
    fn accepts_max_length() {
        let name = "a".repeat(MAX_LEN);
        assert_eq!(PackageName::parse(&name).expect("at cap").as_str(), name);
    }

    // ── Rejected: path-shaping values (the security-load-bearing cases) ─────────

    #[test]
    fn rejects_parent_traversal() {
        PackageName::parse("..").expect_err("`..` must be rejected");
    }

    #[test]
    fn rejects_embedded_parent_traversal() {
        PackageName::parse("../../etc/passwd").expect_err("embedded `..` must be rejected");
    }

    #[test]
    fn rejects_single_dot() {
        PackageName::parse(".").expect_err("`.` must be rejected");
    }

    #[test]
    fn rejects_absolute_unix() {
        PackageName::parse("/etc/passwd").expect_err("absolute path must be rejected");
    }

    #[test]
    fn rejects_embedded_forward_slash() {
        PackageName::parse("foo/bar").expect_err("embedded `/` must be rejected");
    }

    #[test]
    fn rejects_embedded_backslash() {
        PackageName::parse("foo\\bar").expect_err("embedded `\\` must be rejected");
    }

    #[test]
    fn rejects_windows_drive_prefix() {
        PackageName::parse("c:foo").expect_err("drive-letter `:` must be rejected");
    }

    #[test]
    fn rejects_dotfile_name() {
        PackageName::parse(".ipe").expect_err("a leading `.` must be rejected");
    }

    // ── Rejected: shape violations ─────────────────────────────────────────────

    #[test]
    fn rejects_empty() {
        PackageName::parse("").expect_err("empty must be rejected");
    }

    #[test]
    fn rejects_over_length() {
        let name = "a".repeat(MAX_LEN + 1);
        PackageName::parse(&name).expect_err("over-cap must be rejected");
    }

    #[test]
    fn rejects_uppercase() {
        PackageName::parse("Http").expect_err("uppercase must be rejected");
    }

    #[test]
    fn rejects_whitespace() {
        PackageName::parse("foo bar").expect_err("whitespace must be rejected");
        PackageName::parse("foo\n").expect_err("newline must be rejected");
    }

    #[test]
    fn rejects_control_char() {
        PackageName::parse("foo\0bar").expect_err("NUL must be rejected");
    }

    #[test]
    fn rejection_escapes_the_raw_name() {
        let err = PackageName::parse("a\u{1b}[2Jb\n").expect_err("control bytes are rejected");
        let msg = err.to_string();
        assert!(!msg.contains('\u{1b}') && !msg.contains('\n'), "{msg:?}");
        assert!(msg.contains("a\\u{1b}[2Jb\\n"), "{msg:?}");
    }

    #[test]
    fn rejects_non_ascii() {
        PackageName::parse("café").expect_err("non-ASCII must be rejected");
        // A homoglyph that could visually impersonate an ASCII name.
        PackageName::parse("аdmin").expect_err("Cyrillic homoglyph must be rejected");
    }

    #[test]
    fn rejects_leading_hyphen() {
        PackageName::parse("-foo").expect_err("leading `-` must be rejected");
    }

    #[test]
    fn rejects_trailing_hyphen() {
        PackageName::parse("foo-").expect_err("trailing `-` must be rejected");
    }

    #[test]
    fn rejects_doubled_hyphen() {
        PackageName::parse("foo--bar").expect_err("doubled `-` must be rejected");
    }
}
