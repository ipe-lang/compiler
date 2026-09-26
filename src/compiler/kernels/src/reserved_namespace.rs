//! The reserved module-namespace vocabulary and the blessed first-party
//! publisher identity — the single source of truth both the compiler resolver
//! and the registry admission gate read.
//!
//! `Ipe.*` is the trusted namespace: its modules are the bundled, reviewed,
//! first-party standard library. `Rust.*` is the driver-generated FFI interface
//! namespace. Neither may be claimed by an ordinary third-party package, so
//! "first-party = trusted" stays a checked fact rather than a naming convention.
//!
//! This is a closed list, like the [`crate::Capability`] vocabulary: a new
//! reserved prefix is added to [`RESERVED_MODULE_PREFIXES`] here and every
//! enforcement point reads it, so the resolver's reserved-namespace gate and the
//! registry admission gate can never drift apart into two hand-maintained lists.
//!
//! Default-deny: an unknown-provenance package whose module set claims any
//! reserved prefix is rejected. Only the blessed first-party publisher
//! ([`BLESSED_PUBLISHER`]) may own a reserved-prefix module in the registry, and
//! only the compiler's own unforgeable stdlib-injection origin may define one at
//! compile time.

/// Every reserved top-level module segment, in declaration order. A module whose
/// first path segment equals one of these lives in a reserved namespace.
///
/// The vocabulary is closed: adding a new reserved namespace is a single edit
/// here, after which [`reserved_prefix_of`] classifies it for every caller.
pub const RESERVED_MODULE_PREFIXES: &[&str] = &["Ipe", "Rust"];

/// Every reserved package-name namespace, in declaration order.
///
/// A package whose name equals one of these, or extends it by a hyphen segment,
/// lives in a reserved package namespace owned by the blessed first-party
/// publisher.
///
/// The disposable registry-publish-smoke probe packages
/// (`ipe-registry-smoke-probe` / `ipe-registry-smoke-probe-bad`) live here; a
/// third party must not claim a package name in these namespaces, since a
/// squatted probe name could ride the smoke auto-approve path.
///
/// The vocabulary is closed: adding a new reserved package namespace is a single
/// edit here, after which [`reserved_package_prefix_of`] classifies it for every
/// caller.
pub const RESERVED_PACKAGE_PREFIXES: &[&str] = &["ipe-registry-smoke"];

/// The blessed first-party publisher identity — the one account permitted to own
/// a module in a reserved namespace (`Ipe.*`, `Rust.*`) in the registry.
///
/// Held here, once, so the resolver and the admission gate agree on who is
/// first-party. Changing the first-party identity is a single edit at this
/// constant, never a handle sprinkled across enforcement sites. It is compared
/// only against a proven identity (the CLI's `publisher::BlessedPublisher`
/// constructors), never against a self-declared `publisher` string.
pub const BLESSED_PUBLISHER: &str = "arthurmaciel";

/// The reserved prefix a parsed module path claims, if any.
///
/// The input is an already-parsed module path (its segments), never a raw
/// string: this is a typed predicate over structure, not a substring match on
/// user input. `Ipe.Palette` → `Some("Ipe")`; `Ipevil.Thing` → `None` (a
/// distinct top-level segment, not the reserved one); `Main` → `None`.
#[must_use]
pub fn reserved_prefix_of<S: AsRef<str>>(module_path: &[S]) -> Option<&'static str> {
    let first = module_path.first()?.as_ref();
    RESERVED_MODULE_PREFIXES
        .iter()
        .copied()
        .find(|&reserved| reserved == first)
}

/// The reserved package-name prefix a package name claims, if any.
///
/// A segment-boundary predicate, never a raw substring match: a name is reserved
/// iff it equals a reserved prefix `P` or extends it by a hyphen segment
/// (`P-…`). `ipe-registry-smoke-probe` → `Some("ipe-registry-smoke")`;
/// `ipe-registry-smokehouse` → `None` (a distinct name, not a hyphen-segment
/// extension); `cool-lib` → `None`.
#[must_use]
pub fn reserved_package_prefix_of(package_name: &str) -> Option<&'static str> {
    RESERVED_PACKAGE_PREFIXES.iter().copied().find(|&prefix| {
        package_name == prefix
            || package_name
                .strip_prefix(prefix)
                .is_some_and(|rest| rest.starts_with('-'))
    })
}

/// Whether a module path lives in a reserved namespace.
#[must_use]
pub fn is_reserved_module_path<S: AsRef<str>>(module_path: &[S]) -> bool {
    reserved_prefix_of(module_path).is_some()
}

#[cfg(test)]
mod tests {
    use super::{
        RESERVED_MODULE_PREFIXES, is_reserved_module_path, reserved_package_prefix_of,
        reserved_prefix_of,
    };

    #[test]
    fn ipe_and_rust_are_the_reserved_prefixes() {
        assert_eq!(RESERVED_MODULE_PREFIXES, &["Ipe", "Rust"]);
    }

    #[test]
    fn reserved_prefix_matches_the_first_segment_only() {
        assert_eq!(reserved_prefix_of(&["Ipe", "Palette"]), Some("Ipe"));
        assert_eq!(reserved_prefix_of(&["Rust", "Zstd"]), Some("Rust"));
        // A distinct top-level segment that merely starts with the same letters
        // is NOT reserved — this is a segment predicate, not a substring match.
        assert_eq!(reserved_prefix_of(&["Ipevil", "Thing"]), None);
        assert_eq!(reserved_prefix_of(&["Main"]), None);
        assert_eq!(reserved_prefix_of(&["MyIpe", "Ipe"]), None);
    }

    #[test]
    fn empty_path_claims_no_prefix() {
        let empty: &[&str] = &[];
        assert_eq!(reserved_prefix_of(empty), None);
        assert!(!is_reserved_module_path(empty));
    }

    #[test]
    fn is_reserved_agrees_with_prefix_lookup() {
        assert!(is_reserved_module_path(&["Ipe", "String"]));
        assert!(is_reserved_module_path(&["Rust"]));
        assert!(!is_reserved_module_path(&["App", "View"]));
    }

    #[test]
    fn reserved_package_prefix_matches_the_hyphen_segment_boundary_only() {
        // The exact prefix and any hyphen-segment extension are reserved.
        assert_eq!(
            reserved_package_prefix_of("ipe-registry-smoke"),
            Some("ipe-registry-smoke")
        );
        assert_eq!(
            reserved_package_prefix_of("ipe-registry-smoke-probe"),
            Some("ipe-registry-smoke")
        );
        assert_eq!(
            reserved_package_prefix_of("ipe-registry-smoke-probe-bad"),
            Some("ipe-registry-smoke")
        );
        // A distinct name that merely shares the leading characters without a
        // hyphen segment boundary is NOT reserved — this is a segment predicate,
        // not a substring match.
        assert_eq!(reserved_package_prefix_of("ipe-registry-smokehouse"), None);
        assert_eq!(reserved_package_prefix_of("cool-lib"), None);
        assert_eq!(reserved_package_prefix_of(""), None);
    }
}
