//! Typed tables for super-type prim-set membership.
//!
//! Each primitive obligation (Number, Ord, `ComparableKey`, `SqlParam`, Append,
//! Interpolable) is
//! declared once here. Call sites in `unify`, `lib` (emitted-bound gate), and
//! `lib` (concrete-pin gate) all read from this table via [`prim_satisfies`]
//! instead of restating the literal `matches!` arms independently.
//!
//! The one sanctioned axis of variation — ordering over `String` — is encoded
//! as a [`BoundSite`] parameter: at an *emitted-generic* site `String` is
//! excluded from Ord (the Rust backend requires `Copy` for ordering generics);
//! at a *concrete-pin* site `String` is included (direct comparison borrows).

/// Which call-site context is checking the bound.
///
/// The only obligation that varies between sites is `Ord` over `String`:
/// the generic-emission gate excludes `String` (Rust `Copy` restriction),
/// while the concrete-pin gate includes it (borrow-based direct comparison).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BoundSite {
    /// A generic type-parameter emission (the `emitted_bound_satisfied` gate).
    EmittedGeneric,
    /// A concrete type pinned directly (the `concrete_super_ok` and
    /// `super_concrete_ok` head-pin gates).
    ConcretePin,
}

/// Prim names that satisfy the `number` super-type (`+`, `-`, `*`) — exactly
/// [`ipe_diagnostics::NUMBER_TYPES`], the table the help line names.
pub const NUMBER: &[&str] = &ipe_diagnostics::NUMBER_TYPES;

/// Prim names that satisfy `ord` at an **emitted-generic** site.
///
/// `String` is excluded: Rust ordering generics require `Copy`, which `String`
/// does not implement. A direct `"a" > "b"` (concrete-pin) borrows, so
/// `String` is admitted there via [`ORD_BORROW`].
pub const ORD_COPY: &[&str] = &["Int", "Float", "Char", "Bool"];

/// Prim names that satisfy `ord` at a **concrete-pin** site.
///
/// `String` is included: direct comparison borrows operands and needs no
/// `Copy`. Differs from [`ORD_COPY`] only in the `String` slot. Exactly
/// [`ipe_diagnostics::COMPARABLE_TYPES`], the table the help line names.
pub const ORD_BORROW: &[&str] = &ipe_diagnostics::COMPARABLE_TYPES;

/// Prim names that satisfy the `comparable` key constraint (`Set` element /
/// `Dict` key at the Ipê type level).
///
/// `Float` is admitted here because Ipê's type system accepts it as
/// `comparable`; the Rust-backend reality that `f64` is neither `Hash` nor
/// `Eq` is enforced at lowering (see `ipe_lower`'s `float_key_rejected`).
/// Exactly [`ipe_diagnostics::COMPARABLE_TYPES`], the table the help line names.
pub const COMPARABLE_KEY: &[&str] = &ipe_diagnostics::COMPARABLE_TYPES;

/// Prim names that satisfy the SQL-bind-parameter constraint.
pub const SQL_PARAM: &[&str] = &["Int", "Float", "String", "Bool", "SqlValue"];

/// The bare scalar prim that satisfies `append` (the `++` operator on scalars).
///
/// `List _` is also appendable, but it carries a type argument and is checked
/// structurally at the call sites; only the bare-scalar membership lives here.
pub const APPEND_PRIM: &[&str] = &["String"];

/// Prim names that satisfy the interpolation constraint (`{{…}}` / `Log.*With`
/// attributes) — exactly [`ipe_diagnostics::INTERPOLABLE_TYPES`], the closed
/// scalar set the runtime's sealed `IpeInterpolate` trait is implemented for.
pub const INTERPOLABLE: &[&str] = &ipe_diagnostics::INTERPOLABLE_TYPES;

/// Whether primitive name `prim` satisfies super-type bound `bound` at
/// call-site `site`.
///
/// Returns `false` for `None` (non-bare-prim types do not satisfy prim-set
/// bounds via this table; structural checks such as `List _` for `append` are
/// handled at the call sites).
#[must_use]
#[inline]
pub fn prim_satisfies_number(prim: Option<&str>) -> bool {
    prim.is_some_and(|p| NUMBER.contains(&p))
}

#[must_use]
#[inline]
pub fn prim_satisfies_ord(prim: Option<&str>, site: BoundSite) -> bool {
    let table = match site {
        BoundSite::EmittedGeneric => ORD_COPY,
        BoundSite::ConcretePin => ORD_BORROW,
    };
    prim.is_some_and(|p| table.contains(&p))
}

#[must_use]
#[inline]
pub fn prim_satisfies_comparable_key(prim: Option<&str>) -> bool {
    prim.is_some_and(|p| COMPARABLE_KEY.contains(&p))
}

#[must_use]
#[inline]
pub fn prim_satisfies_sql_param(prim: Option<&str>) -> bool {
    prim.is_some_and(|p| SQL_PARAM.contains(&p))
}

#[must_use]
#[inline]
pub fn prim_satisfies_append_prim(prim: Option<&str>) -> bool {
    prim.is_some_and(|p| APPEND_PRIM.contains(&p))
}

#[must_use]
#[inline]
pub fn prim_satisfies_interpolable(prim: Option<&str>) -> bool {
    prim.is_some_and(|p| INTERPOLABLE.contains(&p))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_PRIMS: &[&str] = &["Int", "Float", "Char", "String", "Bool", "SqlValue", "Unit"];

    /// Every prim satisfies the exact bounds declared in the tables.
    #[test]
    fn super_bound_predicates_agree() {
        // NUMBER
        for p in ALL_PRIMS {
            let expected = NUMBER.contains(p);
            assert_eq!(
                prim_satisfies_number(Some(p)),
                expected,
                "NUMBER mismatch for {p}"
            );
        }
        assert!(!prim_satisfies_number(None));

        // ORD: EmittedGeneric (Copy-restricted — no String)
        for p in ALL_PRIMS {
            let expected = ORD_COPY.contains(p);
            assert_eq!(
                prim_satisfies_ord(Some(p), BoundSite::EmittedGeneric),
                expected,
                "ORD_COPY mismatch for {p}"
            );
        }

        // ORD: ConcretePin (borrow — String ok)
        for p in ALL_PRIMS {
            let expected = ORD_BORROW.contains(p);
            assert_eq!(
                prim_satisfies_ord(Some(p), BoundSite::ConcretePin),
                expected,
                "ORD_BORROW mismatch for {p}"
            );
        }

        // COMPARABLE_KEY
        for p in ALL_PRIMS {
            let expected = COMPARABLE_KEY.contains(p);
            assert_eq!(
                prim_satisfies_comparable_key(Some(p)),
                expected,
                "COMPARABLE_KEY mismatch for {p}"
            );
        }

        // SQL_PARAM
        for p in ALL_PRIMS {
            let expected = SQL_PARAM.contains(p);
            assert_eq!(
                prim_satisfies_sql_param(Some(p)),
                expected,
                "SQL_PARAM mismatch for {p}"
            );
        }

        // APPEND_PRIM
        for p in ALL_PRIMS {
            let expected = APPEND_PRIM.contains(p);
            assert_eq!(
                prim_satisfies_append_prim(Some(p)),
                expected,
                "APPEND_PRIM mismatch for {p}"
            );
        }

        // INTERPOLABLE
        for p in ALL_PRIMS {
            let expected = INTERPOLABLE.contains(p);
            assert_eq!(
                prim_satisfies_interpolable(Some(p)),
                expected,
                "INTERPOLABLE mismatch for {p}"
            );
        }
        assert!(!prim_satisfies_interpolable(None));
    }

    /// The interpolation set is exactly the five scalars — `Unit` and
    /// `SqlValue` (and every non-bare-prim type) are refused.
    #[test]
    fn interpolable_is_exactly_the_five_scalars() {
        for p in ["String", "Int", "Float", "Bool", "Char"] {
            assert!(prim_satisfies_interpolable(Some(p)), "{p} must interpolate");
        }
        for p in ["Unit", "SqlValue", "List", "Maybe", "Secret", "Request"] {
            assert!(
                !prim_satisfies_interpolable(Some(p)),
                "{p} must not interpolate"
            );
        }
    }

    /// The one sanctioned divergence: ORD over "String" differs by site.
    #[test]
    fn ord_string_diverges_by_site() {
        assert!(
            !prim_satisfies_ord(Some("String"), BoundSite::EmittedGeneric),
            "String must NOT satisfy ORD at EmittedGeneric (Copy required)"
        );
        assert!(
            prim_satisfies_ord(Some("String"), BoundSite::ConcretePin),
            "String MUST satisfy ORD at ConcretePin (borrow ok)"
        );
    }
}
