#![forbid(unsafe_code)]
//! The foreign-binding coverage-matrix gate: the foreign surface enumerates
//! every capability axis in the closed vocabulary, and the aspect columns judge
//! each on capability-declared, boundary-discipline-wired, within-grant,
//! documented, and refusal-tested.
//!
//! This is the security-weighted sibling of the env-var coverage matrix: every
//! capability axis is one row, every security aspect is one column, and a hole
//! is named at its coordinate. The refusal-tested column is the load-bearing
//! security gate — a wired boundary gate with no reject-path test is a Hole
//! here, not a warning.

use ipe::coverage::contract::{AspectCheck, Cell, Surface};
use ipe::coverage::foreign_surface::{
    BoundaryClass, CapabilityDeclaredColumn, FOREIGN_ALLOWLIST, ForeignSurface,
};
use ipe::coverage::matrix;
use ipe_kernels::Capability;

#[test]
fn foreign_surface_is_non_empty() {
    let items = ForeignSurface
        .all()
        .expect("the live foreign surface must enumerate");
    assert!(
        !items.is_empty(),
        "the foreign surface must enumerate at least one capability axis",
    );
}

#[test]
fn foreign_surface_matches_capability_all() {
    // The surface is a direct mapping of `Capability::ALL` — the two must agree
    // so no axis can be added to the vocabulary without appearing on the surface.
    let surface_items = ForeignSurface
        .all()
        .expect("the live foreign surface must enumerate");
    let all_caps: Vec<Capability> = Capability::ALL.to_vec();
    assert_eq!(
        surface_items.len(),
        all_caps.len(),
        "foreign surface item count must equal Capability::ALL length"
    );
    for (item, cap) in surface_items.iter().zip(all_caps.iter()) {
        assert_eq!(
            item.capability, *cap,
            "foreign surface row order must mirror Capability::ALL"
        );
    }
}

#[test]
fn foreign_surface_label_is_the_wire_name() {
    for item in ForeignSurface
        .all()
        .expect("the live foreign surface must enumerate")
    {
        let label = ForeignSurface::label(&item);
        assert_eq!(
            label,
            item.capability.as_str(),
            "label of {:?} must be its wire name",
            item.capability
        );
    }
}

#[test]
fn every_js_port_axis_is_classified_as_js_port() {
    for item in ForeignSurface
        .all()
        .expect("the live foreign surface must enumerate")
    {
        if let Capability::JsPort(_) = item.capability {
            assert_eq!(
                item.boundary_class,
                BoundaryClass::JsPort,
                "{:?} must be classified JsPort",
                item.capability
            );
        }
    }
}

#[test]
fn capability_declared_column_passes_over_every_axis() {
    // Every axis in `Capability::ALL` round-trips through `as_str`/`from_str`
    // by construction; this test pins that the column agrees.
    let col = CapabilityDeclaredColumn;
    for item in ForeignSurface
        .all()
        .expect("the live foreign surface must enumerate")
    {
        assert!(
            matches!(col.check(&item), Cell::Ok),
            "capability-declared must pass for {:?} (wire: {:?})",
            item.capability,
            item.capability.as_str()
        );
    }
}

#[test]
fn capability_declared_column_rejects_a_synthetic_bad_item() {
    // Structural: if `as_str` returned an empty string the column would fire.
    // We cannot easily construct such an item without patching the enum, so
    // this test verifies the detection logic by checking that `from_str` does
    // reject an unknown wire name — the column's detection path.
    use std::str::FromStr as _;
    assert!(
        Capability::from_str("not-a-real-capability").is_err(),
        "from_str must reject an unrecognised wire name — the capability-declared \
         column's detection depends on this"
    );
}

#[test]
fn matrix_has_no_unexpected_holes() {
    // Run the full matrix and filter out the structurally-reasoned allowlist
    // entries. Any remaining hole is an unexpected security gap.
    use std::fmt::Write as _;

    let report = matrix::run_foreign().expect("the foreign matrix run must not fail closed");

    let mut unexpected = String::new();
    for h in report.holes.iter().filter(|h| {
        !FOREIGN_ALLOWLIST
            .iter()
            .any(|(aspect, symbol, _)| *aspect == h.aspect && *symbol == h.symbol)
    }) {
        let _ = writeln!(
            unexpected,
            "  HOLE [{}] {}: {}",
            h.aspect, h.symbol, h.message
        );
    }

    assert!(
        unexpected.is_empty(),
        "the foreign-binding coverage columns must pass over the whole surface (or \
         be recorded in FOREIGN_ALLOWLIST with a structural reason):\n{unexpected}\n\
         (allowlist has {} entr(y/ies))",
        FOREIGN_ALLOWLIST.len(),
    );
}

#[test]
fn allowlisted_holes_are_still_real() {
    // An allowlist entry that no longer corresponds to a real hole is stale;
    // stale entries hide genuine new holes and must be removed.
    let report = matrix::run_foreign().expect("the foreign matrix run must not fail closed");
    for (aspect, symbol, reason) in FOREIGN_ALLOWLIST {
        let present = report
            .holes
            .iter()
            .any(|h| h.aspect == *aspect && h.symbol == *symbol);
        assert!(
            present,
            "allowlisted hole [{aspect}] {symbol} ({reason}) is no longer \
             reported — remove the stale allowlist entry",
        );
    }
}

#[test]
fn refusal_tested_column_marks_disclosure_axes_not_applicable() {
    use ipe::coverage::foreign_surface::RefusalTestedColumn;
    let col = RefusalTestedColumn::new();
    for item in ForeignSurface
        .all()
        .expect("the live foreign surface must enumerate")
    {
        if item.boundary_class == BoundaryClass::Disclosure {
            assert!(
                matches!(col.check(&item), Cell::NotApplicable { .. }),
                "refusal-tested must be NotApplicable for disclosure axis {:?}",
                item.capability
            );
        }
    }
}

#[test]
fn within_grant_column_marks_disclosure_axes_not_applicable() {
    use ipe::coverage::foreign_surface::WithinGrantColumn;
    let col = WithinGrantColumn::new();
    for item in ForeignSurface
        .all()
        .expect("the live foreign surface must enumerate")
    {
        if item.boundary_class == BoundaryClass::Disclosure {
            assert!(
                matches!(col.check(&item), Cell::NotApplicable { .. }),
                "within-grant must be NotApplicable for disclosure axis {:?} \
                 (no OS isolation surface exists for this class)",
                item.capability
            );
        }
    }
}

#[test]
fn boundary_discipline_column_marks_disclosure_axes_not_applicable() {
    use ipe::coverage::foreign_surface::BoundaryDisciplineWiredColumn;
    let col = BoundaryDisciplineWiredColumn::new();
    for item in ForeignSurface
        .all()
        .expect("the live foreign surface must enumerate")
    {
        if item.boundary_class == BoundaryClass::Disclosure {
            assert!(
                matches!(col.check(&item), Cell::NotApplicable { .. }),
                "boundary-discipline-wired must be NotApplicable for disclosure \
                 axis {:?}",
                item.capability
            );
        }
    }
}

#[test]
fn js_port_axes_pass_boundary_discipline() {
    use ipe::coverage::foreign_surface::BoundaryDisciplineWiredColumn;
    let col = BoundaryDisciplineWiredColumn::new();
    for item in ForeignSurface
        .all()
        .expect("the live foreign surface must enumerate")
    {
        if item.boundary_class == BoundaryClass::JsPort {
            assert!(
                matches!(col.check(&item), Cell::Ok),
                "boundary-discipline-wired must pass for JsPort axis {:?} — \
                 the seal-decode gate must be present in the runtime source",
                item.capability
            );
        }
    }
}

#[test]
fn native_ffi_axes_pass_boundary_discipline() {
    use ipe::coverage::foreign_surface::BoundaryDisciplineWiredColumn;
    let col = BoundaryDisciplineWiredColumn::new();
    let items: Vec<_> = ForeignSurface
        .all()
        .expect("the live foreign surface must enumerate")
        .into_iter()
        .filter(|i| i.boundary_class == BoundaryClass::NativeFfi)
        .collect();
    assert!(
        !items.is_empty(),
        "there must be at least one NativeFfi item on the surface"
    );
    for item in items {
        assert!(
            matches!(col.check(&item), Cell::Ok),
            "boundary-discipline-wired must pass for NativeFfi axis {:?} — \
             a jail invocation must be present in the sandbox source",
            item.capability
        );
    }
}

#[test]
fn js_port_axes_pass_refusal_tested() {
    use ipe::coverage::foreign_surface::RefusalTestedColumn;
    let col = RefusalTestedColumn::new();
    for item in ForeignSurface
        .all()
        .expect("the live foreign surface must enumerate")
    {
        if item.boundary_class == BoundaryClass::JsPort {
            assert!(
                matches!(col.check(&item), Cell::Ok),
                "refusal-tested must pass for JsPort axis {:?} — \
                 a test driving the seal-decode REJECT path \
                 (SealDecodeError:: or \"seal decode rejected\") must exist",
                item.capability
            );
        }
    }
}

#[test]
fn native_ffi_axes_pass_refusal_tested() {
    use ipe::coverage::foreign_surface::RefusalTestedColumn;
    let col = RefusalTestedColumn::new();
    for item in ForeignSurface
        .all()
        .expect("the live foreign surface must enumerate")
    {
        if item.boundary_class == BoundaryClass::NativeFfi {
            assert!(
                matches!(col.check(&item), Cell::Ok),
                "refusal-tested must pass for NativeFfi axis {:?} — \
                 a test driving must_refuse or UnknownCapability must exist \
                 in the FFI or capability test trees",
                item.capability
            );
        }
    }
}

#[test]
fn surface_is_deterministic() {
    let first = ForeignSurface
        .all()
        .expect("the live foreign surface must enumerate");
    let second = ForeignSurface
        .all()
        .expect("the live foreign surface must enumerate");
    assert_eq!(
        first.len(),
        second.len(),
        "two enumerations must have the same length"
    );
    for (a, b) in first.iter().zip(second.iter()) {
        assert_eq!(
            a.capability, b.capability,
            "two enumerations must agree at every position"
        );
    }
}

#[test]
fn network_and_filesystem_axes_pass_refusal_tested() {
    // Network and filesystem are the two OS-resource axes most likely to have
    // existing tests — pin them individually so a regression is named
    // precisely rather than hidden inside the full matrix result.
    use ipe::coverage::foreign_surface::RefusalTestedColumn;
    let col = RefusalTestedColumn::new();

    let network_item = ForeignSurface
        .all()
        .expect("the live foreign surface must enumerate")
        .into_iter()
        .find(|i| i.capability == Capability::Network)
        .expect("Network must be on the surface");
    let filesystem_item = ForeignSurface
        .all()
        .expect("the live foreign surface must enumerate")
        .into_iter()
        .find(|i| i.capability == Capability::Filesystem)
        .expect("Filesystem must be on the surface");

    assert!(
        matches!(col.check(&network_item), Cell::Ok),
        "refusal-tested must pass for network — a test proving the network \
         capability is refused when un-granted must exist"
    );
    assert!(
        matches!(col.check(&filesystem_item), Cell::Ok),
        "refusal-tested must pass for filesystem — a test proving the filesystem \
         capability is refused when un-granted must exist"
    );
}
