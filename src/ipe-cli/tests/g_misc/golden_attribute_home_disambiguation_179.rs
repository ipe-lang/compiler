//! E2E regression golden for `Attribute<msg>` type-identity
//! disambiguation between `ipe_runtime::html::Attribute` and
//! `ipe_runtime::ui::element::Attribute`.
//!
//! ## The bug
//!
//! `Attribute` exists in BOTH `Ipe.Ui` (→ `ui::element::Attribute`) and
//! `Ipe.Html.Attributes` (→ `html::Attribute`).  The lowerer disambiguates by
//! `is_html = home contains "Html"`. If a bare/aliased `Attribute` from a
//! stdlib module reaches the empty-home sentinel (stdlib imports are
//! skipped by both the dep-injection loop and the `qualifier_paths`
//! construction), `is_html` always fails and BOTH the bare-exposed form
//! (`Ipe.Web.Head.pairToAttr`) and the qualified form
//! (`Ipe.Ui.Chart.svgRootAttrs`) mis-lower `Attribute msg` to
//! `ui::element::Attribute` while their `Attr.attribute` bodies produce
//! `html::Attribute` — an exit-0-then-cargo-fail E0308 SEAL violation.
//!
//! ## What is tested
//!
//! * `ipe build` compiles `tests/golden/attribute_home_disambiguation_179/
//!   Main.ipe` (canon → types → lower → Rust backend).
//! * The emitted Rust project `cargo build`s (the type-identity fix means the
//!   `html::Attribute`-producing bodies now agree with their return-type
//!   annotations) and the binary runs and exits 0.
//! * The rendered `<svg>` carries the attributes from BOTH a polymorphic-msg
//!   `pairToAttr` (bare `Attribute` exposed from `Ipe.Html.Attributes`) and a
//!   `svgRootAttrs`-style list, proving the `html::Attribute` list flowed into
//!   the `Html.node` slot without a cast.
//!
//! `oracle_divergence = true` — the assertion is ipe's own correct render, not
//! a golden oracle diff; the point is the Attribute NEWTYPE identity, which the golden
//! backend does not model.
//!
//! Run:
//!
//! ```text
//! IPE_E2E=1 cargo test golden_attribute_home_disambiguation_179
//! ```

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    let joined = e2e_support::manifest_dir!().join("..").join("..");
    std::fs::canonicalize(&joined).unwrap_or(joined)
}

/// Compile / build / run the golden and return its run outcome. Gated on
/// `IPE_E2E=1`.
fn build_run_attribute_home_179() -> crate::support::RunOutcome {
    let root = repo_root();
    let dir = root
        .join("tests")
        .join("golden")
        .join("attribute_home_disambiguation_179");
    let entry = dir.join("Main.ipe");
    let out = crate::support::scratch_root().join("ipec_attribute_home_179_e2e");
    let _ = std::fs::remove_dir_all(&out);

    let runtime = e2e_support::require_runtime().into_path_buf();
    let built = ipe::build(&entry, &out, &runtime);
    assert!(
        built.is_ok(),
        "ipe build must succeed for attribute_home_disambiguation_179: {:?}",
        built.err()
    );

    crate::support::build_and_run_emitted("attribute_home_disambiguation_179", &out)
}

#[test]
fn attribute_home_disambiguation_179_builds_and_renders() {
    if e2e_support::e2e_tier() == e2e_support::Tier::Unit {
        return;
    }

    let outcome = build_run_attribute_home_179();
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "binary must exit 0 (the html::Attribute return types must agree with \
         their html::Attribute-producing bodies)\n--- stdout ---\n{}",
        outcome.stdout
    );

    let rendered = outcome.stdout;

    // The `<svg>` root — proves `svgRootAttrs` (a `List (Attribute msg)`) flowed
    // into `Html.node`'s `html::Attribute` slot.
    assert!(
        rendered.contains("<svg"),
        "must render an <svg> root\n--- stdout ---\n{rendered}"
    );
    // Attributes from the polymorphic-msg `svgRootAttrs` list.
    assert!(
        rendered.contains("viewBox=\"0 0 100 40\""),
        "svgRootAttrs viewBox attribute must render\n--- stdout ---\n{rendered}"
    );
    assert!(
        rendered.contains("role=\"img\""),
        "svgRootAttrs role attribute must render\n--- stdout ---\n{rendered}"
    );
    // Attributes produced by `pairToAttr` (bare exposed `Attribute` from
    // Ipe.Html.Attributes, mapped over a list) — the exact target shape.
    assert!(
        rendered.contains("width=\"100\"") && rendered.contains("height=\"40\""),
        "pairToAttr-produced width/height attributes must render\n--- stdout ---\n{rendered}"
    );
    // The nested <rect> child confirms the whole svg subtree serialised.
    assert!(
        rendered.contains("<rect"),
        "nested <rect> must render\n--- stdout ---\n{rendered}"
    );
}
