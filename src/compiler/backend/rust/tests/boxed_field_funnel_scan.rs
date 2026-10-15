//! A pattern asks whether a constructor field is boxed in exactly one function.
//!
//! A cyclic self-edge field is `Box<…>` in the emitted enum, so every pattern
//! renderer that reads a constructor's payload must honour the box the same
//! way at every depth. `render_user_ctor_args` is that one place: this scan
//! lexes `patterns.rs` and refuses any read of the declared field types
//! (`variant_fields`) or of the box decision (`is_cyclic_self_field`) from any
//! other function there, so a renderer that grows its own boxed-field logic
//! goes red.

use std::collections::BTreeSet;

use proc_macro2::{Delimiter, TokenStream, TokenTree};

/// The `EmitCtx` lookups that decide how a constructor field is read.
const FIELD_LOOKUPS: &[&str] = &["variant_fields", "is_cyclic_self_field"];

/// The one function allowed to perform them.
const FUNNEL: &str = "render_user_ctor_args";

/// Every `(enclosing fn, lookup)` pair in `src`, the fn being the innermost one.
fn lookup_sites(src: &str) -> Result<BTreeSet<(String, String)>, String> {
    let stream: TokenStream = src.parse().map_err(|e| format!("does not lex: {e}"))?;
    let mut sites = BTreeSet::new();
    let mut pending: Vec<(TokenStream, String)> = vec![(stream, String::new())];
    while let Some((stream, owner)) = pending.pop() {
        // The name after a `fn` keyword, waiting for the body it owns.
        let mut named: Option<String> = None;
        let mut after_fn = false;
        for tok in stream {
            match tok {
                TokenTree::Ident(id) => {
                    let spelled = id.to_string();
                    if after_fn {
                        named = Some(spelled);
                        after_fn = false;
                    } else if spelled == "fn" {
                        after_fn = true;
                    } else if FIELD_LOOKUPS.contains(&spelled.as_str()) {
                        sites.insert((owner.clone(), spelled));
                    }
                }
                TokenTree::Group(g) => {
                    after_fn = false;
                    if g.delimiter() == Delimiter::Brace
                        && let Some(name) = named.take()
                    {
                        pending.push((g.stream(), name));
                    } else {
                        pending.push((g.stream(), owner.clone()));
                    }
                }
                TokenTree::Punct(p) => {
                    after_fn = false;
                    // A bodiless `fn` declaration ends at its `;`.
                    if p.as_char() == ';' {
                        named = None;
                    }
                }
                TokenTree::Literal(_) => after_fn = false,
            }
        }
    }
    Ok(sites)
}

/// The sites in `src` outside the funnel.
fn stray_sites(src: &str) -> Result<Vec<(String, String)>, String> {
    Ok(lookup_sites(src)?
        .into_iter()
        .filter(|(owner, _)| owner != FUNNEL)
        .collect())
}

/// `patterns.rs` reads a constructor's field types and box decision only in the funnel.
#[test]
fn patterns_read_boxed_fields_only_through_the_funnel() -> Result<(), String> {
    let path = e2e_support::manifest_dir!().join("src/emit_expr/patterns.rs");
    let src = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let stray = stray_sites(&src)?;
    assert!(
        stray.is_empty(),
        "a constructor field's box decision is read only in `{FUNNEL}`; \
         stray (fn, lookup) sites: {stray:?}"
    );
    let sites = lookup_sites(&src)?;
    for lookup in FIELD_LOOKUPS {
        assert!(
            sites.contains(&(FUNNEL.to_owned(), (*lookup).to_owned())),
            "`{FUNNEL}` performs `{lookup}`; the scan would otherwise pass vacuously"
        );
    }
    Ok(())
}

/// A lookup in any other function, nested or not, goes red; the funnel's own does not.
#[test]
fn a_boxed_field_lookup_outside_the_funnel_is_refused() -> Result<(), String> {
    let funnel = "fn render_user_ctor_args(ctx: &C) { \
                  let f = ctx.variant_fields(h, t, v); ctx.is_cyclic_self_field(f, h, t); }";
    assert!(stray_sites(funnel)?.is_empty(), "the funnel's lookups pass");
    let cases = [
        (
            "fn render_pat(ctx: &C) { ctx.is_cyclic_self_field(f, h, t); }",
            ("render_pat", "is_cyclic_self_field"),
        ),
        (
            "fn render_user_ctor_args() { fn inner(ctx: &C) { ctx.variant_fields(h, t, v); } }",
            ("inner", "variant_fields"),
        ),
        (
            "fn decl();\nconst X: usize = { variant_fields(); 0 };",
            ("", "variant_fields"),
        ),
        (
            "fn owned_elem(ctx: &C) { let g = |p| ctx.is_cyclic_self_field(p, h, t); }",
            ("owned_elem", "is_cyclic_self_field"),
        ),
    ];
    for (src, (owner, lookup)) in cases {
        assert_eq!(
            stray_sites(src)?,
            vec![(owner.to_owned(), lookup.to_owned())],
            "{src}"
        );
    }
    Ok(())
}
