//! Indexed table of a `view`'s appearance literals (style values, attribute
//! strings, static text), read at render time.
//!
//! The compiler bakes a `view`'s appearance literals in as this table's
//! defaults and emits each literal site as a `get(idx)` read. Prod holds only
//! the defaults, so the table-reading `view` renders exactly what a direct
//! literal emit would — one render semantics, dev == prod. In dev an
//! appearance edit ships a patch (`apply_patch`) over the live socket; the
//! running program swaps the affected entries and re-renders with its current
//! Model, with no recompile.
//!
//! `get` is total: an out-of-range index returns `""` rather than panicking, so
//! a stale patch index can never make a well-typed program fall over.

/// A `view`'s appearance literals, indexed by emit-assigned position.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LiteralTable {
    values: Vec<String>,
}

impl LiteralTable {
    /// Build a table from the compiler-baked default literals, in emit order.
    ///
    /// In a dev appearance-hot-swap process (flag on, non-production — see
    /// [`dev_overlay_active`]) the baked table is overlaid with any patch the
    /// dev control path has registered for this exact defaults signature, so
    /// the re-rendered `view` reflects the live edit without a recompile. With
    /// the flag off (or in production) no overlay is ever consulted and the
    /// result is exactly the baked defaults — one render semantics, dev == prod.
    #[must_use]
    pub fn from_defaults(defaults: &[&str]) -> Self {
        let mut table = Self {
            values: defaults.iter().map(|s| (*s).to_string()).collect(),
        };
        if dev_overlay_active() {
            table.apply_dev_overlay();
        }
        table
    }

    /// Apply the dev overlay patch registered for this table's defaults
    /// signature, if any. Never called on a flag-off / production render (the
    /// `from_defaults` gate short-circuits first), so it adds no prod cost.
    fn apply_dev_overlay(&mut self) {
        if let Some(patch) = dev_overlay_patch_for(&self.values) {
            self.apply_patch(&patch);
        }
    }

    /// The literal at `idx`, or `""` when `idx` is out of range.
    ///
    /// Total by construction: no index — stale patch or otherwise — can panic.
    #[must_use]
    pub fn get(&self, idx: usize) -> &str {
        self.values.get(idx).map_or("", String::as_str)
    }

    /// Apply an appearance patch: replace the value at each given index.
    ///
    /// An out-of-range index in the patch is ignored (the patch describes
    /// entries that must already exist in the baked table), keeping the
    /// operation total.
    pub fn apply_patch(&mut self, patch: &[(usize, String)]) {
        for (idx, value) in patch {
            if let Some(slot) = self.values.get_mut(*idx) {
                *slot = value.clone();
            }
        }
    }

    /// The number of literals in the table.
    #[must_use]
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Whether the table holds no literals.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

// ─── dev-only appearance-hot-swap overlay ───────────────────────────────────
//
// The running web app owns its view tables through the emitted `from_defaults`
// prologue, which rebuilds a table from baked defaults on every `view` call. To
// hot-swap an appearance literal without a recompile, the dev control path
// registers a patch here keyed by the view's *defaults signature* (its exact
// baked values, in emit order); the next `from_defaults` for that signature
// overlays the patch, so a re-render of `view(currentModel)` reflects the edit.
//
// Keying by the defaults signature (rather than a single global patch) confines
// an edit to the one view whose literals it describes: a second view with
// different defaults never sees it. The defaults never mutate — only the table
// instance is patched — so the signature stays stable across re-renders.
//
// The overlay is inert unless [`dev_overlay_active`] holds (flag on AND a
// dev intent). In a production build the flag is off and the dev control
// path is never mounted, so no patch is ever registered and `from_defaults`
// never consults the overlay — one render semantics, dev == prod.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// The registered dev patches, keyed by a view's baked-defaults signature.
/// `None` until the first registration; empty map thereafter reads as "no
/// overlay". Guarded by a `Mutex`; a poisoned lock is recovered (the map holds
/// only inert value patches, so a panic mid-update cannot leave it unsound).
type DevOverlay = HashMap<Vec<String>, Vec<(usize, String)>>;

fn dev_overlay() -> &'static Mutex<DevOverlay> {
    static OVERLAY: OnceLock<Mutex<DevOverlay>> = OnceLock::new();
    OVERLAY.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Whether the appearance-hot-swap overlay may affect a render: the
/// `IPE_WATCH_HOT_APPEARANCE` flag is set to a truthy value AND the process
/// holds a [`DevIntent`](crate::telemetry::DevIntent). Read on every
/// `from_defaults`, so it is cached once.
///
/// This is the single gate that keeps the overlay a dev-only mechanism: with
/// the flag off (the default), or on a release build or in production, it
/// returns `false`, so
/// `from_defaults` returns the baked defaults untouched and the overlay is
/// never even consulted.
#[must_use]
pub fn dev_overlay_active() -> bool {
    #[cfg(test)]
    #[cfg(not(target_arch = "wasm32"))]
    if let Some(forced) = test_override::get() {
        return forced;
    }
    static ACTIVE: OnceLock<bool> = OnceLock::new();
    *ACTIVE.get_or_init(|| {
        let flag_on = crate::system::read_env_var("IPE_WATCH_HOT_APPEARANCE")
            .ok()
            .is_some_and(|v| !v.is_empty() && v != "0");
        overlay_gate(flag_on, crate::telemetry::dev_intent_from_env().as_ref())
    })
}

/// The overlay gate under an explicit flag read and dev-intent proof.
const fn overlay_gate(flag_on: bool, dev: Option<&crate::telemetry::DevIntent>) -> bool {
    flag_on && dev.is_some()
}

/// Test-only override for [`dev_overlay_active`], so a test can exercise both the
/// active and inert paths without depending on process-global env cached at
/// first call. Never compiled into a non-test build, so it cannot affect the
/// production gate.
#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod test_override {
    use std::sync::atomic::{AtomicU8, Ordering};

    // 0 = unset (fall through to the env gate); 1 = forced inactive; 2 = forced active.
    static OVERRIDE: AtomicU8 = AtomicU8::new(0);

    pub(super) fn get() -> Option<bool> {
        match OVERRIDE.load(Ordering::SeqCst) {
            1 => Some(false),
            2 => Some(true),
            _ => None,
        }
    }

    pub(crate) fn set(active: Option<bool>) {
        let v = match active {
            None => 0,
            Some(false) => 1,
            Some(true) => 2,
        };
        OVERRIDE.store(v, Ordering::SeqCst);
    }
}

/// Force [`dev_overlay_active`] for a test, or `None` to fall back to the env
/// gate. Test-support only.
#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn set_dev_overlay_active_for_test(active: Option<bool>) {
    test_override::set(active);
}

/// The single process-wide guard every test that touches the dev overlay
/// (the override flag AND the registered patches, both process-global statics)
/// must hold, so no two such tests — in this module or elsewhere in the web
/// crate — interleave their global-state mutations.
#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn overlay_test_lock() -> std::sync::MutexGuard<'static, ()> {
    static GUARD: std::sync::Mutex<()> = std::sync::Mutex::new(());
    GUARD.lock().unwrap_or_else(|e| e.into_inner())
}

/// Register (or replace) the dev patch for the view whose baked defaults are
/// `defaults`. A subsequent `from_defaults` for that exact signature overlays
/// the patch. No-op when the dev overlay is inactive, so a stray call in a
/// production build changes nothing.
///
/// Replacing (not merging) means the most recent edit for a view fully
/// describes its current appearance state — the watch classifier sends the
/// full appearance delta for the edited view each time.
pub fn register_dev_patch(defaults: &[String], patch: Vec<(usize, String)>) {
    if !dev_overlay_active() {
        return;
    }
    let mut map = dev_overlay().lock().unwrap_or_else(|e| e.into_inner());
    map.insert(defaults.to_vec(), patch);
}

/// The dev patch registered for a view's defaults signature, if any.
fn dev_overlay_patch_for(defaults: &[String]) -> Option<Vec<(usize, String)>> {
    let map = dev_overlay().lock().unwrap_or_else(|e| e.into_inner());
    map.get(defaults).cloned()
}

/// Clear all registered dev patches. Test-support for asserting the flag-off /
/// inert path without cross-test overlay leakage.
#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn clear_dev_overlay_for_test() {
    let mut map = dev_overlay().lock().unwrap_or_else(|e| e.into_inner());
    map.clear();
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::LiteralTable;

    #[test]
    fn table_get_is_total_and_patchable() {
        let mut t = LiteralTable::from_defaults(&["12px", "red"]);
        assert_eq!(t.get(0), "12px");
        assert_eq!(t.get(99), ""); // out of range is total, never panics
        t.apply_patch(&[(0, "16px".to_string())]);
        assert_eq!(t.get(0), "16px");
        assert_eq!(t.get(1), "red"); // untouched
    }

    #[test]
    fn empty_table_get_is_empty_string() {
        let t = LiteralTable::from_defaults(&[]);
        assert!(t.is_empty());
        assert_eq!(t.len(), 0);
        assert_eq!(t.get(0), "");
    }

    #[test]
    fn out_of_range_patch_index_is_ignored() {
        let mut t = LiteralTable::from_defaults(&["a"]);
        t.apply_patch(&[(5, "z".to_string())]);
        assert_eq!(t.get(0), "a");
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn multi_entry_patch_replaces_each_named_index() {
        let mut t = LiteralTable::from_defaults(&["a", "b", "c"]);
        t.apply_patch(&[(0, "A".to_string()), (2, "C".to_string())]);
        assert_eq!(t.get(0), "A");
        assert_eq!(t.get(1), "b");
        assert_eq!(t.get(2), "C");
    }

    // ─── dev overlay (appearance hot-swap) ─────────────────────────────────
    //
    // The override + overlay are process-global statics, so these tests
    // serialise on one guard to avoid cross-test interference; each restores the
    // override to "unset" and clears the overlay on the way out.
    use super::overlay_test_lock as overlay_test_guard;

    // The flag alone never activates the overlay: without a dev intent (a
    // release build under `ENV=dev`) the gate is closed.
    #[test]
    fn overlay_inactive_on_release_under_env_dev() {
        let dev = crate::telemetry::test_dev_intent();
        assert!(!super::overlay_gate(true, None));
        assert!(!super::overlay_gate(false, Some(&dev)));
        assert!(super::overlay_gate(true, Some(&dev)));
        if !cfg!(feature = "dev-posture") {
            let _g = overlay_test_guard();
            super::set_dev_overlay_active_for_test(None);
            crate::system::locked_set_var("ENV", "dev");
            crate::system::locked_set_var("IPE_WATCH_HOT_APPEARANCE", "1");
            assert!(!super::dev_overlay_active());
            crate::system::locked_remove_var("IPE_WATCH_HOT_APPEARANCE");
            crate::system::locked_remove_var("ENV");
        }
    }

    #[test]
    fn overlay_inactive_by_default_renders_baked_defaults() {
        let _g = overlay_test_guard();
        super::set_dev_overlay_active_for_test(Some(false));
        super::clear_dev_overlay_for_test();

        // Registration is a no-op while inactive, so from_defaults is untouched —
        // byte-identical to today's baked table.
        super::register_dev_patch(&["12px".to_string()], vec![(0, "16px".to_string())]);
        let t = LiteralTable::from_defaults(&["12px"]);
        assert_eq!(
            t.get(0),
            "12px",
            "inactive overlay must not patch the render"
        );

        super::clear_dev_overlay_for_test();
        super::set_dev_overlay_active_for_test(None);
    }

    #[test]
    fn overlay_active_patches_matching_defaults_signature_only() {
        let _g = overlay_test_guard();
        super::set_dev_overlay_active_for_test(Some(true));
        super::clear_dev_overlay_for_test();

        // A patch registered for one view's defaults signature overlays that
        // view's table on the next from_defaults …
        super::register_dev_patch(&["12px".to_string()], vec![(0, "16px".to_string())]);
        let patched = LiteralTable::from_defaults(&["12px"]);
        assert_eq!(
            patched.get(0),
            "16px",
            "active overlay patches the matching view"
        );

        // … and leaves a DIFFERENT view (different defaults) untouched.
        let other = LiteralTable::from_defaults(&["red"]);
        assert_eq!(
            other.get(0),
            "red",
            "a non-matching signature is never patched"
        );

        super::clear_dev_overlay_for_test();
        super::set_dev_overlay_active_for_test(None);
    }

    #[test]
    fn overlay_out_of_range_patch_index_is_ignored() {
        let _g = overlay_test_guard();
        super::set_dev_overlay_active_for_test(Some(true));
        super::clear_dev_overlay_for_test();

        super::register_dev_patch(&["a".to_string()], vec![(9, "z".to_string())]);
        let t = LiteralTable::from_defaults(&["a"]);
        assert_eq!(
            t.get(0),
            "a",
            "an out-of-range patch index is ignored, render total"
        );

        super::clear_dev_overlay_for_test();
        super::set_dev_overlay_active_for_test(None);
    }

    // Load-bearing dev == prod conformance at the mechanism level: a view whose
    // appearance literals (style value, attribute string, static text) are read
    // from a baked-default `LiteralTable` renders byte-identically to the same
    // view with those literals written directly. This is the property the whole
    // appearance-hot-swap transform rests on — reading `get(idx)` on the baked
    // defaults is indistinguishable from the direct literal, so prod (which only
    // ever holds the defaults) renders exactly what a direct emit would.
    //
    // Uses the `html` render core, which only compiles under `web-core`; the
    // table itself is pure and also compiles under a `control-wire`-only tui
    // dev-loop build, where this render-conformance check does not apply.
    #[cfg(feature = "web-core")]
    #[test]
    fn baked_default_table_renders_identically_to_direct_literals() {
        // Serialise against the overlay tests so their process-global override
        // can never make from_defaults patch mid-assertion.
        let _g = overlay_test_guard();
        super::set_dev_overlay_active_for_test(Some(false));
        use crate::html::{Attribute, Html, render_html};

        // A representative view: an element carrying a style attribute value and
        // a plain attribute string, wrapping a static text node — the three
        // appearance-literal kinds in Step 2's scope.
        fn view_direct() -> Html<()> {
            Html::HElement(
                "div".to_string(),
                vec![
                    Attribute::Attr("style".to_string(), "padding: 12px".to_string()),
                    Attribute::Attr("class".to_string(), "card".to_string()),
                ],
                vec![Html::HText("Hello".to_string())],
            )
        }

        fn view_tabled(t: &LiteralTable) -> Html<()> {
            Html::HElement(
                "div".to_string(),
                vec![
                    Attribute::Attr("style".to_string(), t.get(0).to_string()),
                    Attribute::Attr("class".to_string(), t.get(1).to_string()),
                ],
                vec![Html::HText(t.get(2).to_string())],
            )
        }

        let table = LiteralTable::from_defaults(&["padding: 12px", "card", "Hello"]);

        let direct = render_html(&view_direct());
        let tabled = render_html(&view_tabled(&table));
        assert_eq!(
            direct, tabled,
            "baked-default table must render byte-identically to direct literals (dev == prod)"
        );

        // And an appearance edit — a patch swapping the style value — changes
        // only that literal in the render, with no recompile and no other drift.
        let mut patched = table;
        patched.apply_patch(&[(0, "padding: 16px".to_string())]);
        let patched_render = render_html(&view_tabled(&patched));
        assert!(patched_render.contains("padding: 16px"));
        assert!(patched_render.contains("Hello"));
        assert!(patched_render.contains(r#"class="card""#));

        super::set_dev_overlay_active_for_test(None);
    }
}
