//! Live properties: the boolean attributes a patch mirrors onto a DOM property.
//!
//! Once the user or a script sets `checked` or `selected`, the element's
//! property stops following its attribute, so a patch that only rewrote the
//! attribute would leave the page showing a state the program no longer holds.
//! Every patch writer therefore writes the property beside the attribute: a
//! present attribute sets the property, a removed one clears it. Presence is
//! the whole state, as in HTML and as first paint renders it, so a present
//! attribute holding the text `"false"` is on, exactly as the server-rendered
//! page shows it. This table is the one list; `client.js` mirrors it and a test
//! pins the mirror.

/// The attributes, lowercase, whose DOM property a patch writes beside them.
pub const LIVE_PROPS: [&str; 3] = ["checked", "selected", "disabled"];

/// The DOM property a patched attribute `name` drives, ASCII case folded;
/// `None` for an attribute whose property follows it on its own.
#[must_use]
pub fn live_prop(name: &str) -> Option<&'static str> {
    LIVE_PROPS
        .into_iter()
        .find(|prop| prop.eq_ignore_ascii_case(name))
}

/// The property state a patch leaves for a live attribute: on when the patch
/// sets it, whatever its text, off when the patch removes it.
#[must_use]
pub const fn live_prop_state(value: Option<&str>) -> bool {
    value.is_some()
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::{LIVE_PROPS, live_prop, live_prop_state};

    const CLIENT_JS: &str = include_str!("../web/client.js");

    /// The body of `client.js`'s `__IPE_LIVE_PROPS` table, between its braces.
    fn client_table() -> &'static str {
        let start = CLIENT_JS
            .find("var __IPE_LIVE_PROPS = Object.freeze({")
            .map(|at| at + "var __IPE_LIVE_PROPS = Object.freeze({".len());
        let Some(start) = start else {
            return "";
        };
        CLIENT_JS
            .get(start..)
            .and_then(|rest| rest.find("})").and_then(|end| rest.get(..end)))
            .unwrap_or("")
    }

    /// `client.js` mirrors exactly the live properties of [`LIVE_PROPS`].
    ///
    /// Each maps to its own name. Red if either list gains or drops one.
    #[test]
    fn client_js_mirrors_the_live_prop_table() {
        let mut mirrored: Vec<String> = client_table()
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .map(str::to_owned)
            .collect();
        mirrored.sort();
        let mut wanted: Vec<String> = LIVE_PROPS
            .iter()
            .map(|prop| format!("{prop}: \"{prop}\""))
            .collect();
        wanted.sort();
        assert_eq!(mirrored, wanted);
    }

    /// `client.js` sets a live property from the attribute's presence alone.
    ///
    /// Red if the client returns to reading the text `"false"` as off, which
    /// first paint never does.
    #[test]
    fn client_js_sets_a_live_prop_by_presence() {
        assert!(CLIENT_JS.contains("if (prop !== null) el[prop] = true;"));
        assert!(CLIENT_JS.contains("if (prop !== null) el[prop] = false;"));
        assert!(!CLIENT_JS.contains("el[prop] = v !== \"false\""));
    }

    /// The client folds case before it looks a patched name up in the table
    /// and before it mirrors a `value` onto the field.
    ///
    /// Red if either reads the patched name unfolded, so `Checked` drives no
    /// property or `VALUE` no value, where the wasm writer folds both.
    #[test]
    fn client_js_folds_case_before_the_lookup() {
        assert!(CLIENT_JS.contains("var lk = String(k).toLowerCase();"));
        assert!(CLIENT_JS.contains("__IPE_LIVE_PROPS, lk)"));
        assert!(CLIENT_JS.contains("? __IPE_LIVE_PROPS[lk] : null;"));
        assert!(CLIENT_JS.contains("if (lk === \"value\" && (\"value\" in el)) {"));
        assert!(!CLIENT_JS.contains("if (k === \"value\""));
    }

    #[test]
    fn live_prop_names_the_table_case_folded() {
        assert_eq!(live_prop("checked"), Some("checked"));
        assert_eq!(live_prop("SELECTED"), Some("selected"));
        assert_eq!(live_prop("Disabled"), Some("disabled"));
    }

    /// An attribute outside the table drives no property.
    ///
    /// Red if the lookup matches by prefix or admits any name.
    #[test]
    fn live_prop_refuses_other_names() {
        for name in ["value", "check", "checkedx", "hidden", "", "data-checked"] {
            assert_eq!(live_prop(name), None, "{name}");
        }
    }

    /// A set attribute is on whatever its text; only a removal turns it off.
    ///
    /// Red if a value's text, `"false"` or empty, decides the state.
    #[test]
    fn live_prop_state_is_presence() {
        for text in ["", "true", "false", "checked", "0"] {
            assert!(live_prop_state(Some(text)), "{text:?}");
        }
        assert!(!live_prop_state(None));
    }
}
