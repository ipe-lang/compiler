//! The runtime display sanitiser and the compiler's source hazard table name one set.
//!
//! Neither crate can import the other, and this crate already sees both, so the
//! pin lives here: removing an entry from either table turns a test red. The
//! control roles are pinned inside `ipe_diagnostics` by a build-time assert, so
//! this file compares the non-control entries. CI job `test-run`.

use ipe_diagnostics::terminal::SourceHazard;
use ipe_runtime_rust::tui::cell::{BIDI_AND_SEPARATOR_HAZARDS, sanitize_rune};

/// The runtime bidi and separator table holds exactly the non-control source hazards.
#[test]
fn runtime_bidi_table_is_the_source_non_control_hazard_set() -> Result<(), String> {
    for c in char::MIN..=char::MAX {
        let source = SourceHazard::of(c).is_some() && !c.is_control();
        let runtime = BIDI_AND_SEPARATOR_HAZARDS
            .iter()
            .any(|range| range.contains(&c));
        if source != runtime {
            return Err(format!(
                "U+{:04X}: source table {source}, runtime table {runtime}",
                u32::from(c)
            ));
        }
    }
    Ok(())
}

/// Every character the lexer refuses as a display hazard the runtime draws as a space.
#[test]
fn every_source_hazard_is_blanked_by_the_runtime_sanitiser() -> Result<(), String> {
    for c in char::MIN..=char::MAX {
        if SourceHazard::of(c).is_some() && sanitize_rune(c) != ' ' {
            return Err(format!("U+{:04X} reaches a runtime display", u32::from(c)));
        }
    }
    Ok(())
}
