//! Folding ranges: the import block plus every multi-line top-level
//! declaration. Pure over `parse` — an unparseable buffer folds nothing.

use ipe_db::{IpeDatabase, SourceFile};
use lsp_types::{FoldingRange, FoldingRangeKind};

use crate::offset::{PositionEncoding, first_line, offset_to_position};

/// The foldable regions of one module, in source order.
#[must_use]
pub fn folding_ranges(
    db: &IpeDatabase,
    file: SourceFile,
    encoding: PositionEncoding,
) -> Vec<FoldingRange> {
    let Ok(module) = ipe_db::parse(db, file) else {
        return Vec::new();
    };
    let text = file.text(db);
    let mut out: Vec<FoldingRange> = Vec::new();

    // The import block folds as one region: from the first import's module
    // name through the last import's final token.
    if let (Some(first), Some(last)) = (module.imports.first(), module.imports.last()) {
        let lo = first.name.span.lo;
        let hi = last.span.hi;
        push_range(
            &mut out,
            text,
            lo,
            hi,
            Some(FoldingRangeKind::Imports),
            encoding,
        );
    }

    for value in &module.values {
        // A value's `Located` span is its NAME; the decl runs to the body's
        // end.
        let lo = value.value.name.span.lo;
        let hi = value.value.body.span.hi.max(value.span.hi);
        push_range(&mut out, text, lo, hi, None, encoding);
    }
    for union in &module.unions {
        push_range(&mut out, text, union.span.lo, union.span.hi, None, encoding);
    }
    for alias in &module.aliases {
        push_range(&mut out, text, alias.span.lo, alias.span.hi, None, encoding);
    }
    out.sort_by_key(|range| (range.start_line, range.end_line));
    out
}

/// Append a fold for `[lo, hi)` when it spans more than one line.
fn push_range(
    out: &mut Vec<FoldingRange>,
    text: &str,
    lo: u32,
    hi: u32,
    kind: Option<FoldingRangeKind>,
    encoding: PositionEncoding,
) {
    let start = offset_to_position(text, lo as usize, encoding);
    let end = offset_to_position(text, hi as usize, encoding);
    if end.line > start.line {
        out.push(FoldingRange {
            start_line: start.line,
            start_character: None,
            end_line: end.line,
            end_character: None,
            kind,
            collapsed_text: Some(first_line_preview(text, lo as usize)),
        });
    }
}

/// A short preview string for the folded region — the line starting at
/// `offset`, cut to its longest whole-character prefix of at most 40 bytes.
/// Editors display this inline when the region is collapsed so the user can
/// see what is hidden.
fn first_line_preview(text: &str, offset: usize) -> String {
    const PREVIEW_BYTES: usize = 40;
    let slice = text.get(offset..).unwrap_or("");
    let first_line = first_line(slice).trim_end();
    if first_line.len() <= PREVIEW_BYTES {
        first_line.to_owned()
    } else {
        let end = first_line
            .char_indices()
            .map(|(at, ch)| at + ch.len_utf8())
            .take_while(|&end| end <= PREVIEW_BYTES)
            .last()
            .unwrap_or(0);
        format!("{}…", first_line.get(..end).unwrap_or(""))
    }
}

#[cfg(test)]
mod tests {
    use ipe_db::{IpeDatabase, ModuleOrigin, SourceFile, SourceRoot};

    use super::folding_ranges;
    use crate::offset::PositionEncoding;

    fn file(db: &IpeDatabase, path: &[&str], text: &str) -> SourceFile {
        SourceFile::new(
            db,
            path.iter().map(|s| (*s).to_owned()).collect(),
            text.to_owned(),
            ModuleOrigin::User,
        )
    }

    fn root_of(db: &IpeDatabase, files: &[(&[&str], SourceFile)]) -> SourceRoot {
        SourceRoot::new(
            db,
            files
                .iter()
                .map(|(path, f)| (path.iter().map(|s| (*s).to_owned()).collect(), *f))
                .collect(),
        )
    }

    /// Every folding range for a multi-line declaration must carry a non-empty
    /// `collapsed_text` preview.
    #[test]
    fn collapsed_text_is_set_on_multi_line_decl() {
        const SRC: &str = "module Main exposing (main)\n\nmain : Int\nmain =\n    42\n";
        let db = IpeDatabase::new();
        let f = file(&db, &["Main"], SRC);
        let _root = root_of(&db, &[(&["Main"], f)]);
        let ranges = folding_ranges(&db, f, PositionEncoding::Utf16);
        assert!(
            !ranges.is_empty(),
            "a multi-line binding must produce at least one folding range"
        );
        for r in &ranges {
            let text = r
                .collapsed_text
                .as_deref()
                .expect("collapsed_text must be Some on every folding range");
            assert!(
                !text.is_empty(),
                "collapsed_text must be non-empty; got empty string for range {r:?}"
            );
        }
        // The preview for `main` starts with `main`.
        let main_preview = ranges.iter().find(|r| {
            r.collapsed_text
                .as_deref()
                .is_some_and(|t| t.starts_with("main"))
        });
        assert!(
            main_preview.is_some(),
            "collapsed_text for `main` binding must start with \"main\"; ranges: {ranges:?}"
        );
    }

    /// Long first lines are truncated and end with `…`.
    #[test]
    fn collapsed_text_truncates_long_lines() {
        use super::first_line_preview;
        let long = "a".repeat(50);
        let preview = first_line_preview(&long, 0);
        assert!(
            preview.ends_with('…'),
            "preview of a 50-char line must end with …: {preview:?}"
        );
        // The prefix before `…` is at most 40 bytes.
        let without_ellipsis: &str = preview.trim_end_matches('…');
        assert!(
            without_ellipsis.len() <= 40,
            "truncated prefix must be ≤ 40 bytes: {}",
            without_ellipsis.len()
        );
    }

    /// A character straddling the 40-byte cut is left out whole, never split.
    #[test]
    fn collapsed_text_cuts_before_a_straddling_character() {
        use super::first_line_preview;
        let line = format!("{}😀{}", "a".repeat(38), "b".repeat(10));
        assert_eq!(first_line_preview(&line, 0), format!("{}…", "a".repeat(38)));
        let wide = "😀".repeat(12);
        assert_eq!(
            first_line_preview(&wide, 0),
            format!("{}…", "😀".repeat(10))
        );
    }

    /// The preview stops at the first line break a client counts, a lone `\r` included.
    #[test]
    fn collapsed_text_stops_at_every_line_break() {
        use super::first_line_preview;
        for text in ["main =\n    1", "main =\r\n    1", "main =\r    1"] {
            assert_eq!(first_line_preview(text, 0), "main =", "{text:?}");
        }
    }
}
