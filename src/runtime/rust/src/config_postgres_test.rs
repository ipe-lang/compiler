// Behavioral regression tests for the Postgres `db_format_sql` placeholder
// rewriter.
//
// The rewriter lives in `config_postgres.rs`, which is NOT part of this crate's
// module tree in a normal build — it is `include_str!`'d verbatim by the
// emitter (`ipe_backend_rust::project`) and only ever compiled inside an
// *emitted* postgres project. `cargo nextest -p ipe-runtime-rust` therefore
// never exercises the real rewriter (the in-crate `config.rs` `db_format_sql`
// is the sqlite identity fn).
//
// This module re-includes the same source file under `#[path]`, but only under
// `cfg(all(test, feature = "db"))`, so the exact bytes that get emitted are the
// bytes under test — a future edit to the quote-aware scan cannot silently
// desync placeholder numbering without a test here failing. Nothing here is
// ever emitted: the emitter reads `config_postgres.rs` alone.

// The re-included file carries the full production surface (`DbPool`,
// `ipe_db_url`, `db_last_insert_id`, …); only `db_format_sql` and its scan
// helpers are exercised, so the rest reads as dead code in this test-only view.
#[allow(dead_code)]
#[path = "config_postgres.rs"]
mod pg;

#[cfg(test)]
mod tests {
    use super::pg::db_format_sql;

    // Convenience: rewrite and return the placeholder-numbered string.
    fn fmt(s: &str) -> String {
        db_format_sql(s.to_string())
    }

    #[test]
    fn plain_placeholders_number_sequentially() {
        assert_eq!(
            fmt("SELECT * FROM t WHERE a = ? AND b = ? AND c = ?"),
            "SELECT * FROM t WHERE a = $1 AND b = $2 AND c = $3"
        );
    }

    #[test]
    fn adjacent_placeholders_number_sequentially() {
        assert_eq!(fmt("??"), "$1$2");
        assert_eq!(fmt("(?,?,?)"), "($1,$2,$3)");
    }

    #[test]
    fn question_in_single_quoted_literal_is_not_renumbered() {
        // The `?` inside 'why?' is data, not a placeholder; the trailing `?`
        // is $1.
        assert_eq!(
            fmt("SELECT * FROM t WHERE note = 'why?' AND id = ?"),
            "SELECT * FROM t WHERE note = 'why?' AND id = $1"
        );
    }

    #[test]
    fn question_in_double_quoted_identifier_is_not_renumbered() {
        assert_eq!(
            fmt(r#"SELECT "col?" FROM t WHERE id = ?"#),
            r#"SELECT "col?" FROM t WHERE id = $1"#
        );
    }

    #[test]
    fn doubled_single_quote_is_an_escaped_quote_not_a_terminator() {
        // '' is an embedded quote: the literal spans the whole `'a''?''b'`, so
        // its inner `?` stays literal and the real placeholder is $1.
        assert_eq!(fmt("SELECT 'a''?''b' , ?"), "SELECT 'a''?''b' , $1");
    }

    #[test]
    fn doubled_double_quote_is_an_escaped_quote_not_a_terminator() {
        assert_eq!(fmt(r#"SELECT "a""?""b" , ?"#), r#"SELECT "a""?""b" , $1"#);
    }

    #[test]
    fn empty_dollar_quote_tag_spans_its_body() {
        // `$$…$$` (empty tag): the `?` inside is literal, the outer `?` is $1.
        assert_eq!(fmt("SELECT $$why?$$ , ?"), "SELECT $$why?$$ , $1");
    }

    #[test]
    fn named_dollar_quote_tag_spans_its_body() {
        assert_eq!(
            fmt("SELECT $tag$why?$tag$ , ?"),
            "SELECT $tag$why?$tag$ , $1"
        );
    }

    #[test]
    fn dollar_quote_with_digit_in_tag_after_first_char() {
        // A tag char may be a digit after the first position (`t1`).
        assert_eq!(fmt("SELECT $t1$why?$t1$ , ?"), "SELECT $t1$why?$t1$ , $1");
    }

    #[test]
    fn dollar_quote_inner_prefix_tag_does_not_close_early() {
        // The closer must be the FULL `$ab$`; an inner `$a$` that is a prefix of
        // the tag must NOT terminate the span. The `?` between them is literal.
        assert_eq!(fmt("SELECT $ab$x$a$?$ab$ , ?"), "SELECT $ab$x$a$?$ab$ , $1");
    }

    #[test]
    fn bare_dollar_not_opening_a_tag_is_copied_and_following_question_numbers() {
        // `$ ` is not a dollar-quote opener (space is not a tag char and there
        // is no closing `$`), so it is copied verbatim and the `?` after is $1.
        assert_eq!(fmt("cost $ ?"), "cost $ $1");
        // A lone trailing `$` likewise: not an opener.
        assert_eq!(fmt("a$ ?"), "a$ $1");
    }

    #[test]
    fn unterminated_dollar_quote_copies_remainder_verbatim() {
        // No matching `$tag$` closer: the remainder (including its `?`) is
        // copied as-is; no placeholder is emitted for the swallowed `?`.
        assert_eq!(fmt("SELECT $tag$why? and ?"), "SELECT $tag$why? and ?");
    }

    #[test]
    fn line_comment_to_end_of_line_is_skipped() {
        // A `?` after `--` on the same line is literal; the `?` on the next
        // line is $1.
        assert_eq!(
            fmt("SELECT 1 -- why? note\n WHERE id = ?"),
            "SELECT 1 -- why? note\n WHERE id = $1"
        );
    }

    #[test]
    fn line_comment_running_to_end_of_input_is_skipped() {
        // `--` with no trailing newline consumes to EOF; the inner `?` stays
        // literal and no placeholder is emitted.
        assert_eq!(fmt("SELECT 1 -- trailing ?"), "SELECT 1 -- trailing ?");
    }

    #[test]
    fn block_comment_is_skipped() {
        assert_eq!(
            fmt("SELECT 1 /* why? */ WHERE id = ?"),
            "SELECT 1 /* why? */ WHERE id = $1"
        );
    }

    #[test]
    fn nested_block_comment_is_skipped_to_the_outer_close() {
        // Postgres nests block comments: the span must close only at the outer
        // `*/`, so the `?` between the inner and outer closers is still literal.
        assert_eq!(
            fmt("SELECT 1 /* a /* ? */ ? */ WHERE id = ?"),
            "SELECT 1 /* a /* ? */ ? */ WHERE id = $1"
        );
    }

    #[test]
    fn unterminated_block_comment_consumes_the_remainder() {
        // No closing `*/`: the rest is a comment, its `?` stays literal.
        assert_eq!(fmt("SELECT 1 /* why? and ?"), "SELECT 1 /* why? and ?");
    }

    #[test]
    fn cross_span_numbering_from_the_issue() {
        // The canonical mixed-span example: placeholders in ordinary text are
        // $1..$6 in order; every `?` inside a literal / dollar-quote / line
        // comment / block comment is copied verbatim and does NOT advance the
        // counter.
        let input = "? '?' ? $$?$$ ? -- ?\n ? /* ? */ ?";
        assert_eq!(fmt(input), "$1 '?' $2 $$?$$ $3 -- ?\n $4 /* ? */ $5");
    }

    #[test]
    fn multibyte_utf8_text_is_preserved_and_placeholders_still_number() {
        // A non-ASCII codepoint inside a literal must be copied opaquely and
        // must not desync the following placeholder.
        assert_eq!(
            fmt("SELECT 'café?' , ? , 'naïve' , ?"),
            "SELECT 'café?' , $1 , 'naïve' , $2"
        );
    }

    #[test]
    fn like_escape_clause_survives_the_placeholder_rewrite() {
        assert_eq!(
            fmt("SELECT * FROM t WHERE (n LIKE ? ESCAPE '\\')"),
            "SELECT * FROM t WHERE (n LIKE $1 ESCAPE '\\')"
        );
        assert_eq!(
            fmt("SELECT * FROM t WHERE ((n LIKE ? ESCAPE '\\') AND (substr(n, 1, length(?)) = ?))"),
            "SELECT * FROM t WHERE ((n LIKE $1 ESCAPE '\\') AND (substr(n, 1, length($2)) = $3))"
        );
    }

    #[test]
    fn no_placeholders_is_identity() {
        assert_eq!(fmt("SELECT 1"), "SELECT 1");
        assert_eq!(fmt(""), "");
    }
}
