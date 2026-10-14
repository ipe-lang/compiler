// Behavioral regression tests for the Postgres `db_format_sql` placeholder
// rewriter (issue #2061).
//
// The rewriter lives in `config_postgres.rs`, the Postgres driver aliases the
// crate root compiles as `config` only under `db-postgres`. The runtime's own
// test builds select the *sqlite* `config.rs`, whose `db_format_sql` is the
// identity, so this module drives the quote-aware `?`→`$N` rewrite directly.
//
// To lock the placeholder-numbering invariant without duplicating the rewriter,
// this module `include!`s the exact template into a private inner module and
// drives its `db_format_sql`. `include!` (not a copy) means the tests fail if
// the template's behavior ever changes, so a future edit cannot silently desync
// the emitted binds. `crate::system` / `crate::app_config` referenced by the
// template's `ipe_db_url` resolve here because the include lands inside this
// crate.

#[cfg(all(test, feature = "db"))]
mod postgres_template {
    // The template exposes the full emitter-facing config surface
    // (`DbPool`/`ipe_db_url`/`db_last_insert_id`/…); these tests drive only
    // `db_format_sql`, so the rest is legitimately unused here.
    #![allow(dead_code)]
    include!("config_postgres.rs");
}

#[cfg(all(test, feature = "db"))]
mod tests {
    use super::postgres_template::db_format_sql;

    fn rewrite(sql: &str) -> String {
        db_format_sql(sql.to_string())
    }

    #[test]
    fn sequential_placeholders_number_in_order() {
        assert_eq!(
            rewrite("SELECT * FROM t WHERE a = ? AND b = ? AND c = ?"),
            "SELECT * FROM t WHERE a = $1 AND b = $2 AND c = $3"
        );
    }

    #[test]
    fn adjacent_placeholders_number_consecutively() {
        assert_eq!(rewrite("??"), "$1$2");
    }

    #[test]
    fn question_mark_inside_single_quoted_literal_is_not_renumbered() {
        assert_eq!(
            rewrite("SELECT * FROM t WHERE note = 'why?' AND id = ?"),
            "SELECT * FROM t WHERE note = 'why?' AND id = $1"
        );
    }

    #[test]
    fn question_mark_inside_double_quoted_identifier_is_not_renumbered() {
        assert_eq!(
            rewrite(r#"SELECT "col?" FROM t WHERE id = ?"#),
            r#"SELECT "col?" FROM t WHERE id = $1"#
        );
    }

    #[test]
    fn doubled_single_quote_escape_keeps_span_open() {
        // `''` is an embedded quote, not a terminator: the `?` after it is still
        // inside the literal and must not be renumbered.
        assert_eq!(rewrite("SELECT 'a''b?' , ?"), "SELECT 'a''b?' , $1");
    }

    #[test]
    fn doubled_double_quote_escape_keeps_span_open() {
        assert_eq!(rewrite(r#"SELECT "a""b?" , ?"#), r#"SELECT "a""b?" , $1"#);
    }

    #[test]
    fn empty_dollar_quote_hides_inner_question_mark() {
        assert_eq!(rewrite("SELECT $$a?b$$ , ?"), "SELECT $$a?b$$ , $1");
    }

    #[test]
    fn named_dollar_quote_hides_inner_question_mark() {
        assert_eq!(
            rewrite("SELECT $tag$a?b$tag$ , ?"),
            "SELECT $tag$a?b$tag$ , $1"
        );
    }

    #[test]
    fn dollar_tag_with_inner_prefix_needs_full_tag_to_close() {
        // A `$ta$` inside a `$tag$…$tag$` body is NOT the closer; only the full
        // `$tag$` ends the span, so the `?` before the real close stays hidden.
        assert_eq!(
            rewrite("SELECT $tag$x $ta$ y?$tag$ , ?"),
            "SELECT $tag$x $ta$ y?$tag$ , $1"
        );
    }

    #[test]
    fn dollar_tag_cannot_start_with_a_digit() {
        // `$1$` is not a valid dollar-quote opening tag (a tag may not start
        // with a digit), so the text is ordinary and the later `?` renumbers.
        assert_eq!(rewrite("SELECT $1$ , ?"), "SELECT $1$ , $1");
    }

    #[test]
    fn unterminated_dollar_quote_copies_remainder_verbatim() {
        // No matching `$tag$` closer: the remainder is copied as-is (sqlx
        // surfaces the malformed SQL), so the trailing `?` is not renumbered.
        assert_eq!(rewrite("SELECT $tag$a?b , ?"), "SELECT $tag$a?b , ?");
    }

    #[test]
    fn line_comment_hides_question_mark_to_eol() {
        assert_eq!(
            rewrite("SELECT 1 -- why?\nWHERE id = ?"),
            "SELECT 1 -- why?\nWHERE id = $1"
        );
    }

    #[test]
    fn line_comment_hides_question_mark_to_eof() {
        assert_eq!(rewrite("SELECT 1 -- trailing ?"), "SELECT 1 -- trailing ?");
    }

    #[test]
    fn block_comment_hides_question_mark() {
        assert_eq!(rewrite("SELECT /* q? */ ?"), "SELECT /* q? */ $1");
    }

    #[test]
    fn nested_block_comment_hides_question_mark() {
        // Postgres nests block comments: the inner `*/` closes only the inner
        // comment, so the `?` between the two closers is still commented out.
        assert_eq!(
            rewrite("SELECT /* a /* b? */ c? */ ?"),
            "SELECT /* a /* b? */ c? */ $1"
        );
    }

    #[test]
    fn unterminated_block_comment_consumes_remainder() {
        assert_eq!(
            rewrite("SELECT /* never closes ?"),
            "SELECT /* never closes ?"
        );
    }

    #[test]
    fn cross_span_numbering_stays_sequential() {
        // A `?` interleaved with every hidden-span kind must number in pure
        // emission order across the spans: $1..$5.
        assert_eq!(
            rewrite("? '?' ? $$?$$ ? -- ?\n ? /* ? */ ?"),
            "$1 '?' $2 $$?$$ $3 -- ?\n $4 /* ? */ $5"
        );
    }

    #[test]
    fn lone_trailing_delimiters_are_ordinary_text() {
        for sql in ["?$", "?-", "?/", "? $é", "?-é", "?/é"] {
            let expected = sql.replacen('?', "$1", 1);
            assert_eq!(rewrite(sql), expected, "{sql}");
        }
    }

    #[test]
    fn unterminated_quote_consumes_remainder() {
        assert_eq!(rewrite("? 'never closes ?"), "$1 'never closes ?");
        assert_eq!(rewrite("? \"never closes ?"), "$1 \"never closes ?");
        assert_eq!(rewrite("'"), "'");
    }

    #[test]
    fn multibyte_text_between_placeholders_is_preserved() {
        assert_eq!(rewrite("SELECT 'café?' , ?"), "SELECT 'café?' , $1");
    }
}
