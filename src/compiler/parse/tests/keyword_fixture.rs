//! The Ipê keyword fixture code-review's highlighter is pinned against must
//! be exactly the lexer's `KEYWORDS`, one word per line, in declaration
//! order — so a reserved word added to the language reaches the reviewer's
//! highlighting, or this test goes red.

const KEYWORD_FIXTURE: &str = include_str!("../../../../tools/ipe-index/tests/keywords_ipe.json");

#[test]
fn keyword_fixture_is_the_lexer_table() {
    let body = ipe_parse::KEYWORDS
        .iter()
        .map(|w| format!("  \"{w}\""))
        .collect::<Vec<_>>()
        .join(",\n");
    assert_eq!(
        KEYWORD_FIXTURE,
        format!("[\n{body}\n]\n"),
        "tools/ipe-index/tests/keywords_ipe.json drifted from `ipe_parse::KEYWORDS`"
    );
}
