//! Reading a served `Ipe.Web` live page the way its client reads it.
//!
//! A live page hands its client the per-session values (`sid`, `epoch`,
//! `base`, `csrf`) and the client config in one inert JSON block,
//! `<script type="application/json" id="ipe-boot">`. A test that drives the
//! page's wire protocol reads those values from the block, never from text the
//! page happens to contain.

/// The opening tag of a live page's boot data block.
///
/// The runtime's `boot_block` writes this tag; every live e2e test that reads a
/// page through this module goes red if the two drift.
pub const BOOT_BLOCK_OPEN: &str = "<script type=\"application/json\" id=\"ipe-boot\">";

/// The page's boot data block, parsed as JSON.
///
/// `None` when the page carries no block, the block is unclosed, or its body is
/// not JSON.
#[must_use]
pub fn boot_data(html: &str) -> Option<serde_json::Value> {
    let rest = html.get(html.find(BOOT_BLOCK_OPEN)? + BOOT_BLOCK_OPEN.len()..)?;
    serde_json::from_str(rest.get(..rest.find("</script>")?)?).ok()
}

/// The string field `key` at the top level of the page's boot data block.
///
/// `None` when [`boot_data`] is `None`, the field is absent, or it is not a
/// string.
#[must_use]
pub fn boot_string(html: &str, key: &str) -> Option<String> {
    boot_data(html)?.get(key)?.as_str().map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::{BOOT_BLOCK_OPEN, boot_string};

    fn page(block_body: &str) -> String {
        format!("<body><div id=\"ipe-root\"></div>{BOOT_BLOCK_OPEN}{block_body}</script></body>")
    }

    #[test]
    fn reads_an_escaped_field() {
        let html = page(r#"{"epoch":"a\u003c/script\u003e.1","sid":"s"}"#);
        assert_eq!(boot_string(&html, "epoch").as_deref(), Some("a</script>.1"));
        assert_eq!(boot_string(&html, "sid").as_deref(), Some("s"));
    }

    #[test]
    fn refuses_a_page_without_a_readable_block() {
        assert_eq!(boot_string("<body></body>", "epoch"), None);
        assert_eq!(boot_string(&page("not json"), "epoch"), None);
        assert_eq!(boot_string(&page(r#"{"epoch":7}"#), "epoch"), None);
        assert_eq!(boot_string(&page(r#"{"sid":"s"}"#), "epoch"), None);
        let unclosed = format!("{BOOT_BLOCK_OPEN}{{\"epoch\":\"e\"}}");
        assert_eq!(boot_string(&unclosed, "epoch"), None);
        let old_global = "<script>window.__IPE_EPOCH=\"e\";</script>";
        assert_eq!(boot_string(old_global, "epoch"), None);
    }
}
