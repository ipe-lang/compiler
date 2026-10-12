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

/// The opening of the client script tag the boot block immediately precedes.
const CLIENT_TAG_OPEN: &str = "<script src=\"";

/// The path segment of the client script's `src`.
const CLIENT_PATH: &str = "/_ipe/client.";

/// The page's boot data block, parsed as JSON.
///
/// The block is the one the client binds: its element immediately precedes the
/// client's own `<script src="…/_ipe/client.…">` tag. A block-shaped element
/// anywhere else in the page (app markup earlier in the body) is never read.
///
/// `None` when the page carries no such block, carries more than one, the
/// block is unclosed, or its body is not JSON.
#[must_use]
pub fn boot_data(html: &str) -> Option<serde_json::Value> {
    let mut bound = html.match_indices(BOOT_BLOCK_OPEN).filter_map(|(at, _)| {
        let rest = html.get(at + BOOT_BLOCK_OPEN.len()..)?;
        let end = rest.find("</script>")?;
        let after = rest
            .get(end + "</script>".len()..)?
            .strip_prefix(CLIENT_TAG_OPEN)?;
        let src = after.get(..after.find('"')?)?;
        if src.contains(CLIENT_PATH) {
            rest.get(..end)
        } else {
            None
        }
    });
    let body = bound.next()?;
    if bound.next().is_some() {
        return None;
    }
    serde_json::from_str(body).ok()
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

    const CLIENT: &str = "<script src=\"/app/_ipe/client.0123456789abcdef.js\"></script>";

    fn page(block_body: &str) -> String {
        format!(
            "<body><div id=\"ipe-root\"></div></body>{BOOT_BLOCK_OPEN}{block_body}</script>{CLIENT}"
        )
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
        let unbound = format!("<body>{BOOT_BLOCK_OPEN}{{\"epoch\":\"e\"}}</script></body>");
        assert_eq!(boot_string(&unbound, "epoch"), None);
        let other_script = format!(
            "{BOOT_BLOCK_OPEN}{{\"epoch\":\"e\"}}</script><script src=\"/app.js\"></script>"
        );
        assert_eq!(boot_string(&other_script, "epoch"), None);
    }

    #[test]
    fn reads_the_block_before_the_client_tag_never_an_earlier_decoy() {
        let decoy = format!("<body>{BOOT_BLOCK_OPEN}{{\"epoch\":\"decoy\"}}</script>");
        let html = page(r#"{"epoch":"real"}"#).replace("<body>", &decoy);
        assert_eq!(boot_string(&html, "epoch").as_deref(), Some("real"));
    }

    #[test]
    fn refuses_two_blocks_bound_to_a_client_tag() {
        let first = format!("<body>{BOOT_BLOCK_OPEN}{{\"epoch\":\"a\"}}</script>{CLIENT}");
        let html = page(r#"{"epoch":"b"}"#).replace("<body>", &first);
        assert_eq!(boot_string(&html, "epoch"), None);
    }
}
