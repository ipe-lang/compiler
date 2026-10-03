//! Ipe.Email — provider-abstract email send (Resend / SendGrid / SES / SMTP).
//!
//! Mirror of ``. The Ipê records
//! (`EmailMessage` / `Attachment` / `SesConfig` / `SmtpConfig`) and the
//! `EmailProvider` ADT map to the runtime types below via the
//! runtimeOpaqueTypes registry — so the generated `StdEmail*` are `pub use`
//! aliases, Ipê field access + record literals resolve onto these pub fields,
//! and `Resend "key"` / `Ses cfg` construct the enum variants directly.
//!
//! Field names match the Ipê aliases verbatim (camelCase `textBody` /
//! `htmlBody` / `replyTo` / `mimeType` — hence the non_snake_case allow).
//!
//! Providers: Resend + SendGrid + SES (v2, SigV4) over HTTPS.
//! SMTP goes through the `lettre` transport (opportunistic/required STARTTLS or
//! implicit TLS on 465), completing the provider surface.
//!
//! `IPE_EMAIL_DRY_RUN=1` short-circuits every provider and returns a synthetic
//! id — used by tests so they don't depend on third-party services.
//! `IPE_EMAIL_ENDPOINT_<PROVIDER>` overrides per-provider URLs for fixtures.

use super::*;
use crate::secret::Secret;
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

/// `Ipe.Email.EmailAddress` — an opaque, parse-validated email address.
///
/// The ONLY constructor is [`email_address_parse`] which returns `None` for
/// any string that fails the structural check: `user@domain.tld`, no name
/// component, no embedded spaces. A bare `String` can NEVER silently coerce to
/// this type —
/// passing `"not-an-email"` where an `EmailAddress` is expected is a Ipê
/// type error, not a silent send failure.
///
/// `Clone + PartialEq`: addresses are compared (e.g. in reply-to matching).
/// `Debug`: the address is NOT a secret — it is transmitted in email headers.
#[derive(Clone, PartialEq, Debug)]
pub struct EmailAddress(String);

impl std::fmt::Display for EmailAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl crate::stringify::IpeStringify for EmailAddress {
    fn ipe_show(&self) -> String {
        self.0.clone()
    }
}

/// `EmailAddress.parse : String -> Maybe EmailAddress` — the single parse
/// boundary. Returns `None` when the string is not a structurally valid
/// bare address (`user@domain.tld`). Mirrors `String.isEmail`'s rules.
#[must_use]
pub fn email_address_parse(s: String) -> crate::core::IpeMaybe<EmailAddress> {
    if email_address_is_valid(&s) {
        crate::core::IpeMaybe::Just(EmailAddress(s))
    } else {
        crate::core::IpeMaybe::Nothing
    }
}

/// `EmailAddress.toString : EmailAddress -> String` — recover the address string.
#[must_use]
pub fn email_address_to_string(addr: EmailAddress) -> String {
    addr.0
}

impl EmailAddress {
    /// Borrow the validated address string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume into the owned address string.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

/// Structural validation matching `String.isEmail` /  `net/mail.ParseAddress`
/// posture: bare `user@domain.tld`, no name component, no embedded spaces.
fn email_address_is_valid(s: &str) -> bool {
    crate::string::string_is_email(s.to_owned())
}

/// Ipê.Email.EmailMessage — field names/types match the Ipê record alias.
///
/// Address fields (`from`, `to`, `cc`, `bcc`, `replyTo`) carry validated
/// `EmailAddress` values: construction via `parseAddress` is the ONLY path,
/// so an invalid address is a Ipê compile-time type error. Subject, body, and
/// MIME fields remain `String`. Attachment bodies are `Vec<u8>` (Bytes).
#[allow(non_snake_case)]
#[derive(Clone, Debug)]
pub struct EmailMessage {
    pub from: EmailAddress,
    pub to: Vec<EmailAddress>,
    pub cc: Vec<EmailAddress>,
    pub bcc: Vec<EmailAddress>,
    pub subject: String,
    pub textBody: String,
    pub htmlBody: String,
    pub attachments: Vec<EmailAttachment>,
    pub replyTo: EmailAddress,
}

/// Ipê.Email.Attachment — `content` carries the attachment body as raw bytes.
///
/// The Ipê `Attachment.content` field is typed `Bytes` (`Vec<u8>` on Rust),
/// matching the runtime field directly — no `.as_bytes()` / `.into_bytes()`
/// shim is needed at the provider boundary.
#[allow(non_snake_case)]
#[derive(Clone, Debug)]
pub struct EmailAttachment {
    pub filename: String,
    pub mimeType: String,
    /// Attachment body as raw bytes. Pass `File.readFileBytes` output
    /// (a `Bytes` = `Vec<u8>`) or `Bytes.fromString` for text content.
    pub content: Vec<u8>,
}

/// Ipê.Email.SesConfig.
///
/// `secret` is the SES secret access key — a sealed [`Secret`], revealed only
/// inside [`send_ses`] at the SigV4 signing step. `key` (the access-key id)
/// identifies the IAM principal and travels in the request's credential scope,
/// so it is not itself a secret.
#[derive(Clone, Debug)]
pub struct SesConfig {
    pub region: String,
    pub key: String,
    pub secret: Secret,
}

/// Ipê.Email.SmtpConfig.
///
/// `pass` is the SMTP password — a sealed [`Secret`], revealed only inside
/// [`send_smtp`] when building the transport credentials (over a required-TLS
/// channel when a user is configured).
#[derive(Clone, Debug)]
pub struct SmtpConfig {
    pub host: String,
    pub port: i64,
    pub user: String,
    pub pass: Secret,
}

/// Ipê.Email.EmailProvider — the ADT; variant names match the Ipê ctors.
///
/// The Resend / SendGrid API keys are sealed [`Secret`]s; the SES / SMTP
/// credentials are sealed inside their config records. A provider is `Debug`-
/// safe by construction: every credential it carries redacts under `Debug`
/// (see [`Secret`]), so logging a whole `EmailProvider` never leaks a plaintext.
#[derive(Clone, Debug)]
pub enum EmailProvider {
    Resend(Secret),
    Ses(SesConfig),
    SendGrid(Secret),
    Smtp(SmtpConfig),
}

fn email_gen_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    hex::encode(nanos.to_le_bytes())
}

fn email_endpoint(provider: &str, def: &str) -> String {
    let env = format!("IPE_EMAIL_ENDPOINT_{}", provider.to_uppercase());
    crate::system::read_env_var(&env).unwrap_or_else(|_| def.to_string())
}

/// Email.send : EmailProvider -> EmailMessage -> Task Error String
pub fn email_send<E: From<String> + Send + 'static>(
    provider: EmailProvider,
    msg: EmailMessage,
) -> IpeTask<E, String> {
    Box::pin(async move {
        if crate::system::read_env_var("IPE_EMAIL_DRY_RUN").as_deref() == Ok("1") {
            return IpeResult::Ok(format!("dry-run-{}", email_gen_id()));
        }
        // `msg.from` is an `EmailAddress` — structurally valid by construction;
        // no empty-string guard needed here.
        if msg.to.is_empty() {
            return IpeResult::Err(
                "email.send: at least one recipient required"
                    .to_string()
                    .into(),
            );
        }
        // Reveal the sealed key ONLY here, at the send boundary — the plaintext
        // exists only as a local passed straight into the provider call, never
        // logged, stored, or returned. For SES / SMTP the reveal happens deeper
        // still, inside the provider fn at the exact signing / auth step.
        match provider {
            EmailProvider::Resend(key) => {
                send_resend(&crate::secret::secret_reveal(key), &msg).await
            }
            EmailProvider::SendGrid(key) => {
                send_sendgrid(&crate::secret::secret_reveal(key), &msg).await
            }
            EmailProvider::Ses(cfg) => send_ses(&cfg, &msg).await,
            EmailProvider::Smtp(cfg) => send_smtp(&cfg, &msg).await,
        }
    })
}

// ──────────────────── HTTP helper ────────────────────

async fn email_post_json<E: From<String>>(
    url: &str,
    headers: &[(&str, String)],
    payload: Vec<u8>,
) -> Result<serde_json::Value, E> {
    // SSRF guard parity with the Http.* client. The provider endpoint is
    // operator-supplied (IPE_EMAIL_ENDPOINT_<PROVIDER>) and the SES host is
    // region-interpolated, so when IPE_HTTP_DENY_PRIVATE is set this pins DNS to
    // a vetted non-private addr — otherwise a crafted endpoint could exfiltrate
    // the bearer token + payload to a metadata/loopback host. Email POSTs never
    // follow redirects.
    let builder = reqwest::Client::builder().timeout(std::time::Duration::from_secs(30));
    let builder = match crate::http_client::ssrf_apply(
        builder,
        url,
        crate::http_client::RedirectPolicy::NoRedirects,
    )
    .await
    {
        Ok(b) => b,
        Err(refusal) => return Err(format!("http: {refusal}").into()),
    };
    let client = match builder.build() {
        Ok(c) => c,
        Err(e) => return Err(format!("email: client build failed: {}", e).into()),
    };
    let mut rb = client.post(url).body(payload);
    for (k, v) in headers {
        rb = rb.header(*k, v.as_str());
    }
    let resp = match rb.send().await {
        Ok(r) => r,
        Err(e) => return Err(format!("email: request failed: {}", e).into()),
    };
    let status = resp.status().as_u16();
    // Bound the provider response by STREAMING bytes up to a hard cap, never by
    // trusting `Content-Length`: a misbehaving/compromised endpoint can declare a
    // small (or omit the) length and then stream unboundedly, so a length-only
    // precheck is bypassable. Mirror `http_client::read_body_capped`'s incremental
    // cap. Provider id-JSON responses are tiny; 1 MiB is a generous ceiling.
    let body = read_email_body_capped::<E>(resp, EMAIL_RESPONSE_CAP).await?;
    if status >= 400 {
        return Err(format!("email: status {}: {}", status, body).into());
    }
    Ok(serde_json::from_str(&body).unwrap_or(serde_json::Value::Null))
}

/// Hard cap on a provider HTTP response body (1 MiB). Provider id-JSON responses
/// are a few hundred bytes; anything past this is a misbehaving/compromised
/// endpoint and is rejected rather than buffered.
const EMAIL_RESPONSE_CAP: usize = 1024 * 1024;

/// Read a response body into a `String`, bounding the buffered bytes at `cap` by
/// draining the byte stream incrementally. Unlike `Content-Length`, this can't be
/// defeated by a lying/omitted header or a chunked/compressed body — the resident
/// buffer is bounded to `cap` regardless. UTF-8 lossy (provider bodies are JSON).
async fn read_email_body_capped<E: From<String>>(
    resp: reqwest::Response,
    cap: usize,
) -> Result<String, E> {
    use futures_util::StreamExt;
    let mut buf: Vec<u8> = Vec::new();
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let bytes = match chunk {
            Ok(b) => b,
            Err(e) => return Err(format!("email: reading provider response failed: {}", e).into()),
        };
        if buf.len().saturating_add(bytes.len()) > cap {
            return Err(format!("email: provider response too large (> {} bytes)", cap).into());
        }
        buf.extend_from_slice(&bytes);
    }
    #[expect(
        clippy::disallowed_methods,
        reason = "a provider response is display text, not a URL component"
    )]
    let text = String::from_utf8_lossy(&buf).into_owned();
    Ok(text)
}

// ──────────────────── Resend ────────────────────

async fn send_resend<E: From<String>>(api_key: &str, m: &EmailMessage) -> IpeResult<E, String> {
    if api_key.is_empty() {
        return IpeResult::Err("email.send/Resend: empty API key".to_string().into());
    }
    let mut body = serde_json::Map::new();
    body.insert("from".into(), m.from.as_str().to_string().into());
    body.insert("to".into(), to_json_array(&m.to));
    body.insert("subject".into(), m.subject.clone().into());
    if !m.cc.is_empty() {
        body.insert("cc".into(), to_json_array(&m.cc));
    }
    if !m.bcc.is_empty() {
        body.insert("bcc".into(), to_json_array(&m.bcc));
    }
    if !m.textBody.is_empty() {
        body.insert("text".into(), m.textBody.clone().into());
    }
    if !m.htmlBody.is_empty() {
        body.insert("html".into(), m.htmlBody.clone().into());
    }
    body.insert("reply_to".into(), m.replyTo.as_str().to_string().into());
    if !m.attachments.is_empty() {
        let atts: Vec<serde_json::Value> = m
            .attachments
            .iter()
            .map(|a| {
                // Resend expects `content` as a base64 string. Encode the body
                // bytes directly so every byte value round-trips correctly.
                serde_json::json!({
                    "filename": a.filename,
                    // Resend expects `content` as base64. The content field is
                    // already `Vec<u8>` (Bytes) — encode directly, no conversion.
                    "content": B64.encode(&a.content),
                })
            })
            .collect();
        body.insert("attachments".into(), atts.into());
    }
    let payload = serde_json::to_vec(&serde_json::Value::Object(body)).unwrap_or_default();
    let endpoint = email_endpoint("resend", "https://api.resend.com/emails");
    let resp: serde_json::Value = match email_post_json(
        &endpoint,
        &[
            ("Authorization", format!("Bearer {}", api_key)),
            ("Content-Type", "application/json".to_string()),
        ],
        payload,
    )
    .await
    {
        Ok(v) => v,
        Err(e) => return IpeResult::Err(e),
    };
    let id = resp
        .get("id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("resend-{}", email_gen_id()));
    IpeResult::Ok(id)
}

// ──────────────────── SendGrid ────────────────────

async fn send_sendgrid<E: From<String>>(api_key: &str, m: &EmailMessage) -> IpeResult<E, String> {
    if api_key.is_empty() {
        return IpeResult::Err("email.send/SendGrid: empty API key".to_string().into());
    }
    let mut personalisation = serde_json::Map::new();
    personalisation.insert("to".into(), addr_objs(&m.to));
    if !m.cc.is_empty() {
        personalisation.insert("cc".into(), addr_objs(&m.cc));
    }
    if !m.bcc.is_empty() {
        personalisation.insert("bcc".into(), addr_objs(&m.bcc));
    }
    let mut content: Vec<serde_json::Value> = Vec::new();
    if !m.textBody.is_empty() {
        content.push(serde_json::json!({ "type": "text/plain", "value": m.textBody }));
    }
    if !m.htmlBody.is_empty() {
        content.push(serde_json::json!({ "type": "text/html", "value": m.htmlBody }));
    }
    let mut body = serde_json::json!({
        "personalizations": [ serde_json::Value::Object(personalisation) ],
        "from": { "email": m.from.as_str() },
        "subject": m.subject,
        "content": content,
    });
    json_obj_set(
        &mut body,
        "reply_to",
        serde_json::json!({ "email": m.replyTo.as_str() }),
    );
    if !m.attachments.is_empty() {
        // SendGrid v3 attachments: base64 `content` (the field is `Vec<u8>`
        // so encode directly — no conversion), `filename`, `type` (MIME),
        // `disposition`.
        let atts: Vec<serde_json::Value> = m
            .attachments
            .iter()
            .map(|a| {
                serde_json::json!({
                    "content": B64.encode(&a.content),
                    "filename": a.filename,
                    "type": a.mimeType,
                    "disposition": "attachment",
                })
            })
            .collect();
        json_obj_set(&mut body, "attachments", atts.into());
    }
    let payload = serde_json::to_vec(&body).unwrap_or_default();
    let endpoint = email_endpoint("sendgrid", "https://api.sendgrid.com/v3/mail/send");
    match email_post_json::<E>(
        &endpoint,
        &[
            ("Authorization", format!("Bearer {}", api_key)),
            ("Content-Type", "application/json".to_string()),
        ],
        payload,
    )
    .await
    {
        Ok(_) => IpeResult::Ok(format!("sendgrid-{}", email_gen_id())),
        Err(e) => IpeResult::Err(e),
    }
}

/// Total `obj[key] = val` for a serde_json Value (no-op if `v` isn't an object,
/// which can't happen for the `json!({…})`-built objects here). Avoids the
/// panic-capable `Value` IndexMut.
fn json_obj_set(v: &mut serde_json::Value, key: &str, val: serde_json::Value) {
    if let Some(o) = v.as_object_mut() {
        o.insert(key.to_string(), val);
    }
}

// ──────────────────── SES v2 (SigV4) ────────────────────

async fn send_ses<E: From<String>>(cfg: &SesConfig, m: &EmailMessage) -> IpeResult<E, String> {
    // Reveal the sealed secret access key ONCE, here at the send boundary — it is
    // consumed only by `ses_sign_v4` below (the SigV4 HMAC chain) and is never
    // logged or returned. The empty-key precheck reads the revealed local, not
    // the `Secret` (which has no `is_empty`, by design).
    let secret = crate::secret::secret_reveal(cfg.secret.clone());
    if cfg.region.is_empty() || cfg.key.is_empty() || secret.is_empty() {
        return IpeResult::Err(
            "email.send/Ses: region+key+secret required"
                .to_string()
                .into(),
        );
    }
    // SES v2 simple-content (used below) cannot carry attachments — that needs the
    // raw-MIME (Content.Raw) path, which this module does not build. Rather than
    // SILENTLY DROP attachments (data loss), fail loudly. Resend/SendGrid/SMTP
    // support attachments.
    if !m.attachments.is_empty() {
        return IpeResult::Err(
            "email.send/Ses: attachments require the raw-MIME path, not yet supported on SES \
             (use Resend / SendGrid / SMTP for attachments)"
                .to_string()
                .into(),
        );
    }
    // SSRF guard: `region` is interpolated into the SES host
    // (`email.{region}.amazonaws.com`) AND the SigV4 credential scope. An
    // attacker-controlled region containing `/`, `.`, `@`, `:` or other URL
    // metacharacters would redirect the signed request to an arbitrary host.
    // AWS region names are `[a-z0-9-]+` only — reject anything else.
    if !cfg
        .region
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return IpeResult::Err(
            "email.send/Ses: invalid region (must match [a-z0-9-])"
                .to_string()
                .into(),
        );
    }
    let mut simple = serde_json::json!({
        "Subject": { "Data": m.subject, "Charset": "UTF-8" },
        "Body": { "Text": { "Data": m.textBody, "Charset": "UTF-8" } },
    });
    if !m.htmlBody.is_empty()
        && let Some(b) = simple
            .get_mut("Body")
            .and_then(serde_json::Value::as_object_mut)
    {
        b.insert(
            "Html".to_string(),
            serde_json::json!({ "Data": m.htmlBody, "Charset": "UTF-8" }),
        );
    }
    let to_strings: Vec<&str> = m.to.iter().map(|a| a.as_str()).collect();
    let cc_strings: Vec<&str> = m.cc.iter().map(|a| a.as_str()).collect();
    let bcc_strings: Vec<&str> = m.bcc.iter().map(|a| a.as_str()).collect();
    let mut destination = serde_json::json!({ "ToAddresses": to_strings });
    if !m.cc.is_empty() {
        json_obj_set(
            &mut destination,
            "CcAddresses",
            serde_json::json!(cc_strings),
        );
    }
    if !m.bcc.is_empty() {
        json_obj_set(
            &mut destination,
            "BccAddresses",
            serde_json::json!(bcc_strings),
        );
    }
    let body = serde_json::json!({
        "FromEmailAddress": m.from.as_str(),
        "Destination": destination,
        "Content": { "Simple": simple },
    });
    let payload = serde_json::to_vec(&body).unwrap_or_default();

    let host = format!("email.{}.amazonaws.com", cfg.region);
    let headers = ses_sign_v4(&host, &cfg.region, &cfg.key, &secret, &payload);
    let endpoint = email_endpoint("ses", &format!("https://{}/v2/email/outbound-emails", host));
    let header_refs: Vec<(&str, String)> = headers.iter().map(|(k, v)| (*k, v.clone())).collect();
    match email_post_json::<E>(&endpoint, &header_refs, payload).await {
        Ok(_) => IpeResult::Ok(format!("ses-{}", email_gen_id())),
        Err(e) => IpeResult::Err(e),
    }
}

fn hex_sha256(b: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b);
    hex::encode(h.finalize())
}

fn hmac_bytes(key: &[u8], msg: &[u8]) -> Vec<u8> {
    // STRUCTURALLY-DEAD Err: `Hmac<D>::new_from_slice` returns `Ok` for any key.
    // Kept as a LOUD `.expect`, not eliminated: this helper is called five times in
    // the SigV4 key-derivation chain (each output keys the next), so a threaded dead
    // Result Err that a caller `.unwrap_or(vec![])`s would substitute an empty/wrong
    // MAC and forge a plausible-but-invalid AWS signature — a silent-wrong-crypto
    // defect the loud `.expect` prevents. See the ledger for the full verdict.
    // IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — structurally-dead HMAC InvalidLength in the SES SigV4 chain; loud .expect beats a dead Result Err that could become a silent wrong signature [ledger #2]
    #[allow(clippy::expect_used)]
    let mut mac = HmacSha256::new_from_slice(key).expect("hmac key");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

fn ses_sign_v4(
    host: &str,
    region: &str,
    key: &str,
    secret: &str,
    payload: &[u8],
) -> Vec<(&'static str, String)> {
    // AWS SigV4 timestamps. Format YYYYMMDDTHHMMSSZ + YYYYMMDD.
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (amz_date, date_stamp) = sigv4_timestamps(secs);

    let canonical_request = [
        "POST",
        "/v2/email/outbound-emails",
        "",
        "content-type:application/json",
        &format!("host:{}", host),
        &format!("x-amz-date:{}", amz_date),
        "",
        "content-type;host;x-amz-date",
        &hex_sha256(payload),
    ]
    .join("\n");

    let credential_scope = format!("{}/{}/ses/aws4_request", date_stamp, region);
    let string_to_sign = [
        "AWS4-HMAC-SHA256",
        &amz_date,
        &credential_scope,
        &hex_sha256(canonical_request.as_bytes()),
    ]
    .join("\n");

    let k_date = hmac_bytes(format!("AWS4{}", secret).as_bytes(), date_stamp.as_bytes());
    let k_region = hmac_bytes(&k_date, region.as_bytes());
    let k_service = hmac_bytes(&k_region, b"ses");
    let k_signing = hmac_bytes(&k_service, b"aws4_request");
    let signature = hex::encode(hmac_bytes(&k_signing, string_to_sign.as_bytes()));

    let auth = format!(
        "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders=content-type;host;x-amz-date, Signature={}",
        key, credential_scope, signature
    );
    vec![
        ("Content-Type", "application/json".to_string()),
        ("Host", host.to_string()),
        ("X-Amz-Date", amz_date),
        ("Authorization", auth),
    ]
}

// Convert a Unix-epoch second count into (YYYYMMDDTHHMMSSZ, YYYYMMDD) in UTC
// without pulling chrono into this module's hot path (chrono IS available, but
// a self-contained civil-from-days keeps the SigV4 logic auditable).
fn sigv4_timestamps(epoch_secs: u64) -> (String, String) {
    let days = (epoch_secs / 86_400) as i64;
    let rem = epoch_secs % 86_400;
    let (hh, mm, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (y, mo, d) = civil_from_days(days);
    (
        format!("{:04}{:02}{:02}T{:02}{:02}{:02}Z", y, mo, d, hh, mm, ss),
        format!("{:04}{:02}{:02}", y, mo, d),
    )
}

// Howard Hinnant's civil_from_days — days since 1970-01-01 -> (y, m, d).
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

// ──────────────────── SMTP (lettre) ────────────────────

/// `Ipe.Email.send (Smtp cfg) msg` — SMTP transport via `lettre`: connect to
/// host:port, **opportunistic STARTTLS** (upgrade to TLS when the server
/// advertises it, plaintext otherwise), PLAIN auth when a user is configured.
/// lettre's builder assembles standards-compliant MIME (text/html alternative
/// plus attachments); not byte-identical to a hand-rolled wire, but the
/// delivered message (from/to/cc/bcc/reply-to/subject/body/attachments) is
/// equivalent. A local plaintext catcher (no STARTTLS advertised) is reachable
/// via the opportunistic fallback, which is how this is verified.
async fn send_smtp<E: From<String>>(cfg: &SmtpConfig, m: &EmailMessage) -> IpeResult<E, String> {
    use lettre::message::header::ContentType;
    use lettre::message::{Attachment, Mailbox, MultiPart, SinglePart};
    use lettre::transport::smtp::authentication::Credentials;
    use lettre::transport::smtp::client::{Tls, TlsParameters};
    use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

    if cfg.host.is_empty() || cfg.port == 0 {
        return IpeResult::Err("email.send/Smtp: host+port required".to_string().into());
    }

    let parse_mbox = |s: &str| -> Result<Mailbox, String> {
        s.parse::<Mailbox>()
            .map_err(|e| format!("email.send/Smtp: bad address {:?}: {}", s, e))
    };

    let mut builder = Message::builder();
    builder = match parse_mbox(m.from.as_str()) {
        Ok(mb) => builder.from(mb),
        Err(e) => return IpeResult::Err(e.into()),
    };
    for to in &m.to {
        match parse_mbox(to.as_str()) {
            Ok(mb) => builder = builder.to(mb),
            Err(e) => return IpeResult::Err(e.into()),
        }
    }
    for cc in &m.cc {
        match parse_mbox(cc.as_str()) {
            Ok(mb) => builder = builder.cc(mb),
            Err(e) => return IpeResult::Err(e.into()),
        }
    }
    for bcc in &m.bcc {
        match parse_mbox(bcc.as_str()) {
            Ok(mb) => builder = builder.bcc(mb),
            Err(e) => return IpeResult::Err(e.into()),
        }
    }
    match parse_mbox(m.replyTo.as_str()) {
        Ok(mb) => builder = builder.reply_to(mb),
        Err(e) => return IpeResult::Err(e.into()),
    }
    builder = builder.subject(m.subject.clone());

    // Body: text/html alternative when both are set, else a single part. lettre
    // rejects an empty body, so an all-empty message sends a single space.
    let content: MultiPart = match (m.textBody.is_empty(), m.htmlBody.is_empty()) {
        (false, false) => MultiPart::alternative()
            .singlepart(SinglePart::plain(m.textBody.clone()))
            .singlepart(SinglePart::html(m.htmlBody.clone())),
        (true, false) => MultiPart::related().singlepart(SinglePart::html(m.htmlBody.clone())),
        (false, true) => MultiPart::related().singlepart(SinglePart::plain(m.textBody.clone())),
        (true, true) => MultiPart::related().singlepart(SinglePart::plain(" ".to_string())),
    };

    let built = if m.attachments.is_empty() {
        builder.multipart(content)
    } else {
        let mut mixed = MultiPart::mixed().multipart(content);
        for att in &m.attachments {
            let ct = att
                .mimeType
                .parse::<ContentType>()
                .unwrap_or(ContentType::TEXT_PLAIN);
            // `att.content` is already `Vec<u8>` — pass directly to lettre.
            mixed = mixed
                .singlepart(Attachment::new(att.filename.clone()).body(att.content.clone(), ct));
        }
        builder.multipart(mixed)
    };
    let email = match built {
        Ok(e) => e,
        Err(e) => return IpeResult::Err(format!("email.send/Smtp: build: {}", e).into()),
    };

    // Transport TLS policy. PLAIN auth must NEVER ride a cleartext channel: when
    // credentials are configured a network MITM that strips the STARTTLS
    // advertisement would otherwise harvest user/pass under opportunistic mode.
    // So: port 465 → implicit TLS (Wrapper); credentials set → STARTTLS REQUIRED
    // (no cleartext fallback); no credentials → opportunistic STARTTLS
    // (unauthenticated relay — nothing secret to leak).
    let tls = match TlsParameters::new(cfg.host.clone()) {
        Ok(t) => t,
        Err(e) => return IpeResult::Err(format!("email.send/Smtp: tls: {}", e).into()),
    };
    let tls_policy = if cfg.port == 465 {
        Tls::Wrapper(tls)
    } else if !cfg.user.is_empty() {
        Tls::Required(tls)
    } else {
        Tls::Opportunistic(tls)
    };
    // Validate the port range before narrowing: `cfg.port` is an i64 from Ipê, so
    // a bare `as u16` truncates (65536 → 0, 70000 → 4464, -1 → 65535) and would
    // silently dial a wrong/garbage port. Surface a clear Err instead.
    let port = match u16::try_from(cfg.port) {
        Ok(p) => p,
        Err(_) => {
            return IpeResult::Err(
                "email.send/Smtp: port out of range (1-65535)"
                    .to_string()
                    .into(),
            );
        }
    };
    // SSRF guard — same policy as the reqwest (HTTP POST) path that attaches the
    // bearer token: if a private/loopback host slipped through the operator config,
    // deny before lettre dials. Credentials (cfg.user / cfg.pass) must not ride an
    // unguarded channel to a metadata or loopback endpoint. Under deny-private the
    // transport dials the vetted address, never the name (a second resolution
    // could rebind to an internal host); the certificate is still verified
    // against `cfg.host`, which `TlsParameters` carries.
    let configured = crate::ssrf::ConfiguredHost::from_config(cfg.host.clone());
    let vetted = match crate::ssrf::VettedDial::for_configured_host(&configured, port).await {
        Ok(vetted) => vetted,
        Err(refusal) => return IpeResult::Err(format!("email.send/Smtp: {refusal}").into()),
    };
    // Explicit transport deadline matching the reqwest path's 30s bound, so a
    // stalled SMTP peer (STARTTLS handshake is multi-round-trip) can't hold the
    // task open on lettre's default timeout.
    let mut tb =
        AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(vetted.dial_host(&cfg.host))
            .port(port)
            .tls(tls_policy)
            .timeout(Some(std::time::Duration::from_secs(30)));
    if !cfg.user.is_empty() {
        // Reveal the sealed password ONLY here, at the AUTH step — the plaintext
        // is moved straight into lettre's `Credentials` and is never logged or
        // returned. The TLS policy above already forced `Tls::Required` whenever a
        // user is set, so these credentials never ride a cleartext channel.
        tb = tb.credentials(Credentials::new(
            cfg.user.clone(),
            crate::secret::secret_reveal(cfg.pass.clone()),
        ));
    }
    let transport = tb.build();

    match transport.send(email).await {
        Ok(_) => IpeResult::Ok(format!("smtp-{}", email_gen_id())),
        Err(e) => IpeResult::Err(format!("email.send/Smtp: {}", e).into()),
    }
}

// ──────────────────── small helpers ────────────────────

fn to_json_array(xs: &[EmailAddress]) -> serde_json::Value {
    serde_json::Value::Array(
        xs.iter()
            .map(|a| serde_json::Value::String(a.as_str().to_string()))
            .collect(),
    )
}

fn addr_objs(xs: &[EmailAddress]) -> serde_json::Value {
    serde_json::Value::Array(
        xs.iter()
            .map(|a| serde_json::json!({ "email": a.as_str() }))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dry_run_returns_synthetic_id() {
        crate::system::locked_set_var("IPE_EMAIL_DRY_RUN", "1");
        let from_addr = EmailAddress("a@example.com".to_owned());
        let to_addr = EmailAddress("b@example.com".to_owned());
        let msg = EmailMessage {
            from: from_addr.clone(),
            to: vec![to_addr],
            cc: vec![],
            bcc: vec![],
            subject: "hi".into(),
            textBody: "hello".into(),
            htmlBody: String::new(),
            attachments: vec![],
            replyTo: from_addr,
        };
        let r: IpeResult<String, String> = email_send(
            EmailProvider::Resend(crate::secret::secret_from_string("key".into())),
            msg,
        )
        .await;
        match r {
            IpeResult::Ok(id) => assert!(id.starts_with("dry-run-")),
            IpeResult::Err(e) => panic!("dry-run failed: {}", e),
        }
        crate::system::locked_remove_var("IPE_EMAIL_DRY_RUN");
    }

    // ── Provider credential secrecy (leak-proof) tests ──────────────────────

    /// The plaintext credential a provider is built from. If ANY `Debug` /
    /// stringify path over an `EmailProvider` echoes this, the test fails.
    const CRED_MARKER: &str = "sk_live_LEAK_MARKER_9f3z";

    /// `Debug`-formatting an `EmailProvider` (or its config records) must render
    /// the sealed credential as the redacted placeholder, never the plaintext —
    /// this is the security invariant the `Secret` typing buys. Covers every
    /// variant: the bare-key `Resend` / `SendGrid` and the config-record
    /// `Ses` / `Smtp`.
    #[test]
    fn provider_debug_never_leaks_the_credential() {
        let providers = vec![
            EmailProvider::Resend(crate::secret::secret_from_string(CRED_MARKER.to_owned())),
            EmailProvider::SendGrid(crate::secret::secret_from_string(CRED_MARKER.to_owned())),
            EmailProvider::Ses(SesConfig {
                region: "us-east-1".to_owned(),
                key: "AKIAEXAMPLE".to_owned(),
                secret: crate::secret::secret_from_string(CRED_MARKER.to_owned()),
            }),
            EmailProvider::Smtp(SmtpConfig {
                host: "smtp.example.com".to_owned(),
                port: 587,
                user: "mailer".to_owned(),
                pass: crate::secret::secret_from_string(CRED_MARKER.to_owned()),
            }),
        ];
        for p in &providers {
            let shown = format!("{p:?}");
            assert!(
                !shown.contains(CRED_MARKER),
                "EmailProvider Debug leaked the plaintext credential: {shown}"
            );
            assert!(
                shown.contains("<redacted>"),
                "EmailProvider Debug must render the credential as <redacted>: {shown}"
            );
        }
    }

    /// The `secret_reveal` un-seal at the send boundary must recover the exact
    /// plaintext (proving the seal is not lossy) — the positive counterpart to
    /// the leak test. This is the ONLY path that recovers the plaintext.
    #[test]
    fn send_boundary_reveal_recovers_the_credential() {
        let sealed = crate::secret::secret_from_string(CRED_MARKER.to_owned());
        assert_eq!(crate::secret::secret_reveal(sealed), CRED_MARKER);
    }

    // ── EmailAddress typed parse boundary tests ──────────────────────────────

    /// `parseAddress` returns `Just` for a structurally valid address.
    #[test]
    fn email_address_parse_valid_returns_just() {
        let result = email_address_parse("user@example.com".to_string());
        assert!(
            matches!(result, crate::core::IpeMaybe::Just(_)),
            "valid email must parse to Just"
        );
    }

    /// `parseAddress` returns `Nothing` for an invalid address — never a silent accept.
    #[test]
    fn email_address_parse_invalid_returns_nothing() {
        for bad in &[
            "not-an-email",
            "@no-user",
            "no-at-sign",
            "spaces in@address.com",
            "",
            "missing@",
        ] {
            let result = email_address_parse((*bad).to_string());
            assert!(
                matches!(result, crate::core::IpeMaybe::Nothing),
                "invalid address {:?} must parse to Nothing, got Just",
                bad
            );
        }
    }

    /// `addressToString` is a left-inverse of `parseAddress` for valid addresses.
    #[test]
    fn email_address_to_string_roundtrip() {
        let addr_str = "user@example.com".to_string();
        let parsed = match email_address_parse(addr_str.clone()) {
            crate::core::IpeMaybe::Just(a) => a,
            crate::core::IpeMaybe::Nothing => panic!("valid address should parse"),
        };
        assert_eq!(email_address_to_string(parsed), addr_str);
    }

    #[test]
    fn civil_from_days_epoch() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        // Day 18628 after epoch = Jan 1 of the year the fixture uses.
        assert_eq!(civil_from_days(18628), (2021, 1, 1));
    }

    // ── Bytes content field fidelity tests ──────────────────────────────────

    /// `EmailAttachment.content` is `Vec<u8>`: non-UTF-8 bytes that would be
    /// corrupted by a `String` bridge must survive the pipeline byte-for-byte.
    ///
    /// A `String`-typed `content` field would require `.as_bytes()` or
    /// `.into_bytes()` at every provider boundary; the pre-migration code did
    /// exactly that.  These bytes — `0x9e 0xfe`, invalid UTF-8 — would round-trip
    /// correctly through base64 encoding but are representative of the class of
    /// payloads that a `String` field would silently reject (e.g. via a lossy
    /// UTF-8 decode truncating or replacing invalid sequences).
    #[test]
    fn attachment_content_bytes_roundtrip_non_utf8() {
        // 0x9e and 0xfe are not valid UTF-8 start bytes (not representable in a
        // Rust `String`).  They must flow through the `content: Vec<u8>` field
        // without any UTF-8 validation step.
        let non_utf8: Vec<u8> = vec![0x9e, 0xfe, 0x00, 0xff, 0x80];
        let att = EmailAttachment {
            filename: "binary.bin".to_string(),
            mimeType: "application/octet-stream".to_string(),
            content: non_utf8.clone(),
        };
        // The bytes must be retrievable from the field unchanged.
        assert_eq!(
            att.content, non_utf8,
            "non-UTF-8 bytes must survive the Vec<u8> content field unchanged"
        );
        // The base64 encoding the provider paths emit must decode back to the
        // original bytes — proving the pipeline is lossless end-to-end.
        let b64 = B64.encode(&att.content);
        let decoded = B64.decode(&b64).expect("base64 decode must succeed");
        assert_eq!(
            decoded, non_utf8,
            "non-UTF-8 bytes must survive base64 encode/decode without corruption"
        );
    }

    /// Full byte range (0x00–0xFF) survives the `content: Vec<u8>` field.
    #[test]
    fn attachment_content_bytes_full_range_roundtrip() {
        let all_bytes: Vec<u8> = (0u8..=255u8).collect();
        let att = EmailAttachment {
            filename: "all.bin".to_string(),
            mimeType: "application/octet-stream".to_string(),
            content: all_bytes.clone(),
        };
        assert_eq!(att.content, all_bytes);
        let b64 = B64.encode(&att.content);
        let decoded = B64.decode(&b64).expect("base64 decode");
        assert_eq!(
            decoded, all_bytes,
            "all 256 byte values must survive the pipeline"
        );
    }

    // ── SMTP SSRF guard tests ────────────────────────────────────────────────

    /// A helper that exercises only the SSRF gate on a synthetic `SmtpConfig`,
    /// bypassing the actual SMTP dial.  The guard must fire before
    /// `builder_dangerous` is reached, so the error text identifies the
    /// SSRF block string, not a connection / TLS error.
    async fn smtp_ssrf_result(host: &str) -> IpeResult<String, String> {
        // Construct a minimal SmtpConfig with an in-range port (25) so the
        // port-range check passes and only the SSRF gate is the discriminator.
        let cfg = SmtpConfig {
            host: host.to_string(),
            port: 25,
            user: String::new(),
            pass: crate::secret::secret_from_string(String::new()),
        };
        // VettedDial::for_configured_host mirrors the guard in email_send_smtp exactly.
        // We test at this layer rather than driving the full send so the test
        // dials nothing (IP literals are decided without a lookup).
        let port_u16 = u16::try_from(cfg.port).unwrap_or(25);
        let configured = crate::ssrf::ConfiguredHost::from_config(cfg.host.clone());
        match crate::ssrf::VettedDial::for_configured_host(&configured, port_u16).await {
            Err(e) => IpeResult::Err(format!("email.send/Smtp: {e}")),
            Ok(_) => IpeResult::Ok("gate-passed".into()),
        }
    }

    #[tokio::test]
    async fn smtp_ssrf_blocks_loopback_when_deny_private_on() {
        crate::system::locked_set_var("IPE_HTTP_DENY_PRIVATE", "1");
        let r = smtp_ssrf_result("127.0.0.1").await;
        assert!(
            matches!(r, IpeResult::Err(ref e) if e.contains("blocked")),
            "loopback SMTP host must be blocked: {r:?}"
        );
        crate::system::locked_remove_var("IPE_HTTP_DENY_PRIVATE");
    }

    #[tokio::test]
    async fn smtp_ssrf_blocks_link_local_when_deny_private_on() {
        crate::system::locked_set_var("IPE_HTTP_DENY_PRIVATE", "1");
        let r = smtp_ssrf_result("169.254.169.254").await;
        assert!(
            matches!(r, IpeResult::Err(ref e) if e.contains("blocked")),
            "link-local SMTP host must be blocked: {r:?}"
        );
        crate::system::locked_remove_var("IPE_HTTP_DENY_PRIVATE");
    }

    #[tokio::test]
    async fn smtp_ssrf_error_class_matches_http_path_for_same_private_host() {
        // The SMTP and HTTP (reqwest) paths must return the same error CLASS
        // (both contain "blocked") for the same private host, proving parity.
        crate::system::locked_set_var("IPE_HTTP_DENY_PRIVATE", "1");
        let smtp_err = match smtp_ssrf_result("10.0.0.1").await {
            IpeResult::Err(e) => e,
            IpeResult::Ok(_) => panic!("expected SSRF block for 10.0.0.1"),
        };
        let http_err = crate::http_client::ssrf_apply_with(
            reqwest::Client::builder(),
            "http://10.0.0.1/",
            crate::http_client::RedirectPolicy::NoRedirects,
            crate::ssrf::DialPolicy::DenyPrivate,
            crate::http_client::VettingResolver::system(),
        )
        .await
        .err()
        .map(|refusal| refusal.to_string())
        .unwrap_or_default();
        assert!(
            smtp_err.contains("blocked"),
            "SMTP error must contain 'blocked': {smtp_err}"
        );
        assert!(
            http_err.contains("blocked"),
            "HTTP error must contain 'blocked': {http_err}"
        );
        crate::system::locked_remove_var("IPE_HTTP_DENY_PRIVATE");
    }

    #[tokio::test]
    async fn smtp_ssrf_passes_private_when_deny_private_off() {
        crate::system::locked_set_var("IPE_HTTP_DENY_PRIVATE", "0");
        // Guard off: loopback is a pass (dev/relay workflow).
        assert!(
            matches!(smtp_ssrf_result("127.0.0.1").await, IpeResult::Ok(_)),
            "guard off must not block private host"
        );
        crate::system::locked_remove_var("IPE_HTTP_DENY_PRIVATE");
    }
}
