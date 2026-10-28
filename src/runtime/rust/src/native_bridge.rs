//! The native mobile bridge channel: its constants, request envelope and reply grammar.
//!
//! A mobile shell answers first-party `Ipe.Browser.*` calls over one versioned
//! JSON channel. Every value the port glue and the shells read is defined here
//! once and rendered into them. [`parse_reply`] is the reply grammar the glue's
//! `parseBridgeReply` mirrors, and [`Reject`] is the one closed refusal table
//! both sides map to Ipê values.

/// The wire protocol version every envelope carries.
pub const BRIDGE_PROTOCOL_VERSION: u32 = 1;

/// The name the shell registers its message channel under.
pub const BRIDGE_CHANNEL_NAME: &str = "__ipeNative";

/// The largest serialized request the glue sends and a shell accepts.
pub const BRIDGE_MAX_REQUEST_BYTES: usize = 65_536;

/// The most bridge requests a page holds in flight at once.
///
/// Equal to the runtime's outstanding-waiter ceiling; the build fails when the
/// two differ wherever both are compiled.
pub const BRIDGE_MAX_OUTSTANDING: usize = 256;

/// How long the glue waits for a reply before settling the request unavailable.
///
/// Equal to the runtime's request deadline; the build fails when the two differ
/// wherever both are compiled.
pub const BRIDGE_REPLY_DEADLINE_MS: u64 = 10_000;

/// The most `notification.show` requests a shell honours within one window.
pub const BRIDGE_NOTIFY_BURST: u32 = 10;

/// The length of the shell's `notification.show` rate window.
pub const BRIDGE_NOTIFY_WINDOW_MS: u64 = 10_000;

/// The byte ceiling on a notification title.
pub const NOTIFICATION_TITLE_MAX_BYTES: usize = 256;

/// The byte ceiling on a notification body.
pub const NOTIFICATION_BODY_MAX_BYTES: usize = 1024;

/// The byte ceiling on a notification tag.
pub const NOTIFICATION_TAG_MAX_BYTES: usize = 64;

/// The characters a notification tag may carry besides ASCII letters and digits.
///
/// `-` stays last so the glue renders it into a character class as a literal.
pub const NOTIFICATION_TAG_PUNCTUATION: &str = "._-";

/// The cap name the handshake request carries.
pub const HANDSHAKE_CAP_NAME: &str = "bridge";

/// The identifier the port glue binds the handshake cap name to.
pub const HANDSHAKE_CAP_GLUE_NAME: &str = "CAP_BRIDGE";

/// The request id reserved for the handshake.
pub const HELLO_ID: &str = "0";

/// The largest reply a shell sends and the runtime decodes.
#[cfg(feature = "json")]
pub use crate::seal_codec::DEFAULT_SEAL_MAX_INPUT_BYTES as BRIDGE_MAX_REPLY_BYTES;

#[cfg(all(
    feature = "json",
    any(
        feature = "tokio",
        all(target_arch = "wasm32", feature = "wasm-client")
    )
))]
// IPE-RUST-AUDIT:ACCEPTED (Arthur Maciel) — compile-time `const` assertion (not a runtime panic); fails the BUILD if a mirrored bridge ceiling drifts from the runtime port ceiling it mirrors [ledger #boundary]
const _: () = assert!(
    BRIDGE_MAX_OUTSTANDING == crate::js_port::MAX_OUTSTANDING
        && BRIDGE_REPLY_DEADLINE_MS == crate::js_port::REQUEST_TIMEOUT_MS
);

/// A capability a shell can serve natively.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BridgeCap {
    /// Local notifications.
    Notification,
    /// The push subscription.
    Push,
}

impl BridgeCap {
    /// Every bridged capability, in declaration order.
    pub const ALL: &'static [Self] = &[Self::Notification, Self::Push];

    /// The wire name of this capability.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Notification => "notification",
            Self::Push => "push",
        }
    }

    /// The identifier the port glue binds this capability's wire name to.
    #[must_use]
    pub const fn glue_name(self) -> &'static str {
        match self {
            Self::Notification => "CAP_NOTIFICATION",
            Self::Push => "CAP_PUSH",
        }
    }

    /// The capability a wire name spells, or `None` for any other text.
    #[must_use]
    pub fn from_wire(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|cap| cap.as_str() == name)
    }
}

/// One operation of the bridge protocol.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BridgeOp {
    /// The handshake that learns the shell's version and capabilities.
    Hello,
    /// Read the notification permission without prompting.
    NotificationPermission,
    /// Prompt for the notification permission.
    NotificationRequest,
    /// Show one notification.
    NotificationShow,
    /// Subscribe to push with an application key.
    PushSubscribe,
    /// Read the current push subscription.
    PushCurrent,
    /// Drop the push subscription.
    PushUnsubscribe,
}

impl BridgeOp {
    /// Every operation, in declaration order.
    pub const ALL: &'static [Self] = &[
        Self::Hello,
        Self::NotificationPermission,
        Self::NotificationRequest,
        Self::NotificationShow,
        Self::PushSubscribe,
        Self::PushCurrent,
        Self::PushUnsubscribe,
    ];

    /// The capability this operation belongs to, or `None` for the handshake.
    #[must_use]
    pub const fn cap(self) -> Option<BridgeCap> {
        match self {
            Self::Hello => None,
            Self::NotificationPermission | Self::NotificationRequest | Self::NotificationShow => {
                Some(BridgeCap::Notification)
            }
            Self::PushSubscribe | Self::PushCurrent | Self::PushUnsubscribe => {
                Some(BridgeCap::Push)
            }
        }
    }

    /// The `cap` field this operation's request carries.
    #[must_use]
    pub const fn cap_name(self) -> &'static str {
        match self.cap() {
            Some(cap) => cap.as_str(),
            None => HANDSHAKE_CAP_NAME,
        }
    }

    /// The identifier the port glue binds this operation's `cap` name to.
    #[must_use]
    pub const fn cap_glue_name(self) -> &'static str {
        match self.cap() {
            Some(cap) => cap.glue_name(),
            None => HANDSHAKE_CAP_GLUE_NAME,
        }
    }

    /// The `op` field this operation's request carries.
    #[must_use]
    pub const fn op_name(self) -> &'static str {
        match self {
            Self::Hello => "hello",
            Self::NotificationPermission => "permission",
            Self::NotificationRequest => "request",
            Self::NotificationShow => "show",
            Self::PushSubscribe => "subscribe",
            Self::PushCurrent => "current",
            Self::PushUnsubscribe => "unsubscribe",
        }
    }

    /// The identifier the port glue binds this operation's `[cap, op]` pair to.
    #[must_use]
    pub const fn glue_name(self) -> &'static str {
        match self {
            Self::Hello => "OP_HELLO",
            Self::NotificationPermission => "OP_NOTIFICATION_PERMISSION",
            Self::NotificationRequest => "OP_NOTIFICATION_REQUEST",
            Self::NotificationShow => "OP_NOTIFICATION_SHOW",
            Self::PushSubscribe => "OP_PUSH_SUBSCRIBE",
            Self::PushCurrent => "OP_PUSH_CURRENT",
            Self::PushUnsubscribe => "OP_PUSH_UNSUBSCRIBE",
        }
    }

    /// The operation a `cap`/`op` pair spells, or `None` for any other pair.
    #[must_use]
    pub fn from_wire(cap: &str, op: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|candidate| candidate.cap_name() == cap && candidate.op_name() == op)
    }
}

/// The closed set of refusals a shell answers with.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Reject {
    /// The user or the OS refused the permission.
    Denied,
    /// The device or the OS lacks the facility.
    Unavailable,
    /// The user dismissed the prompt.
    Cancelled,
    /// A malformed envelope, an unknown cap or op, or a cap the shell does not accept.
    Refused,
    /// A size, outstanding or rate ceiling.
    Limit,
    /// The envelope's version is not supported.
    Version,
}

/// The error kind a [`Reject`] maps to where a module has no value of its own for it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BridgeErrorKind {
    /// `Error.permissionDenied`.
    PermissionDenied,
    /// `Error.unavailable`.
    Unavailable,
    /// `Error.invalidInput`.
    InvalidInput,
    /// `Error.limitExceeded`.
    LimitExceeded,
}

/// The `Ipe.Browser.Notification` reply a bridge outcome becomes.
///
/// One member per constructor of the module's closed `JsMsg` vocabulary.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NotificationFrame {
    /// The permission was granted.
    Granted,
    /// The notification was shown.
    Shown,
    /// The permission was refused.
    Denied,
    /// Notifications are unavailable.
    Unavailable,
}

impl NotificationFrame {
    /// The frame field this reply sets: `event` for a success, `error` for a failure.
    #[must_use]
    pub const fn field(self) -> &'static str {
        match self {
            Self::Granted | Self::Shown => "event",
            Self::Denied | Self::Unavailable => "error",
        }
    }

    /// The value the frame field carries.
    #[must_use]
    pub const fn wire(self) -> &'static str {
        match self {
            Self::Granted => "granted",
            Self::Shown => "shown",
            Self::Denied => "denied",
            Self::Unavailable => "unavailable",
        }
    }
}

impl Reject {
    /// Every refusal, in declaration order.
    pub const ALL: &'static [Self] = &[
        Self::Denied,
        Self::Unavailable,
        Self::Cancelled,
        Self::Refused,
        Self::Limit,
        Self::Version,
    ];

    /// The wire code of this refusal.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Denied => "denied",
            Self::Unavailable => "unavailable",
            Self::Cancelled => "cancelled",
            Self::Refused => "refused",
            Self::Limit => "limit",
            Self::Version => "version",
        }
    }

    /// The identifier the port glue binds this refusal's wire code to.
    #[must_use]
    pub const fn glue_name(self) -> &'static str {
        match self {
            Self::Denied => "REJECT_DENIED",
            Self::Unavailable => "REJECT_UNAVAILABLE",
            Self::Cancelled => "REJECT_CANCELLED",
            Self::Refused => "REJECT_REFUSED",
            Self::Limit => "REJECT_LIMIT",
            Self::Version => "REJECT_VERSION",
        }
    }

    /// The refusal a wire code spells, or `None` for any other text.
    #[must_use]
    pub fn from_wire(code: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|reject| reject.as_str() == code)
    }

    /// The error kind this refusal maps to in a module with no value of its own for it.
    #[must_use]
    pub const fn error_kind(self) -> BridgeErrorKind {
        match self {
            Self::Denied => BridgeErrorKind::PermissionDenied,
            Self::Unavailable | Self::Cancelled | Self::Version => BridgeErrorKind::Unavailable,
            Self::Refused => BridgeErrorKind::InvalidInput,
            Self::Limit => BridgeErrorKind::LimitExceeded,
        }
    }

    /// The fixed message an error built from this refusal carries.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::Denied => "permission denied by the device",
            Self::Unavailable => "unavailable on this device",
            Self::Cancelled => "the prompt was dismissed",
            Self::Refused => "the device refused the request",
            Self::Limit => "a device limit was reached",
            Self::Version => "the device speaks another bridge version",
        }
    }

    /// The `Ipe.Browser.Notification` reply this refusal becomes.
    ///
    /// The module's closed vocabulary names a denial and an absence only, so every
    /// refusal but a denial reads as unavailable there.
    #[must_use]
    pub const fn notification_frame(self) -> NotificationFrame {
        match self {
            Self::Denied => NotificationFrame::Denied,
            Self::Unavailable | Self::Cancelled | Self::Refused | Self::Limit | Self::Version => {
                NotificationFrame::Unavailable
            }
        }
    }
}

/// A notification permission state a shell reports.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PermissionState {
    /// The permission is granted.
    Granted,
    /// The permission is refused.
    Denied,
}

impl PermissionState {
    /// Every state, in declaration order.
    pub const ALL: &'static [Self] = &[Self::Granted, Self::Denied];

    /// The wire value of this state.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Granted => "granted",
            Self::Denied => "denied",
        }
    }

    /// The identifier the port glue binds this state's wire value to.
    #[must_use]
    pub const fn glue_name(self) -> &'static str {
        match self {
            Self::Granted => "STATE_GRANTED",
            Self::Denied => "STATE_DENIED",
        }
    }

    /// The state a wire value spells, or `None` for any other text.
    #[must_use]
    pub fn from_wire(value: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|state| state.as_str() == value)
    }

    /// The `Ipe.Browser.Notification` reply a permission request answered with this state becomes.
    #[must_use]
    pub const fn notification_frame(self) -> NotificationFrame {
        match self {
            Self::Granted => NotificationFrame::Granted,
            Self::Denied => NotificationFrame::Denied,
        }
    }
}

/// Whether `tag` fits the notification tag grammar.
#[must_use]
pub fn is_notification_tag(tag: &str) -> bool {
    tag.len() <= NOTIFICATION_TAG_MAX_BYTES
        && tag
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || NOTIFICATION_TAG_PUNCTUATION.contains(c))
}

/// Why a request or a reply was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BridgeRefusal {
    /// The text is longer than its ceiling.
    TooLarge,
    /// The text is not one JSON object.
    Malformed,
    /// The object carries a field outside the envelope.
    UnknownField,
    /// `v` is absent or is not the protocol version.
    WrongVersion,
    /// `id` is absent, is not text, or names no outstanding request.
    UnknownId,
    /// The reply carries both `ok` and `reject`.
    BothOutcomes,
    /// The reply carries neither `ok` nor `reject`.
    NoOutcome,
    /// `ok` is not an object.
    MalformedOk,
    /// `reject` is not one of the six codes.
    UnknownReject,
    /// A request id outside the id grammar, or the handshake id on another operation.
    BadId,
    /// A request field is longer than its ceiling or outside its grammar.
    BadField,
}

/// The id of one bridge request: 1 to 16 lowercase hex digits.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RequestId(String);

impl RequestId {
    /// The id `text` spells.
    ///
    /// # Errors
    ///
    /// [`BridgeRefusal::BadId`] for text outside 1 to 16 lowercase hex digits.
    pub fn new(text: &str) -> Result<Self, BridgeRefusal> {
        let in_grammar = (1..=16).contains(&text.len())
            && text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if in_grammar {
            Ok(Self(text.to_owned()))
        } else {
            Err(BridgeRefusal::BadId)
        }
    }

    /// The id's text.
    #[must_use]
    pub const fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

/// One operation together with the arguments its request carries.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum BridgeCall {
    /// The handshake.
    Hello,
    /// Read the notification permission.
    NotificationPermission,
    /// Prompt for the notification permission.
    NotificationRequest,
    /// Show one notification.
    NotificationShow {
        /// The title.
        title: String,
        /// The body.
        body: String,
        /// The tag.
        tag: String,
    },
    /// Subscribe to push.
    PushSubscribe {
        /// The application server key.
        application_key: String,
    },
    /// Read the current push subscription.
    PushCurrent,
    /// Drop the push subscription.
    PushUnsubscribe,
}

impl BridgeCall {
    /// The operation this call performs.
    #[must_use]
    pub const fn op(&self) -> BridgeOp {
        match self {
            Self::Hello => BridgeOp::Hello,
            Self::NotificationPermission => BridgeOp::NotificationPermission,
            Self::NotificationRequest => BridgeOp::NotificationRequest,
            Self::NotificationShow { .. } => BridgeOp::NotificationShow,
            Self::PushSubscribe { .. } => BridgeOp::PushSubscribe,
            Self::PushCurrent => BridgeOp::PushCurrent,
            Self::PushUnsubscribe => BridgeOp::PushUnsubscribe,
        }
    }
}

/// One request, ready to encode.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BridgeRequest {
    id: RequestId,
    call: BridgeCall,
}

impl BridgeRequest {
    /// A request carrying `call` under `id`.
    ///
    /// # Errors
    ///
    /// [`BridgeRefusal::BadId`] when the handshake id and the handshake call do not
    /// go together; [`BridgeRefusal::BadField`] for a notification field past its
    /// ceiling or outside its grammar.
    pub fn new(id: RequestId, call: BridgeCall) -> Result<Self, BridgeRefusal> {
        if (id.as_str() == HELLO_ID) != (call == BridgeCall::Hello) {
            return Err(BridgeRefusal::BadId);
        }
        if let BridgeCall::NotificationShow { title, body, tag } = &call {
            let fits = title.len() <= NOTIFICATION_TITLE_MAX_BYTES
                && body.len() <= NOTIFICATION_BODY_MAX_BYTES
                && is_notification_tag(tag);
            if !fits {
                return Err(BridgeRefusal::BadField);
            }
        }
        Ok(Self { id, call })
    }

    /// The request's id.
    #[must_use]
    pub const fn id(&self) -> &RequestId {
        &self.id
    }

    /// The request's call.
    #[must_use]
    pub const fn call(&self) -> &BridgeCall {
        &self.call
    }
}

#[cfg(feature = "json")]
mod wire {
    use super::{
        BRIDGE_MAX_REPLY_BYTES, BRIDGE_MAX_REQUEST_BYTES, BRIDGE_PROTOCOL_VERSION, BridgeCall,
        BridgeOp, BridgeRefusal, BridgeRequest, NotificationFrame, PermissionState, Reject,
        RequestId,
    };
    use serde_json::{Map, Value};

    /// A JSON object.
    pub type Object = Map<String, Value>;

    /// One parsed reply.
    ///
    /// Its `Debug` shows the id and the refusal and withholds the `ok` payload,
    /// which can carry a push subscription's endpoint and secrets.
    #[derive(Clone, PartialEq)]
    pub enum BridgeReply {
        /// The shell performed the request; the payload is the `ok` object.
        Ok {
            /// The request this reply answers.
            id: RequestId,
            /// The `ok` object.
            payload: Object,
        },
        /// The shell refused the request.
        Rejected {
            /// The request this reply answers.
            id: RequestId,
            /// The refusal.
            reject: Reject,
        },
    }

    impl std::fmt::Debug for BridgeReply {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::Ok { id, payload: _ } => f
                    .debug_struct("Ok")
                    .field("id", id)
                    .field("payload", &"<redacted>")
                    .finish(),
                Self::Rejected { id, reject } => f
                    .debug_struct("Rejected")
                    .field("id", id)
                    .field("reject", reject)
                    .finish(),
            }
        }
    }

    impl BridgeReply {
        /// The request this reply answers.
        #[must_use]
        pub const fn id(&self) -> &RequestId {
            match self {
                Self::Ok { id, .. } | Self::Rejected { id, .. } => id,
            }
        }
    }

    /// Whether `value` is the protocol version, as the glue's strict equality reads it.
    fn is_protocol_version(value: Option<&Value>) -> bool {
        value.and_then(Value::as_f64).map(f64::to_bits)
            == Some(f64::from(BRIDGE_PROTOCOL_VERSION).to_bits())
    }

    impl BridgeRequest {
        /// The request as the one JSON string the channel carries.
        ///
        /// # Errors
        ///
        /// [`BridgeRefusal::TooLarge`] when the text is longer than
        /// `BRIDGE_MAX_REQUEST_BYTES`.
        pub fn encode(&self) -> Result<String, BridgeRefusal> {
            let op = self.call.op();
            let mut args = Object::new();
            match &self.call {
                BridgeCall::NotificationShow { title, body, tag } => {
                    args.insert("title".to_owned(), Value::from(title.as_str()));
                    args.insert("body".to_owned(), Value::from(body.as_str()));
                    args.insert("tag".to_owned(), Value::from(tag.as_str()));
                }
                BridgeCall::PushSubscribe { application_key } => {
                    args.insert(
                        "applicationKey".to_owned(),
                        Value::from(application_key.as_str()),
                    );
                }
                BridgeCall::Hello
                | BridgeCall::NotificationPermission
                | BridgeCall::NotificationRequest
                | BridgeCall::PushCurrent
                | BridgeCall::PushUnsubscribe => {}
            }
            let mut envelope = Object::new();
            envelope.insert("v".to_owned(), Value::from(BRIDGE_PROTOCOL_VERSION));
            envelope.insert("id".to_owned(), Value::from(self.id.as_str()));
            envelope.insert("cap".to_owned(), Value::from(op.cap_name()));
            envelope.insert("op".to_owned(), Value::from(op.op_name()));
            envelope.insert("args".to_owned(), Value::Object(args));
            let text = Value::Object(envelope).to_string();
            if text.len() > BRIDGE_MAX_REQUEST_BYTES {
                return Err(BridgeRefusal::TooLarge);
            }
            Ok(text)
        }
    }

    /// The reply `text` spells, answering one of `outstanding`.
    ///
    /// The grammar the glue's `parseBridgeReply` holds: one JSON object of `v`,
    /// `id` and exactly one of `ok` (an object) or `reject` (one of the six codes),
    /// whose `id` names an outstanding request.
    ///
    /// # Errors
    ///
    /// The [`BridgeRefusal`] naming the first rule `text` breaks.
    pub fn parse_reply(
        text: &str,
        outstanding: &[RequestId],
    ) -> Result<BridgeReply, BridgeRefusal> {
        if text.len() > BRIDGE_MAX_REPLY_BYTES {
            return Err(BridgeRefusal::TooLarge);
        }
        let Ok(Value::Object(fields)) = serde_json::from_str::<Value>(text) else {
            return Err(BridgeRefusal::Malformed);
        };
        if fields
            .keys()
            .any(|key| !matches!(key.as_str(), "v" | "id" | "ok" | "reject"))
        {
            return Err(BridgeRefusal::UnknownField);
        }
        if !is_protocol_version(fields.get("v")) {
            return Err(BridgeRefusal::WrongVersion);
        }
        let Some(id) = fields
            .get("id")
            .and_then(Value::as_str)
            .and_then(|text| outstanding.iter().find(|id| id.as_str() == text))
        else {
            return Err(BridgeRefusal::UnknownId);
        };
        match (fields.get("ok"), fields.get("reject")) {
            (Some(_), Some(_)) => Err(BridgeRefusal::BothOutcomes),
            (None, None) => Err(BridgeRefusal::NoOutcome),
            (Some(ok), None) => ok
                .as_object()
                .ok_or(BridgeRefusal::MalformedOk)
                .map(|payload| BridgeReply::Ok {
                    id: id.clone(),
                    payload: payload.clone(),
                }),
            (None, Some(code)) => code
                .as_str()
                .and_then(Reject::from_wire)
                .ok_or(BridgeRefusal::UnknownReject)
                .map(|reject| BridgeReply::Rejected {
                    id: id.clone(),
                    reject,
                }),
        }
    }

    /// The `Ipe.Browser.Notification` reply a parsed reply to a notification `op` becomes.
    ///
    /// A permission request reads the `state` its `ok` reports, and any other
    /// payload is unavailable; a shown notification is `Shown`; a refusal maps
    /// through [`Reject::notification_frame`]. `None` for an op outside the
    /// notification capability.
    #[must_use]
    pub fn notification_frame(op: BridgeOp, reply: &BridgeReply) -> Option<NotificationFrame> {
        let frame = match (op, reply) {
            (
                BridgeOp::Hello
                | BridgeOp::PushSubscribe
                | BridgeOp::PushCurrent
                | BridgeOp::PushUnsubscribe,
                _,
            ) => return None,
            (
                BridgeOp::NotificationPermission
                | BridgeOp::NotificationRequest
                | BridgeOp::NotificationShow,
                BridgeReply::Rejected { reject, .. },
            ) => reject.notification_frame(),
            (BridgeOp::NotificationShow, BridgeReply::Ok { .. }) => NotificationFrame::Shown,
            (
                BridgeOp::NotificationPermission | BridgeOp::NotificationRequest,
                BridgeReply::Ok { payload, .. },
            ) => payload
                .get("state")
                .and_then(Value::as_str)
                .and_then(PermissionState::from_wire)
                .map_or(
                    NotificationFrame::Unavailable,
                    PermissionState::notification_frame,
                ),
        };
        Some(frame)
    }
}

#[cfg(feature = "json")]
pub use wire::{BridgeReply, Object, notification_frame, parse_reply};

#[cfg(all(test, feature = "json"))]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn id(text: &str) -> RequestId {
        RequestId::new(text).unwrap_or_else(|_| RequestId(String::new()))
    }

    fn outstanding() -> Vec<RequestId> {
        vec![id(HELLO_ID), id("1f")]
    }

    fn parse(value: &Value) -> Result<BridgeReply, BridgeRefusal> {
        parse_reply(&value.to_string(), &outstanding())
    }

    #[test]
    fn the_reply_grammar_admits_an_ok_and_each_reject_code() {
        assert!(matches!(
            parse(&json!({"v": 1, "id": "1f", "ok": {}})),
            Ok(BridgeReply::Ok { .. })
        ));
        for &reject in Reject::ALL {
            let reply = parse(&json!({"v": 1, "id": "1f", "reject": reject.as_str()}));
            assert_eq!(
                reply,
                Ok(BridgeReply::Rejected {
                    id: id("1f"),
                    reject
                })
            );
        }
    }

    #[test]
    fn a_reply_naming_no_outstanding_request_is_refused() {
        for bad in [json!("20"), json!("1F"), json!(31), json!(null)] {
            assert_eq!(
                parse(&json!({"v": 1, "id": bad, "ok": {}})),
                Err(BridgeRefusal::UnknownId)
            );
        }
        assert_eq!(
            parse(&json!({"v": 1, "ok": {}})),
            Err(BridgeRefusal::UnknownId)
        );
        assert!(parse(&json!({"v": 1, "id": "1f", "ok": {}})).is_ok());
    }

    #[test]
    fn a_reply_with_another_version_is_refused() {
        for bad in [json!(2), json!(0), json!("1"), json!(null), json!(true)] {
            assert_eq!(
                parse(&json!({"v": bad, "id": "1f", "ok": {}})),
                Err(BridgeRefusal::WrongVersion)
            );
        }
        assert_eq!(
            parse(&json!({"id": "1f", "ok": {}})),
            Err(BridgeRefusal::WrongVersion)
        );
        assert!(parse(&json!({"v": 1.0, "id": "1f", "ok": {}})).is_ok());
    }

    #[test]
    fn a_reply_with_both_or_neither_outcome_is_refused() {
        assert_eq!(
            parse(&json!({"v": 1, "id": "1f", "ok": {}, "reject": "denied"})),
            Err(BridgeRefusal::BothOutcomes)
        );
        assert_eq!(
            parse(&json!({"v": 1, "id": "1f"})),
            Err(BridgeRefusal::NoOutcome)
        );
        assert!(parse(&json!({"v": 1, "id": "1f", "reject": "denied"})).is_ok());
    }

    #[test]
    fn a_reply_with_an_unknown_reject_code_is_refused() {
        for bad in [json!("Denied"), json!("timeout"), json!(""), json!(1)] {
            assert_eq!(
                parse(&json!({"v": 1, "id": "1f", "reject": bad})),
                Err(BridgeRefusal::UnknownReject)
            );
        }
        assert!(parse(&json!({"v": 1, "id": "1f", "reject": "limit"})).is_ok());
    }

    #[test]
    fn a_reply_off_the_envelope_is_refused() {
        assert_eq!(
            parse(&json!({"v": 1, "id": "1f", "ok": []})),
            Err(BridgeRefusal::MalformedOk)
        );
        assert_eq!(
            parse(&json!({"v": 1, "id": "1f", "ok": null})),
            Err(BridgeRefusal::MalformedOk)
        );
        assert_eq!(
            parse(&json!({"v": 1, "id": "1f", "ok": {}, "event": "x"})),
            Err(BridgeRefusal::UnknownField)
        );
        for text in ["", "[]", "{", "1", "\"x\""] {
            assert_eq!(
                parse_reply(text, &outstanding()),
                Err(BridgeRefusal::Malformed)
            );
        }
    }

    #[test]
    fn a_reply_past_the_ceiling_is_refused_and_one_at_it_is_read() {
        let head = r#"{"v":1,"id":"1f","ok":{"s":""#;
        let tail = r#""}}"#;
        let fill = BRIDGE_MAX_REPLY_BYTES - head.len() - tail.len();
        let at = format!("{head}{}{tail}", "a".repeat(fill));
        assert_eq!(at.len(), BRIDGE_MAX_REPLY_BYTES);
        assert!(parse_reply(&at, &outstanding()).is_ok());
        let past = format!("{head}{}{tail}", "a".repeat(fill + 1));
        assert_eq!(
            parse_reply(&past, &outstanding()),
            Err(BridgeRefusal::TooLarge)
        );
    }

    #[test]
    fn a_request_id_outside_the_grammar_is_refused() {
        for bad in ["", "A", "g", "-1", "12345678901234567"] {
            assert_eq!(RequestId::new(bad), Err(BridgeRefusal::BadId));
        }
        assert!(RequestId::new("1234567890abcdef").is_ok());
        assert_eq!(
            BridgeRequest::new(id(HELLO_ID), BridgeCall::PushCurrent),
            Err(BridgeRefusal::BadId)
        );
        assert_eq!(
            BridgeRequest::new(id("1"), BridgeCall::Hello),
            Err(BridgeRefusal::BadId)
        );
    }

    fn show(title: usize, body: usize, tag: &str) -> Result<BridgeRequest, BridgeRefusal> {
        BridgeRequest::new(
            id("2"),
            BridgeCall::NotificationShow {
                title: "t".repeat(title),
                body: "b".repeat(body),
                tag: tag.to_owned(),
            },
        )
    }

    #[test]
    fn a_notification_field_past_its_ceiling_is_refused() {
        let tag_at = "a".repeat(NOTIFICATION_TAG_MAX_BYTES);
        assert!(
            show(
                NOTIFICATION_TITLE_MAX_BYTES,
                NOTIFICATION_BODY_MAX_BYTES,
                &tag_at
            )
            .is_ok()
        );
        assert!(show(0, 0, "A-z_0.9").is_ok());
        for refused in [
            show(NOTIFICATION_TITLE_MAX_BYTES + 1, 0, ""),
            show(0, NOTIFICATION_BODY_MAX_BYTES + 1, ""),
            show(0, 0, &format!("{tag_at}a")),
            show(0, 0, "a b"),
            show(0, 0, "a/b"),
            show(0, 0, "\u{e9}"),
        ] {
            assert_eq!(refused, Err(BridgeRefusal::BadField));
        }
    }

    #[test]
    fn a_request_past_the_ceiling_is_refused_and_one_at_it_encodes() {
        let encoded_len = |key: &str| {
            BridgeRequest::new(
                id("3"),
                BridgeCall::PushSubscribe {
                    application_key: key.to_owned(),
                },
            )
            .and_then(|request| request.encode())
            .map(|text| text.len())
        };
        let base = encoded_len("");
        assert!(base.is_ok(), "{base:?}");
        let at = "k".repeat(BRIDGE_MAX_REQUEST_BYTES - base.unwrap_or_default());
        assert_eq!(encoded_len(&at), Ok(BRIDGE_MAX_REQUEST_BYTES));
        assert_eq!(encoded_len(&format!("{at}k")), Err(BridgeRefusal::TooLarge));
    }

    #[test]
    fn the_bridged_caps_match_the_compiler_vocabulary() {
        let ours: Vec<&str> = BridgeCap::ALL.iter().map(|cap| cap.as_str()).collect();
        let compiler: Vec<&str> = ipe_kernels::BridgeCap::ALL
            .iter()
            .map(|cap| cap.as_str())
            .collect();
        assert_eq!(ours, compiler);
        assert!(!ours.contains(&HANDSHAKE_CAP_NAME));
    }

    #[test]
    fn the_mirrored_ceilings_equal_the_runtime_ones() {
        assert_eq!(BRIDGE_MAX_OUTSTANDING, crate::js_port::MAX_OUTSTANDING);
        assert_eq!(BRIDGE_REPLY_DEADLINE_MS, crate::js_port::REQUEST_TIMEOUT_MS);
        assert_eq!(
            BRIDGE_MAX_REPLY_BYTES,
            crate::seal_codec::DEFAULT_SEAL_MAX_INPUT_BYTES
        );
    }

    /// What a mock shell answers.
    #[derive(Clone, Copy)]
    enum Answer {
        Grant,
        Refuse,
        Reject(Reject),
    }

    /// The call a test sends for each operation.
    fn call_for(op: BridgeOp) -> BridgeCall {
        match op {
            BridgeOp::Hello => BridgeCall::Hello,
            BridgeOp::NotificationPermission => BridgeCall::NotificationPermission,
            BridgeOp::NotificationRequest => BridgeCall::NotificationRequest,
            BridgeOp::NotificationShow => BridgeCall::NotificationShow {
                title: "Ready".to_owned(),
                body: "The build finished".to_owned(),
                tag: "build.done".to_owned(),
            },
            BridgeOp::PushSubscribe => BridgeCall::PushSubscribe {
                application_key: "BPk".to_owned(),
            },
            BridgeOp::PushCurrent => BridgeCall::PushCurrent,
            BridgeOp::PushUnsubscribe => BridgeCall::PushUnsubscribe,
        }
    }

    /// A shell in pure Rust: reads one request text and answers it.
    ///
    /// It holds the shell side of the protocol: the version, the closed cap/op
    /// set, the request ceiling and the field ceilings, each refused with the
    /// matching code.
    fn mock_shell(request: &str, answer: Answer) -> String {
        let reply = |id: &Value, outcome: (&str, Value)| {
            let mut fields = serde_json::Map::new();
            fields.insert("v".to_owned(), json!(BRIDGE_PROTOCOL_VERSION));
            fields.insert("id".to_owned(), id.clone());
            fields.insert(outcome.0.to_owned(), outcome.1);
            Value::Object(fields).to_string()
        };
        let reject = |id: &Value, code: Reject| reply(id, ("reject", json!(code.as_str())));
        let parsed: Value = serde_json::from_str(request).unwrap_or(Value::Null);
        let id = parsed.get("id").cloned().unwrap_or(Value::Null);
        if request.len() > BRIDGE_MAX_REQUEST_BYTES {
            return reject(&id, Reject::Limit);
        }
        if parsed.get("v") != Some(&json!(BRIDGE_PROTOCOL_VERSION)) {
            return reject(&id, Reject::Version);
        }
        let op = match (
            parsed.get("cap").and_then(Value::as_str),
            parsed.get("op").and_then(Value::as_str),
        ) {
            (Some(cap), Some(op)) => BridgeOp::from_wire(cap, op),
            _ => None,
        };
        let Some(op) = op else {
            return reject(&id, Reject::Refused);
        };
        let args = parsed.get("args").cloned().unwrap_or(Value::Null);
        let text = |key: &str| args.get(key).and_then(Value::as_str).unwrap_or_default();
        if op == BridgeOp::NotificationShow
            && (text("title").len() > NOTIFICATION_TITLE_MAX_BYTES
                || text("body").len() > NOTIFICATION_BODY_MAX_BYTES
                || !is_notification_tag(text("tag")))
        {
            return reject(&id, Reject::Refused);
        }
        let state = |granted: bool| {
            let state = if granted {
                PermissionState::Granted
            } else {
                PermissionState::Denied
            };
            json!({"state": state.as_str()})
        };
        let ok = match (op, answer) {
            (_, Answer::Reject(code)) => return reject(&id, code),
            (BridgeOp::Hello, _) => {
                let caps: Vec<&str> = BridgeCap::ALL.iter().map(|cap| cap.as_str()).collect();
                json!({"v": BRIDGE_PROTOCOL_VERSION, "caps": caps})
            }
            (BridgeOp::NotificationPermission | BridgeOp::NotificationRequest, answer) => {
                state(matches!(answer, Answer::Grant))
            }
            (BridgeOp::PushSubscribe, _) | (BridgeOp::PushCurrent, Answer::Grant) => {
                json!({"subscription": "sub-text"})
            }
            (BridgeOp::PushCurrent, Answer::Refuse) => json!({"subscription": null}),
            (BridgeOp::NotificationShow | BridgeOp::PushUnsubscribe, _) => json!({}),
        };
        reply(&id, ("ok", ok))
    }

    /// One round trip: encode `op`'s request, let the mock shell answer, parse the reply.
    fn round_trip(op: BridgeOp, answer: Answer) -> Result<BridgeReply, BridgeRefusal> {
        let request_id = if op == BridgeOp::Hello {
            id(HELLO_ID)
        } else {
            id("a1")
        };
        let request = BridgeRequest::new(request_id.clone(), call_for(op))?;
        let text = request.encode()?;
        parse_reply(&mock_shell(&text, answer), &[request_id])
    }

    #[test]
    fn every_op_answered_by_the_mock_shell_reads_as_its_ipe_value() {
        for &op in BridgeOp::ALL {
            for answer in [Answer::Grant, Answer::Refuse] {
                let reply = round_trip(op, answer);
                assert!(
                    matches!(reply, Ok(BridgeReply::Ok { .. })),
                    "{op:?}: {reply:?}"
                );
                let Ok(reply) = reply else { return };
                let expected = match (op, answer) {
                    (
                        BridgeOp::NotificationPermission | BridgeOp::NotificationRequest,
                        Answer::Grant,
                    ) => Some(NotificationFrame::Granted),
                    (BridgeOp::NotificationPermission | BridgeOp::NotificationRequest, _) => {
                        Some(NotificationFrame::Denied)
                    }
                    (BridgeOp::NotificationShow, _) => Some(NotificationFrame::Shown),
                    (
                        BridgeOp::Hello
                        | BridgeOp::PushSubscribe
                        | BridgeOp::PushCurrent
                        | BridgeOp::PushUnsubscribe,
                        _,
                    ) => None,
                };
                assert_eq!(notification_frame(op, &reply), expected, "{op:?}");
                let BridgeReply::Ok { payload, .. } = reply else {
                    return;
                };
                match op {
                    BridgeOp::Hello => {
                        assert_eq!(payload.get("v"), Some(&json!(BRIDGE_PROTOCOL_VERSION)));
                        let caps = payload.get("caps").and_then(Value::as_array);
                        let names = caps.map(|caps| {
                            caps.iter()
                                .filter_map(Value::as_str)
                                .filter_map(BridgeCap::from_wire)
                                .count()
                        });
                        assert_eq!(names, Some(BridgeCap::ALL.len()));
                    }
                    BridgeOp::PushSubscribe => {
                        assert_eq!(payload.get("subscription"), Some(&json!("sub-text")));
                    }
                    BridgeOp::PushCurrent => {
                        let expected = match answer {
                            Answer::Grant => json!("sub-text"),
                            Answer::Refuse | Answer::Reject(_) => Value::Null,
                        };
                        assert_eq!(payload.get("subscription"), Some(&expected));
                    }
                    BridgeOp::NotificationPermission
                    | BridgeOp::NotificationRequest
                    | BridgeOp::NotificationShow
                    | BridgeOp::PushUnsubscribe => {}
                }
            }
        }
    }

    #[test]
    fn every_reject_from_the_mock_shell_reads_as_its_ipe_value() {
        for &op in BridgeOp::ALL {
            for &code in Reject::ALL {
                let reply = round_trip(op, Answer::Reject(code));
                assert!(reply.is_ok(), "{op:?} {code:?}: {reply:?}");
                let Ok(reply) = reply else { return };
                assert_eq!(
                    reply,
                    BridgeReply::Rejected {
                        id: reply.id().clone(),
                        reject: code
                    }
                );
                let expected = match op.cap() {
                    Some(BridgeCap::Notification) => Some(if code == Reject::Denied {
                        NotificationFrame::Denied
                    } else {
                        NotificationFrame::Unavailable
                    }),
                    Some(BridgeCap::Push) | None => None,
                };
                assert_eq!(notification_frame(op, &reply), expected, "{op:?} {code:?}");
            }
        }
        let kinds: Vec<BridgeErrorKind> = Reject::ALL.iter().map(|r| r.error_kind()).collect();
        assert_eq!(
            kinds,
            [
                BridgeErrorKind::PermissionDenied,
                BridgeErrorKind::Unavailable,
                BridgeErrorKind::Unavailable,
                BridgeErrorKind::InvalidInput,
                BridgeErrorKind::LimitExceeded,
                BridgeErrorKind::Unavailable,
            ]
        );
    }

    #[test]
    fn the_mock_shell_refuses_an_envelope_off_the_protocol() {
        let outstanding = [id("5")];
        let answer = |request: &Value| {
            parse_reply(
                &mock_shell(&request.to_string(), Answer::Grant),
                &outstanding,
            )
        };
        let rejected = |code| {
            Ok(BridgeReply::Rejected {
                id: id("5"),
                reject: code,
            })
        };
        assert_eq!(
            answer(&json!({"v": 2, "id": "5", "cap": "push", "op": "current", "args": {}})),
            rejected(Reject::Version)
        );
        assert_eq!(
            answer(&json!({"v": 1, "id": "5", "cap": "push", "op": "show", "args": {}})),
            rejected(Reject::Refused)
        );
        assert_eq!(
            answer(
                &json!({"v": 1, "id": "5", "cap": "notification", "op": "show",
                "args": {"title": "", "body": "", "tag": "a b"}})
            ),
            rejected(Reject::Refused)
        );
        assert!(matches!(
            answer(&json!({"v": 1, "id": "5", "cap": "push", "op": "current", "args": {}})),
            Ok(BridgeReply::Ok { .. })
        ));
    }

    #[test]
    fn a_permission_reply_off_its_payload_reads_unavailable() {
        let outstanding = [id("6")];
        let reply = parse_reply(r#"{"v":1,"id":"6","ok":{"state":"maybe"}}"#, &outstanding);
        assert!(reply.is_ok(), "{reply:?}");
        let Ok(reply) = reply else { return };
        assert_eq!(
            notification_frame(BridgeOp::NotificationRequest, &reply),
            Some(NotificationFrame::Unavailable)
        );
    }
}
