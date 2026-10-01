//! Ipe.Uuid kernels — v4 / v7 / parse via the `uuid` crate.
//!
//! Module is `uuid_kernel` (not `uuid`) to avoid clashing with the `uuid`
//! crate; functions use the `::uuid::` extern path.
//!
//! # Entropy is an EFFECT, not a pure value
//!
//! `v4` / `v7` draw fresh entropy on every call, so they are typed on the
//! effect tier — `Ipe.Uuid.{v4,v7} : () -> Task Error String`, called
//! `Uuid.v4 ()` exactly like `Time.now ()` / `Crypto.randomToken n`. This makes
//! "entropy typed as a memoizable pure `String`" UNREPRESENTABLE: a pure
//! `String` is eligible for CSE / memoization / reordering, so two `Uuid.v4`
//! references could collapse to one shared value (the soundness lie a shared-ref implementation
//! backend still carries via its bare `Uuid.v4 : String` shape). The generation
//! runs INSIDE the returned future's body, so each `.run()` of the task
//! re-evaluates and yields a distinct id — proved by the `v4_two_runs_differ`
//! unit test here and the `uuid_distinct` E2E golden.
//!
//! `parse` stays PURE (`String -> Maybe String`): it inspects an existing
//! string with no entropy and no side effect — a genuine parser, not the
//! arity-0 codegen artifact.

use super::{IpeMaybe, IpeTask, ok_res};

/// Ipe.Uuid.v4 : () -> Task Error String
///
/// The random draw happens inside the future body so every `.run()` yields a
/// FRESH id — entropy is not memoizable. Bound is `E: From<String>` to match
/// the other entropy Tasks (`crypto_random_token`), so a discarded
/// `let _ = Uuid.v4 ()` auto-forces identically; generation itself never errors.
#[must_use]
pub fn uuid_v4<E: From<String> + Send + 'static>(_: ()) -> IpeTask<E, String> {
    Box::pin(async move { ok_res(::uuid::Uuid::new_v4().to_string()) })
}

/// Ipe.Uuid.v7 : () -> Task Error String  (time-ordered)
///
/// SECURITY: a v7 UUID embeds a millisecond timestamp and is SORTABLE/guessable
/// by design — it is NOT a secret. Use it for ordered ids, never as a bearer
/// token / session id / password-reset nonce (use `crypto_random_token` for
/// those). `v4` is random (getrandom/CSPRNG) but UUIDs are still only 122 bits of
/// formatted entropy — prefer `crypto_random_token` for security tokens.
/// (Audit finding: low — documented contract.)
#[must_use]
pub fn uuid_v7<E: From<String> + Send + 'static>(_: ()) -> IpeTask<E, String> {
    Box::pin(async move { ok_res(::uuid::Uuid::now_v7().to_string()) })
}

/// Ipe.Uuid.parse : String -> Maybe String  (canonicalise or Nothing)
///
/// PURE: no entropy, no effect — a real parser over an existing string. Kept off
/// the Task tier deliberately (it is not the arity-0 entropy artifact).
#[must_use]
pub fn uuid_parse(s: String) -> IpeMaybe<String> {
    match ::uuid::Uuid::parse_str(&s) {
        Ok(u) => IpeMaybe::Just(u.to_string()),
        Err(_) => IpeMaybe::Nothing,
    }
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;
    use crate::IpeResult;

    /// Run one entropy Task to completion, unwrapping the Ok payload. The error
    /// channel is `String` here (the tests never hit it — generation is total).
    async fn run(task: IpeTask<String, String>) -> String {
        match task.await {
            IpeResult::Ok(v) => v,
            IpeResult::Err(e) => panic!("uuid task errored unexpectedly: {e}"),
        }
    }

    #[tokio::test]
    async fn v4_shape_and_parse() {
        let id = run(uuid_v4(())).await;
        assert_eq!(id.len(), 36); // 8-4-4-4-12
        assert_eq!(&id[14..15], "4", "v4 version nibble");
        assert!(matches!(uuid_parse(id), IpeMaybe::Just(_)));
        assert!(matches!(
            uuid_parse("not-a-uuid".to_string()),
            IpeMaybe::Nothing
        ));
    }

    /// SOUNDNESS: two runs of a `Uuid.v4` Task yield DISTINCT ids. Entropy is an
    /// effect, not a memoizable pure value — if `v4` were typed `String` the
    /// optimizer could collapse two references into one shared value.
    #[tokio::test]
    async fn v4_two_runs_differ() {
        let a = run(uuid_v4(())).await;
        let b = run(uuid_v4(())).await;
        assert_ne!(a, b, "two Uuid.v4 runs must produce different ids");
    }

    #[tokio::test]
    async fn v7_is_valid_and_fresh() {
        let a = run(uuid_v7(())).await;
        let b = run(uuid_v7(())).await;
        assert_eq!(&a[14..15], "7", "v7 version nibble");
        assert!(matches!(uuid_parse(a.clone()), IpeMaybe::Just(_)));
        assert_ne!(a, b, "two Uuid.v7 runs must produce different ids");
    }
}
