//! Property-based tests for the Ipê Rust runtime.
#![cfg(not(target_arch = "wasm32"))]

use ipe_runtime_rust::*;
use proptest::prelude::*;

// ═══════════════════════════════════════════════════════════════════
// Core types — direct from the runtime
// ═══════════════════════════════════════════════════════════════════

proptest! {
    #[test]
    fn result_with_default_ok(def: i64, x: i64) {
        let r: IpeResult<&str, i64> = IpeResult::Ok(x);
        prop_assert_eq!(result_with_default(def, r), x);
    }

    #[test]
    fn result_with_default_err(def: i64, s: String) {
        let r: IpeResult<String, i64> = IpeResult::Err(s);
        prop_assert_eq!(result_with_default(def, r), def);
    }

    #[test]
    fn result_map_id(x: i64) {
        let r: IpeResult<&str, i64> = IpeResult::Ok(x);
        let mapped = ipe_result_map(r, |v| v);
        prop_assert_eq!(mapped, IpeResult::Ok(x));
    }

    #[test]
    fn maybe_map_id(x: i64) {
        let m: IpeMaybe<i64> = IpeMaybe::Just(x);
        let mapped = ipe_maybe_map(m, |v| v);
        prop_assert_eq!(mapped, IpeMaybe::Just(x));
    }
}

// ═══════════════════════════════════════════════════════════════════
// String operations
// ═══════════════════════════════════════════════════════════════════

proptest! {
    #[test]
    fn string_length_appends(a: String, b: String) {
        let ab = string_append(a.clone(), b.clone());
        prop_assert_eq!(string_length(ab), string_length(a) + string_length(b));
    }

    #[test]
    fn string_reverse_involution(s: String) {
        let rev = string_reverse(s.clone());
        prop_assert_eq!(string_reverse(rev), s);
    }

    #[test]
    fn string_trim_noop_on_plain(s: String) {
        let plain: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        let trimmed = string_trim(plain.clone());
        prop_assert_eq!(trimmed, plain);
    }

    #[test]
    fn string_to_int_roundtrip(n: i64) {
        let s = string_from_int(n);
        let parsed = string_to_int(s);
        prop_assert_eq!(parsed, IpeMaybe::Just(n));
    }
}

// ═══════════════════════════════════════════════════════════════════
// Task combinators (require tokio feature)
// ═══════════════════════════════════════════════════════════════════

#[cfg(feature = "tokio")]
mod task_tests {
    use ipe_runtime_rust::*;

    fn run<A: Send + 'static>(task: IpeTask<IpeError, A>) -> IpeResult<IpeError, A> {
        task_run(task)
    }

    /// Set `key` through the Ipê `System.setenv` kernel (the runtime's env overlay).
    fn setenv(key: &str, val: &str) {
        assert!(run(system_setenv::<IpeError>(key.to_string(), val.to_string())).is_ok());
    }

    /// Unset `key` through the Ipê `System.unsetenv` kernel (the runtime's env overlay).
    fn unsetenv(key: &str) {
        assert!(run(system_unsetenv::<IpeError>(key.to_string())).is_ok());
    }

    fn mk_task<A: Send + 'static>(a: A) -> IpeTask<IpeError, A> {
        ipe_runtime_rust::task::task_succeed::<IpeError, A>(a)
    }

    #[test]
    fn task_succeed_ok() {
        assert_eq!(run(mk_task(42)), IpeResult::Ok(42));
    }

    #[test]
    fn task_map_ok() {
        let f = |x: i64| x + 1;
        assert_eq!(run(task_map(f, mk_task(41))), IpeResult::Ok(42));
    }

    #[test]
    fn task_and_then_ok() {
        let f = |x: i64| mk_task(x * 2);
        assert_eq!(run(task_and_then(mk_task(21), f)), IpeResult::Ok(42));
    }

    #[test]
    fn task_fail_is_err() {
        let err: IpeError = str_err("boom");
        let t: IpeTask<IpeError, i64> = ipe_runtime_rust::task::task_fail::<IpeError, i64>(err);
        assert!(run(t).is_err());
    }

    // `System.getenv : String -> Task Error String`. Regression guard: it MUST
    // return a `IpeTask` (not a bare `String`), or it fails to type-check in any
    // `Task.andThen`/`Task.run` position — and an unset var MUST short-circuit
    // with `Err` (matching the `System_getenv` ErrNotFound), not `Ok("")`,
    // so a chained Task fails identically on both backends.
    #[test]
    fn system_getenv_present_is_ok() {
        setenv("IPE_TEST_GETENV_PRESENT", "hello");
        let t: IpeTask<IpeError, String> =
            system_getenv::<IpeError>("IPE_TEST_GETENV_PRESENT".to_string());
        assert_eq!(run(t), IpeResult::Ok("hello".to_string()));
    }

    #[test]
    fn system_getenv_unset_is_err() {
        unsetenv("IPE_TEST_GETENV_UNSET_XYZ_42");
        let t: IpeTask<IpeError, String> =
            system_getenv::<IpeError>("IPE_TEST_GETENV_UNSET_XYZ_42".to_string());
        assert!(run(t).is_err());
    }

    /// `System.getenv` and `getenvOr` never answer a temp-root key, even one
    /// the program set itself with `System.setenv`: the temp root is resolved
    /// only by the scratch primitive.
    #[test]
    fn system_getenv_refuses_temp_root_keys() {
        for key in ["TMPDIR", "TMP", "TEMP", "tmpdir"] {
            let set: IpeTask<IpeError, ()> =
                system_setenv::<IpeError>(key.to_string(), "/attacker/base".to_string());
            assert!(run(set).is_ok(), "{key:?}");
            let got: IpeTask<IpeError, String> = system_getenv::<IpeError>(key.to_string());
            assert!(run(got).is_err(), "{key:?}");
            assert_eq!(
                system_getenv_or(key.to_string(), "fallback".to_string()),
                "fallback",
                "{key:?}"
            );
        }
    }

    // System.getenvInt / getenvBool / getArg — golden-verified semantics (unset → Err
    // NotFound; non-int / non-bool → Err Ffi; getArg indexes the FULL arg vector
    // and is out-of-range → Ok Nothing, never Err).
    #[test]
    fn system_getenv_int_ok_and_errs() {
        setenv("IPE_TEST_INT_OK", "42");
        setenv("IPE_TEST_INT_BAD", "abc");
        unsetenv("IPE_TEST_INT_UNSET");
        assert_eq!(
            run(system_getenv_int::<IpeError>("IPE_TEST_INT_OK".to_string())),
            IpeResult::Ok(42)
        );
        assert!(
            run(system_getenv_int::<IpeError>(
                "IPE_TEST_INT_BAD".to_string()
            ))
            .is_err()
        );
        assert!(
            run(system_getenv_int::<IpeError>(
                "IPE_TEST_INT_UNSET".to_string()
            ))
            .is_err()
        );
    }

    #[test]
    fn system_getenv_bool_truthy_falsy_unset() {
        setenv("IPE_TEST_BOOL_T", "yes");
        setenv("IPE_TEST_BOOL_F", "0");
        setenv("IPE_TEST_BOOL_BAD", "maybe");
        unsetenv("IPE_TEST_BOOL_UNSET");
        assert_eq!(
            run(system_getenv_bool::<IpeError>(
                "IPE_TEST_BOOL_T".to_string()
            )),
            IpeResult::Ok(true)
        );
        assert_eq!(
            run(system_getenv_bool::<IpeError>(
                "IPE_TEST_BOOL_F".to_string()
            )),
            IpeResult::Ok(false)
        );
        assert!(
            run(system_getenv_bool::<IpeError>(
                "IPE_TEST_BOOL_BAD".to_string()
            ))
            .is_err()
        );
        assert!(
            run(system_getenv_bool::<IpeError>(
                "IPE_TEST_BOOL_UNSET".to_string()
            ))
            .is_err()
        );
    }

    #[test]
    fn system_get_arg_in_and_out_of_range() {
        // index 0 is the program name (the test binary) — always present.
        assert!(matches!(
            run(system_get_arg::<IpeError>(0)),
            IpeResult::Ok(IpeMaybe::Just(_))
        ));
        assert_eq!(
            run(system_get_arg::<IpeError>(9999)),
            IpeResult::Ok(IpeMaybe::Nothing)
        );
        assert_eq!(
            run(system_get_arg::<IpeError>(-1)),
            IpeResult::Ok(IpeMaybe::Nothing)
        );
    }
}

// ═══════════════════════════════════════════════════════════════════
// JSON encode/decode (require json feature)
// ═══════════════════════════════════════════════════════════════════

#[cfg(feature = "json")]
mod json_tests {
    use ipe_runtime_rust::*;

    #[test]
    fn json_int_roundtrip() {
        let json = ipe_runtime_rust::json::json_enc_int(42);
        let encoded = ipe_runtime_rust::json::json_enc_encode(0, json);
        let decoder: Decoder<IpeError, i64> = ipe_runtime_rust::json::json_decode_int();
        let decoded = ipe_runtime_rust::json::decode_from_json_string(decoder, encoded);
        assert_eq!(decoded, IpeResult::Ok(42));
    }

    #[test]
    fn json_string_roundtrip() {
        let json = ipe_runtime_rust::json::json_enc_string("hello".to_string());
        let encoded = ipe_runtime_rust::json::json_enc_encode(0, json);
        let decoder: Decoder<IpeError, String> = ipe_runtime_rust::json::json_decode_string();
        let decoded = ipe_runtime_rust::json::decode_from_json_string(decoder, encoded);
        assert_eq!(decoded, IpeResult::Ok("hello".to_string()));
    }

    #[test]
    fn json_bool_roundtrip() {
        let json = ipe_runtime_rust::json::json_enc_bool(true);
        let encoded = ipe_runtime_rust::json::json_enc_encode(0, json);
        let decoder: Decoder<IpeError, bool> = ipe_runtime_rust::json::json_decode_bool();
        let decoded = ipe_runtime_rust::json::decode_from_json_string(decoder, encoded);
        assert_eq!(decoded, IpeResult::Ok(true));
    }
}

// ═══════════════════════════════════════════════════════════════════
// Standalone tests (not property-based, but useful signals)
// ═══════════════════════════════════════════════════════════════════

#[test]
fn string_is_empty_true() {
    assert!(string_is_empty(String::new()));
}

#[test]
fn string_to_int_fails_on_bad_input() {
    assert_eq!(string_to_int("not a number".to_string()), IpeMaybe::Nothing);
}

#[test]
fn string_to_lower_upper_consistent() {
    let s = "Hello World".to_string();
    let upper = string_to_upper(s.clone());
    let lower_upper = string_to_lower(upper);
    let lower = string_to_lower(s);
    assert_eq!(lower_upper, lower);
}

// ═══════════════════════════════════════════════════════════════════
// Byte-sequence FFI coercion helpers
// ═══════════════════════════════════════════════════════════════════

proptest! {
    // to_u8_vec then widen back is identity on in-range bytes.
    #[test]
    fn byte_vec_roundtrip(xs in proptest::collection::vec(0u8..=255, 0..64)) {
        let as_i64: Vec<i64> = xs.iter().map(|&b| i64::from(b)).collect();
        prop_assert_eq!(to_u8_vec(&as_i64), xs.clone());
        prop_assert_eq!(from_u8_slice(&xs), as_i64);
    }

    // to_u8_array succeeds iff the input length matches N; never panics.
    #[test]
    fn to_u8_array_len_checked(xs in proptest::collection::vec(0i64..256, 0..40)) {
        let r: IpeResult<String, [u8; 16]> = to_u8_array(&xs);
        if xs.len() == 16 {
            prop_assert!(r.is_ok());
        } else {
            prop_assert!(r.is_err());
        }
    }

    /// `to_array` succeeds exactly when input length matches N, never panics.
    #[test]
    fn to_array_len_checked(xs in proptest::collection::vec(proptest::prelude::any::<i64>(), 0..16usize)) {
        const N: usize = 8;
        let result: IpeResult<IpeError, [i64; N]> = to_array::<IpeError, i64, N>(&xs);
        if xs.len() == N {
            prop_assert!(matches!(result, IpeResult::Ok(_)));
            if let IpeResult::Ok(arr) = result {
                for i in 0..N {
                    prop_assert_eq!(arr[i], xs[i]);
                }
            }
        } else {
            prop_assert!(matches!(result, IpeResult::Err(_)));
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// Ipe.Email SMTP transport (require email feature) — deterministic error
// paths. The positive path (delivery to a local SMTP catcher) is verified
// out-of-band; here we lock in that the lettre-backed send_smtp is TOTAL:
// bad config / bad address surface a clean Err, never a panic.
// ═══════════════════════════════════════════════════════════════════

#[cfg(feature = "email")]
mod email_smtp_tests {
    use ipe_runtime_rust::*;

    fn addr(s: &str) -> EmailAddress {
        // Tests use known-valid addresses; construct directly via the private
        // field to avoid the parse overhead.  In production Ipê source, the
        // ONLY path is `parseAddress`.
        match email_address_parse(s.to_owned()) {
            IpeMaybe::Just(a) => a,
            IpeMaybe::Nothing => panic!("test helper: {:?} is not a valid address", s),
        }
    }

    fn msg(from: &str) -> EmailMessage {
        let from_addr = addr(from);
        EmailMessage {
            from: from_addr.clone(),
            to: vec![addr("rcpt@example.com")],
            cc: vec![],
            bcc: vec![],
            subject: "s".to_string(),
            textBody: "b".to_string(),
            htmlBody: String::new(),
            attachments: vec![],
            replyTo: from_addr,
        }
    }

    #[test]
    fn smtp_empty_host_is_err() {
        let cfg = SmtpConfig {
            host: String::new(),
            port: 0,
            user: String::new(),
            pass: secret_from_string(String::new()),
        };
        let t = email_send::<IpeError>(EmailProvider::Smtp(cfg), msg("a@b.com"));
        assert!(task_run(t).is_err());
    }

    #[test]
    fn smtp_unreachable_host_is_err() {
        // Port 2599 on localhost is (almost certainly) not listening;
        // the send must fail rather than hang.
        let cfg = SmtpConfig {
            host: "127.0.0.1".to_string(),
            port: 2599,
            user: String::new(),
            pass: secret_from_string(String::new()),
        };
        let t = email_send::<IpeError>(EmailProvider::Smtp(cfg), msg("a@b.com"));
        assert!(task_run(t).is_err());
    }
}
