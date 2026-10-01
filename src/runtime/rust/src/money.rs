//! Ipe.Money kernels — currency table + format / rate registry / allocate.
//!
//!
//! The Ipê-side `Money` ADT carries a typed `Currency` enum + a `Decimal`
//! amount. At the Ffi boundary, the wrappers in `ipe-stdlib/Std/Money.ipe`
//! convert the Currency into its ISO 4217 code (a String) before calling
//! these kernels — so every function below takes the code as a plain String.

use super::{Decimal, IpeMaybe, IpeResult};
use rust_decimal::Decimal as RD;
use rust_decimal::RoundingStrategy;
use rust_decimal::prelude::ToPrimitive;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

// ── Currency table ─────────────────────────────────────────────────

/// One row of the ISO 4217 / cryptocurrency lookup table.
struct CurrencyInfo {
    minor_units: u32,
    symbol: &'static str,
    name: &'static str,
}

fn lookup_currency(code: &str) -> Option<CurrencyInfo> {
    let c = code.trim().to_uppercase();
    let (minor_units, symbol, name) = match c.as_str() {
        "USD" => (2u32, "$", "US Dollar"),
        "EUR" => (2, "€", "Euro"),
        "GBP" => (2, "£", "British Pound"),
        "JPY" => (0, "¥", "Japanese Yen"),
        "CNY" => (2, "¥", "Chinese Yuan"),
        "AUD" => (2, "A$", "Australian Dollar"),
        "CAD" => (2, "C$", "Canadian Dollar"),
        "CHF" => (2, "Fr.", "Swiss Franc"),
        "HKD" => (2, "HK$", "Hong Kong Dollar"),
        "SGD" => (2, "S$", "Singapore Dollar"),
        "NZD" => (2, "NZ$", "New Zealand Dollar"),
        "SEK" => (2, "kr", "Swedish Krona"),
        "NOK" => (2, "kr", "Norwegian Krone"),
        "DKK" => (2, "kr", "Danish Krone"),
        "PLN" => (2, "zł", "Polish Złoty"),
        "CZK" => (2, "Kč", "Czech Koruna"),
        "HUF" => (2, "Ft", "Hungarian Forint"),
        "RON" => (2, "lei", "Romanian Leu"),
        "BGN" => (2, "лв", "Bulgarian Lev"),
        "TRY" => (2, "₺", "Turkish Lira"),
        "ZAR" => (2, "R", "South African Rand"),
        "BRL" => (2, "R$", "Brazilian Real"),
        "MXN" => (2, "$", "Mexican Peso"),
        "ARS" => (2, "$", "Argentine Peso"),
        "CLP" => (0, "$", "Chilean Peso"),
        "INR" => (2, "₹", "Indian Rupee"),
        "PKR" => (2, "₨", "Pakistani Rupee"),
        "BDT" => (2, "৳", "Bangladeshi Taka"),
        "LKR" => (2, "₨", "Sri Lankan Rupee"),
        "NPR" => (2, "₨", "Nepalese Rupee"),
        "KRW" => (0, "₩", "South Korean Won"),
        "TWD" => (2, "NT$", "Taiwan Dollar"),
        "THB" => (2, "฿", "Thai Baht"),
        "VND" => (0, "₫", "Vietnamese Đồng"),
        "PHP" => (2, "₱", "Philippine Peso"),
        "IDR" => (2, "Rp", "Indonesian Rupiah"),
        "MYR" => (2, "RM", "Malaysian Ringgit"),
        "AED" => (2, "د.إ", "UAE Dirham"),
        "SAR" => (2, "﷼", "Saudi Riyal"),
        "QAR" => (2, "﷼", "Qatari Riyal"),
        "KWD" => (3, "د.ك", "Kuwaiti Dinar"),
        "BHD" => (3, "ب.د", "Bahraini Dinar"),
        "OMR" => (3, "﷼", "Omani Rial"),
        "JOD" => (3, "د.أ", "Jordanian Dinar"),
        "ILS" => (2, "₪", "Israeli Shekel"),
        "EGP" => (2, "ج.م", "Egyptian Pound"),
        "NGN" => (2, "₦", "Nigerian Naira"),
        "KES" => (2, "Sh", "Kenyan Shilling"),
        "GHS" => (2, "₵", "Ghanaian Cedi"),
        "MAD" => (2, "د.م.", "Moroccan Dirham"),
        "TND" => (3, "د.ت", "Tunisian Dinar"),
        "DZD" => (2, "د.ج", "Algerian Dinar"),
        "RUB" => (2, "₽", "Russian Ruble"),
        "UAH" => (2, "₴", "Ukrainian Hryvnia"),
        "BTC" => (8, "₿", "Bitcoin"),
        "ETH" => (18, "Ξ", "Ether"),
        "USDT" => (6, "₮", "Tether"),
        "USDC" => (6, "$", "USD Coin"),
        _ => return None,
    };
    Some(CurrencyInfo {
        minor_units,
        symbol,
        name,
    })
}

/// "Is this a known ISO 4217 / crypto code?" — used by `money_is_known_currency`.
fn is_known(code: &str) -> bool {
    lookup_currency(code).is_some()
}

// ── Property kernels ───────────────────────────────────────────────

#[must_use]
pub fn money_minor_units(code: String) -> i64 {
    match lookup_currency(&code) {
        Some(c) => i64::from(c.minor_units),
        None => 2,
    }
}

#[must_use]
pub fn money_symbol(code: String) -> String {
    let upper = code.trim().to_uppercase();
    match lookup_currency(&upper) {
        Some(c) => c.symbol.to_string(),
        None => upper,
    }
}

#[must_use]
pub fn money_currency_name(code: String) -> String {
    let upper = code.trim().to_uppercase();
    match lookup_currency(&upper) {
        Some(c) => c.name.to_string(),
        None => upper,
    }
}

#[must_use]
pub fn money_is_known_currency(code: String) -> bool {
    is_known(&code)
}

/// Every ISO 4217 / crypto code the runtime currency table recognises.
///
/// This is the canonical enumeration of the `lookup_currency` match arms.
/// External consumers (tests, the `Money_allCodes` kernel) use this function
/// as the single source of truth for the full code set — asserting that the
/// Ipê-side enum, `currencyCode`, `parseCurrency`, and `knownCurrency` all
/// cover exactly this set.
#[must_use]
pub fn money_all_codes() -> Vec<String> {
    [
        "USD", "EUR", "GBP", "JPY", "CNY", "AUD", "CAD", "CHF", "HKD", "SGD", "NZD", "SEK", "NOK",
        "DKK", "PLN", "CZK", "HUF", "RON", "BGN", "TRY", "ZAR", "BRL", "MXN", "ARS", "CLP", "INR",
        "PKR", "BDT", "LKR", "NPR", "KRW", "TWD", "THB", "VND", "PHP", "IDR", "MYR", "AED", "SAR",
        "QAR", "KWD", "BHD", "OMR", "JOD", "ILS", "EGP", "NGN", "KES", "GHS", "MAD", "TND", "DZD",
        "RUB", "UAH", "BTC", "ETH", "USDT", "USDC",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

// ── Format kernels ─────────────────────────────────────────────────

/// `format : Code -> Decimal -> String` — "$12.34" / "-$12.34".
#[must_use]
pub fn money_format(code: String, amount: Decimal) -> String {
    let upper = code.trim().to_uppercase();
    let (minor, symbol) = match lookup_currency(&upper) {
        Some(c) => (c.minor_units, c.symbol.to_string()),
        None => (2, upper.clone()),
    };
    let neg = amount.0.is_sign_negative();
    let abs = if neg { -amount.0 } else { amount.0 };
    // Pre-ROUND to the target minor units before formatting. `format!("{:.*}")`
    // over a raw Decimal TRUNCATES when precision < scale (rust_decimal
    // `to_str_internal`), so "12.345" at 2dp would render "12.34". Use
    // HALF-AWAY-FROM-ZERO so "2.545" → "2.55".
    let rounded = abs.round_dp_with_strategy(minor, RoundingStrategy::MidpointAwayFromZero);
    let fixed = format!("{:.*}", minor as usize, rounded);
    if neg {
        format!("-{symbol}{fixed}")
    } else {
        format!("{symbol}{fixed}")
    }
}

/// `formatWithCode : Code -> Decimal -> String` — "12.34 USD" for B2B output.
#[must_use]
pub fn money_format_with_code(code: String, amount: Decimal) -> String {
    let upper = code.trim().to_uppercase();
    let minor = match lookup_currency(&upper) {
        Some(c) => c.minor_units,
        None => 2,
    };
    // Pre-ROUND (half-away-from-zero) before formatting so the raw Decimal is
    // not truncated when its scale exceeds the currency's minor units.
    let rounded = amount
        .0
        .round_dp_with_strategy(minor, RoundingStrategy::MidpointAwayFromZero);
    format!("{:.*} {}", minor as usize, rounded, upper)
}

// ── FX rate registry ───────────────────────────────────────────────

fn rates() -> &'static Mutex<HashMap<(String, String), RD>> {
    static RATES: OnceLock<Mutex<HashMap<(String, String), RD>>> = OnceLock::new();
    RATES.get_or_init(|| Mutex::new(HashMap::new()))
}

/// `setRate : Code -> Code -> Decimal -> Result Error ()`.
/// Negative or zero rate → error. Inverse auto-registered.
#[must_use]
pub fn money_set_rate<E: From<String>>(
    from: String,
    to: String,
    rate: Decimal,
) -> IpeResult<E, ()> {
    // Reject absurd codes (real ISO-4217 / crypto tickers are ≤ ~5 chars; 16 is
    // generous) so the registry key can't be a memory-amplification vector.
    const MAX_CODE_LEN: usize = 16;
    // Bound the registry: distinct (from,to) pairs would otherwise accumulate
    // without limit (memory-DoS). Updating an existing pair is always allowed.
    const MAX_RATES: usize = 4096;
    if rate.0.is_zero() || rate.0.is_sign_negative() {
        return IpeResult::Err("Money.setRate: rate must be positive".to_string().into());
    }
    let from = from.trim().to_uppercase();
    let to = to.trim().to_uppercase();
    if from.len() > MAX_CODE_LEN || to.len() > MAX_CODE_LEN {
        return IpeResult::Err("Money.setRate: currency code too long".to_string().into());
    }
    let mut map = rates()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if map.len() >= MAX_RATES && !map.contains_key(&(from.clone(), to.clone())) {
        return IpeResult::Err("Money.setRate: rate registry is full".to_string().into());
    }
    map.insert((from.clone(), to.clone()), rate.0);
    // Auto-inverse so consumers don't need both directions.
    // Use checked_div: the zero-guard above makes this impossible in normal
    // operation, but a subnormal or denormal Decimal could still produce None —
    // skip the auto-inverse rather than panic.
    if let Some(inv) = RD::from(1).checked_div(rate.0) {
        // Honour MAX_RATES for the auto-inverse too: when the map is at capacity
        // and the reverse pair does not already exist, skip the inverse insert so
        // the registry can never exceed MAX_RATES (was +1 per near-full pair).
        if map.len() < MAX_RATES || map.contains_key(&(to.clone(), from.clone())) {
            // Cap the auto-inverse to 16 decimal places. Without the cap a
            // non-terminating inverse (e.g. 1/3) would carry rust_decimal's
            // full mantissa precision, producing more digits than a caller
            // would expect for a rate derived from its reciprocal.
            map.insert(
                (to, from),
                inv.round_dp_with_strategy(16, RoundingStrategy::MidpointAwayFromZero),
            );
        }
    }
    IpeResult::Ok(())
}

/// `getRate : Code -> Code -> Result Error Decimal`.
/// from == to returns 1.0; else looks up. Missing → Err.
#[must_use]
pub fn money_get_rate<E: From<String>>(from: String, to: String) -> IpeResult<E, Decimal> {
    let from = from.trim().to_uppercase();
    let to = to.trim().to_uppercase();
    if from == to {
        return IpeResult::Ok(Decimal(RD::from(1)));
    }
    let map = rates()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match map.get(&(from.clone(), to.clone())) {
        Some(r) => IpeResult::Ok(Decimal(*r)),
        None => IpeResult::Err(format!("Money.getRate: no rate registered for {from}→{to}").into()),
    }
}

/// `hasRate : Code -> Code -> Bool`.
#[must_use]
pub fn money_has_rate(from: String, to: String) -> bool {
    let from = from.trim().to_uppercase();
    let to = to.trim().to_uppercase();
    if from == to {
        return true;
    }
    let map = rates()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    map.contains_key(&(from, to))
}

/// `clearRates : () -> Result Error ()` — test/admin only.
/// The compiled-source `Ipe.Money.clearRates` is a point-free `Kernel.kernel`
/// alias of type `() -> Result Error ()`, so the emit passes a unit argument
/// (matching the arity-1 unit-kernel convention, e.g. `uuid_v4(_: ())`).
#[must_use]
pub fn money_clear_rates<E: From<String>>(_: ()) -> IpeResult<E, ()> {
    let mut map = rates()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    map.clear();
    IpeResult::Ok(())
}

// ── Allocate (fair split with residue distributed early) ───────────

/// `allocate : Int -> Int -> Decimal -> List Decimal`.
/// Work in minor units (integer) to avoid rounding drift, then shift back.
/// First `remainder` slots receive (base + 1), the rest receive `base`.
///
/// Uses `checked_mul`/`checked_div`/`checked_add`/`checked_sub` on every
/// `rust_decimal` operation that is reachable from caller-controlled `Decimal`
/// inputs — the bare operators panic on overflow, which is the same bug class
/// as an `unwrap`. On overflow (astronomically large amounts or exotic `places`
/// values) the function returns an empty Vec rather than panicking; normal
/// monetary amounts (< 10^15 major units) are unaffected.
#[must_use]
pub fn money_allocate(places: i64, parts: i64, amount: Decimal) -> Vec<Decimal> {
    if parts <= 0 {
        return Vec::new();
    }
    let places = places.max(0) as u32;
    // Shift to minor units (× 10^places). `10_i64.checked_pow` guards i64
    // overflow for extreme `places` values (≥ 19). On None we saturate to
    // i64::MAX — the scale still fits in Decimal, and the trunc() below will
    // produce a very large number whose allocate output is still correct (the
    // `checked_*` chain below catches any subsequent overflow).
    let factor = 10_i64.checked_pow(places).unwrap_or(i64::MAX);
    let scale = RD::from(factor);
    // checked_mul: amount × scale. Overflow → empty (no panic).
    let total_minor = match amount.0.checked_mul(scale) {
        Some(v) => v.trunc(),
        None => return Vec::new(),
    };
    let parts_dec = RD::from(parts);
    // checked_div: total_minor / parts. parts > 0 guard above makes zero
    // impossible in normal flow, but Decimal can still return None for edge
    // cases (e.g. NaN-like states from saturated inputs).
    let base = match total_minor.checked_div(parts_dec) {
        Some(v) => v.trunc(),
        None => return Vec::new(),
    };
    // checked_mul + checked_sub: base × parts and total_minor − that.
    let Some(base_times_parts) = base.checked_mul(parts_dec) else {
        return Vec::new();
    };
    let Some(remainder) = total_minor.checked_sub(base_times_parts) else {
        return Vec::new();
    };
    // `remainder` is integer-VALUED (both operands were `.trunc()`'d) but its
    // Decimal scale may be > 0, so `to_string()` can render "3.00" — which
    // `parse::<i64>()` then REJECTS, silently dropping the remainder pennies and
    // mis-distributing the allocation. Convert via the numeric `to_i64()` (scale-
    // independent) instead of a string round-trip. (Audit finding: correctness.)
    // Distribute the residue TOWARD ZERO by sign. A `.max(0)` would drop the
    // residue entirely for a NEGATIVE total → the shares would no longer sum to
    // the input. For a negative remainder, |rem_int| early slots get
    // `base - 1` (more negative); for positive, `base + 1` — either way the shares
    // sum back to the exact input.
    let rem_int = remainder.trunc().to_i64().unwrap_or(0);
    // saturating_abs (not `unsigned_abs() as i64`): for the theoretical
    // rem_int == i64::MIN edge, `unsigned_abs() as i64` wraps back to i64::MIN
    // (negative), making the `i < extra_slots` loop never fire and silently
    // dropping the entire residue. saturating_abs yields i64::MAX (harmlessly
    // large given the parts ≤ 100k bound below).
    let extra_slots = rem_int.saturating_abs();
    let step: i64 = if rem_int < 0 { -1 } else { 1 };
    let inv_scale = RD::from(factor);
    // Bound the share count: `parts` is caller-controlled; a huge value both
    // allocates a large Vec (≈16 bytes/Decimal) and runs the checked-Decimal loop
    // once per slot — a per-call amplification vector. A "fair split" of money
    // realistically tops out in the thousands; 100k is already extravagant, so cap
    // there to cut the worst-case allocation + loop work 10× vs the prior 1e6 bound.
    if parts > 100_000 {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(parts as usize);
    for i in 0..parts {
        // base ± 1 (toward zero by sign) for the first |remainder| slots.
        let share = if i < extra_slots {
            match base.checked_add(RD::from(step)) {
                Some(v) => v,
                None => return Vec::new(),
            }
        } else {
            base
        };
        // checked_div: shift back to major units (÷ 10^places).
        match share.checked_div(inv_scale) {
            Some(v) => out.push(Decimal(v)),
            None => return Vec::new(),
        }
    }
    out
}

// Silence unused-warning on IpeMaybe import (kept for symmetry with sibling kernels).
#[allow(dead_code)]
fn _unused_ipemaybe<T>() -> IpeMaybe<T> {
    IpeMaybe::Nothing
}

#[cfg(test)]
#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::*;
    use rust_decimal::Decimal as RD;
    use std::str::FromStr;

    fn d(s: &str) -> Decimal {
        Decimal(RD::from_str(s).unwrap())
    }

    // Serialise tests that mutate the process-global fx-rate registry
    // (`rates()`). cargo runs tests in parallel, so without this guard one
    // test's clear/set lands mid-assertion in another and the round-trip
    // flakes. Poison-tolerant: a panic in one rate test must not wedge the
    // next via an unwrap on a poisoned lock.
    fn rate_test_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[test]
    fn test_allocate_negative_total_shares_sum_to_input() {
        // CORRECTNESS regression: a NEGATIVE total must still have its residue
        // distributed (the old `.max(0)` dropped it → shares summed to -99.99).
        let shares = money_allocate(2, 3, d("-100.00"));
        assert_eq!(shares.len(), 3);
        let sum: RD = shares.iter().fold(RD::from(0), |acc, s| acc + s.0);
        assert_eq!(
            sum,
            RD::from_str("-100.00").unwrap(),
            "negative shares must sum to the input"
        );
        // Residue lands on the first slot, toward zero by sign (more negative).
        assert_eq!(shares[0].0, RD::from_str("-33.34").unwrap());
    }

    #[test]
    fn test_allocate_distributes_remainder_pennies() {
        // 100.00 / 3 at 2 places → [33.34, 33.33, 33.33], summing to 100.00.
        // The remainder penny MUST land on the first share — the old
        // `to_string().parse::<i64>()` rendered the remainder as "1.00" and
        // failed to parse, dropping it (shares would sum to 99.99).
        let shares = money_allocate(2, 3, d("100.00"));
        assert_eq!(shares.len(), 3);
        assert_eq!(shares[0].0, RD::from_str("33.34").unwrap());
        assert_eq!(shares[1].0, RD::from_str("33.33").unwrap());
        assert_eq!(shares[2].0, RD::from_str("33.33").unwrap());
        let sum: RD = shares.iter().fold(RD::from(0), |acc, s| acc + s.0);
        assert_eq!(sum, RD::from_str("100.00").unwrap());
    }

    #[test]
    fn test_money_format_rounds_half_away_from_zero() {
        // CORRECTNESS: format must pre-ROUND to the currency's minor units
        // (half-away-from-zero), NOT truncate.
        // "2.545" at 2dp → "2.55" (truncation would give "2.54").
        assert_eq!(money_format("USD".into(), d("2.545")), "$2.55");
        assert_eq!(money_format_with_code("USD".into(), d("2.545")), "2.55 USD");
        // 12.345 → 12.35 (was 12.34 under truncation).
        assert_eq!(money_format("USD".into(), d("12.345")), "$12.35");
        // Negative ties round away from zero in magnitude: -2.545 → -$2.55.
        assert_eq!(money_format("USD".into(), d("-2.545")), "-$2.55");
        // JPY has 0 minor units: 2.5 → 3 (half-away-from-zero).
        assert_eq!(money_format("JPY".into(), d("2.5")), "¥3");
    }

    #[test]
    fn test_money_minor_units() {
        assert_eq!(money_minor_units("USD".into()), 2);
        assert_eq!(money_minor_units("JPY".into()), 0);
        assert_eq!(money_minor_units("BHD".into()), 3);
        assert_eq!(money_minor_units("BTC".into()), 8);
        // Unknown code → fallback to 2
        assert_eq!(money_minor_units("XYZ".into()), 2);
    }

    #[test]
    fn test_money_symbol_and_name() {
        assert_eq!(money_symbol("USD".into()), "$");
        assert_eq!(money_symbol("EUR".into()), "€");
        assert_eq!(money_symbol("xyz".into()), "XYZ");
        assert_eq!(money_currency_name("USD".into()), "US Dollar");
        assert_eq!(money_currency_name("XYZ".into()), "XYZ");
    }

    #[test]
    fn test_money_is_known() {
        assert!(money_is_known_currency("USD".into()));
        assert!(money_is_known_currency("usd".into()));
        assert!(!money_is_known_currency("XYZ".into()));
    }

    #[test]
    fn test_money_format() {
        assert_eq!(money_format("USD".into(), d("12.34")), "$12.34");
        assert_eq!(money_format("USD".into(), d("-12.34")), "-$12.34");
        assert_eq!(money_format("JPY".into(), d("1234")), "¥1234");
        // Unknown code → fallback to code as symbol
        assert_eq!(money_format("XYZ".into(), d("100")), "XYZ100.00");
    }

    #[test]
    fn test_money_format_with_code() {
        assert_eq!(
            money_format_with_code("USD".into(), d("12.34")),
            "12.34 USD"
        );
        assert_eq!(money_format_with_code("jpy".into(), d("1234")), "1234 JPY");
        // BHD has 3 minor units
        assert_eq!(
            money_format_with_code("BHD".into(), d("1.234")),
            "1.234 BHD"
        );
    }

    #[test]
    fn test_money_rates_roundtrip() {
        let _guard = rate_test_lock();
        // Clear any rates from prior tests
        let _: IpeResult<String, ()> = money_clear_rates(());
        // Set USD->EUR = 0.9; auto-registers EUR->USD ≈ 1.111
        let _: IpeResult<String, ()> = money_set_rate("USD".into(), "EUR".into(), d("0.9"));
        assert!(money_has_rate("USD".into(), "EUR".into()));
        assert!(money_has_rate("EUR".into(), "USD".into()));
        let r: IpeResult<String, Decimal> = money_get_rate("USD".into(), "EUR".into());
        match r {
            IpeResult::Ok(v) => assert_eq!(v.0.to_string(), "0.9"),
            IpeResult::Err(_) => panic!("getRate USD->EUR failed"),
        }
        // Identity
        let r2: IpeResult<String, Decimal> = money_get_rate("USD".into(), "USD".into());
        if let IpeResult::Ok(v) = r2 {
            assert_eq!(v.0, RD::from(1));
        } else {
            panic!("identity rate failed");
        }
        // Missing
        let r3: IpeResult<String, Decimal> = money_get_rate("USD".into(), "XYZ".into());
        assert!(matches!(r3, IpeResult::Err(_)));
    }

    #[test]
    fn test_money_set_rate_negative_rejected() {
        let _guard = rate_test_lock();
        let _: IpeResult<String, ()> = money_clear_rates(());
        let r: IpeResult<String, ()> = money_set_rate("USD".into(), "EUR".into(), d("-1"));
        assert!(matches!(r, IpeResult::Err(_)));
        let r: IpeResult<String, ()> = money_set_rate("USD".into(), "EUR".into(), d("0"));
        assert!(matches!(r, IpeResult::Err(_)));
    }

    #[test]
    fn test_money_allocate_three_ways() {
        // $100.00 split 1:1:1 → [33.34, 33.33, 33.33], sum = 100.00
        let parts = money_allocate(2, 3, d("100"));
        assert_eq!(parts.len(), 3);
        // Sum must equal input exactly (no drift).
        let sum: RD = parts.iter().map(|p| p.0).sum();
        assert_eq!(sum, RD::from_str("100.00").unwrap());
        // First slot carries the extra cent.
        assert_eq!(parts[0].0, RD::from_str("33.34").unwrap());
        assert_eq!(parts[1].0, RD::from_str("33.33").unwrap());
        assert_eq!(parts[2].0, RD::from_str("33.33").unwrap());
    }

    #[test]
    fn test_money_allocate_zero_parts() {
        assert!(money_allocate(2, 0, d("100")).is_empty());
    }

    /// `money_all_codes` is the SSOT for the runtime currency table.
    /// Every code must round-trip through `is_known` and be free of duplicates.
    #[test]
    fn money_all_codes_complete_and_unique() {
        let codes = money_all_codes();
        assert_eq!(codes.len(), 58, "expected 58 known currency codes");

        // No duplicates.
        let mut seen = std::collections::HashSet::new();
        for code in &codes {
            assert!(seen.insert(code.as_str()), "duplicate code: {code}");
        }

        // Every listed code is recognised by `is_known`.
        for code in &codes {
            assert!(
                is_known(code),
                "code {code} in money_all_codes but not in lookup_currency"
            );
        }
    }

    /// An unrecognised code is rejected at every gate.
    #[test]
    fn money_unknown_code_rejected() {
        let unknown = "XYZ";
        assert!(!is_known(unknown));
        assert!(!money_is_known_currency(unknown.to_string()));
        assert!(lookup_currency(unknown).is_none());
    }
}
