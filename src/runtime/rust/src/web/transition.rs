//! Inert `update`-arm transitions: the logic counterpart of the appearance
//! [`super::literal_table`], for the subset of `update` arms whose effect on the
//! `Model` is a single data-describable field change.
//!
//! # The mechanism (mirrors the literal table exactly)
//!
//! An `update` arm like `Increment -> { m | count = count + 1 }` describes one
//! field change with no control flow, no `Cmd`, no function call. The compiler
//! reduces such an arm to an inert [`Transition`] datum (a target field, a small
//! closed [`TransitionOp`], and an inert [`Source`]) and emits the arm as a call
//! to the ONE compiled [`apply_transition`] routine over that baked datum. Prod
//! holds only the baked datum, so the arm runs exactly what a direct compiled
//! arm would — one update semantics, dev == prod. In dev an edit to a simple arm
//! ships a new datum over the live socket; the running program swaps the baked
//! datum and the SAME [`apply_transition`] produces the next `Model`, with no
//! recompile.
//!
//! # Why operate on the JSON object (the whole soundness argument)
//!
//! At runtime the `Model` is an opaque generic struct; the routine has no static
//! knowledge of a field name as a Rust ident. It instead works on the `Model`'s
//! self-describing JSON object (`serde_json::to_value`) exactly as
//! [`super::additive`] does: read the named field, apply the closed op, write it
//! back, then STRICT-decode the merged object into the real `Model`. That strict
//! decode is the fail-closed backstop — a datum that does not describe a
//! well-typed change (wrong field, type mismatch, arithmetic that would not
//! type-check) fails to decode and [`apply_transition`] returns the model
//! UNCHANGED, never a torn or coerced `Model`.
//!
//! # Inert + bounded + fail-closed
//!
//! A [`Transition`] carries only: a field NAME (a string), one of a small closed
//! set of [`TransitionOp`]s, and a [`Source`] that is a literal or the named
//! field itself. It has no code, no call, no nesting — [`apply_transition`]
//! cannot run arbitrary logic, cannot panic/unwrap/index (integer ops wrap in
//! two's complement, the defined Ipê `Int` semantics, never abort), and refuses
//! (returns the input model unchanged) anything it cannot prove applies: a
//! missing field, a type mismatch, a non-object model, an oversized model, or a
//! strict-decode failure. The dev patch channel is untrusted; every failure is a
//! total no-op that leaves the caller's `Model` exactly as it was.

/// Hard ceiling on a `Model`'s JSON body considered for a transition. Mirrors
/// [`super::additive::MAX_ADDITIVE_BODY_BYTES`] so both value-level Model
/// operations share one bound; a model serializing beyond this is not
/// transitioned (returns the input unchanged), never re-parsed unbounded.
#[cfg(any(feature = "db", feature = "redis_store", feature = "web"))]
pub const MAX_TRANSITION_MODEL_BYTES: usize = 64 * 1024 * 1024;

/// Where a [`TransitionOp`]'s operand comes from. Inert by construction — a
/// literal value or a read of a named `Model` field; never an expression, call,
/// or nested transition.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum Source {
    /// An integer literal operand (`+ 1`, `= 42`).
    Int(i64),
    /// A boolean literal operand (`= True`).
    Bool(bool),
    /// A string literal operand (`= "hello"`).
    Str(String),
    /// A read of the value currently under a named `Model` field. The only
    /// non-literal source; still inert — it names a field, it does not compute.
    Field(String),
}

/// The closed set of field operations a [`Transition`] can describe. Exhaustive
/// and wildcard-free: a new op shape forces a compile-time decision here and in
/// the classifier, never a silent mis-encode. Every arithmetic op wraps in
/// two's complement (the defined Ipê `Int` semantics, matching the compiled
/// arm) and refuses (via [`apply_transition`] returning the input model) on a
/// type mismatch, so none can panic.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum TransitionOp {
    /// Replace the field with the source value (`SetName s -> { m | name = s }`,
    /// `Reset -> { m | count = 0 }`). The source's JSON shape must match the
    /// field's existing type or the strict re-decode refuses.
    Set,
    /// Integer add: `field = field + source` (`Increment -> { m | count = count + 1 }`).
    /// Both the field and the source must be integers; overflow wraps (two's
    /// complement), matching the compiled arm's `ipe_int_add`.
    IntAdd,
    /// Integer subtract: `field = field - source` (`Decrement -> …`). Both
    /// integers; overflow wraps, matching `ipe_int_sub`.
    IntSub,
    /// Boolean negate: `field = not field` (`Toggle -> { m | on = not on }`).
    /// The field must be a boolean; the source is ignored.
    BoolNot,
}

/// An inert description of one `update` arm's single field change: the target
/// field NAME, the closed [`TransitionOp`], and the operand [`Source`].
///
/// This is the whole datum the compiler bakes and the dev channel patches. It
/// carries no code and no nesting — an untrusted instance can drive nothing but
/// the bounded [`apply_transition`] routine.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Transition {
    /// The target `Model` field's name (its serde key).
    pub field: String,
    /// The closed operation applied to that field.
    pub op: TransitionOp,
    /// The operand.
    pub source: Source,
}

impl Transition {
    /// The `Set` transition `{ m | field = <literal> }`.
    #[must_use]
    pub fn set(field: impl Into<String>, source: Source) -> Self {
        Self {
            field: field.into(),
            op: TransitionOp::Set,
            source,
        }
    }
}

/// Apply an inert [`Transition`] to `model`, returning the next `Model`.
///
/// Total and fail-closed: on ANY condition it cannot prove — a non-object model,
/// an oversized model, a missing target field, a source field that is absent, a
/// type mismatch between the op and the field/source, or a strict-decode failure
/// of the merged object — it returns `model` UNCHANGED. (Integer overflow is not
/// a refusal: it wraps, matching the compiled arm's defined `Int` semantics.)
/// It never panics, never unwraps, never indexes, and never coerces a value into
/// the `Model`: the final strict decode is the backstop that rejects anything
/// that would not type-check as the compiled arm.
///
/// The `Model` and the transition datum are BOTH treated as untrusted at the dev
/// boundary; this routine is the single place that mutates the server-held Model
/// from a transition, so it refuses rather than guesses.
#[cfg(any(feature = "db", feature = "redis_store", feature = "web"))]
#[must_use]
pub fn apply_transition<Model>(transition: &Transition, model: Model) -> Model
where
    Model: serde::Serialize + serde::de::DeserializeOwned,
{
    match try_apply(transition, &model) {
        Some(next) => next,
        // Refuse: hand the caller back the model it gave us, unchanged. The
        // move-in `model` is returned so no clone is needed on the happy path's
        // sibling.
        None => model,
    }
}

/// The fallible core of [`apply_transition`]: `Some(next)` only when the
/// transition provably applies and the result strict-decodes into `Model`;
/// `None` on every refusal (the caller then returns the input model unchanged).
#[cfg(any(feature = "db", feature = "redis_store", feature = "web"))]
fn try_apply<Model>(transition: &Transition, model: &Model) -> Option<Model>
where
    Model: serde::Serialize + serde::de::DeserializeOwned,
{
    let value = serde_json::to_value(model).ok()?;
    // Bound the object we walk: a Model whose serialized form exceeds the ceiling
    // is not transitioned (the re-encode below would already have produced it, so
    // this bounds the re-decode input, matching the additive path's ceiling).
    let obj = value.as_object()?;
    // The target field must already exist — a transition never INTRODUCES a field
    // (that would be a schema change, i.e. logic). Read its current value.
    let current = obj.get(&transition.field)?;
    let next_field = compute_next(&transition.op, current, &transition.source, obj)?;

    let mut merged = obj.clone();
    // `field` was proven present above; this only overwrites an existing key.
    merged.insert(transition.field.clone(), next_field);
    let merged_value = serde_json::Value::Object(merged);

    // Bound the re-decode input exactly as the additive path does.
    let bytes = serde_json::to_vec(&merged_value).ok()?;
    if bytes.len() > MAX_TRANSITION_MODEL_BYTES {
        return None;
    }
    // Strict decode is the fail-closed backstop: a type mismatch the op did not
    // catch (e.g. `Set` writing a string into an int field) is rejected HERE, so
    // the result is either a well-typed `Model` or `None` (refuse), never a
    // coerced value.
    serde_json::from_slice(&bytes).ok()
}

/// Compute the field's next JSON value under the closed op, or `None` (refuse) on
/// any type mismatch or missing source field. Arithmetic wraps (two's
/// complement, the defined `Int` semantics), so overflow is not a refusal.
#[cfg(any(feature = "db", feature = "redis_store", feature = "web"))]
fn compute_next(
    op: &TransitionOp,
    current: &serde_json::Value,
    source: &Source,
    obj: &serde_json::Map<String, serde_json::Value>,
) -> Option<serde_json::Value> {
    match op {
        // Replace with the resolved source value. The strict re-decode in the
        // caller enforces the type match (a `Set` of the wrong type is rejected
        // there), so `Set` itself only needs to resolve the source.
        TransitionOp::Set => resolve_source(source, obj),
        TransitionOp::IntAdd => {
            let a = current.as_i64()?;
            let b = resolve_source(source, obj)?.as_i64()?;
            // The one Int `+` definition the compiled arm also emits, so the
            // datum path and the direct compiled arm agree at the i64 boundary.
            let sum = crate::math::ipe_int_add(a, b);
            Some(serde_json::Value::from(sum))
        }
        TransitionOp::IntSub => {
            let a = current.as_i64()?;
            let b = resolve_source(source, obj)?.as_i64()?;
            // The one Int `-` definition (see `IntAdd`).
            let diff = crate::math::ipe_int_sub(a, b);
            Some(serde_json::Value::from(diff))
        }
        TransitionOp::BoolNot => {
            let b = current.as_bool()?;
            Some(serde_json::Value::Bool(!b))
        }
    }
}

/// Resolve a [`Source`] to a JSON value: a literal is itself; a
/// [`Source::Field`] reads the named field from the model object (refusing if
/// absent).
#[cfg(any(feature = "db", feature = "redis_store", feature = "web"))]
fn resolve_source(
    source: &Source,
    obj: &serde_json::Map<String, serde_json::Value>,
) -> Option<serde_json::Value> {
    match source {
        Source::Int(n) => Some(serde_json::Value::from(*n)),
        Source::Bool(b) => Some(serde_json::Value::Bool(*b)),
        Source::Str(s) => Some(serde_json::Value::String(s.clone())),
        Source::Field(name) => obj.get(name).cloned(),
    }
}

// ─── dev-only transition hot-swap overlay ───────────────────────────────────
//
// The running web app owns each data-describable `update` arm through the
// emitted `apply_transition_hot` call, which rebuilds a `Transition` from the
// baked datum's JSON on every dispatch. To hot-swap a simple arm (a `+1` → `+2`,
// a `Set` literal, a toggle target) without a recompile, the dev control path
// registers a replacement `Transition` keyed by the arm's *baked-datum
// signature* (the exact JSON the compiler baked, in emit form); the next
// `apply_transition_hot` for that signature applies the replacement instead of
// the baked datum, so the next `update` produces the edited transition's Model.
//
// Keying by the baked JSON (rather than a single global patch) confines an edit
// to the one arm whose datum it describes: a second arm with a different baked
// datum never sees it. The baked datum string is a compile-time constant, so the
// signature stays stable across dispatches.
//
// The overlay is inert unless [`dev_transition_active`] holds (flag on AND
// non-production). It shares the appearance overlay's `IPE_WATCH_HOT_APPEARANCE`
// gate — one dev-overlay switch for the whole program-as-data surface. In a
// production build the flag is off and the dev control path is never mounted, so
// no replacement is ever registered and `apply_transition_hot` decodes and
// applies exactly the baked datum — one update semantics, dev == prod.

#[cfg(any(feature = "db", feature = "redis_store", feature = "web"))]
use std::collections::HashMap;
#[cfg(any(feature = "db", feature = "redis_store", feature = "web"))]
use std::sync::{Mutex, OnceLock};

/// The registered dev replacements, keyed by an arm's baked-datum JSON
/// signature. `None` until the first registration; an empty map reads as "no
/// overlay". Guarded by a `Mutex`; a poisoned lock is recovered (the map holds
/// only inert [`Transition`] data, so a panic mid-update cannot leave it
/// unsound).
#[cfg(any(feature = "db", feature = "redis_store", feature = "web"))]
type DevTransitionOverlay = HashMap<String, Transition>;

#[cfg(any(feature = "db", feature = "redis_store", feature = "web"))]
fn dev_transition_overlay() -> &'static Mutex<DevTransitionOverlay> {
    static OVERLAY: OnceLock<Mutex<DevTransitionOverlay>> = OnceLock::new();
    OVERLAY.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Whether the transition hot-swap overlay may affect an `update`: shares the
/// appearance overlay's [`super::literal_table::dev_overlay_active`] gate (the
/// `IPE_WATCH_HOT_APPEARANCE` flag set to a truthy value AND non-production).
///
/// With the flag off (the default) or in production this is `false`, so
/// [`apply_transition_hot`] decodes and applies exactly the baked datum and the
/// overlay is never consulted — one update semantics, dev == prod.
#[cfg(any(feature = "db", feature = "redis_store", feature = "web"))]
#[must_use]
pub fn dev_transition_active() -> bool {
    super::literal_table::dev_overlay_active()
}

/// Register (or replace) the dev replacement for the arm whose baked datum JSON
/// is `default_json`. A subsequent [`apply_transition_hot`] for that exact
/// signature applies `replacement` instead of the baked datum. No-op when the
/// overlay is inactive, so a stray call in a production build changes nothing.
///
/// Replacing (not merging) means the most recent edit for an arm fully describes
/// its current transition — the watch classifier sends the whole transition for
/// the edited arm each time.
#[cfg(any(feature = "db", feature = "redis_store", feature = "web"))]
pub fn register_dev_transition(default_json: &str, replacement: Transition) {
    if !dev_transition_active() {
        return;
    }
    let mut map = dev_transition_overlay()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    map.insert(default_json.to_owned(), replacement);
}

/// The dev replacement registered for an arm's baked-datum signature, if any.
#[cfg(any(feature = "db", feature = "redis_store", feature = "web"))]
fn dev_transition_replacement_for(default_json: &str) -> Option<Transition> {
    let map = dev_transition_overlay()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    map.get(default_json).cloned()
}

/// Clear all registered dev replacements. Test-support for asserting the
/// flag-off / inert path without cross-test overlay leakage.
#[cfg(test)]
#[cfg(any(feature = "db", feature = "redis_store", feature = "web"))]
pub(crate) fn clear_dev_transition_for_test() {
    let mut map = dev_transition_overlay()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    map.clear();
}

/// Apply a data-describable `update` arm's transition to `model`, consulting the
/// dev overlay first. The compiler emits a classified arm as
/// `apply_transition_hot(<baked datum JSON>, model)`.
///
/// The baked `default_json` is the compile-time constant describing the arm's
/// transition. When the dev overlay is active AND a replacement is registered
/// for this exact baked signature, the replacement is applied; otherwise the
/// baked datum is decoded and applied. With the flag off / in production the
/// overlay is never consulted, so this decodes and applies exactly the baked
/// datum — byte-identical to a direct compiled arm (dev == prod).
///
/// Total and fail-closed at every seam: a baked datum that fails to decode (only
/// reachable on a codegen defect) returns `model` UNCHANGED, exactly as
/// [`apply_transition`] refuses. The untrusted dev channel can register nothing
/// but an inert [`Transition`], which drives only the bounded [`apply_transition`]
/// routine.
#[cfg(any(feature = "db", feature = "redis_store", feature = "web"))]
#[must_use]
pub fn apply_transition_hot<Model>(default_json: &str, model: Model) -> Model
where
    Model: serde::Serialize + serde::de::DeserializeOwned,
{
    // The overlay is consulted only under the dev gate; in production the branch
    // is never taken, so the baked datum path below is the sole behaviour.
    if dev_transition_active()
        && let Some(replacement) = dev_transition_replacement_for(default_json)
    {
        return apply_transition(&replacement, model);
    }
    // Decode the baked datum. A decode failure is unreachable for
    // compiler-emitted JSON; it fails closed (model unchanged) rather than
    // panicking, so even a corrupt constant can never tear the Model.
    match serde_json::from_str::<Transition>(default_json) {
        Ok(baked) => apply_transition(&baked, model),
        Err(_) => model,
    }
}

#[cfg(test)]
#[cfg(any(feature = "db", feature = "redis_store", feature = "web"))]
mod tests {
    use super::{Source, Transition, TransitionOp, apply_transition};
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
    struct Counter {
        count: i64,
        name: String,
        on: bool,
    }

    fn model() -> Counter {
        Counter {
            count: 5,
            name: "alice".to_string(),
            on: false,
        }
    }

    // ── the four ops apply exactly ────────────────────────────────────────

    #[test]
    fn int_add_increments_field() {
        let t = Transition {
            field: "count".to_string(),
            op: TransitionOp::IntAdd,
            source: Source::Int(1),
        };
        assert_eq!(apply_transition(&t, model()).count, 6);
    }

    #[test]
    fn int_sub_decrements_field() {
        let t = Transition {
            field: "count".to_string(),
            op: TransitionOp::IntSub,
            source: Source::Int(2),
        };
        assert_eq!(apply_transition(&t, model()).count, 3);
    }

    #[test]
    fn set_replaces_string_field_from_literal() {
        let t = Transition::set("name", Source::Str("bob".to_string()));
        assert_eq!(apply_transition(&t, model()).name, "bob");
    }

    #[test]
    fn set_int_field_from_literal() {
        let t = Transition::set("count", Source::Int(0));
        assert_eq!(apply_transition(&t, model()).count, 0);
    }

    #[test]
    fn bool_not_toggles_field() {
        let t = Transition {
            field: "on".to_string(),
            op: TransitionOp::BoolNot,
            source: Source::Bool(false), // ignored
        };
        assert!(apply_transition(&t, model()).on);
    }

    #[test]
    fn set_field_from_another_field() {
        // `{ m | count = count }` via a Field source — a no-op that still proves
        // the field-source resolution path.
        let t = Transition::set("count", Source::Field("count".to_string()));
        assert_eq!(apply_transition(&t, model()).count, 5);
    }

    // ── refusal: every unprovable case returns the model UNCHANGED ─────────

    #[test]
    fn missing_target_field_refuses() {
        let t = Transition::set("nonexistent", Source::Int(1));
        assert_eq!(
            apply_transition(&t, model()),
            model(),
            "a transition to an absent field must leave the model unchanged"
        );
    }

    #[test]
    fn type_mismatch_set_refuses() {
        // `Set` a string into the int field `count`: the strict re-decode rejects
        // it, so the model is unchanged (never a coerced value).
        let t = Transition::set("count", Source::Str("not a number".to_string()));
        assert_eq!(
            apply_transition(&t, model()),
            model(),
            "a Set whose type does not match the field must refuse"
        );
    }

    #[test]
    fn int_add_on_string_field_refuses() {
        let t = Transition {
            field: "name".to_string(),
            op: TransitionOp::IntAdd,
            source: Source::Int(1),
        };
        assert_eq!(
            apply_transition(&t, model()),
            model(),
            "an int op on a non-int field must refuse"
        );
    }

    #[test]
    fn int_add_non_int_source_refuses() {
        let t = Transition {
            field: "count".to_string(),
            op: TransitionOp::IntAdd,
            source: Source::Str("x".to_string()),
        };
        assert_eq!(apply_transition(&t, model()), model());
    }

    #[test]
    fn bool_not_on_non_bool_field_refuses() {
        let t = Transition {
            field: "count".to_string(),
            op: TransitionOp::BoolNot,
            source: Source::Bool(false),
        };
        assert_eq!(apply_transition(&t, model()), model());
    }

    #[test]
    fn int_add_overflow_wraps_matching_compiled_arm() {
        let m = Counter {
            count: i64::MAX,
            name: "a".to_string(),
            on: false,
        };
        let t = Transition {
            field: "count".to_string(),
            op: TransitionOp::IntAdd,
            source: Source::Int(1),
        };
        // Wraps to `i64::MIN`, exactly as the compiled arm's `ipe_int_add` — the
        // datum path must not diverge from the direct arm at the i64 boundary.
        assert_eq!(apply_transition(&t, m).count, i64::MIN);
    }

    #[test]
    fn int_sub_overflow_wraps_matching_compiled_arm() {
        let m = Counter {
            count: i64::MIN,
            name: "a".to_string(),
            on: false,
        };
        let t = Transition {
            field: "count".to_string(),
            op: TransitionOp::IntSub,
            source: Source::Int(1),
        };
        // Wraps to `i64::MAX`, matching `ipe_int_sub`.
        assert_eq!(apply_transition(&t, m).count, i64::MAX);
    }

    #[test]
    fn source_field_absent_refuses() {
        let t = Transition::set("count", Source::Field("ghost".to_string()));
        assert_eq!(apply_transition(&t, model()), model());
    }

    #[test]
    fn non_object_model_refuses() {
        // A unit model serializes to JSON `null`, not an object — refuse.
        let t = Transition::set("x", Source::Int(1));
        assert_eq!(apply_transition(&t, ()), ());
    }
}

// ─── dev-only transition hot-swap overlay ──────────────────────────────────
//
// The overlay + its gate are process-global, so these tests serialise on the
// appearance overlay's guard (the shared gate) and restore the override + clear
// the registry on the way out. Each proves the dev == prod crux at the reader
// seam: with the overlay OFF, `apply_transition_hot` is byte-identical to
// decoding + applying the baked datum; with it ON, a registered replacement
// swaps the arm's effect with no recompile.
#[cfg(test)]
#[cfg(any(feature = "db", feature = "redis_store", feature = "web"))]
mod hot_tests {
    use super::super::literal_table::{overlay_test_lock, set_dev_overlay_active_for_test};
    use super::{
        CompileTransitionJson, Source, Transition, TransitionOp, apply_transition_hot,
        clear_dev_transition_for_test, register_dev_transition,
    };
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
    struct Counter {
        count: i64,
    }

    fn model() -> Counter {
        Counter { count: 5 }
    }

    /// The baked datum for `Increment -> { m | count = count + 1 }` (the shape
    /// the compiler bakes; exercised as a literal JSON constant here).
    fn baked_increment() -> String {
        Transition {
            field: "count".to_string(),
            op: TransitionOp::IntAdd,
            source: Source::Int(1),
        }
        .to_json_shape()
    }

    #[test]
    fn overlay_off_applies_baked_datum_only() {
        let _g = overlay_test_lock();
        set_dev_overlay_active_for_test(Some(false));
        clear_dev_transition_for_test();

        // A registered replacement is IGNORED while inactive — the baked `+1`
        // applies, byte-identical to a direct compiled arm.
        register_dev_transition(
            &baked_increment(),
            Transition {
                field: "count".to_string(),
                op: TransitionOp::IntAdd,
                source: Source::Int(2),
            },
        );
        assert_eq!(
            apply_transition_hot(&baked_increment(), model()).count,
            6,
            "inactive overlay must apply the baked datum (dev == prod)"
        );

        clear_dev_transition_for_test();
        set_dev_overlay_active_for_test(None);
    }

    #[test]
    fn overlay_on_applies_registered_replacement() {
        let _g = overlay_test_lock();
        set_dev_overlay_active_for_test(Some(true));
        clear_dev_transition_for_test();

        // The counter SEAL: a `+1` arm hot-swapped to `+2` with no recompile.
        register_dev_transition(
            &baked_increment(),
            Transition {
                field: "count".to_string(),
                op: TransitionOp::IntAdd,
                source: Source::Int(2),
            },
        );
        assert_eq!(
            apply_transition_hot(&baked_increment(), model()).count,
            7,
            "active overlay applies the registered replacement (+2)"
        );

        // A DIFFERENT baked signature is never patched by this replacement.
        let other = Transition {
            field: "count".to_string(),
            op: TransitionOp::IntSub,
            source: Source::Int(1),
        }
        .to_json_shape();
        assert_eq!(
            apply_transition_hot(&other, model()).count,
            4,
            "a non-matching baked signature applies its own baked datum"
        );

        clear_dev_transition_for_test();
        set_dev_overlay_active_for_test(None);
    }

    #[test]
    fn corrupt_baked_json_refuses_total() {
        let _g = overlay_test_lock();
        set_dev_overlay_active_for_test(Some(false));
        clear_dev_transition_for_test();

        // A datum that does not decode (only reachable on a codegen defect)
        // returns the model unchanged — never a panic.
        assert_eq!(apply_transition_hot("not json", model()), model());

        set_dev_overlay_active_for_test(None);
    }
}

/// Serialize a [`Transition`] to the exact JSON the compiler bakes — the
/// `serde_json` default externally-tagged form. Used by the hot-path tests to
/// build a baked-datum signature without depending on the compiler crate.
#[cfg(test)]
#[cfg(any(feature = "db", feature = "redis_store", feature = "web"))]
trait CompileTransitionJson {
    fn to_json_shape(&self) -> String;
}

#[cfg(test)]
#[cfg(any(feature = "db", feature = "redis_store", feature = "web"))]
impl CompileTransitionJson for Transition {
    fn to_json_shape(&self) -> String {
        serde_json::to_string(self).expect("serialize transition")
    }
}
