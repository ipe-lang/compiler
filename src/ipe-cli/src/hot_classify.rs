//! The `ipe dev watch` appearance-hot-swap classifier.
//!
//! On a source edit under `IPE_WATCH_HOT_APPEARANCE`, the watch loop already has
//! the just-produced emit and the previous one. This module decides, from those
//! two emitted Rust projects alone, whether the edit is **`AppearanceOnly`**
//! (only hoisted style-literal *values* changed) or **Logic** (anything else). On
//! `AppearanceOnly` the loop POSTs a `LiteralTable` patch to the running app and
//! skips the cargo rebuild; on Logic it recompiles as usual.
//!
//! ## Why the emit is the ground truth
//!
//! The emitter is the single source of what the running program does. Diffing
//! the *emitted Rust* (not a hand-rolled AST diff that could drift from it) makes
//! the classification conservative by construction: a hoisted style literal is
//! the only thing that can differ between two emits while everything else stays
//! byte-identical, because that is exactly the transform the hoist performs
//! (`__ipe_lit.get(N)` reads are stable; only the baked
//! `LiteralTable::from_defaults(&[…])` default *values* move). Any other source
//! change — new structure, a conditional, a Model-dependent value, an `update`
//! edit — perturbs the emitted Rust somewhere other than a defaults array's
//! contents, or changes a defaults array's *length*, and forces `Logic`.
//!
//! ## The invariant
//!
//! **Unprovable ⇒ Logic ⇒ recompile.** `AppearanceOnly` is returned *only* when,
//! after masking every `from_defaults(&[…])` array's contents, the two emits are
//! byte-identical AND every corresponding array has the same length. Nothing
//! that touches control flow, structure, a handler, or the Model can satisfy
//! that, so a logic edit can never be misclassified as appearance. A false
//! `Logic` is merely a slow rebuild; a false `AppearanceOnly` would be a
//! correctness bug — so the bias is always toward `Logic`.

use ipe_backend::EmittedProject;

/// The patch for one edited view.
///
/// Carries the running app's *current* baked-defaults signature (which keys the
/// runtime overlay — the app is not recompiled, so it still bakes these values)
/// plus the `(index, new_value)` deltas to apply.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ViewPatch {
    /// The PREVIOUS baked defaults, in emit order. This is the signature the
    /// running app's compiled `view` passes to `from_defaults`, so it is the key
    /// the runtime overlay matches — send the old values, not the new.
    pub defaults: Vec<String>,
    /// The appearance delta: `(index, new_value)` for each changed default.
    pub patch: Vec<(usize, String)>,
}

/// A hot-swappable transition patch for one edited `update` arm.
///
/// The running app's compiled arm reads its baked datum through
/// `apply_transition_hot("<old_json>", model)`; the app is not recompiled, so it
/// still bakes `old_json`. The overlay is keyed by that exact baked string, so
/// the patch carries the OLD json (the key the running app matches) and the NEW
/// json (the edited transition to register).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TransitionPatch {
    /// The PREVIOUS baked datum JSON — the key the running app's compiled arm
    /// passes to `apply_transition_hot`, hence the overlay key. Send the OLD
    /// value, not the new.
    pub old_json: String,
    /// The edited transition's JSON — the replacement to register for `old_json`.
    pub new_json: String,
}

/// A hot-swappable additive-`Msg`-set patch for an edit that extended the `Msg`
/// variant surface.
///
/// The running app's compiled `Msg` set is described by `live_json` (it still
/// bakes this descriptor, since it is not recompiled); `candidate_json` is the
/// edited program's set. The app's `/_ipe/hot-msg` endpoint accepts the pair only
/// when `candidate_json` is a proven additive superset of `live_json`, so a
/// returning session's in-flight `handler_id`s still resolve. A non-additive
/// change never produces a `MsgSetPatch` (the classifier withholds it), so the
/// edit falls through to a recompile.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MsgSetPatch {
    /// The PREVIOUS baked `Msg`-set descriptor JSON — the live set the running app
    /// still describes, hence the endpoint's comparison key.
    pub live_json: String,
    /// The edited program's `Msg`-set descriptor JSON — the additive-superset
    /// candidate to register.
    pub candidate_json: String,
}

/// A hot-swappable sub-description patch for one edited `subscriptions` entry.
///
/// The running app's compiled entry reads its baked datum through
/// `sub_every_hot("<old_json>")`; the app is not recompiled, so it still bakes
/// `old_json`. The overlay is keyed by that exact baked string, so the patch
/// carries the OLD json (the key the running app matches) and the NEW json (the
/// edited sub-description to register).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SubPatch {
    /// The PREVIOUS baked datum JSON — the key the running app's compiled entry
    /// passes to `sub_every_hot`, hence the overlay key. Send the OLD value, not
    /// the new.
    pub old_json: String,
    /// The edited sub-description's JSON — the replacement to register for
    /// `old_json`.
    pub new_json: String,
}

/// A hot-swappable init patch for an edited data-describable `init`.
///
/// The running app's compiled `init` reads its baked starting-Model datum through
/// `apply_init_hot("<old_json>", <compiled record>)`; the app is not recompiled,
/// so it still bakes `old_json`. The overlay is keyed by that exact baked string,
/// so the patch carries the OLD json (the key the running app matches at session
/// creation) and the NEW json (the edited init datum to register). An init edit
/// affects only FRESH sessions; a live session keeps its Model.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InitPatch {
    /// The PREVIOUS baked init datum JSON — the key the running app's compiled
    /// `init` passes to `apply_init_hot`, hence the overlay key. Send the OLD
    /// value, not the new.
    pub old_json: String,
    /// The edited init datum's JSON — the replacement to register for `old_json`.
    pub new_json: String,
}

/// A hot-swappable Cmd-wiring patch for an `update` arm whose baked wiring datum
/// changed (which compiled effect the arm fires).
///
/// The effect BODY is unchanged and still compiled in the running app; only the
/// WIRING (the selected effect id) is data, so the patch carries the OLD json (the
/// overlay key) and the NEW json (the edited wiring).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WiringPatch {
    /// The PREVIOUS baked wiring datum JSON — the key the running app's compiled
    /// arm passes to `select_cmd_hot`, hence the overlay key. Send the OLD value.
    pub old_json: String,
    /// The edited wiring datum's JSON — the replacement to register for `old_json`.
    pub new_json: String,
}

/// The set of hot-swappable deltas an edit produced with no recompile.
///
/// Carries the appearance (view literal) patches, the `update`-arm transition
/// patches, the additive-`Msg`-set patches, the `subscriptions`-entry
/// sub-description patches, the session-`init` datum patches, and the
/// `update`-arm Cmd-wiring patches. All are pushed to the running app over the
/// live socket; each may be empty.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HotSwap {
    /// One [`ViewPatch`] per view whose hoisted appearance literals changed.
    pub views: Vec<ViewPatch>,
    /// One [`TransitionPatch`] per `update` arm whose baked transition changed.
    pub transitions: Vec<TransitionPatch>,
    /// One [`MsgSetPatch`] per file whose baked `Msg`-set descriptor changed
    /// additively (a variant added, none removed/retyped).
    pub msg_sets: Vec<MsgSetPatch>,
    /// One [`SubPatch`] per `subscriptions` entry whose baked sub-description
    /// changed.
    pub subs: Vec<SubPatch>,
    /// One [`InitPatch`] per `init` whose baked starting-Model datum changed.
    pub inits: Vec<InitPatch>,
    /// One [`WiringPatch`] per `update` arm whose baked Cmd wiring changed.
    pub wirings: Vec<WiringPatch>,
}

impl HotSwap {
    /// `true` when this hot-swap carries no patch on any channel — the two emits
    /// were byte-identical (a no-op re-emit: a whitespace-only edit, or a
    /// duplicate filesystem event on an already-current source). An empty
    /// hot-swap applies nothing to the running app, so it must NOT stand in for a
    /// rebuild: the caller falls through to the normal build path instead of
    /// short-circuiting, which is what keeps a duplicate save from cancelling an
    /// in-flight rebuild of the same source.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.views.is_empty()
            && self.transitions.is_empty()
            && self.msg_sets.is_empty()
            && self.subs.is_empty()
            && self.inits.is_empty()
            && self.wirings.is_empty()
    }
}

/// The classification of a source edit, derived from the emitted-Rust diff.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Classification {
    /// The only deltas are hoisted appearance-literal *values*, `update`-arm
    /// transition *data*, and/or `subscriptions`-entry sub-description *data*;
    /// hot-swap without a recompile. Empty when two emits are byte-identical — a
    /// no-op edit, still on the fast path.
    HotSwappable(HotSwap),
    /// Anything else — recompile. This is the conservative fallback.
    Logic,
}

/// Classify an edit from the previous and new emitted projects.
///
/// Returns [`Classification::AppearanceOnly`] iff the two emits differ *only* in
/// the default values inside `LiteralTable::from_defaults(&[…])` arrays (same set
/// of files, same array count and lengths, everything outside the arrays
/// byte-identical); otherwise [`Classification::Logic`].
#[must_use]
pub fn classify(prev: &EmittedProject, next: &EmittedProject) -> Classification {
    // The Cargo.toml is code (deps, features) — any change there is Logic.
    if prev.cargo_toml != next.cargo_toml {
        return Classification::Logic;
    }
    // A file added or removed is a structural change.
    if prev.files.len() != next.files.len() {
        return Classification::Logic;
    }
    let mut hot = HotSwap::default();
    for (rel, prev_src) in &prev.files {
        let Some(next_src) = next.files.get(rel) else {
            // A renamed/removed path — structural.
            return Classification::Logic;
        };
        // Fast exit: identical file contributes nothing.
        if prev_src == next_src {
            continue;
        }
        match classify_file(prev_src, next_src) {
            FileDelta::HotSwappable(mut delta) => {
                hot.views.append(&mut delta.views);
                hot.transitions.append(&mut delta.transitions);
                hot.msg_sets.append(&mut delta.msg_sets);
                hot.subs.append(&mut delta.subs);
                hot.inits.append(&mut delta.inits);
                hot.wirings.append(&mut delta.wirings);
            }
            FileDelta::Logic => return Classification::Logic,
        }
    }
    Classification::HotSwappable(hot)
}

/// The per-file classification result.
enum FileDelta {
    /// Only appearance-literal values and/or transition data changed; the
    /// hot-swappable deltas for this file.
    HotSwappable(HotSwap),
    /// Any other textual difference.
    Logic,
}

/// The literal marker that opens a defaults array in the emitted Rust. Kept in
/// sync with the emitter's `literal_table_prologue`
/// (`from_defaults(&[…])`). If the emitter's spelling ever changes, no array is
/// recognised and every edit conservatively falls to `Logic` — safe, never a
/// false `AppearanceOnly`.
const DEFAULTS_OPEN: &str = "from_defaults(&[";

/// Every data channel scanned out of one emitted file: the appearance
/// (`from_defaults`) arrays plus each positional datum channel (transition arm,
/// subscriptions entry, session-`init`, `update`-arm Cmd wiring) and the at-most-one
/// `Msg`-set descriptor. Produced once per side by [`scan_channels`], so the
/// per-channel scan-and-count discipline lives in one place.
struct Channels {
    arrays: Vec<DefaultsArray>,
    trans: Vec<TransitionData>,
    subs: Vec<TransitionData>,
    inits: Vec<InitData>,
    wire: Vec<TransitionData>,
    msg_set: Option<String>,
}

/// Scan every channel of one emitted `src`. Returns `None` (⇒ `Logic`) if any
/// scanner refuses (an emit shape it cannot prove) — never a guess. The `Msg`-set
/// descriptor is optional (at most one per emitted web app); its absence is not a
/// refusal.
fn scan_channels(src: &str) -> Option<Channels> {
    Some(Channels {
        arrays: scan_defaults_arrays(src)?,
        trans: scan_transition_data(src)?,
        subs: scan_sub_data(src)?,
        inits: scan_init_data(src)?,
        wire: scan_wiring_data(src)?,
        msg_set: scan_msg_set(src),
    })
}

/// Whether every positional channel has the SAME occurrence count on both sides. A
/// differing count is structural (a datum-bearing call was added or removed, or a
/// hoisted view appeared/disappeared) ⇒ Logic. The `Msg`-set descriptor's
/// appearance/disappearance is handled separately by the caller (it is a superset
/// decision, not a count).
const fn channels_counts_match(prev: &Channels, next: &Channels) -> bool {
    prev.arrays.len() == next.arrays.len()
        && prev.trans.len() == next.trans.len()
        && prev.subs.len() == next.subs.len()
        && prev.inits.len() == next.inits.len()
        && prev.wire.len() == next.wire.len()
}

/// Build one [`ViewPatch`] per `from_defaults` array whose default VALUES changed,
/// keyed by the OLD defaults (the signature the running app's compiled `view` still
/// bakes). `prev`/`next` are already equal in count (checked by
/// [`channels_counts_match`]); returns `None` (⇒ `Logic`) if any corresponding
/// array's element COUNT differs — a literal added/removed inside one view is
/// structural, not an appearance edit.
fn diff_view_patches(prev: &[DefaultsArray], next: &[DefaultsArray]) -> Option<Vec<ViewPatch>> {
    let mut views = Vec::new();
    for (pa, na) in prev.iter().zip(next.iter()) {
        if pa.values.len() != na.values.len() {
            return None;
        }
        let mut patch = Vec::new();
        for (idx, (pv, nv)) in pa.values.iter().zip(na.values.iter()).enumerate() {
            if pv != nv {
                patch.push((idx, nv.clone()));
            }
        }
        if !patch.is_empty() {
            views.push(ViewPatch {
                defaults: pa.values.clone(),
                patch,
            });
        }
    }
    Some(views)
}

/// Diff two versions of one emitted file. Everything outside the
/// `from_defaults(&[…])` array contents must be byte-identical, and each
/// corresponding array must have the same number of elements; then the delta is
/// exactly the changed default values.
fn classify_file(prev_src: &str, next_src: &str) -> FileDelta {
    // Scan every data channel on both sides once (parse, don't validate): an
    // unparsable emit or a channel whose occurrence count changed between the two
    // emits is structural, so `scan_channels` returns `None` ⇒ Logic.
    let Some(prev_ch) = scan_channels(prev_src) else {
        return FileDelta::Logic;
    };
    let Some(next_ch) = scan_channels(next_src) else {
        return FileDelta::Logic;
    };
    if !channels_counts_match(&prev_ch, &next_ch) {
        return FileDelta::Logic;
    }

    // The `Msg`-set descriptor: a descriptor that APPEARS or DISAPPEARS between
    // emits is structural (a web app was added/removed or the hot gate flipped)
    // ⇒ Logic. A descriptor present on BOTH sides that changed NON-additively (a
    // variant removed/retyped) ⇒ Logic. A descriptor that changed ADDITIVELY yields
    // a `MsgSetPatch` below; an unchanged one yields none.
    match (&prev_ch.msg_set, &next_ch.msg_set) {
        (Some(live), Some(cand)) if live != cand => {
            if !msg_set_is_additive_superset(live, cand) {
                return FileDelta::Logic;
            }
        }
        (Some(_), None) | (None, Some(_)) => return FileDelta::Logic,
        _ => {}
    }

    let Channels {
        arrays: prev_arrays,
        trans: prev_trans,
        subs: prev_subs,
        inits: prev_inits,
        wire: prev_wire,
        msg_set: prev_msg_set,
    } = prev_ch;
    let Channels {
        arrays: next_arrays,
        trans: next_trans,
        subs: next_subs,
        inits: next_inits,
        wire: next_wire,
        msg_set: next_msg_set,
    } = next_ch;

    // The masked regions are: (1) every `from_defaults(&[…])` array's contents,
    // and (2) every hoisted-read TOTAL-FALLBACK literal
    // (`__ipe_lit.get(N).parse::<T>().unwrap_or(<literal>)`). A typed style value
    // is emitted at BOTH sites — the baked default AND the read's `unwrap_or`
    // fallback — from the SAME source literal, so a value edit moves them
    // together. The fallback is inert (it fires only if a patch fails to parse,
    // which never happens in dev/prod), and it always equals the corresponding
    // default, so masking it cannot admit a false `AppearanceOnly`: any genuine
    // logic change still perturbs the skeleton outside these masks. The `String`
    // hoist reads via `.to_string()` (no fallback), so it has no such site.
    // The transition-datum literal argument is ALSO masked: the whole `<json>`
    // string inside `apply_transition_hot("<json>", …)` may change while the arm
    // structure is byte-identical (a `+1` → `+2` edit changes only the baked
    // `source`). Masking it keeps a data-only arm edit hot-swappable, exactly as
    // masking a `from_defaults` array keeps an appearance edit hot-swappable; any
    // structural change to the arm still perturbs the skeleton and forces Logic.
    let Some(prev_masks) = mask_spans(
        prev_src,
        &prev_arrays,
        &prev_trans,
        &prev_subs,
        &prev_inits,
        &prev_wire,
    ) else {
        return FileDelta::Logic;
    };
    let Some(next_masks) = mask_spans(
        next_src,
        &next_arrays,
        &next_trans,
        &next_subs,
        &next_inits,
        &next_wire,
    ) else {
        return FileDelta::Logic;
    };
    // A differing number of masked sites is itself structural.
    if prev_masks.len() != next_masks.len() {
        return FileDelta::Logic;
    }

    // If the skeletons (source with every masked region blanked) differ,
    // something other than a hoisted style value / a transition datum moved
    // (structure, control flow, a handler, a read index) → Logic.
    if skeleton(prev_src, &prev_masks) != skeleton(next_src, &next_masks) {
        return FileDelta::Logic;
    }

    let Some(views) = diff_view_patches(&prev_arrays, &next_arrays) else {
        return FileDelta::Logic;
    };

    // Each changed positional datum (transition arm, subscriptions entry,
    // session-`init`, `update`-arm Cmd wiring) yields a patch keyed by the OLD json
    // — the running app still bakes it, so it is the overlay key; the NEW json is
    // the replacement to register. The one `diff_datum_patches` helper collapses
    // every positional channel.
    let transitions = diff_datum_patches(&prev_trans, &next_trans, |old_json, new_json| {
        TransitionPatch { old_json, new_json }
    });
    let subs = diff_datum_patches(&prev_subs, &next_subs, |old_json, new_json| SubPatch {
        old_json,
        new_json,
    });
    let inits = diff_datum_patches(&prev_inits, &next_inits, |old_json, new_json| InitPatch {
        old_json,
        new_json,
    });
    let wirings = diff_datum_patches(&prev_wire, &next_wire, |old_json, new_json| WiringPatch {
        old_json,
        new_json,
    });

    // An additively-changed `Msg`-set descriptor (proven above) yields a patch:
    // the running app still bakes the OLD (live) descriptor, so it is the endpoint
    // comparison key; the NEW descriptor is the additive-superset candidate.
    let mut msg_sets = Vec::new();
    if let (Some(live), Some(cand)) = (&prev_msg_set, &next_msg_set)
        && live != cand
    {
        msg_sets.push(MsgSetPatch {
            live_json: live.clone(),
            candidate_json: cand.clone(),
        });
    }

    FileDelta::HotSwappable(HotSwap {
        views,
        transitions,
        msg_sets,
        subs,
        inits,
        wirings,
    })
}

/// A located baked datum literal that carries its parsed json — the common shape
/// [`diff_datum_patches`] pairs across every positional channel (transition arm,
/// subscriptions entry, session-`init`, `update`-arm Cmd wiring). Implemented for
/// each scanned-datum struct so the one differ works over all of them.
trait DatumJson {
    /// The baked datum's json — the overlay key on the old side, the replacement
    /// on the new side.
    fn json(&self) -> &str;
}

/// Pair the previous and new baked datum literals (equal in count, checked by the
/// caller) and build one patch per changed datum via `mk`, which receives the OLD
/// json (the overlay key) and the NEW json (the replacement). Shared by the
/// transition-arm, subscriptions-entry, session-`init`, and Cmd-wiring legs, whose
/// patch shape is identical.
fn diff_datum_patches<D: DatumJson, P>(
    prev: &[D],
    next: &[D],
    mk: impl Fn(String, String) -> P,
) -> Vec<P> {
    let mut out = Vec::new();
    for (p, n) in prev.iter().zip(next.iter()) {
        if p.json() != n.json() {
            out.push(mk(p.json().to_owned(), n.json().to_owned()));
        }
    }
    out
}

/// The `Msg`-set descriptor const the emitter bakes under the hot gate. Kept in
/// sync with `emit_web::msg_set_descriptor_item`
/// (`const IPE_WEB_MSG_SET: &str = "<json>";`). If the emitter's spelling ever
/// changes, no descriptor is recognised and a `Msg`-set edit conservatively takes
/// the ordinary path — never a false hot-swap.
const MSG_SET_OPEN: &str = "const IPE_WEB_MSG_SET: &str = ";

/// Locate the `Msg`-set descriptor JSON baked in `src`, if the emitter emitted
/// one under the hot gate. Returns `Some(json)` for the first occurrence,
/// `None` when the file bakes no descriptor (the emitter emits at most one per
/// emitted web app). A malformed occurrence (not a string literal) also yields
/// `None`, so an unrecognised shape never produces a spurious patch.
fn scan_msg_set(src: &str) -> Option<String> {
    scan_msg_set_located(src).map(|(json, _span)| json)
}

/// Like [`scan_msg_set`] but also returns the byte span of the descriptor's JSON
/// string CONTENTS (past the opening `"`, up to the closing `"`), for masking. The
/// descriptor string is masked so a purely-additive descriptor change does not
/// perturb the skeleton (exactly as a transition datum is masked); a non-additive
/// change is caught separately and forces `Logic`.
fn scan_msg_set_located(src: &str) -> Option<(String, MaskSpan)> {
    let bytes = src.as_bytes();
    let rel = src.find(MSG_SET_OPEN)?;
    let arg_at = skip_ws(bytes, rel + MSG_SET_OPEN.len());
    if *bytes.get(arg_at)? != b'"' {
        return None;
    }
    let inner_start = arg_at + 1;
    let (json, next) = parse_string_literal(src, arg_at)?;
    Some((
        json,
        MaskSpan {
            start: inner_start,
            end: next - 1,
        },
    ))
}

/// Whether `candidate_json` is an additive superset of `live_json`: both are
/// well-formed `Msg`-set descriptors, share the same schema tag, and every
/// variant in `live_json` is present in `candidate_json` with an identical
/// signature. Returns `false` on any parse failure or any non-additive change (a
/// removed/retyped variant), so a `Msg`-set patch is produced ONLY for a proven
/// additive extension — the same discipline the runtime endpoint re-checks before
/// accepting.
///
/// The comparison mirrors the runtime `web::msg_set::is_additive_superset` over
/// the same JSON shape; it is duplicated here (rather than depending on the
/// runtime crate) so the watch classifier stays a pure text-diff with no runtime
/// link, exactly as the transition/appearance scans do.
fn msg_set_is_additive_superset(live_json: &str, candidate_json: &str) -> bool {
    let Some((live_schema, live_vars)) = parse_msg_set(live_json) else {
        return false;
    };
    let Some((cand_schema, cand_vars)) = parse_msg_set(candidate_json) else {
        return false;
    };
    if live_schema != cand_schema {
        return false;
    }
    // Every live variant must survive with an identical signature. A missing one
    // is a removal; a differing signature is a retype. Either refuses.
    live_vars.iter().all(|(name, sig)| {
        cand_vars
            .iter()
            .find(|(cn, _)| cn == name)
            .is_some_and(|(_, csig)| csig == sig)
    })
}

/// Parse a `Msg`-set descriptor JSON into `(schema, [(name, signature)])`, where
/// each variant's SIGNATURE is the raw serde form of its `shape` field (so two
/// variants compare equal iff their names AND shape encodings match). Returns
/// `None` on any structural surprise — a non-object, a missing `schema`/`variants`,
/// a non-array `variants`, a malformed entry — so a corrupt descriptor is treated
/// as non-additive (the caller then recompiles).
fn parse_msg_set(json: &str) -> Option<(i64, Vec<(String, String)>)> {
    let value: serde_json::Value = serde_json::from_str(json).ok()?;
    let obj = value.as_object()?;
    let schema = obj.get("schema")?.as_i64()?;
    let variants = obj.get("variants")?.as_array()?;
    let mut out = Vec::with_capacity(variants.len());
    for v in variants {
        let vobj = v.as_object()?;
        let name = vobj.get("name")?.as_str()?.to_owned();
        // The shape is compared by its canonical serde string, so a scalar tag
        // (`"Unit"`) and a compound tag (`{"Compound":"Int,Str"}`) each round-trip
        // to a stable signature; a change of either is a retype.
        let sig = serde_json::to_string(vobj.get("shape")?).ok()?;
        out.push((name, sig));
    }
    Some((schema, out))
}

/// One `apply_transition_hot("<json>", …)` occurrence located in a source file:
/// the datum JSON string and the byte span of its contents (for masking).
struct TransitionData {
    /// Byte offset of the first char inside the json string literal (past the `"`).
    inner_start: usize,
    /// Byte offset of the closing `"` of the json string literal.
    inner_end: usize,
    /// The parsed (unescaped) json string — the baked datum.
    json: String,
}

impl DatumJson for TransitionData {
    fn json(&self) -> &str {
        &self.json
    }
}

/// The literal opening an emitted transition-datum read in the emitted Rust.
/// Kept in sync with the emitter's `emit_transition_arm`
/// (`apply_transition_hot("<json>", <model>)`). If the emitter's spelling ever
/// changes, no datum is recognised and every edit conservatively falls to
/// `Logic` — safe, never a false hot-swap.
const TRANSITION_OPEN: &str = "apply_transition_hot(";

/// Locate every `apply_transition_hot("<json>", …)` call in `src` and parse its
/// first argument (the baked datum JSON string literal). Returns `None`
/// (⇒ `Logic`) if any occurrence's first argument is not a well-formed string
/// literal — never a guess. A file with no occurrences returns `Some(empty)`.
fn scan_transition_data(src: &str) -> Option<Vec<TransitionData>> {
    let bytes = src.as_bytes();
    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some(rel) = src[from..].find(TRANSITION_OPEN) {
        let open = from + rel;
        // The first argument begins at the first `"` after the `(`.
        let arg_at = skip_ws(bytes, open + TRANSITION_OPEN.len());
        if *bytes.get(arg_at)? != b'"' {
            return None;
        }
        let inner_start = arg_at + 1;
        let (json, next) = parse_string_literal(src, arg_at)?;
        // `next` is just past the closing quote; the closing quote is `next - 1`.
        out.push(TransitionData {
            inner_start,
            inner_end: next - 1,
            json,
        });
        from = next;
    }
    Some(out)
}

/// The literal opening an emitted sub-description read in the emitted Rust. Kept
/// in sync with the emitter's `emit_sub_arm`
/// (`ipe_runtime::web::sub_every_hot("<json>")`). If the emitter's spelling ever
/// changes, no datum is recognised and every edit conservatively falls to `Logic`
/// — safe, never a false hot-swap.
const SUB_OPEN: &str = "sub_every_hot(";

/// Locate every `sub_every_hot("<json>")` call in `src` and parse its first
/// argument (the baked datum JSON string literal). Returns `None` (⇒ `Logic`) if
/// any occurrence's first argument is not a well-formed string literal — never a
/// guess. A file with no occurrences returns `Some(empty)`. Reuses
/// [`TransitionData`] (same shape: the parsed json plus its inner byte span for
/// masking).
fn scan_sub_data(src: &str) -> Option<Vec<TransitionData>> {
    let bytes = src.as_bytes();
    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some(rel) = src[from..].find(SUB_OPEN) {
        let open = from + rel;
        // The first argument begins at the first `"` after the `(`.
        let arg_at = skip_ws(bytes, open + SUB_OPEN.len());
        if *bytes.get(arg_at)? != b'"' {
            return None;
        }
        let inner_start = arg_at + 1;
        let (json, next) = parse_string_literal(src, arg_at)?;
        out.push(TransitionData {
            inner_start,
            inner_end: next - 1,
            json,
        });
        from = next;
    }
    Some(out)
}

/// One `apply_init_hot("<json>", <compiled record>)` occurrence located in a
/// source file: the datum JSON string, its inner byte span (for the json mask),
/// and the span of the SECOND argument (the compiled record fallback, which
/// changes together with the datum on an `init` edit and so is masked too).
struct InitData {
    /// Byte offset of the first char inside the json string literal (past the `"`).
    json_inner_start: usize,
    /// Byte offset of the closing `"` of the json string literal.
    json_inner_end: usize,
    /// Byte offset of the first char of the second argument (the compiled record).
    arg2_start: usize,
    /// Byte offset just past the last char of the second argument (at the `)`).
    arg2_end: usize,
    /// The parsed (unescaped) json string — the baked init datum.
    json: String,
}

impl DatumJson for InitData {
    fn json(&self) -> &str {
        &self.json
    }
}

/// The literal opening an emitted init-datum read in the emitted Rust. Kept in
/// sync with the emitter's `emit_init_datum`
/// (`apply_init_hot("<json>", <compiled record>)`). If the emitter's spelling
/// ever changes, no datum is recognised and every edit conservatively falls to
/// `Logic` — safe, never a false hot-swap.
const INIT_OPEN: &str = "apply_init_hot(";

/// Locate every `apply_init_hot("<json>", <compiled record>)` call in `src`,
/// parsing its first argument (the baked datum JSON string literal) and locating
/// its second argument (the compiled record fallback). Returns `None`
/// (⇒ `Logic`) if any occurrence is malformed — never a guess. A file with no
/// occurrences returns `Some(empty)`.
fn scan_init_data(src: &str) -> Option<Vec<InitData>> {
    let bytes = src.as_bytes();
    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some(rel) = src[from..].find(INIT_OPEN) {
        let open = from + rel;
        // The first argument begins at the first `"` after the `(`.
        let arg_at = skip_ws(bytes, open + INIT_OPEN.len());
        if *bytes.get(arg_at)? != b'"' {
            return None;
        }
        let json_inner_start = arg_at + 1;
        let (json, after_str) = parse_string_literal(src, arg_at)?;
        // A comma separates the two arguments.
        let comma = skip_ws(bytes, after_str);
        if *bytes.get(comma)? != b',' {
            return None;
        }
        let arg2_start = skip_ws(bytes, comma + 1);
        // The whole call opened at `(` just before `INIT_OPEN`'s end; find its
        // matching close paren to bound the second argument. `match_close_paren`
        // takes the offset just past the opening `(`.
        let call_open = open + INIT_OPEN.len();
        let close = match_close_paren(src, call_open)?;
        // The second argument runs from `arg2_start` up to the closing `)`.
        if close < arg2_start {
            return None;
        }
        out.push(InitData {
            json_inner_start,
            json_inner_end: after_str - 1,
            arg2_start,
            arg2_end: close,
            json,
        });
        from = close;
    }
    Some(out)
}

/// The literal opening an emitted Cmd-wiring datum read in the emitted Rust. Kept
/// in sync with the emitter's `emit_cmd_wiring_arm`
/// (`select_cmd_hot("<json>", <count>)`). If the emitter's spelling ever changes,
/// no datum is recognised and every edit conservatively falls to `Logic` — safe,
/// never a false hot-swap.
const WIRING_OPEN: &str = "select_cmd_hot(";

/// Locate every `select_cmd_hot("<json>", …)` call in `src` and parse its first
/// argument (the baked wiring datum JSON string literal). Returns `None`
/// (⇒ `Logic`) if any occurrence's first argument is not a well-formed string
/// literal — never a guess. A file with no occurrences returns `Some(empty)`.
/// Reuses [`TransitionData`] (a json string + its inner span) — the wiring's
/// second argument (the effect count) is part of the skeleton, so it is NOT
/// captured or masked (a count change is structural → recompile).
fn scan_wiring_data(src: &str) -> Option<Vec<TransitionData>> {
    let bytes = src.as_bytes();
    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some(rel) = src[from..].find(WIRING_OPEN) {
        let open = from + rel;
        let arg_at = skip_ws(bytes, open + WIRING_OPEN.len());
        if *bytes.get(arg_at)? != b'"' {
            return None;
        }
        let inner_start = arg_at + 1;
        let (json, next) = parse_string_literal(src, arg_at)?;
        out.push(TransitionData {
            inner_start,
            inner_end: next - 1,
            json,
        });
        from = next;
    }
    Some(out)
}

/// One `from_defaults(&[…])` occurrence located in a source file.
struct DefaultsArray {
    /// Byte offset of the first element char inside the array (just past `&[`).
    inner_start: usize,
    /// Byte offset of the closing `]`.
    inner_end: usize,
    /// The parsed (unescaped) default values, in order.
    values: Vec<String>,
}

/// A half-open byte span `[start, end)` of `src` masked out of the skeleton.
#[derive(Clone, Copy)]
struct MaskSpan {
    start: usize,
    end: usize,
}

/// Every masked region of `src`, in ascending, non-overlapping source order: the
/// contents of each `from_defaults(&[…])` array plus each hoisted-read
/// `unwrap_or(<literal>)` fallback argument. Returns `None` (⇒ `Logic`) if a
/// hoisted read's fallback cannot be located, so an unrecognised emit shape is
/// conservative.
fn mask_spans(
    src: &str,
    arrays: &[DefaultsArray],
    transitions: &[TransitionData],
    subs: &[TransitionData],
    inits: &[InitData],
    wirings: &[TransitionData],
) -> Option<Vec<MaskSpan>> {
    let mut spans: Vec<MaskSpan> = arrays
        .iter()
        .map(|a| MaskSpan {
            start: a.inner_start,
            end: a.inner_end,
        })
        .collect();
    spans.extend(transitions.iter().map(|t| MaskSpan {
        start: t.inner_start,
        end: t.inner_end,
    }));
    // The sub-description datum literal argument is masked exactly like a
    // transition datum: the whole `<json>` inside `sub_every_hot("<json>")` may
    // change (an interval or tick-message edit) while the entry structure stays
    // byte-identical. Masking it keeps a data-only subscription edit hot-swappable;
    // any structural change to the entry still perturbs the skeleton and forces
    // Logic.
    spans.extend(subs.iter().map(|s| MaskSpan {
        start: s.inner_start,
        end: s.inner_end,
    }));
    // The init-datum call masks TWO regions per occurrence: the `<json>` string
    // inside `apply_init_hot("<json>", <compiled record>)` AND the second argument
    // (the compiled record fallback). Both change together on a data-only `init`
    // edit (`count = 0` → `count = 1` moves the baked datum AND re-emits the record
    // literal); masking both keeps such an edit hot-swappable, while any change to
    // the call STRUCTURE (a different kernel, a new `init`) still perturbs the
    // skeleton outside these masks → Logic.
    for t in inits {
        spans.push(MaskSpan {
            start: t.json_inner_start,
            end: t.json_inner_end,
        });
        spans.push(MaskSpan {
            start: t.arg2_start,
            end: t.arg2_end,
        });
    }
    // The wiring datum's `<json>` argument is masked exactly like a transition
    // datum: a wiring edit changes only the baked `<json>` inside
    // `select_cmd_hot("<json>", <count>)` while the arm structure and the effect
    // `<count>` are byte-identical. Masking it keeps a wiring-only edit
    // hot-swappable; a new effect body changes the `<count>` (skeleton) → Logic.
    spans.extend(wirings.iter().map(|t| MaskSpan {
        start: t.inner_start,
        end: t.inner_end,
    }));
    spans.extend(scan_hoisted_read_fallbacks(src)?);
    // The `Msg`-set descriptor const's JSON contents are masked too, so a
    // purely-additive descriptor change (a new variant appended) does not perturb
    // the skeleton. A NON-additive descriptor change is caught separately (see
    // `classify_file`) and forces `Logic`, so masking here can never admit a
    // variant removal/retype as a hot-swap.
    if let Some((_json, span)) = scan_msg_set_located(src) {
        spans.push(span);
    }
    spans.sort_by_key(|s| s.start);
    Some(spans)
}

/// Rebuild `src` with every masked span blanked to a fixed placeholder, so two
/// files whose ONLY differences fall inside masked spans produce identical
/// skeletons. `spans` must be ascending and non-overlapping.
fn skeleton(src: &str, spans: &[MaskSpan]) -> String {
    let mut out = String::with_capacity(src.len());
    let mut cursor = 0usize;
    for s in spans {
        if s.start < cursor {
            continue; // defensive: skip any overlap rather than slice-panic
        }
        out.push_str(&src[cursor..s.start]);
        out.push('\u{0}'); // fixed placeholder for the whole masked region
        cursor = s.end;
    }
    out.push_str(&src[cursor..]);
    out
}

/// The literal opening a hoisted style-value read in the emitted Rust.
const HOISTED_READ_OPEN: &str = "__ipe_lit.get(";
/// The total-fallback call spliced after a typed hoisted read's `parse::<T>()`.
const UNWRAP_OR_OPEN: &str = ".unwrap_or(";

/// Locate every typed hoisted-read total-fallback argument
/// (`__ipe_lit.get(N).parse::<T>().unwrap_or(<literal>)`) and return the span of
/// its `<literal>` argument (the bytes strictly inside the `unwrap_or(...)`
/// parens). A `String` hoist reads via `.to_string()` and has no `unwrap_or`, so
/// it contributes nothing. Returns `None` if an `unwrap_or` cannot be balanced,
/// so a malformed shape falls to `Logic`.
fn scan_hoisted_read_fallbacks(src: &str) -> Option<Vec<MaskSpan>> {
    let mut spans = Vec::new();
    let mut from = 0usize;
    while let Some(rel) = src[from..].find(HOISTED_READ_OPEN) {
        let read_at = from + rel;
        let after_read = read_at + HOISTED_READ_OPEN.len();
        // The fallback, if any, is the FIRST `.unwrap_or(` after this read but
        // before the NEXT hoisted read. A `String` hoist has none in that window.
        let window_end = src[after_read..]
            .find(HOISTED_READ_OPEN)
            .map_or(src.len(), |n| after_read + n);
        if let Some(u_rel) = src[after_read..window_end].find(UNWRAP_OR_OPEN) {
            let arg_start = after_read + u_rel + UNWRAP_OR_OPEN.len();
            let arg_end = match_close_paren(src, arg_start)?;
            spans.push(MaskSpan {
                start: arg_start,
                end: arg_end,
            });
        }
        from = after_read;
    }
    Some(spans)
}

/// Given `pos` just past an opening `(`, return the byte offset of its matching
/// `)` (the byte AT the close). Balances nested parens; ignores parens inside
/// string literals so a `")"` in a fallback string does not miscount. Returns
/// `None` if unbalanced (⇒ conservative `Logic`).
fn match_close_paren(src: &str, mut pos: usize) -> Option<usize> {
    let bytes = src.as_bytes();
    let mut depth: usize = 1;
    while let Some(&b) = bytes.get(pos) {
        match b {
            b'"' => {
                let (_s, next) = parse_string_literal(src, pos)?;
                pos = next;
                continue;
            }
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(pos);
                }
            }
            _ => {}
        }
        pos += 1;
    }
    None
}

/// Locate every `from_defaults(&[…])` array in `src` and parse its elements.
///
/// Returns `None` (⇒ caller falls to `Logic`) if any occurrence cannot be parsed
/// as a well-formed list of Rust string literals — never a guess. A file with no
/// occurrences returns `Some(empty)`.
fn scan_defaults_arrays(src: &str) -> Option<Vec<DefaultsArray>> {
    let mut arrays = Vec::new();
    let mut search_from = 0usize;
    while let Some(rel) = src.get(search_from..)?.find(DEFAULTS_OPEN) {
        let open = search_from + rel;
        let inner_start = open + DEFAULTS_OPEN.len();
        let (values, inner_end) = parse_string_array(src, inner_start)?;
        arrays.push(DefaultsArray {
            inner_start,
            inner_end,
            values,
        });
        search_from = inner_end;
    }
    Some(arrays)
}

/// Parse a comma-separated list of Rust double-quoted string literals starting at
/// `pos` (the first byte after `&[`), through the closing `]`. Returns the
/// unescaped values and the byte offset of the `]`, or `None` on anything
/// unexpected (so the caller conservatively classifies `Logic`).
///
/// Only the escapes the emitter can produce via `{:?}` on a `String` are handled:
/// `\"`, `\\`, `\n`, `\r`, `\t`, `\0`, and `\u{…}`. Any other escape or a
/// non-string element yields `None`.
fn parse_string_array(src: &str, mut pos: usize) -> Option<(Vec<String>, usize)> {
    let bytes = src.as_bytes();
    let mut values = Vec::new();
    loop {
        pos = skip_ws(bytes, pos);
        match bytes.get(pos)? {
            b']' => return Some((values, pos)),
            b'"' => {
                let (s, next) = parse_string_literal(src, pos)?;
                values.push(s);
                pos = skip_ws(bytes, next);
                match bytes.get(pos)? {
                    b',' => pos += 1,
                    b']' => return Some((values, pos)),
                    _ => return None,
                }
            }
            // An empty array (`from_defaults(&[])`) closes immediately; anything
            // else here (a non-string element) is unrecognised → conservative.
            _ => return None,
        }
    }
}

/// Skip ASCII whitespace, returning the next non-space offset.
fn skip_ws(bytes: &[u8], mut pos: usize) -> usize {
    while let Some(b) = bytes.get(pos) {
        if b.is_ascii_whitespace() {
            pos += 1;
        } else {
            break;
        }
    }
    pos
}

/// Parse one Rust double-quoted string literal in `src` starting at `pos`.
///
/// `src.as_bytes()[pos]` must be `b'"'`. Returns the unescaped `String` and the
/// offset just past the closing quote. `src` stays a `&str` end to end, so the
/// UTF-8 proof the caller already holds travels in the type: decoding a raw
/// char here costs O(1), inspecting at most 4 bytes and never re-validating
/// the remainder of `src`.
fn parse_string_literal(src: &str, pos: usize) -> Option<(String, usize)> {
    let bytes = src.as_bytes();
    if *bytes.get(pos)? != b'"' {
        return None;
    }
    let mut i = pos + 1;
    let mut out = String::new();
    loop {
        match *bytes.get(i)? {
            b'"' => return Some((out, i + 1)),
            b'\\' => {
                let esc = *bytes.get(i + 1)?;
                match esc {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'n' => out.push('\n'),
                    b'r' => out.push('\r'),
                    b't' => out.push('\t'),
                    b'0' => out.push('\0'),
                    b'u' => {
                        // `\u{XXXX}` — the only multi-byte escape `{:?}` emits.
                        let (ch, next) = parse_unicode_escape(bytes, i + 2)?;
                        out.push(ch);
                        i = next;
                        continue;
                    }
                    _ => return None,
                }
                i += 2;
            }
            // A raw byte in the string body. `src` is already proven UTF-8, so
            // decode the scalar directly at this offset — an O(1) boundary
            // check plus one scalar decode, never a revalidation of the tail.
            // An offset off a char boundary (a lone continuation byte) yields
            // `None` here, exactly as the old whole-tail decode did.
            _ => {
                let ch = src.get(i..)?.chars().next()?;
                let len = ch.len_utf8();
                out.push(ch);
                i += len;
            }
        }
    }
}

/// Parse a `{HHHH}` payload of a `\u{…}` escape at `pos` (just past the `u`),
/// returning the decoded char and the offset just past the closing `}`.
fn parse_unicode_escape(bytes: &[u8], pos: usize) -> Option<(char, usize)> {
    if *bytes.get(pos)? != b'{' {
        return None;
    }
    let mut i = pos + 1;
    let mut code: u32 = 0;
    let mut digits = 0;
    while let Some(&b) = bytes.get(i) {
        if b == b'}' {
            if digits == 0 {
                return None;
            }
            let ch = char::from_u32(code)?;
            return Some((ch, i + 1));
        }
        let d = (b as char).to_digit(16)?;
        code = code.checked_mul(16)?.checked_add(d)?;
        digits += 1;
        if digits > 6 {
            return None;
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipe_backend::EmittedProject;
    use std::collections::BTreeMap;

    fn project(files: &[(&str, &str)], cargo: &str) -> EmittedProject {
        let mut map = BTreeMap::new();
        for (path, body) in files {
            // `RelPath` validates a relative path; the emitter only ever emits
            // valid ones, so any test path here is well-formed.
            let rel = ipe_backend::RelPath::new(*path).expect("test rel path");
            map.insert(rel, (*body).to_owned());
        }
        EmittedProject {
            files: map,
            cargo_toml: cargo.to_owned(),
            uses_webview: false,
        }
    }

    fn table(defaults: &[&str]) -> String {
        let rendered: Vec<String> = defaults.iter().map(|d| format!("{d:?}")).collect();
        format!("from_defaults(&[{}])", rendered.join(", "))
    }

    /// Mirror the emitter's TYPED-Int hoist for a single-value view: the baked
    /// `from_defaults(&["N"])` prologue AND the read site whose `unwrap_or(Ni64)`
    /// fallback re-embeds the same source literal (the second changing site that
    /// the masking must absorb).
    fn typed_int_view(n: i64) -> String {
        format!(
            "fn view() {{ let __ipe_lit = ipe_runtime::web::LiteralTable::{}; \
             ui_padding_(__ipe_lit.get(0).parse::<i64>().unwrap_or({n}i64)) }}",
            table(&[&n.to_string()]),
        )
    }

    /// Assert `classify` returned `HotSwappable` and hand back its VIEW patches,
    /// so callers extract fields via [`first_patch`] (never a panicking index). A
    /// `Logic` result is the test's failure — surfaced by asserting the variant
    /// matches before destructuring; the `else` arm is dead once the assertion
    /// holds and returns an empty vec (no `panic!`/`unreachable!`).
    fn expect_appearance(prev: &EmittedProject, next: &EmittedProject) -> Vec<ViewPatch> {
        let got = classify(prev, next);
        assert!(
            matches!(got, Classification::HotSwappable(_)),
            "expected HotSwappable, got {got:?}"
        );
        if let Classification::HotSwappable(hot) = got {
            hot.views
        } else {
            Vec::new()
        }
    }

    /// Assert `classify` returned `HotSwappable` and hand back its TRANSITION
    /// patches (same discipline as [`expect_appearance`]).
    fn expect_transitions(prev: &EmittedProject, next: &EmittedProject) -> Vec<TransitionPatch> {
        let got = classify(prev, next);
        assert!(
            matches!(got, Classification::HotSwappable(_)),
            "expected HotSwappable, got {got:?}"
        );
        if let Classification::HotSwappable(hot) = got {
            hot.transitions
        } else {
            Vec::new()
        }
    }

    /// The first view patch, asserting there is at least one. Returns an owned
    /// clone so no diverging fallback is needed for the (asserted-away) empty
    /// case.
    fn first_patch(ps: &[ViewPatch]) -> ViewPatch {
        assert!(!ps.is_empty(), "expected at least one view patch");
        ps.first().cloned().unwrap_or_default()
    }

    // ── (a) padding 12 → 16: AppearanceOnly, 1-entry patch ────────────────
    #[test]
    fn padding_value_edit_is_appearance_only() {
        let prev = project(
            &[(
                "src/main.rs",
                &format!("fn view() {{ let __ipe_lit = {}; body }}", table(&["12"])),
            )],
            "cargo",
        );
        let next = project(
            &[(
                "src/main.rs",
                &format!("fn view() {{ let __ipe_lit = {}; body }}", table(&["16"])),
            )],
            "cargo",
        );
        let ps = expect_appearance(&prev, &next);
        assert_eq!(ps.len(), 1);
        let p = first_patch(&ps);
        assert_eq!(p.defaults, vec!["12".to_owned()]);
        assert_eq!(p.patch, vec![(0, "16".to_owned())]);
    }

    // The real TYPED-Int emit shape: the source literal appears BOTH in the baked
    // defaults AND in the read's `unwrap_or(Ni64)` fallback. Both move on a
    // `padding 12 -> 16` edit; the fallback mask must absorb the second site so
    // the edit stays AppearanceOnly (this is the exact shape a naive
    // defaults-only diff misclassified as Logic).
    #[test]
    fn typed_int_padding_edit_with_read_fallback_is_appearance_only() {
        let prev = project(&[("src/main.rs", &typed_int_view(12))], "cargo");
        let next = project(&[("src/main.rs", &typed_int_view(16))], "cargo");
        let ps = expect_appearance(&prev, &next);
        assert_eq!(ps.len(), 1);
        let p = first_patch(&ps);
        assert_eq!(p.defaults, vec!["12".to_owned()]);
        assert_eq!(p.patch, vec![(0, "16".to_owned())]);
    }

    // But a change to the read site's STRUCTURE (not just the paired fallback
    // literal) is still Logic — e.g. a different kernel around the read. The mask
    // only blanks the `unwrap_or(...)` argument, never the surrounding call.
    #[test]
    fn changed_read_kernel_is_logic() {
        let prev = project(
            &[(
                "src/main.rs",
                &format!(
                    "let __ipe_lit = ipe_runtime::web::LiteralTable::{}; \
                     ui_padding_(__ipe_lit.get(0).parse::<i64>().unwrap_or(12i64))",
                    table(&["12"])
                ),
            )],
            "cargo",
        );
        let next = project(
            &[(
                "src/main.rs",
                &format!(
                    "let __ipe_lit = ipe_runtime::web::LiteralTable::{}; \
                     ui_spacing_(__ipe_lit.get(0).parse::<i64>().unwrap_or(12i64))",
                    table(&["12"])
                ),
            )],
            "cargo",
        );
        assert_eq!(classify(&prev, &next), Classification::Logic);
    }

    // A colour edit across a multi-element array patches only the changed index.
    #[test]
    fn colour_channel_edit_patches_single_index() {
        let prev = project(&[("src/main.rs", &table(&["255", "0", "0"]))], "cargo");
        let next = project(&[("src/main.rs", &table(&["255", "128", "0"]))], "cargo");
        let ps = expect_appearance(&prev, &next);
        assert_eq!(ps.len(), 1);
        let p = first_patch(&ps);
        assert_eq!(p.defaults, vec!["255", "0", "0"]);
        assert_eq!(p.patch, vec![(1, "128".to_owned())]);
    }

    // A font-family (String-valued) edit — the String hoist surface.
    #[test]
    fn font_family_string_edit_is_appearance_only() {
        let prev = project(&[("src/main.rs", &table(&["monospace"]))], "cargo");
        let next = project(&[("src/main.rs", &table(&["serif"]))], "cargo");
        let ps = expect_appearance(&prev, &next);
        assert_eq!(first_patch(&ps).patch, vec![(0, "serif".to_owned())]);
    }

    // ── (b) structural edit: add an element ⇒ Logic ───────────────────────
    #[test]
    fn structural_edit_outside_array_is_logic() {
        let prev = project(
            &[(
                "src/main.rs",
                &format!("div([]) ; let __ipe_lit = {};", table(&["12"])),
            )],
            "cargo",
        );
        // A new `span([])` node appears — skeleton differs.
        let next = project(
            &[(
                "src/main.rs",
                &format!("div([]) ; span([]) ; let __ipe_lit = {};", table(&["12"])),
            )],
            "cargo",
        );
        assert_eq!(classify(&prev, &next), Classification::Logic);
    }

    // Adding a hoisted literal (array grows) is structural → Logic.
    #[test]
    fn array_length_growth_is_logic() {
        let prev = project(&[("src/main.rs", &table(&["12"]))], "cargo");
        let next = project(&[("src/main.rs", &table(&["12", "16"]))], "cargo");
        assert_eq!(classify(&prev, &next), Classification::Logic);
    }

    // A whole new hoisted view (a second defaults array appears) → Logic.
    #[test]
    fn new_defaults_array_is_logic() {
        let prev = project(&[("src/main.rs", &table(&["12"]))], "cargo");
        let next = project(
            &[(
                "src/main.rs",
                &format!("{} ... {}", table(&["12"]), table(&["red"])),
            )],
            "cargo",
        );
        assert_eq!(classify(&prev, &next), Classification::Logic);
    }

    // ── (c) control-flow / conditional edit ⇒ Logic ───────────────────────
    #[test]
    fn conditional_edit_is_logic() {
        let prev = project(
            &[(
                "src/main.rs",
                &format!("if a {{ x }} let __ipe_lit = {};", table(&["12"])),
            )],
            "cargo",
        );
        let next = project(
            &[(
                "src/main.rs",
                &format!(
                    "if a {{ x }} else {{ y }} let __ipe_lit = {};",
                    table(&["12"])
                ),
            )],
            "cargo",
        );
        assert_eq!(classify(&prev, &next), Classification::Logic);
    }

    // ── (d) Model-dependent value change ⇒ Logic ──────────────────────────
    // A Model-dependent value is NOT hoisted (only compile-time-constant style
    // literals are), so the change lands in ordinary emitted code — skeleton
    // differs → Logic.
    #[test]
    fn model_dependent_value_change_is_logic() {
        let prev = project(
            &[(
                "src/main.rs",
                &format!("text(model.count) ; {};", table(&["12"])),
            )],
            "cargo",
        );
        let next = project(
            &[(
                "src/main.rs",
                &format!("text(model.count + 1) ; {};", table(&["12"])),
            )],
            "cargo",
        );
        assert_eq!(classify(&prev, &next), Classification::Logic);
    }

    // ── (e) update / logic edit ⇒ Logic ───────────────────────────────────
    #[test]
    fn update_body_edit_is_logic() {
        let prev = project(
            &[
                ("src/main.rs", &table(&["12"])),
                ("src/update.rs", "fn update(m) { m }"),
            ],
            "cargo",
        );
        let next = project(
            &[
                ("src/main.rs", &table(&["12"])),
                ("src/update.rs", "fn update(m) { m + 1 }"),
            ],
            "cargo",
        );
        assert_eq!(classify(&prev, &next), Classification::Logic);
    }

    // A dependency/Cargo.toml change is Logic even with identical source files.
    #[test]
    fn cargo_toml_change_is_logic() {
        let prev = project(&[("src/main.rs", &table(&["12"]))], "cargo-a");
        let next = project(&[("src/main.rs", &table(&["12"]))], "cargo-b");
        assert_eq!(classify(&prev, &next), Classification::Logic);
    }

    // A file added is structural.
    #[test]
    fn file_added_is_logic() {
        let prev = project(&[("src/main.rs", &table(&["12"]))], "cargo");
        let next = project(
            &[
                ("src/main.rs", &table(&["12"])),
                ("src/extra.rs", "fn extra() {}"),
            ],
            "cargo",
        );
        assert_eq!(classify(&prev, &next), Classification::Logic);
    }

    // A renamed file (same count, different path) is structural.
    #[test]
    fn file_renamed_is_logic() {
        let prev = project(&[("src/a.rs", &table(&["12"]))], "cargo");
        let next = project(&[("src/b.rs", &table(&["12"]))], "cargo");
        assert_eq!(classify(&prev, &next), Classification::Logic);
    }

    // A no-op edit (byte-identical emit) is AppearanceOnly with no patches — it
    // stays on the fast path (no recompile for a whitespace-only source edit
    // that the emitter normalises away).
    #[test]
    fn identical_emit_is_empty_appearance_patch() {
        let p = project(&[("src/main.rs", &table(&["12"]))], "cargo");
        assert_eq!(
            classify(&p, &p.clone()),
            Classification::HotSwappable(HotSwap::default())
        );
    }

    // Two views, only one edited: one patch, keyed by that view's own defaults.
    #[test]
    fn only_the_edited_view_is_patched() {
        let prev = project(
            &[(
                "src/main.rs",
                &format!("A {} B {} C", table(&["12"]), table(&["red"])),
            )],
            "cargo",
        );
        let next = project(
            &[(
                "src/main.rs",
                &format!("A {} B {} C", table(&["16"]), table(&["red"])),
            )],
            "cargo",
        );
        let ps = expect_appearance(&prev, &next);
        assert_eq!(ps.len(), 1);
        let p = first_patch(&ps);
        assert_eq!(p.defaults, vec!["12".to_owned()]);
        assert_eq!(p.patch, vec![(0, "16".to_owned())]);
    }

    // Escaped values (quotes/backslashes) round-trip through the parser so the
    // patch carries the unescaped source value the runtime overlay expects.
    #[test]
    fn escaped_value_edit_roundtrips_unescaped() {
        let prev = project(&[("src/main.rs", &table(&["a\"b"]))], "cargo");
        let next = project(&[("src/main.rs", &table(&["a\"c"]))], "cargo");
        let ps = expect_appearance(&prev, &next);
        let p = first_patch(&ps);
        assert_eq!(p.defaults, vec!["a\"b".to_owned()]);
        assert_eq!(p.patch, vec![(0, "a\"c".to_owned())]);
    }

    // A non-ASCII (multi-byte) value round-trips.
    #[test]
    fn multibyte_value_roundtrips() {
        let prev = project(&[("src/main.rs", &table(&["café"]))], "cargo");
        let next = project(&[("src/main.rs", &table(&["thé"]))], "cargo");
        let ps = expect_appearance(&prev, &next);
        assert_eq!(first_patch(&ps).patch, vec![(0, "thé".to_owned())]);
    }

    // A file with no hoisted literals whose body changes is Logic (no arrays to
    // absorb the delta).
    #[test]
    fn non_hoisted_file_body_change_is_logic() {
        let prev = project(&[("src/main.rs", "fn view() { plain }")], "cargo");
        let next = project(&[("src/main.rs", "fn view() { plainer }")], "cargo");
        assert_eq!(classify(&prev, &next), Classification::Logic);
    }

    // Empty defaults arrays on both sides with a body change → Logic (nothing to
    // hoist, the change is real code).
    #[test]
    fn empty_arrays_with_body_change_is_logic() {
        let prev = project(&[("src/main.rs", &format!("x {} y", table(&[])))], "cargo");
        let next = project(&[("src/main.rs", &format!("z {} y", table(&[])))], "cargo");
        assert_eq!(classify(&prev, &next), Classification::Logic);
    }

    // ── transition-data hot-swap (update arm) ─────────────────────────────

    /// Mirror the emitter's classified-arm shape: an arm body emitted as
    /// `apply_transition_hot("<json>", model)`.
    fn transition_arm(json: &str) -> String {
        format!(
            "fn update(msg: Msg, model: Model) {{ match msg {{ \
             Increment => (ipe_runtime::web::apply_transition_hot({json:?}, model), cmd_none()), \
             }} }}"
        )
    }

    const INC1: &str = r#"{"field":"count","op":"IntAdd","source":{"Int":1}}"#;
    const INC2: &str = r#"{"field":"count","op":"IntAdd","source":{"Int":2}}"#;

    // The counter SEAL at the classifier level: a `+1` → `+2` arm edit changes
    // ONLY the baked datum json inside `apply_transition_hot(...)` → a
    // transition-only hot-swap, no recompile.
    #[test]
    fn transition_source_edit_is_hot_swappable() {
        let prev = project(&[("src/update.rs", &transition_arm(INC1))], "cargo");
        let next = project(&[("src/update.rs", &transition_arm(INC2))], "cargo");
        let ts = expect_transitions(&prev, &next);
        assert_eq!(ts.len(), 1);
        assert_eq!(
            ts.first().cloned().unwrap_or_default(),
            TransitionPatch {
                old_json: INC1.to_owned(),
                new_json: INC2.to_owned(),
            }
        );
    }

    // A no-op transition edit (identical) contributes no transition patch.
    #[test]
    fn identical_transition_arm_has_no_patch() {
        let p = project(&[("src/update.rs", &transition_arm(INC1))], "cargo");
        assert_eq!(expect_transitions(&p, &p.clone()), vec![]);
    }

    // A change to the arm STRUCTURE around the transition call (a new arm, a
    // different call) is Logic — only the json argument is masked, never the
    // surrounding code.
    #[test]
    fn arm_structure_change_is_logic() {
        let prev = project(&[("src/update.rs", &transition_arm(INC1))], "cargo");
        let next = project(
            &[(
                "src/update.rs",
                &transition_arm(INC1).replace("cmd_none()", "cmd_batch(vec![])"),
            )],
            "cargo",
        );
        assert_eq!(classify(&prev, &next), Classification::Logic);
    }

    // An arm that GAINS a transition call (arm count grows) is structural → Logic.
    #[test]
    fn added_transition_call_is_logic() {
        let prev = project(&[("src/update.rs", "fn update() { plain }")], "cargo");
        let next = project(&[("src/update.rs", &transition_arm(INC1))], "cargo");
        assert_eq!(classify(&prev, &next), Classification::Logic);
    }

    // ── additive-Msg-set descriptor hot-swap ──────────────────────────────

    /// Assert `classify` returned `HotSwappable` and hand back its `Msg`-set
    /// patches (same discipline as [`expect_appearance`]/[`expect_transitions`]).
    fn expect_msg_sets(prev: &EmittedProject, next: &EmittedProject) -> Vec<MsgSetPatch> {
        let got = classify(prev, next);
        assert!(
            matches!(got, Classification::HotSwappable(_)),
            "expected HotSwappable, got {got:?}"
        );
        if let Classification::HotSwappable(hot) = got {
            hot.msg_sets
        } else {
            Vec::new()
        }
    }

    // ── init-datum hot-swap (session init) ────────────────────────────────

    /// Assert `classify` returned `HotSwappable` and hand back its INIT patches.
    fn expect_inits(prev: &EmittedProject, next: &EmittedProject) -> Vec<InitPatch> {
        let got = classify(prev, next);
        assert!(
            matches!(got, Classification::HotSwappable(_)),
            "expected HotSwappable, got {got:?}"
        );
        if let Classification::HotSwappable(hot) = got {
            hot.inits
        } else {
            Vec::new()
        }
    }

    // ── sub-description hot-swap (subscriptions entry) ────────────────────

    /// Assert `classify` returned `HotSwappable` and hand back its SUB patches
    /// (same discipline as [`expect_transitions`]).
    fn expect_subs(prev: &EmittedProject, next: &EmittedProject) -> Vec<SubPatch> {
        let got = classify(prev, next);
        assert!(
            matches!(got, Classification::HotSwappable(_)),
            "expected HotSwappable, got {got:?}"
        );
        if let Classification::HotSwappable(hot) = got {
            hot.subs
        } else {
            Vec::new()
        }
    }

    /// Mirror the emitter's baked descriptor const, inside an otherwise-identical
    /// app skeleton (so only the descriptor JSON differs between two emits).
    fn app_with_msg_set(json: &str) -> String {
        format!(
            "fn app() {{ const IPE_WEB_MODEL_SCHEMA_TAG: [u8; 32] = [0]; \
             #[allow(dead_code)] const IPE_WEB_MSG_SET: &str = {json:?}; \
             ipe_runtime::tea::WebApp(serve) }}"
        )
    }

    const MS_COUNTER: &str = r#"{"schema":1,"variants":[{"name":"Increment","shape":"Unit"},{"name":"Decrement","shape":"Unit"}]}"#;
    // `Reset` appended — an additive superset.
    const MS_WITH_RESET: &str = r#"{"schema":1,"variants":[{"name":"Increment","shape":"Unit"},{"name":"Decrement","shape":"Unit"},{"name":"Reset","shape":"Unit"}]}"#;
    // `Decrement` removed — a non-additive change.
    const MS_REMOVED: &str = r#"{"schema":1,"variants":[{"name":"Increment","shape":"Unit"}]}"#;
    // `Increment` retyped Unit -> Str — a non-additive change.
    const MS_RETYPED: &str = r#"{"schema":1,"variants":[{"name":"Increment","shape":"Str"},{"name":"Decrement","shape":"Unit"}]}"#;

    // The additive-Msg SEAL at the classifier level: appending a variant to the
    // baked descriptor (skeleton otherwise identical) is a hot-swappable Msg-set
    // patch carrying the OLD (live) descriptor as the key and the NEW as candidate.
    #[test]
    fn added_variant_descriptor_is_hot_swappable() {
        let prev = project(&[("src/main.rs", &app_with_msg_set(MS_COUNTER))], "cargo");
        let next = project(
            &[("src/main.rs", &app_with_msg_set(MS_WITH_RESET))],
            "cargo",
        );
        let ms = expect_msg_sets(&prev, &next);
        assert_eq!(ms.len(), 1);
        assert_eq!(
            ms.first().cloned().unwrap_or_default(),
            MsgSetPatch {
                live_json: MS_COUNTER.to_owned(),
                candidate_json: MS_WITH_RESET.to_owned(),
            }
        );
    }

    /// Mirror the emitter's data-describable `init` shape: an `init` body emitted
    /// as `apply_init_hot("<json>", <compiled record>)`. Both the json AND the
    /// compiled record change on a `count = X` edit.
    fn init_body(json: &str, count: i64) -> String {
        format!(
            "fn init(_req: Req) {{ (ipe_runtime::web::apply_init_hot({json:?}, \
             Model {{ count: {count}i64 }}), cmd_none()) }}"
        )
    }

    const INIT0: &str = r#"{"model":{"count":0}}"#;
    const INIT1: &str = r#"{"model":{"count":1}}"#;

    // The init SEAL at the classifier level: a `count = 0` → `count = 1` init edit
    // changes ONLY the baked datum json AND the paired compiled record (both
    // masked) → an init-only hot-swap, no recompile.
    #[test]
    fn init_source_edit_is_hot_swappable() {
        let prev = project(&[("src/main.rs", &init_body(INIT0, 0))], "cargo");
        let next = project(&[("src/main.rs", &init_body(INIT1, 1))], "cargo");
        let is = expect_inits(&prev, &next);
        assert_eq!(is.len(), 1);
        assert_eq!(
            is.first().cloned().unwrap_or_default(),
            InitPatch {
                old_json: INIT0.to_owned(),
                new_json: INIT1.to_owned(),
            }
        );
    }

    /// Mirror the emitter's classified-entry shape: a subscriptions body emitted as
    /// `ipe_runtime::web::sub_every_hot("<json>")`.
    fn sub_entry(json: &str) -> String {
        format!("fn subscriptions(model: Model) {{ ipe_runtime::web::sub_every_hot({json:?}) }}")
    }

    const SUB1000: &str = r#"{"interval_ms":1000,"msg_json":"\"Tick\""}"#;
    const SUB500: &str = r#"{"interval_ms":500,"msg_json":"\"Tick\""}"#;

    // The interval SEAL at the classifier level: a `1000ms` → `500ms` entry edit
    // changes ONLY the baked datum json inside `sub_every_hot(...)` → a sub-only
    // hot-swap, no recompile.
    #[test]
    fn sub_interval_edit_is_hot_swappable() {
        let prev = project(&[("src/subs.rs", &sub_entry(SUB1000))], "cargo");
        let next = project(&[("src/subs.rs", &sub_entry(SUB500))], "cargo");
        let ss = expect_subs(&prev, &next);
        assert_eq!(ss.len(), 1);
        assert_eq!(
            ss.first().cloned().unwrap_or_default(),
            SubPatch {
                old_json: SUB1000.to_owned(),
                new_json: SUB500.to_owned(),
            }
        );
    }

    // A removed variant in the descriptor is non-additive → Logic (recompile).
    #[test]
    fn removed_variant_descriptor_is_logic() {
        let prev = project(&[("src/main.rs", &app_with_msg_set(MS_COUNTER))], "cargo");
        let next = project(&[("src/main.rs", &app_with_msg_set(MS_REMOVED))], "cargo");
        assert_eq!(classify(&prev, &next), Classification::Logic);
    }

    // A retyped variant in the descriptor is non-additive → Logic (recompile).
    #[test]
    fn retyped_variant_descriptor_is_logic() {
        let prev = project(&[("src/main.rs", &app_with_msg_set(MS_COUNTER))], "cargo");
        let next = project(&[("src/main.rs", &app_with_msg_set(MS_RETYPED))], "cargo");
        assert_eq!(classify(&prev, &next), Classification::Logic);
    }

    // An unchanged descriptor contributes no Msg-set patch.
    #[test]
    fn unchanged_descriptor_has_no_patch() {
        let p = project(&[("src/main.rs", &app_with_msg_set(MS_COUNTER))], "cargo");
        assert_eq!(expect_msg_sets(&p, &p.clone()), vec![]);
    }

    // A descriptor that APPEARS between emits (hot gate flipped / app added) is
    // structural → Logic.
    #[test]
    fn descriptor_appearing_is_logic() {
        let prev = project(&[("src/main.rs", "fn app() { plain }")], "cargo");
        let next = project(&[("src/main.rs", &app_with_msg_set(MS_COUNTER))], "cargo");
        assert_eq!(classify(&prev, &next), Classification::Logic);
    }

    // A no-op sub edit (identical) contributes no sub patch.
    #[test]
    fn identical_sub_entry_has_no_patch() {
        let p = project(&[("src/subs.rs", &sub_entry(SUB1000))], "cargo");
        assert_eq!(expect_subs(&p, &p.clone()), vec![]);
    }

    // A change to the entry STRUCTURE around the sub call (a new call) is Logic —
    // only the json argument is masked, never the surrounding code.
    #[test]
    fn sub_structure_change_is_logic() {
        let prev = project(&[("src/subs.rs", &sub_entry(SUB1000))], "cargo");
        let next = project(
            &[(
                "src/subs.rs",
                &sub_entry(SUB1000).replace("sub_every_hot", "sub_none_wrap"),
            )],
            "cargo",
        );
        assert_eq!(classify(&prev, &next), Classification::Logic);
    }

    // A no-op init edit (identical) contributes no init patch.
    #[test]
    fn identical_init_has_no_patch() {
        let p = project(&[("src/main.rs", &init_body(INIT0, 0))], "cargo");
        assert_eq!(expect_inits(&p, &p.clone()), vec![]);
    }

    // A change to the `init` STRUCTURE around the call (a different kernel) is
    // Logic — only the json and the record arg are masked, never the surrounding
    // code.
    #[test]
    fn init_structure_change_is_logic() {
        let prev = project(&[("src/main.rs", &init_body(INIT0, 0))], "cargo");
        let next = project(
            &[(
                "src/main.rs",
                &init_body(INIT0, 0).replace("cmd_none()", "cmd_batch(vec![])"),
            )],
            "cargo",
        );
        assert_eq!(classify(&prev, &next), Classification::Logic);
    }

    // An entry that GAINS a sub call (call count grows) is structural → Logic.
    #[test]
    fn added_sub_call_is_logic() {
        let prev = project(&[("src/subs.rs", "fn subscriptions() { plain }")], "cargo");
        let next = project(&[("src/subs.rs", &sub_entry(SUB1000))], "cargo");
        assert_eq!(classify(&prev, &next), Classification::Logic);
    }

    // An `init` that GAINS a data-describable call (count grows) is structural →
    // Logic.
    #[test]
    fn added_init_call_is_logic() {
        let prev = project(&[("src/main.rs", "fn init() { plain }")], "cargo");
        let next = project(&[("src/main.rs", &init_body(INIT0, 0))], "cargo");
        assert_eq!(classify(&prev, &next), Classification::Logic);
    }

    // ── Cmd-wiring hot-swap (update arm) ──────────────────────────────────

    /// Assert `classify` returned `HotSwappable` and hand back its WIRING patches.
    fn expect_wirings(prev: &EmittedProject, next: &EmittedProject) -> Vec<WiringPatch> {
        let got = classify(prev, next);
        assert!(
            matches!(got, Classification::HotSwappable(_)),
            "expected HotSwappable, got {got:?}"
        );
        if let Classification::HotSwappable(hot) = got {
            hot.wirings
        } else {
            Vec::new()
        }
    }

    /// Mirror the emitter's classified-arm wiring shape:
    /// `select_cmd_hot("<json>", <count>)`.
    fn wiring_arm(json: &str, count: usize) -> String {
        format!(
            "fn update(msg: Msg, model: Model) {{ match msg {{ \
             Increment => (apply_transition_hot(\"t\", model), \
             ipe_runtime::web::select_cmd_hot({json:?}, {count})), \
             }} }}"
        )
    }

    const WNONE: &str = r#"{"effect":null}"#;
    const WEFF0: &str = r#"{"effect":0}"#;

    // The wiring SEAL at the classifier level: an arm rewired from no-effect to
    // effect id 0 changes ONLY the baked wiring json (the `<count>` is unchanged,
    // so the effect body was already compiled) → a wiring-only hot-swap.
    #[test]
    fn wiring_id_edit_is_hot_swappable() {
        let prev = project(&[("src/update.rs", &wiring_arm(WNONE, 1))], "cargo");
        let next = project(&[("src/update.rs", &wiring_arm(WEFF0, 1))], "cargo");
        let ws = expect_wirings(&prev, &next);
        assert_eq!(ws.len(), 1);
        assert_eq!(
            ws.first().cloned().unwrap_or_default(),
            WiringPatch {
                old_json: WNONE.to_owned(),
                new_json: WEFF0.to_owned(),
            }
        );
    }

    // A no-op wiring edit (identical) contributes no wiring patch.
    #[test]
    fn identical_wiring_arm_has_no_patch() {
        let p = project(&[("src/update.rs", &wiring_arm(WNONE, 1))], "cargo");
        assert_eq!(expect_wirings(&p, &p.clone()), vec![]);
    }

    // A change to the effect COUNT (a genuinely-new effect body grows the arm's
    // compiled effect table) is structural → Logic (recompile the body).
    #[test]
    fn wiring_effect_count_change_is_logic() {
        let prev = project(&[("src/update.rs", &wiring_arm(WEFF0, 1))], "cargo");
        let next = project(&[("src/update.rs", &wiring_arm(WEFF0, 2))], "cargo");
        assert_eq!(classify(&prev, &next), Classification::Logic);
    }

    // ── one character decoded costs O(1), not O(remaining file length) ───

    // A literal with a 4-byte scalar (the longest UTF-8 encoding) decodes
    // correctly; the same `pos` moved one byte into that scalar — off its char
    // boundary, and not the literal's opening quote — refuses rather than
    // guessing at a different character from whatever bytes follow.
    #[test]
    fn decode_reads_at_most_one_scalar() {
        let src = "\"\u{1F600} more text\"";
        let (s, next) = parse_string_literal(src, 0).expect("literal with a 4-byte scalar parses");
        assert_eq!(s, "\u{1F600} more text");
        assert_eq!(next, src.len());

        // Byte 2 is the second byte of the 4-byte scalar: off its char
        // boundary, so the decode refuses instead of decoding past it.
        assert_eq!(parse_string_literal(src, 2), None);
    }

    // A 4 MiB "é…é" literal (2,000,000 two-byte scalars), followed by a later
    // transition datum so the remaining-file tail stays long for every scalar
    // the OLD whole-tail-revalidating decode would re-walk. Quadratic cost
    // here is ~4×10^12 byte checks (minutes to hours); linear cost is
    // milliseconds — a six-order-of-magnitude margin, so the wall budget
    // cannot flake on a slow runner.
    #[test]
    fn large_non_ascii_literal_classifies_in_linear_work() {
        let big = "é".repeat(2_000_000);
        let prev_src = format!("{} {}", table(&[big.as_str()]), transition_arm(INC1));
        let next_src = format!("{} {}", table(&[big.as_str()]), transition_arm(INC2));
        let prev = project(&[("src/main.rs", &prev_src)], "cargo");
        let next = project(&[("src/main.rs", &next_src)], "cargo");

        let start = std::time::Instant::now();
        let got = classify(&prev, &next);
        let elapsed = start.elapsed();

        assert!(
            matches!(got, Classification::HotSwappable(_)),
            "expected HotSwappable, got {got:?}"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(10),
            "classification took {elapsed:?}; expected O(1)-per-scalar decoding \
             to finish well under 10s"
        );
    }
}
