//! Type-structure probes over `Ty` / `canon::Type`: whether a type
//! contains a variable or function, breaks `Clone`, covers a template, or
//! carries a given record-key set, plus signature-template matching.

use std::collections::BTreeMap;

use ipe_canon::ast as canon;
use ipe_intern::{Interner, Symbol};
use ipe_types::{ConHead, EmittedHeads, HeadIdentity, Ty, paired_ty_children};

use super::is_opaque_boxed_wrapper;

/// Does this solved [`Ty`] contain a free type variable anywhere? Used to keep
/// the lowerer's record-shape collection to fully-concrete shapes — a
/// variable-bearing (generic) record reaches the backend through a signature,
/// where the type variable still has a source [`Symbol`] to name the generic.
pub(super) fn ty_contains_var(ty: &Ty) -> bool {
    match ty {
        Ty::Var(_) | Ty::Wildcard => true,
        Ty::Unit => false,
        Ty::Fun(a, b) => ty_contains_var(a) || ty_contains_var(b),
        Ty::Tuple(elems) => elems.iter().any(ty_contains_var),
        Ty::Record(fields, _) => fields.values().any(ty_contains_var),
        Ty::Con { args, .. } => args.iter().any(ty_contains_var),
    }
}

/// Does this solved [`Ty`] contain a function type anywhere?
///
/// A field of a synthesised record struct whose type embeds a `Box<dyn Fn>`
/// cannot satisfy the struct's derived `Clone`/`Debug`/`PartialEq` nor its
/// `IpeStringify` impl — so the field type carrying a function is the unsound
/// shape. Used by [`embeds_nonderivable_function`] to test a payload field.
pub(super) fn ty_contains_fun(ty: &Ty) -> bool {
    match ty {
        Ty::Fun(_, _) => true,
        Ty::Var(_) | Ty::Wildcard | Ty::Unit => false,
        Ty::Tuple(elems) => elems.iter().any(ty_contains_fun),
        Ty::Con { args, .. } => args.iter().any(ty_contains_fun),
        Ty::Record(fields, _) => fields.values().any(ty_contains_fun),
    }
}

/// Does `ty` store a function inside a DERIVE CARRIER — a record field, a
/// user-enum / collection / tuple payload — as opposed to a bare arrow or a
/// function behind an opaque boxed wrapper?
///
/// A derive carrier is a Rust struct/enum the backend `#[derive]`s `Clone` over,
/// so a function reaching one through a generic type parameter emits a
/// `<T: Clone>` bound the `Box<dyn Fn>` value cannot discharge. An opaque boxed
/// wrapper (`Decoder`/`Task`/`Cmd`/`Sub`) renders to a `Clone` handle over its
/// payload and derives nothing over it, so a function there is legitimate and is
/// NOT flagged. Used by the computed-callee gate
/// ([`Lowerer::reject_value_callee_fn_into_carrier`]) to decide whether a value
/// callee's result laundered a function into a carrier the value path cannot
/// `Arc`-promote.
pub(super) fn ty_has_fun_in_derive_carrier(interner: &Interner, ty: &Ty) -> bool {
    match ty {
        Ty::Var(_) | Ty::Wildcard | Ty::Unit => false,
        // A bare arrow at the top of the walk is a direct position, not a
        // carrier field; recurse its own operand/result so a carrier nested
        // inside an arrow type is still seen.
        Ty::Fun(a, b) => {
            ty_has_fun_in_derive_carrier(interner, a) || ty_has_fun_in_derive_carrier(interner, b)
        }
        Ty::Tuple(elems) => elems.iter().any(ty_contains_fun),
        // An opaque boxed wrapper stores its payload behind a trait object and
        // derives nothing over it — a function there is legitimate.
        Ty::Con { name, .. } if is_opaque_boxed_wrapper(interner, *name) => false,
        // Every other constructor head (a user enum, a builtin collection) is a
        // derive carrier over its type arguments.
        Ty::Con { args, .. } => args.iter().any(ty_contains_fun),
        Ty::Record(fields, _) => fields.values().any(ty_contains_fun),
    }
}

/// Does instantiating a generic type parameter to `ty` make the emitted Rust
/// generic parameter's unconditional `Clone` bound unsatisfiable?
///
/// A generic user function emits `fn f<T1: Clone>(..)` (`render_fn_generics`
/// injects `Clone` on every type parameter, and generic composite structs
/// derive `Clone` with a `T1: Clone` bound). A function value instantiating
/// that parameter lowers to a `Box<dyn Fn>` — which is not `Clone` — so the
/// instantiation is cargo-broken (E0277) regardless of the surrounding shape.
/// This predicate is the value-side condition for that breakage: a function
/// reachable in `ty` that is NOT stored behind an opaque boxed wrapper
/// (`Decoder`/`Task`/`Cmd`/`Sub`, whose Rust rendering IS `Clone` over any
/// payload). A function behind such a wrapper does not break the bound and is
/// not flagged; a bare function, or one nested in a tuple / record / collection
/// / enum payload, does.
pub(super) fn generic_binding_breaks_clone(interner: &Interner, ty: &Ty) -> bool {
    match ty {
        Ty::Fun(_, _) => true,
        Ty::Var(_) | Ty::Wildcard | Ty::Unit => false,
        Ty::Tuple(elems) => elems
            .iter()
            .any(|e| generic_binding_breaks_clone(interner, e)),
        // An opaque boxed wrapper renders to a `Clone` handle over its payload
        // (the payload lives behind a trait object), so a function under it does
        // not break the parameter's `Clone` bound.
        Ty::Con { name, .. } if is_opaque_boxed_wrapper(interner, *name) => false,
        Ty::Con { args, .. } => args
            .iter()
            .any(|a| generic_binding_breaks_clone(interner, a)),
        Ty::Record(fields, _) => fields
            .values()
            .any(|f| generic_binding_breaks_clone(interner, f)),
    }
}

/// Does the covering `template` type match the literal's `concrete` field type,
/// treating a template-side type VARIABLE as a wildcard that matches anything?
///
/// This mirrors the backend's `record_struct_by_key` disambiguation: a
/// synthesised struct registered from a signature/ctor is either monomorphic
/// (its field types must equal the literal's exactly) or generic (a template
/// variable at a field position instantiates to the literal's concrete type).
/// The gate must accept exactly the shapes the backend can synthesise, so the
/// coverage check compares field types with the SAME rule — never merely the
/// field-name set (which would accept a `{ run : Int }` signature covering a
/// `{ run = \n -> … }` literal and emit an `Arc<dyn Fn>` value into an `i64`
/// field: an accept-then-cargo-E0308 SEAL break).
///
/// Constructor heads compare under [`HeadIdentity::Emitted`] with `lowering`
/// as the oracle: two heads cover each other exactly when both lower to one
/// emitted type, the identity the backend's struct-template match compares.
/// A reserved builtin spelled under its stdlib home covers its empty-home
/// kernel spelling; a same-named union of another module never covers.
pub(super) fn ty_covers_as_template(
    template: &Ty,
    concrete: &Ty,
    lowering: &dyn EmittedHeads,
) -> bool {
    match (template, concrete) {
        // A template variable instantiates to any concrete type; unit matches
        // unit — both admit their concrete unconditionally.
        (Ty::Var(_) | Ty::Wildcard, _) | (Ty::Unit, Ty::Unit) => true,
        (Ty::Record(tf, _), Ty::Record(cf, _)) => {
            tf.len() == cf.len()
                && tf.iter().all(|(k, tv)| {
                    cf.get(k)
                        .is_some_and(|cv| ty_covers_as_template(tv, cv, lowering))
                })
        }
        _ => paired_ty_children(template, concrete, HeadIdentity::Emitted(lowering))
            .is_some_and(|mut pairs| pairs.all(|(t, c)| ty_covers_as_template(t, c, lowering))),
    }
}

/// Does `ty` (or any type nested within it) contain a record that COVERS the
/// function-field record literal whose field types are `lit_fields`?
///
/// Coverage is TYPE-aware, not field-name-only: a candidate record covers only
/// when its field-name set matches AND every field type matches the literal's
/// (a template variable on the candidate side is a wildcard, exactly as the
/// backend's generic-struct instantiation allows). A name-only match against a
/// record with a differently-typed field (`{ run : Int }`, or even
/// `{ run : String -> String }` for a `{ run : Int -> Int }` literal) registers
/// a struct whose field type the literal's value does not fit — an
/// accept-then-cargo-E0308 SEAL break.
///
/// Used by [`Lowerer::fn_field_record_covered_by_signature`] to determine
/// whether a function-field record literal's shape appears in at least one
/// top-level binding's inferred type — the condition under which the backend's
/// signature scan will register the struct, making a separate
/// [`collect_records_in_ty`] registration unnecessary.
pub(super) fn ty_contains_record_key_set(
    ty: &Ty,
    lit_fields: &BTreeMap<Symbol, Ty>,
    lowering: &dyn EmittedHeads,
) -> bool {
    match ty {
        Ty::Record(fields, _) => {
            if fields.len() == lit_fields.len()
                && lit_fields.iter().all(|(k, lv)| {
                    fields
                        .get(k)
                        .is_some_and(|cv| ty_covers_as_template(cv, lv, lowering))
                })
            {
                return true;
            }
            fields
                .values()
                .any(|f| ty_contains_record_key_set(f, lit_fields, lowering))
        }
        Ty::Fun(a, b) => {
            ty_contains_record_key_set(a, lit_fields, lowering)
                || ty_contains_record_key_set(b, lit_fields, lowering)
        }
        Ty::Tuple(elems) => elems
            .iter()
            .any(|e| ty_contains_record_key_set(e, lit_fields, lowering)),
        Ty::Con { args, .. } => args
            .iter()
            .any(|a| ty_contains_record_key_set(a, lit_fields, lowering)),
        Ty::Var(_) | Ty::Wildcard | Ty::Unit => false,
    }
}

/// Does the covering canonical `template` type match the literal's `concrete`
/// [`Ty`] field type, treating a canon type VARIABLE as a wildcard?  The
/// canon/[`Ty`] cross-representation mirror of [`ty_covers_as_template`], used
/// for union constructor payload types (declared as [`canon::Type`]); its
/// constructor heads compare under the same [`HeadIdentity::Emitted`] rule, the
/// canon head's home lowered over the concrete side's arguments.
pub(super) fn canon_covers_as_template(
    template: &canon::Type,
    concrete: &Ty,
    lowering: &dyn EmittedHeads,
) -> bool {
    match (template, concrete) {
        (canon::Type::Var(_) | canon::Type::Wildcard, _) | (canon::Type::Unit, Ty::Unit) => true,
        (canon::Type::Lambda(tp, tr), Ty::Fun(cp, cr)) => {
            canon_covers_as_template(tp, cp, lowering) && canon_covers_as_template(tr, cr, lowering)
        }
        (canon::Type::Tuple(ts), Ty::Tuple(cs)) => {
            ts.len() == cs.len()
                && ts
                    .iter()
                    .zip(cs)
                    .all(|(t, c)| canon_covers_as_template(t, c, lowering))
        }
        (
            canon::Type::Con {
                home: th,
                name: tn,
                args: ta,
            },
            Ty::Con {
                module: cm,
                name: cn,
                args: ca,
            },
        ) => HeadIdentity::Emitted(lowering)
            .paired_args(
                ConHead {
                    home: th,
                    name: *tn,
                    args: ta,
                },
                ConHead {
                    home: cm,
                    name: *cn,
                    args: ca,
                },
            )
            .is_some_and(|mut pairs| pairs.all(|(t, c)| canon_covers_as_template(t, c, lowering))),
        // A closed record must cover the literal field-for-field. An open row
        // `{ r | … }` is treated the same: its declared fields must present and
        // match the literal exactly (the literal is a closed record, so extra
        // absorbed fields would change the synthesised struct — reject them).
        (canon::Type::Record(tf) | canon::Type::RecordOpen(_, tf), Ty::Record(cf, _)) => {
            tf.len() == cf.len()
                && tf.iter().all(|(k, tv)| {
                    cf.get(k)
                        .is_some_and(|cv| canon_covers_as_template(tv, cv, lowering))
                })
        }
        _ => false,
    }
}

/// Does `ty` (or any type nested within it) contain a record that covers the
/// function-field record literal (`lit_fields`)?  Mirrors
/// [`ty_contains_record_key_set`] for the canonical [`canon::Type`] used in
/// union constructor payload declarations — so the gate can check whether a
/// function-field record shape is covered by an ADT constructor and will
/// therefore be registered by the backend's enum variant field scan
/// (`collect_record_shapes` over `module.types`).  Coverage is TYPE-aware via
/// [`canon_covers_as_template`], never field-name-only.
pub(super) fn canon_type_contains_record_key_set(
    ty: &canon::Type,
    lit_fields: &BTreeMap<Symbol, Ty>,
    lowering: &dyn EmittedHeads,
) -> bool {
    let covers = |fields: &[(Symbol, canon::Type)]| -> bool {
        fields.len() == lit_fields.len()
            && lit_fields.iter().all(|(k, lv)| {
                fields
                    .iter()
                    .any(|(name, ft)| name == k && canon_covers_as_template(ft, lv, lowering))
            })
    };
    match ty {
        canon::Type::Record(fields) => {
            covers(fields)
                || fields
                    .iter()
                    .any(|(_, ft)| canon_type_contains_record_key_set(ft, lit_fields, lowering))
        }
        canon::Type::Lambda(a, b) => {
            canon_type_contains_record_key_set(a, lit_fields, lowering)
                || canon_type_contains_record_key_set(b, lit_fields, lowering)
        }
        canon::Type::Tuple(elems) => elems
            .iter()
            .any(|e| canon_type_contains_record_key_set(e, lit_fields, lowering)),
        canon::Type::Con { args, .. } => args
            .iter()
            .any(|a| canon_type_contains_record_key_set(a, lit_fields, lowering)),
        canon::Type::RecordOpen(_, fields) => {
            covers(fields)
                || fields
                    .iter()
                    .any(|(_, ft)| canon_type_contains_record_key_set(ft, lit_fields, lowering))
        }
        canon::Type::Var(_) | canon::Type::Wildcard | canon::Type::Unit => false,
    }
}

/// Match a declared signature-template type against the solved (monomorphic)
/// type it was instantiated to at a use site, recording each template type
/// variable's binding in `subst`. Structural, one arm per [`Ty`] shape; a
/// template variable binds to the whole concrete sub-type at its position, and
/// a template arrow / tuple / record / constructor recurses structurally.
///
/// A shape or arity mismatch (a solved region that does not instantiate the
/// template) leaves `subst` as far as it got and returns without error: the
/// gate this feeds only ever *adds* a rejection, so an incomplete match can at
/// worst miss a binding (fail-open for that argument), never fabricate one. The
/// caller treats a fabricated binding as the only unsound direction, and there
/// is none: a variable is bound solely to the concrete type structurally
/// aligned with its declared position.
///
/// Template and concrete were unified, so constructor heads compare under
/// [`HeadIdentity::Unified`], the rule inference applied to them.
pub(super) fn match_signature_template(
    template: &Ty,
    concrete: &Ty,
    subst: &mut BTreeMap<u32, Ty>,
    interner: &Interner,
) {
    match (template, concrete) {
        (Ty::Var(v), _) => {
            subst.entry(*v).or_insert_with(|| concrete.clone());
        }
        // A wildcard names no variable, so it binds nothing.
        (Ty::Wildcard, _) => {}
        (Ty::Record(tf, _), Ty::Record(cf, _)) => {
            for (k, tv) in tf {
                if let Some(cv) = cf.get(k) {
                    match_signature_template(tv, cv, subst, interner);
                }
            }
        }
        _ => {
            for (t, c) in paired_ty_children(template, concrete, HeadIdentity::Unified(interner))
                .into_iter()
                .flatten()
            {
                match_signature_template(t, c, subst, interner);
            }
        }
    }
}
