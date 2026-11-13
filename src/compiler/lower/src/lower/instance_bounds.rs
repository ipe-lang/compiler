//! The supply side of every runtime bound a callee puts on a value.
//!
//! A kernel's runtime function ([`ipe_kernels::StdlibKernel::runtime_bounds`])
//! and a user function's emitted generic ([`ipe_ir::Func::type_params`]) each
//! demand Rust traits of the type a reference instantiates them at. This
//! module answers, for one demanded [`Bound`] and one lowered instance type,
//! whether the type supplies it ([`bound_met_by`]). The lowerer refuses an
//! unmet demand with IPE-L0164 at the reference, so `cargo` never meets an
//! instance `ipe` accepted and the trait refuses.

use std::cell::{Cell, OnceCell, RefCell};
use std::collections::{BTreeMap, HashMap};

use ipe_diagnostics::{CalleeDemand, Diagnostic, LowerError, ModelLeaf, Span};
use ipe_intern::{Interner, Symbol};
use ipe_ir::{BoundSet, CarrierLeaf, Func, FuncId, IrType, ModPath};

use super::clone_class::{
    CloneClass, CloneEnv, bounded_nonclone, clone_class, enum_is_opaque_ffi_handle,
};
use super::signature_bounds::generics_are_clone;
use super::{CalleeInstance, SiteSlot, bound_vars};

/// One trait of a [`BoundSet`], the unit a callee demands and an instance supplies.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Bound {
    /// Wrapping `+`.
    Add,
    /// Wrapping `-`.
    Sub,
    /// Wrapping `*`.
    Mul,
    /// `PartialOrd`.
    Ord,
    /// `Copy`.
    Copy,
    /// `Clone`.
    Clone,
    /// `PartialEq`.
    Eq,
    /// `Ord`, the total order.
    OrdTotal,
    /// `Hash`.
    Hash,
    /// `IpeStringify`.
    Show,
    /// `Into<SqlParam>`.
    SqlParam,
    /// `IpeRow`.
    IpeRow,
    /// `IpeInterpolate`.
    Interpolable,
    /// `'static`.
    Static,
    /// `Send`.
    Send,
    /// `Sync`.
    Sync,
}

impl Bound {
    /// Every bound, one per [`BoundSet`] bit.
    pub(super) const ALL: [Self; 16] = [
        Self::Add,
        Self::Sub,
        Self::Mul,
        Self::Ord,
        Self::Copy,
        Self::Clone,
        Self::Eq,
        Self::OrdTotal,
        Self::Hash,
        Self::Show,
        Self::SqlParam,
        Self::IpeRow,
        Self::Interpolable,
        Self::Static,
        Self::Send,
        Self::Sync,
    ];

    /// Whether `set` holds this bound.
    pub(super) const fn in_set(self, set: BoundSet) -> bool {
        match self {
            Self::Add => set.has_add(),
            Self::Sub => set.has_sub(),
            Self::Mul => set.has_mul(),
            Self::Ord => set.has_ord(),
            Self::Copy => set.has_copy(),
            Self::Clone => set.has_clone(),
            Self::Eq => set.has_eq(),
            Self::OrdTotal => set.has_ord_total(),
            Self::Hash => set.has_hash(),
            Self::Show => set.has_show(),
            Self::SqlParam => set.has_sql_param(),
            Self::IpeRow => set.has_ipe_row(),
            Self::Interpolable => set.has_interpolable(),
            Self::Static => set.has_static(),
            Self::Send => set.has_send(),
            Self::Sync => set.has_sync(),
        }
    }

    /// The bounds a kernel's runtime-bound row demands, in [`Self::ALL`] order.
    pub(super) fn of_runtime(row: ipe_kernels::RuntimeBounds) -> impl Iterator<Item = Self> {
        use ipe_kernels::RuntimeBounds;
        [
            (RuntimeBounds::CLONE, Self::Clone),
            (RuntimeBounds::PARTIAL_EQ, Self::Eq),
            (RuntimeBounds::SYNC, Self::Sync),
        ]
        .into_iter()
        .filter(move |(bit, _)| row.contains(*bit))
        .map(|(_, bound)| bound)
    }
}

/// Whether an instance type supplies one demanded bound.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(super) enum Supply {
    /// The type supplies the bound.
    Met,
    /// The type does not supply the bound; `leaf` names the part that lacks it.
    Unmet {
        /// What the callee does with the value, in Ipê words.
        demand: CalleeDemand,
        /// The offending part of the type, as the diagnostic names it.
        leaf: Box<str>,
    },
    /// The type is a generic of the referencing function, which carries the
    /// demand to that function's own references.
    Forwarded,
}

/// Whether a value of `ty` supplies the bound `bound`.
///
/// A bare generic or row variable of the referencing function is
/// [`Supply::Forwarded`]: the cross-call fixpoint copies the demand onto it,
/// and every generic is `Clone` ([`generics_are_clone`]). A concrete type is
/// judged per row:
///
/// - `Clone`: the type is `Clone` under the emitted generic bound
///   ([`bounded_nonclone`]); a function is `Clone` only on the shared `Arc`
///   carrier ([`IrType::SharedFun`]).
/// - `Copy`: the type is a `Copy` scalar or a tuple of them.
/// - `Sync`, `Send` and `'static` on a concrete type: met. The per-carrier
///   auto-trait table is #2961's; until it lands no row refuses here. Every
///   kernel `Sync` row also demands `Clone`, and every user generic is
///   `Clone`, so a non-`Sync` effect carrier is refused by its `Clone` row
///   first.
/// - `IpeRow`: the runtime implements it for exactly `Dict String String`
///   and `WebReq`.
/// - `PartialEq`: the type is derivable by the predicate the backend derives
///   by ([`eq_supplied`]); the type checker's `Equatable` obligation refuses
///   the same types first (IPE-T0014), so this is the second boundary.
/// - Arithmetic, ordering, hashing, rendering, interpolation and SQL
///   parameters are proven by the type checker's obligations before
///   lowering (`TyBounds`, IPE-T0014), so they are met here.
pub(super) fn bound_met_by(env: CloneEnv<'_>, bound: Bound, ty: &IrType) -> Supply {
    if matches!(ty, IrType::Generic(_) | IrType::RowGeneric(_)) {
        return if bound == Bound::Clone && generics_are_clone() {
            Supply::Met
        } else {
            Supply::Forwarded
        };
    }
    match bound {
        Bound::Clone => {
            if bounded_nonclone(env, ty) {
                Supply::Unmet {
                    demand: CalleeDemand::Copies,
                    leaf: nonclone_leaf_name(env, ty),
                }
            } else {
                Supply::Met
            }
        }
        Bound::Copy => {
            if is_copy(env, ty) {
                Supply::Met
            } else {
                Supply::Unmet {
                    demand: CalleeDemand::Copies,
                    leaf: whole_type_name(env.interner, ty),
                }
            }
        }
        Bound::IpeRow => {
            let row = matches!(ty, IrType::WebReq)
                || matches!(ty, IrType::Dict(k, v) if **k == IrType::Str && **v == IrType::Str);
            if row {
                Supply::Met
            } else {
                Supply::Unmet {
                    demand: CalleeDemand::ReadsAsRow,
                    leaf: whole_type_name(env.interner, ty),
                }
            }
        }
        Bound::Eq => eq_supplied(env, None, ty),
        Bound::Static
        | Bound::Send
        | Bound::Sync
        | Bound::Add
        | Bound::Sub
        | Bound::Mul
        | Bound::Ord
        | Bound::OrdTotal
        | Bound::Hash
        | Bound::Show
        | Bound::SqlParam
        | Bound::Interpolable => Supply::Met,
    }
}

/// Whether a value of `ty` supplies `PartialEq`.
///
/// Judged by [`ipe_ir::ir_type_is_derivable`], the predicate the backend
/// derives an enum's `PartialEq` by: a registered enum answers its
/// [`ipe_ir::enum_derivable_fixpoint`] fact (`enum_derivable` when the caller
/// holds it, else computed once here and only when the walk meets an enum),
/// any other enum [`ipe_ir::unregistered_enum_derivable`]. A generic is
/// derivable: its `PartialEq` is the referencing function's own bound.
pub(super) fn eq_supplied(
    env: CloneEnv<'_>,
    enum_derivable: Option<&BTreeMap<(ModPath, Symbol), bool>>,
    ty: &IrType,
) -> Supply {
    let computed: OnceCell<BTreeMap<(ModPath, Symbol), bool>> = OnceCell::new();
    let lookup = |home: &ModPath, name: Symbol| {
        enum_derivable
            .unwrap_or_else(|| {
                computed.get_or_init(|| ipe_ir::enum_derivable_fixpoint(env.interner, env.payloads))
            })
            .get(&(home.clone(), name))
            .copied()
            .unwrap_or_else(|| ipe_ir::unregistered_enum_derivable(env.interner, home, name))
    };
    if ipe_ir::ir_type_is_derivable(ty, &lookup) {
        Supply::Met
    } else {
        Supply::Unmet {
            demand: CalleeDemand::Compares,
            leaf: whole_type_name(env.interner, ty),
        }
    }
}

/// Whether a value of `ty` is Rust `Copy`: a `Copy` scalar, or a tuple of them.
fn is_copy(env: CloneEnv<'_>, ty: &IrType) -> bool {
    if let IrType::Tuple(items) = ty {
        return items
            .iter()
            .all(|item| clone_class(env, item) == CloneClass::CopyLeaf);
    }
    clone_class(env, ty) == CloneClass::CopyLeaf
}

/// The name of the first non-`Clone` part of `ty`, as IPE-L0164 prints it.
fn nonclone_leaf_name(env: CloneEnv<'_>, ty: &IrType) -> Box<str> {
    let leaf = first_nonclone_leaf(env, ty);
    whole_type_name(env.interner, leaf.as_ref().unwrap_or(ty))
}

/// The first part of `ty` with no `Clone` of its own, in the shared held walk's order.
fn first_nonclone_leaf(env: CloneEnv<'_>, ty: &IrType) -> Option<IrType> {
    let found: RefCell<Option<IrType>> = RefCell::new(None);
    let held = ipe_ir::ir_type_holds(ty, env.payloads, &|t| {
        let leaf = is_nonclone_leaf(env, t);
        if leaf {
            found.borrow_mut().get_or_insert_with(|| t.clone());
        }
        leaf
    });
    found.into_inner().filter(|_| held)
}

/// Whether `t` itself lacks `Clone`: a non-`Clone` default carrier or an opaque FFI handle.
fn is_nonclone_leaf(env: CloneEnv<'_>, t: &IrType) -> bool {
    let opaque_ffi = matches!(t, IrType::Enum { home, name, .. }
        if enum_is_opaque_ffi_handle(env, home, *name));
    opaque_ffi
        || (matches!(ipe_ir::carrier_leaf(t), CarrierLeaf::NonClone)
            && !matches!(t, IrType::Generic(_) | IrType::RowGeneric(_)))
}

/// What an app-role refusal blames in a non-`Clone` Model or Msg `ty`.
///
/// The record field holding the first non-`Clone` part (empty when `ty` is
/// no record) and that part's kind. `None` when `ty` is `Clone`, so the role
/// check refuses exactly what the callee-bound `Clone` check would.
fn nonclone_role_blame(env: CloneEnv<'_>, ty: &IrType) -> Option<(Box<str>, ModelLeaf)> {
    if !bounded_nonclone(env, ty) {
        return None;
    }
    let field = match ty {
        IrType::Record(fields) => fields
            .iter()
            .find(|(_, field_ty)| bounded_nonclone(env, field_ty))
            .and_then(|(sym, _)| env.interner.resolve(*sym))
            .unwrap_or(""),
        _ => "",
    };
    let leaf = first_nonclone_leaf(env, ty)
        .and_then(|leaf| leaf_kind(&leaf))
        // The remaining non-`Clone` leaves: an app handle or an opaque FFI handle.
        .unwrap_or(ModelLeaf::Handle);
    Some((field.into(), leaf))
}

/// What an app-role refusal blames in a Model or Msg `ty` that misses `bound`.
///
/// The record field holding the first part that misses it (empty when `ty`
/// is no record) and that part's kind. `None` when `ty` supplies `bound`
/// ([`bound_met_by`], with `PartialEq` judged by the module's
/// `enum_derivable` facts), so the role gate refuses exactly what the app
/// entry's callee-bound check would.
pub(super) fn role_blame(
    env: CloneEnv<'_>,
    enum_derivable: &BTreeMap<(ModPath, Symbol), bool>,
    bound: Bound,
    ty: &IrType,
) -> Option<(Box<str>, ModelLeaf)> {
    if bound == Bound::Clone {
        return nonclone_role_blame(env, ty);
    }
    let misses = |t: &IrType| {
        let supply = if bound == Bound::Eq {
            eq_supplied(env, Some(enum_derivable), t)
        } else {
            bound_met_by(env, bound, t)
        };
        matches!(supply, Supply::Unmet { .. })
    };
    if !misses(ty) {
        return None;
    }
    let field = match ty {
        IrType::Record(fields) => fields
            .iter()
            .find(|(_, field_ty)| misses(field_ty))
            .and_then(|(sym, _)| env.interner.resolve(*sym))
            .unwrap_or(""),
        _ => "",
    };
    let found: Cell<Option<ModelLeaf>> = Cell::new(None);
    let held = ipe_ir::ir_type_holds(ty, env.payloads, &|t| {
        let kind = leaf_kind(t);
        if found.get().is_none() {
            found.set(kind);
        }
        kind.is_some()
    });
    // A miss with no function, effect or decoder part is an opaque handle's.
    let leaf = found.get().filter(|_| held).unwrap_or(ModelLeaf::Handle);
    Some((field.into(), leaf))
}

/// The kind an app-role refusal names `t` by, when `t` is a function, an effect or a decoder.
const fn leaf_kind(t: &IrType) -> Option<ModelLeaf> {
    match t {
        IrType::Fun(..) | IrType::FnOnceChain(..) | IrType::SharedFun(..) => {
            Some(ModelLeaf::Function)
        }
        IrType::Cmd(_) => Some(ModelLeaf::Command),
        IrType::Sub(_) => Some(ModelLeaf::Subscription),
        IrType::Task(_) => Some(ModelLeaf::Task),
        IrType::Decoder(_) => Some(ModelLeaf::Decoder),
        _ => None,
    }
}

/// The head of `ty` in Ipê words: `Task`, `function`, a union's own name.
fn whole_type_name(interner: &Interner, ty: &IrType) -> Box<str> {
    let name = if matches!(ty, IrType::Task(_)) {
        "Task"
    } else if matches!(ty, IrType::Cmd(_)) {
        "Cmd"
    } else if matches!(ty, IrType::Sub(_)) {
        "Sub"
    } else if matches!(
        ty,
        IrType::Fun(..) | IrType::FnOnceChain(..) | IrType::SharedFun(..)
    ) {
        "function"
    } else if matches!(
        ty,
        IrType::WebApp | IrType::TuiApp | IrType::CliApp | IrType::WorkerApp
    ) {
        "app handle"
    } else if let IrType::Enum { name, .. } = ty {
        interner.resolve(*name).unwrap_or("value")
    } else if matches!(ty, IrType::Str) {
        "String"
    } else if matches!(ty, IrType::List(_)) {
        "List"
    } else if matches!(ty, IrType::Maybe(_)) {
        "Maybe"
    } else if matches!(ty, IrType::Record(_)) {
        "record"
    } else {
        "value"
    };
    name.into()
}

/// The IPE-L0164 refusal of `callee`'s `demand` at `span`, naming `leaf`.
pub(super) const fn callee_bound_unmet(
    span: Span,
    callee: Box<str>,
    demand: CalleeDemand,
    leaf: Box<str>,
) -> Diagnostic {
    Diagnostic::Lower {
        span,
        msg: LowerError::CalleeBoundUnmet {
            callee,
            demand,
            leaf,
        },
    }
}

/// Refuse every user-function reference whose concrete instance misses a bound of the callee's generics.
///
/// Each recorded reference ([`CalleeInstance`]) is aligned against its
/// callee's signature, every parameter and then the return type, through the
/// shapes both share. Every type a callee generic is instantiated with is
/// judged against that generic's finalized bounds ([`bound_met_by`]). Runs
/// after the cross-call fixpoint, so a bound a callee only acquires through
/// its own callees is demanded too.
///
/// A slot the reference's solved type lowers only with its unfixed type
/// variables read as `JsonVal` ([`SiteSlot::Unlowered`]) is judged on that
/// reading, the carrier its call pin settles it to. Fail-closed: a slot that
/// mentions a bounded generic but has no solved type, or one that does not
/// lower even so, is refused. A site of a shape the signature does not share
/// names no instance there; the fixpoint obliges every generic of the
/// referencing function it mentions.
///
/// `Err` carries the referencing function and the refusal, at the reference.
pub(super) fn check_user_instances(
    funcs: &[Func],
    instances: &HashMap<FuncId, Vec<CalleeInstance>>,
    env: CloneEnv<'_>,
) -> Result<(), (FuncId, Diagnostic)> {
    let by_id: HashMap<FuncId, &Func> = funcs.iter().map(|f| (f.id, f)).collect();
    for caller in funcs {
        let Some(refs) = instances.get(&caller.id) else {
            continue;
        };
        for instance in refs {
            let Some(callee) = by_id.get(&instance.callee) else {
                continue;
            };
            check_instance(callee, instance, env).map_err(|d| (caller.id, d))?;
        }
    }
    Ok(())
}

/// [`check_user_instances`] for one reference to `callee`.
fn check_instance(
    callee: &Func,
    instance: &CalleeInstance,
    env: CloneEnv<'_>,
) -> Result<(), Diagnostic> {
    let slots = callee
        .params
        .iter()
        .enumerate()
        .map(|(i, p)| (&p.ty, instance.params.get(i)))
        .chain(std::iter::once((
            &callee.ret,
            instance.tails.get(callee.params.len()),
        )));
    let slots: Vec<(&IrType, Option<&SiteSlot>)> = slots.collect();
    let name = || -> Box<str> {
        env.interner
            .resolve(callee.name)
            .unwrap_or("function")
            .into()
    };
    for (target, bounds) in bound_vars(callee) {
        if bounds.is_unbounded() {
            continue;
        }
        for (sig, site) in &slots {
            if !super::ir_type_mentions_generic(sig, target) {
                continue;
            }
            let site = match site {
                Some(SiteSlot::Lowered(site) | SiteSlot::Unlowered(_, Some(site))) => site,
                Some(SiteSlot::Unlowered(_, None)) | None => {
                    return Err(callee_bound_unmet(
                        instance.span,
                        name(),
                        CalleeDemand::Copies,
                        "value of unknown type".into(),
                    ));
                }
            };
            let mut found: Vec<&IrType> = Vec::new();
            if !aligned_instances(sig, target, site, &mut found) {
                continue;
            }
            for ty in found {
                for bound in Bound::ALL.into_iter().filter(|b| b.in_set(bounds)) {
                    if let Supply::Unmet { demand, leaf } = bound_met_by(env, bound, ty) {
                        return Err(callee_bound_unmet(instance.span, name(), demand, leaf));
                    }
                }
            }
        }
    }
    Ok(())
}

/// Collect into `out` every part of `site` the generic `target` of `sig` is instantiated with.
///
/// Walks `sig` alongside `site` through the shapes they share, as
/// `align_param_slot` does: the three function carriers pair with one
/// another, every other shape through [`ipe_ir::paired_children`]. `false`
/// when `target` sits under a `sig` shape `site` does not share.
fn aligned_instances<'s>(
    sig: &'s IrType,
    target: Symbol,
    site: &'s IrType,
    out: &mut Vec<&'s IrType>,
) -> bool {
    if !super::ir_type_mentions_generic(sig, target) {
        return true;
    }
    if matches!(sig, IrType::Generic(_) | IrType::RowGeneric(_)) {
        out.push(site);
        return true;
    }
    match (sig, site) {
        (IrType::Record(a), IrType::Record(b)) => a.iter().all(|(field, ca)| {
            b.get(field)
                .is_some_and(|cb| aligned_instances(ca, target, cb, out))
        }),
        (
            IrType::Fun(pa, ra) | IrType::SharedFun(pa, ra) | IrType::FnOnceChain(pa, ra),
            IrType::Fun(pb, rb) | IrType::SharedFun(pb, rb) | IrType::FnOnceChain(pb, rb),
        ) => {
            pa.len() == pb.len()
                && pa
                    .iter()
                    .zip(pb)
                    .all(|(ca, cb)| aligned_instances(ca, target, cb, out))
                && aligned_instances(ra, target, rb, out)
        }
        _ => ipe_ir::paired_children(sig, site)
            .is_some_and(|mut pairs| pairs.all(|(ca, cb)| aligned_instances(ca, target, cb, out))),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use ipe_diagnostics::{CalleeDemand, ModelLeaf};
    use ipe_intern::Interner;
    use ipe_ir::{BoundSet, EnumPayloadTable, IrType, ModPath};

    use super::{Bound, CloneEnv, Supply, bound_met_by, role_blame};

    /// Run `check` with an empty classification context.
    fn with_env(check: impl FnOnce(CloneEnv<'_>)) {
        let interner = Interner::new();
        let ffi = BTreeSet::new();
        let payloads = EnumPayloadTable::new();
        check(CloneEnv {
            interner: &interner,
            transparent_ffi: &ffi,
            payloads: &payloads,
        });
    }

    /// The single-bit set of `bound`.
    const fn set_of(bound: Bound) -> BoundSet {
        let none = BoundSet::UNBOUNDED;
        match bound {
            Bound::Add => none.with_add(),
            Bound::Sub => none.with_sub(),
            Bound::Mul => none.with_mul(),
            Bound::Ord => none.with_ord(),
            Bound::Copy => none.with_copy(),
            Bound::Clone => none.with_clone(),
            Bound::Eq => none.with_eq(),
            Bound::OrdTotal => none.with_ord_total(),
            Bound::Hash => none.with_hash(),
            Bound::Show => none.with_show(),
            Bound::SqlParam => none.with_sql_param(),
            Bound::IpeRow => none.with_ipe_row(),
            Bound::Interpolable => none.with_interpolable(),
            Bound::Static => none.with_static(),
            Bound::Send => none.with_send(),
            Bound::Sync => none.with_sync(),
        }
    }

    /// The bounds [`bound_met_by`] decides from the type rather than the type checker.
    const fn decided_here(bound: Bound) -> bool {
        matches!(
            bound,
            Bound::Clone | Bound::Copy | Bound::IpeRow | Bound::Eq
        )
    }

    /// Whether a set carrying `bound` also carries `other` by implication.
    ///
    /// `BoundSet::with_send` adds `'static`, and `BoundSet::with_sync` adds
    /// `Send` and `'static`; no other bound implies another.
    const fn implied_by(bound: Bound, other: Bound) -> bool {
        matches!(
            (bound, other),
            (Bound::Send, Bound::Static) | (Bound::Sync, Bound::Send | Bound::Static)
        )
    }

    /// Each bound reads its own bit and the bits it implies, and every bit has a bound.
    #[test]
    fn every_bound_reads_its_own_bit() {
        for bound in Bound::ALL {
            let set = set_of(bound);
            for other in Bound::ALL {
                assert_eq!(
                    other.in_set(set),
                    other == bound || implied_by(bound, other),
                    "{other:?} in {bound:?}"
                );
            }
        }
        assert!(Bound::ALL.iter().all(|b| b.in_set(full_set())));
    }

    /// The set holding every bound.
    fn full_set() -> BoundSet {
        Bound::ALL
            .into_iter()
            .fold(BoundSet::UNBOUNDED, |acc, b| union(acc, set_of(b)))
    }

    /// `a` with every bit of `b` added.
    fn union(a: BoundSet, b: BoundSet) -> BoundSet {
        Bound::ALL
            .into_iter()
            .filter(|bound| bound.in_set(b))
            .fold(a, |acc, bound| match bound {
                Bound::Add => acc.with_add(),
                Bound::Sub => acc.with_sub(),
                Bound::Mul => acc.with_mul(),
                Bound::Ord => acc.with_ord(),
                Bound::Copy => acc.with_copy(),
                Bound::Clone => acc.with_clone(),
                Bound::Eq => acc.with_eq(),
                Bound::OrdTotal => acc.with_ord_total(),
                Bound::Hash => acc.with_hash(),
                Bound::Show => acc.with_show(),
                Bound::SqlParam => acc.with_sql_param(),
                Bound::IpeRow => acc.with_ipe_row(),
                Bound::Interpolable => acc.with_interpolable(),
                Bound::Static => acc.with_static(),
                Bound::Send => acc.with_send(),
                Bound::Sync => acc.with_sync(),
            })
    }

    /// The pin readings `()` and `JsonVal` agree with the supply table on every bound it decides.
    #[test]
    fn unit_and_json_agree_with_the_pin_tables() {
        with_env(|env| {
            for bound in Bound::ALL.into_iter().filter(|b| decided_here(*b)) {
                let unit = bound_met_by(env, bound, &IrType::Unit) == Supply::Met;
                assert_eq!(unit, set_of(bound).met_by_unit(), "() and {bound:?}");
                let json = bound_met_by(env, bound, &IrType::Json) == Supply::Met;
                assert_eq!(json, set_of(bound).met_by_json(), "JsonVal and {bound:?}");
            }
        });
    }

    /// A generic is forwarded, except for the `Clone` every generic carries.
    #[test]
    fn a_generic_is_forwarded() {
        with_env(|env| {
            let mut interner = Interner::new();
            let a = interner.intern("a");
            assert!(a.is_ok(), "interning a one-letter name");
            for ty in a
                .into_iter()
                .flat_map(|a| [IrType::Generic(a), IrType::RowGeneric(a)])
            {
                for bound in Bound::ALL {
                    let want = if bound == Bound::Clone {
                        Supply::Met
                    } else {
                        Supply::Forwarded
                    };
                    assert_eq!(bound_met_by(env, bound, &ty), want, "{bound:?}");
                }
            }
        });
    }

    /// The effect carriers and the boxed function are not `Clone`; the shared function is.
    #[test]
    fn effects_and_boxed_functions_are_not_clone() {
        with_env(|env| {
            let task = IrType::Task(Box::new(IrType::Unit));
            for (ty, leaf) in [
                (task.clone(), "Task"),
                (IrType::Cmd(Box::new(IrType::Unit)), "Cmd"),
                (IrType::Sub(Box::new(IrType::Unit)), "Sub"),
                (
                    IrType::Fun(vec![IrType::Int], Box::new(IrType::Int)),
                    "function",
                ),
                (IrType::Maybe(Box::new(task.clone())), "Task"),
                (IrType::List(Box::new(task.clone())), "Task"),
                (IrType::Tuple(vec![IrType::Int, task]), "Task"),
            ] {
                assert!(
                    matches!(bound_met_by(env, Bound::Clone, &ty), Supply::Unmet { leaf: ref l, .. } if &**l == leaf),
                    "{ty:?}"
                );
            }
            let shared = IrType::SharedFun(vec![IrType::Int], Box::new(IrType::Int));
            assert_eq!(bound_met_by(env, Bound::Clone, &shared), Supply::Met);
            assert_eq!(bound_met_by(env, Bound::Clone, &IrType::Str), Supply::Met);
        });
    }

    /// `PartialEq` is refused for a decoder, a function and a database handle,
    /// bare or nested, and supplied for a list of integers.
    #[test]
    fn equality_is_refused_for_a_decoder_and_supplied_for_values() {
        with_env(|env| {
            let decoder = IrType::Decoder(Box::new(IrType::Int));
            for ty in [
                decoder.clone(),
                IrType::List(Box::new(decoder.clone())),
                IrType::Maybe(Box::new(decoder)),
                IrType::Db,
                IrType::Regex,
                IrType::Fun(vec![IrType::Int], Box::new(IrType::Int)),
            ] {
                assert!(
                    matches!(
                        bound_met_by(env, Bound::Eq, &ty),
                        Supply::Unmet {
                            demand: CalleeDemand::Compares,
                            ..
                        }
                    ),
                    "{ty:?}"
                );
            }
            let ints = IrType::List(Box::new(IrType::Int));
            assert_eq!(bound_met_by(env, Bound::Eq, &ints), Supply::Met);
        });
    }

    /// An opaque `Rust.*` handle has no `PartialEq`; a registered enum
    /// holding only integers has it, and one holding the handle does not.
    #[test]
    fn equality_is_refused_for_an_opaque_handle_and_its_holders() {
        let mut interner = Interner::new();
        let names =
            ["Rust", "Zstd", "Encoder", "Main", "Plain", "Holds", "A"].map(|n| interner.intern(n));
        assert!(
            names.iter().all(Result::is_ok),
            "interning the fixture names"
        );
        let [
            Ok(rust),
            Ok(zstd),
            Ok(encoder),
            Ok(main),
            Ok(plain),
            Ok(holds),
            Ok(ctor),
        ] = names
        else {
            return;
        };
        let handle = IrType::Enum {
            home: ModPath(vec![rust, zstd]),
            name: encoder,
            args: Vec::new(),
        };
        let main_home = ModPath(vec![main]);
        let mut payloads = EnumPayloadTable::new();
        payloads.insert((main_home.clone(), plain), vec![(ctor, vec![IrType::Int])]);
        payloads.insert(
            (main_home.clone(), holds),
            vec![(ctor, vec![handle.clone()])],
        );
        let ffi = BTreeSet::new();
        let env = CloneEnv {
            interner: &interner,
            transparent_ffi: &ffi,
            payloads: &payloads,
        };
        let main_enum = |name| IrType::Enum {
            home: main_home.clone(),
            name,
            args: Vec::new(),
        };
        for (ty, met) in [
            (handle, false),
            (main_enum(plain), true),
            (main_enum(holds), false),
        ] {
            assert_eq!(
                bound_met_by(env, Bound::Eq, &ty) == Supply::Met,
                met,
                "{ty:?}"
            );
        }
    }

    /// A Model missing `PartialEq` is blamed by the role gate, naming the field
    /// and its leaf, while a `Clone`-only judgement admits it.
    #[test]
    fn role_blame_names_the_field_a_model_misses_equality_by() {
        let mut interner = Interner::new();
        let names = ["count", "widget", "parse"].map(|n| interner.intern(n));
        assert!(
            names.iter().all(Result::is_ok),
            "interning the fixture names"
        );
        let [Ok(count), Ok(widget), Ok(parse)] = names else {
            return;
        };
        let ffi = BTreeSet::new();
        let payloads = EnumPayloadTable::new();
        let env = CloneEnv {
            interner: &interner,
            transparent_ffi: &ffi,
            payloads: &payloads,
        };
        let derivable = BTreeMap::new();
        let element = IrType::CustomElement {
            down: Box::new(IrType::Int),
            up: Box::new(IrType::Str),
        };
        let with_element =
            IrType::Record(BTreeMap::from([(count, IrType::Int), (widget, element)]));
        let with_decoder = IrType::Record(BTreeMap::from([
            (count, IrType::Int),
            (parse, IrType::Decoder(Box::new(IrType::Int))),
        ]));
        assert_eq!(
            role_blame(env, &derivable, Bound::Clone, &with_element),
            None
        );
        assert_eq!(
            role_blame(env, &derivable, Bound::Eq, &with_element),
            Some(("widget".into(), ModelLeaf::Handle))
        );
        assert_eq!(
            role_blame(env, &derivable, Bound::Eq, &with_decoder),
            Some(("parse".into(), ModelLeaf::Decoder))
        );
        let plain = IrType::Record(BTreeMap::from([(count, IrType::Int)]));
        assert_eq!(role_blame(env, &derivable, Bound::Eq, &plain), None);
    }

    /// `Copy` is supplied by the scalars only; `IpeRow` by its two runtime rows only.
    #[test]
    fn copy_and_row_are_closed_sets() {
        with_env(|env| {
            assert_eq!(bound_met_by(env, Bound::Copy, &IrType::Int), Supply::Met);
            let pair = IrType::Tuple(vec![IrType::Int, IrType::Float]);
            assert_eq!(bound_met_by(env, Bound::Copy, &pair), Supply::Met);
            assert!(matches!(
                bound_met_by(env, Bound::Copy, &IrType::Str),
                Supply::Unmet { .. }
            ));
            let row = IrType::Dict(Box::new(IrType::Str), Box::new(IrType::Str));
            assert_eq!(bound_met_by(env, Bound::IpeRow, &row), Supply::Met);
            assert_eq!(
                bound_met_by(env, Bound::IpeRow, &IrType::WebReq),
                Supply::Met
            );
            assert!(matches!(
                bound_met_by(env, Bound::IpeRow, &IrType::Str),
                Supply::Unmet { .. }
            ));
        });
    }
}
