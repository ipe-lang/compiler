//! Where a declared type holds a UI message slot, by the lowerer's own reading.
//!
//! [`super::Lowerer::ir_type_from_ty`] reads the message argument of each
//! constructor in [`UI_MSG_SLOTS`] through `ir_type_from_ty_ui_msg`, which
//! lowers a free variable there to `()`; every other position reads a free
//! variable some other way (refused, or `JsonVal` on the JSON path). A use pin
//! for a callee type parameter must read that parameter the way its positions
//! do, so the pin and the use's own node types name one Rust type.

use std::collections::BTreeSet;

use ipe_intern::Symbol;
use ipe_types::{RowTail, Ty};

/// One UI message-slot constructor: its name, its arity, and the index of the
/// argument the lowerer reads as the message slot.
#[derive(Clone, Copy, Debug)]
pub(super) struct UiMsgSlot {
    pub(super) name: &'static str,
    pub(super) arity: usize,
    pub(super) slot: usize,
}

const fn single(name: &'static str) -> UiMsgSlot {
    UiMsgSlot {
        name,
        arity: 1,
        slot: 0,
    }
}

/// Every constructor whose message argument `ir_type_from_ty` reads through
/// `ir_type_from_ty_ui_msg`. `View engine msg` is the carrier the per-engine
/// view aliases (`Element`, `Screen`, `Lines`) canonicalise to: its engine tag
/// is no slot.
pub(super) const UI_MSG_SLOTS: [UiMsgSlot; 12] = [
    single("Html"),
    UiMsgSlot {
        name: "View",
        arity: 2,
        slot: 1,
    },
    single("Element"),
    single("Screen"),
    single("TuiAttr"),
    single("Lines"),
    single("CliAttr"),
    single("Attribute"),
    single("Event"),
    single("Label"),
    single("Placeholder"),
    single("RadioOption"),
];

/// The message-slot argument index of a constructor called `name` applied to
/// `arity` arguments, when it is one of [`UI_MSG_SLOTS`].
pub(super) fn slot_of(name: &str, arity: usize) -> Option<usize> {
    UI_MSG_SLOTS
        .iter()
        .find(|s| s.name == name && s.arity == arity)
        .map(|s| s.slot)
}

/// The type variables of a declared type, as raws, split by where they occur.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct UiSlotVars {
    /// Occurring only in UI message slots.
    pub(super) only: BTreeSet<u32>,
    /// Occurring both in a UI message slot and elsewhere.
    pub(super) mixed: BTreeSet<u32>,
}

/// Classify the variables of `ty`; `slot` names the message-slot argument index
/// of a constructor `(module, name, arity)`, or `None` when it has none.
///
/// A constructor's argument is a slot position only directly: a non-slot
/// constructor nested inside a slot resets the position, the way the lowerer
/// reads a compound message type strictly.
pub(super) fn ui_slot_vars(
    ty: &Ty,
    slot: impl Fn(&[Symbol], Symbol, usize) -> Option<usize>,
) -> UiSlotVars {
    let mut ui = BTreeSet::new();
    let mut other = BTreeSet::new();
    let mut stack: Vec<(&Ty, bool)> = vec![(ty, false)];
    while let Some((t, in_slot)) = stack.pop() {
        let mut note = |raw: u32| {
            if in_slot {
                ui.insert(raw);
            } else {
                other.insert(raw);
            }
        };
        match t {
            Ty::Var(raw) => note(*raw),
            Ty::Fun(a, b) => {
                stack.push((a, in_slot));
                stack.push((b, in_slot));
            }
            Ty::Con { module, name, args } => {
                let at = slot(module.as_slice(), *name, args.len());
                stack.extend(args.iter().enumerate().map(|(i, a)| (a, at == Some(i))));
            }
            Ty::Tuple(elems) => stack.extend(elems.iter().map(|e| (e, in_slot))),
            Ty::Record(fields, tail) => {
                match tail {
                    RowTail::Open(raw) => note(*raw),
                    RowTail::Closed => {}
                }
                stack.extend(fields.values().map(|v| (v, in_slot)));
            }
            Ty::Wildcard | Ty::Unit => {}
        }
    }
    UiSlotVars {
        only: ui.difference(&other).copied().collect(),
        mixed: ui.intersection(&other).copied().collect(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use ipe_intern::{Interner, Symbol};
    use ipe_types::Ty;

    use super::{UiSlotVars, slot_of, ui_slot_vars};

    /// The raw of the message variable the classification tests place.
    const MSG: u32 = 3;

    fn con(name: Symbol, args: Vec<Ty>) -> Ty {
        Ty::Con {
            module: vec![],
            name,
            args,
        }
    }

    /// `String -> View Web msg` (what `render : String -> Element msg`
    /// canonicalises to) holds `msg` only in a message slot; the engine tag is
    /// no slot.
    #[test]
    fn the_view_carrier_message_argument_is_a_slot() {
        let mut interner = Interner::new();
        let (view, web, string) = (
            interner.intern("View").unwrap(),
            interner.intern("Web").unwrap(),
            interner.intern("String").unwrap(),
        );
        let ty = Ty::Fun(
            Box::new(con(string, vec![])),
            Box::new(con(view, vec![con(web, vec![]), Ty::Var(MSG)])),
        );
        let vars = ui_slot_vars(&ty, |_, name, arity| {
            interner.resolve(name).and_then(|n| slot_of(n, arity))
        });
        assert_eq!(
            vars,
            UiSlotVars {
                only: BTreeSet::from([MSG]),
                mixed: BTreeSet::new(),
            }
        );
        // A variable in the engine-tag position is no message slot.
        let tag = con(view, vec![Ty::Var(MSG), Ty::Unit]);
        let vars = ui_slot_vars(&tag, |_, name, arity| {
            interner.resolve(name).and_then(|n| slot_of(n, arity))
        });
        assert!(vars.only.is_empty() && vars.mixed.is_empty());
    }

    /// A variable in a message slot and outside one is mixed, never slot-only.
    #[test]
    fn a_variable_also_outside_a_slot_is_mixed() {
        let mut interner = Interner::new();
        let (view, web) = (
            interner.intern("View").unwrap(),
            interner.intern("Web").unwrap(),
        );
        let ty = Ty::Tuple(vec![
            con(view, vec![con(web, vec![]), Ty::Var(MSG)]),
            Ty::Var(MSG),
        ]);
        let vars = ui_slot_vars(&ty, |_, name, arity| {
            interner.resolve(name).and_then(|n| slot_of(n, arity))
        });
        assert_eq!(
            vars,
            UiSlotVars {
                only: BTreeSet::new(),
                mixed: BTreeSet::from([MSG]),
            }
        );
    }

    /// The slot table answers by name and arity both: a mis-arity application
    /// holds no slot.
    #[test]
    fn a_mis_arity_application_holds_no_slot() {
        assert_eq!(slot_of("View", 2), Some(1));
        assert_eq!(slot_of("View", 1), None);
        assert_eq!(slot_of("Html", 1), Some(0));
        assert_eq!(slot_of("Html", 2), None);
        assert_eq!(slot_of("List", 1), None);
    }
}
