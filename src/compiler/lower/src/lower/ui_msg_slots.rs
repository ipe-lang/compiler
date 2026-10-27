//! Where a declared type holds a UI message slot, by the lowerer's own reading.
//!
//! [`UI_MSG_SLOTS`] is the one table of UI message-slot constructors. The
//! reader ([`super::Lowerer::ir_type_from_ty`]) selects its UI arm by
//! [`lookup`] and reads the message argument through
//! `ir_type_from_ty_ui_msg`, which lowers a free variable there to `()` and
//! takes a [`MsgArg`], a value only [`lookup`] builds from a table row: a
//! position no row names cannot be read as a message slot. The use-pin
//! classifier ([`open_var_uses`]) asks the same lookup, so a pin for a callee
//! type parameter reads it the way the use's own node types do.
//!
//! [`open_var_ir`] is the one table of what an open variable reads as by its
//! position's [`OpenVarUse`]; the UI, `Result` and JSON readers default an
//! open variable through it.

use std::collections::{BTreeMap, BTreeSet};

use ipe_intern::Symbol;
use ipe_ir::{IrType, UiCtor};
use ipe_types::{RowTail, Ty};

/// How a slot constructor selects its [`UiCtor`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum UiSlotCtor {
    /// Always this ctor.
    Fixed(UiCtor),
    /// By the engine tag in argument 0 (`View engine msg`).
    ByEngineTag,
    /// By the constructor's home: `Ipe.Html` or `Ipe.Ui`.
    ByAttributeHome,
}

/// One UI message-slot constructor: its name, its arity, the index of the
/// argument read as the message slot, and how it selects its [`UiCtor`].
///
/// The fields are private, so a row exists only in [`UI_MSG_SLOTS`].
#[derive(Clone, Copy, Debug)]
pub(super) struct UiMsgSlot {
    name: &'static str,
    arity: usize,
    slot: usize,
    ctor: UiSlotCtor,
}

impl UiMsgSlot {
    #[cfg(test)]
    pub(super) const fn name(&self) -> &'static str {
        self.name
    }

    #[cfg(test)]
    pub(super) const fn arity(&self) -> usize {
        self.arity
    }

    pub(super) const fn slot(&self) -> usize {
        self.slot
    }

    pub(super) const fn ctor(&self) -> UiSlotCtor {
        self.ctor
    }
}

/// The message argument of a [`UI_MSG_SLOTS`] constructor's application.
///
/// The field is private, so only [`lookup`] builds one: holding a `MsgArg` is
/// the proof that its position is a table slot.
#[derive(Clone, Copy, Debug)]
pub(super) struct MsgArg<'t>(&'t Ty);

impl<'t> MsgArg<'t> {
    pub(super) const fn ty(self) -> &'t Ty {
        self.0
    }
}

const fn single(name: &'static str, ctor: UiCtor) -> UiMsgSlot {
    UiMsgSlot {
        name,
        arity: 1,
        slot: 0,
        ctor: UiSlotCtor::Fixed(ctor),
    }
}

/// Every UI message-slot constructor. `View engine msg` is the carrier the
/// per-engine view aliases (`Element`, `Screen`, `Lines`) canonicalise to: its
/// engine tag is no slot.
pub(super) const UI_MSG_SLOTS: [UiMsgSlot; 12] = [
    single("Html", UiCtor::Html),
    UiMsgSlot {
        name: "View",
        arity: 2,
        slot: 1,
        ctor: UiSlotCtor::ByEngineTag,
    },
    single("Element", UiCtor::Element),
    single("Screen", UiCtor::Cells),
    single("TuiAttr", UiCtor::TuiAttribute),
    single("Lines", UiCtor::CliLines),
    single("CliAttr", UiCtor::CliAttribute),
    UiMsgSlot {
        name: "Attribute",
        arity: 1,
        slot: 0,
        ctor: UiSlotCtor::ByAttributeHome,
    },
    single("Event", UiCtor::HtmlEvent),
    single("Label", UiCtor::Label),
    single("Placeholder", UiCtor::Placeholder),
    single("RadioOption", UiCtor::RadioOption),
];

/// The [`UI_MSG_SLOTS`] row of a constructor called `name` applied to `args`,
/// with its message argument, when the name and the arity match a row.
pub(super) fn lookup<'t>(name: &str, args: &'t [Ty]) -> Option<(&'static UiMsgSlot, MsgArg<'t>)> {
    let row = UI_MSG_SLOTS
        .iter()
        .find(|s| s.name == name && s.arity == args.len())?;
    Some((row, MsgArg(args.get(row.slot)?)))
}

/// The argument index of the error in `Result e a`.
pub(super) const RESULT_ERROR_SLOT: usize = 0;

/// The error slot of a constructor called `name` applied to `args`, when it
/// is `Result e a`.
pub(super) fn result_error_slot(name: &str, args: &[Ty]) -> Option<usize> {
    (name == "Result" && args.len() == 2).then_some(RESULT_ERROR_SLOT)
}

/// How a position of a declared type uses a type variable: the reading an
/// open variable gets there.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub(super) enum OpenVarUse {
    /// The message argument of a UI type (`Html msg`): reads as `()`.
    UiMessage,
    /// The error argument of `Result e a`: reads as the project error.
    ResultError,
    /// Any other position: reads as the JSON carrier.
    Value,
}

/// What an open variable reads as at a position used as `role`: `()` in a UI
/// message slot, the project error (the `Ok` wrapper's fixed error) in a
/// `Result` error slot, the JSON carrier anywhere else.
pub(super) const fn open_var_ir(role: OpenVarUse) -> IrType {
    match role {
        OpenVarUse::UiMessage => IrType::Unit,
        OpenVarUse::ResultError => IrType::Error,
        OpenVarUse::Value => IrType::Json,
    }
}

/// The type variables of a declared type, as raws, each with the uses of its
/// positions.
pub(super) type OpenVarUses = BTreeMap<u32, BTreeSet<OpenVarUse>>;

/// Classify the variables of `ty`; `slot` names the argument index and use of
/// the one special slot of a constructor `(module, name)` applied to `args`,
/// or `None` when it has none.
///
/// A position is a slot only directly: the readers read a compound type in a
/// slot (a function, a tuple, a record, a non-slot constructor) by its own
/// arms, so every variable inside one is a [`OpenVarUse::Value`].
pub(super) fn open_var_uses(
    ty: &Ty,
    slot: impl Fn(&[Symbol], Symbol, &[Ty]) -> Option<(usize, OpenVarUse)>,
) -> OpenVarUses {
    let mut uses = OpenVarUses::new();
    let mut stack: Vec<(&Ty, OpenVarUse)> = vec![(ty, OpenVarUse::Value)];
    while let Some((t, role)) = stack.pop() {
        match t {
            Ty::Var(raw) => {
                uses.entry(*raw).or_default().insert(role);
            }
            Ty::Fun(a, b) => {
                stack.push((a, OpenVarUse::Value));
                stack.push((b, OpenVarUse::Value));
            }
            Ty::Con { module, name, args } => {
                let at = slot(module.as_slice(), *name, args);
                stack.extend(args.iter().enumerate().map(|(i, a)| {
                    let role = match at {
                        Some((s, special)) if s == i => special,
                        Some(_) | None => OpenVarUse::Value,
                    };
                    (a, role)
                }));
            }
            Ty::Tuple(elems) => stack.extend(elems.iter().map(|e| (e, OpenVarUse::Value))),
            Ty::Record(fields, tail) => {
                match tail {
                    RowTail::Open(raw) => {
                        uses.entry(*raw).or_default().insert(OpenVarUse::Value);
                    }
                    RowTail::Closed => {}
                }
                stack.extend(fields.values().map(|v| (v, OpenVarUse::Value)));
            }
            Ty::Wildcard | Ty::Unit => {}
        }
    }
    uses
}

/// Whether `roles` is the UI message slot alone.
pub(super) fn only_ui_message(roles: &BTreeSet<OpenVarUse>) -> bool {
    roles.len() == 1 && roles.contains(&OpenVarUse::UiMessage)
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use ipe_intern::{Interner, Symbol};
    use ipe_types::Ty;

    use super::{OpenVarUse, OpenVarUses, lookup, open_var_uses, result_error_slot};

    /// The raw of the message variable the classification tests place.
    const MSG: u32 = 3;

    fn con(name: Symbol, args: Vec<Ty>) -> Ty {
        Ty::Con {
            module: vec![],
            name,
            args,
        }
    }

    /// The slot index of `name` applied to `args`, by the table.
    fn slot_at(name: &str, args: &[Ty]) -> Option<usize> {
        lookup(name, args).map(|(row, _)| row.slot())
    }

    /// Classify `ty` by the tables alone (no program union shadows a name).
    fn classify(interner: &Interner, ty: &Ty) -> OpenVarUses {
        open_var_uses(ty, |_, name, args| {
            let name = interner.resolve(name)?;
            slot_at(name, args)
                .map(|s| (s, OpenVarUse::UiMessage))
                .or_else(|| result_error_slot(name, args).map(|s| (s, OpenVarUse::ResultError)))
        })
    }

    /// The classification of `MSG` alone, by `uses`.
    fn msg_uses(uses: &[OpenVarUse]) -> OpenVarUses {
        BTreeMap::from([(MSG, uses.iter().copied().collect())])
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
        assert_eq!(classify(&interner, &ty), msg_uses(&[OpenVarUse::UiMessage]));
        // A variable in the engine-tag position is no message slot.
        let tag = con(view, vec![Ty::Var(MSG), Ty::Unit]);
        assert_eq!(classify(&interner, &tag), msg_uses(&[OpenVarUse::Value]));
    }

    /// `Result e a` holds `e` in its error slot and `a` as a value; a variable
    /// in both is used both ways.
    #[test]
    fn the_result_error_argument_is_a_slot() {
        const OK: u32 = 4;
        let mut interner = Interner::new();
        let result = interner.intern("Result").unwrap();
        let ty = con(result, vec![Ty::Var(MSG), Ty::Var(OK)]);
        assert_eq!(
            classify(&interner, &ty),
            BTreeMap::from([
                (MSG, BTreeSet::from([OpenVarUse::ResultError])),
                (OK, BTreeSet::from([OpenVarUse::Value])),
            ])
        );
        let both = Ty::Tuple(vec![ty, Ty::Var(MSG)]);
        assert_eq!(
            classify(&interner, &both).get(&MSG),
            Some(&BTreeSet::from([
                OpenVarUse::ResultError,
                OpenVarUse::Value
            ]))
        );
        // A mis-arity `Result` holds no error slot.
        assert_eq!(result_error_slot("Result", &[Ty::Unit]), None);
        assert_eq!(result_error_slot("Result", &[Ty::Unit, Ty::Unit]), Some(0));
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
        assert_eq!(
            classify(&interner, &ty),
            msg_uses(&[OpenVarUse::UiMessage, OpenVarUse::Value])
        );
    }

    /// A variable inside a tuple, a function or a record that fills a message
    /// slot is read strictly by the reader, so it occurs outside a slot.
    #[test]
    fn a_compound_message_type_holds_no_slot_variable() {
        let mut interner = Interner::new();
        let html = interner.intern("Html").unwrap();
        let field = interner.intern("f").unwrap();
        let compounds = [
            Ty::Tuple(vec![Ty::Var(MSG), Ty::Unit]),
            Ty::Fun(Box::new(Ty::Unit), Box::new(Ty::Var(MSG))),
            Ty::Record(
                std::collections::BTreeMap::from([(field, Ty::Var(MSG))]),
                ipe_types::RowTail::Closed,
            ),
            Ty::Record(
                std::collections::BTreeMap::new(),
                ipe_types::RowTail::Open(MSG),
            ),
        ];
        for compound in compounds {
            let ty = con(html, vec![compound.clone()]);
            assert_eq!(
                classify(&interner, &ty),
                msg_uses(&[OpenVarUse::Value]),
                "`Html ({compound:?})` holds no slot-only variable"
            );
            let mixed = Ty::Tuple(vec![con(html, vec![Ty::Var(MSG)]), ty]);
            assert_eq!(
                classify(&interner, &mixed),
                msg_uses(&[OpenVarUse::UiMessage, OpenVarUse::Value]),
                "beside a direct slot, `Html ({compound:?})` makes the variable mixed"
            );
        }
    }

    /// The slot table answers by name and arity both: a mis-arity application
    /// holds no slot.
    #[test]
    fn a_mis_arity_application_holds_no_slot() {
        let one = [Ty::Unit];
        let two = [Ty::Unit, Ty::Unit];
        assert_eq!(slot_at("View", &two), Some(1));
        assert_eq!(slot_at("View", &one), None);
        assert_eq!(slot_at("Html", &one), Some(0));
        assert_eq!(slot_at("Html", &two), None);
        assert_eq!(slot_at("List", &one), None);
    }
}
