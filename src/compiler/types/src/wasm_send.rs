//! The wasm `Decoder`-element gate (`IPE-N0052`).
//!
//! A `Decoder` element is moved into runtime decoding kernels that require
//! `Send` on every target (`decode_list<T: 'static + Send>`), while on a wasm
//! target the effect carriers `Cmd` / `Sub` / `Task` are not `Send`. A program
//! whose decoder element is, or holds, an effect carrier therefore has no valid
//! wasm build, so this gate refuses it at `ipe` time instead of letting
//! `cargo` fail on the emitted Rust.
//!
//! The walk runs over every solved region type, so each instantiation of a
//! generic definition is checked at its concrete type at the use site. A type
//! variable in a decoder-element position is accepted only when some
//! definition's signature exposes it in such a position (then every use is a
//! region of its own, checked at its instantiated type); an unexposed variable
//! is refused, because no use site would ever see what it is instantiated to.

use std::collections::BTreeSet;

use ipe_canon::ast as canon;
use ipe_diagnostics::{Diagnostic, NameError};
use ipe_intern::{Interner, Symbol};

use crate::{RowTail, SolvedTypes, Ty, is_solver_var, untag_solver_var};

/// A user union's identity: `(home, name)`, matching [`Ty::Con`]'s `(module, name)`.
type UnionKey = (Vec<Symbol>, Symbol);

/// How a type-constructor name is treated by the gate.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Head {
    /// `Decoder`: its element is a `Send`-required position.
    Decoder,
    /// `Cmd` / `Sub` / `Task`: an effect carrier, not `Send` on wasm.
    Effect,
    /// Any other constructor.
    Other,
}

fn head(interner: &Interner, name: Symbol) -> Head {
    match interner.resolve(name) {
        Some("Decoder") => Head::Decoder,
        Some("Cmd" | "Sub" | "Task") => Head::Effect,
        Some(_) | None => Head::Other,
    }
}

/// The unions' facts the region walk needs, computed once per program.
struct UnionFacts {
    /// Unions some constructor field of which holds an effect carrier.
    effectful: BTreeSet<UnionKey>,
    /// `(union, parameter index)` pairs whose parameter reaches a decoder
    /// element inside some constructor field.
    decoder_params: BTreeSet<(UnionKey, usize)>,
}

impl UnionFacts {
    fn new(module: &canon::Module, interner: &Interner) -> Self {
        let mut effectful = BTreeSet::new();
        // Each round either grows the set or stops; it can grow at most once
        // per union, so `unions.len() + 1` rounds reach the fixpoint.
        for _ in 0..=module.unions.len() {
            let before = effectful.len();
            for u in &module.unions {
                let key = (u.home.clone(), u.name);
                if !effectful.contains(&key)
                    && u.ctors
                        .iter()
                        .flat_map(|c| &c.args)
                        .any(|t| type_holds_effect(t, &effectful, interner))
                {
                    effectful.insert(key);
                }
            }
            if effectful.len() == before {
                break;
            }
        }
        let mut decoder_params = BTreeSet::new();
        // Bounded by the total parameter count, as above.
        let total: usize = module.unions.iter().map(|u| u.vars.len()).sum();
        for _ in 0..=total {
            let before = decoder_params.len();
            for u in &module.unions {
                let key = (u.home.clone(), u.name);
                let mut found = Vec::new();
                for field in u.ctors.iter().flat_map(|c| &c.args) {
                    collect_required_vars(field, false, &decoder_params, interner, &mut found);
                }
                for sym in found {
                    if let Some(j) = u.vars.iter().position(|v| *v == sym) {
                        decoder_params.insert((key.clone(), j));
                    }
                }
            }
            if decoder_params.len() == before {
                break;
            }
        }
        Self {
            effectful,
            decoder_params,
        }
    }

    fn arg_required(&self, module: &[Symbol], name: Symbol, index: usize) -> bool {
        self.decoder_params
            .iter()
            .any(|((home, n), j)| home.as_slice() == module && *n == name && *j == index)
    }

    fn is_effectful(&self, module: &[Symbol], name: Symbol) -> bool {
        self.effectful
            .iter()
            .any(|(home, n)| home.as_slice() == module && *n == name)
    }
}

/// Does a declared field type hold an effect carrier by value?
fn type_holds_effect(t: &canon::Type, effectful: &BTreeSet<UnionKey>, interner: &Interner) -> bool {
    match t {
        canon::Type::Con { home, name, args } => match head(interner, *name) {
            Head::Effect => true,
            Head::Decoder => false,
            Head::Other => {
                effectful.contains(&(home.clone(), *name))
                    || args
                        .iter()
                        .any(|a| type_holds_effect(a, effectful, interner))
            }
        },
        canon::Type::Lambda(..) | canon::Type::Var(_) | canon::Type::Unit => false,
        canon::Type::Tuple(items) => items
            .iter()
            .any(|a| type_holds_effect(a, effectful, interner)),
        canon::Type::Record(fields) | canon::Type::RecordOpen(_, fields) => fields
            .iter()
            .any(|(_, a)| type_holds_effect(a, effectful, interner)),
    }
}

/// Collect the type variables of a declared type that sit in a decoder-element position.
fn collect_required_vars(
    t: &canon::Type,
    required: bool,
    decoder_params: &BTreeSet<(UnionKey, usize)>,
    interner: &Interner,
    out: &mut Vec<Symbol>,
) {
    match t {
        canon::Type::Var(s) => {
            if required {
                out.push(*s);
            }
        }
        canon::Type::RecordOpen(s, fields) => {
            if required {
                out.push(*s);
            }
            for (_, a) in fields {
                collect_required_vars(a, required, decoder_params, interner, out);
            }
        }
        canon::Type::Con { home, name, args } => {
            let inner = |j: usize| match head(interner, *name) {
                Head::Decoder => true,
                Head::Effect => false,
                Head::Other => required || decoder_params.contains(&((home.clone(), *name), j)),
            };
            for (j, a) in args.iter().enumerate() {
                collect_required_vars(a, inner(j), decoder_params, interner, out);
            }
        }
        canon::Type::Tuple(items) => {
            for a in items {
                collect_required_vars(a, required, decoder_params, interner, out);
            }
        }
        canon::Type::Record(fields) => {
            for (_, a) in fields {
                collect_required_vars(a, required, decoder_params, interner, out);
            }
        }
        canon::Type::Lambda(param, result) => {
            collect_required_vars(param, false, decoder_params, interner, out);
            collect_required_vars(result, false, decoder_params, interner, out);
        }
        canon::Type::Unit => {}
    }
}

/// The first thing in a solved type that cannot sit in a decoder element.
enum Offender {
    /// A named constructor: an effect carrier or a union holding one.
    Con(Symbol),
    /// A type variable no signature exposes in a decoder-element position.
    Var,
}

/// Walks solved types, tracking whether the current position is a decoder element.
struct Walk<'a> {
    facts: &'a UnionFacts,
    interner: &'a Interner,
}

impl Walk<'_> {
    /// Collect the raw ids of every type variable (and open row tail) in a decoder-element position.
    fn required_vars(&self, ty: &Ty, required: bool, out: &mut BTreeSet<u32>) {
        self.visit(ty, required, &mut |node, req| {
            if req {
                match node {
                    Node::Var(raw) => {
                        out.insert(raw);
                    }
                    Node::Con { .. } => {}
                }
            }
            None::<()>
        });
    }

    /// The first offender in a decoder-element position, if any.
    fn offender(&self, ty: &Ty, exposed: &Exposed) -> Option<Offender> {
        self.visit(ty, false, &mut |node, req| {
            if !req {
                return None;
            }
            match node {
                Node::Var(raw) => (!exposed.contains(raw)).then_some(Offender::Var),
                Node::Con { name, offends } => offends.then_some(Offender::Con(name)),
            }
        })
    }

    /// Visit every variable and constructor, stopping at the first `Some`.
    fn visit<R>(
        &self,
        ty: &Ty,
        required: bool,
        f: &mut impl FnMut(Node, bool) -> Option<R>,
    ) -> Option<R> {
        match ty {
            Ty::Var(raw) => f(Node::Var(*raw), required),
            // A function renders as a `Send + Sync` closure, so it is never an
            // offender itself; a decoder inside its parameter or result still is.
            Ty::Fun(param, result) => self
                .visit(param, false, f)
                .or_else(|| self.visit(result, false, f)),
            Ty::Unit => None,
            Ty::Con { module, name, args } => {
                let kind = head(self.interner, *name);
                let offends = match kind {
                    Head::Effect => true,
                    Head::Decoder => false,
                    Head::Other => self.facts.is_effectful(module, *name),
                };
                if let Some(r) = f(
                    Node::Con {
                        name: *name,
                        offends,
                    },
                    required,
                ) {
                    return Some(r);
                }
                args.iter().enumerate().find_map(|(j, a)| {
                    let req = match kind {
                        Head::Decoder => true,
                        Head::Effect => false,
                        Head::Other => required || self.facts.arg_required(module, *name, j),
                    };
                    self.visit(a, req, f)
                })
            }
            Ty::Tuple(items) => items.iter().find_map(|a| self.visit(a, required, f)),
            Ty::Record(fields, tail) => fields
                .values()
                .find_map(|a| self.visit(a, required, f))
                .or_else(|| match tail {
                    RowTail::Open(raw) => f(Node::Var(*raw), required),
                    RowTail::Closed => None,
                }),
        }
    }
}

/// A leaf the walk reports.
#[derive(Clone, Copy)]
enum Node {
    Var(u32),
    /// `offends`: an effect carrier, or a union holding one.
    Con {
        name: Symbol,
        offends: bool,
    },
}

/// The type variables some signature exposes in a decoder-element position.
///
/// Solver-space ids are stored untagged; annotation-space ids as-is. The two
/// sets are kept apart because the spaces overlap numerically.
#[derive(Default)]
struct Exposed {
    solver: BTreeSet<u32>,
    annotation: BTreeSet<u32>,
}

impl Exposed {
    fn contains(&self, raw: u32) -> bool {
        if is_solver_var(raw) {
            self.solver.contains(&untag_solver_var(raw))
        } else {
            self.annotation.contains(&raw)
        }
    }

    fn insert(&mut self, raw: u32) {
        if is_solver_var(raw) {
            self.solver.insert(untag_solver_var(raw));
        } else {
            self.annotation.insert(raw);
        }
    }
}

/// Refuse an effect carrier inside a `Decoder` element (`IPE-N0052`).
///
/// Call this only for a target whose effect carriers are not `Send`
/// ([`ipe_kernels::Target::effect_carriers_are_send`] is false).
///
/// # Errors
/// [`Diagnostic::Name`] with [`NameError::EffectCarrierInDecoder`] at the first
/// region (in `(home, span)` order) whose type places a `Cmd`, `Sub`, `Task`,
/// a union holding one, or an unexposed type variable in a decoder element,
/// paired with that region's home module path for attribution.
pub fn check_wasm_decoder_elements(
    solved: &SolvedTypes,
    module: &canon::Module,
    interner: &Interner,
) -> Result<(), (Diagnostic, Vec<Symbol>)> {
    let facts = UnionFacts::new(module, interner);
    let walk = Walk {
        facts: &facts,
        interner,
    };
    let mut exposed = Exposed::default();
    for (key, ty) in &solved.env {
        let mut raws = BTreeSet::new();
        walk.required_vars(ty, false, &mut raws);
        for raw in raws {
            exposed.insert(raw);
            // A typed binding's signature names annotation symbols; its body's
            // regions name the solver representatives those symbols map to.
            if let Some(map) = solved.poly_var_map.get(key) {
                for (rep, sym) in map {
                    if sym.as_raw() == raw {
                        exposed.solver.insert(*rep);
                    }
                }
            }
        }
    }
    for ((home, span), ty) in &solved.regions {
        if let Some(off) = walk.offender(ty, &exposed) {
            let found: Box<str> = match off {
                Offender::Con(name) => interner.resolve(name).unwrap_or("an effect type").into(),
                Offender::Var => "a type variable".into(),
            };
            return Err((
                Diagnostic::Name {
                    span: *span,
                    msg: NameError::EffectCarrierInDecoder { found },
                },
                home.clone(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use ipe_diagnostics::Span;

    use super::*;

    type CheckResult = Result<(), (Diagnostic, Vec<Symbol>)>;

    struct Fixture {
        i: Interner,
        home: Vec<Symbol>,
    }

    impl Fixture {
        fn new() -> Self {
            let mut fx = Self {
                i: Interner::new(),
                home: Vec::new(),
            };
            fx.home = vec![fx.sym("Main")];
            fx
        }

        #[allow(clippy::expect_used)] // a short test literal is always within the interner's capacity
        fn sym(&mut self, s: &str) -> Symbol {
            self.i.intern(s).expect("intern test literal")
        }

        fn con(&mut self, name: &str, args: Vec<Ty>) -> Ty {
            Ty::Con {
                module: Vec::new(),
                name: self.sym(name),
                args,
            }
        }

        fn user(&mut self, name: &str, args: Vec<Ty>) -> Ty {
            Ty::Con {
                module: self.home.clone(),
                name: self.sym(name),
                args,
            }
        }

        fn canon_con(&mut self, builtin: bool, name: &str, args: Vec<canon::Type>) -> canon::Type {
            canon::Type::Con {
                home: if builtin {
                    Vec::new()
                } else {
                    self.home.clone()
                },
                name: self.sym(name),
                args,
            }
        }

        fn module(&self, unions: Vec<canon::Union>) -> canon::Module {
            canon::Module {
                imports_unsafe_submodule: false,
                imported_web_capabilities: BTreeSet::new(),
                name: self.home.clone(),
                unions,
                defs: Vec::new(),
            }
        }

        fn union(&mut self, name: &str, vars: &[&str], fields: Vec<canon::Type>) -> canon::Union {
            let name = self.sym(name);
            canon::Union {
                home: self.home.clone(),
                name,
                vars: vars.iter().map(|v| self.sym(v)).collect(),
                ctors: vec![canon::Ctor {
                    name,
                    index: 0,
                    arity: fields.len(),
                    args: fields,
                    span: Span::DUMMY,
                }],
            }
        }

        fn solved(&self, env: Vec<(Symbol, Ty)>, regions: Vec<Ty>) -> SolvedTypes {
            SolvedTypes {
                env: env
                    .into_iter()
                    .map(|(s, t)| ((self.home.clone(), s), t))
                    .collect(),
                regions: regions
                    .into_iter()
                    .zip(0_u32..)
                    .map(|(t, n)| ((self.home.clone(), Span::new(n, n.saturating_add(1))), t))
                    .collect(),
                expected: BTreeMap::new(),
                bounds: BTreeMap::new(),
                warnings: Vec::new(),
                poly_var_map: BTreeMap::new(),
                untyped_type_params: BTreeMap::new(),
                msg_defaulted_vars: BTreeMap::new(),
            }
        }

        fn check(&self, solved: &SolvedTypes, unions: Vec<canon::Union>) -> CheckResult {
            check_wasm_decoder_elements(solved, &self.module(unions), &self.i)
        }
    }

    fn refused(r: &CheckResult) -> bool {
        matches!(
            r,
            Err((
                Diagnostic::Name {
                    msg: NameError::EffectCarrierInDecoder { .. },
                    ..
                },
                _
            ))
        )
    }

    #[test]
    fn decoder_of_each_effect_carrier_is_refused() {
        for carrier in ["Cmd", "Sub", "Task"] {
            let mut fx = Fixture::new();
            let msg = fx.user("Msg", Vec::new());
            let eff = fx.con(carrier, vec![msg]);
            let dec = fx.con("Decoder", vec![eff]);
            let r = fx.check(&fx.solved(Vec::new(), vec![dec]), Vec::new());
            assert!(refused(&r), "Decoder ({carrier} Msg) must be refused");
        }
    }

    #[test]
    fn nested_effect_carrier_in_a_decoder_element_is_refused() {
        let mut fx = Fixture::new();
        let int = fx.con("Int", Vec::new());
        let task = fx.con("Task", vec![int.clone(), int]);
        let list = fx.con("List", vec![task]);
        let jobs = fx.sym("jobs");
        let rec = Ty::Record(BTreeMap::from([(jobs, list)]), RowTail::Closed);
        let dec = fx.con("Decoder", vec![Ty::Tuple(vec![Ty::Unit, rec])]);
        let r = fx.check(&fx.solved(Vec::new(), vec![dec]), Vec::new());
        assert!(refused(&r));
    }

    #[test]
    fn union_holding_an_effect_carrier_is_refused_in_a_decoder() {
        let mut fx = Fixture::new();
        let cmd = fx.canon_con(true, "Cmd", vec![canon::Type::Unit]);
        let inner = fx.union("Inner", &[], vec![cmd]);
        let inner_ref = fx.canon_con(false, "Inner", Vec::new());
        let outer = fx.union("Outer", &[], vec![inner_ref]);
        let outer_ty = fx.user("Outer", Vec::new());
        let dec = fx.con("Decoder", vec![outer_ty]);
        let r = fx.check(&fx.solved(Vec::new(), vec![dec]), vec![outer, inner]);
        assert!(
            refused(&r),
            "a union reaching Cmd through another union is effectful"
        );
    }

    #[test]
    fn union_parameter_reaching_a_decoder_is_refused_at_an_effect_type() {
        let mut fx = Fixture::new();
        let a = fx.sym("a");
        let field = fx.canon_con(true, "Decoder", vec![canon::Type::Var(a)]);
        let wrap = fx.union("Wrap", &["a"], vec![field]);
        let cmd = fx.con("Cmd", vec![Ty::Unit]);
        let wrapped = fx.user("Wrap", vec![cmd]);
        let r = fx.check(&fx.solved(Vec::new(), vec![wrapped]), vec![wrap]);
        assert!(refused(&r), "Wrap (Cmd ()) holds a Decoder (Cmd ())");
    }

    #[test]
    fn unexposed_type_variable_in_a_decoder_element_is_refused() {
        let mut fx = Fixture::new();
        let hidden = Ty::Var(crate::tag_solver_var(7));
        let dec = fx.con("Decoder", vec![hidden]);
        let r = fx.check(&fx.solved(Vec::new(), vec![dec]), Vec::new());
        assert!(refused(&r));
    }

    #[test]
    fn exposed_type_variable_in_a_decoder_element_is_accepted() {
        let mut fx = Fixture::new();
        let v = Ty::Var(crate::tag_solver_var(7));
        let sig_dec = fx.con("Decoder", vec![v.clone()]);
        let sig = Ty::Fun(Box::new(v.clone()), Box::new(sig_dec));
        let helper = fx.sym("helper");
        let dec = fx.con("Decoder", vec![v]);
        let r = fx.check(&fx.solved(vec![(helper, sig)], vec![dec]), Vec::new());
        assert!(r.is_ok());
    }

    #[test]
    fn decoder_inside_a_function_type_is_refused_at_an_effect_type() {
        let mut fx = Fixture::new();
        let msg = fx.user("Msg", Vec::new());
        let cmd = fx.con("Cmd", vec![msg]);
        let dec = fx.con("Decoder", vec![cmd.clone()]);
        let use_site = Ty::Fun(Box::new(cmd), Box::new(dec));
        let r = fx.check(&fx.solved(Vec::new(), vec![use_site]), Vec::new());
        assert!(
            refused(&r),
            "a generic use at `Cmd Msg -> Decoder (Cmd Msg)` is refused"
        );
    }

    #[test]
    fn typed_signature_exposes_its_body_representative() {
        let mut fx = Fixture::new();
        let a = fx.sym("a");
        let helper = fx.sym("helper");
        let sig = fx.con("Decoder", vec![Ty::Var(a.as_raw())]);
        let body = fx.con("Decoder", vec![Ty::Var(crate::tag_solver_var(9))]);
        let mut solved = fx.solved(vec![(helper, sig)], vec![body]);
        solved
            .poly_var_map
            .insert((fx.home.clone(), helper), BTreeMap::from([(9, a)]));
        assert!(fx.check(&solved, Vec::new()).is_ok());
    }

    #[test]
    fn plain_data_and_functions_in_a_decoder_element_are_accepted() {
        let mut fx = Fixture::new();
        let msg = fx.user("Msg", Vec::new());
        let cmd = fx.con("Cmd", vec![msg.clone()]);
        let handler = Ty::Fun(Box::new(msg.clone()), Box::new(cmd.clone()));
        let dec_msg = fx.con("Decoder", vec![msg.clone()]);
        let dec_fn = fx.con("Decoder", vec![handler]);
        let task_of_dec = fx.con("Task", vec![msg, dec_msg.clone()]);
        let cmd_of_cmd = fx.con("Cmd", vec![cmd]);
        let r = fx.check(
            &fx.solved(Vec::new(), vec![dec_msg, dec_fn, task_of_dec, cmd_of_cmd]),
            Vec::new(),
        );
        assert!(r.is_ok(), "only a decoder element is Send-required");
    }
}
