//! Every `Ipe.Browser.*.Internals` decoder gates on its own capability's frame tag.
//!
//! The tag a module accepts is its `portTag` literal, asserted equal to the wire
//! name of the capability its import path discloses, and every decoder the
//! module exposes or hands to `Js.request`/`Js.subscribe` reads that tag first.

use std::collections::BTreeSet;

use ipe_intern::{Interner, Symbol};
use ipe_kernels::WebCapability;
use ipe_stdlib::COMPILED_STD_MODULES;
use ipe_syntax::{Exposed, Exposing, Expr, Expr_, Module, Pattern_, TypeAnnotation, Value};

/// One parsed `Ipe.Browser.<Api>.Internals` module and the names it is read by.
struct Internals {
    dotted: &'static str,
    capability: WebCapability,
    module: Module,
    interner: Interner,
}

impl Internals {
    fn symbol(&mut self, name: &str) -> Symbol {
        self.interner.intern(name).expect("a short name interns")
    }

    fn value(&self, name: Symbol) -> Option<&Value> {
        self.module
            .values
            .iter()
            .map(|v| &v.value)
            .find(|v| v.name.value == name)
    }

    fn text(&self, sym: Symbol) -> &str {
        self.interner.resolve(sym).unwrap_or_default()
    }
}

/// Every `Ipe.Browser.<Api>.Internals` module in the compiled stdlib, parsed.
fn internals_modules() -> Vec<Internals> {
    COMPILED_STD_MODULES
        .iter()
        .filter_map(|m| {
            let segments: Vec<&str> = m.dotted.split('.').collect();
            if !matches!(segments.as_slice(), ["Ipe", "Browser", _, "Internals"]) {
                return None;
            }
            let capability = WebCapability::for_browser_module(&segments);
            assert!(capability.is_some(), "{} discloses no capability", m.dotted);
            let mut interner = Interner::new();
            let module = ipe_parse::parse_module(m.source, &mut interner);
            assert!(module.is_ok(), "{} does not parse", m.dotted);
            let module = module.ok()?;
            Some(Internals {
                dotted: m.dotted,
                capability: capability?,
                module,
                interner,
            })
        })
        .collect()
}

/// The result type of an annotation, past every arrow.
fn result_type(annotation: &TypeAnnotation) -> &TypeAnnotation {
    match annotation {
        TypeAnnotation::TLambda(_, result) => result_type(result),
        other => other,
    }
}

/// Whether `expr` is `Decode.andThen (gateTag body) (Decode.field "tag" Decode.string)`,
/// directly or as the body of the one local binding it names or applies.
fn gated(internals: &mut Internals, expr: &Expr, follow: bool) -> bool {
    let decode = internals.symbol("Decode");
    let and_then = internals.symbol("andThen");
    let field = internals.symbol("field");
    let string = internals.symbol("string");
    let gate_tag = internals.symbol("gateTag");
    if let Expr_::Call(callee, args) = &expr.value
        && matches!(&callee.value, Expr_::VarQual(q, m) if *q == decode && *m == and_then)
        && let [gate, read] = args.as_slice()
    {
        let gate_ok = matches!(
            &gate.value,
            Expr_::Call(f, gate_args)
                if matches!(&f.value, Expr_::VarLocal(name) if *name == gate_tag)
                    && gate_args.len() == 1
        );
        let read_ok = matches!(
            &read.value,
            Expr_::Call(f, read_args)
                if matches!(&f.value, Expr_::VarQual(q, m) if *q == decode && *m == field)
                    && matches!(
                        read_args.as_slice(),
                        [key, decoder]
                            if matches!(&key.value, Expr_::Str(k) if k == "tag")
                                && matches!(
                                    &decoder.value,
                                    Expr_::VarQual(q, m) if *q == decode && *m == string
                                )
                    )
        );
        return gate_ok && read_ok;
    }
    if !follow {
        return false;
    }
    let target = match &expr.value {
        Expr_::VarLocal(name) => Some(*name),
        Expr_::Call(callee, _) => match &callee.value {
            Expr_::VarLocal(name) => Some(*name),
            _ => None,
        },
        _ => None,
    };
    let body = target.and_then(|name| internals.value(name).map(|v| v.body.clone()));
    body.is_some_and(|body| gated(internals, &body, false))
}

/// `gateTag body tag = if tag == portTag then body else Decode.fail "<constant>"`.
fn gate_tag_compares_with_port_tag(internals: &mut Internals) -> bool {
    let gate_tag = internals.symbol("gateTag");
    let port_tag = internals.symbol("portTag");
    let decode = internals.symbol("Decode");
    let fail = internals.symbol("fail");
    let Some(value) = internals.value(gate_tag) else {
        return false;
    };
    let [body_pat, tag_pat] = value.patterns.as_slice() else {
        return false;
    };
    let (Pattern_::PVar(body_param), Pattern_::PVar(tag_param)) = (&body_pat.value, &tag_pat.value)
    else {
        return false;
    };
    let Expr_::If(branches, otherwise) = &value.body.value else {
        return false;
    };
    let [(condition, then)] = branches.as_slice() else {
        return false;
    };
    let compares = match &condition.value {
        Expr_::Binops(operands, last) => match operands.as_slice() {
            [(left, op)] => {
                matches!(&left.value, Expr_::VarLocal(t) if t == tag_param)
                    && internals.text(op.value) == "=="
                    && matches!(&last.value, Expr_::VarLocal(p) if *p == port_tag)
            }
            _ => false,
        },
        _ => false,
    };
    let passes = matches!(&then.value, Expr_::VarLocal(b) if b == body_param);
    let refuses_without_echo = matches!(
        &otherwise.value,
        Expr_::Call(f, args)
            if matches!(&f.value, Expr_::VarQual(q, m) if *q == decode && *m == fail)
                && matches!(args.as_slice(), [message] if matches!(&message.value, Expr_::Str(_)))
    );
    compares && passes && refuses_without_echo
}

/// The decoder argument of every `Js.request cmd decoder` / `Js.subscribe decoder toMsg`.
fn port_decoders(internals: &mut Internals) -> Vec<Expr> {
    let js = internals.symbol("Js");
    let request = internals.symbol("request");
    let subscribe = internals.symbol("subscribe");
    let mut found = Vec::new();
    let mut stack: Vec<Expr> = internals
        .module
        .values
        .iter()
        .map(|v| v.value.body.clone())
        .collect();
    while let Some(expr) = stack.pop() {
        match expr.value {
            Expr_::Call(callee, args) => {
                let position = match &callee.value {
                    Expr_::VarQual(q, m) if *q == js && *m == request => Some(1),
                    Expr_::VarQual(q, m) if *q == js && *m == subscribe => Some(0),
                    _ => None,
                };
                if let Some(decoder) = position.and_then(|p| args.get(p)) {
                    found.push(decoder.clone());
                }
                stack.push(*callee);
                stack.extend(args);
            }
            Expr_::Case(scrutinee, arms) => {
                stack.push(*scrutinee);
                stack.extend(arms.into_iter().map(|(_, rhs)| rhs));
            }
            Expr_::Lambda(_, body) | Expr_::Access(body, _) => stack.push(*body),
            Expr_::Binops(operands, last) => {
                stack.extend(operands.into_iter().map(|(operand, _)| operand));
                stack.push(*last);
            }
            Expr_::Let(bindings, body) => {
                stack.extend(bindings.into_iter().map(|b| b.body));
                stack.push(*body);
            }
            Expr_::If(branches, otherwise) => {
                for (condition, branch) in branches {
                    stack.push(condition);
                    stack.push(branch);
                }
                stack.push(*otherwise);
            }
            Expr_::Tuple(items) | Expr_::List(items) => stack.extend(items),
            Expr_::Record(fields) | Expr_::Update(_, fields) => {
                stack.extend(fields.into_iter().map(|(_, value)| value));
            }
            _ => {}
        }
    }
    found
}

/// Each module's `portTag` is the wire name of the capability its path discloses,
/// and the modules cover every capability but `raw` exactly once.
#[test]
fn every_port_tag_is_its_capability_wire_name() {
    let mut modules = internals_modules();
    let mut covered = BTreeSet::new();
    for internals in &mut modules {
        let port_tag = internals.symbol("portTag");
        let value = internals.value(port_tag);
        assert!(value.is_some(), "{} defines no portTag", internals.dotted);
        let literal = value.and_then(|v| match &v.body.value {
            Expr_::Str(text) if v.patterns.is_empty() => Some(text.clone()),
            _ => None,
        });
        assert_eq!(
            literal.as_deref(),
            Some(internals.capability.as_str()),
            "{}'s portTag is not its capability's wire name",
            internals.dotted
        );
        assert!(
            covered.insert(internals.capability.as_str()),
            "{} repeats a capability",
            internals.dotted
        );
    }
    let expected: BTreeSet<&str> = WebCapability::ALL
        .iter()
        .copied()
        .filter(|cap| *cap != WebCapability::Raw)
        .map(WebCapability::as_str)
        .collect();
    assert_eq!(covered, expected);
}

/// Every decoder a module exposes or hands to the port reads `tag` first and
/// passes the rest only through `gateTag`, which compares against `portTag`.
#[test]
fn every_port_decoder_reads_its_tag_first() {
    for mut internals in internals_modules() {
        let dotted = internals.dotted;
        assert!(
            gate_tag_compares_with_port_tag(&mut internals),
            "{dotted}'s gateTag does not refuse every tag but portTag with a constant text"
        );
        let decoder = internals.symbol("Decoder");
        let exposed: Vec<Symbol> = match &internals.module.exposing.value {
            Exposing::All => internals
                .module
                .values
                .iter()
                .map(|v| v.value.name.value)
                .collect(),
            Exposing::List(items) => items
                .iter()
                .filter_map(|item| match &item.value {
                    Exposed::Value(name) => Some(*name),
                    Exposed::Type(..) => None,
                })
                .collect(),
        };
        let mut exposed_decoders = 0usize;
        for name in exposed {
            let value = internals.value(name).cloned();
            let Some(value) = value else { continue };
            let is_decoder = value.type_annotation.as_ref().is_some_and(|annotation| {
                matches!(
                    result_type(&annotation.value),
                    TypeAnnotation::TType(_, segments, _) if segments.last() == Some(&decoder)
                )
            });
            if !is_decoder {
                continue;
            }
            exposed_decoders += 1;
            let text = internals.text(name).to_owned();
            assert!(
                gated(&mut internals, &value.body, true),
                "{dotted}.{text} decodes a frame without reading its tag first"
            );
        }
        assert!(exposed_decoders > 0, "{dotted} exposes no decoder");
        let decoders = port_decoders(&mut internals);
        assert!(!decoders.is_empty(), "{dotted} has no port call site");
        for decoder in decoders {
            assert!(
                gated(&mut internals, &decoder, true),
                "{dotted} hands the port a decoder that does not read its tag first"
            );
        }
    }
}
