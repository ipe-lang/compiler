//! Every `Ipe.Browser.*.Internals` decoder gates on its own capability's frame tag.
//!
//! The tag a module accepts is its `portTag` literal, asserted equal to the wire
//! name of the capability its import path discloses, and every decoder the
//! module exposes or hands to any `Ipe.Ffi.Js` member reads that tag first. Only
//! these modules reach the port, and every port use is visible to the scan.

use std::collections::BTreeSet;

use ipe_intern::{Interner, Symbol};
use ipe_kernels::WebCapability;
use ipe_stdlib::{COMPILED_STD_MODULES, MODULES};
use ipe_syntax::{
    Exposed, Exposing, Expr, Expr_, Module, Pattern, Pattern_, TypeAnnotation, Value,
};

/// One parsed `Ipe.Browser.<Api>.Internals` module and the names it is read by.
struct Internals {
    dotted: &'static str,
    capability: WebCapability,
    module: Module,
    interner: Interner,
}

impl Internals {
    #[allow(clippy::expect_used)] // A test helper: interning a short ASCII name cannot fail.
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

/// How many top-level references `gated` follows from a decoder to its gate
/// (`subscribeReply` applies `reply`, whose body is the gate).
const FOLLOW_DEPTH: usize = 3;

/// Whether `expr` is `Decode.andThen (gateTag body) (Decode.field "tag" Decode.string)`,
/// directly or as the body of a top-level value it names or applies, at most
/// `depth` references away.
fn gated(internals: &mut Internals, expr: &Expr, depth: usize) -> bool {
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
    let Some(depth) = depth.checked_sub(1) else {
        return false;
    };
    let target = match &expr.value {
        Expr_::VarLocal(name) => Some(*name),
        Expr_::Call(callee, _) => match &callee.value {
            Expr_::VarLocal(name) => Some(*name),
            _ => None,
        },
        _ => None,
    };
    let body = target.and_then(|name| internals.value(name).map(|v| v.body.clone()));
    body.is_some_and(|body| gated(internals, &body, depth))
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

/// Which argument of each `Ipe.Ffi.Js` member is a decoder; `None` for a member
/// that takes none.
///
/// `js_decoder_positions_match_the_ffi_signatures` holds it to the `Ipe.Ffi.Js`
/// annotations, so a new member cannot reach a port call site unclassified.
const JS_DECODER_POSITION: &[(&str, Option<usize>)] = &[
    ("send", None),
    ("subscribe", Some(0)),
    ("request", Some(1)),
    ("openSession", Some(1)),
    ("sessionFrames", Some(1)),
    ("sendToSession", None),
    ("closeSession", Some(2)),
];

/// What one walk of a module finds at its port.
#[derive(Default)]
struct PortScan {
    /// The decoder argument of every saturated `Js.<member>` call that takes one.
    decoders: Vec<Expr>,
    /// Every `Js.<member>` use whose decoder the walk cannot see.
    unseen: Vec<String>,
    /// Every name a parameter, lambda, `let` or `case` pattern binds.
    binders: Vec<Symbol>,
}

/// Each name `pattern` binds.
fn pattern_binders(pattern: &Pattern, out: &mut Vec<Symbol>) {
    match &pattern.value {
        Pattern_::PVar(name) => out.push(*name),
        Pattern_::PAlias(inner, name) => {
            out.push(name.value);
            pattern_binders(inner, out);
        }
        Pattern_::PRecord(fields) => out.extend(fields.iter().map(|f| f.value)),
        Pattern_::PCtor(_, _, items)
        | Pattern_::PTuple(items)
        | Pattern_::PList(items)
        | Pattern_::POr(items) => {
            for item in items {
                pattern_binders(item, out);
            }
        }
        Pattern_::PCons(head, tail) => {
            pattern_binders(head, out);
            pattern_binders(tail, out);
        }
        Pattern_::PAnything
        | Pattern_::PDebugAnything
        | Pattern_::PUnit
        | Pattern_::PInt(_)
        | Pattern_::PBool(_)
        | Pattern_::PChar(_)
        | Pattern_::PStr(_) => {}
    }
}

/// The decoder position of `Js.<member>`, or `Err` naming a member the table lacks.
fn js_member(internals: &Internals, member: Symbol) -> Result<Option<usize>, String> {
    let text = internals.text(member);
    JS_DECODER_POSITION
        .iter()
        .find(|(name, _)| *name == text)
        .map(|(_, position)| *position)
        .ok_or_else(|| format!("unknown member Js.{text}"))
}

/// Walks `expr`, recording port decoders, unseen port uses and local binders.
fn scan(internals: &Internals, js: Symbol, expr: &Expr, out: &mut PortScan) {
    match &expr.value {
        Expr_::Call(callee, args) => {
            if let Expr_::VarQual(q, member) = &callee.value
                && *q == js
            {
                match js_member(internals, *member) {
                    Ok(Some(position)) => match args.get(position) {
                        Some(decoder) => out.decoders.push(decoder.clone()),
                        None => out.unseen.push(format!(
                            "Js.{} applied without its decoder",
                            internals.text(*member)
                        )),
                    },
                    Ok(None) => {}
                    Err(unknown) => out.unseen.push(unknown),
                }
            } else {
                scan(internals, js, callee, out);
            }
            for arg in args {
                scan(internals, js, arg, out);
            }
        }
        Expr_::VarQual(q, member) if *q == js => match js_member(internals, *member) {
            Ok(None) => {}
            Ok(Some(_)) => out
                .unseen
                .push(format!("Js.{} passed as a value", internals.text(*member))),
            Err(unknown) => out.unseen.push(unknown),
        },
        Expr_::Case(scrutinee, arms) => {
            scan(internals, js, scrutinee, out);
            for (pattern, rhs) in arms {
                pattern_binders(pattern, &mut out.binders);
                scan(internals, js, rhs, out);
            }
        }
        Expr_::Lambda(patterns, body) => {
            for pattern in patterns {
                pattern_binders(pattern, &mut out.binders);
            }
            scan(internals, js, body, out);
        }
        Expr_::Access(body, _) => scan(internals, js, body, out),
        Expr_::Binops(operands, last) => {
            for (operand, _) in operands {
                scan(internals, js, operand, out);
            }
            scan(internals, js, last, out);
        }
        Expr_::Let(bindings, body) => {
            for binding in bindings {
                pattern_binders(&binding.pat, &mut out.binders);
                scan(internals, js, &binding.body, out);
            }
            scan(internals, js, body, out);
        }
        Expr_::If(branches, otherwise) => {
            for (condition, branch) in branches {
                scan(internals, js, condition, out);
                scan(internals, js, branch, out);
            }
            scan(internals, js, otherwise, out);
        }
        Expr_::Tuple(items) | Expr_::List(items) => {
            for item in items {
                scan(internals, js, item, out);
            }
        }
        Expr_::Record(fields) | Expr_::Update(_, fields) => {
            for (_, value) in fields {
                scan(internals, js, value, out);
            }
        }
        Expr_::VarLocal(_)
        | Expr_::VarQual(..)
        | Expr_::TaskAndThen
        | Expr_::Int(_)
        | Expr_::Float(_)
        | Expr_::Str(_)
        | Expr_::MultilineStr { .. }
        | Expr_::Char(_)
        | Expr_::Unit => {}
    }
}

/// One walk over every top-level value of the module.
fn port_scan(internals: &mut Internals) -> PortScan {
    let js = internals.symbol("Js");
    let mut out = PortScan::default();
    for value in &internals.module.values {
        for pattern in &value.value.patterns {
            pattern_binders(pattern, &mut out.binders);
        }
        scan(internals, js, &value.value.body, &mut out);
    }
    out
}

/// Every stdlib module, embedded or compiled, parsed with its dotted name.
fn every_stdlib_module() -> Vec<(&'static str, Module, Interner)> {
    let compiled = COMPILED_STD_MODULES.iter().map(|m| (m.dotted, m.source));
    let embedded = MODULES.iter().map(|m| (m.name, m.source));
    compiled
        .chain(embedded)
        .filter_map(|(dotted, source)| {
            let mut interner = Interner::new();
            let module = ipe_parse::parse_module(source, &mut interner);
            assert!(module.is_ok(), "{dotted} does not parse");
            Some((dotted, module.ok()?, interner))
        })
        .collect()
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
                gated(&mut internals, &value.body, FOLLOW_DEPTH),
                "{dotted}.{text} decodes a frame without reading its tag first"
            );
        }
        assert!(exposed_decoders > 0, "{dotted} exposes no decoder");
        let scan = port_scan(&mut internals);
        assert!(
            scan.unseen.is_empty(),
            "{dotted} reaches the port where its decoder cannot be judged: {:?}",
            scan.unseen
        );
        let shadowing: Vec<&str> = scan
            .binders
            .iter()
            .filter(|binder| {
                internals
                    .module
                    .values
                    .iter()
                    .any(|v| v.value.name.value == **binder)
            })
            .map(|binder| internals.text(*binder))
            .collect();
        assert!(
            shadowing.is_empty(),
            "{dotted} binds a local over a top-level name the gate reads: {shadowing:?}"
        );
        assert!(!scan.decoders.is_empty(), "{dotted} has no port call site");
        for decoder in scan.decoders {
            assert!(
                gated(&mut internals, &decoder, FOLLOW_DEPTH),
                "{dotted} hands the port a decoder that does not read its tag first"
            );
        }
    }
}

/// `JS_DECODER_POSITION` names every value `Ipe.Ffi.Js` exposes, each with the
/// one argument its annotation types as a `Decoder`.
#[test]
fn js_decoder_positions_match_the_ffi_signatures() {
    let modules = every_stdlib_module();
    let js = modules
        .iter()
        .find(|(dotted, _, _)| *dotted == "Ipe.Ffi.Js");
    assert!(js.is_some(), "Ipe.Ffi.Js is not a stdlib module");
    let Some((_, module, interner)) = js else {
        return;
    };
    let Exposing::List(items) = &module.exposing.value else {
        assert!(
            matches!(module.exposing.value, Exposing::List(_)),
            "Ipe.Ffi.Js exposes everything"
        );
        return;
    };
    let mut seen = Vec::new();
    for item in items {
        let Exposed::Value(name) = &item.value else {
            continue;
        };
        let text = interner.resolve(*name).unwrap_or_default();
        let value = module.values.iter().find(|v| v.value.name.value == *name);
        let annotation = value.and_then(|v| v.value.type_annotation.as_ref());
        assert!(annotation.is_some(), "Js.{text} has no annotation");
        let mut positions = Vec::new();
        let mut cursor = annotation.map(|a| &a.value);
        let mut index = 0usize;
        while let Some(TypeAnnotation::TLambda(argument, result)) = cursor {
            if matches!(
                argument.as_ref(),
                TypeAnnotation::TType(_, segments, _)
                    if segments.last().and_then(|s| interner.resolve(*s)) == Some("Decoder")
            ) {
                positions.push(index);
            }
            index += 1;
            cursor = Some(result.as_ref());
        }
        let expected = JS_DECODER_POSITION
            .iter()
            .find(|(member, _)| *member == text)
            .map(|(_, position)| *position);
        assert!(
            positions.len() <= 1,
            "Js.{text} takes more than one decoder"
        );
        assert_eq!(
            expected,
            Some(positions.first().copied()),
            "Js.{text}'s decoder position is not the one JS_DECODER_POSITION lists"
        );
        seen.push(text.to_owned());
    }
    let mut listed: Vec<&str> = JS_DECODER_POSITION.iter().map(|(m, _)| *m).collect();
    listed.sort_unstable();
    seen.sort_unstable();
    assert_eq!(
        seen, listed,
        "JS_DECODER_POSITION and Ipe.Ffi.Js's values differ"
    );
}

/// Only an `Ipe.Browser.<Api>.Internals` module reaches the port, through
/// `import Ipe.Ffi.Js as Js` with no exposing list, and its `Decode` qualifier
/// is `Ipe.Json.Decode`; no module but `Ipe.Ffi.Js` names a `Js_` kernel.
#[test]
fn only_browser_internals_reach_the_port_through_the_js_qualifier() {
    for (dotted, module, interner) in every_stdlib_module() {
        let source = COMPILED_STD_MODULES
            .iter()
            .map(|m| (m.dotted, m.source))
            .chain(MODULES.iter().map(|m| (m.name, m.source)))
            .find(|(name, _)| *name == dotted)
            .map(|(_, source)| source)
            .unwrap_or_default();
        if dotted != "Ipe.Ffi.Js" {
            assert!(
                !source.contains("\"Js_"),
                "{dotted} names a Js_ kernel outside Ipe.Ffi.Js"
            );
        }
        let segments: Vec<&str> = dotted.split('.').collect();
        let internals = matches!(segments.as_slice(), ["Ipe", "Browser", _, "Internals"]);
        for import in &module.imports {
            let name: Vec<&str> = import
                .name
                .value
                .iter()
                .map(|s| interner.resolve(*s).unwrap_or_default())
                .collect();
            let alias = import.alias.and_then(|a| interner.resolve(a));
            let bare = matches!(&import.exposing.value, Exposing::List(items) if items.is_empty());
            if name == ["Ipe", "Ffi", "Js"] {
                assert!(internals, "{dotted} imports Ipe.Ffi.Js");
                assert!(
                    alias == Some("Js") && bare,
                    "{dotted} imports Ipe.Ffi.Js other than `as Js` with no exposing list"
                );
            } else if internals {
                assert!(alias != Some("Js"), "{dotted} aliases another module as Js");
                assert!(
                    alias != Some("Decode") || name == ["Ipe", "Json", "Decode"],
                    "{dotted} aliases another module as Decode"
                );
            }
        }
    }
}
