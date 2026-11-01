//! The typed foreign-call AST and its reject-at-decode gate.
//!
//! A [`Call`] describes how to invoke one foreign function: the callee path,
//! which wrapper argument feeds which slot, the receiver form, and every
//! involved type. Its ONLY constructor is [`Call::decode`], which runs the
//! structural checks *inside* decode — a malformed AST is a hard `IPE-F4400`
//! diagnostic, never a deferred cargo failure. Once decode succeeds,
//! [`Call::render_body`] and every other render method is total: illegal
//! placement is unrepresentable, so no emitted call can fail the Rust build.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::diag::{CallDefect, Diagnostic, WireDefect};
use crate::naming::{RustIdent, RustPathSegment, RustTypeExpr, arg_name};
use crate::num_coerce::{NumWidth, num_saturate};
use crate::typeref::{ArgTypeRef, ClosureKind, InnerTypeRef, WireTypeRef};

/// Whether the call has a receiver (a self input) or is a free/static call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallKind {
    /// `recv.method(args)` — has a self input; a receiver MUST be present.
    Method,
    /// `Path::method(args)` / `Path(args)` — no self input, no receiver.
    Function,
}

/// How a receiver is passed to the method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ByKind {
    /// `&arg`.
    Ref,
    /// `&mut arg`.
    RefMut,
    /// `arg`.
    Value,
}

impl ByKind {
    fn apply(self, s: &str) -> String {
        match self {
            Self::Ref => format!("&{s}"),
            Self::RefMut => format!("&mut {s}"),
            Self::Value => s.to_owned(),
        }
    }
}

/// The receiver of a method call: which wrapper value-arg supplies it and how
/// it is passed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Receiver {
    /// The wrapper value-arg index supplying the receiver.
    pub arg: usize,
    /// The borrow form.
    pub by: ByKind,
}

const fn default_true() -> bool {
    true
}

/// The wire shape of a `call` object, decoded permissively; every absent
/// optional key takes the byte-compatible default.
#[derive(Debug, Deserialize)]
struct WireCall {
    kind: String,
    path: Vec<String>,
    #[serde(default, rename = "typeArgs")]
    type_args: Vec<WireTypeRef>,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    receiver: Option<WireReceiver>,
    #[serde(default)]
    args: Vec<usize>,
    #[serde(default, rename = "argTypes")]
    arg_types: Vec<WireTypeRef>,
    ret: WireTypeRef,
    #[serde(default = "default_true", rename = "assocOnType")]
    assoc_on_type: bool,
    #[serde(default, rename = "iterAdapters")]
    iter_adapters: Vec<usize>,
    #[serde(default, rename = "borrowAsRefArgs")]
    borrow_as_ref_args: Vec<usize>,
    #[serde(default, rename = "traitQualifier")]
    trait_qualifier: Option<(String, String)>,
    #[serde(default, rename = "isAsync")]
    is_async: bool,
    #[serde(default, rename = "methodTurbofish")]
    method_turbofish: Vec<WireTypeRef>,
}

#[derive(Debug, Deserialize)]
struct WireReceiver {
    arg: usize,
    by: String,
}

/// One validated Rust call expression. Fields are private: the only way to
/// obtain a `Call` is [`Call::decode`], so every existing value has passed
/// the structural checks and every render method is total.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call {
    kind: CallKind,
    path: Vec<RustPathSegment>,
    type_args: Vec<InnerTypeRef>,
    method: Option<RustIdent>,
    receiver: Option<Receiver>,
    args: Vec<usize>,
    arg_types: Vec<ArgTypeRef>,
    ret: InnerTypeRef,
    assoc_on_type: bool,
    iter_adapters: Vec<usize>,
    borrow_as_ref_args: Vec<usize>,
    trait_qualifier: Option<(RustTypeExpr, RustTypeExpr)>,
    is_async: bool,
    method_turbofish: Vec<InnerTypeRef>,
}

impl Call {
    /// Decode + validate a `call` JSON object against the enclosing generic
    /// block's declared param count. `function` names the binding for the
    /// diagnostic. This is the ONLY constructor.
    ///
    /// # Errors
    ///
    /// `IPE-F4401` for wire-level defects (JSON shape, unknown kind strings);
    /// `IPE-F4400` for a structurally unrenderable call.
    pub fn decode(
        n_params: usize,
        value: serde_json::Value,
        function: &str,
    ) -> Result<Self, Diagnostic> {
        let wire_malformed = |defect: WireDefect| Diagnostic::WireMalformed {
            context: format!("call for `{function}`"),
            defect,
        };
        let unrenderable = |defect: CallDefect| Diagnostic::CallUnrenderable {
            function: function.to_owned(),
            defect,
        };

        let w: WireCall = serde_json::from_value(value).map_err(|e| {
            wire_malformed(WireDefect::Json {
                detail: e.to_string(),
            })
        })?;

        let kind = match w.kind.as_str() {
            "method" => CallKind::Method,
            "function" => CallKind::Function,
            _ => return Err(wire_malformed(WireDefect::UnknownCallKind { got: w.kind })),
        };
        let receiver = match w.receiver {
            None => None,
            Some(r) => {
                let by = match r.by.as_str() {
                    "ref" => ByKind::Ref,
                    "refmut" => ByKind::RefMut,
                    "value" => ByKind::Value,
                    _ => return Err(wire_malformed(WireDefect::UnknownByKind { got: r.by })),
                };
                Some(Receiver { arg: r.arg, by })
            }
        };

        // Position-split the type references: a closure anywhere but a direct
        // arg slot is unrepresentable in the domain types (`IPE-F4400`).
        let type_args: Vec<InnerTypeRef> = w
            .type_args
            .into_iter()
            .map(InnerTypeRef::try_from)
            .collect::<Result<_, _>>()
            .map_err(unrenderable)?;
        let arg_types: Vec<ArgTypeRef> = w
            .arg_types
            .into_iter()
            .map(ArgTypeRef::try_from)
            .collect::<Result<_, _>>()
            .map_err(unrenderable)?;
        let ret = InnerTypeRef::try_from(w.ret).map_err(unrenderable)?;
        let method_turbofish: Vec<InnerTypeRef> = w
            .method_turbofish
            .into_iter()
            .map(InnerTypeRef::try_from)
            .collect::<Result<_, _>>()
            .map_err(unrenderable)?;

        // Every path segment / method / trait-qualifier renders VERBATIM into
        // the wrapper body, so each is parsed into a validated newtype at
        // decode — an injection-bearing segment drops the binding (over-drop)
        // rather than reaching emission.
        let path: Vec<RustPathSegment> = w
            .path
            .iter()
            .map(|seg| RustPathSegment::parse(seg))
            .collect::<Result<_, _>>()
            .map_err(wire_malformed)?;
        let method = match &w.method {
            None => None,
            Some(m) => Some(RustIdent::parse(m).map_err(wire_malformed)?),
        };
        let trait_qualifier = match &w.trait_qualifier {
            None => None,
            Some((self_path, trait_path)) => {
                let s = RustTypeExpr::parse(self_path).map_err(wire_malformed)?;
                let t = RustTypeExpr::parse(trait_path).map_err(wire_malformed)?;
                Some((s, t))
            }
        };

        let call = Self {
            kind,
            path,
            type_args,
            method,
            receiver,
            args: w.args,
            arg_types,
            ret,
            assoc_on_type: w.assoc_on_type,
            iter_adapters: w.iter_adapters,
            borrow_as_ref_args: w.borrow_as_ref_args,
            trait_qualifier,
            is_async: w.is_async,
            method_turbofish,
        };
        call.validate(n_params).map_err(unrenderable)?;
        Ok(call)
    }

    /// The wrapper's value-arg count: one past the max arg index referenced
    /// by the receiver + args. Validation proved the indices gap-free, so
    /// this never undercounts a referenced arg.
    #[must_use]
    pub fn arity(&self) -> usize {
        self.referenced_indices()
            .into_iter()
            .max()
            .map_or(0, |m| m + 1)
    }

    /// Whether the host function is `async fn`.
    #[must_use]
    pub const fn is_async(&self) -> bool {
        self.is_async
    }

    /// Whether the callee is a trait associated fn/method — the shape whose
    /// only correct render is UFCS (`<Self as Trait>::m`). The flat-field
    /// `_bindings.rs` emitter skips such a binding entirely; it is emitted by
    /// the generic-instance path instead.
    #[must_use]
    pub const fn has_trait_qualifier(&self) -> bool {
        self.trait_qualifier.is_some()
    }

    /// The declared argument type of each wrapper value-arg, in slot order.
    #[must_use]
    pub fn arg_types(&self) -> &[ArgTypeRef] {
        &self.arg_types
    }

    /// The method receiver, when the call is a method (validation proved the
    /// method ⇔ receiver correspondence).
    #[must_use]
    pub const fn receiver(&self) -> Option<Receiver> {
        self.receiver
    }

    /// The wrapper return type reference.
    #[must_use]
    pub const fn ret(&self) -> &InnerTypeRef {
        &self.ret
    }

    fn referenced_indices(&self) -> Vec<usize> {
        let mut idxs: Vec<usize> = self.receiver.iter().map(|r| r.arg).collect();
        idxs.extend(&self.args);
        idxs
    }

    /// Re-serialize to the wire JSON shape, omitting every default-valued
    /// key exactly as the inspector does. The cached `kernel.json` carries
    /// this re-serialization of the validated domain value, so a warm build
    /// re-runs the identical decode gate on read (a hand-corrupted cache is
    /// re-rejected).
    #[must_use]
    pub fn to_wire_json(&self) -> serde_json::Value {
        let mut o = serde_json::Map::new();
        let kind = match self.kind {
            CallKind::Method => "method",
            CallKind::Function => "function",
        };
        o.insert("kind".into(), kind.into());
        let path: Vec<&str> = self.path.iter().map(RustPathSegment::as_str).collect();
        o.insert("path".into(), serde_json::json!(path));
        if !self.type_args.is_empty() {
            let ts: Vec<serde_json::Value> = self
                .type_args
                .iter()
                .map(InnerTypeRef::to_wire_json)
                .collect();
            o.insert("typeArgs".into(), ts.into());
        }
        if let Some(m) = &self.method {
            o.insert("method".into(), m.as_str().into());
        }
        if let Some(r) = self.receiver {
            let by = match r.by {
                ByKind::Ref => "ref",
                ByKind::RefMut => "refmut",
                ByKind::Value => "value",
            };
            o.insert(
                "receiver".into(),
                serde_json::json!({"arg": r.arg, "by": by}),
            );
        }
        if !self.args.is_empty() {
            o.insert("args".into(), serde_json::json!(self.args));
        }
        if !self.arg_types.is_empty() {
            let ts: Vec<serde_json::Value> = self
                .arg_types
                .iter()
                .map(ArgTypeRef::to_wire_json)
                .collect();
            o.insert("argTypes".into(), ts.into());
        }
        o.insert("ret".into(), self.ret.to_wire_json());
        if !self.assoc_on_type {
            o.insert("assocOnType".into(), false.into());
        }
        if !self.iter_adapters.is_empty() {
            o.insert("iterAdapters".into(), serde_json::json!(self.iter_adapters));
        }
        if !self.borrow_as_ref_args.is_empty() {
            o.insert(
                "borrowAsRefArgs".into(),
                serde_json::json!(self.borrow_as_ref_args),
            );
        }
        if let Some((s, t)) = &self.trait_qualifier {
            o.insert(
                "traitQualifier".into(),
                serde_json::json!([s.as_str(), t.as_str()]),
            );
        }
        if self.is_async {
            o.insert("isAsync".into(), true.into());
        }
        if !self.method_turbofish.is_empty() {
            let ts: Vec<serde_json::Value> = self
                .method_turbofish
                .iter()
                .map(InnerTypeRef::to_wire_json)
                .collect();
            o.insert("methodTurbofish".into(), ts.into());
        }
        serde_json::Value::Object(o)
    }

    /// The structural checks that make every render method total.
    fn validate(&self, n_params: usize) -> Result<(), CallDefect> {
        // (1) every param ref anywhere is < n_params.
        let mut param_refs = Vec::new();
        for t in &self.type_args {
            t.param_indices(&mut param_refs);
        }
        for t in &self.arg_types {
            t.param_indices(&mut param_refs);
        }
        for t in &self.method_turbofish {
            t.param_indices(&mut param_refs);
        }
        self.ret.param_indices(&mut param_refs);
        if let Some(&bad) = param_refs.iter().find(|&&i| i >= n_params) {
            return Err(CallDefect::ParamRefOutOfRange {
                index: bad,
                n_params,
            });
        }
        // (2) receiver present iff the call is a method.
        match (self.kind, &self.receiver) {
            (CallKind::Method, None) => return Err(CallDefect::ReceiverMissingForMethod),
            (CallKind::Function, Some(_)) => return Err(CallDefect::ReceiverForbiddenForFunction),
            _ => {}
        }
        // (3) + (4) arg indices unique and gap-free from 0 (non-negativity is
        // structural: the wire type is usize).
        let idxs = self.referenced_indices();
        let mut seen: Vec<usize> = Vec::new();
        for &i in &idxs {
            if seen.contains(&i) {
                return Err(CallDefect::ArgIndexDuplicated { index: i });
            }
            seen.push(i);
        }
        let arity = idxs.iter().max().map_or(0, |m| m + 1);
        if let Some(missing) = (0..arity).find(|j| !idxs.contains(j)) {
            return Err(CallDefect::ArgIndexGap { missing });
        }
        // (5) argTypes covers exactly one type per wrapper value-arg.
        if self.arg_types.len() != arity {
            return Err(CallDefect::ArgTypeArityMismatch {
                arg_types_len: self.arg_types.len(),
                arity,
            });
        }
        // (6) closure-only-as-direct-arg is structural: `InnerTypeRef` has no
        // closure variant, so the domain conversion already rejected it.
        // (7) every iterAdapters index targets a real Vec-typed slot.
        for &i in &self.iter_adapters {
            if i >= arity {
                return Err(CallDefect::IterAdapterOutOfRange { index: i, arity });
            }
            let is_vec =
                matches!(self.arg_types.get(i), Some(ArgTypeRef::Inner(t)) if t.is_vec_ctor());
            if !is_vec {
                return Err(CallDefect::IterAdapterTargetNotVec { index: i });
            }
        }
        Ok(())
    }

    /// Render the wrapper BODY call expression. `params` are the declared
    /// generic param names, positional with `Param` indices.
    #[must_use]
    pub fn render_body(&self, params: &[String]) -> String {
        let path_str = self
            .path
            .iter()
            .map(RustPathSegment::as_str)
            .collect::<Vec<_>>()
            .join("::");
        let render_list = |trs: &[InnerTypeRef]| -> String {
            let rendered: Vec<String> = trs.iter().map(|t| t.render(params)).collect();
            rendered.join(", ")
        };
        let turbofish = if self.type_args.is_empty() {
            String::new()
        } else {
            format!("::<{}>", render_list(&self.type_args))
        };
        // The method's OWN generics' resolved concretes, rendered as a
        // method-level turbofish. The EXPLICIT list is the ONLY source: the
        // inspector emits one entry per serde/mono-reduced own generic, and a
        // method with NO own generics (a CONCRETE serde claims lift such as
        // `validate -> HashMap<String, Value>`) legitimately touches serde
        // with no turbofish at all — inferring one from serde-touch was an
        // E0107 on every such method. Empty list => empty string.
        let explicit_method_turbofish = if self.method_turbofish.is_empty() {
            String::new()
        } else {
            format!("::<{}>", render_list(&self.method_turbofish))
        };
        let method_turbofish = explicit_method_turbofish.clone();
        let callee = match (&self.trait_qualifier, &self.method) {
            // A trait method on a concrete type renders `<Self as Trait>::m`.
            // No path turbofish — every tyvar reaches the callee through a
            // typed value-arg; the serde-driven method turbofish still fires
            // (without it Rust cannot infer the reduced `T`).
            (Some((self_path, trait_path)), m) => {
                let m = m.as_ref().map_or("", RustIdent::as_str);
                format!(
                    "<{} as {}>::{m}{method_turbofish}",
                    self_path.as_str(),
                    trait_path.as_str()
                )
            }
            // An assoc fn / method on a TYPE: the turbofish binds the impl
            // Self type BEFORE the method; the method's own generics go after.
            (None, Some(m)) if self.assoc_on_type => {
                format!(
                    "{path_str}{turbofish}::{}{explicit_method_turbofish}",
                    m.as_str()
                )
            }
            // A FREE function in a crate/module: the path turbofish is
            // OMITTED (partial `::<A, B>` is E0107; a turbofish on the crate
            // path is E0109) — Rust infers every type-param from the args.
            (None, Some(m)) => {
                format!("{path_str}::{}{explicit_method_turbofish}", m.as_str())
            }
            (None, None) => format!("{path_str}{turbofish}"),
        };
        let mut all_args: Vec<String> = Vec::with_capacity(self.arity());
        if let Some(r) = self.receiver {
            all_args.push(r.by.apply(&arg_name(r.arg)));
        }
        all_args.extend(self.args.iter().map(|&j| self.render_value_arg(j)));
        format!("{callee}({})", all_args.join(", "))
    }

    /// Render value-arg `j` at the call site: the owned-clone bridge for a
    /// by-ref closure, the deserialised `sv_j` local for a serde slot, the
    /// saturating narrow for a concrete numeric width, the `.into_iter()` /
    /// `.as_ref()` adapters, else the bare identifier.
    fn render_value_arg(&self, j: usize) -> String {
        // A concrete numeric param travels as the Ipê carrier; narrow to the
        // foreign width at the call site (identity for i64/f64).
        if let Some(ArgTypeRef::Inner(InnerTypeRef::Prim(w))) = self.arg_types.get(j)
            && let Some(nw) = NumWidth::parse(w.as_str())
        {
            return num_saturate(nw, &arg_name(j));
        }
        match self.arg_types.get(j) {
            // The host wants `Fn(&A)`; the Ipê closure only takes OWNED
            // values, so each borrowed slot is cloned to owned inside a
            // bridge — a reference can never escape the FFI boundary.
            Some(ArgTypeRef::Closure {
                by_ref: true,
                arg_types,
                ..
            }) => owned_clone_bridge(j, arg_types.len()),
            // A serde-reduced value-arg is passed as the deserialised local
            // the wrapper prelude binds (`sv_j`), not the raw JSON `String`.
            Some(ArgTypeRef::Inner(InnerTypeRef::SerdeValue)) => format!("sv_{j}"),
            // A `&T` serde input borrows the same owned local.
            Some(ArgTypeRef::Inner(InnerTypeRef::SerdeValueRef)) => format!("&sv_{j}"),
            _ => {
                if self.iter_adapters.contains(&j) {
                    format!("{}.into_iter()", arg_name(j))
                } else if self.borrow_as_ref_args.contains(&j) {
                    format!("{}.as_ref()", arg_name(j))
                } else {
                    arg_name(j)
                }
            }
        }
    }

    /// Render the wrapper RETURN type (the payload inside the runtime's
    /// result carrier).
    #[must_use]
    pub fn render_ret_type(&self, params: &[String]) -> String {
        self.ret.render(params)
    }

    /// Render wrapper value-arg `j`'s Rust type for the wrapper signature.
    /// A closure slot emits `Fj` (the fresh type-param from
    /// [`Call::closure_bounds`]); a concrete numeric width emits its Ipê
    /// carrier; everything else renders directly. The `()` fallback for an
    /// out-of-range `j` is unreachable post-validation, kept total.
    #[must_use]
    pub fn render_arg_type_at(&self, params: &[String], j: usize) -> String {
        match self.arg_types.get(j) {
            Some(ArgTypeRef::Closure { .. }) => format!("F{j}"),
            Some(ArgTypeRef::Inner(InnerTypeRef::Prim(w))) => NumWidth::parse(w.as_str())
                .map_or_else(
                    || InnerTypeRef::Prim(w.clone()).render(params),
                    |nw| nw.carrier().rust().to_owned(),
                ),
            Some(ArgTypeRef::Inner(t)) => t.render(params),
            None => "()".to_owned(),
        }
    }

    /// One `"Fj: Kind(args) -> ret [+ ::core::clone::Clone]"` bound string
    /// per closure arg, in wrapper-arg-index order — slots directly into the
    /// emitted wrapper's `<…>` type-param clause.
    #[must_use]
    pub fn closure_bounds(&self, params: &[String]) -> Vec<String> {
        self.arg_types
            .iter()
            .enumerate()
            .filter_map(|(j, at)| match at {
                ArgTypeRef::Closure {
                    kind,
                    arg_types,
                    ret,
                    ..
                } => {
                    let args: Vec<String> = arg_types.iter().map(|t| t.render(params)).collect();
                    let clone = if kind.needs_clone() {
                        " + ::core::clone::Clone"
                    } else {
                        ""
                    };
                    Some(format!(
                        "F{j}: {}({}) -> {}{clone}",
                        kind.as_str(),
                        args.join(", "),
                        ret.render(params)
                    ))
                }
                ArgTypeRef::Inner(_) => None,
            })
            .collect()
    }

    /// The closure trait kind of every closure-typed slot, keyed by wrapper
    /// value-arg index. The capture gate consults this to learn whether a
    /// slot is multi-call (`Fn`/`FnMut` — Clone captures required) or
    /// single-call (`FnOnce` — a move-in non-Clone capture is admitted).
    #[must_use]
    pub fn closure_slot_kinds(&self) -> BTreeMap<usize, ClosureKind> {
        self.arg_types
            .iter()
            .enumerate()
            .filter_map(|(j, at)| match at {
                ArgTypeRef::Closure { kind, .. } => Some((j, *kind)),
                ArgTypeRef::Inner(_) => None,
            })
            .collect()
    }
}

/// The owned-clone bridge for a by-ref closure wrapper-arg at value-arg
/// index `j` whose host signature is `Fn(&T0, …, &T{n-1}) -> R`:
///
/// ```text
/// move |__r0, __r1| { let __v0 = __r0.clone(); let __v1 = __r1.clone(); argJ(__v0, __v1) }
/// ```
///
/// A reference handed in by the host is consumed entirely inside the bridge
/// and never reaches Ipê. The `__`-prefixed names are hygienic (a wrapper
/// param is always `argK`).
fn owned_clone_bridge(j: usize, arity: usize) -> String {
    use std::fmt::Write;
    let ref_params: Vec<String> = (0..arity).map(|i| format!("__r{i}")).collect();
    let mut clone_stmts = String::new();
    for i in 0..arity {
        // Writing into a String is infallible.
        let _ = write!(clone_stmts, "let __v{i} = __r{i}.clone(); ");
    }
    let owned_args: Vec<String> = (0..arity).map(|i| format!("__v{i}")).collect();
    format!(
        "move |{}| {{ {clone_stmts}{}({}) }}",
        ref_params.join(", "),
        arg_name(j),
        owned_args.join(", ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn decode(n_params: usize, v: serde_json::Value) -> Result<Call, Diagnostic> {
        Call::decode(n_params, v, "test_fn")
    }

    /// The `CallDefect` of an `IPE-F4400` rejection; `None` for anything else
    /// (the caller's `assert_eq!` then reports the mismatch).
    fn call_defect(r: Result<Call, Diagnostic>) -> Option<CallDefect> {
        match r {
            Err(Diagnostic::CallUnrenderable { defect, .. }) => Some(defect),
            _ => None,
        }
    }

    /// The `WireDefect` of an `IPE-F4401` rejection; `None` for anything else.
    fn wire_defect(r: Result<Call, Diagnostic>) -> Option<WireDefect> {
        match r {
            Err(Diagnostic::WireMalformed { defect, .. }) => Some(defect),
            _ => None,
        }
    }

    fn set(v: &mut serde_json::Value, key: &str, val: serde_json::Value) {
        v.as_object_mut()
            .expect("a JSON object")
            .insert(key.to_owned(), val);
    }

    fn static_ctor() -> serde_json::Value {
        json!({
            "kind": "function",
            "path": ["::box1", "Box1"],
            "typeArgs": [{"param": 0}],
            "method": "make",
            "args": [0],
            "argTypes": [{"param": 0}],
            "ret": {"ctor": "::box1::Box1", "args": [{"param": 0}]}
        })
    }

    fn method_left() -> serde_json::Value {
        json!({
            "kind": "method",
            "path": ["::mycrate", "Pair"],
            "typeArgs": [{"param": 0}, {"param": 1}],
            "method": "left",
            "receiver": {"arg": 0, "by": "ref"},
            "args": [],
            "argTypes": [{"ctor": "::mycrate::Pair", "args": [{"param": 0}, {"param": 1}]}],
            "ret": {"param": 0}
        })
    }

    #[test]
    fn decodes_and_renders_a_static_ctor() {
        let c = decode(1, static_ctor()).expect("decodes");
        let params = vec!["a".to_owned()];
        assert_eq!(c.render_body(&params), "::box1::Box1::<A>::make(arg0)");
        assert_eq!(c.render_ret_type(&params), "::box1::Box1<A>");
        assert_eq!(c.render_arg_type_at(&params, 0), "A");
        assert_eq!(c.arity(), 1);
    }

    #[test]
    fn decodes_and_renders_a_method_with_a_ref_receiver() {
        let c = decode(2, method_left()).expect("decodes");
        let params = vec!["k".to_owned(), "v".to_owned()];
        assert_eq!(
            c.render_body(&params),
            "::mycrate::Pair::<K, V>::left(&arg0)"
        );
        assert_eq!(c.render_ret_type(&params), "K");
        assert_eq!(c.arity(), 1);
    }

    #[test]
    fn free_crate_function_omits_the_turbofish() {
        let c = decode(
            2,
            json!({
                "kind": "function",
                "path": ["::clo"],
                "typeArgs": [{"param": 0}, {"param": 1}],
                "method": "map_each",
                "args": [0, 1],
                "argTypes": [
                    {"ctor": "Vec", "args": [{"param": 0}]},
                    {"closure": {"kind": "Fn", "byRef": false,
                                  "argTypes": [{"param": 0}], "ret": {"param": 1}}}
                ],
                "ret": {"ctor": "Vec", "args": [{"param": 1}]},
                "assocOnType": false
            }),
        )
        .expect("decodes");
        let params = vec!["a".to_owned(), "b".to_owned()];
        assert_eq!(c.render_body(&params), "::clo::map_each(arg0, arg1)");
        assert_eq!(
            c.closure_bounds(&params),
            vec!["F1: Fn(A) -> B + ::core::clone::Clone".to_owned()]
        );
        assert_eq!(c.render_arg_type_at(&params, 1), "F1");
        assert_eq!(
            c.closure_slot_kinds(),
            BTreeMap::from([(1, ClosureKind::Fn)])
        );
    }

    #[test]
    fn by_ref_closure_arg_passes_the_owned_clone_bridge() {
        let keep = |by_ref: bool| {
            decode(
                1,
                json!({
                    "kind": "function",
                    "path": ["::clo"],
                    "typeArgs": [{"param": 0}],
                    "method": "keep",
                    "args": [0, 1],
                    "argTypes": [
                        {"ctor": "Vec", "args": [{"param": 0}]},
                        {"closure": {"kind": "Fn", "byRef": by_ref,
                                      "argTypes": [{"param": 0}], "ret": {"prim": "bool"}}}
                    ],
                    "ret": {"ctor": "Vec", "args": [{"param": 0}]},
                    "assocOnType": false
                }),
            )
            .expect("decodes")
        };
        let params = vec!["a".to_owned()];
        let bridged = keep(true).render_body(&params);
        assert!(
            bridged.contains("move |__r0| { let __v0 = __r0.clone(); arg1(__v0) }"),
            "{bridged}"
        );
        let direct = keep(false).render_body(&params);
        assert!(direct.contains("(arg0, arg1)"), "{direct}");
        assert!(!direct.contains(".clone()"), "{direct}");
    }

    #[test]
    fn multi_borrow_closure_clones_each_arg_independently() {
        let c = decode(
            2,
            json!({
                "kind": "function",
                "path": ["::clo"],
                "typeArgs": [{"param": 0}, {"param": 1}],
                "method": "zip_with",
                "args": [0],
                "argTypes": [
                    {"closure": {"kind": "Fn", "byRef": true,
                                  "argTypes": [{"param": 0}, {"param": 1}], "ret": {"param": 0}}}
                ],
                "ret": {"param": 0},
                "assocOnType": false
            }),
        )
        .expect("decodes");
        let r = c.render_body(&["a".to_owned(), "b".to_owned()]);
        assert!(
            r.contains(
                "move |__r0, __r1| { let __v0 = __r0.clone(); let __v1 = __r1.clone(); arg0(__v0, __v1) }"
            ),
            "{r}"
        );
    }

    #[test]
    fn ufcs_trait_method_renders_the_qualified_callee() {
        let c = decode(
            1,
            json!({
                "kind": "method",
                "path": ["::tm", "Circle"],
                "method": "keyed",
                "receiver": {"arg": 0, "by": "ref"},
                "args": [1],
                "argTypes": [{"ctor": "::tm::Circle"}, {"param": 0}],
                "ret": {"prim": "i64"},
                "traitQualifier": ["::tm::Circle", "::tm::Scale"]
            }),
        )
        .expect("decodes");
        let r = c.render_body(&["T".to_owned()]);
        assert_eq!(r, "<::tm::Circle as ::tm::Scale>::keyed(&arg0, arg1)");
        assert!(!r.contains("::tm::Circle::keyed"), "{r}");
    }

    #[test]
    fn serde_generic_turbofish_comes_only_from_the_explicit_list() {
        // Serde-reduced own generic: the inspector emits the explicit list.
        let c = decode(
            0,
            json!({
                "kind": "method",
                "path": ["::db", "Db"],
                "method": "get_obj",
                "receiver": {"arg": 0, "by": "ref"},
                "args": [],
                "argTypes": [{"ctor": "::db::Db"}],
                "ret": {"ctor": "::core::result::Result",
                        "args": [{"serdeValue": true}, {"ctor": "::std::string::String"}]},
                "traitQualifier": ["::db::Db", "::db::Repo"],
                "methodTurbofish": [{"serdeValue": true}],
                "isAsync": true
            }),
        )
        .expect("decodes");
        assert!(c.is_async());
        assert_eq!(
            c.render_body(&[]),
            "<::db::Db as ::db::Repo>::get_obj::<serde_json::Value>(&arg0)"
        );
        // A CONCRETE serde return (claims map lift) has NO own generics and
        // no explicit list — the call must render with NO turbofish (the
        // host method takes zero generic arguments; inferring one is E0107).
        let c = decode(
            0,
            json!({
                "kind": "method",
                "path": ["::fb", "Validator"],
                "method": "validate",
                "receiver": {"arg": 0, "by": "ref"},
                "args": [],
                "argTypes": [{"ctor": "::fb::Validator"}],
                "ret": {"ctor": "::core::result::Result",
                        "args": [{"serdeValue": true}, {"prim": "String"}]},
                "traitQualifier": ["::fb::Validator", "::fb::TokenValidator"],
                "isAsync": true
            }),
        )
        .expect("decodes");
        assert_eq!(
            c.render_body(&[]),
            "<::fb::Validator as ::fb::TokenValidator>::validate(&arg0)"
        );
    }

    #[test]
    fn serde_value_arg_renders_the_deserialised_local() {
        let c = decode(
            0,
            json!({
                "kind": "method",
                "path": ["::db", "Db"],
                "method": "put_obj",
                "receiver": {"arg": 0, "by": "ref"},
                "args": [1],
                "argTypes": [{"ctor": "::db::Db"}, {"serdeValue": true}],
                "ret": {"ctor": "::core::result::Result",
                        "args": [{"ctor": "()"}, {"ctor": "::std::string::String"}]},
                "traitQualifier": ["::db::Db", "::db::Repo"],
                "methodTurbofish": [{"serdeValue": true}],
                "isAsync": true
            }),
        )
        .expect("decodes");
        assert_eq!(
            c.render_body(&[]),
            "<::db::Db as ::db::Repo>::put_obj::<serde_json::Value>(&arg0, sv_1)"
        );
    }

    #[test]
    fn non_serde_trait_method_omits_the_method_turbofish() {
        let c = decode(
            1,
            json!({
                "kind": "method",
                "path": ["::tm", "Circle"],
                "typeArgs": [{"param": 0}],
                "method": "keyed",
                "receiver": {"arg": 0, "by": "ref"},
                "args": [1],
                "argTypes": [{"ctor": "::tm::Circle"}, {"param": 0}],
                "ret": {"prim": "i64"},
                "traitQualifier": ["::tm::Circle", "::tm::Scale"]
            }),
        )
        .expect("decodes");
        assert!(!c.render_body(&["T".to_owned()]).contains("::<"));
    }

    #[test]
    fn explicit_method_turbofish_names_a_concrete_per_own_generic() {
        let c = decode(
            0,
            json!({
                "kind": "method",
                "path": ["::db", "Db"],
                "method": "get_obj",
                "receiver": {"arg": 0, "by": "ref"},
                "args": [1],
                "argTypes": [{"ctor": "::db::Db"}, {"ctor": "::std::string::String"}],
                "ret": {"ctor": "::core::result::Result",
                        "args": [{"serdeValue": true}, {"ctor": "::std::string::String"}]},
                "traitQualifier": ["::db::Db", "::db::Repo"],
                "methodTurbofish": [{"serdeValue": true}, {"ctor": "String"}]
            }),
        )
        .expect("decodes");
        assert_eq!(
            c.render_body(&[]),
            "<::db::Db as ::db::Repo>::get_obj::<serde_json::Value, String>(&arg0, arg1)"
        );
    }

    #[test]
    fn iterator_bound_arg_renders_into_iter_only_on_tagged_slots() {
        let mk = |adapters: serde_json::Value| {
            decode(
                1,
                json!({
                    "kind": "function",
                    "path": ["::it"],
                    "method": "sum_all",
                    "args": [0, 1],
                    "argTypes": [
                        {"ctor": "::Vec", "args": [{"param": 0}]},
                        {"ctor": "::Vec", "args": [{"param": 0}]}
                    ],
                    "ret": {"param": 0},
                    "assocOnType": false,
                    "iterAdapters": adapters
                }),
            )
        };
        let tagged = mk(json!([1])).expect("decodes");
        assert_eq!(
            tagged.render_body(&["a".to_owned()]),
            "::it::sum_all(arg0, arg1.into_iter())"
        );
        let untagged = mk(json!([])).expect("decodes");
        assert_eq!(
            untagged.render_body(&["a".to_owned()]),
            "::it::sum_all(arg0, arg1)"
        );
    }

    #[test]
    fn borrow_as_ref_arg_renders_as_ref() {
        let c = decode(
            0,
            json!({
                "kind": "function",
                "path": ["::semver"],
                "method": "parse",
                "args": [0],
                "argTypes": [{"ctor": "::std::string::String"}],
                "ret": {"ctor": "::std::string::String"},
                "assocOnType": false,
                "borrowAsRefArgs": [0]
            }),
        )
        .expect("decodes");
        assert_eq!(c.render_body(&[]), "::semver::parse(arg0.as_ref())");
    }

    #[test]
    fn numeric_prim_arg_narrows_via_num_saturate() {
        let c = decode(
            0,
            json!({
                "kind": "function",
                "path": ["::num"],
                "method": "take_u32",
                "args": [0],
                "argTypes": [{"prim": "u32"}],
                "ret": {"prim": "u64"},
                "assocOnType": false
            }),
        )
        .expect("decodes");
        assert_eq!(
            c.render_body(&[]),
            "::num::take_u32((arg0).clamp(0, u32::MAX as i64) as u32)"
        );
        // The wrapper param type is the carrier, not the foreign width.
        assert_eq!(c.render_arg_type_at(&[], 0), "i64");
    }

    #[test]
    fn wire_round_trip_is_lossless_and_re_validates() {
        for v in [
            static_ctor(),
            method_left(),
            json!({
                "kind": "method",
                "path": ["::db", "Db"],
                "method": "get_obj",
                "receiver": {"arg": 0, "by": "refmut"},
                "args": [1],
                "argTypes": [
                    {"ctor": "::db::Db"},
                    {"closure": {"kind": "FnOnce", "byRef": true,
                                  "argTypes": [{"serdeValue": true}], "ret": {"prim": "bool"}}}
                ],
                "ret": {"serdeValueRef": true},
                "assocOnType": false,
                "borrowAsRefArgs": [],
                "traitQualifier": ["::db::Db", "::db::Repo"],
                "isAsync": true,
                "methodTurbofish": [{"serdeValue": true}]
            }),
        ] {
            let first = decode(2, v).expect("decodes");
            let rewired = first.to_wire_json();
            let second = Call::decode(2, rewired.clone(), "test_fn").expect("re-decodes");
            assert_eq!(first, second, "round-trip must be lossless: {rewired}");
        }
    }

    // ── negative corpus: each structural check rejects, never defaults ──

    #[test]
    fn rejects_an_unknown_kind() {
        let mut v = static_ctor();
        set(&mut v, "kind", json!("staticmethod"));
        assert!(matches!(
            wire_defect(decode(1, v)),
            Some(WireDefect::UnknownCallKind { .. })
        ));
    }

    #[test]
    fn rejects_an_unknown_receiver_by_kind() {
        let mut v = method_left();
        set(&mut v, "receiver", json!({"arg": 0, "by": "borrow"}));
        assert!(matches!(
            wire_defect(decode(2, v)),
            Some(WireDefect::UnknownByKind { .. })
        ));
    }

    #[test]
    fn rejects_an_out_of_range_param_ref() {
        let mut v = static_ctor();
        set(&mut v, "ret", json!({"param": 5}));
        assert_eq!(
            call_defect(decode(1, v)),
            Some(CallDefect::ParamRefOutOfRange {
                index: 5,
                n_params: 1
            })
        );
    }

    #[test]
    fn rejects_a_missing_ret_field() {
        let mut v = static_ctor();
        v.as_object_mut().expect("object").remove("ret");
        assert!(matches!(
            wire_defect(decode(1, v)),
            Some(WireDefect::Json { .. })
        ));
    }

    #[test]
    fn rejects_a_method_with_no_receiver() {
        let mut v = method_left();
        v.as_object_mut().expect("object").remove("receiver");
        assert_eq!(
            call_defect(decode(2, v)),
            Some(CallDefect::ReceiverMissingForMethod)
        );
    }

    #[test]
    fn rejects_a_function_carrying_a_receiver() {
        let mut v = static_ctor();
        set(&mut v, "receiver", json!({"arg": 0, "by": "ref"}));
        assert_eq!(
            call_defect(decode(1, v)),
            Some(CallDefect::ReceiverForbiddenForFunction)
        );
    }

    #[test]
    fn rejects_a_gapped_arg_index() {
        let mut v = static_ctor();
        set(&mut v, "args", json!([0, 2]));
        set(
            &mut v,
            "argTypes",
            json!([{"param": 0}, {"param": 0}, {"param": 0}]),
        );
        assert_eq!(
            call_defect(decode(1, v)),
            Some(CallDefect::ArgIndexGap { missing: 1 })
        );
    }

    #[test]
    fn rejects_a_duplicated_arg_index() {
        let mut v = method_left();
        set(&mut v, "args", json!([0]));
        set(&mut v, "argTypes", json!([{"ctor": "::mycrate::Pair"}]));
        assert_eq!(
            call_defect(decode(2, v)),
            Some(CallDefect::ArgIndexDuplicated { index: 0 })
        );
    }

    #[test]
    fn rejects_an_arg_types_arity_mismatch() {
        let mut v = static_ctor();
        set(&mut v, "argTypes", json!([{"param": 0}, {"param": 0}]));
        assert_eq!(
            call_defect(decode(1, v)),
            Some(CallDefect::ArgTypeArityMismatch {
                arg_types_len: 2,
                arity: 1
            })
        );
    }

    #[test]
    fn rejects_a_negative_arg_index_at_the_wire_layer() {
        let mut v = static_ctor();
        set(&mut v, "args", json!([-1]));
        assert!(matches!(
            wire_defect(decode(1, v)),
            Some(WireDefect::Json { .. })
        ));
    }

    #[test]
    fn rejects_a_closure_nested_in_a_container() {
        let mut v = static_ctor();
        set(
            &mut v,
            "argTypes",
            json!([
                {"ctor": "Vec", "args": [
                    {"closure": {"kind": "Fn", "argTypes": [{"param": 0}], "ret": {"prim": "bool"}}}
                ]}
            ]),
        );
        assert_eq!(
            call_defect(decode(1, v)),
            Some(CallDefect::ClosureNestedOrNonDirect)
        );
    }

    #[test]
    fn rejects_a_closure_in_the_return_position() {
        let mut v = static_ctor();
        set(
            &mut v,
            "ret",
            json!({"closure": {"kind": "Fn", "argTypes": [{"param": 0}], "ret": {"prim": "bool"}}}),
        );
        assert_eq!(
            call_defect(decode(1, v)),
            Some(CallDefect::ClosureNestedOrNonDirect)
        );
    }

    #[test]
    fn rejects_an_out_of_range_iter_adapter() {
        let mut v = static_ctor();
        set(
            &mut v,
            "argTypes",
            json!([{"ctor": "::Vec", "args": [{"param": 0}]}]),
        );
        set(&mut v, "iterAdapters", json!([3]));
        assert_eq!(
            call_defect(decode(1, v)),
            Some(CallDefect::IterAdapterOutOfRange { index: 3, arity: 1 })
        );
    }

    #[test]
    fn rejects_an_iter_adapter_on_a_non_vec_arg() {
        let mut v = static_ctor();
        set(&mut v, "iterAdapters", json!([0]));
        assert_eq!(
            call_defect(decode(1, v)),
            Some(CallDefect::IterAdapterTargetNotVec { index: 0 })
        );
    }

    #[test]
    fn rejects_a_type_ref_with_two_discriminators() {
        let mut v = static_ctor();
        set(&mut v, "ret", json!({"param": 0, "prim": "i64"}));
        let detail = match wire_defect(decode(1, v)) {
            Some(WireDefect::Json { detail }) => detail,
            _ => String::new(),
        };
        assert!(detail.contains("more than one discriminator"), "{detail}");
    }
}
