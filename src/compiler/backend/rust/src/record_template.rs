//! Record-struct templates: one struct per unifiable class of a field-name set.
//!
//! Two occurrences of one field-name set share a struct when they unify, with
//! the type variables of each occurrence renamed apart. A value can flow from
//! one record type to another only when the two unify, so every value-flow
//! between occurrences stays inside one struct. The struct's template is the
//! least general generalization (anti-unification) of every member, so each
//! member instantiates it through `match_template`.

use std::collections::BTreeMap;

use ipe_diagnostics::{DResult, Diagnostic};
use ipe_intern::Symbol;
use ipe_ir::IrType;

use crate::RecordFields;

/// One synthesised struct's reconciled form.
#[derive(Debug, PartialEq, Eq)]
pub struct RecordClass {
    /// The struct's field template, sorted by field name.
    pub template: RecordFields,
    /// The template's type variables, in first-occurrence field order.
    pub type_params: Vec<Symbol>,
    /// Every occurrence in this class, in first-occurrence order.
    pub members: Vec<RecordFields>,
}

/// Partition the occurrences of one field-name set into unifiable classes.
///
/// Classes with a generic template lead, then the monomorphic ones, each group
/// in first-occurrence order. A class whose generalization is alpha-equivalent
/// to one of its members takes that member verbatim as its template, so a
/// single-member class keeps its occurrence byte for byte. Otherwise the
/// template's variables are the interner's first symbols by index (only their
/// position names the Rust parameter); `symbol_count` is the interner's size,
/// so every chosen symbol is one it handed out.
///
/// # Errors
///
/// A [`Diagnostic::CompilerBug`] when `occurrences` is empty, when a row
/// variable reaches a record template, or when the template needs more
/// variables than the interner holds symbols.
pub fn reconcile(
    key: &[String],
    occurrences: &[RecordFields],
    symbol_count: usize,
) -> DResult<Vec<RecordClass>> {
    if occurrences.is_empty() {
        return Err(bug(format!(
            "record field set {{{}}} has no collected shape",
            key.join(", ")
        )));
    }
    let mut parent: Vec<usize> = (0..occurrences.len()).collect();
    for (i, left) in occurrences.iter().enumerate() {
        for (j, right) in occurrences.iter().enumerate().skip(i + 1) {
            if fields_unify(left, right)? {
                let (ri, rj) = (find(&parent, i), find(&parent, j));
                if let Some(slot) = parent.get_mut(rj.max(ri)) {
                    *slot = ri.min(rj);
                }
            }
        }
    }
    // A root is its class's least index, so the map iterates the classes in
    // first-occurrence order.
    let mut groups: BTreeMap<usize, Vec<RecordFields>> = BTreeMap::new();
    for (i, occ) in occurrences.iter().enumerate() {
        groups
            .entry(find(&parent, i))
            .or_default()
            .push(occ.clone());
    }
    let mut classes = Vec::with_capacity(groups.len());
    for members in groups.into_values() {
        let template = class_template(&members, symbol_count)?;
        let mut type_params = Vec::new();
        for (_, ty) in &template {
            ipe_ir::collect_generics(ty, &mut type_params);
        }
        classes.push(RecordClass {
            template,
            type_params,
            members,
        });
    }
    classes.sort_by_key(|class| class.type_params.is_empty());
    Ok(classes)
}

/// Do two field lists unify, with each side's type variables renamed apart?
///
/// The lists must carry equal names in equal order.
///
/// # Errors
///
/// A [`Diagnostic::CompilerBug`] when a row variable is reached.
pub fn fields_unify(left: &[(String, IrType)], right: &[(String, IrType)]) -> DResult<bool> {
    if left.len() != right.len() {
        return Ok(false);
    }
    let mut bindings = Bindings::new();
    for ((ln, lt), (rn, rt)) in left.iter().zip(right) {
        if ln != rn || !unify((Side::Left, lt), (Side::Right, rt), &mut bindings)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// The union-find root of `i`.
fn find(parent: &[usize], mut i: usize) -> usize {
    while let Some(&p) = parent.get(i) {
        if p == i {
            break;
        }
        i = p;
    }
    i
}

/// The template of one class: a member verbatim when one is alpha-equivalent
/// to the class's generalization, else the generalization itself.
fn class_template(members: &[RecordFields], symbol_count: usize) -> DResult<RecordFields> {
    let first = members
        .first()
        .ok_or_else(|| bug("empty record class".to_owned()))?;
    let mut vars = Variables::default();
    let mut template = Vec::with_capacity(first.len());
    for (index, (name, _)) in first.iter().enumerate() {
        let mut column = Vec::with_capacity(members.len());
        for member in members {
            let (member_name, ty) = member
                .get(index)
                .ok_or_else(|| bug(format!("record class member lacks field `{name}`")))?;
            if member_name != name {
                return Err(bug(format!(
                    "record class members disagree on field `{name}` (`{member_name}`)"
                )));
            }
            column.push(ty);
        }
        template.push((name.clone(), generalize(&column, &mut vars)?));
    }
    if let Some(member) = members
        .iter()
        .find(|member| ipe_ir::alpha_equivalent_fields(&template, member))
    {
        return Ok(member.clone());
    }
    if vars.columns.len() > symbol_count {
        return Err(bug(format!(
            "record template needs {} type variables but the interner holds {symbol_count} symbols",
            vars.columns.len()
        )));
    }
    Ok(template)
}

/// The generalization's variables: each disagreeing column of subterms, keyed
/// by its position in this list.
#[derive(Default)]
struct Variables {
    /// One column per variable; a repeated column reuses its variable.
    columns: Vec<Vec<IrType>>,
}

impl Variables {
    /// The variable standing for `column`, minted on first sight.
    fn variable(&mut self, column: &[&IrType]) -> DResult<IrType> {
        let owned: Vec<IrType> = column.iter().map(|ty| (*ty).clone()).collect();
        let index = self
            .columns
            .iter()
            .position(|c| *c == owned)
            .unwrap_or_else(|| {
                self.columns.push(owned);
                self.columns.len() - 1
            });
        let raw = u32::try_from(index)
            .map_err(|_| bug("record template variable index exceeds u32".to_owned()))?;
        Ok(IrType::Generic(Symbol::from_raw(raw)))
    }
}

/// The least general generalization of one column of field types.
fn generalize(column: &[&IrType], vars: &mut Variables) -> DResult<IrType> {
    let (first, rest) = column
        .split_first()
        .ok_or_else(|| bug("empty record template column".to_owned()))?;
    if column.iter().any(|ty| matches!(ty, IrType::RowGeneric(_))) {
        return Err(row_generic_bug());
    }
    if !contains_generic(first) && rest.iter().all(|ty| *ty == *first) {
        return Ok((*first).clone());
    }
    if let IrType::Record(first_fields) = first {
        let same_keys = rest.iter().all(
            |ty| matches!(ty, IrType::Record(fields) if fields.keys().eq(first_fields.keys())),
        );
        if same_keys {
            let mut out = BTreeMap::new();
            for key in first_fields.keys() {
                let mut sub = Vec::with_capacity(column.len());
                for ty in column {
                    if let IrType::Record(fields) = ty
                        && let Some(field) = fields.get(key)
                    {
                        sub.push(field);
                    }
                }
                out.insert(*key, generalize(&sub, vars)?);
            }
            return Ok(IrType::Record(out));
        }
        return vars.variable(column);
    }
    let width = ipe_ir::paired_children(first, first).map_or(0, Iterator::count);
    let mut child_columns: Vec<Vec<&IrType>> = vec![Vec::with_capacity(column.len()); width];
    for ty in column {
        let Some(pairs) = ipe_ir::paired_children(first, ty) else {
            return vars.variable(column);
        };
        for (sub, (_, child)) in child_columns.iter_mut().zip(pairs) {
            sub.push(child);
        }
    }
    let mut node = (*first).clone();
    let slots = children_mut(&mut node);
    if slots.len() != child_columns.len() {
        return Err(bug(
            "record template node's children disagree with its head pairing".to_owned(),
        ));
    }
    for (slot, sub) in slots.into_iter().zip(&child_columns) {
        *slot = generalize(sub, vars)?;
    }
    Ok(node)
}

/// Does `ty` hold a type variable anywhere?
fn contains_generic(ty: &IrType) -> bool {
    let mut found = Vec::new();
    ipe_ir::collect_generics(ty, &mut found);
    !found.is_empty() || holds_row_generic(ty)
}

/// Does `ty` hold a row variable anywhere?
fn holds_row_generic(ty: &IrType) -> bool {
    if matches!(ty, IrType::RowGeneric(_)) {
        return true;
    }
    if let IrType::Record(fields) = ty {
        return fields.values().any(holds_row_generic);
    }
    ipe_ir::paired_children(ty, ty)
        .is_some_and(|mut pairs| pairs.any(|(child, _)| holds_row_generic(child)))
}

/// The mutable children of a compound node, in [`ipe_ir::paired_children`]
/// order: the positional sequence, then the fixed slots.
///
/// A record, a variable, and a leaf have none.
#[allow(clippy::too_many_lines)] // One arm per `IrType` variant, so a new variant is a compile error.
fn children_mut(ty: &mut IrType) -> Vec<&mut IrType> {
    match ty {
        IrType::List(x)
        | IrType::Maybe(x)
        | IrType::Set(x)
        | IrType::Task(x)
        | IrType::Cmd(x)
        | IrType::Sub(x)
        | IrType::Decoder(x)
        | IrType::WebRoute(x)
        | IrType::Ui { msg: x, .. } => vec![&mut **x],
        IrType::Result(x1, x2)
        | IrType::Dict(x1, x2)
        | IrType::CustomElement { down: x1, up: x2 } => vec![&mut **x1, &mut **x2],
        IrType::Tuple(xs) | IrType::Enum { args: xs, .. } => xs.iter_mut().collect(),
        IrType::Fun(params, ret)
        | IrType::SharedFun(params, ret)
        | IrType::FnOnceChain(params, ret) => {
            let mut out: Vec<&mut IrType> = params.iter_mut().collect();
            out.push(&mut **ret);
            out
        }
        IrType::Record(..)
        | IrType::Generic(..)
        | IrType::RowGeneric(..)
        | IrType::UiPlain(..)
        | IrType::Int
        | IrType::Float
        | IrType::Bool
        | IrType::Str
        | IrType::Char
        | IrType::Unit
        | IrType::Bytes
        | IrType::Json
        | IrType::Db
        | IrType::ServerRequest
        | IrType::ServerResponse
        | IrType::ServerRoute
        | IrType::ServerCookie
        | IrType::StreamWriter
        | IrType::HttpRequest
        | IrType::Regex
        | IrType::WebSocketServer
        | IrType::WebSocketServerCfg
        | IrType::WebReq
        | IrType::SessionHandle
        | IrType::BackoffStrategy
        | IrType::Order
        | IrType::HttpMethod
        | IrType::Decimal
        | IrType::ErrorKind
        | IrType::Error
        | IrType::ErrorDetails
        | IrType::ErrorInfo
        | IrType::PanicInfo
        | IrType::TypeInfo
        | IrType::SqlFragment
        | IrType::Secret
        | IrType::Path
        | IrType::Url
        | IrType::UrlRelative
        | IrType::Dsn
        | IrType::DbLocation
        | IrType::Connection
        | IrType::ConnReadOnly
        | IrType::ConnReadWrite
        | IrType::Setting
        | IrType::ShapeWeb
        | IrType::ShapeWebView
        | IrType::ShapeTerminal
        | IrType::ProcessRunWithCfg
        | IrType::ProcessRunInPtyCfg
        | IrType::CacheCfg
        | IrType::WebSocketClientCfg
        | IrType::CacheStats
        | IrType::CsvDoc
        | IrType::EmailMessage
        | IrType::EmailAttachment
        | IrType::EmailSesConfig
        | IrType::EmailSmtpConfig
        | IrType::EmailProvider
        | IrType::CryptoKey
        | IrType::CryptoMac
        | IrType::EmailAddress
        | IrType::Locale
        | IrType::Principal
        | IrType::AuthConfig
        | IrType::TokenSource
        | IrType::WebApp
        | IrType::TuiApp
        | IrType::CliApp
        | IrType::WorkerApp => Vec::new(),
    }
}

/// Which occurrence a type variable belongs to; the two sides never share one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Side {
    /// The first occurrence.
    Left,
    /// The second occurrence.
    Right,
}

/// A side-tagged type: the side names the scope of its variables.
type Sided<'a> = (Side, &'a IrType);

/// The unifier's substitution from a side-tagged variable to a side-tagged type.
type Bindings<'a> = BTreeMap<(Side, Symbol), Sided<'a>>;

/// Follow `bindings` from a variable to the type it stands for.
fn resolve<'a>(mut ty: Sided<'a>, bindings: &Bindings<'a>) -> Sided<'a> {
    while let (side, IrType::Generic(sym)) = ty {
        match bindings.get(&(side, *sym)) {
            Some(next) => ty = *next,
            None => break,
        }
    }
    ty
}

/// Unify two side-tagged types, extending `bindings`.
fn unify<'a>(left: Sided<'a>, right: Sided<'a>, bindings: &mut Bindings<'a>) -> DResult<bool> {
    let (ls, lt) = resolve(left, bindings);
    let (rs, rt) = resolve(right, bindings);
    if matches!(lt, IrType::RowGeneric(_)) || matches!(rt, IrType::RowGeneric(_)) {
        return Err(row_generic_bug());
    }
    if let IrType::Generic(l) = lt {
        if matches!(rt, IrType::Generic(r) if ls == rs && l == r) {
            return Ok(true);
        }
        return bind((ls, *l), (rs, rt), bindings);
    }
    if let IrType::Generic(r) = rt {
        return bind((rs, *r), (ls, lt), bindings);
    }
    if let (IrType::Record(lm), IrType::Record(rm)) = (lt, rt) {
        if !lm.keys().eq(rm.keys()) {
            return Ok(false);
        }
        for (lv, rv) in lm.values().zip(rm.values()) {
            if !unify((ls, lv), (rs, rv), bindings)? {
                return Ok(false);
            }
        }
        return Ok(true);
    }
    // Every other pair agrees in head through the SSOT pairing, or is a leaf
    // pair compared whole.
    let Some(pairs) = ipe_ir::paired_children(lt, rt) else {
        return Ok(lt == rt);
    };
    for (lc, rc) in pairs {
        if !unify((ls, lc), (rs, rc), bindings)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Bind `var` to `ty` unless `ty` holds `var` (the occurs check).
fn bind<'a>(var: (Side, Symbol), ty: Sided<'a>, bindings: &mut Bindings<'a>) -> DResult<bool> {
    if occurs(var, ty, bindings) {
        return Ok(false);
    }
    bindings.insert(var, ty);
    Ok(true)
}

/// Does the side-tagged variable `var` occur in `ty` under `bindings`?
fn occurs(var: (Side, Symbol), ty: Sided<'_>, bindings: &Bindings<'_>) -> bool {
    let (side, ty) = resolve(ty, bindings);
    if let IrType::Generic(sym) = ty {
        return (side, *sym) == var;
    }
    if let IrType::Record(fields) = ty {
        return fields
            .values()
            .any(|field| occurs(var, (side, field), bindings));
    }
    ipe_ir::paired_children(ty, ty)
        .is_some_and(|mut pairs| pairs.any(|(child, _)| occurs(var, (side, child), bindings)))
}

/// The fail-closed error for a row variable reaching a record template.
fn row_generic_bug() -> Diagnostic {
    bug(
        "row-generic type reached record-struct template reconciliation; an open row must never \
         enter the struct registry"
            .to_owned(),
    )
}

/// An internal invariant violation in record-template reconciliation.
const fn bug(detail: String) -> Diagnostic {
    Diagnostic::CompilerBug {
        where_: "ipe_backend_rust::record_template",
        detail,
    }
}

#[cfg(test)]
mod tests {
    use ipe_intern::Interner;

    use super::*;

    /// A one-field list named `q`.
    fn q(ty: IrType) -> RecordFields {
        vec![("q".to_owned(), ty)]
    }

    /// Two unifiable generic shapes (`{q:a}` and `{q:(a,a)}`) share one struct
    /// whose template is the more general member, verbatim.
    #[test]
    fn unifiable_generic_shapes_share_one_struct() -> DResult<()> {
        let mut interner = Interner::new();
        let a = interner.intern("a")?;
        let scalar = q(IrType::Generic(a));
        let pair = q(IrType::Tuple(vec![IrType::Generic(a), IrType::Generic(a)]));
        let concrete = q(IrType::Tuple(vec![IrType::Int, IrType::Int]));
        let out = reconcile(
            &["q".to_owned()],
            &[scalar.clone(), pair.clone(), concrete.clone()],
            interner.len(),
        )?;
        assert_eq!(
            out,
            vec![RecordClass {
                template: scalar.clone(),
                type_params: vec![a],
                members: vec![scalar, pair, concrete],
            }]
        );
        Ok(())
    }

    /// Alpha-equivalent shapes fold to one struct whose template is the first.
    #[test]
    fn alpha_equivalent_shapes_fold_to_the_first() -> DResult<()> {
        let mut interner = Interner::new();
        let a = interner.intern("a")?;
        let b = interner.intern("b")?;
        let with_a = q(IrType::Generic(a));
        let with_b = q(IrType::Generic(b));
        let out = reconcile(&["q".to_owned()], &[with_a.clone(), with_b], interner.len())?;
        assert_eq!(out.len(), 1);
        assert_eq!(out.first().map(|c| &c.template), Some(&with_a));
        Ok(())
    }

    /// Two generic shapes that each instantiate the other nowhere
    /// (`{q:(a,Int)}`, `{q:(Int,b)}`) share one struct whose template is their
    /// generalization `{q:(V1,V2)}`, which no member is alpha-equivalent to.
    #[test]
    fn crossed_generic_shapes_generalize_to_fresh_variables() -> DResult<()> {
        let mut interner = Interner::new();
        let a = interner.intern("a")?;
        let b = interner.intern("b")?;
        let left = q(IrType::Tuple(vec![IrType::Generic(a), IrType::Int]));
        let right = q(IrType::Tuple(vec![IrType::Int, IrType::Generic(b)]));
        let both = q(IrType::Tuple(vec![IrType::Int, IrType::Int]));
        let out = reconcile(&["q".to_owned()], &[left, right, both], interner.len())?;
        let [class] = out.as_slice() else {
            return Err(bug(format!("expected one class, got {out:?}")));
        };
        assert_eq!(class.type_params.len(), 2);
        assert_eq!(class.members.len(), 3);
        let fresh = class
            .type_params
            .iter()
            .map(|s| IrType::Generic(*s))
            .collect::<Vec<_>>();
        assert_eq!(class.template, q(IrType::Tuple(fresh)));
        Ok(())
    }

    /// Distinct concrete shapes never unify, so each keeps its own struct.
    #[test]
    fn distinct_concrete_shapes_keep_their_own_structs() -> DResult<()> {
        let out = reconcile(&["q".to_owned()], &[q(IrType::Int), q(IrType::Str)], 0)?;
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|c| c.type_params.is_empty()));
        Ok(())
    }

    /// The occurs check refuses `{x:a, y:List a}` against `{x:List b, y:b}`.
    #[test]
    fn occurs_check_refuses_an_infinite_unifier() -> DResult<()> {
        let mut interner = Interner::new();
        let a = interner.intern("a")?;
        let b = interner.intern("b")?;
        let left = vec![
            ("x".to_owned(), IrType::Generic(a)),
            ("y".to_owned(), IrType::List(Box::new(IrType::Generic(a)))),
        ];
        let right = vec![
            ("x".to_owned(), IrType::List(Box::new(IrType::Generic(b)))),
            ("y".to_owned(), IrType::Generic(b)),
        ];
        assert!(!fields_unify(&left, &right)?);
        Ok(())
    }

    /// Variables on the two sides are renamed apart: `{x:a, y:Int}` unifies
    /// with `{x:Str, y:a}` although both spell `a`.
    #[test]
    fn sides_are_renamed_apart() -> DResult<()> {
        let mut interner = Interner::new();
        let a = interner.intern("a")?;
        let left = vec![
            ("x".to_owned(), IrType::Generic(a)),
            ("y".to_owned(), IrType::Int),
        ];
        let right = vec![
            ("x".to_owned(), IrType::Str),
            ("y".to_owned(), IrType::Generic(a)),
        ];
        assert!(fields_unify(&left, &right)?);
        Ok(())
    }

    /// A row variable fails closed in both the unifier and the generalization.
    #[test]
    fn row_generic_fails_closed() -> DResult<()> {
        let mut interner = Interner::new();
        let r = interner.intern("r")?;
        let row = q(IrType::RowGeneric(r));
        assert!(fields_unify(&row, &q(IrType::Int)).is_err());
        assert!(reconcile(&["q".to_owned()], &[row], interner.len()).is_err());
        Ok(())
    }

    /// A template needing more variables than the interner holds fails closed.
    #[test]
    fn variable_pool_exhaustion_fails_closed() {
        let left = q(IrType::Tuple(vec![IrType::Int, IrType::Str]));
        let right = q(IrType::Tuple(vec![IrType::Str, IrType::Int]));
        let mut interner = Interner::new();
        let Ok(a) = interner.intern("a") else {
            return;
        };
        let generic = q(IrType::Generic(a));
        assert!(reconcile(&["q".to_owned()], &[generic, left, right], 0).is_ok());
        let crossed = q(IrType::Tuple(vec![IrType::Generic(a), IrType::Int]));
        let other = q(IrType::Tuple(vec![IrType::Int, IrType::Generic(a)]));
        assert!(reconcile(&["q".to_owned()], &[crossed, other], 1).is_err());
    }
}
