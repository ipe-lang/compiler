//! Declaration-graph checks on the user types every module declares.
//!
//! Two facts come from the graph of custom type declarations, each walked
//! iteratively over its strongly connected components:
//!
//! * [`expansive_cycle`] — a type that reaches itself with a parameter wrapped
//!   in a larger type (`type Nested a = Leaf a | Nest (Nested (List a))`) has
//!   no finite set of instances, so the Rust build overflows building them.
//!   The rule is the expansive-cycle check of ECMA-335 II.9.2: a node is a
//!   `(type, parameter)` pair, an edge runs from each parameter to the
//!   argument position it is passed in, and an edge is *expanding* when the
//!   argument strictly contains the parameter. A cycle through an expanding
//!   edge is refused.
//! * [`NominalLevels`] — the type levels each declared type renders to. A
//!   nullary type is a leaf in the solved graph, yet it costs rustc the levels
//!   of every payload it holds, so a chain of declarations nests like a chain
//!   of applications. A recursive group of declarations is boxed, yet the Rust
//!   build walks through every distinct instantiation of the group's members
//!   before it meets the cycle, so the group costs each instantiation's level
//!   and payload, summed. A group that passes its parameters on permuted
//!   (`type P a b = E a b | S (P b a)`) instantiates a member once per
//!   arrangement its references reach, and each is charged.
//!
//! [`check_declarations`] runs both before inference, and also measures every
//! top-level annotation, so a declared type past [`TYPE_DEPTH_LIMIT`] is
//! refused where it is written even when nothing uses it.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use ipe_canon::ast as canon;
use ipe_diagnostics::nesting::{TYPE_DEPTH_LIMIT, TYPE_LEVELS_PER_ARROW, TYPE_SIZE_LIMIT};
use ipe_diagnostics::{DResult, Diagnostic, Span, TypeError, TypeSizeOrigin};
use ipe_intern::{Interner, Symbol};

use crate::{Budget, InferError};

/// The stage named by an internal invariant failure of these walks.
const STAGE: &str = "ipe_types::expansive";

/// The type levels each declared custom type renders to, keyed by home and name.
///
/// A type the table does not hold (a builtin, or a type no declaration in scope
/// defines) is level 0.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NominalLevels {
    by_home: BTreeMap<Vec<Symbol>, BTreeMap<Symbol, u16>>,
}

impl NominalLevels {
    /// The table that holds no custom type.
    pub const EMPTY: Self = Self {
        by_home: BTreeMap::new(),
    };

    /// The level of the custom type `name` declared in `home`.
    #[must_use]
    pub fn level(&self, home: &[Symbol], name: Symbol) -> u16 {
        self.by_home
            .get(home)
            .and_then(|names| names.get(&name))
            .copied()
            .unwrap_or(0)
    }

    /// Record `level` for the custom type `name` declared in `home`.
    fn insert(&mut self, home: &[Symbol], name: Symbol, level: u16) {
        self.by_home
            .entry(home.to_vec())
            .or_default()
            .insert(name, level);
    }
}

/// The declarations one module is checked against: its own first, then every
/// dependency union in scope.
struct Table<'u> {
    unions: Vec<&'u canon::Union>,
    index: BTreeMap<(&'u [Symbol], Symbol), usize>,
    /// The first `own` entries of `unions` are the module's own declarations.
    own: usize,
}

impl<'u> Table<'u> {
    fn new(module_unions: &'u [canon::Union], dep_unions: &[&'u canon::Union]) -> Self {
        let unions: Vec<&'u canon::Union> = module_unions
            .iter()
            .chain(dep_unions.iter().copied())
            .collect();
        let mut index = BTreeMap::new();
        for (i, u) in unions.iter().enumerate() {
            index.entry((u.home.as_slice(), u.name)).or_insert(i);
        }
        Self {
            unions,
            index,
            own: module_unions.len(),
        }
    }

    /// The table index of the custom type `name` declared in `home`.
    fn find(&self, home: &[Symbol], name: Symbol) -> Option<usize> {
        self.index.get(&(home, name)).copied()
    }

    fn union(&self, i: usize) -> DResult<&'u canon::Union> {
        self.unions.get(i).copied().ok_or_else(walk_bug)
    }
}

/// An index one of these walks built itself was out of range.
fn walk_bug() -> Diagnostic {
    Diagnostic::CompilerBug {
        where_: STAGE,
        detail: "a declaration-graph index is out of range".to_owned(),
    }
}

/// Push the type nodes `t` holds directly.
fn push_children<'t>(t: &'t canon::Type, out: &mut Vec<&'t canon::Type>) {
    match t {
        canon::Type::Lambda(a, b) => {
            out.push(a);
            out.push(b);
        }
        canon::Type::Var(_) | canon::Type::Wildcard | canon::Type::Unit => {}
        canon::Type::Con { args, .. } => out.extend(args.iter()),
        canon::Type::Tuple(elems) => out.extend(elems.iter()),
        canon::Type::Record(fields) | canon::Type::RecordOpen(_, fields) => {
            out.extend(fields.iter().map(|(_, f)| f));
        }
    }
}

/// Every type node of `t`, `t` itself first, ticking `budget` once per node.
fn nodes<'t>(t: &'t canon::Type, budget: &mut Budget) -> DResult<Vec<&'t canon::Type>> {
    let mut seen = Vec::new();
    let mut work = vec![t];
    while let Some(node) = work.pop() {
        budget.tick()?;
        seen.push(node);
        push_children(node, &mut work);
    }
    Ok(seen)
}

/// The strongly connected components of a graph.
#[derive(Debug, PartialEq, Eq)]
pub struct Components {
    /// The component of each node.
    pub of: Vec<usize>,
    /// The members of each component, every component listed after all the
    /// components it reaches.
    pub members: Vec<Vec<usize>>,
}

/// One node's state in [`components`].
#[derive(Clone, Copy, Default)]
struct TarjanNode {
    index: Option<usize>,
    low: usize,
    on_stack: bool,
    component: Option<usize>,
}

fn tarjan_node(nodes: &[TarjanNode], v: usize) -> DResult<TarjanNode> {
    nodes.get(v).copied().ok_or_else(walk_bug)
}

fn tarjan_node_mut(nodes: &mut [TarjanNode], v: usize) -> DResult<&mut TarjanNode> {
    nodes.get_mut(v).ok_or_else(walk_bug)
}

/// The strongly connected components of the graph `succ` lists the successors of.
///
/// Tarjan's algorithm over an explicit stack of frames, so the walk never
/// recurses; it ticks `budget` once per node and once per edge.
///
/// # Errors
/// [`TypeError::StepBudgetExceeded`] if the budget runs out;
/// [`Diagnostic::CompilerBug`] on a successor outside the graph.
pub fn components(succ: &[Vec<usize>], budget: &mut Budget) -> DResult<Components> {
    let mut nodes = vec![TarjanNode::default(); succ.len()];
    let mut stack: Vec<usize> = Vec::new();
    let mut members: Vec<Vec<usize>> = Vec::new();
    let mut counter = 0usize;
    let enter = |nodes: &mut [TarjanNode], stack: &mut Vec<usize>, counter: &mut usize, v| {
        let node = tarjan_node_mut(nodes, v)?;
        node.index = Some(*counter);
        node.low = *counter;
        node.on_stack = true;
        *counter = counter.saturating_add(1);
        stack.push(v);
        Ok::<(), Diagnostic>(())
    };
    for root in 0..succ.len() {
        if tarjan_node(&nodes, root)?.index.is_some() {
            continue;
        }
        budget.tick()?;
        enter(&mut nodes, &mut stack, &mut counter, root)?;
        let mut frames: Vec<(usize, usize)> = vec![(root, 0)];
        while let Some(frame) = frames.last_mut() {
            let v = frame.0;
            let next = succ.get(v).ok_or_else(walk_bug)?.get(frame.1).copied();
            if let Some(w) = next {
                frame.1 = frame.1.saturating_add(1);
                budget.tick()?;
                let w_node = tarjan_node(&nodes, w)?;
                match w_node.index {
                    None => {
                        enter(&mut nodes, &mut stack, &mut counter, w)?;
                        frames.push((w, 0));
                    }
                    Some(w_index) if w_node.on_stack => {
                        let v_node = tarjan_node_mut(&mut nodes, v)?;
                        v_node.low = v_node.low.min(w_index);
                    }
                    Some(_) => {}
                }
                continue;
            }
            frames.pop();
            let v_node = tarjan_node(&nodes, v)?;
            if let Some(&(parent, _)) = frames.last() {
                let parent_node = tarjan_node_mut(&mut nodes, parent)?;
                parent_node.low = parent_node.low.min(v_node.low);
            }
            if v_node.index == Some(v_node.low) {
                let id = members.len();
                let mut component = Vec::new();
                loop {
                    let w = stack.pop().ok_or_else(walk_bug)?;
                    let w_node = tarjan_node_mut(&mut nodes, w)?;
                    w_node.on_stack = false;
                    w_node.component = Some(id);
                    component.push(w);
                    if w == v {
                        break;
                    }
                }
                members.push(component);
            }
        }
    }
    let of = nodes
        .iter()
        .map(|n| n.component.ok_or_else(walk_bug))
        .collect::<DResult<Vec<usize>>>()?;
    Ok(Components { of, members })
}

/// One `(type, parameter)` edge of the expansion graph.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ExpansionEdge {
    from: usize,
    to: usize,
    expanding: bool,
}

/// A custom type that reaches itself with a parameter wrapped in a larger type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Expansive<'u> {
    /// The refused declaration.
    pub union: &'u canon::Union,
    /// The parameter that grows around the cycle.
    pub param: Symbol,
}

/// The first of the module's own declarations on an expanding cycle, if any.
///
/// Only the module's own declarations contribute edges: a dependency cannot
/// name this module's types, so every cycle through one of them lies among
/// them, and a dependency's own cycles were refused in its own module.
///
/// # Errors
/// [`TypeError::StepBudgetExceeded`] if the budget runs out;
/// [`Diagnostic::CompilerBug`] on an internal index failure.
pub fn expansive_cycle<'u>(
    module_unions: &'u [canon::Union],
    dep_unions: &[&'u canon::Union],
    budget: &mut Budget,
) -> DResult<Option<Expansive<'u>>> {
    let table = Table::new(module_unions, dep_unions);
    // Node `base[u] + i` is parameter `i` of union `u`; `owners` maps it back.
    let mut base = Vec::with_capacity(table.unions.len());
    let mut owners: Vec<(usize, usize)> = Vec::new();
    for (u, union) in table.unions.iter().enumerate() {
        base.push(owners.len());
        owners.extend((0..union.vars.len()).map(|i| (u, i)));
    }
    let node_of = |u: usize, param: usize| -> DResult<usize> {
        base.get(u)
            .map(|b| b.saturating_add(param))
            .ok_or_else(walk_bug)
    };
    let mut edges: Vec<ExpansionEdge> = Vec::new();
    for (u, union) in table.unions.iter().enumerate().take(table.own) {
        let params = |p: Symbol| union.vars.iter().position(|v| *v == p);
        for field in union.ctors.iter().flat_map(|c| c.args.iter()) {
            for node in nodes(field, budget)? {
                let canon::Type::Con { home, name, args } = node else {
                    continue;
                };
                let Some(target) = table.find(home, *name) else {
                    continue;
                };
                // An argument past the target's parameters is passed to no
                // parameter, so it adds no edge.
                let arity = table.union(target)?.vars.len();
                for (j, arg) in args.iter().enumerate().take(arity) {
                    let to = node_of(target, j)?;
                    if let canon::Type::Var(p) = arg {
                        if let Some(i) = params(*p) {
                            edges.push(ExpansionEdge {
                                from: node_of(u, i)?,
                                to,
                                expanding: false,
                            });
                        }
                        continue;
                    }
                    for inner in nodes(arg, budget)? {
                        if let canon::Type::Var(p) = inner
                            && let Some(i) = params(*p)
                        {
                            edges.push(ExpansionEdge {
                                from: node_of(u, i)?,
                                to,
                                expanding: true,
                            });
                        }
                    }
                }
            }
        }
    }
    let mut succ: Vec<Vec<usize>> = vec![Vec::new(); owners.len()];
    for edge in &edges {
        succ.get_mut(edge.from).ok_or_else(walk_bug)?.push(edge.to);
    }
    let components = components(&succ, budget)?;
    let component = |v: usize| components.of.get(v).copied().ok_or_else(walk_bug);
    for edge in &edges {
        if edge.expanding && component(edge.from)? == component(edge.to)? {
            let (u, i) = owners.get(edge.from).copied().ok_or_else(walk_bug)?;
            let union = table.union(u)?;
            let param = union.vars.get(i).copied().ok_or_else(walk_bug)?;
            return Ok(Some(Expansive { union, param }));
        }
    }
    Ok(None)
}

/// How a custom type named inside a type is charged.
#[derive(Clone, Copy)]
enum Named {
    /// A member of the recursive group being measured: boxed, no level of its own.
    InGroup,
    /// Any other type, at its declared level.
    Level(u16),
}

/// The type levels `t` renders to, each custom type charged as `named` says.
///
/// An arrow costs [`TYPE_LEVELS_PER_ARROW`]; a tuple and a non-empty record
/// one level; a type application at least one level and at least the named
/// type's own level. Iterative: one explicit stack, one budget tick per node.
fn declared_depth(
    t: &canon::Type,
    budget: &mut Budget,
    named: &dyn Fn(&[Symbol], Symbol) -> Named,
) -> DResult<u16> {
    let mut work: Vec<(&canon::Type, bool)> = vec![(t, false)];
    let mut done: Vec<u16> = Vec::new();
    let mut children = Vec::new();
    while let Some((node, expanded)) = work.pop() {
        children.clear();
        push_children(node, &mut children);
        if expanded {
            let at = done
                .len()
                .checked_sub(children.len())
                .ok_or_else(walk_bug)?;
            let deepest = done.drain(at..).max().unwrap_or(0);
            done.push(own_levels(node, named).saturating_add(deepest));
        } else {
            budget.tick()?;
            work.push((node, true));
            work.extend(children.iter().map(|c| (*c, false)));
        }
    }
    done.pop().ok_or_else(walk_bug)
}

/// The levels the type former at the top of `t` adds over its children.
fn own_levels(t: &canon::Type, named: &dyn Fn(&[Symbol], Symbol) -> Named) -> u16 {
    match t {
        canon::Type::Var(_) | canon::Type::Wildcard | canon::Type::Unit => 0,
        canon::Type::Lambda(..) => TYPE_LEVELS_PER_ARROW,
        canon::Type::Tuple(_) | canon::Type::RecordOpen(..) => 1,
        canon::Type::Record(fields) => u16::from(!fields.is_empty()),
        canon::Type::Con { home, name, args } => match named(home, *name) {
            Named::InGroup => u16::from(!args.is_empty()),
            Named::Level(level) => level.max(u16::from(!args.is_empty())),
        },
    }
}

/// The deepest payload field of `ctor`, each named type charged as `named` says.
fn deepest_field(
    ctor: &canon::Ctor,
    budget: &mut Budget,
    named: &dyn Fn(&[Symbol], Symbol) -> Named,
) -> DResult<u16> {
    let mut deepest = 0u16;
    for field in &ctor.args {
        deepest = deepest.max(declared_depth(field, budget, named)?);
    }
    Ok(deepest)
}

/// A module's own declaration whose level passes [`TYPE_DEPTH_LIMIT`].
#[derive(Clone, Copy, Debug)]
struct DeclaredTooDeep<'u> {
    union: &'u canon::Union,
    /// The constructor whose payload crosses the ceiling, else the declaration.
    span: Span,
    depth: u16,
}

/// A declaration [`nominal_levels`] refuses.
#[derive(Clone, Copy, Debug)]
enum Refused<'u> {
    /// A module's own declaration past [`TYPE_DEPTH_LIMIT`].
    TooDeep(DeclaredTooDeep<'u>),
    /// The declaration and constructor that instantiate a member of a group
    /// with arguments past [`TYPE_SIZE_LIMIT`] nodes.
    TooLarge(&'u canon::Union, Span),
}

#[cfg(test)]
impl<'u> Refused<'u> {
    /// The depth refusal, if this is one.
    const fn too_deep(self) -> Option<DeclaredTooDeep<'u>> {
        match self {
            Self::TooDeep(found) => Some(found),
            Self::TooLarge(..) => None,
        }
    }
}

/// A type together with the number of nodes it holds.
#[derive(Debug, PartialEq, Eq)]
struct Counted {
    ty: canon::Type,
    size: u64,
}

impl Counted {
    /// A type variable, one node.
    const fn var(v: Symbol) -> Self {
        Self {
            ty: canon::Type::Var(v),
            size: 1,
        }
    }
}

/// `t` with each of `vars` replaced by the value at its position in `actuals`,
/// or `None` when the result would hold more than `room` nodes.
///
/// The result's size is counted, one budget tick per node of `t`, and charged
/// to `budget` in full before any value is copied. A variable with no value
/// (an application given too few arguments) is left as written. Iterative:
/// one explicit stack.
fn substitute(
    t: &canon::Type,
    vars: &[Symbol],
    actuals: &[Counted],
    room: u64,
    budget: &mut Budget,
) -> DResult<Option<Counted>> {
    let value = |v: &Symbol| {
        vars.iter()
            .position(|p| p == v)
            .and_then(|i| actuals.get(i))
    };
    let mut size = 0u64;
    let mut work = vec![t];
    while let Some(node) = work.pop() {
        budget.tick()?;
        let own = match node {
            canon::Type::Var(v) => value(v).map_or(1, |val| val.size),
            canon::Type::Wildcard
            | canon::Type::Unit
            | canon::Type::Lambda(..)
            | canon::Type::Con { .. }
            | canon::Type::Tuple(_)
            | canon::Type::Record(_)
            | canon::Type::RecordOpen(..) => 1,
        };
        size = size.saturating_add(own);
        if size > room {
            return Ok(None);
        }
        push_children(node, &mut work);
    }
    budget.charge(size)?;
    let mut work: Vec<(&canon::Type, bool)> = vec![(t, false)];
    let mut done: Vec<canon::Type> = Vec::new();
    let mut children = Vec::new();
    while let Some((node, expanded)) = work.pop() {
        children.clear();
        push_children(node, &mut children);
        if !expanded {
            work.push((node, true));
            work.extend(children.iter().rev().map(|c| (*c, false)));
            continue;
        }
        let at = done
            .len()
            .checked_sub(children.len())
            .ok_or_else(walk_bug)?;
        let mut kids = done.split_off(at).into_iter();
        let mut next = || kids.next().ok_or_else(walk_bug);
        let rebuilt = match node {
            canon::Type::Var(v) => value(v).map_or(canon::Type::Var(*v), |val| val.ty.clone()),
            canon::Type::Wildcard => canon::Type::Wildcard,
            canon::Type::Unit => canon::Type::Unit,
            canon::Type::Lambda(..) => {
                let from = next()?;
                canon::Type::Lambda(Box::new(from), Box::new(next()?))
            }
            canon::Type::Con { home, name, args } => canon::Type::Con {
                home: home.clone(),
                name: *name,
                args: args.iter().map(|_| next()).collect::<DResult<_>>()?,
            },
            canon::Type::Tuple(elems) => {
                canon::Type::Tuple(elems.iter().map(|_| next()).collect::<DResult<_>>()?)
            }
            canon::Type::Record(fields) => canon::Type::Record(
                fields
                    .iter()
                    .map(|(f, _)| Ok((*f, next()?)))
                    .collect::<DResult<_>>()?,
            ),
            canon::Type::RecordOpen(row, fields) => canon::Type::RecordOpen(
                *row,
                fields
                    .iter()
                    .map(|(f, _)| Ok((*f, next()?)))
                    .collect::<DResult<_>>()?,
            ),
        };
        done.push(rebuilt);
    }
    let ty = done.pop().ok_or_else(walk_bug)?;
    Ok(Some(Counted { ty, size }))
}

/// One instantiation of a member of a recursive group.
struct Instance<'u> {
    member: usize,
    /// The member's arguments, written over the parameters of the member the
    /// walk started from.
    args: Vec<Counted>,
    /// The nodes the arguments hold together.
    size: u64,
    /// The declaration and constructor whose payload applied the member.
    applied_by: Option<(&'u canon::Union, Span)>,
}

/// The constructor that applied a member of a group a second time, with other
/// arguments.
type Reapplied<'u> = Option<(&'u canon::Union, Span)>;

/// What walking a recursive group's instantiations found.
enum Orbit<'u> {
    /// The group's level, and the constructor that reapplied a member.
    Level(u16, Reapplied<'u>),
    /// An instantiation whose arguments hold more than [`TYPE_SIZE_LIMIT`]
    /// nodes, at the declaration and constructor that built it.
    TooLarge(&'u canon::Union, Span),
}

/// The level of the recursive group `costs` holds, walked from `root`, and the
/// constructor that first applied a member a second time with other arguments.
///
/// rustc builds every distinct instantiation of the group that `root` reaches,
/// each holding its member's payload over its own arguments, before it meets
/// the cycle. A group that passes its parameters on in another order (`type P a
/// b = E a b | S (P b a)`) instantiates one member several times, so the level
/// is the sum, over the distinct instantiations, of the member's cost plus its
/// deepest argument. The walk stops as soon as the sum passes
/// [`TYPE_DEPTH_LIMIT`]: every member of a recursive group costs at least one
/// level, so at most `TYPE_DEPTH_LIMIT + 1` instantiations are built however
/// many the group has. An instantiation whose arguments would hold more than
/// [`TYPE_SIZE_LIMIT`] nodes is refused before it is built, and every node
/// built or compared is charged to `budget`.
fn orbit_level<'u>(
    table: &Table<'u>,
    costs: &BTreeMap<usize, u16>,
    root: usize,
    budget: &mut Budget,
    named: &dyn Fn(&[Symbol], Symbol) -> Named,
) -> DResult<Orbit<'u>> {
    let start = table.union(root)?;
    let size = u64::try_from(start.vars.len()).unwrap_or(u64::MAX);
    if size > TYPE_SIZE_LIMIT {
        return Ok(Orbit::TooLarge(start, start.name_span));
    }
    budget.charge(size)?;
    let mut pending = VecDeque::from([Instance {
        member: root,
        args: start.vars.iter().copied().map(Counted::var).collect(),
        size,
        applied_by: None,
    }]);
    let mut built: Vec<Instance<'u>> = Vec::new();
    let mut level = 0u16;
    let mut reapplied = None;
    while let Some(instance) = pending.pop_front() {
        let mut member_seen = false;
        let mut instance_seen = false;
        for other in &built {
            budget.tick()?;
            if other.member == instance.member {
                member_seen = true;
                budget.charge(other.size.min(instance.size))?;
                if other.args == instance.args {
                    instance_seen = true;
                    break;
                }
            }
        }
        if instance_seen {
            continue;
        }
        if member_seen && reapplied.is_none() {
            reapplied = instance.applied_by;
        }
        let cost = costs.get(&instance.member).copied().ok_or_else(walk_bug)?;
        let mut widest = 0u16;
        for arg in &instance.args {
            widest = widest.max(declared_depth(&arg.ty, budget, named)?);
        }
        level = level.saturating_add(cost.saturating_add(widest));
        if level > TYPE_DEPTH_LIMIT {
            break;
        }
        let union = table.union(instance.member)?;
        for ctor in &union.ctors {
            for field in &ctor.args {
                for node in nodes(field, budget)? {
                    if let canon::Type::Con { home, name, args } = node
                        && let Some(target) = table.find(home, *name)
                        && costs.contains_key(&target)
                    {
                        let mut applied = Vec::with_capacity(args.len());
                        let mut size = 0u64;
                        for arg in args {
                            let headroom = TYPE_SIZE_LIMIT.saturating_sub(size);
                            let Some(value) =
                                substitute(arg, &union.vars, &instance.args, headroom, budget)?
                            else {
                                return Ok(Orbit::TooLarge(union, ctor.span));
                            };
                            size = size.saturating_add(value.size);
                            applied.push(value);
                        }
                        pending.push_back(Instance {
                            member: target,
                            args: applied,
                            size,
                            applied_by: Some((union, ctor.span)),
                        });
                    }
                }
            }
        }
        built.push(instance);
    }
    Ok(Orbit::Level(level, reapplied))
}

/// The levels of every declaration in the table, plus the shallowest of the
/// module's own declarations past [`TYPE_DEPTH_LIMIT`].
///
/// A member's cost is one level plus its deepest payload, where a member of its
/// own group is charged only as an application (the recursion is boxed) and any
/// other type its own level; a member with no payload costs nothing. A group's
/// level is the deepest [`orbit_level`] from any of its members: rustc walks a
/// path through every distinct instantiation of the group, and each one's
/// payload, before it meets the cycle, so the deepest member alone does not
/// bound it.
fn nominal_levels<'u>(
    table: &Table<'u>,
    budget: &mut Budget,
) -> DResult<(NominalLevels, Option<Refused<'u>>)> {
    let mut succ: Vec<Vec<usize>> = Vec::with_capacity(table.unions.len());
    for union in &table.unions {
        let mut targets = BTreeSet::new();
        for field in union.ctors.iter().flat_map(|c| c.args.iter()) {
            for node in nodes(field, budget)? {
                if let canon::Type::Con { home, name, .. } = node
                    && let Some(target) = table.find(home, *name)
                {
                    targets.insert(target);
                }
            }
        }
        succ.push(targets.into_iter().collect());
    }
    let components = components(&succ, budget)?;
    let mut by_index: Vec<u16> = vec![0; table.unions.len()];
    let mut levels = NominalLevels::default();
    let mut refused: Option<DeclaredTooDeep<'u>> = None;
    for (id, group) in components.members.iter().enumerate() {
        let named = |home: &[Symbol], name: Symbol| match table.find(home, name) {
            Some(i) if components.of.get(i) == Some(&id) => Named::InGroup,
            Some(i) => Named::Level(by_index.get(i).copied().unwrap_or(0)),
            None => Named::Level(0),
        };
        let mut costs = BTreeMap::new();
        let mut fields_by_member = Vec::with_capacity(group.len());
        for &u in group {
            let union = table.union(u)?;
            let mut per_ctor = Vec::with_capacity(union.ctors.len());
            let mut payload = None::<u16>;
            for ctor in &union.ctors {
                let deepest = deepest_field(ctor, budget, &named)?;
                if !ctor.args.is_empty() {
                    payload = Some(payload.unwrap_or(0).max(deepest));
                }
                per_ctor.push(deepest);
            }
            let cost = payload.map_or(0, |deepest| deepest.saturating_add(1));
            costs.insert(u, cost);
            fields_by_member.push((u, union, per_ctor, cost));
        }
        let mut level = 0u16;
        let mut reapplied = None;
        for &root in group {
            let (from_root, again) = match orbit_level(table, &costs, root, budget, &named)? {
                Orbit::Level(from_root, again) => (from_root, again),
                Orbit::TooLarge(by, span) => {
                    return Ok((levels, Some(Refused::TooLarge(by, span))));
                }
            };
            if from_root > level {
                level = from_root;
                reapplied = again;
            }
        }
        for (u, union, per_ctor, cost) in fields_by_member {
            *by_index.get_mut(u).ok_or_else(walk_bug)? = level;
            levels.insert(&union.home, union.name, level);
            if u < table.own
                && level > TYPE_DEPTH_LIMIT
                && refused.is_none_or(|best| level < best.depth)
            {
                // The constructor whose payload, over what the rest of the
                // group costs, crosses the ceiling, else the declaration, when
                // the depth comes from the other members.
                let crossing = || {
                    let rest = level.saturating_sub(cost);
                    let span = union
                        .ctors
                        .iter()
                        .zip(&per_ctor)
                        .find(|(ctor, deepest)| {
                            !ctor.args.is_empty()
                                && rest.saturating_add(1).saturating_add(**deepest)
                                    > TYPE_DEPTH_LIMIT
                        })
                        .map_or(union.name_span, |(ctor, _)| ctor.span);
                    DeclaredTooDeep {
                        union,
                        span,
                        depth: level,
                    }
                };
                // Else the constructor that instantiated a member again, with
                // its parameters passed on in another shape.
                refused = Some(
                    reapplied.map_or_else(crossing, |(by, span)| DeclaredTooDeep {
                        union: by,
                        span,
                        depth: level,
                    }),
                );
            }
        }
    }
    Ok((levels, refused.map(Refused::TooDeep)))
}

/// Check the module's declarations and top-level annotations, and return the
/// level of every declared type in scope.
///
/// Refuses, before any inference: a custom type on an expanding cycle
/// ([`TypeError::ExpansiveRecursion`], at its declaration); a custom type whose
/// level passes [`TYPE_DEPTH_LIMIT`] ([`TypeError::TypeTooDeep`], at the
/// constructor whose payload crosses it); and a top-level annotation deeper
/// than the ceiling ([`TypeError::TypeTooDeep`], at the annotated name); and a
/// recursive group that instantiates a member with arguments past
/// [`TYPE_SIZE_LIMIT`] nodes ([`TypeError::TypeTooLarge`], at the constructor
/// that applies it). Every
/// declaration and annotation is measured, used or not.
///
/// # Errors
/// [`InferError::Sited`] carrying one of the refusals above;
/// [`InferError::Program`] on step-budget exhaustion or an internal failure.
pub fn check_declarations(
    interner: &Interner,
    budget: &mut Budget,
    module: &canon::Module,
    dep_unions: &[&canon::Union],
) -> Result<NominalLevels, InferError> {
    if let Some(found) =
        expansive_cycle(&module.unions, dep_unions, budget).map_err(InferError::unsited)?
    {
        let resolve = |s: Symbol| {
            interner
                .resolve(s)
                .map(Box::<str>::from)
                .ok_or_else(|| InferError::unsited(unresolved(s)))
        };
        let diag = Diagnostic::Type {
            span: found.union.name_span,
            msg: TypeError::ExpansiveRecursion {
                union: resolve(found.union.name)?,
                param: resolve(found.param)?,
            },
        };
        return Err(InferError::sited_at_path(diag, &found.union.home));
    }
    let table = Table::new(&module.unions, dep_unions);
    let (levels, refused) = nominal_levels(&table, budget).map_err(InferError::unsited)?;
    match refused {
        None => {}
        Some(Refused::TooDeep(found)) => {
            return Err(InferError::sited_at_path(
                too_deep(found.span, found.depth),
                &found.union.home,
            ));
        }
        Some(Refused::TooLarge(union, span)) => {
            return Err(InferError::sited_at_path(too_large(span), &union.home));
        }
    }
    let named = |home: &[Symbol], name: Symbol| Named::Level(levels.level(home, name));
    for def in &module.defs {
        if let canon::Def::Typed { home, name, ty, .. } = def {
            let depth = declared_depth(ty, budget, &named).map_err(InferError::unsited)?;
            if depth > TYPE_DEPTH_LIMIT {
                return Err(InferError::sited_at_path(too_deep(name.span, depth), home));
            }
        }
    }
    Ok(levels)
}

/// [`TypeError::TypeTooDeep`] for a declared type `depth` levels deep at `span`.
const fn too_deep(span: Span, depth: u16) -> Diagnostic {
    Diagnostic::Type {
        span,
        msg: TypeError::TypeTooDeep {
            depth,
            limit: TYPE_DEPTH_LIMIT,
        },
    }
}

/// [`TypeError::TypeTooLarge`] for a declared type built past [`TYPE_SIZE_LIMIT`] at `span`.
const fn too_large(span: Span) -> Diagnostic {
    Diagnostic::Type {
        span,
        msg: TypeError::TypeTooLarge {
            limit: TYPE_SIZE_LIMIT,
            origin: TypeSizeOrigin::Declaration,
        },
    }
}

/// A declaration's symbol has no spelling in the interner.
fn unresolved(s: Symbol) -> Diagnostic {
    Diagnostic::CompilerBug {
        where_: STAGE,
        detail: format!("declaration symbol {} has no spelling", s.as_raw()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SolverSteps;

    fn budget() -> Budget {
        Budget::unbounded()
    }

    fn con(home: &[Symbol], name: Symbol, args: Vec<canon::Type>) -> canon::Type {
        canon::Type::Con {
            home: home.to_vec(),
            name,
            args,
        }
    }

    fn union(
        home: &[Symbol],
        name: Symbol,
        vars: Vec<Symbol>,
        ctors: Vec<(Symbol, Vec<canon::Type>)>,
    ) -> canon::Union {
        canon::Union {
            home: home.to_vec(),
            name,
            name_span: Span::DUMMY,
            vars,
            ctors: ctors
                .into_iter()
                .enumerate()
                .map(|(index, (name, args))| canon::Ctor {
                    name,
                    index,
                    arity: args.len(),
                    args,
                    span: Span::DUMMY,
                })
                .collect(),
        }
    }

    fn levels_of(unions: &[canon::Union]) -> DResult<NominalLevels> {
        let table = Table::new(unions, &[]);
        Ok(nominal_levels(&table, &mut budget())?.0)
    }

    #[test]
    fn components_list_each_group_after_the_groups_it_reaches() -> DResult<()> {
        // 0 -> 1 <-> 2 -> 3
        let succ = vec![vec![1], vec![2], vec![1, 3], vec![]];
        let found = components(&succ, &mut budget())?;
        assert_eq!(found.of.first(), Some(&2));
        assert_eq!(found.of.get(1), found.of.get(2));
        assert_eq!(found.of.get(3), Some(&0));
        assert_eq!(found.members.len(), 3);
        Ok(())
    }

    #[test]
    fn a_self_recursive_type_is_one_level_over_its_payload() -> DResult<()> {
        let mut i = Interner::new();
        let home = [i.intern("Main")?];
        let (list, nil, cons, a) = (
            i.intern("List")?,
            i.intern("Nil")?,
            i.intern("Cons")?,
            i.intern("a")?,
        );
        let unions = [union(
            &home,
            list,
            vec![a],
            vec![
                (nil, vec![]),
                (
                    cons,
                    vec![
                        canon::Type::Var(a),
                        con(&home, list, vec![canon::Type::Var(a)]),
                    ],
                ),
            ],
        )];
        // The `List a` field is one application over `a`.
        assert_eq!(levels_of(&unions)?.level(&home, list), 2);
        Ok(())
    }

    /// `n` applications of the builtin `Maybe` around `inner`.
    fn maybes(maybe: Symbol, n: usize, inner: canon::Type) -> canon::Type {
        (0..n).fold(inner, |t, _| con(&[], maybe, vec![t]))
    }

    #[test]
    fn a_reference_to_its_own_group_charges_each_instantiation() -> DResult<()> {
        let mut i = Interner::new();
        let home = [i.intern("Main")?];
        let (w, leaf, node, a, int) = (
            i.intern("W")?,
            i.intern("Leaf")?,
            i.intern("Node")?,
            i.intern("a")?,
            i.intern("Int")?,
        );
        // `Node (W (W (W Int)))`: each application of `W` is one level of the
        // field the Rust enum holds, though `W` itself is boxed, so `W a` costs
        // 4. The field instantiates `W` at `W (W Int)`, `W Int` and `Int`, each
        // 4 over its argument's depth: 4 + 6 + 5 + 4.
        let field = (0..3).fold(con(&[], int, vec![]), |t, _| con(&home, w, vec![t]));
        let unions = [union(
            &home,
            w,
            vec![a],
            vec![(leaf, vec![canon::Type::Var(a)]), (node, vec![field])],
        )];
        assert_eq!(levels_of(&unions)?.level(&home, w), 19);
        Ok(())
    }

    #[test]
    fn a_recursive_group_costs_every_member_payload() -> DResult<()> {
        let mut i = Interner::new();
        let home = [i.intern("Main")?];
        let (ta, tb, to_b, to_a, end, maybe) = (
            i.intern("A")?,
            i.intern("B")?,
            i.intern("ToB")?,
            i.intern("ToA")?,
            i.intern("End")?,
            i.intern("Maybe")?,
        );
        // Each member holds the other under `k` `Maybe`s. Neither payload
        // alone nears the ceiling, but rustc walks `A`, `k` levels, `B`, `k`
        // levels before it meets the cycle: `2 (k + 1)` deep.
        let k = usize::from(TYPE_DEPTH_LIMIT) / 2;
        let mut unions = [
            union(
                &home,
                ta,
                vec![],
                vec![
                    (end, vec![]),
                    (to_b, vec![maybes(maybe, k, con(&home, tb, vec![]))]),
                ],
            ),
            union(
                &home,
                tb,
                vec![],
                vec![(to_a, vec![maybes(maybe, k, con(&home, ta, vec![]))])],
            ),
        ];
        let mut payload_spans = Vec::new();
        for (n, u) in unions.iter_mut().enumerate() {
            let lo = u32::try_from(n).unwrap_or(u32::MAX);
            if let Some(ctor) = u.ctors.iter_mut().find(|c| !c.args.is_empty()) {
                ctor.span = Span::new(lo, lo.saturating_add(1));
                payload_spans.push(ctor.span);
            }
        }
        let deep = TYPE_DEPTH_LIMIT + 2;
        let table = Table::new(&unions, &[]);
        let (levels, refused) = nominal_levels(&table, &mut budget())?;
        assert_eq!(levels.level(&home, ta), deep);
        assert_eq!(levels.level(&home, tb), deep);
        // Refused at a member's payload constructor, over the other's cost.
        let refused = refused
            .and_then(Refused::too_deep)
            .map(|r| (r.span, r.depth));
        assert!(
            refused.is_some_and(|(span, depth)| depth == deep && payload_spans.contains(&span)),
            "{refused:?}",
        );
        Ok(())
    }

    #[test]
    fn a_mutually_recursive_pair_is_two_levels() -> DResult<()> {
        let mut i = Interner::new();
        let home = [i.intern("Main")?];
        let (t, f, tc, fc, end) = (
            i.intern("Tree")?,
            i.intern("Forest")?,
            i.intern("Node")?,
            i.intern("Trees")?,
            i.intern("End")?,
        );
        let unions = [
            union(&home, t, vec![], vec![(tc, vec![con(&home, f, vec![])])]),
            union(
                &home,
                f,
                vec![],
                vec![
                    (end, vec![]),
                    (fc, vec![con(&home, t, vec![]), con(&home, f, vec![])]),
                ],
            ),
        ];
        let levels = levels_of(&unions)?;
        assert_eq!(levels.level(&home, t), 2);
        assert_eq!(levels.level(&home, f), 2);
        Ok(())
    }

    #[test]
    fn a_declaration_chain_is_as_deep_as_it_is_long() -> DResult<()> {
        let mut i = Interner::new();
        let home = [i.intern("Main")?];
        let names = (0..4)
            .map(|k| i.intern(&format!("U{k}")))
            .collect::<DResult<Vec<Symbol>>>()?;
        let unions = names
            .iter()
            .enumerate()
            .map(|(k, name)| {
                let payload = k
                    .checked_sub(1)
                    .and_then(|prev| names.get(prev))
                    .map(|prev| vec![con(&home, *prev, vec![])])
                    .unwrap_or_default();
                union(&home, *name, vec![], vec![(*name, payload)])
            })
            .collect::<Vec<_>>();
        let levels = levels_of(&unions)?;
        for (k, name) in names.iter().enumerate() {
            assert_eq!(usize::from(levels.level(&home, *name)), k, "U{k}");
        }
        Ok(())
    }

    #[test]
    fn a_chain_one_past_the_ceiling_is_refused_at_the_crossing_constructor() -> DResult<()> {
        let mut i = Interner::new();
        let home = [i.intern("Main")?];
        let past = usize::from(TYPE_DEPTH_LIMIT) + 1;
        let names = (0..=past)
            .map(|k| i.intern(&format!("U{k}")))
            .collect::<DResult<Vec<Symbol>>>()?;
        let mut unions = Vec::new();
        for (k, name) in names.iter().enumerate() {
            let payload = k
                .checked_sub(1)
                .and_then(|prev| names.get(prev))
                .map(|prev| vec![con(&home, *prev, vec![])])
                .unwrap_or_default();
            let mut u = union(&home, *name, vec![], vec![(*name, payload)]);
            let lo = u32::try_from(k).unwrap_or(u32::MAX);
            if let Some(ctor) = u.ctors.first_mut() {
                ctor.span = Span::new(lo, lo.saturating_add(1));
            }
            unions.push(u);
        }
        let table = Table::new(&unions, &[]);
        let (_, refused) = nominal_levels(&table, &mut budget())?;
        let past_lo = u32::try_from(past).unwrap_or(u32::MAX);
        assert_eq!(
            refused
                .and_then(Refused::too_deep)
                .map(|r| (r.union.name, r.span, r.depth)),
            names.get(past).map(|n| (
                *n,
                Span::new(past_lo, past_lo.saturating_add(1)),
                TYPE_DEPTH_LIMIT + 1
            )),
        );
        Ok(())
    }

    #[test]
    fn an_expanding_cycle_is_refused_and_a_regular_one_accepted() -> DResult<()> {
        let mut i = Interner::new();
        let home = [i.intern("Main")?];
        let (nested, leaf, nest, a, list) = (
            i.intern("Nested")?,
            i.intern("Leaf")?,
            i.intern("Nest")?,
            i.intern("a")?,
            i.intern("List")?,
        );
        let leaf_ctor = (leaf, vec![canon::Type::Var(a)]);
        // `Nest (Nested (List a))`: `a` reaches itself inside a `List`.
        let expanding = [union(
            &home,
            nested,
            vec![a],
            vec![
                leaf_ctor.clone(),
                (
                    nest,
                    vec![con(
                        &home,
                        nested,
                        vec![con(&[], list, vec![canon::Type::Var(a)])],
                    )],
                ),
            ],
        )];
        let found = expansive_cycle(&expanding, &[], &mut budget())?;
        assert_eq!(found.map(|e| (e.union.name, e.param)), Some((nested, a)));
        // `Nest (List (Nested a))`: every level is `Nested a`.
        let regular = [union(
            &home,
            nested,
            vec![a],
            vec![
                leaf_ctor,
                (
                    nest,
                    vec![con(
                        &[],
                        list,
                        vec![con(&home, nested, vec![canon::Type::Var(a)])],
                    )],
                ),
            ],
        )];
        assert_eq!(expansive_cycle(&regular, &[], &mut budget())?, None);
        Ok(())
    }

    /// `name` over `vars` with a nullary `Z`, an `E` holding every parameter,
    /// and a `Rot` holding `name` applied to `applied`, `Rot` at span `2..3`.
    fn passing_on(
        home: &[Symbol],
        name: Symbol,
        ctors: [Symbol; 3],
        vars: &[Symbol],
        applied: Vec<canon::Type>,
    ) -> canon::Union {
        let [z, e, rot] = ctors;
        let mut u = union(
            home,
            name,
            vars.to_vec(),
            vec![
                (z, vec![]),
                (e, vars.iter().map(|v| canon::Type::Var(*v)).collect()),
                (rot, vec![con(home, name, applied)]),
            ],
        );
        if let Some(ctor) = u.ctors.get_mut(2) {
            ctor.span = Span::new(2, 3);
        }
        u
    }

    #[test]
    fn a_group_passing_its_parameters_on_permuted_costs_each_arrangement() -> DResult<()> {
        let mut i = Interner::new();
        let home = [i.intern("Main")?];
        let ctors = [i.intern("Z")?, i.intern("E")?, i.intern("Rot")?];
        let (p, a, b) = (i.intern("P")?, i.intern("a")?, i.intern("b")?);
        let (va, vb) = (canon::Type::Var(a), canon::Type::Var(b));
        // `Rot (P a b)` passes the parameters on as they came: one
        // instantiation, costing one level over its deepest payload, `P a b`.
        let same = [passing_on(
            &home,
            p,
            ctors,
            &[a, b],
            vec![va.clone(), vb.clone()],
        )];
        assert_eq!(levels_of(&same)?.level(&home, p), 2);
        // `Rot (P b a)` swaps them: `P a b` and `P b a` are two instantiations.
        let swapped = [passing_on(&home, p, ctors, &[a, b], vec![vb, va])];
        assert_eq!(levels_of(&swapped)?.level(&home, p), 4);
        Ok(())
    }

    #[test]
    fn a_rotation_one_past_the_ceiling_is_refused_at_the_rotating_constructor() -> DResult<()> {
        let mut i = Interner::new();
        let home = [i.intern("Main")?];
        let ctors = [i.intern("Z")?, i.intern("E")?, i.intern("Rot")?];
        let r = i.intern("R")?;
        // `Rot (R a2 … ak a1)` reaches all `k` rotations, each costing 2.
        let half = usize::from(TYPE_DEPTH_LIMIT) / 2;
        let rotation = |names: &mut Interner, k: usize| -> DResult<canon::Union> {
            let vars = (1..=k)
                .map(|n| names.intern(&format!("a{n}")))
                .collect::<DResult<Vec<Symbol>>>()?;
            let applied = vars
                .iter()
                .cycle()
                .skip(1)
                .take(k)
                .map(|v| canon::Type::Var(*v))
                .collect();
            Ok(passing_on(&home, r, ctors, &vars, applied))
        };
        let fits = [rotation(&mut i, half)?];
        let table = Table::new(&fits, &[]);
        let (levels, refused) = nominal_levels(&table, &mut budget())?;
        assert_eq!(levels.level(&home, r), TYPE_DEPTH_LIMIT);
        assert!(refused.is_none(), "{refused:?}");
        let past = [rotation(&mut i, half + 1)?];
        let table = Table::new(&past, &[]);
        let (_, refused) = nominal_levels(&table, &mut budget())?;
        assert_eq!(
            refused.and_then(Refused::too_deep).map(|found| (
                found.union.name,
                found.span,
                found.depth
            )),
            Some((r, Span::new(2, 3), TYPE_DEPTH_LIMIT + 2)),
        );
        Ok(())
    }

    #[test]
    fn an_application_past_its_parameters_adds_no_edge() -> DResult<()> {
        let mut i = Interner::new();
        let home = [i.intern("Main")?];
        let (t, x, a) = (i.intern("A")?, i.intern("X")?, i.intern("a")?);
        // `X (A a a)`: the second `a` is passed to no parameter of `A`.
        let unions = [union(
            &home,
            t,
            vec![a],
            vec![(
                x,
                vec![con(
                    &home,
                    t,
                    vec![canon::Type::Var(a), canon::Type::Var(a)],
                )],
            )],
        )];
        assert_eq!(expansive_cycle(&unions, &[], &mut budget())?, None);
        // `A a` and `A a a` are two instantiations, each costing 2.
        assert_eq!(levels_of(&unions)?.level(&home, t), 4);
        Ok(())
    }

    /// `type B p1 … pk = B p1 … pk` and `type T a b c d = Z | X (T Int (B a … a)
    /// (B b … b) (B c … c))`, `X` spanned at byte 7.
    fn widening(names: &mut Interner, k: usize) -> DResult<[canon::Union; 2]> {
        let home = [names.intern("Main")?];
        let (boxed, grower, int) = (names.intern("B")?, names.intern("T")?, names.intern("Int")?);
        let (leaf, widen) = (names.intern("Z")?, names.intern("X")?);
        let params = (1..=k)
            .map(|n| names.intern(&format!("p{n}")))
            .collect::<DResult<Vec<Symbol>>>()?;
        let vars = ["a", "b", "c", "d"]
            .iter()
            .map(|v| names.intern(v))
            .collect::<DResult<Vec<Symbol>>>()?;
        let over = |v: Symbol| con(&home, boxed, vec![canon::Type::Var(v); k]);
        let applied = std::iter::once(con(&home, int, vec![]))
            .chain(vars.iter().take(3).copied().map(over))
            .collect();
        let held = params.iter().map(|p| canon::Type::Var(*p)).collect();
        let mut grows = union(
            &home,
            grower,
            vars,
            vec![(leaf, vec![]), (widen, vec![con(&home, grower, applied)])],
        );
        if let Some(ctor) = grows.ctors.get_mut(1) {
            ctor.span = Span::new(7, 8);
        }
        Ok([union(&home, boxed, params, vec![(boxed, held)]), grows])
    }

    #[test]
    fn instantiations_widening_past_the_size_ceiling_are_refused_before_they_are_built()
    -> DResult<()> {
        let mut i = Interner::new();
        // The largest instantiation holds `4 + 3k + 2k^2 + k^3` nodes: 62 482
        // at 39, 67 324 at 40.
        let fits = widening(&mut i, 39)?;
        let table = Table::new(&fits, &[]);
        let (levels, refused) = nominal_levels(&table, &mut budget())?;
        assert!(refused.is_none(), "{refused:?}");
        let home = [i.intern("Main")?];
        assert_eq!(levels.level(&home, i.intern("T")?), 24);
        for k in [40, 1500] {
            let past = widening(&mut i, k)?;
            let table = Table::new(&past, &[]);
            // A budget far below the nodes the widest instantiation would copy.
            let steps = SolverSteps::new(1_000_000).ok_or_else(walk_bug)?;
            let (_, refused) = nominal_levels(&table, &mut Budget::new(steps))?;
            let at = match refused {
                Some(Refused::TooLarge(by, span)) => Some((by.name, span)),
                Some(Refused::TooDeep(_)) | None => None,
            };
            assert_eq!(at, Some((i.intern("T")?, Span::new(7, 8))), "{refused:?}");
        }
        Ok(())
    }

    #[test]
    fn a_charge_past_the_budget_exhausts_it() -> DResult<()> {
        let steps = SolverSteps::new(10).ok_or_else(walk_bug)?;
        let mut budget = Budget::new(steps);
        budget.charge(4)?;
        assert_eq!(budget.spent(), 4);
        assert!(budget.charge(7).is_err());
        assert_eq!(budget.spent(), 10);
        assert!(budget.tick().is_err());
        Ok(())
    }
}
