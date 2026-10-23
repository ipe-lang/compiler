//! Which type parameters of the program's enums a Rust declaration uses.
//!
//! rustc refuses a type parameter no field uses (E0392), and a use that only
//! passes the parameter back to its own enum, or to another enum that never
//! uses it, is no use: `type T a = L | N (T a)` declares `enum T<A> { L,
//! N(Box<T<A>>) }`, which rustc refuses. The parameter carries nothing at
//! runtime, so lowering erases it from the declaration and from every
//! application. The lowerer erases through [`EnumParamUse`] and the emitter
//! refuses a declaration it still finds a dead parameter in, through the same
//! table.

use std::collections::BTreeMap;

use ipe_diagnostics::{DResult, Diagnostic};
use ipe_intern::Symbol;

use crate::ir::{EnumDef, IrType, ModPath, Variant};

/// For every enum of one program, which of its type parameters a field uses.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EnumParamUse {
    live: BTreeMap<(ModPath, Symbol), Vec<bool>>,
}

/// One occurrence of a parameter in a field, and how many of the enum
/// parameters it is passed through are not yet known to be used.
struct Occurrence {
    param: usize,
    waiting: usize,
}

/// Every parameter of the program numbered once, and the occurrences waiting
/// on each.
struct Graph {
    /// Each enum's first parameter number and its parameter count.
    offsets: BTreeMap<(ModPath, Symbol), (usize, usize)>,
    occurrences: Vec<Occurrence>,
    /// For each parameter, the occurrences passed through it, once per pass.
    waiters: Vec<Vec<usize>>,
    /// Parameters known used, not yet propagated.
    ready: Vec<usize>,
}

impl Graph {
    fn new(defs: &[&EnumDef]) -> Self {
        let mut offsets = BTreeMap::new();
        let mut total = 0usize;
        for def in defs {
            offsets.insert((def.home.clone(), def.name), (total, def.type_params.len()));
            total = total.saturating_add(def.type_params.len());
        }
        Self {
            offsets,
            occurrences: Vec::new(),
            waiters: vec![Vec::new(); total],
            ready: Vec::new(),
        }
    }

    /// Record every occurrence of `def`'s parameters in its fields.
    fn record(&mut self, def: &EnumDef) {
        let base = self
            .offsets
            .get(&(def.home.clone(), def.name))
            .map_or(0, |(base, _)| *base);
        for field in def.variants.iter().flat_map(|v| v.fields.iter()) {
            let mut stack: Vec<(&IrType, Vec<usize>)> = vec![(field, Vec::new())];
            while let Some((ty, through)) = stack.pop() {
                match ty {
                    IrType::Generic(sym) => {
                        if let Some(position) = def.type_params.iter().position(|p| p == sym) {
                            self.occurs(base.saturating_add(position), &through);
                        }
                    }
                    IrType::Enum { home, name, args } => {
                        let target = self.offsets.get(&(home.clone(), *name)).copied();
                        for (position, arg) in args.iter().enumerate() {
                            let mut next = through.clone();
                            if let Some((target_base, arity)) = target
                                && position < arity
                            {
                                next.push(target_base.saturating_add(position));
                            }
                            stack.push((arg, next));
                        }
                    }
                    other => {
                        let mut kids = Vec::new();
                        push_children(other, &mut kids);
                        stack.extend(kids.into_iter().map(|k| (k, through.clone())));
                    }
                }
            }
        }
    }

    /// `param` occurs passed through the parameters `through`.
    fn occurs(&mut self, param: usize, through: &[usize]) {
        if through.is_empty() {
            self.ready.push(param);
            return;
        }
        let id = self.occurrences.len();
        for step in through {
            if let Some(waiting) = self.waiters.get_mut(*step) {
                waiting.push(id);
            }
        }
        self.occurrences.push(Occurrence {
            param,
            waiting: through.len(),
        });
    }

    /// Each enum's parameters, used or not.
    fn solve(mut self) -> BTreeMap<(ModPath, Symbol), Vec<bool>> {
        let mut live = vec![false; self.waiters.len()];
        while let Some(param) = self.ready.pop() {
            let Some(slot) = live.get_mut(param) else {
                continue;
            };
            if *slot {
                continue;
            }
            *slot = true;
            for id in self.waiters.get(param).into_iter().flatten() {
                if let Some(occ) = self.occurrences.get_mut(*id) {
                    occ.waiting = occ.waiting.saturating_sub(1);
                    if occ.waiting == 0 {
                        self.ready.push(occ.param);
                    }
                }
            }
        }
        self.offsets
            .into_iter()
            .map(|(key, (base, arity))| {
                let flags = (0..arity)
                    .map(|at| live.get(base.saturating_add(at)).copied().unwrap_or(true))
                    .collect();
                (key, flags)
            })
            .collect()
    }
}

impl EnumParamUse {
    /// The least set of used parameters over `defs`.
    ///
    /// A parameter is used when a field names it outside any enum application,
    /// or as an argument of an enum in `defs` whose parameter at that position
    /// is used. An argument of an enum outside `defs`, or past its parameters,
    /// counts as used: its declaration is not this program's to judge.
    #[must_use]
    pub fn of<'a>(defs: impl IntoIterator<Item = &'a EnumDef>) -> Self {
        let defs: Vec<&EnumDef> = defs.into_iter().collect();
        let mut graph = Graph::new(&defs);
        for def in &defs {
            graph.record(def);
        }
        Self {
            live: graph.solve(),
        }
    }

    /// Is the parameter at `position` of enum `(home, name)` used?
    ///
    /// An enum or position outside the table is: only a parameter the table
    /// proved unused is erased.
    #[must_use]
    pub fn is_used(&self, home: &ModPath, name: Symbol, position: usize) -> bool {
        self.live
            .get(&(home.clone(), name))
            .and_then(|flags| flags.get(position))
            .is_none_or(|used| *used)
    }

    /// How many type parameters enum `(home, name)` declares, when the table
    /// holds it.
    #[must_use]
    pub fn declared_arity(&self, home: &ModPath, name: Symbol) -> Option<usize> {
        self.live.get(&(home.clone(), name)).map(Vec::len)
    }

    /// `args` of an application of enum `(home, name)` without those its
    /// declaration erases.
    #[must_use]
    pub fn used_args<T>(&self, home: &ModPath, name: Symbol, args: Vec<T>) -> Vec<T> {
        args.into_iter()
            .enumerate()
            .filter(|(position, _)| self.is_used(home, name, *position))
            .map(|(_, arg)| arg)
            .collect()
    }

    /// `def` with its unused parameters erased from the declaration and from
    /// every enum application its fields hold.
    #[must_use]
    pub fn erase_in_def(&self, def: EnumDef) -> EnumDef {
        let EnumDef {
            name,
            home,
            type_params,
            variants,
        } = def;
        let type_params = self.used_args(&home, name, type_params);
        let variants = variants
            .into_iter()
            .map(|Variant { name, fields }| Variant {
                name,
                fields: fields.into_iter().map(|f| self.erase_in(f)).collect(),
            })
            .collect();
        EnumDef {
            name,
            home,
            type_params,
            variants,
        }
    }

    /// `ty` with every enum application's erased arguments dropped.
    #[must_use]
    pub fn erase_in(&self, ty: IrType) -> IrType {
        erase(self, ty)
    }

    /// A [`Diagnostic::CompilerBug`] when some enum in the table declares a
    /// parameter no field uses, which rustc would refuse.
    ///
    /// # Errors
    ///
    /// The first such enum, by nominal identity.
    pub fn refuse_unused(&self) -> DResult<()> {
        let Some((_, flags)) = self
            .live
            .iter()
            .find(|(_, flags)| flags.iter().any(|used| !used))
        else {
            return Ok(());
        };
        let unused: Vec<usize> = flags
            .iter()
            .enumerate()
            .filter(|(_, used)| !**used)
            .map(|(at, _)| at)
            .collect();
        Err(Diagnostic::CompilerBug {
            where_: "ipe_ir::EnumParamUse::refuse_unused",
            detail: format!(
                "an enum declares type parameters no field uses (positions {unused:?})"
            ),
        })
    }
}

/// The type arguments `ty` holds one level down.
#[allow(clippy::too_many_lines)] // one arm per IrType variant, deliberately exhaustive
fn push_children<'t>(ty: &'t IrType, out: &mut Vec<&'t IrType>) {
    match ty {
        IrType::Task(inner)
        | IrType::Maybe(inner)
        | IrType::List(inner)
        | IrType::Set(inner)
        | IrType::Cmd(inner)
        | IrType::Sub(inner)
        | IrType::Decoder(inner)
        | IrType::WebRoute(inner)
        | IrType::Ui { msg: inner, .. } => out.push(inner),
        IrType::Result(a, b) | IrType::Dict(a, b) | IrType::CustomElement { down: a, up: b } => {
            out.push(a);
            out.push(b);
        }
        IrType::Enum { args: elems, .. } | IrType::Tuple(elems) => out.extend(elems),
        IrType::Record(fields) => out.extend(fields.values()),
        IrType::Fun(params, ret)
        | IrType::SharedFun(params, ret)
        | IrType::FnOnceChain(params, ret) => {
            out.extend(params);
            out.push(ret);
        }
        IrType::Generic(_)
        | IrType::RowGeneric(_)
        | IrType::Int
        | IrType::Float
        | IrType::Bool
        | IrType::Str
        | IrType::Char
        | IrType::Unit
        | IrType::Bytes
        | IrType::Json
        | IrType::Db
        | IrType::BackoffStrategy
        | IrType::Order
        | IrType::HttpMethod
        | IrType::ErrorKind
        | IrType::Error
        | IrType::ErrorDetails
        | IrType::ErrorInfo
        | IrType::PanicInfo
        | IrType::TypeInfo
        | IrType::ServerRequest
        | IrType::ServerResponse
        | IrType::ServerRoute
        | IrType::ServerCookie
        | IrType::StreamWriter
        | IrType::HttpRequest
        | IrType::Regex
        | IrType::WebSocketServer
        | IrType::WebSocketServerCfg
        | IrType::UiPlain(_)
        | IrType::Decimal
        | IrType::WebReq
        | IrType::SessionHandle
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
        | IrType::WorkerApp => {}
    }
}

/// `ty` with every enum application's erased arguments dropped.
#[allow(clippy::too_many_lines)] // one arm per IrType variant, deliberately exhaustive
fn erase(uses: &EnumParamUse, ty: IrType) -> IrType {
    let one = |t: Box<IrType>| Box::new(erase(uses, *t));
    let all = |ts: Vec<IrType>| ts.into_iter().map(|t| erase(uses, t)).collect::<Vec<_>>();
    match ty {
        IrType::Enum { home, name, args } => {
            let args = all(uses.used_args(&home, name, args));
            IrType::Enum { home, name, args }
        }
        IrType::Task(t) => IrType::Task(one(t)),
        IrType::Maybe(t) => IrType::Maybe(one(t)),
        IrType::List(t) => IrType::List(one(t)),
        IrType::Set(t) => IrType::Set(one(t)),
        IrType::Cmd(t) => IrType::Cmd(one(t)),
        IrType::Sub(t) => IrType::Sub(one(t)),
        IrType::Decoder(t) => IrType::Decoder(one(t)),
        IrType::WebRoute(t) => IrType::WebRoute(one(t)),
        IrType::Ui { ctor, msg } => IrType::Ui {
            ctor,
            msg: one(msg),
        },
        IrType::Result(a, b) => IrType::Result(one(a), one(b)),
        IrType::Dict(a, b) => IrType::Dict(one(a), one(b)),
        IrType::CustomElement { down, up } => IrType::CustomElement {
            down: one(down),
            up: one(up),
        },
        IrType::Tuple(ts) => IrType::Tuple(all(ts)),
        IrType::Record(fields) => IrType::Record(
            fields
                .into_iter()
                .map(|(f, t)| (f, erase(uses, t)))
                .collect(),
        ),
        IrType::Fun(ps, r) => IrType::Fun(all(ps), one(r)),
        IrType::SharedFun(ps, r) => IrType::SharedFun(all(ps), one(r)),
        IrType::FnOnceChain(ps, r) => IrType::FnOnceChain(all(ps), one(r)),
        leaf @ (IrType::Generic(_)
        | IrType::RowGeneric(_)
        | IrType::Int
        | IrType::Float
        | IrType::Bool
        | IrType::Str
        | IrType::Char
        | IrType::Unit
        | IrType::Bytes
        | IrType::Json
        | IrType::Db
        | IrType::BackoffStrategy
        | IrType::Order
        | IrType::HttpMethod
        | IrType::ErrorKind
        | IrType::Error
        | IrType::ErrorDetails
        | IrType::ErrorInfo
        | IrType::PanicInfo
        | IrType::TypeInfo
        | IrType::ServerRequest
        | IrType::ServerResponse
        | IrType::ServerRoute
        | IrType::ServerCookie
        | IrType::StreamWriter
        | IrType::HttpRequest
        | IrType::Regex
        | IrType::WebSocketServer
        | IrType::WebSocketServerCfg
        | IrType::UiPlain(_)
        | IrType::Decimal
        | IrType::WebReq
        | IrType::SessionHandle
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
        | IrType::WorkerApp) => leaf,
    }
}

#[cfg(test)]
mod tests {
    use ipe_diagnostics::DResult;
    use ipe_intern::Interner;

    use super::*;

    /// `name` over `params`, one variant per entry of `fields`, each named by
    /// the `ctors` entry at its position.
    fn def(
        home: &ModPath,
        name: Symbol,
        params: Vec<Symbol>,
        ctors: &[Symbol],
        fields: Vec<Vec<IrType>>,
    ) -> EnumDef {
        EnumDef {
            name,
            home: home.clone(),
            type_params: params,
            variants: ctors
                .iter()
                .zip(fields)
                .map(|(name, fields)| Variant {
                    name: *name,
                    fields,
                })
                .collect(),
        }
    }

    fn app(home: &ModPath, name: Symbol, args: Vec<IrType>) -> IrType {
        IrType::Enum {
            home: home.clone(),
            name,
            args,
        }
    }

    #[test]
    fn a_parameter_passed_only_back_to_its_enums_is_unused() -> DResult<()> {
        let mut i = Interner::new();
        let home = ModPath(vec![i.intern("Main")?]);
        let (tree, up, down, pa, pb) = (
            i.intern("T")?,
            i.intern("U")?,
            i.intern("W")?,
            i.intern("a")?,
            i.intern("b")?,
        );
        let (leaf, node) = (i.intern("L")?, i.intern("N")?);
        let var_a = IrType::Generic(pa);
        let var_b = IrType::Generic(pb);
        let defs = [
            // `type T a b = L | N (T a b) b`: `a` only recurs, `b` is held.
            def(
                &home,
                tree,
                vec![pa, pb],
                &[leaf, node],
                vec![
                    vec![],
                    vec![
                        app(&home, tree, vec![var_a.clone(), var_b.clone()]),
                        var_b.clone(),
                    ],
                ],
            ),
            // `type U a = U (W a)` and `type W a = W (U a)`: `a` only cycles.
            def(
                &home,
                up,
                vec![pa],
                &[up],
                vec![vec![app(&home, down, vec![var_a.clone()])]],
            ),
            def(
                &home,
                down,
                vec![pa],
                &[down],
                vec![vec![app(&home, up, vec![var_a])]],
            ),
        ];
        let uses = EnumParamUse::of(&defs);
        assert!(!uses.is_used(&home, tree, 0));
        assert!(uses.is_used(&home, tree, 1));
        assert!(!uses.is_used(&home, up, 0));
        assert!(!uses.is_used(&home, down, 0));
        assert!(uses.refuse_unused().is_err());
        let erased: Vec<EnumDef> = defs.into_iter().map(|d| uses.erase_in_def(d)).collect();
        let first = erased
            .first()
            .map(|d| (d.type_params.clone(), d.variants.clone()));
        assert_eq!(
            first,
            Some((
                vec![pb],
                vec![
                    Variant {
                        name: leaf,
                        fields: vec![]
                    },
                    Variant {
                        name: node,
                        fields: vec![app(&home, tree, vec![var_b.clone()]), var_b]
                    },
                ]
            ))
        );
        assert!(EnumParamUse::of(&erased).refuse_unused().is_ok());
        Ok(())
    }

    #[test]
    fn a_parameter_passed_to_a_used_position_is_used() -> DResult<()> {
        let mut i = Interner::new();
        let home = ModPath(vec![i.intern("Main")?]);
        let (held, passes, open, pa) = (
            i.intern("H")?,
            i.intern("P")?,
            i.intern("Q")?,
            i.intern("a")?,
        );
        let (rec, ext) = (i.intern("R")?, i.intern("Ext")?);
        let var_a = IrType::Generic(pa);
        let defs = [
            // `type H a = H a`: held directly.
            def(&home, held, vec![pa], &[held], vec![vec![var_a.clone()]]),
            // `type P a = P (H a) | R (P a)`: passed on to a held position.
            def(
                &home,
                passes,
                vec![pa],
                &[passes, rec],
                vec![
                    vec![app(&home, held, vec![var_a.clone()])],
                    vec![app(&home, passes, vec![var_a.clone()])],
                ],
            ),
            // `type Q a = Q (Ext a) (List a -> Int)`: an enum outside the
            // program, and a function, both use it.
            def(
                &home,
                open,
                vec![pa],
                &[open],
                vec![vec![
                    app(&ModPath(vec![]), ext, vec![var_a.clone()]),
                    IrType::Fun(vec![IrType::List(Box::new(var_a))], Box::new(IrType::Int)),
                ]],
            ),
        ];
        let uses = EnumParamUse::of(&defs);
        assert!(uses.is_used(&home, held, 0));
        assert!(uses.is_used(&home, passes, 0));
        assert!(uses.is_used(&home, open, 0));
        assert!(uses.refuse_unused().is_ok());
        Ok(())
    }

    #[test]
    fn the_declared_arity_is_the_parameter_count_of_a_held_enum_only() -> DResult<()> {
        let mut i = Interner::new();
        let home = ModPath(vec![i.intern("Main")?]);
        let (pair, other, pa, pb) = (
            i.intern("Pair")?,
            i.intern("Other")?,
            i.intern("a")?,
            i.intern("b")?,
        );
        let defs = [def(
            &home,
            pair,
            vec![pa, pb],
            &[pair],
            vec![vec![IrType::Generic(pa), IrType::Generic(pb)]],
        )];
        let uses = EnumParamUse::of(&defs);
        assert_eq!(uses.declared_arity(&home, pair), Some(2));
        assert_eq!(uses.declared_arity(&home, other), None);
        assert_eq!(uses.declared_arity(&ModPath(vec![]), pair), None);
        Ok(())
    }
}
