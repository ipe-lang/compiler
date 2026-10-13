//! The single structural walk over the VALUE components an [`IrType`] holds.
//!
//! Every "does a value of this type hold an X?" predicate (a `Task`, an effect
//! carrier, an opaque FFI handle, a non-`Clone` carrier) is one leaf test over
//! this walk, so the descent rules live in exactly one exhaustive `match`: a new
//! [`IrType`] variant breaks the build here instead of silently falling into a
//! per-predicate `_ => false` arm.

use std::collections::{BTreeMap, BTreeSet};

use ipe_intern::Symbol;

use crate::ir::{EnumDef, IrType, ModPath};

/// Every named enum's variants as `(variant name, payload field types)`, keyed by `(home, name)`.
///
/// Built from the lowered [`EnumDef`]s (see [`enum_payload_table`]); the
/// frontend's clone classifier and the backend's `Clone` fixpoint read the same
/// shape, so both see the same payloads.
pub type EnumPayloadTable = BTreeMap<(ModPath, Symbol), Vec<(Symbol, Vec<IrType>)>>;

/// Deepest nesting [`ir_type_holds`] descends before it answers `true`.
///
/// Source type nesting is already bounded by the parser; this ceiling keeps the
/// walk itself bounded by construction. Past it the walk fails closed: it
/// reports the leaf as held, the conservative answer for every "holds a
/// hazardous component" predicate.
pub const MAX_HELD_WALK_DEPTH: u16 = 512;

/// The payload table of `defs`.
#[must_use]
pub fn enum_payload_table<'a>(defs: impl IntoIterator<Item = &'a EnumDef>) -> EnumPayloadTable {
    defs.into_iter()
        .map(|def| {
            let variants = def
                .variants
                .iter()
                .map(|v| (v.name, v.fields.clone()))
                .collect();
            ((def.home.clone(), def.name), variants)
        })
        .collect()
}

/// Does a value of type `ty` hold a component satisfying `leaf`?
///
/// `leaf` is tested on `ty` itself and on every value component reachable from
/// it: the elements of every transparent carrier (`Maybe`, `List`, `Set`,
/// `Result`, `Dict`, tuple, record, `Ui` message, `WebRoute` page) and, for a
/// named enum, both its type arguments and every variant payload field looked
/// up in `payloads`. An enum absent from `payloads` contributes only its type
/// arguments. A payload field naming one of the enum's own type parameters is
/// covered by walking the arguments, so walking raw payload fields plus all
/// arguments over-approximates, never under-approximates.
///
/// Function, decoder, effect (`Task` / `Cmd` / `Sub`) and widget-handle types
/// are opaque values: `leaf` sees them, but their type parameters are not held
/// components. Each named enum is expanded at most once per walk, so recursive
/// types terminate; nesting beyond [`MAX_HELD_WALK_DEPTH`] answers `true`.
///
/// `leaf` must be a flat test: a leaf that starts another walk escapes both the
/// expanded-enum set and the depth ceiling of this one. A predicate that needs
/// more reach picks a wider [`Reach`] through [`ir_type_reaches`] instead.
#[must_use]
pub fn ir_type_holds(
    ty: &IrType,
    payloads: &EnumPayloadTable,
    leaf: &impl Fn(&IrType) -> bool,
) -> bool {
    ir_type_reaches(ty, payloads, Reach::Held, leaf)
}

/// Which components of a value one walk visits.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Reach {
    /// The components a value holds; effect and widget-handle parameters stay opaque.
    Held,
    /// The held components plus what effects yield and widget handles seal.
    ///
    /// An effect is a `Task` / `Cmd` / `Sub`. The same single walk descends those parameters, so a type recursive
    /// through an effect (`type Stream = Next Int (Task Error Stream) | End`)
    /// still expands each enum once and stays under the depth ceiling.
    HeldOrYielded,
}

/// Does a value of type `ty` reach a component satisfying `leaf` under `reach`?
///
/// [`ir_type_holds`] is this walk at [`Reach::Held`]; every other rule of that
/// walk (transparent carriers, enum arguments and payloads, one expansion per
/// enum, the fail-closed depth ceiling, the flat-leaf contract) is shared.
#[must_use]
pub fn ir_type_reaches(
    ty: &IrType,
    payloads: &EnumPayloadTable,
    reach: Reach,
    leaf: &impl Fn(&IrType) -> bool,
) -> bool {
    HeldWalk {
        payloads,
        leaf,
        reach,
        expanded: BTreeSet::new(),
    }
    .holds(ty, 0)
}

/// Does any variant payload of enum `(home, name)` hold a component satisfying `leaf`?
///
/// The same walk as [`ir_type_holds`], started at the enum's payload fields
/// alone (its type arguments are the caller's to classify). An enum absent
/// from `payloads` holds nothing.
#[must_use]
pub fn enum_payload_holds(
    home: &ModPath,
    name: Symbol,
    payloads: &EnumPayloadTable,
    leaf: &impl Fn(&IrType) -> bool,
) -> bool {
    HeldWalk {
        payloads,
        leaf,
        reach: Reach::Held,
        expanded: BTreeSet::new(),
    }
    .payload_holds(home, name, 0)
}

/// One walk's state: the payload table, the leaf test, the reach, and the enums already expanded.
struct HeldWalk<'a, F> {
    payloads: &'a EnumPayloadTable,
    leaf: &'a F,
    reach: Reach,
    expanded: BTreeSet<(ModPath, Symbol)>,
}

impl<F: Fn(&IrType) -> bool> HeldWalk<'_, F> {
    fn any<'t>(&mut self, tys: impl IntoIterator<Item = &'t IrType>, depth: u16) -> bool {
        tys.into_iter().any(|t| self.holds(t, depth))
    }

    fn payload_holds(&mut self, home: &ModPath, name: Symbol, depth: u16) -> bool {
        let key = (home.clone(), name);
        let payloads = self.payloads;
        let variants = payloads.get(&key);
        // An enum already expanded in this walk either answered `false` or is
        // still being expanded further up (a recursive type); either way it
        // adds nothing new here.
        if !self.expanded.insert(key) {
            return false;
        }
        variants.is_some_and(|vs| self.any(vs.iter().flat_map(|(_, fields)| fields), depth))
    }

    fn holds(&mut self, ty: &IrType, depth: u16) -> bool {
        if (self.leaf)(ty) {
            return true;
        }
        let Some(next) = depth.checked_add(1).filter(|d| *d <= MAX_HELD_WALK_DEPTH) else {
            return true;
        };
        match ty {
            IrType::Maybe(e) | IrType::List(e) | IrType::Set(e) | IrType::WebRoute(e) => {
                self.holds(e, next)
            }
            IrType::Ui { msg, .. } => self.holds(msg, next),
            IrType::Result(a, b) | IrType::Dict(a, b) => {
                self.holds(a, next) || self.holds(b, next)
            }
            IrType::Tuple(es) => self.any(es, next),
            IrType::Record(fields) => self.any(fields.values(), next),
            IrType::Enum { home, name, args } => {
                self.any(args, next) || self.payload_holds(home, *name, next)
            }
            // Effects and widget handles: their parameters describe what they
            // yield or seal, reached only when the walk asks for it.
            IrType::Task(e) | IrType::Cmd(e) | IrType::Sub(e) => match self.reach {
                Reach::Held => false,
                Reach::HeldOrYielded => self.holds(e, next),
            },
            IrType::CustomElement { down, up } => match self.reach {
                Reach::Held => false,
                Reach::HeldOrYielded => self.holds(down, next) || self.holds(up, next),
            },
            // Opaque values: their type parameters describe what they produce
            // or consume, not a component the value holds.
            IrType::Fun(_, _)
            | IrType::SharedFun(_, _)
            | IrType::FnOnceChain(_, _)
            | IrType::Decoder(_)
            // Leaves.
            | IrType::Int
            | IrType::Float
            | IrType::Bool
            | IrType::Str
            | IrType::Char
            | IrType::Unit
            | IrType::Bytes
            | IrType::Json
            | IrType::Db
            | IrType::Generic(_)
            | IrType::RowGeneric(_)
            | IrType::ServerRequest
            | IrType::ServerResponse
            | IrType::ServerRoute
            | IrType::ServerCookie
            | IrType::StreamWriter
            | IrType::HttpRequest
            | IrType::WebSocketServer
            | IrType::WebSocketServerCfg
            | IrType::UiPlain(_)
            | IrType::WebReq
            | IrType::SessionHandle
            | IrType::Order
            | IrType::BackoffStrategy
            | IrType::HttpMethod
            | IrType::Decimal
            | IrType::Principal
            | IrType::AuthConfig
            | IrType::TokenSource
            | IrType::ErrorKind
            | IrType::Error
            | IrType::ErrorDetails
            | IrType::ErrorInfo
            | IrType::PanicInfo
            | IrType::TypeInfo
            | IrType::SqlFragment
            | IrType::Secret
            | IrType::Path
            | IrType::Regex
            | IrType::ProcessRunWithCfg
            | IrType::ProcessRunInPtyCfg
            | IrType::CacheCfg
            | IrType::CacheStats
            | IrType::WebSocketClientCfg
            | IrType::CsvDoc
            | IrType::EmailMessage
            | IrType::EmailAttachment
            | IrType::EmailSesConfig
            | IrType::EmailSmtpConfig
            | IrType::EmailProvider
            | IrType::CryptoKey
            | IrType::CryptoMac
            | IrType::EmailAddress
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
            | IrType::Locale
            | IrType::WebApp
            | IrType::TuiApp
            | IrType::CliApp
            | IrType::WorkerApp => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use ipe_diagnostics::DResult;
    use ipe_intern::Interner;

    use super::*;
    use crate::ir::Variant;

    fn is_task(t: &IrType) -> bool {
        matches!(t, IrType::Task(_))
    }

    fn task() -> IrType {
        IrType::Task(Box::new(IrType::Unit))
    }

    fn named(home: &ModPath, name: Symbol, args: Vec<IrType>) -> IrType {
        IrType::Enum {
            home: home.clone(),
            name,
            args,
        }
    }

    #[test]
    fn tuple_and_record_holding_task_are_found() -> DResult<()> {
        let table = EnumPayloadTable::new();
        let mut interner = Interner::new();
        let f = interner.intern("f")?;
        let tuple = IrType::Tuple(vec![IrType::Int, task()]);
        let record = IrType::Record(BTreeMap::from([(f, IrType::List(Box::new(task())))]));
        assert!(ir_type_holds(&tuple, &table, &is_task));
        assert!(ir_type_holds(&record, &table, &is_task));
        assert!(!ir_type_holds(
            &IrType::Tuple(vec![IrType::Int, IrType::Str]),
            &table,
            &is_task
        ));
        Ok(())
    }

    #[test]
    fn enum_payload_holding_task_is_found() -> DResult<()> {
        let mut interner = Interner::new();
        let home = ModPath(vec![interner.intern("Main")?]);
        let job = interner.intern("Job")?;
        let run = interner.intern("Run")?;
        let table = enum_payload_table(&[EnumDef {
            name: job,
            home: home.clone(),
            type_params: Vec::new(),
            variants: vec![Variant {
                name: run,
                fields: vec![task()],
            }],
        }]);
        let ty = named(&home, job, Vec::new());
        assert!(ir_type_holds(&ty, &table, &is_task));
        assert!(ir_type_holds(
            &IrType::List(Box::new(ty.clone())),
            &table,
            &is_task
        ));
        assert!(enum_payload_holds(&home, job, &table, &is_task));
        // Without the payload table only the (empty) type arguments are walked.
        assert!(!ir_type_holds(&ty, &EnumPayloadTable::new(), &is_task));
        Ok(())
    }

    #[test]
    fn recursive_enum_terminates() -> DResult<()> {
        let mut interner = Interner::new();
        let home = ModPath(vec![interner.intern("Main")?]);
        let tree = interner.intern("Tree")?;
        let forest = interner.intern("Forest")?;
        let leaf = interner.intern("Leaf")?;
        let node = interner.intern("Node")?;
        let a = interner.intern("a")?;
        // type Tree a = Leaf a | Node (Forest a)
        // type Forest a = Forest (List (Tree a))
        let tree_of_a = named(&home, tree, vec![IrType::Generic(a)]);
        let table = enum_payload_table(&[
            EnumDef {
                name: tree,
                home: home.clone(),
                type_params: vec![a],
                variants: vec![
                    Variant {
                        name: leaf,
                        fields: vec![IrType::Generic(a)],
                    },
                    Variant {
                        name: node,
                        fields: vec![named(&home, forest, vec![IrType::Generic(a)])],
                    },
                ],
            },
            EnumDef {
                name: forest,
                home: home.clone(),
                type_params: vec![a],
                variants: vec![Variant {
                    name: forest,
                    fields: vec![IrType::List(Box::new(tree_of_a))],
                }],
            },
        ]);
        let of_int = named(&home, tree, vec![IrType::Int]);
        let of_task = named(&home, tree, vec![task()]);
        assert!(!ir_type_holds(&of_int, &table, &is_task));
        assert!(ir_type_holds(&of_task, &table, &is_task));
        Ok(())
    }

    #[test]
    fn opaque_values_hide_their_parameters() {
        let table = EnumPayloadTable::new();
        let fun = IrType::Fun(vec![task()], Box::new(task()));
        let nested_task = IrType::Task(Box::new(task()));
        let is_inner_task =
            |t: &IrType| matches!(t, IrType::Task(inner) if **inner == IrType::Unit);
        assert!(!ir_type_holds(&fun, &table, &is_task));
        assert!(!ir_type_holds(&nested_task, &table, &is_inner_task));
    }

    #[test]
    fn nesting_past_the_ceiling_fails_closed() {
        let table = EnumPayloadTable::new();
        let mut ty = IrType::Int;
        for _ in 0..=MAX_HELD_WALK_DEPTH {
            ty = IrType::List(Box::new(ty));
        }
        assert!(ir_type_holds(&ty, &table, &is_task));
    }

    fn is_fun(t: &IrType) -> bool {
        matches!(t, IrType::Fun(_, _))
    }

    fn fun() -> IrType {
        IrType::Fun(vec![IrType::Int], Box::new(IrType::Int))
    }

    #[test]
    fn yielded_reach_descends_effects_and_widget_handles() {
        let table = EnumPayloadTable::new();
        let task_fun = IrType::Task(Box::new(fun()));
        let cmd_fun = IrType::Cmd(Box::new(IrType::Maybe(Box::new(fun()))));
        let widget = IrType::CustomElement {
            down: Box::new(IrType::Int),
            up: Box::new(fun()),
        };
        for ty in [&task_fun, &cmd_fun, &widget] {
            assert!(!ir_type_holds(ty, &table, &is_fun));
            assert!(ir_type_reaches(ty, &table, Reach::HeldOrYielded, &is_fun));
        }
        // A decoder stays opaque at every reach.
        let hof = IrType::Decoder(Box::new(fun()));
        assert!(!ir_type_reaches(
            &hof,
            &table,
            Reach::HeldOrYielded,
            &is_fun
        ));
    }

    #[test]
    fn type_recursive_through_an_effect_terminates() -> DResult<()> {
        let mut interner = Interner::new();
        let home = ModPath(vec![interner.intern("Main")?]);
        let stream = interner.intern("Stream")?;
        let next = interner.intern("Next")?;
        let end = interner.intern("End")?;
        let emit = interner.intern("Emit")?;
        let stream_ty = named(&home, stream, Vec::new());
        // type Stream = Next Int (Task Error Stream) | End
        let data_only = enum_payload_table(&[EnumDef {
            name: stream,
            home: home.clone(),
            type_params: Vec::new(),
            variants: vec![
                Variant {
                    name: next,
                    fields: vec![
                        IrType::Int,
                        IrType::Task(Box::new(IrType::Result(
                            Box::new(IrType::Error),
                            Box::new(stream_ty.clone()),
                        ))),
                    ],
                },
                Variant {
                    name: end,
                    fields: Vec::new(),
                },
            ],
        }]);
        assert!(!ir_type_reaches(
            &stream_ty,
            &data_only,
            Reach::HeldOrYielded,
            &is_fun
        ));
        assert!(!enum_payload_holds(&home, stream, &data_only, &is_fun));
        // type Stream = Next Int (Task Error Stream) | Emit (Int -> Int)
        let with_fun = enum_payload_table(&[EnumDef {
            name: stream,
            home,
            type_params: Vec::new(),
            variants: vec![
                Variant {
                    name: next,
                    fields: vec![IrType::Int, IrType::Task(Box::new(stream_ty.clone()))],
                },
                Variant {
                    name: emit,
                    fields: vec![fun()],
                },
            ],
        }]);
        assert!(ir_type_reaches(
            &IrType::Task(Box::new(stream_ty)),
            &with_fun,
            Reach::HeldOrYielded,
            &is_fun
        ));
        Ok(())
    }

    #[test]
    fn types_mutually_recursive_through_effects_terminate() -> DResult<()> {
        let mut interner = Interner::new();
        let home = ModPath(vec![interner.intern("Main")?]);
        let ping = interner.intern("Ping")?;
        let reply = interner.intern("Pong")?;
        let go = interner.intern("Go")?;
        let back = interner.intern("Back")?;
        let ping_ty = named(&home, ping, Vec::new());
        let reply_ty = named(&home, reply, Vec::new());
        // type Ping = Go (Task Error Pong)
        // type Pong = Back (Cmd Ping) (Sub Pong)
        let table = enum_payload_table(&[
            EnumDef {
                name: ping,
                home: home.clone(),
                type_params: Vec::new(),
                variants: vec![Variant {
                    name: go,
                    fields: vec![IrType::Task(Box::new(reply_ty.clone()))],
                }],
            },
            EnumDef {
                name: reply,
                home,
                type_params: Vec::new(),
                variants: vec![Variant {
                    name: back,
                    fields: vec![
                        IrType::Cmd(Box::new(ping_ty.clone())),
                        IrType::Sub(Box::new(reply_ty.clone())),
                    ],
                }],
            },
        ]);
        assert!(!ir_type_reaches(
            &ping_ty,
            &table,
            Reach::HeldOrYielded,
            &is_fun
        ));
        assert!(!ir_type_reaches(
            &reply_ty,
            &table,
            Reach::HeldOrYielded,
            &is_fun
        ));
        Ok(())
    }

    #[test]
    fn yielded_nesting_past_the_ceiling_fails_closed() {
        let table = EnumPayloadTable::new();
        let mut ty = IrType::Int;
        for _ in 0..=MAX_HELD_WALK_DEPTH {
            ty = IrType::Task(Box::new(ty));
        }
        assert!(ir_type_reaches(&ty, &table, Reach::HeldOrYielded, &is_fun));
        // At `Held` reach the outer effect is opaque, so nothing is nested.
        assert!(!ir_type_holds(&ty, &table, &is_fun));
    }
}
