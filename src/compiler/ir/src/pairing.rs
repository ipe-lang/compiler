//! Head-identity pairing of two [`IrType`] nodes' children.
//!
//! Every structural walk that runs two lowered types side by side pairs their
//! children through [`paired_children`], so no walk can pair two distinct
//! constructors that merely share an arity.

use core::array;
use core::iter::Zip;
use core::slice;

use crate::IrType;

/// The positional child pairs of two same-headed [`IrType`] nodes.
///
/// Yields the positional sequence (tuple elements, enum arguments, function
/// parameters) pairwise, then the fixed slots (a payload, a function's return,
/// a `Result`'s error then ok) in declaration order.
#[derive(Clone, Debug)]
pub struct PairedChildren<'a> {
    seq: Zip<slice::Iter<'a, IrType>, slice::Iter<'a, IrType>>,
    slots: array::IntoIter<Option<(&'a IrType, &'a IrType)>, 2>,
}

/// One pair of mirrored children.
type Pair<'a> = (&'a IrType, &'a IrType);

impl<'a> PairedChildren<'a> {
    /// Fixed slots only, no positional sequence.
    fn slots(first: Pair<'a>, second: Option<Pair<'a>>) -> Self {
        let empty: &[IrType] = &[];
        Self {
            seq: empty.iter().zip(empty),
            slots: [Some(first), second].into_iter(),
        }
    }

    /// A positional sequence then an optional trailing slot; `None` when the sequences differ in length.
    fn seq(a: &'a [IrType], b: &'a [IrType], trailing: Option<Pair<'a>>) -> Option<Self> {
        (a.len() == b.len()).then(|| Self {
            seq: a.iter().zip(b),
            slots: [trailing, None].into_iter(),
        })
    }
}

impl<'a> Iterator for PairedChildren<'a> {
    type Item = Pair<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.seq
            .next()
            .or_else(|| self.slots.by_ref().flatten().next())
    }
}

/// The child pairs of `a` and `b` when both nodes have one head, else `None`.
///
/// Heads are identical when the variants agree and every identity field
/// agrees: an [`IrType::Enum`] by `home` and `name` (nominal identity, so two
/// same-short-named types from different modules never pair), an
/// [`IrType::Ui`] by `ctor`, a function by its carrier (`Fun`, `SharedFun` and
/// `FnOnceChain` are distinct Rust types). Positional children must agree in
/// count. A record (keyed by field, not position), a leaf, a generic, and every
/// mismatched pair yield `None`, so a caller that treats `None` as "no shared
/// shape" fails closed.
#[must_use]
#[allow(clippy::too_many_lines)] // One arm per `IrType` variant, so a new variant is a compile error, not a silent `None`.
pub fn paired_children<'a>(a: &'a IrType, b: &'a IrType) -> Option<PairedChildren<'a>> {
    let payload = |x: &'a IrType, y: &'a IrType| Some(PairedChildren::slots((x, y), None));
    let two_slots = |x1: &'a IrType, x2: &'a IrType, y1: &'a IrType, y2: &'a IrType| {
        Some(PairedChildren::slots((x1, y1), Some((x2, y2))))
    };
    match a {
        IrType::List(x) => match b {
            IrType::List(y) => payload(x, y),
            _ => None,
        },
        IrType::Maybe(x) => match b {
            IrType::Maybe(y) => payload(x, y),
            _ => None,
        },
        IrType::Set(x) => match b {
            IrType::Set(y) => payload(x, y),
            _ => None,
        },
        IrType::Task(x) => match b {
            IrType::Task(y) => payload(x, y),
            _ => None,
        },
        IrType::Cmd(x) => match b {
            IrType::Cmd(y) => payload(x, y),
            _ => None,
        },
        IrType::Sub(x) => match b {
            IrType::Sub(y) => payload(x, y),
            _ => None,
        },
        IrType::Decoder(x) => match b {
            IrType::Decoder(y) => payload(x, y),
            _ => None,
        },
        IrType::WebRoute(x) => match b {
            IrType::WebRoute(y) => payload(x, y),
            _ => None,
        },
        IrType::Ui { ctor: cx, msg: x } => match b {
            IrType::Ui { ctor: cy, msg: y } if cx == cy => payload(x, y),
            _ => None,
        },
        IrType::Result(x1, x2) => match b {
            IrType::Result(y1, y2) => two_slots(x1, x2, y1, y2),
            _ => None,
        },
        IrType::Dict(x1, x2) => match b {
            IrType::Dict(y1, y2) => two_slots(x1, x2, y1, y2),
            _ => None,
        },
        IrType::CustomElement { down: x1, up: x2 } => match b {
            IrType::CustomElement { down: y1, up: y2 } => two_slots(x1, x2, y1, y2),
            _ => None,
        },
        IrType::Tuple(x) => match b {
            IrType::Tuple(y) => PairedChildren::seq(x, y, None),
            _ => None,
        },
        IrType::Enum {
            home: hx,
            name: nx,
            args: x,
        } => match b {
            IrType::Enum {
                home: hy,
                name: ny,
                args: y,
            } if hx == hy && nx == ny => PairedChildren::seq(x, y, None),
            _ => None,
        },
        IrType::Fun(px, rx) => match b {
            IrType::Fun(py, ry) => PairedChildren::seq(px, py, Some((&**rx, &**ry))),
            _ => None,
        },
        IrType::SharedFun(px, rx) => match b {
            IrType::SharedFun(py, ry) => PairedChildren::seq(px, py, Some((&**rx, &**ry))),
            _ => None,
        },
        IrType::FnOnceChain(px, rx) => match b {
            IrType::FnOnceChain(py, ry) => PairedChildren::seq(px, py, Some((&**rx, &**ry))),
            _ => None,
        },
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
        | IrType::WebSocketServer
        | IrType::WebSocketServerCfg
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
        | IrType::WorkerApp => None,
    }
}

#[cfg(test)]
mod tests {
    use super::paired_children;
    use crate::{IrType, ModPath, UiCtor};
    use ipe_intern::Interner;

    fn pairs(a: &IrType, b: &IrType) -> Option<Vec<(IrType, IrType)>> {
        paired_children(a, b).map(|ps| ps.map(|(x, y)| (x.clone(), y.clone())).collect())
    }

    /// Same-headed nodes pair every child in declaration order.
    #[test]
    fn same_head_pairs_children_in_order() {
        let fun = |p: IrType, r: IrType| IrType::Fun(vec![p], Box::new(r));
        assert_eq!(
            pairs(
                &fun(IrType::Int, IrType::Bool),
                &fun(IrType::Str, IrType::Char)
            ),
            Some(vec![
                (IrType::Int, IrType::Str),
                (IrType::Bool, IrType::Char)
            ])
        );
        let result = |e: IrType, o: IrType| IrType::Result(Box::new(e), Box::new(o));
        assert_eq!(
            pairs(
                &result(IrType::Int, IrType::Bool),
                &result(IrType::Str, IrType::Unit)
            ),
            Some(vec![
                (IrType::Int, IrType::Str),
                (IrType::Bool, IrType::Unit)
            ])
        );
    }

    /// Two enums of one arity pair only when home and name both agree.
    #[test]
    fn enum_pairs_by_home_and_name_not_arity() {
        let mut interner = Interner::new();
        #[allow(clippy::expect_used)] // a fresh interner accepts these names
        let mut sym = |s: &str| interner.intern(s).expect("intern");
        let (main, lib, pair, swap) = (sym("Main"), sym("Lib"), sym("Pair"), sym("Swap"));
        let enum_of = |home, name| IrType::Enum {
            home: ModPath(vec![home]),
            name,
            args: vec![IrType::Int],
        };
        assert!(pairs(&enum_of(main, pair), &enum_of(main, pair)).is_some());
        assert_eq!(pairs(&enum_of(main, pair), &enum_of(main, swap)), None);
        assert_eq!(pairs(&enum_of(main, pair), &enum_of(lib, pair)), None);
    }

    /// Mismatched carriers, `Ui` ctors, and positional lengths never pair.
    #[test]
    fn distinct_heads_and_lengths_refuse() {
        let ui = |ctor| IrType::Ui {
            ctor,
            msg: Box::new(IrType::Int),
        };
        assert_eq!(pairs(&ui(UiCtor::Html), &ui(UiCtor::Cells)), None);
        assert_eq!(
            pairs(
                &IrType::List(Box::new(IrType::Int)),
                &IrType::Set(Box::new(IrType::Int))
            ),
            None
        );
        assert_eq!(
            pairs(
                &IrType::Tuple(vec![IrType::Int, IrType::Int]),
                &IrType::Tuple(vec![IrType::Int, IrType::Int, IrType::Int])
            ),
            None
        );
        assert_eq!(
            pairs(
                &IrType::Fun(vec![IrType::Int], Box::new(IrType::Int)),
                &IrType::SharedFun(vec![IrType::Int], Box::new(IrType::Int))
            ),
            None
        );
        assert_eq!(pairs(&IrType::Int, &IrType::Int), None);
    }
}
