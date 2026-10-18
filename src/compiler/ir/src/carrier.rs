//! The function-value carrier decider shared by lowering, the IR passes and
//! the backend.
//!
//! One definition answers whether a function value fills an `Arc` slot or a
//! `Box` slot, so no stage re-derives the choice from a rendered type string.

use crate::IrType;

/// Whether a function value of IR type `ty` is built with `Arc::new`.
///
/// True when the value fills one of the runtime's `Arc<dyn Fn + Send + Sync>`
/// callback slots (so it must be boxed with `Arc::new`, not `Box::new`). The
/// shapes:
///   • `ServerHandler<E>`: `Fn(ServerRequest) -> IpeTask<E, ServerResponse>`
///   • `WsServerCfg` callbacks, `-> IpeTask<E, ()>`:
///       - `Fn(WsHandle)`           (onConnect / onClose)
///       - `Fn(WsHandle, String)`   (onMessage)
///       - `Fn(WsHandle, Error)`    (onError — 2nd param is the error type,
///         NOT String; its setter `ws_server_with_on_error` takes `Arc<…>`)
///
/// This MUST dispatch on the `IrType` STRUCTURE, never on the rendered type
/// string. The backend's `render_type` renders `ServerHandler<E>` as the type-ALIAS name
/// `"ServerHandler<IpeError>"` — NOT the expanded `"Arc<dyn Fn…>"` — so a
/// `starts_with("Arc<")` string test silently misclassifies every handler shape
/// as `Box` and reintroduces the E0308 seal break for inline
/// `Server.post path (\req -> …)` handler lambdas (the regression this shared
/// helper closes). The param patterns are kept in LOCK-STEP with the backend
/// `render_type`'s WS/ServerHandler Arc arms (`emit_types.rs`) — a shape rendered as `Arc<…>`
/// there but boxed with `Box::new` here (or vice-versa) is an E0308. Both
/// the backend's `emit_func_value` and `emit_lambda` route through here so the
/// two emit paths can never drift, and the IR's borrow analysis reads the same
/// decider when it builds a function-value adapter.
#[must_use]
pub fn wants_arc_ctor(ty: &IrType) -> bool {
    // A promoted `SharedFun` slot renders `Arc<dyn Fn>` (`render_type`), so its
    // value must be built with `Arc::new`, not `Box::new` — the two carriers are
    // distinct Rust types and mixing them is an E0308.
    if matches!(ty, IrType::SharedFun(_, _)) {
        return true;
    }
    matches!(ty,
        IrType::Fun(params, ret)
            if (matches!(params.as_slice(), [IrType::ServerRequest])
                && matches!(ret.as_ref(), IrType::Task(inner)
                    if matches!(inner.as_ref(), IrType::ServerResponse)))
               || (matches!(
                    params.as_slice(),
                    [IrType::WebSocketServer]
                        | [IrType::WebSocketServer, IrType::Str | IrType::Error]
                ) && matches!(ret.as_ref(), IrType::Task(inner)
                    if matches!(inner.as_ref(), IrType::Unit)))
    )
}
