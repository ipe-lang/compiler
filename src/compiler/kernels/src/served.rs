//! The served-listener fact: whether a built program opens an inbound listener.
//!
//! A serving kernel carries a [`ServedListenerKind`] in its row; lowering folds
//! every serving kernel the built entry reaches into one [`ServedListener`]. The
//! fact is runtime-free: a port the program writes stays a raw
//! [`SourcePortLiteral`], parsed into a port once at the sandbox boundary.

/// Which listener a serving kernel opens; picks the operator key and port source.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ServedListenerKind {
    /// A `Web` application host: it binds the web default port.
    WebHost,
    /// `Server.listen`: its first argument is the port.
    ServerPortArg,
}

/// The listener the built program reaches, folded by lowering.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum ServedListener {
    /// No serving kernel is reached.
    #[default]
    NotServed,
    /// The program serves on the port this names.
    Serves(ServedPort),
}

/// The port a serving program binds, as the source states it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ServedPort {
    /// A `Web` application entry: the web default port.
    WebDefault,
    /// `Server.listen` with an integer literal port.
    ServerLiteral(SourcePortLiteral),
    /// A computed port, an eta or partial use, or two different literals.
    ServerDynamic,
    /// A web host and a `Server.listen` both reached.
    Several,
}

/// The program's port as written; not yet a port (no range checked here).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SourcePortLiteral(i64);

impl SourcePortLiteral {
    /// Wrap the integer the program wrote.
    #[must_use]
    pub const fn new(raw: i64) -> Self {
        Self(raw)
    }

    /// The integer the program wrote.
    #[must_use]
    pub const fn get(self) -> i64 {
        self.0
    }
}

impl ServedPort {
    /// Join two reached ports: commutative and total.
    ///
    /// Equal values stay; two different literals give [`Self::ServerDynamic`];
    /// a server port with the web default gives [`Self::Several`], which absorbs.
    #[must_use]
    pub const fn join(self, other: Self) -> Self {
        match (self, other) {
            (Self::WebDefault, Self::WebDefault) => Self::WebDefault,
            (Self::Several, _)
            | (_, Self::Several)
            | (Self::WebDefault, Self::ServerLiteral(_) | Self::ServerDynamic)
            | (Self::ServerLiteral(_) | Self::ServerDynamic, Self::WebDefault) => Self::Several,
            (Self::ServerLiteral(a), Self::ServerLiteral(b)) => {
                if a.0 == b.0 {
                    Self::ServerLiteral(a)
                } else {
                    Self::ServerDynamic
                }
            }
            (Self::ServerDynamic, Self::ServerLiteral(_) | Self::ServerDynamic)
            | (Self::ServerLiteral(_), Self::ServerDynamic) => Self::ServerDynamic,
        }
    }
}

impl ServedListener {
    /// Join two reached facts: commutative and total.
    #[must_use]
    pub const fn join(self, other: Self) -> Self {
        match (self, other) {
            (Self::NotServed, x) | (x, Self::NotServed) => x,
            (Self::Serves(a), Self::Serves(b)) => Self::Serves(a.join(b)),
        }
    }

    /// Fold one reached port into this fact.
    #[must_use]
    pub const fn with(self, port: ServedPort) -> Self {
        self.join(Self::Serves(port))
    }
}

#[cfg(test)]
mod tests {
    use super::{ServedListener, ServedPort, SourcePortLiteral};

    fn lit(n: i64) -> ServedPort {
        ServedPort::ServerLiteral(SourcePortLiteral::new(n))
    }

    #[test]
    fn join_is_commutative_and_total() {
        let ports = [
            ServedPort::WebDefault,
            lit(8000),
            lit(9000),
            ServedPort::ServerDynamic,
            ServedPort::Several,
        ];
        for a in ports {
            for b in ports {
                assert_eq!(a.join(b), b.join(a), "{a:?} join {b:?}");
            }
            assert_eq!(a.join(a), a);
            assert_eq!(a.join(ServedPort::Several), ServedPort::Several);
        }
        assert_eq!(lit(8000).join(lit(9000)), ServedPort::ServerDynamic);
        assert_eq!(lit(8000).join(ServedPort::WebDefault), ServedPort::Several);
        assert_eq!(
            ServedPort::ServerDynamic.join(ServedPort::WebDefault),
            ServedPort::Several
        );
        assert_eq!(
            ServedListener::NotServed.with(lit(8000)),
            ServedListener::Serves(lit(8000))
        );
        assert_eq!(
            ServedListener::NotServed.join(ServedListener::NotServed),
            ServedListener::NotServed
        );
    }
}
