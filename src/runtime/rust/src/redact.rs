//! `Redacted<T>` — a field carrier whose `Debug` never prints the value.
//!
//! A runtime type that holds secret-role data (a cookie value, a principal's
//! identity) wraps each such field in [`Redacted`]. Its `Debug` writes [`REDACTED`] and nothing else, so the
//! owning type can keep `#[derive(Debug)]` and every `{:?}` of it — a runtime
//! log line, a `dbg!`, the stringify `Debug` fallback — prints the type's
//! structure with the secret fields masked. The value stays reachable to the
//! runtime code that owns it through `Deref` and [`Redacted::into_inner`]. There
//! is no inherent `get`: a method of that name would shadow the wrapped
//! value's own (`BTreeMap::get`) through auto-deref.
//!
//! `Redacted` implements no `Display` and no `IpeStringify`, so there is no
//! second formatting path that could reach the value. Std-only and declared in
//! every runtime module set; reached by qualified path (`crate::redact::…`),
//! never glob-re-exported.

/// The one spelling of a masked value, shared by every redacting `Debug` and
/// the `Secret` renderers.
pub const REDACTED: &str = "<redacted>";

/// A value whose `Debug` is [`REDACTED`], whatever it holds.
///
/// Equality, hashing and cloning delegate to the value; only formatting is
/// masked.
#[derive(Clone, Default, PartialEq, Eq, Hash)]
pub struct Redacted<T>(T);

impl<T> Redacted<T> {
    /// Wrap `value`.
    pub const fn new(value: T) -> Self {
        Self(value)
    }

    /// The wrapped value, by move.
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> From<T> for Redacted<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

impl<T> std::ops::Deref for Redacted<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T> std::ops::DerefMut for Redacted<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T> std::fmt::Debug for Redacted<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(REDACTED)
    }
}

/// Write a redacting `Debug` for a struct whose layout is fixed by emitted code.
///
/// Some runtime structs mirror an Ipê record (the emitter builds and reads their
/// fields by name), so their secret-role fields cannot change type to
/// [`Redacted`]. Their `Debug` is generated here instead: the listed `shown`
/// fields print their own `Debug`, every `masked` field prints [`REDACTED`],
/// and the `struct` destructure names every field, so a field added to the
/// struct and absent from both lists is a compile error (E0027), never a field
/// printed by default.
macro_rules! redacting_debug {
    ($ty:ident { shown: [$($shown:ident),* $(,)?], masked: [$($masked:ident),* $(,)?] $(,)? }) => {
        impl ::std::fmt::Debug for $ty {
            // The bindings carry the field names, which mirror camelCase Ipê fields.
            #[allow(non_snake_case)]
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                let Self { $($shown,)* $($masked: _,)* } = self;
                f.debug_struct(stringify!($ty))
                    $(.field(stringify!($shown), $shown))*
                    $(.field(stringify!($masked), &$crate::redact::Redacted::new(())))*
                    .finish()
            }
        }
    };
}
pub(crate) use redacting_debug;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    #[test]
    fn debug_never_prints_the_value() {
        let r = Redacted::new("Bearer S3CR3T".to_owned());
        assert_eq!(format!("{r:?}"), REDACTED);
        assert_eq!(format!("{r:#?}"), REDACTED);
        assert_eq!(r.as_str(), "Bearer S3CR3T");
    }

    #[allow(non_snake_case)]
    struct Mirror {
        method: String,
        authHeader: String,
    }
    redacting_debug!(Mirror {
        shown: [method],
        masked: [authHeader]
    });

    #[test]
    fn the_macro_masks_every_listed_field() {
        let m = Mirror {
            method: "GET".to_owned(),
            authHeader: "Bearer S3CR3T".to_owned(),
        };
        let shown = format!("{m:?}");
        assert_eq!(shown, "Mirror { method: \"GET\", authHeader: <redacted> }");
        assert!(!shown.contains("S3CR3T"));
        assert_eq!(m.authHeader.len(), 13);
    }
}
