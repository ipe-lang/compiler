//! The trait facts of a named enum's rendered Rust type, and the closed set of
//! Ipê enums whose Rust type the runtime defines instead of the emitted crate.
//!
//! A named [`IrType::Enum`] reaches the backend in exactly one of three forms: a
//! registered [`crate::EnumDef`] the backend emits (its traits come from the
//! whole-program fixpoint), an opaque `Rust.*` FFI handle (the foreign crate's
//! type, assumed to implement nothing), or one of the [`RuntimeBridgedEnum`]s
//! below (the runtime's own derives). The frontend's union skip-list and the
//! backend's enum-fact lookup both read [`RuntimeBridgedEnum`], so the set of
//! unions lowered without an `EnumDef` and the set the backend knows the facts
//! of cannot drift.

use ipe_intern::{Interner, Symbol};

use crate::ir::{CarrierLeaf, IrType, carrier_leaf};
use crate::show_policy::{ShowLeaf, show_leaf};

/// Which trait families a named enum's rendered Rust type implements.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EnumTraits {
    /// `Clone`.
    pub clone: bool,
    /// The full `Clone + Debug + PartialEq` derive set.
    pub derivable: bool,
    /// `serde::Serialize + serde::de::DeserializeOwned`.
    pub serde: bool,
}

impl EnumTraits {
    /// A type that implements none of the tracked traits.
    pub const NONE: Self = Self {
        clone: false,
        derivable: false,
        serde: false,
    };
}

/// An Ipê enum whose Rust type is defined by the runtime, not emitted from an `EnumDef`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RuntimeBridgedEnum {
    /// `Ipe.Cache.Cache` — the runtime `IpeCacheHandle`.
    CacheHandle,
    /// `Ipe.Config.Decoder` — lowered to the runtime decoder carrier.
    ConfigDecoder,
    /// `Ipe.PubSub.Topic` — lowered to its `String` name.
    PubSubTopic,
    /// `Ipe.Email.EmailProvider` — the runtime `email::EmailProvider`.
    EmailProvider,
    /// The builtin `ChunkEvent` — the runtime `http_stream::ChunkEvent<IpeError>`.
    ChunkEvent,
    /// The builtin `StreamId` — the runtime `IpeStreamId`.
    StreamId,
    /// The builtin `RedirectPolicy` — the runtime `http_client::RedirectPolicy`.
    RedirectPolicy,
    /// The builtin `DbFailure` — the runtime `error::IpeDbFailure`.
    DbFailure,
}

impl RuntimeBridgedEnum {
    /// Every runtime-bridged enum.
    pub const ALL: [Self; 8] = [
        Self::CacheHandle,
        Self::ConfigDecoder,
        Self::PubSubTopic,
        Self::EmailProvider,
        Self::ChunkEvent,
        Self::StreamId,
        Self::RedirectPolicy,
        Self::DbFailure,
    ];

    /// The home module path segments the enum is declared under.
    #[must_use]
    pub const fn home(self) -> &'static [&'static str] {
        match self {
            Self::CacheHandle => &["Ipe", "Cache"],
            Self::ConfigDecoder => &["Ipe", "Config"],
            Self::PubSubTopic => &["Ipe", "PubSub"],
            Self::EmailProvider => &["Ipe", "Email"],
            Self::ChunkEvent | Self::StreamId | Self::RedirectPolicy | Self::DbFailure => &[],
        }
    }

    /// The enum's Ipê type name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::CacheHandle => "Cache",
            Self::ConfigDecoder => "Decoder",
            Self::PubSubTopic => "Topic",
            Self::EmailProvider => "EmailProvider",
            Self::ChunkEvent => "ChunkEvent",
            Self::StreamId => "StreamId",
            Self::RedirectPolicy => "RedirectPolicy",
            Self::DbFailure => "DbFailure",
        }
    }

    /// Is the enum declared as a stdlib source union the lowerer must skip?
    ///
    /// The builtin ones have no source declaration; they are registered by the
    /// compiler and never reach the lowerer's union list.
    #[must_use]
    pub const fn is_source_union(self) -> bool {
        match self {
            Self::CacheHandle | Self::ConfigDecoder | Self::PubSubTopic | Self::EmailProvider => {
                true
            }
            Self::ChunkEvent | Self::StreamId | Self::RedirectPolicy | Self::DbFailure => false,
        }
    }

    /// The traits the runtime's Rust type implements.
    #[must_use]
    pub const fn traits(self) -> EnumTraits {
        match self {
            // `IpeStreamId`, `ChunkEvent<IpeError>`, `IpeDbFailure` and the
            // `String` a topic lowers to all derive `Clone`, `Debug`,
            // `PartialEq` and serde.
            Self::StreamId | Self::ChunkEvent | Self::PubSubTopic | Self::DbFailure => EnumTraits {
                clone: true,
                derivable: true,
                serde: true,
            },
            // `IpeCacheHandle` derives `Clone, Debug, PartialEq` without serde.
            Self::CacheHandle => EnumTraits {
                clone: true,
                derivable: true,
                serde: false,
            },
            // `RedirectPolicy` and `EmailProvider` derive `Clone, Debug` only;
            // the decoder carrier has a hand-written `Clone` only.
            Self::RedirectPolicy | Self::EmailProvider | Self::ConfigDecoder => EnumTraits {
                clone: true,
                derivable: false,
                serde: false,
            },
        }
    }

    /// The show leaf of the runtime's Rust type.
    #[must_use]
    pub const fn show_leaf(self) -> ShowLeaf {
        match self {
            Self::CacheHandle => show_leaf::CACHE_HANDLE,
            Self::ConfigDecoder => show_leaf::DECODER,
            // A topic lowers to its `String` name.
            Self::PubSubTopic => show_leaf::STRING,
            Self::EmailProvider => show_leaf::EMAIL_PROVIDER,
            Self::ChunkEvent => show_leaf::CHUNK_EVENT,
            Self::StreamId => show_leaf::STREAM_ID,
            Self::RedirectPolicy => show_leaf::REDIRECT_POLICY,
            Self::DbFailure => show_leaf::DB_FAILURE,
        }
    }

    /// The runtime-bridged enum named `name` under `home`, if any.
    #[must_use]
    pub fn classify(home: &[&str], name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|e| e.home() == home && e.name() == name)
    }
}

/// Is `home` a driver-generated FFI interface module (`Rust.*`)?
///
/// The `Rust.*` namespace is origin-reserved at canonicalisation, so the home
/// prefix is the provenance of an FFI declaration. It is NOT the provenance of
/// opacity: an FFI interface declares both opaque handles and transparent
/// unions ([`FfiUnion`]).
#[must_use]
pub fn home_is_ffi_interface(interner: &Interner, home: &[Symbol]) -> bool {
    home.first()
        .and_then(|s| interner.resolve(*s))
        .is_some_and(|s| s == "Rust")
}

/// The `Ipe.Db.Store` unions whose `row` type parameter is phantom.
///
/// No constructor of these unions holds a `row` value: the parameter ties a
/// query predicate, policy, correlated-subquery leaf or projection to its
/// store's row type at the type-checker only. Lowering drops the argument, so
/// each emits as a non-generic enum (`IpeDbStoreCond`, `IpeDbStorePred`, …)
/// whose construction is type-determinate, and the type checker's trait walks
/// skip the argument because no Rust trait bound can reach it.
pub const STORE_ROW_PHANTOM_UNIONS: [&str; 5] = ["Cond", "Policy", "Pred", "ExistsRef", "Select"];

/// Is `(home, name)` one of the [`STORE_ROW_PHANTOM_UNIONS`] of `Ipe.Db.Store`?
#[must_use]
pub fn is_store_row_phantom_union(interner: &Interner, home: &[Symbol], name: Symbol) -> bool {
    matches!(
        home,
        [a, b, c] if interner.resolve(*a) == Some("Ipe")
            && interner.resolve(*b) == Some("Db")
            && interner.resolve(*c) == Some("Store")
    ) && interner
        .resolve(name)
        .is_some_and(|n| STORE_ROW_PHANTOM_UNIONS.contains(&n))
}

/// What a union declared under an FFI interface home lowers to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FfiUnion {
    /// The opaque-handle placeholder `type N = N`: no `EnumDef` is lowered,
    /// its values are the foreign crate's own type, and it has no show row.
    OpaqueHandle,
    /// A real closed-union declaration: it lowers to an app enum with an
    /// emitted `IpeStringify` impl, like any user union.
    Transparent,
}

impl FfiUnion {
    /// Classify the union `name` declared under an FFI interface home, given
    /// each constructor's `(name, arity)`.
    ///
    /// The placeholder is exactly one nullary constructor spelling the type
    /// name; the FFI driver never declares a transparent union of that shape,
    /// so the two are distinct by construction. The lowerer (which `EnumDef`s
    /// to emit) and the type checker (which types have a rendering) both read
    /// this one classification, so they cannot disagree on a union.
    #[must_use]
    pub fn classify(name: Symbol, ctors: impl IntoIterator<Item = (Symbol, usize)>) -> Self {
        let mut ctors = ctors.into_iter();
        match (ctors.next(), ctors.next()) {
            (Some((ctor, 0)), None) if ctor == name => Self::OpaqueHandle,
            _ => Self::Transparent,
        }
    }
}

/// Is a non-carrier, non-enum leaf in an enum payload or record field `Clone`?
///
/// The one leaf rule the frontend's clone classifier and the backend's
/// enum/record `Clone` fixpoint share. A bare type variable is `Clone`: every
/// emitted enum and record bounds its type parameters `T: Clone`. Every other
/// leaf, a row variable included, takes its [`carrier_leaf`] verdict. A
/// transparent carrier or named enum answers `true`: the caller walks its
/// members itself. The rule is flat — it never inspects a carried element — so
/// it is a sound held-walk leaf.
#[must_use]
pub fn payload_leaf_is_clone(ty: &IrType) -> bool {
    match carrier_leaf(ty) {
        CarrierLeaf::Clone | CarrierLeaf::Carrier(_) => true,
        CarrierLeaf::NonClone => matches!(ty, IrType::Generic(_)),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn classify_round_trips_every_bridged_enum() {
        for e in RuntimeBridgedEnum::ALL {
            assert_eq!(RuntimeBridgedEnum::classify(e.home(), e.name()), Some(e));
        }
    }

    #[test]
    fn bridged_enum_identities_are_unique() {
        let keys: BTreeSet<_> = RuntimeBridgedEnum::ALL
            .iter()
            .map(|e| (e.home(), e.name()))
            .collect();
        assert_eq!(keys.len(), RuntimeBridgedEnum::ALL.len());
    }

    #[test]
    fn classify_refuses_a_foreign_home_or_name() {
        assert_eq!(RuntimeBridgedEnum::classify(&["Main"], "Cache"), None);
        assert_eq!(RuntimeBridgedEnum::classify(&[], "Cache"), None);
        assert_eq!(
            RuntimeBridgedEnum::classify(&["Ipe", "Cache"], "Widget"),
            None
        );
        assert_eq!(
            RuntimeBridgedEnum::classify(&["Rust", "Demo"], "Widget"),
            None
        );
    }

    #[test]
    fn bridged_traits_are_ordered_serde_then_derivable_then_clone() {
        for e in RuntimeBridgedEnum::ALL {
            let t = e.traits();
            assert!(!t.serde || t.derivable, "{e:?}: serde without derivable");
            assert!(!t.derivable || t.clone, "{e:?}: derivable without clone");
        }
    }

    #[test]
    fn payload_leaf_clone_admits_a_type_variable_and_refuses_a_row_variable() {
        let sym = ipe_intern::Symbol::from_raw(0);
        assert!(payload_leaf_is_clone(&IrType::Generic(sym)));
        assert!(!payload_leaf_is_clone(&IrType::RowGeneric(sym)));
        assert!(!payload_leaf_is_clone(&IrType::Task(Box::new(
            IrType::Unit
        ))));
    }

    #[test]
    fn only_the_nullary_self_named_union_is_an_opaque_handle() {
        let mut i = Interner::new();
        let mut sym = |s: &str| i.intern(s).expect("intern");
        let (shade, on, level, encoder) = (sym("Shade"), sym("On"), sym("Level"), sym("Encoder"));
        assert_eq!(
            FfiUnion::classify(encoder, [(encoder, 0)]),
            FfiUnion::OpaqueHandle
        );
        for ctors in [
            vec![(shade, 1)],
            vec![(on, 0)],
            vec![(shade, 0), (level, 1)],
            vec![(on, 0), (level, 1)],
            vec![],
        ] {
            assert_eq!(
                FfiUnion::classify(shade, ctors.clone()),
                FfiUnion::Transparent,
                "{ctors:?}"
            );
        }
    }

    #[test]
    fn only_a_rust_home_is_an_ffi_interface() {
        let mut i = Interner::new();
        let rust = i.intern("Rust").expect("intern");
        let tm = i.intern("Tm").expect("intern");
        let main = i.intern("Main").expect("intern");
        assert!(home_is_ffi_interface(&i, &[rust, tm]));
        assert!(!home_is_ffi_interface(&i, &[main, rust]));
        assert!(!home_is_ffi_interface(&i, &[]));
    }

    #[test]
    fn payload_leaf_clone_is_flat_over_carriers() {
        let fun = IrType::Fun(vec![IrType::Int], Box::new(IrType::Int));
        assert!(!payload_leaf_is_clone(&fun));
        assert!(payload_leaf_is_clone(&IrType::Maybe(Box::new(fun))));
    }
}
