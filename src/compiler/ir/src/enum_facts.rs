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
}

impl RuntimeBridgedEnum {
    /// Every runtime-bridged enum.
    pub const ALL: [Self; 7] = [
        Self::CacheHandle,
        Self::ConfigDecoder,
        Self::PubSubTopic,
        Self::EmailProvider,
        Self::ChunkEvent,
        Self::StreamId,
        Self::RedirectPolicy,
    ];

    /// The home module path segments the enum is declared under.
    #[must_use]
    pub const fn home(self) -> &'static [&'static str] {
        match self {
            Self::CacheHandle => &["Ipe", "Cache"],
            Self::ConfigDecoder => &["Ipe", "Config"],
            Self::PubSubTopic => &["Ipe", "PubSub"],
            Self::EmailProvider => &["Ipe", "Email"],
            Self::ChunkEvent | Self::StreamId | Self::RedirectPolicy => &[],
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
            Self::ChunkEvent | Self::StreamId | Self::RedirectPolicy => false,
        }
    }

    /// The traits the runtime's Rust type implements.
    #[must_use]
    pub const fn traits(self) -> EnumTraits {
        match self {
            // `IpeStreamId`, `ChunkEvent<IpeError>` and the `String` a topic
            // lowers to all derive `Clone`, `Debug`, `PartialEq` and serde.
            Self::StreamId | Self::ChunkEvent | Self::PubSubTopic => EnumTraits {
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
    fn payload_leaf_clone_is_flat_over_carriers() {
        let fun = IrType::Fun(vec![IrType::Int], Box::new(IrType::Int));
        assert!(!payload_leaf_is_clone(&fun));
        assert!(payload_leaf_is_clone(&IrType::Maybe(Box::new(fun))));
    }
}
