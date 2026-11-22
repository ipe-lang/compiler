//! The feature-gated runtime items the backend emits, each with the cargo
//! features the runtime crate compiles it under.
//!
//! An emitter names one of these items only through
//! [`crate::EmitCtx::use_item`], which records it and returns its path. After
//! emit, [`check_items`] holds every recorded item against the feature set the
//! build selected, so a posture that emits an item its build does not compile
//! is refused at `ipe` time, never by cargo.

use std::collections::BTreeSet;
use std::fmt;

use ipe_diagnostics::Diagnostic;

/// One runtime-crate cargo feature an item's gate names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CargoFeature {
    /// `web-core`: the `ipe_runtime::web` module.
    WebCore,
    /// `db`: the database layer.
    Db,
    /// `redis_store`: the Redis session store.
    RedisStore,
    /// `web`: the served web host.
    Web,
}

impl CargoFeature {
    /// The feature's name in the runtime crate's `[features]` table.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WebCore => "web-core",
            Self::Db => "db",
            Self::RedisStore => "redis_store",
            Self::Web => "web",
        }
    }
}

/// The cargo-feature predicate the runtime crate compiles an item under: the
/// item's own `#[cfg(..)]` joined with every enclosing module's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeaturePredicate {
    /// `feature = "<name>"`.
    Feature(CargoFeature),
    /// `all(..)`: every member holds.
    All(&'static [Self]),
    /// `any(..)`: some member holds.
    Any(&'static [Self]),
}

impl FeaturePredicate {
    /// Whether the predicate holds when exactly the `selected` cargo features
    /// are on.
    #[must_use]
    pub fn holds(self, selected: &BTreeSet<&str>) -> bool {
        match self {
            Self::Feature(feature) => selected.contains(feature.as_str()),
            Self::All(all) => all.iter().all(|p| p.holds(selected)),
            Self::Any(any) => any.iter().any(|p| p.holds(selected)),
        }
    }

    /// Every cargo feature the predicate names.
    #[must_use]
    pub fn features(self) -> BTreeSet<CargoFeature> {
        let mut out = BTreeSet::new();
        self.collect_features(&mut out);
        out
    }

    fn collect_features(self, out: &mut BTreeSet<CargoFeature>) {
        match self {
            Self::Feature(feature) => {
                out.insert(feature);
            }
            Self::All(members) | Self::Any(members) => {
                for member in members {
                    member.collect_features(out);
                }
            }
        }
    }
}

impl fmt::Display for FeaturePredicate {
    /// The predicate in `#[cfg(..)]` syntax.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (word, members) = match self {
            Self::Feature(feature) => return write!(f, "feature = \"{}\"", feature.as_str()),
            Self::All(members) => ("all", members),
            Self::Any(members) => ("any", members),
        };
        write!(f, "{word}(")?;
        for (i, member) in members.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{member}")?;
        }
        write!(f, ")")
    }
}

/// The gate of the session-scoped hot readers: the `web` module
/// (`web-core`) and, inside it, a live host with an overlay channel.
const WEB_HOT_LOGIC: FeaturePredicate = FeaturePredicate::All(&[
    FeaturePredicate::Feature(CargoFeature::WebCore),
    FeaturePredicate::Any(&[
        FeaturePredicate::Feature(CargoFeature::Db),
        FeaturePredicate::Feature(CargoFeature::RedisStore),
        FeaturePredicate::Feature(CargoFeature::Web),
    ]),
]);

/// The gate of the served web host entry points.
const WEB_HOST: FeaturePredicate = FeaturePredicate::All(&[
    FeaturePredicate::Feature(CargoFeature::WebCore),
    FeaturePredicate::Feature(CargoFeature::Web),
]);

/// A feature-gated runtime function the backend emits a call to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RuntimeItem {
    /// The `update`-arm transition reader.
    ApplyTransitionHot,
    /// The `subscriptions` tick-source reader.
    SubEveryHot,
    /// The `init` datum reader.
    ApplyInitHot,
    /// The `update`-arm Cmd-wiring dispatch.
    FireCmdWiring,
    /// `Html.renderStatic`.
    WebRenderStatic,
    /// A standalone single-page `Web.tea` app.
    WebApp,
    /// A standalone routed `Web.tea` app.
    WebAppRouted,
    /// A mountable single-page `Web.embed` app.
    WebEmbed,
    /// A mountable routed `Web.embed` app.
    WebEmbedRouted,
}

impl RuntimeItem {
    /// Every row of the table.
    pub const ALL: [Self; 9] = [
        Self::ApplyTransitionHot,
        Self::SubEveryHot,
        Self::ApplyInitHot,
        Self::FireCmdWiring,
        Self::WebRenderStatic,
        Self::WebApp,
        Self::WebAppRouted,
        Self::WebEmbed,
        Self::WebEmbedRouted,
    ];

    /// The fully-qualified path the emitted crate names the item by.
    #[must_use]
    pub const fn path(self) -> &'static str {
        match self {
            Self::ApplyTransitionHot => "ipe_runtime::web::apply_transition_hot",
            Self::SubEveryHot => "ipe_runtime::web::sub_every_hot",
            Self::ApplyInitHot => "ipe_runtime::web::apply_init_hot",
            Self::FireCmdWiring => "ipe_runtime::web::fire_cmd_wiring",
            Self::WebRenderStatic => "ipe_runtime::web::web_render_static",
            Self::WebApp => "ipe_runtime::web::web_app",
            Self::WebAppRouted => "ipe_runtime::web::web_app_routed",
            Self::WebEmbed => "ipe_runtime::web::web_embed",
            Self::WebEmbedRouted => "ipe_runtime::web::web_embed_routed",
        }
    }

    /// The cargo features the runtime crate compiles the item under.
    #[must_use]
    pub const fn requires(self) -> FeaturePredicate {
        match self {
            Self::ApplyTransitionHot
            | Self::SubEveryHot
            | Self::ApplyInitHot
            | Self::FireCmdWiring => WEB_HOT_LOGIC,
            Self::WebRenderStatic
            | Self::WebApp
            | Self::WebAppRouted
            | Self::WebEmbed
            | Self::WebEmbedRouted => WEB_HOST,
        }
    }
}

/// An emitted runtime item the selected feature set does not compile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnselectedRuntimeItem {
    /// The item the emitted crate names.
    pub item: RuntimeItem,
    /// The predicate the selected features fail.
    pub requires: FeaturePredicate,
}

impl From<UnselectedRuntimeItem> for Diagnostic {
    fn from(refused: UnselectedRuntimeItem) -> Self {
        Self::CompilerBug {
            where_: "ipe_backend_rust::runtime_items::check_items",
            detail: format!(
                "the emitted program names `{}`, which the runtime crate compiles only under \
                 `{}`, but the build's selected runtime features do not satisfy it",
                refused.item.path(),
                refused.requires
            ),
        }
    }
}

/// Refuse the first recorded item whose predicate the `selected` cargo
/// features (the transitive set the build turns on) do not satisfy.
///
/// # Errors
///
/// [`UnselectedRuntimeItem`] naming the item and its predicate.
pub fn check_items(
    items: &BTreeSet<RuntimeItem>,
    selected: &BTreeSet<&str>,
) -> Result<(), UnselectedRuntimeItem> {
    items
        .iter()
        .find(|item| !item.requires().holds(selected))
        .map_or(Ok(()), |&item| {
            Err(UnselectedRuntimeItem {
                item,
                requires: item.requires(),
            })
        })
}

#[cfg(test)]
mod tests {
    use super::{RuntimeItem, UnselectedRuntimeItem, check_items};
    use std::collections::BTreeSet;

    /// The features `ipe init tui` under `ipe dev watch` selects.
    const TUI_WATCH: [&str; 6] = [
        "tui",
        "control-wire",
        "json",
        "async",
        "random",
        "dev-posture",
    ];

    fn set(features: &[&'static str]) -> BTreeSet<&'static str> {
        features.iter().copied().collect()
    }

    #[test]
    fn a_tui_watch_build_refuses_the_cmd_wiring_dispatch() {
        let items = BTreeSet::from([RuntimeItem::FireCmdWiring]);
        let refused = check_items(&items, &set(&TUI_WATCH));
        assert!(
            matches!(
                refused,
                Err(UnselectedRuntimeItem {
                    item: RuntimeItem::FireCmdWiring,
                    ..
                })
            ),
            "got {refused:?}"
        );
    }

    #[test]
    fn the_web_closure_admits_the_cmd_wiring_dispatch() {
        let items = BTreeSet::from([RuntimeItem::FireCmdWiring]);
        let mut features = set(&TUI_WATCH);
        features.extend(["web", "web-core"]);
        assert_eq!(check_items(&items, &features), Ok(()));
    }

    #[test]
    fn web_core_alone_refuses_every_hot_reader() {
        let features = set(&["web-core", "control-wire"]);
        for item in [
            RuntimeItem::ApplyTransitionHot,
            RuntimeItem::SubEveryHot,
            RuntimeItem::ApplyInitHot,
            RuntimeItem::FireCmdWiring,
        ] {
            let refused = check_items(&BTreeSet::from([item]), &features);
            assert!(
                matches!(refused, Err(UnselectedRuntimeItem { item: got, .. }) if got == item),
                "{item:?}: got {refused:?}"
            );
        }
    }

    #[test]
    fn no_recorded_item_needs_no_feature() {
        assert_eq!(check_items(&BTreeSet::new(), &BTreeSet::new()), Ok(()));
    }

    #[test]
    fn the_diagnostic_names_the_path_and_the_gate() {
        let refused = UnselectedRuntimeItem {
            item: RuntimeItem::ApplyInitHot,
            requires: RuntimeItem::ApplyInitHot.requires(),
        };
        let diagnostic = ipe_diagnostics::Diagnostic::from(refused);
        assert!(
            matches!(
                &diagnostic,
                ipe_diagnostics::Diagnostic::CompilerBug { detail, .. }
                    if detail.contains("ipe_runtime::web::apply_init_hot")
                        && detail.contains(
                            "all(feature = \"web-core\", any(feature = \"db\", \
                             feature = \"redis_store\", feature = \"web\"))"
                        )
            ),
            "got {diagnostic:?}"
        );
    }
}
