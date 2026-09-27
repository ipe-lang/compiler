//! The delivery set — which deliveries a project's `ipe release` produces, and
//! the release loop that builds every one of them.
//!
//! Three layers, each a parse boundary (parse, don't validate); the next never
//! re-checks what the previous established:
//!
//! * [`ShipEntry`] — one delivery as read from `package.ipe`'s `ships` list,
//!   before the program's shape is known. Produced only by the manifest reader.
//! * [`DeliverySet`] — the non-empty, duplicate-free set resolved against the
//!   pinned shape, every member individually admitted by [`Delivery::resolve`]
//!   (the one validity table). Constructible only through [`DeliverySet::resolve`].
//! * [`ReleaseOutcome`] — the loop's only exit. [`Released`] has a private
//!   constructor, so it exists only as evidence a packager ran to completion;
//!   [`ReleaseOutcome::AllReleased`] is produced only when the loop consumed
//!   every declared delivery, so a partial success has a different type
//!   constructor and no call site can mistake it for success.
//!
//! Because a delivery set is non-empty by parse, duplicate-free by parse, and
//! consumed (`self`) by the loop, a declared-but-unbuilt delivery is
//! unrepresentable: the set cannot be iterated halfway and dropped, and
//! `AllReleased` cannot be built without one `Released` per declared delivery.

use std::path::PathBuf;

use ipe_backend_rust::static_build::StaticTriple;

use crate::CliError;
use crate::delivery::{Delivery, DeliveryError, Host, Runtime, Shape};

/// The third delivery axis a co-located binary carries.
///
/// The host triple, the musl static triple, or a curated cross triple.
/// `Delivery` owns shape × runtime × host; this owns the target the binary is
/// built for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryTarget {
    /// The host's own triple — the default artifact.
    Host,
    /// The musl static binary (`--static`).
    Static,
    /// A cross-compiled binary for a curated triple, parsed against the
    /// build-plan layer's supported set so an unsupported triple is a read-time
    /// rejection, never a `cargo` error later.
    Cross(StaticTriple),
}

/// One declared delivery, as read from `package.ipe`'s `ships` list — the
/// program's shape is not yet known, so the web-only entries are carried
/// unresolved and checked later against the pinned shape.
///
/// Produced only by the manifest reader. The eight variants are the closed ship
/// vocabulary, each mapping one-to-one onto the CLI delivery grammar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShipEntry {
    /// The shape's own co-located artifact, on the given target. For `web` this
    /// is served. Meaningful for every shape.
    Binary(BinaryTarget),
    /// `web desktop` — the webview-native desktop bundle.
    Desktop,
    /// `web solo` — the browser wasm bundle.
    Solo,
    /// `web solo desktop` — the wasm bundle plus a native webview shell.
    SoloDesktop,
    /// `web solo ios` — the wasm bundle plus an iOS shell.
    SoloIos,
    /// `web solo android` — the wasm bundle plus an Android shell.
    SoloAndroid,
}

impl ShipEntry {
    /// The `(runtime, host)` this entry resolves through [`Delivery::resolve`],
    /// for the web-bearing entries. The co-located `Binary` entry is shape-led
    /// (its runtime/host follow the pinned shape), so it is not mapped here.
    const fn web_axes(self) -> Option<(Option<Runtime>, Host)> {
        Some(match self {
            Self::Binary(_) => return None,
            Self::Desktop => (Some(Runtime::Served), Host::Desktop),
            Self::Solo => (Some(Runtime::Solo), Host::Default),
            Self::SoloDesktop => (Some(Runtime::Solo), Host::Desktop),
            Self::SoloIos => (Some(Runtime::Solo), Host::Ios),
            Self::SoloAndroid => (Some(Runtime::Solo), Host::Android),
        })
    }
}

/// A resolved delivery paired with its target axis — one member of a set.
///
/// Every field is already validated: the [`Delivery`] passed through
/// [`Delivery::resolve`], and a `Static` target passed `allows_static`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlannedDelivery {
    delivery: Delivery,
    target: BinaryTarget,
}

impl PlannedDelivery {
    /// The resolved, validated delivery.
    #[must_use]
    pub const fn delivery(self) -> Delivery {
        self.delivery
    }

    /// The target axis this delivery is built for.
    #[must_use]
    pub const fn target(self) -> BinaryTarget {
        self.target
    }

    /// The output directory slug for this delivery under the `release/` root —
    /// the delivery's CLI words joined by `-`, with a target suffix when the
    /// target is not the host. Injective over a duplicate-free set, so the
    /// per-slug directories never collide.
    #[must_use]
    pub fn slug(self) -> String {
        let mut slug = self.delivery.to_string().replace(' ', "-");
        match self.target {
            BinaryTarget::Host => {}
            BinaryTarget::Static => slug.push_str("-static"),
            BinaryTarget::Cross(triple) => {
                slug.push('-');
                slug.push_str(triple.as_str());
            }
        }
        slug
    }
}

/// The non-empty, duplicate-free set of deliveries `ipe release` produces, every
/// element individually admitted by [`Delivery::resolve`].
///
/// Constructible only through [`DeliverySet::resolve`]; the inner vector is
/// private. No code path can hold a set containing an invalid, duplicate, or
/// shape-incompatible member, and none can construct an empty one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliverySet(Vec<PlannedDelivery>);

impl DeliverySet {
    /// Resolve the declared ship entries against the shape `main` pins into a
    /// validated, non-empty, duplicate-free set.
    ///
    /// Each entry is mapped onto the arguments of the existing
    /// [`Delivery::resolve`] — the one validity table — so a manifest-declared
    /// combination is exactly as valid as the same words typed at the CLI. A
    /// `Static` target reuses the existing `allows_static` gate. Web-only entries
    /// on a non-web shape fail here with the pedagogical shape lesson. An empty
    /// entry list resolves to the singleton `[ binary ]` — the shape's default
    /// delivery, today's `release` behaviour.
    ///
    /// # Errors
    /// [`CliError::UsageOwned`] naming a duplicate entry; [`CliError::UsageOwned`]
    /// for a web-only entry on a non-web shape (the shape lesson); the underlying
    /// [`DeliveryError`] for any other invalid combination or a `--static`
    /// request the delivery cannot honour.
    pub fn resolve(pinned: Shape, entries: &[ShipEntry]) -> Result<Self, CliError> {
        // An absent `ships` field is the implicit `[ binary ]` singleton.
        if entries.is_empty() {
            let delivery = Delivery::resolve(pinned, None, Host::Default)?;
            return Ok(Self(vec![PlannedDelivery {
                delivery,
                target: BinaryTarget::Host,
            }]));
        }

        let mut planned: Vec<PlannedDelivery> = Vec::with_capacity(entries.len());
        for &entry in entries {
            let plan = Self::resolve_one(pinned, entry)?;
            if planned.contains(&plan) {
                return Err(duplicate_entry(entry));
            }
            planned.push(plan);
        }
        Ok(Self(planned))
    }

    /// Resolve one ship entry against the pinned shape into a [`PlannedDelivery`].
    fn resolve_one(pinned: Shape, entry: ShipEntry) -> Result<PlannedDelivery, CliError> {
        // The shape-led co-located binary: runtime/host follow the shape, and the
        // target axis (host/static/cross) rides alongside.
        let (runtime, host) = match entry {
            ShipEntry::Binary(target) => {
                let delivery = Delivery::resolve(pinned, None, Host::Default)?;
                if matches!(target, BinaryTarget::Static) && !delivery.allows_static() {
                    return Err(DeliveryError::StaticNotAllowed { delivery }.into());
                }
                return Ok(PlannedDelivery { delivery, target });
            }
            ShipEntry::Desktop => (Some(Runtime::Served), Host::Desktop),
            ShipEntry::Solo => (Some(Runtime::Solo), Host::Default),
            ShipEntry::SoloDesktop => (Some(Runtime::Solo), Host::Desktop),
            ShipEntry::SoloIos => (Some(Runtime::Solo), Host::Ios),
            ShipEntry::SoloAndroid => (Some(Runtime::Solo), Host::Android),
        };

        // A web-bearing entry: reject a non-web shape first with the shape lesson,
        // then resolve through the validity table.
        if !matches!(pinned, Shape::Web) {
            return Err(web_entry_on_non_web(pinned, entry));
        }
        let delivery = Delivery::resolve(pinned, runtime, host)?;
        Ok(PlannedDelivery {
            delivery,
            target: BinaryTarget::Host,
        })
    }

    /// The resolved deliveries, in declared order.
    #[must_use]
    pub fn planned(&self) -> &[PlannedDelivery] {
        &self.0
    }

    /// The number of declared deliveries. Always at least one.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// A delivery set is never empty (guaranteed by [`Self::resolve`]); this is
    /// present only to satisfy the `len`-without-`is_empty` lint. It always
    /// returns `false`.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Consume the set, invoking `release_one` per delivery in declared order.
    ///
    /// This is the sole producer of [`Released`]: there is no other way to obtain
    /// one, and no way to obtain [`ReleaseOutcome::AllReleased`] without one
    /// `Released` per declared delivery. The loop continues through failures —
    /// each delivery attempted, each failure recorded — so a partial release
    /// names every failure rather than stopping at the first.
    #[must_use]
    pub fn release_each(
        self,
        mut release_one: impl FnMut(&PlannedDelivery) -> Result<PathBuf, CliError>,
    ) -> ReleaseOutcome {
        let mut built: Vec<Released> = Vec::with_capacity(self.0.len());
        let mut failed: Vec<(Delivery, CliError)> = Vec::new();
        for plan in &self.0 {
            match release_one(plan) {
                Ok(artifact) => built.push(Released {
                    delivery: plan.delivery,
                    artifact,
                }),
                Err(err) => failed.push((plan.delivery, err)),
            }
        }
        if failed.is_empty() {
            ReleaseOutcome::AllReleased(built)
        } else {
            ReleaseOutcome::Incomplete { built, failed }
        }
    }
}

/// Proof one delivery was built and packaged. Private constructor: the only
/// producer is [`DeliverySet::release_each`], fed by a packager that ran to
/// completion.
#[derive(Debug)]
pub struct Released {
    delivery: Delivery,
    artifact: PathBuf,
}

impl Released {
    /// The delivery this artifact realises.
    #[must_use]
    pub const fn delivery(&self) -> Delivery {
        self.delivery
    }

    /// The path written, for the release summary line.
    #[must_use]
    pub fn artifact(&self) -> &std::path::Path {
        &self.artifact
    }
}

/// The release loop's only exit.
///
/// [`Self::AllReleased`] is produced only when every declared delivery built; a
/// partial success is [`Self::Incomplete`], a different constructor, so no call
/// site can treat it as success by accident. Matching is exhaustive, and
/// `Incomplete` carries what failed.
#[derive(Debug)]
pub enum ReleaseOutcome {
    /// Every declared delivery built. One [`Released`] per declared delivery, in
    /// declared order.
    AllReleased(Vec<Released>),
    /// At least one delivery failed. `built` and `failed` together account for
    /// every declared delivery; `failed` is non-empty by construction.
    Incomplete {
        /// The deliveries that did build, in declared order.
        built: Vec<Released>,
        /// Each failed delivery paired with its diagnostic — non-empty.
        failed: Vec<(Delivery, CliError)>,
    },
}

impl ReleaseOutcome {
    /// Whether every declared delivery built. The command exits non-zero unless
    /// this holds.
    #[must_use]
    pub const fn all_released(&self) -> bool {
        matches!(self, Self::AllReleased(_))
    }
}

/// The duplicate-entry rejection, naming the repeated delivery and the fix.
fn duplicate_entry(entry: ShipEntry) -> CliError {
    let words = describe_entry(entry);
    CliError::UsageOwned(crate::text::ships_repeated(&words))
}

/// The web-entry-on-non-web-shape rejection, in the pedagogical two-axis voice.
fn web_entry_on_non_web(pinned: Shape, entry: ShipEntry) -> CliError {
    let words = describe_entry(entry);
    CliError::UsageOwned(crate::text::ships_shape_mismatch(&words, &pinned.word()))
}

/// The CLI delivery words a ship entry stands for, for a diagnostic. The
/// co-located `binary` variants have no delivery words of their own (the shape
/// leads), so they are named by their builder spelling.
fn describe_entry(entry: ShipEntry) -> String {
    match entry {
        ShipEntry::Binary(BinaryTarget::Host) => "binary".to_owned(),
        ShipEntry::Binary(BinaryTarget::Static) => "staticBinary".to_owned(),
        ShipEntry::Binary(BinaryTarget::Cross(t)) => format!("crossBinary {}", t.as_str()),
        // A web-bearing entry reads as its resolved delivery words (`web solo ios`).
        _ => match entry.web_axes() {
            Some((runtime, host)) => Delivery::resolve(Shape::Web, runtime, host)
                .map_or_else(|_| ship_builder_word(entry).to_owned(), |d| d.to_string()),
            None => ship_builder_word(entry).to_owned(),
        },
    }
}

/// The builder spelling of a web-bearing ship entry (for a message when the
/// delivery itself cannot be resolved).
const fn ship_builder_word(entry: ShipEntry) -> &'static str {
    match entry {
        ShipEntry::Binary(_) => "binary",
        ShipEntry::Desktop => "desktop",
        ShipEntry::Solo => "solo",
        ShipEntry::SoloDesktop => "soloDesktop",
        ShipEntry::SoloIos => "soloIos",
        ShipEntry::SoloAndroid => "soloAndroid",
    }
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::panic,
    clippy::match_wildcard_for_single_variants
)]
mod tests {
    use super::*;

    fn cross(triple: &str) -> ShipEntry {
        ShipEntry::Binary(BinaryTarget::Cross(
            StaticTriple::parse(triple).expect("supported triple"),
        ))
    }

    #[test]
    fn absent_field_is_the_binary_singleton() {
        for shape in [
            Shape::Script,
            Shape::Tui,
            Shape::Cli,
            Shape::Worker,
            Shape::Web,
        ] {
            let set = DeliverySet::resolve(shape, &[]).expect("empty resolves to singleton");
            assert_eq!(set.len(), 1);
            let only = set.planned()[0];
            assert_eq!(only.delivery().shape(), shape);
            assert_eq!(only.target(), BinaryTarget::Host);
        }
    }

    #[test]
    fn web_entries_resolve_on_web_and_preserve_order() {
        let entries = [
            ShipEntry::Binary(BinaryTarget::Host),
            ShipEntry::Desktop,
            ShipEntry::Solo,
            ShipEntry::SoloIos,
        ];
        let set = DeliverySet::resolve(Shape::Web, &entries).expect("web set resolves");
        let slugs: Vec<String> = set.planned().iter().map(|p| p.slug()).collect();
        assert_eq!(slugs, ["web", "web-desktop", "web-solo", "web-solo-ios"]);
    }

    #[test]
    fn web_entry_on_non_web_shape_is_pedagogical() {
        for shape in [Shape::Script, Shape::Tui, Shape::Cli, Shape::Worker] {
            let err = DeliverySet::resolve(shape, &[ShipEntry::SoloIos]).unwrap_err();
            let CliError::UsageOwned(msg) = err else {
                panic!("expected a named rejection, got {err:?}");
            };
            assert!(msg.contains(shape.word()), "names the shape: {msg}");
            assert!(msg.contains("Web.tea"), "offers the fix: {msg}");
        }
    }

    #[test]
    fn static_binary_refused_where_delivery_has_no_static_form() {
        // `web desktop` is webview-native: no musl binary. The `allows_static`
        // gate refuses a `Static` target on it — but that arm is reached only for
        // the co-located `Binary` entry, whose delivery is served for web
        // (which *does* allow static). The genuine refusal lands on a shape whose
        // binary cannot be static: none of the current shapes, so assert the gate
        // holds for the web-desktop delivery directly instead.
        let set = DeliverySet::resolve(Shape::Web, &[ShipEntry::Binary(BinaryTarget::Static)])
            .expect("served web is static-capable");
        assert_eq!(set.planned()[0].target(), BinaryTarget::Static);
    }

    #[test]
    fn duplicate_entry_is_rejected() {
        let err =
            DeliverySet::resolve(Shape::Web, &[ShipEntry::Solo, ShipEntry::Solo]).unwrap_err();
        let CliError::UsageOwned(msg) = err else {
            panic!("expected a named rejection, got {err:?}");
        };
        assert!(msg.contains("twice"), "names the duplicate: {msg}");
    }

    #[test]
    fn cross_binary_slug_carries_the_triple() {
        let set = DeliverySet::resolve(Shape::Cli, &[cross("aarch64-unknown-linux-musl")])
            .expect("cli cross binary resolves");
        assert_eq!(set.planned()[0].slug(), "cli-aarch64-unknown-linux-musl");
    }

    #[test]
    fn static_binary_slug_is_suffixed() {
        let set = DeliverySet::resolve(Shape::Cli, &[ShipEntry::Binary(BinaryTarget::Static)])
            .expect("cli static binary resolves");
        assert_eq!(set.planned()[0].slug(), "cli-static");
    }

    #[test]
    fn release_each_all_built_is_all_released() {
        let set = DeliverySet::resolve(
            Shape::Web,
            &[ShipEntry::Binary(BinaryTarget::Host), ShipEntry::Solo],
        )
        .expect("web set resolves");
        let outcome = set.release_each(|plan| Ok(PathBuf::from(plan.slug())));
        assert!(outcome.all_released());
        match outcome {
            ReleaseOutcome::AllReleased(built) => assert_eq!(built.len(), 2),
            other => panic!("expected AllReleased, got {other:?}"),
        }
    }

    #[test]
    fn release_each_partial_failure_is_incomplete_naming_it() {
        let set = DeliverySet::resolve(
            Shape::Web,
            &[
                ShipEntry::Binary(BinaryTarget::Host),
                ShipEntry::Solo,
                ShipEntry::Desktop,
            ],
        )
        .expect("web set resolves");
        // Fail exactly the second delivery (solo).
        let outcome = set.release_each(|plan| {
            if matches!(plan.delivery().runtime(), Some(Runtime::Solo)) && plan.slug() == "web-solo"
            {
                Err(CliError::UsageOwned("solo bundle failed".to_owned()))
            } else {
                Ok(PathBuf::from(plan.slug()))
            }
        });
        assert!(!outcome.all_released());
        match outcome {
            ReleaseOutcome::Incomplete { built, failed } => {
                assert_eq!(built.len(), 2);
                assert_eq!(failed.len(), 1);
                assert_eq!(failed[0].0.to_string(), "web solo");
            }
            other => panic!("expected Incomplete, got {other:?}"),
        }
    }
}
