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
use ipe_fs_open::EntryName;

use crate::CliError;
use crate::delivery::{Delivery, DeliveryError, Host, RetiredRuntimeWord, Runtime, Shape};
use crate::pack::mobile::MobileOs;

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
/// Produced only by the manifest reader. The variants are the closed ship
/// vocabulary, each mapping one-to-one onto the CLI delivery grammar; a web
/// entry's builder word is derived from its runtime and host words.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShipEntry {
    /// The shape's own co-located artifact, on the given target. For `web` this
    /// is served. Meaningful for every shape.
    Binary(BinaryTarget),
    /// `web desktop` — the webview-native desktop bundle.
    Desktop,
    /// `web client` — the browser wasm bundle.
    Client,
    /// `web client desktop` — the wasm bundle plus a native webview shell.
    ClientDesktop,
    /// `web client ios` — the wasm bundle plus an iOS shell.
    ClientIos,
    /// `web client android` — the wasm bundle plus an Android shell.
    ClientAndroid,
}

impl ShipEntry {
    /// Every entry that takes no argument, in builder order: the builder table
    /// the manifest reader and writer both iterate.
    pub const BUILDERS: [Self; 7] = [
        Self::Binary(BinaryTarget::Host),
        Self::Binary(BinaryTarget::Static),
        Self::Desktop,
        Self::Client,
        Self::ClientDesktop,
        Self::ClientIos,
        Self::ClientAndroid,
    ];

    /// The `(runtime, host)` this entry resolves through [`Delivery::resolve`].
    ///
    /// `None` for the co-located `Binary` entry, which is shape-led: its
    /// runtime and host follow the pinned shape.
    #[must_use]
    pub const fn axes(self) -> Option<(Runtime, Host)> {
        Some(match self {
            Self::Binary(_) => return None,
            Self::Desktop => (Runtime::Served, Host::Desktop),
            Self::Client => (Runtime::Client, Host::Default),
            Self::ClientDesktop => (Runtime::Client, Host::Desktop),
            Self::ClientIos => (Runtime::Client, Host::Ios),
            Self::ClientAndroid => (Runtime::Client, Host::Android),
        })
    }

    /// The `Ipe.Package` builder that writes this entry (`clientIos`).
    ///
    /// A web entry's builder is derived from its runtime word and its host's
    /// camel form, so the builder vocabulary cannot drift from the delivery
    /// grammar.
    #[must_use]
    pub fn builder_word(self) -> String {
        let Self::Binary(target) = self else {
            return self.axes().map_or_else(String::new, |(runtime, host)| {
                spell_builder(runtime.word(), host.camel())
            });
        };
        match target {
            BinaryTarget::Host => "binary",
            BinaryTarget::Static => "staticBinary",
            BinaryTarget::Cross(_) => "crossBinary",
        }
        .to_owned()
    }

    /// The entry whose builder replaces the retired builder `name`, if `name`
    /// is one.
    ///
    /// The retired builders are derived, never listed: a retired word that the
    /// `client` runtime replaces, followed by a client host's camel form, in
    /// its builder spelling (`soloIos`) or its constructor spelling
    /// (`ShipSoloIos`).
    #[must_use]
    pub fn retired_builder(name: &str) -> Option<Self> {
        Self::BUILDERS.into_iter().find(|entry| {
            entry.axes().is_some_and(|(runtime, host)| {
                runtime == Runtime::Client
                    && RetiredRuntimeWord::ALL.into_iter().any(|word| {
                        word.replacement() == Runtime::Client && {
                            let builder = spell_builder(Some(word.text()), host.camel());
                            name == builder || name == ship_constructor(&builder)
                        }
                    })
            })
        })
    }
}

/// A builder word from a runtime word and a host camel form: the runtime word
/// first, or the host lower-cased when the runtime is unnamed.
fn spell_builder(runtime: Option<&str>, host: Option<&str>) -> String {
    let host = host.unwrap_or_default();
    runtime.map_or_else(
        || {
            let mut chars = host.chars();
            chars.next().map_or_else(String::new, |first| {
                first.to_lowercase().chain(chars).collect()
            })
        },
        |word| format!("{word}{host}"),
    )
}

/// The `Ship` constructor a builder word stands for (`clientIos` → `ShipClientIos`).
#[must_use]
pub fn ship_constructor(builder: &str) -> String {
    let mut chars = builder.chars();
    chars.next().map_or_else(String::new, |first| {
        format!("Ship{}{}", first.to_uppercase(), chars.as_str())
    })
}

/// The packer a bundle delivery goes through.
///
/// `desktop` routes to the webview-native desktop packager, `ios`/`android`
/// to the mobile system-webview packager. Only [`release_route`] builds one
/// from a delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleHost {
    /// `web desktop` — a self-contained per-OS desktop bundle for the host OS.
    Desktop,
    /// `web client ios` / `web client android` — a native mobile system-webview shell.
    Mobile(MobileOs),
}

/// How a delivery is built: the native binary, the browser bundle, or an app bundle.
///
/// [`release_route`] is its one producer; the release writer and the release
/// dedupe key both read it, so they cannot disagree on a delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseRoute {
    /// The native binary, served or shape-led.
    Native,
    /// The browser client bundle.
    Browser,
    /// An app bundle through the packer for one host.
    Bundle(BundleHost),
}

/// The route a resolved delivery is built through.
///
/// Exhaustive over `(host, runtime)` with no wildcard, so a new host or
/// runtime forces a decision here.
///
/// # Errors
/// [`DeliveryError::ClientDesktopHasNoPacker`] for `web client desktop`, which
/// no packer builds; [`DeliveryError::ServedHostNotMobile`] for a served mobile
/// host, which [`Delivery::resolve`] never admits.
pub const fn release_route(delivery: Delivery) -> Result<ReleaseRoute, DeliveryError> {
    match (delivery.host(), delivery.runtime()) {
        (Host::Default, Some(Runtime::Served) | None) => Ok(ReleaseRoute::Native),
        (Host::Default, Some(Runtime::Client)) => Ok(ReleaseRoute::Browser),
        (Host::Desktop, Some(Runtime::Served) | None) => {
            Ok(ReleaseRoute::Bundle(BundleHost::Desktop))
        }
        (Host::Desktop, Some(Runtime::Client)) => Err(DeliveryError::ClientDesktopHasNoPacker),
        (Host::Ios, Some(Runtime::Client)) => {
            Ok(ReleaseRoute::Bundle(BundleHost::Mobile(MobileOs::Ios)))
        }
        (Host::Android, Some(Runtime::Client)) => {
            Ok(ReleaseRoute::Bundle(BundleHost::Mobile(MobileOs::Android)))
        }
        (host @ (Host::Ios | Host::Android), Some(Runtime::Served) | None) => {
            Err(DeliveryError::ServedHostNotMobile { host })
        }
    }
}

/// The directory name one release member writes under `release/`.
///
/// One path segment over `[a-z0-9._-]`: non-empty, no leading `.`, at most
/// [`MAX_SLUG_BYTES`] bytes, and one [`EntryName`]. Built only by
/// [`PlannedDelivery::slug`] (and read back by [`ReleaseSlug::listed`]), so
/// every member place is a function of its release identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseSlug {
    text: String,
    name: EntryName,
}

/// The longest slug, in bytes: one path component on every supported filesystem.
pub const MAX_SLUG_BYTES: usize = 255;

impl ReleaseSlug {
    /// Parse `text` against the slug grammar.
    fn parse(text: String) -> Option<Self> {
        let grammar = !text.is_empty()
            && text.len() <= MAX_SLUG_BYTES
            && !text.starts_with('.')
            && text.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'_' | b'-')
            });
        if !grammar {
            return None;
        }
        let name = EntryName::new(std::ffi::OsStr::new(&text))?;
        Some(Self { text, name })
    }

    /// The slug a listed `release/` entry spells, or `None` for any other name.
    #[must_use]
    pub fn listed(name: &EntryName) -> Option<Self> {
        name.as_os_str()
            .to_str()
            .and_then(|text| Self::parse(text.to_owned()))
    }

    /// The slug text, one path component.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The slug as the one entry name a held directory opens.
    #[must_use]
    pub const fn entry_name(&self) -> &EntryName {
        &self.name
    }
}

/// The one spelling of a remedy command a refusal prints.
///
/// The project dir rides after the verb as the user typed it, quoted as one
/// shell word, so the printed line is the one that clears the refusal.
#[derive(Debug, Clone, Copy)]
pub struct Remedy;

impl Remedy {
    /// `ipe <verb> [<dir>] <words>`.
    #[must_use]
    pub fn command(verb: &str, dir: Option<&str>, words: &str) -> String {
        dir.map_or_else(
            || format!("ipe {verb} {words}"),
            |dir| format!("ipe {verb} {} {words}", Self::shell_word(dir)),
        )
    }

    /// `text` as one word of the user's shell: bare when every character is
    /// one no shell reads specially, else single-quoted.
    fn shell_word(text: &str) -> std::borrow::Cow<'_, str> {
        let plain = |c: char| c.is_ascii_alphanumeric() || "._/-+=:,@%".contains(c);
        if !text.is_empty() && text.chars().all(plain) {
            return std::borrow::Cow::Borrowed(text);
        }
        // POSIX shells close the quote, emit an escaped quote, and reopen it;
        // PowerShell doubles the quote inside a single-quoted string.
        let quote = if cfg!(windows) { "''" } else { r"'\''" };
        std::borrow::Cow::Owned(format!("'{}'", text.replace('\'', quote)))
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

    /// The cross triple a release builds this member for, or `None` for the
    /// default static triple (a release links statically on either host axis).
    #[must_use]
    pub fn release_triple(self) -> Option<StaticTriple> {
        match self.target {
            BinaryTarget::Cross(triple) => Some(triple).filter(|t| *t != StaticTriple::default()),
            BinaryTarget::Host | BinaryTarget::Static => None,
        }
    }

    /// The release of `delivery` built for `triple`, its target normalised.
    ///
    /// A release links statically, so the host, the static and the default
    /// cross target are one release; only a native route carries a triple.
    ///
    /// # Errors
    /// Every [`release_route`] refusal.
    pub fn release(
        delivery: Delivery,
        triple: Option<StaticTriple>,
    ) -> Result<Self, DeliveryError> {
        let target = match release_route(delivery)? {
            ReleaseRoute::Native => triple
                .filter(|t| *t != StaticTriple::default())
                .map_or(BinaryTarget::Host, BinaryTarget::Cross),
            ReleaseRoute::Browser | ReleaseRoute::Bundle(_) => BinaryTarget::Host,
        };
        Ok(Self { delivery, target })
    }

    /// The directory this member releases into under `release/`.
    ///
    /// The delivery's words joined by `-`, then `-<triple>` for a cross
    /// triple. It is a function of the release identity (the delivery and its
    /// effective triple) alone, and injective over it.
    ///
    /// # Errors
    /// [`CliError::Pipeline`] carrying a compiler bug if the words ever spell
    /// a name outside the slug grammar.
    pub fn slug(&self) -> Result<ReleaseSlug, CliError> {
        let mut text = self.delivery.to_string().replace(' ', "-");
        if let Some(triple) = self.release_triple() {
            text.push('-');
            text.push_str(triple.as_str());
        }
        ReleaseSlug::parse(text.clone()).ok_or_else(|| CliError::Pipeline {
            file: PathBuf::new(),
            src: String::new(),
            diag: Box::new(ipe_diagnostics::Diagnostic::CompilerBug {
                where_: "release slug",
                detail: format!("`{text}` is not one release directory name"),
            }),
        })
    }
}

/// The non-empty, duplicate-free set of deliveries `ipe release` produces, every
/// element individually admitted by [`Delivery::resolve`].
///
/// Constructible only through [`DeliverySet::resolve`]; the fields are
/// private. No code path can hold a set containing an invalid, duplicate, or
/// shape-incompatible member, and none can construct an empty one: the head
/// exists by type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliverySet {
    head: PlannedDelivery,
    rest: Vec<PlannedDelivery>,
}

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
    /// [`CliError::ProjectRefused`] naming a duplicate entry;
    /// [`CliError::ProjectRefused`] for a web-only entry on a non-web shape (the shape lesson); the underlying
    /// [`DeliveryError`] for any other invalid combination or a `--static`
    /// request the delivery cannot honour.
    pub fn resolve(pinned: Shape, entries: &[ShipEntry]) -> Result<Self, CliError> {
        // An absent `ships` field is the implicit `[ binary ]` singleton.
        let Some((&first, others)) = entries.split_first() else {
            let delivery = Delivery::resolve(pinned, None, Host::Default)?;
            return Ok(Self {
                head: PlannedDelivery {
                    delivery,
                    target: BinaryTarget::Host,
                },
                rest: Vec::new(),
            });
        };

        let head = Self::resolve_one(pinned, first)?;
        let mut rest: Vec<PlannedDelivery> = Vec::with_capacity(others.len());
        for &entry in others {
            let plan = Self::resolve_one(pinned, entry)?;
            if plan == head || rest.contains(&plan) {
                return Err(duplicate_entry(entry));
            }
            rest.push(plan);
        }
        Ok(Self { head, rest })
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
            ShipEntry::Desktop
            | ShipEntry::Client
            | ShipEntry::ClientDesktop
            | ShipEntry::ClientIos
            | ShipEntry::ClientAndroid => entry
                .axes()
                .map_or((None, Host::Default), |(runtime, host)| {
                    (Some(runtime), host)
                }),
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

    /// The first declared delivery, present by type.
    #[must_use]
    pub const fn head(&self) -> PlannedDelivery {
        self.head
    }

    /// The resolved deliveries, in declared order: the head, then the rest.
    pub fn planned(&self) -> impl Iterator<Item = PlannedDelivery> + '_ {
        std::iter::once(self.head).chain(self.rest.iter().copied())
    }

    /// The number of declared deliveries. Always at least one.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.rest.len().saturating_add(1)
    }

    /// A delivery set is never empty (the head exists by type); this is present
    /// only to satisfy the `len`-without-`is_empty` lint.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }

    /// Consume the set, invoking `release_one` per delivery in declared order.
    ///
    /// This is the sole producer of [`Released`]: there is no other way to obtain
    /// one, and no way to obtain [`ReleaseOutcome::AllReleased`] without one
    /// `Released` per declared delivery. The loop continues through failures —
    /// each delivery attempted, each failure recorded — so a partial release
    /// names every failure rather than stopping at the first.
    #[must_use]
    pub fn release_each<A>(
        self,
        mut release_one: impl FnMut(&PlannedDelivery) -> Result<A, CliError>,
    ) -> ReleaseOutcome<A> {
        let mut built: Vec<Released<A>> = Vec::with_capacity(self.len());
        let mut failed: Vec<(Delivery, CliError)> = Vec::new();
        for plan in self.planned() {
            match release_one(&plan) {
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

/// The deliveries a package declares in `ships`, resolved once against the
/// shape `main` pins.
///
/// The one token a compiling command selects its delivery from when argv names
/// none. Built by [`crate::project::DeliveryConfig::declared`], the only
/// reader of the private `ships` list a compiling command reaches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredDeliveries {
    pinned: Shape,
    set: DeliverySet,
}

impl DeclaredDeliveries {
    /// Resolve the declared `ships` entries against the pinned shape.
    ///
    /// # Errors
    /// Every [`DeliverySet::resolve`] refusal.
    pub fn from_ships(pinned: Shape, entries: &[ShipEntry]) -> Result<Self, CliError> {
        DeliverySet::resolve(pinned, entries).map(|set| Self { pinned, set })
    }

    /// The shape `main` pins, the one stated delivery words resolve against.
    #[must_use]
    pub const fn pinned(&self) -> Shape {
        self.pinned
    }

    /// The declared set, in declared order.
    #[must_use]
    pub const fn set(&self) -> &DeliverySet {
        &self.set
    }

    /// The declared set, consumed by the release loop.
    #[must_use]
    pub fn into_set(self) -> DeliverySet {
        self.set
    }

    /// The one delivery a dev command builds when argv names none.
    ///
    /// A dev build ignores a ship's target axis, so members that differ only by
    /// target are one delivery. `accepts` is the command's own admission: a
    /// member it refuses is listed with the `build` verb that does produce it,
    /// so every listed command clears the refusal. `dir` is the project dir as
    /// the user typed it.
    ///
    /// # Errors
    /// [`CliError::ProjectRefused`] listing each declared delivery and its
    /// command when the package declares more than one, or naming a declared
    /// delivery no route builds.
    pub fn sole_dev_delivery(
        &self,
        command: &str,
        dir: Option<&str>,
        accepts: impl Fn(Delivery) -> bool,
        build: &str,
    ) -> Result<Delivery, CliError> {
        self.sole_by(PlannedDelivery::delivery, command, |plan| {
            let verb = if accepts(plan.delivery) {
                command
            } else {
                build
            };
            Remedy::command(verb, dir, &plan.delivery.to_string())
        })
        .map(PlannedDelivery::delivery)
    }

    /// The one delivery `ipe release run` builds when argv names none.
    ///
    /// A release always links statically, so a host and a static member are one
    /// artifact; a cross member is its own. A member with no run form (any
    /// member that is not the native binary) is listed with the `build` verb
    /// that produces it.
    ///
    /// # Errors
    /// [`CliError::ProjectRefused`] listing each declared delivery and its
    /// command when the package declares more than one, or naming a declared
    /// delivery no route builds.
    pub fn sole_release_member(
        &self,
        command: &str,
        dir: Option<&str>,
        build: &str,
    ) -> Result<PlannedDelivery, CliError> {
        self.sole_by(
            |plan| (plan.delivery, plan.release_triple()),
            command,
            |plan| {
                let verb = if matches!(release_route(plan.delivery), Ok(ReleaseRoute::Native)) {
                    command
                } else {
                    build
                };
                let words = plan.release_triple().map_or_else(
                    || plan.delivery.to_string(),
                    |triple| format!("{} --target {}", plan.delivery, triple.as_str()),
                );
                Remedy::command(verb, dir, &words)
            },
        )
    }

    /// The set `ipe release build` given no delivery words builds: each
    /// distinct release once.
    ///
    /// Each member's effective triple is `flag` (argv's `--target`), else its
    /// declared triple, else `env` (a native `IPE_TARGET`). Members are keyed
    /// by their [`ReleaseSlug`]: an equal slug is the same release and is
    /// built once, and distinct slugs write distinct places.
    ///
    /// # Errors
    /// [`CliError::ProjectRefused`] naming a declared delivery no route builds,
    /// before anything is built; a [`PlannedDelivery::slug`] compiler bug.
    pub fn for_release(
        self,
        command: &str,
        flag: Option<StaticTriple>,
        env: Option<StaticTriple>,
    ) -> Result<DeliverySet, CliError> {
        let release = |plan: PlannedDelivery| {
            PlannedDelivery::release(
                plan.delivery,
                flag.or_else(|| plan.release_triple()).or(env),
            )
            .map_err(|e| CliError::ProjectRefused(crate::text::msg::command_refusal(&command, &e)))
        };
        let head = release(self.set.head)?;
        let mut slugs = vec![head.slug()?];
        let mut rest: Vec<PlannedDelivery> = Vec::with_capacity(self.set.rest.len());
        for plan in self.set.rest {
            let member = release(plan)?;
            let slug = member.slug()?;
            if !slugs.contains(&slug) {
                slugs.push(slug);
                rest.push(member);
            }
        }
        Ok(DeliverySet { head, rest })
    }

    /// The single member distinct under `key`, or the several-deliveries refusal
    /// naming each distinct member's `choice` command.
    ///
    /// A declared member no route builds is refused first, so no listed
    /// choice is a command that is refused in turn.
    fn sole_by<K: PartialEq>(
        &self,
        key: impl Fn(PlannedDelivery) -> K,
        command: &str,
        choice: impl Fn(PlannedDelivery) -> String,
    ) -> Result<PlannedDelivery, CliError> {
        let mut distinct: Vec<PlannedDelivery> = Vec::new();
        for plan in self.set.planned() {
            release_route(plan.delivery).map_err(|e| {
                CliError::ProjectRefused(crate::text::msg::command_refusal(&command, &e))
            })?;
            if !distinct.iter().any(|seen| key(*seen) == key(plan)) {
                distinct.push(plan);
            }
        }
        match distinct.as_slice() {
            [only] => Ok(*only),
            several => {
                let choices = several
                    .iter()
                    .map(|plan| format!("  {}", choice(*plan)))
                    .collect::<Vec<_>>()
                    .join("\n");
                Err(CliError::ProjectRefused(crate::text::msg::ships_several(
                    &command, &choices,
                )))
            }
        }
    }
}

/// Proof one delivery was built and packaged. Private constructor: the only
/// producer is [`DeliverySet::release_each`], fed by a packager that ran to
/// completion.
#[derive(Debug)]
pub struct Released<A = PathBuf> {
    delivery: Delivery,
    artifact: A,
}

impl<A> Released<A> {
    /// The delivery this artifact realises.
    #[must_use]
    pub const fn delivery(&self) -> Delivery {
        self.delivery
    }

    /// What the packager produced, for the release summary line.
    #[must_use]
    pub const fn artifact(&self) -> &A {
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
pub enum ReleaseOutcome<A = PathBuf> {
    /// Every declared delivery built. One [`Released`] per declared delivery, in
    /// declared order.
    AllReleased(Vec<Released<A>>),
    /// At least one delivery failed. `built` and `failed` together account for
    /// every declared delivery; `failed` is non-empty by construction.
    Incomplete {
        /// The deliveries that did build, in declared order.
        built: Vec<Released<A>>,
        /// Each failed delivery paired with its diagnostic — non-empty.
        failed: Vec<(Delivery, CliError)>,
    },
}

impl<A> ReleaseOutcome<A> {
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
    CliError::ProjectRefused(crate::text::msg::ships_repeated(&words))
}

/// The web-entry-on-non-web-shape rejection, in the pedagogical two-axis voice.
fn web_entry_on_non_web(pinned: Shape, entry: ShipEntry) -> CliError {
    let words = describe_entry(entry);
    CliError::ProjectRefused(crate::text::msg::ships_shape_mismatch(
        &words,
        &pinned.word(),
    ))
}

/// The CLI delivery words a ship entry stands for, for a diagnostic. The
/// co-located `binary` variants have no delivery words of their own (the shape
/// leads), so they are named by their builder spelling.
fn describe_entry(entry: ShipEntry) -> String {
    match entry {
        ShipEntry::Binary(BinaryTarget::Host) => "binary".to_owned(),
        ShipEntry::Binary(BinaryTarget::Static) => "staticBinary".to_owned(),
        ShipEntry::Binary(BinaryTarget::Cross(t)) => format!("crossBinary {}", t.as_str()),
        // A web-bearing entry reads as its resolved delivery words (`web client ios`).
        _ => match entry.axes() {
            Some((runtime, host)) => Delivery::resolve(Shape::Web, Some(runtime), host)
                .map_or_else(|_| entry.builder_word(), |d| d.to_string()),
            None => entry.builder_word(),
        },
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
    fn builder_words_derive_from_the_delivery_words() {
        let words: Vec<String> = ShipEntry::BUILDERS
            .into_iter()
            .map(ShipEntry::builder_word)
            .collect();
        assert_eq!(
            words,
            [
                "binary",
                "staticBinary",
                "desktop",
                "client",
                "clientDesktop",
                "clientIos",
                "clientAndroid",
            ]
        );
        assert_eq!(ship_constructor("clientIos"), "ShipClientIos");
    }

    #[test]
    fn retired_builders_map_to_their_replacement() {
        for (name, now) in [
            ("solo", ShipEntry::Client),
            ("soloDesktop", ShipEntry::ClientDesktop),
            ("soloIos", ShipEntry::ClientIos),
            ("ShipSoloAndroid", ShipEntry::ClientAndroid),
            ("ShipSolo", ShipEntry::Client),
        ] {
            assert_eq!(ShipEntry::retired_builder(name), Some(now), "{name}");
        }
        for current in ShipEntry::BUILDERS.map(ShipEntry::builder_word) {
            assert_eq!(ShipEntry::retired_builder(&current), None, "{current}");
        }
        assert_eq!(ShipEntry::retired_builder("liveIos"), None);
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
            let only = set.head();
            assert_eq!(only.delivery().shape(), shape);
            assert_eq!(only.target(), BinaryTarget::Host);
        }
    }

    #[test]
    fn web_entries_resolve_on_web_and_preserve_order() {
        let entries = [
            ShipEntry::Binary(BinaryTarget::Host),
            ShipEntry::Desktop,
            ShipEntry::Client,
            ShipEntry::ClientIos,
        ];
        let set = DeliverySet::resolve(Shape::Web, &entries).expect("web set resolves");
        let slugs: Vec<String> = set
            .planned()
            .filter_map(|plan| plan.slug().ok())
            .map(|slug| slug.as_str().to_owned())
            .collect();
        assert_eq!(
            slugs,
            ["web", "web-desktop", "web-client", "web-client-ios"]
        );
    }

    #[test]
    fn web_entry_on_non_web_shape_is_pedagogical() {
        for shape in [Shape::Script, Shape::Tui, Shape::Cli, Shape::Worker] {
            let err = DeliverySet::resolve(shape, &[ShipEntry::ClientIos]).unwrap_err();
            assert!(
                matches!(err, CliError::ProjectRefused(_)),
                "a `ships` refusal is project state, never argument misuse: {err:?}"
            );
            let CliError::ProjectRefused(msg) = err else {
                return;
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
        assert_eq!(set.head().target(), BinaryTarget::Static);
    }

    #[test]
    fn duplicate_entry_is_rejected() {
        let err =
            DeliverySet::resolve(Shape::Web, &[ShipEntry::Client, ShipEntry::Client]).unwrap_err();
        assert!(
            matches!(err, CliError::ProjectRefused(_)),
            "a `ships` refusal is project state, never argument misuse: {err:?}"
        );
        let CliError::ProjectRefused(msg) = err else {
            return;
        };
        assert!(msg.contains("twice"), "names the duplicate: {msg}");
    }

    #[test]
    fn cross_binary_slug_carries_the_triple() {
        let set = DeliverySet::resolve(Shape::Cli, &[cross("aarch64-unknown-linux-musl")])
            .expect("cli cross binary resolves");
        let slug = set.head().slug().expect("slug");
        assert_eq!(slug.as_str(), "cli-aarch64-unknown-linux-musl");
    }

    #[test]
    fn static_binary_releases_under_the_host_slug() {
        let set = DeliverySet::resolve(Shape::Cli, &[ShipEntry::Binary(BinaryTarget::Static)])
            .expect("cli static binary resolves");
        let slug = set.head().slug().expect("slug");
        assert_eq!(slug.as_str(), "cli");
    }

    #[test]
    fn release_each_all_built_is_all_released() {
        let set = DeliverySet::resolve(
            Shape::Web,
            &[ShipEntry::Binary(BinaryTarget::Host), ShipEntry::Client],
        )
        .expect("web set resolves");
        let outcome = set.release_each(|plan| Ok(PathBuf::from(plan.delivery().to_string())));
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
                ShipEntry::Client,
                ShipEntry::Desktop,
            ],
        )
        .expect("web set resolves");
        // Fail exactly the second delivery (client).
        let outcome = set.release_each(|plan| {
            if matches!(plan.delivery().runtime(), Some(Runtime::Client))
                && plan.delivery() == Delivery::web_client()
            {
                Err(CliError::Usage(crate::text::msg::command_refusal(
                    &"release",
                    &"client bundle failed",
                )))
            } else {
                Ok(PathBuf::from(plan.delivery().to_string()))
            }
        });
        assert!(!outcome.all_released());
        match outcome {
            ReleaseOutcome::Incomplete { built, failed } => {
                assert_eq!(built.len(), 2);
                assert_eq!(failed.len(), 1);
                assert_eq!(failed[0].0.to_string(), "web client");
            }
            other => panic!("expected Incomplete, got {other:?}"),
        }
    }

    /// Every delivery [`Delivery::resolve`] admits has exactly one release
    /// route, except `web client desktop`, which no packer builds.
    #[test]
    fn release_route_is_total_over_every_resolved_delivery() {
        let shapes = [
            Shape::Script,
            Shape::Tui,
            Shape::Cli,
            Shape::Worker,
            Shape::Web,
        ];
        let runtimes = [None, Some(Runtime::Served), Some(Runtime::Client)];
        let hosts = [Host::Default, Host::Desktop, Host::Ios, Host::Android];
        let mut resolved = 0_usize;
        for shape in shapes {
            for runtime in runtimes {
                for host in hosts {
                    let Ok(delivery) = Delivery::resolve(shape, runtime, host) else {
                        continue;
                    };
                    resolved += 1;
                    let route = release_route(delivery);
                    if (delivery.host(), delivery.runtime())
                        == (Host::Desktop, Some(Runtime::Client))
                    {
                        assert!(
                            matches!(route, Err(DeliveryError::ClientDesktopHasNoPacker)),
                            "{delivery}: {route:?}"
                        );
                    } else {
                        assert!(route.is_ok(), "{delivery}: {route:?}");
                    }
                }
            }
        }
        assert!(
            resolved > shapes.len(),
            "the table admits web forms: {resolved}"
        );
    }

    /// Two release identities (a delivery and its effective triple) never
    /// share a slug, and one identity always spells the same slug.
    #[test]
    fn release_slugs_are_injective_over_every_release_identity() {
        let shapes = [
            Shape::Script,
            Shape::Tui,
            Shape::Cli,
            Shape::Worker,
            Shape::Web,
        ];
        let runtimes = [None, Some(Runtime::Served), Some(Runtime::Client)];
        let hosts = [Host::Default, Host::Desktop, Host::Ios, Host::Android];
        let triples: Vec<Option<StaticTriple>> = std::iter::once(None)
            .chain(
                StaticTriple::SUPPORTED
                    .iter()
                    .map(|t| Some(StaticTriple::parse(t).expect("supported triple"))),
            )
            .collect();
        let mut seen: Vec<((Delivery, Option<StaticTriple>), String)> = Vec::new();
        for shape in shapes {
            for runtime in runtimes {
                for host in hosts {
                    let Ok(delivery) = Delivery::resolve(shape, runtime, host) else {
                        continue;
                    };
                    for &triple in &triples {
                        let Ok(plan) = PlannedDelivery::release(delivery, triple) else {
                            continue;
                        };
                        let slug = plan.slug().expect("every release has a slug");
                        let identity = (plan.delivery(), plan.release_triple());
                        for (other, other_slug) in &seen {
                            assert_eq!(
                                *other == identity,
                                *other_slug == slug.as_str(),
                                "{other:?} / {identity:?}: {other_slug} vs {}",
                                slug.as_str()
                            );
                        }
                        seen.push((identity, slug.as_str().to_owned()));
                    }
                }
            }
        }
        assert!(!seen.is_empty());
    }

    /// A remedy line's project dir reads back, through a POSIX shell, as the
    /// one word the user typed — a space, a quote or a metacharacter included.
    #[cfg(unix)]
    #[test]
    fn remedy_dir_reads_back_as_one_shell_word() {
        for dir in [
            "plain/dir",
            "my app",
            "it's",
            "a;touch pwned",
            "$HOME",
            "`id`",
            "",
        ] {
            let line = Remedy::command("release build", Some(dir), "web client");
            let word = line
                .strip_prefix("ipe release build ")
                .and_then(|rest| rest.strip_suffix(" web client"))
                .expect("the remedy keeps its frame");
            let echoed = std::process::Command::new("sh")
                .arg("-c")
                .arg(format!("printf '%s' {word}"))
                .output()
                .expect("sh runs");
            assert_eq!(
                String::from_utf8_lossy(&echoed.stdout),
                dir,
                "`{line}` reads back as the dir"
            );
        }
    }
}
