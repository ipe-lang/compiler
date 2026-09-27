//! The `ipe rust add` / `ipe rust install` / `ipe rust remove` commands and the
//! build-time FFI seam: interface-module injection + backend emission-input
//! assembly.
//!
//! `ipe rust add <crate>` runs the `ipe-ffi-inspector` inside the `ipe_sandbox`
//! bubblewrap jail (fetch posture: network on, everything else confined),
//! decodes the inspection, and writes the six cache artifacts under
//! `<project>/.ipe/cache/ffi/rust/`. At build time the driver loads that
//! cache, injects one `Rust.<Crate>` interface module per installed crate
//! (origin [`ipe_canon::ModuleOrigin::FfiInterface`] — unforgeable), and
//! hands the backend its [`ipe_backend_rust::FfiEmit`] inputs.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use ipe_ffi::driver::{CrateName, CrateSpec, FfiCache, InstalledCrate, VersionPin};
use ipe_ffi::pkginfo::FeatureName;

use crate::CliError;
use crate::text;

/// The FFI cache directory under `dir`, the same path the FFI driver writes.
fn cache_dir_under(dir: &Path) -> PathBuf {
    FfiCache::at_project_root(dir).root().to_path_buf()
}

/// The project manifest that bounds the upward cache-discovery walk.
const PROJECT_MANIFEST: &str = "package.ipe";

/// The legacy TOML manifest name the `ipe rust install` text inspector reads
/// for `[rust.dependencies]` / `[rust.wrapper]`, pending the ergonomic Rust-FFI
/// work that lifts those bindings out of a `package.ipe`.
const PROJECT_MANIFEST_TOML: &str = "ipe.toml";

/// The invoking user's real uid, read from the owner of `/proc/self` (no FFI
/// dependency). `u32::MAX` on failure — a sentinel no real cache dir matches,
/// so a failed read refuses rather than accepts.
#[cfg(unix)]
fn current_uid() -> u32 {
    use std::os::unix::fs::MetadataExt as _;
    std::fs::metadata("/proc/self").map_or(u32::MAX, |m| m.uid())
}

/// Whether a path is owned by the current uid and not world-writable — an FFI
/// cache anyone can write is a code-injection delivery vector (its
/// `_bindings.rs` compiles unsandboxed into the crate), so it is refused
/// rather than loaded. Group-writability is not rejected: a default umask of
/// `0o002` makes user-created dirs group-writable under the user's own private
/// group, and rejecting that would refuse every legitimately-installed cache;
/// the load-time re-derivation gate is the primary barrier, this narrows the
/// discovery surface.
#[cfg(unix)]
fn is_trusted_cache_dir(dir: &Path) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    std::fs::metadata(dir).is_ok_and(|md| md.uid() == current_uid() && md.mode() & 0o002 == 0)
}

#[cfg(not(unix))]
fn is_trusted_cache_dir(_dir: &Path) -> bool {
    true
}

/// Walk up from `start` looking for an FFI artifact cache, bounded at the
/// nearest `package.ipe` project root.
///
/// Never walks above the nearest `package.ipe`, so a planted ancestor cache
/// outside the project cannot be discovered. A found cache not owned by the
/// invoking uid (or group/other-writable) is REFUSED, not loaded, since its
/// `_bindings.rs` compiles unsandboxed into the crate.
///
/// # Errors
///
/// [`CliError::UsageOwned`] when a discovered cache fails the ownership check.
pub fn find_cache_root(start: &Path) -> Result<Option<PathBuf>, CliError> {
    let mut dir = if start.is_dir() {
        Some(start)
    } else {
        start.parent()
    };
    while let Some(d) = dir {
        let candidate = cache_dir_under(d);
        if candidate.is_dir() {
            if is_trusted_cache_dir(&candidate) {
                return Ok(Some(candidate));
            }
            return Err(CliError::UsageOwned(text::ffi_cache_untrusted(
                &candidate.display(),
            )));
        }
        // Stop at the project root: do not walk above the nearest package.ipe.
        if d.join(PROJECT_MANIFEST).is_file() {
            return Ok(None);
        }
        dir = d.parent();
    }
    Ok(None)
}

/// Load the installed-crate catalog for a build rooted at (or blamed on)
/// `blame_path`. Absent cache ⇒ empty catalog.
///
/// # Errors
/// [`CliError::Pipeline`] wrapping the catalog loader's diagnostic (a
/// tampered or half-written cache is refused, never silently skipped).
pub fn load_catalog_for(blame_path: &Path) -> Result<Vec<InstalledCrate>, CliError> {
    let Some(cache_root) = find_cache_root(blame_path)? else {
        return Ok(Vec::new());
    };
    ipe_ffi::driver::load_catalog(&cache_root)
        .map_err(|diag| CliError::UsageOwned(diag.to_string()))
}

/// Inject each installed crate's interface module into the build's source
/// map, returning the set of injected module paths (they earn
/// [`ipe_canon::ModuleOrigin::FfiInterface`] at input creation).
///
/// # Errors
/// [`CliError::UsageOwned`] when a project module already claims an
/// installed crate's `Rust.*` module path.
pub fn inject_interfaces(
    sources: &mut BTreeMap<Vec<String>, (PathBuf, String)>,
    catalog: &[InstalledCrate],
    cache_root_hint: &Path,
) -> Result<BTreeSet<Vec<String>>, CliError> {
    let mut injected = BTreeSet::new();
    for c in catalog {
        let mod_path: Vec<String> = c.module_name.split('.').map(str::to_owned).collect();
        if sources.contains_key(&mod_path) {
            return Err(CliError::UsageOwned(text::ffi_module_clash(
                &c.module_name,
                &c.slug,
            )));
        }
        let pseudo_path = cache_root_hint.join(format!("{}.ipe", c.slug));
        sources.insert(mod_path.clone(), (pseudo_path, c.interface_source.clone()));
        injected.insert(mod_path);
    }
    Ok(injected)
}

/// Assemble the backend emission inputs from the catalog: the merged
/// module-qualified opaque-type map, the de-duplicated pinned dep lines, and
/// the combined `src/ffi.rs` (one `pub mod <slug>` per crate).
///
/// # Errors
/// [`CliError::UsageOwned`] when two installed crates pin the SAME
/// dependency name to different lines — an unbuildable `Cargo.toml` refused
/// here rather than discovered by `cargo`.
pub fn assemble_emit(
    catalog: &[InstalledCrate],
) -> Result<Option<ipe_backend_rust::FfiEmit>, CliError> {
    use std::fmt::Write as _;
    if catalog.is_empty() {
        return Ok(None);
    }
    let mut foreign_types: BTreeMap<String, String> = BTreeMap::new();
    let mut wrapper_glue: BTreeMap<String, ipe_backend_rust::FfiWrapperGlue> = BTreeMap::new();
    // The DIRECT FFI crates (registry names, `_`→`-` as the dep line renders them):
    // these are the crates the app links against and MUST be pinned exactly; a
    // version conflict on one of these is a genuine, unbuildable error.
    let direct_crate_names: BTreeSet<String> =
        catalog.iter().map(|c| c.slug.replace('_', "-")).collect();
    // name → (version, unioned feature set). Cargo unifies features additively for
    // one crate+version across the graph, so a multi-crate manifest whose members
    // pin the SAME dependency (`async-stripe-shared`) at the SAME version but with
    // DIFFERENT feature requests (bare from one, `serialize`/`deserialize` from
    // another) is not a conflict — it is a union. A VERSION disagreement on a DIRECT
    // FFI crate is a genuine conflict (refused); a version disagreement on a
    // TRANSITIVE dep (e.g. `syn` 2.x from one member, 3.x from another — each member
    // was inspected in its own jail with its own lockfile) is NOT ours to pin: Cargo
    // resolves the transitive graph of the direct pins itself and legitimately links
    // both majors of a build-dep. Such a dep is dropped from the emitted `[dependencies]`
    // (recorded as unpinned) rather than exact-pinned to one arbitrary version.
    let mut dep_by_name: BTreeMap<String, (String, BTreeSet<String>)> = BTreeMap::new();
    let mut unpinned_transitives: BTreeSet<String> = BTreeSet::new();
    let mut bindings_source = String::from(
        "//! Foreign-crate FFI wrappers — one module per installed crate.\n\
         //! Generated from the project's `.ipe/cache/ffi/rust` artifacts.\n",
    );
    for c in catalog {
        for (name, path) in &c.opaque_types {
            foreign_types.insert(format!("{}.{name}", c.module_name), path.clone());
        }
        assemble_wrapper_glue(c, &mut wrapper_glue)?;
        // A `[rust.define.struct/enum]` type is DEFINED in the emitted
        // `_bindings.rs` (wrapped `pub mod <slug> { … } pub use <slug>::*;` in
        // `src/ffi.rs`), so it resolves at the crate-absolute path
        // `crate::ffi::<slug>::<Name>` — never an external `::crate::Path`, and
        // never the bare `<Name>` glob (the `pub use` re-exports inside
        // `src/ffi.rs`, but the backend renders the foreign-type path into the
        // app's MAIN module tree, where only a crate-absolute path resolves).
        for name in &c.define_types {
            let key = format!("{}.{name}", c.module_name);
            // A define type sharing a name with an inspected opaque of the same
            // crate would silently overwrite the other's path (a wrong Rust type
            // the SEAL would then compile against). Fail closed — the author must
            // rename one; the two nominals are genuinely different Rust types.
            if foreign_types.contains_key(&key) {
                return Err(CliError::UsageOwned(text::ffi_define_opaque_collision(
                    &c.slug, &name,
                )));
            }
            foreign_types.insert(key, format!("crate::ffi::{}::{name}", c.slug));
        }
        for line in &c.cargo_deps {
            let Some((name, version, features)) = parse_dep_line(line) else {
                return Err(CliError::UsageOwned(text::ffi_dependency_line_unparsable(
                    &c.slug, &line,
                )));
            };
            if unpinned_transitives.contains(&name) {
                continue;
            }
            match dep_by_name.get_mut(&name) {
                Some((prev_version, _)) if *prev_version != version => {
                    if direct_crate_names.contains(&name) {
                        return Err(CliError::UsageOwned(text::ffi_dependency_pin_conflict(
                            &name,
                            &prev_version,
                            &version,
                        )));
                    }
                    // Transitive dep resolved to different versions in different member
                    // jails — defer to Cargo's own transitive resolution.
                    dep_by_name.remove(&name);
                    unpinned_transitives.insert(name);
                }
                Some((_, prev_features)) => {
                    prev_features.extend(features);
                }
                None => {
                    dep_by_name.insert(name, (version, features));
                }
            }
        }
        // Writing into a String is infallible.
        let _ = write!(
            bindings_source,
            "\npub mod {slug} {{\n{body}}}\npub use {slug}::*;\n",
            slug = c.slug,
            body = c.bindings_source
        );
    }
    let dep_lines: Vec<String> = dep_by_name
        .into_iter()
        .map(|(name, (version, features))| render_merged_dep_line(&name, &version, &features))
        .collect();
    Ok(Some(ipe_backend_rust::FfiEmit {
        foreign_types,
        dep_lines,
        bindings_source,
        interface_modules: catalog.iter().map(|c| c.module_name.clone()).collect(),
        wrapper_glue,
    }))
}

/// Assemble one crate's per-wrapper transparent conversion glue from the
/// interface's structured positions + the crate's transparent shapes.
///
/// A referenced shape missing from the catalog is an internal invariant
/// violation (the interface derived both), refused rather than emitted as a
/// seam whose two sides disagree.
///
/// # Errors
/// [`CliError::UsageOwned`] naming the crate, binding, and missing shape.
fn assemble_wrapper_glue(
    c: &InstalledCrate,
    wrapper_glue: &mut BTreeMap<String, ipe_backend_rust::FfiWrapperGlue>,
) -> Result<(), CliError> {
    for b in &c.bindings {
        if b.transparent_params.iter().all(Option::is_none) && b.transparent_result.is_none() {
            continue;
        }
        let glue_ty = |name: &str| -> Result<ipe_backend_rust::FfiGlueType, CliError> {
            let t = c.transparent_types.get(name).ok_or_else(|| {
                CliError::UsageOwned(text::ffi_transparent_without_shape(
                    &c.slug,
                    &name,
                    &b.ref_name,
                ))
            })?;
            Ok(glue_type_of(&c.module_name, &c.slug, t))
        };
        let mut params = Vec::with_capacity(b.transparent_params.len());
        for p in &b.transparent_params {
            params.push(match p {
                None => None,
                Some(name) => Some(glue_ty(name)?),
            });
        }
        let result = match &b.transparent_result {
            None => None,
            Some(r) => Some(ipe_backend_rust::FfiResultGlue {
                in_result: r.in_result,
                ty: glue_ty(&r.type_name)?,
            }),
        };
        wrapper_glue.insert(
            b.wrapper_ident.clone(),
            ipe_backend_rust::FfiWrapperGlue { params, result },
        );
    }
    Ok(())
}

/// One transparent shape in the backend's glue vocabulary. An imported crate
/// type's path absolutizes with a leading `::` (the wrapper spelling); a
/// define-defined type carries the BARE nominal (the define convention — the
/// import classification refuses bare paths) and resolves crate-locally at
/// `crate::ffi::<slug>::<Name>`, where its `_bindings.rs` definition lives.
/// The union's app-side identity is the interface module + nominal, resolved
/// by the backend against the enum the lowerer emitted.
fn glue_type_of(
    module_name: &str,
    slug: &str,
    t: &ipe_ffi::transparency::TransparentType,
) -> ipe_backend_rust::FfiGlueType {
    use ipe_ffi::transparency::{ForeignVariantPayload, TransparentType};
    let absolutize = |p: &str| -> String {
        if p.contains("::") {
            format!("::{}", p.trim_start_matches(':'))
        } else {
            format!("crate::ffi::{slug}::{p}")
        }
    };
    match t {
        TransparentType::Struct {
            rust_path, fields, ..
        } => ipe_backend_rust::FfiGlueType::Record {
            rust_path: absolutize(rust_path.as_str()),
            fields: fields.iter().map(|f| f.name.as_str().to_owned()).collect(),
        },
        TransparentType::Enum {
            name,
            rust_path,
            variants,
        } => ipe_backend_rust::FfiGlueType::Union {
            module: module_name.split('.').map(str::to_owned).collect(),
            name: name.as_str().to_owned(),
            rust_path: absolutize(rust_path.as_str()),
            variants: variants
                .iter()
                .map(|v| ipe_backend_rust::FfiGlueVariant {
                    name: v.name.as_str().to_owned(),
                    payload: match &v.payload {
                        ForeignVariantPayload::Unit => ipe_backend_rust::FfiGluePayload::Unit,
                        ForeignVariantPayload::Tuple(cs) => {
                            ipe_backend_rust::FfiGluePayload::Tuple(cs.len())
                        }
                        ForeignVariantPayload::Struct(ms) => {
                            ipe_backend_rust::FfiGluePayload::Struct(
                                ms.iter().map(|m| m.name.as_str().to_owned()).collect(),
                            )
                        }
                    },
                })
                .collect(),
        },
    }
}

/// Parse a generated dep line into `(name, version, features)`. Two shapes are
/// produced by `cargo_dep_lines`:
///   `name = "=X.Y.Z"`
///   `name = { version = "=X.Y.Z", features = ["a", "b"] }`
/// The version is returned WITHOUT the leading `=`. Returns `None` if neither
/// shape matches (a malformed line the caller refuses).
fn parse_dep_line(line: &str) -> Option<(String, String, BTreeSet<String>)> {
    let (name, rest) = line.split_once('=')?;
    let name = name.trim().to_owned();
    let rest = rest.trim();
    if let Some(inner) = rest.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
        // Inline table: pull `version = "=X"` and `features = [...]`.
        let version = extract_quoted_after(inner, "version")?
            .trim_start_matches('=')
            .to_owned();
        let features = inner
            .split_once("features")
            .and_then(|(_, after)| after.split_once('['))
            .and_then(|(_, list)| list.split_once(']'))
            .map(|(list, _)| {
                list.split(',')
                    .map(|f| f.trim().trim_matches('"').to_owned())
                    .filter(|f| !f.is_empty())
                    .collect::<BTreeSet<String>>()
            })
            .unwrap_or_default();
        Some((name, version, features))
    } else {
        // Bare: `"=X.Y.Z"`.
        let version = rest
            .trim()
            .trim_matches('"')
            .trim_start_matches('=')
            .to_owned();
        if version.is_empty() {
            return None;
        }
        Some((name, version, BTreeSet::new()))
    }
}

/// Extract the first double-quoted string that follows `key` in `s`
/// (`key = "value"` → `Some("value")`).
fn extract_quoted_after(s: &str, key: &str) -> Option<String> {
    let after = s.split_once(key)?.1;
    let after = after.split_once('"')?.1;
    let (value, _) = after.split_once('"')?;
    Some(value.to_owned())
}

/// Render the merged dep line, matching `render_dep_line`'s two shapes so the
/// emitted `Cargo.toml` is byte-identical to the single-crate case when there
/// are no extra features.
fn render_merged_dep_line(name: &str, version: &str, features: &BTreeSet<String>) -> String {
    if features.is_empty() {
        format!("{name} = \"={version}\"")
    } else {
        let quoted: Vec<String> = features.iter().map(|f| format!("\"{f}\"")).collect();
        format!(
            "{name} = {{ version = \"={version}\", features = [{}] }}",
            quoted.join(", ")
        )
    }
}

/// All FFI seam outputs produced from a single project-scoped catalog load.
///
/// Returned by [`prepare_ffi`]; consumed by the build pipeline, `ipe watch`,
/// and `ipe lsp` so all three go through exactly the same injection steps.
pub struct FfiPrep {
    /// The parsed per-crate entries — used to assemble [`ipe_backend_rust::FfiEmit`].
    pub catalog: Vec<InstalledCrate>,
    /// Cross-crate foreign-type nominal unification decisions (one Ipê home
    /// per foreign type) applied to the catalog before injection.
    pub unify: ipe_ffi::unify::UnifyReport,
    /// The module paths injected into the source map (earn
    /// `ModuleOrigin::FfiInterface` at [`crate::create_source_root`]).
    pub injected: BTreeSet<Vec<String>>,
    /// The assembled backend emission inputs, or `None` when no crates are
    /// installed. Mirrors the `ffi_emit` local in `run_build_inner`.
    pub emit: Option<ipe_backend_rust::FfiEmit>,
}

/// Load, inject, and assemble the FFI catalog for a project in one step.
///
/// This is the shared seam used by `run_build`, `ipe watch`, and `ipe lsp` so
/// all three compilation paths go through the SAME catalog-load → interface-
/// inject → emit-assemble sequence. Each caller was previously duplicating
/// these steps independently, or (in `watch`/`lsp`) skipping them entirely —
/// both are bugs (CO-INCR-005).
///
/// `blame_path` is the project entry file or manifest: the catalog search
/// walks up from it looking for `.ipe/cache/ffi/rust`.
///
/// `sources` is mutated in-place: one `Rust.<Crate>` interface module is
/// inserted per installed crate.
///
/// # Errors
/// [`CliError`] when the catalog is tampered/unreadable, or two installed
/// crates pin the same dependency to conflicting version lines.
pub fn prepare_ffi(
    sources: &mut BTreeMap<Vec<String>, (PathBuf, String)>,
    blame_path: &Path,
) -> Result<FfiPrep, CliError> {
    let mut catalog = load_catalog_for(blame_path)?;
    // The asserted-call classifications lean on two unforgeable names: the
    // `Rust.Ffi` module and the `ipe_asserted_` wrapper prefix. No installed
    // crate may claim either — refused at load, before anything is injected.
    for c in &catalog {
        if c.module_name == ipe_canon::asserted::ASSERTED_MODULE {
            return Err(CliError::UsageOwned(text::ffi_reserved_module_claimed(
                &c.slug,
                &ipe_canon::asserted::ASSERTED_MODULE,
            )));
        }
        if let Some(ident) = c
            .wrapper_idents
            .iter()
            .find(|w| w.starts_with(ipe_canon::asserted::ASSERTED_WRAPPER_PREFIX))
        {
            return Err(CliError::UsageOwned(text::ffi_reserved_wrapper_prefix(
                &c.slug,
                &ident,
                &ipe_canon::asserted::ASSERTED_WRAPPER_PREFIX,
            )));
        }
    }
    // One Ipê home per foreign type: collapse same-defining-path nominals
    // across the catalog BEFORE injection, so every injected signature and
    // the assembled `foreign_types` map agree on one nominal per type.
    let unify = ipe_ffi::unify::unify_foreign_nominals(&mut catalog);
    // Scan for asserted calls BEFORE interface injection, while `sources`
    // holds only project (and stdlib) modules.
    let ScannedFfi { asserted, consts } = scan_asserted(sources, &catalog)?;
    let cache_hint = find_cache_root(blame_path)?.unwrap_or_default();
    let mut injected = inject_interfaces(sources, &catalog, &cache_hint)?;
    let mut emit = assemble_emit(&catalog)?;
    if !asserted.is_empty() || !consts.is_empty() {
        let mod_path: Vec<String> = ipe_canon::asserted::ASSERTED_MODULE
            .split('.')
            .map(str::to_owned)
            .collect();
        if sources.contains_key(&mod_path) {
            return Err(CliError::UsageOwned(text::ffi_reserved_module_exists(
                &ipe_canon::asserted::ASSERTED_MODULE,
            )));
        }
        let iface = ipe_ffi::asserted::render_asserted_interface(&asserted, &consts);
        sources.insert(mod_path.clone(), (cache_hint.join("Rust.Ffi.ipe"), iface));
        injected.insert(mod_path);
        // `validate` proved every target crate is installed, so the catalog —
        // and therefore the assembled emit — is non-empty here.
        let Some(e) = emit.as_mut() else {
            return Err(CliError::UsageOwned(
                text::ffi_asserted_empty_catalog().to_owned(),
            ));
        };
        if !asserted.is_empty() {
            e.bindings_source.push('\n');
            e.bindings_source
                .push_str(&ipe_ffi::asserted::emit_asserted_shims(&asserted));
        }
        if !consts.is_empty() {
            e.bindings_source.push('\n');
            e.bindings_source
                .push_str(&ipe_ffi::asserted::emit_const_shims(&consts));
        }
        e.interface_modules
            .push(ipe_canon::asserted::ASSERTED_MODULE.to_owned());
    }
    Ok(FfiPrep {
        catalog,
        unify,
        injected,
        emit,
    })
}

/// Scan every project source module for asserted-call sites
/// (`Rust.Ffi.call "<path>"`) and validate each against the installed-crate
/// catalog, deduplicating identical assertions.
///
/// A module that fails to parse is skipped here: it cannot carry a working
/// asserted call, and the compile pipeline reports the parse error with full
/// context moments later.
///
/// # Errors
/// [`CliError::Pipeline`] (IPE-N0038, span-attributed) for a malformed site;
/// [`CliError::UsageOwned`] (IPE-F4414) for a refused assertion.
/// The two native-binding surfaces one scan pass produces: forwarder calls
/// (`Rust.fn` / `Rust.Ffi.call`) and bare-scalar constant reads (`Rust.const`).
/// A single pass over the modules yields both — splitting the scan would
/// re-parse every module.
struct ScannedFfi {
    asserted: Vec<ipe_ffi::asserted::AssertedSpec>,
    consts: Vec<ipe_ffi::asserted::ConstSpec>,
}

fn scan_asserted(
    sources: &BTreeMap<Vec<String>, (PathBuf, String)>,
    catalog: &[InstalledCrate],
) -> Result<ScannedFfi, CliError> {
    let mut specs = Vec::new();
    let mut const_specs = Vec::new();
    for (file, text) in sources.values() {
        // Cheap pre-filter: skip a module that spells no native-binding surface
        // before the parse. `scan_module` is the authoritative classifier; this
        // only avoids parsing modules that cannot carry one.
        if !text.contains("Rust.Ffi.call")
            && !text.contains("Rust.fn")
            && !text.contains("Rust.const")
        {
            continue;
        }
        let mut interner = ipe_intern::Interner::new();
        let Ok(module) = ipe_parse::parse_module(text, &mut interner) else {
            continue;
        };
        let uses = ipe_canon::asserted::scan_module(&module, &interner).map_err(|diag| {
            CliError::Pipeline {
                file: file.clone(),
                src: text.clone(),
                diag: Box::new(diag),
            }
        })?;
        for u in uses {
            // A native constant reads a bare scalar; every other surface is a
            // forwarder. The classifier carried on the use routes the two.
            if matches!(u.callee, ipe_canon::asserted::AssertedCallee::RustConst) {
                let spec =
                    ipe_ffi::asserted::validate_const(u.path, &u.annotation, &interner, catalog)
                        .map_err(|d| CliError::UsageOwned(d.to_string()))?;
                const_specs.push(spec);
            } else {
                let spec = ipe_ffi::asserted::validate(u.path, &u.annotation, &interner, catalog)
                    .map_err(|d| CliError::UsageOwned(d.to_string()))?;
                specs.push(spec);
            }
        }
    }
    let asserted =
        ipe_ffi::asserted::dedupe(specs).map_err(|d| CliError::UsageOwned(d.to_string()))?;
    let consts = ipe_ffi::asserted::dedupe_consts(const_specs)
        .map_err(|d| CliError::UsageOwned(d.to_string()))?;
    Ok(ScannedFfi { asserted, consts })
}

/// Locate the `ipe-ffi-inspector` binary: beside the running `ipe`
/// executable first, then `$PATH`.
fn inspector_binary() -> Result<PathBuf, CliError> {
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let sibling = dir.join("ipe-ffi-inspector");
        if sibling.is_file() {
            return Ok(sibling);
        }
    }
    if let Some(paths) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&paths) {
            let candidate = dir.join("ipe-ffi-inspector");
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    Err(CliError::Usage(text::ffi_inspector_not_found()))
}

/// A per-invocation scratch directory under the sanctioned write-boundary
/// root (`~/.cache/ipe/ffi-scratch/`), created with an unpredictable name via
/// 128-bit OS entropy and exclusive-create semantics so a pre-seeded symlink or
/// directory causes failure rather than reuse.  `/tmp` is never used: it is
/// world-writable and outside the write-boundary.  HOME must be set; absent it
/// the function fails closed rather than falling back to a world-writable path.
fn make_scratch_dir(krate: &str) -> Result<PathBuf, CliError> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or(CliError::Usage(text::ffi_add_home_unset()))?;
    let base = home.join(".cache/ipe/ffi-scratch");
    crate::scratch::ScratchDir::new_under(&base, &format!("add-{krate}"))
        .map(crate::scratch::ScratchDir::into_path)
        .map_err(|e| CliError::UsageOwned(text::ffi_add_scratch_dir(&e)))
}

/// Read-only jail binds for the toolchain, deliberately NARROW: never the
/// `~/.cargo` parent (which carries `credentials.toml`, the crates.io API
/// token). Only `~/.cargo/bin` (the proxy binaries) and `~/.rustup` are
/// exposed. Returns `(toolchain_ro_binds, path_prepend, rustup_home)`.
fn toolchain_binds(inspector: &Path) -> (Vec<PathBuf>, Vec<PathBuf>, Option<PathBuf>) {
    let mut toolchain_ro_binds = Vec::new();
    // The inspector binary may live under a masked mount ($HOME target dirs) —
    // re-bind its directory read-only.
    if let Some(dir) = inspector.parent() {
        toolchain_ro_binds.push(dir.to_path_buf());
    }
    let mut path_prepend = Vec::new();
    let mut rustup_home = None;
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        let cargo_bin = home.join(".cargo/bin");
        if cargo_bin.is_dir() {
            path_prepend.push(cargo_bin.clone());
            // Bind ONLY the bin dir — NEVER the ~/.cargo parent, so
            // credentials.toml stays outside the jail.
            toolchain_ro_binds.push(cargo_bin);
        }
        let rustup = home.join(".rustup");
        if rustup.is_dir() {
            toolchain_ro_binds.push(rustup.clone());
            rustup_home = Some(rustup);
        }
    }
    (toolchain_ro_binds, path_prepend, rustup_home)
}

/// The jail resource caps: the fail-closed defaults, each raisable through an
/// explicit env override that prints a warning (an SDK-scale dependency
/// closure — hundreds of crates under one `cargo check`/rustdoc — legitimately
/// needs more CPU/wall/output than the small-crate defaults).
fn jail_limits() -> ipe_sandbox::ResourceLimits {
    let mut limits = ipe_sandbox::ResourceLimits::default();
    let with_override = |var: &str, slot: &mut u64, scale: u64| {
        if let Ok(raw) = std::env::var(var) {
            if let Ok(v) = raw.parse::<u64>().map(|v| v.saturating_mul(scale))
                && v > 0
            {
                crate::screen::chatter(
                    crate::screen::Stream::Stderr,
                    crate::screen::Tone::UserError,
                    &format!("WARNING: jail cap override {var}={raw}"),
                );
                *slot = v;
            } else {
                crate::screen::chatter(
                    crate::screen::Stream::Stderr,
                    crate::screen::Tone::UserError,
                    &format!("WARNING: ignoring non-numeric jail cap override {var}={raw}"),
                );
            }
        }
    };
    with_override("IPE_FFI_RSS_MB", &mut limits.rss_bytes, 1024 * 1024);
    with_override("IPE_FFI_CPU_SECS", &mut limits.cpu_secs, 1);
    with_override("IPE_FFI_WALL_SECS", &mut limits.wall_secs, 1);
    with_override("IPE_FFI_FD_CAP", &mut limits.fd_cap, 1);
    with_override("IPE_FFI_PROC_CAP", &mut limits.proc_cap, 1);
    with_override("IPE_FFI_OUT_CAP_MB", &mut limits.out_cap_bytes, 1024 * 1024);
    limits
}

/// Run one jailed inspector phase over the shared `scoped_tmp`, returning its
/// captured stdout.
fn run_phase(
    caps: &ipe_sandbox::Capabilities,
    network: ipe_sandbox::NetworkPolicy,
    scoped_tmp: &Path,
    toolchain_ro_binds: Vec<PathBuf>,
    path_prepend: Vec<PathBuf>,
    rustup_home: Option<PathBuf>,
    payload: &[OsString],
) -> Result<ipe_sandbox::JailedOutput, CliError> {
    let io_err = |detail: String| CliError::UsageOwned(text::command_refusal(&"add", &detail));
    let spec = ipe_sandbox::JailSpec {
        network,
        scoped_tmp: scoped_tmp.to_path_buf(),
        registry_cache: None,
        toolchain: None,
        toolchain_ro_binds,
        path_prepend,
        rustup_home,
        limits: jail_limits(),
    };
    ipe_sandbox::run_in_bwrap_jail(caps, &spec, payload)
        .map_err(|d| io_err(format!("sandboxed inspection failed: {d}")))
}

/// Run the inspector for `krate` inside the sandbox jail and return its
/// stdout (the inspection JSON).
///
/// Two phases over a SHARED scoped scratch dir (same in-jail `CARGO_HOME`):
///   1. fetch (`FetchOnly`, network on) — the inspector runs `--fetch-only`,
///      populating the registry cache; NO proc-macro / build-script / rustdoc
///      expansion, so no foreign code runs while egress is available.
///   2. introspect (`Denied`, fresh empty net namespace, `CARGO_NET_OFFLINE`)
///      — rustdoc expands proc-macros / build scripts (the foreign code) with
///      NO network egress, so the crates.io token cannot be exfiltrated even
///      if it were reachable (it is not — see [`toolchain_binds`]).
fn run_inspector(
    krate: &CrateSpec,
    features: &[String],
    allow_build_scripts: bool,
) -> Result<String, CliError> {
    run_inspector_job(
        &InspectorJob::Single { krate, features },
        allow_build_scripts,
    )
}

/// One jailed inspector invocation: either a single crate or a MULTI-crate
/// manifest. The manifest form matters beyond convenience: the inspector's
/// cross-crate impl index is process-global, so a trait method defined in one
/// crate and implemented for a sibling's type (the async-SDK `send` shape)
/// resolves only when every project crate is inspected in ONE process.
enum InspectorJob<'a> {
    /// `ipe add <crate>`.
    Single {
        /// The crate (with optional version pin).
        krate: &'a CrateSpec,
        /// The requested feature list.
        features: &'a [String],
    },
    /// `ipe install` — every `[rust.dependencies]` entry in one run.
    Manifest {
        /// Per-crate (spec, features) pairs.
        entries: &'a [(CrateSpec, Vec<String>)],
    },
    /// A `[rust.wrapper]` local wrapper crate: inspected from an absolute path
    /// (bound RO by the whole-`/` jail bind), binding only the exposed symbols.
    WrapperPath {
        /// The wrapper crate's Cargo package name (the inspection slug).
        krate: &'a CrateName,
        /// The absolute, package-jailed wrapper-crate directory.
        abs_path: &'a str,
        /// The public symbols to bind (empty ⇒ every public symbol).
        expose: &'a [String],
    },
}

/// Serialize the inspector's `--manifest` JSON into the scoped scratch dir
/// (the only jail-writable mount, so the path is visible inside the jail).
fn write_inspector_manifest(
    scoped_tmp: &Path,
    entries: &[(CrateSpec, Vec<String>)],
) -> Result<PathBuf, CliError> {
    let arr: Vec<serde_json::Value> = entries
        .iter()
        .map(|(spec, feats)| serde_json::json!({ "name": spec.inspector_arg(), "features": feats }))
        .collect();
    let path = scoped_tmp.join("ipe-install-manifest.json");
    let body = serde_json::Value::Array(arr).to_string();
    std::fs::write(&path, body)
        .map_err(|e| CliError::UsageOwned(text::ffi_install_manifest_write_failed(&e)))?;
    Ok(path)
}

/// The full inspector argv (program + flags) for one phase of a job. The
/// manifest path, when present, was written into the jail-visible scratch.
fn inspector_payload(
    inspector: &Path,
    job: &InspectorJob,
    manifest_path: Option<&Path>,
    allow_build_scripts: bool,
    fetch_only: bool,
) -> Vec<OsString> {
    let mut payload: Vec<OsString> = vec![inspector.to_path_buf().into_os_string()];
    match job {
        InspectorJob::Single { krate, features } => {
            payload.extend(ipe_ffi::driver::inspector_argv(
                krate,
                features,
                None,
                allow_build_scripts,
                fetch_only,
            ));
        }
        InspectorJob::Manifest { .. } => {
            if fetch_only {
                payload.push("--fetch-only".into());
            }
            if allow_build_scripts {
                payload.push("--allow-build-scripts".into());
            }
            payload.push("--manifest".into());
            if let Some(p) = manifest_path {
                payload.push(p.to_path_buf().into_os_string());
            }
        }
        InspectorJob::WrapperPath {
            krate,
            abs_path,
            expose,
        } => {
            if fetch_only {
                payload.push("--fetch-only".into());
            }
            if allow_build_scripts {
                payload.push("--allow-build-scripts".into());
            }
            payload.push("--path".into());
            payload.push((*abs_path).into());
            if !expose.is_empty() {
                payload.push("--expose".into());
                payload.push(expose.join(",").into());
            }
            payload.push(krate.as_str().into());
        }
    }
    payload
}

/// How an inspector job should be run, once the host's sandbox capabilities and
/// the operator's unsandboxed override have been weighed. Every reachable
/// combination maps to exactly one variant, so no host configuration can fall
/// through to a branch its capabilities doom.
enum SandboxRoute {
    /// bubblewrap with the mandatory cap helpers present — the jailed path.
    Jailed,
    /// The operator accepted running foreign build code without a jail. Reached
    /// either when bwrap is absent or when its cap helpers are missing, and only
    /// when `IPE_FFI_ALLOW_UNSANDBOXED=1` is set.
    Unsandboxed,
    /// bwrap is absent and no override is set — refuse, advising bwrap.
    RefuseNoBwrap,
    /// bwrap is present but a mandatory cap helper is missing and no override is
    /// set — refuse, advising the missing helpers.
    RefuseMissingCaps { missing: Vec<&'static str> },
}

/// Decide how to run an inspector job from the host's sandbox capabilities and
/// the unsandboxed override. Pure so the refusal and override paths are pinned
/// by tests without spawning a subprocess.
fn choose_sandbox_route(
    mechanism: &ipe_sandbox::Mechanism,
    missing_caps: Vec<&'static str>,
    unsandboxed_ok: bool,
) -> SandboxRoute {
    match mechanism {
        ipe_sandbox::Mechanism::Bwrap(_) if missing_caps.is_empty() => SandboxRoute::Jailed,
        ipe_sandbox::Mechanism::Bwrap(_) | ipe_sandbox::Mechanism::Refused if unsandboxed_ok => {
            SandboxRoute::Unsandboxed
        }
        ipe_sandbox::Mechanism::Bwrap(_) => SandboxRoute::RefuseMissingCaps {
            missing: missing_caps,
        },
        ipe_sandbox::Mechanism::Refused => SandboxRoute::RefuseNoBwrap,
    }
}

fn run_inspector_job(job: &InspectorJob, allow_build_scripts: bool) -> Result<String, CliError> {
    let inspector = inspector_binary()?;
    let scratch_hint = match job {
        InspectorJob::Single { krate, .. } => krate.name().as_str(),
        InspectorJob::WrapperPath { krate, .. } => krate.as_str(),
        InspectorJob::Manifest { .. } => "manifest",
    };

    let caps = ipe_sandbox::probe();
    let mechanism = ipe_sandbox::select_mechanism(&caps);
    let unsandboxed_ok = ipe_sandbox::unsandboxed_override_set();
    let io_err = |detail: String| CliError::UsageOwned(text::command_refusal(&"add", &detail));

    match choose_sandbox_route(&mechanism, ipe_sandbox::missing_caps(&caps), unsandboxed_ok) {
        SandboxRoute::RefuseNoBwrap => {
            return Err(CliError::Usage(text::ffi_no_bubblewrap()));
        }
        SandboxRoute::RefuseMissingCaps { missing } => {
            return Err(io_err(format!(
                "missing mandatory sandbox cap helper(s): {} — install coreutils \
                 (timeout) and util-linux (prlimit), or set IPE_FFI_ALLOW_UNSANDBOXED=1 \
                 (dangerous)",
                missing.join(", ")
            )));
        }
        SandboxRoute::Unsandboxed => {
            return run_inspector_job_unsandboxed(
                &inspector,
                job,
                scratch_hint,
                allow_build_scripts,
            );
        }
        SandboxRoute::Jailed => {}
    }

    let scoped_tmp = make_scratch_dir(scratch_hint)?;
    let binds = toolchain_binds(&inspector);
    let result = match job {
        // A single crate — or a single local wrapper crate — is one
        // populate-free bind over the historical two phases (fetch,
        // introspect) on one scoped scratch. A wrapper crate is local, so
        // its fetch phase only resolves the wrapper's own registry deps.
        InspectorJob::Single { .. } | InspectorJob::WrapperPath { .. } => run_single_bwrap(
            &inspector,
            job,
            &caps,
            &scoped_tmp,
            &binds,
            allow_build_scripts,
        ),
        // A multi-crate manifest is CHUNKED: one fetch, then a per-crate
        // populate sequence that accumulates the cross-crate index through
        // a checkpoint, then a per-crate bind — so no single jailed run
        // exceeds the wall, which the whole-manifest run did (its populate
        // + bind of every crate ran under one wall budget).
        InspectorJob::Manifest { entries } => run_manifest_bwrap_chunked(
            &inspector,
            entries,
            &caps,
            &scoped_tmp,
            &binds,
            allow_build_scripts,
        ),
    };
    let _ = std::fs::remove_dir_all(&scoped_tmp);
    result
}

/// The toolchain jail binds, grouped so the chunked driver can clone them once
/// per phase without repeating the tuple destructure.
type ToolchainBinds = (Vec<PathBuf>, Vec<PathBuf>, Option<PathBuf>);

/// The historical two-phase single-crate flow: fetch (network on, no foreign
/// code) then introspect (no egress, foreign code runs) over one scratch.
fn run_single_bwrap(
    inspector: &Path,
    job: &InspectorJob,
    caps: &ipe_sandbox::Capabilities,
    scoped_tmp: &Path,
    binds: &ToolchainBinds,
    allow_build_scripts: bool,
) -> Result<String, CliError> {
    let io_err = |detail: String| CliError::UsageOwned(text::command_refusal(&"add", &detail));
    let (toolchain_ro_binds, path_prepend, rustup_home) = binds;
    let with_payload =
        |fetch_only: bool| inspector_payload(inspector, job, None, allow_build_scripts, fetch_only);
    run_phase(
        caps,
        ipe_sandbox::NetworkPolicy::FetchOnly,
        scoped_tmp,
        toolchain_ro_binds.clone(),
        path_prepend.clone(),
        rustup_home.clone(),
        &with_payload(true),
    )?;
    let out = run_phase(
        caps,
        ipe_sandbox::NetworkPolicy::Denied,
        scoped_tmp,
        toolchain_ro_binds.clone(),
        path_prepend.clone(),
        rustup_home.clone(),
        &with_payload(false),
    )?;
    if out.status != Some(0) {
        return Err(io_err(format!(
            "inspector exited with {:?}\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    String::from_utf8(out.stdout)
        .map_err(|_| io_err("inspector produced non-UTF-8 output".to_owned()))
}

/// The inspector argv for one chunk of the manifest flow: a single-crate
/// manifest file plus optional cross-crate checkpoint load/save flags. The
/// manifest form is kept (never `Single`) so a one-crate chunk still emits a
/// JSON array — the shape `run_install` decodes.
fn manifest_chunk_payload(
    inspector: &Path,
    manifest_path: &Path,
    allow_build_scripts: bool,
    fetch_only: bool,
    xc_load: Option<&Path>,
    xc_save: Option<&Path>,
) -> Vec<OsString> {
    let mut payload: Vec<OsString> = vec![inspector.to_path_buf().into_os_string()];
    if fetch_only {
        payload.push("--fetch-only".into());
    }
    if allow_build_scripts {
        payload.push("--allow-build-scripts".into());
    }
    if let Some(p) = xc_load {
        payload.push("--xc-load".into());
        payload.push(p.to_path_buf().into_os_string());
    }
    if let Some(p) = xc_save {
        payload.push("--xc-save".into());
        payload.push(p.to_path_buf().into_os_string());
    }
    payload.push("--manifest".into());
    payload.push(manifest_path.to_path_buf().into_os_string());
    payload
}

/// Run one jailed introspect chunk (network denied — foreign code runs here)
/// and return its stdout, mapping a non-zero exit to a typed error.
fn run_introspect_chunk(
    caps: &ipe_sandbox::Capabilities,
    scoped_tmp: &Path,
    binds: &ToolchainBinds,
    payload: &[OsString],
) -> Result<String, CliError> {
    let io_err = |detail: String| CliError::UsageOwned(text::command_refusal(&"add", &detail));
    let (toolchain_ro_binds, path_prepend, rustup_home) = binds;
    let out = run_phase(
        caps,
        ipe_sandbox::NetworkPolicy::Denied,
        scoped_tmp,
        toolchain_ro_binds.clone(),
        path_prepend.clone(),
        rustup_home.clone(),
        payload,
    )?;
    if out.status != Some(0) {
        return Err(io_err(format!(
            "inspector exited with {:?}\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    String::from_utf8(out.stdout)
        .map_err(|_| io_err("inspector produced non-UTF-8 output".to_owned()))
}

/// Chunk a multi-crate manifest into per-crate jailed runs so no single run
/// exceeds the jail wall.
///
/// One shared scratch (one `CARGO_HOME`, one checkpoint) hosts three stages:
///  1. **Fetch** — one network-on run over the WHOLE manifest, populating the
///     scoped registry. No foreign code runs (the inspector stops at
///     `--fetch-only`).
///  2. **Populate** — one network-denied run PER crate, each loading the prior
///     crate's checkpoint and saving the accumulated one. A crate's build
///     scripts run here, but the checkpoint is read before any foreign code
///     and rewritten (full accumulated maps) after it, so no crate can corrupt
///     the index a sibling later loads — the trust model of the single-process
///     populate pass, split across processes.
///  3. **Bind** — one network-denied run PER crate, each loading the COMPLETE
///     checkpoint, so every sibling impl is indexed before the crate binds.
///
/// Returns the concatenated bind results as one JSON array string — the shape
/// the whole-manifest run produced, so `run_install`'s decode is unchanged.
fn run_manifest_bwrap_chunked(
    inspector: &Path,
    entries: &[(CrateSpec, Vec<String>)],
    caps: &ipe_sandbox::Capabilities,
    scoped_tmp: &Path,
    binds: &ToolchainBinds,
    allow_build_scripts: bool,
) -> Result<String, CliError> {
    let io_err = |detail: String| CliError::UsageOwned(text::command_refusal(&"add", &detail));
    let (toolchain_ro_binds, path_prepend, rustup_home) = binds;

    // Stage 1 — fetch every crate in one network-on run (no foreign code).
    let full_manifest = write_inspector_manifest(scoped_tmp, entries)?;
    let fetch_payload = manifest_chunk_payload(
        inspector,
        &full_manifest,
        allow_build_scripts,
        true,
        None,
        None,
    );
    run_phase(
        caps,
        ipe_sandbox::NetworkPolicy::FetchOnly,
        scoped_tmp,
        toolchain_ro_binds.clone(),
        path_prepend.clone(),
        rustup_home.clone(),
        &fetch_payload,
    )?;

    // The checkpoint lives in the shared scratch: written by each populate
    // chunk, read by the next populate chunk and by every bind chunk. It is a
    // jail-writable path, but each process reads it before foreign code runs
    // and rewrites it after, so a build script cannot plant facts a sibling
    // then trusts.
    let checkpoint = scoped_tmp.join("xc-checkpoint.json");

    // Stage 2 — populate the cross-crate index one crate at a time.
    for (i, (spec, features)) in entries.iter().enumerate() {
        let chunk_manifest =
            write_inspector_manifest_chunk(scoped_tmp, &format!("populate-{i}"), spec, features)?;
        let xc_load = (i > 0).then_some(checkpoint.as_path());
        let payload = manifest_chunk_payload(
            inspector,
            &chunk_manifest,
            allow_build_scripts,
            false,
            xc_load,
            Some(checkpoint.as_path()),
        );
        // Populate emits no stdout of interest (bindings discarded); a non-zero
        // exit still surfaces as an error.
        let _ = run_introspect_chunk(caps, scoped_tmp, binds, &payload)?;
    }

    // Stage 3 — bind each crate against the complete cross-crate index.
    let mut bound: Vec<serde_json::Value> = Vec::with_capacity(entries.len());
    for (i, (spec, features)) in entries.iter().enumerate() {
        let chunk_manifest =
            write_inspector_manifest_chunk(scoped_tmp, &format!("bind-{i}"), spec, features)?;
        let payload = manifest_chunk_payload(
            inspector,
            &chunk_manifest,
            allow_build_scripts,
            false,
            Some(checkpoint.as_path()),
            None,
        );
        let json = run_introspect_chunk(caps, scoped_tmp, binds, &payload)?;
        // A manifest chunk always emits a JSON array (of one PkgInfo).
        match serde_json::from_str::<serde_json::Value>(&json) {
            Ok(serde_json::Value::Array(items)) => bound.extend(items),
            Ok(other) => bound.push(other),
            Err(e) => {
                return Err(io_err(format!(
                    "invalid inspector JSON for `{}`: {e}",
                    spec.inspector_arg()
                )));
            }
        }
    }
    serde_json::to_string(&serde_json::Value::Array(bound))
        .map_err(|e| io_err(format!("re-serializing chunked inspection failed: {e}")))
}

/// Serialize a SINGLE-crate inspector manifest into the scoped scratch under a
/// stage-unique name (`<stage>.json`), so a crate's populate and bind chunks —
/// and successive crates — never clobber each other's manifest file.
fn write_inspector_manifest_chunk(
    scoped_tmp: &Path,
    stage: &str,
    spec: &CrateSpec,
    features: &[String],
) -> Result<PathBuf, CliError> {
    let arr = serde_json::json!([{ "name": spec.inspector_arg(), "features": features }]);
    let path = scoped_tmp.join(format!("ipe-install-{stage}.json"));
    std::fs::write(&path, arr.to_string())
        .map_err(|e| CliError::UsageOwned(text::ffi_install_manifest_chunk_write_failed(&e)))?;
    Ok(path)
}

/// The explicit `IPE_FFI_ALLOW_UNSANDBOXED=1` escape hatch: one direct argv
/// spawn, loudly labelled.
fn run_inspector_job_unsandboxed(
    inspector: &Path,
    job: &InspectorJob,
    scratch_hint: &str,
    allow_build_scripts: bool,
) -> Result<String, CliError> {
    let io_err = |detail: String| CliError::UsageOwned(text::command_refusal(&"add", &detail));
    crate::screen::chatter(
        crate::screen::Stream::Stderr,
        crate::screen::Tone::UserError,
        "WARNING: running the FFI inspector UNSANDBOXED (IPE_FFI_ALLOW_UNSANDBOXED=1)",
    );
    let scoped_tmp = make_scratch_dir(scratch_hint)?;
    let manifest_path = match job {
        InspectorJob::Manifest { entries } => Some(write_inspector_manifest(&scoped_tmp, entries)?),
        InspectorJob::Single { .. } | InspectorJob::WrapperPath { .. } => None,
    };
    let payload = inspector_payload(
        inspector,
        job,
        manifest_path.as_deref(),
        allow_build_scripts,
        false,
    );
    let (program, rest) = payload
        .split_first()
        .ok_or(CliError::Usage(text::ffi_add_no_payload()))?;
    let out = std::process::Command::new(program)
        .args(rest)
        .output()
        .map_err(|e| io_err(e.to_string()));
    let _ = std::fs::remove_dir_all(&scoped_tmp);
    let out = out?;
    if !out.status.success() {
        return Err(io_err(format!(
            "inspector exited with {:?}\n{}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    String::from_utf8(out.stdout)
        .map_err(|_| io_err("inspector produced non-UTF-8 output".to_owned()))
}

/// Inspect + install a `[rust.wrapper]` local wrapper crate.
///
/// The path is decode-jailed to the package tree by
/// [`ipe_ffi::wrapper::WrapperManifest`], then canonicalized under the project
/// root; the inspector binds only the exposed symbols and reports the crate's
/// absolute path as `wrapperPath`, so the emitted app crate depends on it by
/// `path`. The wrapper's build runs in the same RCE jail as a crate's build
/// script — the whole-`/` read-only bind makes the local source readable, and
/// the sandboxed build catches a non-compiling wrapper BEFORE exit 0.
fn install_wrapper(
    cache: &FfiCache,
    raw: &RawWrapperTable,
    assume_yes: bool,
    allow_build_scripts: bool,
) -> Result<(), CliError> {
    let manifest =
        ipe_ffi::wrapper::WrapperManifest::parse(&raw.path, &raw.expose, &raw.capabilities)
            .map_err(|diag| CliError::UsageOwned(diag.to_string()))?;
    // Resolve the package-jailed relative path to an absolute directory under
    // the project root. Canonicalization also confirms the wrapper crate
    // actually exists before any jailed build.
    let rel = manifest.path().as_str();
    let abs = std::fs::canonicalize(rel)
        .map_err(|e| CliError::UsageOwned(text::ffi_install_wrapper_crate(&rel, &e)))?;
    // The lexical `..`/absolute jail on the relative path is not enough:
    // canonicalization resolves symlinks, so a checked-in symlink under the
    // package could still point the resolved directory outside the project. Bind
    // the resolved path back inside the project root — a wrapper that escapes it
    // is refused before any jailed build.
    let project_root = std::fs::canonicalize(".")
        .map_err(|e| CliError::UsageOwned(text::ffi_install_project_root(&e)))?;
    if !abs.starts_with(&project_root) {
        return Err(CliError::UsageOwned(
            text::ffi_install_wrapper_outside_root(&rel, &abs.display()),
        ));
    }
    let abs_str = abs
        .to_str()
        .ok_or_else(|| CliError::UsageOwned(text::ffi_install_wrapper_not_utf8(&rel)))?
        .to_owned();
    // The wrapper crate's Cargo package name is the inspection slug. Derive it
    // from the directory name, gated through the crate-name charset.
    let krate = CrateName::parse(abs.file_name().and_then(|n| n.to_str()).unwrap_or(rel))
        .map_err(|diag| CliError::UsageOwned(diag.to_string()))?;

    // The capability gate runs BEFORE the trust prompt and any jailed compile: a
    // wrapper whose effects Ipê cannot contain at run must be refused before we
    // ask to build it. It scans the wrapper's own `.rs`, reconciles the inferred
    // set against the declared one, and refuses any runtime-unenforceable or
    // opaque capability (there is no runtime sandbox around the emitted app in
    // this release, so such a capability would be uncontained — refuse rather
    // than admit unenforced).
    enforce_wrapper_capabilities(&abs, manifest.capabilities())?;

    if !assume_yes {
        use std::io::Write as _;
        crate::screen::chatter(
            crate::screen::Stream::Stderr,
            crate::screen::Tone::Text,
            &format!(
                "About to COMPILE a local wrapper crate `{}` at {} (inside the isolation jail).",
                krate.as_str(),
                abs_str
            ),
        );
        crate::screen::prompt("Continue? [y/N] ");
        let _ = std::io::stdout().flush();
        if !crate::read_yes_no() {
            return Err(CliError::Usage(text::install_aborted()));
        }
    }
    let expose = manifest.expose_names();
    let json = run_inspector_job(
        &InspectorJob::WrapperPath {
            krate: &krate,
            abs_path: &abs_str,
            expose: &expose,
        },
        allow_build_scripts,
    )?;
    // A single-crate inspector run may emit a singleton array; unwrap it.
    let doc_text = match serde_json::from_str::<serde_json::Value>(&json) {
        Ok(serde_json::Value::Array(items)) if items.len() == 1 => items
            .first()
            .map(serde_json::Value::to_string)
            .unwrap_or(json),
        _ => json,
    };
    let (pkg, paths) = ipe_ffi::driver::install_from_inspection(cache, &doc_text)
        .map_err(|diag| CliError::UsageOwned(diag.to_string()))?;
    let iface = ipe_ffi::interface::crate_interface(&pkg);
    crate::screen::Screen::new(crate::screen::Stream::Stdout)
        .line(
            crate::screen::Tone::Text,
            &format!(
                "added wrapper `{}`: {} bindings ({} skipped) -> {}",
                pkg.name(),
                iface.bindings.len(),
                iface.skipped.len(),
                paths.interface.display()
            ),
        )
        .emit();
    Ok(())
}

/// The capability gate for a `[rust.wrapper]` crate: scan its source, reconcile
/// the inferred set against the author's declaration, and REFUSE any wrapper
/// whose effects Ipê cannot enforce at run.
///
/// The three-layer defence, load-bearing part last (spec §5):
///   1. **Static inference** proposes a coarse capability set by token-scanning
///      the wrapper's `.rs` (string/comment-safe, over-approximating).
///   2. **Declaration** is the author's typed [`Capability`] set (already parsed
///      fail-closed by [`ipe_ffi::wrapper::WrapperManifest`]).
///   3. **Enforcement**: there is no runtime sandbox around the emitted app in
///      this release, so a capability on a runtime-enforced axis is infeasible to
///      contain — [`ipe_ffi::capability_scan::reconcile`] REFUSES it rather than
///      admit it unenforced. Only wrappers confined to the containable axes
///      (clock/random, or none) install.
///
/// # Errors
/// [`CliError::Io`] on a read failure; [`CliError::UsageOwned`] when the
/// reconcile refuses the wrapper (naming every reason and the proposed set).
/// The jail-holds verdict for THIS host — the admit path's per-target hand-off.
///
/// The refuse-until-jail → admit-and-isolate hand-off is per-target: a
/// runtime-enforced axis is admitted only where the jail actually holds. The
/// deploy target is unknown at install, so the honest proxy is this host's jail
/// capability — `ipe add` and `ipe run` typically run on the same machine. It is
/// built from [`ipe_sandbox::run_jail::platform_confined_axes`] — the SET of
/// runtime-enforced axes the compiled-in `exec_in_run_jail` arm actually confines
/// on this host, single-sourced to that arm by the `on_jailed_target!` macro. So
/// the admit path can never claim an axis the jail does not enforce: a full-set
/// host (Linux/macOS) admits-and-isolates every axis, an empty-set (stub) host
/// refuse-gaps every axis, and a future partial-coverage host admits only the
/// axes it confines.
fn jail_for_host() -> ipe_ffi::capability_scan::JailForTarget {
    let mut confined = ipe_ffi::capability_scan::CapabilitySet::EMPTY;
    for &axis in ipe_sandbox::run_jail::platform_confined_axes() {
        confined = confined.with(axis);
    }
    ipe_ffi::capability_scan::JailForTarget::Holds(confined)
}

fn enforce_wrapper_capabilities(
    wrapper_dir: &Path,
    declared: &BTreeSet<ipe_ffi::capability_scan::Capability>,
) -> Result<(), CliError> {
    // Collect every `.rs` under the wrapper crate (incl. `build.rs`, `bin/`,
    // nested modules). A single unscanned file is a hole, so the walk is
    // recursive and unfiltered.
    let mut rs_files: Vec<PathBuf> = Vec::new();
    collect_wrapper_rust_files(wrapper_dir, &mut rs_files)?;
    rs_files.sort();

    let mut sources: Vec<(String, String)> = Vec::with_capacity(rs_files.len());
    for file in &rs_files {
        let src =
            crate::io_bounded::read_to_string_capped(file, crate::io_bounded::FFI_CACHE_READ_CAP)?;
        sources.push((file.display().to_string(), src));
    }
    let scan = ipe_ffi::capability_scan::scan_sources(
        sources.iter().map(|(f, s)| (f.as_str(), s.as_str())),
    );

    // A wrapper with any non-`std` Cargo dependency is opaque: a dependency's
    // capabilities live in source the scan never opens.
    let non_std_deps = wrapper_non_std_dependencies(wrapper_dir)?;

    let jail = jail_for_host();

    // A best-effort honesty smell test on the declaration: surface an obvious
    // under-declaration (the scan proposes an axis the author did not declare)
    // that the jail nonetheless CONFINES on this host. An undeclared axis the
    // jail does NOT confine is refused by the reconcile below, so it is not a
    // "will still contain" note. This is DEFEATABLE and never the boundary — the
    // jail is — but it nudges an honest declaration.
    let confined = jail.confined();
    let undeclared: Vec<&str> = scan
        .proposed
        .difference(declared)
        .filter(|c| confined.confines(**c))
        .map(|c| c.as_str())
        .collect();
    if !undeclared.is_empty() {
        crate::screen::chatter(
            crate::screen::Stream::Stderr,
            crate::screen::Tone::Text,
            &format!(
                "note: the wrapper's source appears to reach {} that it did not declare. \
                 The runtime jail will still contain any undeclared effect (it fails closed at \
                 the OS boundary), but an honest declaration is the consent surface a user sees — \
                 consider declaring it.",
                undeclared.join(", ")
            ),
        );
    }

    match ipe_ffi::capability_scan::reconcile_for(declared, &scan, &non_std_deps, jail) {
        ipe_ffi::capability_scan::Verdict::Admit { declared } => {
            let contains_native_ffi =
                declared.contains(&ipe_ffi::capability_scan::Capability::NativeFfi);
            let cap_line = if declared.is_empty() {
                "wrapper capability check: no capabilities — pure compute.".to_owned()
            } else {
                let names: Vec<&str> = declared.iter().map(|c| c.as_str()).collect();
                format!(
                    "wrapper capability check: admitted and isolated by the runtime jail — {}.",
                    names.join(", ")
                )
            };
            let consent_note = if contains_native_ffi {
                "\n  note: this wrapper crosses into native `Rust.` code (native-ffi). Ipê \
                 cannot infer its true effects — the runtime jail CONTAINS it (an undeclared \
                 syscall fails closed), but does not PROVE the declared set is complete. \
                 Installing is informed consent to the declared capabilities."
            } else {
                ""
            };
            crate::screen::Screen::new(crate::screen::Stream::Stdout)
                .line(
                    crate::screen::Tone::Text,
                    &format!("{cap_line}{consent_note}"),
                )
                .emit();
            Ok(())
        }
        ipe_ffi::capability_scan::Verdict::Refuse { reasons, proposed } => {
            use std::fmt::Write as _;
            let mut message = String::from(
                "ipe install: the wrapper crate cannot be admitted — its capabilities cannot be \
                 enforced in this release.\n",
            );
            for reason in &reasons {
                let _ = writeln!(message, "  - {reason}");
            }
            if proposed.is_empty() {
                let _ = writeln!(
                    message,
                    "  inferred from its source: (none — but see the reasons above)"
                );
            } else {
                let names: Vec<&str> = proposed.iter().map(|c| c.as_str()).collect();
                let _ = writeln!(message, "  inferred from its source: {}", names.join(", "));
            }
            message.push_str(
                "  Ipê has no runtime sandbox around the emitted app yet, so a wrapper that \
                 touches the network, filesystem, environment, a subprocess, native FFI, or a \
                 non-std dependency would run uncontained. Narrow the wrapper to pure compute \
                 (Tier 1 `[rust.define.*]` covers the safe shapes), or wait for the runtime jail.",
            );
            Err(CliError::UsageOwned(message))
        }
    }
}

/// Recursively collect every `.rs` file under a wrapper crate directory.
///
/// # Errors
/// [`CliError::Io`] on a directory-read failure.
fn collect_wrapper_rust_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), CliError> {
    let entries = std::fs::read_dir(dir).map_err(|e| CliError::Io {
        path: dir.to_path_buf(),
        source: e,
    })?;
    for entry in entries {
        let entry = entry.map_err(|e| CliError::Io {
            path: dir.to_path_buf(),
            source: e,
        })?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|e| CliError::Io {
            path: path.clone(),
            source: e,
        })?;
        if file_type.is_dir() {
            // Never descend into `target/`: a built wrapper's dependency source is
            // not the author's Rust and would swamp the scan (and re-flag deps we
            // already refuse via the manifest). The author surface is `src/`,
            // `build.rs`, and any sibling module files.
            if path.file_name().and_then(|n| n.to_str()) == Some("target") {
                continue;
            }
            collect_wrapper_rust_files(&path, out)?;
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
    Ok(())
}

/// The wrapper crate's non-`std` Cargo dependency names, read from its
/// `Cargo.toml`. A wrapper with any external dependency is opaque to the source
/// scan (a dependency's capabilities live in source the scan never opens), so
/// each name becomes a refuse trigger.
///
/// This is a deliberately conservative line-scan of EVERY Cargo dependency-table
/// form — `[dependencies]`, `[build-dependencies]`, `[target.*.dependencies]`,
/// `[workspace.dependencies]`, and the `[….dependencies.<name>]` sub-table — via
/// [`parse_cargo_dependency_names`]. It OVER-collects (the safe direction): an
/// over-refused wrapper costs an author a narrowing, whereas a missed dep would
/// admit an unconstrained capability. `dev-dependencies` are excluded (test/
/// build-only, never shipped).
///
/// # Errors
/// [`CliError::Io`] on a read failure (an unreadable manifest is refused, not
/// silently treated as dependency-free).
fn wrapper_non_std_dependencies(wrapper_dir: &Path) -> Result<Vec<String>, CliError> {
    let manifest = wrapper_dir.join("Cargo.toml");
    if !manifest.is_file() {
        // No manifest means no crate to inspect; the inspector will fail loudly
        // later. Treat as no declared deps here (the source scan still runs).
        return Ok(Vec::new());
    }
    let text = crate::io_bounded::read_to_string_capped(
        &manifest,
        crate::io_bounded::SMALL_FILE_READ_CAP,
    )?;
    Ok(parse_cargo_dependency_names(&text))
}

/// Extract every dependency name from a `Cargo.toml`'s text — the pure,
/// unit-testable core of [`wrapper_non_std_dependencies`].
///
/// Parse, don't validate: the manifest is parsed into a typed TOML document and
/// EVERY dependency table is read structurally, so a trailing comment on a
/// header, whitespace inside `[ dependencies ]`, an inline
/// `dependencies = { … }` table, and the `[target.*]` / `[workspace]` forms all
/// resolve identically — a hand-rolled line scan under-refuses on those and any
/// missed dependency would admit an unconstrained capability. A manifest that
/// does not parse yields the whole document's key set conservatively via the
/// fallback, so a malformed `Cargo.toml` never silently reports "no deps"
/// (the inspector's own build then fails it loudly).
fn parse_cargo_dependency_names(text: &str) -> Vec<String> {
    let Ok(doc) = text.parse::<toml::Value>() else {
        // A `Cargo.toml` that does not parse is refused conservatively: if the
        // word `dependencies` appears anywhere, treat it as having a dependency
        // (a sentinel name), so a malformed manifest cannot fail OPEN. The real
        // build later rejects the unparseable manifest loudly.
        return if text.contains("dependencies") {
            vec!["<unparseable-cargo-toml>".to_owned()]
        } else {
            Vec::new()
        };
    };
    let mut deps: BTreeSet<String> = BTreeSet::new();
    collect_dependency_tables(&doc, &mut deps);
    deps.into_iter().collect()
}

/// Walk a parsed `Cargo.toml` value, inserting the name of every dependency
/// declared in any `dependencies` or `build-dependencies` table — at the top
/// level, under `[target.*]`, or under `[workspace]`. `dev-dependencies` are
/// test/build-only and never shipped, so they are deliberately NOT collected.
fn collect_dependency_tables(value: &toml::Value, out: &mut BTreeSet<String>) {
    let Some(table) = value.as_table() else {
        return;
    };
    for (key, sub) in table {
        match key.as_str() {
            // A shipped dependency table: every KEY is a dependency name.
            "dependencies" | "build-dependencies" => {
                if let Some(deps) = sub.as_table() {
                    for name in deps.keys() {
                        out.insert(name.clone());
                    }
                }
            }
            // Any other table may nest a dependency table one or more levels
            // down: `[target.<cfg>].dependencies`, `[workspace].dependencies`,
            // or a future/unknown Cargo form. Recurse into EVERY sub-table so no
            // nesting escapes the scan (bounded by the parser's own nesting
            // limit). Over-collection is the safe direction — a spurious name
            // only over-refuses a wrapper, whereas a missed one would admit an
            // unconstrained capability.
            _ => collect_dependency_tables(sub, out),
        }
    }
}

/// Map an FFI driver diagnostic to a [`CliError`] that does NOT trigger the
/// `CommandUsage` help page.
///
/// A build/inspection failure is not command-line misuse — showing the `ipe
/// rust add` usage synopsis after a pkg-config error is noise, not help.
/// `Resolve` passes through `with_help_on_misuse` unchanged and renders via
/// the normal `ipe: {msg}` path.
///
/// Render an inspector diagnostic as a `CliError`. The raw log escape hatch is
/// the caller's concern (it holds the inspection document): under `--verbose` a
/// caller emits the raw log via [`emit_raw_inspector_log`] before this summary.
fn ffi_build_error(diag: ipe_ffi::diag::Diagnostic) -> CliError {
    // Convert the FFI diagnostic into the shared typed currency and route it
    // through the single pipeline renderer. Both text and `--format json` now
    // use the same path as every P/N/T/L diagnostic.
    let shared: ipe_diagnostics::Diagnostic = diag.into();
    CliError::Pipeline {
        file: PathBuf::new(),
        src: String::new(),
        diag: Box::new(shared),
    }
}

/// Emit the raw inspector error log to stderr — the `--verbose` escape hatch
/// behind the summarised build diagnostic. Each line is stripped of control
/// characters (except tab) so raw build-script stderr cannot forge terminal
/// markup. A document with no error channel prints nothing.
fn emit_raw_inspector_log(inspection_json: &str) {
    let log = ipe_ffi::driver::inspection_error_log(inspection_json);
    if log.is_empty() {
        return;
    }
    crate::screen::chatter(
        crate::screen::Stream::Stderr,
        crate::screen::Tone::Text,
        "raw inspector log (--verbose):",
    );
    for line in &log {
        let clean: String = line
            .chars()
            .filter(|c| *c == '\t' || !c.is_control())
            .collect();
        crate::screen::chatter(
            crate::screen::Stream::Stderr,
            crate::screen::Tone::Aux,
            &format!("  {clean}"),
        );
    }
}

/// Detect the inspector's `--allow-build-scripts` refusal text in a raw error
/// message and return it as a warning string suitable for a banner.
///
/// The inspector prints this when it finds build-script crates but the flag
/// was not passed. Returns `None` when the text is not present.
fn detect_build_scripts_hint(raw: &str) -> Option<&str> {
    // The inspector emits a line containing "--allow-build-scripts" in its
    // human-readable refusal message. Any line that mentions it is the hint.
    raw.lines().find(|l| l.contains("--allow-build-scripts"))
}

/// Map a raw inspector `UsageOwned` error string to a `CliError::Resolve`
/// that never triggers the `CommandUsage` help page.
///
/// If the raw error contains the `--allow-build-scripts` refusal hint, the
/// hint is pulled out and rendered as a separate emphasised warning banner so
/// the user can see the actionable flag clearly.
fn map_inspector_error(msg: String) -> CliError {
    // Detect the hint before consuming `msg`, then branch.
    let hint_line: Option<String> = detect_build_scripts_hint(&msg).map(|l| l.trim().to_owned());
    hint_line.map_or(CliError::Resolve(msg), |hint| {
        // The build-scripts refusal: render the hint as a banner so the
        // `--allow-build-scripts` flag stands out as the actionable next step.
        let p = crate::style::Palette::for_stream(&std::io::stderr());
        let banner = format!(
            "{y}warning:{r} some crates in the dependency graph have build scripts.\n\
             Pass {bold}--allow-build-scripts{r} to proceed (you will see a warning naming\n\
             those packages first, and they will run inside the isolation jail).\n\
             \n\
             {dim}hint: {hint}{r}",
            y = p.bright_yellow,
            bold = p.bold,
            dim = p.dim,
            r = p.reset,
        );
        CliError::Resolve(banner)
    })
}

/// Shared tail of `add` / `install`: inspect one crate + write its artifacts.
///
/// Emits progress stage lines to stderr as each phase runs so the user can
/// follow the long resolve → inspect → build sequence.
fn add_one(
    cache: &FfiCache,
    krate: &CrateSpec,
    features: &[String],
    allow_build_scripts: bool,
    verbose: bool,
) -> Result<(), CliError> {
    use crate::progress::{Mode, Stage};
    let mode = Mode::for_stream(&std::io::stderr());
    let crate_label = krate.name().as_str();

    let stage = Stage::with_mode(std::io::stderr(), mode, format!("resolving {crate_label}…"));
    let json_result = run_inspector(krate, features, allow_build_scripts);
    let json = match json_result {
        Ok(j) => {
            stage.success(format!("resolved {crate_label}"));
            j
        }
        Err(e) => {
            stage.failure(format!("resolve failed for {crate_label}"));
            // A build failure from the inspector is not command-line misuse.
            return Err(match e {
                CliError::UsageOwned(msg) => map_inspector_error(msg),
                other => other,
            });
        }
    };
    // A multi-crate inspector run emits a JSON array; `ipe add` runs one
    // crate, but tolerate the array wrapper by unwrapping a singleton.
    let doc_text = match serde_json::from_str::<serde_json::Value>(&json) {
        Ok(serde_json::Value::Array(items)) if items.len() == 1 => items
            .first()
            .map(serde_json::Value::to_string)
            .unwrap_or(json),
        _ => json,
    };
    // Lift `foreign` declarations from the project's source files and merge them
    // into the inspection document before the driver decodes it, so each
    // author-declared adapter/struct/enum flows through the same `PkgInfo` gate
    // and the unforgeable `FfiInterface` module as an inspected binding.
    let doc_text = match crate::io_bounded::read_to_string_capped(
        std::path::Path::new(PROJECT_MANIFEST),
        crate::io_bounded::MANIFEST_READ_CAP,
    ) {
        Ok(text) => {
            reject_legacy_define_tables(&text)?;
            let src_root = Path::new("src");
            let (closures, structs, enums, opaques) = scan_foreign_defines(src_root)?;
            let sole_dep = rust_dependencies_from_manifest(&text).len() <= 1;
            merge_provides(
                &doc_text,
                krate.name().as_str(),
                &closures,
                &structs,
                &enums,
                &opaques,
                sole_dep,
            )?
        }
        // No manifest (a bare `ipe add` outside a project) ⇒ nothing to merge.
        Err(_) => doc_text,
    };
    let build_stage = Stage::with_mode(std::io::stderr(), mode, format!("building {crate_label}…"));
    let install_result = ipe_ffi::driver::install_from_inspection(cache, &doc_text);
    match install_result {
        Ok((pkg, paths)) => {
            build_stage.success(format!("built {crate_label}"));
            let iface = ipe_ffi::interface::crate_interface(&pkg);
            crate::screen::Screen::new(crate::screen::Stream::Stdout)
                .line(
                    crate::screen::Tone::Text,
                    &format!(
                        "added `{}` v{}: {} bindings ({} skipped) -> {}",
                        pkg.name(),
                        pkg.version(),
                        iface.bindings.len(),
                        iface.skipped.len(),
                        paths.interface.display()
                    ),
                )
                .emit();
            Ok(())
        }
        Err(diag) => {
            build_stage.failure(format!("build failed for {crate_label}"));
            if verbose {
                emit_raw_inspector_log(&doc_text);
            }
            Err(ffi_build_error(diag))
        }
    }
}

/// The file the FFI text inspector reads the `[rust.dependencies]` vocabulary
/// from.
///
/// `package.ipe` cannot yet express `[rust.dependencies]` (the outstanding
/// ergonomic Rust-FFI work), so a native `package.ipe` keeps that vocabulary in
/// a sibling `ipe.toml` sidecar, which is read here. A path that is already an
/// `ipe.toml` (or any non-`package.ipe`) is read as-is, and a `package.ipe`
/// with no sidecar falls back to itself so a pure-Ipê manifest stays a no-op.
fn ffi_vocabulary_source(manifest_path: &Path) -> PathBuf {
    if manifest_path.file_name().and_then(|n| n.to_str()) == Some(PROJECT_MANIFEST)
        && let Some(dir) = manifest_path.parent()
    {
        let sidecar = dir.join(PROJECT_MANIFEST_TOML);
        if sidecar.is_file() {
            return sidecar;
        }
    }
    manifest_path.to_path_buf()
}

/// Returns an error if `text` contains a legacy `[[rust.define.*]]` TOML table.
///
/// `[[rust.define.*]]` is no longer supported; declare FFI types via `foreign`
/// in `src/Ffi/<Crate>.ipe` instead.
fn reject_legacy_define_tables(text: &str) -> Result<(), CliError> {
    if text.contains("[[rust.define.") {
        return Err(CliError::Usage(crate::text::ffi_legacy_define_removed()));
    }
    Ok(())
}

/// Install the registry FFI dependencies declared in `manifest_path`'s
/// `[rust.dependencies]` into the project root's `.ipe/cache/ffi/rust`.
///
/// Used by the package audit gate to regenerate bindings from the pinned crates
/// rather than trusting any committed cache. The generated artifacts are written
/// into the project's own `.ipe/cache/ffi/rust` directory, so the audit gate's
/// ownership check (`is_trusted_cache_dir`) passes — the directory is created by
/// the invoking process under the invoking uid, not world-writable.
///
/// `allow_build_scripts` controls whether the bwrap-jailed inspector runs each
/// crate's build scripts. The audit gate always passes `true` because build
/// scripts run inside the bwrap jail with network access denied; skipping them
/// would silently omit bindings for crates that require them to generate their
/// API surface. The jail, not pre-verification, is the confinement boundary.
///
/// Pure-Ipê manifests without `[rust.dependencies]` or `[rust.wrapper]` are a
/// no-op: the function returns `Ok(())` immediately.
///
/// # Errors
/// [`CliError::Io`] when the manifest cannot be read; [`CliError::UsageOwned`]
/// when the jailed inspector fails or produces an undecodable result.
pub fn install_registry_deps_for_project(
    manifest_path: &Path,
    allow_build_scripts: bool,
) -> Result<(), CliError> {
    let project_root = manifest_path.parent().unwrap_or_else(|| Path::new("."));
    // The `[rust.dependencies]` FFI vocabulary lives in the `ipe.toml` sidecar
    // for a native `package.ipe`, so resolve the source that actually carries it
    // before scanning for dependencies.
    let ffi_source = ffi_vocabulary_source(manifest_path);
    let text = crate::io_bounded::read_to_string_capped(
        &ffi_source,
        crate::io_bounded::MANIFEST_READ_CAP,
    )?;
    let deps = rust_dependencies_from_manifest(&text);
    if deps.is_empty() {
        return Ok(());
    }
    let cache = FfiCache::at_project_root(project_root);
    let mut entries: Vec<(CrateSpec, Vec<String>)> = Vec::with_capacity(deps.len());
    for dep in &deps {
        let name =
            CrateName::parse(&dep.name).map_err(|diag| CliError::UsageOwned(diag.to_string()))?;
        let version = match dep.version.trim() {
            "" | "*" => None,
            pin => Some(
                VersionPin::parse(pin).map_err(|diag| CliError::UsageOwned(diag.to_string()))?,
            ),
        };
        let mut features = Vec::with_capacity(dep.features.len());
        for feat in &dep.features {
            features.push(
                FeatureName::parse(feat)
                    .map_err(|defect| CliError::UsageOwned(defect.to_string()))?,
            );
        }
        let features: Vec<String> = features.iter().map(|f| f.as_str().to_owned()).collect();
        entries.push((CrateSpec::new(name, version), features));
    }
    let json = run_inspector_job(
        &InspectorJob::Manifest { entries: &entries },
        allow_build_scripts,
    )
    .map_err(|e| match e {
        CliError::UsageOwned(msg) => map_inspector_error(msg),
        other => other,
    })?;
    let val: serde_json::Value = serde_json::from_str(&json)
        .map_err(|e| CliError::UsageOwned(text::ffi_regen_invalid_json(&e)))?;
    let items: Vec<serde_json::Value> = match val {
        serde_json::Value::Array(items) => items,
        one @ serde_json::Value::Object(_) => vec![one],
        other => {
            return Err(CliError::UsageOwned(text::ffi_regen_unexpected_shape(
                &other,
            )));
        }
    };
    reject_legacy_define_tables(&text)?;
    // Lift `foreign` declarations from the project's source files.
    let src_root = project_root.join("src");
    let (closures, structs, enums, opaques) = scan_foreign_defines(&src_root)?;
    let sole_dep = deps.len() <= 1;
    for item in &items {
        let item_crate = item
            .get("name")
            .or_else(|| item.get("pkg"))
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| CliError::UsageOwned(text::ffi_regen_item_unnamed(&item)))?
            .to_owned();
        let merged = merge_provides(
            &item.to_string(),
            &item_crate,
            &closures,
            &structs,
            &enums,
            &opaques,
            sole_dep,
        )?;
        ipe_ffi::driver::install_from_inspection(&cache, &merged).map_err(ffi_build_error)?;
    }
    Ok(())
}

/// `ipe rust <add|remove|install> …` — the Rust foreign-function group.
///
/// Bare `ipe rust` prints the group's own `--help` page (the single source of
/// truth in `help::command`). Every subcommand dispatches to the existing FFI
/// command body unchanged.
///
/// # Errors
/// [`CliError`] on an unknown subcommand or any subcommand failure.
pub fn run_rust(rest: &[String]) -> Result<(), CliError> {
    match rest.split_first() {
        // A bare `ipe rust` is misuse, not a help request: fail closed with the
        // usage hint so the dispatcher shows the `--help` page and exits
        // non-zero — matching bare `ipe package`. An explicit `ipe rust --help`
        // is still honoured as a help request upstream.
        None => Err(CliError::Usage(text::rust_usage())),
        Some((sub, args)) if sub == "add" => run_add(args),
        Some((sub, args)) if sub == "remove" => run_remove(args),
        Some((sub, args)) if sub == "install" => run_install(args),
        Some((sub, _)) => Err(crate::cli_args::usage_unknown_subcommand(
            "rust",
            sub,
            "add, remove, or install",
        )),
    }
}

/// `ipe rust add <crate>[@<version>] [--features a,b] [--yes] [--verbose]`.
///
/// # Errors
/// [`CliError`] on misuse, a refused inspection, or a cache-write failure.
pub fn run_add(rest: &[String]) -> Result<(), CliError> {
    let mut krate: Option<String> = None;
    let mut features: Vec<String> = Vec::new();
    let mut assume_yes = false;
    let mut allow_build_scripts = false;
    let mut verbose = false;
    let mut it = rest.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--features" => {
                let raw = it.next().ok_or_else(|| {
                    CliError::UsageOwned(text::flag_needs_value(&"rust add", &"--features"))
                })?;
                // Parse, don't validate: gate each feature name at the boundary
                // before it can reach the emitted manifest's `features` array.
                for feat in raw.split(',') {
                    let gated = FeatureName::parse(feat)
                        .map_err(|defect| CliError::UsageOwned(defect.to_string()))?;
                    features.push(gated.as_str().to_owned());
                }
            }
            "--yes" => assume_yes = true,
            "--allow-build-scripts" => allow_build_scripts = true,
            "--verbose" => verbose = true,
            other if krate.is_none() => krate = Some(other.to_owned()),
            _ => {
                return Err(CliError::Usage(text::rust_add_usage()));
            }
        }
    }
    let raw = krate.ok_or(CliError::Usage(text::rust_add_usage()))?;
    let spec = CrateSpec::parse(&raw).map_err(|diag| CliError::UsageOwned(diag.to_string()))?;

    if !assume_yes {
        use std::io::Write as _;
        crate::screen::chatter(
            crate::screen::Stream::Stderr,
            crate::screen::Tone::Text,
            &ipe_ffi::driver::trust_summary(spec.name(), "", None, 0),
        );
        crate::screen::prompt("[y/N] ");
        let _ = std::io::stdout().flush();
        if !crate::read_yes_no() {
            return Err(CliError::Usage(text::rust_add_aborted()));
        }
    }

    let cache = FfiCache::at_project_root(Path::new("."));
    add_one(&cache, &spec, &features, allow_build_scripts, verbose)
}

/// `ipe rust remove <crate>`.
///
/// # Errors
/// [`CliError`] on misuse or a cache-delete failure.
pub fn run_remove(rest: &[String]) -> Result<(), CliError> {
    let [raw] = rest else {
        return Err(CliError::Usage(text::rust_remove_usage()));
    };
    let cache = FfiCache::at_project_root(Path::new("."));
    let slug = ipe_ffi::driver::slugify(raw);
    cache
        .remove_package(&slug)
        .map_err(|diag| CliError::UsageOwned(diag.to_string()))?;
    crate::screen::Screen::new(crate::screen::Stream::Stdout)
        .line(crate::screen::Tone::Text, &format!("removed `{raw}`"))
        .emit();
    Ok(())
}

/// `ipe rust install [--yes] [--allow-build-scripts] [--verbose]` — (re)inspect every
/// rust-dependency crate the project's manifest binds, honouring each entry's
/// version pin and feature list.
///
/// The manifest's rust-dependency + wrapper vocabulary is read from a legacy
/// `ipe.toml`'s `[rust.dependencies]` / `[rust.wrapper]` TOML sections, the only
/// format the text inspector understands. Reading those bindings out of a
/// `package.ipe` is part of the outstanding ergonomic Rust-FFI work, so a
/// `package.ipe`-only project is refused with that pointer rather than silently
/// installing nothing.
///
/// # Errors
/// [`CliError`] on misuse, a missing manifest, or any per-crate failure.
#[allow(clippy::too_many_lines)] // one linear command body: parse manifest, prompt, inspect, per-crate merge+install
pub fn run_install(rest: &[String]) -> Result<(), CliError> {
    let mut assume_yes = false;
    let mut allow_build_scripts = false;
    let mut verbose = false;
    for flag in rest {
        match flag.as_str() {
            "--yes" => assume_yes = true,
            "--allow-build-scripts" => allow_build_scripts = true,
            "--verbose" => verbose = true,
            _ => {
                return Err(CliError::Usage(text::rust_install_usage()));
            }
        }
    }
    if crate::project::manifest_in_dir(Path::new(".")).is_some() {
        return Err(CliError::Usage(text::rust_install_package_ipe_unsupported()));
    }
    let manifest = Path::new(PROJECT_MANIFEST_TOML);
    if !manifest.is_file() {
        return Err(CliError::Usage(text::rust_install_no_manifest()));
    }
    let text =
        crate::io_bounded::read_to_string_capped(manifest, crate::io_bounded::MANIFEST_READ_CAP)
            .map_err(|e| CliError::UsageOwned(text::command_refusal(&"install", &e)))?;
    let deps = rust_dependencies_from_manifest(&text);
    let wrapper = rust_wrapper_from_manifest(&text);
    if deps.is_empty() && wrapper.is_none() {
        crate::screen::Screen::new(crate::screen::Stream::Stdout)
            .line(
                crate::screen::Tone::Text,
                "ipe install: no [rust.dependencies] or [rust.wrapper] entries",
            )
            .emit();
        return Ok(());
    }
    let cache = FfiCache::at_project_root(Path::new("."));
    // A `[rust.wrapper]` local crate is inspected + bound like any dependency,
    // from its package-jailed path. Processed before the registry deps so a
    // wrapper-only manifest still installs.
    if let Some(w) = &wrapper {
        install_wrapper(&cache, w, assume_yes, allow_build_scripts)?;
    }
    if deps.is_empty() {
        return Ok(());
    }
    // Bare `ipe install` COMPILES every listed untrusted crate — the same
    // build-script/proc-macro RCE surface `ipe add` gates. Prompt once for the
    // whole list; reserve the silent path for an explicit `--yes`.
    if !assume_yes {
        use std::io::Write as _;
        let names: Vec<&str> = deps.iter().map(|d| d.name.as_str()).collect();
        crate::screen::chatter(
            crate::screen::Stream::Stderr,
            crate::screen::Tone::Text,
            &format!(
                "About to fetch and COMPILE untrusted code for {} crate(s): {}\n\
                 Compiling runs each crate's build scripts and proc-macros (inside the isolation jail).",
                names.len(),
                names.join(", ")
            ),
        );
        crate::screen::prompt("Continue? [y/N] ");
        let _ = std::io::stdout().flush();
        if !crate::read_yes_no() {
            return Err(CliError::Usage(text::install_aborted()));
        }
    }
    let mut entries: Vec<(CrateSpec, Vec<String>)> = Vec::with_capacity(deps.len());
    for dep in &deps {
        let name =
            CrateName::parse(&dep.name).map_err(|diag| CliError::UsageOwned(diag.to_string()))?;
        // `*` / empty keep the historical latest-stable resolution; anything
        // else pins the inspector's probe (a prerelease NEEDS an exact `=`).
        let version = match dep.version.trim() {
            "" | "*" => None,
            pin => Some(
                VersionPin::parse(pin).map_err(|diag| CliError::UsageOwned(diag.to_string()))?,
            ),
        };
        // Parse, don't validate: every feature name is gated at the boundary
        // (it is later spliced into the emitted manifest's `features` array).
        let mut features = Vec::with_capacity(dep.features.len());
        for feat in &dep.features {
            features.push(
                FeatureName::parse(feat)
                    .map_err(|defect| CliError::UsageOwned(defect.to_string()))?,
            );
        }
        let features: Vec<String> = features.iter().map(|f| f.as_str().to_owned()).collect();
        entries.push((CrateSpec::new(name, version), features));
    }
    // ONE inspector invocation for the whole list: the cross-crate impl
    // index is process-global, so a trait method defined in one dependency
    // and implemented for a sibling's type (the async-SDK `send` shape)
    // binds only when every crate is inspected together.
    let json = run_inspector_job(
        &InspectorJob::Manifest { entries: &entries },
        allow_build_scripts,
    )
    .map_err(|e| match e {
        CliError::UsageOwned(msg) => map_inspector_error(msg),
        other => other,
    })?;
    let val: serde_json::Value = serde_json::from_str(&json)
        .map_err(|e| CliError::UsageOwned(text::ffi_install_invalid_json(&e)))?;
    let items: Vec<serde_json::Value> = match val {
        serde_json::Value::Array(items) => items,
        one @ serde_json::Value::Object(_) => vec![one],
        other => {
            return Err(CliError::UsageOwned(text::ffi_install_unexpected_shape(
                &other,
            )));
        }
    };
    reject_legacy_define_tables(&text)?;
    // Lift `foreign` declarations from the project's source files; merge them
    // per-crate below. `sole_dep` decides whether an unqualified entry attaches.
    let (closures, structs, enums, opaques) = scan_foreign_defines(Path::new("src"))?;
    let sole_dep = deps.len() <= 1;
    for item in items {
        // The crate's own name, from its inspection document, is the key an
        // unqualified `[[rust.define.closure]]` attaches to under `sole_dep`
        // and a qualified one matches against.
        // The manifest's `[rust.dependencies]` key is the crates.io name (the
        // inspection `name`), so match on it; `pkg` (the lib ident) is the
        // fallback for a legacy document that omits `name`.
        let item_crate = item
            .get("name")
            .or_else(|| item.get("pkg"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_owned();
        let merged = merge_provides(
            &item.to_string(),
            &item_crate,
            &closures,
            &structs,
            &enums,
            &opaques,
            sole_dep,
        )?;
        let (pkg, paths) =
            ipe_ffi::driver::install_from_inspection(&cache, &merged).map_err(|diag| {
                if verbose {
                    emit_raw_inspector_log(&merged);
                }
                ffi_build_error(diag)
            })?;
        let iface = ipe_ffi::interface::crate_interface(&pkg);
        crate::screen::chatter(
            crate::screen::Stream::Stderr,
            crate::screen::Tone::Text,
            &format!(
                "added `{}` v{}: {} bindings ({} skipped) -> {}",
                pkg.name(),
                pkg.version(),
                iface.bindings.len(),
                iface.skipped.len(),
                paths.interface.display()
            ),
        );
    }
    Ok(())
}

/// One `[rust.dependencies]` manifest entry.
#[derive(Debug, PartialEq, Eq)]
struct ManifestDep {
    /// The dependency key (the crates.io package name).
    name: String,
    /// The version requirement (empty when unspecified).
    version: String,
    /// The requested feature list (empty when unspecified).
    features: Vec<String>,
}

/// One `[[rust.define.closure]]` manifest entry — the author-declared surface
/// that turns an Ipê function value into a Rust `dyn Fn` of an exact signature.
///
/// This is Rust-side native code shown to the user under informed consent, like
/// any `[rust.*]` surface; it never routes untrusted text into emitted Rust —
/// the `signature` is re-parsed through the closed [`ipe_ffi`] carrier/bound
/// gate (`ClosureSig`) in the driver's `PkgInfo` decode, so a malformed entry
/// over-drops rather than emit-and-cargo-fail, and the wrapper the driver mints
/// lives in the unforgeable `FfiInterface` module exactly like every other
/// binding (user `.ipe` source still cannot mint a `ForeignCall`).
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ManifestDefineClosure {
    /// The dependency this closure adapter augments (the `[rust.dependencies]`
    /// key). Empty ⇒ attach to the sole dependency (an ambiguity when there is
    /// more than one, refused at merge).
    pub(crate) krate: String,
    /// The wrapper name (the Ipê-facing binding / tri-artifact key).
    pub(crate) name: String,
    /// The exact author-declared target signature, verbatim from the manifest.
    /// It reaches emitted Rust only after re-parsing through `ClosureSig`.
    pub(crate) signature: String,
}

/// One `[[rust.define.struct]]` manifest entry — the author-declared surface
/// that DEFINES a nominal Rust type (a record of owned carrier fields, with an
/// allowlisted `#[derive]` set) plus a constructor wrapper.
///
/// Like the closure surface, this is Rust-side native code shown under informed
/// consent; it never routes untrusted text into emitted Rust — the type name,
/// every field name/type, and every derive re-parse through the driver's closed
/// `StructDef` gate in `PkgInfo` decode, so a malformed entry over-drops rather
/// than emit-and-cargo-fail, and the wrapper lives in the unforgeable
/// `FfiInterface` module exactly like every other binding.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ManifestDefineStruct {
    /// The dependency this struct augments (empty ⇒ the sole dependency).
    pub(crate) krate: String,
    /// The constructor wrapper name (the Ipê-facing binding / tri-artifact key).
    pub(crate) ctor: String,
    /// The Rust type name to define.
    pub(crate) struct_name: String,
    /// The struct fields as `(name, carrier-spelling)` pairs, in order.
    pub(crate) fields: Vec<(String, String)>,
    /// The requested derive tokens (validated against the closed allowlist in
    /// the driver, never rendered raw).
    pub(crate) derives: Vec<String>,
}

/// One `[[rust.define.enum]]` manifest entry — the author-declared surface that
/// DEFINES a nominal Rust `enum` (a sum of unit / tuple-payload variants over
/// owned carriers, with an allowlisted `#[derive]` set) plus one constructor
/// wrapper per variant. This is the P4 `define` form — the shape an Iced/TEA
/// `Message` needs.
///
/// Like the struct surface, this is Rust-side native code shown under informed
/// consent; it never routes untrusted text into emitted Rust — the enum name,
/// every variant name/payload type, and every derive re-parse through the
/// driver's closed `EnumDef` gate in `PkgInfo` decode, so a malformed entry
/// over-drops rather than emit-and-cargo-fail, and the wrappers live in the
/// unforgeable `FfiInterface` module exactly like every other binding.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ManifestDefineEnum {
    /// The dependency this enum augments (empty ⇒ the sole dependency).
    pub(crate) krate: String,
    /// The constructor-wrapper prefix (the Ipê-facing binding / tri-artifact
    /// key). Each variant's constructor is named `<ctor>_<snake(variant)>`.
    pub(crate) ctor: String,
    /// The Rust enum name to define.
    pub(crate) enum_name: String,
    /// The variants as `(name, payload-carrier-spellings)` pairs, in order.
    /// An empty payload list is a unit variant.
    pub(crate) variants: Vec<(String, Vec<String>)>,
    /// The requested derive tokens (validated against the closed allowlist in
    /// the driver, never rendered raw).
    pub(crate) derives: Vec<String>,
}

/// Extract the manifest's `[rust.dependencies]` / `["rust.dependencies"]`
/// entries. Values may be a bare version string (`uuid = "1"`) or an inline
/// table (`stripe = { version = "=1.0.0-rc.6", features = ["a", "b"] }`).
/// A raw `[rust.wrapper]` manifest table: the local wrapper-crate path, the
/// public symbols to bind, and the (accepted-but-not-enforced) capability set.
/// Every field is carried verbatim; `ipe_ffi::wrapper::WrapperManifest::parse`
/// is the gate that validates the path (package-jailed) and each symbol.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct RawWrapperTable {
    pub(crate) path: String,
    pub(crate) expose: Vec<String>,
    pub(crate) capabilities: Vec<String>,
}

/// Read the single `[rust.wrapper]` table from a manifest, or `None` when the
/// package declares no wrapper crate. Line-based, matching the other
/// `[rust.*]` readers here (no TOML dependency in this crate).
pub(crate) fn rust_wrapper_from_manifest(text: &str) -> Option<RawWrapperTable> {
    let mut in_table = false;
    let mut table = RawWrapperTable::default();
    let mut found = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_table = crate::project::is_rust_wrapper_header(line);
            if in_table {
                found = true;
            }
            continue;
        }
        if !in_table || line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let key = k.trim().trim_matches('"');
        let value = v.trim();
        match key {
            "path" => value.trim_matches('"').clone_into(&mut table.path),
            "expose" => table.expose = parse_string_array(value),
            "capabilities" => table.capabilities = parse_string_array(value),
            _ => {}
        }
    }
    found.then_some(table)
}

/// Parse a `["a", "b"]` inline array into its string elements.
fn parse_string_array(value: &str) -> Vec<String> {
    let inner = value
        .trim()
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(value);
    inner
        .split(',')
        .map(|s| s.trim().trim_matches('"').to_owned())
        .filter(|s| !s.is_empty())
        .collect()
}

fn rust_dependencies_from_manifest(text: &str) -> Vec<ManifestDep> {
    let mut in_table = false;
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_table = line == "[rust.dependencies]" || line == "[\"rust.dependencies\"]";
            continue;
        }
        if !in_table || line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let name = k.trim().trim_matches('"').to_owned();
            let value = v.trim();
            if let Some(body) = value
                .strip_prefix('{')
                .and_then(|rest| rest.strip_suffix('}'))
            {
                out.push(ManifestDep {
                    name,
                    version: inline_table_string(body, "version").unwrap_or_default(),
                    features: inline_table_string_array(body, "features"),
                });
            } else {
                out.push(ManifestDep {
                    name,
                    version: value.trim_matches('"').to_owned(),
                    features: Vec::new(),
                });
            }
        }
    }
    out
}

/// Read `key = "value"` out of an inline-table body.
fn inline_table_string(body: &str, key: &str) -> Option<String> {
    let at = find_inline_key(body, key)?;
    let rest = body.get(at..)?;
    let (_, after_eq) = rest.split_once('=')?;
    let after_quote = after_eq.trim_start().strip_prefix('"')?;
    after_quote.split_once('"').map(|(v, _)| v.to_owned())
}

/// Read `key = ["a", "b"]` out of an inline-table body.
fn inline_table_string_array(body: &str, key: &str) -> Vec<String> {
    let Some(at) = find_inline_key(body, key) else {
        return Vec::new();
    };
    let Some(rest) = body.get(at..) else {
        return Vec::new();
    };
    let Some((_, after_eq)) = rest.split_once('=') else {
        return Vec::new();
    };
    let Some(after_bracket) = after_eq.trim_start().strip_prefix('[') else {
        return Vec::new();
    };
    let Some((inner, _)) = after_bracket.split_once(']') else {
        return Vec::new();
    };
    inner
        .split(',')
        .map(|s| s.trim().trim_matches('"').to_owned())
        .filter(|s| !s.is_empty())
        .collect()
}

/// The byte offset of `key` as a whole word in an inline-table body (so
/// `version` never matches inside `some_version_like_name`).
fn find_inline_key(body: &str, key: &str) -> Option<usize> {
    let bytes = body.as_bytes();
    let mut from = 0;
    while let Some(rel) = body.get(from..)?.find(key) {
        let at = from + rel;
        let before_ok = at == 0
            || bytes
                .get(at.wrapping_sub(1))
                .is_none_or(|b| !b.is_ascii_alphanumeric() && *b != b'_');
        let after = at + key.len();
        let after_ok = bytes
            .get(after)
            .is_none_or(|b| !b.is_ascii_alphanumeric() && *b != b'_');
        if before_ok && after_ok {
            return Some(at);
        }
        from = at + key.len();
    }
    None
}

/// The `snake_case` of a Rust type name (`CounterState` → `counter_state`), for
/// the default constructor-wrapper name.
pub(crate) fn to_snake_case(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 4);
    for (i, c) in s.chars().enumerate() {
        if c.is_ascii_uppercase() {
            if i != 0 {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// Whether a `[[rust.define.*]]` entry keyed by `entry_crate` attaches to
/// `crate_name`: a qualified entry matches by name; an unqualified one attaches
/// only when the crate is the SOLE dependency (`sole_dep`).
fn define_attaches(entry_crate: &str, crate_name: &str, sole_dep: bool) -> bool {
    if entry_crate.is_empty() {
        sole_dep
    } else {
        entry_crate == crate_name
    }
}

/// Refuse an unqualified `[[rust.define.*]]` entry under a multi-crate manifest
/// (it cannot be attributed to one crate — parse, don't validate at the manifest
/// boundary). `kind` names the surface for the diagnostic; `name` the entry.
fn reject_ambiguous_define<'a>(
    kind: &str,
    sole_dep: bool,
    mut unqualified: impl Iterator<Item = &'a str>,
) -> Result<(), CliError> {
    if !sole_dep && let Some(name) = unqualified.next() {
        return Err(CliError::UsageOwned(text::ffi_define_crate_ambiguous(
            &kind, &name,
        )));
    }
    Ok(())
}

/// Merge every `[[rust.define.closure]]` / `[[rust.define.struct]]` entry that
/// targets `crate_name` into the crate's inspection JSON, as synthetic
/// `functions` carrying the wire flags the driver's `PkgInfo` decode reads.
///
/// The driver's `install_from_inspection` already accepts the merged document
/// and decodes each synthetic entry through the same gate as an inspected
/// function (an ill-formed `signature`/struct over-drops at decode, never
/// emit-and-cargo-fail). The trust gate is intact: the entry is author-declared
/// native code the driver mints into the `FfiInterface` module — user `.ipe`
/// source never sees it.
///
/// An entry whose `crate` is empty attaches to `crate_name` only when it is the
/// SOLE dependency (`sole_dep`); an unqualified entry under a multi-crate
/// manifest is ambiguous and refused, never silently attached to every crate.
/// Refuse any unqualified `foreign`/`[[rust.define.*]]` entry under a
/// multi-crate manifest, across all four surfaces (closure/struct/enum/opaque).
fn reject_ambiguous_defines(
    closures: &[ManifestDefineClosure],
    structs: &[ManifestDefineStruct],
    enums: &[ManifestDefineEnum],
    opaques: &[ManifestDefineOpaque],
    sole_dep: bool,
) -> Result<(), CliError> {
    reject_ambiguous_define(
        "closure",
        sole_dep,
        closures
            .iter()
            .filter(|c| c.krate.is_empty())
            .map(|c| c.name.as_str()),
    )?;
    reject_ambiguous_define(
        "struct",
        sole_dep,
        structs
            .iter()
            .filter(|s| s.krate.is_empty())
            .map(|s| s.ctor.as_str()),
    )?;
    reject_ambiguous_define(
        "enum",
        sole_dep,
        enums
            .iter()
            .filter(|e| e.krate.is_empty())
            .map(|e| e.ctor.as_str()),
    )?;
    reject_ambiguous_define(
        "opaque",
        sole_dep,
        opaques
            .iter()
            .filter(|o| o.krate.is_empty())
            .map(|o| o.ipe_name.as_str()),
    )
}

/// Build the synthetic `functions` entries the driver decodes for every
/// closure/struct/enum define that attaches to `crate_name` — the DEFINE
/// surfaces that mint a Rust type or adapter. Opaque declarations are NOT
/// functions; they merge into `declaredOpaques` separately.
fn build_synthetic_functions(
    crate_name: &str,
    closures: &[ManifestDefineClosure],
    structs: &[ManifestDefineStruct],
    enums: &[ManifestDefineEnum],
    sole_dep: bool,
) -> Vec<serde_json::Value> {
    closures
        .iter()
        .filter(|c| define_attaches(&c.krate, crate_name, sole_dep))
        .map(|c| {
            serde_json::json!({
                "name": c.name,
                "effect": "pure",
                "isClosureAdapter": true,
                "closureSig": c.signature,
            })
        })
        .chain(
            structs
                .iter()
                .filter(|s| define_attaches(&s.krate, crate_name, sole_dep))
                .map(|s| {
                    let fields: Vec<serde_json::Value> = s
                        .fields
                        .iter()
                        .map(|(n, t)| serde_json::json!({ "name": n, "type": t }))
                        .collect();
                    serde_json::json!({
                        "name": s.ctor,
                        "effect": "pure",
                        "isStructCtor": true,
                        "structName": s.struct_name,
                        "structFields": fields,
                        "structDerives": s.derives,
                    })
                }),
        )
        .chain(
            enums
                .iter()
                .filter(|e| define_attaches(&e.krate, crate_name, sole_dep))
                .map(|e| {
                    let variants: Vec<serde_json::Value> = e
                        .variants
                        .iter()
                        .map(|(n, payload)| serde_json::json!({ "name": n, "payload": payload }))
                        .collect();
                    serde_json::json!({
                        "name": e.ctor,
                        "effect": "pure",
                        "isEnumDef": true,
                        "enumName": e.enum_name,
                        "enumVariants": variants,
                        "enumDerives": e.derives,
                    })
                }),
        )
        .collect()
}

fn merge_provides(
    inspection_json: &str,
    crate_name: &str,
    closures: &[ManifestDefineClosure],
    structs: &[ManifestDefineStruct],
    enums: &[ManifestDefineEnum],
    opaques: &[ManifestDefineOpaque],
    sole_dep: bool,
) -> Result<String, CliError> {
    reject_ambiguous_defines(closures, structs, enums, opaques, sole_dep)?;
    let synthetic = build_synthetic_functions(crate_name, closures, structs, enums, sole_dep);
    let attached_opaques: Vec<&ManifestDefineOpaque> = opaques
        .iter()
        .filter(|o| define_attaches(&o.krate, crate_name, sole_dep))
        .collect();
    if synthetic.is_empty() && attached_opaques.is_empty() {
        return Ok(inspection_json.to_owned());
    }
    let mut doc: serde_json::Value = serde_json::from_str(inspection_json)
        .map_err(|e| CliError::UsageOwned(text::ffi_inspection_not_object_detail(&e)))?;
    if !synthetic.is_empty() {
        let obj = doc
            .as_object_mut()
            .ok_or_else(|| CliError::UsageOwned(text::ffi_inspection_not_object().to_owned()))?;
        let serde_json::Value::Array(functions) = obj
            .entry("functions")
            .or_insert_with(|| serde_json::Value::Array(Vec::new()))
        else {
            return Err(CliError::UsageOwned(
                text::ffi_inspection_functions_not_array().to_owned(),
            ));
        };
        functions.extend(synthetic);
    }
    merge_declared_opaques(&mut doc, crate_name, &attached_opaques)?;
    Ok(doc.to_string())
}

/// Resolve each attached `foreign … kind = Opaque "<Type>"` against the crate's
/// own inspection and merge the survivors into the doc's `declaredOpaques` map
/// (Ipê handle nominal → absolute Rust path).
///
/// Fail-closed at every step, so a handle is minted only over a type the
/// inspector actually reported AND left opaque:
///   - the named type must appear in the inspection's reported `types`;
///   - it must NOT have surfaced transparently (a transparent record/union is a
///     value type, not a handle) — a transparent target is refused;
///   - the resolved Rust path is rendered absolute (`::crate::Type`) so it
///     matches the opaque-path spelling the emitter and the asserted-call
///     validator resolve against.
fn merge_declared_opaques(
    doc: &mut serde_json::Value,
    crate_name: &str,
    opaques: &[&ManifestDefineOpaque],
) -> Result<(), CliError> {
    if opaques.is_empty() {
        return Ok(());
    }
    // The inspection's reported foreign types: `{ name, rustPath, kind }`. A
    // classification error leaves a type opaque, so this reads the RAW reports
    // and treats a transparent classification (via `ForeignTypeCatalog`) as the
    // only disqualifier — everything else the inspector reported stays a handle.
    let types = doc
        .get("types")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let transparent = transparent_type_names(&types);

    let mut declared: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
    for o in opaques {
        let reported = types.iter().find(|t| {
            t.get("name").and_then(serde_json::Value::as_str) == Some(o.rust_type.as_str())
        });
        let Some(reported) = reported else {
            return Err(CliError::UsageOwned(text::ffi_opaque_unknown_type(
                &o.ipe_name,
                &o.rust_type,
                &crate_name,
            )));
        };
        if transparent.contains(o.rust_type.as_str()) {
            return Err(CliError::UsageOwned(text::ffi_opaque_is_transparent(
                &o.ipe_name,
                &o.rust_type,
            )));
        }
        let rust_path = reported
            .get("rustPath")
            .and_then(serde_json::Value::as_str)
            .filter(|p| !p.is_empty())
            .ok_or_else(|| {
                CliError::UsageOwned(text::ffi_opaque_without_path(&o.ipe_name, &o.rust_type))
            })?;
        let absolute = if rust_path.starts_with("::") {
            rust_path.to_owned()
        } else {
            format!("::{rust_path}")
        };
        if let Some(prev) = declared.get(o.ipe_name.as_str())
            && prev.as_str() != Some(absolute.as_str())
        {
            return Err(CliError::UsageOwned(text::ffi_opaque_declared_twice(
                &o.ipe_name,
            )));
        }
        declared.insert(o.ipe_name.clone(), serde_json::Value::String(absolute));
    }
    if let Some(obj) = doc.as_object_mut() {
        obj.insert(
            "declaredOpaques".to_owned(),
            serde_json::Value::Object(declared),
        );
    }
    Ok(())
}

/// The reported-type names the representation classifier surfaces TRANSPARENTLY
/// (a value record or closed union) — the set a `foreign … Opaque` target may
/// not name, since a transparent type is a value, not a handle.
fn transparent_type_names(types: &[serde_json::Value]) -> BTreeSet<String> {
    let doc = serde_json::json!({
        "pkg": "opaque_probe",
        "name": "opaque_probe",
        "version": "0.0.0",
        "errors": [],
        "types": types,
    });
    // A probe decode failure never widens the opaque surface: if the axis cannot
    // be classified, treat nothing as transparent (the inspected-type membership
    // check is the primary gate).
    ipe_ffi::pkginfo::PkgInfo::decode_json(&doc.to_string()).map_or_else(
        |_| BTreeSet::new(),
        |pkg| pkg.foreign_types().transparent().keys().cloned().collect(),
    )
}

/// One `foreign X = { crate = "…", kind = Opaque "<Type>" }` declaration — an
/// OPAQUE Ipê handle minted over a crate type the inspector reports but does not
/// destructure (a `Connection`, `Hasher`, …). No fields, no constructor: the
/// handle is a runtime-owned resource whose value never crosses transparently.
///
/// The declaration DECLARES the nominal so a `.fn` method that takes or returns
/// the handle (`connect : () -> Connection`) resolves against the crate's opaque
/// map without the program importing `Rust.<Crate>`. It is fail-closed: the named
/// type must be an inspected opaque type of the crate (a reported `types` entry
/// that did NOT surface transparently) — an un-inspectable or transparent target
/// is refused at merge, never minted blind.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ManifestDefineOpaque {
    /// The dependency this handle names (empty ⇒ the sole dependency).
    pub(crate) krate: String,
    /// The Ipê-facing handle nominal (the `foreign <Name>` head).
    pub(crate) ipe_name: String,
    /// The inspected crate type's reported name — resolved to its absolute Rust
    /// path against the crate's inspection at merge, then validated opaque.
    pub(crate) rust_type: String,
}

/// A single `foreign` declaration extracted from a `.ipe` source file, ready for
/// lifting into a `ManifestDefine*` value.
///
/// Four shapes, each selected by the record's `kind` field:
///
/// - `Struct` — `{ crate = "…", kind = Struct { field = Carrier }, derives = [ … ] }`
/// - `Enum`   — `{ crate = "…", kind = Enum [ Variant "Name" [ Carrier ] ], derives = [ … ] }`
/// - `Closure`— `{ crate = "…", kind = Closure { args = [ Carrier ], returns = Carrier } }`
/// - `Opaque` — `{ crate = "…", kind = Opaque "<Type>" }`
///
/// The `Struct`/`Enum`/`Closure` shapes DEFINE a nominal in the emitted
/// `_bindings.rs`, byte-identical to what the TOML `[[rust.define.*]]` readers
/// produced; `Opaque` DECLARES a handle over an existing inspected crate type.
#[derive(Debug, PartialEq, Eq)]
enum ForeignDefine {
    Struct(ManifestDefineStruct),
    Enum(ManifestDefineEnum),
    Closure(ManifestDefineClosure),
    Opaque(ManifestDefineOpaque),
}

/// The tuple returned by `scan_foreign_defines`:
/// `(closures, structs, enums, opaques)`.
type ForeignDefines = (
    Vec<ManifestDefineClosure>,
    Vec<ManifestDefineStruct>,
    Vec<ManifestDefineEnum>,
    Vec<ManifestDefineOpaque>,
);

/// Walk every `.ipe` source file reachable from `src_root`, parse each module,
/// and extract its `foreign` declarations, lifting each inert `Foreign` record
/// into a `ManifestDefine*` value through the same record-reading discipline the
/// package-manifest pipeline uses.
///
/// A parse error in any source module is silently skipped here — the compile
/// pipeline will surface it with full context moments later. A malformed
/// `foreign` declaration (invalid carrier, unknown kind, …) is a typed refusal
/// returned as an `Err` with a `CliError::UsageOwned` carrying the source path
/// and reason; the caller decides whether to propagate it immediately or defer.
///
/// The returned vectors are the exact same `ManifestDefine*` shapes the TOML
/// readers produce, so they feed unchanged into `merge_provides`.
pub(crate) fn scan_foreign_defines(src_root: &Path) -> Result<ForeignDefines, CliError> {
    let mut closures = Vec::new();
    let mut structs = Vec::new();
    let mut enums = Vec::new();
    let mut opaques = Vec::new();

    let mut ipe_files = Vec::new();
    collect_ipe_files(src_root, &mut ipe_files)?;
    ipe_files.sort();

    for file in &ipe_files {
        let Ok(text) =
            crate::io_bounded::read_to_string_capped(file, crate::io_bounded::MANIFEST_READ_CAP)
        else {
            continue;
        };
        // Fast reject: skip files with no `foreign` keyword.
        if !text.contains("foreign") {
            continue;
        }
        let mut interner = ipe_intern::Interner::new();
        let Ok(module) = ipe_parse::parse_module(&text, &mut interner) else {
            continue; // compile pipeline surfaces parse errors
        };
        if module.foreigns.is_empty() {
            continue;
        }
        let reader = ForeignReader {
            interner: &interner,
            src: &text,
            file,
        };
        for foreign in &module.foreigns {
            match reader.lift_foreign(foreign)? {
                ForeignDefine::Struct(s) => structs.push(s),
                ForeignDefine::Enum(e) => enums.push(e),
                ForeignDefine::Closure(c) => closures.push(c),
                ForeignDefine::Opaque(o) => opaques.push(o),
            }
        }
    }
    Ok((closures, structs, enums, opaques))
}

/// Recursively collect every `.ipe` file under `dir`.
fn collect_ipe_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), CliError> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Ok(()); // missing or unreadable source dir — compiler reports it
    };
    for entry in entries {
        let Ok(entry) = entry else { continue };
        let path = entry.path();
        let Ok(ft) = entry.file_type() else { continue };
        if ft.is_dir() {
            collect_ipe_files(&path, out)?;
        } else if path.extension().and_then(|e| e.to_str()) == Some("ipe") {
            out.push(path);
        }
    }
    Ok(())
}

/// Borrowed context for lifting one `ForeignDecl` into a `ForeignDefine`.
struct ForeignReader<'a> {
    interner: &'a ipe_intern::Interner,
    src: &'a str,
    file: &'a Path,
}

impl ForeignReader<'_> {
    /// Resolve a `Symbol` to its interned text, or `""` on failure.
    fn text(&self, sym: ipe_intern::Symbol) -> &str {
        self.interner.resolve(sym).unwrap_or("")
    }

    /// Emit a typed refusal with a source location prefix.
    fn reject(&self, span: ipe_diagnostics::Span, reason: &str) -> CliError {
        let (line, col) = line_col_from_span(self.src, span.lo);
        CliError::UsageOwned(text::located_refusal(
            &self.file.display(),
            &line,
            &col,
            &reason,
        ))
    }

    /// Lift one `ForeignDecl` into a `ForeignDefine`, refusing with a span if the
    /// declaration body is not a valid inert `Foreign` record.
    ///
    /// The body is a record literal `{ crate = "…", kind = <Kind>, derives = [ … ] }`.
    /// `crate` and `kind` are required; `derives` and `ctor` are optional. The
    /// `kind` field selects the shape — `Struct { … }`, `Enum [ … ]`,
    /// `Closure { … }`, or `Opaque` — and each maps to the same `ManifestDefine*`
    /// value the TOML `[[rust.define.*]]` reader produces, so emitted Rust is
    /// unchanged. No field holds a function or effect: reading the record runs no
    /// author code.
    fn lift_foreign(
        &self,
        foreign: &ipe_diagnostics::Located<ipe_syntax::ForeignDecl>,
    ) -> Result<ForeignDefine, CliError> {
        let decl = &foreign.value;
        let name_text = self.text(decl.name.value).to_owned();

        let fields = self.expect_record(&decl.body)?;

        let mut krate: Option<String> = None;
        let mut kind_expr: Option<&ipe_syntax::Expr> = None;
        let mut derives: Vec<String> = Vec::new();
        let mut ctor: Option<String> = None;
        for (fname_loc, value) in fields {
            match self.text(fname_loc.value) {
                "crate" => krate = Some(self.expect_string(value)?),
                "kind" => kind_expr = Some(value),
                "derives" => derives = self.read_derives(value)?,
                "ctor" => ctor = Some(self.expect_string(value)?),
                other => {
                    return Err(self.reject(
                        fname_loc.span,
                        &format!(
                            "`{other}` is not a `Foreign` field — use `crate`, `kind`, \
                             `derives`, or `ctor`"
                        ),
                    ));
                }
            }
        }

        let krate = krate.ok_or_else(|| {
            self.reject(
                foreign.span,
                "a `foreign` declaration needs a `crate = \"<crate-name>\"` field",
            )
        })?;
        let kind_expr = kind_expr.ok_or_else(|| {
            self.reject(
                foreign.span,
                "a `foreign` declaration needs a `kind = <Struct|Enum|Closure|Opaque>` field",
            )
        })?;

        self.lift_kind(foreign, kind_expr, krate, name_text, derives, ctor)
    }

    /// Decode the `kind` field of a `Foreign` record into a `ForeignDefine`,
    /// carrying the already-read `crate`/`derives`/`ctor` fields.
    fn lift_kind(
        &self,
        foreign: &ipe_diagnostics::Located<ipe_syntax::ForeignDecl>,
        kind_expr: &ipe_syntax::Expr,
        krate: String,
        name: String,
        derives: Vec<String>,
        ctor: Option<String>,
    ) -> Result<ForeignDefine, CliError> {
        let (ctor_name, args) = self.expect_ctor_app(kind_expr, "a `kind`")?;
        match ctor_name {
            "Struct" => self.lift_struct(foreign, args, krate, name, derives, ctor),
            "Enum" => self.lift_enum(foreign, args, krate, name, derives, ctor),
            "Closure" => self.lift_closure(foreign, args, krate, name),
            "Opaque" => self.lift_opaque(foreign, args, krate, name),
            other => Err(self.reject(
                kind_expr.span,
                &format!(
                    "`{other}` is not a `kind` — use `Struct {{ … }}`, `Enum [ … ]`, \
                     `Closure {{ … }}`, or `Opaque \"<Type>\"`."
                ),
            )),
        }
    }

    /// Lift a `kind = Opaque "<Type>"` payload into a `ManifestDefineOpaque`. The
    /// argument is a single string LITERAL naming the inspected crate type; the
    /// fail-closed "must be an inspected opaque type" check happens later at
    /// `merge_provides`, where the crate's inspection is in hand.
    fn lift_opaque(
        &self,
        foreign: &ipe_diagnostics::Located<ipe_syntax::ForeignDecl>,
        args: &[ipe_syntax::Expr],
        krate: String,
        ipe_name: String,
    ) -> Result<ForeignDefine, CliError> {
        let type_arg = args.first().ok_or_else(|| {
            self.reject(
                foreign.span,
                "`Opaque` requires a string type argument `Opaque \"<Type>\"`",
            )
        })?;
        if args.len() > 1 {
            return Err(self.reject(
                type_arg.span,
                "`Opaque` takes exactly one string type argument `Opaque \"<Type>\"`",
            ));
        }
        let rust_type = self.expect_string(type_arg)?;
        if rust_type.is_empty() {
            return Err(self.reject(
                type_arg.span,
                "`Opaque` type name must not be empty — name the crate's reported type",
            ));
        }
        Ok(ForeignDefine::Opaque(ManifestDefineOpaque {
            krate,
            ipe_name,
            rust_type,
        }))
    }

    /// Lift a `kind = Struct { field = Carrier, … }` payload into a
    /// `ManifestDefineStruct`, byte-identical to the TOML path.
    fn lift_struct(
        &self,
        foreign: &ipe_diagnostics::Located<ipe_syntax::ForeignDecl>,
        args: &[ipe_syntax::Expr],
        krate: String,
        struct_name: String,
        derives: Vec<String>,
        ctor: Option<String>,
    ) -> Result<ForeignDefine, CliError> {
        let record_arg = args.first().ok_or_else(|| {
            self.reject(
                foreign.span,
                "`Struct` requires a record argument `{ field = Carrier }`",
            )
        })?;
        let fields = self.read_struct_fields(record_arg)?;
        if fields.is_empty() {
            return Err(self.reject(
                foreign.span,
                "a `foreign` struct declaration must have at least one field",
            ));
        }

        let ctor = ctor.unwrap_or_else(|| format!("{}_new", to_snake_case(&struct_name)));
        Ok(ForeignDefine::Struct(ManifestDefineStruct {
            krate,
            ctor,
            struct_name,
            fields,
            derives,
        }))
    }

    /// Lift a `kind = Enum [ Variant "Name" [ Carrier, … ], … ]` payload into a
    /// `ManifestDefineEnum`, byte-identical to the TOML path.
    fn lift_enum(
        &self,
        foreign: &ipe_diagnostics::Located<ipe_syntax::ForeignDecl>,
        args: &[ipe_syntax::Expr],
        krate: String,
        enum_name: String,
        derives: Vec<String>,
        ctor: Option<String>,
    ) -> Result<ForeignDefine, CliError> {
        let list_arg = args.first().ok_or_else(|| {
            self.reject(
                foreign.span,
                "`Enum` requires a variant list `[ Variant \"Name\" [ … ], … ]`",
            )
        })?;
        let variants = self.read_enum_variants(list_arg)?;
        if variants.is_empty() {
            return Err(self.reject(
                foreign.span,
                "a `foreign` enum declaration must have at least one variant",
            ));
        }

        let ctor = ctor.unwrap_or_else(|| format!("{}_new", to_snake_case(&enum_name)));
        Ok(ForeignDefine::Enum(ManifestDefineEnum {
            krate,
            ctor,
            enum_name,
            variants,
            derives,
        }))
    }

    /// Lift a `kind = Closure { args = [ Carrier, … ], returns = Carrier }`
    /// payload into a `ManifestDefineClosure`, byte-identical to the TOML path.
    ///
    /// The record builds the canonical `Fn(P0, P1, …) -> R + Send + Sync +
    /// 'static` signature string the driver's `ClosureSig::parse` consumes; the
    /// bound set `{Send, Sync, 'static}` is implicit (the only set the sync adapter
    /// supports).
    fn lift_closure(
        &self,
        foreign: &ipe_diagnostics::Located<ipe_syntax::ForeignDecl>,
        args: &[ipe_syntax::Expr],
        krate: String,
        name: String,
    ) -> Result<ForeignDefine, CliError> {
        let record_arg = args.first().ok_or_else(|| {
            self.reject(
                foreign.span,
                "`Closure` requires a record argument `{ args = [ … ], returns = Carrier }`",
            )
        })?;
        let signature = self.read_closure_signature(record_arg)?;
        Ok(ForeignDefine::Closure(ManifestDefineClosure {
            krate,
            name,
            signature,
        }))
    }

    /// Read a `{ args = [ Carrier, … ], returns = Carrier }` record into the
    /// `Fn(P0, …) -> R + Send + Sync + 'static` signature string the driver
    /// decodes via `ClosureSig::parse`.
    ///
    /// Carriers are bare upper-case names: `Int`, `Float`, `Bool`, `Char`,
    /// `String`, `Bytes`, or an opaque handle name. An unknown carrier is
    /// rejected with a span.
    fn read_closure_signature(&self, expr: &ipe_syntax::Expr) -> Result<String, CliError> {
        let fields = self.expect_record(expr)?;
        let mut args_expr: Option<&ipe_syntax::Expr> = None;
        let mut returns_expr: Option<&ipe_syntax::Expr> = None;
        for (fname_loc, value) in fields {
            match self.text(fname_loc.value) {
                "args" => args_expr = Some(value),
                "returns" => returns_expr = Some(value),
                other => {
                    return Err(self.reject(
                        fname_loc.span,
                        &format!("`{other}` is not a `Closure` field — use `args` or `returns`"),
                    ));
                }
            }
        }
        let args_expr = args_expr
            .ok_or_else(|| self.reject(expr.span, "`Closure` requires an `args = [ … ]` field"))?;
        let returns_expr = returns_expr.ok_or_else(|| {
            self.reject(expr.span, "`Closure` requires a `returns = Carrier` field")
        })?;

        let params = self.read_carrier_list(args_expr)?;
        let ret = self.read_carrier_type_from_expr(returns_expr)?;

        let sig = format!(
            "Fn({}) -> {} + Send + Sync + 'static",
            params.join(", "),
            ret
        );
        Ok(sig)
    }

    /// Read a list-literal of carrier names into their canonical spellings.
    fn read_carrier_list(&self, expr: &ipe_syntax::Expr) -> Result<Vec<String>, CliError> {
        use ipe_syntax::Expr_;
        let Expr_::List(items) = &expr.value else {
            return Err(self.reject(expr.span, "expected a list of carriers `[ Int, … ]`"));
        };
        items
            .iter()
            .map(|item| self.read_carrier_type_from_expr(item))
            .collect()
    }

    /// Read a `Struct { field = Carrier, … }` record payload into
    /// `(field-name, carrier-spelling)` pairs, in source order.
    ///
    /// In Ipê expression context, record literals use `=` for field assignment:
    /// `{ value = Int }`. The right-hand side is an upper-case name (a blessed
    /// carrier: `Int`, `String`, `Bool`, `Char`, `Float`, `Bytes`) or an opaque
    /// handle name (any bare upper-case identifier).
    fn read_struct_fields(
        &self,
        expr: &ipe_syntax::Expr,
    ) -> Result<Vec<(String, String)>, CliError> {
        let fields = self.expect_record(expr)?;
        let mut out = Vec::new();
        for (name_loc, val_expr) in fields {
            let field_name = self.text(name_loc.value).to_owned();
            let carrier = self.read_carrier_type_from_expr(val_expr)?;
            out.push((field_name, carrier));
        }
        Ok(out)
    }

    /// Read a carrier spelling from an expression that represents a field value
    /// in a record literal `{ field = Int }`. The parser produces `Int` as
    /// `Expr_::VarLocal("Int")`.
    fn read_carrier_type_from_expr(&self, expr: &ipe_syntax::Expr) -> Result<String, CliError> {
        use ipe_syntax::Expr_;
        match &expr.value {
            // Bare upper-case names: `Int`, `Float`, `Bool`, `Char`, `String`, `Bytes`,
            // or any opaque handle whose name starts with an ASCII upper-case letter.
            Expr_::VarLocal(sym) => {
                let n = self.text(*sym);
                match n {
                    "Int" => Ok("Int".to_owned()),
                    "Float" => Ok("Float".to_owned()),
                    "Bool" => Ok("Bool".to_owned()),
                    "Char" => Ok("Char".to_owned()),
                    "String" => Ok("String".to_owned()),
                    "Bytes" => Ok("Bytes".to_owned()),
                    other if other.chars().next().is_some_and(|c| c.is_ascii_uppercase()) => {
                        // Upper-case bare name → opaque handle.
                        Ok(other.to_owned())
                    }
                    other => Err(self.reject(
                        expr.span,
                        &format!(
                            "`{other}` is not a valid field carrier — use `Int`, `Float`, `Bool`, \
                             `Char`, `String`, `Bytes`, or an upper-case opaque handle name"
                        ),
                    )),
                }
            }
            _ => Err(self.reject(
                expr.span,
                "expected a field carrier (`Int`, `String`, …) as a bare upper-case name",
            )),
        }
    }

    /// Read a `derives = [ Default, Clone, Debug, … ]` list into derive token
    /// strings. Each element is a bare upper-case constructor naming a Rust
    /// derive; the closed allowlist (`ffi_derive_name`) is the single source of
    /// truth, so a misspelt derive is a refusal, never emitted Rust.
    fn read_derives(&self, expr: &ipe_syntax::Expr) -> Result<Vec<String>, CliError> {
        let items = self.expect_list(expr)?;
        let mut out = Vec::new();
        for item in items {
            let name = self.expect_ctor(item, "a derive")?;
            let derive = ffi_derive_name(name).ok_or_else(|| {
                self.reject(
                    item.span,
                    &format!(
                        "`{name}` is not a recognised derive — accepted: \
                         `Default`, `Clone`, `Debug`, `Copy`, `PartialEq`, `Eq`, \
                         `PartialOrd`, `Ord`, `Hash`"
                    ),
                )
            })?;
            out.push(derive.to_owned());
        }
        Ok(out)
    }

    /// Read a `[ Variant "Name" [ Carrier, … ], … ]` list into
    /// `(variant-name, payload-carrier-spellings)` pairs.
    fn read_enum_variants(
        &self,
        expr: &ipe_syntax::Expr,
    ) -> Result<Vec<(String, Vec<String>)>, CliError> {
        let items = self.expect_list(expr)?;
        let mut out = Vec::new();
        for item in items {
            let (ctor, args) = self.expect_ctor_app(item, "a variant")?;
            if ctor != "Variant" {
                return Err(self.reject(
                    item.span,
                    &format!("`{ctor}` is not a variant — use `Variant \"Name\" [ Carrier, … ]`"),
                ));
            }
            let name_arg = args.first().ok_or_else(|| {
                self.reject(item.span, "`Variant` requires a string name argument")
            })?;
            let variant_name = self.expect_string(name_arg)?;
            if variant_name.is_empty()
                || !variant_name
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_uppercase())
            {
                return Err(self.reject(
                    item.span,
                    "a variant name must be a non-empty upper-case identifier",
                ));
            }
            let payload = if let Some(payload_arg) = args.get(1) {
                self.read_carrier_list(payload_arg)?
            } else {
                Vec::new()
            };
            out.push((variant_name, payload));
        }
        Ok(out)
    }

    /// Require `expr` to be a record literal `{ … }`, returning its
    /// `(field-name, value)` pairs. Any other shape is rejected — a `foreign`
    /// declaration is inert data, never a computed value.
    fn expect_record<'e>(
        &self,
        expr: &'e ipe_syntax::Expr,
    ) -> Result<
        &'e [(
            ipe_diagnostics::Located<ipe_intern::Symbol>,
            ipe_syntax::Expr,
        )],
        CliError,
    > {
        use ipe_syntax::Expr_;
        match &expr.value {
            Expr_::Record(fields) => Ok(fields.as_slice()),
            _ => Err(self.reject(
                expr.span,
                "expected a record literal `{ … }` — a `foreign` declaration is written as a \
                 record of literals, never computed",
            )),
        }
    }

    /// Require `expr` to be a bare nullary constructor, returning its name.
    /// `what` names the expected kind in the error.
    fn expect_ctor<'e>(&'e self, expr: &ipe_syntax::Expr, what: &str) -> Result<&'e str, CliError> {
        use ipe_syntax::Expr_;
        match &expr.value {
            Expr_::VarLocal(n) | Expr_::VarQual(_, n) => Ok(self.text(*n)),
            _ => Err(self.reject(
                expr.span,
                &format!("expected {what} as a constructor, never a computed value or binding"),
            )),
        }
    }

    /// Require `expr` to be a constructor APPLIED to arguments (`Struct { … }`,
    /// `Variant "…" [ … ]`), returning `(ctor-name, args)`. A bare nullary
    /// constructor yields an empty argument slice.
    fn expect_ctor_app<'e>(
        &'e self,
        expr: &'e ipe_syntax::Expr,
        what: &str,
    ) -> Result<(&'e str, &'e [ipe_syntax::Expr]), CliError> {
        use ipe_syntax::Expr_;
        match &expr.value {
            Expr_::Call(callee, args) => {
                let name = match &callee.value {
                    Expr_::VarLocal(n) | Expr_::VarQual(_, n) => self.text(*n),
                    _ => {
                        return Err(self.reject(
                            callee.span,
                            &format!(
                                "expected {what} as a constructor applied to its argument, never \
                                 a computed function"
                            ),
                        ));
                    }
                };
                Ok((name, args.as_slice()))
            }
            Expr_::VarLocal(n) | Expr_::VarQual(_, n) => Ok((self.text(*n), &[])),
            _ => Err(self.reject(expr.span, &format!("expected {what} as a constructor"))),
        }
    }

    /// Read a list-literal expression, returning its element expressions.
    fn expect_list<'e>(
        &self,
        expr: &'e ipe_syntax::Expr,
    ) -> Result<&'e [ipe_syntax::Expr], CliError> {
        use ipe_syntax::Expr_;
        match &expr.value {
            Expr_::List(items) => Ok(items.as_slice()),
            _ => Err(self.reject(expr.span, "expected a list literal `[ … ]`")),
        }
    }

    /// Read a string-literal expression; reject anything that is not a literal.
    fn expect_string(&self, expr: &ipe_syntax::Expr) -> Result<String, CliError> {
        use ipe_syntax::Expr_;
        match &expr.value {
            Expr_::Str(s) => Ok(s.clone()),
            _ => Err(self.reject(
                expr.span,
                "expected a string literal — a `foreign` declaration field may only be a literal",
            )),
        }
    }
}

/// Map a derive constructor name to the Rust derive token the driver decodes.
/// The constructor spelling and the emitted token coincide; this closed match is
/// the allowlist, so an unrecognised derive is rejected rather than emitted.
fn ffi_derive_name(ctor: &str) -> Option<&'static str> {
    match ctor {
        "Clone" => Some("Clone"),
        "Debug" => Some("Debug"),
        "Default" => Some("Default"),
        "PartialEq" => Some("PartialEq"),
        "Eq" => Some("Eq"),
        "PartialOrd" => Some("PartialOrd"),
        "Ord" => Some("Ord"),
        "Hash" => Some("Hash"),
        "Copy" => Some("Copy"),
        _ => None,
    }
}

/// Compute the 1-based `(line, col)` of a byte offset in `src`. Degrades
/// gracefully to `(1, 1)` on an out-of-range offset — the lift pass stays total.
fn line_col_from_span(src: &str, off: u32) -> (usize, usize) {
    let off = off as usize;
    let mut line = 1usize;
    let mut col = 1usize;
    for (i, ch) in src.char_indices() {
        if i >= off {
            break;
        }
        if ch == '\n' {
            line += 1;
            col = 1;
        } else {
            col += 1;
        }
    }
    (line, col)
}

#[cfg(test)]
/// Test-only re-export so `project.rs` tests can verify that the ffi.rs
/// wrapper-header reader uses the same predicate as `is_rust_wrapper_header`.
pub(crate) fn rust_wrapper_header_accepted_by_ffi_reader(line: &str) -> bool {
    crate::project::is_rust_wrapper_header(line)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jail_for_host_tracks_the_compiled_in_run_jail() {
        // The admit hand-off must equal the run-jail's own compiled-in confined
        // set, whatever that set is: this is the single source that stops the
        // admit path claiming a jail the target does not compile in —
        // `jail_for_host` folds EXACTLY `platform_confined_axes()`, so the two
        // cannot drift on any target (full, partial, or empty).
        let mut from_axes = ipe_ffi::capability_scan::CapabilitySet::EMPTY;
        for &axis in ipe_sandbox::run_jail::platform_confined_axes() {
            from_axes = from_axes.with(axis);
        }
        assert_eq!(
            jail_for_host(),
            ipe_ffi::capability_scan::JailForTarget::Holds(from_axes)
        );
        assert_eq!(jail_for_host().confined(), from_axes);

        // A non-empty compiled-in axis list must mean the platform is a jailed
        // target (and vice-versa): a stub host confines nothing. This keeps the
        // predicate and the axis list in lock without assuming the set is FULL —
        // a jailed target may be PARTIAL (Windows).
        if ipe_sandbox::run_jail::platform_supports_jail() {
            assert!(
                !from_axes.is_empty(),
                "a jailed host must confine at least one axis"
            );
        } else {
            assert!(
                from_axes.is_empty(),
                "a stub host must confine no axis (refuse-gap)"
            );
        }
    }

    #[test]
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn jail_for_host_holds_on_linux_x86_64() {
        // Linux/x86_64 confines every runtime-enforced axis → the full set.
        assert_eq!(
            jail_for_host(),
            ipe_ffi::capability_scan::JailForTarget::FULLY_CONFINED
        );
        assert!(jail_for_host().confined().is_full());
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn jail_for_host_holds_on_macos() {
        // macOS confines every runtime-enforced axis → the full set.
        assert_eq!(
            jail_for_host(),
            ipe_ffi::capability_scan::JailForTarget::FULLY_CONFINED
        );
        assert!(jail_for_host().confined().is_full());
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn jail_for_host_confines_the_partial_windows_set() {
        // Windows is a jailed target with a PARTIAL confined set: the admit path
        // must fold EXACTLY the run-jail's single-sourced axis list — never
        // assume FULL. subprocess + env + filesystem + network + native-ffi are
        // confined by the Job Object + AppContainer + launcher scrub (with
        // filesystem/network fail-closed at runtime off an ACL volume), and
        // database is derived from net + fs.
        let confined = jail_for_host().confined();
        use ipe_ffi::capability_scan::Capability;
        for cap in [
            Capability::Subprocess,
            Capability::Env,
            Capability::Filesystem,
            Capability::Network,
            Capability::NativeFfi,
            Capability::Database,
        ] {
            assert!(confined.confines(cap), "Windows must confine {cap:?}");
        }
        // The fold must equal the run-jail's own list — no drift, no over-claim.
        let mut from_axes = ipe_ffi::capability_scan::CapabilitySet::EMPTY;
        for &axis in ipe_sandbox::run_jail::platform_confined_axes() {
            from_axes = from_axes.with(axis);
        }
        assert_eq!(confined, from_axes);
    }

    #[test]
    fn manifest_rust_dependencies_table_parses_both_spellings() {
        let text = "[project]\nname = \"x\"\n\n[\"rust.dependencies\"]\nsemver = \"1\"\n\n[live]\nport = 1\n";
        assert_eq!(
            rust_dependencies_from_manifest(text),
            vec![ManifestDep {
                name: "semver".to_owned(),
                version: "1".to_owned(),
                features: Vec::new(),
            }]
        );
        let text2 = "[rust.dependencies]\nuuid = \"1.10\"\n";
        assert_eq!(
            rust_dependencies_from_manifest(text2),
            vec![ManifestDep {
                name: "uuid".to_owned(),
                version: "1.10".to_owned(),
                features: Vec::new(),
            }]
        );
    }

    #[test]
    fn manifest_rust_wrapper_table_reads_path_expose_and_capabilities() {
        let text = "[project]\nname = \"app\"\n\n\
                    [rust.wrapper]\n\
                    path = \"wrappers/engine\"\n\
                    expose = [\"make\", \"describe\", \"Engine\"]\n\
                    capabilities = [\"network\"]\n";
        let w = rust_wrapper_from_manifest(text).expect("wrapper table present");
        assert_eq!(w.path, "wrappers/engine");
        assert_eq!(w.expose, ["make", "describe", "Engine"]);
        assert_eq!(w.capabilities, ["network"]);
        // The typed gate accepts it (path is package-jailed, symbols validate)
        // and parses the declared capability into the closed vocabulary.
        let parsed = ipe_ffi::wrapper::WrapperManifest::parse(&w.path, &w.expose, &w.capabilities)
            .expect("typed decode accepts a jailed relative path + valid symbols");
        assert_eq!(parsed.path().as_str(), "wrappers/engine");
        assert!(
            parsed
                .capabilities()
                .contains(&ipe_ffi::capability_scan::Capability::Network)
        );
    }

    #[test]
    fn manifest_without_a_wrapper_table_reports_none() {
        let text = "[rust.dependencies]\nsemver = \"1\"\n";
        assert!(rust_wrapper_from_manifest(text).is_none());
    }

    #[test]
    fn wrapper_cargo_dep_scan_catches_every_dependency_table_form() {
        // The guardian's fail-open case: a target-cfg / triple / workspace dep
        // table must be scanned, or a network dep (`reqwest`) hides there and a
        // Network-capable wrapper installs unconstrained.
        let text = "\
[package]
name = \"w\"

[dependencies]
serde = \"1\"

[build-dependencies]
cc = \"1\"

[target.'cfg(unix)'.dependencies]
reqwest = \"0.12\"

[target.x86_64-unknown-linux-gnu.dependencies]
libc_dep = \"0.2\"

[workspace.dependencies]
tokio = \"1\"

[dependencies.hyper]
version = \"1\"
";
        let deps = parse_cargo_dependency_names(text);
        for expected in ["serde", "cc", "reqwest", "libc_dep", "tokio", "hyper"] {
            assert!(
                deps.iter().any(|d| d == expected),
                "dep `{expected}` must be caught: {deps:?}"
            );
        }
    }

    #[test]
    fn wrapper_cargo_dep_scan_survives_unusual_but_valid_toml() {
        // The forms a hand-rolled line scan under-refuses on — each a real Cargo
        // dependency the structural parse resolves identically. A miss here would
        // admit a Network-capable wrapper unconstrained.
        // Trailing comment on the header.
        let commented = "[dependencies] # a comment\nreqwest = \"0.12\"\n";
        assert!(
            parse_cargo_dependency_names(commented)
                .iter()
                .any(|d| d == "reqwest"),
            "a header with a trailing comment must still be scanned"
        );
        // An inline dependency table under a target-cfg parent.
        let inline = "[target.'cfg(unix)']\ndependencies = { reqwest = \"0.12\" }\n";
        assert!(
            parse_cargo_dependency_names(inline)
                .iter()
                .any(|d| d == "reqwest"),
            "an inline dependencies table must be scanned"
        );
        // A workspace inline dependencies table.
        let ws = "[workspace]\ndependencies = { tokio = \"1\" }\n";
        assert!(
            parse_cargo_dependency_names(ws)
                .iter()
                .any(|d| d == "tokio"),
            "a workspace inline dependencies table must be scanned"
        );
    }

    #[test]
    fn wrapper_cargo_dep_scan_excludes_dev_dependencies() {
        // `dev-dependencies` are test/build-only and never ship, so they are not
        // a runtime capability surface and must NOT force a refuse.
        let text = "[package]\nname = \"w\"\n\n[dev-dependencies]\nproptest = \"1\"\n";
        let deps = parse_cargo_dependency_names(text);
        assert!(
            !deps.iter().any(|d| d == "proptest"),
            "dev-dependencies must not be flagged: {deps:?}"
        );
        // Target-scoped dev-dependencies are likewise excluded.
        let scoped = "[target.'cfg(unix)'.dev-dependencies]\nproptest = \"1\"\n";
        assert!(
            parse_cargo_dependency_names(scoped).is_empty(),
            "target dev-dependencies must not be flagged"
        );
    }

    #[test]
    fn a_pure_wrapper_cargo_toml_has_no_deps() {
        let text = "[package]\nname = \"w\"\nversion = \"0.1.0\"\nedition = \"2021\"\n";
        assert!(parse_cargo_dependency_names(text).is_empty());
    }

    #[test]
    fn a_malformed_cargo_toml_mentioning_dependencies_fails_closed() {
        // An unparseable manifest that names `dependencies` must NOT report an
        // empty set (fail-open); it yields a sentinel so the wrapper is refused.
        let text = "[dependencies\nreqwest = \"0.12\"  # missing closing bracket";
        let deps = parse_cargo_dependency_names(text);
        assert!(
            !deps.is_empty(),
            "a malformed manifest mentioning dependencies must fail closed: {deps:?}"
        );
    }

    #[test]
    fn a_wrapper_path_escape_is_refused_by_the_typed_gate() {
        let text = "[rust.wrapper]\npath = \"../evil\"\nexpose = [\"f\"]\n";
        let w = rust_wrapper_from_manifest(text).expect("table present");
        assert!(
            ipe_ffi::wrapper::WrapperManifest::parse(&w.path, &w.expose, &w.capabilities).is_err(),
            "a `..` escape must be refused at decode"
        );
    }

    #[test]
    fn manifest_rust_dependencies_inline_table_carries_pin_and_features() {
        let text = "[rust.dependencies]\n\
                    async-stripe-checkout = { version = \"=1.0.0-rc.6\", features = [\"checkout_session\"] }\n\
                    firestore = { version = \"0.49\" }\n\
                    plain = \"2\"\n";
        assert_eq!(
            rust_dependencies_from_manifest(text),
            vec![
                ManifestDep {
                    name: "async-stripe-checkout".to_owned(),
                    version: "=1.0.0-rc.6".to_owned(),
                    features: vec!["checkout_session".to_owned()],
                },
                ManifestDep {
                    name: "firestore".to_owned(),
                    version: "0.49".to_owned(),
                    features: Vec::new(),
                },
                ManifestDep {
                    name: "plain".to_owned(),
                    version: "2".to_owned(),
                    features: Vec::new(),
                },
            ]
        );
    }

    #[test]
    fn manifest_chunk_is_a_single_crate_array_with_pin_and_features() {
        let scratch =
            std::env::temp_dir().join(format!("ipe-chunk-manifest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(&scratch).expect("mk scratch");
        let spec = CrateSpec::parse("async-stripe-checkout@=1.0.0-rc.6").expect("spec parses");
        let path = write_inspector_manifest_chunk(
            &scratch,
            "populate-0",
            &spec,
            &["checkout_session".to_owned()],
        )
        .expect("chunk write");
        assert_eq!(
            path.file_name().and_then(|f| f.to_str()),
            Some("ipe-install-populate-0.json"),
            "the stage names the file so chunks never clobber each other"
        );
        let body = std::fs::read_to_string(&path).expect("read chunk");
        let val: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        let arr = val.as_array().expect("a single-crate array");
        assert_eq!(arr.len(), 1, "one crate per chunk");
        let entry = arr.first().expect("the single crate entry");
        assert_eq!(
            entry.get("name"),
            Some(&serde_json::json!("async-stripe-checkout@=1.0.0-rc.6"))
        );
        assert_eq!(
            entry.get("features"),
            Some(&serde_json::json!(["checkout_session"]))
        );
        let _ = std::fs::remove_dir_all(&scratch);
    }

    #[test]
    fn chunk_payload_wires_xc_flags_and_manifest_shell_free() {
        let inspector = Path::new("/opt/ipe/bin/ipe-ffi-inspector");
        let manifest = Path::new("/scratch/ipe-install-populate-1.json");
        let load = Path::new("/scratch/xc-checkpoint.json");
        let save = Path::new("/scratch/xc-checkpoint.json");
        let payload =
            manifest_chunk_payload(inspector, manifest, true, false, Some(load), Some(save));
        let rendered: Vec<String> = payload
            .iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect();
        // The accumulating populate chunk: load prior, save merged, over a
        // single-crate manifest, with build scripts allowed and no fetch flag.
        // The value following each flag is asserted by finding the flag and
        // reading the next token via `.get`, never a raw index.
        let arg_after = |flag: &str| -> Option<&String> {
            rendered
                .iter()
                .position(|s| s == flag)
                .and_then(|at| rendered.get(at + 1))
        };
        assert_eq!(
            rendered.first().map(String::as_str),
            Some("/opt/ipe/bin/ipe-ffi-inspector")
        );
        assert!(rendered.contains(&"--allow-build-scripts".to_owned()));
        assert!(!rendered.contains(&"--fetch-only".to_owned()));
        assert_eq!(
            arg_after("--xc-load").map(String::as_str),
            Some("/scratch/xc-checkpoint.json")
        );
        assert_eq!(
            arg_after("--xc-save").map(String::as_str),
            Some("/scratch/xc-checkpoint.json")
        );
        assert_eq!(
            arg_after("--manifest").map(String::as_str),
            Some("/scratch/ipe-install-populate-1.json")
        );
        // No shell metacharacter smuggled into any token (direct-argv contract).
        assert!(
            rendered
                .iter()
                .all(|t| !t.contains(';') && !t.contains('|'))
        );
    }

    /// `prepare_ffi` with a blame path that has no `.ipe/cache/ffi/rust`
    /// directory up-tree returns an empty `FfiPrep` (no crates installed).
    /// This is the common case for every project that has never run `ipe add`.
    #[test]
    fn prepare_ffi_no_cache_returns_empty_prep() {
        let tmp = std::env::temp_dir();
        let mut sources: BTreeMap<Vec<String>, (std::path::PathBuf, String)> = BTreeMap::new();
        let prep = super::prepare_ffi(&mut sources, &tmp.join("Main.ipe"))
            .expect("prepare_ffi on a no-cache path must not error");
        assert!(prep.catalog.is_empty(), "no crates should be loaded");
        assert!(prep.injected.is_empty(), "no modules should be injected");
        assert!(prep.emit.is_none(), "emit should be None with no crates");
    }

    #[test]
    fn cache_root_walk_stops_at_the_ipe_toml_project_root() {
        let tmp = std::env::temp_dir().join(format!("ipe-t1-cacheroot-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        // Ancestor cache (a planted vector) ABOVE the project root.
        let ancestor_cache = cache_dir_under(tmp.as_path());
        std::fs::create_dir_all(&ancestor_cache).expect("mk ancestor cache");
        // The project root, with its own package.ipe, one level down; no cache.
        let project = tmp.join("proj");
        std::fs::create_dir_all(&project).expect("mk project");
        std::fs::write(
            project.join("package.ipe"),
            "module Package exposing (package)\n",
        )
        .expect("write manifest");
        let src = project.join("src");
        std::fs::create_dir_all(&src).expect("mk src");
        // Discovery from inside the project must NOT climb past package.ipe to the
        // planted ancestor cache — it returns None.
        let found = find_cache_root(&src).expect("no error");
        assert_eq!(found, None, "must not discover the ancestor cache");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn owned_project_cache_is_discovered() {
        let tmp = std::env::temp_dir().join(format!("ipe-t1-owncache-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let cache = cache_dir_under(tmp.as_path());
        std::fs::create_dir_all(&cache).expect("mk cache");
        std::fs::write(
            tmp.join("package.ipe"),
            "module Package exposing (package)\n",
        )
        .expect("manifest");
        // The invoker owns a freshly-created dir, so it is trusted + found.
        let found = find_cache_root(&tmp).expect("no error");
        assert_eq!(found.as_deref(), Some(cache.as_path()));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[cfg(unix)]
    #[test]
    fn world_writable_cache_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = std::env::temp_dir().join(format!("ipe-t1-wwcache-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let cache = cache_dir_under(tmp.as_path());
        std::fs::create_dir_all(&cache).expect("mk cache");
        std::fs::write(
            tmp.join("package.ipe"),
            "module Package exposing (package)\n",
        )
        .expect("manifest");
        // Make the cache world-writable — the delivery vector for a planted
        // _bindings.rs — and confirm discovery refuses it.
        std::fs::set_permissions(&cache, std::fs::Permissions::from_mode(0o777)).expect("chmod");
        let r = find_cache_root(&tmp);
        assert!(matches!(r, Err(CliError::UsageOwned(_))), "{r:?}");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn scratch_dir_is_under_the_cache_root_and_fails_on_a_pre_existing_path() {
        // HOME must be set for the sanctioned path; the test crate always has
        // one. The scratch dir lives under ~/.cache/ipe/ffi-scratch/, never
        // /tmp.
        let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
            return;
        };
        let scratch = make_scratch_dir("semver").expect("first create succeeds");
        assert!(
            scratch.starts_with(home.join(".cache/ipe/ffi-scratch")),
            "scratch under the write-boundary root: {}",
            scratch.display()
        );
        assert!(scratch.is_dir());
        // A second `create_dir` on the SAME path fails (planted-dir race
        // rejection). `make_scratch_dir` uses a fresh name each call, so we
        // assert the primitive directly on the returned path.
        assert!(
            std::fs::create_dir(&scratch).is_err(),
            "re-creating an existing scratch path must fail"
        );
        let _ = std::fs::remove_dir_all(&scratch);
    }

    #[test]
    fn toolchain_binds_never_include_the_cargo_parent_or_credentials() {
        let inspector = PathBuf::from("/opt/ipe/bin/ipe-ffi-inspector");
        let (binds, _path, _rustup) = toolchain_binds(&inspector);
        for b in &binds {
            let s = b.to_string_lossy();
            assert!(
                !s.ends_with("/.cargo"),
                "the ~/.cargo parent must never be bound: {s}"
            );
            assert!(
                !s.contains("credentials"),
                "no credentials path may be bound: {s}"
            );
        }
    }

    #[test]
    fn conflicting_dep_pins_are_refused() {
        let mk = |slug: &str, line: &str| InstalledCrate {
            slug: slug.to_owned(),
            module_name: format!("Rust.{slug}"),
            kernel_name: format!("Rust_{slug}"),
            interface_source: String::new(),
            bindings_source: String::new(),
            opaque_types: BTreeMap::new(),
            opaque_type_ids: BTreeMap::new(),
            define_types: BTreeSet::new(),
            transparent_types: BTreeMap::new(),
            bindings: Vec::new(),
            dep_versions: BTreeMap::new(),
            inspected_free_fns: BTreeMap::new(),
            inspected_consts: BTreeMap::new(),
            cargo_deps: vec![line.to_owned()],
            wrapper_idents: BTreeSet::new(),
        };
        // Two crates agreeing on a shared dep line dedupe to one.
        let ok = assemble_emit(&[mk("a", "serde = \"=1.0.1\""), mk("b", "serde = \"=1.0.1\"")]);
        assert!(ok.is_ok_and(|e| e.is_some_and(|e| e.dep_lines == vec!["serde = \"=1.0.1\""])));
        // A VERSION disagreement on a DIRECT FFI crate (the dep name IS a catalog slug)
        // is a real, unbuildable conflict → refused. (A transitive-dep version conflict
        // instead defers to Cargo — see `transitive_version_conflict_defers_to_cargo`.)
        let clash = assemble_emit(&[
            mk("serde", "serde = \"=1.0.1\""),
            mk("other", "serde = \"=1.0.2\""),
        ]);
        assert!(clash.is_err());
    }

    #[test]
    fn same_version_different_features_unify() {
        // The stripe-manifest shape: `async-stripe-shared` pinned bare by one crate
        // (as a transitive dep) and with features by another (its own self-line).
        // Same version → Cargo-style feature union, NOT a conflict.
        let mk = |slug: &str, line: &str| InstalledCrate {
            slug: slug.to_owned(),
            module_name: format!("Rust.{slug}"),
            kernel_name: format!("Rust_{slug}"),
            interface_source: String::new(),
            bindings_source: String::new(),
            opaque_types: BTreeMap::new(),
            opaque_type_ids: BTreeMap::new(),
            define_types: BTreeSet::new(),
            transparent_types: BTreeMap::new(),
            bindings: Vec::new(),
            dep_versions: BTreeMap::new(),
            inspected_free_fns: BTreeMap::new(),
            inspected_consts: BTreeMap::new(),
            cargo_deps: vec![line.to_owned()],
            wrapper_idents: BTreeSet::new(),
        };
        let e = assemble_emit(&[
            mk("a", "async-stripe-shared = \"=1.0.0-rc.6\""),
            mk(
                "b",
                "async-stripe-shared = { version = \"=1.0.0-rc.6\", features = [\"serialize\", \"deserialize\"] }",
            ),
        ])
        .expect("union must not error")
        .expect("emit present");
        assert_eq!(
            e.dep_lines,
            vec![
                "async-stripe-shared = { version = \"=1.0.0-rc.6\", features = [\"deserialize\", \"serialize\"] }"
                    .to_owned()
            ],
            "features union into one line at the shared version"
        );
    }

    #[test]
    fn transitive_version_conflict_defers_to_cargo() {
        // A TRANSITIVE dep (`syn`, not a catalog crate) pinned to two majors by two
        // members — each inspected in its own jail — must NOT refuse the build and must
        // NOT be exact-pinned to one arbitrary version. It is dropped so Cargo resolves
        // the transitive graph of the direct pins itself.
        let mk = |slug: &str, lines: Vec<&str>| InstalledCrate {
            slug: slug.to_owned(),
            module_name: format!("Rust.{slug}"),
            kernel_name: format!("Rust_{slug}"),
            interface_source: String::new(),
            bindings_source: String::new(),
            opaque_types: BTreeMap::new(),
            opaque_type_ids: BTreeMap::new(),
            define_types: BTreeSet::new(),
            transparent_types: BTreeMap::new(),
            bindings: Vec::new(),
            dep_versions: BTreeMap::new(),
            inspected_free_fns: BTreeMap::new(),
            inspected_consts: BTreeMap::new(),
            cargo_deps: lines.into_iter().map(str::to_owned).collect(),
            wrapper_idents: BTreeSet::new(),
        };
        let e = assemble_emit(&[
            mk("a", vec!["a = \"=1.0.0\"", "syn = \"=2.0.119\""]),
            mk("b", vec!["b = \"=1.0.0\"", "syn = \"=3.0.0\""]),
        ])
        .expect("transitive conflict must not error")
        .expect("emit present");
        assert!(
            e.dep_lines.iter().all(|l| !l.starts_with("syn =")),
            "the conflicting transitive `syn` is dropped, not pinned: {:?}",
            e.dep_lines
        );
        assert!(
            e.dep_lines.contains(&"a = \"=1.0.0\"".to_owned())
                && e.dep_lines.contains(&"b = \"=1.0.0\"".to_owned()),
            "the direct crates stay pinned: {:?}",
            e.dep_lines
        );
        // A DIRECT crate version conflict is still a hard error.
        let clash = assemble_emit(&[
            mk("stripe", vec!["stripe = \"=1.0.0\""]),
            mk("other", vec!["stripe = \"=2.0.0\""]),
        ]);
        assert!(
            clash.is_err(),
            "a direct-crate version conflict still refuses"
        );
    }

    #[test]
    fn merge_injects_a_matching_closure_as_a_synthetic_function() {
        let doc = "{\"pkg\":\"demo\",\"name\":\"demo\",\"functions\":[]}";
        let closures = vec![ManifestDefineClosure {
            krate: "demo".to_owned(),
            name: "update_fn".to_owned(),
            signature: "Fn(Int) -> Int + Send + Sync + 'static".to_owned(),
        }];
        let merged = merge_provides(doc, "demo", &closures, &[], &[], &[], true).expect("merges");
        let val: serde_json::Value = serde_json::from_str(&merged).expect("valid json");
        let fns = val
            .get("functions")
            .and_then(serde_json::Value::as_array)
            .expect("functions array");
        assert_eq!(fns.len(), 1);
        let f0 = fns.first().expect("one function");
        assert_eq!(
            f0.get("name").and_then(serde_json::Value::as_str),
            Some("update_fn")
        );
        assert_eq!(
            f0.get("isClosureAdapter")
                .and_then(serde_json::Value::as_bool),
            Some(true)
        );
        assert_eq!(
            f0.get("closureSig").and_then(serde_json::Value::as_str),
            Some("Fn(Int) -> Int + Send + Sync + 'static")
        );
    }

    #[test]
    fn merge_leaves_a_non_matching_crate_untouched() {
        let doc = "{\"pkg\":\"other\",\"name\":\"other\",\"functions\":[]}";
        let closures = vec![ManifestDefineClosure {
            krate: "demo".to_owned(),
            name: "update_fn".to_owned(),
            signature: "Fn(Int) -> Int".to_owned(),
        }];
        // A qualified entry for `demo` does not attach to `other`.
        let merged = merge_provides(doc, "other", &closures, &[], &[], &[], false).expect("merges");
        let val: serde_json::Value = serde_json::from_str(&merged).expect("valid json");
        assert!(
            val.get("functions")
                .and_then(serde_json::Value::as_array)
                .expect("array")
                .is_empty()
        );
    }

    #[test]
    fn an_unqualified_closure_under_a_multi_crate_manifest_is_refused() {
        let doc = "{\"pkg\":\"demo\",\"name\":\"demo\",\"functions\":[]}";
        let closures = vec![ManifestDefineClosure {
            krate: String::new(),
            name: "update_fn".to_owned(),
            signature: "Fn(Int) -> Int".to_owned(),
        }];
        // sole_dep = false ⇒ an unattributed entry cannot be placed: refuse.
        assert!(merge_provides(doc, "demo", &closures, &[], &[], &[], false).is_err());
        // sole_dep = true ⇒ it attaches to the one crate.
        assert!(merge_provides(doc, "demo", &closures, &[], &[], &[], true).is_ok());
    }

    #[test]
    fn an_unqualified_struct_under_a_multi_crate_manifest_is_refused() {
        let doc = "{\"pkg\":\"demo\",\"name\":\"demo\",\"functions\":[]}";
        let structs = vec![ManifestDefineStruct {
            krate: String::new(),
            ctor: "counter_new".to_owned(),
            struct_name: "Counter".to_owned(),
            fields: vec![("value".to_owned(), "i64".to_owned())],
            derives: Vec::new(),
        }];
        assert!(merge_provides(doc, "demo", &[], &structs, &[], &[], false).is_err());
        assert!(merge_provides(doc, "demo", &[], &structs, &[], &[], true).is_ok());
    }

    /// An inspection document that reports one opaque type `Client` (a struct
    /// with hidden members, so the classifier leaves it opaque).
    fn doc_reporting_opaque_client() -> String {
        serde_json::json!({
            "pkg": "postgres",
            "name": "postgres",
            "version": "0.1.0",
            "functions": [],
            "errors": [],
            "types": [
                { "name": "Client", "rustPath": "postgres::Client",
                  "kind": "struct", "hiddenMembers": true }
            ]
        })
        .to_string()
    }

    #[test]
    fn a_declared_opaque_over_a_reported_type_is_merged() {
        let opaques = vec![ManifestDefineOpaque {
            krate: "postgres".to_owned(),
            ipe_name: "Connection".to_owned(),
            rust_type: "Client".to_owned(),
        }];
        let merged = merge_provides(
            &doc_reporting_opaque_client(),
            "postgres",
            &[],
            &[],
            &[],
            &opaques,
            true,
        )
        .expect("merges");
        let val: serde_json::Value = serde_json::from_str(&merged).expect("valid json");
        assert_eq!(
            val.get("declaredOpaques")
                .and_then(|d| d.get("Connection"))
                .and_then(serde_json::Value::as_str),
            Some("::postgres::Client"),
            "{merged}"
        );
    }

    #[test]
    fn a_declared_opaque_over_an_unreported_type_is_refused() {
        let opaques = vec![ManifestDefineOpaque {
            krate: "postgres".to_owned(),
            ipe_name: "Connection".to_owned(),
            rust_type: "Nonexistent".to_owned(),
        }];
        let err = merge_provides(
            &doc_reporting_opaque_client(),
            "postgres",
            &[],
            &[],
            &[],
            &opaques,
            true,
        )
        .expect_err("must_refuse: an un-inspected type cannot mint a handle");
        assert!(
            matches!(&err, CliError::UsageOwned(m) if m.contains("not an inspected type")),
            "{err:?}"
        );
    }

    #[test]
    fn a_declared_opaque_over_a_transparent_type_is_refused() {
        // A struct with two identity-carrier fields surfaces TRANSPARENTLY, so
        // it is a value type — an `Opaque` handle over it is refused.
        let doc = serde_json::json!({
            "pkg": "geo", "name": "geo", "version": "0.1.0",
            "functions": [], "errors": [],
            "types": [
                { "name": "Point", "rustPath": "geo::Point", "kind": "struct",
                  "fields": [
                    { "name": "x", "type": "Int", "rustType": "i64" },
                    { "name": "y", "type": "Int", "rustType": "i64" }
                  ]}
            ]
        })
        .to_string();
        let opaques = vec![ManifestDefineOpaque {
            krate: "geo".to_owned(),
            ipe_name: "Pt".to_owned(),
            rust_type: "Point".to_owned(),
        }];
        let err = merge_provides(&doc, "geo", &[], &[], &[], &opaques, true)
            .expect_err("must_refuse: a transparent value type is not a handle");
        assert!(
            matches!(&err, CliError::UsageOwned(m) if m.contains("TRANSPARENTLY")),
            "{err:?}"
        );
    }

    #[test]
    fn an_unqualified_opaque_under_a_multi_crate_manifest_is_refused() {
        let opaques = vec![ManifestDefineOpaque {
            krate: String::new(),
            ipe_name: "Connection".to_owned(),
            rust_type: "Client".to_owned(),
        }];
        // sole_dep = false ⇒ an unattributed declaration cannot be placed.
        assert!(
            merge_provides(
                &doc_reporting_opaque_client(),
                "postgres",
                &[],
                &[],
                &[],
                &opaques,
                false
            )
            .is_err()
        );
        // sole_dep = true ⇒ it attaches to the one crate.
        assert!(
            merge_provides(
                &doc_reporting_opaque_client(),
                "postgres",
                &[],
                &[],
                &[],
                &opaques,
                true
            )
            .is_ok()
        );
    }

    #[test]
    fn lift_opaque_reads_the_kind_and_rejects_a_non_literal() {
        let interner_and_module = |src: &str| {
            let mut interner = ipe_intern::Interner::new();
            let module = ipe_parse::parse_module(src, &mut interner).expect("parses");
            (interner, module)
        };
        // A well-formed opaque declaration lifts to `ManifestDefineOpaque`.
        let (interner, module) = interner_and_module(
            "module M exposing (..)\n\nforeign Connection =\n    { crate = \"postgres\"\n    , kind = Opaque \"Client\"\n    }\n",
        );
        let reader = ForeignReader {
            interner: &interner,
            src: "",
            file: Path::new("M.ipe"),
        };
        let foreign = module.foreigns.first().expect("one foreign");
        let lifted = reader.lift_foreign(foreign).expect("lifts");
        assert_eq!(
            lifted,
            ForeignDefine::Opaque(ManifestDefineOpaque {
                krate: "postgres".to_owned(),
                ipe_name: "Connection".to_owned(),
                rust_type: "Client".to_owned(),
            })
        );
        // A non-literal type argument is refused (literal-only, invariant 5).
        let (interner2, module2) = interner_and_module(
            "module M exposing (..)\n\nname = \"Client\"\n\nforeign Connection =\n    { crate = \"postgres\"\n    , kind = Opaque name\n    }\n",
        );
        let reader2 = ForeignReader {
            interner: &interner2,
            src: "",
            file: Path::new("M.ipe"),
        };
        let foreign2 = module2.foreigns.first().expect("one foreign");
        assert!(
            reader2.lift_foreign(foreign2).is_err(),
            "must_refuse a computed type name"
        );
    }

    /// A one-crate `InstalledCrate` with the given opaque + define type maps.
    fn crate_with_types(slug: &str, opaque: &[(&str, &str)], define: &[&str]) -> InstalledCrate {
        InstalledCrate {
            slug: slug.to_owned(),
            module_name: format!("Rust.{slug}"),
            kernel_name: format!("Rust_{slug}"),
            interface_source: String::new(),
            bindings_source: String::new(),
            opaque_types: opaque
                .iter()
                .map(|(n, p)| ((*n).to_owned(), (*p).to_owned()))
                .collect(),
            opaque_type_ids: BTreeMap::new(),
            define_types: define.iter().map(|n| (*n).to_owned()).collect(),
            transparent_types: BTreeMap::new(),
            bindings: Vec::new(),
            dep_versions: BTreeMap::new(),
            inspected_free_fns: BTreeMap::new(),
            inspected_consts: BTreeMap::new(),
            cargo_deps: Vec::new(),
            wrapper_idents: BTreeSet::new(),
        }
    }

    #[test]
    fn a_define_type_renders_a_crate_absolute_ffi_path() {
        // A define-defined type lives in `crate::ffi::<slug>::<Name>` (the app
        // crate's own module tree), NOT at an external `::crate::Path`.
        let emit = assemble_emit(&[crate_with_types("iced", &[], &["Counter", "Message"])])
            .expect("emit ok")
            .expect("emit present");
        assert_eq!(
            emit.foreign_types
                .get("Rust.iced.Counter")
                .map(String::as_str),
            Some("crate::ffi::iced::Counter")
        );
        assert_eq!(
            emit.foreign_types
                .get("Rust.iced.Message")
                .map(String::as_str),
            Some("crate::ffi::iced::Message")
        );
    }

    #[test]
    fn a_transparent_define_glues_at_its_crate_local_path() {
        // A transparent define shape carries the BARE nominal (the define
        // convention); the assembled conversion glue must resolve it to the
        // crate-local `crate::ffi::<slug>::<Name>` where its `_bindings.rs`
        // definition lives — never an external `::Name`.
        let mut c = crate_with_types("demo", &[], &[]);
        let t = ipe_ffi::transparency::TransparentType::from_projection_json(&serde_json::json!({
            "name": "Counter", "kind": "struct", "rustPath": "Counter",
            "fields": [{"name": "value", "carrier": "Int"}]
        }))
        .expect("decodes");
        c.transparent_types.insert("Counter".to_owned(), t);
        c.bindings.push(ipe_ffi::interface::InterfaceBinding {
            ref_name: "counter_new".to_owned(),
            wrapper_ident: "Rust_demo_counter_new".to_owned(),
            arity: 1,
            sig: "Int -> Counter".to_owned(),
            transparent_params: Vec::new(),
            transparent_result: Some(ipe_ffi::interface::TransparentResult {
                type_name: "Counter".to_owned(),
                in_result: false,
            }),
        });
        let emit = assemble_emit(&[c]).expect("emit ok").expect("emit present");
        let glue = emit
            .wrapper_glue
            .get("Rust_demo_counter_new")
            .expect("constructor glue assembled");
        let result = glue.result.as_ref().expect("result conversion");
        assert_eq!(
            result.ty,
            ipe_backend_rust::FfiGlueType::Record {
                rust_path: "crate::ffi::demo::Counter".to_owned(),
                fields: vec!["value".to_owned()],
            }
        );
        // A transparent define is a native app type — never a foreign-path
        // mapping.
        assert!(!emit.foreign_types.contains_key("Rust.demo.Counter"));
    }

    #[test]
    fn a_define_type_colliding_with_an_inspected_opaque_is_refused() {
        // A define type sharing a name with an inspected opaque of the SAME
        // crate would silently overwrite one path — the two are different Rust
        // types. Fail closed rather than emit a wrong-type binding.
        let clash = assemble_emit(&[crate_with_types(
            "iced",
            &[("Element", "::iced::Element")],
            &["Element"],
        )]);
        assert!(clash.is_err(), "a define-vs-opaque name clash must refuse");
    }

    #[test]
    fn build_failure_does_not_trigger_usage_help() {
        // A build/inspection failure must not be wrapped into CliError::Usage*
        // (which `with_help_on_misuse` converts to CommandUsage + help page).
        // The `Pipeline` variant (typed diagnostic) never triggers usage help.
        let diag = ipe_ffi::diag::Diagnostic::WireMalformed {
            context: "crate `bevy`".to_owned(),
            defect: ipe_ffi::diag::WireDefect::Json {
                detail: "the inspector failed: error[E0412]: cannot find type".to_owned(),
            },
        };
        let err = ffi_build_error(diag);
        assert!(
            matches!(err, CliError::Pipeline { .. }),
            "build failure must produce CliError::Pipeline (typed diagnostic), got {err:?}"
        );
    }

    #[test]
    fn build_scripts_hint_is_detected_in_raw_error() {
        let raw = "inspector exited with Some(1)\n\
            error: some crates require build scripts\n\
            pass --allow-build-scripts to proceed anyway";
        assert!(
            detect_build_scripts_hint(raw).is_some(),
            "the --allow-build-scripts text must be detected"
        );
        assert!(
            detect_build_scripts_hint("unrelated cargo error: E0001").is_none(),
            "a plain build error must not be detected as a build-scripts hint"
        );
    }

    #[test]
    #[allow(clippy::panic)]
    fn build_scripts_error_renders_as_warning_not_usage_help() {
        let raw = "inspector exited with Some(1)\n\
            crates with build scripts found\n\
            pass --allow-build-scripts to proceed";
        let err = map_inspector_error(raw.to_owned());
        match err {
            CliError::Resolve(msg) => {
                assert!(
                    msg.contains("--allow-build-scripts"),
                    "the actionable flag must appear in the message"
                );
            }
            other => panic!("expected Resolve, got {other:?}"),
        }
    }

    // ── foreign-declaration lift tests ──────────────────────────────────────

    /// Parse a `foreign` source snippet and expect lifting to fail, returning
    /// the error message for further assertions.
    fn lift_one_err(src: &str) -> String {
        lift_first_foreign(src).expect_err("lift_foreign should fail for an invalid declaration")
    }

    /// An invalid carrier in a `foreign` struct field is rejected with a span
    /// pointing at the bad carrier. Lower-case field types are not carriers.
    #[test]
    fn foreign_struct_invalid_carrier_is_refused() {
        // `int` (lower-case) is not a valid carrier name.
        let bad = "module Main exposing (..)\n\nforeign Foo =\n          { crate = \"x\"\n          , kind = Struct { value = int }\n          }\n";
        let err = lift_one_err(bad);
        assert!(
            err.contains("not a valid field carrier") || err.contains("carrier"),
            "error must mention carrier: {err}"
        );
    }

    /// A derive that is not in the blessed allowlist is refused.
    #[test]
    fn foreign_struct_unknown_derive_is_refused() {
        let src = "module Main exposing (..)\n\nforeign Foo =\n          { crate = \"x\"\n          , kind = Struct { value = Int }\n          , derives = [ Display ]\n          }\n";
        let err = lift_one_err(src);
        assert!(
            err.contains("not a recognised derive") || err.contains("derive"),
            "error must mention derive: {err}"
        );
    }

    /// An unknown record field is refused, blocking injection of arbitrary Rust
    /// code through an unblessed vocabulary.
    #[test]
    fn foreign_struct_unknown_builder_is_refused() {
        let src = "module Main exposing (..)\n\nforeign Foo =\n          { crate = \"x\"\n          , kind = Struct { value = Int }\n          , inject = \"unsafe\"\n          }\n";
        let err = lift_one_err(src);
        assert!(
            err.contains("not a `Foreign` field") || err.contains("field"),
            "error must mention field: {err}"
        );
    }

    /// An unknown `kind` constructor (not `Struct`/`Enum`/`Closure`) is refused.
    #[test]
    fn foreign_unknown_shape_is_refused() {
        let src = "module Main exposing (..)\n\nforeign Foo =\n          { crate = \"x\"\n          , kind = Phantom\n          }\n";
        let err = lift_one_err(src);
        assert!(
            err.contains("not a `kind`") || err.contains("kind"),
            "error must mention kind: {err}"
        );
    }

    /// `scan_foreign_defines` on a non-existent directory returns three empty
    /// vectors — it must not propagate an I/O error for a missing src dir.
    #[test]
    fn scan_foreign_defines_on_missing_src_returns_empty() {
        // Use a path that is extremely unlikely to exist.
        let non_existent = std::path::Path::new("/tmp/__ipe_lane1_no_such_dir_ae3338f3");
        let (c, s, e, o) =
            scan_foreign_defines(non_existent).expect("missing dir must not be an error");
        assert!(c.is_empty() && s.is_empty() && e.is_empty() && o.is_empty());
    }

    /// `scan_foreign_defines` on a directory whose `.ipe` files have no
    /// `foreign` keyword returns four empty vectors without error.
    #[test]
    fn scan_foreign_defines_skips_files_without_foreign_keyword() {
        use std::io::Write as _;
        // Write a plain .ipe file (no `foreign` keyword) to a temp directory.
        let dir = std::env::temp_dir().join("ipe_lane1_no_foreign_test_ae3338f3");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let mut f = std::fs::File::create(dir.join("Main.ipe")).expect("create file");
        f.write_all(b"module Main exposing (..)\n\nmain = Io.println \"hello\"\n")
            .expect("write");
        drop(f);
        let (closures, structs, enums, opaques) =
            scan_foreign_defines(&dir).expect("no foreign keyword must not produce an error");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            closures.is_empty() && structs.is_empty() && enums.is_empty() && opaques.is_empty()
        );
    }

    #[test]
    fn legacy_define_tables_are_rejected() {
        let toml_with_define = r#"
[package]
name = "my-pkg"

[[rust.define.struct]]
name = "Counter"
fields = { value = "i64" }
"#;
        let err = reject_legacy_define_tables(toml_with_define)
            .expect_err("must reject legacy [[rust.define.*]]");
        let msg = err.to_string();
        assert!(
            msg.contains("[[rust.define.*]] is no longer supported"),
            "diagnostic must say what is rejected: {msg}"
        );
        assert!(
            msg.contains("foreign"),
            "diagnostic must point to the replacement surface: {msg}"
        );
    }

    #[test]
    fn clean_manifest_passes_the_define_table_guard() {
        let toml_clean = r#"
[package]
name = "my-pkg"

[rust.dependencies]
iced = "=0.12.1"
"#;
        reject_legacy_define_tables(toml_clean)
            .expect("manifest without [[rust.define.*]] must pass");
    }

    /// Parse `src` and lift its first `foreign` declaration through the record
    /// reader, returning either the lifted `ForeignDefine` or the refusal
    /// message. The read is purely syntactic — no author code runs.
    fn lift_first_foreign(src: &str) -> Result<ForeignDefine, String> {
        let mut interner = ipe_intern::Interner::new();
        let module = ipe_parse::parse_module(src, &mut interner).expect("parse");
        let foreign = module.foreigns.first().expect("one foreign decl");
        let reader = ForeignReader {
            interner: &interner,
            src,
            file: std::path::Path::new("Ffi.ipe"),
        };
        reader.lift_foreign(foreign).map_err(|e| e.to_string())
    }

    #[test]
    fn record_struct_lifts_to_the_same_define_as_the_toml_path() {
        let src = "module Ffi exposing (Counter)\n\
                   foreign Counter =\n\
                   \x20   { crate = \"iced\"\n\
                   \x20   , kind = Struct { value = Int }\n\
                   \x20   , derives = [ Default, Clone ]\n\
                   \x20   }\n";
        let got = lift_first_foreign(src).expect("valid struct record");
        assert_eq!(
            got,
            ForeignDefine::Struct(ManifestDefineStruct {
                krate: "iced".to_owned(),
                ctor: "counter_new".to_owned(),
                struct_name: "Counter".to_owned(),
                fields: vec![("value".to_owned(), "Int".to_owned())],
                derives: vec!["Default".to_owned(), "Clone".to_owned()],
            })
        );
    }

    #[test]
    fn record_enum_lifts_variants_and_payloads() {
        let src = "module Ffi exposing (Message)\n\
                   foreign Message =\n\
                   \x20   { crate = \"iced\"\n\
                   \x20   , kind = Enum [ Variant \"Increment\" [], Variant \"Set\" [ Int ] ]\n\
                   \x20   , derives = [ Clone, Debug ]\n\
                   \x20   }\n";
        let got = lift_first_foreign(src).expect("valid enum record");
        assert_eq!(
            got,
            ForeignDefine::Enum(ManifestDefineEnum {
                krate: "iced".to_owned(),
                ctor: "message_new".to_owned(),
                enum_name: "Message".to_owned(),
                variants: vec![
                    ("Increment".to_owned(), vec![]),
                    ("Set".to_owned(), vec!["Int".to_owned()]),
                ],
                derives: vec!["Clone".to_owned(), "Debug".to_owned()],
            })
        );
    }

    #[test]
    fn record_closure_builds_the_canonical_signature() {
        let src = "module Ffi exposing (update)\n\
                   foreign update =\n\
                   \x20   { crate = \"iced\"\n\
                   \x20   , kind = Closure { args = [ Int, String ], returns = Int }\n\
                   \x20   }\n";
        let got = lift_first_foreign(src).expect("valid closure record");
        assert_eq!(
            got,
            ForeignDefine::Closure(ManifestDefineClosure {
                krate: "iced".to_owned(),
                name: "update".to_owned(),
                signature: "Fn(Int, String) -> Int + Send + Sync + 'static".to_owned(),
            })
        );
    }

    #[test]
    fn a_misspelt_derive_is_a_refusal() {
        let src = "module Ffi exposing (Counter)\n\
                   foreign Counter =\n\
                   \x20   { crate = \"iced\"\n\
                   \x20   , kind = Struct { value = Int }\n\
                   \x20   , derives = [ Cloen ]\n\
                   \x20   }\n";
        let err = lift_first_foreign(src).expect_err("misspelt derive must refuse");
        assert!(err.contains("Cloen"), "{err}");
        assert!(err.contains("not a recognised derive"), "{err}");
    }

    #[test]
    fn a_misspelt_kind_is_a_refusal() {
        let src = "module Ffi exposing (Counter)\n\
                   foreign Counter =\n\
                   \x20   { crate = \"iced\"\n\
                   \x20   , kind = Strcut { value = Int }\n\
                   \x20   }\n";
        let err = lift_first_foreign(src).expect_err("misspelt kind must refuse");
        assert!(err.contains("Strcut"), "{err}");
        assert!(err.contains("not a `kind`"), "{err}");
    }

    #[test]
    fn a_non_record_body_is_a_refusal() {
        let src = "module Ffi exposing (Counter)\n\
                   foreign Counter = \"iced\"\n";
        let err = lift_first_foreign(src).expect_err("a string body must refuse");
        assert!(err.contains("record literal"), "{err}");
    }

    #[test]
    fn a_missing_crate_field_is_a_refusal() {
        let src = "module Ffi exposing (Counter)\n\
                   foreign Counter =\n\
                   \x20   { kind = Struct { value = Int } }\n";
        let err = lift_first_foreign(src).expect_err("a missing crate must refuse");
        assert!(err.contains("crate"), "{err}");
    }

    #[test]
    fn an_unknown_field_is_a_refusal() {
        let src = "module Ffi exposing (Counter)\n\
                   foreign Counter =\n\
                   \x20   { crate = \"iced\"\n\
                   \x20   , kind = Struct { value = Int }\n\
                   \x20   , flavour = \"spicy\"\n\
                   \x20   }\n";
        let err = lift_first_foreign(src).expect_err("an unknown field must refuse");
        assert!(err.contains("flavour"), "{err}");
    }

    fn bwrap() -> ipe_sandbox::Mechanism {
        ipe_sandbox::Mechanism::Bwrap(PathBuf::from("/usr/bin/bwrap"))
    }

    #[test]
    fn bwrap_with_all_caps_runs_jailed() {
        assert!(matches!(
            choose_sandbox_route(&bwrap(), vec![], false),
            SandboxRoute::Jailed
        ));
        // The override is irrelevant when the jail is fully viable.
        assert!(matches!(
            choose_sandbox_route(&bwrap(), vec![], true),
            SandboxRoute::Jailed
        ));
    }

    #[test]
    fn bwrap_missing_caps_without_override_refuses() {
        assert!(matches!(
            choose_sandbox_route(&bwrap(), vec!["timeout", "prlimit"], false),
            SandboxRoute::RefuseMissingCaps { missing } if missing == vec!["timeout", "prlimit"]
        ));
    }

    #[test]
    fn bwrap_missing_caps_with_override_runs_unsandboxed() {
        // The escape hatch the missing-caps message advertises must be live on
        // exactly this configuration: bwrap present, cap helpers absent.
        assert!(matches!(
            choose_sandbox_route(&bwrap(), vec!["prlimit"], true),
            SandboxRoute::Unsandboxed
        ));
    }

    #[test]
    fn no_bwrap_without_override_refuses() {
        assert!(matches!(
            choose_sandbox_route(&ipe_sandbox::Mechanism::Refused, vec![], false),
            SandboxRoute::RefuseNoBwrap
        ));
    }

    #[test]
    fn no_bwrap_with_override_runs_unsandboxed() {
        assert!(matches!(
            choose_sandbox_route(&ipe_sandbox::Mechanism::Refused, vec![], true),
            SandboxRoute::Unsandboxed
        ));
    }
}
