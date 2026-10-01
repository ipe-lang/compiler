#![forbid(unsafe_code)]
//! Anti-drift gate: every EXPORT of every compiled-source stdlib module resolves
//! through the real compiler pipeline.
//!
//! The source-vs-kernel drift class: a compiled-source `Ipe.*` module declares a
//! member in its `exposing (...)` list, but the member has no resolvable home —
//! no local body, no re-export, and (for an `Ffi.kernel "…"` alias) no matching
//! registered kernel. Such a member type-checks nowhere: a `Module.member` call
//! fails name-resolution (IPE-N0005 / IPE-N0028). An earlier `Ipe.Random`
//! shipped exactly this — `shuffle`/`weighted`/the seeded helpers were declared
//! but had no kernel row.
//!
//! This gate canonicalises EVERY compiled-source module (types included, unlike
//! the parse-only `ipe_stdlib::every_exported_value_has_a_home` floor) by
//! importing it into one `Main` and driving the production compile pipeline. A
//! module whose export is a dangling declaration or a broken kernel alias fails
//! its own canonicalisation here — pre-cargo, in the fast (non-E2E) path.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use ipe::project;
use ipe_db::Db as _;
use ipe_intern::Interner;
use ipe_types::{RowTail, Ty, VarNamer};

type UserSources = BTreeMap<Vec<String>, String>;
type PreparedSources = BTreeMap<Vec<String>, (PathBuf, String)>;

fn prepared(user: &UserSources) -> (PreparedSources, BTreeSet<Vec<String>>) {
    let mut sources: PreparedSources = user
        .iter()
        .map(|(p, text)| {
            (
                p.clone(),
                (
                    PathBuf::from(format!("<resolvability>/{}.ipe", p.join("/"))),
                    text.clone(),
                ),
            )
        })
        .collect();
    let mut discovered: Vec<project::DiscoveredModule> = sources
        .iter()
        .map(|(p, (path, _))| project::DiscoveredModule::user(path.clone(), p.clone()))
        .collect();
    let injected = project::inject_compiled_std_closure(&mut sources, &mut discovered);
    (sources, injected)
}

fn entry_path() -> Vec<String> {
    vec!["Main".to_owned()]
}

/// The native, non-E2E build configuration every probe compiles under.
fn native_config(db: &ipe_db::IpeDatabase) -> ipe_db::BuildConfig {
    ipe_db::BuildConfig::new(
        db,
        ipe_backend_rust::DbDriver::Sqlite,
        None,
        ipe_ir::Target::Native,
        Vec::new(),
        false,
        ipe_backend_rust::BuildIntent::Development,
        None,
        false,
        String::new(),
        false,
        false,
    )
}

/// Compile one synthesized `Main` through the production pipeline; `Ok` iff the
/// whole closure — every injected compiled-source module — canonicalises,
/// type-checks, and lowers.
fn compile_main(main: &str) -> Result<(), String> {
    let mut user = UserSources::new();
    user.insert(entry_path(), main.to_owned());
    let (sources, injected) = prepared(&user);
    let db = ipe_db::IpeDatabase::new();
    let root = ipe::create_source_root(&db, &sources, &injected, &BTreeSet::new());
    let config = native_config(&db);
    ipe::compile_prepared(
        &db,
        root,
        &sources,
        &entry_path(),
        Path::new("<resolvability>"),
        config,
    )
    .map(|_| ())
    .map_err(|e| e.to_string())
}

/// Like [`compile_main`], but adds extra user modules to the graph. Used to route
/// a `Ipe.Tea.*` shape module through a `main`-less helper (exempt from the
/// IPE-N0033 Program-imports-a-shape gate) while `Main` stays a plain Program.
fn compile_main_with_helper(main: &str, extras: &[(Vec<String>, String)]) -> Result<(), String> {
    let mut user = UserSources::new();
    user.insert(entry_path(), main.to_owned());
    for (path, text) in extras {
        user.insert(path.clone(), text.clone());
    }
    let (sources, injected) = prepared(&user);
    let db = ipe_db::IpeDatabase::new();
    let root = ipe::create_source_root(&db, &sources, &injected, &BTreeSet::new());
    let config = native_config(&db);
    ipe::compile_prepared(
        &db,
        root,
        &sources,
        &entry_path(),
        Path::new("<resolvability>"),
        config,
    )
    .map(|_| ())
    .map_err(|e| e.to_string())
}

/// Every compiled-source stdlib module, imported ONE AT A TIME into a `Main`,
/// must resolve.
///
/// Each module is compiled in isolation (a `Main` importing only it) so the gate
/// tests one module's own export resolution — not the incidental cross-module
/// name interactions of importing the whole stdlib into a single graph. A broken
/// export (a dangling declaration or an `Ffi.kernel "…"` alias with no registered
/// kernel) fails the imported module's own canonicalisation, so the compile fails
/// and the culprit is named. Importing with `as` (no member use) is enough: the
/// injected module is canonicalised as a dependency, and a homeless export cannot
/// survive that pass.
#[test]
fn compiled_source_modules_resolve_all_exports() {
    let mut failures: Vec<String> = Vec::new();
    for m in ipe_stdlib::COMPILED_STD_MODULES {
        // A `Ipe.Tea.*` shape module marks any plain-`main` importer a TEA-app
        // contradiction (IPE-N0033). Route it through a `main`-less helper module
        // — exempt from that gate — so the export resolution still runs while
        // `Main` stays a plain Program.
        let is_tea_shape = m
            .dotted
            .strip_prefix("Ipe.Tea.")
            .is_some_and(|rest| rest.contains('.'));
        let result = if is_tea_shape {
            let helper = format!(
                "module Probe exposing (probe)\nimport {} as M\n\nprobe : Int\nprobe =\n    0\n",
                m.dotted,
            );
            compile_main_with_helper(
                "module Main exposing (main)\nimport Ipe.Io as Io\nimport Probe\n\n\
                 main : Task Error ()\nmain =\n    Io.println \"ok\"\n",
                &[(vec!["Probe".to_owned()], helper)],
            )
        } else {
            let main = format!(
                "module Main exposing (main)\nimport Ipe.Io as Io\nimport {} as M\n\n\
                 main : Task Error ()\nmain =\n    Io.println \"ok\"\n",
                m.dotted,
            );
            compile_main(&main)
        };
        if let Err(e) = result {
            failures.push(format!("{}: {e}", m.dotted));
        }
    }
    assert!(
        failures.is_empty(),
        "every compiled-source stdlib module must resolve all its exports \
         through the real pipeline — a failure here is source-vs-kernel drift \
         (a declared-but-homeless export or a broken `Ffi.kernel` alias):\n{}",
        failures.join("\n"),
    );
}

/// Every EXPOSED VALUE of every kernel-veneer `MODULES` fixture resolves through
/// the real pipeline against the qualifier catalog.
///
/// The veneers (`Ipe.System`, `Ipe.Http`, `Ipe.Process`, …) are NEVER injected as
/// source — `inject_compiled_std_closure` consults `COMPILED_STD_MODULES` alone,
/// so their `Kernel.kernel "…"` bodies never compile. A `Module.member` call
/// instead resolves against the pre-installed kernel-qualifier catalog. A member
/// listed in the veneer's `exposing (...)` but absent from that catalog (and from
/// the kernel registry) type-checks nowhere: the call is IPE-N0005, yet `ipe doc`
/// still advertises it (docs derive from the fixtures). This gate references
/// every exposed value at a real call site so a catalog-homeless veneer export
/// fails the compile here, pre-cargo — closing the same drift class the
/// compiled-source gate closes for `COMPILED_STD_MODULES`.
#[test]
fn kernel_veneer_modules_resolve_all_exports() {
    use ipe_syntax::{Exposed, Exposing};

    let mut failures: Vec<String> = Vec::new();
    for m in ipe_stdlib::MODULES {
        let mut interner = Interner::new();
        let parsed = match ipe_parse::parse_module(m.source, &mut interner) {
            Ok(p) => p,
            Err(e) => {
                failures.push(format!("{}: veneer failed to parse: {e:?}", m.name));
                continue;
            }
        };
        let value_names: Vec<String> = match &parsed.exposing.value {
            // An export-all veneer has nothing to cross-check name-by-name.
            Exposing::All => continue,
            Exposing::List(items) => items
                .iter()
                .filter_map(|item| match &item.value {
                    Exposed::Value(n) => interner.resolve(*n).map(str::to_owned),
                    Exposed::Type(_, _) => None,
                })
                .collect(),
        };
        if value_names.is_empty() {
            continue;
        }

        // Reference every exposed value at a real call site: one bare top-level
        // binding per value forces name resolution (and HM inference of its
        // scheme) independently, so a catalog-homeless member fails resolution
        // and names itself. No application is needed — a dangling `Module.member`
        // reference already resolves against the catalog.
        let mut probes = String::new();
        for (i, name) in value_names.iter().enumerate() {
            let _ = writeln!(probes, "probe{i} = M.{name}");
        }
        let main = format!(
            "module Main exposing (main)\nimport Ipe.Io as Io\nimport {} as M\n\n\
             {probes}\nmain : Task Error ()\nmain =\n    Io.println \"ok\"\n",
            m.name,
        );

        if let Err(e) = compile_main(&main) {
            failures.push(format!("{}: {e}", m.name));
        }
    }
    assert!(
        failures.is_empty(),
        "every kernel-veneer stdlib module must resolve all its exposed values \
         through the real pipeline — a failure here is a veneer that advertises \
         (and documents) a member with no catalog home (IPE-N0005 at any call \
         site):\n{}",
        failures.join("\n"),
    );
}

/// Focused regression: the whole `Ipe.Random` surface resolves + type-checks at
/// real call sites — the exact members that were homeless (`shuffle`,
/// `weighted`, `choice`, and the seeded `seed`/`seededInt`/`seededFloat`/
/// `seededChoice` over the opaque `Seed`).
#[test]
fn random_full_surface_resolves() {
    let main = concat!(
        "module Main exposing (main)\n",
        "import Ipe.Io as Io\n",
        "import Ipe.String as String\n",
        "import Ipe.Task as Task\n",
        "import Ipe.Random as Random\n\n",
        "seededLine : String\n",
        "seededLine =\n",
        "    let\n",
        "        s0 = Random.seed 7\n",
        "        i = Random.seededInt s0 1 10\n",
        "        f = Random.seededFloat s0\n",
        "        c = Random.seededChoice s0 [ 1, 2, 3 ]\n",
        "    in\n",
        "    case i of\n",
        "        ( v, _ ) -> String.fromInt v\n\n",
        "draw : Task Error String\n",
        "draw =\n",
        "    Random.int 1 6\n",
        "        |> Task.andThen (\\_ -> Random.float 0.0 1.0)\n",
        "        |> Task.andThen (\\_ -> Random.range 1 6)\n",
        "        |> Task.andThen (\\_ -> Random.choice [ 10, 20 ])\n",
        "        |> Task.andThen (\\_ -> Random.shuffle [ 1, 2, 3 ])\n",
        "        |> Task.andThen (\\_ -> Random.weighted [ ( 1.0, \"a\" ) ])\n",
        "        |> Task.map (\\_ -> seededLine)\n\n",
        "main : Task Error ()\n",
        "main = Task.andThen (\\line -> Io.println line) draw\n",
    );

    let outcome = compile_main(main);
    assert!(
        outcome.is_ok(),
        "the whole Ipe.Random surface must resolve + type-check: {:?}",
        outcome.err(),
    );
}

// ── Kernel-alias annotation ≡ enforced scheme ───────────────────────────────
//
// A `Module.member` that resolves to a kernel (every veneer value, and every
// point-free `x = Kernel.kernel "…"` alias of a compiled-source module) is typed
// by the kernel's registered scheme — its source annotation is never checked.
// The annotation is nonetheless the documented contract (`ipe doc` renders it),
// so it must EQUAL the enforced scheme. The probe below proves that equality
// through the real pipeline: `annN : <annotation>` / `annN = M.member` fails the
// compile when the annotation contradicts or over-generalises the scheme, and
// the accepted `annN` vs the scheme of the kernel `infN = M.member` resolves to
// differ (up to type-variable renaming) when the annotation is merely more
// specific.

/// Which exposed values of a module resolve to a kernel scheme.
enum AliasScope {
    /// A veneer: every exposed value resolves through the qualifier catalog.
    EveryExposedValue,
    /// A compiled-source module: exactly the exported kernel aliases canon
    /// records for it (`ModuleExports::kernel_aliases`) skip checking; every
    /// other body is compiled against its annotation.
    CanonKernelAliases(BTreeSet<String>),
}

/// One exposed kernel-resolved member and its source annotation text.
struct AliasMember {
    name: String,
    annotation: String,
}

/// A module's kernel-resolved members plus the import context their
/// annotations are written in.
struct ProbeModule {
    dotted: String,
    /// Source text standing in for the module's shipped source in every probe
    /// graph (the injected module keeps its stdlib origin).
    replacement: Option<String>,
    /// The module's own `import` lines (the kernel-alias import excluded).
    imports: String,
    /// The exposed types the module itself owns (not re-exposed imports); the
    /// probe writes them `M.T` (a veneer's types are reachable only qualified).
    own_types: BTreeSet<String>,
    members: Vec<AliasMember>,
}

fn dotted_path(dotted: &str) -> Vec<String> {
    dotted.split('.').map(str::to_owned).collect()
}

/// `user` plus its injected compiled-stdlib closure, with `replacement`'s text
/// standing in for the named injected module.
fn prepared_with(
    user: &UserSources,
    replacement: Option<(&str, &str)>,
) -> Result<(PreparedSources, BTreeSet<Vec<String>>), String> {
    let (mut sources, injected) = prepared(user);
    if let Some((dotted, text)) = replacement {
        let path = dotted_path(dotted);
        if !injected.contains(&path) {
            return Err(format!("{dotted}: not an injected compiled-source module"));
        }
        let Some(slot) = sources.get_mut(&path) else {
            return Err(format!("{dotted}: missing from the prepared sources"));
        };
        text.clone_into(&mut slot.1);
    }
    Ok((sources, injected))
}

/// The exported kernel aliases canon records for `dotted`.
///
/// This is canon's own classification (`detect_kernel_alias`), read from its
/// resolved output rather than re-derived, so the gate probes exactly the
/// bindings whose annotation the compiler never checks.
fn canon_kernel_aliases(
    dotted: &str,
    replacement: Option<&str>,
) -> Result<BTreeSet<String>, String> {
    let mut user = UserSources::new();
    user.insert(
        entry_path(),
        format!("module Main exposing (main)\nimport {dotted} as M\n\nmain : Int\nmain =\n    0\n"),
    );
    let (sources, injected) = prepared_with(&user, replacement.map(|text| (dotted, text)))?;
    let db = ipe_db::IpeDatabase::new();
    let root = ipe::create_source_root(&db, &sources, &injected, &BTreeSet::new());
    let path = dotted_path(dotted);
    let Some(file) = root.files(&db).get(&path).copied() else {
        return Err(format!("{dotted}: not in the injected graph"));
    };
    let canon = ipe_db::canonicalize(&db, root, file).clone().map_err(|d| {
        let text = sources.get(&path).map_or("", |(_, t)| t.as_str());
        format!(
            "{dotted}: failed to canonicalise: {}",
            ipe_diagnostics::render(&d, &format!("{dotted}.ipe"), text)
        )
    })?;
    let interner = db.interner().lock();
    canon
        .exports
        .kernel_aliases
        .keys()
        .map(|s| {
            interner
                .resolve(*s)
                .map(str::to_owned)
                .ok_or_else(|| format!("{dotted}: a kernel-alias name is not interned"))
        })
        .collect()
}

/// A binding's image under the pair-consistent renaming.
#[derive(PartialEq, Eq)]
enum Image {
    Var(u32),
    Seal(String),
}

/// The pair-consistent renaming built while comparing two types.
#[derive(Default)]
struct VarPairs {
    left: BTreeMap<u32, u32>,
    right: BTreeMap<u32, Image>,
    /// Probe-local nullary types standing in for scheme variables a probe
    /// annotation may not state; each pairs bijectively with one variable.
    seals: BTreeSet<String>,
    seal_left: BTreeMap<String, u32>,
}

impl VarPairs {
    fn with_seals(seals: &BTreeSet<String>) -> Self {
        Self {
            seals: seals.clone(),
            ..Self::default()
        }
    }

    /// Record `a ↔ b`; `false` when either side is already paired elsewhere.
    fn pair(&mut self, a: u32, b: u32) -> bool {
        let l = *self.left.entry(a).or_insert(b);
        let r_ok = *self.right.entry(b).or_insert(Image::Var(a)) == Image::Var(a);
        l == b && r_ok
    }

    /// Record seal `name ↔ b`; `false` when either side is already paired
    /// elsewhere.
    fn pair_seal(&mut self, name: &str, b: u32) -> bool {
        let l = *self.seal_left.entry(name.to_owned()).or_insert(b);
        let image = Image::Seal(name.to_owned());
        let r_ok = *self
            .right
            .entry(b)
            .or_insert_with(|| Image::Seal(name.to_owned()))
            == image;
        l == b && r_ok
    }
}

/// Alpha-equivalence: equal up to a bijective renaming of type (and row)
/// variables, with each declared seal standing for one scheme variable.
fn alpha_eq(a: &Ty, b: &Ty, interner: &Interner, vars: &mut VarPairs) -> bool {
    match (a, b) {
        (Ty::Var(x), Ty::Var(y)) => vars.pair(*x, *y),
        (Ty::Con { name, args, .. }, Ty::Var(y)) if args.is_empty() => {
            match interner.resolve(*name) {
                Some(seal) if vars.seals.contains(seal) => vars.pair_seal(seal, *y),
                _ => false,
            }
        }
        (Ty::Fun(a1, r1), Ty::Fun(a2, r2)) => {
            alpha_eq(a1, a2, interner, vars) && alpha_eq(r1, r2, interner, vars)
        }
        (
            Ty::Con {
                module: m1,
                name: n1,
                args: x1,
            },
            Ty::Con {
                module: m2,
                name: n2,
                args: x2,
            },
        ) => {
            ipe_types::con_heads_compatible(m1, *n1, m2, *n2, interner)
                && x1.len() == x2.len()
                && x1
                    .iter()
                    .zip(x2)
                    .all(|(p, q)| alpha_eq(p, q, interner, vars))
        }
        (Ty::Unit, Ty::Unit) => true,
        (Ty::Tuple(x1), Ty::Tuple(x2)) => {
            x1.len() == x2.len()
                && x1
                    .iter()
                    .zip(x2)
                    .all(|(p, q)| alpha_eq(p, q, interner, vars))
        }
        (Ty::Record(f1, t1), Ty::Record(f2, t2)) => {
            let tails = match (t1, t2) {
                (RowTail::Closed, RowTail::Closed) => true,
                (RowTail::Open(x), RowTail::Open(y)) => vars.pair(*x, *y),
                (RowTail::Closed, RowTail::Open(_)) | (RowTail::Open(_), RowTail::Closed) => false,
            };
            tails
                && f1.len() == f2.len()
                && f1
                    .iter()
                    .zip(f2)
                    .all(|((k1, v1), (k2, v2))| k1 == k2 && alpha_eq(v1, v2, interner, vars))
        }
        _ => false,
    }
}

fn render(ty: &Ty, interner: &Interner) -> String {
    ipe_types::ty_to_doc(ty, interner, &mut VarNamer::new()).map_or_else(
        |e| format!("{ty:?} (unrenderable: {e:?})"),
        |doc| ipe_diagnostics::render_ty(&doc),
    )
}

fn span_text(source: &str, span: ipe_diagnostics::Span) -> Option<&str> {
    let lo = usize::try_from(span.lo).ok()?;
    let hi = usize::try_from(span.hi).ok()?;
    source.get(lo..hi)
}

/// A module's exposed value names (`None` when it exposes everything) and
/// its own type names, those it exposes without importing them.
fn exposure(
    parsed: &ipe_syntax::Module,
    interner: &Interner,
) -> (Option<BTreeSet<String>>, BTreeSet<String>) {
    use ipe_syntax::{Exposed, Exposing};

    let name = |s| interner.resolve(s).unwrap_or_default().to_owned();
    let exposed: Option<Vec<&Exposed>> = match &parsed.exposing.value {
        Exposing::All => None,
        Exposing::List(items) => Some(items.iter().map(|item| &item.value).collect()),
    };
    let exposed_values: Option<BTreeSet<String>> = exposed.as_ref().map(|items| {
        items
            .iter()
            .filter_map(|e| match e {
                Exposed::Value(n) => Some(name(*n)),
                Exposed::Type(_, _) => None,
            })
            .collect()
    });
    let exposed_type_names: Option<BTreeSet<String>> = exposed.as_ref().map(|items| {
        items
            .iter()
            .filter_map(|e| match e {
                Exposed::Type(n, _) => Some(name(*n)),
                Exposed::Value(_) => None,
            })
            .collect()
    });
    let imported_types: BTreeSet<String> = parsed
        .imports
        .iter()
        .filter_map(|import| match &import.exposing.value {
            Exposing::List(items) => Some(items),
            Exposing::All => None,
        })
        .flatten()
        .filter_map(|item| match &item.value {
            Exposed::Type(n, _) => Some(name(*n)),
            Exposed::Value(_) => None,
        })
        .collect();
    // An exposed type the module does not import is its own, whether declared
    // in source or supplied by the kernel (`Ipe.Ui.Tui.Attribute`).
    let own_types: BTreeSet<String> = exposed_type_names.map_or_else(
        || {
            parsed
                .unions
                .iter()
                .map(|u| name(u.value.name.value))
                .chain(parsed.aliases.iter().map(|a| name(a.value.name.value)))
                .collect()
        },
        |set| set.difference(&imported_types).cloned().collect(),
    );
    (exposed_values, own_types)
}

/// Collect a module's exposed kernel-resolved members; `Err` names a member
/// the gate cannot check (unparsable module, missing annotation, or a
/// kernel-shaped binding canon does not record).
fn alias_members(dotted: &str, source: &str, scope: &AliasScope) -> Result<ProbeModule, String> {
    use ipe_syntax::Expr_;

    let mut interner = Interner::new();
    let parsed = ipe_parse::parse_module(source, &mut interner)
        .map_err(|e| format!("{dotted}: failed to parse: {e:?}"))?;
    let name = |s| interner.resolve(s).unwrap_or_default().to_owned();

    let (exposed_values, own_types) = exposure(&parsed, &interner);
    let is_exposed = |member: &str| {
        exposed_values
            .as_ref()
            .is_none_or(|set| set.contains(member))
    };

    let mut imports = String::new();
    for import in &parsed.imports {
        let path: Vec<String> = import.name.value.iter().map(|s| name(*s)).collect();
        if path == ["Ipe", "Ffi", "Kernel"] {
            continue;
        }
        let text = span_text(source, import.span)
            .ok_or_else(|| format!("{dotted}: import span out of range"))?;
        imports.push_str(text);
        imports.push('\n');
    }

    if let AliasScope::CanonKernelAliases(aliases) = scope {
        let exposed_bindings: BTreeSet<String> = parsed
            .values
            .iter()
            .map(|v| name(v.value.name.value))
            .filter(|n| is_exposed(n))
            .collect();
        if let Some(missing) = aliases.difference(&exposed_bindings).next() {
            return Err(format!(
                "{dotted}.{missing}: canon exports a kernel alias with no exposed source binding"
            ));
        }
    }

    let mut members = Vec::new();
    for value in &parsed.values {
        let value = &value.value;
        let member = name(value.name.value);
        if !is_exposed(&member) {
            continue;
        }
        if let AliasScope::CanonKernelAliases(aliases) = scope
            && !aliases.contains(&member)
        {
            // A point-free `_.kernel "…"` body canon did not classify as an
            // alias would silently escape the probe; refuse it instead.
            let kernel_shaped = value.patterns.is_empty()
                && matches!(
                    &value.body.value,
                    Expr_::Call(callee, args)
                        if args.len() == 1
                            && matches!(
                                &callee.value,
                                Expr_::VarQual(_, k) if interner.resolve(*k) == Some("kernel")
                            )
                );
            if kernel_shaped {
                return Err(format!(
                    "{dotted}.{member}: kernel-alias-shaped binding canon does not record \
                     as a kernel alias — the gate would skip it"
                ));
            }
            continue;
        }
        let annotation = value
            .type_annotation
            .as_ref()
            .and_then(|a| span_text(source, a.span))
            .ok_or_else(|| {
                format!("{dotted}.{member}: exposed kernel-resolved value has no annotation")
            })?;
        members.push(AliasMember {
            name: member,
            annotation: annotation.to_owned(),
        });
    }
    Ok(ProbeModule {
        dotted: dotted.to_owned(),
        replacement: None,
        imports,
        own_types,
        members,
    })
}

const PROBE_MAIN: &str = "module Main exposing (main)\nimport Ipe.Io as Io\nimport Probe\n\n\
                          main : Task Error ()\nmain =\n    Io.println \"ok\"\n";

fn probe_path() -> Vec<String> {
    vec!["Probe".to_owned()]
}

/// `text` with every standalone word (neither qualified nor qualifying) that
/// `f` maps replaced by its image.
fn rewrite_words(text: &str, f: impl Fn(&str) -> Option<String>) -> String {
    let mut out = String::with_capacity(text.len());
    let mut word = String::new();
    let mut prev: Option<char> = None;
    let mut before_word: Option<char> = None;
    let flush = |word: &mut String, before: Option<char>, next: Option<char>, out: &mut String| {
        if word.is_empty() {
            return;
        }
        match (before != Some('.') && next != Some('.'))
            .then(|| f(word.as_str()))
            .flatten()
        {
            Some(image) => out.push_str(&image),
            None => out.push_str(word),
        }
        word.clear();
    };
    for c in text.chars() {
        if c.is_alphanumeric() || c == '_' {
            if word.is_empty() {
                before_word = prev;
            }
            word.push(c);
        } else {
            flush(&mut word, before_word, Some(c), &mut out);
            out.push(c);
        }
        prev = Some(c);
    }
    flush(&mut word, before_word, None, &mut out);
    out
}

/// `annotation` with every bare, unqualified `own_types` name written `M.T`.
fn qualify(annotation: &str, own_types: &BTreeSet<String>) -> String {
    rewrite_words(annotation, |w| {
        own_types.contains(w).then(|| format!("M.{w}"))
    })
}

fn seal_name(i: usize) -> String {
    format!("IpeProbeSeal{i}")
}

/// `annotation` with the `i`-th of `seal_vars` written as the probe-local
/// nullary type named by [`seal_name`] for `i`.
fn seal_annotation(annotation: &str, seal_vars: &[&str]) -> String {
    rewrite_words(annotation, |w| {
        seal_vars.iter().position(|v| *v == w).map(seal_name)
    })
}

/// The probe module restating `members`, declaring `seals` probe-local
/// nullary types first.
fn probe_source(m: &ProbeModule, members: &[AliasMember], seals: usize) -> String {
    let mut s = format!(
        "module Probe exposing (..)\n{}import {} as M\n",
        m.imports, m.dotted
    );
    for i in 0..seals {
        let _ = write!(s, "\n\ntype {0} =\n    {0}Value\n", seal_name(i));
    }
    for (i, member) in members.iter().enumerate() {
        let _ = write!(
            s,
            "\n\nann{i} : {}\nann{i} =\n    M.{}\n\n\ninf{i} =\n    M.{}\n",
            qualify(&member.annotation, &m.own_types),
            member.name,
            member.name
        );
    }
    s
}

/// A drift: the member index plus why its annotation is not the scheme.
type Drift = (usize, String);

/// Why a probe could not be compared.
#[derive(Debug)]
struct ProbeFailure {
    /// The refusing diagnostic's exact code; `None` for a malformed probe graph.
    code: Option<&'static str>,
    rendered: String,
}

/// Type-check one probe (routed through a `main`-less helper, so `Ipe.Tea.*`
/// shapes stay legal) and compare each accepted `annN` against the scheme of
/// the kernel the pipeline resolves `infN = M.member` to.
///
/// The scheme is read from the kernel table inference instantiates, not from
/// `infN`'s solved type: an unannotated top-level binding is numeric-,
/// interpolation- and UI-msg-defaulted, which would pin `number`/`msg` to a
/// ground type the scheme never states.
fn run_probe(
    m: &ProbeModule,
    probe: &str,
    count: usize,
    seals: &BTreeSet<String>,
) -> Result<Vec<Drift>, ProbeFailure> {
    let graph_failure = |rendered: String| ProbeFailure {
        code: None,
        rendered,
    };
    let mut user = UserSources::new();
    user.insert(entry_path(), PROBE_MAIN.to_owned());
    user.insert(probe_path(), probe.to_owned());
    let (sources, injected) = prepared_with(
        &user,
        m.replacement
            .as_deref()
            .map(|text| (m.dotted.as_str(), text)),
    )
    .map_err(graph_failure)?;
    let db = ipe_db::IpeDatabase::new();
    let root = ipe::create_source_root(&db, &sources, &injected, &BTreeSet::new());
    let files = root.files(&db);
    let (Some(entry), Some(module)) = (files.get(&entry_path()), files.get(&probe_path())) else {
        return Err(graph_failure(
            "probe graph lacks `Main` or `Probe`".to_owned(),
        ));
    };
    let refused = |d: &ipe_diagnostics::Diagnostic| ProbeFailure {
        code: Some(d.code().as_str()),
        rendered: ipe_diagnostics::render(d, "<resolvability>/Probe.ipe", probe),
    };
    let types = ipe_db::typecheck_module(&db, root, *entry, *module)
        .clone()
        .map_err(|(d, _)| refused(&d))?;
    let canon = ipe_db::canonicalize(&db, root, *module)
        .clone()
        .map_err(|d| refused(&d))?;
    let kernel_table = ipe_db::kernel_types(&db, root)
        .clone()
        .map_err(|d| refused(&d))?;
    let interner = db.interner().lock();
    let annotated: BTreeMap<String, &Ty> = types
        .env
        .iter()
        .filter_map(|(k, t)| interner.resolve(*k).map(|n| (n.to_owned(), t)))
        .collect();
    // `infN = M.member` names the kernel the pipeline routes `M.member` to.
    let resolved: BTreeMap<String, &ipe_canon::ast::Expr_> = canon
        .module
        .defs
        .iter()
        .filter_map(|def| match def {
            ipe_canon::ast::Def::Untyped { name, body, .. } => interner
                .resolve(name.value)
                .map(|n| (n.to_owned(), &body.value)),
            ipe_canon::ast::Def::Typed { .. } => None,
        })
        .collect();
    let mut drifts = Vec::new();
    for i in 0..count {
        let (Some(ann), Some(route)) = (
            annotated.get(&format!("ann{i}")),
            resolved.get(&format!("inf{i}")),
        ) else {
            drifts.push((
                i,
                "probe binding missing from the solved program".to_owned(),
            ));
            continue;
        };
        let ipe_canon::ast::Expr_::VarKernel {
            id: Some(kernel), ..
        } = route
        else {
            drifts.push((i, "does not resolve to a registered kernel".to_owned()));
            continue;
        };
        let Some((_, inf)) = kernel_table.iter().find(|(k, _)| k == kernel) else {
            drifts.push((i, format!("kernel `{kernel:?}` carries no type scheme")));
            continue;
        };
        if !alpha_eq(ann, inf, &interner, &mut VarPairs::with_seals(seals)) {
            drifts.push((
                i,
                format!(
                    "annotated `{}` but the compiler assigns `{}`",
                    render(ann, &interner),
                    render(inf, &interner)
                ),
            ));
        }
    }
    drop(interner);
    Ok(drifts)
}

/// Every drifted member of `m`, each described as `Module.member : ann — why`.
fn module_drifts(m: &ProbeModule) -> Vec<String> {
    if m.members.is_empty() {
        return Vec::new();
    }
    let no_seals = BTreeSet::new();
    let describe = |member: &AliasMember, why: &str| {
        format!(
            "{}.{} : {} — {why}",
            m.dotted, member.name, member.annotation
        )
    };
    match run_probe(
        m,
        &probe_source(m, &m.members, 0),
        m.members.len(),
        &no_seals,
    ) {
        Ok(drifts) => drifts
            .iter()
            .filter_map(|(i, why)| m.members.get(*i).map(|member| describe(member, why)))
            .collect(),
        Err(whole) => {
            // Localise: re-probe each member alone so the culprit names itself.
            let singles: Vec<String> = m
                .members
                .iter()
                .filter_map(|member| {
                    match run_probe(
                        m,
                        &probe_source(m, std::slice::from_ref(member), 0),
                        1,
                        &no_seals,
                    ) {
                        Ok(drifts) => drifts.first().map(|(_, why)| describe(member, why)),
                        Err(e) => Some(describe(
                            member,
                            &format!(
                                "annotation rejected against the enforced scheme: {}",
                                e.rendered
                            ),
                        )),
                    }
                })
                .collect();
            if singles.is_empty() {
                vec![format!(
                    "{}: probe failed as a whole: {}",
                    m.dotted, whole.rendered
                )]
            } else {
                singles
            }
        }
    }
}

/// A member whose annotation a probe cannot restate verbatim.
struct Unprobeable {
    path: &'static str,
    /// The exact diagnostic code refusing the verbatim restatement.
    code: &'static str,
    /// The annotation's type variables that refusal forbids. The gate restates
    /// the annotation with each written as a probe-local nullary type and
    /// compares that against the scheme, so the entry is still checked.
    seal_vars: &'static [&'static str],
}

/// Members whose annotation a probe cannot restate verbatim. The gate requires
/// the exact refusal (so an entry that stops being necessary fails instead of
/// lingering) AND compares the sealed restatement against the scheme.
const UNPROBEABLE: &[Unprobeable] = &[Unprobeable {
    // A user annotation may not leave a `CustomElement` seal polymorphic; only
    // the stdlib boundary member itself is generic over `down` / `up`.
    path: "Ipe.Ffi.Js.CustomElement.node",
    code: "IPE-N0039",
    seal_vars: &["down", "up"],
}];

/// Check one `UNPROBEABLE` member; `Err` says why it fails the gate.
fn check_unprobeable(
    m: &ProbeModule,
    member: &AliasMember,
    entry: &Unprobeable,
) -> Result<(), String> {
    let path = entry.path;
    let verbatim = run_probe(
        m,
        &probe_source(m, std::slice::from_ref(member), 0),
        1,
        &BTreeSet::new(),
    );
    if !matches!(&verbatim, Err(ProbeFailure { code: Some(c), .. }) if *c == entry.code) {
        return Err(format!(
            "{path}: listed UNPROBEABLE for {} but the verbatim probe gave {verbatim:?}",
            entry.code
        ));
    }
    let sealed = AliasMember {
        name: member.name.clone(),
        annotation: seal_annotation(&member.annotation, entry.seal_vars),
    };
    let seals: BTreeSet<String> = (0..entry.seal_vars.len()).map(seal_name).collect();
    if let Some(unused) = seals
        .iter()
        .find(|s| !sealed.annotation.contains(s.as_str()))
    {
        return Err(format!(
            "{path} : {} — seal variable for `{unused}` does not occur in the annotation",
            member.annotation
        ));
    }
    match run_probe(
        m,
        &probe_source(m, std::slice::from_ref(&sealed), entry.seal_vars.len()),
        1,
        &seals,
    ) {
        Ok(drifts) if drifts.is_empty() => Ok(()),
        other => Err(format!(
            "{path} : {} — the sealed restatement `{}` is not the enforced scheme: {other:?}",
            member.annotation, sealed.annotation
        )),
    }
}

/// Every exposed kernel-resolved value's annotation EQUALS the scheme the
/// compiler enforces for `Module.member`.
///
/// Covers every veneer value (`MODULES`) and every exported kernel alias canon
/// records for a compiled-source module — the two places an annotation is
/// documentation the type checker never reads. Floors pin that every veneer
/// and every canon-recorded alias is actually probed, so the gate cannot pass
/// by checking nothing.
#[test]
fn kernel_alias_annotations_equal_enforced_schemes() {
    let mut failures: Vec<String> = Vec::new();
    let mut modules: Vec<(&str, &str, AliasScope)> = ipe_stdlib::MODULES
        .iter()
        .map(|m| (m.name, m.source, AliasScope::EveryExposedValue))
        .collect();
    let mut expected: BTreeSet<String> = BTreeSet::new();
    for m in ipe_stdlib::COMPILED_STD_MODULES {
        match canon_kernel_aliases(m.dotted, None) {
            Ok(aliases) => {
                expected.extend(aliases.iter().map(|a| format!("{}.{a}", m.dotted)));
                modules.push((m.dotted, m.source, AliasScope::CanonKernelAliases(aliases)));
            }
            Err(e) => failures.push(e),
        }
    }
    let mut probed: BTreeSet<String> = BTreeSet::new();
    let mut exempted: BTreeSet<String> = BTreeSet::new();
    for (dotted, source, scope) in &modules {
        match alias_members(dotted, source, scope) {
            Ok(mut m) => {
                let (exempt, checked): (Vec<AliasMember>, Vec<AliasMember>) =
                    m.members.into_iter().partition(|member| {
                        let path = format!("{}.{}", m.dotted, member.name);
                        UNPROBEABLE.iter().any(|u| u.path == path)
                    });
                m.members = checked;
                for member in &exempt {
                    let path = format!("{}.{}", m.dotted, member.name);
                    let Some(entry) = UNPROBEABLE.iter().find(|u| u.path == path) else {
                        continue;
                    };
                    match check_unprobeable(&m, member, entry) {
                        Ok(()) => {
                            exempted.insert(path);
                        }
                        Err(e) => failures.push(e),
                    }
                }
                for member in &m.members {
                    probed.insert(format!("{}.{}", m.dotted, member.name));
                }
                failures.extend(module_drifts(&m));
            }
            Err(e) => failures.push(e),
        }
    }
    for veneer in ipe_stdlib::MODULES {
        let prefix = format!("{}.", veneer.name);
        assert!(
            probed.iter().any(|p| p.starts_with(&prefix)),
            "veneer {} contributed no probed member — the gate would skip it",
            veneer.name,
        );
    }
    let covered: BTreeSet<String> = probed.union(&exempted).cloned().collect();
    let unprobed: Vec<&String> = expected.difference(&covered).collect();
    assert!(
        unprobed.is_empty(),
        "canon-recorded kernel aliases the gate never checked: {unprobed:?}"
    );
    for entry in UNPROBEABLE {
        assert!(
            exempted.contains(entry.path) || failures.iter().any(|f| f.starts_with(entry.path)),
            "UNPROBEABLE entry `{}` names no exposed kernel alias",
            entry.path
        );
    }
    for pinned in [
        "Ipe.Bytes.length",
        "Ipe.File.readFile",
        "Ipe.Random.int",
        "Ipe.System.exit",
    ] {
        assert!(
            probed.contains(pinned),
            "`{pinned}` must be probed; probed = {probed:?}"
        );
    }
    assert!(
        failures.is_empty(),
        "every exposed kernel-resolved stdlib value's annotation must equal the \
         scheme the compiler enforces — a drift documents a contract the \
         compiler does not keep:\n{}",
        failures.join("\n"),
    );
}

/// Refusal: an annotation MORE SPECIFIC than the scheme type-checks (it is an
/// instance) yet documents the wrong contract — the comparator must flag it.
#[test]
fn alias_gate_flags_an_over_specific_annotation() {
    let m = ProbeModule {
        dotted: "Ipe.System".to_owned(),
        replacement: None,
        imports: String::new(),
        own_types: BTreeSet::new(),
        members: vec![AliasMember {
            name: "exit".to_owned(),
            annotation: "Int -> Int".to_owned(),
        }],
    };
    let drifts = module_drifts(&m);
    assert!(
        drifts.len() == 1 && drifts.iter().all(|d| d.contains("Ipe.System.exit")),
        "`exit : Int -> Int` over `Int -> a` must be one drift: {drifts:?}",
    );
}

/// Refusal: an annotation CONTRADICTING the scheme fails the probe compile and
/// is reported against the member.
#[test]
fn alias_gate_flags_a_contradicting_annotation() {
    let m = ProbeModule {
        dotted: "Ipe.File".to_owned(),
        replacement: None,
        imports: "import Ipe.Error exposing (Error)\n".to_owned(),
        own_types: BTreeSet::new(),
        members: vec![AliasMember {
            name: "readFile".to_owned(),
            annotation: "String -> Task Error String".to_owned(),
        }],
    };
    let drifts = module_drifts(&m);
    assert!(
        drifts.len() == 1 && drifts.iter().all(|d| d.contains("Ipe.File.readFile")),
        "`readFile : String -> …` over `Path -> …` must be one drift: {drifts:?}",
    );
}

/// Control: a type-variable renaming is the same scheme, not a drift.
#[test]
fn alias_gate_accepts_an_alpha_renamed_annotation() {
    let m = ProbeModule {
        dotted: "Ipe.System".to_owned(),
        replacement: None,
        imports: String::new(),
        own_types: BTreeSet::new(),
        members: vec![AliasMember {
            name: "exit".to_owned(),
            annotation: "Int -> zzz".to_owned(),
        }],
    };
    let drifts = module_drifts(&m);
    assert!(drifts.is_empty(), "`Int -> zzz` is `Int -> a`: {drifts:?}");
}

/// Refusal: a compiled-source module WITHOUT the `Ipe.Ffi.Kernel` import is
/// still probed — canon's alias set, not the import, selects the members — and
/// a drifted annotation there is flagged.
#[test]
fn alias_gate_probes_a_module_without_the_kernel_import() {
    let bytes = ipe_stdlib::COMPILED_STD_MODULES
        .iter()
        .find(|m| m.dotted == "Ipe.Bytes");
    assert!(
        bytes.is_some(),
        "`Ipe.Bytes` must be a compiled-source module"
    );
    let bytes = bytes.expect("`bytes` must be present");
    assert!(
        !bytes.source.contains("import Ipe.Ffi.Kernel"),
        "the refusal needs a module that does not import `Ipe.Ffi.Kernel`"
    );
    let shipped = "length : Bytes -> Int";
    assert!(
        bytes.source.contains(shipped),
        "`Ipe.Bytes` must ship `{shipped}`"
    );
    let drifted = bytes
        .source
        .replacen(shipped, "length : Bytes -> String", 1);
    let aliases = canon_kernel_aliases("Ipe.Bytes", Some(&drifted));
    assert!(
        aliases.as_ref().is_ok_and(|a| a.contains("length")),
        "canon must record `Ipe.Bytes.length` as a kernel alias: {aliases:?}"
    );
    let aliases = aliases.expect("`aliases` must succeed");
    let members = alias_members(
        "Ipe.Bytes",
        &drifted,
        &AliasScope::CanonKernelAliases(aliases),
    );
    assert!(
        members
            .as_ref()
            .is_ok_and(|m| m.members.iter().any(|x| x.name == "length")),
        "`Ipe.Bytes.length` must be selected for probing: {:?}",
        members.as_ref().err()
    );
    let mut m = members.expect("`members` must succeed");
    m.replacement = Some(drifted);
    let drifts = module_drifts(&m);
    assert!(
        drifts.len() == 1 && drifts.iter().all(|d| d.contains("Ipe.Bytes.length")),
        "`length : Bytes -> String` over `Bytes -> Int` must be one drift: {drifts:?}",
    );
}

/// Refusal: a kernel-shaped exposed binding canon does not record as an alias
/// fails the selection instead of silently escaping the probe.
#[test]
fn alias_gate_refuses_an_unrecorded_kernel_shaped_binding() {
    let source = "module Ipe.Bytes exposing (length)\n\nlength : Bytes -> Int\nlength =\n    Kernel.kernel \"Bytes_length\"\n";
    let members = alias_members(
        "Ipe.Bytes",
        source,
        &AliasScope::CanonKernelAliases(BTreeSet::new()),
    );
    assert!(
        members
            .as_ref()
            .err()
            .is_some_and(|e| e.contains("Ipe.Bytes.length")),
        "an unrecorded kernel-shaped binding must be refused: {:?}",
        members.as_ref().map(|m| m.members.len())
    );
}

/// The shipped `Ipe.Ffi.Js.CustomElement` probe module with `node`'s
/// annotation replaced by `annotation`, plus that member.
#[allow(clippy::panic)] // a missing shipped module or member is the test failure
fn custom_element_node(annotation: &str) -> (ProbeModule, AliasMember) {
    let dotted = "Ipe.Ffi.Js.CustomElement";
    let Some(module) = ipe_stdlib::COMPILED_STD_MODULES
        .iter()
        .find(|m| m.dotted == dotted)
    else {
        panic!("`{dotted}` must be a compiled-source module");
    };
    let aliases = match canon_kernel_aliases(dotted, None) {
        Ok(a) if a.contains("node") => a,
        other => panic!("canon must record `{dotted}.node` as a kernel alias: {other:?}"),
    };
    let m = match alias_members(
        dotted,
        module.source,
        &AliasScope::CanonKernelAliases(aliases),
    ) {
        Ok(m) => m,
        Err(e) => panic!("`{dotted}` members must select: {e:?}"),
    };
    let Some(name) = m
        .members
        .iter()
        .find(|x| x.name == "node")
        .map(|x| x.name.clone())
    else {
        panic!("`{dotted}.node` must be selected");
    };
    let member = AliasMember {
        name,
        annotation: annotation.to_owned(),
    };
    (m, member)
}

const NODE_ANNOTATION: &str = "CustomElement down up -> down -> (up -> msg) -> Element msg";

/// Control: the shipped `UNPROBEABLE` entry passes its exact-code and sealed
/// checks.
#[test]
fn unprobeable_gate_accepts_the_shipped_entry() {
    let (m, member) = custom_element_node(NODE_ANNOTATION);
    let entry = UNPROBEABLE
        .iter()
        .find(|u| u.path == "Ipe.Ffi.Js.CustomElement.node");
    assert!(entry.is_some(), "`CustomElement.node` must be listed");
    let entry = entry.expect("`entry` must be present");
    let checked = check_unprobeable(&m, &member, entry);
    assert!(checked.is_ok(), "the shipped entry must pass: {checked:?}");
}

/// Refusal: an entry naming a different refusal code than the verbatim probe
/// gives fails the gate.
#[test]
fn unprobeable_gate_refuses_a_wrong_code() {
    let (m, member) = custom_element_node(NODE_ANNOTATION);
    let entry = Unprobeable {
        path: "Ipe.Ffi.Js.CustomElement.node",
        code: "IPE-T0001",
        seal_vars: &["down", "up"],
    };
    let checked = check_unprobeable(&m, &member, &entry);
    assert!(
        checked
            .as_ref()
            .is_err_and(|e| e.contains("listed UNPROBEABLE for IPE-T0001")),
        "a wrong refusal code must fail the gate: {checked:?}"
    );
}

/// Refusal: a stale entry — a member whose verbatim probe now succeeds —
/// fails the gate instead of lingering.
#[test]
fn unprobeable_gate_refuses_a_stale_entry() {
    let m = ProbeModule {
        dotted: "Ipe.System".to_owned(),
        replacement: None,
        imports: String::new(),
        own_types: BTreeSet::new(),
        members: Vec::new(),
    };
    let member = AliasMember {
        name: "exit".to_owned(),
        annotation: "Int -> a".to_owned(),
    };
    let entry = Unprobeable {
        path: "Ipe.System.exit",
        code: "IPE-N0039",
        seal_vars: &["a"],
    };
    let checked = check_unprobeable(&m, &member, &entry);
    assert!(
        checked.as_ref().is_err_and(
            |e| e.contains("listed UNPROBEABLE for IPE-N0039") && e.contains("gave Ok(")
        ),
        "an entry whose verbatim probe succeeds must fail the gate: {checked:?}"
    );
}

/// Refusal: a seal variable absent from the annotation fails the gate.
#[test]
fn unprobeable_gate_refuses_an_unused_seal() {
    let (m, member) = custom_element_node(NODE_ANNOTATION);
    let entry = Unprobeable {
        path: "Ipe.Ffi.Js.CustomElement.node",
        code: "IPE-N0039",
        seal_vars: &["down", "up", "absent"],
    };
    let checked = check_unprobeable(&m, &member, &entry);
    assert!(
        checked
            .as_ref()
            .is_err_and(|e| e.contains("does not occur in the annotation")),
        "an unused seal variable must fail the gate: {checked:?}"
    );
}

/// Refusal: an annotation whose sealed restatement differs from the enforced
/// scheme fails the gate even though its verbatim refusal code matches.
#[test]
fn unprobeable_gate_refuses_a_sealed_drift() {
    let drifted = "CustomElement down up -> up -> (up -> msg) -> Element msg";
    let (m, member) = custom_element_node(drifted);
    let entry = Unprobeable {
        path: "Ipe.Ffi.Js.CustomElement.node",
        code: "IPE-N0039",
        seal_vars: &["down", "up"],
    };
    let checked = check_unprobeable(&m, &member, &entry);
    assert!(
        checked
            .as_ref()
            .is_err_and(|e| e.contains("is not the enforced scheme")),
        "a drifted sealed restatement must fail the gate: {checked:?}"
    );
}

/// Control: the seal comparator pairs each seal with one scheme variable, and
/// refuses one seal standing for two distinct variables.
#[test]
fn seal_comparison_is_bijective() {
    let mut interner = Interner::new();
    let seal = interner.intern("IpeProbeSeal0");
    assert!(seal.is_ok(), "interning a seal name must succeed");
    let seal = seal.expect("`seal` must succeed");
    let seal_ty = Ty::Con {
        module: Vec::new(),
        name: seal,
        args: Vec::new(),
    };
    let seals = BTreeSet::from([seal_name(0)]);
    let same = Ty::Fun(Box::new(seal_ty.clone()), Box::new(seal_ty));
    let scheme_same = Ty::Fun(Box::new(Ty::Var(1)), Box::new(Ty::Var(1)));
    let scheme_split = Ty::Fun(Box::new(Ty::Var(1)), Box::new(Ty::Var(2)));
    assert!(alpha_eq(
        &same,
        &scheme_same,
        &interner,
        &mut VarPairs::with_seals(&seals)
    ));
    assert!(!alpha_eq(
        &same,
        &scheme_split,
        &interner,
        &mut VarPairs::with_seals(&seals)
    ));
    assert!(
        !alpha_eq(&same, &scheme_same, &interner, &mut VarPairs::default()),
        "an undeclared nullary type is never a scheme variable"
    );
}

/// `File.readFileLimit` takes the documented `ByteSize` ceiling.
#[test]
fn file_read_file_limit_takes_a_byte_size_ceiling() {
    let main = concat!(
        "module Main exposing (main)\n",
        "import Ipe.ByteSize as ByteSize exposing (ByteSize)\n",
        "import Ipe.File as File\n",
        "import Ipe.Io as Io\n",
        "import Ipe.Path as Path exposing (Path)\n",
        "import Ipe.Task as Task\n\n",
        "sourceCeiling : ByteSize\n",
        "sourceCeiling =\n",
        "    ByteSize.mib 16\n\n",
        "readCapped : Path -> Task Error String\n",
        "readCapped path =\n",
        "    File.readFileLimit path sourceCeiling\n\n",
        "main : Task Error ()\n",
        "main =\n",
        "    Path.fromString \"/tmp/ipe-probe\"\n",
        "        |> Task.fromResult\n",
        "        |> Task.andThen readCapped\n",
        "        |> Task.andThen Io.println\n",
    );
    let outcome = compile_main(main);
    assert!(
        outcome.is_ok(),
        "`File.readFileLimit path (ByteSize.mib 16)` must type-check: {:?}",
        outcome.err(),
    );
}

/// Refusal: a bare `Int` ceiling (unit-ambiguous) is rejected.
#[test]
fn file_read_file_limit_rejects_a_bare_int_ceiling() {
    let main = concat!(
        "module Main exposing (main)\n",
        "import Ipe.File as File\n",
        "import Ipe.Io as Io\n",
        "import Ipe.Path as Path exposing (Path)\n",
        "import Ipe.Task as Task\n\n",
        "readBare : Path -> Task Error String\n",
        "readBare file =\n",
        "    File.readFileLimit file 16\n\n",
        "main : Task Error ()\n",
        "main =\n",
        "    Path.fromString \"/tmp/ipe-probe\"\n",
        "        |> Task.fromResult\n",
        "        |> Task.andThen readBare\n",
        "        |> Task.andThen Io.println\n",
    );
    let outcome = compile_main(main);
    assert!(
        outcome.as_ref().is_err_and(|e| e.contains("ByteSize")),
        "a bare-`Int` ceiling must be a type error naming `ByteSize`: {outcome:?}",
    );
}

/// `path` is an ordinary name: a binder called `path` applied to a string
/// literal is a plain call, whatever the literal holds.
#[test]
fn a_binder_named_path_applied_to_a_string_is_an_ordinary_call() {
    let main = concat!(
        "module Main exposing (main)\n",
        "import Ipe.File as File\n",
        "import Ipe.Path as Path exposing (Path)\n",
        "import Ipe.Task as Task\n\n",
        "truncate : Path -> Task Error ()\n",
        "truncate path =\n",
        "    File.writeFile path \"\"\n\n",
        "main : Task Error ()\n",
        "main =\n",
        "    Path.fromString \"/tmp/ipe-probe\"\n",
        "        |> Task.fromResult\n",
        "        |> Task.andThen truncate\n",
    );
    let outcome = compile_main(main);
    assert!(
        outcome.is_ok(),
        "`File.writeFile path \"\"` with a `path` binder must type-check: {:?}",
        outcome.err(),
    );
}

/// A `Main` that imports the `Styles` helper, so the helper is type-checked.
const STYLES_MAIN: &str = "module Main exposing (main)\nimport Ipe.Io as Io\nimport Styles\n\n\
                           main : Task Error ()\nmain =\n    Io.println \"ok\"\n";

fn compile_styles(styles: &str) -> Result<(), String> {
    compile_main_with_helper(
        STYLES_MAIN,
        &[(vec!["Styles".to_owned()], styles.to_owned())],
    )
}

/// The terminal engines' documented `Attribute msg` is nameable: qualified,
/// exposed bare, and through the `Ipe.Ui.Cells` re-export, each unifying with
/// the attributes the engine's builders mint.
#[test]
fn terminal_attribute_types_are_nameable() {
    let styles = concat!(
        "module Styles exposing (banner, bare, legacy, legacyView, line)\n",
        "import Ipe.Color.Ansi as Ansi\n",
        "import Ipe.Ui.Cells as Cells\n",
        "import Ipe.Ui.Cli as Cli\n",
        "import Ipe.Ui.Tui as Tui exposing (Attribute, Screen)\n\n",
        "emphasis : List (Tui.Attribute msg)\n",
        "emphasis =\n    [ Tui.bold, Tui.color Ansi.red ]\n\n",
        "banner : Screen msg\n",
        "banner =\n    Tui.el emphasis (Tui.text \"hi\")\n\n",
        "bare : List (Attribute msg)\n",
        "bare =\n    [ Tui.dim ]\n\n",
        "legacy : List (Cells.Attribute msg)\n",
        "legacy =\n    [ Tui.underline ]\n\n",
        "legacyView : Cells.Screen msg\n",
        "legacyView =\n    Cells.el legacy (Cells.text \"x\")\n\n",
        "lineAttrs : List (Cli.Attribute msg)\n",
        "lineAttrs =\n    [ Cli.bold ]\n\n",
        "line : Cli.Lines msg\n",
        "line =\n    Cli.line lineAttrs \"x\"\n",
    );
    let outcome = compile_styles(styles);
    assert!(
        outcome.is_ok(),
        "terminal `Attribute msg` annotations must type-check: {:?}",
        outcome.err(),
    );
}

/// Refusal: the two terminal engines' attributes stay distinct types — a Cli
/// attribute in a Tui builder is a type error, not a silent coercion.
#[test]
fn terminal_attribute_types_stay_distinct() {
    let styles = concat!(
        "module Styles exposing (banner)\n",
        "import Ipe.Ui.Cli as Cli\n",
        "import Ipe.Ui.Tui as Tui\n\n",
        "banner : Tui.Screen msg\n",
        "banner =\n    Tui.el [ Cli.bold ] (Tui.text \"hi\")\n",
    );
    let outcome = compile_styles(styles);
    assert!(
        outcome.as_ref().is_err_and(|e| e.contains("IPE-T0001")),
        "a Cli attribute in a Tui builder must be a type mismatch: {outcome:?}",
    );
}

/// Refusal: a Tui colour attribute takes a terminal-palette `AnsiColor`, so the
/// sRGB colour surface (`Color`/`rgb`/`rgba`/`white`/`black`) is not exported at
/// all — there is no sRGB colour a Tui program could even name to pass to
/// `Tui.color`. `Ipe.Ui.Tui` never declared these locally (they aliased the
/// WEB module's sRGB kernels via the global `Color` builtin reservation), so a
/// reference to `Tui.white` fails name resolution rather than type-checking.
#[test]
fn tui_does_not_export_an_srgb_color_surface() {
    let styles = concat!(
        "module Styles exposing (tint)\n",
        "import Ipe.Ui.Tui as Tui\n\n",
        "tint : Tui.Attribute msg\n",
        "tint =\n    Tui.color Tui.white\n",
    );
    let outcome = compile_styles(styles);
    assert!(
        outcome.as_ref().is_err_and(|e| e.contains("IPE-N0005")),
        "`Tui.white` must fail name resolution now that Tui exports no sRGB \
         colour surface: {outcome:?}",
    );
}
