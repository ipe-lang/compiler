//! Pins every stdlib union named like a builtin type to its head identity.
//!
//! An `Ipe`-rooted union shares its head with the empty-home builtin of the
//! same name unless `ipe_types::STDLIB_DISTINCT_UNIONS` lists it. A builtin
//! type name is any name the canonicaliser treats as a builtin, a builtin union
//! declares, or a kernel scheme mints with the empty home. A stdlib union
//! reusing one is therefore the builtin's own spelling (an exact constructor
//! mirror of a builtin union, a shared opaque carrier, or a listed source
//! declaration of a runtime type) or listed as distinct; anything else would
//! let a value of one type type-check where the other is expected.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use ipe_canon::builtins::BUILTIN_UNIONS;
use ipe_intern::Interner;
use ipe_types::Ty;

/// Stdlib unions whose declaration is the source form of the runtime type the
/// empty-home builtin of that name lowers to, so the two are one head.
///
/// Each entry is `(home, name)`.
const SAME_HEAD_DECLARATIONS: &[(&[&str], &str)] = &[
    // The retry-backoff schedule: the `Task` retry kernels name the empty-home
    // `BackoffStrategy`, and both spellings lower to the runtime
    // `task::BackoffStrategy`.
    (&["Ipe", "Task"], "BackoffStrategy"),
];

/// One stdlib union whose name is a builtin type name.
#[derive(Debug)]
struct Collision {
    home: Vec<String>,
    name: String,
    /// `(constructor name, payload arity)` in declaration order.
    ctors: Vec<(String, usize)>,
}

/// Every `.ipe` file under `dir`, recursively, in a stable order.
fn ipe_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    let read = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let mut entries = Vec::new();
    for entry in read {
        entries.push(entry.map_err(|e| format!("{}: {e}", dir.display()))?.path());
    }
    entries.sort();
    for path in entries {
        if path.is_dir() {
            ipe_files(&path, out)?;
        } else if path.extension().is_some_and(|ext| ext == "ipe") {
            out.push(path);
        }
    }
    Ok(())
}

/// The stdlib source root.
fn stdlib_root() -> PathBuf {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../stdlib")).to_path_buf()
}

/// The interned string behind `sym`.
fn text(interner: &Interner, sym: ipe_intern::Symbol) -> Result<String, String> {
    interner
        .resolve(sym)
        .map(str::to_owned)
        .ok_or_else(|| format!("no backing string for symbol {}", sym.as_raw()))
}

/// Collect the name of every empty-home constructor head inside `ty`.
fn empty_home_heads(
    ty: &Ty,
    interner: &Interner,
    out: &mut BTreeSet<String>,
) -> Result<(), String> {
    match ty {
        Ty::Var(_) | Ty::Wildcard | Ty::Unit => Ok(()),
        Ty::Fun(arg, result) => {
            empty_home_heads(arg, interner, out)?;
            empty_home_heads(result, interner, out)
        }
        Ty::Con { module, name, args } => {
            if module.is_empty() {
                out.insert(text(interner, *name)?);
            }
            args.iter()
                .try_for_each(|arg| empty_home_heads(arg, interner, out))
        }
        Ty::Tuple(items) => items
            .iter()
            .try_for_each(|item| empty_home_heads(item, interner, out)),
        Ty::Record(fields, _) => fields
            .values()
            .try_for_each(|field| empty_home_heads(field, interner, out)),
    }
}

/// Every type name a kernel scheme mints with the empty builtin home.
fn kernel_empty_home_names() -> Result<BTreeSet<String>, String> {
    let mut interner = Interner::new();
    let table = ipe_types::kernel_type_table(&mut interner)
        .map_err(|e| format!("the kernel type table must build: {e:?}"))?;
    let mut names = BTreeSet::new();
    for (_, ty) in table.schemed() {
        empty_home_heads(ty, &interner, &mut names)?;
    }
    if names.is_empty() {
        return Err("no kernel scheme mints an empty-home type".to_owned());
    }
    Ok(names)
}

/// Every stdlib union whose name is a builtin type name.
fn collisions() -> Result<Vec<Collision>, String> {
    let kernel_names = kernel_empty_home_names()?;
    let is_builtin_name = |name: &str| {
        ipe_canon::is_reserved_builtin_type_name(name)
            || BUILTIN_UNIONS.iter().any(|b| b.type_name == name)
            || kernel_names.contains(name)
    };
    let root = stdlib_root();
    let mut files = Vec::new();
    ipe_files(&root, &mut files)?;
    if files.is_empty() {
        return Err(format!("no stdlib sources under {}", root.display()));
    }
    let mut found = Vec::new();
    for file in files {
        let src = std::fs::read_to_string(&file).map_err(|e| format!("{}: {e}", file.display()))?;
        let mut interner = Interner::new();
        let module = ipe_parse::parse_module(&src, &mut interner)
            .map_err(|e| format!("{} must parse: {e:?}", file.display()))?;
        let relative = file
            .strip_prefix(&root)
            .map_err(|e| format!("{}: {e}", file.display()))?;
        let home: Vec<String> = relative
            .with_extension("")
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect();
        for union in &module.unions {
            let name = text(&interner, union.value.name.value)?;
            if !is_builtin_name(&name) {
                continue;
            }
            let mut ctors = Vec::with_capacity(union.value.ctors.len());
            for c in &union.value.ctors {
                ctors.push((text(&interner, c.value.name)?, c.value.args.len()));
            }
            found.push(Collision {
                home: home.clone(),
                name,
                ctors,
            });
        }
    }
    Ok(found)
}

/// Whether `home.name` is an entry of `table`.
fn listed_in(table: &[(&[&str], &str)], home: &[String], name: &str) -> bool {
    table.iter().any(|(entry_home, entry_name)| {
        *entry_name == name
            && entry_home
                .iter()
                .copied()
                .eq(home.iter().map(String::as_str))
    })
}

/// Whether `home.name` is listed in `STDLIB_DISTINCT_UNIONS`.
fn listed_distinct(home: &[String], name: &str) -> bool {
    listed_in(ipe_types::STDLIB_DISTINCT_UNIONS, home, name)
}

/// Whether `ctors` is exactly the builtin union `name`'s constructor list.
fn mirrors_builtin(name: &str, ctors: &[(String, usize)]) -> bool {
    BUILTIN_UNIONS
        .iter()
        .filter(|b| b.type_name == name)
        .any(|b| {
            b.ctors.len() == ctors.len()
                && b.ctors
                    .iter()
                    .zip(ctors)
                    .all(|((want, _, arity), (got, got_arity))| {
                        *want == got.as_str() && arity == got_arity
                    })
        })
}

/// Whether the stdlib union `c` is the builtin's own spelling: an exact
/// constructor mirror, a shared opaque carrier, or a listed source declaration.
fn is_builtin_spelling(c: &Collision) -> bool {
    mirrors_builtin(&c.name, &c.ctors)
        || ipe_canon::is_stdlib_shared_carrier_type(&c.name)
        || listed_in(SAME_HEAD_DECLARATIONS, &c.home, &c.name)
}

/// A stdlib union reusing a builtin type name is either the builtin's own
/// spelling or listed as a distinct head.
#[test]
fn every_builtin_named_stdlib_union_is_a_spelling_or_listed_distinct() {
    let found = collisions().expect("the stdlib scan must succeed");
    let unclassified: Vec<String> = found
        .into_iter()
        .filter(|c| !is_builtin_spelling(c) && !listed_distinct(&c.home, &c.name))
        .map(|c| format!("{}.{}", c.home.join("."), c.name))
        .collect();
    assert!(
        unclassified.is_empty(),
        "these stdlib unions reuse a builtin type name without being its spelling \
         and would merge with the builtin head; list them in \
         `STDLIB_DISTINCT_UNIONS`: {unclassified:?}"
    );
}

/// Every `STDLIB_DISTINCT_UNIONS` entry names a stdlib union that exists and
/// is not the builtin's spelling, so the table never carries a stale entry.
#[test]
fn every_listed_distinct_union_is_a_real_non_mirror() {
    let found = collisions().expect("the stdlib scan must succeed");
    for (home, name) in ipe_types::STDLIB_DISTINCT_UNIONS {
        let entry = found.iter().find(|c| {
            c.name == *name && home.iter().copied().eq(c.home.iter().map(String::as_str))
        });
        assert!(
            entry.is_some_and(|c| !is_builtin_spelling(c)),
            "`{}.{name}` is listed distinct but no stdlib union of that home and \
             name exists apart from the builtin's own spelling",
            home.join(".")
        );
    }
}

/// Every `SAME_HEAD_DECLARATIONS` entry names a builtin-named stdlib union that
/// exists and is not also listed distinct.
#[test]
fn every_same_head_declaration_is_a_real_unlisted_union() {
    let found = collisions().expect("the stdlib scan must succeed");
    for (home, name) in SAME_HEAD_DECLARATIONS {
        let exists = found
            .iter()
            .any(|c| c.name == *name && home.iter().copied().eq(c.home.iter().map(String::as_str)));
        assert!(
            exists,
            "`{}.{name}` is a same-head declaration but no stdlib union of that \
             home and name is named like a builtin",
            home.join(".")
        );
        let home_owned: Vec<String> = home.iter().map(|s| (*s).to_owned()).collect();
        assert!(
            !listed_distinct(&home_owned, name),
            "`{}.{name}` cannot be both one head with the builtin and distinct",
            home.join(".")
        );
    }
}

/// The builtin-name universe reaches beyond the builtin unions: `Color` and
/// `Length` are opaque builtins no builtin union declares, and the scan must
/// still classify the `Ipe.Css` unions named after them.
#[test]
fn the_scan_sees_opaque_builtin_names() {
    let found = collisions().expect("the stdlib scan must succeed");
    for name in ["Color", "Length"] {
        assert!(
            found
                .iter()
                .any(|c| c.name == name && c.home == ["Ipe", "Css"]),
            "`Ipe.Css.{name}` must be classified against the builtin `{name}`"
        );
    }
}
