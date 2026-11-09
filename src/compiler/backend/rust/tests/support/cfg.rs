//! The one `#[cfg(..)]` grammar the runtime closure checks evaluate through.
//!
//! A predicate is parsed with `syn` into a [`Cfg`] and evaluated against the
//! configuration one emitted crate builds under ([`CfgEnv`]) to a three-valued
//! [`Truth`]: it holds, it fails, or the build host decides it. An atom the
//! grammar does not know is refused, never read as either truth.

use std::collections::BTreeSet;

/// Whether a `#[cfg(..)]` predicate holds in one emitted build.
///
/// It holds, it fails, or it varies with the host the emitted crate is built
/// on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Truth {
    Holds,
    Fails,
    Varies,
}

impl Truth {
    pub const fn and(self, other: Self) -> Self {
        match (self, other) {
            (Self::Fails, _) | (_, Self::Fails) => Self::Fails,
            (Self::Holds, Self::Holds) => Self::Holds,
            (Self::Holds | Self::Varies, Self::Varies) | (Self::Varies, Self::Holds) => {
                Self::Varies
            }
        }
    }

    pub const fn or(self, other: Self) -> Self {
        match (self, other) {
            (Self::Holds, _) | (_, Self::Holds) => Self::Holds,
            (Self::Fails, Self::Fails) => Self::Fails,
            (Self::Fails | Self::Varies, Self::Varies) | (Self::Varies, Self::Fails) => {
                Self::Varies
            }
        }
    }

    /// The truth of a decided atom.
    const fn of(holds: bool) -> Self {
        if holds { Self::Holds } else { Self::Fails }
    }

    pub const fn not(self) -> Self {
        match self {
            Self::Holds => Self::Fails,
            Self::Fails => Self::Holds,
            Self::Varies => Self::Varies,
        }
    }
}

/// One parsed `#[cfg(..)]` predicate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Cfg {
    /// `feature = "<name>"`.
    Feature(String),
    /// `test`, and a `#[test]` function: never set in an emitted build.
    Test,
    /// `target_arch = "wasm32"` / `target_family = "wasm"`.
    Wasm,
    /// An atom the build host decides: `unix`, `windows`, `target_os = ..`,
    /// `panic = ..`, a `--cfg` flag the toolchain sets.
    Host,
    All(Vec<Self>),
    Any(Vec<Self>),
    Not(Box<Self>),
}

/// The bare cfg flags the build host decides.
const HOST_CFG_FLAGS: &[&str] = &["unix", "windows", "debug_assertions", "ipe_asan"];

/// The `key = ".."` cfg atoms the build host decides, whatever the value.
const HOST_CFG_KEYS: &[&str] = &[
    "target_os",
    "target_vendor",
    "target_env",
    "target_pointer_width",
    "target_endian",
    "target_has_atomic",
    "panic",
];

/// Parse one cfg predicate.
///
/// A predicate the evaluator cannot read is refused, never read as either
/// truth.
pub fn parse_cfg(meta: &syn::Meta) -> Result<Cfg, String> {
    let name = meta
        .path()
        .get_ident()
        .map(ToString::to_string)
        .unwrap_or_default();
    match meta {
        syn::Meta::Path(_) => match name.as_str() {
            "test" => Ok(Cfg::Test),
            flag if HOST_CFG_FLAGS.contains(&flag) => Ok(Cfg::Host),
            _ => Err(format!("unknown cfg flag `{name}`")),
        },
        syn::Meta::NameValue(pair) => {
            let syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Str(value),
                ..
            }) = &pair.value
            else {
                return Err(format!("cfg `{name} = ..` carries no string value"));
            };
            let value = value.value();
            match (name.as_str(), value.as_str()) {
                ("feature", _) => Ok(Cfg::Feature(value)),
                ("target_arch", "wasm32") | ("target_family", "wasm") => Ok(Cfg::Wasm),
                ("target_arch" | "target_family", _) => Ok(Cfg::Host),
                (key, _) if HOST_CFG_KEYS.contains(&key) => Ok(Cfg::Host),
                _ => Err(format!("unknown cfg atom `{name} = \"{value}\"`")),
            }
        }
        syn::Meta::List(list) => {
            let args = list
                .parse_args_with(
                    syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
                )
                .map_err(|e| format!("cfg `{name}(..)` does not parse: {e}"))?
                .iter()
                .map(parse_cfg)
                .collect::<Result<Vec<_>, _>>()?;
            match name.as_str() {
                "all" => Ok(Cfg::All(args)),
                "any" => Ok(Cfg::Any(args)),
                "not" => {
                    let mut args = args.into_iter();
                    match (args.next(), args.next()) {
                        (Some(one), None) => Ok(Cfg::Not(Box::new(one))),
                        _ => Err("cfg `not(..)` takes exactly one predicate".to_owned()),
                    }
                }
                _ => Err(format!("unknown cfg combinator `{name}(..)`")),
            }
        }
    }
}

/// The predicate `attrs` compile their node under.
///
/// Every `#[cfg(..)]` is joined, and a `#[test]` function is compiled only by
/// a test build. `None` when no attribute gates the node; `#[cfg_attr(..)]`
/// gates nothing.
pub fn attrs_cfg(attrs: &[syn::Attribute]) -> Result<Option<Cfg>, String> {
    let mut all = Vec::new();
    for attr in attrs {
        let path = attr.path();
        if path.is_ident("cfg") {
            let meta = attr
                .parse_args::<syn::Meta>()
                .map_err(|e| format!("`#[cfg(..)]` does not parse: {e}"))?;
            all.push(parse_cfg(&meta)?);
        } else if path.segments.last().is_some_and(|seg| seg.ident == "test") {
            all.push(Cfg::Test);
        }
    }
    Ok((!all.is_empty()).then_some(Cfg::All(all)))
}

/// Every top-level `mod` declaration of `file`, with the predicate it is
/// compiled under.
///
/// The predicate joins the file's inner `#![cfg(..)]` with the declaration's
/// own attributes; an unreadable predicate refuses the whole file.
pub fn top_level_mods(file: &syn::File) -> Result<Vec<(&syn::ItemMod, Cfg)>, String> {
    let file_cond = attrs_cfg(&file.attrs)?;
    file.items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Mod(m) => Some(m),
            _ => None,
        })
        .map(|m| {
            let mut all: Vec<Cfg> = file_cond.iter().cloned().collect();
            all.extend(attrs_cfg(&m.attrs)?);
            Ok((m, Cfg::All(all)))
        })
        .collect()
}

/// The configuration one emitted crate builds under.
///
/// It is the set of Cargo features (and optional dependencies) on and whether
/// the crate targets wasm32. `test` is never set.
pub struct CfgEnv {
    pub features: BTreeSet<String>,
    pub wasm: bool,
}

impl CfgEnv {
    pub fn eval(&self, cfg: &Cfg) -> Truth {
        match cfg {
            Cfg::Feature(name) => Truth::of(self.features.contains(name)),
            Cfg::Test => Truth::Fails,
            Cfg::Wasm => Truth::of(self.wasm),
            Cfg::Host => Truth::Varies,
            Cfg::All(all) => all
                .iter()
                .fold(Truth::Holds, |truth, c| truth.and(self.eval(c))),
            Cfg::Any(any) => any
                .iter()
                .fold(Truth::Fails, |truth, c| truth.or(self.eval(c))),
            Cfg::Not(inner) => self.eval(inner).not(),
        }
    }
}

/// The top-level modules a crate root declares, each with every predicate it
/// is declared under.
///
/// Read by the dependency-model closures, which ask whether the runtime crate
/// compiles a module an emitted program names as `ipe_runtime::<module>::`.
#[allow(dead_code)] // the module-set closure reads declarations through `top_level_mods`
pub struct ModuleGates {
    decls: Vec<(String, Cfg)>,
}

#[allow(dead_code)] // the module-set closure reads declarations through `top_level_mods`
impl ModuleGates {
    /// Parse a crate root's source; a file that does not parse, or a
    /// declaration predicate the grammar cannot read, is refused.
    pub fn parse(src: &str) -> Result<Self, String> {
        let file = syn::parse_file(src).map_err(|e| format!("crate root does not parse: {e}"))?;
        let decls = top_level_mods(&file)?
            .into_iter()
            .map(|(m, cond)| (m.ident.to_string(), cond))
            .collect();
        Ok(Self { decls })
    }

    /// Whether the crate compiles module `name` in `env`.
    ///
    /// A module declared more than once is compiled when any declaration is;
    /// an undeclared module fails.
    pub fn truth(&self, name: &str, env: &CfgEnv) -> Truth {
        self.decls
            .iter()
            .filter(|(decl, _)| decl == name)
            .fold(Truth::Fails, |truth, (_, cond)| truth.or(env.eval(cond)))
    }

    /// Every module in `modules` the crate does not compile in every build of
    /// `env`, one line each.
    ///
    /// A module is satisfied only when its declaration holds: one declared
    /// under a predicate the build host decides is absent on some host, and an
    /// undeclared one is absent everywhere.
    pub fn unsatisfied<'m>(
        &self,
        modules: impl IntoIterator<Item = &'m String>,
        env: &CfgEnv,
    ) -> Vec<String> {
        modules
            .into_iter()
            .filter_map(|name| {
                let conds: Vec<&Cfg> = self
                    .decls
                    .iter()
                    .filter(|(decl, _)| decl == name)
                    .map(|(_, cond)| cond)
                    .collect();
                let verdict = match self.truth(name, env) {
                    Truth::Holds => return None,
                    Truth::Fails if conds.is_empty() => "is not declared",
                    Truth::Fails => "is not compiled",
                    Truth::Varies => "is compiled only on some build hosts",
                };
                Some(format!(
                    "`ipe_runtime::{name}::` needs `mod {name}`, which {verdict} (declared under {conds:?})"
                ))
            })
            .collect()
    }

    /// Whether the crate declares no module at all.
    pub const fn is_empty(&self) -> bool {
        self.decls.is_empty()
    }
}
