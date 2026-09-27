//! The injectable Ipê interface module — the consumer-side seed artifact.
//!
//! For each bound crate the driver injects one ordinary, fully-annotated Ipê
//! module (`module Rust.Semver exposing (…)`) whose value bodies are
//! `Ffi.binding "<wrapper_fn_ident>" a0 …` forwarders. FFI signatures thus
//! flow through the SAME annotation → `Ty` path every user annotation takes:
//! there is no second, hand-maintained scheme table to drift against
//! (the kernel-registry design's OPEN DECISION 1, resolved by construction).
//!
//! Inclusion is gated fail-closed: a function reaches the interface only when
//! its wrapper region actually exists in `_bindings.rs`, its signature's
//! opaque foreign types all resolve to unambiguous Rust paths, and no foreign
//! type shadows an Ipê reserved builtin type. Anything else is skipped with a
//! reason (over-drop, never an under-bind that `cargo` rejects).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use crate::emit::{opaque_names_in, transparent_type_decl, wrapper_ipe_signature};
use crate::pkginfo::{FnInfo, PkgInfo};
use crate::transparency::TransparentType;

/// One binding included in the interface module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceBinding {
    /// The Ipê-visible name (= `wrapper_ref_name`, the `kernel.json` key).
    pub ref_name: String,
    /// The `_bindings.rs` wrapper `pub fn` identifier the body forwards to.
    pub wrapper_ident: String,
    /// Ipê-side arity (unit param for a zero-arg foreign fn).
    pub arity: usize,
    /// The full Ipê HM signature string.
    pub sig: String,
    /// Per-parameter transparent-type nominal, aligned with the Ipê arity —
    /// `Some(name)` marks a position whose value the backend converts between
    /// the Ipê record/union and the foreign struct/enum at the call seam.
    /// Empty when no transparent type occurs anywhere in the signature.
    pub transparent_params: Vec<Option<String>>,
    /// The result's transparent payload, when the binding returns one.
    pub transparent_result: Option<TransparentResult>,
}

/// A binding result that carries a transparent foreign type: the nominal and
/// whether it sits inside the fallibility wrapper (`Result Error T`) or bare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransparentResult {
    /// The transparent type's Ipê-visible nominal.
    pub type_name: String,
    /// `true` for a `Result Error T` result, `false` for a bare `T`.
    pub in_result: bool,
}

/// A binding excluded from the interface, with the reason — surfaced in the
/// coverage report so an over-drop is visible, never silent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedBinding {
    /// The `wrapper_ref_name` of the skipped function.
    pub ref_name: String,
    /// Why it was excluded.
    pub reason: String,
}

/// The complete consumer-side view of one bound crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrateInterface {
    /// Ipê module qualifier, e.g. `Rust.Semver`.
    pub module_name: String,
    /// Kernel-name prefix, e.g. `Rust_Semver`.
    pub kernel_name: String,
    /// The injectable Ipê module source.
    pub source: String,
    /// Opaque foreign type name → absolute Rust path (`Version` →
    /// `::semver::Version`), for backend type rendering.
    pub opaque_types: BTreeMap<String, String>,
    /// Opaque foreign type name → the type's canonical DEFINING path (the
    /// rustdoc `paths` identity). Drives cross-crate nominal unification:
    /// two member modules whose same-named opaques carry the SAME defining
    /// path are the SAME Rust type and collapse to one Ipê nominal. A name
    /// absent here (older cache / no recoverable identity) never unifies.
    pub opaque_type_ids: BTreeMap<String, String>,
    /// The nominal names this crate's define surfaces DEFINE **and surface as
    /// opaque handles** (`type N = N`) — closure handles always, and any
    /// `[rust.define.struct/enum]` type that does not qualify for the
    /// transparent surface. Unlike [`Self::opaque_types`] — external crate
    /// types the inspector found at an absolute `::crate::Path` — a define type
    /// is DEFINED in the emitted `_bindings.rs` and lives at
    /// `crate::ffi::<slug>::<Name>`. The slug is not known here (the interface
    /// generator has only the `PkgInfo`), so the crate-local path is assembled
    /// downstream (`assemble_emit`) where the slug is; this set is the ground
    /// truth for WHICH names are define-defined so the two paths never blur. A
    /// define type that surfaces transparently lives in
    /// [`Self::transparent_types`] instead — a name is a record/union OR a
    /// handle, never both.
    pub define_types: BTreeSet<String>,
    /// The transparent types this interface SURFACES, keyed by Ipê-visible
    /// nominal — both provenances of the representation axis:
    ///
    /// * imported crate types the classification decoded transparent, narrowed
    ///   to the names the interface admits (no collision with another surface,
    ///   a path consistent with the signatures) AND some admitted binding
    ///   references — an unreferenced transparent import is pruned here, never
    ///   carried dead into every downstream artifact;
    /// * define-defined structs/enums whose every member is an identity
    ///   carrier and which no other define surface holds opaquely — their
    ///   `rust_path` is the BARE nominal (the define convention), resolved
    ///   crate-locally downstream where the cache slug is known.
    ///
    /// These names are excluded from [`Self::opaque_types`] and
    /// [`Self::define_types`]: a name is a record/union OR a handle, never
    /// both.
    pub transparent_types: BTreeMap<String, TransparentType>,
    /// The included bindings.
    pub bindings: Vec<InterfaceBinding>,
    /// The excluded bindings, with reasons.
    pub skipped: Vec<SkippedBinding>,
}

/// Collect `Name → ::absolute::path` for every nominal foreign type mentioned
/// in the package's Rust type strings.
///
/// A base name claimed by two DIFFERENT paths is poisoned (removed): two
/// distinct foreign types would otherwise unify nominally on the Ipê side.
/// Poisoned names travel back so the per-fn gate can drop their users.
fn foreign_path_map(pkg: &PkgInfo) -> (BTreeMap<String, String>, BTreeSet<String>) {
    let mut map: BTreeMap<String, String> = BTreeMap::new();
    let mut poisoned: BTreeSet<String> = BTreeSet::new();
    let mut visit = |raw: &str| {
        for (base, path) in path_tokens(raw) {
            match map.get(&base) {
                Some(prev) if *prev != path => {
                    poisoned.insert(base);
                }
                Some(_) => {}
                None => {
                    map.insert(base, path);
                }
            }
        }
    };
    for f in pkg.fns() {
        visit(f.recv_rust_type());
        for p in f.params().iter().chain(f.results().iter()) {
            visit(p.rust_type_str());
            visit(&p.foreign_ty);
        }
    }
    for name in &poisoned {
        map.remove(name);
    }
    (map, poisoned)
}

/// Extract every `seg::…::Base` path token from a Rust type string, returning
/// `(Base, ::seg::…::Base)` pairs. Generic arguments split into their own
/// tokens; a bare identifier (no `::`) carries no path and is skipped.
fn path_tokens(raw: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut token = String::new();
    let flush = |token: &mut String, out: &mut Vec<(String, String)>| {
        if token.contains("::") {
            let normalized = if token.starts_with("::") {
                token.clone()
            } else {
                format!("::{token}")
            };
            if let Some(base) = normalized.rsplit("::").next()
                && !base.is_empty()
                && base.chars().next().is_some_and(char::is_uppercase)
            {
                out.push((base.to_owned(), normalized.clone()));
                // A SUBMODULE type surfaces under the inspector's
                // path-derived Ipê head (`checkout_session::ProductData` →
                // `Checkout_sessionProductData`); the map must answer for
                // that key too or every submodule type is "unresolvable".
                let composite = ipe_head_from_rust_path(&normalized);
                if !composite.is_empty() && composite != *base {
                    out.push((composite, normalized));
                }
            }
        }
        token.clear();
    };
    for c in raw.chars() {
        if c.is_alphanumeric() || c == '_' || c == ':' {
            token.push(c);
        } else {
            flush(&mut token, &mut out);
        }
    }
    flush(&mut token, &mut out);
    out
}

/// The inspector's path-derived Ipê head for a qualified Rust type path —
/// submodule segments CamelCase-join ahead of the type name so same-named
/// types in different submodules stay distinct (`::regex::bytes::Regex` →
/// `BytesRegex`; `::stripe_checkout::checkout_session::ProductData` →
/// `Checkout_sessionProductData`); a crate-root type keeps its bare name
/// unless that name collides with an Ipê builtin carrier, in which case the
/// crate segment joins too (`::bytes::Bytes` → `BytesBytes`). MUST mirror the
/// inspector's `ipe_name_from_path` — a drift makes submodule types
/// "unresolvable" and silently over-drops their whole surface.
fn ipe_head_from_rust_path(path: &str) -> String {
    fn camel(s: &str) -> String {
        let mut c = s.chars();
        c.next().map_or_else(String::new, |f| {
            f.to_uppercase().collect::<String>() + c.as_str()
        })
    }
    let segs: Vec<&str> = path.split("::").filter(|s| !s.is_empty()).collect();
    match segs.as_slice() {
        [] => String::new(),
        [one] => (*one).to_owned(),
        [crate_seg, mods @ .., ty] => {
            let builtin_collision =
                mods.is_empty() && matches!(*ty, "Bytes" | "String" | "Int" | "Float" | "Bool");
            let mut out = String::new();
            if builtin_collision {
                out.push_str(&camel(crate_seg));
            }
            for m in mods {
                out.push_str(&camel(m));
            }
            out.push_str(ty);
            out
        }
    }
}

/// Collect every foreign NOMINAL base name reachable from one Rust type
/// string — the generic HEAD and each generic ARGUMENT, recursively.
///
/// `stripe::Response<stripe::CheckoutSession>` yields both `Response` and
/// `CheckoutSession`; `Vec<semver::Error>` yields `Error`. A base is a
/// capitalised identifier (a type), never a scalar/lifetime/module segment.
fn foreign_nominal_bases(raw: &str, out: &mut BTreeSet<String>) {
    /// Bare (path-less) std heads whose Ipê mapping IS the builtin — `String`
    /// is the `String` carrier, `Vec` is `List`, … The inspector renders
    /// crate-local types with a qualified path, so a bare occurrence of one of
    /// these is std by construction, never a foreign nominal shadowing a
    /// builtin.
    const BARE_STD_CARRIERS: &[&str] = &[
        "String", "Vec", "Option", "Result", "HashMap", "BTreeMap", "HashSet", "BTreeSet",
    ];
    let mut token = String::new();
    let flush = |token: &mut String, out: &mut BTreeSet<String>| {
        // The last `::`-segment of the token is the type's own name.
        let base = token.rsplit("::").next().unwrap_or(token);
        let bare_std = !token.contains("::") && BARE_STD_CARRIERS.contains(&base);
        if base.chars().next().is_some_and(char::is_uppercase) && !bare_std {
            out.insert(base.to_owned());
        }
        token.clear();
    };
    for c in raw.chars() {
        if c.is_alphanumeric() || c == '_' || c == ':' {
            token.push(c);
        } else {
            // `<`, `,`, `>`, `&`, ` `, `(`, `)` all break a nominal token —
            // so a generic head and its args each flush separately.
            flush(&mut token, out);
        }
    }
    flush(&mut token, out);
}

/// The Ok arm of a `Result<Ok, Err>` type string (any path prefix), else the
/// input unchanged. A foreign error type in the ERR position folds into the
/// typed Ipê `Error` at the wrapper boundary — it never reaches the Ipê
/// signature, so it must be excluded from the reserved-collision scan (else a
/// legitimate `Result<Version, semver::Error>` would be over-dropped on its
/// harmless `Error` arm).
fn result_ok_arm(raw: &str) -> &str {
    let Some(open) = raw.find("Result<") else {
        return raw;
    };
    let inner = raw.get(open + "Result<".len()..).unwrap_or("");
    let mut depth = 0_i32;
    for (i, c) in inner.char_indices() {
        match c {
            '<' | '(' => depth += 1,
            '>' | ')' => depth -= 1,
            ',' if depth == 0 => return inner.get(..i).unwrap_or(inner).trim(),
            _ => {}
        }
    }
    inner
}

/// The first foreign nominal in `f`'s parameter / result / receiver types
/// that collides with an Ipê reserved builtin type name, if any.
///
/// Two scans per param: the RAW Rust type through the rust-syntax nominal
/// tokenizer (catches a foreign type folding onto a builtin HEAD), and the
/// Ipê-typed rendering through the ipe-syntax opaque scan — there the builtin
/// heads (`Result`/`Maybe`/`Task`/`Error`, …) are the language's own
/// containers, never foreign nominals, so tokenizing them as foreign would
/// over-drop every fallible binding on its own carrier.
fn foreign_reserved_collision(f: &FnInfo) -> Option<String> {
    let mut bases = BTreeSet::new();
    for p in f.params().iter().chain(f.results().iter()) {
        foreign_nominal_bases(result_ok_arm(p.rust_type_str()), &mut bases);
        opaque_names_in(&p.foreign_ty, &mut bases);
    }
    foreign_nominal_bases(f.recv_rust_type(), &mut bases);
    bases
        .into_iter()
        .find(|b| ipe_canon::is_user_type_declaration_forbidden(b))
}

/// `true` when `name` is an Ipê value identifier the generated module may bind.
///
/// The name must lex as one plain identifier token (ASCII shape, not a
/// keyword — the lexer's own table) and be lowercase-led.
fn valid_ipe_value_name(name: &str) -> bool {
    ipe_parse::is_identifier(name) && name.starts_with(|c: char| c.is_ascii_lowercase())
}

/// The classification's transparent set narrowed to the names this interface
/// may surface. Each exclusion is fail-closed and recorded: a name that
/// collides with a reserved builtin, a poisoned nominal, or a fn-signature
/// path that disagrees with the catalog's defining path falls back to the
/// opaque handle (it stays in the ordinary opaque pipeline), never to a
/// record/union whose conversion glue could name the wrong Rust type.
fn admitted_transparent(
    pkg: &PkgInfo,
    path_map: &BTreeMap<String, String>,
    poisoned: &BTreeSet<String>,
    skipped: &mut Vec<SkippedBinding>,
) -> BTreeMap<String, TransparentType> {
    let mut out = BTreeMap::new();
    for (name, t) in pkg.foreign_types().transparent() {
        let drop = |reason: String, skipped: &mut Vec<SkippedBinding>| {
            skipped.push(SkippedBinding {
                ref_name: format!("type {name}"),
                reason,
            });
        };
        if ipe_canon::is_user_type_declaration_forbidden(name) {
            drop(
                format!("transparent type `{name}` shadows an Ipê reserved builtin type"),
                skipped,
            );
            continue;
        }
        if poisoned.contains(name) {
            drop(
                format!("transparent type `{name}` is claimed by two distinct Rust paths"),
                skipped,
            );
            continue;
        }
        // The signatures resolve this nominal through `path_map`; the glue
        // resolves it through the catalog's `rust_path`. They must be one
        // path, or the record surface and the wrapper would name different
        // Rust types (an E0308 the SEAL forbids).
        if let Some(sig_path) = path_map.get(name)
            && sig_path.trim_start_matches(':') != t.rust_path().as_str().trim_start_matches(':')
        {
            drop(
                format!(
                    "transparent type `{name}` resolves to `{sig_path}` in signatures but \
                     `{}` in the type catalog",
                    t.rust_path().as_str()
                ),
                skipped,
            );
            continue;
        }
        out.insert(name.clone(), t.clone());
    }
    out
}

/// Split an Ipê signature into its top-level ` -> ` segments, keeping any
/// parenthesised region (a tuple, a grouped fn param) intact.
fn split_top_level_arrows(sig: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut depth: i64 = 0;
    for piece in sig.split(" -> ") {
        let opens = piece.chars().filter(|c| *c == '(').count();
        let closes = piece.chars().filter(|c| *c == ')').count();
        if depth > 0 {
            if let Some(last) = out.last_mut() {
                last.push_str(" -> ");
                last.push_str(piece);
            }
        } else {
            out.push(piece.to_owned());
        }
        depth += i64::try_from(opens).unwrap_or(0) - i64::try_from(closes).unwrap_or(0);
        depth = depth.max(0);
    }
    out
}

/// Where the admitted transparent types sit in one binding's signature.
///
/// The conversion glue covers a transparent type in exactly two positions: a
/// whole parameter, and the result payload (bare or directly under the
/// `Result Error` fallibility wrapper). Any other occurrence — a tuple or
/// container component, a `Task` payload — is refused so the binding
/// over-drops with a recorded reason instead of emitting a seam whose two
/// sides disagree on the representation.
fn transparent_positions(
    sig: &str,
    transparent: &BTreeMap<String, TransparentType>,
) -> Result<(Vec<Option<String>>, Option<TransparentResult>), String> {
    let occurs = |seg: &str| {
        seg.split(|c: char| !c.is_alphanumeric() && c != '_')
            .find(|tok| transparent.contains_key(*tok))
            .map(str::to_owned)
    };
    if transparent.is_empty() || occurs(sig).is_none() {
        return Ok((Vec::new(), None));
    }
    let segs = split_top_level_arrows(sig);
    let Some((result_seg, param_segs)) = segs.split_last() else {
        return Ok((Vec::new(), None));
    };
    let mut params = Vec::with_capacity(param_segs.len());
    for seg in param_segs {
        let seg = seg.trim();
        if transparent.contains_key(seg) {
            params.push(Some(seg.to_owned()));
        } else if let Some(t) = occurs(seg) {
            return Err(format!(
                "transparent type `{t}` in a parameter position the conversion glue \
                 does not cover yet"
            ));
        } else {
            params.push(None);
        }
    }
    let result_seg = result_seg.trim();
    let result = if transparent.contains_key(result_seg) {
        Some(TransparentResult {
            type_name: result_seg.to_owned(),
            in_result: false,
        })
    } else if let Some(rest) = result_seg.strip_prefix("Result Error ")
        && transparent.contains_key(rest.trim())
    {
        Some(TransparentResult {
            type_name: rest.trim().to_owned(),
            in_result: true,
        })
    } else if let Some(t) = occurs(result_seg) {
        return Err(format!(
            "transparent type `{t}` in a result position the conversion glue does not \
             cover yet"
        ));
    } else {
        None
    };
    Ok((params, result))
}

/// `true` when an Ipê signature string contains a TUPLE — a parenthesised
/// region with a top-level comma (`(Int, Int)`); `Maybe (List Int)` has no
/// comma and stays clean.
fn contains_tuple(sig: &str) -> bool {
    let mut depth = 0_u32;
    for c in sig.chars() {
        match c {
            '(' => depth = depth.saturating_add(1),
            ')' => depth = depth.saturating_sub(1),
            ',' if depth > 0 => return true,
            _ => {}
        }
    }
    false
}

/// Build the consumer-side interface for one validated package.
#[must_use]
#[allow(clippy::too_many_lines)] // one linear per-binding gate cascade
pub fn crate_interface(pkg: &PkgInfo) -> CrateInterface {
    let module_name = crate::naming::rust_module_name(pkg.pkg_path());
    let kernel_name = crate::naming::rust_kernel_name(pkg.pkg_path());
    let survivors = crate::bindings::surviving_ref_names(pkg);
    let (path_map, poisoned) = foreign_path_map(pkg);

    let mut bindings: Vec<InterfaceBinding> = Vec::new();
    let mut skipped: Vec<SkippedBinding> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut used_opaques: BTreeSet<String> = BTreeSet::new();
    let mut used_transparent: BTreeSet<String> = BTreeSet::new();
    let mut define_types: BTreeSet<String> = BTreeSet::new();
    let mut claimed_defines: BTreeSet<String> = BTreeSet::new();
    let mut define_transparent: BTreeMap<String, TransparentType> = BTreeMap::new();
    let define_refs = define_referenced_nominals(pkg);
    let admitted = admitted_transparent(pkg, &path_map, &poisoned, &mut skipped);

    for f in pkg.fns() {
        let ref_name = f.wrapper_ref_name();
        let skip = |reason: &str, skipped: &mut Vec<SkippedBinding>| {
            skipped.push(SkippedBinding {
                ref_name: ref_name.clone(),
                reason: reason.to_owned(),
            });
        };
        if ref_name.starts_with('_') {
            continue; // internal probe artifact, not a binding
        }
        if !valid_ipe_value_name(&ref_name) {
            skip("name is not a legal Ipê identifier", &mut skipped);
            continue;
        }
        if f.generic().is_some_and(|g| !g.params.is_empty()) {
            skip(
                "parametric generic — monomorphised instances are not consumer-wired yet",
                &mut skipped,
            );
            continue;
        }
        // A closure adapter's wrapper takes an Ipê function value and returns a
        // boxed Rust closure surfaced as an opaque handle nominal. It is admitted
        // as an arity-1 Ipê forwarder — `(A -> B -> R) -> <Handle>` — so a program
        // can HOLD the closure and hand it to a foreign `run`-style entrypoint,
        // never seeing the `Box<dyn Fn …>` inside.
        //
        // The admission is gated on the emitter exactly like struct/enum: an
        // unresolvable/parameterised opaque param or return (`Element<'a, Msg>`)
        // over-drops the whole region in `_bindings.rs`, dropping the ref-name
        // from `survivors`. The emitter is the single resolvability oracle — the
        // `type <Handle>` alias and the wrapper share ONE region, so the interface
        // can never surface a forwarder onto an alias/wrapper that was not emitted
        // (a SEAL breach).
        if let crate::pkginfo::FnShape::ClosureAdapter { sig } = f.shape() {
            if survivors.contains(&ref_name) {
                admit_closure_forwarder(
                    &ref_name,
                    sig,
                    &mut DefineAdmission {
                        kernel_name: &kernel_name,
                        transparent_imports: &admitted,
                        path_map: &path_map,
                        poisoned: &poisoned,
                        define_refs: &define_refs,
                        bindings: &mut bindings,
                        skipped: &mut skipped,
                        seen: &mut seen,
                        claimed: &mut claimed_defines,
                        opaque_defines: &mut define_types,
                        transparent_defines: &mut define_transparent,
                    },
                );
            } else {
                skip(
                    "define.closure with an unresolvable or parameterised opaque \
                     param/return — adapter over-dropped in _bindings.rs",
                    &mut skipped,
                );
            }
            continue;
        }
        // A define.struct / define.enum DEFINES an Ipê-held nominal Rust type
        // and admits its constructor(s) as Ipê forwarders. The whole surface is
        // synthesised from the parsed def (its `params()`/`results()` are empty —
        // it is a manifest entry, not an inspected fn), so its signature, arity,
        // and nominal name all come from the def, never from the empty fn shape.
        //
        // The forwarder is admitted only when the emitter kept the definition's
        // wrapper region: an opaque field/payload the crate cannot name (a bare or
        // lifetime/generic-parameterised handle) over-drops in `_bindings.rs`,
        // dropping the ref-name from `survivors`. Gating here keeps the interface
        // from surfacing a forwarder onto a wrapper fn that was never emitted (a
        // SEAL breach), with the emitter as the single resolvability oracle.
        if matches!(
            f.shape(),
            crate::pkginfo::FnShape::StructCtor { .. }
                | crate::pkginfo::FnShape::EnumDefCtor { .. }
        ) && !survivors.contains(&ref_name)
        {
            skip(
                "define.struct/enum with an unresolvable or parameterised opaque \
                 field/payload — definition over-dropped in _bindings.rs",
                &mut skipped,
            );
            continue;
        }
        if let crate::pkginfo::FnShape::StructCtor { def } = f.shape() {
            admit_struct_forwarder(
                &ref_name,
                def,
                &mut DefineAdmission {
                    kernel_name: &kernel_name,
                    transparent_imports: &admitted,
                    path_map: &path_map,
                    poisoned: &poisoned,
                    define_refs: &define_refs,
                    bindings: &mut bindings,
                    skipped: &mut skipped,
                    seen: &mut seen,
                    claimed: &mut claimed_defines,
                    opaque_defines: &mut define_types,
                    transparent_defines: &mut define_transparent,
                },
            );
            continue;
        }
        if let crate::pkginfo::FnShape::EnumDefCtor { def } = f.shape() {
            admit_enum_forwarders(
                &ref_name,
                def,
                &mut DefineAdmission {
                    kernel_name: &kernel_name,
                    transparent_imports: &admitted,
                    path_map: &path_map,
                    poisoned: &poisoned,
                    define_refs: &define_refs,
                    bindings: &mut bindings,
                    skipped: &mut skipped,
                    seen: &mut seen,
                    claimed: &mut claimed_defines,
                    opaque_defines: &mut define_types,
                    transparent_defines: &mut define_transparent,
                },
            );
            continue;
        }
        if !survivors.contains(&ref_name) {
            skip("no wrapper region in _bindings.rs", &mut skipped);
            continue;
        }
        // A foreign nominal that collides with an Ipê reserved builtin type is
        // unsound TWO ways: one that folds onto a builtin HEAD (`semver::Error`
        // → the Ipê `Error`, while the wrapper keeps `semver::Error` — an
        // E0308), and one that would be DECLARED as an opaque `type X`
        // (`stripe::Response` → `IPE-N0026`). The raw-type scan below catches
        // the head-fold case (which never reaches the signature's opaque set);
        // the sig-opaque scan further down catches the declared-opaque case.
        if let Some(bad) = foreign_reserved_collision(f) {
            skip(
                &format!("foreign type `{bad}` shadows an Ipê reserved builtin type"),
                &mut skipped,
            );
            continue;
        }
        let sig = wrapper_ipe_signature(f);
        // A tuple anywhere in the signature renders as a Rust tuple whose
        // integer components keep their RAW widths (`(u64, u16)`), while the
        // Ipê signature maps every integer to `Int` (i64) — the forwarder
        // would be an E0308. Over-drop until tuple-component scalar coercion
        // is wired into the wrapper emitter.
        //
        // Two shapes coerce their tuple components and so type-check: a
        // by-borrow reader's receiver-threaded tuple (`(R, T)`), whose wrapper
        // coerces the result component before pairing it with the receiver
        // handle; and a plain multi-result tuple all of whose components are
        // owned scalars — a numeric width (widened to its `Int`/`Float` carrier),
        // an owned `String`, or a `bool` (each an identity coercion). Any other
        // tuple (a `&`-borrow, opaque handle, or nested-container component)
        // still over-drops until that wiring exists.
        if contains_tuple(&sig)
            && !f.is_borrow_reader()
            && !crate::bindings::multi_result_tuple_is_coercible(f)
        {
            skip(
                "tuple in signature needs component scalar coercion — not yet wired",
                &mut skipped,
            );
            continue;
        }
        // Where the admitted transparent types sit in this signature — or a
        // recorded over-drop when one occurs in a position the conversion
        // glue does not cover (a container/tuple component, a Task payload).
        let (transparent_params, transparent_result) = match transparent_positions(&sig, &admitted)
        {
            Ok(positions) => positions,
            Err(reason) => {
                skip(&reason, &mut skipped);
                continue;
            }
        };
        // The opaque foreign types the SIGNATURE would declare (`type X`) —
        // the ground truth for both the reserved-builtin collision gate and
        // the path-resolvability gate. Reading the final signature (not the
        // raw `rust_type`) catches an inspector `ipeType` override that maps a
        // generic head like `stripe::Response<…>` to the bare `Response`.
        // An admitted transparent nominal is a record/union declaration, not
        // an opaque handle, so it leaves the opaque pipeline here.
        let mut opaques = BTreeSet::new();
        opaque_names_in(&sig, &mut opaques);
        opaques.retain(|n| !admitted.contains_key(n));
        if let Some(bad) = opaques
            .iter()
            .find(|n| ipe_canon::is_user_type_declaration_forbidden(n))
        {
            skip(
                &format!("foreign type `{bad}` shadows an Ipê reserved builtin type"),
                &mut skipped,
            );
            continue;
        }
        if let Some(bad) = opaques.iter().find(|n| poisoned.contains(*n)) {
            skip(
                &format!("foreign type `{bad}` is claimed by two distinct Rust paths"),
                &mut skipped,
            );
            continue;
        }
        if let Some(bad) = opaques.iter().find(|n| !path_map.contains_key(*n)) {
            skip(
                &format!("foreign type `{bad}` has no resolvable Rust path"),
                &mut skipped,
            );
            continue;
        }
        if !seen.insert(ref_name.clone()) {
            skip(
                "duplicate binding name — first occurrence kept",
                &mut skipped,
            );
            continue;
        }
        used_opaques.extend(opaques);
        used_transparent.extend(transparent_params.iter().flatten().cloned());
        used_transparent.extend(transparent_result.iter().map(|r| r.type_name.clone()));
        bindings.push(InterfaceBinding {
            wrapper_ident: crate::naming::wrapper_fn_ident(&kernel_name, &ref_name),
            arity: f.params().len().max(1),
            sig,
            ref_name,
            transparent_params,
            transparent_result,
        });
    }

    // Surface only the transparent types some admitted binding references —
    // an unreferenced record/union would ride dead through every downstream
    // artifact (interface module, emitted enum, glue map). The prune is
    // recorded, so over-drop stays visible.
    let mut transparent_types = admitted;
    let unreferenced: Vec<String> = transparent_types
        .keys()
        .filter(|n| !used_transparent.contains(*n))
        .cloned()
        .collect();
    for name in unreferenced {
        transparent_types.remove(&name);
        skipped.push(SkippedBinding {
            ref_name: format!("type {name}"),
            reason: "transparent type is referenced by no admitted binding — not surfaced"
                .to_owned(),
        });
    }
    // Transparent DEFINE shapes join the surfaced set after the prune: a
    // define record/union is referenced by its own constructor forwarders by
    // construction, so the unreferenced-import prune never applies to it. Key
    // collisions are impossible — the claim gate refused any define nominal an
    // admitted transparent import already holds.
    transparent_types.append(&mut define_transparent);

    let mut opaque_types: BTreeMap<String, String> = used_opaques
        .iter()
        .filter_map(|n| path_map.get(n).map(|p| (n.clone(), p.clone())))
        .collect();
    // Author-DECLARED opaque handles (`foreign X = { kind = Opaque "Type" }`)
    // join the surfaced set unconditionally: the declaration exists so the
    // handle nominal resolves even when no binding references it yet, so it is
    // NOT subject to the used-only prune above. A declared name that collides
    // with an inspected opaque of a DIFFERENT path is refused — the two are
    // different Rust types that would share one nominal; the crate's own
    // inspected opaque wins and the declaration is dropped rather than
    // overwriting the resolved path with a mismatched one.
    //
    // A declared opaque nominal that ANOTHER surface already claims — a define
    // nominal (`type N = N`) or a transparent record/union of the crate — is
    // refused, never inserted: `render_module` emits one `type <Name> = <Name>`
    // for `opaque_types.keys().chain(define_types.iter())` and one export per
    // set, so a nominal in two sets would emit a DUPLICATED `type` declaration
    // and a doubled `exposing` entry (an `E0428` / duplicate-definition the app
    // crate cannot compile — an `ipe`-exit-0 ⇒ cargo-fail SEAL breach). This
    // mirrors `claim_nominal`'s define-vs-transparent refusal: each nominal is
    // surfaced by at most ONE surface, whichever declares it second is dropped.
    for (name, path) in pkg.declared_opaques() {
        if define_types.contains(name) {
            skipped.push(SkippedBinding {
                ref_name: format!("type {name}"),
                reason: format!(
                    "declared opaque `{name}` collides with a define-defined nominal of the crate"
                ),
            });
            continue;
        }
        if transparent_types.contains_key(name) {
            skipped.push(SkippedBinding {
                ref_name: format!("type {name}"),
                reason: format!(
                    "declared opaque `{name}` collides with a transparent foreign type of the crate"
                ),
            });
            continue;
        }
        match opaque_types.get(name) {
            Some(existing) if existing == path => {}
            Some(_) => {
                // A genuine nominal/path conflict — keep the inspected path,
                // never let a declaration silently retarget an in-use handle.
            }
            None => {
                opaque_types.insert(name.clone(), path.clone());
            }
        }
    }
    let opaque_type_ids: BTreeMap<String, String> = opaque_types
        .iter()
        .filter_map(|(n, p)| {
            pkg.foreign_type_ids()
                .get(p)
                .map(|defid| (n.clone(), defid.clone()))
        })
        .collect();

    let source = render_module(
        &module_name,
        &BTreeMap::new(),
        &opaque_types,
        &define_types,
        &transparent_types,
        &bindings,
    );
    CrateInterface {
        module_name,
        kernel_name,
        source,
        opaque_types,
        opaque_type_ids,
        define_types,
        transparent_types,
        bindings,
        skipped,
    }
}

/// The shared context and sinks for admitting the define surfaces
/// (`define.struct` / `define.enum` / `define.closure`).
struct DefineAdmission<'a> {
    /// Kernel-name prefix for wrapper identifiers.
    kernel_name: &'a str,
    /// The admitted transparent IMPORT set — a define nominal colliding with
    /// one is refused (the crate's own type wins).
    transparent_imports: &'a BTreeMap<String, TransparentType>,
    /// Inspected foreign nominal → Rust path, and the ambiguous nominals —
    /// a define nominal an inspected type also claims stays opaque.
    path_map: &'a BTreeMap<String, String>,
    poisoned: &'a BTreeSet<String>,
    /// Nominals some define surface holds as an opaque carrier (a closure
    /// signature, another define's field/payload) — those seams name the
    /// defined Rust type directly, so the nominal must keep the opaque
    /// representation.
    define_refs: &'a BTreeSet<String>,
    bindings: &'a mut Vec<InterfaceBinding>,
    skipped: &'a mut Vec<SkippedBinding>,
    seen: &'a mut BTreeSet<String>,
    /// Every claimed define nominal, transparent or opaque — the E0428 gate.
    claimed: &'a mut BTreeSet<String>,
    /// Define nominals surfacing as opaque handles (`type N = N`).
    opaque_defines: &'a mut BTreeSet<String>,
    /// Define nominals surfacing as records/unions with conversion glue.
    transparent_defines: &'a mut BTreeMap<String, TransparentType>,
}

impl DefineAdmission<'_> {
    /// Record one skipped-binding row.
    fn skip(&mut self, ref_name: &str, reason: String) {
        self.skipped.push(SkippedBinding {
            ref_name: ref_name.to_owned(),
            reason,
        });
    }

    /// The representation decision for one define struct/enum nominal: the
    /// transparent shape when the definition qualifies AND no other surface
    /// pins the nominal to the opaque representation, else the reason it stays
    /// an opaque handle. Fail-closed: any doubt keeps the opaque default.
    ///
    /// Transparency is a least-fixpoint over the define types a surface names at
    /// a member seam: a define type may surface transparent only when every
    /// define type it references (a field/payload carrier, a closure signature
    /// slot) is itself transparent. A referenced type held at a member seam is
    /// pinned opaque through [`define_referenced_nominals`], so a type holding
    /// it can never qualify — [`crate::transparency::classify_define_struct`] /
    /// [`crate::transparency::classify_define_enum`] admit only identity SCALAR
    /// members, and a define-nominal member is not a scalar. The referenced
    /// type's un-flip therefore fans back out to its holder by construction: a
    /// record surfaced over an opaque or dropped member would be an
    /// `ipe`-exit-0-then-cargo-fail (a missing type or an `E0308`), the keystone
    /// breach this decision forbids.
    fn representation(
        &self,
        nominal: &str,
        classify: impl FnOnce() -> Result<TransparentType, String>,
    ) -> Result<TransparentType, String> {
        if self.define_refs.contains(nominal) {
            return Err(
                "another define surface holds it as an opaque handle — a seam the \
                 conversion glue does not cover"
                    .to_owned(),
            );
        }
        if self.path_map.contains_key(nominal) || self.poisoned.contains(nominal) {
            return Err(
                "an inspected foreign type of the crate claims the same nominal".to_owned(),
            );
        }
        classify()
    }

    /// Apply the representation decision for a claimed define nominal:
    /// register the transparent shape (returning the forwarders' result
    /// conversion) or the opaque nominal (recording the reason so the
    /// conservative fallback stays visible in the coverage ledger).
    fn surface_define(
        &mut self,
        nominal: &str,
        classify: impl FnOnce() -> Result<TransparentType, String>,
    ) -> Option<TransparentResult> {
        match self.representation(nominal, classify) {
            Ok(t) => {
                self.transparent_defines.insert(nominal.to_owned(), t);
                Some(TransparentResult {
                    type_name: nominal.to_owned(),
                    in_result: false,
                })
            }
            Err(reason) => {
                self.opaque_defines.insert(nominal.to_owned());
                self.skip(
                    &format!("type {nominal}"),
                    format!("define type surfaces as an opaque nominal: {reason}"),
                );
                None
            }
        }
    }

    /// Remove a claimed nominal from every registration (an enum whose every
    /// variant forwarder dropped declares no reachable constructor).
    fn unclaim(&mut self, nominal: &str) {
        self.claimed.remove(nominal);
        self.opaque_defines.remove(nominal);
        self.transparent_defines.remove(nominal);
    }
}

/// Every nominal a define surface references at a member seam: closure
/// signature params/returns and define types' fields/payloads. A define type
/// named here must keep the opaque-handle representation — the referencing
/// wrapper's seam names the defined Rust type directly, a position the
/// record/union conversion glue does not cover.
///
/// This set is the seed of the transparency least-fixpoint (see
/// [`DefineAdmission::representation`]): a referenced nominal is pinned opaque,
/// and because [`crate::transparency::classify_define_struct`] /
/// [`crate::transparency::classify_define_enum`] admit only identity SCALAR
/// members, a type holding any define-nominal member is disqualified in the same
/// pass — so the un-flip fans transitively to every referencing parent without a
/// second iteration. Flipping a seam is the removal of THAT seam's carrier
/// contribution from this set, in the same change that emits and seals the
/// seam's conversion glue; until then every referenced nominal stays fail-closed
/// opaque with its reason recorded.
fn define_referenced_nominals(pkg: &PkgInfo) -> BTreeSet<String> {
    use crate::carrier::{Carrier, ClosureRet};
    let mut out = BTreeSet::new();
    let mut note = |c: &Carrier| {
        if let Carrier::Opaque(id) = c {
            out.insert(id.as_str().to_owned());
        }
    };
    for f in pkg.fns() {
        match f.shape() {
            crate::pkginfo::FnShape::ClosureAdapter { sig } => {
                for c in &sig.params {
                    note(c);
                }
                match &sig.ret {
                    ClosureRet::Total(_) => {}
                    ClosureRet::Result(c)
                    | ClosureRet::Option(c)
                    | ClosureRet::AsyncResult(c)
                    | ClosureRet::AsyncOption(c) => note(c),
                }
            }
            crate::pkginfo::FnShape::StructCtor { def } => {
                for (_, c) in &def.fields {
                    note(c);
                }
            }
            crate::pkginfo::FnShape::EnumDefCtor { def } => {
                for v in &def.variants {
                    for c in &v.payload {
                        note(c);
                    }
                }
            }
            _ => {}
        }
    }
    out
}

/// Admit a `define.struct` constructor as an Ipê forwarder, registering the
/// struct's nominal as a define-defined type.
///
/// The whole surface is synthesised from the parsed [`StructDef`]: the forwarder
/// signature and arity come from the field carriers (the fn's own
/// `params()`/`results()` are empty — it is a manifest entry), and the nominal is
/// the struct's own name. An all-identity-carrier struct no other define surface
/// references surfaces TRANSPARENT — a record alias plus result-conversion glue
/// on the constructor, the same machinery a transparent import rides — while
/// anything less keeps the opaque nominal with its reason recorded. Over-drops
/// fail-closed:
///
/// * a constructor name that is not a legal Ipê value identifier is dropped;
/// * a duplicate constructor name keeps the first;
/// * the struct nominal routes through [`claim_nominal`], which refuses a
///   reserved-builtin shadow or a collision with another define surface
///   (an admitted shadowing/colliding nominal is a silent-wrong-type or
///   duplicate-definition SEAL breach — refuse, never rename).
fn admit_struct_forwarder(ctor: &str, def: &crate::carrier::StructDef, adm: &mut DefineAdmission) {
    let type_name = def.name.as_str();
    if !valid_ipe_value_name(ctor) {
        adm.skip(
            ctor,
            "define.struct constructor name is not a legal Ipê identifier".to_owned(),
        );
        return;
    }
    if !adm.seen.insert(ctor.to_owned()) {
        adm.skip(
            ctor,
            "duplicate binding name — first occurrence kept".to_owned(),
        );
        return;
    }
    if let Err(reason) = claim_nominal(
        "define.struct",
        type_name,
        adm.claimed,
        adm.transparent_imports,
    ) {
        adm.skip(ctor, reason);
        return;
    }
    let transparent_result = adm.surface_define(type_name, || {
        crate::transparency::classify_define_struct(def)
    });
    adm.bindings.push(InterfaceBinding {
        wrapper_ident: crate::naming::wrapper_fn_ident(adm.kernel_name, ctor),
        // A fieldless struct's forwarder is a unary `() -> T` function (its
        // wrapper takes the unit value), the same convention as a zero-param
        // inspected binding.
        arity: def.fields.len().max(1),
        sig: def.forwarder_ipe_sig(),
        ref_name: ctor.to_owned(),
        transparent_params: Vec::new(),
        transparent_result,
    });
}

/// Admit each `define.enum` variant constructor as an Ipê forwarder, registering
/// the enum's nominal ONCE.
///
/// The enum is one Rust type; its N per-variant constructor fns all return that
/// one nominal, so the nominal registers once and each variant forwarder differs
/// only in its value-level `ref_name` (`<ctor>_<snake(variant)>`) and arity. An
/// all-identity-carrier enum no other define surface references surfaces
/// TRANSPARENT — a closed union plus result-conversion glue on every variant
/// forwarder, the same machinery a transparent import rides — while anything
/// less keeps the opaque nominal with its reason recorded. Over-drops
/// fail-closed:
///
/// * the enum nominal routes through [`claim_nominal`] up-front, which refuses a
///   reserved-builtin shadow or a collision with another define surface,
///   dropping the WHOLE entry (all variant forwarders) — a shadowing/colliding
///   nominal is a silent-wrong-type or duplicate-definition SEAL breach;
/// * a per-variant constructor name that is not a legal Ipê value identifier is
///   dropped INDIVIDUALLY (each variant name is independent), the rest kept;
/// * a duplicate constructor name keeps the first.
fn admit_enum_forwarders(ref_name: &str, def: &crate::carrier::EnumDef, adm: &mut DefineAdmission) {
    let enum_name = def.name.as_str();
    // Claim the ONE shared nominal up-front so a reserved-builtin shadow or a
    // collision with another define surface refuses the WHOLE entry fail-closed
    // — a variant forwarder must never point at an enum whose `type` was dropped.
    // An enum with no surviving variant un-claims the nominal at the tail.
    if let Err(reason) = claim_nominal(
        "define.enum",
        enum_name,
        adm.claimed,
        adm.transparent_imports,
    ) {
        adm.skip(ref_name, reason);
        return;
    }
    let transparent_result =
        adm.surface_define(enum_name, || crate::transparency::classify_define_enum(def));
    let mut any_admitted = false;
    for v in &def.variants {
        // The per-variant constructor `ref_name` — the SAME construction the
        // wrapper emitter uses for the emitted `pub fn`, so the forwarder's
        // `wrapper_ident` cannot drift from the fn it forwards to.
        let variant_ref = format!(
            "{ref_name}_{}",
            crate::naming::variant_snake(v.name.as_str())
        );
        if !valid_ipe_value_name(&variant_ref) {
            adm.skip(
                &variant_ref,
                "define.enum variant constructor name is not a legal Ipê identifier".to_owned(),
            );
            continue;
        }
        if !adm.seen.insert(variant_ref.clone()) {
            adm.skip(
                &variant_ref,
                "duplicate binding name — first occurrence kept".to_owned(),
            );
            continue;
        }
        adm.bindings.push(InterfaceBinding {
            wrapper_ident: crate::naming::wrapper_fn_ident(adm.kernel_name, &variant_ref),
            // A unit variant's forwarder is a unary `() -> T` function (its
            // wrapper takes the unit value), the same convention as a
            // zero-param inspected binding.
            arity: v.payload.len().max(1),
            sig: v.forwarder_ipe_sig(enum_name),
            ref_name: variant_ref,
            transparent_params: Vec::new(),
            transparent_result: transparent_result.clone(),
        });
        any_admitted = true;
    }
    // Keep the nominal only when at least one variant forwarder survives — an
    // enum whose every variant name is illegal declares no reachable constructor,
    // so a bare `type` would be a dead opaque. Un-claim it otherwise (it was
    // claimed up-front for the fail-closed collision gate).
    if !any_admitted {
        adm.unclaim(enum_name);
    }
}

/// Admit a `define.closure` adapter as an arity-1 Ipê forwarder, registering
/// its returned boxed closure's opaque handle nominal as a define-defined type.
///
/// The wrapper takes ONE argument — the Ipê function value — and returns the
/// boxed closure surfaced as the handle nominal (see
/// [`crate::naming::closure_handle_nominal`]); the forwarder's Ipê signature is
/// `(A -> B -> R) -> <Handle>`, synthesised from the parsed [`ClosureSig`]'s
/// carriers, never the empty fn params. The handle registers in `define_types`
/// so the backend resolves it at the crate-local `crate::ffi::<slug>::<Handle>`,
/// exactly as a define-struct/enum nominal.
///
/// Over-drops fail-closed — the handle nominal is never renamed to dodge a clash:
///
/// * a `ref_name` that is not a legal Ipê value identifier, or a duplicate
///   `ref_name`, is dropped (keeping the first);
/// * the handle nominal routes through [`claim_nominal`], which refuses a
///   reserved-builtin shadow or a collision with any other define surface
///   (struct / enum / another closure adapter) fail-closed.
fn admit_closure_forwarder(
    ref_name: &str,
    sig: &crate::carrier::ClosureSig,
    adm: &mut DefineAdmission,
) {
    if !valid_ipe_value_name(ref_name) {
        adm.skip(
            ref_name,
            "define.closure adapter name is not a legal Ipê identifier".to_owned(),
        );
        return;
    }
    let handle = crate::naming::closure_handle_nominal(ref_name);
    if !adm.seen.insert(ref_name.to_owned()) {
        adm.skip(
            ref_name,
            "duplicate binding name — first occurrence kept".to_owned(),
        );
        return;
    }
    if let Err(reason) = claim_nominal(
        "define.closure handle",
        &handle,
        adm.claimed,
        adm.transparent_imports,
    ) {
        adm.skip(ref_name, reason);
        return;
    }
    // A boxed-closure handle is a sealed value by nature — it always keeps the
    // opaque representation.
    adm.opaque_defines.insert(handle.clone());
    adm.bindings.push(InterfaceBinding {
        wrapper_ident: crate::naming::wrapper_fn_ident(adm.kernel_name, ref_name),
        arity: 1,
        sig: sig.forwarder_ipe_sig(&handle),
        ref_name: ref_name.to_owned(),
        transparent_params: Vec::new(),
        transparent_result: None,
    });
}

/// Claim a define-defined nominal for the interface, fail-closed.
///
/// EVERY define surface — struct, enum, closure handle — DEFINES a bare
/// in-module `pub struct`/`pub enum`/`pub type` in the one emitted
/// `pub mod <slug>` region, so two distinct definitions that claim the SAME
/// nominal are an `E0428` the app crate cannot compile — an `ipe`-exit-0 ⇒
/// cargo-fail SEAL breach. Routing every claim through here makes "each define
/// nominal registered at most once" the ONLY representable outcome, independent
/// of admission order (a name-collision is refused whichever surface declares it
/// second, never renamed to dodge the clash):
///
/// * a nominal shadowing an Ipê reserved builtin is refused (a shadowing nominal
///   is a silent-wrong-type breach);
/// * a nominal already claimed by another define surface is refused.
///
/// Returns `Ok(())` with the nominal inserted into `claimed` (the caller then
/// registers it opaque or transparent), or `Err(reason)` naming the broken rule
/// for the caller to record as a skip.
fn claim_nominal(
    kind: &str,
    nominal: &str,
    claimed: &mut BTreeSet<String>,
    transparent: &BTreeMap<String, TransparentType>,
) -> Result<(), String> {
    if ipe_canon::is_user_type_declaration_forbidden(nominal) {
        return Err(format!(
            "{kind} type `{nominal}` shadows an Ipê reserved builtin type"
        ));
    }
    // A define nominal colliding with an admitted transparent foreign type
    // would declare the record/union AND the define type under one name in
    // one module (E0428 / a silently-wrong type). The crate's own type wins;
    // the author renames the define.
    if transparent.contains_key(nominal) {
        return Err(format!(
            "{kind} type `{nominal}` collides with a transparent foreign type of the crate"
        ));
    }
    if !claimed.insert(nominal.to_owned()) {
        return Err(format!(
            "{kind} type `{nominal}` collides with another define-defined nominal"
        ));
    }
    Ok(())
}

/// Render the injectable module text.
///
/// Opaque types are exported WITHOUT `(..)` so their placeholder constructor
/// never escapes the module; the lowerer additionally fails closed on any
/// constructor use of a foreign union. A transparent enum exports WITH `(..)`
/// — its constructors ARE the surface — and a transparent struct exports its
/// record alias name.
///
/// `imports` (home module → type names) renders one
/// `import <Home> exposing (T, …)` line per entry: the catalog unification
/// demotes a re-declared foreign type to an import of its ONE home module, so
/// the importer's bare `T` canonicalises to the home's nominal.
pub fn render_module(
    module_name: &str,
    imports: &BTreeMap<String, BTreeSet<String>>,
    opaque_types: &BTreeMap<String, String>,
    define_types: &BTreeSet<String>,
    transparent_types: &BTreeMap<String, TransparentType>,
    bindings: &[InterfaceBinding],
) -> String {
    let mut exports: Vec<String> = opaque_types.keys().cloned().collect();
    exports.extend(define_types.iter().cloned());
    exports.extend(transparent_types.values().map(|t| match t {
        TransparentType::Struct { name, .. } => name.as_str().to_owned(),
        TransparentType::Enum { name, .. } => format!("{name}(..)"),
    }));
    exports.extend(bindings.iter().map(|b| b.ref_name.clone()));
    let mut out = format!("module {module_name} exposing ({})\n", exports.join(", "));
    for (home, names) in imports {
        let joined = names.iter().cloned().collect::<Vec<_>>().join(", ");
        let _ = write!(out, "\nimport {home} exposing ({joined})\n");
    }
    // Both an inspected opaque foreign type and a `define`-defined nominal are
    // Ipê-held opaque handles — one nullary `type <Name> = <Name>` declaration,
    // exported WITHOUT `(..)` so the placeholder constructor never escapes. The
    // two differ only in their Rust PATH (external `::crate::T` vs crate-local
    // `crate::ffi::<slug>::T`), resolved downstream, never in their Ipê surface.
    for name in opaque_types.keys().chain(define_types.iter()) {
        // Writing into a String is infallible.
        let _ = write!(out, "\ntype {name} = {name}\n");
    }
    // A transparent foreign type declares its REAL shape: a record alias for a
    // struct, a closed union for an enum — the representation axis surfaced.
    for t in transparent_types.values() {
        let _ = write!(out, "\n{}\n", transparent_type_decl(t));
    }
    for b in bindings {
        let args: Vec<String> = (0..b.arity).map(crate::naming::arg_name).collect();
        let args_joined = args.join(" ");
        // An arity-0 binding only occurs in a legacy stored projection (every
        // generated forwarder is at least unary — a zero-param foreign fn and
        // a nullary define constructor both take the unit value). It renders
        // the zero-arg shape its stored zero-param wrapper matches.
        if b.arity == 0 {
            let _ = write!(
                out,
                "\n{} : {}\n{} =\n    Ffi.binding \"{}\"\n",
                b.ref_name, b.sig, b.ref_name, b.wrapper_ident
            );
        } else {
            let _ = write!(
                out,
                "\n{} : {}\n{} {} =\n    Ffi.binding \"{}\" {}\n",
                b.ref_name, b.sig, b.ref_name, args_joined, b.wrapper_ident, args_joined
            );
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pkginfo::PkgInfo;

    /// Every lexer keyword is refused as a binding name — `foreign`/`do`
    /// included — so a foreign binding can never emit an unparseable module.
    #[test]
    fn every_ipe_keyword_is_refused_as_a_binding_name() {
        for kw in ipe_parse::KEYWORDS {
            assert!(!valid_ipe_value_name(kw), "keyword {kw:?} accepted");
        }
    }

    /// Non-ASCII names the lexer would not tokenize as one identifier are
    /// refused; non-keywords like `alias`/`port` are admitted.
    #[test]
    fn binding_name_charset_is_the_lexer_ascii_set() {
        for bad in [
            "caf\u{e9}",
            "\u{e9}t\u{e9}",
            "x\u{0301}",
            "n\u{b2}",
            "\u{ff58}",
            "Upper",
            "_x",
            "",
        ] {
            assert!(!valid_ipe_value_name(bad), "{bad:?} accepted");
        }
        for good in ["alias", "port", "where", "major_field", "x1"] {
            assert!(valid_ipe_value_name(good), "{good:?} refused");
        }
    }

    fn pkg() -> PkgInfo {
        let doc = serde_json::json!({
            "pkg": "semver",
            "name": "semver",
            "version": "1.0.26",
            "functions": [
                {
                    "name": "parse",
                    "params": [{"name": "text", "type": "&str", "ipeType": "String"}],
                    "results": [{"name": "", "type": "Result<Version, Error>",
                                 "rustType": "Result<semver::Version, semver::Error>"}],
                    "effect": "fallible"
                },
                {
                    "name": "major_field",
                    "params": [{"name": "self", "type": "&Version", "ipeType": "Version",
                                "rustType": "semver::Version"}],
                    "results": [{"name": "", "type": "u64", "rustType": "u64"}],
                    "effect": "pure",
                    "recvType": "Version",
                    "recvRustType": "semver::Version",
                    "methodName": "major",
                    "isField": true
                },
                {
                    "name": "explain",
                    "params": [{"name": "self", "type": "&Error", "ipeType": "Error",
                                "rustType": "semver::Error"}],
                    "results": [{"name": "", "type": "String"}],
                    "effect": "pure",
                    "recvType": "Error",
                    "recvRustType": "semver::Error"
                }
            ],
            "errors": [],
            "transitiveDeps": [
                {"ident": "semver", "name": "semver", "version": "1.0.26"}
            ],
            "foreignTypeIds": {
                "::semver::Version": "semver::version::Version"
            }
        });
        PkgInfo::decode_json(&doc.to_string()).expect("decodes")
    }

    #[test]
    fn interface_includes_survivors_and_maps_opaque_paths() {
        let iface = crate_interface(&pkg());
        assert_eq!(iface.module_name, "Rust.Semver");
        assert_eq!(iface.kernel_name, "Rust_Semver");
        let names: Vec<&str> = iface.bindings.iter().map(|b| b.ref_name.as_str()).collect();
        assert_eq!(
            names,
            vec!["parse", "major_field_from_version"],
            "{:?}",
            iface.skipped
        );
        assert_eq!(
            iface.opaque_types.get("Version").map(String::as_str),
            Some("::semver::Version")
        );
        // The defining-path identity rides along for catalog unification.
        assert_eq!(
            iface.opaque_type_ids.get("Version").map(String::as_str),
            Some("semver::version::Version")
        );
        // `Error` is a builtin head — never an opaque decl, and `explain`
        // (whose receiver is the foreign `semver::Error`) is dropped.
        assert!(!iface.opaque_types.contains_key("Error"));
        assert!(
            iface
                .skipped
                .iter()
                .any(|s| s.ref_name == "explain_from_error"
                    && s.reason.contains("shadows an Ipê reserved builtin type")),
            "{:?}",
            iface.skipped
        );
    }

    #[test]
    fn a_declared_only_opaque_surfaces_even_without_a_binding() {
        // A crate with no functions but one DECLARED opaque handle: the handle
        // nominal must survive into `opaque_types` (the used-only prune does not
        // apply to a declaration) and be exported as `type Conn = Conn`.
        let doc = serde_json::json!({
            "pkg": "postgres",
            "name": "postgres",
            "version": "0.1.0",
            "functions": [],
            "errors": [],
            "declaredOpaques": { "Conn": "::postgres::Client" }
        });
        let pkg = PkgInfo::decode_json(&doc.to_string()).expect("decodes");
        let iface = crate_interface(&pkg);
        assert_eq!(
            iface.opaque_types.get("Conn").map(String::as_str),
            Some("::postgres::Client")
        );
        assert!(
            iface.source.contains("type Conn = Conn"),
            "{}",
            iface.source
        );
        assert!(iface.source.contains("exposing (Conn)"), "{}", iface.source);
    }

    #[test]
    fn a_declared_opaque_colliding_with_a_transparent_define_is_refused() {
        // One `foreign` head used as BOTH a define nominal (an all-identity
        // struct → a transparent record `Widget`) AND a declared opaque handle
        // (`Opaque "Client"`) must NOT emit `Widget` from two surfaces: that
        // would render `type Widget = Widget` beside the record alias and list
        // `Widget` twice in `exposing` — a duplicate-definition the app crate
        // cannot compile. The declared opaque is refused; the transparent
        // define keeps the nominal.
        let doc = serde_json::json!({
            "pkg": "demo", "name": "demo", "version": "0.1.0",
            "functions": [{
                "name": "widget_new", "effect": "pure", "isStructCtor": true,
                "structName": "Widget",
                "structFields": [{ "name": "x", "type": "i64" }],
                "structDerives": ["Clone"]
            }],
            "errors": [],
            "declaredOpaques": { "Widget": "::demo::Client" }
        });
        let iface = crate_interface(&PkgInfo::decode_json(&doc.to_string()).expect("decodes"));
        // The nominal is surfaced ONCE, by the transparent define — the declared
        // opaque never entered `opaque_types`.
        assert!(
            iface.transparent_types.contains_key("Widget"),
            "{:?}",
            iface.skipped
        );
        assert!(
            !iface.opaque_types.contains_key("Widget"),
            "declared opaque must be refused, not surfaced: {:?}",
            iface.opaque_types
        );
        // No `type Widget = Widget` opaque decl rides alongside the record.
        assert!(
            !iface.source.contains("type Widget = Widget"),
            "{}",
            iface.source
        );
        // The `exposing` header lists `Widget` exactly once.
        let header = iface.source.lines().next().expect("module header line");
        assert_eq!(header.matches("Widget").count(), 1, "{header}");
        // The refusal is recorded, naming the transparent collision.
        assert!(
            iface.skipped.iter().any(|s| s.ref_name == "type Widget"
                && s.reason
                    .contains("collides with a transparent foreign type")),
            "{:?}",
            iface.skipped
        );
    }

    #[test]
    fn a_declared_opaque_colliding_with_a_define_opaque_nominal_is_refused() {
        // A `foreign` head used as BOTH a define nominal that stays an opaque
        // handle (a `Bytes`-field struct → `type Blob = Blob`) AND a declared
        // opaque (`Opaque "Other"`) would emit `type Blob = Blob` twice and
        // double the `exposing` entry. The declared opaque is refused; the
        // define keeps the nominal at ITS resolved representation.
        let doc = serde_json::json!({
            "pkg": "demo", "name": "demo", "version": "0.1.0",
            "functions": [{
                "name": "blob_new", "effect": "pure", "isStructCtor": true,
                "structName": "Blob",
                "structFields": [{ "name": "data", "type": "Bytes" }],
                "structDerives": ["Clone"]
            }],
            "errors": [],
            "declaredOpaques": { "Blob": "::demo::Other" }
        });
        let iface = crate_interface(&PkgInfo::decode_json(&doc.to_string()).expect("decodes"));
        assert!(iface.define_types.contains("Blob"), "{:?}", iface.skipped);
        // The declared opaque never overwrote the define nominal's path.
        assert!(
            !iface.opaque_types.contains_key("Blob"),
            "declared opaque must be refused, not surfaced: {:?}",
            iface.opaque_types
        );
        // Exactly one `type Blob = Blob` renders (from the define), not two.
        assert_eq!(
            iface.source.matches("type Blob = Blob").count(),
            1,
            "{}",
            iface.source
        );
        // The `exposing` header lists `Blob` exactly once.
        let header = iface.source.lines().next().expect("module header line");
        assert_eq!(header.matches("Blob").count(), 1, "{header}");
        // The refusal is recorded, naming the define collision.
        assert!(
            iface.skipped.iter().any(|s| s.ref_name == "type Blob"
                && s.reason.contains("collides with a define-defined nominal")),
            "{:?}",
            iface.skipped
        );
    }

    #[test]
    fn plain_multi_result_numeric_string_bool_tuple_is_admitted_not_dropped() {
        // A non-borrow-reader free fn returning a tuple of numeric / owned
        // `String` / `bool` components used to over-drop on the tuple gate; each
        // component is now coercible (numeric widens to its carrier, String/bool
        // ride identity), so it binds. A tuple carrying an OPAQUE component still
        // drops — its ownership/path wiring is not in the tuple emitter.
        let doc = serde_json::json!({
            "pkg": "geom",
            "name": "geom",
            "version": "0.1.0",
            "functions": [
                {
                    "name": "extent",
                    "params": [],
                    "results": [{"name": "", "type": "(Int, Int)", "rustType": "(u64, u32)"}],
                    "effect": "pure"
                },
                {
                    "name": "labelled_extent",
                    "params": [],
                    "results": [{"name": "", "type": "(Int, String, Bool)",
                                 "rustType": "(u64, String, bool)"}],
                    "effect": "pure"
                },
                {
                    "name": "handle_extent",
                    "params": [],
                    "results": [{"name": "", "type": "(Int, Version)",
                                 "rustType": "(u64, Version)"}],
                    "effect": "pure"
                }
            ],
            "errors": []
        });
        let iface = crate_interface(&PkgInfo::decode_json(&doc.to_string()).expect("decodes"));
        assert!(
            iface
                .bindings
                .iter()
                .any(|b| b.ref_name == "extent" && b.sig == "() -> Result Error (Int, Int)"),
            "{:?}",
            iface.skipped
        );
        // The String/bool-carrying tuple now binds too.
        assert!(
            iface
                .bindings
                .iter()
                .any(|b| b.ref_name == "labelled_extent"
                    && b.sig == "() -> Result Error (Int, String, Bool)"),
            "{:?}",
            iface.skipped
        );
        // The opaque-carrying tuple still over-drops on the tuple gate.
        assert!(
            iface
                .skipped
                .iter()
                .any(|s| s.ref_name == "handle_extent"
                    && s.reason.contains("component scalar coercion")),
            "{:?}",
            iface.skipped
        );
    }

    #[test]
    fn rendered_module_is_annotated_forwarders() {
        let iface = crate_interface(&pkg());
        let src = &iface.source;
        assert!(
            src.starts_with(
                "module Rust.Semver exposing (Version, parse, major_field_from_version)"
            ),
            "{src}"
        );
        assert!(src.contains("\ntype Version = Version\n"), "{src}");
        assert!(
            src.contains("\nparse : String -> Result Error Version\nparse arg0 =\n    Ffi.binding \"semver_parse\" arg0\n"),
            "{src}"
        );
        assert!(
            src.contains(
                "\nmajor_field_from_version : Version -> Int\nmajor_field_from_version arg0 =\n    Ffi.binding \"semver_major_field_from_version\" arg0\n"
            ),
            "{src}"
        );
    }

    #[test]
    fn conflicting_paths_poison_the_base_name() {
        let (map, poisoned) = foreign_path_map(&pkg());
        assert_eq!(
            map.get("Version").map(String::as_str),
            Some("::semver::Version")
        );
        assert!(poisoned.is_empty());
        assert_eq!(
            path_tokens("HashMap<foo::Bar, baz::Bar>"),
            vec![
                ("Bar".to_owned(), "::foo::Bar".to_owned()),
                ("Bar".to_owned(), "::baz::Bar".to_owned()),
            ]
        );
    }

    /// One-crate package carrying a single `define.struct` entry.
    fn struct_pkg(ctor: &str, name: &str, fields: &serde_json::Value) -> PkgInfo {
        let doc = serde_json::json!({
            "pkg": "demo", "name": "demo", "version": "0.1.0",
            "functions": [{
                "name": ctor, "effect": "pure", "isStructCtor": true,
                "structName": name, "structFields": fields, "structDerives": ["Clone"]
            }],
            "errors": []
        });
        PkgInfo::decode_json(&doc.to_string()).expect("decodes")
    }

    /// One-crate package carrying a single `define.enum` entry.
    fn enum_pkg(ctor: &str, name: &str, variants: &serde_json::Value) -> PkgInfo {
        let doc = serde_json::json!({
            "pkg": "demo", "name": "demo", "version": "0.1.0",
            "functions": [{
                "name": ctor, "effect": "pure", "isEnumDef": true,
                "enumName": name, "enumVariants": variants, "enumDerives": ["Clone"]
            }],
            "errors": []
        });
        PkgInfo::decode_json(&doc.to_string()).expect("decodes")
    }

    #[test]
    fn define_struct_admits_a_forwarder_and_a_transparent_record() {
        let iface = crate_interface(&struct_pkg(
            "counter_new",
            "Counter",
            &serde_json::json!([{ "name": "value", "type": "i64" }]),
        ));
        // An all-identity-carrier define struct surfaces as a transparent
        // record, not an opaque nominal.
        assert!(
            iface.transparent_types.contains_key("Counter"),
            "{:?}",
            iface.skipped
        );
        assert!(iface.define_types.is_empty(), "{:?}", iface.define_types);
        let b = iface
            .bindings
            .iter()
            .find(|b| b.ref_name == "counter_new")
            .expect("counter_new admitted");
        // Arity + signature come from the def's fields, not the empty fn params.
        assert_eq!(b.arity, 1);
        assert_eq!(b.sig, "Int -> Counter");
        assert_eq!(b.wrapper_ident, "demo_counter_new");
        // The constructor's foreign result converts through the record glue.
        assert_eq!(
            b.transparent_result,
            Some(TransparentResult {
                type_name: "Counter".to_owned(),
                in_result: false
            })
        );
        // The forwarder + the record alias both render into the module.
        assert!(
            iface
                .source
                .contains("\ntype alias Counter = { value : Int }\n"),
            "{}",
            iface.source
        );
        assert!(
            iface.source.contains(
                "\ncounter_new : Int -> Counter\ncounter_new arg0 =\n    Ffi.binding \"demo_counter_new\" arg0\n"
            ),
            "{}",
            iface.source
        );
    }

    #[test]
    fn define_struct_outside_the_identity_set_stays_an_opaque_nominal() {
        // A `Bytes` field is a legal define carrier but outside the identity
        // set the conversion glue moves — the type keeps the opaque handle,
        // with the reason recorded.
        let iface = crate_interface(&struct_pkg(
            "blob_new",
            "Blob",
            &serde_json::json!([{ "name": "data", "type": "Bytes" }]),
        ));
        assert!(iface.define_types.contains("Blob"), "{:?}", iface.skipped);
        assert!(iface.transparent_types.is_empty());
        assert!(
            iface.source.contains("\ntype Blob = Blob\n"),
            "{}",
            iface.source
        );
        let b = iface
            .bindings
            .iter()
            .find(|b| b.ref_name == "blob_new")
            .expect("blob_new admitted");
        assert_eq!(b.transparent_result, None);
        assert!(
            iface.skipped.iter().any(|s| s.ref_name == "type Blob"
                && s.reason.contains("outside the identity carrier set")),
            "{:?}",
            iface.skipped
        );
    }

    #[test]
    fn define_type_referenced_by_a_closure_stays_an_opaque_nominal() {
        // The closure adapter's seam names the defined Rust type directly, so a
        // define type a closure signature references must keep the opaque
        // representation — a record surface would make the app-side function
        // value's type disagree with the adapter's expected box type.
        let doc = serde_json::json!({
            "pkg": "demo", "name": "demo", "version": "0.1.0",
            "functions": [
                {
                    "name": "counter_new", "effect": "pure", "isStructCtor": true,
                    "structName": "Counter",
                    "structFields": [{ "name": "value", "type": "i64" }],
                    "structDerives": ["Clone"]
                },
                {
                    "name": "step_fn", "effect": "pure", "isClosureAdapter": true,
                    "closureSig":
                        "Fn(Counter) -> Result<Counter, Error> + Send + Sync + 'static"
                }
            ],
            "errors": []
        });
        let iface = crate_interface(&PkgInfo::decode_json(&doc.to_string()).expect("decodes"));
        assert!(
            iface.define_types.contains("Counter"),
            "{:?}",
            iface.skipped
        );
        assert!(!iface.transparent_types.contains_key("Counter"));
        assert!(
            iface
                .skipped
                .iter()
                .any(|s| s.ref_name == "type Counter" && s.reason.contains("opaque handle")),
            "{:?}",
            iface.skipped
        );
    }

    #[test]
    fn define_type_sharing_an_inspected_nominal_stays_an_opaque_nominal() {
        // A define struct named like an inspected foreign type of the crate
        // must not surface a record under the shared nominal — the two are
        // different Rust types.
        let doc = serde_json::json!({
            "pkg": "demo", "name": "demo", "version": "0.1.0",
            "functions": [
                {
                    "name": "version_new", "effect": "pure", "isStructCtor": true,
                    "structName": "Version",
                    "structFields": [{ "name": "value", "type": "i64" }],
                    "structDerives": ["Clone"]
                },
                {
                    "name": "current",
                    "params": [],
                    "results": [{"name": "", "type": "Version",
                                 "rustType": "demo::Version"}],
                    "effect": "pure"
                }
            ],
            "errors": []
        });
        let iface = crate_interface(&PkgInfo::decode_json(&doc.to_string()).expect("decodes"));
        assert!(
            iface.define_types.contains("Version"),
            "{:?}",
            iface.skipped
        );
        assert!(!iface.transparent_types.contains_key("Version"));
        assert!(
            iface.skipped.iter().any(
                |s| s.ref_name == "type Version" && s.reason.contains("inspected foreign type")
            ),
            "{:?}",
            iface.skipped
        );
    }

    #[test]
    fn define_struct_fieldless_is_a_unit_arg_forwarder() {
        // A zero-field struct's constructor takes the unit value — the emitted
        // `pub fn` has a `_: ()` param, matching the zero-param inspected
        // convention — and the type stays an opaque nominal (an empty record
        // surfaces nothing the handle does not).
        let iface = crate_interface(&struct_pkg("unit_new", "Unit", &serde_json::json!([])));
        let b = iface
            .bindings
            .iter()
            .find(|b| b.ref_name == "unit_new")
            .expect("unit_new admitted");
        assert_eq!(b.arity, 1);
        assert_eq!(b.sig, "() -> Unit");
        assert!(iface.define_types.contains("Unit"), "{:?}", iface.skipped);
        assert!(
            iface.source.contains(
                "\nunit_new : () -> Unit\nunit_new arg0 =\n    Ffi.binding \"demo_unit_new\" arg0\n"
            ),
            "{}",
            iface.source
        );
    }

    #[test]
    fn define_enum_admits_one_forwarder_per_variant_and_one_nominal() {
        let iface = crate_interface(&enum_pkg(
            "message_new",
            "Message",
            &serde_json::json!([
                { "name": "Increment", "payload": [] },
                { "name": "SetValue", "payload": ["i64"] }
            ]),
        ));
        // An all-identity-carrier define enum surfaces as a transparent closed
        // union, registered exactly once, not per-variant.
        assert!(
            iface.transparent_types.contains_key("Message"),
            "{:?}",
            iface.skipped
        );
        assert!(iface.define_types.is_empty(), "{:?}", iface.define_types);
        assert!(
            iface
                .source
                .contains("\ntype Message = Increment | SetValue Int\n"),
            "{}",
            iface.source
        );
        let inc = iface
            .bindings
            .iter()
            .find(|b| b.ref_name == "message_new_increment")
            .expect("unit-variant forwarder");
        assert_eq!(inc.arity, 1);
        assert_eq!(inc.sig, "() -> Message");
        assert_eq!(inc.wrapper_ident, "demo_message_new_increment");
        let setv = iface
            .bindings
            .iter()
            .find(|b| b.ref_name == "message_new_set_value")
            .expect("payload-variant forwarder");
        assert_eq!(setv.arity, 1);
        assert_eq!(setv.sig, "Int -> Message");
        // Every variant forwarder converts its foreign result through the
        // union glue.
        for b in [inc, setv] {
            assert_eq!(
                b.transparent_result,
                Some(TransparentResult {
                    type_name: "Message".to_owned(),
                    in_result: false
                })
            );
        }
        // The unit variant binds the unit value; the payload variant its Int.
        assert!(
            iface.source.contains(
                "\nmessage_new_increment : () -> Message\nmessage_new_increment arg0 =\n    Ffi.binding \"demo_message_new_increment\" arg0\n"
            ),
            "{}",
            iface.source
        );
        assert!(
            iface.source.contains(
                "\nmessage_new_set_value : Int -> Message\nmessage_new_set_value arg0 =\n    Ffi.binding \"demo_message_new_set_value\" arg0\n"
            ),
            "{}",
            iface.source
        );
    }

    #[test]
    fn define_type_shadowing_a_builtin_is_refused_whole() {
        // A define type named `Result` (a reserved builtin) refuses the WHOLE
        // entry — no forwarder, no nominal — an admitted shadow is a silent
        // wrong-type SEAL breach.
        let iface = crate_interface(&enum_pkg(
            "result_new",
            "Result",
            &serde_json::json!([{ "name": "Ok", "payload": [] }]),
        ));
        assert!(iface.define_types.is_empty());
        assert!(iface.bindings.iter().all(|b| b.ref_name != "result_new_ok"));
        assert!(
            iface
                .skipped
                .iter()
                .any(|s| s.reason.contains("shadows an Ipê reserved builtin type")),
            "{:?}",
            iface.skipped
        );
    }

    /// One-crate package with a transparent `Point` struct and `Shade` enum in
    /// the type catalog, plus the given functions.
    fn transparent_pkg(functions: &serde_json::Value) -> PkgInfo {
        let doc = serde_json::json!({
            "pkg": "tm", "name": "tm", "version": "0.1.0",
            "functions": functions,
            "errors": [],
            "types": [
                {"name": "Point", "rustPath": "tm::Point", "kind": "struct",
                 "fields": [
                    {"name": "x", "type": "Int", "rustType": "i64"},
                    {"name": "y", "type": "Float", "rustType": "f64"}
                 ]},
                {"name": "Shade", "rustPath": "tm::Shade", "kind": "enum",
                 "variants": [
                    {"name": "On", "kind": "unit"},
                    {"name": "Level", "kind": "tuple",
                     "members": [{"name": "0", "type": "Int", "rustType": "i64"}]}
                 ]}
            ]
        });
        PkgInfo::decode_json(&doc.to_string()).expect("decodes")
    }

    #[test]
    fn transparent_types_surface_as_record_alias_and_closed_union() {
        let iface = crate_interface(&transparent_pkg(&serde_json::json!([
            {"name": "shift",
             "params": [{"name": "p", "type": "Point", "ipeType": "Point",
                         "rustType": "tm::Point"}],
             "results": [{"name": "", "type": "Shade", "rustType": "tm::Shade"}],
             "effect": "pure"}
        ])));
        // Real declarations, exported — the union WITH its constructors.
        assert!(
            iface
                .source
                .contains("\ntype alias Point = { x : Int, y : Float }\n"),
            "{}",
            iface.source
        );
        assert!(
            iface.source.contains("\ntype Shade = On | Level Int\n"),
            "{}",
            iface.source
        );
        assert!(
            iface.source.contains("Point, Shade(..)"),
            "{}",
            iface.source
        );
        // Never opaque handles too: one name, one representation.
        assert!(iface.opaque_types.is_empty(), "{:?}", iface.opaque_types);
        assert_eq!(iface.transparent_types.len(), 2);
        // The binding records where the conversions apply.
        let b = iface.bindings.first().expect("shift admitted");
        assert_eq!(b.transparent_params, vec![Some("Point".to_owned())]);
        assert_eq!(
            b.transparent_result,
            Some(TransparentResult {
                type_name: "Shade".to_owned(),
                in_result: true,
            })
        );
    }

    #[test]
    fn transparent_type_in_an_uncovered_position_over_drops_the_binding() {
        // `Maybe Point` result: the conversion glue covers a bare param and a
        // bare/Result-wrapped result only — anything else over-drops with a
        // recorded reason instead of emitting a mis-wired seam.
        let iface = crate_interface(&transparent_pkg(&serde_json::json!([
            {"name": "find",
             "params": [{"name": "q", "type": "&str", "ipeType": "String"}],
             "results": [{"name": "", "type": "Maybe Point",
                          "rustType": "Option<tm::Point>", "ipeType": "Maybe Point"}],
             "effect": "pure"}
        ])));
        assert!(iface.bindings.is_empty(), "{:?}", iface.bindings);
        assert!(
            iface
                .skipped
                .iter()
                .any(|s| s.ref_name == "find" && s.reason.contains("does not cover")),
            "{:?}",
            iface.skipped
        );
    }

    #[test]
    fn unreferenced_transparent_types_are_pruned_from_the_surface() {
        // No admitted binding mentions Point or Shade — neither is declared,
        // and the prune is recorded.
        let iface = crate_interface(&transparent_pkg(&serde_json::json!([
            {"name": "version",
             "params": [],
             "results": [{"name": "", "type": "String"}],
             "effect": "pure"}
        ])));
        assert!(iface.transparent_types.is_empty());
        assert!(
            !iface.source.contains("type alias Point"),
            "{}",
            iface.source
        );
        assert!(!iface.source.contains("type Shade"), "{}", iface.source);
        assert!(
            iface.skipped.iter().any(|s| s.ref_name == "type Point"
                && s.reason.contains("referenced by no admitted binding")),
            "{:?}",
            iface.skipped
        );
    }

    #[test]
    fn signature_path_disagreement_drops_transparency_to_the_opaque_baseline() {
        // The fn signatures resolve `Point` at `other::Point` while the type
        // catalog claims `tm::Point`: gluing would name the wrong Rust type,
        // so transparency drops and the name stays an opaque handle.
        let iface = crate_interface(&transparent_pkg(&serde_json::json!([
            {"name": "shift",
             "params": [{"name": "p", "type": "Point", "ipeType": "Point",
                         "rustType": "other::Point"}],
             "results": [{"name": "", "type": "Point", "rustType": "other::Point"}],
             "effect": "pure"}
        ])));
        assert!(!iface.transparent_types.contains_key("Point"));
        assert!(
            iface.source.contains("\ntype Point = Point\n"),
            "{}",
            iface.source
        );
        assert_eq!(
            iface.opaque_types.get("Point").map(String::as_str),
            Some("::other::Point")
        );
        let b = iface
            .bindings
            .iter()
            .find(|b| b.ref_name == "shift")
            .expect("shift binds as opaque");
        assert!(b.transparent_params.iter().all(Option::is_none));
        assert!(b.transparent_result.is_none());
        assert!(
            iface
                .skipped
                .iter()
                .any(|s| s.ref_name == "type Point" && s.reason.contains("resolves to")),
            "{:?}",
            iface.skipped
        );
    }

    #[test]
    fn define_nominal_colliding_with_a_transparent_type_is_refused() {
        // A `[rust.define.struct]` claiming `Point` while the crate's own
        // `Point` is transparent would declare two types under one nominal.
        // The crate's type wins; the define entry is refused with a reason.
        let doc = serde_json::json!({
            "pkg": "tm", "name": "tm", "version": "0.1.0",
            "functions": [
                {"name": "shift",
                 "params": [{"name": "p", "type": "Point", "ipeType": "Point",
                             "rustType": "tm::Point"}],
                 "results": [{"name": "", "type": "Point", "rustType": "tm::Point"}],
                 "effect": "pure"},
                {"name": "point_new", "effect": "pure", "isStructCtor": true,
                 "structName": "Point",
                 "structFields": [{ "name": "x", "type": "i64" }],
                 "structDerives": []}
            ],
            "errors": [],
            "types": [
                {"name": "Point", "rustPath": "tm::Point", "kind": "struct",
                 "fields": [{"name": "x", "type": "Int", "rustType": "i64"}]}
            ]
        });
        let iface = crate_interface(&PkgInfo::decode_json(&doc.to_string()).expect("decodes"));
        assert!(iface.transparent_types.contains_key("Point"));
        assert!(!iface.define_types.contains("Point"));
        assert!(
            iface
                .skipped
                .iter()
                .any(|s| s.ref_name == "point_new"
                    && s.reason.contains("transparent foreign type")),
            "{:?}",
            iface.skipped
        );
    }

    #[test]
    fn top_level_arrow_split_keeps_parenthesised_groups_whole() {
        assert_eq!(
            split_top_level_arrows("Point -> Result Error Shade"),
            vec!["Point".to_owned(), "Result Error Shade".to_owned()]
        );
        assert_eq!(
            split_top_level_arrows("(Int -> Int) -> Point"),
            vec!["(Int -> Int)".to_owned(), "Point".to_owned()]
        );
        assert_eq!(split_top_level_arrows("()"), vec!["()".to_owned()]);
    }
}
