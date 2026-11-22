//! The signature a member's documentation shows: the annotation as written,
//! admitted only when it agrees with the checked type.
//!
//! A checked type names its variables by first-seen letters and has every
//! alias expanded away, so it reads unlike the source (`Result a b` for a
//! written `Result e a`). The written annotation reads as the author meant it,
//! but it is only text until it is compared: [`shown`] admits it when its
//! alias-expanded form is α-equivalent to the checked type, and otherwise
//! reports [`SignatureDrift`], so no rendering prints a type the checker did
//! not prove. A caller with a drift shows the checked type.
//!
//! Every recursion walks a type the parser's nesting cap already bounds; alias
//! expansion is bounded by [`MAX_ALIAS_EXPANSIONS`] per comparison, so a
//! self-referential alias table is a drift, never a loop.

use std::collections::BTreeMap;

use ipe_diagnostics::TyDoc;
use ipe_intern::{Interner, Symbol};
use ipe_syntax::TypeAnnotation;

/// The most alias uses one comparison expands before it reports a drift.
pub const MAX_ALIAS_EXPANSIONS: u32 = 256;

/// The signature text a member's entry shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShownSignature {
    text: String,
}

impl ShownSignature {
    /// The checked type's own rendering, with no annotation to admit.
    pub fn checked(checked: &TyDoc) -> Self {
        Self {
            text: crate::doc::plain_signature(checked),
        }
    }

    /// The flat signature text.
    pub fn text(&self) -> &str {
        &self.text
    }
}

/// A written annotation that does not agree with the checked type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignatureDrift;

/// One `type alias` a module declares, for expanding a written annotation.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Alias {
    params: Vec<Box<str>>,
    body: TyDoc,
}

/// The `type alias` declarations an annotation may name, by alias name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AliasTable {
    by_name: BTreeMap<Box<str>, Alias>,
}

impl AliasTable {
    /// Record `name params = body`.
    fn insert(&mut self, name: Box<str>, params: Vec<Box<str>>, body: TyDoc) {
        self.by_name.insert(name, Alias { params, body });
    }
}

/// The signature to show for a member whose checked type is `checked`.
///
/// With no `written` annotation the checked type is shown. With one, the
/// annotation is shown when, every alias of `aliases` expanded, it is the
/// checked type up to a renaming of variables.
///
/// # Errors
/// [`SignatureDrift`] when the annotation does not agree with `checked`.
pub fn shown(
    checked: &TyDoc,
    written: Option<&TyDoc>,
    aliases: &AliasTable,
) -> Result<ShownSignature, SignatureDrift> {
    let Some(written) = written else {
        return Ok(ShownSignature::checked(checked));
    };
    let mut check = Agreement {
        aliases,
        written_to_checked: BTreeMap::new(),
        checked_to_written: BTreeMap::new(),
        expansions: 0,
    };
    if check.agree(written, checked) {
        Ok(ShownSignature {
            text: crate::doc::plain_signature(written),
        })
    } else {
        Err(SignatureDrift)
    }
}

/// One α-equivalence comparison's variable bijection and expansion budget.
struct Agreement<'a> {
    aliases: &'a AliasTable,
    written_to_checked: BTreeMap<Box<str>, Box<str>>,
    checked_to_written: BTreeMap<Box<str>, Box<str>>,
    expansions: u32,
}

impl Agreement<'_> {
    /// Whether `written`, aliases expanded, is `checked` under the bijection
    /// built so far.
    fn agree(&mut self, written: &TyDoc, checked: &TyDoc) -> bool {
        if let TyDoc::Con { name, args, .. } = written
            && let Some(alias) = self.aliases.by_name.get(name)
            && alias.params.len() == args.len()
        {
            if self.expansions >= MAX_ALIAS_EXPANSIONS {
                return false;
            }
            self.expansions = self.expansions.saturating_add(1);
            let binding: BTreeMap<&str, &TyDoc> = alias
                .params
                .iter()
                .map(Box::as_ref)
                .zip(args.iter())
                .collect();
            let expanded = substitute(&alias.body, &binding);
            return self.agree(&expanded, checked);
        }
        match (written, checked) {
            (TyDoc::Var(w), TyDoc::Var(c)) => self.bind(w, c),
            (TyDoc::Unit, TyDoc::Unit) => true,
            (TyDoc::Fun(wa, wb), TyDoc::Fun(ca, cb)) => self.agree(wa, ca) && self.agree(wb, cb),
            (
                TyDoc::Con {
                    name: wn, args: wa, ..
                },
                TyDoc::Con {
                    name: cn, args: ca, ..
                },
            ) => wn == cn && self.agree_all(wa, ca),
            (TyDoc::Tuple(we), TyDoc::Tuple(ce)) => self.agree_all(we, ce),
            (TyDoc::Record(wf), TyDoc::Record(cf)) => {
                wf.len() == cf.len()
                    && wf
                        .iter()
                        .zip(cf.iter())
                        .all(|((wn, wt), (cn, ct))| wn == cn && self.agree(wt, ct))
            }
            _ => false,
        }
    }

    fn agree_all(&mut self, written: &[TyDoc], checked: &[TyDoc]) -> bool {
        written.len() == checked.len()
            && written
                .iter()
                .zip(checked.iter())
                .all(|(w, c)| self.agree(w, c))
    }

    /// Pair written variable `w` with checked variable `c`, one to one.
    fn bind(&mut self, w: &str, c: &str) -> bool {
        match (
            self.written_to_checked.get(w),
            self.checked_to_written.get(c),
        ) {
            (None, None) => {
                self.written_to_checked.insert(w.into(), c.into());
                self.checked_to_written.insert(c.into(), w.into());
                true
            }
            (Some(held_c), Some(held_w)) => held_c.as_ref() == c && held_w.as_ref() == w,
            _ => false,
        }
    }
}

/// `body` with each parameter variable of `binding` replaced by its argument.
fn substitute(body: &TyDoc, binding: &BTreeMap<&str, &TyDoc>) -> TyDoc {
    match body {
        TyDoc::Var(v) => binding
            .get(v.as_ref())
            .map_or_else(|| body.clone(), |arg| (*arg).clone()),
        TyDoc::Unit => TyDoc::Unit,
        TyDoc::Fun(a, b) => TyDoc::Fun(
            Box::new(substitute(a, binding)),
            Box::new(substitute(b, binding)),
        ),
        TyDoc::Con { module, name, args } => TyDoc::Con {
            module: module.clone(),
            name: name.clone(),
            args: args.iter().map(|a| substitute(a, binding)).collect(),
        },
        TyDoc::Tuple(elems) => TyDoc::Tuple(elems.iter().map(|e| substitute(e, binding)).collect()),
        TyDoc::Record(fields) => TyDoc::Record(
            fields
                .iter()
                .map(|(name, ty)| (name.clone(), substitute(ty, binding)))
                .collect(),
        ),
    }
}

/// The written annotation `annotation` as a [`TyDoc`], each variable keeping
/// its source spelling and each head its written name.
///
/// `None` for a form a [`TyDoc`] cannot carry (an open record), or a symbol
/// the interner does not hold: the caller then shows the checked type.
fn written_type(annotation: &TypeAnnotation, interner: &Interner) -> Option<TyDoc> {
    let spell = |symbol: Symbol| interner.resolve(symbol).map(Box::<str>::from);
    Some(match annotation {
        TypeAnnotation::TLambda(a, b) => TyDoc::Fun(
            Box::new(written_type(a, interner)?),
            Box::new(written_type(b, interner)?),
        ),
        TypeAnnotation::TVar(v) => TyDoc::Var(spell(*v)?),
        TypeAnnotation::TType(qualifier, segments, args) => TyDoc::Con {
            module: spell(*qualifier)?,
            name: spell(*segments.last()?)?,
            args: args
                .iter()
                .map(|a| written_type(a, interner))
                .collect::<Option<_>>()?,
        },
        TypeAnnotation::TUnit => TyDoc::Unit,
        TypeAnnotation::TTuple(elems) => TyDoc::Tuple(
            elems
                .iter()
                .map(|e| written_type(e, interner))
                .collect::<Option<_>>()?,
        ),
        TypeAnnotation::TRecord(fields) => {
            let mut out = fields
                .iter()
                .map(|(name, ty)| Some((spell(name.value)?, written_type(ty, interner)?)))
                .collect::<Option<Vec<_>>>()?;
            out.sort_by(|a, b| a.0.cmp(&b.0));
            TyDoc::Record(out.into())
        }
        TypeAnnotation::TRecordOpen(..) => return None,
    })
}

/// A module's written annotations and the aliases they may name, read once
/// from its parsed source.
#[derive(Debug, Clone, Default)]
pub struct WrittenSignatures {
    annotations: BTreeMap<String, TyDoc>,
    aliases: AliasTable,
}

impl WrittenSignatures {
    /// Every annotated value and every `type alias` of `source`.
    ///
    /// # Errors
    /// The parse diagnostic when `source` does not parse.
    pub fn parse(source: &str) -> Result<Self, ipe_diagnostics::Diagnostic> {
        let mut interner = Interner::new();
        let parsed = ipe_parse::parse_module(source, &mut interner)?;
        let mut out = Self::default();
        for alias in &parsed.aliases {
            let alias = &alias.value;
            let (Some(name), Some(params), Some(body)) = (
                interner.resolve(alias.name.value),
                alias
                    .vars
                    .iter()
                    .map(|v| interner.resolve(v.value).map(Box::<str>::from))
                    .collect::<Option<Vec<_>>>(),
                written_type(&alias.body.value, &interner),
            ) else {
                continue;
            };
            out.aliases.insert(name.into(), params, body);
        }
        for value in &parsed.values {
            let value = &value.value;
            let (Some(name), Some(annotation)) =
                (interner.resolve(value.name.value), &value.type_annotation)
            else {
                continue;
            };
            if let Some(ty) = written_type(&annotation.value, &interner) {
                out.annotations.insert(name.to_owned(), ty);
            }
        }
        Ok(out)
    }

    /// The signature `name` shows over its `checked` type: the admitted
    /// annotation, or the checked type when there is none or it drifts.
    pub fn shown_for(&self, name: &str, checked: &TyDoc) -> ShownSignature {
        shown(checked, self.annotations.get(name), &self.aliases)
            .unwrap_or_else(|SignatureDrift| ShownSignature::checked(checked))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn var(v: &str) -> TyDoc {
        TyDoc::Var(v.into())
    }

    fn con(name: &str, args: Vec<TyDoc>) -> TyDoc {
        TyDoc::Con {
            module: "Ipe.Result".into(),
            name: name.into(),
            args: args.into(),
        }
    }

    fn fun(a: TyDoc, b: TyDoc) -> TyDoc {
        TyDoc::Fun(Box::new(a), Box::new(b))
    }

    #[test]
    fn signature_keeps_written_var_names() {
        let checked = con("Result", vec![var("a"), var("b")]);
        let written = WrittenSignatures::parse("module M exposing (r)\n\nr : Result e a\nr = r\n")
            .expect("the fixture parses");
        let shown = written.shown_for("r", &checked);
        assert_eq!(shown.text(), "Result e a");
    }

    #[test]
    fn signature_keeps_alias() {
        let checked = fun(con("Int", vec![]), con("Maybe", vec![con("Int", vec![])]));
        let written = WrittenSignatures::parse(
            "module M exposing (p)\n\ntype alias Parse a = Int -> Maybe a\n\np : Parse Int\np = p\n",
        )
        .expect("the fixture parses");
        let shown = written.shown_for("p", &checked);
        assert_eq!(shown.text(), "Parse Int");
    }

    #[test]
    fn signature_drift_refused() {
        let checked = fun(con("Int", vec![]), con("String", vec![]));
        let wrong = fun(con("String", vec![]), con("Int", vec![]));
        assert_eq!(
            shown(&checked, Some(&wrong), &AliasTable::default()),
            Err(SignatureDrift)
        );
        let merged = fun(var("a"), var("a"));
        let distinct = fun(var("a"), var("b"));
        assert_eq!(
            shown(&distinct, Some(&merged), &AliasTable::default()),
            Err(SignatureDrift),
            "two written variables over one checked variable is not a renaming"
        );
        assert_eq!(
            shown(&merged, Some(&distinct), &AliasTable::default()),
            Err(SignatureDrift),
            "one written variable over two checked variables is not a renaming"
        );
        let written =
            WrittenSignatures::parse("module M exposing (f)\n\nf : String -> Int\nf = f\n")
                .expect("the fixture parses");
        let fallback = written.shown_for("f", &checked);
        assert_eq!(
            fallback.text(),
            "Int -> String",
            "a drift never prints the written text"
        );
    }

    #[test]
    fn a_self_referential_alias_is_a_drift_not_a_loop() {
        let mut aliases = AliasTable::default();
        aliases.insert("Loop".into(), Vec::new(), con("Loop", vec![]));
        assert_eq!(
            shown(&con("Int", vec![]), Some(&con("Loop", vec![])), &aliases),
            Err(SignatureDrift)
        );
    }

    #[test]
    fn no_annotation_shows_the_checked_type() {
        let checked = fun(var("a"), var("a"));
        let shown = shown(&checked, None, &AliasTable::default()).expect("no drift");
        assert_eq!(shown.text(), "a -> a");
    }
}
